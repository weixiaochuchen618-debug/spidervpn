//! 服务器记录与登录凭据：`<data root>/servers/<server-id>/`。
//!
//! 两个文件，分开存不是为了好看：
//! - `record.json`：公开（名字、host、port、user、主机指纹、时间）。**不含密码**，
//!   可以直接给人看、贴进工单；
//! - `credential.dpapi.json`：密码，整段封在 DPAPI 里，熵绑定这条记录的完整身份
//!   （id + host + port + user + 指纹）。换掉其中任何一项都解不开——一份被拷走的
//!   凭据文件不能被拿去连另一台服务器。
//!
//! 写入一律「临时文件 + sync + 重命名」：中途断电不会留下半个 JSON。
//! 凭据**先于**记录写盘：宁可留下一个没人引用的信封，也不要出现「有记录、解不开密码」。
//!
//! 与旧版的对应：`ServerRegistry.psm1` 的 `SavedLoginRef` + `credentials\<ref>.json`
//! （DPAPI v2，熵绑 ServerRecordId + Host + Port + User + PinnedHostKey）。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::pairing::{dpapi, zero, PairError};
use crate::ssh::Target;

const RECORD_FILE: &str = "record.json";
const CREDENTIAL_FILE: &str = "credential.dpapi.json";
const ID_LEN: usize = 36;

/// 一条服务器记录。字段刻意少：部署要用的身份信息全在这里，别的一律现读。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRecord {
    pub id: String,
    /// 显示名。默认 `user@host`，之后可以改（改名只动这一个字段）。
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// `SHA256:` 开头的主机公钥指纹。**这条记录的身份就是它**。
    pub fingerprint: String,
    pub created_at: String,
    pub updated_at: String,
}

impl ServerRecord {
    pub fn target(&self) -> Target {
        Target::new(&self.host, self.port, &self.user)
    }

    /// 给人看的一行：`root@203.0.113.10:22`。
    pub fn address(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }

    fn to_json(&self) -> Value {
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.ServerRecord",
            "Id": self.id,
            "Name": self.name,
            "Host": self.host,
            "Port": self.port,
            "User": self.user,
            "Fingerprint": self.fingerprint,
            "CreatedAtUtc": self.created_at,
            "UpdatedAtUtc": self.updated_at,
        })
    }

    fn from_json(value: &Value) -> Result<ServerRecord, PairError> {
        let text = |key: &str| -> Result<String, PairError> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| invalid("服务器记录缺少字段。"))
        };
        let port = value
            .get("Port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0)
            .ok_or_else(|| invalid("服务器记录的端口无效。"))?;
        Ok(ServerRecord {
            id: text("Id")?,
            name: text("Name")?,
            host: text("Host")?,
            port,
            user: text("User")?,
            fingerprint: text("Fingerprint")?,
            created_at: text("CreatedAtUtc")?,
            updated_at: text("UpdatedAtUtc")?,
        })
    }
}

fn invalid(message: &str) -> PairError {
    PairError::new_pub("ServerRecordInvalid", message)
}

fn invalid_id() -> PairError {
    PairError::new_pub("InvalidServerId", "服务器记录标识无效。")
}

fn write_failed(message: &str, error: &std::io::Error) -> PairError {
    PairError::new_pub("ServerWriteFailed", &format!("{message}：{error}"))
}

/// 小写 UUID（8-4-4-4-12，只允许 0-9a-f）。
///
/// 记录 id 会直接拼进路径，不卡死形状就等于允许 `..\..\` 决定写到哪里。
/// 与 `pairstore` 同一个判据，各自实现是因为两边的错误码不同——共用一份会让
/// 「哪个标识非法」这句话说不清。
fn is_server_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != ID_LEN {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte) {
                    return false;
                }
            }
        }
    }
    true
}

fn servers_dir(root: &Path) -> PathBuf {
    root.join("servers")
}

fn server_dir(root: &Path, id: &str) -> Result<PathBuf, PairError> {
    if !is_server_id(id) {
        return Err(invalid_id());
    }
    Ok(servers_dir(root).join(id))
}

fn write_json(path: &Path, value: &Value) -> Result<(), PairError> {
    let text = serde_json::to_vec_pretty(value)
        .map_err(|_| PairError::new_pub("ServerWriteFailed", "服务器记录无法序列化。"))?;
    let parent = path
        .parent()
        .ok_or_else(|| PairError::new_pub("ServerWriteFailed", "服务器记录路径无效。"))?;
    std::fs::create_dir_all(parent).map_err(|e| write_failed("创建服务器记录目录失败", &e))?;
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..8u32 {
        let temp = parent.join(format!(
            ".{}.tmp-{}-{attempt}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("record"),
            std::process::id()
        ));
        let file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(write_failed("创建服务器记录临时文件失败", &e)),
        };
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = file;
            file.write_all(&text)?;
            // 先落盘再改名：否则崩溃后可能得到一个名字正确、内容是空的文件。
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, path)
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&temp);
            return Err(write_failed("写入服务器记录失败", &e));
        }
        return Ok(());
    }
    Err(write_failed(
        "写入服务器记录失败（临时文件一直被占用）",
        &last.unwrap_or_else(|| std::io::Error::other("unknown")),
    ))
}

fn read_json(path: &Path) -> Result<Value, PairError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PairError::new_pub("ServerRecordNotFound", "本机没有这条服务器记录。")
        } else {
            invalid(&format!("读取服务器记录失败：{e}"))
        }
    })?;
    serde_json::from_str(&text).map_err(|_| invalid("服务器记录文件不是合法 JSON。"))
}

/// 凭据信封的熵。**身份一变就解不开**，这是「凭据不能挪用到别的服务器」的实现方式。
///
/// 用 `\n` 分隔而不是 `|`：host 与 user 在写入前已经禁掉了控制字符，
/// 而 `|` 是合法的用户名字符（虽然罕见），留着它等于给拼接留一个歧义口。
fn binding_of(record: &ServerRecord) -> String {
    format!(
        "TradeChannel.Deploy.v1\n{}\n{}\n{}\n{}\n{}",
        record.id, record.host, record.port, record.user, record.fingerprint
    )
}

/// host/user 的形状检查。除了「别为空」，还要挡住控制字符与分隔符：
/// 它们会被拼进熵、也会出现在记录文件与界面上。
fn validate_target(target: &Target) -> Result<(), PairError> {
    let bad = |text: &str| {
        text.is_empty()
            || text.chars().any(|c| c.is_control())
            || text.contains('|')
            || text.contains('\n')
    };
    if bad(&target.host) {
        return Err(invalid("服务器地址为空或包含不允许的字符。"));
    }
    if bad(&target.user) {
        return Err(invalid("登录用户名为空或包含不允许的字符。"));
    }
    Ok(())
}

/// 记下这台服务器：验过的指纹 + 封好的密码。
///
/// 同一目标（host/port/user）再记一次 = **更新**：id 与创建时间保持不变，
/// 名字与密码换新。但**指纹变了就拒绝**——那不是「更新」，是「换了台机器」，
/// 得由人先确认（删掉旧记录再重新信任），不能悄悄覆盖。
pub fn trust(
    root: &Path,
    target: &Target,
    fingerprint: &str,
    password: &str,
    now_unix: i64,
) -> Result<ServerRecord, PairError> {
    trust_with(root, target, fingerprint, password, true, now_unix)
}

/// 同上，但由调用方决定**要不要把密码落盘**。
///
/// 为什么需要这个开关：界面上的「在这台电脑记住登录资料」不是一个装饰性的勾。
/// 不勾时密码只该活在这一次的内存里；照旧无条件写信封，等于用户说「不要记住」
/// 而我们替他记住了——这是比多问一次密码严重得多的错。
///
/// 不落盘时**顺手删掉旧信封**：那台服务器以前也许被记住过，既然这次明确说了
/// 不记，留着一份「其实还留着密码」的文件就是界面在骗人。记录本身（指纹、地址）
/// 保留——身份钉住与保存密码是两件事。
///
/// r92 起它只是 [`trust_with_credential`] 的密码档薄壳：12+ 条既有用例从这里进，
/// 删掉它们只会让用例更吵，不会让代码更安全。
pub fn trust_with(
    root: &Path,
    target: &Target,
    fingerprint: &str,
    password: &str,
    persist_credential: bool,
    now_unix: i64,
) -> Result<ServerRecord, PairError> {
    trust_with_credential(
        root,
        target,
        fingerprint,
        &crate::credential::Credential::password(password),
        persist_credential,
        now_unix,
    )
}

/// 记下这台服务器：验过的指纹 + 封好的凭据。**唯一真正写信封的地方。**
///
/// 同一目标（host/port/user）再记一次 = **更新**：id 与创建时间保持不变，
/// 名字与凭据换新。但**指纹变了就拒绝**——那不是「更新」，是「换了台机器」，
/// 得由人先确认（删掉旧记录再重新信任），不能悄悄覆盖。
///
/// 信封里存的是「凭据原文」：密码档存 `Password`，私钥档存 `PrivateKeyPem`
/// （+ 有口令时存 `Passphrase`）。存私钥不是「多存一份秘密」——不存的话界面上的
/// 「在这台电脑记住登录资料」在私钥模式下会**静默不生效**，那比多一个加密文件糟。
pub fn trust_with_credential(
    root: &Path,
    target: &Target,
    fingerprint: &str,
    credential: &crate::credential::Credential,
    persist_credential: bool,
    now_unix: i64,
) -> Result<ServerRecord, PairError> {
    validate_target(target)?;
    let fingerprint = fingerprint.trim();
    if !fingerprint.starts_with("SHA256:") || fingerprint.len() < 12 {
        return Err(invalid("主机指纹必须是 SHA256: 开头的形状。"));
    }
    if !credential.is_usable() {
        return Err(invalid(match credential.kind() {
            crate::credential::CredentialKind::Password => "密码为空，没有保存任何记录。",
            crate::credential::CredentialKind::Key => "私钥内容为空，没有保存任何记录。",
        }));
    }
    let now = crate::pairing::rfc3339_micros(now_unix);

    let existing = find_by_target(root, target)?;
    let record = match existing {
        Some(record) if record.fingerprint != fingerprint => {
            return Err(PairError::new_pub(
                "ServerIdentityChanged",
                &format!(
                    "{} 的指纹与记录不一致（记录 {}，本次 {fingerprint}）。\
                     服务器可能重装过；确认无误后先删掉旧记录再重新信任。",
                    record.address(),
                    record.fingerprint
                ),
            ));
        }
        Some(record) => ServerRecord { name: record.name, updated_at: now, ..record },
        None => ServerRecord {
            id: crate::pairing::random_uuid_v4(),
            name: format!("{}@{}", target.user, target.host),
            host: target.host.clone(),
            port: target.port,
            user: target.user.clone(),
            fingerprint: fingerprint.to_string(),
            created_at: now.clone(),
            updated_at: now,
        },
    };

    let dir = server_dir(root, &record.id)?;
    std::fs::create_dir_all(&dir).map_err(|e| write_failed("创建服务器记录目录失败", &e))?;

    if persist_credential {
        // 凭据先落盘：反过来会留下「有记录、解不开密码」的坏状态。
        let binding = binding_of(&record);
        let mut payload = payload_of(&binding, credential);
        let sealed = dpapi::protect_with(&payload, binding.as_bytes());
        // 无论成败都清掉明文缓冲：`String` 的堆内存不归我们管，能清一次就清一次。
        unsafe { zero(payload.as_bytes_mut()) };
        let sealed = sealed?;
        write_json(
            &dir.join(CREDENTIAL_FILE),
            &json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.DeployCredential",
                "Protected": sealed,
            }),
        )?;
    } else {
        // 用户这次明确不要记住：把以前留下的信封删掉，别让文件继续替我们记着。
        let _ = std::fs::remove_file(dir.join(CREDENTIAL_FILE));
    }
    write_json(&dir.join(RECORD_FILE), &record.to_json())?;
    Ok(record)
}

/// 登记一条从**恢复包**导入的服务器记录（r94）。
///
/// 与 [`trust_with_credential`] 的差别只有两条：
/// - 名字来自恢复包（不是 `user@host`）；
/// - 凭据可以是 `None`：包里没带登录资料时，只登记身份，**不动**这台服务器上
///   已经存在的信封（导入一份不含凭据的包，不该把原来的密码删掉）。
///
/// 安全判据与信任路径相同：同一目标 + 不同指纹 = 拒绝，不悄悄覆盖。
pub fn register_recovered(
    root: &Path,
    name: &str,
    target: &Target,
    fingerprint: &str,
    credential: Option<&crate::credential::Credential>,
    now_unix: i64,
) -> Result<ServerRecord, PairError> {
    validate_target(target)?;
    let fingerprint = fingerprint.trim();
    if !fingerprint.starts_with("SHA256:") || fingerprint.len() < 12 {
        return Err(invalid("恢复包里的主机指纹不是 SHA256: 开头的形状。"));
    }
    let name = name.trim();
    if name.chars().count() > 128 || name.chars().any(|ch| ch.is_control()) {
        return Err(invalid("恢复包里的服务器名称无效。"));
    }
    if let Some(credential) = credential {
        if !credential.is_usable() {
            return Err(invalid(match credential.kind() {
                crate::credential::CredentialKind::Password => {
                    "恢复包里的服务器密码为空，没有登记。"
                }
                crate::credential::CredentialKind::Key => {
                    "恢复包里的 SSH 私钥内容为空，没有登记。"
                }
            }));
        }
    }
    let now = crate::pairing::rfc3339_micros(now_unix);
    let existing = find_by_target(root, target)?;
    let record = match existing {
        Some(record) if record.fingerprint != fingerprint => {
            return Err(PairError::new_pub(
                "ServerIdentityChanged",
                &format!(
                    "{} 的指纹与恢复包不一致（记录 {}，恢复包 {fingerprint}）。\
                     服务器可能重装过；确认无误后先删掉旧记录再导入。",
                    record.address(),
                    record.fingerprint
                ),
            ));
        }
        Some(record) => ServerRecord {
            name: if name.is_empty() {
                record.name
            } else {
                name.to_string()
            },
            updated_at: now,
            ..record
        },
        None => ServerRecord {
            id: crate::pairing::random_uuid_v4(),
            name: if name.is_empty() {
                format!("{}@{}", target.user, target.host)
            } else {
                name.to_string()
            },
            host: target.host.clone(),
            port: target.port,
            user: target.user.clone(),
            fingerprint: fingerprint.to_string(),
            created_at: now.clone(),
            updated_at: now,
        },
    };

    let dir = server_dir(root, &record.id)?;
    std::fs::create_dir_all(&dir).map_err(|e| write_failed("创建服务器记录目录失败", &e))?;
    if let Some(credential) = credential {
        let binding = binding_of(&record);
        let mut payload = payload_of(&binding, credential);
        let sealed = dpapi::protect_with(&payload, binding.as_bytes());
        unsafe { zero(payload.as_bytes_mut()) };
        let sealed = sealed?;
        write_json(
            &dir.join(CREDENTIAL_FILE),
            &json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.DeployCredential",
                "Protected": sealed,
            }),
        )?;
    }
    write_json(&dir.join(RECORD_FILE), &record.to_json())?;
    Ok(record)
}

/// 信封里那一层的明文（DPAPI 之前）。**只有这一个地方拼这个形状**。
///
/// 与 `deploycred::payload_of` 是同一套键名：两个信封的打开方式一致，
/// 「换个地方存」不该让格式也跟着换。
fn payload_of(binding: &str, credential: &crate::credential::Credential) -> String {
    let mut map = serde_json::Map::new();
    map.insert("Binding".to_string(), Value::String(binding.to_string()));
    map.insert(
        "Kind".to_string(),
        Value::String(credential.kind().as_str().to_string()),
    );
    match credential {
        crate::credential::Credential::Password(secret) => {
            map.insert(
                "Password".to_string(),
                Value::String(secret.expose().to_string()),
            );
        }
        crate::credential::Credential::Key { pem, passphrase, .. } => {
            map.insert(
                "PrivateKeyPem".to_string(),
                Value::String(pem.expose().to_string()),
            );
            if let Some(passphrase) = passphrase {
                map.insert(
                    "Passphrase".to_string(),
                    Value::String(passphrase.expose().to_string()),
                );
            }
        }
    }
    Value::Object(map).to_string()
}

/// 改显示名：**只动 `Name` 与 `UpdatedAtUtc`**，不碰地址、指纹与凭据。
///
/// 凭据信封的熵（[`binding_of`]）不含 `Name`，所以改名不会让已保存的密码失效——
/// 任何「改个名字就要重新输密码」的行为都是设计错误。名字只在本机显示，
/// 不改服务器上的任何东西。
pub fn rename(
    root: &Path,
    id: &str,
    name: &str,
    now_unix: i64,
) -> Result<ServerRecord, PairError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid("服务器名称不能为空。"));
    }
    if name.chars().count() > 120 {
        return Err(invalid("服务器名称最多 120 个字。"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("服务器名称不能包含换行、制表符等控制字符。"));
    }
    let dir = server_dir(root, id)?;
    let path = dir.join(RECORD_FILE);
    let mut record = ServerRecord::from_json(&read_json(&path)?)?;
    // 记录里的 Id 必须与目录名一致：不一致时按 id 改名会写到另一条记录上。
    if record.id != id {
        return Err(invalid("服务器记录里的标识与文件名不一致。"));
    }
    if record.name == name {
        return Ok(record);
    }
    record.name = name.to_string();
    record.updated_at = crate::pairing::rfc3339_micros(now_unix);
    write_json(&path, &record.to_json())?;
    Ok(record)
}

/// 读出这条记录封着的凭据。
///
/// 两种失败要分开说：
/// - 信封解不开（换电脑/换账户/文件损坏）→ `CredentialUnavailable`，用户得重新输一次；
/// - 解开了但 `Binding` 对不上（记录被改过）→ `CredentialBindingChanged`，
///   这是「有人动过记录」，不能当成普通的「密码失效」。
///
/// 旧信封（内层没有 `Kind`）一律读成密码：历史行为，零迁移。
pub fn credential(
    root: &Path,
    record: &ServerRecord,
) -> Result<crate::credential::StoredCredential, PairError> {
    let dir = server_dir(root, &record.id)?;
    let envelope = read_json(&dir.join(CREDENTIAL_FILE)).map_err(|_| {
        PairError::new_pub("CredentialUnavailable", "这条服务器记录没有保存登录凭据，请重新输入一次。")
    })?;
    let sealed = envelope
        .get("Protected")
        .and_then(Value::as_str)
        .ok_or_else(|| PairError::new_pub("CredentialUnavailable", "登录凭据信封缺少内容。"))?;
    let binding = binding_of(record);
    let mut plain = dpapi::unprotect_with(sealed, binding.as_bytes())
        .map_err(|_| {
            PairError::new_pub(
                "CredentialUnavailable",
                "登录凭据无法解开（换了电脑或账户，或服务器身份已变化），请重新输入一次。",
            )
        })?
        .into_bytes();
    let value: Value = serde_json::from_slice(&plain).map_err(|_| {
        PairError::new_pub("CredentialUnavailable", "登录凭据的内容无法解析。")
    })?;
    let stored_binding = value.get("Binding").and_then(Value::as_str).unwrap_or("");
    let stored = read_payload(&value);
    let matched = stored_binding == binding && stored.is_usable();
    zero(&mut plain);
    if !matched {
        return Err(PairError::new_pub(
            "CredentialBindingChanged",
            "登录凭据与这条服务器记录不匹配（记录被改过？），请重新输入一次。",
        ));
    }
    Ok(stored)
}

/// 把信封里那一层明文读成凭据。与 [`payload_of`] 是同一个形状的两端。
fn read_payload(value: &Value) -> crate::credential::StoredCredential {
    use crate::credential::{CredentialKind, StoredCredential};
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    match CredentialKind::parse(&text("Kind")) {
        CredentialKind::Password => StoredCredential::password(text("Password")),
        CredentialKind::Key => {
            let passphrase = value
                .get("Passphrase")
                .and_then(Value::as_str)
                .filter(|item| !item.is_empty())
                .map(str::to_string);
            StoredCredential::key(text("PrivateKeyPem"), passphrase)
        }
    }
}

/// 全部记录，按名字排序。目录名不合规的跳过；名字合规但内容坏掉的**照实报错**——
/// 静默跳过会让人以为服务器记录丢了。
pub fn list(root: &Path) -> Result<Vec<ServerRecord>, PairError> {
    let dir = servers_dir(root);
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(invalid(&format!("读取服务器记录目录失败：{e}"))),
    };
    for entry in entries {
        let entry = entry.map_err(|e| invalid(&format!("读取服务器记录失败：{e}")))?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if !is_server_id(&name) {
            continue;
        }
        let path = entry.path().join(RECORD_FILE);
        if !path.exists() {
            // 只有凭据、没有记录：上次写到一半被打断。跳过，别把半个东西报成一条服务器。
            continue;
        }
        out.push(ServerRecord::from_json(&read_json(&path)?)?);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(out)
}

pub fn find_by_target(
    root: &Path,
    target: &Target,
) -> Result<Option<ServerRecord>, PairError> {
    Ok(list(root)?.into_iter().find(|record| {
        record.host.eq_ignore_ascii_case(&target.host)
            && record.port == target.port
            && record.user == target.user
    }))
}

/// 这条记录有没有长期保存的登录资料。**只读**（「删除本机部署资料」的预览用）。
///
/// 只看「文件在不在」：不试着解开它。预览不该为了回答一个是非题去碰 DPAPI，
/// 也不该因为「换过电脑所以解不开」就把一份确实还躺在磁盘上的凭据说成不存在。
pub fn has_saved_credential(root: &Path, id: &str) -> bool {
    match server_dir(root, id) {
        Ok(dir) => dir.join(CREDENTIAL_FILE).is_file(),
        Err(_) => false,
    }
}

/// 删掉一条记录（连同凭据）。只用于「用户明确要删」与「指纹变了之后重来」。
pub fn remove(root: &Path, id: &str) -> Result<(), PairError> {
    let dir = server_dir(root, id)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(write_failed("删除服务器记录失败", &e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-servers-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const FP: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn target() -> Target {
        Target::new("203.0.113.10", 22, "root")
    }

    #[test]
    fn a_trusted_server_round_trips_its_credential() {
        let root = temp_root("roundtrip");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).expect("应当能记住");
        assert!(is_server_id(&record.id));
        assert_eq!(record.name, "root@203.0.113.10");
        assert_eq!(credential(&root, &record).unwrap().password_text(), "s3cret");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：恢复包导入用包里的名字，且**没有凭据也能登记**（只登记身份）。
    #[test]
    fn a_recovered_server_keeps_its_name_and_can_have_no_credential() {
        let root = temp_root("recovered-name");
        let record = register_recovered(
            &root,
            "自建 · 恢复的服务器",
            &target(),
            FP,
            None,
            1_700_000_000,
        )
        .expect("应当能登记");
        assert_eq!(record.name, "自建 · 恢复的服务器");
        assert_eq!(record.fingerprint, FP);
        assert!(credential(&root, &record).is_err(), "没带凭据就不该有信封");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：包里带了凭据就写进 DPAPI 信封；重复导入同一目标只更新名字与凭据。
    #[test]
    fn a_recovered_server_round_trips_its_credential_and_upserts() {
        let root = temp_root("recovered-cred");
        let secret = crate::credential::Credential::password("s3cret");
        let first = register_recovered(
            &root,
            "恢复一",
            &target(),
            FP,
            Some(&secret),
            1_700_000_000,
        )
        .expect("应当能登记");
        assert_eq!(credential(&root, &first).unwrap().password_text(), "s3cret");
        let second = register_recovered(
            &root,
            "恢复二",
            &target(),
            FP,
            Some(&crate::credential::Credential::password("s3cret2")),
            1_700_000_001,
        )
        .expect("同一目标应更新");
        assert_eq!(second.id, first.id, "同一目标必须复用同一条记录");
        assert_eq!(second.name, "恢复二");
        assert_eq!(credential(&root, &second).unwrap().password_text(), "s3cret2");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：不含凭据的恢复包**不许**把已有的信封删掉。
    #[test]
    fn a_recovery_package_without_a_credential_keeps_the_existing_envelope() {
        let root = temp_root("recovered-keep");
        let trusted = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let recovered = register_recovered(
            &root,
            "恢复的名字",
            &target(),
            FP,
            None,
            1_700_000_002,
        )
        .unwrap();
        assert_eq!(recovered.id, trusted.id);
        assert_eq!(recovered.name, "恢复的名字");
        assert_eq!(
            credential(&root, &recovered).unwrap().password_text(),
            "s3cret",
            "导入不含凭据的包不该把原来记住的密码删掉"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：同一目标、不同指纹 = 拒绝（恢复包不能悄悄换掉服务器身份）。
    #[test]
    fn a_recovered_server_refuses_a_different_fingerprint_for_the_same_target() {
        let root = temp_root("recovered-mismatch");
        trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let other = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let error = register_recovered(&root, "换过的", &target(), other, None, 1_700_000_001)
            .expect_err("指纹不一致必须拒绝");
        assert_eq!(error.code, "ServerIdentityChanged", "{error:?}");
        assert!(error.message.contains("不一致"), "{}", error.message);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r94：包里的指纹/名字形状不对在写任何文件之前拒绝。
    #[test]
    fn a_recovered_server_is_validated_before_writing() {
        let root = temp_root("recovered-invalid");
        let error = register_recovered(&root, "名字", &target(), "not-a-fingerprint", None, 1)
            .expect_err("指纹形状不对");
        assert!(error.message.contains("SHA256"), "{}", error.message);
        let error = register_recovered(&root, "带\u{0007}控制字符", &target(), FP, None, 1)
            .expect_err("名字含控制字符");
        assert!(error.message.contains("名称"), "{}", error.message);
        assert!(list(&root).unwrap().is_empty(), "拒收不许留下记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_public_record_never_contains_the_password() {
        let root = temp_root("nopass");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let text = std::fs::read_to_string(
            server_dir(&root, &record.id).unwrap().join(RECORD_FILE),
        )
        .unwrap();
        assert!(!text.contains("s3cret"), "公开记录里出现了密码：{text}");
        assert!(text.contains(FP), "指纹必须在公开记录里：{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 最关键的一条：凭据不能挪用到另一台服务器。
    ///
    /// 做法是把记录里的 host 改掉（模拟「有人把记录文件复制过去改了一行」），
    /// 再用改过的记录去解同一份信封——必须解不开。
    #[test]
    fn a_credential_cannot_be_replayed_against_another_identity() {
        let root = temp_root("replay");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let mut moved = record.clone();
        moved.host = "198.51.100.7".to_string();
        // `StoredCredential` 刻意不派生 `Debug`（里面是秘密），不能用 `expect_err`。
        let error = match credential(&root, &moved) {
            Err(error) => error,
            Ok(_) => panic!("换了身份必须解不开"),
        };
        assert_eq!(error.code, "CredentialUnavailable", "{error:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn trusting_the_same_target_again_reuses_the_record_and_replaces_the_secret() {
        let root = temp_root("upsert");
        let first = trust(&root, &target(), FP, "old", 1_700_000_000).unwrap();
        let second = trust(&root, &target(), FP, "new", 1_700_000_100).unwrap();
        assert_eq!(first.id, second.id, "同一台服务器不该产生第二条记录");
        assert_eq!(first.created_at, second.created_at, "创建时间保持不变");
        assert_ne!(first.updated_at, second.updated_at, "更新时间要变");
        assert_eq!(credential(&root, &second).unwrap().password_text(), "new");
        assert_eq!(list(&root).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_changed_host_key_is_refused_instead_of_overwritten() {
        let root = temp_root("changed");
        trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let other = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let error = trust(&root, &target(), other, "s3cret", 1_700_000_100)
            .expect_err("指纹变了必须拒绝");
        assert_eq!(error.code, "ServerIdentityChanged", "{error:?}");
        assert_eq!(list(&root).unwrap()[0].fingerprint, FP, "旧记录不能被改掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_invalid_id_is_never_used_as_a_path() {
        let root = temp_root("id");
        assert!(server_dir(&root, "..\\..\\windows").is_err());
        assert!(server_dir(&root, "9F1C2A44-0B7D-4C1E-9A2B-3C4D5E6F7A8B").is_err(), "大写也不收");
        assert!(remove(&root, "../../etc").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_with_only_a_credential_is_not_reported_as_a_server() {
        let root = temp_root("orphan");
        let dir = servers_dir(&root).join("9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CREDENTIAL_FILE), "{}").unwrap();
        assert!(list(&root).unwrap().is_empty(), "半个东西不能报成一条服务器");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_record_is_reported_not_silently_skipped() {
        let root = temp_root("corrupt");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        std::fs::write(
            server_dir(&root, &record.id).unwrap().join(RECORD_FILE),
            "{ not json",
        )
        .unwrap();
        let error = list(&root).expect_err("坏记录必须报错");
        assert_eq!(error.code, "ServerRecordInvalid", "{error:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_credential_says_so_instead_of_panicking() {
        let root = temp_root("missing");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        std::fs::remove_file(server_dir(&root, &record.id).unwrap().join(CREDENTIAL_FILE)).unwrap();
        let error = match credential(&root, &record) {
            Err(error) => error,
            Ok(_) => panic!("没有凭据必须报错"),
        };
        assert_eq!(error.code, "CredentialUnavailable", "{error:?}");
        assert!(error.message.contains("重新输入"), "{}", error.message);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 改名只动显示名：地址、指纹、创建时间、**凭据**都不许变。
    #[test]
    fn renaming_changes_only_the_display_name_and_keeps_the_credential() {
        let root = temp_root("rename");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let renamed = rename(&root, &record.id, "  东京节点  ", 1_700_003_600).unwrap();
        assert_eq!(renamed.name, "东京节点", "首尾空白要吃掉");
        assert_eq!(renamed.host, record.host);
        assert_eq!(renamed.fingerprint, record.fingerprint);
        assert_eq!(renamed.created_at, record.created_at, "创建时间不变");
        assert_ne!(renamed.updated_at, record.updated_at, "更新时间要变");
        assert_eq!(
            credential(&root, &renamed).unwrap().password_text(),
            "s3cret",
            "改名不许让密码失效"
        );
        assert_eq!(list(&root).unwrap()[0].name, "东京节点");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_empty_or_control_name_is_refused_and_changes_nothing() {
        let root = temp_root("rename-bad");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        for bad in ["", "   ", "a\nb", "a\tb"] {
            let error = rename(&root, &record.id, bad, 1_700_003_600).expect_err("非法名称必须拒绝");
            assert_eq!(error.code, "ServerRecordInvalid", "{bad:?} {error:?}");
        }
        let too_long = "名".repeat(121);
        assert!(rename(&root, &record.id, &too_long, 1_700_003_600).is_err());
        assert_eq!(list(&root).unwrap()[0].name, record.name, "拒绝时记录不能被改");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn renaming_an_unknown_record_says_it_is_missing() {
        let root = temp_root("rename-missing");
        let error = rename(
            &root,
            "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "随便",
            1_700_000_000,
        )
        .expect_err("没有这条记录必须报错");
        assert_eq!(error.code, "ServerRecordNotFound", "{error:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 删除记录要连凭据一起删；重复删同一条不算错（幂等）。
    #[test]
    fn removing_a_record_deletes_its_credential_and_is_idempotent() {
        let root = temp_root("remove");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        let dir = server_dir(&root, &record.id).unwrap();
        assert!(dir.is_dir());
        remove(&root, &record.id).unwrap();
        assert!(!dir.exists(), "目录与凭据必须一起删掉");
        assert!(list(&root).unwrap().is_empty());
        remove(&root, &record.id).expect("重复删除不应报错");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 「在这台电脑记住登录资料」不勾时：记录（身份）照写，密码一个字都不落盘。
    ///
    /// 这条不测就等于没做：无条件写信封是旧行为，而旧行为**看起来一切正常**——
    /// 只有真去读那个文件才发现密码还在。
    #[test]
    fn not_remembering_keeps_the_identity_but_never_writes_the_password() {
        let root = temp_root("nopersist");
        let record = trust_with(&root, &target(), FP, "s3cret", false, 1_700_000_000)
            .expect("身份仍要记下来");
        let dir = server_dir(&root, &record.id).unwrap();
        assert!(!dir.join(CREDENTIAL_FILE).exists(), "不许写出凭据信封");
        assert!(dir.join(RECORD_FILE).exists(), "身份记录必须留着（指纹要钉住）");
        assert_eq!(list(&root).unwrap().len(), 1);
        assert_eq!(
            match credential(&root, &record) {
                Err(error) => error.code,
                Ok(_) => panic!("没有信封时读不出密码"),
            },
            "CredentialUnavailable"
        );

        // 以前记住过、这次说不要：旧信封必须被删掉，否则界面在骗人。
        let again = trust(&root, &target(), FP, "s3cret", 1_700_000_100).unwrap();
        assert!(dir.join(CREDENTIAL_FILE).exists());
        trust_with(&root, &target(), FP, "s3cret", false, 1_700_000_200).unwrap();
        assert_eq!(again.id, record.id, "同一台服务器不该多出记录");
        assert!(!dir.join(CREDENTIAL_FILE).exists(), "不记了就要把旧信封删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 旧信封（内层没有 `Kind`）：读成密码。历史行为，零迁移。
    #[test]
    fn a_legacy_envelope_without_kind_reads_as_a_password() {
        let root = temp_root("legacy");
        let record = trust(&root, &target(), FP, "s3cret", 1_700_000_000).unwrap();
        // 把信封改写成「旧格式」：解不开原信封，只能重新封一份没有 Kind 的。
        let binding = binding_of(&record);
        let mut payload = json!({ "Binding": binding, "Password": "s3cret" }).to_string();
        let sealed = dpapi::protect_with(&payload, binding.as_bytes()).unwrap();
        unsafe { zero(payload.as_bytes_mut()) };
        std::fs::write(
            server_dir(&root, &record.id).unwrap().join(CREDENTIAL_FILE),
            json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.DeployCredential",
                "Protected": sealed,
            })
            .to_string(),
        )
        .unwrap();
        let stored = credential(&root, &record).expect("旧信封必须还能读");
        assert_eq!(stored.kind(), crate::credential::CredentialKind::Password);
        assert_eq!(stored.password_text(), "s3cret");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 私钥也能长期记住：存进去、读出来、能解析成可用凭据。
    ///
    /// 不存的话，界面上的「在这台电脑记住登录资料」在私钥模式下会**静默不生效**
    /// ——用户勾了、界面说记住了、下次却还要再选一次文件。
    #[test]
    fn a_key_credential_round_trips_through_the_long_term_envelope() {
        let fixture = crate::ssh::test_support::key_fixture();
        let root = temp_root("keyfile");
        let key_credential = crate::credential::Credential::from_key_pem(&fixture.pem, None)
            .expect("明文钥应当能解析");
        let record =
            trust_with_credential(&root, &target(), FP, &key_credential, true, 1_700_000_000)
                .expect("私钥也要能记住");

        let stored = credential(&root, &record).expect("读回来");
        assert_eq!(stored.kind(), crate::credential::CredentialKind::Key);
        assert_eq!(stored.pem_text(), fixture.pem);
        let restored = stored.into_credential().expect("私钥应当仍能解析");
        assert!(restored.is_usable());

        // 公开记录里一个字节的私钥都没有；指纹照旧在。
        let text =
            std::fs::read_to_string(server_dir(&root, &record.id).unwrap().join(RECORD_FILE))
                .unwrap();
        assert!(!text.contains("BEGIN"), "公开记录里出现了私钥：{text}");
        assert!(!text.contains("PRIVATE KEY"), "公开记录里出现了私钥：{text}");
        assert!(text.contains(FP), "指纹必须还在公开记录里：{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 说不要记住：`record.json` 还在（身份要钉住），私钥一个字都不落盘。
    #[test]
    fn not_remembering_never_writes_the_key() {
        let fixture = crate::ssh::test_support::key_fixture();
        let root = temp_root("nokey");
        let credential = crate::credential::Credential::from_key_pem(&fixture.pem, None).unwrap();
        let record = trust_with_credential(&root, &target(), FP, &credential, false, 1_700_000_000)
            .expect("身份仍要记下来");
        let dir = server_dir(&root, &record.id).unwrap();
        assert!(!dir.join(CREDENTIAL_FILE).exists(), "不许写出凭据信封");
        assert!(dir.join(RECORD_FILE).exists(), "身份记录必须留着（指纹要钉住）");
        for path in [dir.join(CREDENTIAL_FILE), dir.join(RECORD_FILE)] {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(
                !text.contains("BEGIN OPENSSH PRIVATE KEY"),
                "私钥泄漏到了 {}：{text}",
                path.display()
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `has_saved_credential` 语义不变：只看文件在不在，不解包。
    #[test]
    fn has_saved_credential_still_only_asks_whether_the_file_exists() {
        let fixture = crate::ssh::test_support::key_fixture();
        let root = temp_root("hassaved");
        let credential = crate::credential::Credential::from_key_pem(&fixture.pem, None).unwrap();
        let record = trust_with_credential(&root, &target(), FP, &credential, true, 1_700_000_000)
            .unwrap();
        assert!(has_saved_credential(&root, &record.id), "存了私钥也算「有登录资料」");
        std::fs::remove_file(server_dir(&root, &record.id).unwrap().join(CREDENTIAL_FILE)).unwrap();
        assert!(!has_saved_credential(&root, &record.id));
        let _ = std::fs::remove_dir_all(&root);
    }
}
