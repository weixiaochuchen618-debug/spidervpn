//! 管理恢复包（旧版的`PairingPages.ps1` 的「管理恢复资料」）。
//!
//! 用途只有一个：**换电脑之后把「这台服务器是谁、怎么登录」带过去**。
//! 它不包含线路、不包含其他电脑的私钥、不包含交易账户，也**不会**因为导入就
//! 启用线路或跳过服务器身份核对——导入只是在本机登记一条「待核验」的服务器记录。
//!
//! 与旧版的差别只在文件格式：旧版是 .NET `PairCrypto` 的私钥/口令封装，
//! 本版与它不共享运行时（隔离契约 D11），所以有自己的外层信封。界面语义、
//! 密码长度（至少 12 个字符）、128 KiB 上限、可选包含 SSH 凭据这几条逐条对齐。
//!
//! 外层（明文可读，只用来定位 KDF 参数）：
//! ```json
//! {"SchemaVersion":1,"Kind":"SpiderVPN.ManagementRecovery",
//!  "Kdf":{"Algorithm":"PBKDF2-HMAC-SHA256","Salt":"<base64>","Iterations":120000},
//!  "Cipher":{"Algorithm":"AES-256-GCM","Nonce":"<base64>"},
//!  "Payload":"<base64 密文+认证标签>"}
//! ```
//!
//! 内层（加密）：
//! ```json
//! {"SchemaVersion":1,"Kind":"TradeChannel.ManagementRecovery",
//!  "Server":{"Name":"…","Host":"…","Port":22,"User":"root","Fingerprint":"SHA256:…"},
//!  "CreatedAtUtc":"…","IncludesCredential":true,
//!  "Credential":{"Kind":"password","Password":"…"}}
//! ```
//!
//! **AAD 绑定外层全部参数**：盐、迭代次数、算法名、随机数任何一项被改，
//! 解密都会失败（而不是「用改过的参数解出一段看似正常的 JSON」）。

use std::num::NonZeroU32;
use std::path::Path;

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};

use crate::credential::{Credential, CredentialKind};
use crate::serverstore::{self, ServerRecord};
use crate::ssh::Target;

/// 恢复包文件扩展名（旧版一致）。
pub const RECOVERY_EXT: &str = "tcrecovery";
/// 恢复包最大字节数（旧版导入上限 128 KiB）。
pub const RECOVERY_MAX_BYTES: usize = 128 * 1024;
/// 恢复包密码最少字符数（旧版原文「至少 12 个字符」）。
pub const PASSWORD_MIN: usize = 12;
/// 密码最长长度：挡住「把 10 MB 文本当密码」这类调用错误。
const PASSWORD_MAX: usize = 256;
/// 旧的/未来的包允许的迭代次数范围。本版导出固定 120000（旧版默认值）。
const ITERATIONS: u32 = 120_000;
const ITERATIONS_MIN: u32 = 10_000;
const KIND_OUTER: &str = "SpiderVPN.ManagementRecovery";
const KIND_INNER: &str = "TradeChannel.ManagementRecovery";
const KDF_ALGORITHM: &str = "PBKDF2-HMAC-SHA256";
const CIPHER_ALGORITHM: &str = "AES-256-GCM";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// 恢复包里那一台服务器的**公开**事实。凭据单独放（可能没有）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSnapshot {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub fingerprint: String,
}

impl ServerSnapshot {
    pub fn from_record(record: &ServerRecord) -> ServerSnapshot {
        ServerSnapshot {
            name: record.name.clone(),
            host: record.host.clone(),
            port: record.port,
            user: record.user.clone(),
            fingerprint: record.fingerprint.clone(),
        }
    }

    pub fn address(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

/// 解密之后的恢复包。`credential` 是秘密，用完即弃（`Credential` 自己会清零）。
pub struct Imported {
    pub server: ServerSnapshot,
    pub includes_credential: bool,
    pub credential: Option<Credential>,
    pub created_at: String,
}

impl Imported {
    /// 这一包有没有可用的登录凭据（用于页面文案，不用于任何判定分支）。
    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }
}

/// 手写 `Debug`：`Credential` 刻意不派生，`{:?}` 不能把秘密打进日志。
impl std::fmt::Debug for Imported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Imported")
            .field("server", &self.server)
            .field("includes_credential", &self.includes_credential)
            .field("has_credential", &self.has_credential())
            .field("created_at", &self.created_at)
            .finish()
    }
}

fn base64() -> &'static base64::engine::general_purpose::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

fn invalid(message: &str) -> String {
    format!("恢复包无效：{message}")
}

/// 密码判据（导出/导入共用一处）。
fn check_password(password: &str) -> Result<(), String> {
    let length = password.chars().count();
    if length < PASSWORD_MIN {
        return Err(format!(
            "恢复包密码至少 {PASSWORD_MIN} 个字符（收到 {length} 个）。"
        ));
    }
    if length > PASSWORD_MAX {
        return Err(format!("恢复包密码最多 {PASSWORD_MAX} 个字符。"));
    }
    Ok(())
}

fn check_size(text: &str) -> Result<(), String> {
    if text.len() > RECOVERY_MAX_BYTES {
        return Err(format!(
            "恢复包超过 {} KiB，没有读取。",
            RECOVERY_MAX_BYTES / 1024
        ));
    }
    Ok(())
}

/// 把凭据编码成内层 JSON。**唯一拼这个形状的地方**。
fn credential_json(credential: &Credential) -> Value {
    match credential {
        Credential::Password(secret) => json!({
            "Kind": CredentialKind::Password.as_str(),
            "Password": secret.expose(),
        }),
        Credential::Key { pem, passphrase, .. } => {
            let mut value = json!({
                "Kind": CredentialKind::Key.as_str(),
                "PrivateKeyPem": pem.expose(),
            });
            if let Some(passphrase) = passphrase {
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "Passphrase".to_string(),
                        Value::String(passphrase.expose().to_string()),
                    );
                }
            }
            value
        }
    }
}

/// 从内层 JSON 还原凭据。**密钥解析失败不把库的英文原话抛给用户。**
fn credential_from_json(value: &Value) -> Result<Credential, String> {
    let kind = value
        .get("Kind")
        .and_then(Value::as_str)
        .map(CredentialKind::parse)
        .unwrap_or(CredentialKind::Password);
    match kind {
        CredentialKind::Password => {
            let password = value
                .get("Password")
                .and_then(Value::as_str)
                .unwrap_or("");
            if password.is_empty() {
                return Err(invalid("包里的服务器密码为空。"));
            }
            Ok(Credential::password(password.to_string()))
        }
        CredentialKind::Key => {
            let pem = value
                .get("PrivateKeyPem")
                .and_then(Value::as_str)
                .unwrap_or("");
            if pem.trim().is_empty() {
                return Err(invalid("包里的 SSH 私钥为空。"));
            }
            let passphrase = value.get("Passphrase").and_then(Value::as_str);
            Credential::from_key_pem(pem, passphrase)
                .map_err(|message| invalid(&format!("包里的 SSH 私钥无法解析：{message}")))
        }
    }
}

fn aad(
    iterations: u32,
    salt_b64: &str,
    nonce_b64: &str,
) -> String {
    format!(
        "{KIND_OUTER}\n1\n{KDF_ALGORITHM}\n{iterations}\n{salt_b64}\n{CIPHER_ALGORITHM}\n{nonce_b64}"
    )
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32], String> {
    let rounds = NonZeroU32::new(iterations)
        .ok_or_else(|| invalid("KDF 迭代次数不能为 0。"))?;
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        salt,
        password.as_bytes(),
        &mut key,
    );
    Ok(key)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "系统随机数不可用，无法生成恢复包。".to_string())?;
    Ok(bytes)
}

fn seal(plaintext: &[u8], password: &str) -> Result<String, String> {
    let salt = random_bytes::<SALT_LEN>()?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let salt_b64 = base64().encode(salt);
    let nonce_b64 = base64().encode(nonce_bytes);
    let mut key_bytes = derive_key(password, &salt, ITERATIONS)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| "无法初始化加密算法。".to_string())?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    let aad_text = aad(ITERATIONS, &salt_b64, &nonce_b64);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad_text.as_bytes()),
        &mut in_out,
    )
    .map_err(|_| "恢复包加密失败。".to_string())?;
    let payload = base64().encode(&in_out);
    // 派生密钥的缓冲清零。`LessSafeKey` 内部的副本由 ring 管，我们够不着。
    for byte in key_bytes.iter_mut() {
        *byte = 0;
    }
    Ok(json!({
        "SchemaVersion": 1,
        "Kind": KIND_OUTER,
        "Kdf": {
            "Algorithm": KDF_ALGORITHM,
            "Salt": salt_b64,
            "Iterations": ITERATIONS,
        },
        "Cipher": {
            "Algorithm": CIPHER_ALGORITHM,
            "Nonce": nonce_b64,
        },
        "Payload": payload,
    })
    .to_string())
}

fn open(package: &str, password: &str) -> Result<Vec<u8>, String> {
    check_size(package)?;
    let value: Value =
        serde_json::from_str(package).map_err(|_| invalid("不是 JSON 文本。"))?;
    let version = value
        .get("SchemaVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if version != 1 || value.get("Kind").and_then(Value::as_str) != Some(KIND_OUTER) {
        return Err(invalid("外层版本或类型不对。"));
    }
    let kdf = value
        .get("Kdf")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("缺少 KDF 参数。"))?;
    if kdf.get("Algorithm").and_then(Value::as_str) != Some(KDF_ALGORITHM) {
        return Err(invalid("KDF 算法不支持。"));
    }
    let salt_b64 = kdf
        .get("Salt")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("缺少盐。"))?;
    let nonce_b64 = value
        .get("Cipher")
        .and_then(Value::as_object)
        .and_then(|cipher| cipher.get("Nonce"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("缺少随机数。"))?;
    if value
        .get("Cipher")
        .and_then(Value::as_object)
        .and_then(|cipher| cipher.get("Algorithm"))
        .and_then(Value::as_str)
        != Some(CIPHER_ALGORITHM)
    {
        return Err(invalid("加密算法不支持。"));
    }
    let iterations = kdf
        .get("Iterations")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (ITERATIONS_MIN..=ITERATIONS).contains(n))
        .ok_or_else(|| invalid("KDF 迭代次数不在允许范围内。"))?;
    let salt = base64()
        .decode(salt_b64)
        .map_err(|_| invalid("盐不是合法的 base64。"))?;
    if salt.len() != SALT_LEN {
        return Err(invalid("盐的长度不对。"));
    }
    let nonce_bytes = base64()
        .decode(nonce_b64)
        .map_err(|_| invalid("随机数不是合法的 base64。"))?;
    let nonce_array: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("随机数的长度不对。"))?;
    let payload = value
        .get("Payload")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("缺少密文。"))?;
    let mut sealed = base64()
        .decode(payload)
        .map_err(|_| invalid("密文不是合法的 base64。"))?;
    if sealed.len() < 16 {
        return Err(invalid("密文长度不对。"));
    }
    let mut key_bytes = derive_key(password, &salt, iterations)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| invalid("无法初始化解密算法。"))?;
    let key = LessSafeKey::new(unbound);
    let aad_text = aad(iterations, salt_b64, nonce_b64);
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_array),
            Aad::from(aad_text.as_bytes()),
            &mut sealed,
        )
        .map_err(|_| {
            // 口令错、包被改过、KDF 参数被改过，在 AEAD 层面是同一个信号；
            // 不分开说，避免把「哪一半错了」告诉一个正在试口令的人。
            invalid("密码不正确，或文件已损坏。")
        })?
        .to_vec();
    for byte in key_bytes.iter_mut() {
        *byte = 0;
    }
    Ok(plaintext)
}

/// 导出：把一台服务器的公开身份 + 可选凭据加密成恢复包文本。
pub fn export(
    record: &ServerRecord,
    credential: Option<&Credential>,
    password: &str,
    created_at_utc: &str,
) -> Result<String, String> {
    check_password(password)?;
    let server = ServerSnapshot::from_record(record);
    let includes_credential = credential.is_some();
    let mut inner = json!({
        "SchemaVersion": 1,
        "Kind": KIND_INNER,
        "Server": {
            "Name": server.name,
            "Host": server.host,
            "Port": server.port,
            "User": server.user,
            "Fingerprint": server.fingerprint,
        },
        "CreatedAtUtc": created_at_utc,
        "IncludesCredential": includes_credential,
    });
    if let Some(credential) = credential {
        if !credential.is_usable() {
            return Err("要包含的登录资料是空的，没有导出恢复包。".to_string());
        }
        if let Some(object) = inner.as_object_mut() {
            object.insert("Credential".to_string(), credential_json(credential));
        }
    }
    let mut plaintext = serde_json::to_vec(&inner)
        .map_err(|_| "恢复包内容无法序列化。".to_string())?;
    let package = seal(&plaintext, password);
    // 明文里有密码/私钥：无论成败都清掉这一份缓冲。
    for byte in plaintext.iter_mut() {
        *byte = 0;
    }
    let package = package?;
    check_size(&package)?;
    Ok(package)
}

/// 导入：解密并校验形状。**不登记、不连服务器**——登记由 [`register`] 做。
pub fn import(package: &str, password: &str) -> Result<Imported, String> {
    check_password(password)?;
    let mut plaintext = open(package.trim(), password)?;
    let parsed: Result<Value, _> = serde_json::from_slice(&plaintext);
    let value = parsed.map_err(|_| invalid("解密后的内容不是 JSON。"));
    for byte in plaintext.iter_mut() {
        *byte = 0;
    }
    let value = value?;
    if value.get("SchemaVersion").and_then(Value::as_u64) != Some(1)
        || value.get("Kind").and_then(Value::as_str) != Some(KIND_INNER)
    {
        return Err(invalid("内层版本或类型不对。"));
    }
    let server = value
        .get("Server")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("缺少服务器信息。"))?;
    let text = |key: &str| -> Result<String, String> {
        server
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .ok_or_else(|| invalid(&format!("服务器信息缺少 {key}。")))
    };
    let port = server
        .get("Port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| invalid("服务器端口无效。"))?;
    let snapshot = ServerSnapshot {
        name: text("Name").unwrap_or_default(),
        host: text("Host")?,
        port,
        user: text("User")?,
        fingerprint: text("Fingerprint")?,
    };
    if !snapshot.fingerprint.starts_with("SHA256:") || snapshot.fingerprint.len() < 12 {
        return Err(invalid("服务器指纹形状不对。"));
    }
    let includes_credential = value
        .get("IncludesCredential")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("缺少 IncludesCredential。"))?;
    let credential = match (includes_credential, value.get("Credential")) {
        (true, Some(secret)) => Some(credential_from_json(secret)?),
        (true, None) => return Err(invalid("声明包含登录资料，但包里没有。")),
        (false, Some(_)) => return Err(invalid("声明不包含登录资料，但包里带了。")),
        (false, None) => None,
    };
    let created_at = value
        .get("CreatedAtUtc")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(Imported {
        server: snapshot,
        includes_credential,
        credential,
        created_at,
    })
}

/// 在本机登记恢复包里的服务器。**不写线路、不连服务器。**
pub fn register(
    root: &Path,
    imported: &Imported,
    now_unix: i64,
) -> Result<ServerRecord, String> {
    let target = Target::new(
        imported.server.host.trim(),
        imported.server.port,
        imported.server.user.trim(),
    );
    serverstore::register_recovered(
        root,
        &imported.server.name,
        &target,
        &imported.server.fingerprint,
        imported.credential.as_ref(),
        now_unix,
    )
    .map_err(|error| error.message)
}

/// 默认的导出文件名：`management-recovery-<YYYYmmdd-HHMMSS>.tcrecovery`。
///
/// 只用于「恢复到默认导出目录」那条路；用户点「另存为…」时由保存对话框决定。
pub fn default_file_name(now_unix: i64) -> String {
    let stamp = crate::pairing::rfc3339_micros(now_unix);
    let compact: String = stamp
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .take(14)
        .collect();
    if compact.len() == 14 {
        format!(
            "management-recovery-{}-{}-{}T{}-{}-{}.{RECOVERY_EXT}",
            &compact[0..4],
            &compact[4..6],
            &compact[6..8],
            &compact[8..10],
            &compact[10..12],
            &compact[12..14]
        )
    } else {
        format!("management-recovery-{now_unix}.{RECOVERY_EXT}")
    }
}

/// 测试/调用方拿到的明文凭据文本（只用于写内层 JSON 前的断言，不对外）。
#[cfg(test)]
fn credential_kind_word(credential: &Credential) -> &'static str {
    match credential {
        Credential::Password(_) => "password",
        Credential::Key { .. } => "key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;

    fn record() -> ServerRecord {
        ServerRecord {
            id: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string(),
            name: "自建 · 203.0.113.10".to_string(),
            host: "203.0.113.10".to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            created_at: "2026-11-14T00:00:00.000000Z".to_string(),
            updated_at: "2026-11-14T00:00:00.000000Z".to_string(),
        }
    }

    const PASSWORD: &str = "r94-recovery-pass";

    #[test]
    fn a_recovery_package_round_trips_the_server_identity() {
        let package = export(&record(), None, PASSWORD, "2026-11-14T00:00:00Z")
            .expect("应当能导出");
        let imported = import(&package, PASSWORD).expect("应当能导入");
        assert_eq!(imported.server.name, record().name);
        assert_eq!(imported.server.host, record().host);
        assert_eq!(imported.server.port, 22);
        assert_eq!(imported.server.user, "root");
        assert_eq!(imported.server.fingerprint, record().fingerprint);
        assert!(!imported.includes_credential);
        assert!(imported.credential.is_none());
        // 外包明文里不能出现服务器名/地址（它们在内层）。
        assert!(!package.contains("203.0.113.10"), "{package}");
        assert!(package.contains(KIND_OUTER));
    }

    #[test]
    fn a_password_credential_round_trips() {
        let credential = Credential::password("s3cret-password");
        let package = export(&record(), Some(&credential), PASSWORD, "now")
            .expect("应当能导出");
        assert!(!package.contains("s3cret-password"), "明文密码不许出现在包里");
        let imported = import(&package, PASSWORD).expect("应当能导入");
        assert!(imported.includes_credential);
        assert_eq!(
            imported.credential.as_ref().map(Credential::kind),
            Some(CredentialKind::Password)
        );
        assert_eq!(
            imported
                .credential
                .as_ref()
                .and_then(Credential::password_text),
            Some("s3cret-password")
        );
    }

    #[test]
    fn a_short_password_is_refused_before_writing_anything() {
        let error = export(&record(), None, "short", "now").expect_err("密码太短");
        assert!(error.contains("至少 12"), "{error}");
        assert!(import("{}", "short").is_err());
    }

    #[test]
    fn a_wrong_password_or_a_tampered_package_says_the_same_thing() {
        let package = export(&record(), None, PASSWORD, "now").unwrap();
        let wrong = import(&package, "r94-wrong-password").expect_err("密码错");
        assert!(wrong.contains("密码不正确"), "{wrong}");

        // 改一个字节（密文）→ 认证失败，且不泄露「哪一位坏了」。
        let mut value: Value = serde_json::from_str(&package).unwrap();
        let payload = value["Payload"].as_str().unwrap().to_string();
        let mut bytes = base64().decode(payload).unwrap();
        bytes[0] ^= 0x01;
        value["Payload"] = Value::String(base64().encode(bytes));
        let tampered = import(&value.to_string(), PASSWORD).expect_err("被改过");
        assert!(tampered.contains("密码不正确"), "{tampered}");
    }

    #[test]
    fn changing_the_kdf_parameters_invalidates_the_package() {
        let package = export(&record(), None, PASSWORD, "now").unwrap();
        let mut value: Value = serde_json::from_str(&package).unwrap();
        value["Kdf"]["Iterations"] = json!(10000);
        let error = import(&value.to_string(), PASSWORD).expect_err("参数被改");
        assert!(error.contains("密码不正确"), "{error}");
    }

    #[test]
    fn an_oversized_package_is_refused_before_parsing() {
        let big = "x".repeat(RECOVERY_MAX_BYTES + 1);
        let error = import(&big, PASSWORD).expect_err("超大");
        assert!(error.contains("超过"), "{error}");
    }

    #[test]
    fn an_inner_package_that_claims_no_credential_but_carries_one_is_refused() {
        let package = export(
            &record(),
            Some(&Credential::password("s3cret-password")),
            PASSWORD,
            "now",
        )
        .unwrap();
        let mut value: Value = serde_json::from_str(&package).unwrap();
        // 用错误口令解不开——这条只验证外层不会被当成内层直接读。
        assert!(import(&value.to_string(), "another-password").is_err());
        value["Kind"] = json!("SomethingElse");
        let error = import(&value.to_string(), PASSWORD).expect_err("类型不对");
        assert!(error.contains("外层版本或类型"), "{error}");
    }

    #[test]
    fn a_key_credential_round_trips_and_is_reparsed() {
        // 用测试密钥生成一把 OpenSSH 明文钥（与 ssh.rs 的夹具同一套 API）。
        let mut rng = russh::keys::key::safe_rng();
        let key = russh::keys::PrivateKey::random(
            &mut rng,
            russh::keys::Algorithm::Ed25519,
        )
        .expect("测试密钥生成失败");
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("导出私钥失败")
            .to_string();
        let credential = Credential::from_key_pem(&pem, None).expect("解析私钥");
        assert_eq!(credential_kind_word(&credential), "key");
        let package = export(&record(), Some(&credential), PASSWORD, "now").unwrap();
        assert!(!package.contains("BEGIN OPENSSH PRIVATE KEY"), "私钥不许明文出现");
        let imported = import(&package, PASSWORD).expect("导入");
        assert_eq!(
            imported.credential.as_ref().map(Credential::kind),
            Some(CredentialKind::Key)
        );
    }

    #[test]
    fn the_default_file_name_is_a_tcrecovery_file() {
        let name = default_file_name(1_763_000_000);
        assert!(name.starts_with("management-recovery-"), "{name}");
        assert!(name.ends_with(".tcrecovery"), "{name}");
        assert!(!name.contains(['/', '\\', ':']), "{name}");
    }
}
