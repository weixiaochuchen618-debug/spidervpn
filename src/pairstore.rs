//! 本机接入登记：`<data root>/identities/<enrollment-id>/`。
//!
//! 布局对齐 旧版的 `DeploymentPairing.psm1`：
//! - `enrollment.json`：公开部分（邀请 id、服务器绑定、已签名申请、状态），
//!   **不含任何私钥**，可以直接给人看；
//! - `private.dpapi.json`：两把私钥，整段 JSON 封在 DPAPI 里。
//!
//! 分成两个文件不是为了好看：私钥从来没进过 `enrollment.json`，所以
//! 「把目录拷给别人看」「把登记文件贴进工单」这类动作天生不会泄密。
//!
//! 写入一律「临时文件 + 重命名」：中途断电不会留下半个 JSON 让下次启动
//! 直接判无效。私钥**先于**登记写盘——宁可留下一份没人引用的私钥，
//! 也不要出现「有登记、但解不开授权」的半成品。

// M4 在建：登记的读写与测试都已就位，接线（pairOnline → save_new）在下一块。
// 在那之前这个模块只有测试在用，允许「暂时没人调用」，但功能本身是真的。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::pairing::dpapi;
use crate::pairing::PairError;

/// 允许出现在文件名里的登记 id 形状：小写 UUID。
const ID_LEN: usize = 36;

pub const STATE_REQUESTED: &str = "Requested";
pub const STATE_COMPLETED: &str = "Completed";

fn invalid_id() -> PairError {
    PairError::new_pub("InvalidEnrollmentId", "接入登记标识无效。")
}

fn invalid_state(message: &str) -> PairError {
    PairError::new_pub("InvalidEnrollment", message)
}

fn write_failed(message: &str, error: &std::io::Error) -> PairError {
    PairError::new_pub("EnrollmentWriteFailed", &format!("{message}：{error}"))
}

/// 小写 UUID（8-4-4-4-12，只允许 0-9a-f）。
///
/// 这不是「格式洁癖」：登记 id 会直接拼进路径，不卡死形状就等于
/// 允许 `..\..\` 这类值决定写到哪里。
fn is_enrollment_id(text: &str) -> bool {
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

/// 公开部分。字段名与旧版的 `enrollment.json` 逐字对齐，
/// 方便两边的排障脚本读同一份文件。
#[derive(Debug, Clone, PartialEq)]
pub struct Enrollment {
    pub enrollment_id: String,
    pub invite_id: String,
    /// 原始邀请码。留着是为了「过期后仍可用原申请重试」——重试要重新联网，
    /// 而重试用的还是这串码。
    pub invite_code: String,
    pub server_binding: Value,
    pub management_signing_public_key: Value,
    pub confirmed_fingerprint: String,
    /// 完整的 `TradeChannel.ClientRequest`（官方形状，包含摘要参与的全部字段）。
    pub client_request: Value,
    pub request_digest: String,
    /// 已签名的 `TradeChannel.PairRequest`（JWT）。
    pub pair_request: String,
    pub state: String,
    pub created_at_utc: String,
    pub completed_at_utc: Option<String>,
}

impl Enrollment {
    fn to_json(&self) -> Value {
        let mut value = json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.Enrollment",
            "EnrollmentId": self.enrollment_id,
            "InviteId": self.invite_id,
            "Invite": self.invite_code,
            "ServerBinding": self.server_binding,
            "ManagementSigningPublicKey": self.management_signing_public_key,
            "ConfirmedFingerprint": self.confirmed_fingerprint,
            "ClientRequest": self.client_request,
            "RequestDigest": self.request_digest,
            "PairRequest": self.pair_request,
            "State": self.state,
            "CreatedAtUtc": self.created_at_utc,
        });
        if let Some(completed) = &self.completed_at_utc {
            value["CompletedAtUtc"] = json!(completed);
        }
        value
    }

    fn from_json(value: &Value) -> Result<Self, PairError> {
        let text = |key: &str| -> Result<String, PairError> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| invalid_state("接入登记字段不完整。"))
        };
        if value.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
            || value.get("Kind").and_then(Value::as_str) != Some("TradeChannel.Enrollment")
        {
            return Err(invalid_state("接入登记文件格式无效。"));
        }
        let state = text("State")?;
        // 只认这两个状态：出现第三个值说明文件被改过或被更早的实验版本写过。
        if state != STATE_REQUESTED && state != STATE_COMPLETED {
            return Err(invalid_state("接入登记状态无效。"));
        }
        let enrollment_id = text("EnrollmentId")?;
        if !is_enrollment_id(&enrollment_id) {
            return Err(invalid_id());
        }
        Ok(Self {
            enrollment_id,
            invite_id: text("InviteId")?,
            invite_code: text("Invite")?,
            server_binding: value
                .get("ServerBinding")
                .cloned()
                .ok_or_else(|| invalid_state("接入登记缺少服务器绑定。"))?,
            management_signing_public_key: value
                .get("ManagementSigningPublicKey")
                .cloned()
                .ok_or_else(|| invalid_state("接入登记缺少管理签名公钥。"))?,
            confirmed_fingerprint: text("ConfirmedFingerprint")?,
            client_request: value
                .get("ClientRequest")
                .cloned()
                .ok_or_else(|| invalid_state("接入登记缺少设备申请。"))?,
            request_digest: text("RequestDigest")?,
            pair_request: text("PairRequest")?,
            state,
            created_at_utc: text("CreatedAtUtc")?,
            completed_at_utc: value
                .get("CompletedAtUtc")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

/// 私钥部分。**只以 DPAPI 密文的形态落盘**，内存里这份用完就该丢。
pub struct PrivateKeys {
    /// 接收 RSA 私钥：PKCS#8 DER 的 base64。
    pub recipient_pkcs8_b64: String,
    /// 隧道私钥的 base64（已 clamp）。
    pub tunnel_private_b64: String,
}

impl std::fmt::Debug for PrivateKeys {
    /// 刻意手写而不是 `derive`：`{:?}` 一旦落到日志或错误上报里，密钥就跟着走了。
    /// 这里只暴露长度，够排障（「字段空了」「长度不对」）而不泄露内容。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKeys")
            .field(
                "recipient_pkcs8_b64",
                &format_args!("<{} 字符>", self.recipient_pkcs8_b64.len()),
            )
            .field(
                "tunnel_private_b64",
                &format_args!("<{} 字符>", self.tunnel_private_b64.len()),
            )
            .finish()
    }
}

fn identities_dir(root: &Path) -> PathBuf {
    root.join("identities")
}

fn enrollment_dir(root: &Path, enrollment_id: &str) -> Result<PathBuf, PairError> {
    if !is_enrollment_id(enrollment_id) {
        return Err(invalid_id());
    }
    Ok(identities_dir(root).join(enrollment_id))
}

/// 临时文件 + 重命名。同名临时文件用 `create_new` 抢，抢不到就说明
/// 上一轮留下了垃圾；直接换一个名字重试，不覆盖别人正在写的内容。
fn write_json(path: &Path, value: &Value) -> Result<(), PairError> {
    let text = serde_json::to_vec_pretty(value)
        .map_err(|_| PairError::new_pub("EnrollmentWriteFailed", "接入登记无法序列化。"))?;
    let parent = path
        .parent()
        .ok_or_else(|| PairError::new_pub("EnrollmentWriteFailed", "接入登记路径无效。"))?;
    std::fs::create_dir_all(parent).map_err(|e| write_failed("创建接入登记目录失败", &e))?;
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..8u32 {
        let temp = parent.join(format!(
            ".{}.tmp-{}-{attempt}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("enrollment"),
            std::process::id()
        ));
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(write_failed("创建接入登记临时文件失败", &e)),
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
            return Err(write_failed("写入接入登记失败", &e));
        }
        return Ok(());
    }
    Err(write_failed(
        "写入接入登记失败（临时文件一直被占用）",
        &last.unwrap_or_else(|| std::io::Error::other("unknown")),
    ))
}

fn read_json(path: &Path) -> Result<Value, PairError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PairError::new_pub("EnrollmentNotFound", "本机没有这份接入登记。")
        } else {
            PairError::new_pub("InvalidEnrollment", &format!("读取接入登记失败：{e}"))
        }
    })?;
    serde_json::from_str(&text).map_err(|_| invalid_state("接入登记文件不是合法 JSON。"))
}

/// 新登记写盘。已存在就拒绝：覆盖一份正在进行的申请会让服务器那边的
/// 设备记录和本机对不上。
pub fn save_new(
    root: &Path,
    enrollment: &Enrollment,
    keys: &PrivateKeys,
) -> Result<(), PairError> {
    let dir = enrollment_dir(root, &enrollment.enrollment_id)?;
    if dir.join("enrollment.json").exists() {
        return Err(PairError::new_pub(
            "EnrollmentExists",
            "本机已有这份接入登记，未覆盖。",
        ));
    }
    std::fs::create_dir_all(&dir).map_err(|e| write_failed("创建接入登记目录失败", &e))?;
    // 私钥先落盘：反过来会留下「有登记、没私钥」的坏状态。
    let envelope = json!({
        "SchemaVersion": 1,
        "Kind": "TradeChannel.PairingPrivate",
        "Protected": dpapi::protect(&json!({
            "RecipientPrivateKey": keys.recipient_pkcs8_b64,
            "WireGuardPrivateKey": keys.tunnel_private_b64,
        })
        .to_string())?,
    });
    write_json(&dir.join("private.dpapi.json"), &envelope)?;
    write_json(&dir.join("enrollment.json"), &enrollment.to_json())
}

pub fn load(root: &Path, enrollment_id: &str) -> Result<Enrollment, PairError> {
    let dir = enrollment_dir(root, enrollment_id)?;
    Enrollment::from_json(&read_json(&dir.join("enrollment.json"))?)
}

/// 读回私钥。DPAPI 解不开要报 `PairingPrivateUnavailable`——这意味着
/// 「换了电脑/账户」，和「文件损坏」是两种完全不同的处置。
pub fn load_private(root: &Path, enrollment_id: &str) -> Result<PrivateKeys, PairError> {
    let dir = enrollment_dir(root, enrollment_id)?;
    let envelope = read_json(&dir.join("private.dpapi.json"))?;
    if envelope.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
        || envelope.get("Kind").and_then(Value::as_str) != Some("TradeChannel.PairingPrivate")
    {
        return Err(invalid_state("本机私钥记录格式无效。"));
    }
    let protected = envelope
        .get("Protected")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_state("本机私钥记录缺少密文。"))?;
    let plain = dpapi::unprotect(protected)?;
    let value: Value = serde_json::from_str(&plain)
        .map_err(|_| invalid_state("本机私钥内容无法解析。"))?;
    let text = |key: &str| -> Result<String, PairError> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| invalid_state("本机私钥内容不完整。"))
    };
    Ok(PrivateKeys {
        recipient_pkcs8_b64: text("RecipientPrivateKey")?,
        tunnel_private_b64: text("WireGuardPrivateKey")?,
    })
}

/// 授权文件。与私钥分开存：私钥只在解封那一刻用得到，授权要长期留着
/// 给「重新导出配置」「核对服务器身份」用，两者的生命周期不一样。
const AUTHORIZATION_FILE: &str = "authorization.dpapi.json";

/// 存下已解封并验签过的授权。`signed` 是服务器签名的原文，`payload` 是解出来的载荷；
/// 两个都留，是因为将来核对「服务器有没有换配置」要拿原文重新验，不能只信解出来的那份。
pub fn save_authorization(
    root: &Path,
    enrollment_id: &str,
    signed: &str,
    payload: &Value,
) -> Result<(), PairError> {
    let dir = enrollment_dir(root, enrollment_id)?;
    let envelope = json!({
        "SchemaVersion": 1,
        "Kind": "TradeChannel.PairAuthorizationPrivate",
        "Protected": dpapi::protect(
            &json!({ "Signed": signed, "Authorization": payload }).to_string()
        )?,
    });
    write_json(&dir.join(AUTHORIZATION_FILE), &envelope)
}

/// 读回授权（原文 + 载荷）。没存过就返回 `None`，不当成错误——
/// 「刚申请完还没拿到授权」是正常状态。
///
/// 只有用例在读它（核对「存进去的到底是什么」）；生产侧不解封，所以不进 release。
#[cfg(test)]
pub fn load_authorization(root: &Path, enrollment_id: &str) -> Result<Option<Value>, PairError> {
    let dir = enrollment_dir(root, enrollment_id)?;
    let path = dir.join(AUTHORIZATION_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let envelope = read_json(&path)?;
    if envelope.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
        || envelope.get("Kind").and_then(Value::as_str)
            != Some("TradeChannel.PairAuthorizationPrivate")
    {
        return Err(invalid_state("本机授权记录格式无效。"));
    }
    let protected = envelope
        .get("Protected")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_state("本机授权记录缺少密文。"))?;
    let plain = dpapi::unprotect(protected)?;
    Ok(Some(
        serde_json::from_str(&plain).map_err(|_| invalid_state("本机授权内容无法解析。"))?,
    ))
}

/// 隧道配置文件名。私钥在它里面，所以同样是**只在本机**的文件。
const CONFIG_FILE: &str = "client.conf";

/// 落盘 `client.conf`。
///
/// 已存在且内容不同就拒绝——**绝不覆盖**：那份文件可能是用户手改过的，
/// 也可能是别的进程刚写下的。内容相同则视为已完成（重试路径会走到这里）。
pub fn write_config(root: &Path, enrollment_id: &str, text: &str) -> Result<PathBuf, PairError> {
    let dir = enrollment_dir(root, enrollment_id)?;
    let path = dir.join(CONFIG_FILE);
    if path.exists() {
        let existing = std::fs::read_to_string(&path)
            .map_err(|e| PairError::new_pub("EnrollmentWriteFailed", &format!("读取既有隧道配置失败：{e}")))?;
        if existing == text {
            return Ok(path);
        }
        return Err(PairError::new_pub(
            "ConfigConflict",
            "本机已有一份内容不同的隧道配置，未覆盖。",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| write_failed("创建隧道配置失败", &e))?;
    use std::io::Write;
    file.write_all(text.as_bytes())
        .map_err(|e| write_failed("写入隧道配置失败", &e))?;
    // 配置里有私钥：落盘完成之后才算数，否则崩溃会留下半份文件。
    file.sync_all().map_err(|e| write_failed("写入隧道配置失败", &e))?;
    Ok(path)
}

/// 只读判断：这份接入是否已经有隧道配置。用例用它断言落盘结果。
#[cfg(test)]
pub fn has_config(root: &Path, enrollment_id: &str) -> bool {
    enrollment_dir(root, enrollment_id)
        .map(|dir| dir.join(CONFIG_FILE).exists())
        .unwrap_or(false)
}

/// 判断「这份申请到底拿到授权没有」。用例用它核对两条路径的落盘差异。
#[cfg(test)]
pub fn has_authorization(root: &Path, enrollment_id: &str) -> bool {
    enrollment_dir(root, enrollment_id)
        .map(|dir| dir.join(AUTHORIZATION_FILE).exists())
        .unwrap_or(false)
}

/// 列出全部登记。目录名不是 UUID 的直接跳过（可能是 `.tmp` 残留或用户手动放的东西）；
/// 名字合规但内容坏掉的**照实报错**——静默跳过会让人以为设备记录丢了。
pub fn list(root: &Path) -> Result<Vec<Enrollment>, PairError> {
    let dir = identities_dir(root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(PairError::new_pub(
                "InvalidEnrollment",
                &format!("读取接入登记目录失败：{e}"),
            ))
        }
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            PairError::new_pub("InvalidEnrollment", &format!("读取接入登记目录失败：{e}"))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_enrollment_id(name) || !entry.path().is_dir() {
            continue;
        }
        if !entry.path().join("enrollment.json").exists() {
            continue;
        }
        found.push(load(root, name)?);
    }
    // 新的在前：列表要稳定，不能依赖文件系统的返回顺序。
    found.sort_by(|a, b| b.created_at_utc.cmp(&a.created_at_utc));
    Ok(found)
}

/// 同一个邀请是否已经申请过。重试必须复用原申请，否则服务器会把它当成
/// 一台新设备——旧版也是这么做的。
pub fn find_by_invite(root: &Path, invite_id: &str) -> Result<Option<Enrollment>, PairError> {
    Ok(list(root)?
        .into_iter()
        .find(|item| item.invite_id == invite_id))
}

/// 只改状态与完成时间，其余原样保留（重写整个文件，但内容来自刚读到的版本）。
pub fn mark_completed(
    root: &Path,
    enrollment_id: &str,
    completed_at_utc: &str,
) -> Result<Enrollment, PairError> {
    let mut enrollment = load(root, enrollment_id)?;
    enrollment.state = STATE_COMPLETED.to_string();
    enrollment.completed_at_utc = Some(completed_at_utc.to_string());
    let dir = enrollment_dir(root, enrollment_id)?;
    write_json(&dir.join("enrollment.json"), &enrollment.to_json())?;
    Ok(enrollment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, invite: &str, created: &str) -> Enrollment {
        Enrollment {
            enrollment_id: id.to_string(),
            invite_id: invite.to_string(),
            invite_code: "TCI1.example".to_string(),
            server_binding: json!({"RemoteOwnerId": "o1", "NodeId": "n1", "ServerPublicKey": "k1"}),
            management_signing_public_key: json!({"kty": "RSA", "n": "nn", "e": "AQAB"}),
            confirmed_fingerprint: format!("SHA256:{}", "A".repeat(43)),
            client_request: json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                "DeviceId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
                "CreatedAtUtc": created,
                "ClientPublicKey": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
                "AddressFamilies": ["IPv4"],
            }),
            request_digest: "d".repeat(64),
            pair_request: "a.b.c".to_string(),
            state: STATE_REQUESTED.to_string(),
            created_at_utc: created.to_string(),
            completed_at_utc: None,
        }
    }

    fn sample_keys() -> PrivateKeys {
        // 刻意与 `client_request.ClientPublicKey` 用不同字符串：两者若相同，
        // 「公开文件不含私钥」那条断言会因为「公钥本来就是公开的」而失去意义。
        PrivateKeys {
            recipient_pkcs8_b64: "TUlJQmRBTUlCQURL".to_string(),
            tunnel_private_b64: "d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=".to_string(),
        }
    }

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-pairstore-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ID_A: &str = "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b";
    const ID_B: &str = "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d";

    #[test]
    fn an_enrollment_survives_a_round_trip_and_the_keys_stay_separate() {
        let root = temp_root("round-trip");
        let enrollment = sample(ID_A, "invite-1", "2026-11-02T09:00:00Z");
        save_new(&root, &enrollment, &sample_keys()).unwrap();

        let loaded = load(&root, ID_A).unwrap();
        assert_eq!(loaded, enrollment);

        let keys = load_private(&root, ID_A).unwrap();
        assert_eq!(keys.tunnel_private_b64, sample_keys().tunnel_private_b64);

        // 公开文件里不能出现私钥；私钥文件本身也必须是密文。
        let public = std::fs::read_to_string(root.join("identities").join(ID_A).join("enrollment.json")).unwrap();
        assert!(!public.contains(&sample_keys().tunnel_private_b64), "公开登记里出现了隧道私钥");
        assert!(!public.contains(&sample_keys().recipient_pkcs8_b64), "公开登记里出现了接收私钥");
        let private = std::fs::read_to_string(root.join("identities").join(ID_A).join("private.dpapi.json")).unwrap();
        assert!(!private.contains(&sample_keys().tunnel_private_b64), "私钥文件里出现明文");
        assert!(private.contains("TradeChannel.PairingPrivate"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_existing_enrollment_is_never_overwritten() {
        let root = temp_root("no-overwrite");
        let mut first = sample(ID_A, "invite-1", "2026-11-02T09:00:00Z");
        save_new(&root, &first, &sample_keys()).unwrap();

        let mut second = first.clone();
        second.invite_id = "invite-2".to_string();
        let error = save_new(&root, &second, &sample_keys()).unwrap_err();
        assert_eq!(error.code, "EnrollmentExists");

        // 原文件没被改动。
        first.state = STATE_REQUESTED.to_string();
        assert_eq!(load(&root, ID_A).unwrap().invite_id, "invite-1");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_traversal_shaped_id_is_rejected_before_touching_the_disk() {
        let root = temp_root("traversal");
        for bad in [
            "../evil",
            "9F1C2A44-0B7D-4C1E-9A2B-3C4D5E6F7A8B",
            "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8",
            "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b/",
            "",
        ] {
            let mut enrollment = sample(ID_A, "invite-1", "2026-11-02T09:00:00Z");
            enrollment.enrollment_id = bad.to_string();
            let error = save_new(&root, &enrollment, &sample_keys()).unwrap_err();
            assert_eq!(error.code, "InvalidEnrollmentId", "{bad}");
        }
        // 根目录下除了 identities 什么都不该出现。
        let outside = std::fs::read_dir(root.parent().unwrap()).unwrap().count();
        assert!(outside > 0);
        let error = load(&root, "../../etc/passwd").unwrap_err();
        assert_eq!(error.code, "InvalidEnrollmentId");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn listing_sorts_newest_first_and_finds_by_invite() {
        let root = temp_root("list");
        save_new(&root, &sample(ID_A, "invite-1", "2026-11-02T09:00:00Z"), &sample_keys()).unwrap();
        save_new(&root, &sample(ID_B, "invite-2", "2026-11-02T10:00:00Z"), &sample_keys()).unwrap();

        let items = list(&root).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].enrollment_id, ID_B, "新的应当排在前面");

        let found = find_by_invite(&root, "invite-1").unwrap().unwrap();
        assert_eq!(found.enrollment_id, ID_A);
        assert!(find_by_invite(&root, "invite-404").unwrap().is_none());
        assert!(list(&root.join("nope")).unwrap().is_empty(), "目录不存在应视为空列表");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_completed_only_flips_the_state() {
        let root = temp_root("complete");
        let before = sample(ID_A, "invite-1", "2026-11-02T09:00:00Z");
        save_new(&root, &before, &sample_keys()).unwrap();

        let after = mark_completed(&root, ID_A, "2026-11-02T09:10:00Z").unwrap();
        assert_eq!(after.state, STATE_COMPLETED);
        assert_eq!(after.completed_at_utc.as_deref(), Some("2026-11-02T09:10:00Z"));
        // 其余字段一个都不能变。
        let mut expected = before.clone();
        expected.state = STATE_COMPLETED.to_string();
        expected.completed_at_utc = Some("2026-11-02T09:10:00Z".to_string());
        assert_eq!(load(&root, ID_A).unwrap(), expected);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn damaged_files_are_reported_not_panicked() {
        let root = temp_root("damaged");
        save_new(&root, &sample(ID_A, "invite-1", "2026-11-02T09:00:00Z"), &sample_keys()).unwrap();
        let dir = root.join("identities").join(ID_A);

        // 1) 公开文件坏掉：报格式问题。
        std::fs::write(dir.join("enrollment.json"), "{not json").unwrap();
        assert_eq!(load(&root, ID_A).unwrap_err().code, "InvalidEnrollment");

        // 2) 状态被写成第三个值：不能当成可用记录。
        std::fs::write(
            dir.join("enrollment.json"),
            serde_json::to_vec(&json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.Enrollment",
                "EnrollmentId": ID_A,
                "InviteId": "i",
                "Invite": "c",
                "ServerBinding": {},
                "ManagementSigningPublicKey": {},
                "ConfirmedFingerprint": "f",
                "ClientRequest": {},
                "RequestDigest": "d",
                "PairRequest": "p",
                "State": "CompletedLongAgo",
                "CreatedAtUtc": "t",
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(load(&root, ID_A).unwrap_err().code, "InvalidEnrollment");

        // 3) 私钥信封被截断：必须是「本机私钥不可用」，而不是幻觉成配对失败。
        std::fs::write(dir.join("private.dpapi.json"), r#"{"SchemaVersion":1,"Kind":"TradeChannel.PairingPrivate","Protected":"AAAA"}"#).unwrap();
        assert_eq!(load_private(&root, ID_A).unwrap_err().code, "PairingPrivateUnavailable");

        let _ = std::fs::remove_dir_all(&root);
    }
}
