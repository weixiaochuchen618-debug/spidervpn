//! 任务级登录凭据：`<数据根>\deployments\credentials\<RunId>.bin`。
//!
//! 为什么要有这一份（与 `serverstore` 的长期凭据分开）：
//!
//! - 长期凭据回答「这台服务器以后都可以直接登录吗」，用户勾「在这台电脑记住登录资料」
//!   才写；不勾就该只在这次内存里用，跑完不留痕。
//! - 任务级凭据回答的是**另一个问题**：「这条部署中途断了，我回来接着做，还要不要
//!   再输一次密码」。它绑的是 `RunId` 而不是服务器，所以任务结束（完成 / 取消 /
//!   放弃）就地删除，不必去动服务器记录。
//!
//! 为什么要 DPAPI 而不是明文：文件落在数据根下，那棵树的 ACL 只是「管理员可写」，
//! 同机其他账户读到它就能登进服务器。整段用当前 Windows 用户封起来，换电脑/换用户
//! 直接解不开——与 `serverstore` 用的是同一套原语，熵里绑 RunId + 目标，文件被拷走
//! 也换不到别的任务上。
//!
//! 为什么要 24 小时过期：**这是承诺，不是缓存策略**。界面上写着「最长 24 小时」，
//! 超时还留着密码等于骗人。过期就地删除，读的一方拿不到就走「请补一次密码」。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::credential::{Credential, CredentialKind, StoredCredential};
use crate::pairing::dpapi;
use crate::secretfile;

/// 界面上写死的那个窗口（「最长 24 小时」）。两处必须是同一个数，所以只有这一份。
pub const TTL_SECONDS: u64 = 24 * 60 * 60;

const DIR: &str = "credentials";
/// 文件后缀：`<RunId>.bin`。内容是 JSON（DPAPI 信封），不是二进制——后缀只是
/// 让人一眼认出「这是封起来的凭据，不是给人看的记录」。
const EXT: &str = "bin";

/// 凭据的熵：**绑这条任务与这个目标**。
///
/// `\n` 分隔而不是 `|`：user 里可能真的有 `|`，拼进熵就会让两份不同的绑定算出同一串。
pub fn binding_of(run_id: &str, host: &str, port: u16, user: &str) -> String {
    format!("TradeChannel.DeployTask.v1\n{run_id}\n{host}\n{port}\n{user}")
}

/// `<root>/deployments/credentials/<RunId>.bin`。
///
/// `RunId` 会直接拼进路径，所以先过形状检查：不卡死就等于允许 `..\..\` 决定写哪儿。
pub fn file_of(root: &Path, run_id: &str) -> Result<PathBuf, String> {
    if !crate::deploystore::is_run_id(run_id) {
        return Err("部署任务标识不是合法的 36 位小写 UUID。".to_string());
    }
    Ok(root.join("deployments").join(DIR).join(run_id).with_extension(EXT))
}

/// 写一份任务级凭据。返回 `Err` 是给人看的原话。
///
/// 打开的信封内容（DPAPI 里那一层）：
///
/// ```text
/// 旧：{"Binding":"…","Password":"s3cret"}
/// 新：{"Binding":"…","Kind":"password","Password":"s3cret"}
///     {"Binding":"…","Kind":"key","PrivateKeyPem":"<pem>","Passphrase":"<或省略>"}
/// ```
///
/// **熵（[`binding_of`]）一个字不改**：把 `Kind` 加进熵，旧文件就会从「解不开」
/// 变成「悄悄换了一份」，我们也就再也说不出「登录方式已变化」这句人话。
///
/// 走 `secretfile::write`：文件一出现就是「只有本人/管理员/SYSTEM 可读」，
/// 不给别人留一个「文件已建、ACL 还没收」的窗口。
pub fn save(
    root: &Path,
    run_id: &str,
    binding: &str,
    credential: &Credential,
) -> Result<(), String> {
    if !credential.is_usable() {
        return Err(match credential.kind() {
            CredentialKind::Password => "密码为空，没有保存任何登录资料。",
            CredentialKind::Key => "私钥内容为空，没有保存任何登录资料。",
        }
        .to_string());
    }
    let path = file_of(root, run_id)?;
    let mut payload = payload_of(binding, credential);
    let sealed = dpapi::protect_with(&payload, binding.as_bytes()).map_err(|error| error.message);
    // 无论成败都清一次明文缓冲：堆内存不归我们管，能清一次就清一次。
    unsafe { crate::pairing::zero(payload.as_bytes_mut()) };
    let sealed = sealed?;
    let text = json!({
        "SchemaVersion": 1,
        "Kind": "TradeChannel.DeployTaskCredential",
        "RunId": run_id,
        "Protected": sealed,
    })
    .to_string();
    secretfile::write(&path, &text).map_err(|error| format!("没能保存这次任务的登录资料：{error}"))
}

/// 信封里那一层的明文（DPAPI 之前）。**只有这一个地方拼这个形状**。
fn payload_of(binding: &str, credential: &Credential) -> String {
    let mut map = serde_json::Map::new();
    map.insert("Binding".to_string(), Value::String(binding.to_string()));
    map.insert(
        "Kind".to_string(),
        Value::String(credential.kind().as_str().to_string()),
    );
    match credential {
        Credential::Password(secret) => {
            map.insert(
                "Password".to_string(),
                Value::String(secret.expose().to_string()),
            );
        }
        Credential::Key { pem, passphrase, .. } => {
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

/// 读一份任务级凭据。
///
/// **任何读不出来的情况都返回 `None`**（没有文件、超过 24 小时、信封解不开、
/// 绑定对不上）：它们对调用方是同一件事——「这一次没有可用的登录资料」。
/// 绝不能用 `Err` 让部署失败：丢一份辅助凭据把一次能成功的部署变成失败，
/// 代价远大于让用户重新输一遍密码。
///
/// 过期时顺手删掉文件：界面上承诺「最长 24 小时」，留着它只是让下一个读的人
/// 再做一遍同样的判断。
pub fn load(root: &Path, run_id: &str, binding: &str) -> Option<StoredCredential> {
    let path = file_of(root, run_id).ok()?;
    let meta = std::fs::metadata(&path).ok()?;
    // 过期判据用 mtime：它记录的是「下一次写这份文件」的时刻，与信封里的内容无关，
    // 也没法被内容改写作假。
    let expired = meta
        .modified()
        .ok()
        .and_then(|stamp| stamp.elapsed().ok())
        .map(|age| age.as_secs() > TTL_SECONDS)
        .unwrap_or(false);
    if expired {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let envelope: Value = serde_json::from_str(&text).ok()?;
    let sealed = envelope.get("Protected").and_then(Value::as_str)?;
    let mut plain = dpapi::unprotect_with(sealed, binding.as_bytes())
        .ok()?
        .into_bytes();
    let value: Value = serde_json::from_slice(&plain).ok()?;
    let stored_binding = value.get("Binding").and_then(Value::as_str).unwrap_or("");
    // 旧文件没有 `Kind`：`parse("")` → Password，与历史行为一致（零迁移）。
    let stored = read_payload(&value);
    let matched = stored_binding == binding && stored.is_usable();
    crate::pairing::zero(&mut plain);
    if matched {
        Some(stored)
    } else {
        None
    }
}

/// 把信封里那一层明文读成凭据。与 [`payload_of`] 是同一个形状的两端。
fn read_payload(value: &Value) -> StoredCredential {
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

/// 删掉一份任务级凭据。幂等：没有这个文件也算成功。
///
/// 任务完成 / 取消 / 放弃时都要调一次——**「清除」是这条功能的承诺**，
/// 少调一处就会留下一个用户以为已经删掉的密码文件。
pub fn remove(root: &Path, run_id: &str) {
    let Ok(path) = file_of(root, run_id) else {
        return;
    };
    let _ = std::fs::remove_file(&path);
}

/// 这些 RunId 名下有几份任务级凭据。**只读**（「删除本机部署资料」的预览用）。
///
/// 目录不存在 = 0 份（凭据目录是第一次保存时才建的）。判据与 [`file_of`] 同一条：
/// `<RunId>.bin` 的文件主干必须是这批 RunId 之一，别的一律不算。
pub fn count_for_runs(root: &Path, run_ids: &[String]) -> usize {
    if run_ids.is_empty() {
        return 0;
    }
    let dir = root.join("deployments").join(DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut count = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|item| item.to_str()) != Some(EXT) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|item| item.to_str()) else {
            continue;
        };
        if run_ids.iter().any(|run_id| run_id == stem) {
            count += 1;
        }
    }
    count
}

/// 启动时清一遍过期文件。返回删掉的条数（给自检/日志用）。
///
/// 为什么需要：任务可能永远停在 NeedsAttention 上没人管，而 `remove` 只在
/// 「用户对这条记录做了动作」时才跑。启动扫描是唯一能兜住「再也没人碰它」的地方。
pub fn sweep_expired(root: &Path) -> usize {
    let dir = root.join("deployments").join(DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|item| item.to_str()) != Some(EXT) {
            continue;
        }
        let expired = std::fs::metadata(&path)
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|stamp| stamp.elapsed().ok())
            .map(|age| age.as_secs() > TTL_SECONDS)
            .unwrap_or(false);
        if expired && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-deploycred-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RUN: &str = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";

    /// 密码那一档的明文（断言用；私钥那一档见下面的专门用例）。
    fn plain(stored: Option<StoredCredential>) -> Option<String> {
        stored.map(|item| item.password_text().to_string())
    }

    #[test]
    fn a_task_credential_round_trips_under_its_own_run() {
        let root = temp_root("roundtrip");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).expect("应当能存下来");
        assert_eq!(plain(load(&root, RUN, &binding)).as_deref(), Some("s3cret"));
        // 文件确实按 `<RunId>.bin` 落在 deployments\credentials 下。
        let path = file_of(&root, RUN).unwrap();
        assert!(path.exists(), "{}", path.display());
        assert!(path.to_string_lossy().replace('\\', "/").contains("deployments/credentials/"));
        assert!(path.to_string_lossy().ends_with(&format!("{RUN}.bin")));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 换一条任务（或换目标）就解不开：文件被拷走也换不到别的部署上。
    #[test]
    fn a_credential_cannot_be_replayed_on_another_binding() {
        let root = temp_root("replay");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).unwrap();
        let other = binding_of(RUN, "198.51.100.7", 22, "root");
        assert!(load(&root, RUN, &other).is_none(), "目标变了必须解不开");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 超过 24 小时：读回「没有」，并且文件被删掉（界面上承诺过的最长时限）。
    #[test]
    fn an_expired_credential_reads_as_absent_and_is_deleted() {
        let root = temp_root("expired");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).unwrap();
        let path = file_of(&root, RUN).unwrap();
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(TTL_SECONDS + 60);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(old).unwrap();
        drop(file);
        assert!(load(&root, RUN, &binding).is_none(), "过期一律当成没有");
        assert!(!path.exists(), "过期文件必须就地删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 没有文件、id 形状不对：都是「没有」，不是错误。
    #[test]
    fn a_missing_or_invalid_run_reads_as_absent_without_error() {
        let root = temp_root("missing");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        assert!(load(&root, RUN, &binding).is_none());
        assert!(load(&root, "..\\..\\windows", &binding).is_none());
        assert!(save(&root, "..\\..\\windows", &binding, &Credential::password("x")).is_err());
        assert!(save(&root, RUN, &binding, &Credential::password("")).is_err(), "空密码不该写出文件");
        assert!(!file_of(&root, RUN).unwrap().exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removing_is_idempotent() {
        let root = temp_root("remove");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).unwrap();
        remove(&root, RUN);
        assert!(load(&root, RUN, &binding).is_none());
        remove(&root, RUN); // 再删一次不许 panic
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 启动扫描：过期的被清掉，没过期的一个都不许动。
    #[test]
    fn the_startup_sweep_only_touches_expired_files() {
        let root = temp_root("sweep");
        let fresh = binding_of(RUN, "203.0.113.10", 22, "root");
        let stale_run = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let stale = binding_of(stale_run, "198.51.100.7", 22, "root");
        save(&root, RUN, &fresh, &Credential::password("keep")).unwrap();
        save(&root, stale_run, &stale, &Credential::password("drop")).unwrap();
        let stale_path = file_of(&root, stale_run).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&stale_path)
            .unwrap();
        file.set_modified(
            std::time::SystemTime::now() - std::time::Duration::from_secs(TTL_SECONDS + 1),
        )
        .unwrap();
        drop(file);
        assert_eq!(sweep_expired(&root), 1);
        assert_eq!(plain(load(&root, RUN, &fresh)).as_deref(), Some("keep"));
        assert!(!stale_path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 预览要的那个计数：只数这批 RunId 的 `.bin`，别人的一份都不算。
    #[test]
    fn counting_only_counts_files_that_belong_to_the_given_runs() {        let root = temp_root("count");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).unwrap();
        let other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let other_binding = binding_of(other, "203.0.113.10", 22, "root");
        save(&root, other, &other_binding, &Credential::password("s3cret")).unwrap();

        assert_eq!(count_for_runs(&root, &[RUN.to_string()]), 1);
        assert_eq!(
            count_for_runs(&root, &[RUN.to_string(), other.to_string()]),
            2
        );
        assert_eq!(count_for_runs(&root, &[]), 0, "空清单不该去数别人的文件");
        assert_eq!(
            count_for_runs(&root, &["9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string()]),
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 旧信封（内层没有 `Kind`）：一律当密码。**零迁移是承诺，不是巧合。**
    #[test]
    fn a_legacy_envelope_without_kind_reads_as_a_password() {
        let root = temp_root("legacy");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        write_legacy(&root, RUN, &binding, "s3cret");
        let stored = load(&root, RUN, &binding).expect("旧信封必须还能读");
        assert_eq!(stored.kind(), CredentialKind::Password);
        assert_eq!(stored.password_text(), "s3cret");
        let credential = stored.into_credential().expect("密码档不该解析失败");
        assert_eq!(credential.kind(), CredentialKind::Password);
        assert_eq!(credential.password_text(), Some("s3cret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 私钥档往返：存进去 → 读出来 → **真的能跑一条 `ssh::exec`**。
    #[test]
    fn a_key_credential_round_trips_through_the_task_envelope() {
        let fixture = crate::ssh::test_support::key_fixture();
        let server = crate::ssh::test_support::start_key_server(&fixture.fingerprint);
        let root = temp_root("key");
        let binding = binding_of(RUN, "127.0.0.1", server.port, "root");
        let credential = Credential::from_key_pem(&fixture.pem, None).expect("明文钥");
        save(&root, RUN, &binding, &credential).expect("私钥也要能存");

        let stored = load(&root, RUN, &binding).expect("读回来");
        assert_eq!(stored.kind(), CredentialKind::Key);
        assert_eq!(stored.pem_text(), fixture.pem);
        let restored = stored.into_credential().expect("私钥应当仍能解析");
        let out = crate::ssh::exec(
            &crate::ssh::Target::new("127.0.0.1", server.port, "root"),
            &restored,
            Some(&server.fingerprint),
            "echo ok",
            std::time::Duration::from_secs(10),
        )
        .expect("从信封恢复的私钥应当能登录");
        assert_eq!(out.stdout, "ok\n");

        // 文件里不许有 PEM 原文：它整段封在 DPAPI 里。
        let text = std::fs::read_to_string(file_of(&root, RUN).unwrap()).unwrap();
        assert!(!text.contains("BEGIN"), "信封外层泄漏了私钥：{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 存的是密码，就不能被读成私钥（反之亦然）：这是「登录方式已变化」判据的前提。
    #[test]
    fn a_credential_saved_as_a_password_does_not_read_back_as_a_key() {
        let root = temp_root("kindswap");
        let binding = binding_of(RUN, "203.0.113.10", 22, "root");
        save(&root, RUN, &binding, &Credential::password("s3cret")).unwrap();
        let stored = load(&root, RUN, &binding).expect("读回来");
        assert_eq!(stored.kind(), CredentialKind::Password, "存的是密码就得读成密码");
        assert!(stored.pem_text().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 手动写一份**旧格式**（内层只有 `Binding` + `Password`）的信封。
    fn write_legacy(root: &Path, run_id: &str, binding: &str, password: &str) {
        let mut payload = json!({ "Binding": binding, "Password": password }).to_string();
        let sealed = dpapi::protect_with(&payload, binding.as_bytes()).expect("旧信封应当能封");
        unsafe { crate::pairing::zero(payload.as_bytes_mut()) };
        let text = json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.DeployTaskCredential",
            "RunId": run_id,
            "Protected": sealed,
        })
        .to_string();
        let path = file_of(root, run_id).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }
}
