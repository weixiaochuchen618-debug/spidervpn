//! 一次登录用什么：服务器密码，或一把 SSH 私钥。
//!
//! 为什么单独一个模块（r92）：
//!
//! - **解析只发生一次**。加密私钥的 bcrypt KDF 每次 100–300 ms，而一次部署要发
//!   十几条命令；把「PEM + 口令 → `PrivateKey`」放在传输层，就等于每条命令都付一次。
//!   这里解析完，`ssh` 层只拿 `Arc<PrivateKey>`。
//! - **口令只在这一个模块里出现过**。`ssh::Auth` 里没有口令字段，所以
//!   「口令被打印进日志」这件事在类型层面就不成立。
//! - **旧记录/旧信封零迁移**。`Kind` 缺省一律按密码解释（历史行为），
//!   只有真的选了私钥才多出 `Kind: "key"`。
//!
//! 与旧版的对应：`DeploymentPages.ps1` 的 `DeployLoginMethod` + `DeployKeyPath`
//! （`PrivateKeyFile(path, passphrase)`），凭据类型是 `SavedLoginRef` 里的
//! `Password` / `PrivateKeyPem` 两档。
//!
//! ## 清内存的边界（如实写在这里，不假装）
//!
//! 我们自己持有的 `String` 在 `Drop` 时清零。但 `decode_secret_key` 内部会把 PEM
//! base64 解出来的 DER 放进它自己的缓冲、解密时也会把口令 clone 一份去喂 bcrypt
//! —— 那些拷贝不归我们管，drop 之后仍然留在堆上。**不 fork 库**，也不为了「清得更
//! 干净」在我们这一层再复制第三份：多复制一份只会扩大泄漏面。

use std::sync::Arc;

use russh::keys::{decode_secret_key, PrivateKey};

/// 读私钥文件的大小上限。
///
/// 私钥最长的也就几 KB；超过这个量说明多半选错了文件——选成安装包或镜像时
/// 2 GB 会直接把内存吃光，而那时用户看到的是一台卡死的机器。
pub const KEY_FILE_CAP: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// 秘密文本
// ---------------------------------------------------------------------------

/// 一段用完即清零的文本（原 `deployengine::Secret`，r92 搬到这里）。
///
/// 为什么还要包一层 `String`（而不是直接用 `String`）：`Drop` 里清零这件事
/// 必须绑定在类型上，不能靠每个调用点记得「用完调 clear」。
pub struct Secret(String);

impl Secret {
    pub fn new(text: impl Into<String>) -> Secret {
        Secret(text.into())
    }

    /// 取出明文。只在真正要交给 `ssh`/`decode_secret_key` 的那一刻用。
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 只有「全是空白」算空。
    ///
    /// 口令可以有首尾空格（私钥的口令是用户自己定的，空格也是内容），
    /// 所以不能用 `is_empty()` 判；但「敲了几个空格」这种输入仍然当没填——
    /// 与密码框旧行为在这一点上保持一致。
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        crate::pairing::zero(&mut bytes);
    }
}

impl std::fmt::Debug for Secret {
    /// 刻意不打印内容：`{:?}` 进日志是最常见的一次泄漏。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

// ---------------------------------------------------------------------------
// 登录方式
// ---------------------------------------------------------------------------

/// 这次用什么登录。**非秘密**（说的是方式，不是内容），所以能进记录、能进导出摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Password,
    Key,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::Password => "password",
            CredentialKind::Key => "key",
        }
    }

    /// 宽容读：大小写不敏感，`privatekey` / `sshkey` / `private_key` 都当私钥；
    /// 空串、缺字段、表外值 → 密码（旧文件与旧记录都按密码解释，零迁移）。
    pub fn parse(text: &str) -> CredentialKind {
        let normalized = text.trim().to_ascii_lowercase().replace(['_', '-', ' '], "");
        match normalized.as_str() {
            "key" | "privatekey" | "sshkey" | "identityfile" | "privatekeyfile" => {
                CredentialKind::Key
            }
            _ => CredentialKind::Password,
        }
    }

    /// 界面上那句人话（「登录方式已变化」要说的是这个，不是 `"key"`）。
    pub fn label(self) -> &'static str {
        match self {
            CredentialKind::Password => "服务器密码",
            CredentialKind::Key => "SSH 私钥",
        }
    }
}

// ---------------------------------------------------------------------------
// 凭据
// ---------------------------------------------------------------------------

/// 一次登录用的完整凭据（**持有秘密**）。
///
/// 私钥分支同时留 `pem` 文本和 `key` 两样：
/// - `pem` 要写进 DPAPI 信封（「记住登录资料」与 24 小时续跑都要原文）；
/// - `key` 是解析结果，`ssh` 层直接用，避免每条命令重跑一次 bcrypt。
///
/// 不派生 `Debug`（会把密钥材料打进日志）、不派生 `Clone`（秘密不该被悄悄复制）。
/// 跨线程用 `Arc<Credential>`。
pub enum Credential {
    Password(Secret),
    Key {
        pem: Secret,
        passphrase: Option<Secret>,
        key: Arc<PrivateKey>,
    },
}

impl Credential {
    pub fn password(text: impl Into<String>) -> Credential {
        Credential::Password(Secret::new(text))
    }

    /// 从 PEM 文本解析。口令在这里用完即弃（`Arc<PrivateKey>` 里已经没有口令了）。
    ///
    /// 三段式探针：先 `None` 判「要不要口令」，再带口令判「口令错」——
    /// 两句话分开说，用户才知道该改口令还是该换文件。
    pub fn from_key_pem(pem: &str, passphrase: Option<&str>) -> Result<Credential, String> {
        if pem.trim().is_empty() {
            return Err("私钥内容为空，没有可用的登录资料。".to_string());
        }
        let typed = passphrase.map(str::to_string).filter(|text| !text.trim().is_empty());
        match decode_secret_key(pem, None) {
            Ok(key) => Ok(Credential::Key {
                pem: Secret::new(pem),
                // 未加密的钥填了口令：**忽略，不报错**（对齐 旧版的
                // `PrivateKeyFile(path, passphrase)`：用户常常不确定自己的钥有没有口令，
                // 直接报错等于让他去猜）。
                passphrase: None,
                key: Arc::new(key),
            }),
            Err(error) => {
                // OpenSSH/PKCS#5 加密钥会明确报 `KeyIsEncrypted`；PKCS#8 的
                // `BEGIN ENCRYPTED PRIVATE KEY` 与 PuTTY v3 只有解析错误，
                // 所以再看一眼原文——否则一个「有口令的 PKCS#8」会被念成
                // 「这不是能用的私钥」，而我们下一句还写着支持这种格式。
                let encrypted = matches!(error, russh::keys::Error::KeyIsEncrypted)
                    || looks_encrypted(pem);
                if !encrypted {
                    return Err(
                        "这个文件不是能用的 SSH 私钥。支持 OpenSSH 新格式\
                         （含 -----BEGIN OPENSSH PRIVATE KEY-----）、PEM/PKCS#8\
                         （-----BEGIN RSA PRIVATE KEY----- / -----BEGIN PRIVATE KEY----- / \
                         -----BEGIN ENCRYPTED PRIVATE KEY-----）和 PuTTY .ppk（v2/v3）。\
                         注意别选成公钥（.pub）。"
                            .to_string(),
                    );
                }
                let Some(secret) = typed.as_deref() else {
                    return Err(
                        "这个 SSH 私钥有口令保护：请在密码框里填写这个私钥的口令。".to_string()
                    );
                };
                match decode_secret_key(pem, Some(secret)) {
                    Ok(key) => Ok(Credential::Key {
                        pem: Secret::new(pem),
                        passphrase: Some(Secret::new(secret)),
                        key: Arc::new(key),
                    }),
                    // 口令错与文件坏在库层面**无法**可靠区分（PKCS#8 口令错给的是
                    // Der/Pkcs8 类错误，OpenSSH 加密钥给的是解析失败），
                    // 所以宁可诚实地说「或」，也不猜。
                    Err(_) => Err(
                        "私钥口令不正确（也可能是这个私钥文件已损坏，读不出密钥）。\
                         请核对口令；没有口令的私钥请把密码框留空。"
                            .to_string(),
                    ),
                }
            }
        }
    }

    pub fn kind(&self) -> CredentialKind {
        match self {
            Credential::Password(_) => CredentialKind::Password,
            Credential::Key { .. } => CredentialKind::Key,
        }
    }

    /// 落信封用。密码凭据给 `Some`，私钥凭据给 `None`。
    pub fn password_text(&self) -> Option<&str> {
        match self {
            Credential::Password(secret) => Some(secret.expose()),
            Credential::Key { .. } => None,
        }
    }

    pub fn pem_text(&self) -> Option<&str> {
        match self {
            Credential::Password(_) => None,
            Credential::Key { pem, .. } => Some(pem.expose()),
        }
    }

    pub fn passphrase_text(&self) -> Option<&str> {
        match self {
            Credential::Password(_) => None,
            Credential::Key { passphrase, .. } => passphrase.as_ref().map(Secret::expose),
        }
    }

    /// 内容非空才算「有凭据」。空密码 / 空 PEM 都是「这一次没有凭据」。
    pub fn is_usable(&self) -> bool {
        match self {
            Credential::Password(secret) => !secret.is_blank(),
            Credential::Key { pem, .. } => !pem.is_blank(),
        }
    }

    /// 造一份新的、内容相同的凭据。
    ///
    /// 为什么需要它（而不是 `Clone`）：`servercmd::resolve_identity` 借到一份
    /// `&Credential`，却要把它交给调用方**长期持有**。私钥本体是 `Arc`，这里只
    /// 复制 PEM 文本（几 KB），不会重跑一次 bcrypt。秘密的复制被收在这一个
    /// 有名字的方法里，读代码的人能看见它在哪儿发生。
    pub fn duplicate(&self) -> Credential {
        match self {
            Credential::Password(secret) => Credential::password(secret.expose()),
            Credential::Key { pem, passphrase, key } => Credential::Key {
                pem: Secret::new(pem.expose()),
                passphrase: passphrase.as_ref().map(|item| Secret::new(item.expose())),
                key: Arc::clone(key),
            },
        }
    }
}

/// 文本里有没有「加密私钥」的迹象。
///
/// 只认三处固定标记：PKCS#8 的 `BEGIN ENCRYPTED PRIVATE KEY`、PKCS#5 的
/// `Proc-Type: 4,ENCRYPTED`、PuTTY 的 `Encryption: aes256-cbc`。**不猜**别的写法。
fn looks_encrypted(pem: &str) -> bool {
    pem.contains("BEGIN ENCRYPTED PRIVATE KEY")
        || pem.contains("Proc-Type: 4,ENCRYPTED")
        || pem.contains("Encryption: aes256-cbc")
}

// ---------------------------------------------------------------------------
// 信封里取出来的凭据
// ---------------------------------------------------------------------------

/// 信封里取出来的凭据（**持有秘密**，`Drop` 时由 `Secret` 逐个清零）。
///
/// 为什么单独一个类型（不用 `Credential`）：从信封里拿到的只有文本，
/// 私钥还没解析（解析要跑 KDF）。让「解开的信封」与「可用的凭据」是两个类型，
/// 就不可能把「还没解析的 PEM」误传给 `ssh`。
pub struct StoredCredential {
    kind: CredentialKind,
    password: Secret,
    pem: Secret,
    passphrase: Option<Secret>,
}

impl StoredCredential {
    pub fn password(password: impl Into<String>) -> StoredCredential {
        StoredCredential {
            kind: CredentialKind::Password,
            password: Secret::new(password),
            pem: Secret::new(""),
            passphrase: None,
        }
    }

    pub fn key(pem: impl Into<String>, passphrase: Option<String>) -> StoredCredential {
        StoredCredential {
            kind: CredentialKind::Key,
            password: Secret::new(""),
            pem: Secret::new(pem),
            passphrase: passphrase.map(Secret::new),
        }
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    pub fn password_text(&self) -> &str {
        self.password.expose()
    }

    pub fn pem_text(&self) -> &str {
        self.pem.expose()
    }

    pub fn passphrase_text(&self) -> Option<&str> {
        self.passphrase.as_ref().map(Secret::expose)
    }

    /// 内容非空才算「有凭据」。
    pub fn is_usable(&self) -> bool {
        match self.kind {
            CredentialKind::Password => !self.password.is_blank(),
            CredentialKind::Key => !self.pem.is_blank(),
        }
    }

    /// 解析成可用凭据。私钥坏在这里才暴露（信封本身是好的）。
    pub fn into_credential(self) -> Result<Credential, String> {
        match self.kind {
            CredentialKind::Password => Ok(Credential::Password(self.password)),
            CredentialKind::Key => Credential::from_key_pem(
                self.pem.expose(),
                self.passphrase.as_ref().map(Secret::expose),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// 从文件读私钥
// ---------------------------------------------------------------------------

/// 从文件读 + 解析。**唯一**读私钥文件的地方（大小上限、编码、文案只此一份）。
///
/// 判据顺序是「先本地、后网络」：这里的每一个 `Err` 都发生在发出一个字节之前。
pub fn credential_from_key_file(path: &str, passphrase: Option<&str>) -> Result<Credential, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("请选择 SSH 私钥文件（或改用服务器密码登录）。".to_string());
    }
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // 不区分「不存在」与「不是文件」：对用户是同一件事——这个路径选不出私钥。
        Err(_) => {
            return Err(format!(
                "找不到这个私钥文件：{path}。请重新选择，或改用服务器密码登录。"
            ))
        }
    };
    if !meta.is_file() {
        return Err(format!(
            "找不到这个私钥文件：{path}。请重新选择，或改用服务器密码登录。"
        ));
    }
    if meta.len() > KEY_FILE_CAP {
        let kb = meta.len().div_ceil(1024);
        return Err(format!(
            "这个文件有 {kb} KB，不像 SSH 私钥（私钥通常只有几 KB）。\
             请确认选的是私钥文件，不要选安装包或镜像。"
        ));
    }
    // 先看大小再读：这就是上面那个上限的意义。
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(format!(
                "读不了这个私钥文件：{path}（{}）。请检查文件权限，或改用服务器密码登录。",
                io_reason(&error)
            ))
        }
    };
    let mut text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return Err(
                "这个文件不是文本格式的私钥（可能是别的二进制格式）。支持的格式见下面的说明。"
                    .to_string(),
            )
        }
    };
    let parsed = Credential::from_key_pem(&text, passphrase);
    // 文件内容整段清一次：解析结果（`Arc<PrivateKey>`）已经与这段文本无关了。
    unsafe { crate::pairing::zero(text.as_bytes_mut()) };
    parsed
}

/// 读文件失败的中文原因。
///
/// 不用 `error.to_string()`：那是英文 + `os error 5`，贴到界面上等于没说。
fn io_reason(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "没有读取权限",
        std::io::ErrorKind::NotFound => "文件不在了",
        _ => "文件读不出来",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Credential` **刻意不派生 `Debug`**（密钥材料不许进日志），所以测试里不能用
    /// `expect_err`（它要求 `T: Debug`）。用模式匹配表达同一件事。
    fn expect_error(result: Result<Credential, String>, message: &str) -> String {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn an_unencrypted_openssh_key_needs_no_passphrase() {
        let fixture = crate::ssh::test_support::key_fixture();
        let credential = Credential::from_key_pem(&fixture.pem, None).expect("明文钥应当能解析");
        assert_eq!(credential.kind(), CredentialKind::Key);
        assert!(credential.is_usable());
        assert_eq!(credential.pem_text(), Some(fixture.pem.as_str()));
        assert_eq!(credential.passphrase_text(), None, "没给口令就不该凭空造一个");
        assert_eq!(credential.password_text(), None);
    }

    #[test]
    fn an_unencrypted_key_ignores_a_typed_passphrase() {
        let fixture = crate::ssh::test_support::key_fixture();
        let credential =
            Credential::from_key_pem(&fixture.pem, Some("随便填的口令")).expect("未加密钥不能因为多填了口令就失败");
        assert_eq!(credential.passphrase_text(), None, "口令被忽略，不该被记住");
    }

    #[test]
    fn an_encrypted_key_without_a_passphrase_says_it_needs_one() {
        let fixture = crate::ssh::test_support::key_fixture();
        let pem = crate::ssh::test_support::encrypted_pem(&fixture.key, "pw-1");
        let error = expect_error(Credential::from_key_pem(&pem, None), "加密钥不给口令必须失败");
        assert!(error.contains("有口令保护"), "{error}");
    }

    #[test]
    fn an_encrypted_key_with_the_wrong_passphrase_says_the_passphrase_is_wrong() {
        let fixture = crate::ssh::test_support::key_fixture();
        let pem = crate::ssh::test_support::encrypted_pem(&fixture.key, "pw-1");
        let error = expect_error(
            Credential::from_key_pem(&pem, Some("wrong")),
            "口令错必须失败",
        );
        assert!(error.contains("私钥口令不正确"), "{error}");
        // russh/ssh-key 的英文内部错误一个词都不许漏到界面上。
        for leak in ["Could not read key", "SshKey", "Decrypt", "bcrypt", "Error"] {
            assert!(!error.contains(leak), "错误文案泄漏了内部词 {leak}：{error}");
        }
    }

    #[test]
    fn an_encrypted_key_with_the_right_passphrase_authenticates() {
        let fixture = crate::ssh::test_support::key_fixture();
        let pem = crate::ssh::test_support::encrypted_pem(&fixture.key, "pw-1");
        let credential =
            Credential::from_key_pem(&pem, Some("pw-1")).expect("口令对就该解析成功");
        assert_eq!(credential.kind(), CredentialKind::Key);
        assert_eq!(credential.passphrase_text(), Some("pw-1"), "口令要留着（信封要原文）");
        assert!(credential.is_usable());
    }

    #[test]
    fn a_public_key_file_is_refused_with_a_hint_about_pub() {
        let text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7p1k6QdQ9f0dZbn2l4hV3LQ4kzO0v3yqZ0n3J0mZ0K test@host\n";
        let error = expect_error(Credential::from_key_pem(text, None), "公钥不是私钥");
        assert!(error.contains(".pub"), "要提示「别选成公钥」：{error}");
    }

    #[test]
    fn a_pem_pkcs8_key_is_accepted() {
        let fixture = crate::ssh::test_support::key_fixture();
        let mut pem = Vec::new();
        russh::keys::encode_pkcs8_pem(&fixture.key, &mut pem).expect("应当能编成 PKCS#8");
        let text = String::from_utf8(pem).expect("PKCS#8 PEM 是文本");
        assert!(text.contains("BEGIN PRIVATE KEY"), "{text}");
        let credential = Credential::from_key_pem(&text, None).expect("PKCS#8 也要认");
        assert_eq!(credential.kind(), CredentialKind::Key);
    }

    #[test]
    fn an_oversized_file_is_refused_before_reading_it() {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-credential-big-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("huge.pem");
        std::fs::write(&path, vec![b'A'; 300 * 1024]).unwrap();
        let error = expect_error(
            credential_from_key_file(&path.to_string_lossy(), None),
            "超大文件必须直接拒绝",
        );
        assert!(error.contains("KB"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_key_file_says_which_path_is_gone() {
        let path = std::env::temp_dir().join("tcrs-credential-not-there-9241").join("id");
        let error = expect_error(
            credential_from_key_file(&path.to_string_lossy(), None),
            "不存在的文件必须拒绝",
        );
        assert!(error.contains("找不到这个私钥文件"), "{error}");
        assert!(error.contains("id"), "要把路径原话说出来：{error}");
        assert!(error.contains("请重新选择"), "{error}");
    }

    #[test]
    fn an_empty_path_is_refused_with_the_other_way_out() {
        let error = expect_error(credential_from_key_file("   ", None), "空路径必须拒绝");
        assert!(error.contains("请选择 SSH 私钥文件"), "{error}");
    }

    #[test]
    fn stored_credential_round_trips_both_kinds() {
        let password = StoredCredential::password("s3cret").into_credential().expect("密码");
        assert_eq!(password.kind(), CredentialKind::Password);
        assert_eq!(password.password_text(), Some("s3cret"));

        let fixture = crate::ssh::test_support::key_fixture();
        let key = StoredCredential::key(fixture.pem.clone(), None)
            .into_credential()
            .expect("明文钥");
        assert_eq!(key.kind(), CredentialKind::Key);
        assert_eq!(key.pem_text(), Some(fixture.pem.as_str()));

        let pem = crate::ssh::test_support::encrypted_pem(&fixture.key, "pw-1");
        let locked = StoredCredential::key(pem.clone(), Some("pw-1".to_string()))
            .into_credential()
            .expect("口令跟着信封一起存");
        assert_eq!(locked.passphrase_text(), Some("pw-1"));
    }

    #[test]
    fn an_empty_stored_credential_is_not_usable() {
        assert!(!StoredCredential::password("   ").is_usable());
        assert!(!StoredCredential::key("", None).is_usable());
        assert!(StoredCredential::password("x").is_usable());
    }

    /// 记录/信封里的登录方式：缺省与表外值都按密码，私有钥的几种写法都认。
    #[test]
    fn the_login_method_is_read_tolerantly() {
        assert_eq!(CredentialKind::parse(""), CredentialKind::Password);
        assert_eq!(CredentialKind::parse("password"), CredentialKind::Password);
        assert_eq!(CredentialKind::parse("改过的值"), CredentialKind::Password);
        assert_eq!(CredentialKind::parse("key"), CredentialKind::Key);
        assert_eq!(CredentialKind::parse(" KEY "), CredentialKind::Key);
        assert_eq!(CredentialKind::parse("PrivateKey"), CredentialKind::Key);
        assert_eq!(CredentialKind::parse("ssh_key"), CredentialKind::Key);
        assert_eq!(CredentialKind::parse("private-key"), CredentialKind::Key);
        assert_eq!(CredentialKind::Key.as_str(), "key");
        assert_eq!(CredentialKind::Password.as_str(), "password");
    }

    /// 口令的首尾空格是内容的一部分；但「全是空格」等于没填。
    #[test]
    fn an_empty_passphrase_is_not_a_missing_passphrase() {
        assert!(!Secret::new("  a  ").is_blank());
        assert_eq!(Secret::new("  a  ").expose(), "  a  ");
        assert!(Secret::new("   ").is_blank());
        assert!(Secret::new("").is_blank());
    }

    /// `duplicate` 只复制 PEM 文本，私钥本体是同一个 `Arc`（不重解析）。
    #[test]
    fn duplicating_a_key_credential_reuses_the_parsed_key() {
        let fixture = crate::ssh::test_support::key_fixture();
        let credential = Credential::from_key_pem(&fixture.pem, None).unwrap();
        let copy = credential.duplicate();
        assert_eq!(copy.kind(), CredentialKind::Key);
        assert_eq!(copy.pem_text(), credential.pem_text());
    }
}
