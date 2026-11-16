//! SSH 传输层：只做三件事——连上、验主机指纹、跑一条命令。
//!
//! 为什么不用系统的 `ssh.exe`：
//! 1. **密码认证没法安全地喂给它**。GUI 进程要交互输入密码，只能靠 `SSH_ASKPASS`，
//!    而它在 Windows 上要配套一个可执行脚本 + 环境变量，凭据会落到临时文件里。
//! 2. **主机指纹必须由我们按记录钉住**，不能写进用户的 `known_hosts`：
//!    那会把「本产品连过哪台服务器」留在系统里，也会让别的 ssh 客户端继承这份信任。
//! 3. 部署要一步一报告，解析子进程的 stderr 比解析协议本身更脆。
//!
//! 与旧版的对应：`DeploymentTransport.psm1` 用 SSH.NET；这里用 russh。
//! 语义对齐：**先确认主机身份、再送凭据**；密码不落日志；每条命令带超时与输出上限。
//!
//! 线程模型：russh 是 async 的，本程序其余部分全是同步的。这里在内部起一个
//! current_thread 运行时，对外只暴露同步函数——调用方不用染上 async。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{client, ChannelMsg};

/// 单条命令的输出上限。部署命令（`apt-get install`、`wg genkey`）正常都在几 KB；
/// 超过这个量说明命令跑飞了，继续收只会把内存吃光。
const OUTPUT_CAP: usize = 256 * 1024;

/// 目标服务器。`host` 可以是域名或 IP。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
}

impl Target {
    pub fn new(host: &str, port: u16, user: &str) -> Target {
        Target {
            host: host.trim().to_string(),
            port: if port == 0 { 22 } else { port },
            user: user.trim().to_string(),
        }
    }

    /// 解析 `用户@主机[:端口]`。
    ///
    /// **不收 IPv6 字面量**：`2001:db8::1` 会被 `rsplit_once(':')` 拆成
    /// 「主机 `2001:db8:`、端口 1」——一个能连但连错地方的结果，比直接报错难查得多。
    pub fn parse(spec: &str) -> Result<Target, String> {
        let spec = spec.trim();
        let (user, rest) = spec
            .split_once('@')
            .ok_or_else(|| format!("需要写成 用户名@主机[:端口]，例如 root@203.0.113.10：{spec}"))?;
        if user.trim().is_empty() || rest.trim().is_empty() {
            return Err(format!("用户名和主机都不能为空：{spec}"));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port: u16 = port
                    .trim()
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| format!("端口必须是 1–65535：{port}"))?;
                (host, port)
            }
            Some(_) => {
                return Err(format!("暂不支持 IPv6 字面量地址，请用域名或 IPv4：{rest}"));
            }
            None => (rest, 22),
        };
        Ok(Target::new(host, port, user))
    }
}

/// 一次命令的结果。`code` 是远端进程的退出码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: u32,
    pub stdout: String,
    pub stderr: String,
    /// 输出被 `OUTPUT_CAP` 截断过。**必须如实告诉调用方**：
    /// 截断后的输出不能拿去做「包含某关键字」这种判定。
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 第一次连这台服务器（或记录里还没存指纹）。调用方要把指纹显示给人确认，
    /// 确认后把指纹写进记录，下次再连就是「已钉住」。**此时没有发送任何凭据。**
    HostKeyUnknown { fingerprint: String },
    /// 记录里的指纹与这次看到的不一致。**必须停下**，不能「更新一下继续」：
    /// 中间人攻击与「服务器重装了」在这层看起来一模一样，只有人能分辨。
    HostKeyMismatch { expected: String, actual: String },
    /// 主机身份没问题，但用户名/密码被拒。
    Auth,
    /// 连不上：DNS、拒绝连接、协商失败。消息原样带出（不含凭据）。
    Connect(String),
    /// 整体超时（连接 + 认证 + 命令）。
    Timeout,
    /// 命令层面失败：没有退出码、通道打不开。
    Command(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HostKeyUnknown { fingerprint } => {
                write!(f, "这台服务器的主机指纹还没有确认：{fingerprint}")
            }
            Error::HostKeyMismatch { expected, actual } => write!(
                f,
                "服务器主机指纹与记录不一致（记录 {expected}，本次 {actual}）；可能换过机器或被中间人接管"
            ),
            Error::Auth => write!(f, "用户名或密码不正确"),
            Error::Connect(e) => write!(f, "连不上服务器：{e}"),
            Error::Timeout => write!(f, "连接服务器超时"),
            Error::Command(e) => write!(f, "服务器上的命令没有正常结束：{e}"),
        }
    }
}

/// 主机公钥指纹，形状与 OpenSSH 一致：`SHA256:<base64>`。
///
/// 证书形式取它承载的公钥——用户确认的是「哪把钥匙」，不是「哪张证书」。
fn fingerprint_of(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => {
            key.fingerprint(HashAlg::Sha256).to_string()
        }
        PublicKeyOrCertificate::Certificate(cert) => {
            cert.public_key().fingerprint(HashAlg::Sha256).to_string()
        }
    }
}

/// 只读主机指纹、不认证、不执行任何命令。
///
/// 部署流程的第一步：先把指纹拿给用户看，用户确认后才把密码交出去。
pub fn probe_host_key(target: &Target, timeout: Duration) -> Result<String, Error> {
    let handler = PinHandler {
        expected: None,
        // 只读指纹：连握手都不完成，绝不接受未知身份（这是「确认身份前不发密码」的立足点）。
        accept_unknown: false,
        seen: Arc::new(Mutex::new(None)),
    };
    let seen = Arc::clone(&handler.seen);

    let rt = runtime()?;
    let outcome = rt.block_on(async {
        tokio::time::timeout(timeout, open_session(target, handler, timeout)).await
    });

    if let Some(fingerprint) = seen.lock().ok().and_then(|g| g.clone()) {
        // 拿到指纹就够：`check_server_key` 一律返回 false，所以连接本来就会被拒。
        return Ok(fingerprint);
    }
    match outcome {
        Ok(Err(e)) => Err(Error::Connect(e.to_string())),
        Ok(Ok(_)) => Err(Error::Connect("服务器没有提供主机公钥".to_string())),
        Err(_) => Err(Error::Timeout),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Connect(format!("无法初始化网络运行时：{e}")))
}

async fn open_session(
    target: &Target,
    handler: PinHandler,
    timeout: Duration,
) -> Result<client::Handle<PinHandler>, russh::Error> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(timeout),
        ..Default::default()
    });
    client::connect(config, (target.host.as_str(), target.port), handler).await
}

/// 首次接触时对「没见过的主机身份」怎么办。
///
/// 默认 [`UnknownKey::Refuse`]：**确认身份之前不发送密码**，只把指纹带回去等人核对。
/// [`UnknownKey::Accept`] 是 旧版「自动记住首次服务器身份」用的 TOFU 路径：
/// 接受这一次，由调用方在**命令真的跑成功之后**再钉住指纹——先钉后验等于把
/// 「连上了」当成「身份对」，顺序反了就没意义了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKey {
    Refuse,
    Accept,
}

/// 一次成功执行的结果 + 服务器这次出示的指纹。
///
/// 指纹**一定**有（握手阶段就拿得到），但**今天没有任何生产路径读它**：AutoTrust 走的是
/// `servercmd::resolve_identity` → [`probe_host_key`]（先只读探一次、钉住之后才发密码），
/// 比「一边跑命令一边接受陌生身份」更保守；生产侧只用 [`exec`]（永远 `Refuse`）。
/// 这个字段留着，是为了让 `exec_with` 的用例能断言「接受陌生身份时拿到的是哪一枚」——
/// 别再把它当成「AutoTrust 的落记录靠它」（那句注释曾经是假的，r83 改掉）。
#[derive(Debug, Clone)]
pub struct Ran {
    pub output: Output,
    pub fingerprint: String,
}

/// 一次登录用什么凭据。**只借、不拥有**：口令/PEM 的生命周期由调用方的
/// [`crate::credential::Credential`] 管。
///
/// 为什么要这个枚举而不是两个函数（`exec_password` / `exec_key`）：
/// 主机指纹、超时、输出上限、错误映射这四条逻辑必须只有一份——分成两个函数，
/// 迟早出现「私钥那条忘了验指纹」这种只在一半路径上成立的保证。
///
/// 刻意**不派生 `Debug`**：`PrivateKey` 的 `{:?}` 会把密钥材料打进日志，
/// 而「打印一下上下文」是这个仓库里最常见的调试动作。
#[derive(Clone, Copy)]
pub enum Auth<'a> {
    Password(&'a str),
    /// 已经解析好的私钥（解析在 `credential` 模块，口令也在那里用完即弃）。
    ///
    /// 为什么收 `&Arc<PrivateKey>` 而不是 PEM + 口令：加密钥的 bcrypt KDF
    /// 每次 100–300 ms，而一次部署要发十几条命令；把解析放进这里等于每条命令付一次。
    Key(&'a Arc<PrivateKey>),
}

impl<'a> Auth<'a> {
    /// 从「这一次到底有没有凭据」得到一个 `Auth`。
    ///
    /// `None` 时沿用今天 `password.unwrap_or("")` 的语义：拿空密码去连，由服务器拒。
    /// 这样「没有凭据」仍然是一条正常的认证失败，而不是我们编造出来的第四种状态。
    pub fn from_option(credential: Option<&'a crate::credential::Credential>) -> Auth<'a> {
        match credential {
            Some(credential) => Auth::from(credential),
            None => Auth::Password(""),
        }
    }
}

impl<'a> From<&'a str> for Auth<'a> {
    fn from(password: &'a str) -> Auth<'a> {
        Auth::Password(password)
    }
}

/// `&String` 也要能直接喂进来：`ipc` 里大量 `&password` 是 `&String`
/// 而不是 `&str`，少这一条就得在 200 个调用点各加一次 `as_str()`。
impl<'a> From<&'a String> for Auth<'a> {
    fn from(password: &'a String) -> Auth<'a> {
        Auth::Password(password.as_str())
    }
}

impl<'a> From<&'a crate::credential::Credential> for Auth<'a> {
    fn from(credential: &'a crate::credential::Credential) -> Auth<'a> {
        match credential {
            crate::credential::Credential::Password(secret) => Auth::Password(secret.expose()),
            crate::credential::Credential::Key { key, .. } => Auth::Key(key),
        }
    }
}

/// 跑一条命令。`expected` 是记录里钉住的指纹；`None` 表示还没确认过，
/// 此时会返回 [`Error::HostKeyUnknown`] 并且**不会**发送凭据。
pub fn exec<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: Option<&str>,
    command: &str,
    timeout: Duration,
) -> Result<Output, Error> {
    exec_with(target, auth, expected, UnknownKey::Refuse, command, timeout).map(|ran| ran.output)
}

/// 同 [`exec`]，但可以指定「没见过的主机身份」怎么处理，并把指纹带回来。
pub fn exec_with<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: Option<&str>,
    unknown: UnknownKey,
    command: &str,
    timeout: Duration,
) -> Result<Ran, Error> {
    let auth = auth.into();
    let handler = PinHandler {
        expected: expected.map(str::to_string),
        accept_unknown: unknown == UnknownKey::Accept && expected.is_none(),
        seen: Arc::new(Mutex::new(None)),
    };
    let seen = Arc::clone(&handler.seen);

    let rt = runtime()?;

    let result = rt.block_on(async {
        tokio::time::timeout(timeout, async {
            let mut session = open_session(target, handler, timeout)
                .await
                .map_err(|e| Error::Connect(e.to_string()))?;

            let result = match auth {
                Auth::Password(password) => session
                    .authenticate_password(target.user.clone(), password)
                    .await
                    .map_err(|e| Error::Connect(e.to_string()))?,
                Auth::Key(key) => {
                    // RSA 必须协商 rsa-sha2-*，否则新版 OpenSSH 服务器直接拒
                    // （"no mutual signature algorithm"）。非 RSA 时
                    // `PrivateKeyWithHashAlg::new` 自己忽略 hash_alg，
                    // 所以这里统一问一次比加分支更不容易漏。
                    let hash = match session.best_supported_rsa_hash().await {
                        Ok(Some(inner)) => inner,
                        _ => None,
                    };
                    let key = PrivateKeyWithHashAlg::new(Arc::clone(key), hash);
                    session
                        .authenticate_publickey(target.user.clone(), key)
                        .await
                        .map_err(|e| Error::Connect(e.to_string()))?
                }
            };
            if !result.success() {
                return Err(Error::Auth);
            }

            let mut channel = session
                .channel_open_session()
                .await
                .map_err(|e| Error::Command(e.to_string()))?;
            channel
                .exec(true, command)
                .await
                .map_err(|e| Error::Command(e.to_string()))?;

            let mut stdout: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            let mut code: Option<u32> = None;
            let mut truncated = false;
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        truncated |= push_capped(&mut stdout, &data);
                    }
                    ChannelMsg::ExtendedData { data, ext } if ext == 1 => {
                        truncated |= push_capped(&mut stderr, &data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    _ => {}
                }
            }
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "done")
                .await;
            let code = code.ok_or_else(|| {
                Error::Command("服务器没有返回退出码（命令可能被中断）".to_string())
            })?;
            Ok(Output {
                code,
                stdout: String::from_utf8_lossy(&stdout).to_string(),
                stderr: String::from_utf8_lossy(&stderr).to_string(),
                truncated,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    });

    match result {
        Ok(output) => {
            // 握手成功就一定有指纹；没有只能说明实现坏了，不该悄悄放过。
            let fingerprint = seen
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .ok_or_else(|| Error::Connect("握手没有记录主机指纹".to_string()))?;
            Ok(Ran { output, fingerprint })
        }
        Err(Error::Connect(message)) => {
            // 连接被拒有两种原因：网络问题，或**主机身份没过**。
            // 后者必须报成它自己的错误，否则用户只会看到「连不上」，
            // 而真正该做的是核对指纹。
            let actual = seen.lock().ok().and_then(|g| g.clone());
            match (expected, actual) {
                (None, Some(fingerprint)) => Err(Error::HostKeyUnknown { fingerprint }),
                (Some(want), Some(got)) if want != got => {
                    Err(Error::HostKeyMismatch { expected: want.to_string(), actual: got })
                }
                _ => Err(Error::Connect(message)),
            }
        }
        Err(other) => Err(other),
    }
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8]) -> bool {
    let room = OUTPUT_CAP.saturating_sub(buf.len());
    if data.len() <= room {
        buf.extend_from_slice(data);
        false
    } else {
        buf.extend_from_slice(&data[..room]);
        true
    }
}

#[derive(Clone)]
struct PinHandler {
    /// `None` = 还没确认过：按 `accept_unknown` 决定，默认拒绝并只把指纹带回去。
    expected: Option<String>,
    /// 只在 `expected == None` 时有意义：接受一个没见过的主机身份。
    accept_unknown: bool,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for PinHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let actual = fingerprint_of(server_public_key);
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(actual.clone());
        }
        Ok(match self.expected.as_deref() {
            Some(want) => want == actual.as_str(),
            // 没见过：只有显式要求 TOFU 时才放行；钉住由调用方在认证成功后做。
            None => self.accept_unknown,
        })
    }
}

/// 测试用的本地 SSH 服务。`deploy` 的端到端用例也用它——
/// 「传输层能跑」和「部署检查能跑」必须是同一条真链路，不是两套桩。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{self, Auth as ServerAuth, Msg, Server as _, Session, VerifiedPublicKey};
    use russh::{Channel, ChannelId};

    /// 固定的测试主机密钥（`ssh-keygen -t ed25519`，仅测试用，不是秘密）。
    const HOST_KEY: &str = include_str!("../tests/fixtures/ssh/test_host_ed25519");
    pub(crate) const PASSWORD: &str = "test-password";

    // 一次登录用什么凭据。
    //
    // 为什么用进程级 `OnceLock` 而不是给 handler 加字段：`TestServer::new_client`
    // 每来一条连接就造一个新 handler，把「允许哪把公钥」挂到连接上是错的位置——
    // 它描述的是「这台测试服务器接受谁」，不是「这条连接是谁」。
    //
    // （r92 起改成了每个服务一份：见 `TestServerHandle`。）

    /// 一把现生成的 ed25519 私钥：明文 PEM + 指纹 + 本体。
    ///
    /// 为什么随机生成而不是往仓库里塞一对固定测试钥：随机钥能覆盖
    /// 「未知公钥被拒」这条判据而不用把任何一把私钥（哪怕只是测试用的）签进仓库。
    pub(crate) struct KeyFixture {
        pub key: PrivateKey,
        /// OpenSSH 新格式 PEM（`-----BEGIN OPENSSH PRIVATE KEY-----`）。
        pub pem: String,
        pub fingerprint: String,
    }

    pub(crate) fn key_fixture() -> KeyFixture {
        let mut rng = russh::keys::key::safe_rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("测试密钥应当能生成");
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("测试密钥应当能导出成 PEM")
            .to_string();
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        KeyFixture { key, pem, fingerprint }
    }

    /// 同一把钥的口令保护版本（OpenSSH 的 bcrypt 加密格式）。
    pub(crate) fn encrypted_pem(key: &PrivateKey, passphrase: &str) -> String {
        let mut rng = russh::keys::key::safe_rng();
        key.encrypt(&mut rng, passphrase)
            .expect("测试密钥应当能加密")
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("加密钥应当能导出成 PEM")
            .to_string()
    }

    /// 环境检查脚本的假输出。真脚本在 `deploy::INSPECT_SCRIPT`，
    /// 这里只负责「服务器那边会回什么」，两边字段必须一一对应。
    const INSPECT_REPLY: &str = "TC_KERNEL=Linux\n\
TC_ARCH=x86_64\n\
TC_UID=0\n\
TC_DISTRO=debian\n\
TC_VERSION=12\n\
TC_SYSTEMD=yes\n\
TC_OPENSSL=yes\n\
TC_WG=no\n\
TC_WGDIR=no\n\
TC_UFW=absent\n\
TC_DOCKER=no\n\
TC_FORWARD_POLICY=ACCEPT\n\
TC_DONE=1\n";

    /// 部署脚本的假输出（`deploy::install_script` 的收尾三行）。
    const DEPLOY_REPLY: &str = "TC_INTERFACE=tc9f1c2a44\n\
TC_SERVER_PUBLIC=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
TC_LISTEN_PORT=51820\n\
TC_SUBNET=10.66.0.0/24\n\
TC_IFACE_ADDRESS=10.66.0.1/24\n\
TC_DONE=1\n";

    /// 一台跑起来的测试服务器。
    ///
    /// `publickey_attempts` 是「服务端真的收到了几次公钥认证尝试」——
    /// 「指纹不过就一个凭据都不发」这条判据只能靠它证明。
    pub(crate) struct TestServerHandle {
        pub port: u16,
        pub fingerprint: String,
        publickey_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl TestServerHandle {
        pub(crate) fn publickey_attempts(&self) -> usize {
            self.publickey_attempts
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// 测试服务器接受哪一把公钥。`None` = 拒绝所有公钥（只用密码）。
    ///
    /// 挂在 `server::Server` 上而不是挂在 handler 上：`new_client` 每来一条连接
    /// 就造一个新 handler，而「这台服务器接受谁」是服务器级的身份。
    struct TestServer {
        allowed_key: Option<String>,
        publickey_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl server::Server for TestServer {
        type Handler = TestHandler;
        fn new_client(&mut self, _: Option<SocketAddr>) -> TestHandler {
            TestHandler {
                allowed_key: self.allowed_key.clone(),
                publickey_attempts: Arc::clone(&self.publickey_attempts),
            }
        }
    }

    struct TestHandler {
        allowed_key: Option<String>,
        publickey_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl server::Handler for TestHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<ServerAuth, Self::Error> {
            Ok(if password == PASSWORD { ServerAuth::Accept } else { ServerAuth::reject() })
        }

        /// 公钥认证：**所有权已验证**的那一步（`VerifiedPublicKey`）才做判定，用指纹比对。
        ///
        /// 不在 `auth_publickey_offered` 里判：RFC 4252 明确说那个阶段还没有证明
        /// 「对方真的持有这把私钥」，默认实现直接放行报价、把判定留到这里。
        async fn auth_publickey(
            &mut self,
            _user: &str,
            key: VerifiedPublicKey<'_>,
        ) -> Result<ServerAuth, Self::Error> {
            self.publickey_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let seen = key.public_key.fingerprint(HashAlg::Sha256).to_string();
            let ok = self.allowed_key.as_deref() == Some(seen.as_str());
            Ok(if ok { ServerAuth::Accept } else { ServerAuth::reject() })
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let command = String::from_utf8_lossy(data).to_string();
            // 三条固定命令 + 环境检查脚本 + 部署脚本（按各自的特征串识别）。
            let (out, err, code) = if command.contains("TC_KERNEL=") {
                (INSPECT_REPLY.to_string(), String::new(), 0u32)
            } else if command.contains("TC_PEER=") {
                // peer 脚本：把脚本里 PUB='…' 抠出来回显，行为与真脚本一致。
                let pub_key = command
                    .split("PUB='")
                    .nth(1)
                    .and_then(|rest| rest.split('\'').next())
                    .unwrap_or("")
                    .to_string();
                (
                    format!(
                        "TC_PEER={pub_key}\nTC_SERVER_PUBLIC={}\nTC_DONE=1\n",
                        "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
                    ),
                    String::new(),
                    0u32,
                )
            } else if command.contains("wg-quick@") {
                (DEPLOY_REPLY.to_string(), String::new(), 0u32)
            } else {
                match command.as_str() {
                    "echo ok" => ("ok\n".to_string(), String::new(), 0u32),
                    "fail" => (String::new(), "boom\n".to_string(), 7u32),
                    _ => (String::new(), "unknown command\n".to_string(), 127u32),
                }
            };
            session.data(channel, out.into_bytes())?;
            if !err.is_empty() {
                session.extended_data(channel, 1, err.into_bytes())?;
            }
            session.exit_status_request(channel, code)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// 起一台本地 SSH 服务，返回端口与它自己的主机指纹。
    ///
    /// `allowed_key` = 这台服务接受哪一把客户端公钥的指纹（`None` 只用密码）。
    fn start_server_inner(allowed_key: Option<String>) -> TestServerHandle {
        let key = PrivateKey::from_openssh(HOST_KEY).expect("测试主机密钥必须能解析");
        assert_eq!(key.algorithm(), Algorithm::Ed25519, "夹具必须还是 ed25519");
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("应当能占一个临时端口");
        let addr = listener.local_addr().expect("临时端口必须可读");
        drop(listener);

        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts_for_server = Arc::clone(&attempts);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("测试服务端运行时");
            rt.block_on(async move {
                let config = Arc::new(server::Config {
                    keys: vec![key],
                    ..Default::default()
                });
                let mut sh = TestServer {
                    allowed_key,
                    publickey_attempts: attempts_for_server,
                };
                let _ = sh.run_on_address(config, addr).await;
            });
        });
        // 等它真的在听：`run_on_address` 是异步绑定，立刻连会拿到 connection refused。
        for _ in 0..100 {
            if std::net::TcpStream::connect(addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        TestServerHandle {
            port: addr.port(),
            fingerprint,
            publickey_attempts: attempts,
        }
    }

    pub(crate) fn start_server() -> (u16, String) {
        let handle = start_server_inner(None);
        (handle.port, handle.fingerprint)
    }

    /// 起一台**认私钥**的本地服务：只接受 `fingerprint` 这一把公钥。
    pub(crate) fn start_key_server(fingerprint: &str) -> TestServerHandle {
        start_server_inner(Some(fingerprint.to_string()))
    }

    pub(crate) fn target(port: u16) -> Target {
        Target::new("127.0.0.1", port, "root")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{start_server, target, PASSWORD};
    use super::*;
    use russh::keys::Algorithm;
    use std::time::Duration;

    #[test]
    fn a_pinned_host_key_runs_the_command_and_returns_its_output() {
        let (port, fingerprint) = start_server();
        let out = exec(&target(port), PASSWORD, Some(&fingerprint), "echo ok", Duration::from_secs(10))
            .expect("指纹正确时应当能执行命令");
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "ok\n");
        assert!(!out.truncated);
    }

    #[test]
    fn a_failing_command_keeps_its_exit_code_and_stderr() {
        let (port, fingerprint) = start_server();
        let out = exec(&target(port), PASSWORD, Some(&fingerprint), "fail", Duration::from_secs(10))
            .expect("命令失败不是传输失败");
        assert_eq!(out.code, 7, "退出码必须原样带回：调用方靠它判断部署步骤成没成");
        assert_eq!(out.stderr, "boom\n");
    }

    #[test]
    fn an_unconfirmed_host_reports_its_fingerprint_without_sending_a_password() {
        let (port, fingerprint) = start_server();
        let error = exec(&target(port), PASSWORD, None, "echo ok", Duration::from_secs(10))
            .expect_err("没有钉住指纹时不能继续");
        assert_eq!(error, Error::HostKeyUnknown { fingerprint });
        // 这一条是本模块最重要的断言：确认身份之前，密码一个字节都不许发出去。
        // 实现上靠 `check_server_key` 返回 false —— 握手就断了，认证根本没开始。
    }

    /// 自动记住（TOFU）：接受没见过的主机身份，并把**这次的**指纹带回去。
    /// 调用方靠它落记录——所以这枚指纹必须是服务器真的那枚，不能是占位。
    #[test]
    fn tofu_accepts_an_unknown_key_and_reports_what_it_saw() {
        let (port, fingerprint) = start_server();
        let ran = exec_with(
            &target(port),
            PASSWORD,
            None,
            UnknownKey::Accept,
            "echo ok",
            Duration::from_secs(10),
        )
        .expect("自动记住时这一次应当放行");
        assert_eq!(ran.output.code, 0);
        assert_eq!(ran.output.stdout, "ok\n");
        assert_eq!(ran.fingerprint, fingerprint, "带回来的必须是服务器真出示的那枚指纹");
    }

    /// 自动策略**不能**放宽已钉住的比对：指纹变了就是换了台机器，一律拦。
    #[test]
    fn a_pinned_fingerprint_is_still_enforced_even_when_tofu_is_on() {
        let (port, _) = start_server();
        let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let error = exec_with(
            &target(port),
            PASSWORD,
            Some(wrong),
            UnknownKey::Accept,
            "echo ok",
            Duration::from_secs(10),
        )
        .expect_err("钉住了就必须比对");
        assert!(matches!(error, Error::HostKeyMismatch { .. }), "{error:?}");
    }

    #[test]
    fn a_changed_host_key_is_reported_as_a_mismatch_not_a_connection_error() {        let (port, _) = start_server();
        let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let error = exec(&target(port), PASSWORD, Some(wrong), "echo ok", Duration::from_secs(10))
            .expect_err("指纹不一致必须拒绝");
        match error {
            Error::HostKeyMismatch { expected, actual } => {
                assert_eq!(expected, wrong);
                assert!(actual.starts_with("SHA256:"), "{actual}");
            }
            other => panic!("必须是 HostKeyMismatch，实际：{other:?}"),
        }
    }

    #[test]
    fn a_wrong_password_is_an_auth_failure_not_a_network_failure() {
        let (port, fingerprint) = start_server();
        let error = exec(&target(port), "wrong", Some(&fingerprint), "echo ok", Duration::from_secs(10))
            .expect_err("密码错误必须报错");
        assert_eq!(error, Error::Auth, "「密码不对」和「连不上」要分开：一个要用户改密码，一个要查网络");
    }

    /// 私钥这条路的端到端证据：真的跑一条命令，拿到它的输出。
    #[test]
    fn a_private_key_authenticates_and_runs_the_command() {
        let super::test_support::KeyFixture { key, pem: _, fingerprint: key_fp } =
            super::test_support::key_fixture();
        let server = super::test_support::start_key_server(&key_fp);
        let key = Arc::new(key);
        let out = exec(
            &target(server.port),
            Auth::Key(&key),
            Some(&server.fingerprint),
            "echo ok",
            Duration::from_secs(10),
        )
        .expect("服务器认这把公钥时应当能执行命令");
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "ok\n");
        assert!(!out.truncated);
    }

    /// 服务器不认这把公钥：必须是**认证失败**，不是「连不上」。
    ///
    /// 这两句话让用户做的事完全不同（换一把钥 vs 查网络/防火墙）。
    #[test]
    fn an_unknown_public_key_is_refused_as_an_auth_failure() {
        let unknown = super::test_support::key_fixture();
        let known = super::test_support::key_fixture();
        let server = super::test_support::start_key_server(&known.fingerprint);
        let unknown = Arc::new(unknown.key);
        let error = exec(
            &target(server.port),
            Auth::Key(&unknown),
            Some(&server.fingerprint),
            "echo ok",
            Duration::from_secs(10),
        )
        .expect_err("未知公钥必须被拒");
        assert_eq!(error, Error::Auth, "必须是认证失败，而不是网络错误：{error:?}");
        assert!(!matches!(error, Error::Connect(_)));
    }

    /// 未加密的钥 + 乱填的口令：仍然成功（对齐 旧版的容忍）。
    #[test]
    fn an_unencrypted_key_with_a_passphrase_still_works() {
        let fixture = super::test_support::key_fixture();
        let server = super::test_support::start_key_server(&fixture.fingerprint);
        // 口令填了但钥没加密：`credential` 会把口令忽略掉，这里是那条语义的传输层对照。
        let credential = crate::credential::Credential::from_key_pem(&fixture.pem, Some("乱填"))
            .expect("未加密钥不该因为多填了口令就失败");
        let out = exec(
            &target(server.port),
            Auth::from(&credential),
            Some(&server.fingerprint),
            "echo ok",
            Duration::from_secs(10),
        )
        .expect("未加密钥应当能登录");
        assert_eq!(out.stdout, "ok\n");
    }

    /// 指纹不对：必须在**送出公钥之前**就停下。
    ///
    /// 断言服务端收到的公钥认证次数为 0 —— 只看客户端返回值不够，
    /// 「拒绝了但又把换了个路径发一遍」这种错，只有服务端计数能抓住。
    #[test]
    fn a_pinned_fingerprint_is_enforced_before_a_key_is_sent() {
        let fixture = super::test_support::key_fixture();
        let server = super::test_support::start_key_server(&fixture.fingerprint);
        let key = Arc::new(fixture.key);
        let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let error = exec(
            &target(server.port),
            Auth::Key(&key),
            Some(wrong),
            "echo ok",
            Duration::from_secs(10),
        )
        .expect_err("指纹不一致必须拒绝");
        assert!(matches!(error, Error::HostKeyMismatch { .. }), "{error:?}");
        assert_eq!(
            server.publickey_attempts(),
            0,
            "身份没确认之前，公钥一个字节都不许发出去"
        );
    }

    /// RSA 私钥：必须协商 `rsa-sha2-*`（否则新版 OpenSSH 直接以
    /// "no mutual signature algorithm" 拒绝）。一条就够，RSA 生成慢。
    #[test]
    fn an_rsa_private_key_negotiates_a_sha2_signature() {
        let mut rng = russh::keys::key::safe_rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None })
            .expect("测试 RSA 密钥应当能生成");
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("RSA 钥应当能导出")
            .to_string();
        // 走一次真实的 PEM 解析：这条用例要覆盖的是「解析 + 认证」整条路。
        let credential = crate::credential::Credential::from_key_pem(&pem, None)
            .expect("RSA PEM 应当能解析");
        let server = super::test_support::start_key_server(&fingerprint);
        let out = exec(
            &target(server.port),
            Auth::from(&credential),
            Some(&server.fingerprint),
            "echo ok",
            Duration::from_secs(20),
        )
        .expect("RSA 私钥应当能登录");
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "ok\n");
    }

    #[test]
    fn probing_the_host_key_returns_the_fingerprint_without_authenticating() {
        let (port, fingerprint) = start_server();
        let probed = probe_host_key(&target(port), Duration::from_secs(10)).expect("应当能读到主机指纹");
        assert_eq!(probed, fingerprint);
    }

    #[test]
    fn a_target_spec_parses_with_and_without_a_port() {
        let plain = Target::parse("root@203.0.113.10").expect("默认端口");
        assert_eq!(plain, Target::new("203.0.113.10", 22, "root"));
        let explicit = Target::parse("root@node.example.com:2222").expect("显式端口");
        assert_eq!(explicit.port, 2222);
        assert_eq!(explicit.host, "node.example.com");
    }

    #[test]
    fn a_bad_target_spec_is_refused_with_the_reason() {
        assert!(Target::parse("root203.0.113.10").unwrap_err().contains("用户名@主机"));
        assert!(Target::parse("root@203.0.113.10:0").unwrap_err().contains("端口"));
        assert!(Target::parse("root@203.0.113.10:99999").unwrap_err().contains("端口"));
        assert!(Target::parse("@203.0.113.10").unwrap_err().contains("不能为空"));
        // IPv6 字面量必须明确拒绝：拆错了会连到一个能通但完全不对的地址。
        assert!(Target::parse("root@2001:db8::1").unwrap_err().contains("IPv6"));
    }

    /// 整条 CLI 链路：`--server-trust` 存下密码 → `--server-inspect` 直接复用。
    ///
    /// 为什么单列一条：前面那些用例验的是库函数，而这一条验的是**接线**——
    /// 参数怎么解析、密码从哪读、记录落在哪个根、第二次还会不会去要密码。
    /// 只有设了 `SPIDERVPN_TEST_EXE` 才跑：它要启动真正的 exe，
    /// 而 `CARGO_BIN_EXE_*` 只在集成测试里给，单元测试拿不到这个路径。
    #[test]
    fn the_cli_saves_a_trusted_server_and_reuses_its_credential() {
        let Ok(exe) = std::env::var("SPIDERVPN_TEST_EXE") else {
            eprintln!("跳过：未设置 SPIDERVPN_TEST_EXE（CLI 端到端只在手动验收时跑）");
            return;
        };
        use std::io::Write;
        use std::process::{Command, Stdio};

        let (port, fingerprint) = start_server();
        let spec = format!("root@127.0.0.1:{port}");
        let root = std::env::temp_dir().join(format!(
            "tcrs-cli-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        // 1) 信任：核对指纹 + 从标准输入读密码 + 落记录。
        let mut child = Command::new(&exe)
            .args(["--server-trust", &spec, "--fingerprint", &fingerprint])
            .env("SPIDERVPN_ROOT", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("应当能启动被测程序");
        child
            .stdin
            .as_mut()
            .expect("stdin 已接管")
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .expect("应当能写入密码");
        let out = child.wait_with_output().expect("等待被测程序");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "保存失败：{text}");
        assert!(text.contains("已保存服务器记录"), "{text}");

        // 记录落在**数据根**（`<SPIDERVPN_ROOT>\data`）下，不是安装根本身。
        let records = crate::serverstore::list(&root.join("data")).expect("应当能列出记录");
        assert_eq!(records.len(), 1, "应当只有一条记录：{records:?}");
        assert_eq!(records[0].fingerprint, fingerprint);

        // 2) 检查：**不给指纹、不给密码**，靠记录里的凭据完成。
        let out = Command::new(&exe)
            .args(["--server-inspect", &spec])
            .env("SPIDERVPN_ROOT", &root)
            .stdin(Stdio::null())
            .output()
            .expect("等待被测程序");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "复用凭据失败：{text}");
        assert!(text.contains("debian"), "应当打印环境摘要：{text}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
