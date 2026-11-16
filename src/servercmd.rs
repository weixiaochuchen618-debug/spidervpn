//! 「自己搭服务器」这条链路的编排：接本机、登记线路、一键全流程。
//!
//! 单独一个模块的理由：`main.rs` 只该管参数解析与退出码。这里的每一步都要么发 SSH、
//! 要么写本机状态，散在 `main` 里会让「哪一步失败、该退几号」变成一堆互不相干的 `return`。
//!
//! 与旧版的对应关系：`--server-setup` 就是它的「一键部署」——检查 → 装服务端 →
//! 装兼容连接 → 把本机接进去 → 登记线路，中间不需要用户再敲第二次命令。
//!
//! # 为什么拆成六个可分步函数（A2/A3 部署中心 T02）
//!
//! 部署要变成「可断点、可核对、可续跑」的任务，就不能再是「一次函数调用干到底」：
//!
//! | 函数 | 干什么 | 远程写 |
//! |---|---|---|
//! | [`resolve_identity`] | 有记录用记录，没有就先确认指纹再收密码 | 无（`probe_host_key` 只读） |
//! | [`check_environment`] | `deploy::inspect` 只读检查 | 无 |
//! | [`install_udp`] | 装包、写 `/etc/wireguard/<iface>.conf`、起服务 | **有** |
//! | [`install_transport_step`] | 装兼容连接（失败不拦整条流程） | **有** |
//! | [`attach_self`] | 本机密钥先落盘 → `add_peer` → 写 `client.conf` | **有** |
//! | [`register_lines_verified`] | 登记 1~2 条线路，**写完再读回来核一次** | 本机写 |
//!
//! [`setup`] 保留为**顺序调用这六个函数**的薄壳：命令行 `--server-setup` 与界面
//! 走的是同一段编排，行为与措辞一字不变。分成六段不是为了多几条路径，而是让上层
//! 能「做完一步、落一次盘、再决定下一步」——那正是崩溃后能续跑的前提。
//!
//! # 进度是结构化事件
//!
//! 每一步不再直接往一个 `FnMut(&str)` 里塞已经拼好的句子，而是发
//! [`StepEvent`]（步骤下标 + 种类 + 人话）。理由有两个：
//!
//! 1. 引擎要把它写进运行记录（哪一步、什么性质、什么时候），而记录里需要的
//!    是**结构化**的三元组，不是一句已经带好 `[2/4]` 前缀的字符串；
//! 2. `StepEvent` 的构造器**不接受任何秘密**（没有密码参数），从签名上堵死
//!    「顺手把密码拼进进度文本」这条路。
//!
//! 命令行仍然看到一模一样的中文行——由 [`render_event`] 统一渲染，措辞不变。

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{self, LineConfig, Transport};
use crate::deploy;
use crate::events::Origin;
use crate::pairing;
use crate::selfcheck;
use crate::serverstore;
use crate::ssh;

/// 本机的隧道私钥文件（在 `<root>\servers\<id>\` 下）。
///
/// 它存在的唯一理由：`add_peer` 成功之后、`client.conf` 写下去之前，进程要是死了，
/// 这把私钥就**永久丢失**，服务端留下一个谁也连不上的 peer。先把私钥落盘，
/// 再拿它去和服务端说话，崩溃后还能把这一步捞回来。
pub const TUNNEL_KEY_FILE: &str = "tunnel.key";

/// 登记好的一条线路（只带界面上要显示的三样东西）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub transport: Option<Transport>,
}

impl Registered {
    /// 界面上那一行怎么念。「兼容连接」三个字必须出现：两条线路名字只差后缀，
    /// 不说清楚用户会以为是重复导入。
    pub fn describe(&self) -> String {
        match self.transport {
            Some(Transport::Tcp) => format!("{}（{}，兼容连接）", self.name, self.endpoint),
            _ => format!("{}（{}，标准连接）", self.name, self.endpoint),
        }
    }
}

/// 一键部署的结果。界面靠它填「完成」页，命令行靠它打印摘要。
#[derive(Debug, Clone)]
pub struct SetupReport {
    pub address: String,
    /// 这一次是**自动**记住的服务器身份（旧版的 AutomaticFirstUse）。
    /// `None` = 用的是已有记录，或用户显式确认过指纹。
    pub auto_trusted_fingerprint: Option<String>,
    pub interface: String,
    pub udp_port: u16,
    /// `None` = 兼容连接没装上（标准连接那条仍然可用）。
    pub transport: Option<deploy::TransportInstalled>,
    pub lines: Vec<Registered>,
    /// 服务端本来就部署过，这一步跳过了安装。
    pub reused_server: bool,
}

impl SetupReport {
    /// 命令行完成摘要里「必须说出来」的那两句：自动记住的指纹、复用了已有部署。
    ///
    /// 这两条不是装饰。TOFU（没给指纹、按设置自动记住）**替用户做了一个安全决定**：
    /// 用户至少要知道「这一次没核对过，记下的是服务器现在出示的这枚指纹」，否则
    /// 「完成」二字等于把一次身份决定藏起来。`reused_server` 同理：跳过安装是
    /// 「重跑不打断」的结果，不说就会被当成「又装了一遍」。
    ///
    /// 每行自带标签（`身份    ：…`），调用方只负责缩进——这样断言可以直接盯着这句话，
    /// 不用在测试里把格式重拼一遍。
    pub fn notices(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(fingerprint) = &self.auto_trusted_fingerprint {
            lines.push(format!(
                "身份    ：这次没有给指纹，已按设置自动记住并采用服务器现在出示的 {fingerprint}；下次连接会按它核对。"
            ));
        }
        if self.reused_server {
            lines.push("服务端  ：本来就部署过，这次跳过了安装。".to_string());
        }
        lines
    }
}

/// 失败时带上「该退几号」。`code` 与 `crate::exit` 的常量一致，
/// 界面据此决定是提示重试还是让人改配置。
#[derive(Debug, Clone)]
pub struct SetupError {
    pub code: u8,
    pub message: String,
}

impl SetupError {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        SetupError {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 结构化进度事件
// ---------------------------------------------------------------------------

/// 「这条事件不属于任何一个步骤」（身份确认、主机指纹这类前置动作）。
pub const STEP_NOT_APPLICABLE: u8 = u8::MAX;

/// 进度事件的种类。**种类只有四种**：多一种就要多一处渲染与一处记录映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// 步骤开始（引擎据此把该步置 `Running`）。
    Start,
    /// 过程里的普通信息行。
    Detail,
    /// 值得醒目的内容（兼容连接没装上之类）。渲染时会自动加「！」。
    Warning,
    /// 不属于任何步骤的说明（主机指纹、服务器记录）。
    Note,
}

impl StepKind {
    /// 落盘用的机器名（记录里的 `Kind`）。**不是**给人看的文案。
    ///
    /// 引擎把事件写进运行记录时用它；T02 只做出来（有单测逐个断言），
    /// 所以本阶段暂时标为未使用。
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            StepKind::Start => "start",
            StepKind::Detail => "detail",
            StepKind::Warning => "warning",
            StepKind::Note => "note",
        }
    }
}

/// 一条进度事件：第几步、什么性质、人话。
///
/// 构造器只接受 `impl Into<String>` 的文案，**没有任何秘密参数**。这一条是硬的：
/// 进度文本会进记录、进日志、进界面，一旦能传秘密，迟早会有人传。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepEvent {
    pub step_idx: u8,
    pub kind: StepKind,
    pub message: String,
}

impl StepEvent {
    /// 某一步开始了。
    pub fn start(step_idx: u8, message: impl Into<String>) -> StepEvent {
        StepEvent {
            step_idx,
            kind: StepKind::Start,
            message: message.into(),
        }
    }

    /// 某一步的过程信息（缩进一行）。
    pub fn detail(step_idx: u8, message: impl Into<String>) -> StepEvent {
        StepEvent {
            step_idx,
            kind: StepKind::Detail,
            message: message.into(),
        }
    }

    /// 某一步出了值得醒目的情况（缩进一行并前置「！」）。
    pub fn warning(step_idx: u8, message: impl Into<String>) -> StepEvent {
        StepEvent {
            step_idx,
            kind: StepKind::Warning,
            message: message.into(),
        }
    }

    /// 不属于任何步骤的说明。
    pub fn note(message: impl Into<String>) -> StepEvent {
        StepEvent {
            step_idx: STEP_NOT_APPLICABLE,
            kind: StepKind::Note,
            message: message.into(),
        }
    }
}

/// 把结构化事件渲染成命令行那行文本。**措辞与拆分前逐字一致**：
///
/// - `Start` → `[3/4] …`
/// - `Detail` → `    …`
/// - `Warning` → `    ！…`
/// - `Note` → 原样（不带前缀、不缩进）
///
/// 渲染集中在这一处，是为了让「界面/命令行看到的中文」只有一个来源；
/// 引擎要的是事件本身，不需要这份文本。
pub fn render_event(event: &StepEvent) -> String {
    match event.kind {
        StepKind::Start => format!("[{}/4] {}", u16::from(event.step_idx) + 1, event.message),
        StepKind::Detail => format!("    {}", event.message),
        StepKind::Warning => format!("    ！{}", event.message),
        StepKind::Note => event.message.clone(),
    }
}

/// 事件出口的类型别名：六个分步函数都用它，测试里塞一个收集器就行。
pub type EventSink<'a> = &'a mut dyn FnMut(&StepEvent);

// ---------------------------------------------------------------------------
// 第 1 步：身份（本步**没有任何远程写**）
// ---------------------------------------------------------------------------

/// 已经确定的「服务器是谁 + 用什么凭据」。
///
/// `credential` 是秘密：只在内存里活着，不进记录、不进进度、不进日志。
/// 手写 `Debug`（`Credential` 刻意不派生）：只报「哪种登录方式」，不碰内容。
pub struct IdentityResolved {
    pub record: serverstore::ServerRecord,
    /// 登录凭据（**秘密**）。调用方用完即弃。
    pub credential: crate::credential::Credential,
    /// 这一次是自动记住的身份（`Some(指纹)`）；`None` = 已有记录或用户显式确认。
    pub auto_trusted: Option<String>,
}

impl std::fmt::Debug for IdentityResolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityResolved")
            .field("record", &self.record)
            .field("credential", &self.credential.kind())
            .field("auto_trusted", &self.auto_trusted)
            .finish()
    }
}

/// 第一次接触一台服务器时，主机身份从哪来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstTrust<'a> {
    /// 用户已经核对过、把指纹给了我们。
    Given(&'a str),
    /// 自动记住（TOFU）：读一次就采用，并在报告里标成「自动」。
    Remember,
    /// 既没给指纹、设置也关着：必须停下来问人。
    Ask,
}

/// 这个判断单独抽出来，是因为它决定了「要不要把密码交出去」——
/// 不能只藏在一条 `if let` 里，得能被逐条断言。
fn first_trust(given: Option<&str>, auto_trust: bool) -> FirstTrust<'_> {
    match given {
        Some(value) => FirstTrust::Given(value),
        None if auto_trust => FirstTrust::Remember,
        None => FirstTrust::Ask,
    }
}

/// 第 1 步：确定服务器身份与登录凭据。
///
/// 远程动作只有一个**只读**的 `probe_host_key`（确认「服务器现在拿的就是这枚指纹」），
/// 所以这一步不需要 `PendingOperation`，重跑也安全。
///
/// `auto_trust` = 「自动记住首次服务器身份」。只影响**第一次**接触一台服务器：
/// 为真时读一次指纹就直接采用（并标成自动），为假时必须由人给出指纹。
/// 已有记录 / 指纹变化都不受它影响——那不是「首次」，本就该拦。
pub fn resolve_identity(
    data_root: &Path,
    spec_text: &str,
    fingerprint: Option<&str>,
    credential: Option<&crate::credential::Credential>,
    auto_trust: bool,
    persist_credential: bool,
    origin: &Origin,
    emit: EventSink<'_>,
) -> Result<IdentityResolved, SetupError> {
    let target = ssh::Target::parse(spec_text)
        .map_err(|message| SetupError::new(crate::exit::USAGE, message))?;

    // 自动记住只在「首次接触」那一个分支里置位，最后原样报到界面上——
    // 「自动」这件事必须能被看见，不能悄悄发生。
    let mut auto_trusted: Option<String> = None;
    // 空凭据等于没给：空密码不该被当成「用户输入了新密码」写进信封。
    let typed = credential.filter(|item| item.is_usable());
    let (record, credential) = match serverstore::find_by_target(data_root, &target) {
        Ok(Some(record)) => {
            // 用户这次亲手输入的凭据**优先于**记录里封着的那一份。
            //
            // 以前这里无条件读信封：于是一份「只记身份、不记密码」的记录
            // （用户没勾「记住登录资料」）会变成「这台服务器再也登不上」——
            // 明明刚刚才把凭据递给过我们。
            match typed {
                Some(given) => {
                    let now = crate::model::now_epoch_secs_u64() as i64;
                    let updated = serverstore::trust_with_credential(
                        data_root,
                        &target,
                        &record.fingerprint,
                        given,
                        persist_credential,
                        now,
                    )
                    .map_err(|error| {
                        let code = if error.code == "ServerIdentityChanged" {
                            crate::exit::CONFLICT
                        } else {
                            crate::exit::CONFIG
                        };
                        SetupError::new(code, error.message)
                    })?;
                    (updated, given.duplicate())
                }
                None => {
                    let stored = serverstore::credential(data_root, &record).map_err(|error| {
                        SetupError::new(
                            crate::exit::ENVIRONMENT,
                            format!(
                                "{} 请重新保存一次登录凭据（--server-trust {} --fingerprint <指纹>）。",
                                error.message, spec_text
                            ),
                        )
                    })?;
                    // 信封本身是好的、里面的私钥却坏了（换过格式/被改过）：如实说出来，
                    // 不要退回「请输入密码」——那会让用户以为「记住」根本没生效。
                    let credential = stored.into_credential().map_err(|message| {
                        SetupError::new(crate::exit::ENVIRONMENT, message)
                    })?;
                    (record, credential)
                }
            }
        }
        Ok(None) => {
            let Some(given) = typed else {
                return Err(SetupError::new(
                    crate::exit::USAGE,
                    "第一次连接这台服务器需要登录凭据。".to_string(),
                ));
            };
            // 「自动记住首次服务器身份」只在这一个分支起作用：**没有记录、也没有人给指纹**。
            // 别的分支（已有记录、指纹变化）都不受影响——那不是「首次」。
            let (wanted, automatic) = match first_trust(fingerprint, auto_trust) {
                FirstTrust::Given(given) => {
                    // 保存前真连一次：确认服务器**现在**拿的就是这枚指纹。
                    emit(&StepEvent::note("正在核对主机指纹 …"));
                    match ssh::probe_host_key(&target, Duration::from_secs(15)) {
                        Ok(actual) if actual == given => {}
                        Ok(actual) => {
                            return Err(SetupError::new(
                                crate::exit::CONFLICT,
                                format!(
                                    "指纹不一致：你确认的是 {given}，服务器现在给的是 {actual}。"
                                ),
                            ))
                        }
                        Err(error) => {
                            return Err(SetupError::new(
                                crate::ssh_exit_code(&error),
                                error.to_string(),
                            ))
                        }
                    }
                    (given.to_string(), false)
                }
                FirstTrust::Remember => {
                    // TOFU：读一次、直接采用，但要**说出来**——自动记住不等于悄悄记住。
                    emit(&StepEvent::note("第一次连接这台服务器，正在读取主机身份 …"));
                    let actual = match ssh::probe_host_key(&target, Duration::from_secs(15)) {
                        Ok(actual) => actual,
                        Err(error) => {
                            return Err(SetupError::new(
                                crate::ssh_exit_code(&error),
                                error.to_string(),
                            ))
                        }
                    };
                    emit(&StepEvent::note(format!(
                        "已记住服务器身份：{actual}（自动；可在设置里关闭「自动记住首次服务器身份」）"
                    )));
                    (actual, true)
                }
                FirstTrust::Ask => {
                    return Err(SetupError::new(
                        crate::exit::CONFLICT,
                        format!("第一次连接 {spec_text}，需要先读取主机指纹并核对。"),
                    ));
                }
            };
            let now = crate::model::now_epoch_secs_u64() as i64;
            match serverstore::trust_with_credential(
                data_root,
                &target,
                &wanted,
                given,
                persist_credential,
                now,
            ) {
                Ok(record) if automatic => {
                    auto_trusted = Some(wanted);
                    (record, given.duplicate())
                }
                Ok(record) => {
                    emit(&StepEvent::note(format!(
                        "已保存服务器记录：{}",
                        record.address()
                    )));
                    (record, given.duplicate())
                }
                Err(error) => {
                    let code = if error.code == "ServerIdentityChanged" {
                        crate::exit::CONFLICT
                    } else {
                        crate::exit::CONFIG
                    };
                    return Err(SetupError::new(code, error.message));
                }
            }
        }
        Err(error) => return Err(SetupError::new(crate::exit::CONFIG, error.message)),
    };

    // 「谁在哪台机器上确认了身份」要留痕。**不含凭据**，也不含任何可复原的内容。
    let detail = format!(
        "{} 身份 {}",
        record.address(),
        if auto_trusted.is_some() { "自动记住" } else { "沿用/已确认" }
    );
    crate::events::record(data_root, "部署：确认服务器身份", true, &detail, origin);

    Ok(IdentityResolved {
        record,
        credential,
        auto_trusted,
    })
}

// ---------------------------------------------------------------------------
// 第 2 步：只读检查
// ---------------------------------------------------------------------------

/// 第 2 步：只读检查这台机器够不够格装我们的服务。
///
/// **没有任何远程写**：`deploy::inspect` 只读。环境不合格直接报 `environment`，
/// 一个字节都不改。
pub fn check_environment<'a>(
    record: &serverstore::ServerRecord,
    auth: impl Into<ssh::Auth<'a>>,
    spec: &deploy::Spec,
    emit: EventSink<'_>,
) -> Result<deploy::Environment, SetupError> {
    let address = record.address();
    emit(&StepEvent::start(0, format!("检查 {address} 的环境 …")));
    let environment = deploy::inspect(
        &record.target(),
        auth,
        Some(&record.fingerprint),
        Some(&spec.interface),
        Duration::from_secs(30),
    )
    .map_err(|error| SetupError::new(crate::ssh_exit_code(&error), error.to_string()))?;
    for line in environment.summary().lines() {
        emit(&StepEvent::detail(0, line.to_string()));
    }
    if let Some(reason) = environment.blocking_reason() {
        return Err(SetupError::new(
            crate::exit::ENVIRONMENT,
            format!("这台服务器不能部署：{reason}"),
        ));
    }
    Ok(environment)
}

// ---------------------------------------------------------------------------
// 第 3 步：标准连接（UDP）
// ---------------------------------------------------------------------------

/// 标准连接这一步的结果。
///
/// `installed` 为 `None` 有且只有一种情况：隧道本来就起着（`reused`），
/// 这一步什么都没做。之所以不是直接返回 `deploy::Installed`，是因为
/// 「复用已有部署」根本拿不到 `Installed`——硬要造一个就等于伪造证据。
#[derive(Debug, Clone)]
pub struct UdpStep {
    /// 这次真的装出什么（`reused` 时为 `None`）。引擎要把它写进 `Steps[1].Evidence`。
    /// T02 阶段 `setup()` 只用 `reused`，所以暂时标为未使用。
    #[allow(dead_code)]
    pub installed: Option<deploy::Installed>,
    pub reused: bool,
}

/// 第 3 步：装标准连接（WireGuard + NAT）。**有远程写。**
///
/// 上层必须**先落 `PendingOperation` 再调它**：它一进去就可能改服务器。
pub fn install_udp<'a>(
    record: &serverstore::ServerRecord,
    auth: impl Into<ssh::Auth<'a>>,
    spec: &deploy::Spec,
    environment: &deploy::Environment,
    emit: EventSink<'_>,
) -> Result<UdpStep, SetupError> {
    let reused = environment
        .tunnel
        .as_ref()
        .map(|tunnel| tunnel.up)
        .unwrap_or(false);
    if reused {
        emit(&StepEvent::start(
            1,
            format!("服务端已部署（{}），跳过安装。", spec.interface),
        ));
        return Ok(UdpStep {
            installed: None,
            reused: true,
        });
    }
    emit(&StepEvent::start(1, "安装服务端（WireGuard + NAT）…"));
    let installed = deploy::install(
        &record.target(),
        auth,
        &record.fingerprint,
        spec,
        Duration::from_secs(300),
    )
    .map_err(|error| SetupError::new(crate::ssh_exit_code(&error), error.to_string()))?;
    emit(&StepEvent::detail(
        1,
        format!(
            "接口 {}（{}），UDP {}",
            installed.interface, installed.interface_address, installed.port
        ),
    ));
    Ok(UdpStep {
        installed: Some(installed),
        reused: false,
    })
}

// ---------------------------------------------------------------------------
// 第 4 步：兼容连接（TCP）
// ---------------------------------------------------------------------------

/// 第 4 步：装兼容连接。**有远程写。**
///
/// 失败**不拦整条流程**：标准连接那条已经可用，为了一条备选把已经装好的东西回滚掉
/// 只会让用户白折腾一遍。但必须醒目地说出来，所以返回 `Ok(None)` + 两条 `warning`
/// 事件，而不是 `Err`。
///
/// 身份私钥只在服务器 `/etc/tradechannel/transport.env`：`new_identity` 生成的私钥
/// 直接进脚本，**本机不落、不进记录**。
pub fn install_transport_step<'a>(
    record: &serverstore::ServerRecord,
    auth: impl Into<ssh::Auth<'a>>,
    spec: &deploy::Spec,
    emit: EventSink<'_>,
) -> Result<Option<deploy::TransportInstalled>, SetupError> {
    emit(&StepEvent::start(
        2,
        format!("安装兼容连接（TCP {}）…", spec.tcp_port()),
    ));
    let identity = deploy::new_identity_with(spec.tcp_port(), spec.tcp_server_name()).map_err(
        |message| {
            SetupError::new(
                crate::exit::INTERNAL,
                format!("生成传输身份失败：{message}"),
            )
        },
    )?;
    match deploy::install_transport(
        &record.target(),
        auth,
        &record.fingerprint,
        spec,
        &record.host,
        &identity,
        Duration::from_secs(420),
    ) {
        Ok(installed) => {
            emit(&StepEvent::detail(
                2,
                format!(
                    "TCP {}，握手域名 {}（组件 {}，身份 {}）",
                    installed.port,
                    installed.server_name,
                    match installed.component.as_str() {
                        "reused" => "复用已装",
                        _ => "本次新装",
                    },
                    match installed.identity.as_str() {
                        "reused" => "复用已有",
                        _ => "本次新建",
                    }
                ),
            ));
            Ok(Some(installed))
        }
        Err(error) => {
            // 兼容连接装不上不该拦着整个流程：标准连接那条已经可用。
            // 但必须醒目——UDP 被拦的网络里，它是唯一的出路。
            emit(&StepEvent::warning(
                2,
                format!("兼容连接没有装上：{error}"),
            ));
            emit(&StepEvent::warning(
                2,
                "本次只登记标准连接，稍后可以单独重试兼容连接。",
            ));
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// 第 5 步：把本机接进去
// ---------------------------------------------------------------------------

/// 第 5 步的结果：服务器接受了本机，本机的 `client.conf` 也已经落盘。
///
/// 私钥**不在**这个结构里（它在 `client.conf` 与 `tunnel.key` 两个文件里）；
/// 这里只留 `parsed`，它是登记线路要用的参数视图（本身也不含私钥）。
#[derive(Debug, Clone)]
pub struct Attachment {
    /// 服务端的回答（服务端公钥 + 已登记的客户端公钥）。引擎要把这两样写进证据。
    /// T02 阶段 `setup()` 只用 `parsed`，所以暂时标为未使用。
    #[allow(dead_code)]
    pub ack: deploy::PeerAck,
    /// 这条服务器的目录（`tunnel.key` / `client.conf` 都在这儿）。
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub parsed: pairing::line::ClientConf,
}

/// 第 5 步：把本机接进服务器。**有远程写**（`add_peer`）。
///
/// 次序是硬要求，不是风格：**先把私钥落到 `tunnel.key`，再拿公钥去和服务端说话**。
/// 反过来一旦 `add_peer` 成功而 `client.conf` 还没写就崩了，那把私钥就永久消失，
/// 服务器上留一个谁也连不上的 peer。
pub fn attach_self<'a>(
    data_root: &Path,
    record: &serverstore::ServerRecord,
    auth: impl Into<ssh::Auth<'a>>,
    spec: &deploy::Spec,
    emit: EventSink<'_>,
) -> Result<Attachment, SetupError> {
    emit(&StepEvent::start(3, "把本机接进去 …"));
    let dir = data_root.join("servers").join(&record.id);
    let (client_private, client_public) = ensure_tunnel_key(&dir);
    let ack = deploy::add_peer(
        &record.target(),
        auth,
        &record.fingerprint,
        spec,
        &client_public,
        Duration::from_secs(120),
    )
    .map_err(|error| SetupError::new(crate::ssh_exit_code(&error), error.to_string()))?;

    let conf = deploy::client_conf(spec, &ack.server_public, &record.host, &client_private);
    std::fs::create_dir_all(&dir)
        .map_err(|e| SetupError::new(crate::exit::CONFIG, format!("创建服务器目录失败：{e}")))?;
    // 走 secretfile：文件一出现就是「只有本人/管理员/SYSTEM 可读」，不给别人留窗口。
    crate::secretfile::write(&dir.join("client.conf"), &conf).map_err(|e| {
        SetupError::new(
            crate::exit::CONFIG,
            format!("写 client.conf 失败（设置文件访问权限也会在这一步）：{e}"),
        )
    })?;
    let parsed = pairing::line::parse_client_conf(&conf).map_err(|error| {
        SetupError::new(
            crate::exit::INTERNAL,
            format!("生成的客户端配置没有通过自检：{}", error.message),
        )
    })?;
    Ok(Attachment { ack, dir, parsed })
}

// ---------------------------------------------------------------------------
// 第 6 步：登记线路（本机写）+ 写后核对
// ---------------------------------------------------------------------------

/// 第 6 步：登记 1~2 条线路，**写完再读回来核一次**。
///
/// 「登记成功」不能只看 `register_lines` 有没有返回 `Ok`：它写的是
/// `config.json` 与 `lines\<id>.json` 两处，任何一处没落下来，「完成」就是假的。
/// 所以这里做完再看一眼：`config.json` 里能读到这条线路，且它的线路文件能解析。
pub fn register_lines_verified(
    data_root: &Path,
    host: &str,
    parsed: &pairing::line::ClientConf,
    compatible: Option<&pairing::line::Compatible>,
    preferred: Option<config::Transport>,
    origin: &Origin,
) -> Result<Vec<Registered>, SetupError> {
    let lines = register_lines(data_root, host, parsed, compatible, preferred, origin)
        .map_err(|message| SetupError::new(crate::exit::CONFIG, message))?;

    let cfg_path = data_root.join(config::DEFAULT_PATH);
    let cfg = match config::load(&cfg_path) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return Err(SetupError::new(
                crate::exit::CONFIG,
                "登记线路之后配置文件不见了。".to_string(),
            ))
        }
        Err(error) => {
            return Err(SetupError::new(
                crate::exit::CONFIG,
                format!("登记线路之后读不回 config.json：{error}"),
            ))
        }
    };
    for line in &lines {
        let Some(entry) = cfg.lines.iter().find(|item| item.id == line.id) else {
            return Err(SetupError::new(
                crate::exit::CONFIG,
                format!("线路「{}」没有登记进 config.json。", line.name),
            ));
        };
        let path = entry.engine_config_path(data_root);
        match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => {}
            _ => {
                return Err(SetupError::new(
                    crate::exit::CONFIG,
                    format!("线路「{}」的配置文件没有落盘。", line.name),
                ))
            }
        }
    }
    Ok(lines)
}

// ---------------------------------------------------------------------------
// 本机密钥：先落盘再说话
// ---------------------------------------------------------------------------

/// 本机的隧道私钥：`client.conf` → `tunnel.key` → 新生成并先落盘。
///
/// 复用不是优化，是正确性：每重跑一次就换一把新密钥，服务端就会累积一堆谁也用不上的
/// peer，而用户看到的只是「peer 列表越来越长」——等到哪天真要清理，已经分不清哪个是活的。
///
/// 三级顺序的理由：
/// 1. `client.conf` 是「已经接过一次」的老路径，它里面的私钥就是服务端认识的那把；
/// 2. `tunnel.key` 是「`add_peer` 成功了但 `client.conf` 还没写」的救命路径；
/// 3. 都没有才新生成——**生成之后立刻原子落盘**，再去和服务器说话。
///
/// 落盘失败时不返回错误：这一次接入仍然能成（密钥在内存里），只是崩溃后无法续。
/// 把它变成错误反而会拦住一次本来能完成的部署 —— 代价比「少一条续跑线索」更大。
///
/// 读到已有文件时**顺手收紧访问权限**（F1）：升级上来的 `client.conf` 是继承来的
/// `BUILTIN\Users:(RX)`，别人能读走私钥。收紧失败不改返回值——这次部署仍要继续，
/// 但启动扫描（`secretfile::tighten_data_root`）还会再试一次并报出来。
pub fn ensure_tunnel_key(dir: &Path) -> (String, String) {
    let path = dir.join("client.conf");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(conf) = pairing::line::parse_client_conf(&text) {
            if let Ok(public) = pairing::keys::tunnel_public_from_private_b64(&conf.private_key) {
                let _ = crate::secretfile::tighten(&path);
                return (conf.private_key, public);
            }
        }
    }

    let stored = dir.join(TUNNEL_KEY_FILE);
    if let Ok(text) = std::fs::read_to_string(&stored) {
        let private = text.trim().to_string();
        if !private.is_empty() {
            if let Ok(public) = pairing::keys::tunnel_public_from_private_b64(&private) {
                let _ = crate::secretfile::tighten(&stored);
                return (private, public);
            }
        }
    }

    let (private, public) = pairing::keys::tunnel_keypair();
    let _ = write_private(&stored, &private);
    (private, public)
}

/// 本机的隧道私钥。对外签名保持不变，内部走 [`ensure_tunnel_key`]。
pub fn client_tunnel_key(dir: &Path) -> (String, String) {
    ensure_tunnel_key(dir)
}

/// 原子写一个含私钥的文件：临时文件 → 收紧 → 写 → `sync_all` → `rename`。
///
/// 平台差异已经收进 [`crate::secretfile`]：Unix 是 `0600`，Windows 是 DACL
/// （`SY` + `BA` + 所有者，受保护、不继承）。这里原来那句「Windows 不必单独设 ACL」
/// 是错的——数据根不在用户目录下，继承来的是 `BUILTIN\Users:(RX)`。
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    crate::secretfile::write(path, text)
}

// ---------------------------------------------------------------------------
// 登记线路（本体不变）
// ---------------------------------------------------------------------------

/// 把本机接进服务器之后要做的本机部分：生成 1~2 条线路并登记。
///
/// `compatible` 为 `Some` 时**同时**登记兼容连接那条。两条线路共用同一份 WireGuard
/// 身份（`parsed`），差别只在「WireGuard 的 UDP 包走不走 REALITY 中转」——这正是
/// 旧版两个 profile 的关系，只是这里落成两条线路而不是一条线路的两个档位。
///
/// 幂等：同名 = 同一条线路（`line_id` 的约定），重跑是更新而不是新增，
/// 并且**沿用原来的端口**（端口一换，系统代理和已保存的运行时配置就都指错了地方）。
pub fn register_lines(
    data_root: &Path,
    host: &str,
    parsed: &pairing::line::ClientConf,
    compatible: Option<&pairing::line::Compatible>,
    preferred: Option<Transport>,
    origin: &Origin,
) -> Result<Vec<Registered>, String> {
    let cfg_path = data_root.join(config::DEFAULT_PATH);
    let mut cfg = match config::load(&cfg_path) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => pairing::line::empty_config(),
        Err(error) => return Err(format!("读取线路配置失败（请先修好 config.json）：{error}")),
    };

    // **一条线路、两种连接方式**（旧版的做法）：名字不再带「（兼容连接）」，
    // 兼容参数写进线路的附属文件（`lines\<id>.compatible.json`），连与切时按需注入。
    //
    // 之前建两条线路是错的：同一台服务器出现两张卡片，而卡片上的「标准/兼容」开关对标准
    // 那条按不动（它的文件里没有 VLESS 参数）——开关等于摆设，用户只能靠换卡片来换方式。
    let name = format!("自建 · {host}");
    let id = pairing::line::line_id(&cfg, &name);
    // 「自动」不是「改回标准」：重跑一次就把用户选好的兼容连接拨回标准，
    // 在 UDP 被拦的网络里等于把唯一能用的那条换成连不上的。
    let existing_transport = cfg
        .lines
        .iter()
        .find(|line| line.id == id)
        .and_then(|line| line.transport);
    let transport = preferred.or(existing_transport);
    // 已经登记过的线路沿用原端口；新线路才从区间里挑。
    let keep = cfg
        .lines
        .iter()
        .find(|line| line.id == id)
        .and_then(|line| selfcheck::port_from_endpoint(&line.proxy_endpoint));
    let port = pairing::line::choose_port(&cfg, &id, keep).map_err(|e| e.message.clone())?;
    let mut body = pairing::line::build(parsed, compatible, port, cfg.mode, &cfg.split, &cfg.agents)
        .map_err(|e| format!("生成「{name}」失败：{}", e.message))?;
    // 用户这次显式选了兼容：落盘的线路文件也要是兼容态（否则配置说 Tcp、文件是标准，
    // 连接时才派生，检查过的东西和连的东西不是同一份）。
    if transport == Some(Transport::Tcp) {
        if let Some(params) = compatible {
            let mut root: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("线路配置无法回读：{e}"))?;
            let obj = root
                .as_object_mut()
                .ok_or_else(|| "线路配置顶层必须是对象".to_string())?;
            let ours = config::LineCompatible {
                server: params.server.clone(),
                port: params.port,
                uuid: params.uuid.clone(),
                server_name: params.server_name.clone(),
                reality_public_key: params.reality_public_key.clone(),
                reality_short_id: params.reality_short_id.clone(),
            };
            crate::engine_config::apply_transport_with(obj, Transport::Tcp, Some(&ours))
                .map_err(|e| format!("生成「{name}」的兼容连接版本失败：{e}"))?;
            body = serde_json::to_string_pretty(&root)
                .map_err(|e| format!("兼容连接版本无法序列化：{e}"))?;
        }
    }
    let line = LineConfig {
        id: id.clone(),
        name: name.clone(),
        proxy_endpoint: format!("127.0.0.1:{port}"),
        transport,
        // 自建线路是刚生成的一份新参数，没有任何验证依据。
        verified_transport: None,
    };
    pairing::line::register(data_root, &mut cfg, &line, &body, origin)
        .map_err(|e| e.message.clone())?;
    // 兼容参数最后落：线路已经登记成功，附属文件写失败也不能把已经建好的线路撤掉，
    // 但要如实报错——否则用户以为「一台服务器两种方式」，实际只有标准。
    if let Some(params) = compatible {
        let ours = config::LineCompatible {
            server: params.server.clone(),
            port: params.port,
            uuid: params.uuid.clone(),
            server_name: params.server_name.clone(),
            reality_public_key: params.reality_public_key.clone(),
            reality_short_id: params.reality_short_id.clone(),
        };
        line.save_compatible(data_root, &ours)
            .map_err(|e| format!("保存兼容连接参数失败：{e}"))?;
    }
    Ok(vec![Registered {
        id,
        name,
        endpoint: line.proxy_endpoint,
        transport,
    }])
}

// ---------------------------------------------------------------------------
// 一键部署：顺序调用六个步骤的薄壳
// ---------------------------------------------------------------------------

/// 把上一版留下的成对线路并成一条（幂等）。
///
/// 上一版的做法是「同一台服务器登记两条线路」：`自建 · host` 与 `自建 · host（兼容连接）`。
/// 后果是真机撞到的那个：两张卡片说的是同一台机器，而卡片上那颗「标准/兼容」开关对前者
/// 按不动——标准线路的文件里根本没有 VLESS 参数。
///
/// 现在改成一条线路两套方式（旧版的做法），这里把已经产生的成对线路收口：
/// 1. 从兼容那条的线路文件里读出参数，落成标准那条的附属文件；
/// 2. 如果选中的是兼容那条，改成选中标准那条并把它的方式设成 Tcp（用户本来就在用兼容）；
/// 3. 配置落盘成功**之后**才删旧的线路文件与附属文件——顺序反了会留下「配置指向不存在的文件」。
///
/// 任何一步不成立（读不到参数、名字对不上）就跳过那一条，绝不猜参数。
pub fn merge_compatible_lines(root: &Path) -> Result<usize, String> {
    let cfg_path = root.join(config::DEFAULT_PATH);
    // 这里只检查是否需要合并：不能因为检查本身就把 schema 1 配置写成 schema 2。
    // 真正的迁移提示与落盘由 main 的首次写命令统一负责。
    let Some(mut cfg) = config::load_readonly(&cfg_path).map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    let suffix = "（兼容连接）";
    // 先只读地把「成对」找出来：并的过程中不能一边持有引用一边改 cfg。
    let mut todo: Vec<(String, String, crate::config::LineCompatible)> = Vec::new();
    for line in &cfg.lines {
        let Some(base_name) = line.name.strip_suffix(suffix) else { continue };
        if base_name.trim().is_empty() {
            continue;
        }
        let Some(base) = cfg
            .lines
            .iter()
            .find(|other| other.id != line.id && other.name == base_name)
        else {
            continue; // 兄弟不在了（用户删过）：这条就当独立线路留着，不擅自删
        };
        let Ok(text) = std::fs::read_to_string(line.engine_config_path(root)) else {
            continue; // 读不到线路文件：宁可不并，也不能凭空造参数
        };
        let Some(params) = crate::engine_config::compatible_from_body(&text) else {
            continue;
        };
        todo.push((line.id.clone(), base.id.clone(), params));
    }
    if todo.is_empty() {
        return Ok(0);
    }
    let mut removed: Vec<String> = Vec::new();
    for (compat_id, base_id, params) in &todo {
        let Some(base) = cfg.lines.iter().find(|line| &line.id == base_id) else {
            continue;
        };
        base.save_compatible(root, params)
            .map_err(|e| format!("写兼容参数失败（{base_id}）：{e}"))?;
        if &cfg.selected == compat_id {
            cfg.selected = base_id.clone();
            if let Some(target) = cfg.lines.iter_mut().find(|line| &line.id == base_id) {
                // 用户当时选的是兼容那条 = 他要用兼容；并过来之后方式跟着走。
                target.transport = Some(Transport::Tcp);
            }
        }
        removed.push(compat_id.clone());
    }
    if removed.is_empty() {
        return Ok(0);
    }
    cfg.lines.retain(|line| !removed.iter().any(|id| id == &line.id));
    // 走带来源的保存：操作记录里要看得出这条是「程序自己收口」而不是用户点了什么。
    config::save_with_origin(&cfg_path, &cfg, &crate::events::Origin::other())
        .map_err(|e| format!("保存合并后的配置失败：{e}"))?;
    for id in &removed {
        let _ = std::fs::remove_file(config::engine_config_path_for(root, id));
        let _ = std::fs::remove_file(config::compatible_path_for(root, id));
    }
    Ok(removed.len())
}

/// 一键部署：检查 → 装服务端 → 装兼容连接 → 把本机接进去 → 登记线路。
///
/// 三条设计约束（与旧版的「一键部署」对齐）：
///
/// 1. **第一次连一台没见过的机器必须停下来确认指纹**。TOFU 是安全边界，
///    自动化掉它就等于「谁来都连」。确认过之后（记录已存）才是真一键。
/// 2. **兼容连接失败不拦着整个流程**。标准连接那条已经可用，为了一条备选
///    把已经装好的东西回滚掉，只会让用户白折腾一遍。但必须醒目地说出来。
/// 3. **重跑不打断**。服务端已部署就跳过安装；线路同名即更新、端口沿用原值、
///    peer 用同一把密钥。重装一次是用户排障的第一反应，那一步要是把现有连接换掉了，
///    排障就变成添乱。
///
/// `password` / `fingerprint` 只在「还没有服务器记录」时用得上：已有记录时走 DPAPI
/// 里那份凭据，调用方传什么都不看。命令行这条入口只有密码（没有私钥参数），
/// 私钥登录只从界面/引擎进来——见 [`resolve_identity`] 的 `credential` 参数。
///
/// 这个函数**只有一份编排**（依次调六个步骤，一句多余的话都不说）：界面与命令行
/// 都从这里走，所以不可能出现「命令行能装、界面装不上」那种漂移。上层要做
/// 「分步 + 落盘 + 断点续跑」（A2/A3 的引擎），就直接调那六个函数，别抄这一段。
pub fn setup(
    data_root: &Path,
    spec_text: &str,
    fingerprint: Option<&str>,
    password: Option<&str>,
    auto_trust: bool,
    origin: &Origin,
    progress: &mut dyn FnMut(&str),
) -> Result<SetupReport, SetupError> {
    // 命令行那条入口只认字符串行；这里把它包成事件消费者，
    // 渲染走 `render_event`，所以输出的中文与拆分前逐字一致。
    let mut emit = |event: &StepEvent| {
        let line = render_event(event);
        progress(&line);
    };

    // 命令行只有密码这条路（`--server-trust`/`--server-setup` 没有私钥参数），
    // 所以这里包成 `Credential::password`。空串在这里被 `is_usable()` 过滤成「没给」。
    let typed = password.map(|text| crate::credential::Credential::password(text));
    let resolved = resolve_identity(
        data_root,
        spec_text,
        fingerprint,
        typed.as_ref(),
        auto_trust,
        // 命令行这一条路径永远落盘：`--server-setup` / `--server-trust` 的语义
        // 本来就是「把这台服务器记下来」。只有界面上的勾选才有「不记」这一档。
        true,
        origin,
        &mut emit,
    )?;
    let spec = deploy::Spec::for_record(&resolved.record.id);
    if let Err(message) = spec.validate() {
        return Err(SetupError::new(crate::exit::USAGE, message));
    }

    let environment = check_environment(&resolved.record, &resolved.credential, &spec, &mut emit)?;
    let udp = install_udp(
        &resolved.record,
        &resolved.credential,
        &spec,
        &environment,
        &mut emit,
    )?;
    let transport =
        install_transport_step(&resolved.record, &resolved.credential, &spec, &mut emit)?;
    let attachment = attach_self(
        data_root,
        &resolved.record,
        &resolved.credential,
        &spec,
        &mut emit,
    )?;
    let params = transport
        .as_ref()
        .map(|item| item.compatible(&resolved.record.host));
    let lines = register_lines_verified(
        data_root,
        &resolved.record.host,
        &attachment.parsed,
        params.as_ref(),
        // 命令行没有「默认连接方式」这个选项：沿用自动（与旧行为一致）。
        None,
        origin,
    )?;

    Ok(SetupReport {
        address: resolved.record.address(),
        auto_trusted_fingerprint: resolved.auto_trusted,
        interface: spec.interface,
        udp_port: spec.port,
        transport,
        lines,
        reused_server: udp.reused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-servercmd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn conf() -> pairing::line::ClientConf {
        pairing::line::parse_client_conf(
            "[Interface]\r\n\
             PrivateKey = d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=\r\n\
             Address = 10.66.0.2/32\r\n\
             MTU = 1380\r\n\
             \r\n\
             [Peer]\r\n\
             PublicKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\r\n\
             AllowedIPs = 0.0.0.0/0\r\n\
             Endpoint = 203.0.113.10:51820\r\n\
             PersistentKeepalive = 25\r\n",
        )
        .expect("这份配置必须能解析")
    }

    fn compatible() -> pairing::line::Compatible {
        pairing::line::Compatible {
            server: "203.0.113.10".to_string(),
            port: 8443,
            uuid: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string(),
            server_name: "www.bing.com".to_string(),
            reality_public_key: "yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk".to_string(),
            reality_short_id: "0123456789abcdef".to_string(),
        }
    }

    /// 自动记住指纹时必须说出来：那是替用户做的一次身份决定，藏在「完成」后面
    /// 等于没说。反过来，用户自己确认过指纹、也没复用部署时，一个字都不该多。
    #[test]
    fn the_completion_report_says_when_the_fingerprint_was_auto_trusted() {
        let mut report = SetupReport {
            address: "root@203.0.113.10:22".to_string(),
            auto_trusted_fingerprint: Some("SHA256:AbCdEf".to_string()),
            interface: "tc0".to_string(),
            udp_port: 8443,
            transport: None,
            lines: Vec::new(),
            reused_server: true,
        };
        let notices = report.notices();
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(
            notices[0].contains("自动记住") && notices[0].contains("SHA256:AbCdEf"),
            "要说清「记下的是哪一枚」：{}",
            notices[0]
        );
        assert!(
            notices[0].contains("下次连接会按它核对"),
            "还要说清这枚指纹以后怎么用：{}",
            notices[0]
        );
        assert!(
            !notices[0].contains("你确认"),
            "自动记住不是用户确认的，不许这么写：{}",
            notices[0]
        );
        assert!(
            notices[1].contains("跳过了安装"),
            "复用了已有部署也要说：{}",
            notices[1]
        );

        // 用户自己给过指纹、服务端也是新装的：不该多出任何一句话。
        report.auto_trusted_fingerprint = None;
        report.reused_server = false;
        assert!(report.notices().is_empty());
    }

    /// 「首次接触怎么决定」三种组合，逐条断言——这条链决定要不要把密码交出去。
    #[test]
    fn first_trust_follows_the_switch_only_when_nobody_gave_a_fingerprint() {
        // 人已经核对过：用它，与设置无关。
        assert_eq!(first_trust(Some("SHA256:AAA"), true), FirstTrust::Given("SHA256:AAA"));
        assert_eq!(first_trust(Some("SHA256:AAA"), false), FirstTrust::Given("SHA256:AAA"));
        // 没给指纹 + 设置开 = 自动记住（TOFU）。
        assert_eq!(first_trust(None, true), FirstTrust::Remember);
        // 没给指纹 + 设置关 = 必须停下来问人。
        assert_eq!(first_trust(None, false), FirstTrust::Ask);
    }

    /// 没有兼容参数时只登记一条，而且选中它。
    #[test]
    fn without_compatible_parameters_only_the_standard_line_is_registered() {
        let root = temp_root("standard");
        let origin = Origin::cli();
        let lines =
            register_lines(&root, "203.0.113.10", &conf(), None, None, &origin).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].transport, None);
        assert!(lines[0].name.contains("自建"));
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 1);
        assert_eq!(cfg.selected, cfg.lines[0].id);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 两条都登记时，**选中的必须是标准连接那条**（兼容连接是备选，不是默认）。
    /// 老数据结构收口：成对线路并成一条——参数进附属文件、选中项跟过来、旧文件删掉，幂等。
    #[test]
    fn merging_an_old_pair_keeps_one_line_with_both_methods() {
        let root = temp_root("merge");
        let origin = Origin::cli();
        let base_name = "自建 · 203.0.113.10".to_string();
        let cfg_text = format!(
            r#"{{"schema":2,"selected":"B","lines":[
                {{"id":"A","name":"{base_name}","proxy_endpoint":"127.0.0.1:17911"}},
                {{"id":"B","name":"{base_name}（兼容连接）","proxy_endpoint":"127.0.0.1:17912","transport":"tcp"}}]}}"#
        );
        let mut cfg = crate::config::parse(&cfg_text).unwrap();
        crate::config::save_with_origin(&root.join(crate::config::DEFAULT_PATH), &cfg, &origin).unwrap();
        std::fs::create_dir_all(root.join("lines")).unwrap();
        let standard = pairing::line::build(
            &conf(),
            Some(&compatible()),
            17911,
            crate::config::Mode::Proxy,
            &crate::config::SplitConfig::default(),
            &crate::config::AgentsConfig::default(),
        )
        .unwrap();
        let tcp_body = crate::engine_config::derive(&standard, Transport::Tcp).unwrap();
        std::fs::write(root.join("lines").join("A.json"), standard.as_bytes()).unwrap();
        std::fs::write(root.join("lines").join("B.json"), tcp_body.as_bytes()).unwrap();

        let merged = merge_compatible_lines(&root).unwrap();
        assert_eq!(merged, 1, "成对线路必须并成一条");
        cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 1, "并完只剩一条");
        assert_eq!(cfg.selected, "A", "选中的是兼容那条 → 并过来还是选中同一条线路");
        assert_eq!(cfg.lines[0].transport, Some(Transport::Tcp), "用户本来就在用兼容，方式跟过来");
        assert!(cfg.lines[0].load_compatible(&root).is_some(), "参数必须落成附属文件");
        assert!(!root.join("lines").join("B.json").exists(), "旧的第二条线路文件要删掉");
        assert_eq!(merge_compatible_lines(&root).unwrap(), 0, "再跑一次什么也不做");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一台服务器 = **一条线路、两套方式**（旧版的做法）。
    ///
    /// 兼容参数落在线路自己的附属文件里，默认方式是标准；线路文件本身必须是干净的标准档，
    /// 而「能不能切兼容」由附属文件兜住——这正是上一版做错的地方（两条线路，开关还按不动）。
    #[test]
    fn one_line_carries_both_methods_and_the_params_land_in_its_own_file() {
        let root = temp_root("both");
        let origin = Origin::cli();
        let lines = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            None,
            &origin,
        )
        .unwrap();
        assert_eq!(lines.len(), 1, "同一台服务器只登记一条线路");
        assert_eq!(lines[0].transport, None, "默认是标准连接");

        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 1, "配置里也只有一条");
        let line = cfg.lines.iter().find(|l| l.id == cfg.selected).expect("选中的必须存在");
        let params = line.load_compatible(&root).expect("兼容参数必须落成线路的附属文件");
        let expect = compatible();
        assert_eq!(params.port, expect.port);
        assert_eq!(params.uuid, expect.uuid);
        assert_eq!(params.server_name, expect.server_name);

        let path = line.engine_config_path(&root);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!crate::engine_config::tcp_shaped(&text), "默认态的线路文件必须是标准档");
        crate::engine_config::check_transport(&path, Transport::Tcp)
            .expect("有附属参数就必须能在同一条线路上切到兼容");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn rerunning_updates_in_place_and_keeps_the_ports() {
        let root = temp_root("rerun");
        let origin = Origin::cli();
        let first = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            None,
            &origin,
        )
        .unwrap();
        let again = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            None,
            &origin,
        )
        .unwrap();
        assert_eq!(first, again, "重跑必须落在同一条线路上");
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 1, "重跑不能多出线路");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn an_existing_user_choice_survives_a_rerun() {
        let root = temp_root("choice");
        let origin = Origin::cli();
        let first = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            None,
            &origin,
        )
        .unwrap();
        let line_id = first[0].id.clone();
        let path = root.join(config::DEFAULT_PATH);
        let mut cfg = config::load(&path).unwrap().unwrap();
        cfg.lines[0].transport = Some(Transport::Tcp);
        config::save_with_origin(&path, &cfg, &origin).unwrap();

        let again = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            None,
            &origin,
        )
        .unwrap();
        assert_eq!(again[0].transport, Some(Transport::Tcp), "自动档必须沿用用户选的方式");
        let cfg = config::load(&path).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 1);
        assert_eq!(cfg.lines[0].id, line_id);
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn an_explicit_tcp_preference_selects_the_compatible_line() {
        let root = temp_root("prefer-tcp");
        let origin = Origin::cli();
        let lines = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            Some(Transport::Tcp),
            &origin,
        )
        .unwrap();
        let tcp_id = lines
            .iter()
            .find(|line| line.transport == Some(Transport::Tcp))
            .expect("应当有兼容连接线路")
            .id
            .clone();
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.selected, tcp_id, "显式选择兼容连接时应选中它");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 显式选了「标准连接」：即使用户之前选过兼容连接，也要切回标准。
    /// 部署时显式选兼容：同一条线路的初始方式就是 Tcp，文件也派生过；
    /// 再跑一次显式选标准，同一条线路切回来，文件回到标准态（参数仍在）。
    #[test]
    fn an_explicit_transport_preference_flips_the_same_line_both_ways() {
        let root = temp_root("prefer-transport");
        let origin = Origin::cli();
        let first = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            Some(Transport::Tcp),
            &origin,
        )
        .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].transport, Some(Transport::Tcp));
        let line_id = first[0].id.clone();
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        let line = cfg.lines.iter().find(|l| l.id == line_id).unwrap();
        let path = line.engine_config_path(&root);
        assert!(
            crate::engine_config::tcp_shaped(&std::fs::read_to_string(&path).unwrap()),
            "显式选了兼容，落盘的线路文件也必须是兼容态"
        );

        let again = register_lines(
            &root,
            "203.0.113.10",
            &conf(),
            Some(&compatible()),
            Some(Transport::Udp),
            &origin,
        )
        .unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].id, line_id, "还是那一条线路，不是新的一条");
        assert_eq!(again[0].transport, Some(Transport::Udp));
        assert!(
            !crate::engine_config::tcp_shaped(&std::fs::read_to_string(&path).unwrap()),
            "切回标准后文件必须是标准态"
        );
        let cfg = config::load(&root.join(config::DEFAULT_PATH)).unwrap().unwrap();
        let line = cfg.lines.iter().find(|l| l.id == line_id).unwrap();
        assert!(line.load_compatible(&root).is_some(), "切回标准不能把兼容参数抹掉");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn descriptions_name_the_connection_kind() {
        let standard = Registered {
            id: "standard".to_string(),
            name: "自建 · 1.2.3.4".to_string(),
            endpoint: "127.0.0.1:17890".to_string(),
            transport: None,
        };
        let compat = Registered {
            id: "compat".to_string(),
            name: "自建 · 1.2.3.4（兼容连接）".to_string(),
            endpoint: "127.0.0.1:17893".to_string(),
            transport: Some(Transport::Tcp),
        };
        assert!(standard.describe().contains("标准连接"));
        assert!(compat.describe().contains("兼容连接"));
    }

    /// 已有 `client.conf` 时必须复用私钥——否则每重跑一次就在服务端多一个僵尸 peer。
    #[test]
    fn the_tunnel_key_is_reused_when_a_client_conf_exists() {
        let root = temp_root("key");
        let (first_private, first_public) = client_tunnel_key(&root);
        let text = deploy::client_conf(
            &deploy::Spec::for_record("32d4f356-db4b-4ca5-8f06-cda3587a5f80"),
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "203.0.113.10",
            &first_private,
        );
        std::fs::write(root.join("client.conf"), text).unwrap();
        let (second_private, second_public) = client_tunnel_key(&root);
        assert_eq!(second_private, first_private, "重跑必须复用同一把私钥");
        assert_eq!(second_public, first_public);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **T02 的关键用例**：`client.conf` 还没写就崩了，私钥必须还在 ——
    /// 否则服务端上留下一个谁也连不上的 peer，而本机再也拿不回那把私钥。
    #[test]
    fn the_tunnel_key_survives_a_crash_before_client_conf_is_written() {
        let root = temp_root("tunnelkey");
        let (private, public) = ensure_tunnel_key(&root);
        assert!(
            root.join(TUNNEL_KEY_FILE).is_file(),
            "第一次就要把私钥先落盘"
        );
        let stored = std::fs::read_to_string(root.join(TUNNEL_KEY_FILE)).unwrap();
        assert_eq!(stored.trim(), private, "落盘的就是刚才那把");
        assert!(!root.join("client.conf").exists(), "此时还没有 client.conf");

        // 模拟崩溃后重启：只有 tunnel.key，没有 client.conf —— 必须复用同一把。
        let (again_private, again_public) = ensure_tunnel_key(&root);
        assert_eq!(again_private, private, "崩溃后必须捞回同一把私钥");
        assert_eq!(again_public, public);

        // 连隧道文件的形状也要对：一行 base64，没有别的东西。
        assert_eq!(stored.lines().count(), 1, "私钥文件只有一行：{stored:?}");
        assert_eq!(stored.trim().len(), 44, "WireGuard 私钥是 44 位 base64");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `client.conf` 里的私钥优先于 `tunnel.key`：老路径不能被新文件抢走。
    #[test]
    fn client_conf_wins_over_a_stale_tunnel_key() {
        let root = temp_root("precedence");
        // 先造一把「过期」的 tunnel.key。
        let (stale_private, _) = pairing::keys::tunnel_keypair();
        write_private(&root.join(TUNNEL_KEY_FILE), &stale_private).unwrap();
        // 再造一份 client.conf，里面的私钥是另一把。
        let (live_private, _) = pairing::keys::tunnel_keypair();
        let text = deploy::client_conf(
            &deploy::Spec::for_record("32d4f356-db4b-4ca5-8f06-cda3587a5f80"),
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "203.0.113.10",
            &live_private,
        );
        std::fs::write(root.join("client.conf"), text).unwrap();
        let (chosen, _) = ensure_tunnel_key(&root);
        assert_eq!(chosen, live_private, "服务端认的是 client.conf 里那把");
        assert_ne!(chosen, stale_private);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 「自动记住首次服务器身份」关着时：第一次连没见过的机器、又没给指纹，必须停下来问人。
    /// （开关开着的那条路径是 TOFU，见 `first_trust` 的判定与 `ssh::UnknownKey::Accept` 的用例。）
    #[test]
    fn with_the_switch_off_a_first_connection_without_a_fingerprint_stops_and_asks() {
        let root = temp_root("tofu");
        let origin = Origin::cli();
        let error = setup(
            &root,
            "root@203.0.113.10",
            None,
            Some("whatever"),
            false,
            &origin,
            &mut |_| {},
        )
        .expect_err("没有指纹不能继续");
        assert_eq!(error.code, crate::exit::CONFLICT);
        assert!(error.message.contains("指纹"), "{}", error.message);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 地址写错了要在连网之前就被拒，不能等密码输完才报。
    #[test]
    fn a_bad_spec_is_refused_before_touching_the_network() {
        let root = temp_root("badspec");
        let origin = Origin::cli();
        let error = setup(&root, "root203.0.113.10", None, None, true, &origin, &mut |_| {})
            .expect_err("没有 @ 必须拒绝");
        assert_eq!(error.code, crate::exit::USAGE);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 分步入口也要在连网之前拒掉写错的地址（引擎会先调它，不该等 SSH 超时）。
    #[test]
    fn resolve_identity_refuses_a_bad_spec_before_the_network() {
        let root = temp_root("badspec2");
        let origin = Origin::cli();
        let mut events: Vec<StepEvent> = Vec::new();
        let error = resolve_identity(
            &root,
            "203.0.113.10",
            None,
            Some(&crate::credential::Credential::password("x")),
            true,
            true,
            &origin,
            &mut |event| events.push(event.clone()),
        )
        .expect_err("没有 @ 必须拒绝");
        assert_eq!(error.code, crate::exit::USAGE);
        assert!(events.is_empty(), "连网络都没碰，不该有任何进度事件");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 渲染必须与拆分前逐字一致：CLI 的输出就是这些行。
    #[test]
    fn the_rendered_event_matches_the_old_wording_character_by_character() {
        assert_eq!(
            render_event(&StepEvent::start(0, "检查 root@203.0.113.10:22 的环境 …")),
            "[1/4] 检查 root@203.0.113.10:22 的环境 …"
        );
        assert_eq!(
            render_event(&StepEvent::start(1, "安装服务端（WireGuard + NAT）…")),
            "[2/4] 安装服务端（WireGuard + NAT）…"
        );
        assert_eq!(
            render_event(&StepEvent::start(3, "把本机接进去 …")),
            "[4/4] 把本机接进去 …"
        );
        assert_eq!(
            render_event(&StepEvent::detail(1, "接口 tc3f2b9c1e（10.66.0.1/24），UDP 51820")),
            "    接口 tc3f2b9c1e（10.66.0.1/24），UDP 51820"
        );
        assert_eq!(
            render_event(&StepEvent::warning(2, "兼容连接没有装上：超时")),
            "    ！兼容连接没有装上：超时"
        );
        assert_eq!(
            render_event(&StepEvent::note("已保存服务器记录：root@203.0.113.10:22")),
            "已保存服务器记录：root@203.0.113.10:22"
        );
    }

    /// 事件的三元组要能被上层直接写进记录：步骤下标、种类、文案，一个都不能少。
    #[test]
    fn every_event_carries_step_index_kind_and_message() {
        let start = StepEvent::start(2, "安装兼容连接（TCP 8443）…");
        assert_eq!(start.step_idx, 2);
        assert_eq!(start.kind, StepKind::Start);
        assert_eq!(start.kind.label(), "start");

        let note = StepEvent::note("正在核对主机指纹 …");
        assert_eq!(note.step_idx, STEP_NOT_APPLICABLE);
        assert_eq!(note.kind, StepKind::Note);
        assert_eq!(note.kind.label(), "note");

        assert_eq!(StepKind::Detail.label(), "detail");
        assert_eq!(StepKind::Warning.label(), "warning");
    }

    /// `N/4` 的分母与步骤下标必须落在同一范围：事件的 `step_idx` 只能是 0..=3。
    #[test]
    fn step_indices_stay_within_the_four_product_steps() {
        for index in 0..4u8 {
            let event = StepEvent::start(index, "x");
            assert!(render_event(&event).starts_with(&format!("[{}/4]", index + 1)));
        }
    }
}
