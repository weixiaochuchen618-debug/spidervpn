//! 部署引擎：线程、队列、lane、检查点推进、只读核对（T03）。
//!
//! 为什么不是「一条长命令」：`Step::Long` 会让整段部署持着 `Ctx.transaction_gate`
//! 最长 10 分钟，期间转后台、离页、崩溃续跑全都不成立。引擎把部署拆成**四个检查点**，
//! 每个检查点自己写盘，所以「关掉界面」与「进程被杀」都不丢进度。
//!
//! 三条硬规则（违反任意一条就会出「配置里有、记录里没有」的设备）：
//!
//! 1. **判据必须早于副作用**：写命令发出**之前**先把 `PendingOperation` 落盘。
//!    崩溃后靠它知道「有没有可能已经写了」。
//! 2. **有 `Outcome == Pending` 时永不重发写命令**：只能走只读核对，核对结论是
//!    `Applied` 才往下走，`NotApplied` 也要用户显式点重试。
//! 3. **秘密只在内存**：`ActivePass` 持有 `Secret`，`Drop` 时清零；进度文本由
//!    `deployrun::humanize` 生成，那个函数的签名里没有密码参数。
//!
//! 线程模型：
//!
//! ```text
//! IPC/CLI ──Cmd──> 监督线程（1s 轮询：处理命令 / 提升队列 / 每 5s 写心跳）
//!                       │ 每 lane 空闲且 active < 3 时
//!                       └──> pass 线程（跑完发 Cmd::PassFinished）
//! ```
//!
//! 记录写盘由 [`Inner::mutate`] 统一串行化：先 `load` 最新、再改、再 `save`
//! （`Revision+1`）。心跳线程与 pass 线程都走这条路径，所以不会互相覆盖。
//!
//! T05 已经接上 `Ctx.engine`：`deployment-*` 十条短命令、`main` 里的单例启动，
//! 以及管道/界面共用同一个句柄。所以这里**不再**整体允许未使用——死代码必须能被
//! 编译器点名，而不是靠人记。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::deploy;
use crate::deploystore::{
    now_utc, DeploymentStore, Executor, PendingOperation, Plan, Reason, RunRecord, StoreError,
    Target, ERROR_CLASS_CONFIG, ERROR_CLASS_CONFLICT, ERROR_CLASS_ENVIRONMENT, ERROR_CLASS_INTERNAL,
    ERROR_CLASS_NETWORK, ERROR_CLASS_USAGE, NEXT_ACTION_COMPLETE_COMPATIBLE, NEXT_ACTION_NONE,
    NEXT_ACTION_RECONCILE, NEXT_ACTION_RETRY_STEP, NEXT_ACTION_VIEW_LINE, NEXT_ACTION_WAIT_QUEUE,
    OUTCOME_APPLIED, OUTCOME_NOT_APPLIED, OUTCOME_PENDING, OUTCOME_UNKNOWN, PENDING_KIND_ADD_PEER,
    PENDING_KIND_TRANSPORT_INSTALL, PENDING_KIND_UDP_INSTALL, REASON_FAILED,
    REASON_IDENTITY_CHANGED, REASON_OUTCOME_UNKNOWN, REASON_PARTIAL, STATE_CANCELLED, STATE_COMPLETE,
    STATE_NEEDS_ATTENTION, STATE_PAUSED, STATE_QUEUED, STATE_RUNNING, STEP_STATUS_DONE,
    STEP_STATUS_FAILED, STEP_STATUS_RUNNING,
    VERIFY_BY_PROBE_UDP_STATE, VERIFY_BY_READ_TRANSPORT,
};
use crate::deployrun::{
    decide_resume, humanize, plan_pass, settle_step, PassDecision, PassPlan, PassRefusal,
    ResumeDecision, StepOutcome, UpstreamFacts, STEP_COUNT,
};
use crate::serverstore::ServerRecord;

/// 同时最多跑几个 pass。常量而不是用户设置：3 路 SSH + 每路约 20MB 下载，
/// 对家用带宽与磁盘都够用，再多只会让每一步都变慢。
pub const MAX_ACTIVE: usize = 3;

/// 监督线程的轮询间隔（也是「命令多久被看见」的上限）。
const TICK: Duration = Duration::from_millis(1000);

/// 心跳间隔。超过 15 秒没有心跳，重启后的恢复才会改判（留三倍余量）。
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// 秘密
// ---------------------------------------------------------------------------

// r92 起 `Credential` / `CredentialKind` 住在 `credential` 模块：传输层（`ssh`）也需要
// 「一次登录用什么」，而引擎不该是那个类型的定义者。
// `Secret` 已没有外部调用点（既有用例都改成了 `Credential::password(..)`），所以不再
// 从这里再导出——留着只会多一条未使用警告。
pub use crate::credential::{Credential, CredentialKind};

// ---------------------------------------------------------------------------
// 与远程动作的接缝
// ---------------------------------------------------------------------------

/// 一次远程动作的输入。`record` 只有 Step0 之后才有（Step0 自己负责把它建出来）。
pub struct OpsReq<'a> {
    pub data_root: &'a Path,
    /// `user@host:port`（自己持有：避免为了借一个临时字符串把调用点写得很别扭）。
    pub address: String,
    pub fingerprint: String,
    /// 这一次用哪份凭据。`None` = 这一次没有可用凭据（沿用旧语义：拿空密码去连，
    /// 由服务器拒）。**借用**：凭据的生命周期由 `Arc<Credential>` 在 `Queued` 里管。
    pub credential: Option<&'a Credential>,
    pub spec: &'a deploy::Spec,
    pub record: Option<&'a ServerRecord>,
    /// 这次登录拿到的密码**要不要落盘**（界面上的「在这台电脑记住登录资料」）。
    ///
    /// 放在请求里而不是让 `ProdOps` 去读设置：这是**这一次部署**的决定，
    /// 由写这条记录的人（`deployment-start`）决定，进程级的设置说不清这件事。
    pub persist_credential: bool,
}

/// 动作失败的分类。`definite` 决定「明确没生效」还是「结果未知」：
/// 前者可以重试，后者只能先核对。
#[derive(Debug, Clone)]
pub struct OpsError {
    pub class: &'static str,
    pub code: String,
    pub message: String,
    /// `true` = 脚本/认证自己说的「没做」（可以重试）；
    /// `false` = 连接断、超时、输出不完整（**不许重试**，先核对）。
    pub definite: bool,
}

impl OpsError {
    pub fn definite(class: &'static str, code: impl Into<String>, message: impl Into<String>) -> OpsError {
        OpsError {
            class,
            code: code.into(),
            message: message.into(),
            definite: true,
        }
    }

    pub fn unknown(class: &'static str, code: impl Into<String>, message: impl Into<String>) -> OpsError {
        OpsError {
            class,
            code: code.into(),
            message: message.into(),
            definite: false,
        }
    }
}

/// Step0 的身份结论。
#[derive(Debug, Clone)]
pub struct IdentityFacts {
    /// 服务器记录（引擎后续步骤要用它的 id/host/fingerprint 生成计划与请求）。
    pub record: ServerRecord,
    pub auto_trusted: bool,
}

/// 环境检查（只读）。只留引擎要用与证据要写的字段，完整 `Environment` 不进记录。
#[derive(Debug, Clone, Default)]
pub struct EnvFacts {
    pub kernel: String,
    pub arch: String,
    pub uid: u32,
    pub distro: String,
    pub distro_version: String,
    pub systemd: bool,
    pub openssl: bool,
    pub wireguard_tools: bool,
    pub wireguard_dir: bool,
    pub ufw: String,
    pub forward_policy: String,
    /// 这台服务器上这条隧道现在是不是 up（决定 UDP 安装能不能复用）。
    pub tunnel_up: bool,
    /// 不能部署的人话原因（非 Linux / 非 root / 没 systemd）。
    pub blocking_reason: Option<String>,
}

/// 装标准连接的结果。
#[derive(Debug, Clone, Default)]
pub struct UdpInstallFacts {
    pub reused: bool,
    pub interface: String,
    pub address: String,
    pub port: u16,
}

/// 只读核对的结果（`deploy::UdpState` 的子集）。
#[derive(Debug, Clone, Default)]
pub struct ProbeFacts {
    pub tunnel_up: bool,
    pub conf_present: bool,
    pub unit_active: bool,
    pub listen_port: Option<u16>,
    pub peers: Vec<String>,
}

impl ProbeFacts {
    /// 三个否定条件同时成立才敢说「明确没生效」。
    pub fn clearly_not_applied(&self) -> bool {
        !self.tunnel_up && !self.conf_present && !self.unit_active
    }

    pub fn matches_plan(&self, plan: &Plan) -> bool {
        self.tunnel_up && self.listen_port == Some(plan.udp_port)
    }

    pub fn has_peer(&self, public_key: &str) -> bool {
        !public_key.is_empty() && self.peers.iter().any(|item| item == public_key)
    }
}

/// 兼容连接（TCP）的参数。全部非秘密（本来就要写进客户端线路文件）。
#[derive(Debug, Clone, Default)]
pub struct TransportFacts {
    pub port: u16,
    pub server_name: String,
    pub uuid: String,
    pub reality_public_key: String,
    pub short_id: String,
    pub component: String,
    pub identity: String,
}

/// `add_peer` 的应答。
#[derive(Debug, Clone, Default)]
pub struct PeerFacts {
    pub server_public: String,
    pub client_public: String,
}

/// 登记后的一条线路。
#[derive(Debug, Clone, Default)]
pub struct LineFacts {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub transport: Option<String>,
}

/// 远程/本机动作的接缝。生产实现是 [`ProdOps`]，测试用脚本化的假实现。
///
/// 用 `&self` + `Send + Sync`：两个不同服务器的 pass 必须能并发调它
/// （`Mutex<dyn Ops>` 会把「两台服务器并发」悄悄变成串行）。
pub trait Ops: Send + Sync {
    fn resolve_identity(&self, req: &OpsReq) -> Result<IdentityFacts, OpsError>;
    fn check_environment(&self, req: &OpsReq) -> Result<EnvFacts, OpsError>;
    fn install_udp(&self, req: &OpsReq, tunnel_up: bool) -> Result<UdpInstallFacts, OpsError>;
    fn probe_udp_state(&self, req: &OpsReq) -> Result<ProbeFacts, OpsError>;
    fn install_transport(&self, req: &OpsReq) -> Result<Option<TransportFacts>, OpsError>;
    fn read_transport(&self, req: &OpsReq) -> Result<Option<TransportFacts>, OpsError>;
    fn add_peer(&self, req: &OpsReq, client_public: &str) -> Result<PeerFacts, OpsError>;
    /// 写 `client.conf`（含私钥）。**必须在核对设备之前**：崩在「核对通过」与
    /// 「登记线路」之间时，重启后能从这份文件里读回服务器公钥，不必再发一次写命令。
    fn write_client_conf(
        &self,
        req: &OpsReq,
        client_private: &str,
        server_public: &str,
    ) -> Result<(), OpsError>;

    /// 登记线路（本机 `config.json` 写，幂等）。参数从 `client.conf` 读回，
    /// 所以崩溃之后只要那份文件还在，就能把这一步捞回来。
    /// `preferred` 是用户这次选的「默认连接方式」：`Some(Tcp)` = 选中兼容连接那条；
    /// `None` = 自动（沿用旧行为：标准连接优先，用户已有选择则保留）。
    fn register_lines(
        &self,
        req: &OpsReq,
        compatible: Option<&TransportFacts>,
        preferred: Option<crate::config::Transport>,
    ) -> Result<Vec<LineFacts>, OpsError>;

    /// 本机隧道密钥（`client.conf` → `tunnel.key` → 新生成）。默认实现走产品代码，
    /// 假实现可以返回固定密钥，避免测试碰真实文件。
    fn ensure_tunnel_key(&self, dir: &Path) -> (String, String) {
        crate::servercmd::ensure_tunnel_key(dir)
    }
}

/// 生产实现：把引擎的动作接到 `servercmd` / `deploy` / `pairing` 上。
pub struct ProdOps {
    origin: crate::events::Origin,
}

impl ProdOps {
    pub fn new(origin: crate::events::Origin) -> ProdOps {
        ProdOps { origin }
    }

}

/// 把 `ssh::Error` 映射成引擎的分类。判据只有一处，别在调用点各写一份。
///
/// `kind` 只影响「服务器拒绝」那一句：密码错与私钥不被接受是**两件不同的错**，
/// 用户要做的事也不同（改密码 vs 把公钥加进 `authorized_keys`）。
fn map_ssh_error(error: &crate::ssh::Error, kind: CredentialKind) -> OpsError {
    use crate::ssh::Error;
    match error {
        Error::Auth => OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "AccessRequired",
            match kind {
                CredentialKind::Password => error.to_string(),
                CredentialKind::Key =>
                    "服务器不接受这把 SSH 私钥（或登录用户名不对）。请确认这个公钥已加入\
                     服务器的 authorized_keys，并且登录账户有 sudo 权限。"
                        .to_string(),
            },
        ),
        Error::HostKeyMismatch { .. } | Error::HostKeyUnknown { .. } => {
            OpsError::definite(ERROR_CLASS_CONFLICT, "IdentityChanged", error.to_string())
        }
        Error::Connect(_) | Error::Timeout => {
            OpsError::unknown(ERROR_CLASS_NETWORK, "NoMarker", error.to_string())
        }
        // 命令层失败：脚本自己报了码就是「明确没做」，没有码再按未知处理。
        Error::Command(message) => {
            let definite = message.contains("TC_ERROR")
                || message.contains("脚本")
                || message.contains("退出码");
            if definite {
                OpsError::definite(ERROR_CLASS_ENVIRONMENT, "CommandFailed", message.clone())
            } else {
                OpsError::unknown(ERROR_CLASS_NETWORK, "NoMarker", message.clone())
            }
        }
    }
}

/// 这一次用的是哪种登录方式。没有凭据时按密码说（与旧文案一致）。
fn credential_kind(credential: Option<&Credential>) -> CredentialKind {
    credential
        .map(|item| item.kind())
        .unwrap_or(CredentialKind::Password)
}

impl Ops for ProdOps {
    fn resolve_identity(&self, req: &OpsReq) -> Result<IdentityFacts, OpsError> {
        let resolved = crate::servercmd::resolve_identity(
            req.data_root,
            &req.address,
            Some(req.fingerprint.as_str()).filter(|text| !text.is_empty()),
            req.credential,
            true,
            // 「记住登录资料」这一次勾没勾，一直传到真正写信封的那一层。
            req.persist_credential,
            &self.origin,
            &mut |_| {},
        )
        .map_err(|error| {
            let class = match error.code {
                crate::exit::CONFIG => ERROR_CLASS_CONFIG,
                crate::exit::USAGE => ERROR_CLASS_USAGE,
                crate::exit::ENVIRONMENT => ERROR_CLASS_ENVIRONMENT,
                crate::exit::NETWORK => ERROR_CLASS_NETWORK,
                crate::exit::CONFLICT => ERROR_CLASS_CONFLICT,
                _ => ERROR_CLASS_INTERNAL,
            };
            OpsError::definite(class, "SetupFailed", error.message)
        })?;
        Ok(IdentityFacts {
            record: resolved.record,
            auto_trusted: resolved.auto_trusted.is_some(),
        })
    }

    fn check_environment(&self, req: &OpsReq) -> Result<EnvFacts, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let spec = req.spec;
        let environment = crate::servercmd::check_environment(
            record,
            crate::ssh::Auth::from_option(req.credential),
            spec,
            &mut |_| {},
        )
        .map_err(|error| OpsError::definite(ERROR_CLASS_ENVIRONMENT, "InspectFailed", error.message))?;
        Ok(EnvFacts {
            kernel: environment.kernel.clone(),
            arch: environment.arch.clone(),
            uid: environment.uid,
            distro: environment.distro.clone(),
            distro_version: environment.distro_version.clone(),
            systemd: environment.systemd,
            openssl: environment.openssl,
            wireguard_tools: environment.wireguard_tools,
            wireguard_dir: environment.wireguard_dir,
            ufw: environment.ufw.clone(),
            forward_policy: environment.forward_policy.clone(),
            tunnel_up: environment.tunnel.as_ref().map(|item| item.up).unwrap_or(false),
            blocking_reason: environment.blocking_reason(),
        })
    }

    fn install_udp(&self, req: &OpsReq, tunnel_up: bool) -> Result<UdpInstallFacts, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let spec = req.spec;
        // 与 `servercmd::install_udp` 同一条判据：隧道已经 up 就复用，不重装。
        if tunnel_up {
            return Ok(UdpInstallFacts {
                reused: true,
                interface: spec.interface.clone(),
                address: spec.address.clone(),
                port: spec.port,
            });
        }
        let installed = deploy::install(
            &record.target(),
            crate::ssh::Auth::from_option(req.credential),
            &record.fingerprint,
            spec,
            Duration::from_secs(300),
        )
        .map_err(|error| map_ssh_error(&error, credential_kind(req.credential)))?;
        Ok(UdpInstallFacts {
            reused: false,
            interface: installed.interface,
            address: installed.interface_address,
            port: installed.port,
        })
    }

    fn probe_udp_state(&self, req: &OpsReq) -> Result<ProbeFacts, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let state = deploy::probe_udp_state(
            &record.target(),
            crate::ssh::Auth::from_option(req.credential),
            &record.fingerprint,
            &req.spec.interface,
            Duration::from_secs(60),
        )
        .map_err(|error| map_ssh_error(&error, credential_kind(req.credential)))?;
        Ok(ProbeFacts {
            tunnel_up: state.tunnel_up,
            conf_present: state.conf_present,
            unit_active: state.unit_active,
            listen_port: state.listen_port,
            peers: state.peers,
        })
    }

    fn install_transport(&self, req: &OpsReq) -> Result<Option<TransportFacts>, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let installed = crate::servercmd::install_transport_step(
            record,
            crate::ssh::Auth::from_option(req.credential),
            req.spec,
            &mut |_| {},
        )
        .map_err(|error| OpsError::definite(ERROR_CLASS_ENVIRONMENT, "TransportFailed", error.message))?;
        Ok(installed.map(|item| TransportFacts {
            port: item.port,
            server_name: item.server_name,
            uuid: item.uuid,
            reality_public_key: item.public_key,
            short_id: item.short_id,
            component: item.component,
            identity: item.identity,
        }))
    }

    fn read_transport(&self, req: &OpsReq) -> Result<Option<TransportFacts>, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let installed = deploy::read_transport(
            &record.target(),
            crate::ssh::Auth::from_option(req.credential),
            &record.fingerprint,
            Duration::from_secs(40),
        )
        .map_err(|error| map_ssh_error(&error, credential_kind(req.credential)))?;
        Ok(installed.map(|item| TransportFacts {
            port: item.port,
            server_name: item.server_name,
            uuid: item.uuid,
            reality_public_key: item.public_key,
            short_id: item.short_id,
            component: item.component,
            identity: item.identity,
        }))
    }

    fn add_peer(&self, req: &OpsReq, client_public: &str) -> Result<PeerFacts, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let ack = deploy::add_peer(
            &record.target(),
            crate::ssh::Auth::from_option(req.credential),
            &record.fingerprint,
            req.spec,
            client_public,
            Duration::from_secs(120),
        )
        .map_err(|error| map_ssh_error(&error, credential_kind(req.credential)))?;
        Ok(PeerFacts {
            server_public: ack.server_public,
            client_public: ack.client_public,
        })
    }

    fn write_client_conf(
        &self,
        req: &OpsReq,
        client_private: &str,
        server_public: &str,
    ) -> Result<(), OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let conf = deploy::client_conf(req.spec, server_public, &record.host, client_private);
        // 写 client.conf（含私钥）走 secretfile：创建即收紧 ACL。
        let dir = req.data_root.join("servers").join(&record.id);
        crate::secretfile::write(&dir.join("client.conf"), &conf)
            .map_err(|error| OpsError::definite(ERROR_CLASS_CONFIG, "ClientConfFailed", error.to_string()))?;
        Ok(())
    }

    fn register_lines(
        &self,
        req: &OpsReq,
        compatible: Option<&TransportFacts>,
        preferred: Option<crate::config::Transport>,
    ) -> Result<Vec<LineFacts>, OpsError> {
        let record = req
            .record
            .ok_or_else(|| OpsError::definite(ERROR_CLASS_INTERNAL, "NoRecord", "缺少服务器记录"))?;
        let dir = req.data_root.join("servers").join(&record.id);
        let text = std::fs::read_to_string(dir.join("client.conf")).map_err(|error| {
            OpsError::definite(ERROR_CLASS_CONFIG, "ClientConfMissing", format!("读不到 client.conf：{error}"))
        })?;
        let parsed = crate::pairing::line::parse_client_conf(&text).map_err(|error| {
            OpsError::definite(ERROR_CLASS_INTERNAL, "ClientConfInvalid", error.message)
        })?;
        let params = compatible.map(|item| crate::pairing::line::Compatible {
            server: record.host.clone(),
            port: item.port,
            uuid: item.uuid.clone(),
            server_name: item.server_name.clone(),
            reality_public_key: item.reality_public_key.clone(),
            reality_short_id: item.short_id.clone(),
        });
        let lines = crate::servercmd::register_lines_verified(
            req.data_root,
            &record.host,
            &parsed,
            params.as_ref(),
            preferred,
            &self.origin,
        )
        .map_err(|error| OpsError::definite(ERROR_CLASS_CONFIG, "RegisterFailed", error.message))?;
        Ok(lines
            .into_iter()
            .map(|line| LineFacts {
                id: line.id,
                name: line.name,
                endpoint: line.endpoint,
                transport: line.transport.map(|item| format!("{item:?}")),
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// 共享状态
// ---------------------------------------------------------------------------

/// 一个正在跑的 pass。
pub struct ActivePass {
    pub lane_key: String,
    pub started_at_secs: u64,
    pause_requested: AtomicBool,
    cancel_requested: AtomicBool,
}

impl ActivePass {
    fn new(lane_key: String) -> ActivePass {
        ActivePass {
            lane_key,
            started_at_secs: crate::model::now_epoch_secs_u64(),
            pause_requested: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
        }
    }

    pub fn pause_requested(&self) -> bool {
        self.pause_requested.load(Ordering::SeqCst)
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::SeqCst)
    }
}

struct Queued {
    run_id: String,
    lane_key: String,
    credential: Option<Arc<Credential>>,
    verify_only: bool,
}

/// 队列与活动的只读视图。界面/CLI 从这里读，不碰记录文件。
pub struct EngineShared {
    pub instance_id: String,
    active: Mutex<HashMap<String, Arc<ActivePass>>>,
    queued: Mutex<Vec<Queued>>,
    revision: AtomicU64,
    store_error: Mutex<String>,
    /// 启动恢复里「写盘失败」的那句话（空 = 一切正常）。
    ///
    /// 它必须能被读到：恢复失败时记录**原样留在** `Running`，界面要是照常渲染，
    /// 用户看到的就是「还在部署」——正是「先显示 Running 让它自己好」这条禁令
    /// 要挡掉的东西。`deployment-list` 用它把 `TasksRead` 压成 `failed`。
    recover_error: Mutex<String>,
}

impl EngineShared {
    fn new(instance_id: String) -> EngineShared {
        EngineShared {
            instance_id,
            active: Mutex::new(HashMap::new()),
            queued: Mutex::new(Vec::new()),
            revision: AtomicU64::new(0),
            store_error: Mutex::new(String::new()),
            recover_error: Mutex::new(String::new()),
        }
    }

    pub fn active_count(&self) -> usize {
        self.active.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn queued_count(&self) -> usize {
        self.queued.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_active(&self, run_id: &str) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(run_id)
    }

    pub fn is_queued(&self, run_id: &str) -> bool {
        self.queued
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|item| item.run_id == run_id)
    }

    pub fn lane_busy(&self, lane_key: &str) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|item| item.lane_key == lane_key)
    }

    /// `Revision`：界面缓存靠它失效（不看 mtime）。
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    pub fn store_error(&self) -> String {
        self.store_error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn recover_error(&self) -> String {
        self.recover_error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_recover_error(&self, message: &str) {
        if let Ok(mut slot) = self.recover_error.lock() {
            *slot = message.to_string();
        }
    }

    fn bump(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------

enum Cmd {
    Start {
        run_id: String,
        credential: Option<Arc<Credential>>,
    },
    Continue {
        run_id: String,
        credential: Option<Arc<Credential>>,
        verify_only: bool,
    },
    Pause {
        run_id: String,
    },
    Cancel {
        run_id: String,
    },
    Background {
        run_id: String,
    },
    /// 用户动作被前置条件拦下（身份变了 / 需要凭据 / 上游核对不过）：
    /// 把结论写进记录，让界面下次刷新时看到「停在哪儿、为什么」。
    ///
    /// **不执行任何步骤、不发 SSH、不碰 `PendingOperation`**——它只改
    /// `State/Reason/NextAction` 这三个给人看的字段。走引擎而不是 IPC 直接写盘，
    /// 是为了守住「记录只有引擎写」这条规则（避免 IPC 与 pass 互相覆盖）。
    NoteBlocked {
        run_id: String,
        category: &'static str,
        class: &'static str,
        code: &'static str,
        text: String,
        next_action: &'static str,
    },
    PassFinished {
        run_id: String,
    },
    Shutdown,
}

struct Inner {
    data_root: PathBuf,
    store: DeploymentStore,
    ops: Arc<dyn Ops>,
    shared: Arc<EngineShared>,
    tx: Sender<Cmd>,
    /// 所有记录写盘的串行闸门：先重新 load，再改，再 save。
    write_lock: Mutex<()>,
    origin: crate::events::Origin,
}

impl Inner {
    fn mutate<F>(&self, run_id: &str, edit: F) -> Result<RunRecord, StoreError>
    where
        F: FnOnce(&mut RunRecord),
    {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut run = self.store.load(run_id)?;
        edit(&mut run);
        run.updated_at_utc = Some(now_utc());
        self.store.save(&mut run)?;
        self.shared.bump();
        Ok(run)
    }

    fn record_store_error(&self, error: &StoreError) {
        if let Ok(mut slot) = self.shared.store_error.lock() {
            *slot = error.message.clone();
        }
        self.shared.bump();
    }

    fn handle_cmd(&self, cmd: Cmd) {
        match cmd {
            Cmd::Start { run_id, credential } => self.enqueue(run_id, credential, false),
            Cmd::Continue {
                run_id,
                credential,
                verify_only,
            } => {
                // 幂等：已经在跑或已在队列里就不再入队（连点只产生一个有效后续操作）。
                if self.shared.is_active(&run_id) || self.shared.is_queued(&run_id) {
                    return;
                }
                self.enqueue(run_id, credential, verify_only);
            }
            Cmd::Pause { run_id } => {
                if let Some(pass) = self
                    .shared
                    .active
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&run_id)
                {
                    // P1-1：只在步骤边界落地，这里只记意图。
                    pass.pause_requested.store(true, Ordering::SeqCst);
                }
            }
            Cmd::Cancel { run_id } => {
                if let Some(pass) = self
                    .shared
                    .active
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&run_id)
                {
                    pass.cancel_requested.store(true, Ordering::SeqCst);
                    return;
                }
                // 还没开始跑的，直接落终态（不进 pass，不会留下半成品）。
                //
                // 但**必须先离开队列**：`promote` 只认「在不在队列里」，不看记录状态。
                // 留在队列里的话，它会白占一个 lane 名额，等轮到自己才被 `plan_pass`
                // 的 Terminal 判据退回来——期间别的服务器可能因此排不上。
                self.shared
                    .queued
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|item| item.run_id != run_id);
                let _ = self.mutate(&run_id, |run| {
                    if crate::deployrun::transition_ok(&run.state, STATE_CANCELLED) {
                        run.state = STATE_CANCELLED.to_string();
                        run.next_action = NEXT_ACTION_NONE.to_string();
                        run.finished_at_utc = Some(now_utc());
                    }
                });
            }
            Cmd::Background { run_id } => {
                let _ = self.mutate(&run_id, |run| {
                    let executor = run.executor.get_or_insert_with(Executor::default);
                    executor.background = true;
                });
            }
            Cmd::NoteBlocked {
                run_id,
                category,
                class,
                code,
                text,
                next_action,
            } => {
                let _ = self.mutate(&run_id, |run| {
                    // 终态、或已经在跑：不改写。前置条件判断**早于**任何副作用
                    // （这里唯一的副作用就是写盘，但仍按同一条规矩写）。
                    if crate::deployrun::is_terminal_state(&run.state)
                        || !crate::deployrun::transition_ok(&run.state, STATE_NEEDS_ATTENTION)
                    {
                        return;
                    }
                    run.state = STATE_NEEDS_ATTENTION.to_string();
                    run.reason = Some(Reason::now(category, class, code, &text));
                    run.next_action = next_action.to_string();
                });
            }
            Cmd::PassFinished { run_id } => {
                self.shared
                    .active
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&run_id);
                self.shared.bump();
            }
            Cmd::Shutdown => {}
        }
    }

    fn enqueue(&self, run_id: String, credential: Option<Arc<Credential>>, verify_only: bool) {
        let run = match self.store.load(&run_id) {
            Ok(run) => run,
            Err(error) => {
                self.record_store_error(&error);
                return;
            }
        };
        let lane_key = run.target.lane_key();
        // 先在记录上写「排队中」：即使进程立刻死掉，用户看到的也是「还没开始」。
        // `Draft` 不能直达 `Queued`（白名单只有 Draft→WaitingUser→Queued）：
        // 用户点「开始部署」就等于已经确认过表单，中间态不落盘。
        let _ = self.mutate(&run_id, |run| {
            let next = match run.state.as_str() {
                crate::deploystore::STATE_DRAFT => {
                    if crate::deployrun::transition_ok(
                        crate::deploystore::STATE_DRAFT,
                        crate::deploystore::STATE_WAITING_USER,
                    ) && crate::deployrun::transition_ok(
                        crate::deploystore::STATE_WAITING_USER,
                        STATE_QUEUED,
                    ) {
                        Some(STATE_QUEUED)
                    } else {
                        None
                    }
                }
                STATE_NEEDS_ATTENTION | STATE_PAUSED => {
                    if crate::deployrun::transition_ok(&run.state, STATE_QUEUED) {
                        Some(STATE_QUEUED)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(state) = next {
                run.state = state.to_string();
                run.next_action = NEXT_ACTION_WAIT_QUEUE.to_string();
            }
        });
        self.shared
            .queued
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Queued {
                run_id,
                lane_key,
                credential,
                verify_only,
            });
        self.shared.bump();
    }

    /// 提升队列：active < 3 且这条 lane 没被占。
    fn promote(&self, handle: &EngineHandle) {
        loop {
            let mut active = self.shared.active.lock().unwrap_or_else(|e| e.into_inner());
            if active.len() >= MAX_ACTIVE {
                return;
            }
            let mut queued = self.shared.queued.lock().unwrap_or_else(|e| e.into_inner());
            let Some(index) = queued.iter().position(|item| {
                !active.values().any(|pass| pass.lane_key == item.lane_key)
            }) else {
                return;
            };
            let item = queued.remove(index);
            let pass = Arc::new(ActivePass::new(item.lane_key));
            active.insert(item.run_id.clone(), pass.clone());
            drop(queued);
            drop(active);
            self.shared.bump();

            // 状态在 pass 内部落 Running（它自己写盘，避免两处各写一次）。
            handle.spawn_pass(item.run_id, item.credential, item.verify_only, pass);
        }
    }

    fn heartbeat(&self) {
        let ids: Vec<String> = self
            .shared
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        for run_id in ids {
            let _ = self.mutate(&run_id, |run| {
                if let Some(executor) = run.executor.as_mut() {
                    executor.heartbeat_at_utc = Some(now_utc());
                }
            });
        }
    }
}

/// 投递意图的句柄（可克隆，给 IPC/界面用）。
#[derive(Clone)]
pub struct EngineHandle {
    tx: Sender<Cmd>,
    shared: Arc<EngineShared>,
    inner: Arc<Inner>,
}

/// 手写 `Debug`（`Ctx` 派生了 `Debug`，所以这里必须有）。
///
/// **不能**派生：`Cmd` 里装着 `Arc<Credential>`（服务器密码 / SSH 私钥），
/// 派生的 `Debug` 会在「打印上下文」这种再普通不过的动作里把秘密写进日志。
/// 这里只报计数。
impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("active", &self.shared.active_count())
            .field("queued", &self.shared.queued_count())
            .finish()
    }
}

impl EngineHandle {
    pub fn start_run(&self, run_id: &str, credential: Option<Credential>) {
        let _ = self.tx.send(Cmd::Start {
            run_id: run_id.to_string(),
            credential: credential.map(Arc::new),
        });
    }

    pub fn continue_run(&self, run_id: &str, credential: Option<Credential>, verify_only: bool) {
        let _ = self.tx.send(Cmd::Continue {
            run_id: run_id.to_string(),
            credential: credential.map(Arc::new),
            verify_only,
        });
    }

    pub fn pause(&self, run_id: &str) {
        let _ = self.tx.send(Cmd::Pause {
            run_id: run_id.to_string(),
        });
    }

    /// 把「用户动作被拦下」的结论写进记录（见 [`Cmd::NoteBlocked`]）。
    ///
    /// 只写给人看的三个字段，不执行任何步骤。调用方**不必**等它落盘：
    /// 回包只说「没有执行」，下一次刷新自然会读到原因。
    pub fn note_blocked(
        &self,
        run_id: &str,
        category: &'static str,
        class: &'static str,
        code: &'static str,
        text: &str,
        next_action: &'static str,
    ) {
        let _ = self.tx.send(Cmd::NoteBlocked {
            run_id: run_id.to_string(),
            category,
            class,
            code,
            text: text.to_string(),
            next_action,
        });
    }

    pub fn cancel(&self, run_id: &str) {
        let _ = self.tx.send(Cmd::Cancel {
            run_id: run_id.to_string(),
        });
    }

    pub fn background(&self, run_id: &str) {
        let _ = self.tx.send(Cmd::Background {
            run_id: run_id.to_string(),
        });
    }

    pub fn shared(&self) -> &Arc<EngineShared> {
        &self.shared
    }

    pub fn is_active(&self, run_id: &str) -> bool {
        self.shared.is_active(run_id)
    }

    /// 启动恢复有没有写盘失败（空 = 没有）。
    ///
    /// `deployment-list` 用它把 `TasksRead` 压成 `failed`：**记录还留在 `Running`**
    /// 这件事必须让界面知道，否则那一行会一直显示「正在部署」。
    pub fn recover_error(&self) -> String {
        self.shared.recover_error()
    }

    fn spawn_pass(
        &self,
        run_id: String,
        credential: Option<Arc<Credential>>,
        verify_only: bool,
        pass: Arc<ActivePass>,
    ) {
        let inner = self.inner.clone();
        let tx = self.tx.clone();
        let fallback = run_id.clone();
        let result = std::thread::Builder::new()
            .name(format!("deploy-pass-{}", &run_id[..run_id.len().min(8)]))
            .spawn(move || {
                run_pass(inner, run_id.clone(), credential, verify_only, pass);
                let _ = tx.send(Cmd::PassFinished { run_id });
            });
        if result.is_err() {
            // 线程起不来：把 active 摘掉，否则这条记录会永远显示「正在跑」。
            let _ = self.tx.send(Cmd::PassFinished { run_id: fallback });
        }
    }
}

/// 启动裁剪的结果（r79）。字段是给人看的，不是给策略用的。
pub struct PruneOutcome {
    pub removed: usize,
    pub kept: usize,
    pub error: String,
    pub keep: usize,
    pub keep_days: u64,
}

/// 启动时的部署记录裁剪（r79）：**只在启动跑一次**。
///
/// 三条护栏，任何一条不满足就不删那条记录：
///
/// 1. **归档不删**（`prune_terminal` 里的独立判据）——用户按过「留着」；
/// 2. **还有未读提醒的不删**——提醒里存着 `RunId`，删了记录再点「查看」只能得到
///    「记录读不到」。等用户看过或归档，下一轮自然清掉；
/// 3. **读不到提醒就整轮不裁**——不知道哪些记录被引用时，宁可不删。
///
/// 被删的只有「已完成 / 已取消 + 超过 7 天 + 不满足上面两条」这一批。界面本来
/// 就看不到它们（底部队列只留 24 小时，也没有记录页），所以用户是无感的；
/// 换来的是 `runs\` 目录与「每帧重读全部记录」的开销有上界。
pub fn prune_records(root: &std::path::Path) -> Option<PruneOutcome> {
    let unread = crate::reminder::unread(root).ok()?;
    let protected: std::collections::HashSet<String> =
        unread.into_iter().map(|item| item.run_id).collect();
    let report = crate::deploystore::DeploymentStore::open(root).prune_terminal(
        crate::deploystore::KEEP_TERMINAL,
        crate::deploystore::MAX_TERMINAL_AGE_SECS,
        |id| protected.contains(id),
    );
    Some(PruneOutcome {
        removed: report.removed,
        kept: report.kept,
        error: report.error,
        keep: crate::deploystore::KEEP_TERMINAL,
        keep_days: crate::deploystore::MAX_TERMINAL_AGE_SECS / (24 * 60 * 60),
    })
}

/// 引擎本体。`Drop` 会停掉监督线程（进程退出时不必依赖它）。
pub struct Engine {
    handle: EngineHandle,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Engine {
    pub fn start(data_root: PathBuf, ops: Arc<dyn Ops>, origin: crate::events::Origin) -> Engine {
        let instance_id = crate::pairing::random_uuid_v4();
        let shared = Arc::new(EngineShared::new(instance_id));
        let (tx, rx) = mpsc::channel();
        let store = DeploymentStore::open(&data_root);
        let inner = Arc::new(Inner {
            data_root: data_root.clone(),
            store,
            ops,
            shared: shared.clone(),
            tx: tx.clone(),
            write_lock: Mutex::new(()),
            origin,
        });

        let handle = EngineHandle {
            tx,
            shared: shared.clone(),
            inner: inner.clone(),
        };
        let supervisor = {
            let inner = inner.clone();
            let handle = handle.clone();
            std::thread::Builder::new()
                .name("deploy-supervisor".to_string())
                .spawn(move || supervisor_loop(inner, handle, rx))
                .expect("部署监督线程必须能起来")
        };

        Engine {
            handle,
            join: Some(supervisor),
        }
    }

    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.handle.tx.send(Cmd::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// 启动恢复的结论。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoverReport {
    /// 被改判成 `NeedsAttention` 的记录条数。
    pub rewritten: usize,
    /// 改判写盘失败的条数。**不为 0 时界面必须说「读不出来」**，不许照常显示「正在部署」。
    pub failed: usize,
    /// 人话（空 = 一切正常）。给 `deployment-list` 的 `TasksRead="failed"` 用。
    pub error: String,
}

impl RecoverReport {
    /// 有没有没处理干净的东西（读不出来也算）。
    pub fn is_clean(&self) -> bool {
        self.failed == 0 && self.error.is_empty()
    }
}

/// 「还有 N 个部署没有完成」——T09 关窗守卫用的那句话。
///
/// 活动 + 排队**都算**：排队那条虽然还没开始跑，退出同样等于把它丢掉
/// （下次启动只能看到一条「被打断」的记录，还得手工重试）。只数活动 pass 会让
/// 「刚点了开始部署就关窗」这个最常见的时间点恰好漏判。
pub fn busy_sentence(active: usize, queued: usize) -> Option<String> {
    let count = active + queued;
    if count == 0 {
        None
    } else {
        Some(format!("还有 {count} 个部署没有完成"))
    }
}

impl Engine {
    /// **启动扫描**：把上一个进程留下的 `Running`/`Queued` 记录改判。
    ///
    /// 必须在 `instance::acquire` 之后、任何 pass 起来之前调用一次（`main` 里就是这么做的）。
    /// 只做这一件事：改状态 + 写一条操作记录。**不**入队、不登录、不重放写命令。
    ///
    /// 永不 panic、永不把错误吞掉：写盘失败进 [`RecoverReport::error`]，
    /// 由 `deployment-list` 转成「任务记录读不出来」——留在 `Running` 又照常显示，
    /// 是这条线上最坏的结果。
    pub fn recover_all(&self) -> RecoverReport {
        self.handle.inner.recover_all()
    }
}

impl Inner {
    fn recover_all(&self) -> RecoverReport {
        let mut report = RecoverReport::default();
        let loaded = self.store.load_all();
        if !loaded.is_usable() {
            // 目录都读不了：不知道有没有要恢复的记录。交出去，让界面说「读不出来」。
            report.failed = 1;
            report.error = format!("启动时读不了部署任务记录：{}", loaded.error);
            self.shared.set_recover_error(&report.error);
            return report;
        }

        let now = crate::model::now_epoch_secs_u64();
        let pid = i64::from(std::process::id());
        // 与心跳线程、pass 线程共用同一把写盘闸门：恢复跑在启动早期，但「早期」
        // 不是并发安全的理由。
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        for run in &loaded.runs {
            // 「引擎里还有它」= 有活动 pass **或**还排在队列里。后者在启动扫描时
            // 必然为假（命令队列还没人投递），但把它算进来是免费的：将来若有人在
            // 别处再调一次 `recover_all`，不会把一条刚受理、还没提升的排队记录判死。
            let busy = self.shared.is_active(&run.run_id) || self.shared.is_queued(&run.run_id);
            let decision = crate::deployrun::recover(run, pid, now, busy);
            let crate::deployrun::Recovery::Rewrite {
                mut run, detail, ..
            } = decision
            else {
                continue;
            };
            match self.store.save(&mut run) {
                Ok(()) => {
                    report.rewritten += 1;
                    // 改判是「本程序替用户做的决定」，必须留痕：只写 RunId 短码 + 结论，
                    // 不含服务器地址、密码、私钥（`detail` 由纯函数拼，那里拿不到秘密）。
                    crate::events::record(
                        self.data_root.as_path(),
                        "部署恢复",
                        true,
                        &detail,
                        &self.origin,
                    );
                }
                Err(error) => {
                    report.failed += 1;
                    if report.error.is_empty() {
                        report.error = format!("有部署任务没能改判（写盘失败）：{}", error.message);
                    }
                }
            }
        }
        if report.rewritten > 0 {
            self.shared.bump();
        }
        if !report.error.is_empty() {
            self.shared.set_recover_error(&report.error);
        }
        report
    }
}

fn supervisor_loop(inner: Arc<Inner>, handle: EngineHandle, rx: Receiver<Cmd>) {
    let mut last_beat = Instant::now();
    'outer: loop {
        match rx.recv_timeout(TICK) {
            Ok(Cmd::Shutdown) => break,
            Ok(cmd) => {
                inner.handle_cmd(cmd);
                // 一次把已经排队的命令处理完：两条部署同时投递时，第二条不该等到
                // 下一个 1 秒 tick 才被提升（否则「两台服务器并发」会变成「隔一秒先后跑」）。
                while let Ok(next) = rx.try_recv() {
                    if matches!(next, Cmd::Shutdown) {
                        break 'outer;
                    }
                    inner.handle_cmd(next);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        inner.promote(&handle);
        if last_beat.elapsed() >= HEARTBEAT_EVERY {
            inner.heartbeat();
            last_beat = Instant::now();
        }
    }
}

// ---------------------------------------------------------------------------
// pass 的执行
// ---------------------------------------------------------------------------

impl Inner {
    /// pass 线程保存自己内存里的记录。它是这条记录进度的唯一写者；
    /// 心跳线程走 [`Inner::mutate`]（先 load 再改），所以不会把进度盖掉。
    ///
    /// 但反过来要注意：pass 手里的副本可能**落后于**那些 `mutate`（心跳、转后台
    /// 各自把 `Revision` +1）。版本号必须以磁盘为准——照抄旧值会让两次落盘撞出
    /// 同一个 `Revision`，「每一步都真的落了盘」就无法从记录上证明。
    fn save(&self, run: &mut RunRecord) -> Result<(), String> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(current) = self.store.load(&run.run_id) {
            run.revision = current.revision;
        }
        self.store.save(run).map_err(|error| error.message)?;
        // 任务级凭据的生命周期终点：**完成 / 取消就删**。
        //
        // 放在 `save` 里是因为它是所有终态写盘的汇合点（完成、取消、pass 收尾
        // 都从这里过）。`NeedsAttention` / `Paused` **不删**：那条任务还要接着做，
        // 删了就等于让用户在最需要免输密码的时候重新输一遍。
        if matches!(run.state.as_str(), STATE_COMPLETE | STATE_CANCELLED) {
            crate::deploycred::remove(&self.data_root, &run.run_id);
        }
        // 结果提醒在这里收：`save` 是所有会让记录进入 `Complete`/`NeedsAttention`/
        // `Paused`/`Cancelled` 的路径的汇合点。幂等由 (RunId,State,Step,Code) 保证，
        // 所以每次 save 都调用是安全的。
        //
        // 写失败**不影响部署本身**：提醒是附加品，不能让它把一次成功的部署变成失败。
        let _ = crate::reminder::note(&self.data_root, run);
        self.shared.bump();
        Ok(())
    }
}

fn run_pass(
    inner: Arc<Inner>,
    run_id: String,
    credential: Option<Arc<Credential>>,
    verify_only: bool,
    pass: Arc<ActivePass>,
) {
    if let Err(error) = pass_body(&inner, &run_id, credential.as_deref(), verify_only, &pass) {
        // 引擎自身的意外：记录绝不能停在 Running（那会让界面永远显示「正在跑」）。
        let _ = inner.mutate(&run_id, |run| {
            if crate::deployrun::transition_ok(&run.state, STATE_NEEDS_ATTENTION) {
                run.state = STATE_NEEDS_ATTENTION.to_string();
                run.reason = Some(Reason::now(
                    REASON_FAILED,
                    ERROR_CLASS_INTERNAL,
                    "EngineError",
                    &error,
                ));
                run.next_action = NEXT_ACTION_RETRY_STEP.to_string();
            }
        });
    }
}

fn pass_body(
    inner: &Arc<Inner>,
    run_id: &str,
    credential: Option<&Credential>,
    verify_only: bool,
    pass: &ActivePass,
) -> Result<(), String> {
    let mut run = inner.store.load(run_id).map_err(|error| error.message)?;

    // ① 核对原操作。有未决写时这是**唯一**允许的动作（也是「核对」按钮的入口）。
    //    核对结论是 Applied 时清空未决写、把该步标 Done，然后继续往下走。
    if verify_only || crate::deployrun::has_unverified_write(&run) {
        if !reconcile(inner, &mut run, credential)? {
            return Ok(());
        }
    }

    let plan = match plan_pass(&run) {
        PassDecision::Refuse(PassRefusal::Terminal) => return Ok(()),
        PassDecision::Refuse(PassRefusal::AllDone) => return finalize(inner, &mut run, None),
        PassDecision::Refuse(PassRefusal::UnverifiedWrite) => return Ok(()),
        PassDecision::Run(plan) => plan,
    };

    mark_running(inner, &mut run)?;

    // ② 续跑时先拿回记录（只读、幂等；不新建、不改指纹）。
    let mut record: Option<ServerRecord> = None;
    if plan.resume_from > 0 {
        match resolve_only(inner, &run, credential) {
            Ok(facts) => record = Some(facts),
            Err(error) => {
                let reason = reason_from_ops(&error);
                let action = if error.code == "AccessRequired" {
                    crate::deploystore::NEXT_ACTION_ENTER_CREDENTIALS
                } else {
                    NEXT_ACTION_RETRY_STEP
                };
                return settle_attention(inner, &mut run, Some(plan.resume_from), reason, action);
            }
        }
    }

    // ③ 已 Done 的上游步骤要重新核对（只读）。核对不过就回退到该步。
    let facts = collect_upstream(inner, &run, &plan, credential, record.as_ref());
    let from = match decide_resume(&plan, &facts) {
        ResumeDecision::From(from) => from,
        ResumeDecision::IdentityChanged => {
            return settle_attention(
                inner,
                &mut run,
                None,
                Reason::now(
                    REASON_IDENTITY_CHANGED,
                    ERROR_CLASS_CONFLICT,
                    "IdentityChanged",
                    "服务器的身份与记录不一致，请重新核对指纹。",
                ),
                crate::deploystore::NEXT_ACTION_CONFIRM_FINGERPRINT,
            )
        }
        ResumeDecision::NeedsRecovery => {
            return settle_attention(
                inner,
                &mut run,
                Some(2),
                Reason::now(
                    crate::deploystore::REASON_NEEDS_RECOVERY,
                    ERROR_CLASS_CONFIG,
                    "NeedsRecovery",
                    "服务器上的兼容连接参数与本机记录对不上，需要先核对。",
                ),
                NEXT_ACTION_RECONCILE,
            )
        }
    };

    // ④ 逐步骤推进。暂停/取消只在步骤边界落地（P1-1）。
    let mut deferred: Option<(u8, Reason)> = None;
    let mut step = from;
    while usize::from(step) < STEP_COUNT {
        if pass.cancel_requested() {
            return finish_cancelled(inner, &mut run);
        }
        if pass.pause_requested() {
            return finish_paused(inner, &mut run);
        }

        open_step(inner, &mut run, step)?;
        let outcome = run_step(inner, &mut run, step, credential, record.as_ref())?;
        if step == 0 && record.is_none() {
            // Step0 已经把记录建出来（或读回来）了：后三步要用完整的 ServerRecord。
            // 这里多一次只读解析，换来「记录只有一个来源」，不做内存里的影子状态。
            record = resolve_only(inner, &run, credential).ok();
        }

        // 兼容连接失败不阻断：保住 UDP 与线路的成果，最后判 Partial（Q3）。
        if step == 2 {
            if let StepOutcome::Failed { reason } = &outcome {
                deferred = Some((2, reason.clone()));
                step += 1;
                continue;
            }
        }

        settle_step(&mut run, step, outcome, &now_utc())?;
        inner.save(&mut run)?;
        if run.state != STATE_RUNNING {
            return Ok(());
        }
        step += 1;
    }

    finalize(inner, &mut run, deferred)
}

/// 记录进入 Running（执行者 = 本进程）。`background` 保留用户之前的选择。
fn mark_running(inner: &Arc<Inner>, run: &mut RunRecord) -> Result<(), String> {
    if run.state != STATE_RUNNING {
        if !crate::deployrun::transition_ok(&run.state, STATE_RUNNING) {
            return Err(format!("状态机不允许 {} → Running", run.state));
        }
        run.state = STATE_RUNNING.to_string();
    }
    // 上一次尝试已经有结论（失败/取消/完成/被启动恢复收尾）→ 这是新的一次。
    // 暂停后继续、补密码后继续时上一次还没有结论，所以不会多出一条历史。
    crate::deployrun::begin_attempt(run, &now_utc());
    run.started_at_utc.get_or_insert_with(now_utc);
    let background = run.executor.as_ref().map(|item| item.background).unwrap_or(false);
    run.executor = Some(Executor {
        instance_id: inner.shared.instance_id.clone(),
        pid: i64::from(std::process::id()),
        heartbeat_at_utc: Some(now_utc()),
        background,
    });
    run.next_action = NEXT_ACTION_NONE.to_string();
    inner.save(run)
}

fn open_step(inner: &Arc<Inner>, run: &mut RunRecord, step: u8) -> Result<(), String> {
    if let Some(slot) = run.steps.get_mut(usize::from(step)) {
        if slot.status != STEP_STATUS_DONE {
            slot.status = STEP_STATUS_RUNNING.to_string();
            slot.started_at_utc.get_or_insert_with(now_utc);
        }
    }
    run.step = Some(step);
    inner.save(run)
}

fn finish_cancelled(inner: &Arc<Inner>, run: &mut RunRecord) -> Result<(), String> {
    if !crate::deployrun::transition_ok(&run.state, STATE_CANCELLED) {
        return Err(format!("状态机不允许 {} → Cancelled", run.state));
    }
    run.state = STATE_CANCELLED.to_string();
    run.next_action = NEXT_ACTION_NONE.to_string();
    run.finished_at_utc = Some(now_utc());
    // 用户按的取消也会让这次尝试结束：历史里要能看出「这次是取消的」，
    // 而不是一条永远没有结束时间的尝试。
    crate::deployrun::finish_attempt(run, &now_utc(), None, "");
    inner.save(run)
}

fn finish_paused(inner: &Arc<Inner>, run: &mut RunRecord) -> Result<(), String> {
    if !crate::deployrun::transition_ok(&run.state, STATE_PAUSED) {
        return Err(format!("状态机不允许 {} → Paused", run.state));
    }
    run.state = STATE_PAUSED.to_string();
    run.next_action = NEXT_ACTION_NONE.to_string();
    inner.save(run)
}

/// 停在「需要处理」。
///
/// `step` 是**哪一步失败了**。传 `None` 表示这次停下不属于任何一步的执行失败
/// （上游校验不过、核对阶段连不上）——这时**一个步骤都不许动**：
/// 把已经 `Done` 的步骤改成 `Failed`，页面就会说「检查服务器环境与身份：失败」，
/// 用户照着重试第 0 步，可真正该做的是核对指纹。步骤状态是「事实」，
/// 判定是「结论」，两者不能混写。
fn settle_attention(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    step: Option<u8>,
    reason: Reason,
    next_action: &str,
) -> Result<(), String> {
    if !crate::deployrun::transition_ok(&run.state, STATE_NEEDS_ATTENTION) {
        return Err(format!("状态机不允许 {} → NeedsAttention", run.state));
    }
    if let Some(index) = step {
        if let Some(slot) = run.steps.get_mut(usize::from(index)) {
            slot.status = STEP_STATUS_FAILED.to_string();
            slot.error = Some(reason.clone());
            slot.finished_at_utc = Some(now_utc());
        }
        run.step = Some(index);
    }
    run.state = STATE_NEEDS_ATTENTION.to_string();
    let mut reason = reason;
    if reason.text.trim().is_empty() {
        reason.text = humanize(&reason);
    }
    run.reason = Some(reason);
    run.next_action = next_action.to_string();
    // 这次尝试到此为止：把「失败在第几步、什么码」写进历史。`step=None` 表示停下
    // 不属于任何一步的执行失败（上游校验、核对连不上），历史里同样记一次结束——
    // 它确实停了，只是没有一个「失败步骤」。
    let code = run
        .reason
        .as_ref()
        .map(|item| item.code.clone())
        .unwrap_or_default();
    crate::deployrun::finish_attempt(run, &now_utc(), step, &code);
    if crate::deployrun::has_unverified_write(run) {
        crate::deployrun::mark_attempt_needs_reconcile(run);
    }
    inner.save(run)
}

/// 收尾：Partial（TCP 没装上）或 Complete（四步全 Done 且没有未决写）。
fn finalize(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    deferred: Option<(u8, Reason)>,
) -> Result<(), String> {
    if let Some((index, reason)) = deferred {
        if let Some(slot) = run.steps.get_mut(usize::from(index)) {
            slot.status = STEP_STATUS_FAILED.to_string();
            slot.error = Some(reason.clone());
            slot.finished_at_utc = Some(now_utc());
        }
        if !crate::deployrun::transition_ok(&run.state, STATE_NEEDS_ATTENTION) {
            return Err(format!("状态机不允许 {} → NeedsAttention", run.state));
        }
        run.state = STATE_NEEDS_ATTENTION.to_string();
        run.reason = Some(Reason::now(
            REASON_PARTIAL,
            ERROR_CLASS_ENVIRONMENT,
            "TcpFailed",
            "标准连接已经可用，兼容连接还没装上。",
        ));
        run.next_action = NEXT_ACTION_COMPLETE_COMPATIBLE.to_string();
        run.step = Some(3);
        // 「部分完成」也是一次尝试的结论：失败步骤 = TCP 那一步，码 = TcpFailed。
        crate::deployrun::finish_attempt(run, &now_utc(), Some(index), "TcpFailed");
        return inner.save(run);
    }

    let done = run.steps.iter().filter(|step| step.is_done()).count();
    if done == STEP_COUNT && run.pending_operation.is_none() {
        if !crate::deployrun::transition_ok(&run.state, STATE_COMPLETE) {
            return Err(format!("状态机不允许 {} → Complete", run.state));
        }
        run.state = STATE_COMPLETE.to_string();
        run.next_action = NEXT_ACTION_VIEW_LINE.to_string();
        run.finished_at_utc = Some(now_utc());
        run.step = Some(u8::try_from(STEP_COUNT).unwrap_or(4));
        // 成功收尾：这次尝试以「没有失败步骤」结束。
        crate::deployrun::finish_attempt(run, &now_utc(), None, "");
    }
    inner.save(run)
}

// ---------------------------------------------------------------------------
// 只读核对（唯一的「不写服务器」路径）
// ---------------------------------------------------------------------------

/// 核对未决写。返回 `true` = 已生效并已把该步标 Done，可以继续往下走。
///
/// 三条结论各自去哪，架构 §1.5 定死了：Applied → 清空 + Done；NotApplied →
/// 停下让用户点重试（**核对只负责把「不知道」变成「知道」**）；Unknown → 保持
/// `NeedsAttention/OutcomeUnknown`，只给「核対原操作」。
fn reconcile(inner: &Arc<Inner>, run: &mut RunRecord, credential: Option<&Credential>) -> Result<bool, String> {
    let Some(pending) = run.pending_operation.clone() else {
        return Ok(false);
    };
    let record = match resolve_only(inner, run, credential) {
        Ok(record) => record,
        Err(error) => {
            let reason = reason_from_ops(&error);
            return settle_attention(inner, run, None, reason, NEXT_ACTION_RECONCILE).map(|_| false);
        }
    };
    let spec = deploy::Spec::for_record(&record.id);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", record.user, record.host, record.port),
        fingerprint: record.fingerprint.clone(),
        credential,
        spec: &spec,
        // 只有 Step0 会真的去写凭据；其余步骤只是把同一个决定透传下去，
        // 免得将来再加一条「重登」路径时各自记得不一样。
        persist_credential: run.remember_saved,
        record: Some(&record),
    };

    let (verdict, step) = match pending.kind.as_str() {
        PENDING_KIND_UDP_INSTALL => match inner.ops.probe_udp_state(&req) {
            Ok(probe) if probe.matches_plan(&run.plan) => (OUTCOME_APPLIED, 1),
            Ok(probe) if probe.clearly_not_applied() => (OUTCOME_NOT_APPLIED, 1),
            _ => (OUTCOME_UNKNOWN, 1),
        },
        PENDING_KIND_TRANSPORT_INSTALL => match inner.ops.read_transport(&req) {
            Ok(Some(facts)) if !facts.server_name.is_empty() => (OUTCOME_APPLIED, 2),
            Ok(None) => (OUTCOME_NOT_APPLIED, 2),
            _ => (OUTCOME_UNKNOWN, 2),
        },
        PENDING_KIND_ADD_PEER => {
            let key = pending.client_public_key.clone().unwrap_or_default();
            match inner.ops.probe_udp_state(&req) {
                // 设备在，但本机线路没登记：这也算「没生效」——否则记录会写着 4/4，
                // 而 `config.json` 里一条线路都没有（用户看到「完成」但连不上）。
                Ok(probe) if probe.has_peer(&key) => {
                    if lines_present(inner, run) == Some(true) {
                        (OUTCOME_APPLIED, 3)
                    } else {
                        (OUTCOME_NOT_APPLIED, 3)
                    }
                }
                Ok(probe) if probe.tunnel_up => (OUTCOME_NOT_APPLIED, 3),
                _ => (OUTCOME_UNKNOWN, 3),
            }
        }
        // 表外种类：不猜，按未知处理（更保守）。
        _ => (OUTCOME_UNKNOWN, run.step.unwrap_or(0)),
    };

    if let Some(slot) = run.pending_operation.as_mut() {
        slot.outcome = verdict.to_string();
    }

    match verdict {
        OUTCOME_APPLIED => {
            if let Some(slot) = run.steps.get_mut(usize::from(step)) {
                slot.status = STEP_STATUS_DONE.to_string();
                slot.finished_at_utc = Some(now_utc());
                slot.error = None;
            }
            run.pending_operation = None;
            // 未决写核对成「已生效」：历史里那句「需要核对」要跟着改成「已核对」。
            crate::deployrun::mark_attempt_reconciled(run);
            run.reason = None;
            run.step = Some(step.saturating_add(1));
            run.next_action = NEXT_ACTION_WAIT_QUEUE.to_string();
            if !crate::deployrun::transition_ok(&run.state, STATE_QUEUED) {
                return Err(format!("状态机不允许 {} → Queued", run.state));
            }
            run.state = STATE_QUEUED.to_string();
            inner.save(run)?;
            // 已经拿到「生效」的铁证，同一次 pass 里继续往下走（不必等用户再点一次）。
            run.state = STATE_RUNNING.to_string();
            Ok(true)
        }
        OUTCOME_NOT_APPLIED => {
            run.state = STATE_NEEDS_ATTENTION.to_string();
            run.reason = Some(Reason::now(
                REASON_FAILED,
                ERROR_CLASS_ENVIRONMENT,
                "NotApplied",
                "只读核对确认这一步没有生效，可以重试。",
            ));
            run.next_action = NEXT_ACTION_RETRY_STEP.to_string();
            // 核对有结论了（没生效）→ 这次尝试在这里结束，且未决写已经不需要再核对。
            crate::deployrun::finish_attempt(run, &now_utc(), Some(step), "NotApplied");
            crate::deployrun::mark_attempt_reconciled(run);
            inner.save(run)?;
            Ok(false)
        }
        _ => {
            run.state = STATE_NEEDS_ATTENTION.to_string();
            run.reason = Some(Reason::now(
                REASON_OUTCOME_UNKNOWN,
                ERROR_CLASS_NETWORK,
                "OutcomeUnknown",
                "核对还是没能确认结果，请稍后再试一次。",
            ));
            run.next_action = NEXT_ACTION_RECONCILE.to_string();
            // 核对没能给出结论：这次尝试照样结束了（停了），只是结论仍是「需要核对」。
            crate::deployrun::finish_attempt(run, &now_utc(), Some(step), "OutcomeUnknown");
            inner.save(run)?;
            Ok(false)
        }
    }
}

fn resolve_only(
    inner: &Arc<Inner>,
    run: &RunRecord,
    credential: Option<&Credential>,
) -> Result<ServerRecord, OpsError> {
    let hint = run
        .target
        .server_record_id
        .clone()
        .unwrap_or_else(|| run.run_id.clone());
    let spec = deploy::Spec::for_record(&hint);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", run.target.user, run.target.host, run.target.port),
        fingerprint: run.identity.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: None,
    };
    inner.ops.resolve_identity(&req).map(|facts| facts.record)
}

fn collect_upstream(
    inner: &Arc<Inner>,
    run: &RunRecord,
    plan: &PassPlan,
    credential: Option<&Credential>,
    record: Option<&ServerRecord>,
) -> UpstreamFacts {
    let mut facts = UpstreamFacts::default();
    let Some(record) = record else {
        return facts;
    };
    facts.identity_matches = Some(
        !run.identity.fingerprint.is_empty() && record.fingerprint == run.identity.fingerprint,
    );

    let spec = deploy::Spec::for_record(&record.id);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", record.user, record.host, record.port),
        fingerprint: record.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: Some(record),
    };

    if plan.resume_from > 1 && plan.verify.contains(&1) {
        facts.udp_matches_plan = inner
            .ops
            .probe_udp_state(&req)
            .ok()
            .map(|probe| probe.matches_plan(&run.plan));
    }
    if plan.resume_from > 2 && plan.verify.contains(&2) {
        facts.transport_matches_plan = inner
            .ops
            .read_transport(&req)
            .ok()
            .map(|installed| installed.is_some());
    }
    if plan.resume_from > 3 {
        facts.lines_present = lines_present(inner, run);
    }
    facts
}

fn lines_present(inner: &Arc<Inner>, run: &RunRecord) -> Option<bool> {
    let cfg = crate::config::load(&inner.data_root.join(crate::config::DEFAULT_PATH))
        .ok()
        .flatten()?;
    let prefix = format!("自建 · {}", run.target.host);
    Some(cfg.lines.iter().any(|line| line.name.starts_with(&prefix)))
}

fn reason_from_ops(error: &OpsError) -> Reason {
    Reason::now(
        if error.definite {
            REASON_FAILED
        } else {
            REASON_OUTCOME_UNKNOWN
        },
        error.class,
        &error.code,
        &error.message,
    )
}

fn failure_outcome(error: OpsError) -> StepOutcome {
    let reason = reason_from_ops(&error);
    if error.definite {
        StepOutcome::Failed { reason }
    } else {
        StepOutcome::Unknown { reason }
    }
}

fn clear_pending(run: &mut RunRecord) {
    run.pending_operation = None;
}

fn pend(
    run: &mut RunRecord,
    kind: &str,
    verify_by: &str,
    client_public_key: Option<String>,
) -> PendingOperation {
    let pending = PendingOperation {
        kind: kind.to_string(),
        attempt_no: run.attempt_no,
        started_at_utc: Some(now_utc()),
        verify_by: verify_by.to_string(),
        plan_digest: run.plan_digest.clone(),
        client_public_key,
        outcome: OUTCOME_PENDING.to_string(),
    };
    run.pending_operation = Some(pending.clone());
    pending
}

fn mark_pending_unknown(run: &mut RunRecord) {
    if let Some(slot) = run.pending_operation.as_mut() {
        slot.outcome = OUTCOME_UNKNOWN.to_string();
    }
}

fn plan_digest(record: &ServerRecord, spec: &deploy::Spec) -> String {
    use sha2::{Digest, Sha256};
    let text = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        record.host, record.user, record.fingerprint, spec.interface, spec.port, spec.mtu, spec.subnet
    );
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// 四个检查点
// ---------------------------------------------------------------------------

fn run_step(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    step: u8,
    credential: Option<&Credential>,
    record: Option<&ServerRecord>,
) -> Result<StepOutcome, String> {
    match step {
        0 => run_step0(inner, run, credential),
        1 => run_step1(inner, run, credential, record),
        2 => run_step2(inner, run, credential, record),
        3 => run_step3(inner, run, credential, record),
        _ => Ok(StepOutcome::Failed {
            reason: Reason::now(
                REASON_FAILED,
                ERROR_CLASS_INTERNAL,
                "BadStep",
                &format!("步骤下标越界：{step}"),
            ),
        }),
    }
}

fn missing_record() -> StepOutcome {
    StepOutcome::Failed {
        reason: Reason::now(
            REASON_FAILED,
            ERROR_CLASS_INTERNAL,
            "NoRecord",
            "缺少服务器记录，请从第一步重新开始。",
        ),
    }
}

/// Step0：检查服务器环境与身份。**无远程写**，所以不需要 `PendingOperation`。
fn run_step0(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    credential: Option<&Credential>,
) -> Result<StepOutcome, String> {
    let hint = run
        .target
        .server_record_id
        .clone()
        .unwrap_or_else(|| run.run_id.clone());
    let hint_spec = deploy::Spec::for_record(&hint);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", run.target.user, run.target.host, run.target.port),
        fingerprint: run.identity.fingerprint.clone(),
        credential,
        spec: &hint_spec,
        persist_credential: run.remember_saved,
        record: None,
    };

    let facts = match inner.ops.resolve_identity(&req) {
        Ok(facts) => facts,
        Err(error) => return Ok(failure_outcome(error)),
    };

    // 身份与目标写回记录：后面三步都按这份记录走。
    // 「登录方式 / 私钥路径」不是身份，由 `deployment-start` 写进来，这里**必须原样保留**
    // ——覆盖成默认值等于把用户选的私钥登录悄悄改回密码登录，下一次续跑就去试密码了。
    run.target = Target {
        host: facts.record.host.clone(),
        port: facts.record.port,
        user: facts.record.user.clone(),
        server_record_id: Some(facts.record.id.clone()),
        ..run.target.clone()
    };
    run.identity.fingerprint = facts.record.fingerprint.clone();
    run.identity.auto_trusted = facts.auto_trusted;

    let spec = deploy::Spec::for_record(&facts.record.id);
    if let Err(message) = spec.validate() {
        return Ok(StepOutcome::Failed {
            reason: Reason::now(REASON_FAILED, ERROR_CLASS_CONFIG, "SpecInvalid", &message),
        });
    }
    run.plan.interface = spec.interface.clone();
    run.plan.udp_port = spec.port;
    run.plan.subnet = spec.subnet.clone();
    run.plan.mtu = spec.mtu;
    run.plan_digest = plan_digest(&facts.record, &spec);

    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!(
            "{}@{}:{}",
            facts.record.user, facts.record.host, facts.record.port
        ),
        fingerprint: facts.record.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: Some(&facts.record),
    };
    let env = match inner.ops.check_environment(&req) {
        Ok(env) => env,
        Err(error) => return Ok(failure_outcome(error)),
    };
    if let Some(reason) = env.blocking_reason {
        return Ok(StepOutcome::Failed {
            reason: Reason::now(
                REASON_FAILED,
                ERROR_CLASS_ENVIRONMENT,
                "EnvironmentBlocked",
                &reason,
            ),
        });
    }

    Ok(StepOutcome::Done {
        evidence: json!({
            "kernel": env.kernel,
            "arch": env.arch,
            "uid": env.uid,
            "distro": env.distro,
            "distroVersion": env.distro_version,
            "systemd": env.systemd,
            "openssl": env.openssl,
            "wireguardTools": env.wireguard_tools,
            "wireguardDir": env.wireguard_dir,
            "ufw": env.ufw,
            "forwardPolicy": env.forward_policy,
            "tunnelUp": env.tunnel_up,
        }),
    })
}

/// Step1：准备标准连接（UDP）。**有远程写**。
fn run_step1(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    credential: Option<&Credential>,
    record: Option<&ServerRecord>,
) -> Result<StepOutcome, String> {
    let Some(record) = record else {
        return Ok(missing_record());
    };
    let spec = deploy::Spec::for_record(&record.id);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", record.user, record.host, record.port),
        fingerprint: record.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: Some(record),
    };
    let tunnel_up = run
        .steps
        .first()
        .and_then(|step| step.evidence.get("tunnelUp"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    // 写前落盘：这一步之后进程随时可能死，记录必须先知道「有可能写了」。
    pend(run, PENDING_KIND_UDP_INSTALL, VERIFY_BY_PROBE_UDP_STATE, None);
    inner.save(run)?;

    match inner.ops.install_udp(&req, tunnel_up) {
        Ok(facts) => match inner.ops.probe_udp_state(&req) {
            Ok(probe) if probe.matches_plan(&run.plan) => {
                clear_pending(run);
                Ok(StepOutcome::Done {
                    evidence: json!({
                        "listenPort": probe.listen_port,
                        "unitActive": probe.unit_active,
                        "confPresent": probe.conf_present,
                        "reused": facts.reused,
                        "interface": facts.interface,
                    }),
                })
            }
            Ok(probe) if probe.clearly_not_applied() => {
                clear_pending(run);
                Ok(StepOutcome::Failed {
                    reason: Reason::now(
                        REASON_FAILED,
                        ERROR_CLASS_ENVIRONMENT,
                        "NotApplied",
                        "标准连接没有生效（只读核对确认）。",
                    ),
                })
            }
            _ => {
                mark_pending_unknown(run);
                Ok(StepOutcome::Unknown {
                    reason: Reason::now(
                        REASON_OUTCOME_UNKNOWN,
                        ERROR_CLASS_NETWORK,
                        "OutcomeUnknown",
                        "标准连接的结果还没核实，先核对再决定下一步。",
                    ),
                })
            }
        },
        Err(error) if error.definite => {
            clear_pending(run);
            Ok(failure_outcome(error))
        }
        Err(error) => {
            mark_pending_unknown(run);
            Ok(failure_outcome(error))
        }
    }
}

/// Step2：准备兼容连接（TCP）。失败**不阻断**整体（保住 UDP 成果）。
fn run_step2(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    credential: Option<&Credential>,
    record: Option<&ServerRecord>,
) -> Result<StepOutcome, String> {
    let Some(record) = record else {
        return Ok(missing_record());
    };
    let spec = spec_for_run(run, &record.id);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", record.user, record.host, record.port),
        fingerprint: record.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: Some(record),
    };

    pend(
        run,
        PENDING_KIND_TRANSPORT_INSTALL,
        VERIFY_BY_READ_TRANSPORT,
        None,
    );
    inner.save(run)?;

    match inner.ops.install_transport(&req) {
        Ok(Some(facts)) => match inner.ops.read_transport(&req) {
            Ok(Some(read)) if read.port == facts.port && !read.server_name.is_empty() => {
                clear_pending(run);
                Ok(StepOutcome::Done {
                    evidence: json!({
                        "port": read.port,
                        "serverName": read.server_name,
                        "uuid": read.uuid,
                        "realityPublicKey": read.reality_public_key,
                        "shortId": read.short_id,
                        "component": read.component,
                        "identity": read.identity,
                    }),
                })
            }
            Ok(Some(_)) => {
                mark_pending_unknown(run);
                Ok(StepOutcome::Unknown {
                    reason: Reason::now(
                        REASON_OUTCOME_UNKNOWN,
                        ERROR_CLASS_CONFIG,
                        "TransportMismatch",
                        "装上的兼容连接参数与这一次不一样，先核对。",
                    ),
                })
            }
            Ok(None) => {
                clear_pending(run);
                Ok(StepOutcome::Failed {
                    reason: Reason::now(
                        REASON_FAILED,
                        ERROR_CLASS_ENVIRONMENT,
                        "TransportNotListening",
                        "兼容连接没有读回来（只读核对确认）。",
                    ),
                })
            }
            Err(error) => {
                mark_pending_unknown(run);
                Ok(failure_outcome(error))
            }
        },
        Ok(None) => {
            clear_pending(run);
            Ok(StepOutcome::Failed {
                reason: Reason::now(
                    REASON_FAILED,
                    ERROR_CLASS_ENVIRONMENT,
                    "TransportFailed",
                    "兼容连接没能装起来。",
                ),
            })
        }
        Err(error) if error.definite => {
            clear_pending(run);
            Ok(failure_outcome(error))
        }
        Err(error) => {
            mark_pending_unknown(run);
            Ok(failure_outcome(error))
        }
    }
}

/// Step3：接入本机并登记线路。3a 本机密钥 → 3b add_peer（写）→ 3c 核对 → 3d 登记。
fn run_step3(
    inner: &Arc<Inner>,
    run: &mut RunRecord,
    credential: Option<&Credential>,
    record: Option<&ServerRecord>,
) -> Result<StepOutcome, String> {
    let Some(record) = record else {
        return Ok(missing_record());
    };
    // 登记时按这一次选的「默认连接方式」决定选中哪条线路。
    // 只认三档：`Tcp` / `Udp` / 空（自动）；表外值当自动，不猜。
    let preferred = match run.plan.transport_word() {
        "Tcp" => Some(crate::config::Transport::Tcp),
        "Udp" => Some(crate::config::Transport::Udp),
        _ => None,
    };
    let spec = spec_for_run(run, &record.id);
    let req = OpsReq {
        data_root: &inner.data_root,
        address: format!("{}@{}:{}", record.user, record.host, record.port),
        fingerprint: record.fingerprint.clone(),
        credential,
        spec: &spec,
        persist_credential: run.remember_saved,
        record: Some(record),
    };

    // 3a：私钥先落盘再说（`add_peer` 成功后崩掉，私钥不能丢）。
    let dir = inner.data_root.join("servers").join(&record.id);
    let (client_private, client_public) = inner.ops.ensure_tunnel_key(&dir);
    run.plan.client_public_key = Some(client_public.clone());

    // 3b：写前落盘，带上公钥（核对时用它判断「这台设备到底加上没有」）。
    pend(
        run,
        PENDING_KIND_ADD_PEER,
        VERIFY_BY_PROBE_UDP_STATE,
        Some(client_public.clone()),
    );
    inner.save(run)?;

    match inner.ops.add_peer(&req, &client_public) {
        Ok(ack) => {
            // 3c-pre：先把 client.conf 落盘（含服务器公钥）。崩在「核对通过」与「登记线路」
            // 之间时，重启后能从这份文件里读回公钥——否则只能再发一次 add_peer（写命令）。
            if let Err(error) = inner.ops.write_client_conf(&req, &client_private, &ack.server_public) {
                clear_pending(run);
                return Ok(failure_outcome(error));
            }
            match inner.ops.probe_udp_state(&req) {
            Ok(probe) if probe.has_peer(&client_public) => {
                if let Some(slot) = run.pending_operation.as_mut() {
                    slot.outcome = OUTCOME_APPLIED.to_string();
                }
                let compatible = compatible_from(run);
                match inner.ops.register_lines(&req, compatible.as_ref(), preferred) {
                    Ok(lines) => {
                        clear_pending(run);
                        let evidence: Vec<serde_json::Value> = lines
                            .iter()
                            .map(|line| {
                                json!({
                                    "id": line.id,
                                    "name": line.name,
                                    "endpoint": line.endpoint,
                                    "transport": line.transport,
                                })
                            })
                            .collect();
                        Ok(StepOutcome::Done {
                            evidence: json!({ "lines": evidence }),
                        })
                    }
                    Err(error) => {
                        clear_pending(run);
                        Ok(failure_outcome(error))
                    }
                }
            }
            Ok(probe) if probe.tunnel_up => {
                if let Some(slot) = run.pending_operation.as_mut() {
                    slot.outcome = OUTCOME_NOT_APPLIED.to_string();
                }
                clear_pending(run);
                Ok(StepOutcome::Failed {
                    reason: Reason::now(
                        REASON_FAILED,
                        ERROR_CLASS_ENVIRONMENT,
                        "PeerNotApplied",
                        "服务器上没有这台设备（只读核对确认）。",
                    ),
                })
            }
            _ => {
                mark_pending_unknown(run);
                Ok(StepOutcome::Unknown {
                    reason: Reason::now(
                        REASON_OUTCOME_UNKNOWN,
                        ERROR_CLASS_NETWORK,
                        "OutcomeUnknown",
                        "这台设备到底加上没有还没核实，先核对再决定下一步。",
                    ),
                })
            }
            }
        }
        Err(error) if error.definite => {
            clear_pending(run);
            Ok(failure_outcome(error))
        }
        Err(error) => {
            mark_pending_unknown(run);
            Ok(failure_outcome(error))
        }
    }
}

/// 这一次部署要用的 `deploy::Spec`：默认参数 + 记录里批准过的兼容连接选择。
///
/// **只覆盖兼容连接的两项**（端口 / 握手域名）。UDP 端口、网段、MTU 仍由
/// `Spec::for_record` 一处决定——它们与「这一条记录」绑定，不该有第二个来源。
fn spec_for_run(run: &RunRecord, record_id: &str) -> deploy::Spec {
    let mut spec = deploy::Spec::for_record(record_id);
    spec.transport_port = run.plan.tcp_port_or_default();
    spec.transport_server_name = run.plan.server_name_or_default();
    spec
}

/// 从 Step2 的证据里取回兼容连接参数。Step2 没成功时返回 `None`（只登记标准线路）。
fn compatible_from(run: &RunRecord) -> Option<TransportFacts> {
    let evidence = &run.steps.get(2)?.evidence;
    let port = u16::try_from(evidence.get("port")?.as_u64()?).ok()?;
    let server_name = evidence.get("serverName")?.as_str()?.to_string();
    if server_name.is_empty() {
        return None;
    }
    Some(TransportFacts {
        port,
        server_name,
        uuid: text_of(evidence, "uuid"),
        reality_public_key: text_of(evidence, "realityPublicKey"),
        short_id: text_of(evidence, "shortId"),
        component: text_of(evidence, "component"),
        identity: text_of(evidence, "identity"),
    })
}

fn text_of(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    // -----------------------------------------------------------------------
    // 脚本化的假 Ops：记录调用次数、可以按序喂探针结果、可以控制「写」的时长
    // -----------------------------------------------------------------------

    struct FakeState {
        calls: Vec<&'static str>,
        write_calls: usize,
        running: usize,
        peak: usize,
        hold: Duration,
        probe: VecDeque<ProbeFacts>,
        transport: Option<TransportFacts>,
        added_public: Vec<String>,
        fail_udp: Option<OpsError>,
        /// 下一次 `check_environment` 直接失败（造「只读检查失败」这一档故障）。
        fail_env: Option<OpsError>,
    }

    struct FakeOps {
        state: Mutex<FakeState>,
        live: AtomicUsize,
    }

    impl FakeOps {
        fn new() -> FakeOps {
            FakeOps {
                state: Mutex::new(FakeState {
                    calls: Vec::new(),
                    write_calls: 0,
                    running: 0,
                    peak: 0,
                    hold: Duration::ZERO,
                    probe: VecDeque::new(),
                    transport: Some(TransportFacts {
                        port: 8443,
                        server_name: "www.example.com".to_string(),
                        uuid: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string(),
                        reality_public_key: "A".repeat(43),
                        short_id: "0123456789abcdef".to_string(),
                        component: "installed".to_string(),
                        identity: "created".to_string(),
                    }),
                    added_public: Vec::new(),
                    fail_udp: None,
                    fail_env: None,
                }),
                live: AtomicUsize::new(0),
            }
        }

        fn fail_next_udp(&self, error: OpsError) {
            self.state.lock().unwrap().fail_udp = Some(error);
        }

        /// 让下一次 Step0 只读检查失败。用 `definite` 造的错是「脚本自己说了没做成」，
        /// 用 `unknown` 造的是「连不上、输出不完整」——两者都不许被当成成功。
        fn fail_next_env(&self, error: OpsError) {
            self.state.lock().unwrap().fail_env = Some(error);
        }

        fn set_hold(&self, hold: Duration) {
            self.state.lock().unwrap().hold = hold;
        }

        fn push_probe(&self, probe: ProbeFacts) {
            self.state.lock().unwrap().probe.push_back(probe);
        }

        fn push_peer(&self, public_key: &str) {
            self.state
                .lock()
                .unwrap()
                .added_public
                .push(public_key.to_string());
        }

        fn count(&self, name: &str) -> usize {
            self.state
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|item| **item == name)
                .count()
        }

        fn write_calls(&self) -> usize {
            self.state.lock().unwrap().write_calls
        }

        fn peak(&self) -> usize {
            self.state.lock().unwrap().peak
        }

        fn enter(&self) {
            let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            let mut state = self.state.lock().unwrap();
            state.running = now;
            state.peak = state.peak.max(now);
        }

        fn exit(&self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn record_for(address: &str) -> ServerRecord {
        let (user, host_port) = address.split_once('@').unwrap_or(("root", address));
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, "22"));
        ServerRecord {
            id: format!("rec-{host}-{port}"),
            name: format!("{user}@{host}"),
            host: host.to_string(),
            port: port.parse().unwrap_or(22),
            user: user.to_string(),
            fingerprint: "SHA256:AAAA".to_string(),
            created_at: "2026-11-09T00:00:00Z".to_string(),
            updated_at: "2026-11-09T00:00:00Z".to_string(),
        }
    }

    impl Ops for FakeOps {
        fn resolve_identity(&self, req: &OpsReq) -> Result<IdentityFacts, OpsError> {
            self.state.lock().unwrap().calls.push("resolve_identity");
            Ok(IdentityFacts {
                record: record_for(&req.address),
                auto_trusted: false,
            })
        }

        fn check_environment(&self, _req: &OpsReq) -> Result<EnvFacts, OpsError> {
            let injected = {
                let mut state = self.state.lock().unwrap();
                state.calls.push("check_environment");
                state.fail_env.take()
            };
            if let Some(error) = injected {
                return Err(error);
            }
            Ok(EnvFacts {
                kernel: "Linux".to_string(),
                arch: "x86_64".to_string(),
                uid: 0,
                distro: "debian".to_string(),
                distro_version: "12".to_string(),
                systemd: true,
                openssl: true,
                wireguard_tools: true,
                wireguard_dir: true,
                ufw: "inactive".to_string(),
                forward_policy: "ACCEPT".to_string(),
                tunnel_up: false,
                blocking_reason: None,
            })
        }

        fn install_udp(&self, _req: &OpsReq, _tunnel_up: bool) -> Result<UdpInstallFacts, OpsError> {
            self.enter();
            let outcome = {
                let mut state = self.state.lock().unwrap();
                state.calls.push("install_udp");
                state.write_calls += 1;
                match state.fail_udp.take() {
                    Some(error) => Err(error),
                    None => Ok(UdpInstallFacts {
                        reused: false,
                        interface: "tc12345678".to_string(),
                        address: "10.66.0.1/24".to_string(),
                        port: 51_820,
                    }),
                }
            };
            let hold = self.state.lock().unwrap().hold;
            if !hold.is_zero() {
                std::thread::sleep(hold);
            }
            self.exit();
            outcome
        }

        fn probe_udp_state(&self, _req: &OpsReq) -> Result<ProbeFacts, OpsError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("probe_udp_state");
            if let Some(probe) = state.probe.pop_front() {
                return Ok(probe);
            }
            Ok(ProbeFacts {
                tunnel_up: true,
                conf_present: true,
                unit_active: true,
                listen_port: Some(51_820),
                peers: state.added_public.clone(),
            })
        }

        fn install_transport(&self, _req: &OpsReq) -> Result<Option<TransportFacts>, OpsError> {
            self.enter();
            let outcome = {
                let mut state = self.state.lock().unwrap();
                state.calls.push("install_transport");
                state.write_calls += 1;
                Ok(state.transport.clone())
            };
            let hold = self.state.lock().unwrap().hold;
            if !hold.is_zero() {
                std::thread::sleep(hold);
            }
            self.exit();
            outcome
        }

        fn read_transport(&self, _req: &OpsReq) -> Result<Option<TransportFacts>, OpsError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("read_transport");
            Ok(state.transport.clone())
        }

        fn add_peer(&self, _req: &OpsReq, client_public: &str) -> Result<PeerFacts, OpsError> {
            self.enter();
            let outcome = {
                let mut state = self.state.lock().unwrap();
                state.calls.push("add_peer");
                state.write_calls += 1;
                state.added_public.push(client_public.to_string());
                Ok(PeerFacts {
                    server_public: "SERVER-PUBLIC".to_string(),
                    client_public: client_public.to_string(),
                })
            };
            let hold = self.state.lock().unwrap().hold;
            if !hold.is_zero() {
                std::thread::sleep(hold);
            }
            self.exit();
            outcome
        }

        fn write_client_conf(
            &self,
            _req: &OpsReq,
            _client_private: &str,
            _server_public: &str,
        ) -> Result<(), OpsError> {
            self.state.lock().unwrap().calls.push("write_client_conf");
            Ok(())
        }

        fn register_lines(
            &self,
            req: &OpsReq,
            compatible: Option<&TransportFacts>,
            _preferred: Option<crate::config::Transport>,
        ) -> Result<Vec<LineFacts>, OpsError> {
            self.state.lock().unwrap().calls.push("register_lines");
            let host = req
                .record
                .map(|record| record.host.clone())
                .unwrap_or_default();
            let mut lines = vec![LineFacts {
                id: "L1".to_string(),
                name: format!("自建 · {host}"),
                endpoint: "127.0.0.1:1080".to_string(),
                transport: None,
            }];
            if compatible.is_some() {
                lines.push(LineFacts {
                    id: "L2".to_string(),
                    name: format!("自建 · {host}（兼容连接）"),
                    endpoint: "127.0.0.1:1081".to_string(),
                    transport: Some("Tcp".to_string()),
                });
            }
            // 真的写一份最小 config.json：`lines_present` 读的是它，假实现不能只用返回值糊弄。
            let mut cfg = crate::pairing::line::empty_config();
            cfg.lines.push(crate::config::LineConfig {
                id: "L1".to_string(),
                name: format!("自建 · {host}"),
                proxy_endpoint: "127.0.0.1:1080".to_string(),
                transport: None,
                verified_transport: None,
            });
            let _ = crate::config::save(
                &req.data_root.join(crate::config::DEFAULT_PATH),
                &cfg,
            );
            Ok(lines)
        }

        fn ensure_tunnel_key(&self, _dir: &Path) -> (String, String) {
            ("TEST-PRIVATE-KEY".to_string(), "TEST-PUBLIC-KEY".to_string())
        }
    }

    // -----------------------------------------------------------------------
    // 夹具
    // -----------------------------------------------------------------------

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-engine-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_run(root: &Path, run_id: &str, host: &str) -> RunRecord {
        make_run_with(root, run_id, host, "SHA256:AAAA")
    }

    /// 同 `make_run`，但指定记录里**记着**的指纹。
    ///
    /// `FakeOps::resolve_identity` 恒返回 `SHA256:AAAA`，所以传别的值就等于造出
    /// 「服务器身份与记录不一致」——这是四类故障里唯一不能靠注入错误码制造的一档：
    /// 它必须发生在只读核对的**比对**阶段，而不是某次调用失败。
    fn make_run_with(root: &Path, run_id: &str, host: &str, fingerprint: &str) -> RunRecord {
        let mut run = crate::deployrun::new_draft(
            run_id,
            &format!("自建 · {host}"),
            Target {
                host: host.to_string(),
                port: 22,
                user: "root".to_string(),
                server_record_id: None,
                ..Default::default()
            },
            fingerprint,
            "2026-11-09T00:00:00Z",
        );
        DeploymentStore::open(root).create(&mut run).unwrap();
        run
    }

    fn wait_for(root: &Path, run_id: &str, want: &[&str]) -> RunRecord {
        let store = DeploymentStore::open(root);
        let started = Instant::now();
        loop {
            if let Ok(run) = store.load(run_id) {
                if want.contains(&run.state.as_str()) {
                    return run;
                }
            }
            if started.elapsed() > Duration::from_secs(20) {
                let current = store.load(run_id).map(|run| run.state).unwrap_or_default();
                panic!("等不到状态 {want:?}，当前是 {current:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn engine(root: &Path, ops: Arc<FakeOps>) -> Engine {
        Engine::start(root.to_path_buf(), ops, crate::events::Origin::auto())
    }

    /// 轮询直到条件成立（用于「命令已发出、pass 还没起」的窗口）。
    fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
        let started = Instant::now();
        while !condition() {
            if started.elapsed() > Duration::from_secs(10) {
                panic!("等不到：{what}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 等这条记录的 pass 真正退场。
    ///
    /// 记录先变 `NeedsAttention`、pass 才返回，中间有个毫秒级窗口：这时点「继续」
    /// 会被幂等逻辑当成「还在跑」丢掉。真实界面在这个窗口里按钮还是禁用的，
    /// 测试必须显式等它过去，否则测的是竞态而不是产品行为。
    fn wait_idle(engine: &Engine, run_id: &str) {
        let started = Instant::now();
        loop {
            let handle = engine.handle();
            if !handle.is_active(run_id) && !handle.shared().is_queued(run_id) {
                return;
            }
            if started.elapsed() > Duration::from_secs(10) {
                panic!("pass 一直不退场：{run_id}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // -----------------------------------------------------------------------
    // 验收用例
    // -----------------------------------------------------------------------

    /// 正常一次跑完：四步全 Done、Complete、写动作恰好三次。
    /// r79：启动裁剪的三条护栏——归档不删、有未读提醒不删、读不到提醒整轮不裁。
    #[test]
    fn startup_pruning_keeps_archived_and_reminded_records() {
        let root = temp_root("prune-guard");
        let store = crate::deploystore::DeploymentStore::open(&root);
        let now = crate::model::now_epoch_secs_u64();
        let old = crate::selfcheck::at_rfc3339(now.saturating_sub(30 * 24 * 3600))
            .unwrap_or_default();
        let fresh = crate::selfcheck::at_rfc3339(now).unwrap_or_default();

        let mut make = |label: &str, finished: &str| {
            let id = crate::pairing::random_uuid_v4();
            let mut run = crate::deployrun::new_draft(
                &id,
                label,
                crate::deploystore::Target {
                    host: "203.0.113.10".to_string(),
                    port: 22,
                    user: "root".to_string(),
                    server_record_id: None,
                    ..Default::default()
                },
                "SHA256:AAAA",
                finished,
            );
            run.state = crate::deploystore::STATE_COMPLETE.to_string();
            run.finished_at_utc = Some(finished.to_string());
            run.updated_at_utc = Some(finished.to_string());
            store.create(&mut run).unwrap();
            run
        };

        let plain = make("普通旧记录", &old);
        let archived = make("归档过的旧记录", &old);
        let reminded = make("有未读提醒的旧记录", &old);
        let recent = make("刚完成的记录", &fresh);

        // 归档：用户按过「留着」。
        {
            let mut run = store.load(&archived.run_id).unwrap();
            run.archived_at_utc = Some(crate::deploystore::now_utc());
            store.save(&mut run).unwrap();
        }
        // 未读提醒：提醒里存着 RunId，删了「查看」就指向空。
        crate::reminder::note(&root, &reminded).expect("收提醒");

        let outcome = prune_records(&root).expect("提醒读得出来时必须给结论");
        assert_eq!(outcome.error, "", "{}", outcome.error);
        assert_eq!(outcome.removed, 1, "只该删「没归档、没提醒、够旧」那一条");
        assert!(store.load(&plain.run_id).is_err(), "普通旧记录应当被删");
        assert!(store.load(&archived.run_id).is_ok(), "归档的不许删");
        assert!(store.load(&reminded.run_id).is_ok(), "有未读提醒的不许删");
        assert!(store.load(&recent.run_id).is_ok(), "没超 7 天的不许删");

        // 读不到提醒 → 整轮不裁：宁可留，也不要删掉«可能有提醒»的那条。
        let another = make("第二条普通旧记录", &old);
        std::fs::write(crate::reminder::path(&root), b"{ not json").unwrap();
        assert!(
            prune_records(&root).is_none(),
            "提醒读不出来时必须整轮放弃，而不是当成「没有提醒」"
        );
        assert!(
            store.load(&another.run_id).is_ok(),
            "整轮放弃时一条都不许删"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_run_walks_all_four_steps_and_ends_complete() {
        let root = temp_root("clean");
        let ops = Arc::new(FakeOps::new());
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "aaaaaaaa-1111-4111-8111-111111111111", "10.0.0.1");

        engine
            .handle()
            .start_run(&run.run_id, Some(Credential::password("pw")));

        let done = wait_for(&root, &run.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert_eq!(done.state, STATE_COMPLETE, "{:?}", done.reason);
        assert_eq!(done.steps.iter().filter(|step| step.is_done()).count(), 4);
        assert!(done.pending_operation.is_none(), "跑完不许留下未决写");
        assert_eq!(done.next_action, NEXT_ACTION_VIEW_LINE);
        assert_eq!(ops.write_calls(), 3, "UDP + 兼容连接 + 接入本机");
        assert_eq!(ops.count("install_udp"), 1);

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 结果未知 → 只读核对确认「已生效」→ 清空未决写、继续跑完。核对**不许重发写**。
    #[test]
    fn an_unknown_write_is_reconciled_then_continues_without_replaying_it() {
        let root = temp_root("reconcile-applied");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_udp(OpsError::unknown(ERROR_CLASS_NETWORK, "NoMarker", "连接断了"));
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "bbbbbbbb-1111-4111-8111-111111111111", "10.0.0.2");

        engine
            .handle()
            .start_run(&run.run_id, Some(Credential::password("pw")));
        let waiting = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION, STATE_COMPLETE]);
        assert_eq!(waiting.state, STATE_NEEDS_ATTENTION);
        assert_eq!(waiting.reason.as_ref().unwrap().category, REASON_OUTCOME_UNKNOWN);
        assert!(waiting.pending_operation.is_some(), "结果未知必须留下未决写");
        assert_eq!(ops.count("install_udp"), 1);
        wait_idle(&engine, &run.run_id);

        engine
            .handle()
            .continue_run(&run.run_id, Some(Credential::password("pw")), true);

        // 只等 Complete：记录此刻还是 NeedsAttention，把它放进 want 会立刻「命中」。
        let done = wait_for(&root, &run.run_id, &[STATE_COMPLETE]);
        assert!(done.pending_operation.is_none(), "核对通过要清空未决写");
        assert_eq!(ops.count("install_udp"), 1, "核对绝不能重发写命令");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 核对仍是「不知道」→ 保持 NeedsAttention/OutcomeUnknown，写调用次数不变。
    #[test]
    fn a_reconcile_that_stays_unknown_never_touches_the_server() {
        let root = temp_root("reconcile-unknown");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_udp(OpsError::unknown(ERROR_CLASS_NETWORK, "NoMarker", "连接断了"));
        // conf 在、接口 down：既不是「生效」也不是「明确没生效」。
        ops.push_probe(ProbeFacts {
            tunnel_up: false,
            conf_present: true,
            unit_active: false,
            listen_port: None,
            peers: Vec::new(),
        });
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "cccccccc-1111-4111-8111-111111111111", "10.0.0.3");

        engine
            .handle()
            .start_run(&run.run_id, Some(Credential::password("pw")));
        wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION]);
        wait_idle(&engine, &run.run_id);

        let probes_before = ops.count("probe_udp_state");
        engine
            .handle()
            .continue_run(&run.run_id, Some(Credential::password("pw")), true);
        wait_until(
            || ops.count("probe_udp_state") > probes_before,
            "核对时的只读探针",
        );
        wait_idle(&engine, &run.run_id);
        let again = DeploymentStore::open(&root).load(&run.run_id).unwrap();
        assert_eq!(again.reason.as_ref().unwrap().category, REASON_OUTCOME_UNKNOWN);
        assert_eq!(again.next_action, NEXT_ACTION_RECONCILE);
        assert_eq!(again.pending_operation.as_ref().unwrap().outcome, OUTCOME_UNKNOWN);
        assert_eq!(ops.write_calls(), 1, "核对前后都不许多写一次");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 同一台服务器两条记录必须串行（lane 不空闲就排队），并发峰值 = 1。
    #[test]
    fn two_runs_on_the_same_server_never_overlap() {
        let root = temp_root("lane");
        let ops = Arc::new(FakeOps::new());
        ops.set_hold(Duration::from_millis(60));
        let engine = engine(&root, ops.clone());
        let one = make_run(&root, "dddddddd-1111-4111-8111-111111111111", "10.0.0.4");
        let two = make_run(&root, "eeeeeeee-1111-4111-8111-111111111111", "10.0.0.4");

        engine.handle().start_run(&one.run_id, Some(Credential::password("pw")));
        engine.handle().start_run(&two.run_id, Some(Credential::password("pw")));

        wait_for(&root, &one.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        wait_for(&root, &two.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert_eq!(ops.peak(), 1, "同一台服务器的两个 pass 不许重叠");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 两台不同服务器可以并发（峰值 ≥ 2）。
    #[test]
    fn two_servers_can_run_at_the_same_time() {
        let root = temp_root("parallel");
        let ops = Arc::new(FakeOps::new());
        // hold 原来只有 120ms：满负载跑全量时（r50 遇过一次）第一条 pass 会在
        // 第二条线程真的起来之前就退场，`peak` 只有 1 —— 那是**测试的时间窗太窄**，
        // 不是串行。放宽到 800ms，让「同时 active」成为必然而不是碰运气。
        ops.set_hold(Duration::from_millis(800));
        let engine = engine(&root, ops.clone());
        let one = make_run(&root, "ffffffff-1111-4111-8111-111111111111", "10.0.0.5");
        let two = make_run(&root, "11111111-2222-4222-8222-222222222222", "10.0.0.6");

        engine.handle().start_run(&one.run_id, Some(Credential::password("pw")));
        engine.handle().start_run(&two.run_id, Some(Credential::password("pw")));

        // 先确认两条都进了 active（这是「并发」的前提），再等它们跑完。
        // 只看最终状态的话，串行跑完也会通过——那正是这条用例要挡的反面。
        wait_until(
            || {
                engine.handle().is_active(&one.run_id) && engine.handle().is_active(&two.run_id)
            },
            "两台服务器同时 active",
        );
        wait_for(&root, &one.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        wait_for(&root, &two.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert!(ops.peak() >= 2, "两台服务器应当能并发，实际峰值 {}", ops.peak());

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 崩在「设备已加上」与「线路已登记」之间：核对必须判「没生效」，不许报 4/4。
    #[test]
    fn a_peer_without_registered_lines_is_not_reported_as_done() {
        let root = temp_root("peer-only");
        let ops = Arc::new(FakeOps::new());
        ops.push_peer("TEST-PUBLIC-KEY");
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "33333333-4444-4444-8444-444444444444", "10.0.0.8");

        // 手工造现场：前三步 Done、第四步留着未决写（add_peer 发出去了、登记没做）。
        let store = DeploymentStore::open(&root);
        let mut record = store.load(&run.run_id).unwrap();
        record.state = STATE_NEEDS_ATTENTION.to_string();
        record.step = Some(3);
        for index in 0..3 {
            record.steps[index].status = STEP_STATUS_DONE.to_string();
        }
        record.plan.udp_port = 51_820;
        record.pending_operation = Some(PendingOperation {
            kind: PENDING_KIND_ADD_PEER.to_string(),
            attempt_no: 1,
            started_at_utc: Some(now_utc()),
            verify_by: VERIFY_BY_PROBE_UDP_STATE.to_string(),
            plan_digest: record.plan_digest.clone(),
            client_public_key: Some("TEST-PUBLIC-KEY".to_string()),
            outcome: OUTCOME_PENDING.to_string(),
        });
        store.save(&mut record).unwrap();

        engine
            .handle()
            .continue_run(&run.run_id, Some(Credential::password("pw")), true);
        wait_until(
            || {
                DeploymentStore::open(&root)
                    .load(&run.run_id)
                    .map(|record| {
                        record
                            .pending_operation
                            .as_ref()
                            .map(|pending| pending.outcome.as_str() != OUTCOME_PENDING)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            },
            "核对写出结论",
        );

        let after = DeploymentStore::open(&root).load(&run.run_id).unwrap();
        assert_eq!(
            after.state, STATE_NEEDS_ATTENTION,
            "设备在但线路没登记，不能算完成"
        );
        assert_eq!(after.next_action, NEXT_ACTION_RETRY_STEP);
        assert_eq!(
            after.pending_operation.as_ref().unwrap().outcome,
            OUTCOME_NOT_APPLIED
        );
        assert!(after.steps.iter().filter(|step| step.is_done()).count() < 4);

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 连点「继续」只产生一个有效后续操作：写命令只发一次。
    #[test]
    fn repeated_continue_clicks_do_not_duplicate_work() {
        let root = temp_root("idempotent");
        let ops = Arc::new(FakeOps::new());
        ops.set_hold(Duration::from_millis(80));
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "22222222-3333-4333-8333-333333333333", "10.0.0.7");

        engine
            .handle()
            .start_run(&run.run_id, Some(Credential::password("pw")));
        for _ in 0..5 {
            engine
                .handle()
                .continue_run(&run.run_id, Some(Credential::password("pw")), false);
        }

        let done = wait_for(&root, &run.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert_eq!(done.state, STATE_COMPLETE, "{:?}", done.reason);
        assert_eq!(ops.count("install_udp"), 1, "连点不许重复安装");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // IPC ↔ 引擎的接缝
    // -----------------------------------------------------------------------

    fn ipc_ctx(root: &Path, engine: &Engine) -> crate::ipc::Ctx {
        crate::ipc::Ctx {
            root: root.to_path_buf(),
            log_dir: root.join("logs"),
            engine: Some(engine.handle()),
            ..Default::default()
        }
    }

    fn call_ipc(ctx: &crate::ipc::Ctx, raw: &str) -> serde_json::Value {
        serde_json::from_str(&crate::ipc::handle_line_with(raw, ctx)).expect("回包必须是 JSON")
    }

    /// `deployment-start` 真的会建记录并把 pass 跑起来。
    ///
    /// 这条用例专门盯接缝：`Ctx.engine` 是 `Option`，两层各自测都绿、接缝没接上，
    /// 表现出来就是「点了开始，什么都没发生」——只有真机才发现。
    #[test]
    fn the_ipc_start_command_really_enqueues_a_pass() {
        let root = temp_root("ipc-start");
        let ops = Arc::new(FakeOps::new());
        let engine = engine(&root, ops.clone());
        let ctx = ipc_ctx(&root, &engine);

        let reply = call_ipc(
            &ctx,
            r#"{"cmd":"deployment-start","spec":"root@10.0.0.9","fingerprint":"SHA256:AAAA","password":"pw"}"#,
        );
        assert_eq!(reply["ok"], json!(true), "{reply}");
        let run_id = reply["deployment"]["RunId"].as_str().unwrap().to_string();
        assert!(crate::deploystore::is_run_id(&run_id), "{run_id}");

        // 受理之后记录必须**已经在磁盘上**（`deployment-start` 先落盘再投递）。
        let stored = DeploymentStore::open(&root)
            .load(&run_id)
            .expect("受理后记录必须已落盘");

        let done = wait_for(&root, &run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert_eq!(done.state, STATE_COMPLETE, "{:?}", done.reason);
        assert_eq!(done.steps.iter().filter(|step| step.is_done()).count(), 4);
        assert_eq!(ops.write_calls(), 3);
        assert_eq!(ops.count("install_udp"), 1);
        assert_eq!(stored.revision, 1, "create 之后是第 1 版");

        // `deployment-get` 读的是同一份事实：四步、状态、主行动作都要能对上。
        let view = call_ipc(
            &ctx,
            &format!(r#"{{"cmd":"deployment-get","runId":"{run_id}"}}"#),
        );
        assert_eq!(view["ok"], json!(true), "{view}");
        assert_eq!(view["deployment"]["Run"]["State"], json!(STATE_COMPLETE));
        assert_eq!(view["deployment"]["Run"]["StepsDone"], json!(4));
        assert_eq!(
            view["deployment"]["Run"]["Action"],
            json!("viewLine"),
            "完成之后的主动作是「查看线路」"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `deployment-list` 把「未完成」放进 `Tasks`、把跑完的放进 `Deployments`。
    #[test]
    fn the_ipc_list_projects_running_and_finished_runs_apart() {
        let root = temp_root("ipc-list");
        let ops = Arc::new(FakeOps::new());
        ops.set_hold(Duration::from_millis(120));
        let engine = engine(&root, ops.clone());
        let ctx = ipc_ctx(&root, &engine);

        let reply = call_ipc(
            &ctx,
            r#"{"cmd":"deployment-start","spec":"root@10.0.0.10","fingerprint":"SHA256:AAAA","password":"pw"}"#,
        );
        let run_id = reply["deployment"]["RunId"].as_str().unwrap().to_string();

        // 跑到一半：`Tasks` 里有它，`Running` 必须为真（记录 Running **且** 引擎里有活动 pass）。
        wait_until(
            || {
                DeploymentStore::open(&root)
                    .load(&run_id)
                    .map(|run| run.state == STATE_RUNNING)
                    .unwrap_or(false)
            },
            "记录进入 Running",
        );
        let mid = call_ipc(&ctx, r#"{"cmd":"deployment-list"}"#);
        assert_eq!(mid["ok"], json!(true), "{mid}");
        let tasks = mid["deployment"]["Tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1, "{mid}");
        assert_eq!(tasks[0]["Id"], json!(run_id));
        assert_eq!(tasks[0]["Running"], json!(null), "Tasks 没有 Running 字段");
        assert_eq!(mid["deployment"]["Deployments"][0]["Running"], json!(true));

        wait_for(&root, &run_id, &[STATE_COMPLETE]);
        let after = call_ipc(&ctx, r#"{"cmd":"deployment-list"}"#);
        assert!(
            after["deployment"]["Tasks"].as_array().unwrap().is_empty(),
            "跑完就不该留在「未完成」里：{after}"
        );
        assert_eq!(after["deployment"]["Deployments"][0]["RunId"], json!(run_id));
        assert_eq!(
            after["deployment"]["Deployments"][0]["Running"],
            json!(false)
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 取消一条还在排队的记录：要**同时**离开队列并落终态。
    ///
    /// 只落终态不清队列时，`promote` 仍会把它拎起来（它只看「在不在队列」），
    /// 白占一个 lane 名额——另一台服务器可能因此排不上。
    #[test]
    fn cancelling_a_queued_run_removes_it_from_the_queue() {
        let root = temp_root("cancel-queued");
        let ops = Arc::new(FakeOps::new());
        // 第一条把 lane 占久一点：**断言必须在它还没跑完时做**。
        // 否则它一跑完 `two` 就会被 `promote` 拎走（那时「清没清队列」看不出区别），
        // 这条用例就成了假绿——第一版正是这么写的，去掉 `retain` 也照样绿。
        ops.set_hold(Duration::from_millis(1_200));
        let engine = engine(&root, ops.clone());
        let one = make_run(&root, "44444444-5555-4555-8555-555555555555", "10.0.0.11");
        let two = make_run(&root, "55555555-6666-4666-8666-666666666666", "10.0.0.11");

        // 同一个 lane：第二条必然先排队。
        engine.handle().start_run(&one.run_id, Some(Credential::password("pw")));
        engine.handle().start_run(&two.run_id, Some(Credential::password("pw")));
        wait_until(
            || engine.handle().shared().is_queued(&two.run_id),
            "第二条进入队列",
        );

        engine.handle().cancel(&two.run_id);
        wait_until(
            || {
                DeploymentStore::open(&root)
                    .load(&two.run_id)
                    .map(|run| run.state == STATE_CANCELLED)
                    .unwrap_or(false)
            },
            "取消落终态",
        );

        // lane 还占着：这时它必须**已经离开队列**。没有这一步，取消掉的记录
        // 会在下一次 `promote` 被拎起来，白占一个名额。
        assert!(
            !engine.handle().shared().is_queued(&two.run_id),
            "取消后必须立刻离开队列，而不是等被提升时才退出"
        );
        assert!(!engine.handle().is_active(&two.run_id), "取消的记录不该有 pass");

        let after = DeploymentStore::open(&root).load(&two.run_id).unwrap();
        assert!(
            after.steps.iter().all(|step| !step.is_done()),
            "没跑过就不该有已完成的步骤"
        );

        // 收尾：放开第一条，让它正常跑完（不把 9 秒留在这里）。
        ops.set_hold(Duration::ZERO);
        wait_for(&root, &one.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // T09：关窗守卫的那句话
    // -----------------------------------------------------------------------

    /// 排队也算「没跑完」。只数活动 pass 会让「刚点开始就关窗」漏判——
    /// 那一秒记录还躺在队列里，进程一退就丢了。
    #[test]
    fn a_queued_deployment_also_counts_as_unfinished() {
        assert_eq!(busy_sentence(0, 0), None, "真的没有部署：放行退出");
        assert_eq!(
            busy_sentence(0, 1).as_deref(),
            Some("还有 1 个部署没有完成"),
            "排队中的也必须拦住：退出等于把它丢掉"
        );
        assert_eq!(
            busy_sentence(1, 0).as_deref(),
            Some("还有 1 个部署没有完成")
        );
        assert_eq!(
            busy_sentence(2, 1).as_deref(),
            Some("还有 3 个部署没有完成"),
            "条数是活动 + 排队，不是二选一"
        );
    }

    // -----------------------------------------------------------------------
    // T04：启动恢复
    // -----------------------------------------------------------------------

    /// 把一条记录改成「上一个进程跑到一半就死了」的样子。
    fn write_dead_run(root: &Path, run_id: &str, pid: i64, heartbeat_ago: u64) -> u64 {
        let store = DeploymentStore::open(root);
        let mut run = store.load(run_id).unwrap();
        run.state = STATE_RUNNING.to_string();
        run.step = Some(1);
        run.next_action = NEXT_ACTION_NONE.to_string();
        run.steps[0].status = STEP_STATUS_DONE.to_string();
        run.steps[1].status = STEP_STATUS_RUNNING.to_string();
        run.executor = Some(Executor {
            instance_id: "dead-process".to_string(),
            pid,
            heartbeat_at_utc: Some(crate::deploystore::stamp_utc(
                crate::model::now_epoch_secs_u64().saturating_sub(heartbeat_ago),
            )),
            background: false,
        });
        store.save(&mut run).unwrap();
        store.load(run_id).unwrap().revision
    }

    /// 重启扫描把死执行者的记录改判成 `NeedsAttention`，并且**不重新入队**。
    ///
    /// 这条用例同时守三件事：状态改对了、`Running` 投影为假（页面不再说「正在部署」）、
    /// 一次 `Ops` 调用都没有（恢复不登录、不探测、不重放任何写命令）。
    #[test]
    fn startup_recovery_judges_a_dead_record_without_rerunning_anything() {
        let root = temp_root("recover-dead");
        let run_id = "cccccccc-2222-4222-8222-222222222222";
        make_run(&root, run_id, "10.0.0.7");
        let revision_before = write_dead_run(&root, run_id, 999_999, 600);

        let ops = Arc::new(FakeOps::new());
        let engine = engine(&root, ops.clone());
        let report = engine.recover_all();
        assert_eq!(report.rewritten, 1, "{report:?}");
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(engine.handle().recover_error(), "");

        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(after.state, STATE_NEEDS_ATTENTION);
        assert_eq!(
            after.reason.as_ref().unwrap().category,
            crate::deploystore::REASON_INTERRUPTED
        );
        assert_eq!(after.next_action, NEXT_ACTION_RETRY_STEP);
        assert!(
            after.revision > revision_before,
            "改判必须落一次盘（{} → {}）",
            revision_before,
            after.revision
        );

        // 页面「正在部署」的两条判据，现在都为假。
        assert!(!crate::deployrun::is_running(
            &after,
            engine.handle().is_active(run_id)
        ));
        assert!(!engine.handle().shared().is_queued(run_id), "永不自动入队");
        assert!(
            ops.count("resolve_identity") == 0 && ops.write_calls() == 0,
            "恢复不许发起任何执行"
        );

        // 留痕：一行「部署恢复」，含 RunId 短码，不含服务器名。
        let log = std::fs::read_to_string(crate::events::path(&root)).unwrap();
        assert!(log.contains("部署恢复"), "{log}");
        assert!(log.contains("cccccccc"), "{log}");
        assert!(!log.contains("自建 · 10.0.0.7"), "恢复记录不带任务名：{log}");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 本进程自己的活动记录（pid 相同 + 心跳新鲜）一个字都不许改。
    #[test]
    fn startup_recovery_leaves_a_live_record_alone() {
        let root = temp_root("recover-live");
        let run_id = "dddddddd-3333-4333-8333-333333333333";
        make_run(&root, run_id, "10.0.0.8");
        let revision_before =
            write_dead_run(&root, run_id, i64::from(std::process::id()), 0);

        let engine = engine(&root, Arc::new(FakeOps::new()));
        let report = engine.recover_all();
        assert_eq!(report.rewritten, 0, "{report:?}");

        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(after.state, STATE_RUNNING, "本进程的记录不许被自己改判");
        assert_eq!(after.revision, revision_before, "没有改动就不该落盘");
        assert!(after.reason.is_none());

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 改判写盘失败：记录**原样留在** `Running`（没有改动，所以没有说谎），
    /// 但结论必须交出去——`recover_error` 非空，`deployment-list` 会据此报「读不出来」。
    ///
    /// 这条只对 Windows 有意义：那边的 `rename` 覆盖只读文件会失败，Unix 不会。
    #[cfg(windows)]
    #[test]
    fn a_failed_recovery_write_is_reported_instead_of_left_looking_alive() {
        let root = temp_root("recover-fail");
        let run_id = "eeeeeeee-4444-4444-8444-444444444444";
        make_run(&root, run_id, "10.0.0.9");
        write_dead_run(&root, run_id, 999_999, 600);
        let path = root.join("deployments").join("runs").join(format!("{run_id}.json"));
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        let engine = engine(&root, Arc::new(FakeOps::new()));
        let report = engine.recover_all();
        assert_eq!(report.rewritten, 0);
        assert_eq!(report.failed, 1, "{report:?}");
        assert!(!report.is_clean());
        assert!(report.error.contains("写盘失败"), "{}", report.error);
        assert!(
            !engine.handle().recover_error().is_empty(),
            "结论必须能被 deployment-list 读到"
        );

        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(after.state, STATE_RUNNING, "写不进去就不许假装写进去了");

        // 收尾：放开只读，否则删目录会失败。
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // T11：P0 验收主链路（端到端）
    // -----------------------------------------------------------------------

    /// 要点 1：同一条部署从头到尾是**一个** RunId；「转后台」既不改记录身份，也不打断推进。
    ///
    /// 三个断言各有各的用处：`Revision` 严格递增证明每一步都真的落了盘（不是内存里
    /// 自说自话）；`StepsDone` 单调不减且真的变过证明推进发生了（只验终态的话，
    /// 中间卡住再跳过去也会通过）；转后台之后还在涨，证明执行上下文在引擎里而不是页面里。
    #[test]
    fn one_run_id_survives_background_and_keeps_moving() {
        let root = temp_root("one-run");
        let ops = Arc::new(FakeOps::new());
        // 让每一步慢下来：太快的话整条流程在两次采样之间就跑完了，
        // 「单调递增」会退化成只有一个点——那种断言永远为真。
        ops.set_hold(Duration::from_millis(120));
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "cccccccc-1111-4111-8111-111111111111", "10.0.0.3");
        let store = DeploymentStore::open(&root);

        engine.handle().start_run(&run.run_id, Some(Credential::password("pw")));

        let mut samples: Vec<(u64, u32)> = Vec::new();
        let mut backgrounded = false;
        let mut saw_growth = false;
        let started = Instant::now();
        loop {
            if let Ok(current) = store.load(&run.run_id) {
                assert_eq!(current.run_id, run.run_id, "RunId 不许中途换");
                let point = (current.revision, crate::deployrun::steps_done(&current));
                if samples.last() != Some(&point) {
                    if let Some(previous) = samples.last() {
                        assert!(
                            point.0 > previous.0,
                            "Revision 必须严格递增：{samples:?} → {point:?}"
                        );
                        assert!(
                            point.1 >= previous.1,
                            "StepsDone 不许回退：{samples:?} → {point:?}"
                        );
                        saw_growth |= point.1 > previous.1;
                    }
                    samples.push(point);
                }
                // 「转后台」只在真的有 pass 在跑时才有意义（ipc 层也是这么判的）。
                if !backgrounded && engine.handle().is_active(&run.run_id) {
                    engine.handle().background(&run.run_id);
                    backgrounded = true;
                }
                match current.state.as_str() {
                    STATE_COMPLETE => break,
                    STATE_NEEDS_ATTENTION | STATE_CANCELLED => {
                        panic!("跑出了不该出现的状态：{} {:?}", current.state, current.reason)
                    }
                    _ => {}
                }
            }
            if started.elapsed() > Duration::from_secs(20) {
                panic!("20 秒还没跑完，采样={samples:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(backgrounded, "这条用例必须真的点过「转后台」");
        assert!(
            saw_growth,
            "StepsDone 一次都没变，等于没测到推进：{samples:?}"
        );
        assert!(
            samples.len() >= 4,
            "采样点太少（{}），单调性没有说服力",
            samples.len()
        );
        let done = store.load(&run.run_id).unwrap();
        assert_eq!(done.state, STATE_COMPLETE);
        assert_eq!(crate::deployrun::steps_done(&done), 4);
        assert_eq!(ops.count("install_udp"), 1, "转后台不许重发写");
        assert!(done.pending_operation.is_none(), "跑完不许留下未决写");

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// pass 手里的记录副本可能落后于监督线程的落盘（心跳、转后台走 `mutate`，
    /// 各自把 `Revision` +1）。进度保存必须以磁盘上的最新版本为起点，否则两次
    /// 落盘会撞出同一个 `Revision`——满载跑全量时 `one_run_id_survives…`
    /// 就是被这个竞态打红的，而且它只在负载高、心跳恰好插进两步之间时出现。
    #[test]
    fn a_pass_save_starts_from_the_revision_on_disk() {
        let root = temp_root("revision-race");
        let ops = Arc::new(FakeOps::new());
        let engine = engine(&root, ops);
        let run = make_run(&root, "abababab-1111-4111-8111-111111111111", "10.0.0.9");
        let store = DeploymentStore::open(&root);

        // 两个读者各拿一份同一版本的记录：pass 与监督线程。
        let mut pass_copy = store.load(&run.run_id).unwrap();
        let mut supervisor_copy = store.load(&run.run_id).unwrap();
        supervisor_copy.updated_at_utc = Some(now_utc());
        store.save(&mut supervisor_copy).unwrap();
        assert_eq!(supervisor_copy.revision, 2, "监督线程先落一版");

        // pass 用旧副本保存进度：版本号必须接着磁盘走（2 → 3），不能也写成 2。
        engine.handle.inner.save(&mut pass_copy).unwrap();
        assert_eq!(
            pass_copy.revision, 3,
            "两次落盘不许共用同一个 Revision（pass 的副本落后一版）"
        );
        assert_eq!(store.load(&run.run_id).unwrap().revision, 3);

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 重试在记录上必须是**第二次尝试**：第一次的错误码留在历史里。
    ///
    /// 这条走真实 pass（不是纯函数）：`mark_running` 是唯一知道「一次 pass 开始了」的
    /// 地方，判据放错地方时只有这里能抓到。
    #[test]
    fn a_retry_after_a_failed_pass_records_a_second_attempt() {
        let root = temp_root("attempt-history");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_env(OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "EnvUnreadable",
            "读不到服务器环境",
        ));
        let eng = engine(&root, ops);
        let run = make_run(&root, "e1000000-1111-4111-8111-111111111111", "10.1.0.9");
        eng.handle().start_run(&run.run_id, None);
        let stopped = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION]);
        assert_eq!(stopped.attempts.len(), 1, "第一次失败：还是同一条尝试");
        assert!(
            stopped.attempts[0].finished_at_utc.is_some(),
            "失败必须给这次尝试写上结束时间"
        );
        assert_eq!(stopped.attempts[0].failed_step, Some(0));
        assert_eq!(stopped.attempts[0].error_code, "EnvUnreadable");

        // 等 pass 真正退场再点继续：中间那个毫秒级窗口会被幂等逻辑吞掉。
        wait_idle(&eng, &run.run_id);
        eng.handle().continue_run(&run.run_id, None, false);
        // 不能直接 `wait_for([Complete, NeedsAttention])`：状态本来就在 NeedsAttention，
        // 那一等会立刻返回旧记录（测的就不是重试了）。等的是**记录上出现第二次尝试**。
        wait_until(
            || {
                DeploymentStore::open(&root)
                    .load(&run.run_id)
                    .map(|item| {
                        item.attempts
                            .get(1)
                            .map(|attempt| attempt.finished_at_utc.is_some())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            },
            "第二次尝试跑出结论",
        );
        let after = DeploymentStore::open(&root).load(&run.run_id).unwrap();
        assert_eq!(after.attempts.len(), 2, "重试必须是新的一次尝试");
        assert_eq!(
            after.attempts[0].error_code, "EnvUnreadable",
            "第一次的结论不许被抹掉"
        );
        assert_eq!(after.attempts[1].no, 2);
        assert!(
            after.attempts[1].finished_at_utc.is_some(),
            "第二次跑完也要有结论"
        );

        drop(eng);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P1-3：一次失败的 pass 要在磁盘上留下一条未读提醒——关掉窗口也还在。
    #[test]
    fn a_failed_pass_leaves_one_unread_reminder() {
        let root = temp_root("reminder-fail");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_env(OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "EnvUnreadable",
            "读不到服务器环境",
        ));
        let eng = engine(&root, ops);
        let run = make_run(&root, "f1000000-1111-4111-8111-111111111111", "10.1.1.1");
        eng.handle().start_run(&run.run_id, None);
        let stopped = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION]);
        assert_eq!(stopped.attempts.len(), 1);

        // 记录先落盘、提醒紧接着写——两步之间有个毫秒级窗口。等它出现，
        // 别把「写提醒还没轮到」当成「没写提醒」。
        wait_until(
            || {
                crate::reminder::unread(&root)
                    .map(|items| items.len() == 1)
                    .unwrap_or(false)
            },
            "未读提醒出现在磁盘上",
        );
        let unread = crate::reminder::unread(&root).expect("读提醒");
        assert_eq!(unread.len(), 1, "一次结果只提醒一次");
        assert_eq!(unread[0].run_id, run.run_id);
        assert_eq!(unread[0].state, STATE_NEEDS_ATTENTION);
        assert_eq!(unread[0].step, 0, "去重键里的「阶段」是失败的那一步");
        assert_eq!(unread[0].code, "EnvUnreadable");
        assert_eq!(unread[0].name, "自建 · 10.1.1.1");

        // 同一条记录再被保存（心跳/转后台/重试准备）不许再提醒一次。
        crate::reminder::note(&root, &stopped).expect("幂等");
        assert_eq!(crate::reminder::unread(&root).unwrap().len(), 1);

        drop(eng);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 要点 3：四类故障各自只给**允许的那一个**下一步。
    ///
    /// 四档分开造，因为它们的区别不在「失败了」而在「下一步允许做什么」：
    /// 只读失败 / 明确写失败 → 重试本步骤；写结果未知 → 只能核对（不许重发写）；
    /// 身份变化 → 重新核对指纹（连重试都不给，因为「重试」等于拿错的身份再试一次）。
    #[test]
    fn four_fault_classes_offer_only_their_allowed_action() {
        // ① 只读检查失败（Step0）：脚本自己说读不到环境。
        let root = temp_root("fault-readonly");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_env(OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "EnvUnreadable",
            "读不到服务器环境",
        ));
        let eng = engine(&root, ops);
        let run = make_run(&root, "d1000000-1111-4111-8111-111111111111", "10.1.0.1");
        eng.handle().start_run(&run.run_id, Some(Credential::password("pw")));
        let stopped = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION, STATE_COMPLETE]);
        assert_eq!(stopped.state, STATE_NEEDS_ATTENTION, "① 只读失败");
        assert_eq!(
            stopped.steps[0].status,
            crate::deploystore::STEP_STATUS_FAILED,
            "① Step0 应当是 Failed"
        );
        assert_eq!(stopped.reason.as_ref().unwrap().category, REASON_FAILED, "①");
        assert_eq!(
            stopped.next_action,
            crate::deploystore::NEXT_ACTION_RETRY_STEP,
            "① 只读失败只给「重试本步骤」"
        );
        assert!(stopped.pending_operation.is_none(), "① 还没写，不许留未决写");
        drop(eng);
        let _ = std::fs::remove_dir_all(&root);

        // ② 明确写失败（Step1）：脚本自己说没装成，可以重试。
        let root = temp_root("fault-write");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_udp(OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "ListenFailed",
            "端口被占用",
        ));
        let eng = engine(&root, ops);
        let run = make_run(&root, "d2000000-1111-4111-8111-111111111111", "10.1.0.2");
        eng.handle().start_run(&run.run_id, Some(Credential::password("pw")));
        let stopped = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION, STATE_COMPLETE]);
        assert_eq!(stopped.state, STATE_NEEDS_ATTENTION, "② 明确写失败");
        assert_eq!(stopped.reason.as_ref().unwrap().category, REASON_FAILED, "②");
        assert_eq!(
            stopped.reason.as_ref().unwrap().code,
            "ListenFailed",
            "② 脚本自述的失败码要原样带出来"
        );
        assert_eq!(
            stopped.next_action,
            crate::deploystore::NEXT_ACTION_RETRY_STEP,
            "② 明确没写成就允许重试"
        );
        assert!(
            stopped.pending_operation.is_none(),
            "② 「明确没做成」不是未决写"
        );
        drop(eng);
        let _ = std::fs::remove_dir_all(&root);

        // ③ 写结果未知（Step1）：写成功但只读核对说不清。
        let root = temp_root("fault-unknown");
        let ops = Arc::new(FakeOps::new());
        // 端口对不上、又不是「三者全假」→ 既不是 matches_plan 也不是 clearly_not_applied。
        ops.push_probe(ProbeFacts {
            tunnel_up: true,
            conf_present: true,
            unit_active: true,
            listen_port: Some(9999),
            peers: Vec::new(),
        });
        let eng = engine(&root, ops);
        let run = make_run(&root, "d3000000-1111-4111-8111-111111111111", "10.1.0.3");
        eng.handle().start_run(&run.run_id, Some(Credential::password("pw")));
        let stopped = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION, STATE_COMPLETE]);
        assert_eq!(stopped.state, STATE_NEEDS_ATTENTION, "③ 写结果未知");
        assert_eq!(
            stopped.reason.as_ref().unwrap().category,
            REASON_OUTCOME_UNKNOWN,
            "③"
        );
        assert_eq!(
            stopped.next_action,
            crate::deploystore::NEXT_ACTION_RECONCILE,
            "③ 结果未知只能核对，不许给重试"
        );
        let pending = stopped.pending_operation.as_ref().expect("③ 必须留下未决写");
        assert_eq!(
            pending.outcome,
            crate::deploystore::OUTCOME_UNKNOWN,
            "③ 核对也说不清"
        );
        // 「没有直接重装入口」的可执行版本：唯一动作是 reconcile，不是 continue。
        assert_eq!(
            crate::deployrun::action_of(&stopped),
            ("reconcile", "核对原操作"),
            "③ 详情页的主动作必须是核对"
        );
        drop(eng);
        let _ = std::fs::remove_dir_all(&root);

        // ④ 身份变化：**续跑时**记录里的指纹与服务器返回的对不上。
        //
        // 注意这一档必须走「先停下、再续跑」：首次部署（`resume_from == 0`）不比对指纹
        // ——那时记录里的指纹是用户刚刚确认过的，没有第二个来源可以比。真实场景也正是
        // 「上次记着的指纹，这次连上去发现变了」，所以先造一次明确失败把记录停在 Step1。
        let root = temp_root("fault-identity");
        let ops = Arc::new(FakeOps::new());
        ops.fail_next_udp(OpsError::definite(
            ERROR_CLASS_ENVIRONMENT,
            "ListenFailed",
            "先停一下",
        ));
        let eng = engine(&root, ops);
        let run = make_run_with(
            &root,
            "d4000000-1111-4111-8111-111111111111",
            "10.1.0.4",
            "SHA256:AAAA",
        );
        eng.handle().start_run(&run.run_id, Some(Credential::password("pw")));
        let first_stop = wait_for(&root, &run.run_id, &[STATE_NEEDS_ATTENTION, STATE_COMPLETE]);
        assert_eq!(first_stop.state, STATE_NEEDS_ATTENTION, "④ 前置：先停在 Step1");
        wait_idle(&eng, &run.run_id);

        // 把记录里的指纹改掉（模拟「服务器换了身份」，或记录被写坏）。
        let store = DeploymentStore::open(&root);
        let mut tampered = store.load(&run.run_id).unwrap();
        tampered.identity.fingerprint = "SHA256:WRONG".to_string();
        store.save(&mut tampered).unwrap();

        eng.handle()
            .continue_run(&run.run_id, Some(Credential::password("pw")), false);
        // **不能**用 `wait_for(NeedsAttention)`：记录此刻已经是第一次失败留下的
        // `NeedsAttention/Failed`，一进来就命中，读到的是上一帧（r48/r49 踩过的坑）。
        // 等一个只有续跑才会出现的信号：动作被改判成「重新核对指纹」。
        wait_until(
            || {
                DeploymentStore::open(&root)
                    .load(&run.run_id)
                    .map(|current| {
                        current.state == STATE_NEEDS_ATTENTION
                            && current.next_action
                                == crate::deploystore::NEXT_ACTION_CONFIRM_FINGERPRINT
                    })
                    .unwrap_or(false)
            },
            "④ 续跑后应改判成「需要处理 + 重新核对指纹」",
        );
        let stopped = DeploymentStore::open(&root).load(&run.run_id).unwrap();
        assert_eq!(stopped.state, STATE_NEEDS_ATTENTION, "④ 身份变化");
        assert_eq!(
            stopped.reason.as_ref().unwrap().category,
            REASON_IDENTITY_CHANGED,
            "④"
        );
        assert_eq!(
            stopped.next_action,
            crate::deploystore::NEXT_ACTION_CONFIRM_FINGERPRINT,
            "④ 身份对不上时「重试」等于拿错的身份再试一次，所以只给重新核对"
        );
        // 关键：已经做成的 Step0 必须还是 `Done`。上游校验失败不属于任何一步的执行失败，
        // 把它标成 `Failed` 会让页面说「检查服务器环境与身份：失败」，用户照着重试第 0 步，
        // 而真正该做的是核对指纹——这是 T11 验收抓到的真缺陷（`settle_attention` 传了 0）。
        assert_eq!(
            stopped.steps[0].status,
            crate::deploystore::STEP_STATUS_DONE,
            "④ 已经做成的步骤不许被这次改判污染"
        );
        assert!(stopped.steps[0].error.is_none(), "④ Step0 不该挂错误");
        assert_eq!(
            stopped.step,
            Some(1),
            "④ 步骤指针必须留在真正停下的那一步（Step1），不许被拽回第 0 步"
        );
        assert!(stopped.pending_operation.is_none(), "④ 没写过");
        drop(eng);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 要点 5：完成态 `Running=false`，线路登记过一次，且没有额外的写。
    ///
    /// 「完成」不等于「已连接」：这里能证明的只有「引擎没再碰服务器」——
    /// 代理与当前连接是另一层的事，不在部署引擎的职责里。
    #[test]
    fn a_completed_run_is_never_running_and_registers_its_lines() {
        let root = temp_root("complete-view");
        let ops = Arc::new(FakeOps::new());
        let engine = engine(&root, ops.clone());
        let run = make_run(&root, "e1000000-1111-4111-8111-111111111111", "10.2.0.1");

        engine.handle().start_run(&run.run_id, Some(Credential::password("pw")));
        let done = wait_for(&root, &run.run_id, &[STATE_COMPLETE, STATE_NEEDS_ATTENTION]);
        assert_eq!(done.state, STATE_COMPLETE, "{:?}", done.reason);
        // 记录先在磁盘上变成 Complete，pass 才退场——中间有个毫秒级窗口。
        // 「跑完了就不该还在跑」说的是引擎**退场之后**的事实，所以先等它退场。
        wait_idle(&engine, &run.run_id);

        // `Running` 的定义是两处同时成立；引擎里已经没有它了，所以必须为假。
        assert!(!engine.handle().is_active(&run.run_id));
        assert!(!crate::deployrun::is_running(&done, false));
        let view = crate::deployrun::run_view(&done, false);
        assert_eq!(view["Running"], serde_json::json!(false));
        assert_eq!(view["StepsDone"], serde_json::json!(4));
        assert_eq!(
            view["NextAction"],
            serde_json::json!(crate::deploystore::NEXT_ACTION_VIEW_LINE)
        );
        // 三个写步骤各一次，线路登记一次；完成之后不再有任何调用。
        assert_eq!(ops.write_calls(), 3);
        assert_eq!(ops.count("register_lines"), 1);
        assert_eq!(ops.count("install_udp"), 1);
        assert_eq!(ops.count("add_peer"), 1);

        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }
}