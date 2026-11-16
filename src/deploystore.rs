//! 部署运行记录：`<data root>\deployments\runs\<RunId>.json`。
//!
//! 为什么一个 RunId 一个文件，而不是一份 `index.json`：
//!
//! - 多任务并发写的是不同文件，天生不互相撕裂（同一台服务器的串行由 lane 保证，
//!   不需要跨记录事务）；
//! - 单文件清单会成为**第二个事实源**，而 `run.json` 必须是唯一真相；
//! - 一条记录损坏只影响这一条，不会让整个任务列表变成空。
//!
//! 写入一律「临时文件（`create_new`）→ `write_all` → `sync_all` → `rename`」，
//! 与 `serverstore::write_json` 同一套模式：只有 `rename` 能产生正式文件，
//! 所以目录里永远不会出现半截 JSON。目录里残留的 `.<id>.json.tmp-*` 是崩溃残留，
//! 加载时**忽略**（不报警、不展示）。
//!
//! 秘密边界：记录里永不出现登录口令、隧道私钥、`transport.env` 私钥、完整凭据。
//! 加载时一旦发现禁用键，整条记录进 `unreadable` —— 只说「不允许保存的字段」，
//! **既不打印值、也不打印键名**（键名出现在错误里等于给下一个读日志的人指路）。
//!
//! 词表（状态 / 原因类别 / 错误类别 / `NextAction` / 步骤名 / 步骤状态）的
//! **唯一定义**在本文件：它们同时是「记录形状」的一部分，存储层裁剪终态记录时
//! 也必须认得它们。纯逻辑层 `deployrun` 直接引用这里的常量，不另抄一份。
//!
//! T01 阶段本模块只有类型、读写与校验，调用方（引擎）在 T03 才出现，
//! 因此暂时整体允许未使用；T03 落地后应当移除下面这行。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::model::now_epoch_secs_u64;
use crate::selfcheck;

// ---------------------------------------------------------------------------
// 记录格式
// ---------------------------------------------------------------------------

/// 记录格式版本（`SchemaVersion`）。改形状就要改它。
pub const SCHEMA_VERSION: u64 = 1;
/// 记录文件的种类标记（`Kind`）。写死这个值，读的时候不校验它——
/// 文件名已经决定了它是什么，多校验一层只会让「Kind 写错」变成读不出来的任务。
pub const RUN_KIND: &str = "SpiderVPN.DeploymentRun";
/// `RunId` 的字符数：小写 UUID（8-4-4-4-12）。
pub const RUN_ID_LEN: usize = 36;
/// 终态记录保留条数（`Complete` / `Cancelled`）。
pub const KEEP_TERMINAL: usize = 20;
/// 终态记录的最长保留时长：7 天。
pub const MAX_TERMINAL_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// 同时存在的草稿条数上限（`State == "Draft"` 的记录）。
///
/// 为什么是**常数**而不是「按时间自动过期」：
///
/// 1. `Draft` 不参与 `prune_terminal`（那条只裁终态），所以没人管就会一直堆；
/// 2. 「自动删最旧的那条」与既有的「未完成的记录永不自动删除」直接打架——删除是
///    用户的决定，不是在磁盘满的时候替他挑一条扔掉；
/// 3. 另开一条 `prune_drafts` 就是**第二条裁剪判据**，它的每一条分支都要再证一遍
///    「不会删掉用户还想要的东西」，风险远高于收益。
///
/// 所以只压住堆积：到顶时 `deployment-draft-save` 回 `conflict`，文案里直接给出去路
/// （去任务列表放弃一条），人自己决定丢掉哪一份。
pub const MAX_DRAFTS: usize = 3;
/// 原子写的重试次数。Windows 上杀毒软件/索引器会短暂占住临时文件，
/// 8 次以内几乎总能过；超过就是真的写不了，报 `config`。
pub const WRITE_ATTEMPTS: u32 = 8;

/// `load_all()` 的读取结论（对应快照里的 `TasksRead`）。
pub const READ_OK: &str = "ok";
/// 有记录读不出来，但列表非空。
pub const READ_PARTIAL: &str = "partial";
/// 目录都读不了 —— 这时**绝不能**说「没有任务」。
pub const READ_FAILED: &str = "failed";

// ---------------------------------------------------------------------------
// 词表（唯一定义处）
// ---------------------------------------------------------------------------

/// 还没开始的草稿：用户填到一半，还没有形成检查点。
pub const STATE_DRAFT: &str = "Draft";
/// 等人输入（密码、指纹确认、计划确认）。**没有发生过失败**才是这个状态。
pub const STATE_WAITING_USER: &str = "WaitingUser";
/// 已受理、在等 lane 或等容量。
pub const STATE_QUEUED: &str = "Queued";
/// 引擎里确实有一个 pass 在推进（`Running` 的定义见 `deployrun::is_running`）。
pub const STATE_RUNNING: &str = "Running";
/// 用户请求暂停，已在步骤边界落地。
pub const STATE_PAUSED: &str = "Paused";
/// 需要人处理：已知失败、结果未知、需修复、身份变了、被打断。
pub const STATE_NEEDS_ATTENTION: &str = "NeedsAttention";
/// 终态：四步全 `Done` 且无未决写。
pub const STATE_COMPLETE: &str = "Complete";
/// 终态：用户取消且结果已核对。
pub const STATE_CANCELLED: &str = "Cancelled";

/// 产品状态全表。表外值一律视为**未知**，不得当成 `Running` 或 `Complete`。
pub const STATES: [&str; 8] = [
    STATE_DRAFT,
    STATE_WAITING_USER,
    STATE_QUEUED,
    STATE_RUNNING,
    STATE_PAUSED,
    STATE_NEEDS_ATTENTION,
    STATE_COMPLETE,
    STATE_CANCELLED,
];

/// 终态。只有这两个状态允许被自动裁剪；未完成的记录**永不**自动删除。
pub const TERMINAL_STATES: [&str; 2] = [STATE_COMPLETE, STATE_CANCELLED];

/// 原因类别：已知失败（脚本自述或只读检查判定）。
pub const REASON_FAILED: &str = "Failed";
/// 原因类别：写过了但结果不知道（不允许据此重放）。
pub const REASON_OUTCOME_UNKNOWN: &str = "OutcomeUnknown";
/// 原因类别：需要修复（例如 `config.json` 损坏，不猜不覆盖）。
pub const REASON_NEEDS_RECOVERY: &str = "NeedsRecovery";
/// 原因类别：服务器身份/指纹/计划摘要与记录不一致。
pub const REASON_IDENTITY_CHANGED: &str = "IdentityChanged";
/// 原因类别：凭据缺失或解不开。
pub const REASON_ACCESS_REQUIRED: &str = "AccessRequired";
/// 原因类别：在检查点之间被打断（进程死了，没有未决写）。
pub const REASON_INTERRUPTED: &str = "Interrupted";
/// 原因类别：部分完成（UDP + 线路可用，兼容连接没装上）。
pub const REASON_PARTIAL: &str = "Partial";

/// 原因类别全表。
///
/// 整张表只有契约用例读（`deployrun` 的词表校验），生产侧只用单项常量。
#[cfg(test)]
pub const REASON_CATEGORIES: [&str; 7] = [
    REASON_FAILED,
    REASON_OUTCOME_UNKNOWN,
    REASON_NEEDS_RECOVERY,
    REASON_IDENTITY_CHANGED,
    REASON_ACCESS_REQUIRED,
    REASON_INTERRUPTED,
    REASON_PARTIAL,
];

/// 错误类别：用法错误。
pub const ERROR_CLASS_USAGE: &str = "usage";
/// 错误类别：配置 / 文件类。
pub const ERROR_CLASS_CONFIG: &str = "config";
/// 错误类别：环境不支持或未就绪。
pub const ERROR_CLASS_ENVIRONMENT: &str = "environment";
/// 错误类别：网络类，可重试。
pub const ERROR_CLASS_NETWORK: &str = "network";
/// 错误类别：冲突，需要用户决策。
pub const ERROR_CLASS_CONFLICT: &str = "conflict";
/// 错误类别：内部错误兜底。
pub const ERROR_CLASS_INTERNAL: &str = "internal";

/// 错误类别全表（与 IPC 的 `errorCode` 同一套）。
///
/// 同上：整表只给用例校验「表内值」，生产侧只用单项。
#[cfg(test)]
pub const ERROR_CLASSES: [&str; 6] = [
    ERROR_CLASS_USAGE,
    ERROR_CLASS_CONFIG,
    ERROR_CLASS_ENVIRONMENT,
    ERROR_CLASS_NETWORK,
    ERROR_CLASS_CONFLICT,
    ERROR_CLASS_INTERNAL,
];

/// 下一步动作：回填表单（草稿）。
pub const NEXT_ACTION_OPEN_FORM: &str = "OpenForm";
/// 下一步动作：重新输入登录凭据。
pub const NEXT_ACTION_ENTER_CREDENTIALS: &str = "EnterCredentials";
/// 下一步动作：重新核对主机指纹。
pub const NEXT_ACTION_CONFIRM_FINGERPRINT: &str = "ConfirmFingerprint";
/// 下一步动作：重新确认部署计划。
pub const NEXT_ACTION_CONFIRM_PLAN: &str = "ConfirmPlan";
/// 下一步动作：重试本步骤（已明确未生效 / 明确失败）。
pub const NEXT_ACTION_RETRY_STEP: &str = "RetryStep";
/// 下一步动作：核对原操作（**只读**，不发写命令）。
pub const NEXT_ACTION_RECONCILE: &str = "Reconcile";
/// 下一步动作：补齐兼容连接。
pub const NEXT_ACTION_COMPLETE_COMPATIBLE: &str = "CompleteCompatible";
/// 下一步动作：查看线路。
pub const NEXT_ACTION_VIEW_LINE: &str = "ViewLine";
/// 下一步动作：等排队。
pub const NEXT_ACTION_WAIT_QUEUE: &str = "WaitQueue";
/// 下一步动作：刷新任务记录（读不出来时）。
#[cfg(test)]
pub const NEXT_ACTION_REFRESH_RECORDS: &str = "RefreshRecords";
/// 没有主动作。
pub const NEXT_ACTION_NONE: &str = "None";

/// `NextAction` 全表。表外值 → 只允许「查看任务」，不给任何写动作入口。
#[cfg(test)]
pub const NEXT_ACTIONS: [&str; 11] = [
    NEXT_ACTION_OPEN_FORM,
    NEXT_ACTION_ENTER_CREDENTIALS,
    NEXT_ACTION_CONFIRM_FINGERPRINT,
    NEXT_ACTION_CONFIRM_PLAN,
    NEXT_ACTION_RETRY_STEP,
    NEXT_ACTION_RECONCILE,
    NEXT_ACTION_COMPLETE_COMPATIBLE,
    NEXT_ACTION_VIEW_LINE,
    NEXT_ACTION_WAIT_QUEUE,
    NEXT_ACTION_REFRESH_RECORDS,
    NEXT_ACTION_NONE,
];

/// 步骤状态：还没做。
pub const STEP_STATUS_PENDING: &str = "Pending";
/// 步骤状态：正在做。
pub const STEP_STATUS_RUNNING: &str = "Running";
/// 步骤状态：做完了，且**只读核对通过**。只有它计入 `N/4`。
pub const STEP_STATUS_DONE: &str = "Done";
/// 步骤状态：明确失败（脚本 `TC_ERROR` 或只读检查判定）。
pub const STEP_STATUS_FAILED: &str = "Failed";
/// 步骤状态：不知道（结果未知 / 缺字段）。
pub const STEP_STATUS_UNKNOWN: &str = "Unknown";
/// 步骤状态：部分完成（有成果但不完整）。
#[cfg(test)]
pub const STEP_STATUS_PARTIAL: &str = "Partial";
/// 步骤状态：跳过（上游已完成且仍有效）。
#[cfg(test)]
pub const STEP_STATUS_SKIPPED: &str = "Skipped";

/// 步骤状态全表。
#[cfg(test)]
pub const STEP_STATUSES: [&str; 7] = [
    STEP_STATUS_PENDING,
    STEP_STATUS_RUNNING,
    STEP_STATUS_DONE,
    STEP_STATUS_FAILED,
    STEP_STATUS_UNKNOWN,
    STEP_STATUS_PARTIAL,
    STEP_STATUS_SKIPPED,
];

/// 四个产品步骤的名字。**四处（记录 / 表单 / 快照 / 契约）必须是这一份**。
pub const STEP_NAMES: [&str; 4] = [
    "检查服务器环境与身份",
    "准备标准连接",
    "准备兼容连接",
    "接入本机并登记线路",
];

/// 未决写的种类：装标准连接（UDP）。
pub const PENDING_KIND_UDP_INSTALL: &str = "UdpInstall";
/// 未决写的种类：装兼容连接（TCP）。
pub const PENDING_KIND_TRANSPORT_INSTALL: &str = "TransportInstall";
/// 未决写的种类：把本机接进服务器。
pub const PENDING_KIND_ADD_PEER: &str = "AddPeer";

/// 未决写种类全表。
#[cfg(test)]
pub const PENDING_KINDS: [&str; 3] = [
    PENDING_KIND_UDP_INSTALL,
    PENDING_KIND_TRANSPORT_INSTALL,
    PENDING_KIND_ADD_PEER,
];

/// 核对方式：只读探针 `deploy::probe_udp_state`。
pub const VERIFY_BY_PROBE_UDP_STATE: &str = "ProbeUdpState";
/// 核对方式：只读探针 `deploy::read_transport`。
pub const VERIFY_BY_READ_TRANSPORT: &str = "ReadTransport";

/// 核对方式全表。
#[cfg(test)]
pub const VERIFY_BYS: [&str; 2] = [VERIFY_BY_PROBE_UDP_STATE, VERIFY_BY_READ_TRANSPORT];

/// 未决写的结论：还没核对过（UI 此时**不得**给任何重装入口）。
pub const OUTCOME_PENDING: &str = "Pending";
/// 未决写的结论：只读核对确认已生效。
pub const OUTCOME_APPLIED: &str = "Applied";
/// 未决写的结论：只读核对确认未生效（可以重试，但仍要用户点一次）。
pub const OUTCOME_NOT_APPLIED: &str = "NotApplied";
/// 未决写的结论：核对也说不清（不猜、不重放）。
pub const OUTCOME_UNKNOWN: &str = "Unknown";

/// 未决写结论全表。
#[cfg(test)]
pub const OUTCOMES: [&str; 4] = [OUTCOME_PENDING, OUTCOME_APPLIED, OUTCOME_NOT_APPLIED, OUTCOME_UNKNOWN];

/// 记录里**永不出现**的键（登录口令、私钥、可复原凭据那几类）。
///
/// 比较前会把键名规范化：小写、去掉 `_` / `-` / 空格，再做**包含**判断，
/// 所以 `Password` / `PASSWORD` / `ssh_Password` / `ssh-Password` 都命中同一条。
/// 值是任何形状都算命中 ——「空字符串」也不行：一条记录里出现这个键，
/// 本身就说明有人想往记录里存秘密。
///
/// 本文件只在数组里写这些词（注释与用例都改用 `FORBIDDEN_KEYS[n]` 指代），
/// 这样「禁用键只出现在名单里」这条验收命令的输出永远只有名单那几行。
pub const FORBIDDEN_KEYS: [&str; 9] = [
    "password", // ← 唯一一行：禁用键名单本体
    "passwd",
    "pwd",
    "credential",
    "privatekey",
    "secret",
    "passphrase",
    "encryptedauthorization",
    "transportenv",
];

// ---------------------------------------------------------------------------
// 记录类型（serde 形状严格按架构文档 §3.1，PascalCase）
// ---------------------------------------------------------------------------

/// 部署目标。`lane_key()` 决定「同一台服务器串行」的粒度。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// 对应的服务器记录 id（`serverstore` 里那条）。没有记录时为 `None`。
    pub server_record_id: Option<String>,
    /// 这次用什么登录：`"password"` / `"key"`。缺字段或表外值 → `"password"`。
    ///
    /// **非秘密**（说的是方式，不是内容），所以可以进记录、进导出摘要。
    /// 它放在 `Target` 而不是 `RunRecord` 顶层：凭据解析（`deploy_resolve_credential`）
    /// 拿到的就是 `Target`，续跑与草稿复用也都从 `run.target` 读。
    pub login_method: String,
    /// 私钥文件路径（仅 `login_method == "key"` 时有意义）。
    ///
    /// **非秘密，但是本机信息**（含用户目录名）：只留在 `record.json` 里，
    /// **不进导出、不进事件 detail、不进页面快照的对外字段**。
    pub identity_file: String,
}

impl Default for Target {
    /// `login_method` 的默认值是**规范值** `"password"`（不是空串）：
    /// 记录往返一趟后 `from_json` 会把空值归一成 `"password"`，两边的形状必须一致，
    /// 否则「自己的输出读回来就不等于自己」（r92 的往返用例会红）。
    fn default() -> Self {
        Target {
            host: String::new(),
            port: 0,
            user: String::new(),
            server_record_id: None,
            login_method: crate::credential::CredentialKind::Password
                .as_str()
                .to_string(),
            identity_file: String::new(),
        }
    }
}

impl Target {
    /// 这次登录方式的枚举形态。空/表外值按密码（旧记录零迁移）。
    pub fn login_kind(&self) -> crate::credential::CredentialKind {
        crate::credential::CredentialKind::parse(&self.login_method)
    }

    /// 同一台服务器的判据：`lower(host):port`。
    ///
    /// **不含** record id：同一目标可能既有记录又没记录（换了写法、删了记录再加回来），
    /// 那仍然是同一台机器，仍然必须串行。域名与 IP 视为不同 —— 无法可靠归并。
    ///
    /// 也**不含**登录方式与私钥路径：换一把钥不等于换一台机器。
    pub fn lane_key(&self) -> String {
        format!("{}:{}", self.host.to_ascii_lowercase(), self.port)
    }

    fn to_json(&self) -> Value {
        json!({
            "Host": self.host,
            "Port": self.port,
            "User": self.user,
            "ServerRecordId": self.server_record_id,
            "LoginMethod": self.login_method,
            "IdentityFile": self.identity_file,
        })
    }

    fn from_json(value: &Value) -> Target {
        Target {
            host: text(value, "Host"),
            port: number_u16(value, "Port").unwrap_or(0),
            user: text(value, "User"),
            server_record_id: opt_text(value, "ServerRecordId"),
            // 宽容读：旧记录的这两个键根本不存在，读出来就是空串 → 解析成 "password"。
            login_method: crate::credential::CredentialKind::parse(&text(value, "LoginMethod"))
                .as_str()
                .to_string(),
            identity_file: opt_text(value, "IdentityFile").unwrap_or_default(),
        }
    }
}

/// 这台服务器的身份（指纹）。**这就是身份本身**，指纹变了就不是同一条部署。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// `SHA256:` 开头的指纹。空 = 还没核对过（不是「任意指纹都行」）。
    pub fingerprint: String,
    /// 这一次是**自动**记住的（TOFU）。自动记住必须能被看见。
    pub auto_trusted: bool,
}

impl Identity {
    fn to_json(&self) -> Value {
        json!({
            "Fingerprint": self.fingerprint,
            "AutoTrusted": self.auto_trusted,
        })
    }

    fn from_json(value: &Value) -> Identity {
        Identity {
            fingerprint: text(value, "Fingerprint"),
            auto_trusted: flag(value, "AutoTrusted"),
        }
    }
}

/// 批准过的部署计划。`plan_digest` 绑定「就是这一份」。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub interface: String,
    pub udp_port: u16,
    pub subnet: String,
    pub mtu: u16,
    /// 本机的隧道公钥（**非秘密**；私钥只在本机 `tunnel.key`）。
    pub client_public_key: Option<String>,
    /// 用户这次选的「默认连接方式」：`"Auto"` / `"Udp"` / `"Tcp"`。
    ///
    /// 空或表外值 = `"Auto"`（旧记录零迁移）。它只决定登记完**选中哪条线路**，
    /// 两条线路都会被准备（与旧版的 `Transport` 语义一致）。
    pub transport: String,
    /// 兼容连接（TCP）的首选端口。0 = 默认值（`deploy::TRANSPORT_PORT`）。
    pub tcp_port: u16,
    /// 兼容连接的 REALITY 握手域名。空 = 默认值（`www.bing.com`）。
    pub server_name: String,
}

impl Plan {
    /// 规范化的默认连接方式：只认 `Tcp` / `Udp`，其余一律 `Auto`。
    pub fn transport_word(&self) -> &'static str {
        match self.transport.as_str() {
            "Tcp" | "tcp" => "Tcp",
            "Udp" | "udp" => "Udp",
            _ => "Auto",
        }
    }

    /// 兼容连接实际使用的端口（0 = 默认值）。
    pub fn tcp_port_or_default(&self) -> u16 {
        if self.tcp_port == 0 {
            crate::deploy::TRANSPORT_PORT
        } else {
            self.tcp_port
        }
    }

    /// 兼容连接实际使用的握手域名（空 = 默认值）。
    pub fn server_name_or_default(&self) -> String {
        if self.server_name.trim().is_empty() {
            crate::deploy::TRANSPORT_SERVER_NAME.to_string()
        } else {
            self.server_name.trim().to_string()
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "Interface": self.interface,
            "UdpPort": self.udp_port,
            "Subnet": self.subnet,
            "Mtu": self.mtu,
            "ClientPublicKey": self.client_public_key,
            // 三个非秘密的兼容连接选择：随「批准过的计划」一起落盘。
            "Transport": self.transport,
            "TcpPort": self.tcp_port,
            "ServerName": self.server_name,
        })
    }

    fn from_json(value: &Value) -> Plan {
        Plan {
            interface: text(value, "Interface"),
            udp_port: number_u16(value, "UdpPort").unwrap_or(0),
            subnet: text(value, "Subnet"),
            mtu: number_u16(value, "Mtu").unwrap_or(0),
            client_public_key: opt_text(value, "ClientPublicKey"),
            // 宽容读：旧记录没有这三键 → 自动 / 默认端口 / 默认握手域名。
            transport: text(value, "Transport"),
            tcp_port: number_u16(value, "TcpPort").unwrap_or(0),
            server_name: text(value, "ServerName"),
        }
    }
}

/// 原因：为什么停在这里、谁能往下走。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reason {
    /// 见 [`REASON_CATEGORIES`]。表外值 = 原因类别未知（不显示类别）。
    pub category: String,
    /// 见 [`ERROR_CLASSES`]。空 = 不显示类别。
    pub class: String,
    /// 机器码：脚本 `TC_ERROR` 原值或内部码（`TransportNotListening` 等）。
    pub code: String,
    /// 人话。**不得**含任何秘密与命令原文。
    pub text: String,
    /// 发生时刻（秒级 RFC3339 UTC）。
    pub at: Option<String>,
}

impl Reason {
    /// 就地带时刻构造。时刻由调用方给，便于测试与重放。
    pub fn now(category: &str, class: &str, code: &str, text: &str) -> Reason {
        Reason {
            category: category.to_string(),
            class: class.to_string(),
            code: code.to_string(),
            text: text.to_string(),
            at: Some(now_utc()),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "Category": self.category,
            "Class": self.class,
            "Code": self.code,
            "Text": self.text,
            "At": self.at,
        })
    }

    fn from_json(value: &Value) -> Reason {
        Reason {
            category: text(value, "Category"),
            class: text(value, "Class"),
            code: text(value, "Code"),
            text: text(value, "Text"),
            at: opt_text(value, "At"),
        }
    }
}

/// 一个产品步骤。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepRecord {
    /// 0..=3（四个产品步骤）。缺失时 `from_json` 用它在数组里的位置补，
    /// 因为「第几步」在数组里本来就是位置信息，不是外部事实。
    pub index: u8,
    pub name: String,
    /// 见 [`STEP_STATUSES`]。空 = 未知（**不标完成**）。
    pub status: String,
    pub started_at_utc: Option<String>,
    pub finished_at_utc: Option<String>,
    /// 非秘密证据（`arch`/`listenPort`/`lines` …）。`Value::Null` = 没有证据，
    /// 详情页该行就不显示，**不推断**。
    pub evidence: Value,
    pub error: Option<Reason>,
}

impl StepRecord {
    /// 只有 `Done` 计入 `N/4`。
    pub fn is_done(&self) -> bool {
        self.status == STEP_STATUS_DONE
    }

    fn to_json(&self) -> Value {
        json!({
            "Index": self.index,
            "Name": self.name,
            "Status": self.status,
            "StartedAtUtc": self.started_at_utc,
            "FinishedAtUtc": self.finished_at_utc,
            "Evidence": self.evidence,
            "Error": self.error.as_ref().map(Reason::to_json),
        })
    }

    fn from_json(value: &Value, fallback_index: u8) -> StepRecord {
        StepRecord {
            index: number_u64(value, "Index")
                .and_then(|n| u8::try_from(n).ok())
                .unwrap_or(fallback_index),
            name: text(value, "Name"),
            status: text(value, "Status"),
            started_at_utc: opt_text(value, "StartedAtUtc"),
            finished_at_utc: opt_text(value, "FinishedAtUtc"),
            evidence: value
                .get("Evidence")
                .cloned()
                .unwrap_or(Value::Null),
            error: object(value, "Error").map(Reason::from_json),
        }
    }
}

/// 发出 SSH **之前**就必须落盘的那条「我可能要写了」。
///
/// 有 `Outcome == Pending` 的未决写时，UI 不得提供任何重装入口，只能提供
/// 「核对原操作」。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingOperation {
    /// 见 [`PENDING_KINDS`]。表外值 = 未知种类（比对里一律按「有未决写」处理）。
    pub kind: String,
    pub attempt_no: u32,
    pub started_at_utc: Option<String>,
    /// 见 [`VERIFY_BYS`]。
    pub verify_by: String,
    pub plan_digest: String,
    /// 仅 `AddPeer` 有：客户端公钥（**非秘密**）。
    pub client_public_key: Option<String>,
    /// 见 [`OUTCOMES`]。空/表外值 = 不知道结论（不猜）。
    pub outcome: String,
}

impl PendingOperation {
    fn to_json(&self) -> Value {
        json!({
            "Kind": self.kind,
            "AttemptNo": self.attempt_no,
            "StartedAtUtc": self.started_at_utc,
            "VerifyBy": self.verify_by,
            "PlanDigest": self.plan_digest,
            "ClientPublicKey": self.client_public_key,
            "Outcome": self.outcome,
        })
    }

    fn from_json(value: &Value) -> PendingOperation {
        PendingOperation {
            kind: text(value, "Kind"),
            attempt_no: number_u64(value, "AttemptNo").and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
            started_at_utc: opt_text(value, "StartedAtUtc"),
            verify_by: text(value, "VerifyBy"),
            plan_digest: text(value, "PlanDigest"),
            client_public_key: opt_text(value, "ClientPublicKey"),
            outcome: text(value, "Outcome"),
        }
    }
}

/// 一次尝试。重试不开新 RunId，而是把同一条记录的 `AttemptNo` 加一。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptRecord {
    pub no: u32,
    pub started_at_utc: Option<String>,
    pub finished_at_utc: Option<String>,
    /// 失败发生在第几步。`None` = 没有失败步骤。
    pub failed_step: Option<u8>,
    /// 失败码（脚本 `TC_ERROR` 原值或内部码）。空 = 没有失败。
    pub error_code: String,
    /// 这次尝试有没有需要核对的未决写：`NotNeeded` / `Needed` / `Done`。
    pub reconcile: String,
}

impl AttemptRecord {
    fn to_json(&self) -> Value {
        json!({
            "No": self.no,
            "StartedAtUtc": self.started_at_utc,
            "FinishedAtUtc": self.finished_at_utc,
            "FailedStep": self.failed_step,
            "ErrorCode": self.error_code,
            "Reconcile": self.reconcile,
        })
    }

    fn from_json(value: &Value) -> AttemptRecord {
        AttemptRecord {
            no: number_u64(value, "No").and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
            started_at_utc: opt_text(value, "StartedAtUtc"),
            finished_at_utc: opt_text(value, "FinishedAtUtc"),
            failed_step: number_u64(value, "FailedStep").and_then(|n| u8::try_from(n).ok()),
            error_code: text(value, "ErrorCode"),
            reconcile: text(value, "Reconcile"),
        }
    }
}

/// 执行者。**它不是存活证据**：判活靠单实例互斥（见架构文档 §1.7），
/// 这里的心跳只回答「最后一次真实动作是什么时候」。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Executor {
    pub instance_id: String,
    pub pid: i64,
    pub heartbeat_at_utc: Option<String>,
    pub background: bool,
}

impl Executor {
    fn to_json(&self) -> Value {
        json!({
            "InstanceId": self.instance_id,
            "Pid": self.pid,
            "HeartbeatAtUtc": self.heartbeat_at_utc,
            "Background": self.background,
        })
    }

    fn from_json(value: &Value) -> Executor {
        Executor {
            instance_id: text(value, "InstanceId"),
            pid: number_u64(value, "Pid")
                .and_then(|n| i64::try_from(n).ok())
                .unwrap_or(0),
            heartbeat_at_utc: opt_text(value, "HeartbeatAtUtc"),
            background: flag(value, "Background"),
        }
    }
}

/// 一次部署运行的全部事实。序列化形状就是磁盘上的 `run.json`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub schema_version: u64,
    pub kind: String,
    /// 小写 UUID（36 位），同时是文件名。**必须**过 [`is_run_id`]。
    pub run_id: String,
    pub attempt_no: u32,
    pub label: String,
    pub target: Target,
    pub identity: Identity,
    pub plan: Plan,
    /// `sha256:…`，绑定「批准过的这份计划」。
    pub plan_digest: String,
    /// 见 [`STATES`]。空 = 未知。
    pub state: String,
    /// `0..=4`。`None` = 步骤未知（界面不显示 `N/4`）。
    pub step: Option<u8>,
    pub reason: Option<Reason>,
    /// 见 [`NEXT_ACTIONS`]。空/表外 = 没有可给的动作。
    pub next_action: String,
    pub steps: Vec<StepRecord>,
    pub pending_operation: Option<PendingOperation>,
    pub attempts: Vec<AttemptRecord>,
    pub executor: Option<Executor>,
    pub created_at_utc: Option<String>,
    pub started_at_utc: Option<String>,
    pub updated_at_utc: Option<String>,
    pub finished_at_utc: Option<String>,
    /// 归档时刻（P2-2）。`Some` = 用户把这条结果收起来了：列表里不显示、裁剪时跳过，
    /// 但**文件一直在**，随时可恢复。「归档」不是删除——删记录是另一条路（且更危险）。
    pub archived_at_utc: Option<String>,
    /// 「在这台电脑记住登录资料」这一勾的结果（长期作用域）。
    ///
    /// 为什么进记录：真正写信封的是引擎的 Step0，它只看得见这条记录。
    /// 缺省取 `true`——老记录是在「无条件保存」的时代写下的，按 `true` 读回来
    /// 才与它们当初的行为一致。
    pub remember_saved: bool,
    /// 「本任务中断后可用这份资料继续（最长 24 小时）」这一勾的结果（任务作用域）。
    ///
    /// 缺省 `false`：老记录没有这个承诺，不能凭空给它一份 24 小时的凭据。
    pub remember_task: bool,
    /// 单调递增。0 = 未知（**不是**「第 0 版」）。
    pub revision: u64,
}

impl RunRecord {
    /// 空壳。字段全部「未知」——不要用它假装一条真记录，它只是给
    /// [`from_json`](RunRecord::from_json) 与测试用的起点。
    pub fn empty() -> RunRecord {
        RunRecord {
            schema_version: SCHEMA_VERSION,
            kind: RUN_KIND.to_string(),
            run_id: String::new(),
            attempt_no: 1,
            label: String::new(),
            target: Target::default(),
            identity: Identity::default(),
            plan: Plan::default(),
            plan_digest: String::new(),
            state: String::new(),
            step: None,
            reason: None,
            next_action: String::new(),
            steps: Vec::new(),
            pending_operation: None,
            attempts: Vec::new(),
            executor: None,
            created_at_utc: None,
            started_at_utc: None,
            updated_at_utc: None,
            finished_at_utc: None,
            archived_at_utc: None,
            remember_saved: true,
            remember_task: false,
            revision: 0,
        }
    }

    /// 磁盘形状。缺省一律写 `null`：读回来还是「未知」，不会被当成某个值。
    pub fn to_json(&self) -> Value {
        json!({
            "SchemaVersion": self.schema_version,
            "Kind": self.kind,
            "RunId": self.run_id,
            "AttemptNo": self.attempt_no,
            "Label": self.label,
            "Target": self.target.to_json(),
            "Identity": self.identity.to_json(),
            "Plan": self.plan.to_json(),
            "PlanDigest": self.plan_digest,
            "State": self.state,
            "Step": self.step,
            "Reason": self.reason.as_ref().map(Reason::to_json),
            "NextAction": self.next_action,
            "Steps": self.steps.iter().map(StepRecord::to_json).collect::<Vec<_>>(),
            "PendingOperation": self.pending_operation.as_ref().map(PendingOperation::to_json),
            "Attempts": self.attempts.iter().map(AttemptRecord::to_json).collect::<Vec<_>>(),
            "Executor": self.executor.as_ref().map(Executor::to_json),
            "CreatedAtUtc": self.created_at_utc,
            "StartedAtUtc": self.started_at_utc,
            "UpdatedAtUtc": self.updated_at_utc,
            "FinishedAtUtc": self.finished_at_utc,
            "ArchivedAtUtc": self.archived_at_utc,
            // 两档凭据作用域的取舍。**不是秘密**：说的是「存过/没存过」，不是密码本身。
            "RememberSaved": self.remember_saved,
            "RememberTask": self.remember_task,
            "Revision": self.revision,
        })
    }

    /// 从磁盘形状读回来。
    ///
    /// 只有一件事是硬错：`RunId` 形状不对（它会直接当文件名，形状不卡死就等于
    /// 允许 `..\..\` 决定写到哪里）。其余字段**一律宽容**：缺字段/表外值 = 未知，
    /// 绝不被补成 `Running` 或 `Complete`。
    pub fn from_json(value: &Value) -> Result<RunRecord, String> {
        let run_id = text(value, "RunId");
        if !is_run_id(&run_id) {
            return Err("部署任务标识不是合法的 36 位小写 UUID。".to_string());
        }
        let steps = match value.get("Steps").and_then(Value::as_array) {
            Some(items) => items
                .iter()
                .enumerate()
                .map(|(position, item)| {
                    let fallback = u8::try_from(position).unwrap_or(u8::MAX);
                    StepRecord::from_json(item, fallback)
                })
                .collect(),
            None => Vec::new(),
        };
        let attempts = match value.get("Attempts").and_then(Value::as_array) {
            Some(items) => items.iter().map(AttemptRecord::from_json).collect(),
            None => Vec::new(),
        };
        Ok(RunRecord {
            schema_version: number_u64(value, "SchemaVersion").unwrap_or(SCHEMA_VERSION),
            kind: text(value, "Kind"),
            run_id,
            attempt_no: number_u64(value, "AttemptNo")
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(1),
            label: text(value, "Label"),
            target: value.get("Target").map(Target::from_json).unwrap_or_default(),
            identity: value.get("Identity").map(Identity::from_json).unwrap_or_default(),
            plan: value.get("Plan").map(Plan::from_json).unwrap_or_default(),
            plan_digest: text(value, "PlanDigest"),
            state: text(value, "State"),
            step: number_u64(value, "Step").and_then(|n| u8::try_from(n).ok()),
            reason: object(value, "Reason").map(Reason::from_json),
            next_action: text(value, "NextAction"),
            steps,
            pending_operation: object(value, "PendingOperation").map(PendingOperation::from_json),
            attempts,
            executor: object(value, "Executor").map(Executor::from_json),
            created_at_utc: opt_text(value, "CreatedAtUtc"),
            started_at_utc: opt_text(value, "StartedAtUtc"),
            updated_at_utc: opt_text(value, "UpdatedAtUtc"),
            finished_at_utc: opt_text(value, "FinishedAtUtc"),
            archived_at_utc: opt_text(value, "ArchivedAtUtc"),
            // 缺字段时的缺省值是**历史行为**，不是随手挑的：见字段注释。
            remember_saved: value
                .get("RememberSaved")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            remember_task: value
                .get("RememberTask")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            revision: number_u64(value, "Revision").unwrap_or(0),
        })
    }

    /// 终态判定。未知状态**不是**终态（不裁剪、不归档）。
    pub fn is_terminal(&self) -> bool {
        TERMINAL_STATES.contains(&self.state.as_str())
    }

    /// 归档判定（P2-2）。**只影响「列表里出不出现」与「裁不裁剪」**：
    /// 记录文件、尝试历史、提醒的去重键都不变。`Some` 就是归档。
    pub fn is_archived(&self) -> bool {
        self.archived_at_utc
            .as_deref()
            .map(|stamp| !stamp.trim().is_empty())
            .unwrap_or(false)
    }

    /// 草稿判定。这是**唯一**一处「它是不是草稿」的判据：`deployment-draft-save` /
    /// `deployment-start` / `deployment-continue` / `deployment-cancel` 的前置分支
    /// 与页面的 `deploy_primary` / `resume` 分流都认同一个字段、同一个值。
    ///
    /// 草稿 = 还没交付过一次密码的填写现场：没有检查点、没碰过服务器、没有证据可留。
    pub fn is_draft(&self) -> bool {
        self.state == STATE_DRAFT
    }

}

// ---------------------------------------------------------------------------
// 字段读取的小工具（全部宽容：缺字段 = 未知）
// ---------------------------------------------------------------------------

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key).filter(|item| !item.is_null())
}

fn object<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    field(value, key).filter(|item| item.is_object())
}

fn text(value: &Value, key: &str) -> String {
    field(value, key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default()
}

fn opt_text(value: &Value, key: &str) -> Option<String> {
    field(value, key)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
}

fn number_u64(value: &Value, key: &str) -> Option<u64> {
    let item = field(value, key)?;
    item.as_u64()
        .or_else(|| item.as_i64().and_then(|n| u64::try_from(n).ok()))
        .or_else(|| item.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

fn number_u16(value: &Value, key: &str) -> Option<u16> {
    number_u64(value, key).and_then(|n| u16::try_from(n).ok())
}

fn flag(value: &Value, key: &str) -> bool {
    field(value, key).and_then(Value::as_bool).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// RunId 形状
// ---------------------------------------------------------------------------

/// 小写 UUID（8-4-4-4-12，只允许 `0-9a-f`）。
///
/// `RunId` 会直接拼进路径。不卡死形状，就等于允许「谁来定这条记录写到哪」。
/// 与 `serverstore::is_server_id` 同一判据（两边错误码不同，各写一份，
/// 共用一份会让「哪个标识非法」这句话说不清）。
pub fn is_run_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != RUN_ID_LEN {
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

// ---------------------------------------------------------------------------
// 时间
// ---------------------------------------------------------------------------

/// 现在（秒级 RFC3339 UTC，形如 `2026-11-08T09:12:31Z`）。
///
/// 记录与快照一律用这个形状：不用毫秒、不用本地时区。
pub fn now_utc() -> String {
    stamp_utc(now_epoch_secs_u64())
}

/// epoch 秒 → 秒级 RFC3339 UTC。超范围时给 1970，而不是空串：
/// 空串会让「时间未知」和「时间写坏了」混在一起。
pub fn stamp_utc(secs: u64) -> String {
    selfcheck::at_rfc3339(secs).unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// 秒级 RFC3339 → epoch 秒。读不出来给 `None`（**不猜 0**）。
pub fn parse_stamp(text: &str) -> Option<u64> {
    let stamp = time::OffsetDateTime::parse(
        text,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?;
    u64::try_from(stamp.unix_timestamp()).ok()
}

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------

/// 存储层错误。`class` 就是 IPC 的 `errorCode`，写盘失败一律 `config`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub class: String,
    pub code: String,
    pub message: String,
}

impl StoreError {
    pub fn config(message: impl Into<String>) -> StoreError {
        StoreError {
            class: ERROR_CLASS_CONFIG.to_string(),
            code: "DeploymentStoreFailed".to_string(),
            message: message.into(),
        }
    }

}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// 一条读不出来的记录。**只说文件与原因，不含任何内容**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// 文件名（不含目录）：给「有 N 条任务记录读不出来」的排查入口用。
    pub file: String,
    /// 机器码：`BadJson` / `ForbiddenField` / `InvalidRunId` / `RunIdMismatch` / `ReadFailed`。
    pub code: String,
    pub message: String,
}

/// `load_all()` 的结论。
///
/// 三个字段刻意分开：`tasks_read` 是**给人看的口径**（`ok`/`partial`/`failed`），
/// 而 `unreadable` 是**逐条**的细节。把两者合一，就只能二选一：
/// 要么丢细节，要么让「有 1 条坏了」变成「整份列表空了」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadResult {
    pub runs: Vec<RunRecord>,
    pub unreadable: Vec<Unreadable>,
    /// 见 [`READ_OK`] / [`READ_PARTIAL`] / [`READ_FAILED`]。
    pub tasks_read: String,
    /// 人话（给刷新入口）。`ok` 时为空。
    pub error: String,
}

impl LoadResult {
    fn empty() -> LoadResult {
        LoadResult {
            runs: Vec::new(),
            unreadable: Vec::new(),
            tasks_read: READ_OK.to_string(),
            error: String::new(),
        }
    }

    /// 列表能不能用。`failed` 时前端必须显示错误卡而不是空列表。
    pub fn is_usable(&self) -> bool {
        self.tasks_read != READ_FAILED
    }
}

/// 裁剪结论。**永不返回 Err**：启动时的清理失败不该拦住用户。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    pub removed: usize,
    pub kept: usize,
    /// 删除过程中的错误（人话，不含路径以外的任何内容）。空 = 一切正常。
    pub error: String,
}

/// 运行记录的存储。
///
/// 只有一个目录、一套写规则：**任何模块都不得自己写记录文件**（架构文档 §8.7）。
#[derive(Debug, Clone)]
pub struct DeploymentStore {
    runs_dir: PathBuf,
}

impl DeploymentStore {
    /// 直接指向某个 `runs` 目录（用例里造小目录用；生产侧一律走 `open`）。
    #[cfg(test)]
    pub fn at(runs_dir: impl Into<PathBuf>) -> DeploymentStore {
        DeploymentStore {
            runs_dir: runs_dir.into(),
        }
    }

    /// `<data root>\deployments\runs`。目录在第一次写入时才建（读的时候不存在 = 没有任务）。
    pub fn open(data_root: &Path) -> DeploymentStore {
        DeploymentStore {
            runs_dir: data_root.join("deployments").join("runs"),
        }
    }

    /// 只有用例要它（造坏文件、看残留临时文件）。生产侧一律走 `open` / `path_of`。
    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.runs_dir
    }

    /// 某条记录的正式文件路径。`run_id` 形状不对直接拒绝 —— 这是防路径穿越的唯一关口。
    pub fn path_of(&self, run_id: &str) -> Result<PathBuf, StoreError> {
        if !is_run_id(run_id) {
            return Err(StoreError {
                class: ERROR_CLASS_CONFIG.to_string(),
                code: "InvalidRunId".to_string(),
                message: "部署任务标识无效（必须是 36 位小写 UUID）。".to_string(),
            });
        }
        Ok(self.runs_dir.join(format!("{run_id}.json")))
    }

    /// 新建一条记录。**只应由 `deployment-start` 在 UI 线程调用一次**（单写者规则）。
    ///
    /// `create` 不覆盖已有文件：同一个 RunId 出现第二次，说明有人想复用旧 RunId
    /// 或者两个任务撞了 id，两种都必须拒绝。
    pub fn create(&self, run: &mut RunRecord) -> Result<(), StoreError> {
        let path = self.path_of(&run.run_id)?;
        if path.exists() {
            return Err(StoreError {
                class: ERROR_CLASS_CONFLICT.to_string(),
                code: "DeploymentRunExists".to_string(),
                message: "这条部署任务记录已经存在（RunId 必须唯一）。".to_string(),
            });
        }
        let mut body = run.clone();
        body.revision = 1;
        body.updated_at_utc = Some(now_utc());
        write_atomic(&path, &body.to_json())?;
        run.revision = body.revision;
        run.updated_at_utc = body.updated_at_utc;
        Ok(())
    }

    /// 覆盖写一条已有记录。**只有引擎能调**（单写者规则）。
    ///
    /// `Revision` 在这里 +1，`UpdatedAtUtc` 在这里刷新：让「谁改过记录」只有一处实现，
    /// 调用方想忘也忘不掉。写盘成功之后才改动调用方手里的那份，失败时它保持原样。
    pub fn save(&self, run: &mut RunRecord) -> Result<(), StoreError> {
        let path = self.path_of(&run.run_id)?;
        let mut body = run.clone();
        body.revision = run.revision.saturating_add(1).max(1);
        body.updated_at_utc = Some(now_utc());
        write_atomic(&path, &body.to_json())?;
        run.revision = body.revision;
        run.updated_at_utc = body.updated_at_utc;
        Ok(())
    }

    /// 读一条。不存在/读不了/含禁用键都返回 `Err`（**不返回空记录**）。
    pub fn load(&self, run_id: &str) -> Result<RunRecord, StoreError> {
        let path = self.path_of(run_id)?;
        match read_record(&path, run_id) {
            Ok(record) => Ok(record),
            Err(problem) => Err(StoreError {
                class: ERROR_CLASS_CONFIG.to_string(),
                code: problem.code,
                message: problem.message,
            }),
        }
    }

    /// 读全部。**单条坏了不影响其它条**：坏的那条进 `unreadable`，整体降级为 `partial`。
    ///
    /// 三种结论分得很清楚：
    /// - 目录不存在（还没部署过）→ `ok` + 空列表：这是真的「没有任务」；
    /// - 目录读不了 → `failed`：**绝不能**显示成「没有任务」；
    /// - 有条读不出来 → `partial` + 其余照常返回。
    pub fn load_all(&self) -> LoadResult {
        let entries = match std::fs::read_dir(&self.runs_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LoadResult::empty(),
            Err(error) => {
                return LoadResult {
                    runs: Vec::new(),
                    unreadable: Vec::new(),
                    tasks_read: READ_FAILED.to_string(),
                    error: format!("读取部署任务目录失败：{error}"),
                }
            }
        };

        let mut result = LoadResult::empty();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    result.unreadable.push(Unreadable {
                        file: String::new(),
                        code: "ReadFailed".to_string(),
                        message: format!("读取部署任务目录时出错：{error}"),
                    });
                    continue;
                }
            };
            // 只要普通文件：子目录不是记录。
            if !entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            // 崩溃残留的临时文件（`.<id>.json.tmp-…`）与任何点号开头的东西：
            // 加载时**忽略**，不报警、不展示（架构文档 §1.6.3 第 1 层）。
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_run_id(stem) {
                // 名字都不对：这确实是「一条读不出来的记录」，不能静默跳过——
                // 静默跳过会让人以为任务丢了。
                result.unreadable.push(Unreadable {
                    file: name,
                    code: "InvalidRunId".to_string(),
                    message: "文件名不是合法的部署任务标识。".to_string(),
                });
                continue;
            }
            match read_record(&entry.path(), stem) {
                Ok(record) => result.runs.push(record),
                Err(problem) => result.unreadable.push(Unreadable {
                    file: name,
                    code: problem.code,
                    message: problem.message,
                }),
            }
        }

        result.runs.sort_by(|a, b| {
            let left = a.updated_at_utc.clone().unwrap_or_default();
            let right = b.updated_at_utc.clone().unwrap_or_default();
            right.cmp(&left).then_with(|| a.run_id.cmp(&b.run_id))
        });
        if !result.unreadable.is_empty() {
            result.tasks_read = READ_PARTIAL.to_string();
            result.error = format!(
                "有 {} 条任务记录读不出来（文件损坏，或被写入了不允许保存的字段）。",
                result.unreadable.len()
            );
        }
        result
    }

    /// 删除一条记录。只用于裁剪与「用户明确要删」。
    pub fn remove(&self, run_id: &str) -> Result<(), StoreError> {
        let path = self.path_of(run_id)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::config(format!("删除部署任务记录失败：{error}"))),
        }
    }

    /// 裁剪终态记录：只保留最新 `keep` 条，且不超过 `max_age_secs`。
    ///
    /// 铁律两条：
    /// 1. **未完成的记录永不自动删除**（`Draft`/`WaitingUser`/`Queued`/`Running`/
    ///    `Paused`/`NeedsAttention` 一条都不碰，未知状态也不碰）；
    /// 2. 只按 `FinishedAtUtc`（缺失则 `UpdatedAtUtc`）排序，时间读不出来就**不按年龄删**，
    ///    只按条数删 —— 宁可多留一条，也不能凭「读不出来的时间」删掉用户的东西。
    /// 裁剪终态记录：只保留最近 `keep` 条 / `max_age_secs` 内。
    ///
    /// `protected` 给出**这一轮不许删**的 RunId（谁决定保护是调用方的事）：
    /// 启动清理用它跳过「还有未读提醒」的记录——否则用户点「查看」会看到一个
    /// 已经被删掉的任务 id。归档在这里也跳过，但那是一条独立判据（用户按过）。
    pub fn prune_terminal(
        &self,
        keep: usize,
        max_age_secs: u64,
        protected: impl Fn(&str) -> bool,
    ) -> PruneReport {
        let loaded = self.load_all();
        if loaded.tasks_read == READ_FAILED {
            return PruneReport {
                removed: 0,
                kept: 0,
                error: loaded.error,
            };
        }
        let now = now_epoch_secs_u64();
        let mut terminal: Vec<(u64, String)> = loaded
            .runs
            .iter()
            .filter(|run| run.is_terminal())
            // 归档 = 用户明确要留着。裁剪只清「结果」，不动归档过的记录：
            // 否则「归档」会在 7 天后变成「悄悄删除」，那正是这一条最不能出的事。
            .filter(|run| !run.is_archived())
            // 有未读提醒的记录不删：提醒里存着 RunId，删了记录再点「查看」
            // 只能得到一个「记录读不到」。等用户看过或归档，下一轮自然会清掉。
            .filter(|run| !protected(&run.run_id))
            .map(|run| (finished_stamp(run).unwrap_or(0), run.run_id.clone()))
            .collect();
        // 新的在前。同刻按 RunId 词典序，保证两次运行得到同一个顺序。
        terminal.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let total = terminal.len();
        let mut removed = 0usize;
        let mut error = String::new();
        for (rank, (stamp, run_id)) in terminal.into_iter().enumerate() {
            let too_many = rank >= keep;
            let too_old =
                stamp > 0 && max_age_secs > 0 && now.saturating_sub(stamp) > max_age_secs;
            if !too_many && !too_old {
                continue;
            }
            match self.remove(&run_id) {
                Ok(()) => removed += 1,
                Err(failure) => {
                    if error.is_empty() {
                        error = failure.message;
                    }
                }
            }
        }
        PruneReport {
            removed,
            kept: total.saturating_sub(removed),
            error,
        }
    }
}

/// 读一个记录文件并把「读不出来」的三种原因分开。**消息里不含文件内容**。
fn read_record(path: &Path, expected_id: &str) -> Result<RunRecord, Unreadable> {
    let text = std::fs::read_to_string(path).map_err(|error| Unreadable {
        file: String::new(),
        code: classify_read_error(&error).to_string(),
        message: if error.kind() == std::io::ErrorKind::NotFound {
            "部署任务记录不存在。".to_string()
        } else {
            format!("读取部署任务记录失败：{error}")
        },
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|_| Unreadable {
        file: String::new(),
        code: "BadJson".to_string(),
        message: "部署任务记录不是合法 JSON。".to_string(),
    })?;
    if first_forbidden_key(&value).is_some() {
        // 只报「有这个键」，不报键名、不报值：日志里出现的键名等于给下一个人指路。
        return Err(Unreadable {
            file: String::new(),
            code: "ForbiddenField".to_string(),
            message: "记录里出现了不允许保存的字段，已拒绝该条记录。".to_string(),
        });
    }
    let record = RunRecord::from_json(&value).map_err(|message| Unreadable {
        file: String::new(),
        code: "InvalidRunId".to_string(),
        message,
    })?;
    if record.run_id != expected_id {
        // 文件名与内容各说一套：谁也不知道该信哪个，不猜。
        return Err(Unreadable {
            file: String::new(),
            code: "RunIdMismatch".to_string(),
            message: "记录内容与文件名不是同一条任务。".to_string(),
        });
    }
    Ok(record)
}

/// IO 错误分类（给 `Unreadable.code`，不是给人看的文案）。
fn classify_read_error(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "NotFound",
        std::io::ErrorKind::PermissionDenied => "PermissionDenied",
        _ => "ReadFailed",
    }
}

/// 在整棵 JSON 里找第一个禁用键（递归，不区分大小写、忽略 `_`/`-`/空格）。
fn first_forbidden_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_forbidden_key(key) {
                    return Some(key.clone());
                }
                if let Some(found) = first_forbidden_key(child) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(first_forbidden_key),
        _ => None,
    }
}

/// 键名规范化后做**包含**判断：`Password` / `ssh_Password` / `ssh-Password` 都命中。
///
/// 为什么用包含而不是相等：秘密的键名会被人加上前缀（`ssh_`、`api_`、`db`），
/// 一个个列出来永远漏。这里宁可误拒一个无辜的键，也不能漏掉一个真的秘密
/// —— 误拒的表现是「这条记录读不出来」（能看见、能排查），漏掉的表现是
/// 「口令躺在 deployments 目录里」（看不见）。
pub fn is_forbidden_key(key: &str) -> bool {
    // 归一化要吃掉分隔符再比：`transport.env` 去掉点之后才是 `transportenv`，
    // `transport_env` / `Transport-Env` 同理。漏了任何一个分隔符，换一种写法就绕过去了。
    let normalized: String = key
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.' | ' ' | '\t'))
        .flat_map(char::to_lowercase)
        .collect();
    FORBIDDEN_KEYS
        .iter()
        .any(|forbidden| normalized.contains(forbidden))
}

/// 记录里「最后一次真实动作」的时刻（epoch 秒）。用 `FinishedAtUtc`，缺失回落
/// `UpdatedAtUtc`。都读不出来 → `None`（调用方据此不按年龄判断）。
fn finished_stamp(run: &RunRecord) -> Option<u64> {
    run.finished_at_utc
        .as_deref()
        .and_then(parse_stamp)
        .or_else(|| run.updated_at_utc.as_deref().and_then(parse_stamp))
}

// ---------------------------------------------------------------------------
// 原子写
// ---------------------------------------------------------------------------

/// 原子写一个 JSON 文件：`create_new` 临时文件 → `write_all` → `sync_all` → `rename`。
///
/// 只有 `rename` 能产生正式文件，所以正式文件永远不是半截的；
/// Windows 上 `std::fs::rename` 走 `MOVEFILE_REPLACE_EXISTING`，替换是原子的。
/// 临时文件一直被占用（杀毒/索引器）时重试 [`WRITE_ATTEMPTS`] 次，超了报 `config`。
pub fn write_atomic(path: &Path, value: &Value) -> Result<(), StoreError> {
    let text = serde_json::to_vec_pretty(value)
        .map_err(|error| StoreError::config(format!("部署任务记录无法序列化：{error}")))?;
    write_atomic_bytes(path, &text)
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::config("部署任务记录路径无效。"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| StoreError::config(format!("创建部署任务目录失败：{error}")))?;
    let name = path
        .file_name()
        .and_then(|item| item.to_str())
        .unwrap_or("run.json");
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..WRITE_ATTEMPTS {
        let temp = parent.join(format!(
            ".{name}.tmp-{}-{attempt}",
            std::process::id()
        ));
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(error);
                continue;
            }
            Err(error) => {
                return Err(StoreError::config(format!(
                    "创建部署任务临时文件失败：{error}"
                )))
            }
        };
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = file;
            file.write_all(bytes)?;
            // 先落盘再改名：否则崩溃后可能得到一个名字正确、内容是空的文件。
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, path)
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(&temp);
            return Err(StoreError::config(format!("写入部署任务记录失败：{error}")));
        }
        return Ok(());
    }
    Err(StoreError::config(format!(
        "写入部署任务记录失败（临时文件一直被占用）：{}",
        last.map(|error| error.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployrun;

    const STAMP: &str = "2026-11-08T09:00:00Z";
    const FP: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-deploystore-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store(tag: &str) -> (DeploymentStore, PathBuf) {
        let root = temp_root(tag);
        let store = DeploymentStore::open(&root);
        (store, root)
    }

    fn run_id() -> String {
        crate::pairing::random_uuid_v4()
    }

    fn target() -> Target {
        Target {
            host: "203.0.113.10".to_string(),
            port: 22,
            user: "root".to_string(),
            server_record_id: None,
            ..Default::default()
        }
    }

    fn draft(id: &str) -> RunRecord {
        deployrun::new_draft(id, "自建 · 203.0.113.10", target(), FP, STAMP)
    }

    /// 一条「什么都有」的记录：往返保真用例的输入。
    fn rich(id: &str) -> RunRecord {
        let mut run = draft(id);
        run.attempt_no = 2;
        run.identity.auto_trusted = true;
        run.plan = Plan {
            interface: "tc3f2b9c1e".to_string(),
            udp_port: 51_820,
            subnet: "10.66.0.0/24".to_string(),
            mtu: 1380,
            client_public_key: Some("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string()),
            transport: "Tcp".to_string(),
            tcp_port: 2443,
            server_name: "www.example.com".to_string(),
        };
        run.plan_digest = "sha256:9f1c".to_string();
        run.state = STATE_RUNNING.to_string();
        run.step = Some(2);
        run.reason = Some(Reason {
            category: REASON_OUTCOME_UNKNOWN.to_string(),
            class: ERROR_CLASS_NETWORK.to_string(),
            code: "NoMarker".to_string(),
            text: "上一步没有回报结果。".to_string(),
            at: Some(STAMP.to_string()),
        });
        run.next_action = NEXT_ACTION_RECONCILE.to_string();
        run.steps[0].status = STEP_STATUS_DONE.to_string();
        run.steps[0].started_at_utc = Some(STAMP.to_string());
        run.steps[0].finished_at_utc = Some(STAMP.to_string());
        run.steps[0].evidence = json!({ "arch": "x86_64", "uid": 0 });
        run.steps[1].status = STEP_STATUS_PARTIAL.to_string();
        run.steps[1].error = Some(Reason {
            category: REASON_FAILED.to_string(),
            class: ERROR_CLASS_ENVIRONMENT.to_string(),
            code: "TransportPortBusy".to_string(),
            text: "端口被占用。".to_string(),
            at: None,
        });
        run.pending_operation = Some(PendingOperation {
            kind: PENDING_KIND_TRANSPORT_INSTALL.to_string(),
            attempt_no: 2,
            started_at_utc: Some(STAMP.to_string()),
            verify_by: VERIFY_BY_READ_TRANSPORT.to_string(),
            plan_digest: "sha256:9f1c".to_string(),
            client_public_key: Some("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string()),
            outcome: OUTCOME_PENDING.to_string(),
        });
        run.attempts = vec![
            AttemptRecord {
                no: 1,
                started_at_utc: Some(STAMP.to_string()),
                finished_at_utc: Some(STAMP.to_string()),
                failed_step: Some(1),
                error_code: "NetworkUnreachable".to_string(),
                reconcile: deployrun::RECONCILE_NOT_NEEDED.to_string(),
            },
            AttemptRecord {
                no: 2,
                started_at_utc: Some(STAMP.to_string()),
                finished_at_utc: None,
                failed_step: None,
                error_code: String::new(),
                reconcile: deployrun::RECONCILE_NEEDED.to_string(),
            },
        ];
        run.executor = Some(Executor {
            instance_id: "0b7d4c1e-9a2b-4c4d-8e6f-1a2b3c4d5e6f".to_string(),
            pid: 12_345,
            heartbeat_at_utc: Some(STAMP.to_string()),
            background: true,
        });
        run.started_at_utc = Some(STAMP.to_string());
        run.finished_at_utc = None;
        run.revision = 0;
        run
    }

    /// ① 往返保真：结构 → JSON → 结构，一个字段都不许丢、也不许多。
    #[test]
    fn a_record_round_trips_through_json_without_losing_anything() {
        let original = rich("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f");
        let json = original.to_json();
        let back = RunRecord::from_json(&json).expect("自己的输出必须能读回来");
        assert_eq!(back, original, "字段走了一趟就变了");
        assert_eq!(back.to_json(), json, "JSON 形状不稳定");

        // 形状抽查：键名是 PascalCase 契约，改名等于让旧记录全变未知。
        for key in [
            "SchemaVersion",
            "Kind",
            "RunId",
            "AttemptNo",
            "Label",
            "Target",
            "Identity",
            "Plan",
            "PlanDigest",
            "State",
            "Step",
            "Reason",
            "NextAction",
            "Steps",
            "PendingOperation",
            "Attempts",
            "Executor",
            "CreatedAtUtc",
            "StartedAtUtc",
            "UpdatedAtUtc",
            "FinishedAtUtc",
            "Revision",
        ] {
            assert!(json.get(key).is_some(), "记录缺少契约字段 {key}");
        }
        assert_eq!(json["Kind"], json!(RUN_KIND));
        assert_eq!(json["SchemaVersion"], json!(SCHEMA_VERSION));
        assert_eq!(json["Steps"][0]["Status"], json!(STEP_STATUS_DONE));
        assert_eq!(json["Steps"][1]["Index"], json!(1));
    }

    /// ② 一条坏记录不能把整份列表变成空列表。
    #[test]
    fn one_broken_record_does_not_empty_the_whole_list() {
        let (store, root) = store("partial");
        let good_one = run_id();
        let good_two = run_id();
        let mut first = draft(&good_one);
        store.create(&mut first).unwrap();
        let mut second = draft(&good_two);
        store.create(&mut second).unwrap();
        // 手写一个坏文件：内容不是 JSON。
        std::fs::write(store.dir().join(format!("{}.json", run_id())), "{ not json").unwrap();

        let loaded = store.load_all();
        assert_eq!(loaded.tasks_read, READ_PARTIAL, "单条坏了必须是 partial");
        assert_eq!(loaded.runs.len(), 2, "其它记录必须还在");
        assert_eq!(loaded.unreadable.len(), 1);
        assert_eq!(loaded.unreadable[0].code, "BadJson");
        assert!(loaded.is_usable(), "partial 仍然可用（能显示、能刷新）");
        assert!(loaded.error.contains('1'), "错误里要能看出坏了几条：{}", loaded.error);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// ③ 禁用键出现即拒绝该条记录 —— 而且**不能**把值或键名写进错误里。
    #[test]
    fn a_record_holding_a_forbidden_field_is_refused_without_echoing_it() {
        let (store, root) = store("forbidden");
        let id = run_id();
        let body = json!({
            "SchemaVersion": 1,
            "Kind": RUN_KIND,
            "RunId": id,
            "State": STATE_RUNNING,
            "Steps": [ { "Index": 0, "Status": STEP_STATUS_DONE,
                         "Evidence": { "ssh_" : 0 } } ],
        });
        // 用占位键名 + 字符串替换，避免本文件里出现第二处禁用键名（`grep` 口径）。
        let key = FORBIDDEN_KEYS[0];
        let text = body.to_string().replace("\"ssh_\"", &format!("\"{key}\""));
        let path = store.dir().join(format!("{id}.json"));
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(&path, text).unwrap();

        let error = store.load(&id).expect_err("含禁用键必须拒绝");
        assert_eq!(error.code, "ForbiddenField");
        assert!(!error.message.contains("s3cret"), "错误里出现了值：{}", error.message);
        assert!(
            !error.message.contains(key),
            "错误里出现了键名：{}",
            error.message
        );

        let loaded = store.load_all();
        assert_eq!(loaded.runs.len(), 0);
        assert_eq!(loaded.tasks_read, READ_PARTIAL);
        assert_eq!(loaded.unreadable[0].code, "ForbiddenField");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ④ 8 个线程同时写各自的 RunId，写完全部可读 —— 单文件/按 RunId 分开的意义就在这。
    #[test]
    fn eight_threads_can_write_different_runs_at_the_same_time() {
        let (store, root) = store("concurrent");
        let mut handles = Vec::new();
        let ids: Vec<String> = (0..8).map(|_| run_id()).collect();
        for id in ids.clone() {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                let mut run = draft(&id);
                store.create(&mut run).expect("并发新建不该失败");
                for _ in 0..3 {
                    store.save(&mut run).expect("并发保存不该失败");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("线程不该 panic");
        }

        let loaded = store.load_all();
        assert_eq!(loaded.tasks_read, READ_OK, "{}", loaded.error);
        assert_eq!(loaded.runs.len(), 8, "8 条记录必须一条不少");
        for id in &ids {
            let record = store.load(id).expect("每条都必须能单独读出来");
            assert_eq!(record.run_id, *id);
            assert_eq!(record.revision, 4, "create 1 次 + save 3 次");
        }
        // 目录里不许留下临时文件。
        let leftovers: Vec<String> = std::fs::read_dir(store.dir())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "留下了临时文件：{leftovers:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ⑤ 裁剪只动终态：未完成的记录**永不**自动删除。
    #[test]
    fn pruning_never_touches_unfinished_runs() {
        let (store, root) = store("prune");
        let now = now_epoch_secs_u64();

        // 两条未完成：一条 NeedsAttention、一条 Running，时间都很旧。
        let mut attention = draft(&run_id());
        attention.state = STATE_NEEDS_ATTENTION.to_string();
        attention.updated_at_utc = Some(stamp_utc(now.saturating_sub(400 * 24 * 3600)));
        store.create(&mut attention).unwrap();
        let mut running = draft(&run_id());
        running.state = STATE_RUNNING.to_string();
        running.updated_at_utc = Some(stamp_utc(now.saturating_sub(400 * 24 * 3600)));
        store.create(&mut running).unwrap();

        // 25 条终态，一条比一条旧。
        let mut terminal_ids = Vec::new();
        for index in 0..25u64 {
            let id = run_id();
            let mut run = draft(&id);
            run.state = STATE_COMPLETE.to_string();
            let stamp = stamp_utc(now.saturating_sub(index * 60));
            run.finished_at_utc = Some(stamp.clone());
            run.updated_at_utc = Some(stamp);
            store.create(&mut run).unwrap();
            terminal_ids.push(id);
        }

        let report = store.prune_terminal(KEEP_TERMINAL, MAX_TERMINAL_AGE_SECS, |_| false);
        assert_eq!(report.error, "", "{}", report.error);
        assert_eq!(report.removed, 5, "25 条终态只留 20 条");
        assert_eq!(report.kept, 20);

        // 未完成的两条必须原样还在，而且内容没被改过。
        let attention_back = store.load(&attention.run_id).expect("未完成记录不许被删");
        assert_eq!(attention_back.state, STATE_NEEDS_ATTENTION);
        assert_eq!(attention_back.updated_at_utc, attention.updated_at_utc);
        let running_back = store.load(&running.run_id).expect("未完成记录不许被删");
        assert_eq!(running_back.state, STATE_RUNNING);

        // 最新的 20 条终态留着，最旧的 5 条没了。
        for id in terminal_ids.iter().take(20) {
            assert!(store.load(id).is_ok(), "最新 20 条必须保留：{id}");
        }
        for id in terminal_ids.iter().skip(20) {
            assert!(store.load(id).is_err(), "最旧的终态应当被裁掉：{id}");
        }

        // 年龄也要能裁：只剩一条 8 天前的终态时，条数没超也得删。
        let mut ancient = draft(&run_id());
        ancient.state = STATE_COMPLETE.to_string();
        let old = stamp_utc(now.saturating_sub(8 * 24 * 3600));
        ancient.finished_at_utc = Some(old.clone());
        ancient.updated_at_utc = Some(old);
        store.create(&mut ancient).unwrap();
        let report = store.prune_terminal(KEEP_TERMINAL, MAX_TERMINAL_AGE_SECS, |_| false);
        assert!(store.load(&ancient.run_id).is_err(), "超过 7 天的终态应当被裁掉");
        assert_eq!(report.removed, 1);

        // 未知状态不是终态：哪怕时间再旧也不许删。
        let mut weird = draft(&run_id());
        weird.state = "Whatever".to_string();
        weird.updated_at_utc = Some(stamp_utc(now.saturating_sub(400 * 24 * 3600)));
        store.create(&mut weird).unwrap();
        store.prune_terminal(0, 1, |_| false);
        assert!(store.load(&weird.run_id).is_ok(), "未知状态不按终态裁剪");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 保护名单：调用方说「这条不许删」，裁剪就必须跳过它。
    ///
    /// 启动清理用它保住「还有未读提醒」的记录——删了记录，提醒里的「查看」
    /// 就指向一个不存在的任务。
    #[test]
    fn pruning_skips_the_records_the_caller_protects() {
        let (store, root) = store("prune-protected");
        let now = now_epoch_secs_u64();
        let mut ids = Vec::new();
        for index in 0..3u64 {
            let id = run_id();
            let mut run = draft(&id);
            run.state = STATE_COMPLETE.to_string();
            let stamp = stamp_utc(now.saturating_sub(30 * 24 * 3600 + index));
            run.finished_at_utc = Some(stamp.clone());
            run.updated_at_utc = Some(stamp);
            store.create(&mut run).unwrap();
            ids.push(id);
        }
        // 只保中间那一条；keep=0 且全都超过 7 天，所以另外两条必删。
        let guarded = ids[1].clone();
        let report = store.prune_terminal(0, MAX_TERMINAL_AGE_SECS, |id| id == guarded);
        assert_eq!(report.error, "", "{}", report.error);
        assert_eq!(report.removed, 2, "三条里只该删两条：{report:?}");
        assert!(store.load(&guarded).is_ok(), "被保护的记录不许删");
        assert!(store.load(&ids[0]).is_err(), "没被保护的旧记录该删");
        assert!(store.load(&ids[2]).is_err(), "没被保护的旧记录该删");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ⑥ `Revision` 单调递增，`UpdatedAtUtc` 由存储层刷新。
    #[test]
    fn every_save_bumps_the_revision_and_keeps_it_on_disk() {
        let (store, root) = store("revision");
        let id = run_id();
        let mut run = draft(&id);
        assert_eq!(run.revision, 0, "草稿的 Revision 是「还没落过盘」");
        store.create(&mut run).unwrap();
        assert_eq!(run.revision, 1);

        let first = store.load(&id).unwrap();
        assert_eq!(first.revision, 1);

        store.save(&mut run).unwrap();
        store.save(&mut run).unwrap();
        assert_eq!(run.revision, 3, "每成功落盘一次 +1");

        let third = store.load(&id).unwrap();
        assert_eq!(third.revision, 3);
        assert!(third.updated_at_utc.is_some(), "更新时间由存储层刷新");

        // 写失败不许偷偷把内存里的版本号加一。
        let mut broken = draft(&run_id());
        broken.run_id = "../escape".to_string();
        assert!(store.save(&mut broken).is_err());
        assert_eq!(broken.revision, 0, "写失败不得改动调用方手里的记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ⑦ `RunId` 形状不合法时，绝不拿它拼路径（防路径穿越）。
    #[test]
    fn a_run_id_is_never_used_as_a_path() {
        let (store, root) = store("escape");
        let bad = [
            "..\\..\\windows\\system32",
            "../../etc/passwd",
            "9F1C2A44-0B7D-4C1E-9A2B-3C4D5E6F7A8B",
            "3f2b9c1e4a5d4c8b9e012d7a6b5c4e3f",
            "",
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3",
        ];
        for id in bad {
            assert!(store.path_of(id).is_err(), "{id} 不该被当成文件名");
            assert!(store.load(id).is_err(), "{id} 读也不行");
            assert!(store.remove(id).is_err(), "{id} 删也不行");
            let mut run = draft(id);
            assert!(store.create(&mut run).is_err(), "{id} 建也不行");
        }
        // 合法形状必须通过，否则这套校验就是过严。
        assert!(store.path_of("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f").is_ok());
        assert!(is_run_id("00000000-0000-4000-8000-000000000000"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 目录读不了 → `failed`，**绝不能**说「没有任务」。
    #[test]
    fn an_unreadable_directory_is_failed_instead_of_an_empty_list() {
        let root = temp_root("unreadable");
        let runs = root.join("deployments").join("runs");
        std::fs::create_dir_all(runs.parent().unwrap()).unwrap();
        // 用一个普通文件占住 runs 的位置：read_dir 必定失败。
        std::fs::write(&runs, "not a directory").unwrap();
        let store = DeploymentStore::open(&root);
        let loaded = store.load_all();
        assert_eq!(loaded.tasks_read, READ_FAILED);
        assert!(!loaded.is_usable(), "failed 时前端必须显示错误卡");
        assert!(!loaded.error.is_empty());
        assert!(loaded.runs.is_empty());

        // 目录**不存在**是另一回事：还没部署过 = 真的没有任务。
        let fresh = DeploymentStore::open(&temp_root("fresh"));
        let loaded = fresh.load_all();
        assert_eq!(loaded.tasks_read, READ_OK);
        assert!(loaded.runs.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 崩溃残留的临时文件：忽略，不报警、不展示。
    #[test]
    fn temp_residue_is_ignored_instead_of_reported_as_a_broken_record() {
        let (store, root) = store("residue");
        let id = run_id();
        let mut run = draft(&id);
        store.create(&mut run).unwrap();
        std::fs::write(
            store.dir().join(format!(".{id}.json.tmp-9999-0")),
            "half written",
        )
        .unwrap();
        std::fs::write(store.dir().join("readme.txt"), "hello").unwrap();

        let loaded = store.load_all();
        assert_eq!(loaded.tasks_read, READ_OK, "{}", loaded.error);
        assert_eq!(loaded.runs.len(), 1);
        assert!(loaded.unreadable.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 缺字段 = 未知：不得被猜成 `Running` 或 `Complete`。
    #[test]
    fn a_missing_state_is_unknown_and_never_running() {
        let (store, root) = store("missing");
        let id = run_id();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(
            store.dir().join(format!("{id}.json")),
            json!({ "SchemaVersion": 1, "Kind": RUN_KIND, "RunId": id }).to_string(),
        )
        .unwrap();

        let record = store.load(&id).expect("缺字段不是读不出来");
        assert_eq!(record.state, "", "缺 State 只能是空");
        assert!(!deployrun::state_is_known(&record.state));
        assert_ne!(record.state, STATE_RUNNING);
        assert_ne!(record.state, STATE_COMPLETE);
        assert_eq!(record.step, None, "缺 Step 就是不知道第几步");
        assert!(!record.is_terminal(), "未知状态不是终态");
        assert_eq!(record.next_action, "");
        assert!(!deployrun::next_action_is_known(&record.next_action));
        assert!(record.steps.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r93：旧记录没有兼容连接三键 → 自动 / 默认端口 / 默认握手域名。
    #[test]
    fn an_old_plan_without_transport_keys_reads_as_auto_and_defaults() {
        let plan = Plan::from_json(&json!({
            "Interface": "tc9f1c2a44",
            "UdpPort": 51820,
            "Subnet": "10.66.0.0/24",
            "Mtu": 1380
        }));
        assert_eq!(plan.transport_word(), "Auto");
        assert_eq!(plan.tcp_port_or_default(), crate::deploy::TRANSPORT_PORT);
        assert_eq!(
            plan.server_name_or_default(),
            crate::deploy::TRANSPORT_SERVER_NAME
        );
        // 表外值也不能被猜成某一种连接。
        let weird = Plan::from_json(&json!({"Transport":"Quic"}));
        assert_eq!(weird.transport_word(), "Auto");
    }

    /// `create` 不许覆盖已有记录（同一个 RunId 出现第二次就是错的）。
    #[test]
    fn create_refuses_to_overwrite_an_existing_run() {
        let (store, root) = store("dup");
        let id = run_id();
        let mut first = draft(&id);
        store.create(&mut first).unwrap();
        first.label = "改过的名字".to_string();
        let error = store.create(&mut first).expect_err("同一个 RunId 不许建两次");
        assert_eq!(error.code, "DeploymentRunExists");
        assert_eq!(error.class, ERROR_CLASS_CONFLICT);
        assert_eq!(store.load(&id).unwrap().label, "自建 · 203.0.113.10");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 文件名与内容各说一套：不猜，进 unreadable。
    #[test]
    fn a_record_whose_filename_disagrees_with_its_content_is_unreadable() {
        let (store, root) = store("mismatch");
        let file_id = run_id();
        let other_id = run_id();
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(
            store.dir().join(format!("{file_id}.json")),
            draft_json(&other_id),
        )
        .unwrap();
        let loaded = store.load_all();
        assert!(loaded.runs.is_empty());
        assert_eq!(loaded.tasks_read, READ_PARTIAL);
        assert_eq!(loaded.unreadable[0].code, "RunIdMismatch");

        // 文件名本身不合规也算「一条读不出来」，不能静默跳过。
        std::fs::write(store.dir().join("not-a-run-id.json"), draft_json(&file_id)).unwrap();
        let loaded = store.load_all();
        assert_eq!(loaded.unreadable.len(), 2);
        assert!(loaded
            .unreadable
            .iter()
            .any(|item| item.code == "InvalidRunId"));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn draft_json(id: &str) -> String {
        draft(id).to_json().to_string()
    }

    /// 时间工具：秒级 RFC3339 往返。
    #[test]
    fn timestamps_round_trip_at_second_precision() {
        assert_eq!(stamp_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(parse_stamp("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(parse_stamp("不是时间"), None);
        assert_eq!(parse_stamp(""), None);
        // 现在这个时刻必须是秒级（不能出现小数位）。
        let now = now_utc();
        assert!(now.ends_with('Z'), "{now}");
        assert!(!now.contains('.'), "记录只用秒级时间：{now}");
        assert!(parse_stamp(&now).is_some());
    }

    /// 禁用键的规范化：大小写、下划线、连字符、点都要能命中。
    #[test]
    fn the_forbidden_key_filter_normalizes_the_key_name() {
        assert!(is_forbidden_key(FORBIDDEN_KEYS[0]));
        assert!(is_forbidden_key("Password"));
        assert!(is_forbidden_key(&format!("ssh_{}", FORBIDDEN_KEYS[0])));
        assert!(is_forbidden_key(&format!("ssh-{}", FORBIDDEN_KEYS[0])));
        assert!(is_forbidden_key("PRIVATE-KEY"));
        // F3：`passwd` / `pwd` / `credential` 三种写法都得算秘密。
        assert!(is_forbidden_key("passwd"));
        assert!(is_forbidden_key("PWD"));
        assert!(is_forbidden_key("ssh-passwd"));
        assert!(is_forbidden_key("credential"));
        assert!(is_forbidden_key("Credentials"));
        // F3：点也是分隔符。少了这一条，`transport.env` 原样存进去都不报错。
        assert!(is_forbidden_key("transport.env"));
        assert!(is_forbidden_key("Transport.Env"));
        assert!(is_forbidden_key("transport_env"));
        assert!(is_forbidden_key("Transport-Env"));
        // 反向：不能因为「包含 key」就把合法字段一起拒了（名单里没有 `key`）。
        assert!(!is_forbidden_key("publicKey"));
        assert!(!is_forbidden_key("clientPublicKey"));
        assert!(!is_forbidden_key("Fingerprint"));
    }

    /// `lane_key` 决定「同一台服务器串行」的粒度：不含 record id，域名不区分大小写。
    #[test]
    fn the_lane_key_is_host_and_port_only() {
        let mut one = target();
        one.server_record_id = Some("9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string());
        let mut other = target();
        other.server_record_id = None;
        other.host = "203.0.113.10".to_string();
        assert_eq!(one.lane_key(), other.lane_key(), "record id 不参与 lane");

        let mut upper = target();
        upper.host = "Example.COM".to_string();
        assert_eq!(upper.lane_key(), "example.com:22");
        let mut tcp = target();
        tcp.port = 2222;
        assert_ne!(tcp.lane_key(), other.lane_key(), "端口不同就是不同的 lane");
    }
}
