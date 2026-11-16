//! 状态判定层（**纯函数**：不碰 FFI、不读时钟、不读磁盘）。
//!
//! 这是「只说实话」的结构性保证：`Guard=Protected` 只能由**可归属的逐条证据**产生，
//! 与「刚才安装调用返回成功」无关（PRD P0-5 / A19）。
//!
//! # 三个正交维度（架构 §4.1 / §5.2，主理人裁决）
//!
//! | 维度 | 取值 | 谁决定 |
//! |---|---|---|
//! | 三态 `state` | `Protected` / `Unprotected` / `Unknown` | 逐条证据 + 基础设施 |
//! | 证据时龄 `freshness` | `JustVerified` / `Recent` / `Aging` / `Expired` | 单调时钟算出的时龄分档 |
//! | 本次核验 `verify_pending` | `None` / `Declined` / `Failed` / `Unknown` | 最近一次失效事件后的重试结果 |
//!
//! **三者不得互相改写**：断开后核验被拒，是「旧证据 + 较旧 + 本次未能重新核验」，
//! 不是 `Unknown`（A23）；时龄走到 `Aging` 也不改三态（只有 24h 才降 `Unknown`）。
//!
//! # 判定优先级（架构 §6.6.2「两层」）
//!
//! 第一层（拿不到可信且可归属的证据 → `Unknown`）：
//! `Unsupported` → `ReadError`(名单读不到) → 读取错误(`NoPermission`/`BfeUnavailable`/`ReadError`)
//! → `BfeUnavailable` → `LegacyConflict` → 无来源 `NotVerifiedYet`(或主动解除 `UserRemoved`)
//! → `EvidenceUnprotected` → `StoreMismatch` → `BootChanged` → `ConfigChanged`
//! → 时龄缺失 `Corrupt` → `EvidenceExpired`(≥24h)。
//!
//! 第二层（证据可信 → `Protected`/`Unprotected`）：
//! `EmptyProgramList` → `UserRemoved` → `ProgramUnresolved` →
//! `InfrastructureMissing`/`InfrastructureConflict` → `DisabledFilter` → `MissingFilter` →
//! `ExtraFilter` → `Ok`。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::identity::{ProgramIdentity, ResolvedEntry, UnresolvedEntry};

/// 过滤器槽位（present/recognized/persistent/disabled/filter_id）。
///
/// **唯一定义在 `wfp.rs`**（它是 WFP 的事实），这里只转出，避免两份形状。
pub use super::wfp::FilterSlot;
use super::wfp::{Layer, WfpError};

// ---------------------------------------------------------------------------
// 常量（时效与摘要口径）
// ---------------------------------------------------------------------------

/// 进入「较旧」档的阈值：20 分钟（PRD §7 时龄分档）。
pub const STALE_AGING_SECS: u64 = 20 * 60;

/// 证据的**唯一**时间型硬上限：24 小时（PRD §4.1.1）。
///
/// 除了它，**任何时间流逝都不降级**：30 秒、10 分钟、25 分钟一律照常。
/// 把真实存在的保护说成「无法确认」，本身就是另一种不实信息。
pub const EVIDENCE_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// 摘要口径版本。改口径就升级它：老证据自动失效（不允许新旧口径混算）。
pub const DIGEST_SCHEMA: &str = "tcrs-guard-digest/v3";

/// 「保护启用」意图（Q8：Trade 名单非空即推导为「有意图」，**不新增显式开关**）。
pub const INTENT_GUARD_ENABLED: &str = "guard-enabled";

/// 「用户已主动解除」意图（Q8）。它**只影响文案与旧证据失效**，
/// 不是权限判断、不是启用开关：下次连接安装成功就清除。
pub const INTENT_USER_REMOVED: &str = "user-removed";

// ---------------------------------------------------------------------------
// 三态 / 原因 / 来源 / 时龄 / 本次核验
// ---------------------------------------------------------------------------

/// 三态。**只有这三种**，且 `Protected` 的准入条件写死在 [`evaluate`] 里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardState {
    Protected,
    Unprotected,
    Unknown,
}

impl GuardState {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardState::Protected => "Protected",
            GuardState::Unprotected => "Unprotected",
            GuardState::Unknown => "Unknown",
        }
    }
}

/// 判定原因。**机器可读**，界面据它决定下一步（诊断/修复/空态/重新核验）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardReason {
    Ok,
    EmptyProgramList,
    /// 名单里有进程，但没有任何一条需要保护的交易条目（全设直连/日常）。
    NoTradePrograms,
    InfrastructureMissing,
    InfrastructureConflict,
    MissingFilter,
    ExtraFilter,
    DisabledFilter,
    ProgramUnresolved,
    /// 用户显式「解除交易保护」之后的诚实状态（Q8）：不是故障、不该红告警。
    UserRemoved,
    NoPermission,
    ReadError,
    BfeUnavailable,
    LegacyConflict,
    InstallFailed,
    SyncRefusedForeign,
    NotVerifiedYet,
    /// 证据来自上一次开机（`boot_id` 不符）。
    BootChanged,
    /// 名单/解析结果/意图/身份版本变了（`config_digest` 不符）。
    ConfigChanged,
    /// 证据超过 24 小时没有任何重新核验（唯一时间型降级）。
    EvidenceExpired,
    /// 存储可被本进程（= 同用户任何进程）写入 → 内容不可信（P0-16/A21）。
    EvidenceUnprotected,
    /// 记录的 `StoreKind` 与本次所选存储不一致（生产/测试串场）。
    StoreMismatch,
    /// 记录损坏（长度/Sha256/字段级校验不过）。
    Corrupt,
    Unsupported,
}

impl GuardReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardReason::Ok => "Ok",
            GuardReason::EmptyProgramList => "EmptyProgramList",
            GuardReason::NoTradePrograms => "NoTradePrograms",
            GuardReason::InfrastructureMissing => "InfrastructureMissing",
            GuardReason::InfrastructureConflict => "InfrastructureConflict",
            GuardReason::MissingFilter => "MissingFilter",
            GuardReason::ExtraFilter => "ExtraFilter",
            GuardReason::DisabledFilter => "DisabledFilter",
            GuardReason::ProgramUnresolved => "ProgramUnresolved",
            GuardReason::UserRemoved => "UserRemoved",
            GuardReason::NoPermission => "NoPermission",
            GuardReason::ReadError => "ReadError",
            GuardReason::BfeUnavailable => "BfeUnavailable",
            GuardReason::LegacyConflict => "LegacyConflict",
            GuardReason::InstallFailed => "InstallFailed",
            GuardReason::SyncRefusedForeign => "SyncRefusedForeign",
            GuardReason::NotVerifiedYet => "NotVerifiedYet",
            GuardReason::BootChanged => "BootChanged",
            GuardReason::ConfigChanged => "ConfigChanged",
            GuardReason::EvidenceExpired => "EvidenceExpired",
            GuardReason::EvidenceUnprotected => "EvidenceUnprotected",
            GuardReason::StoreMismatch => "StoreMismatch",
            GuardReason::Corrupt => "Corrupt",
            GuardReason::Unsupported => "Unsupported",
        }
    }

    /// 这个原因是否**已经确定**（不是「还不知道」）。
    ///
    /// 界面据此决定：确定的 `Unprotected` 才出「未完整开启」的提示；
    /// 不确定的一律中性措辞 + 诊断入口。
    pub fn is_conclusive(&self) -> bool {
        !matches!(
            self,
            GuardReason::NotVerifiedYet
                | GuardReason::NoPermission
                | GuardReason::ReadError
                | GuardReason::BfeUnavailable
                | GuardReason::LegacyConflict
                | GuardReason::BootChanged
                | GuardReason::ConfigChanged
                | GuardReason::EvidenceExpired
                | GuardReason::EvidenceUnprotected
                | GuardReason::StoreMismatch
                | GuardReason::Corrupt
                | GuardReason::Unsupported
        )
    }
}

/// 证据**由谁产生**（PRD §7 硬要求：来源不明不得显示 `Protected`）。
///
/// 规范集**只有三种**（PRD §7「不造含糊值 / 不造同义多值」）：
/// `ElevatedVerify` / `ElevatedInstallReadback` / `LiveRead`。
/// 「用户点重新核验」走的也是 `ElevatedVerify`，不再单独给一个同义值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardSource {
    /// 非提权点读（L 路径）。默认关闭（见 `mod.rs::LIVE_READ_SUPPORTED`）。
    LiveRead,
    /// 提权核验（P 路径，权威；含「用户点重新核验」）。
    ElevatedVerify,
    /// 同一次提权会话内的**安装读回**（A19：唯一的「安装即可信」路径）。
    ElevatedInstallReadback,
    /// 没有证据 / 来源不明（`as_str()` 给空串，不许冒充某个来源）。
    None,
}

impl Default for GuardSource {
    fn default() -> Self {
        GuardSource::None
    }
}

impl GuardSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardSource::LiveRead => "LiveRead",
            GuardSource::ElevatedVerify => "ElevatedVerify",
            GuardSource::ElevatedInstallReadback => "ElevatedInstallReadback",
            GuardSource::None => "",
        }
    }

    /// 记录里的来源字符串 → 枚举。**不认识的一律 `None`**（不猜、不沿用）。
    ///
    /// `ElevatedReverify` 是早期落过盘的旧字符串，这里**只当读入别名**映射到
    /// `ElevatedVerify`（同一语义，见 PRD §7 源集合裁决）。写出路径永不产生它。
    pub fn parse(text: &str) -> Option<GuardSource> {
        match text.trim() {
            "LiveRead" => Some(GuardSource::LiveRead),
            "ElevatedVerify" => Some(GuardSource::ElevatedVerify),
            "ElevatedInstallReadback" => Some(GuardSource::ElevatedInstallReadback),
            "ElevatedReverify" => Some(GuardSource::ElevatedVerify),
            _ => None,
        }
    }

    pub fn is_some(&self) -> bool {
        !matches!(self, GuardSource::None)
    }
}

/// 证据时龄分档（PRD §7）。**只影响展示**，不参与三态判定（24h 除外）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// `< 60s`：刚刚核验。
    JustVerified,
    /// `60s ~ 20min`：N 分钟前核验。
    Recent,
    /// `>= 20min`（且 < 24h）：较旧：N 分钟前核验 + 「重新核验」入口。
    Aging,
    /// `>= 24h`：状态已降 `Unknown{EvidenceExpired}`。
    Expired,
}

impl Freshness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Freshness::JustVerified => "JustVerified",
            Freshness::Recent => "Recent",
            Freshness::Aging => "Aging",
            Freshness::Expired => "Expired",
        }
    }
}

/// 时龄分档（唯一定义，四档边界在单测里逐点钉住）。
pub fn freshness_of(age_secs: u64) -> Freshness {
    if age_secs >= EVIDENCE_MAX_AGE_SECS {
        Freshness::Expired
    } else if age_secs >= STALE_AGING_SECS {
        Freshness::Aging
    } else if age_secs < 60 {
        Freshness::JustVerified
    } else {
        Freshness::Recent
    }
}

/// 时龄文案（PRD §7 逐字要求，必须显示）。
///
/// 分档（PRD 裁决 ⑤，2026-11-05 修订）：
/// - `< 60s`：「刚刚核验」
/// - `1 ~ 19min`：「N 分钟前核验」
/// - `20 ~ 59min`：「较旧：N 分钟前核验」
/// - `>= 60min` 且 `< 24h`：「较旧：N 小时前核验」（不写「1380 分钟」这种丑数字）
/// - `>= 24h`：状态已降 `Unknown{EvidenceExpired}`，文案提示重新核验
pub fn age_text(age_secs: u64) -> String {
    match freshness_of(age_secs) {
        Freshness::JustVerified => "刚刚核验".to_string(),
        Freshness::Recent => format!("{} 分钟前核验", age_secs / 60),
        Freshness::Aging => {
            if age_secs >= 60 * 60 {
                format!("较旧：{} 小时前核验", age_secs / 3600)
            } else {
                format!("较旧：{} 分钟前核验", age_secs / 60)
            }
        }
        Freshness::Expired => "上次核验已超过 24 小时，请重新核验".to_string(),
    }
}

/// 本次「强制失效事件」之后的重试结果。
///
/// **它不改三态**：旧证据该是什么状态还是什么状态，这个字段只说明
/// 「这一次没能刷新它」。这样断开后拒绝提权时，用户看到的是
/// 「已保护（较旧）+ 本次未能重新核验」，而不是一夜回到 `Unknown`（A23）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyPending {
    None,
    /// 用户在 UAC 上点了「否」。
    Declined,
    /// 提权/写入/读回失败（不是拒绝）。
    Failed,
    /// 尚未尝试 / 结果不明。
    Unknown,
}

impl VerifyPending {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerifyPending::None => "None",
            VerifyPending::Declined => "Declined",
            VerifyPending::Failed => "Failed",
            VerifyPending::Unknown => "Unknown",
        }
    }

    pub fn is_pending(&self) -> bool {
        !matches!(self, VerifyPending::None)
    }
}

// ---------------------------------------------------------------------------
// 时钟（单调优先，抗回拨）
// ---------------------------------------------------------------------------

/// 时龄计算用的时钟。**判定层只认这个 trait**，生产实现见 `wfp_win::SystemClock`。
///
/// 为什么需要它：
/// 1. 墙钟（`SystemTime`）可被用户/时间同步改掉，改早两小时会让 25 分钟的证据「变未来」；
/// 2. 单调时钟（`GetTickCount64`）不受改时间影响，跨睡眠仍继续增长（架构 A-14 的 spike 结论）；
/// 3. 测试要能注入假时钟，不能真的去休眠 24 小时。
pub trait Clock {
    /// 当前墙钟（epoch 秒）。**只用于展示** `VerifiedAtUtc` 与无单调读数时的兜底。
    fn now_epoch(&self) -> f64;
    /// 单调毫秒（开机以来）。**用于算时龄**。
    fn tick_ms(&self) -> u64;
}

/// 固定时钟（测试用）。
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    pub epoch: f64,
    pub tick_ms: u64,
}

impl FixedClock {
    pub fn new(epoch: f64, tick_ms: u64) -> FixedClock {
        FixedClock { epoch, tick_ms }
    }
}

impl Clock for FixedClock {
    fn now_epoch(&self) -> f64 {
        self.epoch
    }
    fn tick_ms(&self) -> u64 {
        self.tick_ms
    }
}

// ---------------------------------------------------------------------------
// 证据
// ---------------------------------------------------------------------------

/// 基础设施检测结果（provider/subLayer/BFE/旧版对象）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardDetection {
    pub provider_present: bool,
    pub sublayer_present: bool,
    /// provider 与 subLayer 都存在**且定义与我们的一致**（key 相同但定义不同 → 冲突）。
    pub infrastructure_verified: bool,
    /// 检测到 旧版留下的对象（只标记，不删不接管）。
    pub legacy_guard_present: bool,
    /// BFE 是否就绪。`false` 时持久规则不生效（是「无法确认」，不是「未启用」）。
    pub bfe_ready: bool,
}

impl Default for GuardDetection {
    fn default() -> Self {
        GuardDetection {
            provider_present: false,
            sublayer_present: false,
            infrastructure_verified: false,
            legacy_guard_present: false,
            bfe_ready: true,
        }
    }
}

/// 证据里的单程序记录（安装/核验时写入，读回时逐条比对）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramEvidence {
    pub name: String,
    pub path: String,
    pub app_id: Vec<u8>,
    pub ipv4: FilterSlot,
    pub ipv6: FilterSlot,
}

impl ProgramEvidence {
    pub fn slot(&self, layer: Layer) -> FilterSlot {
        match layer {
            Layer::V4 => self.ipv4,
            Layer::V6 => self.ipv6,
        }
    }

    /// 两族都合格，且 `FilterId != 0`（0 = BFE 没分配 id，当不了证据）。
    pub fn slot_ok(&self, layer: Layer) -> bool {
        let s = self.slot(layer);
        s.ok() && s.filter_id.unwrap_or(0) != 0
    }

    pub fn ok(&self) -> bool {
        self.slot_ok(Layer::V4) && self.slot_ok(Layer::V6)
    }
}

/// 一次读取的全部证据。**判定层的唯一输入之一**。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct GuardEvidence {
    pub programs: Vec<ProgramEvidence>,
    pub detection: GuardDetection,
    /// 读取时的错误（`Some` 表示这次没读到：没权限 / BFE 没起）。
    pub read_error: Option<WfpError>,
    /// 证据产生时刻（墙钟，仅展示）。
    pub verified_at_epoch: Option<f64>,
    /// 证据产生时刻（单调毫秒，**算时龄用**）。`None` 时退回墙钟。
    pub verified_at_tick_ms: Option<u64>,
    pub source: GuardSource,
    /// 名单 + 解析结果 + provider 身份/版本 + 意图 的摘要。
    pub config_digest: String,
    /// 开机标识（同一台机器两次开机必须不同）。
    pub boot_id: String,
    /// 枚举到的「属于我们 provider 但不是合格 block」的多余规则数（`ExtraFilter` 用）。
    pub extra_owned_filters: usize,
    /// 产生证据时旧版 旧版是否正在运行（冲突态变化 → 证据失效）。
    pub legacy_running_at_verify: bool,
    /// 证据来自哪种存储（`Registry` / `IsolatedFile`），用于交叉校验。
    pub store_kind: String,
}

// ---------------------------------------------------------------------------
// 判定输入与输出
// ---------------------------------------------------------------------------

/// [`evaluate`] 的上下文（环境事实 + 时钟）。**没有隐式输入**。
pub struct EvalContext {
    /// 当前开机标识。
    pub current_boot_id: String,
    /// 当前配置摘要。
    pub current_config_digest: String,
    /// 本次失效事件后的重试结果（不改三态）。
    pub verify_pending: VerifyPending,
    /// 存储可信自检结果（`EvidenceStore::trusted()`）。`false` → `Unknown{EvidenceUnprotected}`。
    pub evidence_trusted: bool,
    /// 平台不支持（非 Windows / 32 位）。
    pub unsupported: bool,
    /// 本次读到的存储类型（与记录里的 `StoreKind` 交叉校验）。
    pub store_kind: String,
    /// 时钟（单调优先）。
    pub clock: Box<dyn Clock>,
}

impl Default for EvalContext {
    fn default() -> Self {
        EvalContext {
            current_boot_id: String::new(),
            current_config_digest: String::new(),
            verify_pending: VerifyPending::None,
            evidence_trusted: true,
            unsupported: false,
            store_kind: String::new(),
            clock: Box::new(FixedClock::new(0.0, 0)),
        }
    }
}

/// [`evaluate`] 的全部输入。
pub struct EvaluationInput<'a> {
    pub evidence: &'a GuardEvidence,
    /// 参与保护的名单条目（解析成功、轻量身份）。
    pub entries: &'a [ResolvedEntry],
    /// 未参与保护的条目（老条目/找不到/超限）。
    pub unresolved: &'a [UnresolvedEntry],
    /// 实际参与保护的条目数；`-1` = 读不到。
    pub trade_program_count: i64,
    /// 名单进程总条数；`-1` = 读不到。与 Count 一起区分三种空态。
    pub trade_program_listed: i64,
    /// 检测到旧版客户端正在运行（此时不读/写任何 WFP 对象）。
    pub legacy_conflict: bool,
    /// 用户已主动「解除交易保护」（Q8）。**只影响文案与待核验提示**。
    pub user_removed: bool,
    pub ctx: &'a EvalContext,
}

/// 单个程序在快照里的状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramGuardStatus {
    pub name: String,
    pub path: Option<String>,
    pub device_path: Option<String>,
    pub participated: bool,
    pub unresolved_reason: Option<String>,
    pub ipv4: FilterSlot,
    pub ipv6: FilterSlot,
}

impl ProgramGuardStatus {
    /// 这个程序两族都合格了吗（`Protected` 的必要条件，逐程序看）。
    pub fn ok(&self) -> bool {
        self.slot_ok(Layer::V4) && self.slot_ok(Layer::V6)
    }

    fn slot_ok(&self, layer: Layer) -> bool {
        if !self.participated {
            return false;
        }
        let s = self.slot(layer);
        s.ok() && s.filter_id.unwrap_or(0) != 0
    }

    fn slot(&self, layer: Layer) -> FilterSlot {
        match layer {
            Layer::V4 => self.ipv4,
            Layer::V6 => self.ipv6,
        }
    }
}

/// 状态投影。**唯一来源**：`ipc::status_json` 从这里取字段，前端只渲染。
#[derive(Debug, Clone, PartialEq)]
pub struct GuardStatus {
    pub state: GuardState,
    pub reason: GuardReason,
    pub summary: String,
    /// 提权视角说明（R25-1）。`Some` 时 CLI/界面在末尾**追加**一句「这个视角证明不了防篡改」。
    ///
    /// **只影响展示**：判定链不看这个字段，`summary` 与三态逐字不变。
    /// 为什么要它：只读核验要管理员，而证据写进 HKLM 之后管理员进程天然「可写」，
    /// 于是「刚用管理员终端装完」紧接着读到的是 `Unknown{EvidenceUnprotected}`；
    /// 不加这一句，用户会把「视角问题」读成「安装失败」。
    pub perspective_note: Option<String>,
    /// **实际参与保护**的条目数（target==Trade 且路径解析成功）。
    pub trade_program_count: i64,
    /// 名单里的进程条目总数（含直连/日常与未解析条目），用于区分三种空态。
    pub trade_program_listed: i64,
    pub source: GuardSource,
    /// 时龄分档（展示维度，与三态正交）。
    pub freshness: Freshness,
    /// 本次核验结果（展示维度，与三态正交）。
    pub verify_pending: VerifyPending,
    pub evidence_at: Option<String>,
    pub evidence_age_secs: Option<u64>,
    /// 时龄文案（PRD §7 必须显示）。
    pub age_text: String,
    pub boot_id_match: bool,
    pub config_digest_match: bool,
    pub evidence_trusted: bool,
    pub store_kind: String,
    pub unsupported: bool,
    pub detection: GuardDetection,
    pub programs: Vec<ProgramGuardStatus>,
}

impl Default for GuardStatus {
    fn default() -> Self {
        GuardStatus::unknown(GuardReason::NotVerifiedYet, -1)
    }
}

impl GuardStatus {
    pub fn new(state: GuardState, reason: GuardReason) -> GuardStatus {
        GuardStatus {
            state,
            reason,
            summary: summary_for(state, reason).to_string(),
            perspective_note: None,
            trade_program_count: 0,
            trade_program_listed: 0,
            source: GuardSource::None,
            freshness: Freshness::Expired,
            verify_pending: VerifyPending::None,
            evidence_at: None,
            evidence_age_secs: None,
            age_text: String::new(),
            boot_id_match: false,
            config_digest_match: false,
            evidence_trusted: false,
            store_kind: String::new(),
            unsupported: false,
            detection: GuardDetection::default(),
            programs: Vec::new(),
        }
    }

    /// 「无法确认」的便捷构造：**任何**缺证据的场景都从这里出去。
    pub fn unknown(reason: GuardReason, trade_program_count: i64) -> GuardStatus {
        let mut st = GuardStatus::new(GuardState::Unknown, reason);
        st.trade_program_count = trade_program_count;
        // 「读不到配置」时两个计数都只能说不知道；绝不能把 -1 冒充成「尚未添加」。
        st.trade_program_listed = trade_program_count;
        st
    }

    /// 非 Windows / 32 位：不宣称、不出三态卡（PRD §2.3）。
    pub fn unsupported() -> GuardStatus {
        let mut st = GuardStatus::new(GuardState::Unknown, GuardReason::Unsupported);
        st.unsupported = true;
        st.trade_program_count = -1;
        st.trade_program_listed = -1;
        st
    }

    pub fn is_protected(&self) -> bool {
        self.state == GuardState::Protected
    }

    /// 快照字段（PRD §7 / 架构 §4.3）。顶层是界面直接用的字段，`GuardEvidence` 是明细。
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "Guard": self.state.as_str(),
            "TradeProgramCount": self.trade_program_count,
            "TradeProgramListed": self.trade_program_listed,
            "GuardSummary": self.summary,
            "GuardVerifiedAtUtc": self.evidence_at,
            "GuardEvidenceAge": self.age_text,
            "GuardEvidenceAgeSeconds": self.evidence_age_secs,
            // 「较旧」= 界面必须给「重新核验」入口（PRD §7）
            "GuardEvidenceStale": self.freshness == Freshness::Aging,
            "GuardEvidenceFreshness": self.freshness.as_str(),
            "GuardVerifyPending": self.verify_pending.as_str(),
            // R25-1：管理员进程视角说明（没有就是空串，界面据此判断「不追加」）。
            "GuardPerspectiveNote": self.perspective_note.clone().unwrap_or_default(),
            "GuardEvidenceSource": self.source.as_str(),
            "GuardEvidenceTrusted": self.evidence_trusted,
            "GuardEvidenceBootId": self.boot_id_match,
            "GuardConfigDigest": self.config_digest_match,
            "GuardEvidence": {
                "Source": self.source.as_str(),
                "Freshness": self.freshness.as_str(),
                "VerifyPending": self.verify_pending.as_str(),
                "VerifiedAtUtc": self.evidence_at,
                "AgeSeconds": self.evidence_age_secs,
                "AgeText": self.age_text,
                "BootIdMatch": self.boot_id_match,
                "ConfigDigestMatch": self.config_digest_match,
                "EvidenceTrusted": self.evidence_trusted,
                "Store": self.store_kind,
                "Reason": self.reason.as_str(),
                "ReasonConclusive": self.reason.is_conclusive(),
                "Unsupported": self.unsupported,
                "LegacyGuardPresent": self.detection.legacy_guard_present,
                "Detection": {
                    "ProviderPresent": self.detection.provider_present,
                    "SubLayerPresent": self.detection.sublayer_present,
                    "InfrastructureVerified": self.detection.infrastructure_verified,
                    "BfeReady": self.detection.bfe_ready,
                },
                "Programs": self.programs.iter().map(|p| serde_json::json!({
                    "Name": p.name,
                    "Path": p.path,
                    "DevicePath": p.device_path,
                    "Participated": p.participated,
                    "UnresolvedReason": p.unresolved_reason,
                    "Protected": p.ok(),
                    "IPv4": slot_json(&p.ipv4),
                    "IPv6": slot_json(&p.ipv6),
                })).collect::<Vec<_>>(),
            },
        })
    }

    fn with(mut self, state: GuardState, reason: GuardReason) -> GuardStatus {
        self.state = state;
        self.reason = reason;
        self.summary = summary_for(state, reason).to_string();
        self
    }
}

fn slot_json(slot: &FilterSlot) -> serde_json::Value {
    serde_json::json!({
        "Present": slot.present,
        "Recognized": slot.recognized,
        "Persistent": slot.persistent,
        "Disabled": slot.disabled,
        "FilterId": slot.filter_id,
    })
}

// ---------------------------------------------------------------------------
// 句子表
// ---------------------------------------------------------------------------

/// 状态对应的**一句话**（PRD §7 定稿文案）。后端出句子，前端只渲染。
pub fn summary_for(state: GuardState, reason: GuardReason) -> &'static str {
    match (state, reason) {
        (GuardState::Protected, _) => "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。",
        (GuardState::Unprotected, GuardReason::EmptyProgramList) => {
            "尚未添加要保护的程序，这不是故障。"
        }
        (GuardState::Unprotected, GuardReason::NoTradePrograms) => {
            "名单里没有需要保护的程序（当前都设为直连或日常）。"
        }
        (GuardState::Unprotected, GuardReason::UserRemoved) => {
            "交易保护已解除；下次连接会重新启用。"
        }
        (GuardState::Unprotected, _) => "交易程序直连保护未完整启用，请检查保护规则。",
        (GuardState::Unknown, GuardReason::EvidenceExpired) => {
            "交易保护状态无法确认（上次核验已超过 24 小时）。"
        }
        (GuardState::Unknown, GuardReason::EvidenceUnprotected) => {
            "交易保护状态无法确认（核验记录的存储可被普通程序改写）。"
        }
        (GuardState::Unknown, GuardReason::BootChanged) => {
            "交易保护状态无法确认（开机后还没有重新核验）。"
        }
        (GuardState::Unknown, GuardReason::ConfigChanged) => {
            "交易保护状态无法确认（名单已变更，需要重新核验）。"
        }
        (GuardState::Unknown, GuardReason::Unsupported) => "当前系统不支持交易程序直连保护。",
        (GuardState::Unknown, GuardReason::NoPermission) => {
            "交易保护状态无法确认（没有管理员权限，无法核验规则）。"
        }
        (GuardState::Unknown, _) => "交易保护状态无法确认。",
    }
}

// ---------------------------------------------------------------------------
// 提权视角说明（R25-1，纯函数）
// ---------------------------------------------------------------------------

/// 「这个视角证明不了防篡改」的逐字文案。**只此一处**，CLI 与界面共用同一句。
pub const PERSPECTIVE_NOTE_ELEVATED: &str =
    "当前是管理员进程，可以改写核验记录；这个视角无法证明防篡改生效，请用普通权限进程复核。";

/// 提权视角说明：**仅在「注册表证据 + 本进程提权 + 自检不过」时**返回一句实话。
///
/// 为什么需要它：`trusted = !writable_by_me()`。管理员进程能写
/// `HKLM\SOFTWARE\SpiderVPN\Guard`，所以**同一次管理员会话里**刚装完、
/// 紧接着读到的就是 `Unknown{EvidenceUnprotected}`——判定没错（这个视角确实证明不了
/// 记录没被动过），但用户会把「无法确认」直接读成「安装失败」。
///
/// **纯函数**：`elevated` 由调用方注入（生产走 `probe::elevated`），
/// 否则单测没法覆盖「提权/非提权」两个分支。
pub fn perspective_note(store_kind: &str, elevated: bool, reason: GuardReason) -> Option<String> {
    if store_kind == "Registry" && elevated && reason == GuardReason::EvidenceUnprotected {
        Some(PERSPECTIVE_NOTE_ELEVATED.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------

/// 证据 → 状态。**纯函数**：同样的输入永远同样的输出，可全分支覆盖。
pub fn evaluate(input: &EvaluationInput<'_>) -> GuardStatus {
    let ev = input.evidence;
    let ctx = input.ctx;
    let now = ctx.clock.now_epoch();
    let tick_now = ctx.clock.tick_ms();
    let age_secs = evidence_age_secs(ev, now, tick_now);

    let boot_id_match =
        !ctx.current_boot_id.is_empty() && same_boot_id(&ev.boot_id, &ctx.current_boot_id);
    let config_digest_match =
        !ctx.current_config_digest.is_empty() && ev.config_digest == ctx.current_config_digest;

    let st = GuardStatus {
        state: GuardState::Unknown,
        reason: GuardReason::NotVerifiedYet,
        summary: String::new(),
        // 视角说明由 `status_with` 填（它才知道本进程是否提权）；判定层保持纯函数。
        perspective_note: None,
        trade_program_count: input.trade_program_count,
        trade_program_listed: input.trade_program_listed,
        source: ev.source,
        freshness: age_secs.map(freshness_of).unwrap_or(Freshness::Expired),
        verify_pending: ctx.verify_pending,
        evidence_at: ev.verified_at_epoch.map(iso8601_utc),
        evidence_age_secs: age_secs,
        age_text: age_secs.map(age_text).unwrap_or_default(),
        boot_id_match,
        config_digest_match,
        evidence_trusted: ctx.evidence_trusted,
        store_kind: ctx.store_kind.clone(),
        unsupported: ctx.unsupported,
        detection: ev.detection,
        programs: build_program_details(ev, input.entries, input.unresolved),
    }
    .with(GuardState::Unknown, GuardReason::NotVerifiedYet);

    // ---------------- 第一层：拿不到「可信且可归属」的证据 ----------------
    if ctx.unsupported {
        return st.with(GuardState::Unknown, GuardReason::Unsupported);
    }
    if input.trade_program_listed < 0 {
        return st.with(GuardState::Unknown, GuardReason::ReadError);
    }
    // 旧版在跑是环境冲突：即使名单为空也不能把冲突说成「未启用」。
    if input.legacy_conflict {
        return st.with(GuardState::Unknown, GuardReason::LegacyConflict);
    }
    // 三种空态先于证据判定：它们是配置事实，不依赖 WFP/BFE/证据。
    if input.trade_program_listed == 0 {
        return st.with(GuardState::Unprotected, GuardReason::EmptyProgramList);
    }
    if input.trade_program_count == 0 && input.unresolved.is_empty() {
        // 名单里全是直连/日常：用户没有做错任何事，不得红告警（A24）。
        return st.with(GuardState::Unprotected, GuardReason::NoTradePrograms);
    }
    if !input.unresolved.is_empty() {
        // 有交易条目但解析不出绝对路径：这是确定的「不参与保护」，不是「无法确认」。
        return st.with(GuardState::Unprotected, GuardReason::ProgramUnresolved);
    }
    if let Some(err) = ev.read_error {
        // 例外：没权限但手上有可用记录 → 继续按记录判定（来源与时间照实标出）
        let usable_record = ev.source.is_some() && ctx.evidence_trusted;
        if !(err.is_permission() && usable_record) {
            return st.with(GuardState::Unknown, reason_for_error(err));
        }
    }
    if !ev.detection.bfe_ready {
        return st.with(GuardState::Unknown, GuardReason::BfeUnavailable);
    }
    if !ev.source.is_some() {
        // 没有证据。但如果是用户主动解除的（Q8），要说「已解除」而不是「无法确认」。
        if input.user_removed && input.trade_program_count > 0 {
            return st.with(GuardState::Unprotected, GuardReason::UserRemoved);
        }
        return st.with(GuardState::Unknown, GuardReason::NotVerifiedYet);
    }
    if !ctx.evidence_trusted {
        // 存储自检不过：内容再漂亮也不能信（P0-16/A21）
        return st.with(GuardState::Unknown, GuardReason::EvidenceUnprotected);
    }
    if !ctx.store_kind.is_empty() && !ev.store_kind.is_empty() && ctx.store_kind != ev.store_kind {
        return st.with(GuardState::Unknown, GuardReason::StoreMismatch);
    }
    if !boot_id_match {
        return st.with(GuardState::Unknown, GuardReason::BootChanged);
    }
    if !config_digest_match {
        return st.with(GuardState::Unknown, GuardReason::ConfigChanged);
    }
    let Some(age) = age_secs else {
        return st.with(GuardState::Unknown, GuardReason::Corrupt);
    };
    if age >= EVIDENCE_MAX_AGE_SECS {
        return st.with(GuardState::Unknown, GuardReason::EvidenceExpired);
    }

    // ---------------- 第二层：证据可信，判「覆盖得全不全」 ----------------
    if input.user_removed {
        // 主动解除之后即使还有旧证据残留，也不该说「已保护」（用户刚亲手关掉它）
        return st.with(GuardState::Unprotected, GuardReason::UserRemoved);
    }
    if !ev.detection.infrastructure_verified {
        let reason = if ev.detection.provider_present && ev.detection.sublayer_present {
            GuardReason::InfrastructureConflict
        } else {
            GuardReason::InfrastructureMissing
        };
        return st.with(GuardState::Unprotected, reason);
    }
    let mut missing = false;
    let mut disabled = false;
    for program in &st.programs {
        if !program.participated {
            continue;
        }
        for layer in Layer::ALL {
            if !program.slot_ok(layer) {
                if program.slot(layer).is_disabled() {
                    disabled = true;
                } else {
                    missing = true;
                }
            }
        }
    }
    if disabled {
        return st.with(GuardState::Unprotected, GuardReason::DisabledFilter);
    }
    if missing {
        return st.with(GuardState::Unprotected, GuardReason::MissingFilter);
    }
    if ev.extra_owned_filters > 0 {
        return st.with(GuardState::Unprotected, GuardReason::ExtraFilter);
    }
    if st.programs.is_empty() || !st.programs.iter().all(|p| p.ok()) {
        return st.with(GuardState::Unprotected, GuardReason::MissingFilter);
    }
    st.with(GuardState::Protected, GuardReason::Ok)
}

/// 时龄（秒）。**单调时钟优先**，墙钟只做兜底。
///
/// 抗回拨：墙钟被改早两小时时，单调钟仍给出正确的增长；
/// 只有「没有单调读数」或「单调读数回退（跨重启/异常）」时才用墙钟。
pub fn evidence_age_secs(ev: &GuardEvidence, now_epoch: f64, tick_now: u64) -> Option<u64> {
    if let Some(tick) = ev.verified_at_tick_ms {
        if tick_now >= tick {
            return Some((tick_now - tick) / 1000);
        }
        // 单调钟回退：不能给出负时龄，退回墙钟
    }
    ev.verified_at_epoch
        .map(|t| (now_epoch - t).max(0.0).round() as u64)
}

/// 两个开机标识是否一致（容差 5 秒：两次读 `GetTickCount64` 会有一两秒抖动）。
pub fn same_boot_id(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    match (a.trim().parse::<f64>(), b.trim().parse::<f64>()) {
        (Ok(x), Ok(y)) => (x - y).abs() <= 5.0,
        // 不是数字（未来格式）：只接受完全相等
        _ => a.trim() == b.trim(),
    }
}

fn reason_for_error(err: WfpError) -> GuardReason {
    if err.is_permission() {
        GuardReason::NoPermission
    } else if err.is_bfe_down() {
        GuardReason::BfeUnavailable
    } else {
        GuardReason::ReadError
    }
}

fn build_program_details(
    ev: &GuardEvidence,
    entries: &[ResolvedEntry],
    unresolved: &[UnresolvedEntry],
) -> Vec<ProgramGuardStatus> {
    let mut out: Vec<ProgramGuardStatus> = Vec::with_capacity(entries.len() + unresolved.len());
    for entry in entries {
        let path_text = entry.path.to_string_lossy().to_string();
        let matched = ev.programs.iter().find(|p| p.path.eq_ignore_ascii_case(&path_text));
        let (ipv4, ipv6, device_path) = match matched {
            Some(p) => (
                p.ipv4,
                p.ipv6,
                Some(super::identity::device_path_from_app_id(&p.app_id)),
            ),
            None => (FilterSlot::absent(), FilterSlot::absent(), None),
        };
        out.push(ProgramGuardStatus {
            name: entry.name.clone(),
            path: Some(path_text),
            device_path,
            participated: true,
            unresolved_reason: None,
            ipv4,
            ipv6,
        });
    }
    for item in unresolved {
        out.push(ProgramGuardStatus {
            name: item.name.clone(),
            path: item.path.clone(),
            device_path: None,
            participated: false,
            unresolved_reason: Some(item.reason.clone()),
            ipv4: FilterSlot::absent(),
            ipv6: FilterSlot::absent(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// config_digest
// ---------------------------------------------------------------------------

/// 名单 + 解析结果 + provider 身份/版本 + 意图 的摘要。
///
/// 覆盖（PRD §4.1.1 第 3 条 / 主理人 #3）：
/// 1. **provider 身份/版本**：`OWNER_MARKER`（换版本 = 换摘要 = 旧证据失效）；
/// 2. **意图**：启用 / 用户已解除（Q8 的标记必须参与，否则解除后旧证据仍能撑起 Protected）；
/// 3. **解析后的绝对路径集合**（大小写归一、按路径排序：顺序变化不算变更）；
/// 4. **未解析条目**（名字 + 原样路径 + 原因：它们会让状态最多 Unprotected，必须进摘要）。
///
/// # 为什么**不含** `app_id`
///
/// 写证据的一侧（提权子进程）拿得到 `app_id`，读证据的一侧（未提权界面刷新）
/// 只愿意算轻量的路径集合。两侧一旦用不同口径，记录里的摘要与当前摘要**永远**对不上，
/// 结果是「每次都 `ConfigChanged`」——一个静默的永久故障。
/// `app_id` 本身是路径的确定性函数（`FwpmGetAppIdFromFileName0` 的规范化结果），
/// 所以用路径做键不损失检测能力。
pub fn config_digest(
    ids: &[ProgramIdentity],
    unresolved: &[UnresolvedEntry],
    removed: bool,
) -> String {
    let pairs: Vec<(String, String)> = ids
        .iter()
        .map(|i| (i.path.to_string_lossy().to_string(), i.name.clone()))
        .collect();
    config_digest_paths(&pairs, unresolved, removed)
}

/// 轻量口径（只有路径，不碰 BFE）：状态刷新用。
///
/// **与 [`config_digest`] 完全同值**（同一实现）——这不是巧合，是两个入口必须可互换，
/// 否则「写证据」与「读证据」会落到不同摘要上。
pub fn config_digest_light(
    entries: &[ResolvedEntry],
    unresolved: &[UnresolvedEntry],
    removed: bool,
) -> String {
    let pairs: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.path.to_string_lossy().to_string(), e.name.clone()))
        .collect();
    config_digest_paths(&pairs, unresolved, removed)
}

/// 摘要的**唯一实现**：`(路径, 名字)` 集合 + 未解析条目 + 身份/意图。
fn config_digest_paths(
    resolved: &[(String, String)],
    unresolved: &[UnresolvedEntry],
    removed: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_SCHEMA.as_bytes());
    hasher.update([0u8]);
    hasher.update(super::wfp::OWNER_MARKER);
    hasher.update([0u8]);
    hasher.update(INTENT_GUARD_ENABLED.as_bytes());
    hasher.update([0u8]);
    if removed {
        hasher.update(INTENT_USER_REMOVED.as_bytes());
    }
    hasher.update([0u8]);
    let mut pairs: Vec<(String, String)> = resolved
        .iter()
        .map(|(path, name)| (path.to_lowercase(), name.to_lowercase()))
        .collect();
    pairs.sort();
    for (path, name) in pairs {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
    }
    digest_unresolved(&mut hasher, unresolved);
    hex(&hasher.finalize())
}

fn digest_unresolved(hasher: &mut Sha256, unresolved: &[UnresolvedEntry]) {
    let mut pending: Vec<(String, String, String)> = unresolved
        .iter()
        .map(|u| {
            (
                u.name.to_lowercase(),
                u.path.clone().unwrap_or_default().to_lowercase(),
                u.reason_id.clone(),
            )
        })
        .collect();
    pending.sort();
    for (name, path, reason) in pending {
        hasher.update(b"unresolved");
        hasher.update([0u8]);
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(reason.as_bytes());
        hasher.update([0u8]);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// 时间格式
// ---------------------------------------------------------------------------

/// epoch 秒 → `YYYY-MM-DDTHH:MM:SSZ`（自己算：只需 UTC、秒级、单方向）。
pub fn iso8601_utc(epoch: f64) -> String {
    let secs = epoch.floor() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// epoch 秒 → 带毫秒的 UTC（证据时间戳：毫秒便于诊断排序与「同秒多次核验」区分）。
pub fn iso8601_utc_millis(epoch: f64) -> String {
    let secs = epoch.floor();
    let millis = (((epoch - secs) * 1000.0).round() as i64).clamp(0, 999);
    format!("{}.{:03}Z", iso8601_utc(secs).trim_end_matches('Z'), millis)
}

/// Howard Hinnant 的 `civil_from_days`（1970-01-01 起的天数 → 年月日）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 年月日 → 1970-01-01 起的天数（`civil_from_days` 的逆）。
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 解析 `YYYY-MM-DDTHH:MM:SS(.mmm)?Z`（我们自己的两种格式）。
///
/// 只支持这一种形状：证据时间戳**只有我们写**，不需要通用 ISO 解析器。
pub fn parse_iso8601_millis(text: &str) -> Option<f64> {
    let t = text.trim();
    if t.len() < 20 || !t.ends_with('Z') {
        return None;
    }
    let (date, rest) = t.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let body = rest.trim_end_matches('Z');
    let (hms, frac) = match body.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (body, None),
    };
    let mut tp = hms.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let s: i64 = tp.next()?.parse().ok()?;
    let millis: f64 = match frac {
        Some(f) => format!("0.{f}").parse().ok()?,
        None => 0.0,
    };
    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + h * 3600 + mi * 60 + s;
    Some(secs as f64 + millis)
}

// ---------------------------------------------------------------------------
// 证据记录（结构；读写实现在 `evidence.rs`）
// ---------------------------------------------------------------------------

/// 记录 schema。**不认识就当没有证据**（`Unknown`），不做字段猜测式迁移。
pub const RECORD_SCHEMA: u32 = 1;

/// 记录里的「用户已主动解除」标记来源。**它不是证据**。
pub const SOURCE_USER_REMOVED: &str = "UserRemoved";

/// 记录读不出来的原因（全部导向 `Unknown`，不做任何推测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// 存储里没有记录（从未核验 / 已解除）。
    Missing,
    Io(String),
    Parse(String),
    /// `SchemaVersion` 不认识。
    Schema(u32),
    /// `StoreKind` 与本次所选存储不一致（生产/测试串场）。
    StoreMismatch(String),
    /// `Sha256` 不符或长度异常（损坏，不是伪造）。
    Corrupt(String),
    /// 来源字符串不认识（不许猜成某个已知来源）。
    Source(String),
    /// 没有权限。
    AccessDenied,
}

impl RecordError {
    pub fn message(&self) -> String {
        match self {
            RecordError::Missing => "没有交易保护核验记录".into(),
            RecordError::Io(e) => format!("交易保护核验记录读取失败：{e}"),
            RecordError::Parse(e) => format!("交易保护核验记录无法解析：{e}"),
            RecordError::Schema(n) => format!("交易保护核验记录版本不认识（schema {n}）"),
            RecordError::StoreMismatch(k) => {
                format!("交易保护核验记录来自另一种存储（{k}），不能沿用")
            }
            RecordError::Corrupt(e) => format!("交易保护核验记录已损坏：{e}"),
            RecordError::Source(s) => format!("交易保护核验记录的来源不认识（{s}），不能沿用"),
            RecordError::AccessDenied => "没有权限读取交易保护核验记录".into(),
        }
    }
}

/// 记录里的槽位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecordSlot {
    #[serde(rename = "Present")]
    pub present: bool,
    #[serde(rename = "Recognized")]
    pub recognized: bool,
    #[serde(rename = "Persistent")]
    pub persistent: bool,
    #[serde(rename = "Disabled")]
    pub disabled: bool,
    #[serde(rename = "FilterId", default)]
    pub filter_id: Option<u64>,
}

impl From<FilterSlot> for RecordSlot {
    fn from(s: FilterSlot) -> RecordSlot {
        RecordSlot {
            present: s.present,
            recognized: s.recognized,
            persistent: s.persistent,
            disabled: s.disabled,
            filter_id: s.filter_id,
        }
    }
}

impl From<RecordSlot> for FilterSlot {
    fn from(s: RecordSlot) -> FilterSlot {
        FilterSlot {
            present: s.present,
            recognized: s.recognized,
            persistent: s.persistent,
            disabled: s.disabled,
            filter_id: s.filter_id,
        }
    }
}

/// 记录里的单程序条目。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordProgram {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Path")]
    pub path: String,
    /// appId 是 UTF-16 字节：用数字数组最省事且不丢信息（不用 base64 引依赖）。
    #[serde(rename = "AppId")]
    pub app_id: Vec<u8>,
    #[serde(rename = "IPv4")]
    pub ipv4: RecordSlot,
    #[serde(rename = "IPv6")]
    pub ipv6: RecordSlot,
}

/// 落盘的证据记录（架构 §4.4.2 的 schema 1）。
///
/// 字段顺序**就是**规范序列化顺序：`Sha256` 是对「本结构去掉 `Sha256` 后」的 JSON
/// 序列化算的，读取时能原样重算校验（挡损坏，**不挡管理员**——§4.4.5）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardRecord {
    #[serde(rename = "SchemaVersion")]
    pub schema_version: u32,
    /// `Registry` / `IsolatedFile`（交叉校验生产/测试串场）。
    #[serde(rename = "StoreKind")]
    pub store_kind: String,
    /// 写入版本（诊断/顺序告警用；**不作为有效性依据**）。
    #[serde(rename = "RecordVersion", default)]
    pub record_version: u64,
    /// 本次写入的随机串：父进程写完回读必须与它一致，否则视为没写成功。
    #[serde(rename = "Nonce", default)]
    pub nonce: String,
    #[serde(rename = "BootId")]
    pub boot_id: String,
    #[serde(rename = "ConfigDigest")]
    pub config_digest: String,
    #[serde(rename = "VerifiedAtUtc")]
    pub verified_at_utc: String,
    /// 单调毫秒（算时龄用；墙钟被改也不影响）。
    #[serde(rename = "VerifiedAtTickMs", default)]
    pub verified_at_tick_ms: u64,
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "VerifierPid", default)]
    pub verifier_pid: u32,
    #[serde(rename = "VerifierElevated", default)]
    pub verifier_elevated: bool,
    #[serde(rename = "AppVersion", default)]
    pub app_version: String,
    #[serde(rename = "ProviderPresent")]
    pub provider_present: bool,
    #[serde(rename = "SubLayerPresent")]
    pub sublayer_present: bool,
    #[serde(rename = "InfrastructureVerified")]
    pub infrastructure_verified: bool,
    #[serde(rename = "LegacyGuardPresent", default)]
    pub legacy_guard_present: bool,
    /// 核验当时旧版 旧版是否在跑（冲突态变化 → 证据失效）。
    #[serde(rename = "LegacyRunningAtVerify", default)]
    pub legacy_running_at_verify: bool,
    #[serde(rename = "BfeReady", default = "default_true")]
    pub bfe_ready: bool,
    #[serde(rename = "ExtraOwnedFilters", default)]
    pub extra_owned_filters: usize,
    #[serde(rename = "Programs", default)]
    pub programs: Vec<RecordProgram>,
    #[serde(rename = "Sha256", default)]
    pub sha256: String,
}

fn default_true() -> bool {
    true
}

impl GuardRecord {
    /// 由证据构造记录（`source` 由调用方决定：只有提权枚举结果才有资格）。
    pub fn from_evidence(
        ev: &GuardEvidence,
        nonce: &str,
        verifier_pid: u32,
        verifier_elevated: bool,
        record_version: u64,
    ) -> GuardRecord {
        let mut rec = GuardRecord {
            schema_version: RECORD_SCHEMA,
            store_kind: ev.store_kind.clone(),
            record_version,
            nonce: nonce.to_string(),
            boot_id: ev.boot_id.clone(),
            config_digest: ev.config_digest.clone(),
            verified_at_utc: ev.verified_at_epoch.map(iso8601_utc_millis).unwrap_or_default(),
            verified_at_tick_ms: ev.verified_at_tick_ms.unwrap_or(0),
            source: ev.source.as_str().to_string(),
            verifier_pid,
            verifier_elevated,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            provider_present: ev.detection.provider_present,
            sublayer_present: ev.detection.sublayer_present,
            infrastructure_verified: ev.detection.infrastructure_verified,
            legacy_guard_present: ev.detection.legacy_guard_present,
            legacy_running_at_verify: ev.legacy_running_at_verify,
            bfe_ready: ev.detection.bfe_ready,
            extra_owned_filters: ev.extra_owned_filters,
            programs: ev
                .programs
                .iter()
                .map(|p| RecordProgram {
                    name: p.name.clone(),
                    path: p.path.clone(),
                    app_id: p.app_id.clone(),
                    ipv4: p.ipv4.into(),
                    ipv6: p.ipv6.into(),
                })
                .collect(),
            sha256: String::new(),
        };
        rec.seal();
        rec
    }

    /// 算 `Sha256` 并写进本结构（对「不含 Sha256」的规范序列化取哈希）。
    pub fn seal(&mut self) {
        self.sha256 = self.compute_sha256();
    }

    fn compute_sha256(&self) -> String {
        let mut copy = self.clone();
        copy.sha256.clear();
        let bytes = serde_json::to_vec(&copy).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex(&hasher.finalize())
    }

    /// 校验 `Sha256`（挡损坏，不挡管理员）。
    pub fn verify_seal(&self) -> bool {
        !self.sha256.is_empty() && self.sha256 == self.compute_sha256()
    }

    /// 记录 → 证据。来源**照实还原**；认不出来源 → `None`（→ 不可能是 `Protected`）。
    pub fn to_evidence(&self) -> GuardEvidence {
        GuardEvidence {
            programs: self
                .programs
                .iter()
                .map(|p| ProgramEvidence {
                    name: p.name.clone(),
                    path: p.path.clone(),
                    app_id: p.app_id.clone(),
                    ipv4: p.ipv4.into(),
                    ipv6: p.ipv6.into(),
                })
                .collect(),
            detection: GuardDetection {
                provider_present: self.provider_present,
                sublayer_present: self.sublayer_present,
                infrastructure_verified: self.infrastructure_verified,
                legacy_guard_present: self.legacy_guard_present,
                bfe_ready: self.bfe_ready,
            },
            read_error: None,
            verified_at_epoch: parse_iso8601_millis(&self.verified_at_utc),
            verified_at_tick_ms: if self.verified_at_tick_ms == 0 {
                None
            } else {
                Some(self.verified_at_tick_ms)
            },
            source: GuardSource::parse(&self.source).unwrap_or(GuardSource::None),
            config_digest: self.config_digest.clone(),
            boot_id: self.boot_id.clone(),
            extra_owned_filters: self.extra_owned_filters,
            legacy_running_at_verify: self.legacy_running_at_verify,
            store_kind: self.store_kind.clone(),
        }
    }

    /// 这是不是「用户主动解除」的标记记录（不是证据）。
    pub fn is_user_removed(&self) -> bool {
        self.source == SOURCE_USER_REMOVED
    }
}

/// 作废一份证据记录：**改名不删**（保留可审计副本），成功后原路径不再存在。
///
/// 只用于隔离文件存储；注册表存储的作废由 `evidence::RegistryStore` 自己实现
/// （删值或写成标记），语义相同：**旧证据不能再被读到**。
pub fn invalidate_record(path: &std::path::Path, reason: &str, now_epoch: f64) -> bool {
    if !path.exists() {
        return false;
    }
    let invalid = path.with_extension("invalid.json");
    let moved = std::fs::rename(path, &invalid).is_ok();
    if !moved {
        // 改名失败（被占用/权限）：退化成删除——**宁可丢证据，也不能让它继续生效**。
        let _ = std::fs::remove_file(path);
    }
    let note = format!("reason={reason}\nat={}\n", iso8601_utc(now_epoch));
    let _ = std::fs::write(path.with_extension("invalid-reason.txt"), note);
    true
}

// ---------------------------------------------------------------------------
// 单测（纯逻辑）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn app_id(path: &str) -> Vec<u8> {
        path.encode_utf16().chain(std::iter::once(0u16)).flat_map(|u| u.to_le_bytes()).collect()
    }

    fn resolved(name: &str, path: &str) -> ResolvedEntry {
        ResolvedEntry { name: name.to_string(), path: path.into() }
    }

    fn identity(name: &str, path: &str) -> ProgramIdentity {
        ProgramIdentity {
            name: name.to_string(),
            path: path.into(),
            app_id: app_id(path),
            device_path: path.to_lowercase(),
        }
    }

    fn good_slot(id: u64) -> FilterSlot {
        FilterSlot { present: true, recognized: true, persistent: true, disabled: false, filter_id: Some(id) }
    }

    fn program(name: &str, path: &str) -> ProgramEvidence {
        ProgramEvidence {
            name: name.to_string(),
            path: path.to_string(),
            app_id: app_id(path),
            ipv4: good_slot(11),
            ipv6: good_slot(12),
        }
    }

    fn detection_ok() -> GuardDetection {
        GuardDetection {
            provider_present: true,
            sublayer_present: true,
            infrastructure_verified: true,
            legacy_guard_present: false,
            bfe_ready: true,
        }
    }

    const NOW: f64 = 1_700_000_000.0;
    const TICK: u64 = 5_000_000;

    fn evidence(programs: Vec<ProgramEvidence>) -> GuardEvidence {
        GuardEvidence {
            programs,
            detection: detection_ok(),
            read_error: None,
            verified_at_epoch: Some(NOW),
            verified_at_tick_ms: Some(TICK),
            source: GuardSource::ElevatedVerify,
            config_digest: "digest".into(),
            boot_id: "boot-1".into(),
            extra_owned_filters: 0,
            legacy_running_at_verify: false,
            store_kind: "IsolatedFile".into(),
        }
    }

    fn ctx_at(age_secs: u64) -> EvalContext {
        EvalContext {
            current_boot_id: "boot-1".into(),
            current_config_digest: "digest".into(),
            verify_pending: VerifyPending::None,
            evidence_trusted: true,
            unsupported: false,
            store_kind: "IsolatedFile".into(),
            clock: Box::new(FixedClock::new(NOW + age_secs as f64, TICK + age_secs * 1000)),
        }
    }

    fn input<'a>(
        ev: &'a GuardEvidence,
        entries: &'a [ResolvedEntry],
        unresolved: &'a [UnresolvedEntry],
        ctx: &'a EvalContext,
    ) -> EvaluationInput<'a> {
        EvaluationInput {
            evidence: ev,
            entries,
            unresolved,
            trade_program_count: (entries.len() + unresolved.len()) as i64,
            trade_program_listed: (entries.len() + unresolved.len()) as i64,
            legacy_conflict: false,
            user_removed: false,
            ctx,
        }
    }

    #[test]
    fn full_evidence_is_protected() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let ctx = ctx_at(10);
        let st = evaluate(&input(&ev, &entries, &[], &ctx));
        assert_eq!(st.state, GuardState::Protected);
        assert_eq!(st.reason, GuardReason::Ok);
        assert_eq!(st.freshness, Freshness::JustVerified);
        assert_eq!(st.age_text, "刚刚核验");
        assert_eq!(st.evidence_age_secs, Some(10));
        assert!(st.boot_id_match && st.config_digest_match && st.evidence_trusted);
        assert_eq!(st.store_kind, "IsolatedFile");
        assert!(st.programs[0].ok());
    }

    #[test]
    fn all_direct_entries_are_a_neutral_empty_state() {
        // A24：名单里有 3 条进程，但全设为直连/日常 → 不是「尚未添加」，也不是故障。
        let ev = GuardEvidence::default();
        let ctx = ctx_at(0);
        let mut inp = input(&ev, &[], &[], &ctx);
        inp.trade_program_count = 0;
        inp.trade_program_listed = 3;
        let st = evaluate(&inp);
        assert_eq!(st.state, GuardState::Unprotected);
        assert_eq!(st.reason, GuardReason::NoTradePrograms);
        assert_eq!(st.summary, "名单里没有需要保护的程序（当前都设为直连或日常）。");
        assert_eq!(st.trade_program_count, 0);
        assert_eq!(st.trade_program_listed, 3);
    }

    #[test]
    fn mixed_lists_count_only_trade_participants() {
        // A25：2 条名单里只有 1 条 target==Trade；Count=1、Listed=2。
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let ctx = ctx_at(10);
        let mut inp = input(&ev, &entries, &[], &ctx);
        inp.trade_program_count = 1;
        inp.trade_program_listed = 2;
        let st = evaluate(&inp);
        assert_eq!(st.state, GuardState::Protected, "{st:?}");
        assert_eq!(st.trade_program_count, 1);
        assert_eq!(st.trade_program_listed, 2);
    }

    #[test]
    fn age_never_downgrades_before_twenty_four_hours() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        for (age, want_fresh, want_text) in [
            (0u64, Freshness::JustVerified, "刚刚核验"),
            (59, Freshness::JustVerified, "刚刚核验"),
            (60, Freshness::Recent, "1 分钟前核验"),
            (10 * 60, Freshness::Recent, "10 分钟前核验"),
            (20 * 60 - 1, Freshness::Recent, "19 分钟前核验"),
            (20 * 60, Freshness::Aging, "较旧：20 分钟前核验"),
            (25 * 60, Freshness::Aging, "较旧：25 分钟前核验"),
            (23 * 3600 + 59 * 60, Freshness::Aging, "较旧：23 小时前核验"),
        ] {
            let ctx = ctx_at(age);
            let st = evaluate(&input(&ev, &entries, &[], &ctx));
            assert_eq!(st.state, GuardState::Protected, "age={age} 不许降级");
            assert_eq!(st.freshness, want_fresh, "age={age}");
            assert_eq!(st.age_text, want_text, "age={age}");
        }
    }

    #[test]
    fn twenty_four_hours_is_the_only_time_based_downgrade() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let ctx = ctx_at(23 * 3600 + 59 * 60 + 59);
        assert_eq!(evaluate(&input(&ev, &entries, &[], &ctx)).state, GuardState::Protected);
        let ctx = ctx_at(EVIDENCE_MAX_AGE_SECS);
        let st = evaluate(&input(&ev, &entries, &[], &ctx));
        assert_eq!(st.state, GuardState::Unknown);
        assert_eq!(st.reason, GuardReason::EvidenceExpired);
        assert_eq!(st.summary, "交易保护状态无法确认（上次核验已超过 24 小时）。");
        assert_eq!(st.freshness, Freshness::Expired);
    }

    #[test]
    fn verify_pending_never_rewrites_the_state() {
        // A23：断开后核验被拒 = 旧证据 + 较旧 + 本次未能重新核验，**不是** Unknown。
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        for pending in [VerifyPending::Declined, VerifyPending::Failed, VerifyPending::Unknown] {
            let mut ctx = ctx_at(25 * 60);
            ctx.verify_pending = pending;
            let st = evaluate(&input(&ev, &entries, &[], &ctx));
            assert_eq!(st.state, GuardState::Protected, "{pending:?} 不许改三态");
            assert_eq!(st.verify_pending, pending);
            assert_eq!(st.freshness, Freshness::Aging);
        }
    }

    #[test]
    fn unattributable_evidence_is_unknown_with_the_right_reason() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let mut ctx = ctx_at(10);
        ctx.current_boot_id = "boot-2".into();
        let st = evaluate(&input(&ev, &entries, &[], &ctx));
        assert_eq!(st.reason, GuardReason::BootChanged);
        assert_eq!(st.state, GuardState::Unknown);

        let mut ctx = ctx_at(10);
        ctx.current_config_digest = "other".into();
        assert_eq!(evaluate(&input(&ev, &entries, &[], &ctx)).reason, GuardReason::ConfigChanged);

        let mut ctx = ctx_at(10);
        ctx.store_kind = "Registry".into();
        assert_eq!(evaluate(&input(&ev, &entries, &[], &ctx)).reason, GuardReason::StoreMismatch);

        let mut ctx = ctx_at(10);
        ctx.evidence_trusted = false;
        let st = evaluate(&input(&ev, &entries, &[], &ctx));
        assert_eq!(st.reason, GuardReason::EvidenceUnprotected);
        assert_eq!(st.state, GuardState::Unknown, "记录内容再漂亮也不许 Protected（A21）");
    }

    #[test]
    fn perspective_note_appears_only_for_the_elevated_registry_view() {
        // R25-1 三种组合：只有「注册表证据 + 管理员进程 + 自检不过」才需要那句视角说明。
        // 逐字断言：这句话会出现在 CLI 与界面上，改一个字都是新事实，必须被测试挡住。
        assert_eq!(
            perspective_note("Registry", true, GuardReason::EvidenceUnprotected).as_deref(),
            Some("当前是管理员进程，可以改写核验记录；这个视角无法证明防篡改生效，请用普通权限进程复核。")
        );
        // 普通权限：同一条记录读到的是「可信」，本就不会落到 EvidenceUnprotected；
        // 万一落到，也不是视角问题，不许拿这句话糊过去。
        assert_eq!(
            perspective_note("Registry", false, GuardReason::EvidenceUnprotected),
            None,
            "非提权进程没有「自己能改写」这个视角偏差"
        );
        // 非注册表存储（隔离文件）：判定不依赖「我能不能写 HKLM」，不该提管理员。
        assert_eq!(
            perspective_note("IsolatedFile", true, GuardReason::EvidenceUnprotected),
            None,
            "隔离文件存储与提权无关"
        );
        // 提权但与存储自检无关的原因：不许乱加解释。
        assert_eq!(perspective_note("Registry", true, GuardReason::BootChanged), None);
        assert_eq!(perspective_note("Registry", true, GuardReason::NoPermission), None);
    }

    #[test]
    fn coverage_gaps_cap_the_state_at_unprotected() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let mut p = program("a.exe", "C:\\app\\a.exe");
        p.ipv6 = FilterSlot::absent();
        assert_eq!(
            evaluate(&input(&evidence(vec![p]), &entries, &[], &ctx_at(10))).reason,
            GuardReason::MissingFilter
        );
        let mut p = program("a.exe", "C:\\app\\a.exe");
        p.ipv4 = FilterSlot { disabled: true, ..good_slot(1) };
        assert_eq!(
            evaluate(&input(&evidence(vec![p]), &entries, &[], &ctx_at(10))).reason,
            GuardReason::DisabledFilter
        );
        // filterId=0（BFE 没分配 id）也不能算
        let mut p = program("a.exe", "C:\\app\\a.exe");
        p.ipv4 = good_slot(0);
        assert_eq!(
            evaluate(&input(&evidence(vec![p]), &entries, &[], &ctx_at(10))).reason,
            GuardReason::MissingFilter
        );
        let unresolved = vec![UnresolvedEntry {
            name: "old.exe".into(),
            reason: "需要确认程序位置".into(),
            reason_id: "MissingPath".into(),
            path: None,
        }];
        assert_eq!(
            evaluate(&input(
                &evidence(vec![program("a.exe", "C:\\app\\a.exe")]),
                &entries,
                &unresolved,
                &ctx_at(10)
            ))
            .reason,
            GuardReason::ProgramUnresolved
        );
        assert_eq!(
            evaluate(&input(&evidence(vec![]), &[], &[], &ctx_at(10))).reason,
            GuardReason::EmptyProgramList
        );
        let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        ev.extra_owned_filters = 2;
        assert_eq!(evaluate(&input(&ev, &entries, &[], &ctx_at(10))).reason, GuardReason::ExtraFilter);
    }

    #[test]
    fn user_removed_is_its_own_state_not_a_failure() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = GuardEvidence { source: GuardSource::None, ..evidence(vec![]) };
        let ctx_zero = ctx_at(0);
        let mut inp = input(&ev, &entries, &[], &ctx_zero);
        inp.user_removed = true;
        let st = evaluate(&inp);
        assert_eq!(st.state, GuardState::Unprotected);
        assert_eq!(st.reason, GuardReason::UserRemoved);
        assert_eq!(st.summary, "交易保护已解除；下次连接会重新启用。");
        assert!(!st.summary.contains("未完整启用"), "解除不是故障（Q8）");

        let ev2 = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let ctx_ten = ctx_at(10);
        let mut inp2 = input(&ev2, &entries, &[], &ctx_ten);
        inp2.user_removed = true;
        assert_eq!(evaluate(&inp2).reason, GuardReason::UserRemoved, "残留证据也不许说已保护");
    }

    #[test]
    fn no_evidence_is_unknown_never_protected() {
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = GuardEvidence::default();
        let st = evaluate(&input(&ev, &entries, &[], &ctx_at(0)));
        assert_eq!(st.state, GuardState::Unknown);
        assert_eq!(st.reason, GuardReason::NotVerifiedYet);
        assert_eq!(st.source, GuardSource::None);
        assert!(!st.is_protected());
    }

    #[test]
    fn monotonic_clock_wins_over_a_backdated_wall_clock() {
        // 墙钟被改早 2 小时：时龄仍按单调钟算（25 分钟）。
        let entries = vec![resolved("a.exe", "C:\\app\\a.exe")];
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let mut ctx = ctx_at(25 * 60);
        ctx.clock = Box::new(FixedClock::new(NOW - 7200.0, TICK + 25 * 60 * 1000));
        let st = evaluate(&input(&ev, &entries, &[], &ctx));
        assert_eq!(st.evidence_age_secs, Some(25 * 60));
        assert_eq!(st.freshness, Freshness::Aging);
        // 单调读数缺失 → 退回墙钟（30 秒）
        let mut ev2 = ev.clone();
        ev2.verified_at_tick_ms = None;
        let st = evaluate(&input(&ev2, &entries, &[], &ctx_at(30)));
        assert_eq!(st.evidence_age_secs, Some(30));
    }

    #[test]
    fn digest_covers_list_identity_and_intents() {
        let a = identity("a.exe", "C:\\app\\a.exe");
        let b = identity("b.exe", "C:\\app\\b.exe");
        let d1 = config_digest(&[a.clone(), b.clone()], &[], false);
        assert_eq!(d1, config_digest(&[b.clone(), a.clone()], &[], false), "顺序不算变更");
        assert_eq!(d1.len(), 64);
        assert_ne!(d1, config_digest(&[a.clone()], &[], false), "删一条必须变");
        assert_ne!(
            d1,
            config_digest(&[identity("a.exe", "C:\\app\\a2.exe"), b.clone()], &[], false),
            "路径变了必须变"
        );
        let un = UnresolvedEntry {
            name: "old.exe".into(),
            reason: "找不到程序文件".into(),
            reason_id: "NotFound".into(),
            path: None,
        };
        assert_ne!(
            d1,
            config_digest(&[a.clone(), b], std::slice::from_ref(&un), false),
            "未解析条目必须进摘要"
        );
        let un2 = UnresolvedEntry { reason_id: "MissingPath".into(), ..un.clone() };
        assert_ne!(
            config_digest(&[], std::slice::from_ref(&un), false),
            config_digest(&[], std::slice::from_ref(&un2), false),
            "原因变化也算变更"
        );
        assert_ne!(
            config_digest(&[a.clone()], &[], false),
            config_digest(&[a], &[], true),
            "主动解除必须让旧证据失效"
        );
        // 轻量口径与完整口径必须同值（架构 §4.2：写证据与读证据不能落到两个摘要上）
        assert_eq!(
            config_digest(&[identity("a.exe", "C:\\app\\a.exe")], &[], false),
            config_digest_light(&[resolved("a.exe", "C:\\app\\a.exe")], &[], false)
        );
    }

    #[test]
    fn record_seal_detects_corruption_and_round_trips() {
        let ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        let rec = GuardRecord::from_evidence(&ev, "nonce-1", 42, true, 7);
        assert_eq!(rec.schema_version, RECORD_SCHEMA);
        assert_eq!(rec.store_kind, "IsolatedFile");
        assert_eq!(rec.nonce, "nonce-1");
        assert!(rec.verify_seal(), "刚写完必须能自校验");
        let text = serde_json::to_string(&rec).unwrap();
        let back: GuardRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back, rec);
        assert!(back.verify_seal());
        let mut tampered = back.clone();
        tampered.programs[0].ipv4.filter_id = Some(999);
        assert!(!tampered.verify_seal(), "改内容必须被 Sha256 抓到（挡损坏）");
        let mut no_seal = back.clone();
        no_seal.sha256.clear();
        assert!(!no_seal.verify_seal());
        // seal 是可重算的：重新 seal 后又能通过
        tampered.seal();
        assert!(tampered.verify_seal());
    }

    #[test]
    fn record_keeps_the_real_source_and_the_removed_marker() {
        let mut ev = evidence(vec![program("a.exe", "C:\\app\\a.exe")]);
        ev.source = GuardSource::ElevatedInstallReadback;
        let rec = GuardRecord::from_evidence(&ev, "n", 1, true, 1);
        assert_eq!(rec.source, "ElevatedInstallReadback");
        assert_eq!(rec.to_evidence().source, GuardSource::ElevatedInstallReadback);
        assert!(!rec.is_user_removed());
        let mut marker = rec.clone();
        marker.source = SOURCE_USER_REMOVED.to_string();
        marker.seal();
        assert!(marker.is_user_removed());
        assert_eq!(marker.to_evidence().source, GuardSource::None, "标记不是证据");
    }

    #[test]
    fn timestamps_round_trip_with_millis() {
        let t = 1_700_000_000.123;
        let text = iso8601_utc_millis(t);
        assert!(text.ends_with('Z'));
        assert!(text.contains('.'), "{text}");
        let back = parse_iso8601_millis(&text).unwrap();
        assert!((back - t).abs() < 0.002, "{text} → {back}");
        assert_eq!(iso8601_utc(0.0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000.0), "2023-11-14T22:13:20Z");
        assert_eq!(parse_iso8601_millis("2023-11-14T22:13:20Z"), Some(1_700_000_000.0));
        assert_eq!(parse_iso8601_millis("垃圾"), None);
    }

    #[test]
    fn summaries_avoid_forbidden_claims() {
        let states = [GuardState::Protected, GuardState::Unprotected, GuardState::Unknown];
        let reasons = [
            GuardReason::Ok,
            GuardReason::EmptyProgramList,
            GuardReason::UserRemoved,
            GuardReason::MissingFilter,
            GuardReason::NotVerifiedYet,
            GuardReason::BootChanged,
            GuardReason::ConfigChanged,
            GuardReason::EvidenceExpired,
            GuardReason::EvidenceUnprotected,
            GuardReason::Unsupported,
        ];
        for s in states {
            for r in reasons {
                let text = summary_for(s, r);
                assert!(!text.is_empty());
                for banned in ["走交易线路", "子进程", "开机即保护", "实时"] {
                    assert!(!text.contains(banned), "{s:?}/{r:?}: {text}");
                }
            }
        }
        assert!(!GuardReason::EvidenceExpired.is_conclusive());
        assert!(GuardReason::MissingFilter.is_conclusive());
        assert!(!GuardReason::NotVerifiedYet.is_conclusive());
        assert!(GuardReason::UserRemoved.is_conclusive(), "主动解除是确定的结论");
    }
}
