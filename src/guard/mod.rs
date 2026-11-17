//! 交易程序直连阻断（WFP）的对外 API 与编排。
//!
//! # 分层（改这一层之前先读）
//!
//! ```text
//! ipc / main / connect        ← 编排调用方（只认本模块的函数）
//!   └── guard::mod           ← 口径 + 编排 + 失效登记（本文件）
//!         ├── evidence.rs    ← 证据的唯一读写口（注册表 / 隔离文件）
//!         ├── elevate.rs     ← 一次性提权子进程（唯一提权路径）
//!         ├── wfp_win.rs     ← GuardBackend 的真实现（真实 FFI）
//!         ├── wfp.rs         ← ABI 常量、filterKey、recognize（平台无关）
//!         ├── identity.rs    ← 名单 → 程序身份
//!         └── state.rs       ← 判定（纯函数，不碰 FFI）
//! ```
//!
//! # 三条不可越界的规则
//!
//! 1. **状态只有一个来源**：`status_with()` 的输出。前端/表单本地推断都是缺陷。
//! 2. **判定不碰 FFI，FFI 不决定状态**：`state::evaluate` 是纯函数。
//! 3. **提权只有一条路**：`elevate::apply` 起 `--guard-apply` 子进程；每次动 WFP 之前
//!    先过 [`GuardCache::should_prompt`]（600 秒抑制窗，避免 UAC 风暴）。
//!
//! # 失败绝不阻断连接
//!
//! [`ensure_before_connect`] 返回 [`GuardOutcome`] 而不是 `Result`：guard 没装上时连接照旧
//! 建立（用户默认），但**必须可见**——`note()` 里写清「本次未启用交易保护」。
//!
//! # 名单的口径（PRD Q1 裁决）
//!
//! 名单 = `split.processes` 中 `target == Trade` 的条目；直连/日常条目**绝不**进阻断。

// T04/T05 会消费其中一部分（诊断、卸载）；这是 binary crate，`pub` 不抑制 dead_code。
// TODO(T05)：接完后删掉这行 allow。
#![allow(dead_code)]

pub mod elevate;
pub mod egress_policy;
pub mod evidence;
pub mod identity;
pub mod lease_helper;
pub mod proxy_identity;
pub mod state;
pub mod tun_identity;
pub mod wfp;
pub mod wfp_win;

use std::path::Path;
use std::sync::Mutex;

pub use elevate::{ElevateError, GuardAction, GuardReply, GuardRequest};
pub use evidence::{EvidenceStore, IsolatedFileStore, RemovedMarker, StoreKind};
pub use identity::{
    EntryRef, ProgramIdentity, ResolveOutcome, ResolveOutcomeLight, MAX_PROGRAMS,
};
pub use state::{
    config_digest_light, evaluate, Clock, EvalContext, EvaluationInput, FilterSlot,
    GuardDetection, GuardEvidence, GuardReason, GuardRecord, GuardSource, GuardState, GuardStatus,
    ProgramEvidence, RecordError, VerifyPending,
};
pub use wfp::{Layer, WfpError};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 「非提权点读」（L 路径）的总开关。**默认关闭**。
///
/// 架构 §1.4 实测：非提权会话下 `FwpmProviderGetByKey0`/`FwpmSubLayerGetByKey0`/
/// `FwpmTransactionBegin0` 全部返回 `ACCESS_DENIED`，`FwpmFilterCreateEnumHandle0`
/// 返回 `FWP_E_NEVER_MATCH`。所以「普通权限每次快照都去 WFP 看一眼」在 OS 层面不成立。
/// 唯一窄路（创建时写允许本人读的 DACL）必须由 spike-1 证明；在证明之前保持关闭：
/// 宁可诚实地说「无法确认」，也不要靠猜测说「已保护」。
pub const LIVE_READ_SUPPORTED: bool = false;

/// 拒绝提权后的抑制窗（秒）：`explicit=false` 的请求在窗内不再弹 UAC。
pub const GUARD_PROMPT_SUPPRESS_SECS: u64 = 600;

/// 提权预算（秒）。`operation_budget("connect")` 在名单非空时加它。
pub const GUARD_ELEVATION_BUDGET_SECS: f64 = 180.0;

/// 显式命令（verify/sync/remove）的预算（秒）：一次 UAC + 一次 WFP 事务 + 一次枚举。
pub const GUARD_EXPLICIT_BUDGET_SECS: f64 = 120.0;

/// 并发互斥名前缀。**必须**以 `Global\SpiderVPN-` 开头：
/// 与旧版客户端的守卫互斥完全分开（隔离契约）。
pub const GUARD_MUTEX_PREFIX: &str = "Global\\SpiderVPN-Guard-";

/// P0-13 那句安全说明的**唯一定义**。
///
/// 名单内的交易程序正在运行、用户又坚持继续时，我们必须如实说清「得到的是什么」：
/// 阻断是**前向**的，已经建立的连接不会被切断。界面确认框的 `Note` 与
/// [`install_explicit`] / [`sync_explicit`] 的拒绝文案都复用它——同一句话写两遍，
/// 迟早会有一处说岔，而这里说错就是「假安全承诺」。
pub const RUNNING_ACK_NOTE: &str = "已建立的连接不会被切断，只有新连接会被阻止。";

/// 开机标识的比较容差（秒）。
pub const BOOT_ID_TOLERANCE_SECS: f64 = 5.0;

/// 本版是否提供该能力（非 Windows / 32 位 → `false`，界面不出三态卡）。
pub fn platform_supported() -> bool {
    wfp_win::PLATFORM_SUPPORTED
}

/// 当前时刻（epoch 秒）。
pub fn now_epoch() -> f64 {
    wfp_win::now_epoch()
}

/// 当前单调毫秒（开机以来）。
pub fn tick_ms() -> u64 {
    wfp_win::tick_ms()
}

/// 本次开机的标识。
pub fn boot_id() -> String {
    wfp_win::boot_id()
}

/// 两个开机标识是否指向同一次开机（带容差）。
pub fn same_boot(a: &str, b: &str) -> bool {
    state::same_boot_id(a, b)
}

// ---------------------------------------------------------------------------
// 名单
// ---------------------------------------------------------------------------

/// 名单的**唯一口径**：`split.processes` 里 `target == Trade` 的条目。
pub fn trade_program_entries(cfg: &crate::config::AppConfig) -> Vec<(String, Option<String>)> {
    cfg.split
        .processes
        .iter()
        .filter(|e| e.target() == crate::config::SplitTarget::Trade)
        .map(|e| (e.value().to_string(), e.path().map(|p| p.to_string())))
        .collect()
}

/// 名单的完整身份（含 appId）。安装/同步/写证据时用。
pub fn trade_identities(cfg: &crate::config::AppConfig) -> ResolveOutcome {
    let raw = trade_program_entries(cfg);
    let refs: Vec<EntryRef<'_>> =
        raw.iter().map(|(name, path)| EntryRef::new(name, path.as_deref())).collect();
    let env = wfp_win::SystemIdentityEnv::new();
    identity::resolve_all(&refs, &env)
}

/// 名单的轻量身份（不算 appId，不碰 BFE）。状态刷新用。
pub fn trade_entries_light(cfg: &crate::config::AppConfig) -> ResolveOutcomeLight {
    let raw = trade_program_entries(cfg);
    let refs: Vec<EntryRef<'_>> =
        raw.iter().map(|(name, path)| EntryRef::new(name, path.as_deref())).collect();
    let env = wfp_win::SystemIdentityEnv::new();
    identity::resolve_all_light(&refs, &env)
}

// ---------------------------------------------------------------------------
// 失效登记与进程内缓存
// ---------------------------------------------------------------------------

/// 强制失效事件（PRD §4.1.1 那张表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidReason {
    Connect,
    Disconnect,
    ListChanged,
    ExplicitVerify,
    Upgrade,
    LegacyConflictChanged,
    /// 用户显式解除（同时会写 `UserRemoved` 标记）。
    UserRemove,
}

impl InvalidReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            InvalidReason::Connect => "connect",
            InvalidReason::Disconnect => "disconnect",
            InvalidReason::ListChanged => "list-changed",
            InvalidReason::ExplicitVerify => "explicit-verify",
            InvalidReason::Upgrade => "upgrade",
            InvalidReason::LegacyConflictChanged => "legacy-conflict-changed",
            InvalidReason::UserRemove => "user-remove",
        }
    }
}

/// 进程内状态缓存（**不是**证据）：只放「这次会话里发生了什么」。
///
/// 它**不缓存证据内容**：证据一律从 store 现读，避免「缓存冻结时龄」这类错误。
#[derive(Debug, Default)]
pub struct GuardCache {
    inner: Mutex<CacheInner>,
}

#[derive(Debug, Default)]
struct CacheInner {
    verify_pending: Option<VerifyPending>,
    declined_at: Option<f64>,
    record_version: u64,
    last_invalid: Option<String>,
}

impl GuardCache {
    pub fn new() -> GuardCache {
        GuardCache::default()
    }

    /// 登记一次强制失效：把「待核验」置上（具体结果等重试回来再写）。
    pub fn mark_invalidated(&self, why: InvalidReason) {
        let mut g = self.lock();
        g.verify_pending = Some(VerifyPending::Unknown);
        g.last_invalid = Some(why.as_str().to_string());
    }

    pub fn set_verify_pending(&self, pending: VerifyPending) {
        self.lock().verify_pending = Some(pending);
    }

    pub fn clear_verify_pending(&self) {
        self.lock().verify_pending = None;
    }

    pub fn verify_pending(&self) -> VerifyPending {
        self.lock().verify_pending.unwrap_or(VerifyPending::None)
    }

    /// 记一次「用户拒绝了提权」（抑制窗起点）。
    pub fn note_declined(&self, now: f64) {
        let mut g = self.lock();
        g.declined_at = Some(now);
        g.verify_pending = Some(VerifyPending::Declined);
    }

    /// 现在该不该弹 UAC？
    ///
    /// - `explicit=true`（用户主动点「重新核验/解除」）→ 总是允许，绕过抑制窗；
    /// - 否则：最近 `GUARD_PROMPT_SUPPRESS_SECS` 内拒绝过 → 不弹（避免 UAC 风暴）。
    pub fn should_prompt(&self, explicit: bool, now: f64) -> bool {
        if explicit {
            return true;
        }
        match self.lock().declined_at {
            Some(t) => (now - t) > GUARD_PROMPT_SUPPRESS_SECS as f64,
            None => true,
        }
    }

    /// 分配一个写入版本号（递增）。
    pub fn next_record_version(&self) -> u64 {
        let mut g = self.lock();
        g.record_version += 1;
        g.record_version
    }

    pub fn record_version(&self) -> u64 {
        self.lock().record_version
    }

    pub fn last_invalid(&self) -> Option<String> {
        self.lock().last_invalid.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        // 缓存里没有「必须一致」的不变量：中毒后继续用比 panic 好（否则一次 panic 会
        // 让整个 UI 永久拿不到状态）。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 生成一次性 nonce（父进程与子进程用它确认「刚写的这条真的写进去了」）。
///
/// 不引随机库：pid + 单调毫秒 + 计数器足够区分「本次这一条」。
/// 它**不是**安全凭据（我们不做密码学防伪，见 evidence.rs 头注释）。
pub fn new_nonce(cache: &GuardCache) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:08x}{:08x}{:04x}",
        std::process::id(),
        (tick_ms() & 0xffff_ffff) as u32,
        ((seq ^ cache.record_version()) & 0xffff) as u16
    )
}

// ---------------------------------------------------------------------------
// 依赖注入：真实现 / 测试假实现
// ---------------------------------------------------------------------------

/// WFP 后端。生产实现是 `wfp_win::WindowsWfp`；测试注入假实现（不碰 WFP）。
pub trait GuardBackend {
    /// 本后端在这台机器上能不能用（非 Windows → false）。
    fn available(&self) -> bool;
    /// 只读核验（**已提权上下文**调用）。
    fn read(&self, ids: &[ProgramIdentity], expect: &Expect) -> Result<GuardEvidence, WfpError>;
    /// 安装/补齐（幂等：已存在的合格规则不重复建）。
    fn install(&self, ids: &[ProgramIdentity], expect: &Expect) -> Result<GuardEvidence, WfpError>;
    /// 名单变更后的整笔同步（一个事务内全量替换）。
    fn sync(&self, ids: &[ProgramIdentity], expect: &Expect) -> Result<GuardEvidence, WfpError>;
    /// 解除（只删自有对象，顺序 filter → subLayer → provider，然后回读）。
    fn remove(&self) -> Result<GuardEvidence, WfpError>;
}

/// 期望值（父进程与子进程必须算得一模一样，否则读回没有意义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    pub boot_id: String,
    pub config_digest: String,
    pub store_kind: StoreKind,
    pub legacy_running: bool,
}

/// 注入点：把「提权 / 宿主时间 / 旧版探测 / 运行中进程」都变成可替换的，
/// 这样编排逻辑可以在**普通权限、无 UAC、无 WFP** 的环境里被完整测试。
pub struct GuardHooks {
    pub elevated: Box<dyn Fn() -> bool + Send + Sync>,
    pub request: Box<dyn Fn(&GuardRequest) -> Result<GuardReply, ElevateError> + Send + Sync>,
    pub legacy_running: Box<dyn Fn() -> bool + Send + Sync>,
    pub now: Box<dyn Fn() -> f64 + Send + Sync>,
    pub tick_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    pub running_programs: Box<dyn Fn(&[ProgramIdentity]) -> Vec<String> + Send + Sync>,
}

impl GuardHooks {
    /// 生产实现：真提权子进程 + 真探测。
    pub fn production() -> GuardHooks {
        GuardHooks {
            elevated: Box::new(crate::probe::elevated),
            request: Box::new(|req| elevate::apply(req)),
            legacy_running: Box::new(crate::isolation::legacy_running),
            now: Box::new(now_epoch),
            tick_ms: Box::new(tick_ms),
            running_programs: Box::new(|ids| wfp_win::running_programs(ids)),
        }
    }

    /// 测试实现：什么都不会真的弹 UAC / 碰 WFP。
    pub fn inert() -> GuardHooks {
        GuardHooks {
            elevated: Box::new(|| false),
            request: Box::new(|_| Err(ElevateError::Declined)),
            legacy_running: Box::new(|| false),
            now: Box::new(|| 1_700_000_000.0),
            tick_ms: Box::new(|| 5_000_000),
            running_programs: Box::new(|_| Vec::new()),
        }
    }

    pub fn now(&self) -> f64 {
        (self.now)()
    }

    pub fn tick(&self) -> u64 {
        (self.tick_ms)()
    }

    pub fn elevated(&self) -> bool {
        (self.elevated)()
    }

    pub fn legacy(&self) -> bool {
        (self.legacy_running)()
    }
}

/// 一次安装/同步的结局。**永不 `Err`**：连接不会因为 guard 失败而失败。
#[derive(Debug, Clone, PartialEq)]
pub enum GuardOutcome {
    /// 名单空：不建任何对象、不提权。
    NotApplicable { count: i64 },
    /// 装好了（`status` 来自同一次提权内的逐条读回）。
    Installed { status: GuardStatus, source: GuardSource },
    /// 已经是最新，没有写入。
    Unchanged { status: GuardStatus },
    /// 失败（连接继续，但必须可见）。
    Failed { status: GuardStatus, message: String },
}

impl GuardOutcome {
    /// 给 `did`/备注用的一句话（用户可见）。
    pub fn note(&self) -> String {
        match self {
            GuardOutcome::NotApplicable { .. } => "没有需要保护的交易程序，未启用交易保护".to_string(),
            GuardOutcome::Installed { .. } => {
                "交易程序直连保护已启用（断开通道后仍保留）".to_string()
            }
            GuardOutcome::Unchanged { .. } => "交易程序直连保护已是最新".to_string(),
            GuardOutcome::Failed { message, .. } => message.clone(),
        }
    }

    pub fn status(&self) -> Option<&GuardStatus> {
        match self {
            GuardOutcome::NotApplicable { .. } => None,
            GuardOutcome::Installed { status, .. }
            | GuardOutcome::Unchanged { status }
            | GuardOutcome::Failed { status, .. } => Some(status),
        }
    }

    /// 这次到底有没有装成（`TradingDirectAccessBlocked` 的真实值）。
    pub fn blocked(&self) -> bool {
        matches!(self, GuardOutcome::Installed { .. } | GuardOutcome::Unchanged { .. })
    }
}

// ---------------------------------------------------------------------------
// 状态投影
// ---------------------------------------------------------------------------

/// 读一次证据并判定。**只消费证据，不产生证据**。
pub fn status_with(
    cfg: Option<&crate::config::AppConfig>,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> GuardStatus {
    let Some(cfg) = cfg else {
        // 配置读不出来：不能说「尚未添加」（那是把「读不到」说成「没有」）
        return GuardStatus::unknown(GuardReason::ReadError, -1);
    };
    let raw = trade_program_entries(cfg);
    // Listed 是界面上的进程名单总数（含 direct/daily/unresolved）；Count 只算实际参与保护者。
    let listed_total = cfg.split.processes.len() as i64;
    if !platform_supported() {
        let mut st = GuardStatus::unsupported();
        st.trade_program_count = raw.len() as i64;
        st.trade_program_listed = listed_total;
        return st;
    }

    let light = trade_entries_light(cfg);
    let removed = store.read_removed().is_some();
    let digest = config_digest_light(&light.entries, &light.unresolved, removed);

    // L 路径（默认关闭）：本版恒无。
    let live: Option<GuardEvidence> = None;

    let (mut ev, trusted, record_err) = match live {
        Some(ev) => (ev, true, None),
        None => match store.read() {
            Ok(rec) => {
                if rec.is_user_removed() {
                    // 标记记录（Q8）：没有证据，但用户是主动解除的。
                    (GuardEvidence::default(), store.trusted(), None)
                } else {
                    (rec.to_evidence(), store.trusted(), None)
                }
            }
            Err(e) => (GuardEvidence::default(), store.trusted(), Some(e)),
        },
    };
    // 读失败也要进判定：没权限是真的「读不到」，其余表现为「没有可用证据」。
    if let Some(RecordError::AccessDenied) = record_err {
        ev.read_error = Some(WfpError::AccessDenied);
    }

    let legacy_running = hooks.legacy();
    // 冲突态变化 = 强制失效事件（PRD §4.1.1）：用一个对不上的摘要落到 ConfigChanged。
    let digest = if ev.source.is_some() && ev.legacy_running_at_verify != legacy_running {
        format!("{digest}-legacy-changed")
    } else {
        digest
    };

    let ctx = EvalContext {
        current_boot_id: boot_id(),
        current_config_digest: digest,
        verify_pending: cache.verify_pending(),
        evidence_trusted: trusted,
        unsupported: false,
        store_kind: store.kind().as_str().to_string(),
        clock: Box::new(wfp_win::SystemClock::new()),
    };
    let input = EvaluationInput {
        evidence: &ev,
        entries: &light.entries,
        unresolved: &light.unresolved,
        trade_program_count: light.entries.len() as i64,
        trade_program_listed: listed_total,
        legacy_conflict: legacy_running,
        user_removed: removed,
        ctx: &ctx,
    };
    evaluate(&input)
}

// ---------------------------------------------------------------------------
// 面向 IPC / CLI 的便捷入口（生产 hooks + 生产 store 的唯一装配处）
// ---------------------------------------------------------------------------

/// 一次 guard 动作需要的外部装配：**存储 + 缓存 + 提权/时间注入点**。
///
/// 调用方（`connect` / `ipc` / `main`）只搬这一个结构，测试也只注这一个——
/// 这样「连接流程在写还原凭据之前就调了保护」这条契约可以在没有 UAC、没有 WFP 的
/// 环境里被完整验证。
pub struct GuardContext<'a> {
    pub store: &'a dyn EvidenceStore,
    pub cache: &'a GuardCache,
    pub hooks: &'a GuardHooks,
}

impl<'a> GuardContext<'a> {
    /// 临时拼一个上下文（测试里最常用）。
    pub fn new(store: &'a dyn EvidenceStore, cache: &'a GuardCache, hooks: &'a GuardHooks) -> Self {
        GuardContext { store, cache, hooks }
    }
}

/// 生产上下文的**持有者**：把 `Box<dyn EvidenceStore>` 与 `GuardHooks` 放在一起，
/// 让调用方能用 `&ProductionGuard` 活过整条事务。
pub struct ProductionGuard {
    pub store: Box<dyn EvidenceStore>,
    pub hooks: GuardHooks,
}

impl ProductionGuard {
    /// 按数据根装配（有 `SPIDERVPN_ROOT` → 隔离文件；否则生产注册表）。
    pub fn new(root: &Path, legacy_running: bool) -> Option<ProductionGuard> {
        let store = evidence::select(root).ok()?;
        Some(ProductionGuard { store, hooks: production_hooks(legacy_running) })
    }

    pub fn context(&self) -> GuardContext<'_> {
        GuardContext { store: self.store.as_ref(), cache: cache(), hooks: &self.hooks }
    }
}

/// 进程内缓存单例。
///
/// 提权抑制窗必须**跨命令**生效（一次拒绝之后 600 秒内不再弹第二次），所以它不能是
/// 每次调用新建的局部变量。放在这里而不是调用方：调用方（ipc/main/connect）不该知道
/// 缓存的形状。
pub fn cache() -> &'static GuardCache {
    use std::sync::OnceLock;
    static CACHE: OnceLock<GuardCache> = OnceLock::new();
    CACHE.get_or_init(GuardCache::new)
}

/// 按数据根选 store（生产注册表 / 隔离文件）。**唯一选择点在 `evidence::select`**。
///
/// 返回 `None` 表示「这个根算不出合法路径」，调用方必须当作「读不到证据」而不是
/// 换成别的 store——兜底的后果是测试或隔离环境摸到生产 HKLM。
pub fn store_for(root: &Path) -> Option<Box<dyn EvidenceStore>> {
    evidence::select(root).ok()
}

/// 测试/夹具用的根路径便捷写入口。生产写入仍只能走提权子进程的 `EvidenceStore::write`。
pub fn write_evidence_record(root: &Path, rec: &GuardRecord) -> Result<(), String> {
    let store = store_for(root).ok_or_else(|| "无法确定证据存储位置".to_string())?;
    store.write(rec)
}

/// 测试/夹具用的根路径便捷读入口。
pub fn read_evidence_record(root: &Path) -> Result<GuardRecord, RecordError> {
    let store = store_for(root).ok_or_else(|| RecordError::Io("无法确定证据存储位置".into()))?;
    store.read()
}

/// 生产 hooks 的工厂（把 `legacy_running` 固定成调用方看到的那一份）。
fn production_hooks(legacy_running: bool) -> GuardHooks {
    let mut hooks = GuardHooks::production();
    hooks.legacy_running = Box::new(move || legacy_running);
    hooks
}

/// 读状态（**不写任何东西**）：`ipc::status_json`、CLI `--guard-status` 都用它。
pub fn status(
    cfg: Option<&crate::config::AppConfig>,
    root: &Path,
    legacy_running: bool,
) -> GuardStatus {
    let listed = cfg.map(|c| c.split.processes.len() as i64).unwrap_or(-1);
    let participating =
        cfg.map(|c| trade_entries_light(c).entries.len() as i64).unwrap_or(-1);
    let Some(store) = store_for(root) else {
        let mut st = GuardStatus::unknown(GuardReason::ReadError, participating);
        st.trade_program_listed = listed;
        return st;
    };
    let hooks = production_hooks(legacy_running);
    attach_perspective(status_with(cfg, store.as_ref(), cache(), &hooks), crate::probe::elevated())
}

/// 把「提权视角说明」挂到投影上。**只写展示字段**，不动三态与 `summary`。
///
/// 单独抽成函数是为了能被单测钉住：`status()` 依赖当前进程是否提权（测试机通常是提权会话），
/// 而纯函数 `state::perspective_note` 又只覆盖了「该不该有这句话」。真正容易写错的是
/// **「有没有把它赋值上去」**——这一步没有测试就会静默失效，CLI 与界面都少一句话。
fn attach_perspective(mut st: GuardStatus, elevated: bool) -> GuardStatus {
    st.perspective_note = state::perspective_note(&st.store_kind, elevated, st.reason);
    st
}

/// 作废当前证据（强制失效事件）。返回「是否真的动过存储」。
///
/// 只在**名单真的变了**时调用：顺序抖动不该让卡片翻成「待核验」。
pub fn invalidate_evidence(root: &Path, reason: &str) -> bool {
    let Some(store) = store_for(root) else {
        return false;
    };
    store.invalidate(reason).is_ok()
}

/// 连前预检（`guard-precheck`，`Sync`，**不弹 UAC、不写任何东西**）。
///
/// 给界面在「连接」按钮前用：会弹 UAC 吗？有没有交易程序还在跑（P0-13）？
pub fn precheck(
    cfg: Option<&crate::config::AppConfig>,
    root: &Path,
    legacy_running: bool,
) -> serde_json::Value {
    let listed = cfg.map(|c| c.split.processes.len() as i64).unwrap_or(-1);
    let count = cfg.map(|c| trade_entries_light(c).entries.len() as i64).unwrap_or(-1);
    let st = status(cfg, root, legacy_running);
    let running = match cfg {
        Some(c) => {
            let resolved = trade_identities(c);
            wfp_win::running_programs(&resolved.programs)
        }
        None => Vec::new(),
    };
    let elevated = crate::probe::elevated();
    let will_prompt = count > 0 && !elevated && cache().should_prompt(false, now_epoch());
    serde_json::json!({
        "ok": true,
        "TradeProgramCount": count,
        "TradeProgramListed": listed,
        "Elevated": elevated,
        "WillPrompt": will_prompt,
        "Suppressed": !cache().should_prompt(false, now_epoch()) && count > 0 && !elevated,
        "LegacyRunning": legacy_running,
        "RunningPrograms": running,
        "PlatformSupported": platform_supported(),
        "Guard": st.state.as_str(),
        "GuardSummary": st.summary,
        "GuardVerifyPending": st.verify_pending.as_str(),
    })
}

/// P0-13 的共享闸门：名单里的交易程序正在跑、用户又没有明确确认时，拒绝显式写动作。
///
/// **放在本模块而不是 ipc 层**是硬要求：命令行（`--guard-install` / `--guard-sync`）与
/// 界面（`guardEnable` 确认框）必须共用同一份判据，否则两处口径一漂，就有一条路能绕过提示。
///
/// 这个判断**只读**：不弹 UAC（不碰 `hooks.request`）、不写证据、不改配置、不动缓存。
/// 所以它可以、也必须排在证据存储之前——拒绝时连存储都不建立。
fn reject_running_unacknowledged(
    cfg: &crate::config::AppConfig,
    hooks: &GuardHooks,
    acknowledge_running: bool,
) -> Result<(), String> {
    if acknowledge_running {
        // 用户已经看过提示（提示里带着 [`RUNNING_ACK_NOTE`]）并坚持继续：如实照做。
        return Ok(());
    }
    if trade_program_entries(cfg).is_empty() {
        // 名单空：没有对象要保护，谈不上「先退出」。
        return Ok(());
    }
    let resolved = trade_identities(cfg);
    let running = (hooks.running_programs)(&resolved.programs);
    if running.is_empty() {
        return Ok(());
    }
    Err(format!(
        "请先退出交易软件再启用交易保护（正在运行：{}）。{RUNNING_ACK_NOTE}\
         确实仍要启用时，请在界面里确认；命令行可加 --acknowledge-running。",
        running.join("、")
    ))
}

/// `--guard-install` / `guard-install`：显式安装（`explicit=true` 绕过抑制窗）。
///
/// `acknowledge_running` 是「用户在 P0-13 提示里选了『仍要启用』」这一事实；
/// 为 `false` 时，名单程序还在跑就直接拒绝（见 [`reject_running_unacknowledged`]）。
pub fn install_explicit(
    cfg: &crate::config::AppConfig,
    root: &Path,
    legacy_running: bool,
    acknowledge_running: bool,
) -> Result<GuardStatus, String> {
    explicit_install(GuardAction::Install, cfg, root, legacy_running, acknowledge_running)
}

/// `--guard-sync` / `guard-sync`：显式整笔同步。闸门与安装完全同一份。
pub fn sync_explicit(
    cfg: &crate::config::AppConfig,
    root: &Path,
    legacy_running: bool,
    acknowledge_running: bool,
) -> Result<GuardStatus, String> {
    explicit_install(GuardAction::Sync, cfg, root, legacy_running, acknowledge_running)
}

/// install / sync 的共用生产入口：闸门 → 证据存储 → 原来的安装路径。
///
/// 闸门排在 [`store_for`] **之前**：被拒绝时一步副作用都不许有，
/// 而且「程序在跑」这句话必须比「条目解析不出来」先说出来。
fn explicit_install(
    action: GuardAction,
    cfg: &crate::config::AppConfig,
    root: &Path,
    legacy_running: bool,
    acknowledge_running: bool,
) -> Result<GuardStatus, String> {
    let hooks = production_hooks(legacy_running);
    reject_running_unacknowledged(cfg, &hooks, acknowledge_running)?;
    let store = store_for(root).ok_or_else(|| "无法确定证据存储位置".to_string())?;
    install_like_explicit(action, cfg, store.as_ref(), cache(), &hooks)
}

/// install / sync 的**同一份实现**，注入点由调用方提供（单测走这里）。
///
/// 判据仍然只有 [`reject_running_unacknowledged`] 一处——这里绝不重写一份。
pub fn run_explicit_install(
    action: GuardAction,
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
    acknowledge_running: bool,
) -> Result<GuardStatus, String> {
    // 过了这一句才会走到提权：「拒绝早于任何副作用」就靠这一行的位置。
    reject_running_unacknowledged(cfg, hooks, acknowledge_running)?;
    install_like_explicit(action, cfg, store, cache, hooks)
}

/// 闸门**已通过**之后的安装/同步。私有：调用方必须先过 [`reject_running_unacknowledged`]，
/// 否则就绕过了 P0-13 的提示（那正是这条需求要防的事）。
fn install_like_explicit(
    action: GuardAction,
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> Result<GuardStatus, String> {
    let outcome = run_install_like(action, cfg, store, cache, hooks, true);
    outcome_to_result(outcome, cfg, store, cache, hooks)
}

/// `--guard-verify` / `guard-verify`：显式重新核验（用户点「重新核验」）。
pub fn verify_status(
    cfg: &crate::config::AppConfig,
    root: &Path,
    legacy_running: bool,
) -> Result<GuardStatus, String> {
    let store = store_for(root).ok_or_else(|| "无法确定证据存储位置".to_string())?;
    let hooks = production_hooks(legacy_running);
    verify_explicit(cfg, store.as_ref(), cache(), &hooks)
}

/// `--guard-remove` / `guard-remove`：显式解除。
pub fn remove_status(
    cfg: &crate::config::AppConfig,
    root: &Path,
    legacy_running: bool,
) -> Result<GuardStatus, String> {
    let store = store_for(root).ok_or_else(|| "无法确定证据存储位置".to_string())?;
    let hooks = production_hooks(legacy_running);
    remove_explicit(cfg, store.as_ref(), cache(), &hooks)
}

fn outcome_to_result(
    outcome: GuardOutcome,
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> Result<GuardStatus, String> {
    match outcome {
        GuardOutcome::Installed { status, .. } | GuardOutcome::Unchanged { status } => Ok(status),
        GuardOutcome::NotApplicable { .. } => Ok(status_with(Some(cfg), store, cache, hooks)),
        GuardOutcome::Failed { message, .. } => Err(message),
    }
}

// ---------------------------------------------------------------------------
// 提权编排
// ---------------------------------------------------------------------------

fn build_request(
    action: GuardAction,
    ids: &[ProgramIdentity],
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
    explicit: bool,
) -> GuardRequest {
    let light = trade_entries_light(cfg);
    let removed = store.read_removed().is_some();
    GuardRequest {
        action,
        programs: ids.to_vec(),
        explicit,
        config_digest: state::config_digest(ids, &light.unresolved, removed),
        nonce: new_nonce(cache),
        boot_id: boot_id(),
        store_kind: store.kind().as_str().to_string(),
        legacy_running: hooks.legacy(),
        record_version: cache.next_record_version(),
    }
}

/// 拿一次互斥：一次只允许一个交易保护动作。
fn with_guard_mutex<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let name = format!("{}{}", GUARD_MUTEX_PREFIX, wfp::PROVIDER_KEY.replace('-', "").to_uppercase());
    let _guard = wfp_win::NamedMutex::acquire(&name)?;
    Ok(f())
}

/// 连接前的 0.7 步：安装/补齐持久阻断。**永不阻断连接**。
///
/// 顺序要求（PRD §5.6 / 架构 §5.1）：必须在「写还原凭据 / 改系统代理 / 起引擎」之前。
pub fn ensure_before_connect(
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> GuardOutcome {
    cache.mark_invalidated(InvalidReason::Connect);
    if trade_program_entries(cfg).is_empty() {
        // 名单空：不建对象、不提权，也不该让用户看到「失败」。
        cache.clear_verify_pending();
        return GuardOutcome::NotApplicable { count: 0 };
    }
    if hooks.legacy() {
        // 旧版在跑：不碰任何 WFP 对象，连接继续。
        let st = status_with(Some(cfg), store, cache, hooks);
        return GuardOutcome::Failed {
            status: st,
            message: "检测到旧版客户端正在运行：本次未启用交易保护（两个程序不能同时接管）"
                .to_string(),
        };
    }
    run_install_like(GuardAction::Install, cfg, store, cache, hooks, false)
}

/// 名单变更后的整笔同步（一个事务内全量替换）。
pub fn sync_after_list_change(
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> GuardOutcome {
    cache.mark_invalidated(InvalidReason::ListChanged);
    if trade_program_entries(cfg).is_empty() {
        cache.clear_verify_pending();
        return GuardOutcome::NotApplicable { count: 0 };
    }
    run_install_like(GuardAction::Sync, cfg, store, cache, hooks, false)
}

fn run_install_like(
    action: GuardAction,
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
    explicit: bool,
) -> GuardOutcome {
    let resolved = trade_identities(cfg);
    let now = hooks.now();
    if !hooks.elevated() && !cache.should_prompt(explicit, now) {
        // 抑制窗内：不弹 UAC，如实说「本次没重试」
        let st = status_with(Some(cfg), store, cache, hooks);
        return GuardOutcome::Failed {
            status: st,
            message: "本次未启用交易保护（最近拒绝过管理员确认，本次不再询问）".to_string(),
        };
    }
    if resolved.programs.is_empty() {
        let st = status_with(Some(cfg), store, cache, hooks);
        return GuardOutcome::Failed {
            status: st,
            message: "本次未启用交易保护：名单条目找不到可执行文件，请确认程序位置".to_string(),
        };
    }
    let req = build_request(action, &resolved.programs, cfg, store, cache, hooks, explicit);
    let attempt = with_guard_mutex(|| (hooks.request)(&req));
    let reply = match attempt {
        Err(msg) => return failed_with(cfg, store, cache, hooks, msg),
        Ok(Err(e)) => {
            if e.is_declined() {
                cache.note_declined(now);
            } else {
                cache.set_verify_pending(VerifyPending::Failed);
            }
            return failed_with(cfg, store, cache, hooks, e.message());
        }
        Ok(Ok(reply)) => reply,
    };
    // A19：reply 必须逐条覆盖「每个参与程序 × {IPv4,IPv6}」且 filterId != 0，
    // 否则视为 BadReply（不落证据、不产生 Protected）。
    let fresh = match validate_reply(&reply, &resolved.programs) {
        Ok(ev) => ev,
        Err(msg) => {
            cache.set_verify_pending(VerifyPending::Failed);
            return failed_with(cfg, store, cache, hooks, format!("本次未能记录核验结果：{msg}"));
        }
    };
    // 证据由**子进程**在提权会话内写；父进程这里只回读确认它真写了且 nonce 对得上。
    match store.read() {
        Ok(rec) if rec.nonce == req.nonce && !rec.is_user_removed() => {
            cache.clear_verify_pending();
            let st = status_with(Some(cfg), store, cache, hooks);
            if st.is_protected() {
                GuardOutcome::Installed { status: st, source: fresh.source }
            } else {
                GuardOutcome::Unchanged { status: st }
            }
        }
        Ok(_) => {
            cache.set_verify_pending(VerifyPending::Failed);
            failed_with(cfg, store, cache, hooks, "本次未能记录核验结果（回读的核验标识不一致）".to_string())
        }
        Err(e) => {
            cache.set_verify_pending(VerifyPending::Failed);
            failed_with(cfg, store, cache, hooks, format!("本次未能记录核验结果：{}", e.message()))
        }
    }
}

fn failed_with(
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
    message: String,
) -> GuardOutcome {
    let st = status_with(Some(cfg), store, cache, hooks);
    GuardOutcome::Failed { status: st, message }
}

/// 校验子进程回复（A19）：每个参与程序 × 两族都要有独立记录，且 `filterId != 0`。
///
/// **安装 API 的返回值不算证据**：缺任何一条就是 `BadReply`。
pub fn validate_reply(
    reply: &GuardReply,
    programs: &[ProgramIdentity],
) -> Result<GuardEvidence, String> {
    let ev = reply.result.clone().map_err(|e| format!("提权助手报告失败：{e}"))?;
    if programs.is_empty() {
        return Ok(ev);
    }
    if ev.source == GuardSource::None {
        return Err("回复没有来源标记".to_string());
    }
    for want in programs {
        let path = want.path.to_string_lossy();
        let got = ev.programs.iter().find(|p| p.path.eq_ignore_ascii_case(&path));
        let Some(got) = got else {
            return Err(format!("回复缺少程序「{}」的逐条记录", want.name));
        };
        for layer in [Layer::V4, Layer::V6] {
            if !got.slot_ok(layer) {
                return Err(format!(
                    "回复里「{}」的 {} 记录不完整（或 filterId 为 0）",
                    want.name,
                    layer.label()
                ));
            }
        }
    }
    Ok(ev)
}

/// 断开后的强制重新核验（PRD §4.2：断开是强制失效事件）。
///
/// **永不 `Err`**：拿不到新证据时把「本次未能重新核验」写进 `status.verify_pending`，
/// 旧证据按 §4.1.1 继续老化展示（A23：不得污染三态）。
pub fn reverify_after_disconnect(
    cfg: Option<&crate::config::AppConfig>,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> GuardStatus {
    cache.mark_invalidated(InvalidReason::Disconnect);
    let Some(cfg) = cfg else {
        return GuardStatus::unknown(GuardReason::ReadError, -1);
    };
    if trade_program_entries(cfg).is_empty() {
        // 名单空：没有对象可核验，不该为它弹 UAC。
        cache.clear_verify_pending();
        return status_with(Some(cfg), store, cache, hooks);
    }
    let now = hooks.now();
    if !hooks.elevated() && !cache.should_prompt(false, now) {
        // 抑制窗内：不弹第二次 UAC（「不制造 UAC 风暴」那条硬规则）
        cache.set_verify_pending(VerifyPending::Declined);
        return status_with(Some(cfg), store, cache, hooks);
    }
    let resolved = trade_identities(cfg);
    let req =
        build_request(GuardAction::Verify, &resolved.programs, cfg, store, cache, hooks, false);
    match with_guard_mutex(|| (hooks.request)(&req)) {
        Err(_) => cache.set_verify_pending(VerifyPending::Failed),
        Ok(Err(e)) => {
            if e.is_declined() {
                cache.note_declined(now);
            } else {
                cache.set_verify_pending(VerifyPending::Failed);
            }
        }
        Ok(Ok(_)) => cache.clear_verify_pending(),
    }
    status_with(Some(cfg), store, cache, hooks)
}

/// 显式解除（调用方已拿到二次确认）。`Err` 只会是「回读没通过 / 被拒绝 / 有程序在跑」。
pub fn remove_explicit(
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> Result<GuardStatus, String> {
    // A7：交易软件在运行就拒绝解除（规则被占用，删了也未必成功，用户还会以为已解除）
    let resolved = trade_identities(cfg);
    let running = (hooks.running_programs)(&resolved.programs);
    if !running.is_empty() {
        return Err(format!("请先退出交易软件再解除保护（正在运行：{}）", running.join("、")));
    }
    let req =
        build_request(GuardAction::Remove, &resolved.programs, cfg, store, cache, hooks, true);
    match with_guard_mutex(|| (hooks.request)(&req)) {
        Err(msg) => return Err(msg),
        Ok(Err(e)) => {
            // 拒绝/失败：解除**没有**发生，绝不能悄悄返回「已解除」。
            if e.is_declined() {
                cache.note_declined(hooks.now());
            } else {
                cache.set_verify_pending(VerifyPending::Failed);
            }
            return Err(e.message());
        }
        Ok(Ok(_)) => {}
    }
    cache.mark_invalidated(InvalidReason::UserRemove);
    // 回读：子进程已写 `Removed` 标记并删除 `Evidence` 值；若还能读到「provider 仍在」，
    // 就说明规则没删干净，不能说「已解除」。
    match store.read() {
        Ok(rec) if rec.provider_present => {
            Err("规则可能仍在，需要管理员确认后才能解除".to_string())
        }
        Ok(_) => {
            cache.clear_verify_pending();
            Ok(status_with(Some(cfg), store, cache, hooks))
        }
        // 读不到 = 也没有证据说 provider 还在；解除已由子进程回读确认
        Err(RecordError::Missing) => {
            cache.clear_verify_pending();
            Ok(status_with(Some(cfg), store, cache, hooks))
        }
        Err(e) => Err(format!("解除后回读失败：{}", e.message())),
    }
}

/// 显式重新核验（用户点「重新核验 / 运行诊断」）。`explicit=true` 绕过抑制窗。
pub fn verify_explicit(
    cfg: &crate::config::AppConfig,
    store: &dyn EvidenceStore,
    cache: &GuardCache,
    hooks: &GuardHooks,
) -> Result<GuardStatus, String> {
    cache.mark_invalidated(InvalidReason::ExplicitVerify);
    if trade_program_entries(cfg).is_empty() {
        cache.clear_verify_pending();
        return Ok(status_with(Some(cfg), store, cache, hooks));
    }
    let resolved = trade_identities(cfg);
    let req = build_request(GuardAction::Verify, &resolved.programs, cfg, store, cache, hooks, true);
    match with_guard_mutex(|| (hooks.request)(&req)) {
        Err(msg) => {
            cache.set_verify_pending(VerifyPending::Failed);
            return Err(msg);
        }
        Ok(Err(e)) => {
            if e.is_declined() {
                cache.note_declined(hooks.now());
            } else {
                cache.set_verify_pending(VerifyPending::Failed);
            }
            return Err(e.message());
        }
        Ok(Ok(_)) => cache.clear_verify_pending(),
    }
    Ok(status_with(Some(cfg), store, cache, hooks))
}

/// 当前名单里正在运行的程序（P0-13 前置提示用；非提权）。
pub fn running_programs(cfg: &crate::config::AppConfig, hooks: &GuardHooks) -> Vec<String> {
    let resolved = trade_identities(cfg);
    (hooks.running_programs)(&resolved.programs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, SplitConfig, SplitTarget};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-modv3-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn empty_cfg() -> AppConfig {
        crate::config::parse(r#"{"schema":2}"#).expect("最小配置必须能解析")
    }

    fn cfg_with(entries: &[(&str, Option<&str>)]) -> AppConfig {
        let mut cfg = empty_cfg();
        let mut split = SplitConfig::default();
        for (name, path) in entries {
            split.add_process_entry(name, SplitTarget::Trade, *path);
        }
        cfg.split = split;
        cfg
    }

    fn hooks_inert() -> GuardHooks {
        GuardHooks::inert()
    }

    /// 计数桩：`hooks.request` 每被调用一次就 +1，然后如实回报「用户拒绝」。
    ///
    /// 用它来钉死「拒绝早于副作用」——被闸门挡住时这个计数必须是 0，
    /// 也就是一次 UAC 都没弹。`running_programs` 由各用例自行覆盖。
    fn counting_request_hooks(calls: Arc<AtomicUsize>) -> GuardHooks {
        let mut hooks = hooks_inert();
        hooks.request = Box::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(ElevateError::Declined)
        });
        hooks
    }

    #[test]
    fn an_empty_list_never_prompts_and_never_fails() {
        let dir = tmp("empty");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let hooks = hooks_inert();
        let out = ensure_before_connect(&empty_cfg(), &store, &cache, &hooks);
        assert_eq!(out, GuardOutcome::NotApplicable { count: 0 });
        assert!(!out.blocked());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unresolved_entry_fails_visibly_without_prompting() {
        let dir = tmp("declined");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let hooks = hooks_inert();
        let cfg = cfg_with(&[("absent.exe", None)]);
        let out = ensure_before_connect(&cfg, &store, &cache, &hooks);
        match &out {
            GuardOutcome::Failed { message, .. } => {
                assert!(message.contains("未启用交易保护"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!out.blocked());
        // 抑制窗：拒绝后 600 秒内不再允许非显式提权；显式请求必须能绕过
        cache.note_declined(1_700_000_000.0);
        assert!(!cache.should_prompt(false, 1_700_000_010.0));
        assert!(cache.should_prompt(true, 1_700_000_010.0));
        assert!(cache.should_prompt(false, 1_700_000_000.0 + 601.0));
        assert_eq!(cache.verify_pending(), VerifyPending::Declined);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_conflict_does_not_touch_wfp_but_still_connects() {
        let dir = tmp("legacy");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let mut hooks = hooks_inert();
        hooks.legacy_running = Box::new(|| true);
        hooks.request = Box::new(|_| panic!("旧版在跑时绝不许发起提权"));
        let cfg = cfg_with(&[("a.exe", None)]);
        let out = ensure_before_connect(&cfg, &store, &cache, &hooks);
        assert!(!out.blocked());
        match &out {
            GuardOutcome::Failed { message, status } => {
                assert!(message.contains("旧版"), "{message}");
                assert_eq!(status.state, GuardState::Unknown);
                assert_eq!(status.reason, GuardReason::LegacyConflict);
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reply_without_per_program_records_is_a_bad_reply() {
        // A19 反向：只带「成功」不带逐条枚举 → BadReply，不能当证据。
        let want = ProgramIdentity {
            name: "t.exe".into(),
            path: "C:\\app\\t.exe".into(),
            app_id: vec![1, 0],
            device_path: "\\device\\t.exe".into(),
        };
        let bare = GuardEvidence {
            source: GuardSource::ElevatedInstallReadback,
            ..Default::default()
        };
        let err = validate_reply(
            &GuardReply { result: Ok(bare), notes: Vec::new() },
            std::slice::from_ref(&want),
        )
        .unwrap_err();
        assert!(err.contains("缺少程序"), "{err}");

        let good = FilterSlot {
            present: true,
            recognized: true,
            persistent: true,
            disabled: false,
            filter_id: Some(5),
        };
        let ev = GuardEvidence {
            source: GuardSource::ElevatedInstallReadback,
            programs: vec![ProgramEvidence {
                name: "t.exe".into(),
                path: "C:\\app\\t.exe".into(),
                app_id: vec![1, 0],
                ipv4: good,
                ipv6: good,
            }],
            ..Default::default()
        };
        assert!(validate_reply(
            &GuardReply { result: Ok(ev), notes: Vec::new() },
            std::slice::from_ref(&want)
        )
        .is_ok());

        // filterId == 0 也不行（BFE 没分配 id）
        let ev = GuardEvidence {
            source: GuardSource::ElevatedInstallReadback,
            programs: vec![ProgramEvidence {
                name: "t.exe".into(),
                path: "C:\\app\\t.exe".into(),
                app_id: vec![1, 0],
                ipv4: FilterSlot { filter_id: Some(0), ..good },
                ipv6: good,
            }],
            ..Default::default()
        };
        assert!(validate_reply(
            &GuardReply { result: Ok(ev), notes: Vec::new() },
            std::slice::from_ref(&want)
        )
        .is_err());
    }

    #[test]
    fn remove_refuses_while_a_trade_program_is_running() {
        let dir = tmp("remove-run");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let mut hooks = hooks_inert();
        hooks.running_programs = Box::new(|_| vec!["t.exe".to_string()]);
        hooks.request = Box::new(|_| panic!("有程序在跑时不许发起解除"));
        let cfg = cfg_with(&[("t.exe", None)]);
        let err = remove_explicit(&cfg, &store, &cache, &hooks).unwrap_err();
        assert!(err.contains("请先退出交易软件"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0-13 的**启用侧**闸门（安装）：程序在跑 + 未确认 → 拒绝，且**一次提权请求都不许发**。
    ///
    /// 「早于任何副作用」不是形容词：这里同时钉死 `hooks.request` 调用次数为 0，
    /// 缓存也没被动过（`record_version` / `verify_pending` 都是原值）。
    #[test]
    fn install_refuses_while_a_trade_program_runs_and_requests_nothing() {
        let dir = tmp("install-run");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = counting_request_hooks(calls.clone());
        hooks.running_programs = Box::new(|_| vec!["t.exe".to_string(), "b.exe".to_string()]);
        // 名单条目故意不给路径：闸门必须**先于**「条目解析不出来」那条分支生效，
        // 否则用户会看到一句与「程序在跑」无关的话术。
        let cfg = cfg_with(&[("t.exe", None), ("b.exe", None)]);

        let err = run_explicit_install(GuardAction::Install, &cfg, &store, &cache, &hooks, false)
            .unwrap_err();

        assert!(err.contains("t.exe") && err.contains("b.exe"), "要列出在跑的程序名：{err}");
        assert!(err.contains("请先退出"), "{err}");
        assert!(err.contains(RUNNING_ACK_NOTE), "必须如实说明只阻断新连接：{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "拒绝必须早于提权请求");
        assert_eq!(cache.record_version(), 0, "拒绝不许递增缓存里的版本号");
        assert_eq!(cache.verify_pending(), VerifyPending::None, "拒绝不许写「待核验」");
        assert!(!dir.join("guard").join("evidence.json").exists(), "拒绝不许写证据");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 已确认（用户点过「仍要启用」）→ 照原路径继续：提权请求**确实**被发出一次。
    #[test]
    fn install_continues_when_the_running_programs_are_acknowledged() {
        let dir = tmp("install-ack");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = counting_request_hooks(calls.clone());
        hooks.running_programs = Box::new(|_| vec!["t.exe".to_string()]);
        // 要走到提权那一步，名单条目必须**解析得出来**（用本测试程序自身）。
        let exe = std::env::current_exe().expect("测试程序自身的路径必须可读");
        let exe = exe.to_string_lossy().to_string();
        let cfg = cfg_with(&[("self.exe", Some(exe.as_str()))]);

        let err = run_explicit_install(GuardAction::Install, &cfg, &store, &cache, &hooks, true)
            .unwrap_err(); // 注入的 request 返回 Declined，所以最终仍是失败

        assert_eq!(calls.load(Ordering::SeqCst), 1, "确认后必须真的去请求提权：{err}");
        assert!(!err.contains("请先退出"), "确认过就不该再拿闸门拦一次：{err}");
        assert!(err.contains("未获得管理员确认"), "走到的是原来的提权路径：{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 没有程序在跑：闸门不参与判断，`acknowledge_running` 是真是假都一样放行。
    #[test]
    fn no_running_programs_never_blocks_the_install() {
        let dir = tmp("install-idle");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let exe = std::env::current_exe().expect("测试程序自身的路径必须可读");
        let exe = exe.to_string_lossy().to_string();
        let cfg = cfg_with(&[("self.exe", Some(exe.as_str()))]);

        for ack in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut hooks = counting_request_hooks(calls.clone());
            // 进程枚举结果为空：名单里没有正在跑的程序。
            hooks.running_programs = Box::new(|_| Vec::new());
            let err =
                run_explicit_install(GuardAction::Install, &cfg, &store, &cache, &hooks, ack)
                    .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 1, "没程序在跑就不许拦（ack={ack}）：{err}");
            assert!(!err.contains("请先退出"), "没程序在跑不该说「请先退出」（ack={ack}）：{err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 同步（`guard-sync`）与安装共用同一份闸门：在跑 + 未确认 → 拒绝，且不发提权。
    #[test]
    fn sync_refuses_while_a_trade_program_runs_and_requests_nothing() {
        let dir = tmp("sync-run");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = counting_request_hooks(calls.clone());
        hooks.running_programs = Box::new(|_| vec!["Trader.exe".to_string()]);
        let cfg = cfg_with(&[("Trader.exe", None)]);

        let err = run_explicit_install(GuardAction::Sync, &cfg, &store, &cache, &hooks, false)
            .unwrap_err();

        assert!(err.contains("Trader.exe"), "{err}");
        assert!(err.contains("请先退出"), "{err}");
        assert!(err.contains(RUNNING_ACK_NOTE), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "拒绝必须早于提权请求");
        assert_eq!(cache.record_version(), 0);

        // 已确认 → 走原路径（这一次真的请求提权）。
        let exe = std::env::current_exe().expect("测试程序自身的路径必须可读");
        let exe = exe.to_string_lossy().to_string();
        let cfg = cfg_with(&[("self.exe", Some(exe.as_str()))]);
        let calls2 = Arc::new(AtomicUsize::new(0));
        let mut hooks2 = counting_request_hooks(calls2.clone());
        hooks2.running_programs = Box::new(|_| vec!["Trader.exe".to_string()]);
        let _ = run_explicit_install(GuardAction::Sync, &cfg, &store, &cache, &hooks2, true)
            .unwrap_err();
        assert_eq!(calls2.load(Ordering::SeqCst), 1, "确认后同步必须继续");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_explicit_bypasses_the_suppression_window() {
        let dir = tmp("verify");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        cache.note_declined(1_700_000_000.0);
        let mut hooks = hooks_inert();
        hooks.request = Box::new(|_| Err(ElevateError::SpawnFailed("test".into())));
        let cfg = cfg_with(&[("a.exe", None)]);
        // 显式核验：即使刚拒绝过也会尝试（注入的是失败，但确实被调用了）
        let err = verify_explicit(&cfg, &store, &cache, &hooks).unwrap_err();
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reverify_after_disconnect_never_errors_and_keeps_pending() {
        let dir = tmp("reverify");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        cache.note_declined(1_700_000_000.0);
        let hooks = hooks_inert();
        let cfg = cfg_with(&[("a.exe", None)]);
        let st = reverify_after_disconnect(Some(&cfg), &store, &cache, &hooks);
        // 抑制窗内：不弹 UAC，标 Declined；三态不被污染
        assert_eq!(st.verify_pending, VerifyPending::Declined);
        assert!(!st.is_protected());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_reports_missing_store_as_not_verified() {
        let dir = tmp("status");
        let store = IsolatedFileStore::new(&dir).unwrap();
        let cache = GuardCache::new();
        let hooks = hooks_inert();
        let st = status_with(Some(&empty_cfg()), &store, &cache, &hooks);
        assert_eq!(st.trade_program_count, 0);
        assert!(!st.is_protected());
        assert_eq!(st.store_kind, "IsolatedFile");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R25-1 的**接线**测试：`state::perspective_note` 只管「该不该有这句话」，
    /// 这里钉死「`status()` 有没有真的把它挂到投影上」——漏了这一步，CLI 与界面
    /// 都会静默少一句话，而纯函数测试仍然全绿。
    #[test]
    fn status_attaches_perspective_note_for_the_elevated_registry_view() {
        let mut st = GuardStatus::unknown(GuardReason::EvidenceUnprotected, 1);
        st.store_kind = "Registry".to_string();
        let st = attach_perspective(st, true);
        assert_eq!(
            st.perspective_note.as_deref(),
            Some(state::PERSPECTIVE_NOTE_ELEVATED)
        );
        // 这句话只解释「视角」，不许动三态与标题（否则就是把安装成功说成失败）。
        assert_eq!(st.state, GuardState::Unknown);
        assert_eq!(st.reason, GuardReason::EvidenceUnprotected);
        assert_eq!(
            st.summary,
            state::summary_for(GuardState::Unknown, GuardReason::EvidenceUnprotected)
        );

        // 非提权：同一条记录本就该判「可信」，不需要也不允许拿这句话解释。
        let mut plain = GuardStatus::unknown(GuardReason::EvidenceUnprotected, 1);
        plain.store_kind = "Registry".to_string();
        assert_eq!(attach_perspective(plain, false).perspective_note, None);
    }

    /// 只能读到 `Err(AccessDenied)` 的存储：模拟「未提权会话去读 HKLM 证据」。
    ///
    /// 关键点：`trusted()` 故意返回 `true`。存储本身可信、但这一会话读不到——这正是
    /// 生产里 `RegistryStore` 在普通权限下的样子（`trusted = !writable_by_me = true`）。
    /// 用它来钉死「可信 ≠ 可乐观」：读不到就只能说「无法确认」。
    struct DeniedStore;

    impl EvidenceStore for DeniedStore {
        fn kind(&self) -> StoreKind {
            StoreKind::Registry
        }
        fn read(&self) -> Result<GuardRecord, RecordError> {
            Err(RecordError::AccessDenied)
        }
        fn write(&self, _rec: &GuardRecord) -> Result<(), String> {
            Err("模拟未提权：拒绝写入".to_string())
        }
        fn writable_by_me(&self) -> bool {
            false
        }
        fn trusted(&self) -> bool {
            true
        }
        fn read_removed(&self) -> Option<RemovedMarker> {
            None
        }
        fn write_removed(&self, _marker: &RemovedMarker) -> Result<(), String> {
            Err("模拟未提权：拒绝写入".to_string())
        }
        fn clear_removed(&self) -> Result<(), String> {
            Err("模拟未提权：拒绝写入".to_string())
        }
        fn invalidate(&self, _reason: &str) -> Result<(), String> {
            Err("模拟未提权：拒绝写入".to_string())
        }
    }

    /// A3：走**真实入口**（`store.read()` 返回 `Err(AccessDenied)`），不是手工塞
    /// `GuardEvidence::read_error`。`tests/guard_state.rs` 覆盖的是判定层那一段；
    /// 这里补的是它上游半步——`status_with` 有没有把「读不到」如实带进判定。
    #[test]
    fn store_access_denied_maps_to_no_permission() {
        let store = DeniedStore;
        let cache = GuardCache::new();
        let hooks = hooks_inert();
        // 名单里必须有一条**解析得出来**的交易程序（指向本测试程序自身，必然存在），
        // 否则会先落到「名单为空 / 条目未解析」那几条分支，走不到读失败那一步。
        let exe = std::env::current_exe().expect("测试程序自身的路径必须可读");
        let exe = exe.to_string_lossy().to_string();
        let cfg = cfg_with(&[("self.exe", Some(exe.as_str()))]);

        let st = status_with(Some(&cfg), &store, &cache, &hooks);

        assert_eq!(st.state, GuardState::Unknown, "读不到证据只能说「无法确认」，不许猜");
        assert_eq!(st.reason, GuardReason::NoPermission);
        assert_ne!(
            st.state,
            GuardState::Unprotected,
            "读失败不得被说成「用户已解除保护」——那是把「读不到」当成「没有」"
        );
        // `GuardEvidence::default()` 没有来源，所以「有可用记录就按记录判定」的例外
        // 不该被触发；这条断言把那个例外的前提条件钉住。
        assert_eq!(st.source, GuardSource::None, "读失败时手上没有可用记录");
        assert_eq!(st.store_kind, "Registry", "判定用的是本次所选存储的种类");
    }
}
