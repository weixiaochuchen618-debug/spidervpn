//! 部署运行的**纯逻辑层**：词表、状态机、以及后续的推进与投影。
//!
//! 这个模块**不做 IO、不发 SSH、不碰 `WebUi`**。它的全部输入是一条
//! [`RunRecord`](crate::deploystore::RunRecord) 和一个布尔（引擎里有没有这个 RunId 的
//! 活动 pass），输出是「新记录」「要不要执行」「能不能转后台」这类判断。
//!
//! 为什么硬要拆出这一层：状态机里最容易出现的事故不是崩溃，而是「代码顺手把
//! `NeedsAttention` 改成 `Running`」。把它做成纯函数 + 显式白名单（[`transition_ok`]），
//! 这种顺手就编不过 —— 非法流转只有一种走法，就是被拒绝并写错误。
//!
//! 词表本身（状态 / 原因类别 / 错误类别 / `NextAction` / 步骤名 / 步骤状态）的
//! **唯一定义在 [`crate::deploystore`]**：它们同时是记录形状的一部分。本模块只提供
//! `is_*_known()` 与状态机，不另抄一份字符串。
//!
//! ## 缺字段口径（贯穿全模块）
//!
//! 缺字段 = **未知**，不是 ok / false / 空 / 进行中。所以：
//!
//! - `state` 为空 → [`state_is_known`] 为假 → 界面显示「状态需要核对」，
//!   **不得**当成 `Running` 或 `Complete`；
//! - `next_action` 为空或表外 → 只给「查看任务」，不给任何写动作入口；
//! - `steps` 为空 → `N/4` 不显示，只显示「步骤未知」。
//!
//! `plan_pass` / `settle_step` / `decide_resume` / `humanize` 已由 T03 的引擎接上；
//! `project_tasks` / `project_deployments` / `run_view` 由 T05 的 IPC 命令接上；
//! `recover` 由 T04 的启动扫描接上（`deployengine::Engine::recover_all`）；
//! 快照接线（T06）也已完成。
//!
//! **不整体放行 `dead_code`**（r77 收窄）：会死的东西逐项处理——只被测试用到的
//! 加 `#[cfg(test)]`（它们不进 release 产物），领域里真实存在、但引擎暂时还没
//! 产生的那种加 `#[allow(dead_code)]` 并写清理由。模块级 `#![allow(dead_code)]`
//! 会让「新加了一个没人用的函数」永远不报警，等于把这项检查关掉。

use crate::deploystore::{
    AttemptRecord, Plan, Reason, RunRecord, StepRecord, Target, NEXT_ACTION_OPEN_FORM,
    NEXT_ACTION_RECONCILE, NEXT_ACTION_RETRY_STEP, STATE_CANCELLED,
    STATE_COMPLETE, STATE_DRAFT, STATE_NEEDS_ATTENTION, STATE_PAUSED, STATE_QUEUED, STATE_RUNNING,
    STATE_WAITING_USER, STATES, STEP_NAMES, STEP_STATUS_DONE,
    NEXT_ACTION_NONE, REASON_ACCESS_REQUIRED, REASON_FAILED, REASON_IDENTITY_CHANGED,
    REASON_INTERRUPTED, REASON_NEEDS_RECOVERY, REASON_OUTCOME_UNKNOWN, REASON_PARTIAL,
};
// 词表本身只给「表内值校验」用，而那些校验只被契约用例调用（见下方 `#[cfg(test)]`）。
// 单独一条 `use`：release 产物不会因为「导入了没人读的常量」而报警，
// 测试构建又照常拿得到它们。
#[cfg(test)]
use crate::deploystore::{
    ERROR_CLASSES, NEXT_ACTIONS, OUTCOMES, PENDING_KINDS, REASON_CATEGORIES, STEP_STATUSES,
    VERIFY_BYS,
};

/// 一次尝试不需要核对（没有发生过未决写）。
pub const RECONCILE_NOT_NEEDED: &str = "NotNeeded";
/// 这次尝试留下了未决写，需要核对。
pub const RECONCILE_NEEDED: &str = "Needed";
/// 未决写已经核对完。
pub const RECONCILE_DONE: &str = "Done";

/// 四个产品步骤的条数。`N/4` 的分母就是它，不要在两处各写一个 4。
pub const STEP_COUNT: usize = STEP_NAMES.len();

// ---------------------------------------------------------------------------
// 词表判定
// ---------------------------------------------------------------------------

/// 值在不在表里。空串一律算「不在」——空是「不知道」，不是某个合法值。
pub fn is_known(table: &[&'static str], value: &str) -> bool {
    !value.is_empty() && table.contains(&value)
}

/// 记录的 `State` 是不是表内值。表外/缺失 → 未知（不得当 `Running`/`Complete`）。
pub fn state_is_known(value: &str) -> bool {
    is_known(&STATES, value)
}

/// `Reason.Category` 是不是表内值。
#[cfg(test)]
pub fn reason_category_is_known(value: &str) -> bool {
    is_known(&REASON_CATEGORIES, value)
}

/// `Reason.Class` 是不是 IPC 那六类之一。
#[cfg(test)]
pub fn error_class_is_known(value: &str) -> bool {
    is_known(&ERROR_CLASSES, value)
}

/// `NextAction` 是不是表内值。表外 → 不给任何写动作入口。
#[cfg(test)]
pub fn next_action_is_known(value: &str) -> bool {
    is_known(&NEXT_ACTIONS, value)
}

/// `Steps[].Status` 是不是表内值。表外 → 该步按「未知」显示，不标完成。
#[cfg(test)]
pub fn step_status_is_known(value: &str) -> bool {
    is_known(&STEP_STATUSES, value)
}

/// `PendingOperation.Kind` 是不是表内值。表外 → 按「有未决写」处理（更保守）。
#[cfg(test)]
pub fn pending_kind_is_known(value: &str) -> bool {
    is_known(&PENDING_KINDS, value)
}

/// `PendingOperation.VerifyBy` 是不是表内值。
#[cfg(test)]
pub fn verify_by_is_known(value: &str) -> bool {
    is_known(&VERIFY_BYS, value)
}

/// `PendingOperation.Outcome` 是不是表内值。表外 → 结论未知（不猜）。
#[cfg(test)]
pub fn outcome_is_known(value: &str) -> bool {
    is_known(&OUTCOMES, value)
}

// ---------------------------------------------------------------------------
// 状态机
// ---------------------------------------------------------------------------

/// 这个流转合不合法。
///
/// 白名单写死（架构文档 §3.2）。两条容易漏、但必须成立：
///
/// 1. **同状态写自己永远合法**：一遍 pass 里会反复更新同一条记录（换原因、刷心跳、
///    补证据），如果连这也拒绝，引擎每次写盘都得先伪造一个中间状态。
/// 2. **表外值一律非法**：不认识的状态既不能从它出发，也不能走到它。
///    「不认识就往默认值走」正是把 `NeedsAttention` 悄悄变成 `Running` 的那种写法。
pub fn transition_ok(from: &str, to: &str) -> bool {
    if !state_is_known(from) || !state_is_known(to) {
        return false;
    }
    if from == to {
        return true;
    }
    match from {
        // 草稿：填完并开始（等人确认），或者被丢掉。
        STATE_DRAFT => matches!(to, STATE_WAITING_USER | STATE_CANCELLED),
        // 等人输入：确认后受理；也可能反过来要重新填（只填不执行），或需要人处理。
        STATE_WAITING_USER => matches!(
            to,
            STATE_QUEUED | STATE_NEEDS_ATTENTION | STATE_DRAFT | STATE_CANCELLED
        ),
        // 已受理：拿到 lane 才 Running；上游校验不过就直接 NeedsAttention。
        STATE_QUEUED => matches!(to, STATE_RUNNING | STATE_NEEDS_ATTENTION | STATE_CANCELLED),
        // 在跑：唯一能走到 Complete 的地方。
        STATE_RUNNING => matches!(
            to,
            STATE_COMPLETE | STATE_NEEDS_ATTENTION | STATE_PAUSED | STATE_CANCELLED
        ),
        // 暂停：继续 = 重新排队（不直接 Running：lane 得重新拿）。
        STATE_PAUSED => matches!(to, STATE_QUEUED | STATE_NEEDS_ATTENTION | STATE_CANCELLED),
        // 需要人处理：只能由用户显式动作往前推。
        STATE_NEEDS_ATTENTION => matches!(
            to,
            STATE_QUEUED | STATE_WAITING_USER | STATE_COMPLETE | STATE_CANCELLED
        ),
        // 终态：不得外流。「再添加」是新 RunId，绝不复用旧 RunId。
        STATE_COMPLETE | STATE_CANCELLED => false,
        _ => false,
    }
}

/// 终态（`Complete` / `Cancelled`）。终态只能打开看，不能执行。
pub fn is_terminal_state(state: &str) -> bool {
    matches!(state, STATE_COMPLETE | STATE_CANCELLED)
}

/// `Running` 的**唯一**定义：记录说 `Running` **且** 引擎 `active` 里有这个 RunId。
///
/// 两处任一不成立即为假。崩溃之后引擎里必然没有它，所以 `Running` 不可能为真
/// —— 这条判据存在的理由就是「不允许页面在崩溃后继续显示正在跑」。
pub fn is_running(run: &RunRecord, is_active: bool) -> bool {
    is_active && run.state == STATE_RUNNING
}

/// 能不能「转后台继续」。
///
/// 判据只有一份（这里）。失败、结果未知、需修复、暂停、完成、取消、等新确认
/// **全部**为假：这些情况下关掉页面等于让人以为「还在跑」。
pub fn can_background(run: &RunRecord, is_active: bool) -> bool {
    is_active
        && matches!(run.state.as_str(), STATE_RUNNING | STATE_QUEUED)
        && run.reason.is_none()
        && match &run.pending_operation {
            None => true,
            // `Pending` = 写命令已经发出去了但还没核对：这时「后台继续」是允许的
            // （它本来就是后台在跑），但记录上不许出现任何重装入口。
            Some(pending) => pending.outcome == crate::deploystore::OUTCOME_PENDING,
        }
}

// ---------------------------------------------------------------------------
// 步骤与进度
// ---------------------------------------------------------------------------

/// `N/4` 的分子：`Status == Done` 的**个数**。
///
/// 注意不是「前缀长度」：部分完成时可能 0、1、2、3 都是 Done 而中间某步 Failed，
/// 用前缀长度会把已经做成的步骤抹掉。
pub fn steps_done(run: &RunRecord) -> u32 {
    run.steps.iter().filter(|step| step.is_done()).count() as u32
}

/// 当前步骤：第一个 `Status != Done` 的下标；四步全 Done → `4`。
///
/// 没有任何步骤信息 → `None`（界面不显示 `N/4`，只显示「步骤未知」）。
pub fn current_step(run: &RunRecord) -> Option<u8> {
    if run.steps.is_empty() {
        return None;
    }
    run.steps
        .iter()
        .position(|step| !step.is_done())
        .map(|index| u8::try_from(index).unwrap_or(u8::MAX))
        .or(Some(u8::try_from(run.steps.len()).unwrap_or(u8::MAX)))
}

/// 人话的「进行到哪」：`3/4 · 准备兼容连接`。未知时给 `None`，
/// 由调用方显示「步骤未知」——**不写 0/4**，那会被读成「一步都没做」。
pub fn progress_text(run: &RunRecord) -> Option<String> {
    let index = current_step(run)?;
    let name = STEP_NAMES.get(usize::from(index)).copied().unwrap_or("");
    if name.is_empty() {
        return Some(format!("{}/{}", steps_done(run), STEP_COUNT));
    }
    Some(format!(
        "{}/{} · {}",
        steps_done(run),
        STEP_COUNT,
        name
    ))
}

// ---------------------------------------------------------------------------
// 重启改判（T04）
// ---------------------------------------------------------------------------

/// 心跳超过这么多秒就算过期。
///
/// 15 秒 = 3 个心跳间隔（引擎每 5 秒写一次）。它**不是**「判断存活」的依据——
/// 存活是证明出来的：`instance::acquire` 的命名互斥覆盖整个进程，所以本进程
/// 持锁时，任何**其它**能写记录的实例都必然不在运行。这个数字只负责挡住一类
/// 窗口：本进程刚建好记录、pass 还没起来写第一拍心跳。
pub const HEARTBEAT_STALE_SECS: u64 = 15;

/// [`recover`] 决定不动这条记录的原因。
///
/// 五种都写出来（而不是一个 `None`）是因为它们对应五种完全不同的现场：
/// 排查「为什么重启后这条还显示正在部署」时，必须能一眼说清是哪一条判据放过了它。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySkip {
    /// 终态：只读，永不改判。
    Terminal,
    /// 引擎里还有它的活动 pass：可能是心跳还没写下一拍。
    Active,
    /// 不在执行中的状态（草稿 / 等确认 / 已暂停 / 已经需要处理）。
    NotExecuting,
    /// 记录里的执行者就是本进程。
    OwnExecutor,
    /// 心跳还新。
    FreshHeartbeat,
}

impl RecoverySkip {
    /// 一句话说明（日志/测试用，不进界面）。当前只有测试在用，故不进 release。
    #[cfg(test)]
    pub fn why(self) -> &'static str {
        match self {
            RecoverySkip::Terminal => "终态记录不改判",
            RecoverySkip::Active => "本进程还有它的活动 pass",
            RecoverySkip::NotExecuting => "状态不是在执行",
            RecoverySkip::OwnExecutor => "执行者就是本进程",
            RecoverySkip::FreshHeartbeat => "心跳还没有过期",
        }
    }
}

/// [`recover`] 的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// 不动这条记录。
    Keep(RecoverySkip),
    /// 改判成 `NeedsAttention`。
    Rewrite {
        /// 新记录。`Revision` 不在这里加——由 `DeploymentStore::save` 统一递增
        /// （与 `settle_step` 同一约定：纯函数只改事实，版本号是存储层的事）。
        run: RunRecord,
        /// `OutcomeUnknown` 或 `Interrupted`。
        category: &'static str,
        /// 一句话结论，进 `operations.jsonl` 的 `detail`（只含 RunId 短码与结论）。
        detail: String,
    },
}

/// **重启后的改判**：这条记录的执行者还在不在？
///
/// 判据链（架构 §1.7）——注意它是**证明**，不是启发式：
///
/// 1. 只有 `Running` / `Queued` 才代表「有人在推进它」。`Draft`/`WaitingUser`
///    只是表单，`Paused` 是用户按下的，`NeedsAttention` 已经在等人——都不动。
/// 2. 本进程有它的活动 pass（`is_active`，引擎里也可以把「还在队列里」算进来）
///    → 不动。刚起的 pass 可能还没写第一拍心跳，这时按心跳判死会把它自己改判掉。
/// 3. `Executor.Pid == current_pid` → 不动。
/// 4. 心跳还在 15 秒内 → 不动（给上一条兜底）。
/// 5. 其余：执行者必然已死（单实例互斥）。有未核对的写 → `OutcomeUnknown`，
///    否则 `Interrupted`。**永不**自动入队、自动登录、自动重放。
///
/// 未决写用 [`has_unverified_write`] 而不是「`PendingOperation` 字段在不在」：
/// 核对过 `Applied`/`NotApplied` 的写已经**有结论**，那不是「结果未知」，
/// 按未知处理会让用户去核对一条早就核对完的记录。
pub fn recover(run: &RunRecord, current_pid: i64, now_secs: u64, is_active: bool) -> Recovery {
    if is_terminal_state(&run.state) {
        return Recovery::Keep(RecoverySkip::Terminal);
    }
    if is_active {
        return Recovery::Keep(RecoverySkip::Active);
    }
    if !matches!(run.state.as_str(), STATE_RUNNING | STATE_QUEUED) {
        return Recovery::Keep(RecoverySkip::NotExecuting);
    }
    if let Some(executor) = run.executor.as_ref() {
        if executor.pid == current_pid {
            return Recovery::Keep(RecoverySkip::OwnExecutor);
        }
    }
    // 心跳缺失/解析不了 = 不知道它什么时候跳过最后一拍。**当成过期**：
    // 「不知道」不能拿来当作「还活着」的理由，那正是崩溃后继续显示正在跑的来源。
    let heartbeat = run
        .executor
        .as_ref()
        .and_then(|executor| executor.heartbeat_at_utc.as_deref())
        .and_then(crate::deploystore::parse_stamp);
    if let Some(heartbeat) = heartbeat {
        if now_secs.saturating_sub(heartbeat) <= HEARTBEAT_STALE_SECS {
            return Recovery::Keep(RecoverySkip::FreshHeartbeat);
        }
    }

    let unknown = has_unverified_write(run);
    let (category, code, next_action, text) = if unknown {
        (
            REASON_OUTCOME_UNKNOWN,
            "OutcomeUnknown",
            NEXT_ACTION_RECONCILE,
            "上次被打断，有一条写命令还没核对结论：先核对原操作。",
        )
    } else {
        (
            REASON_INTERRUPTED,
            "Interrupted",
            NEXT_ACTION_RETRY_STEP,
            "上次没有跑完（程序意外退出），可以从这一步继续。",
        )
    };

    let mut next = run.clone();
    next.state = STATE_NEEDS_ATTENTION.to_string();
    next.next_action = next_action.to_string();
    next.reason = Some(Reason::now(
        category,
        crate::deploystore::ERROR_CLASS_INTERNAL,
        code,
        text,
    ));
    // 被强杀的那次尝试也要有结论，否则重启后第一次重试会把它和新的这次混成一条
    // 「跨了一次崩溃的尝试」。结束时间取**最后一拍心跳**（能证明的最后时刻）；
    // 没有心跳就取判定时刻——宁可说「在重启时判定结束」，也不留一条永远进行中的历史。
    let ended_at = run
        .executor
        .as_ref()
        .and_then(|item| item.heartbeat_at_utc.clone())
        .filter(|stamp| !stamp.trim().is_empty())
        .unwrap_or_else(|| crate::deploystore::stamp_utc(now_secs));
    finish_attempt(&mut next, &ended_at, None, code);
    if let Some(index) = current_step(run) {
        next.step = Some(index);
        // 卡在「进行中」的那一步改成「未核实」：我们没有它的结论，
        // 说完成是假的，说失败也是假的。**只动这一种状态**——已经 Done 的步骤
        // 是核对过的成果，`Pending` 的是真的还没开始，两者都不许碰。
        if let Some(slot) = next.steps.get_mut(usize::from(index)) {
            if slot.status == crate::deploystore::STEP_STATUS_RUNNING {
                slot.status = crate::deploystore::STEP_STATUS_UNKNOWN.to_string();
            }
        }
    }

    let detail = format!(
        "{} · {}（{} → 需要处理）",
        run.run_id.chars().take(8).collect::<String>(),
        text,
        run.state
    );
    Recovery::Rewrite {
        run: next,
        category,
        detail,
    }
}

// ---------------------------------------------------------------------------
// 新记录
// ---------------------------------------------------------------------------

/// 一条全新的草稿记录（`Draft`，四步全 `Pending`，`Revision` 仍是 0）。
///
/// `Revision` 故意留在 0：它是「还没落过盘」的意思，由
/// [`DeploymentStore::create`](crate::deploystore::DeploymentStore::create) 置为 1。
/// 调用方要是自己写了 1，落盘后就成了「第 1 版写了两遍」。
pub fn new_draft(
    run_id: &str,
    label: &str,
    target: Target,
    fingerprint: &str,
    created_at_utc: &str,
) -> RunRecord {
    let mut run = RunRecord::empty();
    run.run_id = run_id.to_string();
    run.label = label.to_string();
    run.target = target;
    run.identity.fingerprint = fingerprint.to_string();
    run.identity.auto_trusted = false;
    run.plan = Plan::default();
    run.state = STATE_DRAFT.to_string();
    run.step = Some(0);
    run.next_action = NEXT_ACTION_OPEN_FORM.to_string();
    run.steps = STEP_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| StepRecord {
            index: u8::try_from(index).unwrap_or(u8::MAX),
            name: (*name).to_string(),
            status: crate::deploystore::STEP_STATUS_PENDING.to_string(),
            started_at_utc: None,
            finished_at_utc: None,
            evidence: serde_json::Value::Null,
            error: None,
        })
        .collect();
    run.pending_operation = None;
    run.attempts = vec![AttemptRecord {
        no: 1,
        started_at_utc: Some(created_at_utc.to_string()),
        finished_at_utc: None,
        failed_step: None,
        error_code: String::new(),
        reconcile: RECONCILE_NOT_NEEDED.to_string(),
    }];
    run.executor = None;
    run.created_at_utc = Some(created_at_utc.to_string());
    run.started_at_utc = None;
    run.updated_at_utc = Some(created_at_utc.to_string());
    run.finished_at_utc = None;
    run.revision = 0;
    run
}

/// 记录上有没有「已经写出去、但还没核对」的未决写。
///
/// 有它的时候，UI **不得**提供「重试安装 / 重新部署」，只能提供「核对原操作」。
///
/// 别用「`PendingOperation` 字段在不在」代替它：字段在只说明**有过**一条写（结案后
/// 记录里仍要留着这条证据），不说明结论未知。要判「能不能重试」只能看 `Outcome`
/// ——这正是 T03 接调用方时踩过的那个坑（两个名字原来都叫 `has_unverified_write`）。
pub fn has_unverified_write(run: &RunRecord) -> bool {
    match &run.pending_operation {
        None => false,
        Some(pending) => !matches!(
            pending.outcome.as_str(),
            crate::deploystore::OUTCOME_APPLIED | crate::deploystore::OUTCOME_NOT_APPLIED
        ),
    }
}

/// 记录上挂着的失败原因（如果有）。
pub fn reason_of(run: &RunRecord) -> Option<&Reason> {
    run.reason.as_ref()
}

/// 任务编号的短码（前 8 位）。列表、详情页、诊断摘要共用一处，别各写一遍。
pub fn run_short(run_id: &str) -> String {
    run_id.chars().take(8).collect()
}

/// 步骤下标对应的步骤名（越界给空串，**不 panic**）。
#[cfg(test)]
pub fn step_name(index: u8) -> &'static str {
    STEP_NAMES
        .get(usize::from(index))
        .copied()
        .unwrap_or("")
}

// ---------------------------------------------------------------------------
// 尝试历史（P1-4）
// ---------------------------------------------------------------------------

/// 这一次 pass 开始时，要不要在记录上追加一次尝试。
///
/// 判据只有一条：**上一次尝试已经有结论**（`FinishedAtUtc` 非空）→ 这是新的一次。
///
/// 所以「把尝试结束掉」的责任在**所有会让 pass 停下的路径**上，而不在「用户点了几次」：
/// `settle_attention`（失败/结果未知/上游校验不过）、`finish_cancelled`、
/// `finalize`（完成/部分完成）、以及启动恢复 `recover`（被强杀的那次按最后一拍心跳收尾）。
/// 暂停后继续、补密码后继续都**不**结束尝试，因此也不会凭空多出一条历史。
pub fn begin_attempt(run: &mut RunRecord, now_utc: &str) -> bool {
    let needs_new = run
        .attempts
        .last()
        .map(|item| item.finished_at_utc.is_some())
        .unwrap_or(true);
    if !needs_new {
        return false;
    }
    let no = run.attempts.last().map(|item| item.no + 1).unwrap_or(1);
    run.attempts.push(AttemptRecord {
        no,
        started_at_utc: Some(now_utc.to_string()),
        finished_at_utc: None,
        failed_step: None,
        error_code: String::new(),
        reconcile: RECONCILE_NOT_NEEDED.to_string(),
    });
    true
}

/// 给**最后一次**尝试写上结论。
///
/// 已经有结论的不覆盖：`settle_attention` 可能在同一次 pass 里被调用多次，
/// 第二次改写的只会是「结束时间」，而失败步骤/错误码会变成最后一次调用者的。
/// 返回是否真的写了。
pub fn finish_attempt(
    run: &mut RunRecord,
    now_utc: &str,
    failed_step: Option<u8>,
    error_code: &str,
) -> bool {
    let Some(last) = run.attempts.last_mut() else {
        return false;
    };
    if last.finished_at_utc.is_some() {
        return false;
    }
    last.finished_at_utc = Some(now_utc.to_string());
    last.failed_step = failed_step;
    last.error_code = error_code.to_string();
    true
}

/// 这次尝试留下了未决写：历史里要能说清「为什么停在核对」。
pub fn mark_attempt_needs_reconcile(run: &mut RunRecord) {
    if let Some(last) = run.attempts.last_mut() {
        last.reconcile = RECONCILE_NEEDED.to_string();
    }
}

/// 未决写已经核对完：历史里那句「需要核对」要跟着变成「已核对」。
pub fn mark_attempt_reconciled(run: &mut RunRecord) {
    if let Some(last) = run.attempts.last_mut() {
        // 只有真的需要过核对的那次才改写：`NotNeeded` 是一次都没发生，
        // 写成 `Done` 会让人以为「核对过一条不存在的写」。
        if last.reconcile == RECONCILE_NEEDED {
            last.reconcile = RECONCILE_DONE.to_string();
        }
    }
}

/// 当前步骤的人话名（未知给「步骤未知」）。
#[cfg(test)]
pub fn current_step_name(run: &RunRecord) -> &'static str {
    match current_step(run) {
        Some(index) if usize::from(index) < STEP_NAMES.len() => step_name(index),
        _ => "步骤未知",
    }
}

/// 只有 `Done` 计入完成。这条单独写成一个函数，是为了让「补一个状态」的人
/// 必须到这儿来确认一次：「这个新状态算不算完成」。
#[cfg(test)]
pub fn counts_as_done(status: &str) -> bool {
    status == STEP_STATUS_DONE
}

// ---------------------------------------------------------------------------
// 一次 pass 的计划（T03）
// ---------------------------------------------------------------------------

/// 这次 pass 从哪一步开始、要把哪些「已经 Done 的上游步骤」重新核对一遍。
///
/// 「重新核对」是**只读**的：核对结果只能决定「跳过 / 回退到某步 / 需要人处理」，
/// 绝不顺手执行写操作（架构 §1.3.5 的铁律）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassPlan {
    /// 从这一步开始做（0..4）。
    pub resume_from: u8,
    /// 已 Done 但这次要重新核对的上游步骤下标（只读探针；核对不过就回退）。
    pub verify: Vec<u8>,
}

/// `plan_pass` 拒绝执行的理由。三种都**不产生任何执行意图**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassRefusal {
    /// 终态：只能打开看。
    Terminal,
    /// 有未决写还没核对：只允许「核对原操作」，不许重试/重装。
    UnverifiedWrite,
    /// 四步全 Done 但记录不是终态（记录不一致）：交给收尾判定，不重跑。
    AllDone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassDecision {
    Run(PassPlan),
    Refuse(PassRefusal),
}

/// 纯函数：只看记录决定「这次从哪开始、核对什么」。
///
/// 判据刻意保守：
/// - 终态一律不跑（哪怕状态机被手工改过）；
/// - 有未核对完的写一律不跑（重放写命令比「停下等人」危险得多）；
/// - 四步全 Done 也不再跑（`Complete` 的收尾由引擎做，不重登服务器）。
pub fn plan_pass(run: &RunRecord) -> PassDecision {
    if is_terminal_state(&run.state) {
        return PassDecision::Refuse(PassRefusal::Terminal);
    }
    if has_unverified_write(run) {
        return PassDecision::Refuse(PassRefusal::UnverifiedWrite);
    }
    let Some(current) = current_step(run) else {
        return PassDecision::Run(PassPlan {
            resume_from: 0,
            verify: Vec::new(),
        });
    };
    if usize::from(current) >= STEP_COUNT {
        return PassDecision::Refuse(PassRefusal::AllDone);
    }
    let verify = run
        .steps
        .iter()
        .filter(|step| usize::from(step.index) < usize::from(current) && step.is_done())
        .map(|step| step.index)
        .collect();
    PassDecision::Run(PassPlan {
        resume_from: current,
        verify,
    })
}

/// 上游只读核对的事实（由引擎采集，`decide_resume` 消费）。
#[derive(Debug, Clone, Default)]
pub struct UpstreamFacts {
    /// Step1 的核对结果：`None` = 没探（或探针失败，按「不知道」处理）。
    pub udp_matches_plan: Option<bool>,
    /// Step2 的核对结果：`None` = 没读到；`Some(false)` = 读到了但对不上计划。
    pub transport_matches_plan: Option<bool>,
    /// Step3 的本机核对：线路是否还在 `config.json` 里。
    pub lines_present: Option<bool>,
    /// 服务器记录与指纹是否仍与记录一致。
    pub identity_matches: Option<bool>,
}

/// `decide_resume` 的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeDecision {
    /// 从 `from` 开始（可能因为上游失效而回退）。
    From(u8),
    /// 身份变了：不跑，写 `NeedsAttention/IdentityChanged`。
    IdentityChanged,
    /// 读到了兼容连接但参数对不上：`NeedsRecovery`，不静默沿用。
    NeedsRecovery,
}

/// 纯函数：上游核对完之后，到底从哪一步开始。
///
/// 回退只回**到该步**，不从头：Step0 的证据（身份/环境）此时仍然有效。
pub fn decide_resume(plan: &PassPlan, facts: &UpstreamFacts) -> ResumeDecision {
    if facts.identity_matches == Some(false) {
        return ResumeDecision::IdentityChanged;
    }
    let mut from = plan.resume_from;
    if from > 3 && facts.lines_present == Some(false) {
        from = 3;
    }
    if from > 2 && facts.transport_matches_plan == Some(false) {
        return ResumeDecision::NeedsRecovery;
    }
    if from > 2 && facts.transport_matches_plan.is_none() && plan.verify.contains(&2) {
        from = 2;
    }
    if from > 1 && facts.udp_matches_plan == Some(false) {
        from = 1;
    }
    ResumeDecision::From(from)
}

// ---------------------------------------------------------------------------
// 一步做完之后怎么落账（T03）
// ---------------------------------------------------------------------------

/// 一步的结果。**只有这四种**：写不清「到底生效没有」的时候不许编一个。
#[derive(Debug, Clone)]
pub enum StepOutcome {
    /// 成功（有证据）。
    Done { evidence: serde_json::Value },
    /// 这一步失败了，但前面的成果要保住（Step2 的 `Partial`）。
    ///
    /// 引擎现在还没有产生它的路径（Step2 失败一律走 `Failed`），但落账与投影
    /// 都必须认这种结论——删掉它，将来接上 Step2 的「部分完成」时就得重新发明
    /// 一个名字，而且会悄悄少一条「成果保住了」的语义。所以留着，并写清理由。
    #[allow(dead_code)]
    Partial {
        evidence: serde_json::Value,
        reason: Reason,
    },
    /// 明确失败（脚本自己说了，或只读核对确认没生效）。
    Failed { reason: Reason },
    /// 结果未知：必须停在 `NeedsAttention/OutcomeUnknown`，只给「核对原操作」。
    Unknown { reason: Reason },
}

/// 把一步的结果写进记录。**不改 `Revision`、不写盘**：那是存储层的事。
///
/// 状态流转先过 [`transition_ok`]，非法流转直接返回错误——这样「顺手把
/// NeedsAttention 改成 Running」在编译期之后还会被运行时拦一次。
pub fn settle_step(
    run: &mut RunRecord,
    index: u8,
    outcome: StepOutcome,
    now_utc: &str,
) -> Result<(), String> {
    let step_index = usize::from(index);
    if step_index >= run.steps.len() {
        return Err(format!(
            "步骤下标越界：{index}（共 {} 步）",
            run.steps.len()
        ));
    }

    let (status, state, next_action) = match &outcome {
        StepOutcome::Done { .. } => (STEP_STATUS_DONE, run.state.clone(), NEXT_ACTION_NONE),
        StepOutcome::Partial { .. } => (
            crate::deploystore::STEP_STATUS_FAILED,
            STATE_NEEDS_ATTENTION.to_string(),
            crate::deploystore::NEXT_ACTION_COMPLETE_COMPATIBLE,
        ),
        StepOutcome::Failed { .. } => (
            crate::deploystore::STEP_STATUS_FAILED,
            STATE_NEEDS_ATTENTION.to_string(),
            crate::deploystore::NEXT_ACTION_RETRY_STEP,
        ),
        StepOutcome::Unknown { .. } => (
            crate::deploystore::STEP_STATUS_UNKNOWN,
            STATE_NEEDS_ATTENTION.to_string(),
            crate::deploystore::NEXT_ACTION_RECONCILE,
        ),
    };

    if !transition_ok(&run.state, &state) {
        return Err(format!("状态机不允许 {} → {}", run.state, state));
    }

    let slot = &mut run.steps[step_index];
    match outcome {
        StepOutcome::Done { evidence } => {
            slot.status = status.to_string();
            slot.finished_at_utc = Some(now_utc.to_string());
            slot.evidence = evidence;
            slot.error = None;
            run.state = state;
            run.step = Some(index.saturating_add(1));
            run.reason = None;
            run.next_action = next_action.to_string();
        }
        StepOutcome::Partial { evidence, reason } => {
            slot.status = status.to_string();
            slot.finished_at_utc = Some(now_utc.to_string());
            slot.evidence = evidence;
            slot.error = Some(reason.clone());
            run.state = state;
            run.step = Some(index);
            run.next_action = next_action.to_string();
            run.reason = Some(reason);
        }
        StepOutcome::Failed { reason } | StepOutcome::Unknown { reason } => {
            slot.status = status.to_string();
            slot.finished_at_utc = Some(now_utc.to_string());
            slot.error = Some(reason.clone());
            run.state = state;
            run.step = Some(index);
            run.next_action = next_action.to_string();
            run.reason = Some(reason);
        }
    }
    // 这一步把任务停进了「需要处理」：这次尝试到此为止。`Done` 只是往下走，不写。
    // 判据用状态而不是 outcome：少写一种 outcome 时，这里也不会漏掉一次尝试的收尾。
    if run.state == STATE_NEEDS_ATTENTION {
        let code = run
            .reason
            .as_ref()
            .map(|item| item.code.clone())
            .unwrap_or_default();
        finish_attempt(run, now_utc, Some(index), &code);
        if has_unverified_write(run) {
            mark_attempt_needs_reconcile(run);
        }
    }
    Ok(())
}

/// 把人话写出来。**签名里没有 secret 参数**——从类型上堵死「顺手把密码拼进进度」。
pub fn humanize(reason: &Reason) -> String {
    if !reason.text.trim().is_empty() {
        return reason.text.clone();
    }
    match reason.category.as_str() {
        REASON_FAILED => "这一步没有成功。",
        REASON_OUTCOME_UNKNOWN => "这一步的结果还没核实，先核对再决定下一步。",
        REASON_NEEDS_RECOVERY => "服务器上的配置与本机记录对不上，需要先核对。",
        REASON_IDENTITY_CHANGED => "服务器的身份与记录不一致，请重新核对指纹。",
        REASON_ACCESS_REQUIRED => "登录凭据不可用，请重新输入。",
        REASON_INTERRUPTED => "上次没有跑完。",
        REASON_PARTIAL => "标准连接已经可用，兼容连接还没装上。",
        _ => "需要处理。",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// 任务投影（`deployment-list` / `deployment-get` / 快照三处共用）
// ---------------------------------------------------------------------------
//
// 三处各写一遍的下场是「列表说核对、点进去说重试」。所以投影只在这里算一次，
// 其余地方都是照抄。全部是纯函数：输入记录 + 「引擎里有没有它」，输出 JSON。

/// 状态的人话。表外状态**不许**落到「进行中」——那会让崩溃后的记录看起来还在跑。
pub fn state_text(state: &str) -> &'static str {
    match state {
        STATE_DRAFT => "未开始",
        STATE_WAITING_USER => "等待确认",
        STATE_QUEUED => "排队中",
        STATE_RUNNING => "正在部署",
        STATE_PAUSED => "已暂停",
        STATE_NEEDS_ATTENTION => "需要处理",
        STATE_COMPLETE => "已完成",
        STATE_CANCELLED => "已取消",
        _ => "状态需要核对",
    }
}

/// 任务卡片上那**唯一**一颗按钮：`(机器名, 人话)`。
///
/// 机器名进 `data-action`，人话进按钮文字。列表与详情页共用这一份，
/// 两边各写一遍就会出现「列表说核对、点进去说重试」。
///
/// 有 `PendingOperation.Outcome == Pending` 时**只**给「核对原操作」：
/// 那一步已经发出写命令，重发一遍不是「重试」而是「再来一次写」。
pub fn action_of(run: &RunRecord) -> (&'static str, &'static str) {
    // 终态只读：`Complete` 给「查看线路」（`finalize` 把 NextAction 写成 `ViewLine`），
    // `Cancelled` 给「查看」。这里按状态定，不读 `NextAction`——终态记录上那份字段
    // 可能是历史遗留值，照它渲染会冒出「重试本步骤」这种不该有的入口。
    if is_terminal_state(&run.state) {
        return if run.state == STATE_COMPLETE {
            ("viewLine", "查看线路")
        } else {
            ("view", "查看")
        };
    }
    if has_unverified_write(run) {
        return ("reconcile", "核对原操作");
    }
    match run.next_action.as_str() {
        crate::deploystore::NEXT_ACTION_ENTER_CREDENTIALS => ("enterCredentials", "输入密码继续"),
        crate::deploystore::NEXT_ACTION_RECONCILE => ("reconcile", "核对原操作"),
        crate::deploystore::NEXT_ACTION_RETRY_STEP => ("continue", "重试本步骤"),
        crate::deploystore::NEXT_ACTION_CONFIRM_FINGERPRINT
        | crate::deploystore::NEXT_ACTION_CONFIRM_PLAN => ("confirm", "重新确认"),
        crate::deploystore::NEXT_ACTION_COMPLETE_COMPATIBLE => {
            ("completeCompatible", "补齐兼容连接")
        }
        crate::deploystore::NEXT_ACTION_VIEW_LINE => ("viewLine", "查看线路"),
        crate::deploystore::NEXT_ACTION_WAIT_QUEUE => ("resume", "查看"),
        // `OpenForm` 是草稿的默认动作；崩溃后残留的 Running 记录也带着它，
        // 那时说「继续填写」是骗人——只能「查看」。
        crate::deploystore::NEXT_ACTION_OPEN_FORM => {
            if run.state == STATE_DRAFT {
                ("resume", "继续填写")
            } else {
                ("resume", "查看")
            }
        }
        _ => match run.state.as_str() {
            STATE_PAUSED | STATE_WAITING_USER | STATE_DRAFT => ("resume", "继续"),
            _ => ("resume", "查看"),
        },
    }
}

/// 卡片标题行：`3/4 · 准备兼容连接`；`NeedsAttention` 时追加原因。
pub fn task_label(run: &RunRecord) -> String {
    // 草稿一步都没跑过：新记录把 `Step` 设成 `Some(0)`，于是 `progress_text` 会
    // 老老实实算出「0/4 · 检查服务器环境与身份」——而任务卡（`web/app.js`）**只渲染
    // `Label`、不渲染 `StateText`**，界面就会写着「检查服务器环境与身份」，一秒钟都没检查过。
    // 这是本项目最忌讳的一类错：状态说假话。所以草稿的标题行直接说「未开始」，
    // 与 `state_text` / `summary_of` 同一个词，一处口径。
    if run.is_draft() {
        return "未开始".to_string();
    }
    let base = progress_text(run).unwrap_or_else(|| "步骤未知".to_string());
    if run.state == STATE_NEEDS_ATTENTION {
        if let Some(reason) = reason_of(run) {
            return format!("{base}：{}", humanize(reason));
        }
    }
    base
}

/// 底部任务条的一句话。
pub fn summary_of(run: &RunRecord) -> String {
    match run.state.as_str() {
        STATE_COMPLETE => "部署完成".to_string(),
        STATE_CANCELLED => "已取消".to_string(),
        STATE_NEEDS_ATTENTION => reason_of(run)
            .map(humanize)
            .unwrap_or_else(|| "需要处理。".to_string()),
        STATE_RUNNING => progress_text(run).unwrap_or_else(|| "正在部署".to_string()),
        STATE_QUEUED => "排队中".to_string(),
        STATE_PAUSED => "已暂停".to_string(),
        STATE_WAITING_USER => "等待确认".to_string(),
        STATE_DRAFT => "未开始".to_string(),
        _ => "状态需要核对".to_string(),
    }
}

/// 一条记录的完整投影（`deployment-get` 的 `Run`，也是列表里每条的元素形状）。
///
/// 记录本身的字段原样保留（PascalCase），另外补五个**算出来的**字段：
/// `StepsDone` / `Label` / `Action` / `ActionLabel` / `Running` / `CanBackground`。
/// 「算出来的」不写回记录：记录只有引擎写，投影只读。
pub fn run_view(run: &RunRecord, is_active: bool) -> serde_json::Value {
    let mut value = run.to_json();
    let (action, action_label) = action_of(run);
    if let Some(object) = value.as_object_mut() {
        object.insert("StepsDone".to_string(), serde_json::json!(steps_done(run)));
        // `Name` 是记录上的名字（「自建 · 203.0.113.10」），与 `project_tasks` 同名同义；
        // `Label` 是**进度标签**（「3/4 · 准备标准连接：…」）。详情页的标题只能用 `Name`：
        // 拿 `Label` 当标题会得到一句两行的长句。
        object.insert("Name".to_string(), serde_json::json!(run.label));
        object.insert("Label".to_string(), serde_json::json!(task_label(run)));
        object.insert("Summary".to_string(), serde_json::json!(summary_of(run)));
        object.insert("Action".to_string(), serde_json::json!(action));
        object.insert("ActionLabel".to_string(), serde_json::json!(action_label));
        object.insert(
            "Running".to_string(),
            serde_json::json!(is_running(run, is_active)),
        );
        object.insert(
            "CanBackground".to_string(),
            serde_json::json!(can_background(run, is_active)),
        );
        object.insert(
            "RunShort".to_string(),
            serde_json::json!(run_short(&run.run_id)),
        );
    }
    value
}

/// 已归档（P2-2）最多给多少条。归档**不参与裁剪**（用户要留着），所以这里必须
/// 有个上界，否则列表会随着归档越来越多而无限长。按归档时刻取最新的 N 条。
pub const MAX_ARCHIVED_SHOWN: usize = 20;

/// 已归档的投影：只给「认得出、点得开、恢复得回来」需要的字段。
///
/// 与 `Tasks`/`Deployments` 同一口径：**只透传，不在页面重算**。
pub fn project_archived(runs: &[RunRecord]) -> Vec<serde_json::Value> {
    let mut items: Vec<&RunRecord> = runs.iter().filter(|run| run.is_archived()).collect();
    items.sort_by(|left, right| {
        right
            .archived_at_utc
            .cmp(&left.archived_at_utc)
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
    items.truncate(MAX_ARCHIVED_SHOWN);
    items
        .into_iter()
        .map(|run| {
            serde_json::json!({
                "RunId": run.run_id.clone(),
                "RunShort": run_short(&run.run_id),
                "Name": run.label.clone(),
                "State": run.state.clone(),
                "StateText": state_text(&run.state),
                "Summary": summary_of(run),
                "StepsDone": steps_done(run),
                "Host": run.target.host.clone(),
                "Port": run.target.port,
                "UpdatedAtUtc": run.updated_at_utc.clone(),
                "ArchivedAtUtc": run.archived_at_utc.clone(),
                // 筛选（P2-1）用：归档的条目也要能按「失败 / 结果未知 / …」分开。
                "ReasonCategory": run.reason.as_ref().map(|item| item.category.clone()).unwrap_or_default(),
                "ReasonCode": run.reason.as_ref().map(|item| item.code.clone()).unwrap_or_default(),
            })
        })
        .collect()
}

/// 草稿放多久算「很久没动」。超过就给一句提示——**只是提示**。
///
/// 本产品**不做自动过期**：「未完成的记录不会被自己删掉」是同一块底线。
/// 到期的草稿要么用户接着填，要么用户点「放弃这次填写」，没有第三种走法。
pub const DRAFT_STALE_DAYS: u64 = 7;

/// 草稿总览（C6）：几条、最旧的那条放了几天、要不要提醒。
///
/// 口径：
/// - 只数 `Draft` 且没归档的；
/// - 时龄取 `CreatedAtUtc`（用户**开始填**的那一刻），不是 `UpdatedAtUtc`——
///   后者会被「又打开看了一次」刷新，那样任何草稿都永远看起来是新的；
/// - 时间戳缺失 = 时龄**未知**：`HasAge=false`、`OldestDays=0`，文案里不出现天数。
///   说「0 天」会被读成「刚建的」，猜一个数字更是编的；
/// - 文案在这里拼好（`Summary`/`Hint`），页面只负责显示——同一句话只有一处。
pub fn draft_summary(runs: &[RunRecord], now_secs: u64) -> serde_json::Value {
    let drafts: Vec<&RunRecord> = runs
        .iter()
        .filter(|run| run.is_draft())
        .filter(|run| !run.is_archived())
        .collect();
    let oldest = drafts
        .iter()
        .filter_map(|run| run.created_at_utc.as_deref())
        .filter_map(crate::deploystore::parse_stamp)
        .min();
    let has_age = oldest.is_some();
    let days = oldest
        .map(|stamp| now_secs.saturating_sub(stamp) / (24 * 60 * 60))
        .unwrap_or(0);
    let count = drafts.len();
    let stale = has_age && days >= DRAFT_STALE_DAYS;
    let summary = match (count, has_age) {
        (0, _) => String::new(),
        (many, true) => format!("{many} 份没填完的部署，最旧的一份放了 {days} 天。"),
        (many, false) => format!("{many} 份没填完的部署。"),
    };
    let hint = if count == 0 {
        String::new()
    } else if stale {
        format!(
            "超过 {DRAFT_STALE_DAYS} 天没动过。可以接着填，也可以放弃——草稿不会自己消失。"
        )
    } else {
        "草稿不会自己消失；不想留着就点「放弃这次填写」。".to_string()
    };
    serde_json::json!({
        "Count": count,
        "OldestDays": days,
        "HasAge": has_age,
        "Stale": stale,
        "StaleDays": DRAFT_STALE_DAYS,
        "Max": crate::deploystore::MAX_DRAFTS,
        "Summary": summary,
        "Hint": hint,
    })
}

/// `Tasks` 的分组次序（架构文档 §3.4 第 1 条）。
fn task_rank(state: &str) -> u8 {
    match state {
        STATE_NEEDS_ATTENTION => 0,
        STATE_RUNNING | STATE_QUEUED => 1,
        STATE_WAITING_USER | STATE_PAUSED => 2,
        STATE_DRAFT => 3,
        // 表外状态排在最后：它既不是「要处理」也不是「在跑」，不能挤到前面抢注意力。
        _ => 4,
    }
}

/// `Deployments` 的分组次序（架构文档 §3.4 第 2 条）。
fn deployment_rank(run: &RunRecord, is_active: bool) -> u8 {
    if is_running(run, is_active) {
        return 0;
    }
    match run.state.as_str() {
        STATE_NEEDS_ATTENTION => 1,
        STATE_PAUSED | STATE_WAITING_USER | STATE_QUEUED => 2,
        STATE_COMPLETE | STATE_CANCELLED => 3,
        _ => 4,
    }
}

/// 未完成任务（含 `Draft`）。终态**不**在这里——「未完成的添加」只放没做完的。
pub fn project_tasks(
    runs: &[RunRecord],
    is_active: impl Fn(&str) -> bool,
) -> Vec<serde_json::Value> {
    let mut items: Vec<&RunRecord> = runs
        .iter()
        // 归档的任务不进「未完成的添加」：用户明确把它收起来了。
        // 想看/想恢复走「已归档」那一块（`project_archived`）。
        .filter(|run| !run.is_archived())
        .filter(|run| !is_terminal_state(&run.state))
        .collect();
    items.sort_by(|left, right| {
        task_rank(&left.state)
            .cmp(&task_rank(&right.state))
            .then_with(|| right.updated_at_utc.cmp(&left.updated_at_utc))
            // 同一秒更新的两条要有稳定次序，否则两次刷新顺序会跳。
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
    items
        .into_iter()
        .map(|run| {
            let active = is_active(&run.run_id);
            let (action, action_label) = action_of(run);
            let mut object = serde_json::Map::new();
            object.insert("Id".to_string(), serde_json::json!(run.run_id));
            object.insert("Name".to_string(), serde_json::json!(run.label));
            object.insert("Label".to_string(), serde_json::json!(task_label(run)));
            object.insert("State".to_string(), serde_json::json!(run.state));
            object.insert(
                "StateText".to_string(),
                serde_json::json!(state_text(&run.state)),
            );
            object.insert("Step".to_string(), serde_json::json!(current_step(run)));
            object.insert("StepsDone".to_string(), serde_json::json!(steps_done(run)));
            object.insert("Host".to_string(), serde_json::json!(run.target.host));
            object.insert("Port".to_string(), serde_json::json!(run.target.port));
            object.insert(
                "UpdatedAtUtc".to_string(),
                serde_json::json!(run.updated_at_utc),
            );
            object.insert("Action".to_string(), serde_json::json!(action));
            object.insert("ActionLabel".to_string(), serde_json::json!(action_label));
            object.insert(
                "RunShort".to_string(),
                serde_json::json!(run.run_id.chars().take(8).collect::<String>()),
            );
            object.insert(
                "CanBackground".to_string(),
                serde_json::json!(can_background(run, active)),
            );
            // 原因是**可选**的：没有就真的不写这个键，前端「缺失即不显示」。
            if let Some(reason) = reason_of(run) {
                object.insert(
                    "ReasonCategory".to_string(),
                    serde_json::json!(reason.category),
                );
                object.insert("ReasonText".to_string(), serde_json::json!(humanize(reason)));
            }
            serde_json::Value::Object(object)
        })
        .collect()
}

/// 底部任务条：非 `Draft` 的全部 + 最近 24 小时内的终态。
pub fn project_deployments(
    runs: &[RunRecord],
    is_active: impl Fn(&str) -> bool,
    now_secs: u64,
) -> Vec<serde_json::Value> {
    let mut items: Vec<&RunRecord> = runs
        .iter()
        .filter(|run| run.state != STATE_DRAFT)
        // 归档的记录不进底部队列：用户把它收起来了。想看/想恢复走
        // `project_archived`（线路页「已归档」）——归档不是删除，文件一直在。
        .filter(|run| !run.is_archived())
        .filter(|run| {
            if !is_terminal_state(&run.state) {
                return true;
            }
            // 终态只留最近 24 小时：更早的是「历史」，去「记录」页看。
            run.finished_at_utc
                .as_deref()
                .and_then(crate::deploystore::parse_stamp)
                .map(|finished| now_secs.saturating_sub(finished) <= 24 * 60 * 60)
                .unwrap_or(false)
        })
        .collect();
    items.sort_by(|left, right| {
        deployment_rank(left, is_active(&left.run_id))
            .cmp(&deployment_rank(right, is_active(&right.run_id)))
            .then_with(|| right.updated_at_utc.cmp(&left.updated_at_utc))
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
    items
        .into_iter()
        .map(|run| {
            let active = is_active(&run.run_id);
            let mut object = serde_json::Map::new();
            object.insert("RunId".to_string(), serde_json::json!(run.run_id));
            object.insert("Name".to_string(), serde_json::json!(run.label));
            object.insert("State".to_string(), serde_json::json!(run.state));
            object.insert(
                "StateText".to_string(),
                serde_json::json!(state_text(&run.state)),
            );
            object.insert("Summary".to_string(), serde_json::json!(summary_of(run)));
            object.insert("Step".to_string(), serde_json::json!(current_step(run)));
            object.insert("StepsDone".to_string(), serde_json::json!(steps_done(run)));
            object.insert("Host".to_string(), serde_json::json!(run.target.host));
            object.insert("Port".to_string(), serde_json::json!(run.target.port));
            object.insert(
                "UpdatedAtUtc".to_string(),
                serde_json::json!(run.updated_at_utc),
            );
            object.insert(
                "Running".to_string(),
                serde_json::json!(is_running(run, active)),
            );
            if let Some(reason) = reason_of(run) {
                object.insert(
                    "ReasonCategory".to_string(),
                    serde_json::json!(reason.category),
                );
            }
            if let Some(finished) = &run.finished_at_utc {
                object.insert(
                    "FinishedAtUtc".to_string(),
                    serde_json::json!(finished),
                );
            }
            serde_json::Value::Object(object)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host: "203.0.113.10".to_string(),
            port: 22,
            user: "root".to_string(),
            server_record_id: None,
            ..Default::default()
        }
    }

    fn draft() -> RunRecord {
        new_draft(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            "自建 · 203.0.113.10",
            target(),
            "SHA256:AAAA",
            "2026-11-08T09:00:00Z",
        )
    }

    /// C6：草稿总览只数草稿；时龄按「开始填」那一刻算；时间戳缺失就说未知。
    #[test]
    fn draft_summary_counts_drafts_and_measures_from_the_start_time() {
        let now = crate::deploystore::parse_stamp("2026-11-12T00:00:00Z").unwrap() + 2 * 86_400;

        let mut fresh = draft();
        fresh.created_at_utc = Some("2026-11-12T00:00:00Z".to_string());
        let mut old = draft();
        old.run_id = "d2".to_string();
        old.created_at_utc = Some("2026-11-01T00:00:00Z".to_string());
        // 不是草稿的不进统计——哪怕它比草稿还旧。
        let mut done = draft();
        done.state = STATE_COMPLETE.to_string();
        done.created_at_utc = Some("2026-10-01T00:00:00Z".to_string());
        // 归档的草稿也不进：用户已经把它收起来了。
        let mut archived = draft();
        archived.run_id = "d3".to_string();
        archived.created_at_utc = Some("2026-10-01T00:00:00Z".to_string());
        archived.archived_at_utc = Some("2026-11-10T00:00:00Z".to_string());

        let summary = draft_summary(&[fresh.clone(), old, done, archived], now);
        assert_eq!(summary["Count"], serde_json::json!(2));
        assert_eq!(summary["OldestDays"], serde_json::json!(13));
        assert_eq!(summary["HasAge"], serde_json::json!(true));
        assert_eq!(summary["Stale"], serde_json::json!(true));
        let text = summary["Summary"].as_str().unwrap_or("");
        assert!(text.contains("2 份") && text.contains("13 天"), "{text}");
        let hint = summary["Hint"].as_str().unwrap_or("");
        assert!(hint.contains("7 天"), "提示要说清阈值：{hint}");
        assert!(hint.contains("不会自己消失"), "必须说清不自动过期：{hint}");

        // 时间戳缺失 = 时龄未知：不出现天数，也不许说「0 天」（那会被读成刚建的）。
        let mut unknown = draft();
        unknown.created_at_utc = None;
        let summary = draft_summary(&[unknown], now);
        assert_eq!(summary["HasAge"], serde_json::json!(false));
        assert_eq!(summary["OldestDays"], serde_json::json!(0));
        assert_eq!(summary["Stale"], serde_json::json!(false));
        assert_eq!(
            summary["Summary"],
            serde_json::json!("1 份没填完的部署。"),
            "未知时龄不许写天数"
        );

        // 一份都没有：空串，页面据此不显示这一块。
        let empty = draft_summary(&[], now);
        assert_eq!(empty["Count"], serde_json::json!(0));
        assert_eq!(empty["Summary"], serde_json::json!(""));
        assert_eq!(empty["Hint"], serde_json::json!(""));
    }

    /// 归档的条目只出现在「已归档」，并且带着筛选要用的状态词与原因类别。
    #[test]
    fn an_archived_record_goes_only_into_the_archived_projection() {
        let mut run = draft();
        run.state = STATE_NEEDS_ATTENTION.to_string();
        run.reason = Some(reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT));
        run.archived_at_utc = Some("2026-11-12T12:00:00Z".to_string());

        assert!(
            project_tasks(std::slice::from_ref(&run), |_| false).is_empty(),
            "归档的不能出现在「未完成的添加」"
        );
        assert!(
            project_deployments(std::slice::from_ref(&run), |_| false, NOW).is_empty(),
            "归档的不能出现在底部队列"
        );
        let archived = project_archived(std::slice::from_ref(&run));
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0]["StateText"], serde_json::json!("需要处理"));
        // 筛选（P2-1）按类别分「失败 / 结果未知 / …」：投影必须带出来。
        assert_eq!(archived[0]["ReasonCategory"], serde_json::json!("Failed"));
        assert_eq!(
            archived[0]["ArchivedAtUtc"],
            serde_json::json!("2026-11-12T12:00:00Z")
        );
    }

    /// 重试 = 记录上的新一次尝试；第一次的结论必须原样留着。
    #[test]
    fn a_retry_appends_a_new_attempt_and_keeps_the_previous_conclusion() {
        let mut run = draft();
        // 第一次还没开始：没有结论，不追加。
        assert!(!begin_attempt(&mut run, "2026-11-12T10:00:00Z"));
        assert_eq!(run.attempts.len(), 1);

        // 第一次失败收尾。第二次收尾不许覆盖第一次的结论。
        assert!(finish_attempt(
            &mut run,
            "2026-11-12T10:05:00Z",
            Some(1),
            "ListenFailed"
        ));
        assert!(!finish_attempt(
            &mut run,
            "2026-11-12T10:09:00Z",
            Some(2),
            "Other"
        ));
        assert_eq!(run.attempts[0].failed_step, Some(1));
        assert_eq!(run.attempts[0].error_code, "ListenFailed");
        assert_eq!(
            run.attempts[0].finished_at_utc.as_deref(),
            Some("2026-11-12T10:05:00Z")
        );

        // 上一次有结论 → 新的一次，编号 +1，上一次不被清空。
        assert!(begin_attempt(&mut run, "2026-11-12T10:10:00Z"));
        assert_eq!(run.attempts.len(), 2);
        assert_eq!(run.attempts[1].no, 2);
        assert!(run.attempts[1].finished_at_utc.is_none());
        assert_eq!(run.attempts[0].error_code, "ListenFailed");
    }

    /// 「需要核对 / 已核对」只跟着真实的核对走：没需要过就不许写 `Done`。
    #[test]
    fn reconcile_flags_follow_the_real_reconcile() {
        let mut run = draft();
        finish_attempt(&mut run, "2026-11-12T10:05:00Z", Some(1), "ListenFailed");
        mark_attempt_reconciled(&mut run);
        assert_eq!(
            run.attempts[0].reconcile, RECONCILE_NOT_NEEDED,
            "一次都没发生过未决写，不许写「已核对」"
        );
        mark_attempt_needs_reconcile(&mut run);
        assert_eq!(run.attempts[0].reconcile, RECONCILE_NEEDED);
        mark_attempt_reconciled(&mut run);
        assert_eq!(run.attempts[0].reconcile, RECONCILE_DONE);
    }

    /// 被强杀的那次尝试也必须有结论，否则下一次重试会把它吞成同一条。
    #[test]
    fn a_recovered_record_closes_the_interrupted_attempt_at_the_last_heartbeat() {
        let ours = i64::from(std::process::id());
        let before = executing(STATE_RUNNING, 424_242, Some(NOW - 600));
        let heartbeat = crate::deploystore::stamp_utc(NOW - 600);
        let (after, _) = rewritten(recover(&before, ours, NOW, false));
        assert!(
            after.attempts[0].finished_at_utc.is_some(),
            "被打断也要有结论，否则重试会接在同一条上"
        );
        assert_eq!(
            after.attempts[0].finished_at_utc.as_deref(),
            Some(heartbeat.as_str()),
            "结束时间取最后一拍心跳，不是判定时刻"
        );
        assert_eq!(after.attempts[0].error_code, "Interrupted");
        assert_eq!(after.attempts[0].failed_step, None, "没有哪一步是「失败」");
        assert_eq!(after.attempts.len(), before.attempts.len());
        assert_eq!(after.attempts[0].no, before.attempts[0].no);
        assert_eq!(
            after.attempts[0].started_at_utc, before.attempts[0].started_at_utc,
            "这是同一次尝试的结束，不是新的一次"
        );
    }

    /// 状态机的白名单逐条断言。这条用例的用途不是「跑一遍」，而是
    /// **任何一次偷偷放宽都必然让它红**。
    #[test]
    fn the_state_machine_only_allows_the_listed_transitions() {
        // 正向：产品主链
        assert!(transition_ok(STATE_DRAFT, STATE_WAITING_USER));
        assert!(transition_ok(STATE_WAITING_USER, STATE_QUEUED));
        assert!(transition_ok(STATE_QUEUED, STATE_RUNNING));
        assert!(transition_ok(STATE_RUNNING, STATE_COMPLETE));
        assert!(transition_ok(STATE_RUNNING, STATE_PAUSED));
        assert!(transition_ok(STATE_PAUSED, STATE_QUEUED));
        assert!(transition_ok(STATE_NEEDS_ATTENTION, STATE_QUEUED));
        assert!(transition_ok(STATE_NEEDS_ATTENTION, STATE_COMPLETE));
        assert!(transition_ok(STATE_NEEDS_ATTENTION, STATE_CANCELLED));

        // 反向：绝不能有的那几条
        assert!(!transition_ok(STATE_NEEDS_ATTENTION, STATE_RUNNING), "必须经 Queued");
        assert!(!transition_ok(STATE_PAUSED, STATE_RUNNING), "必须重新拿 lane");
        assert!(!transition_ok(STATE_COMPLETE, STATE_RUNNING), "终态不得外流");
        assert!(!transition_ok(STATE_CANCELLED, STATE_QUEUED), "终态不得外流");
        assert!(!transition_ok(STATE_DRAFT, STATE_RUNNING), "草稿不能直接跑");
        assert!(!transition_ok(STATE_QUEUED, STATE_COMPLETE), "没跑过不能算完成");

        // 同状态写自己永远合法（一遍 pass 里会反复更新同一条记录）
        for state in STATES {
            assert!(transition_ok(state, state), "{state} 写自己必须合法");
        }
    }

    /// 表外值：两个方向都不合法。这条挡住「加状态忘了加白名单 → 一路绿灯」。
    #[test]
    fn an_unknown_state_cannot_be_entered_or_left() {
        assert!(!transition_ok("running", STATE_QUEUED), "大小写敏感");
        assert!(!transition_ok(STATE_QUEUED, "Finished"));
        assert!(!transition_ok("", STATE_QUEUED));
        assert!(!transition_ok(STATE_QUEUED, ""));
        assert!(!transition_ok("", ""), "空对空也不行：那是两个未知");
    }

    /// 词表外一律视为未知 —— 不做 `_ => 默认值`。
    #[test]
    fn values_outside_the_vocabulary_are_unknown_not_defaults() {
        assert!(state_is_known(STATE_NEEDS_ATTENTION));
        assert!(!state_is_known("Unknown"));
        assert!(!state_is_known(""));

        assert!(reason_category_is_known(crate::deploystore::REASON_OUTCOME_UNKNOWN));
        assert!(!reason_category_is_known("Whatever"));

        assert!(error_class_is_known(crate::deploystore::ERROR_CLASS_CONFIG));
        assert!(!error_class_is_known("Config"), "错误类别区分大小写");

        assert!(next_action_is_known(crate::deploystore::NEXT_ACTION_RECONCILE));
        assert!(!next_action_is_known("Retry"), "表外动作不得进入按钮映射");

        assert!(step_status_is_known(crate::deploystore::STEP_STATUS_PARTIAL));
        assert!(!step_status_is_known("done"));

        assert!(pending_kind_is_known(crate::deploystore::PENDING_KIND_ADD_PEER));
        assert!(!pending_kind_is_known("SomethingNew"));

        assert!(verify_by_is_known(crate::deploystore::VERIFY_BY_READ_TRANSPORT));
        assert!(!verify_by_is_known(""));

        assert!(outcome_is_known(crate::deploystore::OUTCOME_APPLIED));
        assert!(!outcome_is_known("Maybe"));
    }

    /// 新草稿的形状：四步全 Pending、状态 Draft、Revision 0（落盘才变 1）。
    #[test]
    fn a_draft_starts_with_four_pending_steps_and_no_revision() {
        let run = draft();
        assert_eq!(run.state, STATE_DRAFT);
        assert_eq!(run.revision, 0);
        assert_eq!(run.steps.len(), STEP_COUNT);
        assert_eq!(run.next_action, NEXT_ACTION_OPEN_FORM);
        assert_eq!(steps_done(&run), 0);
        assert_eq!(current_step(&run), Some(0));
        assert_eq!(run.attempts.len(), 1);
        assert_eq!(run.attempts[0].reconcile, RECONCILE_NOT_NEEDED);
        for (index, step) in run.steps.iter().enumerate() {
            assert_eq!(usize::from(step.index), index);
            assert_eq!(step.name, STEP_NAMES[index]);
            assert_eq!(step.status, crate::deploystore::STEP_STATUS_PENDING);
            assert!(
                step.evidence.is_null(),
                "没有证据就是 Null，不能塞一个空对象"
            );
        }
        assert!(tf_progress_is_readable(&run), "草稿的进度必须是可读的 0/4");
    }

    fn tf_progress_is_readable(run: &RunRecord) -> bool {
        progress_text(run).as_deref() == Some("0/4 · 检查服务器环境与身份")
    }

    /// `N/4` 数的是 Done 的**个数**，不是前缀长度；Partial 不算完成。
    #[test]
    fn steps_done_counts_done_only_and_ignores_the_prefix() {
        let mut run = draft();
        run.steps[0].status = crate::deploystore::STEP_STATUS_DONE.to_string();
        run.steps[1].status = crate::deploystore::STEP_STATUS_DONE.to_string();
        run.steps[2].status = crate::deploystore::STEP_STATUS_PARTIAL.to_string();
        run.steps[3].status = crate::deploystore::STEP_STATUS_DONE.to_string();
        assert_eq!(steps_done(&run), 3, "Partial 不算完成");
        assert_eq!(current_step(&run), Some(2), "当前步骤是第一个没 Done 的");
        assert_eq!(current_step_name(&run), STEP_NAMES[2]);

        for step in run.steps.iter_mut() {
            step.status = crate::deploystore::STEP_STATUS_DONE.to_string();
        }
        assert_eq!(steps_done(&run), 4);
        assert_eq!(current_step(&run), Some(4), "全 Done → 4");
        assert_eq!(progress_text(&run).as_deref(), Some("4/4"));
    }

    /// 没有任何步骤信息时，`N/4` 不显示 —— 不能显示 0/4（那会被读成「一步没做」）。
    #[test]
    fn a_record_without_steps_has_no_progress_text() {
        let mut run = draft();
        run.steps.clear();
        assert_eq!(current_step(&run), None);
        assert_eq!(progress_text(&run), None);
        assert_eq!(current_step_name(&run), "步骤未知");
    }

    /// `Running` 与 `CanBackground` 都要求引擎里真有活动 pass。
    #[test]
    fn running_and_background_both_require_a_live_pass() {
        let mut run = draft();
        run.state = STATE_RUNNING.to_string();
        assert!(!is_running(&run, false), "没有活动的 pass 就不是 Running");
        assert!(is_running(&run, true));
        assert!(can_background(&run, true));
        assert!(!can_background(&run, false), "没有执行上下文就不能转后台");

        run.reason = Some(Reason::now(
            crate::deploystore::REASON_FAILED,
            crate::deploystore::ERROR_CLASS_NETWORK,
            "NoMarker",
            "上次没有跑完。",
        ));
        assert!(!can_background(&run, true), "带原因的记录不许转后台");
    }

    /// 未决写的判别：只有 `Pending` 才算「写已发出、还没核对」。
    #[test]
    fn an_unverified_write_is_only_the_pending_outcome() {
        let mut run = draft();
        run.state = STATE_RUNNING.to_string();
        assert!(!has_unverified_write(&run));
        let mut pending = crate::deploystore::PendingOperation {
            kind: crate::deploystore::PENDING_KIND_UDP_INSTALL.to_string(),
            attempt_no: 1,
            started_at_utc: Some("2026-11-08T09:10:00Z".to_string()),
            verify_by: crate::deploystore::VERIFY_BY_PROBE_UDP_STATE.to_string(),
            plan_digest: "sha256:abc".to_string(),
            client_public_key: None,
            outcome: crate::deploystore::OUTCOME_PENDING.to_string(),
        };
        run.pending_operation = Some(pending.clone());
        assert!(has_unverified_write(&run), "Pending 必须算未核对");
        assert!(can_background(&run, true), "Pending 时它本来就在后台跑");

        pending.outcome = crate::deploystore::OUTCOME_APPLIED.to_string();
        run.pending_operation = Some(pending.clone());
        assert!(!has_unverified_write(&run), "核对过就不算未核对");

        pending.outcome = String::new();
        run.pending_operation = Some(pending);
        assert!(has_unverified_write(&run), "结论未知按未核对处理（更保守）");
    }

    // ---------- T03：pass 计划、回退、结算 ----------

    fn reason(category: &str, class: &str) -> Reason {
        Reason::now(category, class, "Test", "测试用原因。")
    }

    /// 终态 / 有未决写 / 全 Done：三种都**不产生执行意图**。
    #[test]
    fn a_pass_refuses_to_start_in_three_cases() {
        let mut run = draft();
        run.state = STATE_COMPLETE.to_string();
        assert_eq!(plan_pass(&run), PassDecision::Refuse(PassRefusal::Terminal));

        let mut run = draft();
        run.state = STATE_NEEDS_ATTENTION.to_string();
        run.pending_operation = Some(crate::deploystore::PendingOperation {
            kind: crate::deploystore::PENDING_KIND_UDP_INSTALL.to_string(),
            attempt_no: 1,
            started_at_utc: None,
            verify_by: crate::deploystore::VERIFY_BY_PROBE_UDP_STATE.to_string(),
            plan_digest: String::new(),
            client_public_key: None,
            outcome: crate::deploystore::OUTCOME_PENDING.to_string(),
        });
        assert_eq!(
            plan_pass(&run),
            PassDecision::Refuse(PassRefusal::UnverifiedWrite),
            "有未决写时只能核对，不能开始新一轮"
        );

        let mut run = draft();
        for step in run.steps.iter_mut() {
            step.status = STEP_STATUS_DONE.to_string();
        }
        run.state = STATE_RUNNING.to_string();
        assert_eq!(plan_pass(&run), PassDecision::Refuse(PassRefusal::AllDone));
    }

    /// 部分完成：从第一个没 Done 的步骤开始，已 Done 的上游进 `verify`（只读核对）。
    #[test]
    fn a_pass_plans_from_the_first_unfinished_step() {
        let mut run = draft();
        run.steps[0].status = STEP_STATUS_DONE.to_string();
        run.steps[1].status = STEP_STATUS_DONE.to_string();
        run.state = STATE_RUNNING.to_string();

        let PassDecision::Run(plan) = plan_pass(&run) else {
            panic!("应当可以跑");
        };
        assert_eq!(plan.resume_from, 2);
        assert_eq!(plan.verify, vec![0, 1], "已 Done 的两步都要重新核对");

        // 第二步也 Done 就只有第一步进 verify。
        let mut later = draft();
        for index in 0..3 {
            later.steps[index].status = STEP_STATUS_DONE.to_string();
        }
        let PassDecision::Run(plan) = plan_pass(&later) else {
            panic!("应当可以跑");
        };
        assert_eq!(plan.resume_from, 3);
        assert_eq!(plan.verify, vec![0, 1, 2]);
    }

    /// 上游核对：失效就**只回退到那一步**，不从头重来；身份变了完全不跑。
    #[test]
    fn resume_rolls_back_only_to_the_broken_step() {
        let plan = PassPlan {
            resume_from: 3,
            verify: vec![0, 1, 2],
        };

        // 全都没问题：从原计划继续。
        let ok = UpstreamFacts {
            udp_matches_plan: Some(true),
            transport_matches_plan: Some(true),
            lines_present: Some(true),
            identity_matches: Some(true),
        };
        assert_eq!(decide_resume(&plan, &ok), ResumeDecision::From(3));

        // UDP 掉了：回第 1 步（0 步的证据还能用）。
        let udp_lost = UpstreamFacts {
            udp_matches_plan: Some(false),
            ..ok.clone()
        };
        assert_eq!(decide_resume(&plan, &udp_lost), ResumeDecision::From(1));

        // UDP 在、TCP 没了：回第 2 步。
        let tcp_lost = UpstreamFacts {
            transport_matches_plan: None,
            ..ok.clone()
        };
        assert_eq!(decide_resume(&plan, &tcp_lost), ResumeDecision::From(2));

        // 线路被删：回第 3 步重新登记。
        let lines_lost = UpstreamFacts {
            lines_present: Some(false),
            ..ok.clone()
        };
        assert_eq!(decide_resume(&plan, &lines_lost), ResumeDecision::From(3));

        // 身份变了：不跑。
        let identity = UpstreamFacts {
            identity_matches: Some(false),
            ..ok.clone()
        };
        assert_eq!(decide_resume(&plan, &identity), ResumeDecision::IdentityChanged);

        // TCP 读到了但对不上：不能静默沿用。
        let mismatch = UpstreamFacts {
            transport_matches_plan: Some(false),
            ..ok
        };
        assert_eq!(decide_resume(&plan, &mismatch), ResumeDecision::NeedsRecovery);
    }

    /// 结算：四种结果各自落在哪个状态与主行动作上。
    #[test]
    fn settling_a_step_lands_on_the_documented_state_and_action() {
        let now = "2026-11-09T00:00:00Z";
        let mut run = draft();
        run.state = STATE_RUNNING.to_string();

        settle_step(
            &mut run,
            0,
            StepOutcome::Done {
                evidence: serde_json::json!({"arch": "x86_64"}),
            },
            now,
        )
        .unwrap();
        assert!(run.steps[0].is_done());
        assert_eq!(run.step, Some(1), "Done 之后前进到下一步");
        assert_eq!(run.state, STATE_RUNNING);

        let mut failed = draft();
        failed.state = STATE_RUNNING.to_string();
        settle_step(
            &mut failed,
            1,
            StepOutcome::Failed {
                reason: reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT),
            },
            now,
        )
        .unwrap();
        assert_eq!(failed.state, STATE_NEEDS_ATTENTION);
        assert_eq!(failed.next_action, crate::deploystore::NEXT_ACTION_RETRY_STEP);
        assert_eq!(failed.step, Some(1), "失败不退步下标");

        let mut unknown = draft();
        unknown.state = STATE_RUNNING.to_string();
        settle_step(
            &mut unknown,
            1,
            StepOutcome::Unknown {
                reason: reason(REASON_OUTCOME_UNKNOWN, crate::deploystore::ERROR_CLASS_NETWORK),
            },
            now,
        )
        .unwrap();
        assert_eq!(unknown.next_action, crate::deploystore::NEXT_ACTION_RECONCILE);
        assert_eq!(
            unknown.steps[1].status,
            crate::deploystore::STEP_STATUS_UNKNOWN
        );

        let mut partial = draft();
        partial.state = STATE_RUNNING.to_string();
        for index in [0, 3] {
            partial.steps[index].status = STEP_STATUS_DONE.to_string();
        }
        settle_step(
            &mut partial,
            2,
            StepOutcome::Partial {
                evidence: serde_json::Value::Null,
                reason: reason(REASON_PARTIAL, crate::deploystore::ERROR_CLASS_ENVIRONMENT),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            partial.next_action,
            crate::deploystore::NEXT_ACTION_COMPLETE_COMPATIBLE,
            "TCP 没装上 → 补齐兼容连接"
        );
        assert_eq!(partial.reason.as_ref().unwrap().category, REASON_PARTIAL);
    }

    /// 终态上再结算必须被状态机拒绝（这是「不许把 Complete 改回 Running」的最后一道闸）。
    #[test]
    fn settling_onto_a_terminal_record_is_refused() {
        let mut run = draft();
        run.state = STATE_COMPLETE.to_string();
        let error = settle_step(
            &mut run,
            0,
            StepOutcome::Failed {
                reason: reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT),
            },
            "2026-11-09T00:00:00Z",
        )
        .expect_err("终态不得流转");
        assert!(error.contains("状态机不允许"), "{error}");
    }

    // ---------- T05：任务投影 ----------

    fn with_state(mut run: RunRecord, state: &str, updated: &str) -> RunRecord {
        run.state = state.to_string();
        run.updated_at_utc = Some(updated.to_string());
        run
    }

    /// `Tasks`：终态不在里面；分组次序按架构文档；同组按更新时间倒序。
    #[test]
    fn tasks_exclude_terminal_runs_and_follow_the_documented_order() {
        let attention = with_state(
            draft(),
            STATE_NEEDS_ATTENTION,
            "2026-11-09T01:00:00Z",
        );
        let mut running = draft();
        running.run_id = "aaaaaaaa-1111-4111-8111-111111111111".to_string();
        let running = with_state(running, STATE_RUNNING, "2026-11-09T03:00:00Z");
        let mut queued = draft();
        queued.run_id = "bbbbbbbb-1111-4111-8111-111111111111".to_string();
        let queued = with_state(queued, STATE_QUEUED, "2026-11-09T02:00:00Z");
        let mut draft_run = draft();
        draft_run.run_id = "cccccccc-1111-4111-8111-111111111111".to_string();
        let draft_run = with_state(draft_run, STATE_DRAFT, "2026-11-09T04:00:00Z");
        let mut done = draft();
        done.run_id = "dddddddd-1111-4111-8111-111111111111".to_string();
        let done = with_state(done, STATE_COMPLETE, "2026-11-09T05:00:00Z");

        let runs = vec![done, draft_run, queued, running, attention];
        let tasks = project_tasks(&runs, |_| false);

        let ids: Vec<&str> = tasks
            .iter()
            .map(|task| task["Id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 4, "终态不进 Tasks：{tasks:?}");
        assert_eq!(ids[3], "cccccccc-1111-4111-8111-111111111111", "Draft 排最后");
        assert_eq!(ids[2], "bbbbbbbb-1111-4111-8111-111111111111", "Queued 在 Draft 之前");
        assert_eq!(ids[1], "aaaaaaaa-1111-4111-8111-111111111111", "Running 在 NeedsAttention 之后");
        assert!(
            !ids.contains(&"dddddddd-1111-4111-8111-111111111111"),
            "Complete 不该出现"
        );
        // 没有原因时**不写** `ReasonCategory` 键：前端靠「缺失」决定不显示那一行。
        assert!(tasks[0].get("ReasonCategory").is_none(), "{:?}", tasks[0]);
    }

    /// `NeedsAttention` 的任务标题要带原因；`N/4` 用 Done 的**个数**而不是前缀长度。
    #[test]
    fn a_task_label_carries_the_reason_only_when_something_needs_attention() {
        let mut run = draft();
        run.state = STATE_NEEDS_ATTENTION.to_string();
        run.steps[0].status = STEP_STATUS_DONE.to_string();
        run.steps[1].status = STEP_STATUS_DONE.to_string();
        run.steps[2].status = crate::deploystore::STEP_STATUS_FAILED.to_string();
        run.reason = Some(reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT));
        let label = task_label(&run);
        assert!(label.starts_with("2/4"), "{label}");
        // 记录里有现成文案就用它（`humanize` 优先取 `Text`），没有才按类别兜底。
        assert!(label.contains("测试用原因"), "{label}");

        let mut healthy = draft();
        healthy.steps[0].status = STEP_STATUS_DONE.to_string();
        healthy.state = STATE_RUNNING.to_string();
        assert_eq!(task_label(&healthy), "1/4 · 准备标准连接");
        assert!(
            !task_label(&healthy).contains('：'),
            "没问题就不该追加原因"
        );
    }

    /// 底部队列：终态只留 24 小时内的；`Running` 必须同时满足「记录 Running」+「引擎里有」。
    #[test]
    fn deployments_keep_recent_terminal_runs_and_require_a_live_pass_for_running() {
        let now = 1_800_000_000u64;
        let mut fresh = draft();
        fresh.run_id = "aaaaaaaa-1111-4111-8111-111111111111".to_string();
        fresh.state = STATE_COMPLETE.to_string();
        fresh.finished_at_utc = Some(crate::deploystore::stamp_utc(now - 60 * 60));
        let mut stale = draft();
        stale.run_id = "bbbbbbbb-1111-4111-8111-111111111111".to_string();
        stale.state = STATE_COMPLETE.to_string();
        stale.finished_at_utc = Some(crate::deploystore::stamp_utc(now - 48 * 60 * 60));
        let mut crashed = draft();
        crashed.run_id = "cccccccc-1111-4111-8111-111111111111".to_string();
        crashed.state = STATE_RUNNING.to_string();

        let runs = vec![fresh, stale, crashed];
        let live = project_deployments(&runs, |_| false, now);
        assert_eq!(live.len(), 2, "48 小时前的终态不进底部队列：{live:?}");
        assert!(
            live.iter().all(|item| item["Running"] == serde_json::json!(false)),
            "引擎里没有活动 pass 时 Running 必须为假"
        );

        let alive = project_deployments(&runs, |id| id.starts_with("cccccccc"), now);
        let running = alive
            .iter()
            .find(|item| item["State"] == serde_json::json!(STATE_RUNNING))
            .expect("Running 那条要在列表里");
        assert_eq!(running["Running"], serde_json::json!(true));
    }

    /// 投影里的 `Action`：终态只读；有未决写只给核对；其余按 `NextAction` 走。
    #[test]
    fn the_single_action_follows_the_pending_operation_first() {
        let mut run = draft();
        run.state = STATE_NEEDS_ATTENTION.to_string();
        run.next_action = crate::deploystore::NEXT_ACTION_RETRY_STEP.to_string();
        assert_eq!(action_of(&run), ("continue", "重试本步骤"));

        // 有未决写：只能核对——这是「重发写命令」与「只读核对」之间的那道闸。
        run.pending_operation = Some(crate::deploystore::PendingOperation {
            kind: crate::deploystore::PENDING_KIND_UDP_INSTALL.to_string(),
            attempt_no: 1,
            started_at_utc: None,
            verify_by: crate::deploystore::VERIFY_BY_PROBE_UDP_STATE.to_string(),
            plan_digest: String::new(),
            client_public_key: None,
            outcome: crate::deploystore::OUTCOME_PENDING.to_string(),
        });
        assert_eq!(action_of(&run), ("reconcile", "核对原操作"));

        let mut done = draft();
        done.state = STATE_COMPLETE.to_string();
        assert_eq!(action_of(&done), ("viewLine", "查看线路"));
        let mut cancelled = draft();
        cancelled.state = STATE_CANCELLED.to_string();
        assert_eq!(action_of(&cancelled), ("view", "查看"));
    }

    // ---------- 夹具：12 种记录形状 + 1 个坏文件 ----------
    //
    // 夹具是**磁盘形状**（`fixtures/deployment-runs/*.json`），不是内存里的构造：
    // 它同时钉住 `from_json` 的宽容口径与投影口径。字段名改错、状态漏加、
    // 动作表漂移，这三种都会在这里红。

    fn fixture_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/deployment-runs")
    }

    /// 12 种记录形状。文件名是给人读的，**不是** RunId——真记录的文件名必须是
    /// UUID（`DeploymentStore` 靠它防路径穿越），所以走 `load_all` 的那条用例
    /// 会先把它们复制成 UUID 文件名，见下。
    const FIXTURES: [&str; 12] = [
        "draft.json",
        "waiting-user.json",
        "queued.json",
        "running.json",
        "paused.json",
        "attention-retry.json",
        "attention-unknown.json",
        "attention-credentials.json",
        "partial.json",
        "complete.json",
        "cancelled.json",
        "unknown-state.json",
    ];

    fn load_fixture(name: &str) -> RunRecord {
        let path = fixture_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("读不到夹具 {}：{error}", path.display()));
        let value: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{name} 不是合法 JSON：{error}"));
        RunRecord::from_json(&value).unwrap_or_else(|error| panic!("{name} 读不成记录：{error}"))
    }

    /// 12 种状态各一份：状态 → 唯一主动作 → `N/4` 必须一起对上。
    #[test]
    fn every_fixture_projects_to_the_documented_action_and_progress() {
        let cases: [(&str, &str, &str, &str, u32); 12] = [
            ("draft.json", STATE_DRAFT, "resume", "继续填写", 0),
            ("waiting-user.json", STATE_WAITING_USER, "confirm", "重新确认", 1),
            ("queued.json", STATE_QUEUED, "resume", "查看", 1),
            ("running.json", STATE_RUNNING, "resume", "查看", 2),
            ("paused.json", STATE_PAUSED, "resume", "继续", 2),
            ("attention-retry.json", STATE_NEEDS_ATTENTION, "continue", "重试本步骤", 1),
            ("attention-unknown.json", STATE_NEEDS_ATTENTION, "reconcile", "核对原操作", 1),
            (
                "attention-credentials.json",
                STATE_NEEDS_ATTENTION,
                "enterCredentials",
                "输入密码继续",
                0,
            ),
            (
                "partial.json",
                STATE_NEEDS_ATTENTION,
                "completeCompatible",
                "补齐兼容连接",
                3,
            ),
            ("complete.json", STATE_COMPLETE, "viewLine", "查看线路", 4),
            ("cancelled.json", STATE_CANCELLED, "view", "查看", 1),
            // 表外状态：不许显示成完成，也不许显示成进行中。
            ("unknown-state.json", "", "resume", "查看", 0),
        ];

        for (file, state, action, action_label, done) in cases {
            let run = load_fixture(file);
            assert_eq!(run.state, state, "{file}");
            assert_eq!(run.steps.len(), STEP_COUNT, "{file} 必须有四步");
            assert_eq!(steps_done(&run), done, "{file} 的 StepsDone");
            assert_eq!(action_of(&run), (action, action_label), "{file} 的唯一主动作");
            let label = task_label(&run);
            if state == STATE_DRAFT {
                // 草稿一步都没跑过：`0/4 · 检查服务器环境与身份` 会让任务卡写着
                // 「正在检查服务器」，而它连一次握手都没发生。标题行只许说「未开始」。
                assert_eq!(label, "未开始", "{file} 的 Label");
                assert!(
                    !label.contains("检查服务器环境"),
                    "{file} 的 Label 不许出现步骤名：{label}"
                );
                continue;
            }
            assert!(
                label.starts_with(&format!("{done}/4")),
                "{file} 的 Label 应以 {done}/4 开头，实际是 {label}"
            );
            // `NeedsAttention` 必须带上原因；其余的标题里不该出现「：」。
            if state == STATE_NEEDS_ATTENTION {
                assert!(label.contains('：'), "{file} 的 Label 缺原因：{label}");
            } else {
                assert!(!label.contains('：'), "{file} 不该带原因：{label}");
            }
        }
    }

    /// 草稿的任务卡标题行只能说「未开始」。
    ///
    /// 为什么值得一条独立用例：`web/app.js` 的任务卡**只渲染 `Label`、不渲染
    /// `StateText`**。而 `new_draft` 把 `step` 设成 `Some(0)`，`progress_text` 于是
    /// 老老实实算出「0/4 · 检查服务器环境与身份」——界面上就写着「正在检查服务器环境」，
    /// 可这条记录一次握手都没发生。这类「状态说假话」是这个产品最不能出的错。
    #[test]
    fn a_draft_card_says_not_started_and_never_names_a_step() {
        let run = draft();
        assert_eq!(run.state, STATE_DRAFT);
        assert_eq!(current_step(&run), Some(0), "新草稿的 Step 就是 0（这正是坑的来源）");
        assert_eq!(task_label(&run), "未开始");
        assert!(!task_label(&run).contains("检查服务器环境"));
        // 与状态词、任务条一句话同口径：一处「未开始」，三处都读它。
        assert_eq!(state_text(STATE_DRAFT), "未开始");
        assert_eq!(summary_of(&run), "未开始");

        // 记录名（标题）**不许**被顺手改掉：详情页标题只能用 `Name`。
        let view = run_view(&run, false);
        assert_eq!(view["Name"], serde_json::json!("自建 · 203.0.113.10"));
        assert_eq!(view["Label"], serde_json::json!("未开始"), "进度标签才是未开始");
        assert_eq!(view["State"], serde_json::json!("Draft"));
        assert_eq!(view["StepsDone"], serde_json::json!(0));
        assert_eq!(view["ActionLabel"], serde_json::json!("继续填写"));

        // 非草稿不受影响：同一条记录一旦开始，标题行就该回到 `N/4 · 步骤名`。
        let mut started = draft();
        started.state = STATE_QUEUED.to_string();
        started.next_action = crate::deploystore::NEXT_ACTION_WAIT_QUEUE.to_string();
        assert!(
            task_label(&started).starts_with("0/4"),
            "开始之后必须回到进度标签：{}",
            task_label(&started)
        );
    }

    /// 「转后台」只在**真的有 pass 在跑**时成立：同一条 `running.json`，
    /// 引擎里有它才是 true，没有就是 false（崩溃后不许假装还在跑）。
    #[test]
    fn the_running_fixture_only_counts_as_running_with_a_live_pass() {
        let run = load_fixture("running.json");
        assert!(can_background(&run, true), "有活动 pass 时可以转后台");
        assert!(!can_background(&run, false), "没有活动 pass 时不许转后台");
        assert!(!is_running(&run, false));

        // 完成 / 失败 / 有原因：一律不许转后台（关掉页面等于让人以为还在跑）。
        for file in ["complete.json", "attention-retry.json", "attention-unknown.json"] {
            let run = load_fixture(file);
            assert!(!can_background(&run, true), "{file} 不该允许转后台");
        }
    }

    /// 整套夹具走一遍 `load_all`：坏文件只让整体降级为 `partial`，不吞掉其余记录。
    /// 这正是页面「有 N 条读不出来 + 刷新」那条路径的真实输入。
    ///
    /// 夹具文件名是给人读的，而真实记录的文件名必须是 UUID，所以这里复制一份并
    /// 逐个改写 `RunId`——顺带证明「文件名和 RunId 对不上就会被拒绝」。
    #[test]
    fn the_fixture_set_loads_as_partial_with_one_unreadable_file() {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-deploy-fixtures-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run_id = |index: usize| format!("00000000-0000-4000-8000-{index:012x}");

        for (index, file) in FIXTURES.iter().enumerate() {
            let text = std::fs::read_to_string(fixture_dir().join(file)).expect("夹具必须在仓库里");
            let mut value: serde_json::Value = serde_json::from_str(&text).expect("夹具必须是 JSON");
            value["RunId"] = serde_json::json!(run_id(index));
            std::fs::write(
                dir.join(format!("{}.json", run_id(index))),
                value.to_string(),
            )
            .unwrap();
        }
        // 第 13 个：坏文件。它必须进 `unreadable`，而不是让整份列表变空。
        std::fs::write(dir.join(format!("{}.json", run_id(99))), b"{ not json").unwrap();

        let loaded = crate::deploystore::DeploymentStore::at(&dir).load_all();
        assert_eq!(loaded.tasks_read, crate::deploystore::READ_PARTIAL);
        assert_eq!(loaded.unreadable.len(), 1, "{:?}", loaded.unreadable);
        assert_eq!(loaded.runs.len(), 12, "12 条能读的记录一条都不许丢");
        assert!(!loaded.error.is_empty(), "partial 必须给一句人话");

        // 未完成 10 条（12 减去 complete / cancelled 两份终态）。
        let tasks = project_tasks(&loaded.runs, |_| false);
        assert_eq!(tasks.len(), 10);
        // 底部队列：**不含 Draft**（还没开始的草稿不属于「正在发生的事」），
        // 但两份终态都在（今天刚结束，仍在 24 小时内）→ 12 - 1 = 11。
        let now = crate::deploystore::parse_stamp(
            &load_fixture("complete.json").finished_at_utc.unwrap(),
        )
        .unwrap();
        let deployments = project_deployments(&loaded.runs, |_| false, now);
        assert_eq!(deployments.len(), 11);
        assert!(
            deployments
                .iter()
                .all(|item| item["State"] != serde_json::json!(STATE_DRAFT)),
            "草稿不该出现在底部队列里"
        );
        assert!(
            deployments.iter().all(|item| item["Running"] == serde_json::json!(false)),
            "没有活动 pass，谁都不许是 Running"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 坏文件本身必须读不出来（否则上面那条 `partial` 就是假的）。
    #[test]
    fn the_damaged_fixture_is_really_unreadable() {
        let path = fixture_dir().join("damaged.json");
        let text = std::fs::read_to_string(&path).expect("坏文件也要在仓库里");
        let outcome = serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|error| error.to_string())
            .and_then(|value| RunRecord::from_json(&value));
        assert!(outcome.is_err(), "damaged.json 必须被拒绝：{outcome:?}");
    }

    /// `humanize` 只在没有现成文案时兜底；它**不接受**任何秘密参数（签名就是证据）。
    #[test]
    fn humanize_prefers_the_stored_text_and_falls_back_by_category() {
        let mut with_text = reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT);
        with_text.text = "服务器上没有 systemd。".to_string();
        assert_eq!(humanize(&with_text), "服务器上没有 systemd。");

        let mut empty = reason(REASON_OUTCOME_UNKNOWN, crate::deploystore::ERROR_CLASS_NETWORK);
        empty.text.clear();
        assert!(humanize(&empty).contains("核对"), "{}", humanize(&empty));

        let mut unknown = Reason::default();
        unknown.category = "Whatever".to_string();
        assert_eq!(humanize(&unknown), "需要处理。");
    }

    /// 词表与记录必须对得上：四步名字、七种步骤状态、四种未决写结论，
    /// 一个不多一个不少。改了词表而忘了改别处，这里先红。
    #[test]
    fn the_vocabularies_stay_in_sync_with_the_record_shape() {
        assert_eq!(STEP_NAMES.len(), STEP_COUNT);
        assert_eq!(STEP_COUNT, 4);
        assert_eq!(crate::deploystore::STATES.len(), 8);
        assert_eq!(crate::deploystore::STEP_STATUSES.len(), 7);
        assert_eq!(crate::deploystore::OUTCOMES.len(), 4);
        assert_eq!(crate::deploystore::PENDING_KINDS.len(), 3);
        assert_eq!(crate::deploystore::VERIFY_BYS.len(), 2);
        assert_eq!(crate::deploystore::NEXT_ACTIONS.len(), 11);
        assert_eq!(crate::deploystore::REASON_CATEGORIES.len(), 7);
        assert_eq!(crate::deploystore::ERROR_CLASSES.len(), 6);
        for status in crate::deploystore::STEP_STATUSES {
            assert_eq!(
                counts_as_done(status),
                status == STEP_STATUS_DONE,
                "{status} 的完成口径被改了"
            );
        }
    }

    // ---------- T04：重启改判 ----------

    const NOW: u64 = 1_781_000_000;

    fn executor(pid: i64, heartbeat_secs: Option<u64>) -> crate::deploystore::Executor {
        crate::deploystore::Executor {
            instance_id: "0b7d4c1e-9a2b-4c4d-8e6f-1a2b3c4d5e6f".to_string(),
            pid,
            heartbeat_at_utc: heartbeat_secs.map(crate::deploystore::stamp_utc),
            background: false,
        }
    }

    fn executing(state: &str, pid: i64, heartbeat_secs: Option<u64>) -> RunRecord {
        let mut run = draft();
        run.state = state.to_string();
        run.executor = Some(executor(pid, heartbeat_secs));
        run
    }

    fn pending(outcome: &str) -> crate::deploystore::PendingOperation {
        crate::deploystore::PendingOperation {
            kind: crate::deploystore::PENDING_KIND_UDP_INSTALL.to_string(),
            attempt_no: 1,
            started_at_utc: Some(crate::deploystore::stamp_utc(NOW - 120)),
            verify_by: crate::deploystore::VERIFY_BY_PROBE_UDP_STATE.to_string(),
            plan_digest: "sha256:00".to_string(),
            client_public_key: None,
            outcome: outcome.to_string(),
        }
    }

    fn rewritten(decision: Recovery) -> (RunRecord, &'static str) {
        match decision {
            Recovery::Rewrite {
                run, category, ..
            } => (run, category),
            Recovery::Keep(skip) => panic!("不该放过这条记录：{}", skip.why()),
        }
    }

    /// 四种组合：pid 相同/不同 × 心跳新/旧。只有「pid 不同 + 心跳过期」才改判。
    ///
    /// 前三种各挡一类假阳性：本进程刚建的记录（pid 相同）、本进程的活动 pass
    /// （`is_active`）、以及心跳还没来得及写下一拍的那个窗口。
    #[test]
    fn only_a_dead_executor_with_a_stale_heartbeat_is_rewritten() {
        let ours = i64::from(std::process::id());

        assert_eq!(
            recover(&executing(STATE_RUNNING, ours, Some(NOW - 600)), ours, NOW, false),
            Recovery::Keep(RecoverySkip::OwnExecutor),
            "本进程写的记录不许被自己改判（pid 相同）"
        );
        assert_eq!(
            recover(&executing(STATE_RUNNING, 424_242, Some(NOW - 5)), ours, NOW, false),
            Recovery::Keep(RecoverySkip::FreshHeartbeat),
            "心跳还在 15 秒内：可能只是下一拍没写"
        );
        assert_eq!(
            recover(&executing(STATE_RUNNING, 424_242, Some(NOW - 600)), ours, NOW, true),
            Recovery::Keep(RecoverySkip::Active),
            "引擎里还有活动 pass 的不改判（哪怕心跳看着旧）"
        );

        let (run, category) = rewritten(recover(
            &executing(STATE_RUNNING, 424_242, Some(NOW - 600)),
            ours,
            NOW,
            false,
        ));
        assert_eq!(category, REASON_INTERRUPTED);
        assert_eq!(run.state, STATE_NEEDS_ATTENTION);
        assert_eq!(run.next_action, NEXT_ACTION_RETRY_STEP);
        assert_eq!(run.reason.as_ref().unwrap().category, REASON_INTERRUPTED);
        assert!(run.reason.as_ref().unwrap().text.contains("从这一步继续"));
    }

    /// 心跳缺失/写坏了 = 不知道 → 按过期处理。把「不知道」当「还活着」，
    /// 就是崩溃后继续显示「正在部署」的来源。
    #[test]
    fn a_missing_or_broken_heartbeat_counts_as_stale() {
        let ours = i64::from(std::process::id());
        for heartbeat in [None, Some(0)] {
            let (run, category) = rewritten(recover(
                &executing(STATE_RUNNING, 424_242, heartbeat),
                ours,
                NOW,
                false,
            ));
            assert_eq!(category, REASON_INTERRUPTED, "心跳 {heartbeat:?}");
            assert_eq!(run.state, STATE_NEEDS_ATTENTION);
        }

        // 排队中的记录**从来没有执行者**（`enqueue` 只写状态）。它同样要改判：
        // 那条队列随着进程一起没了，永远等不到提升。
        let mut queued = draft();
        queued.state = STATE_QUEUED.to_string();
        assert!(queued.executor.is_none());
        let (run, category) = rewritten(recover(&queued, ours, NOW, false));
        assert_eq!(category, REASON_INTERRUPTED);
        assert_eq!(run.state, STATE_NEEDS_ATTENTION);
    }

    /// 未决写用「有没有核对结论」判，不是「字段在不在」。
    ///
    /// 核对成 `Applied`/`NotApplied` 的写已经**有结论**：那是被打断（可以续），
    /// 不是结果未知（必须先核对）。判错就会让人去核对一条早核对完的记录。
    #[test]
    fn an_unverified_write_is_outcome_unknown_and_a_resolved_one_is_not() {
        let ours = i64::from(std::process::id());
        let mut run = executing(STATE_RUNNING, 424_242, Some(NOW - 600));
        run.pending_operation = Some(pending(crate::deploystore::OUTCOME_PENDING));

        let (next, category) = rewritten(recover(&run, ours, NOW, false));
        assert_eq!(category, REASON_OUTCOME_UNKNOWN);
        assert_eq!(next.next_action, NEXT_ACTION_RECONCILE, "结果未知只能先核对");
        assert!(next.reason.as_ref().unwrap().text.contains("核对"));

        for resolved in [
            crate::deploystore::OUTCOME_APPLIED,
            crate::deploystore::OUTCOME_NOT_APPLIED,
        ] {
            let mut run = executing(STATE_RUNNING, 424_242, Some(NOW - 600));
            run.pending_operation = Some(pending(resolved));
            let (next, category) = rewritten(recover(&run, ours, NOW, false));
            assert_eq!(category, REASON_INTERRUPTED, "结论是 {resolved}");
            assert_eq!(next.next_action, NEXT_ACTION_RETRY_STEP);
        }
    }

    /// 卡在「进行中」的那一步改成「未核实」；已完成的不许动。
    #[test]
    fn the_interrupted_step_becomes_unknown_and_done_steps_stay_done() {
        let ours = i64::from(std::process::id());
        let mut run = executing(STATE_RUNNING, 424_242, Some(NOW - 600));
        run.steps[0].status = STEP_STATUS_DONE.to_string();
        run.steps[1].status = crate::deploystore::STEP_STATUS_RUNNING.to_string();
        run.step = Some(1);
        run.revision = 7;

        let (next, _) = rewritten(recover(&run, ours, NOW, false));
        assert_eq!(next.steps[0].status, STEP_STATUS_DONE, "做成的步骤不许被抹掉");
        assert_eq!(next.steps[1].status, crate::deploystore::STEP_STATUS_UNKNOWN);
        assert_eq!(next.steps[2].status, crate::deploystore::STEP_STATUS_PENDING);
        assert_eq!(next.step, Some(1), "停在哪一步要说出来");
        assert_eq!(next.revision, 7, "版本号由存储层递增，纯函数不碰");
        assert_eq!(next.finished_at_utc, None, "需要处理不是完成");
        assert_eq!(steps_done(&next), 1, "未核实不计入 N/4");
    }

    /// 另外三种「不该动」：终态、草稿/等确认/已暂停、已经需要处理。
    /// 尤其是 `Paused`：那是用户按下的，重启把它改成「需要处理」等于替用户做决定。
    #[test]
    fn terminal_draft_paused_and_needs_attention_are_left_alone() {
        let ours = i64::from(std::process::id());
        for (state, skip) in [
            (STATE_COMPLETE, RecoverySkip::Terminal),
            (STATE_CANCELLED, RecoverySkip::Terminal),
            (STATE_DRAFT, RecoverySkip::NotExecuting),
            (STATE_WAITING_USER, RecoverySkip::NotExecuting),
            (STATE_PAUSED, RecoverySkip::NotExecuting),
            (STATE_NEEDS_ATTENTION, RecoverySkip::NotExecuting),
        ] {
            let mut run = executing(state, 424_242, Some(NOW - 600));
            run.reason = Some(reason(REASON_FAILED, crate::deploystore::ERROR_CLASS_ENVIRONMENT));
            assert_eq!(recover(&run, ours, NOW, false), Recovery::Keep(skip), "{state}");
        }
    }

    /// 改判不产生任何执行意图：它只写状态、原因、下一步动作、以及**给被打断的那次
    /// 尝试补一个结论**，不碰队列。
    ///
    /// 这条断言是「永不自动续跑」的可执行版本——本文件里根本不该出现
    /// 那两个「起 pass / 续跑」的命令名，由 `the_pure_layer_never_summons_the_engine` 扫。
    #[test]
    fn recovery_rewrites_only_the_human_facing_fields() {
        let ours = i64::from(std::process::id());
        let before = executing(STATE_RUNNING, 424_242, Some(NOW - 600));
        let (after, _) = rewritten(recover(&before, ours, NOW, false));
        assert_eq!(after.run_id, before.run_id);
        assert_eq!(after.label, before.label);
        assert_eq!(after.target, before.target);
        assert_eq!(after.identity, before.identity);
        assert_eq!(after.plan, before.plan);
        assert_eq!(after.executor, before.executor, "死掉的执行者是证据，留着");
        // P1-4：被强杀的那次尝试要补结论（结束时间 + `Interrupted`），但编号、起点
        // 与条数都不动——它是同一次尝试的结束，不是凭空多出来的一次。
        assert_eq!(after.attempts.len(), before.attempts.len());
        assert_eq!(after.attempts[0].no, before.attempts[0].no);
        assert_eq!(
            after.attempts[0].started_at_utc,
            before.attempts[0].started_at_utc
        );
        assert!(after.attempts[0].finished_at_utc.is_some());
        assert_eq!(after.attempts[0].error_code, "Interrupted");
        assert_eq!(after.created_at_utc, before.created_at_utc);
        assert_eq!(after.started_at_utc, before.started_at_utc);
        assert_ne!(after.state, before.state);
        assert_ne!(after.reason, before.reason);
        assert_ne!(after.next_action, before.next_action);

        // `detail` 只带 RunId 短码与结论：它是 `operations.jsonl` 的一行，
        // 秘密边界（架构 §1.10）在这里也必须成立。
        let Recovery::Rewrite { detail, .. } = recover(&before, ours, NOW, false) else {
            panic!("必须改判");
        };
        assert!(detail.starts_with("3f2b9c1e"));
        assert!(!detail.contains(&before.label), "不带服务器名/地址：{detail}");
    }

    /// 源码扫描：这个文件里不许出现「起 pass / 续跑」的那两个命令名。
    ///
    /// 纯函数层拿不到 `Sender<Cmd>`，所以它本来也发不出去——这条断言守的是
    /// **将来**：有人为了「恢复完顺手续一下」把引擎句柄递进来，名字先红。
    /// 断言里的名字用 `concat!` 拼，否则扫描会扫到自己。
    #[test]
    fn the_pure_layer_never_summons_the_engine() {
        let source = include_str!("deployrun.rs");
        for name in [
            concat!("Cmd::", "Start"),
            concat!("Cmd::", "Continue"),
        ] {
            assert!(
                !source.contains(name),
                "恢复/投影层出现了 {name}：自动续跑是被禁止的"
            );
        }
    }

    /// 缺字段的记录 = 未知，**既不是**「一步没做」**也不是**「全做完了」。
    ///
    /// 这条守的是共享知识第 12 条。三个断言各自挡一种谎：`StepsDone==0` 挡「猜成完成」；
    /// `progress_text==None` 挡「显示 0/4」（那会被读成「一步都没做」）；
    /// `Revision==0` 挡「当成第 0 版正常记录」——它其实表示这份记录没写过版本号。
    #[test]
    fn a_record_without_steps_is_unknown_not_done_and_not_zero_of_four() {
        let run = load_fixture("missing-fields.json");
        assert!(run.steps.is_empty(), "这份夹具本来就没有 Steps");
        assert_eq!(steps_done(&run), 0, "缺字段不许猜成已完成");
        assert_eq!(current_step(&run), None, "步骤未知");
        assert_eq!(progress_text(&run), None, "未知进度不许写成 0/4");
        let reason = run.reason.as_ref().expect("这份夹具带原因");
        assert_eq!(task_label(&run), format!("步骤未知：{}", humanize(reason)));
        assert_eq!(run.revision, 0, "0 = 未知，不是「第 0 版」");
        assert!(run.executor.is_none(), "缺 Executor 就是没有执行者信息");
        assert_eq!(run.attempts.len(), 0);
        // 不知道做到哪一步，就只能先核对——不许给「重试本步骤」。
        assert_eq!(action_of(&run), ("reconcile", "核对原操作"));
    }

    /// 未决写 + 「核对也说不清」：唯一动作是核对，而且**连后台都不许转**。
    ///
    /// 与 `attention-unknown.json`（`Outcome:Pending`）的区别全在 `Outcome`：
    /// `Pending` 是「还没核对」，`Unknown` 是「核对过但说不清」。后者不是「在跑」，
    /// 是「不知道跑到哪了」——把它当在跑，用户就会关掉页面等一个不会来的结果。
    #[test]
    fn an_unverifiable_write_offers_reconcile_and_no_background() {
        let run = load_fixture("attention-unverifiable.json");
        let pending = run.pending_operation.as_ref().expect("这份夹具必须带未决写");
        assert_eq!(pending.kind, crate::deploystore::PENDING_KIND_ADD_PEER);
        assert_eq!(pending.outcome, crate::deploystore::OUTCOME_UNKNOWN);
        assert_eq!(action_of(&run), ("reconcile", "核对原操作"));
        assert!(!can_background(&run, true), "结果未知不是「在跑」，不许转后台");
        assert!(!is_running(&run, true), "NeedsAttention 永远不是 Running");
        // 第三步「未核实」：既不显示完成，也不显示失败。
        assert_eq!(
            run.steps[3].status,
            crate::deploystore::STEP_STATUS_UNKNOWN,
            "没有结论的那一步只能是 Unknown"
        );
        assert_eq!(steps_done(&run), 3, "只有 Done 计入 N/4");
        // 两次尝试都记着「需要核对」，页面上才说得清为什么停在这儿。
        assert_eq!(run.attempts.len(), 2);
        assert_eq!(run.attempts[1].reconcile, "Needed");
    }
}

// ---------------------------------------------------------------------------
// 契约文档守门（T10）
// ---------------------------------------------------------------------------

/// 契约文档最危险的失效方式不是写错，而是**写得比代码漂亮**：文档里出现一个
/// 代码里根本没有的字段名，读的人会照着它去对接，然后在一个不存在的键上等一辈子。
/// 这类漂移在评审里看不出来（两个文件分开看都很合理），只有机器比对能抓住。
///
/// 放在 `deployrun` 里而不是单开一个 `mod`：这些用例守的是部署域的契约，
/// 而且多一个顶层 `mod` 声明会让 release 产物的段排布变动几百字节——
/// 那点差异没法解释，只会给「本批到底改没改产品代码」添乱。
#[cfg(test)]
mod contract_tests {
    //! 部署中心契约文档的守门用例（T10）。
    //!
    //! 契约文档最危险的失效方式不是写错，而是**写得比代码漂亮**：文档里出现一个
    //! 代码里根本没有的字段名，读的人会照着它去对接，然后在一个不存在的键上等一辈子。
    //! 这类漂移在评审里看不出来（两个文件分开看都很合理），只有机器比对能抓住。
    //!
    //! 所以这里只做一件很笨的事：把 §4.16 里所有反引号包着的标识符抽出来，
    //! 逐个证明它在 `src/*.rs` 里真的出现过。再加一条反向抽查：五个关键概念必须
    //! 在文档里出现——否则就是「代码有、文档没写」，同样是漂移。
    //!
    //! 为什么读文件而不是 `include_str!`：这份文档改一次就重编译整包不值得，
    //! 而且 `include_str!` 会把 800 行 Markdown 塞进 release 二进制。

    #![cfg(test)]

    use std::path::{Path, PathBuf};

    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn contract_doc() -> String {
        let path = crate_root().join("docs").join("ipc-contract-0.1.4.md");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("读不到契约文档 {}：{error}", path.display()))
    }

    /// §4.16 的正文：从标题到下一个一级标题之前。
    fn deploy_section(doc: &str) -> &str {
        let start = doc
            .find("### 4.16")
            .unwrap_or_else(|| panic!("契约文档里没有 §4.16 —— 部署中心的契约不能缺席"));
        let rest = &doc[start..];
        let end = rest
            .find("\n## 5. `operations.jsonl` v2")
            .unwrap_or_else(|| panic!("§4.16 之后找不到 §5 的分界，切片会吞掉整份文档"));
        &rest[..end]
    }

    /// 全部 Rust 源码拼一起。文档提到的东西必须能在**某个**文件里找到。
    fn all_source() -> String {
        let dir = crate_root().join("src");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("读不到源码目录 {}：{error}", dir.display()))
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
            .collect();
        // 目录顺序不保证稳定；排序只为让失败信息可复现。
        files.sort();
        assert!(files.len() > 40, "源码文件数不对（{}），路径可能指错了", files.len());
        files
            .iter()
            .map(|path| {
                std::fs::read_to_string(path)
                    .unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 反引号里、长得像 Rust 标识符的词。
    ///
    /// 判据刻意窄：首字母大写、只含字母数字、至少三个字符、且含一个小写字母。
    /// 这样 `IPC`（缩写）、`N/4`、`sha256:…`、`deployment-start`（命令名，小写）都不会进来，
    /// 而 `RunRecord`、`TasksRead`、`NeedsAttention`、`UdpInstall` 都会。
    fn identifiers(section: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let bytes: Vec<char> = section.chars().collect();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] != '`' {
                index += 1;
                continue;
            }
            let Some(close) = bytes[index + 1..].iter().position(|ch| *ch == '`') else {
                break;
            };
            let inner: String = bytes[index + 1..index + 1 + close].iter().collect();
            index += close + 2;
            // 反引号里可能还有别的东西（`{a:1}`、`src/x.rs::f`），逐词看。
            for word in inner.split(|ch: char| !ch.is_ascii_alphanumeric()) {
                let ok = word.len() >= 3
                    && word.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
                    && word.chars().all(|ch| ch.is_ascii_alphanumeric())
                    && word.chars().any(|ch| ch.is_ascii_lowercase());
                if ok && !found.iter().any(|seen| seen == word) {
                    found.push(word.to_string());
                }
            }
        }
        found
    }

    /// §4.16 里每个像标识符的词，都必须在源码里出现过。
    ///
    /// 这条用例失败通常只有两种原因：① 文档写了一个不存在的字段（该改文档）；
    /// ② 代码里改了名字但文档没跟上（该改文档或改代码，但不该两边都不知道）。
    #[test]
    fn every_identifier_in_the_deployment_contract_exists_in_source() {
        let doc = contract_doc();
        let section = deploy_section(&doc);
        let source = all_source();
        let names = identifiers(section);
        assert!(
            names.len() >= 50,
            "只抽出 {} 个标识符，抽取规则可能失效了",
            names.len()
        );
        let missing: Vec<&String> = names.iter().filter(|name| !source.contains(*name)).collect();
        assert!(
            missing.is_empty(),
            "契约 §4.16 提到但源码里找不到的标识符：{missing:?}"
        );
    }

    /// 反向抽查：这五个概念是部署中心的骨架，代码里有，文档就必须写到。
    ///
    /// 前向那条挡「文档凭空造字段」，这条挡「代码长出新东西但文档没写」。
    #[test]
    fn the_deployment_contract_covers_the_five_load_bearing_concepts() {
        let doc = contract_doc();
        let section = deploy_section(&doc);
        for needle in [
            // 读取三态：把「读不出来」说成「没有任务」是这块最贵的一种谎。
            "TasksRead",
            // 后台按钮指向唯一一条记录；空串不是「随便挑一条」。
            "CanBackgroundRunId",
            // 写命令之前先落盘的那条记录。
            "PendingOperation",
            // 唯一可以说「没有任务」的组合。
            "UnreadableCount",
            // 只裁终态；未完成的永不自动删。
            "prune_terminal",
        ] {
            assert!(
                section.contains(needle),
                "契约 §4.16 没写 {needle}，但它决定了页面的行为"
            );
        }
    }

    /// `deployment-*` 八条必须同时在命令总表和 §4.16 里出现。
    ///
    /// 命令总表是「有没有这条命令」，§4.16 是「它到底代表什么」。只写一处的后果是：
    /// 有人照着总表实现了命令，却不知道 `ok:true` 只代表受理。
    ///
    /// r69 加了 `deployment-draft-save`：它把向导的非秘密字段写进一条 `Draft` 记录，
    /// 是「关掉窗口后地址还在」的唯一来源，所以必须与另外七条同列。
    #[test]
    fn all_ten_deployment_commands_appear_in_both_places() {
        let doc = contract_doc();
        let section = deploy_section(&doc);
        let commands = [
            "deployment-start",
            "deployment-draft-save",
            "deployment-list",
            "deployment-get",
            "deployment-continue",
            "deployment-pause",
            "deployment-cancel",
            "deployment-background",
            "deployment-export",
            "deployment-archive",
        ];
        // 命令总表在 §3.2：只要求出现过（表格与 §4.16 的引用都算）。
        for command in commands {
            assert!(
                doc.matches(command).count() >= 2,
                "{command} 在文档里出现次数不足：命令总表与 §4.16 都要有"
            );
            assert!(section.contains(command), "§4.16 没写 {command}");
        }
        // 短命令这条规矩必须写死，且要能被人一眼看到。
        assert!(
            section.contains("短命令只代表受理"),
            "§4.16 丢了「短命令只代表受理」这条——`ok:true` 会被当成「做完了」"
        );
    }

    /// 三张 mermaid 文件必须存在且非空。
    ///
    /// 图放在 docs 里是为了能被评审单独打开；架构文档里的版本是权威版，
    /// 两边不同步比没有图更糟，所以至少要能证明文件还在。
    #[test]
    fn the_mermaid_diagrams_are_checked_in() {
        for name in [
            "deployment-center-class-diagram.mermaid",
            "deployment-center-sequence-diagram.mermaid",
            "deployment-center-recovery-diagram.mermaid",
        ] {
            let path = crate_root().join("docs").join(name);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("缺 {}：{error}", path.display()));
            assert!(text.len() > 400, "{name} 太短，可能是占位");
            assert!(
                text.contains("mermaid") || text.contains("classDiagram") || text.contains("sequenceDiagram"),
                "{name} 里没有 mermaid 图类型声明"
            );
        }
        let _ = Path::new("docs");
    }
}
