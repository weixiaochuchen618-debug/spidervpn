//! 连接状态投影（纯函数）。
//!
//! 迁移自 旧版的 `Get-TCSessionPresentation`：它当时就被写成「所有文件/进程/API 输入都由调用方提供」的
//! 纯函数，因此可以原样搬过来当参考语义，且能穷举测试。
//!
//! 两条设计约束：
//! 1. **文案与状态键保持一致**。用户看到的中文提示、按钮可用性，不能因为换了语言就悄悄变。
//! 2. **时间用「秒」而不是时间戳类型**。PS 侧是 ISO 字符串，Rust 侧若引入 chrono 只为算两个差值，
//!    多一个依赖只为省三行；这里约定入参就是「距 epoch 的秒数」，转换发生在适配层。
//!
//! **不变量（新增输入前先读这条）**：本模块每条分支都必须有真实来源——每个 `Identity` / `Evidence`
//! 的布尔字段都要有能置成「非默认值」的构造点，否则那段逻辑永远不会触发。
//! 本模块每条分支都必须在生产链路有真实来源；新增恒 false/true 的输入视为缺陷
//! （历史：`boot_restart_detected` 与 `untracked` 均因「没有生产者」被删整条分支）。
//! `every_identity_flag_changes_the_projection` 守住「字段被读到」这一半（逐字段翻转、断言投影确实变了）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKey {
    Disconnected,
    Unconfigured,
    Connecting,
    Connected,
    Disconnecting,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    Setup,
    Disconnect,
    Retry,
    /// 已连接但通道不通：给「重新连接」，而不是让用户以为现在能用。
    Reconnect,
    None,
}

impl StateKey {
    /// 对外字符串。`--status` 的 `state=`、IPC `status` 的 `state` 字段都取这里，
    /// 三者同一份映射，才不会出现「命令行说 Fault、界面说已连接」这种两套说法。
    /// 取值沿用 Debug 名（`Fault` / `Connected` / …），验收断言与界面都按这些词对齐。
    pub fn as_str(self) -> &'static str {
        match self {
            StateKey::Disconnected => "Disconnected",
            StateKey::Unconfigured => "Unconfigured",
            StateKey::Connecting => "Connecting",
            StateKey::Connected => "Connected",
            StateKey::Disconnecting => "Disconnecting",
            StateKey::Fault => "Fault",
        }
    }
}

impl Action {
    /// 同 `StateKey::as_str`：`action=Disconnect` 与 IPC 的 `action` 字段共用一个来源。
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Connect => "Connect",
            Action::Setup => "Setup",
            Action::Disconnect => "Disconnect",
            Action::Retry => "Retry",
            Action::Reconnect => "Reconnect",
            Action::None => "None",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// 当前有通道进程记录。
    pub current: bool,
    /// 监督进程活着。
    pub supervisor_alive: bool,
    /// 引擎进程活着。
    pub engine_alive: bool,
    /// 存在会话（未完整运行即为异常态）。
    pub session_present: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// 通道自身状态：Starting / Running / Stopping / Disconnecting / Stopped / StoppedWithError
    pub state: String,
    /// 启动时刻（epoch 秒）。
    pub started_at: Option<f64>,
    /// 记录写入时刻（epoch 秒），断开超时以它为起点兜底。
    pub record_written_at: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub deployment_present: bool,
    pub identity: Identity,
    pub snapshot: Snapshot,
    pub fault: Option<String>,
    pub stop_requested: bool,
    pub stop_requested_at: Option<f64>,
    pub control_available: bool,
    pub observed_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Presentation {
    pub key: StateKey,
    pub title: String,
    pub detail: String,
    pub action: Action,
    pub enabled: bool,
    pub error: Option<String>,
}

/// 启动超过这个秒数仍未完成，按异常处理。
const START_TIMEOUT_SECS: f64 = 60.0;
/// 断开超过这个秒数仍未完成，按异常处理。
const STOP_TIMEOUT_SECS: f64 = 30.0;

fn elapsed(now: Option<f64>, then: Option<f64>) -> Option<f64> {
    match (now, then) {
        (Some(n), Some(t)) => Some(n - t),
        _ => None,
    }
}

pub fn present(e: &Evidence) -> Presentation {
    let i = &e.identity;
    let s = &e.snapshot;

    // 默认：未连接。选择线路后点击连接，不自动连接。
    let mut p = Presentation {
        key: StateKey::Disconnected,
        title: "未连接".to_string(),
        detail: "选择线路后点击连接；不会自动连接。".to_string(),
        action: Action::Connect,
        enabled: true,
        error: None,
    };

    let can_start = e.deployment_present && i.current == false && !i.session_present && e.fault.is_none();

    if !e.deployment_present {
        p.key = StateKey::Unconfigured;
        p.title = "尚未配置".to_string();
        p.detail = "请在部署页导入或接管节点，然后连接。".to_string();
        p.action = Action::Setup;
    }

    let running_by_record = i.current && i.supervisor_alive;

    if running_by_record && e.stop_requested {
        p.key = StateKey::Disconnecting;
        p.title = "正在断开".to_string();
        p.detail = "已请求停止通道，正在等待清理完成；交易保护仍保留。".to_string();
        p.action = Action::None;
        p.enabled = false;
    } else if let Some(f) = &e.fault {
        p.key = StateKey::Fault;
        p.error = Some(f.clone());
    } else if running_by_record && matches!(s.state.as_str(), "Starting" | "Stopping" | "Disconnecting") {
        if s.state == "Starting" {
            p.key = StateKey::Connecting;
            p.title = "正在连接".to_string();
            p.detail = "正在启动并核对通道，请稍候。".to_string();
            if let Some(secs) = elapsed(e.observed_at, s.started_at) {
                if secs > START_TIMEOUT_SECS {
                    p.key = StateKey::Fault;
                    p.error = Some("启动未在预期时间内完成，请断开后重试。".to_string());
                }
            }
        } else {
            p.key = StateKey::Disconnecting;
            p.title = "正在断开".to_string();
            p.detail = "正在停止通道并保留交易保护，请稍候。".to_string();
        }
        p.action = Action::None;
        p.enabled = false;
    } else if running_by_record && i.engine_alive && s.state == "Running" && e.control_available {
        p.key = StateKey::Connected;
        p.title = "已连接".to_string();
        p.detail = "通道进程与本机控制接口正常；行情、历史数据和订单需分别检查。".to_string();
        p.action = Action::Disconnect;
        p.enabled = true;
    } else if i.session_present {
        p.key = StateKey::Fault;
        p.error = Some("会话未完整运行，请断开后重新连接。".to_string());
    } else if i.current && s.state == "StoppedWithError" {
        p.key = StateKey::Fault;
        p.error = Some("上次通道异常停止，请检查诊断信息后重试连接。".to_string());
    }

    // 断开超时：从「请求停止时刻」起算，没有就用「记录写入时刻」。
    if p.key == StateKey::Disconnecting {
        let since = e.stop_requested_at.or(s.record_written_at);
        if let Some(secs) = elapsed(e.observed_at, since) {
            if secs > STOP_TIMEOUT_SECS {
                p.key = StateKey::Fault;
                p.error = Some("断开未在预期时间内完成，请重试断开并检查诊断信息。".to_string());
            }
        }
    }

    if p.key == StateKey::Fault {
        p.title = "连接需要处理".to_string();
        p.detail = p.error.clone().unwrap_or_default();
        if i.supervisor_alive || i.engine_alive {
            // 还有东西在跑：先断开，不能盲目重连。
            p.action = Action::Disconnect;
            p.enabled = true;
        } else {
            p.action = Action::Retry;
            p.enabled = can_start;
        }
    }

    p
}

/// 把"通道自检"的结论叠到投影上：**已连接但自检没过**时，必须让用户看见"通道未通"。
///
/// 为什么不能只写进 detail：`state=Connected` + 灰字说明，用户会以为自己已经能用了；
/// 这里把标题标注、动作换成「重新连接」，才算"看起来能用、其实没用"的那个坑被堵上。
pub fn apply_channel_check(mut p: Presentation, check: Option<&str>) -> Presentation {
    let Some(sentence) = check else { return p };
    // 两种失败句式：老记录「通道自检未通过：…」、经交易出口「通道自检（经交易出口）未通过：…」。
    // 「自检跳过」不算失败（没能验，不等于验出问题），标题保持原样，结论在自检那一行里显示。
    // 「没测出来」同样不算失败：2 秒预算内没等到响应**不构成结论**（冷启动常见），
    // 挂「通道未通」会把一条能用的连接说成坏的——真机撞到过。
    let failed = sentence.starts_with("通道自检未通过")
        || sentence.starts_with("通道自检（经交易出口）未通过");
    if p.key != StateKey::Connected || !failed {
        return p;
    }
    p.title = format!("{}（通道未通）", p.title);
    p.detail = sentence.to_string();
    p.action = Action::Reconnect;
    p.enabled = true;
    p
}

/// 「状态 + 通道自检」的唯一投影：CLI 的 `--status` 与界面的 `status` 都走这里。
///
/// 两处各拼一遍（`present` 之后再自己补括注）必然会长出两种说法——上一轮就是
/// 「命令行说已连接、界面说通道未通」被当成两个功能。
pub fn present_with_check(ev: &Evidence, check: Option<&str>) -> Presentation {
    apply_channel_check(present(ev), check)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Evidence {
        Evidence { deployment_present: true, ..Default::default() }
    }

    #[test]
    fn connected_but_channel_failed_says_the_same_thing_everywhere() {
        // 措辞定稿：界面标题与 CLI `--status` 的「状态」行都出自 present_with_check，
        // 一句「已连接（通道未通）」——两处各拼一套就会变回两种说法。
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.snapshot.state = "Running".into();
        e.control_available = true;
        let p = present_with_check(
            &e,
            Some("通道自检（经交易出口）未通过：连 www.gstatic.com 失败：交易出口没有连上"),
        );
        assert_eq!(p.title, "已连接（通道未通）");
        assert_eq!(p.action, Action::Reconnect, "标注了未通就要给「重新连接」");

        // 通过 / 跳过 / 没测出来都不加括注：没验出结论，不等于验出问题。
        // 「没测出来」是 2 秒预算内没等到响应（冷启动常见），挂「通道未通」会把一条
        // 能用的连接说成坏的——真机上撞到过。
        for ok in [
            "通道自检（经交易出口）：通过（HTTP 204）",
            "自检跳过：探测端口 17893 被占用",
            "通道自检（经交易出口）没测出来：探测请求在 2000 毫秒内没有响应",
        ] {
            assert_eq!(present_with_check(&e, Some(ok)).title, "已连接", "{ok}");
        }
    }

    #[test]
    fn connected_but_channel_not_working_is_marked_and_offers_reconnect() {
        // 「连上了但通道不通」不能让用户以为能用：标题标注 + 动作换「重新连接」+ detail 以自检结论开头。
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.snapshot.state = "Running".into();
        e.control_available = true;
        let p = present(&e);
        assert_eq!(p.key, StateKey::Connected, "前提：先要是已连接");
        assert_eq!(p.action, Action::Disconnect, "前提：正常已连接的动作是断开");

        let failed = "通道自检未通过：连 www.gstatic.com 失败：连接超时";
        let p = apply_channel_check(p, Some(failed));
        assert!(p.title.contains("通道未通"), "标题必须标注：{}", p.title);
        assert_eq!(p.action, Action::Reconnect, "动作要变成「重新连接」");
        assert!(p.enabled, "「重新连接」要可点");
        assert!(p.detail.starts_with("通道自检未通过"), "detail 要以自检结论开头：{}", p.detail);
    }

    #[test]
    fn channel_check_does_not_touch_other_states_or_a_passing_check() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.snapshot.state = "Running".into();
        e.control_available = true;
        let before = present(&e);
        let after = apply_channel_check(before.clone(), Some("通道自检：通过（HTTP 204）"));
        assert_eq!(before, after, "自检通过时不许动投影");

        // 未连接时即使有旧的失败结论，也不许把它贴到别的状态上
        let idle = present(&base());
        let after = apply_channel_check(idle.clone(), Some("通道自检未通过：x"));
        assert_eq!(idle, after, "非「已连接」状态不受自检结论影响");
    }

    #[test]
    fn trade_exit_failure_and_skip_are_handled_by_their_own_rules() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.snapshot.state = "Running".into();
        e.control_available = true;
        let ok = present(&e);

        // 经交易出口的失败：必须同样标注「通道未通」+ 换「重新连接」
        let via_failed = "通道自检（经交易出口）未通过：连 www.gstatic.com 失败：交易出口没有连上";
        let p = apply_channel_check(ok.clone(), Some(via_failed));
        assert!(p.title.contains("通道未通"), "经交易出口的失败也要标注：{}", p.title);
        assert_eq!(p.action, Action::Reconnect);
        assert!(p.detail.starts_with("通道自检（经交易出口）未通过"), "{}", p.detail);

        // 跳过（没能验）不是"验出问题"：标题不动，结论只体现在自检那一行里
        let skipped = "自检跳过：探测端口 17893 被占用";
        let p = apply_channel_check(ok.clone(), Some(skipped));
        assert_eq!(p, ok, "跳过不许把标题改成「通道未通」");
    }

    #[test]
    fn default_is_disconnected_and_offers_connect() {
        let p = present(&base());
        assert_eq!(p.key, StateKey::Disconnected);
        assert_eq!(p.action, Action::Connect);
        assert!(p.enabled);
        assert_eq!(p.title, "未连接");
    }

    #[test]
    fn no_deployment_asks_to_setup() {
        let e = Evidence { deployment_present: false, ..Default::default() };
        let p = present(&e);
        assert_eq!(p.key, StateKey::Unconfigured);
        assert_eq!(p.action, Action::Setup);
    }

    /// 守卫：投影输入里不许有「恒为常量」的字段。
    ///
    /// 做法是逐字段翻转、断言**投影输出真的变了** —— 只有真被读到的字段才可能让它变。
    /// 这条比「写个恒真断言」有意义：`boot_restart_detected` 那种恒 false 的 seam 会在这里被抓住
    /// （它翻转后投影毫无变化，因为它根本没接来源，也不可能被置真）。
    fn assert_flag_matters(name: &str, build: &dyn Fn(bool) -> Evidence) {
        let on = present(&build(true));
        let off = present(&build(false));
        assert_ne!(on, off, "字段 {name} 置真/置假后投影完全没变 —— 它没有真实来源，或那段逻辑已经死了");
    }

    #[test]
    fn every_identity_flag_changes_the_projection() {
        // current：有记录 + 守护活着 + 引擎活着 + Running + 控制可用 → 已连接；没记录 → 未连接
        assert_flag_matters("current", &|v| {
            let mut e = base();
            e.identity.current = v;
            e.identity.supervisor_alive = true;
            e.identity.engine_alive = true;
            e.snapshot.state = "Running".into();
            e.control_available = true;
            e
        });
        // supervisor_alive：守护一死，会话就不完整（不再算已连接）
        assert_flag_matters("supervisor_alive", &|v| {
            let mut e = base();
            e.identity.current = true;
            e.identity.supervisor_alive = v;
            e.identity.engine_alive = true;
            e.snapshot.state = "Running".into();
            e.control_available = true;
            e
        });
        // engine_alive：引擎没了就不算已连接
        assert_flag_matters("engine_alive", &|v| {
            let mut e = base();
            e.identity.current = true;
            e.identity.supervisor_alive = true;
            e.identity.engine_alive = v;
            e.snapshot.state = "Running".into();
            e.control_available = true;
            e
        });
        // session_present：会话不完整 → 故障态
        assert_flag_matters("session_present", &|v| {
            let mut e = base();
            e.identity.session_present = v;
            e
        });
    }

    #[test]
    fn starting_within_timeout_is_connecting() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.snapshot.state = "Starting".into();
        e.snapshot.started_at = Some(1_000.0);
        e.observed_at = Some(1_010.0);
        let p = present(&e);
        assert_eq!(p.key, StateKey::Connecting);
        assert_eq!(p.action, Action::None);
        assert!(!p.enabled, "连接中按钮必须不可用");
    }

    #[test]
    fn starting_over_timeout_becomes_fault() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.snapshot.state = "Starting".into();
        e.snapshot.started_at = Some(1_000.0);
        e.observed_at = Some(1_061.0);
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
        assert!(p.error.unwrap().contains("启动未在预期时间内完成"));
        // 监督进程还活着 → 只能先断开
        assert_eq!(p.action, Action::Disconnect);
    }

    #[test]
    fn running_with_engine_and_control_is_connected() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.control_available = true;
        e.snapshot.state = "Running".into();
        let p = present(&e);
        assert_eq!(p.key, StateKey::Connected);
        assert_eq!(p.action, Action::Disconnect);
    }

    #[test]
    fn running_without_control_interface_is_not_connected() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.control_available = false; // 控制接口不可用
        e.snapshot.state = "Running".into();
        let p = present(&e);
        assert_ne!(p.key, StateKey::Connected, "控制接口不通不能算已连接");
    }

    #[test]
    fn stop_requested_shows_disconnecting_even_if_running() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.identity.engine_alive = true;
        e.control_available = true;
        e.snapshot.state = "Running".into();
        e.stop_requested = true;
        let p = present(&e);
        assert_eq!(p.key, StateKey::Disconnecting);
        assert_eq!(p.action, Action::None);
    }

    #[test]
    fn disconnecting_over_timeout_becomes_fault() {
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.snapshot.state = "Disconnecting".into();
        e.stop_requested_at = Some(2_000.0);
        e.observed_at = Some(2_031.0);
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
        assert!(p.error.unwrap().contains("断开未在预期时间内完成"));
    }

    #[test]
    fn session_present_but_not_running_is_fault() {
        let mut e = base();
        e.identity.session_present = true;
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
        // 没有任何进程活着 → 可以重试
        assert_eq!(p.action, Action::Retry);
    }

    #[test]
    fn stopped_with_error_is_fault() {
        let mut e = base();
        e.identity.current = true;
        e.snapshot.state = "StoppedWithError".into();
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
        assert!(p.error.unwrap().contains("异常停止"));
    }

    #[test]
    fn fault_with_dead_processes_disables_retry_without_deployment() {
        let mut e = base();
        e.deployment_present = false;
        e.fault = Some("任意故障".into());
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
        assert_eq!(p.action, Action::Retry);
        assert!(!p.enabled, "没有部署就不该允许重试");
    }

    #[test]
    fn fault_precedence_over_connecting() {
        // 有故障且同时处于 Starting：故障优先，不能显示成「正在连接」
        let mut e = base();
        e.identity.current = true;
        e.identity.supervisor_alive = true;
        e.snapshot.state = "Starting".into();
        e.fault = Some("引擎异常".into());
        let p = present(&e);
        assert_eq!(p.key, StateKey::Fault);
    }

    #[test]
    fn as_str_matches_debug_names() {
        // 对外字符串与 Debug 名必须一致：IPC/`--status` 一直按 Debug 名当契约，
        // 这里钉住，避免有人只改一边导致两处口径分叉。
        for k in [
            StateKey::Disconnected,
            StateKey::Unconfigured,
            StateKey::Connecting,
            StateKey::Connected,
            StateKey::Disconnecting,
            StateKey::Fault,
        ] {
            assert_eq!(k.as_str(), format!("{:?}", k));
        }
        for a in [Action::Connect, Action::Setup, Action::Disconnect, Action::Retry, Action::None] {
            assert_eq!(a.as_str(), format!("{:?}", a));
        }
    }
}
