//! 连接/断开的事务编排。
//!
//! 这里的顺序是**有代价的次序**，每一步都为了「失败时还能退回去」：
//!
//! connect:  写还原凭据 → 改系统代理 → 起引擎 → 写运行时记录
//!           引擎起不来 ⇒ 立刻按凭据还原代理，再把凭据删掉。否则会留下
//!           「代理指向一个没起来的引擎」这种最糟状态：用户会以为网断了。
//!
//! disconnect: 停引擎 → 还原代理 → 删凭据 → 删运行时记录
//!           先停引擎再还原代理：反过来的话，代理已经指回原处，但引擎还在跑，
//!           中间那段时间流量会绕过代理直连——交易场景下这是风险。
//!
//! 依赖全部通过 `Deps` 注入，所以整条事务能在临时注册表键 + 假引擎上测。

use std::path::Path;

use crate::config::AppConfig;
use crate::engine::EngineConfig;
use crate::model::RuntimeRecord;
use crate::proxy::{self, ProxyStore};

pub struct Deps<'a> {
    pub store: &'a ProxyStore,
    /// 按计划写系统代理。注入是为了能测「写失败 → 回滚」：
    /// 真实注册表上 `read()` 会先失败（plan 直接 blocked），造不出「能读、不能写」的现场。
    /// 生产路径一律传 `&write_proxy`。
    pub apply: &'a dyn Fn(&ProxyStore, &[proxy::Change]) -> Result<(), String>,
    /// 拉起引擎，返回 pid。
    pub spawn: &'a dyn Fn(&EngineConfig) -> Result<i64, String>,
    /// 停止引擎。
    pub kill: &'a dyn Fn(i64) -> Result<(), String>,
    /// 引擎 pid 是否还活着。注入是为了让「起来就崩」这条路径能在单测里确定性复现。
    pub alive: &'a dyn Fn(i64) -> bool,
    /// 当前进程是否提权。注入同理：验收机通常是提权会话，靠它才能测非管理员路径。
    pub elevated: &'a dyn Fn() -> bool,
    pub journal_path: &'a Path,
    pub runtime_path: &'a Path,
    pub now: f64,
    /// 交易保护步骤（连接前 0.7 步 / 断开后强制核验）。
    ///
    /// `None` 只用于「与交易保护无关的移植测试」；生产路径一律传
    /// `ProductionGuard::context()`——否则这条保护就静默消失了。
    pub guard: Option<crate::guard::GuardContext<'a>>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// 已经处于目标状态，没做任何写入。
    AlreadyDone,
    /// 实际执行的动作摘要。
    Done(Vec<String>),
}

/// 生产用的写代理实现（`Deps.apply` 的默认值）。
pub fn write_proxy(store: &ProxyStore, changes: &[proxy::Change]) -> Result<(), String> {
    store.apply(changes)
}

fn write_runtime(
    path: &Path,
    engine_pid: i64,
    now: f64,
    state: &str,
    trading_blocked: bool,
) -> Result<(), String> {
    // 只写本程序自己需要的字段，形状与 model::RuntimeRecord 对齐。
    // SupervisorPid 是**发起连接的进程**（就是我们自己），EnginePid 才是引擎。
    // 早先两个字段写同一个 pid，等于对外宣称「引擎就是守护」——守护退出、只剩引擎时仍会被
    // 判成「守护活着」，状态就会报「已连接」，而实际没有任何进程在服务控制管道。
    let rec = serde_json::json!({
        "SchemaVersion": 1,
        "SupervisorPid": std::process::id() as i64,
        "EnginePid": engine_pid,
        "StartedAt": iso_from_epoch(now),
        "State": state,
        "Error": null,
        "CleanupError": false,
        // 真实值：来自本次连接 0.7 步的实际结局（**不许**写死）。写死会同时制造
        // 「明明没装上却说已阻断」和「装上了却说没阻断」两种谎。
        "TradingDirectAccessBlocked": trading_blocked,
        "BootStartedAt": iso_from_epoch(now)
    });
    // 原子写：半截 JSON 会让「引擎 pid 找不到」——断开杀不掉、already 永不成立。
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, rec.to_string()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("写运行时记录失败：{e}")
    })?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("替换运行时记录失败：{e}"));
    }
    Ok(())
}

/// 秒 → RFC3339。只用于给记录一个可读时间，不参与任何判定。
fn iso_from_epoch(secs: f64) -> String {
    let d = std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(secs.max(0.0));
    let odt = time::OffsetDateTime::from(d);
    odt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// 删掉运行时引擎配置（连接失败或断开后调用）。
///
/// 它里面只有一对"本次连接用"的自检凭据；留着没有任何用处，还会让人把
/// 「存在这个文件」当成「曾经连过」的证据。
pub fn discard_runtime_config(root: &std::path::Path) {
    let _ = std::fs::remove_file(root.join("runtime-engine.json"));
}

/// 这条线路实际会以哪种方式接管：以引擎配置里的入站为准，读不到才退回全局字段。
pub fn effective_mode(cfg: &AppConfig, engine: &EngineConfig) -> crate::config::Mode {
    engine
        .args
        .iter()
        .position(|a| a == "-c")
        .and_then(|i| engine.args.get(i + 1))
        .and_then(|p| crate::engine_config::actual_mode(std::path::Path::new(p)))
        .unwrap_or(cfg.mode)
}

/// 连接前的无副作用幂等检查。必须先于运行时配置和探测凭据的生成。
///
/// Ok(true)：现有引擎、模式、代理接管全部与目标相符，可直接 AlreadyDone；
/// Ok(false)：没有活的引擎，允许准备新配置；
/// Err：引擎还活着但当前状态与目标不一致，先断开，不能覆盖运行时文件。
pub fn preflight_before_prepare(
    cfg: &AppConfig,
    root: &Path,
    store: &ProxyStore,
    alive: &dyn Fn(i64) -> bool,
    legacy_running: bool,
) -> Result<bool, String> {
    let runtime_path = root.join("runtime.json");
    let engine_alive = read_engine_pid_opt(&runtime_path).map(alive).unwrap_or(false);
    if !engine_alive {
        return Ok(false);
    }
    let line = cfg.current_line()
        .ok_or_else(|| "当前引擎仍在运行，但线路已不存在；请先断开".to_string())?;
    let runtime_engine = root.join("runtime-engine.json");
    // 旧线路如果不需要派生规则，prepare_engine_config 直接返回原线路文件，
    // 此时 runtime-engine.json 不存在也是合法的运行态。兼容这条路径，
    // 但原线路也无法读取时仍拒绝重建。
    let active_config_path = if runtime_engine.exists() {
        runtime_engine
    } else {
        cfg.current_engine_path(root)
            .ok_or_else(|| "当前引擎仍在运行，但无法定位其线路配置；请先断开".to_string())?
    };
    let active_mode = crate::engine_config::actual_mode(&active_config_path)
        .ok_or_else(|| "当前引擎仍在运行，但无法核验其配置；请先断开，避免覆盖运行时凭据".to_string())?;
    if active_mode != cfg.mode {
        return Err("当前引擎仍在运行，但接管模式已变更；请先断开再连接".to_string());
    }
    if active_mode != crate::config::Mode::Tun {
        let plan = proxy::plan_connect(&store.read(), &line.proxy_endpoint, legacy_running);
        if plan.blocked.is_some() || !plan.changes.is_empty() {
            return Err("当前引擎仍在运行，但系统代理与本次线路不匹配；请先断开再连接".to_string());
        }
    }
    Ok(true)
}

/// 无须再次准备配置的 AlreadyDone 分支仍需与正常连接记录保持同一语义。
pub fn record_already_connected(
    cfg: &AppConfig,
    root: &Path,
    origin: &crate::events::Origin,
) -> Outcome {
    let line = cfg.current_line().map(|l| (l.id.clone(), l.name.clone())).unwrap_or_default();
    let mode = crate::engine_config::actual_mode(&root.join("runtime-engine.json")).unwrap_or(cfg.mode);
    crate::events::record(
        root,
        crate::events::CONNECT,
        true,
        &format!("{}（{}，当时已在连接状态）", line.1, mode.label()),
        &origin.clone().with_obj(format!("line:{}", line.0)),
    );
    Outcome::AlreadyDone
}

/// 连接。**这是唯一入口**：命令行 `--connect` 与界面按钮都从这里进。
///
/// 操作记录就挂在这一层：里面那套事务（写凭据→改代理→起引擎→写运行时记录）
/// 不该知道「有人在记日志」，而两个入口各记一次迟早会有一边忘。
#[cfg(test)]
pub fn connect(
    cfg: &AppConfig,
    engine: &EngineConfig,
    deps: &Deps,
    legacy_running: bool,
) -> Result<Outcome, String> {
    connect_with_origin(cfg, engine, deps, legacy_running, &crate::events::Origin::other())
}

pub fn connect_with_origin(
    cfg: &AppConfig,
    engine: &EngineConfig,
    deps: &Deps,
    legacy_running: bool,
    origin: &crate::events::Origin,
) -> Result<Outcome, String> {
    // 数据根由运行时记录的路径反推：它就在根下（`<root>\runtime.json`）。
    let root = deps.runtime_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    let line = cfg.current_line().map(|l| (l.id.clone(), l.name.clone())).unwrap_or_default();
    let mode = effective_mode(cfg, engine);
    let origin = origin.clone().with_obj(format!("line:{}", line.0));
    let out = connect_inner(cfg, engine, deps, legacy_running);
    match &out {
        Ok(Outcome::Done(_)) => crate::events::record(
            &root,
            crate::events::CONNECT,
            true,
            &format!("{}（{}）", line.1, mode.label()),
            &origin,
        ),
        // 已经连着再点一次也算一次操作：记下「当时就是这个状态」，比留个空档好查。
        Ok(Outcome::AlreadyDone) => crate::events::record(
            &root,
            crate::events::CONNECT,
            true,
            &format!("{}（{}，当时已在连接状态）", line.1, mode.label()),
            &origin,
        ),
        // 失败原因原文照抄：排障要看的就是这句话，转述会丢掉关键信息。
        Err(e) => crate::events::record(&root, crate::events::CONNECT, false, e, &origin),
    }
    out
}

fn connect_inner(
    cfg: &AppConfig,
    engine: &EngineConfig,
    deps: &Deps,
    legacy_running: bool,
) -> Result<Outcome, String> {
    // 没有线路就没有连接可言：这里必须拒绝，而不是拿一个空端点去改系统代理。
    let Some(line) = cfg.current_line() else {
        return Err("未配置线路：请先导入线路或用 --set-line 写入一条".to_string());
    };
    let endpoint = line.proxy_endpoint.clone();

    // 用**实际生效**的模式，而不是全局字段：全局 mode 可能与这条线路的入站不一致。
    // 提到最前面是因为它决定"要不要碰系统代理"——TUN 根本不走系统代理。
    let mode = effective_mode(cfg, engine);
    let tun = mode == crate::config::Mode::Tun;

    // TUN：**不读、不写、不还原**系统代理。所以也绝不能因为"读不到代理键"被拒——
    // 没有代理键的机器照样能用 TUN（QA 在那种环境里复现过 exit 13）。
    // 代理模式相反：读不到就接管不了，必须拒绝。
    let plan = if tun {
        None
    } else {
        let current = deps.store.read();
        let plan = proxy::plan_connect(&current, &endpoint, legacy_running);
        if let Some(b) = plan.blocked {
            return Err(b);
        }
        Some((current, plan))
    };

    // 用注入的 `alive` 而不是硬编码探针：否则这条分支在单测里根本走不到。
    // TUN 没有"代理变更"可言，只要引擎活着就是已达成目标。
    let engine_alive =
        read_engine_pid_opt(deps.runtime_path).map(|p| (deps.alive)(p)).unwrap_or(false);
    let no_proxy_work = plan.as_ref().map(|(_, p)| p.changes.is_empty()).unwrap_or(true);
    if engine_alive && no_proxy_work {
        return Ok(Outcome::AlreadyDone);
    }

    let mut did = Vec::new();

    // 0) TUN 要管理员权限：**动手之前**先确认能不能做。
    //    回滚能兜住是运气，回滚失败就把用户锁在接管状态——那是我们花两轮修过的事故。
    //    这条消息里绝不能出现「引擎启动失败」：那是回滚路径的措辞，两条路径必须能区分。
    //    位置在 `already` 之后：已经连着就不需要提权，也不该因为权限把它报成失败。
    if tun && !(deps.elevated)() {
        return Err(tun_need_admin_msg());
    }

    // 0.5) 端口必须是我们能用的。绑一下立刻放掉：端口被别人占着就没有「我们的通道」可言，
    //    而连接后的自检只会看到「这个端口能出网」，等于替别人的代理作证（假通过）。
    //    必须排在写还原凭据与改系统代理之前——端口不可用就不该把用户留在接管状态。
    //    注：这一步也在 `already` 之后，否则「已经连着」（端口正是我们引擎占着）会被误判成冲突。
    if let Some(port) = crate::selfcheck::port_from_endpoint(&endpoint) {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => drop(l),
            Err(e) => {
                return Err(format!(
                    "端口 127.0.0.1:{port} 已被占用（可能是另一个代理程序在运行）：{e}。请在导入线路时换一个端口。"
                ))
            }
        }
    }

    // 0.7) 交易程序直连阻断（PRD §5.6 / 架构 §5.1）。**顺序是硬要求**：
    //      必须在「写还原凭据 / 改系统代理 / 起引擎」之前——否则通道一起来，交易程序
    //      就已经能经由通道出去了，而阻断还没落地，那一段窗口正是要消灭的东西。
    //
    //      **永不阻断连接**：拒绝提权、装失败、旧版在跑，都只把结论写进 `did` 与运行时
    //      记录的 `TradingDirectAccessBlocked`，连接照旧建立（用户默认要的是通道）。
    //      例外只有一个：guard 装成功之后的步骤失败时，**不解除**已生效的保护。
    let mut trading_blocked = false;
    let mut guard_note: Option<String> = None;
    if let Some(g) = deps.guard.as_ref() {
        let outcome = crate::guard::ensure_before_connect(cfg, g.store, g.cache, g.hooks);
        trading_blocked = outcome.blocked();
        guard_note = Some(outcome.note());
    }
    if let Some(note) = &guard_note {
        // 放进 `did` 是唯一的用户可见通道：连接输出与操作记录都会带上这句话。
        did.push(note.clone());
    }

    // 1) 先落还原凭据。没有它就不许动系统代理。
    //    TUN 不写：它压根没改代理，写一份"还原凭据"只会让断开时去还原一个没动过的值。
    if let Some((current, _)) = &plan {
        if !deps.journal_path.exists() {
            let j = proxy::ProxyJournal::from_snapshot(current, &endpoint, deps.now);
            proxy::write_journal(deps.journal_path, &j)?;
            did.push("写入还原凭据".to_string());
        }
    }

    // 2) 改系统代理。apply 是逐键写：可能写了 ProxyEnable=1 却没写 ProxyServer ——
    //    那就是「半个接管」。失败必须立刻按凭据回滚，不能留在这个状态里。
    if let Some((_, plan)) = &plan {
        if !plan.changes.is_empty() {
            if let Err(e) = (deps.apply)(deps.store, &plan.changes) {
                // 写了一半 → 只能盲还原：这时候「是不是我们设的」已经判断不出来了。
                let note = match rollback_blind(deps.store, deps.journal_path) {
                    Ok(_) => "系统代理已还原".to_string(),
                    Err(x) => format!("还原也失败，请执行 --restore-apply：{x}"),
                };
                return Err(format!("修改系统代理失败：{e}；{note}"));
            }
            did.push(format!("修改系统代理 {} 项", plan.changes.len()));
        }
    }

    // 3) 起引擎。失败必须回滚代理，否则会留下「代理指向空服务」的状态。
    let pid = match (deps.spawn)(engine) {
        Ok(p) => p,
        Err(e) => {
            let note = rollback_note(deps, &endpoint, tun);
            return Err(format!("引擎启动失败：{e}；{note}"));
        }
    };

    // 3.5) spawn 成功不等于引擎真的活着：TUN 建网卡失败、配置被拒这类错都发生在进程
    //      起来之后几十毫秒内。不看这一段就会报「已连接」，把用户留在「代理指向死引擎」——
    //      这是我们最要消灭的那种「看起来连上了」。前置的提权检查挡不住「管理员但引擎自己崩」。
    if !await_alive(deps, pid) {
        let note = rollback_note(deps, &endpoint, tun);
        // 运行时记录也清掉：引擎没活下来，留着记录等于事后对状态投影撒谎。
        let _ = std::fs::remove_file(deps.runtime_path);
        let hint = if mode == crate::config::Mode::Tun {
            format!("。{TUN_HINT}")
        } else {
            String::new()
        };
        return Err(format!("引擎启动后立即退出（pid={pid}）；{note}{hint}"));
    }
    did.push(format!("启动引擎 pid={pid}"));

    // 4) 写运行时记录。放在宽限之后：引擎没活下来就根本不该留下记录。
    //    写失败必须先把引擎杀掉：没有记录就找不到 pid，断开时杀不掉它，
    //    而且 `already` 永远不成立——每次连接都会再起一个引擎。
    if let Err(e) = write_runtime(deps.runtime_path, pid, deps.now, "Running", trading_blocked) {
        let kill_note = match (deps.kill)(pid) {
            Ok(()) => format!("已停止引擎 pid={pid}"),
            Err(x) => format!("停止引擎失败（{x}），请手动结束 pid={pid}"),
        };
        let note = rollback_note(deps, &endpoint, tun);
        return Err(format!("写运行时记录失败：{e}；{kill_note}；{note}"));
    }
    did.push("写入运行时记录".to_string());

    Ok(Outcome::Done(did))
}

/// TUN 权限提示的公共部分：前置拦截、闪退回滚、`explain` 三处都从这里拼，
/// 免得哪天只改了其中一处，用户看到三种说法。
const TUN_HINT: &str = "TUN 模式需要管理员权限运行本程序";

/// TUN 前置拦截的固定措辞。刻意不含「引擎启动失败」——那是回滚路径的说法。
fn tun_need_admin_msg() -> String {
    format!("{TUN_HINT}：请用「以管理员身份启动」的入口重新打开")
}

/// 引擎起来之后的观察窗：能活过 `GRACE_MS` 才算「起来了」。
///
/// 只等「活到窗口结束」——窗口内任何一次探测发现它没了，立刻判定失败并回滚。
/// 代价是每次连接多等 `GRACE_MS`；TUN 建卡失败通常在几十毫秒内就退，这个窗口足够。
const GRACE_MS: u64 = 800;
const GRACE_STEP_MS: u64 = 50;

fn await_alive(deps: &Deps, pid: i64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(GRACE_MS);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(GRACE_STEP_MS));
        if !(deps.alive)(pid) {
            return false;
        }
        if std::time::Instant::now() >= deadline {
            return true;
        }
    }
}

/// 给连接失败的原因补一句 TUN 专用提示。
///
/// 只对「引擎启动失败」（spawn 就失败）补：而 TUN 权限问题现在由前置检查挡在更前面，
/// 这条只兜「引擎文件不可用」这类与权限无关的启动失败。端口被占、被旧版挡下都不加，
/// 否则会把排查方向带偏。
pub fn explain(msg: String, mode: crate::config::Mode) -> String {
    if mode == crate::config::Mode::Tun && msg.contains("引擎启动失败") {
        format!("{msg}。{TUN_HINT}")
    } else {
        msg
    }
}

/// 断开不需要配置：要停的引擎 pid 在 `runtime.json`，要还原的值在还原凭据里，
/// 两者都在配置之外。配置缺失或损坏时仍然必须能断开——否则用户会被锁死在接管状态。
#[cfg(test)]
pub fn disconnect(cfg: Option<&AppConfig>, deps: &Deps) -> Result<Outcome, String> {
    disconnect_with_origin(cfg, deps, &crate::events::Origin::other())
}

pub fn disconnect_with_origin(
    cfg: Option<&AppConfig>,
    deps: &Deps,
    origin: &crate::events::Origin,
) -> Result<Outcome, String> {
    let root = deps.runtime_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    let object = cfg
        .and_then(|c| c.current_line())
        .map(|l| format!("line:{}", l.id))
        .unwrap_or_else(|| "connection".to_string());
    let origin = origin.clone().with_obj(object);
    let out = disconnect_inner(cfg, deps);
    match &out {
        Ok(Outcome::Done(steps)) => {
            let detail = if steps.is_empty() {
                "没有需要还原的改动".to_string()
            } else {
                steps.join("、")
            };
            crate::events::record(&root, crate::events::DISCONNECT, true, &detail, &origin);
        }
        // 本来就没连：这不是一次「操作」，留一条「断开（没连过）」只会淹没真正的断开记录。
        Ok(Outcome::AlreadyDone) => {}
        Err(e) => crate::events::record(&root, crate::events::DISCONNECT, false, e, &origin),
    }
    out
}

fn disconnect_inner(cfg: Option<&AppConfig>, deps: &Deps) -> Result<Outcome, String> {
    let mut did = Vec::new();

    // 1) 先停引擎：否则还原代理之后，引擎仍在跑，流量会绕过代理直连。
    //    这里必须按 EnginePid 停——守护就是我们自己，照着 SupervisorPid 去 kill 等于自杀。
    if let Some(pid) = read_engine_pid_opt(deps.runtime_path) {
        (deps.kill)(pid)?;
        did.push(format!("停止引擎 pid={pid}"));
    }
    let _ = std::fs::remove_file(deps.runtime_path);

    // 断开前先判断这条连接是哪种模式：**TUN 从没碰过系统代理**，就不该去还原（也不该去读代理键）。
    // 认的是引擎真正吃的那份配置（连接期间它一定在）；文件没了（异常退出）才退回配置字段。
    let engine_cfg = deps.runtime_path.with_file_name("runtime-engine.json");
    let tun_conn = match crate::engine_config::actual_mode(&engine_cfg) {
        Some(m) => m == crate::config::Mode::Tun,
        None => cfg.map(|c| c.mode) == Some(crate::config::Mode::Tun),
    };
    // 运行时引擎配置里带着本次探测凭据：断开必须连它一起清掉——凭据不许留在磁盘上。
    // 它本来就是每次连接重新生成的派生物，删了下次连接会再生成。
    let _ = std::fs::remove_file(&engine_cfg);

    // 2) 还原代理：优先用凭据里记录的端点；配置只是最后的兜底，没有也能还原。
    //    TUN 跳过：它没写过凭据，去还原只会动到我们没碰过的值。
    if !tun_conn {
        let endpoint = cfg
            .and_then(|c| c.current_line())
            .map(|l| l.proxy_endpoint.clone())
            .unwrap_or_default();
        let rb = rollback_proxy(deps, &endpoint)?;
        if rb {
            did.push("还原系统代理".to_string());
        }
    }

    if did.is_empty() {
        return Ok(Outcome::AlreadyDone);
    }

    // 3) 断开是**强制失效事件**（PRD §4.2 / §4.1.1）：旧证据当场作废，然后尝试一次核验。
    //
    //    这里永不 `Err`：被拒绝/失败只影响 `GuardVerifyPending`（「本次未能重新核验」），
    //    三态与旧证据的时龄照旧展示（A23）。断开本身更不能因为核验失败而失败——
    //    那会把用户锁在接管状态，是我们最不能接受的那种失败。
    if let Some(g) = deps.guard.as_ref() {
        let st = crate::guard::reverify_after_disconnect(cfg, g.store, g.cache, g.hooks);
        did.push(disconnect_guard_note(&st));
    }
    Ok(Outcome::Done(did))
}

/// 断开后那句话：**只说「这次核验的结果」，不改口说状态**。
fn disconnect_guard_note(st: &crate::guard::GuardStatus) -> String {
    match st.verify_pending {
        crate::guard::VerifyPending::None => "交易保护已重新核验".to_string(),
        crate::guard::VerifyPending::Declined => {
            "交易保护本次未能重新核验（未获得管理员确认）".to_string()
        }
        crate::guard::VerifyPending::Failed => "交易保护本次未能重新核验（核验失败）".to_string(),
        crate::guard::VerifyPending::Unknown => "交易保护本次未能重新核验".to_string(),
    }
}

/// 关窗清理：把「断开」整条事务跑一遍，返回做过的动作。
///
/// 直接调 `disconnect`，**一步都不复制**——「点按钮断开」和「关窗口断开」若是两份实现，
/// 迟早会长出两套行为，而这两种时机的现场往往不一样，最不该分叉。
///
/// 没配置或没有运行时记录时返回空步骤：关窗不该因为「没啥可清理」而报错。
pub fn shutdown_cleanup(
    cfg: Option<&AppConfig>,
    deps: &Deps,
    origin: &crate::events::Origin,
) -> Result<Vec<String>, String> {
    match disconnect_with_origin(cfg, deps, origin)? {
        Outcome::AlreadyDone => Ok(Vec::new()),
        Outcome::Done(steps) => Ok(steps),
    }
}

/// 按凭据把代理改回去。返回是否真的改了。成功后删除凭据。
/// 连接失败时那句"代理怎么办"的说明。
///
/// TUN 从没碰过系统代理：既不该去读凭据（那台机器可能压根没有代理键），
/// 也不能说"已还原"（没动过的东西谈不上还原）。
fn rollback_note(deps: &Deps, endpoint: &str, tun: bool) -> String {
    if tun {
        return "未接管系统代理，无需还原".to_string();
    }
    match rollback_proxy(deps, endpoint) {
        Ok(_) => "系统代理已还原".to_string(),
        Err(x) => format!("还原也失败，请执行 --restore-apply：{x}"),
    }
}

fn rollback_proxy(deps: &Deps, fallback_endpoint: &str) -> Result<bool, String> {
    restore_from_journal(deps.store, deps.journal_path, fallback_endpoint)
}

/// 按凭据还原系统代理；读不到当前代理时**盲还原**。返回是否真的改了。
///
/// 连接失败时的自动回滚与 `--restore-apply` **共用这一份**：三处错误提示都以
/// 「请执行 --restore-apply」作兜底承诺，那条命令就不能比自动回滚更弱——
/// 否则用户被自动回滚救不了的场景，手工命令也救不了。
pub fn restore_from_journal(
    store: &ProxyStore,
    journal_path: &Path,
    fallback_endpoint: &str,
) -> Result<bool, String> {
    let j = match proxy::read_journal(journal_path) {
        Ok(Some(j)) => j,
        Ok(None) => return Ok(false),
        Err(e) => return Err(e),
    };
    let current = store.read();
    // 读不到当前代理时不能拒绝还原：那会把用户永久留在接管状态。
    // 直接按凭据写回接管前的值，并明确告警（用户可能改过设置，我们要让他知道）。
    if !current.readable {
        let changes = proxy::plan_restore_blind(&j);
        store.apply(&changes)?;
        let _ = std::fs::remove_file(journal_path);
        eprintln!("警告：无法读取当前系统代理，已按还原凭据直接写回接管前的值。");
        return Ok(true);
    }
    // 用凭据里记录的端点判断「是否还是我们设的」；凭据里没有就退回配置值。
    let ours = if j.endpoint.is_empty() { fallback_endpoint } else { j.endpoint.as_str() };
    let rp = proxy::plan_restore(&j, &current, ours);
    for warning in &rp.warnings {
        eprintln!("系统代理还原提醒：{warning}");
    }
    if let Some(b) = rp.blocked {
        return Err(b);
    }
    if rp.changes.is_empty() {
        let _ = std::fs::remove_file(journal_path);
        return Ok(false);
    }
    store.apply(&rp.changes)?;
    let _ = std::fs::remove_file(journal_path);
    Ok(true)
}

/// 写代理失败后的回滚：当前状态是「写了一半」的混合态——可能 ProxyEnable 已经是我们的、
/// ProxyServer 还是旧值。此时任何「这还是不是我们设的」的启发式判断都不可靠，
/// 唯一安全的做法是**无条件写回凭据里那份接管前的快照**。
fn rollback_blind(store: &ProxyStore, journal_path: &Path) -> Result<bool, String> {
    let j = match proxy::read_journal(journal_path) {
        Ok(Some(j)) => j,
        Ok(None) => return Ok(false),
        Err(e) => return Err(e),
    };
    let changes = proxy::plan_restore_blind(&j);
    store.apply(&changes)?;
    let _ = std::fs::remove_file(journal_path);
    Ok(true)
}

/// 启动自愈：上次异常退出（强杀 / 注销 / 断电）会留下「凭据在、引擎已死、代理还指着我们」。
/// 不在启动时修，用户下次开机就是断网。
///
/// 这条不依赖任何回调，覆盖全部异常退出方式——它才是主防线，注销钩子只是尽力而为。
/// 引擎还活着就一律不动：那是有人在正常服务这条通道。
pub fn heal_stale(store: &ProxyStore, journal_path: &Path, runtime_path: &Path) -> Option<String> {
    if !journal_path.exists() {
        return None;
    }
    let engine_alive =
        read_engine_pid_opt(runtime_path).map(crate::probe::pid_alive).unwrap_or(false);
    if engine_alive {
        return None;
    }
    Some(match restore_from_journal(store, journal_path, "") {
        Ok(_) => {
            let _ = std::fs::remove_file(runtime_path);
            // 自愈同理：残留的 runtime-engine.json 里可能还有上次的探测凭据，一并清掉。
            let _ = std::fs::remove_file(runtime_path.with_file_name("runtime-engine.json"));
            // 自愈成功后必须把「通道自检通过」清掉：状态已经是「未连接」，
            // 还挂着一条"通过"的结论就是假证据（`--disconnect` 路径一直是这么做的，这里漏了）。
            if let Some(root) = journal_path.parent() {
                crate::selfcheck::clear(root);
            }
            "上次退出未清理（残留还原凭据 + 引擎已不在），已自动还原系统代理".to_string()
        }
        Err(e) => format!("上次退出未清理，自动还原失败：{e}；请执行 --restore-apply"),
    })
}

/// 运行时记录里的**引擎** pid。断开要停的是引擎，不是守护——
/// 守护就是发起连接的那个进程，照着 SupervisorPid 去 kill 等于杀掉自己。
fn read_engine_pid_opt(path: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    let rec: RuntimeRecord = serde_json::from_str(&text).ok()?;
    rec.engine_pid.filter(|p| *p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LineConfig, AppConfig};

    fn cfg() -> AppConfig {
        cfg_on(next_test_port())
    }

    fn cfg_on(port: u16) -> AppConfig {
        AppConfig {
            schema: 1,
            mode: crate::config::Mode::Proxy,
            auto_start: false,
            auto_connect: false,
            close_to_tray: false,
            quality_warning: true,
            auto_trust_first_connection: true,
            selected: "L1".into(),
            split: Default::default(),
            agents: Default::default(),
            exits: Default::default(),
            lines: vec![LineConfig {
                id: "L1".into(),
                name: "测试线路".into(),
                proxy_endpoint: format!("127.0.0.1:{port}"),
                transport: None,
                verified_transport: None,
            }],
            engine: None,
        }
    }

    /// 每个用例一个不同的端口，且按进程号取基址。
    ///
    /// 两层都要：**用例之间**不能同端口（连接现在会真去 bind，同进程并行跑会互抢）；
    /// **进程之间**也要错开（可能同时有另一个 `cargo test`/真机引擎在跑，撞上就变成看运气的测试）。
    fn next_test_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static N: AtomicU16 = AtomicU16::new(0);
        let base = 50_000 + (std::process::id() % 200) as u16 * 60;
        base + N.fetch_add(1, Ordering::Relaxed)
    }

    fn engine() -> EngineConfig {
        EngineConfig { binary: r"C:\Windows\System32\PING.EXE".into(), args: vec!["-n".into(), "30".into(), "127.0.0.1".into()] }
    }

    struct Fixture {
        store: ProxyStore,
        journal: std::path::PathBuf,
        runtime: std::path::PathBuf,
    }

    fn fixture(tag: &str) -> Fixture {
        let key = format!(r"Software\SpiderVPN\tests\conn-{tag}-{}", std::process::id());
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&key);
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &0u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:7897").unwrap();
            k.set_value("ProxyOverride", &"localhost;<local>").unwrap();
        }
        let dir = std::env::temp_dir().join(format!("tcrs-conn-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Fixture {
            store: ProxyStore { key_path: key },
            journal: dir.join("proxy-journal.json"),
            runtime: dir.join("runtime.json"),
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.store.key_path);
        }
    }

    fn deps<'a>(f: &'a Fixture, spawn: &'a dyn Fn(&EngineConfig) -> Result<i64, String>, kill: &'a dyn Fn(i64) -> Result<(), String>) -> Deps<'a> {
        // 默认：引擎活着、进程已提权。要测别的路径用下面的 deps_with。
        deps_with(f, spawn, kill, &always_alive, &always_elevated)
    }

    fn deps_with<'a>(
        f: &'a Fixture,
        spawn: &'a dyn Fn(&EngineConfig) -> Result<i64, String>,
        kill: &'a dyn Fn(i64) -> Result<(), String>,
        alive: &'a dyn Fn(i64) -> bool,
        elevated: &'a dyn Fn() -> bool,
    ) -> Deps<'a> {
        Deps {
            store: &f.store,
            apply: &write_proxy,
            spawn,
            kill,
            alive,
            elevated,
            journal_path: &f.journal,
            runtime_path: &f.runtime,
            now: 1_700_000_000.0,
            guard: None,
        }
    }

    // fn item 是 'static 的，可以安全地当成 &dyn Fn 传进 Deps。
    fn always_alive(_pid: i64) -> bool {
        true
    }
    fn never_alive(_pid: i64) -> bool {
        false
    }
    fn always_elevated() -> bool {
        true
    }
    fn not_elevated() -> bool {
        false
    }

    fn cfg_with_mode(port: u16, mode: crate::config::Mode) -> AppConfig {
        AppConfig { mode, ..cfg_on(port) }
    }

    #[test]
    fn tun_hint_only_for_engine_start_failure() {
        use crate::config::Mode;
        let e = "引擎启动失败：拒绝访问；系统代理已还原".to_string();
        assert!(explain(e.clone(), Mode::Tun).contains("管理员权限"), "TUN 起不来最常见就是没提权");
        assert_eq!(explain(e.clone(), Mode::Proxy), e, "代理模式不该冒出一句 TUN 提示");
        let other = "端口 127.0.0.1:17890 已被占用".to_string();
        assert_eq!(explain(other.clone(), Mode::Tun), other, "端口问题与权限无关，别误导排查方向");
    }

    /// 造一个"引擎配置里带 TUN 入站"的 EngineConfig（`effective_mode` 靠它认模式）。
    fn tun_engine(dir: &std::path::Path) -> EngineConfig {
        let cfg = dir.join("engine-tun.json");
        std::fs::write(&cfg, r#"{"inbounds":[{"type":"tun","tag":"t"}]}"#).unwrap();
        EngineConfig {
            binary: r"C://Windows//System32//PING.EXE".into(),
            args: vec!["-c".into(), cfg.to_string_lossy().to_string()],
        }
    }

    #[test]
    fn tun_connect_never_touches_the_system_proxy() {
        // TUN 不走系统代理：不读、不写、不写还原凭据，断开也不还原。
        // 【回归】之前它和代理模式共用同一段 preflight，没有代理键的机器上会被 exit 13 挡住。
        use crate::config::Mode;
        let f = fixture("tun-noproxy");
        let c = cfg_with_mode(17895, Mode::Tun);
        let e = tun_engine(f.runtime.parent().unwrap());
        let before = f.store.read();
        let spawn = |_: &EngineConfig| Ok(4242i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);

        let out = connect(&c, &e, &d, false).expect("TUN 应当直接连上（不该被代理 preflight 挡住）");
        assert!(matches!(out, Outcome::Done(_)));
        assert!(!f.journal.exists(), "TUN 不该写还原凭据");
        let mid = f.store.read();
        assert_eq!(mid.enable, before.enable, "TUN 不许改 ProxyEnable");
        assert_eq!(mid.server, before.server, "TUN 不许改 ProxyServer");

        // 断开：TUN 没有代理要还原，代理键一个字节都不许动
        disconnect(Some(&c), &d).unwrap();
        let post = f.store.read();
        assert_eq!(post.enable, before.enable, "断开也不许动代理");
        assert_eq!(post.server, before.server);
        assert!(!f.journal.exists());
    }

    #[test]
    fn connect_then_disconnect_restores_proxy() {
        let f = fixture("happy");
        let c = cfg();
        let before = f.store.read();
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);

        let out = connect(&c, &engine(), &d, false).unwrap();
        assert!(matches!(out, Outcome::Done(_)));
        let mid = f.store.read();
        assert!(mid.enable);
        assert_eq!(mid.server.as_deref(), Some(c.current_line().unwrap().proxy_endpoint.as_str()));
        assert!(f.journal.exists(), "凭据必须已落盘");
        assert!(f.runtime.exists(), "运行时记录必须已写");

        // 运行时引擎配置里带着本次探测凭据（连接时生成）：断开必须连它一起清掉。
        let runtime_engine = f.runtime.with_file_name("runtime-engine.json");
        std::fs::write(&runtime_engine, r#"{"inbounds":[]}"#).unwrap();

        let out = disconnect(Some(&cfg()), &d).unwrap();
        assert!(matches!(out, Outcome::Done(_)));
        let after = f.store.read();
        assert_eq!(after.enable, before.enable);
        assert_eq!(after.server, before.server);
        assert_eq!(after.bypass, before.bypass);
        assert!(!f.journal.exists(), "还原后凭据应被删除");
        assert!(!f.runtime.exists());
        assert!(!runtime_engine.exists(), "带探测凭据的运行时引擎配置必须随断开清掉");
    }

    #[test]
    fn connect_rolls_back_proxy_when_engine_fails() {
        let f = fixture("rollback");
        let before = f.store.read();
        let spawn = |_: &EngineConfig| Err("模拟启动失败".to_string());
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);

        let err = connect(&cfg(), &engine(), &d, false).unwrap_err();
        assert!(err.contains("引擎启动失败"));

        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "启动失败必须把代理改回去");
        assert_eq!(after.server, before.server);
        assert!(!f.journal.exists(), "回滚完成后凭据应清掉");
    }

    #[test]
    fn connect_is_blocked_when_legacy_running() {
        let f = fixture("legacy");
        let spawn = |_: &EngineConfig| Ok(1i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);
        let err = connect(&cfg(), &engine(), &d, true).unwrap_err();
        assert!(err.contains("旧版"));
        assert!(!f.journal.exists(), "被阻止时不该留下任何痕迹");
    }

    #[test]
    fn connect_fails_fast_when_port_is_taken() {
        let f = fixture("port-taken");
        // 端口被别的程序占着：真机上这很常见（另一个代理先起在同一个端口）。
        // 此时自检会看到「这个端口能出网」，等于替别人的代理作证——必须在动手之前就拒绝。
        let squatter = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = squatter.local_addr().unwrap().port();
        let before = f.store.read();
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);

        let err = connect(&cfg_on(port), &engine(), &d, false).unwrap_err();
        assert!(err.contains("已被占用"), "错误要说清是端口被占：{err}");
        assert!(err.contains(&port.to_string()), "要指出是哪个端口：{err}");
        // 失败必须干净：不动系统代理、不写凭据、不写运行时记录。
        assert!(!f.journal.exists(), "端口不可用时不该写还原凭据");
        assert!(!f.runtime.exists(), "端口不可用时不该起引擎/写运行时记录");
        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "端口不可用时不许改系统代理");
        assert_eq!(after.server, before.server);
        assert_eq!(after.bypass, before.bypass);
        drop(squatter);
    }

    #[test]
    fn port_free_check_does_not_consume_the_port() {
        let f = fixture("port-free");
        let port = next_test_port();
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);

        connect(&cfg_on(port), &engine(), &d, false).unwrap();
        // 检查是「绑一下立刻放掉」：连接跑完后端口仍然可以被绑定。
        // （假引擎不监听，所以这里能拿到；拿不到就说明我们把端口留在了占用状态。）
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => drop(l),
            Err(e) => panic!("端口可用性检查不能把端口留在占用状态：{e}"),
        }
    }

    #[test]
    fn apply_failure_rolls_back_the_half_takeover() {
        // 真实风险：apply 是逐键写，可能写了 ProxyEnable=1 却没写 ProxyServer。
        // 用户拿到的错误若只说「写 ProxyServer 失败」，没人知道代理已经被改了一半。
        let f = fixture("apply-fail");
        let before = f.store.read();
        let calls = std::cell::Cell::new(0);
        // 第一次（接管）故意只写第一项就失败——正是「半接管」的现场；之后的回滚走真实写入。
        let apply = |store: &ProxyStore, changes: &[proxy::Change]| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                let _ = store.apply(&changes[..1]);
                return Err("模拟写 ProxyServer 失败".to_string());
            }
            store.apply(changes)
        };
        let spawned = std::cell::Cell::new(0);
        let spawn = |_: &EngineConfig| {
            spawned.set(spawned.get() + 1);
            Ok(424242i64)
        };
        let kill = |_: i64| Ok(());
        let d = Deps {
            store: &f.store,
            apply: &apply,
            spawn: &spawn,
            kill: &kill,
            alive: &always_alive,
            elevated: &always_elevated,
            journal_path: &f.journal,
            runtime_path: &f.runtime,
            now: 1_700_000_000.0,
            guard: None,
        };

        let err = connect(&cfg_on(next_test_port()), &engine(), &d, false).unwrap_err();
        assert!(err.contains("修改系统代理失败"), "要说清哪一步失败：{err}");
        assert!(
            err.contains("已还原") || err.contains("--restore-apply"),
            "错误里必须交代回滚结果，否则用户不知道代理是半态还是一场空：{err}"
        );
        assert_eq!(spawned.get(), 0, "代理没改成就不允许起引擎");
        // 关键：三项都回到接管前，不是半态
        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "ProxyEnable 必须回到接管前");
        assert_eq!(after.server, before.server, "ProxyServer 必须回到接管前");
        assert_eq!(after.bypass, before.bypass);
        assert!(!f.journal.exists(), "回滚成功后凭据要清掉");
        assert!(!f.runtime.exists());
    }

    // ---------- 评审第 2/3/4/5/6 条：原子写、失败回滚、启动自愈 ----------

    #[test]
    fn runtime_write_failure_kills_the_engine_and_rolls_back() {
        // 运行时记录路径被一个目录占住 → 写必失败。
        let f = fixture("runtime-fail");
        let before = f.store.read();
        std::fs::create_dir_all(&f.runtime).unwrap();
        let killed = std::cell::Cell::new(0i64);
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |pid: i64| {
            killed.set(pid);
            Ok(())
        };
        let d = deps(&f, &spawn, &kill);

        let err = connect(&cfg_on(next_test_port()), &engine(), &d, false).unwrap_err();
        assert!(err.contains("写运行时记录失败"), "{err}");
        assert_eq!(killed.get(), 424242, "没有记录就找不到 pid，必须先杀引擎");
        assert!(err.contains("已停止引擎"), "要把停引擎的结果说出来：{err}");
        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "代理必须回滚");
        assert_eq!(after.server, before.server);
        assert!(!f.journal.exists(), "凭据应清掉");
        let _ = std::fs::remove_dir_all(&f.runtime);
    }

    #[test]
    fn heal_restores_when_credential_left_but_engine_is_gone() {
        // 强杀/断电后的现场：凭据在、引擎已死、代理还指着我们。启动时必须自动还原。
        let f = fixture("heal-stale");
        let taken = crate::proxy::ProxySnapshot {
            enable: true,
            server: Some("127.0.0.1:17890".to_string()),
            bypass: Some("localhost".to_string()),
            readable: true,
        };
        std::fs::write(
            &f.journal,
            r#"{"schema":1,"endpoint":"127.0.0.1:17890","saved_at_secs":0,
                "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
        )
        .unwrap();
        std::fs::write(
            &f.runtime,
            r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":4194303,"State":"Running"}"#,
        )
        .unwrap();
        let _ = taken;

        let msg = heal_stale(&f.store, &f.journal, &f.runtime).expect("应当自愈并报出来");
        assert!(msg.contains("已自动还原"), "{msg}");
        assert!(!f.journal.exists(), "自愈后凭据要清掉");
        assert!(!f.runtime.exists(), "自愈后运行时记录要清掉");
        let after = f.store.read();
        assert!(!after.enable, "代理必须回到接管前（关）");
        assert_eq!(after.server.as_deref(), Some("127.0.0.1:7897"));
    }

    #[test]
    fn heal_clears_the_last_check_record_after_restoring() {
        // 缺陷回归：自愈完状态是「未连接」，却还挂着「通道自检：通过」——那是假证据。
        let f = fixture("heal-check");
        std::fs::write(
            &f.journal,
            r#"{"schema":1,"endpoint":"127.0.0.1:17890","saved_at_secs":0,
                "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
        )
        .unwrap();
        std::fs::write(
            &f.runtime,
            r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":4194303,"State":"Running"}"#,
        )
        .unwrap();
        // 上一次连接留下的"通过"结论
        let check = f.journal.parent().unwrap().join(crate::selfcheck::FILE_NAME);
        std::fs::write(&check, r#"{"ok":true,"status":204,"error":null,"at":1}"#).unwrap();

        let msg = heal_stale(&f.store, &f.journal, &f.runtime).expect("应当自愈");
        assert!(msg.contains("已自动还原"), "{msg}");
        assert!(!check.exists(), "自愈后通道自检结论必须清掉，否则「未连接 + 自检通过」自相矛盾");
    }

    #[test]
    fn heal_leaves_a_live_connection_alone() {
        // 引擎还活着 = 有人正在服务这条通道：不许动。
        let f = fixture("heal-live");
        std::fs::write(
            &f.journal,
            r#"{"schema":1,"endpoint":"127.0.0.1:17890","saved_at_secs":0,
                "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
        )
        .unwrap();
        std::fs::write(
            &f.runtime,
            format!(
                r#"{{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":{},"State":"Running"}}"#,
                std::process::id()
            ),
        )
        .unwrap();

        assert_eq!(heal_stale(&f.store, &f.journal, &f.runtime), None, "活着就别动");
        assert!(f.journal.exists());
    }

    #[test]
    fn restore_from_journal_blind_when_registry_unreadable() {
        // 读不到当前代理（键不存在）时也要按凭据写回：这是 --restore-apply 的兜底能力。
        let f = fixture("blind");
        let blind = crate::proxy::ProxyStore {
            key_path: format!(r"Software\SpiderVPN	estslind-{}", std::process::id()),
        };
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&blind.key_path);
        std::fs::write(
            &f.journal,
            r#"{"schema":1,"endpoint":"127.0.0.1:17890","saved_at_secs":0,
                "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
        )
        .unwrap();

        let changed = restore_from_journal(&blind, &f.journal, "").expect("盲还原应当成功");
        assert!(changed, "应当真的写了");
        assert!(!f.journal.exists(), "还原后凭据清除");
        let after = blind.read();
        assert!(!after.enable);
        assert_eq!(after.server.as_deref(), Some("127.0.0.1:7897"), "按凭据写回原值");
        let _ = hkcu.delete_subkey_all(&blind.key_path);
    }

    // ---------- 引擎「起得来随即退出」：全量回滚 ----------

    #[test]
    fn engine_dies_immediately_rolls_back_everything() {
        let f = fixture("dies");
        let before = f.store.read();
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &never_alive, &always_elevated);

        let err = connect(&cfg_on(next_test_port()), &engine(), &d, false).unwrap_err();
        assert!(err.contains("引擎启动后立即退出"), "错误要点明是起来又死了：{err}");
        assert!(err.contains("系统代理已还原"), "回滚结果也要报出来：{err}");
        // 失败必须干净：什么都不许留下
        assert!(!f.journal.exists(), "闪退后不该留着还原凭据");
        assert!(!f.runtime.exists(), "闪退后不该留着运行时记录");
        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "代理必须回到接管前");
        assert_eq!(after.server, before.server);
        assert_eq!(after.bypass, before.bypass);
    }

    #[test]
    fn engine_alive_grace_does_not_change_success_path() {
        let f = fixture("grace-ok");
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &always_alive, &always_elevated);

        match connect(&cfg_on(next_test_port()), &engine(), &d, false).unwrap() {
            Outcome::Done(steps) => {
                assert!(steps.iter().any(|s| s.starts_with("启动引擎 pid=424242")), "{steps:?}");
                assert!(steps.contains(&"写入运行时记录".to_string()), "{steps:?}");
            }
            other => panic!("引擎活着就该是 Done：{other:?}"),
        }
        assert!(f.journal.exists());
        assert!(f.runtime.exists());
    }

    #[test]
    fn tun_mode_death_mentions_administrator() {
        let f = fixture("tun-dies");
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &never_alive, &always_elevated);

        let err = connect(&cfg_with_mode(next_test_port(), crate::config::Mode::Tun), &engine(), &d, false)
            .unwrap_err();
        assert!(err.contains("引擎启动后立即退出"), "{err}");
        assert!(err.contains("管理员"), "TUN 下要提示权限这一层原因：{err}");
    }

    #[test]
    fn grace_period_is_bounded() {
        // 防「万一写成死循环」：alive 恒 false 时必须在宽限上限附近返回。
        let f = fixture("grace-bound");
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &never_alive, &always_elevated);

        let t0 = std::time::Instant::now();
        let _ = connect(&cfg_on(next_test_port()), &engine(), &d, false).unwrap_err();
        let ms = t0.elapsed().as_millis();
        assert!(ms <= 1_200, "宽限上限 800ms，实测 {ms}ms —— 是不是变成死等了");
    }

    // ---------- TUN 前置：没有管理员权限就别动手 ----------

    #[test]
    fn tun_without_elevation_fails_before_touching_anything() {
        let f = fixture("tun-noadmin");
        let before = f.store.read();
        let spawned = std::cell::Cell::new(0);
        let spawn = |_: &EngineConfig| {
            spawned.set(spawned.get() + 1);
            Ok(424242i64)
        };
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &always_alive, &not_elevated);

        let err = connect(&cfg_with_mode(next_test_port(), crate::config::Mode::Tun), &engine(), &d, false)
            .unwrap_err();
        assert!(err.contains("管理员"), "要说清是权限问题：{err}");
        assert!(
            !err.contains("引擎启动失败"),
            "前置拦截不能借用回滚路径的措辞，否则两条路径分不开：{err}"
        );
        assert!(!err.contains("引擎启动后立即退出"), "这是「没动手」，不是「起来又死了」：{err}");
        // 什么都没动
        assert_eq!(spawned.get(), 0, "拦截要在起引擎之前");
        assert!(!f.journal.exists(), "不该写还原凭据");
        assert!(!f.runtime.exists(), "不该写运行时记录");
        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "不该改系统代理");
        assert_eq!(after.server, before.server);
        assert_eq!(after.bypass, before.bypass);
    }

    /// 写一份只有这类入站的引擎配置，返回路径（用于让 `effective_mode` 读到"实际模式"）。
    fn engine_cfg_with_inbounds(tag: &str, inbounds: &str) -> (EngineConfig, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("tcrs-effmode-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("line.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"inbounds":{inbounds},"outbounds":[{{"type":"direct","tag":"direct"}}],"route":{{"rules":[],"final":"direct"}}}}"#
            ),
        )
        .unwrap();
        let mut eng = engine();
        eng.args = vec!["run".into(), "-c".into(), path.to_string_lossy().into_owned()];
        (eng, dir)
    }

    #[test]
    fn tun_line_requires_elevation_even_when_global_mode_says_proxy() {
        // D6 方向②（最危险的那个）：全局 mode=proxy，但选中的线路是 TUN 配置。
        // 旧实现拿全局字段判断"不需要管理员" → 跳过提权直接起 TUN（真建卡、真改路由表），
        // 而界面还显示「代理」。必须按**线路实际入站**判定为 TUN，并在动手之前拦下。
        let f = fixture("tun-line-proxy-mode");
        let (eng, dir) = engine_cfg_with_inbounds("tun", r#"[{"type":"tun","tag":"trade-tun"}]"#);
        let spawned = std::cell::Cell::new(0);
        let spawn = |_: &EngineConfig| {
            spawned.set(spawned.get() + 1);
            Ok(424242i64)
        };
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &always_alive, &not_elevated);
        let err = connect(
            &cfg_with_mode(next_test_port(), crate::config::Mode::Proxy),
            &eng,
            &d,
            false,
        )
        .unwrap_err();
        assert!(
            err.contains("管理员"),
            "TUN 线路即使在全局 proxy 下也必须要求管理员：{err}"
        );
        assert_eq!(spawned.get(), 0, "拦截要在起引擎之前");
        assert!(!f.journal.exists(), "不该写还原凭据");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_line_does_not_require_elevation_even_when_global_mode_says_tun() {
        // D6 方向①：全局 mode=tun，但线路是 proxy 配置 → 不该平白要求管理员。
        let f = fixture("proxy-line-tun-mode");
        let (eng, dir) = engine_cfg_with_inbounds(
            "proxy",
            r#"[{"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":18000}]"#,
        );
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &always_alive, &not_elevated);
        assert!(
            matches!(
                connect(
                    &cfg_with_mode(next_test_port(), crate::config::Mode::Tun),
                    &eng,
                    &d,
                    false
                ),
                Ok(Outcome::Done(_))
            ),
            "线路只有 mixed 入站时不该要求管理员（全局 mode 只是导入默认值）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_mode_does_not_require_elevation() {
        let f = fixture("proxy-noadmin");
        let spawn = |_: &EngineConfig| Ok(424242i64);
        let kill = |_: i64| Ok(());
        let d = deps_with(&f, &spawn, &kill, &always_alive, &not_elevated);

        assert!(
            matches!(connect(&cfg_on(next_test_port()), &engine(), &d, false), Ok(Outcome::Done(_))),
            "系统代理模式不需要管理员，非提权下必须照常成功"
        );
    }

    #[test]
    fn preflight_does_not_regenerate_live_engine_configuration() {
        let f = fixture("preflight-existing");
        let cfg = cfg();
        let runtime_engine = f.runtime.with_file_name("runtime-engine.json");
        std::fs::write(&runtime_engine, r#"{"inbounds":[{"type":"mixed","tag":"tc-mixed"}]}"#).unwrap();
        write_runtime(&f.runtime, 4242, 1_700_000_000.0, "Running", false).unwrap();
        f.store.apply(&[
            proxy::Change { key: "ProxyEnable", from: "0".into(), to: "1".into() },
            proxy::Change {
                key: "ProxyServer", from: "127.0.0.1:7897".into(),
                to: cfg.current_line().unwrap().proxy_endpoint.clone(),
            },
        ]).unwrap();

        let root = f.runtime.parent().unwrap();
        assert_eq!(
            preflight_before_prepare(&cfg, root, &f.store, &always_alive, false),
            Ok(true),
            "运行中且代理匹配时，必须绕过配置及凭据再生成",
        );
        let before = std::fs::read(&runtime_engine).unwrap();
        assert_eq!(std::fs::read(&runtime_engine).unwrap(), before);

        // 即使 PID 存活，代理被第三方改过也不能准备新运行时配置。
        f.store.apply(&[
            proxy::Change {
                key: "ProxyServer", from: cfg.current_line().unwrap().proxy_endpoint.clone(),
                to: "127.0.0.1:30000".into(),
            },
        ]).unwrap();
        assert!(preflight_before_prepare(&cfg, root, &f.store, &always_alive, false).is_err());
        assert_eq!(std::fs::read(&runtime_engine).unwrap(), before);
        assert_eq!(preflight_before_prepare(&cfg, root, &f.store, &never_alive, false), Ok(false));
    }

    #[test]
    fn second_connect_is_idempotent_when_already_connected() {
        let f = fixture("idem");
        let c = cfg(); // 两次必须同一条线路（cfg() 每次都取新端口）
        let spawn = |_: &EngineConfig| Ok(std::process::id() as i64); // 用真实存活的本进程
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);
        connect(&c, &engine(), &d, false).unwrap();
        // 第二次：代理已指向我们、运行时记录里的 pid 还活着 → 不该重复动手
        let out = connect(&c, &engine(), &d, false).unwrap();
        assert_eq!(out, Outcome::AlreadyDone);
    }

    #[test]
    fn record_separates_supervisor_pid_from_engine_pid() {
        let f = fixture("pids");
        let spawn = |_: &EngineConfig| Ok(777_777i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);
        connect(&cfg(), &engine(), &d, false).unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&f.runtime).unwrap()).unwrap();
        // 守护是发起连接的进程（就是本测试进程），引擎是 spawn 出来的那个——两个字段不能混
        assert_eq!(v["SupervisorPid"], std::process::id() as i64, "SupervisorPid 必须是守护自己");
        assert_eq!(v["EnginePid"], 777_777i64, "EnginePid 必须是引擎");
        assert_ne!(v["SupervisorPid"], v["EnginePid"], "两个字段是两种东西，不该相等");
    }

    #[test]
    fn disconnect_stops_engine_not_the_supervisor_itself() {
        let f = fixture("kill-engine");
        let spawn = |_: &EngineConfig| Ok(888_888i64);
        let killed = std::cell::Cell::new(0i64);
        let kill = |pid: i64| {
            killed.set(pid);
            Ok(())
        };
        let d = deps(&f, &spawn, &kill);
        connect(&cfg(), &engine(), &d, false).unwrap();
        disconnect(Some(&cfg()), &d).unwrap();

        assert_eq!(killed.get(), 888_888, "要停的是引擎；照 SupervisorPid 停会把自己杀掉");
        assert_ne!(killed.get(), std::process::id() as i64);
    }

    // ---------- 关窗清理 ----------
    #[test]
    fn shutdown_cleanup_disconnects_and_removes_records() {
        let f = fixture("shutdown");
        let before = f.store.read();

        // 造一份「已连接」现场：代理指向我们，还原凭据与运行时记录都在
        let j = proxy::ProxyJournal::from_snapshot(&before, "127.0.0.1:17890", 0.0);
        proxy::write_journal(&f.journal, &j).unwrap();
        f.store
            .apply(&[
                proxy::Change { key: "ProxyEnable", from: "0".into(), to: "1".into() },
                proxy::Change {
                    key: "ProxyServer",
                    from: before.server.clone().unwrap_or_default(),
                    to: "127.0.0.1:17890".into(),
                },
            ])
            .unwrap();
        write_runtime(&f.runtime, 4242, 1_700_000_000.0, "Running", false).unwrap();

        let killed = std::cell::Cell::new(0i64);
        let kill = |pid: i64| {
            killed.set(pid);
            Ok(())
        };
        let spawn = |_: &EngineConfig| Ok(0i64);
        let d = deps(&f, &spawn, &kill);

        let steps = shutdown_cleanup(Some(&cfg()), &d, &crate::events::Origin::other()).unwrap();
        assert_eq!(killed.get(), 4242, "必须停掉运行时记录里的引擎");
        assert!(steps.iter().any(|s| s.contains("停止引擎")), "步骤要能看出做了什么：{steps:?}");
        assert!(!f.runtime.exists(), "运行时记录必须删掉");
        assert!(!f.journal.exists(), "还原凭据必须删掉");

        let after = f.store.read();
        assert_eq!(after.enable, before.enable, "代理必须还原");
        assert_eq!(after.server, before.server);
    }

    #[test]
    fn shutdown_cleanup_without_records_is_a_noop() {
        let f = fixture("shutdown-empty");
        let killed = std::cell::Cell::new(false);
        let kill = |_: i64| {
            killed.set(true);
            Ok(())
        };
        let spawn = |_: &EngineConfig| Ok(0i64);
        let d = deps(&f, &spawn, &kill);

        assert!(
            shutdown_cleanup(Some(&cfg()), &d, &crate::events::Origin::other()).unwrap().is_empty(),
            "没记录就该是空操作"
        );
        assert!(!killed.get(), "没有运行时记录就不许杀任何进程");
        assert!(
            shutdown_cleanup(None, &d, &crate::events::Origin::other()).unwrap().is_empty(),
            "没配置同样是空操作"
        );
        assert!(!killed.get());
    }

    #[test]
    fn shutdown_cleanup_surfaces_kill_failure() {
        let f = fixture("shutdown-killfail");
        write_runtime(&f.runtime, 777, 1_700_000_000.0, "Running", false).unwrap();
        let kill = |_: i64| Err("模拟停止失败".to_string());
        let spawn = |_: &EngineConfig| Ok(0i64);
        let d = deps(&f, &spawn, &kill);

        let err = shutdown_cleanup(Some(&cfg()), &d, &crate::events::Origin::other()).unwrap_err();
        // 失败原因必须能一眼判定，否则关窗后用户只知道「没清理干净」
        assert!(err.contains("模拟停止失败"), "错误原因丢了：{err}");
    }
    /// 造一份运行时记录：守护指向一个不存在的 pid，引擎指向一个真实存活的 pid。
    fn write_runtime_for(f: &Fixture, engine_pid: i64) {
        let rec = serde_json::json!({
            "SchemaVersion": 1,
            "SupervisorPid": 999_999_i64,
            "EnginePid": engine_pid,
            "StartedAt": "2026-10-26T00:00:00Z",
            "State": "Running",
            "Error": null,
            "CleanupError": false,
            "TradingDirectAccessBlocked": false,
            "BootStartedAt": "2026-10-26T00:00:00Z"
        });
        std::fs::write(&f.runtime, rec.to_string()).unwrap();
    }

    #[test]
    fn disconnect_works_without_config() {
        // 配置缺失/损坏时仍必须能断开，否则用户被锁死在接管状态。
        let f = fixture("nocfg");
        let before = f.store.read();
        // 先按正常流程接管一次，留下凭据与记录
        let spawn = |_: &EngineConfig| Ok(std::process::id() as i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);
        connect(&cfg(), &engine(), &d, false).unwrap();
        write_runtime_for(&f, std::process::id() as i64);

        // 断开：不给配置
        let killed = std::cell::Cell::new(0i64);
        let kill2 = |pid: i64| { killed.set(pid); Ok(()) };
        let d2 = Deps { store: &f.store, apply: &write_proxy, spawn: &spawn, kill: &kill2,
                        alive: &always_alive, elevated: &always_elevated,
                        journal_path: &f.journal, runtime_path: &f.runtime, now: 1_700_000_000.0,
                        guard: None };
        let out = disconnect(None, &d2).unwrap();
        assert!(matches!(out, Outcome::Done(_)), "无配置也必须能断开");
        assert_eq!(killed.get(), std::process::id() as i64, "要按 EnginePid 停，不是守护 pid");
        assert!(!f.runtime.exists());
        assert!(!f.journal.exists());
        let after = f.store.read();
        assert_eq!(after.enable, before.enable);
        assert_eq!(after.server, before.server);
    }

    #[test]
    fn disconnect_without_any_record_is_noop() {
        let f = fixture("noop");
        let killed = std::cell::Cell::new(0i64);
        let spawn = |_: &EngineConfig| Ok(1i64);
        let kill = |pid: i64| { killed.set(pid); Ok(()) };
        let d = deps(&f, &spawn, &kill);
        let out = disconnect(None, &d).unwrap();
        assert_eq!(out, Outcome::AlreadyDone);
        assert_eq!(killed.get(), 0, "没有记录就不该去杀任何进程");
    }

    #[test]
    fn shutdown_cleanup_without_config_still_disconnects() {
        // 关窗时配置可能已经损坏，清理仍要走完。
        let f = fixture("close-nocfg");
        let spawn = |_: &EngineConfig| Ok(std::process::id() as i64);
        let kill = |_: i64| Ok(());
        let d = deps(&f, &spawn, &kill);
        connect(&cfg(), &engine(), &d, false).unwrap();
        write_runtime_for(&f, std::process::id() as i64);

        let steps = shutdown_cleanup(None, &d, &crate::events::Origin::other()).unwrap();
        assert!(!steps.is_empty(), "有记录时清理必须真的做事");
        assert!(!f.journal.exists());
        assert!(!f.runtime.exists());
    }
    #[test]
    fn rollback_restores_even_when_proxy_unreadable() {
        // 键根本不存在 ⇒ store.read() 不可读。旧实现会在这里拒绝还原，
        // 把用户永久留在接管状态；现在必须走盲还原把凭据里的值写回去。
        let key = format!(r"Software\SpiderVPN\tests\blind-{}", std::process::id());
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&key);
        let store = ProxyStore { key_path: key.clone() };

        let dir = std::env::temp_dir().join(format!("tcrs-blind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let journal = dir.join("proxy-journal.json");
        let runtime = dir.join("runtime.json");
        let j = proxy::ProxyJournal {
            schema: 1,
            endpoint: "127.0.0.1:17890".into(),
            saved_at_secs: 0.0,
            saved: proxy::SavedProxy {
                enable: false,
                server: Some("127.0.0.1:7897".into()),
                bypass: Some("localhost;<local>".into()),
            },
        };
        proxy::write_journal(&journal, &j).unwrap();
        std::fs::write(&runtime, r#"{"SchemaVersion":1,"SupervisorPid":999999,"EnginePid":999999,"State":"Running"}"#).unwrap();

        let spawn = |_: &EngineConfig| Ok(1i64);
        let kill = |_: i64| Ok(());
        let d = Deps {
            store: &store,
            apply: &write_proxy,
            spawn: &spawn,
            kill: &kill,
            alive: &always_alive,
            elevated: &always_elevated,
            journal_path: &journal,
            runtime_path: &runtime,
            now: 1_700_000_000.0,
            guard: None,
        };

        let out = disconnect(None, &d).expect("读不到代理也必须能还原");
        assert!(matches!(out, Outcome::Done(_)));
        let after = store.read();
        assert!(after.readable, "盲还原应当把键写出来");
        assert_eq!(after.enable, j.saved.enable);
        assert_eq!(after.server, j.saved.server);
        assert_eq!(after.bypass, j.saved.bypass);
        assert!(!journal.exists());
        assert!(!runtime.exists());

        let _ = hkcu.delete_subkey_all(&key);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
