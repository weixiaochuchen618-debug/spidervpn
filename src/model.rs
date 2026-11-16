//! 运行时记录的只读模型。
//!
//! 字段名与旧版写出的 JSON **逐字一致**（`deployment.json` / `runtime.json`），
//! 这样两边的数据可以直接互相读懂，不需要中间格式转换。
//!
//! 三条原则：
//! 1. **不认识的结构就报错，不要猜**。旧版没有 `SchemaVersion` 的文件不校验版本，
//!    但字段缺失必须显式失败——静默用默认值会让「读到了坏数据」看起来像「一切正常」。
//! 2. **不做进程探测**。这里只解析「记录说了什么」，进程是否真的活着由 `Probe` 提供。
//!    混在一起就再也测不出「记录说在跑、实际已死」这种情况了。
//! 3. **时间统一转成距 epoch 的秒数**，与 `presentation` 的入参一致。


use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeRecord {
    #[serde(rename = "SchemaVersion", default)]
    pub schema_version: i64,
    #[serde(rename = "SupervisorPid", default)]
    pub supervisor_pid: i64,
    #[serde(rename = "EnginePid", default)]
    pub engine_pid: Option<i64>,
    #[serde(rename = "StartedAt", default)]
    pub started_at: String,
    #[serde(rename = "State", default)]
    pub state: String,
    #[serde(rename = "Error", default)]
    pub error: Option<String>,
    // 唯一的读者是 `raw_json_matches_real_shape`：证明真实记录里的这个开关能被正确解析。
    // 其余旧字段（CleanupError / BootStartedAt）零读者，已删。
    #[serde(rename = "TradingDirectAccessBlocked", default)]
    #[allow(dead_code)]
    pub trading_direct_access_blocked: bool,
    // 本次连接的探测入站凭据（tc-check，每次连接重新生成）。只写 runtime.json，
    // 断开随整个文件消失；旧记录没有这两个键 → None。
    // **警告**：本结构带这两个字段后，任何把记录整体 Debug 打进日志的路径都会带出凭据——
    // 新增日志时只许打印单个业务字段，不许 `{:?}` 整条记录。
    #[serde(rename = "ProbeUser", default)]
    pub probe_user: Option<String>,
    #[serde(rename = "ProbePass", default)]
    pub probe_pass: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    /// 文件存在但读不出来。
    Io(String),
    /// JSON 结构不符合预期。
    Parse(String),
    /// 版本号不认识：宁可拒绝，也不要按旧格式猜。
    UnsupportedSchema(i64),
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, LoadError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io(e.to_string()))?;
    let v = serde_json::from_str::<T>(&text).map_err(|e| LoadError::Parse(e.to_string()))?;
    Ok(Some(v))
}

pub fn load_runtime(path: &Path) -> Result<Option<RuntimeRecord>, LoadError> {
    let rec: Option<RuntimeRecord> = load_json(path)?;
    if let Some(r) = &rec {
        // 现场实测：Run-TradeChannel.ps1 写死 SchemaVersion=2（不是 1）。
        // 只认 1 会让真机上 load_runtime 直接失败、「已连接」永远不成立。
        // 这里按「已知版本区间」判定，遇到更新的版本仍要拒绝，但不再假设只有一个版本。
        if !(1..=2).contains(&r.schema_version) {
            return Err(LoadError::UnsupportedSchema(r.schema_version));
        }
    }
    Ok(rec)
}

/// 把 ISO-8601 时间转成距 epoch 的秒数。
///
/// 只接受带偏移量的形式（旧版写的就是 `+00:00`）；解析失败返回 `None`，
/// **不**回退成「现在」——那会让超时判断永远不触发。
pub fn iso_to_epoch_secs(s: &str) -> Option<f64> {
    if s.trim().is_empty() {
        return None;
    }
    let fmt = time::format_description::well_known::Rfc3339;
    let odt = time::OffsetDateTime::parse(s, &fmt).ok()?;
    Some(odt.unix_timestamp_nanos() as f64 / 1_000_000_000.0)
}

/// 进程/会话探测。抽成 trait 是为了让「记录说在跑、实际已死」可测。
pub trait Probe {
    fn process_alive(&self, pid: i64) -> bool;
    fn session_present(&self) -> bool;
    fn control_available(&self) -> bool;
}

/// 由记录 + 探测结果组装证据，喂给 `presentation::present`。
pub fn evidence_from(
    rt: Option<&RuntimeRecord>,
    configured: bool,
    probe: &dyn Probe,
    now: f64,
) -> crate::presentation::Evidence {
    use crate::presentation::{Evidence, Identity, Snapshot};

    let mut e = Evidence {
        // 「已配置」由调用方按本程序自己的 config.json 判定——不再从旧版部署记录里推。
        deployment_present: configured,
        observed_at: Some(now),
        control_available: probe.control_available(),
        ..Default::default()
    };

    if let Some(r) = rt {
        let supervisor_alive = r.supervisor_pid > 0 && probe.process_alive(r.supervisor_pid);
        let engine_alive = r.engine_pid.map(|p| p > 0 && probe.process_alive(p)).unwrap_or(false);
        e.identity = Identity {
            current: true,
            // pid 字段存在不代表进程活着：必须问探测层。
            supervisor_alive,
            engine_alive,
            // 引擎还活着但守护不在（一次性 CLI 连接后 CLI 已退出、或界面被强杀）：
            // 这时的会话并不完整。不能报「未连接」——那会让人以为网络已经干净，
            // 实际代理还指着那个没人管的引擎；按会话不完整处理，才会引导用户去断开。
            session_present: probe.session_present() || (engine_alive && !supervisor_alive),
        };
        e.snapshot = Snapshot {
            state: r.state.clone(),
            started_at: iso_to_epoch_secs(&r.started_at),
            record_written_at: iso_to_epoch_secs(&r.started_at),
        };
        // 记录里带 Error 且状态是异常态时，才算故障。
        if r.state == "StoppedWithError" {
            e.fault = None; // 交给 present 的 StoppedWithError 分支，保持文案一致
        }
        if let Some(err) = &r.error {
            if !err.is_empty() && r.state != "Running" && r.state != "Stopped" {
                e.fault = Some(err.clone());
            }
        }
    }

    e
}

/// 当前时间（距 epoch 的秒数，带小数）。全仓只此一份：`connect::Deps::now`、自检记录、
/// 状态投影都用它，避免三处各写一遍、口径慢慢漂。
pub fn now_epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 只到秒的时间戳（自检记录那种只要整数的地方用）。
pub fn now_epoch_secs_u64() -> u64 {
    now_epoch_secs() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProbe {
        alive: Vec<i64>,
        session: bool,
        control: bool,
    }
    impl Probe for FakeProbe {
        fn process_alive(&self, pid: i64) -> bool {
            self.alive.contains(&pid)
        }
        fn session_present(&self) -> bool {
            self.session
        }
        fn control_available(&self) -> bool {
            self.control
        }
    }

    fn rt(state: &str) -> RuntimeRecord {
        RuntimeRecord {
            schema_version: 1,
            supervisor_pid: 100,
            engine_pid: Some(200),
            started_at: "2026-10-26T11:40:10.2793604+00:00".into(),
            state: state.into(),
            ..Default::default()
        }
    }

    #[test]
    fn parses_fractional_seconds_with_offset() {
        let s = iso_to_epoch_secs("2026-10-26T11:40:10.2793604+00:00");
        assert!(s.is_some(), "7 位小数+偏移量必须能解析");
    }

    #[test]
    fn empty_or_bad_time_is_none_not_now() {
        assert_eq!(iso_to_epoch_secs(""), None);
        assert_eq!(iso_to_epoch_secs("not-a-time"), None);
        assert_eq!(iso_to_epoch_secs("2026-10-26 11:40:10"), None, "缺时区不能猜");
    }

    #[test]
    fn missing_files_are_none_not_error() {
        let p = std::env::temp_dir().join("tcrs-definitely-missing.json");
        // 不用 assert_eq!：那要求记录类型实现 PartialEq，而这些类型本就不该逐步比较。
        assert!(load_runtime(&p).unwrap().is_none());
    }

    #[test]
    fn schema_two_is_accepted_because_that_is_what_the_engine_writes() {
        // 旧版现场写的是 2；只认 1 会让真机永远读不到运行时状态。
        let p = std::env::temp_dir().join(format!("tcrs-schema2-{}.json", std::process::id()));
        std::fs::write(&p, r#"{"SchemaVersion":2,"SupervisorPid":1,"State":"Running"}"#).unwrap();
        let r = load_runtime(&p).expect("2 必须被接受");
        assert_eq!(r.unwrap().schema_version, 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unknown_future_schema_is_rejected() {
        let p = std::env::temp_dir().join(format!("tcrs-schema-{}.json", std::process::id()));
        std::fs::write(&p, r#"{"SchemaVersion":99,"State":"Running"}"#).unwrap();
        let r = load_runtime(&p);
        assert!(matches!(r, Err(LoadError::UnsupportedSchema(99))));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn record_says_running_but_process_dead_is_not_connected() {
        let rec = rt("Running");
        let probe = FakeProbe { alive: vec![], session: false, control: true };
        let e = evidence_from(Some(&rec), true, &probe, 1_000.0);
        assert!(!e.identity.supervisor_alive, "pid 在记录里不等于进程活着");
        let p = crate::presentation::present(&e);
        assert_ne!(p.key, crate::presentation::StateKey::Connected);
    }

    #[test]
    fn running_with_live_processes_and_control_is_connected() {
        let rec = rt("Running");
        let probe = FakeProbe { alive: vec![100, 200], session: false, control: true };
        let e = evidence_from(Some(&rec), true, &probe, 1_000.0);
        assert!(!e.identity.session_present, "守护与引擎都在时不该判成会话不完整");
        let p = crate::presentation::present(&e);
        assert_eq!(p.key, crate::presentation::StateKey::Connected);
    }

    #[test]
    fn record_error_becomes_fault_through_the_real_producer() {
        // Fault 的主来源：运行时记录里的 Error（不是投影层手工喂的）。
        // 「引擎在跑但身份/状态不对」这条报错能力必须留着——它就是靠这条链路。
        let mut rec = rt("Starting");
        rec.error = Some("引擎异常退出".into());
        let probe = FakeProbe { alive: vec![100, 200], session: false, control: true };
        let e = evidence_from(Some(&rec), true, &probe, 1_000.0);
        assert_eq!(e.fault.as_deref(), Some("引擎异常退出"), "记录里的错误必须传进投影");
        let p = crate::presentation::present(&e);
        assert_eq!(p.key, crate::presentation::StateKey::Fault);
        assert!(p.error.unwrap().contains("引擎异常退出"));
    }

    #[test]
    fn engine_alive_without_supervisor_is_fault_not_disconnected() {
        // 现场：一次性 CLI 连接后 CLI 已退出，或界面被强杀——引擎还在跑，没人管它。
        let rec = rt("Running"); // supervisor 100 / engine 200
        let probe = FakeProbe { alive: vec![200], session: false, control: true };
        let e = evidence_from(Some(&rec), true, &probe, 1_000.0);
        assert!(e.identity.engine_alive);
        assert!(!e.identity.supervisor_alive);
        assert!(e.identity.session_present, "引擎在、守护不在，会话不算完整");

        let p = crate::presentation::present(&e);
        // 不能说「未连接」（网络其实还挂在代理上），也不能说「已连接」（没人服务控制面）
        assert_eq!(p.key, crate::presentation::StateKey::Fault);
        assert_eq!(p.action, crate::presentation::Action::Disconnect);
    }

    #[test]
    fn raw_json_matches_real_shape() {
        // 字段名取自 旧版真实写出的文件，改名会在这里立刻失败。
        let json = r#"{"SchemaVersion":2,"SupervisorPid":100,"EnginePid":200,
            "StartedAt":"2026-10-26T11:40:10.2793604+00:00","State":"Running",
            "Error":null,"CleanupError":false,"TradingDirectAccessBlocked":true,
            "BootStartedAt":"2026-10-26T11:40:05+00:00"}"#;
        let r: RuntimeRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.schema_version, 2, "用现场真实版本号，别再用假数据");
        assert_eq!(r.supervisor_pid, 100);
        assert_eq!(r.state, "Running");
        assert!(r.trading_direct_access_blocked);
    }
}
