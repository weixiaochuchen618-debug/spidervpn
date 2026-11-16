//! 系统代理的**只读**快照 + 变更计划。
//!
//! 这一层刻意只做读与算，不写。代理接管是唯一会直接影响用户网络的动作，
//! 必须先能被人看见「要改哪几个值、从什么改成什么」，再谈落笔。
//!
//! 两条硬规则：
//! 1. **旧版在跑就不接管**。两个程序抢同一个系统代理，用户会看到网络时通时断，
//!    而两边都认为自己是「正确」的。
//! 2. **必须记下原值**。没有原值就无法还原，「断开后网络恢复原样」就成了空话。

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

const IE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProxySnapshot {
    pub enable: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
    /// 读取是否成功。读不到不等于「没有代理」，两者必须分开表述。
    pub readable: bool,
}

impl ProxySnapshot {
    /// 读当前用户的系统代理设置（WinINET 层）。
    pub fn read() -> ProxySnapshot {
        ProxyStore::system().read()
    }
}

/// 注册表访问器。**抽成带路径的结构，是为了能在临时键上测写入与还原**——
/// 否则「还原逻辑是否正确」只能靠改真机代理来验证，那是拿用户的网络做测试。
#[derive(Debug, Clone)]
pub struct ProxyStore {
    pub key_path: String,
}

impl ProxyStore {
    pub fn system() -> ProxyStore {
        // 测试钩子：用环境变量把「系统代理」指到临时键，就能跑完整的落笔/还原流程
        // 而不碰真实网络设置。生产环境不设这个变量，行为与直接写 IE_KEY 完全一致。
        if let Ok(p) = std::env::var("SPIDERVPN_PROXY_KEY") {
            if !p.trim().is_empty() {
                return ProxyStore { key_path: p };
            }
        }
        ProxyStore { key_path: IE_KEY.to_string() }
    }

    pub fn read(&self) -> ProxySnapshot {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = match hkcu.open_subkey_with_flags(&self.key_path, KEY_READ) {
            Ok(k) => k,
            Err(_) => return ProxySnapshot { readable: false, ..Default::default() },
        };
        let enable = key.get_value::<u32, _>("ProxyEnable").map(|v| v != 0).unwrap_or(false);
        let server = key.get_value::<String, _>("ProxyServer").ok();
        let bypass = key.get_value::<String, _>("ProxyOverride").ok();
        ProxySnapshot { enable, server, bypass, readable: true }
    }

    /// 按计划写入。任一写入失败立即返回错误，**不吞掉**。
    pub fn apply(&self, changes: &[Change]) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(&self.key_path)
            .map_err(|e| format!("打开注册表键失败：{e}"))?;
        for c in changes {
            match c.key {
                "ProxyEnable" => {
                    let v: u32 = c.to.parse().map_err(|_| format!("ProxyEnable 不是数字：{}", c.to))?;
                    key.set_value("ProxyEnable", &v).map_err(|e| format!("写 ProxyEnable 失败：{e}"))?;
                }
                "ProxyServer" => key
                    .set_value("ProxyServer", &c.to)
                    .map_err(|e| format!("写 ProxyServer 失败：{e}"))?,
                "ProxyOverride" => key
                    .set_value("ProxyOverride", &c.to)
                    .map_err(|e| format!("写 ProxyOverride 失败：{e}"))?,
                other => return Err(format!("未知的键，拒绝写入：{other}")),
            }
        }
        Ok(())
    }
}

/// 按当前接管规则复原「本程序实际写过的值」。
///
/// 不修改 journal 的 schema：老凭据仍可读。通过同一个 plan_connect 纯函数推导
/// 应用之后的状态，避免在计划与还原中各维护一套 ProxyOverride 拼接算法。
fn expected_proxy_after_takeover(journal: &ProxyJournal, endpoint: &str) -> ProxySnapshot {
    let mut expected = ProxySnapshot {
        enable: journal.saved.enable,
        server: journal.saved.server.clone(),
        bypass: journal.saved.bypass.clone(),
        readable: true,
    };
    let plan = plan_connect(&expected, endpoint, false);
    for change in plan.changes {
        match change.key {
            "ProxyEnable" => expected.enable = change.to == "1",
            "ProxyServer" => expected.server = Some(change.to),
            "ProxyOverride" => expected.bypass = Some(change.to),
            _ => {}
        }
    }
    expected
}

/// 还原计划：只有当前代理服务器还是我们的端点才尝试还原。
///
/// 对启用状态和绕过列表逐字段比较「本程序实际写入值」；已被其他程序/用户
/// 修改的字段绝不回写。连接失败的半写入回滚仍由 rollback_blind 处理。
pub fn plan_restore(
    journal: &ProxyJournal,
    current: &ProxySnapshot,
    our_endpoint: &str,
) -> RestorePlan {
    let mut warnings = Vec::new();
    if !current.readable {
        return RestorePlan {
            changes: Vec::new(),
            warnings,
            blocked: Some("无法读取当前系统代理设置，拒绝还原（避免写入不可预期的值）".into()),
        };
    }

    if current.server.as_deref() != Some(our_endpoint) {
        warnings.push(format!(
            "当前代理已不是本程序设置的端点（现在是 {}），不做还原以免覆盖别人的设置",
            current.server.as_deref().unwrap_or("(空)")
        ));
        return RestorePlan { changes: Vec::new(), warnings, blocked: None };
    }

    let expected = expected_proxy_after_takeover(journal, our_endpoint);
    let mut changes = Vec::new();
    if current.enable != journal.saved.enable {
        if current.enable == expected.enable {
            changes.push(Change {
                key: "ProxyEnable",
                from: if current.enable { "1".into() } else { "0".into() },
                to: if journal.saved.enable { "1".into() } else { "0".into() },
            });
        } else {
            warnings.push("ProxyEnable 已由其他程序修改，保留当前值".into());
        }
    }

    let saved_server = journal.saved.server.clone().unwrap_or_default();
    if current.server.clone().unwrap_or_default() != saved_server {
        changes.push(Change {
            key: "ProxyServer",
            from: current.server.clone().unwrap_or_default(),
            to: saved_server,
        });
    }

    if current.bypass != journal.saved.bypass {
        if current.bypass == expected.bypass {
            changes.push(Change {
                key: "ProxyOverride",
                from: current.bypass.clone().unwrap_or_default(),
                to: journal.saved.bypass.clone().unwrap_or_default(),
            });
        } else {
            warnings.push("ProxyOverride 已由其他程序修改，保留当前值".into());
        }
    }

    RestorePlan { changes, warnings, blocked: None }
}

/// 读不到当前代理时的兜底计划：直接按凭据把接管前的值写回去。
///
/// 常规还原要读当前值，是为了避免覆盖「用户后来自己改的设置」。但读不到时若拒绝还原，
/// 用户就被永久留在代理接管状态——那比覆盖一个我们本来就要还原的旧值更糟。
pub fn plan_restore_blind(journal: &ProxyJournal) -> Vec<Change> {
    let mut changes = vec![
        Change {
            key: "ProxyEnable",
            from: String::new(),
            to: if journal.saved.enable { "1".to_string() } else { "0".to_string() },
        },
        Change {
            key: "ProxyServer",
            from: String::new(),
            to: journal.saved.server.clone().unwrap_or_default(),
        },
    ];
    if let Some(b) = &journal.saved.bypass {
        changes.push(Change { key: "ProxyOverride", from: String::new(), to: b.clone() });
    }
    changes
}

#[derive(Debug, Clone, PartialEq)]
pub struct RestorePlan {
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    pub blocked: Option<String>,
}

/// 接管时落盘的还原凭据。存在自己的数据根里，崩溃后也能还原。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProxyJournal {
    pub schema: u32,
    pub endpoint: String,
    pub saved_at_secs: f64,
    pub saved: SavedProxy,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SavedProxy {
    pub enable: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
}

impl ProxyJournal {
    pub fn from_snapshot(snapshot: &ProxySnapshot, endpoint: &str, now_secs: f64) -> ProxyJournal {
        ProxyJournal {
            schema: 1,
            endpoint: endpoint.to_string(),
            saved_at_secs: now_secs,
            saved: SavedProxy {
                enable: snapshot.enable,
                server: snapshot.server.clone(),
                bypass: snapshot.bypass.clone(),
            },
        }
    }
}

/// 测试专用注入点：模拟「临时文件写完、替换前断掉」。
///
/// 只在 `cfg(test)` 下编译，发布产物里没有这段——它不是产品行为的一部分。
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FAIL_BEFORE_REPLACE: Cell<bool> = const { Cell::new(false) };
    }
    pub fn arm(v: bool) {
        FAIL_BEFORE_REPLACE.with(|f| f.set(v));
    }
    pub fn armed() -> bool {
        FAIL_BEFORE_REPLACE.with(|f| f.get())
    }
}

pub fn write_journal(path: &std::path::Path, j: &ProxyJournal) -> Result<(), String> {
    let text = serde_json::to_string_pretty(j).map_err(|e| e.to_string())?;
    // 原子写：凭据写半截 → 解析失败 → `connect` 拒绝、`--restore-apply` 也失败 →
    // 用户被永久锁在「代理指向我们」的状态里。所以先写临时文件再替换。
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("写还原凭据失败：{e}")
    })?;
    #[cfg(test)]
    if fault::armed() {
        // 模拟「写到一半断掉」：临时文件里只有半截内容，目标文件必须原样不动。
        let _ = std::fs::write(&tmp, "{\"schema\":1,\"saved\":");
        let _ = std::fs::remove_file(&tmp);
        return Err("写还原凭据失败：注入的测试故障".to_string());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // 替换失败时把临时文件清掉：留着一个半截的 `.tmp` 只会在下次排查时误导人。
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("替换还原凭据失败：{e}"));
    }
    Ok(())
}

pub fn read_journal(path: &std::path::Path) -> Result<Option<ProxyJournal>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    // 同 config：外部工具可能写进 UTF-8 BOM，serde_json 不认，会让凭据凭空「无法解析」，
    // 而凭据读不出来就没法还原代理——这是必须容忍的一类脏数据。
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let j: ProxyJournal = serde_json::from_str(text).map_err(|e| format!("还原凭据无法解析：{e}"))?;
    if j.schema != 1 {
        return Err(format!("还原凭据版本不支持：{}", j.schema));
    }
    Ok(Some(j))
}

/// 维护卡与概览横幅共用的只读投影。
///
/// `can_restore` 表示可以把这份凭据交给现有还原后端处理，包括外部端点的零写回清理和
/// 当前键不可读时的盲还原；无凭据时为 false，但界面仍允许执行幂等 no-op。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceStatus {
    pub journal_present: bool,
    pub proxy_owned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub can_restore: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 从已经取得的凭据与代理快照计算维护状态。抽成纯函数，五态测试不必改真实注册表。
pub fn maintenance_status_from(
    journal: Result<Option<ProxyJournal>, String>,
    current: &ProxySnapshot,
) -> MaintenanceStatus {
    match journal {
        Ok(None) => MaintenanceStatus {
            journal_present: false,
            proxy_owned: false,
            endpoint: None,
            can_restore: false,
            detail: None,
        },
        Err(e) => MaintenanceStatus {
            journal_present: true,
            proxy_owned: false,
            endpoint: None,
            can_restore: false,
            detail: Some(e),
        },
        Ok(Some(j)) => {
            let owned = current.readable
                && !j.endpoint.is_empty()
                && current.server.as_deref() == Some(j.endpoint.as_str());
            let detail = if !current.readable {
                Some("当前系统代理不可读；执行还原时将按凭据写回接管前的值。".to_string())
            } else if !owned {
                Some("当前代理未指向本程序；不会覆盖当前设置，可清理残留凭据。".to_string())
            } else {
                let plan = plan_restore(&j, current, &j.endpoint);
                if plan.changes.is_empty() {
                    Some("当前代理已与接管前一致；可清理残留凭据。".to_string())
                } else {
                    None
                }
            };
            MaintenanceStatus {
                journal_present: true,
                proxy_owned: owned,
                endpoint: if j.endpoint.is_empty() { None } else { Some(j.endpoint) },
                can_restore: true,
                detail,
            }
        }
    }
}

/// 读取当前维护状态；只读凭据与调用方指定的代理键。
pub fn maintenance_status(store: &ProxyStore, journal_path: &std::path::Path) -> MaintenanceStatus {
    let journal = read_journal(journal_path);
    let current = store.read();
    maintenance_status_from(journal, &current)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub key: &'static str,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectPlan {
    /// 将要写入的变更（顺序即写入顺序）。
    pub changes: Vec<Change>,
    /// 需要用户知晓、但不阻止继续的事项。
    pub warnings: Vec<String>,
    /// 阻止继续的原因。非空时 `changes` 必须为空——不允许「带病计划」。
    pub blocked: Option<String>,
    /// 原始快照，断开时按它还原。
    pub original: ProxySnapshot,
}

/// 期望的代理端点，例如 `127.0.0.1:7890`。
pub fn plan_connect(
    current: &ProxySnapshot,
    desired_endpoint: &str,
    legacy_running: bool,
) -> ConnectPlan {
    let mut warnings = Vec::new();

    if !current.readable {
        // 读不到就不猜：宁可拒绝，也不要在不知道原值的情况下覆盖别人的设置。
        return ConnectPlan {
            changes: Vec::new(),
            warnings,
            blocked: Some("无法读取当前系统代理设置，拒绝接管（避免覆盖无法还原的配置）".into()),
            original: current.clone(),
        };
    }

    if legacy_running {
        return ConnectPlan {
            changes: Vec::new(),
            warnings,
            blocked: Some(
                "检测到旧版客户端正在运行：两个程序不能同时接管系统代理，请先关闭它".into(),
            ),
            original: current.clone(),
        };
    }

    if current.enable {
        match &current.server {
            Some(s) if s == desired_endpoint => {
                warnings.push("系统代理已指向本程序的端点，无需改动".into());
                return ConnectPlan { changes: Vec::new(), warnings, blocked: None, original: current.clone() };
            }
            Some(s) => warnings.push(format!(
                "当前系统代理指向 {s}，接管后会被改为 {desired_endpoint}；断开时会还原"
            )),
            None => warnings.push(
                "系统代理已启用但未记录服务器地址，接管后会改为本程序端点".into(),
            ),
        }
    }

    let mut changes = Vec::new();
    if !current.enable {
        changes.push(Change { key: "ProxyEnable", from: "0".into(), to: "1".into() });
    }
    let from_server = current.server.clone().unwrap_or_default();
    if from_server != desired_endpoint {
        changes.push(Change {
            key: "ProxyServer",
            from: from_server,
            to: desired_endpoint.to_string(),
        });
    }
    // 绕过列表只能**追加**，不能覆盖。
    // 实测教训：用户的 ProxyOverride 可能是一长串（localhost;127.*;192.168.*;10.*;172.16-31.*;<local>），
    // 直接写成 `<local>` 会让内网与局域网段全部走代理——这是接管代理最容易造成的「静默破坏」。
    let from_bypass = current.bypass.clone().unwrap_or_default();
    if !bypass_has_local(&from_bypass) {
        let merged = if from_bypass.trim().is_empty() {
            "<local>".to_string()
        } else {
            format!("{};<local>", from_bypass.trim_end_matches(';'))
        };
        changes.push(Change { key: "ProxyOverride", from: from_bypass, to: merged });
    }

    ConnectPlan { changes, warnings, blocked: None, original: current.clone() }
}

/// 绕过列表里是否已经包含 `<local>`（大小写不敏感，分号分隔）。
fn bypass_has_local(list: &str) -> bool {
    list.split(';').any(|p| p.trim().eq_ignore_ascii_case("<local>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(enable: bool, server: Option<&str>) -> ProxySnapshot {
        ProxySnapshot {
            enable,
            server: server.map(|s| s.to_string()),
            bypass: None,
            readable: true,
        }
    }

    #[test]
    fn disabled_proxy_yields_three_changes() {
        let p = plan_connect(&snap(false, None), "127.0.0.1:7890", false);
        assert!(p.blocked.is_none());
        assert_eq!(p.changes.len(), 3, "启用 + 服务器 + 绕过 三处");
        assert_eq!(p.changes[0].key, "ProxyEnable");
        assert_eq!(p.changes[0].to, "1");
        assert_eq!(p.original.enable, false, "必须留下原值以便还原");
    }

    #[test]
    fn already_pointing_at_us_is_noop() {
        let p = plan_connect(&snap(true, Some("127.0.0.1:7890")), "127.0.0.1:7890", false);
        assert!(p.blocked.is_none());
        assert!(p.changes.is_empty(), "已经指向我们就不该再写");
    }

    #[test]
    fn overwriting_someone_elses_proxy_warns_but_records_original() {
        let p = plan_connect(&snap(true, Some("10.0.0.1:8080")), "127.0.0.1:7890", false);
        assert!(p.blocked.is_none());
        assert!(p.warnings.iter().any(|w| w.contains("10.0.0.1:8080")));
        // 原值必须原样保留，否则断开还原就成了空话
        assert_eq!(p.original.server.as_deref(), Some("10.0.0.1:8080"));
        assert_eq!(p.changes[0].from, "10.0.0.1:8080");
    }

    #[test]
    fn legacy_running_blocks_everything() {
        let p = plan_connect(&snap(false, None), "127.0.0.1:7890", true);
        assert!(p.blocked.is_some());
        assert!(p.changes.is_empty(), "被阻止时不允许有任何变更项");
    }

    #[test]
    fn unreadable_state_blocks_instead_of_guessing() {
        let s = ProxySnapshot { readable: false, ..Default::default() };
        let p = plan_connect(&s, "127.0.0.1:7890", false);
        assert!(p.blocked.is_some());
        assert!(p.changes.is_empty());
    }

    #[test]
    fn bypass_is_appended_not_replaced() {
        // 这条是实测缺陷的回归：真实机器的 ProxyOverride 是一长串，
        // 旧实现会把它覆盖成只剩 <local>，导致内网直连规则全部失效。
        let mut s = snap(false, None);
        s.bypass = Some("localhost;127.*;192.168.*;10.*".into());
        let p = plan_connect(&s, "127.0.0.1:7890", false);
        let b = p.changes.iter().find(|c| c.key == "ProxyOverride").unwrap();
        assert_eq!(b.to, "localhost;127.*;192.168.*;10.*;<local>", "必须保留原有条目");
        assert!(b.to.contains("192.168.*"), "内网段不能被丢掉");
    }

    #[test]
    fn bypass_already_containing_local_is_untouched() {
        let mut s = snap(true, Some("127.0.0.1:7890"));
        s.bypass = Some("localhost;<LOCAL>".into());
        let p = plan_connect(&s, "127.0.0.1:7890", false);
        assert!(p.changes.is_empty(), "已有 <local> 就不该再改绕过列表");
    }

    #[test]
    fn reading_real_registry_does_not_panic() {
        // 只要求「能读或明确标记不可读」，不允许 panic，也不允许把不可读当成 false。
        let s = ProxySnapshot::read();
        if s.readable {
            let _ = s.enable;
        } else {
            assert!(s.server.is_none());
        }
    }

    // ---------- 还原 ----------

    fn journal(enable: bool, server: &str, bypass: Option<&str>) -> ProxyJournal {
        ProxyJournal {
            schema: 1,
            endpoint: "127.0.0.1:7890".into(),
            saved_at_secs: 0.0,
            saved: SavedProxy {
                enable,
                server: Some(server.to_string()),
                bypass: bypass.map(|s| s.to_string()),
            },
        }
    }

    #[test]
    fn restore_puts_back_original_values() {
        let j = journal(false, "127.0.0.1:7897", Some("<local>"));
        let current = snap(true, Some("127.0.0.1:7890")); // 我们设的
        let p = plan_restore(&j, &current, "127.0.0.1:7890");
        assert!(p.blocked.is_none());
        let enable = p.changes.iter().find(|c| c.key == "ProxyEnable").unwrap();
        assert_eq!(enable.to, "0");
        let server = p.changes.iter().find(|c| c.key == "ProxyServer").unwrap();
        assert_eq!(server.to, "127.0.0.1:7897");
    }

    #[test]
    fn restore_preserves_user_modified_enable_when_endpoint_is_ours() {
        let j = journal(true, "127.0.0.1:7897", Some("localhost"));
        // SpiderVPN 只改服务器和绕过列表，用户随后手动关掉了代理。
        let current = ProxySnapshot {
            enable: false, server: Some("127.0.0.1:7890".into()),
            bypass: Some("localhost;<local>".into()), readable: true,
        };
        let plan = plan_restore(&j, &current, "127.0.0.1:7890");
        assert!(!plan.changes.iter().any(|c| c.key == "ProxyEnable"));
        assert!(plan.changes.iter().any(|c| c.key == "ProxyServer"));
        assert!(plan.changes.iter().any(|c| c.key == "ProxyOverride"));
    }

    #[test]
    fn restore_preserves_user_modified_bypass_when_endpoint_is_ours() {
        let j = journal(false, "127.0.0.1:7897", Some("localhost"));
        let current = ProxySnapshot {
            enable: true, server: Some("127.0.0.1:7890".into()),
            bypass: Some("localhost;192.168.*;<local>".into()), readable: true,
        };
        let plan = plan_restore(&j, &current, "127.0.0.1:7890");
        assert!(!plan.changes.iter().any(|c| c.key == "ProxyOverride"));
        assert!(plan.changes.iter().any(|c| c.key == "ProxyEnable"));
        assert!(plan.changes.iter().any(|c| c.key == "ProxyServer"));
        assert!(plan.warnings.iter().any(|w| w.contains("ProxyOverride")));
    }

    #[test]
    fn restore_refuses_when_someone_else_changed_it() {
        let j = journal(false, "127.0.0.1:7897", None);
        let current = snap(true, Some("10.1.2.3:8080")); // 用户后来自己改的
        let p = plan_restore(&j, &current, "127.0.0.1:7890");
        assert!(p.changes.is_empty(), "别人改过就不能覆盖");
        assert!(p.warnings.iter().any(|w| w.contains("不做还原")));
    }

    #[test]
    fn maintenance_projection_distinguishes_all_recovery_states() {
        let current = snap(true, Some("127.0.0.1:7890"));
        let missing = maintenance_status_from(Ok(None), &current);
        assert!(!missing.journal_present && !missing.proxy_owned && !missing.can_restore);
        assert!(missing.detail.is_none());

        let broken = maintenance_status_from(Err("还原凭据无法解析：bad".into()), &current);
        assert!(broken.journal_present && !broken.can_restore);
        assert!(broken.detail.as_deref().unwrap_or("").contains("无法解析"));

        let j = journal(false, "127.0.0.1:7897", Some("<local>"));
        let owned = maintenance_status_from(Ok(Some(j.clone())), &current);
        assert!(owned.journal_present && owned.proxy_owned && owned.can_restore);
        assert_eq!(owned.endpoint.as_deref(), Some("127.0.0.1:7890"));
        assert!(owned.detail.is_none(), "正常待还原不需要附加警告：{owned:?}");
        let json = serde_json::to_value(&owned).unwrap();
        assert_eq!(json["journalPresent"], true);
        assert_eq!(json["canRestore"], true);

        let external = maintenance_status_from(
            Ok(Some(j.clone())),
            &snap(true, Some("10.1.2.3:8080")),
        );
        assert!(!external.proxy_owned && external.can_restore);
        assert!(external.detail.as_deref().unwrap_or("").contains("不会覆盖"));

        let unreadable = maintenance_status_from(
            Ok(Some(j)),
            &ProxySnapshot { readable: false, ..Default::default() },
        );
        assert!(!unreadable.proxy_owned && unreadable.can_restore);
        assert!(unreadable.detail.as_deref().unwrap_or("").contains("不可读"));
    }

    #[test]
    fn plan_restore_refuses_when_unreadable_and_caller_falls_back_to_blind() {
        // 库层的保护：读不到当前值就不给「按现状还原」的计划，避免覆盖看不见的设置。
        // 但用户不能被永久留在接管状态——调用方（connect::rollback_proxy）必须改走
        // plan_restore_blind。这个分工在 connect 侧有专门的测试钉住。
        let j = journal(false, "127.0.0.1:7897", None);
        let current = ProxySnapshot { readable: false, ..Default::default() };
        let p = plan_restore(&j, &current, "127.0.0.1:7890");
        assert!(p.blocked.is_some());
        assert!(p.changes.is_empty());

        // 盲还原必须能给出可执行的写回计划，否则调用方也没有退路
        let blind = plan_restore_blind(&j);
        assert!(!blind.is_empty(), "读不到时必须有兜底计划");
    }

    #[test]
    fn blind_restore_uses_saved_values() {
        let j = journal(false, "127.0.0.1:7897", Some("localhost;<local>"));
        let c = plan_restore_blind(&j);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].key, "ProxyEnable");
        assert_eq!(c[0].to, "0");
        assert_eq!(c[1].to, "127.0.0.1:7897");
        assert_eq!(c[2].to, "localhost;<local>");
    }

    #[test]
    fn blind_restore_omits_bypass_when_never_saved() {
        let j = journal(true, "10.0.0.1:8080", None);
        let c = plan_restore_blind(&j);
        assert_eq!(c.len(), 2, "原来没有绕过列表就不该凭空白写一条");
    }

    fn snapshot_for_test() -> ProxySnapshot {
        ProxySnapshot {
            enable: false,
            server: Some("127.0.0.1:7897".to_string()),
            bypass: Some("localhost".to_string()),
            readable: true,
        }
    }

    #[test]
    fn journal_write_is_atomic_and_leaves_no_temp_file() {
        // 凭据写半截 → 解析失败 → connect 拒绝、--restore-apply 也救不了 → 用户锁在接管状态。
        let dir = std::env::temp_dir().join(format!("tcrs-journal-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("proxy-journal.json");
        let j = ProxyJournal::from_snapshot(&snapshot_for_test(), "127.0.0.1:17890", 1.0);

        write_journal(&p, &j).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(serde_json::from_str::<ProxyJournal>(&text).is_ok(), "落盘内容必须完整可解析");
        assert!(!dir.join("proxy-journal.json.tmp").exists(), "不许留下临时文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_journal_write_keeps_the_previous_file_intact() {
        // 目标文件只读 → 替换失败。此时**旧凭据必须原样还在**：那是唯一能救用户的东西。
        let dir = std::env::temp_dir().join(format!("tcrs-journal-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("proxy-journal.json");
        let old = ProxyJournal::from_snapshot(&snapshot_for_test(), "127.0.0.1:17890", 1.0);
        write_journal(&p, &old).unwrap();
        let before = std::fs::read_to_string(&p).unwrap();

        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&p, perms).unwrap();
        let newer = ProxyJournal::from_snapshot(&snapshot_for_test(), "127.0.0.1:9999", 2.0);
        let err = write_journal(&p, &newer).unwrap_err();
        assert!(err.contains("还原凭据"), "错误要说清是凭据写不了：{err}");
        // 半截/半新都不允许：旧内容必须一字不动
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before, "旧凭据必须原样保留");
        assert!(!dir.join("proxy-journal.json.tmp").exists(), "失败也不许留临时文件");

        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&p, perms).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interrupted_write_never_leaves_a_half_written_credential() {
        // 关键场景：写到一半断掉（断电/被杀）。目标文件必须**要么完好、要么不存在**，
        // 绝不能出现半截 JSON —— 那会让 connect 拒绝、--restore-apply 也救不回来。
        let dir = std::env::temp_dir().join(format!("tcrs-journal-half-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("proxy-journal.json");
        let good = ProxyJournal::from_snapshot(&snapshot_for_test(), "127.0.0.1:17890", 1.0);
        write_journal(&p, &good).unwrap();
        let before = std::fs::read_to_string(&p).unwrap();

        fault::arm(true);
        let err = write_journal(&p, &good).unwrap_err();
        fault::arm(false);
        assert!(err.contains("还原凭据"), "{err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before, "半截内容绝不能落到凭据上");
        assert!(serde_json::from_str::<ProxyJournal>(&before).is_ok(), "旧凭据仍可解析");
        assert!(!dir.join("proxy-journal.json.tmp").exists(), "不许留下临时文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_roundtrip_and_schema_guard() {
        let path = std::env::temp_dir().join(format!("tcrs-journal-{}.json", std::process::id()));
        let j = journal(false, "127.0.0.1:7897", Some("localhost;<local>"));
        write_journal(&path, &j).unwrap();
        let back = read_journal(&path).unwrap().unwrap();
        assert_eq!(back, j);

        let mut bad = j.clone();
        bad.schema = 2;
        write_journal(&path, &bad).unwrap();
        assert!(read_journal(&path).is_err(), "版本不支持必须报错");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn journal_with_utf8_bom_is_still_readable() {
        // 凭据读不出来就没法还原代理，所以这类脏数据必须容忍。
        let path = std::env::temp_dir().join(format!("tcrs-journal-bom-{}.json", std::process::id()));
        let j = journal(false, "127.0.0.1:7897", Some("<local>"));
        let text = serde_json::to_string(&j).unwrap();
        std::fs::write(&path, format!("\u{feff}{text}")).unwrap();
        assert_eq!(read_journal(&path).unwrap().unwrap(), j);
        let _ = std::fs::remove_file(&path);
    }

    /// 在**临时注册表键**上跑真实的写入与还原，全程不碰系统代理。
    #[test]
    fn scratch_registry_apply_then_restore_returns_to_original() {
        let store = ProxyStore {
            key_path: format!(r"Software\SpiderVPN\tests\{}", std::process::id()),
        };
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&store.key_path);

        // 铺一份「用户原本的设置」
        {
            let (k, _) = hkcu.create_subkey(&store.key_path).unwrap();
            k.set_value("ProxyEnable", &0u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:7897").unwrap();
            k.set_value("ProxyOverride", &"localhost;192.168.*;<local>").unwrap();
        }
        let before = store.read();
        assert!(before.readable);
        assert!(!before.enable);

        // 接管
        let plan = plan_connect(&before, "127.0.0.1:7890", false);
        assert!(plan.blocked.is_none());
        store.apply(&plan.changes).unwrap();
        let after_apply = store.read();
        assert!(after_apply.enable, "接管后应启用");
        assert_eq!(after_apply.server.as_deref(), Some("127.0.0.1:7890"));
        assert!(
            after_apply.bypass.as_deref().unwrap_or("").contains("192.168.*"),
            "绕过列表必须还在"
        );

        // 还原
        let j = ProxyJournal::from_snapshot(&before, "127.0.0.1:7890", 0.0);
        let restore = plan_restore(&j, &after_apply, "127.0.0.1:7890");
        assert!(restore.blocked.is_none());
        store.apply(&restore.changes).unwrap();
        let after_restore = store.read();
        assert_eq!(after_restore.enable, before.enable);
        assert_eq!(after_restore.server, before.server);
        assert_eq!(after_restore.bypass, before.bypass);

        let _ = hkcu.delete_subkey_all(&store.key_path);
    }
}
