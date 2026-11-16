//! 线路的「本机出口网卡」绑定（`<数据根>\line-network.json`）。
//!
//! 这里只回答两件事：**这条线路指定了哪张网卡**，以及**那张网卡现在还在这台电脑上吗**。
//! 真正的绑定动作在连接前由 [`crate::engine_config::apply_bind_interface`] 写进运行时配置，
//! 不在这里；本模块不碰线路文件、不碰系统代理、不连服务器。
//!
//! 为什么绑定按**线路**记而不是按机器记：交易线路与日常线路的出口本来就可能不同
//! （网线走交易、Wi-Fi 走日常）。旧版的 `LineNetworkUpdate` 也是按 LineId 记的。
//!
//! 键用线路 **id** 而不是名字：改个显示名不该把绑定弄丢。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 绑定表文件名。与 `config.json` 同级，都属于本机事实。
pub const FILE: &str = "line-network.json";

/// 绑定表：线路 id → 网卡名。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bindings {
    map: BTreeMap<String, String>,
}

impl Bindings {
    /// 这条线路指定的网卡；`None` = 跟随系统默认。
    pub fn get(&self, line_id: &str) -> Option<&str> {
        self.map.get(line_id).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 写入一条（空串 = 删掉这条）。返回是否真的变了——调用方据此决定要不要写盘，
    /// 与 `apply_bind_interface` 的「同值不算变化」是同一个约定。
    pub fn put(&mut self, line_id: &str, interface: &str) -> bool {
        let line_id = line_id.trim();
        let interface = interface.trim();
        if line_id.is_empty() {
            return false;
        }
        let before = self.map.get(line_id).cloned().unwrap_or_default();
        if before == interface {
            return false;
        }
        if interface.is_empty() {
            self.map.remove(line_id);
        } else {
            self.map.insert(line_id.to_string(), interface.to_string());
        }
        true
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut bindings = serde_json::Map::new();
        for (line, interface) in &self.map {
            bindings.insert(line.clone(), serde_json::Value::String(interface.clone()));
        }
        serde_json::json!({ "schema": 1, "bindings": bindings })
    }

    /// 坏形状一律读成空：绑定不是可信判据，读不出来就等于「没指定」。
    /// 把它当成错误会让「这个文件被谁改坏」升级成「整个连接路径读不到配置」。
    pub fn from_json(value: &serde_json::Value) -> Self {
        let mut map = BTreeMap::new();
        if let Some(object) = value.get("bindings").and_then(serde_json::Value::as_object) {
            for (line, interface) in object {
                let Some(name) = interface.as_str() else { continue };
                let name = name.trim();
                if line.trim().is_empty() || name.is_empty() {
                    continue;
                }
                map.insert(line.clone(), name.to_string());
            }
        }
        Self { map }
    }
}

pub fn path(root: &Path) -> PathBuf {
    root.join(FILE)
}

pub fn load(root: &Path) -> Bindings {
    let Ok(text) = std::fs::read_to_string(path(root)) else {
        return Bindings::default();
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => Bindings::from_json(&value),
        Err(_) => Bindings::default(),
    }
}

/// 写一条绑定（空串 = 删）。没有变化就不写盘。
///
/// 落盘用 tmp + rename：半个文件等于「绑定表整张读不出来」，那会让所有线路
/// 一起退回系统默认——一个用户只想改一条线路，不该付这个代价。
pub fn set(root: &Path, line_id: &str, interface: &str) -> Result<Bindings, String> {
    let mut bindings = load(root);
    if !bindings.put(line_id, interface) {
        return Ok(bindings);
    }
    save(root, &bindings)?;
    Ok(bindings)
}

/// 删掉一条线路的绑定（删线路时用；读不到文件就当已经删了）。
pub fn forget(root: &Path, line_id: &str) -> Result<bool, String> {
    let mut bindings = load(root);
    if bindings.get(line_id).is_none() && !bindings.map.contains_key(line_id) {
        return Ok(false);
    }
    bindings.put(line_id, "");
    save(root, &bindings)?;
    Ok(true)
}

fn save(root: &Path, bindings: &Bindings) -> Result<(), String> {
    let target = path(root);
    if bindings.is_empty() {
        // 空表不留在磁盘上：留一个 `{"schema":1,"bindings":{}}` 只会让人以为
        // 「这里本来有东西、被清掉了」，而实际上什么都没指定。
        match std::fs::remove_file(&target) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("删除出口网卡记录失败（{}）：{e}", target.display())),
        }
    }
    let text = serde_json::to_string_pretty(&bindings.to_json())
        .map_err(|e| format!("生成出口网卡记录失败：{e}"))?;
    let temp = target.with_file_name(format!("{FILE}.tmp"));
    std::fs::write(&temp, text.as_bytes())
        .map_err(|e| format!("写入出口网卡记录失败（{}）：{e}", temp.display()))?;
    std::fs::rename(&temp, &target)
        .map_err(|e| format!("落盘出口网卡记录失败（{}）：{e}", target.display()))?;
    Ok(())
}

/// 连接时到底绑哪张网卡：`(要绑的名字, 指定了但当前不可用的名字)`。
///
/// 三条判据：
/// - 没指定 → 系统默认（拿不到就是空串 = 一个字段都不写）；
/// - 指定且这台电脑上确实有 → 用它；
/// - 指定但**不在了** → 返回空串 + 把名字带出来。调用方必须拒绝连接：
///   静默回退到默认网卡等于把交易流量放到用户没选的那条出口上，
///   而「绑一张不存在的网卡」会让引擎直接起不来（`sing-box` 解析失败）。
pub fn resolve(chosen: Option<&str>, available: &[String], default: &str) -> (String, Option<String>) {
    let chosen = chosen.map(str::trim).filter(|s| !s.is_empty());
    match chosen {
        // **没指定就真的不绑**（旧版的行为：`route.auto_detect_interface = true`，
        // 全程不写 `bind_interface`）。把默认网卡名写进 `bind_interface` 会让 sing-box
        // 在 Windows 上按名字解析接口——而 `GetAdaptersAddresses` 给出的名字
        // （如 `wireless_32768`）sing-box 解析不了，报
        // `route ip+net: no such network interface`，于是**每一个出站都拨不出去**：
        // 隧道建不起来、握手包一个都发不出去，而直连流量照旧——看起来就像"只有部分网站不通"。
        None => (String::new(), None),
        Some(name) => {
            let present = available
                .iter()
                .any(|item| item.trim().eq_ignore_ascii_case(name));
            if present {
                (name.to_string(), None)
            } else {
                (String::new(), Some(name.to_string()))
            }
        }
    }
}

/// 给连接路径用：读绑定表 + 现场问一次网卡，算出这次要绑谁。
///
/// 每次连接现读磁盘，不缓存：用户在「连接方式与网络」里刚改的值必须立刻生效，
/// 缓存一致性换来的那点毫秒不值得。
pub fn for_connect(root: &Path, line_id: &str) -> (String, Option<String>) {
    let bindings = load(root);
    let chosen = bindings.get(line_id).map(|s| s.to_string());
    let available = crate::autoroute::interfaces();
    let default = crate::autoroute::network_info().interface;
    resolve(chosen.as_deref(), &available, &default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_binding_writes_no_bind_interface_at_all() {
        let available = names(&["以太网", "WLAN"]);
        assert_eq!(
            resolve(None, &available, ""),
            (String::new(), None),
            "没指定就**不写 bind_interface**，交给 sing-box 的 auto_detect_interface"
        );
        // 只有空白也算「没指定」：不能被当成网卡名写进配置。
        assert_eq!(resolve(Some("  "), &available, "WLAN"), (String::new(), None));
        assert_eq!(
            resolve(None, &available, ""),
            (String::new(), None),
            "默认网卡读不到 = 不写任何字段"
        );
    }

    #[test]
    fn a_bound_interface_that_still_exists_wins() {
        let available = names(&["以太网", "WLAN"]);
        assert_eq!(
            resolve(Some("WLAN"), &available, "以太网"),
            ("WLAN".to_string(), None),
            "用户指定的网卡优先于默认网卡"
        );
    }

    #[test]
    fn a_bound_interface_that_is_gone_is_reported_not_silently_replaced() {
        let available = names(&["以太网", "WLAN"]);
        let (bind, stale) = resolve(Some("雷雳网桥"), &available, "以太网");
        assert_eq!(bind, "", "不绑一张不存在的网卡（引擎会直接起不来）");
        assert_eq!(stale.as_deref(), Some("雷雳网桥"));
    }

    #[test]
    fn binding_table_round_trips_and_empty_write_removes_the_file() {
        let root = std::env::temp_dir().join(format!("tc-netbind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        assert!(load(&root).is_empty(), "没有文件就是空表");
        set(&root, "hk", "以太网").unwrap();
        assert_eq!(load(&root).get("hk"), Some("以太网"));
        assert!(path(&root).exists());

        // 同值不写盘：把文件 mtime 当判据不可靠，改成「内容不变」+ 返回值。
        let before = std::fs::read_to_string(path(&root)).unwrap();
        let again = set(&root, "hk", "以太网").unwrap();
        assert_eq!(again.get("hk"), Some("以太网"));
        assert_eq!(std::fs::read_to_string(path(&root)).unwrap(), before);

        // 空串 = 清除。清到最后一条时文件本身也不留。
        set(&root, "hk", "").unwrap();
        assert!(load(&root).get("hk").is_none());
        assert!(!path(&root).exists(), "空表不该留一个空 JSON 在磁盘上");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_broken_file_reads_as_no_binding_instead_of_failing_the_connection() {
        let root = std::env::temp_dir().join(format!("tc-netbind-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(path(&root), b"{ not json").unwrap();
        assert!(load(&root).is_empty(), "坏文件当没指定：不能让它挡住连接");

        // 形状对但值是垃圾：只保留字符串型的非空项。
        let value = serde_json::json!({"schema":1,"bindings":{"hk":"以太网","bad":7,"":"x","junk":"  "}});
        let parsed = Bindings::from_json(&value);
        assert_eq!(parsed.get("hk"), Some("以太网"));
        assert_eq!(parsed.get("bad"), None);
        assert_eq!(parsed.get("junk"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forgetting_a_line_drops_only_that_line() {
        let root = std::env::temp_dir().join(format!("tc-netbind-forget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        set(&root, "hk", "以太网").unwrap();
        set(&root, "jp", "WLAN").unwrap();
        assert!(forget(&root, "hk").unwrap());
        let left = load(&root);
        assert_eq!(left.get("hk"), None);
        assert_eq!(left.get("jp"), Some("WLAN"), "别的线路的绑定不许被牵连");
        assert!(!forget(&root, "hk").unwrap(), "再删一次是「没变化」，不是错误");
        let _ = std::fs::remove_dir_all(&root);
    }
}
