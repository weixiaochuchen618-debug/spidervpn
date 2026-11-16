//! 注销 / 关机时的**尽力而为**清理。
//!
//! 为什么是「尽力而为」：`SetConsoleCtrlHandler` 抓不到任务管理器强杀、也抓不到断电。
//! 真正的主防线是启动自愈（`connect::heal_stale`）：下次启动发现「凭据在、引擎已死」就自动还原。
//! 这里的价值只在于「正常注销/关机」这种有机会收尾的场合，能让用户少一次「开机先断网」。
//!
//! 不引依赖：`kernel32` 直接链接。
//! 时间预算：系统注销给进程的时间很短，所以清理放到子线程，主线程最多等 3 秒就返回，
//! 宁可留一点残留（下次启动能修），也不能拖住系统注销。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const CTRL_CLOSE_EVENT: u32 = 2;
const CTRL_LOGOUT_EVENT: u32 = 5;
const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// 系统给的最长等待。超过就让它过去——拖住注销比留一点残留更糟。
const BUDGET_MS: u64 = 3_000;

#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

static ROOT: OnceLock<PathBuf> = OnceLock::new();

unsafe extern "system" fn on_console_event(event: u32) -> i32 {
    if !matches!(event, CTRL_CLOSE_EVENT | CTRL_LOGOUT_EVENT | CTRL_SHUTDOWN_EVENT) {
        return 0;
    }
    let Some(root) = ROOT.get() else { return 0 };
    let r = root.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(cleanup_now(&r));
    });
    // 等一会儿就走：系统注销不会给我们太久。
    let _ = rx.recv_timeout(std::time::Duration::from_millis(BUDGET_MS));
    1
}

/// 注册注销/关机钩子。注册失败不影响主流程（自愈仍在）。
pub fn install(root: &Path) {
    let _ = ROOT.set(root.to_path_buf());
    unsafe {
        SetConsoleCtrlHandler(Some(on_console_event), 1);
    }
}

/// 真正干活的部分（可测）：按凭据停引擎、还原代理、删记录。
///
/// 直接复用 `connect::shutdown_cleanup`——注销清理与关窗清理必须是同一套动作，
/// 两条实现迟早会分叉，而在「注销时只还原了一半」这种场景里分叉最难查。
pub fn cleanup_now(root: &Path) -> Result<Vec<String>, String> {
    let store = crate::proxy::ProxyStore::system();
    let journal = root.join("proxy-journal.json");
    let runtime = root.join("runtime.json");
    let deps = crate::connect::Deps {
        store: &store,
        apply: &crate::connect::write_proxy,
        // 清理路径绝不启动引擎。
        spawn: &|_e: &crate::engine::EngineConfig| Err::<i64, String>("注销清理不应启动引擎".into()),
        kill: &|pid: i64| crate::engine::stop(pid, 3_000),
        alive: &crate::probe::pid_alive,
        elevated: &crate::probe::elevated,
        journal_path: &journal,
        runtime_path: &runtime,
        now: 0.0,
        // 注销/关机清理绝不弹 UAC：它是清理路径，不是用户显式断开。
        guard: None,
    };
    crate::connect::shutdown_cleanup(None, &deps, &crate::events::Origin::auto())
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    fn scratch(tag: &str) -> (String, PathBuf) {
        let key = format!(r"Software\SpiderVPN\tests\logoff-{tag}-{}", std::process::id());
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&key);
        let (k, _) = hkcu.create_subkey(&key).unwrap();
        k.set_value("ProxyEnable", &1u32).unwrap();
        k.set_value("ProxyServer", &"127.0.0.1:17890").unwrap();
        k.set_value("ProxyOverride", &"localhost;<local>").unwrap();
        let dir = std::env::temp_dir().join(format!("tcrs-logoff-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (key, dir)
    }

    #[test]
    fn cleanup_restores_proxy_and_drops_the_credential() {
        // 注销清理与关窗清理走同一段代码：这里钉住「真的按凭据还原并删凭据」。
        let (key, dir) = scratch("restore");
        let store = crate::proxy::ProxyStore { key_path: key.clone() };
        let journal = dir.join("proxy-journal.json");
        let runtime = dir.join("runtime.json");
        let before = store.read();
        let _ = before;
        // 凭据里记的是**接管前**的值（enable=0 / 7897），而当前键是接管后的（enable=1 / 17890）。
        std::fs::write(
            &journal,
            r#"{"schema":1,"endpoint":"127.0.0.1:17890","saved_at_secs":0,
                "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
        )
        .unwrap();
        std::fs::write(
            &runtime,
            r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":4194303,"State":"Running"}"#,
        )
        .unwrap();

        // 直接复用 cleanup_now 的内部依赖：用临时键的 store 走一遍（默认 store 会碰真实键）。
        let deps = crate::connect::Deps {
            store: &store,
            apply: &crate::connect::write_proxy,
            spawn: &|_e: &crate::engine::EngineConfig| Err::<i64, String>("不应启动引擎".into()),
            kill: &|_pid: i64| Ok(()),
            alive: &|_pid: i64| false,
            elevated: &|| true,
            journal_path: &journal,
            runtime_path: &runtime,
            now: 0.0,
            guard: None,
        };
        let steps = crate::connect::shutdown_cleanup(
            None,
            &deps,
            &crate::events::Origin::other(),
        )
        .expect("清理应当成功");
        assert!(steps.iter().any(|s| s.contains("还原系统代理")), "{steps:?}");
        assert!(!journal.exists(), "清理后凭据必须删除");
        assert!(!runtime.exists(), "清理后运行时记录必须删除");
        // 键要回到接管前
        let after = store.read();
        assert!(!after.enable, "注销清理后代理必须关掉");
        assert_eq!(after.server.as_deref(), Some("127.0.0.1:7897"));

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&key);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
