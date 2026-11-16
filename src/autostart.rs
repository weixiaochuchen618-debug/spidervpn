//! 开机自启：HKCU 的 Run 键。
//!
//! 为什么是 Run 键而不是计划任务：
//! - 纯 HKCU，**不需要管理员权限**——自启的是普通入口，要 TUN 的用户仍得自己用管理员入口；
//! - 旧版用计划任务（`*.UIStartup`），那是它的运行时资源，本程序不碰；
//! - 幂等最容易做：写值/删值，不涉及「任务已存在」这类状态迁移。
//!
//! 值内容指向安装根的启动入口 `.cmd`，而不是 exe：入口脚本负责 `cd /d <bin>`，
//! 直接在 Run 里写 exe 的话，某些启动路径下工作目录不可控。

use std::path::Path;

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

/// Run 键下的值名。与产品名一致，用户在 regedit 里一眼能认出是谁写的。
pub const VALUE_NAME: &str = "SpiderVPN";

/// 默认键路径（相对 HKCU）。测试用 `SPIDERVPN_RUN_KEY` 指到临时键。
pub const DEFAULT_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// 安装根下的启动入口文件名（`install-local.ps1` 生成的普通入口）。
pub const LAUNCHER_NAME: &str = "启动SpiderVPN.cmd";

/// 实际使用的键路径。测试钩子只影响路径，不改变「写什么值」。
pub fn key_path() -> String {
    match std::env::var("SPIDERVPN_RUN_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => DEFAULT_KEY.to_string(),
    }
}

/// 自启该指向什么：优先安装根的启动入口，找不到就退回 exe 本身。
///
/// 安装布局是 `<安装根>\bin\spidervpn.exe`，所以安装根 = exe 的父目录的父目录。
pub fn launcher_target(exe: &Path) -> String {
    let root = exe.parent().and_then(|bin| bin.parent());
    if let Some(root) = root {
        let cmd = root.join(LAUNCHER_NAME);
        if cmd.exists() {
            return cmd.to_string_lossy().to_string();
        }
    }
    // 退回到 exe 本身：至少还能起来，只是工作目录不由我们控制。
    exe.to_string_lossy().to_string()
}

/// 写自启项。重复写同一个值不报错（幂等）。
///
/// 值**必须带引号**：安装路径一旦含空格（换成 `C://Program Files\...` 就会），
/// 不带引号的命令行会被 Windows 按空格切成两段，自启静默失效——而且只在别人机器上复现。
pub fn enable_in(key: &str, target: &str) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu
        .create_subkey(key)
        .map_err(|e| format!("打开 Run 键失败（{key}）：{e}"))?;
    let quoted = quote_command(target);
    run.set_value(VALUE_NAME, &quoted)
        .map_err(|e| format!("写自启项失败（{key}\\{VALUE_NAME}）：{e}"))
}

/// Run 值统一用双引号包住；已经带引号的不重复加。
pub fn quote_command(target: &str) -> String {
    if target.starts_with('"') && target.ends_with('"') {
        target.to_string()
    } else {
        format!("\"{target}\"")
    }
}

/// 删自启项。本来就不存在也算成功——用户点「关」时不该因为「没开过」而报错。
pub fn disable_in(key: &str) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = match hkcu.open_subkey_with_flags(key, KEY_WRITE) {
        Ok(k) => k,
        // 连键都没有 = 没有任何自启项，正是我们要的结果。
        Err(_) => return Ok(()),
    };
    match run.delete_value(VALUE_NAME) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("删除自启项失败（{key}\\{VALUE_NAME}）：{e}")),
    }
}

/// 读当前自启项。只用于自检/展示，`None` 表示没开。
pub fn current_in(key: &str) -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = hkcu.open_subkey_with_flags(key, KEY_READ).ok()?;
    let raw: String = run.get_value(VALUE_NAME).ok()?;
    Some(unquote(&raw))
}

/// 去掉外层引号（展示与比对用；写进去的仍是带引号的形式）。
fn unquote(raw: &str) -> String {
    raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(raw).to_string()
}

/// 按配置里的开关同步 Run 键（默认键路径）。
pub fn sync(enabled: bool, exe: &Path) -> Result<(), String> {
    let key = key_path();
    if enabled {
        enable_in(&key, &launcher_target(exe))
    } else {
        disable_in(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个用例一个临时键：不碰真实 Run 键。这里直接传 key 参数，不用环境变量，免得并行用例互踩。
    fn test_key(tag: &str) -> String {
        format!(r"Software\SpiderVPN\tests\run-{tag}-{}", std::process::id())
    }

    fn cleanup(key: &str) {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(key);
    }

    #[test]
    fn enable_then_disable_roundtrip() {
        let key = test_key("roundtrip");
        cleanup(&key);
        assert_eq!(current_in(&key), None, "没写过就该读不到");

        enable_in(&key, r"C:\x\启动SpiderVPN.cmd").unwrap();
        assert_eq!(current_in(&key).as_deref(), Some(r"C:\x\启动SpiderVPN.cmd"));
        // 磁盘上存的必须是**带引号**的形式：安装路径含空格时，不带引号会被 Windows 切断，
        // 自启静默失效（而且只在别人机器上复现）。
        let run = RegKey::predef(HKEY_CURRENT_USER).open_subkey(&key).unwrap();
        let raw: String = run.get_value(VALUE_NAME).unwrap();
        assert_eq!(raw, "\"C:\\x\\启动SpiderVPN.cmd\"", "Run 值要带引号：{raw}");

        disable_in(&key).unwrap();
        assert_eq!(current_in(&key), None, "关掉之后该值必须消失");
        cleanup(&key);
    }

    #[test]
    fn enable_is_idempotent_and_keeps_one_value() {
        let key = test_key("idem");
        cleanup(&key);
        enable_in(&key, r"C:\x\a.cmd").unwrap();
        enable_in(&key, r"C:\x\a.cmd").unwrap();
        assert_eq!(current_in(&key).as_deref(), Some(r"C:\x\a.cmd"));
        let run = RegKey::predef(HKEY_CURRENT_USER).open_subkey(&key).unwrap();
        let names: Vec<String> = run.enum_values().filter_map(|v| v.ok()).map(|(n, _)| n).collect();
        assert_eq!(names.len(), 1, "重复开启只能留一个值：{names:?}");
        cleanup(&key);
    }

    #[test]
    fn disable_when_absent_is_ok() {
        let key = test_key("absent");
        cleanup(&key);
        // 连键都不存在
        assert!(disable_in(&key).is_ok(), "没开过就点关，不该报错");
        enable_in(&key, "x").unwrap();
        disable_in(&key).unwrap();
        assert!(disable_in(&key).is_ok(), "重复关也不该报错");
        cleanup(&key);
    }

    #[test]
    fn launcher_target_prefers_the_cmd_next_to_bin() {
        // 安装布局：<根>\bin\spidervpn.exe + <根>\启动SpiderVPN.cmd
        let root = std::env::temp_dir().join(format!("tcrs-autostart-{}", std::process::id()));
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("spidervpn.exe");
        std::fs::write(&exe, b"x").unwrap();
        let cmd = root.join(LAUNCHER_NAME);
        std::fs::write(&cmd, b"x").unwrap();

        assert_eq!(launcher_target(&exe), cmd.to_string_lossy(), "有启动入口就指向它");

        std::fs::remove_file(&cmd).unwrap();
        assert_eq!(launcher_target(&exe), exe.to_string_lossy(), "没有启动入口就退回 exe 本身");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn key_path_honours_the_test_hook() {
        let restore = std::env::var("SPIDERVPN_RUN_KEY").ok();
        std::env::remove_var("SPIDERVPN_RUN_KEY");
        assert_eq!(key_path(), DEFAULT_KEY, "默认就是 HKCU 的 Run 键");
        std::env::set_var("SPIDERVPN_RUN_KEY", r"Software\SpiderVPN\tests\x");
        assert_eq!(key_path(), r"Software\SpiderVPN\tests\x");
        std::env::set_var("SPIDERVPN_RUN_KEY", "   ");
        assert_eq!(key_path(), DEFAULT_KEY, "空值当没设，别把值写到根上去");
        match restore {
            Some(v) => std::env::set_var("SPIDERVPN_RUN_KEY", v),
            None => std::env::remove_var("SPIDERVPN_RUN_KEY"),
        }
    }
}
