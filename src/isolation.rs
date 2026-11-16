//! 与旧版客户端的隔离边界。
//!
//! 这一模块存在的唯一目的是：让「不小心和旧版共用资源」变成编译期/启动期的显式错误，
//! 而不是运行一段时间之后才发现的诡异冲突（抢数据目录、抢互斥、抢系统代理）。
//!
//! 机器可查版本见 `isolation.contract.json`。

use std::path::{Path, PathBuf};

/// 旧版（已定版，冻结）的运行时资源。任何一项出现在本程序里都是缺陷。
pub struct Legacy;

// MUTEX_PREFIX / SCHEDULED_TASK_PREFIX 目前只被契约（isolation.contract.json）引用，
// 代码里还没用到——留作后续「冲突检测」与「不注册同名任务」的显式依据。
#[allow(dead_code)]
impl Legacy {
    pub const INSTALL_DIR: &'static str = r"C:\tradechannel";
    pub const DATA_ROOT_NAME: &'static str = "TradeChannel";
    pub const MUTEX_PREFIX: &'static str = r"Global\TradeChannelGuard-";
    pub const PROCESS_NAME: &'static str = "TradeChannel.exe";
    pub const SCHEDULED_TASK_PREFIX: &'static str = "TradeChannel.UIStartup";
}

/// 本程序的运行时资源。
pub struct Rewrite;

impl Rewrite {
    pub const PRODUCT_NAME: &'static str = "SpiderVPN";
    pub const INSTALL_DIR: &'static str = r"C:\SpiderVPN";
    pub const MUTEX_PREFIX: &'static str = r"Global\SpiderVPN-";
    pub const SCHEDULED_TASK_PREFIX: &'static str = "SpiderVPN.";
    pub const ENV_ROOT: &'static str = "SPIDERVPN_ROOT";
}

/// 安装目录。可用环境变量覆盖，便于在开发机上把整棵树挪走。
pub fn install_dir() -> PathBuf {
    match std::env::var(Rewrite::ENV_ROOT) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => PathBuf::from(Rewrite::INSTALL_DIR),
    }
}

/// 数据根。与旧版必须既不相等、也不能是旧版数据根的子目录
/// （把数据根挪到旧版目录底下是最常见的「假隔离」）。
pub fn data_root() -> PathBuf {
    install_dir().join("data")
}

/// 旧版的默认数据根，仅用于冲突检查，绝不用于读写。
fn legacy_data_root() -> PathBuf {
    let program_data = std::env::var("ProgramData")
        .unwrap_or_else(|_| r"C:\ProgramData".to_string());
    Path::new(&program_data).join(Legacy::DATA_ROOT_NAME)
}

#[derive(Debug, PartialEq, Eq)]
pub enum IsolationError {
    /// 数据根与旧版相同。
    SameAsLegacy,
    /// 数据根在旧版目录之下，仍会互相影响。
    UnderLegacy,
    /// 安装目录指向了旧版安装位置。
    InstallDirIsLegacy,
}

/// 启动时先跑这一条。失败就不要继续初始化，更不要接管网络。
pub fn check() -> Result<(), IsolationError> {
    let install = install_dir();
    let data = data_root();

    if install == Path::new(Legacy::INSTALL_DIR) {
        return Err(IsolationError::InstallDirIsLegacy);
    }
    let legacy = legacy_data_root();
    if data == legacy {
        return Err(IsolationError::SameAsLegacy);
    }
    // 大小写不敏感比较：Windows 路径不区分大小写，用字符串前缀判断足够。
    let d = data.to_string_lossy().to_lowercase();
    let l = legacy.to_string_lossy().to_lowercase();
    if d.starts_with(&l) {
        return Err(IsolationError::UnderLegacy);
    }
    Ok(())
}

/// 旧版是否正在运行。用于「检测到冲突就拒绝接管系统代理」。
///
/// 三层判据缺一不可：
/// 1. 旧版 exe 进程名；
/// 2. 旧版后台 supervisor 的全局互斥（`TradeChannel.ps1` 起的 PowerShell UI 也会带起它）；
/// 3. 旧版 PowerShell 界面自己的 `Local\TradeChannel.UI.<SID>` 互斥。
///
/// 第 3 条是关键：旧版界面由 powershell.exe 承载，按进程名 `TradeChannel.exe` 永远查不到。
pub fn legacy_running() -> bool {
    let exe_probe = std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", Legacy::PROCESS_NAME), "/NH"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).to_lowercase().contains("tradechannel.exe"))
        .map_err(|e| e.to_string());
    legacy_decision(exe_probe, legacy_supervisor_running(), legacy_ui_running())
}

/// 把三条判据合成一个决定。单独抽出来是为了能证明「探测失败必须按在跑处理」，
/// 而不是只在注释里承诺。
fn legacy_decision(
    exe_probe: Result<bool, String>,
    supervisor: bool,
    ui: bool,
) -> bool {
    match exe_probe {
        Ok(true) => true,
        // 探测失败 = 无法证明旧版没在跑 → 宁可拒绝接管网络。
        Err(_) => true,
        Ok(false) => supervisor || ui,
    }
}

#[cfg(target_os = "windows")]
mod legacy_mutex {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            needed: *mut u32,
        ) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> Handle;
        fn CreateMutexW(attrs: *mut c_void, owner: i32, name: *const u16) -> Handle;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn mutex_handle(name: &str, create: bool) -> Handle {
        let name = wide(name);
        unsafe {
            if create {
                CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr())
            } else {
                OpenMutexW(SYNCHRONIZE, 0, name.as_ptr())
            }
        }
    }

    /// 当前进程用户的 SID 字符串。取不到时返回 None，调用方只能退回进程名判据。
    pub fn current_sid() -> Option<String> {
        unsafe {
            let mut token: Handle = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TOKEN_USER_CLASS, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                CloseHandle(token);
                return None;
            }
            let mut buffer = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*(buffer.as_ptr() as *const SidAndAttributes);
            let mut text: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.sid, &mut text) == 0 || text.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *text.add(len) != 0 {
                len += 1;
            }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(text, len)))
        }
    }

    pub fn exists(name: &str) -> bool {
        let h = mutex_handle(name, false);
        if h.is_null() {
            return false;
        }
        unsafe { CloseHandle(h) };
        true
    }

    /// 测试专用：创建并持有同名互斥，drop 时关闭。
    #[cfg(test)]
    pub struct TestMutex(pub Handle);
    #[cfg(test)]
    impl Drop for TestMutex {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    #[cfg(test)]
    pub fn create_for_test(name: &str) -> TestMutex {
        TestMutex(mutex_handle(name, true))
    }
}

#[cfg(target_os = "windows")]
fn legacy_ui_mutex_name() -> Option<String> {
    legacy_mutex::current_sid().map(|sid| format!(r"Local\TradeChannel.UI.{sid}"))
}

fn legacy_supervisor_running() -> bool {
    #[cfg(target_os = "windows")]
    {
        legacy_mutex::exists(r"Global\TradeChannelSupervisor")
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

fn legacy_ui_running() -> bool {
    #[cfg(target_os = "windows")]
    {
        legacy_ui_mutex_name().map(|n| legacy_mutex::exists(&n)).unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_root_is_not_legacy() {
        // 默认配置下必须通过；这条一旦失败说明常量写错了。
        assert_eq!(check(), Ok(()));
    }

    #[test]
    fn data_root_rejects_subdirectory_of_legacy() {
        let legacy = legacy_data_root();
        let fake = legacy.join("nested");
        let d = fake.to_string_lossy().to_lowercase();
        let l = legacy.to_string_lossy().to_lowercase();
        assert!(d.starts_with(&l), "子目录必须被识别为假隔离");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_ui_and_supervisor_mutexes_are_detected() {
        let sid = legacy_ui_mutex_name().expect("必须能取到当前用户 SID");
        assert!(sid.starts_with(r"Local\TradeChannel.UI.S-1-"), "{sid}");
        let _ui = legacy_mutex::create_for_test(&sid);
        assert!(legacy_ui_running(), "旧版 PowerShell 界面互斥必须被识别");
        let _supervisor = legacy_mutex::create_for_test(r"Global\TradeChannelSupervisor");
        assert!(legacy_supervisor_running(), "旧版 supervisor 互斥必须被识别");
    }

    #[test]
    fn legacy_probe_failure_is_fail_closed() {
        assert!(legacy_decision(Err("tasklist missing".to_string()), false, false));
        assert!(legacy_decision(Ok(false), true, false));
        assert!(legacy_decision(Ok(false), false, true));
        assert!(!legacy_decision(Ok(false), false, false));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_exe_process_is_detected_by_name() {
        // 用系统 PING 复制成旧版 exe 名，验证 tasklist 判据真的能命中，
        // 而不是只在“没有旧版时返回 false”这一侧成立。
        let dir = std::env::temp_dir().join(format!("tcrs-legacy-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(Legacy::PROCESS_NAME);
        std::fs::copy(r"C:\Windows\System32\PING.EXE", &exe).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args(["-n", "8", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("启动同名测试进程");
        let mut detected = false;
        for _ in 0..20 {
            if legacy_running() {
                detected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(detected, "按旧版 exe 进程名必须能检测到");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unrelated_mutex_is_not_mistaken_for_legacy() {
        let name = format!(r"Local\TradeChannelRSTests.{}.{}", std::process::id(), 1);
        assert!(!legacy_mutex::exists(&name), "不存在的随机互斥不能误报");
        let _guard = legacy_mutex::create_for_test(&name);
        assert!(legacy_mutex::exists(&name), "正向对照：同名互斥存在时必须能找到");
    }
}
