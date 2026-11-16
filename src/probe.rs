//! 真实环境探测：进程是否存活、会话是否存在、控制接口是否可用。
//!
//! 与 `model` 分开是为了让状态投影可以脱离系统测试——把「记录说在跑、实际已死」
//! 这类情况用假探针喂进去，而不是只能靠真机撞。

use crate::model::Probe;

type Handle = *mut core::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(h: Handle) -> i32;
    fn WaitForSingleObject(h: Handle, millis: u32) -> u32;
}

/// 只要「同步」权限：能等它变成 signaled 就够了，不需要读内存或改状态。
const SYNCHRONIZE: u32 = 0x0010_0000;
const WAIT_TIMEOUT: u32 = 258;

#[derive(Debug, Default)]
pub struct SystemProbe {
    /// 会话文件是否存在（由调用方探测后传入，避免这里再去碰磁盘布局）。
    pub session_present: bool,
    /// 控制接口（命名管道）是否可用。**由调用方按实测填充**（`ipc::evidence` 收到的是这次 ping 的结果），
    /// 探针自己不猜：报「可用」必须有依据。
    pub control_available: bool,
}

/// 单个 pid 是否存活。抽成函数是为了能直接注入进 `connect::Deps`（那里要 `&dyn Fn`）。
pub fn pid_alive(pid: i64) -> bool {
    SystemProbe::default().process_alive(pid)
}

/// 本进程是否提权（能写 HKLM\SOFTWARE 就是）。
///
/// 用注册表句柄而不是 `IsUserAnAdmin`/`CheckTokenMembership`：`winreg` 已经在依赖里，
/// 不必为一句判定再声明 Win32 API，也不必担心它在不同 Windows 版本上的行为差异。
pub fn is_elevated() -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WRITE};
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags("SOFTWARE", KEY_WRITE).is_ok()
}

/// 生产代码用的提权判定，尊重测试钩子 `SPIDERVPN_FORCE_NONADMIN=1`。
///
/// 为什么要有钩子：验收机基本都是提权会话，没有它「非管理员」那条分支永远跑不到，
/// 而那条分支正是「动手之前先拒绝」的关键证据。钩子只影响这个判定的返回值，不做任何特权操作。
pub fn elevated() -> bool {
    if forced_nonadmin() {
        return false;
    }
    is_elevated()
}

/// 测试钩子是否生效。单独抽出来，是为了让它能被单测直接钉住。
pub fn forced_nonadmin() -> bool {
    matches!(std::env::var("SPIDERVPN_FORCE_NONADMIN").as_deref(), Ok("1"))
}

impl Probe for SystemProbe {
    fn process_alive(&self, pid: i64) -> bool {
        if pid <= 0 || pid > u32::MAX as i64 {
            return false;
        }
        let h = unsafe { OpenProcess(SYNCHRONIZE, 0, pid as u32) };
        if h.is_null() {
            return false;
        }
        // OpenProcess 成功**不代表进程还活着**：只要还有人持有句柄（比如我们自己的
        // Child），已退出的进程对象依然能被打开。必须问「它 signaled 了吗」。
        let rc = unsafe { WaitForSingleObject(h, 0) };
        unsafe { CloseHandle(h) };
        rc == WAIT_TIMEOUT
    }

    fn session_present(&self) -> bool {
        self.session_present
    }

    fn control_available(&self) -> bool {
        self.control_available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_alive() {
        let p = SystemProbe::default();
        assert!(p.process_alive(std::process::id() as i64));
    }

    #[test]
    fn absurd_pids_are_not_alive() {
        let p = SystemProbe::default();
        assert!(!p.process_alive(0));
        assert!(!p.process_alive(-1));
        // 一个大到不存在的 pid：OpenProcess 失败即视为不在
        assert!(!p.process_alive(0x7FFF_FFFE));
    }

    #[test]
    fn control_interface_is_not_claimed_available() {
        // 这条是防「假装已连接」的：没有 IPC 就不能报可用。
        let p = SystemProbe::default();
        assert!(!p.control_available());
    }

    #[test]
    fn nonadmin_hook_overrides_the_real_probe() {
        // 钩子的用途：验收机通常是提权会话，靠它才能跑到「非管理员」那条分支。
        let restore = std::env::var("SPIDERVPN_FORCE_NONADMIN").ok();
        std::env::set_var("SPIDERVPN_FORCE_NONADMIN", "1");
        assert!(forced_nonadmin(), "设了 1 就必须判定为强制非管理员");
        assert!(!elevated(), "强制非管理员时，无论真实权限如何都返回 false");
        std::env::set_var("SPIDERVPN_FORCE_NONADMIN", "0");
        assert!(!forced_nonadmin(), "只有 1 才算生效，别的值一律不算");
        assert_eq!(elevated(), is_elevated(), "钩子不生效时应等于真实判定");
        match restore {
            Some(v) => std::env::set_var("SPIDERVPN_FORCE_NONADMIN", v),
            None => std::env::remove_var("SPIDERVPN_FORCE_NONADMIN"),
        }
    }
}
