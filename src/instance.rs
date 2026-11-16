//! 单实例：同机只允许一个 `SpiderVPN` 在跑。
//!
//! 用 Win32 命名互斥，名字必须落在 `Global\SpiderVPN-*`（见 D11）。
//! 刻意不复用旧版那把 `TradeChannelGuard` 互斥——复用就等于和旧版互斥，
//! 两个程序会互相把对方当成「自己已经在跑」，那是最恶劣的一种耦合。
//!
//! 这里直接声明 kernel32 的函数，不引入 `windows` crate：只需要 3 个调用，
//! 引一个大依赖反而增加供应链面。

use std::ptr;

type Handle = *mut core::ffi::c_void;

const ERROR_ALREADY_EXISTS: u32 = 183;

#[link(name = "kernel32")]
extern "system" {
    fn CreateMutexW(attrs: *mut core::ffi::c_void, initial_owner: i32, name: *const u16) -> Handle;
    fn GetLastError() -> u32;
    fn CloseHandle(h: Handle) -> i32;
}

pub struct InstanceGuard {
    handle: Handle,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AcquireError {
    /// 已经有另一个本程序实例在跑。
    AlreadyRunning,
    /// 创建互斥失败（权限或系统错误）。
    Failed(u32),
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 取得单实例锁。成功返回的 guard 在 drop 时释放。
pub fn acquire(name: &str) -> Result<InstanceGuard, AcquireError> {
    // 互斥名必须带我们的前缀，否则会跟旧版撞上。
    if !name.starts_with(crate::isolation::Rewrite::MUTEX_PREFIX) {
        return Err(AcquireError::Failed(87)); // ERROR_INVALID_PARAMETER
    }
    let wide = to_wide(name);
    // bInitialOwner = 0：不持有所有权，只借「对象是否存在」判断单实例，
    // 这样不需要 ReleaseMutex，进程崩溃也不会留下需要清理的所有权。
    let h = unsafe { CreateMutexW(ptr::null_mut(), 0, wide.as_ptr()) };
    if h.is_null() {
        return Err(AcquireError::Failed(unsafe { GetLastError() }));
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(h) };
        return Err(AcquireError::AlreadyRunning);
    }
    Ok(InstanceGuard { handle: h })
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_reports_already_running() {
        let name = format!("{}test-{}", crate::isolation::Rewrite::MUTEX_PREFIX, std::process::id());
        let first = acquire(&name).expect("第一次应当成功");
        // 不用 assert_eq!：那会要求 InstanceGuard: Debug + PartialEq，而它不该有这两个派生。
        assert!(matches!(acquire(&name), Err(AcquireError::AlreadyRunning)));
        drop(first);
        // 释放后应当能再次取得，证明 guard 的 drop 真的关了句柄
        assert!(acquire(&name).is_ok(), "guard 释放后应可重新获取");
    }

    #[test]
    fn rejects_name_without_our_prefix() {
        // 用常量拼出「旧版那种名字」，避免在源码里硬写旧版互斥字面量
        // （隔离门会扫这些字面量，硬写就是在给自己埋违规）。
        let legacy_like = format!("{}should-not-happen", crate::isolation::Legacy::MUTEX_PREFIX);
        let r = acquire(&legacy_like);
        assert!(matches!(r, Err(AcquireError::Failed(87))));
    }
}
