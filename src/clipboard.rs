//! 剪贴板：只做「把一段文本放进去」这一件事。
//!
//! 为什么不用第三方 crate：整个程序只写一次剪贴板（复制邀请码），为它引一个
//! 带平台后端的依赖不值得；这里用到的四个 API 都在已经依赖的 `windows-sys` 里。
//!
//! 失败要说出来：剪贴板可能被别的程序占着（`OpenClipboard` 会失败），
//! 这时界面不能显示「已复制」——用户去粘贴会得到上一次的内容。

// CF_UNICODETEXT。数值固定（Windows 的剪贴板格式常量是 ABI 的一部分），
// 这里写字面量是因为它不在 windows-sys 的 DataExchange 模块里导出。
#[cfg(windows)]
const CLIPBOARD_UNICODETEXT: u32 = 13;

#[cfg(windows)]
pub fn set_text(text: &str) -> Result<(), String> {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // 结尾 0：剪贴板里的字符串必须以 NUL 收尾，长度按字节算。
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * 2;
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return Err("剪贴板正被其他程序占用，请稍后再点一次。".into());
        }
        // 从打开到关闭之间的每一步失败都要 CloseClipboard，否则整个系统都写不进剪贴板。
        if EmptyClipboard() == 0 {
            CloseClipboard();
            return Err("剪贴板没有清空成功，请稍后再点一次。".into());
        }
        let handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if handle.is_null() {
            CloseClipboard();
            return Err("内存不足，没能准备邀请码。".into());
        }
        let target = GlobalLock(handle) as *mut u16;
        if target.is_null() {
            CloseClipboard();
            return Err("内存不足，没能准备邀请码。".into());
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), target, wide.len());
        GlobalUnlock(handle);
        // 成功之后这块内存归系统所有，**不能**自己 GlobalFree。
        if SetClipboardData(CLIPBOARD_UNICODETEXT, handle).is_null() {
            CloseClipboard();
            return Err("剪贴板没有接受邀请码，请稍后再点一次。".into());
        }
        CloseClipboard();
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_text(_text: &str) -> Result<(), String> {
    Err("这个平台没有实现剪贴板。".into())
}
