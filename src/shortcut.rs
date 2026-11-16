//! 桌面快捷方式（A7）。
//!
//! 为什么不是「用 COM 现生成一个 .lnk」：Rust 侧没有任何 COM 绑定（`windows-sys` 不声明
//! `IShellLinkW`），而手写 ShellLink 二进制会让 `os.startfile` 报 WinError 1155（踩过）。
//! 所以这里**复用安装程序已经生成好的那一份**：桌面缺了，就从业已存在的开始菜单副本复制
//! 过去——目标、参数、图标、工作目录全是安装时算好的，一个字节都不用猜。
//!
//! 口径：
//! - 桌面已有 → **不覆盖**，只如实说「已经有了」。覆盖一份用户可能自己改过的快捷方式是
//!   更糟的选择；
//! - 开始菜单也没有 → 不做假动作，直接让人重跑安装程序；
//! - 复制后复核大小：复制被拦或磁盘满都不会静默成功。
//!
//! r101 增补：**读**快捷方式走 Shell COM（`IShellLinkW` + `IPersistFile`），不手写二进制。
//! 落点只有一处——[`executable_target`]：把「拖进来的任意文件」换成「能拿去匹配进程的
//! exe 路径」。写（创建快捷方式）仍然只复制现成的那一份，两件事的方向不同、判据也不同。

use std::path::{Path, PathBuf};

/// 与安装脚本、包目录保持一致的名字（用户认的是这个名字，不是 exe 名）。
pub const LNK_NAME: &str = "交易通道.lnk";

/// 一个 .lnk 至少要有几百字节（头 + 至少一个 ItemID + 结束块）。
/// 小于这个数只可能是坏文件，复制过去等于给用户一个点了没反应的图标。
const MIN_LNK_BYTES: u64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 这次真的创建了。
    Created,
    /// 桌面本来就有，没有改动。
    AlreadyThere,
}

impl Outcome {
    pub fn message(&self) -> &'static str {
        match self {
            Outcome::Created => "已在桌面创建「交易通道」快捷方式。",
            Outcome::AlreadyThere => {
                "桌面已经有「交易通道」快捷方式，没有改动；如果点它没反应，删掉后再点这个按钮。"
            }
        }
    }
}

/// 创建桌面快捷方式（真实路径）。
pub fn ensure_desktop_shortcut() -> Result<Outcome, String> {
    let desktop = desktop_dir().ok_or_else(|| {
        "找不到桌面目录（USERPROFILE 未设置），无法创建快捷方式。".to_string()
    })?;
    let source = start_menu_shortcut()
        .filter(|p| p.is_file())
        .ok_or_else(|| {
            "开始菜单里也没有「交易通道」快捷方式；请重新运行安装程序后再试。".to_string()
        })?;
    ensure_with(&desktop, &source)
}

/// 可注入路径的实现（单测用）。
pub fn ensure_with(desktop: &Path, source: &Path) -> Result<Outcome, String> {
    let target = desktop.join(LNK_NAME);
    if target.is_file() {
        return Ok(Outcome::AlreadyThere);
    }
    let size = std::fs::metadata(source)
        .map(|m| m.len())
        .map_err(|e| format!("读不到开始菜单里的快捷方式：{e}"))?;
    if size < MIN_LNK_BYTES {
        return Err(format!(
            "开始菜单里的快捷方式不完整（{size} 字节，至少应有 {MIN_LNK_BYTES}）；请重新运行安装程序。"
        ));
    }
    std::fs::copy(source, &target).map_err(|e| format!("创建桌面快捷方式失败：{e}"))?;
    // 复核：复制被安全软件拦下、磁盘满、目标被占用，都不会返回 Err 之外的第二种结果，
    // 但「返回 Ok 却只写了一半」是可能的，所以按大小再比一次。
    let copied = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    if copied != size {
        return Err(format!(
            "创建后校验失败：桌面上的文件 {copied} 字节，开始菜单副本 {size} 字节。"
        ));
    }
    Ok(Outcome::Created)
}

/// 桌面目录。**先问 Shell**：`SHGetKnownFolderPath(FOLDERID_Desktop)` 是资源管理器自己用的那
/// 一份答案——用户把桌面移到 D 盘、或由 OneDrive 接管时，只看 `%USERPROFILE%\Desktop` 会往一个
/// 看不见的旧目录里放文件，然后回报「已创建」（比报错更糟）。Shell 不答才退回环境变量。
pub fn desktop_dir() -> Option<PathBuf> {
    if let Some(path) = shell_desktop() {
        return Some(path);
    }
    let profile = PathBuf::from(std::env::var_os("USERPROFILE")?);
    let plain = profile.join("Desktop");
    if plain.is_dir() {
        return Some(plain);
    }
    let redirected = profile.join("OneDrive").join("Desktop");
    if redirected.is_dir() {
        return Some(redirected);
    }
    if let Some(onedrive) = std::env::var_os("OneDrive") {
        let candidate = PathBuf::from(onedrive).join("Desktop");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    // 都不存在也把默认路径交回去：让错误落在「复制失败」上，而不是「没有桌面」这种
    // 让人无从下手的话上（真实目录确实可能在非标准位置）。
    Some(plain)
}

#[cfg(windows)]
fn shell_desktop() -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_Desktop};
    let mut raw: *mut u16 = std::ptr::null_mut();
    // KF_FLAG_DEFAULT = 0、htoken = null → 当前用户；不写注册表、不需要 COM 初始化。
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_Desktop, 0, std::ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let text = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(raw, len)) };
    unsafe { CoTaskMemFree(raw as *const core::ffi::c_void) };
    let path = PathBuf::from(text);
    // 目录不存在就等于没答：交给环境变量兜底，别拿一个空路径去复制。
    path.is_dir().then_some(path)
}

#[cfg(not(windows))]
fn shell_desktop() -> Option<PathBuf> {
    None
}

/// 安装脚本写的开始菜单快捷方式位置（`install-local.ps1` 的 `$startLnk`）。
pub fn start_menu_shortcut() -> Option<PathBuf> {
    let appdata = PathBuf::from(std::env::var_os("APPDATA")?);
    Some(
        appdata
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("SpiderVPN")
            .join(LNK_NAME),
    )
}

// ---------------------------------------------------------------------------
// r101：把拖进来的文件换成「能拿去匹配进程的 exe 路径」
// ---------------------------------------------------------------------------

/// 拖放进来的文件 → 交易程序 exe 的路径。`None` = 这里面没有可用的程序。
///
/// 判据只在这里（宿主 `ui.rs` 只负责「取路径 → 填表单 → 推快照」）：
/// - `.exe`：直接用它；
/// - `.lnk`：向 Shell 要它指向的目标，目标是 `.exe` 就用它；
/// - 其它（文件夹、.bat、.txt……）：不是交易程序。
///
/// **后缀是唯一判据，不要求文件现在就在盘上**（也不查 `.lnk` 的目标是否存在）。
/// 理由：`.lnk` 里存的是别的程序写下的字符串，程序可能刚被挪走、可能装在暂时没连上的盘上，
/// 而这一页本来就有「确认程序位置…」这条修复入口来收拾这种情况——填进去的是一条**可修**的
/// 路径；不填则是把用户「明明拖进来了却毫无反应」堵死，还得逼他手动浏览去指一个他刚拖过的
/// 程序。反过来，在这里判「不存在」等于把「这个快捷方式有程序、只是此刻摸不到」说成
/// 「找不到可用的程序」——那是错误的自述。
///
/// 真会返回 `None`（宿主据此「不填 + 明确提示」）的只有三种：
/// 后缀既不是 `.exe` 也不是 `.lnk`；`.lnk` 解析失败（含 `GetPath` 返回空串的 URL/特殊目标）；
/// 解析出的目标后缀不是 `.exe`（文件夹、.bat……）。
pub fn executable_target(path: &Path) -> Option<PathBuf> {
    if is_program(path) {
        return Some(path.to_path_buf());
    }
    if !is_shortcut(path) {
        return None;
    }
    link_target(path).filter(|target| is_program(target))
}

/// 这是不是一个桌面快捷方式。宿主用它决定「换不出程序时要不要吭声」：
/// 拖的是快捷方式而没反应，用户只会看到「拖了没用」。
pub fn is_shortcut(path: &Path) -> bool {
    has_extension(path, "lnk")
}

/// 「是不是程序」= 后缀 `.exe`（大小写不敏感）。**不碰文件系统**：见
/// [`executable_target`] 里「后缀是唯一判据」的原因。
fn is_program(path: &Path) -> bool {
    has_extension(path, "exe")
}

fn has_extension(path: &Path, wanted: &str) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(wanted))
}

/// 快捷方式指向的目标，原样交回——**不判断它是不是文件、也不查它在不在**。
///
/// 用**默认 flags**，不用 `SLGP_RAWPATH`：本机桌面上的 `Mirasim.lnk` 里同时存了绝对路径
/// 和带环境变量的形式，`SLGP_RAWPATH` 拿到的是 `%USERPROFILE%\…` 那种没展开的原始串——
/// 那不是可用路径，还得自己展开环境变量。默认 flags 让 Shell 展开，拿到的就是资源管理器
/// 双击时会用的那一条。
#[cfg(windows)]
fn link_target(path: &Path) -> Option<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Com::STGM_READ;

    with_shell_link(|link, persist| {
        let file = wide(path)?;
        unsafe { persist.Load(PCWSTR(file.as_ptr()), STGM_READ) }.ok()?;
        // 空串 = 不是文件类快捷方式（URL/特殊目标）：`link_path` 会给出 None，
        // 于是走「不填 + 明确提示」那条路，而不是把一个空路径填进输入框。
        unsafe { link_path(link, 0) }
    })
}

#[cfg(not(windows))]
fn link_target(_path: &Path) -> Option<PathBuf> {
    // 没有 Shell 就没有别的读法：宁可给 None（调用方会提示），也不去猜二进制格式。
    None
}

/// 建一个 ShellLink 对象、初始化 COM、跑完 `body` 再配对释放。
///
/// COM 初始化在这里做而不是甩给调用方：拖放回调跑在 UI 线程，wry 已经 `OleInitialize`
/// 过（单线程套间），再要一次会拿到 `S_FALSE`（引用计数 +1，必须配对 `CoUninitialize`）；
/// 换成 MTA 的线程则回 `RPC_E_CHANGED_MODE`——两种都说明「COM 可用」，只有别的失败才算
/// 解析失败。整套流程不上 panic：这里失败的正确后果是「这次拖放没识别出来」。
#[cfg(windows)]
fn with_shell_link<T>(body: impl FnOnce(&IShellLinkW, &IPersistFile) -> Option<T>) -> Option<T> {
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};

    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let balance = hr.is_ok();
    if hr.is_err() && hr != RPC_E_CHANGED_MODE {
        return None;
    }
    let answer = match unsafe { create_shell_link() } {
        Some((link, persist)) => body(&link, &persist),
        None => None,
    };
    if balance {
        unsafe { CoUninitialize() };
    }
    answer
}

#[cfg(windows)]
type IShellLinkW = windows::Win32::UI::Shell::IShellLinkW;
#[cfg(windows)]
type IPersistFile = windows::Win32::System::Com::IPersistFile;

#[cfg(windows)]
unsafe fn create_shell_link() -> Option<(IShellLinkW, IPersistFile)> {
    use windows::core::{Interface, IUnknown, GUID};
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    // `windows` 没有生成这个 coclass（它不是 metadata 里的 WinRT 类），所以写常量：
    // CLSID_ShellLink = {00021401-0000-0000-C000-000000000046}。
    const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x0002_1401_0000_0000_c000_0000_0000_0046);
    let link: IShellLinkW =
        CoCreateInstance(&CLSID_SHELL_LINK, None::<&IUnknown>, CLSCTX_INPROC_SERVER).ok()?;
    let persist: IPersistFile = link.cast().ok()?;
    Some((link, persist))
}

#[cfg(windows)]
unsafe fn link_path(link: &IShellLinkW, flags: u32) -> Option<PathBuf> {
    // 64 KiB 个 UTF-16 单位：长路径 + 带环境变量的原始值都够。`GetPath` 自己按传入长度截断。
    let mut buffer = vec![0u16; 32 * 1024];
    // 第二个参数是 `WIN32_FIND_DATAW`：传 null 才不去碰那个结构（我们只要路径）。
    link.GetPath(&mut buffer, std::ptr::null_mut(), flags).ok()?;
    let len = buffer.iter().position(|&unit| unit == 0)?;
    if len == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
}

/// 路径 → 以 0 结尾的 UTF-16。用 `OsStrExt` 而不是 `to_string_lossy`：路径里的
/// 非 UTF-16 部分在往返中会被替换成 U+FFFD，那就变成另一个文件了。
#[cfg(windows)]
fn wide(path: &Path) -> Option<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.is_empty() {
        return None;
    }
    units.push(0);
    Some(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-shortcut-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("desktop")).unwrap();
        std::fs::create_dir_all(p.join("start")).unwrap();
        p
    }

    /// 造一个「够大」的假 .lnk：内容不重要，大小与存在性才是被测对象。
    fn fake_lnk(path: &Path, size: usize) {
        std::fs::write(path, vec![b'L'; size]).unwrap();
    }

    #[test]
    fn copies_the_start_menu_shortcut_when_the_desktop_has_none() {
        let root = tmp("create");
        let source = root.join("start").join(LNK_NAME);
        fake_lnk(&source, 1_919);
        let desktop = root.join("desktop");
        assert_eq!(ensure_with(&desktop, &source).unwrap(), Outcome::Created);
        let created = desktop.join(LNK_NAME);
        assert!(created.is_file());
        assert_eq!(std::fs::metadata(&created).unwrap().len(), 1_919);
        // 内容逐字节相同：复制的是同一份 .lnk，不是重新拼的。
        assert_eq!(std::fs::read(&created).unwrap(), std::fs::read(&source).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn never_overwrites_an_existing_desktop_shortcut() {
        let root = tmp("keep");
        let source = root.join("start").join(LNK_NAME);
        fake_lnk(&source, 1_919);
        let desktop = root.join("desktop");
        let existing = desktop.join(LNK_NAME);
        // 用户自己那份（比如手工改过目标）：不许被动。
        std::fs::write(&existing, b"user-owned").unwrap();
        assert_eq!(ensure_with(&desktop, &source).unwrap(), Outcome::AlreadyThere);
        assert_eq!(std::fs::read(&existing).unwrap(), b"user-owned");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refuses_a_truncated_start_menu_copy_instead_of_installing_a_dead_icon() {
        let root = tmp("tiny");
        let source = root.join("start").join(LNK_NAME);
        fake_lnk(&source, 10);
        let desktop = root.join("desktop");
        let err = ensure_with(&desktop, &source).unwrap_err();
        assert!(err.contains("不完整"), "{err}");
        assert!(!desktop.join(LNK_NAME).exists(), "不合格的来源不许留下半份文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reports_a_clear_error_when_the_source_is_missing() {
        let root = tmp("missing");
        let desktop = root.join("desktop");
        let err = ensure_with(&desktop, &root.join("start").join(LNK_NAME)).unwrap_err();
        assert!(err.contains("读不到"), "{err}");
        assert!(!desktop.join(LNK_NAME).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn messages_say_what_actually_happened() {
        assert!(Outcome::Created.message().contains("已在桌面创建"));
        // 已存在时必须给下一步（删掉再点），否则用户面对「没反应」的图标没有出路。
        assert!(Outcome::AlreadyThere.message().contains("删掉"));
    }

    /// Shell 那一支至少要**答得出一个真实存在的目录**。本机注册表里的桌面值是
    /// `%USERPROFILE%\Desktop`（按进程环境展开），所以它和回退路径天然等价——这一条证明不了
    /// 「绝对路径重定向也跟得上」，但能抓住指针读错、忘记释放前就取串这类会直接退化成 None 的错误。
    #[cfg(windows)]
    #[test]
    fn shell_answers_an_existing_desktop_folder() {
        let path = shell_desktop().expect("SHGetKnownFolderPath 应能回答桌面位置");
        assert!(path.is_dir(), "{}", path.display());
        assert!(path.is_absolute(), "{}", path.display());
        // 桌面上一定有的东西：本机用户的桌面不会是盘符根。
        assert!(path.parent().is_some(), "{}", path.display());
    }

    // -----------------------------------------------------------------------
    // r101 拖放识别：`.exe` 直通 / `.lnk` 换成它指向的程序
    // -----------------------------------------------------------------------

    /// 造一个「程序」：解析侧不看内容，只要求后缀是 `.exe`、文件真的在。
    fn fake_exe(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"MZ").unwrap();
        path
    }

    /// 现场用 Shell 生成一个 .lnk：不提交二进制 fixture，也不依赖本机任何现成路径
    /// （否则测试在别人机器上会因为「那个程序没装」而红得莫名其妙）。
    #[cfg(windows)]
    fn save_link(lnk: &Path, target: &Path) {
        use windows::core::PCWSTR;
        let saved = with_shell_link(|link, persist| {
            let target = wide(target)?;
            let file = wide(lnk)?;
            unsafe {
                link.SetPath(PCWSTR(target.as_ptr())).ok()?;
                persist.Save(PCWSTR(file.as_ptr()), true).ok()?;
            }
            Some(())
        });
        assert!(saved.is_some(), "造不出测试用快捷方式：{}", lnk.display());
        assert!(lnk.is_file(), "{}", lnk.display());
    }

    #[test]
    fn an_exe_path_is_used_as_is() {
        let root = tmp("exe-direct");
        let exe = fake_exe(&root.join("app"), "NinjaTrader.exe");
        assert_eq!(executable_target(&exe).as_deref(), Some(exe.as_path()));
        // 大小写不是判据：拖进来的路径由资源管理器给，后缀大小写不可控。
        assert!(is_program(Path::new(r"C:\Apps\TRADER.EXE")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn anything_that_is_not_a_program_is_rejected() {
        let root = tmp("not-program");
        let bat = root.join("run.bat");
        std::fs::write(&bat, b"@echo off").unwrap();
        assert_eq!(executable_target(&bat), None);
        assert_eq!(executable_target(&root.join("app")), None, "文件夹不是程序");
        assert_eq!(executable_target(&root.join("notes.txt")), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_shortcut_is_replaced_by_the_program_it_points_at() {
        let root = tmp("lnk-target");
        // 目录与文件名都带空格：与真实安装路径同形，顺带盯住「路径被截断」这类错。
        let exe = fake_exe(
            &root.join("Program Files").join("Mirasim"),
            "Mirasim Terminal.exe",
        );
        let lnk = root.join("desktop").join("Mirasim.lnk");
        save_link(&lnk, &exe);
        // 填进去的必须是**目标 exe**，不是 .lnk（配置要拿去匹配进程）。
        assert_eq!(executable_target(&lnk).as_deref(), Some(exe.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_shortcut_to_something_that_is_not_an_exe_yields_nothing() {
        let root = tmp("lnk-not-exe");
        let bat = root.join("start.bat");
        std::fs::write(&bat, b"@echo off").unwrap();
        let bat_lnk = root.join("desktop").join("start.lnk");
        save_link(&bat_lnk, &bat);
        assert_eq!(executable_target(&bat_lnk), None);
        // 指向文件夹的快捷方式也一样：那是「打开这个目录」，不是一个交易程序。
        let folder = root.join("Torrent Folder");
        std::fs::create_dir_all(&folder).unwrap();
        let folder_lnk = root.join("desktop").join("folder.lnk");
        save_link(&folder_lnk, &folder);
        assert_eq!(executable_target(&folder_lnk), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_shortcut_whose_target_is_gone_still_hands_over_the_path_it_stored() {
        let root = tmp("lnk-gone");
        let lnk = root.join("desktop").join("Removed.lnk");
        // 目标故意不创建：快捷方式里存的就是一条路径，程序被挪走/还没装上都不改变
        // 「用户想加的是它」这件事。填进去的路径后面还能用「确认程序位置」改，
        // 而在这里判「不存在」会把它误说成「找不到可用的程序」。
        let target = root.join("gone").join("Removed.exe");
        save_link(&lnk, &target);
        assert_eq!(executable_target(&lnk).as_deref(), Some(target.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn an_unreadable_shortcut_yields_nothing_instead_of_panicking() {
        let root = tmp("lnk-broken");
        let lnk = root.join("desktop").join("broken.lnk");
        std::fs::write(&lnk, b"not a real shortcut").unwrap();
        assert_eq!(executable_target(&lnk), None);
        // 扩展名对、文件是空的：同一条路（解析失败 → 交给调用方提示）。
        let empty = root.join("desktop").join("empty.lnk");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(executable_target(&empty), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
