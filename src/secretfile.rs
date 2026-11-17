//! 含秘密的文件（WireGuard 私钥）的落盘与访问收紧。
//!
//! 这台机器上有**三个**文件里躺着同一把私钥：
//!
//! - `servers\<id>\client.conf` —— `[Interface] PrivateKey`，引擎和 WireGuard 都要读；
//! - `servers\<id>\tunnel.key` —— `add_peer` 成功但 `client.conf` 还没写时的救命副本；
//! - `lines\<id>.json` —— sing-box 线路，WireGuard outbound 的 `private_key`。
//!
//! 任意一个被同机其他账户读走，别人就能冒充本设备接入服务器；能被改写，就能把本机
//! 的流量引到别处。这不是理论风险：`data` 目录建在安装目录下（不在用户目录里），
//! 继承到的是 `BUILTIN\Users:(RX)` + `NT AUTHORITY\Authenticated Users:(M)`。
//!
//! 原来那句「Windows 没有 POSIX 权限位，所以不必单独设 ACL」是错的，而且错得刚好
//! 相反：Unix 上的 `0600` 只在 `#[cfg(unix)]` 里，Windows 侧等于什么都没做。
//!
//! 两条硬要求：
//!
//! 1. **文件一出现就是紧的**：先建空临时文件、立刻设 DACL、再写内容。反过来会留下
//!    一个「内容已落盘、权限还没收」的窗口 —— 那时候别人抢到一个读句柄就够了。
//! 2. **已有文件也要收紧**：升级上来时私钥早就存在，新代码不会重写它们，所以启动时
//!    扫一遍。收紧是幂等的，扫描也是只读目录、不改内容。

use std::path::{Path, PathBuf};

/// 「只有本机管理员、SYSTEM 与文件所有者」能访问。
///
/// `P` = 受保护（不继承父目录的 ACE，否则 Users 那条会顺着继承链爬回来）；
/// `SY` = SYSTEM，`BA` = Administrators，`OW` = Owner Rights（当前所有者）。
///
/// 用 `OW` 而不是硬编码某个 SID：文件是哪个账户建的，那个账户就是所有者。管理员身份
/// 运行时创建的文件所有者是 `BUILTIN\Administrators`，`OW` 与 `BA` 两条都覆盖到。
const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

/// 原子创建私有的提权 IPC 目录与文件。
///
/// Windows 必须把受保护 DACL 作为 CreateDirectoryW/CreateFileW 的创建参数；
/// 旧的「先 create，再 SetNamedSecurityInfoW」存在可抢打开句柄的竞态窗口。
/// 其它平台只用于测试，不参与生产 Windows 提权。
#[cfg(windows)]
fn with_private_creation_attributes<T>(
    operation: impl FnOnce(&windows_sys::Win32::Security::SECURITY_ATTRIBUTES) -> std::io::Result<T>,
) -> std::io::Result<T> {
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    let sddl: Vec<u16> = OWNER_ONLY_SDDL.encode_utf16().chain(Some(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut(),
        )
    } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = operation(&attributes);
    unsafe { LocalFree(descriptor as HLOCAL); }
    result
}

/// 若已存在同名目录，必须失败；绝不进入攻击者提前准备的目录。
pub fn create_private_ipc_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        return with_private_creation_attributes(|attributes| {
            if unsafe { CreateDirectoryW(wide.as_ptr(), attributes) } == 0 {
                Err(std::io::Error::last_os_error())
            } else { Ok(()) }
        });
    }
    #[cfg(not(windows))]
    {
        std::fs::create_dir(path)?;
        protect_ipc_directory(path)
    }
}

/// 原子创建受保护的空请求/回执文件，供原权限用户与高权限子进程协作。
pub fn create_private_ipc_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_SHARE_DELETE,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        return with_private_creation_attributes(|attributes| {
            const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(), GENERIC_READ_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(unsafe { std::fs::File::from_raw_handle(handle) })
            }
        });
    }
    #[cfg(not(windows))]
    {
        let file = std::fs::OpenOptions::new().read(true).write(true)
            .create_new(true).open(path)?;
        if let Err(e) = tighten(path) { drop(file); let _ = std::fs::remove_file(path); return Err(e); }
        Ok(file)
    }
}

/// 创建后、写入任何提权请求前，保护一次性 Guard IPC 目录。
/// 默认 TEMP 下可能继承过宽的 ACE：禁止继承，只允许所有者、管理员与 SYSTEM。
pub fn protect_ipc_directory(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(std::io::Error::other("提权 IPC 目录必须是实体目录"));
    }
    #[cfg(windows)]
    { restrict(path) }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(any(windows, unix)))]
    { Err(std::io::Error::other("当前系统不支持受保护的 IPC 目录")) }
}

/// 原子写一个含秘密的文本文件：临时文件 → 收紧 → 写入 → 落盘 → 改名。
///
/// 失败时删掉临时文件，**不留半成品**。返回值由调用方决定文案（CLI 与界面各有各的措辞）。
pub fn write(path: &Path, text: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("路径无效"))?;
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|item| item.to_str())
        .unwrap_or("secret");
    let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    // 上次崩溃留下的同名临时文件：先清掉，否则 create_new 一定失败。
    let _ = std::fs::remove_file(&temp);

    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        // 收紧必须在写内容之前：此刻文件还是空的，别人即便抢到句柄也拿不到私钥。
        restrict(&temp)?;
        {
            use std::io::Write;
            file.write_all(text.as_bytes())?;
            file.write_all(b"\n")?;
            // 先落盘再改名：否则崩溃后可能得到一个名字正确、内容是空的文件。
            file.sync_all()?;
        }
        // Windows 上句柄没关就改名会失败，这里显式收掉。
        drop(file);
        std::fs::rename(&temp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// 把已有文件收紧到「只有本人/管理员/SYSTEM」。文件不存在视为成功（幂等）。
pub fn tighten(path: &Path) -> std::io::Result<()> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => restrict(path),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// 启动时扫一遍数据根，把**已经存在**的私钥文件收紧。
///
/// 返回失败的条目（人话），由调用方决定打印还是记日志。失败**不阻断启动**：文件可能
/// 属于别的账户、当前进程没有 `WRITE_DAC`，为此让用户连界面都进不去更糟。但也不能
/// 静默——漏掉的那一条就是仍然敞着的私钥。
pub fn tighten_data_root(root: &Path) -> Vec<String> {
    let mut targets: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(root.join("servers")) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            targets.push(dir.join("client.conf"));
            targets.push(dir.join(TUNNEL_KEY_FILE));
        }
    }

    if let Ok(entries) = std::fs::read_dir(root.join("lines")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|item| item.to_str()) == Some("json") {
                targets.push(path);
            }
        }
    }

    let mut failed = Vec::new();
    for path in targets {
        if let Err(error) = tighten(&path) {
            failed.push(format!("{}：{error}", path.display()));
        }
    }
    failed
}

/// 与 `servercmd::TUNNEL_KEY_FILE` 同一个名字。这里单独写一份，是为了让本模块不依赖
/// `servercmd`（`servercmd` 反过来要依赖本模块，反向引用会绕成环）。
const TUNNEL_KEY_FILE: &str = "tunnel.key";

#[cfg(windows)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl_wide: Vec<u16> = OWNER_ONLY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SD 里包着 DACL，`SetNamedSecurityInfoW` 要的是裸 DACL，先取出来。
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let read = unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
    };
    if read == 0 || present == 0 || dacl.is_null() {
        let error = if read == 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other("安全描述符里没有 DACL")
        };
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err(error);
    }

    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor as HLOCAL) };

    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(any(windows, unix)))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-secret-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 写进去的内容一字不差（末尾补一个换行），临时文件不留。
    #[test]
    fn a_written_secret_keeps_its_text_and_leaves_no_temp_file() {
        let dir = temp_dir("write");
        let path = dir.join("tunnel.key");
        write(&path, "abcdef").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abcdef\n");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "临时文件必须清理掉：{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 文件不存在不是错误：启动扫描会遍历一堆可能不存在的名字。
    #[test]
    fn tightening_a_missing_file_is_not_an_error() {
        let dir = temp_dir("missing");
        let path = dir.join("client.conf");
        assert!(tighten(&path).is_ok());
        assert!(!path.exists(), "收紧不许顺手创建文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 连收紧两次仍是成功（启动扫描每次开机都跑）。
    #[test]
    fn tightening_is_idempotent() {
        let dir = temp_dir("idem");
        let path = dir.join("tunnel.key");
        write(&path, "secret").unwrap();
        assert!(tighten(&path).is_ok());
        assert!(tighten(&path).is_ok());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn privileged_ipc_objects_have_secure_acl_at_creation() {
        let parent = temp_dir("ipc-atomic-parent");
        grant_test_inheritable_users_modify(&parent);
        let dir = parent.join("private");
        create_private_ipc_dir(&dir).unwrap();
        let req = dir.join("req.json");
        let reply = dir.join("res.json");
        let _req_handle = create_private_ipc_file(&req).unwrap();
        let _reply_handle = create_private_ipc_file(&reply).unwrap();
        assert!(create_private_ipc_dir(&dir).is_err());
        assert!(create_private_ipc_file(&req).is_err());
        for item in [&dir, &req, &reply] {
            let acl = dacl_sddl(item);
            assert!(acl.starts_with("D:P"), "must be protected from creation: {acl}");
            for principal in [";;;SY)", ";;;BA)", ";;;OW)"] {
                assert!(acl.contains(principal), "missing {principal}: {acl}");
            }
            assert!(!acl.contains(";;;AU)") && !acl.contains(";;;BU)"),
                "untrusted users must never receive an inherited ACE: {acl}");
        }
        drop(_req_handle);
        drop(_reply_handle);
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[cfg(windows)]
    #[test]
    fn privileged_ipc_directory_has_no_inherited_acl() {
        let dir = temp_dir("guard-ipc");
        protect_ipc_directory(&dir).unwrap();
        let acl = acl_of(&dir);
        assert!(!acl.contains("(I)"), "IPC 目录不允许继承其他账户写权限：{acl}");
        assert!(!acl.contains("Authenticated Users"), "{acl}");
        assert!(!acl.contains("BUILTIN\\Users"), "{acl}");
        let _ = std::fs::remove_dir(&dir);
    }

    /// 用 Win32 直接把受保护 DACL 读回为不依赖系统界面语言的 SDDL。
    /// 这比只检查 icacls 的 (I) 更严格：还核对不同管理员 UAC 所需的 BA、
    /// 原调用账户所需的 OW，以及本机 SYSTEM 的 SY。
    #[cfg(windows)]
    fn dacl_sddl(path: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };
        use windows_sys::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, ConvertSecurityDescriptorToStringSecurityDescriptorW,
            SE_FILE_OBJECT, SDDL_REVISION_1,
        };

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW failed for {}", path.display());
        assert!(!descriptor.is_null());

        let mut rendered: *mut u16 = std::ptr::null_mut();
        let mut len = 0u32;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                &mut rendered, &mut len,
            )
        };
        assert_ne!(ok, 0, "ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
        assert!(!rendered.is_null());
        let value = unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(rendered, len as usize))
        };
        unsafe {
            LocalFree(rendered as HLOCAL);
            LocalFree(descriptor as HLOCAL);
        }
        value
    }

    #[cfg(windows)]
    #[test]
    fn guard_ipc_dacl_explicitly_grants_original_owner_admins_and_system() {
        let dir = temp_dir("guard-cross-account");
        protect_ipc_directory(&dir).unwrap();
        let request = dir.join("req.json");
        let reply = dir.join("res.json");
        std::fs::File::create(&request).unwrap();
        std::fs::File::create(&reply).unwrap();
        tighten(&request).unwrap();
        tighten(&reply).unwrap();

        for item in [&dir, &request, &reply] {
            let acl = dacl_sddl(item);
            assert!(acl.starts_with("D:P"), "{} lacks protected DACL: {acl}", item.display());
            for principal in [";;;SY)", ";;;BA)", ";;;OW)"] {
                assert!(acl.contains(principal),
                    "{} missing {principal} on explicit DACL: {acl}", item.display());
            }
            assert!(!acl.contains(";;;AU)") && !acl.contains(";;;BU)"),
                "{} grants permissions to ordinary users: {acl}", item.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    fn acl_of(path: &Path) -> String {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .expect("icacls 必须可用（Windows 自带）");
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    /// 让测试自己的随机目录**显式拥有宽松可继承的旧版 ACL**。
    /// GitHub Windows Runner 的 %TEMP% 可能天然禁止继承，因此不能把
    /// "普通新建文件一定有 (I)" 当成测试前提。
    /// 仅用于临时测试目录，正式产品逻辑不会调用。
    #[cfg(windows)]
    fn grant_test_inheritable_users_modify(dir: &Path) {
        let output = std::process::Command::new("icacls")
            .arg(dir)
            .arg("/grant")
            .arg("*S-1-5-11:(OI)(CI)(M)")
            .output()
            .expect("Windows runner 必须提供 icacls");
        assert!(output.status.success(),
            "无法在隔离测试目录建立旧版宽松 ACL：{}",
            String::from_utf8_lossy(&output.stderr));
    }

    /// 新写的私钥文件：只有管理员/SYSTEM/所有者能碰，而且不再继承父目录的 ACE。
    ///
    /// 判据用「没有 `(I)`」而不是「没有 BUILTIN\Users」：父目录不同，继承来的组也不同
    /// （`%TEMP%` 下是几个未解析的能力 SID，现场数据根下才是 Users）。`(I)` 是继承标记，
    /// 受保护的 DACL 一条都不该有——这条判据在任何父目录下都成立。
    #[cfg(windows)]
    #[test]
    fn a_written_secret_is_readable_only_by_owner_admins_and_system() {
        let dir = temp_dir("acl");
        let path = dir.join("client.conf");
        write(&path, "PrivateKey = abc").unwrap();

        let acl = acl_of(&path);
        assert!(!acl.contains("(I)"), "不该有继承来的 ACE：\n{acl}");
        assert!(
            !acl.contains("BUILTIN\\Users"),
            "Users 不该在 ACL 里：\n{acl}"
        );
        assert!(
            !acl.contains("Authenticated Users"),
            "Authenticated Users 不该在 ACL 里：\n{acl}"
        );
        assert!(acl.contains("BUILTIN\\Administrators"), "{acl}");
        assert!(acl.contains("NT AUTHORITY\\SYSTEM"), "{acl}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 升级上来的文件（继承父目录的松 ACL）也能被收紧——这是 F1 的现场形态。
    #[cfg(windows)]
    #[test]
    fn tightening_closes_a_file_that_inherited_the_loose_acl() {
        let dir = temp_dir("tighten");
        // 真实构造旧版 Authenticated Users:(M) 继承权限，而非假定
        // Windows Runner 的用户 TEMP 目录本来就有松 ACL。
        grant_test_inheritable_users_modify(&dir);
        let path = dir.join("client.conf");
        std::fs::write(&path, "PrivateKey = abc").unwrap();
        let before = acl_of(&path);
        assert!(
            before.contains("(I)"),
            "前提：直接写出来的文件一定带继承 ACE\n{before}"
        );

        tighten(&path).unwrap();

        let after = acl_of(&path);
        assert!(
            !after.contains("(I)"),
            "收紧后不许剩下继承 ACE：\n{after}"
        );
        assert!(
            !after.contains("BUILTIN\\Users"),
            "收紧后 Users 必须消失：\n{after}"
        );
        assert!(
            !after.contains("Authenticated Users"),
            "收紧后 Authenticated Users 必须消失：\n{after}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "PrivateKey = abc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 数据根扫描覆盖三个落点，且不碰不含私钥的文件。
    #[cfg(windows)]
    #[test]
    fn the_root_scan_covers_all_three_private_key_files() {
        let root = temp_dir("root");
        // 创建受控的旧安装目录宽 ACL：确保四个文件**确实都**
        // 继承 Authenticated Users 的写权限，回归才有安全意义。
        grant_test_inheritable_users_modify(&root);
        let server = root.join("servers").join("9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        let lines = root.join("lines");
        std::fs::create_dir_all(&server).unwrap();
        std::fs::create_dir_all(&lines).unwrap();

        let conf = server.join("client.conf");
        let key = server.join("tunnel.key");
        let line = lines.join("81ea5efab7154128621517c5bb98fde63a5.json");
        let plain = root.join("config.json");
        for path in [&conf, &key, &line, &plain] {
            std::fs::write(path, "{}").unwrap();
        }

        let failed = tighten_data_root(&root);
        assert!(failed.is_empty(), "不该有失败：{failed:?}");

        for path in [&conf, &key, &line] {
            let acl = acl_of(path);
            assert!(!acl.contains("(I)"), "{} 没被收紧：\n{acl}", path.display());
            assert!(!acl.contains("Authenticated Users"),
                "{} 仍泄露给旧版宽松账户组：\n{acl}", path.display());
        }
        // config.json 不在私钥落点名单里：不收紧，也不该被创建/删除。
        let plain_acl = acl_of(&plain);
        assert!(
            plain_acl.contains("(I)"),
            "config.json 不该被一并收紧：\n{plain_acl}"
        );
        assert!(plain.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
