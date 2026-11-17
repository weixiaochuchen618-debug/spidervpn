//! SEC-03: install-time trust boundary for the shipped client and engine.
//!
//! Only the Rust installer action writes/decides Windows DACLs. PowerShell is
//! a thin packaging entry point. We do not alter the user's data-root path,
//! UI, connection state machine or WFP persistent BLOCK rules.
//!
//! This layer is deliberately not a signature/origin guarantee: a hostile
//! package, an already-running attacker holding file handles, or an
//! administrator can still replace content. Live A/B/C account and upgrade
//! acceptance is mandatory before SEC-03 can be closed.

#![cfg(windows)]

use std::path::{Component, Path};

// Explicit OWNER RIGHTS RX prevents a non-admin legacy directory owner
// retaining implicit WRITE_DAC after a formerly loose directory is sealed.
// BUILTIN\Users gets read/traverse/execute, never create/write/delete.
const CODE_DIR_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;OW)";
const CODE_FILE_SDDL: &str =
    "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;OW)";
// Untrusted preferences/runtime records remain in C:\SpiderVPN\data.
// Never inherit the protected code directory's read-only ACL into data.
// Secret-bearing files inside data still use secretfile.rs private DACLs.
const DATA_DIR_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)";

const ROOT_FILES: &[&str] = &[
    "启动SpiderVPN.cmd",
    "以管理员身份启动SpiderVPN.cmd",
    "卸载SpiderVPN.cmd",
    "uninstall.ps1",
    "用户速查.md",
];
const BIN_FILES: &[&str] = &[
    "spidervpn.exe",
    "sing-box.exe",
    "WebView2Loader.dll",
    "sing-box.LICENSE.txt",
];

/// Admin-only entry used before AND after copying the verified package.
/// A production binary must not be used as a general-purpose ACL editor:
/// the install root is fixed by the existing isolation contract.
pub fn seal_installed_product(target: &Path) -> Result<(), String> {
    if !crate::probe::is_elevated() {
        return Err("安全安装需要管理员权限：请以管理员身份运行 SpiderVPN 安装器".into());
    }
    if !cfg!(debug_assertions)
        && !target.to_string_lossy().eq_ignore_ascii_case(crate::isolation::Rewrite::INSTALL_DIR)
    {
        return Err("正式版只支持 C:\\SpiderVPN 可信安装目录，拒绝重定向受保护 ACL".into());
    }
    seal_layout(target)
}

fn check_target(target: &Path) -> Result<(), String> {
    // Reject drive roots, UNC, and lexical escapes; do not turn this
    // privileged operation into a generic recursive chmod.
    use std::path::Prefix;
    if target.to_string_lossy().split(['\\', '/']).any(|s| s == "." || s == "..") {
        return Err("安装路径不能包含 . 或 ..".into());
    }
    let mut components = target.components();
    match (components.next(), components.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir))
            if matches!(prefix.kind(), Prefix::Disk(_)) => {}
        _ => return Err("安装根必须是本机磁盘上的绝对路径".into()),
    }
    let rest: Vec<_> = components.collect();
    if rest.is_empty() || rest.iter().any(|c| !matches!(c, Component::Normal(_))) {
        return Err("安装根不能是卷根或包含 . / .. 路径跳转".into());
    }
    Ok(())
}

fn no_reparse(path: &Path) -> Result<(), String> {
    use crate::guard::identity::{reparse_chain, IdentityEnv};
    let env = crate::guard::wfp_win::SystemIdentityEnv::new();
    for part in reparse_chain(path) {
        // Missing final component is allowed BEFORE atomic CreateDirectoryW,
        // but a dangling symlink is present in symlink_metadata and rejected.
        match std::fs::symlink_metadata(&part) {
            Ok(_) if env.is_reparse_point(&part) => {
                return Err(format!("可信安装路径存在目录联接/重解析点：{}", part.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("无法验证路径 {}：{e}", part.display())),
        }
    }
    Ok(())
}

fn directory(path: &Path, sddl: &str) -> Result<(), String> {
    no_reparse(path)?;
    let meta = std::fs::symlink_metadata(path);
    match meta {
        Ok(m) if m.file_type().is_dir() => {
            protect(path, sddl)?;
        }
        Ok(_) => return Err(format!("安装目录并非真实目录：{}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_protected_dir(path, sddl)?;
        }
        Err(e) => return Err(format!("无法检查安装目录 {}：{e}", path.display())),
    }
    no_reparse(path)?;
    verify(path, sddl)
}

fn no_external_hardlinks(path: &Path) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let file = std::fs::File::open(path)
        .map_err(|e| format!("无法打开安装文件 {}：{e}", path.display()))?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(format!("无法核验安装文件硬链接数量 {}：{}",
            path.display(), std::io::Error::last_os_error()));
    }
    if info.nNumberOfLinks != 1 {
        return Err(format!("安装代码文件存在外部硬链接 {}，拒绝以管理员身份覆盖",
            path.display()));
    }
    Ok(())
}

fn seal_file(path: &Path) -> Result<(), String> {
    no_reparse(path)?;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("无法检查安装文件 {}：{e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("安装文件必须是常规文件：{}", path.display()));
    }
    no_external_hardlinks(path)?;
    protect(path, CODE_FILE_SDDL)?;
    no_reparse(path)?;
    verify(path, CODE_FILE_SDDL)
}

/// Preserve the installer's original layout and user-visible launchers.
/// Unknown binaries in the code directory are a refusal, not silently
/// deleted or accepted as DLL search-path candidates.
pub fn seal_layout(root: &Path) -> Result<(), String> {
    check_target(root)?;
    let bin = root.join("bin");
    directory(root, CODE_DIR_SDDL)?;
    directory(&bin, CODE_DIR_SDDL)?;

    let data = root.join("data");
    no_reparse(&data)?;
    // On a legacy installation preserve existing data ACLs and contents;
    // a fresh install explicitly grants the existing non-admin write model.
    if !data.exists() {
        directory(&data, DATA_DIR_SDDL)?;
    } else if !std::fs::symlink_metadata(&data)
        .map_err(|e| e.to_string())?.file_type().is_dir()
    {
        return Err("现有 data 路径不是实体目录；拒绝安装".into());
    }

    for entry in std::fs::read_dir(&bin)
        .map_err(|e| format!("读取代码目录失败：{e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !BIN_FILES.iter().any(|known| name.eq_ignore_ascii_case(known)) {
            return Err(format!(
                "代码目录存在未知文件/目录 {}；请先核实其来源，安全安装不会自动删除",
                entry.path().display()
            ));
        }
        seal_file(&entry.path())?;
    }
    for name in ROOT_FILES {
        let path = root.join(name);
        if path.exists() {
            seal_file(&path)?;
        }
    }
    // Read back all known code objects after modifications. A silently
    // failed security API call must never be reported as protected.
    verify(root, CODE_DIR_SDDL)?;
    verify(&bin, CODE_DIR_SDDL)?;
    for name in BIN_FILES {
        let path = bin.join(name);
        if path.exists() { verify(&path, CODE_FILE_SDDL)?; }
    }
    for name in ROOT_FILES {
        let path = root.join(name);
        if path.exists() { verify(&path, CODE_FILE_SDDL)?; }
    }
    Ok(())
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(Some(0)).collect()
}

fn with_sddl<T>(
    sddl: &str,
    op: impl FnOnce(*mut core::ffi::c_void) -> Result<T, String>,
) -> Result<T, String> {
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    let s: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
        s.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()
    ) } == 0 {
        return Err(format!("创建安装 DACL 失败：{}", std::io::Error::last_os_error()));
    }
    let result = op(sd);
    unsafe { LocalFree(sd as HLOCAL); }
    result
}

fn create_protected_dir(path: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let name = wide(path.as_os_str());
    with_sddl(sddl, |sd| {
        let attr = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(name.as_ptr(), &attr) } == 0 {
            Err(format!("创建受保护安装目录 {} 失败：{}", path.display(), std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    })
}

fn protect(path: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    let name = wide(path.as_os_str());
    with_sddl(sddl, |sd| {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0
            || present == 0 || dacl.is_null()
        {
            return Err("安装 DACL 内部格式无效".into());
        }
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(), std::ptr::null_mut(),
                dacl, std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(format!("设置安装对象 DACL {} 失败：Win32 {}", path.display(), status));
        }
        Ok(())
    })
}

fn actual_sddl(path: &Path) -> Result<String, String> {
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, ConvertSecurityDescriptorToStringSecurityDescriptorW,
        SE_FILE_OBJECT, SDDL_REVISION_1,
    };
    let name = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe { GetNamedSecurityInfoW(
        name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(), std::ptr::null_mut(),
        std::ptr::null_mut(), std::ptr::null_mut(), &mut sd
    ) };
    if status != 0 || sd.is_null() {
        return Err(format!("读回安装 DACL {} 失败：Win32 {}", path.display(), status));
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    let mut len = 0;
    let ok = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut text, &mut len
    ) };
    if ok == 0 || text.is_null() {
        unsafe {
            if !text.is_null() { LocalFree(text as HLOCAL); }
            LocalFree(sd as HLOCAL);
        }
        return Err(format!("安装对象 DACL 格式化失败：{}", path.display()));
    }
    let actual = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len as usize))
            .trim_end_matches('\0').to_owned()
    };
    unsafe { LocalFree(text as HLOCAL); LocalFree(sd as HLOCAL); }
    Ok(actual)
}

/// Windows adds AI to an already-protected DACL during an ACL rewrite.
/// Only this control-bit representation is allowed to differ; ACEs may not.
fn same_protected_acl(got: &str, expected: &str) -> bool {
    if got == expected {
        return true;
    }
    match (got.strip_prefix("D:PAI"), expected.strip_prefix("D:P")) {
        (Some(actual_aces), Some(expected_aces)) => actual_aces == expected_aces,
        _ => false,
    }
}

/// Intentionally require an exact, protected allowlist: no inherited or
/// additional write ACE, no inherited owner full control, and no NULL DACL.
fn verify(path: &Path, expected: &str) -> Result<(), String> {
    let got = actual_sddl(path)?;
    // SetNamedSecurityInfoW can mark a protected DACL "AI" (auto-inherit
    // machinery has processed it). D:PAI is still protected; "AI" does
    // not add an ACE. Compare every ACE byte-for-byte, never accept a
    // standalone D:AI, inherited ACE, extra SID or broader mask.
    if !same_protected_acl(&got, expected) {
        return Err(format!(
            "安装权限不符合受保护 ACL；对象 {}，期望 {expected}，实际 {got}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "tcrs-sec03-{tag}-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn fresh_install_protects_code_and_keeps_data_writable() {
        let path = root("fresh");
        seal_layout(&path).expect("must create protected code and writable data");
        assert!(path.join("bin").is_dir());
        assert!(path.join("data").is_dir());
        verify(&path, CODE_DIR_SDDL).unwrap();
        verify(&path.join("bin"), CODE_DIR_SDDL).unwrap();
        verify(&path.join("data"), DATA_DIR_SDDL).unwrap();
        let config = path.join("data").join("config.json");
        std::fs::write(&config, r#"{"mode":"proxy"}"#).unwrap();
        assert!(std::fs::read_to_string(config).unwrap().contains("proxy"));
        seal_layout(&path).expect("idempotent, no data wipe");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn legacy_wide_bin_acl_is_closed_and_files_are_verified() {
        let path = root("legacy");
        let bin = path.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let code = bin.join("sing-box.exe");
        std::fs::write(&code, b"fake binary").unwrap();
        let output = std::process::Command::new("icacls")
            .arg(&bin).arg("/grant").arg("*S-1-5-11:(OI)(CI)(M)")
            .output().expect("icacls");
        assert!(output.status.success(), "failed to seed loose ACL: {:?}",
            String::from_utf8_lossy(&output.stderr));
        assert!(verify(&bin, CODE_DIR_SDDL).is_err(), "insecure bin must fail before seal");
        seal_layout(&path).unwrap();
        verify(&bin, CODE_DIR_SDDL).unwrap();
        verify(&code, CODE_FILE_SDDL).unwrap();
        assert!(std::fs::read(&code).unwrap() == b"fake binary");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unexpected_binary_in_bin_is_a_hard_error_not_deleted() {
        let path = root("unknown");
        let bin = path.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let extra = bin.join("evil.dll");
        std::fs::write(&extra, b"not allowed").unwrap();
        assert!(seal_layout(&path).is_err(), "unknown DLL must not be tolerated");
        assert!(extra.exists(), "do not silently delete user files");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn preexisting_engine_hardlink_is_rejected_without_overwriting_source() {
        let path = root("hardlink");
        let bin = path.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let outside = path.join("outside-engine.exe");
        std::fs::write(&outside, b"do not overwrite this external file").unwrap();
        let alias = bin.join("sing-box.exe");
        std::fs::hard_link(&outside, &alias).unwrap();
        assert!(no_external_hardlinks(&alias).is_err());
        assert!(seal_layout(&path).is_err(), "hard-linked engine must fail closed");
        assert_eq!(std::fs::read(&outside).unwrap(),
            b"do not overwrite this external file");
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn windows_auto_inheritance_control_bit_never_broadens_code_dacl() {
        let without_prefix = CODE_DIR_SDDL.strip_prefix("D:P").unwrap();
        let ai = format!("D:PAI{without_prefix}");
        assert!(same_protected_acl(CODE_DIR_SDDL, CODE_DIR_SDDL));
        assert!(same_protected_acl(&ai, CODE_DIR_SDDL));
        for invalid in [
            format!("D:AI{without_prefix}"),
            format!("D:PAI{without_prefix}(A;;FA;;;AU)"),
            format!("D:PAI{without_prefix}(A;;FA;;;WD)"),
            format!("D:PAI{without_prefix}(A;;FA;;;OW)"),
            format!("D:P(A;;FA;;;AU)"),
        ] {
            assert!(!same_protected_acl(&invalid, CODE_DIR_SDDL),
                "must reject unprotected/added privilege: {invalid}");
        }
    }

    #[test]
    fn path_traversal_and_volume_root_are_rejected() {
        for path in [r"C:\", r"C:\SpiderVPN\..", r"\\server\share\SpiderVPN",
                     r"C:\SpiderVPN\.\bin", r"relative\SpiderVPN"] {
            assert!(check_target(Path::new(path)).is_err(), "{path}");
        }
    }
}
