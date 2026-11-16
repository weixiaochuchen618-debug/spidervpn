//! 名单身份解析（`guard::identity`）的全分支验证。
//!
//! 这些用例**在普通权限下可自动跑完**，因为身份解析的核心是纯逻辑 + 一个可注入的
//! [`IdentityEnv`]。文件系统部分用真实临时目录（`std::fs`），reparse point 用
//! 真实符号链接/目录联接；「appId 解析」用假环境（真实现要走 WFP RPC，属于 T03 的手工项）。
//!
//! 为什么值得这么细：身份解析错了，保护就是「保护了另一个程序，真正要保护的那个照样裸奔」。
//! 尤其是「老条目只有 exe 名」这种情况——**绝不能**去磁盘上按名字搜索（PRD P0-9 / 架构 A-5）。

#[path = "../src/guard/identity.rs"]
mod identity;

use std::path::{Path, PathBuf};

use identity::{
    device_path_from_app_id, has_exe_extension, is_absolute_path, reparse_chain, resolve_all,
    resolve_all_light, resolve_entry, resolve_entry_light, EntryRef, IdentityEnv, IdentityError,
    MAX_PROGRAMS,
};

/// 临时目录夹具：名字带 pid，避免并行用例互相踩。
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("tcrs-guard-id-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("建临时目录");
        Dir(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// 造一个「看起来像 exe」的普通文件。身份解析不读内容，只读路径与属性。
    fn exe(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, b"MZ").expect("写夹具文件");
        p
    }

    fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).expect("建子目录");
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 真实文件系统 + 可控的 appId（appId 那一步是 WFP RPC，这里是集成测试不该碰的东西）。
struct RealFs {
    fail_app_id: Vec<String>,
}

impl RealFs {
    fn new() -> RealFs {
        RealFs { fail_app_id: Vec::new() }
    }

    fn failing(mut self, path: &Path) -> RealFs {
        self.fail_app_id.push(path.to_string_lossy().to_lowercase());
        self
    }
}

impl IdentityEnv for RealFs {
    fn exists(&self, path: &Path) -> bool {
        match std::fs::metadata(path) {
            Ok(m) => m.is_file(),
            Err(_) => false,
        }
    }

    fn is_reparse_point(&self, path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Ok(m) => m.file_type().is_symlink(),
            Err(_) => false,
        }
    }

    fn app_id(&self, path: &Path) -> Result<Vec<u8>, IdentityError> {
        if self.fail_app_id.iter().any(|f| *f == path.to_string_lossy().to_lowercase()) {
            return Err(IdentityError::AppIdFailed);
        }
        // 造一份与真实现同形的 appId：`\device\harddiskvolume3\...` + NUL，UTF-16LE。
        // **小写**是刻意的：`FwpmGetAppIdFromFileName0` 返回的就是规范化后的小写 device path
        // （实测 `\\device\\harddiskvolume3\\windows\\system32\\cmd.exe`），去重靠的正是这一点。
        let text = format!(
            "\\device\\harddiskvolume3{}",
            path.to_string_lossy().replace(':', "").to_lowercase()
        );
        Ok(text.encode_utf16().chain(std::iter::once(0u16)).flat_map(|u| u.to_le_bytes()).collect())
    }
}

#[test]
fn pure_checks_cover_the_edge_cases() {
    assert!(is_absolute_path("C:\\Program Files\\T\\Trader.exe"));
    assert!(is_absolute_path("\\\\server\\share\\trader.exe"), "UNC 也是绝对路径");
    assert!(!is_absolute_path("Trader.exe"));
    assert!(!is_absolute_path(".\\Trader.exe"));
    assert!(!is_absolute_path("C:Trader.exe"), "盘符相对不是绝对路径");
    assert!(!is_absolute_path("  "));

    assert!(has_exe_extension("C:\\a\\b.EXE"));
    assert!(!has_exe_extension("C:\\a\\b.dll"));
    assert!(!has_exe_extension("C:\\a\\b.exe.tmp"));

    let chain: Vec<String> = reparse_chain(Path::new("C:\\a\\b\\c.exe"))
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    assert_eq!(chain, vec!["C:\\a", "C:\\a\\b", "C:\\a\\b\\c.exe"], "必须逐级，且不含盘符本身");
}

#[test]
fn a_real_exe_resolves_with_identity_and_device_path() {
    let dir = Dir::new("ok");
    let exe = dir.exe("trader.exe");
    let env = RealFs::new();
    let id = resolve_entry("trader.exe", Some(&exe.to_string_lossy()), &env).expect("应当解析成功");
    assert_eq!(id.name, "trader.exe");
    assert_eq!(id.path, exe);
    assert!(!id.app_id.is_empty());
    assert!(id.device_path.to_lowercase().contains("trader.exe"));
    // device path 是 UTF-16 解出来的，不该带 NUL
    assert!(!id.device_path.contains('\0'));
}

#[test]
fn old_entries_without_a_path_are_never_guessed() {
    let dir = Dir::new("old");
    dir.exe("trader.exe"); // 即使同名文件就在附近，也不许被「猜」到
    let env = RealFs::new();
    let err = resolve_entry("trader.exe", None, &env).unwrap_err();
    assert_eq!(err, IdentityError::MissingPath);
    assert!(err.reason().contains("不会去猜路径"));
    assert_eq!(resolve_entry_light("trader.exe", None, &env).unwrap_err(), IdentityError::MissingPath);
}

#[test]
fn every_failure_branch_is_covered() {
    let dir = Dir::new("fail");
    let exe = dir.exe("trader.exe");
    let dll = dir.exe("trader.dll");
    let env = RealFs::new().failing(&dir.path().join("broken.exe"));
    dir.exe("broken.exe");

    let rel = resolve_entry("t", Some("trader.exe"), &env).unwrap_err();
    assert_eq!(rel, IdentityError::NotAbsolute);
    let dll_err = resolve_entry("t", Some(&dll.to_string_lossy()), &env).unwrap_err();
    assert_eq!(dll_err, IdentityError::NotExe);
    let missing = dir.path().join("gone.exe");
    assert_eq!(
        resolve_entry("t", Some(&missing.to_string_lossy()), &env).unwrap_err(),
        IdentityError::NotFound
    );
    let app_id = resolve_entry("t", Some(&dir.path().join("broken.exe").to_string_lossy()), &env)
        .unwrap_err();
    assert_eq!(app_id, IdentityError::AppIdFailed);
    // 目录不是程序
    assert_eq!(
        resolve_entry("t", Some(&dir.sub("folder.exe").to_string_lossy()), &env).unwrap_err(),
        IdentityError::NotFound,
        "目录不能当程序身份"
    );
    // 每条原因都要能直接给用户看
    for e in [
        IdentityError::MissingPath,
        IdentityError::NotAbsolute,
        IdentityError::NotExe,
        IdentityError::NotFound,
        IdentityError::ReparsePoint,
        IdentityError::AppIdFailed,
        IdentityError::TooMany,
    ] {
        assert!(!e.reason().is_empty());
        assert!(!e.reason().contains("0x"));
        assert!(!e.id().is_empty());
    }
    // 成功的那条要真的成功（否则上面的失败断言可能是假阴性）
    assert!(resolve_entry("t", Some(&exe.to_string_lossy()), &env).is_ok());
}

#[cfg(windows)]
#[test]
fn a_real_symlink_is_rejected() {
    // 符号链接创建需要权限（Developer Mode 或管理员），拿不到就跳过——
    // 这条不是「必须绿」，而是「能造出来就一定要拒绝」。
    let dir = Dir::new("link");
    let target = dir.exe("real.exe");
    let link = dir.path().join("link.exe");
    let made = std::os::windows::fs::symlink_file(&target, &link).is_ok();
    if !made {
        eprintln!("跳过：本机不允许创建符号链接（这条是手工项）");
        return;
    }
    let env = RealFs::new();
    assert_eq!(
        resolve_entry("link.exe", Some(&link.to_string_lossy()), &env).unwrap_err(),
        IdentityError::ReparsePoint
    );
    // 父目录是链接也要拒
    let sub = dir.sub("real-sub");
    let inner = sub.join("inner.exe");
    std::fs::write(&inner, b"MZ").unwrap();
    let dirlink = dir.path().join("dir-link");
    if std::os::windows::fs::symlink_dir(&sub, &dirlink).is_ok() {
        let through = dirlink.join("inner.exe");
        assert_eq!(
            resolve_entry("inner.exe", Some(&through.to_string_lossy()), &env).unwrap_err(),
            IdentityError::ReparsePoint,
            "父目录是链接也要拒绝"
        );
    }
}

#[test]
fn resolve_all_keeps_reasons_and_counts_totals() {
    let dir = Dir::new("all");
    let good = dir.exe("good.exe");
    let good2 = dir.exe("good2.exe");
    let env = RealFs::new();
    let missing = dir.path().join("missing.exe");

    let good_s = good.to_string_lossy().to_string();
    let good2_s = good2.to_string_lossy().to_string();
    let missing_s = missing.to_string_lossy().to_string();
    let entries = [
        EntryRef::new("old.exe", None),
        EntryRef::new("good.exe", Some(good_s.as_str())),
        EntryRef::new("good2.exe", Some(good2_s.as_str())),
        EntryRef::new("missing.exe", Some(missing_s.as_str())),
    ];
    let out = resolve_all(&entries, &env);
    assert_eq!(out.total, 4, "TradeProgramCount 是名单条数，不是参与条数");
    assert_eq!(out.programs.len(), 2);
    assert_eq!(out.unresolved.len(), 2);
    assert!(!out.all_participated());
    assert_eq!(out.unresolved[0].reason_id, "MissingPath");
    assert_eq!(out.unresolved[1].reason_id, "NotFound");
    assert_eq!(out.unresolved[1].path.as_deref(), Some(missing_s.as_str()));

    // 轻量路径对同一份名单给出同样的「参与/不参与」结论
    let light = resolve_all_light(&entries, &env);
    assert_eq!(light.total, 4);
    assert_eq!(light.entries.len(), 2);
    assert_eq!(light.unresolved.len(), 2);
}

#[test]
fn duplicate_identities_are_deduplicated() {
    let dir = Dir::new("dup");
    let a = dir.exe("a.exe");
    let env = RealFs::new();
    // 同一路径写两遍（大小写不同）：只留一条，但 total 反映真实条数
    let lower = a.to_string_lossy().to_string();
    let upper = lower.to_uppercase();
    let entries = [
        EntryRef::new("a.exe", Some(lower.as_str())),
        EntryRef::new("A.EXE", Some(upper.as_str())),
    ];
    let out = resolve_all(&entries, &env);
    assert_eq!(out.programs.len(), 1, "同一 appId 只建一组规则");
    assert_eq!(out.total, 2);
    let light = resolve_all_light(&entries, &env);
    assert_eq!(light.entries.len(), 1, "轻量路径按路径去重（大小写不敏感）");
}

#[test]
fn the_64_entry_limit_is_reported_for_every_extra_entry() {
    let dir = Dir::new("limit");
    let env = RealFs::new();
    let mut paths: Vec<String> = Vec::new();
    for i in 0..(MAX_PROGRAMS + 2) {
        paths.push(dir.exe(&format!("p{i}.exe")).to_string_lossy().to_string());
    }
    let names: Vec<String> = (0..paths.len()).map(|i| format!("p{i}.exe")).collect();
    let entries: Vec<EntryRef<'_>> = names
        .iter()
        .zip(paths.iter())
        .map(|(n, p)| EntryRef::new(n.as_str(), Some(p.as_str())))
        .collect();
    let out = resolve_all(&entries, &env);
    assert_eq!(out.total, MAX_PROGRAMS + 2);
    assert_eq!(out.programs.len(), MAX_PROGRAMS);
    assert_eq!(out.unresolved.len(), 2);
    assert!(out.unresolved.iter().all(|u| u.reason_id == "TooMany"));
    assert!(out.unresolved[0].reason.contains(&MAX_PROGRAMS.to_string()));
}

#[test]
fn device_path_decoding_is_strict() {
    let ok: Vec<u8> = "\\device\\harddiskvolume3\\a.exe\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert_eq!(device_path_from_app_id(&ok), "\\device\\harddiskvolume3\\a.exe");
    assert_eq!(device_path_from_app_id(&[1, 2, 3]), "");
    assert_eq!(device_path_from_app_id(&[]), "");
    assert_eq!(device_path_from_app_id(&[0, 0]), "");
}

#[test]
fn light_resolution_never_touches_app_id() {
    let dir = Dir::new("light");
    let exe = dir.exe("trader.exe");
    // 让 appId 一定失败：轻量路径仍应成功（它不做那次 RPC）
    let env = RealFs::new().failing(&exe);
    assert!(resolve_entry("t", Some(&exe.to_string_lossy()), &env).is_err());
    let light = resolve_entry_light("t", Some(&exe.to_string_lossy()), &env).expect("轻量解析不该失败");
    assert_eq!(light.path, exe);
}
