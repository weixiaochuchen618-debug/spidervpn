//! 隧道引擎的进程管理。
//!
//! 只做三件事：拉起、判定存活、停止。**不解释引擎的输出**——那是引擎自己的事，
//! 在这里解析日志只会让两边耦合，引擎换个版本就得改这里。
//!
//! 停止策略：先温和（taskkill 不带 /F，等于请求关闭），超时才强制。
//! 直接 /F 会让引擎来不及撤销自己的系统改动。

use crate::model::Probe;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct EngineConfig {
    pub binary: String,
    pub args: Vec<String>,
}

/// 拉起引擎后的句柄。只留 pid：存活判定统一走 `probe::pid_alive`，
/// 不在这里另养一个 Child——那会让「谁说得算」出现两套。
#[derive(Debug)]
pub struct EngineHandle {
    pub pid: i64,
}

impl EngineHandle {
    /// 引擎还活着吗。**只有测试在用**（生产一律 `probe::pid_alive`），所以只在测试构建里编译；
    /// 实现也直接走同一个探针，避免两套判定口径。
    #[cfg(test)]
    pub fn alive(&self) -> bool {
        crate::probe::pid_alive(self.pid)
    }
}

/// SEC-03 第一层边界：在**管理员** 模式下，低权限配置文件不得
/// 指定任意目录里的可执行文件来替换管理员将要启动的引擎。
///
/// 此检查仅锁定与 SpiderVPN 自身同目录的 `sing-box.exe`，不更改普通
/// 权限用户的代理模式；管理员身份无论 Proxy/TUN 都必须核对。
/// 它不是“安装目录安全”证明：若安装目录依旧可由
/// 普通用户改写，SEC-03 必须继续通过保护安装目录和 ACL 实机验收。
pub fn validate_privileged_engine(
    requested: &std::path::Path,
    frontend_executable: &std::path::Path,
) -> Result<(), String> {
    let bin_dir = frontend_executable.parent()
        .ok_or_else(|| "无法确认 SpiderVPN 主程序目录".to_string())?;
    let bundled = bin_dir.join("sing-box.exe");
    if !bundled.is_file() || !requested.is_file() {
        return Err("管理员 模式要求随包的 sing-box.exe 存在且是普通文件".into());
    }
    let trusted = std::fs::canonicalize(&bundled)
        .map_err(|e| format!("无法确认随包 sing-box.exe 身份：{e}"))?;
    let selected = std::fs::canonicalize(requested)
        .map_err(|e| format!("无法确认所选引擎程序身份：{e}"))?;
    if selected != trusted {
        return Err(
            "管理员 模式只允许使用与 SpiderVPN 程序同目录的 sing-box.exe；             配置指定了其他可执行程序，已在启动前拒绝".into(),
        );
    }
    #[cfg(windows)]
    {
        use crate::guard::identity::{reparse_chain, IdentityEnv};
        let env = crate::guard::wfp_win::SystemIdentityEnv::new();
        for path in [frontend_executable, &bundled, requested] {
            if reparse_chain(path).iter().any(|part| env.is_reparse_point(part)) {
                return Err("管理员 模式的引擎或主程序路径存在重解析点，拒绝跟随链接".into());
            }
        }
    }
    Ok(())
}

/// Query the *primary process token*, not registry writability, a caller
/// supplied bool, the current thread's impersonation token or the legacy
/// SPIDERVPN_FORCE_NONADMIN test hook. CreateProcess runs with the primary
/// token. An error or incomplete/unknown reply must never mean non-admin.
#[cfg(windows)]
pub(crate) fn actual_process_elevation() -> Result<bool, String> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw = std::ptr::null_mut();
    // SAFETY: valid pseudo-handle to this process, writable out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0
        || raw.is_null()
    {
        return Err(format!("无法核验管理员 引擎执行权限（进程 Token）：{}", std::io::Error::last_os_error()));
    }
    // SAFETY: OpenProcessToken returned an owned token handle.
    let _token = unsafe { OwnedHandle::from_raw_handle(raw) };
    read_token_elevation(raw)
}

#[cfg(windows)]
fn read_token_elevation(raw: windows_sys::Win32::Foundation::HANDLE) -> Result<bool, String> {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
    let mut value = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    let mut returned = 0u32;
    // SAFETY: token remains owned, output is correctly sized and aligned.
    if unsafe { GetTokenInformation(raw, TokenElevation,
        (&mut value as *mut TOKEN_ELEVATION).cast(), size, &mut returned) } == 0
    {
        return Err(format!("无法核验管理员 引擎执行权限（TokenElevation）：{}", std::io::Error::last_os_error()));
    }
    if returned != size {
        return Err("无法核验管理员 引擎执行权限（TokenElevation 长度未知）".into());
    }
    match value.TokenIsElevated {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("无法核验管理员 引擎执行权限（TokenElevation 值未知）".into()),
    }
}

/// One actual execution gate shared by start and the version subprocess.
/// This only enforces the existing bundled-path/reparse policy, not a
/// signature, trusted ACL, or same-file-object CreateProcess guarantee.
pub(crate) fn checked_engine_program(requested: &std::path::Path)
    -> Result<std::path::PathBuf, String>
{
    #[cfg(windows)]
    {
        if !actual_process_elevation()? {
            // Preserve the real standard user's configured path verbatim.
            return Ok(requested.to_path_buf());
        }
        let frontend = std::env::current_exe()
            .map_err(|e| format!("无法确认 SpiderVPN 主程序身份：{e}"))?;
        validate_privileged_engine(requested, &frontend)?;
        // Never hand a separate caller-controlled alias/relative executable
        // path back to Command after the privileged policy check.
        Ok(frontend.parent().ok_or("无法确认 SpiderVPN 主程序目录")?.join("sing-box.exe"))
    }
    #[cfg(not(windows))]
    {
        let _ = requested;
        Err("无法在此平台核验管理员 引擎执行权限".into())
    }
}

/// 拉起引擎。失败信息里带上程序路径——只说「启动失败」没法排查。
pub fn start(cfg: &EngineConfig, log_dir: &std::path::Path) -> Result<EngineHandle, String> {
    if cfg.binary.trim().is_empty() {
        return Err("引擎程序路径为空".into());
    }
    if !std::path::Path::new(&cfg.binary).exists() {
        return Err(format!("引擎程序不存在：{}", cfg.binary));
    }
    let program = checked_engine_program(std::path::Path::new(&cfg.binary))?;
    // Keep the actual shared registration across Command::spawn. A child
    // may outlive us; process occupancy is checked independently of this handle.
    let _runtime_occupancy = crate::runtime_occupancy::admit()?;
    let _ = std::fs::create_dir_all(log_dir);

    // 引擎自己的 stdout/stderr 必须落盘（`logs\engine.log`）。
    //
    // 以前是 `Stdio::null()`：引擎报的每一条错误都被丢掉，排查时只能靠外部抓包猜。
    // 真机上「连上了但网站打不开」就是被这条挡住的——sing-box 明明在日志里写了
    // `route ip+net: no such network interface`，我们却一个字节都没留下。
    // 追加写、超过 5 MB 先清掉，避免无界增长。
    let log_path = log_dir.join("engine.log");
    if std::fs::metadata(&log_path).map(|m| m.len() > 5 * 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::remove_file(&log_path);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();
    let mut cmd = Command::new(&program);
    cmd.args(&cfg.args).stdin(Stdio::null());
    match &log_file {
        Some(file) => {
            if let Ok(err) = file.try_clone() {
                cmd.stdout(Stdio::from(file.try_clone().unwrap_or_else(|_| err.try_clone().unwrap())));
                cmd.stderr(Stdio::from(err));
            } else {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    if let Some(mut file) = log_file {
        use std::io::Write;
        let _ = writeln!(
            file,
            "\n===== {} 启动 {} =====",
            crate::deploystore::now_utc(),
            cfg.binary
        );
    }

    // Windows：不弹控制台窗口。否则用户每次连接都会看到一个黑框。
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let child = cmd.spawn().map_err(|e| format!("启动引擎失败（{}）：{e}", cfg.binary))?;
    let pid = child.id() as i64;
    // child 在这里被释放：句柄关掉不影响进程继续跑（引擎是独立进程，断开靠 taskkill 按 pid 停）。
    Ok(EngineHandle { pid })
}

/// 停止引擎：先请求关闭，超时再强制。
pub fn stop(pid: i64, graceful_ms: u64) -> Result<(), String> {
    if pid <= 0 {
        return Ok(());
    }
    // 温和关闭：taskkill 不带 /F
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let deadline = Instant::now() + Duration::from_millis(graceful_ms);
    while Instant::now() < deadline {
        if !crate::probe::SystemProbe::default().process_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 还没退：强制结束整个进程树（引擎可能自己拉了子进程）
    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("强制停止引擎失败：{e}"))?;

    // taskkill 返回成功不等于进程已经消失（内核还在回收）。继续等到它真的没了，
    // 否则「停止成功」是假的——调用方会立刻去改系统代理，而引擎可能还在跑。
    let deadline = Instant::now() + Duration::from_millis(2_000);
    while Instant::now() < deadline {
        if !crate::probe::SystemProbe::default().process_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("引擎进程 {pid} 在强制结束后仍未退出"))
}

/// 引擎从哪来。界面只说路径，但**代码要分得清**：配置里那份是用户的选择，
/// 自带副本是兜底——兜底时若还按用户选择去报错，就等于假装文件还在。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `config.json` 的 `engine.binary`，且那份文件真的在。
    Configured,
    /// 本安装目录自带的 `sing-box.exe`（配置为空、或配置的那份已经不在了）。
    Bundled,
}

/// 引擎的**生效**路径。优先级：
/// 1. 配置的那份（存在，且**不是**从旧版安装目录借来的）；
/// 2. 自带副本；
/// 3. 借来的那份（自带副本也没有时，能用总比不能用好）。
///
/// 为什么把「借来的」排到最后：旧版的安装目录里有一份 `assets\sing-box.exe`，历史配置把
/// 它写进了 `engine.binary`。旧版一卸载/改目录，这条引用就断，用户看到的是「引擎启动后立即
/// 退出」——真正的原因只是借来的那份没了。把自带副本排在它前面，就等于把这条依赖剪掉，
/// 而且**不用改用户的配置文件**（改了反而会覆盖掉他可能故意选的版本）。
///
/// `dirs` 是**候选目录**（按顺序找 `sing-box.exe`），`legacy` 是「旧版安装目录」前缀。
/// 两者都由调用方给：生产用安装目录 + 程序目录 + 旧版安装目录，测试用临时目录，
/// 这样这个判断不依赖运行环境。
pub fn resolve(
    configured: &str,
    dirs: &[std::path::PathBuf],
    legacy: Option<&std::path::Path>,
) -> Option<(std::path::PathBuf, Origin)> {
    let want = configured.trim();
    let borrowed = !want.is_empty()
        && legacy.is_some_and(|root| {
            // 比字符串而不是 `Path::starts_with`：现场配置里写的是正斜杠，
            // 而 `Legacy::INSTALL_DIR` 是反斜杠，按组件比会在大小写/分隔符上踩空。
            let norm = |s: &str| s.replace('/', "\\").to_ascii_lowercase();
            norm(want).starts_with(&format!("{}\\", norm(&root.to_string_lossy())))
        });
    if !borrowed && !want.is_empty() {
        let p = std::path::PathBuf::from(want);
        if p.is_file() {
            return Some((p, Origin::Configured));
        }
    }
    for dir in dirs {
        let candidate = dir.join("sing-box.exe");
        if candidate.is_file() {
            return Some((candidate, Origin::Bundled));
        }
    }
    if borrowed {
        let p = std::path::PathBuf::from(want);
        if p.is_file() {
            return Some((p, Origin::Configured));
        }
    }
    None
}

/// `resolve` 的生产用法：候选目录 = `数据根的上层\bin`（安装模式）与程序所在目录（免安装模式），
/// 「借来的」前缀 = 旧版的安装目录。
///
/// 用**数据根反推**安装目录而不是直接读 `isolation::install_dir()`：数据根恒为
/// `<安装目录>\data`（`isolation::data_root`），这样传进来的 `root` 就决定了候选范围——
/// 测试用临时根时不会因为这台机器上真装了一份 `sing-box.exe` 而让结果随环境变。
pub fn resolve_for(root: &std::path::Path, configured: &str) -> Option<(std::path::PathBuf, Origin)> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(install) = root.parent() {
        dirs.push(install.join("bin"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let dir = dir.to_path_buf();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    let legacy = std::path::PathBuf::from(crate::isolation::Legacy::INSTALL_DIR);
    resolve(configured, &dirs, Some(&legacy))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;


    // Run the original and new real-process assertions from a disposable
    // frontend directory, not beside the actual installed executable or a
    // different cargo test binary. Child selection is test-harness only;
    // neither it nor FORCE_NONADMIN is consulted by the execution policy.
    #[cfg(windows)]
    pub(crate) fn isolated_engine_entry(test_name: &str, harmless_engine: &str) -> bool {
        let exe = std::env::current_exe().unwrap();
        const FRONTEND: &str = "spidervpn-engine-entry-fixture.exe";
        if exe.file_name().and_then(|n| n.to_str()) == Some(FRONTEND) {
            return false;
        }
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = test_name.rsplit("::").next().unwrap();
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        // Never reuse or erase a pre-existing directory. Each original
        // test gets its own frontend, engine, logs and data, even when
        // multiple tests execute in one cargo invocation.
        let root = loop {
            let dir = std::env::temp_dir().join(format!("tcrs-entry-{name}-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create isolated frontend directory: {err}"),
            }
        };
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
        }
        let _cleanup = Cleanup(root.clone());
        let child = root.join(FRONTEND);
        std::fs::copy(&exe, &child).unwrap();
        std::fs::copy(harmless_engine, root.join("sing-box.exe")).unwrap();
        assert_eq!(std::fs::read(root.join("sing-box.exe")).unwrap(),
            std::fs::read(harmless_engine).unwrap(), "exact harmless fixture image");
        let dll = exe.parent().unwrap().join("WebView2Loader.dll");
        if dll.is_file() {
            std::fs::copy(dll, root.join("WebView2Loader.dll")).unwrap();
        }
        let mut command = Command::new(&child);
        command.args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .current_dir(&root);
        // Only the explicit entry-gate tests challenge the legacy hook.
        // The three real connection regressions must run with no forced
        // nonadmin flag; all tests keep the inherited primary token.
        if test_name == "engine::tests::start_reports_pid_and_process_is_alive"
            || test_name == "ipc::tests::the_real_probe_rejects_a_program_that_is_not_sing_box"
        {
            command.env("SPIDERVPN_FORCE_NONADMIN", "1");
        } else {
            command.env_remove("SPIDERVPN_FORCE_NONADMIN");
        }
        let output = command.output().expect("run isolated real-token test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success() && stdout.contains("1 passed")
            && stdout.contains("ENGINE_ENTRY_ACTUAL_TOKEN"),
            "isolated test did not execute successfully: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr));
        print!("{stdout}");
        true
    }


    #[cfg(windows)]
    pub(crate) fn with_engine_junction(target: &std::path::Path, check: impl FnOnce(&std::path::Path)) {
        // Junction lives outside the target, so there is no recursive cycle.
        let dir = tmp_dirs("entry-junction");
        let link = dir.join("linked");
        struct Cleanup(std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::fs::remove_dir(&self.0).unwrap();
                std::fs::remove_dir(&self.1).unwrap();
            }
        }
        let output = Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/D", "/C", "mklink", "/J"]).arg(&link).arg(target)
            .output().unwrap();
        assert!(output.status.success(), "create isolated junction: {}",
            String::from_utf8_lossy(&output.stderr));
        let _cleanup = Cleanup(link.clone(), dir);
        check(&link.join("sing-box.exe"));
    }

    #[test]
    fn actual_token_query_failure_is_not_nonadmin() {
        // Actual Win32 failure; do not create a fake token/elevation bool.
        // Production query takes only the owned current-process handle.
        assert!(read_token_elevation(std::ptr::null_mut()).is_err());
        assert!(actual_process_elevation().is_ok(), "real current process token must be queryable");
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={} null_token_query_refused=true",
            actual_process_elevation().unwrap());
    }

    /// 用系统自带的 ping 当「假引擎」：它是个会活一会儿的普通进程，
    /// 不监听端口、不改任何系统设置，用来验证拉起与停止的正反路径。
    fn sleeper() -> EngineConfig {
        EngineConfig {
            binary: r"C:\Windows\System32\PING.EXE".to_string(),
            args: vec!["-n".into(), "30".into(), "127.0.0.1".into()],
        }
    }

    #[test]
    fn start_reports_pid_and_process_is_alive() {
        if isolated_engine_entry(
            "engine::tests::start_reports_pid_and_process_is_alive",
            r"C:\Windows\System32\PING.EXE",
        ) { return; }
        assert_eq!(std::env::var("SPIDERVPN_FORCE_NONADMIN").as_deref(), Ok("1"));
        let elevated = actual_process_elevation().expect("actual primary token");
        let frontend = std::env::current_exe().unwrap();
        let root = frontend.parent().unwrap();
        let dir = root.join("logs");
        let mut cfg = sleeper();
        let custom = root.join("external");
        std::fs::create_dir(&custom).unwrap();
        let external_same_name = custom.join("sing-box.exe");
        std::fs::copy(&cfg.binary, &external_same_name).unwrap();
        if elevated {
            for rejected in [cfg.binary.clone(), external_same_name.to_string_lossy().into_owned()] {
                let bad = EngineConfig { binary: rejected, args: cfg.args.clone() };
                match start(&bad, &dir) {
                    Err(error) => assert!(error.contains("同目录"), "{error}"),
                    Ok(handle) => {
                        stop(handle.pid, 100).unwrap();
                        panic!("real elevated start admitted external image");
                    }
                }
                assert!(!dir.exists(), "rejected engine must not create logs or spawn");
            }
            with_engine_junction(root, |linked| {
                let bad = EngineConfig { binary: linked.to_string_lossy().into_owned(),
                    args: cfg.args.clone() };
                match start(&bad, &dir) {
                    Err(error) => assert!(error.contains("重解析"), "{error}"),
                    Ok(handle) => {
                        stop(handle.pid, 100).unwrap();
                        panic!("real elevated start followed a junction");
                    }
                }
                assert!(!dir.exists());
            });
            cfg.binary = root.join("sing-box.exe").to_string_lossy().into_owned();
        } else {
            // Exercise a genuine non-elevated custom same-name engine.
            cfg.binary = external_same_name.to_string_lossy().into_owned();
        }
        let h = start(&cfg, &dir).expect("应当能启动");
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={elevated} legacy_force_nonadmin=1 actual_start=true external_rejected={elevated} junction_rejected={elevated} standard_custom_started={}", !elevated);
        assert!(h.pid > 0);
        assert!(crate::probe::SystemProbe::default().process_alive(h.pid));
        assert!(h.alive());
        let pid = h.pid;
        stop(pid, 1_000).unwrap();
        assert!(!crate::probe::SystemProbe::default().process_alive(pid), "停止后进程必须消失");
    }

    #[test]
    fn privileged_engine_cannot_be_selected_from_arbitrary_config_path() {
        let dir = tmp_dirs("privileged-identity");
        let bin = dir.join("bin");
        let custom = dir.join("custom");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&custom).unwrap();
        let frontend = bin.join("spidervpn.exe");
        let bundled = bin.join("sing-box.exe");
        let injected = custom.join("sing-box.exe");
        for file in [&frontend, &bundled, &injected] {
            std::fs::write(file, b"test executable").unwrap();
        }
        assert!(validate_privileged_engine(&bundled, &frontend).is_ok());
        assert!(validate_privileged_engine(&injected, &frontend).is_err(),
            "配置指定的其他 exe 即使同名，也不能被管理员 任意执行");
        assert!(validate_privileged_engine(&bin.join("missing.exe"), &frontend).is_err());
        std::fs::remove_file(&bundled).unwrap();
        assert!(validate_privileged_engine(&bundled, &frontend).is_err(),
            "缺少随包引擎时不能默默回退到用户可写配置路径");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_binary_is_a_clear_error_not_a_panic() {
        let cfg = EngineConfig { binary: r"C:\definitely\not\here.exe".into(), args: vec![] };
        let e = start(&cfg, &std::env::temp_dir()).unwrap_err();
        assert!(e.contains("不存在"), "错误信息要能指导排查：{e}");
    }

    #[test]
    fn empty_binary_is_rejected() {
        let cfg = EngineConfig { binary: "  ".into(), args: vec![] };
        assert!(start(&cfg, &std::env::temp_dir()).is_err());
    }

    #[test]
    fn stopping_pid_zero_is_a_noop() {
        assert!(stop(0, 100).is_ok());
    }

    fn tmp_dirs(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-engine-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 引擎的四个组合：配置在 → 用配置；配置不在/为空 → 用自带副本；都没有 → None。
    /// 第二条是这次要解决的现场问题（配置指向已卸载的 旧版）。
    #[test]
    fn resolve_prefers_the_configured_engine_and_falls_back_to_the_bundled_copy() {
        let root = tmp_dirs("resolve");
        let bundled_dir = root.join("bin");
        std::fs::create_dir_all(&bundled_dir).unwrap();
        let bundled = bundled_dir.join("sing-box.exe");
        std::fs::write(&bundled, b"fake").unwrap();
        let dirs = vec![bundled_dir.clone()];
        let configured = root.join("elsewhere/sing-box.exe");

        // 配置的那份在：用它，别被自带副本顶掉（用户可能故意选了更新的版本）。
        std::fs::create_dir_all(configured.parent().unwrap()).unwrap();
        std::fs::write(&configured, b"fake").unwrap();
        assert_eq!(
            resolve(configured.to_str().unwrap(), &dirs, None),
            Some((configured.clone(), Origin::Configured))
        );

        // 配置的那份被删了（旧版卸载）：退到自带副本，而不是报「引擎不存在」。
        std::fs::remove_file(&configured).unwrap();
        assert_eq!(
            resolve(configured.to_str().unwrap(), &dirs, None),
            Some((bundled.clone(), Origin::Bundled))
        );

        // 压根没配：安装包自带引擎时，装完就能连，不必先去设置页选一次。
        assert_eq!(resolve("  ", &dirs, None), Some((bundled.clone(), Origin::Bundled)));

        // 两处都没有：None，调用方必须给出能指导排查的话（不是猜一个路径）。
        let empty = tmp_dirs("empty");
        assert_eq!(resolve("", &[empty.clone()], None), None);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// 从旧版安装目录**借来**的引擎要排在自带副本之后：那条引用会随着旧版卸载而断。
    /// 注意这条规则只在内存里生效——不改用户的 config.json。
    #[test]
    fn a_path_borrowed_from_the_old_install_loses_to_the_bundled_copy() {
        let root = tmp_dirs("borrowed");
        let legacy = root.join("tradechannel");
        let legacy_engine = legacy.join("assets").join("sing-box.exe");
        std::fs::create_dir_all(legacy_engine.parent().unwrap()).unwrap();
        std::fs::write(&legacy_engine, b"old").unwrap();
        let bundled_dir = root.join("bin");
        std::fs::create_dir_all(&bundled_dir).unwrap();
        let bundled = bundled_dir.join("sing-box.exe");
        std::fs::write(&bundled, b"new").unwrap();

        // 借来的 + 自带副本 → 用自带副本（现场配置写的是正斜杠，也必须认得出来）。
        let forward = legacy_engine.to_string_lossy().replace('\\', "/");
        for written in [legacy_engine.to_string_lossy().to_string(), forward] {
            assert_eq!(
                resolve(&written, &[bundled_dir.clone()], Some(&legacy)),
                Some((bundled.clone(), Origin::Bundled)),
                "写法：{written}"
            );
        }

        // 借来的 + 没有自带副本 → 仍然用借来的：能用总比不能用好。
        assert_eq!(
            resolve(legacy_engine.to_str().unwrap(), &[], Some(&legacy)),
            Some((legacy_engine.clone(), Origin::Configured))
        );

        // 不在旧版目录下的配置不受这条规则影响。
        let own = root.join("mine").join("sing-box.exe");
        std::fs::create_dir_all(own.parent().unwrap()).unwrap();
        std::fs::write(&own, b"mine").unwrap();
        assert_eq!(
            resolve(own.to_str().unwrap(), &[bundled_dir], Some(&legacy)),
            Some((own, Origin::Configured))
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
