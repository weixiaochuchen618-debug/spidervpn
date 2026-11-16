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

/// 拉起引擎。失败信息里带上程序路径——只说「启动失败」没法排查。
pub fn start(cfg: &EngineConfig, log_dir: &std::path::Path) -> Result<EngineHandle, String> {
    if cfg.binary.trim().is_empty() {
        return Err("引擎程序路径为空".into());
    }
    if !std::path::Path::new(&cfg.binary).exists() {
        return Err(format!("引擎程序不存在：{}", cfg.binary));
    }
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
    let mut cmd = Command::new(&cfg.binary);
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
mod tests {
    use super::*;

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
        let dir = std::env::temp_dir();
        let h = start(&sleeper(), &dir).expect("应当能启动");
        assert!(h.pid > 0);
        assert!(crate::probe::SystemProbe::default().process_alive(h.pid));
        assert!(h.alive());
        let pid = h.pid;
        stop(pid, 1_000).unwrap();
        assert!(!crate::probe::SystemProbe::default().process_alive(pid), "停止后进程必须消失");
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
