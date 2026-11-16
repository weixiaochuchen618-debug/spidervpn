//! 命令行参数校验：**少了值 / 参数写错必须当场报错退出，绝不掉进图形界面**。
//!
//! 背景（真实事故）：`--use` 少给值时程序不是报错，而是进了 GUI 事件循环，弹出一个窗口、
//! 没有任何提示，并且**占着 exe**——后续升级 `Copy-Item` 全部失败，看着像"装成功了但版本没变"。
//! 所以这里的断言除了退出码，还有一条：**必须在 2 秒内退出**（证明没进 GUI）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-argv-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

/// 跑一次并返回（退出码，stdout，耗时）。带 5 秒兜底：真的进了 GUI 就杀掉并让断言红。
fn run_timed(root: &Path, args: &[&str]) -> (Option<i32>, String, Duration) {
    assert!(!root.as_os_str().is_empty(), "必须给临时数据根");
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env(
            "SPIDERVPN_PROXY_KEY",
            format!(r"Software\SpiderVPN\tests\argv-{}", std::process::id()),
        )
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\argv-run-{}", std::process::id()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("等待被测程序").is_some() {
            let out = child.wait_with_output().expect("取输出");
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            return (out.status.code(), text, started.elapsed());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return (None, String::from("<5 秒未退出，已强杀>"), started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn value_taking_flags_without_a_value_fail_fast() {
    let root = tmp_root("novalue");
    // 这几条都是"带值"的命令：只给 flag 不给值，必须报错退出，而不是开窗口。
    for flag in [
        "--use",
        "--remove-line",
        "--set-line",
        "--import",
        "--split-add-process",
        "--split-add-domain",
        "--split-remove-process",
        "--split-remove-domain",
        "--server-inspect",
        "--server-trust",
        "--server-forget",
        "--fingerprint",
    ] {
        let (code, out, took) = run_timed(&root, &[flag]);
        assert_eq!(code, Some(2), "{flag} 缺值要给 exit 2（用法错误），实际 {code:?}：{out}");
        assert!(out.contains("需要参数"), "{flag} 要说清缺什么：{out}");
        assert!(out.contains("用法"), "{flag} 要给一个用法示例：{out}");
        // 最关键的一条：没有掉进 GUI（否则会一直等到有人关窗）
        assert!(took < Duration::from_secs(2), "{flag} 必须 2 秒内退出，实测 {took:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// 部署命令的形状错误必须在**碰网络之前**就退出：一条要连外网的命令卡住 5 秒，
/// 用户只会以为程序死了。
#[test]
fn server_commands_refuse_a_bad_spec_before_touching_the_network() {
    let root = tmp_root("serverspec");
    let cases: &[(&[&str], &str)] = &[
        (&["--server-inspect", "root203.0.113.10"], "用户名@主机"),
        (&["--server-inspect", "root@2001:db8::1"], "IPv6"),
        (&["--server-forget", "root@203.0.113.10:0"], "端口"),
        (&["--server-trust", "root@203.0.113.10"], "--fingerprint"),
    ];
    for (args, needle) in cases {
        let (code, out, took) = run_timed(&root, args);
        assert_eq!(code, Some(2), "{args:?} 应当是用法错误：{out}");
        assert!(out.contains(needle), "{args:?} 要说清哪里不对（应含 {needle}）：{out}");
        assert!(took < Duration::from_secs(2), "{args:?} 必须立刻退出，实测 {took:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_line_with_too_few_values_is_rejected() {
    let root = tmp_root("setline");
    let (code, out, took) = run_timed(&root, &["--set-line", "L1", "名称"]);
    assert_eq!(code, Some(2), "只给两个值也要拒绝：{out}");
    assert!(out.contains("需要参数") && out.contains("--set-line"), "{out}");
    assert!(took < Duration::from_secs(2), "必须立刻退出，实测 {took:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unknown_flag_is_rejected_and_says_how_to_open_the_ui() {
    let root = tmp_root("unknown");
    for bad in ["--lst", "--conect", "--nosuchflag"] {
        let (code, out, took) = run_timed(&root, &[bad]);
        assert_eq!(code, Some(2), "{bad} 应当是未知参数：{out}");
        assert!(out.contains("未知参数"), "{out}");
        assert!(out.contains(bad), "要指出是哪个：{out}");
        assert!(out.contains("不带参数运行可打开界面"), "要告诉用户怎么进界面：{out}");
        assert!(took < Duration::from_secs(2), "{bad} 必须立刻退出，实测 {took:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn extra_value_on_a_valueless_flag_is_rejected() {
    let root = tmp_root("extra");
    // `--status` 不吃值：多写一个词要报「多余参数」，而不是被默默忽略
    let (code, out, took) = run_timed(&root, &["--status", "乱写"]);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("多余参数"), "{out}");
    assert!(took < Duration::from_secs(2), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn no_arguments_still_opens_the_gui() {
    // 这条是防回退：不带参数必须照旧进图形界面（不能因为我们加了校验就变成报错）。
    let root = tmp_root("gui");
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .env("SPIDERVPN_ROOT", &root)
        .env(
            "SPIDERVPN_PROXY_KEY",
            format!(r"Software\SpiderVPN\tests\argv-gui-{}", std::process::id()),
        )
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\argv-gui-run-{}", std::process::id()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动被测程序");
    std::thread::sleep(Duration::from_secs(2));
    let alive = child.try_wait().expect("检查进程").is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(alive, "不带参数时应当进入界面（进程存活），而不是直接退出");
    let _ = std::fs::remove_dir_all(&root);
}
