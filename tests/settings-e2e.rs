//! 两个开关（开机自启 / 启动后自动连接）的端到端：跑真实可执行文件。
//!
//! 自启项一律写到 `SPIDERVPN_RUN_KEY` 指到的临时键，**真实 HKCU Run 键一个字节都不碰**。
//! 放 `tests/` 的理由同其他 e2e：单元测试里拿不到 `CARGO_BIN_EXE_*`。
//!
//! 为什么不去读注册表：本机安全策略禁止外部程序读（`reg.exe` 被黑名单拦下），集成测试也拿不到
//! `winreg`。这里改为断言**产品自己的回读输出** —— `--set-autostart` 写完会回读 Run 值并打印，
//! 那正是「写进去了」的证据；键本身的读写细节由 `autostart` 模块内的单测（直接用 winreg）覆盖。
//! 临时键只删值、不删键：空键无害，且没有 reg.exe 可用。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-settings-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

/// 临时 Run 键：每个用例一个，装在 HKCU 下但在 `tests` 子树里。
fn test_run_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\settings-{tag}-{}", std::process::id())
}

/// 铺一份合法配置（有两个开关字段也没关系：老配置本来就不带，正好覆盖向后兼容）。
fn write_config(root: &Path, extra: &str) {
    let body = format!(
        r#"{{"schema":1{extra},"line":{{"id":"L1","name":"设置用例","proxy_endpoint":"127.0.0.1:17999"}},"engine":{{"binary":"C:\\Windows\\System32\\PING.EXE","args":["-n","300","127.0.0.1"]}}}}"#
    );
    std::fs::write(root.join("data").join("config.json"), body).expect("写配置");
}

/// 跑一次被测程序。带超时：参数一旦被忽略，程序会走到界面分支并挂着不退。
fn run(root: &Path, run_key: &str, args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env("SPIDERVPN_RUN_KEY", run_key)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if child.try_wait().expect("等待被测程序").is_some() {
            let out = child.wait_with_output().expect("取输出");
            return (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 30 秒未退出：参数是不是被忽略了？");
}

/// 从 `--set-autostart` 的回读输出里取出 Run 值：`…（HKCU Run: <键> = <值>）`。
fn echoed_run_value(out: &str) -> String {
    let line = out.lines().find(|l| l.contains("HKCU Run:")).unwrap_or_else(|| panic!("没有回读行：{out}"));
    let after = line.split('=').nth(1).unwrap_or_else(|| panic!("回读行里没有值：{line}"));
    after.trim().trim_end_matches('）').trim().to_string()
}

#[test]
fn set_autostart_on_writes_run_key_and_off_removes_it() {
    let root = tmp_root("autostart");
    let key = test_run_key("autostart");
    write_config(&root, "");

    let (code, out) = run(&root, &key, &["--set-autostart", "on"]);
    assert_eq!(code, Some(0), "--set-autostart on 应当成功：{out}");
    assert!(out.contains("已开启开机自启"), "要给一句中文确认：{out}");
    // 配置里记下了
    let cfg = std::fs::read_to_string(root.join("data").join("config.json")).unwrap();
    assert!(cfg.contains("\"auto_start\": true"), "配置要落盘：{cfg}");
    // Run 键写了，且指向一个真实存在的入口（安装根的 .cmd，找不到则退回 exe）
    let v = echoed_run_value(&out);
    assert!(
        v.ends_with("启动SpiderVPN.cmd") || v.ends_with("spidervpn.exe"),
        "自启项要指向启动入口或 exe：{v}"
    );
    assert!(Path::new(&v).exists(), "写进去的路径必须真实存在：{v}");

    let (code, out) = run(&root, &key, &["--set-autostart", "off"]);
    assert_eq!(code, Some(0), "--set-autostart off 应当成功：{out}");
    assert!(out.contains("已关闭开机自启"), "{out}");
    assert_eq!(echoed_run_value(&out), "无", "关掉之后自启项必须真的没了（回读为空）");
    let cfg = std::fs::read_to_string(root.join("data").join("config.json")).unwrap();
    assert!(cfg.contains("\"auto_start\": false"), "{cfg}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_autostart_is_idempotent() {
    let root = tmp_root("autostart-idem");
    let key = test_run_key("autostart-idem");
    write_config(&root, "");

    assert_eq!(run(&root, &key, &["--set-autostart", "on"]).0, Some(0));
    let (code, out) = run(&root, &key, &["--set-autostart", "on"]);
    assert_eq!(code, Some(0), "连开两次不该报错：{out}");
    assert!(echoed_run_value(&out).ends_with(".cmd") || echoed_run_value(&out).ends_with(".exe"),
            "第二遍也要能回读到值：{out}");

    // 收尾：把值关掉，别在真实 HKCU 里留一个指向临时 exe 的自启项。
    assert_eq!(run(&root, &key, &["--set-autostart", "off"]).0, Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_autoconnect_on_does_not_touch_the_run_key() {
    let root = tmp_root("autoconnect");
    let key = test_run_key("autoconnect");
    write_config(&root, "");

    let (code, out) = run(&root, &key, &["--set-autoconnect", "on"]);
    assert_eq!(code, Some(0), "{out}");
    let cfg = std::fs::read_to_string(root.join("data").join("config.json")).unwrap();
    assert!(cfg.contains("\"auto_connect\": true"), "{cfg}");
    assert!(!out.contains("HKCU Run"), "自动连接与开机自启是两件事，这条命令不该碰 Run 键：{out}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_shows_both_switches() {
    let root = tmp_root("status-switches");
    let key = test_run_key("status-switches");
    // 老配置：没有两个字段，也必须能读、显示「关」
    write_config(&root, "");
    let (code, out) = run(&root, &key, &["--status"]);
    assert_eq!(code, Some(0), "旧配置必须照旧能读：{out}");
    assert!(out.contains("开机自启  ：关"), "{out}");
    assert!(out.contains("自动连接  ：关"), "{out}");

    assert_eq!(run(&root, &key, &["--set-autostart", "on"]).0, Some(0));
    assert_eq!(run(&root, &key, &["--set-autoconnect", "on"]).0, Some(0));
    let (_, out) = run(&root, &key, &["--status"]);
    assert!(out.contains("开机自启  ：开"), "{out}");
    assert!(out.contains("自动连接  ：开"), "{out}");

    // 收尾：关掉自启项，别在真实 HKCU 里留下指向临时 exe 的值。
    assert_eq!(run(&root, &key, &["--set-autostart", "off"]).0, Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_closetotray_persists_and_status_shows_it() {
    let root = tmp_root("closetotray");
    let key = test_run_key("closetotray");
    write_config(&root, "");

    // 缺省：关窗即断开（历史行为）
    let (_, out) = run(&root, &key, &["--status"]);
    assert!(out.contains("关窗行为  ：断开并退出"), "旧配置必须还是断开并退出：{out}");

    let (code, out) = run(&root, &key, &["--set-closetotray", "on"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已开启关窗缩到托盘"), "要给中文确认：{out}");
    let cfg = std::fs::read_to_string(root.join("data").join("config.json")).unwrap();
    assert!(cfg.contains("\"close_to_tray\": true"), "{cfg}");
    let (_, out) = run(&root, &key, &["--status"]);
    assert!(out.contains("关窗行为  ：缩到托盘（保持连接）"), "{out}");
    assert!(!out.contains("HKCU Run"), "关窗行为与开机自启无关，不该碰 Run 键：{out}");

    let (code, out) = run(&root, &key, &["--set-closetotray", "off"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已关闭关窗缩到托盘"), "{out}");
    let (_, out) = run(&root, &key, &["--status"]);
    assert!(out.contains("关窗行为  ：断开并退出"), "{out}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn startup_heals_a_stale_takeover_left_by_a_killed_process() {
    // 强杀/断电后的现场：凭据在、引擎已死、代理还指着本程序。
    // 下次启动必须自动还原——否则用户开机第一件事就是断网。
    // 这条打的是「启动自愈」这段接线：把 main 里那次 heal 调用去掉，它会红。
    let root = tmp_root("heal");
    let key = test_run_key("heal");
    write_config(&root, "");
    let data = root.join("data");
    std::fs::write(
        data.join("proxy-journal.json"),
        r#"{"schema":1,"endpoint":"127.0.0.1:17999","saved_at_secs":0,
            "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
    )
    .unwrap();
    // 引擎 pid 用一个不可能存在的值：模拟「引擎早没了」
    std::fs::write(
        data.join("runtime.json"),
        r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":4194303,"State":"Running"}"#,
    )
    .unwrap();

    let (code, out) = run(&root, &key, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已自动还原"), "启动时必须自愈并说出来：{out}");
    assert!(!data.join("proxy-journal.json").exists(), "自愈后凭据要清掉");
    assert!(!data.join("runtime.json").exists(), "自愈后运行时记录要清掉");

    let _ = std::fs::remove_dir_all(&root);
}
