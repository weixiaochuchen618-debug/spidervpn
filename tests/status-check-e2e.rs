//! `--status` 里的「通道自检」一行：跑真实可执行文件，确认它读的是数据根下的 `last-check.json`。
//!
//! 放 `tests/` 的理由与 import-e2e.rs 相同：单元测试里拿不到 `CARGO_BIN_EXE_*`。
//! 数据根用环境变量只传给子进程，不在本进程 `set_var`（会与并行用例抢全局环境）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-status-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时目录");
    p
}

/// 跑一次 `--status`，返回（退出码，stdout）。
///
/// 带超时：`--status` 一旦没被识别，程序会走到界面分支并挂着不退——「挂死」比「失败」更难查。
fn run_status(root: &Path) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .arg("--status")
        .env("SPIDERVPN_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if child.try_wait().expect("等待被测程序").is_some() {
            let out = child.wait_with_output().expect("取被测程序输出");
            return (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("--status 30 秒未退出：参数是不是被忽略了、走到了界面分支？");
}

/// 数据根是 `<root>\data`（与 `isolation::data_root` 一致）。
fn record(root: &Path, body: &str) {
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("建数据目录");
    std::fs::write(data.join("last-check.json"), body).expect("写自检结论");
}

#[test]
fn status_shows_last_check_passed() {
    let root = tmp_root("passed");
    record(&root, r#"{"ok":true,"status":204,"error":null,"at":1700000000}"#);
    let (code, stdout) = run_status(&root);
    assert_eq!(code, Some(0), "--status 应当成功：{stdout}");
    assert!(
        stdout.contains("通道自检  ：通过（HTTP 204）"),
        "要原样报出上次自检的结论（含状态码）：{stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_shows_failed_check_with_reason() {
    let root = tmp_root("failed");
    record(
        &root,
        r#"{"ok":false,"status":null,"error":"连不上本机代理端口 17890：拒绝连接","at":1700000000}"#,
    );
    let (code, stdout) = run_status(&root);
    assert_eq!(code, Some(0), "--status 应当成功：{stdout}");
    // 失败文案必须带上探测目标：用户才能分清「域名被屏蔽」和「代理坏了」。
    assert!(
        stdout.contains("未通过（连 www.gstatic.com 失败：连不上本机代理端口 17890"),
        "失败原因与目标都要露出来：{stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_without_record_says_undetected() {
    let root = tmp_root("none");
    let (code, stdout) = run_status(&root);
    assert_eq!(code, Some(0), "--status 应当成功：{stdout}");
    assert!(stdout.contains("通道自检  ：未检测"), "没有记录就是未检测：{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_with_broken_record_still_says_undetected() {
    let root = tmp_root("broken");
    record(&root, "{not json");
    let (code, stdout) = run_status(&root);
    assert_eq!(code, Some(0), "结论文件坏掉不能让 --status 失败：{stdout}");
    assert!(stdout.contains("通道自检  ：未检测"), "坏文件按未检测处理：{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_shows_proxy_mode_for_old_config_without_mode_field() {
    // 向后兼容的关键一条：用户现有的 config.json 没有 mode 字段，
    // 读出来必须是「代理」——不能因为加了这个字段就把他静默切到别的接管方式。
    let root = tmp_root("old-mode");
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("建数据目录");
    let old = r#"{"schema":1,"line":{"id":"L9","name":"老配置","proxy_endpoint":"127.0.0.1:17999"}}"#;
    std::fs::write(data.join("config.json"), old).expect("写旧配置");
    let (code, stdout) = run_status(&root);
    assert_eq!(code, Some(0), "旧配置必须照旧能读：{stdout}");
    assert!(stdout.contains("模式      ：代理"), "没有 mode 字段就是代理模式：{stdout}");
    assert!(stdout.contains("老配置"), "线路信息也要正常显示：{stdout}");
    // 线路只显示名字、不显示 id（id 是名字的小写 slug，并排显示会被当成重复）。
    // D3 之后线路名在横幅那一行：「线路：老配置  端点：…」。
    assert!(stdout.contains("线路：老配置"), "线路行要原样显示名字：{stdout}");
    assert!(!stdout.contains("(L9)"), "不允许把 id 拼在名字后面：{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}
