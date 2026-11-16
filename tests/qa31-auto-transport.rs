//! R31「自动连接方式」的端到端复核（QA 编写，独立于 `transport-e2e.rs`）。
//!
//! 只验两件在进程边界上才看得清的事：
//! 1. 手写的老配置（只有 `id`/`name`/`proxy_endpoint`）跑 `--lines` 必须说「标准连接（默认）」，
//!    跑一次 `--set-transport auto` 之后落盘的 JSON 里**不许**出现 `transport` /
//!    `verified_transport` 这两个空键（`skip_serializing_if` 要在真文件上也生效）。
//! 2. 连接失败只清「已验证」，不许动用户固定的 `transport`。
//!
//! 系统代理一律写临时键（`SPIDERVPN_PROXY_KEY`），真实系统代理与注册表主路径不碰。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-qa31e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时数据根");
    p
}

fn proxy_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\qa31-{tag}-{}", std::process::id())
}

fn make_proxy_key(key: &str) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (k, _) = hkcu.create_subkey(key).expect("建临时代理键");
    k.set_value("ProxyEnable", &0u32).unwrap();
    k.set_value("ProxyServer", &"127.0.0.1:7897".to_string()).unwrap();
    k.set_value("ProxyOverride", &"localhost;127.*".to_string()).unwrap();
}

fn drop_proxy_key(key: &str) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let _ = hkcu.delete_subkey_all(key);
}

fn run(root: &Path, key: &str, args: &[&str]) -> (Option<i32>, String) {
    run_engine(root, key, args, "-n 1 127.0.0.1")
}

fn run_engine(root: &Path, key: &str, args: &[&str], engine_args: &str) -> (Option<i32>, String) {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let n = RUNS.fetch_add(1, Ordering::Relaxed);
    let out_path = root.join(format!("cli-{n}.out"));
    let err_path = root.join(format!("cli-{n}.err"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env("SPIDERVPN_PROXY_KEY", key)
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\qa31-run-{}", std::process::id()),
        )
        .env("SPIDERVPN_ENGINE_ARGS", engine_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out_path).expect("建输出文件")))
        .stderr(Stdio::from(std::fs::File::create(&err_path).expect("建错误输出文件")))
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("等待被测程序") {
            return (status.code(), std::fs::read_to_string(&out_path).unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 60 秒未退出（{args:?}）");
}

fn cfg_path(root: &Path) -> PathBuf {
    root.join("data").join("config.json")
}

fn cfg_text(root: &Path) -> String {
    std::fs::read_to_string(cfg_path(root)).expect("读 config.json")
}

fn cfg_json(root: &Path) -> serde_json::Value {
    serde_json::from_str(&cfg_text(root)).expect("config.json 必须是合法 JSON")
}

fn free_port() -> u16 {
    loop {
        let p = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if p <= 60_000 {
            return p;
        }
    }
}

/// 带 VLESS + REALITY 中转参数的线路文件（兼容连接能派生的形状）。
fn write_transport_profile(root: &Path) -> PathBuf {
    let dir = root.join("src").join("a");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("dual-mode.json");
    std::fs::write(
        &f,
        r#"{
            "inbounds": [{ "type": "tun", "tag": "trade-tun" }],
            "dns": { "servers": [{ "type": "udp", "tag": "dns-direct", "server": "192.168.1.1" }] },
            "endpoints": [{ "type": "wireguard", "tag": "hk", "address": ["10.7.0.2/32"] }],
            "route": { "rules": [], "final": "trade-exit" },
            "outbounds": [
                { "type": "vless", "tag": "provider-a", "server": "203.0.113.7", "server_port": 443,
                  "uuid": "11111111-2222-3333-4444-555555555555",
                  "tls": { "enabled": true, "server_name": "cdn.example.com",
                           "utls": { "enabled": true, "fingerprint": "chrome" },
                           "reality": { "enabled": true,
                                        "public_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1",
                                        "short_id": "ab12" } } },
                { "type": "selector", "tag": "trade-exit", "outbounds": ["hk"], "default": "hk" },
                { "type": "direct", "tag": "direct" }
            ]
        }"#,
    )
    .unwrap();
    f
}

/// 手写一份 0.1.4 之前形状的配置：**没有** `transport` / `verified_transport`。
fn write_legacy_config(root: &Path) {
    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:7890"}]}"#,
    )
    .unwrap();
}

#[test]
fn qa31_legacy_config_lists_as_default_and_auto_leaves_no_empty_keys() {
    let root = tmp_root("legacy");
    let key = proxy_key("legacy");
    make_proxy_key(&key);
    write_legacy_config(&root);

    // 一档：手写老配置 → 标准连接（默认）。不许因为缺字段就变成「已选」或「自动」。
    let (code, out) = run(&root, &key, &["--lines"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("标准连接（默认）"), "老配置必须显示「默认」：{out}");
    assert!(!out.contains("（已选）"), "老配置没有「已选」：{out}");
    assert!(!out.contains("（自动）"), "老配置没有「自动」：{out}");

    // 跑一次 auto：它跳过 check_transport（这条线路连线路文件都没有），必须照样成功。
    let (code, out) = run(&root, &key, &["--set-transport", "auto"]);
    assert_eq!(code, Some(0), "没有线路文件时 auto 也要能设（只是取消固定）：{out}");
    assert!(
        out.contains("已改为自动选择（采用这条线路已验证的方式）"),
        "CLI 文案要逐字对上：{out}"
    );

    // 落盘文件里两个键都不许出现——不是 null，不是空串，是**没有这个键**。
    let text = cfg_text(&root);
    assert!(!text.contains("\"transport\":"), "`transport` 键不许出现：{text}");
    assert!(
        !text.contains("\"verified_transport\""),
        "从没验证过的线路不许写 `verified_transport`：{text}"
    );
    let disk = cfg_json(&root);
    assert!(disk["lines"][0].get("transport").is_none(), "{disk}");
    assert!(disk["lines"][0].get("verified_transport").is_none(), "{disk}");

    // 再列一次：仍是「标准连接（默认）」。
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("标准连接（默认）"), "auto 之后无依据仍是「默认」：{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn qa31_cli_rejects_an_unknown_transport_with_exit_2_and_no_write() {
    let root = tmp_root("cli-bad");
    let key = proxy_key("cli-bad");
    make_proxy_key(&key);
    write_legacy_config(&root);
    let before = std::fs::read(cfg_path(&root)).unwrap();

    let (code, out) = run(&root, &key, &["--set-transport", "quic"]);
    assert_eq!(code, Some(2), "取值非法属用法错误，退出码必须是 2：{out}");
    assert!(out.contains("auto"), "可选值里必须列出 auto：{out}");
    assert!(out.contains("udp") && out.contains("tcp"), "原来两种也不能少：{out}");
    assert_eq!(
        std::fs::read(cfg_path(&root)).unwrap(),
        before,
        "拒绝时配置必须逐字节不变"
    );

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn qa31_failed_connect_clears_the_evidence_but_keeps_the_users_choice() {
    let root = tmp_root("fail-keeps-choice");
    let key = proxy_key("fail-keeps-choice");
    make_proxy_key(&key);

    // 先导入一条带中转参数的线路。
    let profile = write_transport_profile(&root);
    let port = free_port();
    let (code, out) = run(
        &root,
        &key,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C:\Windows\System32\PING.EXE",
            "--port",
            &port.to_string(),
            "--line-name",
            "线路甲",
        ],
    );
    assert_eq!(code, Some(0), "导入应当成功：{out}");

    // 摆一个真实现场：用户固定了兼容连接，而且这条线路验证过兼容连接。
    let mut cfg = cfg_json(&root);
    cfg["lines"][0]["transport"] = serde_json::json!("tcp");
    cfg["lines"][0]["verified_transport"] = serde_json::json!("tcp");
    // 引擎换成「存在但起来就退出」的程序：连接一定在「引擎启动后立即退出」处失败
    // （失败分支才会清依据）。`where.exe` 不带参数会立刻以 1 退出。
    cfg["engine"]["binary"] = serde_json::json!(r"C:\Windows\System32\where.exe");
    std::fs::write(&cfg_path(&root), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

    let (code, out) = run_engine(&root, &key, &["--connect"], "");
    assert_ne!(code, Some(0), "引擎起不来，连接必须失败：{out}");
    assert!(out.contains("失败"), "要说清失败：{out}");

    let after = cfg_json(&root);
    assert_eq!(
        after["lines"][0]["transport"],
        serde_json::json!("tcp"),
        "连接失败只清依据，**不许**动用户固定的连接方式：{after}"
    );
    assert!(
        after["lines"][0].get("verified_transport").is_none(),
        "本次没连上，上一次的「通过」不再成立：{after}"
    );
    // 固定还在 → 下次仍是兼容连接。
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("兼容连接（已选）"), "固定仍然生效：{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}
