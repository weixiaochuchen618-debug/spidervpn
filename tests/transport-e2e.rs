//! 线路级连接方式（标准连接 Udp / 兼容连接 Tcp）的端到端。
//!
//! 三件事必须成立：
//! 1. 选过的连接方式存得下来，`--lines` 如实显示「已选 / 默认」；
//! 2. 线路文件里没有 VLESS + REALITY 参数时，选兼容连接要被拒绝，且配置一个字节都不动；
//! 3. 切换只影响**下次连接**：正在跑的那份运行时配置不许改（旧版的
//!    「已保存下次默认方式，当前连接保持」）。
//!
//! 系统代理一律写临时键（`SPIDERVPN_PROXY_KEY`），真机网络设置一个字节都不碰。
//! 输出落**文件**而不是管道：假引擎活得比连接进程久，管道写端被它继承时
//! `wait_with_output` 会一直等到引擎退出。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const PING: &str = r"C:\Windows\System32\PING.EXE";
/// 假引擎活着的参数（`ping` 会持续 300 秒）。
const ENGINE_ALIVE: &str = "-n 300 127.0.0.1";

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-tr-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时数据根");
    p
}

fn proxy_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\tr-{tag}-{}", std::process::id())
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
            format!(r"Software\SpiderVPN\tests\tr-run-{}", std::process::id()),
        )
        .env("SPIDERVPN_ENGINE_ARGS", ENGINE_ALIVE)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out_path).expect("建输出文件")))
        .stderr(Stdio::from(std::fs::File::create(&err_path).expect("建错误输出文件")))
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("等待被测程序") {
            let out = std::fs::read_to_string(&out_path).unwrap_or_default();
            return (status.code(), out);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 60 秒未退出（{args:?}）");
}

fn free_port() -> u16 {
    loop {
        let p = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        // 端口 +3 是自检探测口，越过 65532 会被导入按上限拒绝。
        if p <= 60_000 {
            return p;
        }
    }
}

/// 只有 WireGuard 隧道、没有任何中转参数的线路文件（标准连接的形状）。
fn write_udp_profile(root: &Path, tag: &str) -> PathBuf {
    let dir = root.join("src").join(tag);
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
                { "type": "selector", "tag": "trade-exit", "outbounds": ["hk"], "default": "hk" },
                { "type": "direct", "tag": "direct" }
            ]
        }"#,
    )
    .unwrap();
    f
}

/// 带 VLESS + REALITY 中转参数的线路文件（兼容连接能派生的形状）。
fn write_transport_profile(root: &Path, tag: &str) -> PathBuf {
    let dir = root.join("src").join(tag);
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

fn import(root: &Path, key: &str, profile: &Path, name: &str) -> u16 {
    let port = free_port();
    let (code, out) = run(
        root,
        key,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            PING,
            "--port",
            &port.to_string(),
            "--line-name",
            name,
        ],
    );
    assert_eq!(code, Some(0), "导入应当成功：{out}");
    port
}

fn config_json(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join("data").join("config.json")).expect("config.json");
    serde_json::from_str(&text).expect("config.json 必须是合法 JSON")
}

#[test]
fn set_transport_persists_the_choice_and_lines_shows_it() {
    let root = tmp_root("persist");
    let key = proxy_key("persist");
    make_proxy_key(&key);
    let profile = write_transport_profile(&root, "a");
    import(&root, &key, &profile, "线路甲");

    // 没选过 → 标准连接，而且是「默认」不是「已选」
    let (code, out) = run(&root, &key, &["--lines"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("标准连接（默认）"), "没选过要显示默认：{out}");

    let (code, out) = run(&root, &key, &["--set-transport", "tcp"]);
    assert_eq!(code, Some(0), "参数齐全就该切得过去：{out}");
    assert!(out.contains("兼容连接"), "{out}");
    assert!(out.contains("当前连接保持"), "要说清只对下次连接生效：{out}");
    assert_eq!(config_json(&root)["lines"][0]["transport"], "tcp", "选择必须落盘");

    // 重读配置仍是新选择（换一个进程读，证明真的写进了文件）
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("兼容连接（已选）"), "{out}");

    // 显式选回标准连接：值要留着（「用户选的」与「默认」是两件事）
    let (code, out) = run(&root, &key, &["--set-transport", "udp"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(config_json(&root)["lines"][0]["transport"], "udp");
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("标准连接（已选）"), "{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_transport_refuses_a_line_without_transport_parameters() {
    let root = tmp_root("refuse");
    let key = proxy_key("refuse");
    make_proxy_key(&key);
    let profile = write_udp_profile(&root, "a");
    import(&root, &key, &profile, "线路甲");
    let cfg_path = root.join("data").join("config.json");
    let before = std::fs::read_to_string(&cfg_path).unwrap();

    // 线路文件里没有 VLESS + REALITY 参数：拒绝，并说清缺什么
    let (code, out) = run(&root, &key, &["--set-transport", "tcp"]);
    assert_eq!(code, Some(3), "线路缺 VLESS + REALITY 参数，属配置问题：{out}");
    assert!(out.contains("连接方式不可用"), "文案要指到连接方式上：{out}");
    assert!(out.contains("VLESS") && out.contains("REALITY"), "要说清缺什么：{out}");
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), before, "拒绝时配置一个字节都不能动");

    // 认不出的值同样拒绝——不许静默当成 udp
    let (code, out) = run(&root, &key, &["--set-transport", "quic"]);
    assert_eq!(code, Some(2), "取值非法属用法错误：{out}");
    assert!(out.contains("udp") && out.contains("tcp"), "要告诉用户可选值：{out}");
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), before);

    // 标准连接永远可选
    let (code, out) = run(&root, &key, &["--set-transport", "udp"]);
    assert_eq!(code, Some(0), "{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn transport_switch_does_not_touch_the_running_connection() {
    // 旧版的原文：「已保存下次默认方式，当前连接保持」。
    let root = tmp_root("live");
    let key = proxy_key("live");
    make_proxy_key(&key);
    let profile = write_transport_profile(&root, "a");
    import(&root, &key, &profile, "线路甲");
    let runtime = root.join("data").join("runtime-engine.json");

    let (code, out) = run(&root, &key, &["--connect"]);
    assert_eq!(code, Some(0), "假引擎活着，连接应当成功：{out}");
    let running = std::fs::read_to_string(&runtime).expect("连上之后必须有运行时配置");
    assert!(
        !running.contains("tc-transport"),
        "默认标准连接，运行中的配置不该带中转：{running}"
    );

    // 连接中切换：只写 config.json
    let (code, out) = run(&root, &key, &["--set-transport", "tcp"]);
    assert_eq!(code, Some(0), "连接中也要能改默认方式：{out}");
    assert_eq!(
        std::fs::read_to_string(&runtime).unwrap(),
        running,
        "当前连接保持：运行中的配置一个字节都不许改"
    );
    assert_eq!(config_json(&root)["lines"][0]["transport"], "tcp");

    // 断开再连：这次才用兼容连接
    let (code, out) = run(&root, &key, &["--disconnect"]);
    assert_eq!(code, Some(0), "断开应当成功：{out}");
    let (code, out) = run(&root, &key, &["--connect"]);
    assert_eq!(code, Some(0), "{out}");
    let after = std::fs::read_to_string(&runtime).expect("重新连上之后必须有运行时配置");
    assert!(after.contains("tc-transport"), "下次连接该用兼容连接：{after}");
    assert!(after.contains("detour"), "endpoint 要挂到中转上：{after}");
    // 线路文件本身仍是标准连接那份（切回去还得靠它）
    let id = config_json(&root)["lines"][0]["id"].as_str().unwrap().to_string();
    let line_file = root.join("data").join("lines").join(format!("{id}.json"));
    let line_raw = std::fs::read_to_string(&line_file).unwrap_or_default();
    assert!(
        !line_raw.is_empty() && !line_raw.contains("tc-transport"),
        "派生的兼容连接只落在运行时配置上：{line_raw}"
    );

    let _ = run(&root, &key, &["--disconnect"]);
    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

/// 「自动」这一档的三件事：`--lines` 说得清是三档中的哪一档、`--set-transport auto`
/// 把偏好清空但不抹证据、非法取值的报错里也要有 auto。
#[test]
fn lines_names_the_three_transport_states_and_auto_clears_the_choice_only() {
    let root = tmp_root("auto");
    let key = proxy_key("auto");
    make_proxy_key(&key);
    let profile = write_transport_profile(&root, "a");
    import(&root, &key, &profile, "线路甲");
    let cfg_path = root.join("data").join("config.json");

    // 一档：「默认」——没固定、也没验证过，跑策略默认的标准连接。
    let (code, out) = run(&root, &key, &["--lines"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("标准连接（默认）"), "没有任何依据时是「默认」：{out}");

    // 摆一个真实现场：这条线路验证过兼容连接（自检通过才会这么写），但用户没有固定。
    let mut cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    cfg["lines"][0]["verified_transport"] = serde_json::json!("tcp");
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

    // 二档：「自动」——没固定、但有依据，生效方式就是那条依据。
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("兼容连接（自动）"), "有依据没固定时是「自动」：{out}");

    // 固定之后是「已选」，依据留着不影响优先级。
    let (code, out) = run(&root, &key, &["--set-transport", "tcp"]);
    assert_eq!(code, Some(0), "{out}");
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("兼容连接（已选）"), "用户固定优先：{out}");
    assert_eq!(config_json(&root)["lines"][0]["verified_transport"], "tcp", "依据不该被抹掉");

    // `auto` = 取消固定：`transport` 从文件里消失（=`None`），`verified_transport` 原样保留。
    let (code, out) = run(&root, &key, &["--set-transport", "auto"]);
    assert_eq!(code, Some(0), "auto 必须能设：{out}");
    assert!(
        out.contains("已改为自动选择（采用这条线路已验证的方式）"),
        "auto 要用自己的文案：{out}"
    );
    assert!(out.contains("当前连接保持"), "仍然只对下次连接生效：{out}");
    let disk = config_json(&root);
    assert!(disk["lines"][0].get("transport").is_none(), "自动 = 不固定：{disk}");
    assert_eq!(disk["lines"][0]["verified_transport"], "tcp", "依据必须留着：{disk}");
    let (_, out) = run(&root, &key, &["--lines"]);
    assert!(out.contains("兼容连接（自动）"), "回到「自动」这一档：{out}");

    // 非法取值：报错要把 auto 也列出来（否则用户以为只有两种选择）。
    let (code, out) = run(&root, &key, &["--set-transport", "quic"]);
    assert_eq!(code, Some(2), "取值非法属用法错误：{out}");
    assert!(out.contains("auto"), "可选值里要有 auto：{out}");
    assert_eq!(config_json(&root), disk, "拒绝时配置一个字节都不能动");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}
