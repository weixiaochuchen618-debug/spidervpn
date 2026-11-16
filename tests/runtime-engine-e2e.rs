//! `runtime-engine.json` 的去留口径：**文件存在 ⟺ 连接正在运行**，自检结论不参与。
//!
//! 命令行端到端两条（界面路径的同一场景在 `src/ipc.rs` 的
//! `ipc_connect_keeps_runtime_engine_config_until_disconnect`，两边同一口径）：
//! 1. 坏成员：引擎活着、探测口没人监听 → 连接在跑，文件必须在；`--disconnect` 之后必须删。
//! 2. 引擎秒退：假引擎起来即退 → 连接失败，文件**事后**必须不存在。
//!
//! 系统代理一律写临时键（`SPIDERVPN_PROXY_KEY`），真机网络设置一个字节都不碰。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const PING: &str = r"C:\Windows\System32\PING.EXE";

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-re-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时数据根");
    p
}

fn proxy_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\re-{tag}-{}", std::process::id())
}

/// 建一个可读的临时「系统代理」键：读不到代理时连接会被拒绝（那是另一条用例的现场）。
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

/// 跑一次本程序。`engine_args` 通过测试缝隙交给假引擎（不设就按真引擎的参数形状跑）。
///
/// 输出落**文件**而不是管道：假引擎活得比连接进程久，管道写端被它继承时
/// `wait_with_output` 会一直等到引擎退出（实测把「连接后立刻检查」拖成 30 秒后检查）。
fn run(root: &Path, key: &str, args: &[&str], engine_args: &str) -> (Option<i32>, String) {
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
            format!(r"Software\SpiderVPN\tests\re-run-{}", std::process::id()),
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
            let out = std::fs::read_to_string(&out_path).unwrap_or_default();
            return (status.code(), out);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 60 秒未退出（{args:?}）");
}

fn free_port() -> u16 {
    // 端口要留出「+3」：随机端口的 +3 可能越过 65532，导入会按 65532 上限拒绝。
    loop {
        let p = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if p <= 60_000 {
            return p;
        }
    }
}

fn write_profile(root: &Path) -> PathBuf {
    let dir = root.join("src");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("dual-mode.json");
    std::fs::write(
        &f,
        r#"{
            "inbounds": [{ "type": "tun", "tag": "trade-tun" }],
            "route": { "rules": [], "final": "daily-exit" },
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" },
                { "type": "selector", "tag": "daily-exit", "outbounds": ["direct"], "default": "direct" }
            ]
        }"#,
    )
    .unwrap();
    f
}

/// 运行记录里的引擎 pid 还活着吗。
///
/// 集成测试拿不到 crate 内的探针，也不能指望外部命令（受限环境下 `tasklist` 这类会挂）：
/// 改成问产品自己——`--status` 只有在「引擎活着、守护已退出」时才会报「连接需要处理」，
/// 引擎死了它会报「未连接」。这句话就是「引擎还在跑」的证据。
fn status_while_engine_runs(root: &Path, key: &str) -> String {
    let (code, out) = run(root, key, &["--status"], "-n 30 127.0.0.1");
    assert_eq!(code, Some(0), "--status 应当成功：{out}");
    out
}

/// 一条导入好的线路（端口随机），引擎是假引擎 PING。
fn setup(root: &Path, key: &str) -> u16 {
    make_proxy_key(key);
    let profile = write_profile(root);
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
            "坏成员线路",
        ],
        "-n 30 127.0.0.1",
    );
    assert_eq!(code, Some(0), "导入应当成功：{out}");
    port
}

#[test]
fn cli_keeps_runtime_engine_config_while_a_bad_member_is_connected() {
    // 坏成员的等价现场：引擎活着、代理已接管、没有任何东西监听线路端口（自检必然不过）。
    let root = tmp_root("cli-keep");
    let key = proxy_key("keep");
    let _port = setup(&root, &key);
    let data = root.join("data");
    let runtime_engine = data.join("runtime-engine.json");
    assert!(!runtime_engine.exists(), "连接之前不该有这个文件");

    let (code, out) = run(&root, &key, &["--connect"], "-n 30 127.0.0.1");
    assert_eq!(code, Some(0), "假引擎活着，连接应当成功：{out}");
    assert!(out.contains("启动引擎 pid="), "连接事务要真的起了引擎：{out}");
    // 「连接在跑」要有证据：运行记录里写着引擎 pid，且产品自己确认引擎还在（见上函数注释）。
    let rec: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("runtime.json")).expect("运行记录"))
            .unwrap();
    assert!(rec["EnginePid"].as_i64().unwrap_or(0) > 0, "运行记录必须有引擎 pid：{rec}");
    assert_eq!(rec["State"], "Running");
    let st = status_while_engine_runs(&root, &key);
    assert!(
        st.contains("连接需要处理"),
        "引擎还在跑、守护已退出时 --status 必须报「连接需要处理」（报未连接说明引擎已死）：{st}"
    );
    assert!(runtime_engine.exists(), "连接在跑，运行时配置必须在：{out}");
    assert!(runtime_engine.metadata().unwrap().len() > 0, "文件不能是空的");
    // 自检没过/跳过都不影响上面这条：这里只说「自检跑过了、给了结论」。
    assert!(
        out.contains("通道自检") || out.contains("自检跳过"),
        "连接后必须有自检结论：{out}"
    );

    let (code, out) = run(&root, &key, &["--disconnect"], "-n 30 127.0.0.1");
    assert_eq!(code, Some(0), "断开应当成功：{out}");
    assert!(!runtime_engine.exists(), "断开之后运行时配置必须删除：{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cli_connect_with_an_instantly_exiting_engine_leaves_no_runtime_engine_config() {
    // 引擎秒退：spawn 成功但活不过观察窗 → 连接返回「启动后立即退出」，文件不许留下
    //（它带着本次探测凭据，留着就是一条假证据）。只看**事后**最终态。
    let root = tmp_root("cli-die");
    let key = proxy_key("die");
    let _port = setup(&root, &key);
    let runtime_engine = root.join("data").join("runtime-engine.json");

    // `ping -n 0` 立刻报参数错误并退出：正是「起来即退」。
    let (code, out) = run(&root, &key, &["--connect"], "-n 0 127.0.0.1");
    assert_eq!(code, Some(5), "引擎秒退必须连接失败（网络类）：{out}");
    assert!(out.contains("引擎启动后立即退出"), "原因要指到引擎秒退上：{out}");
    assert!(!runtime_engine.exists(), "连接没进入运行态，运行时配置必须不存在：{out}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}
