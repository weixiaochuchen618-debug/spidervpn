//! 接管方式切换的端到端：**切换必须在连接前真的落地**（改运行时配置的入站），
//! 而不是只改一行 config.json。
//!
//! 分工：
//! - `ipc::tests::set_mode_*` 证明命令本身（写偏好、无 TUN 素材时拒绝、连接中拒绝）；
//! - 这里证明"写下的偏好会变成引擎实际吃的那份配置"，以及 `--status` 跟着走。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const PING: &str = r"C:\Windows\System32\PING.EXE";
const ENGINE_ALIVE: &str = "-n 300 127.0.0.1";
/// 带 TUN 入站的线路文件（`trade-tun` + mixed），模拟 旧版的 dual-mode.json。
const TUN_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/engine-tun.json");

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-mode-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

fn proxy_key(tag: &str) -> String {
    format!(r"Software\SpiderVPN\tests\mode-{tag}-{}", std::process::id())
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

/// 真实提权路径只允许启动与 SpiderVPN 同目录的 bundled sing-box.exe。
/// E2E 使用隔离安装布局：把系统 ping 作为无网络副作用的假引擎复制进
/// 该布局；不绕过生产校验，也不依赖 CI runner 是否已提权。
fn test_install(root: &Path) -> (PathBuf, PathBuf) {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("建立隔离 bin");
    let frontend = bin.join("spidervpn.exe");
    let engine = bin.join("sing-box.exe");
    if !frontend.is_file() {
        std::fs::copy(env!("CARGO_BIN_EXE_spidervpn"), &frontend)
            .expect("复制真实 Rust 客户端到隔离 bin");
    }
    if !engine.is_file() {
        std::fs::copy(PING, &engine).expect("复制无害系统假引擎到隔离 bin");
    }
    (frontend, engine)
}

fn run(root: &Path, key: &str, args: &[&str]) -> (Option<i32>, String) {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let n = RUNS.fetch_add(1, Ordering::Relaxed);
    let out_path = root.join(format!("cli-{n}.out"));
    let err_path = root.join(format!("cli-{n}.err"));
    let (frontend, _) = test_install(root);
    let mut child = Command::new(&frontend)
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env("SPIDERVPN_PROXY_KEY", key)
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\mode-run-{}", std::process::id()),
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
        if p <= 60_000 {
            return p;
        }
    }
}

fn import(root: &Path, key: &str, tun: bool) {
    let port = free_port().to_string();
    let (_, engine) = test_install(root);
    let engine_path = engine.to_str().expect("隔离测试引擎路径必须为 UTF-8");
    let mut args = vec!["--import", TUN_FIXTURE, "--engine", engine_path, "--port", &port, "--line-name", "双模式线路"];
    if tun {
        args.push("--tun");
    }
    let (code, out) = run(root, key, &args);
    assert_eq!(code, Some(0), "导入应当成功：{out}");
}

/// 把 config.json 的 mode 改成指定值——这正是 `set-mode` 写盘的那一个字段
/// （命令本身由 `ipc::tests::set_mode_*` 覆盖；这里要证明"写下之后真的生效"）。
fn write_mode(root: &Path, mode: &str) {
    let p = root.join("data").join("config.json");
    let text = std::fs::read_to_string(&p).expect("config.json");
    let mut v: serde_json::Value = serde_json::from_str(&text).expect("合法 JSON");
    v["mode"] = serde_json::json!(mode);
    std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).expect("写 config.json");
}

fn runtime_inbounds(root: &Path) -> Vec<serde_json::Value> {
    let p = root.join("data").join("runtime-engine.json");
    let text = std::fs::read_to_string(&p).expect("连上之后必须有运行时配置");
    let v: serde_json::Value = serde_json::from_str(&text).expect("合法 JSON");
    v["inbounds"].as_array().cloned().unwrap_or_default()
}

#[test]
fn the_saved_mode_really_lands_in_the_runtime_config() {
    let root = tmp_root("switch");
    let key = proxy_key("switch");
    make_proxy_key(&key);
    // ① 用 --tun 导入：线路文件里保留 TUN 入站，偏好也是 TUN
    import(&root, &key, true);
    let (code, st) = run(&root, &key, &["--status"]);
    assert_eq!(code, Some(0), "{st}");
    assert!(st.contains("模式      ：TUN"), "导入后 --status 要显示 TUN：{st}");

    // ② 连接：运行时配置里必须有 TUN 入站，且网卡名是我们自己的
    let (code, out) = run(&root, &key, &["--connect"]);
    assert_eq!(code, Some(0), "假引擎活着，连接应当成功：{out}");
    let tun = runtime_inbounds(&root).into_iter().find(|i| i["type"] == "tun");
    let mut tun = tun.expect("选了 TUN，运行时配置里必须有 TUN 入站");
    assert_eq!(tun["interface_name"], "SpiderVPN", "网卡名要改成自己的：{tun}");
    // 「参数一字不动」这么说就按字面比：除了网卡名，其余字段必须与导入时那份完全相同。
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(TUN_FIXTURE).unwrap()).unwrap();
    let mut want = src["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "tun")
        .cloned()
        .expect("夹具里应当有 TUN 入站");
    want.as_object_mut().unwrap().insert(
        "interface_name".to_string(),
        serde_json::json!("SpiderVPN"),
    );
    assert_eq!(tun, want, "TUN 参数必须与导入时那份一致（除了网卡名）");
    let _ = &mut tun;

    // ③ 切到代理（等价 set-mode proxy 写盘）→ 重连：运行时配置里不许再有 TUN
    let (code, out) = run(&root, &key, &["--disconnect"]);
    assert_eq!(code, Some(0), "{out}");
    write_mode(&root, "proxy");
    let (code, out) = run(&root, &key, &["--connect"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        !runtime_inbounds(&root).iter().any(|i| i["type"] == "tun"),
        "选了代理就不能留 TUN 入站（否则仍要管理员、仍改路由）"
    );
    let (_, st) = run(&root, &key, &["--status"]);
    assert!(st.contains("模式      ：代理"), "连接中 --status 要报实际在跑的模式：{st}");

    // ④ 断开后再切回 TUN：这次不连接也要能从 --status 看出来（偏好已写回）
    let (code, out) = run(&root, &key, &["--disconnect"]);
    assert_eq!(code, Some(0), "{out}");
    write_mode(&root, "tun");
    let (_, st) = run(&root, &key, &["--status"]);
    assert!(st.contains("模式      ：TUN"), "{st}");

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn choosing_tun_on_a_proxy_only_line_refuses_at_connect_time() {
    // 没有 TUN 素材的线路硬要 TUN：连接前就拒绝，不许"起了引擎才发现"。
    let root = tmp_root("notun");
    let key = proxy_key("notun");
    make_proxy_key(&key);
    import(&root, &key, false); // 不带 --tun：线路文件里没有 TUN 入站
    write_mode(&root, "tun");
    let (code, out) = run(&root, &key, &["--connect"]);
    assert_eq!(code, Some(3), "TUN 模式但线路没有 TUN 入站，属配置问题：{out}");
    assert!(out.contains("接管方式不可用"), "{out}");
    assert!(out.contains("没有 TUN 入站"), "要说清缺什么：{out}");
    assert!(!root.join("data").join("proxy-journal.json").exists(), "拒绝时不许动系统代理");
    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tun_connect_works_without_a_readable_proxy_key() {
    // QA 的现场：机器上根本没有可读的系统代理键。
    // TUN 压根不写代理，所以这条 preflight 不该挡住它（之前会 exit 13）。
    let key = proxy_key("nokey");
    drop_proxy_key(&key); // 确保键不存在

    // ① 先证明这个现场确实是"没有代理键"：代理模式必须被拒（否则这条用例的前提不成立）
    let root_proxy = tmp_root("nokey-proxy");
    import(&root_proxy, &key, false);
    let (code, out) = run(&root_proxy, &key, &["--connect"]);
    // 走完连接流程才失败（读不到代理键）→ 归网络/连接失败，可重试；不是 argv 或配置问题。
    assert_eq!(code, Some(5), "没有代理键时连接失败：{out}");
    assert!(!out.contains("管理员"), "拒绝原因是代理键，不是权限：{out}");
    assert!(!root_proxy.join("data").join("proxy-journal.json").exists(), "被拒时不许落凭据");

    // ② 同一现场，TUN：不读代理键，照样连上；不写还原凭据
    let root_tun = tmp_root("nokey-tun");
    import(&root_tun, &key, true);
    let (code, out) = run(&root_tun, &key, &["--connect"]);
    assert_eq!(code, Some(0), "TUN 不该被代理键挡住：{out}");
    assert!(
        !root_tun.join("data").join("proxy-journal.json").exists(),
        "TUN 不写还原凭据（它没改过代理）"
    );
    let (_, st) = run(&root_tun, &key, &["--status"]);
    assert!(st.contains("模式      ：TUN"), "{st}");

    // ③ 断开：代理键仍然不存在（一次都没碰过）
    let (code, out) = run(&root_tun, &key, &["--disconnect"]);
    assert_eq!(code, Some(0), "{out}");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    assert!(
        hkcu.open_subkey(&key).is_err(),
        "TUN 的连接与断开都不许碰系统代理键"
    );

    drop_proxy_key(&key);
    let _ = std::fs::remove_dir_all(&root_proxy);
    let _ = std::fs::remove_dir_all(&root_tun);
}
