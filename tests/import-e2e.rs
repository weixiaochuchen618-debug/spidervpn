//! `--import` 的端到端验收：跑真实可执行文件，断言它在本机磁盘上真的产出了什么。
//!
//! 为什么放在 `tests/`：单元测试里拿不到 `CARGO_BIN_EXE_*`，只能靠 `current_exe` 推路径，
//! 而 `cargo test` 在没有集成测试时**不会**构建普通 bin——那样的用例在干净 target 目录上必假失败。
//! 放在这里，cargo 保证先构建 bin 再跑本用例。
//!
//! 数据根一律用环境变量只传给子进程（不在本进程 `set_var`，否则会和并行用例抢全局环境）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 每个用例一个独立数据根：进程内并行跑也不会互删文件。
fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-import-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时目录");
    p
}

/// 造一份线路文件，目录层级照抄真实布局 `lines\<LineId>\profiles\<ProfileId>\dual-mode.json`。
fn write_profile(root: &Path) -> PathBuf {
    let dir = root.join("lines").join("L-fixture").join("profiles").join("Tcp-r1-fixture");
    std::fs::create_dir_all(&dir).expect("建线路目录");
    let f = dir.join("dual-mode.json");
    let body = r#"{
        "log": { "level": "warn" },
        "inbounds": [{ "type": "tun", "tag": "trade-tun", "auto_route": true }],
        "route": { "final": "direct" },
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    }"#;
    std::fs::write(&f, body).expect("写线路文件");
    f
}

/// 跑一次本程序（`--import` / `--status` 都用它），返回（退出码，stdout）。
///
/// 带超时不是多此一举：参数一旦被忽略，程序会走到界面分支并挂着不退出，
/// 那会把整个测试门禁卡死——「挂死」比「失败」更难查。
fn run_cli_streams(root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
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
            return (
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).to_string(),
                String::from_utf8_lossy(&out.stderr).to_string(),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 30 秒未退出：参数是不是被忽略了、走到了界面分支？");
}

fn run_cli(root: &Path, args: &[&str]) -> (Option<i32>, String) {
    let (code, out, _) = run_cli_streams(root, args);
    (code, out)
}

#[test]
fn missing_profile_failure_goes_to_stderr_without_indent() {
    // T-08 DoD④ 的可测部分：界面 `.msg` 与 CLI 取同一句（都走 import_failure），
    // 所以 stderr 里不能有缩进——界面显示的是 `text` 原文，多两个空格就不是同一句了。
    let root = tmp_root("missing-profile");
    let args = [
        "--import",
        "C:/nope/missing.json",
        "--engine",
        "C:/Windows/System32/PING.EXE",
    ];
    let (code, stdout, stderr) = run_cli_streams(&root, &args);
    assert_eq!(code, Some(3), "线路文件不存在属配置/文件类：{stderr}");
    assert!(!stderr.trim().is_empty(), "失败必须写到 stderr");
    assert!(!stderr.starts_with(' '), "不得带缩进，否则与界面显示的不是同一句：{stderr:?}");
    assert!(stderr.contains("missing.json"), "要点名是哪个文件：{stderr}");
    assert!(
        !stdout.contains("missing.json"),
        "同一句只在 stderr 出现一次，避免两路各说一遍：{stdout}"
    );
}

#[test]
fn import_writes_engine_config_and_line() {
    let root = tmp_root("with-name");
    let profile = write_profile(&root);
    let (code, stdout) = run_cli(
        &root,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C:\Windows\System32\PING.EXE",
            "--port",
            "17895",
            "--line-name",
            "香港 01",
        ],
    );
    assert_eq!(code, Some(0), "--import 应当成功：{stdout}");

    let data = root.join("data");
    // 引擎配置按线路落盘：`lines\<id>.json`（id 是名字的 slug）。"香港 01" → 99996e2f01
    let line_json = data.join("lines").join("99996e2f01.json");
    let ej: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&line_json).expect("每条线路的引擎配置必须已生成"),
    )
    .expect("引擎配置必须是合法 JSON");
    let inb = ej["inbounds"].as_array().expect("inbounds 必须是数组");
    assert_eq!(inb.len(), 1, "TUN 入站必须已被整体替换");
    assert_eq!(inb[0]["type"], "mixed");
    assert_eq!(inb[0]["listen"], "127.0.0.1");
    assert_eq!(inb[0]["listen_port"], 17895);
    assert_eq!(ej["outbounds"][0]["tag"], "direct", "节点必须原样保留");
    assert_eq!(ej["route"]["final"], "direct", "route 必须原样保留");
    assert!(!line_json.with_extension("json.tmp").exists(), "临时文件必须已被替换掉");

    let cfg_text = std::fs::read_to_string(data.join("config.json")).expect("config.json 必须已生成");
    let cfg: serde_json::Value = serde_json::from_str(&cfg_text).expect("config.json 必须是合法 JSON");
    assert_eq!(cfg["schema"], 2, "导入写的是 schema 2：{cfg}");
    assert_eq!(cfg["lines"][0]["proxy_endpoint"], "127.0.0.1:17895");
    assert_eq!(cfg["lines"][0]["name"], "香港 01");
    assert_eq!(cfg["lines"][0]["id"], "99996e2f01", "id 是名字的 slug（内部标识，不展示）");
    assert_eq!(cfg["selected"], "99996e2f01", "导入后自动选中这条");
    assert_eq!(cfg["engine"]["binary"], r"C:\Windows\System32\PING.EXE");
    assert!(
        cfg["engine"].get("args").is_none(),
        "schema 2 不再存 args：`-c` 按线路派生：{cfg}"
    );
    assert!(stdout.contains("17895"), "输出要说清做了什么：{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_without_line_name_uses_profile_dir_and_default_port() {
    let root = tmp_root("no-name");
    let profile = write_profile(&root);
    let (code, stdout) = run_cli(
        &root,
        &["--import", &profile.to_string_lossy(), "--engine", r"C:\Windows\System32\PING.EXE"],
    );
    assert_eq!(code, Some(0), "--import 应当成功：{stdout}");

    let data = root.join("data");
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).expect("config.json 必须已生成"))
            .expect("config.json 必须是合法 JSON");
    assert_eq!(cfg["lines"][0]["id"], "Tcp-r1-fixture", "没给 --line-name 时用 profile 所在目录名");
    assert_eq!(cfg["lines"][0]["name"], "Tcp-r1-fixture", "名称缺省时用 id");
    assert_eq!(cfg["lines"][0]["proxy_endpoint"], "127.0.0.1:17890", "没给 --port 时用默认端口");
    assert_eq!(cfg["selected"], "Tcp-r1-fixture");
    let per_line = data.join("lines").join("Tcp-r1-fixture.json");
    let ej: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&per_line).expect("线路的引擎配置必须已生成"))
            .expect("引擎配置必须是合法 JSON");
    assert_eq!(ej["inbounds"][0]["listen_port"], 17890, "引擎配置的端口必须与线路端点一致");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_without_engine_is_rejected_and_writes_nothing() {
    let root = tmp_root("no-engine");
    let profile = write_profile(&root);
    let (code, stdout) = run_cli(&root, &["--import", &profile.to_string_lossy()]);
    assert_eq!(code, Some(2), "缺 --engine 是用法错误：{stdout}");
    assert!(stdout.contains("--engine"), "错误要指明缺哪个参数：{stdout}");
    let data = root.join("data");
    assert!(!data.join("lines").exists(), "报错时不得留下任何线路的引擎配置");
    assert!(!data.join("config.json").exists(), "报错时不得留下线路配置");
    let _ = std::fs::remove_dir_all(&root);
}

/// 带真节点出口的线路文件：TUN 的两条分流规则只在能找到出口时才插得进去，
/// 所以这条用例的夹具必须有一个非 direct 的出站（真实线路里是 `trade-exit`）。
fn write_profile_with_node(root: &Path) -> PathBuf {
    let dir = root.join("lines").join("L-tun").join("profiles").join("Tcp-r1-tun");
    std::fs::create_dir_all(&dir).expect("建线路目录");
    let f = dir.join("dual-mode.json");
    let body = r#"{
        "log": { "level": "warn" },
        "inbounds": [{
            "type": "tun", "tag": "trade-tun", "interface_name": "TradeChannel",
            "address": ["172.30.250.1/30", "fd42:7472:6164::1/126"],
            "mtu": 1380, "stack": "gvisor", "auto_route": true, "strict_route": true
        }],
        "route": { "rules": [{ "action": "route", "outbound": "trade-exit" }], "final": "direct" },
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" }
        ]
    }"#;
    std::fs::write(&f, body).expect("写线路文件");
    f
}

#[test]
fn import_with_tun_flag_writes_tun_mode_and_status_shows_it() {
    let root = tmp_root("tun");
    let profile = write_profile_with_node(&root);
    let (code, stdout) = run_cli(
        &root,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C:/Windows/System32/PING.EXE",
            "--tun",
        ],
    );
    assert_eq!(code, Some(0), "--import --tun 应当成功：{stdout}");

    let data = root.join("data");
    // 1) 线路配置记下了模式
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).expect("config.json 必须已生成"))
            .expect("config.json 必须是合法 JSON");
    assert_eq!(cfg["mode"], "tun", "带 --tun 导入后模式必须是 tun：{cfg}");

    // 2) 引擎配置：TUN 入站 + mixed 入站并存，TUN 参数一字未改（按线路落盘）
    //    线路 id 从配置里取：不同名字的 slug 不同，别在测试里硬编码。
    let id = cfg["selected"].as_str().expect("导入后必须有选中的线路");
    let per_line = data.join("lines").join(format!("{id}.json"));
    let ej: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&per_line).expect("线路的引擎配置必须已生成"))
            .expect("引擎配置必须是合法 JSON");
    let inb = ej["inbounds"].as_array().expect("inbounds 必须是数组");
    assert_eq!(inb.len(), 3, "TUN 与 mixed 并存，末尾再补自检探测入站：{inb:?}");
    assert_eq!(inb[0]["type"], "tun");
    assert_eq!(inb[0]["tag"], "trade-tun", "TUN 入站的 tag 原样沿用");
    assert_eq!(inb[0]["mtu"], 1380, "mtu 是 旧版调好的，不许改");
    assert_eq!(inb[0]["stack"], "gvisor");
    assert_eq!(inb[0]["address"][0], "172.30.250.1/30");
    assert_eq!(inb[1]["type"], "mixed");
    // 探测入站（tc-check）：只监听本机，端口 = mixed 端口 + 3，不带写死凭据（连接时才注入）
    let mixed_port = inb[1]["listen_port"].as_u64().expect("mixed 端口");
    assert_eq!(inb[2]["tag"], "tc-check", "探测入站排在最后：{inb:?}");
    assert_eq!(inb[2]["type"], "socks");
    assert_eq!(inb[2]["listen"], "127.0.0.1");
    assert_eq!(inb[2]["listen_port"].as_u64().unwrap(), mixed_port + 3, "探测端口 = mixed + 3");

    // 3) 最优先规则：探测规则在最前（自检必经交易出口），随后 mixed 与 TUN 都走节点
    let rules = ej["route"]["rules"].as_array().expect("rules 必须是数组");
    assert_eq!(rules[0]["inbound"][0], "tc-check", "首条是探测规则");
    assert_eq!(rules[0]["outbound"], "trade-exit", "探测固定走交易出口");
    assert_eq!(rules[1]["inbound"][0], "tc-mixed");
    assert_eq!(rules[2]["inbound"][0], "trade-tun");
    for r in &rules[..3] {
        assert_eq!(r["outbound"], "trade-exit", "{r} 必须指向节点出口");
    }
    assert_eq!(ej["route"]["final"], "trade-exit");

    // 4) --status 要如实报模式
    let (c2, out2) = run_cli(&root, &["--status"]);
    assert_eq!(c2, Some(0), "--status 应当成功：{out2}");
    assert!(out2.contains("模式      ：TUN"), "TUN 模式要显示出来：{out2}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_refuses_a_port_whose_probe_port_is_taken() {
    // 探测端口（端口+3）被别人占着 → 自检永远只能「跳过」，那是用户看不见的坏状态：
    // 导入时就试绑一次并拒绝，文案说清是哪个端口、该怎么办。
    let root = tmp_root("probe-taken");
    let profile = write_profile(&root);
    // 挑一对都空的端口：随机端口的 +3 可能溢出 u16，固定端口可能被本机占用。
    let port = (20_000..60_000u16)
        .find(|p| {
            std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok()
                && std::net::TcpListener::bind(("127.0.0.1", p + 3)).is_ok()
        })
        .expect("找一对空闲端口");
    let holder = std::net::TcpListener::bind(("127.0.0.1", port + 3)).expect("占住探测端口");

    let args = [
        "--import",
        &profile.to_string_lossy(),
        "--engine",
        r"C:/Windows/System32/PING.EXE",
        "--port",
        &port.to_string(),
        "--line-name",
        "端口占用线路",
    ];
    let (code, _stdout, stderr) = run_cli_streams(&root, &args);
    assert_eq!(code, Some(6), "探测端口被占是冲突，需换端口：{stderr}");
    assert!(
        stderr.contains(&format!(
            "端口冲突：端口 {port} 不可用：它的自检探测端口 {} 已被占用或被系统预留。请换一个线路端口。",
            port + 3
        )),
        // 失败文案走 stderr（T-08）：界面 .msg 与 CLI stderr 必须是同一句，含冲突前缀。
        "文案走 stderr，且要点明是哪个探测端口：{stderr}"
    );
    assert!(!root.join("data").join("config.json").exists(), "被拒绝时不许写配置");

    // 放掉之后同一个端口必须能导入（证明前面是试绑判定，不是把端口记住了）
    drop(holder);
    let (code, out) = run_cli(&root, &args);
    assert_eq!(code, Some(0), "探测端口释放后应当导入成功：{out}");
    let _ = std::fs::remove_dir_all(&root);
}
