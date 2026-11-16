//! 分流规则（进程 / 域名 → 直连）的端到端：命令、落盘、导入时的引擎配置生成。
//!
//! 一律临时根 + 临时代理键；**绝不碰默认数据根**（夹具第一件事就是设 `SPIDERVPN_ROOT`，
//! 缺了直接 panic 退出）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-split-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

fn run(root: &Path, args: &[&str]) -> (Option<i32>, String) {
    // 保险：没有临时根就绝不启动（否则写操作会落到用户默认根）。
    assert!(!root.as_os_str().is_empty(), "必须给临时数据根");
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env(
            "SPIDERVPN_PROXY_KEY",
            format!(r"Software\SpiderVPN\tests\split-{}", std::process::id()),
        )
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\split-run-{}", std::process::id()),
        )
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

fn cfg_json(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join("data").join("config.json")).expect("config.json");
    serde_json::from_str(&text).expect("config.json 必须是合法 JSON")
}

fn write_profile(root: &Path) -> PathBuf {
    let dir = root.join("src");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("dual-mode.json");
    std::fs::write(
        &f,
        r#"{
            "inbounds": [{ "type": "tun", "tag": "trade-tun" }],
            "route": { "rules": [], "final": "direct" },
            "outbounds": [{ "type": "direct", "tag": "direct" },
                          { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" }]
        }"#,
    )
    .unwrap();
    f
}

#[test]
fn split_add_process_and_domain_are_stored_and_listed() {
    let root = tmp_root("add");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17941"]).0, Some(0));

    let (code, out) = run(&root, &["--split-add-process", "TDXW.exe"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已添加分流进程"), "{out}");
    // 域名带 *. 前缀：存进去要去掉
    let (code, out) = run(&root, &["--split-add-domain", "*.qq.com"]);
    assert_eq!(code, Some(0), "{out}");

    let cfg = cfg_json(&root);
    assert_eq!(cfg["split"]["processes"][0], "TDXW.exe", "{cfg}");
    assert_eq!(cfg["split"]["domains"][0], "qq.com", "落盘要去掉 *：{cfg}");

    let (code, out) = run(&root, &["--split-list"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("TDXW.exe") && out.contains("qq.com"), "{out}");
    assert!(!out.contains("*.qq.com"), "列表里也不该出现通配符原文：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_add_is_idempotent_and_case_insensitive() {
    let root = tmp_root("dup");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17942"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-process", "TDXW.exe"]).0, Some(0));
    let (code, out) = run(&root, &["--split-add-process", "tdxw.EXE"]);
    assert_eq!(code, Some(0), "重复添加不是错误：{out}");
    assert!(out.contains("已存在"), "要说清什么都没变：{out}");
    let cfg = cfg_json(&root);
    assert_eq!(cfg["split"]["processes"].as_array().unwrap().len(), 1, "{cfg}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_remove_clears_entries_and_empty_means_all_through_node() {
    let root = tmp_root("remove");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17943"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-process", "TDXW.exe"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-domain", "qq.com"]).0, Some(0));

    assert_eq!(run(&root, &["--split-remove-process", "tdxw.exe"]).0, Some(0));
    let cfg = cfg_json(&root);
    assert!(cfg["split"]["processes"].as_array().unwrap().is_empty(), "{cfg}");
    assert_eq!(run(&root, &["--split-remove-domain", "*.qq.com"]).0, Some(0));
    let cfg = cfg_json(&root);
    assert!(cfg["split"]["domains"].as_array().unwrap().is_empty(), "{cfg}");

    let (code, out) = run(&root, &["--split-list"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("（空）"), "空规则要说清全部走节点：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_edit_is_refused_while_connected_with_no_side_effect() {
    let root = tmp_root("busy");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17944"]).0, Some(0));
    // 有还原凭据 = 正在接管/正在连接
    let journal = root.join("data").join("proxy-journal.json");
    std::fs::write(&journal, r#"{"schema":1}"#).unwrap();
    let before = std::fs::read(root.join("data").join("config.json")).unwrap();

    for cmd in [
        ["--split-add-process", "TDXW.exe"],
        ["--split-add-domain", "qq.com"],
        ["--split-remove-process", "TDXW.exe"],
    ] {
        let (code, out) = run(&root, &cmd);
        assert_eq!(code, Some(4), "{:?} 连接中不允许改分流（当前状态未就绪）：{out}", cmd);
        assert!(out.contains("请先断开"), "错误要告诉用户先断开：{out}");
    }
    // 零副作用：配置一个字节都没变
    assert_eq!(
        std::fs::read(root.join("data").join("config.json")).unwrap(),
        before,
        "被拒绝时不许改配置"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_bakes_the_split_rules_into_the_engine_config() {
    // 这是分流的"最后一公里"：规则必须真的落进引擎配置文件，否则写了等于没写。
    let root = tmp_root("import");
    let profile = write_profile(&root);
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17945"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-process", "curl.exe"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-domain", "*.qq.com"]).0, Some(0));

    let (code, out) = run(
        &root,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C:\Windows\System32\PING.EXE",
            "--port",
            "17945",
            "--line-name",
            "线路甲",
        ],
    );
    assert_eq!(code, Some(0), "{out}");

    let cfg = cfg_json(&root);
    let id = cfg["selected"].as_str().unwrap();
    let engine_path = root.join("data").join("lines").join(format!("{id}.json"));
    let ej: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&engine_path).unwrap()).unwrap();
    let rules = ej["route"]["rules"].as_array().expect("rules 必须是数组");
    assert_eq!(rules[0]["process_name"][0], "curl.exe", "进程规则要在最前面：{rules:?}");
    assert_eq!(rules[0]["outbound"], "direct", "要指向 direct 出站");
    assert_eq!(rules[1]["domain_suffix"][0], "qq.com", "域名规则第二：{rules:?}");
    assert!(!serde_json::to_string(&ej).unwrap().contains("*.qq.com"), "不许带通配符原文");
    // 分流规则在导入后仍留在配置里（导入只换线路与引擎）
    assert_eq!(cfg["split"]["processes"][0], "curl.exe", "{cfg}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_added_after_import_takes_effect_in_the_engine_config() {
    // 缺陷回归：`--import` 之后再 `--split-add-*`，规则必须立刻进线路的引擎配置。
    // 反过来说：把"改完同步到线路文件"那段去掉，这条会红。
    let root = tmp_root("after-import");
    let profile = write_profile(&root);
    let (code, out) = run(
        &root,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C://Windows//System32//PING.EXE",
            "--port",
            "17947",
            "--line-name",
            "线路甲",
        ],
    );
    assert_eq!(code, Some(0), "{out}");
    let cfg = cfg_json(&root);
    let id = cfg["selected"].as_str().unwrap().to_string();
    let engine_path = root.join("data").join("lines").join(format!("{id}.json"));
    let before: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&engine_path).unwrap()).unwrap();
    assert!(
        !before["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("process_name").is_some()),
        "导入时还没有规则：{before}"
    );

    // 关键一步：导入之后再加规则
    let (code, out) = run(&root, &["--split-add-process", "curl.exe"]);
    assert_eq!(code, Some(0), "{out}");
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&engine_path).unwrap()).unwrap();
    assert_eq!(
        after["route"]["rules"][0]["process_name"][0], "curl.exe",
        "加完规则必须立刻进引擎配置（否则连上去根本不生效）：{after}"
    );
    assert_eq!(after["route"]["rules"][0]["outbound"], "direct");

    // 删除后也要从引擎配置里消失
    let (code, out) = run(&root, &["--split-remove-process", "curl.exe"]);
    assert_eq!(code, Some(0), "{out}");
    let cleared: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&engine_path).unwrap()).unwrap();
    assert!(
        !cleared["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("process_name").is_some()),
        "删掉规则后引擎配置里也不许留着：{cleared}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_scope_hint_appears_only_in_proxy_mode_with_process_rules() {
    // 进程规则在两种模式下都生效；要提示的是"覆盖范围"：系统代理模式只影响经过我们的流量。
    let root = tmp_root("scope");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17961"]).0, Some(0));
    let (code, out) = run(&root, &["--split-add-process", "TDXW.exe"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("只有经过本程序的流量才受分流规则影响"), "proxy 模式加进程规则要给提示：{out}");
    assert!(out.contains("TUN 模式"), "提示要给出更彻底的做法：{out}");
    let (_, list) = run(&root, &["--split-list"]);
    assert!(list.contains("只有经过本程序的流量才受分流规则影响"), "列表里也要带：{list}");

    // 切到 TUN：提示消失
    let profile = write_profile(&root);
    assert_eq!(
        run(
            &root,
            &[
                "--import",
                &profile.to_string_lossy(),
                "--engine",
                r"C://Windows//System32//PING.EXE",
                "--port",
                "17961",
                "--line-name",
                "线路甲",
                "--tun",
            ],
        )
        .0,
        Some(0)
    );
    let (_, list) = run(&root, &["--split-list"]);
    assert!(!list.contains("只有经过本程序的流量才受分流规则影响"), "TUN 模式不该再有这条提示：{list}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_input_validation_rejects_bad_forms_without_touching_the_config() {
    let root = tmp_root("validate");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17962"]).0, Some(0));
    let before = std::fs::read(root.join("data").join("config.json")).unwrap();

    let cases: [(&str, &str, &str); 4] = [
        // (命令, 值, 期望文案片段)
        ("--split-add-process", r"C://Program Files//TDXW.exe", "不要填完整路径"),
        ("--split-add-process", "TDXW", ".exe 结尾"),
        ("--split-add-domain", "https://qq.com", "不要带协议或路径"),
        ("--split-add-domain", "localhost", "至少要有两级"),
    ];
    for (cmd, value, want) in cases {
        let (code, out) = run(&root, &[cmd, value]);
        assert_eq!(code, Some(2), "{cmd} {value} 取值非法，属用法错误：{out}");
        assert!(out.contains(want), "{cmd} {value} 的文案要含「{want}」：{out}");
        assert_eq!(
            std::fs::read(root.join("data").join("config.json")).unwrap(),
            before,
            "被拒绝时配置一个字节都不许变（{cmd} {value}）"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_scope_hint_also_shows_for_domain_only_rules() {
    // 这条限制对域名规则同样成立：用户配了域名规则、某个程序还是照旧时，需要一个说法。
    let root = tmp_root("scope-dom");
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", "127.0.0.1:17963"]).0, Some(0));
    let (code, out) = run(&root, &["--split-add-domain", "qq.com"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("只有经过本程序的流量才受分流规则影响"),
        "只有域名规则时也要提示：{out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 造一条线路，并让它**实际是 TUN**（lines/<id>.json 里有 tun 入站）。
fn make_line_actual_mode(root: &Path, id: &str, tun: bool) {
    let data = root.join("data");
    let lines = data.join("lines");
    std::fs::create_dir_all(&lines).unwrap();
    let inb = if tun {
        r#"{"type":"tun","tag":"trade-tun","interface_name":"SpiderVPN"}"#
    } else {
        r#"{"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":18890}"#
    };
    std::fs::write(
        lines.join(format!("{id}.json")),
        format!(
            r#"{{"inbounds":[{inb}],"route":{{"rules":[],"final":"daily-exit"}},
                "outbounds":[{{"type":"direct","tag":"direct"}},
                             {{"type":"selector","tag":"trade-exit","outbounds":["direct"],"default":"direct"}},
                             {{"type":"selector","tag":"daily-exit","outbounds":["direct"],"default":"direct"}}]}}"#
        ),
    )
    .unwrap();
    let mut cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).unwrap()).unwrap();
    cfg["selected"] = serde_json::Value::String(id.to_string());
    std::fs::write(data.join("config.json"), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
}

fn set_global_mode(root: &Path, mode: &str) {
    let data = root.join("data");
    let mut cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).unwrap()).unwrap();
    cfg["mode"] = serde_json::Value::String(mode.to_string());
    std::fs::write(data.join("config.json"), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
}

#[test]
fn scope_hint_follows_the_lines_actual_mode_not_the_global_flag() {
    // D7：提示的条件原来读全局 mode，2×2 两个方向都错。必须按**选中线路的实际模式**判断。
    // 前提：必须先有一条规则，否则提示本来就不打印（否则断言假绿）。
    let root = tmp_root("d7");
    assert_eq!(run(&root, &["--set-line", "L-tun", "TUN线路", "127.0.0.1:18890"]).0, Some(0));
    assert_eq!(run(&root, &["--split-add-domain", "qq.com"]).0, Some(0), "先有一条规则");

    // 格2：全局 proxy + 线路实际 TUN → 提示必须**不出现**
    make_line_actual_mode(&root, "L-tun", true);
    set_global_mode(&root, "proxy");
    let (_, list) = run(&root, &["--split-list"]);
    assert!(list.contains("分流规则"), "前提：列表要打出来：{list}");
    assert!(
        !list.contains("要覆盖全部程序"),
        "线路实际是 TUN，就不该再劝用户切 TUN：{list}"
    );

    // 格3：全局 tun + 线路实际代理 → 提示必须**出现**（该警告没警告最危险）
    assert_eq!(run(&root, &["--set-line", "L-proxy", "代理线路", "127.0.0.1:18891"]).0, Some(0));
    make_line_actual_mode(&root, "L-proxy", false);
    set_global_mode(&root, "tun");
    let (_, list) = run(&root, &["--split-list"]);
    assert!(
        list.contains("要覆盖全部程序"),
        "实际只有系统代理却没提示，用户会以为全覆盖了：{list}"
    );

    // 边界（必须保留的短路）：**没有规则时不该凭空弹这句范围说明**——
    // 用户压根没配分流，讲"分流只能管到经过本程序的流量"只是噪音。
    let bare = tmp_root("d7-norule");
    assert_eq!(run(&bare, &["--set-line", "L0", "空规则线路", "127.0.0.1:18892"]).0, Some(0));
    make_line_actual_mode(&bare, "L0", false); // 实际是代理，但规则为空
    let (_, list) = run(&bare, &["--split-list"]);
    assert!(
        !list.contains("要覆盖全部程序"),
        "没有分流规则时不该提示范围：{list}"
    );
    let _ = std::fs::remove_dir_all(&bare);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn failed_connect_leaves_no_runtime_engine_config() {
    // 端口被占 → exit 13，且数据根里不得新增 runtime-engine.json（它含只对本次连接有效的凭据）。
    let root = tmp_root("runtime-clean");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    assert_eq!(run(&root, &["--set-line", "L1", "线路甲", &format!("127.0.0.1:{port}")]).0, Some(0));
    let profile = write_profile(&root);
    assert_eq!(
        run(
            &root,
            &[
                "--import",
                &profile.to_string_lossy(),
                "--engine",
                r"C://Windows//System32//PING.EXE",
                "--port",
                &port.to_string(),
                "--line-name",
                "线路甲",
            ],
        )
        .0,
        Some(0)
    );
    let held = std::net::TcpListener::bind(("127.0.0.1", port)).expect("占住端口");
    let (code, out) = run(&root, &["--connect"]);
    assert_eq!(code, Some(5), "端口被占属连接失败（网络类）：{out}");
    assert!(
        !root.join("data").join("runtime-engine.json").exists(),
        "连接失败后不许留下 runtime-engine.json：{out}"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}
