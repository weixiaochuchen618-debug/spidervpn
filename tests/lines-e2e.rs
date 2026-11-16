//! 多线路（schema 2）的端到端：导入/切换/删除/迁移/连接。
//!
//! 全部用临时数据根，不碰真实 `C:\SpiderVPN\data`；引擎一律用系统自带的 `PING.EXE`
//! （它不会监听端口、不改系统设置），需要"引擎起不来"的场合也靠它。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-lines-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data")).expect("建临时数据根");
    p
}

/// 造一份最小线路文件（带一个非 direct 出站，两种模式都能导入）。
fn write_profile(root: &Path, tag: &str) -> PathBuf {
    let dir = root.join("lines-src").join(tag);
    std::fs::create_dir_all(&dir).expect("建线路源目录");
    let f = dir.join("dual-mode.json");
    let body = r#"{
        "inbounds": [{ "type": "tun", "tag": "trade-tun", "mtu": 1380, "stack": "gvisor", "auto_route": true }],
        "route": { "rules": [], "final": "direct" },
        "outbounds": [{ "type": "direct", "tag": "direct" },
                      { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" }]
    }"#;
    std::fs::write(&f, body).expect("写线路文件");
    f
}

/// 本文件专属的临时代理键：**绝不让测试碰到用户真实的系统代理**（隔离契约的硬要求）。
/// 键要先建出来：代理模式读不到键就会拒绝连接，那会把「按现在的期望失败」变成「因环境失败」。
fn proxy_key() -> String {
    format!(r"Software\SpiderVPN\tests\lines-proxy-{}", std::process::id())
}

fn make_proxy_key() {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (k, _) = hkcu.create_subkey(proxy_key()).expect("建临时代理键");
    k.set_value("ProxyEnable", &0u32).unwrap();
    k.set_value("ProxyServer", &"127.0.0.1:7897".to_string()).unwrap();
    k.set_value("ProxyOverride", &"localhost;127.*".to_string()).unwrap();
}

fn run(root: &Path, args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env("SPIDERVPN_PROXY_KEY", proxy_key())
        .env("SPIDERVPN_RUN_KEY", format!(r"Software\SpiderVPN\tests\lines-{}", std::process::id()))
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

fn config_json(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join("data").join("config.json")).expect("config.json 必须已生成");
    serde_json::from_str(&text).expect("config.json 必须是合法 JSON")
}

fn history(root: &Path) -> Vec<serde_json::Value> {
    let path = root.join("data").join("logs").join("operations.jsonl");
    let text = std::fs::read_to_string(path).expect("operations.jsonl 必须已生成");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("每行都必须是合法 JSON"))
        .collect()
}

#[test]
fn cli_records_import_and_remove_with_explicit_provenance() {
    let root = tmp_root("provenance");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "线路甲", "17996").0, Some(0));
    assert_eq!(import(&root, &p, "线路乙", "17997").0, Some(0));

    let imported = history(&root);
    let add = imported
        .iter()
        .find(|e| e["action"] == "导入线路" && e["detail"].as_str().unwrap_or("").contains("线路乙"))
        .expect("第二次导入必须有一条记录");
    assert_eq!(add["src"], "cli", "命令行写入必须记 cli：{add}");
    assert!(add["actor"].as_str().unwrap_or("").starts_with("pid:"), "{add}");
    assert!(add["obj"].as_str().unwrap_or("").starts_with("line:"), "{add}");

    assert_eq!(run(&root, &["--remove-line", "线路甲"]).0, Some(0));
    let removed = history(&root);
    let last = removed.last().expect("删除后必须有记录");
    assert_eq!(last["action"], "删除线路", "{last}");
    assert_eq!(last["src"], "cli", "{last}");
    assert!(last["obj"].as_str().unwrap_or("").starts_with("line:"), "{last}");
    let _ = std::fs::remove_dir_all(&root);
}

fn import(root: &Path, profile: &Path, name: &str, port: &str) -> (Option<i32>, String) {
    make_proxy_key();
    run(
        root,
        &[
            "--import",
            &profile.to_string_lossy(),
            "--engine",
            r"C:\Windows\System32\PING.EXE",
            "--port",
            port,
            "--line-name",
            name,
        ],
    )
}

#[test]
fn import_two_names_keeps_both_lines_and_selects_the_last() {
    let root = tmp_root("two");
    let p1 = write_profile(&root, "a");
    let p2 = write_profile(&root, "b");
    assert_eq!(import(&root, &p1, "线路甲", "17996").0, Some(0));
    let (code, out) = import(&root, &p2, "线路乙", "17997");
    assert_eq!(code, Some(0), "{out}");

    let cfg = config_json(&root);
    assert_eq!(cfg["lines"].as_array().unwrap().len(), 2, "两条线路都要在：{cfg}");
    let names: Vec<&str> = cfg["lines"].as_array().unwrap().iter().map(|l| l["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"线路甲") && names.contains(&"线路乙"), "{names:?}");
    let selected = cfg["selected"].as_str().unwrap();
    let selected_name = cfg["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"].as_str() == Some(selected))
        .map(|l| l["name"].as_str().unwrap())
        .unwrap();
    assert_eq!(selected_name, "线路乙", "最后一次导入的线路要自动选中");
    // 每条线路都有自己的引擎配置
    for l in cfg["lines"].as_array().unwrap() {
        let id = l["id"].as_str().unwrap();
        assert!(
            root.join("data").join("lines").join(format!("{id}.json")).exists(),
            "线路 {id} 应当有自己的引擎配置"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn importing_the_same_name_again_updates_in_place() {
    let root = tmp_root("same");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "同名线路", "17996").0, Some(0));
    let (code, out) = import(&root, &p, "同名线路", "17998");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已更新"), "同名再导入要说「已更新」：{out}");

    let cfg = config_json(&root);
    assert_eq!(cfg["lines"].as_array().unwrap().len(), 1, "同名只能有一条：{cfg}");
    assert_eq!(cfg["lines"][0]["proxy_endpoint"], "127.0.0.1:17998", "端点要被更新");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn use_switches_by_name_and_reports_candidates_when_missing() {
    let root = tmp_root("use");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "线路甲", "17996").0, Some(0));
    assert_eq!(import(&root, &p, "线路乙", "17997").0, Some(0));

    // 按名字（大小写不敏感，名字里有中文也一样）
    let (code, out) = run(&root, &["--use", "线路甲"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已切换到线路"), "{out}");
    let (_, status) = run(&root, &["--status"]);
    assert!(status.contains("线路：线路甲"), "切换后状态行要跟着变：{status}");

    // 按 id
    let cfg = config_json(&root);
    let id_b = cfg["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["name"] == "线路乙")
        .map(|l| l["id"].as_str().unwrap().to_string())
        .unwrap();
    assert_eq!(run(&root, &["--use", &id_b]).0, Some(0));

    // 找不到 → exit 12 且列出候选
    let (code, out) = run(&root, &["--use", "不存在的线路"]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("找不到线路"), "{out}");
    assert!(out.contains("可选线路") && out.contains("线路甲"), "要列出候选：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn lines_lists_all_and_marks_the_selected_one() {
    let root = tmp_root("list");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "线路甲", "17996").0, Some(0));
    assert_eq!(import(&root, &p, "线路乙", "17997").0, Some(0));

    let (code, out) = run(&root, &["--lines"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("线路甲") && out.contains("线路乙"), "{out}");
    // 选中的那条带星号（乙是最后一次导入）
    let marked: Vec<&str> = out.lines().filter(|l| l.trim_start().starts_with('*')).collect();
    assert_eq!(marked.len(), 1, "只能有一条被标为选中：{out}");
    assert!(marked[0].contains("线路乙"), "星号要在当前选中的那条上：{out}");
    // 没被选中的那条前面不能有星号
    let unmarked = out.lines().find(|l| l.contains("线路甲")).unwrap();
    assert!(!unmarked.trim_start().starts_with('*'), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn remove_line_keeps_selection_unless_the_selected_one_is_removed() {
    let root = tmp_root("remove");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "线路甲", "17996").0, Some(0));
    assert_eq!(import(&root, &p, "线路乙", "17997").0, Some(0)); // 乙 现在是选中
    let cfg = config_json(&root);
    let id_a = cfg["lines"].as_array().unwrap().iter().find(|l| l["name"] == "线路甲").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let id_b = cfg["selected"].as_str().unwrap().to_string();

    // 删非选中项：选中不变
    assert_eq!(run(&root, &["--remove-line", "线路甲"]).0, Some(0));
    let cfg = config_json(&root);
    assert_eq!(cfg["lines"].as_array().unwrap().len(), 1);
    assert_eq!(cfg["selected"], id_b.as_str(), "删非选中项不该改变选中");
    assert!(
        !root.join("data").join("lines").join(format!("{id_a}.json")).exists(),
        "线路删了，它的引擎配置也要删"
    );

    // 重新加一条，删选中项 → 回退到第一条
    assert_eq!(import(&root, &p, "线路丙", "17999").0, Some(0));
    assert_eq!(run(&root, &["--remove-line", "线路丙"]).0, Some(0));
    let cfg = config_json(&root);
    let remaining = cfg["lines"][0]["id"].as_str().unwrap();
    assert_eq!(cfg["selected"], remaining, "删掉选中项要回退到第一条");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn removing_every_line_leaves_status_working_and_connect_refusing() {
    let root = tmp_root("empty");
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "唯一线路", "17996").0, Some(0));
    assert_eq!(run(&root, &["--remove-line", "唯一线路"]).0, Some(0));

    let (code, status) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "线路删光了，--status 也不能崩：{status}");
    assert!(status.contains("线路：尚未配置"), "{status}");
    assert!(status.contains("线路数    ：0"), "{status}");

    let (code, out) = run(&root, &["--connect"]);
    assert_eq!(code, Some(3), "没有线路时连接必须失败：{out}");
    assert!(out.contains("未配置线路"), "要说清是缺线路：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn connect_uses_the_selected_lines_endpoint() {
    // 两条线路各占一个端口；占住"选中"那条的端口 → 报错里的端口号就证明用的是它。
    // 端口用运行时分配：写死会和同批并行跑的用例撞车（曾经就这样红过一次，查起来像逻辑 bug）。
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }
    let root = tmp_root("connect");
    let p = write_profile(&root, "a");
    let port_a = free_port();
    let mut port_b = free_port();
    while port_b == port_a {
        port_b = free_port();
    }
    assert_eq!(import(&root, &p, "线路甲", &port_a.to_string()).0, Some(0));
    assert_eq!(import(&root, &p, "线路乙", &port_b.to_string()).0, Some(0)); // 乙 选中
    assert_eq!(run(&root, &["--use", "线路甲"]).0, Some(0)); // 改成甲

    let held = std::net::TcpListener::bind(("127.0.0.1", port_a)).expect("占住甲的端口");
    let (code, out) = run(&root, &["--connect"]);
    assert_eq!(code, Some(5), "端口被占属连接失败（网络类）：{out}");
    assert!(
        out.contains(&port_a.to_string()),
        "连接必须用选中线路（甲）的端点，而不是另一条：{out}"
    );
    assert!(!out.contains(&port_b.to_string()), "不该出现另一条线路的端口：{out}");
    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------- schema 1 → 2 迁移（真实 CLI）----------

#[test]
fn schema1_config_is_upgraded_once_with_a_notice() {
    let root = tmp_root("mig");
    let data = root.join("data");
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":1,"mode":"proxy","line":{"id":"L1","name":"老线路","proxy_endpoint":"127.0.0.1:17890"},
            "engine":{"binary":"C:\\Windows\\System32\\PING.EXE","args":["run","-c","<old>\\engine.json"]}}"#,
    )
    .unwrap();
    std::fs::write(data.join("engine.json"), r#"{"log":{"level":"warn"},"inbounds":[],"outbounds":[]}"#).unwrap();

    // 只读命令不算数：--status 只展示、不落盘
    let before_ro = std::fs::read(data.join("config.json")).unwrap();
    let (code, out_ro) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out_ro}");
    assert!(!out_ro.contains("已把配置升级为多线路格式"), "只读命令不该触发迁移：{out_ro}");
    assert!(out_ro.contains("线路：老线路"), "但要在内存里读得出来：{out_ro}");
    assert_eq!(std::fs::read(data.join("config.json")).unwrap(), before_ro, "只读命令不许改文件");

    // 第一个写命令才真正迁移
    let (code, out) = run(&root, &["--set-autoconnect", "on"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已把配置升级为多线路格式"), "写命令要提示一次：{out}");

    let cfg = config_json(&root);
    assert_eq!(cfg["schema"], 2);
    assert_eq!(cfg["lines"][0]["name"], "老线路");
    assert_eq!(cfg["selected"], "L1");
    assert_eq!(cfg["engine"]["binary"], r"C:\Windows\System32\PING.EXE");
    assert!(cfg["engine"].get("args").is_none(), "schema 2 不再存 args：{cfg}");
    // 旧 engine.json 被**复制**成 lines/L1.json
    let copied = data.join("lines").join("L1.json");
    assert!(copied.exists(), "旧引擎配置要复制给第一条线路");
    assert!(data.join("engine.json").exists(), "复制不是移动，旧文件留着");

    // 第二次启动：不再提示、不再改写
    let before = std::fs::read_to_string(data.join("config.json")).unwrap();
    let (code, out2) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out2}");
    assert!(!out2.contains("已把配置升级为多线路格式"), "迁移只提示一次：{out2}");
    assert_eq!(std::fs::read_to_string(data.join("config.json")).unwrap(), before, "第二次不该改写文件");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn schema1_with_unparseable_engine_fails_and_leaves_the_file_alone() {
    let root = tmp_root("mig-bad");
    let data = root.join("data");
    let bad = r#"{"schema":1,"line":{"id":"L1","name":"老线路","proxy_endpoint":"127.0.0.1:17890"},"engine":{"binary":"","args":["run","-c","x.json"]}}"#;
    std::fs::write(data.join("config.json"), bad).unwrap();
    let before = std::fs::read(data.join("config.json")).unwrap();

    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(3), "认不出引擎要拒绝启动：{out}");
    assert!(out.contains("配置升级失败") || out.contains("认不出引擎"), "{out}");
    assert_eq!(std::fs::read(data.join("config.json")).unwrap(), before, "失败时原文件一个字节都不能动");
    assert!(!data.join("lines").exists(), "失败时不该创建 lines 目录");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn readonly_commands_never_write_a_schema1_config() {
    // 用户的配置是 schema 1 时，只读命令必须零写入：--status / --lines / --plan / --restore。
    let root = tmp_root("ro");
    let data = root.join("data");
    let v1 = r#"{"schema":1,"line":{"id":"L1","name":"老线路","proxy_endpoint":"127.0.0.1:17890"},
        "engine":{"binary":"C:////Windows////System32////PING.EXE"}}"#;
    std::fs::write(data.join("config.json"), v1).unwrap();
    std::fs::write(data.join("engine.json"), r#"{"inbounds":[]}"#).unwrap();
    let cfg_before = std::fs::read(data.join("config.json")).unwrap();
    let eng_before = std::fs::read(data.join("engine.json")).unwrap();

    for cmd in ["--status", "--lines", "--plan", "--restore", "--headless"] {
        let (code, out) = run(&root, &[cmd]);
        assert_eq!(code, Some(0), "{cmd} 应当成功：{out}");
        assert_eq!(
            std::fs::read(data.join("config.json")).unwrap(),
            cfg_before,
            "{cmd} 不许改 config.json"
        );
        assert_eq!(
            std::fs::read(data.join("engine.json")).unwrap(),
            eng_before,
            "{cmd} 不许动 engine.json"
        );
        assert!(!data.join("lines").exists(), "{cmd} 不许创建 lines 目录");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn missing_line_reports_13_for_every_command_and_missing_engine_reports_8() {
    // 缺什么报什么，不按命令分家：缺线路 → 13；缺引擎 → 8。
    let root = tmp_root("codes");
    let data = root.join("data");
    // 先造一条线路（这样才有 engine 之外的比较基准）
    let p = write_profile(&root, "a");
    assert_eq!(import(&root, &p, "唯一线路", "17996").0, Some(0));

    // ---- 缺线路：把唯一那条删掉 ----
    assert_eq!(run(&root, &["--remove-line", "唯一线路"]).0, Some(0));
    for cmd in ["--connect", "--plan"] {
        let (code, out) = run(&root, &[cmd]);
        assert_eq!(code, Some(3), "{cmd} 缺线路属配置类：{out}");
        assert!(out.contains("未配置线路"), "{cmd} 要说清缺线路：{out}");
    }

    // ---- 缺引擎：线路在，但把 engine 抹掉 ----
    assert_eq!(import(&root, &p, "再来一条", "17997").0, Some(0));
    let mut cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).unwrap()).unwrap();
    cfg.as_object_mut().unwrap().remove("engine");
    std::fs::write(data.join("config.json"), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    let (code, out) = run(&root, &["--connect"]);
    assert_eq!(code, Some(3), "缺引擎必须是 8：{out}");
    assert!(out.contains("未配置引擎"), "{out}");

    // ---- 配置本身缺失：不算「缺线路」，保持原来的码（这里是 0 的 --status）----
    std::fs::remove_file(data.join("config.json")).unwrap();
    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "没有配置文件时 --status 照旧正常退出：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reimport_after_upgrade_keeps_the_persisted_id() {
    // 红线：id 规则变了，但已落盘的 id 不能被重算——同名再导入必须更新那一条，而不是新建。
    let root = tmp_root("idkeep");
    let data = root.join("data");
    // 模拟用户现场：id 是中文（旧规则生成），引擎配置在 ____.json
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"selected":"示例线路","engine":{"binary":"C:////Windows////System32////PING.EXE"},
            "lines":[{"id":"示例线路","name":"示例线路","proxy_endpoint":"127.0.0.1:17890"}]}"#,
    )
    .unwrap();
    std::fs::create_dir_all(data.join("lines")).unwrap();
    std::fs::write(data.join("lines").join("____.json"), r#"{"inbounds":[],"outbounds":[]}"#).unwrap();

    let p = write_profile(&root, "a");
    // 端口动态分配：硬编码 17899 会撞 旧版的 provider 中继监听段（17901–17908）——
    // 本机 20:49 起 旧版的 Run-TradeChannel.ps1 在听 17902 = 17899+3。
    // 这是环境冲突，不是产品行为；动态取端口消除这个脆弱性（本测试的主题是 id 保留，与端口无关）。
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("取空闲端口");
        l.local_addr().unwrap().port()
    }; // listener 在此 drop，端口释放给导入用
    let port = port.to_string();
    let (code, out) = import(&root, &p, "示例线路", &port);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已更新"), "同名再导入必须走更新语义：{out}");

    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data.join("config.json")).unwrap()).unwrap();
    assert_eq!(cfg["lines"].as_array().unwrap().len(), 1, "不能因为 id 规则变化就多出一条：{cfg}");
    assert_eq!(cfg["lines"][0]["id"], "示例线路", "已落盘的 id 必须原样保留");
    assert_eq!(cfg["lines"][0]["proxy_endpoint"], format!("127.0.0.1:{port}"), "端点要更新");
    assert!(data.join("lines").join("____.json").exists(), "引擎配置仍在这条线路的老路径上");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn missing_config_file_is_8_for_every_command() {
    // 「配置缺失」不是「缺线路」：码与文案都要能区分，否则用户以为线路被删了。
    // 动作命令同一把尺子（`--headless` 是自检命令，见下一条用例：它一律 0）。
    let root = tmp_root("nocfg");
    std::fs::remove_file(root.join("data").join("config.json")).ok();
    for cmd in ["--connect", "--plan"] {
        let (code, out) = run(&root, &[cmd]);
        assert_eq!(code, Some(3), "{cmd} 配置缺失保持 exit 8：{out}");
        assert!(out.contains("找不到配置文件"), "{cmd} 文案要说清是文件没了：{out}");
        assert!(out.contains("config.json"), "{out}");
        assert!(!out.contains("未配置线路"), "{cmd} 不能说成「未配置线路」：{out}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn plan_reports_13_only_when_the_config_exists_but_has_no_line() {
    // 与上一条配成一对：配置在、线路空 → 13（缺线路）。
    let root = tmp_root("plan-noline");
    std::fs::write(
        root.join("data").join("config.json"),
        r#"{"schema":2,"selected":"","lines":[],"engine":{"binary":"C://Windows//System32//PING.EXE"}}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--plan"]);
    assert_eq!(code, Some(3), "缺线路是 13：{out}");
    assert!(out.contains("未配置线路"), "{out}");
    assert!(!out.contains("找不到配置文件"), "配置明明在，不许说文件没了：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn headless_exits_zero_even_when_nothing_is_configured() {
    // headless 是自检命令：它不执行动作，「尚未配置」是合法状态——写进输出就够，
    // 不该让 CI 在新机器上直接失败。三种现场都必须 exit 0 且说明当前状态。
    let root = tmp_root("headless-zero");
    let data = root.join("data");

    // 现场一：配置文件不存在
    let (code, out) = run(&root, &["--headless"]);
    assert_eq!(code, Some(0), "配置不存在也要 exit 0：{out}");
    assert!(out.contains("尚未配置"), "输出要说清还没配：{out}");

    // 现场二：配置在、lines 为空
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"selected":"","lines":[],"engine":{"binary":"C:////Windows////System32////PING.EXE"}}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--headless"]);
    assert_eq!(code, Some(0), "线路为空也要 exit 0：{out}");
    assert!(out.contains("尚未配置"), "{out}");

    // 现场三：线路在、缺 engine.binary
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"selected":"a","lines":[{"id":"a","name":"线路甲","proxy_endpoint":"127.0.0.1:17911"}]}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--headless"]);
    assert_eq!(code, Some(0), "缺引擎也要 exit 0：{out}");
    assert!(out.contains("尚未配置"), "引擎没配也要说出来：{out}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn plan_and_connect_report_8_when_the_engine_is_missing() {
    // 定稿矩阵第三行：缺 engine.binary → plan 8 / connect 8（headless 仍 0）。
    let root = tmp_root("noengine");
    let data = root.join("data");
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"selected":"a","lines":[{"id":"a","name":"线路甲","proxy_endpoint":"127.0.0.1:17912"}]}"#,
    )
    .unwrap();
    for cmd in ["--plan", "--connect"] {
        let (code, out) = run(&root, &[cmd]);
        assert_eq!(code, Some(3), "{cmd} 缺引擎必须是 8：{out}");
        assert!(out.contains("未配置引擎"), "{cmd} 要说清缺引擎：{out}");
    }
    let (code, out) = run(&root, &["--headless"]);
    assert_eq!(code, Some(0), "headless 不因缺引擎失败：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_prints_the_current_line_only_once() {
    // D3：`--status` 里同一线路出现两次（横幅一行 + 状态块一行）。
    // 口径：**保留横幅「线路：X 端点：…」**（用户最常看），状态块只留「线路数」；完整列表归 `--lines`。
    let root = tmp_root("status-once");
    assert_eq!(run(&root, &["--set-line", "L1", "唯一线路", "127.0.0.1:17981"]).0, Some(0));
    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    let banner = out.lines().filter(|l| l.trim_start().starts_with("线路：")).count();
    assert_eq!(banner, 1, "横幅那行要保留且只有一条：{out}");
    assert!(out.contains("线路：唯一线路"), "要看得到当前线路名：{out}");
    assert_eq!(
        out.lines().filter(|l| l.contains("线路      ：")).count(),
        0,
        "状态块里不该再重复一条「线路      ：」：{out}"
    );
    assert_eq!(
        out.lines().filter(|l| l.contains("端点      ：")).count(),
        0,
        "端点也在横幅里，状态块不要重复：{out}"
    );
    assert_eq!(
        out.lines().filter(|l| l.contains("线路数    ：")).count(),
        1,
        "线路数要留着（那是另一条信息）：{out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn heal_clears_the_last_check_record_after_restoring() {
    // D1：强杀/断电后重启 → 自愈还原了代理，但上一次的「通道自检：通过」还留着，
    // 于是「未连接」下面写着「通过（HTTP 204）」——用户会以为还连着。
    let root = tmp_root("heal-check");
    let data = root.join("data");
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"mode":"proxy","selected":"a","engine":{"binary":"C:////Windows////System32////PING.EXE"},
            "lines":[{"id":"a","name":"线路甲","proxy_endpoint":"127.0.0.1:17982"}]}"#,
    )
    .unwrap();
    // 现场：凭据在 + 引擎已死（用一个几乎不可能存在的 pid）+ 上一次的自检结论
    std::fs::write(
        data.join("proxy-journal.json"),
        r#"{"schema":1,"endpoint":"127.0.0.1:17982","saved_at_secs":0,
            "saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("runtime.json"),
        r#"{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":4194303,"State":"Running"}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("last-check.json"),
        r#"{"ok":true,"status":204,"error":null,"at":1}"#,
    )
    .unwrap();

    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("已自动还原"), "应当提示自愈过：{out}");
    assert!(out.contains("未连接"), "状态是未连接：{out}");
    assert!(!out.contains("通道自检：通过"), "未连接却报「通过」，这是假象：{out}");
    assert!(out.contains("通道自检：未检测") || out.contains("通道自检  ：未检测"), "应是未检测：{out}");
    assert!(!data.join("last-check.json").exists(), "自检记录本身要被清掉");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn status_shows_the_saved_mode_until_connected_then_the_running_one() {
    // 口径（第 5 轮修正）：**未连接**时「模式」行报的是 config.mode（下次连接会用哪种）；
    // **连接中**报引擎真正在跑的那一种（读 runtime-engine.json）。
    // 线路文件里的 tun 入站只是**素材**，不是"当前模式"的声明——拿它当答案会骗人。
    let root = tmp_root("mode-truth");
    let data = root.join("data");
    std::fs::create_dir_all(data.join("lines")).unwrap();
    // ① 全局 mode=tun、线路里只有 mixed：未连接 → 报 TUN（偏好），不是"线路文件里有什么"
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"mode":"tun","selected":"a","engine":{"binary":"C:////Windows////System32////PING.EXE"},
            "lines":[{"id":"a","name":"代理线路","proxy_endpoint":"127.0.0.1:18890"}]}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("lines").join("a.json"),
        r#"{"inbounds":[{"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":18890}],
            "route":{"rules":[],"final":"daily-exit"},
            "outbounds":[{"type":"direct","tag":"direct"},
                         {"type":"selector","tag":"trade-exit","outbounds":["direct"],"default":"direct"},
                         {"type":"selector","tag":"daily-exit","outbounds":["direct"],"default":"direct"}]}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("模式      ：TUN"), "未连接时报偏好（下次连接会用 tun）：{out}");

    // ② 全局 proxy、线路里**确实有** tun 入站：未连接 → 仍然报代理（素材不是当前模式）
    std::fs::write(
        data.join("config.json"),
        r#"{"schema":2,"mode":"proxy","selected":"b","engine":{"binary":"C:////Windows////System32////PING.EXE"},
            "lines":[{"id":"b","name":"TUN线路","proxy_endpoint":"127.0.0.1:18891"}]}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("lines").join("b.json"),
        r#"{"inbounds":[{"type":"tun","tag":"trade-tun","interface_name":"SpiderVPN"},
                        {"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":18891}],
            "route":{"rules":[],"final":"daily-exit"},
            "outbounds":[{"type":"direct","tag":"direct"},
                         {"type":"selector","tag":"trade-exit","outbounds":["direct"],"default":"direct"},
                         {"type":"selector","tag":"daily-exit","outbounds":["direct"],"default":"direct"}]}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("模式      ：代理"), "线路文件里有 tun 也不许说当前是 TUN：{out}");

    // ③ 连接中（runtime-engine.json 存在）→ 报引擎真正在跑的那份
    std::fs::write(
        data.join("runtime-engine.json"),
        r#"{"inbounds":[{"type":"tun","tag":"trade-tun","interface_name":"SpiderVPN"}]}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("模式      ：TUN"), "连接中必须报运行时配置里的模式：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_line_refuses_a_port_whose_probe_port_is_taken() {
    // 与 --import 同一条规则：`--set-line` 写进去的端口以后连接时要用，
    // 它的 +3 绑不上就等于给自己留一个「永远跳过」的自检。
    let root = tmp_root("probe-taken");
    // 挑一对都空的端口：随机端口的 +3 可能溢出 u16，固定端口可能被本机占用。
    let port = (20_000..60_000u16)
        .find(|p| {
            std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok()
                && std::net::TcpListener::bind(("127.0.0.1", p + 3)).is_ok()
        })
        .expect("找一对空闲端口");
    let holder = std::net::TcpListener::bind(("127.0.0.1", port + 3)).expect("占住探测端口");

    let endpoint = format!("127.0.0.1:{port}");
    let (code, out) = run(&root, &["--set-line", "L1", "端口占用线路", &endpoint]);
    assert_eq!(code, Some(6), "探测端口被占是冲突，需换端口：{out}");
    assert!(
        out.contains(&format!(
            "端口 {port} 不可用：它的自检探测端口 {} 已被占用或被系统预留。请换一个线路端口。",
            port + 3
        )),
        "文案是定稿，且要点明是哪个探测端口：{out}"
    );
    assert!(!root.join("data").join("config.json").exists(), "被拒绝时不许写配置");

    drop(holder);
    let (code, out) = run(&root, &["--set-line", "L1", "端口占用线路", &endpoint]);
    assert_eq!(code, Some(0), "探测端口释放后应当写入成功：{out}");
    let _ = std::fs::remove_dir_all(&root);
}
