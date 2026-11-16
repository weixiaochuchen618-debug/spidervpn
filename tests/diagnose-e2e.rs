//! `--diagnose` 的端到端：目标推导、三态结论、退出码、只读性。
//!
//! 只探 TCP（WireGuard 的 peer 是 UDP）：所以"纯 UDP 未验证"必须是**结论里的话**，
//! 而不是一个假的"通过"。这里钉的就是这条不撒谎的线。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-diag-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("data").join("lines")).expect("建临时数据根");
    p
}

/// 写配置 + 线路引擎配置。`transport` 是配置里记的连接方式（None = 没选过）。
fn setup(root: &Path, transport: Option<&str>, line_body: &str) {
    let data = root.join("data");
    let tr = match transport {
        Some(t) => format!(r#","transport":"{t}""#),
        None => String::new(),
    };
    std::fs::write(
        data.join("config.json"),
        format!(
            r#"{{"schema":2,"mode":"proxy","selected":"L1","lines":[
                {{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17985"{tr}}}]}}"#
        ),
    )
    .expect("写配置");
    std::fs::write(data.join("lines").join("L1.json"), line_body).expect("写线路配置");
}

fn run(root: &Path, args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .env("SPIDERVPN_ROOT", root)
        .env(
            "SPIDERVPN_RUN_KEY",
            format!(r"Software\SpiderVPN\tests\diag-{}", std::process::id()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动被测程序");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if child.try_wait().expect("等待被测程序").is_some() {
            let out = child.wait_with_output().expect("取输出");
            return (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("被测程序 60 秒未退出（{args:?}）");
}

/// 纯 UDP 线路：WireGuard endpoint 带 peer（服务器地址 + UDP 端口）。
fn udp_line(host: &str, port: u16) -> String {
    format!(
        r#"{{
  "endpoints": [{{ "type":"wireguard", "tag":"hk", "address":["10.7.0.2/32"],
                  "peers":[{{ "address":"{host}", "port":{port}, "public_key":"x" }}] }}],
  "outbounds": [{{ "type":"selector", "tag":"trade-exit", "outbounds":["hk"], "default":"hk" }},
                {{ "type":"direct", "tag":"direct" }}],
  "route": {{ "rules": [], "final": "trade-exit" }}
}}"#
    )
}

/// 兼容连接线路：多一条 tag=tc-transport 的 vless。
fn tcp_line(host: &str, port: u16) -> String {
    format!(
        r#"{{
  "endpoints": [{{ "type":"wireguard", "tag":"hk", "address":["10.7.0.2/32"],
                  "peers":[{{ "address":"{host}", "port":51820, "public_key":"x" }}] }}],
  "outbounds": [
    {{ "type":"vless", "tag":"tc-transport", "server":"{host}", "server_port":{port},
       "uuid":"11111111-2222-3333-4444-555555555555",
       "tls": {{ "enabled":true, "server_name":"cdn.example.com",
                 "reality": {{ "enabled":true,
                              "public_key":"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1",
                              "short_id":"ab12" }} }} }},
    {{ "type":"selector", "tag":"trade-exit", "outbounds":["hk"], "default":"hk" }},
    {{ "type":"direct", "tag":"direct" }}],
  "route": {{ "rules": [], "final": "trade-exit" }}
}}"#
    )
}

/// 从「可建立连接，耗时 38 ms」里取出毫秒数（取不到就让断言更难写错）。
fn latency_of(out: &str, port_label: &str) -> u128 {
    let line = out
        .lines()
        .find(|l| l.contains(port_label) && l.contains("可建立连接，耗时 "))
        .unwrap_or_else(|| panic!("没找到 {port_label} 的可达行：{out}"));
    let tail = line.split("可建立连接，耗时 ").nth(1).unwrap_or("");
    tail.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("延迟不是数字：{line}"))
}

#[test]
fn udp_line_probes_22_and_443_and_keeps_udp_unverified() {
    // 443 上放一个本地监听当"管理/Web 端口可达"的现场（Windows 上绑 443 不需要管理员；
    // 万一已被别人占着，那它照样是"可达"，用例的意图不变）。
    let held = std::net::TcpListener::bind("127.0.0.1:443").ok();
    let root = tmp_root("udp");
    setup(&root, None, &udp_line("127.0.0.1", 51820));

    let (code, out) = run(&root, &["--diagnose"]);
    assert_eq!(code, Some(0), "探测到可达端口就是成功：{out}");
    assert!(out.contains("诊断：线路甲（标准连接）"), "标题要带线路名与连接方式：{out}");
    assert!(out.contains("TCP 127.0.0.1:22  "), "要探管理端口并显示完整目标：{out}");
    let ms = latency_of(&out, ":443");
    assert!(ms < 2_500, "延迟必须在超时窗口内：{ms}");
    // WireGuard 的端点是 UDP：只说明"不适用"，绝不当成失败
    assert!(
        out.contains("UDP 127.0.0.1:51820  该端点走 UDP，TCP 探测不适用"),
        "要明确标注 UDP 不适用：{out}"
    );
    assert!(
        out.contains("结论：管理或 Web 端口可达；当前为 UDP WireGuard，尚未验证 UDP 与设备授权。"),
        "总结句必须是 旧版那一句（不许说成「通道正常」）：{out}"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn transport_line_probes_the_transport_port_and_reports_reality_pending() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("占一个空闲端口当传输端口");
    let port = held.local_addr().unwrap().port();
    let root = tmp_root("tcp");
    setup(&root, Some("tcp"), &tcp_line("127.0.0.1", port));

    let (code, out) = run(&root, &["--diagnose"]);
    assert_eq!(code, Some(0), "传输端口可达即成功：{out}");
    assert!(out.contains("诊断：线路甲（兼容连接）"), "标题要说兼容连接：{out}");
    let ms = latency_of(&out, &format!(":{port}"));
    assert!(ms < 2_500, "{ms}");
    // 部分可达：管理口通常没开，但不影响结论
    assert!(
        out.contains("TCP 127.0.0.1:22  "),
        "除了传输端口还要看管理口并显示完整目标：{out}"
    );
    assert!(
        out.contains("结论：TCP 传输端口可达；Reality 认证、WireGuard 握手及转发需连接后检查。"),
        "总结句要说明 Reality/握手仍未验证：{out}"
    );
    assert!(!out.contains("不能据此判定离线"), "这条线路的结论不该出现纯 UDP 那句话：{out}");
    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_unusable_host_exits_network_and_never_calls_the_server_offline() {
    // 构造"两个口都探不到"的现场，**必须与环境无关**，这条踩过两次坑：
    // ① 黑洞 IP（192.0.2.1）不行：本机 0.0.0.0:22 有服务在听、外网又被 TUN 接管，22 口会探成"可达"；
    // ② 保留域名（no-such-host.invalid）也不行：DNS 要 11 秒才回 NXDOMAIN，遇上 TUN 的 fake-ip
    //    还可能给出一个能连上的假 IP（实测偶发红）。
    // `999.1.1.1` 是非法 IP 字面量：getaddrinfo 在本地立刻拒绝（实测 1ms、零DNS查询），
    // 于是两个目标都在解析这一步就不可达——正是"线路文件里的服务器地址填坏了"这个现场。
    let root = tmp_root("blackhole");
    setup(&root, None, &udp_line("999.1.1.1", 51820));

    let (code, out) = run(&root, &["--diagnose"]);
    assert_eq!(code, Some(5), "两个口都探不到就是诊断失败：{out}");
    assert!(out.contains("TCP 999.1.1.1:22  无可用 TCP 响应，耗时 "), "{out}");
    assert!(out.contains("可能未监听、端口受限或路径不可达"), "{out}");
    assert!(out.contains("；下一步："), "末尾必须同时给结论与下一步：{out}");
    assert!(out.contains("网络侧封禁"), "UDP 两个 TCP 口不通要检查网络侧封禁：{out}");
    assert!(
        out.contains("结论：未探测到 TCP 22/443 响应。纯 UDP 服务器可能仍正常，不能据此判定离线。"),
        "必须明说不能据此判定离线：{out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_tcp_choice_without_a_transit_outbound_exits_network_and_says_nothing_was_probed() {
    // 配置说走兼容连接，但文件里没有中转出站：连接时会被直接拒绝，
    // 诊断也不能替它探 22/443 然后给出"看起来还行"的结论。
    let root = tmp_root("notransit");
    setup(&root, Some("tcp"), &udp_line("127.0.0.1", 51820));
    let (code, out) = run(&root, &["--diagnose"]);
    assert_eq!(code, Some(5), "{out}");
    assert!(out.contains("未探测任何端口："), "要明说没做验证：{out}");
    assert!(out.contains("没有可用的中转出站"), "{out}");
    assert!(out.contains("不代表服务器离线"), "没做验证不等于服务器离线：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn no_line_reuses_the_unconfigured_message_and_exits_config() {
    let root = tmp_root("noline");
    std::fs::write(
        root.join("data").join("config.json"),
        r#"{"schema":2,"selected":"","lines":[]}"#,
    )
    .unwrap();
    let (code, out) = run(&root, &["--diagnose"]);
    // 没线路是「配置类」，不是「网络不通」：两者必须分开，否则脚本会把配置问题当网络重试。
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("未配置线路"), "复用既有文案：{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn diagnose_is_read_only() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("占一个空闲端口");
    let port = held.local_addr().unwrap().port();
    let root = tmp_root("readonly");
    setup(&root, Some("tcp"), &tcp_line("127.0.0.1", port));
    let cfg = root.join("data").join("config.json");
    let line = root.join("data").join("lines").join("L1.json");
    let before = (std::fs::read(&cfg).unwrap(), std::fs::read(&line).unwrap());

    let (code, out) = run(&root, &["--diagnose"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(std::fs::read(&cfg).unwrap(), before.0, "诊断不许改 config.json");
    assert_eq!(std::fs::read(&line).unwrap(), before.1, "诊断不许改线路配置");
    assert!(
        !root.join("data").join("runtime.json").exists(),
        "诊断不需要连接，不该冒出运行记录"
    );
    assert!(
        !root.join("data").join("last-check.json").exists(),
        "诊断不是自检，不该写自检结论"
    );
    assert!(
        !root.join("data").join("proxy-journal.json").exists(),
        "诊断不动系统代理，不该有还原凭据"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}
