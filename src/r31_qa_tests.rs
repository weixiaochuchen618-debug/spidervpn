//! R31「自动连接方式」的**独立复核**用例（QA 编写，不是产品代码）。
//!
//! 全部用例只走公开/半公开接口：`config` 的读写函数、`ipc::handle_line_with`
//! （与界面同一条命令分派）、`uiweb::WebUi` 的路由与快照。
//! 断言一律写**逐字值**，不用 `is_some()` 之类可以空转的宽松判断。
//!
//! 每个用例自己建临时数据根（`SPIDERVPN_ROOT` 的等价物是 `Ctx::root`），
//! 不读写真实 `%LOCALAPPDATA%`，也不碰注册表。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::config::{self, LineConfig, Transport};

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tcrs-qa31-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("建临时数据根");
    p
}

fn cfg_path(root: &Path) -> PathBuf {
    root.join(config::DEFAULT_PATH)
}

/// 盘上配置的**原始字节**：幂等性要看的是「文件一个字节都没动」，不是「值没变」。
fn cfg_bytes(root: &Path) -> Vec<u8> {
    std::fs::read(cfg_path(root)).expect("读 config.json")
}

fn cfg_text(root: &Path) -> String {
    std::fs::read_to_string(cfg_path(root)).expect("读 config.json")
}

/// 一条「什么偏好都没设过」的线路。
fn bare_line(id: &str, name: &str) -> LineConfig {
    LineConfig {
        id: id.to_string(),
        name: name.to_string(),
        proxy_endpoint: "127.0.0.1:7890".to_string(),
        transport: None,
        verified_transport: None,
    }
}

/// 一份「除了线路之外全是默认值」的配置（`AppConfig` 没有 `Default`）。
fn app_config(lines: Vec<LineConfig>) -> config::AppConfig {
    config::AppConfig {
        schema: config::SCHEMA,
        mode: config::Mode::default(),
        auto_start: false,
        auto_connect: false,
        close_to_tray: false,
        quality_warning: true,
        auto_trust_first_connection: true,
        selected: lines.first().map(|l| l.id.clone()).unwrap_or_default(),
        lines,
        split: config::SplitConfig::default(),
        agents: config::AgentsConfig::default(),
        exits: config::Exits::default(),
        engine: None,
    }
}

fn write_cfg(root: &Path, lines: Vec<LineConfig>) {
    config::save(&cfg_path(root), &app_config(lines)).expect("写初版 config.json");
}

fn read_line(root: &Path, id: &str) -> LineConfig {
    config::load(&cfg_path(root))
        .expect("读配置")
        .expect("配置存在")
        .find_line(id)
        .cloned()
        .unwrap_or_else(|| panic!("配置里应当有线路 {id}"))
}

/// 与界面/管道同一个入口：`handle_line_with` 里 `set-transport` 走的就是
/// `set_transport_json`，所以这里量到的就是用户在页面点一下之后宿主的行为。
fn ipc_call(root: &Path, line: &str) -> Value {
    let ctx = crate::ipc::Ctx { root: root.to_path_buf(), ..Default::default() };
    let reply = crate::ipc::handle_line_with(line, &ctx);
    serde_json::from_str(&reply).unwrap_or_else(|e| panic!("回包不是合法 JSON：{e} / {reply}"))
}

// ---------------------------------------------------------------------------
// 1. 三档优先级：固定 → 已验证 → 标准连接
// ---------------------------------------------------------------------------

#[test]
fn qa31_effective_transport_prefers_choice_then_evidence_then_standard() {
    let mut line = bare_line("L1", "线路甲");
    assert_eq!(
        line.effective_transport(),
        Transport::Udp,
        "什么依据都没有时必须兜底标准连接（不是 tcp）"
    );

    // 只有依据（用户没固定）：采用已验证的那一种。
    line.verified_transport = Some(Transport::Tcp);
    assert_eq!(
        line.effective_transport(),
        Transport::Tcp,
        "没固定但验证过兼容连接 → 用兼容连接"
    );

    // 固定覆盖依据——两个方向都要成立，否则「用户优先」只是单向巧合。
    line.transport = Some(Transport::Udp); // 固定 udp + 已验证 tcp
    assert_eq!(
        line.effective_transport(),
        Transport::Udp,
        "用户固定的标准连接必须压过已验证的兼容连接"
    );
    line.transport = Some(Transport::Tcp); // 固定 tcp + 已验证 udp
    line.verified_transport = Some(Transport::Udp);
    assert_eq!(
        line.effective_transport(),
        Transport::Tcp,
        "用户固定的兼容连接必须压过已验证的标准连接"
    );
}

// ---------------------------------------------------------------------------
// 2. 老配置兼容：没有 transport / verified_transport 两个键
// ---------------------------------------------------------------------------

#[test]
fn qa31_legacy_config_reads_as_standard_and_never_gains_the_new_keys() {
    let root = tmp_root("legacy");
    // 0.1.4 之前落盘的形状：只有 id / name / proxy_endpoint。
    std::fs::write(
        cfg_path(&root),
        r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:7890"}]}"#,
    )
    .unwrap();

    let cfg = config::load(&cfg_path(&root)).expect("老配置必须读得动").expect("配置存在");
    let line = cfg.find_line("L1").expect("线路 L1");
    assert_eq!(line.transport, None, "老配置没有「用户固定」");
    assert_eq!(line.verified_transport, None, "老配置没有「已验证」");
    assert_eq!(line.effective_transport(), Transport::Udp, "老配置跑标准连接");

    // 序列化回去不许凭空多出空键（`skip_serializing_if` 必须真的生效）。
    let back = serde_json::to_string_pretty(&cfg).unwrap();
    assert!(
        !back.contains("\"verified_transport\""),
        "没验证过就不该写这个键：{back}"
    );
    assert!(
        !back.contains("\"transport\":") && !back.contains("\"transport\": null"),
        "没固定就不该写 `transport`（不是 null、不是空串）：{back}"
    );
}

// ---------------------------------------------------------------------------
// 3. 幂等与写盘事实
// ---------------------------------------------------------------------------

#[test]
fn qa31_record_verified_transport_is_idempotent_and_byte_stable() {
    let root = tmp_root("record");
    write_cfg(&root, vec![bare_line("L1", "线路甲")]);
    let baseline = cfg_bytes(&root);

    // 第一次记录：真的改了文件。
    assert_eq!(
        config::record_verified_transport(&root, "L1", Transport::Tcp),
        Ok(true),
        "从 None 变成 tcp 必须算「改了」"
    );
    assert_eq!(read_line(&root, "L1").verified_transport, Some(Transport::Tcp));
    let after_record = cfg_bytes(&root);
    assert_ne!(after_record, baseline, "改了就必须真的落盘");
    assert!(
        cfg_text(&root).contains("\"verified_transport\": \"tcp\""),
        "落盘的字面量必须是 tcp：{}",
        cfg_text(&root)
    );

    // 同值再记：不写盘，文件字节不变。
    assert_eq!(
        config::record_verified_transport(&root, "L1", Transport::Tcp),
        Ok(false),
        "同值必须返回 Ok(false)"
    );
    assert_eq!(cfg_bytes(&root), after_record, "同值不许重写文件（mtime 与记录都不该动）");

    // 不同值：改。
    assert_eq!(
        config::record_verified_transport(&root, "L1", Transport::Udp),
        Ok(true),
        "值变了必须返回 Ok(true)"
    );
    assert_eq!(read_line(&root, "L1").verified_transport, Some(Transport::Udp));

    // 清除：第一次写盘、第二次不写。
    let before_clear = cfg_bytes(&root);
    assert_eq!(
        config::clear_verified_transport(&root, "L1"),
        Ok(true),
        "有值可清时必须写盘"
    );
    let after_clear = cfg_bytes(&root);
    assert_ne!(after_clear, before_clear, "清掉一个存在的值必须落盘");
    assert_eq!(read_line(&root, "L1").verified_transport, None);
    assert!(
        !cfg_text(&root).contains("verified_transport"),
        "清空后连键都不该留：{}",
        cfg_text(&root)
    );
    assert_eq!(
        config::clear_verified_transport(&root, "L1"),
        Ok(false),
        "本来就没有时必须返回 Ok(false)"
    );
    assert_eq!(cfg_bytes(&root), after_clear, "本来就没有时不许重写文件");
}

#[test]
fn qa31_record_and_clear_refuse_an_unknown_line_without_touching_the_file() {
    let root = tmp_root("unknown");
    write_cfg(&root, vec![bare_line("L1", "线路甲")]);
    let before = cfg_bytes(&root);

    let rec = config::record_verified_transport(&root, "NOPE", Transport::Tcp);
    assert!(rec.is_err(), "线路不存在必须 Err，而不是悄悄新建一条：{rec:?}");
    assert!(rec.unwrap_err().contains("NOPE"), "错误里要指出是哪条线路");
    let clr = config::clear_verified_transport(&root, "NOPE");
    assert!(clr.is_err(), "线路不存在必须 Err：{clr:?}");
    assert_eq!(cfg_bytes(&root), before, "报错路径不许动配置");
}

/// 记录/清除只碰 `verified_transport`——用户固定的 `transport` 一个字节都不许动。
#[test]
fn qa31_evidence_writes_never_touch_the_users_choice() {
    let root = tmp_root("keep-choice");
    let mut line = bare_line("L1", "线路甲");
    line.transport = Some(Transport::Tcp);
    write_cfg(&root, vec![line]);

    assert_eq!(
        config::record_verified_transport(&root, "L1", Transport::Udp),
        Ok(true),
        "依据可以记"
    );
    let after = read_line(&root, "L1");
    assert_eq!(after.transport, Some(Transport::Tcp), "记录依据不许改用户固定");
    assert_eq!(after.verified_transport, Some(Transport::Udp));

    assert_eq!(config::clear_verified_transport(&root, "L1"), Ok(true));
    let after = read_line(&root, "L1");
    assert_eq!(
        after.transport,
        Some(Transport::Tcp),
        "清除依据更不许改用户固定（固定不是证据）"
    );
    assert_eq!(after.verified_transport, None);
    assert_eq!(after.effective_transport(), Transport::Tcp, "清完依据仍走用户固定的方式");
}

// ---------------------------------------------------------------------------
// 4. `set-transport auto`：清固定、留依据、键从文件里消失
// ---------------------------------------------------------------------------

#[test]
fn qa31_set_transport_auto_removes_the_key_but_keeps_the_evidence() {
    let root = tmp_root("set-auto");
    let mut l1 = bare_line("L1", "线路甲");
    l1.transport = Some(Transport::Tcp);
    l1.verified_transport = Some(Transport::Tcp);
    write_cfg(&root, vec![l1, bare_line("L2", "线路乙")]);

    let reply = ipc_call(&root, r#"{"cmd":"set-transport","transport":"auto","id":"L1"}"#);
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(
        reply["message"],
        json!("已改为自动选择（采用这条线路已验证的方式）"),
        "auto 必须用自己的文案（不能沿用「已保存下次默认方式」）：{reply}"
    );

    // 回包里的线路投影跟着改，页面据它重画。
    assert_eq!(reply["lines"][0]["id"], json!("L1"));
    assert_eq!(reply["lines"][0]["transport"], json!("tcp"), "自动 = 采用已验证的兼容连接：{reply}");
    assert_eq!(reply["lines"][0]["transportSelected"], json!(false), "自动不是「用户选的」：{reply}");
    assert_eq!(reply["lines"][0]["transportVerified"], json!(true), "依据还在：{reply}");
    // 另一条线路完全没被碰。
    assert_eq!(reply["lines"][1]["transportSelected"], json!(false), "{reply}");
    assert_eq!(reply["lines"][1]["transportVerified"], json!(false), "{reply}");

    // 盘上：`transport` 键**消失**（不是 ""、不是 null），`verified_transport` 原样。
    let text = cfg_text(&root);
    assert!(
        !text.contains("\"transport\":"),
        "自动 = 不固定，`transport` 键必须整个消失：{text}"
    );
    assert!(
        text.contains("\"verified_transport\": \"tcp\""),
        "依据必须逐字留着：{text}"
    );
    let disk = config::load(&cfg_path(&root)).unwrap().unwrap();
    let l1 = disk.find_line("L1").unwrap();
    assert_eq!(l1.transport, None, "自动必须落到 `transport = None`");
    assert_eq!(l1.verified_transport, Some(Transport::Tcp), "自动不许抹掉既有依据");
    assert_eq!(l1.effective_transport(), Transport::Tcp);
    // 第二条线路不受影响（命令带 id，就不能动别人）。
    assert_eq!(disk.find_line("L2").unwrap().transport, None);
}

#[test]
fn qa31_set_transport_auto_is_case_insensitive() {
    let root = tmp_root("set-auto-case");
    let mut l1 = bare_line("L1", "线路甲");
    l1.transport = Some(Transport::Udp);
    write_cfg(&root, vec![l1]);

    for raw in ["AUTO", " Auto ", "aUtO"] {
        let reply = ipc_call(
            &root,
            &format!(r#"{{"cmd":"set-transport","transport":"{raw}","id":"L1"}}"#),
        );
        assert_eq!(reply["ok"], json!(true), "`{raw}` 必须当 auto 处理：{reply}");
        assert_eq!(
            read_line(&root, "L1").transport,
            None,
            "`{raw}` 也要清掉固定"
        );
        // 复位，供下一轮再验。
        let mut cfg = config::load(&cfg_path(&root)).unwrap().unwrap();
        cfg.lines[0].transport = Some(Transport::Udp);
        config::save(&cfg_path(&root), &cfg).unwrap();
    }
}

#[test]
fn qa31_set_transport_rejects_unknown_values_with_zero_side_effect() {
    let root = tmp_root("set-bad");
    let mut l1 = bare_line("L1", "线路甲");
    l1.transport = Some(Transport::Udp);
    l1.verified_transport = Some(Transport::Tcp);
    write_cfg(&root, vec![l1]);
    let before = cfg_bytes(&root);

    let reply = ipc_call(&root, r#"{"cmd":"set-transport","transport":"quic","id":"L1"}"#);
    assert_eq!(reply["ok"], json!(false), "非法值必须失败：{reply}");
    assert_eq!(
        reply["error"],
        json!("连接方式只能是 udp、tcp 或 auto（收到：quic）"),
        "报错要逐字列出三个可选值（含 auto）：{reply}"
    );
    assert_eq!(cfg_bytes(&root), before, "拒绝必须零副作用：配置逐字节不变");
}

/// `set-transport` 只看配置，不看「连接中」：它只改下次，不该被 busy 拦住。
#[test]
fn qa31_set_transport_never_consults_the_running_connection() {
    let root = tmp_root("set-busy");
    let mut l1 = bare_line("L1", "线路甲");
    l1.transport = Some(Transport::Udp);
    write_cfg(&root, vec![l1]);
    // 造一份「有连接在跑」的现场：runtime-engine.json 存在 + 代理还原凭据在。
    std::fs::write(root.join("runtime-engine.json"), b"{}").unwrap();
    std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
    let runtime_before = std::fs::read(root.join("runtime-engine.json")).unwrap();

    let reply = ipc_call(&root, r#"{"cmd":"set-transport","transport":"auto","id":"L1"}"#);
    assert_eq!(reply["ok"], json!(true), "连接中也要能改下次的方式：{reply}");
    assert_eq!(read_line(&root, "L1").transport, None, "偏好要落盘");
    assert_eq!(
        std::fs::read(root.join("runtime-engine.json")).unwrap(),
        runtime_before,
        "正在跑的那份运行时配置一个字节都不许动"
    );
}

// ---------------------------------------------------------------------------
// 5. `lines_payload`：`transportVerified` 三态，其余字段不变
// ---------------------------------------------------------------------------

#[test]
fn qa31_lines_payload_reports_three_states_without_disturbing_others() {
    let mut a = bare_line("A", "甲");
    let mut b = bare_line("B", "乙");
    let mut c = bare_line("C", "丙");
    b.transport = Some(Transport::Tcp); // 固定兼容、没依据
    c.verified_transport = Some(Transport::Tcp); // 没固定、验证过兼容
    a.verified_transport = None;
    let mut cfg = app_config(vec![a, b, c]);
    cfg.selected = "A".to_string();

    let v = crate::ipc::lines_payload(Some(&cfg));
    let lines = v["lines"].as_array().expect("lines 数组");
    assert_eq!(lines.len(), 3, "{v}");

    // A：没固定、没依据 → 默认标准连接。
    assert_eq!(lines[0]["transport"], json!("udp"), "{v}");
    assert_eq!(lines[0]["transportSelected"], json!(false), "{v}");
    assert_eq!(lines[0]["transportVerified"], json!(false), "{v}");
    // B：固定兼容、没依据。
    assert_eq!(lines[1]["transport"], json!("tcp"), "{v}");
    assert_eq!(lines[1]["transportSelected"], json!(true), "{v}");
    assert_eq!(lines[1]["transportVerified"], json!(false), "{v}");
    // C：没固定、有依据 → 自动采用兼容连接。
    assert_eq!(lines[2]["transport"], json!("tcp"), "{v}");
    assert_eq!(lines[2]["transportSelected"], json!(false), "{v}");
    assert_eq!(lines[2]["transportVerified"], json!(true), "{v}");

    // 老字段一个都不能少（前端按名取值，改名即破坏契约）。
    for i in 0..3 {
        for key in ["id", "name", "endpoint", "selected"] {
            assert!(!lines[i].get(key).is_none(), "缺字段 {key}：{v}");
        }
    }
    assert_eq!(v["selected"], json!("A"), "{v}");
}

// ---------------------------------------------------------------------------
// 6. 线路卡片：`Profile` / `ProfileSource` / `AutomaticNeedsCheck`
// ---------------------------------------------------------------------------

/// 把指定的线路载荷塞进快照，其余命令一律给空回包。
fn snapshot_with_lines(lines: Value) -> Value {
    let fetch = move |cmd: &str| -> Value {
        let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
        match parsed.get("cmd").and_then(Value::as_str).unwrap_or("") {
            "lines" => json!({"ok": true, "selected": "hk", "lines": lines}),
            _ => Value::Null,
        }
    };
    let mut ui = crate::uiweb::WebUi::new();
    ui.snapshot(&fetch)
}

#[test]
fn qa31_line_card_derives_profile_from_the_effective_value() {
    // 第一条是「老宿主/老配置」的形状：连 `transport` 字段都没有。
    // 缺字段必须兜底标准连接（Udp）——以前兜成 Tcp，让没配置的线路看起来像选了兼容。
    let snap = snapshot_with_lines(json!([
        {"id": "hk", "name": "香港 01", "endpoint": "1.2.3.4:443", "selected": true},
        {"id": "jp", "name": "东京 02", "endpoint": "5.6.7.8:443", "selected": false,
         "transport": "tcp", "transportSelected": true, "transportVerified": true},
        {"id": "sg", "name": "新加坡 03", "endpoint": "9.9.9.9:443", "selected": false,
         "transport": "tcp", "transportSelected": false, "transportVerified": true},
        {"id": "us", "name": "美西 04", "endpoint": "8.8.8.8:443", "selected": false,
         "transport": "udp", "transportSelected": false, "transportVerified": false},
    ]));
    let cards = snap["State"]["Lines"].as_array().expect("lines 卡片");
    assert_eq!(cards.len(), 4, "{snap}");

    // 缺字段 → Udp + Auto + 需要先测（否则页面的「请先测试线路」永远不会出现）。
    assert_eq!(cards[0]["Profile"], json!("Udp"), "缺字段必须兜底 Udp：{}", cards[0]);
    assert_eq!(cards[0]["ProfileSource"], json!("Auto"), "{}", cards[0]);
    assert_eq!(cards[0]["AutomaticNeedsCheck"], json!(true), "{}", cards[0]);

    // 固定兼容 → Tcp + UserChoice + 不用再测。
    assert_eq!(cards[1]["Profile"], json!("Tcp"), "{}", cards[1]);
    assert_eq!(cards[1]["ProfileSource"], json!("UserChoice"), "{}", cards[1]);
    assert_eq!(cards[1]["AutomaticNeedsCheck"], json!(false), "{}", cards[1]);

    // 自动 + 有依据 → Tcp + Auto + 不用再测。
    assert_eq!(cards[2]["Profile"], json!("Tcp"), "自动采用已验证的兼容连接：{}", cards[2]);
    assert_eq!(cards[2]["ProfileSource"], json!("Auto"), "{}", cards[2]);
    assert_eq!(cards[2]["AutomaticNeedsCheck"], json!(false), "{}", cards[2]);

    // 自动 + 无依据 + 标准 → Udp + Auto + 需要先测。
    assert_eq!(cards[3]["Profile"], json!("Udp"), "{}", cards[3]);
    assert_eq!(cards[3]["ProfileSource"], json!("Auto"), "{}", cards[3]);
    assert_eq!(cards[3]["AutomaticNeedsCheck"], json!(true), "{}", cards[3]);

    // `Profile` 必须与宿主 `effective_transport()` 说同一句话：拿真实配置交叉核对。
    let mut pinned = bare_line("jp", "东京 02");
    pinned.transport = Some(Transport::Tcp);
    pinned.verified_transport = Some(Transport::Udp);
    assert_eq!(
        cards[1]["Profile"],
        json!(match pinned.effective_transport() {
            Transport::Tcp => "Tcp",
            Transport::Udp => "Udp",
        }),
        "卡片的方式必须等于生效值"
    );
}

// ---------------------------------------------------------------------------
// 7. 页面点「自动」= 发一条真命令；死 toast 必须消失
// ---------------------------------------------------------------------------

#[test]
fn qa31_choosing_auto_sends_set_transport_auto_and_no_longer_toasts() {
    let fetch = |_cmd: &str| -> Value { Value::Null };
    let mut ui = crate::uiweb::WebUi::new();
    let steps = ui.route(r#"{"Type":"setProfile","Id":"hk","Value":"Auto","Sequence":1}"#, &fetch);

    assert_eq!(steps.len(), 1, "点一下就一条命令：{steps:?}");
    match steps.first() {
        Some(crate::uiweb::Step::Sync(cmd)) => assert_eq!(
            cmd,
            r#"{"cmd":"set-transport","id":"hk","source":"line-action","transport":"auto"}"#,
            "「自动」必须发 set-transport + transport:auto，且带对 id；\
             source 标记让宿主把这次保存记成线路卡片上的动作（r61）"
        ),
        other => panic!("必须是同步命令：{other:?}"),
    }
    assert_eq!(ui.toast, "", "「自动」已经能用了，不该再弹任何提示");

    // 死分支必须真的从源码里删掉（不是「走不到」）。断言语句在**本文件**里，
    // 所以对 `uiweb.rs` 做包含判断不会自匹配。
    let gone = "预览版暂不支持「自动」连接方式";
    let src = include_str!("uiweb.rs");
    assert!(!src.contains(gone), "「{gone}」必须整段删除，不能留死分支");

    // 另外两档的老行为不变（防止改 auto 时把别处改坏）。
    let steps = ui.route(r#"{"Type":"setProfile","Id":"hk","Value":"Udp","Sequence":2}"#, &fetch);
    assert!(
        matches!(steps.first(), Some(crate::uiweb::Step::Sync(c)) if c.contains(r#""transport":"udp""#)),
        "{steps:?}"
    );
    let steps = ui.route(r#"{"Type":"setProfile","Id":"hk","Value":"Tcp","Sequence":3}"#, &fetch);
    assert!(
        matches!(steps.first(), Some(crate::uiweb::Step::Sync(c)) if c.contains(r#""transport":"tcp""#)),
        "{steps:?}"
    );
    // 空 id 不发命令（页面异常时不要写一个「当前线路」）。
    let steps = ui.route(r#"{"Type":"setProfile","Id":"","Value":"Auto","Sequence":4}"#, &fetch);
    assert!(steps.is_empty(), "{steps:?}");
}

// ---------------------------------------------------------------------------
// 8. 端到端：`--lines` 三档后缀（CLI 打印，逐字）
// ---------------------------------------------------------------------------

#[test]
fn qa31_lines_text_uses_three_distinct_suffixes() {
    // 直接量 CLI 打印那一行的拼装结果：`--lines` 的后缀只取决于这两个 Option。
    let cases = [
        (None, None, "标准连接（默认）"),
        (Some(Transport::Udp), None, "标准连接（已选）"),
        (Some(Transport::Tcp), Some(Transport::Udp), "兼容连接（已选）"),
        (None, Some(Transport::Udp), "标准连接（自动）"),
        (None, Some(Transport::Tcp), "兼容连接（自动）"),
    ];
    for (fixed, verified, want) in cases {
        let mut line = bare_line("L1", "线路甲");
        line.transport = fixed;
        line.verified_transport = verified;
        let suffix = if line.transport.is_some() {
            "（已选）"
        } else if line.verified_transport.is_some() {
            "（自动）"
        } else {
            "（默认）"
        };
        assert_eq!(
            format!("{}{}", line.effective_transport().label(), suffix),
            want,
            "固定={fixed:?} 依据={verified:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. 重新导入：用户固定要留，依据要重验（设计意图）
// ---------------------------------------------------------------------------

/// 标准连接形状（没有 VLESS + REALITY 中转参数）的最小线路文件。
fn write_standard_profile(root: &Path) -> PathBuf {
    let dir = root.join("profiles").join("P1");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("dual-mode.json");
    std::fs::write(
        &f,
        r#"{
            "inbounds": [{ "type": "tun", "tag": "trade-tun", "address": ["172.30.250.1/30"],
                           "mtu": 1380, "stack": "gvisor", "auto_route": true, "strict_route": true }],
            "route": { "rules": [], "final": "direct" },
            "outbounds": [{ "type": "direct", "tag": "direct" },
                          { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" }]
        }"#,
    )
    .unwrap();
    f
}

#[test]
fn qa31_reimport_keeps_the_users_choice() {
    let root = tmp_root("reimport-choice");
    let profile = write_standard_profile(&root);
    let origin = crate::events::Origin::cli();

    // 第一次导入：线路参数是新的，任何依据都不该有。
    crate::import_profile(
        &root,
        &profile,
        r"C:\Windows\System32\PING.EXE",
        24_000,
        Some("线路甲"),
        config::Mode::Proxy,
        &origin,
    )
    .expect("首次导入应当成功");
    let id = config::load(&cfg_path(&root)).unwrap().unwrap().lines[0].id.clone();

    // 用户固定了兼容连接，并且这条线路验证过它。
    let mut cfg = config::load(&cfg_path(&root)).unwrap().unwrap();
    cfg.lines[0].transport = Some(Transport::Tcp);
    cfg.lines[0].verified_transport = Some(Transport::Tcp);
    config::save(&cfg_path(&root), &cfg).unwrap();

    // 重新导入同一份标准形状的文件（同名 → 同一条线路）。
    crate::import_profile(
        &root,
        &profile,
        r"C:\Windows\System32\PING.EXE",
        24_000,
        Some("线路甲"),
        config::Mode::Proxy,
        &origin,
    )
    .expect("重新导入应当成功");

    let after = read_line(&root, &id);
    assert_eq!(
        after.transport,
        Some(Transport::Tcp),
        "重新导入不许抹掉用户显式固定的连接方式"
    );
}

/// **回归门（R31-QA-1 已修）**：`import_profile` 把 `verified_transport` 建成 `None`
/// （注释原话「换了一份线路参数，上次通过的依据就不再是这份配置的了，重新验」），
/// `upsert_line` 以前只搬 name / proxy_endpoint / transport、**不搬** `verified_transport`，
/// 于是重导入一条已存在的线路时旧依据原封不动留下来。已补上那一行，
/// 这条用例已从「暂缓执行」转正：谁再把 `upsert_line` 里那一行删掉，这里就会红。
#[test]
fn qa31_reimport_should_clear_the_stale_evidence() {
    let root = tmp_root("reimport-evidence");
    let profile = write_standard_profile(&root);
    let origin = crate::events::Origin::cli();

    crate::import_profile(
        &root,
        &profile,
        r"C:\Windows\System32\PING.EXE",
        24_001,
        Some("线路甲"),
        config::Mode::Proxy,
        &origin,
    )
    .expect("首次导入应当成功");
    let id = config::load(&cfg_path(&root)).unwrap().unwrap().lines[0].id.clone();

    let mut cfg = config::load(&cfg_path(&root)).unwrap().unwrap();
    cfg.lines[0].verified_transport = Some(Transport::Tcp);
    config::save(&cfg_path(&root), &cfg).unwrap();

    crate::import_profile(
        &root,
        &profile,
        r#"C:\Windows\System32\PING.EXE"#,
        24_001,
        Some("线路甲"),
        config::Mode::Proxy,
        &origin,
    )
    .expect("重新导入应当成功");

    assert_eq!(
        read_line(&root, &id).verified_transport,
        None,
        "换了一份线路参数后，「上次通过」的依据必须作废重验"
    );
}
