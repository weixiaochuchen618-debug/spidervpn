//! 邀请页的宿主侧用例（r33）。
//!
//! 这一层的风险不是密码学（那在 `pairhost_tests` 里钉住了），而是**状态机与投影**：
//! 阶段推错会让页面一直转圈，投影错会让完整邀请码漏进快照（快照每秒重推、会进日志、
//! 会被截图）。所以这里每一条都盯着「哪一步发了什么命令」与「快照里到底有什么」。

use serde_json::{json, Value};

use crate::uiweb::{Step, WebUi};

fn empty(_command: &str) -> Value {
    json!({})
}

/// 快照是 `{Page, State}` 两层：页面读的是 `State`，断言也按同一层看。
fn state(view: &Value) -> &Value {
    view.get("State").unwrap_or(&Value::Null)
}

fn begin(ui: &mut WebUi) {
    ui.route(r#"{"Type":"invite","Phase":"Begin","Id":"L1"}"#, &empty);
}

/// 签发成功后的回包（与 `ipc::invite_reply` 同形状）。
const CODE: &str = "TCI1.eyJ2IjoxLCJoIjoiMjAzLjAuMTEzLjEwIn0-SECRETTAIL";

fn created(ui: &mut WebUi) {
    ui.finish_op(&json!({
        "ok": true,
        "invite": {
            "Section": "Create",
            "Data": {
                "ServerId": "S1",
                "Code": CODE,
                "InviteId": "I1",
                // 离线交接要的是签名邀请本身，不是 TCI1 码。
                "Invite": "eyJhbGciOiJSUzI1NiJ9.eyJLaW5kIjoiVHJhZGVjaGFubmVsLlBhaXJJbnZpdGUifQ.c2ln",
                "ManagementFingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ExpiresAtUtc": "2026-11-07T06:00:00Z",
                "DeviceName": "新电脑",
                "LifetimeSeconds": 1800
            }
        }
    }));
}

#[test]
fn 进入邀请页会建会话并切页() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    assert_eq!(ui.page, "invite");
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["LineId"], "L1");
    // 默认 30 分钟，与旧版的预设一致。
    assert_eq!(state(&view)["Invite"]["LifetimeSeconds"], 1800);
    assert_eq!(state(&view)["Invite"]["State"], "");
    // 进页面先量 18443：这一步没走完之前，页面停在「正在检查」。
    assert_eq!(state(&view)["Invite"]["Phase"], "Checking");
    assert_eq!(state(&view)["Invite"]["Reachability"]["Status"], "Checking");
}

#[test]
fn 进页面会先发一次自检并带上线路() {
    let mut ui = WebUi::new();
    let steps = ui.route(r#"{"Type":"invite","Phase":"Begin","Id":"L1"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-reachability"), "{command}");
            assert!(command.contains(r#""line":"L1""#), "{command}");
        }
        other => panic!("自检必须走长命令（要真连一次网络），实际是 {other:?}"),
    }
}

#[test]
fn 自检结果落进快照且不挡住生成() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    // 端口被防火墙挡住：如实进投影，页面才有话说。
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Reachability", "Data": {
            "Status": "Refused", "Port": 18443, "Host": "203.0.113.10"
        }}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Reachability"]["Status"], "Refused");
    assert_eq!(state(&view)["Invite"]["Phase"], "", "自检结束就该回到设置页");
    // 不通不是错误：码照样能生成，只是页面会提示先放行端口。
    let steps = ui.route(r#"{"Type":"invite","Phase":"CreateNew","Value":1800}"#, &empty);
    assert!(matches!(&steps[0], Step::Long(c) if c.contains("invite-create")));
}

#[test]
fn 生成邀请码走长命令并带上线路与有效期() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    let steps = ui.route(r#"{"Type":"invite","Phase":"CreateNew","Value":7200}"#, &empty);
    assert_eq!(steps.len(), 1, "生成只该发一条命令");
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-create"), "{command}");
            assert!(command.contains(r#""line":"L1""#), "{command}");
            assert!(command.contains(r#""lifetime":7200"#), "{command}");
        }
        other => panic!("生成邀请码必须走长命令，实际是 {other:?}"),
    }
    // 页面此刻应显示「正在生成」，而不是停在设置页让人再点一次。
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Phase"], "Creating");
    assert_eq!(state(&view)["Invite"]["LifetimeSeconds"], 7200);
}

#[test]
fn 有效期越界时回落默认值而不是发出非法命令() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    // 5 分钟低于下限（10 分钟）：不拒绝整个动作，但要按默认值签发。
    let steps = ui.route(r#"{"Type":"invite","Phase":"CreateNew","Value":300}"#, &empty);
    match &steps[0] {
        Step::Long(command) => assert!(command.contains(r#""lifetime":1800"#), "{command}"),
        other => panic!("应当是长命令，实际是 {other:?}"),
    }
}

#[test]
fn 签发回包落进快照且预览不暴露完整码() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["State"], "Open");
    assert_eq!(state(&view)["Invite"]["InviteId"], "I1");
    assert_eq!(state(&view)["Invite"]["ExpiresAtUtc"], "2026-11-07T06:00:00Z");
    assert_eq!(state(&view)["Invite"]["CodePresent"], true);
    let preview = state(&view)["Invite"]["CodePreview"].as_str().unwrap_or("");
    assert!(preview.starts_with("TCI1."), "{preview}");
    assert!(!preview.contains("SECRETTAIL"), "预览里不能有完整码：{preview}");
    // 整个快照里都不该出现尾部——它会进日志、进截图。
    assert!(!ui.snapshot(&empty).to_string().contains("SECRETTAIL"));
}

#[test]
fn 显示邀请码只递一次且不进快照() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    let steps = ui.route(r#"{"Type":"invite","Phase":"Reveal"}"#, &empty);
    assert_eq!(steps.len(), 1);
    match &steps[0] {
        Step::Script(script) => {
            assert!(script.contains("inviteCode"), "{script}");
            assert!(script.contains("__tcPush"), "要经页面既有的消息入口，{script}");
            assert!(script.contains(CODE), "递出去的必须是完整码");
        }
        other => panic!("显示必须走一次性脚本通道，实际是 {other:?}"),
    }
    // 递出去之后快照依然干净：这条命令是「只发一次」，不是「改成明文存着」。
    assert!(!ui.snapshot(&empty).to_string().contains("SECRETTAIL"));
}

#[test]
fn 作废之后码不再可用() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    let steps = ui.route(r#"{"Type":"invite","Phase":"Cancel"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => assert!(command.contains("invite-cancel"), "{command}"),
        other => panic!("作废应当是长命令，实际是 {other:?}"),
    }
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Cancel", "Data": {"ServerId": "S1", "InviteId": "I1", "State": "Cancelled"}}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["State"], "Cancelled");
    // 作废的码留在内存里只会让「复制」复制出一张废码。
    assert_eq!(state(&view)["Invite"]["CodePresent"], false);
    // 此时再点「显示」不能凭空造出码来。
    let steps = ui.route(r#"{"Type":"invite","Phase":"Reveal"}"#, &empty);
    assert!(steps.is_empty(), "没有码时不该发脚本");
}

#[test]
fn 失败回包给的是具体下一步而不是笼统重试() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Create", "Data": {
            "ErrorCode": "InviteNeedsServer",
            "ErrorMessage": "这条线路不对应本机保存的服务器。"
        }}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["ErrorCode"], "InviteNeedsServer");
    // 「去服务器页处理」才是能解决问题的那一步；给「重试」只会得到同一句话。
    assert_eq!(state(&view)["Invite"]["NextAction"], "OpenServer");
    // 失败之后不能还停在「正在生成」。
    assert_eq!(state(&view)["Invite"]["Phase"], "");
}

#[test]
fn 关掉页面会清掉会话() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    ui.route(r#"{"Type":"invite","Phase":"Close"}"#, &empty);
    assert_eq!(ui.page, "lines");
    assert_eq!(state(&ui.snapshot(&empty))["Invite"], Value::Null);
}

#[test]
fn 线路归属到服务器时才能邀请() {
    let fetch = |command: &str| -> Value {
        if command.contains("servers") {
            json!({"ok": true, "servers": [
                {"Id": "S1", "Name": "自建 · 203.0.113.10", "Host": "203.0.113.10", "LineIds": ["L1"]}
            ]})
        } else if command.contains("lines") {
            json!({"ok": true, "selected": "L1", "lines": [
                {"id": "L1", "name": "自建 · 203.0.113.10", "proxy_endpoint": "127.0.0.1:7890"},
                {"id": "L2", "name": "别人给的", "proxy_endpoint": "127.0.0.1:7891"}
            ]})
        } else {
            json!({})
        }
    };
    let mut ui = WebUi::new();
    let view = ui.snapshot(&fetch);
    let lines = state(&view)["Lines"].as_array().expect("要有线路");
    let owned = lines.iter().find(|line| line["Id"] == "L1").expect("L1");
    assert_eq!(owned["CanInvite"], true);
    assert_eq!(owned["ServerRecordId"], "S1");
    assert_eq!(owned["ServerName"], "自建 · 203.0.113.10");
    // 没有归属的线路不能邀请：点进去会得到「这台服务器不归你管」。
    let other = lines.iter().find(|line| line["Id"] == "L2").expect("L2");
    assert_eq!(other["CanInvite"], false);
    assert_eq!(other["ServerRecordId"], "");
}


/// 归属表失败一次不能把入口锁死。
///
/// 原来的实现把失败也缓存 30 秒：命令失败一次（进程刚起、盘正忙），「邀请其他电脑」
/// 就灰掉半分钟，而用户看不到任何线索。失败必须当场重试。
#[test]
fn 归属表失败一次不会把入口锁死() {
    let fail = std::cell::Cell::new(true);
    let fetch = |command: &str| -> Value {
        if command.contains("servers") {
            if fail.get() {
                json!({"ok": false, "servers": [], "error": "目录正忙"})
            } else {
                json!({"ok": true, "servers": [
                    {"Id": "S1", "Name": "自建", "Host": "1.2.3.4", "LineIds": ["L1"]}
                ]})
            }
        } else if command.contains("lines") {
            json!({"ok": true, "selected": "L1", "lines": [
                {"id": "L1", "name": "自建", "proxy_endpoint": "127.0.0.1:7890"}
            ]})
        } else {
            json!({})
        }
    };
    let mut ui = WebUi::new();
    let first = ui.snapshot(&fetch);
    assert_eq!(state(&first)["Lines"][0]["CanInvite"], false);
    // 命令恢复：下一帧就该能邀请，而不是等缓存过期。
    fail.set(false);
    let second = ui.snapshot(&fetch);
    assert_eq!(state(&second)["Lines"][0]["CanInvite"], true);
    assert_eq!(state(&second)["Lines"][0]["ServerRecordId"], "S1");
}

#[test]
fn 多服务器选择会同时保存线路与服务器并用于签发() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    // 从上一台服务器的结果重新选择：旧结果必须立即退出投影。
    ui.route(r#"{"Type":"invite","Phase":"Choose"}"#, &empty);
    let choose = ui.snapshot(&empty);
    assert_eq!(state(&choose)["Invite"]["InviteId"], "");
    assert_eq!(state(&choose)["Invite"]["State"], "");
    assert_eq!(state(&choose)["Invite"]["CodePresent"], false);

    ui.route(
        r#"{"Type":"invite","Phase":"Target","Id":"L2","Value":"S2"}"#,
        &empty,
    );
    let selected = ui.snapshot(&empty);
    assert_eq!(state(&selected)["Invite"]["LineId"], "L2");
    assert_eq!(state(&selected)["Invite"]["ServerId"], "S2");

    let steps = ui.route(r#"{"Type":"invite","Phase":"CreateNew","Value":1800}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains(r#""line":"L2""#), "必须签到选中的服务器：{command}");
            assert!(!command.contains(r#""line":"L1""#), "不能退回旧线路：{command}");
        }
        other => panic!("生成邀请码必须走长命令，实际是 {other:?}"),
    }
}

#[test]
fn 失败后的重试重发失败的那一条命令而不是新动作() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    // 签发失败：页面给的下一步是「重试」，重试必须是再签发一次。
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Create", "Data": {
            "ErrorCode": "InviteNetwork",
            "ErrorMessage": "连不上这台服务器。"
        }}
    }));
    let steps = ui.route(r#"{"Type":"invite","Phase":"Retry"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-create"), "{command}");
            assert!(command.contains(r#""lifetime":1800"#), "{command}");
            assert!(command.contains(r#""line":"L1""#), "{command}");
        }
        other => panic!("重试签发必须走长命令，实际是 {other:?}"),
    }
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Phase"], "Creating");
    assert_eq!(state(&view)["Invite"]["ErrorCode"], "");

    // 检查失败：同一个「重试」按钮，这次要重查状态，而不是再签一张。
    created(&mut ui);
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Status", "Data": {
            "ErrorCode": "InviteNetwork", "ErrorMessage": "连不上这台服务器。"
        }}
    }));
    let steps = ui.route(r#"{"Type":"invite","Phase":"Retry"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => assert!(command.contains("invite-status"), "{command}"),
        other => panic!("重查必须走长命令，实际是 {other:?}"),
    }
}

#[test]
fn 重新生成会立即离开上一张结果卡并清除旧码() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    ui.route(r#"{"Type":"invite","Phase":"CreateNew","Value":1800}"#, &empty);
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Phase"], "Creating");
    assert_eq!(state(&view)["Invite"]["InviteId"], "");
    assert_eq!(state(&view)["Invite"]["State"], "");
    assert_eq!(state(&view)["Invite"]["CodePresent"], false);
    assert!(!view.to_string().contains("SECRETTAIL"));
}

// ---- 离线交接（r67） ----

#[test]
fn 离线交接复用当前邀请并批准新电脑的申请() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);

    // 改用离线邀请：手上已有完整邀请，不该再签发一张。
    let steps = ui.route(r#"{"Type":"invite","Phase":"Offline"}"#, &empty);
    assert!(steps.is_empty(), "已有完整邀请时不该再发命令：{steps:?}");
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Offline"], true);
    assert_eq!(state(&view)["Invite"]["OfflineInvitePresent"], true);
    assert_eq!(
        state(&view)["Invite"]["OfflineFingerprint"],
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    // 完整邀请不走快照，只走剪贴板。
    assert!(!view.to_string().contains("eyJhbGciOiJSUzI1NiJ9"));

    let request = "eyJhbGciOiJSUzI1NiJ9.eyJLaW5kIjoiVHJhZGVjaGFubmVsLlBhaXJSZXF1ZXN0In0.c2ln";
    let steps = ui.route(
        &json!({"Type":"invite","Phase":"OfflineApprove","Id":"L1","Value":request}).to_string(),
        &empty,
    );
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-authorize"), "{command}");
            assert!(command.contains(r#""line":"L1""#), "{command}");
            assert!(command.contains(request), "{command}");
        }
        other => panic!("离线批准必须走长命令，实际是 {other:?}"),
    }
    assert_eq!(ui.snapshot(&empty)["State"]["Invite"]["Phase"], "Creating");

    // 批准回包：只投影「已生成」，授权本身留在宿主侧。
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Authorize", "Data": {
            "ServerId": "S1",
            "InviteId": "I1",
            "RequestId": "R1",
            "DeviceName": "新电脑",
            "PairingCode": "ABCDEF123456",
            "Authorization": "header.key.iv.ct.tag"
        }}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["OfflineAuthorizationPresent"], true);
    assert_eq!(state(&view)["Invite"]["OfflineDeviceName"], "新电脑");
    assert_eq!(state(&view)["Invite"]["OfflinePairingCode"], "ABCDEF123456");
    assert!(!view.to_string().contains("header.key.iv.ct.tag"), "授权不进快照");
}

#[test]
fn 旧服务器没有完整邀请时离线入口会补签一张二十四小时邀请() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Create", "Data": {
            "ServerId": "S1",
            "Code": CODE,
            "InviteId": "I1",
            "ExpiresAtUtc": "2026-11-07T06:00:00Z",
            "DeviceName": "新电脑",
            "LifetimeSeconds": 1800
        }}
    }));
    let steps = ui.route(r#"{"Type":"invite","Phase":"Offline"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-create"), "{command}");
            assert!(command.contains(r#""lifetime":86400"#), "{command}");
        }
        other => panic!("补签离线邀请必须走长命令，实际是 {other:?}"),
    }
    assert_eq!(ui.snapshot(&empty)["State"]["Invite"]["Offline"], true);
}

#[test]
fn 重新开启接收服务会先自动判定而不是盲重装() {
    let mut ui = WebUi::new();
    begin(&mut ui);
    created(&mut ui);
    let steps = ui.route(r#"{"Type":"invite","Phase":"Rearm"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("invite-preflight"), "{command}");
            assert!(command.contains(r#""line":"L1""#), "{command}");
            assert!(
                !command.contains("invite-init"),
                "不能绕开判定直接重装：{command}"
            );
        }
        other => panic!("自动判定必须走长命令，实际是 {other:?}"),
    }
    assert_eq!(ui.snapshot(&empty)["State"]["Invite"]["Phase"], "Checking");

    // 判定结果（防火墙档）要落进投影：页面据此显示具体的下一步，而不是笼统的「连不上」。
    ui.finish_op(&json!({
        "ok": true,
        "invite": {"Section": "Preflight", "Data": {
            "Status": "Timeout", "Port": 18443, "Host": "203.0.113.10",
            "Verdict": "Firewall",
            "Detail": "服务在跑，但从这台电脑连不上 18443；服务器防火墙开着，请在云防火墙放行 TCP 18443。",
            "Repaired": false, "Installed": true, "Active": true, "PortListening": true
        }}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Invite"]["Reachability"]["Verdict"], "Firewall");
    assert_eq!(state(&view)["Invite"]["Phase"], "");
}

#[test]
fn 新电脑的离线三步按顺序推进且旧回包被忽略() {
    let mut ui = WebUi::new();
    let steps = ui.route(
        r#"{"Type":"pairOnline","Phase":"OfflineInspect","Code":"a.b.c","Name":"新电脑"}"#,
        &empty,
    );
    match &steps[0] {
        Step::Long(command) => assert!(command.contains("pair-offline-inspect"), "{command}"),
        other => panic!("离线校验必须走长命令，实际是 {other:?}"),
    }
    let view = ui.snapshot(&empty);
    let pair = &state(&view)["Pair"];
    assert_eq!(pair["Offline"], true);
    assert_eq!(pair["Phase"], "Creating");
    let pair_id = pair["PairId"].as_str().unwrap().to_string();

    // 旧回包（另一个 PairId）不能把会话推进。
    ui.finish_op(&json!({
        "ok": true,
        "pairOffline": {"Stage": "Inspect", "PairId": "other", "Code": "",
            "Fingerprint": "SHA256:X", "DeviceName": "新电脑",
            "ExpiresAtUtc": "2026-11-12T00:00:00Z", "NodeName": ""}
    }));
    assert_eq!(ui.snapshot(&empty)["State"]["Pair"]["Phase"], "Creating");

    ui.finish_op(&json!({
        "ok": true,
        "pairOffline": {"Stage": "Inspect", "PairId": pair_id, "Code": "",
            "Fingerprint": "SHA256:KNOWN", "DeviceName": "新电脑",
            "ExpiresAtUtc": "2026-11-12T00:00:00Z", "NodeName": "node-1"}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Pair"]["Phase"], "OfflineReady");
    assert_eq!(state(&view)["Pair"]["OfflineFingerprint"], "SHA256:KNOWN");

    let steps = ui.route(r#"{"Type":"pairOnline","Phase":"OfflineRequest"}"#, &empty);
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("pair-offline-request"), "{command}");
            assert!(command.contains("SHA256:KNOWN"), "{command}");
            assert!(command.contains(&pair_id), "{command}");
        }
        other => panic!("生成申请必须走长命令，实际是 {other:?}"),
    }
    ui.finish_op(&json!({
        "ok": true,
        "pairOffline": {"Stage": "Request", "PairId": pair_id, "Code": "",
            "EnrollmentId": "E1", "InviteId": "I1", "RequestText": "request.jws",
            "PairingCode": "ABCDEF123456", "DeviceName": "新电脑",
            "ExpiresAtUtc": "2026-11-12T00:00:00Z", "Resumed": false}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Pair"]["Phase"], "OfflineRequested");
    assert_eq!(state(&view)["Pair"]["OfflineRequest"], "request.jws");
    assert_eq!(state(&view)["Pair"]["PairingCode"], "ABCDEF123456");

    let steps = ui.route(
        r#"{"Type":"pairOnline","Phase":"OfflineComplete","Code":"grant.jwe","Name":"离线线路"}"#,
        &empty,
    );
    match &steps[0] {
        Step::Long(command) => {
            assert!(command.contains("pair-offline-complete"), "{command}");
            assert!(command.contains("grant.jwe"), "{command}");
            assert!(command.contains("E1"), "{command}");
        }
        other => panic!("导入授权必须走长命令，实际是 {other:?}"),
    }
    ui.finish_op(&json!({
        "ok": true,
        "pairOffline": {"Stage": "Complete", "PairId": pair_id, "Code": "",
            "LineId": "L9", "LineName": "离线线路", "Compatible": false,
            "State": "Completed", "EnrollmentId": "E1"}
    }));
    let view = ui.snapshot(&empty);
    assert_eq!(state(&view)["Pair"]["Phase"], "Complete");
    assert_eq!(state(&view)["Pair"]["LocalName"], "离线线路");
}
