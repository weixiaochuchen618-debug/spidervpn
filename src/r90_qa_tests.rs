//! r90「删除这台服务器在本机的部署资料」的独立复核（QA 编写）。
//!
//! 与 `servercleanup::tests` / `ipc::tests` 里的用例**方法不同**，目的也不同：那两组
//! 验的是「按设计跑通」，这里验的是「换个角度去证伪」：
//!
//! - 零副作用不是比三个文件，而是对整个数据根做一次「相对路径 → (是否目录, 长度,
//!   修改时间)」的全量快照，前后逐项相等；
//! - 归属判据不只造 `None`，还造一条**同 host:port、但归属是另一条记录**的；
//! - 提醒文件里混一条缺 `RunId` 的坏行、以及整份读不懂的文件；
//! - runs 目录里放一条坏 JSON（`partial`）；
//! - 删不掉时用「允许读、不允许删」的共享模式（`FILE_SHARE_READ | FILE_SHARE_WRITE`），
//!   与工程师用的 `FILE_SHARE_READ` 不同：这里必须允许读，否则判据根本读不到那条记录，
//!   测到的就不是「删不掉」而是「看不见」。
//!
//! 这些用例只读产品逻辑、不改它。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{json, Value};

use crate::ipc::Ctx;

const RECORD_A: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const RECORD_B: &str = "1a2b3c4d-5e6f-4a8b-9c0d-e1f2a3b4c5d6";
const RUN_A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
const RUN_B: &str = "bbbbbbbb-2222-4222-8222-222222222222";
const RUN_C: &str = "cccccccc-3333-4333-8333-333333333333";
/// 坏 JSON 的那条（名字仍是合法 RunId，坏的是内容）。
const RUN_PARTIAL: &str = "eeeeeeee-5555-4555-8555-555555555555";
const HOST: &str = "203.0.113.10";

// ---------------------------------------------------------------------------
// 铺盘
// ---------------------------------------------------------------------------

fn temp_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tcrs-r90-qa-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ctx_for(root: &Path) -> Ctx {
    Ctx {
        cfg: None,
        root: root.to_path_buf(),
        log_dir: root.join("logs"),
        source: crate::events::Source::Other,
        ..Ctx::default()
    }
}

fn call(body: &str, ctx: &Ctx) -> Value {
    serde_json::from_str(&crate::ipc::handle_line_with(body, ctx)).expect("回包必须是一行合法 JSON")
}

fn write_record(root: &Path, id: &str, host: &str) {
    let dir = root.join("servers").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("record.json"),
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.ServerRecord",
            "Id": id,
            "Name": format!("root@{host}"),
            "Host": host,
            "Port": 22,
            "User": "root",
            "Fingerprint": "SHA256:abcdefghijkl",
            "CreatedAtUtc": "2026-11-10T00:00:00Z",
            "UpdatedAtUtc": "2026-11-10T00:00:00Z",
        })
        .to_string(),
    )
    .unwrap();
}

fn write_saved_credential(root: &Path, id: &str) {
    let dir = root.join("servers").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("credential.dpapi.json"), "{}").unwrap();
}

fn write_run_at(root: &Path, run_id: &str, host: &str, record_id: Option<&str>, state: &str) {
    let dir = root.join("deployments").join("runs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{run_id}.json")),
        json!({
            "SchemaVersion": 1,
            "Kind": "SpiderVPN.DeploymentRun",
            "RunId": run_id,
            "State": state,
            "Target": {
                "Host": host,
                "Port": 22,
                "User": "root",
                "ServerRecordId": record_id,
            },
        })
        .to_string(),
    )
    .unwrap();
}

fn write_run(root: &Path, run_id: &str, record_id: Option<&str>, state: &str) {
    write_run_at(root, run_id, HOST, record_id, state);
}

fn run_file(root: &Path, run_id: &str) -> PathBuf {
    root.join("deployments")
        .join("runs")
        .join(format!("{run_id}.json"))
}

fn credential_file(root: &Path, run_id: &str) -> PathBuf {
    root.join("deployments")
        .join("credentials")
        .join(format!("{run_id}.bin"))
}

fn write_task_credential(root: &Path, run_id: &str) {
    let dir = root.join("deployments").join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{run_id}.bin")), "{}").unwrap();
}

fn reminder_file(root: &Path) -> PathBuf {
    root.join("deployments").join("reminders.json")
}

/// 原样写一份提醒文档（条目由调用方给，好塞坏行）。
fn write_reminder_document(root: &Path, items: Value) {
    let file = reminder_file(root);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        &file,
        json!({
            "Schema": 1,
            "Kind": "TradeChannel.DeployReminders",
            "Reminders": items,
        })
        .to_string(),
    )
    .unwrap();
}

fn reminder_of(run_id: &str, state: &str) -> Value {
    json!({
        "Id": format!("{run_id}-{state}"),
        "RunId": run_id,
        "State": state,
        "Step": 4,
        "CreatedAtUtc": "2026-11-10T00:00:00Z",
    })
}

fn write_line(root: &Path, line: &str, host: &str) {
    let dir = root.join("lines");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{line}.json")),
        format!(r#"{{"outbounds":[{{"type":"wireguard","server":"{host}"}}]}}"#),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 全量快照：相对路径 → (是否目录, 长度, 修改时间, 内容指纹)
//
// 目录的**修改时间不参与比对**：NTFS 上「在目录里建/删文件」对目录自身时间戳的写入是
// 延迟的，铺完盘再读一次目录就会看到它跳了一下——那是文件系统的懒更新，不是程序写了
// 盘。把目录时间纳入比对会让每个用例都假红（实测如此）。目录的**存在性**照比不误：
// 预览要是在哪儿建/删了一个目录，仍然会被抓到。
// ---------------------------------------------------------------------------

const FILE_KIND: u8 = 0;
const DIR_KIND: u8 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Entry {
    kind: u8,
    len: u64,
    mtime: Option<SystemTime>,
    digest: u64,
}

type Snap = BTreeMap<String, Entry>;

/// FNV-1a：只要够发现「同长度但内容变了」，不做密码学用途。
fn digest_of(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn snapshot(root: &Path) -> Snap {
    let mut out = Snap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            let rel = path
                .strip_prefix(root)
                .map(|tail| tail.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let record = if meta.is_dir() {
                stack.push(path);
                Entry {
                    kind: DIR_KIND,
                    len: 0,
                    mtime: None,
                    digest: 0,
                }
            } else {
                let bytes = std::fs::read(&path).unwrap_or_default();
                Entry {
                    kind: FILE_KIND,
                    len: meta.len(),
                    mtime: meta.modified().ok(),
                    digest: digest_of(&bytes),
                }
            };
            out.insert(rel, record);
        }
    }
    out
}

/// 前后快照的差异（只列表，不打印整棵树）。
fn snapshot_diff(before: &Snap, after: &Snap) -> Vec<String> {
    let mut diff = Vec::new();
    for (path, before_value) in before {
        match after.get(path) {
            None => diff.push(format!("消失：{path}")),
            Some(after_value) if after_value != before_value => {
                diff.push(format!("变了：{path} {before_value:?} -> {after_value:?}"))
            }
            Some(_) => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            diff.push(format!("新增：{path}"));
        }
    }
    diff
}

fn assert_same_snapshot(before: &Snap, after: &Snap, what: &str) {
    let diff = snapshot_diff(before, after);
    assert!(diff.is_empty(), "{what} 改动了磁盘：{diff:#?}");
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("读不了 {}：{error}", path.display()))
}

// ---------------------------------------------------------------------------
// 1. 预览：整个数据根一个字节都不许变
// ---------------------------------------------------------------------------

#[test]
fn the_preview_leaves_every_file_and_directory_in_the_data_root_untouched() {
    let root = temp_root("preview-snapshot");
    write_record(&root, RECORD_A, HOST);
    write_saved_credential(&root, RECORD_A);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    write_run(&root, RUN_B, None, "Complete");
    write_task_credential(&root, RUN_A);
    write_reminder_document(
        &root,
        json!([
            reminder_of(RUN_A, "Complete"),
            reminder_of(RUN_B, "Complete"),
        ]),
    );
    // 崩溃残留的临时文件也要在快照里：预览若「顺手清理」它，同样算副作用。
    std::fs::write(
        root.join("deployments")
            .join("runs")
            .join(format!(".{RUN_A}.json.tmp-1")),
        b"{}",
    )
    .unwrap();
    std::fs::write(root.join("runtime.json"), b"{}").unwrap();

    let before = snapshot(&root);
    let ctx = ctx_for(&root);
    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    let after = snapshot(&root);

    assert_eq!(preview["ok"], true, "{preview}");
    assert_eq!(preview["serverCleanup"]["Runs"], 1, "{preview}");
    assert_same_snapshot(&before, &after, "server-cleanup-preview");

    // 仪器自检：同长度、不同字节也要被抓到——否则上面那句「完全一致」等于没验。
    std::fs::write(root.join("runtime.json"), b"[]").unwrap();
    std::fs::remove_file(run_file(&root, RUN_A)).unwrap();
    let tampered = snapshot(&root);
    let caught = snapshot_diff(&after, &tampered);
    assert!(
        caught.iter().any(|line| line.contains("runtime.json")),
        "快照必须发现内容变了：{caught:#?}"
    );
    assert!(
        caught.iter().any(|line| line.contains(RUN_A)),
        "快照必须发现文件没了：{caught:#?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 2. 归属：只认 server_record_id，同 host:port 的另外两条都不许动
// ---------------------------------------------------------------------------

#[test]
fn ownership_is_the_record_id_even_when_host_and_port_are_identical() {
    let root = temp_root("ownership-ab");
    // 两条记录指向同一台机器（同一 host:port）——比「None」更狠的一种邻居。
    write_record(&root, RECORD_A, HOST);
    write_record(&root, RECORD_B, HOST);
    write_saved_credential(&root, RECORD_A);
    write_saved_credential(&root, RECORD_B);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    write_run(&root, RUN_B, None, "Complete");
    write_run(&root, RUN_C, Some(RECORD_B), "Complete");

    let neighbors = [run_file(&root, RUN_B), run_file(&root, RUN_C)];
    let neighbor_bytes: Vec<Vec<u8>> = neighbors.iter().map(|path| read_bytes(path)).collect();
    let other_record = root.join("servers").join(RECORD_B).join("record.json");
    let other_record_bytes = read_bytes(&other_record);

    let ctx = ctx_for(&root);
    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(preview["ok"], true, "{preview}");
    assert_eq!(
        preview["serverCleanup"]["Runs"], 1,
        "预览只许数写着这条记录的那一条：{preview}"
    );

    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(done["serverCleanupResult"]["RemovedRuns"], 1, "{done}");

    assert!(!run_file(&root, RUN_A).exists(), "属于它的那条要删掉");
    for (path, bytes) in neighbors.iter().zip(neighbor_bytes.iter()) {
        assert!(path.is_file(), "{} 不是它的资料，必须留着", path.display());
        assert_eq!(&read_bytes(path), bytes, "{} 的字节不许变", path.display());
    }
    assert!(
        other_record.is_file(),
        "另一条记录（同 host:port）的目录不许被动"
    );
    assert_eq!(read_bytes(&other_record), other_record_bytes);
    assert!(!root.join("servers").join(RECORD_A).exists(), "自己的记录要删掉");
    let listed: Vec<String> = done["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["Id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(listed, vec![RECORD_B.to_string()], "只剩另一条记录：{done}");
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 3. 提醒里混一条缺 RunId 的坏行
// ---------------------------------------------------------------------------

#[test]
fn a_reminder_line_that_cannot_be_attributed_survives_the_cleanup() {
    let root = temp_root("reminder-bad-line");
    write_record(&root, RECORD_A, HOST);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    write_run(&root, RUN_B, None, "Complete");
    // 第二条是坏行：`Id` 是数字、没有 `RunId`。
    write_reminder_document(
        &root,
        json!([
            reminder_of(RUN_A, "Complete"),
            {"Id": 5},
            reminder_of(RUN_B, "Complete"),
        ]),
    );

    let ctx = ctx_for(&root);
    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(preview["ok"], true, "坏行不许让预览失败：{preview}");
    assert_eq!(preview["serverCleanup"]["Reminders"], 1, "{preview}");

    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(done["ok"], true, "坏行不许让执行失败：{done}");
    assert_eq!(done["serverCleanupResult"]["RemovedReminders"], 1, "{done}");
    assert!(
        done["serverCleanupResult"]["Failed"].as_array().unwrap().is_empty(),
        "{done}"
    );

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(reminder_file(&root)).unwrap())
        .expect("写回之后仍必须是合法 JSON");
    let items = raw["Reminders"].as_array().cloned().unwrap_or_default();
    assert_eq!(items.len(), 2, "只许摘掉属于它的那一条：{raw}");
    assert!(
        items
            .iter()
            .any(|item| item.get("RunId").and_then(Value::as_str) == Some(RUN_B)),
        "别人的提醒一条都不许动：{raw}"
    );
    let bad = items
        .iter()
        .find(|item| item.get("RunId").is_none())
        .expect("缺 RunId 的坏行必须原样留着");
    assert_eq!(bad["Id"], json!(5), "坏行的字段不许被改写：{raw}");
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 4. 提醒文件整份读不懂：conflict 之外的另一种拒绝，且一个文件都不删
// ---------------------------------------------------------------------------

#[test]
fn an_unreadable_reminder_file_refuses_both_commands_and_deletes_nothing() {
    let root = temp_root("reminder-corrupt");
    write_record(&root, RECORD_A, HOST);
    write_saved_credential(&root, RECORD_A);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    write_task_credential(&root, RUN_A);
    {
        let file = reminder_file(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{ not json").unwrap();
    }

    let before = snapshot(&root);
    let ctx = ctx_for(&root);

    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(preview["ok"], false, "{preview}");
    assert_eq!(preview["errorCode"], "config", "{preview}");

    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(done["ok"], false, "{done}");
    assert_eq!(done["errorCode"], "config", "{done}");

    let after = snapshot(&root);
    assert_same_snapshot(&before, &after, "读不懂提醒文件时的预览与执行");
    assert!(run_file(&root, RUN_A).is_file(), "一条任务记录都不许删");
    assert!(credential_file(&root, RUN_A).is_file(), "任务级凭据也不许删");
    assert!(root.join("servers").join(RECORD_A).is_dir(), "记录目录不许删");
    assert_eq!(
        read_bytes(&reminder_file(&root)),
        b"{ not json".to_vec(),
        "读不懂的文件不许被重写"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 5. partial：runs 目录里有一条坏 JSON
// ---------------------------------------------------------------------------

#[test]
fn a_partial_run_record_is_neither_counted_nor_deleted() {
    let root = temp_root("partial-run");
    write_record(&root, RECORD_A, HOST);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    std::fs::write(run_file(&root, RUN_PARTIAL), b"{oops").unwrap();
    let partial_bytes = read_bytes(&run_file(&root, RUN_PARTIAL));

    let ctx = ctx_for(&root);
    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(preview["ok"], true, "一条坏记录不许让预览失败：{preview}");
    assert_eq!(preview["serverCleanup"]["Runs"], 1, "坏的那条不许被计入：{preview}");
    assert_eq!(preview["serverCleanup"]["Blocked"], "", "{preview}");

    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(done["serverCleanupResult"]["RemovedRuns"], 1, "{done}");
    assert!(!run_file(&root, RUN_A).exists());
    assert!(
        run_file(&root, RUN_PARTIAL).is_file(),
        "读不懂归属的那条必须留在原地"
    );
    assert_eq!(read_bytes(&run_file(&root, RUN_PARTIAL)), partial_bytes);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 6. 三条（四种）拦截，每条都要磁盘逐字节不变
// ---------------------------------------------------------------------------

#[test]
fn every_blocking_condition_refuses_with_conflict_and_freezes_the_disk() {
    struct Case {
        tag: &'static str,
        state: &'static str,
        line: Option<&'static str>,
        expect_in_error: &'static str,
    }
    let cases = [
        Case {
            tag: "lines",
            state: "Complete",
            line: Some("L1"),
            expect_in_error: "条线路",
        },
        Case {
            tag: "running",
            state: "Running",
            line: None,
            expect_in_error: "没有结束",
        },
        Case {
            tag: "queued",
            state: "Queued",
            line: None,
            expect_in_error: "没有结束",
        },
        Case {
            tag: "unknown-state",
            state: "Hovering",
            line: None,
            expect_in_error: "状态读不出来",
        },
    ];

    for case in cases {
        let root = temp_root(case.tag);
        write_record(&root, RECORD_A, HOST);
        write_saved_credential(&root, RECORD_A);
        write_run(&root, RUN_A, Some(RECORD_A), case.state);
        write_task_credential(&root, RUN_A);
        if let Some(line) = case.line {
            write_line(&root, line, HOST);
        }

        let before = snapshot(&root);
        let ctx = ctx_for(&root);
        let preview = call(
            &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
            &ctx,
        );
        assert_eq!(preview["ok"], true, "[{}] {preview}", case.tag);
        let blocked = preview["serverCleanup"]["Blocked"].as_str().unwrap_or_default();
        assert!(
            blocked.contains(case.expect_in_error),
            "[{}] 拦截理由要说清：{preview}",
            case.tag
        );

        let done = call(
            &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
            &ctx,
        );
        assert_eq!(done["ok"], false, "[{}] {done}", case.tag);
        assert_eq!(done["errorCode"], "conflict", "[{}] {done}", case.tag);
        assert!(
            done["error"].as_str().unwrap_or_default().contains(case.expect_in_error),
            "[{}] {done}",
            case.tag
        );

        let after = snapshot(&root);
        assert_same_snapshot(&before, &after, &format!("[{}] 被拦截时", case.tag));
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// 预览之后状态变了：执行侧必须**再判一次**，而不是照着旧预览删。
#[test]
fn a_state_change_between_preview_and_confirm_still_blocks_the_cleanup() {
    let root = temp_root("stale-preview");
    write_record(&root, RECORD_A, HOST);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    let ctx = ctx_for(&root);

    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(preview["serverCleanup"]["Blocked"], "", "{preview}");

    // 用户看确认框的时候，引擎把这条推进成了 Running。
    write_run(&root, RUN_A, Some(RECORD_A), "Running");
    let before = snapshot(&root);

    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(done["ok"], false, "旧预览不能当判据：{done}");
    assert_eq!(done["errorCode"], "conflict", "{done}");
    let after = snapshot(&root);
    assert_same_snapshot(&before, &after, "过时预览后执行");
    assert!(run_file(&root, RUN_A).is_file());
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 7 + 8. 删不掉：如实列出来，`ok` 仍为真；记录目录仍被删掉，且话说得清
// ---------------------------------------------------------------------------

#[test]
fn a_run_file_that_cannot_be_deleted_is_named_in_the_reply_but_the_record_still_goes() {
    use std::os::windows::fs::OpenOptionsExt;
    // 允许别人读、也允许别人写，只**不允许删**（没给 FILE_SHARE_DELETE）。
    // 必须允许读：判据要先读得到这条记录，测的才是「删不掉」，不是「看不见」。
    const FILE_SHARE_READ_AND_WRITE: u32 = 0x0000_0003;

    let root = temp_root("undeletable");
    write_record(&root, RECORD_A, HOST);
    write_saved_credential(&root, RECORD_A);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");
    write_task_credential(&root, RUN_A);
    write_reminder_document(&root, json!([reminder_of(RUN_A, "Complete")]));

    let path = run_file(&root, RUN_A);
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_AND_WRITE)
        .open(&path)
        .expect("要能占住这个文件");

    let ctx = ctx_for(&root);
    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    let result = &done["serverCleanupResult"];
    assert_eq!(done["ok"], true, "已经删了一半，不许报整体失败：{done}");
    assert_eq!(result["RemovedRuns"], 0, "{done}");

    let failed: Vec<&str> = result["Failed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(failed.len(), 1, "删不掉的那一项要单独列出来：{done}");
    assert!(failed[0].contains(RUN_A), "要能认出是哪一条：{done}");

    let message = result["Message"].as_str().unwrap_or_default();
    // 刻意留一行证据（`--nocapture` 才看得到）：这句话是要给人读的，验收时得看原文。
    println!("[evidence] 有提醒与凭据、只删不掉任务记录时的 Message = {message}");
    assert!(message.contains("没删掉"), "这句话必须说明有东西没删掉：{done}");
    assert!(message.contains("1 项"), "要说清有几项：{done}");
    assert!(message.contains(RUN_A), "要能看出是哪一项没删掉：{done}");

    assert!(path.is_file(), "文件确实还在，就不许说删了");
    // 其余该删的都删了：提醒与任务级凭据。
    assert_eq!(result["RemovedReminders"], 1, "{done}");
    assert_eq!(result["RemovedCredentials"], 1, "{done}");
    // 8：记录目录是最后一步，不与任务记录的失败绑定。
    assert!(
        !root.join("servers").join(RECORD_A).exists(),
        "记录目录在这一步仍应被删掉（先摘叶子、最后拔根）：{done}"
    );
    assert!(
        done["servers"].as_array().unwrap().is_empty(),
        "回包里的列表也应当没有这条记录了：{done}"
    );

    // 记录已经拔掉了，所以「再点一次」拿不到重试：它连这条记录都找不到了。
    // 这里只是把当前事实钉住（不是认可这个取舍），免得下一个人以为还能重试那条残留文件。
    let again = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    assert_eq!(again["ok"], false, "{again}");
    assert_eq!(again["errorCode"], "config", "{again}");
    assert!(
        again["error"]
            .as_str()
            .unwrap_or_default()
            .contains("本机没有这条服务器记录"),
        "{again}"
    );

    drop(holder);
    let _ = std::fs::remove_dir_all(&root);
}

/// 没有任何部署资料的记录：预览不许顺手建出 `deployments\`（那本身就是副作用）。
#[test]
fn previewing_a_record_with_no_deploy_material_creates_no_directory() {
    let root = temp_root("preview-empty");
    write_record(&root, RECORD_A, HOST);

    let before = snapshot(&root);
    let ctx = ctx_for(&root);
    let preview = call(
        &format!(r#"{{"cmd":"server-cleanup-preview","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    let after = snapshot(&root);

    assert_eq!(preview["ok"], true, "{preview}");
    assert_eq!(preview["serverCleanup"]["Runs"], 0, "{preview}");
    assert_eq!(preview["serverCleanup"]["Reminders"], 0, "{preview}");
    assert_eq!(preview["serverCleanup"]["TaskCredentials"], 0, "{preview}");
    assert_eq!(
        preview["serverCleanup"]["Items"],
        json!(["服务器记录"]),
        "{preview}"
    );
    assert_same_snapshot(&before, &after, "无资料时的预览");
    assert!(
        !root.join("deployments").exists(),
        "本来不存在的 deployments\\ 不许被预览建出来"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 只删不掉一条任务记录、别的都没有：这时那句话仍然要点名是哪一项。
#[test]
fn a_single_undeletable_run_record_is_named_even_when_nothing_else_was_removed() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ_AND_WRITE: u32 = 0x0000_0003;

    let root = temp_root("undeletable-only");
    write_record(&root, RECORD_A, HOST);
    write_run(&root, RUN_A, Some(RECORD_A), "Complete");

    let path = run_file(&root, RUN_A);
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_AND_WRITE)
        .open(&path)
        .expect("要能占住这个文件");

    let ctx = ctx_for(&root);
    let done = call(
        &format!(r#"{{"cmd":"server-cleanup","id":"{RECORD_A}"}}"#),
        &ctx,
    );
    let result = &done["serverCleanupResult"];
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(result["RemovedRuns"], 0, "{done}");
    assert_eq!(result["RemovedReminders"], 0, "{done}");
    assert_eq!(result["RemovedCredentials"], 0, "{done}");
    let message = result["Message"].as_str().unwrap_or_default();
    println!("[evidence] 只删不掉一条任务记录时的 Message = {message}");
    assert!(message.contains("1 项没删掉"), "{done}");
    assert!(message.contains(RUN_A), "要能看出是哪一项：{done}");
    assert!(path.is_file(), "{done}");

    drop(holder);
    let _ = std::fs::remove_dir_all(&root);
}
