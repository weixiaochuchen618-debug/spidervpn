//! 界面发起的长操作（连接 / 断开 / 诊断）的结果记录：`<data root>/logs/ui-operations.json`。
//!
//! 线路动作（`lineaction`）只是这条路的第二块。第一块是**连接与断开**：它们改系统代理、
//! 起停引擎，是这台机器上副作用最大的两个动作。进程在中间被杀掉时，用户看到的是
//! 「刚才点了连接，然后程序没了」——现在到底连没连上、代理有没有被改、还原凭据还在
//! 不在，全是未知。页面若把这次点击忘掉，用户只能猜。
//!
//! 所以动作在**开始时**就落盘（`Pending`），有结论后再改写成 `Succeeded` / `Failed`。
//! 启动时把仍是 `Pending` 的记录改判：连接/断开 → `NeedsReview`（副作用未知，必须核对）；
//! 诊断是只读操作，不产生需要核对的后果，改判 `Failed` 并说明「可以重新运行」。
//!
//! 记录里**不存命令原文**：重试只能由用户重新点一次连接/诊断，宿主从不回放原请求。
//! 这样既不会把带参数的请求（例如以后可能出现的凭据）落进日志，也不存在「重试跑的是
//! 一份过期的意图」这种问题。
//!
//! 写入沿用临时文件 + 重命名：中途断电不会留下半截 JSON（半截记录既不能展示也不能核对）。
//! 同类动作只留最新一条（`NeedsReview` 除外——那是还没人管的事实，不能因为用户又点了
//! 一次就消失）；总量有上限，先丢最早的已结束记录，永远不丢 `NeedsReview`。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

pub const KIND: &str = "TradeChannel.UiOperations";
pub const SCHEMA: u32 = 1;

const DIR: &str = "logs";
const NAME: &str = "ui-operations.json";
const MAX_RECORDS: usize = 200;
const MAX_MESSAGE_CHARS: usize = 300;

pub const CONNECT: &str = "Connect";
pub const DISCONNECT: &str = "Disconnect";
pub const DIAGNOSE: &str = "Diagnose";

pub const PENDING: &str = "Pending";
pub const SUCCEEDED: &str = "Succeeded";
pub const FAILED: &str = "Failed";
pub const NEEDS_REVIEW: &str = "NeedsReview";

/// 进程内的写锁。`begin` 在 UI 线程、`finish` 在协调线程、`settle` 在管道/请求线程，
/// 三个线程写同一个文件：没有锁就会互相当成「对方不存在」，后写者覆盖先写者。
static STORE_LOCK: Mutex<()> = Mutex::new(());

fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub kind: String,
    pub phase: String,
    pub message: String,
    pub code: String,
    pub started_at_utc: String,
    pub started_at_unix: i64,
    pub finished_at_utc: String,
    pub origin: String,
}

pub fn path(root: &Path) -> PathBuf {
    root.join(DIR).join(NAME)
}

/// 给人看的路径。界面只说相对位置，不把用户的绝对目录带出去。
pub fn display_path() -> String {
    format!("{DIR}\\{NAME}")
}

fn bad(message: &str) -> String {
    format!("{message}（{}）", display_path())
}

fn now_rfc3339() -> String {
    crate::provider::now_rfc3339()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 记录里的一句话**不是**宿主回包的完整拷贝：截断，免得一次异常把整份记录撑大。
fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_MESSAGE_CHARS {
        return text.to_string();
    }
    let mut clipped: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
    clipped.push('…');
    clipped
}

/// 哪些命令值得记录。只有会改系统状态、且用户会在界面上等的长命令：
/// 其余长命令（部署、邀请、设备）各有自己的记录/进度通道，塞进来只会重复。
pub fn kind_of_command(cmd: &str) -> Option<&'static str> {
    match cmd {
        "connect" => Some(CONNECT),
        "disconnect" => Some(DISCONNECT),
        "diagnose" => Some(DIAGNOSE),
        _ => None,
    }
}

pub fn label(kind: &str) -> &'static str {
    match kind {
        CONNECT => "连接",
        DISCONNECT => "断开",
        DIAGNOSE => "诊断",
        _ => "操作",
    }
}

/// 新记录：开始时就把 id 与开始时间定下来。`Pending` 由这里统一给。
fn started(kind: &str, origin: &str) -> Record {
    Record {
        id: crate::pairing::random_uuid_v4(),
        kind: kind.to_string(),
        phase: PENDING.to_string(),
        message: String::new(),
        code: String::new(),
        started_at_utc: now_rfc3339(),
        started_at_unix: now_unix(),
        finished_at_utc: String::new(),
        origin: origin.to_string(),
    }
}

pub fn to_json(record: &Record) -> Value {
    json!({
        "Id": record.id,
        "Kind": record.kind,
        "Phase": record.phase,
        "Message": record.message,
        "Code": record.code,
        "StartedAtUtc": record.started_at_utc,
        "StartedAtUnix": record.started_at_unix,
        "FinishedAtUtc": record.finished_at_utc,
        "Origin": record.origin,
    })
}

fn from_json(item: &Value) -> Option<Record> {
    let text_of = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default()
    };
    let known_phase = matches!(
        text_of("Phase").as_str(),
        PENDING | SUCCEEDED | FAILED | NEEDS_REVIEW
    );
    if !known_phase {
        return None;
    }
    Some(Record {
        id: text_of("Id"),
        kind: text_of("Kind"),
        phase: text_of("Phase"),
        message: text_of("Message"),
        code: text_of("Code"),
        started_at_utc: text_of("StartedAtUtc"),
        started_at_unix: item.get("StartedAtUnix").and_then(Value::as_i64).unwrap_or(0),
        finished_at_utc: text_of("FinishedAtUtc"),
        origin: text_of("Origin"),
    })
}

fn load_unlocked(root: &Path) -> Result<Vec<Record>, String> {
    let file = path(root);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(bad(&format!("读取操作记录失败：{error}"))),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| bad("操作记录不是合法 JSON，无法判断这些操作的结果"))?;
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return Err(bad("操作记录的文件类型不认识"));
    }
    let mut out = Vec::new();
    for item in value
        .get("Records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(record) = from_json(&item) else {
            return Err(bad("操作记录里有一条的阶段不认识，无法判断它做没做成"));
        };
        if record.id.trim().is_empty() {
            return Err(bad("操作记录里有一条缺少 id，无法核对"));
        }
        if record.started_at_utc.trim().is_empty() {
            return Err(bad("操作记录里有一条缺少开始时间，无法判断先后"));
        }
        if !matches!(record.kind.as_str(), CONNECT | DISCONNECT | DIAGNOSE) {
            return Err(bad("操作记录里有一条的类型不认识"));
        }
        out.push(record);
    }
    Ok(out)
}

fn save_unlocked(root: &Path, records: &[Record]) -> Result<(), String> {
    let file = path(root);
    if records.is_empty() {
        return match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(bad(&format!("清除操作记录失败：{error}"))),
        };
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| bad(&format!("创建操作记录目录失败：{error}")))?;
    }
    let body = json!({
        "SchemaVersion": SCHEMA,
        "Kind": KIND,
        "Records": records.iter().map(to_json).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&body)
        .map_err(|_| bad("操作记录无法序列化"))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|error| bad(&format!("写入操作记录失败：{error}")))?;
    std::fs::rename(&temp, &file).map_err(|error| bad(&format!("写入操作记录失败：{error}")))
}

/// 读出全部记录。文件不存在 = 没有记录；坏记录**照实报错**——静默当成空会让
/// 「待核对」的入口永远消失，而记录文件还在那里。
pub fn load(root: &Path) -> Result<Vec<Record>, String> {
    let _guard = lock_store();
    load_unlocked(root)
}

pub fn save(root: &Path, records: &[Record]) -> Result<(), String> {
    let _guard = lock_store();
    save_unlocked(root, records)
}

/// 超出上限时丢最早的**已结束**记录。`NeedsReview` / `Pending` 是「还没人管」的事实，
/// 任何情况下都不静默丢掉。
fn trim(records: &mut Vec<Record>) {
    while records.len() > MAX_RECORDS {
        let Some(position) = records
            .iter()
            .position(|record| matches!(record.phase.as_str(), SUCCEEDED | FAILED))
        else {
            break;
        };
        records.remove(position);
    }
}

/// 开始一个操作：先落 `Pending`，再由调用方真正执行。写不进去时调用方必须**不开始**——
/// 「做了但没记录」正是这套记录要消灭的状态。
pub fn begin(root: &Path, kind: &str, origin: &str) -> Result<Record, String> {
    if !matches!(kind, CONNECT | DISCONNECT | DIAGNOSE) {
        return Err(bad("这个操作类型不认识，不能记录"));
    }
    let _guard = lock_store();
    let mut records = load_unlocked(root)?;
    // 同类只留最新一条；`NeedsReview` 保留——它还没被核对，不能被新一次点击掩埋。
    records.retain(|existing| !(existing.kind == kind && existing.phase != NEEDS_REVIEW));
    let record = started(kind, origin);
    records.push(record.clone());
    trim(&mut records);
    save_unlocked(root, &records)?;
    Ok(record)
}

fn update(
    root: &Path,
    id: &str,
    from_phase: &str,
    phase: &str,
    message: &str,
    code: &str,
) -> Result<Record, String> {
    if !matches!(phase, SUCCEEDED | FAILED) {
        return Err(bad("结论阶段不认识，记录没有落盘"));
    }
    let _guard = lock_store();
    let mut records = load_unlocked(root)?;
    let Some(record) = records.iter_mut().find(|record| record.id == id) else {
        return Err(bad(if from_phase == PENDING {
            "找不到这条操作的开始记录，结果没有落盘"
        } else {
            "这条操作记录已经不在了"
        }));
    };
    if record.phase != from_phase {
        return Err(bad(if from_phase == PENDING {
            "这条操作记录已经结束，不能重复写入结果"
        } else {
            "这条操作记录已经不需要核对：结论已经确定"
        }));
    }
    record.phase = phase.to_string();
    record.message = clip(message);
    record.code = code.to_string();
    record.finished_at_utc = now_rfc3339();
    let updated = record.clone();
    save_unlocked(root, &records)?;
    Ok(updated)
}

/// 执行结束：只接受仍在 `Pending` 的记录。找不到/已结束都报错而不是补写——
/// 那说明调用方跳过了 [`begin`]，补一条会让「中断」与「做完」的边界变模糊。
pub fn finish(root: &Path, id: &str, phase: &str, message: &str, code: &str) -> Result<Record, String> {
    update(root, id, PENDING, phase, message, code)
}

/// 核对结论：只接受 `NeedsReview` 的记录。核对**只查已有事实，绝不重放原操作**。
pub fn settle(root: &Path, id: &str, phase: &str, message: &str, code: &str) -> Result<Record, String> {
    update(root, id, NEEDS_REVIEW, phase, message, code)
}

pub fn get(root: &Path, id: &str) -> Result<Option<Record>, String> {
    Ok(load(root)?.into_iter().find(|record| record.id == id))
}

/// 一条记录能不能重试，以及重试时**到底会发生什么**。
///
/// 记录里没有命令原文（这是有意的：不能把带参数的请求落进日志），所以「重试」
/// 永远不是「重放原命令」，而是「按当前事实再做一次同类操作」。这段描述就是
/// 给用户看的那句话——不写清楚，用户会以为重试会回到失败前的状态。
///
/// 只开放三类可安全重放的操作：
/// - 连接/断开本身是幂等的，失败后重做不会叠加副作用；
/// - 诊断是只读的，重跑不会改变任何东西。
/// 其它（交易保护写规则、部署、邀请）各有自己的恢复通道，不走这里。
pub fn retry_plan(record: &Record) -> Value {
    let (can_retry, label, note) = match (record.phase.as_str(), record.kind.as_str()) {
        (SUCCEEDED, _) => (false, "", "这条操作已经成功，不需要重试。"),
        (PENDING, _) => (false, "", "这条操作还在进行中，请等它结束。"),
        (NEEDS_REVIEW, _) => (
            false,
            "",
            "上次的结果还没核对：先核对当前连接与系统代理，再决定是否重试。",
        ),
        (FAILED, CONNECT) => (
            true,
            "重试连接",
            "按当前选中的线路重新连接；不会使用旧记录里的参数。",
        ),
        (FAILED, DISCONNECT) => (
            true,
            "重试断开",
            "按当前状态再断开一次；已经断开时不会产生额外改动。",
        ),
        (FAILED, DIAGNOSE) => (true, "重新诊断", "诊断是只读操作，可以安全重跑。"),
        _ => (false, "", "这条操作不支持重试。"),
    };
    json!({"CanRetry": can_retry, "Label": label, "Note": note})
}

/// 启动恢复：上一进程留下的 `Pending` 必须在这里改判。
///
/// 调用点必须在持有单实例锁之后、界面开始推送状态之前——执行者不是本进程，
/// 就等于「操作开始后那个进程死了」，没有第二种解释。
///
/// - 连接/断开有副作用且可能是**半个**改动：→ `NeedsReview`，等人工核对；
/// - 诊断只读：→ `Failed`（`InterruptedReadOnly`），如实说「可以重新运行」，
///   不让一个查不出后果的操作去占「待处理」的位置。
pub fn recover_pending(root: &Path) -> Result<usize, String> {
    let _guard = lock_store();
    let mut records = load_unlocked(root)?;
    let mut rewritten = 0;
    let now = now_rfc3339();
    for record in records.iter_mut().filter(|record| record.phase == PENDING) {
        if record.kind == DIAGNOSE {
            record.phase = FAILED.to_string();
            record.code = "InterruptedReadOnly".to_string();
            record.message =
                "上次诊断没有拿到结果（只读操作，不会改动系统）；可以重新运行诊断。".to_string();
        } else {
            record.phase = NEEDS_REVIEW.to_string();
            record.code = "Interrupted".to_string();
            record.message = format!(
                "上次「{}」没拿到结果，程序就退出了；请先核对当前连接状态与系统代理。",
                label(&record.kind)
            );
        }
        record.finished_at_utc = now.clone();
        rewritten += 1;
    }
    if rewritten > 0 {
        save_unlocked(root, &records)?;
    }
    Ok(rewritten)
}

/// 三处调用点共用的一小包：数据根 + 同一把写锁。
///
/// 存的是路径而不是打开的句柄：数据根在进程启动后不再变化，每次读写都重新打开文件，
/// 才能看到管道/界面另一条线程刚写下的内容。
#[derive(Clone)]
pub struct Journal {
    root: std::sync::Arc<PathBuf>,
}

impl Journal {
    pub fn new(root: impl Into<PathBuf>) -> Journal {
        Journal {
            root: std::sync::Arc::new(root.into()),
        }
    }

    pub fn begin(&self, kind: &str, origin: &str) -> Result<Record, String> {
        begin(&self.root, kind, origin)
    }

    pub fn finish(&self, id: &str, phase: &str, message: &str, code: &str) -> Result<Record, String> {
        finish(&self.root, id, phase, message, code)
    }

    pub fn recover_pending(&self) -> Result<usize, String> {
        recover_pending(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-oprecord-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn no_record_means_nothing_to_review() {
        let root = temp_root("missing");
        assert!(load(&root).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_started_operation_round_trips_and_the_file_is_deleted_when_empty() {
        let root = temp_root("roundtrip");
        let record = begin(&root, CONNECT, "ui").unwrap();
        assert_eq!(record.phase, PENDING);
        assert!(!record.id.is_empty());
        assert!(!record.started_at_utc.is_empty());

        let finished = finish(
            &root,
            &record.id,
            SUCCEEDED,
            "连接完成",
            "",
        )
        .unwrap();
        assert_eq!(finished.phase, SUCCEEDED);
        assert!(!finished.finished_at_utc.is_empty());
        assert_eq!(load(&root).unwrap(), vec![finished]);

        let raw = std::fs::read_to_string(path(&root)).unwrap();
        assert!(raw.contains(KIND), "{raw}");
        assert!(raw.contains("\"Phase\": \"Succeeded\""), "{raw}");
        assert!(
            !raw.contains(&root.to_string_lossy().to_string()),
            "记录不该带绝对路径：{raw}"
        );
        assert!(!path(&root).with_extension("json.tmp").exists(), "临时文件必须被重命名走");

        save(&root, &[]).unwrap();
        assert!(!path(&root).exists(), "清完最后一条要把记录文件删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn beginning_the_same_kind_again_replaces_concluded_records_but_keeps_review() {
        let root = temp_root("replace");
        let first = begin(&root, CONNECT, "ui").unwrap();
        finish(&root, &first.id, FAILED, "失败", "Network").unwrap();
        begin(&root, DISCONNECT, "tray").unwrap();
        // 一条待核对：后来的同类操作不许把它掩埋。
        let interrupted = begin(&root, DIAGNOSE, "ui").unwrap();
        recover_pending(&root).unwrap();
        let review = load(&root)
            .unwrap()
            .into_iter()
            .find(|record| record.id == interrupted.id)
            .unwrap();
        assert_eq!(review.phase, FAILED, "诊断中断是「失败但只读」，不进待核对");

        let connect_review = {
            let pending = begin(&root, CONNECT, "ui").unwrap();
            recover_pending(&root).unwrap();
            load(&root)
                .unwrap()
                .into_iter()
                .find(|record| record.id == pending.id)
                .unwrap()
        };
        assert_eq!(connect_review.phase, NEEDS_REVIEW);

        let next = begin(&root, CONNECT, "ui").unwrap();
        let loaded = load(&root).unwrap();
        let connects: Vec<&Record> = loaded.iter().filter(|r| r.kind == CONNECT).collect();
        assert_eq!(connects.len(), 2, "待核对的那条必须留着：{loaded:?}");
        assert!(connects.iter().any(|r| r.id == next.id && r.phase == PENDING));
        assert!(
            connects.iter().any(|r| r.id == connect_review.id && r.phase == NEEDS_REVIEW),
            "{loaded:?}"
        );
        assert_eq!(
            loaded.iter().filter(|r| r.kind == DISCONNECT).count(),
            1,
            "{loaded:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finishing_without_a_start_is_reported_instead_of_appending() {
        let root = temp_root("nofinish");
        let error = finish(&root, "missing", SUCCEEDED, "完成", "")
            .expect_err("没有 begin 就不能 finish");
        assert!(error.contains("ui-operations.json"), "{error}");
        assert!(load(&root).unwrap().is_empty(), "失败不许补写一条记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_finished_record_cannot_be_finished_twice() {
        let root = temp_root("twice");
        let record = begin(&root, CONNECT, "ui").unwrap();
        finish(&root, &record.id, SUCCEEDED, "完成", "").unwrap();
        let error = finish(&root, &record.id, FAILED, "又失败", "Other").expect_err("不能重复写结论");
        assert!(error.contains("已经结束"), "{error}");
        assert_eq!(load(&root).unwrap()[0].phase, SUCCEEDED);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn settle_only_accepts_a_record_that_still_needs_review() {
        let root = temp_root("settle");
        let pending = begin(&root, CONNECT, "ui").unwrap();
        let error = settle(&root, &pending.id, SUCCEEDED, "完成了", "ReviewedApplied")
            .expect_err("还在跑的操作不能被核对");
        assert!(error.contains("不需要核对"), "{error}");
        finish(&root, &pending.id, FAILED, "中断", "Interrupted").unwrap();
        let error = settle(&root, &pending.id, SUCCEEDED, "完成了", "ReviewedApplied")
            .expect_err("结论已定的记录不能再核对");
        assert!(error.contains("不需要核对"), "{error}");

        let interrupted = begin(&root, DISCONNECT, "ui").unwrap();
        recover_pending(&root).unwrap();
        let settled = settle(
            &root,
            &interrupted.id,
            SUCCEEDED,
            "上次断开已经完成",
            "ReviewedApplied",
        )
        .unwrap();
        assert_eq!(settled.phase, SUCCEEDED);
        assert_eq!(settled.code, "ReviewedApplied");
        assert_eq!(get(&root, &interrupted.id).unwrap(), Some(settled));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_recovery_rewrites_only_pending_records() {
        let root = temp_root("recover");
        let connect = begin(&root, CONNECT, "ui").unwrap();
        let diagnose = begin(&root, DIAGNOSE, "ui").unwrap();
        let done = begin(&root, DISCONNECT, "ui").unwrap();
        finish(&root, &done.id, SUCCEEDED, "已断开", "").unwrap();

        assert_eq!(recover_pending(&root).unwrap(), 2, "只有还在飞的记录会被改判");
        let loaded = load(&root).unwrap();
        let connect = loaded.iter().find(|r| r.id == connect.id).unwrap();
        assert_eq!(connect.phase, NEEDS_REVIEW);
        assert_eq!(connect.code, "Interrupted");
        assert!(connect.message.contains("请先核对"), "{connect:?}");
        assert!(!connect.finished_at_utc.is_empty());
        let diagnose = loaded.iter().find(|r| r.id == diagnose.id).unwrap();
        assert_eq!(diagnose.phase, FAILED, "只读操作不需要人工核对");
        assert_eq!(diagnose.code, "InterruptedReadOnly");
        assert!(diagnose.message.contains("可以重新运行"), "{diagnose:?}");
        let done = loaded.iter().find(|r| r.id == done.id).unwrap();
        assert_eq!(done.phase, SUCCEEDED, "已经完成的记录不许被恢复改判");
        assert_eq!(recover_pending(&root).unwrap(), 0, "第二次恢复无事可做");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_record_is_reported_instead_of_silently_empty() {
        let root = temp_root("corrupt");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "{ not json").unwrap();
        let error = load(&root).expect_err("坏记录必须报错");
        assert!(error.contains("ui-operations.json"), "{error}");

        std::fs::write(&file, r#"{"SchemaVersion":1,"Kind":"Other","Records":[]}"#).unwrap();
        assert!(load(&root).is_err(), "类型不对也要报错，不能当成空记录");

        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.UiOperations","Records":[{"Kind":"Connect","Phase":"Pending"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("缺 id 的记录没法核对，必须报错");
        assert!(error.contains("缺少 id"), "{error}");

        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.UiOperations","Records":[{"Id":"a","Kind":"Connect","Phase":"Pending"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("缺开始时间就没法判断先后");
        assert!(error.contains("缺少开始时间"), "{error}");

        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.UiOperations","Records":[{"Id":"a","Kind":"Upgrade","Phase":"Pending","StartedAtUtc":"2026-01-01T00:00:00Z"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("类型不认识不能猜");
        assert!(error.contains("类型不认识"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_phase_is_not_guessed() {
        let root = temp_root("phase");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.UiOperations","Records":[{"Id":"a","Kind":"Connect","Phase":"Maybe","StartedAtUtc":"2026-01-01T00:00:00Z"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("阶段不认识就不能猜");
        assert!(error.contains("阶段不认识"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn trimming_drops_the_oldest_concluded_record_and_never_an_unreviewed_one() {
        let mut records: Vec<Record> = Vec::new();
        let mut review = started(CONNECT, "ui");
        review.id = "review".to_string();
        review.phase = NEEDS_REVIEW.to_string();
        records.push(review);
        for index in 0..MAX_RECORDS {
            let mut record = started(DISCONNECT, "ui");
            record.id = format!("done-{index}");
            record.phase = SUCCEEDED.to_string();
            records.push(record);
        }
        assert!(records.len() > MAX_RECORDS);
        trim(&mut records);
        assert_eq!(records.len(), MAX_RECORDS);
        assert!(records.iter().any(|r| r.id == "review"), "待核对记录永远不丢");
        assert!(!records.iter().any(|r| r.id == "done-0"), "先丢最早的已结束记录");
        assert!(records.iter().any(|r| r.id == format!("done-{}", MAX_RECORDS - 1)));
    }

    #[test]
    fn retry_is_offered_only_for_failed_replayable_operations() {
        let root = temp_root("retry-plan");
        let finished = begin(&root, CONNECT, "ui").unwrap();
        finish(&root, &finished.id, FAILED, "引擎没起来", "EngineStartFailed").unwrap();
        let failed = load(&root).unwrap().into_iter().find(|r| r.id == finished.id).unwrap();
        let plan = retry_plan(&failed);
        assert_eq!(plan["CanRetry"], true);
        assert_eq!(plan["Label"], "重试连接");
        assert!(
            plan["Note"].as_str().unwrap().contains("当前选中的线路"),
            "重试描述必须说清「不是重放旧命令」：{plan}"
        );

        let succeeded = begin(&root, DIAGNOSE, "ui").unwrap();
        finish(&root, &succeeded.id, SUCCEEDED, "完成", "").unwrap();
        let done = load(&root).unwrap().into_iter().find(|r| r.id == succeeded.id).unwrap();
        assert_eq!(retry_plan(&done)["CanRetry"], false, "成功的不需要重试");

        let pending = begin(&root, DISCONNECT, "ui").unwrap();
        let running = load(&root).unwrap().into_iter().find(|r| r.id == pending.id).unwrap();
        assert_eq!(retry_plan(&running)["CanRetry"], false, "还在跑的不能重试");

        let interrupted = begin(&root, CONNECT, "ui").unwrap();
        recover_pending(&root).unwrap();
        let review = load(&root).unwrap().into_iter().find(|r| r.id == interrupted.id).unwrap();
        let plan = retry_plan(&review);
        assert_eq!(plan["CanRetry"], false, "待核对的必须先核对");
        assert!(plan["Note"].as_str().unwrap().contains("核对"), "{plan}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn messages_are_clipped_and_command_text_is_never_stored() {
        let root = temp_root("clip");
        let record = begin(&root, CONNECT, "ui").unwrap();
        let long = "错".repeat(MAX_MESSAGE_CHARS + 50);
        let finished = finish(&root, &record.id, FAILED, &long, "Network").unwrap();
        assert_eq!(finished.message.chars().count(), MAX_MESSAGE_CHARS + 1);
        let raw = std::fs::read_to_string(path(&root)).unwrap();
        assert!(!raw.contains("Password"), "记录不是命令日志：{raw}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
