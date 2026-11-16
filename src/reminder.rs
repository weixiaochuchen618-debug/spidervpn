//! 部署结果提醒：`<data root>/deployments/reminders.json`（与 `runs\` 同级）。
//!
//! 部署是唯一一件「关掉窗口也在跑」的事。跑完之后，如果用户不在电脑前，结论只会
//! 留在任务列表里——而那需要他自己想起来去看。这个文件记的是「有一条结果你还没看过」，
//! 它必须**活过重启**：用户可能第二天才回来。
//!
//! 三条口径：
//!
//! 1. **去重键是 `RunId + State + Step + Code`**（PRD P1-3 原文）。同一次失败重试再失败
//!    不重复提醒；换了步骤或错误码才算新的一条。
//! 2. **只记四种状态**：`Complete` / `NeedsAttention` / `Paused` / `Cancelled`。
//!    `Queued`/`Running` 不是结果，提醒它们只会变成噪音。
//! 3. **读不出来照实报错**：静默当成空列表，会让「有一条结果没看」永远消失，
//!    而用户根本不知道自己错过了什么。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::deploystore::RunRecord;

pub const KIND: &str = "TradeChannel.DeployReminders";
pub const SCHEMA: u32 = 1;

/// 只提醒这四种状态（与 PRD P1-3 一一对应）。
pub const STATES: [&str; 4] = [
    crate::deploystore::STATE_COMPLETE,
    crate::deploystore::STATE_NEEDS_ATTENTION,
    crate::deploystore::STATE_PAUSED,
    crate::deploystore::STATE_CANCELLED,
];

/// 最多留多少条。超了从**最旧的**开始丢：提醒是「最近发生了什么」，
/// 不是审计账本（那是 `operations.jsonl`）。丢之前先丢已读的。
pub const MAX_REMINDERS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reminder {
    pub id: String,
    pub run_id: String,
    pub name: String,
    pub state: String,
    pub step: u8,
    /// 原因类别（`Failed`/`OutcomeUnknown`/…）。空 = 没有原因（完成/取消）。
    /// 列表筛选（P2-1）按它分「失败 / 结果未知 / …」，所以它必须落在提醒文件里，
    /// 不能只留在原记录上——提醒要活过重启，记录却可能已经不在列表里了。
    pub category: String,
    pub code: String,
    pub text: String,
    pub created_at_utc: String,
    pub read_at_utc: Option<String>,
}

impl Reminder {
    pub fn is_unread(&self) -> bool {
        self.read_at_utc.is_none()
    }

    fn key(&self) -> String {
        dedupe_key(&self.run_id, &self.state, self.step, &self.code)
    }

    fn to_json(&self) -> Value {
        json!({
            "Id": self.id,
            "RunId": self.run_id,
            "Name": self.name,
            "State": self.state,
            "Step": self.step,
            "Category": self.category,
            "Code": self.code,
            "Text": self.text,
            "CreatedAtUtc": self.created_at_utc,
            "ReadAtUtc": self.read_at_utc,
        })
    }

    fn from_json(value: &Value) -> Option<Reminder> {
        let text_of = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        };
        let run_id = text_of("RunId")?;
        let state = text_of("State")?;
        Some(Reminder {
            id: text_of("Id").unwrap_or_else(|| format!("{run_id}:{state}")),
            run_id,
            name: text_of("Name").unwrap_or_default(),
            state,
            step: u8::try_from(value.get("Step").and_then(Value::as_u64).unwrap_or(0))
                .unwrap_or(0),
            category: text_of("Category").unwrap_or_default(),
            code: text_of("Code").unwrap_or_default(),
            text: text_of("Text").unwrap_or_default(),
            created_at_utc: text_of("CreatedAtUtc").unwrap_or_default(),
            read_at_utc: text_of("ReadAtUtc"),
        })
    }
}

pub fn path(root: &Path) -> PathBuf {
    // 与记录同一个约定：`<data root>\deployments\`（`deploystore` 的 `runs\` 就在它下面）。
    // 多拼一层 `data` 会让读的一侧永远找不到文件——页面于是「一条提醒都没有」，
    // 而文件明明躺在隔壁。r71 的真机验收抓到的就是这一条。
    root.join("deployments").join("reminders.json")
}

/// 给人看的相对路径（界面与日志只说这个，不把用户的绝对目录带出去）。
pub fn display_path() -> &'static str {
    "deployments\\reminders.json"
}

fn bad(message: &str) -> String {
    format!("{message}（{}）", display_path())
}

fn dedupe_key(run_id: &str, state: &str, step: u8, code: &str) -> String {
    format!("{run_id}|{state}|{step}|{code}")
}

/// 读出全部提醒。文件不存在 = 没有提醒；坏记录**照实报错**。
pub fn load(root: &Path) -> Result<Vec<Reminder>, String> {
    let file = path(root);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(bad(&format!("读取部署提醒失败：{error}"))),
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|_| bad("部署提醒不是合法 JSON，读不出有哪些结果"))?;
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return Err(bad("部署提醒的文件类型不认识"));
    }
    let mut out = Vec::new();
    for item in value
        .get("Reminders")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(reminder) = Reminder::from_json(&item) else {
            return Err(bad("部署提醒里有一条缺少任务编号或状态"));
        };
        out.push(reminder);
    }
    Ok(out)
}

/// 写回全部提醒。空列表 = 删掉文件（没有待办就不留空壳）。
fn save(root: &Path, items: &[Reminder]) -> Result<(), String> {
    let file = path(root);
    if items.is_empty() {
        match std::fs::remove_file(&file) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(bad(&format!("清空部署提醒失败：{error}"))),
        }
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| bad(&format!("创建部署提醒目录失败：{error}")))?;
    }
    let payload = json!({
        "Schema": SCHEMA,
        "Kind": KIND,
        "Reminders": items.iter().map(Reminder::to_json).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&payload)
        .map_err(|error| bad(&format!("序列化部署提醒失败：{error}")))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text.as_bytes())
        .map_err(|error| bad(&format!("写部署提醒失败：{error}")))?;
    std::fs::rename(&temp, &file).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        bad(&format!("部署提醒落盘失败：{error}"))
    })?;
    Ok(())
}

/// 收一条提醒。**幂等**：同一次结果重复调用只会有一条。
///
/// 返回 `Some` 表示这次真的新增了一条（调用方可以据此弹托盘，虽然当前没有那样做）。
pub fn note(root: &Path, run: &RunRecord) -> Result<Option<Reminder>, String> {
    if !STATES.contains(&run.state.as_str()) {
        return Ok(None);
    }
    let step = run.step.unwrap_or(0);
    let (category, code) = match run.reason.as_ref() {
        Some(reason) => (reason.category.clone(), reason.code.clone()),
        None => (String::new(), String::new()),
    };
    let key = dedupe_key(&run.run_id, &run.state, step, &code);

    let mut items = load(root)?;
    if items.iter().any(|item| item.key() == key) {
        return Ok(None);
    }
    let text = match run.reason.as_ref() {
        Some(reason) => crate::deployrun::humanize(reason),
        None => crate::deployrun::summary_of(run),
    };
    let reminder = Reminder {
        id: crate::pairing::random_uuid_v4(),
        run_id: run.run_id.clone(),
        name: run.label.clone(),
        state: run.state.clone(),
        step,
        category,
        code,
        text,
        created_at_utc: crate::deploystore::now_utc(),
        read_at_utc: None,
    };
    items.push(reminder.clone());
    trim(&mut items);
    save(root, &items)?;
    Ok(Some(reminder))
}

/// 裁剪到 [`MAX_REMINDERS`]：先丢已读里最旧的，再丢未读里最旧的。
///
/// 顺序是刻意的——「已读」比「未读」便宜，丢它不会让人错过任何结果。
fn trim(items: &mut Vec<Reminder>) {
    if items.len() <= MAX_REMINDERS {
        return;
    }
    while items.len() > MAX_REMINDERS {
        // 最旧的已读（按创建时间）；没有已读才动最旧的未读。
        let read = items
            .iter()
            .enumerate()
            .filter(|(_, item)| !item.is_unread())
            .min_by_key(|(_, item)| item.created_at_utc.clone())
            .map(|(index, _)| index);
        let index = read.unwrap_or(0);
        items.remove(index);
    }
}

/// 打开一条任务就等于看过它的结果：把它名下所有未读提醒标成已读。
///
/// 返回改了几条（0 = 本来就没有未读，调用方不必再写盘）。
pub fn mark_read(root: &Path, run_id: &str) -> Result<usize, String> {
    let mut items = load(root)?;
    let stamp = crate::deploystore::now_utc();
    let mut changed = 0usize;
    for item in items.iter_mut() {
        if item.run_id == run_id && item.is_unread() {
            item.read_at_utc = Some(stamp.clone());
            changed += 1;
        }
    }
    if changed > 0 {
        save(root, &items)?;
    }
    Ok(changed)
}

/// 未读提醒（新的在前）。快照只要这一份。
pub fn unread(root: &Path) -> Result<Vec<Reminder>, String> {
    let mut items = load(root)?;
    items.retain(Reminder::is_unread);
    items.reverse();
    Ok(items)
}

// ---------------------------------------------------------------------------
// 按 RunId 清账（「删除这台服务器的本机部署资料」用）
//
// 这一组刻意走**原始的 `Value`** 而不是 `Reminder`：任务被删掉之后，文件里有些条目
// 可能已经缺字段（旧版本写的、或者手改坏的）。用类型化的读法，一条坏条目就会让整份
// 清理失败；用 `Value` 则能「只摘掉认得出的那几条，其余原样写回」——看不懂的东西
// 一个字节都不动，这是清理与销毁的分界线。
// ---------------------------------------------------------------------------

/// 读一遍提醒文件。`Ok(None)` = 文件不存在（= 没有提醒）。
///
/// 整个文件读不懂时**报错且不覆盖**：下面唯一一次写盘就发生在这之后，读不懂的东西
/// 不许被一次「顺手清理」写没。
fn read_document(root: &Path) -> Result<Option<Value>, String> {
    let file = path(root);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(bad(&format!("读取部署提醒失败：{error}"))),
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|_| bad("部署提醒不是合法 JSON，读不出有哪些结果"))?;
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return Err(bad("部署提醒的文件类型不认识"));
    }
    Ok(Some(value))
}

/// 这一条提醒是不是这批 RunId 的。
///
/// 认不出 `RunId` 的条目一律算「不是」：看不懂的东西不替用户销毁。
fn belongs_to(item: &Value, wanted: &HashSet<&str>) -> bool {
    item.get("RunId")
        .and_then(Value::as_str)
        .map(|run_id| wanted.contains(run_id))
        .unwrap_or(false)
}

/// 这些 RunId 名下有几条提醒。**只读**（预览用）。
pub fn count_for_runs(root: &Path, run_ids: &[String]) -> Result<usize, String> {
    if run_ids.is_empty() {
        return Ok(0);
    }
    let Some(document) = read_document(root)? else {
        return Ok(0);
    };
    let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
    Ok(document
        .get("Reminders")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|item| belongs_to(item, &wanted)).count())
        .unwrap_or(0))
}

/// 删掉这些 RunId 名下的提醒，返回删掉的条数。幂等：一条都没命中就 `Ok(0)`。
///
/// 写回是 tmp + rename（与 `save` 同一口径）：中途崩不会留下半个文件。删空的语义
/// 也与 `save` 一致——没有待办就不留空壳文件。
pub fn remove_runs(root: &Path, run_ids: &[String]) -> Result<usize, String> {
    if run_ids.is_empty() {
        return Ok(0);
    }
    let Some(mut document) = read_document(root)? else {
        return Ok(0);
    };
    let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
    let items = document
        .get("Reminders")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut kept: Vec<Value> = Vec::with_capacity(items.len());
    let mut removed = 0usize;
    for item in items {
        if belongs_to(&item, &wanted) {
            removed += 1;
        } else {
            kept.push(item);
        }
    }
    if removed == 0 {
        // 一条都没命中：不写盘。空跑一次写盘等于给了自己一次改坏文件的机会。
        return Ok(0);
    }
    let file = path(root);
    if kept.is_empty() {
        match std::fs::remove_file(&file) {
            Ok(()) => return Ok(removed),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
            Err(error) => return Err(bad(&format!("清空部署提醒失败：{error}"))),
        }
    }
    if let Some(object) = document.as_object_mut() {
        object.insert("Reminders".to_string(), Value::Array(kept));
    }
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| bad(&format!("序列化部署提醒失败：{error}")))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text.as_bytes())
        .map_err(|error| bad(&format!("写部署提醒失败：{error}")))?;
    std::fs::rename(&temp, &file).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        bad(&format!("部署提醒落盘失败：{error}"))
    })?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploystore::{Target, NEXT_ACTION_RETRY_STEP, REASON_FAILED};

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-reminder-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(state: &str, step: u8, code: &str) -> RunRecord {
        let mut run = crate::deployrun::new_draft(
            "b1000000-1111-4111-8111-111111111111",
            "自建 · 203.0.113.10",
            Target {
                host: "203.0.113.10".to_string(),
                port: 22,
                user: "root".to_string(),
                server_record_id: None,
                ..Default::default()
            },
            "SHA256:AAAA",
            "2026-11-12T10:00:00Z",
        );
        run.state = state.to_string();
        run.step = Some(step);
        if !code.is_empty() {
            run.reason = Some(crate::deploystore::Reason::now(
                REASON_FAILED,
                crate::deploystore::ERROR_CLASS_ENVIRONMENT,
                code,
                "端口被占用",
            ));
            run.next_action = NEXT_ACTION_RETRY_STEP.to_string();
        }
        run
    }

    #[test]
    fn the_same_result_is_reminded_only_once() {
        let root = temp_root("dedupe");
        let failed = run(crate::deploystore::STATE_NEEDS_ATTENTION, 1, "ListenFailed");
        assert!(note(&root, &failed).unwrap().is_some());
        assert!(
            note(&root, &failed).unwrap().is_none(),
            "同一条结果重复落盘不许再提醒一次"
        );
        let stored = load(&root).unwrap();
        assert_eq!(stored.len(), 1);
        // 筛选（P2-1）要按类别分「失败 / 结果未知 / …」：类别必须落盘。
        assert_eq!(stored[0].category, "Failed");
        assert_eq!(stored[0].code, "ListenFailed");

        // 换了步骤 = 新的一条（「阶段」是去重键的一部分）。
        let other_step = run(crate::deploystore::STATE_NEEDS_ATTENTION, 2, "ListenFailed");
        assert!(note(&root, &other_step).unwrap().is_some());
        // 换了错误码 = 新的一条。
        let other_code = run(crate::deploystore::STATE_NEEDS_ATTENTION, 1, "UdpInstallFailed");
        assert!(note(&root, &other_code).unwrap().is_some());
        assert_eq!(load(&root).unwrap().len(), 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 文件必须和 `runs\` 同级（`<数据根>\deployments\`）。
    ///
    /// 这一条是 r71 真机验收抓到的原样回归：多拼一层 `data` 时，写的一侧与读的一侧
    /// 各自自洽、单测全绿，只有「页面上一片空白」这个事实能暴露它。
    #[test]
    fn the_file_lives_next_to_the_run_records() {
        let root = temp_root("layout");
        note(&root, &run(crate::deploystore::STATE_COMPLETE, 4, "")).unwrap();
        assert_eq!(
            path(&root),
            root.join("deployments").join("reminders.json"),
            "提醒文件必须与 deploystore 的 runs\\ 同目录"
        );
        assert!(path(&root).is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_the_four_result_states_are_reminded() {
        let root = temp_root("states");
        for state in [
            crate::deploystore::STATE_QUEUED,
            crate::deploystore::STATE_RUNNING,
            crate::deploystore::STATE_WAITING_USER,
            crate::deploystore::STATE_DRAFT,
        ] {
            assert!(
                note(&root, &run(state, 0, "")).unwrap().is_none(),
                "{state} 不是结果，不该提醒"
            );
        }
        for state in STATES {
            assert!(
                note(&root, &run(state, 0, "")).unwrap().is_some(),
                "{state} 是结果，必须提醒"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn opening_the_task_marks_its_reminders_read() {
        let root = temp_root("read");
        note(&root, &run(crate::deploystore::STATE_COMPLETE, 4, "")).unwrap();
        note(&root, &run(crate::deploystore::STATE_NEEDS_ATTENTION, 1, "ListenFailed")).unwrap();
        assert_eq!(unread(&root).unwrap().len(), 2);
        assert_eq!(mark_read(&root, "b1000000-1111-4111-8111-111111111111").unwrap(), 2);
        assert!(unread(&root).unwrap().is_empty());
        assert!(load(&root).unwrap().iter().all(|item| !item.is_unread()));
        // 再打开一次：没有未读，不该无脑写盘。
        assert_eq!(mark_read(&root, "b1000000-1111-4111-8111-111111111111").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_an_empty_list() {
        let root = temp_root("corrupt");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{not json").unwrap();
        assert!(load(&root).is_err(), "坏记录必须报错");
        assert!(unread(&root).is_err());
        assert!(note(&root, &run(crate::deploystore::STATE_COMPLETE, 4, "")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_oldest_read_reminders_are_dropped_first() {
        let root = temp_root("trim");
        let mut items: Vec<Reminder> = (0..MAX_REMINDERS)
            .map(|index| Reminder {
                id: format!("id-{index}"),
                run_id: format!("run-{index}"),
                name: "自建 · 203.0.113.10".to_string(),
                state: crate::deploystore::STATE_COMPLETE.to_string(),
                step: 4,
                category: String::new(),
                code: String::new(),
                text: "部署完成".to_string(),
                created_at_utc: format!("2026-11-12T{:02}:00:00Z", index % 24),
                read_at_utc: if index < 3 { None } else { Some("2026-11-12T12:00:00Z".to_string()) },
            })
            .collect();
        items.push(items[0].clone());
        trim(&mut items);
        assert_eq!(items.len(), MAX_REMINDERS);
        assert!(
            items.iter().any(|item| item.run_id == "run-0"),
            "未读的最后才丢：它还在"
        );
        let _ = root;
    }

    #[test]
    fn the_file_never_carries_a_credential() {
        let root = temp_root("secret");
        let mut run = run(crate::deploystore::STATE_NEEDS_ATTENTION, 1, "ListenFailed");
        run.reason = Some(crate::deploystore::Reason::now(
            REASON_FAILED,
            crate::deploystore::ERROR_CLASS_ENVIRONMENT,
            "ListenFailed",
            "端口被占用",
        ));
        note(&root, &run).unwrap();
        let text = std::fs::read_to_string(path(&root)).unwrap().to_lowercase();
        for forbidden in ["password", "privatekey", "private_key", "secret"] {
            assert!(!text.contains(forbidden), "提醒文件里出现了 {forbidden}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 按 RunId 清账：只摘掉认得出的那几条，其余（含认不出 `RunId` 的坏条目）原样留下。
    ///
    /// 「坏条目保留」不是洁癖：那份文件是用户的待办清单，一条读不懂的记录也许正是
    /// 他想看却没看的那条结果——清理服务器记录不该顺手把它销毁。
    #[test]
    fn removing_by_run_id_keeps_every_entry_it_cannot_attribute() {
        let root = temp_root("remove-runs");
        std::fs::create_dir_all(path(&root).parent().unwrap()).unwrap();
        std::fs::write(
            path(&root),
            json!({
                "Schema": SCHEMA,
                "Kind": KIND,
                "Reminders": [
                    {"Id": "r1", "RunId": "run-a", "State": "Complete", "Step": 4},
                    {"Id": "r2", "RunId": "run-a", "State": "Cancelled", "Step": 2},
                    {"Id": "r3", "RunId": "run-b", "State": "Complete", "Step": 4},
                    // 认不出 RunId 的条目：不属于任何一次清理。
                    {"Id": "r4", "State": "Complete", "Step": 4},
                ],
            })
            .to_string(),
        )
        .unwrap();

        let ours = vec!["run-a".to_string()];
        assert_eq!(count_for_runs(&root, &ours).unwrap(), 2);
        assert_eq!(remove_runs(&root, &ours).unwrap(), 2);

        // 直接读盘比对（`load` 是全有或全无的严格读法：那条缺 `RunId` 的条目会让它
        // 报错——这是既有行为，清理**不改**它，也不替用户修）。
        let raw: Value =
            serde_json::from_str(&std::fs::read_to_string(path(&root)).unwrap()).unwrap();
        let items = raw["Reminders"].as_array().cloned().unwrap_or_default();
        assert_eq!(items.len(), 2, "认不出 RunId 的条目必须还在：{raw}");
        assert!(
            items.iter().any(|item| item.get("RunId").and_then(Value::as_str) == Some("run-b")),
            "别人的提醒一条都不许动：{raw}"
        );
        assert!(
            items.iter().any(|item| item.get("RunId").is_none()),
            "认不出 RunId 的条目必须原样留着：{raw}"
        );
        assert!(
            !items
                .iter()
                .any(|item| item.get("RunId").and_then(Value::as_str) == Some("run-a")),
            "属于它的两条都要删掉：{raw}"
        );

        // 幂等：再删一次没有命中，就不写盘。
        assert_eq!(remove_runs(&root, &ours).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 整个文件读不懂：报错，并且**一个字节都不改**。
    #[test]
    fn a_corrupt_file_is_never_rewritten_by_a_cleanup() {
        let root = temp_root("remove-corrupt");
        std::fs::create_dir_all(path(&root).parent().unwrap()).unwrap();
        std::fs::write(path(&root), b"{not json").unwrap();
        assert!(count_for_runs(&root, &["run-a".to_string()]).is_err());
        assert!(remove_runs(&root, &["run-a".to_string()]).is_err());
        assert_eq!(std::fs::read(path(&root)).unwrap(), b"{not json".to_vec());
        let _ = std::fs::remove_dir_all(&root);
    }
}
