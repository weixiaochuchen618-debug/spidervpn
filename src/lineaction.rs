//! 线路动作（测速 / 保存连接方式）的结果记录：`<data root>/logs/line-actions.json`。
//!
//! 界面上的「测速」与「保存下次连接方式」不是一步完成的：前者要等一次网络往返，
//! 后者要等一次落盘。进程在这中间被杀掉时，**动作做没做成没人知道**——页面若
//! 悄悄把这次点击忘掉，用户就会以为「我保存过兼容连接」，而配置里其实还是标准。
//!
//! 所以动作在**开始时就落盘**（`Pending`），有结论后再改写成 `Succeeded` / `Failed`。
//! 启动时把仍是 `Pending` 的记录改判成 `NeedsReview`：那必然是一次被中断的动作，
//! 页面必须给「核对结果」的入口，而且核对**不能重新提交原操作**。
//!
//! 一条线路的同一种动作只留一条记录：界面上一张卡片只有一行位置，堆十条历史只会
//! 让「最近一次的结果」难以辨认。历史本来就在 `history.json` 里。
//!
//! 写入同样是「临时文件 + 重命名」：中途断电不会留下半截 JSON（半截记录读不出来，
//! 而读不出来的记录既不能展示也不能核对）。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub const KIND: &str = "TradeChannel.LineActions";
pub const SCHEMA: u32 = 1;

const DIR: &str = "logs";
const NAME: &str = "line-actions.json";

pub const CHECK: &str = "Check";
pub const PREFERENCE: &str = "Preference";

pub const PENDING: &str = "Pending";
pub const SUCCEEDED: &str = "Succeeded";
pub const FAILED: &str = "Failed";
pub const NEEDS_REVIEW: &str = "NeedsReview";

/// 一次线路动作。`requested` 只对 `Preference` 有意义（`udp`/`tcp`/`auto`）；
/// `at_unix` 是开始时刻，核对测速结果时用它限定采样窗口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub id: String,
    pub line_id: String,
    pub line_name: String,
    pub kind: String,
    pub profile_id: String,
    pub requested: String,
    pub phase: String,
    pub message: String,
    pub code: String,
    pub at_utc: String,
    pub at_unix: i64,
    pub finished_at_utc: String,
    pub latency_ms: Option<u64>,
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

/// 新动作：开始时就带着自己的 id 与开始时间落盘。`Pending` 由这里统一给，
/// 调用方只描述「谁、做了什么」。
pub fn started(
    line_id: &str,
    line_name: &str,
    kind: &str,
    profile_id: &str,
    requested: &str,
) -> Action {
    Action {
        id: crate::pairing::random_uuid_v4(),
        line_id: line_id.to_string(),
        line_name: line_name.to_string(),
        kind: kind.to_string(),
        profile_id: profile_id.to_string(),
        requested: requested.to_string(),
        phase: PENDING.to_string(),
        message: String::new(),
        code: String::new(),
        at_utc: now_rfc3339(),
        at_unix: now_unix(),
        finished_at_utc: String::new(),
        latency_ms: None,
    }
}

pub fn to_json(action: &Action) -> Value {
    json!({
        "Id": action.id,
        "LineId": action.line_id,
        "LineName": action.line_name,
        "Kind": action.kind,
        "ProfileId": action.profile_id,
        "Requested": action.requested,
        "Phase": action.phase,
        "Message": action.message,
        "Code": action.code,
        "AtUtc": action.at_utc,
        "AtUnix": action.at_unix,
        "FinishedAtUtc": action.finished_at_utc,
        "LatencyMs": action.latency_ms,
    })
}

fn from_json(item: &Value) -> Option<Action> {
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
    Some(Action {
        id: text_of("Id"),
        line_id: text_of("LineId"),
        line_name: text_of("LineName"),
        kind: text_of("Kind"),
        profile_id: text_of("ProfileId"),
        requested: text_of("Requested"),
        phase: text_of("Phase"),
        message: text_of("Message"),
        code: text_of("Code"),
        at_utc: text_of("AtUtc"),
        at_unix: item.get("AtUnix").and_then(Value::as_i64).unwrap_or(0),
        finished_at_utc: text_of("FinishedAtUtc"),
        latency_ms: item.get("LatencyMs").and_then(Value::as_u64),
    })
}

/// 读出全部记录。文件不存在 = 没有记录；坏记录**照实报错**——静默当成空会让
/// 页面上「核对结果」永远消失，而记录文件还在那里。
pub fn load(root: &Path) -> Result<Vec<Action>, String> {
    let file = path(root);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(bad(&format!("读取线路操作记录失败：{error}"))),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| bad("线路操作记录不是合法 JSON，无法判断这些操作的结果"))?;
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return Err(bad("线路操作记录的文件类型不认识"));
    }
    let mut out = Vec::new();
    for item in value
        .get("Actions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(action) = from_json(&item) else {
            return Err(bad("线路操作记录里有一条的阶段不认识，无法判断它做没做成"));
        };
        if action.id.trim().is_empty() {
            return Err(bad("线路操作记录里有一条缺少 id，无法核对"));
        }
        if action.line_id.trim().is_empty() {
            return Err(bad("线路操作记录里有一条缺少线路 id，无法贴回线路"));
        }
        if !matches!(action.kind.as_str(), CHECK | PREFERENCE) {
            return Err(bad("线路操作记录里有一条的类型不认识"));
        }
        out.push(action);
    }
    Ok(out)
}

/// 写回全部记录。空列表 = 删掉文件（没有记录就不该留一个空壳，
/// 否则「文件存在」会让人以为还有没核对完的动作）。
pub fn save(root: &Path, actions: &[Action]) -> Result<(), String> {
    let file = path(root);
    if actions.is_empty() {
        return match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(bad(&format!("清除线路操作记录失败：{error}"))),
        };
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| bad(&format!("创建线路操作记录目录失败：{error}")))?;
    }
    let body = json!({
        "SchemaVersion": SCHEMA,
        "Kind": KIND,
        "Actions": actions.iter().map(to_json).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&body)
        .map_err(|_| bad("线路操作记录无法序列化"))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|error| bad(&format!("写入线路操作记录失败：{error}")))?;
    std::fs::rename(&temp, &file).map_err(|error| bad(&format!("写入线路操作记录失败：{error}")))
}

/// 开始一个动作。同一条线路的同一种动作只会留最新的一条——旧记录被这次点击取代。
/// 返回落盘后的记录（id 由 [`started`] 生成）。
pub fn begin(root: &Path, action: Action) -> Result<Action, String> {
    let mut actions = load(root)?;
    actions.retain(|existing| {
        !(existing.line_id == action.line_id && existing.kind == action.kind)
    });
    actions.push(action.clone());
    save(root, &actions)?;
    Ok(action)
}

/// 结束一个动作：按「线路 + 类型」找到它并改写结论。
///
/// 找不到记录时**报错而不是补写**：那说明调用方跳过了 [`begin`]，这次动作没有
/// 「开始」的事实，补一条会让「中断」与「做完」的边界变模糊。
#[allow(clippy::too_many_arguments)]
pub fn finish(
    root: &Path,
    line_id: &str,
    kind: &str,
    phase: &str,
    message: &str,
    code: &str,
    latency_ms: Option<u64>,
) -> Result<Action, String> {
    let mut actions = load(root)?;
    let Some(action) = actions
        .iter_mut()
        .find(|action| action.line_id == line_id && action.kind == kind)
    else {
        return Err(bad("找不到这条线路动作的开始记录，结果没有落盘"));
    };
    action.phase = phase.to_string();
    action.message = message.to_string();
    action.code = code.to_string();
    action.latency_ms = latency_ms;
    action.finished_at_utc = now_rfc3339();
    let updated = action.clone();
    save(root, &actions)?;
    Ok(updated)
}

/// 按 id 改判一条记录（核对用）：只改结论字段，不动开始时间与请求内容。
pub fn update_phase(
    root: &Path,
    id: &str,
    phase: &str,
    message: &str,
    code: &str,
    latency_ms: Option<u64>,
) -> Result<Action, String> {
    let mut actions = load(root)?;
    let Some(action) = actions.iter_mut().find(|action| action.id == id) else {
        return Err(bad("这条线路操作记录已经不在了"));
    };
    action.phase = phase.to_string();
    action.message = message.to_string();
    action.code = code.to_string();
    action.latency_ms = latency_ms;
    action.finished_at_utc = now_rfc3339();
    let updated = action.clone();
    save(root, &actions)?;
    Ok(updated)
}

pub fn get(root: &Path, id: &str) -> Result<Option<Action>, String> {
    Ok(load(root)?.into_iter().find(|action| action.id == id))
}

/// 启动恢复：上一进程留下的 `Pending` 全部改判为 `NeedsReview`。
///
/// 调用点必须在持有单实例锁之后、界面开始推送状态之前——执行者不是本进程，
/// 就等于「动作开始后那个进程死了」，没有第二种解释。
pub fn recover_pending(root: &Path) -> Result<usize, String> {
    let mut actions = load(root)?;
    let mut rewritten = 0;
    let now = now_rfc3339();
    for action in actions.iter_mut().filter(|action| action.phase == PENDING) {
        action.phase = NEEDS_REVIEW.to_string();
        action.message = "上次操作还没拿到结果，程序就退出了；请先核对结果。".to_string();
        action.code = "Interrupted".to_string();
        action.finished_at_utc = now.clone();
        rewritten += 1;
    }
    if rewritten > 0 {
        save(root, &actions)?;
    }
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-lineaction-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn action(line_id: &str, kind: &str) -> Action {
        started(line_id, &format!("线路 {line_id}"), kind, "Tcp", "tcp")
    }

    #[test]
    fn no_record_means_nothing_to_review() {
        let root = temp_root("missing");
        assert!(load(&root).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_finished_action_round_trips_and_the_file_is_deleted_when_empty() {
        let root = temp_root("roundtrip");
        let started_action = begin(&root, action("jp", PREFERENCE)).unwrap();
        let finished = finish(
            &root,
            "jp",
            PREFERENCE,
            SUCCEEDED,
            "已固定为兼容连接，下次连接生效。",
            "",
            None,
        )
        .unwrap();
        assert_eq!(finished.id, started_action.id);
        assert_eq!(finished.phase, SUCCEEDED);
        assert!(!finished.finished_at_utc.is_empty());

        let loaded = load(&root).unwrap();
        assert_eq!(loaded, vec![finished]);

        let raw = std::fs::read_to_string(path(&root)).unwrap();
        assert!(raw.contains("\"Kind\"") && raw.contains(KIND), "{raw}");
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
    fn beginning_the_same_action_again_replaces_it_and_keeps_other_lines() {
        let root = temp_root("replace");
        begin(&root, action("jp", CHECK)).unwrap();
        begin(&root, action("jp", PREFERENCE)).unwrap();
        let first = begin(&root, action("jp", CHECK)).unwrap();
        begin(&root, action("hk", CHECK)).unwrap();

        let loaded = load(&root).unwrap();
        assert_eq!(loaded.len(), 3, "{loaded:?}");
        let jp_checks: Vec<&Action> = loaded
            .iter()
            .filter(|a| a.line_id == "jp" && a.kind == CHECK)
            .collect();
        assert_eq!(jp_checks.len(), 1, "同线同类型只留最新一条：{loaded:?}");
        assert_eq!(jp_checks[0].id, first.id);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finishing_without_a_start_is_reported_instead_of_appending() {
        let root = temp_root("nofinish");
        let error = finish(&root, "jp", CHECK, SUCCEEDED, "测量完成", "", Some(42))
            .expect_err("没有 begin 就不能 finish");
        assert!(error.contains("line-actions.json"), "{error}");
        assert!(load(&root).unwrap().is_empty(), "失败不许补写一条记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn update_and_get_find_the_record_by_id() {
        let root = temp_root("update");
        let action = begin(&root, action("jp", CHECK)).unwrap();
        let updated = update_phase(
            &root,
            &action.id,
            SUCCEEDED,
            "已确认上次测量完成：42 ms",
            "",
            Some(42),
        )
        .unwrap();
        assert_eq!(updated.phase, SUCCEEDED);
        assert_eq!(get(&root, &action.id).unwrap(), Some(updated));
        assert!(get(&root, "missing").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_recovery_rewrites_only_pending_actions() {
        let root = temp_root("recover");
        let pending = begin(&root, action("jp", CHECK)).unwrap();
        begin(&root, action("hk", PREFERENCE)).unwrap();
        finish(&root, "hk", PREFERENCE, SUCCEEDED, "已保存", "", None).unwrap();

        let rewritten = recover_pending(&root).unwrap();
        assert_eq!(rewritten, 1, "只有还在飞的记录会被改判");

        let loaded = load(&root).unwrap();
        let jp = loaded.iter().find(|a| a.line_id == "jp").unwrap();
        assert_eq!(jp.phase, NEEDS_REVIEW);
        assert_eq!(jp.code, "Interrupted");
        assert_eq!(jp.id, pending.id, "恢复不是新记录，原 id 必须保留");
        assert!(!jp.finished_at_utc.is_empty());
        assert!(jp.message.contains("程序就退出"), "要如实说为什么没结果：{jp:?}");
        let hk = loaded.iter().find(|a| a.line_id == "hk").unwrap();
        assert_eq!(hk.phase, SUCCEEDED, "已经完成的记录不许被恢复改判");
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
        assert!(error.contains("line-actions.json"), "{error}");

        std::fs::write(&file, r#"{"SchemaVersion":1,"Kind":"Other","Actions":[]}"#).unwrap();
        assert!(load(&root).is_err(), "类型不对也要报错，不能当成空记录");

        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.LineActions","Actions":[{"LineId":"jp","Kind":"Check","Phase":"Pending"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("缺 id 的记录没法核对，必须报错");
        assert!(error.contains("缺少 id"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_phase_is_not_guessed() {
        let root = temp_root("phase");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.LineActions","Actions":[{"Id":"a","LineId":"jp","Kind":"Check","Phase":"Maybe"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("阶段不认识就不能猜");
        assert!(error.contains("阶段不认识"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
