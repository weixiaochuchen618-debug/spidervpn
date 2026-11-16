//! 「删除这台服务器在本机的部署资料」：判据与执行。
//!
//! 为什么单独一个模块：**判据只能有一处**。预览（`server-cleanup-preview`）与执行
//! （`server-cleanup`）都调 [`assess`]，所以「确认框里列的」与「真的删掉的」是同一份
//! 清单。两边各算一遍，迟早会出现「预览说 3 条、删的时候是 5 条」——用户看到的
//! 是一句假话，而且没人能事先发现。
//!
//! 归属判据只有一条：`run.target.server_record_id == Some(这条记录的 id)`。
//! **绝不按 host:port 猜**：以地址手工建的任务（`server_record_id == None`）不是这条
//! 记录的资料，按地址匹配会把它一起删掉，等于替用户烧了别人的账。同一台机器上
//! 「有记录」与「没记录」的两次部署本来就允许并存（`deploystore::Target::lane_key`
//! 的注释写着为什么它们仍是同一台机器，但那是**串行判据**，不是**归属判据**）。
//!
//! 删除顺序是「先摘叶子、最后拔根」：记录目录（里面还躺着长期凭据）留到最后。
//! 中途失败时留下的仍是「能看出这台服务器曾经存在」的东西，而不是一堆认不出主人
//! 的孤儿文件。
//!
//! 「有没有还在跑」的判据**不是** `RunRecord::is_terminal()`。那个口径（只有
//! `Complete`/`Cancelled` 算终态、未知不算）是给**裁剪**与**归档**用的：那两件事
//! 是自动发生的，删错一条就是灾难，所以宁可少删。这里是用户**明确**要删，拦错的
//! 代价不对称——把 `NeedsAttention`（上一次部署失败、等他处理）当成「还在跑」，
//! 结果就是「这台服务器我这辈子都删不掉」。所以这里只防「引擎可能还在写」：
//! `Running` / `Queued` 拦，状态读不出来的单独拦（认不出就不动），其余一律放行。

use std::path::Path;

use serde_json::{json, Value};

use crate::deploycred;
use crate::deploystore::{self, DeploymentStore};
use crate::reminder;
use crate::serverstore::{self, ServerRecord};

/// 一次判断的结论。`to_json` 的字段名就是契约，页面按它渲染。
#[derive(Debug, Clone)]
pub struct Assessment {
    record: ServerRecord,
    /// 属于这条记录、可删的 RunId。执行侧**只用这一份清单**（见模块头注释）。
    run_ids: Vec<String>,
    /// 还有几条线路用这台服务器。由调用方给：线路归属是 `ipc::server_items` 算的，
    /// 这里再算一遍就会出现两套「这条线路是不是指向它」的口径。
    pub lines: usize,
    pub runs: usize,
    pub archived: usize,
    /// 引擎可能还在写的条数（`Queued` / `Running`）。**不是**「非终态」的条数：
    /// 见模块头注释——`NeedsAttention` 之类已经停下来了，拦它们等于永远删不掉。
    pub active: usize,
    pub reminders: usize,
    pub credentials: usize,
    pub saved_credential: bool,
    /// 空 = 可以删；非空 = 不能删的原因（人话，可能有多句，`\n` 分隔）。
    pub blocked: String,
    /// 给确认框逐项列出的短句。只列**真的有**的项。
    pub items: Vec<String>,
}

impl Assessment {
    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.record.id,
            "Name": self.record.name,
            "Host": self.record.host,
            "Port": self.record.port,
            "User": self.record.user,
            "Lines": self.lines,
            "Runs": self.runs,
            "Archived": self.archived,
            "Active": self.active,
            "Reminders": self.reminders,
            "TaskCredentials": self.credentials,
            "SavedCredential": self.saved_credential,
            "Blocked": self.blocked,
            "Items": self.items,
        })
    }
}

/// 拒绝执行的两种原因。分开是因为它们对用户是两件事：
/// 「现在还不能删（等等或先处理）」与「我读不出磁盘上的东西（别删，先查）」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// 有前置条件没满足（线路在用 / 还有部署没结束）。
    Blocked(String),
    /// 记录读不出来：**不许当成「0 条」继续删**。
    Config(String),
}

/// 执行结论。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub removed_runs: usize,
    pub removed_reminders: usize,
    pub removed_credentials: usize,
    /// 想删但没删掉的短句。**必须如实列出**：不许把「文件还在」说成删干净了。
    pub failed: Vec<String>,
}

impl Outcome {
    pub fn to_json(&self) -> Value {
        json!({
            "RemovedRuns": self.removed_runs,
            "RemovedReminders": self.removed_reminders,
            "RemovedCredentials": self.removed_credentials,
            "Failed": self.failed,
            "Message": self.message(),
        })
    }

    /// 一句话结论。有没删掉的项时必须说明有几项，不能让这句听起来像全部成功。
    pub fn message(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.removed_runs > 0 {
            parts.push(format!("{} 条部署记录", self.removed_runs));
        }
        if self.removed_reminders > 0 {
            parts.push(format!("{} 条提醒", self.removed_reminders));
        }
        if self.removed_credentials > 0 {
            parts.push(format!("{} 份登录资料", self.removed_credentials));
        }
        let mut text = if parts.is_empty() {
            if self.failed.is_empty() {
                // 服务器记录本身也删掉了，所以这句不是空话。
                "已删除这台服务器的本机记录（没有部署记录、提醒或登录资料）".to_string()
            } else {
                // 括号里那句是**承诺**：有东西没删掉时它就变成了假话
                // （「没有部署记录」紧接着又被下一句列出来）。
                "已删除这台服务器的本机记录".to_string()
            }
        } else {
            list_counts("已删除这台服务器在本机的", &parts)
        };
        if !self.failed.is_empty() {
            text.push_str(&format!(
                "；另有 {} 项没删掉：{}",
                self.failed.len(),
                self.failed.join("、")
            ));
        }
        text
    }
}

/// 结论里那个列举：`在本机的 3 条部署记录、2 条提醒与 1 份登录资料`。
///
/// **空格规则只有这一处**：每个分段都以数字开头（「3 条部署记录」），紧挨着它的
/// 汉字（`的`、`与`）后面留一个空格；顿号是标点，后面直接接数字不空。
/// 别在调用点手拼——两处各写一遍，迟早写出「的1 条」或「与1 份」。
fn list_counts(lead: &str, parts: &[String]) -> String {
    match parts.len() {
        0 => lead.to_string(),
        1 => format!("{lead} {}", parts[0]),
        _ => format!(
            "{lead} {}与 {}",
            parts[..parts.len() - 1].join("、"),
            parts[parts.len() - 1]
        ),
    }
}

/// 判断这条服务器记录在本机有哪些部署资料、能不能删。**只读，一个字节都不写**。
///
/// 三种失败分得很清楚：
/// - 任务目录整个读不出来 → `Err`：我们不知道有哪些任务，宁可拒绝也不许当成 0 条；
/// - 提醒文件读不出来 → `Err`：连「要删几条提醒」都说不清，就没有「删干净」可言；
/// - 某条任务记录读不出来（`partial`）→ **不报错也不猜**：它既不算进条数，也不会被删。
///   看不懂归属的东西一律留在原地（保守一侧），这比替用户顺手删掉安全得多。
pub fn assess(root: &Path, record: &ServerRecord, lines: usize) -> Result<Assessment, String> {
    let loaded = DeploymentStore::open(root).load_all();
    if loaded.tasks_read == deploystore::READ_FAILED {
        let message = if loaded.error.trim().is_empty() {
            "读取本机的部署任务记录失败，无法确定要删除哪些资料。".to_string()
        } else {
            loaded.error
        };
        return Err(message);
    }

    let mut run_ids: Vec<String> = Vec::new();
    let mut archived = 0usize;
    let mut active = 0usize;
    // 状态读不出来的条数（不在 `deploystore::STATES` 里）：认不出就不动，单独拦。
    let mut unknown = 0usize;
    for run in &loaded.runs {
        if run.target.server_record_id.as_deref() != Some(record.id.as_str()) {
            continue;
        }
        run_ids.push(run.run_id.clone());
        if run.is_archived() {
            archived += 1;
        }
        // 只有这两种状态后面可能还有一个线程正在写文件——那才是删除要躲的东西。
        // 与 `deployrun::recover` 的第 1 条判据是同一个口径（「只有 `Running` /
        // `Queued` 才代表有人在推进它；`Draft`/`WaitingUser` 只是表单，`Paused` 是
        // 用户按下的，`NeedsAttention` 已经在等人」）。这里不另发明一套说法。
        if run.state == deploystore::STATE_RUNNING || run.state == deploystore::STATE_QUEUED {
            active += 1;
        } else if !deploystore::STATES.contains(&run.state.as_str()) {
            // 空状态、旧版本写的表外值、"Hovering" 这种东西：不知道它停没停。
            unknown += 1;
        }
    }

    let reminders = reminder::count_for_runs(root, &run_ids)?;
    let credentials = deploycred::count_for_runs(root, &run_ids);
    let saved_credential = serverstore::has_saved_credential(root, &record.id);

    // 三条硬判据。都可能同时成立，那就都说出来（对话框只有一个正文框）。
    let mut reasons: Vec<String> = Vec::new();
    if lines > 0 {
        // 与 `server-remove` 原句一字不差：同一件事在两处说法不同，用户会以为是两个问题。
        reasons.push(format!(
            "还有 {lines} 条线路用到这台服务器；请先删除这些线路，再删服务器记录。"
        ));
    }
    if active > 0 {
        reasons.push(format!(
            "这台服务器还有 {active} 个部署没有结束；请等它跑完（或先取消），再删除本机资料。"
        ));
    }
    if unknown > 0 {
        // 单独一句：说成「还有 N 个部署没有结束」会让用户去找一个根本不存在的东西
        // （那条记录的状态本身就是坏的，界面上不会显示成「进行中」）。
        reasons.push(if unknown == 1 {
            "这台服务器上有一条部署的状态读不出来，先取消或等它结束再删除本机资料。".to_string()
        } else {
            format!(
                "这台服务器上有 {unknown} 条部署的状态读不出来，先取消或等它结束再删除本机资料。"
            )
        });
    }

    let runs = run_ids.len();
    let mut items = vec!["服务器记录".to_string()];
    if runs > 0 {
        let mut text = format!("部署任务记录 {runs} 条");
        if archived > 0 {
            text.push_str(&format!("（含已归档 {archived} 条）"));
        }
        items.push(text);
    }
    if reminders > 0 {
        items.push(format!("结果提醒 {reminders} 条"));
    }
    if credentials > 0 {
        items.push(format!("任务级登录资料 {credentials} 份"));
    }
    if saved_credential {
        items.push("长期保存的登录资料".to_string());
    }

    Ok(Assessment {
        record: record.clone(),
        run_ids,
        lines,
        runs,
        archived,
        active,
        reminders,
        credentials,
        saved_credential,
        blocked: reasons.join("\n"),
        items,
    })
}

/// 按 [`assess`] 的同一套判据再判一次，然后真的删。
///
/// 为什么执行前**又**判一次：预览到确认之间可能过了一段时间（用户去看了别的事，
/// 或者界面上的那一帧已经旧了）。信任一张几分钟前的预览去删文件，等于把判据
/// 交给了时间。
pub fn cleanup(
    root: &Path,
    record: &ServerRecord,
    lines: usize,
) -> Result<Outcome, Refusal> {
    let assessment = assess(root, record, lines).map_err(Refusal::Config)?;
    if !assessment.blocked.is_empty() {
        return Err(Refusal::Blocked(assessment.blocked.clone()));
    }

    let mut outcome = Outcome::default();
    let store = DeploymentStore::open(root);

    // 1) 任务记录本体。
    for run_id in &assessment.run_ids {
        match store.remove(run_id) {
            Ok(()) => outcome.removed_runs += 1,
            Err(error) => outcome
                .failed
                .push(format!("部署任务记录 {run_id}.json（{}）", error.message)),
        }
    }

    // 2) 任务级登录资料。`deploycred::remove` 幂等且不报错，所以「删掉了没有」只能
    //    回头看文件还在不在——这里不许猜。
    for run_id in &assessment.run_ids {
        let Ok(path) = deploycred::file_of(root, run_id) else {
            continue;
        };
        if !path.exists() {
            continue;
        }
        deploycred::remove(root, run_id);
        if path.exists() {
            outcome
                .failed
                .push(format!("任务级登录资料 {run_id}.bin"));
        } else {
            outcome.removed_credentials += 1;
        }
    }

    // 3) 结果提醒。读不懂的文件不覆盖（`reminder::remove_runs` 里说明）。
    match reminder::remove_runs(root, &assessment.run_ids) {
        Ok(removed) => outcome.removed_reminders = removed,
        Err(_) if assessment.reminders == 0 => {}
        Err(_) => outcome
            .failed
            .push(format!("结果提醒 {} 条", assessment.reminders)),
    }

    // 4) 最后才是记录目录本身（含长期保存的 DPAPI 凭据）。
    if let Err(error) = serverstore::remove(root, &record.id) {
        outcome
            .failed
            .push(format!("服务器记录（{}）", error.message));
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const RECORD_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const RUN_A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const RUN_B: &str = "bbbbbbbb-2222-4222-8222-222222222222";

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-servercleanup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn record() -> ServerRecord {
        ServerRecord {
            id: RECORD_ID.to_string(),
            name: "root@203.0.113.10".to_string(),
            host: "203.0.113.10".to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:AAAA".to_string(),
            created_at: "2026-11-10T00:00:00Z".to_string(),
            updated_at: "2026-11-10T00:00:00Z".to_string(),
        }
    }

    /// 造一条部署任务记录：只有「归属」「状态」「归档」三件事，其余字段一律缺省
    /// （`RunRecord::from_json` 对它们宽容）。
    fn write_run(root: &Path, run_id: &str, record_id: Option<&str>, state: &str) {
        write_run_with(root, run_id, record_id, state, false);
    }

    fn write_run_with(
        root: &Path,
        run_id: &str,
        record_id: Option<&str>,
        state: &str,
        archived: bool,
    ) {
        let dir = root.join("deployments").join("runs");
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = json!({
            "SchemaVersion": 1,
            "Kind": "SpiderVPN.DeploymentRun",
            "RunId": run_id,
            "State": state,
            "Target": {
                "Host": "203.0.113.10",
                "Port": 22,
                "User": "root",
                "ServerRecordId": record_id,
            },
        });
        if archived {
            body["ArchivedAtUtc"] = json!("2026-11-10T00:00:00Z");
        }
        std::fs::write(dir.join(format!("{run_id}.json")), body.to_string()).unwrap();
    }

    /// 预置提醒文件：这些 RunId 各一条「已完成」提醒。
    fn write_reminders(root: &Path, run_ids: &[&str]) {
        let dir = root.join("deployments");
        std::fs::create_dir_all(&dir).unwrap();
        let items: Vec<Value> = run_ids
            .iter()
            .map(|run_id| {
                json!({
                    "Id": format!("{run_id}-complete"),
                    "RunId": run_id,
                    "State": "Complete",
                    "Step": 4,
                    "CreatedAtUtc": "2026-11-10T00:00:00Z",
                })
            })
            .collect();
        std::fs::write(
            dir.join("reminders.json"),
            json!({
                "Schema": 1,
                "Kind": crate::reminder::KIND,
                "Reminders": items,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_task_credential(root: &Path, run_id: &str) {
        let dir = root.join("deployments").join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{run_id}.bin")), "{}").unwrap();
    }

    /// 归属判据：同 `host:port` 但 `server_record_id == None` 的那条**不是**它的资料。
    ///
    /// 这条守的是最贵的那个错：按地址猜归属会把用户手工建的另一次部署一起烧掉。
    #[test]
    fn only_runs_that_name_this_record_are_ever_deleted() {
        let root = temp_root("ownership");
        write_run(&root, RUN_A, Some(RECORD_ID), "Complete");
        write_run(&root, RUN_B, None, "Complete");

        let assessment = assess(&root, &record(), 0).expect("应当能判断");
        assert_eq!(assessment.runs, 1, "只有一条写着归属的");
        assert_eq!(assessment.items[1], "部署任务记录 1 条");

        let outcome = cleanup(&root, &record(), 0).expect("应当能删");
        assert_eq!(outcome.removed_runs, 1);
        assert!(
            root.join("deployments")
                .join("runs")
                .join(format!("{RUN_B}.json"))
                .exists(),
            "没写归属的那条必须留着"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 还有部署没结束：判断给理由，执行一个字节都不动。
    #[test]
    fn an_unfinished_run_blocks_the_cleanup_and_nothing_is_removed() {
        let root = temp_root("active");
        write_run(&root, RUN_A, Some(RECORD_ID), "Running");

        let assessment = assess(&root, &record(), 0).unwrap();
        assert_eq!(assessment.active, 1);
        assert!(
            assessment.blocked.contains("还有 1 个部署没有结束"),
            "{}",
            assessment.blocked
        );

        let refusal = cleanup(&root, &record(), 0).expect_err("必须拒绝");
        match refusal {
            Refusal::Blocked(message) => assert!(message.contains("没有结束"), "{message}"),
            other => panic!("必须是 Blocked：{other:?}"),
        }
        assert!(
            root.join("deployments")
                .join("runs")
                .join(format!("{RUN_A}.json"))
                .exists(),
            "拒绝时一条都不许删"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 上一次部署失败（`NeedsAttention`）**不拦**：那正是用户要清理的现场。
    ///
    /// 这条守的是「判据选错」那种缺陷：用 `is_terminal()` 判「还在跑」会把
    /// `NeedsAttention` 算成未结束，于是这台服务器永远删不掉——而「部署失败之后
    /// 决定不要这台机器」恰恰是最常见的用法。
    #[test]
    fn a_failed_deployment_does_not_block_the_cleanup() {
        let root = temp_root("needs-attention");
        write_run(&root, RUN_A, Some(RECORD_ID), "NeedsAttention");
        write_run_with(&root, RUN_B, Some(RECORD_ID), "Complete", true);

        let assessment = assess(&root, &record(), 0).expect("应当能判断");
        assert_eq!(assessment.runs, 2);
        assert_eq!(assessment.archived, 1);
        assert_eq!(assessment.active, 0, "NeedsAttention 不是在跑");
        assert_eq!(assessment.blocked, "", "失败的部署不该拦住清理");

        let outcome = cleanup(&root, &record(), 0).expect("应当能删");
        assert_eq!(outcome.removed_runs, 2);
        for run in [RUN_A, RUN_B] {
            assert!(
                !root
                    .join("deployments")
                    .join("runs")
                    .join(format!("{run}.json"))
                    .exists(),
                "{run} 应当跟着删掉"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 状态读不出来（不在 `deploystore::STATES` 里）：拦，而且用**自己的**一句话。
    ///
    /// 混进「还有 N 个部署没有结束」会让用户去找一个不存在的东西——那条记录在界面上
    /// 根本不会显示成「进行中」，因为它连状态都读不出来。
    #[test]
    fn an_unreadable_state_blocks_the_cleanup_with_its_own_sentence() {
        let root = temp_root("unknown-state");
        write_run(&root, RUN_A, Some(RECORD_ID), "Hovering");

        let assessment = assess(&root, &record(), 0).expect("应当能判断");
        assert_eq!(assessment.runs, 1);
        assert_eq!(assessment.active, 0, "读不懂的状态不算「在跑」");
        assert!(
            assessment.blocked.contains("状态读不出来"),
            "要说清是状态读不出来：{}",
            assessment.blocked
        );
        assert!(
            !assessment.blocked.contains("没有结束"),
            "别混用「没有结束」那句：{}",
            assessment.blocked
        );

        match cleanup(&root, &record(), 0).expect_err("必须拒绝") {
            Refusal::Blocked(message) => assert!(message.contains("状态读不出来"), "{message}"),
            other => panic!("必须是 Blocked：{other:?}"),
        }
        assert!(
            root.join("deployments")
                .join("runs")
                .join(format!("{RUN_A}.json"))
                .exists(),
            "拒绝时一个文件都不许删"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 线路在用：理由沿用 `server-remove` 的那句原话。
    #[test]
    fn lines_in_use_block_with_the_same_sentence_as_server_remove() {
        let root = temp_root("lines");
        write_run(&root, RUN_A, Some(RECORD_ID), "Complete");
        let assessment = assess(&root, &record(), 2).unwrap();
        assert_eq!(assessment.lines, 2);
        assert_eq!(
            assessment.blocked,
            "还有 2 条线路用到这台服务器；请先删除这些线路，再删服务器记录。"
        );
        assert!(cleanup(&root, &record(), 2).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一句话结论：没有资料可删时不许空着；有没删掉的项时必须说明有几项。
    #[test]
    fn the_message_always_says_what_happened_and_what_did_not() {
        let nothing = Outcome::default();
        assert_eq!(
            nothing.message(),
            "已删除这台服务器的本机记录（没有部署记录、提醒或登录资料）"
        );

        let partial = Outcome {
            removed_runs: 1,
            removed_reminders: 2,
            removed_credentials: 0,
            failed: vec!["部署任务记录 x.json（被占用）".to_string()],
        };
        let text = partial.message();
        assert!(text.contains("1 条部署记录"), "{text}");
        assert!(text.contains("2 条提醒"), "{text}");
        assert!(text.contains("1 项没删掉"), "{text}");
        assert_eq!(partial.to_json()["Failed"].as_array().map(Vec::len), Some(1));
    }

    /// 这句话是用户唯一会读到的结论，所以两种「假话」都要钉住：
    ///
    /// 1. **删不掉时不许说「没有部署记录」**——前半句刚否认完，后半句立刻列出那条
    ///    没删掉的部署记录，等于自相矛盾；
    /// 2. **数字前要有空格**（「在本机的 1 条提醒」，不是「在本机的1 条提醒」）。
    ///
    /// 两处都必须是**字面**断言：写成 `contains("已删除")` 这种松断言，两句假话都能过。
    #[test]
    fn the_message_never_denies_the_records_it_failed_to_delete() {
        use std::os::windows::fs::OpenOptionsExt;
        // 只允许别人读、不允许删：真机上「杀毒/备份软件正拿着它」就是这种形状。
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        // 1) 只有一条 run、删不掉、也没有提醒与凭据。
        let bare = temp_root("message-bare");
        write_run(&bare, RUN_A, Some(RECORD_ID), "Complete");
        let held = bare
            .join("deployments")
            .join("runs")
            .join(format!("{RUN_A}.json"));
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&held)
            .expect("要能独占住这个文件");
        let outcome = cleanup(&bare, &record(), 0).expect("应当能执行");
        let text = outcome.message();
        assert_eq!(outcome.removed_runs, 0, "{text}");
        assert!(text.contains("另有 1 项没删掉"), "{text}");
        assert!(
            !text.contains("没有部署记录"),
            "前半句不许否认后半句列出的事实：{text}"
        );
        assert!(
            text.starts_with("已删除这台服务器的本机记录；另有 1 项没删掉："),
            "删不掉时那句括号必须去掉：{text}"
        );
        drop(holder);
        let _ = std::fs::remove_dir_all(&bare);

        // 2) 数字前缺空格：让「提醒 / 登录资料」排在第一位（run 删不掉，removed_runs 为 0）。
        let extras = temp_root("message-spacing");
        write_run(&extras, RUN_A, Some(RECORD_ID), "Complete");
        write_reminders(&extras, &[RUN_A]);
        write_task_credential(&extras, RUN_A);
        let held = extras
            .join("deployments")
            .join("runs")
            .join(format!("{RUN_A}.json"));
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&held)
            .expect("要能独占住这个文件");
        let outcome = cleanup(&extras, &record(), 0).expect("应当能执行");
        assert_eq!(outcome.removed_runs, 0);
        assert_eq!(outcome.removed_reminders, 1);
        assert_eq!(outcome.removed_credentials, 1);
        let text = outcome.message();
        assert!(!text.contains("的1"), "数字前缺空格：{text}");
        assert!(text.contains("的 1 条提醒"), "{text}");
        assert!(
            text.starts_with("已删除这台服务器在本机的 1 条提醒与 1 份登录资料"),
            "{text}"
        );
        drop(holder);
        let _ = std::fs::remove_dir_all(&extras);
    }
}
