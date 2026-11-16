//! 单任务诊断摘要：把一条部署记录投影成一份**可以直接贴给别人的** Markdown / JSON。
//!
//! 为什么要有它：部署失败时最有用的信息散在记录里的五六个字段上（状态、原因码、
//! 哪一步、未决写、尝试历史）。让用户自己去翻 `deployments\runs\<RunId>.json`
//! 不现实，截图又说不清错误码。
//!
//! 两条硬约束：
//!
//! 1. **字段是白名单**：这里不调 `run.to_json()`。记录以后加字段时，秘密不能因为
//!    「忘了排除」被顺带导出去——新字段要进摘要，必须到这张表里来加一行。
//! 2. **纯函数**：不读盘、不写盘、不碰引擎。写文件是调用方（`ipc`）的事。

use serde_json::{json, Value};

use crate::deploystore::RunRecord;

/// 摘要格式。默认 Markdown（贴给人看），JSON 给脚本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
}

impl Format {
    pub fn parse(text: &str) -> Option<Format> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "markdown" | "md" => Some(Format::Markdown),
            "json" => Some(Format::Json),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Markdown => "md",
            Format::Json => "json",
        }
    }
}

/// 记录 → 摘要投影（白名单）。**不含**任何秘密：
/// 密码从来不在记录里；`Plan.ClientPublicKey` 是公钥，但诊断不需要它，也不导出。
pub fn projection(run: &RunRecord, exported_at_utc: &str) -> Value {
    let steps: Vec<Value> = run
        .steps
        .iter()
        .map(|step| {
            json!({
                "Index": step.index,
                "Name": step.name,
                "Status": step.status,
                "StartedAtUtc": step.started_at_utc,
                "FinishedAtUtc": step.finished_at_utc,
                "ErrorCode": step.error.as_ref().map(|reason| reason.code.clone()),
                "ErrorText": step.error.as_ref().map(|reason| reason.text.clone()),
            })
        })
        .collect();
    let attempts: Vec<Value> = run
        .attempts
        .iter()
        .map(|item| {
            json!({
                "No": item.no,
                "StartedAtUtc": item.started_at_utc,
                "FinishedAtUtc": item.finished_at_utc,
                "FailedStep": item.failed_step,
                "ErrorCode": item.error_code,
                "Reconcile": item.reconcile,
            })
        })
        .collect();
    let pending = run.pending_operation.as_ref().map(|item| {
        json!({
            "Kind": item.kind,
            "Outcome": item.outcome,
            "VerifyBy": item.verify_by,
            "StartedAtUtc": item.started_at_utc,
            "PlanDigest": item.plan_digest,
        })
    });
    let executor = run.executor.as_ref().map(|item| {
        json!({
            "Pid": item.pid,
            "Background": item.background,
            "HeartbeatAtUtc": item.heartbeat_at_utc,
        })
    });
    let reason = run.reason.as_ref().map(|item| {
        json!({
            "Category": item.category,
            "Class": item.class,
            "Code": item.code,
            "Text": item.text,
            "AtUtc": item.at,
        })
    });
    json!({
        "Kind": "TradeChannel.DeployDiagnostic",
        "Schema": 1,
        "ExportedAtUtc": exported_at_utc,
        "Run": {
            "RunId": run.run_id,
            "RunShort": crate::deployrun::run_short(&run.run_id),
            "Name": run.label,
            "State": run.state,
            "StateText": crate::deployrun::state_text(&run.state),
            "StepsDone": crate::deployrun::steps_done(run),
            "Step": run.step,
            "NextAction": run.next_action,
            "Target": {
                "User": run.target.user,
                "Host": run.target.host,
                "Port": run.target.port,
            },
            "Fingerprint": run.identity.fingerprint,
            // 这一次的指纹是不是「没人工核对、按设置自动记住」的。
            // 排障时「为什么它信这台机器」有一半答案在这里。
            "AutoTrusted": run.identity.auto_trusted,
            "PlanDigest": run.plan_digest,
            "Revision": run.revision,
            "CreatedAtUtc": run.created_at_utc,
            "StartedAtUtc": run.started_at_utc,
            "UpdatedAtUtc": run.updated_at_utc,
            "FinishedAtUtc": run.finished_at_utc,
            "Reason": reason,
            "Steps": steps,
            "Attempts": attempts,
            "PendingOperation": pending,
            "Executor": executor,
            "Plan": {
                "Interface": run.plan.interface,
                "UdpPort": run.plan.udp_port,
                "Subnet": run.plan.subnet,
                "Mtu": run.plan.mtu,
            },
        },
    })
}

/// 时间：`None` / 空 → `—`，其余原样（记录里本来就是人读的 UTC 串）。
fn at(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("—")
        .to_string()
}

fn cell(value: &str) -> String {
    // Markdown 表格里 `|` 会把一列劈成两列。
    value.replace('|', "\\|").replace('\n', " ")
}

/// 渲染。两种格式共用同一份投影，避免「Markdown 有、JSON 没有」。
pub fn render(run: &RunRecord, format: Format, exported_at_utc: &str) -> Result<String, String> {
    let value = projection(run, exported_at_utc);
    match format {
        Format::Json => serde_json::to_string_pretty(&value)
            .map(|text| format!("{text}\n"))
            .map_err(|error| format!("生成 JSON 摘要失败：{error}")),
        Format::Markdown => Ok(markdown(&value)),
    }
}

fn markdown(value: &Value) -> String {
    let run = &value["Run"];
    let text_of = |key: &str| {
        run.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let opt = |key: &str| {
        run.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
    };

    let mut out = String::new();
    out.push_str("# 部署诊断摘要\n\n");
    out.push_str(&format!("- 记录：{}\n", text_of("Name")));
    out.push_str(&format!(
        "- 任务编号：{}（{}）\n",
        text_of("RunId"),
        text_of("RunShort")
    ));
    out.push_str(&format!(
        "- 状态：{}（{}）\n",
        text_of("StateText"),
        text_of("State")
    ));
    let step = run.get("Step").and_then(Value::as_u64);
    let done = run.get("StepsDone").and_then(Value::as_u64).unwrap_or(0);
    match step {
        Some(index) => out.push_str(&format!("- 进度：{done}/4 步（停在第 {} 步）\n", index + 1)),
        None => out.push_str(&format!("- 进度：{done}/4 步（当前步骤未知）\n")),
    }
    out.push_str(&format!("- 下一步：{}\n", text_of("NextAction")));
    let target = &run["Target"];
    out.push_str(&format!(
        "- 目标：{}@{}:{}\n",
        target["User"].as_str().unwrap_or(""),
        target["Host"].as_str().unwrap_or(""),
        target["Port"].as_u64().unwrap_or(0)
    ));
    out.push_str(&format!(
        "- 指纹：{}{}\n",
        text_of("Fingerprint"),
        if run["AutoTrusted"].as_bool().unwrap_or(false) {
            "（这一次是自动记住的，没有人工核对）"
        } else {
            ""
        }
    ));
    out.push_str(&format!(
        "- 时间：创建 {} ｜ 开始 {} ｜ 更新 {} ｜ 结束 {}\n",
        at(&opt("CreatedAtUtc")),
        at(&opt("StartedAtUtc")),
        at(&opt("UpdatedAtUtc")),
        at(&opt("FinishedAtUtc"))
    ));
    out.push_str(&format!(
        "- 记录版本：{}\n",
        run.get("Revision").and_then(Value::as_u64).unwrap_or(0)
    ));
    if let Some(executor) = run.get("Executor").filter(|item| !item.is_null()) {
        out.push_str(&format!(
            "- 执行者：pid {}（后台：{}，最后一拍心跳 {}）\n",
            executor.get("Pid").and_then(Value::as_i64).unwrap_or(0),
            if executor.get("Background").and_then(Value::as_bool) == Some(true) {
                "是"
            } else {
                "否"
            },
            at(&executor.get("HeartbeatAtUtc").and_then(Value::as_str).map(str::to_string))
        ));
    }

    out.push_str("\n## 原因\n\n");
    match run.get("Reason").filter(|item| !item.is_null()) {
        Some(reason) => {
            out.push_str(&format!(
                "- 分类：{} ｜ 错误类：{} ｜ 错误码：{}\n",
                reason.get("Category").and_then(Value::as_str).unwrap_or("—"),
                reason.get("Class").and_then(Value::as_str).unwrap_or("—"),
                reason.get("Code").and_then(Value::as_str).unwrap_or("—")
            ));
            out.push_str(&format!(
                "- 说明：{}\n",
                reason.get("Text").and_then(Value::as_str).unwrap_or("—")
            ));
        }
        None => out.push_str("- 没有失败原因（这次没有停下）。\n"),
    }

    out.push_str("\n## 四步\n\n");
    out.push_str("| # | 步骤 | 状态 | 开始 | 结束 | 错误 |\n|---|---|---|---|---|---|\n");
    if let Some(steps) = run.get("Steps").and_then(Value::as_array) {
        for step in steps {
            let index = step.get("Index").and_then(Value::as_u64).unwrap_or(0) + 1;
            let code = step
                .get("ErrorCode")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string);
            let error = match code {
                Some(code) => {
                    let text = step.get("ErrorText").and_then(Value::as_str).unwrap_or("");
                    if text.is_empty() {
                        code
                    } else {
                        format!("{code}：{text}")
                    }
                }
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "| {index} | {} | {} | {} | {} | {} |\n",
                cell(step.get("Name").and_then(Value::as_str).unwrap_or("")),
                cell(step.get("Status").and_then(Value::as_str).unwrap_or("")),
                cell(&at(&step.get("StartedAtUtc").and_then(Value::as_str).map(str::to_string))),
                cell(&at(&step.get("FinishedAtUtc").and_then(Value::as_str).map(str::to_string))),
                cell(&error)
            ));
        }
    }

    out.push_str("\n## 尝试历史\n\n");
    let attempts = run
        .get("Attempts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if attempts.is_empty() {
        out.push_str("- 还没有尝试记录。\n");
    } else {
        out.push_str("| 次 | 开始 | 结束 | 失败步骤 | 错误码 | 核对 |\n|---|---|---|---|---|---|\n");
        for item in &attempts {
            let failed_step = item
                .get("FailedStep")
                .and_then(Value::as_u64)
                .map(|index| format!("第 {} 步", index + 1))
                .unwrap_or_else(|| "—".to_string());
            let code = item
                .get("ErrorCode")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("—");
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                item.get("No").and_then(Value::as_u64).unwrap_or(0),
                cell(&at(&item.get("StartedAtUtc").and_then(Value::as_str).map(str::to_string))),
                cell(&at(&item.get("FinishedAtUtc").and_then(Value::as_str).map(str::to_string))),
                cell(&failed_step),
                cell(code),
                cell(item.get("Reconcile").and_then(Value::as_str).unwrap_or("—"))
            ));
        }
    }

    out.push_str("\n## 未决写\n\n");
    match run.get("PendingOperation").filter(|item| !item.is_null()) {
        Some(pending) => {
            out.push_str(&format!(
                "- 种类：{} ｜ 结论：{} ｜ 核对方式：{} ｜ 开始：{}\n",
                pending.get("Kind").and_then(Value::as_str).unwrap_or("—"),
                pending.get("Outcome").and_then(Value::as_str).unwrap_or("—"),
                pending.get("VerifyBy").and_then(Value::as_str).unwrap_or("—"),
                at(&pending
                    .get("StartedAtUtc")
                    .and_then(Value::as_str)
                    .map(str::to_string))
            ));
        }
        None => out.push_str("- 没有未核对完的写操作。\n"),
    }

    out.push_str(
        "\n---\n\n这份摘要只来自本机记录（`deployments\\runs\\<RunId>.json`）。\
         密码不在记录里；隧道私钥只在本机，不在任何记录或日志中。\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploystore::{Reason, Target};

    const PASSWORD: &str = "Sup3r-Secret-P@ss";

    fn record() -> RunRecord {
        let mut run = crate::deployrun::new_draft(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
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
        run.state = crate::deploystore::STATE_NEEDS_ATTENTION.to_string();
        run.step = Some(1);
        run.next_action = crate::deploystore::NEXT_ACTION_RETRY_STEP.to_string();
        run.steps[0].status = crate::deploystore::STEP_STATUS_DONE.to_string();
        run.steps[1].status = crate::deploystore::STEP_STATUS_FAILED.to_string();
        let reason = Reason::now(
            crate::deploystore::REASON_FAILED,
            crate::deploystore::ERROR_CLASS_ENVIRONMENT,
            "ListenFailed",
            "端口被占用",
        );
        run.steps[1].error = Some(reason.clone());
        run.reason = Some(reason);
        crate::deployrun::finish_attempt(&mut run, "2026-11-12T10:03:00Z", Some(1), "ListenFailed");
        run
    }

    #[test]
    fn the_markdown_summary_says_what_happened_and_where() {
        let text = render(&record(), Format::Markdown, "2026-11-12T12:00:00Z").unwrap();
        for needle in [
            "# 部署诊断摘要",
            "自建 · 203.0.113.10",
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            "需要处理（NeedsAttention）",
            "1/4 步（停在第 2 步）",
            "root@203.0.113.10:22",
            "ListenFailed",
            "端口被占用",
            "准备标准连接",
            "尝试历史",
            "没有未核对完的写操作",
        ] {
            assert!(text.contains(needle), "摘要里缺 {needle}：\n{text}");
        }
        // 表格必须是四步 + 一行表头分隔。
        assert!(text.contains("| 4 | 接入本机并登记线路 |"), "{text}");
    }
    /// 这一次的指纹是「自动记住」的，摘要必须写出来——排障时「它为什么信这台机器」
    /// 有一半答案在这里；人工核对过的则一个字都不许多。
    #[test]
    fn the_summary_says_when_the_fingerprint_was_auto_trusted() {
        let mut run = record();
        run.identity.auto_trusted = true;
        let text = render(&run, Format::Markdown, "2026-11-12T12:00:00Z").unwrap();
        assert!(text.contains("这一次是自动记住的"), "{text}");
        assert!(text.contains("没有人工核对"), "要把「没人核对过」说透：{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(&render(&run, Format::Json, "2026-11-12T12:00:00Z").unwrap()).unwrap();
        assert_eq!(parsed["Run"]["AutoTrusted"], serde_json::json!(true), "{parsed}");

        let mut manual = record();
        manual.identity.auto_trusted = false;
        let text = render(&manual, Format::Markdown, "2026-11-12T12:00:00Z").unwrap();
        assert!(!text.contains("自动记住"), "没自动记住就不许出现这句话：{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(&render(&manual, Format::Json, "2026-11-12T12:00:00Z").unwrap()).unwrap();
        assert_eq!(parsed["Run"]["AutoTrusted"], serde_json::json!(false), "{parsed}");
    }

    #[test]
    fn the_json_summary_is_structured_and_carries_the_same_facts() {
        let text = render(&record(), Format::Json, "2026-11-12T12:00:00Z").unwrap();
        let value: Value = serde_json::from_str(&text).expect("必须是合法 JSON");
        assert_eq!(value["Kind"], json!("TradeChannel.DeployDiagnostic"));
        assert_eq!(value["Schema"], json!(1));
        assert_eq!(
            value["Run"]["RunId"],
            json!("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f")
        );
        assert_eq!(value["Run"]["StateText"], json!("需要处理"));
        assert_eq!(value["Run"]["Steps"].as_array().map(Vec::len), Some(4));
        assert_eq!(value["Run"]["Attempts"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["Run"]["Attempts"][0]["ErrorCode"], json!("ListenFailed"));
        assert_eq!(value["Run"]["Reason"]["Code"], json!("ListenFailed"));
    }

    /// 摘要里不许出现秘密。这条是白名单投影的可执行版本：
    /// 记录以后加字段时，忘记排除秘密会在这里红。
    #[test]
    fn the_summary_never_carries_a_secret() {
        let mut run = record();
        run.step = Some(2);
        for format in [Format::Markdown, Format::Json] {
            let text = render(&run, format, "2026-11-12T12:00:00Z").unwrap();
            for forbidden in [
                PASSWORD,
                "password",
                "Password",
                "PRIVATE KEY",
                "PrivateKey",
                "private_key",
                "tunnel.key",
                "PresharedKey",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{format:?} 摘要里出现了 {forbidden}：\n{text}"
                );
            }
        }
    }

    #[test]
    fn the_format_parser_only_accepts_the_two_known_words() {
        assert_eq!(Format::parse(""), Some(Format::Markdown));
        assert_eq!(Format::parse("md"), Some(Format::Markdown));
        assert_eq!(Format::parse("Markdown"), Some(Format::Markdown));
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("yaml"), None);
        assert_eq!(Format::Markdown.extension(), "md");
        assert_eq!(Format::Json.extension(), "json");
    }
}
