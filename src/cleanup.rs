//! 删除线路后没清掉的本地文件：`<data root>/logs/delete-cleanup.json`。
//!
//! 删除一条线路是两步：先改 `config.json`（线路从列表消失），再删
//! `lines\<id>.json`（引擎配置，含隧道私钥）。第二步可能失败——文件被编辑器占着、
//! 权限被改过。这时**界面必须说“配置删了、文件没删”**，而且这句话要活过重启：
//! 用户可能过几天才回来处理，重启后提示就没了，等于悄悄留下一个私钥文件。
//!
//! 只记重试需要的**最小事实**：id、名字、相对路径、错误原文。绝对路径不落盘：
//! 重试时按 id 用与生成时同一条规则重算路径（[`crate::config::engine_config_path_for`]），
//! 一份被拷走的记录不能在另一个数据根上删到别的文件。
//!
//! 写入是「临时文件 + 重命名」：中途断电不会留下半截 JSON（半截记录读不出来，
//! 而读不出来的记录既不能展示也不能重试）。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub const KIND: &str = "TradeChannel.DeleteCleanup";
pub const SCHEMA: u32 = 1;

const DIR: &str = "logs";
const NAME: &str = "delete-cleanup.json";

/// 一条待清理项。`file` 是相对数据根的展示路径，重试时**不用它**拼路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub name: String,
    pub file: String,
    pub error: String,
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

/// 读出全部待清理项。文件不存在 = 没有待清理；坏记录**照实报错**——
/// 静默当成空会让页面上「重试清理」永远消失，而文件还在那里。
pub fn load(root: &Path) -> Result<Vec<Pending>, String> {
    let file = path(root);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(bad(&format!("读取待清理记录失败：{error}"))),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| bad("待清理记录不是合法 JSON，无法判断还有哪些文件要清"))?;
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return Err(bad("待清理记录的文件类型不认识"));
    }
    let mut out = Vec::new();
    for item in value
        .get("Pending")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let text_of = |key: &str| {
            item.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        };
        let (Some(id), Some(name), Some(file)) = (text_of("Id"), text_of("Name"), text_of("File"))
        else {
            return Err(bad("待清理记录里有一条缺少 id、名字或文件"));
        };
        out.push(Pending {
            id,
            name,
            file,
            error: text_of("Error").unwrap_or_default(),
        });
    }
    Ok(out)
}

/// 写回全部待清理项。空列表 = 删掉文件（没有待办就不该留一个空壳，
/// 否则「文件存在」会让人以为还有东西没清）。
pub fn save(root: &Path, pending: &[Pending]) -> Result<(), String> {
    let file = path(root);
    if pending.is_empty() {
        return match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(bad(&format!("清除待清理记录失败：{error}"))),
        };
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| bad(&format!("创建待清理记录目录失败：{error}")))?;
    }
    let body = json!({
        "SchemaVersion": SCHEMA,
        "Kind": KIND,
        "Pending": pending
            .iter()
            .map(|item| json!({
                "Id": item.id,
                "Name": item.name,
                "File": item.file,
                "Error": item.error,
            }))
            .collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&body)
        .map_err(|_| bad("待清理记录无法序列化"))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|error| bad(&format!("写入待清理记录失败：{error}")))?;
    std::fs::rename(&temp, &file).map_err(|error| bad(&format!("写入待清理记录失败：{error}")))
}

/// 记下（或更新）一条待清理项。同一条线路只留一条，错误原文以最后一次为准。
pub fn upsert(root: &Path, item: Pending) -> Result<(), String> {
    let mut pending = load(root)?;
    match pending.iter_mut().find(|existing| existing.id == item.id) {
        Some(existing) => *existing = item,
        None => pending.push(item),
    }
    save(root, &pending)
}

/// 清掉一条（清理成功后调用）。记录文件本身坏掉时返回错误，但**不阻塞**
/// 调用方把「文件已删」这个事实报给用户——调用方只把它当附加说明。
pub fn clear(root: &Path, id: &str) -> Result<(), String> {
    let mut pending = load(root)?;
    let before = pending.len();
    pending.retain(|item| item.id != id);
    if pending.len() == before {
        return Ok(());
    }
    save(root, &pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-cleanup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn item(id: &str, error: &str) -> Pending {
        Pending {
            id: id.to_string(),
            name: format!("线路 {id}"),
            file: format!("lines\\{id}.json"),
            error: error.to_string(),
        }
    }

    #[test]
    fn no_record_means_nothing_to_clean() {
        let root = temp_root("missing");
        assert_eq!(load(&root).unwrap(), Vec::new());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_keeps_only_the_relative_path_and_round_trips() {
        let root = temp_root("roundtrip");
        upsert(&root, item("jp", "拒绝访问。")).unwrap();
        assert_eq!(load(&root).unwrap(), vec![item("jp", "拒绝访问。")]);

        let raw = std::fs::read_to_string(path(&root)).unwrap();
        assert!(raw.contains("\"Kind\"") && raw.contains(KIND), "{raw}");
        assert!(raw.contains("lines\\\\jp.json"), "相对路径要原样能读回：{raw}");
        assert!(
            !raw.contains(&root.to_string_lossy().to_string()),
            "绝对路径不许落盘：{raw}"
        );

        clear(&root, "jp").unwrap();
        assert!(!path(&root).exists(), "清完最后一条要把记录文件删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn upserting_the_same_line_replaces_it_instead_of_stacking() {
        let root = temp_root("upsert");
        upsert(&root, item("jp", "第一次失败")).unwrap();
        upsert(&root, item("jp", "第二次失败")).unwrap();
        let pending = load(&root).unwrap();
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert_eq!(pending[0].error, "第二次失败");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_record_is_reported_instead_of_silently_empty() {
        let root = temp_root("corrupt");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "{ not json").unwrap();
        let error = load(&root).expect_err("坏记录必须报错");
        assert!(error.contains("delete-cleanup.json"), "{error}");
        std::fs::write(&file, r#"{"SchemaVersion":1,"Kind":"Other","Pending":[]}"#).unwrap();
        assert!(load(&root).is_err(), "类型不对也要报错，不能当成空记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_without_an_id_cannot_be_retried_so_it_is_reported() {
        let root = temp_root("noid");
        let file = path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"SchemaVersion":1,"Kind":"TradeChannel.DeleteCleanup","Pending":[{"Name":"x","File":"lines\\x.json"}]}"#,
        )
        .unwrap();
        let error = load(&root).expect_err("缺 id 的记录没法重试，必须报错");
        assert!(error.contains("缺少 id"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
