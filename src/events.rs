//! 操作记录：本程序做过的动作，一行一条，只读回看。
//!
//! 设计约束（三条，都是踩过的类型）：
//!
//! 1. **只记本机**：写进数据根自己的 `logs\operations.jsonl`，不外传、不上报。
//! 2. **best-effort**：记录失败绝不打断连接、改配置——排障手段不该变成新的故障点。
//! 3. **一处措辞**：所有动作名与详情都在 `record_config_change` / 调用方这里生成，
//!    界面与命令行显示的是同一份文本（两边各写一套，同一次操作就会有两种说法）。
//!
//! 记为「追加写」而不是「状态文件」：审计要的是发生过什么，不是当前是什么。
//! 需要裁剪时只丢最旧的那部分，且整份重写——半截追加会留下一条残行。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{AppConfig, LineConfig};

/// 记录文件（在数据根的 `logs` 目录下）。与引擎日志同目录但不同名：
/// 那个是给人看的滚动文本，这里是一行一条 JSON。
pub const FILE: &str = "operations.jsonl";
/// 「已隐藏」记录的键集合（r96）。隐藏**不删行**：审计文件保持原样，
/// 页面默认不显示，勾上「显示旧版隐藏记录」再出现，可逐条恢复。
const HIDDEN_FILE: &str = "operations.hidden.json";

/// 超过这个大小就裁剪，留最近 [`KEEP`] 条。
const MAX_BYTES: u64 = 256 * 1024;
/// 裁剪后保留的条数。界面上一次最多读 [`READ_LIMIT`] 条，留够翻看的余量。
const KEEP: usize = 500;
/// 界面/命令行一次读多少条（新→旧）。
pub const READ_LIMIT: usize = 200;

/// 动作名（界面与命令行共用这一套字）。
pub const CONNECT: &str = "连接";
pub const DISCONNECT: &str = "断开";
pub const RESTORE: &str = "还原";
pub const IMPORT_LINE: &str = "导入线路";
pub const REMOVE_LINE: &str = "删除线路";
/// 删线路时没删掉的本地引擎配置文件（A4 第二轮）。成功与失败都用这个名字：
/// 同一次清理，只是发生在删除当下还是用户点「重试清理」之后。
pub const CLEANUP: &str = "清理本地文件";
pub const SELECT_LINE: &str = "切换线路";
pub const EDIT_LINE: &str = "修改线路";
pub const RENAME_LINE: &str = "重命名线路";
pub const TRANSPORT: &str = "连接方式";
pub const MODE: &str = "接管方式";
pub const EXIT: &str = "出口设置";
pub const SPLIT: &str = "分流规则";
pub const SETTINGS: &str = "设置";
pub const PROVIDER_ADD: &str = "登记服务商";
pub const PROVIDER_REMOVE: &str = "移除服务商";
/// 按保留策略清理旧的部署记录（r79）：只在启动时发生，删的是「完成/取消 + 超过
/// 7 天 + 没有未读提醒 + 没归档」那一批。记一笔是为了事后能回答「我的记录去哪了」。
pub const PRUNE_RECORDS: &str = "清理部署记录";

/// 操作由哪条通道发起。写入时只允许这一组值，界面与 CLI 都按它筛选。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Ui,
    Cli,
    Pipe,
    Auto,
    #[default]
    Other,
}

impl Source {
    pub fn id(self) -> &'static str {
        match self {
            Source::Ui => "ui",
            Source::Cli => "cli",
            Source::Pipe => "pipe",
            Source::Auto => "auto",
            Source::Other => "other",
        }
    }
}

/// 一次操作的来源上下文。由入口显式创建，底层不得猜测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub source: Source,
    pub actor: String,
    pub obj: Option<String>,
}

impl Origin {
    pub fn new(source: Source) -> Self {
        Self { source, actor: format!("pid:{}", std::process::id()), obj: None }
    }

    pub fn ui() -> Self {
        Self::new(Source::Ui)
    }

    pub fn cli() -> Self {
        Self::new(Source::Cli)
    }

    pub fn pipe() -> Self {
        Self::new(Source::Pipe)
    }

    pub fn auto() -> Self {
        Self::new(Source::Auto)
    }

    pub fn other() -> Self {
        Self::new(Source::Other)
    }

    pub fn with_obj(mut self, obj: impl Into<String>) -> Self {
        self.obj = Some(obj.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    /// UTC RFC3339。界面按本机时区显示（`new Date(ts)`），CLI 原样打印并注明 UTC。
    pub ts: String,
    pub action: String,
    pub ok: bool,
    pub detail: String,
    /// v2 可选字段：旧记录没有它们，读取后保持 None，不丢行。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obj: Option<String>,
}

/// 记录文件路径。
pub fn path(root: &Path) -> PathBuf {
    root.join("logs").join(FILE)
}

/// 写一条记录。**永不返回错误**：调用方都在「已经做完事」的位置上，
/// 记不下来是日志的问题，不是这次连接/改配置失败。
pub fn record(root: &Path, action: &str, ok: bool, detail: &str, origin: &Origin) {
    // 空 root 只可能来自测试里造出来的相对路径：宁可这条不记，也不许往工作目录里写。
    if root.as_os_str().is_empty() {
        return;
    }
    let ev = Event {
        ts: now_rfc3339(),
        action: one_line(action, 24),
        ok,
        detail: one_line(detail, 300),
        src: Some(origin.source.id().to_string()),
        actor: Some(one_line(&origin.actor, 80)),
        obj: origin.obj.as_deref().map(|o| one_line(o, 120)),
    };
    let Ok(json) = serde_json::to_string(&ev) else {
        return;
    };
    // 整行一次写完：一行一次 write，别的进程（命令行）同时写也不会插到行中间。
    let mut buf = String::with_capacity(json.len() + 1);
    buf.push_str(&json);
    buf.push('\n');
    if let Err(e) = append(root, &buf) {
        eprintln!("操作记录写入失败（不影响本次操作）：{e}");
    }
}

fn append(root: &Path, body: &str) -> std::io::Result<()> {
    let p = path(root);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(&p)?;
    f.write_all(body.as_bytes())?;
    f.flush()?;
    drop(f);
    trim_if_large(&p);
    Ok(())
}

/// 超限就整份重写成最近 [`KEEP`] 条。重写走临时文件 + 替换：
/// 直接覆写时掉电会留下半份记录，审计文件被截断比丢几条更糟。
fn trim_if_large(p: &Path) {
    let Ok(meta) = fs::metadata(p) else { return };
    if meta.len() <= MAX_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(p) else { return };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= KEEP {
        return;
    }
    let tail = lines[lines.len() - KEEP..].join("\n");
    let tmp = p.with_extension("jsonl.tmp");
    if fs::write(&tmp, format!("{tail}\n")).is_ok() {
        let _ = fs::rename(&tmp, p);
    }
}

/// 读最近的记录，**新 → 旧**。坏行跳过（不因为一行写坏就整页空白）。
pub fn read(root: &Path, limit: usize) -> Vec<Event> {
    let Ok(text) = fs::read_to_string(path(root)) else {
        return Vec::new();
    };
    let mut out: Vec<Event> = text.lines().filter_map(parse_line).collect();
    out.reverse();
    out.truncate(limit);
    out
}

/// 一条记录在删除时用的稳定键。
///
/// 事件没有 id：`ts|action|detail` 三件套在同一台电脑上足够区分（时间精确到秒，
/// 动作与详情同时撞的概率极低）。分隔符用 \u{1}，正常的动作/详情里不会出现。
pub fn key(ts: &str, action: &str, detail: &str) -> String {
    format!("{ts}\u{1}{action}\u{1}{detail}")
}

/// 已隐藏记录的键集合。文件坏/不存在一律当空：隐藏是显示层的事，
/// 读不出来不该让整页记录消失。
pub fn hidden_keys(root: &Path) -> std::collections::HashSet<String> {
    let Ok(text) = fs::read_to_string(root.join("logs").join(HIDDEN_FILE)) else {
        return std::collections::HashSet::new();
    };
    serde_json::from_str::<Vec<String>>(&text)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

fn write_hidden(root: &Path, keys: &std::collections::HashSet<String>) -> bool {
    let dir = root.join("logs");
    if fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let mut list: Vec<&String> = keys.iter().collect();
    list.sort();
    let Ok(body) = serde_json::to_string(&list) else {
        return false;
    };
    let p = dir.join(HIDDEN_FILE);
    let tmp = p.with_extension("json.tmp");
    if fs::write(&tmp, body).is_err() {
        return false;
    }
    fs::rename(&tmp, &p).is_ok()
}

/// 隐藏指定键的记录，返回**新隐藏**的条数（已经隐藏的不重复计数）。
pub fn hide(root: &Path, keys: &[String]) -> usize {
    if keys.is_empty() || root.as_os_str().is_empty() {
        return 0;
    }
    let mut current = hidden_keys(root);
    let mut added = 0usize;
    for key in keys {
        if current.insert(key.clone()) {
            added += 1;
        }
    }
    if added > 0 && !write_hidden(root, &current) {
        return 0;
    }
    added
}

/// 恢复指定键的记录，返回恢复的条数。
pub fn restore(root: &Path, keys: &[String]) -> usize {
    if keys.is_empty() || root.as_os_str().is_empty() {
        return 0;
    }
    let mut current = hidden_keys(root);
    let mut removed = 0usize;
    for key in keys {
        if current.remove(key) {
            removed += 1;
        }
    }
    if removed > 0 && !write_hidden(root, &current) {
        return 0;
    }
    removed
}

/// 删掉指定键的记录，返回删掉的条数。**只有单测在用**：界面的「删除所选」已改为
/// [`hide`]（旧版的隐藏语义），生产代码不该直接销毁审计行。
///
/// **解析不了的行一律保留**：它走不到「是不是要删」这一步，宁可留着也不替用户
/// 销毁看不懂的数据。写回用 tmp + rename，中途崩不会留下半个文件。
#[cfg(test)]
pub fn remove(root: &Path, keys: &[String]) -> usize {
    if keys.is_empty() || root.as_os_str().is_empty() {
        return 0;
    }
    let p = path(root);
    let Ok(text) = fs::read_to_string(&p) else {
        return 0;
    };
    let wanted: std::collections::HashSet<&str> = keys.iter().map(String::as_str).collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let hit = serde_json::from_str::<serde_json::Value>(line.trim())
            .ok()
            .and_then(|v| {
                let ts = v.get("ts")?.as_str()?.to_string();
                let action = v.get("action").and_then(|a| a.as_str()).unwrap_or("").to_string();
                let detail = v.get("detail").and_then(|d| d.as_str()).unwrap_or("").to_string();
                Some(key(&ts, &action, &detail))
            })
            .map(|k| wanted.contains(k.as_str()))
            .unwrap_or(false);
        if hit {
            removed += 1;
        } else {
            kept.push(line);
        }
    }
    if removed == 0 {
        return 0;
    }
    let body = if kept.is_empty() { String::new() } else { format!("{}\n", kept.join("\n")) };
    let tmp = p.with_extension("jsonl.tmp");
    if fs::write(&tmp, body).is_ok() {
        let _ = fs::rename(&tmp, &p);
    }
    removed
}

fn parse_line(line: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let ts = v.get("ts")?.as_str()?.to_string();
    let action = v.get("action")?.as_str()?.to_string();
    let detail = v.get("detail").and_then(|d| d.as_str()).unwrap_or("").to_string();
    let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
    let src = v.get("src").and_then(|x| x.as_str()).map(str::to_string);
    let actor = v.get("actor").and_then(|x| x.as_str()).map(str::to_string);
    let obj = v.get("obj").and_then(|x| x.as_str()).map(str::to_string);
    Some(Event { ts, action, ok, detail, src, actor, obj })
}

/// 换行会破坏「一行一条」：把控制字符压成空格，再按**字符**截断（不能按字节切，会切碎中文）。
fn one_line(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars * 4));
    for c in s.chars() {
        if c == '\r' || c == '\n' || c == '\t' {
            out.push(' ');
            continue;
        }
        if out.chars().count() >= max_chars {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

fn now_rfc3339() -> String {
    let s = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // 去掉小数秒：记录只要秒级精度，而 ECMAScript 的 `Date` 解析只保证 3 位小数秒
    // （`…:28.9782652Z` 这类 7 位写法在各家引擎里是「能认但不保证」）。
    // 界面上要按本机时区显示它，宁可直接给一个所有引擎都认的形状。
    match (s.find('.'), s.find('Z')) {
        (Some(dot), Some(z)) if dot < z => format!("{}{}", &s[..dot], &s[z..]),
        _ => s,
    }
}

/// 一条可展示的配置变化，对象用于记录页筛选与审计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigChange {
    pub action: &'static str,
    pub detail: String,
    pub obj: Option<String>,
}

impl ConfigChange {
    fn new(action: &'static str, detail: impl Into<String>, obj: impl Into<String>) -> Self {
        Self { action, detail: detail.into(), obj: Some(obj.into()) }
    }
}

/// 一次配置落盘里「用户能看到的变化」。
///
/// 挂在 [`crate::config::save_with_origin`] 上：那条路是**所有**配置改动的唯一出口
/// （界面点按钮、命令行敲参数、导入线路、切方式，全都要经过它）。
/// 在这里记，就不存在「某个入口忘了记」——记录的是真实变化，不是命令声称做过什么。
///
/// `prev = None` 表示首次写配置：此时只报新增的线路，不报「接管方式变成代理」这类默认值。
pub fn record_config_change(
    root: &Path,
    prev: Option<&AppConfig>,
    next: &AppConfig,
    origin: &Origin,
) {
    for change in config_changes(prev, next) {
        let o = origin.clone().with_obj(change.obj.unwrap_or_else(|| "config".to_string()));
        record(root, change.action, true, &change.detail, &o);
    }
}

/// 差异 → 可记录变化。单独抽出来是为了能不落盘就断言措辞。
pub fn config_changes(prev: Option<&AppConfig>, next: &AppConfig) -> Vec<ConfigChange> {
    let mut out: Vec<ConfigChange> = Vec::new();
    let none: Vec<LineConfig> = Vec::new();
    let old_lines: &[LineConfig] = prev.map(|p| p.lines.as_slice()).unwrap_or(&none);

    let added: Vec<&LineConfig> =
        next.lines.iter().filter(|l| !old_lines.iter().any(|o| o.id == l.id)).collect();
    for l in &added {
        out.push(ConfigChange::new(
            IMPORT_LINE,
            format!("{}（{}）", l.name, l.proxy_endpoint),
            format!("line:{}", l.id),
        ));
    }
    for l in old_lines.iter().filter(|o| !next.lines.iter().any(|n| n.id == o.id)) {
        out.push(ConfigChange::new(
            REMOVE_LINE,
            l.name.clone(),
            format!("line:{}", l.id),
        ));
    }
    for l in &next.lines {
        let Some(o) = old_lines.iter().find(|o| o.id == l.id) else { continue };
        if o.name != l.name {
            out.push(ConfigChange::new(
                RENAME_LINE,
                format!("{} → {}", o.name, l.name),
                format!("line:{}", l.id),
            ));
        }
        if o.proxy_endpoint != l.proxy_endpoint {
            out.push(ConfigChange::new(
                EDIT_LINE,
                format!("{} → {}", l.name, l.proxy_endpoint),
                format!("line:{}", l.id),
            ));
        }
        // 比较**生效**的连接方式：`None` 与 `Some(Udp)` 对用户是同一件事（都跑标准连接），
        // 按原文比会报出一条「连接方式 → 标准连接」的假变化。
        if o.effective_transport() != l.effective_transport() {
            out.push(ConfigChange::new(
                TRANSPORT,
                format!("{}：{}", l.name, l.effective_transport().label()),
                format!("line:{}", l.id),
            ));
        }
    }

    // 当前线路：新增的那条上面已经报过「导入线路」，不再重复一条「切换线路」。
    let old_sel = prev.map(|p| p.selected.as_str()).unwrap_or("");
    if old_sel != next.selected {
        if let Some(l) = next.current_line() {
            if !added.iter().any(|a| a.id == l.id) {
                out.push(ConfigChange::new(
                    SELECT_LINE,
                    l.name.clone(),
                    format!("line:{}", l.id),
                ));
            }
        }
    }

    if let Some(p) = prev {
        if p.mode != next.mode {
            out.push(ConfigChange::new(MODE, next.mode.label().to_string(), "mode"));
        }
        if p.exits.daily != next.exits.daily {
            out.push(ConfigChange::new(
                EXIT,
                format!("日常 → {}", next.exits.daily.as_deref().unwrap_or("（缺省）")),
                "exit:daily",
            ));
        }
        if p.exits.trade != next.exits.trade {
            out.push(ConfigChange::new(
                EXIT,
                format!("交易 → {}", next.exits.trade.as_deref().unwrap_or("（缺省）")),
                "exit:trade",
            ));
        }
        for e in &next.split.processes {
            if !p.split.processes.iter().any(|x| x.value() == e.value()) {
                out.push(ConfigChange::new(
                    SPLIT,
                    format!("进程 {} → {}", e.value(), e.target().label()),
                    format!("split:process:{}", e.value()),
                ));
            }
        }
        for e in &p.split.processes {
            if !next.split.processes.iter().any(|x| x.value() == e.value()) {
                out.push(ConfigChange::new(
                    SPLIT,
                    format!("删除进程 {}", e.value()),
                    format!("split:process:{}", e.value()),
                ));
            }
        }
        for e in &next.split.domains {
            if !p.split.domains.iter().any(|x| x.value() == e.value()) {
                out.push(ConfigChange::new(
                    SPLIT,
                    format!("域名 {} → {}", e.value(), e.target().label()),
                    format!("split:domain:{}", e.value()),
                ));
            }
        }
        for e in &p.split.domains {
            if !next.split.domains.iter().any(|x| x.value() == e.value()) {
                out.push(ConfigChange::new(
                    SPLIT,
                    format!("删除域名 {}", e.value()),
                    format!("split:domain:{}", e.value()),
                ));
            }
        }
        // 三个开关：即时生效，也是用户动作，记下来。中文名与界面上的叫法一致。
        for (was, now, label, key) in [
            (p.auto_start, next.auto_start, "开机自动启动", "settings:auto-start"),
            (p.auto_connect, next.auto_connect, "启动后自动连接", "settings:auto-connect"),
            (p.close_to_tray, next.close_to_tray, "关窗缩到托盘", "settings:close-to-tray"),
        ] {
            if was != now {
                out.push(ConfigChange::new(
                    SETTINGS,
                    format!("{} {}", label, if now { "开" } else { "关" }),
                    key,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, SplitTarget, Transport};

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-ev-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn origin() -> Origin {
        Origin { source: Source::Cli, actor: "pid:test".to_string(), obj: None }
    }

    fn cfg_with(lines: &[(&str, &str, &str)], selected: &str) -> AppConfig {
        AppConfig {
            schema: crate::config::SCHEMA,
            mode: Mode::Proxy,
            auto_start: false,
            auto_connect: false,
            close_to_tray: false,
            quality_warning: true,
            auto_trust_first_connection: true,
            selected: selected.to_string(),
            lines: lines
                .iter()
                .map(|(id, name, ep)| LineConfig {
                    id: id.to_string(),
                    name: name.to_string(),
                    proxy_endpoint: ep.to_string(),
                    transport: None,
                    verified_transport: None,
                })
                .collect(),
            agents: Default::default(),
            exits: Default::default(),
            split: Default::default(),
            engine: None,
        }
    }

    #[test]
    fn record_then_read_is_newest_first_and_survives_bad_lines() {
        let root = tmp("read");
        record(&root, CONNECT, true, "线路甲（代理）", &origin());
        record(&root, DISCONNECT, false, "还原失败", &origin());
        // 手写一条坏行：读取不能因为一行坏了就整页空白
        let p = path(&root);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{ not json\n").unwrap();
        drop(f);

        let ev = read(&root, 10);
        assert_eq!(ev.len(), 2, "{ev:?}");
        assert_eq!(ev[0].action, DISCONNECT, "最新的在最前：{ev:?}");
        assert_eq!(ev[0].ok, false);
        assert_eq!(ev[1].action, CONNECT);
        assert!(ev[1].detail.contains("线路甲"));
        assert_eq!(ev[1].src.as_deref(), Some("cli"));
        assert_eq!(ev[1].actor.as_deref(), Some("pid:test"));
        // 时间必须是可被 JS `new Date()` 解析的 RFC3339
        assert!(ev[1].ts.contains('T') && ev[1].ts.len() >= 19, "{}", ev[1].ts);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn one_line_and_truncation_keep_json_valid() {
        let root = tmp("multiline");
        record(&root, "多行", true, "第一行\n第二行\t带制表符", &origin());
        let ev = read(&root, 1);
        assert_eq!(ev[0].detail, "第一行 第二行 带制表符", "换行会破坏一行一条：{}", ev[0].detail);
        // 按字符截断：中文不能被切碎（切碎会让整行 JSON 变非法）
        let long = "中".repeat(400);
        record(&root, "长", true, &long, &origin());
        let ev = read(&root, 1);
        assert!(ev[0].detail.chars().count() <= 301, "{}", ev[0].detail.len());
        assert!(ev[0].detail.ends_with('…'));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_root_never_writes_anything() {
        // 空 root（相对路径造出来的）必须什么都不做：否则记录会落到工作目录里
        record(Path::new(""), CONNECT, true, "x", &origin());
        assert!(!Path::new("logs").join(FILE).exists());
    }

    #[test]
    fn detects_import_select_rename_endpoint_and_transport() {
        let a = cfg_with(&[("L1", "甲", "127.0.0.1:7890")], "L1");
        let mut b = cfg_with(&[("L1", "甲A", "127.0.0.1:7891"), ("L2", "乙", "127.0.0.1:7892")], "L2");
        // 连接方式只对**已有**线路报：新线路的方式是导入的一部分，已经在「导入线路」里了。
        b.lines[0].transport = Some(Transport::Tcp);
        let ch = config_changes(Some(&a), &b);
        let has = |action: &str, needle: &str| {
            ch.iter().any(|c| c.action == action && c.detail.contains(needle))
        };
        assert!(has(IMPORT_LINE, "乙"), "{ch:?}");
        assert!(has(RENAME_LINE, "甲 → 甲A"), "{ch:?}");
        assert!(has(EDIT_LINE, "7891"), "{ch:?}");
        assert!(has(TRANSPORT, "兼容连接"), "{ch:?}");
        assert!(ch.iter().all(|c| c.obj.as_deref().is_some()), "每条变化都要有对象：{ch:?}");
        // 新增的那条同时被选中：不再多报一条「切换线路 → 乙」（导入已经说明了它成为当前线路）
        assert!(!ch.iter().any(|c| c.action == SELECT_LINE), "{ch:?}");
    }

    #[test]
    fn selecting_an_existing_line_is_recorded_as_a_switch() {
        let a = cfg_with(&[("L1", "甲", "127.0.0.1:7890"), ("L2", "乙", "127.0.0.1:7891")], "L1");
        let mut b = a.clone();
        b.selected = "L2".to_string();
        let ch = config_changes(Some(&a), &b);
        assert_eq!(ch.len(), 1, "只该有一条「切换线路」：{ch:?}");
        assert_eq!(ch[0].action, SELECT_LINE);
        assert!(ch[0].detail.contains('乙'), "{ch:?}");
        assert_eq!(ch[0].obj.as_deref(), Some("line:L2"));
    }

    #[test]
    fn first_write_reports_lines_but_not_default_takeover_mode() {
        let b = cfg_with(&[("L1", "甲", "127.0.0.1:7890")], "L1");
        let ch = config_changes(None, &b);
        assert_eq!(ch.len(), 1, "首次落盘只报新增线路：{ch:?}");
        assert_eq!(ch[0].action, IMPORT_LINE);
        assert!(!ch.iter().any(|c| c.action == MODE), "默认的「代理」不是用户改的：{ch:?}");
    }

    #[test]
    fn unchanged_config_produces_no_events() {
        let a = cfg_with(&[("L1", "甲", "127.0.0.1:7890")], "L1");
        assert!(config_changes(Some(&a), &a).is_empty(), "没变化就不许产生记录");
    }

    #[test]
    fn transport_none_and_explicit_udp_are_the_same_to_the_user() {
        let a = cfg_with(&[("L1", "甲", "127.0.0.1:7890")], "L1");
        let mut b = a.clone();
        b.lines[0].transport = Some(Transport::Udp);
        assert!(config_changes(Some(&a), &b).is_empty(), "都跑标准连接，不是变化");
    }

    #[test]
    fn split_and_exit_changes_are_described_in_user_words() {
        let a = cfg_with(&[("L1", "甲", "127.0.0.1:7890")], "L1");
        let mut b = a.clone();
        b.split.add_process("TDXW.exe", SplitTarget::Trade);
        b.exits.daily = Some("provider".to_string());
        let ch = config_changes(Some(&a), &b);
        assert!(ch.iter().any(|c| c.action == SPLIT && c.detail.contains("TDXW.exe") && c.detail.contains("交易出口")), "{ch:?}");
        assert!(ch.iter().any(|c| c.action == EXIT && c.detail.contains("日常")), "{ch:?}");
    }

    #[test]
    fn legacy_records_without_provenance_are_kept_and_parse_as_unknown() {
        let root = tmp("legacy");
        let p = path(&root);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(
            &p,
            "{\"ts\":\"2026-10-29T00:00:00Z\",\"action\":\"连接\",\"ok\":true,\"detail\":\"旧记录\"}\n",
        )
        .unwrap();
        let ev = read(&root, 10);
        assert_eq!(ev.len(), 1, "缺新字段不得丢行：{ev:?}");
        assert!(ev[0].src.is_none() && ev[0].actor.is_none() && ev[0].obj.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trim_keeps_the_newest_tail() {
        let root = tmp("trim");
        let p = path(&root);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        // 造一份超过上限的记录：只要最后几条还在，说明裁掉的是最旧的
        let mut body = String::new();
        for i in 0..9000 {
            body.push_str(&format!(
                "{{\"ts\":\"2026-10-29T00:00:00Z\",\"action\":\"连接\",\"ok\":true,\"detail\":\"第{i}条\"}}\n"
            ));
        }
        fs::write(&p, body).unwrap();
        record(&root, CONNECT, true, "最后一条", &origin());
        let meta = fs::metadata(&p).unwrap();
        assert!(meta.len() <= MAX_BYTES + 4096, "裁剪后仍超限：{}", meta.len());
        let ev = read(&root, 1);
        assert_eq!(ev[0].detail, "最后一条", "最新的必须留下来");
        let _ = fs::remove_dir_all(&root);
    }
    #[test]
    fn hiding_keeps_the_audit_file_and_restore_puts_the_row_back() {
        let root = std::env::temp_dir().join(format!("tc-events-hide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("logs")).unwrap();
        let body = concat!(
            "{\"ts\":\"2026-11-13T02:00:00Z\",\"action\":\"连接\",\"ok\":true,\"detail\":\"甲\"}\n",
            "{\"ts\":\"2026-11-13T01:59:00Z\",\"action\":\"导入\",\"ok\":false,\"detail\":\"乙\"}\n",
        );
        std::fs::write(path(&root), body).unwrap();
        let k = key("2026-11-13T02:00:00Z", "连接", "甲");

        assert_eq!(hide(&root, &[k.clone()]), 1);
        assert_eq!(hide(&root, &[k.clone()]), 0, "已隐藏的不重复计数");
        assert_eq!(
            std::fs::read_to_string(path(&root)).unwrap(),
            body,
            "隐藏不删审计行"
        );
        assert_eq!(read(&root, 10).len(), 2, "隐藏行仍能被读到，只是页面默认不显示");
        assert!(hidden_keys(&root).contains(&k));
        assert_eq!(restore(&root, &[k.clone()]), 1);
        assert_eq!(restore(&root, &[k]), 0);
        assert!(hidden_keys(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_broken_hidden_file_reads_as_empty_instead_of_failing() {
        let root = std::env::temp_dir().join(format!("tc-events-hidden-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("logs").join(HIDDEN_FILE), "{ 不是数组").unwrap();
        assert!(hidden_keys(&root).is_empty(), "坏文件不该让整页记录消失");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removing_selected_rows_keeps_bad_lines() {
        let root = std::env::temp_dir().join(format!("tc-events-remove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("logs")).unwrap();
        let p = path(&root);
        std::fs::write(
            &p,
            concat!(
                "{\"ts\":\"2026-11-13T02:00:00Z\",\"action\":\"连接\",\"ok\":true,\"detail\":\"甲\"}\n",
                "{\"ts\":\"2026-11-13T01:59:00Z\",\"action\":\"导入\",\"ok\":false,\"detail\":\"乙\"}\n",
                "这一行不是 JSON\n"
            ),
        )
        .unwrap();

        let removed = remove(&root, &[key("2026-11-13T02:00:00Z", "连接", "甲")]);
        assert_eq!(removed, 1);
        let left = std::fs::read_to_string(&p).unwrap();
        assert!(left.contains("乙"), "不该删到别的行：{left}");
        assert!(left.contains("这一行不是 JSON"), "解析不了的行必须保留：{left}");
        assert!(!left.contains("甲"), "{left}");
        let _ = std::fs::remove_dir_all(&root);
    }

}
