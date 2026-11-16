//! 服务商接入：读外部代理客户端（Clash Verge / BatVPN）**已落地的配置**，
//! 提取「本机 SOCKS 端口 + 上游节点域名」，登记为独立注册表，
//! 并把对应的 socks 出站与域名直连规则注入当前线路的引擎配置。
//!
//! **本模块没有、也不实现"订阅"**：旧版从不拉取订阅 URL——订阅与节点完全由
//! 外部客户端自己管理（`服务商接入.md:3`）。这里只消费它的产物，节点一个都不进来。
//! 投影形状照旧版的`NodeStore.psm1:954-1005`：出站是 `socks/127.0.0.1:port`，
//! 域名直连是 `dns.rules` 里 `{action:route, domain:[...], server:dns-direct, strategy:prefer_ipv4}`。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const PROVIDERS_FILE: &str = "providers.json";
/// 与旧版的`TradeChannel.Providers.ps1:8` 对齐：域名最多 256 个、档案最多 4 条。
const MAX_DOMAINS: usize = 256;
const MAX_PROVIDERS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provider {
    /// GUID（`D` 格式）。旧版用它做档案主键。
    pub id: String,
    /// 槽位 1–4，决定出站 tag（1=provider，2=provider2…）。
    pub slot: u8,
    pub name: String,
    /// batvpn / clashverge / clash / custom（`clash-verge` 归一化为 `clashverge`）。
    pub kind: String,
    pub directory: String,
    /// 本机 SOCKS 端口（日常）。交易端口缺省复用它。
    pub daily_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trade_port: Option<u16>,
    /// 上游节点域名（完整域名，非 IP）。用途：让这些域名走 dns-direct，避免隧道内解析。
    #[serde(default)]
    pub bootstrap_domains: Vec<String>,
    #[serde(default)]
    pub added_at: String,
}

impl Provider {
    /// 日常出站 tag：slot1=provider，slotN=providerN。交易侧加 `-trade`。
    pub fn daily_tag(&self) -> String {
        if self.slot == 1 { "provider".to_string() } else { format!("provider{}", self.slot) }
    }
    pub fn trade_tag(&self) -> String {
        format!("{}-trade", self.daily_tag())
    }
    pub fn trade_port(&self) -> u16 {
        self.trade_port.unwrap_or(self.daily_port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRegistry {
    pub version: u32,
    #[serde(default)]
    pub providers: Vec<Provider>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        ProviderRegistry { version: 1, providers: Vec::new() }
    }
}

/// 注册表路径：数据根\providers.json。**传入的 root 就是数据根**（`layout.root`），
/// 不要再套一层 `data`——否则文件会落到 `data\data\providers.json`（真机冒烟抓到过）。
pub fn providers_path(root: &Path) -> PathBuf {
    root.join(PROVIDERS_FILE)
}

pub fn load(root: &Path) -> ProviderRegistry {
    let Ok(text) = std::fs::read_to_string(providers_path(root)) else {
        return ProviderRegistry::default();
    };
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .unwrap_or_default()
}

pub fn save(root: &Path, reg: &ProviderRegistry) -> Result<(), String> {
    let path = providers_path(root);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    }
    let text = serde_json::to_string_pretty(reg).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("写入服务商注册表失败：{e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("替换服务商注册表失败：{e}"))?;
    Ok(())
}

/// 「完整域名」校验：不是 IP、不含 URL、不含通配符、不含控制字符。
/// 旧版的`Providers.ps1:69-79`：这些域名要进 dns-direct 规则，写错就把无关域名从 dns-trade 抢走。
fn is_full_domain(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 || s.contains(['/', '*', ' ', '\t']) {
        return false;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // 必须含字母与点（`localhost`、`7895`、纯数字段都不是完整域名）。
    s.contains('.') && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// 客户端目录校验（BUG-601）：必须是**真实存在的盘符绝对目录**，且不能是符号链接/联接点。
/// 依据 旧版的`Providers.ps1:42/:49`（绝对路径、必须存在、无 reparse）——
/// 不校验的后果是注册表里存下用户看不见的假路径，且重复登记会白占 4 个槽位。
fn validate_directory(directory: &str) -> Result<(), String> {
    let s = directory.trim();
    if s.is_empty() {
        return Err("请提供客户端的本机安装目录".to_string());
    }
    let path = Path::new(s);
    // 只接受盘符绝对路径；相对路径、UNC 网络路径都拒绝（"本机目录"）。
    match path.components().next() {
        Some(std::path::Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_)) => {}
        _ => return Err(format!("请提供客户端的本机绝对目录（例如 C:\\...，收到：{s}）")),
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| format!("客户端的安装目录不存在：{s}"))?;
    // 顺序要紧：**先查 reparse 再查 is_dir**。目录联接点（mklink /J）在 symlink_metadata
    // 眼里不是目录，先查 is_dir 会把它报成「不是目录」——用户看着那是个普通目录，文案会让人困惑。
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("安装目录不能是符号链接或联接点：{s}"));
    }
    if !meta.is_dir() {
        return Err(format!("这个路径不是目录：{s}"));
    }
    Ok(())
}

pub fn validate(p: &Provider) -> Result<(), String> {
    if p.slot == 0 || p.slot as usize > MAX_PROVIDERS {
        return Err(format!("槽位只能是 1–{MAX_PROVIDERS}（收到：{}）", p.slot));
    }
    if p.name.trim().is_empty() || p.name.chars().any(|c| c.is_control()) {
        return Err("名称不能为空且不能含控制字符".to_string());
    }
    if p.name.trim().chars().count() > 48 {
        return Err(format!("名称最多 48 个字符（收到：{}）", p.name.trim().chars().count()));
    }
    if p.daily_port == 0 {
        return Err("本机 SOCKS 端口不能为空".to_string());
    }
    if !["batvpn", "clashverge", "clash", "custom"].contains(&p.kind.as_str()) {
        return Err(format!("kind 只能是 batvpn/clashverge/clash/custom（收到：{}）", p.kind));
    }
    validate_directory(&p.directory)?;
    if p.bootstrap_domains.len() > MAX_DOMAINS {
        return Err(format!("上游域名最多 {MAX_DOMAINS} 个（收到：{}）", p.bootstrap_domains.len()));
    }
    for d in &p.bootstrap_domains {
        if !is_full_domain(d) {
            return Err(format!("上游域名必须是完整域名（不能是 IP、URL 或通配符）：{d}"));
        }
    }
    Ok(())
}

/// `clash-verge` 归一化为 `clashverge`（旧版的`Providers.ps1:96-98`）。
pub fn normalize_kind(s: &str) -> String {
    match s.trim() {
        "clash-verge" => "clashverge".to_string(),
        other => other.to_string(),
    }
}

/// 当前时间的 RFC3339（UTC），`added_at` 用。
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// GUID v4（D 格式）。没有 uuid 依赖，用 RandomState 的随机种子 + 时间戳拼一个合法形状。
pub fn new_guid() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let s = std::collections::hash_map::RandomState::new();
    let r1 = { let mut h = s.build_hasher(); h.write_u128(nanos); h.finish() };
    let r2 = { let mut h = s.build_hasher(); h.write_u64((nanos as u64) ^ 0x9e3779b9); h.finish() };
    let ver = ((r1 >> 12) & 0x0fff) | 0x4000; // version 4
    let var = (r2 & 0x3fff) | 0x8000; // variant 10xx
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (nanos & 0xffff_ffff) as u32,
        (r1 & 0xffff) as u16,
        ver as u16,
        var as u16,
        r2 & 0xffff_ffff_ffff
    )
}

/// 一次发现的结果（只读，不落盘）。
#[derive(Debug, Clone, PartialEq)]
pub struct Discovered {
    pub kind: String,
    pub directory: String,
    pub daily_port: u16,
    pub bootstrap_domains: Vec<String>,
    /// 说明用了哪个入口（托管 listener / mixed-port），给 `--provider-discover` 打印用。
    pub entry_note: String,
}

/// 旧版在 Clash Verge 的 Merge.yaml 里准备好的独立入口（`ProviderSetup.ps1:185-189`）。
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedListener {
    pub port: u16,
    pub proxy: String,
}

/// 只认托管块（标记对之间）的内容：块外的 `listeners` 是用户自己的，不能碰。
/// 标记容错：`# >>> TradeChannel` / `# <<< TradeChannel`（旧版的完整形式也以它开头）。
fn extract_managed_block(text: &str) -> Option<String> {
    let mut inside = false;
    let mut out = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("# >>> TradeChannel") {
            inside = true;
            continue;
        }
        if t.starts_with("# <<< TradeChannel") {
            inside = false;
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out.trim().is_empty() { None } else { Some(out) }
}

/// 读 Merge.yaml 里 `tradechannel-trade` 监听器的端口与代理组。
/// 不存在 / 没有托管块 / 解析失败 → None（调用方退回客户端的 mixed-port）。
/// 入口说明：这条服务商现在到底走哪个本机入口（给界面列表与 discover 共用一句话）。
///
/// Clash Verge 优先认 旧版准备好的独立 listener（Merge.yaml 托管块），没有才退 mixed-port；
/// BatVPN 固定是它自己的 SOCKS 入站。措辞只写这一处，两处各写一遍必然长出两种说法。
pub fn entry_note_for(kind: &str, directory: &str, daily_port: u16) -> String {
    if matches!(kind, "clashverge" | "clash") {
        let merge = Path::new(directory).join("profiles").join("Merge.yaml");
        if let Some(l) = managed_listener(&merge) {
            return format!(
                "使用 TradeChannel 管理的独立入口 127.0.0.1:{}（proxy={}）",
                l.port, l.proxy
            );
        }
        return format!("使用客户端混合端口 {daily_port}");
    }
    if kind == "batvpn" {
        return format!("使用 BatVPN 的 SOCKS 入站 {daily_port}");
    }
    format!("使用客户端端口 {daily_port}")
}

/// 已登记服务商的入口说明（界面每一行都要显示"当前用 7895 独立入口"）。
pub fn entry_note(p: &Provider) -> String {
    entry_note_for(&p.kind, &p.directory, p.daily_port)
}

pub fn managed_listener(merge_path: &Path) -> Option<ManagedListener> {
    let text = std::fs::read_to_string(merge_path).ok()?;
    let block = extract_managed_block(&text)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&block).ok()?;
    for l in doc.get("listeners")?.as_sequence()? {
        if l.get("name").and_then(|v| v.as_str()) == Some("tradechannel-trade") {
            let port = u16::try_from(l.get("port")?.as_u64()?).ok()?;
            let proxy = l
                .get("proxy")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            return Some(ManagedListener { port, proxy });
        }
    }
    None
}

fn appdata() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

/// 从 Clash 的 `proxies` 列表里取**域名**（IP 丢弃）——旧版的`ProviderSetup.ps1:165-166`。
fn domains_from_clash_proxies(doc: &serde_yaml::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(proxies) = doc.get("proxies").and_then(|v| v.as_sequence()) {
        for p in proxies {
            if let Some(server) = p.get("server").and_then(|v| v.as_str()) {
                let s = server.trim().to_string();
                if is_full_domain(&s) {
                    out.insert(s);
                }
            }
        }
    }
    out
}

/// 读 Clash Verge 生效配置。**`config.yaml` 不是生效配置**（旧版注释），只认 `clash-verge.yaml`。
/// `proxy-providers`（订阅池直连）模式直接拒绝——上游域名无法完整静态确认（`ProviderSetup.ps1:167`）。
pub fn discover_clash_verge() -> Result<Discovered, String> {
    let base = appdata()
        .map(|a| a.join("io.github.clash-verge-rev.clash-verge-rev"))
        .ok_or("读不到 APPDATA")?;
    let cfg = base.join("clash-verge.yaml");
    if !cfg.exists() {
        return Err(format!(
            "尚未找到 Clash Verge 的生效配置（{}）。请先安装并完成一次订阅导入，再点击自动发现。",
            cfg.display()
        ));
    }
    let text = std::fs::read_to_string(&cfg).map_err(|e| format!("读不到 clash-verge.yaml：{e}"))?;
    let mut d = parse_clash_verge(&text, base.to_string_lossy().to_string())?;
    // 【卡 2】优先用 旧版在 Merge.yaml 里准备好的独立入口（`tradechannel-trade` listener）：
    // 它单独指向客户端的「节点选择」组，与客户端自己的 mixed-port 分离——交易流量不会被别的规则分走。
    // 没有托管块（新机器 / 没跑过自动准备）才退回 mixed-port。
    let merge = base.join("profiles").join("Merge.yaml");
    if let Some(l) = managed_listener(&merge) {
        d.daily_port = l.port;
    }
    d.entry_note = entry_note_for(&d.kind, &d.directory, d.daily_port);
    Ok(d)
}

/// 独立出来便于单测：从 YAML 文本提取。
pub fn parse_clash_verge(text: &str, directory: String) -> Result<Discovered, String> {
    // 解析失败（含 alias / tag / 非法结构）一律 fail-closed——旧版自研解析器也是这个姿态。
    let doc: serde_yaml::Value = serde_yaml::from_str(text)
        .map_err(|e| format!("clash-verge.yaml 解析失败（含别名/标签等不受支持的写法时按不受支持处理）：{e}"))?;
    if doc.get("proxy-providers").is_some() {
        return Err(
            "该配置使用 proxy-providers（订阅池直连）：上游节点域名无法完整静态确认，本版不自动登记。"
                .to_string(),
        );
    }
    // 端口：mixed-port 优先，其次 socks-port、port（旧版的取值顺序）。
    let port = doc
        .get("mixed-port")
        .or_else(|| doc.get("socks-port"))
        .or_else(|| doc.get("port"))
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .ok_or("未找到本机 SOCKS/混合端口（mixed-port / socks-port / port）")?;
    if port == 0 {
        return Err("本机 SOCKS 端口为 0，无效".to_string());
    }
    let domains: Vec<String> = domains_from_clash_proxies(&doc).into_iter().collect();
    if domains.is_empty() {
        return Err(
            "尚未完整识别客户端的上游节点域名。请先导入并加载订阅后重新检测".to_string(),
        );
    }
    Ok(Discovered {
        kind: "clashverge".to_string(),
        directory,
        daily_port: port,
        bootstrap_domains: domains,
        entry_note: String::new(), // 由 discover_clash_verge 决定实际入口后填
    })
}

/// BatVPN：`%APPDATA%\BatVPN\config.json`，取唯一 noauth SOCKS inbound 端口 +
/// `outbounds[].settings.vnext[].address` / `settings.servers[].address` 里非 IP 的域名。
pub fn discover_batvpn() -> Result<Discovered, String> {
    let base = appdata().map(|a| a.join("BatVPN")).ok_or("读不到 APPDATA")?;
    let cfg = base.join("config.json");
    if !cfg.exists() {
        return Err(format!("尚未找到 BatVPN 配置（{}）", cfg.display()));
    }
    let text = std::fs::read_to_string(&cfg).map_err(|e| format!("读不到 BatVPN config.json：{e}"))?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| format!("BatVPN config.json 不是合法 JSON：{e}"))?;
    // 唯一 noauth SOCKS inbound 端口。
    let mut port: Option<u16> = None;
    if let Some(inbounds) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for ib in inbounds {
            let is_socks = ib.get("protocol").and_then(|v| v.as_str()) == Some("socks");
            let noauth = ib
                .get("settings")
                .and_then(|s| s.get("auth"))
                .and_then(|a| a.as_str())
                .map(|a| a == "noauth")
                .unwrap_or(true);
            if is_socks && noauth {
                let p = ib.get("port").and_then(|v| v.as_u64()).and_then(|x| u16::try_from(x).ok());
                if port.is_some() {
                    return Err("BatVPN 有多个 noauth SOCKS 入站，无法确定唯一端口".to_string());
                }
                port = p;
            }
        }
    }
    let port = port.ok_or("BatVPN 没有可用的 noauth SOCKS 入站端口")?;
    let mut domains = BTreeSet::new();
    if let Some(outbounds) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for ob in outbounds {
            for key in ["vnext", "servers"] {
                if let Some(list) = ob.get("settings").and_then(|s| s.get(key)).and_then(|v| v.as_array()) {
                    for node in list {
                        if let Some(addr) = node.get("address").and_then(|v| v.as_str()) {
                            let s = addr.trim().to_string();
                            if is_full_domain(&s) {
                                domains.insert(s);
                            }
                        }
                    }
                }
            }
        }
    }
    if domains.is_empty() {
        return Err("尚未完整识别客户端的上游节点域名。请先导入并加载订阅后重新检测".to_string());
    }
    Ok(Discovered {
        kind: "batvpn".to_string(),
        directory: base.to_string_lossy().to_string(),
        daily_port: port,
        bootstrap_domains: domains.into_iter().collect(),
        entry_note: format!("使用 BatVPN 的 SOCKS 入站 {}", port),
    })
}

// ---------------------------------------------------------------------------
// 线路文件投影（旧版NodeStore.psm1:954-1005 的形状）
// ---------------------------------------------------------------------------

fn socks_outbound(tag: &str, port: u16) -> Value {
    json!({
        "type": "socks",
        "tag": tag,
        "server": "127.0.0.1",
        "server_port": port,
        "version": "5",
        "network": "tcp",
    })
}

/// 更新或插入一条 socks 出站（按 tag）。已存在且端口一致 → 不动。
fn upsert_socks_outbound(
    outbounds: &mut Vec<Value>,
    tag: &str,
    port: u16,
) -> bool {
    for ob in outbounds.iter_mut() {
        if ob.get("tag").and_then(Value::as_str) == Some(tag) {
            let old_port = ob.get("server_port").and_then(Value::as_u64);
            if old_port == Some(port as u64)
                && ob.get("type").and_then(Value::as_str) == Some("socks")
            {
                return false;
            }
            *ob = socks_outbound(tag, port);
            return true;
        }
    }
    outbounds.push(socks_outbound(tag, port));
    true
}

/// 确保 selector 的 outbounds（members）含某个 tag。没有该选择器就跳过（老线路不强加）。
fn ensure_member(obj: &mut serde_json::Map<String, Value>, selector_tag: &str, member: &str) -> bool {
    let Some(outbounds) = obj.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return false;
    };
    for ob in outbounds.iter_mut() {
        if ob.get("tag").and_then(Value::as_str) == Some(selector_tag)
            && ob.get("type").and_then(Value::as_str) == Some("selector")
        {
            let Some(members) = ob.get_mut("outbounds").and_then(Value::as_array_mut) else {
                return false;
            };
            if members.iter().any(|m| m.as_str() == Some(member)) {
                return false;
            }
            members.push(json!(member));
            return true;
        }
    }
    false
}

/// 维护 dns.rules 里的「上游域名走 dns-direct」规则。
/// 形状照旧版：`{action:"route", domain:[...], server:"dns-direct", strategy:"prefer_ipv4"}`。
/// 位置：`clash_mode:"global"` 那条之后（旧版的顺序），没有就插最前。
fn apply_dns_direct_rule(obj: &mut serde_json::Map<String, Value>, domains: &BTreeSet<String>) -> bool {
    let domain_list: Vec<String> = domains.iter().cloned().collect();
    let rule = json!({
        "action": "route",
        "domain": domain_list,
        "server": "dns-direct",
        "strategy": "prefer_ipv4",
    });
    let Some(dns) = obj.get_mut("dns").and_then(Value::as_object_mut) else {
        return false;
    };
    let rules = dns.entry("rules".to_string()).or_insert_with(|| Value::Array(Vec::new()));
    let Some(list) = rules.as_array_mut() else { return false };
    // 找既有直连域名规则：server=dns-direct 且带 domain 字段（strategy=prefer_ipv4）。
    let pos = list.iter().position(|r| {
        r.get("server").and_then(Value::as_str) == Some("dns-direct")
            && r.get("domain").is_some()
    });
    match pos {
        Some(i) => {
            if list[i] == rule {
                return false;
            }
            list[i] = rule;
            true
        }
        None => {
            if domain_list.is_empty() {
                return false; // 没有域名就不加规则（别把空数组写进去）
            }
            let global_pos = list.iter().position(|r| {
                r.get("clash_mode").and_then(Value::as_str) == Some("global")
            });
            let idx = global_pos.map(|i| i + 1).unwrap_or(0);
            list.insert(idx, rule);
            true
        }
    }
}

/// 把当前注册表投影到线路引擎配置：**只 upsert 已登记的槽位**。
/// 空注册表直接返回 false（绝不在用户没登记时动他的线路文件——旧版预置的槽位保持原样）。
/// 返回"是否有变化"。
pub fn apply_to_line(line_path: &Path, reg: &ProviderRegistry) -> Result<bool, String> {
    if reg.providers.is_empty() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(line_path)
        .map_err(|e| format!("读线路引擎配置失败（{}）：{e}", line_path.display()))?;
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON：{e}"))?;
    let Some(obj) = root.as_object_mut() else {
        return Err("线路引擎配置顶层不是对象".to_string());
    };
    let mut changed = false;
    {
        let outbounds = obj
            .entry("outbounds".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(list) = outbounds.as_array_mut() else {
            return Err("线路 outbounds 不是数组".to_string());
        };
        for p in &reg.providers {
            changed |= upsert_socks_outbound(list, &p.daily_tag(), p.daily_port);
            changed |= upsert_socks_outbound(list, &p.trade_tag(), p.trade_port());
        }
    }
    for p in &reg.providers {
        changed |= ensure_member(obj, "daily-exit", &p.daily_tag());
        changed |= ensure_member(obj, "trade-exit", &p.trade_tag());
    }
    let domains: BTreeSet<String> = reg
        .providers
        .iter()
        .flat_map(|p| p.bootstrap_domains.iter().cloned())
        .collect();
    changed |= apply_dns_direct_rule(obj, &domains);
    if changed {
        let text = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
        let tmp = line_path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写入线路配置失败：{e}"))?;
        std::fs::rename(&tmp, line_path).map_err(|e| format!("替换线路配置失败：{e}"))?;
    }
    Ok(changed)
}

/// 删除某个槽位：移除它的两条出站、从两个选择器 members 摘掉、
/// 并把 dns 直连域名重算为"剩余 provider 的并集"。
pub fn remove_from_line(line_path: &Path, slot: u8, reg: &ProviderRegistry) -> Result<bool, String> {
    let daily_tag = if slot == 1 { "provider".to_string() } else { format!("provider{slot}") };
    let trade_tag = format!("{daily_tag}-trade");
    let text = std::fs::read_to_string(line_path)
        .map_err(|e| format!("读线路引擎配置失败：{e}"))?;
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON：{e}"))?;
    let Some(obj) = root.as_object_mut() else {
        return Err("线路引擎配置顶层不是对象".to_string());
    };
    let mut changed = false;
    if let Some(outbounds) = obj.get_mut("outbounds").and_then(Value::as_array_mut) {
        let before = outbounds.len();
        outbounds.retain(|ob| {
            let tag = ob.get("tag").and_then(Value::as_str).unwrap_or("");
            tag != daily_tag && tag != trade_tag
        });
        changed |= outbounds.len() != before;
        // 从选择器 members 摘掉（若成员里还有其他 provider 槽位则保留）。
        for ob in outbounds.iter_mut() {
            if ob.get("type").and_then(Value::as_str) == Some("selector") {
                if let Some(members) = ob.get_mut("outbounds").and_then(Value::as_array_mut) {
                    let mb = members.len();
                    members.retain(|m| {
                        let s = m.as_str().unwrap_or("");
                        s != daily_tag && s != trade_tag
                    });
                    changed |= members.len() != mb;
                }
            }
        }
    }
    let domains: BTreeSet<String> = reg
        .providers
        .iter()
        .flat_map(|p| p.bootstrap_domains.iter().cloned())
        .collect();
    changed |= apply_dns_direct_rule(obj, &domains);
    if changed {
        let text = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
        let tmp = line_path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写入线路配置失败：{e}"))?;
        std::fs::rename(&tmp, line_path).map_err(|e| format!("替换线路配置失败：{e}"))?;
    }
    Ok(changed)
}

/// 一次登记的输入（CLI 的位置参数 / 界面的表单，最后都收成这一份）。
pub struct RegisterInput {
    pub kind: String,
    pub name: String,
    pub directory: String,
    pub daily_port: u16,
    pub bootstrap_domains: Vec<String>,
}

/// 登记一条服务商：查重 → 找空槽位 → 校验 → 投影到线路 → 写注册表。
///
/// **这是唯一一条登记路径**，命令行 `--provider-add` 与界面 `provider-add` 都走它：
/// 两条入口各写一遍，迟早点出两种校验顺序和两套错误文案（D8 的教训）。
/// 任何一步失败都**零副作用**：注册表不写；投影失败时线路文件也不会被改成半截。
#[cfg(test)]
pub fn register(root: &Path, line_path: &Path, input: RegisterInput) -> Result<Provider, String> {
    register_with_origin(root, line_path, input, &crate::events::Origin::other())
}

pub fn register_with_origin(
    root: &Path,
    line_path: &Path,
    input: RegisterInput,
    origin: &crate::events::Origin,
) -> Result<Provider, String> {
    let mut reg = load(root);
    // 同一安装目录不能重复登记：Windows 路径不分大小写，否则 4 个槽位会被同一个客户端白占。
    if let Some(dup) = reg
        .providers
        .iter()
        .find(|p| p.directory.eq_ignore_ascii_case(input.directory.trim()))
    {
        return Err(format!(
            "该安装目录已经登记过了（槽位 {}：{}），请先 --provider-remove 或改登记别的目录",
            dup.slot, dup.name
        ));
    }
    let Some(slot) = (1u8..=MAX_PROVIDERS as u8).find(|s| !reg.providers.iter().any(|p| p.slot == *s))
    else {
        return Err(format!("服务商最多 {MAX_PROVIDERS} 条，请先 --provider-remove 删除一条"));
    };
    let p = Provider {
        id: new_guid(),
        slot,
        name: input.name,
        kind: input.kind,
        directory: input.directory,
        daily_port: input.daily_port,
        trade_port: None,
        bootstrap_domains: input.bootstrap_domains,
        added_at: now_rfc3339(),
    };
    validate(&p)?;
    reg.providers.push(p.clone());
    // 先投影到线路文件，成功才写注册表——投影失败必须零副作用。
    if let Err(e) = apply_to_line(line_path, &reg) {
        return Err(format!("投影到线路配置失败：{e}"));
    }
    save(root, &reg)?;
    // 记在**成功之后**：投影或写注册表失败时什么都没登记，记一条「已登记」会让记录与事实不符。
    crate::events::record(
        root,
        crate::events::PROVIDER_ADD,
        true,
        &format!("{}（{}，端口 {}）", p.name, p.kind, p.daily_port),
        &origin.clone().with_obj(format!("provider:{}", p.slot)),
    );
    Ok(p)
}

/// 删除一条服务商：先从线路配置摘掉对应出站，再写注册表（顺序与登记相反，失败时注册表仍是旧事实）。
#[cfg(test)]
pub fn unregister(root: &Path, line_path: Option<&Path>, slot: u8) -> Result<(), String> {
    unregister_with_origin(root, line_path, slot, &crate::events::Origin::other())
}

pub fn unregister_with_origin(
    root: &Path,
    line_path: Option<&Path>,
    slot: u8,
    origin: &crate::events::Origin,
) -> Result<(), String> {
    let mut reg = load(root);
    let before = reg.providers.len();
    // 名字要在删除前取：记录里写「槽位 2」不如写用户认得的名字。
    let name = reg.providers.iter().find(|p| p.slot == slot).map(|p| p.name.clone());
    reg.providers.retain(|p| p.slot != slot);
    if reg.providers.len() == before {
        return Err(format!("槽位 {slot} 没有已登记的服务商"));
    }
    if let Some(line_path) = line_path {
        if let Err(e) = remove_from_line(line_path, slot, &reg) {
            return Err(format!("从线路配置移除失败：{e}"));
        }
    }
    save(root, &reg)?;
    crate::events::record(
        root,
        crate::events::PROVIDER_REMOVE,
        true,
        &format!("{}（槽位 {slot}）", name.unwrap_or_else(|| "未命名".to_string())),
        &origin.clone().with_obj(format!("provider:{slot}")),
    );
    Ok(())
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-prov-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 一份最小可投影的线路引擎配置（apply_to_line 只要求 outbounds 是数组）。
    fn line(root: &Path) -> PathBuf {
        let p = root.join("line.json");
        std::fs::write(
            &p,
            r#"{"outbounds":[{"type":"direct","tag":"direct"},
                 {"type":"selector","tag":"trade-exit","outbounds":["direct"],"default":"direct"}],
               "route":{"rules":[],"final":"direct"}}"#,
        )
        .unwrap();
        p
    }

    /// 登记要求安装目录真实存在（`validate_directory`），所以每个输入先在临时根下建出来。
    fn input(root: &Path, name: &str, sub: &str, port: u16) -> RegisterInput {
        let dir = root.join(sub);
        std::fs::create_dir_all(&dir).unwrap();
        RegisterInput {
            kind: "clashverge".into(),
            name: name.into(),
            directory: dir.to_string_lossy().to_string(),
            daily_port: port,
            bootstrap_domains: vec!["a.example.com".into()],
        }
    }

    #[test]
    fn register_allocates_the_lowest_free_slot_and_projects_to_the_line() {
        let root = tmp("add");
        let line_path = line(&root);
        let p = register(&root, &line_path, input(&root, "甲", "A", 7890)).unwrap();
        assert_eq!(p.slot, 1, "第一条占槽位 1");
        assert_eq!(p.daily_tag(), "provider");
        // 投影真的写进了线路文件（界面按钮「设为日常出口」靠的就是这个 tag）
        let text = std::fs::read_to_string(&line_path).unwrap();
        assert!(text.contains("provider"), "socks 出站要写进线路：{text}");
        assert!(text.contains("127.0.0.1"), "{text}");
        // 注册表落了盘，且第二条拿槽位 2
        let p2 = register(&root, &line_path, input(&root, "乙", "B", 7891)).unwrap();
        assert_eq!(p2.slot, 2);
        assert_eq!(load(&root).providers.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn register_refuses_a_duplicate_directory_case_insensitively() {
        // Windows 路径不分大小写：同一个客户端占两个槽位就是白占。
        let root = tmp("dup");
        let line_path = line(&root);
        register(&root, &line_path, input(&root, "甲", "Clash", 7890)).unwrap();
        let mut again = input(&root, "甲2", "Clash", 7891);
        again.directory = again.directory.to_uppercase(); // 只改大小写，仍指向同一目录
        let e = register(&root, &line_path, again).unwrap_err();
        assert!(e.contains("已经登记过了"), "{e}");
        assert_eq!(load(&root).providers.len(), 1, "拒绝必须零副作用");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn register_refuses_the_fifth_slot_and_invalid_input_without_side_effects() {
        let root = tmp("max");
        let line_path = line(&root);
        for (i, port) in [7890u16, 7891, 7892, 7893].iter().enumerate() {
            let sub = format!("D{i}");
            register(&root, &line_path, input(&root, &format!("p{i}"), &sub, *port)).unwrap();
        }
        let e = register(&root, &line_path, input(&root, "p5", "D5", 7894)).unwrap_err();
        assert!(e.contains("最多"), "{e}");
        assert_eq!(load(&root).providers.len(), 4);
        // 非法域名：校验拦住，注册表不变
        let mut bad = input(&root, "p6", "D6", 7895);
        bad.bootstrap_domains = vec!["http://x".into()];
        assert!(register(&root, &line_path, bad).is_err());
        assert_eq!(load(&root).providers.len(), 4);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unregister_removes_the_outbound_and_reports_an_empty_slot() {
        // 目录名必须与 `provider::tests` 里的「删除槽位」用例区分开：
        // 两边都叫 `tcrs-prov-rm-<pid>` 时，并行跑会互相删对方的目录，
        // 表现是 `fs::write` 报「拒绝访问（os error 5）」——与被测逻辑毫无关系。
        let root = tmp("unreg");
        let line_path = line(&root);
        register(&root, &line_path, input(&root, "甲", "A", 7890)).unwrap();
        unregister(&root, Some(&line_path), 1).unwrap();
        assert!(load(&root).providers.is_empty());
        let text = std::fs::read_to_string(&line_path).unwrap();
        assert!(!text.contains(r#""tag": "provider""#), "出站要跟着摘掉：{text}");
        let e = unregister(&root, Some(&line_path), 1).unwrap_err();
        assert!(e.contains("没有已登记的服务商"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn entry_note_prefers_the_managed_listener_when_the_block_exists() {
        let root = tmp("entry");
        // 没有 Merge.yaml → 退回客户端混合端口
        assert_eq!(
            entry_note_for("clashverge", root.to_string_lossy().as_ref(), 7890),
            "使用客户端混合端口 7890"
        );
        // 有托管块 → 独立入口（界面要能显示"当前用 7895 独立入口"）
        std::fs::create_dir_all(root.join("profiles")).unwrap();
        std::fs::write(
            root.join("profiles").join("Merge.yaml"),
            r#"# >>> TradeChannel managed block >>>"#
                .to_string()
                + "\nlisteners:\n  - name: tradechannel-trade\n    port: 7895\n    proxy: \"节点选择\"\n# <<< TradeChannel <<<\n",
        )
        .unwrap();
        let note = entry_note_for("clashverge", root.to_string_lossy().as_ref(), 7890);
        assert!(note.contains("127.0.0.1:7895"), "{note}");
        assert!(note.contains("节点选择"), "{note}");
        // BatVPN 固定是自己的 SOCKS 入站
        assert_eq!(entry_note_for("batvpn", "x", 1080), "使用 BatVPN 的 SOCKS 入站 1080");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(slot: u8, port: u16, domains: &[&str]) -> Provider {
        Provider {
            id: "00000000-0000-0000-0000-000000000000".to_string(),
            slot,
            name: format!("P{slot}"),
            kind: "clashverge".to_string(),
            directory: "C:\\x".to_string(),
            daily_port: port,
            trade_port: None,
            bootstrap_domains: domains.iter().map(|s| s.to_string()).collect(),
            added_at: String::new(),
        }
    }

    fn line_json() -> Value {
        json!({
            "outbounds": [
                {"type":"selector","tag":"daily-exit","outbounds":["direct","provider","provider2","provider3","provider4"],"default":"direct"},
                {"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"},
                {"type":"direct","tag":"direct"}
            ],
            "dns": {
                "servers":[{"tag":"dns-direct","type":"udp","server":"192.168.1.1"}],
                "rules":[{"action":"route","clash_mode":"global","server":"dns-trade","strategy":"ipv4_only"}]
            }
        })
    }

    fn write_line(root: &Path) -> PathBuf {
        let p = root.join("line.json");
        std::fs::write(&p, serde_json::to_string_pretty(&line_json()).unwrap()).unwrap();
        p
    }

    #[test]
    fn providers_path_is_inside_data_root_not_nested() {
        // 真机冒烟抓到的回归：layout.root 已经是数据根，再套一层 data 会落进 data\data。
        let root = PathBuf::from(r"C:\SpiderVPN\data");
        let p = providers_path(&root);
        assert_eq!(p, PathBuf::from(r"C:\SpiderVPN\data\providers.json"));
        assert!(!p.to_string_lossy().replace('/', "\\").contains("data\\data"), "不得多套一层 data：{p:?}");
    }

    #[test]
    fn managed_block_is_extracted_and_listener_read() {
        let text = r#"# Profile Enhancement Merge Template
profile:
  store-selected: true
# >>> TradeChannel managed block (do not edit by hand) >>>
sniffer:
  enable: true
listeners:
  - name: tradechannel-trade
    type: socks
    port: 7895
    listen: 127.0.0.1
    users: []
    udp: true
    proxy: "节点选择"
# <<< TradeChannel managed block <<<
"#;
        let block = extract_managed_block(text).expect("应有托管块");
        assert!(block.contains("7895"));
        assert!(!block.contains("store-selected"), "块外内容不得混进来");
        let root = std::env::temp_dir().join(format!("tcrs-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Merge.yaml");
        std::fs::write(&p, text).unwrap();
        let l = managed_listener(&p).expect("应读到 listener");
        assert_eq!(l.port, 7895);
        assert_eq!(l.proxy, "节点选择");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn managed_listener_absent_returns_none() {
        let root = std::env::temp_dir().join(format!("tcrs-merge-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Merge.yaml");
        // 没有托管块：块外的 listeners 是用户自己的，绝不能当我们的入口。
        std::fs::write(&p, "listeners:\n  - name: mine\n    port: 1111\n").unwrap();
        assert!(managed_listener(&p).is_none(), "块外 listeners 不算数");
        // 文件不存在也 None。
        assert!(managed_listener(&root.join("nope.yaml")).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn full_domain_rules() {
        assert!(is_full_domain("a.example.com"));
        assert!(!is_full_domain("1.2.3.4"));
        assert!(!is_full_domain("http://a.com"));
        assert!(!is_full_domain("*.example.com"));
        assert!(!is_full_domain("localhost"));
        assert!(!is_full_domain(""));
    }

    /// 一个真实存在的临时目录（validate 现在要求目录存在，纯字符串夹具不够用了）。
    fn real_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("tcrs-val-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    #[test]
    fn validate_rejects_bad_domains_and_slots() {
        let mut p = provider(1, 7895, &["1.2.3.4"]);
        p.directory = real_dir("bad-domain");
        assert!(validate(&p).unwrap_err().contains("完整域名"));
        p = provider(5, 7895, &[]);
        assert!(validate(&p).unwrap_err().contains("槽位"));
        p = provider(1, 7895, &["a.example.com"]);
        p.directory = real_dir("ok-domain");
        assert!(validate(&p).is_ok());
    }

    /// BUG-601 回归钉子：目录不存在 / 相对路径 / 指向文件 / 名称超长，四种都必须被拒。
    #[test]
    fn directory_validation_rejects_bad_paths() {
        let real = real_dir("dir-ok");
        let mut p = provider(1, 7895, &["a.example.com"]);
        p.directory = real.clone();
        assert!(validate(&p).is_ok(), "真实目录应通过");

        p.directory = "relative-dir".to_string();
        assert!(validate(&p).unwrap_err().contains("绝对目录"), "{:?}", validate(&p));

        p.directory = r"C:\definitely-not-exist-0f3a".to_string();
        assert!(validate(&p).unwrap_err().contains("不存在"));

        let f = Path::new(&real).join("f.txt");
        std::fs::write(&f, b"x").unwrap();
        p.directory = f.to_string_lossy().to_string();
        assert!(validate(&p).unwrap_err().contains("不是目录"));

        p.directory = real;
        p.name = "名".repeat(49);
        assert!(validate(&p).unwrap_err().contains("48"));
    }

    #[test]
    fn clash_verge_yaml_extracts_port_and_domains() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - {name: A, server: node1.example.com, port: 443}
  - {name: B, server: 1.2.3.4, port: 443}
  - {name: C, server: node2.example.com, port: 443}
"#;
        let d = parse_clash_verge(yaml, "C:\\cv".to_string()).unwrap();
        assert_eq!(d.daily_port, 7890);
        assert_eq!(d.bootstrap_domains, vec!["node1.example.com", "node2.example.com"]);
    }

    #[test]
    fn proxy_providers_mode_is_refused() {
        let yaml = "mixed-port: 7890\nproxy-providers:\n  p1: {type: http, url: 'http://x'}\nproxies:\n  - {name: A, server: a.example.com}\n";
        let err = parse_clash_verge(yaml, "C:\\cv".to_string()).unwrap_err();
        assert!(err.contains("proxy-providers"), "{err}");
    }

    #[test]
    fn clash_without_domains_is_refused() {
        let yaml = "mixed-port: 7890\nproxies:\n  - {name: A, server: 1.2.3.4}\n";
        assert!(parse_clash_verge(yaml, "C:\\cv".to_string()).is_err());
    }

    #[test]
    fn apply_injects_outbounds_members_and_dns_rule() {
        let root = std::env::temp_dir().join(format!("tcrs-prov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = write_line(&root);
        let reg = ProviderRegistry {
            version: 1,
            providers: vec![provider(1, 7895, &["a.example.com", "b.example.com"])],
        };
        assert!(apply_to_line(&line, &reg).unwrap());
        let text = std::fs::read_to_string(&line).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        let outbounds = v["outbounds"].as_array().unwrap();
        let provider_ob = outbounds.iter().find(|o| o["tag"] == "provider").unwrap();
        assert_eq!(provider_ob["server_port"], 7895);
        assert_eq!(provider_ob["type"], "socks");
        // 交易侧出站也注入了（复用日常端口）。
        assert!(outbounds.iter().any(|o| o["tag"] == "provider-trade"));
        // daily-exit 的 members 里 provider 已预置 → 不重复；trade-exit 补进 provider-trade。
        let trade_sel = outbounds.iter().find(|o| o["tag"] == "trade-exit").unwrap();
        assert!(trade_sel["outbounds"].as_array().unwrap().iter().any(|m| m == "provider-trade"));
        let daily_sel = outbounds.iter().find(|o| o["tag"] == "daily-exit").unwrap();
        let daily_count = daily_sel["outbounds"].as_array().unwrap().iter().filter(|m| *m == "provider").count();
        assert_eq!(daily_count, 1, "预置的 provider 不得重复");
        // dns 直连域名规则：在 clash_mode:global 之后，含两个域名。
        let rules = v["dns"]["rules"].as_array().unwrap();
        let dns_rule = rules.iter().find(|r| r.get("domain").is_some()).unwrap();
        assert_eq!(dns_rule["server"], "dns-direct");
        assert_eq!(dns_rule["strategy"], "prefer_ipv4");
        assert_eq!(dns_rule["domain"].as_array().unwrap().len(), 2);
        assert_eq!(rules[0]["clash_mode"], "global", "global 仍在最前");
        // 幂等：再注入一次不变。
        assert!(!apply_to_line(&line, &reg).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_empty_registry_touches_nothing() {
        let root = std::env::temp_dir().join(format!("tcrs-prov-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = write_line(&root);
        let before = std::fs::read_to_string(&line).unwrap();
        assert!(!apply_to_line(&line, &ProviderRegistry::default()).unwrap());
        assert_eq!(std::fs::read_to_string(&line).unwrap(), before, "空注册表不得动线路文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_slot_drops_outbounds_and_recalculates_domains() {
        let root = std::env::temp_dir().join(format!("tcrs-prov-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = write_line(&root);
        let mut reg = ProviderRegistry {
            version: 1,
            providers: vec![
                provider(1, 7895, &["a.example.com"]),
                provider(2, 7896, &["b.example.com"]),
            ],
        };
        apply_to_line(&line, &reg).unwrap();
        // 删除 slot1：registry 里只剩 slot2。
        reg.providers.retain(|p| p.slot != 1);
        assert!(remove_from_line(&line, 1, &reg).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&line).unwrap()).unwrap();
        let outbounds = v["outbounds"].as_array().unwrap();
        assert!(!outbounds.iter().any(|o| o["tag"] == "provider"), "slot1 日常出站应被移除");
        assert!(!outbounds.iter().any(|o| o["tag"] == "provider-trade"), "slot1 交易出站应被移除");
        assert!(outbounds.iter().any(|o| o["tag"] == "provider2"), "slot2 保留");
        let dns_rule = v["dns"]["rules"].as_array().unwrap().iter().find(|r| r.get("domain").is_some()).cloned().unwrap();
        let domains = dns_rule["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "b.example.com", "域名重算为剩余 provider 的并集");
        let _ = std::fs::remove_dir_all(&root);
    }
}
