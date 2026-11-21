//! 生成交给引擎的配置文件（数据根下的 `engine.json`）。
//!
//! 为什么不直接把 旧版的线路文件（`dual-mode.json`）丢给引擎：里面的分流规则是给
//! 它自己的认证入站写的，我们换成匿名入站后那些规则永远匹配不上，流量会全部落到 `direct`。
//! 所以必须重写入站与最前面的几条规则，其余（`outbounds`/`dns`/`endpoints`/…）原样带过去。
//!
//! 两种接管方式（`config::Mode`）：
//! - 代理：只留本机 mixed 入站，TUN 入站删掉——否则仍要管理员权限、仍会改系统路由；
//! - TUN：沿用原文件那个调好的 TUN 入站（address/mtu/stack 一个字节都不动），再追加 mixed。
//!
//! 用 `serde_json::Value` 而不是一堆结构体：引擎的字段集一直在变（`endpoints`、
//! `domain_resolver`、`rule_set` 都是后加的），逐字段建模等于引擎每升一次级就要改这里，
//! 而本模块对它们的态度是「不认识也要一字不动地带过去」。

use serde_json::{json, Value};

use crate::config::{Exits, Mode, SplitConfig, SplitTarget, Transport};

/// 引擎配置文件名（数据根下）。
pub const FILE_NAME: &str = "engine.json";

/// 本程序 mixed 入站的 tag。固定名字，排查时能在引擎日志与 `netstat` 里一眼认出是谁开的端口。
pub const MIXED_TAG: &str = "tc-mixed";

/// 自检探测入站（SOCKS）的 tag。端口 = mixed 端口 + 3；带随机用户名/密码，
/// **每次连接重新生成、只写 runtime.json 的 ProbeUser/ProbePass，不落任何配置文件**。
pub const PROBE_TAG: &str = "tc-check";

/// 需要我们自己补直连出站时用的 tag。只在「出站里本来没有 direct」时出现。
pub const DIRECT_TAG: &str = "tc-direct";

/// 线路文件里两个选择器的 tag。旧版的语义：交易程序走 `trade-exit`，其余走 `daily-exit`。
pub const TRADE_EXIT: &str = "trade-exit";
pub const DAILY_EXIT: &str = "daily-exit";

/// 端口不合法的统一文案（全仓只此一份）。`{}` 是用户给的那个值。
pub fn bad_port_msg(v: &str) -> String {
    format!("端口不合法：{v}（应为 1..=65535）")
}

/// 合法端口区间 1..=65535。`u16` 已挡住上界，只剩 0 需要显式拒绝。
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err(bad_port_msg("0"));
    }
    Ok(())
}

/// 从线路的引擎配置文件判断**实际生效**的接管方式：有 TUN 入站就是 TUN，否则代理。
///
/// 为什么要读文件而不是信 `config.json` 的 `mode`：`mode` 是全局字段，而引擎配置是按
/// **每条线路各自导入时**的模式生成的。混着导过 proxy/TUN 线路时，拿全局字段显示/判定
/// 会骗人（界面说代理、引擎其实在接管路由；TUN 的提权检查也会查错对象）。
/// 读不到或文件坏掉返回 None，调用方回落到配置值——这里不编一个"更友好"的结论。
pub fn actual_mode(path: &std::path::Path) -> Option<Mode> {
    let text = std::fs::read_to_string(path).ok()?;
    let root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()?;
    let inbounds = root.get("inbounds").and_then(Value::as_array)?;
    let has_tun = inbounds
        .iter()
        .any(|i| i.get("type").and_then(Value::as_str) == Some("tun"));
    Some(if has_tun { Mode::Tun } else { Mode::Proxy })
}

/// 这条线路**有没有 TUN 素材**（线路文件里有没有 tun 入站）。
///
/// 与"现在用哪种模式"是两件事：切过代理、还没重连时线路文件里仍然留着 TUN 入站，
/// 所以那时候还能切回去。界面用它决定 TUN 单选能不能点。
pub fn tun_available(line_file: &std::path::Path) -> bool {
    actual_mode(line_file) == Some(Mode::Tun)
}

/// **当前接管方式**：连接中读运行时配置（引擎真正吃的那份），未连接用配置里的偏好。
///
/// 未连接时**不能**读线路文件：线路文件里的 tun 入站是**素材**（原料），不是"当前模式"的声明。
/// 一份 `--import --tun` 生成的线路文件，用户后来 `set-mode proxy` 了，文件里仍有 tun，
/// 但下次连接是按 proxy 走的——那时报 TUN 就是撒谎。
pub fn shown_mode(root: &std::path::Path, cfg_mode: Mode) -> Mode {
    let runtime = root.join("runtime-engine.json");
    if runtime.exists() {
        if let Some(m) = actual_mode(&runtime) {
            return m;
        }
    }
    cfg_mode
}

/// 线路端口的实际上限：**65532**，给探测入站留出 +3 的空间。文案是定稿，别改。
pub const PROBE_ROOM_MSG: &str = "端口最大 65532（需要为自检留出探测端口）";

pub fn validate_probe_room(port: u16) -> Result<(), String> {
    if port > 65_532 {
        return Err(PROBE_ROOM_MSG.to_string());
    }
    Ok(())
}

/// 导入/写线路时校验「端口 +3」（自检探测端口）真的能绑：绑不上就拒绝，而不是让用户
/// 连上之后永远只看到「自检跳过」。
///
/// 为什么用试绑而不是解析 `netsh`：`netsh` 的输出随系统语言变，解析它必然在别的语言/版本上碎掉；
/// 而「能不能绑」只有一个权威答案。
pub fn validate_probe_port_free(port: u16) -> Result<(), String> {
    // 上界由 validate_probe_room 先挡住；这里再 checked 一次只是不让溢出变成 panic。
    let probe = port.checked_add(3).ok_or_else(|| PROBE_ROOM_MSG.to_string())?;
    match std::net::TcpListener::bind(("127.0.0.1", probe)) {
        // 试绑成功就立刻放掉：只回答「能不能绑」，不占着用户的端口。
        Ok(l) => drop(l),
        Err(_) => {
            return Err(format!(
                "端口 {port} 不可用：它的自检探测端口 {probe} 已被占用或被系统预留。请换一个线路端口。"
            ))
        }
    }
    Ok(())
}

/// 把线路文件转成本程序能跑的引擎配置。
///
/// `mode` 决定入站与分流：
/// - 代理：只留我们的 mixed 入站（原文件的 TUN 入站必须删掉，否则仍要管理员权限、仍会改路由）；
/// - TUN：保留原文件那个调好的 TUN 入站，再追加 mixed（两条路并存）。
/// `split` 与 `agents` 是**这份配置的全部注入项**，必须一起传：函数内部会先按形状删掉
/// 上一轮生成的全部规则，再按下这两份配置重新生成——只传一份就会删掉另一份的规则。
/// **交易 DNS 必须走隧道**（旧版的模型，`NodeStore.psm1:1013`）。
///
/// 本机 DNS 会被污染：`www.tradingview.com` 在本机解析成 `31.13.96.192`（脸书），
/// `www.gstatic.com` 解析成 `220.181.174.98`（百度）。线路规则按**域名**匹配，一旦先在
/// 本地解析成假 IP，规则匹配不到、隧道照着假 IP 去连——表现就是「连上了但网站打不开」。
/// 原版的做法：
/// ```text
/// servers = [ {udp dns-direct = 本地}, {https dns-trade = 1.1.1.1:443, detour=trade-exit} ]
/// rules   = [ 交易域名/程序 => dns-trade ] ; final = dns-direct ; port 53 => hijack-dns
/// ```
fn normalize_dns_trade(
    obj: &mut serde_json::Map<String, Value>,
    split: &SplitConfig,
    agents: &crate::config::AgentsConfig,
) {
    let mut trade_domains: Vec<Value> = split
        .domains
        .iter()
        .filter(|entry| entry.target() == crate::config::SplitTarget::Trade)
        .map(|entry| Value::String(entry.value().to_string()))
        .collect();
    let trade_programs: Vec<Value> = split
        .processes
        .iter()
        .filter(|entry| entry.target() == crate::config::SplitTarget::Trade)
        .map(|entry| Value::String(entry.value().to_string()))
        .collect();
    // 与 route 规则同一条判据：名单只在「跟随交易线路」时生效，
    // 跟随日常时一个字节都不能留（否则清空名单也删不掉这些 DNS 规则）。
    if agents.lane == crate::config::AgentsLane::Trade {
        for site in &agents.sites {
            if !trade_domains.iter().any(|d| d.as_str() == Some(site.as_str())) {
                trade_domains.push(Value::String(site.clone()));
            }
        }
    }

    // 兼容连接的 DNS 必须挂在**隧道本体**上：取线路里第一个 wireguard endpoint 的 tag。
    let endpoint_tag = obj
        .get("endpoints")
        .and_then(Value::as_array)
        .and_then(|list| {
            list.iter()
                .find(|ep| ep.get("type").and_then(Value::as_str) == Some("wireguard"))
        })
        .and_then(|ep| ep.get("tag"))
        .and_then(Value::as_str)
        .unwrap_or("hk")
        .to_string();
    // 没有 `tc-transport` 出站时**不能**写 dns-trade：标准档的线路里没有这条出站，
    // 写上去就是一个指向不存在出站的引用（引擎会拒绝整份配置）。
    // 标准档本来也连不上服务器，DNS 保持原样即可。
    let has_transport = obj
        .get("outbounds")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .any(|o| o.get("tag").and_then(Value::as_str) == Some("tc-transport"))
        })
        .unwrap_or(false);
    if !has_transport {
        // 标准档：一个字段都不动（这条线本来也连不上服务器，DNS 保持原样）。
        return;
    }
    let mut servers = vec![
        serde_json::json!({"type": "udp", "tag": "dns-direct", "server": "223.5.5.5"}),
        // 经**隧道**问公共解析器：`detour` 指向 wireguard endpoint 本身（不是
        // `trade-exit` 选择器——指选择器时 DNS 会一直等到超时）。
        //
        // 这条是 2026-11-16 真机验证过的：`udp 1.1.1.1, detour=hk` 拿到的
        // `www.tradingview.com` 是 CloudFront 的 13.33.x（真实地址），
        // gstatic 204、tradingview 200。
        //
        // 早先的实现问的是「服务器隧道内地址上的 unbound」（10.66.0.1），那套中继
        // 只有**我们自己部署的**服务器才有；邀请码加入的线路（原版部署）没有，
        // 查询一律 `exchange4: EOF`，整条线等于不可用。改成不依赖服务器配置。
        serde_json::json!({
            "type": "udp", "tag": "dns-trade",
            "server": "1.1.1.1", "detour": endpoint_tag
        }),
    ];
    // 线路文件里若已有 dns-direct，保留它：别把用户/线路自带的本地解析器换掉。
    if let Some(existing) = obj
        .get("dns")
        .and_then(|d| d.get("servers"))
        .and_then(Value::as_array)
        .and_then(|list| {
            list.iter()
                .find(|s| s.get("tag").and_then(Value::as_str) == Some("dns-direct"))
        })
    {
        servers[0] = existing.clone();
    }

    let mut dns_rules: Vec<Value> = Vec::new();
    if !trade_programs.is_empty() {
        dns_rules.push(serde_json::json!({
            "process_name": trade_programs, "action": "route",
            "server": "dns-trade", "strategy": "ipv4_only"
        }));
    }
    if !trade_domains.is_empty() {
        dns_rules.push(serde_json::json!({
            "domain_suffix": trade_domains, "action": "route",
            "server": "dns-trade", "strategy": "ipv4_only"
        }));
    }
    obj.insert(
        "dns".to_string(),
        serde_json::json!({
            "servers": servers,
            "rules": dns_rules,
            // **final 也指向隧道解析器**：本机 ISP 的 DNS 对被墙域名给的是假地址
            // （实测 `github.com → 57.155.223.240`、`www.gstatic.com → 202.101.48.66`），
            // 只把交易域名走隧道不够——日常域名拿到假 IP 一样连不上。
            // 隧道里那个 unbound 的上游走 TCP（这台服务器出站 UDP 53 也被封）。
            "final": "dns-trade",
            "reverse_mapping": true
        }),
    );

    if let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) {
        route.insert(
            "default_domain_resolver".to_string(),
            serde_json::json!({"server": "dns-direct", "strategy": "prefer_ipv4"}),
        );
        // 不插 `hijack-dns`：那是 旧版在 TUN 模式下拦截应用自带 DNS 用的。
        // 我们是代理模式，浏览器/系统代理把**域名**交给引擎，解析由 `dns.final` 决定，
        // 已经走过隧道；插一条 hook 级规则只会打乱既有规则顺序，收益为零。
    }
}

pub fn generate(
    profile_text: &str,
    listen_port: u16,
    mode: Mode,
    split: &SplitConfig,
    agents: &crate::config::AgentsConfig,
    exits: &Exits,
) -> Result<String, String> {
    validate_port(listen_port)?;

    // 容忍 UTF-8 BOM：线路文件常被记事本/PowerShell 改过，BOM 会让 serde_json 直接判格式错误。
    let text = profile_text.strip_prefix('\u{feff}').unwrap_or(profile_text);
    let mut root: Value =
        serde_json::from_str(text).map_err(|e| format!("线路文件不是合法 JSON：{e}"))?;
    let obj = root.as_object_mut().ok_or_else(|| "线路文件顶层必须是 JSON 对象".to_string())?;

    // 没有 outbounds 的配置引擎能起来但什么也连不通——那种「看起来在跑」的失败最难查。
    let has_outbounds =
        obj.get("outbounds").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false);
    if !has_outbounds {
        return Err("线路文件没有 outbounds，无法生成配置".to_string());
    }

    // 入站整体重建，不是追加：原文件那个带 users 的认证入站我们不用，留着只是多一个可被探测的口。
    let (inbounds, tun_tag, probe) = build_inbounds(obj, mode, listen_port)?;
    obj.insert("inbounds".to_string(), Value::Array(inbounds));

    // 我们的入站要最优先的规则：原配置最后有一条 `process_path_regex=.+ => daily-exit`，
    // 而 daily-exit 默认是 direct——不挡住它，从我们入站进来的流量全被判成「日常」走直连。
    // 实测证据：调试日志 match[15] => route(daily-exit) → outbound/direct。
    route_our_inbounds_to_node(obj, tun_tag.as_deref(), probe);
    // 顺序有讲究：`route_our_inbounds_to_node` 是 `insert(0)` 抢最前，所以分流规则要**在它之后**插，
    // 才能排到「入站 → 节点」之前。反过来的话分流永远轮不到匹配 —— 这条有用例盯着。
    // 交易名单与 AI 工具名单在同一个函数里合成一份列表（唯一入口），不能拆成两次调用。
    normalize_split(obj, split, agents);

    // 出口选择：把用户指定的成员写进两个选择器的 default（不指定就保持线路文件自带的值）。
    apply_exits(obj, exits)?;

    // 兜底出口必须指向日常出口，不能留原文件的 `direct`：
    // 原配置的默认出口是直连，靠 `inbound: egress-probe` 那两条规则把流量分到节点；
    // 我们换成匿名 mixed 入站后这两条永远匹配不上，于是全部走直连——代理形同虚设。
    // 实测证据：改之前经代理取到的出口 IP 与直连完全一致。
    fix_final_outbound(obj);

    // 去掉 clash_api 控制口：旧版的引擎正占着 127.0.0.1:17891，我们原样带过来会两边抢同一个端口。
    // 本版不用 Clash API，整段删掉最干净；删空了的 experimental 也一并去掉，别留个空壳。
    if let Some(exp) = obj.get_mut("experimental").and_then(Value::as_object_mut) {
        exp.remove("clash_api");
        if exp.is_empty() {
            obj.remove("experimental");
        }
    }

    serde_json::to_string_pretty(&root).map_err(|e| format!("生成引擎配置失败：{e}"))
}

/// 按模式拼入站数组，返回（入站，TUN 入站的 tag 若有，是否带探测入站）。
///
/// proxy 模式必须把 TUN 入站删干净：留着它引擎仍要管理员权限、仍会改系统路由，
/// 而用户选的是「只走系统代理」。
fn build_inbounds(
    obj: &serde_json::Map<String, Value>,
    mode: Mode,
    port: u16,
) -> Result<(Vec<Value>, Option<String>, bool), String> {
    let mixed = json!({
        "type": "mixed",
        "tag": MIXED_TAG,
        "listen": "127.0.0.1",
        "listen_port": port,
    });
    // 导入时还没有自检计划：按 `+3` 烤进线路文件，连接前再由 `prepare_engine_config`
    // 用计划的端口覆盖（真正生效的是那一份）。
    let probe = probe_port_of(obj, None, Some(port)).is_some();
    match mode {
        Mode::Proxy => Ok((with_probe(vec![mixed], obj, port, None), None, probe)),
        Mode::Tun => {
            // 原文件里的 TUN 入站是 旧版调好的（address/mtu/stack/auto_route），
            // 一字不动地沿用——自己另发明一套参数只会重新踩一遍它踩过的坑。
            let tun = obj
                .get("inbounds")
                .and_then(Value::as_array)
                .and_then(|arr| {
                    arr.iter().find(|i| i.get("type").and_then(Value::as_str) == Some("tun"))
                })
                .cloned()
                .ok_or_else(|| "线路文件没有 TUN 入站，无法生成 TUN 模式配置".to_string())?;
            // 网卡名改成自己的：原文件用 `TradeChannel`，与旧版完全同名，
            // 一旦对方清理残留或两套都在装，系统里就会出现两个同名网卡，排查时分不清谁是谁。
            // 只改名字，address/mtu/stack/auto_route 那些调好的参数仍一字不动。
            let mut tun = tun;
            if let Some(o) = tun.as_object_mut() {
                o.insert(
                    "interface_name".to_string(),
                    Value::String(TUN_INTERFACE.to_string()),
                );
            }
            let tag = tun.get("tag").and_then(Value::as_str).map(str::to_string);
            Ok((with_probe(vec![tun, mixed], obj, port, None), tag, probe))
        }
    }
}

/// 探测入站端口。全仓只有这一处决定它，两个来源按优先级取：
/// 1. `explicit`：自检计划定下的端口（`ProbePlan::Dial.port`）。引擎必须听在**自检要拨的那个口**上，
///    两边各算一次就会在回落动态端口时分叉——自检拨空气，结论变成莫名其妙的「未通过」。
/// 2. `mixed_port + 3`：导入时（还没有自检计划）与老配置的既有口径。
///
/// 线路里没有 trade-exit 选择器时返回 None：没有「交易出口」就没有「经交易出口」
/// 可验，加一个指不出去的规则只会让引擎起不来、或把探测流量悄悄送去直连。
fn probe_port_of(
    obj: &serde_json::Map<String, Value>,
    explicit: Option<u16>,
    mixed_port: Option<u16>,
) -> Option<u16> {
    selector_tag_or(obj, TRADE_EXIT)?;
    explicit.or_else(|| mixed_port.and_then(|p| p.checked_add(3)))
}

/// 在入站列表末尾补上探测入站（能算出端口时）。
///
/// 这里**不写 users**：凭据每次连接重新生成、只写 runtime.json；带固定凭据的入站
/// 才是可被探测的口（旧版那个认证入站就是被这么扫出来的）。
fn with_probe(
    mut inbounds: Vec<Value>,
    obj: &serde_json::Map<String, Value>,
    port: u16,
    explicit: Option<u16>,
) -> Vec<Value> {
    if let Some(p) = probe_port_of(obj, explicit, Some(port)) {
        inbounds.push(json!({
            "type": "socks",
            "tag": PROBE_TAG,
            "listen": "127.0.0.1",
            "listen_port": p,
        }));
    }
    inbounds
}

/// 我们自己的 TUN 网卡名。与旧版的 `TradeChannel` 刻意区分，避免同名网卡混淆。
pub const TUN_INTERFACE: &str = "SpiderVPN";

/// 从我们入站进来的流量一律走节点出口，优先级高于原文件里的进程/规则分流。
///
/// 只加规则、放在最前面：原配置的其余规则原样保留，未来换 profile 也不用改这里。
/// TUN 模式要两条（mixed、TUN）——少了 TUN 那条，TUN 流量会落到原文件的
/// 「任何进程 → daily-exit（默认 direct）」上，等于绕过节点。

fn selector_tag_or(obj: &serde_json::Map<String, Value>, tag: &str) -> Option<String> {
    let outs = obj.get("outbounds").and_then(Value::as_array)?;
    outs.iter()
        .any(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
        .then(|| tag.to_string())
}

/// 两个选择器的当前状态（default + 可选成员），给 `--exits` / `--status` / 界面下拉用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub trade: String,
    pub daily: String,
    pub trade_members: Vec<String>,
    pub daily_members: Vec<String>,
}

/// 从引擎配置里读出口信息。线路文件里没有这两个 selector 就返回 None。
pub fn read_exits(obj: &serde_json::Map<String, Value>) -> Option<ExitInfo> {
    fn one(obj: &serde_json::Map<String, Value>, tag: &str) -> Option<(String, Vec<String>)> {
        let outs = obj.get("outbounds").and_then(Value::as_array)?;
        let sel = outs.iter().find(|o| o.get("tag").and_then(Value::as_str) == Some(tag))?;
        let members: Vec<String> = sel
            .get("outbounds")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let default = sel.get("default").and_then(Value::as_str).unwrap_or("").to_string();
        Some((default, members))
    }
    let (trade, trade_members) = one(obj, TRADE_EXIT)?;
    let (daily, daily_members) = one(obj, DAILY_EXIT)?;
    Some(ExitInfo { trade, daily, trade_members, daily_members })
}

/// 直接从线路的引擎配置文件读（`--exits` / `--status` / 界面用）。
pub fn read_exits_from_file(path: &std::path::Path) -> Result<Option<ExitInfo>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("读不到线路引擎配置（{}）：{e}", path.display()))?;
    let root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON：{e}"))?;
    Ok(root.as_object().and_then(read_exits))
}

/// 把 `exits` 里指定的成员写进两个选择器的 `default`。**成员必须是该选择器的成员**，
/// 否则报错（错误里带可选范围）。返回是否真的改了东西。
pub fn apply_exits(obj: &mut serde_json::Map<String, Value>, exits: &Exits) -> Result<bool, String> {
    let mut changed = false;
    for (which, want) in [("trade", &exits.trade), ("daily", &exits.daily)] {
        let Some(want) = want.as_deref().map(str::trim).filter(|w| !w.is_empty()) else {
            continue;
        };
        let (tag, label) =
            if which == "trade" { (TRADE_EXIT, "交易出口") } else { (DAILY_EXIT, "日常出口") };
        let Some(info) = read_exits(obj) else {
            return Err(format!("线路文件里没有「{tag}」选择器，无法设置{label}"));
        };
        let members = if which == "trade" { &info.trade_members } else { &info.daily_members };
        if !members.iter().any(|m| m == want) {
            return Err(format!(
                "出口 {want} 不在{label}的可选范围：{}",
                members.join(", ")
            ));
        }
        let Some(sel) = obj
            .get_mut("outbounds")
            .and_then(Value::as_array_mut)
            .and_then(|a| a.iter_mut().find(|o| o.get("tag").and_then(Value::as_str) == Some(tag)))
        else {
            continue;
        };
        if sel.get("default").and_then(Value::as_str) == Some(want) {
            continue;
        }
        sel["default"] = Value::String(want.to_string());
        changed = true;
    }
    Ok(changed)
}

/// 就地改线路引擎配置里的两个出口（`--exit-set` 用）。
pub fn apply_exits_to_file(
    path: &std::path::Path,
    exits: &Exits,
) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Err(format!("读不到线路引擎配置（{}）", path.display()));
    };
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON：{e}"))?;
    let Some(obj) = root.as_object_mut() else {
        return Err("线路引擎配置顶层必须是对象".to_string());
    };
    if !apply_exits(obj, exits)? {
        return Ok(false);
    }
    let text = serde_json::to_string_pretty(&root).map_err(|e| format!("生成引擎配置失败：{e}"))?;
    // 写回线路文件：里面含 WireGuard 私钥，走 secretfile 一并收紧 ACL（F1）。
    crate::secretfile::write(path, &text).map_err(|e| format!("写入引擎配置失败：{e}"))?;
    Ok(true)
}

/// 命中分流规则的流量按 `target` 走对应出站；AI 工具名单的规则紧随其后。
///
/// **这是唯一一处往 `route.rules` 里插规则的地方**：交易名单与 AI 工具名单在同一个函数里
/// 合成一份有序列表，一次 `splice(0..0, rules)` 写完。再来第二个入口（各自 splice）会让
/// 顺序不可控，而且两边都按形状删、只补自己那份，会把对方生成的规则删掉。
///
/// 四条约束：
/// 1. 直连出站要有且只认 `type == "direct"` 的那个：没有就追加 `tc-direct`。
///    **不能**复用 `daily-exit` —— 它可能被配成非直连。
/// 2. 规则插在最前面：`route.rules` 先匹配先生效，晚于「入站 → 节点」就等于没写。
/// 3. 空的列表不生成规则：空数组规则在某些 sing-box 版本里会被判无效配置。
/// 4. 顺序（从上到下）：交易名单的进程规则 → 交易名单的域名规则 → 名单的程序 → 名单的
///    浏览器+域名 → 名单的纯域名 → 探测规则 / 我们入站规则 / 线路自带规则。
///    「交易名单在前」是 PRD 的要求；但真正保证「交易名单优先」的是
///    `agents::effective()` 里的**减法**，不是这里的顺序——顺序只影响人读文件时的可读性。
pub fn normalize_split(
    obj: &mut serde_json::Map<String, Value>,
    split: &SplitConfig,
    agents: &crate::config::AgentsConfig,
) -> bool {
    // 返回值语义 = **内容真的变了没有**（不是"跑过没跑过"）。
    // 因为"先删再插"这个做法每次都动数组，若返回值只表示动作，`prepare_engine_config`
    // 会以为每次都需要重写运行时配置 —— 幂等性就从这里破掉了。
    let before = split_state(obj);
    remove_generated_split_rules(obj);
    let mut rules: Vec<Value> = Vec::new();
    rules.extend(split_rules(obj, split));
    rules.extend(agents_rules(obj, agents));
    if !rules.is_empty() {
        if let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) {
            let arr = route.entry("rules".to_string()).or_insert_with(|| Value::Array(Vec::new()));
            if let Some(list) = arr.as_array_mut() {
                // 插到最前：分流必须抢在「入站 → 日常出口」之前匹配。
                list.splice(0..0, rules);
            }
        }
    }
    split_state(obj) != before
}

/// 进程名大小写变体：{原样, 全小写, 首字母大写} 去重，**原样排第一**。
///
/// 为什么需要：sing-box 的 `process_name` 匹配是**大小写敏感**的精确查找
/// （1.14.2 `rule_item_process_name.go`：`processMap[filepath.Base(ProcessPath)]`），
/// 键是磁盘上 exe 文件名的真实大小写。同一个程序在不同安装渠道下文件名大小写可能不同
/// （Claude Desktop 老 Squirrel 是 `claude.exe`、新 MSIX 是 `Claude.exe`；Cursor
/// 各处 `cursor.exe` / `Cursor.exe` 并存）。配置里保存用户/目录写下的原样值，
/// 只在**写进引擎配置**这一步展开变体；域名不在此列（域名匹配自身不区分大小写）。
fn process_name_variants(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    let lower = name.to_lowercase();
    if !out.iter().any(|v| v == &lower) {
        out.push(lower);
    }
    let mut chars = name.chars();
    if let Some(first) = chars.next() {
        let titled: String = first.to_uppercase().collect::<String>() + chars.as_str();
        if !out.iter().any(|v| v == &titled) {
            out.push(titled);
        }
    }
    out
}

/// 一组进程名展开成变体数组：保持条目顺序、跨条目去重。
fn expand_process_names<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        for variant in process_name_variants(name.as_ref()) {
            if !out.contains(&variant) {
                out.push(variant);
            }
        }
    }
    out
}

/// 交易名单那一段规则（原逻辑原样抽出来，顺序一字不改）。
///
/// 顺序固定：先按落点分组的进程规则，再是域名规则；同一类里按 direct/trade/daily 排。
fn split_rules(obj: &mut serde_json::Map<String, Value>, split: &SplitConfig) -> Vec<Value> {
    let mut rules: Vec<Value> = Vec::new();
    if split.is_empty() {
        return rules;
    }
    for target in [SplitTarget::Direct, SplitTarget::Trade, SplitTarget::Daily] {
        let vals = split.processes_for(target);
        if !vals.is_empty() {
            let tag = outbound_tag_for(obj, target);
            rules.push(json!({ "process_name": expand_process_names(&vals), "outbound": tag }));
        }
    }
    for target in [SplitTarget::Direct, SplitTarget::Trade, SplitTarget::Daily] {
        let vals = split.domains_for(target);
        if !vals.is_empty() {
            let tag = outbound_tag_for(obj, target);
            rules.push(json!({ "domain_suffix": vals, "outbound": tag }));
        }
    }
    rules
}

/// AI 工具名单那一段规则（最多 3 条，顺序固定）。
///
/// 两条「一条都不生成」的情形，都必须**在写任何东西之前**返回：
/// 1. 走向=跟随日常上网：名单视为「尚未启用」，生成结果与「没有这份名单」逐字节相同；
/// 2. 线路里没有 `trade-exit`：一条都不生成，而且**不退回直连**。
///    退回直连是语义反转（名单的意思是「走交易线路」），并且 `ensure_direct_outbound`
///    会新增一个 outbounds 条目——那会让 `split_state` 每次都变，直接破坏幂等。
///    这也是这里**不用** `outbound_tag_for(obj, Trade)` 的原因。
fn agents_rules(
    obj: &serde_json::Map<String, Value>,
    agents: &crate::config::AgentsConfig,
) -> Vec<Value> {
    if agents.lane != crate::config::AgentsLane::Trade {
        return Vec::new();
    }
    if !has_trade_exit(obj) {
        return Vec::new();
    }
    let plan = crate::agents::effective(agents);
    if plan.is_empty() {
        // 名单是空的：一条都不生成。
        return Vec::new();
    }
    let tag = TRADE_EXIT.to_string();
    let mut out: Vec<Value> = Vec::new();
    if !plan.path_patterns.is_empty() {
        // 程序：按进程路径正则识别（旧版同款；大小写由 `(?i)` 管，双渠道安装一网打尽）。
        out.push(json!({ "process_path_regex": plan.path_patterns, "outbound": tag }));
    }
    if !plan.web_domains.is_empty() {
        // 网页版：浏览器正则 + 域名**同时**给两个条件。少给进程条件会过匹配
        // （任何程序访问该域名都被搬走），那比欠匹配危险得多。
        out.push(json!({
            "process_path_regex": [crate::agents::BROWSER_PATH_REGEX],
            "domain_suffix": plan.web_domains,
            "outbound": tag
        }));
    }
    if !plan.sites.is_empty() {
        // 纯域名（自定义网站 + 服务类目录项）：不限于浏览器——VS Code 访问也走。
        out.push(json!({ "domain_suffix": plan.sites, "outbound": tag }));
    }
    // 不变式：生成侧的形状必须被删除侧的判据认出来，否则「清空名单后留残条」。
    // 名单规则的 outbound 恒为 TRADE_EXIT（常量，永远在出口集合里）；direct 集合仍按
    // 当前 obj 现算，是为了让判据演进时这里第一时间红，而不是写死空集糊弄过去。
    let direct_tags = direct_outbound_tags(obj);
    debug_assert!(
        out.iter().all(|r| is_ours(r, &direct_tags)),
        "生成的规则必须是 is_ours 认得的形状：{out:?}"
    );
    out
}

/// 这条线路有没有「交易出口」（`trade-exit` 选择器）。
///
/// 生成、界面、status 三处共用这一个谓词，保证「页面说会生效」⟺「生成时真会生成」。
pub fn has_trade_exit(obj: &serde_json::Map<String, Value>) -> bool {
    selector_tag_or(obj, TRADE_EXIT).is_some()
}

/// 读文件版的 [`has_trade_exit`]。读不到/不是合法 JSON 都按「没有」处理：
/// 那两种情况下生成侧同样不会生成名单规则。
pub fn has_trade_exit_file(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    serde_json::from_str::<Value>(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .ok()
        .and_then(|v| v.as_object().map(has_trade_exit))
        .unwrap_or(false)
}

/// 落点 → 出站 tag。选择器不在线路文件里时退回直连（宁可直连也不要指一个不存在的 tag）。
fn outbound_tag_for(obj: &mut serde_json::Map<String, Value>, target: SplitTarget) -> String {
    match target {
        SplitTarget::Trade => {
            selector_tag_or(obj, TRADE_EXIT).unwrap_or_else(|| ensure_direct_outbound(obj))
        }
        SplitTarget::Daily => {
            selector_tag_or(obj, DAILY_EXIT).unwrap_or_else(|| ensure_direct_outbound(obj))
        }
        SplitTarget::Direct => ensure_direct_outbound(obj),
    }
}

/// `normalize_split` 关心的那部分状态（规则 + 出站），用来判断"到底变没变"。
fn split_state(obj: &serde_json::Map<String, Value>) -> (Value, Value) {
    let rules = obj
        .get("route")
        .and_then(|r| r.get("rules"))
        .cloned()
        .unwrap_or(Value::Null);
    let outbounds = obj.get("outbounds").cloned().unwrap_or(Value::Null);
    (rules, outbounds)
}

/// 删掉"我们自己生成的那种规则"，返回是否删掉了东西。
///
/// 判定（P2 加固后）：键集合形状（见 [`is_ours`]）**且** `outbound` 指向我们的出口。
/// 线路文件自带的规则要么带 `inbound` / `rule_set` / `ip_cidr` / `process_path` / `action`
/// 之类被形状排除，要么 `outbound` 是线路自己的 tag——两头都过不了才算我们的。
fn remove_generated_split_rules(obj: &mut serde_json::Map<String, Value>) -> bool {
    // 删除前先把「我们的出口」集合算出来：纯读，不建不写。
    // 在删之前取（而不是删到一半时取）：direct 出站不会被这个函数动，顺序无所谓。
    let direct_tags = direct_outbound_tags(obj);
    let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) else {
        return false;
    };
    let Some(list) = route.get_mut("rules").and_then(Value::as_array_mut) else {
        return false;
    };
    let before = list.len();
    list.retain(|r| !is_ours(r, &direct_tags));
    list.len() != before
}

/// 当前配置里所有 `type == "direct"` 的出站 tag（纯读，不建不写）。
///
/// 这是 [`is_ours`] 出口集合的动态部分：我们生成的 Direct 目标（以及缺选择器时的 Trade/Daily
/// 回退）规则，`outbound` 用的是**线路自己的** direct tag（`ensure_direct_outbound` 复用），
/// 只有线路一个 direct 出站都没有时才新建 `tc-direct`。所以静态白名单
/// `{tc-direct, trade-exit, daily-exit}` 是错的——认不出指向线路 direct tag 的规则，
/// 重新生成时旧规则删不掉，越积越多。这里必须按当前配置现算。
fn direct_outbound_tags(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    obj.get("outbounds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|o| o.get("type").and_then(Value::as_str) == Some("direct"))
                .filter_map(|o| o.get("tag").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 判据：**只**由 `outbound` + 至少一个 `process_name` / `domain_suffix` 组成，没有别的键，
/// **且** `outbound` 是字符串并指向我们的出口：
///
/// ```text
/// outbound ∈ { trade-exit, daily-exit } ∪ { 当前配置里 type==direct 出站的 tag }
/// ```
///
/// 三种形状都是我们的：
/// ```text
/// {outbound, process_name}                        交易名单·进程（用户手输 exe 名）／名单·旧版程序（r21 存量）
/// {outbound, process_path_regex}                 名单·程序（目录路径正则 + 自定义程序转出的模式）
/// {outbound, domain_suffix}                      交易名单·域名／名单·自定义网站与服务域名
/// {outbound, process_name, domain_suffix}         名单·旧版浏览器+域名（r21 存量）
/// {outbound, process_path_regex, domain_suffix}  名单·浏览器+域名（旧版对齐）
/// ```
///
/// 为什么必须扩到三键：旧判据是「两个键**异或**」，第三种形状（同时带两个条件）会被判成
/// 「不是我们的」→ 永远删不掉 → 用户每次保存名单就多一条旧规则，清空名单后依然留在
/// 引擎配置里。**生成侧与删除侧共用这一个函数**——两边各写一份枚举是这份代码里最容易长歪
/// 的地方（生成侧另有 `debug_assert!` 兜底）。
///
/// 为什么必须看 `outbound` 指向哪（P2 数据丢失加固）：只看键集合形状时，线路自带
/// （第三方模板或手改线路文件）、没有 `action`、恰为 `{process_name, outbound}` 两键、
/// `outbound` 是线路自己的出口 tag 的规则，会在我们重新生成引擎配置时被当成我们生成的
/// **静默删掉**——无备份、不可恢复。加上出口归属判据后，这类规则判为「不是我们的」，
/// `normalize_split` 一根手指都不会碰它。残余风险（接受）：两键规则若 `outbound` 恰好是
/// `trade-exit` / `daily-exit` / 线路的 direct tag，与我们自己生成的规则**形状与指向都
/// 不可区分**，仍会被删——这三种出口本来就是"我们的地盘"，拿它写自有规则的线路极少见
/// （已核对本仓夹具：线路规则的键分别是 `[inbound,outbound]` / `[action,inbound,outbound]`
/// / `[action,outbound]`，且都带非我们的键）。
fn is_ours(rule: &Value, direct_tags: &[String]) -> bool {
    let Some(o) = rule.as_object() else { return false };
    // outbound 必须是字符串且落在我们的出口集合里；非字符串（数字/对象/数组）直接判否。
    let Some(outbound) = o.get("outbound").and_then(Value::as_str) else { return false };
    let owned = outbound == TRADE_EXIT
        || outbound == DAILY_EXIT
        || direct_tags.iter().any(|t| t == outbound);
    let has_selector = o.contains_key("process_name")
        || o.contains_key("process_path_regex")
        || o.contains_key("domain_suffix");
    owned
        && has_selector
        && o.keys().all(|k| {
            matches!(
                k.as_str(),
                "outbound" | "process_name" | "process_path_regex" | "domain_suffix"
            )
        })
}

/// 就地把两份名单（交易名单 + AI 工具名单）的规则应用到某个引擎配置文件上。
///
/// **两份配置必须同时传**：这个函数先按形状删掉上一轮生成的全部规则，再按传进来的配置
/// 重新生成。只传一份就会把另一份的规则删掉——那正是本次改动最容易出错的地方，
/// 所以函数名从 `apply_split_to_file` 改成现在这个名字，参数也刻意分成 `split` 与 `agents`。
///
/// 没有变化就不写盘（保持"没配名单时一个字节都不动"）。
pub fn apply_rules_to_file(
    path: &std::path::Path,
    split: &SplitConfig,
    agents: &crate::config::AgentsConfig,
) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false); // 文件不存在：没什么可更新的（下次 import 会生成）
    };
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON（{}）：{e}", path.display()))?;
    let Some(obj) = root.as_object_mut() else { return Ok(false) };
    if !normalize_split(obj, split, agents) {
        return Ok(false);
    }
    let text = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("生成引擎配置失败：{e}"))?;
    // 同一份线路文件（含私钥）：走 secretfile 一并收紧 ACL（F1）。
    crate::secretfile::write(path, &text).map_err(|e| format!("写入引擎配置失败：{e}"))?;
    Ok(true)
}

// ---------- 连接方式（标准连接 Udp / 兼容连接 Tcp）----------

/// 兼容连接那条中转出站的标签。与旧版完全一致（`ConnectionMethods.psm1:224`）：
/// 换名字会让"线路文件里已经有一条 旧版派生的 tc-transport"认不出来。
pub const TRANSPORT_TAG: &str = "tc-transport";

/// 连接方式派生失败的错误前缀。调用方见到它**必须拒绝连接**。
///
/// 为什么不能像分流规则那样"出错就按原文件起"：选 Tcp 却按 Udp 连，是静默降级——
/// 用户选兼容连接，往往恰恰说明 UDP 在这张网上不通，降级等于连了个假的。
pub const TRANSPORT_REFUSED: &str = "连接方式不可用";

pub fn is_transport_refusal(msg: &str) -> bool {
    msg.starts_with(TRANSPORT_REFUSED)
}

/// 接管方式（代理/TUN）派生失败的错误前缀。与 [`TRANSPORT_REFUSED`] 同理：
/// 调用方见到它必须**拒绝连接**——选了 TUN 却按代理连，是静默降级。
pub const MODE_REFUSED: &str = "接管方式不可用";

pub fn is_mode_refusal(msg: &str) -> bool {
    msg.starts_with(MODE_REFUSED)
}

/// TUN 切不过去时那句定稿文案（`set-mode` 与连接前共用，界面也照这句显示）。
pub const NO_TUN_MSG: &str = "这条线路的配置里没有 TUN 入站（导入时只有代理部分），无法切到 TUN。要使用 TUN，请导入一份含 TUN 入站的双模式配置（例如 旧版运行时生成的 dual-mode.json），或用 --import --tun 重新导入。";

/// 连接前把引擎配置的**入站**调成 `cfg.mode` 要的那一种。
///
/// 为什么必须在连接前做：入站是**导入时**由 `generate` 烤进线路文件的（代理导入时 TUN 入站
/// 会被丢掉），所以"切换接管方式"只有在这里落地才真的生效——只改 config.json 是假切换。
///
/// - `Proxy`：只留 mixed（TUN 入站连同它的路由都要去掉，否则仍要管理员、仍改路由）；
/// - `Tun`：保留线路文件里的 TUN 入站（参数是 旧版调好的，一字不动，只把网卡名改成自己的）；
///   线路里本来就没有 TUN 入站 → 报错（让调用方在连接前就说清，而不是等引擎起不来）。
pub fn apply_mode(
    obj: &mut serde_json::Map<String, Value>,
    mode: Mode,
) -> Result<bool, String> {
    let Some(arr) = obj.get("inbounds").and_then(Value::as_array) else {
        return Ok(false); // 没有入站：老文件/异常文件，交给引擎去报错
    };
    let has_tun = arr.iter().any(|i| i.get("type").and_then(Value::as_str) == Some("tun"));
    match mode {
        Mode::Proxy => {
            if !has_tun {
                return Ok(false);
            }
            if let Some(arr) = obj.get_mut("inbounds").and_then(Value::as_array_mut) {
                arr.retain(|i| i.get("type").and_then(Value::as_str) != Some("tun"));
            }
            Ok(true)
        }
        Mode::Tun => {
            if !has_tun {
                return Err(format!("{MODE_REFUSED}：{NO_TUN_MSG}"));
            }
            // 网卡名必须是我们自己的：与旧版同名会让系统里出现两个同名网卡，排查时分不清谁是谁。
            let mut changed = false;
            if let Some(arr) = obj.get_mut("inbounds").and_then(Value::as_array_mut) {
                for i in arr.iter_mut() {
                    if i.get("type").and_then(Value::as_str) != Some("tun") {
                        continue;
                    }
                    if let Some(o) = i.as_object_mut() {
                        if o.get("interface_name").and_then(Value::as_str) != Some(TUN_INTERFACE) {
                            o.insert(
                                "interface_name".to_string(),
                                Value::String(TUN_INTERFACE.to_string()),
                            );
                            changed = true;
                        }
                    }
                }
            }
            Ok(changed)
        }
    }
}

/// 把线路配置就地调成给定的连接方式。**Udp/Tcp 的差异只写在这一处。**
///
/// - `Udp`：只解除 WireGuard endpoint 对 `tc-transport` 的依赖（回到 UDP 直连）；
/// - `Tcp`：多插一条 VLESS + REALITY 中转出站，并给每个 WireGuard endpoint 设 `detour`。
///
/// 返回"内容是否真的变了"：没变时调用方可以继续用线路文件本身，不落运行时配置。
pub fn apply_transport(
    obj: &mut serde_json::Map<String, Value>,
    transport: Transport,
) -> Result<bool, String> {
    let before = obj.clone();
    match transport {
        Transport::Udp => strip_transport(obj),
        Transport::Tcp => install_transport(obj)?,
    }
    // 半截配置的防线：Tcp 分支先校验、后改写，校验不过就直接返回，一个字节都没动。
    Ok(*obj != before)
}

/// 把一份线路文件正文改写成指定连接方式的版本（只动内存，不碰磁盘）。
///
/// 与连接时走同一个 [`apply_transport`]：这里能派生出来，连接时就一定能用。
/// 两边各写一套的话，用户会遇到「生成时好好的、连接时才失败」——最难查的一种。
pub fn derive(text: &str, transport: Transport) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(text))
        .map_err(|e| format!("线路配置不是合法 JSON：{e}"))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| "线路配置顶层必须是对象".to_string())?;
    apply_transport(obj, transport)?;
    // 与 `generate` 同一种排版：同一个目录里两种格式的 JSON 只会让人以为出了事。
    serde_json::to_string_pretty(&value).map_err(|e| format!("线路配置无法序列化：{e}"))
}

/// 只回答"这条线路能不能生成这种连接方式"，不写任何文件（`--set-transport` 切换前用）。
///
/// 与连接时走同一个 [`apply_transport`]：切换时说能行、连接时却失败，是最伤人的那种不一致。
pub fn check_transport(
    line_file: &std::path::Path,
    transport: Transport,
) -> Result<(), String> {
    if transport == Transport::Udp {
        return Ok(()); // 标准连接永远是线路文件本来的样子，没有"能不能"的问题
    }
    let text = std::fs::read_to_string(line_file)
        .map_err(|e| format!("读不到线路文件（{}）：{e}", line_file.display()))?;
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路文件不是合法 JSON：{e}"))?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "线路文件顶层必须是 JSON 对象".to_string())?;
    // 兼容参数存在线路的附属文件里（`<id>.compatible.json`）：文件本身是标准态，
    // 切换时按需注入——这是「一条线路两种方式」的前提。
    let compatible = compatible_at(line_file);
    apply_transport_with(obj, transport, compatible.as_ref()).map(|_| ())
}

/// 读一条线路的兼容连接参数（与线路文件同目录的 `<id>.compatible.json`）。
///
/// 读不到就是 `None`：老线路（部署在「两条线路」那一版之前）没有这个文件，行为必须与
/// 加它之前一字不差——切兼容会照旧被 `transport_params` 拒绝并说清缺什么。
pub fn compatible_at(line_file: &std::path::Path) -> Option<crate::config::LineCompatible> {
    let stem = line_file.file_stem().and_then(|s| s.to_str())?;
    let path = line_file.with_file_name(format!("{stem}.compatible.json"));
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

/// 把兼容参数注入一份标准线路文件（只为派生兼容态用，不落盘）。
fn inject_transport_params(
    obj: &mut serde_json::Map<String, Value>,
    c: &crate::config::LineCompatible,
) -> Result<(), String> {
    if obj.get("outbounds").map(|v| v.is_array()).unwrap_or(false) == false {
        return Err(format!("{TRANSPORT_REFUSED}：线路文件的 outbounds 不是数组"));
    }
    if obj
        .get("outbounds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .any(|o| o.get("tag").and_then(Value::as_str) == Some(TRANSPORT_TAG))
        })
        .unwrap_or(false)
    {
        return Ok(()); // 已经有中转出站（老的两条线路里那条兼容线路就是这种形状）
    }
    let params = TransportParams {
        server: c.server.clone(),
        port: u64::from(c.port),
        uuid: c.uuid.clone(),
        server_name: c.server_name.clone(),
        public_key: c.reality_public_key.clone(),
        short_id: c.reality_short_id.clone(),
    };
    // 先把出站造出来再拿可变借用：`transport_outbound` 要读 dns 段来定 domain_resolver。
    let transit = transport_outbound(obj, &params);
    let Some(arr) = obj.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return Err(format!("{TRANSPORT_REFUSED}：线路文件的 outbounds 不是数组"));
    };
    arr.insert(0, transit);
    Ok(())
}

/// 从一份**兼容态**线路文件里把参数读回来（迁移用：把老的「第二条线路」并进第一条）。
///
/// 只读，不改任何东西；文件不是兼容态或参数不全就返回 `None`（迁移据此跳过，绝不猜）。
pub fn compatible_from_body(text: &str) -> Option<crate::config::LineCompatible> {
    let root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(text)).ok()?;
    let obj = root.as_object()?;
    let p = transport_params(obj).ok()?;
    Some(crate::config::LineCompatible {
        server: p.server,
        port: u16::try_from(p.port).ok()?,
        uuid: p.uuid,
        server_name: p.server_name,
        reality_public_key: p.public_key,
        reality_short_id: p.short_id,
    })
}

/// 与 [`apply_transport`] 相同，但允许**用线路自己的兼容参数补上缺失的中转出站**。
///
/// 这是「一条线路两种方式」的关键一步：标准态的线路文件里没有 VLESS 出站，
/// 不带参数就派生兼容必然失败（也就有了「两张卡片、开关按不动」的坏体验）。
pub fn apply_transport_with(
    obj: &mut serde_json::Map<String, Value>,
    transport: Transport,
    compatible: Option<&crate::config::LineCompatible>,
) -> Result<bool, String> {
    if transport == Transport::Tcp {
        if let Some(c) = compatible {
            if transport_params(obj).is_err() {
                inject_transport_params(obj, c)?;
            }
        }
    }
    apply_transport(obj, transport)
}

/// 线路文件本身是不是"兼容连接那一份"（旧版的 Tcp profile）。
///
/// 判定两个条件缺一不可：
/// - **WireGuard endpoint 真的挂在 `tc-transport` 上**：这才是"这份配置就是要走中转"的证据；
/// - **参数齐全到能再派生一次**（[`transport_params`] 能过）：只看 detour 的话，参数不全的
///   线路会被记成 Tcp，连接时又派生不出来——等于把用户送进一个连不上的状态。
/// 反过来只看参数也不行：标准连接线路也可能把某条带 REALITY 的 vless 当普通出站用，
/// 那样记成 Tcp 就成了替用户改路由。
///
/// 导入时用它把"文件里已经写着的意图"读出来，而不是一律按"没选过 = 标准连接"。
pub fn tcp_shaped(text: &str) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(text.strip_prefix('\u{feff}').unwrap_or(text))
    else {
        return false;
    };
    let Some(obj) = root.as_object() else { return false };
    let depends_on_transport = obj
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|e| {
                e.get("type").and_then(Value::as_str) == Some("wireguard")
                    && e.get("detour").and_then(Value::as_str) == Some(TRANSPORT_TAG)
            })
        })
        .unwrap_or(false);
    depends_on_transport && transport_params(obj).is_ok()
}

#[cfg(test)]
thread_local! {
    /// 只给复合事务的 verify 失败分支做确定性故障注入；线程局部，发布产物不包含。
    static ACTUAL_TRANSPORT_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn force_actual_transport_unknown_for_test(armed: bool) {
    ACTUAL_TRANSPORT_UNKNOWN.with(|flag| flag.set(armed));
}

/// 从引擎实际读取的那份配置识别连接方式。
///
/// 这与 `effective_transport()`（下次连接偏好）以及 `actual_mode()`（代理/TUN 接管方式）
/// 都是不同维度。标准连接要求所有 WireGuard endpoint 都没有 detour；兼容连接要求它们
/// **全部**挂在 `tc-transport` 上，且该标签确实对应参数完整的 VLESS + REALITY 中转。
/// 混合形状、其它 detour、半个中转或不可读 JSON 都返回 None：不知道就说不知道，
/// 绝不能因为“不像兼容连接”就倒推成标准连接。
pub fn actual_transport(path: &std::path::Path) -> Option<Transport> {
    #[cfg(test)]
    if ACTUAL_TRANSPORT_UNKNOWN.with(|flag| flag.get()) {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()?;
    let obj = root.as_object()?;
    let empty = Vec::new();
    let endpoints = obj.get("endpoints").and_then(Value::as_array).unwrap_or(&empty);
    let mut wireguard = 0usize;
    let mut via_transport = 0usize;
    for endpoint in endpoints {
        if endpoint.get("type").and_then(Value::as_str) != Some("wireguard") {
            continue;
        }
        wireguard += 1;
        match endpoint.get("detour") {
            None | Some(Value::Null) => {}
            Some(Value::String(tag)) if tag == TRANSPORT_TAG => via_transport += 1,
            // 其它出站链不是本产品的两档连接方式；非字符串也不是可识别证据。
            Some(_) => return None,
        }
    }
    // 没有 WireGuard endpoint 时，“所有 endpoint 都没有 detour”只是空集合上的真值，
    // 不是标准连接证据；本产品的两档连接方式都以 WireGuard 隧道本体为前提。
    if wireguard == 0 {
        return None;
    }
    if via_transport == 0 {
        return Some(Transport::Udp);
    }
    if via_transport != wireguard {
        return None;
    }
    obj.get("outbounds")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find(|o| {
                o.get("tag").and_then(Value::as_str) == Some(TRANSPORT_TAG)
                    && o.get("type").and_then(Value::as_str) == Some("vless")
            })
        })?;
    // `transport_params` 会优先读取专用 tc-transport；上面已经确认该出站真实存在，
    // 因而不会拿另一条 REALITY 出站替一份悬空 detour 凑出“兼容连接”。
    transport_params(obj).ok()?;
    Some(Transport::Tcp)
}

/// 标准连接：去掉 endpoint 的 `detour`，并在**没人再引用**时删掉残留的中转出站。
///
/// 出站不能无脑删：线路里若有选择器/规则还指着 `tc-transport`，删掉就变成"引用了不存在的
/// 出站"，引擎整体起不来——而用户的这份线路本来能跑。所以只解除我们自己的依赖，
/// 别人的引用一律不动。
fn strip_transport(obj: &mut serde_json::Map<String, Value>) {
    for_wireguard_endpoints(obj, |ep| {
        if ep.get("detour").and_then(Value::as_str) == Some(TRANSPORT_TAG) {
            ep.remove("detour");
        }
    });
    if references_tag(obj, TRANSPORT_TAG) {
        return;
    }
    if let Some(arr) = obj.get_mut("outbounds").and_then(Value::as_array_mut) {
        arr.retain(|o| o.get("tag").and_then(Value::as_str) != Some(TRANSPORT_TAG));
    }
}

/// 兼容连接：给 WireGuard 隧道套一层 VLESS + REALITY 中转。
fn install_transport(obj: &mut serde_json::Map<String, Value>) -> Result<(), String> {
    // 参数与前置条件**先全部校验**，通过了才动配置（不许留下半截 Tcp 配置）。
    let params = transport_params(obj)?;
    let mut endpoints = 0usize;
    let mut foreign_detour: Option<String> = None;
    for_wireguard_endpoints(obj, |ep| {
        endpoints += 1;
        if let Some(d) = ep.get("detour").and_then(Value::as_str) {
            if d != TRANSPORT_TAG && foreign_detour.is_none() {
                foreign_detour = Some(d.to_string());
            }
        }
    });
    if endpoints == 0 {
        return Err(format!(
            "{TRANSPORT_REFUSED}：线路文件没有 WireGuard endpoint，兼容连接无处可挂"
        ));
    }
    // 别人的依赖链不覆盖：改掉它的 detour 可能连带弄坏一份我们不了解的配置。
    if let Some(d) = foreign_detour {
        return Err(format!(
            "{TRANSPORT_REFUSED}：线路文件的 WireGuard endpoint 已依赖其它出站（detour={d}），不覆盖"
        ));
    }
    let old = obj.get("outbounds").and_then(Value::as_array).cloned().unwrap_or_default();
    if let Some(o) = old
        .iter()
        .find(|o| o.get("tag").and_then(Value::as_str) == Some(TRANSPORT_TAG))
    {
        if o.get("type").and_then(Value::as_str) != Some("vless") {
            return Err(format!(
                "{TRANSPORT_REFUSED}：出站标签 {TRANSPORT_TAG} 已被其它类型的出站占用"
            ));
        }
    }

    let transit = transport_outbound(obj, &params);
    let mut next = vec![transit];
    next.extend(
        old.into_iter()
            .filter(|o| o.get("tag").and_then(Value::as_str) != Some(TRANSPORT_TAG)),
    );
    obj.insert("outbounds".to_string(), Value::Array(next));
    for_wireguard_endpoints(obj, |ep| {
        ep.insert("detour".to_string(), Value::String(TRANSPORT_TAG.to_string()));
    });
    Ok(())
}

/// 兼容连接的中转参数。**只能从线路文件里已有的 vless 出站读**：
/// 旧版是部署时由服务器下发（`transport_info`），本版没有部署能力，所以不做任何猜测——
/// 读不到就报错说清缺什么，绝不用占位值凑一份"看起来能跑"的配置。
struct TransportParams {
    server: String,
    port: u64,
    uuid: String,
    server_name: String,
    public_key: String,
    short_id: String,
}

/// 找参数来源：优先专用中转出站（`tag=tc-transport`，旧版派生的线路文件就是这个形状）；
/// 否则要求**恰好一条**带 REALITY 的 vless 出站。多条时拒绝——猜错一条就是把交易流量
/// 导到另一台服务器上。
fn transport_params(obj: &serde_json::Map<String, Value>) -> Result<TransportParams, String> {
    let outbounds: &[Value] = obj.get("outbounds").and_then(Value::as_array).map_or(&[], Vec::as_slice);
    let is_vless = |o: &Value| o.get("type").and_then(Value::as_str) == Some("vless");
    let mut candidates: Vec<&Value> = outbounds
        .iter()
        .filter(|o| is_vless(o) && o.pointer("/tls/reality/public_key").is_some())
        .collect();
    let source = match outbounds
        .iter()
        .find(|o| is_vless(o) && o.get("tag").and_then(Value::as_str) == Some(TRANSPORT_TAG))
    {
        Some(o) => o,
        None => match candidates.len() {
            1 => candidates.remove(0),
            0 => {
                return Err(format!(
                    "{TRANSPORT_REFUSED}：线路文件里没有带 VLESS + REALITY 的出站，拿不到兼容连接参数\
                     （需要 server / server_port / uuid / tls.server_name / tls.reality.public_key）"
                ))
            }
            n => {
                return Err(format!(
                    "{TRANSPORT_REFUSED}：线路文件里有 {n} 条 vless 出站都带 REALITY 参数，\
                     无法确定用哪一条作中转（给要用的那条加上 tag={TRANSPORT_TAG}）"
                ))
            }
        },
    };

    fn need(source: &Value, pointer: &str) -> Result<String, String> {
        source
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{TRANSPORT_REFUSED}：兼容连接参数缺少 {pointer}"))
    }

    let server = need(source, "/server")?;
    let uuid = need(source, "/uuid")?;
    let server_name = need(source, "/tls/server_name")?;
    let public_key = need(source, "/tls/reality/public_key")?;
    let short_id = source
        .pointer("/tls/reality/short_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let port = source
        .pointer("/server_port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or_else(|| format!("{TRANSPORT_REFUSED}：兼容连接参数 server_port 不是 1..=65535 的整数"))?;
    // 下面三条是 旧版的`ConvertTo-CMTransport` 的同一套形状校验。放在这里是为了让
    // "参数写错了"在切换时就暴露，而不是等引擎起不来（那时报的是引擎的错，用户看不懂）。
    if !is_guid(&uuid) {
        return Err(format!("{TRANSPORT_REFUSED}：兼容连接参数 uuid 不是合法的 GUID（{uuid}）"));
    }
    if public_key.len() != 43 || !public_key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!(
            "{TRANSPORT_REFUSED}：兼容连接参数 tls.reality.public_key 必须是 43 位 base64url"
        ));
    }
    if short_id.len() > 16
        || short_id.len() % 2 != 0
        || !short_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(format!(
            "{TRANSPORT_REFUSED}：兼容连接参数 tls.reality.short_id 必须是最多 16 位的偶数长度十六进制"
        ));
    }
    Ok(TransportParams { server, port, uuid, server_name, public_key, short_id })
}

/// 兼容连接的中转出站。字段与旧版的 `New-CMConfiguration`（`ConnectionMethods.psm1:222-226`）
/// 一字不差：换形状等于换协议，服务端就不认了。
fn transport_outbound(obj: &serde_json::Map<String, Value>, p: &TransportParams) -> Value {
    let mut o = serde_json::json!({
        "type": "vless",
        "tag": TRANSPORT_TAG,
        "server": p.server,
        "server_port": p.port,
        "uuid": p.uuid,
        "tls": {
            "enabled": true,
            "server_name": p.server_name,
            "utls": { "enabled": true, "fingerprint": "chrome" },
            "reality": {
                "enabled": true,
                "public_key": p.public_key,
                "short_id": p.short_id
            }
        }
    });
    // 域名的解析指定只在线路里真有 `dns-direct` 时才写：引用一个不存在的 DNS 标签会让
    // 引擎整体起不来（旧版也是先断言所有引用都能解析，才落配置）。
    let has_dns_direct = get_path(obj, "dns/servers")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|s| s.get("tag").and_then(Value::as_str) == Some("dns-direct")))
        .unwrap_or(false);
    if has_dns_direct {
        if let Some(m) = o.as_object_mut() {
            m.insert(
                "domain_resolver".to_string(),
                serde_json::json!({ "server": "dns-direct", "strategy": "prefer_ipv4" }),
            );
        }
    }
    o
}

/// 逐个访问 `endpoints` 里的 WireGuard（`type=wireguard`）endpoint。
/// 中转依赖只挂在它们身上——它们是隧道本体，`outbounds` 里的 vless 只是外贸。
fn for_wireguard_endpoints<F: FnMut(&mut serde_json::Map<String, Value>)>(
    obj: &mut serde_json::Map<String, Value>,
    mut f: F,
) {
    let Some(arr) = obj.get_mut("endpoints").and_then(Value::as_array_mut) else {
        return;
    };
    for ep in arr.iter_mut() {
        let Some(m) = ep.as_object_mut() else { continue };
        if m.get("type").and_then(Value::as_str) == Some("wireguard") {
            f(m);
        }
    }
}

/// 按 `a/b/c` 取子节点。`serde_json::Map` 没有 `Value::pointer`，为这条路克隆整个对象不值得。
fn get_path<'a>(obj: &'a serde_json::Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut keys = path.split('/').filter(|s| !s.is_empty());
    let mut cur = obj.get(keys.next()?)?;
    for k in keys {
        cur = cur.get(k)?;
    }
    Some(cur)
}

/// 配置里还有谁引用着这个出站标签（选择器的 members/default、路由规则、final、DNS 的 detour）。
fn references_tag(obj: &serde_json::Map<String, Value>, tag: &str) -> bool {
    fn rules_reference(rules: &[Value], tag: &str) -> bool {
        rules.iter().any(|r| {
            r.get("outbound").and_then(Value::as_str) == Some(tag)
                || r.get("rules")
                    .and_then(Value::as_array)
                    .map(|c| rules_reference(c, tag))
                    .unwrap_or(false)
        })
    }
    let hit = |v: &Value| v.as_str() == Some(tag);
    let outbounds: &[Value] = obj.get("outbounds").and_then(Value::as_array).map_or(&[], Vec::as_slice);
    let by_outbound = outbounds.iter().any(|o| {
        hit(o.get("detour").unwrap_or(&Value::Null))
            || hit(o.get("default").unwrap_or(&Value::Null))
            || o.get("outbounds").and_then(Value::as_array).map(|a| a.iter().any(hit)).unwrap_or(false)
    });
    let by_endpoint = obj
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|e| hit(e.get("detour").unwrap_or(&Value::Null))))
        .unwrap_or(false);
    let by_route = get_path(obj, "route/final").map(hit).unwrap_or(false)
        || get_path(obj, "route/rules")
            .and_then(Value::as_array)
            .map(|r| rules_reference(r, tag))
            .unwrap_or(false);
    let by_dns = get_path(obj, "dns/servers")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|s| hit(s.get("detour").unwrap_or(&Value::Null))))
        .unwrap_or(false);
    by_outbound || by_endpoint || by_route || by_dns
}

/// `8-4-4-4-12` 的十六进制 GUID。只校验形状：`uuid` 写错的话引擎起不来，而这里能说清是哪个字段。
fn is_guid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// 连接前把分流规则应用到**线路的引擎配置**上，产出真正给引擎用的那份。
///
/// 为什么需要：`--split-*` 只改 `config.json`；而线路的引擎配置是 `--import` 时"烤"好的。
/// 于是"先导入、后加分流"这个最自然的顺序，规则永远进不了引擎。这里在连接前做一次
/// 归一（删旧插新），保证引擎看到的规则一定等于配置文件里的事实。
///
/// `probe_creds` 是本次连接的探测凭据（每次连接重新生成）：
/// - `Some` 且线路配置里有 tc-check 入站 → 把凭据写进该入站的 users，**必定**产出运行时配置。
///   凭据每次都是新的，"无变化捷径"对它不适用——带着没有 users 的探测入站直接起引擎，
///   等于在 127.0.0.1 上开一个谁都能用的口。
/// - `None`（探测端口被占/算不出来）→ 把探测入站连同它的路由规则**摘掉**再产出运行时配置：
///   引擎对绑不上的入站是整体 FATAL（实测 sing-box 1.14.2），不摘掉连"日常能通"都保不住。
/// - 线路配置里本来就没有 tc-check 入站 → 与没加这个参数之前的行为完全一致
///   （没有变化就不落新文件）。
///
/// `probe_port` 是自检计划定下的端口（`ProbePlan::Dial.port`）。`Some` 时探测入站的
/// `listen_port` 以它为准——计划可能已经从 `+3` 回落到动态端口，引擎必须听在自检要拨的那个口上。
/// `None` 时沿用线路文件里的值（老调用点/老配置行为不变）。
///
/// `transport` 是这条线路当前选中的连接方式（见 [`apply_transport`]）：线路文件本身永远是
/// 标准连接那一份，兼容连接在它之上现场派生——一份事实、两种用法，不会有两份文件互相漂移。
/// 给出站绑网卡（C2 剩余）：只给**要拨服务器的出站**写 `bind_interface`。
///
/// 为什么只给这些：`direct`/`block`/选择器没有 `server`，给它们写是无效键；真正会把
/// 包发到服务器的是带 `server` 的出站。绑到物理网卡之后，即使 TUN 抓住默认路由，
/// 引擎到服务器的这条连接也不会绕回隧道里——旧版在 `LineStore`/`CandidateProbe`/
/// `StandbyQuality`/`ProbePath` 四处做的就是这件事。
///
/// `adapter` 为空 = 这次没拿到默认网卡（探测失败/非 Windows）：**一个字段都不写**，
/// 让引擎按系统选路走。写空串或猜一个名字，比不写更糟——猜错会让引擎直接起不来。
/// 服务器地址是不是本机回环。`localhost` / `127.0.0.0/8` / `::1` 都算。
fn dials_loopback(server: &str) -> bool {
    let server = server.trim().to_ascii_lowercase();
    server == "localhost"
        || server == "::1"
        || server == "[::1]"
        || server.starts_with("127.")
}

pub fn apply_bind_interface(
    obj: &mut serde_json::Map<String, Value>,
    adapter: &str,
) -> bool {
    let adapter = adapter.trim();
    if adapter.is_empty() {
        // 不绑就**把已有的绑定删掉**（旧版也是这么做的：候选配置里显式
        // `Remove('bind_interface')`）。导入的线路可能带着别人的网卡名，
        // 留在配置里会让 sing-box 在 Windows 上解析不到接口，
        // 报 `route ip+net: no such network interface`，所有出站都拨不出去。
        let mut changed = false;
        for key in ["outbounds", "endpoints"] {
            if let Some(list) = obj.get_mut(key).and_then(Value::as_array_mut) {
                for item in list.iter_mut() {
                    if let Some(map) = item.as_object_mut() {
                        if map.remove("bind_interface").is_some() {
                            changed = true;
                        }
                    }
                }
            }
        }
        return changed;
    }
    let Some(outs) = obj.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut changed = false;
    for out in outs.iter_mut() {
        let Some(item) = out.as_object_mut() else {
            continue;
        };
        let dials = item
            .get("server")
            .and_then(Value::as_str)
            .map(|server| !server.trim().is_empty())
            .unwrap_or(false);
        if !dials {
            continue;
        }
        // 服务器就在本机（回环）时不能绑：流量根本不经过物理网卡，
        // 绑上去只会让引擎连不上自己。本地代理/自测线路会踩到这一条。
        if dials_loopback(item.get("server").and_then(Value::as_str).unwrap_or("")) {
            continue;
        }
        // 已经是同一个值 → 不算变化：`prepare_engine_config` 靠这个返回值决定
        // 「没变就复用原文件」。
        if item.get("bind_interface").and_then(Value::as_str) == Some(adapter) {
            continue;
        }
        item.insert(
            "bind_interface".to_string(),
            Value::String(adapter.to_string()),
        );
        changed = true;
    }
    changed
}

pub fn prepare_engine_config(
    line_config: &std::path::Path,
    split: &SplitConfig,
    agents: &crate::config::AgentsConfig,
    transport: Transport,
    mode: Mode,
    out_path: &std::path::Path,
    // 默认出口网卡名（`autoroute::network_info().interface`）。空 = 不知道，不写。
    bind_interface: &str,
    probe_creds: Option<(&str, &str)>,
    probe_port: Option<u16>,
) -> Result<std::path::PathBuf, String> {
    let text = std::fs::read_to_string(line_config)
        .map_err(|e| format!("无法读取线路引擎配置（{}）：{e}", line_config.display()))?;
    let mut root: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|e| format!("线路引擎配置不是合法 JSON：{e}"))?;
    let obj = root.as_object_mut()
        .ok_or_else(|| "线路引擎配置的根节点必须是 JSON 对象".to_string())?;
    // DNS 重建并不属于 split/transport 变更，必须单独跟踪，否则仅 DNS
    // 发生变化时会错误复用原配置，漏掉新解析规则。
    let dns_before = obj.get("dns").cloned();
    let resolver_before = obj.get("route")
        .and_then(Value::as_object)
        .and_then(|route| route.get("default_domain_resolver"))
        .cloned();
    // 接管方式先落地：proxy 要去掉 TUN 入站、tun 要确认线路里真有 TUN 参数。
    // 出错原样上报——调用方必须拒绝连接，不许回退成另一种方式连。
    let mode_changed = apply_mode(obj, mode)?;
    // 两份名单一起传：只传一份会删掉另一份的规则（见 `apply_rules_to_file` 的注释）。
    let split_changed = normalize_split(obj, split, agents);
    // DNS 每次连接重建，而不是只在登记线路时写一次：登记发生在部署当时，
    // 之后改过的 DNS 模型（交易域名走隧道 DoH）必须在下一次连接就生效，
    // 否则旧线路永远带着「本地解析」那份配置——真机上就是「连上了但网站打不开」。
    normalize_dns_trade(obj, split, agents);
    // 连接方式：Udp 通常什么也不改（用线路文件本身），Tcp 会多插一条中转出站。
    // 出错必须原样上报——调用方据此拒绝连接，而不是退回另一种方式连。
    // 兼容参数来自线路的附属文件：同一条线路既能走标准也能走兼容，不需要第二张卡片。
    let compatible = compatible_at(line_config);
    let transport_changed = apply_transport_with(obj, transport, compatible.as_ref())?;
    // DNS 放在这之后：只有注入/保留了 `tc-transport` 出站，才谈得上「经隧道解析」。
    normalize_dns_trade(obj, split, agents);
    // A selector's cached/active member may differ from default; enumerate
    // every candidate, including nested selectors. If any could be direct or
    // cannot be resolved, keep the user's chosen connection unchanged but
    // remove the authenticated probe entry point and its routes.
    let evidence_suppressed = probe_creds.is_some()
        && trade_probe_rejection_reason(obj).is_some();
    let probe_changed = match probe_creds {
        Some((user, pass)) if !evidence_suppressed => inject_probe_creds(obj, user, pass, probe_port),
        _ => remove_probe_inbound(obj),
    };
    // 老线路文件（出口改造前生成）里 mixed 规则与 final 都指向 trade-exit：
    // 不纠正的话，升级上来的用户仍然是「全部走节点」，而界面/说明说的是「默认直连」。
    let exit_changed = normalize_default_exit(obj);
    // Never publish a runtime with an authenticated tc-check listener whose
    // first matching route might be daily-exit/direct. Normal split rules
    // remain unchanged, but probe-only traffic takes precedence at runtime.
    let probe_route_changed = if probe_creds.is_some()
        && obj.get("inbounds").and_then(Value::as_array).is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(PROBE_TAG))
        })
    {
        enforce_probe_route_invariant(obj)?
    } else {
        false
    };
    // 绑网卡放最后：前面几步可能增删出站（兼容连接会多插一条），绑完才不会漏。
    let bind_changed = apply_bind_interface(obj, bind_interface);
    let dns_changed = obj.get("dns") != dns_before.as_ref()
        || obj.get("route")
            .and_then(Value::as_object)
            .and_then(|route| route.get("default_domain_resolver"))
            != resolver_before.as_ref();
    if !dns_changed
        && !split_changed
        && !probe_changed
        && !evidence_suppressed
        && !probe_route_changed
        && !exit_changed
        && !transport_changed
        && !mode_changed
        && !bind_changed
    {
        // 没有变化：直接用原文件，连临时文件都不写。
        return Ok(line_config.to_path_buf());
    }
    let text = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("生成运行时引擎配置失败：{e}"))?;
    // 运行时配置是线路的副本，同样含私钥与探测凭据：走 secretfile 收紧 ACL（F1）。
    crate::secretfile::write(out_path, &text)
        .map_err(|e| format!("写入运行时引擎配置失败（{}）：{e}", out_path.display()))?;
    Ok(out_path.to_path_buf())
}

/// 把本次连接的探测凭据写进 tc-check 入站的 users。
///
/// 入站不在线路配置里就返回"没变"（老导入没有它，行为保持一致）。
/// 凭据每次连接都是新的，所以注入成功必然意味着内容变化——不能被当成"没变"而走原文件捷径。
fn inject_probe_creds(
    obj: &mut serde_json::Map<String, Value>,
    user: &str,
    pass: &str,
    probe_port: Option<u16>,
) -> bool {
    // 没有 trade-exit 选择器就没有「经交易出口」可验：不注入。
    // 硬加只会二选一地出错——规则指向不存在的出站（引擎起不来），
    // 或者没有规则、探测流量落到日常出口（自检却报告"经交易出口"，那是假证据）。
    if selector_tag_or(obj, TRADE_EXIT).is_none() {
        return false;
    }
    let mixed_port = obj
        .get("inbounds")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|i| i.get("tag").and_then(Value::as_str) == Some(MIXED_TAG)))
        .and_then(|i| i.get("listen_port"))
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok());
    let Some(port) = probe_port_of(obj, probe_port, mixed_port) else {
        // 算不出探测端口（没有 mixed 入站/端口越界）：不补规则，免得指向不存在的入站。
        return false;
    };
    let existing = obj
        .get("inbounds")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter().position(|i| i.get("tag").and_then(Value::as_str) == Some(PROBE_TAG))
        });
    match existing {
        Some(idx) => {
            let Some(o) = obj
                .get_mut("inbounds")
                .and_then(Value::as_array_mut)
                .and_then(|a| a[idx].as_object_mut())
            else {
                return false;
            };
            o.insert("users".to_string(), json!([{ "username": user, "password": pass }]));
            // 计划给了端口就以计划为准：线路文件里的 `+3` 只是导入时的猜测，
            // 自检要拨的是计划那个端口，引擎必须听在同一个口上（否则结论是"没人监听"）。
            // 计划没给（None）则一个字都不动——老配置/老调用点的行为保持原样。
            if probe_port.is_some() {
                o.insert("listen_port".to_string(), json!(port));
            }
        }
        // 老线路文件（本功能上线前导入）里没有探测入站：**补建一个**。
        // 不补的话升级上来的用户自检永远「跳过」——他会一直看不到通道结论，
        // 而「跳过」在界面上和一个坏掉的探测没有区别。
        None => {
            let arr = obj
                .entry("inbounds".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            let Some(list) = arr.as_array_mut() else { return false };
            list.push(json!({
                "type": "socks",
                "tag": PROBE_TAG,
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{ "username": user, "password": pass }],
            }));
        }
    }
    ensure_probe_rule(obj);
    true
}

/// 把「默认出口」的方向纠正成日常出口（默认直连）。
///
/// 只处理**我们自己的两条**：`tc-mixed` / `tc-check` 之外的入站（egress-probe 等原文件规则）
/// 一律不动；线路自带的 `process_path → trade-exit`（交易程序走节点）也不动。
/// 没有 daily-exit 选择器时什么都不做——老线路只有 trade-exit 一个出口，改了反而全断。
fn normalize_default_exit(obj: &mut serde_json::Map<String, Value>) -> bool {
    if selector_tag_or(obj, DAILY_EXIT).is_none() {
        return false;
    }
    // 「我们自己的入站」= mixed + 所有 tun 入站；按 tag 现取，不写死名字
    // （原文件的 TUN tag 未必叫 trade-tun，写死会漏改或改错）。
    let mut ours: Vec<String> = vec![MIXED_TAG.to_string()];
    if let Some(list) = obj.get("inbounds").and_then(Value::as_array) {
        for i in list {
            if i.get("type").and_then(Value::as_str) == Some("tun") {
                if let Some(t) = i.get("tag").and_then(Value::as_str) {
                    ours.push(t.to_string());
                }
            }
        }
    }
    let mut changed = false;
    let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) else {
        return false;
    };
    if route.get("final").and_then(Value::as_str) != Some(DAILY_EXIT) {
        route.insert("final".to_string(), json!(DAILY_EXIT));
        changed = true;
    }
    if let Some(rules) = route.get_mut("rules").and_then(Value::as_array_mut) {
        for r in rules.iter_mut() {
            let is_ours = r
                .get("inbound")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .any(|v| ours.iter().any(|o| o == v))
                })
                .unwrap_or(false);
            if !is_ours {
                continue;
            }
            if r.get("outbound").and_then(Value::as_str) == Some(DAILY_EXIT) {
                continue;
            }
            if let Some(o) = r.as_object_mut() {
                o.insert("outbound".to_string(), json!(DAILY_EXIT));
                changed = true;
            }
        }
    }
    changed
}

/// 保证「探测入站 → 交易出口」的路由规则在位：必须排在「mixed → 日常兜底」之前，
/// 自检流量才会进交易出口。升级前导入的老线路文件没有这条，注入凭据时补上。
fn ensure_probe_rule(obj: &mut serde_json::Map<String, Value>) {
    if rule_targets_probe(obj) {
        return;
    }
    let Some(list) = obj
        .get_mut("route")
        .and_then(Value::as_object_mut)
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    // 插在「mixed 那条入站规则」之前；找不到就插最前（宁可抢先，也别落到日常兜底后面）。
    let at = list
        .iter()
        .position(|r| {
            r.get("inbound")
                .and_then(Value::as_array)
                .map(|a| a.iter().any(|v| v.as_str() == Some(MIXED_TAG)))
                .unwrap_or(false)
        })
        .unwrap_or(0);
    list.insert(at, json!({ "inbound": [PROBE_TAG], "outbound": TRADE_EXIT }));
}

/// 规则里有没有针对探测入站的那条。
fn rule_targets_probe(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("route")
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|r| {
                r.get("inbound")
                    .and_then(Value::as_array)
                    .map(|x| x.iter().any(|v| v.as_str() == Some(PROBE_TAG)))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Whether the trade-exit *selection graph* could lead to direct/unknown egress.
///
/// Do not trust the selector's `default`: sing-box can retain a selected member
/// across starts or switch members at runtime. The probe is eligible only when
/// **every** possible selector/urltest member terminates in a known tunnel
/// outbound or WireGuard endpoint. Unknown tags/types, cycles and malformed
/// members are deliberately UNVERIFIED, never a VPN-egress PASS.
fn trade_probe_rejection_reason(obj: &serde_json::Map<String, Value>) -> Option<String> {
    fn traverse(
        tag: &str,
        obj: &serde_json::Map<String, Value>,
        seen: &mut std::collections::HashSet<String>,
    ) -> Result<(), &'static str> {
        if !seen.insert(tag.to_string()) {
            return Err("交易出口选择器存在循环，无法确认实际出口");
        }
        let result = (|| {
            let outbounds = obj.get("outbounds").and_then(Value::as_array)
                .ok_or("交易出口缺少出站列表，无法验证")?;
            let endpoints = obj.get("endpoints").and_then(Value::as_array);
            let outbound = outbounds.iter().filter(|v| v.get("tag").and_then(Value::as_str) == Some(tag));
            let endpoint = endpoints.into_iter().flatten()
                .filter(|v| v.get("tag").and_then(Value::as_str) == Some(tag));
            let found: Vec<_> = outbound.chain(endpoint).collect();
            if found.len() != 1 {
                return Err("交易出口包含未知或重复标签，无法确认实际出口");
            }
            let entry = found[0];
            match entry.get("type").and_then(Value::as_str) {
                Some("direct") => Err("交易出口可能经直连，VPN 出口未验证"),
                Some("selector" | "urltest") => {
                    let members = entry.get("outbounds").and_then(Value::as_array)
                        .filter(|a| !a.is_empty())
                        .ok_or("交易出口选择器没有可确认的成员")?;
                    let defaults_to_member = entry.get("default").is_none_or(|default| {
                        default.as_str().is_some_and(|name| {
                            members.iter().any(|m| m.as_str() == Some(name))
                        })
                    });
                    if !defaults_to_member {
                        return Err("交易出口默认成员不在选择器中，无法确认");
                    }
                    for member in members {
                        let selected = member.as_str().filter(|s| !s.is_empty())
                            .ok_or("交易出口包含无效成员，无法确认")?;
                        traverse(selected, obj, seen)?;
                    }
                    Ok(())
                }
                Some("vless" | "vmess" | "trojan" | "shadowsocks" |
                     "hysteria" | "hysteria2" | "tuic" | "anytls" | "wireguard") => Ok(()),
                _ => Err("交易出口包含未知类型，无法排除直连"),
            }
        })();
        seen.remove(tag);
        result
    }

    let is_selector = obj.get("outbounds").and_then(Value::as_array).is_some_and(|outs| {
        outs.iter().any(|o| {
            o.get("tag").and_then(Value::as_str) == Some(TRADE_EXIT)
                && o.get("type").and_then(Value::as_str) == Some("selector")
        })
    });
    if !is_selector {
        return Some("交易出口不是可确认的选择器，VPN 出口未验证".to_string());
    }
    traverse(TRADE_EXIT, obj, &mut std::collections::HashSet::new())
        .err().map(str::to_string)
}

/// Validate the exact runtime that the current connection is about to probe.
/// Absence, malformed JSON, missing authentication or an uncertain selector all
/// mean SKIP, even if a stale port elsewhere would return HTTP 204.
pub(crate) fn probe_evidence_skip_reason_from_file(path: &std::path::Path) -> Option<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return Some("无法读取本次引擎配置，VPN 出口未验证".to_string()),
    };
    let root: Value = match serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)) {
        Ok(v) => v,
        Err(_) => return Some("本次引擎配置格式无法确认，VPN 出口未验证".to_string()),
    };
    let Some(obj) = root.as_object() else {
        return Some("本次引擎配置无法确认，VPN 出口未验证".to_string());
    };
    if let Some(reason) = trade_probe_rejection_reason(obj) {
        return Some(reason);
    }
    let active = obj.get("inbounds").and_then(Value::as_array).is_some_and(|ins| {
        let probes: Vec<_> = ins.iter()
            .filter(|i| i.get("tag").and_then(Value::as_str) == Some(PROBE_TAG))
            .collect();
        if probes.len() != 1 {
            return false;
        }
        let i = probes[0];
        i.get("type").and_then(Value::as_str) == Some("socks")
            && i.get("listen").and_then(Value::as_str) == Some("127.0.0.1")
            && i.get("users").and_then(Value::as_array).is_some_and(|users| {
                users.len() == 1
                    && users[0].get("username").and_then(Value::as_str).is_some()
                    && users[0].get("password").and_then(Value::as_str).is_some()
            })
    });
    if !active {
        return Some("本次未启用可验证的认证探测入口，VPN 出口未验证".to_string());
    }
    let routed = obj.get("route").and_then(Value::as_object)
        .and_then(|route| route.get("rules")).and_then(Value::as_array)
        .and_then(|rules| rules.first())
        .is_some_and(|first| {
            first.get("inbound").and_then(Value::as_array)
                .is_some_and(|tags| tags.len() == 1 && tags[0] == PROBE_TAG)
                && first.get("outbound").and_then(Value::as_str) == Some(TRADE_EXIT)
        });
    (!routed).then(|| "本次认证探测路由无法确认，VPN 出口未验证".to_string())
}

/// Runtime-only fail-closed guard for the authenticated probe listener.
///
/// A preexisting rule can mention tc-check yet target daily-exit (which may
/// select direct). The old `ensure_probe_rule` considered that "present",
/// leaving the probe free to report a false trade-exit success. Refuse any
/// wrong/ambiguous probe rule, and promote the one valid probe rule ahead of
/// competing process/domain/catch-all rules without changing their relative
/// ordering or the mixed/daily path.
fn enforce_probe_route_invariant(obj: &mut serde_json::Map<String, Value>) -> Result<bool, String> {
    if selector_tag_or(obj, TRADE_EXIT).is_none() {
        return Err("tc-check 探测路由缺少 trade-exit 选择器".to_string());
    }
    // A legacy/minimal line may have no route object at all. Publishing an
    // authenticated tc-check listener without a routing rule is unsafe, but
    // rejecting that line also breaks previously supported connections.
    // Build the missing reserved probe rule; refuse malformed existing types.
    let route = obj.entry("route").or_insert_with(|| json!({}));
    let route = route.as_object_mut()
        .ok_or_else(|| "tc-check 探测路由的 route 类型不合法".to_string())?;
    let rules = route.entry("rules").or_insert_with(|| json!([]));
    let rules = rules.as_array_mut()
        .ok_or_else(|| "tc-check 探测路由规则数组类型不合法".to_string())?;
    if rules.is_empty() {
        rules.push(json!({ "inbound": [PROBE_TAG], "outbound": TRADE_EXIT }));
        return Ok(true);
    }
    let mut probe_indices = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let inbounds = rule.get("inbound").and_then(Value::as_array);
        let contains_probe = inbounds.is_some_and(|tags| {
            tags.iter().any(|tag| tag.as_str() == Some(PROBE_TAG))
        });
        if !contains_probe {
            continue;
        }
        let exact_inbound = inbounds.is_some_and(|tags| {
            tags.len() == 1 && tags[0].as_str() == Some(PROBE_TAG)
        });
        let allowed_shape = rule.as_object().is_some_and(|fields| {
            fields.keys().all(|key| matches!(key.as_str(), "inbound" | "outbound" | "action"))
                && fields.get("action").is_none_or(|a| a.as_str() == Some("route"))
        });
        if !exact_inbound || !allowed_shape
            || rule.get("outbound").and_then(Value::as_str) != Some(TRADE_EXIT)
        {
            return Err("tc-check 探测路由不唯一指向 trade-exit，拒绝启动".to_string());
        }
        probe_indices.push(index);
    }
    let first = *probe_indices.first()
        .ok_or_else(|| "tc-check 探测路由缺少 trade-exit 规则".to_string())?;
    // Older imported profiles can contain two equivalent tc-check -> trade-exit
    // rules (one imported, one generated). Deduplicate only fully validated,
    // identical-purpose reserved-tag rules; any wrong destination has already
    // been refused above. Preserve every unrelated rule in original order.
    if probe_indices.len() > 1 {
        for index in probe_indices.iter().rev() {
            rules.remove(*index);
        }
        rules.insert(0, json!({ "inbound": [PROBE_TAG], "outbound": TRADE_EXIT }));
        return Ok(true);
    }
    if first == 0 {
        return Ok(false);
    }
    let rule = rules.remove(first);
    rules.insert(0, rule);
    Ok(true)
}

/// 把探测入站连同它的路由规则整个摘掉（探测端口被占/算不出来时，连接仍要能起）。
fn remove_probe_inbound(obj: &mut serde_json::Map<String, Value>) -> bool {
    let mut changed = false;
    if let Some(list) = obj.get_mut("inbounds").and_then(Value::as_array_mut) {
        let before = list.len();
        list.retain(|i| i.get("tag").and_then(Value::as_str) != Some(PROBE_TAG));
        changed |= list.len() != before;
    }
    if let Some(list) = obj
        .get_mut("route")
        .and_then(Value::as_object_mut)
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    {
        // 只删"针对探测入站"的规则：形状带 inbound:[tc-check]，不会误伤线路自带规则。
        let before = list.len();
        list.retain(|r| {
            !r.get("inbound")
                .and_then(Value::as_array)
                .map(|x| x.iter().any(|v| v.as_str() == Some(PROBE_TAG)))
                .unwrap_or(false)
        });
        changed |= list.len() != before;
    }
    changed
}

/// 线路文件里有没有探测入站。prepare 出错时调用方据此决定还能不能退回原文件起引擎：
/// 带无 users 的探测入站直接起引擎 = 开无认证的口，必须拒绝连接。
pub fn has_probe_inbound_file(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| {
            serde_json::from_str::<Value>(t.strip_prefix('\u{feff}').unwrap_or(&t)).ok()
        })
        .and_then(|v| {
            v.get("inbounds").and_then(Value::as_array).map(|a| {
                a.iter().any(|i| i.get("tag").and_then(Value::as_str) == Some(PROBE_TAG))
            })
        })
        .unwrap_or(false)
}

/// 拿到一个可用的直连出站 tag：有 `type == "direct"` 的复用它的 tag，没有就追加 `tc-direct`。
fn ensure_direct_outbound(obj: &mut serde_json::Map<String, Value>) -> String {
    let existing = obj
        .get("outbounds")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|o| o.get("type").and_then(Value::as_str) == Some("direct"))
                .and_then(|o| o.get("tag").and_then(Value::as_str))
                .map(str::to_string)
        });
    if let Some(tag) = existing {
        return tag;
    }
    let arr = obj
        .entry("outbounds".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(list) = arr.as_array_mut() {
        list.push(json!({ "type": "direct", "tag": DIRECT_TAG }));
    }
    DIRECT_TAG.to_string()
}

fn route_our_inbounds_to_node(
    obj: &mut serde_json::Map<String, Value>,
    tun_tag: Option<&str>,
    probe: bool,
) {
    // **行为反转（用户明确要求）**：我们的入站走**日常出口**（默认直连），交易程序由线路文件
    // 自带的 `process_path` 规则送去 trade-exit。旧版就是这么分工的。
    let tag = selector_tag_or(obj, DAILY_EXIT).or_else(|| pick_exit_tag(obj));
    let Some(tag) = tag else { return };
    let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) else { return };
    let rules = route
        .entry("rules".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(arr) = rules.as_array_mut() {
        // 顺序：探测规则 → mixed → TUN。探测规则会被随后 normalize_split 插进来的
        // 分流规则压到后面，最终落在「分流规则之后、日常兜底（mixed → daily-exit）之前」——
        // 自检流量必须先命中它，才能证明「经交易出口」。
        if probe {
            arr.insert(0, json!({ "inbound": [PROBE_TAG], "outbound": TRADE_EXIT }));
        }
        let mut i = if probe { 1 } else { 0 };
        // 顺序固定：先 mixed、再 TUN。顺序有测试盯着，别随手调换。
        for inbound in [MIXED_TAG].iter().copied().chain(tun_tag) {
            arr.insert(i, json!({
                "inbound": [inbound],
                "action": "route",
                "outbound": tag,
            }));
            i += 1;
        }
    }
}

/// 选一个真正的节点出口：优先 `trade-exit`，其次 `daily-exit`，再次第一个非 direct 的出站。
/// 一个都没有就不动——写出一个不存在的出站会让引擎直接起不来。
fn pick_exit_tag(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let outbounds = obj.get("outbounds").and_then(Value::as_array)?;
    fn tag_of(o: &Value) -> Option<&str> {
        o.get("tag").and_then(Value::as_str)
    }
    fn is_direct(o: &Value) -> bool {
        o.get("type").and_then(Value::as_str) == Some("direct")
    }

    // 1) 首选本产品的交易出口。
    if outbounds.iter().any(|o| tag_of(o) == Some("trade-exit")) {
        return Some("trade-exit".to_string());
    }
    // 2) `daily-exit` 只有在**真的不是直连**时才算出口。
    //    它默认就是 direct——把 final 指过去等于「全部直连」，正是「看着连上了、其实没走节点」
    //    那起事故的原形。宁可落到下一个候选，也不要拿一个 direct 当出口。
    if let Some(o) = outbounds.iter().find(|o| tag_of(o) == Some("daily-exit")) {
        if !is_direct(o) {
            return Some("daily-exit".to_string());
        }
    }
    // 3) 退而求其次：第一个非 direct 的出站。
    outbounds.iter().find(|o| !is_direct(o)).and_then(|o| tag_of(o)).map(str::to_string)
}

/// 把 `route.final` 指向真正的节点出口。
///
/// 优先 `trade-exit`（本产品的交易出口），其次 `daily-exit`，再不行取第一个非 direct 的出站。
/// 一个都找不到就保持原样——盲目改写会造成「配置里写了不存在的出站」而启动失败。
fn fix_final_outbound(obj: &mut serde_json::Map<String, Value>) {
    // final 也指日常出口：没人匹配到的流量按「日常」处理，与入站规则一致。
    let tag = selector_tag_or(obj, DAILY_EXIT).or_else(|| pick_exit_tag(obj));
    if let Some(tag) = tag {
        if let Some(route) = obj.get_mut("route").and_then(Value::as_object_mut) {
            route.insert("final".to_string(), Value::String(tag));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 改动前的生成结果（golden）：`split` 为空时输出必须**逐字节**与它一致。
    /// 这份基线是加分流功能**之前**用同一份夹具抓的，用来证明"没有规则时行为完全不变"。
    const GOLDEN_PROXY_NO_SPLIT: &str = include_str!("../tests/fixtures/engine-no-split.json");

    fn split_with(process: &str) -> SplitConfig {
        let mut s = SplitConfig::default();
        s.add_process(process, SplitTarget::Direct);
        s
    }

    #[test]
    fn normalize_is_idempotent_and_keeps_foreign_rules() {
        // 幂等：连续两次 normalize，规则条数与内容都不许变（否则每次连接都会多插两条）。
        let mut p = profile(); // 自带一条 {"action":"route","outbound":"trade-exit"}，那不是我们的
        let split = split_with("curl.exe");
        let obj = p.as_object_mut().unwrap();

        assert!(normalize_split(obj, &split, &crate::config::AgentsConfig::default()), "第一次应当有变化");
        let once = serde_json::to_string(&obj["route"]["rules"]).unwrap();
        assert!(!normalize_split(obj, &split, &crate::config::AgentsConfig::default()), "第二次不该再有变化");
        let twice = serde_json::to_string(&obj["route"]["rules"]).unwrap();
        assert_eq!(once, twice, "重复 normalize 不许重复插入：{twice}");

        // 线路自带的规则（带 action/inbound 等）一条都不许动
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert!(
            rules.iter().any(|r| r.get("action").is_some() && r.get("process_name").is_none()),
            "外来规则必须保留：{rules:?}"
        );

        // 删空规则：我们生成的两条要消失，外来规则继续在
        assert!(
            normalize_split(obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "删空应当有变化"
        );
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert!(
            !rules
                .iter()
                .any(|r| r.get("process_name").is_some() || r.get("domain_suffix").is_some()),
            "我们生成的规则必须被清掉：{rules:?}"
        );
        assert_eq!(rules.len(), 1, "只该剩下线路自带那条：{rules:?}");
    }

    #[test]
    fn old_line_config_defaults_to_daily_exit() {
        // 老线路文件（出口改造前生成）：mixed → trade-exit、final=trade-exit。
        // 不纠正的话，升级上来的用户仍然是「全部走节点」，与「默认直连」的说法矛盾。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "vless", "tag": "hk", "server": "198.51.100.10", "server_port": 443 },
            { "type": "selector", "tag": TRADE_EXIT, "outbounds": ["hk"], "default": "hk" },
            { "type": "selector", "tag": DAILY_EXIT, "outbounds": ["direct", "hk"], "default": "direct" }
        ]);
        p["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 }
        ]);
        p["route"] = json!({
            "rules": [
                { "action": "route", "inbound": [MIXED_TAG], "outbound": TRADE_EXIT },
                { "process_path": ["C:////WT9////myQuant_sp.exe"], "action": "route", "outbound": TRADE_EXIT }
            ],
            "final": TRADE_EXIT
        });
        let mut obj = p.as_object().unwrap().clone();
        assert!(normalize_default_exit(&mut obj), "老配置必须被纠正");
        assert_eq!(obj["route"]["final"], DAILY_EXIT, "final 要指日常出口");
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outbound"], DAILY_EXIT, "我们的入站改走日常出口");
        assert_eq!(rules[1]["outbound"], TRADE_EXIT, "交易程序那条规则一个字都不许动");
        // 幂等：纠正过之后再跑不应再报「有变化」（否则每次连接都会重写运行时配置）
        assert!(!normalize_default_exit(&mut obj), "已经是日常出口时不许再报变化");
    }

    #[test]
    fn normalize_default_exit_leaves_old_lines_without_daily_selector_alone() {
        // 只有 trade-exit 的老线路：改了会把所有流量指向不存在的出口 → 全断。
        let mut obj = profile().as_object().unwrap().clone();
        obj["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": TRADE_EXIT, "outbounds": ["direct"], "default": "direct" }
        ]);
        obj["route"] = json!({
            "rules": [{ "action": "route", "inbound": [MIXED_TAG], "outbound": TRADE_EXIT }],
            "final": TRADE_EXIT
        });
        assert!(!normalize_default_exit(&mut obj), "没有日常出口就什么都不做");
        assert_eq!(obj["route"]["final"], TRADE_EXIT);
    }

    #[test]
    fn probe_inbound_is_added_to_old_line_configs() {
        // 老线路文件（本功能上线前导入）：没有 tc-check 入站、也没有探测规则。
        // 连接时必须补建入站（端口 = mixed + 3）并补规则——否则升级上来的用户自检永远「跳过」。
        let mut p = profile();
        p["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 }
        ]);
        let mut obj = p.as_object().unwrap().clone();
        assert!(
            !obj["inbounds"].as_array().unwrap().iter().any(|i| i["tag"] == PROBE_TAG),
            "前提：老配置里确实没有探测入站"
        );
        assert!(inject_probe_creds(&mut obj, "u", "p", None), "必须报告「有变化」");
        let probe = obj["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == PROBE_TAG)
            .expect("必须补建探测入站");
        assert_eq!(probe["listen_port"], 18003, "探测端口 = mixed + 3");
        assert_eq!(probe["users"][0]["username"], "u");
        assert_eq!(probe["users"][0]["password"], "p");
        // 规则也要补上，且指向交易出口
        assert!(
            obj["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["inbound"][0] == PROBE_TAG && r["outbound"] == TRADE_EXIT),
            "必须补「探测 → 交易出口」规则：{}",
            obj["route"]["rules"]
        );
    }

    /// Negative: a legacy or hostile profile already points tc-check at
    /// daily-exit (whose default is direct). A successful self-check must
    /// never be possible through that route. No real endpoints or secrets.
    #[test]
    fn tc_check_existing_daily_route_cannot_survive_prepare() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-route-negative-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        profile["route"]["rules"] = json!([
            { "inbound": [PROBE_TAG], "outbound": DAILY_EXIT },
            { "inbound": [MIXED_TAG], "outbound": DAILY_EXIT }
        ]);
        profile["route"]["final"] = json!(DAILY_EXIT);
        std::fs::write(&line, profile.to_string()).unwrap();

        let prepared = prepare_engine_config(
            &line,
            &SplitConfig::default(),
            &crate::config::AgentsConfig::default(),
            Transport::Udp,
            Mode::Proxy,
            &runtime,
            "",
            Some(("synthetic-user", "synthetic-password")),
            Some(18003),
        );
        match prepared {
            // A precise fail-closed refusal is safe; unrelated failures are not.
            Err(reason) => assert!(
                reason.contains("tc-check") || reason.contains("探测"),
                "unexpected refusal instead of a probe-route invariant: {reason}"
            ),
            Ok(path) => {
                let effective: Value =
                    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
                let rules = effective["route"]["rules"].as_array().unwrap();
                let for_probe: Vec<_> = rules
                    .iter()
                    .filter(|r| r["inbound"].as_array().is_some_and(|tags| {
                        tags.iter().any(|tag| tag == PROBE_TAG)
                    }))
                    .collect();
                assert_eq!(for_probe.len(), 1, "ambiguous tc-check routes: {rules:?}");
                assert_eq!(
                    for_probe[0]["outbound"], TRADE_EXIT,
                    "tc-check must never reach daily-exit/direct: {rules:?}"
                );
                assert_eq!(
                    rules[0]["inbound"], json!([PROBE_TAG]),
                    "tc-check route must precede potentially competing rules: {rules:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// A probe routed through the trade-exit *tag* does not prove VPN egress
    /// when the user's selected trade-exit member is itself direct.
    /// Synthetic config only: no private keys, live ports or network traffic.
    #[test]
    fn tc_check_trade_selector_default_direct_cannot_claim_vpn_egress() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-trade-direct-negative-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "wireguard", "tag": "hk", "server": "198.51.100.10", "server_port": 51820 },
            { "type": "selector", "tag": TRADE_EXIT, "outbounds": ["direct", "hk"], "default": "direct" },
            { "type": "selector", "tag": DAILY_EXIT, "outbounds": ["direct", "hk"], "default": "direct" }
        ]);
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        profile["route"]["rules"] = json!([
            { "inbound": [PROBE_TAG], "outbound": TRADE_EXIT },
            { "inbound": [MIXED_TAG], "outbound": DAILY_EXIT }
        ]);
        profile["route"]["final"] = json!(DAILY_EXIT);
        std::fs::write(&line, profile.to_string()).unwrap();

        let prepared = prepare_engine_config(
            &line,
            &SplitConfig::default(),
            &crate::config::AgentsConfig::default(),
            Transport::Udp,
            Mode::Proxy,
            &runtime,
            "",
            Some(("synthetic-user", "synthetic-password")),
            Some(18003),
        );
        match prepared {
            Err(reason) => {
                assert!(
                    reason.contains("trade-exit")
                        || reason.contains("tc-check")
                        || reason.contains("交易出口")
                        || reason.contains("探测"),
                    "unexpected refusal unrelated to trade-direct probe safety: {reason}"
                );
            }
            Ok(path) => {
                let effective: Value =
                    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
                let outbounds = effective["outbounds"].as_array().unwrap();
                let trade = outbounds.iter()
                    .find(|o| o["tag"] == TRADE_EXIT)
                    .expect("trade-exit selector must be present");
                let direct = outbounds.iter()
                    .find(|o| o["tag"] == "direct")
                    .expect("direct outbound must be present");
                let daily = outbounds.iter()
                    .find(|o| o["tag"] == DAILY_EXIT)
                    .expect("daily selector must be present");
                let probe_authenticated = effective["inbounds"].as_array()
                    .is_some_and(|ins| ins.iter().any(|i| {
                        i["tag"] == PROBE_TAG
                            && i["type"] == "socks"
                            && i["users"].as_array().is_some_and(|users| {
                                users.iter().any(|u| {
                                    u["username"] == "synthetic-user"
                                        && u["password"] == "synthetic-password"
                                })
                            })
                    }));
                let probe_routed_to_trade = effective["route"]["rules"].as_array()
                    .is_some_and(|rules| rules.iter().any(|r| {
                        r["outbound"] == TRADE_EXIT
                            && r["inbound"].as_array().is_some_and(|tags| {
                                tags.iter().any(|t| t == PROBE_TAG)
                            })
                    }));
                let trade_selects_direct = trade["type"] == "selector"
                    && trade["default"] == "direct"
                    && trade["outbounds"].as_array().is_some_and(|members| {
                        members.iter().any(|member| member == "direct")
                    })
                    && direct["type"] == "direct";

                // Daily direct is legitimate; do not "fix" normal user behavior.
                assert_eq!(daily["default"], "direct");
                assert!(
                    !(probe_authenticated && probe_routed_to_trade && trade_selects_direct),
                    "trade-exit selector defaults to direct: authenticated tc-check can take a direct path while the trade-exit tag appears verified (no actual VPN egress established)"
                );
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn trade_probe_direct_candidate_even_with_safe_default_is_unverified() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-trade-candidate-direct-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["outbounds"][3]["outbounds"] = json!(["hk", "direct"]);
        profile["outbounds"][3]["default"] = json!("hk");
        std::fs::write(&line, profile.to_string()).unwrap();
        let path = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect("must keep the user's chosen connection, just not its probe");
        let effective: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(effective["outbounds"][3]["default"], "hk", "do not change user's trade selection");
        assert_eq!(effective["outbounds"][4]["default"], "direct", "daily direct is legitimate");
        assert!(effective["inbounds"].as_array().unwrap().iter().all(|i| i["tag"] != PROBE_TAG));
        assert!(probe_evidence_skip_reason_from_file(&path).is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn trade_probe_nested_direct_cycle_and_unknown_members_skip_without_rewriting_trade() {
        for (suffix, member) in [
            ("nested-direct", json!({"type":"selector","tag":"nested","outbounds":["direct","hk"],"default":"hk"})),
            ("cycle", json!({"type":"selector","tag":"nested","outbounds":[TRADE_EXIT],"default":TRADE_EXIT})),
            ("missing", json!({"type":"selector","tag":"nested","outbounds":["not-a-tag"],"default":"not-a-tag"})),
        ] {
            let root = std::env::temp_dir().join(format!(
                "spidervpn-trade-nested-{}-{suffix}", std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let line = root.join("line.json");
            let runtime = root.join("runtime-engine.json");
            let mut profile = profile_with_exits();
            profile["outbounds"][3]["outbounds"] = json!(["nested"]);
            profile["outbounds"][3]["default"] = json!("nested");
            profile["outbounds"].as_array_mut().unwrap().push(member);
            std::fs::write(&line, profile.to_string()).unwrap();
            let path = prepare_engine_config(
                &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
                Transport::Udp, Mode::Proxy, &runtime, "",
                Some(("synthetic-user", "synthetic-password")), Some(18003)
            ).expect("uncertain trade selection must not prevent connecting");
            let effective: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(effective["outbounds"][3]["default"], "nested");
            assert!(effective["inbounds"].as_array().unwrap().iter().all(|i| i["tag"] != PROBE_TAG));
            assert!(probe_evidence_skip_reason_from_file(&path).is_some());
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn trade_probe_safe_non_direct_selection_keeps_authenticated_probe_and_daily_direct() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-trade-all-safe-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let profile = profile_with_exits();
        std::fs::write(&line, profile.to_string()).unwrap();
        let path = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect("non-direct trade members remain probe-eligible");
        let effective: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(effective["outbounds"][4]["default"], "direct");
        assert!(effective["inbounds"].as_array().unwrap().iter().any(|i| {
            i["tag"] == PROBE_TAG && i["users"][0]["username"] == "synthetic-user"
        }));
        assert_eq!(probe_evidence_skip_reason_from_file(&path), None);
        // Runtime postprocessing must never mistake one valid authenticated
        // listener plus an extra unsafe reserved-tag listener for a valid plan.
        let mut tampered = effective.clone();
        tampered["inbounds"].as_array_mut().unwrap().push(json!({
            "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18009
        }));
        std::fs::write(&path, tampered.to_string()).unwrap();
        assert!(probe_evidence_skip_reason_from_file(&path).is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tc_check_valid_route_precedes_catch_all_without_changing_daily_path() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-route-priority-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        profile["route"]["rules"] = json!([
            { "action": "route", "outbound": DAILY_EXIT },
            { "inbound": [PROBE_TAG], "outbound": TRADE_EXIT },
            { "inbound": [MIXED_TAG], "outbound": DAILY_EXIT }
        ]);
        std::fs::write(&line, profile.to_string()).unwrap();
        let path = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect("valid probe route must be made first without losing other rules");
        let effective: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rules = effective["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"], json!([PROBE_TAG]));
        assert_eq!(rules[0]["outbound"], TRADE_EXIT);
        assert_eq!(rules[1]["outbound"], DAILY_EXIT, "catch-all rule remains after probe");
        assert_eq!(rules[2]["inbound"], json!([MIXED_TAG]));
        assert_eq!(rules[2]["outbound"], DAILY_EXIT, "mixed still uses daily exit");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tc_check_missing_route_in_legacy_minimal_line_gets_safe_rule() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-missing-route-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile.as_object_mut().unwrap().remove("route");
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 }
        ]);
        std::fs::write(&line, profile.to_string()).unwrap();
        let path = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect("minimal legacy line must create a safe probe route");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rules = eff["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"], json!([PROBE_TAG]));
        assert_eq!(rules[0]["outbound"], TRADE_EXIT);
        assert_eq!(rules.len(), 1, "missing route must not add competing rules: {rules:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tc_check_legacy_duplicate_trade_routes_are_safely_deduplicated() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-legacy-duplicates-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        profile["route"]["rules"] = json!([
            { "inbound": [PROBE_TAG], "outbound": TRADE_EXIT },
            { "action": "route", "inbound": [MIXED_TAG], "outbound": DAILY_EXIT },
            { "action": "route", "inbound": [PROBE_TAG], "outbound": TRADE_EXIT }
        ]);
        std::fs::write(&line, profile.to_string()).unwrap();
        let path = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect("equivalent legacy duplicate probe rules must not break connection");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rules = eff["route"]["rules"].as_array().unwrap();
        let probes: Vec<_> = rules.iter().filter(|r| {
            r["inbound"].as_array().is_some_and(|tags| tags.iter().any(|tag| tag == PROBE_TAG))
        }).collect();
        assert_eq!(probes.len(), 1, "only one canonical probe route remains: {rules:?}");
        assert_eq!(rules[0]["inbound"], json!([PROBE_TAG]));
        assert_eq!(rules[0]["outbound"], TRADE_EXIT);
        assert_eq!(rules[1]["inbound"], json!([MIXED_TAG]), "mixed route preserved");
        assert_eq!(rules[1]["outbound"], DAILY_EXIT);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tc_check_duplicate_routes_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-tc-check-route-duplicate-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let runtime = root.join("runtime-engine.json");
        let mut profile = profile_with_exits();
        profile["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        profile["route"]["rules"] = json!([
            { "inbound": [PROBE_TAG], "outbound": TRADE_EXIT },
            { "inbound": [PROBE_TAG], "outbound": DAILY_EXIT }
        ]);
        std::fs::write(&line, profile.to_string()).unwrap();
        let error = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &runtime, "",
            Some(("synthetic-user", "synthetic-password")), Some(18003)
        ).expect_err("multiple probe routes must fail closed");
        assert!(error.contains("tc-check"), "{error}");
        assert!(!runtime.exists(), "unsafe runtime configuration must not be published");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn probe_inbound_is_not_added_when_mixed_port_unknown() {
        // 算不出探测端口（没有 mixed 入站）→ 不补入站，**也不能留下指向不存在入站的规则**
        // （悬空 inbound 规则会让引擎整体起不来）。
        let mut p = profile();
        p["inbounds"] = json!([]);
        let mut obj = p.as_object().unwrap().clone();
        assert!(!inject_probe_creds(&mut obj, "u", "p", None), "算不出端口就不能说「有变化」");
        let dangling = obj["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| {
                r["inbound"]
                    .as_array()
                    .map(|a| a.iter().any(|v| v.as_str() == Some(PROBE_TAG)))
                    .unwrap_or(false)
            });
        assert!(!dangling, "不许留下悬空的探测规则：{}", obj["route"]["rules"]);
    }

    #[test]
    fn actual_mode_reads_the_inbounds_not_the_global_flag() {
        let dir = std::env::temp_dir().join(format!("tcrs-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let p = dir.join("tun.json");
        std::fs::write(&p, r#"{"inbounds":[{"type":"tun","tag":"t"},{"type":"mixed"}]}"#).unwrap();
        assert_eq!(actual_mode(&p), Some(Mode::Tun));

        let p = dir.join("proxy.json");
        std::fs::write(&p, r#"{"inbounds":[{"type":"mixed","tag":"tc-mixed"}]}"#).unwrap();
        assert_eq!(actual_mode(&p), Some(Mode::Proxy));

        // 读不到 / 坏文件 / 没有 inbounds：一律 None，由调用方回落到配置值
        assert_eq!(actual_mode(&dir.join("missing.json")), None);
        let p = dir.join("bad.json");
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(actual_mode(&p), None);
        let p = dir.join("empty.json");
        std::fs::write(&p, r#"{"outbounds":[]}"#).unwrap();
        assert_eq!(actual_mode(&p), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_room_rejects_ports_that_leave_no_space_for_the_probe() {
        assert!(validate_probe_room(1).is_ok());
        assert!(validate_probe_room(65_532).is_ok(), "65532 是留出 +3 的最后一档");
        let e = validate_probe_room(65_533).unwrap_err();
        assert_eq!(e, PROBE_ROOM_MSG, "文案是定稿：{e}");
        assert!(validate_probe_room(65_535).is_err());
    }

    #[test]
    fn probe_port_must_be_bindable_at_import_time() {
        // 挑一对都空的端口（port 与 port+3）：随机端口的 +3 可能溢出，固定端口可能被本机占用。
        let base = (20_000..60_000u16)
            .find(|p| {
                std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok()
                    && std::net::TcpListener::bind(("127.0.0.1", p + 3)).is_ok()
            })
            .expect("找一对空闲端口");
        let probe = base + 3;

        // 试绑判定：占住「端口+3」就必须拒绝，并说清是哪个端口不可用、该怎么做。
        let holder = std::net::TcpListener::bind(("127.0.0.1", probe)).unwrap();
        let e = validate_probe_port_free(base).unwrap_err();
        assert_eq!(
            e,
            format!("端口 {base} 不可用：它的自检探测端口 {probe} 已被占用或被系统预留。请换一个线路端口。"),
            "文案是定稿"
        );

        // 放掉之后必须通过，且**不能**把端口留成占用态（试绑要立刻释放）。
        drop(holder);
        validate_probe_port_free(base).expect("释放后应当通过");
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", probe)).is_ok(),
            "校验通过之后端口必须仍然是空的"
        );
    }

    #[test]
    fn prepare_injects_fresh_creds_on_every_connect() {
        // 两次连接必须拿到**不同**的探测凭据，且每次都产出运行时配置（凭据新鲜 → 不许走"无变化"捷径）。
        let root = std::env::temp_dir().join(format!("tcrs-prep-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let out = root.join("runtime-engine.json");
        // 线路文件带探测入站（导入时生成的样子：不带 users）
        let mut p = profile_with_exits();
        p["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": 18003 }
        ]);
        std::fs::write(&line, p.to_string()).unwrap();

        let mut seen = Vec::new();
        for (u, pw) in [("user-A", "pass-A"), ("user-B", "pass-B")] {
            let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", Some((u, pw)), None)
                .unwrap();
            assert_eq!(got, out, "注入凭据必须产出运行时配置（不走原文件捷径）");
            let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
            let probe = eff["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["tag"] == PROBE_TAG)
                .expect("运行时配置必须有探测入站");
            assert_eq!(probe["users"][0]["username"], u);
            assert_eq!(probe["users"][0]["password"], pw);
            // 没给端口（None）= 老行为：线路文件里的 `+3` 一个字节都不动
            assert_eq!(probe["listen_port"], 18003, "没给显式端口时不许改监听端口：{probe}");
            seen.push(probe["users"][0]["username"].as_str().unwrap().to_string());
        }
        assert_ne!(seen[0], seen[1], "两次连接的用户名必须不同");
        // 线路文件本身一个字节都不能动（凭据不落配置文件）
        let line_raw = std::fs::read_to_string(&line).unwrap();
        assert!(!line_raw.contains("user-A") && !line_raw.contains("pass-A"), "{line_raw}");

        // None（探测端口被占）：探测入站与规则必须从运行时配置里摘掉
        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None).unwrap();
        assert_eq!(got, out, "摘除也必须产出运行时配置");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(
            !eff["inbounds"].as_array().unwrap().iter().any(|i| i["tag"] == PROBE_TAG),
            "端口被占时必须摘掉探测入站（引擎对绑不上的入站是 FATAL）：{eff}"
        );
        assert!(
            !eff["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["inbound"][0] == PROBE_TAG),
            "摘入站要连规则一起摘，别留下悬空规则：{eff}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 关键不变量：**引擎配置里写的探测端口 == 自检计划要拨的端口**。
    ///
    /// 这条最容易在「`+3` 回落到动态端口」时分叉：一处仍算 `+3`、一处用计划值，
    /// 结果引擎听 A、自检拨 B，用户看到的是「探测端口上没有监听」——把环境问题
    /// 报成产品坏了。所以两处必须由同一个 `plan.port` 驱动。
    #[test]
    fn engine_probe_port_equals_the_port_the_plan_will_dial() {
        let root = std::env::temp_dir().join(format!("tcrs-prep-port-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let out = root.join("runtime-engine.json");

        // 占住一个端口当「`+3` 被别的程序占着」：plan 会回落到动态端口。
        let squatter = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = squatter.local_addr().unwrap().port();
        let endpoint_port = taken.checked_sub(3).expect("探测端口 = 端点 + 3");

        let mut p = profile_with_exits();
        p["inbounds"] = json!([
            { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": endpoint_port },
            { "type": "socks", "tag": PROBE_TAG, "listen": "127.0.0.1", "listen_port": taken }
        ]);
        std::fs::write(&line, p.to_string()).unwrap();

        let plan = crate::selfcheck::plan_probe(&format!("127.0.0.1:{endpoint_port}"));
        let crate::selfcheck::ProbePlan::Dial { port: planned, username, password } = &plan else {
            panic!("`+3` 被占时必须回落到动态端口，不该跳过：{plan:?}");
        };
        assert_ne!(*planned, taken, "回落之后的端口不能还是被占的那个");

        // 旧文件里写的是 `+3`（= taken）；计划说 planned。引擎配置必须听 planned。
        prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", Some((username, password)), Some(*planned))
            .unwrap();
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let probe = eff["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == PROBE_TAG)
            .expect("运行时配置必须有探测入站");
        assert_eq!(probe["listen_port"], *planned, "引擎监听的必须是自检要拨的那个端口：{probe}");
        drop(squatter);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 代理形状的线路（`profile()` 去掉 TUN 入站）：这条用例只测"分流有无变化"，
    /// 不能把"接管方式裁剪"混进来——那部分由 `apply_mode`/`prepare_applies_...` 单独钉。
    fn proxy_profile() -> Value {
        let mut p = profile();
        let kept: Vec<Value> = p["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["type"] != "tun")
            .cloned()
            .collect();
        p["inbounds"] = Value::Array(kept);
        p
    }

    #[test]
    /// C2 剩余：只给「要拨服务器」的出站绑网卡；直连/选择器不碰；空网卡一个字段都不写。
    /// 交易域名必须**在隧道里**解析（原版模型）：本地 DNS 已被污染，先本地解析就全错。
    #[test]
    fn trade_domains_resolve_through_the_tunnel() {
        let cfg = crate::config::parse(
            r#"{"schema":2,"split":{
                "domains":[{"value":"tradingview.com","target":"trade"},
                           {"value":"bilibili.com","target":"daily"}],
                "processes":[{"value":"Mirasim.exe","target":"trade"}]}}"#,
        )
        .unwrap();
        let mut obj = serde_json::json!({
            // 有中转出站才谈得上「经隧道解析」（标准档没有它，DNS 保持原样）。
            "outbounds": [{"type":"vless","tag":"tc-transport","server":"203.0.113.9","server_port":8443}],
            "dns": {"servers":[{"type":"local","tag":"dns-direct"}]},
            "route": {"rules": [{"inbound":["tc-check"],"outbound":"trade-exit"}], "final":"daily-exit"}
        })
        .as_object_mut()
        .unwrap()
        .clone();
        normalize_dns_trade(&mut obj, &cfg.split, &cfg.agents);

        let servers = obj["dns"]["servers"].as_array().unwrap();
        let trade = servers
            .iter()
            .find(|s| s["tag"] == serde_json::json!("dns-trade"))
            .expect("必须有 dns-trade");
        assert_eq!(trade["type"], serde_json::json!("udp"), "隧道里 UDP 直接透传，少一层失败点");
        assert_eq!(trade["detour"], serde_json::json!("hk"), "detour 必须是隧道端点本身");
        assert_eq!(trade["server"], serde_json::json!("1.1.1.1"), "经隧道问公共解析器（不依赖服务器配置）");
        assert_eq!(obj["dns"]["final"], serde_json::json!("dns-trade"), "所有域名都经隧道解析");

        let rules = obj["dns"]["rules"].as_array().unwrap();
        let domains = rules
            .iter()
            .find(|r| r.get("domain_suffix").is_some())
            .expect("必须有域名规则");
        let list = domains["domain_suffix"].as_array().unwrap();
        assert!(list.iter().any(|d| d == "tradingview.com"));
        assert!(!list.iter().any(|d| d == "bilibili.com"), "日常域名不许进交易 DNS");
        assert_eq!(domains["server"], serde_json::json!("dns-trade"));

        assert_eq!(
            obj["route"]["default_domain_resolver"]["server"],
            serde_json::json!("dns-direct")
        );
    }

    #[test]
    fn bind_interface_only_touches_outbounds_that_dial_a_server() {
        let mut obj = serde_json::json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "socks", "tag": "proxy", "server": "203.0.113.10", "server_port": 1080},
                {"type": "selector", "tag": "trade-exit", "outbounds": ["proxy", "direct"]},
                {"type": "socks", "tag": "blank", "server": "  ", "server_port": 1080},
                {"type": "socks", "tag": "local", "server": "127.0.0.1", "server_port": 1080}
            ]
        })
        .as_object_mut()
        .unwrap()
        .clone();

        assert!(apply_bind_interface(&mut obj, "以太网"), "第一次应当有变化");
        let outs = obj.get("outbounds").and_then(Value::as_array).unwrap();
        assert_eq!(outs[0].get("bind_interface"), None, "直连没有 server，不碰");
        assert_eq!(outs[1]["bind_interface"], serde_json::json!("以太网"));
        assert_eq!(outs[2].get("bind_interface"), None, "选择器没有 server，不碰");
        assert_eq!(outs[3].get("bind_interface"), None, "空 server 不算要拨号");
        assert_eq!(
            outs[4].get("bind_interface"),
            None,
            "回环服务器不能绑网卡（绑了就连不上自己）"
        );

        assert!(!apply_bind_interface(&mut obj, "以太网"), "同值不算变化（幂等）");
        // **空网卡 = 不绑**：必须把文件里残留的绑定清掉。
        // 旧契约是「空网卡不许抹掉已有值」，真机上就是它把一条导入线路的
        // `wireless_32768` 留在配置里，sing-box 解析不到接口 →
        // 所有出站报 `route ip+net: no such network interface` → 隧道完全建不起来。
        assert!(
            apply_bind_interface(&mut obj, "  "),
            "空网卡要把残留绑定清掉，这算一次变化"
        );
        assert_eq!(
            obj["outbounds"][1].get("bind_interface"),
            None,
            "空网卡必须抹掉文件里的绑定（旧版也是 Remove('bind_interface')）"
        );
    }

    /// 找一个真的引擎程序（见调用处注释）。找不到返回 `None`。
    fn find_engine_binary() -> Option<std::path::PathBuf> {
        let mut candidates: Vec<std::path::PathBuf> = vec![
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bin").join("sing-box.exe"),
            std::path::PathBuf::from(r"C:\SpiderVPN\bin\sing-box.exe"),
        ];
        // `dist\SpiderVPN-*-windows-x64\sing-box.exe`：取目录名最大的那份（版本号最大）。
        let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("dist");
        let mut packaged: Vec<std::path::PathBuf> = std::fs::read_dir(&dist)
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .map(|entry| entry.path().join("sing-box.exe"))
                    .filter(|path| path.is_file())
                    .collect()
            })
            .unwrap_or_default();
        packaged.sort();
        candidates.extend(packaged.into_iter().rev());
        candidates.into_iter().find(|path| path.is_file())
    }

    /// 生成的运行时配置能被真引擎接受（`sing-box check`）。
    ///
    /// 这条不做「真的绑上了没有」——那要真机路由。它只证明**写进去的是一个合法字段**，
    /// 不会让引擎起不来。引擎程序不在本机时跳过（不同开发机上不该因此变红）。
    #[test]
    fn the_generated_config_with_bind_interface_passes_the_engine_check() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-bind-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        std::fs::write(
            &line,
            serde_json::json!({
                "log": {"level": "warn"},
                "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "socks", "tag": "proxy", "server": "203.0.113.10",
                     "server_port": 1080, "version": "5"}
                ],
                "route": {"rules": [], "final": "proxy"}
            })
            .to_string(),
        )
        .unwrap();
        let out = root.join("runtime-engine.json");
        let got = prepare_engine_config(
            &line,
            &SplitConfig::default(),
            &crate::config::AgentsConfig::default(),
            Transport::Udp,
            Mode::Proxy,
            &out,
            "以太网",
            None,
            None,
        )
        .unwrap();
        let text = std::fs::read_to_string(&got).unwrap();
        assert!(
            text.contains("\"bind_interface\": \"以太网\""),
            "运行时配置里没写 bind_interface：\n{text}"
        );

        // 引擎程序不在源码树里（它随包分发）。按「开发机上真实存在的顺序」找：
        // 源码 `bin\` → 已装机的 `C://SpiderVPN//bin//` → `dist\` 里最新的包。
        // 一个都找不到时**跳过并说明**：不同机器上不该因为没引擎而变红，但也不能装作验过。
        let Some(binary) = find_engine_binary() else {
            eprintln!(
                "跳过 sing-box check：本机找不到引擎程序（源码 bin\\ 与 C:////SpiderVPN////bin//// 都没有）"
            );
            let _ = std::fs::remove_dir_all(&root);
            return;
        };
        eprintln!("用 {} 校验生成的配置", binary.display());
        let output = std::process::Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&got)
            .output();
        let Ok(output) = output else {
            let _ = std::fs::remove_dir_all(&root);
            return;
        };
        assert!(
            output.status.success(),
            "sing-box check 拒绝了我们生成的配置：{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn prepare_engine_config_rewrites_only_when_something_changes() {
        let root = std::env::temp_dir().join(format!("tcrs-prep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let out = root.join("runtime-engine.json");

        // ① 空规则 + 文件里也没有我们的规则 → 原样返回原路径，连新文件都不落
        std::fs::write(&line, proxy_profile().to_string()).unwrap();
        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None).unwrap();
        assert_eq!(got, line, "没有变化时要复用原文件（行为与加功能之前一致）");
        assert!(!out.exists(), "没有变化时不该产出运行时配置");

        // ② 文件里有旧规则、配置里已删空 → 必须重写，规则被清掉（"磁盘是唯一事实来源"）
        let mut with_rules = proxy_profile();
        normalize_split(
            with_rules.as_object_mut().unwrap(),
            &split_with("curl.exe"),
            &crate::config::AgentsConfig::default(),
        );
        std::fs::write(&line, with_rules.to_string()).unwrap();
        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None).unwrap();
        assert_eq!(got, out, "有变化时要产出运行时配置");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(
            !eff["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.get("process_name").is_some()),
            "配置里没有规则时，陈旧规则必须被清掉：{eff}"
        );

        // ③ 文件是旧的（没有规则）、配置里有 → 连接用的那份必须含规则
        std::fs::write(&line, proxy_profile().to_string()).unwrap();
        let got = prepare_engine_config(&line, &split_with("curl.exe"), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None).unwrap();
        assert_eq!(got, out);
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(eff["route"]["rules"][0]["process_name"][0], "curl.exe", "{eff}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prepare_rejects_missing_or_non_object_line_config() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-prepare-fail-{}", std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("bad-line.json");
        let out = root.join("runtime-engine.json");

        let missing = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &out, "", None, None,
        ).unwrap_err();
        assert!(missing.contains("无法读取线路引擎配置"), "{missing}");
        assert!(!out.exists(), "读取失败不许生成运行时配置");

        std::fs::write(&line, "[]").unwrap();
        let invalid_root = prepare_engine_config(
            &line, &SplitConfig::default(), &crate::config::AgentsConfig::default(),
            Transport::Udp, Mode::Proxy, &out, "", None, None,
        ).unwrap_err();
        assert!(invalid_root.contains("根节点必须是 JSON 对象"), "{invalid_root}");
        assert!(!out.exists(), "非法配置不许生成运行时配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_split_generates_byte_identical_config() {
        // 没有分流规则时，生成结果必须与本功能上线前**一字不差**。
        let out =
            generate(&profile().to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        // 标准档不碰 dns（隧道 DNS 只在有中转出站时才写）：整个输出与上线前逐字节相同。
        assert_eq!(out, GOLDEN_PROXY_NO_SPLIT, "空规则时生成结果不许有任何变化");
        let v: Value = serde_json::from_str(&out).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert!(
            !rules
                .iter()
                .any(|r| r.get("process_name").is_some() || r.get("domain_suffix").is_some()),
            "空规则不许生成分流规则：{rules:?}"
        );
    }

    /// 带两个选择器的现场（模拟真实线路文件）。成员名取自 旧版的形状。
    fn profile_with_exits() -> Value {
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "vless", "tag": "hk", "server": "198.51.100.10", "server_port": 443 },
            { "type": "vless", "tag": "provider2", "server": "198.51.100.11", "server_port": 443 },
            { "type": "selector", "tag": "trade-exit", "outbounds": ["hk", "provider2"], "default": "hk" },
            { "type": "selector", "tag": "daily-exit", "outbounds": ["direct", "hk", "provider2"], "default": "direct" }
        ]);
        // 旧版线路文件里那条"交易程序走 trade-exit"，我们一个字都不改
        p["route"]["rules"] = json!([
            { "process_path": ["C:////TDXW////TDXW.exe"], "outbound": "trade-exit" },
            { "action": "route", "outbound": "daily-exit" }
        ]);
        p
    }

    /// 生成 + 解析。**名单为空**（既有用例的口径：加名单功能之前的行为一字不差）。
    fn gen(p: &Value, split: &SplitConfig, exits: &Exits) -> Value {
        gen_agents(p, split, &crate::config::AgentsConfig::default(), exits)
    }

    /// 生成 + 解析，带 AI 工具名单。
    fn gen_agents(
        p: &Value,
        split: &SplitConfig,
        agents: &crate::config::AgentsConfig,
        exits: &Exits,
    ) -> Value {
        serde_json::from_str(
            &generate(&p.to_string(), 18000, Mode::Proxy, split, agents, exits).unwrap(),
        )
        .unwrap()
    }

    /// 按形状数出「名单产生的规则」：`outbound` + 选择条件（进程/域名），不含别的键，
    /// 且 `outbound` 指向我们的出口（常量两个 + 入参 obj 里现算的 direct 集合）。
    /// 数的口径是**条数与值**，不是「字符串里有没有出现」。
    fn our_rules(obj: &Value) -> Vec<Value> {
        let direct_tags = obj.as_object().map(direct_outbound_tags).unwrap_or_default();
        obj["route"]["rules"]
            .as_array()
            .map(|list| list.iter().filter(|r| is_ours(r, &direct_tags)).cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn exit_set_writes_the_selector_default() {
        // `--exit-set trade hk` / `--exit-set daily provider2` → 两个选择器的 default 被改写
        let exits = Exits { trade: Some("hk".into()), daily: Some("provider2".into()) };
        let v = gen(&profile_with_exits(), &SplitConfig::default(), &exits);
        let outs = v["outbounds"].as_array().unwrap();
        let sel = |tag: &str| {
            outs.iter().find(|o| o["tag"] == tag).unwrap()["default"].as_str().unwrap().to_string()
        };
        assert_eq!(sel("trade-exit"), "hk");
        assert_eq!(sel("daily-exit"), "provider2");
    }

    #[test]
    fn exit_set_rejects_a_member_outside_the_selector() {
        // 成员不在可选范围里 → 报错，且错误里带可选范围（用户能照着改）
        let exits = Exits { trade: Some("hk2".into()), daily: None };
        let mut p = profile_with_exits();
        let obj = p.as_object_mut().unwrap();
        let err = apply_exits(obj, &exits).unwrap_err();
        assert!(err.contains("出口 hk2 不在交易出口的可选范围"), "{err}");
        assert!(err.contains("hk") && err.contains("provider2"), "要列出可选范围：{err}");
    }

    #[test]
    fn read_exits_reports_defaults_and_members() {
        let p = profile_with_exits();
        let info = read_exits(p.as_object().unwrap()).expect("应当读到两个选择器");
        assert_eq!(info.trade, "hk");
        assert_eq!(info.daily, "direct");
        assert_eq!(info.trade_members, vec!["hk".to_string(), "provider2".to_string()]);
        assert_eq!(
            info.daily_members,
            vec!["direct".to_string(), "hk".to_string(), "provider2".to_string()]
        );
    }

    #[test]
    fn split_target_trade_and_daily_map_to_the_selectors() {
        let mut split = SplitConfig::default();
        split.add_process("b.exe", SplitTarget::Trade);
        split.add_domain("qq.com", SplitTarget::Daily);
        let v = gen(&profile_with_exits(), &split, &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["process_name"][0], "b.exe", "{rules:?}");
        assert_eq!(rules[0]["outbound"], TRADE_EXIT, "target=trade 要指 trade-exit");
        assert_eq!(rules[1]["domain_suffix"][0], "qq.com");
        assert_eq!(rules[1]["outbound"], DAILY_EXIT, "target=daily 要指 daily-exit");
    }

    #[test]
    fn legacy_plain_string_entries_still_mean_direct() {
        // 兼容：旧配置里的裸字符串读进来就是 target=direct，生成规则仍指直连出站。
        let old: SplitConfig =
            serde_json::from_str(r#"{"processes":["a.exe"],"domains":["qq.com"]}"#).unwrap();
        assert_eq!(old.processes[0].target(), SplitTarget::Direct);
        assert_eq!(old.domains[0].target(), SplitTarget::Direct);
        let v = gen(&profile_with_exits(), &old, &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outbound"], "direct", "{rules:?}");
        assert_eq!(rules[1]["outbound"], "direct", "{rules:?}");
    }

    #[test]
    fn mixed_targets_produce_one_rule_per_target() {
        let mut split = SplitConfig::default();
        split.add_process("a.exe", SplitTarget::Direct);
        split.add_process("b.exe", SplitTarget::Trade);
        split.add_process("c.exe", SplitTarget::Daily);
        let v = gen(&profile_with_exits(), &split, &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        // direct → trade → daily，三组各一条
        assert_eq!(rules[0]["outbound"], "direct");
        assert_eq!(rules[1]["outbound"], TRADE_EXIT);
        assert_eq!(rules[2]["outbound"], DAILY_EXIT);
        assert_eq!(rules[3]["inbound"][0], PROBE_TAG, "探测规则在分流之后：{rules:?}");
        assert_eq!(rules[4]["inbound"][0], MIXED_TAG, "分流规则仍排在入站之前：{rules:?}");
    }

    #[test]
    fn split_process_rule_routes_to_the_existing_direct_outbound() {
        let mut split = SplitConfig::default();
        split.add_process("TDXW.exe", SplitTarget::Direct);
        let v: Value = serde_json::from_str(
            &generate(&profile().to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap(),
        )
        .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["process_name"][0], "TDXW.exe", "进程规则要在最前面：{rules:?}");
        assert_eq!(rules[0]["outbound"], "direct", "要指向已有的 direct 出站");
        // 出站里本来就有一个 direct，不许再追加第二个
        let directs = v["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["type"] == "direct")
            .count();
        assert_eq!(directs, 1, "已有 direct 出站时要复用，不许追加：{}", v["outbounds"]);
    }

    #[test]
    fn split_domain_rule_uses_suffix_without_wildcard() {
        let mut split = SplitConfig::default();
        split.add_domain("*.qq.com", SplitTarget::Direct);
        assert_eq!(split.domains[0].value(), "qq.com", "落盘前就要去掉 *.");
        let v: Value = serde_json::from_str(
            &generate(&profile().to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap(),
        )
        .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["domain_suffix"][0], "qq.com", "要用 domain_suffix：{rules:?}");
        assert_eq!(rules[0]["outbound"], "direct");
        let raw = serde_json::to_string(&v).unwrap();
        assert!(!raw.contains("*.qq.com"), "引擎配置里不许出现通配符原文：{raw}");
    }

    #[test]
    fn missing_direct_outbound_gets_tc_direct_appended() {
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "vless", "tag": "tc-transport", "server": "198.51.100.10", "server_port": 443 },
            { "type": "selector", "tag": "trade-exit", "outbounds": ["tc-transport"], "default": "tc-transport" }
        ]);
        let mut split = SplitConfig::default();
        split.add_process("TDXW.exe", SplitTarget::Direct);
        let v: Value =
            serde_json::from_str(&generate(&p.to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap())
                .unwrap();
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs.last().unwrap()["type"], "direct", "没有 direct 就要补一个：{outs:?}");
        assert_eq!(outs.last().unwrap()["tag"], DIRECT_TAG);
        assert_eq!(v["route"]["rules"][0]["outbound"], DIRECT_TAG);
        // final 仍是节点出口，不能被分流规则带偏
        assert_eq!(v["route"]["final"], "trade-exit");
    }

    #[test]
    fn split_rules_are_generated_in_proxy_mode_too() {
        // 钉住一个容易被"优化"掉的能力：进程规则在**系统代理模式**下同样要写进引擎配置。
        // 实测（2026-10-27，产物 SHA256 7DBFDF39…）proxy 模式下 curl 命中该规则后出口等于直连基线，
        // 说明 sing-box 会按源地址+端口反查发起进程。见 tests/README.md 的同名提醒：
        // **引擎升级后必须重测**，失效时用户会静默失去分流。
        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        let v: Value = serde_json::from_str(
            &generate(&profile().to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap(),
        )
        .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["process_name"][0], "curl.exe", "proxy 模式也要写进程规则：{rules:?}");
        assert_eq!(rules[0]["outbound"], "direct");
    }

    #[test]
    fn both_split_rules_come_before_our_inbound_rules() {
        let mut split = SplitConfig::default();
        split.add_process("TDXW.exe", SplitTarget::Direct);
        split.add_domain("qq.com", SplitTarget::Direct);
        let v: Value = serde_json::from_str(
            &generate(&profile().to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap(),
        )
        .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["process_name"][0], "TDXW.exe", "进程规则第一");
        assert_eq!(rules[1]["domain_suffix"][0], "qq.com", "域名规则第二");
        // 探测规则与我们的入站规则必须排在分流之后，否则分流永远轮不到匹配
        assert_eq!(rules[2]["inbound"][0], PROBE_TAG, "探测规则在分流之后");
        assert_eq!(rules[3]["inbound"][0], MIXED_TAG, "入站规则要在分流之后");
    }

    #[test]
    fn empty_list_does_not_generate_an_empty_rule() {
        let mut split = SplitConfig::default();
        split.add_process("TDXW.exe", SplitTarget::Direct); // 只有进程，没有域名
        let v: Value = serde_json::from_str(
            &generate(&profile().to_string(), 18000, Mode::Proxy, &split, &crate::config::AgentsConfig::default(), &Exits::default()).unwrap(),
        )
        .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert!(
            !rules.iter().any(|r| r.get("domain_suffix").is_some()),
            "没有域名就不许生成域名规则（空数组规则会被引擎判无效）：{rules:?}"
        );
    }

    #[test]
    fn our_inbound_gets_first_priority_rule_to_the_node() {
        // 原文件最后那条 `process_path_regex=.+ => daily-exit`（默认 direct）会把我们的流量判成直连。
        let out = generate(&profile().to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"][0], PROBE_TAG, "第一条是探测入站的规则");
        assert_eq!(rules[0]["outbound"], "trade-exit", "探测固定走交易出口");
        assert_eq!(rules[1]["inbound"][0], MIXED_TAG, "第二条必须针对我们的 mixed 入站");
        assert_eq!(rules[1]["outbound"], "trade-exit", "必须指向节点出口，不能是 direct");
    }

    #[test]
    fn final_outbound_points_at_a_real_node_not_direct() {
        // 原文件的 final 是 direct，靠 egress-probe 入站规则分流；我们的匿名入站匹配不上，
        // 不改这里的话所有流量都会走直连（实测出口 IP 与直连一致）。
        let out = generate(&profile().to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["route"]["final"], "trade-exit");
    }

    #[test]
    fn inbound_and_final_go_to_daily_exit_even_when_it_is_direct() {
        // **行为反转的锚点**（用户明确要求，2026-10-27）：默认走「日常出口」，而日常出口默认就是直连。
        // 这条与旧版正好相反——旧版把"daily-exit 是 direct"当成事故（那起事故是**用户没选**却被带上车），
        // 现在的语义是"用户选了默认直连"，所以要钉住：入站规则与 final 都指 daily-exit。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": "daily-exit", "outbounds": ["direct", "node-a"], "default": "direct" },
            { "type": "selector", "tag": "trade-exit", "outbounds": ["node-a"], "default": "node-a" },
            { "type": "vless", "tag": "node-a", "server": "198.51.100.10", "server_port": 443 }
        ]);
        let out = generate(&p.to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default())
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["route"]["final"], "daily-exit", "final 要指日常出口（默认直连）");
        let rules = v["route"]["rules"].as_array().unwrap();
        let inbound_rules: Vec<&Value> =
            rules.iter().filter(|r| r.get("inbound").is_some()).collect();
        assert!(!inbound_rules.is_empty(), "要有我们家入站的规则：{rules:?}");
        for r in inbound_rules {
            if r["inbound"][0] == PROBE_TAG {
                // 唯一的例外：探测入站存在的意义就是证明交易出口那条链，必须固定指向它
                assert_eq!(r["outbound"], "trade-exit", "探测入站固定走交易出口：{r}");
                continue;
            }
            assert_eq!(r["outbound"], "daily-exit", "我们的入站也走日常出口：{r}");
        }
        // 线路文件自带的交易程序规则（指向 trade-exit）**不许被我们改坏**
        assert!(
            rules.iter().any(|r| r["outbound"] == "trade-exit"
                && (r.get("process_path").is_some() || r.get("action").is_some())),
            "profile 自带的 trade-exit 规则必须原样保留：{rules:?}"
        );
    }


    #[test]
    fn daily_exit_is_used_only_when_it_really_is_a_node() {
        // 反过来也要成立：daily-exit 真是节点时，它仍是第二候选（不必强求 trade-exit 存在）。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "vless", "tag": "daily-exit", "server": "198.51.100.11", "server_port": 443 },
            { "type": "vless", "tag": "node-b", "server": "198.51.100.12", "server_port": 443 }
        ]);
        let v: Value =
            serde_json::from_str(&generate(&p.to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap()).unwrap();
        assert_eq!(v["route"]["final"], "daily-exit");
    }

    #[test]
    fn final_outbound_falls_back_when_no_named_exit() {
        let mut p = profile();
        p["outbounds"] = json!([{ "type": "direct", "tag": "direct" },
                                { "type": "vless", "tag": "node-a" }]);
        let out = generate(&p.to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["route"]["final"], "node-a", "没有具名出口时用第一个真实出站");
    }

    #[test]
    fn clash_api_control_port_is_removed_to_avoid_collision() {
        // 旧版的引擎占着 17891；原样带过去会让两份引擎抢同一个控制口。
        let mut p = profile();
        p["experimental"] = json!({
            "clash_api": { "external_controller": "127.0.0.1:17891", "secret": "s" }
        });
        let out = generate(&p.to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("experimental").is_none(), "clash_api 删空后 experimental 也应去掉");
        assert!(!out.contains("17891"), "生成的配置里不该再出现旧控制口");
    }

    #[test]
    fn experimental_with_other_fields_is_kept() {
        let mut p = profile();
        p["experimental"] = json!({
            "clash_api": { "external_controller": "127.0.0.1:17891" },
            "cache_file": { "enabled": true }
        });
        let out = generate(&p.to_string(), 18000, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let exp = v.get("experimental").expect("还有其它字段就要保留");
        assert!(exp.get("clash_api").is_none());
        assert!(exp.get("cache_file").is_some(), "不能顺手把别的字段也删了");
    }

    /// 夹具取真实线路文件的字段子集（节点地址、密钥一律不抄进源码）。
    fn profile() -> Value {
        json!({
            "log": { "level": "warn", "timestamp": true },
            "dns": { "servers": [{ "type": "udp", "tag": "dns-direct", "server": "192.168.1.1" }] },
            "inbounds": [
                {
                    "type": "tun", "tag": "trade-tun", "address": ["172.30.250.1/30"],
                    "mtu": 1380, "auto_route": true, "strict_route": true
                },
                {
                    "type": "mixed", "tag": "egress-probe", "listen": "127.0.0.1",
                    "listen_port": 17000, "users": [{ "username": "probe", "password": "x" }]
                }
            ],
            "endpoints": [{ "type": "wireguard", "tag": "hk" }],
            "route": {
                "rules": [{ "action": "route", "outbound": "trade-exit" }],
                "final": "trade-exit", "auto_detect_interface": true
            },
            "experimental": { "clash_api": { "external_controller": "127.0.0.1:17891" } },
            "outbounds": [
                { "type": "vless", "tag": "tc-transport", "server": "198.51.100.10", "server_port": 443 },
                { "type": "selector", "tag": "trade-exit", "outbounds": ["tc-transport"], "default": "tc-transport" },
                { "type": "direct", "tag": "direct" }
            ]
        })
    }

    #[test]
    fn inbounds_become_one_local_mixed_with_given_port() {
        let out = generate(&profile().to_string(), 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let inb = v["inbounds"].as_array().unwrap();
        assert_eq!(inb.len(), 2, "原入站整体替换成我们的 mixed + 自检探测入站");
        assert_eq!(inb[0]["type"], "mixed");
        assert_eq!(inb[0]["tag"], MIXED_TAG);
        assert_eq!(inb[0]["listen"], "127.0.0.1");
        assert_eq!(inb[0]["listen_port"], 17895);
        assert_eq!(inb[1]["tag"], PROBE_TAG, "探测入站跟在 mixed 后面");
        assert_eq!(inb[1]["listen"], "127.0.0.1");
        assert_eq!(inb[1]["listen_port"], 17895 + 3, "探测端口 = 线路端口 + 3");
        assert!(out.contains('\n'), "要格式化输出，出问题时人能直接看");
    }

    #[test]
    fn outbounds_route_dns_endpoints_are_kept() {
        let src = profile();
        let v: Value = serde_json::from_str(&generate(&src.to_string(), 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap()).unwrap();
        // experimental 单独处理：clash_api 必须被删（控制口与旧版冲突），
        // 其余字段仍要一字不动，这条由 experimental_with_other_fields_is_kept 覆盖。
        for key in ["outbounds", "dns", "endpoints", "log"] {
            assert_eq!(v[key], src[key], "顶层键 {key} 必须一字不动地保留");
        }
        // route 里我们只动三处：final，以及插在最前面的「探测 → 交易出口」「本入站 → 节点」两条。
        // 其余一律原样——这条断言防的是「顺手把别人规则也改了」。
        let (mut vr, mut sr) = (v["route"].clone(), src["route"].clone());
        vr.as_object_mut().unwrap().remove("final");
        sr.as_object_mut().unwrap().remove("final");
        // `default_domain_resolver` 也由我们写（指向 dns-direct，用于解析代理目标本身）。
        vr.as_object_mut().unwrap().remove("default_domain_resolver");
        sr.as_object_mut().unwrap().remove("default_domain_resolver");
        let our_probe = vr["rules"].as_array_mut().unwrap().remove(0);
        assert_eq!(our_probe["inbound"][0], PROBE_TAG, "第一条是我们插的探测规则");
        let our_rule = vr["rules"].as_array_mut().unwrap().remove(0);
        assert_eq!(our_rule["inbound"][0], MIXED_TAG, "第二条是我们自己插的入站规则");
        assert_eq!(vr, sr, "route 里除 final 与我们插的两条规则外必须原样保留");
    }

    #[test]
    fn unknown_top_level_keys_survive() {
        let mut src = profile();
        src["future_key"] = json!({ "enabled": true, "nested": [1, 2] });
        let v: Value = serde_json::from_str(&generate(&src.to_string(), 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap()).unwrap();
        assert_eq!(
            v["future_key"],
            json!({ "enabled": true, "nested": [1, 2] }),
            "引擎将来新增的顶层键，本模块不认识也必须带过去"
        );
    }

    #[test]
    fn missing_outbounds_is_a_chinese_error() {
        for bad in [
            json!({ "inbounds": [], "route": {} }),
            json!({ "outbounds": [] }),
            json!({ "outbounds": "direct" }),
            json!({ "outbounds": {} }),
        ] {
            let e = generate(&bad.to_string(), 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap_err();
            assert!(e.contains("没有 outbounds"), "错误要说清缺什么：{e}");
            assert!(e.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)), "错误必须是中文：{e}");
        }
    }

    #[test]
    fn rejects_port_zero_and_accepts_bounds() {
        let e = generate(&profile().to_string(), 0, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap_err();
        assert!(e.contains("端口"), "{e}");
        assert!(generate(&profile().to_string(), 1, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).is_ok(), "1 是最小合法端口");
        assert!(generate(&profile().to_string(), 65535, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).is_ok(), "65535 是最大合法端口");
    }

    #[test]
    fn broken_json_is_a_chinese_error() {
        for bad in ["{not json", "[]", ""] {
            let e = generate(bad, 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap_err();
            assert!(e.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)), "错误必须是中文：{e}");
        }
    }

    #[test]
    fn tun_mode_keeps_the_original_tun_inbound_untouched() {
        let src = profile();
        let v: Value =
            serde_json::from_str(&generate(&src.to_string(), 17895, Mode::Tun, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap()).unwrap();
        let inb = v["inbounds"].as_array().unwrap();
        assert_eq!(inb.len(), 3, "TUN 入站留着；带 users 的认证入站删掉；末尾补探测入站");
        // address/mtu/stack/auto_route 都是 旧版调好的，一个字节都不许动；
        // 唯一允许改的是网卡名——它必须和旧版的 `TradeChannel` 区分开。
        assert_eq!(inb[0]["address"], src["inbounds"][0]["address"]);
        assert_eq!(inb[0]["mtu"], src["inbounds"][0]["mtu"]);
        assert_eq!(inb[0]["stack"], src["inbounds"][0]["stack"]);
        assert_eq!(inb[0]["auto_route"], src["inbounds"][0]["auto_route"]);
        assert_eq!(inb[0]["interface_name"], TUN_INTERFACE);
        assert_ne!(
            inb[0]["interface_name"], src["inbounds"][0]["interface_name"],
            "网卡名刻意不沿用原文件的，避免与旧版同名混淆"
        );
        assert_eq!(inb[0]["type"], "tun");
        assert_eq!(inb[0]["tag"], "trade-tun");
        assert_eq!(inb[1]["type"], "mixed", "系统代理那条路也要保留，两条路并存");
        assert_eq!(inb[1]["tag"], MIXED_TAG);
        assert_eq!(inb[1]["listen_port"], 17895);
        assert_eq!(inb[2]["tag"], PROBE_TAG, "探测入站排在最后");
        assert_eq!(inb[2]["listen_port"], 17895 + 3);
    }

    #[test]
    fn tun_mode_routes_tun_and_mixed_traffic_to_the_node_first() {
        let v: Value =
            serde_json::from_str(&generate(&profile().to_string(), 17895, Mode::Tun, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap())
                .unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"][0], PROBE_TAG, "第一条是探测规则");
        assert_eq!(rules[1]["inbound"][0], MIXED_TAG, "第二条是我们 mixed 那条");
        assert_eq!(rules[2]["inbound"][0], "trade-tun", "第三条是 TUN 入站");
        for r in &rules[..3] {
            assert_eq!(r["outbound"], "trade-exit", "三条都必须指向节点，否则会落到原文件的直连上");
        }
        // 探测规则不带 action（route 是默认动作）；我们自己的两条显式带着
        assert_eq!(rules[1]["action"], "route");
        assert_eq!(rules[2]["action"], "route");
    }

    #[test]
    fn proxy_mode_still_has_no_tun_inbound() {
        // 回归保护：proxy 模式带进 TUN 入站就等于偷偷要管理员权限、偷偷改路由。
        let v: Value =
            serde_json::from_str(&generate(&profile().to_string(), 17895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap())
                .unwrap();
        let inb = v["inbounds"].as_array().unwrap();
        assert_eq!(inb.len(), 2, "mixed + 探测入站");
        assert!(inb.iter().all(|i| i["type"] != "tun"), "代理模式不许出现 TUN 入站");
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"][0], PROBE_TAG, "第一条是探测规则");
        assert_eq!(rules[1]["inbound"][0], MIXED_TAG);
        assert!(
            rules.iter().all(|r| r["inbound"][0] != "trade-tun"),
            "代理模式不该有 TUN 那条规则"
        );
    }

    #[test]
    fn tun_mode_without_tun_inbound_fails_loudly() {
        let mut p = profile();
        p["inbounds"] = json!([{ "type": "mixed", "tag": "egress-probe" }]);
        let e = generate(&p.to_string(), 17895, Mode::Tun, &SplitConfig::default(), &crate::config::AgentsConfig::default(), &Exits::default()).unwrap_err();
        assert!(e.contains("TUN"), "要说清是 TUN 入站缺失：{e}");
        assert!(e.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)), "错误必须是中文：{e}");
    }

    // ---------- 连接方式：标准连接（Udp）/ 兼容连接（Tcp）----------

    /// 标准连接那份：只有 WireGuard endpoint，没有任何中转参数。
    fn udp_line() -> Value {
        json!({
            "log": { "level": "warn" },
            "dns": { "servers": [{ "type": "udp", "tag": "dns-direct", "server": "192.168.1.1" }] },
            "inbounds": [
                { "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 18000 }
            ],
            "endpoints": [
                { "type": "wireguard", "tag": "hk", "address": ["10.7.0.2/32"] },
                { "type": "wireguard", "tag": "jp", "address": ["10.8.0.2/32"] }
            ],
            "outbounds": [
                { "type": "selector", "tag": TRADE_EXIT, "outbounds": ["hk", "jp"], "default": "hk" },
                { "type": "direct", "tag": "direct" }
            ],
            "route": { "rules": [{ "action": "route", "outbound": TRADE_EXIT }], "final": TRADE_EXIT }
        })
    }

    /// 参数齐全的 vless 出站（VLESS + REALITY）。tag 由调用方给：
    /// `tc-transport` = 旧版派生好的形状；别的名字 = 用户自己的中转出站。
    fn transit_outbound(tag: &str) -> Value {
        json!({
            "type": "vless", "tag": tag,
            "server": "203.0.113.7", "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "tls": {
                "enabled": true, "server_name": "cdn.example.com",
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": {
                    "enabled": true,
                    // 43 位 base64url：REALITY 公钥的形状（32 字节）
                    "public_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1",
                    "short_id": "ab12"
                }
            }
        })
    }

    /// 线路文件里带着中转参数，但那条出站还没被当成中转用（tag 不是 `tc-transport`）。
    fn params_line() -> Value {
        prepend_outbound(udp_line(), transit_outbound("provider-a"))
    }

    /// 旧版派生好的兼容连接线路：中转出站已经在里面，tag 就是 `tc-transport`。
    fn tcp_line() -> Value {
        prepend_outbound(udp_line(), transit_outbound(TRANSPORT_TAG))
    }

    fn prepend_outbound(mut p: Value, outbound: Value) -> Value {
        let mut outbounds = p["outbounds"].as_array().unwrap().clone();
        outbounds.insert(0, outbound);
        p["outbounds"] = Value::Array(outbounds);
        p
    }

    fn apply(p: &Value, t: Transport) -> (Result<bool, String>, Value) {
        let mut v = p.clone();
        let r = apply_transport(v.as_object_mut().unwrap(), t);
        (r, v)
    }

    #[test]
    fn actual_transport_accepts_only_complete_unambiguous_runtime_shapes() {
        let root = std::env::temp_dir().join(format!("tcrs-actual-transport-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("runtime-engine.json");
        let read = |v: &Value| {
            std::fs::write(&path, v.to_string()).unwrap();
            actual_transport(&path)
        };

        assert_eq!(read(&params_line()), Some(Transport::Udp), "全部 WireGuard endpoint 直连才是标准连接");
        let (_, compatible) = apply(&params_line(), Transport::Tcp);
        assert_eq!(read(&compatible), Some(Transport::Tcp), "完整中转链才是兼容连接");

        let mut mixed = compatible.clone();
        mixed["endpoints"].as_array_mut().unwrap().push(json!({"type":"wireguard","tag":"hk-2"}));
        let mut external = compatible.clone();
        external["endpoints"][0]["detour"] = json!("provider-a");
        let mut non_string = compatible.clone();
        non_string["endpoints"][0]["detour"] = json!(7);
        let mut dangling = compatible.clone();
        dangling["outbounds"] = json!([{"type":"direct","tag":"direct"}]);
        let mut wrong_type = compatible.clone();
        wrong_type["outbounds"][0]["type"] = json!("direct");
        let mut incomplete = compatible.clone();
        incomplete["outbounds"][0].as_object_mut().unwrap().remove("uuid");
        let no_wireguard = json!({"endpoints":[{"type":"shadowsocks","tag":"other"}],"outbounds":[]});
        let no_endpoints = json!({"endpoints":[],"outbounds":[]});

        for (name, shape) in [
            ("混合直连与中转", mixed),
            ("依赖其它出站", external),
            ("非字符串 detour", non_string),
            ("悬空中转", dangling),
            ("中转标签被其它类型占用", wrong_type),
            ("中转参数不完整", incomplete),
            ("没有 WireGuard endpoint", no_wireguard),
            ("空 endpoint 列表", no_endpoints),
        ] {
            assert_eq!(read(&shape), None, "{name} 必须报未知，不能猜成两档之一：{shape}");
        }
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(actual_transport(&path), None, "不可读 JSON 必须是未知");
        assert_eq!(actual_transport(&root.join("missing.json")), None, "缺文件必须是未知");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn udp_leaves_a_standard_line_completely_untouched() {
        // 最重要的回归：没选过连接方式的老线路，走标准连接时必须**一个字节都不变**。
        let (r, after) = apply(&udp_line(), Transport::Udp);
        assert_eq!(r.unwrap(), false, "标准连接不该改动标准线路");
        assert_eq!(after, udp_line());
    }

    #[test]
    fn tcp_adds_the_transport_outbound_and_points_every_endpoint_at_it() {
        let (changed, v) = apply(&params_line(), Transport::Tcp);
        assert!(changed.unwrap(), "选兼容连接必须真的改了配置");

        let outbounds = v["outbounds"].as_array().unwrap();
        let first = &outbounds[0];
        assert_eq!(first["type"], "vless", "中转出站排在最前：{first}");
        assert_eq!(first["tag"], TRANSPORT_TAG);
        assert_eq!(first["server"], "203.0.113.7", "参数取自线路文件里那条带 REALITY 的 vless");
        assert_eq!(first["server_port"], 443);
        assert_eq!(first["uuid"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(first["tls"]["enabled"], true);
        assert_eq!(first["tls"]["server_name"], "cdn.example.com");
        assert_eq!(first["tls"]["utls"]["fingerprint"], "chrome", "utls 必须是 chrome（与旧版一致）");
        assert_eq!(first["tls"]["reality"]["enabled"], true);
        assert_eq!(
            first["tls"]["reality"]["public_key"],
            "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1"
        );
        assert_eq!(first["tls"]["reality"]["short_id"], "ab12");
        assert_eq!(
            first["domain_resolver"],
            json!({ "server": "dns-direct", "strategy": "prefer_ipv4" }),
            "线路里有 dns-direct 才写这一项"
        );

        // 每个 WireGuard endpoint 都要挂到中转出站上，一个都不许漏
        let eps = v["endpoints"].as_array().unwrap();
        assert_eq!(eps.len(), 2);
        assert!(
            eps.iter().all(|e| e["detour"] == TRANSPORT_TAG),
            "所有 wireguard endpoint 的 detour 必须指向中转：{eps:?}"
        );
        // 原有出站一个不丢，顺序也不动
        let tags: Vec<&str> = outbounds.iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, vec![TRANSPORT_TAG, "provider-a", "trade-exit", "direct"]);
    }

    #[test]
    fn switching_back_to_udp_undoes_the_transport() {
        let (_, tcp) = apply(&tcp_line(), Transport::Tcp);
        let (changed, back) = apply(&tcp, Transport::Udp);
        assert!(changed.unwrap(), "切回标准连接要真的改回来");
        assert_eq!(back, udp_line(), "一来一回必须回到标准连接那份（中转出站删掉）");
        assert!(
            back["endpoints"].as_array().unwrap().iter().all(|e| e.get("detour").is_none()),
            "endpoint 不许残留 detour：{back}"
        );
    }

    #[test]
    fn applying_tcp_twice_changes_nothing_the_second_time() {
        // 幂等：每次连接都会走一遍派生，第二次必须报"没变"（否则每次都多写一份运行时配置）。
        let (_, once) = apply(&tcp_line(), Transport::Tcp);
        let (again, twice) = apply(&once, Transport::Tcp);
        assert_eq!(again.unwrap(), false, "已经是兼容连接了，不该再变");
        assert_eq!(twice, once);
    }

    #[test]
    fn tcp_refuses_without_transport_parameters_and_says_what_is_missing() {
        // 线路文件里没有 vless 中转参数 → 拒绝，而且要把缺的东西说清楚，不许凑一份半截配置。
        let mut v = udp_line();
        let before = v.clone();
        let e = apply_transport(v.as_object_mut().unwrap(), Transport::Tcp).unwrap_err();
        assert!(is_transport_refusal(&e), "错误必须是「连接方式不可用」：{e}");
        assert!(e.contains("VLESS"), "要说清需要什么：{e}");
        assert_eq!(v, before, "拒绝时配置一个字节都不能动");
    }

    #[test]
    fn tcp_refuses_when_more_than_one_vless_could_be_the_transit() {
        // 两条都带 REALITY 时不许猜：猜错一条就是把交易流量导到另一台服务器上。
        let p = prepend_outbound(params_line(), transit_outbound("provider-b"));
        let mut v = p.clone();
        let e = apply_transport(v.as_object_mut().unwrap(), Transport::Tcp).unwrap_err();
        assert!(e.contains("provider") || e.contains("无法确定"), "{e}");
        assert_eq!(v, p);
    }

    #[test]
    fn tcp_names_the_exact_missing_parameter() {
        // 有 vless 出站但缺字段：错误里要出现那个字段名（否则用户只能猜）。
        let mut p = params_line();
        p["outbounds"][0]["tls"].as_object_mut().unwrap().remove("server_name");
        let mut v = p.clone();
        let e = apply_transport(v.as_object_mut().unwrap(), Transport::Tcp).unwrap_err();
        assert!(e.contains("tls/server_name"), "要指名缺哪个参数：{e}");
        assert_eq!(v, p, "失败时不许留下半截配置");
    }

    #[test]
    fn tcp_refuses_parameters_that_look_valid_but_cannot_work() {
        // uuid / 公钥形状写错属于"能存下去但引擎一定起不来"，必须在派生这一步就挡住。
        for (path, bad) in [
            ("uuid", json!("not-a-guid")),
            ("tls/reality/public_key", json!("tooshort")),
            ("tls/reality/short_id", json!("abc")),
            ("server_port", json!(70000)),
        ] {
            let mut p = params_line();
            let (head, last) = path.rsplit_once('/').unwrap_or(("", path));
            let target = if head.is_empty() {
                p["outbounds"][0].as_object_mut().unwrap()
            } else {
                p["outbounds"][0].pointer_mut(&format!("/{head}")).unwrap().as_object_mut().unwrap()
            };
            target.insert(last.to_string(), bad);
            let mut v = p.clone();
            let e = apply_transport(v.as_object_mut().unwrap(), Transport::Tcp).unwrap_err();
            assert!(is_transport_refusal(&e), "{path} 应该被拒绝：{e}");
            assert_eq!(v, p, "{path}: 失败时不许留下半截配置");
        }
    }

    #[test]
    fn tcp_refuses_to_overwrite_someone_elses_dependency() {
        // endpoint 已经依赖别的出站：不覆盖（那条依赖链我们不了解，改掉可能直接弄坏线路）。
        let mut p = params_line();
        p["endpoints"][0]["detour"] = json!("another-proxy");
        let mut v = p.clone();
        let e = apply_transport(v.as_object_mut().unwrap(), Transport::Tcp).unwrap_err();
        assert!(e.contains("another-proxy"), "要说清是谁占着：{e}");
        assert_eq!(v, p, "拒绝时配置一个字节都不能动");
    }

    #[test]
    fn udp_keeps_the_transport_when_something_else_still_uses_it() {
        // 线路里有选择器还指着 tc-transport：删掉它会变成"引用了不存在的出站"，引擎整体起不来。
        // 所以标准连接只解除我们自己的 detour，别人的引用不动。
        let mut p = tcp_line();
        p["outbounds"][1]["outbounds"] = json!(["hk", "jp", TRANSPORT_TAG]);
        for ep in p["endpoints"].as_array_mut().unwrap() {
            ep["detour"] = json!(TRANSPORT_TAG);
        }
        let (_, v) = apply(&p, Transport::Udp);
        assert!(
            v["endpoints"].as_array().unwrap().iter().all(|e| e.get("detour").is_none()),
            "endpoint 的 detour 必须解除：{v}"
        );
        assert!(
            v["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == TRANSPORT_TAG),
            "还有出站引用它，就不能删：{v}"
        );
    }

    #[test]
    fn transport_outbound_skips_domain_resolver_when_the_line_has_no_dns_direct() {
        // 引用一个不存在的 DNS 标签会让引擎整体起不来，所以线路里没有 dns-direct 就不写这项。
        let mut p = params_line();
        p.as_object_mut().unwrap().remove("dns");
        let (_, v) = apply(&p, Transport::Tcp);
        assert!(v["outbounds"][0].get("domain_resolver").is_none(), "{v}");
    }

    #[test]
    fn prepare_uses_the_selected_transport_for_the_next_connection() {
        // 连接时用选中的那份：Tcp 产出带中转的运行时配置，Udp 什么都不改（用线路文件本身）。
        let root = std::env::temp_dir().join(format!("tcrs-prep-tr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let out = root.join("runtime-engine.json");
        std::fs::write(&line, params_line().to_string()).unwrap();

        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None)
            .unwrap();
        assert_eq!(got, line, "标准连接没有变化时要复用线路文件本身");
        assert!(!out.exists(), "标准连接不该产出运行时配置");

        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Tcp, Mode::Proxy, &out, "", None, None)
            .unwrap();
        assert_eq!(got, out, "兼容连接必须产出运行时配置");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(eff["outbounds"][0]["tag"], TRANSPORT_TAG, "{eff}");
        assert!(
            eff["endpoints"].as_array().unwrap().iter().all(|e| e["detour"] == TRANSPORT_TAG),
            "{eff}"
        );
        // 线路文件本身不许被改成兼容连接（下次切回标准连接还得靠它）
        let raw = std::fs::read_to_string(&line).unwrap();
        assert!(!raw.contains(TRANSPORT_TAG), "派生只能落在运行时配置上，线路文件是标准连接那份：{raw}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 接管方式：连接前按 cfg.mode 拼装/裁剪入站 ----------

    /// 带 TUN 入站的线路（TUN 导入的形状）：tun + mixed。
    fn tun_line() -> Value {
        let mut p = params_line();
        let mut inbounds = p["inbounds"].as_array().unwrap().clone();
        inbounds.insert(
            0,
            json!({ "type": "tun", "tag": "trade-tun", "address": ["172.30.250.1/30"],
                    "mtu": 1380, "stack": "gvisor", "auto_route": true }),
        );
        p["inbounds"] = Value::Array(inbounds);
        p
    }

    #[test]
    fn apply_mode_strips_tun_for_proxy_and_requires_tun_for_tun_mode() {
        // proxy：TUN 入站必须去掉（留着仍要管理员、仍改路由，与用户选的方式不符）
        let mut v = tun_line();
        assert!(apply_mode(v.as_object_mut().unwrap(), Mode::Proxy).unwrap());
        let types: Vec<&str> = v["inbounds"].as_array().unwrap().iter()
            .map(|i| i["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["mixed"], "代理模式只留 mixed：{v}");

        // proxy 再跑一次：没变化（幂等，别每次都重写运行时配置）
        assert!(!apply_mode(v.as_object_mut().unwrap(), Mode::Proxy).unwrap());

        // tun：线路里没有 TUN 入站 → 明确报错（连接前就说清，不等引擎起不来）
        let mut no_tun = params_line();
        let e = apply_mode(no_tun.as_object_mut().unwrap(), Mode::Tun).unwrap_err();
        assert!(is_mode_refusal(&e), "必须是「接管方式不可用」：{e}");
        assert!(e.contains("没有 TUN 入站"), "文案要说清缺什么：{e}");

        // tun：有 TUN 入站 → 保留，并把网卡名改成自己的（与旧版同名会撞网卡）
        let mut v = tun_line();
        assert!(apply_mode(v.as_object_mut().unwrap(), Mode::Tun).unwrap(), "改网卡名算变化");
        let tun = v["inbounds"].as_array().unwrap().iter()
            .find(|i| i["type"] == "tun").expect("TUN 入站要留着");
        assert_eq!(tun["interface_name"], TUN_INTERFACE, "{tun}");
        assert_eq!(tun["mtu"], 1380, "参数是 旧版调好的，一字不动：{tun}");
        // 再跑一次幂等
        assert!(!apply_mode(v.as_object_mut().unwrap(), Mode::Tun).unwrap());
    }

    #[test]
    fn prepare_applies_the_configured_mode_to_the_runtime_inbounds() {
        let root = std::env::temp_dir().join(format!("tcrs-prep-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = root.join("line.json");
        let out = root.join("runtime-engine.json");

        // TUN 形状的线路 + 用户选了代理 → 运行时配置里不许有 TUN
        std::fs::write(&line, tun_line().to_string()).unwrap();
        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Proxy, &out, "", None, None)
            .unwrap();
        assert_eq!(got, out, "模式变了就必须产出运行时配置");
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(
            !eff["inbounds"].as_array().unwrap().iter().any(|i| i["type"] == "tun"),
            "选了代理就不能留 TUN 入站：{eff}"
        );

        // 再选 TUN → 运行时配置里出现 TUN
        let got = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Tun, &out, "", None, None)
            .unwrap();
        assert_eq!(got, out);
        let eff: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(
            eff["inbounds"].as_array().unwrap().iter().any(|i| i["type"] == "tun"),
            "选了 TUN 就必须有 TUN 入站：{eff}"
        );

        // 代理形状的线路 + 用户选了 TUN → 连接前拒绝（错误必须是"硬"的，调用方据此拒绝连接）
        std::fs::write(&line, params_line().to_string()).unwrap();
        let e = prepare_engine_config(&line, &SplitConfig::default(), &crate::config::AgentsConfig::default(), Transport::Udp, Mode::Tun, &out, "", None, None)
            .unwrap_err();
        assert!(is_mode_refusal(&e), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tcp_shaped_requires_both_the_detour_and_full_parameters() {
        // 真 Tcp 文件（旧版的 Tcp profile / 实验室副本）：endpoint 挂在中转上 + 参数齐全 → 是。
        let mut p = tcp_line();
        for ep in p["endpoints"].as_array_mut().unwrap() {
            ep["detour"] = json!(TRANSPORT_TAG);
        }
        assert!(tcp_shaped(&p.to_string()), "endpoint 挂在 tc-transport 上且参数齐全，就是兼容连接那份");

        // 误报钉子（BUG-501 的回归）：标准连接线路里恰好有一条带 REALITY 的 vless 当**普通出站**用
        // ——参数在，但路由上没人做"走中转"这个决定 → 不是 Tcp 形状，导入不许记成 Tcp。
        assert!(
            !tcp_shaped(&params_line().to_string()),
            "参数存在 ≠ 路由决定：没有 detour 就不能替用户把隧道改走那条 vless"
        );

        // 弱证据另一半：只有 detour、参数取不全 → 也不是（记成 Tcp 也派生不出来，白送一个连不上的状态）。
        let mut broken = tcp_line();
        for ep in broken["endpoints"].as_array_mut().unwrap() {
            ep["detour"] = json!(TRANSPORT_TAG);
        }
        broken["outbounds"][0]["tls"].as_object_mut().unwrap().remove("reality");
        assert!(!tcp_shaped(&broken.to_string()), "缺 reality 参数就不是可再生的兼容连接");

        // 读不出的文件按"读不出意图"处理，不是报错点（导入有自己的错误文案）。
        assert!(!tcp_shaped("not json"));
        assert!(!tcp_shaped("{}"));
    }

    // ---------- AI 工具名单：规则形状、顺序、优先级、幂等、清空 ----------

    /// 一份「三样都勾了」的名单：程序（内置 + 自定义）、网页版、自定义网站。
    fn agents_trade() -> crate::config::AgentsConfig {
        crate::config::AgentsConfig {
            lane: crate::config::AgentsLane::Trade,
            builtin: vec!["claude-code".into(), "chatgpt-web".into()],
            programs: vec!["my-scan.exe".into()],
            sites: vec!["perplexity.ai".into()],
        }
    }

    fn gen_text(
        p: &Value,
        split: &SplitConfig,
        agents: &crate::config::AgentsConfig,
    ) -> String {
        generate(&p.to_string(), 18000, Mode::Proxy, split, agents, &Exits::default()).unwrap()
    }

    #[test]
    fn agents_generate_exactly_three_rules_in_trade_lane() {
        let v = gen_agents(&profile(), &SplitConfig::default(), &agents_trade(), &Exits::default());
        let rules = our_rules(&v);
        // 条数（不是「字符串里出现过」）：三类各一条、数组内批量。
        assert_eq!(rules.len(), 3, "名单只生成三条规则：{rules:?}");
        assert!(
            rules.iter().all(|r| r["outbound"] == TRADE_EXIT),
            "三条都要指交易出口：{rules:?}"
        );
        // A：程序（内置路径正则 + 自定义程序转出的模式）。claude-code 的两条模式同时覆盖
        //    老 Squirrel（\claude.exe 结尾）与新 MSIX（\WindowsApps\Claude_*\ 目录）。
        let paths = rules[0]["process_path_regex"].as_array().unwrap();
        assert!(paths.contains(&json!(r"(?i)\\claude\.exe$")), "{paths:?}");
        assert!(paths.contains(&json!(r"(?i)\\WindowsApps\\Claude_[^\\]+\\")), "{paths:?}");
        assert!(paths.contains(&json!(r"(?i)\\my-scan\.exe$")), "自定义程序也在程序组：{paths:?}");
        assert!(paths[0].as_str().unwrap().contains("claude"), "目录顺序在前：{paths:?}");
        // B：浏览器 + 域名**同时**给两个条件（少一个就是过匹配）。
        //    浏览器是单条路径正则（旧版的 BrowserPattern + 国产浏览器），域名是网页版全集。
        assert_eq!(
            rules[1]["process_path_regex"],
            json!([crate::agents::BROWSER_PATH_REGEX]),
            "{rules:?}"
        );
        let domains = rules[1]["domain_suffix"].as_array().unwrap();
        assert_eq!(domains.len(), 20, "chatgpt-web 的域名清单：{domains:?}");
        assert!(domains.contains(&json!("chatgpt.com")), "{domains:?}");
        assert!(domains.contains(&json!("o207216.ingest.sentry.io")), "{domains:?}");
        // C：纯域名
        assert_eq!(rules[2]["domain_suffix"], json!(["perplexity.ai"]), "{rules:?}");
    }

    #[test]
    fn process_name_variants_cover_install_channel_case_differences() {
        // 交易名单与自定义程序仍是 process_name（用户手输 exe 名），大小写敏感的引擎
        // 要求变体；v2 起内置程序改用路径正则（(?i) 前缀），变体只服务前两者。
        assert_eq!(process_name_variants("claude.exe"), vec!["claude.exe", "Claude.exe"]);
        assert_eq!(process_name_variants("Cursor.exe"), vec!["Cursor.exe", "cursor.exe"]);
        assert_eq!(process_name_variants("QQBrowser.exe"), vec!["QQBrowser.exe", "qqbrowser.exe"]);
        assert_eq!(process_name_variants("360se.exe"), vec!["360se.exe"], "数字开头没有变体");
        assert_eq!(process_name_variants("chrome.exe"), vec!["chrome.exe", "Chrome.exe"]);
        // 端到端：交易名单里手输 curl.exe → 写进引擎的进程规则带两种大小写。
        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        let v = gen_agents(&profile(), &split, &crate::config::AgentsConfig::default(), &Exits::default());
        let first = &v["route"]["rules"][0];
        assert_eq!(first["process_name"], json!(["curl.exe", "Curl.exe"]), "{first:?}");
        // 内置程序走路径正则：claude-code 的两条模式端到端落在程序规则里。
        let v = gen_agents(&profile(), &SplitConfig::default(), &agents_trade(), &Exits::default());
        let ours = our_rules(&v);
        let paths = ours[0]["process_path_regex"].as_array().unwrap();
        assert!(
            paths.iter().any(|x| x.as_str() == Some(r"(?i)\\claude\.exe$")),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|x| x.as_str() == Some(r"(?i)\\WindowsApps\\Claude_[^\\]+\\")),
            "{paths:?}"
        );
    }

    #[test]
    fn agents_generate_nothing_in_daily_lane() {
        // 走向=跟随日常上网：视为「尚未启用」，生成结果必须与「没有这份名单」逐字节相同。
        let mut daily = agents_trade();
        daily.lane = crate::config::AgentsLane::Daily;
        let with_list = gen_text(&profile(), &SplitConfig::default(), &daily);
        let without = gen_text(&profile(), &SplitConfig::default(), &crate::config::AgentsConfig::default());
        assert_eq!(with_list, without, "日常走向不许留任何名单痕迹");
        let v: Value = serde_json::from_str(&with_list).unwrap();
        assert!(our_rules(&v).is_empty(), "过滤后必须是 0 条：{v}");
    }

    #[test]
    fn agents_do_not_generate_without_trade_exit() {
        // 线路里没有交易出口：一条都不生成，而且**不许退回直连**。
        // 退回直连会新增一个 outbounds 条目 → `split_state` 每次都变 → 幂等直接破掉。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": DAILY_EXIT, "outbounds": ["direct"], "default": "direct" }
        ]);
        let v = gen_agents(&p, &SplitConfig::default(), &agents_trade(), &Exits::default());
        assert!(our_rules(&v).is_empty(), "没有出口就不生成：{v}");
        let outs = v["outbounds"].as_array().unwrap();
        assert!(
            !outs.iter().any(|o| o["tag"] == DIRECT_TAG),
            "不许因为名单而补 tc-direct：{outs:?}"
        );
        assert_eq!(outs.len(), 2, "出站列表一个字都不该变：{outs:?}");
    }

    #[test]
    fn agents_rules_are_removed_when_list_is_cleared() {
        // 删干净：清空名单后上一轮注入的三条必须全部消失（含「浏览器+域名」那种形状），
        // 且 route.rules 只剩线路自带的那条。
        let mut obj = profile().as_object().unwrap().clone();
        let before_foreign =
            obj["route"]["rules"].as_array().map(|a| a.len()).unwrap_or(0);
        assert!(normalize_split(&mut obj, &SplitConfig::default(), &agents_trade()));
        assert_eq!(our_rules(&Value::Object(obj.clone())).len(), 3);
        assert!(normalize_split(
            &mut obj,
            &SplitConfig::default(),
            &crate::config::AgentsConfig::default()
        ));
        assert!(
            our_rules(&Value::Object(obj.clone())).is_empty(),
            "清空后不许留残条：{:?}",
            obj["route"]["rules"]
        );
        assert_eq!(
            obj["route"]["rules"].as_array().map(|a| a.len()).unwrap_or(0),
            before_foreign,
            "只剩线路自带规则"
        );
    }

    #[test]
    fn agents_normalize_is_idempotent() {
        // 同一份配置连续生成两次：第二次必须报「没变」，且规则序列化后完全相等。
        let mut obj = profile().as_object().unwrap().clone();
        let agents = agents_trade();
        let split = split_with("curl.exe");
        assert!(normalize_split(&mut obj, &split, &agents), "第一次应当有变化");
        let once = serde_json::to_string(&obj["route"]["rules"]).unwrap();
        assert!(!normalize_split(&mut obj, &split, &agents), "第二次不该再有变化");
        let twice = serde_json::to_string(&obj["route"]["rules"]).unwrap();
        assert_eq!(once, twice, "重复 normalize 不许重复插入：{twice}");
        assert_eq!(our_rules(&Value::Object(obj)).len(), 4, "交易名单 1 条 + 名单 3 条");
    }

    #[test]
    fn is_ours_recognizes_the_three_shapes_only() {
        // P2 加固后的判据 = 键集合形状 **且** outbound 归属。
        // 出口集合 = {trade-exit, daily-exit} ∪ {当前配置 type=direct 出站的 tag}，
        // 这里用一条有 direct 出站（tag "direct"）的线路代表"当前配置"。
        let tags = vec!["direct".to_string()];
        // 三种形状的正例：outbound 分别是 trade-exit / daily-exit / 线路的 direct tag。
        assert!(is_ours(&json!({"process_name": ["a.exe"], "outbound": TRADE_EXIT}), &tags));
        assert!(is_ours(&json!({"domain_suffix": ["qq.com"], "outbound": DAILY_EXIT}), &tags));
        assert!(is_ours(
            &json!({"process_name": ["chrome.exe"], "domain_suffix": ["chatgpt.com"], "outbound": "direct"}),
            &tags
        ));
        // 形状对、但 outbound 不是我们的：外来 tag（本修复堵住的漏洞）。
        assert!(
            !is_ours(&json!({"process_name": ["a.exe"], "outbound": "line-own-exit"}), &tags),
            "外来出口 tag 的两键规则不是我们的——不许删"
        );
        // outbound 非字符串（数字/数组）直接判否。
        assert!(!is_ours(&json!({"process_name": ["a.exe"], "outbound": 42}), &tags));
        assert!(!is_ours(&json!({"process_name": ["a.exe"], "outbound": ["direct"]}), &tags));
        // 反例：没有选择条件、没有 outbound、以及线路自带的那些键。
        assert!(!is_ours(&json!({"outbound": TRADE_EXIT}), &tags), "没有选择条件不是分流规则");
        assert!(!is_ours(&json!({"process_name": ["a.exe"]}), &tags), "缺 outbound 不是我们的");
        assert!(!is_ours(&json!({"action": "route", "outbound": TRADE_EXIT}), &tags), "带 action 的是线路自带的");
        assert!(!is_ours(&json!({"inbound": [MIXED_TAG], "outbound": TRADE_EXIT}), &tags), "入站规则不是我们的");
        assert!(!is_ours(&json!({"process_name": ["a.exe"], "outbound": TRADE_EXIT, "rule_set": ["x"]}), &tags));
        assert!(!is_ours(&json!("not an object"), &tags));
        // 出口集合为空（线路没有任何 direct 出站）时：常量出口仍认得；
        // tc-direct 只有真的出现在 outbounds 里（我们追加过）才算我们的。
        let empty: Vec<String> = Vec::new();
        assert!(is_ours(&json!({"process_name": ["a.exe"], "outbound": TRADE_EXIT}), &empty));
        assert!(
            !is_ours(&json!({"process_name": ["a.exe"], "outbound": DIRECT_TAG}), &empty),
            "tc-direct 不在 outbounds 里就不是我们的"
        );
    }

    #[test]
    fn trade_list_comes_first_when_overlapping_with_agents() {
        // 旧版语义：同一进程两边都有 → 两条规则都生成，**交易名单在前**，
        // 引擎取先命中——不需要减法，顺序就是优先级。
        let mut split = SplitConfig::default();
        split.add_process("my-scan.exe", SplitTarget::Direct);
        let v = gen_agents(&profile(), &split, &agents_trade(), &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        let split_hit = rules
            .iter()
            .position(|r| {
                r.get("process_name")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().any(|x| x == "my-scan.exe"))
                    .unwrap_or(false)
            })
            .expect("交易名单那条要在");
        let agents_hit = rules
            .iter()
            .position(|r| {
                r.get("process_path_regex")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().any(|x| x.as_str().map(|s| s.contains("my-scan")).unwrap_or(false)))
                    .unwrap_or(false)
            })
            .expect("名单那条也要在（重叠保留）");
        assert_eq!(v["route"]["rules"][split_hit]["outbound"], "direct", "交易名单直连");
        assert_eq!(v["route"]["rules"][agents_hit]["outbound"], TRADE_EXIT, "名单指交易出口");
        assert!(split_hit < agents_hit, "交易名单在前：{split_hit} vs {agents_hit}");
    }

    #[test]
    fn saving_split_alone_keeps_agents_rules() {
        // 回归护栏（本功能最高风险）：只改分流后重新生成，名单的三条必须还在。
        // `normalize_split` 按形状删、只补传进来的那两份配置——任何调用点漏传都会在这里红。
        let mut obj = profile().as_object().unwrap().clone();
        let agents = agents_trade();
        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        assert!(normalize_split(&mut obj, &split, &agents));
        assert_eq!(our_rules(&Value::Object(obj.clone())).len(), 4);
        // 只动分流（再加一条域名），名单配置原样传
        split.add_domain("example.com", SplitTarget::Trade);
        assert!(normalize_split(&mut obj, &split, &agents));
        let rules = our_rules(&Value::Object(obj.clone()));
        assert_eq!(rules.len(), 5, "交易名单 2 条 + 名单 3 条：{rules:?}");
        assert_eq!(rules.iter().filter(|r| r["outbound"] == TRADE_EXIT).count(), 4);
        // 反向：只动名单（清空），交易名单必须原样留着
        assert!(normalize_split(&mut obj, &split, &crate::config::AgentsConfig::default()));
        let rules = our_rules(&Value::Object(obj));
        assert_eq!(rules.len(), 2, "只剩交易名单两条：{rules:?}");
        assert!(rules.iter().all(|r| r["outbound"] != TRADE_EXIT || r.get("inbound").is_none()));
    }

    #[test]
    fn agents_order_after_trade_list() {
        // 顺序：交易名单在前、名单在后，两者都在「入站 → 节点」之前。
        // 语义上「交易名单优先」靠的是 effective() 的减法，这里钉的是文件可读性与断言口径。
        let mut split = SplitConfig::default();
        split.add_process("TDXW.exe", SplitTarget::Trade);
        let v = gen_agents(&profile(), &split, &agents_trade(), &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(
            rules[0]["process_name"],
            json!(["TDXW.exe", "tdxw.exe"]),
            "交易名单第一（含大小写变体）：{rules:?}"
        );
        assert_eq!(rules[1]["outbound"], TRADE_EXIT, "名单紧随其后：{rules:?}");
        let first_inbound = rules
            .iter()
            .position(|r| r.get("inbound").is_some())
            .expect("必须有入站规则");
        assert!(first_inbound >= 4, "四条我们的规则都要排在入站规则之前：{rules:?}");
    }

    #[test]
    fn trade_lane_without_trade_exit_generates_nothing_and_snapshot_is_daily() {
        // 走向存 trade、但这条线路没有交易出口：一条规则都不生成，快照也必须如实。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": DAILY_EXIT, "outbounds": ["direct"], "default": "direct" }
        ]);
        let outs_before = p["outbounds"].as_array().unwrap().len();
        let mut obj = p.as_object().unwrap().clone();
        normalize_split(&mut obj, &SplitConfig::default(), &agents_trade());
        assert!(
            our_rules(&Value::Object(obj.clone())).is_empty(),
            "没有出口时名单规则必须为 0：{:?}",
            obj["route"]["rules"]
        );
        assert_eq!(
            obj["outbounds"].as_array().map(|a| a.len()).unwrap_or(0),
            outs_before,
            "不许为了名单补一个 tc-direct（那会让每次生成都变）：{:?}",
            obj["outbounds"]
        );
        // 首页读 `Agents`、应用页读 `AgentsStored`：存 trade 但实际 Daily。
        assert_eq!(crate::agents::snapshot_lane("trade", "Direct", false), "Daily");
        assert_eq!(crate::agents::lane_effective_id("trade", "Direct", false), "daily");
        // 同一份输入，有出口时才允许说 Trade（证明不是写死 Daily）。
        assert_eq!(crate::agents::snapshot_lane("trade", "Direct", true), "Trade");
    }

    #[test]
    fn same_program_in_split_direct_and_agents_order_decides() {
        // 交易名单 a.exe→直连 + 名单自定义也有 A.EXE：两条都在，交易名单在前，
        // 引擎取先命中（直连赢）。旧版同款顺序优先，不做减法。
        let mut split = SplitConfig::default();
        split.add_process("a.exe", SplitTarget::Direct);
        let agents = crate::config::AgentsConfig {
            lane: crate::config::AgentsLane::Trade,
            builtin: Vec::new(),
            programs: vec!["A.EXE".to_string()],
            sites: Vec::new(),
        };
        let v = gen_agents(&profile(), &split, &agents, &Exits::default());
        let rules = v["route"]["rules"].as_array().unwrap();
        let split_hit = rules
            .iter()
            .position(|r| {
                r.get("process_name")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter().any(|x| {
                            x.as_str().map(|s| s.eq_ignore_ascii_case("a.exe")).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            })
            .expect("交易名单那条要在");
        let agents_hit = rules
            .iter()
            .position(|r| {
                r.get("process_path_regex")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter().any(|x| {
                            x.as_str().map(|s| s.contains("A\\.EXE") || s.contains("a\\.exe")).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            })
            .expect("名单那条也要在");
        assert_eq!(v["route"]["rules"][split_hit]["outbound"], "direct", "交易名单优先");
        assert!(split_hit < agents_hit, "顺序就是优先级：{split_hit} vs {agents_hit}");
        // 名单那条的模式确实来自自定义程序（大小写由 (?i) 管，名字按原样转义）。
        let patterns = v["route"]["rules"][agents_hit]["process_path_regex"].as_array().unwrap();
        assert!(patterns.iter().any(|p| p.as_str() == Some(r"(?i)\\A\.EXE$")), "{patterns:?}");
    }

    #[test]
    fn apply_rules_to_file_keeps_both_lists_and_never_rewrites_unchanged() {
        // 文件级回归：只改分流时名单规则要留着；只改名单（清空）时交易名单要留着；
        // 同一份配置第二次必须返回 false 且文件一个字节都不动。
        let root = std::env::temp_dir().join(format!("tcrs-agents-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("line.json");
        std::fs::write(&path, serde_json::to_string_pretty(&profile_with_exits()).unwrap()).unwrap();

        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        let agents = agents_trade();
        assert!(apply_rules_to_file(&path, &split, &agents).unwrap(), "第一次要真的写");
        let after_first = std::fs::read_to_string(&path).unwrap();
        assert!(
            !apply_rules_to_file(&path, &split, &agents).unwrap(),
            "同一份配置第二次必须报「没变」"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), after_first, "没变就不许改文件");

        // 只改分流：名单 3 条必须仍在（漏传 agents 的调用点会在这里红）。
        let mut split2 = split.clone();
        split2.add_domain("example.com", SplitTarget::Trade);
        assert!(apply_rules_to_file(&path, &split2, &agents).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let ours = our_rules(&v);
        assert_eq!(ours.len(), 5, "交易名单 2 条 + 名单 3 条：{ours:?}");
        assert_eq!(ours.iter().filter(|r| r["outbound"] == TRADE_EXIT).count(), 4);

        // 只改名单（清空）：交易名单 2 条必须原样留着。
        assert!(apply_rules_to_file(&path, &split2, &crate::config::AgentsConfig::default()).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let ours = our_rules(&v);
        assert_eq!(ours.len(), 2, "只剩交易名单两条：{ours:?}");
        assert!(ours.iter().all(|r| r["outbound"] == "direct" || r["outbound"] == TRADE_EXIT));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn line_rule_with_foreign_outbound_tag_is_kept_by_shape() {
        // P2 数据丢失加固后的**正确行为**（旧判据只看键集合形状，会静默删掉这种规则）：
        // 线路自带、没有 `action`、恰为 `{process_name, outbound}` 两键、outbound 是外来
        // tag 的规则，`is_ours` 必须判否；`normalize_split` 一根手指都不许碰它——
        // 重新生成引擎配置时被静默删掉等于无备份的数据丢失。
        let mut obj = json!({
            "route": {"rules": [
                {"process_name": ["line-own.exe"], "outbound": "line-own-exit"},
                {"action": "route", "inbound": ["egress-probe"], "outbound": "daily-exit"}
            ]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        })
        .as_object()
        .unwrap()
        .clone();
        let tags = direct_outbound_tags(&obj);
        assert!(
            !is_ours(&json!({"process_name": ["line-own.exe"], "outbound": "line-own-exit"}), &tags),
            "外来 tag 的两键规则不是我们的"
        );
        assert!(
            !normalize_split(&mut obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "外来规则不被删：内容一个字都没变，必须报「没变」"
        );
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert!(
            rules.iter().any(|r| r["process_name"] == json!(["line-own.exe"])),
            "线路自带的两键规则必须原样保留：{rules:?}"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.get("action").is_some() && r.get("process_name").is_none()),
            "带 action 的规则不受影响：{rules:?}"
        );
        assert_eq!(rules.len(), 2, "一条都不许少：{rules:?}");
    }

    #[test]
    fn line_rule_with_our_direct_tag_is_still_deleted_residual_window() {
        // 诚实钉住**接受的残余窗口**：两键规则若 outbound 恰好是线路的 direct 出站 tag
        // （这里 "direct"），与我们自己 Direct 目标的分流规则在形状与指向上都不可区分，
        // 仍会被当成我们的删掉。出口集合 {trade-exit, daily-exit, 线路 direct tag} 本来就是
        // "我们的地盘"，拿它写自有两键规则的线路极少见（本仓夹具没有这种形状）。
        let mut obj = json!({
            "route": {"rules": [
                {"process_name": ["line-own.exe"], "outbound": "direct"},
                {"action": "route", "inbound": ["egress-probe"], "outbound": "daily-exit"}
            ]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        })
        .as_object()
        .unwrap()
        .clone();
        let tags = direct_outbound_tags(&obj);
        assert!(is_ours(&json!({"process_name": ["line-own.exe"], "outbound": "direct"}), &tags));
        assert!(
            normalize_split(&mut obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "删掉残余窗口内的规则也算「内容变了」"
        );
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert!(
            !rules.iter().any(|r| r["process_name"] == json!(["line-own.exe"])),
            "残余窗口：指向线路 direct tag 的两键规则仍会被删：{rules:?}"
        );
        assert!(rules.iter().any(|r| r.get("action").is_some()), "带 action 的规则不受影响");
    }

    #[test]
    fn split_round_trip_when_line_lacks_direct_outbound() {
        // 回环不回归（P2 加固的另一种打开方式）：线路**没有任何** type=direct 出站时，
        // 第一轮生成会追加 `tc-direct` 且规则指它；第二轮必须把上一轮的 tc-direct 规则
        // **认出来**删掉再重生成（幂等），清空名单后无残条。静态白名单判据在这里会爆。
        let mut p = profile();
        p["outbounds"] = json!([
            { "type": "vless", "tag": "tc-transport", "server": "198.51.100.10", "server_port": 443 },
            { "type": "selector", "tag": "trade-exit", "outbounds": ["tc-transport"], "default": "tc-transport" }
        ]);
        let mut obj = p.as_object().unwrap().clone();
        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        split.add_domain("example.com", SplitTarget::Trade);
        assert!(
            normalize_split(&mut obj, &split, &crate::config::AgentsConfig::default()),
            "第一轮要真的写（补 tc-direct 出站 + 两条规则）"
        );
        assert_eq!(obj["route"]["rules"][0]["outbound"], DIRECT_TAG, "Direct 目标指新建的 tc-direct");
        assert_eq!(obj["route"]["rules"][1]["outbound"], TRADE_EXIT, "Trade 目标指选择器");
        assert!(
            obj["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == DIRECT_TAG),
            "出站列表里要有刚补的 tc-direct"
        );
        assert!(
            !normalize_split(&mut obj, &split, &crate::config::AgentsConfig::default()),
            "第二轮必须认出上一轮的 tc-direct 规则并原样重生成：幂等"
        );
        assert!(
            normalize_split(&mut obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "清空名单要真的删"
        );
        assert!(
            obj["route"]["rules"].as_array().unwrap().iter().all(|r| {
                r.get("process_name").is_none() && r.get("domain_suffix").is_none()
            }),
            "清空后不许留残条：{:?}",
            obj["route"]["rules"]
        );
        assert_eq!(
            obj["route"]["rules"].as_array().map(|a| a.len()).unwrap_or(0),
            1,
            "只剩线路自带那条：{:?}",
            obj["route"]["rules"]
        );
    }

    // ---------- QA 对抗性边界（严过关钉的护栏；只钉行为，不改判据） ----------

    #[test]
    fn qa_two_direct_outbound_tags_are_all_recognized_as_ours() {
        // 边界：线路同时有两个 type=direct 出站（"direct" 与 "tc-direct" 并存——例如把旧
        // 生成文件重新导入）。出口集合按定义包含**所有** direct tag：指向任一者的两键规则
        // 都算我们的、重新生成时会被删。生成侧 ensure_direct_outbound 只复用**数组里第一条**
        // direct（这里 "direct" 在前），所以重生成的规则只指 "direct"。
        let mut obj = json!({
            "route": {"rules": [
                {"process_name": ["a.exe"], "outbound": "direct"},
                {"process_name": ["b.exe"], "outbound": "tc-direct"},
                {"domain_suffix": ["x.com"], "outbound": "direct"}
            ]},
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "direct", "tag": "tc-direct"}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let tags = direct_outbound_tags(&obj);
        assert_eq!(
            tags,
            vec!["direct".to_string(), "tc-direct".to_string()],
            "两个 direct 出站的 tag 都要进集合"
        );
        assert!(is_ours(&json!({"process_name": ["a.exe"], "outbound": "direct"}), &tags));
        assert!(is_ours(&json!({"process_name": ["b.exe"], "outbound": "tc-direct"}), &tags));
        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        assert!(
            normalize_split(&mut obj, &split, &crate::config::AgentsConfig::default()),
            "三条旧规则删两条、重生成一条，内容必须算「变了」"
        );
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "三个旧条全删、重生成一条：{rules:?}");
        assert!(rules.iter().all(|r| r["outbound"] == "direct"), "只指第一条 direct：{rules:?}");
    }

    #[test]
    fn qa_direct_tag_with_foreign_looking_name_is_still_our_territory() {
        // 陷阱边界：线路 direct 出站的 tag 叫一个「看起来外来」的名字（"line-own-exit"）。
        // 判据按 type==direct 的**成员资格**算、不看名字长相：指向它的两键规则仍会被删。
        // 这与 line_rule_with_our_direct_tag_is_still_deleted_residual_window 是同一个
        // 接受的残余窗口，单独钉住是为了防止未来有人把判据改成「按名字白名单」。
        let mut obj = json!({
            "route": {"rules": [
                {"process_name": ["line-own.exe"], "outbound": "line-own-exit"},
                {"action": "route", "outbound": DAILY_EXIT}
            ]},
            "outbounds": [
                {"type": "direct", "tag": "line-own-exit"},
                { "type": "selector", "tag": DAILY_EXIT, "outbounds": ["line-own-exit"], "default": "line-own-exit" }
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let tags = direct_outbound_tags(&obj);
        assert_eq!(tags, vec!["line-own-exit".to_string()], "名字再怪，type=direct 就在地盘里");
        assert!(is_ours(&json!({"process_name": ["line-own.exe"], "outbound": "line-own-exit"}), &tags));
        assert!(
            normalize_split(&mut obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "删掉残余窗口内的规则也算「内容变了」"
        );
        let rules = obj["route"]["rules"].as_array().unwrap();
        assert!(
            !rules.iter().any(|r| r.get("process_name").is_some()),
            "残余窗口：名字外来的 direct tag 指向的两键规则仍会被删：{rules:?}"
        );
        assert!(rules.iter().any(|r| r.get("action").is_some()), "带 action 的规则不受影响");
    }

    #[test]
    fn qa_dangling_outbound_reference_is_kept() {
        // 边界：规则 outbound 指向 outbounds 里**不存在**的 tag（悬空引用，比如手改删了
        // 出站）。不在出口集合 → 不是我们的 → 保留不删（删它才是数据丢失；引擎自己会报错）。
        // 注意悬空的 tc-direct 引用同样保留：tc-direct 只在真出现在 outbounds 里才算我们的。
        let mut obj = json!({
            "route": {"rules": [
                {"process_name": ["ghost.exe"], "outbound": "ghost-exit"},
                {"domain_suffix": ["gone.com"], "outbound": "tc-direct"}
            ]},
            "outbounds": [
                { "type": "vless", "tag": "hk", "server": "198.51.100.10", "server_port": 443 }
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let tags = direct_outbound_tags(&obj);
        assert!(tags.is_empty(), "没有 direct 出站时集合为空");
        assert!(!is_ours(&json!({"process_name": ["ghost.exe"], "outbound": "ghost-exit"}), &tags));
        assert!(
            !is_ours(&json!({"domain_suffix": ["gone.com"], "outbound": "tc-direct"}), &tags),
            "悬空的 tc-direct 引用（出站里没有它）不是我们的"
        );
        assert!(
            !normalize_split(&mut obj, &SplitConfig::default(), &crate::config::AgentsConfig::default()),
            "悬空引用不许删：内容没变，必须报「没变」"
        );
        assert_eq!(
            obj["route"]["rules"].as_array().map(|a| a.len()).unwrap_or(0),
            2,
            "一条都不许少：{:?}",
            obj["route"]["rules"]
        );
    }

    #[test]
    fn qa_normalize_split_idempotent_with_foreign_and_our_rules_at_file_level() {
        // 边界：同一份「外来规则 + 线路自带规则 + 我们规则」的文件连跑两轮：
        // 第二轮必须报「没变」，且文件逐字节不变（不重写 = 时间戳不动）。
        let root = std::env::temp_dir().join(format!("tcrs-qa-isours-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("line.json");
        let mut seed = profile_with_exits();
        seed["route"]["rules"] = json!([
            {"process_name": ["line-own.exe"], "outbound": "line-own-exit"},
            {"process_path": ["C:////TDXW////TDXW.exe"], "outbound": "trade-exit"},
            {"action": "route", "outbound": "daily-exit"}
        ]);
        std::fs::write(&path, serde_json::to_string_pretty(&seed).unwrap()).unwrap();

        let mut split = SplitConfig::default();
        split.add_process("curl.exe", SplitTarget::Direct);
        assert!(
            apply_rules_to_file(&path, &split, &crate::config::AgentsConfig::default()).unwrap(),
            "第一轮要真的写（补一条 curl.exe→direct）"
        );
        let after_first = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&after_first).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 4, "外来 1 + 自带 2 + 我们的 1：{rules:?}");
        assert!(
            rules.iter().any(|r| r["process_name"] == json!(["line-own.exe"])),
            "外来两键规则不许被删：{rules:?}"
        );
        assert!(rules.iter().any(|r| r.get("process_path").is_some()), "线路自带规则不许丢：{rules:?}");
        assert_eq!(our_rules(&v).len(), 1, "我们的规则恰一条：{:?}", our_rules(&v));

        assert!(
            !apply_rules_to_file(&path, &split, &crate::config::AgentsConfig::default()).unwrap(),
            "第二轮必须报「没变」"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after_first,
            "没变就不许改文件（逐字节）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn qa_outbound_null_or_empty_is_not_ours() {
        // 边界补全：outbound 为 null / 空串都不是「指向我们的出口」。
        let tags = vec!["direct".to_string()];
        assert!(!is_ours(&json!({"process_name": ["a.exe"], "outbound": null}), &tags));
        assert!(!is_ours(&json!({"process_name": ["a.exe"], "outbound": ""}), &tags));
    }

    #[test]
    fn check_transport_answers_availability_without_writing_anything() {
        let root = std::env::temp_dir().join(format!("tcrs-check-tr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let no_params = root.join("udp.json");
        std::fs::write(&no_params, udp_line().to_string()).unwrap();
        let with_params = root.join("tcp.json");
        std::fs::write(&with_params, tcp_line().to_string()).unwrap();
        let before = std::fs::read_to_string(&no_params).unwrap();

        assert!(check_transport(&no_params, Transport::Tcp).is_err(), "缺参数要拒绝");
        assert!(check_transport(&no_params, Transport::Udp).is_ok(), "标准连接永远可用");
        assert!(check_transport(&with_params, Transport::Tcp).is_ok(), "参数齐全就该通过");
        assert_eq!(std::fs::read_to_string(&no_params).unwrap(), before, "校验不许改文件");
        assert!(!root.join("runtime-engine.json").exists(), "校验不许产出运行时配置");
        let _ = std::fs::remove_dir_all(&root);
    }
}
