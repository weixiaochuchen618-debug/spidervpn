//! 本程序自己的线路配置（`data\config.json`）。
//!
//! 不复用旧版的 `deployment.json`：那是「旧版的部署记录」，字段语义绑死在它的
//! 清单/事务体系上。这里只保留 Rust 版真正需要的字段，格式独立、可独立演进。
//!
//! **schema 2 起是多线路**：`lines` 数组 + `selected`（存 id）。老配置（schema 1，单条 `line`）
//! 在读的时候无损迁成 schema 2：见 [`load_with_migration`]。
//!
//! 校验原则：**宁可启动时报错，也不要带着半截配置去改系统代理**。
//! 尤其是端点——端口写错会让系统代理指向一个不存在的服务，用户会以为「网断了」。

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_PATH: &str = "config.json";

/// Rust 单元测试共享同一进程的环境变量；涉及引擎参数或临时代理键的用例必须串行。
/// 只存在于测试产物，不改变发布程序的环境变量读取与连接行为。
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 当前配置版本。2 = 多线路（`lines` 数组 + `selected`）。
pub const SCHEMA: u32 = 2;

/// 接管方式。
///
/// 旧配置没有 `mode` 字段时按 `Proxy` 读——加了新字段就把用户现有配置读坏，是不可接受的。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 系统代理：只有本机 mixed 入站，交易终端这类不读系统代理的程序覆盖不到。
    #[default]
    Proxy,
    /// TUN：接管全部流量（含不读系统代理的程序），需要管理员权限。
    Tun,
}

impl Mode {
    /// 给人看的名字。命令行与界面说同一个词，避免两处各叫一个。
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Proxy => "代理",
            Mode::Tun => "TUN",
        }
    }

    /// 机器可用的写法（管道里传 `proxy`/`tun`，与 config.json 里的存法一致）。
    pub fn id(&self) -> &'static str {
        match self {
            Mode::Proxy => "proxy",
            Mode::Tun => "tun",
        }
    }

    /// 从界面/管道传来的字符串取模式。
    ///
    /// 认不出（含空串）一律按 `Proxy`：一个拼错的值不该让导入失败，而代理是本版
    /// 一直以来的默认接管方式，走它最保守。
    pub fn from_name(s: &str) -> Mode {
        match s.trim().to_ascii_lowercase().as_str() {
            "tun" => Mode::Tun,
            _ => Mode::Proxy,
        }
    }
}

/// 连接方式：一条线路的**两份派生配置**之间选一个。
///
/// 这是 旧版里叫「协议」的东西，id 恰好是 `Udp`/`Tcp`（`ConnectionMethods.json:13-90`）。
/// **与 [`Mode`] 正交**：`Mode` 是全局运行时接管方式（代理/TUN），这里说的是隧道怎么承载，
/// 同一条线路在两种 `Mode` 下都各有 Udp/Tcp 两份配置。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// 标准连接：WireGuard endpoint 直接走 UDP（`TransportType=udp-direct`），不改配置。
    #[default]
    Udp,
    /// 兼容连接：WireGuard 隧道套进 VLESS + REALITY（`TransportType=tcp-reality`），
    /// 派生时多插一条 `tc-transport` 出站并给 endpoint 加 `detour`。
    Tcp,
}

impl Transport {
    /// 给人看的名字，与旧版的 `DisplayName` 一致：命令行、`--lines`、文案说同一个词。
    pub fn label(&self) -> &'static str {
        match self {
            Transport::Udp => "标准连接",
            Transport::Tcp => "兼容连接",
        }
    }

    /// 命令行写法。用 旧版的 id（小写）而不是中文：脚本与文档里好敲。
    pub fn id(&self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }

    /// 认不出的值返回 `None`，**不**像 [`Mode::from_name`] 那样兜底。
    ///
    /// 这里认错是有代价的：把 tcp 读成 udp 等于偷偷换掉用户的默认线路方式，
    /// 而用户选 tcp 往往正是因为 UDP 不通——宁可报错让他重敲一次。
    pub fn from_name(s: &str) -> Option<Transport> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(Transport::Udp),
            "tcp" => Some(Transport::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    pub schema: u32,
    /// 接管方式。`#[serde(default)]` 是向后兼容的关键：老配置没有这一项也要能读。
    ///
    /// **全局**，不是线路属性：代理/TUN 是运行时的接管选择，同一条线路两种都能用。
    #[serde(default)]
    pub mode: Mode,
    /// 开机自启（HKCU Run）。旧配置没有这一项 → false：绝不能因为加字段就把用户配置读坏，
    /// 更不能因为读不到就默认打开自启。
    #[serde(default)]
    pub auto_start: bool,
    /// 启动后自动连接。
    #[serde(default)]
    pub auto_connect: bool,
    /// 关窗时缩到托盘并保持连接。
    ///
    /// 缺省 false = 保持原来的安全默认：关窗即断开并退出。用户显式打开才常驻。
    #[serde(default)]
    pub close_to_tray: bool,
    /// 线路变差时是否在首页提醒（旧版的「线路变差提醒」开关）。
    ///
    /// 缺省 **true**：这个提醒是产品默认行为，关掉的才是例外。老配置没有这一项，
    /// 读进来必须是开的——不能因为加字段就把一个安全提醒变成默认关闭。
    #[serde(default = "default_true")]
    pub quality_warning: bool,
    /// 首次连接自动记住服务器身份（旧版的「自动记住首次服务器身份」，TOFU）。
    ///
    /// 缺省 **true**：与旧版同一默认（`AutoTrustFirstConnection` 默认开）。
    /// 开：第一次连一台服务器时，用这次观测到的指纹认证一次，**认证成功之后**才钉住；
    /// 关：首次连接必须由人核对指纹，与原来的行为一致。
    ///
    /// 两种情况下**指纹变化都一律拦下**——那说明换了台机器，必须由人处理，
    /// 不能因为「自动」就把身份变化也放过。
    #[serde(default = "default_true")]
    pub auto_trust_first_connection: bool,
    /// 当前选中的线路 **id**。读不到（线路被删）时由 [`AppConfig::current_line`] 回退第一条。
    #[serde(default)]
    pub selected: String,
    /// 全部线路。空数组合法（用户把线路删光了），此时 `connect` 必须拒绝。
    #[serde(default)]
    pub lines: Vec<LineConfig>,
    /// 两个出口的选择（写进线路配置里两个 selector 的 default）。缺省 = 用线路文件自带的值。
    #[serde(default)]
    pub exits: Exits,
    /// 分流规则：命中的进程/域名按 `target` 走（缺省直连）。
    /// 缺省为空 = 全部走节点（与加这个字段之前的行为一致，老配置读进来就是空）。
    #[serde(default)]
    pub split: SplitConfig,
    /// AI 工具名单。**与 `split` 分开一节**：两者语义不同（分流有三个落点，名单只有一个走向），
    /// 混在一起会让「走向=daily 时不产生规则」这条语义无处安放。
    /// 缺省 = 跟随日常上网 + 空名单（与没有这个功能的版本行为完全一致）。
    #[serde(default)]
    pub agents: AgentsConfig,
    /// 引擎设置。没配就不允许「连接」——总不能连上一个不存在的程序。
    #[serde(default)]
    pub engine: Option<EngineSettings>,
}

impl AppConfig {
    /// 当前线路：`selected` 指向的那条；指不到就用第一条；一条都没有 → `None`。
    pub fn current_line(&self) -> Option<&LineConfig> {
        self.lines
            .iter()
            .find(|l| l.id == self.selected)
            .or_else(|| self.lines.first())
    }

    /// 这条线路是不是当前选中的（`--lines` 打星号用）。`selected` 失效时也认第一条。
    pub fn is_selected(&self, line: &LineConfig) -> bool {
        self.current_line().map(|c| c.id == line.id).unwrap_or(false)
    }

    /// 按 **id 或名字** 找线路（大小写不敏感）。`--use` / `--remove-line` 都走它。
    pub fn find_line(&self, key: &str) -> Option<&LineConfig> {
        let k = key.trim().to_lowercase();
        if k.is_empty() {
            return None;
        }
        self.lines.iter().find(|l| l.id.to_lowercase() == k || l.name.to_lowercase() == k)
    }

    /// 当前线路的引擎配置路径：`<数据根>\lines\<id>.json`。
    pub fn current_engine_path(&self, data_root: &Path) -> Option<std::path::PathBuf> {
        self.current_line().map(|l| l.engine_config_path(data_root))
    }
}

/// 分流规则的落点。`direct` = 直连出站；`trade`/`daily` = 线路文件里两个 selector。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitTarget {
    /// 直连出站（`direct`）。旧配置的裸字符串就是这个。
    #[default]
    Direct,
    /// 交易出口（`trade-exit`）。
    Trade,
    /// 日常出口（`daily-exit`）。
    Daily,
}

impl SplitTarget {
    pub fn label(&self) -> &'static str {
        match self {
            SplitTarget::Direct => "直连",
            SplitTarget::Trade => "交易出口",
            SplitTarget::Daily => "日常出口",
        }
    }

    pub fn from_name(s: &str) -> Option<SplitTarget> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(SplitTarget::Direct),
            "trade" => Some(SplitTarget::Trade),
            "daily" => Some(SplitTarget::Daily),
            _ => None,
        }
    }
}

/// 一条分流规则。**兼容两种写法**：
/// - 旧格式：`"TDXW.exe"` → 等价于 `{value, target: direct}`
/// - 新格式：`{"value":"TDXW.exe","target":"trade"}`（可再带 `path`）
///
/// 落盘时保持"直连就写裸字符串"，这样老配置读写一圈还是原样。
///
/// `path` 是**程序绝对路径**（可选）。只有 `target == trade` 的进程条目才会写它：
/// 交易保护要靠它算出 WFP 的程序身份（只存 exe 名没法可靠地定位程序文件，见 PRD P0-9）。
///
/// 兼容性两条硬约束（架构 §6.4）：
/// 1. **不升 schema**：旧版读到带 `path` 的文件会忽略这个未知字段，照常工作；
/// 2. **不写 path 时序列化逐字节不变**（`skip_serializing_if`），所以「没用这个功能」的
///    配置读一圈写回来与原文件完全相同。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SplitEntry {
    Plain(String),
    Full {
        value: String,
        #[serde(default)]
        target: SplitTarget,
        /// 程序绝对路径。**只有 processes + target=Trade 才会写这个字段**。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
}

impl SplitEntry {
    pub fn new(value: &str, target: SplitTarget) -> SplitEntry {
        SplitEntry::with_path(value, target, None)
    }

    /// 带路径的构造。直连且没有路径时仍然落成裸字符串（保持旧写法不变）。
    ///
    /// 路径为空串按「没有路径」处理：空串不是路径，写进配置只会制造
    /// 「看起来配了、实际解析不出来」的假象。
    pub fn with_path(value: &str, target: SplitTarget, path: Option<&str>) -> SplitEntry {
        let v = value.trim().to_string();
        let p = path
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string());
        if target == SplitTarget::Direct && p.is_none() {
            SplitEntry::Plain(v)
        } else {
            SplitEntry::Full { value: v, target, path: p }
        }
    }

    pub fn value(&self) -> &str {
        match self {
            SplitEntry::Plain(v) => v,
            SplitEntry::Full { value, .. } => value,
        }
    }

    pub fn target(&self) -> SplitTarget {
        match self {
            SplitEntry::Plain(_) => SplitTarget::Direct,
            SplitEntry::Full { target, .. } => *target,
        }
    }

    /// 程序绝对路径（老条目与直连条目为 `None`）。
    pub fn path(&self) -> Option<&str> {
        match self {
            SplitEntry::Plain(_) => None,
            SplitEntry::Full { path, .. } => path.as_deref(),
        }
    }
}

/// 两个出口的当前选择。缺省（`None`）= 用线路文件里选择器自带的 default。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Exits {
    #[serde(default)]
    pub trade: Option<String>,
    #[serde(default)]
    pub daily: Option<String>,
}

/// 分流规则：进程名与域名后缀，按 `target` 决定走哪个出口（缺省直连）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SplitConfig {
    #[serde(default)]
    pub processes: Vec<SplitEntry>,
    #[serde(default)]
    pub domains: Vec<SplitEntry>,
}

impl SplitConfig {
    /// 旧版的默认交易网站（`NodeStore.psm1::TCDefaultDomains`，顺序一致）。
    ///
    /// 「恢复默认网站」恢复的就是这一份；它对应旧版首次运行写进 `index.json` 的
    /// `tradeDomains`。本版不自动写进配置，只由用户点按钮应用。
    pub const DEFAULT_TRADE_DOMAINS: [&'static str; 7] = [
        "tradingview.com",
        "tradingview-widget.com",
        "tradingviewusercontent.com",
        "tvc-cdn.com",
        "tradovate.com",
        "tradovateapi.com",
        "ninjatrader.com",
    ];

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.domains.is_empty()
    }

    /// 域名归一：去掉 `*.` 前缀、小写、去空白。`*.qq.com` 与 `QQ.COM` 都变成 `qq.com`。
    pub fn normalize_domain(s: &str) -> String {
        let t = s.trim().to_ascii_lowercase();
        let t = t.strip_prefix("*.").unwrap_or(&t).to_string();
        t.trim_start_matches('.').to_string()
    }

    /// 加进程：按名字去重（大小写不敏感）；已存在但目标不同 → **改目标**并返回 true。
    ///
    /// 注意：这里**不动** `path`。老调用方（命令行 `--add-process`、引擎规则生成）只有名字，
    /// 不该因为「加了一次同名条目」就把已经确认过的程序路径抹掉。
    pub fn add_process(&mut self, name: &str, target: SplitTarget) -> bool {
        let n = name.trim().to_string();
        if n.is_empty() {
            return false;
        }
        if let Some(i) = self.processes.iter().position(|p| p.value().eq_ignore_ascii_case(&n)) {
            if self.processes[i].target() == target {
                return false;
            }
            let keep_path = self.processes[i].path().map(|p| p.to_string());
            self.processes[i] = SplitEntry::with_path(&n, target, keep_path.as_deref());
            return true;
        }
        self.processes.push(SplitEntry::new(&n, target));
        true
    }

    /// 加进程（带可选绝对路径）。**按名字去重**，与 [`Self::add_process`] 同一套口径：
    ///
    /// - 名字不存在 → 追加；
    /// - 名字已存在、目标相同、路径相同 → `false`（无变化）；
    /// - 名字已存在、目标不同 → 改目标（保留新路径），`true`；
    /// - 名字已存在、目标相同、路径不同（含「补上原本没有的路径」）→ 只更新路径，`true`；
    /// - 名字已存在、目标相同、新调用没给路径 → **保留原路径**，`false`
    ///   （「界面上又点了一次添加」不该把已确认的位置清掉）。
    ///
    /// 同名不同路径**不会**变成两条：名单的身份是名字，路径是它的属性。
    /// 两个不同程序要各自被保护，就该用不同的 exe 名（对齐 旧版的去重口径）。
    pub fn add_process_entry(
        &mut self,
        name: &str,
        target: SplitTarget,
        path: Option<&str>,
    ) -> bool {
        let n = name.trim().to_string();
        if n.is_empty() {
            return false;
        }
        let new_path = path.map(str::trim).filter(|p| !p.is_empty()).map(|p| p.to_string());
        match self.processes.iter().position(|p| p.value().eq_ignore_ascii_case(&n)) {
            None => {
                self.processes.push(SplitEntry::with_path(&n, target, new_path.as_deref()));
                true
            }
            Some(i) => {
                let existing_target = self.processes[i].target();
                let existing_path = self.processes[i].path().map(|p| p.to_string());
                if existing_target == target {
                    // 只可能因为「补上/换掉路径」而变化；没给路径就等于没变化
                    let Some(np) = new_path.clone() else {
                        return false;
                    };
                    if existing_path.as_deref() == Some(np.as_str()) {
                        return false;
                    }
                    self.processes[i] = SplitEntry::with_path(&n, target, Some(&np));
                    return true;
                }
                // 目标变了：路径以本次提供的为准（没提供就沿用旧的，避免静默丢信息）
                let resolved = new_path.or(existing_path);
                self.processes[i] = SplitEntry::with_path(&n, target, resolved.as_deref());
                true
            }
        }
    }

    /// 加域名：存的是归一后的形式（无 `*.`、小写）；已存在但目标不同 → 改目标。
    pub fn add_domain(&mut self, d: &str, target: SplitTarget) -> bool {
        let nd = Self::normalize_domain(d);
        if nd.is_empty() {
            return false;
        }
        if let Some(i) = self.domains.iter().position(|x| x.value() == nd) {
            if self.domains[i].target() == target {
                return false;
            }
            self.domains[i] = SplitEntry::new(&nd, target);
            return true;
        }
        self.domains.push(SplitEntry::new(&nd, target));
        true
    }

    /// 恢复默认交易网站（旧版的 `ResetTradeDomains`）。
    ///
    /// **只替换 `domains` 里 target=trade 的那一组**：恢复默认的本意是「交易网站回到
    /// 出厂那一份」，不该顺手删掉用户给直连/日常出口加的域名，也不该碰程序名单。
    /// 默认值若已被标成别的出口，同样让位——它们必须回到交易出口，否则「恢复默认」
    /// 等于恢复了一半。
    ///
    /// 返回列表**是否真的变了**：重复点同一个按钮不该写盘，也不该说「已恢复」。
    pub fn reset_trade_domains(&mut self) -> bool {
        let before = self.domains.clone();
        self.domains.retain(|entry| entry.target() != SplitTarget::Trade);
        for domain in Self::DEFAULT_TRADE_DOMAINS {
            let normalized = Self::normalize_domain(domain);
            self.domains.retain(|entry| entry.value() != normalized);
            self.domains.push(SplitEntry::new(&normalized, SplitTarget::Trade));
        }
        self.domains != before
    }

    /// 某个落点下的进程名（写引擎规则时按落点分组）。
    pub fn processes_for(&self, target: SplitTarget) -> Vec<String> {
        self.processes
            .iter()
            .filter(|e| e.target() == target)
            .map(|e| e.value().to_string())
            .collect()
    }

    pub fn domains_for(&self, target: SplitTarget) -> Vec<String> {
        self.domains
            .iter()
            .filter(|e| e.target() == target)
            .map(|e| e.value().to_string())
            .collect()
    }

    /// 程序**绝对路径**的格式校验（不做任何系统调用：存在性/reparse 由 `guard::identity` 判）。
    ///
    /// 只挡「一眼就不对」的输入：空串、相对路径、非 `.exe`。
    /// 相对路径必须挡掉：`C:x.exe` 这种「盘符相对」看起来像路径，实际指向哪里取决于
    /// 当前目录——把它写进配置，等于把身份交给一个偶然的工作目录。
    pub fn validate_process_path(path: &str) -> Result<(), String> {
        let p = path.trim();
        if p.is_empty() {
            return Err("程序路径不能为空".to_string());
        }
        if !std::path::Path::new(p).is_absolute() {
            return Err("程序路径必须是绝对路径（例如 C:\\Program Files\\T\\TDXW.exe）".to_string());
        }
        if !p.to_ascii_lowercase().ends_with(".exe") {
            return Err("程序路径要以 .exe 结尾".to_string());
        }
        Ok(())
    }

    /// 进程名的格式校验（命令行与界面共用）。挡的是"永远匹配不上却不报错"的那类输入。
    pub fn validate_process(name: &str) -> Result<(), String> {
        let n = name.trim();
        if n.is_empty() {
            return Err("进程名不能为空".to_string());
        }
        if n.contains('\\') || n.contains('/') || n.contains(':') {
            return Err("请填进程名（例如 TDXW.exe），不要填完整路径".to_string());
        }
        if !n.to_ascii_lowercase().ends_with(".exe") {
            return Err("进程名要以 .exe 结尾".to_string());
        }
        Ok(())
    }

    /// 域名的格式校验：sing-box 的 `domain_suffix` 只吃主机后缀，带协议/路径/单级都吃不到。
    pub fn validate_domain(d: &str) -> Result<(), String> {
        let raw = d.trim();
        if raw.is_empty() {
            return Err("域名不能为空".to_string());
        }
        if raw.contains("://") || raw.contains('/') {
            return Err("域名不要带协议或路径".to_string());
        }
        let nd = Self::normalize_domain(raw);
        if !nd.contains('.')
            || nd.starts_with('.')
            || nd.ends_with('.')
            || nd.split('.').any(|part| part.is_empty())
        {
            return Err("域名至少要有两级，例如 qq.com".to_string());
        }
        Ok(())
    }

    pub fn remove_process(&mut self, name: &str) -> bool {
        let n = name.trim();
        let before = self.processes.len();
        self.processes.retain(|p| !p.value().eq_ignore_ascii_case(n));
        self.processes.len() != before
    }

    pub fn remove_domain(&mut self, d: &str) -> bool {
        let nd = Self::normalize_domain(d);
        let before = self.domains.len();
        self.domains.retain(|x| x.value() != nd);
        self.domains.len() != before
    }
}

/// AI 工具名单的走向。**不复用 [`SplitTarget`]**：那一档有 `direct`，名单没有「直连」这个语义；
/// 独立枚举把非法值挡在类型层（配置里出现 `"lane":"direct"` 会解析失败，而不是变成一个
/// 必须解释的新状态）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentsLane {
    /// 跟随日常上网（默认）。此档**不产生任何规则**。
    #[default]
    Daily,
    /// 使用交易线路。
    Trade,
}

impl AgentsLane {
    pub fn label(&self) -> &'static str {
        match self {
            AgentsLane::Daily => "跟随日常上网",
            AgentsLane::Trade => "使用交易线路",
        }
    }

    /// 机器可用的写法（与 `config.json` 里的存法一致：小写）。
    pub fn id(&self) -> &'static str {
        match self {
            AgentsLane::Daily => "daily",
            AgentsLane::Trade => "trade",
        }
    }

    /// 从界面/管道传来的字符串取走向。**大小写不敏感**：页面传的是首字母大写
    /// （`state.Agents` = `Daily`/`Trade`），命令行与测试可能传小写。认不出返回 `None`
    /// ——调用方要如实报错，不能默默当成 Daily（那等于悄悄关掉用户刚改的走向）。
    pub fn from_value(s: &str) -> Option<AgentsLane> {
        match s.trim().to_ascii_lowercase().as_str() {
            "daily" => Some(AgentsLane::Daily),
            "trade" => Some(AgentsLane::Trade),
            _ => None,
        }
    }
}

/// AI 工具名单：走向 + 内置勾选 + 自定义程序/网站。
///
/// schema **不升 3**：升了会让「已经存过名单的配置」在回滚到旧版本时直接拒绝启动。
/// 保持 2 + `#[serde(default)]` 是双向兼容：老版本读新配置只忽略 `agents` 键，
/// 新版本读老配置得到「跟随日常上网 + 空名单」。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentsConfig {
    #[serde(default)]
    pub lane: AgentsLane,
    /// 内置目录里被勾选的条目 **id**（不是进程名/域名）：目录扩容后老配置照样能认。
    #[serde(default)]
    pub builtin: Vec<String>,
    /// 自定义程序（`.exe` 名，与交易名单同一套校验）。
    #[serde(default)]
    pub programs: Vec<String>,
    /// 自定义网站（归一后的域名后缀：小写、无 `*.`）。
    #[serde(default)]
    pub sites: Vec<String>,
}

impl AgentsConfig {
    /// 空名单（lane 不参与：空名单 + trade 也生成不出任何规则）。
    pub fn is_empty(&self) -> bool {
        self.builtin.is_empty() && self.programs.is_empty() && self.sites.is_empty()
    }

    /// 自定义条目的总数（程序 + 网站合计，上限 [`crate::agents::MAX_CUSTOM`]）。
    pub fn custom_count(&self) -> usize {
        self.programs.len() + self.sites.len()
    }

    /// 归一 / 去重 / 截断。**幂等**，两处调用：读配置之后（容错，绝不因为一行手改坏就起不来）、
    /// 写盘之前（保证落盘形态永远规范）。
    ///
    /// 「读入静默丢、保存报错」不是两套规则：两者用同一套校验，只是处置方式不同
    /// （读入时用户不在场，报错只会阻塞启动；保存时用户在场，必须当场告知）。
    pub fn sanitize(&mut self) {
        // 内置：只留认识的 id、去重，并按**目录顺序**重排（点击顺序无关 → 落盘字节稳定）。
        let mut ids: Vec<(usize, String)> = Vec::new();
        for id in &self.builtin {
            // 不认识的 id 静默丢弃（旧版本配置 / 手工改坏 / 回滚过再升级）。
            let Some(item) = crate::agents::builtin_by_id(id) else { continue };
            let Some(index) = crate::agents::catalog_index(item.id) else { continue };
            if ids.iter().any(|(_, kept)| kept == item.id) {
                continue;
            }
            ids.push((index, item.id.to_string()));
        }
        ids.sort_by_key(|(index, _)| *index);
        self.builtin = ids.into_iter().map(|(_, id)| id).collect();

        // 程序：trim、必须能过 `.exe` 校验、大小写不敏感去重（留第一次的拼写）。
        let mut programs: Vec<String> = Vec::new();
        for value in &self.programs {
            let v = value.trim();
            if SplitConfig::validate_process(v).is_err() {
                continue;
            }
            if programs.iter().any(|kept| kept.eq_ignore_ascii_case(v)) {
                continue;
            }
            programs.push(v.to_string());
        }

        // 网站：归一（去 `*.`、小写、去空白）+ 至少两级；重复只留一条。
        let mut sites: Vec<String> = Vec::new();
        for value in &self.sites {
            let v = SplitConfig::normalize_domain(value);
            if SplitConfig::validate_domain(&v).is_err() {
                continue;
            }
            if sites.iter().any(|kept| kept == &v) {
                continue;
            }
            sites.push(v);
        }

        // 合计上限：按「先程序后网站、先到先得」截断（顺序稳定，两次 sanitize 结果相同）。
        let budget = crate::agents::MAX_CUSTOM;
        if programs.len() > budget {
            programs.truncate(budget);
        }
        let left = budget.saturating_sub(programs.len());
        if sites.len() > left {
            sites.truncate(left);
        }
        self.programs = programs;
        self.sites = sites;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineSettings {
    /// 引擎可执行文件。**不再存 args**：`-c` 指向的配置按线路派生，存下来就会跟线路脱节。
    pub binary: String,
}

impl EngineSettings {
    /// 拼出这次连接要跑的引擎命令行。`config_path` 是**这条线路**的引擎配置。
    ///
    /// **只在 Rust 测试/调试构建启用**的钩子 `SPIDERVPN_ENGINE_ARGS`（空格分隔）
    /// 验收要用「会稳定活着的假引擎」验证连接成功路径，而派生参数（`run -c …`）只有真引擎看得懂。
    /// 生产不设它，形状就是派生出来的那一份。
    pub fn to_engine(&self, config_path: &Path) -> crate::engine::EngineConfig {
        let derived = vec![
            "run".to_string(),
            "-c".to_string(),
            config_path.to_string_lossy().to_string(),
        ];
        // 这个变量原本只为用假的 ping 引擎测试进程生命周期。
        // 正式发布版若继续接受环境变量，提权运行时就可能被外部注入
        // 任意引擎子命令；release 一律使用派生的 run -c 配置路径。
        #[cfg(any(test, debug_assertions))]
        let args = match std::env::var("SPIDERVPN_ENGINE_ARGS") {
            Ok(v) if !v.trim().is_empty() => {
                v.split_whitespace().map(str::to_string).collect::<Vec<_>>()
            }
            _ => derived,
        };
        #[cfg(not(any(test, debug_assertions)))]
        let args = derived;
        crate::engine::EngineConfig { binary: self.binary.clone(), args }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LineConfig {
    pub id: String,
    pub name: String,
    /// 本机代理端点，形如 `127.0.0.1:7890`。
    pub proxy_endpoint: String,
    /// 用户选的连接方式。`None` = 从没选过 → 标准连接（等价 旧版的 `PolicyDefault`）。
    ///
    /// 用 `Option` 而不是直接给默认值，是为了能区分「用户选的 Udp」（`Source=UserChoice`）
    /// 与「默认的 Udp」，`--lines` 要如实说清是哪一种。
    /// 缺这个字段的老配置读成 `None`，行为与加它之前一字不差；没选过时也不写回文件。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    /// 这条线路上**真的连通过**的连接方式（自检通过才记）。`None` = 还没验证过。
    ///
    /// 只服务「自动」这一档：`transport`（用户固定）优先，其次才是它。
    /// 老配置没有这个字段，读成 `None`，行为与加它之前一字不差。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_transport: Option<Transport>,
}

impl LineConfig {
    /// 下次连接实际要用的方式，三档：**用户固定 → 已验证 → 标准连接**。
    ///
    /// 「自动」在 旧版里就是「采用这条线路已验证的方式」（`ProtocolSelection.psm1`），
    /// 所以它必须有一个**真实依据**可依——那就是 [`LineConfig::verified_transport`]，
    /// 只有自检通过的连接才会写进去。用户显式选过的方式永远优先：他改主意了，
    /// 程序不该拿「上次通过」去覆盖他的选择。
    ///
    /// **兜底仍是标准连接**，不是随手挑的：旧版的 `PolicyDefault` 策略就是它——标准连接
    /// 少一层中转、少一个服务器参数、失败面最小；兼容连接是给 UDP 被拦的网络准备的备选，
    /// 该由用户显式选了、或者实测通过过才生效。
    pub fn effective_transport(&self) -> Transport {
        self.transport
            .or(self.verified_transport)
            .unwrap_or(Transport::Udp)
    }
    /// 这条线路的引擎配置路径：`<数据根>\lines\<id>.json`。
    ///
    /// id 会做一次文件名净化：它是从名字派生的，理论上可能带 `\` 或 `:`，
    /// 拼进路径会写到别处去（Windows 上 `a:b` 还是备用数据流）。
    pub fn engine_config_path(&self, data_root: &Path) -> std::path::PathBuf {
        engine_config_path_for(data_root, &self.id)
    }

    /// 这条线路的兼容连接参数（`lines\<id>.compatible.json`）。
    ///
    /// 旧版是「一条线路两种连接方式」，本版最初做成了两条线路——同一台服务器出现两张
    /// 卡片，而卡片里的「标准/兼容」开关对标准那条根本按不动（线路文件里没有 VLESS 参数）。
    /// 参数放这里而不是塞进线路文件：标准态下线路文件必须是干净的，`strip_transport` 会把
    /// 没人引用的中转出站删掉，参数写进去下一次切标准就被抹了。
    pub fn compatible_path(&self, data_root: &Path) -> std::path::PathBuf {
        compatible_path_for(data_root, &self.id)
    }

    /// 读兼容连接参数。**读不出来就当没有**（老线路、文件坏了、从没装过）：调用方只用来
    /// 决定「能不能切到兼容」，静默降级成「不能」比编一份假参数安全得多。
    pub fn load_compatible(&self, data_root: &Path) -> Option<LineCompatible> {
        let text = std::fs::read_to_string(self.compatible_path(data_root)).ok()?;
        serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
    }

    /// 写兼容连接参数（原子替换；设备上只有本机读，不存在并发写者）。
    pub fn save_compatible(
        &self,
        data_root: &Path,
        params: &LineCompatible,
    ) -> Result<(), String> {
        let path = self.compatible_path(data_root);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("建目录失败（{}）：{e}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(params)
            .map_err(|e| format!("序列化兼容连接参数失败：{e}"))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写临时文件失败（{}）：{e}", tmp.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("落盘失败（{}）：{e}", path.display()))
    }
}

/// 兼容连接参数的路径。与 [`engine_config_path_for`] 同源（同一套 id 净化规则），
/// 线路删掉之后按 id 清理时也用它。
pub fn compatible_path_for(data_root: &Path, id: &str) -> std::path::PathBuf {
    data_root
        .join("lines")
        .join(format!("{}.compatible.json", safe_file_stem(id)))
}

/// 一条线路的兼容连接（VLESS + REALITY 中转）参数。全部**非秘密**：uuid 是客户端凭据、
/// REALITY 公钥是服务端公开身份，两者本来就要写进客户端线路文件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineCompatible {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub server_name: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
}

/// 按 id 算引擎配置路径。线路已经删掉时没有 [`LineConfig`] 可用，
/// 待清理记录的重试只能靠这一条——**规则必须与 `LineConfig::engine_config_path` 同源**，
/// 否则重试会对着另一个路径删（或删不到）。
pub fn engine_config_path_for(data_root: &Path, id: &str) -> std::path::PathBuf {
    data_root.join("lines").join(format!("{}.json", safe_file_stem(id)))
}

/// 把 id 净化成安全的文件名片段：只留字母数字与 `-_.`，其余换成 `_`。
pub fn safe_file_stem(id: &str) -> String {
    let s: String = id
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    if s.is_empty() {
        "line".to_string()
    } else {
        s
    }
}

/// 从名字派生 id。**只是内部标识**，界面上从不展示；同名再导入时用它做「更新」的键。
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
            out.push(c.to_ascii_lowercase());
        } else if c.is_whitespace() || matches!(c, '.' | '(' | ')' | '（' | '）') {
            // 空格与常见括号直接丢掉，避免 id 里一堆下划线
        } else {
            // 中文等：转成码点十六进制。保证唯一、可作文件名，且不依赖任何编码库。
            out.push_str(&format!("{:x}", c as u32));
        }
    }
    if out.is_empty() {
        "line".to_string()
    } else {
        out
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    UnsupportedSchema(u32),
    MissingField(&'static str),
    /// 端点格式不对：必须是 `host:port`，端口 1..=65535。
    BadEndpoint(String),
    /// schema 1 → 2 迁移失败。**失败时原文件必须原样不动**——宁可让用户重新导入，
    /// 也不要留下半迁移的配置。
    Migration(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "读取配置失败：{e}"),
            ConfigError::Parse(e) => write!(f, "配置格式错误：{e}"),
            ConfigError::UnsupportedSchema(v) => {
                write!(f, "配置版本不支持：{v}（本程序只认 1 和 {SCHEMA}）")
            }
            ConfigError::MissingField(k) => write!(f, "配置缺少必需字段：{k}"),
            ConfigError::BadEndpoint(e) => write!(f, "代理端点不合法：{e}"),
            ConfigError::Migration(e) => write!(f, "配置升级失败：{e}"),
        }
    }
}

/// 校验 `host:port`。不追求完整的主机名语法，只挡住明显会让代理失效的写法。
pub fn validate_endpoint(s: &str) -> Result<(), ConfigError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ConfigError::BadEndpoint("为空".into()));
    }
    // 端口解析只有一份实现：`selfcheck::port_from_endpoint`（IPv6 走最后一个冒号）。
    let (host, _) = match s.rsplit_once(':') {
        Some(v) => v,
        None => return Err(ConfigError::BadEndpoint(format!("缺少端口：{s}"))),
    };
    if host.trim().is_empty() {
        return Err(ConfigError::BadEndpoint(format!("缺少主机：{s}")));
    }
    if crate::selfcheck::port_from_endpoint(s).is_none() {
        return Err(ConfigError::BadEndpoint(super::engine_config::bad_port_msg(s)));
    }
    Ok(())
}

/// 磁盘上的原始形状：同时容纳 schema 1（`line` + `engine.args`）与 schema 2（`lines` + `selected`）。
/// 只在解析/迁移时用，程序内部一律用 [`AppConfig`]。
#[derive(Deserialize)]
struct RawConfig {
    schema: u32,
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    auto_start: bool,
    #[serde(default)]
    auto_connect: bool,
    #[serde(default)]
    close_to_tray: bool,
    #[serde(default = "default_true")]
    quality_warning: bool,
    #[serde(default = "default_true")]
    auto_trust_first_connection: bool,
    #[serde(default)]
    selected: String,
    #[serde(default)]
    lines: Vec<LineConfig>,
    #[serde(default)]
    split: SplitConfig,
    #[serde(default)]
    agents: AgentsConfig,
    #[serde(default)]
    exits: Exits,
    /// 只出现在 schema 1。
    #[serde(default)]
    line: Option<LineConfig>,
    #[serde(default)]
    engine: Option<RawEngine>,
}

#[derive(Deserialize)]
struct RawEngine {
    #[serde(default)]
    binary: String,
    /// 只出现在 schema 1；迁移时用它兜底找回引擎程序。
    #[serde(default)]
    args: Vec<String>,
}

/// 旧配置里认引擎程序：`engine.args` 的第 0 个元素若是路径就用它（旧版的写法），
/// 否则用 `engine.binary`（本程序 schema 1 的写法）。都没有 → `None`（调用方报错，不猜）。
impl RawEngine {
    fn is_configured(&self) -> bool {
        !self.binary.trim().is_empty()
    }
}

fn pick_old_engine_binary(e: &RawEngine) -> Option<String> {
    fn looks_like_exe(s: &str) -> bool {
        let s = s.trim();
        !s.is_empty() && (s.ends_with(".exe") || s.contains('\\') || s.contains('/'))
    }
    if let Some(first) = e.args.first() {
        if looks_like_exe(first) {
            return Some(first.trim().to_string());
        }
    }
    let b = e.binary.trim();
    if !b.is_empty() {
        return Some(b.to_string());
    }
    None
}

/// 纯解析（不做任何 I/O）：schema 1 → 2 的**内存迁移**在这里完成。
/// 返回 `(配置, 是否从 schema 1 迁来)`——落盘与文件复制由 [`load_with_migration`] 负责。
fn parse_raw(text: &str) -> Result<(AppConfig, bool), ConfigError> {
    // 容忍 UTF-8 BOM：PowerShell 5.1 的 `-Encoding UTF8` 会写 BOM，而 serde_json 不认它，
    // 于是一份合法配置被判「配置格式错误」，程序直接拒绝启动。去掉它，其余解析照常。
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let raw: RawConfig = serde_json::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    match raw.schema {
        1 => migrate_v1(raw).map(|c| (c, true)),
        SCHEMA => finish_v2(raw).map(|c| (c, false)),
        v => Err(ConfigError::UnsupportedSchema(v)),
    }
}

fn migrate_v1(raw: RawConfig) -> Result<AppConfig, ConfigError> {
    let line = raw.line.ok_or(ConfigError::MissingField("line"))?;
    validate_line(&line)?;
    let engine = match raw.engine {
        None => None,
        Some(e) => match pick_old_engine_binary(&e) {
            Some(binary) => Some(EngineSettings { binary }),
            // 不瞎猜：报错让用户重新导入，原文件一个字节都不动。
            None => {
                return Err(ConfigError::Migration(
                    "旧配置里认不出引擎程序（engine.binary 为空，engine.args 第 0 个元素也不是路径），请重新导入线路".into(),
                ))
            }
        },
    };
    Ok(AppConfig {
        schema: SCHEMA,
        mode: raw.mode,
        auto_start: raw.auto_start,
        auto_connect: raw.auto_connect,
        close_to_tray: raw.close_to_tray,
        quality_warning: raw.quality_warning,
        auto_trust_first_connection: raw.auto_trust_first_connection,
        selected: line.id.clone(),
        lines: vec![line],
        split: raw.split.clone(),
        agents: raw.agents.clone(),
        exits: raw.exits.clone(),
        engine,
    })
}

fn default_true() -> bool {
    true
}

fn finish_v2(raw: RawConfig) -> Result<AppConfig, ConfigError> {
    for line in &raw.lines {
        validate_line(line)?;
    }
    if let Some(e) = &raw.engine {
        if !e.is_configured() {
            return Err(ConfigError::MissingField("engine.binary"));
        }
    }
    Ok(AppConfig {
        schema: SCHEMA,
        mode: raw.mode,
        auto_start: raw.auto_start,
        auto_connect: raw.auto_connect,
        close_to_tray: raw.close_to_tray,
        quality_warning: raw.quality_warning,
        auto_trust_first_connection: raw.auto_trust_first_connection,
        selected: raw.selected,
        lines: raw.lines,
        split: raw.split,
        agents: raw.agents,
        exits: raw.exits,
        engine: raw.engine.map(|e| EngineSettings { binary: e.binary }),
    })
}

fn validate_line(l: &LineConfig) -> Result<(), ConfigError> {
    if l.id.trim().is_empty() {
        return Err(ConfigError::MissingField("line.id"));
    }
    if l.name.trim().is_empty() {
        return Err(ConfigError::MissingField("line.name"));
    }
    validate_endpoint(&l.proxy_endpoint)
}

/// 纯解析（不做 I/O）。schema 1 的文本会在这里被迁成内存里的 schema 2。
///
/// 只在测试里直接调用（生产一律走 [`load_with_migration`]，它还要负责落盘），
/// 所以没有 `cfg(test)` 之外的调用方时会报 dead_code——加 `cfg(test)` 比留着警告干净。
#[cfg(test)]
pub fn parse(text: &str) -> Result<AppConfig, ConfigError> {
    parse_raw(text).map(|(c, _)| c)
}

/// 原子写入：先写临时文件再替换。
/// 直接覆写配置时若中途掉电，会留下半截 JSON——那会让程序下次启动直接拒绝运行。
#[cfg(test)]
pub fn save(path: &Path, cfg: &AppConfig) -> Result<(), ConfigError> {
    save_with_origin(path, cfg, &crate::events::Origin::other())
}

/// 带来源的保存。界面、命令行、管道必须各自传入自己的 [`crate::events::Origin`]，
/// 不允许 `record` 从调用栈或全局变量猜来源。
pub fn save_with_origin(
    path: &Path,
    cfg: &AppConfig,
    origin: &crate::events::Origin,
) -> Result<(), ConfigError> {
    // 写之前先读一份旧的：操作记录要的是「改了什么」，而不是「谁调了 save」。
    // 读失败按「没有旧配置」处理（新机器/文件坏了），此时记录只会报新增的线路。
    let prev = load_readonly(path).ok().flatten();
    let text = serde_json::to_string_pretty(cfg).map_err(|e| ConfigError::Parse(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| ConfigError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| ConfigError::Io(e.to_string()))?;
    // 落盘成功才记：写失败时配置还是旧的，记一条「改了」就是对记录撒谎。
    if let Some(root) = path.parent() {
        crate::events::record_config_change(root, prev.as_ref(), cfg, origin);
    }
    Ok(())
}

/// 读配置的结果。`upgraded=true` 表示这次真的完成了 schema 1 → 2 的迁移（**只会有一次**）。
pub struct Loaded {
    pub cfg: AppConfig,
    pub upgraded: bool,
}

/// 读配置，顺带完成 schema 1 → 2 的迁移。
///
/// 迁移是**无损的**：旧 `line` 变第一条线路，旧 `data\engine.json` **复制**成
/// `data\lines\<id>.json`（复制不是移动，旧文件留着不碍事），然后把 schema 2 原子落盘。
/// 任何一步失败都不写盘 —— 半迁移的配置比不迁移更难救。
/// `persist=false` 用于**只读命令**（`--status` / `--lines` / `--plan` / `--restore`）：
/// 老配置在内存里迁成 schema 2 照常可用，但**不写盘、不复制文件**。
/// 理由：只读命令不该改用户的配置——既违反「默认根只读」，也让验收的「跑前跑后一致」失效。
/// 真正的落盘留给第一个写命令（或界面启动）。
pub fn load_with_migration(path: &Path, persist: bool) -> Result<Option<Loaded>, ConfigError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    let (mut cfg, was_v1) = parse_raw(&text)?;
    // 唯一读入口：`load` 与 `load_readonly` 都过这里，所以「手工改坏不阻塞启动」
    // 只需要在这一点做归一。丢弃不认识的内置 id、坏掉的程序名/域名、超限的自定义条目。
    cfg.agents.sanitize();
    if !was_v1 {
        return Ok(Some(Loaded { cfg, upgraded: false }));
    }
    if !persist {
        // 只读命令：内存里迁好就用，文件一个字节都不动（`upgraded=false` 表示「本次没落盘」）。
        return Ok(Some(Loaded { cfg, upgraded: false }));
    }
    let root = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let old_engine_file = root.join(crate::engine_config::FILE_NAME);
    if old_engine_file.exists() {
        if let Some(line) = cfg.lines.first() {
            let target = line.engine_config_path(&root);
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir).map_err(|e| ConfigError::Io(e.to_string()))?;
            }
            std::fs::copy(&old_engine_file, &target).map_err(|e| ConfigError::Io(e.to_string()))?;
        }
    }
    save_with_origin(path, &cfg, &crate::events::Origin::auto())?;
    Ok(Some(Loaded { cfg, upgraded: true }))
}

/// 写路径用的读法：schema 1 会被真正迁成 2 并落盘。
pub fn load(path: &Path) -> Result<Option<AppConfig>, ConfigError> {
    Ok(load_with_migration(path, true)?.map(|l| l.cfg))
}

/// 只读路径用的读法：schema 1 只在内存里迁，**不落盘**。
pub fn load_readonly(path: &Path) -> Result<Option<AppConfig>, ConfigError> {
    Ok(load_with_migration(path, false)?.map(|l| l.cfg))
}

/// 记下「这条线路用这种方式真的连通过」（「自动」档的唯一依据）。
///
/// **幂等**：连接每次成功都会调用它，所以同值时必须直接返回 `Ok(false)` 且**不写盘**——
/// 否则每连一次就改一遍 config.json，mtime 乱跳、操作记录里也会多出一串无意义的行。
/// 返回值就是这个含义：`true` = 真的改了文件，`false` = 本来就是这个值。
///
/// 保存走 [`save_with_origin`]（带来源记录），不自己 `fs::write`：配置文件的唯一写入口
/// 只有一个，绕过它就等于让操作记录漏掉一次改动。
pub fn record_verified_transport(
    root: &Path,
    line_id: &str,
    transport: Transport,
) -> Result<bool, String> {
    let path = root.join(DEFAULT_PATH);
    let mut cfg = match load(&path).map_err(|e| e.to_string())? {
        Some(c) => c,
        None => return Err("找不到配置文件（config.json）".to_string()),
    };
    let Some(line) = cfg.lines.iter_mut().find(|l| l.id == line_id) else {
        return Err(format!("配置里没有这条线路：{line_id}"));
    };
    if line.verified_transport == Some(transport) {
        return Ok(false);
    }
    line.verified_transport = Some(transport);
    save_with_origin(&path, &cfg, &crate::events::Origin::auto()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// 忘掉「这条线路已验证的方式」：连接失败后，上一次的「通过」就不再是证据。
///
/// 同样**幂等**：本来就是 `None` 时返回 `Ok(false)` 且不写盘。用户显式固定的
/// `transport`（[`LineConfig::transport`]）不在这里动——那是用户的选择，不是证据。
pub fn clear_verified_transport(root: &Path, line_id: &str) -> Result<bool, String> {
    let path = root.join(DEFAULT_PATH);
    let mut cfg = match load(&path).map_err(|e| e.to_string())? {
        Some(c) => c,
        None => return Err("找不到配置文件（config.json）".to_string()),
    };
    let Some(line) = cfg.lines.iter_mut().find(|l| l.id == line_id) else {
        return Err(format!("配置里没有这条线路：{line_id}"));
    };
    if line.verified_transport.is_none() {
        return Ok(false);
    }
    line.verified_transport = None;
    save_with_origin(&path, &cfg, &crate::events::Origin::auto()).map_err(|e| e.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// schema 2 的合法配置（当前形状）。
    const OK: &str = r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"香港 01","proxy_endpoint":"127.0.0.1:7890"}]}"#;
    /// schema 1 的合法配置（上一版的形状，用于迁移测试）。
    const V1: &str = r#"{"schema":1,"line":{"id":"L1","name":"香港 01","proxy_endpoint":"127.0.0.1:7890"}}"#;

    #[test]
    fn accepts_valid_config() {
        let c = parse(OK).unwrap();
        assert_eq!(c.current_line().unwrap().proxy_endpoint, "127.0.0.1:7890");
        assert_eq!(c.selected, "L1");
    }

    /// 「自动记住首次服务器身份」：老配置没有这个键，读进来必须是**开**（与旧版同一默认）。
    /// 关掉之后要能原样读回——这是它从一个假开关变成真设置的最低要求。
    #[test]
    fn auto_trust_defaults_to_on_and_round_trips_when_turned_off() {
        assert!(parse(OK).unwrap().auto_trust_first_connection, "缺省必须是开");
        let off = OK.replace("\"schema\":2", "\"schema\":2,\"auto_trust_first_connection\":false");
        assert!(!parse(&off).unwrap().auto_trust_first_connection);
        // 存回去再读一遍：字段名不能写错（写错就等于每次重启又变回开）。
        let round = serde_json::to_string(&parse(&off).unwrap()).unwrap();
        assert!(round.contains("\"auto_trust_first_connection\":false"), "{round}");
        assert!(!parse(&round).unwrap().auto_trust_first_connection);
    }

    #[test]
    fn rejects_unknown_schema() {
        let t = OK.replace("\"schema\":2", "\"schema\":3");
        assert!(matches!(parse(&t), Err(ConfigError::UnsupportedSchema(3))));
    }

    #[test]
    fn rejects_missing_id_or_name() {
        let t = OK.replace("\"id\":\"L1\"", "\"id\":\"  \"");
        assert!(matches!(parse(&t), Err(ConfigError::MissingField("line.id"))));
    }

    #[test]
    fn rejects_bad_endpoints() {
        for bad in ["", "7890", "127.0.0.1:", ":7890", "127.0.0.1:0", "127.0.0.1:abc", "127.0.0.1:70000"] {
            assert!(validate_endpoint(bad).is_err(), "应该拒绝：{bad:?}");
        }
    }

    #[test]
    fn port_errors_share_one_wording() {
        // 端口类错误统一成一句（原来「端口不能为 0」「端口不是数字」两种说法已合并）。
        // 这里钉住新措辞与合法区间：措辞可以统一，校验强度不能变松。
        for bad in ["127.0.0.1:0", "127.0.0.1:abc", "127.0.0.1:70000"] {
            let e = validate_endpoint(bad).unwrap_err().to_string();
            assert!(e.contains("端口不合法"), "端口类错误要用统一措辞：{e}");
            assert!(e.contains("1..=65535"), "要告诉用户合法区间：{e}");
        }
        // 非端口类错误仍保留各自的具体说法
        assert!(validate_endpoint("127.0.0.1").unwrap_err().to_string().contains("缺少端口"));
        assert!(validate_endpoint(":7890").unwrap_err().to_string().contains("缺少主机"));
    }

    #[test]
    fn accepts_ipv6_and_hostnames() {
        for good in ["[::1]:7890", "localhost:1080", "127.0.0.1:65535"] {
            assert!(validate_endpoint(good).is_ok(), "应该接受：{good}");
        }
    }

    #[test]
    fn engine_settings_are_optional_but_validated() {
        let without = parse(OK).unwrap();
        assert!(without.engine.is_none(), "没配引擎也要能用（只是不能连接）");

        let bad = r#"{"schema":2,"lines":[{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890"}],"engine":{"binary":"  "}}"#;
        assert!(matches!(parse(bad), Err(ConfigError::MissingField("engine.binary"))));
    }

    #[test]
    fn engine_command_line_is_derived_per_line_and_the_hook_overrides_it() {
        // 两条断言放同一条用例里：都要改进程级环境变量，分开写会互相踩（Rust 测试是并行跑的）。
        // 其它模块的真实引擎用例也读同一个变量，必须共用跨模块锁，不能只靠合并这两条断言。
        let _env_serial = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let e = EngineSettings { binary: "C:////x////sing-box.exe".into() };
        let path = std::path::Path::new("C:////data////lines////L1.json");
        let restore = std::env::var("SPIDERVPN_ENGINE_ARGS").ok();
        std::env::remove_var("SPIDERVPN_ENGINE_ARGS");

        // 默认：args 不落盘，`-c` 按线路派生
        let cmd = e.to_engine(path);
        assert_eq!(cmd.binary, "C:////x////sing-box.exe");
        assert_eq!(cmd.args, vec!["run", "-c", "C:////data////lines////L1.json"]);

        // 测试钩子：整体替换参数（验收要拿「会稳定活着」的假引擎验证成功路径）
        std::env::set_var("SPIDERVPN_ENGINE_ARGS", "-n 300 127.0.0.1");
        let hooked = e.to_engine(path);
        assert_eq!(hooked.args, vec!["-n", "300", "127.0.0.1"]);
        // 硬约束：钩子**只能**换参数，绝不能换引擎路径——二进制永远来自 config。
        assert_eq!(hooked.binary, "C:////x////sing-box.exe", "钩子不许改变引擎程序");

        match restore {
            Some(v) => std::env::set_var("SPIDERVPN_ENGINE_ARGS", v),
            None => std::env::remove_var("SPIDERVPN_ENGINE_ARGS"),
        }
    }

    // ---------- schema 1 → 2 迁移 ----------

    #[test]
    fn schema1_migrates_to_schema2_in_memory() {
        let c = parse(V1).unwrap();
        assert_eq!(c.schema, SCHEMA);
        assert_eq!(c.lines.len(), 1, "旧的一条线路要变成 lines 的第一条");
        assert_eq!(c.selected, "L1", "迁移后要选中它");
        assert_eq!(c.current_line().unwrap().name, "香港 01");
    }

    #[test]
    fn migration_takes_engine_from_args_when_binary_is_empty() {
        // 旧版风格的 engine：args[0] 就是可执行文件
        let t = r#"{"schema":1,"line":{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890"},
                    "engine":{"args":["C:\\app\\sing-box.exe","run"]}}"#;
        let c = parse(t).unwrap();
        assert_eq!(c.engine.unwrap().binary, "C:\\app\\sing-box.exe");
    }

    #[test]
    fn migration_prefers_binary_when_args_do_not_look_like_a_path() {
        // 本程序 schema 1 的写法：args = ["run","-c",…]，路径在 binary 里
        let t = r#"{"schema":1,"line":{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890"},
                    "engine":{"binary":"C:\\x\\sing-box.exe","args":["run","-c","a.json"]}}"#;
        let c = parse(t).unwrap();
        assert_eq!(c.engine.unwrap().binary, "C:\\x\\sing-box.exe");
    }

    #[test]
    fn migration_refuses_to_guess_the_engine() {
        let t = r#"{"schema":1,"line":{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890"},
                    "engine":{"binary":"","args":["run","-c","a.json"]}}"#;
        let e = parse(t).unwrap_err();
        assert!(matches!(e, ConfigError::Migration(_)), "认不出引擎要报迁移错误：{e}");
        assert!(e.to_string().contains("重新导入"), "要告诉用户怎么办：{e}");
    }

    #[test]
    fn persisted_ids_are_never_reslugged_and_drive_the_file_path() {
        // 红线：用户配置里已经落盘的 id（可能是旧规则生成的，带中文）必须原样保留，
        // 文件名也只能由这个 id 派生——重算 id 会让用户那条线路的 lines\<id>.json 对不上。
        let root = std::env::temp_dir().join(format!("tcrs-idkeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lines")).unwrap();
        let cfg_text = r#"{"schema":2,"selected":"示例线路","lines":[
            {"id":"示例线路","name":"示例线路","proxy_endpoint":"127.0.0.1:17890"}]}"#;
        let cfg_path = root.join(DEFAULT_PATH);
        std::fs::write(&cfg_path, cfg_text).unwrap();
        // 旧规则下这条线路的引擎配置落在这里（中文被净化成下划线）
        let per_line = root.join("lines").join("____.json");
        std::fs::write(&per_line, r#"{"inbounds":[{"type":"mixed","tag":"tc-mixed"}]}"#).unwrap();

        let c = load(&cfg_path).unwrap().expect("配置存在");
        let line = c.current_line().expect("必须有当前线路");
        assert_eq!(line.id, "示例线路", "id 必须原样保留，绝不重算");
        assert_eq!(
            line.engine_config_path(&root),
            per_line,
            "文件名必须由已落盘的 id 派生（同一套规则），不能变成 hex 名字"
        );
        assert!(
            std::fs::read_to_string(line.engine_config_path(&root)).is_ok(),
            "按这个路径必须能读到那条线路的引擎配置"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn readonly_load_migrates_in_memory_without_touching_the_file() {
        // 只读命令（--status/--lines/--plan/--restore）绝不能改用户配置。
        let root = std::env::temp_dir().join(format!("tcrs-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cfg_path = root.join(DEFAULT_PATH);
        std::fs::write(&cfg_path, V1).unwrap();
        std::fs::write(root.join(crate::engine_config::FILE_NAME), r#"{"inbounds":[]}"#).unwrap();
        let before = std::fs::read(&cfg_path).unwrap();

        let c = load_readonly(&cfg_path).unwrap().expect("配置存在");
        assert_eq!(c.schema, SCHEMA, "内存里已经是多线路");
        assert_eq!(c.current_line().unwrap().name, "香港 01");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), before, "只读命令不许改文件");
        assert!(!root.join("lines").exists(), "只读命令不许复制引擎配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_migration_copies_engine_json_and_writes_schema2_once() {
        let root = std::env::temp_dir().join(format!("tcrs-mig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cfg_path = root.join(DEFAULT_PATH);
        std::fs::write(&cfg_path, V1).unwrap();
        let old_engine = root.join(crate::engine_config::FILE_NAME);
        std::fs::write(&old_engine, r#"{"log":{"level":"warn"}}"#).unwrap();

        let first = load_with_migration(&cfg_path, true).unwrap().expect("配置存在");
        assert!(first.upgraded, "第一次读要做迁移");
        assert_eq!(first.cfg.schema, SCHEMA);
        // 旧 engine.json **被复制**（不是移动）到 lines/<id>.json，旧文件仍在
        let per_line = root.join("lines").join("L1.json");
        assert!(per_line.exists(), "每条线路要有自己的引擎配置");
        assert_eq!(
            std::fs::read_to_string(&per_line).unwrap(),
            std::fs::read_to_string(&old_engine).unwrap(),
            "复制的内容必须一字不差"
        );
        assert!(old_engine.exists(), "旧 engine.json 留着不碍事（复制不是移动）");
        // 落盘的是 schema 2
        let text = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(text.contains("\"schema\": 2"), "{text}");
        assert!(text.contains("\"lines\""), "{text}");
        assert!(!text.contains("\"args\""), "schema 2 不再存 args：{text}");

        // 第二次读：不再迁移、也不再改写文件
        let before = std::fs::read_to_string(&cfg_path).unwrap();
        let second = load_with_migration(&cfg_path, true).unwrap().unwrap();
        assert!(!second.upgraded, "迁移只做一次");
        assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), before, "第二次不许改动文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_migration_leaves_the_file_byte_identical() {
        let root = std::env::temp_dir().join(format!("tcrs-mig-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cfg_path = root.join(DEFAULT_PATH);
        let bad = r#"{"schema":1,"line":{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890"},"engine":{"binary":"","args":["run"]}}"#;
        std::fs::write(&cfg_path, bad).unwrap();
        let before = std::fs::read(&cfg_path).unwrap();

        assert!(load_with_migration(&cfg_path, true).is_err(), "认不出引擎必须报错");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), before, "失败时原文件一个字节都不能动");
        assert!(!root.join("lines").exists(), "失败时不该创建 lines 目录");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 多线路查找/回退 ----------

    #[test]
    fn current_line_falls_back_to_the_first_when_selected_is_stale() {
        let t = r#"{"schema":2,"selected":"gone","lines":[
            {"id":"a","name":"A","proxy_endpoint":"127.0.0.1:7001"},
            {"id":"b","name":"B","proxy_endpoint":"127.0.0.1:7002"}]}"#;
        let c = parse(t).unwrap();
        assert_eq!(c.current_line().unwrap().id, "a", "selected 失效要回退第一条，不能变成「没有线路」");
        assert!(c.is_selected(&c.lines[0]));
        assert!(!c.is_selected(&c.lines[1]));
    }

    #[test]
    fn find_line_matches_id_or_name_case_insensitively() {
        let t = r#"{"schema":2,"lines":[
            {"id":"hk-1","name":"香港 01","proxy_endpoint":"127.0.0.1:7001"}]}"#;
        let c = parse(t).unwrap();
        assert!(c.find_line("hk-1").is_some(), "按 id 找");
        assert!(c.find_line("HK-1").is_some(), "大小写不敏感");
        assert!(c.find_line("香港 01").is_some(), "按名字找");
        assert!(c.find_line("不存在的").is_none());
        assert!(c.find_line("  ").is_none(), "空键不能匹配到任何线路");
    }

    #[test]
    fn split_defaults_to_empty_for_old_and_new_configs() {
        // 老配置没有 split 段、新配置没写，都必须读成空 —— 空 = 全部走节点，与加字段前一致。
        for text in [V1, OK] {
            let c = parse(text).unwrap();
            assert!(c.split.is_empty(), "缺字段时必须是空规则：{text}");
            assert!(c.split.processes.is_empty() && c.split.domains.is_empty());
        }
        // 往返：写盘再读回来保持一致
        let t = OK.replace(
            "\"schema\":2",
            "\"schema\":2,\"split\":{\"processes\":[\"TDXW.exe\"],\"domains\":[\"qq.com\"]}",
        );
        let c = parse(&t).unwrap();
        assert_eq!(c.split.processes[0].value(), "TDXW.exe");
        assert_eq!(c.split.domains[0].value(), "qq.com");
        let root = std::env::temp_dir().join(format!("tcrs-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join(DEFAULT_PATH);
        save(&p, &c).unwrap();
        assert_eq!(load(&p).unwrap().unwrap().split, c.split, "分流规则要能存下去再读回来");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_target_labels_are_fool_proof() {
        // D5 回归：分流规则的落点必须说全称。只写「交易」「日常」会被读成"走直连"，
        // 尤其旁边还有一条真的「直连」规则时。
        assert_eq!(SplitTarget::Direct.label(), "直连");
        assert_eq!(SplitTarget::Trade.label(), "交易出口");
        assert_eq!(SplitTarget::Daily.label(), "日常出口");
    }

    #[test]
    fn split_input_validation_rejects_forms_that_can_never_match() {
        // 进程名：路径 / 无扩展名都要拒绝——这类写法存下去就是"永远匹配不上却不报错"。
        assert!(SplitConfig::validate_process("TDXW.exe").is_ok());
        assert!(SplitConfig::validate_process("tdxw.EXE").is_ok(), "大小写无所谓");
        let e = SplitConfig::validate_process(r"C://Program Files//TDXW.exe").unwrap_err();
        assert!(e.contains("不要填完整路径"), "{e}");
        assert!(SplitConfig::validate_process("TDXW").unwrap_err().contains(".exe 结尾"));
        assert!(SplitConfig::validate_process("a/b.exe").is_err(), "斜杠也算路径");

        // 域名：带协议/路径、单级都要拒绝
        assert!(SplitConfig::validate_domain("qq.com").is_ok());
        assert!(SplitConfig::validate_domain("*.qq.com").is_ok());
        assert!(SplitConfig::validate_domain("sub.qq.com").is_ok());
        let e = SplitConfig::validate_domain("https://qq.com").unwrap_err();
        assert!(e.contains("不要带协议或路径"), "{e}");
        assert!(SplitConfig::validate_domain("qq.com/path").unwrap_err().contains("不要带协议或路径"));
        assert!(SplitConfig::validate_domain("localhost").unwrap_err().contains("至少要有两级"));
    }

    #[test]
    fn split_add_and_remove_are_case_insensitive_and_normalize_domains() {
        let mut sp = SplitConfig::default();
        assert!(sp.add_process("TDXW.exe", SplitTarget::Direct), "第一次加应当成功");
        assert!(!sp.add_process("tdxw.EXE", SplitTarget::Direct), "大小写不同也算重复");
        assert_eq!(sp.processes.len(), 1, "重复添加只保留一条");

        assert!(sp.add_domain("*.QQ.com", SplitTarget::Direct));
        assert_eq!(sp.domains[0].value(), "qq.com", "存的是去掉 *. 的小写形式");
        assert!(!sp.add_domain("qq.com", SplitTarget::Direct), "归一后相同也算重复");
        assert!(!sp.add_domain("  ", SplitTarget::Direct), "空值不许进规则");

        assert!(sp.remove_process("Tdxw.exe"), "删除也应大小写不敏感");
        assert!(!sp.remove_process("TDXW.exe"), "删不存在的返回 false");
        assert!(sp.remove_domain("*.qq.com"), "删除域名同样先归一");
        assert!(sp.is_empty(), "删空后 is_empty 必须为真");
    }

    #[test]
    fn resetting_trade_domains_restores_the_legacy_defaults_without_touching_other_targets() {
        let mut sp = SplitConfig::default();
        sp.add_process("TDXW.exe", SplitTarget::Trade);
        sp.add_domain("custom-trade.com", SplitTarget::Trade);
        sp.add_domain("daily-site.com", SplitTarget::Daily);
        sp.add_domain("tradingview.com", SplitTarget::Direct);

        assert!(sp.reset_trade_domains(), "从自定义名单恢复必须算变化");
        let values: Vec<&str> = sp.domains.iter().map(|e| e.value()).collect();
        assert_eq!(
            values,
            vec![
                "daily-site.com",
                "tradingview.com",
                "tradingview-widget.com",
                "tradingviewusercontent.com",
                "tvc-cdn.com",
                "tradovate.com",
                "tradovateapi.com",
                "ninjatrader.com",
            ],
            "只替换交易出口那一组；默认值冲突的旧条目让位并排到最后"
        );
        assert!(
            sp.domains.iter().filter(|e| e.target() == SplitTarget::Trade).all(|e| {
                SplitConfig::DEFAULT_TRADE_DOMAINS.contains(&e.value())
            }),
            "交易出口下只剩下默认值"
        );
        assert_eq!(
            sp.domains.iter().find(|e| e.value() == "daily-site.com").map(|e| e.target()),
            Some(SplitTarget::Daily),
            "其它出口的规则必须原样保留"
        );
        assert_eq!(sp.processes.len(), 1, "程序名单不归这个按钮管");
        assert!(!sp.reset_trade_domains(), "再点一次不该算变化");
    }

    #[test]
    fn empty_lines_is_legal_and_has_no_current_line() {
        let c = parse(r#"{"schema":2,"lines":[]}"#).unwrap();
        assert!(c.current_line().is_none(), "线路删光了也要能读出来（connect 时再拒绝）");
    }

    // ---------- 连接方式（标准连接 Udp / 兼容连接 Tcp）----------

    #[test]
    fn missing_transport_means_udp_for_old_configs() {
        // 回归：加这个字段之前的所有配置都没有它。必须读成「没选过」→ 标准连接，
        // 而且再保存时不许冒出一个默认值写进用户文件（老配置读写一圈要原样）。
        let c = parse(OK).unwrap();
        let line = c.current_line().unwrap();
        assert!(line.transport.is_none(), "缺字段 = 没选过，不能当成「用户选了 Udp」");
        assert_eq!(line.effective_transport(), Transport::Udp, "没选过就走标准连接");
        let back = serde_json::to_string(&c).unwrap();
        assert!(!back.contains("transport"), "没选过就别往用户配置里写这个字段：{back}");
    }

    #[test]
    fn transport_choice_is_persisted_and_kept_distinct_from_the_default() {
        // 「用户选了 Udp」与「没选过」行为一样，但 --lines 要如实区分，所以值必须真的存下来。
        let root = std::env::temp_dir().join(format!("tcrs-cfg-tr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join(DEFAULT_PATH);

        for chosen in [Transport::Tcp, Transport::Udp] {
            let mut cfg = parse(OK).unwrap();
            cfg.lines[0].transport = Some(chosen);
            save(&p, &cfg).unwrap();
            let back = load(&p).unwrap().unwrap();
            assert_eq!(back.lines[0].transport, Some(chosen), "切换后重读必须是新选择");
            assert_eq!(back.lines[0].effective_transport(), chosen);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn transport_ids_labels_and_parsing_are_exact() {
        // id 与旧版注册表一致（Tcp/Udp），中文名与 DisplayName 一致。
        assert_eq!(Transport::Udp.id(), "udp");
        assert_eq!(Transport::Tcp.id(), "tcp");
        assert_eq!(Transport::Udp.label(), "标准连接");
        assert_eq!(Transport::Tcp.label(), "兼容连接");
        assert_eq!(Transport::from_name("tcp"), Some(Transport::Tcp));
        assert_eq!(Transport::from_name(" TCP "), Some(Transport::Tcp), "大小写与空白都要容忍");
        assert_eq!(Transport::from_name("udp"), Some(Transport::Udp));
        // 认不出就返回 None：这里兜底成 udp 等于偷偷换掉用户的默认线路方式。
        assert_eq!(Transport::from_name("quic"), None);
        assert_eq!(Transport::from_name(""), None);
        // 落盘用小写 id，与 mode 的风格一致
        assert_eq!(serde_json::to_string(&Transport::Tcp).unwrap(), "\"tcp\"");
        // 配置里写了认不出的值 → 报错，不许静默当成 udp（那是在偷偷改用户的默认方式）。
        let bad = r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:7890","transport":"quic"}]}"#;
        assert!(matches!(parse(bad), Err(ConfigError::Parse(_))), "{bad}");
    }

    // ---------- 其余选项 ----------

    #[test]
    fn missing_mode_means_proxy_for_old_configs() {
        // 加了 mode 之后，用户现有的 config.json（没有这一项）必须照旧能读，
        // 而且默认语义是「代理」——不能悄悄改成别的接管方式。
        let c = parse(OK).unwrap();
        assert_eq!(c.mode, Mode::Proxy);
        assert_eq!(c.mode.label(), "代理");
        let back = serde_json::to_string(&c).unwrap();
        assert!(back.contains("\"mode\":\"proxy\""), "保存后应写死当前模式：{back}");
    }

    #[test]
    fn tun_mode_roundtrips() {
        let t = OK.replace("\"schema\":2", "\"schema\":2,\"mode\":\"tun\"");
        let c = parse(&t).unwrap();
        assert_eq!(c.mode, Mode::Tun);
        assert_eq!(c.mode.label(), "TUN");
        let root = std::env::temp_dir().join(format!("tcrs-cfg-tun-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        save(&p, &c).unwrap();
        assert_eq!(load(&p).unwrap().unwrap().mode, Mode::Tun, "tun 模式要能存下来再读回来");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mode_from_name_is_forgiving() {
        // 界面/管道传来的值不可控：认不出就按最保守的代理走，别让一个拼错的值把导入卡死。
        assert_eq!(Mode::from_name("tun"), Mode::Tun);
        assert_eq!(Mode::from_name(" TUN "), Mode::Tun, "大小写与空白都要容忍");
        assert_eq!(Mode::from_name("proxy"), Mode::Proxy);
        assert_eq!(Mode::from_name("quic"), Mode::Proxy, "认不出的按代理");
        assert_eq!(Mode::from_name(""), Mode::Proxy, "缺省按代理");
    }

    #[test]
    fn rejects_unknown_mode() {
        // 认不出的模式宁可报错：按错的模式去改网络，比不启动更糟。
        let t = OK.replace("\"schema\":2", "\"schema\":2,\"mode\":\"quic\"");
        assert!(matches!(parse(&t), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn missing_auto_flags_mean_off_for_old_configs() {
        let c = parse(OK).unwrap();
        assert!(!c.auto_start, "缺字段时不能默认开机自启");
        assert!(!c.auto_connect, "缺字段时不能默认自动连接");
        let back = serde_json::to_string(&c).unwrap();
        assert!(back.contains("\"auto_start\":false"), "{back}");
        assert!(back.contains("\"auto_connect\":false"), "{back}");
    }

    #[test]
    fn auto_flags_roundtrip() {
        let t = OK.replace("\"schema\":2", "\"schema\":2,\"auto_start\":true,\"auto_connect\":true");
        let c = parse(&t).unwrap();
        assert!(c.auto_start && c.auto_connect);
        let root = std::env::temp_dir().join(format!("tcrs-cfg-auto-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        save(&p, &c).unwrap();
        let back = load(&p).unwrap().unwrap();
        assert!(back.auto_start && back.auto_connect, "两个开关要能存下去再读回来");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_close_to_tray_keeps_the_old_behaviour() {
        let c = parse(OK).unwrap();
        assert!(!c.close_to_tray, "缺字段时不能默认常驻");
        let back = serde_json::to_string(&c).unwrap();
        assert!(back.contains("\"close_to_tray\":false"), "{back}");
    }

    #[test]
    fn save_then_load_roundtrip() {
        let root = std::env::temp_dir().join(format!("tcrs-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        let cfg = parse(OK).unwrap();
        save(&p, &cfg).unwrap();
        let back = load(&p).unwrap().unwrap();
        assert_eq!(back, cfg);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let root = std::env::temp_dir().join(format!("tcrs-cfg2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        let cfg = parse(OK).unwrap();
        save(&p, &cfg).unwrap();
        assert!(!p.with_extension("json.tmp").exists(), "临时文件必须已被替换掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_file_is_none() {
        let p = std::env::temp_dir().join("tcrs-no-such-config.json");
        assert!(load(&p).unwrap().is_none());
    }

    #[test]
    fn tolerates_utf8_bom() {
        // PowerShell 5.1 的 `-Encoding UTF8` 会写 BOM；serde_json 不认，合法配置会被判格式错误。
        let root = std::env::temp_dir().join(format!("tcrs-cfg-bom-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        std::fs::write(&p, format!("\u{feff}{OK}")).unwrap();
        let c = load(&p).unwrap().expect("带 BOM 的合法配置必须能读");
        assert_eq!(c.current_line().unwrap().proxy_endpoint, "127.0.0.1:7890");
        assert!(parse(&format!("\u{feff}{OK}")).is_ok(), "直接 parse 也要容忍 BOM");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_json_is_error_not_none() {
        let root = std::env::temp_dir().join(format!("tcrs-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        std::fs::write(&p, "{not json").unwrap();
        assert!(load(&p).is_err(), "存在但坏掉的文件不能当成「没配置」");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ids_are_slugged_and_safe_for_file_names() {
        assert_eq!(slug("HK-1"), "hk-1");
        assert_eq!(slug("香港 01"), "99996e2f01", "中文按码点转，保证唯一");
        assert_eq!(slug("   "), "line", "空名也要有个 id");
        assert_eq!(safe_file_stem("a/b:c"), "a_b_c", "路径分隔符与冒号不能进文件名");
        assert_eq!(safe_file_stem(""), "line");
    }

    // ---------- AI 工具名单：配置往返、老配置兜底、归一 ----------

    #[test]
    fn agents_section_round_trips_and_is_byte_stable() {
        let root = std::env::temp_dir().join(format!("tcrs-cfg-agents-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        let mut cfg = parse(OK).unwrap();
        cfg.agents = AgentsConfig {
            lane: AgentsLane::Trade,
            // 故意乱序 + 重复：归一后必须稳定
            builtin: vec!["chatgpt-web".into(), "claude-code".into(), "chatgpt-web".into()],
            programs: vec!["claude.exe".into()],
            sites: vec!["*.Perplexity.AI".into()],
        };
        // 生产路径里写盘前一律先归一（`ipc::save_agents`），这里照同一条契约做，
        // 这样才能验「读→写→再写」字节稳定。
        cfg.agents.sanitize();
        save(&p, &cfg).unwrap();
        let first = std::fs::read_to_string(&p).unwrap();
        let back = load(&p).unwrap().expect("写进去的配置必须能读回来");
        assert_eq!(back.agents.lane, AgentsLane::Trade);
        assert_eq!(back.agents.builtin, vec!["claude-code", "chatgpt-web"], "按目录顺序重排");
        assert_eq!(back.agents.programs, vec!["claude.exe"]);
        assert_eq!(back.agents.sites, vec!["perplexity.ai"], "去 `*.`、小写");
        // 读 → 再写：字节必须一模一样（否则「保存」会在用户没改的情况下改文件）。
        save(&p, &back).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), first, "往返必须字节稳定");
        // schema 仍是 2：升版本会让回滚到旧版时拒绝启动。
        assert_eq!(back.schema, 2);
        assert!(first.contains("\"agents\""), "配置里要有独立一节：{first}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_agents_section_reads_as_daily_with_empty_list() {
        // 老配置（没有 `agents` 节）：不能报错，读成「跟随日常上网 + 空名单」。
        let c = parse(OK).unwrap();
        assert_eq!(c.agents.lane, AgentsLane::Daily, "默认跟随日常上网");
        assert!(c.agents.is_empty(), "三个列表都必须为空");
        assert_eq!(c.agents, AgentsConfig::default());
        // 手写一个只有 lane 的节也要能读
        let t = OK.replace(
            "\"schema\":2",
            "\"schema\":2,\"agents\":{\"lane\":\"trade\"}",
        );
        let c = parse(&t).unwrap();
        assert_eq!(c.agents.lane, AgentsLane::Trade);
        assert!(c.agents.is_empty());
        // 坏值不能让程序起不来：三个列表里的坏值一律静默丢弃（**读路径**才做归一，
        // 所以这里必须走 `load` 而不是纯解析）。
        let root = std::env::temp_dir().join(format!("tcrs-cfg-agents-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let p = root.join(DEFAULT_PATH);
        let t = OK.replace(
            "\"schema\":2",
            "\"schema\":2,\"agents\":{\"builtin\":[\"no-such-item\"],\"programs\":[\"a.txt\",\"\"],\"sites\":[\"abc\",\"\"]}",
        );
        std::fs::write(&p, t).unwrap();
        let c = load(&p).unwrap().expect("坏值不该让配置读不出来");
        assert!(c.agents.is_empty(), "坏值读完是空的，且不报错：{c:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_builtin_ids_are_dropped_silently() {
        let mut cfg = AgentsConfig {
            lane: AgentsLane::Trade,
            builtin: vec!["ghost-item".into(), "cursor".into()],
            programs: vec!["a.exe".into()],
            sites: vec!["qq.com".into()],
        };
        cfg.sanitize();
        assert_eq!(cfg.builtin, vec!["cursor"], "不认识的 id 静默丢，不影响其它字段");
        assert_eq!(cfg.programs, vec!["a.exe"]);
        assert_eq!(cfg.sites, vec!["qq.com"]);
        assert_eq!(cfg.lane, AgentsLane::Trade);
    }

    #[test]
    fn sanitize_dedupes_and_normalizes() {
        let mut cfg = AgentsConfig {
            lane: AgentsLane::Daily,
            builtin: vec!["cursor".into(), " Cursor ".into(), "cursor".into()],
            programs: vec!["A.exe".into(), " a.EXE ".into(), "no-path/allowed.exe".into()],
            sites: vec!["*.QQ.com".into(), "qq.com".into(), " QQ.com ".into(), "abc".into()],
        };
        cfg.sanitize();
        assert_eq!(cfg.builtin, vec!["cursor"], "同一项勾三次也只算一次");
        assert_eq!(cfg.programs, vec!["A.exe"], "大小写不敏感去重，留第一次的拼写");
        assert_eq!(cfg.sites, vec!["qq.com"], "三种写法归一成一条");
        assert_eq!(cfg.lane, AgentsLane::Daily, "sanitize 不动走向");
        // 幂等：再跑一次一个字都不变
        let once = cfg.clone();
        cfg.sanitize();
        assert_eq!(cfg, once, "sanitize 必须幂等");
    }

    #[test]
    fn custom_over_limit_is_truncated_on_load() {
        let mut cfg = AgentsConfig::default();
        cfg.programs = (0..40).map(|i| format!("p{i}.exe")).collect();
        cfg.sites = (0..5).map(|i| format!("site{i}.com")).collect();
        cfg.sanitize();
        assert_eq!(cfg.custom_count(), crate::agents::MAX_CUSTOM, "合计上限 32");
        assert_eq!(cfg.programs.len(), 32, "先程序、先到先得");
        assert!(cfg.sites.is_empty(), "程序用满了额度，网站一个都进不来");

        let mut cfg = AgentsConfig::default();
        cfg.programs = (0..10).map(|i| format!("p{i}.exe")).collect();
        cfg.sites = (0..40).map(|i| format!("site{i}.com")).collect();
        cfg.sanitize();
        assert_eq!(cfg.programs.len(), 10);
        assert_eq!(cfg.sites.len(), 22, "剩下 22 个额度给网站");
    }

    #[test]
    fn agents_lane_accepts_both_spellings_and_rejects_the_rest() {
        assert_eq!(AgentsLane::from_value("Daily"), Some(AgentsLane::Daily));
        assert_eq!(AgentsLane::from_value("daily"), Some(AgentsLane::Daily));
        assert_eq!(AgentsLane::from_value(" Trade "), Some(AgentsLane::Trade));
        // 名单没有「直连」这个语义：认不出就返回 None，调用方如实报错。
        assert_eq!(AgentsLane::from_value("direct"), None);
        assert_eq!(AgentsLane::from_value(""), None);
    }

    // -----------------------------------------------------------------
    // 交易保护：名单条目的可选绝对路径（T02）
    // -----------------------------------------------------------------

    /// 拼一个本机绝对路径（`C:` + 逐段 join）。
    ///
    /// 全部路径夹具都走它：这样测试源码里**不出现任何反斜杠字面量**，
    /// 也就不会有「转义了几个」这种与逻辑无关的坑。
    fn win_path(parts: &[&str]) -> String {
        let sep = std::path::MAIN_SEPARATOR;
        format!("C:{sep}{}", parts.join(&sep.to_string()))
    }

    #[test]
    fn a_split_entry_without_path_serializes_exactly_as_before() {
        // 这是「不升 schema 也不改字节」那条约束的直接证明：同样的输入，
        // 有没有 path 字段参与，输出必须逐字节相同。
        let with_path_none = SplitEntry::with_path("TDXW.exe", SplitTarget::Trade, None);
        let legacy_shape = SplitEntry::Full {
            value: "TDXW.exe".to_string(),
            target: SplitTarget::Trade,
            path: None,
        };
        assert_eq!(
            serde_json::to_string(&with_path_none).unwrap(),
            serde_json::to_string(&legacy_shape).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&with_path_none).unwrap(),
            r#"{"value":"TDXW.exe","target":"trade"}"#,
            "没写 path 时的字节形态必须与加这个字段之前完全一致"
        );
        // 直连条目仍然是裸字符串（历史写法不变）
        assert_eq!(
            serde_json::to_string(&SplitEntry::new("curl.exe", SplitTarget::Direct)).unwrap(),
            r#""curl.exe""#
        );
        // 空路径等于没有路径（空串不是路径，不该被写进配置）
        assert_eq!(
            serde_json::to_string(&SplitEntry::with_path("a.exe", SplitTarget::Trade, Some("  ")))
                .unwrap(),
            r#"{"value":"a.exe","target":"trade"}"#
        );
    }

    #[test]
    fn a_split_entry_with_path_round_trips_and_stays_readable_by_old_versions() {
        let path = win_path(&["T", "TDXW.exe"]);
        let e = SplitEntry::with_path("TDXW.exe", SplitTarget::Trade, Some(&path));
        let text = serde_json::to_string(&e).unwrap();
        assert!(text.contains("\"path\""), "{text}");
        assert!(text.contains("TDXW.exe"), "{text}");
        let back: SplitEntry = serde_json::from_str(&text).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.path(), Some(path.as_str()));

        // 旧版本读到带 path 的文件：serde 忽略未知字段（结构里没有 deny_unknown_fields），
        // 所以「老 exe 读新配置」不会报错，只是丢掉 path —— 这正是回滚时该有的降级。
        #[derive(serde::Deserialize)]
        struct LegacyFull {
            value: String,
            #[serde(default)]
            target: SplitTarget,
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum LegacyEntry {
            Plain(String),
            Full(LegacyFull),
        }
        let legacy: LegacyEntry = serde_json::from_str(&text).expect("旧结构必须能读新文件");
        match legacy {
            LegacyEntry::Full(f) => {
                assert_eq!(f.value, "TDXW.exe");
                assert_eq!(f.target, SplitTarget::Trade);
            }
            LegacyEntry::Plain(_) => panic!("不该被读成裸字符串"),
        }
    }

    #[test]
    fn old_configs_without_path_still_load() {
        let text = r#"{"value":"TDXW.exe","target":"trade"}"#;
        let e: SplitEntry = serde_json::from_str(text).unwrap();
        assert_eq!(e.value(), "TDXW.exe");
        assert_eq!(e.target(), SplitTarget::Trade);
        assert_eq!(e.path(), None, "老条目就是没有路径，不该被补一个");
        // 裸字符串（更老的写法）
        let e: SplitEntry = serde_json::from_str(r#""curl.exe""#).unwrap();
        assert_eq!(e.target(), SplitTarget::Direct);
        assert_eq!(e.path(), None);
    }

    #[test]
    fn add_process_still_deduplicates_by_name_only() {
        // 老行为不能变：命令行 `--add-process` 只有名字。
        let mut s = SplitConfig::default();
        assert!(s.add_process("TDXW.exe", SplitTarget::Trade));
        assert!(!s.add_process("tdxw.exe", SplitTarget::Trade), "同名重复添加 = 无变化");
        assert!(s.add_process("TDXW.exe", SplitTarget::Direct), "改目标算变化");
        assert_eq!(s.processes.len(), 1, "永远只有一条");
        assert_eq!(s.processes[0].target(), SplitTarget::Direct);
        assert_eq!(s.processes_for(SplitTarget::Direct), vec!["TDXW.exe".to_string()]);
        assert!(s.processes_for(SplitTarget::Trade).is_empty());
    }

    #[test]
    fn add_process_keeps_an_already_confirmed_path() {
        // 「又点了一次同名添加」不该把已经确认过的程序位置抹掉。
        let path = win_path(&["T", "TDXW.exe"]);
        let mut s = SplitConfig::default();
        assert!(s.add_process_entry("TDXW.exe", SplitTarget::Trade, Some(&path)));
        assert!(!s.add_process("TDXW.exe", SplitTarget::Trade), "同名同目标 = 无变化");
        assert_eq!(s.processes[0].path(), Some(path.as_str()), "路径必须还在");
    }

    #[test]
    fn add_process_entry_only_touches_the_path_when_it_changes() {
        let a = win_path(&["a.exe"]);
        let b = win_path(&["b", "a.exe"]);
        let mut s = SplitConfig::default();
        assert!(s.add_process_entry("a.exe", SplitTarget::Trade, None));
        assert_eq!(s.processes[0].path(), None);
        assert!(!s.add_process_entry("a.exe", SplitTarget::Trade, None), "没给路径 = 无变化");
        assert!(s.add_process_entry("a.exe", SplitTarget::Trade, Some(&a)), "补上路径 = 变化");
        assert_eq!(s.processes[0].path(), Some(a.as_str()));
        assert!(!s.add_process_entry("A.EXE", SplitTarget::Trade, Some(&a)), "同路径 = 无变化");
        assert!(s.add_process_entry("a.exe", SplitTarget::Trade, Some(&b)), "换路径 = 变化");
        assert_eq!(s.processes[0].path(), Some(b.as_str()));
        assert_eq!(s.processes.len(), 1, "同名不同路径不会变成两条");
    }

    #[test]
    fn changing_the_target_carries_the_path_over() {
        let path = win_path(&["a.exe"]);
        let mut s = SplitConfig::default();
        s.add_process_entry("a.exe", SplitTarget::Trade, Some(&path));
        assert!(s.add_process_entry("a.exe", SplitTarget::Daily, None), "改目标 = 变化");
        assert_eq!(s.processes[0].target(), SplitTarget::Daily);
        assert_eq!(s.processes[0].path(), Some(path.as_str()), "没给新路径就沿用旧的，别静默丢信息");
        // 改回交易出口时也算变化
        assert!(s.add_process_entry("a.exe", SplitTarget::Trade, None));
        assert_eq!(s.processes[0].target(), SplitTarget::Trade);
        assert_eq!(s.processes[0].path(), Some(path.as_str()));
    }

    #[test]
    fn validate_process_path_rejects_the_ambiguous_forms() {
        assert!(SplitConfig::validate_process_path(&win_path(&["Program Files", "T", "TDXW.exe"])).is_ok());
        assert!(SplitConfig::validate_process_path(&win_path(&["a", "b.EXE"])).is_ok(), "扩展名大小写不敏感");
        assert!(SplitConfig::validate_process_path("").is_err());
        assert!(SplitConfig::validate_process_path("TDXW.exe").is_err(), "相对路径不行");
        assert!(SplitConfig::validate_process_path("C:TDXW.exe").is_err(), "盘符相对也不行");
        assert!(SplitConfig::validate_process_path(&win_path(&["a", "b.dll"])).is_err());
        assert!(SplitConfig::validate_process_path(&win_path(&["a", "b"])).is_err());
    }

    #[test]
    fn adding_a_path_does_not_change_the_generated_engine_rules() {
        // 回归钉子（T02 DoD #6）：名单里有没有 path，生成的 `process_name` 规则必须
        // **逐字节**相同。否则「补一个路径」就会悄悄改动引擎行为。
        let mut without = SplitConfig::default();
        without.add_process("TDXW.exe", SplitTarget::Trade);
        without.add_process("curl.exe", SplitTarget::Direct);
        let mut with = SplitConfig::default();
        with.add_process_entry("TDXW.exe", SplitTarget::Trade, Some(&win_path(&["T", "TDXW.exe"])));
        with.add_process_entry(
            "curl.exe",
            SplitTarget::Direct,
            Some(&win_path(&["Windows", "system32", "curl.exe"])),
        );

        fn rules(split: &SplitConfig) -> String {
            let mut profile: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
                r#"{"route":{"rules":[],"final":"direct"},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
            )
            .unwrap();
            crate::engine_config::normalize_split(&mut profile, split, &AgentsConfig::default());
            serde_json::to_string(&profile["route"]["rules"]).unwrap()
        }
        assert_eq!(rules(&without), rules(&with), "加 path 不许改动引擎规则");
        // 同时确认规则里确实有 process_name（否则上面那条「相同」可能是「都空」）
        let text = rules(&with);
        assert!(text.contains("process_name"), "{text}");
    }

    // ---------- 「自动」这一档：verified_transport 的读写 ----------

    /// 老配置里没有 `verified_transport`：读成 `None`，生效方式仍是标准连接，
    /// 序列化时也不把键写出来（没验证过的线路不该在文件里凭空多一项）。
    #[test]
    fn an_old_config_has_no_verified_transport_and_never_gains_the_key() {
        let c = parse(OK).unwrap();
        let line = c.current_line().expect("OK 里有线路");
        assert_eq!(line.verified_transport, None, "老配置不能凭空多出「已验证」");
        assert_eq!(line.effective_transport(), Transport::Udp, "缺依据时兜底标准连接");
        let back = serde_json::to_string(&c).unwrap();
        assert!(!back.contains("verified_transport"), "没验证过就不该写这个键：{back}");
    }

    /// 三档优先级：**用户固定 → 已验证 → 标准连接**。
    #[test]
    fn effective_transport_prefers_the_user_choice_over_the_verified_one() {
        let c = parse(OK).unwrap();
        let mut line = c.current_line().cloned().expect("OK 里有线路");
        // 用户固定 tcp、这条线路验证过 udp → 用 tcp（他改主意了，不能被「上次通过」覆盖）。
        line.transport = Some(Transport::Tcp);
        line.verified_transport = Some(Transport::Udp);
        assert_eq!(line.effective_transport(), Transport::Tcp, "用户固定优先");
        // 没固定、验证过 tcp → 用 tcp（这就是「自动」的全部含义）。
        line.transport = None;
        line.verified_transport = Some(Transport::Tcp);
        assert_eq!(line.effective_transport(), Transport::Tcp, "自动采用已验证的方式");
        // 都没有 → 策略默认。
        line.verified_transport = None;
        assert_eq!(line.effective_transport(), Transport::Udp, "什么依据都没有时是标准连接");
    }

    /// `record_verified_transport` / `clear_verified_transport` 必须**幂等**：
    /// 连接每次成功都会调记录，同值还写盘就会把 config.json 反复改 mtime、刷操作记录。
    ///
    /// 不设 `SPIDERVPN_ROOT`：这两个函数只认调用方给的 `root`（就在临时目录里），
    /// 不读环境变量、也不碰注册表与现场装机目录；下面用「文件内容一个字节没变」证明没写盘。
    #[test]
    fn record_and_clear_verified_transport_are_idempotent() {
        let root = std::env::temp_dir().join(format!("tcrs-cfg-verified-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join(DEFAULT_PATH);
        save(&p, &parse(OK).unwrap()).unwrap();

        // 首次记录：真的写盘，且能读回。
        assert!(
            record_verified_transport(&root, "L1", Transport::Tcp).unwrap(),
            "首次记录必须落盘"
        );
        let back = load(&p).unwrap().unwrap();
        assert_eq!(back.lines[0].verified_transport, Some(Transport::Tcp), "要能读回来");
        assert_eq!(back.lines[0].effective_transport(), Transport::Tcp, "「自动」随即生效");

        // 同值再来一次：返回 false，文件内容一字不差。
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(
            !record_verified_transport(&root, "L1", Transport::Tcp).unwrap(),
            "同值不许再写盘"
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before, "同值时文件不能被重写");

        // 换一种方式：这次要写盘并覆盖。
        assert!(record_verified_transport(&root, "L1", Transport::Udp).unwrap(), "变化必须落盘");
        assert_eq!(
            load(&p).unwrap().unwrap().lines[0].verified_transport,
            Some(Transport::Udp)
        );

        // 清除：首次写盘，第二次本来就没有 → false 且不写盘。
        assert!(clear_verified_transport(&root, "L1").unwrap(), "首次清除要写盘");
        assert_eq!(load(&p).unwrap().unwrap().lines[0].verified_transport, None);
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(!clear_verified_transport(&root, "L1").unwrap(), "已经是空就不该写盘");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before, "幂等清除不许碰文件");

        // 清除不动用户固定：`transport` 是选择，不是证据。
        let mut cfg = load(&p).unwrap().unwrap();
        cfg.lines[0].transport = Some(Transport::Tcp);
        cfg.lines[0].verified_transport = Some(Transport::Tcp);
        save(&p, &cfg).unwrap();
        assert!(clear_verified_transport(&root, "L1").unwrap());
        let back = load(&p).unwrap().unwrap();
        assert_eq!(back.lines[0].verified_transport, None);
        assert_eq!(back.lines[0].transport, Some(Transport::Tcp), "用户的选择不能被清掉");
        assert_eq!(back.lines[0].effective_transport(), Transport::Tcp);

        // 不存在的线路要报错，而不是默默当成功（调用方靠它发现「记错了对象」）。
        assert!(record_verified_transport(&root, "NOPE", Transport::Tcp).is_err());
        assert!(clear_verified_transport(&root, "NOPE").is_err());

        let _ = std::fs::remove_dir_all(&root);
    }
}
