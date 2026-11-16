//! AI 工具名单：内置目录（对齐 旧版）、匹配模式、有效名单与走向口径。
//!
//! 本模块只做**数据 + 纯函数**：不读写文件、不碰 JSON 结构。落盘（`config.json`）、
//! 规则合成（`engine_config`）、界面投影（`uiweb_form` / `ipc`）各自调这里的函数，
//! 三处共用同一份目录与同一个走向谓词——「页面说会生效」与「生成时真会生成」才不会分叉。
//!
//! 与旧版的对齐口径（`runtime\TradeChannel.Agents.ps1`）：
//! 1. **目录逐项移植**：22 项（11 程序 + 9 网页版 + 2 服务域名），id/名称/匹配模式/
//!    Detail 文案/安装路径/MSIX 包名与其一致；
//! 2. **程序按进程路径正则识别**（sing-box `process_path_regex`），不再用进程名——
//!    旧版就是这样同时覆盖 Claude 老 Squirrel（claude.exe）与新 MSIX（WindowsApps\Claude_）的；
//! 3. **三类规则**：程序（路径正则）/ 网页版（浏览器正则 + 域名）/ 服务（纯域名，
//!    浏览器与其他程序访问都走）；
//! 4. **优先级靠规则顺序**（交易名单在前、AI 工具在后），与旧版相同；
//!    与交易名单的重叠只做界面标注，不做减法。
//!
//! 有意分歧（记录在交付文档）：自定义程序仍是「exe 名」（旧版存完整路径），
//! 生成时转成 `(?i)\\<字面转义>$` 路径正则；旧版的 DNS 规则集（agents-dns.json，
//! 让名单域名解析也走交易线路）暂未移植。

use crate::config::{AgentsConfig, SplitConfig};

/// 自定义条目（程序 + 网站合计）上限。与旧版的「自定义上限 32」对齐。
pub const MAX_CUSTOM: usize = 32;

/// 「网页版」规则里浏览器的识别模式（旧版的 `BrowserPattern` + 常用国产浏览器）。
///
/// sing-box 在 Windows 上按**完整路径**匹配 `process_path_regex`；`(?i)` 让大小写无关。
pub const BROWSER_PATH_REGEX: &str = r"(?i)\\(chrome|msedge|firefox|brave|opera|opera_gx|vivaldi|chromium|arc|comet|360se|360chrome|qqbrowser|sogouexplorer)\.exe$";

/// 内置条目的识别方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    /// 按进程路径正则识别：该程序访问的所有网址都随之走。
    Program,
    /// 按「浏览器 + 域名」识别：只有浏览器访问这些网址时才走。
    Web,
    /// 按纯域名识别：浏览器与其他程序（VS Code、命令行工具）访问都走。
    Service,
}

impl AgentKind {
    /// 机器可用的写法（IPC 回包与 `config.json` 里的同类字段用小写）。
    pub fn id(&self) -> &'static str {
        match self {
            AgentKind::Program => "program",
            AgentKind::Web => "web",
            AgentKind::Service => "service",
        }
    }

    /// 名单页的分组标题（与旧版的三个分组一致）。
    pub fn group_label(&self) -> &'static str {
        match self {
            AgentKind::Program => "桌面程序",
            AgentKind::Web => "网页版",
            AgentKind::Service => "模型 API 与下载平台",
        }
    }

    /// 页面上那一句说明（不含具体工具名——名字来自目录，文案里不写死工具名）。
    pub fn note(&self) -> &'static str {
        match self {
            AgentKind::Program => "它访问的网址都随之走",
            AgentKind::Web => "只有浏览器访问这些网址时才走",
            AgentKind::Service => "浏览器和其他程序访问这些域名都走",
        }
    }
}

/// 内置目录里的一项（数据与旧版的 `Get-TCAgentCatalog` 逐项对齐）。
///
/// `id` 是**落盘用的稳定标识**：配置里存的是它，不是进程名/域名。目录会扩、会改匹配方式，
/// 存 id 才能做到「改一个 value」不动用户配置。
#[derive(Debug, Clone, Copy)]
pub struct BuiltinAgent {
    pub id: &'static str,
    pub name: &'static str,
    pub short: &'static str,
    pub kind: AgentKind,
    /// Program：进程路径正则（sing-box `process_path_regex` 求值）。
    pub paths: &'static [&'static str],
    /// Web/Service：域名后缀；Program：浏览器访问也随名单走的域名（旧版的 `BrowserDomains`）。
    /// 旧版里 Program 项另有仅用于 DNS 规则集的 `Domains`——DNS 集暂未移植，这里不存。
    pub domains: &'static [&'static str],
    /// 页面上一行的说明文案（旧版的 `Detail`，原文照抄）。
    pub detail: &'static str,
    /// 「已安装」探测路径（支持 %LOCALAPPDATA% 等环境变量）。
    pub installed: &'static [&'static str],
    /// MSIX 包名（用 `%LOCALAPPDATA%\Packages\<包名>_` 前缀目录做存在性近似）。
    pub package: Option<&'static str>,
}

/// 22 项目录（11 程序 + 9 网页版 + 2 服务域名），与旧版一致。
///
/// 目录是**数据**：实测发现某个匹配模式不对时改这一处即可，不动任何逻辑。
pub const BUILTIN: &[BuiltinAgent] = &[
    BuiltinAgent {
        id: "mirasim",
        name: "Mirasim",
        short: "Mirasim",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\@mirasimdesktop\\"],
        domains: &[],
        detail: "Mirasim 桌面程序。它的助手由 Claude Code 执行，请同时添加 Claude Code。",
        installed: &[r"%LOCALAPPDATA%\Programs\@mirasimdesktop\Mirasim.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "claude-code",
        name: "Claude Code 与 Claude 桌面版",
        short: "Claude Code",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\claude\.exe$", r"(?i)\\WindowsApps\\Claude_[^\\]+\\"],
        domains: &[],
        detail: "claude.exe：命令行、Mirasim 调用的助手和桌面版。",
        installed: &[
            r"%APPDATA%\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
            r"%USERPROFILE%\.local\bin\claude.exe",
        ],
        package: Some("Claude"),
    },
    BuiltinAgent {
        id: "codex",
        name: "Codex 桌面版与命令行",
        short: "Codex",
        kind: AgentKind::Program,
        paths: &[
            r"(?i)\\WindowsApps\\OpenAI\.Codex_[^\\]+\\",
            r"(?i)\\OpenAI\\Codex\\",
            r"(?i)\\codex\.exe$",
        ],
        domains: &[],
        detail: "OpenAI Codex 应用（进程名 ChatGPT.exe）与 codex.exe。",
        installed: &[r"%APPDATA%\npm\node_modules\@openai\codex"],
        package: Some("OpenAI.Codex"),
    },
    BuiltinAgent {
        id: "antigravity",
        name: "Google Antigravity（反重力）",
        short: "Antigravity",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\Antigravity\\"],
        domains: &[],
        detail: "安装在名为 Antigravity 的目录中即可识别，包括它的语言服务。",
        installed: &[r"%LOCALAPPDATA%\Programs\Antigravity\Antigravity.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "cc-switch",
        name: "CC Switch（接口中转）",
        short: "CC Switch",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\cc-switch\.exe$"],
        domains: &[],
        detail: "Codex 或 Claude Code 经它的本地代理联网时，实际出网的是 cc-switch.exe，需一并打开。",
        installed: &[r"%LOCALAPPDATA%\Programs\CC Switch\cc-switch.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "chatgpt-app",
        name: "ChatGPT 桌面版",
        short: "ChatGPT",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\WindowsApps\\OpenAI\.ChatGPT(?:-Desktop)?_[^\\]+\\", r"(?i)\\ChatGPT\\ChatGPT\.exe$"],
        domains: &[],
        detail: "OpenAI ChatGPT 桌面程序与登录、验证、静态资源。",
        installed: &[],
        package: Some("OpenAI.ChatGPT-Desktop"),
    },
    BuiltinAgent {
        id: "cursor",
        name: "Cursor 编辑器",
        short: "Cursor",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\Cursor\\", r"(?i)\\cursor\.exe$"],
        domains: &["cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com", "accounts.x.ai", "accounts.spacex.ai"],
        detail: "Cursor 程序、模型请求、登录和云代理。",
        installed: &[r"%LOCALAPPDATA%\Programs\cursor\Cursor.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "windsurf",
        name: "Windsurf / Devin Desktop",
        short: "Windsurf / Devin",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\Windsurf\\", r"(?i)\\windsurf\.exe$", r"(?i)\\Devin Desktop\\", r"(?i)\\DevinDesktop\.exe$"],
        domains: &["windsurf.com", "codeium.com", "codeiumdata.com", "devin.ai", "cognition.ai"],
        detail: "Windsurf 与 Devin Desktop 程序、Codeium/Cognition 服务。",
        installed: &[r"%LOCALAPPDATA%\Programs\Windsurf\Windsurf.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "perplexity-app",
        name: "Perplexity 桌面版",
        short: "Perplexity",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\perplexity\.exe$", r"(?i)\\Perplexity\\"],
        domains: &["perplexity.ai", "pplx.ai"],
        detail: "Perplexity 程序；Comet 浏览器按下方网页版域名识别。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "ollama",
        name: "Ollama 模型工具",
        short: "Ollama",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\ollama\.exe$", r"(?i)\\Ollama\\"],
        domains: &[],
        detail: "联网下载模型；本机推理仍使用本地回环。",
        installed: &[r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "lmstudio",
        name: "LM Studio",
        short: "LM Studio",
        kind: AgentKind::Program,
        paths: &[r"(?i)\\LM Studio\\", r"(?i)\\LM Studio\.exe$"],
        domains: &[],
        detail: "LM Studio 程序和模型下载，本地服务保持本地。",
        installed: &[r"%LOCALAPPDATA%\Programs\LM Studio\LM Studio.exe"],
        package: None,
    },
    BuiltinAgent {
        id: "claude-web",
        name: "Claude 网页版",
        short: "Claude 网页版",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"],
        detail: "浏览器中的 Claude。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "chatgpt-web",
        name: "ChatGPT 网页版",
        short: "ChatGPT 网页版",
        kind: AgentKind::Web,
        paths: &[],
        domains: &[
            "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com",
            "cdn.openaimerge.com", "challenges.cloudflare.com", "cdn.workos.com", "forwarder.workos.com",
            "frontend-apps-multi-region.workos.com", "images.workoscdn.com", "setup.workos.com",
            "workos.imgix.net", "intercom.io", "intercomcdn.com", "js.stripe.com", "ct.sendgrid.net",
            "o207216.ingest.sentry.io", "o33249.ingest.sentry.io", "rum.browser-intake-datadoghq.com",
        ],
        detail: "浏览器中的 ChatGPT。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "gemini-web",
        name: "Gemini 网页版",
        short: "Gemini 网页版",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["gemini.google.com", "accounts.google.com", "gstatic.com", "googleusercontent.com", "generativelanguage.googleapis.com"],
        detail: "浏览器中的 Gemini。登录与必要公共资源一并走所选 AI 出口。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "perplexity-web",
        name: "Perplexity 网页版",
        short: "Perplexity",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["perplexity.ai", "pplx.ai"],
        detail: "AI 搜索和 Comet 中的 Perplexity 页面。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "grok-web",
        name: "Grok 网页版",
        short: "Grok",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["grok.com", "x.ai"],
        detail: "Grok 页面与 xAI 接口。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "mistral-web",
        name: "Mistral / Le Chat",
        short: "Mistral",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["mistral.ai"],
        detail: "Mistral 聊天和服务接口。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "copilot-web",
        name: "Microsoft Copilot",
        short: "Copilot",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["copilot.microsoft.com", "edgeservices.bing.com", "sydney.bing.com", "login.live.com", "login.microsoftonline.com"],
        detail: "Copilot 网页及 Microsoft 登录。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "aistudio-web",
        name: "Google AI Studio",
        short: "AI Studio",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["aistudio.google.com", "ai.google.dev", "accounts.google.com", "gstatic.com", "googleusercontent.com", "generativelanguage.googleapis.com"],
        detail: "Google AI Studio 与 Gemini API 入口。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "poe-web",
        name: "Poe",
        short: "Poe",
        kind: AgentKind::Web,
        paths: &[],
        domains: &["poe.com", "poecdn.net"],
        detail: "Poe 多模型聊天。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "github-copilot",
        name: "GitHub Copilot API",
        short: "GitHub Copilot",
        kind: AgentKind::Service,
        paths: &[],
        domains: &["githubcopilot.com", "copilot-proxy.githubusercontent.com", "copilot-telemetry.githubusercontent.com"],
        detail: "按 Copilot 服务域名识别，不将整个 VS Code 或 GitHub 网站放入交易出口。",
        installed: &[],
        package: None,
    },
    BuiltinAgent {
        id: "huggingface",
        name: "Hugging Face 模型平台",
        short: "Hugging Face",
        kind: AgentKind::Service,
        paths: &[],
        domains: &["huggingface.co", "hf.co", "hf.space"],
        detail: "模型下载与托管应用，适用于浏览器及模型工具。",
        installed: &[],
        package: None,
    },
];

/// 按 id 找目录项（不认识的 id 返回 None：调用方负责「静默丢弃」）。
pub fn builtin_by_id(id: &str) -> Option<&'static BuiltinAgent> {
    let key = id.trim();
    BUILTIN.iter().find(|item| item.id == key)
}

/// 目录里的位置（配置落盘按它排序：点击顺序无关 → 字节稳定）。
pub fn catalog_index(id: &str) -> Option<usize> {
    let key = id.trim();
    BUILTIN.iter().position(|item| item.id == key)
}

/// 有效名单：三类规则各自的原料（去重合并后的）。
///
/// 三组分开是因为规则形状不同：程序（路径正则）一条、浏览器+域名一条、纯域名一条。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveAgents {
    /// 程序的进程路径正则（内置程序模式 + 自定义程序转出来的模式）。
    pub path_patterns: Vec<String>,
    /// 浏览器+域名那条规则的域名部分（内置网页版 + 程序项的浏览器域名）。
    pub web_domains: Vec<String>,
    /// 纯域名那条规则（自定义网站 + 服务类目录项）。
    pub sites: Vec<String>,
}

impl EffectiveAgents {
    /// 一条规则都不会生成（名单空）。
    pub fn is_empty(&self) -> bool {
        self.path_patterns.is_empty() && self.web_domains.is_empty() && self.sites.is_empty()
    }
}

/// 大小写不敏感的去重追加（不排序、不引入 HashMap：顺序就是落盘顺序）。
fn push_unique(list: &mut Vec<String>, value: &str, fold: bool) {
    let v = value.trim();
    if v.is_empty() {
        return;
    }
    let dup = list.iter().any(|x| {
        if fold {
            x.eq_ignore_ascii_case(v)
        } else {
            x == v
        }
    });
    if !dup {
        list.push(v.to_string());
    }
}

/// 把字面文本转义成正则里的字面量（自定义程序名 → 路径正则用）。
fn escape_regex_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('\\');
            out.push(ch);
        }
    }
    out
}

/// 自定义程序（exe 名）→ 路径正则：`(?i)\\<字面>$`（正则里的 `\\` 是一个字面反斜杠）。
///
/// 与旧版的差别：那边存完整路径并转成 `(?i)^<字面>$`；我们存 exe 名，
/// 转成「以该名字结尾的路径」——匹配语义等价（不区分大小写、任意目录），输入更简单。
pub fn custom_program_pattern(value: &str) -> String {
    format!(r"(?i)\\{}$", escape_regex_literal(value.trim()))
}

/// 交易名单里有没有这一项（**仅用于界面标注**：优先级靠规则顺序，不靠减法）。
///
/// 程序：拿 `C:\<进程名>` 当合成路径跑目录项的路径正则（交易名单存的是 exe 名）。
/// 网页版/服务：域名后缀命中即算。
pub fn in_trade_list(split: &SplitConfig, entry: &BuiltinAgent) -> bool {
    match entry.kind {
        AgentKind::Program => split
            .processes
            .iter()
            .any(|e| entry_path_matches(entry, &format!(r"C:\{}", e.value()))),
        _ => entry
            .domains
            .iter()
            .any(|d| split.domains.iter().any(|e| e.value() == SplitConfig::normalize_domain(d))),
    }
}

/// 目录项的路径正则认不认这条进程路径（正则由 `regex` 求值，与 sing-box 同为 RE2 风味）。
fn entry_path_matches(entry: &BuiltinAgent, path: &str) -> bool {
    entry.paths.iter().any(|pattern| {
        regex::Regex::new(pattern)
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    })
}

/// 算出这份配置**实际会写进引擎**的三组值（走向=交易线路才有意义）。
///
/// 与上一版的差别：**不再对交易名单做减法**。旧版的优先级靠规则顺序
/// （交易名单在前、AI 工具在后，引擎取先命中），重叠项界面只做标注——
/// 路径正则与进程名之间做精确减法既不可靠也不必要。
pub fn effective(cfg: &AgentsConfig) -> EffectiveAgents {
    let mut out = EffectiveAgents::default();
    for item in BUILTIN {
        if !cfg.builtin.iter().any(|id| id == item.id) {
            continue;
        }
        match item.kind {
            AgentKind::Program => {
                for pattern in item.paths {
                    push_unique(&mut out.path_patterns, pattern, false);
                }
                for domain in item.domains {
                    push_unique(&mut out.web_domains, domain, false);
                }
            }
            AgentKind::Web => {
                for domain in item.domains {
                    push_unique(&mut out.web_domains, domain, false);
                }
            }
            AgentKind::Service => {
                for domain in item.domains {
                    push_unique(&mut out.sites, domain, false);
                }
            }
        }
    }
    for value in &cfg.programs {
        // 自定义程序模式大小写折叠去重：「a.exe」与「A.EXE」是同一个程序，不该出两条。
        push_unique(&mut out.path_patterns, &custom_program_pattern(value), true);
    }
    for value in &cfg.sites {
        push_unique(&mut out.sites, &SplitConfig::normalize_domain(value), false);
    }
    out
}

/// 运行状态（旧版的 AgentPresence 三档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Running,
    Installed,
    NotFound,
}

impl Presence {
    pub fn id(&self) -> &'static str {
        match self {
            Presence::Running => "running",
            Presence::Installed => "installed",
            Presence::NotFound => "notfound",
        }
    }

    /// 页面徽标文案（未检测到不显示，避免一列灰字）。
    pub fn label(&self) -> &'static str {
        match self {
            Presence::Running => "运行中",
            Presence::Installed => "已安装",
            Presence::NotFound => "",
        }
    }
}

/// 给定一组正在运行的进程完整路径，判断目录项的运行/安装状态（纯函数，可注入测试）。
pub fn presence_of(entry: &BuiltinAgent, running_paths: &[String]) -> Presence {
    let running = running_paths.iter().any(|p| entry_path_matches(entry, p));
    if running {
        return Presence::Running;
    }
    if entry.installed.iter().any(|p| std::path::Path::new(&expand_env(p)).exists()) {
        return Presence::Installed;
    }
    if let Some(package) = entry.package {
        if msix_package_dir_exists(package) {
            return Presence::Installed;
        }
    }
    Presence::NotFound
}

/// 当前全部进程的完整路径快照（Windows；其他平台返回空）。
pub fn running_process_paths() -> Vec<String> {
    platform::running_process_paths()
}

/// `%VAR%` 展开（只支持目录项里用到的用户级变量；展开失败保留原文）。
fn expand_env(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            if let Ok(expanded) = std::env::var(name) {
                out.push_str(&expanded);
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push('%');
        rest = &rest[start + 1..];
    }
    out.push_str(rest);
    out
}

/// MSIX 包的近似探测：`%LOCALAPPDATA%\Packages\` 下有没有 `<包名>_` 开头的目录
/// （旧版用 Get-AppxPackage；Rust 侧免 WinRT，包目录前缀对页面徽标已足够）。
fn msix_package_dir_exists(package: &str) -> bool {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let dir = std::path::Path::new(&local).join("Packages");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let prefix = format!("{package}_");
    entries
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
}

#[cfg(target_os = "windows")]
mod platform {
    use core::ffi::c_void;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn K32EnumProcesses(pids: *mut u32, size: u32, needed: *mut u32) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    /// 进程完整路径列表（枚举失败按空处理：徽标只是提示，不该挡住页面）。
    pub fn running_process_paths() -> Vec<String> {
        let mut pids = vec![0u32; 1024];
        let mut needed: u32 = 0;
        let ok = unsafe { K32EnumProcesses(pids.as_mut_ptr(), 4096, &mut needed) };
        if ok == 0 {
            return Vec::new();
        }
        pids.truncate((needed / 4) as usize);
        pids.iter()
            .filter(|&&pid| pid != 0)
            .filter_map(|&pid| unsafe {
                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if handle.is_null() {
                    return None;
                }
                let mut buffer = [0u16; 1024];
                let mut size = buffer.len() as u32;
                let got = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
                CloseHandle(handle);
                if got != 0 {
                    Some(String::from_utf16_lossy(&buffer[..size as usize]))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub fn running_process_paths() -> Vec<String> {
        Vec::new()
    }
}

/// 快照里的 `Agents` 取值 = **实际生效**的走向。字段名与取值集合不变（`Daily` / `Trade`）。
///
/// 两条事实必须同时满足（前端只有一个字段，首页与应用页都读它）：
/// - 日常上网走交易线路时，名单实际也走交易线路（全局覆盖）；
/// - 这条线路没有交易出口时，一条规则都生成不了，实际就是「跟随日常上网」。
pub fn snapshot_lane(stored: &str, daily_lane: &str, trade_exit_present: bool) -> &'static str {
    let want_trade = daily_lane.eq_ignore_ascii_case("trade") || stored.eq_ignore_ascii_case("trade");
    if want_trade && trade_exit_present {
        "Trade"
    } else {
        "Daily"
    }
}

/// 走向在「机器可用」这一侧的值（`trade` / `daily`）。IPC 回包的 `laneEffective` 用它，
/// 与 [`snapshot_lane`] 共用同一个谓词——两个投影说同一件事。
pub fn lane_effective_id(stored: &str, daily_lane: &str, trade_exit_present: bool) -> &'static str {
    if snapshot_lane(stored, daily_lane, trade_exit_present) == "Trade" {
        "trade"
    } else {
        "daily"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentsLane, SplitTarget};

    fn builtin(ids: &[&str]) -> AgentsConfig {
        AgentsConfig {
            lane: AgentsLane::Trade,
            builtin: ids.iter().map(|s| s.to_string()).collect(),
            programs: Vec::new(),
            sites: Vec::new(),
        }
    }

    #[test]
    fn catalog_is_the_0_23_1_set() {
        // 与旧版对齐：22 项 = 11 程序 + 9 网页版 + 2 服务域名。
        assert_eq!(BUILTIN.len(), 22, "目录 22 项");
        for (index, item) in BUILTIN.iter().enumerate() {
            assert!(catalog_index(item.id).is_some(), "{}", item.id);
            assert_eq!(catalog_index(item.id), Some(index));
            assert!(
                BUILTIN.iter().filter(|other| other.id == item.id).count() == 1,
                "id 必须唯一：{}",
                item.id
            );
            assert!(!item.name.is_empty() && !item.detail.is_empty(), "{}：名称与说明必填", item.id);
            match item.kind {
                AgentKind::Program => assert!(!item.paths.is_empty(), "{}：程序项必须有路径正则", item.id),
                AgentKind::Web | AgentKind::Service => {
                    assert!(!item.domains.is_empty(), "{}：域名项必须有域名", item.id);
                }
            }
        }
        assert_eq!(BUILTIN.iter().filter(|i| i.kind == AgentKind::Program).count(), 11);
        assert_eq!(BUILTIN.iter().filter(|i| i.kind == AgentKind::Web).count(), 9);
        assert_eq!(BUILTIN.iter().filter(|i| i.kind == AgentKind::Service).count(), 2);
        assert_eq!(MAX_CUSTOM, 32, "目录扩容不该动自定义上限");
    }

    #[test]
    fn every_catalog_pattern_is_a_valid_regex() {
        // 目录模式与浏览器模式都必须是 sing-box（RE2 风味）能编译的正则。
        for item in BUILTIN {
            for pattern in item.paths {
                regex::Regex::new(pattern)
                    .unwrap_or_else(|e| panic!("{} 的模式编译失败：{pattern}（{e}）", item.id));
            }
        }
        regex::Regex::new(BROWSER_PATH_REGEX).expect("浏览器模式必须可编译");
    }

    #[test]
    fn path_patterns_cover_both_claude_install_channels() {
        let claude = builtin_by_id("claude-code").unwrap();
        assert!(entry_path_matches(claude, r"C:\Users\u\AppData\Local\AnthropicClaude\app-0.10.14\claude.exe"), "老 Squirrel 渠道必须命中");
        assert!(entry_path_matches(claude, r"C:\Program Files\WindowsApps\Claude_x64_pzs8sxrjxfjjc\app\Claude.exe"), "新 MSIX 渠道必须命中");
        assert!(!entry_path_matches(claude, r"C:\Tools\unrelated.exe"), "别的程序不许命中");
        // 大小写无关（磁盘上 exe 文件名大小写不统一）。
        assert!(entry_path_matches(claude, r"C:\x\CLAUDE.EXE"));
    }

    #[test]
    fn browser_path_regex_matches_browsers_only() {
        let re = regex::Regex::new(BROWSER_PATH_REGEX).unwrap();
        for path in [
            r"C:\x\chrome.exe",
            r"C:\x\msedge.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\x\Arc.exe",
            r"C:\Users\u\AppData\Local\Comet\comet.exe",
            r"C:\x\QQBrowser.exe",
        ] {
            assert!(re.is_match(path), "浏览器必须命中：{path}");
        }
        for path in [r"C:\x\notepad.exe", r"C:\x\cursor.exe", r"C:\x\Telegram.exe"] {
            assert!(!re.is_match(path), "非浏览器不许命中：{path}");
        }
    }

    #[test]
    fn effective_builds_three_rule_groups() {
        let mut cfg = builtin(&["claude-code", "cursor", "chatgpt-web", "github-copilot"]);
        cfg.programs = vec!["my-scan.exe".to_string()];
        cfg.sites = vec!["Perplexity.ai".to_string()];
        let plan = effective(&cfg);
        // 程序：claude-code 模式 + cursor 模式 + 自定义一条。
        assert!(plan.path_patterns.iter().any(|p| p == r"(?i)\\claude\.exe$"), "{:?}", plan.path_patterns);
        assert!(plan.path_patterns.iter().any(|p| p == r"(?i)\\Cursor\\"), "{:?}", plan.path_patterns);
        assert!(plan.path_patterns.iter().any(|p| p == r"(?i)\\my-scan\.exe$"), "{:?}", plan.path_patterns);
        // 浏览器域名：chatgpt-web 的域名 + cursor 的浏览器域名。
        assert!(plan.web_domains.iter().any(|d| d == "chatgpt.com"), "{:?}", plan.web_domains);
        assert!(plan.web_domains.iter().any(|d| d == "cursor.com"), "{:?}", plan.web_domains);
        // 纯域名：服务项 + 自定义网站（归一化小写）。
        assert!(plan.sites.iter().any(|d| d == "githubcopilot.com"), "{:?}", plan.sites);
        assert!(plan.sites.iter().any(|d| d == "perplexity.ai"), "{:?}", plan.sites);
        // 服务域名不许混进浏览器组：VS Code 访问它也要走。
        assert!(!plan.web_domains.iter().any(|d| d == "githubcopilot.com"), "{:?}", plan.web_domains);
    }

    #[test]
    fn effective_dedups_and_stays_byte_stable() {
        let mut cfg = builtin(&["cursor", "cursor"]);
        cfg.programs = vec!["a.exe".to_string(), "A.exe".to_string()];
        let plan = effective(&cfg);
        assert_eq!(
            plan.path_patterns.len(),
            3,
            "cursor 两条目录模式 + 自定义一条（大小写写法合并）：{:?}",
            plan.path_patterns
        );
        let again = effective(&cfg);
        assert_eq!(plan, again, "同一份配置两次生成必须一致");
    }

    #[test]
    fn custom_program_pattern_is_a_case_insensitive_path_suffix() {
        assert_eq!(custom_program_pattern("my-scan.exe"), r"(?i)\\my-scan\.exe$");
        // 正则元字符必须转义：名字里有点也不许把语义改掉。
        let re = regex::Regex::new(&custom_program_pattern("a.b.exe")).unwrap();
        assert!(re.is_match(r"C:\Tools\a.b.exe"));
        assert!(!re.is_match(r"C:\Tools\aXb.exe"));
        let ci = regex::Regex::new(&custom_program_pattern("my-scan.exe")).unwrap();
        assert!(ci.is_match(r"C:\x\MY-SCAN.EXE"), "大小写无关");
    }

    #[test]
    fn trade_list_overlap_is_annotation_not_subtraction() {
        let mut split = SplitConfig::default();
        split.add_process("CLAUDE.EXE", SplitTarget::Direct);
        let claude = builtin_by_id("claude-code").unwrap();
        assert!(in_trade_list(&split, claude), "交易名单里 claude.exe → 标注重叠");
        assert!(!in_trade_list(&split, builtin_by_id("cursor").unwrap()));

        let mut split = SplitConfig::default();
        split.add_domain("*.ChatGPT.com", SplitTarget::Daily);
        assert!(in_trade_list(&split, builtin_by_id("chatgpt-web").unwrap()));
        assert!(!in_trade_list(&split, builtin_by_id("huggingface").unwrap()));

        // 减法取消后：重叠项照常进名单规则，优先级交给规则顺序（交易名单在前）。
        let plan = effective(&builtin(&["claude-code"]));
        assert!(!plan.path_patterns.is_empty(), "重叠不清除");
    }

    #[test]
    fn presence_uses_running_paths_and_install_hints() {
        let claude = builtin_by_id("claude-code").unwrap();
        assert_eq!(
            presence_of(claude, &[r"C:\x\claude.exe".to_string()]),
            Presence::Running
        );
        // 空路径表 + 本机是否装了 claude-code 不确定：只断言「不是 Running」的合法档位。
        let state = presence_of(claude, &[]);
        assert!(state == Presence::Installed || state == Presence::NotFound);
        assert_eq!(Presence::Running.label(), "运行中");
        assert_eq!(Presence::NotFound.label(), "", "未检测到不显示灰字");
    }

    #[test]
    fn snapshot_lane_follows_global_override_and_trade_exit() {
        assert_eq!(snapshot_lane("daily", "Trade", true), "Trade");
        assert_eq!(snapshot_lane("trade", "Direct", false), "Daily");
        assert_eq!(snapshot_lane("daily", "Trade", false), "Daily", "没有交易出口时生成不了");
        assert_eq!(lane_effective_id("trade", "direct", true), "trade");
    }
}
