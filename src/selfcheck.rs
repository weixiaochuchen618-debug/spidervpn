//! 连接后的通道自检（**经交易出口**）。
//!
//! 为什么需要它：代理写对了、引擎活着、界面显示「已连接」——这三件事同时成立时，流量**仍然可能
//! 被送进直连**（规则、节点、路由任错一处就够）。那种状态下所有「进程在跑」的检查都会通过，
//! 用户却没有任何手段发现自己在裸奔。
//!
//! 为什么经 tc-check 探测入站而不是 mixed：mixed 的流量按默认走**日常出口**，从那里拿到 204
//! 只证明「日常出口能用」，证明不了交易这条腿。探测入站的路由规则写死指向 `trade-exit`，
//! 且带**每次连接重新生成的随机凭据**——凭据只有我们这台引擎认得，握手通过本身就证明了
//! 流量进的是按本次配置启动的这台引擎；HTTP 204 再证明交易出口真的连得出去。
//! （引擎对 users 的强校验已对真 sing-box 1.14.2 实测：只给 0x00 被拒 `05ff`、
//! 错误凭据被拒 `0101`、正确凭据通过 `0100`。）

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

/// 自检目标。`generate_204` 是系统/浏览器判断「有没有被劫持」的标准端点：
/// 正常时只剩一行 204；被门户接管时会给 200/302 外加内容——正是我们想区分的情形。
const HOST: &str = "www.gstatic.com";
const PATH: &str = "/generate_204";

/// 命令行自检的上限。连接是用户显式发起的动作，多等几秒换一条真结论值得。
pub const CLI_TIMEOUT_MS: u64 = 5_000;

/// 界面自检的上限。IPC 回调跑在 UI 线程上，这段时间窗口是不响应的——不能给到 5 秒。
pub const UI_TIMEOUT_MS: u64 = 2_000;

/// 「没等到响应」这句话的标记。**超时与明确失败必须分开说**：2 秒预算下的超时在
/// 冷启动很常见（真机实测 1–3 秒），写成「未通过」会让用户以为隧道坏了，而流量
/// 常常是通的。判据只有 `Check::timed_out` 一处，三处错误文案共用这个标记。
pub const TIMEOUT_MARK: &str = "没有响应";

/// 自检结论文件，落在数据根下。
pub const FILE_NAME: &str = "last-check.json";

/// 当前连接的最后一次成功测量。与自检结论分文件：手动测速失败不能改写通道自检证据。
pub const LATENCY_FILE_NAME: &str = "last-latency.json";

/// `Check.at` 的 epoch 秒转 RFC3339。超范围或非法值返回 None，界面就不显示时间。
pub fn at_rfc3339(secs: u64) -> Option<String> {
    if secs == 0 {
        return None;
    }
    let secs = i64::try_from(secs).ok()?;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// 一次自检的结论。字段名就是 `last-check.json` 的契约（界面与命令行都读它）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct Check {
    pub ok: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
    /// 自检时刻（epoch 秒）。界面上不显示，但排查时能看出这条结论是不是上一次连接留下的。
    pub at: u64,
    /// 经 tc-check 探测入站（走交易出口）得出的结论：决定 verdict/sentence 的句式。
    /// 旧记录没有这个字段按 false 读，文案仍是老样子。
    #[serde(default)]
    pub via_trade_exit: bool,
    /// 跳过原因（端口算不出来/拿不到可用端口）。Some ⇒ 结论只能是「自检跳过：<原因>」，
    /// **绝不**与「通过」并存；调用方也不必再拨号（拨过去连到的是占端口的人）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// 一次真实成功的当前通道测量。`at` 是响应完成时刻，不是按钮点击时刻。
/// `connection_started_at` 把读数绑定到本次连接，防止旧连接记录在新会话里复活。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct Latency {
    pub latency_ms: u64,
    pub at: u64,
    #[serde(default)]
    pub connection_started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasureError {
    pub code: &'static str,
    pub message: String,
}

impl MeasureError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Check {
    /// 这次失败是「没等到响应」，而不是对面明确拒绝/给错东西。
    ///
    /// **超时不等于通道坏**：2 秒预算下冷启动经常超时（真机实测 1–3 秒），下一分钟
    /// 同一个目标 0.1 秒就回 204。判据只此一处，三处错误文案共用 `TIMEOUT_MARK`。
    fn timed_out(&self) -> bool {
        !self.ok
            && self.skipped.is_none()
            && self
                .error
                .as_deref()
                .map(|error| error.contains(TIMEOUT_MARK))
                .unwrap_or(false)
    }

    /// 只给展示层看的结论（`--status` / IPC `check` 字段 / 界面同用这一份）。
    pub fn verdict(&self) -> String {
        if let Some(r) = &self.skipped {
            return format!("自检跳过：{r}");
        }
        if self.ok {
            if self.via_trade_exit {
                format!("通过（HTTP {}，经交易出口）", self.status.unwrap_or(0))
            } else {
                format!("通过（HTTP {}）", self.status.unwrap_or(0))
            }
        } else if self.timed_out() {
            // 「没测出来」不是「验出问题」：预算内没等到响应，结论只能到这。
            if self.via_trade_exit {
                format!("没测出来（经交易出口：{}）", self.failure_text())
            } else {
                format!("没测出来（{}）", self.failure_text())
            }
        } else if self.via_trade_exit {
            format!("未通过（经交易出口：{}）", self.failure_text())
        } else {
            format!("未通过（{}）", self.failure_text())
        }
    }

    /// 完整一句话。**四种**句式是定稿契约，别改：
    /// - 通过：`通道自检（经交易出口）：通过（HTTP 204）`
    /// - 拨号失败 / 对面明确拒绝：`通道自检（经交易出口）未通过：<原因>`
    /// - 预算内没等到响应：`通道自检（经交易出口）没测出来：<原因>`
    /// - 端口不可用（跳过）：`自检跳过：拿不到可用探测端口（…）`
    ///
    /// 「没测出来」与「未通过」必须分开：前者是**没有结论**（冷启动常见），后者是
    /// **有结论且是坏的**。展示层据此决定要不要挂「通道未通」（见 `presentation::apply_channel_check`）。
    pub fn sentence(&self) -> String {
        if let Some(r) = &self.skipped {
            // 跳过说的不是"通道好没好"，是"这次没验成"：它本身就是完整结论，不加前缀。
            return format!("自检跳过：{r}");
        }
        if self.ok {
            if self.via_trade_exit {
                format!("通道自检（经交易出口）：通过（HTTP {}）", self.status.unwrap_or(0))
            } else {
                format!("通道自检：{}", self.verdict())
            }
        } else if self.timed_out() {
            if self.via_trade_exit {
                format!("通道自检（经交易出口）没测出来：{}", self.failure_text())
            } else {
                format!("通道自检没测出来：{}", self.failure_text())
            }
        } else if self.via_trade_exit {
            format!("通道自检（经交易出口）未通过：{}", self.failure_text())
        } else {
            format!("通道自检未通过：{}", self.failure_text())
        }
    }

    /// 事务摘要里的那一格：`完成：…；通道自检跳过（拿不到可用探测端口（…））`。
    ///
    /// 跳过**必须带原因**：摘要行是多数人唯一会看的一行，只写「跳过」等于让他回头去翻
    /// 上面那行结论。通过/未通过的原因本来就写在结论行里，摘要行不重复。
    pub fn step_text(&self) -> String {
        match (&self.skipped, self.ok) {
            (Some(reason), _) => format!("通道自检跳过（{reason}）"),
            (None, true) => "通道自检通过".to_string(),
            (None, false) if self.timed_out() => "通道自检没测出来".to_string(),
            (None, false) => "通道自检未通过".to_string(),
        }
    }

    /// 失败时那句「为什么」。经交易出口的探测错误已自带上下文（探测端口/凭据/目标），
    /// 不再补「连 xxx 失败」前缀，免得把"探测端口连不上"说成"目标站点连不上"。
    fn failure_text(&self) -> String {
        if self.via_trade_exit {
            return match (&self.error, self.status) {
                (Some(e), _) => e.clone(),
                (None, Some(s)) => format!("连 {HOST} 失败：经交易出口拿回 HTTP {s}"),
                (None, None) => "没有拿到响应".to_string(),
            };
        }
        if self.engine_side() {
            self.reason()
        } else {
            format!("连 {HOST} 失败：{}", self.reason())
        }
    }

    /// 结论是否由「引擎侧的问题」得出（而不是和目标站点的通信失败）。
    /// 这类文案里不能加「连 {HOST} 失败」——那会把引擎的问题说成网络的问题。
    /// `last-check.json` 的字段按契约固定，只能靠措辞判断。
    fn engine_side(&self) -> bool {
        self.error.as_deref().map(|e| e.contains("引擎")).unwrap_or(false)
    }

    fn reason(&self) -> String {
        match (&self.error, self.status) {
            (Some(e), _) => e.clone(),
            (None, Some(s)) => format!("代理返回 HTTP {s}"),
            (None, None) => "没有拿到响应".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// 探测计划：连接配置生成之前就要定下来的事
// ---------------------------------------------------------------------------

/// 连接前的探测计划。
///
/// 为什么要在连接前"计划"而不是等自检时再试：探测端口**被别人占**时，引擎对绑不上的
/// 入站是整体 FATAL（实测 sing-box 1.14.2），必须先摘掉探测入站再起引擎；而"占没占"
/// 只有绑一下才知道，这个决定必须赶在连接配置生成之前。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbePlan {
    /// 探测端口可用：凭据已生成（本次连接专用），连接配置会带上带凭据的探测入站。
    Dial { port: u16, username: String, password: String },
    /// 探测端口算不出来/拿不到任何可用端口：连接配置不带探测入站；自检直接报跳过——**不拨号**，
    /// 拨过去连到的是占端口的人，握手注定失败，会把"没法验"误报成"验了且没过"。
    Skip { port: Option<u16>, reason: String },
}

/// 端点 → 探测计划：预检探测端口（绑一下立刻放掉），通过则生成本次连接的随机凭据。
///
/// 端口顺序：`+3` 优先，绑不上才回落到系统分配的空闲端口。
/// 为什么 `+3` 优先：它是既有行为与既有验收的口径（`netstat` 里一眼能认出、报错文案要报得出端口号），
/// 换端口只是「`+3` 真用不了」时的补救——比如被别的程序占住、落在系统保留段、或上一个引擎
/// 刚断还处在 TIME_WAIT。这些都属于**环境问题**，不该把通道结论降级成「跳过」（= 没验）。
pub fn plan_probe(endpoint: &str) -> ProbePlan {
    let Some(port) = probe_port_from_endpoint(endpoint) else {
        return ProbePlan::Skip {
            port: None,
            reason: "探测端口算不出来（线路端口 +3 超出 65535）".to_string(),
        };
    };
    if bind_available(port) {
        return ProbePlan::Dial { port, username: random_token(), password: random_token() };
    }
    match dynamic_port() {
        Some(p) => ProbePlan::Dial { port: p, username: random_token(), password: random_token() },
        // 与「`+3` 被占用」是两件事：这里本机已经**没有任何**端口可用，
        // 说成「被占用」会让人去查一个不存在的占用者。保留 `port` 供排查。
        None => ProbePlan::Skip {
            port: Some(port),
            reason: format!("拿不到可用探测端口（探测端口 {port} 绑不上，系统也没能分配空闲端口）"),
        },
    }
}

/// 让系统分配一个当前空闲的端口（端口耗尽时 None）。
///
/// 绑上就立刻 drop：探测入站由引擎自己绑，我们不占着用户的端口；
/// listen socket 没接过连接，也就不会留下 TIME_WAIT。
fn dynamic_port() -> Option<u16> {
    #[cfg(test)]
    {
        // 线程局部：cargo 并行跑用例时，一个用例打开的「端口耗尽」开关
        // 不能把同进程里另一个正在算端口的用例一起带进 Skip 分支。
        if DYN_PORT_EXHAUSTED.with(|f| f.get()) {
            return None;
        }
    }
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let port = l.local_addr().ok()?.port();
    drop(l);
    Some(port)
}

// 只给用例用：把「系统分不出空闲端口」这一极端分支变成可断言的事实
// （真去耗尽本机端口会污染整台机器）。
//
// **必须是线程局部而不是全局**：`cargo test` 默认多线程并行，全局开关一打开，
// 同进程里任何走 `plan_probe` 的用例都会看到「端口耗尽」——
// 症状是毫无关系的用例偶发「必须回落到动态端口，不能跳过」。
#[cfg(test)]
thread_local! {
    static DYN_PORT_EXHAUSTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 试绑的次数与间隔。上一次的引擎刚释放端口、或系统还在回收时，会有一小段**瞬时**占用：
/// 只试一次就判「跳过」，等于把一次本可以验的通道报成没验成。
const BIND_ATTEMPTS: usize = 3;
const BIND_RETRY_GAP_MS: u64 = 200;

/// 端口现在能不能绑（成功立刻释放，不占着用户的端口）。
fn bind_available(port: u16) -> bool {
    for attempt in 0..BIND_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(BIND_RETRY_GAP_MS));
        }
        if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            drop(l);
            return true;
        }
    }
    false
}

/// 探测端口 = 线路端口 + 3（checked 加法；溢出按「跳过」处理）。
pub fn probe_port_from_endpoint(endpoint: &str) -> Option<u16> {
    port_from_endpoint(endpoint).and_then(|p| p.checked_add(3))
}

/// 随机凭据。std 没有直接的 RNG，借 `RandomState`（OS 种子）+ 纳秒时钟 + 计数器；
/// 只用于本机探测入站的握手证明，不承担密码学职责——但绝不能是常数或可预测的短序列。
fn random_token() -> String {
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    std::time::SystemTime::now().hash(&mut h);
    N.fetch_add(1, Ordering::Relaxed).hash(&mut h);
    std::process::id().hash(&mut h);
    format!("{:016x}", h.finish())
}

/// 把本次探测凭据记进 runtime.json（只动 ProbeUser/ProbePass 两个键，原子替换）。
///
/// 连接事务不认识凭据，这里在连接成功后补写：失败只影响自检（按"没有凭据"未通过），不影响连接。
/// 键名大小写敏感（ProbeUser/ProbePass），与 RuntimeRecord 的字段对应。
pub fn record_probe_creds(
    runtime_path: &Path,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let text = std::fs::read_to_string(runtime_path)
        .map_err(|e| format!("读运行时记录失败（{}）：{e}", runtime_path.display()))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("运行时记录不是合法 JSON：{e}"))?;
    let Some(o) = v.as_object_mut() else {
        return Err("运行时记录顶层必须是对象".to_string());
    };
    o.insert("ProbeUser".to_string(), serde_json::json!(username));
    o.insert("ProbePass".to_string(), serde_json::json!(password));
    let tmp = runtime_path.with_extension("json.tmp");
    std::fs::write(&tmp, v.to_string()).map_err(|e| format!("写运行时记录失败：{e}"))?;
    std::fs::rename(&tmp, runtime_path).map_err(|e| format!("替换运行时记录失败：{e}"))
}

/// 自检用的凭据：从 runtime.json 读（键名大小写敏感：ProbeUser/ProbePass）。
fn probe_creds(root: &Path) -> Option<(String, String)> {
    let rec = crate::model::load_runtime(&root.join("runtime.json")).ok()??;
    Some((rec.probe_user?, rec.probe_pass?))
}

pub(crate) fn runtime_started_at(root: &Path) -> Option<String> {
    let rec = crate::model::load_runtime(&root.join("runtime.json")).ok()??;
    (!rec.started_at.trim().is_empty()).then_some(rec.started_at)
}

/// 当前引擎实际使用的探测入站。连接前的端口规划可能已回落到动态端口，
/// 因而这里只能读运行时配置，绝不能再按线路端口 +3 猜一次。
fn active_probe_port(root: &Path) -> Result<u16, String> {
    let path = root.join("runtime-engine.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取当前引擎配置失败（{}）：{e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(
        text.strip_prefix('\u{feff}').unwrap_or(&text),
    )
    .map_err(|e| format!("当前引擎配置不是合法 JSON：{e}"))?;
    let inbounds = value
        .get("inbounds")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "当前引擎配置缺少 inbounds，无法定位实际探测入站".to_string())?;
    let probes: Vec<_> = inbounds
        .iter()
        .filter(|i| i.get("tag").and_then(serde_json::Value::as_str) == Some(crate::engine_config::PROBE_TAG))
        .collect();
    if probes.len() != 1 {
        return Err(format!(
            "当前引擎配置应有且只有一个 {} 探测入站（实际 {} 个）",
            crate::engine_config::PROBE_TAG,
            probes.len()
        ));
    }
    let probe = probes[0];
    if probe.get("type").and_then(serde_json::Value::as_str) != Some("socks")
        || probe.get("listen").and_then(serde_json::Value::as_str) != Some("127.0.0.1")
    {
        return Err("当前 tc-check 入站不是本机 SOCKS 探测入站，拒绝测量".to_string());
    }
    probe
        .get("listen_port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or_else(|| "当前 tc-check 入站的 listen_port 无效".to_string())
}

// ---------------------------------------------------------------------------
// 探测客户端：SOCKS5（用户名/密码子协商）+ 最小 HTTP GET
// ---------------------------------------------------------------------------

/// 隧道阶段失败的两种"性质"，检查层必须区别对待（验收重点）：
/// - `NotListening`：拨号被拒/超时，探测端口上没有我们的入站。走 `Dial` 之前端口已经 bind 成功过，
///   所以这不是端口冲突，而是**引擎没按配置监听**——归「未通过」：没有监听就没有通道，
///   而「跳过」这一格只留给 plan 阶段连一个端口都拿不到的情形。
/// - `Failed`：隧道建起来了但中途失败——这是"经交易出口验过了，没过"。
#[derive(Debug)]
pub(crate) enum ProbeError {
    NotListening { port: u16 },
    Failed(String),
}

/// 经认证 SOCKS5 入站发一次 HTTP/1.1 请求。
///
/// `want_body` 决定要不要读正文：自检只看状态码（正文读进来是白等），出口 IP 探测
/// 必须读正文。**握手只此一份**——两套握手迟早会在「凭据没生效」这类判定上分叉。
fn socks5_exchange(
    port: u16,
    username: &str,
    password: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
    want_body: bool,
) -> Result<(u16, String), ProbeError> {
    let fail = |m: String| ProbeError::Failed(m);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let timeout = Duration::from_millis(timeout_ms);
    let mut s = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        // 连不上自家探测口（被拒/超时/被过滤）只有一种解释：端口上没有我们的探测入站
        // （引擎没按配置监听 / 老线路配置）。实测有的环境（沙箱过滤层）对无人监听的回环端口
        // 回超时而不是拒绝，只认 ConnectionRefused 会让同一份代码在不同机器上得出两种结论，
        // 所以统一归到 NotListening，由检查层翻成「未通过：端口上没有监听」。
        Err(_) => return Err(ProbeError::NotListening { port }),
    };
    // 读超时与连接超时取同一个上限：整条自检的等待时间才是可预期的。
    s.set_read_timeout(Some(timeout)).map_err(|e| fail(format!("设置读超时失败：{e}")))?;
    s.set_write_timeout(Some(timeout)).map_err(|e| fail(format!("设置写超时失败：{e}")))?;
    // 带超时的 read_n：WouldBlock/TimedOut 统一翻译成"没有响应"（拨号超时分支的固定文案）。
    fn read_n(s: &mut TcpStream, n: usize, timeout_ms: u64) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; n];
        match s.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    Err(format!("探测请求在 {timeout_ms} 毫秒内{TIMEOUT_MARK}"))
                }
                _ => Err(format!("读取探测响应失败：{e}")),
            },
        }
    }

    // 1) 问候：同时报 0x00（无认证）与 0x02（用户名/密码）。服务器必须选 0x02——
    //    选 0x00 等于凭据没生效，那种"通过"不能当证据（对真 sing-box 已实测：选 0x02）。
    s.write_all(&[0x05, 0x02, 0x00, 0x02]).map_err(|e| fail(format!("发出探测请求失败：{e}")))?;
    let g = read_n(&mut s, 2, timeout_ms).map_err(fail)?;
    if g[0] != 0x05 {
        return Err(fail("探测入站返回的不是 SOCKS5".to_string()));
    }
    match g[1] {
        0x02 => {}
        0x00 => {
            return Err(fail(
                "探测入站没有要求认证：凭据未生效，不能拿这种探测当证据".to_string(),
            ));
        }
        0xFF => return Err(fail("探测入站拒绝了所有认证方式".to_string())),
        m => return Err(fail(format!("探测入站选择的认证方式不支持：0x{m:02X}"))),
    }

    // 2) 用户名/密码子协商（RFC 1929）。
    let (u, p) = (username.as_bytes(), password.as_bytes());
    if u.len() > 255 || p.len() > 255 {
        return Err(fail("探测凭据超长（内部错误）".to_string()));
    }
    let mut auth = Vec::with_capacity(3 + u.len() + p.len());
    auth.extend_from_slice(&[0x01, u.len() as u8]);
    auth.extend_from_slice(u);
    auth.push(p.len() as u8);
    auth.extend_from_slice(p);
    s.write_all(&auth).map_err(|e| fail(format!("发出探测请求失败：{e}")))?;
    let a = read_n(&mut s, 2, timeout_ms).map_err(fail)?;
    if a[0] != 0x01 || a[1] != 0x00 {
        return Err(fail("探测凭据被拒绝（引擎可能带着旧配置在跑）".to_string()));
    }

    // 3) CONNECT：域名形式，端口 80。
    let h = host.as_bytes();
    let mut req = Vec::with_capacity(7 + h.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, h.len() as u8]);
    req.extend_from_slice(h);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).map_err(|e| fail(format!("发出探测请求失败：{e}")))?;
    let head = read_n(&mut s, 4, timeout_ms).map_err(fail)?;
    if head[0] != 0x05 {
        return Err(fail("探测入站对 CONNECT 的响应不是 SOCKS5".to_string()));
    }
    if head[1] != 0x00 {
        return Err(fail(format!("连 {host} 失败：交易出口没有连上（SOCKS 错误码 {}）", head[1])));
    }
    // 按 ATYP 把绑定地址的剩余字节读完（内容不用，只把帧读完整）。
    match head[3] {
        0x01 => {
            read_n(&mut s, 6, timeout_ms).map_err(fail)?;
        }
        0x03 => {
            let l = read_n(&mut s, 1, timeout_ms).map_err(fail)?[0];
            read_n(&mut s, l as usize + 2, timeout_ms).map_err(fail)?;
        }
        0x04 => {
            read_n(&mut s, 18, timeout_ms).map_err(fail)?;
        }
        t => return Err(fail(format!("探测入站 CONNECT 响应的地址类型不支持：0x{t:02X}"))),
    }

    // 4) HTTP：origin-form GET，只读状态行——正文与响应头都不需要，
    //    而且对方可能给一个永远不结束的流。
    let http = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(http.as_bytes()).map_err(|e| fail(format!("发出探测请求失败：{e}")))?;
    // **一个 BufReader 读到尾**：`BufReader` 会一次读进比一行更多的字节，读完状态行就把它
    // 丢掉，后面那半个响应（响应头 + 正文）会连同缓冲区一起消失——正文永远是空的。
    let mut reader = BufReader::new(&mut s);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            fail(format!("探测请求在 {timeout_ms} 毫秒内{TIMEOUT_MARK}"))
        }
        _ => fail(format!("读取探测响应失败：{e}")),
    })?;
    if line.trim().is_empty() {
        return Err(fail(format!("连 {host} 失败：在 {timeout_ms} 毫秒内{TIMEOUT_MARK}")));
    }
    let status = parse_status(&line)
        // 状态码只管"拿到没拿到"：算不算通过由 check_and_record 判定，混在一起就没法换口径了。
        .map_err(|_| fail(format!("连 {host} 失败：出口返回的不是 HTTP 响应")))?;
    if !want_body {
        return Ok((status, String::new()));
    }
    // 正文：先吃掉响应头，再最多读 `BODY_LIMIT` 字节。出口 IP 服务的正文只有几十字节，
    // 不设上限会碰上「永远不结束的流」。头读坏了不算失败（正文可能已经拿到了）。
    let mut header = String::new();
    loop {
        header.clear();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header.trim().is_empty() => break,
            Ok(_) if header.len() > 8192 => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let mut body = String::new();
    let _ = reader.take(BODY_LIMIT).read_to_string(&mut body);
    Ok((status, body))
}

/// 出口 IP 服务的正文不会超过这个长度；超出的部分对「取一个地址」没有意义。
const BODY_LIMIT: u64 = 512;

/// 只要状态码（自检用）。
fn socks5_get(
    port: u16,
    username: &str,
    password: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> Result<u16, ProbeError> {
    socks5_exchange(port, username, password, host, path, timeout_ms, false)
        .map(|(status, _)| status)
}

/// 取回正文（出口 IP 探测用）。**同一条握手、同一条交易出口**，只是多读几十字节。
pub fn socks5_text(
    port: u16,
    username: &str,
    password: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> Result<(u16, String), ProbeError> {
    socks5_exchange(port, username, password, host, path, timeout_ms, true)
}

/// 从 `HTTP/1.1 204 No Content` 里取 204。
fn parse_status(line: &str) -> Result<u16, String> {
    let not_http = || "代理返回的不是 HTTP 响应".to_string();
    if !line.starts_with("HTTP/") {
        return Err(not_http());
    }
    line.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok()).ok_or_else(not_http)
}

// ---------------------------------------------------------------------------
// 探测一次并落盘
// ---------------------------------------------------------------------------

/// 按探测计划自检并落盘，返回结论。**永不返回错误**：自检失败不代表连接失败
/// （可能只是这个域名被用户网络屏蔽），把失败变成 Err 会诱使调用方回滚一次正常的连接。
pub fn check_and_record(root: &Path, plan: &ProbePlan, timeout_ms: u64) -> Check {
    // 这是一次新连接的证据采集：无论随后通过、失败或跳过，旧读数都不能留成当前值。
    clear_latency(root);
    let at = crate::model::now_epoch_secs_u64();
    let mut latency = None;
    let c = match plan {
        // 跳过：不拨号（理由见 ProbePlan::Skip 的注释）。
        ProbePlan::Skip { reason, .. } => Check {
            ok: false,
            status: None,
            error: None,
            at,
            via_trade_exit: true,
            skipped: Some(reason.clone()),
        },
        ProbePlan::Dial { port, .. } => match probe_creds(root) {
            None => Check {
                ok: false,
                status: None,
                error: Some("runtime.json 里没有探测凭据，无法验证交易出口".to_string()),
                at,
                via_trade_exit: true,
                skipped: None,
            },
            Some((user, pass)) => {
                let started = Instant::now();
                let result = socks5_get(*port, &user, &pass, HOST, PATH, timeout_ms);
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let completed_at = crate::model::now_epoch_secs_u64();
                match result {
                // 端口在 plan 阶段 bind 成功过（`+3` 或系统分配的端口），拨号却说没人监听——
                // 是引擎没按配置起监听，不是端口冲突。归「未通过」：说成「被占用」会让用户
                // 去查一个根本不存在的占用者，排错方向直接带偏。
                // （「跳过」这一格只留给 plan 阶段连端口都拿不到的那个分支。）
                Err(ProbeError::NotListening { port }) => Check {
                    ok: false,
                    status: None,
                    error: Some(format!("探测端口 {port} 上没有监听（引擎未按配置监听自检入站）")),
                    at,
                    via_trade_exit: true,
                    skipped: None,
                },
                Err(ProbeError::Failed(msg)) => Check {
                    ok: false,
                    status: None,
                    error: Some(msg),
                    at,
                    via_trade_exit: true,
                    skipped: None,
                },
                // 只认 2xx：3xx 可能是被门户/中间人改写，4xx/5xx 多半是代理自己失败了。
                // 宁可报「未通过」让人再看一眼，也不要给一句假的「通过」。
                //
                // 拿到 2xx 之后**再确认一次引擎还活着**：起来几十毫秒就崩的引擎会让
                // 这句「通过」在下一次操作之前就变成假话。
                Ok(s) if (200..=299).contains(&s) => {
                    if engine_alive(root) {
                        latency = runtime_started_at(root).map(|connection_started_at| Latency {
                            latency_ms: elapsed_ms,
                            at: completed_at,
                            connection_started_at,
                        });
                        Check {
                            ok: true,
                            status: Some(s),
                            error: None,
                            at,
                            via_trade_exit: true,
                            skipped: None,
                        }
                    } else {
                        // 状态码是当时的真实观察，照实留下；但结论作废。
                        Check {
                            ok: false,
                            status: Some(s),
                            error: Some("自检期间引擎退出".to_string()),
                            at,
                            via_trade_exit: true,
                            skipped: None,
                        }
                    }
                }
                Ok(s) => Check {
                    ok: false,
                    status: Some(s),
                    error: None,
                    at,
                    via_trade_exit: true,
                    skipped: None,
                },
                }
            }
        },
    };
    if let Some(measured) = latency {
        if let Err(e) = save_latency(root, &measured) {
            eprintln!("延迟测量结果未能写入：{e}");
        }
    }
    // 落盘失败只影响「下次还能不能看到这条结论」，不影响本次连接结果。
    if let Err(e) = save(root, &c) {
        eprintln!("自检结果未能写入：{e}");
    }
    c
}

/// 用户显式点击“测一次”：复用同一认证 SOCKS + HTTP 请求，只更新独立测量记录。
/// 不调用 `check_and_record`，所以无论成功失败都不会重写 `last-check.json`。
pub fn measure_latency_and_record(root: &Path, timeout_ms: u64) -> Result<Latency, MeasureError> {
    let (line_id, profile) = measurement_owner(root);
    let connection_started_at = runtime_started_at(root).ok_or_else(|| {
        MeasureError::new("environment", "当前连接缺少启动标识，请重新连接后测量")
    })?;
    let port = active_probe_port(root).map_err(|e| MeasureError::new("config", e))?;
    let (user, pass) = probe_creds(root).ok_or_else(|| {
        MeasureError::new("environment", "当前连接没有探测凭据，请重新连接后测量")
    })?;
    let started = Instant::now();
    let result = socks5_get(port, &user, &pass, HOST, PATH, timeout_ms);
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let at = crate::model::now_epoch_secs_u64();
    let status = match result {
        Ok(status) => status,
        Err(ProbeError::NotListening { port }) => {
            // 引擎没在监听 = 本机故障，不是线路变差：记 ControllerUnavailable，
            // 首页据此把它从「未响应」的分子分母里剔除（旧版同一条口径）。
            note_failure(root, &line_id, &profile, "ControllerUnavailable");
            return Err(MeasureError::new(
                "network",
                format!("探测端口 {port} 上没有监听，请检查通道后重试"),
            ))
        }
        Err(ProbeError::Failed(message)) => {
            let reason = if message.contains("没有响应") {
                "MeasurementTimeout"
            } else {
                "MeasurementFailed"
            };
            note_failure(root, &line_id, &profile, reason);
            return Err(MeasureError::new("network", message));
        }
    };
    if !(200..=299).contains(&status) {
        note_failure(root, &line_id, &profile, "MeasurementFailed");
        return Err(MeasureError::new(
            "network",
            format!("经交易出口拿回 HTTP {status}，本次测量未成功"),
        ));
    }
    if !engine_alive(root) {
        note_failure(root, &line_id, &profile, "ControllerUnavailable");
        return Err(MeasureError::new("network", "测量期间引擎退出，本次读数无效"));
    }
    let measured = Latency { latency_ms, at, connection_started_at };
    save_latency(root, &measured).map_err(|e| MeasureError::new("config", e))?;
    // 每个「真实测得的延迟」都进采样库：曲线只要能画的点，就不要拿别的数字顶替。
    // 线路与方式从配置里读，读不到就记空——宁可少一次归属，也不要记错到别的线路上。
    crate::perf::record(
        root,
        &line_id,
        &profile,
        latency_ms,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(at),
    );
    Ok(measured)
}

/// 这次测量记在谁名下：当前线路 + 它的连接方式（`标准`/`兼容`）。
/// 读不到配置就返回空串——宁可少一次归属，也不要记错到别的线路上。
fn measurement_owner(root: &Path) -> (String, String) {
    crate::config::load(&root.join(crate::config::DEFAULT_PATH))
        .ok()
        .flatten()
        .and_then(|cfg| {
            cfg.current_line().map(|line| {
                let profile = match line.effective_transport() {
                    crate::config::Transport::Udp => "标准",
                    crate::config::Transport::Tcp => "兼容",
                };
                (line.id.clone(), profile.to_string())
            })
        })
        .unwrap_or_default()
}

/// 失败也要留痕：没有这一行，首页的「未响应比例」永远是 0/M（0%）。
fn note_failure(root: &Path, line_id: &str, profile: &str, reason: &str) {
    crate::perf::record_failure(
        root,
        line_id,
        profile,
        reason,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(crate::model::now_epoch_secs_u64()),
    );
}

/// 引擎还在不在。没有运行时记录、记录坏掉、没写 pid，都按「不在」处理：
/// 自检宁可少做一次，也不能拿别人的端口当自家的。
fn engine_alive(root: &Path) -> bool {
    let rec = match crate::model::load_runtime(&root.join("runtime.json")) {
        Ok(Some(r)) => r,
        _ => return false,
    };
    match rec.engine_pid {
        // 与 connect::Deps 同源：存活判定统一走自由函数，不直接摸 SystemProbe 的 trait 方法
        Some(pid) => crate::probe::pid_alive(pid),
        None => false,
    }
}

/// 写结论。与配置文件同样先写临时文件再替换：断在半路会留下半截 JSON。
pub fn save(root: &Path, c: &Check) -> Result<(), String> {
    let path = root.join(FILE_NAME);
    let text = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}：{e}", path.display()))
}

pub fn save_latency(root: &Path, measured: &Latency) -> Result<(), String> {
    let path = root.join(LATENCY_FILE_NAME);
    let text = serde_json::to_string_pretty(measured).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}：{e}", path.display()))
}

pub fn load_latency(root: &Path) -> Option<Latency> {
    let text = std::fs::read_to_string(root.join(LATENCY_FILE_NAME)).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// 只接受绑定到当前 `runtime.json` 启动标识的读数；旧连接、缺字段或坏文件都降级为未测量。
pub fn load_current_latency(root: &Path) -> Option<Latency> {
    let measured = load_latency(root)?;
    let started_at = runtime_started_at(root)?;
    (measured.connection_started_at == started_at).then_some(measured)
}

pub fn clear_latency(root: &Path) {
    let _ = std::fs::remove_file(root.join(LATENCY_FILE_NAME));
}

/// 读上次连接留下的结论。文件不存在或坏掉都当「未检测」：展示用的证据缺失，
/// 不该变成一条错误，更不该让 `--status` 打不开。
pub fn load(root: &Path) -> Option<Check> {
    let text = std::fs::read_to_string(root.join(FILE_NAME)).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// 清掉失败连接留下的结论与测量。断开后保留上次自检是独立行为，不在这里处理。
pub fn clear(root: &Path) {
    let _ = std::fs::remove_file(root.join(FILE_NAME));
    clear_latency(root);
}

/// 从 `host:port` 端点里取端口。IPv6 端点也带冒号，所以从最后一个冒号切。
pub fn port_from_endpoint(endpoint: &str) -> Option<u16> {
    let (_, p) = endpoint.trim().rsplit_once(':')?;
    p.parse::<u16>().ok().filter(|p| *p > 0)
}

/// 自检真的「未通过」、这次走的是标准连接、而线路文件里**确实有**可用的兼容连接参数时，
/// 给一句可操作的提示（BUG-501：那台机器的 WireGuard UDP 腿被拦，中转才是能走的路）。
///
/// 放在本模块、由两条入口（CLI 连接输出、界面 status 的 `checkHint` 字段）**共用**：
/// 自救的话只在一处算，命令行和界面就不可能出现两种说法。
///
/// 三条纪律：只在真有参数时提（没有参数的线路提这句就是空话）；不改结论行与退出码；
/// **绝不自动切换**——静默换连接方式等于替用户做了他没做的决定，比报错更糟。
pub fn transport_alternative_hint(
    cfg: Option<&crate::config::AppConfig>,
    root: &Path,
    check: &Check,
) -> Option<String> {
    if check.ok || check.skipped.is_some() {
        return None; // 通过不用说；「跳过」说的不是通道好坏，不该引导换方式
    }
    let line = cfg?.current_line()?;
    if line.effective_transport() != crate::config::Transport::Udp {
        return None; // 已在走（或已选）兼容连接：再提示就是噪音
    }
    // 与切换/连接同一个判定：这里说"可用"，切过去就必须真的可用。
    crate::engine_config::check_transport(&line.engine_config_path(root), crate::config::Transport::Tcp)
        .ok()?;
    Some(
        "该线路的兼容连接参数可用：标准连接（UDP）可能被当前网络拦截，可试 --set-transport tcp 后重新连接（只影响下次连接）"
            .to_string(),
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// 一条「文件里有兼容连接参数」的线路（L1 选中），落在临时数据根里。
    fn line_with_params(tag: &str, transport: Option<crate::config::Transport>) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("tcrs-hint-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lines")).unwrap();
        let cfg = crate::config::parse(&format!(
            r#"{{"schema":2,"selected":"L1","lines":[{{"id":"L1","name":"n","proxy_endpoint":"127.0.0.1:17901"}}]}}"#
        ))
        .unwrap();
        let mut cfg = cfg;
        cfg.lines[0].transport = transport;
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        std::fs::write(
            root.join("lines").join("L1.json"),
            r#"{"endpoints":[{"type":"wireguard","tag":"hk"}],
                "outbounds":[
                    {"type":"vless","tag":"provider-a","server":"203.0.113.7","server_port":443,
                     "uuid":"11111111-2222-3333-4444-555555555555",
                     "tls":{"enabled":true,"server_name":"cdn.example.com",
                            "reality":{"enabled":true,"public_key":"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1","short_id":"ab12"}}},
                    {"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"},
                    {"type":"direct","tag":"direct"}]}"#,
        )
        .unwrap();
        root
    }

    #[test]
    fn transport_hint_appears_only_when_udp_failed_and_parameters_exist() {
        let failed = Check { ok: false, ..Default::default() };
        let cfg_of = |root: &std::path::PathBuf| {
            crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten()
        };

        // 未通过 + 标准连接 + 参数在 → 有提示，且那句自救话要点到命令上
        let root = line_with_params("yes", None);
        let hint = transport_alternative_hint(cfg_of(&root).as_ref(), &root, &failed).expect("该有提示");
        assert!(hint.contains("--set-transport tcp"), "要说清怎么自救：{hint}");
        let _ = std::fs::remove_dir_all(&root);

        // 通过 / 跳过都不提示：跳过说的不是通道好坏，引导换方式是噪音
        let root = line_with_params("ok", None);
        assert!(transport_alternative_hint(cfg_of(&root).as_ref(), &root, &Check { ok: true, ..Default::default() }).is_none());
        let skipped = Check { ok: false, skipped: Some("拿不到可用探测端口".into()), ..Default::default() };
        assert!(transport_alternative_hint(cfg_of(&root).as_ref(), &root, &skipped).is_none());
        let _ = std::fs::remove_dir_all(&root);

        // 已选兼容连接 → 不提示（再提就是让他切到已经在用的东西上）
        let root = line_with_params("tcp", Some(crate::config::Transport::Tcp));
        assert!(transport_alternative_hint(cfg_of(&root).as_ref(), &root, &failed).is_none());
        let _ = std::fs::remove_dir_all(&root);

        // 线路文件里没有参数 → 不提示（提示了就是一句做不到的空话）
        let root = line_with_params("no", None);
        std::fs::write(
            root.join("lines").join("L1.json"),
            r#"{"endpoints":[{"type":"wireguard","tag":"hk"}],"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        )
        .unwrap();
        assert!(transport_alternative_hint(cfg_of(&root).as_ref(), &root, &failed).is_none());
        let _ = std::fs::remove_dir_all(&root);

        // 没有配置（Option::None）→ 不提示
        assert!(transport_alternative_hint(None, std::path::Path::new("x"), &failed).is_none());
    }

    /// 一个没人监听的端口：绑一个再立刻放掉。比硬编码 65535 之类可靠得多。
    fn closed_port() -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    }

    /// 造一份运行时记录。自检的前置条件是「记录的引擎 pid 还活着」。
    fn runtime_with_engine(root: &Path, engine_pid: i64) {
        std::fs::create_dir_all(root).unwrap();
        let body = format!(
            r#"{{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":{engine_pid},"StartedAt":"2026-01-01T00:00:00Z","State":"Running","Error":null,"CleanupError":false,"TradingDirectAccessBlocked":false,"BootStartedAt":"2026-01-01T00:00:00Z"}}"#
        );
        std::fs::write(root.join("runtime.json"), body).unwrap();
    }

    /// 「引擎活着」：拿测试进程自己的 pid 当引擎——它当然活着。
    fn live_engine(root: &Path) {
        runtime_with_engine(root, std::process::id() as i64);
    }

    fn with_creds(root: &Path, user: &str, pass: &str) {
        record_probe_creds(&root.join("runtime.json"), user, pass).unwrap();
    }

    fn runtime_probe(root: &Path, port: u16) {
        std::fs::write(
            root.join("runtime-engine.json"),
            format!(
                r#"{{"inbounds":[{{"type":"socks","tag":"tc-check","listen":"127.0.0.1","listen_port":{port}}}]}}"#
            ),
        )
        .unwrap();
    }

    /// 最小的假探测入站：按脚本走完 SOCKS5 认证 / CONNECT / HTTP。
    /// `mode`：`pass`(204) | `pass502` | `noauth` | `connectfail` | `silent`
    /// `expect` 是它认可的凭据——与调用方送来的不一致就按「凭据被拒」处理。
    fn fake_socks5(mode: &'static str, expect_user: &'static str, expect_pass: &'static str) -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).expect("绑定随机端口");
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut s, _)) = l.accept() else { return };
            if mode == "silent" {
                // 收下连接但一个字都不回：这正是「端口在，但没人在干活」的样子。
                std::thread::sleep(Duration::from_millis(1_500));
                return;
            }
            let mut g = [0u8; 4];
            if s.read(&mut g).is_err() { return; }
            if mode == "noauth" {
                // 配置错了才会出现的服务器：选 0x00（不要求认证）
                let _ = s.write_all(&[0x05, 0x00]);
                return;
            }
            let _ = s.write_all(&[0x05, 0x02]);
            // RFC 1929 子协商
            let mut h = [0u8; 2];
            if s.read_exact(&mut h).is_err() { return; }
            let mut u = vec![0u8; h[1] as usize];
            if s.read_exact(&mut u).is_err() { return; }
            let mut pl = [0u8; 1];
            if s.read_exact(&mut pl).is_err() { return; }
            let mut p = vec![0u8; pl[0] as usize];
            if s.read_exact(&mut p).is_err() { return; }
            let authed = u == expect_user.as_bytes() && p == expect_pass.as_bytes();
            let _ = s.write_all(&[0x01, u8::from(!authed)]);
            if !authed { return; }
            // CONNECT 请求：读掉整个帧（内容不解析）
            let mut head = [0u8; 5];
            if s.read_exact(&mut head).is_err() { return; }
            let mut rest = vec![0u8; head[4] as usize + 2];
            let _ = s.read_exact(&mut rest);
            if mode == "connectfail" {
                // REP=0x05：出口拒绝了目标连接（坏成员的样子）
                let _ = s.write_all(&[0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
                return;
            }
            let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
            let mut req = vec![0u8; 256];
            let _ = s.read(&mut req); // HTTP 请求（读多少算多少）
            let status_line = if mode == "pass502" {
                "HTTP/1.1 502 Bad Gateway"
            } else {
                "HTTP/1.1 204 No Content"
            };
            if mode == "slowpass" {
                std::thread::sleep(Duration::from_millis(120));
            }
            let _ = s.write_all(format!("{status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes());
        });
        port
    }

    fn dial_plan(port: u16, user: &str, pass: &str) -> ProbePlan {
        ProbePlan::Dial { port, username: user.to_string(), password: pass.to_string() }
    }

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-selfcheck-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::create_dir_all(&p);
        p
    }

    // ---------- 计划：端口 +3、被占、凭据随机 ----------

    #[test]
    fn probe_port_is_endpoint_port_plus_three() {
        assert_eq!(probe_port_from_endpoint("127.0.0.1:17890"), Some(17_893));
        assert_eq!(probe_port_from_endpoint("127.0.0.1:65532"), Some(65_535), "65532 是最后能放探测入站的端口");
        assert_eq!(probe_port_from_endpoint("127.0.0.1:65533"), None, "+3 溢出 → 按跳过处理");
        assert_eq!(probe_port_from_endpoint("127.0.0.1:65535"), None);
        assert_eq!(probe_port_from_endpoint("127.0.0.1"), None);
    }

    #[test]
    fn plan_probe_dials_plus_three_when_free() {
        // 回归：`+3` 能绑就必须还是 `+3`——既有验收与排错口径都建立在这个端口上，
        // 「能绑也换端口」等于无端改行为。
        let free = closed_port();
        let endpoint = format!("127.0.0.1:{}", free.saturating_sub(3));
        match plan_probe(&endpoint) {
            ProbePlan::Dial { port, .. } => assert_eq!(port, free),
            other => panic!("端口空闲时必须 Dial：{other:?}"),
        }

        // 溢出：+3 超出 65535 → Skip 且没有端口（这一格跟「被占用」无关）
        match plan_probe("127.0.0.1:65533") {
            ProbePlan::Skip { port: None, reason } => {
                assert!(reason.contains("超出 65535"), "{reason}");
            }
            other => panic!("溢出必须 Skip：{other:?}"),
        }
    }

    #[test]
    fn plan_probe_falls_back_to_a_dynamic_port_when_plus_three_is_taken() {
        // `+3` 被别人占住 ≠ 没法自检：换一个系统给的端口照样能验。
        // 这里的占用者一直在（不放），所以走的必然是回落分支。
        let taken = closed_port();
        let endpoint = format!("127.0.0.1:{}", taken.saturating_sub(3));
        let squatter = TcpListener::bind(("127.0.0.1", taken)).unwrap();
        let plan = plan_probe(&endpoint);
        drop(squatter);
        let ProbePlan::Dial { port, .. } = plan else {
            panic!("`+3` 被占时必须回落到动态端口，不能跳过：{plan:?}");
        };
        assert_ne!(port, taken, "回落之后的端口不能还是被占的那个");
        // 那个端口当时必须真能绑（否则回落只是把「跳过」换了层皮）
        let l = TcpListener::bind(("127.0.0.1", port)).expect("回落端口必须可绑");
        drop(l);
    }

    #[test]
    fn probe_port_retries_a_transient_occupation() {
        // 「上次引擎刚释放」这类瞬时占用不该直接判跳过：绑定失败要重试，能绑上就照常拨号。
        let free = closed_port();
        let endpoint = format!("127.0.0.1:{}", free.saturating_sub(3));
        let squatter = TcpListener::bind(("127.0.0.1", free)).unwrap();
        // 第一次试绑注定失败；在重试窗口内把端口放掉。
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(squatter);
        });
        match plan_probe(&endpoint) {
            ProbePlan::Dial { port, .. } => assert_eq!(port, free, "占用消失后必须回到拨号"),
            other => panic!("瞬时占用消失后必须 Dial，不能判跳过：{other:?}"),
        }
    }

    #[test]
    fn skip_means_no_port_at_all_and_says_so() {
        // 「跳过」只剩一个合法来源：`+3` 绑不上**且**系统也分不出空闲端口。
        // 文案必须说这一件事——说成「探测端口被占用」会让人去查一个不存在的占用者。
        let root = tmp_root("skip-reason");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = held.local_addr().unwrap().port();
        let endpoint = format!("127.0.0.1:{}", taken.checked_sub(3).expect("探测端口 = 端点 + 3"));
        DYN_PORT_EXHAUSTED.with(|f| f.set(true));
        let plan = plan_probe(&endpoint);
        DYN_PORT_EXHAUSTED.with(|f| f.set(false));
        let ProbePlan::Skip { port, reason } = &plan else {
            panic!("一个端口都拿不到时必须 Skip：{plan:?}");
        };
        assert_eq!(*port, Some(taken), "跳过时仍要说清是哪个端口绑不上");
        assert!(reason.starts_with("拿不到可用探测端口"), "{reason}");
        assert!(!reason.contains("被占用"), "这不是「被占用」，别把人引到占用者身上：{reason}");

        let c = check_and_record(&root, &plan, 2_000);
        let s = c.sentence();
        assert!(s.starts_with("自检跳过："), "{s}");
        assert!(s.contains(&taken.to_string()), "跳过必须点名端口：{s}");
        assert!(!s.contains("通过"), "跳过不许同时说通过：{s}");
        drop(held);

        // 拨号超时 = 未通过，同样不许混进「跳过」
        let silent = fake_socks5("silent", "u", "p");
        let c = check_and_record(&root, &dial_plan(silent, "u", "p"), 300);
        assert!(!c.sentence().contains("跳过"), "超时不是跳过：{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dial_but_not_listening_is_a_failure_not_a_skip() {
        // plan 走 Dial（端口绑得上）+ 引擎活着但没在探测口上监听 → 拨号被拒。
        // 这是「引擎没按配置监听」，不是端口冲突：必须报**未通过**，
        // 且不许说「跳过」「被占用」——否则用户拿着一个不存在的占用者去排错。
        let root = tmp_root("not-listening");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let free = closed_port();
        let c = check_and_record(&root, &dial_plan(free, "u", "p"), 2_000);
        assert!(!c.ok, "{c:?}");
        let s = c.sentence();
        assert!(s.starts_with("通道自检（经交易出口）未通过："), "{s}");
        assert!(s.contains(&format!("探测端口 {free} 上没有监听")), "{s}");
        assert!(!s.contains("跳过"), "没人监听不是跳过：{s}");
        assert!(!s.contains("被占用"), "端口绑得上，不是被占用：{s}");
        assert_eq!(c.skipped, None, "未通过不许带跳过原因");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_credentials_are_random_per_connection() {
        let free = closed_port();
        let endpoint = format!("127.0.0.1:{}", free.saturating_sub(3));
        let ProbePlan::Dial { username: u1, password: p1, .. } = plan_probe(&endpoint) else {
            panic!("端口空闲");
        };
        let ProbePlan::Dial { username: u2, password: p2, .. } = plan_probe(&endpoint) else {
            panic!("端口仍应空闲");
        };
        assert_ne!(u1, u2, "两次连接的用户名必须不同");
        assert_ne!(p1, p2, "两次连接的密码必须不同");
        assert!(u1.len() >= 8 && p1.len() >= 8, "凭据不能短到可猜：{u1}/{p1}");
    }

    #[test]
    fn probe_creds_roundtrip_through_runtime_json() {
        let root = tmp_root("creds");
        live_engine(&root);
        with_creds(&root, "user-ABC", "pass-XYZ");
        assert_eq!(
            probe_creds(&root),
            Some(("user-ABC".to_string(), "pass-XYZ".to_string()))
        );
        // 键名大小写敏感：写进文件的必须是 ProbeUser/ProbePass（与 RuntimeRecord 的字段一致）
        let raw = std::fs::read_to_string(root.join("runtime.json")).unwrap();
        assert!(raw.contains("\"ProbeUser\"") && raw.contains("\"ProbePass\""), "{raw}");
        assert!(!raw.contains("probeuser"), "键名不能被小写化：{raw}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 文案三态：通过 / 跳过 / 未通过 ----------

    #[test]
    fn pass_sentence_names_the_trade_exit() {
        let root = tmp_root("pass");
        live_engine(&root);
        with_creds(&root, "probe-u", "probe-p");
        let port = fake_socks5("pass", "probe-u", "probe-p");
        let c = check_and_record(&root, &dial_plan(port, "probe-u", "probe-p"), 2_000);
        assert!(c.ok, "{c:?}");
        assert_eq!(c.status, Some(204));
        assert_eq!(c.sentence(), "通道自检（经交易出口）：通过（HTTP 204）");
        // verdict 是 --status 与界面 `check` 字段的那句：也要带上「经交易出口」
        assert_eq!(c.verdict(), "通过（HTTP 204，经交易出口）");
        assert_eq!(load(&root), Some(c), "结论必须落盘");
        let first = load_current_latency(&root).expect("连接后自检成功必须留下首个真实读数");
        assert!(first.at > 0 && first.connection_started_at == "2026-01-01T00:00:00Z");
        assert!(!root.join("last-check.json.tmp").exists(), "临时文件不能留在数据根里");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 超时是「没测出来」，明确失败才是「未通过」——两种结论不能共用一句话。
    #[test]
    fn a_timeout_says_not_measured_instead_of_failed() {
        let timeout = Check {
            ok: false,
            status: None,
            error: Some(format!("探测请求在 2000 毫秒内{TIMEOUT_MARK}")),
            at: 0,
            via_trade_exit: true,
            skipped: None,
        };
        assert_eq!(
            timeout.sentence(),
            "通道自检（经交易出口）没测出来：探测请求在 2000 毫秒内没有响应"
        );
        assert!(!timeout.sentence().contains("未通过"), "超时不许说「未通过」：{}", timeout.sentence());
        assert!(timeout.verdict().starts_with("没测出来（经交易出口："), "{}", timeout.verdict());
        assert_eq!(timeout.step_text(), "通道自检没测出来");

        // 对面明确拒绝（不是超时）：句式保持原样，别把「有结论的坏」说成「没结论」。
        let refused = Check {
            ok: false,
            status: None,
            error: Some("连 www.gstatic.com 失败：连接被拒绝".to_string()),
            at: 0,
            via_trade_exit: true,
            skipped: None,
        };
        assert!(
            refused.sentence().starts_with("通道自检（经交易出口）未通过："),
            "{}",
            refused.sentence()
        );
        assert_eq!(refused.step_text(), "通道自检未通过");
    }

    #[test]
    fn skip_plan_records_skip_without_the_word_passed() {
        let root = tmp_root("skip");
        live_engine(&root);
        let plan = ProbePlan::Skip {
            port: Some(17_993),
            reason: "探测端口 17993 被占用".to_string(),
        };
        let c = check_and_record(&root, &plan, 2_000);
        assert!(!c.ok, "跳过绝不能是 ok");
        assert_eq!(c.sentence(), "自检跳过：探测端口 17993 被占用");
        assert!(!c.sentence().contains("通过"), "跳过时绝不出现「通过」：{}", c.sentence());
        assert!(!c.verdict().contains("通过"));
        assert_eq!(
            load(&root).map(|x| x.skipped),
            Some(Some("探测端口 17993 被占用".to_string()))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn summary_step_carries_the_skip_reason() {
        // 摘要行也必须说清为什么跳过：用户多半只看「完成：…」这一行。
        let skipped = Check {
            skipped: Some("探测端口 17893 被占用".to_string()),
            ..Default::default()
        };
        assert_eq!(skipped.step_text(), "通道自检跳过（探测端口 17893 被占用）");
        // 结论行一字不动：跳过只说一句完整结论，不加前缀、不进摘要。
        assert_eq!(skipped.sentence(), "自检跳过：探测端口 17893 被占用");

        let passed = Check { ok: true, status: Some(204), ..Default::default() };
        assert_eq!(passed.step_text(), "通道自检通过");
        let failed = Check { error: Some("连不上".to_string()), ..Default::default() };
        assert_eq!(failed.step_text(), "通道自检未通过");
    }

    #[test]
    fn wrong_credentials_are_a_failure_not_a_skip() {
        // 与「拨号没人监听」那条刻意成对：隧道阶段失败（凭据被拒）必须报「未通过」——
        // 把"验了且没过"吞成"跳过"是最严重的错。
        let root = tmp_root("wrongcreds");
        live_engine(&root);
        with_creds(&root, "right-user", "right-pass");
        let port = fake_socks5("pass", "other-user", "other-pass");
        let c = check_and_record(&root, &dial_plan(port, "right-user", "right-pass"), 2_000);
        assert!(!c.ok, "{c:?}");
        let s = c.sentence();
        assert!(s.starts_with("通道自检（经交易出口）未通过："), "{s}");
        assert!(s.contains("凭据被拒"), "{s}");
        assert!(!s.contains("自检跳过"), "与端口被占必须是两个分支：{s}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn connect_refused_by_the_exit_is_a_failure_with_the_target_named() {
        let root = tmp_root("connfail");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("connectfail", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "{c:?}");
        let s = c.sentence();
        assert!(s.starts_with("通道自检（经交易出口）未通过："), "{s}");
        assert!(s.contains("连 www.gstatic.com 失败"), "要说清是连目标失败：{s}");
        assert!(s.contains("交易出口没有连上"), "{s}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn silent_tunnel_times_out_as_not_measured_but_still_not_a_pass() {
        // 三个分支必须分得开：通过 / 没测出来（有结论）/ 跳过（没验成）。
        // 拨号超时属于「没测出来」：不是 `ok`，也不许写成「未通过」（那是验出问题）,
        // 更不许混成「自检跳过」。展示层据此不挂「通道未通」。
        let root = tmp_root("silent");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("silent", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 300);
        assert!(!c.ok, "{c:?}");
        let s = c.sentence();
        assert!(s.starts_with("通道自检（经交易出口）没测出来："), "{s}");
        assert!(s.contains("没有响应"), "{s}");
        assert!(!s.contains("未通过"), "超时是「没结论」，不是「验出问题」：{s}");
        assert!(!s.contains("自检跳过"), "{s}");
        assert!(c.verdict().starts_with("没测出来"), "{}", c.verdict());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn anonymous_probe_inbound_voids_the_evidence() {
        // 服务器不要求认证 = 凭据没生效：这种"通过"不能当证据，必须算失败。
        let root = tmp_root("noauth");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("noauth", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "{c:?}");
        assert!(c.sentence().contains("没有要求认证"), "{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_error_status_is_not_passed() {
        let root = tmp_root("502");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("pass502", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "5xx 是出口自己失败了，不能算通过");
        assert_eq!(c.status, Some(502));
        assert_eq!(
            c.sentence(),
            "通道自检（经交易出口）未通过：连 www.gstatic.com 失败：经交易出口拿回 HTTP 502"
        );
        assert_eq!(load_current_latency(&root), None, "新连接自检失败不得留下伪造测量值");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dead_engine_is_not_passed_even_with_a_lively_port() {
        let root = tmp_root("dead-engine");
        // 端口上放一个会回 204 的假探测入站：真去探就能拿回一条「通过」。
        // 引擎已不在时它的 204 必须是假证据——兜住这一点的**只有探测之后的复核**（下面那格
        // 证明的可达时序），探测之前没有第二道拦截：自检紧接连接成功，那一刻引擎不可能已经死了。
        let port = fake_socks5("pass", "u", "p");
        runtime_with_engine(&root, 0x7FFF_FFFE);
        with_creds(&root, "u", "p");

        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "引擎不在就不能给出「通过」，哪怕端口上有人回 204：{c:?}");
        assert!(c.sentence().starts_with("通道自检（经交易出口）未通过："), "{}", c.sentence());
        assert!(!c.sentence().contains("跳过"), "这不是跳过：{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_runtime_record_is_a_failure_not_a_pass() {
        // 没有运行时记录 = 没有凭据可取（连接失败/被清理后就是这个状态）：不许无凭据探测。
        let root = tmp_root("no-runtime");
        let port = fake_socks5("pass", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok);
        assert!(c.sentence().contains("没有探测凭据"), "{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_creds_is_a_failure_not_a_pass() {
        // 引擎活着、但 runtime.json 没有凭据（老版本写的记录）：宁可「未通过」也不许无凭据探测。
        let root = tmp_root("no-creds");
        live_engine(&root);
        let port = fake_socks5("pass", "u", "p");
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "{c:?}");
        assert!(c.sentence().contains("没有探测凭据"), "{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn engine_dying_during_the_probe_voids_the_pass() {
        let root = tmp_root("died-during");
        live_engine(&root);
        with_creds(&root, "u", "p");
        // 假探测入站在回 204 **之前**把运行时记录改成「引擎已死」：模拟引擎在自检期间崩掉。
        // 顺序刻意如此，否则「引擎死没死」变成看运气。
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let flip_root = root.clone();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 64];
                let _ = s.read(&mut b); // greeting
                let _ = s.write_all(&[0x05, 0x02]);
                let mut rest = [0u8; 64];
                let _ = s.read(&mut rest); // 认证帧
                let _ = s.write_all(&[0x01, 0x00]);
                let mut more = [0u8; 64];
                let _ = s.read(&mut more); // CONNECT 帧
                runtime_with_engine(&flip_root, 0x7FFF_FFFE);
                let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
                // 必须把客户端发来的 GET 读完再写响应：带着未读数据关连接，Windows 发的是
                // RST 而不是 FIN，会把客户端接收缓冲里还没读走的 204 一起吃掉（10054）。
                let mut get = [0u8; 256];
                let _ = s.read(&mut get);
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
            }
        });

        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(!c.ok, "引擎在自检期间退出，这句「通过」不能留");
        assert_eq!(c.status, Some(204), "状态码是当时的真实观察，照实留下：{c:?}");
        assert!(c.error.as_deref().unwrap_or_default().contains("引擎"));
        assert!(c.sentence().starts_with("通道自检（经交易出口）未通过："), "{}", c.sentence());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 记录的存取 ----------

    #[test]
    fn missing_or_broken_record_is_just_undetected() {
        let root = tmp_root("undetected");
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(load(&root), None, "文件不存在就是「未检测」");
        std::fs::write(root.join(FILE_NAME), "{not json").unwrap();
        assert_eq!(load(&root), None, "坏文件也只是「未检测」，不是错误");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn old_records_without_the_new_fields_keep_the_old_wording() {
        // 旧版写的 last-check.json 没有 via/skipped 字段：必须还能读，文案保持老样子。
        let root = tmp_root("legacy-record");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(FILE_NAME),
            r#"{"ok":true,"status":204,"error":null,"at":1}"#,
        )
        .unwrap();
        let c = load(&root).expect("旧记录必须可读");
        assert!(c.ok && !c.via_trade_exit && c.skipped.is_none());
        assert_eq!(c.sentence(), "通道自检：通过（HTTP 204）");
        assert_eq!(c.verdict(), "通过（HTTP 204）");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clear_removes_stale_evidence() {
        let root = tmp_root("clear");
        std::fs::create_dir_all(&root).unwrap();
        save(
            &root,
            &Check { ok: true, status: Some(204), error: None, at: 1, ..Default::default() },
        )
        .unwrap();
        clear(&root);
        assert_eq!(load(&root), None, "上一次连接的「通过」不能留给下一次用");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_manual_measurement_times_the_real_runtime_probe_without_touching_selfcheck() {
        let root = tmp_root("t13-measure");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("slowpass", "u", "p");
        runtime_probe(&root, port);
        save(&root, &Check { ok: true, status: Some(204), at: 42, ..Default::default() }).unwrap();
        let check_before = std::fs::read(root.join(FILE_NAME)).unwrap();

        let measured = measure_latency_and_record(&root, 2_000).expect("真实假探测必须测量成功");
        assert!(measured.latency_ms >= 80, "必须包含真实等待，不能填 0 或超时上限：{measured:?}");
        assert!(measured.at > 0, "完成时刻必须真实存在：{measured:?}");
        assert_eq!(measured.connection_started_at, "2026-01-01T00:00:00Z");
        assert_eq!(load_latency(&root), Some(measured.clone()), "测量记录必须可重读");
        assert_eq!(load_current_latency(&root), Some(measured), "同一连接必须能投影该读数");
        assert_eq!(std::fs::read(root.join(FILE_NAME)).unwrap(), check_before,
            "手动测速不得重写通道自检结论");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_successful_measurement_lands_in_the_perf_store() {
        // 曲线只吃「真实测得的延迟」：这条用例保证成功测量一定会落一条采样，
        // 且归属到当前线路与连接方式，而不是一条没有主人的数字。
        let root = tmp_root("t13-sample");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("slowpass", "u", "p");
        runtime_probe(&root, port);
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"}]}"#,
        )
        .expect("测试配置必须是合法 JSON");
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).expect("写入测试配置");

        let measured = measure_latency_and_record(&root, 2_000).expect("真实假探测必须测量成功");
        let samples = crate::perf::load(
            &root,
            "L1",
            measured.at as i64 - 1,
            measured.at as i64 + 1,
        );
        assert_eq!(samples.len(), 1, "成功的测量必须进采样库：{samples:?}");
        assert_eq!(samples[0].ms, Some(measured.latency_ms));
        assert_eq!(samples[0].line_id, "L1");
        assert_eq!(samples[0].profile, "标准", "默认线路是标准（UDP）连接");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_failed_manual_measurement_keeps_real_error_and_previous_evidence() {
        let root = tmp_root("t13-measure-failed");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("pass502", "u", "p");
        runtime_probe(&root, port);
        let previous = Latency { latency_ms: 23, at: 1, connection_started_at: "2026-01-01T00:00:00Z".into() };
        save_latency(&root, &previous).unwrap();
        save(&root, &Check { ok: true, status: Some(204), at: 42, ..Default::default() }).unwrap();
        let check_before = std::fs::read(root.join(FILE_NAME)).unwrap();

        let error = measure_latency_and_record(&root, 2_000).expect_err("HTTP 502 不得伪装成测量成功");
        let error_text = error.to_string();
        assert!(error_text.contains("HTTP 502"), "失败必须保留真实出口响应：{error_text}");
        assert_eq!(load_latency(&root), Some(previous), "失败不得伪造新毫秒数或完成时间");
        assert_eq!(std::fs::read(root.join(FILE_NAME)).unwrap(), check_before,
            "失败同样不得篡改既有自检证据");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_latency_from_another_connection_is_not_current() {
        let root = tmp_root("t13-stale-connection");
        live_engine(&root);
        save_latency(&root, &Latency {
            latency_ms: 18,
            at: 1,
            connection_started_at: "2025-12-31T23:59:59Z".into(),
        }).unwrap();
        assert_eq!(load_current_latency(&root), None, "上一连接的读数不能冒充当前连接");
        clear_latency(&root);
        assert_eq!(load_latency(&root), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn endpoint_port_is_parsed() {
        assert_eq!(port_from_endpoint("127.0.0.1:17890"), Some(17890));
        assert_eq!(port_from_endpoint("[::1]:1080"), Some(1080));
        assert_eq!(port_from_endpoint("127.0.0.1"), None);
        assert_eq!(port_from_endpoint("127.0.0.1:0"), None);
        assert_eq!(port_from_endpoint("127.0.0.1:abc"), None);
    }
}
