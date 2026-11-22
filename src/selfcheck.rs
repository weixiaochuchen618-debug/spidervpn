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
/// For a successful *automatic* tc-check, keep the identity qualified
/// before SOCKS was opened. The raw user/password remain only in memory;
/// the JSON extension stores a port and two domain-separated digests.
struct AutoProbeBinding {
    port: u16,
    user: String,
    pass: String,
    session_fingerprint: String,
    engine_fingerprint: String,
}

fn auto_engine_fingerprint(root: &Path) -> Option<String> {
    use sha2::Digest;
    let bytes = std::fs::read(root.join("runtime-engine.json")).ok()?;
    let mut hash = sha2::Sha256::new();
    hash.update(b"spidervpn/auto-probe-engine/v1\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(&bytes);
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

impl AutoProbeBinding {
    fn capture(root: &Path, port: u16, user: &str, pass: &str) -> Option<Self> {
        let proof = Self {
            port,
            user: user.to_string(),
            pass: pass.to_string(),
            session_fingerprint: check_session_fingerprint(root)?,
            engine_fingerprint: auto_engine_fingerprint(root)?,
        };
        proof.still_current(root).then_some(proof)
    }

    fn still_current(&self, root: &Path) -> bool {
        // Check credentials and the very same bytes of the qualified engine
        // config on BOTH sides of the real #39 route/user/unique-port gate.
        // A route becoming direct (or changing to another safe target) is
        // not equivalent to the route used by the completed HTTP request.
        if check_session_fingerprint(root).as_deref() != Some(&self.session_fingerprint)
            || probe_creds(root).as_ref() != Some(&(self.user.clone(), self.pass.clone()))
            || auto_engine_fingerprint(root).as_deref() != Some(&self.engine_fingerprint)
        {
            return false;
        }
        if crate::engine_config::probe_evidence_skip_reason_for_session(
            &root.join("runtime-engine.json"), self.port, &self.user, &self.pass,
        ).is_some() {
            return false;
        }
        check_session_fingerprint(root).as_deref() == Some(&self.session_fingerprint)
            && auto_engine_fingerprint(root).as_deref() == Some(&self.engine_fingerprint)
    }
}

pub fn check_and_record(root: &Path, plan: &ProbePlan, timeout_ms: u64) -> Check {
    // This check belongs to a new connection: never present old IP/latency
    // evidence as if it were measured by the newly selected trade route.
    crate::exit_probe::clear(root);
    clear_latency(root);
    // A plan's credentials alone cannot prove trade egress. Inspect the exact
    // engine config that was prepared for this session BEFORE any SOCKS dial.
    // If the selector can reach direct (including cached alternate members),
    // skip evidence, but do not undo the user's actual connection/selection.
    let current_creds = probe_creds(root);
    let mut bound_probe: Option<AutoProbeBinding> = None;
    let safe_plan = match plan {
        ProbePlan::Dial { port, username, password } => {
            let mut reason = match current_creds.as_ref() {
                None => None, // preserve the preexisting missing-credentials error
                Some((user, pass)) if user == username && pass == password => {
                    crate::engine_config::probe_evidence_skip_reason_for_session(
                        &root.join("runtime-engine.json"), *port, user, pass,
                    )
                }
                Some(_) => Some("本次探测计划与运行时认证凭据不一致，VPN 出口未验证".to_string()),
            };
            // A valid topology alone is not a snapshot: pin both the
            // authenticated runtime and the exact engine config that passed.
            if reason.is_none() {
                if let Some((user, pass)) = current_creds.as_ref() {
                    bound_probe = AutoProbeBinding::capture(root, *port, user, pass);
                    if bound_probe.is_none() {
                        reason = Some("本次探测会话或交易路由在预检期间改变，VPN 出口未验证".into());
                    }
                }
            }
            reason.map(|reason| ProbePlan::Skip { port: Some(*port), reason })
        }
        _ => None,
    };
    let plan = safe_plan.as_ref().unwrap_or(plan);
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
        ProbePlan::Dial { port, .. } => match current_creds.as_ref() {
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
                    let alive = engine_alive(root);
                    let same_probe = bound_probe.as_ref().is_some_and(|proof| proof.still_current(root));
                    if alive && same_probe {
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
                        // The HTTP status really was observed, but it is not
                        // evidence for an engine/identity/route that changed
                        // while this authenticated request was in flight.
                        Check {
                            ok: false,
                            status: Some(s),
                            error: Some(if alive {
                                "自检期间探测会话或交易路由已改变，本次结果无效"
                            } else {
                                "自检期间引擎退出"
                            }.to_string()),
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
    // The same binding that qualified the HTTP request must survive the
    // final disk commit. NEVER re-stamp a successful OLD response with a
    // fingerprint newly read from an unrelated runtime after SOCKS returns.
    let mut c = c;
    if c.ok {
        let written = bound_probe.as_ref().is_some_and(|proof|
            save_check_with_binding(root, &c, Some(proof)).is_ok()
                && proof.still_current(root) && engine_alive(root));
        if !written {
            c.ok = false;
            c.error = Some("自检证据提交期间会话或交易路由改变，无法确认当前出口".into());
            latency = None;
            clear_latency(root);
            if let Err(e) = save(root, &c) {
                eprintln!("失效自检结论未能写入：{e}");
            }
        }
    } else if let Err(e) = save(root, &c) {
        eprintln!("自检结果未能写入：{e}");
    }
    if let Some(measured) = latency {
        if bound_probe.as_ref().is_some_and(|proof| proof.still_current(root))
            && engine_alive(root)
        {
            if let Err(e) = save_latency(root, &measured) {
                eprintln!("延迟测量结果未能写入：{e}");
            }
        } else {
            clear_latency(root);
        }
    }
    if c.skipped.is_some() {
        // An old transport preference must not be interpreted as verification
        // from this connection when we deliberately could not probe its egress.
        if let Ok(Some(cfg)) = crate::config::load(&root.join(crate::config::DEFAULT_PATH)) {
            if let Some(line) = cfg.current_line() {
                if let Err(e) = crate::config::clear_verified_transport(root, &line.id) {
                    eprintln!("无法清除旧连接验证状态：{e}");
                }
            }
        }
    }
    // The decision was persisted above: successful auto probes use their
    // ORIGINAL pinned identity and route; failure/SKIP uses legacy save.
    c
}

/// 用户显式点击“测一次”：复用同一认证 SOCKS + HTTP 请求，只更新独立测量记录。
/// 不调用 `check_and_record`，所以无论成功失败都不会重写 `last-check.json`。
pub fn measure_latency_and_record(root: &Path, timeout_ms: u64) -> Result<Latency, MeasureError> {
    let (line_id, profile) = measurement_owner(root);
    let connection_started_at = runtime_started_at(root).ok_or_else(|| {
        MeasureError::new("environment", "当前连接缺少启动标识，请重新连接后测量")
    })?;
    // Manual measurement has no independent ProbePlan. Read the live probe
    // port first, then validate that unique SOCKS inbound's users and first
    // trade route against this runtime.json's actual session credentials.
    let port = active_probe_port(root).map_err(|e| MeasureError::new("config", e))?;
    let (user, pass) = probe_creds(root).ok_or_else(|| {
        MeasureError::new("environment", "当前连接没有探测凭据，请重新连接后测量")
    })?;
    if let Some(reason) = crate::engine_config::probe_evidence_skip_reason_for_session(
        &root.join("runtime-engine.json"), port, &user, &pass,
    ) {
        clear_latency(root);
        return Err(MeasureError::new("config", format!("VPN 出口未验证：{reason}")));
    }
    let session_before = check_session_fingerprint(root).ok_or_else(|| {
        MeasureError::new("environment", "当前连接没有可验证的探测会话，请重新连接后测量")
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
    // The process may restart or its runtime files may change during the
    // SOCKS/HTTP exchange. Do not persist a successful latency/perf sample
    // for a different connection from the one we qualified before dialing.
    if check_session_fingerprint(root).as_deref() != Some(&session_before)
        || runtime_started_at(root).as_deref() != Some(&connection_started_at)
        || crate::engine_config::probe_evidence_skip_reason_for_session(
            &root.join("runtime-engine.json"), port, &user, &pass,
        ).is_some()
    {
        clear_latency(root);
        return Err(MeasureError::new("config", "测量期间探测会话或交易路由已改变，本次读数无效"));
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

// A failed check write must not cause the IPC host's next status read to
// project an older PASS. Keep only root paths, never credentials or evidence.
// The on-disk .tmp presence below additionally guards cross-process reads of
// interrupted rename attempts. Storage failures are still reported honestly.
fn failed_check_writes() -> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static FAILED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>> =
        std::sync::OnceLock::new();
    FAILED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn note_failed_check_write(root: &Path, failed: bool) {
    if let Ok(mut paths) = failed_check_writes().lock() {
        if failed {
            paths.insert(root.to_path_buf());
        } else {
            paths.remove(root);
        }
    }
}

/// 写结论。原本的原子替换语义不变；失败时立即废弃当前进程中旧PASS的读取资格。
/// A non-secret, domain-separated identity for a single authenticated probe
/// session. The random credentials are regenerated per connection, and neither
/// their plaintext nor their reversible encoding is persisted in last-check.
/// StartedAt alone is insufficient (test fixtures and fast reconnects collide).
fn check_session_fingerprint(root: &Path) -> Option<String> {
    use sha2::Digest;
    let rec = crate::model::load_runtime(&root.join("runtime.json")).ok()??;
    let started = rec.started_at;
    let user = rec.probe_user?;
    let pass = rec.probe_pass?;
    if started.trim().is_empty() || user.is_empty() || pass.is_empty() {
        return None;
    }
    let mut hash = sha2::Sha256::new();
    hash.update(b"spidervpn/check-session/v1\0");
    for field in [started.as_bytes(), user.as_bytes(), pass.as_bytes()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn save(root: &Path, c: &Check) -> Result<(), String> {
    save_check_with_binding(root, c, None)
}

/// Preserve the legacy public save/Check format, but automatic success MUST
/// persist the proof captured BEFORE its SOCKS/HTTP request. Both the
/// in-memory decision and disk readers enforce that exact qualified route.
fn save_check_with_binding(
    root: &Path, c: &Check, bound: Option<&AutoProbeBinding>,
) -> Result<(), String> {
    let result = (|| -> Result<(), String> {
        let path = root.join(FILE_NAME);
        let mut value = serde_json::to_value(c).map_err(|e| e.to_string())?;
        if c.ok {
            if let Some(proof) = bound {
                if !proof.still_current(root) || !engine_alive(root) {
                    return Err("自检证据提交前会话或交易路由发生变化".into());
                }
                value["session_fingerprint"] =
                    serde_json::Value::String(proof.session_fingerprint.clone());
                value["auto_probe_port"] = serde_json::json!(proof.port);
                value["auto_engine_fingerprint"] =
                    serde_json::Value::String(proof.engine_fingerprint.clone());
            } else if let Some(fingerprint) = check_session_fingerprint(root) {
                // Synthetic/legacy callers retain their previous behavior.
                value["session_fingerprint"] = serde_json::Value::String(fingerprint);
            }
        }
        let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
        if let Some(proof) = bound {
            if !proof.still_current(root) || !engine_alive(root) {
                let _ = std::fs::remove_file(&tmp);
                return Err("自检写盘前会话或交易路由发生变化".into());
            }
        }
        std::fs::rename(&tmp, &path).map_err(|e| format!("{}：{e}", path.display()))?;
        if let Some(proof) = bound {
            // Uncoordinated external writers can race this rename, so also
            // check the final state. The reader independently enforces the
            // pinned engine digest/port/session if the files change later.
            if !proof.still_current(root) || !engine_alive(root) {
                return Err("自检写盘后会话或交易路由发生变化".into());
            }
        }
        Ok(())
    })();
    note_failed_check_write(root, result.is_err());
    result
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

// Fingerprint-only legacy trade PASS has NO original port/route snapshot.
// Never backfill one from the new runtime: only decide if the CURRENT live
// session still has a uniquely identified authenticated, non-direct tc-check.
// This is current-eligibility screening, NOT proof of the historical egress.
fn legacy_online_trade_eligible(root: &Path, stored_session: &str) -> bool {
    let engine_path = root.join("runtime-engine.json");
    let Some(before_engine) = auto_engine_fingerprint(root) else {
        return false;
    };
    let Some((user, pass)) = probe_creds(root) else {
        return false;
    };
    let port = (|| -> Option<u16> {
        let bytes = std::fs::read(&engine_path).ok()?;
        let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let inbounds = json.get("inbounds")?.as_array()?;
        let mut probes = inbounds.iter().filter(|inbound| {
            inbound.get("tag").and_then(serde_json::Value::as_str)
                == Some(crate::engine_config::PROBE_TAG)
        });
        let probe = probes.next()?;
        if probes.next().is_some() {
            return None; // ambiguous live entrance: cannot infer a unique port
        }
        let port = u16::try_from(probe.get("listen_port")?.as_u64()?).ok()?;
        (port != 0).then_some(port)
    })();
    let Some(port) = port else {
        return false; // no trustworthy CURRENT port, not a fabricated old one
    };
    if check_session_fingerprint(root).as_deref() != Some(stored_session)
        || crate::engine_config::probe_evidence_skip_reason_for_session(
            &engine_path, port, &user, &pass,
        ).is_some()
    {
        return false;
    }
    // Recheck after the strict gate: an independent writer may replace the
    // engine/config or runtime during the read; fail closed on observed change.
    engine_alive(root)
        && check_session_fingerprint(root).as_deref() == Some(stored_session)
        && probe_creds(root).as_ref() == Some(&(user, pass))
        && auto_engine_fingerprint(root).as_deref() == Some(&before_engine)
}

/// 读上次连接留下的结论。文件不存在或坏掉都当「未检测」：展示用的证据缺失，
/// 不该变成一条错误，更不该让 `--status` 打不开。
pub fn load(root: &Path) -> Option<Check> {
    // The existing same-process denial and disk .tmp guard remain in force.
    if root.join(FILE_NAME).with_extension("json.tmp").exists()
        || failed_check_writes().lock().map(|paths| paths.contains(root)).unwrap_or(true)
    {
        return None;
    }
    let text = std::fs::read_to_string(root.join(FILE_NAME)).ok()?;
    let value: serde_json::Value =
        serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()?;
    let check: Check = serde_json::from_value(value.clone()).ok()?;
    // No runtime record means this is an offline/disconnected historical
    // check: keep the long-standing "（上次）" and legacy JSON read behavior.
    // With ANY runtime record present, an unbound/old PASS is never eligible
    // as current VPN evidence, including after OS-process restart without
    // either a failed-write memory marker or a residual .tmp file.
    if check.ok && root.join("runtime.json").exists() {
        let stored = value.get("session_fingerprint").and_then(serde_json::Value::as_str)?;
        let current = check_session_fingerprint(root)?;
        if stored != current {
            return None;
        }
        // New automatic PASS records additionally bind the exact engine
        // topology and tc-check entrance that were qualified BEFORE HTTP.
        // The older successful Check JSON remains readable as before.
        if value.get("auto_probe_port").is_some()
            || value.get("auto_engine_fingerprint").is_some()
        {
            let port = u16::try_from(value.get("auto_probe_port")?.as_u64()?).ok()?;
            let engine_fingerprint =
                value.get("auto_engine_fingerprint")?.as_str()?.to_string();
            let (user, pass) = probe_creds(root)?;
            let proof = AutoProbeBinding {
                port, user, pass,
                session_fingerprint: stored.to_string(),
                engine_fingerprint,
            };
            if !proof.still_current(root) || !engine_alive(root) {
                return None;
            }
        } else if check.via_trade_exit {
            // A valid old session digest alone cannot vouch for a route
            // that changed to direct or an unknown tc-check entrance.
            // Do NOT make up its historical port/route and re-stamp JSON.
            if !legacy_online_trade_eligible(root, stored) {
                return None;
            }
        }
    }
    Some(check)
}

/// 清掉失败连接留下的结论与测量。断开后保留上次自检是独立行为，不在这里处理。
pub fn clear(root: &Path) {
    let removed = std::fs::remove_file(root.join(FILE_NAME));
    // If even deleting the old evidence is denied, status must not read it
    // as if it belonged to a later connection in this IPC process.
    note_failed_check_write(root, matches!(removed, Err(ref e)
        if e.kind() != std::io::ErrorKind::NotFound));
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
        // Existing fake SOCKS tests must explicitly model an eligible trade
        // selector; production no longer trusts a port/HTTP204 alone.
        std::fs::write(root.join("runtime-engine.json"),
            r#"{"outbounds":[{"type":"vless","tag":"hk"},{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"}],
                "inbounds":[{"type":"socks","tag":"tc-check","listen":"127.0.0.1",
                "users":[{"username":"u","password":"p"}]}],
                "route":{"rules":[{"inbound":["tc-check"],"outbound":"trade-exit"}]}}"#
        ).unwrap();
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
                r#"{{"outbounds":[{{"type":"vless","tag":"hk"}},{{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"}}],
                    "inbounds":[{{"type":"socks","tag":"tc-check","listen":"127.0.0.1","listen_port":{port},
                    "users":[{{"username":"u","password":"p"}}]}}],
                    "route":{{"rules":[{{"inbound":["tc-check"],"outbound":"trade-exit"}}]}}}}"#
            ),
        )
        .unwrap();
    }

    // Existing synthetic SOCKS tests now declare their actual probe port
    // and credentials, instead of relying on a fake runtime with no port.
    fn runtime_probe_with_creds(root: &Path, port: u16, user: &str, pass: &str) {
        runtime_probe(root, port);
        let path = root.join("runtime-engine.json");
        let mut runtime: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        runtime["inbounds"][0]["users"][0]["username"] = serde_json::json!(user);
        runtime["inbounds"][0]["users"][0]["password"] = serde_json::json!(pass);
        std::fs::write(path, runtime.to_string()).unwrap();
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
        runtime_probe(&root, silent);
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
        runtime_probe(&root, free);
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
    fn trade_direct_unsafe_runtime_skips_without_network_and_invalidates_old_latency() {
        let root = tmp_root("trade-direct-skip");
        live_engine(&root);
        with_creds(&root, "u", "p");
        std::fs::write(root.join("runtime-engine.json"),
            r#"{"outbounds":[{"type":"direct","tag":"direct"},
                {"type":"vless","tag":"hk"},
                {"type":"selector","tag":"trade-exit","outbounds":["direct","hk"],"default":"direct"}],
                "inbounds":[{"type":"socks","tag":"tc-check","listen":"127.0.0.1",
                    "users":[{"username":"u","password":"p"}]}],
                "route":{"rules":[{"inbound":["tc-check"],"outbound":"trade-exit"}]}}"#
        ).unwrap();
        let _ = std::fs::write(root.join(LATENCY_FILE_NAME), "{}");
        let c = check_and_record(&root, &dial_plan(closed_port(), "u", "p"), 1);
        assert!(!c.ok && c.status.is_none() && !c.via_trade_exit.eq(&false));
        assert!(c.skipped.as_deref().is_some_and(|reason| reason.contains("直连")), "{c:?}");
        assert!(c.verdict().starts_with("自检跳过："), "{c:?}");
        assert!(load_current_latency(&root).is_none());
        assert!(!root.join(LATENCY_FILE_NAME).exists());
        assert!(measure_latency_and_record(&root, 1).is_err());
        let _ = std::fs::remove_dir_all(root);
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
        runtime_probe_with_creds(&root, port, "probe-u", "probe-p");
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
        runtime_probe_with_creds(&root, port, "right-user", "right-pass");
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
        runtime_probe(&root, port);
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
        runtime_probe(&root, port);
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
        runtime_probe(&root, port);
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
        runtime_probe(&root, port);
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

        runtime_probe(&root, port);
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

        runtime_probe(&root, port);
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

    // MVP-03 Issue #39: TEST ONLY, loopback synthetic SOCKS, never real VPN.
    #[test]
    fn mvp03_session_probe_runtime_mutations_must_not_claim_vpn() {
        for case in ["wrong_port", "wrong_users", "non_route_action", "extra_route_condition"] {
            let root = tmp_root(&format!("mvp03-session-{case}"));
            live_engine(&root);
            with_creds(&root, "u", "p");
            let port = fake_socks5("pass", "u", "p");
            runtime_probe(&root, port);
            let path = root.join("runtime-engine.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            match case {
                "wrong_port" => {
                    let other = if port == u16::MAX { port - 1 } else { port + 1 };
                    value["inbounds"][0]["listen_port"] = serde_json::json!(other);
                }
                "wrong_users" => {
                    value["inbounds"][0]["users"][0]["password"] = serde_json::json!("other");
                }
                "non_route_action" => {
                    value["route"]["rules"][0]["action"] = serde_json::json!("reject");
                }
                "extra_route_condition" => {
                    value["route"]["rules"][0]["domain_suffix"] =
                        serde_json::json!(["never-matches.invalid"]);
                }
                _ => unreachable!(),
            }
            std::fs::write(&path, value.to_string()).unwrap();
            let c = check_and_record(&root, &dial_plan(port, "u", "p"), 1_000);
            assert!(!c.ok && c.status.is_none(), "{case}: unsafe probe yielded response: {c:?}");
            assert!(c.skipped.is_some(), "{case}: must explicitly SKIP/UNVERIFIED: {c:?}");
            assert!(!load(&root).is_some_and(|saved| saved.ok), "{case}: persisted PASS");
            let _ = std::fs::remove_dir_all(&root);
        }
        // Exact port+credentials, non-direct trade and explicit action=route remain valid.
        let root = tmp_root("mvp03-session-positive");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("pass", "u", "p");
        runtime_probe(&root, port);
        let path = root.join("runtime-engine.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["route"]["rules"][0]["action"] = serde_json::json!("route");
        std::fs::write(&path, value.to_string()).unwrap();
        let c = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(c.ok && c.status == Some(204), "valid authenticated probe regressed: {c:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mvp03_skip_save_failure_must_not_reload_stale_pass() {
        let root = tmp_root("mvp03-save-failure");
        live_engine(&root);
        with_creds(&root, "u", "p");
        save(&root, &Check {
            ok: true, status: Some(204), at: crate::model::now_epoch_secs_u64(),
            via_trade_exit: true, ..Default::default()
        }).unwrap();
        // Directory at temp-file path rejects the new SKIP write on every target.
        std::fs::create_dir(root.join("last-check.json.tmp")).unwrap();
        let original = std::fs::read(root.join(FILE_NAME)).unwrap();
        let now = check_and_record(&root, &ProbePlan::Skip {
            port: Some(17_893), reason: "本次交易出口无法确认".to_string(),
        }, 1);
        assert!(!now.ok && now.skipped.is_some(), "current decision must SKIP: {now:?}");
        assert_eq!(std::fs::read(root.join(FILE_NAME)).unwrap(), original,
            "old PASS must truly survive failed SKIP write for this regression");
        // IPC status_json consumes the same selfcheck::load reader.
        let displayed = load(&root);
        assert!(!displayed.as_ref().is_some_and(|check| check.ok),
            "status reader cannot report stale PASS: {displayed:?}");
        let _ = std::fs::remove_dir_all(root);
    }


    // Issue #41: TEST ONLY. All failure injection is confined to a temp root.
    // No user's real proxy, WFP, VPN, or public endpoint is contacted.
    #[test]
    fn mvp03_restart_without_tmp_cannot_reuse_stale_pass() {
        const CHILD_ROOT: &str = "SPIDERVPN_MVP03_RESTART_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            // The test binary itself is a new process, with a fresh OnceLock.
            let root = std::path::PathBuf::from(root);
            assert!(!root.join("last-check.json.tmp").exists(),
                "child must not inherit a blocked/pending temp-file marker");
            let observed = load(&root);
            assert!(!observed.as_ref().is_some_and(|check| check.ok),
                "new IPC-like reader must not call the old PASS current: {observed:?}");
            return;
        }

        let root = tmp_root("mvp03-restart-without-tmp");
        live_engine(&root);
        save(&root, &Check {
            ok: true,
            status: Some(204),
            at: crate::model::now_epoch_secs_u64(),
            via_trade_exit: true,
            ..Default::default()
        }).unwrap();
        // A directory at the ordinary .tmp write target forces a real
        // filesystem write error. The preexisting PASS must stay on disk.
        let temp = root.join("last-check.json.tmp");
        std::fs::create_dir(&temp).unwrap();
        let current = check_and_record(&root, &ProbePlan::Skip {
            port: Some(17_893),
            reason: "本次会话无法验证交易出口".to_string(),
        }, 1);
        assert!(!current.ok && current.skipped.is_some(), "{current:?}");
        let old: Check =
            serde_json::from_slice(&std::fs::read(root.join(FILE_NAME)).unwrap()).unwrap();
        assert!(old.ok && old.status == Some(204),
            "fixture must truly preserve a previous PASS on disk");
        // Simulate an error that did not leave a .tmp at recovery time.
        std::fs::remove_dir(&temp).unwrap();
        assert!(!temp.exists());
        assert!(load(&root).is_none(),
            "same-process in-memory failure marker must still deny the PASS");

        // This is a real separate OS process using the existing Rust test
        // binary. No artificial clearing of the protected in-memory marker.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "selfcheck::tests::mvp03_restart_without_tmp_cannot_reuse_stale_pass",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT, &root)
            .output()
            .expect("isolated Rust test child must be launchable");
        assert!(output.status.success(),
            "fresh-process stale-PASS check FAILED; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A real local SOCKS responder is used, never a real VPN server.
    /// The trade selector cannot choose direct while daily-exit defaults direct.
    fn mvp03_manual_fixture(tag: &str, status: &'static str) -> std::path::PathBuf {
        let root = tmp_root(&format!("mvp03-manual-{tag}"));
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5(status, "u", "p");
        runtime_probe(&root, port);
        let path = root.join("runtime-engine.json");
        let mut runtime: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let outbounds = runtime["outbounds"].as_array_mut().unwrap();
        outbounds.push(serde_json::json!({"type":"direct","tag":"direct"}));
        outbounds.push(serde_json::json!({
            "type":"selector", "tag":"daily-exit",
            "outbounds":["direct","hk"], "default":"direct"
        }));
        std::fs::write(path, runtime.to_string()).unwrap();
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"synthetic","proxy_endpoint":"127.0.0.1:17901"}]}"#
        ).unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        root
    }

    fn mvp03_manual_mutation_must_not_measure(kind: &str) {
        let root = mvp03_manual_fixture(kind, "pass");
        let path = root.join("runtime-engine.json");
        let mut runtime: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match kind {
            "wrong_users" => {
                // Runtime record still belongs to this connection, but the
                // runtime SOCKS listener names a different authentication user.
                runtime["inbounds"][0]["users"][0]["password"] =
                    serde_json::json!("unrelated-fixture");
            }
            "reject_action" => {
                runtime["route"]["rules"][0]["action"] = serde_json::json!("reject");
            }
            "extra_condition" => {
                runtime["route"]["rules"][0]["domain_suffix"] =
                    serde_json::json!(["never-matches.invalid"]);
            }
            _ => unreachable!(),
        }
        std::fs::write(&path, runtime.to_string()).unwrap();
        assert!(load_latency(&root).is_none(), "fixture must have no prior latency");
        let measured = measure_latency_and_record(&root, 2_000);
        let stored = load_latency(&root);
        let at = crate::model::now_epoch_secs_u64() as i64;
        let samples = crate::perf::load(&root, "L1", at - 30, at + 30);
        assert!(measured.is_err() && stored.is_none() && samples.is_empty(),
            "{kind}: invalid current runtime produced measurement={measured:?}, saved={stored:?}, perf_samples={samples:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mvp03_manual_wrong_runtime_users_cannot_record_latency() {
        mvp03_manual_mutation_must_not_measure("wrong_users");
    }

    #[test]
    fn mvp03_manual_reject_action_cannot_record_latency() {
        mvp03_manual_mutation_must_not_measure("reject_action");
    }

    #[test]
    fn mvp03_manual_extra_route_condition_cannot_record_latency() {
        mvp03_manual_mutation_must_not_measure("extra_condition");
    }

    #[test]
    fn mvp03_manual_valid_204_and_502_controls() {
        let good = mvp03_manual_fixture("good-204", "pass");
        let measured = measure_latency_and_record(&good, 2_000)
            .expect("matching authenticated local 204 must remain measurable");
        assert_eq!(load_current_latency(&good), Some(measured.clone()));
        let at = measured.at as i64;
        assert_eq!(crate::perf::load(&good, "L1", at - 5, at + 5).len(), 1,
            "valid HTTP204 must still create one real measurement sample");
        let _ = std::fs::remove_dir_all(&good);

        let bad = mvp03_manual_fixture("bad-502", "pass502");
        let failure = measure_latency_and_record(&bad, 2_000)
            .expect_err("HTTP502 must not become a successful measurement");
        assert!(failure.message.contains("HTTP 502"), "{failure:?}");
        assert!(load_latency(&bad).is_none(), "HTTP502 must not save latency");
        let _ = std::fs::remove_dir_all(bad);
    }


    #[test]
    fn mvp03_check_pass_fingerprint_binds_current_runtime_and_preserves_offline_history() {
        let root = tmp_root("mvp03-check-fingerprint");
        live_engine(&root);
        with_creds(&root, "fixture-user", "fixture-pass");
        // A CURRENT trade PASS requires a real, uniquely qualified probe
        // entrance. This older fingerprint test originally omitted the port.
        runtime_probe_with_creds(&root, closed_port(), "fixture-user", "fixture-pass");
        let prior = Check {
            ok: true, status: Some(204), at: 42,
            via_trade_exit: true, ..Default::default()
        };
        save(&root, &prior).expect("save authenticated synthetic PASS");
        assert_eq!(load(&root), Some(prior.clone()),
            "same runtime session must still load its own PASS");
        let on_disk = std::fs::read_to_string(root.join(FILE_NAME)).unwrap();
        assert!(on_disk.contains("session_fingerprint"),
            "new successful Check must carry a non-secret session binding");
        assert!(!on_disk.contains("fixture-user") && !on_disk.contains("fixture-pass"),
            "last-check must never persist raw probe credentials");

        // Keep StartedAt identical: a timestamp-only comparison would be
        // falsely green. New runtime credentials represent another session.
        with_creds(&root, "next-user", "next-pass");
        assert!(load(&root).is_none(),
            "same StartedAt must not allow earlier authenticated PASS");

        // After disconnect the unchanged Check record remains available for
        // the previous-session label. No live runtime means historical only.
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert_eq!(load(&root), Some(prior),
            "disconnect must not delete the readable historical PASS");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mvp03_legacy_pass_is_readable_offline_but_not_current_without_binding() {
        let root = tmp_root("mvp03-legacy-fingerprint");
        std::fs::write(root.join(FILE_NAME),
            r#"{"ok":true,"status":204,"error":null,"at":1}"#).unwrap();
        assert!(load(&root).is_some_and(|c| c.ok),
            "old JSON without a fingerprint remains readable as history");
        live_engine(&root);
        with_creds(&root, "u", "p");
        assert!(load(&root).is_none(),
            "legacy PASS without a binding is not proof of a new live session");
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert!(load(&root).is_some_and(|c| c.ok && c.status == Some(204)),
            "historical legacy JSON must stay readable after disconnect");
        let _ = std::fs::remove_dir_all(&root);
    }


    // Issue #45: strict TEST-ONLY composite and in-flight auto-check races.
    // Only synthetic temporary files and 127.0.0.1 SOCKS are involved.
    #[test]
    fn mvp03_composite_fingerprinted_pass_failed_skip_no_tmp_new_os_process() {
        const CHILD_ROOT: &str = "SPIDERVPN_MVP03_COMPOSITE_CHILD_ROOT";
        const CHILD_STAGE: &str = "SPIDERVPN_MVP03_COMPOSITE_CHILD_STAGE";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let root = std::path::PathBuf::from(path);
            let stage = std::env::var(CHILD_STAGE).expect("child stage supplied");
            assert!(!root.join("last-check.json.tmp").exists(),
                "fresh OS process cannot rely on a leftover temporary file");
            let raw = std::fs::read(root.join(FILE_NAME)).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let previous = v["session_fingerprint"].as_str().unwrap();
            assert_eq!(previous.len(), 64, "old PASS must have a real digest");
            let observed = load(&root);
            match stage.as_str() {
                "current" => {
                    assert!(root.join("runtime.json").exists());
                    assert_ne!(check_session_fingerprint(&root).as_deref(), Some(previous),
                        "same StartedAt but new probe credentials must change the digest");
                    assert!(!observed.as_ref().is_some_and(|c| c.ok),
                        "NEW PROCESS reused previously valid old fingerprint as current PASS: {observed:?}");
                }
                "history" => {
                    assert!(!root.join("runtime.json").exists(),
                        "the historical read is after simulated successful disconnect");
                    let historical = observed.expect("disconnected history must remain readable");
                    assert!(historical.ok && historical.status == Some(204)
                        && historical.via_trade_exit,
                        "old fingerprinted PASS must still be available as history: {historical:?}");
                }
                _ => panic!("invalid composite subprocess stage"),
            }
            return;
        }

        let root = tmp_root("mvp03-composite-cross-process");
        live_engine(&root);
        with_creds(&root, "old-synthetic-user", "old-synthetic-password");
        // The preceding PASS must be initially legitimate under the new
        // strict gate; the OS-child/stale-write assertions stay unchanged.
        runtime_probe_with_creds(&root, closed_port(), "old-synthetic-user", "old-synthetic-password");
        let old_started = runtime_started_at(&root).unwrap();
        let prior = Check {
            ok: true, status: Some(204), via_trade_exit: true,
            at: crate::model::now_epoch_secs_u64(), ..Default::default()
        };
        save(&root, &prior).expect("persist a previously eligible PASS");
        assert_eq!(load(&root), Some(prior.clone()),
            "old fingerprint must be truly valid in the first session");
        let old_bytes = std::fs::read(root.join(FILE_NAME)).unwrap();
        let old_value: serde_json::Value = serde_json::from_slice(&old_bytes).unwrap();
        let old_fp = old_value["session_fingerprint"].as_str().unwrap();
        assert_eq!(old_fp.len(), 64);
        assert!(!String::from_utf8_lossy(&old_bytes).contains("old-synthetic-password"),
            "no probe credentials may enter last-check");

        with_creds(&root, "new-synthetic-user", "new-synthetic-password");
        assert_eq!(runtime_started_at(&root), Some(old_started),
            "timestamp collision must be intentional");
        assert_ne!(check_session_fingerprint(&root).as_deref(), Some(old_fp));
        let temporary = root.join("last-check.json.tmp");
        std::fs::create_dir(&temporary).unwrap();
        let skipped = check_and_record(&root, &ProbePlan::Skip {
            port: Some(17_893), reason: "synthetic new session was not verified".into(),
        }, 1);
        assert!(!skipped.ok && skipped.skipped.is_some(), "{skipped:?}");
        assert_eq!(std::fs::read(root.join(FILE_NAME)).unwrap(), old_bytes,
            "SKIP write failure must leave the OLD valid fingerprinted PASS on disk");
        std::fs::remove_dir(&temporary).unwrap();
        assert!(!temporary.exists(), "no .tmp remains before process restart");
        assert!(load(&root).is_none(),
            "same-process failed-write guard should still reject the stale PASS");

        let run_child = |stage: &str| {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "selfcheck::tests::mvp03_composite_fingerprinted_pass_failed_skip_no_tmp_new_os_process",
                    "--nocapture", "--test-threads=1",
                ])
                .env(CHILD_ROOT, &root)
                .env(CHILD_STAGE, stage)
                .output().expect("launch an independent test OS process");
            assert!(out.status.success(),
                "{stage} fresh-process check FAILED; stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr));
        };
        run_child("current");
        // Ordinary disconnect deletes runtime.json, not last-check.json:
        // the original PASS remains readable as "previous", not current.
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert_eq!(std::fs::read(root.join(FILE_NAME)).unwrap(), old_bytes);
        run_child("history");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A deterministic real loopback SOCKS5 server pauses only AFTER reading
    /// the HTTP request, so the production pre-dial guard already ran and
    /// the client cannot receive 204/502 until the test explicitly releases it.
    fn mvp03_gated_auto_socks(
        status: u16,
    ) -> (
        u16,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("loopback auto-check connects");
            stream.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(12))).unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).unwrap();
            let mut header = [0u8; 2];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header[0], 0x01);
            let mut username = vec![0; header[1] as usize];
            stream.read_exact(&mut username).unwrap();
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).unwrap();
            let mut password = vec![0; n[0] as usize];
            stream.read_exact(&mut password).unwrap();
            // Only harmless fixed fixture credentials. Never relay a request.
            assert_eq!(username, b"u");
            assert_eq!(password, b"p");
            stream.write_all(&[0x01, 0x00]).unwrap();

            let mut connect = [0u8; 5];
            stream.read_exact(&mut connect).unwrap();
            assert_eq!(&connect[..4], &[0x05, 0x01, 0x00, 0x03]);
            let mut target = vec![0; connect[4] as usize + 2];
            stream.read_exact(&mut target).unwrap();
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();

            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).expect("get first HTTP line");
            assert_eq!(line, "GET /generate_204 HTTP/1.1\r\n");
            loop {
                line.clear();
                reader.read_line(&mut line).expect("read synthetic HTTP headers");
                if line == "\r\n" { break; }
                assert!(!line.is_empty(), "HTTP request must be complete");
            }
            // The production HTTP client has sent a real request but MUST
            // wait here: no sleeps, guesswork, or production-only test hook.
            arrived_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10))
                .expect("coordinator must release the held HTTP response");
            let response = if status == 204 {
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            };
            stream.write_all(response.as_bytes()).unwrap();
        });
        (port, arrived_rx, release_tx, server)
    }

    fn mvp03_auto_race_fixture(
        tag: &str, status: u16,
    ) -> (
        std::path::PathBuf,
        u16,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let root = tmp_root(tag);
        live_engine(&root);
        with_creds(&root, "u", "p");
        let (port, arrived, release, server) = mvp03_gated_auto_socks(status);
        runtime_probe(&root, port);
        // Explicit user-like daily direct fallback; trade remains a distinct
        // non-direct selector, exactly as the older positive regressions demand.
        let path = root.join("runtime-engine.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["outbounds"].as_array_mut().unwrap().push(
            serde_json::json!({"type":"direct","tag":"direct"}));
        value["outbounds"].as_array_mut().unwrap().push(serde_json::json!({
            "type":"selector","tag":"daily-exit",
            "outbounds":["direct","hk"],"default":"direct"
        }));
        std::fs::write(&path, value.to_string()).unwrap();
        (root, port, arrived, release, server)
    }

    fn mvp03_auto_inflight_case(tag: &str, change: &str, status: u16) {
        let (root, port, arrived, release, server) = mvp03_auto_race_fixture(tag, status);
        let client_root = root.clone();
        let client = std::thread::spawn(move ||
            check_and_record(&client_root, &dial_plan(port, "u", "p"), 15_000));
        arrived.recv_timeout(Duration::from_secs(10))
            .expect("real authenticated SOCKS precheck and HTTP request must reach barrier");

        match change {
            "new_session" => {
                let old_started = runtime_started_at(&root);
                // Keep the timestamp identical to expose stale-session
                // attribution even on a same-second fast reconnect.
                with_creds(&root, "u-new", "p-new");
                let path = root.join("runtime-engine.json");
                let mut engine: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                engine["inbounds"][0]["users"][0]["username"] = serde_json::json!("u-new");
                engine["inbounds"][0]["users"][0]["password"] = serde_json::json!("p-new");
                std::fs::write(path, engine.to_string()).unwrap();
                assert_eq!(runtime_started_at(&root), old_started);
            }
            "trade_direct" => {
                let path = root.join("runtime-engine.json");
                let mut engine: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                engine["route"]["rules"][0]["outbound"] = serde_json::json!("direct");
                std::fs::write(path, engine.to_string()).unwrap();
            }
            "none" => {}
            _ => panic!("invalid race variation"),
        }
        // A production-path precheck now has stale information. Release the
        // synthetic HTTP response only after all file mutations committed.
        release.send(()).unwrap();
        let result = client.join().expect("auto-check client completes");
        server.join().expect("synthetic SOCKS handler completes");
        let on_disk = load(&root);
        if change == "none" && status == 204 {
            assert!(result.ok && result.status == Some(204) && result.via_trade_exit,
                "stable authenticated trade route must PASS normally: {result:?}");
            assert!(on_disk.as_ref().is_some_and(|c| c.ok && c.status == Some(204)),
                "stable HTTP204 must persist a current fingerprinted PASS: {on_disk:?}");
        } else {
            assert!(!result.ok && !on_disk.as_ref().is_some_and(|c| c.ok),
                "{tag}: in-flight change={change}, HTTP{status}: OLD request was attributed as current VPN PASS; result={result:?}, stored={on_disk:?}");
            if status == 502 {
                assert_eq!(result.status, Some(502),
                    "true HTTP502 must remain a non-PASS error without rewriting semantics");
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mvp03_auto_inflight_runtime_session_switch_must_not_pass() {
        mvp03_auto_inflight_case("mvp03-auto-runtime-race", "new_session", 204);
    }

    #[test]
    fn mvp03_auto_inflight_trade_route_switch_must_not_pass() {
        mvp03_auto_inflight_case("mvp03-auto-route-race", "trade_direct", 204);
    }

    #[test]
    fn mvp03_auto_inflight_stable_204_and_502_controls() {
        mvp03_auto_inflight_case("mvp03-auto-control204", "none", 204);
        mvp03_auto_inflight_case("mvp03-auto-control502", "none", 502);
    }

    #[test]
    fn mvp03_stale_engine_runtime_check_is_observed_not_falsely_verified() {
        let root = tmp_root("mvp03-stale-engine-observation");
        runtime_with_engine(&root, -1);
        with_creds(&root, "fixture-only-user", "fixture-only-password");
        assert!(!engine_alive(&root),
            "negative PID is a deterministic synthetic dead-engine record");
        let prior = Check {
            ok: true, status: Some(204), via_trade_exit: true, at: 7,
            ..Default::default()
        };
        save(&root, &prior).unwrap();
        // Characterize rather than declare a new product requirement: status
        // also applies its existing independent live-engine evidence.
        let observed = load(&root);
        assert!(observed.is_none() || observed == Some(prior),
            "only characterize the stale-runtime reader; do not alter its policy");
        let _ = std::fs::remove_dir_all(root);
    }


    #[test]
    fn mvp03_auto_saved_pass_pins_original_engine_route_and_stays_historical_offline() {
        let root = tmp_root("mvp03-autobound-history");
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = fake_socks5("pass", "u", "p");
        runtime_probe(&root, port);
        let proof = check_and_record(&root, &dial_plan(port, "u", "p"), 2_000);
        assert!(proof.ok && proof.status == Some(204), "eligible original route: {proof:?}");
        let disk = std::fs::read_to_string(root.join(FILE_NAME)).unwrap();
        let record: serde_json::Value = serde_json::from_str(&disk).unwrap();
        assert_eq!(record["auto_probe_port"].as_u64(), Some(u64::from(port)));
        assert_eq!(record["session_fingerprint"].as_str().unwrap().len(), 64);
        assert_eq!(record["auto_engine_fingerprint"].as_str().unwrap().len(), 64);
        assert!(!disk.contains(r#""ProbePass""#) && !disk.contains(r#""ProbeUser""#),
            "auto evidence must not store raw SOCKS credentials");
        assert_eq!(load(&root), Some(proof.clone()),
            "original qualified route and session must be readable");

        // A *later* unsafe route switch must also invalidate an already
        // committed automatic PASS at the shared CLI/IPC read boundary.
        let path = root.join("runtime-engine.json");
        let mut engine: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        engine["route"]["rules"][0]["outbound"] = serde_json::json!("direct");
        engine["outbounds"].as_array_mut().unwrap().push(
            serde_json::json!({"type":"direct","tag":"direct"}));
        std::fs::write(path, engine.to_string()).unwrap();
        assert!(load(&root).is_none(),
            "old automatic PASS must not stay current after route becomes direct");
        // Normal disconnect removes runtime.json; the preserved Check remains
        // historical, with the same old 204 status and no UI schema change.
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert_eq!(load(&root), Some(proof),
            "disconnected previous-session Check must remain readable");
        let _ = std::fs::remove_dir_all(root);
    }


    // Issue #49 B1/B2: TEST-ONLY offline evidence, no public endpoint, no
    // real connect_json, HKCU proxy edits, engine/WFP/VPS, or production hooks.
    fn mvp03_b1_fixture(tag: &str) -> (std::path::PathBuf, u16) {
        let root = tmp_root(tag);
        live_engine(&root);
        with_creds(&root, "u", "p");
        let port = closed_port();
        runtime_probe(&root, port);
        let path = root.join("runtime-engine.json");
        let mut engine: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        engine["outbounds"].as_array_mut().unwrap()
            .push(serde_json::json!({"type":"direct","tag":"direct"}));
        engine["outbounds"].as_array_mut().unwrap().push(serde_json::json!({
            "type":"selector","tag":"daily-exit",
            "outbounds":["direct","hk"],"default":"direct"
        }));
        std::fs::write(&path, engine.to_string()).unwrap();
        assert!(crate::engine_config::probe_evidence_skip_reason_for_session(
            &path, port, "u", "p",
        ).is_none(), "old trade PASS must start with genuinely qualified route");
        (root, port)
    }

    fn mvp03_b1_unsafe_direct_route(root: &Path) {
        let path = root.join("runtime-engine.json");
        let mut engine: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        engine["route"]["rules"][0]["outbound"] = serde_json::json!("direct");
        std::fs::write(&path, engine.to_string()).unwrap();
    }

    #[test]
    fn mvp03_b1_old_online_trade_fingerprint_only_route_direct_must_not_pass() {
        let (root, port) = mvp03_b1_fixture("mvp03-b1-legacy-online-direct");
        let original = Check {
            ok: true, status: Some(204), via_trade_exit: true, at: 42,
            ..Default::default()
        };
        // Use the real legacy PUBLIC save path, not handcrafted JSON:
        // the OLD online trade success is an actual valid session-bound PASS.
        save(&root, &original).unwrap();
        let disk = std::fs::read_to_string(root.join(FILE_NAME)).unwrap();
        let rec: serde_json::Value = serde_json::from_str(&disk).unwrap();
        assert_eq!(rec["session_fingerprint"].as_str().map(str::len), Some(64));
        assert!(rec.get("auto_probe_port").is_none()
            && rec.get("auto_engine_fingerprint").is_none(),
            "this MUST exercise fingerprint-only legacy success, not the new auto format");
        assert!(!disk.contains(r#""ProbeUser""#) && !disk.contains(r#""ProbePass""#),
            "last-check must not store authentication credentials");
        assert_eq!(load(&root), Some(original.clone()),
            "old session-bound PASS was genuinely current and readable before change");
        assert!(crate::engine_config::probe_evidence_skip_reason_for_session(
            &root.join("runtime-engine.json"), port, "u", "p",
        ).is_none());
        let unchanged_session = check_session_fingerprint(&root);
        mvp03_b1_unsafe_direct_route(&root);
        assert_eq!(check_session_fingerprint(&root), unchanged_session,
            "B1 must change ONLY routing, not the runtime session");
        assert!(crate::engine_config::probe_evidence_skip_reason_for_session(
            &root.join("runtime-engine.json"), port, "u", "p",
        ).is_some(), "new route is genuinely disqualified");
        let observed = load(&root);
        assert!(!observed.as_ref().is_some_and(|c| c.ok && c.via_trade_exit),
            "B1: fingerprint-only OLD trade PASS was accepted CURRENT after route changed to direct; observed={observed:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mvp03_b1_safe_legacy_trade_nontrade_and_offline_history_controls() {
        let (root, _) = mvp03_b1_fixture("mvp03-b1-safe-controls");
        let trade = Check {
            ok: true, status: Some(204), via_trade_exit: true, at: 15,
            ..Default::default()
        };
        save(&root, &trade).unwrap();
        assert_eq!(load(&root), Some(trade.clone()),
            "qualified old format trade PASS must remain valid online");
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert_eq!(load(&root), Some(trade),
            "disconnected old success is still readable as historical");
        // Re-establish a fresh synthetic runtime for the separate nontrade
        // online positive control; record_probe_creds requires runtime.json.
        live_engine(&root);
        with_creds(&root, "u", "p");
        let nontrade = Check {
            ok: true, status: Some(204), via_trade_exit: false, at: 16,
            ..Default::default()
        };
        save(&root, &nontrade).unwrap();
        assert_eq!(load(&root), Some(nontrade.clone()),
            "explicit nontrade old Check is not an authenticated trade assertion");
        mvp03_b1_unsafe_direct_route(&root);
        assert_eq!(load(&root), Some(nontrade.clone()),
            "route-specific B1 gate must not rewrite legacy nontrade semantics");
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        assert_eq!(load(&root), Some(nontrade),
            "nontrade historical JSON also remains readable offline");
        let _ = std::fs::remove_dir_all(root);
    }

    fn mvp03_b2_config_fixture(root: &Path) -> crate::config::LineConfig {
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"L1","lines":[{"id":"L1","name":"offline-fixture","proxy_endpoint":"127.0.0.1:17891"}]}"#
        ).unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        cfg.current_line().unwrap().clone()
    }

    fn mvp03_b2_after_return_mutation(root: &Path, change: &str) {
        match change {
            "route" => mvp03_b1_unsafe_direct_route(root),
            "session" => {
                let before = runtime_started_at(root);
                with_creds(root, "new-u", "new-p");
                let path = root.join("runtime-engine.json");
                let mut engine: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                engine["inbounds"][0]["users"][0]["username"] = serde_json::json!("new-u");
                engine["inbounds"][0]["users"][0]["password"] = serde_json::json!("new-p");
                std::fs::write(path, engine.to_string()).unwrap();
                assert_eq!(runtime_started_at(root), before,
                    "the fast reconnect uses the SAME StartedAt, by construction");
            }
            "none" => (),
            _ => panic!("unknown mutation fixture"),
        }
    }

    fn mvp03_b2_verified_transport_returned_check_case(tag: &str, change: &str) {
        let root = tmp_root(tag);
        live_engine(&root);
        with_creds(&root, "u", "p");
        let line = mvp03_b2_config_fixture(&root);
        assert_eq!(line.verified_transport, None);
        let port = fake_socks5("pass", "u", "p");
        runtime_probe(&root, port);
        let plan = dial_plan(port, "u", "p");
        // Real production auto-check finishes AND its own current disk
        // evidence is accepted BEFORE caller-stage mutation.
        let returned = check_and_record(&root, &plan, 2_000);
        assert!(returned.ok && returned.status == Some(204), "valid first phase: {returned:?}");
        assert_eq!(load(&root), Some(returned.clone()), "real persisted auto PASS");
        mvp03_b2_after_return_mutation(&root, change);
        if change != "none" {
            assert!(!load(&root).is_some_and(|c| c.ok),
                "new shared reader already recognizes that cached PASS is now stale");
        }
        // Exact production caller condition + actual production persistence
        // function from main.rs and ipc.rs; NOT the proxy-mutating handler.
        let wrote = if returned.ok {
            crate::config::record_verified_transport(
                &root, &line.id, line.effective_transport(),
            ).expect("actual local config write path")
        } else { false };
        let saved = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .unwrap().unwrap();
        let consumed = saved.current_line().unwrap();
        if change == "none" {
            assert!(wrote && consumed.verified_transport == Some(line.effective_transport()),
                "stable caller control must really persist a verified transport");
        } else {
            assert!(!wrote && consumed.verified_transport.is_none(),
                "B2 verified_transport: stale returned Check.ok=true was consumed AFTER {change} mutation; actual production write={wrote}, on-disk verified_transport={:?}, effective_transport={:?}",
                consumed.verified_transport, consumed.effective_transport());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mvp03_b2_post_return_route_change_must_not_persist_verified_transport() {
        mvp03_b2_verified_transport_returned_check_case(
            "mvp03-b2-return-route", "route");
    }

    #[test]
    fn mvp03_b2_post_return_session_change_must_not_persist_verified_transport() {
        mvp03_b2_verified_transport_returned_check_case(
            "mvp03-b2-return-session", "session");
    }

    #[test]
    fn mvp03_b2_stable_caller_verified_transport_control() {
        mvp03_b2_verified_transport_returned_check_case(
            "mvp03-b2-stable-caller", "none");
    }

    /// All exit-probe HTTP bytes are generated by this 127.0.0.1 server;
    /// 8.8.8.8 appears in a synthetic body and local fixture file ONLY.
    /// Neither the SOCKS CONNECT host nor the IP literal is contacted.
    fn mvp03_b2_two_phase_loopback_socks() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for phase in 0..2 {
                let (mut stream, _) = listener.accept().expect("only loopback SOCKS peer");
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut greeting = [0u8; 4];
                stream.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 2, 0, 2]);
                stream.write_all(&[5, 2]).unwrap();
                let mut auth = [0u8; 2];
                stream.read_exact(&mut auth).unwrap();
                let mut username = vec![0u8; auth[1] as usize];
                stream.read_exact(&mut username).unwrap();
                let mut n = [0u8; 1];
                stream.read_exact(&mut n).unwrap();
                let mut password = vec![0u8; n[0] as usize];
                stream.read_exact(&mut password).unwrap();
                assert_eq!(username, b"u");
                assert_eq!(password, b"p");
                stream.write_all(&[1, 0]).unwrap();
                let mut connect = [0u8; 5];
                stream.read_exact(&mut connect).unwrap();
                assert_eq!(&connect[..4], &[5, 1, 0, 3]);
                let mut rest = vec![0u8; connect[4] as usize + 2];
                stream.read_exact(&mut rest).unwrap();
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                assert!(first.starts_with("GET /"), "{first:?}");
                loop {
                    first.clear();
                    reader.read_line(&mut first).unwrap();
                    if first == "\r\n" { break; }
                    assert!(!first.is_empty(), "complete HTTP headers required");
                }
                drop(reader);
                if phase == 0 {
                    stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").unwrap();
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\n8.8.8.8\n").unwrap();
                }
            }
        });
        (port, server)
    }

    fn mvp03_b2_exit_attribution_after_return_case(tag: &str, change: &str) {
        let root = tmp_root(tag);
        live_engine(&root);
        with_creds(&root, "u", "p");
        let line = mvp03_b2_config_fixture(&root);
        std::fs::create_dir_all(root.join("lines")).unwrap();
        // Documentation-only fake server address: only used for comparing a
        // SYNTHETIC local HTTP response; never reached over the network.
        std::fs::write(line.engine_config_path(&root),
            r#"{"outbounds":[{"type":"vless","tag":"hk","server":"8.8.8.8"}]}"#
        ).unwrap();
        let (port, server) = mvp03_b2_two_phase_loopback_socks();
        runtime_probe(&root, port);
        let plan = dial_plan(port, "u", "p");
        let returned = check_and_record(&root, &plan, 3_000);
        assert!(returned.ok && returned.status == Some(204),
            "first real auto-check must finish before mutation: {returned:?}");
        assert_eq!(load(&root), Some(returned.clone()));
        mvp03_b2_after_return_mutation(&root, change);
        if change != "none" {
            assert!(!load(&root).is_some_and(|c| c.ok),
                "shared selfcheck reader must reject new caller context");
        }
        // This is the REAL production exit_probe function invoked with the
        // same cached Check.ok caller condition and original ProbePlan. No
        // main.rs/ipc.rs connect handler, public IP service or proxy switch.
        let observed = if returned.ok {
            crate::exit_probe::probe_and_record(&root, &line, &plan, 2_500)
        } else { None };
        server.join().expect("both local synthetic HTTP calls finished");
        let disk = crate::exit_probe::load(&root);
        assert_eq!(disk, observed, "must inspect real exit-probe.json disk write");
        assert!(disk.is_some(), "loopback 200 IP body must exercise real parser and recorder");
        let rec = disk.as_ref().unwrap();
        assert_eq!(rec.ip, "8.8.8.8", "synthetic response only, not real exit IP");
        if change == "none" {
            assert!(rec.attributed
                && crate::exit_probe::belongs_to_current_connection(rec, &root),
                "stable exit-probe parsing/recording control must be accepted");
        } else {
            assert!(!(rec.attributed
                && crate::exit_probe::belongs_to_current_connection(rec, &root)),
                "B2 exit attribution: old cached Check.ok after {change} change caused real exit-probe.json to contain a CURRENT attributed IP, despite only local synthetic SOCKS bytes: {rec:?}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mvp03_b2_post_return_route_change_must_not_consume_exit_attribution() {
        mvp03_b2_exit_attribution_after_return_case(
            "mvp03-b2-exit-route", "route");
    }

    #[test]
    fn mvp03_b2_post_return_same_started_at_new_session_must_not_attrib_exit() {
        mvp03_b2_exit_attribution_after_return_case(
            "mvp03-b2-exit-new-session", "session");
    }

    #[test]
    fn mvp03_b2_stable_exit_attribution_local_socks_control() {
        mvp03_b2_exit_attribution_after_return_case(
            "mvp03-b2-exit-control", "none");
    }

    #[test]
    fn mvp03_b1_legacy_online_trade_requires_unique_qualified_current_probe() {
        for mutation in ["missing_port", "duplicate_probe", "wrong_users",
                         "unknown_route", "extra_condition", "missing_engine"] {
            let root = tmp_root(&format!("mvp03-b1-current-{mutation}"));
            live_engine(&root);
            with_creds(&root, "u", "p");
            let port = closed_port();
            runtime_probe(&root, port);
            let prior = Check {
                ok: true, status: Some(204), via_trade_exit: true, at: 1,
                ..Default::default()
            };
            save(&root, &prior).unwrap();
            assert_eq!(load(&root), Some(prior.clone()),
                "{mutation}: qualified starting legacy check must be readable");
            let path = root.join("runtime-engine.json");
            if mutation == "missing_engine" {
                std::fs::remove_file(&path).unwrap();
            } else {
                let mut engine: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                match mutation {
                    "missing_port" => {
                        engine["inbounds"][0].as_object_mut().unwrap()
                            .remove("listen_port");
                    }
                    "duplicate_probe" => {
                        let same = engine["inbounds"][0].clone();
                        engine["inbounds"].as_array_mut().unwrap().push(same);
                    }
                    "wrong_users" => {
                        engine["inbounds"][0]["users"][0]["password"] =
                            serde_json::json!("not-the-live-session");
                    }
                    "unknown_route" => {
                        engine["route"]["rules"][0]["outbound"] =
                            serde_json::json!("unknown-egress");
                    }
                    "extra_condition" => {
                        engine["route"]["rules"][0]["domain_suffix"] =
                            serde_json::json!(["never-matches.invalid"]);
                    }
                    _ => unreachable!(),
                }
                std::fs::write(&path, engine.to_string()).unwrap();
            }
            assert!(!load(&root).as_ref().is_some_and(|c| c.ok && c.via_trade_exit),
                "{mutation}: legacy online trade PASS must fail-closed");
            // No deletion/rewriting of the historical JSON by the reader.
            std::fs::remove_file(root.join("runtime.json")).unwrap();
            assert_eq!(load(&root), Some(prior),
                "{mutation}: ordinary disconnect must preserve old Check history");
            let _ = std::fs::remove_dir_all(root);
        }
    }

}
