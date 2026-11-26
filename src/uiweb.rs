//! 旧版web 前端（`web\`）的宿主桥：资产伺服、快照投影、意图分发。
//!
//! 契约（见 deliverables\gstack\rust-ui-web-reuse-plan-2026-11-01.md）：
//! - 宿主 → 页面：`{Type:'snapshot', Page, State:{…}}`，页面只认 `chrome.webview` 的 message 事件。
//! - 页面 → 宿主：按钮 `data-action` 即 `{Type:…, Sequence}`；`State.Ack >= Sequence` 释放等待态。
//! - 本模块只做投影与翻译：命令仍然走既有 `handler`（与 CLI/管道同一条路径），不新增业务。

use serde_json::{json, Value};

use crate::uiweb_form::{Absorbed, DeployFollowUp, FormState, View};

pub const INDEX_HTML: &str = include_str!("../web/index.html");
pub const APP_JS: &str = include_str!("../web/app.js");
pub const APP_CSS: &str = include_str!("../web/app.css");
pub const FORMS_CSS: &str = include_str!("../web/forms.css");
pub const TOKENS_CSS: &str = include_str!("../web/tokens.css");
/// 首帧主题引导（T-19）：`<head>` 里排在样式表之前，深色启动不闪白底。
pub const THEME_BOOT_JS: &str = include_str!("../web/theme-boot.js");

/// 页面 origin：自定义协议在 Windows 上映射为 `http://tc.ui`。
/// CSP 是 `script-src 'self'`，app.js 必须作为独立路径伺服，不能内联。
pub const PAGE_ORIGIN_URL: &str = "http://tc.ui/index.html";

/// 首屏注入：把宿主快照送进页面已有的监听器。app.js 不需要任何改动。
pub const INIT_SCRIPT: &str = "window.__tcPush=function(s){try{if(window.chrome&&window.chrome.webview){window.chrome.webview.dispatchEvent(new MessageEvent('message',{data:s}));}}catch(e){}};";

/// 资产路由：CSP 下每个文件都必须是独立路径。未知路径回 404，由前端自己的降级兜底。
pub fn asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    let p = path.trim_start_matches('/');
    let p = p.split(['?', '#']).next().unwrap_or(p);
    match p {
        "" | "index.html" => Some(("text/html; charset=utf-8", INDEX_HTML.as_bytes())),
        "app.js" => Some(("text/javascript; charset=utf-8", APP_JS.as_bytes())),
        "theme-boot.js" => Some(("text/javascript; charset=utf-8", THEME_BOOT_JS.as_bytes())),
        "app.css" => Some(("text/css; charset=utf-8", APP_CSS.as_bytes())),
        "forms.css" => Some(("text/css; charset=utf-8", FORMS_CSS.as_bytes())),
        "tokens.css" => Some(("text/css; charset=utf-8", TOKENS_CSS.as_bytes())),
        _ => None,
    }
}

/// 一条意图展开成的执行步骤。
#[derive(Debug, Clone)]
pub enum Step {
    /// 同步命令：小命令，直接走 handler，回包立刻进快照。
    Sync(String),
    /// 长命令：进既有 submit_operation 预算通道，完成时经 UiHostEvent 回推。
    Long(String),
    /// 直接对页面执行一段脚本。唯一的用途是**把邀请码单独递给页面**：
    /// 它不能进快照（快照会按秒重推、会进日志、会被截图），所以走一条只发一次的通道。
    Script(String),
}

impl Step {
    /// 这一步要执行的命令行。回包分派（表单吸收）按命令名走，需要原文。
    /// 生产路径按枚举分支执行，用不到原文，只有测试需要。
    #[cfg(test)]
    pub fn command(&self) -> &str {
        match self {
            Step::Sync(c) | Step::Long(c) => c,
            Step::Script(_) => "",
        }
    }
}

/// 跨消息的页面宿主状态。全部可从 UI 线程访问（Rc<RefCell>），不做跨线程。
#[derive(Default)]
pub struct WebUi {
    pub page: String,
    pub ack: u64,
    /// 入站消息序号（D，r56）：最后一条**通过校验**的来包 `Sequence`。
    ///
    /// 与 [`Self::ack`] 是两件事，不能混用：`ack` 是宿主自己的应答计数（每次
    /// `bump()` 加一，前端拿它判「我发的意图处理完了吗」），而这里记的是页面发来的
    /// 序号。旧版用同一个 `$script:WebAck` 兼任两者，是因为它的 `ack` 只在收到
    /// 消息时变；本版 `bump()` 每帧都涨，混用会把页面消息全部挡掉。
    pub inbound_seq: u64,
    pub busy: bool,
    pub operation: Option<Value>,
    /// 被新命令顶掉的那条操作条。只在「新命令被宿主闸门挡下」时用得上：
    /// 拒绝回包要把操作条还原成**真的在跑**的那条，否则界面会说「正在诊断」
    /// 而实际在测速，等测速结束时又会莫名其妙地清空。
    pub op_before_refusal: Option<Value>,
    pub dialog: Option<Value>,
    /// 表单工作流（重命名、连接方式…）。None 表示当前不在表单页。
    pub form: Option<FormState>,
    pub toast: String,
    /// 抽屉里那条响应曲线（`quality-history` 的回包，原样交给页面）。
    pub quality_history: Option<Value>,
    /// 页面发来 ready/theme 后置位：app.js 的 message 监听器已注册，
    /// 此前的快照推送会被它丢掉，所以宿主在 ready 前要周期性重推。
    pub ready: bool,
    pub ready_pushes: u32,
    /// 首页统计卡的 30 分钟摘要内存缓存（键 `line|profile`）。
    /// 快照每秒重建一次，而统计要读采样文件：没有这层缓存就是每秒读一遍盘。
    /// TTL 30 秒与旧版的 `GetTCWebQuality30m` 一致。
    pub quality_cache: std::collections::HashMap<String, (std::time::Instant, Value)>,
    /// 备用线路读数的后台缓存（`measure-backup` 的回包，由采样线程写入）。
    pub standby: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    /// 「添加线路 → 用邀请码加入」的会话。字段名与旧版的 `Pair` 投影一致。
    pub pair: Option<PairSession>,
    /// 「邀请其他电脑」的会话。与 `pair` 分开：两条流程可以各开一次，共用一份状态会互相清掉。
    pub invite: Option<InviteSession>,
    /// 线路 → 服务器的归属缓存（`servers` 命令的回包）。快照每秒重建一次，
    /// 而算一次要遍历所有线路文件：没有缓存就是每秒读一遍盘。TTL 与线路摘要一致。
    pub invite_servers: Option<(std::time::Instant, Vec<Value>)>,
    /// 自动选路证据（`auto-route-list` 的回包）。与归属表同一个理由：每帧读盘没有意义，
    /// 10 秒缓存足够；探测本身是显式动作，补一次快照就能看到新结论。
    pub auto_routes: Option<(std::time::Instant, Value)>,
    /// 连接等待态（A5）。`None` = 没有在等；`Some` = 等名单程序退出后自动连。
    pub pending_connect: Option<PendingConnect>,
    /// A5：用户点了「停止等待」的命令。操作仍在后台跑完；终态回包只更新记录与
    /// 提示，不能清掉之后发起的新操作。
    ///
    /// 按命令名而不是布尔值记：连接还在后台时用户可能已经点了断开，
    /// 连接的终态回包到达时不能让「正在断开」消失。
    pub detached: std::collections::HashSet<String>,
    /// 这台电脑的默认名称（页面第一次打开时填进输入框）。
    pub device_default: String,
}

/// 连接等待态（A5）：名单内交易程序在跑时，用户在确认框里选了「先退出程序」。
///
/// **不是「什么都不做」**。旧版 旧版的行为是：点连接发现交易软件在跑 →
/// 记下目标线路 → 交易软件退出后自动连（`WebPendingConnection` +
/// `ContinueTCWebConnection`）。本版沿用这套语义，只把判据从
/// 「NinjaTrader 在不在跑」换成 r54 已经做好的 `RunningPrograms`（名单内程序）。
///
/// 清掉它的三条路：用户点「取消等待」、超预算（[`PENDING_CONNECT_BUDGET`]）、
/// 或者做了任何别的动作（改线路、断开、进别的页面）——见 `route` 开头那道闸。
#[derive(Debug, Clone)]
pub struct PendingConnect {
    /// 等待期间用户可能改了线路，所以连接前要按这个 id 再 `use` 一次。
    pub line_id: String,
    /// 只用于显示：`PendingConnectionName` 与等待条上的那句话。
    pub line_name: String,
    pub created_at: std::time::Instant,
}

/// 等待预算：与旧版的 `WebPendingBudgetSeconds` 一致（300 秒）。
///
/// 不设预算的等待会变成一个永远不响的承诺：用户关了交易软件又忘了这回事，
/// 半小时后通道突然自己连上，比「等待已结束，请重新选择线路」难解释得多。
pub const PENDING_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(300);

/// 配对会话。页面只读这些字段，**不自己判断阶段**——阶段由宿主推进。
#[derive(Debug, Clone, Default)]
pub struct PairSession {
    pub pair_id: String,
    /// `Creating` / `Verified` / `Preparing` / `Complete` / `Failed`。
    /// 前四个是页面按 `Phase` 决定显示输入框、进度还是结果卡的依据。
    pub phase: String,
    pub stage_label: String,
    pub stage_changed_at: String,
    pub device_name: String,
    pub local_name: String,
    pub node_name: String,
    pub host: String,
    pub expires_at: String,
    pub error_code: String,
    pub error_message: String,
    /// `Retry` / `Reenter` / `ContinueCheck` 等。空 = 只显示说明，不给主按钮。
    pub next_action: String,
    pub epoch: u64,
    /// 邀请码原文。**只留在宿主侧，不投影给页面**：加入这一步要拿它再提交一次申请，
    /// 而它是一份一次性凭据——投影出去就会进页面状态、进截图、进日志。
    /// 页面点「加入」时只发名字，码由这里补上。
    pub code: String,
    /// 离线交接：`true` 时页面走「邀请 → 申请 → 授权」三步，不碰 18443。
    pub offline: bool,
    /// 管理端交来的完整签名邀请（JWS）。在线流程没有它。
    pub offline_invite: String,
    /// 与管理员人工核对过的管理签名指纹。生成申请时原样带回，防止中途被换邀请。
    pub offline_fingerprint: String,
    /// 本机生成的申请原文（公开，交给管理端）。
    pub offline_request: String,
    /// 申请识别码（摘要前 12 位），人工核对用。
    pub pairing_code: String,
    /// 本机登记 id：导入授权时按它找到私钥与申请。
    pub enrollment_id: String,
}

/// 「邀请其他电脑」的会话。页面只读投影，阶段由宿主推进。
///
/// 与 `PairSession` 的关系是**镜像**：那一半是「我要加入别人的线路」，这一半是
/// 「别人要加入我的线路」。两份状态分开存，因为它们可以同时存在（一边加入、
/// 一边邀请），共用一份会互相清掉。
#[derive(Debug, Clone, Default)]
pub struct InviteSession {
    pub server_id: String,
    pub line_id: String,
    /// `Loading` / `Creating` / `Checking`；空 = 设置页（等用户选有效期）。
    pub phase: String,
    /// 离线邀请模式（管理端）。`true` 时结果卡显示「邀请 → 申请 → 授权」三步。
    pub offline: bool,
    /// 服务器签名的邀请本身（JWS）。离线交接交给新电脑的是它，不是 TCI1 码。
    pub invite_jws: String,
    /// 管理签名指纹：与新电脑人工核对的那一串。
    pub fingerprint: String,
    /// 新电脑交回的申请原文（公开）。
    pub offline_request: String,
    /// 交回新电脑的加密授权（一次性，不进快照）。
    pub offline_authorization: String,
    /// 申请里登记的设备名与识别码（核对用）。
    pub offline_device: String,
    pub offline_pairing_code: String,
    pub stage_label: String,
    pub stage_changed_at: String,
    pub invite_id: String,
    /// 邀请码原文。**只留在宿主侧**：投影出去只有截断的 `CodePreview`，
    /// 完整码在用户点「显示/复制」时单独递一次（`Step::Script`）。
    pub code: String,
    /// `Open` / `Consumed` / `Cancelled` / `Expired`。
    pub state: String,
    pub expires_at: String,
    pub device_name: String,
    pub lifetime: i64,
    pub error_code: String,
    pub error_message: String,
    pub next_action: String,
    /// 失败的那条命令（`invite-create` / `invite-status` / `invite-cancel` / `invite-init`）。
    /// 「重试」按钮必须回到同一件事上：重试签发 ≠ 重新作废，不能按按钮文字猜。
    pub retry_command: String,
    pub epoch: u64,
    /// 18443 可达性自检结果（`{Status,Port,Host,CheckedAtUtc}`）。`null` = 还没查过。
    /// 只投影，不做判断：页面按 `Status` 说人话。
    pub reachability: Value,
}

/// 宿主把命令回包合进状态时**允许透传**的键。
///
/// 这是 `main.rs::merge_ui_command_reply` 的唯一来源，而 `finish_op`（本文件）
/// 正是从**状态**里取自己的载荷。表里漏一个键，症状永远是同一句话：
/// **命令跑完了，页面却什么都没发生**——不报错、不超时，就停在「正在处理」。
///
/// 同一类缺陷已经踩过三次，都是真机才发现（页面测试用直构造的回包，绕过了这道合并）：
/// - r36 `servers`：快照里的归属表恒空 → 邀请入口永远灰；
/// - r36 `invite`：长命令回包进不了状态机 → 永远「正在生成邀请码」；
/// - r39 `pairVerify` / `pairJoin`：原生三步加入永远「正在确认邀请码 · 仍在处理」。
///
/// 改完这份表，跑 `ui_reply_whitelist_covers_every_key_finish_op_reads`：
/// 它从**读的那一侧**（`finish_op` 与它调用的 absorb_*）反推该有哪些键。
pub(crate) const UI_REPLY_KEYS: &[&str] = &[
    // 线路/进程/分流/记录/诊断这些「命令自己的业务载荷」。
    // **第八次**：`selected` 漏在白名单外，页面拿不到「当前选中哪条线路」，
    // 于是线路卡片永远不进「使用中」分支——它在等「备用线路读数」（只含**非当前**线路），
    // 单线路时恒为空，卡片一直显示「尚未测量」。测速其实算出了数（写进 `Quality`，
    // 首页那栏会变），卡片纹丝不动 —— 用户看到的就是「点了没反应、这功能是假的」。
    "lines", "selected", "processes", "domains", "changed", "splitMessage", "events", "diagnose",
    // AI 工具名单：这三个数组 + `agents` 状态 + 一句回话必须转交给表单，
    // 否则页面上「点了保存却什么都没变」。
    "builtin", "programs", "sites", "agents", "agentsMessage", "agentsLane",
    // 测速、兼容连接、改名、导出、服务商、入口提示、备份。
    "latencyMs", "measuredAtUtc", "latencyError", "compatibleResult",
    "renameResult", "exportResult", "providers", "entryNote", "backupResult",
    // 交易保护：完整投影 + 解除回包都要落回页面/表单，否则点了按钮没有结果。
    "guard", "guardRemove",
    // `guard-precheck` 的「名单内正在运行的程序」（P0-13）。
    //
    // **这是这份白名单第四次咬人**：r36 `servers`、r36 `invite`、r39 `pairVerify`/`pairJoin`、
    // 本次 `RunningPrograms`。四次症状一模一样——真机上一次都没生效，而单测全绿。
    //
    // 本次的具体后果：漏了这一个键，症状**不是**报错，而是「确认框永远不出现」：启用侧
    // 直接弹 UAC 装规则、连接侧直接接管通道，用户既看不到「请先退出交易软件」，也走不到
    // 「仍要启用/仍要连接」那条路——`absorb_precheck_running` 拿到空数组，静默走「没人跑」分支。
    // 这类缺陷只能在「命令回包 → 合并 → 读」这条缝上测出来：
    // 见 `the_precheck_reply_survives_the_host_side_merge`。
    "RunningPrograms",
    // 自助部署只剩「读指纹」一步（`serverSetup` 随旧向导的完成页一起退役：
    // 现在点「开始部署」落的是部署任务，结论走 `deployment`）。
    "serverProbe", "serverDevices", "serverRevoke", "serverDeviceForget",
    // 卸载服务器通道服务（r66）：预览与执行的回包。漏了它们，页面只会停在
    // 「正在准备卸载…」——又是同一类接缝，所以这次连键带接缝用例一起加。
    "serverUninstallPreview", "serverUninstall",
    // 设备改名（r66）：失败回包也要带自己的键，页面才不会把它当成「整个设备页读不出来」。
    "serverDeviceRename",
    // 「删除这台服务器在本机的部署资料」（r90）：`{ok,serverCleanup:{…,Blocked,Items}}`
    // 与 `{ok,serverCleanupResult:{Removed*,Failed,Message}}`。
    //
    // **第十次同类接缝**：这两条都是 `Step::Sync`，回包同样要过 `merge_ui_command_reply`。
    // 漏了它们，症状是「点了『删除本机部署资料…』什么都没发生」——不弹框、不报错，
    // 因为 `absorb_server_cleanup_preview` 拿到的是没有 `serverCleanup` 的合并态，
    // 于是按「预览读不出来」处理，而失败回包那边也读不到自己的键。
    // 接缝测试：`the_server_cleanup_replies_survive_the_host_side_merge`。
    "serverCleanup", "serverCleanupResult",
    // 补兼容连接（旧版「旧线路维护：增加 TCP」）：`{ok,lineCompatible:{LineId,Port,ServerName,Reused,Message}}`。
    // 这是**第十一次**同一类接缝——漏了它，表单拿到的合并态里没有这个键，
    // 用户看到的就是「点了确认，什么也没发生」。
    "lineCompatible",
    // 出口网卡的读与写共用一个键（r89）：读是「打开页面时拿本机网卡列表」，
    // 写是「保存选了哪一张」。漏了它，页面会永远停在「正在读取本机网卡…」——
    // 命令在毫秒级就跑完了，`finish_op` 却拿不到这份回包。
    "lineNetwork",
    // 邀请入口的归属查询：漏了它，`invite_servers` 拿到的是没有 `servers` 的 status，
    // 于是每条线路都判成「不归你管」，邀请按钮恒灰。
    "servers",
    // 邀请管理（签发/查状态/作废）的四条长命令：`{ok,invite:{Section,Data}}`。
    "invite",
    // 原生三步加入的两条长命令（r39）：`{ok,pairVerify:{…}}` / `{ok,pairJoin:{…}}`。
    // 漏了它们，`webui.pair.phase` 永远是 `Creating`——服务端 401 毫秒就答完了，
    // 页面却一秒一秒数到用户放弃。
    "pairVerify", "pairJoin",
    // 离线交接的三步（r67）：`{ok,pairOffline:{Stage,…}}`。漏了它，新电脑上
    // 「生成申请」和「完成加入」都会停在等待态——白名单第九次同类。
    "pairOffline",
    // `op` 不是命令载荷，而是 `submit_operation` 的调度元数据（`{cmd,phase,…}`）。
    // `finish_op` 要靠它区分「心跳」与「终态」（A5），源码扫描会把它当成读到的键；
    // 登记在这里只是让扫描通过，任何命令回包都**不**应该带它。
    "op",
    // 按记录重试（A6）：`{ok,operationRetry:{Id,Kind,Message}}`。漏了它，重试成功
    // 也只是操作条消失，用户不知道到底重连上没有再。
    "operationRetry",
    // 自动选路（A8）：`{ok,autoRoutes:{NetworkFingerprint,Lines}}`。快照要从合并态里读它，
    // 漏了这条线路卡就永远不显示探测结论。
    "autoRoutes",
    // 自动选路的结果（A8）：`{ok,autoRoute:{...}}`。长命令完成后要弹一句结论。
    "autoRoute",
    // 连接中自动切换（A8 后续）：后台触发，同样要弹一句「换没换、为什么」。
    "autoReroute",
    // 部署中心（A2/A3）：`{ok,deployment:{…}}`。`deployment-*` 全是短命令，
    // 回包要立刻落到表单/任务卡上。**这个键现在就要在**：漏了它，命令真跑完、
    // `finish_op` 拿不到、页面永远转圈且一秒不报错——这个坑已经踩过三次。
    "deployment",
    // 删除预览（A4/r59）：`{ok,deletePreview:{…}}`。
    //
    // **这是白名单第五次咬人**，而且咬的方式最隐蔽：`route` 里的 `fetch` 在生产上是
    // [`merge_ui_command_reply`] 合并后的状态，不是原始命令回包。漏了这个键，预览体
    // 被吞掉，`DeleteDialog` 读不到 `Eligible` 默认 false——真机上点「删除」永远弹
    // 「这条线路现在不能删除」，而单测直接喂原始回包，全绿。
    // 接缝测试：`the_delete_preview_survives_the_host_side_merge`。
    "deletePreview",
    // 删除结果与待清理（A4/r60）：`{ok,deleteResult:{…}}`、`{ok,deleteCleanup:{…}}`、
    // `{ok,deleteCleanupResult:{…}}`。
    //
    // 这里连中三元，症状各不相同，正好说明「白名单漏键」没有单一表现：
    // - 漏 `deleteResult`：删线路后提示永远说「线路已删除」，哪怕文件明明没删掉；
    // - 漏 `deleteCleanup`：快照里待清理列表恒空 → 含私钥的残留文件**静默消失**；
    // - 漏 `deleteCleanupResult`：点「重试清理」后页面一句话都不回。
    // 三条接缝测试：`the_delete_result_survives_the_host_side_merge` /
    // `a_pending_cleanup_survives_the_merge_and_is_projected` /
    // `the_cleanup_retry_reply_survives_the_host_side_merge`。
    "deleteResult", "deleteCleanup", "deleteCleanupResult",
    // 响应曲线（r60 顺手修的旧账）：`{ok,qualityHistory:{…}}`。
    // 它是**第六次**同类缺陷，只是没人把它归进来：抽屉点开一次，曲线恒停在
    // 「正在读取历史…」——命令每次都在毫秒内答完，回包却被合并吞掉。
    // `absorb_reply` 属于 `SYNC_ONLY_READERS`，结构性扫描不覆盖它，只能靠接缝测试：
    // `the_quality_history_reply_survives_the_host_side_merge`。
    // **第九次**：`qualitySummary` 漏在这里，首页「线路响应」永远拿不到 30 分钟统计
    // （后端 58 个采样、中位 122 ms，界面却一直「等待采样」）。
    // 原因是宿主的回包先过 `merge_ui_command_reply`，白名单之外的键全被丢掉，
    // 而 `quality_for` 正是从这份回包里取 `qualitySummary`。
    "qualityHistory", "qualitySummary",
    // 线路动作（A6/r61）：`{ok,lineActions:{ReadError,Actions}}` 与
    // `{ok,lineActionReview:{…}}`。
    //
    // 又一处「快照读的是合并后的状态」：漏了 `lineActions`，快照里每条线路的
    // `Feedback` 恒空、`PendingOperations` 恒空——点过测速、保存过连接方式，
    // 页面却像什么都没发生，连「待核对」都不会出现。
    // 漏了 `lineActionReview`，点「检查结果」后 Toast 与结论都读不到。
    // 接缝测试：`the_line_actions_survive_the_host_side_merge` /
    // `the_line_action_review_survives_the_host_side_merge`。
    "lineActions", "lineActionReview",
    // 界面长操作（A5/A6）：`{ok,operations:{ReadError,Records}}` 与
    // `{ok,operationReview:{…}}`。
    //
    // **第八次同类缺陷**：快照与「查看并处理」都读合并后的状态。漏了 `operations`，
    // 被中断的连接/断开在页面上彻底消失（待核对入口、读错误提示都没有）；漏了
    // `operationReview`，核对完成后一句回话都没有。接缝测试：
    // `the_operation_record_survives_the_host_side_merge` /
    // `the_operation_review_survives_the_host_side_merge`。
    "operations", "operationReview",
    // 管理恢复包（r94）：`{ok,recovery:{Package|ServerId,…}}`。漏了它，页面点
    // 「加密导出」/「解密并登记」都会停在「正在…」——又是同一类接缝。
    "recovery",
    // 操作记录的隐藏/恢复（r96）：`{ok,historyDelete:{deleted,hidden}}`、
    // `{ok,historyRestore:{restored}}`。两条都是同步命令，但宿主下发的
    // 回包是**合并后的状态**；漏了它们，后端确实写了/删了隐藏键，页面却：
    // 删除后不说「已隐藏 N 条」、恢复后行仍挂着「已隐藏（旧版）」。
    "historyDelete", "historyRestore",
];

/// **另一条**合并路径（[`merge_maintenance_reply`]）的透传键，只服务于「还原」。
///
/// 刻意和 [`UI_REPLY_KEYS`] 分开：两条路径的触发条件不同（这条要求回包里先有
/// `restoreResult`），合在一起改一条会牵动另一条。测试里的允许集合是两者的并集
/// 再加失败形状那四个键。
pub(crate) const MAINTENANCE_REPLY_KEYS: &[&str] = &[
    // 还原后的维护投影与它自己的一句结论。
    "maintenance", "restoreResult",
    // 失败形状单独列：这条路径不看 `merge_ui_command_reply` 的 `ok:false` 分支。
    "message", "error", "errorCode", "ok",
];

/// WebView 以完整状态为底，但命令自己的业务载荷与失败形状必须原样保留。
///
/// 调度器尤其依赖 `ok:false` 生成 `op.phase=failed`；诊断结果也不能被状态重建吞掉。
///
/// **它和 [`UI_REPLY_KEYS`] 必须在同一个文件里**：键表与合并逻辑分居两个模块时，
/// 「加了一个键但合并路径没跟上」这类漂移没人看得见。搬到这里之后，
/// [`mod tests`] 可以直接做「原始命令回包 → 真实合并 → reader 读得到」的端到端断言
/// （`the_precheck_reply_survives_the_host_side_merge`），不必再各自造假 fetch。
///
/// 宿主侧唯一调用点：`main.rs::ui_handler`（`fetch` 的实现）。
pub(crate) fn merge_ui_command_reply(state: &mut Value, reply: &Value) {
    if let Some(o) = state.as_object_mut() {
        for key in UI_REPLY_KEYS {
            if let Some(value) = reply.get(*key) {
                o.insert((*key).to_string(), value.clone());
            }
        }
        if reply.get("ok").and_then(Value::as_bool) == Some(false) {
            for key in ["ok", "error", "errorCode", "message"] {
                if let Some(value) = reply.get(key) {
                    o.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    merge_maintenance_reply(state, reply);
}

/// WebView 回包以完整状态为底，但还原自己的结果字段必须原样保留。
/// 否则管道测试全过、页面却收不到 message/errorCode/restoreResult，最容易形成假成功。
///
/// 键在 [`MAINTENANCE_REPLY_KEYS`]（和 [`UI_REPLY_KEYS`] **分两份**：这条路径的
/// 触发条件不同，混成一份以后改一条会牵动另一条）。这里不再内联数组。
pub(crate) fn merge_maintenance_reply(state: &mut Value, reply: &Value) {
    if reply.get("restoreResult").is_none() {
        return;
    }
    if let Some(obj) = state.as_object_mut() {
        for key in MAINTENANCE_REPLY_KEYS {
            if let Some(value) = reply.get(*key) {
                obj.insert((*key).to_string(), value.clone());
            }
        }
    }
}

impl WebUi {
    pub fn new() -> Self {
        Self {
            page: "home".into(),
            // 与旧版一致：默认用机器名，用户可以改；改过就不再覆盖。
            device_default: std::env::var("COMPUTERNAME").unwrap_or_default(),
            ..Default::default()
        }
    }

    fn bump(&mut self) {
        self.ack += 1;
    }

    fn toast(&mut self, message: &str) {
        self.toast = message.to_string();
    }

    /// 断开确认对话框。**只按当次 status 的 Guard 说话**（P0-11）：
    /// - `Protected` 才允许说「仍会阻止直连」，且必须带核验时龄；
    /// - `Unprotected` 明确说断开后可以直连，并区分用户主动解除/没有需要保护的程序；
    /// - `Unknown` 绝不说保护生效，只说无法确认。
    fn disconnect_dialog(fetch: &dyn Fn(&str) -> Value) -> Value {
        let st = fetch(r#"{"cmd":"status"}"#);
        let guard = st.get("Guard").and_then(Value::as_str).unwrap_or("Unknown");
        let reason = st
            .get("GuardEvidence")
            .and_then(|e| e.get("Reason"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let age = st.get("GuardEvidenceAge").and_then(Value::as_str).unwrap_or("");
        let (body, note) = if guard == "Protected" {
            (
                "行情与下单会立刻中断；交易程序直连保护已启用；有持仓请先在交易软件处理。".to_string(),
                if age.is_empty() {
                    "断开后仍会阻止名单程序直连（依据最近一次核验）。需要重新连接时，请重新选择线路并点击连接。".to_string()
                } else {
                    format!("断开后仍会阻止名单程序直连（依据{age}）。需要重新连接时，请重新选择线路并点击连接。")
                },
            )
        } else if guard == "Unprotected" {
            let note = match reason {
                "UserRemoved" => {
                    "交易保护已解除；下次连接会重新启用。断开后名单中的交易程序将可以直接上网。"
                }
                "EmptyProgramList" | "NoTradePrograms" => {
                    "当前名单里没有需要保护的程序；断开后不存在名单程序被放行的额外风险。"
                }
                _ => "断开后名单中的交易程序将可以直接上网；重新连接后会重新核验保护。",
            };
            (
                "行情与下单会立刻中断；交易保护未启用；有持仓请先在交易软件处理。".to_string(),
                note.to_string(),
            )
        } else {
            (
                "行情与下单会立刻中断；交易保护状态无法确认；有持仓请先在交易软件处理。".to_string(),
                "断开后无法确认名单程序是否仍被阻止；重新连接或运行诊断后再判断。".to_string(),
            )
        };
        json!({
            "Id": "disconnect-confirm",
            "Title": "断开连接？",
            "Body": body,
            "Note": note,
            "Confirm": "断开连接",
            "Cancel": "继续交易",
            "Danger": true,
            "Details": "",
            "Progress": false,
            "Scope": "disconnect",
            "Target": "",
        })
    }

    /// 交易程序仍在运行时的连接前置确认（P0-13）。
    fn guard_running_dialog(running: &[String], target: &str) -> Value {
        json!({
            "Id": "guard-running-confirm",
            "Title": "交易程序正在运行",
            "Body": format!("名单中的交易程序正在运行：{}。建议先退出它们，再连接通道。", running.join("、")),
            "Note": "如仍要连接：已建立的连接不会被切断；阻断只影响之后的新连接。",
            "Confirm": "仍要连接",
            "Cancel": "先退出程序",
            "Danger": true,
            "Details": "",
            "Progress": false,
            "Scope": "guard-running",
            "Target": target,
        })
    }

    /// 「现在重新启用」时交易程序仍在运行的确认（P0-13 的**启用侧**）。
    ///
    /// 形状与 [`Self::guard_running_dialog`] 一致，差别只在语义：这里是「要写系统了」，
    /// 所以 `Confirm` 是「仍要启用」。`Note` 复用 `guard::RUNNING_ACK_NOTE`——
    /// 那句安全说明在全仓只有一处定义，界面与命令行说的一定是同一句。
    fn guard_enable_running_dialog(running: &[String]) -> Value {
        json!({
            "Id": "guard-enable-confirm",
            "Title": "交易程序正在运行",
            "Body": format!(
                "名单中的交易程序正在运行：{}。请先退出它们，再启用交易保护。",
                running.join("、")
            ),
            "Note": crate::guard::RUNNING_ACK_NOTE,
            "Confirm": "仍要启用",
            "Cancel": "先退出程序",
            "Danger": true,
            "Details": "",
            "Progress": false,
            "Scope": "guard-enable",
            "Target": "",
        })
    }

    /// 把一条页面消息翻译成宿主动作。`fetch` 是同步取内部状态的入口
    /// （`{"cmd":"status"}` 等），daily/agents 这类要按出口成员反查的意图需要它。
    /// 入站消息门控（D，r56）：返回 `true` 表示这条消息被丢弃。
    ///
    /// 对齐 旧版的 `InvokeTCWebMessage`（`ui/WebShell.ps1:927-945`）：
    /// 长度上限、`Sequence` 单调、对话框 `Id` 必须对得上、表单 `Generation` 必须对得上。
    ///
    /// 两条**放宽**是故意的，都写在对应分支上：`Sequence` / `Id` / `Generation`
    /// 缺失时放行——真实前端每条都带（`web/app.js` 的 `post` 与 `form` 分支），
    /// 缺了只可能是内部调用或测试夹具；真按「缺就拒」处理，会让内部调用莫名其妙失效。
    fn reject_inbound(&mut self, raw: &str, msg: &Value) -> bool {
        let kind = msg.get("Type").and_then(Value::as_str).unwrap_or("");
        if kind.is_empty() {
            return true;
        }
        // 非 form 消息 4 KiB 足够（旧版同阈值）。form 放宽：AI 工具名单一次能带几百行。
        //
        // `pairOnline` / `invite` 单独放宽到 64 KiB：离线交接的加密授权 JWE 实测约
        // 4 KB（4000+ 字符），刚好越过 4 KiB。被这道闸丢掉时页面**不会报错**——
        // 点击被静默吞掉，卡片停在原地，真机首轮就是卡在这里。邀请码本身最长 2 KB，
        // 64 KiB 仍是一个明确的硬上限，不是无限制。
        let limit = if kind == "form" || matches!(kind, "pairOnline" | "invite") {
            64 * 1024
        } else {
            4096
        };
        if raw.len() > limit {
            return true;
        }
        // 页面重载后 `sequence` 从 1 重新开始：`ready` 是「脚本刚活过来」的信号，
        // 这时必须把入站序号归零，否则整页消息会被历史序号全部挡掉——页面直接死。
        // 这一条比旧版多做一步：那边页面几乎不重载，本版 WebView2 会自己恢复。
        if kind == "ready" {
            self.inbound_seq = 0;
        }
        if let Some(value) = msg.get("Sequence") {
            let Some(seq) = value.as_u64() else {
                return true;
            };
            if seq == 0 || seq > 2_147_483_647 || seq <= self.inbound_seq {
                return true;
            }
            self.inbound_seq = seq;
        }
        // 对话框事件必须指向**当前这个框**：用户已经关掉/换成另一个框之后，
        // 过期的事件不许把现在的框关掉。旧版同判据（`$m.Id -cne $script:WebDialogId`）。
        if kind == "confirmDialog" || kind == "cancelDialog" {
            let want = self
                .dialog
                .as_ref()
                .and_then(|dialog| dialog.get("Id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let got = msg.get("Id").and_then(Value::as_str).unwrap_or("");
            if !got.is_empty() && want != got {
                return true;
            }
        }
        // 表单事件必须属于**当前这一代**表单：结构已经重建过，旧事件落到新表单上
        // 会改错字段（旧版的 `Generation` 就是为这件事）。
        //
        // **只挡字段编辑（`Event != "click"`），按钮点击放行**：状态推送有 2 秒节流，
        // 用户完全可能在页面还没收到新快照时连点两下（第一下让 `restructure()`
        // 把 generation 加了 1），这时点击带的必然是上一代——挡掉就是「点了没反应」。
        // 而点击最坏只是重复一次，且各分支本来就有确认条/幂等兜底。
        if kind == "form" {
            let event = msg.get("Event").and_then(Value::as_str).unwrap_or("");
            if event != "click" {
                let want = self.form.as_ref().map(|form| form.generation).unwrap_or(0);
                let got = msg.get("Generation").and_then(Value::as_u64).unwrap_or(0);
                if got != 0 && want != got {
                    return true;
                }
            }
        }
        false
    }

    pub fn route(&mut self, raw: &str, fetch: &dyn Fn(&str) -> Value) -> Vec<Step> {
        let mut steps: Vec<Step> = Vec::new();
        // 长度闸排在解析之前：1 MiB 的 JSON 光是解析就要几十毫秒，先挡掉再谈别的。
        if raw.len() > 1024 * 1024 {
            self.bump();
            return steps;
        }
        let msg: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
        if self.reject_inbound(raw, &msg) {
            // **丢弃也要推进 `ack`**：页面用 `State.Ack >= Sequence` 判「我发的意图
            // 处理完了吗」，静默丢一条会让按钮一直转圈。旧版只对 `pairOnline` /
            // `invite` 单独做了「拒绝也要应答」，这里统一做，免得以后每类再记一遍。
            if let Some(seq) = msg.get("Sequence").and_then(Value::as_u64) {
                self.ack = self.ack.max(seq);
            }
            self.bump();
            return steps;
        }
        let kind = msg.get("Type").and_then(Value::as_str).unwrap_or("").to_string();
        let id = msg.get("Id").and_then(Value::as_str).unwrap_or("").to_string();
        let value = msg.get("Value").and_then(Value::as_str).unwrap_or("").to_string();
        // 等待态只对「继续等」有意义。用户做了任何别的动作（改线路、断开、翻页、
        // 重新连接）都视为放弃等待——否则会出现「我早就换线了，它却自己连了原来那条」。
        // 白名单里这六个不改变意图：其中 `cancelDialog` 恰恰是**进入**等待态的那条路。
        const PENDING_KEEP: [&str; 6] =
            ["ready", "refresh", "theme", "details", "cancelDialog", "cancelWaiting"];
        if !PENDING_KEEP.contains(&kind.as_str()) {
            self.pending_connect = None;
        }
        match kind.as_str() {
            "ready" | "refresh" | "theme" | "details" | "cancelDialog" => {
                if kind == "cancelDialog" {
                    // 「先退出程序」不是「什么都不做」：把对话框里那条线路接成等待态，
                    // 名单程序退出后自动连（A5）。别的对话框（删除/断开/离页）取消就是取消。
                    let dialog = self.dialog.take();
                    if let Some(dialog) = dialog {
                        if dialog.get("Scope").and_then(Value::as_str) == Some("guard-running") {
                            let target = dialog
                                .get("Target")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let name = if target.is_empty() {
                                String::new()
                            } else {
                                line_name(fetch, &target)
                            };
                            self.pending_connect = Some(PendingConnect {
                                line_id: target,
                                line_name: name,
                                created_at: std::time::Instant::now(),
                            });
                            self.toast("等交易软件退出后自动连接");
                        }
                    }
                }
                // ready/theme 是页面脚本存活的第一个信号：此后快照只在事件时推。
                self.ready = true;
                self.bump();
            }
            "pairOnline" => {
                // 三步流程的宿主侧：开新会话 / 校验邀请码 / 加入 / 取消。
                let phase = msg.get("Phase").and_then(Value::as_str).unwrap_or("");
                let code = msg.get("Code").and_then(Value::as_str).unwrap_or("").trim().to_string();
                let name = msg.get("Name").and_then(Value::as_str).unwrap_or("").trim().to_string();
                match phase {
                    // 开新会话：清掉上一轮结果，页面才会显示输入框而不是结果卡。
                    "BeginCode" | "BeginChoose" => {
                        // 页面只管发意图，翻页是宿主的事：不切页的话用户会停在原页，
                        // 点了「用邀请码加入」却什么都没变。
                        self.page = "add-line".to_string();
                        self.pair = None;
                        self.bump();
                    }
                    "Verify" => {
                        if code.is_empty() {
                            let mut session = self.pair.clone().unwrap_or_default();
                            session.phase = "Failed".into();
                            session.error_code = "InvalidOnlineCode".into();
                            session.error_message = "请粘贴完整的一次性邀请码。".into();
                            session.next_action = "Reenter".into();
                            self.pair = Some(session);
                            self.bump();
                        } else {
                            let epoch = self.pair.as_ref().map(|p| p.epoch).unwrap_or(0) + 1;
                            let pair_id = crate::pairing::random_uuid_v4();
                            self.pair = Some(PairSession {
                                pair_id: pair_id.clone(),
                                phase: "Creating".into(),
                                stage_label: "正在确认邀请码".into(),
                                stage_changed_at: crate::pairing::rfc3339_micros(
                                    crate::model::now_epoch_secs_u64() as i64,
                                ),
                                device_name: name.clone(),
                                // 加入那一步要用同一个码再提交一次申请；页面不会重发它。
                                code: code.clone(),
                                epoch,
                                ..Default::default()
                            });
                            // 读邀请要联网：走长命令通道，页面在此期间显示「正在确认」。
                            // `pairId` 是**轮次标记**：连续校验两个码时，A 的回包绝不能落进 B 的会话
                            // （否则会把 A 的节点名/Host 显示在 B 上，还把 B 标成已校验）。
                            steps.push(Step::Long(json_cmd(
                                "pair-verify",
                                &[
                                    ("code", json!(code)),
                                    ("device", json!(name)),
                                    ("pairId", json!(pair_id)),
                                ],
                            )));
                            self.bump();
                        }
                    }
                    "Join" => {
                        // 这一步真的会把邀请用掉：提交申请会在服务器上登记这台设备。
                        // 所以只允许从「校验通过」那一档进来，别的一律如实拒绝、不发命令。
                        let mut session = self.pair.clone().unwrap_or_default();
                        // 页面传来的 `Name` 是用户在「线路名（可以改）」里改过的名字。
                        session.local_name = name.clone();
                        if session.phase != "Verified" || session.code.is_empty() {
                            session.phase = "Failed".into();
                            session.error_code = "InvalidOnlineCode".into();
                            session.error_message =
                                "邀请码还没有校验通过，请先重新校验一次再加入。".into();
                            // 必须给具体动作：留空会被页面兜底成「重试」，而重试只会得到同一句话。
                            session.next_action = "Reenter".into();
                            self.pair = Some(session);
                            self.bump();
                        } else {
                            let stage_at =
                                crate::pairing::rfc3339_micros(crate::model::now_epoch_secs_u64() as i64);
                            session.phase = "Preparing".into();
                            session.stage_label = "正在提交设备申请并生成线路".into();
                            session.stage_changed_at = stage_at;
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                            let device = session.device_name.clone();
                            let code = session.code.clone();
                            let pair_id = session.pair_id.clone();
                            self.pair = Some(session);
                            // 提交申请要联网、要生密钥、还要落两份文件：走长命令通道。
                            steps.push(Step::Long(json_cmd(
                                "pair-join",
                                &[
                                    ("code", json!(code)),
                                    ("device", json!(device)),
                                    ("name", json!(name)),
                                    ("pairId", json!(pair_id)),
                                ],
                            )));
                            self.bump();
                        }
                    }
                    // 离线交接第一步：校验管理端交来的完整邀请。**不联网**——
                    // 新电脑连不上 18443 正是走这条路的理由。
                    "OfflineInspect" => {
                        if code.is_empty() {
                            let mut session = self.pair.clone().unwrap_or_default();
                            session.phase = "Failed".into();
                            session.error_code = "InvalidOfflineInvite".into();
                            session.error_message = "请粘贴管理端复制的完整离线邀请。".into();
                            session.next_action = "Reenter".into();
                            self.pair = Some(session);
                            self.bump();
                        } else {
                            let epoch = self.pair.as_ref().map(|p| p.epoch).unwrap_or(0) + 1;
                            let pair_id = crate::pairing::random_uuid_v4();
                            self.pair = Some(PairSession {
                                pair_id: pair_id.clone(),
                                phase: "Creating".into(),
                                stage_label: "正在校验离线邀请".into(),
                                stage_changed_at: crate::pairing::rfc3339_micros(
                                    crate::model::now_epoch_secs_u64() as i64,
                                ),
                                device_name: name.clone(),
                                offline: true,
                                offline_invite: code.clone(),
                                epoch,
                                ..Default::default()
                            });
                            steps.push(Step::Long(json_cmd(
                                "pair-offline-inspect",
                                &[("invite", json!(code)), ("pairId", json!(pair_id))],
                            )));
                            self.bump();
                        }
                    }
                    // 第二步：在本机生成申请。指纹必须是上一步读出来、并经人工核对的那一串。
                    "OfflineRequest" => {
                        let mut session = self.pair.clone().unwrap_or_default();
                        if !session.offline
                            || session.phase != "OfflineReady"
                            || session.offline_fingerprint.is_empty()
                        {
                            session.phase = "Failed".into();
                            session.error_code = "InvalidOfflineInvite".into();
                            session.error_message = "离线邀请还没有校验通过，请先重新读取一次。".into();
                            session.next_action = "Reenter".into();
                            self.pair = Some(session);
                            self.bump();
                        } else if session.device_name.trim().is_empty() {
                            session.phase = "Failed".into();
                            session.error_code = "InvalidDeviceName".into();
                            session.error_message = "请填写这台电脑的名称（1–64 个字符）。".into();
                            session.next_action = "FixName".into();
                            self.pair = Some(session);
                            self.bump();
                        } else {
                            session.phase = "Creating".into();
                            session.stage_label = "正在生成设备申请".into();
                            session.stage_changed_at = crate::pairing::rfc3339_micros(
                                crate::model::now_epoch_secs_u64() as i64,
                            );
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                            let pair_id = session.pair_id.clone();
                            let invite = session.offline_invite.clone();
                            let fingerprint = session.offline_fingerprint.clone();
                            let device = session.device_name.clone();
                            self.pair = Some(session);
                            steps.push(Step::Long(json_cmd(
                                "pair-offline-request",
                                &[
                                    ("invite", json!(invite)),
                                    ("fingerprint", json!(fingerprint)),
                                    ("device", json!(device)),
                                    ("pairId", json!(pair_id)),
                                ],
                            )));
                            self.bump();
                        }
                    }
                    // 第三步：导入管理端交回的加密授权。`Code` 是授权密文本身。
                    "OfflineComplete" => {
                        let mut session = self.pair.clone().unwrap_or_default();
                        if session.phase != "OfflineRequested"
                            || session.enrollment_id.is_empty()
                            || code.is_empty()
                        {
                            session.phase = "Failed".into();
                            session.error_code = "InvalidAuthorization".into();
                            session.error_message =
                                "还没有生成申请或没有粘贴授权，请按顺序完成上一步。".into();
                            session.next_action = "Retry".into();
                            self.pair = Some(session);
                            self.bump();
                        } else {
                            session.local_name = name.clone();
                            session.phase = "Preparing".into();
                            session.stage_label = "正在导入授权并生成线路".into();
                            session.stage_changed_at = crate::pairing::rfc3339_micros(
                                crate::model::now_epoch_secs_u64() as i64,
                            );
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                            let pair_id = session.pair_id.clone();
                            let enrollment = session.enrollment_id.clone();
                            self.pair = Some(session);
                            steps.push(Step::Long(json_cmd(
                                "pair-offline-complete",
                                &[
                                    ("enrollmentId", json!(enrollment)),
                                    ("authorization", json!(code)),
                                    ("name", json!(name)),
                                    ("pairId", json!(pair_id)),
                                ],
                            )));
                            self.bump();
                        }
                    }
                    // 复制申请：申请是公开资料，但走宿主剪贴板可以避免页面
                    // 因 CSP/权限差异复制失败；文本本身不改变任何状态。
                    "CopyRequest" => {
                        let text = self
                            .pair
                            .as_ref()
                            .map(|session| session.offline_request.clone())
                            .unwrap_or_default();
                        if text.is_empty() {
                            self.toast("还没有生成申请，请先读取邀请并生成。");
                        } else {
                            match crate::clipboard::set_text(&text) {
                                Ok(()) => self.toast("申请已复制，交给管理电脑"),
                                Err(message) => self.toast(&message),
                            }
                        }
                        self.bump();
                    }
                    "Cancel" | "Reset" => {
                        // 取消/重置回到线路页：留在一个空白的添加页会让人以为还能继续。
                        self.page = "lines".to_string();
                        self.pair = None;
                        self.bump();
                    }
                    _ => {}
                }
            }
            "qualityHistory" => {
                // 打开抽屉/切时间范围时才要曲线；Close 表示抽屉已关，把旧数据丢掉。
                if value == "Close" || id.is_empty() {
                    self.quality_history = None;
                } else {
                    self.quality_history = Some(json!({
                        "NodeId": id, "Window": value, "Loading": true, "Reason": "", "Series": [],
                    }));
                    steps.push(Step::Sync(json_cmd(
                        "quality-history",
                        &[("id", json!(id)), ("window", json!(value))],
                    )));
                }
                self.bump();
            }
            "navigate" => {
                let page = msg.get("Page").and_then(Value::as_str).unwrap_or("home");
                self.page = match page {
                    "home" | "lines" | "apps" | "settings" => page.to_string(),
                    _ => "home".to_string(),
                };
                // 导航就是「离开这一页」。表单从前被无条件留着，于是面包屑
                // 「← 返回首页」和左侧导航点下去什么都不发生——前端按 `state.Form`
                // 优先渲染，页面照旧画着表单。自己搭服务器第 0 步没有「关闭」按钮，
                // 用户就被关在那一页里（r84 真机验收抓到的）。
                //
                // **有未保存改动的表单不关**（AI 工具名单的 A9 离页保护）：那种页面
                // 关掉等于静默丢改动，所以仍然留着、由它自己显示「已改 N 项」。
                if self.form.as_ref().and_then(FormState::leave_warning).is_none() {
                    self.form = None;
                }
                self.bump();
            }
            "connect" => {
                // P0-13：连接前先做一次只读预检。名单内交易程序还在跑时，
                // 先让用户退出；坚持继续也要说清「已建立的连接不会被切断」。
                // 预检本身不写任何东西、不弹 UAC。
                let precheck = fetch(&json_cmd("guard-precheck", &[]));
                let running = absorb_precheck_running(&precheck);
                if !running.is_empty() {
                    self.dialog = Some(Self::guard_running_dialog(&running, &id));
                    self.bump();
                } else {
                    if !id.is_empty() {
                        steps.push(Step::Sync(json_cmd("use", &[("id", json!(id))])));
                    }
                    self.begin_op("Connect", &id, "正在连接", "connect");
                    steps.push(Step::Long(json_cmd("connect", &[])));
                }
            }
            "disconnect" => {
                // T-04：断开必须先问一次。旧版的宿主也是先弹确认再执行，
                // 页面这一侧只发意图；不弹就是「点一下行情就断了」。
                // P0-11：正文/说明必须取当前 Guard——「保护仍生效」只在真的核验过时才许说。
                self.dialog = Some(Self::disconnect_dialog(fetch));
                self.bump();
            }
            "testLine" => {
                if !id.is_empty() {
                    self.begin_op("Test", &id, "正在测速", "measure-latency");
                    steps.push(Step::Long(json_cmd(
                        "measure-latency",
                        &[("lineId", json!(id))],
                    )));
                } else {
                    self.bump();
                }
            }
            "delete" => {
                // A4 第一轮：先做只读预览，再决定给不给「删除」按钮。
                // 预览本身读失败时**不落回旧路径**——没有结论就不该出现可点的删除。
                let preview = fetch(&json_cmd("delete-preview", &[("id", json!(id))]));
                self.dialog = Some(delete_dialog(&preview, &id));
                self.bump();
            }
            "confirmDialog" => {
                let dialog = self.dialog.take().unwrap_or(Value::Null);
                let scope = dialog.get("Scope").and_then(Value::as_str).unwrap_or("");
                let target = dialog.get("Target").and_then(Value::as_str).unwrap_or("");
                if scope == "delete" && !target.is_empty() {
                    steps.push(Step::Sync(json_cmd("remove", &[("id", json!(target))])));
                }
                if scope == "guard-running" {
                    if !target.is_empty() {
                        steps.push(Step::Sync(json_cmd("use", &[("id", json!(target))])));
                    }
                    self.begin_op("Connect", target, "正在连接", "connect");
                    steps.push(Step::Long(json_cmd("connect", &[])));
                }
                if scope == "guard-enable" {
                    // 用户看过「请先退出程序」与那句安全说明后仍要启用：带着确认标记去装。
                    // `acknowledgeRunning` 是宿主认的唯一凭据——闸门在 guard 模块里。
                    self.begin_op("GuardEnable", "", "正在重新启用交易保护", "guard-install");
                    steps.push(Step::Long(json_cmd(
                        "guard-install",
                        &[("acknowledgeRunning", json!(true))],
                    )));
                }
                if scope == "agents-leave" {
                    // 用户选了「放弃并返回」：这时候才真的丢草稿。
                    self.form = None;
                }
                if scope == "history-delete" {
                    if let Some(form) = self.form.as_mut() {
                        let keys = form.take_history_pending_keys();
                        if !keys.is_empty() {
                            steps.push(Step::Sync(json_cmd(
                                "history-delete",
                                &[("keys", json!(keys))],
                            )));
                            // 隐藏后立刻重读：页面不能还挂着刚刚被隐藏的那几行。
                            steps.push(Step::Sync(json_cmd("history", &[])));
                            form.history_checked.clear();
                        }
                    }
                }
                if scope == "server-cleanup" && !target.is_empty() {
                    // 用户看过「要删哪些本机资料」之后才真的删。判据在执行侧**再判一次**
                    // （预览可能已经是几分钟前的事），所以这里只管把意图发出去。
                    steps.push(Step::Sync(json_cmd(
                        "server-cleanup",
                        &[("id", json!(target))],
                    )));
                }
                if scope == "deploy-identity" {
                    // 用户核对了指纹并决定首次信任：现在才把密码交给宿主。
                    // 取消（`cancelDialog`）什么都不发——「关闭窗口不会登录」是承诺。
                    if let Some(form) = self.form.as_mut() {
                        steps.extend(form.deploy_start_steps());
                    }
                }
                if scope == "disconnect" {
                    self.begin_op("Disconnect", "", "正在断开", "disconnect");
                    steps.push(Step::Long(json_cmd("disconnect", &[])));
                }
                self.bump();
            }
            "setHomeLine" => {
                if !id.is_empty() {
                    steps.push(Step::Sync(json_cmd("use", &[("id", json!(id))])));
                }
                self.bump();
            }
            "setProfile" => {
                // 三档都要真的发出去：`Auto` 不是「暂不支持」，它是把偏好清空
                // （后端存 `transport = None`），让连接采用这条线路**已验证**的方式。
                let transport = match value.as_str() {
                    "Udp" => "udp",
                    "Tcp" => "tcp",
                    "Auto" => "auto",
                    _ => "",
                };
                if !id.is_empty() && !transport.is_empty() {
                    steps.push(Step::Sync(json_cmd(
                        "set-transport",
                        &[
                            ("id", json!(id)),
                            ("transport", json!(transport)),
                            // 界面发起：宿主据此写一条动作记录，卡片上才有结果可贴。
                            // 命令行 `--set-transport` 不带这个标记，不产生卡片反馈。
                            ("source", json!("line-action")),
                        ],
                    )));
                }
                self.bump();
            }
            "daily" => {
                let member = daily_member(&fetch, &value);
                match member {
                    Some(member) => steps.push(Step::Sync(json_cmd(
                        "exit-set",
                        &[("which", json!("daily")), ("member", json!(member))],
                    ))),
                    None => self.toast("这个日常上网走向当前不可选"),
                }
                self.bump();
            }
            "agents" => {
                // 应用页那一行：立即落盘（只改走向，不动名单）。
                // 页面传的是首字母大写（`state.Agents` = Daily/Trade），宿主要大小写不敏感。
                if !value.is_empty() {
                    steps.push(Step::Sync(json_cmd("agents-lane", &[("Value", json!(value))])));
                }
                self.bump();
            }
            "startup" => {
                let on = msg.get("Value").and_then(Value::as_bool).unwrap_or(false);
                steps.push(Step::Sync(json_cmd("settings", &[("autoStart", json!(on))])));
                self.bump();
            }
            "setting" => {
                let name = msg.get("Name").and_then(Value::as_str).unwrap_or("");
                let on = msg.get("Value").and_then(Value::as_bool).unwrap_or(false);
                match name {
                    "AutoConnectOnLogin" => {
                        steps.push(Step::Sync(json_cmd("settings", &[("autoConnect", json!(on))])));
                    }
                    "AutoTrustFirstConnection" => {
                        steps.push(Step::Sync(json_cmd("settings", &[("autoTrust", json!(on))])));
                    }
                    // 线路变差提醒：关掉后首页只保留质量数字，不再弹横幅、不降级标题。
                    "QualityWarning" => {
                        steps.push(Step::Sync(json_cmd("settings", &[("qualityWarning", json!(on))])));
                    }
                    _ => {}
                }
                self.bump();
            }
            "closeBehavior" => {
                let tray = value == "Tray";
                steps.push(Step::Sync(json_cmd("settings", &[("closeToTray", json!(tray))])));
                self.bump();
            }
            // 表单工作流：旧版前端的线路抽屉里真实存在的两个入口。
            // 打开表单不改业务，真正的写入仍由 `form` 事件的命令完成。
            "rename" => {
                match find_line(&fetch, &id) {
                    Some(l) => {
                        let name = l.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                        self.form = Some(FormState::rename(&id, &name));
                    }
                    None => self.toast("找不到这条线路，请刷新后重试"),
                }
                self.bump();
            }
            "lineSettings" => {
                match find_line(&fetch, &id) {
                    Some(l) => {
                        let name = l.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                        let endpoint =
                            l.get("endpoint").and_then(Value::as_str).unwrap_or("").to_string();
                        let method = match l.get("transport").and_then(Value::as_str) {
                            Some("tcp") => "Tcp",
                            _ => "Udp",
                        };
                        self.form = Some(FormState::line_settings(&id, &name, &endpoint, method));
                        // 打开就现读一次本机网卡：列表与「当前默认出口」都是现场事实，
                        // 不能拿快照里上一帧的值（拔了网线之后那一帧就是假的）。
                        steps.push(Step::Sync(json_cmd("line-network", &[("Id", json!(id))])));
                    }
                    None => self.toast("找不到这条线路，请刷新后重试"),
                }
                self.bump();
            }
            "form" => {
                let event = msg.get("Event").and_then(Value::as_str).unwrap_or("");
                // 返回/完成会直接关掉表单。草稿式表单（AI 工具名单）一旦关了，
                // 「已改 N 项」就没了下文——先问一句，别让改动静默消失。
                // 旧版对应的是 `AgentLeaveTarget`，这里只拦必需的那一页。
                if event == "click" && (id == "back" || id == "done") {
                    if let Some(warning) = self.form.as_ref().and_then(FormState::leave_warning) {
                        self.dialog = Some(json!({
                            "Id": "agents-leave-confirm",
                            "Title": "改动没有保存",
                            "Body": warning,
                            "Note": "点「保存」之后才会生效；现在返回就是放弃这些改动。",
                            "Confirm": "放弃并返回",
                            "Cancel": "继续编辑",
                            "Danger": true,
                            "Details": "",
                            "Progress": false,
                            "Scope": "agents-leave",
                            "Target": "",
                        }));
                        self.bump();
                        return Vec::new();
                    }
                }
                let steps = match self.form.as_mut() {
                    Some(f) => f.event(&msg),
                    None => Vec::new(),
                };
                // 删除操作记录要二次确认（不可逆）。表单只发出「请求」，
                // 弹框归宿主——和部署身份那条走同一套 `dialog`。
                if let Some(count) = self
                    .form
                    .as_mut()
                    .and_then(FormState::take_history_delete_request)
                {
                    let dialog = self
                        .form
                        .as_ref()
                        .map(|form| form.history_delete_dialog(count));
                    self.dialog = dialog;
                }
                // 返回/取消/完成只关表单，不发命令；页面靠 Form=null 回到线路页。
                //
                // `done` 是部署表单的「完成/关闭」：它不能复用 `back`——PageActions 里
                // 已经有一个 `back`，两个同 id 的按钮会让点击落到错误的那一个上。
                if event == "click" && (id == "back" || id == "done") {
                    self.form = None;
                }
                self.bump();
                return steps;
            }
            // M2 工具页：记录是只读列表，诊断是长命令。两者共用表单通道。
            "history" => {
                self.form = Some(FormState::history());
                steps.push(Step::Sync(json_cmd("history", &[])));
                self.bump();
            }
            "diagnostics" => {
                self.form = Some(FormState::diagnose());
                self.begin_op("Diagnose", "", "正在诊断", "diagnose");
                steps.push(Step::Long(json_cmd("diagnose", &[])));
            }
            // 显式重新核验：长命令（一次 UAC + 一次 WFP 读回）。失败回包会由
            // finish_op 带回同一页；这里绝不把「点了按钮」当「已重新核验」。
            "guardVerify" => {
                self.begin_op("GuardVerify", "", "正在核验交易保护", "guard-verify");
                steps.push(Step::Long(json_cmd("guard-verify", &[])));
            }
            // 「现在重新启用」：与「重新核验」**不是**一回事——`guard-verify` 只读，
            // 这一步会真的写系统（装/修规则）。只给 `Unprotected{UserRemoved}` 用：
            // 用户亲手关掉的东西，得能亲手打开，而不是只能等下次连接。
            //
            // P0-13：按下去之前先做与连接侧同一条只读预检。名单程序还在跑就先让用户退出；
            // 这一步**不发命令**，因为装了新规则也挡不住已经建立的连接——直接弹 UAC
            // 会让人误以为「一装就立刻生效」。
            "guardEnable" => {
                let precheck = fetch(&json_cmd("guard-precheck", &[]));
                let running = absorb_precheck_running(&precheck);
                if !running.is_empty() {
                    self.dialog = Some(Self::guard_enable_running_dialog(&running));
                    self.bump();
                } else {
                    self.begin_op("GuardEnable", "", "正在重新启用交易保护", "guard-install");
                    steps.push(Step::Long(json_cmd("guard-install", &[])));
                }
            }
            "maintenance" => {
                self.form = Some(FormState::maintenance());
                steps.push(Step::Sync(json_cmd("maintenance-status", &[])));
                self.bump();
            }
            // 服务器一览（C7）：只读，本地记录。与「服务器与设备」不同——
            // 那个是「从某条线路进去看这台服务器上的设备」，这个是「这台电脑一共记了哪些服务器」。
            "servers" => {
                self.form = Some(FormState::servers());
                steps.push(Step::Sync(json_cmd("servers", &[])));
                self.bump();
            }
            "providers" => {
                self.form = Some(FormState::providers());
                steps.push(Step::Sync(json_cmd("providers", &[])));
                self.bump();
            }
            "domains" => {
                // 名单页（旧版的「管理交易名单」在应用页）。
                self.form = Some(FormState::split());
                steps.push(Step::Sync(json_cmd("split", &[])));
                self.bump();
            }
            // 「管理工具名单」（AI 工具）：应用页第二个名单入口，与交易名单同一形状——
            // 开表单 + 查一次目录（目录不进快照：那是约 2KB 的静态数据，而快照每个事件都发）。
            "agentsList" => {
                self.form = Some(FormState::agents());
                steps.push(Step::Sync(json_cmd("agents", &[])));
                self.bump();
            }
            // 其余入口先如实说，不静默失败。
            // 「自己搭服务器」：前端两个入口（首页空态、配对第二步的「自己搭一台服务器」）
            // 都落到这里（`pairChooseBuild` 发的是 `add`）。
            //
            // 导入已有线路文件仍走命令行 `--import`：那个流程要选文件、读路径，
            // 在 WebView 里做需要另一套文件选择通道，不在这一轮范围内。
            "add" => {
                self.form = Some(FormState::deploy());
                self.bump();
            }
            // 「选择引擎程序」：走**既有的** `pick-file`（`slot:"engine"` 本来就支持），
            // 宿主拿到路径后就地验一遍并写进配置（`set-engine` 的那套判据）。
            // 不要用 `pick-exe`：那条命令的 `target` 只有 direct/trade/daily，
            // 是给「分流选进程目标」用的，不是选引擎。
            "pickEngine" => {
                steps.push(Step::Sync(json_cmd("pick-file", &[("slot", json!("engine"))])));
                self.bump();
            }
            // 「服务器与设备」：只读。按线路找到服务器记录，读一次隧道与设备列表。
            //
            // 它同时是「核对服务器身份」那个按钮的落点（`item.Blocked` 时出现）——
            // 那个场景下用户要的正是「这台服务器现在是什么状态」，同一个页面能回答。
            "lineServer" => {
                let id = msg.get("Id").and_then(Value::as_str).unwrap_or("").to_string();
                self.form = Some(FormState::devices(&id));
                steps.push(Step::Long(json_cmd("server-devices", &[("Id", json!(id))])));
                self.bump();
            }
            // 设置页「创建桌面快捷方式」：**已经能用**——不复用 COM，直接把安装程序生成的
            // 开始菜单快捷方式复制到桌面（`shortcut.rs`）。成功/已存在/失败三种结果都由
            // 宿主给原话，前端不猜。
            "desktopShortcut" => {
                steps.push(Step::Sync(json_cmd("desktop-shortcut", &[])));
                self.bump();
            }
            // A5：用户自己叫停等待。**不发任何命令**——连接根本还没开始，
            // 这里唯一要做的是让等待态消失，并且让「程序退出后自动连」永远不再发生。
            "cancelWaiting" => {
                let was_waiting = self.pending_connect.take().is_some();
                self.toast(if was_waiting {
                    "已取消等待"
                } else {
                    "当前没有等待中的连接"
                });
                self.bump();
            }
            // A5：长操作「停止等待」。**不是中止**——Rust 里业务跑在工作线程上，
            // 强杀会留下半完成的系统代理/引擎。语义是：界面立刻恢复可操作，
            // 操作继续跑完，结论照常写操作记录；终态到达时只提示，不覆盖新操作。
            "cancelOperation" => {
                let kind = self
                    .operation
                    .as_ref()
                    .and_then(|op| op.get("Kind"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let cmd = self
                    .operation
                    .as_ref()
                    .and_then(|op| op.get("Cmd"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let can_cancel = self
                    .operation
                    .as_ref()
                    .and_then(|op| op.get("CanCancel"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if cmd.is_empty() || kind.is_empty() {
                    self.toast("当前没有进行中的操作");
                    self.bump();
                } else if !can_cancel {
                    self.toast("这个操作不能停止等待，请等它结束");
                    self.bump();
                } else {
                    self.detached.insert(cmd);
                    self.busy = false;
                    if let Some(op) = self.operation.as_mut() {
                        op["Detached"] = json!(true);
                        op["CanCancel"] = json!(false);
                    }
                    self.toast(&format!(
                        "已停止等待；{}仍在后台完成，结果会记在操作记录里。",
                        operation_label(&kind)
                    ));
                    self.bump();
                }
            }
            // A6 第二轮：线路动作的「重试 / 核对」。两者是不同的事：
            // - 重试 = 重新提交原命令（还会再写一条结果记录）；
            // - 核对 = 只看已有证据（宿主的 `line-action-review` 保证不重跑原操作）。
            "retryLineAction" => {
                // `Value` 是反馈条目的 id，`Id` 是线路 id；只信赖记录里的字段。
                let list = fetch(&json_cmd("line-action-list", &[]));
                let action = line_action_entry(&list, &value);
                let Some(action) = action else {
                    self.toast("找不到这条操作记录（可能已被新的操作取代），请刷新后重试");
                    self.bump();
                    return steps;
                };
                let text_of = |key: &str| {
                    action
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let phase = text_of("Phase");
                let line_id = text_of("LineId");
                if phase == "Succeeded" {
                    self.toast("这条操作已经成功了，不需要重试");
                } else if line_id.is_empty() {
                    self.toast("这条操作记录缺少线路，无法重试");
                } else if text_of("Kind") == "Preference" {
                    let requested = text_of("Requested");
                    if requested.is_empty() {
                        self.toast("这条操作记录缺少要保存的连接方式，请刷新后重试");
                    } else {
                        steps.push(Step::Sync(json_cmd(
                            "set-transport",
                            &[
                                ("id", json!(line_id)),
                                ("transport", json!(requested)),
                                ("source", json!("line-action")),
                            ],
                        )));
                    }
                } else if text_of("Kind") == "Check" {
                    // 测速是网络往返：走长命令，操作条上要能看到「正在重新测速」。
                    self.begin_op("Test", &line_id, "正在重新测速", "measure-latency");
                    steps.push(Step::Long(json_cmd(
                        "measure-latency",
                        &[("lineId", json!(line_id))],
                    )));
                } else {
                    self.toast("这条操作的类型不认识，无法重试");
                }
                self.bump();
            }
            "reviewLineAction" => {
                // 线路反馈条目的 id 在 `Value`；固定走线路动作核对，不做通用记录的分流。
                let action_id = &value;
                if action_id.is_empty() {
                    self.toast("没有指定要核对哪一条操作记录");
                } else {
                    steps.push(Step::Sync(json_cmd(
                        "line-action-review",
                        &[("id", json!(action_id))],
                    )));
                }
                self.bump();
            }
            // A8：对一条线路显式跑自动选路（会起临时引擎真拨两个候选）。
            "autoRoute" => {
                if id.is_empty() {
                    self.toast("没有指定要自动选路的线路");
                    self.bump();
                    return steps;
                }
                self.begin_op("AutoRoute", &id, "正在探测连接方式", "auto-route");
                steps.push(Step::Long(json_cmd(
                    "auto-route",
                    &[("line", json!(id)), ("refresh", json!(true))],
                )));
                self.bump();
            }
            // A6：按记录重试。先读记录的 `Retry` 安全描述，再发起真正的长命令；
            // 页面不自己按 Kind/Phase 猜哪些能重试。
            "retryOperation" => {
                if id.is_empty() {
                    self.toast("没有指定要重试哪一条操作记录");
                    self.bump();
                    return steps;
                }
                let operations = fetch(&json_cmd("operation-list", &[]));
                let read_error = operations
                    .get("operations")
                    .and_then(|section| section.get("ReadError"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !read_error.is_empty() {
                    self.toast(&format!("操作记录读不出来，无法重试：{read_error}"));
                    self.bump();
                    return steps;
                }
                let record = operations
                    .get("operations")
                    .and_then(|section| section.get("Records"))
                    .and_then(Value::as_array)
                    .and_then(|records| {
                        records
                            .iter()
                            .find(|record| {
                                record.get("Id").and_then(Value::as_str) == Some(id.as_str())
                            })
                            .cloned()
                    });
                let Some(record) = record else {
                    self.toast("这条操作记录已经不在了，请刷新后再看。");
                    self.bump();
                    return steps;
                };
                let plan = record.get("Retry").cloned().unwrap_or(Value::Null);
                if plan.get("CanRetry").and_then(Value::as_bool) != Some(true) {
                    let note = plan
                        .get("Note")
                        .and_then(Value::as_str)
                        .unwrap_or("这条操作现在不能重试");
                    self.toast(note);
                    self.bump();
                    return steps;
                }
                let kind = record
                    .get("Kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let (op_kind, message) = match kind.as_str() {
                    "Connect" => ("Connect", "正在重试连接"),
                    "Disconnect" => ("Disconnect", "正在重试断开"),
                    "Diagnose" => ("Diagnose", "正在重新诊断"),
                    _ => {
                        self.toast("这条操作的类型不支持重试");
                        self.bump();
                        return steps;
                    }
                };
                self.begin_op(op_kind, "", message, "operation-retry");
                steps.push(Step::Long(json_cmd(
                    "operation-retry",
                    &[("id", json!(id))],
                )));
                self.bump();
            }
            "reviewOperation" => {
                // 首页「待处理」的 id 可能来自两种记录：界面长操作（连接/断开/诊断）
                // 或线路动作。先问通用记录；两处都没有时如实说「已经不在了」。
                if id.is_empty() {
                    self.toast("没有指定要核对哪一条操作记录");
                    self.bump();
                    return steps;
                }
                let operations = fetch(&json_cmd("operation-list", &[]));
                let read_error = operations
                    .get("operations")
                    .and_then(|section| section.get("ReadError"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !read_error.is_empty() {
                    // 读不出来 ≠ 没有记录：核对必然无从谈起，把原话给用户。
                    self.toast(&format!("操作记录读不出来，无法核对：{read_error}"));
                } else {
                    let found = operations
                        .get("operations")
                        .and_then(|section| section.get("Records"))
                        .and_then(Value::as_array)
                        .map(|records| {
                            records.iter().any(|record| {
                                record.get("Id").and_then(Value::as_str) == Some(id.as_str())
                            })
                        })
                        .unwrap_or(false);
                    if found {
                        steps.push(Step::Sync(json_cmd(
                            "operation-review",
                            &[("id", json!(id))],
                        )));
                    } else {
                        // 回退：旧页面/旧快照里的线路动作也用 `reviewOperation` 入口。
                        let list = fetch(&json_cmd("line-action-list", &[]));
                        if line_action_entry(&list, &id).is_some() {
                            steps.push(Step::Sync(json_cmd(
                                "line-action-review",
                                &[("id", json!(id))],
                            )));
                        } else {
                            self.toast(
                                "这条待处理记录已经不在了（可能已在别处核对过）；请刷新后再看。",
                            );
                        }
                    }
                }
                self.bump();
            }
            // 「重试清理」：真的重删那个残留文件（A4 第二轮）。
            // id 来自待清理记录；为空说明页面与快照脱节，如实说，不发一条必然被拒的命令。
            "retryDelete" => {
                if id.is_empty() {
                    self.toast("没有指定要清理哪条线路的残留文件");
                } else {
                    steps.push(Step::Sync(json_cmd(
                        "delete-cleanup-retry",
                        &[("id", json!(id))],
                    )));
                }
                self.bump();
            }
            // 删除前的检查是**同步**的（查一次本地文件），没有可取消的「进行中检查」；
            // 待清理列表每帧重读，也不需要手动刷新。两个按钮当前都不会出现，
            // 这里如实回答——「后续版本开放」等于承诺一个不会存在的面板。
            "cancelDeletePreview" => {
                self.toast("删除前的检查是即时的，没有需要取消的操作");
                self.bump();
            }
            "retryDeleteRefresh" => {
                self.toast("待清理状态会自动刷新，不需要手动重试");
                self.bump();
            }
            // 「继续这条部署」：任务行的「继续」和底部任务条的点击都到这儿。
            //
            // 它只做一件事：**把磁盘上的那条记录读出来，用它打开详情页**。
            // 读失败就不开页面（宁可不响应，也不给一张「状态未知」的空页面）。
            "resume" | "resumeDeployment" => {
                if id.is_empty() {
                    self.toast("没有指定要打开哪一条部署任务");
                    self.bump();
                    return steps;
                }
                let reply = fetch(&json_cmd("deployment-get", &[("runId", json!(id))]));
                let run = reply
                    .get("deployment")
                    .and_then(|section| section.get("Run"))
                    .filter(|value| !value.is_null())
                    .cloned();
                match run {
                    Some(run) => {
                        // 草稿（`State=="Draft"`）→ **向导**：预填地址与指纹，密码重输。
                        // 其余 → 详情页（旧行为逐字不变）。分流用的是 `deploy_primary` /
                        // `action_of` 同一个字段 `State`，所以三处口径不会漂。
                        let is_draft = run.get("State").and_then(Value::as_str) == Some("Draft");
                        self.form = Some(if is_draft {
                            FormState::deploy_from_draft(&run)
                        } else {
                            FormState::deploy_run(&id, run)
                        });
                        self.bump();
                    }
                    None => {
                        // 命令层回的原话比「读不到」有用：可能是「任务编号不对」，
                        // 也可能是「记录文件坏了」——两种要走的路不一样。
                        self.toast(
                            reply
                                .get("error")
                                .and_then(Value::as_str)
                                .filter(|text| !text.is_empty())
                                .unwrap_or("读不到这条部署任务"),
                        );
                        self.bump();
                    }
                }
            }
            // 「刷新任务记录」：快照每帧都会重拉 `deployment-list`，所以这里**不发命令**，
            // 只让页面立刻重绘一次（下一次快照就是最新的）。发命令会多一条毫秒级 IPC，
            // 拿到的还是同一份磁盘数据。
            //
            // 它只是**页面动作**（任务行读不出来时的出路），不是 IPC 命令，别加进
            // `is_long_command` 或任何命令分发。
            "deploymentList" => {
                self.bump();
            }
            // 底部队列 / 详情页的「后台继续」：只是把窗口让出来，引擎继续跑。
            "backgroundDeployment" => {
                if id.is_empty() {
                    self.toast("没有指定要转到后台的任务");
                    self.bump();
                    return steps;
                }
                steps.push(Step::Sync(json_cmd(
                    "deployment-background",
                    &[("runId", json!(id))],
                )));
                self.bump();
            }
            // 「邀请其他电脑接入本机线路」：旧版的邀请管理面板。
            //
            // 注意这里**只**剩 invite：配对那几步（pairStart/pairVerify/pairJoin/…）由页面
            // 统一发 `pairOnline`（`app.js::pairAction`），由上面那个分支真正执行；把它们
            // 继续挂在这里等于给一条已经能用的流程回一句「后续版本开放」。
            "invite" => {
                // 消息是**扁平**的（`{Type:'invite', Phase, Id, Value}`）：页面把
                // `data-invite` / `data-id` / `data-value` 三个属性直接摊进 payload。
                let phase = msg.get("Phase").and_then(Value::as_str).unwrap_or("");
                let id = msg
                    .get("Id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                match phase {
                    // 选择服务器：开始一轮全新的会话。不能沿用上一张邀请的编号、
                    // 状态或邀请码，否则 inviteStage 会先把旧结果卡显示出来。
                    "Choose" => {
                        let lifetime = self
                            .invite
                            .as_ref()
                            .map(|session| session.lifetime)
                            .filter(|seconds| *seconds > 0)
                            .unwrap_or(1_800);
                        self.invite = Some(InviteSession {
                            lifetime,
                            ..InviteSession::default()
                        });
                        self.page = "invite".into();
                        self.bump();
                    }
                    // 进页面选线路。`Id` = 线路，`Value` = 服务器记录（多线路时页面先选服务器）。
                    "Begin" | "Target" => {
                        let lifetime = self
                            .invite
                            .as_ref()
                            .map(|session| session.lifetime)
                            .filter(|seconds| *seconds > 0)
                            .unwrap_or(1_800);
                        let mut session = InviteSession {
                            lifetime,
                            ..InviteSession::default()
                        };
                        if phase == "Target" {
                            // 两个值各有各的用途，不能只存一个：line_id 决定 invite-create
                            // 签到哪台服务器，server_id 决定页面把结果显示在哪条归属上。
                            session.line_id = id.clone();
                            session.server_id = msg
                                .get("Value")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .trim()
                                .to_string();
                        } else {
                            session.line_id = id.clone();
                        }
                        // 进页面就先量一次 18443：防火墙没放行时，用户应该在**发码之前**
                        // 看到这句话，而不是等对方粘贴之后再说「连不上」。
                        session.phase = "Checking".into();
                        session.stage_label = "正在检查 18443 能否连通".into();
                        session.stage_changed_at = now_rfc3339();
                        session.reachability = json!({"Status": "Checking"});
                        let line_id = session.line_id.clone();
                        self.invite = Some(session);
                        self.page = "invite".into();
                        self.bump();
                        if !line_id.is_empty() {
                            steps.push(Step::Long(json_cmd(
                                "invite-reachability",
                                &[("line", json!(line_id))],
                            )));
                        }
                    }
                    // 生成：一条长命令。宿主不在这里装身份——`invite-create` 内部会先补齐
                    // （用户不该为了签一张码先记住要跑另一个命令）。
                    "CreateNew" => {
                        // 有效期的值可能以数字或字符串形式到达（`data-value` 是属性，
                        // 页面把它原样带过来），两种都要认。
                        let lifetime = msg
                            .get("Value")
                            .and_then(|raw| {
                                raw.as_i64().or_else(|| {
                                    raw.as_str().and_then(|text| text.trim().parse().ok())
                                })
                            })
                            .filter(|seconds| (600..=86_400).contains(seconds))
                            .unwrap_or(1_800);
                        let mut session = self.invite.clone().unwrap_or_default();
                        clear_issued_invite(&mut session);
                        session.lifetime = lifetime;
                        session.phase = "Creating".into();
                        session.stage_label = "正在生成邀请码".into();
                        session.stage_changed_at = now_rfc3339();
                        session.error_code.clear();
                        session.error_message.clear();
                        session.next_action.clear();
                        let line_id = session.line_id.clone();
                        self.invite = Some(session);
                        steps.push(Step::Long(json_cmd(
                            "invite-create",
                            &[
                                ("line", json!(line_id)),
                                ("lifetime", json!(lifetime)),
                                ("device", json!("新电脑")),
                            ],
                        )));
                        self.bump();
                    }
                    // 重试：必须重发**失败的那一条**。签发失败点重试是重新签发，
                    // 作废失败点重试是再次作废；按同一个按钮名字猜动作会把两张码的
                    // 状态搞混。
                    "Retry" => {
                        let current = self.invite.clone().unwrap_or_default();
                        let retry = current.retry_command.clone();
                        if retry.is_empty() {
                            self.toast("这一步还没有失败过，没有可重试的操作。");
                            self.bump();
                        } else if retry == "invite-create" && current.line_id.is_empty() {
                            self.toast("还没有选中要邀请的线路，请重新进入邀请。");
                            self.bump();
                        } else if (retry == "invite-status" || retry == "invite-cancel")
                            && current.invite_id.is_empty()
                        {
                            let mut session = current;
                            session.error_code = "InviteNotFound".into();
                            session.error_message =
                                "这张邀请还没有生成，没有可重试的对象。".into();
                            session.next_action = "Retry".into();
                            self.invite = Some(session);
                            self.bump();
                        } else {
                            let mut session = current;
                            let (command, fields, phase, label) = match retry.as_str() {
                                "invite-create" => (
                                    "invite-create",
                                    vec![
                                        ("line", json!(session.line_id)),
                                        ("lifetime", json!(session.lifetime)),
                                        ("device", json!("新电脑")),
                                    ],
                                    "Creating",
                                    "正在生成邀请码",
                                ),
                                "invite-status" => (
                                    "invite-status",
                                    vec![
                                        ("line", json!(session.line_id)),
                                        ("inviteId", json!(session.invite_id)),
                                    ],
                                    "Checking",
                                    "正在检查邀请状态",
                                ),
                                "invite-cancel" => (
                                    "invite-cancel",
                                    vec![
                                        ("line", json!(session.line_id)),
                                        ("inviteId", json!(session.invite_id)),
                                    ],
                                    "Checking",
                                    "正在作废邀请码",
                                ),
                                _ => (
                                    "invite-init",
                                    vec![("line", json!(session.line_id))],
                                    "Loading",
                                    "正在准备邀请服务",
                                ),
                            };
                            session.phase = phase.into();
                            session.stage_label = label.into();
                            session.stage_changed_at = now_rfc3339();
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                            session.retry_command.clear();
                            self.invite = Some(session);
                            steps.push(Step::Long(json_cmd(command, &fields)));
                            self.bump();
                        }
                    }
                    // 作废。已经用掉的邀请不能作废（那要撤设备），服务器会如实拒绝。
                    "Cancel" | "CancelRetry" => {
                        let mut session = self.invite.clone().unwrap_or_default();
                        if session.invite_id.is_empty() {
                            session.error_code = "InviteNotFound".into();
                            session.error_message = "这张邀请还没有生成，没有可作废的对象。".into();
                            session.next_action = "Retry".into();
                            self.invite = Some(session);
                            self.bump();
                        } else {
                            let invite_id = session.invite_id.clone();
                            let line_id = session.line_id.clone();
                            session.phase = "Checking".into();
                            session.stage_label = "正在作废邀请码".into();
                            session.stage_changed_at = now_rfc3339();
                            self.invite = Some(session);
                            steps.push(Step::Long(json_cmd(
                                "invite-cancel",
                                &[("line", json!(line_id)), ("inviteId", json!(invite_id))],
                            )));
                            self.bump();
                        }
                    }
                    // 重新检查 / 重新开启接收服务。
                    "Recheck" | "Refresh" => {
                        let session = self.invite.clone().unwrap_or_default();
                        if !session.invite_id.is_empty() {
                            let line_id = session.line_id.clone();
                            let invite_id = session.invite_id.clone();
                            steps.push(Step::Long(json_cmd(
                                "invite-status",
                                &[("line", json!(line_id)), ("inviteId", json!(invite_id))],
                            )));
                        }
                        self.bump();
                    }
                    "Rearm" => {
                        // 不再盲重装：先让宿主自动判定（端口探测 → 服务状态 → 必要时重启），
                        // 防火墙/端口被占这两类问题重装多少次都不会好。
                        let mut session = self.invite.clone().unwrap_or_default();
                        let line_id = session.line_id.clone();
                        session.phase = "Checking".into();
                        session.stage_label = "正在自动检查接收服务".into();
                        session.stage_changed_at = now_rfc3339();
                        session.error_code.clear();
                        session.error_message.clear();
                        session.next_action.clear();
                        session.retry_command.clear();
                        self.invite = Some(session);
                        steps.push(Step::Long(json_cmd(
                            "invite-preflight",
                            &[("line", json!(line_id))],
                        )));
                        self.bump();
                    }
                    // 复制 / 显示：把完整码单独递一次。**不进快照**——快照每秒重推、
                    // 会进日志、会被截图，一次性凭据不该出现在那里。
                    "Copy" | "Reveal" => {
                        let code = self
                            .invite
                            .as_ref()
                            .map(|session| session.code.clone())
                            .unwrap_or_default();
                        if code.is_empty() {
                            self.toast("这张邀请码的内容已经不在这台电脑上了，请重新生成。");
                            self.bump();
                        } else {
                            if phase == "Copy" {
                                match crate::clipboard::set_text(&code) {
                                    Ok(()) => self.toast("邀请码已复制到剪贴板"),
                                    Err(message) => self.toast(&message),
                                }
                            }
                            steps.push(Step::Script(format!(
                                "window.__tcPush({})",
                                json!({"Type": "inviteCode", "Code": code})
                            )));
                            self.bump();
                        }
                    }
                    // 改用离线交接：新电脑连不上 18443 时，把签过名的邀请交给它，
                    // 再把它的申请带回来批准。手上已有完整邀请就直接切；没有就签发
                    // 一张 24 小时（离线交接的上限）的新邀请。
                    "Offline" => {
                        let mut session = self.invite.clone().unwrap_or_default();
                        session.offline = true;
                        session.error_code.clear();
                        session.error_message.clear();
                        session.next_action.clear();
                        session.retry_command.clear();
                        if !session.invite_jws.is_empty() && !session.invite_id.is_empty() {
                            self.invite = Some(session);
                            self.toast("已切换到离线交接：先复制邀请，再把新电脑的申请带回来。");
                            self.bump();
                        } else {
                            // 上一张的编号/状态不能留着：`inviteStage` 会先看它，
                            // 页面就会在「正在生成」时继续显示旧结果卡。
                            clear_issued_invite(&mut session);
                            session.lifetime = 86_400;
                            session.phase = "Creating".into();
                            session.stage_label = "正在生成 24 小时离线邀请".into();
                            session.stage_changed_at = now_rfc3339();
                            let line_id = session.line_id.clone();
                            self.invite = Some(session);
                            steps.push(Step::Long(json_cmd(
                                "invite-create",
                                &[
                                    ("line", json!(line_id)),
                                    ("lifetime", json!(86_400)),
                                    ("device", json!("新电脑")),
                                ],
                            )));
                            self.bump();
                        }
                    }
                    // 离线交接第二步：批准新电脑交回的申请。`Value` 是申请原文。
                    "OfflineApprove" => {
                        let request = msg
                            .get("Value")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let mut session = self.invite.clone().unwrap_or_default();
                        if request.is_empty() {
                            session.error_code = "InviteBadRequest".into();
                            session.error_message = "请粘贴新电脑交回的完整申请。".into();
                            session.next_action = "Retry".into();
                            self.invite = Some(session);
                            self.bump();
                        } else if !session.offline || session.line_id.is_empty() {
                            session.error_code = "InviteNeedsServer".into();
                            session.error_message = "还没有选择要邀请哪条线路，请重新进入邀请。".into();
                            session.next_action = "OpenServer".into();
                            self.invite = Some(session);
                            self.bump();
                        } else {
                            session.offline_request = request.clone();
                            session.phase = "Creating".into();
                            session.stage_label = "正在批准新电脑申请".into();
                            session.stage_changed_at = now_rfc3339();
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                            session.retry_command.clear();
                            let line_id = session.line_id.clone();
                            self.invite = Some(session);
                            steps.push(Step::Long(json_cmd(
                                "invite-authorize",
                                &[("line", json!(line_id)), ("request", json!(request))],
                            )));
                            self.bump();
                        }
                    }
                    // 离线交接的复制：邀请与授权都只经剪贴板，不进快照。
                    "OfflineCopyInvite" => {
                        let text = self
                            .invite
                            .as_ref()
                            .map(|session| session.invite_jws.clone())
                            .unwrap_or_default();
                        if text.is_empty() {
                            self.toast("还没有生成可复制的离线邀请，请先生成一张。");
                        } else {
                            match crate::clipboard::set_text(&text) {
                                Ok(()) => self.toast("离线邀请已复制，交给新电脑"),
                                Err(message) => self.toast(&message),
                            }
                        }
                        self.bump();
                    }
                    "OfflineCopyGrant" => {
                        let text = self
                            .invite
                            .as_ref()
                            .map(|session| session.offline_authorization.clone())
                            .unwrap_or_default();
                        if text.is_empty() {
                            self.toast("还没有可复制的授权，请先批准新电脑的申请。");
                        } else {
                            match crate::clipboard::set_text(&text) {
                                Ok(()) => self.toast("加密授权已复制，交回新电脑"),
                                Err(message) => self.toast(&message),
                            }
                        }
                        self.bump();
                    }
                    // 只清交接物，不取消邀请本身：用户可能需要重贴申请/授权。
                    "OfflineReset" => {
                        if let Some(session) = self.invite.as_mut() {
                            session.offline_request.clear();
                            session.offline_authorization.clear();
                            session.offline_device.clear();
                            session.offline_pairing_code.clear();
                            session.error_code.clear();
                            session.error_message.clear();
                            session.next_action.clear();
                        }
                        self.bump();
                    }
                    "OpenServer" => {
                        // 邀请失败常常是「这台服务器本来就不归你管」：回到线路页，
                        // 那里才有「服务器与设备」的入口。不做跨页自动打开抽屉。
                        self.page = "lines".into();
                        self.toast("请在这条线路上打开「服务器与设备」，确认这台服务器是本机部署的。");
                        self.bump();
                    }
                    "Close" => {
                        self.page = "lines".into();
                        self.invite = None;
                        self.bump();
                    }
                    _ => {
                        self.bump();
                    }
                }
            }
            // 旧版表单（旧版的 `joinLine`）：本版用同一套三步流程替代，没有单独的页面。
            // 留一句能照做的话——按钮点下去毫无反应比说「没有」更糟。
            "joinLine" => {
                self.toast("本版没有旧版表单：请用「用邀请码加入」按提示完成接入");
                self.bump();
            }
            _ => {
                self.bump();
            }
        }
        steps
    }

    /// A5：等待态的每帧推进。返回要执行的步骤（最多一条 `use` + 一条 `connect`）。
    ///
    /// 三条边界，每条都有对应用例：
    /// - 超预算（[`PENDING_CONNECT_BUDGET`]）→ 清等待并说清「等待已结束，请重新选择线路」；
    /// - 有长命令在跑 → 继续等（自动连接不许抢事务门）；
    /// - **`RunningPrograms` 缺失 → 不连**：读不出来不等于「程序都退出了」，
    ///   宁可让用户再点一次，也不许凭一次失败的预检就发起连接。
    pub fn poll_pending_connect(&mut self, fetch: &dyn Fn(&str) -> Value) -> Vec<Step> {
        let Some(pending) = self.pending_connect.as_ref() else {
            return Vec::new();
        };
        if pending.created_at.elapsed() > PENDING_CONNECT_BUDGET {
            self.pending_connect = None;
            self.toast("等待已结束，请重新选择线路");
            self.bump();
            return Vec::new();
        }
        if self.busy {
            return Vec::new();
        }
        let precheck = fetch(&json_cmd("guard-precheck", &[]));
        let Some(running) = precheck.get("RunningPrograms").and_then(Value::as_array) else {
            return Vec::new();
        };
        if !running.is_empty() {
            return Vec::new();
        }
        let pending = self.pending_connect.take().expect("上面刚判过非空");
        let mut steps = Vec::new();
        if !pending.line_id.is_empty() {
            // 等待期间用户可能已经换了线路：按等待时记下的 id 再切一次，
            // 否则连的是「当前线路」而不是用户当初点的那条。
            steps.push(Step::Sync(json_cmd("use", &[("id", json!(pending.line_id))])));
        }
        self.begin_op("Connect", &pending.line_id, "正在连接", "connect");
        steps.push(Step::Long(json_cmd("connect", &[])));
        self.bump();
        steps
    }

    fn begin_op(&mut self, kind: &str, line_id: &str, message: &str, cmd: &str) {
        // 已经有一条在跑、而且不是同一条命令：先把它的样子记下来。
        // 万一这条被宿主的全局闸门挡下，操作条要能还原（见 `finish_op` 的 `refused`）。
        self.op_before_refusal = if self.busy
            && self
                .operation
                .as_ref()
                .and_then(|op| op.get("Cmd"))
                .and_then(Value::as_str)
                != Some(cmd)
        {
            self.operation.clone()
        } else {
            None
        };
        self.busy = true;
        // A5：只有「停止等待不会留下半完成系统状态」的操作才给取消按钮。
        // 交易保护要等 UAC/WFP 事务，停止等待只会让用户以为它被取消了。
        let can_cancel = matches!(kind, "Connect" | "Disconnect" | "Diagnose" | "Test");
        self.operation = Some(json!({
            "Kind": kind,
            "Cmd": cmd,
            "LineId": line_id,
            "Name": "",
            "Message": message,
            "StartedAtUtc": now_rfc3339(),
            "CanCancel": can_cancel,
            "Detached": false,
        }));
    }

    /// 把 `pair-verify` 的回包落进会话。**只认与当前会话同一轮的回复**：
    /// 用户可能在等待期间点了取消，也可能已经改用另一个邀请码重新校验——
    /// 旧回包不能把已关掉的会话又救活，更不能把 A 的节点名/Host 贴到 B 的会话上。
    /// 两道闸：阶段必须是 `Creating`，且回包里的 `PairId` 必须就是这一轮的。
    fn absorb_pair_verify(&mut self, verified: &Value) {
        let Some(session) = self.pair.as_mut() else { return };
        if session.phase != "Creating" {
            return;
        }
        let text = |key: &str| {
            verified
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        // 空 `PairId` 也视为不匹配：那是「不知道是哪一轮」的回包，不能往任何会话里写。
        if text("PairId") != session.pair_id {
            return;
        }
        let code = text("Code");
        if code.is_empty() {
            session.phase = "Verified".into();
            session.stage_label.clear();
            session.stage_changed_at.clear();
            session.node_name = text("NodeName");
            session.host = text("Host");
            session.expires_at = text("ExpiresAtUtc");
            if !text("DeviceName").is_empty() {
                session.device_name = text("DeviceName");
            }
            session.error_code.clear();
            session.error_message.clear();
            session.next_action.clear();
        } else {
            session.phase = "Failed".into();
            session.stage_label.clear();
            session.stage_changed_at.clear();
            session.error_message = text("Message");
            session.next_action = pair_next_action(&code).to_string();
            session.error_code = code;
        }
    }

    /// 把 `pair-join` 的回包落进会话。
    ///
    /// 两道闸，与 `pair-verify` 同一个理由（等待期间用户可能已取消或重新开始）：
    /// 1. 会话必须还在 `Preparing`——取消之后不该被旧回包救活；
    /// 2. 回包里的 `PairId` 必须就是这一轮的——否则连续两次加入时，第一次的
    ///    回包会把第二轮说成「已加入」，而实际上它可能刚失败。
    fn absorb_pair_join(&mut self, joined: &Value) {
        let Some(session) = self.pair.as_mut() else { return };
        if session.phase != "Preparing" {
            return;
        }
        let text = |key: &str| {
            joined
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        // 空 `PairId` 也视为不匹配：那是「不知道是哪一轮」的回包，不能往任何会话里写。
        if text("PairId") != session.pair_id {
            return;
        }
        session.stage_label.clear();
        session.stage_changed_at.clear();
        let code = text("Code");
        if code.is_empty() {
            session.phase = "Complete".into();
            // 线路名以宿主为准：`slug` 撞名时 id 会加后缀，但显示名就是用户输入的那个。
            if !text("LineName").is_empty() {
                session.local_name = text("LineName");
            }
            session.error_code.clear();
            session.error_message.clear();
            session.next_action.clear();
            let name = session.local_name.clone();
            self.toast(&format!("线路已加入：{name}"));
        } else {
            session.phase = "Failed".into();
            session.error_message = text("Message");
            session.error_code = code.clone();
            session.next_action = pair_next_action(&code).to_string();
        }
    }

    /// 把离线交接的回包落进会话。与在线两条回包同一个理由：
    /// 只认**当前这一轮**（`PairId` 相同），旧回包不许把已取消的会话救活。
    ///
    /// 三个阶段共用一个键 `pairOffline`，所以这里按 `Stage` 分派：
    /// - `Inspect`：只带回指纹与邀请事实，页面进入「可以生成申请」；
    /// - `Request`：带回本机申请原文与登记 id；
    /// - `Complete`：带回线路，进入与在线加入相同的结果态。
    fn absorb_pair_offline(&mut self, reply: &Value) {
        let Some(session) = self.pair.as_mut() else { return };
        if !matches!(session.phase.as_str(), "Creating" | "Preparing") {
            return;
        }
        let text = |key: &str| {
            reply
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        if text("PairId") != session.pair_id {
            return;
        }
        let stage = text("Stage");
        let code = text("Code");
        if !code.is_empty() {
            session.phase = "Failed".into();
            session.stage_label.clear();
            session.stage_changed_at.clear();
            session.error_code = code;
            session.error_message = text("Message");
            session.next_action = match stage.as_str() {
                "Inspect" => "Reenter",
                "Request" => "Retry",
                _ => "ContinueCheck",
            }
            .into();
            self.bump();
            return;
        }
        session.error_code.clear();
        session.error_message.clear();
        session.next_action.clear();
        match stage.as_str() {
            "Inspect" => {
                session.offline = true;
                session.offline_fingerprint = text("Fingerprint");
                session.expires_at = text("ExpiresAtUtc");
                if !text("DeviceName").is_empty() {
                    session.device_name = text("DeviceName");
                }
                session.stage_label.clear();
                session.stage_changed_at.clear();
                session.phase = "OfflineReady".into();
            }
            "Request" => {
                session.offline_request = text("RequestText");
                session.enrollment_id = text("EnrollmentId");
                session.pairing_code = text("PairingCode");
                session.stage_label.clear();
                session.stage_changed_at.clear();
                session.phase = "OfflineRequested".into();
            }
            "Complete" => {
                session.stage_label.clear();
                session.stage_changed_at.clear();
                session.phase = "Complete".into();
                if !text("LineName").is_empty() {
                    session.local_name = text("LineName");
                }
                let name = session.local_name.clone();
                self.toast(&format!("线路已加入：{name}"));
            }
            _ => {
                session.phase = "Failed".into();
                session.error_code = "InvalidOfflineResponse".into();
                session.error_message = "离线交接的回包缺少阶段。".into();
                session.next_action = "Retry".into();
            }
        }
        self.bump();
    }

    /// 自动选路证据：10 秒缓存。失败不缓存，下一帧重试。
    fn auto_routes(&mut self, fetch: &dyn Fn(&str) -> Value) -> Value {
        if let Some((at, value)) = &self.auto_routes {
            if at.elapsed().as_secs() < 10 {
                return value.clone();
            }
        }
        let reply = fetch(r#"{"cmd":"auto-route-list"}"#);
        if reply.get("ok").and_then(Value::as_bool) != Some(true) {
            return json!({"Lines": {}});
        }
        let value = reply
            .get("autoRoutes")
            .cloned()
            .unwrap_or_else(|| json!({"Lines": {}}));
        self.auto_routes = Some((std::time::Instant::now(), value.clone()));
        value
    }

    /// 「哪些线路能邀请」的归属表。**只缓存成功的结果**。
    ///
    /// 这里原来把失败也一并缓存 30 秒，代价是：命令只要失败一次（进程刚起、盘正忙），
    /// 「邀请其他电脑」就会灰掉整整半分钟——而用户看到的只是「这个按钮点不动」，
    /// 没有任何线索指向那个已经恢复的失败。失败不缓存，下一帧就重试。
    fn invite_servers(&mut self, fetch: &dyn Fn(&str) -> Value) -> Vec<Value> {
        if let Some((at, list)) = &self.invite_servers {
            if at.elapsed().as_secs() < 10 {
                return list.clone();
            }
        }
        let reply = fetch(r#"{"cmd":"servers"}"#);
        // 先看 `ok`：失败回包里也有一个空的 `servers` 数组，只看数组会把
        // 「读失败」当成「真的没有服务器」缓存起来——那正是入口灰掉半分钟的原因。
        if reply.get("ok").and_then(Value::as_bool) != Some(true) {
            return Vec::new();
        }
        let Some(list) = reply.get("servers").and_then(Value::as_array).cloned() else {
            return Vec::new();
        };
        self.invite_servers = Some((std::time::Instant::now(), list.clone()));
        list
    }

    /// 邀请命令的回包（`{Section, Data}`）。失败也走这里：`Data.ErrorCode` 非空即失败。
    fn absorb_invite(&mut self, payload: &Value) {
        let Some(session) = self.invite.as_mut() else { return };
        let section = payload
            .get("Section")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let data = payload.get("Data").cloned().unwrap_or(Value::Null);
        let text = |key: &str| {
            data.get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        if let Some(code) = data.get("ErrorCode").and_then(Value::as_str) {
            session.phase.clear();
            session.error_code = code.to_string();
            session.error_message = text("ErrorMessage");
            session.next_action = invite_next_action(code).to_string();
            session.retry_command = format!("invite-{}", section.to_lowercase());
            self.bump();
            return;
        }
        session.error_code.clear();
        session.retry_command.clear();
        session.error_message.clear();
        session.next_action.clear();
        if session.server_id.is_empty() {
            session.server_id = text("ServerId");
        }
        match section.as_str() {
            "Init" => {
                session.phase.clear();
                self.toast = "邀请服务已就绪".to_string();
            }
            "Create" => {
                session.phase.clear();
                session.code = text("Code");
                session.invite_id = text("InviteId");
                session.expires_at = text("ExpiresAtUtc");
                session.device_name = text("DeviceName");
                session.state = "Open".to_string();
                // 离线交接要用完整邀请，不是 TCI1 码；指纹给人核对。
                session.invite_jws = text("Invite");
                session.fingerprint = text("ManagementFingerprint");
                session.offline_request.clear();
                session.offline_authorization.clear();
                session.offline_device.clear();
                session.offline_pairing_code.clear();
                // 换了码就是换了轮次：页面据此把「已显示」重置。
                session.epoch += 1;
            }
            // 离线批准：授权只留在宿主侧，页面只看到「已生成」，
            // 复制由「复制授权」那条动作把它单独递进剪贴板。
            "Authorize" => {
                session.phase.clear();
                session.stage_label.clear();
                session.offline_authorization = text("Authorization");
                session.offline_device = text("DeviceName");
                session.offline_pairing_code = text("PairingCode");
                self.toast("已生成加密授权：复制后交回新电脑");
            }
            "Status" => {
                session.phase.clear();
                session.state = text("State");
                if !text("ExpiresAtUtc").is_empty() {
                    session.expires_at = text("ExpiresAtUtc");
                }
            }
            // 可达性自检的回包：只落到投影里，页面对不通的情况自己说人话。
            "Reachability" => {
                session.phase.clear();
                session.stage_label.clear();
                session.reachability = data.clone();
            }
            // 自动判定的回包：形状与可达性一致，另有 Verdict/Detail/Repaired。
            // 结论必须落在会话里——只弹一句 Toast，页面上的「连不上」会继续挂着。
            "Preflight" => {
                session.phase.clear();
                session.stage_label.clear();
                session.reachability = data.clone();
                let detail = text("Detail");
                if !detail.is_empty() {
                    self.toast = detail;
                }
            }
            "Cancel" => {
                session.phase.clear();
                session.state = text("State");
                // 作废之后码就不该再留在内存里：留着只会让「复制」复制出一张废码。
                session.code.clear();
                session.invite_jws.clear();
                session.offline_request.clear();
                session.offline_authorization.clear();
            }
            _ => {}
        }
        self.bump();
    }

    /// 邀请会话 → 旧版的 `Invite` 投影。只投影，不做业务判断。
    fn invite_view(&self) -> Value {
        let Some(session) = self.invite.as_ref() else {
            return Value::Null;
        };
        // 预览只给开头 18 个字符：足够让人确认「是这张」，又不至于在截图里被抄走。
        let preview = if session.code.is_empty() {
            String::new()
        } else {
            let head: String = session.code.chars().take(18).collect();
            format!("{head}…（共 {} 个字符）", session.code.chars().count())
        };
        json!({
            "ServerId": session.server_id,
            "LineId": session.line_id,
            "Phase": session.phase,
            "StageLabel": session.stage_label,
            "StageChangedAtUtc": session.stage_changed_at,
            "InviteId": session.invite_id,
            "State": session.state,
            "ExpiresAtUtc": session.expires_at,
            "DeviceName": session.device_name,
            "CodePresent": !session.code.is_empty(),
            "CodePreview": preview,
            "LifetimeSeconds": if session.lifetime > 0 { session.lifetime } else { 1_800 },
            "LifetimePresets": [600, 1800, 7200, 86400],
            "CompatNoteVisible": false,
            "Epoch": session.epoch,
            "Origin": "line",
            // 可达性自检结论（r37）：由 `invite-reachability` 落进会话，页面据此说人话。
            // 还没量过时是 null——宁可不说，也不显示一句没验过的话。
            "Reachability": session.reachability,
            "ErrorCode": session.error_code,
            "ErrorMessage": session.error_message,
            "NextAction": session.next_action,
            // 离线交接：页面只需要「有没有、是谁」，完整邀请与授权走剪贴板，
            // 不进快照（后者是一次性凭据，前者虽然公开但没必要每秒重推）。
            "Offline": session.offline,
            "OfflineInvitePresent": !session.invite_jws.is_empty(),
            "OfflineFingerprint": session.fingerprint,
            "OfflineDeviceName": session.offline_device,
            "OfflinePairingCode": session.offline_pairing_code,
            "OfflineRequestPresent": !session.offline_request.is_empty(),
            "OfflineAuthorizationPresent": !session.offline_authorization.is_empty(),
        })
    }

    /// 长命令结束（UiHostEvent）后清 busy；失败时把宿主的话放进 Toast。
    ///
    /// 返回「接着要发的命令」：目前只有「自己搭服务器」这一条会用到——读指纹
    /// 是长命令，而它的结果是「直接开始」还是「先确认身份」只有回包里才知道。
    /// 上层（`ui.rs` 的事件循环）拿到这些步骤后就地执行，用户看到的仍是一页一次点击。
    ///
    /// A5 起多两条纪律：
    /// 1. **心跳不清等待态**。`submit_operation` 每秒发一次 `running`，那不是结束；
    ///    以前它们也会走到这里，把 busy/operation 清掉，操作条只能闪一秒。
    /// 2. **停止等待后的终态不覆盖新操作**。连接还在后台时用户可能已经点了断开；
    ///    连接的终态只提示、只落记录，不能把「正在断开」清掉。
    pub fn finish_op(&mut self, state: &Value) -> Vec<Step> {
        self.finish_op_inner(state);
        self.deploy_followup_steps()
    }

    /// 「读指纹」回包之后的接力（`DeployFollowUp`）。
    ///
    /// 为什么需要：部署页只有一颗「开始部署」，一次点击要完成「读指纹 → 确认身份 →
    /// 投递」三件事。读指纹是长命令（走 `finish_op`），而当时还不确定要不要问身份，
    /// 所以决定放在这里做：表单给出「开始」或「先确认」，宿主照着发。
    fn deploy_followup_steps(&mut self) -> Vec<Step> {
        let Some(followup) = self.form.as_mut().and_then(FormState::take_deploy_followup) else {
            return Vec::new();
        };
        match followup {
            DeployFollowUp::Start => match self.form.as_mut() {
                Some(form) => form.deploy_start_steps(),
                None => Vec::new(),
            },
            DeployFollowUp::ConfirmIdentity => {
                // 首次接触一台服务器：**先问人**再交凭据。对话框复用宿主既有的
                // `dialog` 机制（与「断开连接」「删除线路」同一套），
                // 确认后由 `confirmDialog` 分支接着发命令。
                if let Some(form) = self.form.as_ref() {
                    self.dialog = Some(form.deploy_identity_dialog());
                }
                self.bump();
                Vec::new()
            }
        }
    }

    fn finish_op_inner(&mut self, state: &Value) {
        let op = state.get("op");
        let phase = op
            .and_then(|value| value.get("phase"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if phase == "refused" {
            // 被闸门挡下的**另一条**命令（有长命令正在跑）。它没有开始过，
            // 所以这里一个字都不许动：`busy` 与 `operation` 属于正在跑的那条，
            // 清掉就等于「别人拒绝了，却让当前这条看起来结束了」。
            // 只把那句话说出来。
            let message = state
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| state.get("message").and_then(Value::as_str))
                .unwrap_or("另一个操作正在进行，请稍后再试。");
            // 页面在发出这条命令时就把操作条顶上去了（`begin_op`）。宿主拒了它，
            // 就把那条还原成**真的在跑**的：否则界面会挂着「正在诊断」的牌子，
            // 而实际在测速。只在「当前显示的正是被拒的那条」时还原，别的一概不动。
            let refused = op
                .and_then(|value| value.get("cmd"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let showing = self
                .operation
                .as_ref()
                .and_then(|value| value.get("Cmd"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !refused.is_empty() && showing == refused {
                if let Some(previous) = self.op_before_refusal.take() {
                    self.operation = Some(previous);
                }
            }
            self.op_before_refusal = None;
            self.toast(message);
            self.bump();
            return;
        }
        if matches!(phase, "queued" | "running") {
            // 心跳：操作还在跑，等待态必须保留。
            return;
        }
        let finished_cmd = op
            .and_then(|value| value.get("cmd"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let current_cmd = self
            .operation
            .as_ref()
            .and_then(|value| value.get("Cmd"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let was_detached = !finished_cmd.is_empty() && self.detached.remove(&finished_cmd);
        if was_detached && !current_cmd.is_empty() && current_cmd != finished_cmd {
            // 另一个操作正在前台跑：后台那条只提示结果，别的什么都不动。
            let ok = state.get("ok").and_then(Value::as_bool) == Some(true);
            let message = state
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| state.get("error").and_then(Value::as_str))
                .unwrap_or("");
            let label = format!("后台{}", command_label(&finished_cmd));
            self.toast(&if ok {
                format!("{label}已完成")
            } else if message.is_empty() {
                format!("{label}没有成功，详情见操作记录")
            } else {
                format!("{label}没有成功：{message}")
            });
            self.bump();
            return;
        }
        self.busy = false;
        self.operation = None;
        // 刚跑完的长命令可能刚写了一条采样（测速/连接自检）：缓存不失效的话，
        // 用户点了「测一次」还要等最多 30 秒才在卡片上看到新数字。
        self.quality_cache.clear();
        // 自动选路（A8）：探测结论要立刻上屏，缓存的 10 秒旧证据必须作废。
        self.auto_routes = None;
        if let Some(route) = state.get("autoRoute") {
            let message = route
                .get("Note")
                .and_then(Value::as_str)
                .or_else(|| route.get("Evidence").and_then(|e| e.get("Summary")).and_then(Value::as_str))
                .unwrap_or("");
            if !message.is_empty() {
                self.toast(message);
            }
        }
        // 连接中的自动切换（A8 后续）：结论必须上屏，否则用户只会看到一次「无缘无故的断线」。
        if let Some(reroute) = state.get("autoReroute") {
            let message = reroute
                .get("Note")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !message.is_empty() {
                self.toast(message);
            }
        }
        // 按记录重试（A6）：成功时给一句「已重新连接」；失败由下面的通用失败分支
        // 用宿主原话提示，这里不重复。
        if let Some(retry) = state.get("operationRetry") {
            let message = retry
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !message.is_empty() {
                self.toast(message);
            }
        }
        // 邀请管理（签发/查状态/作废）的回包。
        if let Some(payload) = state.get("invite") {
            self.absorb_invite(payload);
        }
        // 校验邀请码的回包：成功转「待加入」，失败转失败态并给出人话与下一步。
        if let Some(verified) = state.get("pairVerify") {
            self.absorb_pair_verify(verified);
        }
        // 加入的回包：成功转「已完成」（页面显示结果卡），失败转失败态。
        if let Some(joined) = state.get("pairJoin") {
            self.absorb_pair_join(joined);
        }
        // 离线交接的三步（校验 / 生成申请 / 导入授权）。
        if let Some(offline) = state.get("pairOffline") {
            self.absorb_pair_offline(offline);
        }
        // 自助部署只剩读指纹这一步是长命令；「开始部署」落的是部署任务（短命令，
        // 回包走 `absorb_reply`）。
        //
        // **失败时命令层只给 `ok:false`，没有 `serverProbe` 字段**：只认字段的写法会让
        // 页面永远停在「正在核对服务器身份…」、开始部署一直灰着（r86 真机验收抓到）。
        // 所以按「这次终态属于 server-probe」来判断，成功失败都收。
        let probe_finished = state.get("serverProbe").is_some()
            || (state.get("ok").and_then(Value::as_bool) == Some(false)
                && state
                    .get("op")
                    .and_then(|op| op.get("cmd"))
                    .and_then(Value::as_str)
                    == Some("server-probe"));
        if probe_finished {
            if let Some(form) = self.form.as_mut() {
                if form.view == View::Deploy {
                    form.absorb_probe(state);
                }
            }
        }
        // 设备页：正常回包带 `serverDevices`；异常结束（宿主命令崩了）只有 `ok:false`，
        // 那种情况也必须落回页面——否则用户永远停在「正在读取…」。
        let device_command_error = state.get("serverDeviceRename").is_some()
            || state.get("serverUninstallPreview").is_some()
            || state.get("serverUninstall").is_some()
            // 撤销失败也保留设备列表：`absorb_revoke` 会把原因贴在页面上。
            || state.get("serverRevoke").is_some()
            // 删除名称记录同理：失败只影响孤儿区块，不该让整页设备列表消失。
            || state.get("serverDeviceForget").is_some();
        if let Some(form) = self.form.as_mut() {
            if form.view == View::Devices {
                if state.get("serverDeviceRename").is_some() {
                    form.absorb_device_rename(state);
                }
                if state.get("serverUninstallPreview").is_some() {
                    form.absorb_uninstall_preview(state);
                }
                if state.get("serverUninstall").is_some() {
                    form.absorb_uninstall(state);
                }
            }
        }
        let devices_failed = state.get("ok").and_then(Value::as_bool) == Some(false)
            && self
                .form
                .as_ref()
                .map(|form| form.view == View::Devices)
                .unwrap_or(false);
        if (state.get("serverDevices").is_some() || devices_failed) && !device_command_error {
            if let Some(form) = self.form.as_mut() {
                form.absorb_devices(state);
            }
        }
        // 撤销设备的回包：成功要把那台设备从列表里摘掉，失败把原因留在页面上。
        if state.get("serverRevoke").is_some() {
            if let Some(form) = self.form.as_mut() {
                if form.view == View::Devices {
                    form.absorb_revoke(state);
                }
            }
        }
        // 删除孤儿名称记录的回包：成功摘掉那一条，失败把原因留在页面上。
        if state.get("serverDeviceForget").is_some() {
            if let Some(form) = self.form.as_mut() {
                if form.view == View::Devices {
                    form.absorb_device_forget(state);
                }
            }
        }
        // 出口网卡（r89）：读和写都带 `lineNetwork`，交给同一条吸收逻辑。
        if state.get("lineNetwork").is_some() {
            if let Some(form) = self.form.as_mut() {
                if form.view == View::LineSettings {
                    form.absorb_line_network(state);
                }
            }
        }
        // 解除交易保护的回包：只有 `guardRemove` 在场才交给维护页，
        // 防止普通 status 的 `guard` 字段被误当成一次解除结果。
        if state.get("guardRemove").is_some() {
            if let Some(form) = self.form.as_mut() {
                if form.view == View::Maintenance {
                    form.absorb_guard_remove(state);
                }
            }
        }
        // 诊断/还原是长命令：结果必须落回它还开着的表单里，不能只弹一句 Toast。
        if let Some(form) = self.form.as_mut() {
            match form.view {
                View::Diagnose => form.absorb_diagnose(state),
                // 解除交易保护已由上面的 guardRemove 分支处理；这里不能再套用还原的文案。
                View::Maintenance if state.get("guardRemove").is_none() => form.absorb_restore(state),
                _ => {}
            }
        }
        self.bump();
        let in_deploy = self
            .form
            .as_ref()
            .map(|form| form.view == View::Deploy)
            .unwrap_or(false);
        if !in_deploy && state.get("ok").and_then(Value::as_bool) == Some(false) {
            let message = state
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| state.get("error").and_then(Value::as_str))
                .unwrap_or("操作没有完成");
            self.toast(message);
        }
    }

    /// 由调用方在同步命令回包后设置（成功/失败各有一句话）。
    ///
    /// 成功且调用方**没给文案**时，保留 `absorb_reply` 刚设的那句（例如
    /// 「已选用引擎：sing-box version 1.14.2」）——用空串覆盖它，用户就只看到「点了没反应」。
    /// 快照消费一次就把 Toast 清空，所以不会把上一次的提示挂在这里。
    pub fn toast_from_reply(&mut self, reply: &Value, ok_message: &str) {
        if reply.get("ok").and_then(Value::as_bool) == Some(false) {
            let message = reply
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| reply.get("error").and_then(Value::as_str))
                .unwrap_or("操作没有完成");
            self.toast(message);
        } else if !ok_message.is_empty() {
            self.toast(ok_message);
        }
    }

    /// 同步命令回包进入表单：改名成功就关表单、失败把宿主的话留在原地。
    /// 不在表单里时什么都不做（回包仍由 `toast_from_reply` 兜底）。
    pub fn absorb_reply(&mut self, command: &str, reply: &Value) {
        let name = crate::ipc::command_name(command).unwrap_or_default();
        if name == "quality-history" {
            // 曲线不属于任何表单，直接挂到快照上。
            self.quality_history = reply.get("qualityHistory").cloned();
            self.bump();
            return;
        }
        // 核对线路动作（A6 第二轮）：**核对完成**本身要有回话——结论写在
        // `lineActionReview.Message` 里（即使结论是「上次保存没落地」，核对也是成功的）。
        // 命令层拒绝（记录不在了/不需要核对）走合并后的 `ok:false` + `message`。
        if name == "line-action-review" {
            let message = reply
                .get("lineActionReview")
                .and_then(|review| review.get("Message"))
                .and_then(Value::as_str)
                .or_else(|| {
                    (reply.get("ok").and_then(Value::as_bool) == Some(false))
                        .then(|| reply.get("message").and_then(Value::as_str))
                        .flatten()
                })
                .unwrap_or("");
            if !message.is_empty() {
                self.toast(message);
            }
            self.bump();
            return;
        }
        // 核对界面长操作（A5/A6）：结论（含「现在还不能下结论」的指引）都在
        // `operationReview.Message`；命令层拒绝走合并后的 `ok:false` + `message`。
        if name == "operation-review" {
            let message = reply
                .get("operationReview")
                .and_then(|review| review.get("Message"))
                .and_then(Value::as_str)
                .or_else(|| {
                    (reply.get("ok").and_then(Value::as_bool) == Some(false))
                        .then(|| reply.get("message").and_then(Value::as_str))
                        .flatten()
                })
                .unwrap_or("");
            if !message.is_empty() {
                self.toast(message);
            }
            self.bump();
            return;
        }
        // 删除线路的结论（A4 第二轮）：配置一定已经改了，本地引擎文件可能没删掉。
        // **必须说出来**——「提示说删了，含私钥的文件却还在」是这个流程里最糟的谎。
        if name == "remove" {
            if let Some(result) = reply.get("deleteResult") {
                let incomplete = result.get("Incomplete").and_then(Value::as_bool) == Some(true);
                if incomplete {
                    let file = result.get("File").and_then(Value::as_str).unwrap_or("");
                    let error = result.get("Error").and_then(Value::as_str).unwrap_or("");
                    self.toast(&format!(
                        "线路已删除，但本地文件 {file} 没删掉：{error}（可在页面提示里重试清理）"
                    ));
                } else {
                    self.toast("线路已删除");
                }
            }
            self.bump();
            return;
        }
        // 「重试清理」的结论：成功 / 文件已经不在 / 还是删不掉，三种都由宿主的
        // `Message` 说原话；读不到结果（极端失败）也要回一句，不能让按钮点完没反应。
        if name == "delete-cleanup-retry" {
            let message = reply
                .get("deleteCleanupResult")
                .and_then(|result| result.get("Message"))
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    reply
                        .get("error")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "清理没有完成，请稍后重试".to_string());
            self.toast(&message);
            self.bump();
            return;
        }
        // 选完引擎：成功/失败都要说一句人话。成功时 `message` 里是版本号，
        // 它才是「真的验过」的证据；页面这一行也会随快照更新成新路径。
        if name == "pick-file" {
            if let Some(set) = reply.get("engineSet") {
                let message = set.get("Message").and_then(Value::as_str).unwrap_or("");
                if !message.is_empty() {
                    self.toast(message);
                }
                self.bump();
                return;
            }
        }
        // 创建桌面快捷方式：成功必须说出来。设置页底部点一下，页面本身没有任何变化，
        // 用户看不到桌面多了个图标——「点完像没反应」正是这个按钮要解决的问题。
        // 失败**不能**在这里 return：交给 `toast_from_reply` 按统一的失败口径说原话。
        if name == "desktop-shortcut" && reply.get("ok").and_then(Value::as_bool) != Some(false) {
            if let Some(message) = reply
                .get("message")
                .and_then(Value::as_str)
                .filter(|m| !m.is_empty())
            {
                self.toast = message.to_string();
            }
            return;
        }
        // 部署命令的回包：页面没开着详情页时（底部任务条点「后台继续」）也要把
        // 结论说出来。否则点了「后台继续」，失败原因只留在日志里。
        if name.starts_with("deployment-") && self.form.is_none() {
            let message = reply
                .get("deployment")
                .and_then(|section| section.get("Message"))
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(|text| text.to_string())
                .or_else(|| {
                    reply
                        .get("error")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(|text| text.to_string())
                });
            if let Some(message) = message {
                self.toast = message;
            }
            self.bump();
            return;
        }
        let Some(form) = self.form.as_mut() else { return };
        // 服务器一览的「删除本机部署资料」：预览先变成一张确认框（弹框归宿主），
        // 执行只是刷新列表 + 一句结论。这两条自己处理完就返回——`absorb` 的默认分支
        // 没有「向宿主申请弹框」的通道。
        if name == "server-cleanup-preview" || name == "server-cleanup" {
            let dialog = if name == "server-cleanup-preview" {
                form.absorb_server_cleanup_preview(reply);
                form.take_server_cleanup_dialog()
            } else {
                form.absorb_server_cleanup(reply);
                None
            };
            if let Some(dialog) = dialog {
                self.dialog = Some(dialog);
            }
            self.bump();
            return;
        }
        match form.absorb(&name, reply) {
            Absorbed::Keep => {}
            Absorbed::Toast(message) => self.toast = message,
            Absorbed::Close(message) => {
                self.form = None;
                self.toast = message;
            }
        }
        self.bump();
    }

    /// 内部状态 JSON → 旧版快照。只投影，不做业务判断。
    pub fn snapshot(&mut self, fetch: &dyn Fn(&str) -> Value) -> Value {
        // 等待态投影（A5）。`DeadlineUtc` 是页面唯一认的钟：前端只按它算倒计时，
        // 不自己存预算（app.js 的 `remainingSeconds` 注释写着这条）。
        let pending_connect = self.pending_connect.as_ref().map(|pending| {
            let left = PENDING_CONNECT_BUDGET.saturating_sub(pending.created_at.elapsed());
            json!({
                "Name": pending.line_name,
                "DeadlineUtc": rfc3339_after(left.as_secs() as i64),
                "SecondsRemaining": left.as_secs() as i64,
            })
        });
        let pending_connect_name = self
            .pending_connect
            .as_ref()
            .map(|pending| pending.line_name.clone())
            .unwrap_or_default();
        let st = fetch(r#"{"cmd":"status"}"#);
        let lines_raw = fetch(r#"{"cmd":"lines"}"#);
        // The lines adapter already carries a later status projection. For a
        // completed disconnect with a valid selection, use that whole offline
        // projection rather than combining the old connected status with new rows.
        let st = if st.get("state").and_then(Value::as_str) == Some("Connected")
            && lines_raw.get("ok").and_then(Value::as_bool) == Some(true)
            && lines_raw.get("state").and_then(Value::as_str) == Some("Disconnected")
            && lines_raw.get("action").and_then(Value::as_str) == Some("Connect")
            && lines_raw.get("selected").and_then(Value::as_str).is_some_and(|id| {
                !id.is_empty()
                    && lines_raw.get("lines").and_then(Value::as_array).is_some_and(|rows| {
                        rows.iter().any(|row| {
                            row.get("id").and_then(Value::as_str) == Some(id)
                                && row.get("selected").and_then(Value::as_bool) == Some(true)
                        })
                    })
            })
            && lines_raw.get("exitEvidence").and_then(Value::as_str).is_some_and(|status| status != "verified")
            && lines_raw.get("exitObservedIp") == Some(&Value::Null)
            && lines_raw.get("exitAttribution").and_then(Value::as_str) == Some("Unknown")
            && lines_raw.get("exitProbeAtUtc") == Some(&Value::Null)
            && lines_raw.get("transportActual") == Some(&Value::Null)
            && lines_raw.get("startedAt").and_then(Value::as_str) == Some("")
            && lines_raw.get("latencyMs") == Some(&Value::Null)
            && lines_raw.get("measuredAtUtc") == Some(&Value::Null)
        {
            lines_raw.clone()
        } else {
            st
        };
        let providers_raw = fetch(r#"{"cmd":"providers"}"#);
        // 部署任务：**同一条命令**（`deployment-list`）给管道、CLI 与页面，三处口径
        // 不会漂。这里刻意不做缓存：读的是本地几十条小 JSON，一帧一次远比
        // 「刚点完却没变」的代价小（架构允许 500ms 缓存，但没有必要）。
        let deployments_raw = fetch(r#"{"cmd":"deployment-list"}"#);
        // 待清理（A4 第二轮）：删线路时没删掉的引擎配置文件（含隧道私钥）。
        // 记录在磁盘上、要活过重启，所以每帧重读，不缓存；读不出来时页面必须说
        // 「不知道」，不能把它显示成「没有」。
        let cleanup_raw = fetch(r#"{"cmd":"delete-cleanup"}"#);
        // 线路动作记录（A6 第二轮）：测速/保存连接方式的最近结果，以及被中断后
        // 需要核对的操作。同样每帧重读——记录文件只有几条，读一次远比「刚点完
        // 却没变」的代价小。读不出来时页面必须说「不知道」，不能显示成「没有」。
        let actions_raw = fetch(r#"{"cmd":"line-action-list"}"#);
        let actions_section = actions_raw
            .get("lineActions")
            .cloned()
            .unwrap_or(Value::Null);
        let line_actions_read_error = actions_section
            .get("ReadError")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let line_actions: Vec<Value> = actions_section
            .get("Actions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // 界面长操作记录（A5/A6）：被中断的连接/断开是副作用未知的操作，必须进
        // 「待处理」；读不出来时页面也要说「不知道」，不能显示成「没发生过」。
        let operations_raw = fetch(r#"{"cmd":"operation-list"}"#);
        let operations_section = operations_raw
            .get("operations")
            .cloned()
            .unwrap_or(Value::Null);
        let operations_read_error = operations_section
            .get("ReadError")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let operation_records: Vec<Value> = operations_section
            .get("Records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let state_key = st.get("state").and_then(Value::as_str).unwrap_or("Fault");
        let running = state_key == "Connected";
        let selected = lines_raw.get("selected").and_then(Value::as_str).unwrap_or("");
        let trade_exit = exit_lane(&st, "exitTrade");
        let trade_is_line = trade_exit == "Trade";

        // 线路 → 服务器的归属：页面每帧都要用，而算一次要遍历线路文件，所以带缓存。
        let servers = self.invite_servers(fetch);
        // 自动选路证据（A8）：同样的缓存理由；连接前探测的结论要显示在线路卡上。
        let auto_routes = self.auto_routes(fetch);
        let (lines, summaries): (Vec<Value>, Vec<(String, Value)>) = {
            // 先按线路取 30 分钟摘要（带 30 秒缓存），再投影：project_line 只读 self，
            // 缓存写入必须发生在借用 self 之前。
            let raw: Vec<Value> = lines_raw
                .get("lines")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut summaries: Vec<(String, Value)> = Vec::new();
            for l in &raw {
                let id = l.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let profile = profile_of(l);
                let summary = self.quality_for(fetch, &id, profile);
                summaries.push((id, summary));
            }
            let lines = raw
                .iter()
                .map(|l| {
                    let summary = l
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| summaries.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone()))
                        .unwrap_or(Value::Null);
                    self.project_line(
                        l,
                        selected,
                        running,
                        trade_is_line,
                        &st,
                        &summary,
                        &servers,
                        &line_actions,
                        &auto_routes,
                    )
                })
                .collect();
            (lines, summaries)
        };

        let providers: Vec<Value> = providers_raw
            .get("providers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|p| {
                        json!({
                            "Id": p.get("id").and_then(Value::as_str).unwrap_or(""),
                            "Name": p.get("name").and_then(Value::as_str).unwrap_or("代理软件"),
                            "Kind": "本机代理",
                            "Applied": p.get("applied").and_then(Value::as_bool).unwrap_or(false)
                                || p.get("effectiveState").and_then(Value::as_str) == Some("effective"),
                            "NeedsUpgrade": false,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // 部署任务的投影：**只透传，不在这里算**。`deployment-list` 已经把
        // `Tasks`/`Deployments`/`TasksRead`/`UnreadableCount` 算好了，快照再算一遍
        // 就会出现「列表说核对、页面说重试」。三个读取状态字段一律原样带过去：
        // `TasksRead` **缺失 = 未知**，页面据此说「状态未知，请刷新」，
        // 而不是把「读不出来」显示成「没有任务」。
        let deploy = deployments_raw.get("deployment").cloned().unwrap_or(Value::Null);
        let tasks: Vec<Value> = deploy
            .get("Tasks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let deployments: Vec<Value> = deploy
            .get("Deployments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let tasks_read = deploy.get("TasksRead").and_then(Value::as_str).unwrap_or("");
        let tasks_read_error = deploy
            .get("TasksReadError")
            .and_then(Value::as_str)
            .unwrap_or("");
        let unreadable_count = deploy
            .get("UnreadableCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // 部署结果提醒（P1-3）：与 Tasks/Deployments 一样只透传。读不出来时
        // `RemindersError` 非空、`Reminders` 是空数组——页面必须说「读不出来」，
        // 不能显示成「没有未读结果」。
        let reminders: Vec<Value> = deploy
            .get("Reminders")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let reminders_error = deploy
            .get("RemindersError")
            .and_then(Value::as_str)
            .unwrap_or("");
        // 已归档（P2-2）：只透传。页面靠 `RunId` 打开、靠详情页恢复。
        let archived: Vec<Value> = deploy
            .get("Archived")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // 草稿总览（C6）：文案由宿主拼好，页面只显示——同一句话只有一处。
        let drafts: Value = deploy.get("Drafts").cloned().unwrap_or(Value::Null);
        // 「后台继续」必须指向**唯一**一条记录：多个候选时不给按钮——按钮点下去
        // 会拿这个 RunId 去调 `deployment-background`，指错就是「把别人的任务转后台」。
        let (can_background, can_background_run) = {
            let mut candidates = tasks
                .iter()
                .filter(|task| task.get("CanBackground").and_then(Value::as_bool) == Some(true));
            match (candidates.next(), candidates.next()) {
                (Some(task), None) => (
                    true,
                    task.get("Id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                ),
                _ => (false, String::new()),
            }
        };

        // 部署任务详情：每帧重读一次这条记录，页面上才看得到进度推进。
        // 只在真正打开着详情页时读——否则每帧多读一份 JSON 没有意义。
        // 读不到就保持上一帧的样子：记录被删掉时页面不该突然变成空白。
        if let Some(run_id) = self
            .form
            .as_ref()
            .map(|form| form.deploy_run_id.clone())
            .filter(|run_id| !run_id.is_empty())
        {
            let reply = fetch(&json_cmd("deployment-get", &[("runId", json!(run_id))]));
            if let Some(run) = reply
                .get("deployment")
                .and_then(|section| section.get("Run"))
                .filter(|value| !value.is_null())
                .cloned()
            {
                if let Some(form) = self.form.as_mut() {
                    form.refresh_run(run);
                }
            }
        }

        // 当前响应只认**最近一次真实读数**（75 秒内），不再拿 status 里的
        // 历史值顶替：引擎停十分钟后界面还在报十分钟前的数，是最难解释的那种错。
        let active_summary = summaries
            .iter()
            .find(|(id, _)| id == selected)
            .map(|(_, v)| v)
            .unwrap_or(&Value::Null);
        let mut fresh = active_summary.get("Fresh").and_then(Value::as_bool).unwrap_or(false);
        let mut last_ms = active_summary.get("LastLatencyMs").and_then(Value::as_i64);
        // 手点「测速」的结果只写进线路动作记录（`line-actions.json`），不进 30 秒采样摘要。
        // 不补这一条，用户点完测速、记录里明明写着「测得当前响应 226 ms」，卡片还是
        // 「暂未测得」——就是「点了没反应」。以最近一次成功的 Check 为准（它比采样更新）。
        if let Some(ms) = line_actions
            .iter()
            .rev()
            .find(|a| {
                a.get("Kind").and_then(Value::as_str) == Some("Check")
                    && a.get("Phase").and_then(Value::as_str) == Some("Succeeded")
                    && a.get("LatencyMs").and_then(Value::as_i64).is_some()
            })
            .and_then(|a| a.get("LatencyMs").and_then(Value::as_i64))
        {
            last_ms = Some(ms);
            fresh = true;
        }
        let degraded = fresh
            && active_summary.get("Degraded").and_then(Value::as_bool).unwrap_or(false);
        let quality = if running {
            Some(json!({
                "LatencyMs": if fresh { last_ms.map(Value::from).unwrap_or(Value::Null) } else { Value::Null },
                "Quality": if fresh { last_ms.map(band).unwrap_or("Unknown") } else { "Unknown" },
                "History": [],
                "ThirtyMinutes": Value::Null,
                "Day": Value::Null,
                "Degraded": degraded,
                "NotificationMessage": if degraded {
                    active_summary.get("NotificationMessage").and_then(Value::as_str).unwrap_or("")
                } else { "" },
            }))
        } else {
            None
        };

        let standby = if running { self.standby_json(selected) } else { Value::Null };

        let trade_name = st.get("line").and_then(Value::as_str).unwrap_or("");
        // 待清理投影：一次只显示一条（前端那张提示卡只认一条记录），处理完镜头自动
        // 落到下一条。`CanRetry=false` 只用于「记录读不出来」——那时候没有任何 id
        // 可以重试，给按钮只会让用户点进同一个失败。
        let cleanup_section = cleanup_raw
            .get("deleteCleanup")
            .cloned()
            .unwrap_or(Value::Null);
        let cleanup_read_error = cleanup_section
            .get("ReadError")
            .and_then(Value::as_str)
            .unwrap_or("");
        let cleanup_pending: Vec<Value> = cleanup_section
            .get("Pending")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let delete_operation = if !cleanup_read_error.is_empty() {
            Some(json!({
                "Id": "",
                "Name": "",
                "Kind": "Cleanup",
                "Phase": "Blocked",
                "Message": format!("待清理记录读不出来：{cleanup_read_error}"),
                "StartedAtUtc": "",
                "CanCancel": false,
                "CanRetry": false,
                "CanCheck": false,
            }))
        } else if let Some(item) = cleanup_pending.first() {
            let text_of = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or("");
            let left = cleanup_pending.len().saturating_sub(1);
            let more = if left > 0 {
                format!("（另有 {left} 条待清理，处理完这条后依次显示）")
            } else {
                String::new()
            };
            Some(json!({
                "Id": text_of("Id"),
                "Name": text_of("Name"),
                "Kind": "Cleanup",
                "Phase": "Blocked",
                "Message": format!(
                    "线路「{}」已从配置删除，但本地引擎配置 {} 没删掉：{}{more}",
                    text_of("Name"), text_of("File"), text_of("Error")
                ),
                "StartedAtUtc": "",
                "CanCancel": false,
                "CanRetry": true,
                "CanCheck": false,
            }))
        } else {
            None
        };
        // 被中断的线路动作：页面「待处理」区逐条给「查看并处理」（A6 第二轮）。
        // 只收 `NeedsReview`——失败但结论明确的动作有「重试」，不需要待处理提示。
        // 通用操作（连接/断开）排在前面：它们的结果决定「现在到底能不能上网」，
        // 比一条测速记录更急（`app.js` 的 ReviewOperation 入口优先找 Connection）。
        let mut pending_actions: Vec<Value> = operation_records
            .iter()
            .filter(|record| {
                record.get("Phase").and_then(Value::as_str) == Some(crate::oprecord::NEEDS_REVIEW)
            })
            .map(pending_operation_of_record)
            .collect();
        pending_actions.extend(
            line_actions
                .iter()
                .filter(|action| {
                    action.get("Phase").and_then(Value::as_str) == Some(crate::lineaction::NEEDS_REVIEW)
                })
                .map(pending_operation_of),
        );
        // A6：失败但可安全重放的操作（连接/断开/诊断）。只收 `Retry.CanRetry`
        // 由记录层算出来的那几条——页面不再自己按 Kind/Phase 猜。
        let retryable_actions: Vec<Value> = operation_records
            .iter()
            .rev()
            .filter(|record| {
                record
                    .get("Retry")
                    .and_then(|plan| plan.get("CanRetry"))
                    .and_then(Value::as_bool)
                    == Some(true)
            })
            .take(3)
            .map(|record| {
                let text = |key: &str| {
                    record
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let kind = text("Kind");
                json!({
                    "Id": text("Id"),
                    "Kind": kind,
                    "Label": crate::oprecord::label(&kind),
                    "Message": text("Message"),
                    "StartedAtUtc": text("StartedAtUtc"),
                    "RetryLabel": record
                        .get("Retry")
                        .and_then(|plan| plan.get("Label"))
                        .and_then(Value::as_str)
                        .unwrap_or("重试"),
                    "RetryNote": record
                        .get("Retry")
                        .and_then(|plan| plan.get("Note"))
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                })
            })
            .collect();
        // AI 工具走向：**两个字段，各说一件事**。
        // - `Agents` = 实际生效值（全局覆盖、以及「这条线路没有交易出口」都算进去）：
        //   首页「应用走向」那一行读它，绝不能写一句「使用交易线路」而实际一条规则都没生成。
        // - `AgentsStored` = 配置里存的值：应用页那个下拉显示它，否则用户选了 trade 却看到
        //   daily（因为线路没出口），会以为「点了没保存」。
        // 两者不一致时应用页多显示一句说明（见 `web/app.js` 的 `agents-inactive-note`）。
        let agents_stored_raw = st.get("agentsLane").and_then(Value::as_str).unwrap_or("daily");
        let agents_stored = if agents_stored_raw.eq_ignore_ascii_case("trade") { "Trade" } else { "Daily" };
        let agents_effective = crate::agents::snapshot_lane(
            agents_stored_raw,
            &exit_lane(&st, "exitDaily"),
            st.get("tradeExitPresent").and_then(Value::as_bool).unwrap_or(false),
        );
        let rendered_form = self.form.as_ref().map(FormState::render).unwrap_or(Value::Null);
        let state = json!({
            "Text": {},
            "ConnectionMethods": [],
            "Version": env!("CARGO_PKG_VERSION"),
            "Ack": self.ack,
            "Form": rendered_form,
            "State": state_key,
            "Running": running,
            // 状态投影自己的动作与原因：会话不完整（引擎还活着、守护已死）时，
            // 宿主判定要「断开」而不是再连一次；首页必须照这个动作给按钮，
            // 否则会出现「状态说需要处理、按钮却是连接」的死路。
            "Action": st.get("action").and_then(Value::as_str).unwrap_or(""),
            "StatusDetail": st.get("detail").and_then(Value::as_str).unwrap_or(""),
            "Busy": self.busy,
            // 阶段文案：正在连接 / 正在测速 / 正在诊断 …… 只在有操作在飞时存在。
            // `Operation.Message` 早就是真消息，这个字段以前是空串——于是「正在做什么」
            // 只有按钮转圈，没有一句话。两者出自同一份状态，不该一个有一个没有。
            "BusyMessage": self
                .operation
                .as_ref()
                .and_then(|operation| operation.get("Message"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            "DeleteOperation": delete_operation.unwrap_or(Value::Null),
            // 删除重试是同步的（删一个本地文件），没有「刷新列表」这一步：
            // 待清理列表本来就每帧重读，所以这一项永远是 `null`。
            "DeleteRefresh": Value::Null,
            "PendingOperations": pending_actions,
            "RetryableOperations": retryable_actions,
            "ReadOnly": false,
            "NinjaRunning": false,
            "PendingConnectionName": pending_connect_name,
            "NodeName": "",
            "TradeName": trade_name,
            // 交易出口的**实际 tag**（线路文件里那个名字），不是常量。
            // 以前恒给 "hk"：非 hk 命名的出口被硬说成香港，任何按 tag 判归属的地方都会错。
            // 取不到（没配交易出口 / 读配置失败）就是空串——「不知道」不该伪装成某个地名。
            "TradeExit": st.get("exitTrade").and_then(Value::as_str).unwrap_or(""),
            "ActiveLineId": selected,
            // IPC emits display labels; keep exact legacy tokens without guessing unknown values.
            "ActiveProfile": match st.get("transportActual").and_then(Value::as_str) {
                Some("标准连接" | "UDP") => "Udp",
                Some("兼容连接" | "TCP") => "Tcp",
                _ => "",
            },
            "PreferredLineId": selected,
            "HomeLineId": selected,
            // 交易保护三态：**只来自后端 status 的判定**（`ipc::status_json` → `guard::status`）。
            // 缺字段时兜底为「无法确认」，**绝不**兜底成 `Protected`——那是 PRD 要消灭的那类谎。
            "Guard": st.get("Guard").and_then(Value::as_str).unwrap_or("Unknown"),
            "TradeProgramCount": st.get("TradeProgramCount").and_then(Value::as_i64).unwrap_or(-1),
            // 名单进程总数（含 direct/daily/unresolved）：区分「尚未添加」与「全设直连」。
            "TradeProgramListed": st.get("TradeProgramListed").and_then(Value::as_i64).unwrap_or(-1),
            // 线路页底部那块只读名单：程序 / 网站 / 辅助解析三组，只含交易出口的条目。
            "TradeList": trade_list_view(&st),
            "Daily": exit_lane(&st, "exitDaily"),
            // 下拉的可用性由宿主给：页面只渲染，不自己判断「什么算代理」。
            "DailyChoices": daily_choices(&st),
            // 实际生效值 / 存储值：字段名与取值集合不变（Daily/Trade）。
            "Agents": agents_effective,
            "AgentsStored": agents_stored,
            "Lines": lines,
            "Providers": providers,
            "Tasks": tasks,
            "Deployments": deployments,
            // 三态读取结论 + 坏了几条：**必须一起给**，否则页面只能二选一
            // （要么把「有 1 条坏了」显示成空列表，要么整块不显示）。
            "TasksRead": tasks_read,
            "TasksReadError": tasks_read_error,
            "UnreadableCount": unreadable_count,
            // 未读的部署结果（P1-3）：重启后仍在，打开任务即标记已读。
            "Reminders": reminders,
            "RemindersError": reminders_error,
            // 已归档（P2-2）：列表里不显示，但能看见、能恢复。
            "Archived": archived,
            // 草稿总览（C6）：`{Count,OldestDays,HasAge,Stale,StaleDays,Max,Summary,Hint}`。
            "Drafts": drafts,
            // 线路动作记录读不出来时页面必须说「不知道」：否则测速/保存的结果看起来
            // 像「从没点过」，「待核对」入口也随之消失——而文件还在那里没被处理。
            "LineActionsReadError": line_actions_read_error,
            // 连接/断开记录读不出来同理：那是「上次操作到底有没有生效」的唯一线索。
            "OperationsReadError": operations_read_error,
            "CanBackground": can_background,
            "CanBackgroundRunId": can_background_run,
            "Quality": quality,
            "Standby": standby,
            "QualityHistory": self.quality_history.clone().unwrap_or(Value::Null),
            "Settings": {
                "OpenAtLogin": st.get("autoStart").and_then(Value::as_bool).unwrap_or(false),
                "AutoConnectOnLogin": st.get("autoConnect").and_then(Value::as_bool).unwrap_or(false),
                "CloseBehavior": if st.get("closeToTray").and_then(Value::as_bool).unwrap_or(false) { "Tray" } else { "ExitInterface" },
                "AutoTrustFirstConnection": st
                    .get("autoTrust")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                "QualityWarning": st.get("qualityWarning").and_then(Value::as_bool).unwrap_or(true),
                // 引擎程序：设置页那一行要显示「已选用哪一个 / 还没选」。
                // 缺了引擎点连接会被拒，所以这句必须来自宿主事实，不能由页面猜。
                "EngineBinary": st.get("engineBinary").and_then(Value::as_str).unwrap_or(""),
                "EngineMissing": st.get("engineMissing").and_then(Value::as_bool).unwrap_or(true),
                "Warning": "",
            },
            "ReadWarning": st.get("linesReadError").and_then(Value::as_str).unwrap_or(""),
            "AutoConnectNotice": "",
            "Dialog": self.dialog.clone(),
            "Toast": self.toast.clone(),
            "SnapshotAtUtc": now_rfc3339(),
            // 连接起点（RFC3339）。字段名是 旧版的契约，页面用它算「引擎已运行 N 分」。
            // 只在「已连接」时由 `status_json` 给出；未连接一律 `null`——
            // 给一个旧起点比给 `null` 更糟：那会显示「已运行 3 小时」而实际没在跑。
            "ConnectedSince": st
                .get("startedAt")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(|value| Value::String(value.to_string()))
                .unwrap_or(Value::Null),
            // 一句话说明与三态出自**同一份证据**（后端句子优先，前端不拼文案）。
            "GuardSummary": st.get("GuardSummary").and_then(Value::as_str).unwrap_or(""),
            // 证据时龄与来源（PRD §7 的五个新字段）：**必须随三态一起出现**，
            // 否则「已保护」就成了一句没有时间锚的话。断开确认对话框也要用它们
            // （T04：「断开后仍会阻止…（依据 N 分钟前的核验）」）。
            "GuardVerifiedAtUtc": st.get("GuardVerifiedAtUtc").cloned().unwrap_or(Value::Null),
            "GuardEvidenceAge": st.get("GuardEvidenceAge").and_then(Value::as_str).unwrap_or(""),
            // 「本次强制失效事件之后有没有重新核验成功」（A23）。它**不改三态**，
            // 界面据此在「已保护（较旧）」后面补一句「本次未能重新核验」。
            // 缺字段时给 `Unknown`：说「不知道有没有核验」比假装「没有待办」安全。
            "GuardVerifyPending": st
                .get("GuardVerifyPending")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
            // R25-1：管理员进程的视角说明（普通权限进程为空串）。前端只在非空时追加，
            // 空串 = 什么都不加，绝不拿它代替三态文案。
            "GuardPerspectiveNote": st
                .get("GuardPerspectiveNote")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "GuardEvidenceAgeSeconds": st
                .get("GuardEvidenceAgeSeconds")
                .cloned()
                .unwrap_or(Value::Null),
            // ≥20 分钟 → 界面显示「较旧」并给「重新核验」按钮（需要管理员确认）。
            "GuardEvidenceStale": st
                .get("GuardEvidenceStale")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "GuardEvidenceSource": st
                .get("GuardEvidenceSource")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "GuardEvidenceBootId": st
                .get("GuardEvidenceBootId")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "GuardConfigDigest": st.get("GuardConfigDigest").and_then(Value::as_str).unwrap_or(""),
            // 证据明细（诊断页与名单页逐条状态用）：原样透传，缺了就是 null。
            "GuardEvidence": st.get("GuardEvidence").cloned().unwrap_or(Value::Null),
            "Pending": pending_connect.unwrap_or(Value::Null),
            "ExitEvidence": {
                // 三档由宿主一次判好（`ipc::exit_evidence`）：`verified` 才允许说「出口已核验」。
                "Verified": st.get("exitEvidence").and_then(Value::as_str) == Some("verified"),
                "Attribution": st
                    .get("exitAttribution")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown"),
                "Status": st.get("exitEvidence").and_then(Value::as_str).unwrap_or("unverified"),
                "Code": "",
                // 出口证据的时刻优先用观测时刻：自检时刻只说明「转发通了」。
                "CheckedAtUtc": st
                    .get("exitProbeAtUtc")
                    .and_then(Value::as_str)
                    .or_else(|| st.get("checkAtUtc").and_then(Value::as_str)),
                "ObservedIP": st.get("exitObservedIp").and_then(Value::as_str),
            },
            "Operation": self.operation.clone(),
            "Pair": self.pair_json(),
            "Invite": self.invite_view(),
            "PairDeviceDefault": self.device_default,
        });
        self.toast.clear();
        json!({"Type": "snapshot", "Page": self.page, "State": state})
    }

    /// 配对会话的投影。字段名必须与旧版完全一致：页面按 `Phase` 决定显示
    /// 输入框、进度还是结果卡，按 `NextAction` 决定给哪个主按钮。
    fn pair_json(&self) -> Value {
        let Some(p) = self.pair.as_ref() else {
            return Value::Null;
        };
        json!({
            "PairId": p.pair_id,
            "Phase": p.phase,
            "StageLabel": p.stage_label,
            "StageChangedAtUtc": p.stage_changed_at,
            "DeviceName": p.device_name,
            "LocalName": p.local_name,
            "NodeName": p.node_name,
            "Host": p.host,
            "ExpiresAtUtc": p.expires_at,
            "ErrorCode": p.error_code,
            "ErrorMessage": p.error_message,
            "NextAction": p.next_action,
            "Epoch": p.epoch,
            // 离线交接：申请原文是公开资料（要交给管理端），可以投影；
            // 邀请原文也是公开签署物（不含令牌），但只在离线模式下投影。
            "Offline": p.offline,
            "OfflineInvite": if p.offline { p.offline_invite.clone() } else { String::new() },
            "OfflineFingerprint": p.offline_fingerprint,
            "OfflineRequest": p.offline_request,
            "PairingCode": p.pairing_code,
            "EnrollmentId": p.enrollment_id,
        })
    }

    /// 一条线路的 30 分钟摘要：命中缓存就不再读采样文件（快照每秒重建一次）。
    /// 缓存键带上连接方式，`标准` 与 `兼容` 的读数不会互相串。
    fn quality_for(&mut self, fetch: &dyn Fn(&str) -> Value, line_id: &str, profile: &str) -> Value {
        let key = format!("{line_id}|{profile}");
        if let Some((at, value)) = self.quality_cache.get(&key) {
            if at.elapsed() < std::time::Duration::from_secs(30) {
                return value.clone();
            }
        }
        let cmd = json_cmd("quality-summary", &[("id", json!(line_id)), ("profile", json!(profile))]);
        let reply = fetch(&cmd);
        let summary = reply.get("qualitySummary").cloned().unwrap_or(Value::Null);

        self.quality_cache
            .insert(key, (std::time::Instant::now(), summary.clone()));
        summary
    }

    /// 备用线路读数（后台线程每 30 秒写一次）→ 旧版的 `Standby` 形状。
    /// 新鲜度在这里算：缓存里存的是测量时刻，页面刷新时才判 180 秒过期。
    fn standby_json(&self, selected: &str) -> Value {
        let items = match self.standby.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return Value::Null,
        };
        if items.is_empty() {
            return Value::Null;
        }
        let now = now_unix();
        let projected: Vec<Value> = items
            .iter()
            .filter(|item| item.get("NodeId").and_then(Value::as_str) != Some(selected))
            .map(|item| {
                let at = item.get("AtUnix").and_then(Value::as_i64).unwrap_or(0);
                let fresh = now - at <= 180;
                json!({
                    "NodeId": item.get("NodeId").cloned().unwrap_or(json!("")),
                    "Name": item.get("LineName").cloned().unwrap_or(json!("")),
                    "LatencyMs": if fresh { item.get("LatencyMs").cloned().unwrap_or(Value::Null) } else { Value::Null },
                    "Fresh": fresh,
                    "Reason": if fresh { "" } else { "SampleExpired" },
                    "Source": "TcpConnect",
                })
            })
            .collect();
        // 推荐 = 新鲜、有读数的里面最快的那条。只是建议，点了仍然走完整连接事务。
        let best = projected
            .iter()
            .filter(|item| item.get("Fresh").and_then(Value::as_bool).unwrap_or(false))
            .filter(|item| item.get("LatencyMs").and_then(Value::as_u64).is_some())
            .min_by_key(|item| item.get("LatencyMs").and_then(Value::as_u64).unwrap_or(u64::MAX))
            .cloned();
        json!({"Items": projected, "Recommendation": best.unwrap_or(Value::Null)})
    }

    fn project_line(
        &self,
        l: &Value,
        selected: &str,
        running: bool,
        trade_is_line: bool,
        st: &Value,
        quality30m: &Value,
        servers: &[Value],
        actions: &[Value],
        auto_routes: &Value,
    ) -> Value {
        let id = l.get("id").and_then(Value::as_str).unwrap_or("");
        // 这条线路是否属于某台本机保存的服务器：属于才给「邀请其他电脑」。
        // 判据是 `servers` 命令算出的归属（线路文件里的出站地址 == 记录里的 host）。
        let invite_server = servers.iter().find(|server| {
            server
                .get("LineIds")
                .and_then(Value::as_array)
                .map(|ids| ids.iter().any(|item| item.as_str() == Some(id)))
                .unwrap_or(false)
        });
        let in_use = running && id == selected && trade_is_line;
        // 连接方式用 `lines_payload` 给的**生效值**（后端 `effective_transport()` 的结果：
        // 用户固定 → 已验证 → 标准）。缺字段按标准连接兜底——与那个默认一致，
        // 不能像以前那样兜成 Tcp（那会让「没配置」的线路看起来像选了兼容连接）。
        let transport = l.get("transport").and_then(Value::as_str).unwrap_or("udp");
        let profile = match transport {
            "tcp" => "Tcp",
            _ => "Udp",
        };
        // 「这一档是用户选的」还是「自动」：以前硬编码 `""`，于是界面永远说「自动选择」，
        // 哪怕用户刚选了兼容并已落盘——这是一句假话，比缺功能严重。
        let transport_selected = l
            .get("transportSelected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transport_verified = l
            .get("transportVerified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Readiness（宿主定文案）：在用 > 已测可用 > 未测试。M3 之后再补 LastConnected/TestFailed。
        let readiness = if in_use {
            json!({"State": "InUse", "Label": "使用中", "Reason": ""})
        } else if running && id == selected {
            json!({"State": "ProviderBackup", "Label": "交易暂走代理软件", "Reason": "切回这条线路不需要重启通道"})
        } else if id == selected && st.get("latencyMs").and_then(Value::as_i64).is_some() {
            json!({"State": "Verified", "Label": "可用", "Reason": ""})
        } else {
            json!({"State": "Untested", "Label": "未测试", "Reason": "还没有测试过"})
        };
        let busy_now = self.busy;
        // 这条线路最近一次「测速 / 保存连接方式」的结果（A6 第二轮）。记录在磁盘上、
        // 要活过重启，所以每帧从快照带来的记录里投影，不在这里缓存。
        let feedback: Vec<Value> = actions
            .iter()
            .filter(|action| action.get("LineId").and_then(Value::as_str) == Some(id))
            .filter(|action| {
                action.get("Phase").and_then(Value::as_str) != Some(crate::lineaction::PENDING)
            })
            .map(line_feedback_of)
            .collect();
        json!({
            "Id": id,
            "Name": l.get("name").and_then(Value::as_str).unwrap_or("我的线路"),
            "Profile": profile,
            "Prepared": true,
            "Readiness": readiness,
            "ProfileSource": if transport_selected { "UserChoice" } else { "Auto" },
            // 自动、且这条线路还没有任何已验证的依据 → 页面那句
            // 「已选自动，请先测试线路以确定下次使用的方式。」在这时才是真话。
            "AutomaticNeedsCheck": !transport_selected && !transport_verified,
            // A8：这条线路最近一次自动探测的结论。没测过就是 null，页面据此显示
            // 「自动：未测量」，而不是拿配置里的偏好冒充结论。
            "AutoRoute": auto_routes
                .get("Lines")
                .and_then(|lines| lines.get(id))
                .cloned()
                .unwrap_or(Value::Null),
            "PreparedProfiles": ["Udp", "Tcp"],
            "Pending": "",
            "Feedback": feedback,
            "Blocked": false,
            "BlockedReason": "",
            "LastOutcome": Value::Null,
            "RecentConnectionFailure": Value::Null,
            "DeleteAvailability": {"CanDelete": !busy_now, "State": "NeedsCheck", "Message": "删除前检查使用情况"},
            "Quality30m": quality30m,
            "CanInvite": invite_server.is_some(),
            "ServerRecordId": invite_server
                .and_then(|server| server.get("Id"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            "ServerName": invite_server
                .and_then(|server| server.get("Name"))
                .and_then(Value::as_str)
                .unwrap_or(""),
        })
    }
}

/// 出口成员 → 旧版车道值（Direct/Provider/Trade）。Trade = 既非直连也非本机代理的成员。
fn exit_lane(st: &Value, field: &str) -> String {
    let value = st.get(field).and_then(Value::as_str).unwrap_or("");
    if value.is_empty() {
        return String::new();
    }
    match lane_of_member_value(value) {
        "direct" => "Direct".into(),
        "provider" => "Provider".into(),
        _ => "Trade".into(),
    }
}

fn lane_of_member_value(value: &str) -> &'static str {
    match value {
        "direct" | "tc-direct" => "direct",
        v if v.starts_with("provider") => "provider",
        _ => "trade",
    }
}

/// status 里的 `tradeList`（lowercase）→ 页面用的 `TradeList`（PascalCase）。
///
/// 线路页照旧版的版式分三组渲染（程序 / 网站 / 辅助解析），字段名必须与页面
/// 现有的 PascalCase 习惯一致，不能把 status 的形状原样丢过去。
///
/// 缺字段（老快照、读配置失败）时给三个空数组而**不是** `null`：页面直接 `.map`
/// 渲染，`null` 会让整块连「连接后显示…」那句空态都消失，看起来像功能没了。
fn trade_list_view(st: &Value) -> Value {
    let list = st.get("tradeList");
    let programs: Vec<Value> = list
        .and_then(|l| l.get("programs"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|p| {
                    json!({
                        // 名字是正文，路径只进 title：长路径铺在正文里会把这一行撑坏。
                        "Name": p.get("name").and_then(Value::as_str).unwrap_or(""),
                        "Path": p.get("path").and_then(Value::as_str).unwrap_or(""),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let domains: Vec<Value> = list
        .and_then(|l| l.get("domains"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // 本版没有「辅助解析」，但字段必须存在且是数组：页面只按数组判空组。
    let aux_domains: Vec<Value> = list
        .and_then(|l| l.get("aux"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "Programs": programs,
        "Domains": domains,
        "AuxDomains": aux_domains,
    })
}

/// 「日常上网」下拉的三个选项：哪个现在真的可选、不可选的原因。
///
/// 之前页面把三项恒列出来，选完才发现不行——`daily` 事件拿 `exitDailyMembers` 反查
/// 成员，查不到只回一句 toast。现在把同一个判据（`lane_of_member_value`）提前到渲染，
/// 不可用的直接置灰并写明原因；**前端不再自己判断「什么算代理」**，避免两套口径。
fn daily_choices(st: &Value) -> Value {
    let members = st.get("exitDailyMembers").and_then(Value::as_array);
    let has = |lane: &str| {
        members
            .map(|list| {
                list.iter().any(|member| {
                    lane_of_member_value(
                        member.get("value").and_then(Value::as_str).unwrap_or(""),
                    ) == lane
                })
            })
            .unwrap_or(false)
    };
    let provider = has("provider");
    let trade = has("trade");
    serde_json::json!([
        {"Value": "Direct", "Label": "本地直连", "Available": true, "Reason": ""},
        {
            "Value": "Provider", "Label": "使用代理软件", "Available": provider,
            "Reason": if provider { "" } else { "还没有登记代理软件" },
        },
        {
            "Value": "Trade", "Label": "使用交易线路", "Available": trade,
            "Reason": if trade { "" } else { "这条线路没有交易出口" },
        },
    ])
}

/// 把页面给的走向值反查成引擎 selector 成员。
fn daily_member(fetch: &dyn Fn(&str) -> Value, want: &str) -> Option<String> {
    let st = fetch(r#"{"cmd":"status"}"#);
    let members = st.get("exitDailyMembers").and_then(Value::as_array)?;
    members
        .iter()
        .map(|m| m.get("value").and_then(Value::as_str).unwrap_or(""))
        .find(|v| lane_of_member_value(v) == lane_of_member_value(want))
        .map(str::to_string)
}

fn line_name(fetch: &dyn Fn(&str) -> Value, id: &str) -> String {
    find_line(fetch, id)
        .and_then(|l| l.get("name").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| "这条线路".to_string())
}

/// 删除线路的对话框：先看预览的结论，再决定给不给「删除」按钮。
///
/// 三种结果共用一张卡：能删 → 危险确认；不能删 → 只读说明（**没有删除按钮**，
/// `Scope=delete-blocked` 的确认是一次 no-op）；预览本身读失败 → 原话说明。
/// 没有预览结论时绝不落回「点一下就删」的旧路径。
fn delete_dialog(preview: &Value, id: &str) -> Value {
    let blocked_dialog = |body: String| {
        json!({
            "Id": format!("delete-blocked-{id}"),
            "Title": "暂时无法删除线路",
            "Body": body,
            "Note": "",
            "Confirm": "知道了",
            "Cancel": "",
            "Danger": false,
            "Details": "",
            "Progress": false,
            "Scope": "delete-blocked",
            "Target": id,
        })
    };

    if preview.get("ok").and_then(Value::as_bool) != Some(true) {
        let message = preview
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("读不出删除预览，请稍后重试。");
        return blocked_dialog(message.to_string());
    }

    let detail = preview.get("deletePreview").cloned().unwrap_or(Value::Null);
    let eligible = detail
        .get("Eligible")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !eligible {
        let messages: Vec<String> = detail
            .get("Blocked")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        item.get("Message").and_then(Value::as_str).map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let body = if messages.is_empty() {
            "这条线路现在不能删除。".to_string()
        } else {
            messages.join("；")
        };
        return blocked_dialog(body);
    }

    let name = detail
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or("这条线路");
    let files: Vec<&str> = detail
        .get("Files")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut removals = vec![format!("config.json 里的「{name}」（id: {id}）")];
    for file in &files {
        removals.push(format!("{file}（线路引擎配置，含隧道私钥）"));
    }
    let mut kept = Vec::new();
    match detail.get("Server").filter(|server| !server.is_null()) {
        Some(server) => {
            let label = server
                .get("Name")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .or_else(|| server.get("Host").and_then(Value::as_str))
                .unwrap_or("这台服务器");
            kept.push(format!("服务器记录与登录凭据（设置 → 服务器）：{label}"));
        }
        None => kept.push("这台电脑上没有与它对应的服务器记录".to_string()),
    }
    kept.push("服务器上的 WireGuard 服务与设备授权".to_string());
    kept.push("其他线路与操作记录".to_string());

    let warnings: Vec<&str> = detail
        .get("Warnings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("Message").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let body = if files.is_empty() {
        format!("确认删除「{name}」？本机会移除线路配置；服务器上的服务与设备授权不受影响。")
    } else {
        format!(
            "确认删除「{name}」？本机会移除线路配置与隧道私钥文件；服务器上的服务与设备授权不受影响。"
        )
    };
    json!({
        "Id": format!("delete-{id}"),
        "Title": "删除线路",
        "Body": body,
        "Note": warnings.join("；"),
        "Confirm": "删除",
        "Cancel": "取消",
        "Danger": true,
        "Details": format!(
            "将删除：\n{}\n\n将保留：\n{}",
            removals.join("\n"),
            kept.join("\n")
        ),
        "Progress": false,
        "Scope": "delete",
        "Target": id,
    })
}

/// 按 id 取一条线路；id 为空时退回当前选中项（个别按钮不带 data-id）。
fn find_line(fetch: &dyn Fn(&str) -> Value, id: &str) -> Option<Value> {
    let payload = fetch(r#"{"cmd":"lines"}"#);
    let items = payload.get("lines").and_then(Value::as_array)?;
    let wanted = if id.is_empty() {
        payload.get("selected").and_then(Value::as_str).unwrap_or("")
    } else {
        id
    };
    items
        .iter()
        .find(|l| l.get("id").and_then(Value::as_str) == Some(wanted))
        .cloned()
}

/// 线路的连接方式 → 采样库里的档位名（`selfcheck` 记的是这两个词）。
fn profile_of(line: &Value) -> &'static str {
    match line.get("transport").and_then(Value::as_str) {
        Some("udp") => "标准",
        _ => "兼容",
    }
}

/// 从 `line-action-list` 的回包里按 id 找一条动作记录。
/// 回包在生产上是**合并后的状态**（`merge_ui_command_reply`），所以既认键名也认
/// 「读不到就当作没有」——空 id 不猜第一条，宁可让调用方说「找不到」。
fn line_action_entry<'a>(list: &'a Value, id: &str) -> Option<&'a Value> {
    if id.is_empty() {
        return None;
    }
    list.get("lineActions")?
        .get("Actions")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("Id").and_then(Value::as_str) == Some(id))
}

/// 一条动作记录 → 前端 `lineFeedback()` 认的形状（`web/app.js:635`）。
///
/// `Status` 只有 Succeeded / Info / 其它三档：这里是「成功」与「需要注意」，
/// 没有 Info。`CanDiagnose` 只给失败的测速——保存连接方式失败时诊断也帮不上忙。
fn line_feedback_of(action: &Value) -> Value {
    let text = |key: &str| action.get(key).and_then(Value::as_str).unwrap_or("");
    let phase = text("Phase");
    let kind = text("Kind");
    let status = match phase {
        crate::lineaction::SUCCEEDED => "Succeeded",
        crate::lineaction::NEEDS_REVIEW => "NeedsReview",
        _ => "Failed",
    };
    json!({
        "Id": text("Id"),
        "Kind": kind,
        "ProfileId": text("ProfileId"),
        "Status": status,
        "Message": text("Message"),
        "Code": text("Code"),
        "AtUtc": text("AtUtc"),
        "NeedsReview": phase == crate::lineaction::NEEDS_REVIEW,
        "ReviewLabel": if kind == crate::lineaction::CHECK { "检查测试结果" } else { "确认保存结果" },
        "CanRetry": phase == crate::lineaction::FAILED,
        "CanDiagnose": kind == crate::lineaction::CHECK && phase != crate::lineaction::SUCCEEDED,
    })
}

/// 待核对动作 → 首页「待处理」提示卡（`{Id,Label,Target,Kind,Message}`）。
/// 一次只显示一条由前端决定；这里给全量，逐条都能「查看并处理」。
fn pending_operation_of(action: &Value) -> Value {
    let text = |key: &str| action.get(key).and_then(Value::as_str).unwrap_or("");
    let line_name = text("LineName");
    let profile = if text("ProfileId").eq_ignore_ascii_case("tcp") {
        "兼容连接"
    } else if text("ProfileId").eq_ignore_ascii_case("udp") {
        "标准连接"
    } else {
        "连接方式"
    };
    let subject = if text("Kind") == crate::lineaction::CHECK {
        format!("{profile}测试")
    } else {
        format!("{profile}保存")
    };
    json!({
        "Id": text("Id"),
        "Kind": "LineAction",
        "Label": format!("{line_name} · {subject}"),
        "Target": text("LineId"),
        "Message": format!(
            "线路「{line_name}」的{subject}结果尚未确认：上次程序退出时还没拿到结论，请先核对。"
        ),
    })
}

/// 一条被中断的界面长操作 → 首页「待处理」提示卡。
///
/// `Kind` 固定 `Connection`：`app.js` 的「ReviewOperation → 查看并处理」按它优先取
/// 待处理项；用 `Label` 区分连接/断开/诊断，不另造一个前端不认识的新类型。
fn pending_operation_of_record(record: &Value) -> Value {
    let text = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or("");
    let (label, message) = match text("Kind") {
        crate::oprecord::CONNECT => (
            "连接",
            "上次「连接」没有拿到结果（程序在操作完成前退出了）。现在是否已连接、系统代理是否还原都还没确认，请先核对。",
        ),
        crate::oprecord::DISCONNECT => (
            "断开",
            "上次「断开」没有拿到结果（程序在操作完成前退出了）。现在是否还连接着、系统代理是否还原都还没确认，请先核对。",
        ),
        crate::oprecord::DIAGNOSE => (
            "诊断",
            "上次「诊断」没有拿到结果（只读操作，不会改动系统）；可以重新运行诊断。",
        ),
        _ => (
            "操作",
            "上次操作没有拿到结果（程序在操作完成前退出了），请先核对。",
        ),
    };
    json!({
        "Id": text("Id"),
        "Kind": "Connection",
        "Label": label,
        "Target": "",
        "Message": message,
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 旧版的分档：`>=500` 较差、`>200` 一般、其余良好。
/// 阈值必须与宿主 `quality-summary` 里 `Sample::quality` 同一套，否则同一读数
/// 在标题和统计卡上会是两种说法。
fn band(ms: i64) -> &'static str {
    if ms >= 500 {
        "Poor"
    } else if ms > 200 {
        "Fair"
    } else {
        "Good"
    }
}

/// 错误码 → 页面上的主按钮。`Retry` 表示「再试一次可能就好」，`Reenter` 表示
/// 「得换一张邀请码或改名字」，空表示「说什么都没用，只能重新开始」。
fn pair_next_action(code: &str) -> &'static str {
    match code {
        // 网络抖动、本机端口/文件一时不可用：同一步重来一次是对的动作。
        "OnlineConnectionFailed"
        | "OnlineTimeout"
        | "ConnectionBusy"
        | "LinePortUnavailable"
        | "LineWriteFailed"
        | "LineConfigSaveFailed"
        | "LineConfigUnavailable"
        | "LineGenerationFailed" => "Retry",
        // 服务器上的邀请服务是旧版本：**码本身还能用**，对方重开一次接收服务之后，
        // 回到这一步再点一次就成。给「重新输入」等于让人把一张好码扔掉。
        "InviteServerOutdated" => "Retry",
        "InvalidOnlineCode"
        | "InvalidOnlineHost"
        | "OnlineInviteExpired"
        | "InviteExpired"
        | "InviteCancelled"
        | "InviteConsumed"
        | "OnlineTlsPinMismatch"
        | "OnlineInviteIdentityMismatch"
        | "InvalidDeviceName"
        | "InvalidOnlineResponse"
        | "OnlineOperationFailed" => "Reenter",
        _ => "Reenter",
    }
}

/// 从 `guard-precheck` 的合并状态里取「正在运行的名单程序」（P0-13 的前置提示用）。
///
/// 连接侧（`connect`）与启用侧（`guardEnable`）读的是**同一份**预检回包，
/// 解析也只许有一份：两处各写一遍，迟早有一处漏读 `RunningPrograms` 就直接放行。
///
/// # 为什么名字是 `absorb_` 前缀
///
/// **不是**因为它改 `self`（它什么都不改，纯读）。是为了让
/// `ui_reply_whitelist_covers_every_key_finish_op_reads` 第 1 步的自动发现扫到它：
/// 那条规则只认 `fn finish_op` 与 `fn absorb*`，用别的名字写「读合并状态」的助手
/// 会整条绕开扫描——r54 的 P0 就是这么漏出去的（`RunningPrograms` 不在白名单里，
/// 真机上确认框永不出现，而所有单测全绿）。
///
/// 形参叫 `state` 也是同一个原因：`collect_keys` 只从 `state` / `reply` 这两个形参名
/// 后面找 `get("…")`。生产给的本来就是「status + 白名单合并」的状态包（见
/// [`merge_ui_command_reply`]），这个名字也更准。
fn absorb_precheck_running(state: &Value) -> Vec<String> {
    state
        .get("RunningPrograms")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter().filter_map(Value::as_str).map(str::to_string).collect()
        })
        .unwrap_or_default()
}

fn json_cmd(cmd: &str, fields: &[(&str, Value)]) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("cmd".into(), json!(cmd));
    for (k, v) in fields {
        obj.insert((*k).to_string(), v.clone());
    }
    Value::Object(obj).to_string()
}

/// 开始生成另一张邀请时，上一张的结果不能继续驱动页面。
///
/// 这不作废服务器上的旧邀请（那只能显式点「取消邀请码」），只是本机不再持有或展示它。
fn clear_issued_invite(session: &mut InviteSession) {
    session.invite_id.clear();
    session.code.clear();
    session.state.clear();
    session.expires_at.clear();
    session.device_name.clear();
    // 离线交接的两份交付物也必须一起清：换了邀请还留着上一张的申请/授权，
    // 用户会把旧授权交给新电脑，而它绑的是另一张邀请。
    session.invite_jws.clear();
    session.fingerprint.clear();
    session.offline_request.clear();
    session.offline_authorization.clear();
    session.offline_device.clear();
    session.offline_pairing_code.clear();
}

/// 邀请失败之后页面该给哪个按钮。
///
/// 留空会让页面兜底成「重试」，而「这台服务器不归你管」重试一百次也是同一句话。
fn invite_next_action(code: &str) -> &'static str {
    match code {
        "InviteNeedsServer" | "InviteNeedsIPv4" | "InviteCredentialMissing" | "InviteNeedsSetup" => {
            "OpenServer"
        }
        // 已经用掉的邀请不能作废：只能重新生成一张。
        "InviteConsumed" => "CancelRetry",
        _ => "Retry",
    }
}

/// 命令名 → 人话。后台终态回包里只有 `cmd`，没有 `Kind`。
///
/// 长命令的**全局闸门**（`ui::OperationBook`）也用它：被挡下的那句话必须说清
/// 「正在做什么」，只写「忙」等于让用户自己猜该等谁。所以这张表要覆盖
/// `ipc::is_long_command` 里的每一条——漏一条就会退化成「正在操作，等它结束再试」。
pub(crate) fn command_label(cmd: &str) -> &'static str {
    match cmd {
        "connect" => "连接",
        "disconnect" => "断开",
        "diagnose" => "诊断",
        "measure-latency" => "测速",
        "restore" => "恢复配置",
        "import" => "导入配置",
        "use-compatible" => "切换兼容连接",
        "pair-verify" | "pair-join" | "pair-offline-request" | "pair-offline-complete" => "配对",
        "invite-init" | "invite-create" => "创建邀请",
        "invite-status" => "读取邀请状态",
        "invite-cancel" => "作废邀请",
        "invite-authorize" => "批准邀请",
        "invite-reachability" => "检查服务器可达性",
        "invite-preflight" => "检查接收服务",
        "server-probe" => "检查服务器",
        "server-devices" => "读取设备列表",
        "server-device-rename" => "重命名设备",
        "server-device-forget" => "移除设备",
        "server-revoke" => "撤销设备",
        "server-uninstall-preview" => "检查卸载条件",
        "server-uninstall" => "卸载通道服务",
        "line-add-compatible" => "补兼容连接",
        "operation-retry" => "按记录重试",
        "auto-route" => "自动选路",
        "auto-reroute" => "自动切换",
        "guard-verify" => "交易保护核验",
        "guard-install" => "交易保护启用",
        "guard-sync" => "交易保护同步",
        "guard-remove" => "交易保护撤销",
        _ => "操作",
    }
}

/// 操作条上的人话。只用于「停止等待」的提示与后台完成提示。
fn operation_label(kind: &str) -> &'static str {
    match kind {
        "Connect" => "连接",
        "Disconnect" => "断开",
        "Diagnose" => "诊断",
        "Test" => "测速",
        "GuardVerify" => "交易保护核验",
        "GuardEnable" => "交易保护启用",
        "AutoRoute" => "自动选路",
        "AutoReroute" => "自动切换",
        _ => "操作",
    }
}

fn now_rfc3339() -> String {
    // 快照的 SnapshotAtUtc/Operation.StartedAtUtc 都用它：前端按 Date.parse 算
    // 「数据过期」与「已等待秒数」，空串会被当成永远过期（首页横幅常驻）。
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// 从现在起 `seconds` 秒之后的 RFC3339——等待态的死线。
///
/// 必须给**未来时刻**：前端拿 `DeadlineUtc` 减当前时间算倒计时，把 `now_rfc3339()`
/// 填进去会让倒计时从 0 起跳，看起来像「等待已经结束了」。
fn rfc3339_after(seconds: i64) -> String {
    let at = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一份 `pair-verify` 回包。`PairId` 必须回显**当前这一轮**：
    /// 宿主现在按轮次丢弃回包，夹具不给 PairId 就等于在测「回包被丢掉」。
    fn verify_reply(ui: &WebUi, body: Value) -> Value {
        let pair_id = ui.pair.as_ref().map(|p| p.pair_id.clone()).unwrap_or_default();
        let mut verify = body;
        verify["PairId"] = json!(pair_id);
        json!({ "ok": true, "pairVerify": verify })
    }

    /// 同上，但刻意用**另一个**轮次（或空轮次）的 PairId：宿主必须整个丢掉。
    fn verify_reply_for(ui: &WebUi, pair_id: &str, body: Value) -> Value {
        let _ = ui;
        let mut verify = body;
        verify["PairId"] = json!(pair_id);
        json!({ "ok": true, "pairVerify": verify })
    }

    /// 生产里的 `fetch` 返回的是「status 载荷 + `UI_REPLY_KEYS` 白名单合并后的命令回包」
    /// （`ui.rs` 的 `fetch` → `main.rs::ui_handler` → [`merge_ui_command_reply`]），
    /// **不是**命令回包本身。
    ///
    /// 一切「宿主侧读 fetch 结果」的用例都必须按这个形状喂：直接回一个命令回包形状的
    /// `{"RunningPrograms":[…]}`，等于把合并这道闸门从测试里拆掉——r54 的 P0
    /// （白名单漏 `RunningPrograms` → 真机确认框永不出现、单测全绿）就是这么漏出去的。
    fn merged_status_with(reply: Value) -> Value {
        let mut state = fetch(r#"{"cmd":"status"}"#);
        merge_ui_command_reply(&mut state, &reply);
        state
    }

    /// `guard-precheck` 的命令回包（`guard/mod.rs` 的 `precheck`，形状逐字对齐）。
    fn precheck_reply(running: Value) -> Value {
        json!({
            "ok": true,
            "TradeProgramCount": 1,
            "TradeProgramListed": 1,
            "Elevated": false,
            "WillPrompt": true,
            "Suppressed": false,
            "LegacyRunning": false,
            "RunningPrograms": running,
            "PlatformSupported": true,
            "Guard": "Unprotected",
            "GuardSummary": "交易保护未启用",
            "GuardVerifyPending": "none",
        })
    }

    fn fetch(cmd: &str) -> Value {
        let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
        let name = parsed.get("cmd").and_then(Value::as_str).unwrap_or("");
        match name {
            "status" => json!({
                "ok": true, "state": "Connected", "title": "已连接", "detail": "",
                "action": "Disconnect", "line": "香港 01", "lineCount": 2,
                "mode": "代理", "modeChoice": "proxy", "transportActual": "UDP",
                "latencyMs": 180, "measuredAtUtc": "2026-11-01T00:00:00Z",
                "exitEvidence": "forwarded-unverified", "exitObservedIp": Value::Null,
                "autoStart": false, "autoConnect": false, "closeToTray": true,
                "engineBinary": "C:/tc/bin/sing-box.exe", "engineMissing": false,
                "exitDaily": "direct", "exitTrade": "hk",
                // AI 工具：存储的走向 + 这条线路有没有交易出口
                "agentsLane": "daily", "tradeExitPresent": true,
                "exitDailyMembers": [{"value": "direct", "label": "本地直连"},
                                     {"value": "hk", "label": "香港 01"}],
                "exitTradeMembers": [{"value": "hk", "label": "香港 01"}],
                "linesRead": "ok", "linesReadError": "",
            }),
            "lines" => json!({
                "ok": true, "selected": "hk",
                "lines": [
                    {"id": "hk", "name": "香港 01", "endpoint": "1.2.3.4:443", "selected": true, "transport": "udp", "transportSelected": false},
                    {"id": "jp", "name": "东京 02", "endpoint": "5.6.7.8:443", "selected": false, "transport": "tcp", "transportSelected": true},
                ],
            }),
            "providers" => json!({"ok": true, "providers": []}),
            // 删除预览：可删（与真命令同形状）。路线 hk 没有引擎配置文件，用来覆盖
            // 「只删配置、不动私钥」的文案分支。
            "delete-preview" => {
                let id = parsed.get("id").and_then(Value::as_str).unwrap_or("");
                let (name, files) = if id == "jp" {
                    ("东京 02", json!(["lines\\jp.json"]))
                } else {
                    ("香港 01", json!([]))
                };
                json!({
                    "ok": true,
                    "deletePreview": {
                        "Id": id,
                        "Name": name,
                        "Selected": id == "hk",
                        "LastLine": false,
                        "Eligible": true,
                        "Blocked": [],
                        "Files": files,
                        "Server": {"Id": "srv-1", "Name": "root@203.0.113.10", "Host": "203.0.113.10"},
                        "Warnings": [],
                    }
                })
            }
            // 统计卡读的是采样库（不是 status 里的历史值）：线路 hk 有读数，jp 没有。
            "quality-summary" => {
                let empty = json!({
                    "SampleCount": 0, "MeasuredCount": 0, "UnavailableCount": 0,
                    "Samples": [], "Fresh": false, "Degraded": false,
                    "LastLatencyMs": Value::Null, "LastReason": Value::Null,
                });
                let summary = if parsed.get("id").and_then(Value::as_str) == Some("hk") {
                    json!({
                        "SampleCount": 3, "MeasuredCount": 2, "UnavailableCount": 1,
                        "Samples": [150, Value::Null], "MedianLatencyMs": 180, "P95LatencyMs": 210,
                        "LastLatencyMs": 180, "LastReason": "Measured", "Fresh": true,
                        "Degraded": false, "NotificationMessage": "",
                    })
                } else {
                    empty
                };
                json!({"ok": true, "qualitySummary": summary})
            }
            _ => Value::Null,
        }
    }

    /// 连接起点：只在后端给了的时候透传，没给就是 `null`。
    ///
    /// 这个字段喂的是首页那句「引擎已运行 N 分」。给一个空串或不给都对页面无害
    /// （页面自己会落到「—」），但**给一个旧起点是有害的**：会显示一个不存在的时长。
    /// 所以后端只在「已连接」时才带它（见 `ipc::status_json`），这里只负责不添油加醋。
    #[test]
    fn snapshot_passes_the_connection_start_through_and_never_invents_one() {
        let with_start = |started: Value, trade_exit: &'static str| {
            move |cmd: &str| {
                let mut base = fetch(cmd);
                if base["state"].as_str() == Some("Connected") {
                    base["startedAt"] = started.clone();
                    base["exitTrade"] = json!(trade_exit);
                }
                base
            }
        };

        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with_start(json!("2026-11-01T09:00:00Z"), "jp"));
        assert_eq!(
            snap["State"]["ConnectedSince"],
            json!("2026-11-01T09:00:00Z"),
            "后端给了起点就必须原样透传"
        );

        // 后端没给（未连接 / 时间读不出来）：必须是 null，不能是空串以外的任何东西。
        let snap = ui.snapshot(&with_start(json!(""), "jp"));
        assert_eq!(
            snap["State"]["ConnectedSince"],
            Value::Null,
            "没有起点时给 null"
        );

        // 后端压根没有这个键（旧宿主 / 读失败）：同样是 null。
        let no_key = |cmd: &str| {
            let mut base = fetch(cmd);
            if let Some(obj) = base.as_object_mut() {
                obj.remove("startedAt");
            }
            base
        };
        let snap = ui.snapshot(&no_key);
        assert_eq!(snap["State"]["ConnectedSince"], Value::Null);
    }

    /// 状态投影的 action/detail 必须原样进快照：会话不完整（引擎还活着、守护已死）
    /// 时宿主判定 `Disconnect`，首页照这个动作给「断开」。以前快照只带 State/Running，
    /// 首页于是给出「连接」——状态说「断开后重新连接」，按钮却会再连一次。
    #[test]
    fn snapshot_passes_the_status_action_and_detail_through() {
        let fault = |action: Value, detail: Value| {
            move |cmd: &str| {
                let mut base = fetch(cmd);
                if base["state"].as_str() == Some("Connected") {
                    base["state"] = json!("Fault");
                    base["action"] = action.clone();
                    base["detail"] = detail.clone();
                }
                base
            }
        };

        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fault(
            json!("Disconnect"),
            json!("会话未完整运行，请断开后重新连接。"),
        ));
        assert_eq!(snap["State"]["Action"], json!("Disconnect"), "动作原样透传");
        assert_eq!(
            snap["State"]["StatusDetail"],
            json!("会话未完整运行，请断开后重新连接。"),
            "原因原样透传"
        );

        // 旧宿主没有这两个键：空串 = 不知道，页面按原逻辑显示，不能自己编。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&|cmd: &str| {
            let mut base = fetch(cmd);
            if let Some(obj) = base.as_object_mut() {
                obj.remove("action");
                obj.remove("detail");
            }
            base
        });
        assert_eq!(snap["State"]["Action"], json!(""));
        assert_eq!(snap["State"]["StatusDetail"], json!(""));
    }

    /// 交易出口是**实际 tag**，不是常量 `hk`。
    ///
    /// 以前恒给 `"hk"`：一条叫 `jp` 的出口会被硬说成香港。快照里唯一能表达
    /// 「这条出口叫什么」的字段就是它，写死等于让所有非 hk 的部署都被念错地名。
    #[test]
    fn snapshot_reports_the_trade_exit_tag_instead_of_a_constant() {
        let with_exit = |tag: &'static str| {
            move |cmd: &str| {
                let mut base = fetch(cmd);
                if base["state"].as_str() == Some("Connected") {
                    base["exitTrade"] = json!(tag);
                }
                base
            }
        };
        let mut ui = WebUi::new();
        assert_eq!(ui.snapshot(&with_exit("jp"))["State"]["TradeExit"], json!("jp"));
        assert_eq!(ui.snapshot(&with_exit("hk"))["State"]["TradeExit"], json!("hk"));
        // 没有交易出口（direct）或读不出来：空串。**绝不**兜底成某个地名。
        assert_eq!(ui.snapshot(&with_exit(""))["State"]["TradeExit"], json!(""));
        assert_eq!(
            ui.snapshot(&with_exit("direct"))["State"]["TradeExit"],
            json!("direct"),
            "直连也是一个真实的出口 tag，不该被吞掉"
        );
    }

    /// 「日常上网」下拉：不可用的走向要当场置灰并给原因，别让用户选完再看 toast。
    /// 判据在宿主（`daily_choices`），前端只渲染——两处各写一套「什么算代理」迟早会分岔。
    #[test]
    fn the_daily_dropdown_disables_what_this_line_cannot_reach() {
        let with_members = |members: Value| {
            move |cmd: &str| {
                let mut base = fetch(cmd);
                if base.get("exitDailyMembers").is_some() {
                    base["exitDailyMembers"] = members.clone();
                }
                base
            }
        };
        let mut ui = WebUi::new();
        let only_direct = ui.snapshot(&with_members(json!([
            {"value": "direct", "label": "本地直连"}
        ])))["State"]["DailyChoices"]
            .clone();
        assert_eq!(only_direct[0]["Available"], true, "{only_direct}");
        assert_eq!(only_direct[1]["Available"], false, "没有服务商就不能选代理：{only_direct}");
        assert_eq!(only_direct[1]["Reason"], "还没有登记代理软件", "{only_direct}");
        assert_eq!(only_direct[2]["Available"], false, "没有交易出口就不能选交易线路：{only_direct}");
        assert_eq!(only_direct[2]["Reason"], "这条线路没有交易出口", "{only_direct}");

        let with_all = ui.snapshot(&with_members(json!([
            {"value": "direct", "label": "本地直连"},
            {"value": "provider:clash", "label": "代理软件（Clash Verge）"},
            {"value": "hk", "label": "香港 01"}
        ])))["State"]["DailyChoices"]
            .clone();
        for index in 0..3 {
            assert_eq!(with_all[index]["Available"], true, "三种都具备时都要能选：{with_all}");
        }
    }

    /// 「正在做什么」要有一句话，而不是只有一个转圈。
    ///
    /// `Operation.Message` 早就是真文案（「正在连接」「正在测速」…），
    /// `BusyMessage` 却一直是空串——同一份状态里一个有一个没有。
    #[test]
    fn busy_message_carries_the_operation_sentence_and_clears_with_it() {
        let mut ui = WebUi::new();
        assert_eq!(ui.snapshot(&fetch)["State"]["BusyMessage"], json!(""));

        ui.begin_op("Connect", "hk", "正在连接", "connect");
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Busy"], json!(true));
        assert_eq!(snap["State"]["BusyMessage"], json!("正在连接"));

        // 长命令回包落地后 busy 与文案必须一起消失，不能留一句过期的话。
        ui.finish_op(&json!({"ok": true}));
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Busy"], json!(false));
        assert_eq!(snap["State"]["BusyMessage"], json!(""));
    }

    #[test]
    fn snapshot_passes_the_guard_verdict_through_instead_of_hardcoding_it() {
        // `Guard`/`TradeProgramCount`/`GuardSummary` 曾经是写死的 "Unknown"/-1/""：
        // 卡片永远是灰色待确认，用户被训练成忽略它（PRD §1 次生伤害）。
        // 现在它们只能来自后端 status，快照只做透传。
        let with_status = |guard: &'static str, count: i64, summary: &'static str| {
            move |cmd: &str| {
                if cmd.contains("\"status\"") {
                    let mut v = fetch(cmd);
                    v["Guard"] = json!(guard);
                    v["TradeProgramCount"] = json!(count);
                    v["TradeProgramListed"] = json!(count);
                    v["GuardSummary"] = json!(summary);
                    v["GuardEvidence"] = json!({
                        "Source": "ElevatedVerify", "Reason": "Ok",
                        "Detection": {"ProviderPresent": true, "SubLayerPresent": true,
                                      "InfrastructureVerified": true, "BfeReady": true},
                        "Programs": [],
                    });
                    // PRD §7 的五个新字段：快照必须原样透传（界面只渲染，不自己算时龄）
                    v["GuardVerifiedAtUtc"] = json!("2026-11-05T09:00:00Z");
                    v["GuardEvidenceAge"] = json!("10 分钟前核验");
                    v["GuardEvidenceAgeSeconds"] = json!(600);
                    v["GuardEvidenceStale"] = json!(false);
                    v["GuardEvidenceSource"] = json!("ElevatedVerify");
                    v["GuardEvidenceBootId"] = json!("1762333200");
                    v["GuardConfigDigest"] = json!("abc123");
                    v["GuardVerifyPending"] = json!("None");
                    v
                } else {
                    fetch(cmd)
                }
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with_status("Protected", 2, "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。"));
        assert_eq!(snap["State"]["Guard"], "Protected");
        assert_eq!(snap["State"]["TradeProgramCount"], 2);
        assert_eq!(snap["State"]["TradeProgramListed"], 2);
        assert_eq!(
            snap["State"]["GuardSummary"],
            "交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。"
        );
        assert_eq!(snap["State"]["GuardEvidence"]["Source"], "ElevatedVerify");
        assert_eq!(snap["State"]["GuardEvidence"]["Detection"]["BfeReady"], true);
        // 时龄/来源/摘要必须一起到界面（否则「已保护」没有时间锚）
        assert_eq!(snap["State"]["GuardVerifiedAtUtc"], "2026-11-05T09:00:00Z");
        assert_eq!(snap["State"]["GuardEvidenceAge"], "10 分钟前核验");
        assert_eq!(snap["State"]["GuardEvidenceAgeSeconds"], 600);
        assert_eq!(snap["State"]["GuardEvidenceStale"], false);
        assert_eq!(snap["State"]["GuardEvidenceSource"], "ElevatedVerify");
        assert_eq!(snap["State"]["GuardEvidenceBootId"], "1762333200");
        assert_eq!(snap["State"]["GuardConfigDigest"], "abc123");
        // A23：本次核验结果必须到界面，否则「已保护（较旧）」后面那句
        // 「本次未能重新核验」永远渲染不出来。
        assert_eq!(snap["State"]["GuardVerifyPending"], "None");

        let snap = ui.snapshot(&with_status("Unprotected", 1, "交易程序直连保护未完整启用，请检查保护规则。"));
        assert_eq!(snap["State"]["Guard"], "Unprotected");
        assert_eq!(snap["State"]["TradeProgramCount"], 1);

        // 空名单：0 条，状态照后端给（前端按 count===0 走空态特例）
        let snap = ui.snapshot(&with_status("Unprotected", 0, "尚未添加要保护的程序，这不是故障。"));
        assert_eq!(snap["State"]["TradeProgramCount"], 0);
    }

    #[test]
    fn a_missing_verify_pending_field_reads_as_unknown_not_none() {
        // 「没有这个字段」与「本次核验成功」不是一回事：前者是不知道，后者才是 None。
        // 把缺字段兜底成 None，界面就会把「没核验过」说成「不需要核验」。
        let bare = |cmd: &str| {
            if cmd.contains("\"status\"") {
                let mut v = fetch(cmd);
                v["Guard"] = json!("Protected");
                v["TradeProgramCount"] = json!(1);
                v["TradeProgramListed"] = json!(1);
                v
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&bare);
        assert_eq!(snap["State"]["GuardVerifyPending"], "Unknown");
    }

    #[test]
    fn disconnect_dialog_follows_the_current_guard_verdict() {
        let with_guard = |guard: &'static str, reason: &'static str, age: &'static str| {
            move |cmd: &str| {
                if cmd.contains("\"status\"") {
                    let mut v = fetch(cmd);
                    v["Guard"] = json!(guard);
                    v["GuardEvidenceAge"] = json!(age);
                    v["GuardEvidence"] = json!({"Reason": reason});
                    v
                } else {
                    fetch(cmd)
                }
            }
        };
        let dialog = WebUi::disconnect_dialog(&with_guard("Protected", "Ok", "10 分钟前核验"));
        let text = dialog.to_string();
        assert!(text.contains("交易程序直连保护已启用"), "{text}");
        assert!(text.contains("依据10 分钟前核验"), "{text}");
        assert!(text.contains("仍会阻止名单程序直连"), "{text}");
        assert!(!text.contains("交易保护仍然生效"), "旧的无证据承诺必须删除：{text}");

        let dialog = WebUi::disconnect_dialog(&with_guard("Unprotected", "MissingFilter", ""));
        let text = dialog.to_string();
        assert!(text.contains("交易保护未启用"), "{text}");
        assert!(text.contains("可以直接上网"), "{text}");
        assert!(!text.contains("仍会阻止"), "未保护时不得说会阻止：{text}");

        let dialog = WebUi::disconnect_dialog(&with_guard("Unknown", "NotVerifiedYet", ""));
        let text = dialog.to_string();
        assert!(text.contains("交易保护状态无法确认"), "{text}");
        assert!(!text.contains("仍会阻止"), "无法确认时不得说会阻止：{text}");
    }

    #[test]
    fn re_enabling_after_a_user_removal_is_an_install_not_a_verify() {
        // `guard-verify` 只读：用它冒充「重新启用」就是假承诺。
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"guardEnable","Sequence":1}"#, &fetch);
        assert!(
            matches!(&steps[0], Step::Long(c) if c.contains("\"guard-install\"")),
            "重新启用必须真的装规则：{steps:?}"
        );
        assert!(ui.busy, "等 UAC/WFP 事务时页面要进入等待态");
    }

    /// P0-13 的**启用侧**：名单程序正在跑时，「现在重新启用」必须先问一次。
    ///
    /// 直接弹 UAC 是错的——用户会以为「规则一装，已经在跑的连接就被挡住了」。
    /// 所以这里同时钉死：不 `begin_op`（`operation` 仍为 `None`）、steps 里没有 `guard-install`。
    ///
    /// 注意 fetch 桩走 [`merged_status_with`]（生产形状）：用命令回包形状的假 fetch，
    /// 这条用例在「白名单漏 `RunningPrograms`」时依然会绿——那就不是回归测试了。
    #[test]
    fn re_enabling_asks_first_when_a_trade_program_is_running() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| {
            if c.contains("\"guard-precheck\"") {
                merged_status_with(precheck_reply(json!(["Trader.exe", "下单助手.exe"])))
            } else {
                fetch(c)
            }
        };
        let steps = ui.route(r#"{"Type":"guardEnable","Sequence":1}"#, &fetch);
        assert!(steps.is_empty(), "还没确认，一条命令都不许发：{steps:?}");
        assert!(ui.operation.is_none(), "还没确认，不能进入等待态");
        assert!(!ui.busy, "还没确认，界面不该显示在忙");

        let dialog = ui.dialog.clone().unwrap_or(Value::Null);
        assert_eq!(dialog["Id"], "guard-enable-confirm");
        assert_eq!(dialog["Title"], "交易程序正在运行");
        assert_eq!(dialog["Scope"], "guard-enable");
        assert_eq!(dialog["Target"], "");
        assert_eq!(dialog["Danger"], true);
        assert_eq!(dialog["Progress"], false);
        assert_eq!(dialog["Confirm"], "仍要启用");
        assert_eq!(dialog["Cancel"], "先退出程序");
        let body = dialog["Body"].as_str().unwrap_or("");
        assert!(body.contains("Trader.exe"), "正文要列出在跑的程序：{body}");
        assert!(body.contains("下单助手.exe"), "正文要列出在跑的程序：{body}");
        assert!(body.contains("请先退出"), "{body}");
        let note = dialog["Note"].as_str().unwrap_or("");
        assert!(note.contains("已建立的连接不会被切断"), "安全说明不许少：{note}");
        assert!(note.contains("只有新连接会被阻止"), "安全说明不许少：{note}");

        // 用户坚持启用：这时才发 `guard-install`，并带上「我看过提示」的标记。
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert_eq!(steps.len(), 1, "确认后只发一条安装命令：{steps:?}");
        assert!(
            matches!(&steps[0], Step::Long(c)
                if c.contains("\"guard-install\"") && c.contains("\"acknowledgeRunning\":true")),
            "确认分支必须带 acknowledgeRunning：{steps:?}"
        );
        assert!(ui.busy);
        assert!(ui.dialog.is_none(), "确认后确认框要收起来");
    }

    /// 取消（「先退出程序」）：确认框收起，**一条命令都不发**——尤其不能悄悄装上。
    #[test]
    fn cancelling_the_guard_enable_prompt_sends_nothing() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| {
            if c.contains("\"guard-precheck\"") {
                merged_status_with(precheck_reply(json!(["Trader.exe"])))
            } else {
                fetch(c)
            }
        };
        ui.route(r#"{"Type":"guardEnable","Sequence":1}"#, &fetch);
        assert!(ui.dialog.is_some());

        let steps = ui.route(r#"{"Type":"cancelDialog","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "取消不发命令：{steps:?}");
        assert!(ui.dialog.is_none(), "取消后确认框要清空");
        assert!(ui.operation.is_none());
        assert!(!ui.busy);
    }

    /// 「自动记住首次服务器身份」以前是**假开关**：快照里硬编码 true，点一下只弹
    /// 「预览版暂未支持」。现在它必须是一个真设置——切换要落盘，显示要跟着配置走。
    #[test]
    fn auto_trust_switch_is_a_real_setting_not_a_placeholder() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(
            r#"{"Type":"setting","Name":"AutoTrustFirstConnection","Value":false,"Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"autoTrust\"") && c.contains("false")),
            "切换必须写进配置：{steps:?}"
        );
        assert!(!ui.toast.contains("暂未支持"), "不许再回占位话术：{:?}", ui.toast);

        // 显示跟随配置：关掉之后快照里必须是关的（以前恒为 true）。
        let off = |c: &str| {
            let mut v = fetch(c);
            if c.contains("status") {
                v["autoTrust"] = serde_json::json!(false);
            }
            v
        };
        let snap = ui.snapshot(&off);
        assert_eq!(
            snap["State"]["Settings"]["AutoTrustFirstConnection"], false,
            "快照要读配置，不能硬编码：{snap}"
        );
    }

    #[test]
    fn desktop_shortcut_runs_a_real_command_instead_of_the_placeholder_toast() {
        // A7：这个按钮以前回「这个面板将在后续版本开放」。现在必须真的落一个动作。
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"desktopShortcut","Sequence":1}"#, &fetch);
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"desktop-shortcut\"")),
            "创建桌面快捷方式必须真的执行命令：{steps:?}"
        );
        assert!(
            !ui.toast.contains("后续版本开放"),
            "不许再回占位话术：{:?}",
            ui.toast
        );
    }

    #[test]
    fn desktop_shortcut_success_is_toasted_and_failure_falls_through_to_the_standard_path() {
        // 成功：页面无字段变化，不回话就等于「点了没反应」。
        let mut ui = WebUi::new();
        ui.absorb_reply(
            r#"{"cmd":"desktop-shortcut"}"#,
            &serde_json::json!({"ok": true, "message": "已在桌面创建「交易通道」快捷方式。"}),
        );
        assert_eq!(ui.toast, "已在桌面创建「交易通道」快捷方式。");

        // 失败：不在 absorb 里回话（否则两处口径会漂），由 toast_from_reply 统一说原话。
        let mut ui = WebUi::new();
        let reply = serde_json::json!({"ok": false, "message": "开始菜单里也没有「交易通道」快捷方式；请重新运行安装程序后再试。"});
        ui.absorb_reply(r#"{"cmd":"desktop-shortcut"}"#, &reply);
        assert!(ui.toast.is_empty(), "失败不许在 absorb 里抢先说话：{:?}", ui.toast);
        ui.toast_from_reply(&reply, "");
        assert!(ui.toast.contains("重新运行安装程序"), "{:?}", ui.toast);
    }

    #[test]
    fn guard_reverify_is_a_long_command_not_a_reconnect() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"guardVerify","Sequence":1}"#, &fetch);
        assert!(
            matches!(&steps[0], Step::Long(c) if c.contains("\"guard-verify\"")),
            "重新核验必须走长命令：{steps:?}"
        );
        assert!(ui.busy, "等 UAC/WFP 读回时页面要进入等待态");
    }

    #[test]
    fn snapshot_falls_back_to_unknown_when_the_backend_gives_no_verdict() {
        // 缺字段时**绝不**兜底成 Protected：那正是 PRD 要消灭的那类谎。
        let strip = |cmd: &str| {
            if cmd.contains("\"status\"") {
                let mut v = fetch(cmd);
                if let Some(o) = v.as_object_mut() {
                    o.remove("Guard");
                    o.remove("TradeProgramCount");
                    o.remove("GuardSummary");
                    o.remove("GuardEvidence");
                }
                v
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&strip);
        assert_eq!(snap["State"]["Guard"], "Unknown", "缺字段只能是「无法确认」");
        assert_eq!(snap["State"]["TradeProgramCount"], -1, "-1 表示「读不到」，不是 0");
        assert_eq!(snap["State"]["GuardSummary"], "");
        assert_eq!(snap["State"]["GuardEvidence"], Value::Null);
        // 缺字段时不许编造时龄/来源（宁可空着）
        assert_eq!(snap["State"]["GuardEvidenceAge"], "");
        assert_eq!(snap["State"]["GuardEvidenceSource"], "");
        assert_eq!(snap["State"]["GuardVerifiedAtUtc"], Value::Null);
        assert_eq!(snap["State"]["GuardEvidenceStale"], false);
    }

    #[test]
    fn snapshot_agents_reflects_config_not_a_constant() {
        // 写死的 "Daily" 已经去掉了：快照里的 `Agents` 必须是**实际生效值**，
        // `AgentsStored` 是配置里存的值。两者一致时前端看不出区别。
        let with = |lane: &'static str, daily: &'static str, trade_exit: bool| {
            move |cmd: &str| {
                if cmd.contains("\"status\"") {
                    let mut v = fetch(cmd);
                    v["agentsLane"] = json!(lane);
                    v["exitDaily"] = json!(daily);
                    v["tradeExitPresent"] = json!(trade_exit);
                    v
                } else {
                    fetch(cmd)
                }
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with("trade", "direct", true));
        assert_eq!(snap["State"]["Agents"], "Trade");
        assert_eq!(snap["State"]["AgentsStored"], "Trade");

        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with("daily", "direct", true));
        assert_eq!(snap["State"]["Agents"], "Daily");
        assert_eq!(snap["State"]["AgentsStored"], "Daily");

        // 全局覆盖：日常上网走交易线路 → 实际按交易线路（存的是 daily 也一样）。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with("daily", "hk", true));
        assert_eq!(snap["State"]["Agents"], "Trade", "全局覆盖");
        assert_eq!(snap["State"]["AgentsStored"], "Daily", "存的值要单独保留给应用页");

        // 存 trade 但线路没有交易出口：实际是 Daily（不能写一句假话），存储值仍是 Trade。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with("trade", "direct", false));
        assert_eq!(snap["State"]["Agents"], "Daily", "没有出口就不生效");
        assert_eq!(snap["State"]["AgentsStored"], "Trade");
    }

    #[test]
    fn snapshot_without_agents_keys_defaults_to_daily() {
        // 老配置/老 status（没有 `agentsLane` 与 `tradeExitPresent` 两个新键）：
        // 快照必须读成「跟随日常上网」，不能因为字段缺失就报错或给出空值。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&|cmd: &str| {
            let mut v = fetch(cmd);
            if cmd.contains("\"status\"") {
                if let Some(o) = v.as_object_mut() {
                    o.remove("agentsLane");
                    o.remove("tradeExitPresent");
                }
            }
            v
        });
        assert_eq!(snap["State"]["Agents"], "Daily", "缺键按跟随日常上网");
        assert_eq!(snap["State"]["AgentsStored"], "Daily", "存储值同样缺省 Daily");
    }

    #[test]
    fn snapshot_projects_the_trade_list_into_pascal_case_groups() {
        // 线路页按旧版的版式分三组渲染，字段名必须是页面认的 PascalCase，
        // 不能把 status 那份 lowercase 形状原样丢过去。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&|cmd: &str| {
            let mut v = fetch(cmd);
            if cmd.contains("\"status\"") {
                v["tradeList"] = json!({
                    "programs": [{"name": "Mirasim.exe", "path": "C:\\Users\\x\\Mirasim.exe"}],
                    "domains": ["tradingview.com"],
                    "aux": [],
                });
            }
            v
        });
        let list = &snap["State"]["TradeList"];
        assert_eq!(list["Programs"][0]["Name"], "Mirasim.exe", "{list}");
        assert_eq!(list["Programs"][0]["Path"], "C:\\Users\\x\\Mirasim.exe", "{list}");
        assert_eq!(list["Domains"][0], "tradingview.com", "{list}");
        assert_eq!(
            list["AuxDomains"].as_array().map(|a| a.len()),
            Some(0),
            "本版没有辅助解析：{list}"
        );
    }

    #[test]
    fn snapshot_without_trade_list_still_gives_three_empty_arrays() {
        // 老快照 / 读配置失败：三个字段必须还在且是数组。给 `null` 的话页面连
        // 「连接后显示当前线路的交易名单」那句空态都渲染不出来，看起来像功能没了。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&|cmd: &str| {
            let mut v = fetch(cmd);
            if cmd.contains("\"status\"") {
                if let Some(o) = v.as_object_mut() {
                    o.remove("tradeList");
                }
            }
            v
        });
        let list = &snap["State"]["TradeList"];
        for key in ["Programs", "Domains", "AuxDomains"] {
            assert!(list[key].is_array(), "{key} 必须是数组：{list}");
            assert_eq!(list[key].as_array().map(|a| a.len()), Some(0), "{key} 必须是空数组：{list}");
        }
    }

    #[test]
    fn agents_list_opens_a_page_instead_of_a_toast() {
        // 「管理工具名单」不再是「这个面板将在后续版本开放」。
        let mut ui = WebUi::new();
        let steps = ui.route(r#"{"Type":"agentsList","Sequence":1}"#, &fetch);
        let form = ui.form.as_ref().expect("必须打开名单页");
        assert_eq!(form.render()["ViewKey"], "agents");
        assert_eq!(form.render()["Title"], "AI 工具名单");
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"agents\"")),
            "要查一次目录：{steps:?}"
        );
        assert!(ui.toast.is_empty(), "不许再弹「后续版本开放」：{}", ui.toast);
    }

    /// 名单页是**草稿式保存**：改了几项但没点保存时按「返回」，以前会把改动直接扔掉，
    /// 页面连一句话都没有。现在必须先问一句，且弹窗期间草稿还在。
    #[test]
    fn leaving_the_agents_page_with_unsaved_changes_asks_before_dropping_them() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"agentsList","Sequence":1}"#, &fetch);
        // 点一行「添加」＝草稿有 1 项改动。
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);

        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        let dialog = ui.dialog.clone().expect("有未保存改动时返回必须先问一句");
        assert_eq!(dialog["Scope"], "agents-leave", "{dialog}");
        assert_eq!(dialog["Title"], "改动没有保存", "{dialog}");
        assert!(
            dialog["Body"].as_str().unwrap_or_default().contains("已改 1 项"),
            "要说清改了几项：{dialog}"
        );
        assert!(steps.is_empty(), "还没决定去哪，不能发命令：{steps:?}");
        assert!(ui.form.is_some(), "弹窗期间页面必须还在（草稿不能先被丢掉）");

        // 「继续编辑」：留在原页，草稿还在。
        ui.route(r#"{"Type":"cancelDialog"}"#, &fetch);
        assert!(ui.form.is_some(), "取消之后必须回到编辑态");
        assert!(ui.dialog.is_none(), "取消要关掉弹窗");

        // 再来一次并「放弃并返回」：这次才真的离开。
        ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(ui.dialog.is_some(), "第二次返回同样要问");
        ui.route(r#"{"Type":"confirmDialog"}"#, &fetch);
        assert!(ui.form.is_none(), "确认之后才关页面");
        assert!(ui.dialog.is_none());
    }

    /// 没改动就别多问一句：返回照旧一步到位。
    #[test]
    fn leaving_the_agents_page_without_changes_does_not_ask() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"agentsList","Sequence":1}"#, &fetch);
        ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(ui.dialog.is_none(), "没改动不该弹窗：{:?}", ui.dialog);
        assert!(ui.form.is_none(), "返回要直接生效");
    }

    // =====================================================================
    // R30 / C4 独立验收：AI 工具名单「返回前先问一句」。
    //
    // 上面两条是随改动一起进来的单测。下面是**独立**按真实报文重走的一遍，
    // 外加它们没覆盖的边界（非名单表单、`done`、保存进行中、弹窗重入、导航）。
    // 这里只钉行为，不改产品逻辑。
    // =====================================================================

    /// 一份「真实形状」的 `agents` 回包：内置目录三项（两项已勾、一项没勾），
    /// 交易名单里一个程序、没有网站，走向跟随日常上网、未在连接中。
    ///
    /// 用它而不是空回包，是为了让基线（`agents_base`）非平凡——否则「有没有改动」
    /// 测出来只是一次空草稿与一次改动的差，掩盖掉 `fill_agents` 那一段的错位。
    fn r30_agents_reply(busy: bool, lane: &str) -> Value {
        json!({
            "ok": true,
            "agents": {
                "lane": lane, "laneEffective": lane,
                "globalOverride": false, "tradeExitPresent": true, "busy": busy,
            },
            "builtin": [
                {"id": "claude", "kind": "program", "name": "Claude", "detail": "",
                 "checked": true, "inTradeList": false},
                {"id": "cursor", "kind": "program", "name": "Cursor", "detail": "",
                 "checked": true, "inTradeList": false},
                {"id": "chatgpt", "kind": "web", "name": "ChatGPT", "detail": "",
                 "checked": false, "inTradeList": false},
            ],
            "programs": [{"value": "Trader.exe", "inTradeList": true}],
            "sites": [],
        })
    }

    /// 按前端真实的打开顺序进名单页：页面发 `agentsList`，宿主产出查目录的同步步骤，
    /// 回包由 `absorb_reply` 吸收（生产路径见 `ui.rs` 的 `Step::Sync` 分支）。
    fn r30_open_agents(ui: &mut WebUi, reply: &Value) {
        let steps = ui.route(r#"{"Type":"agentsList","Sequence":1}"#, &fetch);
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"cmd\":\"agents\"")),
            "打开名单页要查一次目录：{steps:?}"
        );
        ui.absorb_reply(r#"{"cmd":"agents"}"#, reply);
        let form = ui.form.as_ref().expect("名单页必须打开");
        assert_eq!(form.render()["ViewKey"], "agents");
        assert!(form.leave_warning().is_none(), "刚打开、草稿等于基线，不该拦");
    }

    /// 名单页当前「已改 N 项」那句话（只在表单渲染里出现，用来证明草稿真的还在）。
    fn r30_dirty_line(ui: &WebUi) -> String {
        let rendered = ui.form.as_ref().map(|f| f.render().to_string()).unwrap_or_default();
        assert!(
            rendered.contains("已改 1 项，尚未生效"),
            "页面上的「已改 1 项」不见了：{rendered}"
        );
        rendered
    }

    #[test]
    fn r30_agents_leave_asks_first_over_the_real_message_protocol() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);

        // 页面点一行「添加」（ChatGPT 原本不在名单里）——只为草稿，不提交。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);
        assert!(steps.is_empty(), "点一行只动草稿，一条命令都不该发：{steps:?}");
        assert_eq!(
            ui.form.as_ref().and_then(FormState::leave_warning).as_deref(),
            Some("已改 1 项，尚未生效；返回后这些改动会丢失。"),
        );

        // ① 脏时点返回：先问一句，不发任何 Step，表单还在。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(steps.is_empty(), "还没决定去哪，不能顺手发命令：{steps:?}");
        let dialog = ui.dialog.clone().expect("有未保存改动时返回必须先问一句");
        assert_eq!(dialog["Scope"], "agents-leave", "{dialog}");
        assert_eq!(dialog["Title"], "改动没有保存", "{dialog}");
        assert_eq!(
            dialog["Body"], "已改 1 项，尚未生效；返回后这些改动会丢失。",
            "正文要说清改了几项、返回会丢：{dialog}"
        );
        assert_eq!(
            dialog["Note"], "点「保存」之后才会生效；现在返回就是放弃这些改动。",
            "{dialog}"
        );
        assert_eq!(dialog["Confirm"], "放弃并返回", "{dialog}");
        assert_eq!(dialog["Cancel"], "继续编辑", "{dialog}");
        assert_eq!(dialog["Danger"], true, "这条是不可逆的放弃，必须标危险：{dialog}");
        assert!(ui.form.is_some(), "弹窗期间页面必须还在（草稿不能先被丢掉）");

        // ② 点「继续编辑」：弹窗关掉，草稿与「已改 1 项」都还在。
        let steps = ui.route(r#"{"Type":"cancelDialog","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "取消不执行任何命令：{steps:?}");
        assert!(ui.dialog.is_none(), "取消要关掉弹窗");
        assert!(ui.form.is_some(), "取消之后必须回到编辑态");
        r30_dirty_line(&ui);

        // ③ 再点一次返回**仍会问**：这才是「草稿真的没丢」的证据。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(steps.is_empty(), "{steps:?}");
        assert_eq!(
            ui.dialog.as_ref().map(|d| d["Scope"].clone()),
            Some(json!("agents-leave")),
            "草稿还在，所以第二次返回同样要问：{:?}",
            ui.dialog
        );

        // ④ 点「放弃并返回」：这次才真的关页面，且**不许顺手保存**。
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":3}"#, &fetch);
        assert!(
            steps.is_empty(),
            "「放弃并返回」只能丢弃，绝不能偷偷发 agents-save：{steps:?}"
        );
        assert!(ui.form.is_none(), "确认之后才关页面");
        assert!(ui.dialog.is_none(), "确认之后弹窗要关掉");
    }

    #[test]
    fn r30_agents_leave_without_changes_closes_in_one_step() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        // 加了又拿掉 = 回到基线：不算改动，不该多问一句。
        ui.route(
            r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#,
            &fetch,
        );
        ui.route(
            r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#,
            &fetch,
        );
        assert!(
            ui.form.as_ref().and_then(FormState::leave_warning).is_none(),
            "勾回去就等于没改"
        );
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(ui.dialog.is_none(), "没改动不该弹窗：{:?}", ui.dialog);
        assert!(ui.form.is_none(), "返回要直接生效");
        assert!(steps.is_empty(), "关表单不发命令：{steps:?}");
    }

    /// 边界①：别的表单（改一项就落一项）一律不许被拦——多问一句只会变成噪音。
    #[test]
    fn r30_leave_warning_never_blocks_other_forms() {
        // (打开用的报文, 点哪个关闭按钮)。部署表单用的是 `done`（与 `back` 同一条关闭路径）。
        let cases: [(&str, &str); 6] = [
            (r#"{"Type":"domains","Sequence":1}"#, "back"), // 交易名单（Split）
            (r#"{"Type":"providers","Sequence":1}"#, "back"), // 代理软件
            (r#"{"Type":"lineSettings","Id":"hk","Sequence":1}"#, "back"), // 线路设置
            (r#"{"Type":"rename","Id":"hk","Sequence":1}"#, "back"), // 重命名
            (r#"{"Type":"history","Sequence":1}"#, "back"), // 记录
            (r#"{"Type":"add","Sequence":1}"#, "done"),    // 自己搭服务器（部署）
        ];
        for (open, close_id) in cases {
            let mut ui = WebUi::new();
            ui.route(open, &fetch);
            let form = ui.form.as_ref().unwrap_or_else(|| panic!("{open} 应该打开一个表单"));
            let view = form.render()["ViewKey"].clone();
            assert!(
                form.leave_warning().is_none(),
                "{view:?} 不是草稿式保存，不该拦（{open}）"
            );
            let click = format!(r#"{{"Type":"form","Event":"click","Id":"{close_id}"}}"#);
            let steps = ui.route(&click, &fetch);
            assert!(ui.dialog.is_none(), "{view:?} 点 {close_id} 不许弹窗：{:?}", ui.dialog);
            assert!(ui.form.is_none(), "{view:?} 点 {close_id} 要直接关掉");
            assert!(steps.is_empty(), "{view:?} 关闭不该顺带发命令：{steps:?}");
        }
    }

    /// 边界②：`done` 与 `back` 都必须拦。
    ///
    /// 名单页本身没有 `done` 按钮（只有 保存 / 放弃修改 / 返回），所以它只可能来自
    /// 残页或改包；但它语义上就是「关掉这个表单」，不拦就又是一条静默丢草稿的路。
    #[test]
    fn r30_agents_done_is_treated_as_leaving_too() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);

        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"done"}"#, &fetch);
        assert!(steps.is_empty(), "还没决定去哪，不能发命令：{steps:?}");
        assert_eq!(
            ui.dialog.as_ref().map(|d| d["Scope"].clone()),
            Some(json!("agents-leave")),
            "`done` 等于「关表单」，同样要先问：{:?}",
            ui.dialog
        );
        assert!(ui.form.is_some(), "弹窗期间页面必须还在");
        ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert!(ui.form.is_none(), "确认后才关页面");
    }

    /// 边界③：保存进行中（连接中，保存被后端以 `busy` 拒绝）时点返回。
    ///
    /// 保存是**同步命令**：`ui.rs` 里 `Step::Sync` 的执行顺序是
    /// 「跑命令 → absorb_reply → 才重画页面」，所以不存在「回包还在路上、用户已经点了返回」
    /// 的窗口。被拒绝时草稿一个字都没动，因此「尚未生效」是真话，返回拦一句也是对的。
    #[test]
    fn r30_agents_leave_while_save_was_rejected_still_warns_and_persists_nothing() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(true, "daily"); // 连接中：保存按钮不可用
        r30_open_agents(&mut ui, &reply);
        assert!(ui.form.as_ref().unwrap().agents_busy, "连接中要置位");
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);

        // 后端以 busy 拒绝保存：草稿必须「一个字都不动」。
        ui.absorb_reply(
            r#"{"cmd":"agents-save"}"#,
            &json!({"ok": false, "errorCode": "busy", "error": "正在连接，名单要断开后才能保存"}),
        );
        let form = ui.form.as_ref().unwrap();
        assert!(form.agents_busy, "busy 要保持，保存按钮才继续禁用");
        assert_eq!(
            form.leave_warning().as_deref(),
            Some("已改 1 项，尚未生效；返回后这些改动会丢失。"),
            "保存被拒绝 = 仍未生效，返回必须问一句"
        );

        // 返回 → 确认放弃：关页面、不发任何命令（没有第二次保存，也就没有「以为放弃了、其实存了」）。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(steps.is_empty(), "{steps:?}");
        assert!(ui.dialog.is_some(), "必须问一句");
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "放弃不能顺带落盘：{steps:?}");
        assert!(ui.form.is_none());
    }

    /// 边界④：弹窗期间再点返回 / 再点别的按钮，不许重复叠窗、不许把表单提前关掉。
    #[test]
    fn r30_agents_leave_dialog_survives_extra_clicks() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);
        ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        let first = ui.dialog.clone().expect("先有弹窗");

        // 再点一次返回：还是同一个弹窗（`dialog` 只有一个槽位，不会叠第二个），表单没被关。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(steps.is_empty(), "{steps:?}");
        assert_eq!(ui.dialog, Some(first), "弹窗内容不该被改写成别的");
        assert!(ui.form.is_some(), "弹窗期间表单不能被提前关掉");

        // 弹窗期间点「放弃修改」：宿主不设模态门，表单事件照常生效——草稿被清空，
        // 于是「返回」也就不必再问了。如实钉住这一条（前端弹窗是模态遮罩，真人点不到）。
        ui.route(r#"{"Type":"form","Event":"click","Id":"discard"}"#, &fetch);
        assert!(
            ui.form.as_ref().and_then(FormState::leave_warning).is_none(),
            "草稿已回到基线"
        );
        assert!(ui.dialog.is_some(), "点表单按钮不该顺手关掉弹窗");
    }

    /// 边界④-b：弹窗**开着**的时候「保存」被触发（宿主侧没有模态门）。
    ///
    /// 结论（如实钉住，不是本轮改动引入的）：这一步会真的发出一条 `agents-save`，
    /// 弹窗还留在屏幕上、但它的正文「改动没有保存」随后就陈旧了。
    /// 前端 `renderDialog()` 是模态遮罩，真人点不到下面的保存按钮，所以这条只影响
    /// 「残页/改包/自动化」这类路径；且确认后只是关页，不会丢数据。
    #[test]
    fn r30_agents_save_can_still_fire_while_the_leave_dialog_is_open() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);
        ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(ui.dialog.is_some(), "先有离页确认弹窗");

        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"save"}"#, &fetch);
        assert_eq!(steps.len(), 1, "宿主没有模态门，保存照发：{steps:?}");
        assert!(steps[0].command().contains("agents-save"), "{steps:?}");
        assert!(ui.dialog.is_some(), "保存不会关掉弹窗");
        assert!(ui.form.is_some(), "保存也不该关表单");

        // 保存成功后基线跟上，草稿不再脏；此时弹窗那句「改动没有保存」已经不符合事实
        // ——但它只是一个提示，确认后只关页，不会覆盖或丢弃刚存下的内容。
        ui.absorb_reply(r#"{"cmd":"agents-save"}"#, &r30_agents_reply(false, "trade"));
        assert!(ui.form.as_ref().and_then(FormState::leave_warning).is_none());
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":3}"#, &fetch);
        assert!(steps.is_empty(), "确认只是关页：{steps:?}");
        assert!(ui.form.is_none());
    }

    /// 边界⑤：表单开着时点导航（前端 `data-page` → `navigate`）。
    ///
    /// 宿主不动表单，快照里 `Form` 仍然非空 → 前端 `paint()` 走 `state.Form ? workflow()`，
    /// 抽屉会重新画出来。结论：用户**既走不掉**（导航被拉回名单页），**也丢不掉**草稿。
    ///
    /// r84 起这条只对「**有未保存改动**的表单」成立：没有改动的表单导航会真的关掉
    /// （见 `navigating_away_closes_a_form_without_unsaved_changes`），否则
    /// 「自己搭服务器」第 0 步那种没有关闭按钮的页面会把人关死在里头。
    #[test]
    fn r30_navigate_while_agents_form_is_open_keeps_the_form_and_the_draft() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);

        let steps = ui.route(r#"{"Type":"navigate","Page":"home","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "导航不关表单、不发命令：{steps:?}");
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["Page"], "home", "页面确实切走了");
        assert_eq!(snap["State"]["Form"]["ViewKey"], "agents", "但表单还在，前端会把抽屉画回来");
        assert!(ui.dialog.is_none(), "导航不该触发离页确认");
        assert_eq!(
            ui.form.as_ref().and_then(FormState::leave_warning).as_deref(),
            Some("已改 1 项，尚未生效；返回后这些改动会丢失。"),
            "草稿一个字都没丢"
        );
    }

    /// 删除勾选的操作记录：**先弹确认框**，确认后才把键发出去。
    #[test]
    fn deleting_selected_history_rows_asks_first_then_sends_the_keys() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"history","Sequence":1}"#, &|_: &str| json!({}));
        ui.absorb_reply(
            r#"{"cmd":"history"}"#,
            &json!({"ok":true,"events":[
                {"ts":"2026-11-13T02:00:00Z","action":"连接","ok":true,"detail":"甲","src":"ui"},
                {"ts":"2026-11-13T01:59:00Z","action":"导入","ok":false,"detail":"乙","src":"cli"}
            ]}),
        );
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"history-pick:0","Value":true,"Sequence":2}"#,
            &|_: &str| json!({}),
        );
        assert_eq!(ui.form.as_ref().unwrap().history_checked, vec![0]);

        let steps =
            ui.route(r#"{"Type":"form","Event":"click","Id":"history-delete","Sequence":3}"#, &|_: &str| json!({}));
        assert!(steps.is_empty(), "点删除本身不发命令：{steps:?}");
        let dialog = ui.dialog.as_ref().expect("必须弹确认框");
        assert_eq!(dialog["Scope"], "history-delete", "{dialog}");

        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":4}"#, &|_: &str| json!({}));
        let joined = format!("{steps:?}");
        assert!(joined.contains("history-delete"), "{joined}");
        assert!(joined.contains("连接"), "键里要带被删的那一条：{joined}");
        assert!(
            steps
                .iter()
                .any(|step| matches!(step, Step::Sync(c) if c.contains(r#""cmd":"history""#))),
            "删完要立刻重读：{joined}"
        );
    }

    /// r96：恢复隐藏记录走的是真实 `route` → `absorb_reply` 路径。
    ///
    /// 只测 `FormState::absorb` 会漏掉「命令发出去了，页面却没有变」：恢复的键
    /// 是点击时从当前行取的，回包后必须用它把那一行的 `Hidden` 改回来。
    #[test]
    fn restoring_a_hidden_history_row_survives_the_real_route() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"history","Sequence":1}"#, &|_: &str| json!({}));
        ui.absorb_reply(
            r#"{"cmd":"history"}"#,
            &json!({"ok":true,"events":[
                {"ts":"2026-11-13T02:00:00Z","action":"连接","ok":true,"detail":"甲","src":"ui",
                 "Key":"k1","Hidden":true}
            ]}),
        );
        // 默认不显示隐藏行；勾上开关才看得见「恢复显示」。
        assert!(!ui.snapshot(&|_: &str| json!({}))["State"]["Form"].to_string().contains("已隐藏（旧版）"));
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"history-show-hidden","Value":true,"Sequence":2}"#,
            &|_: &str| json!({}),
        );

        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"history-restore:0","Sequence":3}"#,
            &|_: &str| json!({}),
        );
        let joined = format!("{steps:?}");
        assert!(joined.contains("history-restore") && joined.contains("k1"), "{joined}");

        ui.absorb_reply(
            steps[0].command(),
            &json!({"ok":true,"historyRestore":{"restored":1}}),
        );
        // 生产里 `absorb_reply` 收到的是宿主合并后的状态：键不在白名单里就会被吞掉。
        let mut merged = json!({"ok":true});
        merge_ui_command_reply(&mut merged, &json!({"ok":true,"historyRestore":{"restored":1}}));
        assert_eq!(merged["historyRestore"]["restored"], 1, "historyRestore 必须过白名单");
        let mut deleted = json!({"ok":true});
        merge_ui_command_reply(
            &mut deleted,
            &json!({"ok":true,"historyDelete":{"deleted":2,"hidden":true}}),
        );
        assert_eq!(
            deleted["historyDelete"]["deleted"], 2,
            "historyDelete 必须过白名单，否则隐藏后没有「已隐藏 N 条」"
        );

        let snap = ui.snapshot(&|_: &str| json!({}));
        let form = snap["State"]["Form"].to_string();
        assert!(!form.contains("已隐藏（旧版）"), "恢复后标记要消失：{form}");
        assert!(form.contains("甲"), "记录本身要留着：{form}");
    }

    /// 筛选事件要**穿过 `Generation` 闸门**落到宿主：这条走的是真实 `route` 路径
    /// （表单级用例直接调 `form.event`，绕过了闸门）。
    ///
    /// 顺带钉住一个坑：改这些字段时**不能** `restructure()`——那会把代数 +1，
    /// 页面还拿着上一代，下一次输入就被闸门当成过期事件静默丢弃。
    #[test]
    fn a_history_filter_change_survives_the_generation_gate() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"history","Sequence":1}"#, &|_: &str| json!({}));
        ui.absorb_reply(
            r#"{"cmd":"history"}"#,
            &json!({"ok":true,"events":[
                {"ts":"2026-11-13T02:00:00Z","action":"连接","ok":true,"detail":"甲","src":"ui"},
                {"ts":"2026-11-13T01:59:00Z","action":"导入配置","ok":false,"detail":"乙","src":"cli"}
            ]}),
        );
        let generation = ui.form.as_ref().unwrap().generation;
        let raw = format!(
            r#"{{"Type":"form","Event":"change","Id":"history-search","Value":"导入","Generation":{generation},"Sequence":2}}"#
        );
        let _ = ui.route(&raw, &|_: &str| json!({}));

        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.history_search, "导入", "宿主必须存下搜索词");
        assert_eq!(
            form.generation, generation,
            "改筛选不该自增代数，否则下一次编辑会被闸门丢掉"
        );
        let text = serde_json::to_string(&form.render()).unwrap();
        assert!(!text.contains("甲"), "列表没被筛：{text}");
    }

    /// 读指纹失败时，页面必须退回「可以再点一次开始」，而不是永远停在等待态。
    ///
    /// 命令层拒绝的回包里**没有** `serverProbe` 字段，而 `absorb_state` 那条路只认它；
    /// 少了按命令名兜的这一条，页面会一直显示「正在核对服务器身份…」、开始部署恒灰。
    #[test]
    fn a_failed_probe_returns_the_wizard_to_the_form() {
        let mut ui = WebUi::new();
        let form = FormState::deploy();
        ui.form = Some(form);
        {
            let form = ui.form.as_mut().unwrap();
            form.deploy_spec = "192.0.2.10".to_string();
            form.deploy_step = 5;
            form.deploy_notice = "正在读取主机指纹…".into();
        }

        // 走真实路径：长命令的终态由 `finish_op` 吃（`absorb_reply` 只接短命令）。
        ui.finish_op(&json!({
            "ok": false,
            "errorCode": "network",
            "error": "连接超时",
            "operationOnly": true,
            "op": {"cmd": "server-probe", "phase": "finished", "startedAtUtc": "2026-11-13T03:00:00Z", "budgetSec": 15.0}
        }));

        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.deploy_step, 0, "失败必须退回可以再点的状态");
        let text = serde_json::to_string(&form.render()).unwrap();
        assert!(text.contains("连接超时"), "失败原因要贴到页面上：{text}");
        assert!(!text.contains("正在核对服务器身份"), "不许停在等待态：{text}");
    }

    /// 只填 IP 也能继续（r85）：界面不再自己拦「没有 @」。
    ///
    /// 解析规则只有一处（`ipc::deploy_target`：用户名缺省 root、端口缺省 22），
    /// 表单那边用 `deploy_compose_target` 做同一套判据。两边再各写一份，就会出现
    /// 「命令行能跑、界面报错」这种漂移。
    #[test]
    fn the_deploy_wizard_accepts_a_bare_address() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        ui.form.as_mut().unwrap().deploy_spec = "192.168.1.1".to_string();

        // 提示必须先说清缺省，用户才敢只填 IP。r105：这句从正文搬进了地址框的
        // `Hint`（ⓘ），所以只在整份 JSON（含 `Hint`）里查得到。
        let hint = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(hint.contains("可以粘贴完整登录地址"), "{hint}");
        assert!(!hint.contains("支持粘贴 IP 或完整登录地址。"), "正文那句该没了：{hint}");
        assert!(hint.contains("登录账户"), "{hint}");
        assert!(hint.contains("SSH 端口"), "{hint}");

        ui.route(r#"{"Type":"form","Event":"change","Id":"deploy-cloud","Value":true}"#, &fetch);
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"start"}"#, &fetch);
        let joined = format!("{steps:?}");
        assert!(joined.contains("deployment-draft-save"), "{joined}");
        assert!(joined.contains("server-probe"), "要真的去读指纹：{joined}");
        // 账户与端口缺省值被补成 `root@192.168.1.1:22`：页面上看到的必须是
        // 真正会用的那个地址，不能有第二份真相。
        assert!(joined.contains("root@192.168.1.1:22"), "{joined}");

        let after = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(!after.contains("地址要写成"), "不该再报那句：{after}");
        assert!(after.contains("正在核对服务器身份"), "{after}");
    }

    /// 「自己搭服务器」第 0 步：导航必须真的走掉（r84）。
    ///
    /// 这一页**没有「关闭」按钮**，面包屑是 `workflow()` 按 `ParentPage` 自动生成的
    /// `data-page` 按钮（它发 `navigate`）。从前宿主对 `navigate` 无条件保留表单，
    /// 于是面包屑与左侧导航都是「看着能点、按下去没反应」，用户被关在向导里。
    #[test]
    fn navigating_away_closes_a_form_without_unsaved_changes() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"add","Sequence":1}"#, &fetch);
        assert!(ui.form.is_some(), "自己搭服务器应当是一个打开的表单");

        let steps = ui.route(r#"{"Type":"navigate","Page":"lines","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "导航不发命令：{steps:?}");
        assert!(
            ui.form.is_none(),
            "没有未保存改动的表单，导航就该真的关掉它（否则点面包屑/导航毫无反应）"
        );
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["Page"], "lines");
        assert!(
            snap["State"]["Form"].is_null(),
            "快照里也不能再有表单，否则前端照旧画回向导：{snap}"
        );
    }

    /// 边界⑥：已经保存过的改动不再重复计数——「已改 N 项」只算与**当前基线**的差。
    #[test]
    fn r30_agents_saved_then_edited_reports_only_the_new_change() {
        let mut ui = WebUi::new();
        let reply = r30_agents_reply(false, "daily");
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"click","Id":"builtin-chatgpt"}"#, &fetch);

        // 保存：一条同步命令，内容是草稿全量。
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"save"}"#, &fetch);
        assert_eq!(steps.len(), 1, "一次保存 = 一条命令：{steps:?}");
        assert!(
            steps[0].command().contains("agents-save")
                && steps[0].command().contains("\"Lane\":\"daily\"")
                && steps[0].command().contains("chatgpt"),
            "{steps:?}"
        );
        // 成功回包：基线跟着更新（勾上的 chatgpt 进了基线，走向仍是 daily）。
        ui.absorb_reply(r#"{"cmd":"agents-save"}"#, &r30_agents_reply(false, "daily"));
        assert!(
            ui.form.as_ref().and_then(FormState::leave_warning).is_none(),
            "刚存过、没再改：返回不该问"
        );

        // 再点一次「移除」（cursor 原本在名单里）：只多了 1 项，弹窗不能说「已改 2 项」。
        ui.route(
            r#"{"Type":"form","Event":"click","Id":"builtin-cursor"}"#,
            &fetch,
        );
        assert_eq!(
            ui.form.as_ref().and_then(FormState::leave_warning).as_deref(),
            Some("已改 1 项，尚未生效；返回后这些改动会丢失。"),
        );
    }

    /// 边界⑦：这一页**没有**走向控件（归应用页那一行），伪造一条 `lane` 改动
    /// 也不许把页面弄脏——宿主要按「不认识的控件」丢掉，而不是留一个看不见的改动。
    #[test]
    fn r30_agents_forged_lane_change_does_not_dirty_the_page() {
        let mut ui = WebUi::new();
        let mut reply = r30_agents_reply(false, "daily");
        reply["agents"]["globalOverride"] = json!(true);
        r30_open_agents(&mut ui, &reply);
        ui.route(r#"{"Type":"form","Event":"change","Id":"lane","Value":1}"#, &fetch);
        assert!(
            ui.form.as_ref().and_then(FormState::leave_warning).is_none(),
            "页面上不存在的走向控件不该把页面弄脏"
        );
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(ui.dialog.is_none(), "没脏就不问：{:?}", ui.dialog);
        assert!(ui.form.is_none());
        assert!(steps.is_empty(), "{steps:?}");
    }

    #[test]
    fn app_page_lane_click_writes_one_command() {
        // 应用页那一行：只改走向，不发别的命令、不弹提示。
        let mut ui = WebUi::new();
        let steps = ui.route(r#"{"Type":"agents","Value":"Trade","Sequence":2}"#, &fetch);
        assert_eq!(steps.len(), 1, "一次点击 = 一条命令：{steps:?}");
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("agents-lane") && c.contains("\"Value\":\"Trade\"")),
            "{steps:?}"
        );
        assert!(ui.toast.is_empty(), "走向现在真的落盘了，不该再弹旧提示：{}", ui.toast);
        // 空值不发命令（页面异常时也不要写一个空走向）
        let steps = ui.route(r#"{"Type":"agents","Value":""}"#, &fetch);
        assert!(steps.is_empty(), "{steps:?}");
    }

    /// 部署投影：任务卡与底部队列**原样透传**，宿主不自己算。
    ///
    /// 一旦这里开始二次加工（补状态、改文案），页面说的就和管道/CLI 不是同一件事。
    /// 一份 `run_view` 形状的记录（详情页的唯一输入）。
    ///
    /// 刻意从 `Value` 手写而不是走 `deployrun::run_view`：这一层测的是
    /// 「拿到什么就画什么」，混进记录层的计算就分不清是谁错了。
    fn run_fixture(
        state: &str,
        next_action: &str,
        action_label: &str,
        done: u64,
        running: bool,
    ) -> Value {
        let status = |index: u64| {
            if index < done {
                "Done"
            } else if index == done && running {
                "Running"
            } else {
                "Pending"
            }
        };
        let names = [
            "检查服务器环境与身份",
            "准备标准连接",
            "准备兼容连接",
            "接入本机并登记线路",
        ];
        let steps: Vec<Value> = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                json!({
                    "Index": index,
                    "Name": name,
                    "Status": status(index as u64),
                    "Evidence": {},
                    "Error": null,
                })
            })
            .collect();
        json!({
            "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            "RunShort": "3f2b9c1e",
            "Name": "自建 · 203.0.113.10",
            "Label": format!("{done}/4 · 准备标准连接"),
            "State": state,
            "StepsDone": done,
            "Step": done,
            "NextAction": next_action,
            "ActionLabel": action_label,
            "Running": running,
            "CanBackground": false,
            "Steps": steps,
            "PendingOperation": Value::Null,
            "Reason": if state == "NeedsAttention" {
                json!({
                    "Category": "Failed", "Class": "environment", "Code": "NotApplied",
                    "Text": "标准连接没有生效（只读核对确认）。",
                    "AtUtc": "2026-11-09T09:05:00Z",
                })
            } else {
                Value::Null
            },
        })
    }

    /// 表单节点树里所有按钮（含嵌套在 row / card 里的）。
    fn buttons_in(node: &Value) -> Vec<Value> {
        fn walk(node: &Value, out: &mut Vec<Value>) {
            if node.get("Kind").and_then(Value::as_str) == Some("button") {
                out.push(node.clone());
            }
            for key in ["Children", "Nodes"] {
                if let Some(children) = node.get(key).and_then(Value::as_array) {
                    for child in children {
                        walk(child, out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(node, &mut out);
        out
    }

    /// 表单节点树里的每一行文字（断言「页面说了什么」用）。
    fn texts_in(node: &Value) -> Vec<String> {
        fn walk(node: &Value, out: &mut Vec<String>) {
            if node.get("Kind").and_then(Value::as_str) == Some("text") {
                if let Some(text) = node.get("Text").and_then(Value::as_str) {
                    out.push(text.to_string());
                }
            }
            for key in ["Children", "Nodes"] {
                if let Some(children) = node.get(key).and_then(Value::as_array) {
                    for child in children {
                        walk(child, out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(node, &mut out);
        out
    }

    #[test]
    fn snapshot_carries_the_deployment_projection_verbatim() {
        let with_deployments = |cmd: &str| {
            if cmd.contains("deployment-list") {
                json!({"ok": true, "deployment": {
                    "TasksRead": "partial",
                    "TasksReadError": "有 1 条任务记录读不出来（文件损坏，或被写入了不允许保存的字段）。",
                    "UnreadableCount": 1,
                    "Tasks": [{
                        "Id": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                        "Name": "自建 · 203.0.113.10",
                        "Label": "1/4 · 准备标准连接：标准连接没有生效（只读核对确认）。",
                        "State": "NeedsAttention", "StateText": "需要处理",
                        "Step": 1, "StepsDone": 1,
                        "Host": "203.0.113.10", "Port": 22,
                        "Action": "continue", "ActionLabel": "重试本步骤",
                        "CanBackground": false, "RunShort": "3f2b9c1e",
                        "UpdatedAtUtc": "2026-11-09T09:10:00Z",
                        "ReasonCategory": "Failed",
                        "ReasonText": "标准连接没有生效（只读核对确认）。",
                    }],
                    "Deployments": [{
                        "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                        "Name": "自建 · 203.0.113.10",
                        "State": "Running", "StateText": "正在部署",
                        "Summary": "3/4 · 准备兼容连接", "Step": 3, "StepsDone": 2,
                        "Host": "203.0.113.10", "Port": 22, "Running": true,
                        "UpdatedAtUtc": "2026-11-09T09:10:00Z",
                    }],
                    "Reminders": [{
                        "Id": "r-1",
                        "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                        "Name": "自建 · 203.0.113.10",
                        "State": "NeedsAttention", "StateText": "需要处理",
                        "Text": "端口被占用",
                        "CreatedAtUtc": "2026-11-09T09:10:00Z",
                    }],
                    "RemindersError": "",
                    "Archived": [{
                        "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                        "RunShort": "3f2b9c1e",
                        "Name": "自建 · 203.0.113.10",
                        "State": "Complete", "StateText": "已完成",
                        "Summary": "4/4 · 已完成",
                        "StepsDone": 4, "Host": "203.0.113.10", "Port": 22,
                        "UpdatedAtUtc": "2026-11-09T09:10:00Z",
                        "ArchivedAtUtc": "2026-11-10T08:00:00Z",
                    }],
                    "Drafts": {
                        "Count": 2, "OldestDays": 9, "HasAge": true,
                        "Stale": true, "StaleDays": 7, "Max": 3,
                        "Summary": "2 份没填完的部署，最旧的一份放了 9 天。",
                        "Hint": "超过 7 天没动过。可以接着填，也可以放弃——草稿不会自己消失。",
                    },
                }})
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with_deployments);
        let s = &snap["State"];
        assert_eq!(s["TasksRead"], "partial");
        assert_eq!(s["UnreadableCount"], 1);
        assert!(s["TasksReadError"]
            .as_str()
            .unwrap_or("")
            .contains("读不出来"));
        assert_eq!(s["Tasks"].as_array().map(Vec::len), Some(1));
        assert_eq!(s["Tasks"][0]["ActionLabel"], "重试本步骤");
        assert_eq!(s["Tasks"][0]["StepsDone"], 1);
        assert_eq!(s["Tasks"][0]["ReasonCategory"], "Failed");
        assert_eq!(s["Deployments"].as_array().map(Vec::len), Some(1));
        assert_eq!(s["Deployments"][0]["Running"], true);
        assert_eq!(s["Deployments"][0]["Summary"], "3/4 · 准备兼容连接");
        // 未读提醒（P1-3）同样只透传：页面靠 RunId 打开原任务。
        assert_eq!(s["Reminders"].as_array().map(Vec::len), Some(1));
        assert_eq!(s["Reminders"][0]["RunId"], s["Tasks"][0]["Id"]);
        assert_eq!(s["Reminders"][0]["StateText"], "需要处理");
        assert_eq!(s["RemindersError"], "");
        // 已归档（P2-2）同样只透传：页面靠 `RunId` 打开、靠详情页恢复。
        assert_eq!(s["Archived"].as_array().map(Vec::len), Some(1));
        assert_eq!(s["Archived"][0]["RunId"], s["Tasks"][0]["Id"]);
        assert_eq!(s["Archived"][0]["StateText"], "已完成");
        // 草稿总览（C6）原样透传：文案在宿主拼，页面不重算天数。
        assert_eq!(s["Drafts"]["Count"], 2);
        assert_eq!(s["Drafts"]["Stale"], true);
        assert_eq!(
            s["Drafts"]["Summary"],
            "2 份没填完的部署，最旧的一份放了 9 天。"
        );
        // 唯一候选不满足（CanBackground=false）→ 不给按钮，也不给 RunId。
        assert_eq!(s["CanBackground"], false);
        assert_eq!(s["CanBackgroundRunId"], "");
    }

    /// 拿不到 `deployment` 时 `TasksRead` 必须留空（未知）——**不是** `ok`。
    ///
    /// 「缺失 = 未知」是这份契约里最容易被顺手改坏的一条：把空串兜底成 `ok`，
    /// 页面就会在真的读不出来时说「没有任务」。
    #[test]
    fn a_missing_deployment_reply_leaves_the_read_state_unknown() {
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&|cmd| {
            if cmd.contains("deployment-list") {
                json!({"ok": false, "error": "部署引擎没有启动", "errorCode": "environment"})
            } else {
                fetch(cmd)
            }
        });
        let s = &snap["State"];
        assert_eq!(s["TasksRead"], "", "缺失必须是空串（未知），不能是 ok/{s}");
        assert_eq!(s["Tasks"].as_array().map(Vec::len), Some(0));
        assert_eq!(s["UnreadableCount"], 0);
        assert_eq!(s["CanBackground"], false);
        assert_eq!(s["CanBackgroundRunId"], "");
    }

    /// 「刷新任务记录」是**页面动作**，不是命令：不发给宿主，也不弹提示。
    ///
    /// 它唯一的职责是让页面立刻重绘一次——快照每帧都重拉 `deployment-list`，
    /// 多发一条 IPC 只会拿到同一份磁盘数据，用户看到的还是旧结果。断言 steps 为空
    /// 就是在钉住这一点：一旦有人把它接进命令分发，这条往返会悄悄地出现。
    #[test]
    fn refreshing_the_task_list_repaints_without_sending_a_command() {
        let mut ui = WebUi::new();
        // 重绘前后页面都必须是活的：`Tasks` 还是数组，表单/状态没被这次点击搞坏。
        let before = ui.snapshot(&fetch)["State"]["Tasks"].clone();
        assert!(before.is_array(), "重绘前 Tasks 必须是数组：{before}");

        let steps = ui.route(r#"{"Type":"deploymentList"}"#, &fetch);
        assert!(steps.is_empty(), "刷新任务记录不许发命令：{steps:?}");
        assert!(ui.toast.is_empty(), "刷新是非事件，不该弹提示：{}", ui.toast);

        let after = ui.snapshot(&fetch)["State"]["Tasks"].clone();
        assert!(after.is_array(), "重绘后 Tasks 必须是数组：{after}");
    }

    /// 「后台继续」只在**唯一**候选时给出，并说明它属于哪条 RunId。
    ///
    /// 两个候选时给按钮是危险的：按钮点下去拿这个 RunId 调 `deployment-background`，
    /// 指错就是「把另一条任务转后台」，而页面已经按当前表单关掉了。
    #[test]
    fn the_background_button_needs_exactly_one_candidate() {
        let with_tasks = |count: usize| {
            move |cmd: &str| {
                if cmd.contains("deployment-list") {
                    let tasks: Vec<Value> = (0..count)
                        .map(|index| {
                            json!({
                                "Id": format!("00000000-0000-4000-8000-{index:012x}"),
                                "Name": format!("任务 {index}"),
                                "Label": "2/4 · 准备兼容连接",
                                "State": "Running", "StepsDone": 2, "Step": 2,
                                "Host": "203.0.113.10", "Port": 22,
                                "Action": "resume", "ActionLabel": "查看",
                                "CanBackground": true,
                                "UpdatedAtUtc": "2026-11-09T09:10:00Z",
                            })
                        })
                        .collect();
                    json!({"ok": true, "deployment": {
                        "TasksRead": "ok", "TasksReadError": "", "UnreadableCount": 0,
                        "Tasks": tasks, "Deployments": [],
                    }})
                } else {
                    fetch(cmd)
                }
            }
        };

        let mut ui = WebUi::new();
        let one = ui.snapshot(&with_tasks(1));
        assert_eq!(one["State"]["CanBackground"], true);
        assert_eq!(
            one["State"]["CanBackgroundRunId"],
            "00000000-0000-4000-8000-000000000000"
        );

        let mut ui = WebUi::new();
        let two = ui.snapshot(&with_tasks(2));
        assert_eq!(two["State"]["CanBackground"], false, "两个候选不给按钮");
        assert_eq!(two["State"]["CanBackgroundRunId"], "");
    }

    // -----------------------------------------------------------------------
    // T07：部署任务详情（记录驱动的那一页）
    // -----------------------------------------------------------------------

    /// 点任务行的「继续」：**从磁盘读记录**再开页，读不到就不开。
    #[test]
    fn the_resume_action_opens_the_run_that_is_on_disk() {
        let run = run_fixture("NeedsAttention", "RetryStep", "重试这一步", 1, false);
        let with_run = {
            let run = run.clone();
            move |cmd: &str| {
                if cmd.contains("deployment-get") {
                    json!({"ok": true, "deployment": {"Run": run}})
                } else {
                    fetch(cmd)
                }
            }
        };
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"resume","Id":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#, &with_run);

        let form = ui.form.as_ref().expect("必须打开详情页");
        assert_eq!(form.deploy_run_id, "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f");
        assert!(ui.toast.is_empty(), "不许再弹「后续版本开放」：{}", ui.toast);

        let view = form.render();
        assert_eq!(
            view["Title"],
            json!("自建 · 203.0.113.10"),
            "标题用记录上的名字（`Name`），不能用进度标签 `Label`——那是两行大字"
        );
        let texts = texts_in(&view).join("\n");
        assert!(texts.contains("需要处理"), "状态词要出现：\n{texts}");
        assert!(texts.contains("标准连接没有生效"), "原因要出现：\n{texts}");
        assert!(
            !texts.contains("下一步："),
            "不再复述任务行上的动作（它与本页按钮不是同一件事）：\n{texts}"
        );

        let buttons = buttons_in(&view);
        assert_eq!(
            buttons
                .iter()
                .filter(|item| item["Tone"] == json!("primary"))
                .count(),
            1,
            "主按钮只能有一个：{buttons:?}"
        );
        assert_eq!(buttons[0]["Text"], json!("重试这一步"));
    }

    /// 读不到记录：**不开空页面**，把命令层的原话弹出来。
    #[test]
    fn a_missing_run_does_not_open_an_empty_detail_page() {
        let mut ui = WebUi::new();
        ui.route(
            r#"{"Type":"resume","Id":"00000000-0000-4000-8000-000000000000"}"#,
            &|cmd| {
                if cmd.contains("deployment-get") {
                    json!({"ok": false, "error": "没有这条部署任务。", "errorCode": "config"})
                } else {
                    fetch(cmd)
                }
            },
        );
        assert!(ui.form.is_none(), "读不到就别开页");
        assert_eq!(ui.toast, "没有这条部署任务。");
    }

    /// 每种 `NextAction` 只给一个说得通的主动作；排队中与表外值**不给**按钮。
    #[test]
    fn the_detail_page_maps_every_next_action_to_one_primary_button() {
        let cases = [
            ("OpenForm", "开始部署"),
            ("ConfirmPlan", "确认并开始"),
            ("RetryStep", "重试这一步"),
            ("Reconcile", "核对原操作"),
            ("EnterCredentials", "用这个密码继续"),
            ("CompleteCompatible", "补齐兼容连接"),
        ];
        for (next, label) in cases {
            let mut form = FormState::deploy_run(
                "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                run_fixture("NeedsAttention", next, label, 1, false),
            );
            let view = form.render();
            let primaries: Vec<Value> = buttons_in(&view)
                .into_iter()
                .filter(|item| item["Tone"] == json!("primary"))
                .collect();
            assert_eq!(primaries.len(), 1, "{next} 必须只有一个主按钮");
            assert_eq!(primaries[0]["Text"], json!(label), "{next}");
        }

        // 排队中：按钮点了也不会发生任何事，所以一个都不给。
        let mut form = FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("Queued", "WaitQueue", "等待队列", 0, false),
        );
        let view = form.render();
        assert!(
            buttons_in(&view)
                .iter()
                .all(|item| item["Tone"] != json!("primary")),
            "排队中不该有主按钮"
        );

        // 表外动作同样不给按钮：宁可什么都不能点，也不给一个假按钮。
        let mut form = FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("NeedsAttention", "SomethingNew", "新动作", 1, false),
        );
        let view = form.render();
        assert!(
            buttons_in(&view)
                .iter()
                .all(|item| item["Tone"] != json!("primary")),
            "表外动作不该给主按钮"
        );
    }

    /// 「核对」必须带 `verifyOnly`：这一条命令只读，绝不重发写命令。
    #[test]
    fn reconcile_sends_verify_only_and_never_replays_the_write() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("NeedsAttention", "Reconcile", "核对原操作", 1, false),
        ));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 1, "{steps:?}");
        let Step::Sync(payload) = &steps[0] else {
            panic!("核对是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-continue"), "{payload}");
        assert!(payload.contains("\"verifyOnly\":true"), "{payload}");
    }

    /// 用户填的密码：发出去之后本机立刻丢掉。快照里再也不该有它。
    #[test]
    fn the_typed_password_is_dropped_the_moment_it_is_handed_over() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture(
                "NeedsAttention",
                "EnterCredentials",
                "用这个密码继续",
                0,
                false,
            ),
        ));
        let _ = ui.route(
            r#"{"Type":"form","Event":"change","Id":"run-password","Value":"hunter2"}"#,
            &fetch,
        );
        assert_eq!(
            ui.form.as_ref().unwrap().deploy_password,
            "hunter2",
            "填写时先存着（只在内存）"
        );

        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("继续是短命令：{steps:?}");
        };
        assert!(payload.contains("hunter2"), "这一次要带上密码：{payload}");
        assert!(
            ui.form.as_ref().unwrap().deploy_password.is_empty(),
            "交给宿主之后本机必须立刻丢掉"
        );
        let snap = ui.snapshot(&fetch);
        assert!(
            !snap["State"]["Form"].to_string().contains("hunter2"),
            "密码绝不能进快照"
        );
    }

    /// 需要凭据但没填：**不发命令**，就地说明。
    #[test]
    fn continuing_without_the_required_password_sends_nothing() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture(
                "NeedsAttention",
                "EnterCredentials",
                "用这个密码继续",
                0,
                false,
            ),
        ));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "没密码就不该发命令：{steps:?}");
        assert!(ui
            .form
            .as_ref()
            .unwrap()
            .deploy_notice
            .contains("密码"));
    }

    /// 终态只读：只有「完成」，没有重试 / 取消。
    #[test]
    fn a_finished_run_is_read_only_on_the_detail_page() {
        for state in ["Complete", "Cancelled"] {
            let mut form = FormState::deploy_run(
                "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                run_fixture(state, "ViewLine", "查看线路", 4, false),
            );
            let view = form.render();
            let buttons = buttons_in(&view);
            let ids: Vec<&str> = buttons
                .iter()
                .filter_map(|item| item["Id"].as_str())
                .collect();
            // 完成态给「完成 + 导出诊断摘要 + 归档」：导出只读；归档只翻一个显示标记
            // （文件还在、随时能恢复），两者都不改动这次部署本身。
            assert_eq!(
                ids,
                vec!["done", "run-export", "run-archive"],
                "{state} 只能查看：{buttons:?}"
            );
            assert!(texts_in(&view)
                .join("")
                .contains("这次部署已经结束，只能查看。"));
        }
    }

    /// 取消要点两次：**第一次只亮出确认条**，一个命令都不发。
    #[test]
    fn cancelling_asks_once_inside_the_form_before_sending_anything() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("NeedsAttention", "RetryStep", "重试这一步", 1, false),
        ));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-cancel","Generation":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "第一下不能发命令：{steps:?}");
        assert!(ui.form.as_ref().unwrap().deploy_cancel_pending);
        let view = ui.form.as_ref().unwrap().render();
        assert!(texts_in(&view).join("").contains("取消之后这条记录不能再继续"));

        // 点「不取消」：回到原样，仍然没有命令。
        // `run-cancel` 已经 `restructure()` 过一代（1→2），这里必须发**当前**这一代：
        // 真实前端发的是 `state.Form.Generation`，写死旧值会被 Generation 闸挡掉。
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-cancel-back","Generation":2}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "{steps:?}");
        assert!(!ui.form.as_ref().unwrap().deploy_cancel_pending);

        // 再来一次并确认：这才发 `deployment-cancel`。
        let _ = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-cancel","Generation":3}"#,
            &fetch,
        );
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-cancel-confirm","Generation":4}"#,
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("取消是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-cancel"), "{payload}");
        assert!(payload.contains("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"), "{payload}");
    }

    /// 暂停只在**真有一步在跑**时给按钮；排队、已暂停、已完成既不给按钮，点了也不发命令。
    #[test]
    fn pausing_is_offered_only_while_a_step_is_running() {
        for (state, running) in [("Queued", false), ("Paused", false), ("Complete", false), ("Running", true)]
        {
            let mut ui = WebUi::new();
            ui.form = Some(FormState::deploy_run(
                "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                run_fixture(state, "None", "", 1, running),
            ));
            let view = ui.form.as_ref().unwrap().render();
            let pause = buttons_in(&view)
                .into_iter()
                .find(|item| item["Id"] == json!("run-pause"));
            assert_eq!(
                pause.is_some(),
                running,
                "{state} 的暂停按钮给错了：{view}"
            );
            // 按钮与命令走同一条判据：从点下去到宿主受理之间，这一步可能已经跑完了。
            let steps = ui.route(
                r#"{"Type":"form","Event":"click","Id":"run-pause","Generation":1}"#,
                &fetch,
            );
            if running {
                assert_eq!(steps.len(), 1, "{state} 点了要发命令：{steps:?}");
            } else {
                assert!(steps.is_empty(), "{state} 不该发暂停命令：{steps:?}");
                assert!(!ui.form.as_ref().unwrap().deploy_pause_pending);
            }
        }
    }

    /// 点「暂停部署」：只发一次短命令，页面挂上「做完这步再停」，不许连点。
    #[test]
    fn the_pause_button_sends_one_command_and_waits_for_the_step_boundary() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("Running", "None", "", 1, true),
        ));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-pause","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 1, "{steps:?}");
        let Step::Sync(payload) = &steps[0] else {
            panic!("暂停是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-pause"), "{payload}");
        assert!(
            payload.contains("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"),
            "{payload}"
        );
        let form = ui.form.as_ref().unwrap();
        assert!(form.deploy_pause_pending, "受理前也要先挡住连点");
        let view = form.render();
        let texts = texts_in(&view).join("\n");
        assert!(
            texts.contains("已请求暂停：当前步骤做完之后生效"),
            "{texts}"
        );
        assert!(
            buttons_in(&view)
                .iter()
                .all(|item| item["Id"] != json!("run-pause")),
            "已经请求过暂停，不能再给按钮：{:?}",
            buttons_in(&view)
        );

        // 再点同一代：一个命令都不发（按钮没了，逻辑上也要挡住）。
        let again = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-pause","Generation":2}"#,
            &fetch,
        );
        assert!(again.is_empty(), "{again:?}");

        // 受理：提示条留着；失败：撤掉意图，把命令层的原话显示出来。
        let pause_command =
            r#"{"cmd":"deployment-pause","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#;
        ui.absorb_reply(
            pause_command,
            &json!({"ok": true, "deployment": {
                "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                "PauseRequested": true,
                "Message": "已受理：当前步骤做完之后暂停。",
            }}),
        );
        let form = ui.form.as_ref().unwrap();
        assert!(form.deploy_pause_pending);
        assert_eq!(form.deploy_notice, "已受理：当前步骤做完之后暂停。");

        ui.absorb_reply(
            pause_command,
            &json!({"ok": false, "error": "这次部署现在没有在跑的步骤，无法暂停。", "errorCode": "environment"}),
        );
        let form = ui.form.as_ref().unwrap();
        assert!(!form.deploy_pause_pending, "失败必须撤掉暂停意图");
        assert!(form.deploy_notice.contains("无法暂停"), "{}", form.deploy_notice);
    }

    /// 暂停落地后：提示条消失，主按钮变成「继续部署」，点的仍是同一个续跑入口。
    #[test]
    fn a_paused_run_offers_continue_and_clears_the_pause_request() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("Running", "None", "", 1, true),
        ));
        let _ = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-pause","Generation":1}"#,
            &fetch,
        );
        assert!(ui.form.as_ref().unwrap().deploy_pause_pending);

        let paused = run_fixture("Paused", "None", "", 1, false);
        let paused_reply = paused.clone();
        let snap = ui.snapshot(&move |cmd: &str| {
            if cmd.contains("deployment-get") {
                json!({"ok": true, "deployment": {"Run": paused_reply}})
            } else {
                fetch(cmd)
            }
        });
        let form = ui.form.as_ref().unwrap();
        assert!(!form.deploy_pause_pending, "暂停落地后提示条要消失");
        let view = form.render();
        let primaries: Vec<Value> = buttons_in(&view)
            .into_iter()
            .filter(|item| item["Tone"] == json!("primary"))
            .collect();
        assert_eq!(primaries.len(), 1, "{view}");
        assert_eq!(primaries[0]["Text"], json!("继续部署"));
        assert_eq!(primaries[0]["Disabled"], json!(false));
        assert!(
            buttons_in(&view)
                .iter()
                .all(|item| item["Id"] != json!("run-pause")),
            "暂停状态下没有可暂停的步骤"
        );
        let texts = texts_in(&view).join("\n");
        assert!(texts.contains("已暂停"), "{texts}");
        assert!(texts.contains("从下一步接着做"), "{texts}");
        assert_eq!(snap["State"]["Form"]["Generation"], json!(form.generation));

        let generation = form.generation;
        let steps = ui.route(
            &format!(
                r#"{{"Type":"form","Event":"click","Id":"run-go","Generation":{generation}}}"#
            ),
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("继续是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-continue"), "{payload}");
        assert!(payload.contains("\"verifyOnly\":false"), "{payload}");
        assert!(!payload.contains("\"verifyOnly\":true"), "{payload}");
    }

    /// 暂停记录上若还挂着没核对的写：只能核对，绝不能借「继续」重发写命令。
    #[test]
    fn a_paused_run_with_an_unverified_write_still_reconciles_only() {
        let mut run = run_fixture("Paused", "None", "", 1, false);
        run["PendingOperation"] = json!({"Kind": "UdpInstall", "Outcome": "Pending"});
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run,
        ));
        let view = ui.form.as_ref().unwrap().render();
        let primaries: Vec<Value> = buttons_in(&view)
            .into_iter()
            .filter(|item| item["Tone"] == json!("primary"))
            .collect();
        assert_eq!(primaries.len(), 1, "{view}");
        assert_eq!(primaries[0]["Text"], json!("核对原操作"));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("核对是短命令：{steps:?}");
        };
        assert!(payload.contains("\"verifyOnly\":true"), "{payload}");
    }

    /// 详情页每帧从磁盘重读：后台往前走了，页面必须跟着动。
    #[test]
    fn the_detail_page_refreshes_from_disk_every_frame() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run_fixture("Running", "None", "", 1, true),
        ));
        let generation = ui.form.as_ref().unwrap().generation;

        let advanced = run_fixture("Running", "None", "", 2, true);
        let snap = ui.snapshot(&move |cmd: &str| {
            if cmd.contains("deployment-get") {
                json!({"ok": true, "deployment": {"Run": advanced}})
            } else {
                fetch(cmd)
            }
        });
        let form = ui.form.as_ref().unwrap();
        assert_eq!(form.deploy_run["StepsDone"], json!(2), "记录变了要跟着变");
        assert!(
            form.generation > generation,
            "结构变了必须重绘（否则页面还停在上一帧）"
        );
        assert_eq!(snap["State"]["Form"]["Generation"], json!(form.generation));
    }

    /// 记录没变就不重绘：每帧重绘会让页面上的输入框丢焦点。
    #[test]
    fn an_unchanged_run_does_not_force_a_redraw() {
        let run = run_fixture("Running", "None", "", 1, true);
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
            run.clone(),
        ));
        let generation = ui.form.as_ref().unwrap().generation;
        let snap = ui.snapshot(&move |cmd: &str| {
            if cmd.contains("deployment-get") {
                json!({"ok": true, "deployment": {"Run": run}})
            } else {
                fetch(cmd)
            }
        });
        assert_eq!(
            ui.form.as_ref().unwrap().generation,
            generation,
            "同一条记录不该重绘"
        );
        assert_eq!(snap["State"]["Form"]["Generation"], json!(generation));
    }

    /// 底部任务条的「后台继续」：没有打开详情页也要发命令，并把结论说出来。
    #[test]
    fn background_deployment_works_without_an_open_form() {
        let mut ui = WebUi::new();
        let steps = ui.route(
            r#"{"Type":"backgroundDeployment","Id":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("后台继续是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-background"), "{payload}");
        assert!(ui.form.is_none(), "不该顺手开出详情页");

        // 回包到了、页面没开着：结论必须进 toast，而不是静默丢掉。
        ui.absorb_reply(
            payload,
            &json!({"ok": true, "deployment": {"Message": "已转到后台，引擎继续跑。"}}),
        );
        assert_eq!(ui.toast, "已转到后台，引擎继续跑。");
    }

    // -----------------------------------------------------------------------
    // r69：部署草稿（保存 → 恢复 → 开始 / 丢弃）
    // -----------------------------------------------------------------------

    const DRAFT_ID: &str = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";

    /// 一条草稿记录的投影（形状与 `deployrun::run_view` 一致）。
    fn draft_fixture(port: u16, fingerprint: &str) -> Value {
        json!({
            "RunId": DRAFT_ID,
            "Name": "自建 · 203.0.113.10",
            "Label": "0/4 · 检查服务器环境与身份",
            "State": "Draft",
            "StepsDone": 0,
            "Step": 0,
            "NextAction": "OpenForm",
            "Action": "resume",
            "ActionLabel": "继续填写",
            "Running": false,
            "CanBackground": false,
            "Target": {
                "Host": "203.0.113.10",
                "Port": port,
                "User": "root",
                "ServerRecordId": Value::Null,
            },
            "Identity": {"Fingerprint": fingerprint, "AutoTrusted": false},
            "Steps": [],
            "PendingOperation": Value::Null,
            "Reason": Value::Null,
        })
    }

    /// `deployment-draft-save` 的回包必须穿过宿主侧合并，落进表单的 `deploy_draft_id`。
    ///
    /// 漏了这一格，症状**不是**报错，而是「每点一次『读取指纹并继续』就多一条草稿」，
    /// 撞满上限 3 之后用户再也存不下新的地址——同一个坑（白名单/吸收分组漏键）已经踩过四次。
    #[test]
    fn the_draft_id_survives_the_host_side_merge_and_lands_on_the_form() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        let state = merged_status_with(json!({
            "ok": true,
            "deployment": {
                "Run": draft_fixture(22, ""),
                "RunId": DRAFT_ID,
                "Created": true,
                "Message": "已保存这份草稿，关掉窗口后可以从任务列表接着填。",
            },
        }));
        assert!(
            state.get("deployment").is_some(),
            "`deployment` 必须在 UI_REPLY_KEYS 里，否则表单根本读不到回包"
        );
        ui.absorb_reply(r#"{"cmd":"deployment-draft-save"}"#, &state);
        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.deploy_draft_id, DRAFT_ID);
        assert_eq!(form.deploy_step, 0, "存草稿不等于「进入下一步」");
        assert!(
            form.deploy_notice.is_empty(),
            "成功时不该留下提示：{}",
            form.deploy_notice
        );
    }

    /// 出口网卡：保存回包必须走到还开着的表单里，并留下一句看得见的话。
    /// 真机验收发现磁盘写了、页面却像什么都没发生——这条用例把那条路钉住。
    #[test]
    fn saving_the_line_network_leaves_a_visible_notice_in_the_form() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp"));
        let reply = json!({"ok":true,
            "lineNetwork":{"Id":"hk","Default":"以太网","Interfaces":["以太网"],
                           "Bound":"以太网","Effective":"以太网","Stale":false,"StaleName":""},
            "message":"已保存下次连接的出口网卡，当前连接保持"});
        ui.absorb_reply(
            r#"{"cmd":"line-network-set","Id":"hk","Interface":"以太网"}"#,
            &reply,
        );
        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.net_bound, "以太网", "回包里的绑定值要落回表单");
        assert!(
            form.notice.contains("已保存下次连接的出口网卡"),
            "保存成功要在页面上说得出来：{}",
            form.notice
        );
    }

    /// 写盘失败**不挡填写**：不改步骤、不还原地址，只追加一句「关掉窗口后要重填」。
    #[test]
    fn a_failed_draft_save_never_bounces_the_wizard_back() {
        let mut ui = WebUi::new();
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        ui.form = Some(form);
        let state = merged_status_with(json!({
            "ok": false,
            "error": "没能把这份草稿写到磁盘：磁盘已满。",
            "errorCode": "config",
        }));
        ui.absorb_reply(r#"{"cmd":"deployment-draft-save"}"#, &state);
        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.deploy_step, 0, "写不进去也不许把用户弹回/推进");
        assert_eq!(form.deploy_spec, "root@203.0.113.10", "填好的地址不许清掉");
        assert!(form.deploy_draft_id.is_empty(), "没存成就不该有草稿 id");
        assert!(
            form.deploy_notice.contains("关掉窗口后地址要重填"),
            "{}",
            form.deploy_notice
        );
    }

    /// 「开始部署」：同一批里**先落草稿、再读指纹**。
    ///
    /// 指纹要等 probe 回来之后才有（`Absorbed` 带不了命令），所以这一批只能是
    /// 「存草稿 + 读指纹」；投递由宿主在 `finish_op` 之后接着发。
    /// 顺序反了就成了「先读指纹、草稿里还是空地址」。
    #[test]
    fn reading_the_fingerprint_saves_the_draft_first() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        let _ = ui.route(
            r#"{"Type":"form","Event":"change","Id":"spec","Value":"root@203.0.113.10"}"#,
            &fetch,
        );
        ui.route(r#"{"Type":"form","Event":"change","Id":"deploy-cloud","Value":true}"#, &fetch);
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"start","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 2, "一次点击 = 先存草稿、再读指纹：{steps:?}");
        let Step::Sync(save) = &steps[0] else {
            panic!("存草稿是短命令：{steps:?}");
        };
        assert!(save.contains("deployment-draft-save"), "{save}");
        assert!(save.contains("203.0.113.10"), "{save}");
        assert!(
            !save.contains("fingerprint"),
            "这一批还没有指纹（要等 probe 回来）：{save}"
        );
        // 两个勾跟着草稿一起留着：接着填的时候勾选不该回到默认值。
        assert!(save.contains("remember"), "{save}");
        assert!(save.contains("rememberTask"), "{save}");
        let Step::Long(probe) = &steps[1] else {
            panic!("读指纹是长命令：{steps:?}");
        };
        assert!(probe.contains("server-probe"), "{probe}");
    }

    /// 归档/恢复的回包提示必须活过「它自己引起的那一次记录变化」。
    ///
    /// 这是 r73 真机验收抓到的真缺陷：`refresh_run` 的规则是「记录动了就清提示」，
    /// 而归档恰好会改记录（`ArchivedAtUtc`）——于是用户点了「归档」，屏幕上什么也没说，
    /// 只有按钮悄悄换了文案。单测要构造的就是这个顺序：先吸收回包，再来一帧新记录。
    #[test]
    fn the_archive_notice_survives_the_record_change_it_causes() {
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            run_id,
            run_fixture("Complete", "ViewLine", "查看线路", 4, false),
        ));
        ui.absorb_reply(
            r#"{"cmd":"deployment-archive"}"#,
            &serde_json::json!({
                "ok": true,
                "deployment": {
                    "RunId": run_id,
                    "Archived": true,
                    "Message": "已归档：列表里不再显示，记录还在，随时可以恢复。"
                }
            }),
        );
        // 紧接着的那一帧：记录真的变了（归档时刻写进去了）。
        let mut changed = run_fixture("Complete", "ViewLine", "查看线路", 4, false);
        changed["ArchivedAtUtc"] = serde_json::json!("2026-11-12T12:00:00Z");
        ui.form.as_mut().unwrap().refresh_run(changed);
        let text = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(
            text.contains("已归档：列表里不再显示"),
            "归档提示被它自己引起的记录变化清掉了：{text}"
        );

        // 下一帧照常清：这条例外只保一帧，否则「已归档」会一直挂在一个已经恢复的记录上。
        let mut again = run_fixture("Complete", "ViewLine", "查看线路", 4, false);
        again["ArchivedAtUtc"] = serde_json::json!("2026-11-12T12:00:00Z");
        again["Revision"] = serde_json::json!(9);
        ui.form.as_mut().unwrap().refresh_run(again);
        let text = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(!text.contains("已归档：列表里不再显示"), "只保一帧：{text}");
    }

    /// 详情页要说清「这一次的指纹是自动记住的」——那是替用户做的一次身份决定。
    ///
    /// `Identity.AutoTrusted` 从 A9 起就写进记录了，但**没有任何页面读它**：
    /// 用户看到的只有「部署完成」，像是身份核对过一样。人工核对过的则一个字都不许多，
    /// 否则这句话会退化成噪音，反而没人再认真看。
    #[test]
    fn the_detail_page_says_when_the_fingerprint_was_auto_trusted() {
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";

        let mut auto = run_fixture("Complete", "ViewLine", "查看线路", 4, false);
        auto["Identity"] = json!({
            "Fingerprint": "SHA256:AbCdEf",
            "AutoTrusted": true
        });
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(run_id, auto));
        let text = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(text.contains("自动记住"), "{text}");
        assert!(text.contains("SHA256:AbCdEf"), "要带上记下的那一枚：{text}");
        assert!(text.contains("下次连接会按它核对"), "{text}");

        let mut manual = run_fixture("Complete", "ViewLine", "查看线路", 4, false);
        manual["Identity"] = json!({
            "Fingerprint": "SHA256:AbCdEf",
            "AutoTrusted": false
        });
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(run_id, manual));
        let text = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(!text.contains("自动记住"), "人工核对过的不许加这句：{text}");
    }

    /// P2-2：结束态给「归档」，归档态给「恢复」；点击都只发一条短命令。
    #[test]
    fn the_detail_page_archives_and_restores_a_result() {
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            run_id,
            run_fixture("Complete", "ViewLine", "查看线路", 4, false),
        ));
        let rendered = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(rendered.contains("归档"), "{rendered}");
        assert!(!rendered.contains("恢复这条记录"), "{rendered}");

        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-archive","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 1, "{steps:?}");
        let Step::Sync(command) = &steps[0] else {
            panic!("归档是短命令：{steps:?}");
        };
        assert!(command.contains("deployment-archive"), "{command}");
        assert!(command.contains(run_id), "{command}");
        assert!(command.contains("true"), "归档要明确带 archived:true：{command}");

        // 归档态：给的是「恢复」，命令里带 archived:false。
        let mut archived = run_fixture("Complete", "ViewLine", "查看线路", 4, false);
        archived["ArchivedAtUtc"] = serde_json::json!("2026-11-12T12:00:00Z");
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(run_id, archived));
        let rendered = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(rendered.contains("恢复这条记录"), "{rendered}");
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-unarchive","Generation":1}"#,
            &fetch,
        );
        let Step::Sync(command) = &steps[0] else {
            panic!("恢复是短命令：{steps:?}");
        };
        assert!(command.contains("deployment-archive"), "{command}");
        assert!(command.contains("false"), "恢复要明确带 archived:false：{command}");
    }

    /// P2-3：详情页「导出诊断摘要」是一条短命令；回包的 `exportResult.message` 必须上屏。
    ///
    /// 这条同时守两处接缝：按钮在不在（渲染树里）、回包落不落得到页面（absorb 分支）。
    /// 只测命令层的话，「点了没反应」这类缺陷一个也抓不到。
    #[test]
    fn the_detail_page_exports_a_diagnostic_summary() {
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let run = serde_json::json!({
            "RunId": run_id,
            "State": "NeedsAttention",
            "StepsDone": 1,
            "Running": false,
            "NextAction": "RetryStep",
            "Name": "自建 · 203.0.113.10",
            "Steps": [],
            "Attempts": []
        });
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(run_id, run));
        let rendered = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(rendered.contains("导出诊断摘要"), "{rendered}");

        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-export","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 1, "{steps:?}");
        let Step::Sync(command) = &steps[0] else {
            panic!("导出是短命令（写文件而已）：{steps:?}");
        };
        assert!(command.contains("deployment-export"), "{command}");
        assert!(command.contains(run_id), "{command}");

        // 回包落地：漏了 absorb 分支，点了导出页面一个字都不说。
        ui.absorb_reply(
            r#"{"cmd":"deployment-export"}"#,
            &serde_json::json!({
                "ok": true,
                "exportResult": {
                    "ok": true,
                    "path": "C:////exports////deploy-3f2b9c1e-1.md",
                    "message": "已导出诊断摘要（MD）到 C:////exports////deploy-3f2b9c1e-1.md"
                }
            }),
        );
        let after = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(after.contains("已导出诊断摘要"), "{after}");
    }

    /// 投递那一步：`deployment-draft-save` 排在 `deployment-start` 之前，
    /// 两条都带 `runId` + `fingerprint`。顺序反了就是「先投递、草稿里还留着空指纹」。
    #[test]
    fn starting_saves_the_fingerprint_into_the_draft_before_it_is_started() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_fingerprint = "SHA256:AAAA".into();
        form.deploy_known = true;
        form.deploy_step = 1;
        form.deploy_draft_id = DRAFT_ID.into();
        form.deploy_password = "hunter2".into();
        form.deploy_cloud = true;
        let steps = form.deploy_start_steps();
        assert_eq!(steps.len(), 2, "{steps:?}");
        let Step::Sync(save) = &steps[0] else {
            panic!("存草稿是短命令：{steps:?}");
        };
        assert!(save.contains("deployment-draft-save"), "{save}");
        assert!(save.contains(DRAFT_ID), "带 runId 才更新那一条：{save}");
        assert!(save.contains("SHA256:AAAA"), "指纹在这一批进草稿：{save}");
        assert!(
            !save.contains("hunter2"),
            "草稿里一个字的口令都不许有：{save}"
        );
        let Step::Sync(start) = &steps[1] else {
            panic!("开始是短命令：{steps:?}");
        };
        assert!(start.contains("deployment-start"), "{start}");
        assert!(start.contains(DRAFT_ID), "开始也用同一个 runId：{start}");
        assert!(start.contains("SHA256:AAAA"), "{start}");
        assert!(start.contains("hunter2"), "密码只在这一条里交出去：{start}");
        // 密码已经交给宿主：表单内存里那一份必须没了（快照里再也拿不到它）。
        assert!(form.deploy_password.is_empty(), "交出去之后表单不该还留着密码");
        assert_eq!(form.deploy_step, 2, "投递之后这一页是「正在交给引擎」");
    }

    /// 草稿投影上**没有主按钮**：那一颗点下去发的是 `deployment-continue`，
    /// 而引擎会把草稿直接入队——一次没有密码的部署。
    #[test]
    fn a_draft_projection_offers_no_primary_action() {
        let view = FormState::deploy_run(DRAFT_ID, draft_fixture(22, "")).render();
        let buttons = buttons_in(&view);
        assert!(
            buttons.iter().all(|item| item["Tone"] != json!("primary")),
            "草稿不许有主按钮：{view}"
        );
        assert!(
            buttons.iter().all(|item| item["Id"] != json!("run-go")),
            "{view}"
        );
        // 万一点到了（页面与快照脱节）：什么都不发。
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(DRAFT_ID, draft_fixture(22, "")));
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "没有主动作时点了也不发命令：{steps:?}");
    }

    /// 向导里的草稿多一颗 ghost「放弃这次填写」；一次点击只发一条 `deployment-cancel`。
    #[test]
    fn the_wizard_offers_a_way_out_of_a_draft() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_draft_id = DRAFT_ID.into();
        let view = form.render();
        let discard: Vec<Value> = buttons_in(&view)
            .into_iter()
            .filter(|item| item["Id"] == json!("draft-discard"))
            .collect();
        assert_eq!(discard.len(), 1, "草稿必须给出路：{view}");
        assert_eq!(discard[0]["Text"], json!("放弃这次填写"));
        assert_eq!(discard[0]["Tone"], json!("ghost"), "它不是主按钮");

        // 第一次填写（没有草稿 id）时不该出现：没有东西可放弃。
        assert!(
            buttons_in(&FormState::deploy().render())
                .iter()
                .all(|item| item["Id"] != json!("draft-discard")),
            "空白向导不该有「放弃」"
        );

        // step 5（正在读指纹）是等待态：这时候放弃会留下一条「id 指向已删记录」的
        // 半死表单（probe 回包仍会把它推进到 step 1），接着点开始就是 `config` 错误。
        let mut probing = FormState::deploy();
        probing.deploy_draft_id = DRAFT_ID.into();
        probing.deploy_spec = "root@203.0.113.10".into();
        probing.deploy_step = 5;
        let probing_view = probing.render();
        assert!(
            buttons_in(&probing_view)
                .iter()
                .all(|item| item["Id"] != json!("draft-discard")),
            "读指纹的等待态不给出口：{probing_view}"
        );

        let mut ui = WebUi::new();
        ui.form = Some(form);
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"draft-discard","Generation":1}"#,
            &fetch,
        );
        assert_eq!(steps.len(), 1, "丢弃只发一条命令：{steps:?}");
        let Step::Sync(payload) = &steps[0] else {
            panic!("丢弃是短命令：{steps:?}");
        };
        assert!(payload.contains("deployment-cancel"), "{payload}");
        assert!(payload.contains(DRAFT_ID), "{payload}");
        for absent in [
            "deployment-continue",
            "deployment-background",
            "deployment-start",
        ] {
            assert!(!payload.contains(absent), "丢弃不该顺手发 {absent}：{payload}");
        }
    }

    /// 丢弃成功后**离开这一页**并给一句人话；详情页那条旧路径一个字不改。
    #[test]
    fn a_discarded_draft_closes_the_wizard_but_not_the_detail_page() {
        let mut form = FormState::deploy();
        form.deploy_draft_id = DRAFT_ID.into();
        let mut ui = WebUi::new();
        ui.form = Some(form);
        let state = merged_status_with(json!({
            "ok": true,
            "deployment": {
                "RunId": DRAFT_ID,
                "CancelRequested": true,
                "Discarded": true,
                "Message": "已放弃这份草稿，没有留下任务记录。",
            },
        }));
        ui.absorb_reply(r#"{"cmd":"deployment-cancel"}"#, &state);
        assert!(ui.form.is_none(), "草稿丢弃成功就该离开这一页");
        assert_eq!(ui.toast, "已放弃这份草稿，没有留下任务记录。");

        // 详情页：取消只是「已受理」，页面必须留着（要看得见接下来发生什么）。
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy_run(
            DRAFT_ID,
            run_fixture("Queued", "WaitQueue", "等待队列", 0, false),
        ));
        ui.absorb_reply(
            r#"{"cmd":"deployment-cancel"}"#,
            &json!({"ok": true, "deployment": {
                "RunId": DRAFT_ID,
                "CancelRequested": true,
                "Message": "已受理：当前步骤做完之后取消。",
            }}),
        );
        let form = ui.form.as_ref().expect("详情页不许被关掉");
        assert_eq!(
            form.deploy_notice, "已受理：当前步骤做完之后取消。",
            "结论要留在页面上"
        );
    }

    /// 从草稿开始的部署：**草稿身份当场作废**。
    ///
    /// 不清那一格的后果很具体：详情页后来点「取消这次部署」会命中「丢弃草稿」的收尾
    /// （命令是 cancel + 向导形态 + ok），把详情页也关掉——而详情页的取消只是受理，
    /// 页面必须留着看接下来发生什么。
    #[test]
    fn starting_from_a_draft_retires_the_draft_identity() {
        let mut form = FormState::deploy();
        form.deploy_draft_id = DRAFT_ID.into();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_fingerprint = "SHA256:AAAA".into();
        form.deploy_step = 2;
        let mut ui = WebUi::new();
        ui.form = Some(form);
        ui.absorb_reply(
            r#"{"cmd":"deployment-start"}"#,
            &json!({"ok": true, "deployment": {
                "RunId": DRAFT_ID,
                "Accepted": true, "Queued": true, "Message": "已受理，正在部署。",
            }}),
        );
        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.deploy_run_id, DRAFT_ID, "从这里开始由记录驱动");
        assert!(
            form.deploy_draft_id.is_empty(),
            "草稿已经不是草稿了，这一格必须清掉"
        );

        // 于是详情页的取消仍然只留在页面上。
        ui.absorb_reply(
            r#"{"cmd":"deployment-cancel"}"#,
            &json!({"ok": true, "deployment": {
                "RunId": DRAFT_ID,
                "CancelRequested": true,
                "Message": "已受理：当前步骤做完之后取消。",
            }}),
        );
        assert!(ui.form.is_some(), "详情页的取消不许关掉页面");
    }

    /// 「继续填写」：草稿进**同一页表单**（预填地址/账户/端口，密码不取回）；
    /// 其余进详情页。
    #[test]
    fn resume_opens_the_wizard_for_a_draft_and_the_detail_page_for_everything_else() {
        // ① 草稿 + 非 22 端口：账户与端口现在各有输入框，地址栏只留主机。
        let draft = draft_fixture(2222, "SHA256:AAAA");
        let mut ui = WebUi::new();
        ui.route(
            &format!(r#"{{"Type":"resume","Id":"{DRAFT_ID}"}}"#),
            &move |cmd: &str| {
                if cmd.contains("deployment-get") {
                    json!({"ok": true, "deployment": {"Run": draft}})
                } else {
                    fetch(cmd)
                }
            },
        );
        let form = ui.form.as_ref().expect("草稿要打开表单");
        assert_eq!(form.deploy_draft_id, DRAFT_ID);
        assert!(form.deploy_run_id.is_empty(), "草稿不是详情页");
        assert_eq!(form.deploy_spec, "203.0.113.10", "地址栏只留主机");
        assert_eq!(form.deploy_port, "2222", "端口在自己的输入框里");
        assert_eq!(form.deploy_user, "root");
        assert_eq!(form.deploy_fingerprint, "SHA256:AAAA");
        assert_eq!(form.deploy_step, 0, "用户看到的永远是那一页");
        assert!(form.deploy_password.is_empty(), "密码绝不取回");
        assert!(
            !form.deploy_known,
            "记录里没有「这台服务器已经存过凭据」这回事"
        );
        assert!(
            form.deploy_notice.contains("密码由已保存的登录资料提供"),
            "{}",
            form.deploy_notice
        );
        let view = form.render();
        assert!(
            buttons_in(&view)
                .iter()
                .any(|item| item["Id"] == json!("start")),
            "这一页要能开始部署：{view}"
        );
        // 表单里同时有密码框与两个勾——一页收完，不靠翻页。
        let text = serde_json::to_string(&view).unwrap();
        assert!(text.contains("DeployPassword"), "{text}");
        assert!(text.contains("在这台电脑记住登录资料"), "{text}");
        assert!(
            text.contains("中断后可用这份资料继续"),
            "r105：标题收口成这一句（期限在 Hint 里）：{text}"
        );

        // ② 22 端口仍然留在输入框里（不再靠地址里那串 `:22`）。
        let plain = draft_fixture(22, "");
        let mut ui = WebUi::new();
        ui.route(
            &format!(r#"{{"Type":"resume","Id":"{DRAFT_ID}"}}"#),
            &move |cmd: &str| {
                if cmd.contains("deployment-get") {
                    json!({"ok": true, "deployment": {"Run": plain}})
                } else {
                    fetch(cmd)
                }
            },
        );
        let form = ui.form.as_ref().unwrap();
        assert_eq!(form.deploy_spec, "203.0.113.10");
        assert_eq!(form.deploy_port, "22");
        assert_eq!(form.deploy_step, 0, "没有指纹也是同一页");
        assert!(form.deploy_draft_id == DRAFT_ID);

        // ③ 非草稿 → 详情页（旧路径逐字不变）。
        let running = run_fixture("Running", "None", "", 1, true);
        let mut ui = WebUi::new();
        ui.route(
            &format!(r#"{{"Type":"resume","Id":"{DRAFT_ID}"}}"#),
            &move |cmd: &str| {
                if cmd.contains("deployment-get") {
                    json!({"ok": true, "deployment": {"Run": running}})
                } else {
                    fetch(cmd)
                }
            },
        );
        let form = ui.form.as_ref().unwrap();
        assert_eq!(form.deploy_run_id, DRAFT_ID);
        assert!(
            form.deploy_draft_id.is_empty(),
            "进行中的任务不该被当成草稿"
        );
    }

    /// 有指纹（身份已核对）之后，投递落一条**部署任务**：命令必须是 `deployment-start`。
    ///
    /// `server-setup` 的界面路径已经退役（回了 `usage`），页面若还发它，
    /// 用户点「开始部署」只会看到「已改用部署任务」——那是个死按钮。
    #[test]
    fn the_old_wizard_creates_a_deployment_task_instead_of_calling_server_setup() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        let _ = ui.route(
            r#"{"Type":"form","Event":"change","Id":"spec","Value":"root@203.0.113.10"}"#,
            &fetch,
        );
        {
            let form = ui.form.as_mut().unwrap();
            form.deploy_fingerprint = "SHA256:AAAA".into();
            form.deploy_known = true;
            form.deploy_password = "hunter2".into();
            form.deploy_cloud = true;
        }
        // 指纹已经在手：投递由宿主接力（`deploy_start_steps`），不再经过读指纹那一步。
        let steps = ui
            .form
            .as_mut()
            .expect("表单还在")
            .deploy_start_steps();
        // 一次点击 = 一批两步（先落草稿、再开始）。命令仍然是 `deployment-start`。
        assert_eq!(steps.len(), 2, "先存草稿再开始：{steps:?}");
        let Step::Sync(save) = &steps[0] else {
            panic!("存草稿要毫秒级回包：{steps:?}");
        };
        assert!(save.contains("deployment-draft-save"), "{save}");
        let Step::Sync(payload) = &steps[1] else {
            panic!("建任务要毫秒级回包：{steps:?}");
        };
        assert!(payload.contains("deployment-start"), "{payload}");
        assert!(
            !payload.contains("server-setup"),
            "退役的命令不许再出现在界面路径上：{payload}"
        );
    }

    /// 任务建好之后，表单立刻改成记录驱动：页面不该还停在旧向导的「正在部署」。
    #[test]
    fn a_started_deployment_switches_the_form_to_the_record_driven_view() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        ui.absorb_reply(
            r#"{"cmd":"deployment-start"}"#,
            &json!({"ok": true, "deployment": {
                "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                "Accepted": true, "Queued": true,
                "Message": "已受理，正在部署。",
            }}),
        );
        let form = ui.form.as_ref().expect("表单还在");
        assert_eq!(form.deploy_run_id, "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f");
        assert_eq!(form.deploy_run["State"], json!("Queued"));
        // 「已受理」要留在页面上：这一刻记录还没被引擎推进，用户需要一句确认。
        assert_eq!(form.deploy_notice, "已受理，正在部署。");
        let texts = texts_in(&form.render()).join("\n");
        assert!(texts.contains("排队中"), "{texts}");
    }

    /// 建任务失败：不许留下一个假的 RunId（后续每帧都会去读一条不存在的记录）。
    #[test]
    fn a_refused_start_leaves_the_wizard_on_its_form() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::deploy());
        ui.absorb_reply(
            r#"{"cmd":"deployment-start"}"#,
            &json!({"ok": false, "error": "没能把这条部署任务写到磁盘：拒绝访问", "errorCode": "config"}),
        );
        let form = ui.form.as_ref().unwrap();
        assert!(form.deploy_run_id.is_empty(), "失败不许留 RunId");
        assert!(form.deploy_notice.contains("拒绝访问"), "{}", form.deploy_notice);
        assert_eq!(form.deploy_step, 4);
    }

    /// **有未决写时只能核对**，哪怕 `NextAction` 还写着「重试本步骤」。
    ///
    /// 这条优先级与 `deployrun::action_of` 一致：未决写 > NextAction。少这一条，
    /// 界面会给一个「重试」按钮，点下去就是「已经写出去的东西再写一遍」。
    #[test]
    fn a_pending_write_always_wins_over_the_next_action() {
        let mut run = run_fixture("NeedsAttention", "RetryStep", "重试本步骤", 1, false);
        run["PendingOperation"] = json!({
            "Kind": "UdpInstall",
            "AttemptNo": 1,
            "StartedAtUtc": "2026-11-09T09:03:00Z",
            "VerifyBy": "ProbeUdpState",
            "PlanDigest": "sha256:9f1c",
            "ClientPublicKey": Value::Null,
            "Outcome": "Pending",
        });
        let mut form = FormState::deploy_run("3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f", run);

        let view = form.render();
        let primaries: Vec<Value> = buttons_in(&view)
            .into_iter()
            .filter(|item| item["Tone"] == json!("primary"))
            .collect();
        assert_eq!(primaries.len(), 1, "{primaries:?}");
        assert_eq!(primaries[0]["Text"], json!("核对原操作"), "{primaries:?}");

        // 点它必须是只读核对，绝不能重发写命令。
        let mut ui = WebUi::new();
        ui.form = Some(form);
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"run-go","Generation":1}"#,
            &fetch,
        );
        let Step::Sync(payload) = &steps[0] else {
            panic!("核对是短命令：{steps:?}");
        };
        assert!(payload.contains("\"verifyOnly\":true"), "{payload}");
    }

    #[test]
    fn snapshot_matches_the_web_contract() {
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["Type"], "snapshot");
        assert_eq!(snap["Page"], "home");
        let s = &snap["State"];
        assert_eq!(s["State"], "Connected");
        assert_eq!(s["Running"], true);
        assert_eq!(s["TradeExit"], "hk");
        assert_eq!(s["Daily"], "Direct");
        assert_eq!(s["Lines"].as_array().map(Vec::len), Some(2));
        assert_eq!(s["Lines"][0]["Readiness"]["State"], "InUse");
        assert_eq!(s["Lines"][1]["Readiness"]["State"], "Untested");
        assert_eq!(s["Quality"]["LatencyMs"], 180);
        assert_eq!(s["Quality"]["Quality"], "Good");
        assert_eq!(s["Quality"]["Degraded"], false);
        // 统计卡：hk 有读数、jp 一次都没测过（界面显示「暂无读数」，不是 0 ms）。
        assert_eq!(s["Lines"][0]["Quality30m"]["MedianLatencyMs"], 180);
        assert_eq!(s["Lines"][0]["Quality30m"]["UnavailableCount"], 1);
        assert_eq!(s["Lines"][1]["Quality30m"]["SampleCount"], 0);
        assert_eq!(s["Settings"]["CloseBehavior"], "Tray");
        assert_eq!(s["ExitEvidence"]["Status"], "forwarded-unverified");
    }

    #[test]
    fn stale_or_degraded_samples_change_what_the_page_is_told() {
        // 采样过期：宁可说「质量未知」，也不能把半小时前的 180 ms 当当前响应。
        let stale = |cmd: &str| {
            if cmd.contains("quality-summary") {
                json!({"ok": true, "qualitySummary": {
                    "SampleCount": 3, "MeasuredCount": 0, "UnavailableCount": 3,
                    "Samples": [], "LastLatencyMs": Value::Null, "LastReason": "MeasurementTimeout",
                    "Fresh": false, "Degraded": false, "NotificationMessage": "",
                }})
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&stale);
        assert!(snap["State"]["Quality"]["LatencyMs"].is_null(), "{snap}");
        assert_eq!(snap["State"]["Quality"]["Quality"], "Unknown");
        assert_eq!(snap["State"]["Quality"]["Degraded"], false);

        // 连续三次变差：标题会变「线路不稳定」，横幅用宿主那句原话。
        let degraded = |cmd: &str| {
            if cmd.contains("quality-summary") {
                json!({"ok": true, "qualitySummary": {
                    "SampleCount": 3, "MeasuredCount": 3, "UnavailableCount": 0,
                    "Samples": [600, 700], "LastLatencyMs": 700, "LastReason": "Measured",
                    "Fresh": true, "Degraded": true,
                    "NotificationMessage": "当前交易出口连续 3 次延迟较高，请检查线路；当前线路保持。",
                }})
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&degraded);
        assert_eq!(snap["State"]["Quality"]["Degraded"], true);
        assert_eq!(snap["State"]["Quality"]["Quality"], "Poor");
        assert!(snap["State"]["Quality"]["NotificationMessage"]
            .as_str()
            .unwrap_or("")
            .contains("连续 3 次延迟较高"));

        // 健康时的横幅文案必须是空串，页面据此判断不显示。
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Quality"]["NotificationMessage"], "");
    }

    #[test]
    fn standby_items_come_from_the_background_cache_and_recommend_the_fastest() {
        let mut ui = WebUi::new();
        let now = now_unix();
        *ui.standby.lock().unwrap() = vec![
            json!({"NodeId": "jp", "LineName": "东京 02", "LatencyMs": 42, "AtUnix": now}),
            json!({"NodeId": "sg", "LineName": "新加坡", "LatencyMs": 90, "AtUnix": now - 400}),
            json!({"NodeId": "hk", "LineName": "香港 01", "LatencyMs": 12, "AtUnix": now}),
        ];
        let snap = ui.snapshot(&fetch);
        let standby = &snap["State"]["Standby"];
        let items = standby["Items"].as_array().unwrap();
        // 当前线路不参与「备用」列表；过期的条目仍列出但标成不新鲜。
        assert!(items.iter().all(|i| i["NodeId"] != "hk"), "{standby}");
        let sg = items.iter().find(|i| i["NodeId"] == "sg").unwrap();
        assert_eq!(sg["Fresh"], false);
        assert!(sg["LatencyMs"].is_null(), "过期读数不能当当前值报：{sg}");
        assert_eq!(sg["Reason"], "SampleExpired");
        // 推荐只在新鲜的里面挑最快的：42 ms 的东京，不是过期的 90 ms。
        assert_eq!(standby["Recommendation"]["NodeId"], "jp");
        assert_eq!(standby["Recommendation"]["LatencyMs"], 42);
    }

    /// 「服务器与设备」：点一下打开只读页，回包把设备列出来。
    #[test]
    fn the_server_devices_page_lists_what_the_server_reports() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);

        let steps = ui.route(r#"{"Type":"lineServer","Id":"hk","Sequence":1}"#, &fetch);
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains("server-devices") && c.contains("hk")),
            "{steps:?}"
        );
        assert_eq!(ui.form.as_ref().map(|f| f.view), Some(View::Devices));

        ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverDevices": {
                "server": {
                    "name": "root@203.0.113.10", "user": "root", "host": "203.0.113.10",
                    "port": 22, "fingerprint": "SHA256:abc", "interface": "tc32d4f356",
                    "udpPort": 51820, "subnet": "10.66.0.0/24",
                },
                "tunnel": {"up": true, "latestHandshake": 1_700_000_000, "rxBytes": 4096, "txBytes": 2048},
                "devices": [{
                    "address": "10.66.0.2", "shortKey": "zOzOTCHg", "handshake": 1_700_000_000,
                    "rxBytes": 4096, "txBytes": 2048, "endpoint": "203.0.113.5:51820",
                    "thisDevice": true,
                }],
            },
        }));
        let snapshot = ui.snapshot(&fetch).to_string();
        assert!(snapshot.contains("10.66.0.2"), "设备地址要出现");
        assert!(snapshot.contains("（本机）"), "本机要标出来");
        assert!(snapshot.contains("已登记的设备（1 台）"), "要报出设备数");
        assert!(snapshot.contains("tc32d4f356"), "服务器接口要出现");
        assert!(snapshot.contains("SHA256:abc"), "指纹要出现");
    }

    /// 读不到时：错误留在页面上，并给一个「重新读取」。
    #[test]
    fn a_failed_devices_read_keeps_the_reason_on_the_page() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"lineServer","Id":"hk","Sequence":1}"#, &fetch);
        ui.finish_op(&serde_json::json!({
            "ok": false,
            "error": "这条线路不是本机部署的服务器线路",
            "serverDevices": {"error": "这条线路不是本机部署的服务器线路"},
        }));
        let snapshot = ui.snapshot(&fetch).to_string();
        assert!(snapshot.contains("读不到设备列表"), "要有失败标题");
        assert!(snapshot.contains("不是本机部署的"), "要带上宿主的原因");
        assert!(snapshot.contains("重新读取"), "要给重试入口");
    }

    /// 撤销设备：确认后才发命令，回包落到同一张表单，列表当场少一台。
    #[test]
    fn revoking_a_device_updates_the_devices_page_in_place() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"lineServer","Id":"hk","Sequence":1}"#, &fetch);
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverDevices": {
                "server": {
                    "name": "自建 · 1.2.3.4", "host": "1.2.3.4", "port": 22, "user": "root",
                    "fingerprint": "SHA256:abc", "interface": "tc1", "udpPort": 51820,
                    "subnet": "10.66.0.0/24",
                },
                "tunnel": {"up": true, "latestHandshake": 0, "rxBytes": 0, "txBytes": 0},
                "devices": [
                    {
                        "address": "10.66.0.2",
                        "publicKey": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
                        "shortKey": "yAnz5TF+", "handshake": 0, "rxBytes": 0, "txBytes": 0,
                        "endpoint": "(none)", "thisDevice": true,
                    },
                    {
                        "address": "10.66.0.3",
                        "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "shortKey": "AAAAAAAA", "handshake": 0, "rxBytes": 0, "txBytes": 0,
                        "endpoint": "(none)", "thisDevice": false,
                    },
                ],
            },
        }));
        let steps = ui.route(
            r#"{"Type":"form","Id":"revoke-1","Event":"click","Sequence":2}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "确认之前不能发命令：{steps:?}");
        let steps = ui.route(
            r#"{"Type":"form","Id":"revoke-confirm","Event":"click","Sequence":3}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains("server-revoke")),
            "{steps:?}"
        );
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverRevoke": {
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "peers": 1,
            },
        }));
        let snapshot = ui.snapshot(&fetch).to_string();
        assert!(snapshot.contains("已移除这台设备"), "{snapshot}");
        assert!(!snapshot.contains("10.66.0.3"), "被撤销的设备不该还在列表里：{snapshot}");
    }

    /// 「自己搭服务器」从首页入口一路走到底：**一页表单** → 点一次「开始部署」→
    /// 读指纹 → 确认身份 → 投递 → 完成。
    ///
    /// 这条测试守的就是用户要的那个交互：页面上永远只有那一页，
    /// 「读指纹」与「确认身份」都是它的内部步骤，不是另一页。
    #[test]
    fn the_self_hosted_deploy_form_walks_from_address_to_a_task() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);

        // 首页「自己搭服务器」= `add`（配对第二步的「自己搭一台服务器」也发这个）。
        let steps = ui.route(r#"{"Type":"add","Sequence":1}"#, &fetch);
        assert!(steps.is_empty(), "打开表单不该发命令：{steps:?}");
        assert_eq!(ui.form.as_ref().map(|f| f.view), Some(View::Deploy));

        // 空地址点「开始部署」：不发命令，就地提示。
        ui.route(r#"{"Type":"form","Event":"change","Id":"deploy-cloud","Value":true}"#, &fetch);
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"start"}"#, &fetch);
        assert!(steps.is_empty(), "空地址不该发命令");
        assert!(
            ui.form.as_ref().unwrap().deploy_notice.contains("服务器地址"),
            "{}",
            ui.form.as_ref().unwrap().deploy_notice
        );

        // 填地址 → 点「开始部署」→ 同一批两步：落草稿（Sync）+ 读指纹（Long）。
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"spec","Value":"root@203.0.113.10"}"#,
            &fetch,
        );
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"start"}"#, &fetch);
        assert_eq!(steps.len(), 2, "{steps:?}");
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("deployment-draft-save")),
            "{steps:?}"
        );
        assert!(
            matches!(&steps[1], Step::Long(c) if c.contains("server-probe") && c.contains("root@203.0.113.10")),
            "{steps:?}"
        );
        // 页面还在那一页，只是把按钮禁掉并说明在干什么。
        let text = serde_json::to_string(&ui.form.as_ref().unwrap().render()).unwrap();
        assert!(text.contains("正在核对服务器身份"), "{text}");
        assert!(text.contains("DeployPassword"), "密码框仍在同一页：{text}");

        // 回包：第一次接触这台服务器 → 弹「确认首次服务器身份」，一个字都不投递。
        let followups = ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverProbe": {"fingerprint": "SHA256:abc", "known": false},
        }));
        assert!(followups.is_empty(), "确认之前不许发命令：{followups:?}");
        let dialog = ui.dialog.clone().unwrap_or(Value::Null);
        assert_eq!(dialog["Title"], "确认首次服务器身份", "{dialog}");
        assert_eq!(dialog["Scope"], "deploy-identity", "{dialog}");
        assert!(
            dialog["Body"].as_str().unwrap_or("").contains("root@203.0.113.10:22"),
            "对话框要说清目标：{dialog}"
        );
        assert!(
            dialog["Body"].as_str().unwrap_or("").contains("SHA256:abc"),
            "对话框要带上指纹：{dialog}"
        );
        assert!(
            dialog["Note"].as_str().unwrap_or("").contains("关闭窗口不会登录"),
            "{dialog}"
        );
        assert_eq!(ui.form.as_ref().unwrap().deploy_fingerprint, "SHA256:abc");

        // 填密码 → 确认指纹 → 这一批才真的投递。
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"password","Value":"s3cret"}"#,
            &fetch,
        );
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        let start_cmd = steps
            .iter()
            .find_map(|step| match step {
                Step::Sync(c) if c.contains("deployment-start") => Some(c.clone()),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("确认之后要把部署任务投出去，不是已经退役的 server-setup：{steps:?}")
            });
        assert!(
            start_cmd.contains("s3cret"),
            "这一次的密码要交给部署任务：{start_cmd}"
        );
        assert!(start_cmd.contains("SHA256:abc"), "{start_cmd}");
        assert!(
            ui.form.as_ref().unwrap().deploy_password.is_empty(),
            "密码发出去之后不能留在表单里"
        );
        assert_eq!(ui.form.as_ref().unwrap().deploy_step, 2);
        assert!(ui.dialog.is_none(), "确认过的对话框要收掉");

        // 回包：任务编号到了就切到记录驱动的详情页。
        //
        // `deployment-start` 是**短命令**，回包走 `absorb_reply`（不走 `finish_op`）：
        // 这条路径测的正是生产里那一条。
        ui.absorb_reply(
            r#"{"cmd":"deployment-start"}"#,
            &serde_json::json!({
                "ok": true,
                "deployment": {
                    "RunId": "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f",
                    "Accepted": true, "Queued": true, "Message": "已受理，正在部署。",
                },
            }),
        );
        let form = ui.form.as_ref().unwrap();
        assert_eq!(form.deploy_run_id, "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f");
        assert_eq!(form.deploy_run["State"], json!("Queued"));
    }

    /// 已经保存过凭据的服务器：不再问身份、不用再输密码，读指纹回来直接投递。
    #[test]
    fn a_known_server_skips_the_password_field() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"add","Sequence":1}"#, &fetch);
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"spec","Value":"root@203.0.113.10"}"#,
            &fetch,
        );
        ui.route(r#"{"Type":"form","Event":"change","Id":"deploy-cloud","Value":true}"#, &fetch);
        ui.route(r#"{"Type":"form","Event":"click","Id":"start"}"#, &fetch);
        // 已有记录 = 身份早就核对过：不需要确认对话框，直接接力投递。
        let steps = ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverProbe": {"fingerprint": "SHA256:abc", "known": true},
        }));
        assert!(ui.dialog.is_none(), "已知身份不该再问一遍");
        let start_cmd = steps
            .iter()
            .find_map(|step| match step {
                Step::Sync(c) if c.contains("deployment-start") => Some(c.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("开始部署要发 deployment-start：{steps:?}"));
        // 断言的是「没有 password **字段**」——r92 起命令里还会带
        // `loginMethod:"password"`，那不是密码本身，用子串判会误伤。
        let sent: serde_json::Value =
            serde_json::from_str(&start_cmd).unwrap_or(serde_json::Value::Null);
        assert!(
            sent.get("password").is_none(),
            "有凭据时不该再传密码：{start_cmd}"
        );
    }

    /// **密码不能出现在快照里**：快照会进 DOM、进崩溃转储。
    #[test]
    fn the_deploy_password_never_reaches_the_snapshot() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"add","Sequence":1}"#, &fetch);
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"spec","Value":"root@203.0.113.10"}"#,
            &fetch,
        );
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "serverProbe": {"fingerprint": "SHA256:abc", "known": false},
        }));
        ui.route(
            r#"{"Type":"form","Event":"change","Id":"password","Value":"s3cret-value"}"#,
            &fetch,
        );
        let snapshot = ui.snapshot(&fetch).to_string();
        assert!(!snapshot.contains("s3cret-value"), "密码不能出现在快照里");
        // 但「已经填过」这件事要告诉页面，否则用户不知道密码框是不是空的。
        assert!(snapshot.contains("SecretPresent"), "要告诉页面密码已填");
    }

    #[test]
    fn intents_translate_to_existing_commands() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":1}"#, &fetch);
        assert!(matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"use\"")));
        assert!(matches!(steps.last(), Some(Step::Long(c)) if c.contains("\"connect\"")));
        assert!(ui.busy);

        let steps = ui.route(r#"{"Type":"setProfile","Id":"jp","Value":"Tcp","Sequence":2}"#, &fetch);
        assert!(matches!(steps.first(), Some(Step::Sync(c)) if c.contains("set-transport") && c.contains("\"tcp\"")));

        // 线路变差提醒现在有后端了：必须真的发设置命令，不能只弹一句「暂未支持」。
        let steps = ui.route(
            r#"{"Type":"setting","Name":"QualityWarning","Value":false,"Sequence":3}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("settings") && c.contains("qualityWarning")),
            "{steps:?}"
        );
        assert!(ui.toast.is_empty(), "不该再给「暂未支持」的提示：{}", ui.toast);

        let steps = ui.route(r#"{"Type":"daily","Value":"Trade","Sequence":4}"#, &fetch);
        assert!(matches!(steps.first(), Some(Step::Sync(c)) if c.contains("exit-set") && c.contains("\"hk\"")));

        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":5}"#, &fetch);
        assert!(ui.dialog.is_some());
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":6}"#, &fetch);
        assert!(matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"remove\"")));

        // 配对流程已经能用了：页面统一发 `pairOnline`，宿主不再对 pair* 回「后续版本开放」。
        ui.route(r#"{"Type":"pairStart","Sequence":7}"#, &fetch);
        assert!(!ui.toast.contains("后续版本"), "配对已可用，不能再回「后续版本」：{}", ui.toast);
        // 「邀请其他电脑」能用了：真实入口走 `{Phase:'Begin'}`。不带 Phase 的裸消息
        // 只做一次重绘，绝不能回「后续版本开放」——那句话已经不成立。
        ui.route(r#"{"Type":"invite","Sequence":8}"#, &fetch);
        assert!(!ui.toast.contains("后续版本"), "邀请已可用，不能再回「后续版本」：{}", ui.toast);
        // 旧版表单入口也不能点了没反应。
        ui.route(r#"{"Type":"joinLine","Sequence":9}"#, &fetch);
        assert!(ui.toast.contains("旧版表单"), "{}", ui.toast);
    }

    /// 删除预览的三种结论各走各的对话框：能删才给「删除」按钮，
    /// 不能删/读不出只给「知道了」，且确认一次**不发任何命令**。
    fn fetch_with_delete_preview(reply: Value) -> impl Fn(&str) -> Value {
        move |cmd: &str| {
            let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
            if parsed.get("cmd").and_then(Value::as_str) == Some("delete-preview") {
                reply.clone()
            } else {
                fetch(cmd)
            }
        }
    }

    #[test]
    fn delete_dialog_lists_removals_and_preserved_things() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":1}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("必须弹出删除确认");
        assert_eq!(dialog["Scope"], "delete", "{dialog}");
        assert_eq!(dialog["Target"], "jp", "{dialog}");
        assert_eq!(dialog["Confirm"], "删除", "{dialog}");
        assert_eq!(dialog["Danger"], true, "{dialog}");
        assert!(
            dialog["Body"].as_str().unwrap_or("").contains("隧道私钥文件"),
            "有引擎配置时必须说清私钥会被删：{dialog}"
        );
        let details = dialog["Details"].as_str().unwrap_or("");
        assert!(details.contains("将删除"), "{details}");
        assert!(details.contains("lines\\jp.json"), "{details}");
        assert!(details.contains("将保留"), "{details}");
        assert!(
            details.contains("服务器记录与登录凭据（设置 → 服务器）：root@203.0.113.10"),
            "保留项必须点名是哪台服务器：{details}"
        );
        assert!(details.contains("服务器上的 WireGuard 服务与设备授权"), "{details}");

        // 没有引擎配置的线路：文案不能跟着说「私钥会被删」。
        ui.route(r#"{"Type":"delete","Id":"hk","Sequence":2}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("必须弹出删除确认");
        let body = dialog["Body"].as_str().unwrap_or("");
        assert!(body.contains("本机会移除线路配置"), "{dialog}");
        assert!(!body.contains("隧道私钥"), "没有引擎配置就别提私钥：{dialog}");
    }

    #[test]
    fn a_blocked_delete_offers_no_delete_button_and_emits_no_command() {
        let mut ui = WebUi::new();
        let fetch = fetch_with_delete_preview(json!({
            "ok": true,
            "deletePreview": {
                "Id": "jp", "Name": "东京 02", "Selected": false, "LastLine": false,
                "Eligible": false,
                "Blocked": [{"Code": "Busy", "Message": "连接未断开：请先断开再删除。"}],
                "Files": [], "Server": Value::Null, "Warnings": [],
            }
        }));
        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":1}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("必须给出结论");
        assert_eq!(dialog["Title"], "暂时无法删除线路", "{dialog}");
        assert_eq!(dialog["Scope"], "delete-blocked", "{dialog}");
        assert_eq!(dialog["Confirm"], "知道了", "{dialog}");
        assert_eq!(dialog["Cancel"], "", "不能删时不该出现「取消」这种假选择：{dialog}");
        assert_eq!(dialog["Danger"], false, "{dialog}");
        assert!(dialog["Body"].as_str().unwrap_or("").contains("先断开"), "{dialog}");

        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert!(
            !steps.iter().any(|step| matches!(step, Step::Sync(c) if c.contains("\"remove\""))),
            "阻塞结论上确认不许发 remove：{steps:?}"
        );
        assert!(ui.dialog.is_none(), "知道了应当关掉结论框");
    }

    #[test]
    fn a_failed_preview_explains_itself_instead_of_falling_back_to_delete() {
        let mut ui = WebUi::new();
        let fetch = fetch_with_delete_preview(json!({
            "ok": false,
            "error": "读不出删除预览（配置损坏）。",
            "errorCode": "config",
        }));
        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":1}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("读失败也要有结论");
        assert_eq!(dialog["Title"], "暂时无法删除线路", "不得落回旧的一键删除：{dialog}");
        assert_eq!(dialog["Scope"], "delete-blocked", "{dialog}");
        assert!(
            dialog["Body"].as_str().unwrap_or("").contains("配置损坏"),
            "要保留后端原话：{dialog}"
        );

        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert!(
            !steps.iter().any(|step| matches!(step, Step::Sync(c) if c.contains("\"remove\""))),
            "没有预览结论就不许发 remove：{steps:?}"
        );

        // `ok:true` 但没有预览体：同样算「没有结论」，不得当成都可删。
        let mut ui = WebUi::new();
        let fetch = fetch_with_delete_preview(json!({"ok": true}));
        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":1}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("缺预览体也要有结论");
        assert_eq!(dialog["Scope"], "delete-blocked", "{dialog}");
        assert_eq!(dialog["Confirm"], "知道了", "{dialog}");
    }

    /// 生产里 `route` 的 `fetch` 是「status + 白名单合并」，不是原始命令回包。
    /// 预览必须穿过 [`merge_ui_command_reply`]：漏键时单测全绿，真机却永远弹
    /// 「这条线路现在不能删除」（`Eligible` 读不到 → 默认 false）。
    #[test]
    fn the_delete_preview_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "deletePreview": {
                "Id": "jp", "Name": "东京 02", "Selected": false, "LastLine": false,
                "Eligible": true, "Blocked": [], "Files": ["lines\\jp.json"],
                "Server": {"Id": "srv-1", "Name": "root@203.0.113.10", "Host": "203.0.113.10"},
                "Warnings": [],
            }
        }));
        let fetch = move |cmd: &str| {
            let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
            if parsed.get("cmd").and_then(Value::as_str) == Some("delete-preview") {
                merged.clone()
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"delete","Id":"jp","Sequence":1}"#, &fetch);
        let dialog = ui.dialog.as_ref().expect("必须弹出删除确认");
        assert_eq!(
            dialog["Scope"], "delete",
            "预览穿过宿主合并后仍要能删（白名单漏了 deletePreview 就到这里）：{dialog}"
        );
        assert!(
            dialog["Details"].as_str().unwrap_or("").contains("将删除"),
            "{dialog}"
        );
    }

    // ---------- 删除结果核对与待清理（A4 第二轮）----------

    /// `remove` 的回包要穿过宿主合并：漏 `deleteResult` 时页面会把「文件没删掉」
    /// 说成「线路已删除」——正是这一轮要消灭的那句谎。
    #[test]
    fn the_delete_result_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "deleteResult": {
                "Id": "jp", "Name": "东京 02", "File": "lines\\jp.json",
                "Incomplete": true, "Error": "另一个程序正在使用此文件。",
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"remove","id":"jp"}"#, &merged);
        assert!(
            ui.toast.contains("没删掉") && ui.toast.contains("lines\\jp.json"),
            "合并丢了 deleteResult，页面只会说「线路已删除」：{}",
            ui.toast
        );

        let clean = merged_status_with(json!({
            "ok": true,
            "deleteResult": {
                "Id": "jp", "Name": "东京 02", "File": "lines\\jp.json",
                "Incomplete": false, "Error": Value::Null,
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"remove","id":"jp"}"#, &clean);
        assert_eq!(ui.toast, "线路已删除");
    }

    /// 待清理记录要穿过宿主合并呈现到页面上：漏 `deleteCleanup` 时快照恒空，
    /// 含私钥的残留文件就从界面消失了。
    #[test]
    fn a_pending_cleanup_survives_the_merge_and_is_projected() {
        let merged = merged_status_with(json!({
            "ok": true,
            "deleteCleanup": {
                "ReadError": "",
                "Pending": [
                    {"Id": "jp", "Name": "东京 02", "File": "lines\\jp.json", "Error": "被占用。"},
                    {"Id": "us", "Name": "洛杉矶 03", "File": "lines\\us.json", "Error": "拒绝访问。"},
                ],
            }
        }));
        let fetch = move |cmd: &str| {
            let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
            if parsed.get("cmd").and_then(Value::as_str) == Some("delete-cleanup") {
                merged.clone()
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let operation = &snap["State"]["DeleteOperation"];
        assert_eq!(operation["Kind"], "Cleanup", "{operation}");
        assert_eq!(operation["Id"], "jp", "一次显示一条，按记录顺序：{operation}");
        assert_eq!(operation["Phase"], "Blocked", "{operation}");
        assert_eq!(operation["CanRetry"], true, "{operation}");
        assert_eq!(operation["CanCancel"], false, "{operation}");
        let message = operation["Message"].as_str().unwrap_or("");
        assert!(message.contains("没删掉") && message.contains("lines\\jp.json"), "{message}");
        assert!(message.contains("另有 1 条"), "多条待清理要说清还有多少：{message}");
        assert!(snap["State"]["DeleteRefresh"].is_null());
    }

    /// 记录坏了：说「读不出来」且**不给**重试按钮（没有 id 可重试）。
    #[test]
    fn a_corrupt_cleanup_record_is_shown_as_unknown_without_retry() {
        let merged = merged_status_with(json!({
            "ok": false,
            "error": "待清理记录不是合法 JSON（logs\\delete-cleanup.json）",
            "errorCode": "cleanup",
            "deleteCleanup": {
                "Pending": [],
                "ReadError": "待清理记录不是合法 JSON（logs\\delete-cleanup.json）",
            }
        }));
        let fetch = move |cmd: &str| {
            let parsed: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
            if parsed.get("cmd").and_then(Value::as_str) == Some("delete-cleanup") {
                merged.clone()
            } else {
                fetch(cmd)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let operation = &snap["State"]["DeleteOperation"];
        assert_eq!(operation["Kind"], "Cleanup", "{operation}");
        assert_eq!(operation["CanRetry"], false, "{operation}");
        assert!(
            operation["Message"].as_str().unwrap_or("").contains("读不出来"),
            "不能把“读不出”显示成“没有”：{operation}"
        );
    }

    /// 「重试清理」必须发真命令，而不是占位 toast。
    #[test]
    fn retrying_a_cleanup_runs_the_real_command() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"retryDelete","Id":"jp","Sequence":1}"#, &fetch);
        assert!(
            matches!(&steps[0], Step::Sync(c)
                if c.contains("\"delete-cleanup-retry\"") && c.contains("\"id\":\"jp\"")),
            "重试清理没有落到真命令上：{steps:?}"
        );
    }

    /// 重试的回包同样要穿过合并：漏 `deleteCleanupResult` 时点了按钮一句话都没有。
    #[test]
    fn the_cleanup_retry_reply_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "deleteCleanupResult": {
                "Id": "jp", "Name": "东京 02", "File": "lines\\jp.json",
                "Complete": true, "Removed": true, "Error": Value::Null,
                "Message": "已清理线路「东京 02」的残留文件 lines\\jp.json。",
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"delete-cleanup-retry","id":"jp"}"#, &merged);
        assert!(
            ui.toast.contains("已清理"),
            "合并丢了 deleteCleanupResult，点重试后页面不会回话：{}",
            ui.toast
        );
    }

    /// 曲线回包也要穿过合并。它是**早已存在**的第六次同类缺陷：抽屉点开一次，
    /// 曲线恒停在「正在读取历史…」——命令毫秒级答完，回包被合并吞掉。
    #[test]
    fn the_quality_history_reply_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "qualityHistory": {
                "NodeId": "hk", "Window": "ThirtyMinutes", "Loading": false,
                "Reason": "", "Series": [],
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"quality-history"}"#, &merged);
        let snap = ui.snapshot(&fetch);
        assert_eq!(
            snap["State"]["QualityHistory"]["NodeId"], "hk",
            "白名单漏了 qualityHistory，抽屉永远读不到自己的曲线：{}",
            snap["State"]["QualityHistory"]
        );
    }

    /// 「自动」不是一个 toast，而是一条真命令：`set-transport` + `transport: "auto"`。
    #[test]
    fn choosing_auto_sends_a_real_command_and_never_says_unsupported() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(
            r#"{"Type":"setProfile","Id":"hk","Value":"Auto","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c))
                if c.contains("set-transport") && c.contains("\"auto\"") && c.contains("\"hk\"")),
            "「自动」必须发 set-transport：{steps:?}"
        );
        assert!(ui.toast.is_empty(), "「自动」已可用，不该再弹提示：{}", ui.toast);
        // 死分支必须真的删掉，而不只是「不再走到」：源码里不许再有那句 toast。
        // 断言用的原文由两段拼出来——否则 `include_str!` 会把这条断言自己也算进去。
        let gone = concat!("预览版暂不支持", "「自动」连接方式");
        let source = include_str!("uiweb.rs");
        assert!(!source.contains(gone), "「{gone}」的 toast 必须整段删掉，不能留死分支");
        // 标准/兼容两档的老行为不变。
        let steps = ui.route(
            r#"{"Type":"setProfile","Id":"hk","Value":"Udp","Sequence":2}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"udp\"")),
            "{steps:?}"
        );
        let steps = ui.route(
            r#"{"Type":"setProfile","Id":"hk","Value":"Tcp","Sequence":3}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c)) if c.contains("\"tcp\"")),
            "{steps:?}"
        );
    }

    /// 线路卡片必须说真话：`ProfileSource` / `AutomaticNeedsCheck` 不许再是硬编码。
    #[test]
    fn line_cards_report_the_real_profile_source_and_whether_auto_needs_a_check() {
        let with_lines = |lines: Value| {
            move |cmd: &str| {
                let mut v = fetch(cmd);
                if cmd.contains("\"lines\"") {
                    v["lines"] = lines.clone();
                }
                v
            }
        };
        // 三种现场：自动且没依据 / 用户固定 / 自动但已有依据。
        let lines = json!([
            {"id": "hk", "name": "香港 01", "endpoint": "1.2.3.4:443", "selected": true,
             "transport": "udp", "transportSelected": false, "transportVerified": false},
            {"id": "jp", "name": "东京 02", "endpoint": "5.6.7.8:443", "selected": false,
             "transport": "tcp", "transportSelected": true, "transportVerified": true},
            {"id": "sg", "name": "新加坡 03", "endpoint": "9.9.9.9:443", "selected": false,
             "transport": "tcp", "transportSelected": false, "transportVerified": true},
        ]);
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&with_lines(lines));
        let cards = snap["State"]["Lines"].as_array().expect("lines 卡片");
        assert_eq!(cards.len(), 3, "{snap}");
        // 自动、且这条线路没有任何已验证依据 → 页面那句「请先测试线路」才成立。
        assert_eq!(cards[0]["ProfileSource"], "Auto", "{}", cards[0]);
        assert_eq!(cards[0]["AutomaticNeedsCheck"], true, "{}", cards[0]);
        assert_eq!(cards[0]["Profile"], "Udp", "{}", cards[0]);
        // 用户固定了兼容连接 → 卡片不能再说「自动选择」，也不用再提示去测线路。
        assert_eq!(cards[1]["ProfileSource"], "UserChoice", "{}", cards[1]);
        assert_eq!(cards[1]["AutomaticNeedsCheck"], false, "{}", cards[1]);
        assert_eq!(cards[1]["Profile"], "Tcp", "{}", cards[1]);
        // 自动、但已经验证过 → 依据在手，不必再让用户先去测。
        assert_eq!(cards[2]["ProfileSource"], "Auto", "{}", cards[2]);
        assert_eq!(cards[2]["AutomaticNeedsCheck"], false, "{}", cards[2]);
        assert_eq!(cards[2]["Profile"], "Tcp", "自动采用已验证的兼容连接：{}", cards[2]);
    }

    // ---- A6 第二轮：线路动作反馈 / 待核对 / 重试与核对 ----

    /// `line-action-list` 在生产上是**合并后的状态**，测试也按这个形状喂。
    fn actions_fetch(actions: Value) -> impl Fn(&str) -> Value {
        move |c: &str| {
            if c.contains("line-action-list") {
                merged_status_with(json!({
                    "ok": true,
                    "lineActions": {"ReadError": "", "Actions": actions.clone()}
                }))
            } else {
                fetch(c)
            }
        }
    }

    #[test]
    fn retrying_a_failed_preference_resends_the_requested_transport() {
        let mut ui = WebUi::new();
        let fetch = actions_fetch(json!([{
            "Id": "fa1", "LineId": "jp", "LineName": "东京 02", "Kind": "Preference",
            "ProfileId": "Tcp", "Requested": "tcp", "Phase": "Failed",
            "Message": "上次保存没有落地", "Code": "NotApplied",
            "AtUtc": "2026-11-11T01:00:00Z", "LatencyMs": Value::Null,
        }]));
        let steps = ui.route(
            r#"{"Type":"retryLineAction","Id":"jp","Value":"fa1","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c))
                if c.contains("set-transport") && c.contains("\"tcp\"")
                && c.contains("\"jp\"") && c.contains("\"line-action\"")),
            "重试保存必须重新提交记录里的原方式：{steps:?}"
        );
        assert!(ui.toast.is_empty(), "{}", ui.toast);
    }

    #[test]
    fn retrying_a_failed_check_runs_a_real_measurement_as_a_long_command() {
        let mut ui = WebUi::new();
        let fetch = actions_fetch(json!([{
            "Id": "fa2", "LineId": "jp", "LineName": "东京 02", "Kind": "Check",
            "ProfileId": "Udp", "Requested": "", "Phase": "Failed",
            "Message": "连接后测量", "Code": "environment",
            "AtUtc": "2026-11-11T01:00:00Z", "LatencyMs": Value::Null,
        }]));
        let steps = ui.route(
            r#"{"Type":"retryLineAction","Id":"jp","Value":"fa2","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Long(c))
                if c.contains("measure-latency") && c.contains("\"jp\"")),
            "重试测速必须发真测量，且走长命令：{steps:?}"
        );
        let op = ui.operation.as_ref().expect("操作条要显示正在重新测速");
        assert_eq!(op["Kind"], "Test");
        assert_eq!(op["LineId"], "jp");
        assert_eq!(op["Message"], "正在重新测速");
    }

    #[test]
    fn retrying_a_vanished_line_action_says_so_instead_of_running_a_guess() {
        let mut ui = WebUi::new();
        let fetch = actions_fetch(json!([]));
        let steps = ui.route(
            r#"{"Type":"retryLineAction","Id":"jp","Value":"gone","Sequence":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "记录不在就不许猜一条命令：{steps:?}");
        assert!(ui.toast.contains("找不到"), "{}", ui.toast);
    }

    #[test]
    fn reviewing_a_pending_operation_routes_by_which_store_owns_the_id() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        // 线路卡片上的「检查结果」直接用反馈条目的 id，不走存储查询。
        let steps = ui.route(
            r#"{"Type":"reviewLineAction","Id":"jp","Value":"fa1","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c))
                if c.contains("line-action-review") && c.contains("\"fa1\"")),
            "核对要用反馈条目的 id：{steps:?}"
        );

        // 首页待处理项：通用操作记录里有这个 id → operation-review。
        let with_operation = |c: &str| {
            if c.contains("operation-list") {
                merged_status_with(json!({
                    "ok": true,
                    "operations": {"ReadError": "", "Records": [
                        {"Id": "op9", "Kind": "Connect", "Phase": "NeedsReview"}
                    ]}
                }))
            } else {
                fetch(c)
            }
        };
        let steps = ui.route(
            r#"{"Type":"reviewOperation","Id":"op9","Sequence":2}"#,
            &with_operation,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c))
                if c.contains("operation-review") && c.contains("\"op9\"")),
            "通用记录的核对必须发 operation-review：{steps:?}"
        );

        // 通用记录里没有、线路动作里有 → 回退到原来的核对（旧快照/旧页面）。
        let with_line_action = |c: &str| {
            if c.contains("line-action-list") {
                merged_status_with(json!({
                    "ok": true,
                    "lineActions": {"ReadError": "", "Actions": [{"Id": "fa1"}]}
                }))
            } else {
                fetch(c)
            }
        };
        let steps = ui.route(
            r#"{"Type":"reviewOperation","Id":"fa1","Sequence":3}"#,
            &with_line_action,
        );
        assert!(
            matches!(steps.first(), Some(Step::Sync(c))
                if c.contains("line-action-review") && c.contains("\"fa1\"")),
            "线路动作的待处理项必须仍能核对：{steps:?}"
        );

        // 两处都没有：不发一条必然被拒的命令，如实说「已经不在了」。
        let steps = ui.route(
            r#"{"Type":"reviewOperation","Id":"gone","Sequence":4}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "{steps:?}");
        assert!(ui.toast.contains("已经不在了"), "{}", ui.toast);

        // 空 id 同样不发命令；线路动作入口的老行为不变。
        let steps = ui.route(
            r#"{"Type":"reviewLineAction","Id":"jp","Value":"","Sequence":5}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "空 id 不发一条必然被拒的命令：{steps:?}");
        assert!(!ui.toast.is_empty());
    }

    // ---- A5/A6：界面长操作（连接/断开/诊断）的记录、待核对与核对 ----

    #[test]
    fn snapshot_projects_interrupted_connections_before_line_actions() {
        let records = json!([
            {"Id": "op-connect", "Kind": "Connect", "Phase": "NeedsReview",
             "Message": "上次「连接」没拿到结果", "Code": "Interrupted",
             "StartedAtUtc": "2026-11-11T04:00:00Z", "StartedAtUnix": 1,
             "FinishedAtUtc": "", "Origin": "ui"},
            {"Id": "op-done", "Kind": "Disconnect", "Phase": "Succeeded",
             "Message": "断开完成", "Code": "",
             "StartedAtUtc": "2026-11-11T03:00:00Z", "StartedAtUnix": 1,
             "FinishedAtUtc": "2026-11-11T03:00:10Z", "Origin": "tray"},
        ]);
        let fetch = |c: &str| {
            if c.contains("operation-list") {
                merged_status_with(json!({
                    "ok": true,
                    "operations": {"ReadError": "", "Records": records.clone()}
                }))
            } else if c.contains("line-action-list") {
                merged_status_with(json!({
                    "ok": true,
                    "lineActions": {"ReadError": "", "Actions": [{
                        "Id": "fa1", "LineId": "hk", "LineName": "香港 01", "Kind": "Preference",
                        "ProfileId": "Tcp", "Requested": "tcp", "Phase": "NeedsReview",
                        "Message": "中断", "Code": "Interrupted",
                        "AtUtc": "2026-11-11T02:00:00Z", "LatencyMs": Value::Null
                    }]}
                }))
            } else {
                fetch(c)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let pending = snap["State"]["PendingOperations"].as_array().expect("待处理数组");
        assert_eq!(pending.len(), 2, "只收 NeedsReview：{}", snap["State"]["PendingOperations"]);
        assert_eq!(pending[0]["Id"], "op-connect", "连接/断开必须排在前面：{pending:?}");
        assert_eq!(pending[0]["Kind"], "Connection", "前端按它优先展示：{pending:?}");
        assert_eq!(pending[0]["Label"], "连接");
        assert_eq!(pending[0]["Target"], "");
        assert!(
            pending[0]["Message"].as_str().unwrap_or("").contains("请先核对"),
            "{}",
            pending[0]
        );
        assert_eq!(pending[1]["Id"], "fa1", "线路动作仍然要投影：{pending:?}");
        assert_eq!(snap["State"]["OperationsReadError"], "");
    }

    #[test]
    fn a_broken_operation_store_surfaces_its_read_error_in_the_snapshot() {
        let mut ui = WebUi::new();
        let bad = |c: &str| {
            if c.contains("operation-list") {
                merged_status_with(json!({
                    "ok": false,
                    "error": "操作记录不是合法 JSON",
                    "errorCode": "operation-record",
                    "operations": {"ReadError": "操作记录不是合法 JSON", "Records": []}
                }))
            } else {
                fetch(c)
            }
        };
        let snap = ui.snapshot(&bad);
        assert_eq!(snap["State"]["OperationsReadError"], "操作记录不是合法 JSON");
        assert!(
            snap["State"]["PendingOperations"].as_array().unwrap().is_empty(),
            "读不出来时列表必须为空，但不能装作「没有记录」：{}",
            snap["State"]["PendingOperations"]
        );
    }

    /// 存储回包 → 合并白名单 → 快照读取，整条缝都要通。
    #[test]
    fn the_operation_record_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "operations": {"ReadError": "", "Records": [{
                "Id": "op-merge", "Kind": "Disconnect", "Phase": "NeedsReview",
                "Message": "中断", "Code": "Interrupted",
                "StartedAtUtc": "2026-11-11T04:00:00Z", "StartedAtUnix": 1,
                "FinishedAtUtc": "", "Origin": "ui"
            }]}
        }));
        let mut ui = WebUi::new();
        let fetch = |c: &str| {
            if c.contains("operation-list") { merged.clone() } else { fetch(c) }
        };
        let snap = ui.snapshot(&fetch);
        let pending = snap["State"]["PendingOperations"].as_array().unwrap();
        assert_eq!(
            pending.len(), 1,
            "白名单漏了 operations，待核对入口整块消失：{}",
            snap["State"]["PendingOperations"]
        );
        assert_eq!(pending[0]["Id"], "op-merge");
    }

    /// 核对回包 → 合并白名单 → `absorb_reply` 的 Toast，整条缝都要通。
    #[test]
    fn the_operation_review_survives_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "message": "上次连接没有生效：现在没有连接，也没有残留的代理改动。可以重新连接。",
            "operationReview": {
                "Id": "op1", "Kind": "Connect", "Phase": "Failed",
                "Message": "上次连接没有生效：现在没有连接，也没有残留的代理改动。可以重新连接。",
                "Code": "ReviewedNotApplied", "NeedsReview": false, "Origin": "ui"
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"operation-review"}"#, &merged);
        assert!(
            ui.toast.contains("可以重新连接"),
            "白名单漏了 operationReview，核对完成后页面一句话都没有：{}",
            ui.toast
        );
    }

    /// 记录读不出来时，点「查看并处理」不能发一条必然被拒的命令。
    #[test]
    fn reviewing_an_unreadable_operation_store_says_why_instead_of_guessing() {
        let mut ui = WebUi::new();
        let bad = |c: &str| {
            if c.contains("operation-list") {
                merged_status_with(json!({
                    "ok": false,
                    "error": "操作记录不是合法 JSON",
                    "errorCode": "operation-record",
                    "operations": {"ReadError": "操作记录不是合法 JSON", "Records": []}
                }))
            } else {
                fetch(c)
            }
        };
        let steps = ui.route(
            r#"{"Type":"reviewOperation","Id":"op1","Sequence":1}"#,
            &bad,
        );
        assert!(steps.is_empty(), "{steps:?}");
        assert!(ui.toast.contains("读不出来"), "{}", ui.toast);
    }

    #[test]
    fn snapshot_projects_line_action_feedback_and_pending_operations() {
        let actions = json!([
            {"Id": "a1", "LineId": "jp", "LineName": "东京 02", "Kind": "Check",
             "ProfileId": "Udp", "Requested": "", "Phase": "Failed",
             "Message": "连接后测量", "Code": "environment",
             "AtUtc": "2026-11-11T01:00:00Z", "LatencyMs": Value::Null},
            {"Id": "a2", "LineId": "hk", "LineName": "香港 01", "Kind": "Preference",
             "ProfileId": "Tcp", "Requested": "tcp", "Phase": "NeedsReview",
             "Message": "上次操作还没拿到结果，请先核对。", "Code": "Interrupted",
             "AtUtc": "2026-11-11T02:00:00Z", "LatencyMs": Value::Null},
            {"Id": "a3", "LineId": "jp", "LineName": "东京 02", "Kind": "Check",
             "ProfileId": "Udp", "Requested": "", "Phase": "Pending",
             "Message": "", "Code": "",
             "AtUtc": "2026-11-11T03:00:00Z", "LatencyMs": Value::Null},
        ]);
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&actions_fetch(actions));
        let cards = snap["State"]["Lines"].as_array().expect("线路卡片");
        let hk = cards.iter().find(|c| c["Id"] == "hk").expect("hk 卡片");
        let jp = cards.iter().find(|c| c["Id"] == "jp").expect("jp 卡片");

        // hk：被中断的保存 → 需要核对；核对不是重试，所以没有「重试」。
        let hk_feedback = hk["Feedback"].as_array().expect("Feedback 数组");
        assert_eq!(hk_feedback.len(), 1, "{}", hk["Feedback"]);
        assert_eq!(hk_feedback[0]["Status"], "NeedsReview");
        assert_eq!(hk_feedback[0]["NeedsReview"], true);
        assert_eq!(hk_feedback[0]["ReviewLabel"], "确认保存结果");
        assert_eq!(hk_feedback[0]["CanRetry"], false);

        // jp：失败的测速 → 可重试、可诊断；Pending 的那条还不算结果，不能显示成失败。
        let jp_feedback = jp["Feedback"].as_array().expect("Feedback 数组");
        assert_eq!(jp_feedback.len(), 1, "Pending 不许投影成结果：{}", jp["Feedback"]);
        assert_eq!(jp_feedback[0]["Status"], "Failed");
        assert_eq!(jp_feedback[0]["CanRetry"], true);
        assert_eq!(jp_feedback[0]["CanDiagnose"], true);
        assert_eq!(jp_feedback[0]["ReviewLabel"], "检查测试结果");

        let pending = snap["State"]["PendingOperations"].as_array().expect("待处理数组");
        assert_eq!(
            pending.len(), 1,
            "只收 NeedsReview；失败但结论明确的走卡片上的重试：{}",
            snap["State"]["PendingOperations"]
        );
        assert_eq!(pending[0]["Id"], "a2");
        assert_eq!(pending[0]["Kind"], "LineAction");
        assert_eq!(pending[0]["Target"], "hk");
        assert_eq!(pending[0]["Label"], "香港 01 · 兼容连接保存");
        assert!(
            pending[0]["Message"].as_str().unwrap_or("").contains("尚未确认"),
            "{}",
            pending[0]
        );
        assert_eq!(snap["State"]["LineActionsReadError"], "");
    }

    #[test]
    fn a_broken_line_action_store_surfaces_its_read_error_in_the_snapshot() {
        let mut ui = WebUi::new();
        let bad = |c: &str| {
            if c.contains("line-action-list") {
                merged_status_with(json!({
                    "ok": false,
                    "error": "线路操作记录读不出来",
                    "errorCode": "line-action",
                    "lineActions": {"ReadError": "线路操作记录读不出来", "Actions": []}
                }))
            } else {
                fetch(c)
            }
        };
        let snap = ui.snapshot(&bad);
        assert_eq!(snap["State"]["LineActionsReadError"], "线路操作记录读不出来");
        assert!(
            snap["State"]["PendingOperations"].as_array().unwrap().is_empty(),
            "读不出来不能伪装成「没有待核对」"
        );
    }

    /// 第七次同类缺陷的守门：`lineActions` 漏出白名单时，卡片永远没有反馈、
    /// 待核对项永远不出现，而所有直接造假 fetch 的用例仍然全绿。
    #[test]
    fn the_line_actions_survive_the_host_side_merge() {
        let merged = merged_status_with(json!({
            "ok": true,
            "lineActions": {"ReadError": "", "Actions": [
                {"Id": "a1", "LineId": "jp", "LineName": "东京 02", "Kind": "Check",
                 "ProfileId": "Udp", "Requested": "", "Phase": "Failed",
                 "Message": "连接后测量", "Code": "environment",
                 "AtUtc": "2026-11-11T01:00:00Z", "LatencyMs": Value::Null}
            ]}
        }));
        let fetch = move |c: &str| {
            if c.contains("line-action-list") { merged.clone() } else { fetch(c) }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let cards = snap["State"]["Lines"].as_array().expect("线路卡片");
        let jp = cards.iter().find(|c| c["Id"] == "jp").expect("jp 卡片");
        assert_eq!(
            jp["Feedback"][0]["Id"], "a1",
            "白名单漏了 lineActions，卡片永远收不到测速/保存的反馈"
        );
    }

    #[test]
    fn the_line_action_review_reply_survives_the_host_side_merge() {
        let message = "上次保存没有落地：这条线路现在仍是自动选择。可以重试保存。";
        let merged = merged_status_with(json!({
            "ok": true,
            "message": message,
            "lineActionReview": {
                "Id": "a2", "LineId": "hk", "Kind": "Preference", "Phase": "Failed",
                "Message": message, "Code": "NotApplied", "NeedsReview": false,
                "CanRetry": true, "LatencyMs": Value::Null
            }
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"line-action-review","id":"a2"}"#, &merged);
        assert!(
            ui.toast.contains("没有落地"),
            "白名单漏了 lineActionReview，核对完成后页面一句话都没有：{}",
            ui.toast
        );

        // 命令层拒绝（记录不在了 / 不需要核对）也必须回话。
        let refused = merged_status_with(json!({
            "ok": false, "error": "这条线路操作记录已经不在了",
            "errorCode": "missing", "message": "这条线路操作记录已经不在了"
        }));
        let mut ui = WebUi::new();
        ui.absorb_reply(r#"{"cmd":"line-action-review","id":"gone"}"#, &refused);
        assert!(ui.toast.contains("已经不在了"), "{}", ui.toast);
    }

    /// 卸载预览/执行与设备改名失败：这三条都走长命令收尾，页面靠这三个键区分
    /// 「这条命令失败了」与「整页读不出来」。白名单漏一个，页面就永远等不到回包。
    #[test]
    fn the_server_uninstall_and_device_rename_replies_survive_the_host_side_merge() {
        let mut state = json!({"Page": "main", "State": {}});
        merge_ui_command_reply(
            &mut state,
            &json!({
                "ok": true,
                "serverUninstallPreview": {"Id": "s1", "AffectedDevices": 2},
                "serverUninstall": {"Id": "s1", "TransportRemoved": true},
                "serverDeviceRename": {"error": "公钥无效"}
            }),
        );
        assert!(
            state["serverUninstallPreview"].is_object(),
            "白名单漏了 serverUninstallPreview，卸载预览永远画不出来"
        );
        assert!(
            state["serverUninstall"].is_object(),
            "白名单漏了 serverUninstall，卸载完成后页面停在「正在处理…」"
        );
        assert!(
            state["serverDeviceRename"].is_object(),
            "白名单漏了 serverDeviceRename，设备改名失败会被当成整页读不出来"
        );
    }

    #[test]
    fn finish_op_clears_busy_and_surfaces_failure() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"connect","Sequence":1}"#, &fetch);
        assert!(ui.busy);
        ui.finish_op(&json!({"ok": false, "message": "端口被占用"}));
        assert!(!ui.busy);
        assert!(ui.operation.is_none());
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Busy"], false);
        assert_eq!(snap["State"]["Toast"], "端口被占用");
    }

    /// 被拒的那条命令在发出时已经把操作条顶掉了：拒绝回包要还原成真的在跑的那条。
    ///
    /// 不还原的话，界面会挂着「正在诊断」的牌子而实际在测速；等测速结束时
    /// 又因为命令名对不上而无从解释。
    #[test]
    fn a_refused_command_restores_the_operation_bar_it_displaced() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"testLine","Id":"fixture-a","Sequence":1}"#, &fetch);
        assert!(ui.busy);
        assert_eq!(ui.operation.as_ref().unwrap()["Cmd"], "measure-latency");

        // 第二条长命令：页面照旧把操作条顶了上去（这是既有行为，本批不改）。
        ui.route(r#"{"Type":"diagnostics","Sequence":2}"#, &fetch);
        assert_eq!(ui.operation.as_ref().unwrap()["Cmd"], "diagnose");

        ui.finish_op(&json!({
            "ok": false,
            "errorCode": "busy",
            "error": "正在测速，等它结束再试。",
            "operationOnly": true,
            "op": {"cmd": "diagnose", "phase": "refused", "startedAtUtc": "2026-11-12T12:00:00Z", "budgetSec": 0.0}
        }));

        assert!(ui.busy, "测速还在跑");
        assert_eq!(
            ui.operation.as_ref().unwrap()["Cmd"],
            "measure-latency",
            "操作条必须还原成真的在跑的那条"
        );
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Toast"], "正在测速，等它结束再试。");
    }

    /// 每个长命令都必须有中文名——被闸门挡下时那句话要说得清「在等谁」。
    ///
    /// 扫源码而不是抄一份清单：清单会过期，`is_long_command` 才是唯一事实。
    /// 漏一条不会崩，只会让用户看到「正在操作，等它结束再试」——猜不出该等谁。
    #[test]
    fn every_long_command_has_a_human_label() {
        let source = include_str!("ipc.rs");
        let start = source.find("pub fn is_long_command").expect("找不到长命令清单");
        let body = &source[start..];
        let end = body.find("\n}").expect("清单没有结尾");
        let mut checked = 0;
        for piece in body[..end].split("Some(\"").skip(1) {
            let Some(close) = piece.find('"') else { continue };
            let cmd = &piece[..close];
            assert!(
                cmd.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "扫到了不像命令名的东西：{cmd}"
            );
            assert_ne!(
                command_label(cmd),
                "操作",
                "{cmd} 没有中文名：被闸门挡下时只能说「正在操作，等它结束再试」"
            );
            checked += 1;
        }
        assert!(checked >= 30, "只扫到 {checked} 条长命令，规则可能改过了");
    }

    /// 被闸门挡下的那条回包只是一个提示：**不许**清掉正在跑的那条的等待态。
    ///
    /// 少了这个相位判断，「导入被拒」会让页面以为「连接结束了」，
    /// 等待条消失、按钮解禁，用户接着点就是第二次并发。
    #[test]
    fn a_refused_command_keeps_the_running_operation_untouched() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"connect","Sequence":1}"#, &fetch);
        assert!(ui.busy);
        let before = ui.operation.clone();
        assert!(before.is_some(), "连接已经开始，操作条必须在");

        ui.finish_op(&json!({
            "ok": false,
            "errorCode": "busy",
            "error": "正在连接，等它结束再试。",
            "detail": "正在连接，等它结束再试。",
            "operationOnly": true,
            "op": {"cmd": "import", "phase": "refused", "startedAtUtc": "2026-11-12T12:00:00Z", "budgetSec": 0.0}
        }));

        assert!(ui.busy, "被拒的是别人，当前操作还在跑");
        assert_eq!(ui.operation, before, "当前操作条一个字段都不许动");
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Toast"], "正在连接，等它结束再试。");
        assert_eq!(snap["State"]["Busy"], true);
    }

    #[test]
    fn disconnect_asks_once_before_it_runs() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"disconnect","Sequence":1}"#, &fetch);
        assert!(steps.is_empty(), "先弹确认，不能点一下就断行情");
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Dialog"]["Scope"], "disconnect");
        assert_eq!(snap["State"]["Dialog"]["Confirm"], "断开连接");
        assert_eq!(snap["State"]["Dialog"]["Danger"], true);

        let steps = ui.route(r#"{"Type":"cancelDialog","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "取消不执行任何命令");
        assert!(ui.dialog.is_none());
        assert!(!ui.busy);

        ui.route(r#"{"Type":"disconnect","Sequence":3}"#, &fetch);
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":4}"#, &fetch);
        assert!(matches!(&steps[0], Step::Long(c) if c.contains("\"disconnect\"")));
        assert!(ui.busy);
    }

    // ---- D：入站消息门控（r56） ----

    #[test]
    fn a_replayed_sequence_is_dropped() {
        let mut ui = WebUi::new();
        let first = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":7}"#, &fetch);
        assert!(!first.is_empty(), "第一次必须执行：{first:?}");
        let again = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":7}"#, &fetch);
        assert!(again.is_empty(), "同一条消息重放不许再执行一次：{again:?}");
    }

    #[test]
    fn an_out_of_order_sequence_never_rewinds_the_watermark() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"theme","Value":"dark","Sequence":9}"#, &fetch);
        assert_eq!(ui.inbound_seq, 9);
        ui.route(r#"{"Type":"theme","Value":"light","Sequence":4}"#, &fetch);
        assert_eq!(ui.inbound_seq, 9, "倒退的序号不许把水位线拉回去");
    }

    #[test]
    fn a_message_without_sequence_still_works() {
        let mut ui = WebUi::new();
        let steps = ui.route(r#"{"Type":"connect","Id":"hk"}"#, &fetch);
        assert!(!steps.is_empty(), "不带 Sequence 的内部调用必须放行：{steps:?}");
    }

    #[test]
    fn a_non_integer_sequence_is_dropped() {
        for bad in ["\"3\"", "0", "-1", "3.5", "null"] {
            let mut ui = WebUi::new();
            let raw = format!(r#"{{"Type":"connect","Id":"hk","Sequence":{bad}}}"#);
            assert!(
                ui.route(&raw, &fetch).is_empty(),
                "Sequence={bad} 必须拒绝（只认 1..=2147483647 的整数）"
            );
        }
    }

    #[test]
    fn an_oversized_message_is_dropped() {
        let mut ui = WebUi::new();
        let big = format!(
            r#"{{"Type":"connect","Id":"hk","Value":"{}"}}"#,
            "x".repeat(5000)
        );
        assert!(
            ui.route(&big, &fetch).is_empty(),
            "超过 4 KiB 的非 form 消息必须拒绝"
        );
        assert_eq!(ui.inbound_seq, 0, "被拒绝的消息不许推进水位线");
    }

    #[test]
    fn a_stale_dialog_id_never_closes_the_current_dialog() {
        let mut ui = WebUi::new();
        ui.dialog = Some(json!({"Id": "current", "Scope": "delete", "Target": "hk"}));
        let steps = ui.route(r#"{"Type":"cancelDialog","Id":"stale"}"#, &fetch);
        assert!(steps.is_empty());
        assert!(ui.dialog.is_some(), "过期对话框的事件不许把当前框关掉");
        ui.route(r#"{"Type":"cancelDialog","Id":"current"}"#, &fetch);
        assert!(ui.dialog.is_none(), "对得上的 Id 才关框");
    }

    #[test]
    fn a_stale_form_generation_is_dropped_for_field_edits() {
        let mut ui = WebUi::new();
        ui.form = Some(FormState::history());
        ui.form.as_mut().unwrap().generation = 5;
        let stale = r#"{"Type":"form","Id":"filter-all","Event":"change","Generation":4}"#;
        assert!(
            ui.route(stale, &fetch).is_empty(),
            "旧一代表单的**字段编辑**不许落到新表单上"
        );
        // 按钮点击不挡（见 `reject_inbound` 的注释：推送有 2 秒节流，
        // 连点第二下必然带上一代）。这里只要求不 panic、表单还在。
        let click = r#"{"Type":"form","Id":"filter-all","Event":"click","Generation":4}"#;
        let _ = ui.route(click, &fetch);
        assert!(ui.form.is_some(), "点击不该把表单判成非法消息");
    }

    #[test]
    fn ready_resets_the_sequence_so_a_reloaded_page_recovers() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"theme","Value":"dark","Sequence":50}"#, &fetch);
        assert_eq!(ui.inbound_seq, 50);
        // 页面重载：sequence 从 1 重新开始，`ready` 必须把水位线归零。
        ui.route(r#"{"Type":"ready","Sequence":1}"#, &fetch);
        assert_eq!(ui.inbound_seq, 1, "ready 之后必须重新接受小序号");
        let steps = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":2}"#, &fetch);
        assert!(!steps.is_empty(), "重载后的消息不许被历史序号挡掉：{steps:?}");
    }

    #[test]
    fn a_dropped_message_still_advances_the_ack() {
        let mut ui = WebUi::new();
        ui.route(r#"{"Type":"theme","Value":"dark","Sequence":10}"#, &fetch);
        let before = ui.ack;
        // 重放被丢弃，但 ack 必须追上：前端按 `State.Ack >= Sequence` 解除等待。
        ui.route(r#"{"Type":"theme","Value":"dark","Sequence":10}"#, &fetch);
        assert!(ui.ack > before, "丢弃也必须推进 ack");
        assert!(ui.ack >= 10, "ack 要追上被丢弃的那条序号");
    }

    // ---- A5：连接等待态（r55） ----

    /// 造一个预检回包：`running` 是「名单内正在运行的程序」。
    ///
    /// 形状走生产路径（`merge_ui_command_reply` 合并后的状态包）：命令回包形状的
    /// 假 fetch 会让「白名单漏 `RunningPrograms`」这类问题在测试里静默通过。
    fn wait_fetch(running: &[&str]) -> impl Fn(&str) -> Value {
        let list: Vec<Value> = running.iter().map(|name| json!(name)).collect();
        let reply = merged_status_with(precheck_reply(json!(list)));
        move |cmd: &str| {
            if cmd.contains("\"guard-precheck\"") {
                reply.clone()
            } else {
                fetch(cmd)
            }
        }
    }

    #[test]
    fn choosing_exit_the_app_starts_waiting_instead_of_doing_nothing() {
        let mut ui = WebUi::new();
        let waiting = wait_fetch(&["Trader.exe"]);
        // 点连接：先弹框，一条命令都不发。
        let steps = ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
        assert!(steps.is_empty(), "还没确认，不许发命令：{steps:?}");
        assert_eq!(
            ui.dialog.as_ref().map(|d| d["Scope"].clone()),
            Some(json!("guard-running"))
        );

        // 「先退出程序」= cancelDialog：进等待态，仍然一条命令都不发。
        let steps = ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);
        assert!(steps.is_empty(), "等待态本身不执行任何命令：{steps:?}");
        assert!(ui.dialog.is_none());
        let pending = ui.pending_connect.as_ref().expect("必须进入等待态");
        assert_eq!(pending.line_id, "jp");
        assert_eq!(pending.line_name, "东京 02", "等待条要显示用户点的那条线路名");

        let snap = ui.snapshot(&waiting);
        assert_eq!(snap["State"]["PendingConnectionName"], "东京 02");
        assert_eq!(snap["State"]["Pending"]["Name"], "东京 02");
        assert!(
            snap["State"]["Pending"]["DeadlineUtc"]
                .as_str()
                .unwrap_or("")
                .len()
                > 10,
            "DeadlineUtc 必须是可解析的时刻，前端只按它算倒计时：{}",
            snap["State"]["Pending"]
        );
    }

    #[test]
    fn the_wait_connects_once_when_the_programs_are_gone() {
        let mut ui = WebUi::new();
        let waiting = wait_fetch(&["Trader.exe"]);
        ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
        ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);

        // 程序还在跑：一步都不发。
        assert!(ui.poll_pending_connect(&waiting).is_empty());
        assert!(ui.pending_connect.is_some(), "程序没退出就得继续等");

        // 程序退出了：先 `use` 回等待时记下的那条线路，再 `connect`。
        let gone = wait_fetch(&[]);
        let steps = ui.poll_pending_connect(&gone);
        assert_eq!(steps.len(), 2, "{steps:?}");
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("\"use\"") && c.contains("\"jp\"")),
            "必须连回等待时那条线路，不是「当前线路」：{steps:?}"
        );
        assert!(matches!(&steps[1], Step::Long(c) if c.contains("\"connect\"")));
        assert!(ui.busy, "自动连接与手动连接走同一条预算通道");
        assert!(ui.pending_connect.is_none(), "等待态必须消费掉，不能连第二次");

        // 再轮询一次：什么都不发。
        assert!(ui.poll_pending_connect(&gone).is_empty());
    }

    #[test]
    fn cancelling_the_wait_stops_the_automatic_connection() {
        let mut ui = WebUi::new();
        let waiting = wait_fetch(&["Trader.exe"]);
        ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
        ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);

        let steps = ui.route(r#"{"Type":"cancelWaiting"}"#, &waiting);
        assert!(steps.is_empty(), "取消等待不发命令：{steps:?}");
        assert!(ui.pending_connect.is_none());
        assert_eq!(ui.toast, "已取消等待");

        // 程序退出后也不许自己连。
        assert!(ui.poll_pending_connect(&wait_fetch(&[])).is_empty());
        assert_eq!(ui.snapshot(&waiting)["State"]["PendingConnectionName"], "");
    }

    #[test]
    fn any_other_action_drops_the_wait() {
        for action in [
            r#"{"Type":"navigate","Page":"settings"}"#,
            r#"{"Type":"disconnect"}"#,
            r#"{"Type":"connect","Id":"hk"}"#,
        ] {
            let mut ui = WebUi::new();
            let waiting = wait_fetch(&["Trader.exe"]);
            ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
            ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);
            assert!(ui.pending_connect.is_some());

            ui.route(action, &waiting);
            assert!(
                ui.pending_connect.is_none(),
                "「{action}」之后不许还留着等待态"
            );
            assert!(
                ui.poll_pending_connect(&wait_fetch(&[])).is_empty(),
                "「{action}」之后不许再自己连"
            );
        }
    }

    #[test]
    fn a_missing_running_programs_field_never_autoconnects() {
        let mut ui = WebUi::new();
        let waiting = wait_fetch(&["Trader.exe"]);
        ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
        ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);

        // 预检读不出来（没有这个字段）：不许把「不知道」当成「都退出了」。
        let broken = |c: &str| {
            if c.contains("\"guard-precheck\"") {
                json!({"ok": false, "error": "读不到配置"})
            } else {
                fetch(c)
            }
        };
        assert!(ui.poll_pending_connect(&broken).is_empty());
        assert!(ui.pending_connect.is_some(), "读不出来只能继续等，不能连");
    }

    #[test]
    fn a_running_command_holds_the_wait() {
        let mut ui = WebUi::new();
        let waiting = wait_fetch(&["Trader.exe"]);
        ui.route(r#"{"Type":"connect","Id":"jp"}"#, &waiting);
        ui.route(r#"{"Type":"cancelDialog"}"#, &waiting);

        ui.busy = true;
        assert!(
            ui.poll_pending_connect(&wait_fetch(&[])).is_empty(),
            "有长命令在跑时不许抢事务门"
        );
        assert!(ui.pending_connect.is_some());
    }

    #[test]
    fn the_wait_expires_and_says_so() {
        let mut ui = WebUi::new();
        ui.pending_connect = Some(PendingConnect {
            line_id: "jp".into(),
            line_name: "东京 02".into(),
            created_at: std::time::Instant::now()
                - PENDING_CONNECT_BUDGET
                - std::time::Duration::from_secs(1),
        });
        let gone = wait_fetch(&[]);
        assert!(ui.poll_pending_connect(&gone).is_empty());
        assert!(ui.pending_connect.is_none());
        assert_eq!(ui.toast, "等待已结束，请重新选择线路");
    }

    #[test]
    fn connect_prechecks_running_trade_programs_before_touching_the_channel() {
        let mut ui = WebUi::new();
        // fetch 桩走生产形状（status + 白名单合并）：命令回包形状的假 fetch 会让
        // 「白名单漏 `RunningPrograms`」这种 P0 静默通过。
        let fetch = |c: &str| {
            if c.contains("\"guard-precheck\"") {
                merged_status_with(precheck_reply(json!(["Trader.exe"])))
            } else {
                fetch(c)
            }
        };
        // 预检发现交易程序在跑：连接命令必须还没发出。
        let steps = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":1}"#, &fetch);
        assert!(steps.is_empty(), "先确认，不许直接接管：{steps:?}");
        let dialog = ui.dialog.clone().unwrap_or(Value::Null);
        assert_eq!(dialog["Scope"], "guard-running");
        assert!(dialog["Body"].as_str().unwrap_or("").contains("Trader.exe"));
        assert!(dialog["Note"].as_str().unwrap_or("").contains("已建立的连接不会被切断"));

        // 用户坚持继续：才发 use + connect。
        let steps = ui.route(r#"{"Type":"confirmDialog","Sequence":2}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("\"use\"") && c.contains("\"hk\"")));
        assert!(matches!(&steps[1], Step::Long(c) if c.contains("\"connect\"")));
        assert!(ui.busy);
    }

    /// r54 的 P0 **接线**测试：`guard-precheck` 的**原始命令回包**必须能活着穿过宿主侧合并。
    ///
    /// 形状就是真机那条路：`{"ok":true,"RunningPrograms":[…]}` → `merge_ui_command_reply`
    /// （`UI_REPLY_KEYS` 白名单）→ `absorb_precheck_running` 读得到。
    ///
    /// 白名单漏 `RunningPrograms` 时，读者永远拿到空数组，于是**连接侧与启用侧的确认框
    /// 在真机上一次都不会出现**，而两侧的路由用例全绿（它们直接构造了命令回包形状的
    /// fetch）。这条用例在删掉那个键时必须是红的——它守的就是「命令回包 → 合并 → 读」这条缝。
    #[test]
    fn the_precheck_reply_survives_the_host_side_merge() {
        // 1) 最小状态 + 原始回包：宿主侧真正做的就这一件事。
        let mut state = json!({"ok": true, "State": {}});
        merge_ui_command_reply(&mut state, &json!({"ok": true, "RunningPrograms": ["ping.exe"]}));
        assert_eq!(
            absorb_precheck_running(&state),
            vec!["ping.exe".to_string()],
            "`RunningPrograms` 必须能穿过 `merge_ui_command_reply`（`UI_REPLY_KEYS`）：\
             漏了它，P0-13 的两个确认框在真机上永不出现"
        );

        // 2) 生产形状再来一遍（status 载荷 + 完整 precheck 回包）：多个程序名按序保留。
        let full = merged_status_with(precheck_reply(json!(["Trader.exe", "下单助手.exe"])));
        assert_eq!(
            absorb_precheck_running(&full),
            vec!["Trader.exe".to_string(), "下单助手.exe".to_string()]
        );

        // 3) 反方向：没人跑就是空数组，不许把「没读到」说成「有人在跑」。
        let idle = merged_status_with(precheck_reply(json!([])));
        assert!(absorb_precheck_running(&idle).is_empty());

        // 4) 命令失败时回包里根本没有这个键，读出来只能是空——不能凭空造出程序名。
        let mut bare = fetch(r#"{"cmd":"status"}"#);
        merge_ui_command_reply(&mut bare, &json!({"ok": false, "error": "找不到配置文件"}));
        assert!(absorb_precheck_running(&bare).is_empty());
    }

    /// 出口网卡的接缝：回包必须能穿过 `merge_ui_command_reply`，否则页面永远停在
    /// 「正在读取本机网卡…」——命令 1 毫秒就跑完了，`finish_op` 却拿不到这份回包。
    #[test]
    fn the_line_network_reply_survives_the_host_side_merge() {
        let mut state = json!({"ok": true, "State": {}});
        merge_ui_command_reply(
            &mut state,
            &json!({"ok": true, "lineNetwork": {
                "Id": "hk", "Default": "以太网", "Interfaces": ["以太网", "WLAN"],
                "Bound": "", "Effective": "以太网", "Stale": false, "StaleName": ""
            }}),
        );
        let net = state.get("lineNetwork").expect(
            "`lineNetwork` 必须登记进 `UI_REPLY_KEYS`：漏了它，出口网卡那一页永远转圈",
        );
        assert_eq!(net["Interfaces"].as_array().map(|a| a.len()), Some(2));

        // 失败形状：宿主只搬 ok/error/message，没有 `lineNetwork` 时表单该保留原选择。
        let mut failed = json!({"ok": true, "State": {}});
        merge_ui_command_reply(
            &mut failed,
            &json!({"ok": false, "errorCode": "usage", "error": "这台电脑上没有网卡「X」"}),
        );
        assert!(failed.get("lineNetwork").is_none(), "失败回包不许造一个空的 lineNetwork");
        assert_eq!(failed["errorCode"], "usage");
    }

    /// 「删除本机部署资料」（r90）的接缝：预览与执行两条回包都必须能穿过
    /// `merge_ui_command_reply`，并且预览要真的变成一张确认框。
    ///
    /// 这是同一类缺陷的第十次（前九次见 `UI_REPLY_KEYS` 的注释）。漏键的症状是
    /// 「点了『删除本机部署资料…』什么都没发生」：不弹框、不报错、不超时——
    /// 因为 `absorb_server_cleanup_preview` 拿到的是没有 `serverCleanup` 的合并态。
    /// 页面级用例直接喂回包结构，绕过了白名单，所以必须在真实合并上再验一次。
    #[test]
    fn the_server_cleanup_replies_survive_the_host_side_merge() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        // 打开服务器一览，再把列表喂进去（页面按钮的 id 由列表决定）。
        ui.route(r#"{"Type":"servers"}"#, &fetch);
        ui.absorb_reply(
            r#"{"cmd":"servers"}"#,
            &json!({"ok":true,"servers":[{
                "Id":"a1","Name":"东京","Host":"203.0.113.10","Port":22,
                "User":"root","LineIds":[]
            }]}),
        );
        let steps = ui.route(
            r#"{"Type":"form","Event":"click","Id":"server-cleanup:a1","Generation":1}"#,
            &fetch,
        );
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("server-cleanup-preview")),
            "点按钮应该先发只读预览"
        );

        // 1) 预览回包 → 合并 → 确认框。
        let mut state = json!({"ok": true, "State": {}});
        merge_ui_command_reply(
            &mut state,
            &json!({"ok":true,"serverCleanup":{
                "Id":"a1","Name":"东京","Host":"203.0.113.10","Port":22,"User":"root",
                "Lines":0,"Runs":3,"Archived":1,"Active":0,"Reminders":2,
                "TaskCredentials":1,"SavedCredential":true,"Blocked":"",
                "Items":["服务器记录","部署任务记录 3 条（含已归档 1 条）","结果提醒 2 条",
                         "任务级登录资料 1 份","长期保存的登录资料"]
            }}),
        );
        assert!(
            state.get("serverCleanup").is_some(),
            "`serverCleanup` 必须登记进 `UI_REPLY_KEYS`：漏了它，确认框永远不出现"
        );
        ui.absorb_reply(r#"{"cmd":"server-cleanup-preview","id":"a1"}"#, &state);
        let dialog = ui.dialog.clone().expect("预览回包必须变成确认框");
        assert_eq!(dialog["Scope"], "server-cleanup", "{dialog}");
        assert_eq!(dialog["Target"], "a1", "{dialog}");

        // 2) 确认 → 宿主把意图发出去。
        let steps = ui.route(
            r#"{"Type":"confirmDialog","Id":"server-cleanup-confirm","Sequence":3}"#,
            &fetch,
        );
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("\"server-cleanup\"") && c.contains("\"a1\"")),
            "确认后要发 server-cleanup：{steps:?}"
        );
        assert!(ui.dialog.is_none(), "确认之后框要收起来");

        // 3) 执行回包 → 合并 → 页面。
        let mut done = json!({"ok": true, "State": {}});
        merge_ui_command_reply(
            &mut done,
            &json!({"ok":true,"servers":[],"serverCleanupResult":{
                "RemovedRuns":3,"RemovedReminders":2,"RemovedCredentials":1,"Failed":[],
                "Message":"已删除这台服务器在本机的 3 条部署记录、2 条提醒与 1 份登录资料"
            }}),
        );
        assert!(
            done.get("serverCleanupResult").is_some(),
            "`serverCleanupResult` 必须登记进 `UI_REPLY_KEYS`"
        );
        ui.absorb_reply(r#"{"cmd":"server-cleanup","id":"a1"}"#, &done);
        let form = ui.form.as_ref().expect("表单还在");
        assert!(
            form.notice.contains("已删除这台服务器在本机的 3 条部署记录"),
            "结论要落在页面上：{}",
            form.notice
        );
        assert!(form.items.is_empty(), "列表要跟着刷新成空的");
    }

    #[test]
    fn quality_history_shows_loading_then_the_curve_and_clears_on_close() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps =
            ui.route(r#"{"Type":"qualityHistory","Id":"hk","Value":"ThirtyMinutes"}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c)
            if c.contains("quality-history") && c.contains("ThirtyMinutes")));
        assert_eq!(ui.snapshot(&fetch)["State"]["QualityHistory"]["Loading"], true);

        ui.absorb_reply(r#"{"cmd":"quality-history"}"#, &json!({"ok":true,"qualityHistory":{
            "NodeId":"hk","Window":"ThirtyMinutes","Loading":false,"Reason":"",
            "Series":[{"Aggregate":{"Statistics":{"MeasuredCount":2,"AverageLatencyMs":150}}}]}}));
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["QualityHistory"]["Series"][0]["Aggregate"]["Statistics"]
                       ["MeasuredCount"], 2);

        ui.route(r#"{"Type":"qualityHistory","Id":"hk","Value":"Close"}"#, &fetch);
        assert!(ui.snapshot(&fetch)["State"]["QualityHistory"].is_null(), "关抽屉要丢掉旧曲线");
    }

    #[test]
    fn domains_opens_the_split_form_and_reads_the_list() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"domains","Sequence":1}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("\"split\"")));
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["ViewKey"], "split");
        assert_eq!(snap["State"]["Form"]["ParentPage"], "apps");
    }

    #[test]
    fn maintenance_opens_with_the_proxy_status_and_restores_in_place() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"maintenance","Sequence":1}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("maintenance-status")));
        assert_eq!(ui.snapshot(&fetch)["State"]["Form"]["ViewKey"], "maintenance");

        ui.absorb_reply(
            r#"{"cmd":"maintenance-status"}"#,
            &json!({"ok":true,"maintenance":{"journal_present":true,"proxy_owned":false,
                                              "can_restore":true,"endpoint":"127.0.0.1:9545"}}),
        );
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["PageActions"][0]["Disabled"], false);

        ui.finish_op(&json!({"ok":true,"message":"已按凭据还原系统代理。",
            "maintenance":{"journal_present":false,"proxy_owned":false,"can_restore":false}}));
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["ViewKey"], "maintenance", "还原后不关页面");
        assert!(snap["State"]["Form"].to_string().contains("已按凭据还原系统代理"));
    }

    #[test]
    fn history_and_diagnostics_open_forms_and_run_their_commands() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);

        let steps = ui.route(r#"{"Type":"history","Sequence":1}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("\"history\"")));
        assert_eq!(ui.snapshot(&fetch)["State"]["Form"]["ViewKey"], "history");

        let steps = ui.route(r#"{"Type":"diagnostics","Sequence":2}"#, &fetch);
        assert!(matches!(&steps[0], Step::Long(c) if c.contains("diagnose")));
        assert!(ui.busy, "诊断是长命令，页面要进入等待态");
        assert_eq!(ui.snapshot(&fetch)["State"]["Form"]["ViewKey"], "diagnose");

        ui.finish_op(&json!({"ok":true,"diagnose":{
            "items":[{"text":"TCP 1.2.3.4:443  可建立连接，耗时 5 ms"}],
            "verdict":{"code":"ok","text":"线路端点可达","next":""}}}));
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["PageActions"][0]["Text"], "重新诊断");
        assert!(snap["State"]["Form"].to_string().contains("线路端点可达"));
    }

    #[test]
    fn rename_opens_a_form_and_the_snapshot_carries_it() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"rename","Id":"jp","Sequence":1}"#, &fetch);
        assert!(steps.is_empty(), "打开表单不发命令");
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["ViewKey"], "line-rename");
        assert_eq!(snap["State"]["Form"]["Generation"], 1);
        assert_eq!(snap["State"]["Form"]["Nodes"][1]["Kind"], "card");
        assert!(snap["State"]["Form"]["Nodes"][1]["Children"][1]["Value"]
            .as_str()
            .map(|v| v == "东京 02")
            .unwrap_or(false));

        // 表单事件走同一条通道，产出的是既有命令而不是新业务。
        let steps = ui.route(
            r#"{"Type":"form","Event":"change","Id":"name","Value":"东京 03"}"#,
            &fetch,
        );
        assert!(steps.is_empty());
        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"save-rename"}"#, &fetch);
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("rename-line") && c.contains("东京 03")));

        // 回包 ok 后表单关闭、Toast 是宿主那句话；页面据此回到线路页。
        ui.absorb_reply(&steps[0].command(), &json!({"ok":true,"message":"线路名称已保存"}));
        let snap = ui.snapshot(&fetch);
        assert!(snap["State"]["Form"].is_null());
        assert_eq!(snap["State"]["Toast"], "线路名称已保存");
    }

    #[test]
    fn back_closes_the_form_without_running_anything() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"lineSettings","Id":"hk","Sequence":1}"#, &fetch);
        let snap = ui.snapshot(&fetch);
        assert_eq!(snap["State"]["Form"]["ViewKey"], "line-settings");
        assert_eq!(
            snap["State"]["Form"]["Nodes"][0]["Children"][1]["Text"],
            "服务器端点：1.2.3.4:443"
        );

        let steps = ui.route(r#"{"Type":"form","Event":"click","Id":"back"}"#, &fetch);
        assert!(steps.is_empty(), "返回不发命令");
        assert!(ui.snapshot(&fetch)["State"]["Form"].is_null());
    }

    #[test]
    fn unknown_line_does_not_open_an_empty_form() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(r#"{"Type":"rename","Id":"nope","Sequence":1}"#, &fetch);
        assert!(ui.form.is_none());
        assert!(ui.toast.contains("刷新"));
    }

    #[test]
    fn assets_are_served_by_path_for_csp() {
        let (mime, body) = asset("/app.js").expect("app.js");
        assert!(mime.starts_with("text/javascript"));
        assert!(body.starts_with(b"'use strict'"));
        assert!(asset("/tokens.css").is_some());
        let (boot_mime, boot) = asset("/theme-boot.js").expect("theme-boot.js");
        assert!(boot_mime.starts_with("text/javascript"));
        assert!(String::from_utf8_lossy(boot).contains("data-theme"), "引导脚本要真的设主题");
        assert!(asset("/nope.js").is_none());
    }

    #[test]
    fn pairing_moves_through_verify_without_consuming_the_invite() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);

        // 1) 开新会话：切到添加页，且快照里没有 Pair（页面据此显示输入框）。
        let steps = ui.route(
            r#"{"Type":"pairOnline","Phase":"BeginCode","Sequence":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "开新会话不该发出任何命令");
        assert_eq!(ui.page, "add-line", "必须切到添加线路页");
        assert!(ui.pair.is_none());
        assert_eq!(ui.snapshot(&fetch)["State"]["Pair"], Value::Null);

        // 2) 校验：进入 Creating 并发一条只读的 pair-verify 长命令。
        let steps = ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"管理电脑","Sequence":2}"#,
            &fetch,
        );
        let session = ui.pair.as_ref().expect("应当开一个会话");
        assert_eq!(session.phase, "Creating");
        assert_eq!(session.device_name, "管理电脑");
        assert!(!session.pair_id.is_empty(), "会话必须有 id，页面用它区分新旧");
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains("pair-verify") && c.contains("TCI1.abc")),
            "{steps:?}"
        );
        // 命令里必须带轮次标记：回包靠它认出属于哪一轮，否则两次校验的回包会串台。
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains(&session.pair_id)),
            "pair-verify 必须带上这一轮的 PairId：{steps:?}"
        );
        assert!(
            !steps.iter().any(|s| matches!(s, Step::Long(c) if c.contains("pair-join"))),
            "校验阶段绝不能提交申请"
        );

        // 3) 失败回包：转 Failed，给出人话与下一步。
        let reply = verify_reply(
            &ui,
            json!({
                "Code": "OnlineInviteExpired",
                "Message": "邀请码已过期，请重新取得邀请。",
                "Status": "", "NodeId": "", "NodeName": "", "Host": "",
                "ExpiresAtUtc": "", "DeviceName": "管理电脑"
            }),
        );
        ui.finish_op(&reply);
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Failed");
        assert_eq!(session.error_code, "OnlineInviteExpired");
        assert_eq!(session.next_action, "Reenter", "过期只能换一张邀请码");
        assert!(session.error_message.contains("过期"));

        // 4) 成功回包：转 Verified，带上服务器名、入口与有效期。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.def","Name":"管理电脑","Sequence":3}"#,
            &fetch,
        );
        let reply = verify_reply(
            &ui,
            json!({
                "Code": "", "Message": "", "Status": "InvitationReady",
                "NodeId": "node-1", "NodeName": "香港 01",
                "Host": "203.0.113.10", "ExpiresAtUtc": "2027-01-01T00:00:00.000000Z",
                "DeviceName": "管理电脑"
            }),
        );
        ui.finish_op(&reply);
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Verified");
        assert_eq!(session.node_name, "香港 01");
        assert_eq!(session.host, "203.0.113.10");
        assert_eq!(session.expires_at, "2027-01-01T00:00:00.000000Z");
        assert!(session.error_code.is_empty());

        // 5) 加入：真的发一条 pair-join，把码与设备名一起带上；阶段转「正在加入」。
        let steps = ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":4}"#,
            &fetch,
        );
        let Step::Long(join) = steps.first().expect("加入必须真的发命令") else {
            panic!("加入要走长命令通道：{steps:?}");
        };
        assert!(join.contains("pair-join"), "{join}");
        assert!(join.contains("TCI1.def"), "邀请码要由宿主补上（页面不再重发它）：{join}");
        assert!(join.contains("管理电脑"), "设备名取自校验那一步：{join}");
        assert!(join.contains("香港 01"), "线路名取用户改过的那个：{join}");
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Preparing");
        assert!(session.stage_label.contains("生成线路"), "{}", session.stage_label);
        let round = session.pair_id.clone();

        // 6) 成功回包：转 Complete（页面据此显示「线路已加入」结果卡），并留下线路名。
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "pairJoin": {
                "Code": "", "Message": "",
                "PairId": round,
                "LineId": "99996e2f01", "LineName": "香港 01",
                "Compatible": true, "State": "Completed",
            }
        }));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Complete");
        assert!(session.error_code.is_empty());
        assert_eq!(session.local_name, "香港 01");
        assert!(session.next_action.is_empty(), "成功之后不该再给动作");

        // 7) 取消：清掉会话并回到线路页。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Cancel","Id":"x","Sequence":5}"#,
            &fetch,
        );
        assert!(ui.pair.is_none());
        assert_eq!(ui.page, "lines");
    }

    #[test]
    fn a_failed_join_says_what_to_do_next() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"管理电脑","Sequence":1}"#,
            &fetch,
        );
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "n", "NodeName": "香港 01", "Host": "203.0.113.10",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":2}"#,
            &fetch,
        );
        let round = ui.pair.as_ref().unwrap().pair_id.clone();
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "pairJoin": {
                "Code": "LineWriteFailed",
                "Message": "写入线路文件失败（C:\\data\\lines\\x.json）：拒绝访问。",
                "PairId": round,
                "LineId": "", "LineName": "", "Compatible": false, "State": "",
            }
        }));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Failed");
        assert_eq!(session.error_code, "LineWriteFailed");
        // 本机写文件失败重来一次是对的动作；留空会被页面兜底成「重试」，
        // 但那条兜底不该是唯一保证——这里要的是宿主自己说清楚。
        assert_eq!(session.next_action, "Retry");
        assert!(session.error_message.contains("写入线路文件失败"));
    }

    #[test]
    fn joining_without_a_verified_code_never_sends_a_command() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        // 直接点加入（没走过校验）：不发命令，如实说清要先校验。
        let steps = ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":1}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "没有校验过的邀请码不能直接提交申请：{steps:?}");
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Failed");
        assert_eq!(session.next_action, "Reenter");
        assert!(session.error_message.contains("校验"));
    }

    #[test]
    fn a_late_join_reply_never_revives_a_cancelled_session() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"管理电脑","Sequence":1}"#,
            &fetch,
        );
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "n", "NodeName": "香港 01", "Host": "203.0.113.10",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":2}"#,
            &fetch,
        );
        let pair_id = ui.pair.as_ref().unwrap().pair_id.clone();
        // 用户等不及，点了取消。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Cancel","Id":"x","Sequence":3}"#,
            &fetch,
        );
        assert!(ui.pair.is_none());
        // 迟到的成功回包不能把已取消的会话又变成「线路已加入」。
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "pairJoin": {"Code": "", "Message": "", "PairId": pair_id,
                         "LineId": "x", "LineName": "香港 01", "Compatible": false,
                         "State": "Completed"}
        }));
        assert!(ui.pair.is_none(), "取消之后不该再出现会话");
    }

    #[test]
    fn a_join_reply_from_another_round_is_ignored() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"管理电脑","Sequence":1}"#,
            &fetch,
        );
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "n", "NodeName": "香港 01", "Host": "203.0.113.10",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":2}"#,
            &fetch,
        );
        // 上一轮（别的会话）的回包：PairId 对不上，必须整个丢掉。
        ui.finish_op(&serde_json::json!({
            "ok": true,
            "pairJoin": {"Code": "", "Message": "", "PairId": "another-round",
                         "LineId": "x", "LineName": "别人的线路", "Compatible": false,
                         "State": "Completed"}
        }));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Preparing", "别的轮次的回包不能推进这一轮");
        assert_ne!(session.local_name, "别人的线路");
    }

    /// 离线授权 JWE 约 4 KB，不能被 4 KiB 的非表单闸门吞掉。
    #[test]
    fn an_offline_authorization_over_four_kib_is_not_dropped_by_the_length_gate() {
        let mut ui = WebUi::new();
        ui.pair = Some(PairSession {
            pair_id: "round".into(),
            phase: "OfflineRequested".into(),
            enrollment_id: "e1".into(),
            ..Default::default()
        });
        let grant = "a".repeat(5_000);
        let message = json!({
            "Type": "pairOnline", "Phase": "OfflineComplete",
            "Code": grant, "Name": "离线线路", "Sequence": 1
        })
        .to_string();
        let steps = ui.route(&message, &|_| json!({}));
        assert!(
            matches!(steps.first(), Some(Step::Long(command)) if command.contains("pair-offline-complete")),
            "授权超过 4 KiB 时消息被闸门吞掉了：{steps:?}"
        );
        // 其余小消息仍保持 4 KiB：同样的 5 KB 不能借 `connect` 钻进来。
        let mut ui = WebUi::new();
        let huge = "a".repeat(5_000);
        let message = json!({"Type": "connect", "Id": huge, "Sequence": 1}).to_string();
        assert!(ui.route(&message, &|_| json!({})).is_empty());
    }

    /// A5：停止等待只让界面恢复，业务仍在后台跑完。
    #[test]
    fn stopping_the_wait_leaves_the_operation_running_in_the_background() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"connect","Id":"hk","Sequence":1}"#, &fetch);
        assert!(
            matches!(steps.last(), Some(Step::Long(command)) if command.contains("connect")),
            "{steps:?}"
        );
        assert!(ui.busy);
        // 心跳不是结束：一秒一条 running，不能把操作条清掉。
        ui.finish_op(&json!({"operationOnly": true, "op": {"cmd": "connect", "phase": "running"}}));
        assert!(ui.busy, "心跳不该清等待态");
        assert!(ui.operation.is_some());

        let steps = ui.route(r#"{"Type":"cancelOperation","Sequence":2}"#, &fetch);
        assert!(steps.is_empty(), "停止等待不该发任何命令：{steps:?}");
        assert!(!ui.busy, "停止等待后界面要立刻恢复可操作");
        let operation = ui.operation.as_ref().expect("后台操作仍要显示");
        assert_eq!(operation["Detached"], true);
        assert_eq!(operation["CanCancel"], false);
        assert!(ui.toast.contains("后台完成"), "{}", ui.toast);

        // 终态到达：没有新操作，正常收口。
        ui.finish_op(&json!({"ok": true, "op": {"cmd": "connect", "phase": "finished"}}));
        assert!(ui.operation.is_none());
        assert!(ui.detached.is_empty());
    }

    #[test]
    fn a_detached_finish_does_not_clear_a_newer_operation() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.begin_op("Connect", "hk", "正在连接", "connect");
        ui.route(r#"{"Type":"cancelOperation","Sequence":1}"#, &fetch);
        assert!(!ui.busy);
        // 用户不等着了，改为断开：连接仍在后台跑。
        ui.begin_op("Disconnect", "", "正在断开", "disconnect");
        ui.finish_op(&json!({"ok": true, "op": {"cmd": "connect", "phase": "finished"}}));
        assert!(ui.busy, "后台连接结束不能清掉正在进行的断开");
        assert_eq!(ui.operation.as_ref().unwrap()["Kind"], "Disconnect");
        assert!(ui.toast.contains("后台连接已完成"), "{}", ui.toast);
        ui.finish_op(&json!({"ok": true, "op": {"cmd": "disconnect", "phase": "finished"}}));
        assert!(!ui.busy);
        assert!(ui.operation.is_none());
    }

    /// A8：自动选路证据要显示在线路卡上，且「自动选择连接方式」真的发探测命令。
    #[test]
    fn auto_route_evidence_is_projected_and_the_probe_runs_as_a_long_command() {
        let base = |c: &str| fetch(c);
        let fetch = move |c: &str| {
            if c.contains("auto-route-list") {
                json!({"ok": true, "autoRoutes": {"Lines": {"hk": {
                    "Summary": "自动：标准连接（31 ms）", "Winner": "udp",
                    "Expired": false, "Candidates": []
                }}}})
            } else {
                base(c)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let lines = snap["State"]["Lines"].as_array().unwrap();
        let hk = lines.iter().find(|line| line["Id"] == "hk").unwrap();
        assert_eq!(hk["AutoRoute"]["Summary"], "自动：标准连接（31 ms）", "{hk}");

        let steps = ui.route(
            r#"{"Type":"autoRoute","Id":"hk","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains("auto-route") && c.contains("\"refresh\":true")),
            "{steps:?}"
        );
        assert!(ui.busy);
        ui.finish_op(&json!({
            "ok": true,
            "autoRoute": {
                "LineId": "hk", "Transport": "udp", "Source": "Probe",
                "Note": "已按当前网络探测并选出连接方式",
                "Evidence": {"Summary": "自动：标准连接（31 ms）"}
            }
        }));
        assert!(ui.toast.contains("探测"), "{}", ui.toast);
        assert!(ui.auto_routes.is_none(), "探测后要丢掉 10 秒缓存，卡片立刻显示新结论");
    }

    /// A6：失败记录给「重试」，且路由真的重发同类命令；待核对的记录不给。
    #[test]
    fn a_failed_operation_is_offered_for_retry_and_reissued() {
        let failed = json!({
            "Id": "op-fail", "Kind": "Connect", "Phase": "Failed",
            "Message": "引擎没起来", "Code": "EngineStartFailed",
            "StartedAtUtc": "2026-11-11T04:00:00Z",
            "Retry": {
                "CanRetry": true, "Label": "重试连接",
                "Note": "按当前选中的线路重新连接；不会使用旧记录里的参数。"
            }
        });
        let review = json!({
            "Id": "op-review", "Kind": "Connect", "Phase": "NeedsReview",
            "Message": "中断", "Code": "Interrupted",
            "StartedAtUtc": "2026-11-11T03:00:00Z",
            "Retry": {"CanRetry": false, "Label": "", "Note": "先核对当前连接与系统代理。"}
        });
        let base = |c: &str| fetch(c);
        let fetch = move |c: &str| {
            if c.contains("operation-list") {
                json!({"ok": true, "operations": {"ReadError": "", "Records": [review.clone(), failed.clone()]}})
            } else {
                base(c)
            }
        };
        let mut ui = WebUi::new();
        let snap = ui.snapshot(&fetch);
        let retryable = snap["State"]["RetryableOperations"].as_array().unwrap();
        assert_eq!(retryable.len(), 1, "只有 Failed 的那条能重试：{retryable:?}");
        assert_eq!(retryable[0]["RetryLabel"], "重试连接");

        let steps = ui.route(
            r#"{"Type":"retryOperation","Id":"op-fail","Sequence":1}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains("operation-retry") && c.contains("op-fail")),
            "{steps:?}"
        );
        assert!(ui.busy, "重试要进入操作等待态");
        ui.finish_op(&json!({
            "ok": true,
            "operationRetry": {"Id": "op-fail", "Kind": "Connect",
                               "RecordId": "op-new", "Message": "已重新连接"}
        }));
        assert!(ui.toast.contains("已重新连接"), "{}", ui.toast);
        assert!(!ui.busy);

        // 待核对：不给重试，按记录里的说明如实回答。
        let steps = ui.route(
            r#"{"Type":"retryOperation","Id":"op-review","Sequence":2}"#,
            &fetch,
        );
        assert!(steps.is_empty(), "{steps:?}");
        assert!(ui.toast.contains("核对"), "{}", ui.toast);
    }

    #[test]
    fn guard_operations_do_not_offer_stop_waiting() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.begin_op("GuardEnable", "", "正在重新启用交易保护", "guard-install");
        ui.route(r#"{"Type":"cancelOperation","Sequence":1}"#, &fetch);
        assert!(ui.busy, "不能停止等待的操作必须保持等待态");
        assert!(ui.detached.is_empty());
        assert!(ui.toast.contains("不能停止等待"), "{}", ui.toast);
    }

    /// 离线交接的回包必须能穿过宿主的合并白名单。
    ///
    /// 这是同一类接缝的第九次（前八次见 `UI_REPLY_KEYS` 的注释）。页面测试直接喂
    /// `finish_op({pairOffline:…})` 是绿的；生产上 `route` 之后拿到的是合并态，
    /// 白名单漏一个键，新电脑就永远停在「正在读取邀请」。
    #[test]
    fn the_offline_pair_reply_survives_the_host_side_merge() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"OfflineInspect","Code":"a.b.c","Name":"新电脑","Sequence":1}"#,
            &fetch,
        );
        let pair_id = ui.pair.as_ref().unwrap().pair_id.clone();
        let merged = merged_status_with(json!({
            "ok": true,
            "pairOffline": {
                "Stage": "Inspect", "PairId": pair_id, "Code": "",
                "Fingerprint": "SHA256:KNOWN", "DeviceName": "新电脑",
                "ExpiresAtUtc": "2026-11-12T00:00:00Z", "NodeName": "node-1"
            }
        }));
        ui.finish_op(&merged);
        assert_eq!(
            ui.pair.as_ref().map(|session| session.phase.as_str()),
            Some("OfflineReady"),
            "白名单漏了 pairOffline，离线校验完成后页面不会动"
        );
    }

    /// 连续校验两个邀请码时，A 的回包绝不能落进 B 的会话。
    ///
    /// 不说 PairId 的回包（`pair-verify` 前几版就没有这个字段）也算「不知道是哪一轮」：
    /// 它会把 A 的节点名/Host 贴在 B 上、把 B 标成已校验——比失败更糟，因为看起来成功了。
    #[test]
    fn a_verify_reply_from_another_round_never_lands_on_this_session() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.aaaa","Name":"管理电脑","Sequence":1}"#,
            &fetch,
        );
        // 用户没等结果就换了另一张码重新校验：会话换了一轮。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.bbbb","Name":"管理电脑","Sequence":2}"#,
            &fetch,
        );
        let current = ui.pair.as_ref().unwrap().pair_id.clone();
        assert_eq!(ui.pair.as_ref().unwrap().code, "TCI1.bbbb");

        // A 的回包（上一轮）：节点名是「东京 02」。必须整个丢掉。
        ui.finish_op(&verify_reply_for(
            &ui,
            "round-a",
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "node-a", "NodeName": "东京 02", "Host": "198.51.100.9",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Creating", "别的轮次的回包不能把这一轮推进");
        assert!(session.node_name.is_empty(), "A 的节点名贴到了 B 的会话上：{session:?}");
        assert!(session.host.is_empty());

        // 完全不带 PairId 的回包同样丢掉（「不知道是哪一轮」）。
        ui.finish_op(&verify_reply_for(
            &ui,
            "",
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "node-x", "NodeName": "不该出现", "Host": "203.0.113.99",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Creating");
        assert_ne!(session.node_name, "不该出现");

        // 本轮的才认。
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "node-b", "NodeName": "香港 01", "Host": "203.0.113.10",
                   "ExpiresAtUtc": "t", "DeviceName": "管理电脑"}),
        ));
        let session = ui.pair.as_ref().unwrap();
        assert_eq!(session.phase, "Verified");
        assert_eq!(session.node_name, "香港 01");
        assert_eq!(session.pair_id, current);
    }

    /// 「选择引擎程序」这个入口：页面按钮 → 宿主弹选择器 → 验过才写配置 → 结果上屏。
    ///
    /// 这条链是「新用户用邀请码加入之后连不上」的唯一自救路（诊断里那句
    /// 「点击选择引擎程序」指的就是它），所以三段都要有用例盯着。
    #[test]
    fn the_engine_picker_intent_picks_verifies_and_reports_back() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        let steps = ui.route(r#"{"Type":"pickEngine","Id":""}"#, &fetch);
        let Some(Step::Sync(cmd)) = steps.first() else {
            panic!("选择引擎要发一条同步命令：{steps:?}");
        };
        assert!(cmd.contains("pick-file"), "走既有的文件选择器：{cmd}");
        assert!(cmd.contains("\"engine\""), "必须指明选的是引擎（slot）而不是线路文件：{cmd}");
        assert!(!cmd.contains("pick-exe"), "pick-exe 是分流选进程用的，不是选引擎：{cmd}");

        // 成功：Toast 带版本号（「真的验过」的证据），快照里的引擎路径跟着变。
        ui.absorb_reply(
            cmd,
            &json!({
                "ok": true,
                "message": "已选用引擎：sing-box version 1.14.2",
                "engineSet": {
                    "Binary": "C:/tc/bin/sing-box.exe",
                    "Version": "sing-box version 1.14.2",
                    "Message": "已选用引擎：sing-box version 1.14.2"
                },
            }),
        );
        // 调用方（`ui.rs`）在 absorb_reply 之后还会走一次 toast_from_reply；
        // 它不许用空串把刚设好的这句覆盖掉——那正好是「点了没反应」的成因。
        ui.toast_from_reply(
            &json!({"ok": true, "engineSet": {"Binary": "C:/tc/bin/sing-box.exe",
                                              "Version": "sing-box version 1.14.2",
                                              "Message": "已选用引擎：sing-box version 1.14.2"}}),
            "",
        );
        let snap = ui.snapshot(&fetch);
        assert!(
            snap["State"]["Toast"].as_str().unwrap_or("").contains("1.14.2"),
            "调用方那句空文案不该把引擎提示冲掉：{}",
            snap["State"]["Toast"]
        );
        assert_eq!(snap["State"]["Settings"]["EngineBinary"], "C:/tc/bin/sing-box.exe");
        assert_eq!(snap["State"]["Settings"]["EngineMissing"], false);

        // 失败：把宿主那句话原样上屏，不能静默。
        ui.absorb_reply(
            cmd,
            &json!({
                "ok": false,
                "error": "这个程序不是 sing-box（`version` 没有报出版本号）",
                "engineSet": {
                    "Binary": "", "Version": "",
                    "Message": "这个程序不是 sing-box（`version` 没有报出版本号）"
                },
            }),
        );
        let snap = ui.snapshot(&fetch);
        assert!(
            snap["State"]["Toast"].as_str().unwrap_or("").contains("不是 sing-box"),
            "{}",
            snap["State"]["Toast"]
        );
    }

    #[test]
    fn a_late_verify_reply_never_revives_a_cancelled_session() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"n","Sequence":1}"#,
            &fetch,
        );
        // 用户等不及，点了取消。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Cancel","Id":"x","Sequence":2}"#,
            &fetch,
        );
        assert!(ui.pair.is_none());
        // 迟到的回包不能把已关掉的会话救活。
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "", "Message": "", "Status": "InvitationReady",
                   "NodeId": "n", "NodeName": "n", "Host": "h", "ExpiresAtUtc": "t",
                   "DeviceName": "n"}),
        ));
        assert!(ui.pair.is_none(), "取消之后不该再出现会话");
    }

    /// 一次性邀请码是**凭据**：它可以出现在发给宿主的命令里，但绝不能进快照。
    ///
    /// 快照会进页面状态、进截图、进日志；码一旦投影出去，等于把它写在了屏幕上。
    /// 这条用例对整个快照 JSON 做子串检查——只断言「没有 Code 字段」会漏掉放进别的字段。
    #[test]
    fn the_pair_snapshot_never_carries_the_one_time_code() {
        let mut ui = WebUi::new();
        let fetch = |c: &str| fetch(c);
        const CODE: &str = "TCI1.SECRET-CODE-9f1c2a44";
        let steps = ui.route(
            &format!(
                r#"{{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"{CODE}","Name":"管理电脑","Sequence":1}}"#
            ),
            &fetch,
        );
        // 前提：码真的进了宿主会话（否则下面「快照里没有」是空跑）。
        assert_eq!(ui.pair.as_ref().unwrap().code, CODE);
        assert!(
            matches!(steps.first(), Some(Step::Long(c)) if c.contains(CODE)),
            "校验命令必须带上码：{steps:?}"
        );

        let snap = ui.snapshot(&fetch);
        let pair = &snap["State"]["Pair"];
        assert!(!pair.is_null(), "会话必须投影出来，页面才知道在等什么");
        assert!(pair.get("Code").is_none(), "快照里出现了 Code 字段：{pair}");
        assert!(
            !snap.to_string().contains(CODE),
            "一次性邀请码被投影进了快照：{}",
            snap["State"]
        );

        // 失败态与完成态同样不许带出去。
        ui.finish_op(&verify_reply(
            &ui,
            json!({"Code": "OnlineInviteExpired", "Message": "邀请码已过期。",
                   "Status": "", "NodeId": "", "NodeName": "", "Host": "",
                   "ExpiresAtUtc": "", "DeviceName": "管理电脑"}),
        ));
        assert!(!ui.snapshot(&fetch).to_string().contains(CODE), "失败快照带出了邀请码");
    }

    /// 失败之后的「下一步」必须与错误码的语义一致，不能一律落到兜底。
    ///
    /// `Retry` = 同一步再试一次是对的（网络抖动、端口/文件一时不可用）；
    /// `Reenter` = 这张码/这个名字没救了，得换一张。映射错了用户会点一个永远失败的重试，
    /// 或者被迫重新去要一张本来还能用的邀请码。
    #[test]
    fn pair_failures_always_offer_an_action_matching_the_error() {
        // 长命令超时/网络抖动/本机一时不可用：重来一次。
        // `InviteServerOutdated` 也在这组：码没错，是服务器脚本该升级；对方重开一次
        // 接收服务后，同一步重试就是正确出路（换一张码反而白扔一张好码）。
        for code in [
            "OnlineConnectionFailed",
            "OnlineTimeout",
            "ConnectionBusy",
            "LinePortUnavailable",
            "LineWriteFailed",
            "LineConfigSaveFailed",
            "LineConfigUnavailable",
            "LineGenerationFailed",
            "InviteServerOutdated",
        ] {
            assert_eq!(pair_next_action(code), "Retry", "{code} 应当允许重试");
        }
        // 码本身不行了 / 服务器说的东西没法用：只能换一张。
        for code in [
            "InvalidOnlineCode",
            "InvalidOnlineHost",
            "OnlineInviteExpired",
            "InviteConsumed",
            "OnlineTlsPinMismatch",
            "OnlineInviteIdentityMismatch",
            "InvalidDeviceName",
            "InvalidOnlineResponse",
            "OnlineOperationFailed",
            // 服务器下发的兼容参数/隧道参数不合法：再点一次「加入」只会得到同一句话。
            "InvalidTransport",
            "InvalidClientConfig",
            "InvalidClientResponse",
        ] {
            assert_eq!(pair_next_action(code), "Reenter", "{code} 不该被当成可重试");
        }
        // 未知错误码不许被当成「重试」：那会让页面把用户引向一个必然失败的循环。
        assert_eq!(pair_next_action("SomethingBrandNew"), "Reenter");
        assert!(!pair_next_action("SomethingBrandNew").is_empty(), "动作不许留空");
    }

    // ---- 合并白名单的结构性防回归（r39） ----

    /// `finish_op` 这条路径上会**从合并状态里读**的函数。
    ///
    /// 新增吸收函数必须登记进来——下面第一条断言就是不许新代码绕开这份扫描。
    /// `reply_message`（`uiweb_form.rs`）故意不在册：它只读 `message`/`detail`/`error`
    /// 这三个**失败文案**，不是命令载荷，读不到也只是换一句兜底话，不会让页面卡住。
    const MERGED_STATE_READERS: [&str; 19] = [
        "finish_op",
        "absorb_invite",
        "absorb_pair_verify",
        "absorb_pair_join",
        // 离线交接三步共用一个 `pairOffline` 键（r67）。
        "absorb_pair_offline",
        "absorb_probe",
        "absorb_devices",
        "absorb_revoke",
        // 删除已撤销设备的名称记录（r68）。
        "absorb_device_forget",
        // 卸载/设备改名（r66）：三条都吃合并后的回包。
        "absorb_device_rename",
        "absorb_uninstall_preview",
        "absorb_uninstall",
        "absorb_guard_remove",
        // 「删除这台服务器的本机部署资料」（r90）：预览与执行都吃合并后的回包，
        // 两条都是 `Step::Sync`，所以键必须登记进 `UI_REPLY_KEYS`。
        "absorb_server_cleanup_preview",
        "absorb_server_cleanup",
        // 出口网卡的读/写（r89）：同一段吸收，读合并后的 `lineNetwork`。
        "absorb_line_network",
        "absorb_diagnose",
        "absorb_restore",
        // `guard-precheck` 的读者（r54）：它用 `fetch` 读合并状态，不是 `finish_op` 的
        // 后继。**名字是 `absorb_` 前缀的唯一目的就是被第 1 步的自动发现纳入**——
        // 光在这里登记而不改名是假绿：`collect_keys` 只认形参 `state`/`reply`，
        // 形参名不对就等于空扫。两件事必须同时成立，本条注释就是那条约束的记账。
        "absorb_precheck_running",
    ];

    /// 同步命令路径（`ui.rs` 的 `Step::Sync`）：回包**原样**交给它们，不经白名单合并。
    const SYNC_ONLY_READERS: [&str; 2] = ["absorb_reply", "absorb"];


    /// 失败形状：`merge_ui_command_reply` 在 `ok:false` 时单独合并这四个，不在两份白名单里。
    const FAILURE_KEYS: [&str; 4] = ["ok", "error", "errorCode", "message"];

    /// 从源码里切出一个函数的函数体（从签名后的第一个 `{` 起做括号配平）。
    fn function_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
        let start = source.find(&format!("fn {name}("))?;
        let open = start + source[start..].find('{')?;
        let mut depth = 0usize;
        for (index, letter) in source[open..].char_indices() {
            match letter {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&source[open..=open + index]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// 读开头的字符串字面量，只认 `"ident"` 这种形状。
    fn leading_key(text: &str) -> Option<String> {
        let text = text.trim_start().strip_prefix('"')?;
        let key = &text[..text.find('"')?];
        let plain = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain {
            Some(key.to_string())
        } else {
            None
        }
    }

    /// 扫出函数体里读的键：只认 `state.get("k")` / `reply.get("k")` 与 `state["k"]` 两种写法。
    fn collect_keys(body: &str, into: &mut std::collections::BTreeSet<String>) {
        for handle in ["state", "reply"] {
            let mut from = 0;
            while let Some(offset) = body[from..].find(handle) {
                let start = from + offset;
                from = start + handle.len();
                // 左边必须是标识符边界：`host_state` 之类不是这里说的「合并状态」形参。
                let glued = body[..start]
                    .chars()
                    .next_back()
                    .map(|c| c.is_alphanumeric() || c == '_')
                    .unwrap_or(false);
                if glued {
                    continue;
                }
                let rest = body[from..].trim_start();
                let candidate = rest
                    .strip_prefix(".get(")
                    .map(str::trim_start)
                    .or_else(|| rest.strip_prefix('[').map(str::trim_start));
                if let Some(key) = candidate.and_then(leading_key) {
                    into.insert(key);
                }
            }
        }
    }

    /// 合并白名单必须覆盖 `finish_op` 这条路径读的每一个键。
    ///
    /// 为什么这条测试必须存在：`finish_op` 与它的 absorb_* 都是**从状态里取自己的
    /// 载荷**，而状态是 `main.rs::merge_ui_command_reply` 按白名单拼出来的。漏一个键，
    /// 命令跑完也不报错、不超时，页面永远停在「正在处理」。前三次（`servers`、`invite`、
    /// `pairVerify`/`pairJoin`）都是真机才发现——因为 uiweb 的用例全是在这一层**直接
    /// 构造** `{pairVerify:…}` 调 `finish_op`，从不经过那道合并。
    ///
    /// 只做**单向**包含：读到的键 ∈ 白名单。不做「白名单里的键都必须被 Rust 读到」——
    /// `lines`/`processes`/`servers`/`agents`/`latencyMs` 这些是**给页面**的，Rust 侧
    /// 根本不读，反向断言会一次红一片。多透传无害，少才是缺陷。
    #[test]
    fn ui_reply_whitelist_covers_every_key_finish_op_reads() {
        // 两个文件都要扫：真正读键的 absorb_* 大半在表单层（`uiweb_form.rs`），
        // 只扫 `uiweb.rs` 会整片漏掉 `diagnose` 这类只在表单层读的键。
        let sources = [
            ("src/uiweb.rs", include_str!("uiweb.rs")),
            ("src/uiweb_form.rs", include_str!("uiweb_form.rs")),
        ];

        // 1) 这两个文件里凡是「读合并状态」的函数都必须登记，否则第 2 步会漏扫。
        for (file, source) in sources {
            for line in source.lines() {
                let line = line.trim_start();
                let line = line
                    .strip_prefix("pub(crate) ")
                    .or_else(|| line.strip_prefix("pub "))
                    .unwrap_or(line);
                let Some(rest) = line.strip_prefix("fn ") else {
                    continue;
                };
                let name = rest.split('(').next().unwrap_or("").trim();
                if !(name == "finish_op" || name.starts_with("absorb")) {
                    continue;
                }
                assert!(
                    MERGED_STATE_READERS.contains(&name) || SYNC_ONLY_READERS.contains(&name),
                    "{file} 里的 `fn {name}` 没登记：会读合并状态就加进 MERGED_STATE_READERS，\
                     只读同步回包就加进 SYNC_ONLY_READERS——不登记它会绕开这份扫描"
                );
            }
        }

        // 2) 把「读的那一侧」真正读到的键收集出来（两个文件的并集）。
        let mut read: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for name in MERGED_STATE_READERS {
            let body = sources
                .iter()
                .find_map(|(_, source)| function_body(source, name))
                .unwrap_or_else(|| panic!("源码里找不到 `fn {name}`：改名了就把它在这里一起改掉"));
            collect_keys(body, &mut read);
        }

        // 3) 每个读到的键都必须能从状态里拿到：两条合并路径各自的白名单 + 失败四键。
        //    (`maintenance`/`restoreResult` 来自 `merge_maintenance_reply`，那是**另一条**
        //    路径，所以单列一个常量，不混进 `UI_REPLY_KEYS`。)
        let allowed = |key: &str| {
            super::UI_REPLY_KEYS.contains(&key)
                || super::MAINTENANCE_REPLY_KEYS.contains(&key)
                || FAILURE_KEYS.contains(&key)
        };
        let missing: Vec<&String> = read.iter().filter(|key| !allowed(key.as_str())).collect();
        assert!(
            missing.is_empty(),
            "这些键 `finish_op` 会读，但两条合并白名单里都没有——命令跑完页面也不会动：\
             {missing:?}\n命令载荷加进 `src/uiweb.rs` 的 `UI_REPLY_KEYS`、还原相关的加进 \
             `MAINTENANCE_REPLY_KEYS`，然后重跑。当前读到的全部键：{read:?}"
        );
    }

    // ---- 「谁把回包接过去读」的完整扫描（r39 补） ----

    /// 只保留测试模块之前的生产代码。
    ///
    /// 两件事必须同时成立：测试代码自己也在造 `fetch` 桩（`let fetch = |c| fetch(c)`、
    /// `let base = fetch(cmd)`），混进来只是噪音；而 `uiweb_form.rs` 里
    /// `#[cfg(test)]` 还出现在**行内缩进**位置（给用例开的构造函数），
    /// 所以只认**行首**那个与 `mod tests` 成对出现的标记——按 `#[cfg(test)]`
    /// 字面切会把那个文件从第 615 行腰斩，后面 6000 行全扫不到。
    ///
    /// 按行判断而不是按 `"\n#[cfg(test)]\nmod tests"` 配对：这个仓库的文件行尾
    /// 不统一（`uiweb.rs` 与 `uiweb_form.rs` 是 CRLF），写死 `\n` 会让标记匹配不上，
    /// 而匹配不上的后果是**静默**的——整份测试代码被当生产代码扫，`fetch` 调用数
    /// 一次从 23 涨到 174，这条用例反而更难看出问题。
    fn production_part(source: &str) -> &str {
        let mut offset = 0usize;
        let mut mark_start = 0usize;
        let mut previous: Option<&str> = None;
        for line in source.split_inclusive('\n') {
            let text = line.trim_end_matches(|c| c == '\r' || c == '\n');
            if previous == Some("#[cfg(test)]") && text.trim_start().starts_with("mod tests") {
                // `mark_start` 是上一行（`#[cfg(test)]`）的行首。
                return &source[..mark_start];
            }
            previous = Some(text);
            mark_start = offset;
            offset += line.len();
        }
        source
    }

    /// 一个函数的签名形参与函数体：callee 那一跳要按**实参位置**映射到形参名。
    struct FnSource<'a> {
        name: String,
        params: Vec<String>,
        body: &'a str,
    }

    /// 括号配平：从 `open`（指向 `(`）返回配对的 `)` 的位置。
    fn matching_paren(text: &str, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (index, letter) in text[open..].char_indices() {
            match letter {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + index);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// 按顶层逗号切分实参/形参。
    ///
    /// 括号深度只往下夹到 0：`fn(&str) -> Value` 里的 `>` 不该把深度压成负数，
    /// 否则后面那个逗号就不切了（形参表会整段粘成一个）。
    fn split_top_level(text: &str) -> Vec<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut depth = 0isize;
        let mut start = 0usize;
        for (index, letter) in text.char_indices() {
            match letter {
                '<' | '(' | '[' | '{' => depth += 1,
                '>' | ')' | ']' | '}' => {
                    if depth > 0 {
                        depth -= 1;
                    }
                }
                ',' if depth == 0 => {
                    parts.push(text[start..index].to_string());
                    start = index + letter.len_utf8();
                }
                _ => {}
            }
        }
        parts.push(text[start..].to_string());
        parts
    }

    /// 形参表 → 形参名（`self` 丢掉；`mut x` / `&'a x: T` 只取名）。
    fn signature_params(source: &str, after_name: usize) -> Vec<String> {
        let Some(open) = source[after_name..].find('(').map(|at| after_name + at) else {
            return Vec::new();
        };
        let Some(close) = matching_paren(source, open) else {
            return Vec::new();
        };
        split_top_level(&source[open + 1..close])
            .iter()
            .filter_map(|param| {
                let param = param.trim();
                let head = match param.find(':') {
                    Some(at) => &param[..at],
                    None => param,
                };
                let head = head.trim().trim_start_matches('&').trim();
                let head = head.strip_prefix("mut ").unwrap_or(head).trim();
                if head.is_empty() || head == "self" {
                    return None;
                }
                Some(head.to_string())
            })
            .collect()
    }

    /// 逐个列出「函数名 / 形参名 / 函数体」，函数体用括号配平切（与 [`function_body`]
    /// 同一手法，区别只是按顺序枚举而不是按名字找）。
    fn each_function(source: &str) -> Vec<FnSource<'_>> {
        // `fn ` 前面只允许这些修饰词出现——否则命中的是注释里那句 `fn xxx`。
        const MODIFIERS: [&str; 8] = [
            "", "pub", "pub(crate)", "pub(super)", "async", "const", "unsafe", "extern",
        ];
        let mut found: Vec<FnSource<'_>> = Vec::new();
        let mut from = 0usize;
        while let Some(offset) = source[from..].find("fn ") {
            let start = from + offset;
            from = start + "fn ".len();
            let line_start = source[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
            if !MODIFIERS.contains(&source[line_start..start].trim()) {
                continue;
            }
            let name: String = source[from..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let Some(brace) = source[start..].find('{') else {
                continue;
            };
            let open = start + brace;
            let mut depth = 0usize;
            let mut body: Option<&str> = None;
            for (index, letter) in source[open..].char_indices() {
                match letter {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body = Some(&source[open..=open + index]);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(body) = body {
                let params = signature_params(source, from + name.len());
                found.push(FnSource { name, params, body });
            }
        }
        found
    }

    /// 一处 `fetch(…)` 调用被扫成了什么。
    enum FetchKind {
        /// `let <名> = fetch(…)`：有名字的句柄。
        Binding(String),
        /// `fetch(…)` 紧跟 `.get(…)` / `[…]`：没有名字，但读是**当场**发生的。
        Chain,
        /// 既没起名字、也没当场取键：扫描不知道谁在读它。
        Unmatched,
    }

    /// 一处 `fetch(…)` 调用。
    struct FetchUse {
        /// `fetch` 在函数体里的字节偏移。
        at: usize,
        kind: FetchKind,
        /// 这次调用的原文（报错与形状登记都用它）。
        snippet: String,
    }

    /// `fetch(` 前面的 `let <名> =` 里的名字（`let mut <名> =` 也算）。
    ///
    /// 从 `at` 往回走：空白 → `=` → 标识符 → 空白 → 可选 `mut` → `let`。
    /// `let (a, b) = (fetch(…), …)` 这种解构走到 `=` 前面是 `(`，拿不到名字——
    /// 那正是我们要它**报出来**的形状，不是要放过的形状。
    fn binding_name_before(body: &str, at: usize) -> Option<String> {
        fn skip_back(text: &str, mut at: usize) -> usize {
            while at > 0 && text.as_bytes()[at - 1].is_ascii_whitespace() {
                at -= 1;
            }
            at
        }
        let mut index = skip_back(body, at);
        if index == 0 || body.as_bytes()[index - 1] != b'=' {
            return None;
        }
        index = skip_back(body, index - 1);
        let end = index;
        while index > 0
            && (body.as_bytes()[index - 1].is_ascii_alphanumeric() || body.as_bytes()[index - 1] == b'_')
        {
            index -= 1;
        }
        if index == end {
            return None;
        }
        let name = body[index..end].to_string();
        let mut before = skip_back(body, index);
        if before >= 3 && &body[before - 3..before] == "mut" {
            before = skip_back(body, before - 3);
        }
        if before < 3 || &body[before - 3..before] != "let" {
            return None;
        }
        // `outlet` 之类不能当成 `let`：左边还得是词边界。
        let boundary = body[..before - 3].chars().next_back();
        if boundary.map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false) {
            return None;
        }
        Some(name)
    }

    /// 这次 `fetch(…)` 后面是否**当场**取键（`.get(` / `[`）；是就返回那个槽。
    fn chain_slot(body: &str, at: usize) -> Option<KeySlot> {
        let open = body[at..].find('(').map(|offset| at + offset)?;
        let close = matching_paren(body, open)?;
        let rest = body[close + 1..].trim_start();
        if let Some(after) = rest.strip_prefix(".get(") {
            return Some(key_slot(after));
        }
        if let Some(after) = rest.strip_prefix('[') {
            let inner = after.trim_start();
            let inner = inner.strip_prefix('&').unwrap_or(inner).trim_start();
            if inner.starts_with('"') {
                return Some(key_slot(inner));
            }
            if inner.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false) {
                return Some(KeySlot::Opaque(inner.chars().take(32).collect()));
            }
        }
        None
    }

    /// 把函数体里**每一处** `fetch(` 都分类一遍。
    ///
    /// 这是整条用例的地基：`fetch(` 的出现次数必须等于「被识别的次数」，否则
    /// 就有人把回包接走而扫描看不见。上一版只找 `let <名> = fetch(`，
    /// 于是「顺手抽个取回包的小函数」这种正常重构会让整条防线静默归零：
    ///
    /// ```ignore
    /// fn wrap_fetch(fetch: &dyn Fn(&str) -> Value) -> Value {
    ///     fetch(r#"{"cmd":"probe-wrap"}"#)   // 尾表达式，没有 let → 上一版当没看见
    /// }
    /// ```
    fn fetch_uses(body: &str) -> Vec<FetchUse> {
        let mut uses: Vec<FetchUse> = Vec::new();
        let mut cursor = 0usize;
        while let Some(offset) = body[cursor..].find("fetch(") {
            let at = cursor + offset;
            cursor = at + "fetch(".len();
            // 左边必须是词边界：`wrap_fetch(`、`wait_fetch(` 不是 `fetch(` 调用。
            // 少了这一条，一个名字里带 fetch 的 helper 会被当成两处未识别的调用。
            let glued = body[..at]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            if glued {
                continue;
            }
            let snippet = {
                let open = at + "fetch".len();
                let end = matching_paren(body, open).map(|close| close + 1).unwrap_or(body.len());
                let text = &body[at..end];
                text.chars().take(80).collect::<String>()
            };
            let kind = match binding_name_before(body, at) {
                Some(name) => FetchKind::Binding(name),
                None => {
                    if chain_slot(body, at).is_some() {
                        FetchKind::Chain
                    } else {
                        FetchKind::Unmatched
                    }
                }
            };
            uses.push(FetchUse { at, kind, snippet });
        }
        uses
    }

    /// 取出 `fetch(…)` 这一次调用的实参原文（`at` 指向 `fetch(` 的 `f`）。
    fn call_argument<'a>(body: &'a str, at: usize) -> &'a str {
        let Some(open) = body[at..].find('(').map(|offset| at + offset) else {
            return "";
        };
        match matching_paren(body, open) {
            Some(close) => &body[open..=close],
            None => "",
        }
    }

    /// 读一个**裸字符串字面量**：`"status"` 与 `r#"status"#` 都认，内容不限 ASCII。
    fn quoted_literal(text: &str) -> Option<String> {
        let text = text.trim_start();
        if let Some(rest) = text.strip_prefix("r#\"") {
            return rest.find("\"#").map(|end| rest[..end].to_string());
        }
        let rest = text.strip_prefix('"')?;
        rest.find('"').map(|end| rest[..end].to_string())
    }

    /// 这次 `fetch` 打的是哪条命令——用来判定「是不是 status 基线」。
    ///
    /// **只认 `cmd` 的值，不做整段 `contains`。** 上一版用
    /// `call_argument(..).contains("\"status\"")`，于是「把某个**参数值**写成
    /// `json!("status")`」就能让整个函数免税（QA 实证）。这里两条路都只读命令名：
    /// - `json_cmd("…", …)`：取它的第一个实参；
    /// - `{"cmd":"…"}` / `{"cmd": "…"}`：找 `"cmd"` 这个**键**，冒号后面那个字面量。
    ///
    /// 认不出来（如 `fetch(&cmd)`）就返回 `None`，**不豁免**——`quality_for` 正是这种。
    fn command_of(argument: &str) -> Option<String> {
        if let Some(at) = argument.find("json_cmd(") {
            let rest = &argument[at + "json_cmd(".len()..];
            if let Some(name) = quoted_literal(rest) {
                return Some(name);
            }
        }
        let mut from = 0usize;
        while let Some(offset) = argument[from..].find("\"cmd\"") {
            let start = from + offset;
            from = start + "\"cmd\"".len();
            let Some(rest) = argument[from..].trim_start().strip_prefix(':') else {
                continue;
            };
            if let Some(name) = quoted_literal(rest) {
                return Some(name);
            }
        }
        None
    }

    /// 一次键读取的两种结果。
    enum KeySlot {
        /// 确认的字面量键（`"ident"`）。
        Key(String),
        /// 有实参，但不是能确认的键：非 ASCII 字面量、变量、常量、`format!`……
        Opaque(String),
    }

    /// 把 `.get(` / `[` 后面的原文变成一个 [`KeySlot`]。
    ///
    /// **绝不静默丢弃**：上一版这里 `return None`，于是 `reply.get(kb)`（键在变量里）
    /// 与 `reply.get("中文键")`（非 ASCII 字面量）全部无声溜过去（QA 实证）。
    fn key_slot(text: &str) -> KeySlot {
        let trimmed = text.trim_start();
        if let Some(inner) = trimmed.strip_prefix('"') {
            if let Some(end) = inner.find('"') {
                let key = &inner[..end];
                if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return KeySlot::Key(key.to_string());
                }
                return KeySlot::Opaque(format!("\"{key}\""));
            }
        }
        let snippet: String = trimmed.chars().take(48).collect();
        let snippet = snippet.split(')').next().unwrap_or("").trim().to_string();
        KeySlot::Opaque(snippet)
    }

    /// 一次「扫不动」的读：键不是 ASCII 字面量，扫描无法判定它在不在白名单。
    struct OpaqueRead {
        file: String,
        function: String,
        snippet: String,
    }

    /// 收集一个句柄（`fetch` 回包绑定，或它被转交到的 callee 形参）上读的键。
    ///
    /// 认两种形状：`<handle>.get("KEY")` 与 `<handle>["KEY"]`。
    /// `reply.get("a").and_then(|s| s.get("B"))` 里的 `B` 是**载荷内部**的字段，
    /// 不是从合并状态里取的键，不该算进来——所以只认紧跟句柄的那一次读取。
    fn keys_read_from(
        body: &str,
        name: &str,
        from: usize,
        function: &str,
        file: &str,
        into: &mut std::collections::BTreeSet<String>,
        opaque: &mut Vec<OpaqueRead>,
    ) {
        let mut cursor = from;
        while let Some(offset) = body[cursor..].find(name) {
            let start = cursor + offset;
            cursor = start + name.len();
            // 左边必须是标识符边界：`ctx_reply` 不是这里说的 `reply`。
            let glued = body[..start]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            if glued {
                continue;
            }
            let rest = body[cursor..].trim_start();
            let slot = if let Some(after) = rest.strip_prefix(".get(") {
                Some(key_slot(after))
            } else if let Some(after) = rest.strip_prefix('[') {
                // 下标写法：只把**字符串**当键。`[0]` 这种数字下标、`[..]` 切片
                // 不是「读键」，直接放过；`[key]` 这种键在变量里的，记 opaque。
                let inner = after.trim_start();
                let inner = inner.strip_prefix('&').unwrap_or(inner).trim_start();
                let first = inner.chars().next();
                if inner.starts_with('"') {
                    Some(key_slot(inner))
                } else if first.map(|c| c.is_alphabetic() || c == '_').unwrap_or(false) {
                    Some(KeySlot::Opaque(inner.chars().take(32).collect()))
                } else {
                    None
                }
            } else {
                None
            };
            match slot {
                Some(KeySlot::Key(key)) => {
                    into.insert(key);
                }
                Some(KeySlot::Opaque(snippet)) => opaque.push(OpaqueRead {
                    file: file.to_string(),
                    function: function.to_string(),
                    snippet,
                }),
                None => {}
            }
        }
    }

    /// 实参里是否**提到**了这个句柄（按标识符边界，不用子串——`reply2` 不算提到 `reply`）。
    ///
    /// 转交时的包装五花八门：`&preview`、`preview.clone()`、`&*reply`、
    /// `reply.as_ref()`。上一版只认「实参正好等于句柄名」，于是
    /// `helper(reply.clone())` 里读的键整类逃掉（QA 实证）。
    /// 这里只要求「提到」，至于提到之后怎么用，由 callee 那句 `param.get(...)` 说话。
    fn mentions_identifier(argument: &str, handle: &str) -> bool {
        let mut from = 0usize;
        while let Some(offset) = argument[from..].find(handle) {
            let start = from + offset;
            from = start + handle.len();
            let glued_left = argument[..start]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            let glued_right = argument[from..]
                .chars()
                .next()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            if !glued_left && !glued_right {
                return true;
            }
        }
        false
    }

    /// 函数体里所有调用点的 `(被调名, 实参表)`。
    ///
    /// 只为了做**一跳**：`delete_dialog(&preview, &id)` 把回包整个交出去，
    /// 真正的键读发生在 callee 体内（`preview.get("deletePreview")`）。
    /// 不做这一跳，「转交后在 callee 读」这一整类形状都看不见（QA 实证第 5 条）。
    fn call_sites(body: &str) -> Vec<(String, Vec<String>)> {
        let mut sites: Vec<(String, Vec<String>)> = Vec::new();
        let mut cursor = 0usize;
        while let Some(offset) = body[cursor..].find('(') {
            let open = cursor + offset;
            cursor = open + 1;
            let head: Vec<char> = body[..open]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let name: String = head.into_iter().rev().collect();
            if name.is_empty() {
                continue;
            }
            let Some(close) = matching_paren(body, open) else {
                continue;
            };
            sites.push((name, split_top_level(&body[open + 1..close])));
        }
        sites
    }

    /// 按名字找 callee：同文件优先，找不到再跨文件。
    fn find_callee<'a, 'b>(
        functions: &'b [(usize, FnSource<'a>)],
        name: &str,
        file: usize,
    ) -> Option<&'b FnSource<'a>> {
        functions
            .iter()
            .find(|(index, item)| *index == file && item.name == name)
            .or_else(|| functions.iter().find(|(_, item)| item.name == name))
            .map(|(_, item)| item)
    }

    /// 「扫不动」的读必须登记在这里：`(函数名, snippet 原文, 为什么它不是字面量)`。
    ///
    /// **现在是空的**——生产代码里每一处从回包读键都写成了 ASCII 字面量。
    /// 写不出字面量时（键在变量里、在常量里、`format!` 拼出来、或者干脆是中文），
    /// 扫描就无法确认它在不在白名单，而那正是「后端有数据、界面空白」最喜欢的藏身处：
    /// 一开始遇到这种形状直接 `return None`，于是 `reply.get(kb)` 与
    /// `reply.get("中文键")` 全类静默放过。
    ///
    /// 登记粒度是 `(函数, snippet)` **逐字相等**，不是「这个函数整体免税」：
    /// 按函数名豁免的话，同一个函数里后加的第二条动态键会跟着一起免税（QA 实证）。
    /// 另有一条下限：每个函数的 opaque 条数必须等于登记条数。
    const OPAQUE_READS: [(&str, &str, &str); 0] = [];

    /// 「`fetch(` 的结果被接走、但扫描认不出是谁接的」必须登记在这里：
    /// `(形状说明, 为什么允许)`。**现在是空的**——生产代码里每一处 `fetch(` 都是
    /// `let <名> = fetch(…)`。
    ///
    /// 这条存在的意义：`fetch(` 的**出现次数**必须与「被识别的次数」对上账。
    /// 对不上就说明有人把回包接走而扫描看不见，而那种失守是**静默**的——
    /// 整条防线归零、用例照样绿。抽个 helper 包装一下是最正常不过的重构：
    ///
    /// ```ignore
    /// fn wrap_fetch(fetch: &dyn Fn(&str) -> Value) -> Value {
    ///     fetch(r#"{"cmd":"probe-wrap"}"#)   // 尾表达式，没有名字可跟踪
    /// }
    /// ```
    const FETCH_SHAPES: [(&str, &str); 0] = [];

    /// **每一个**把 `fetch` 回包接过去按键读的函数，读到的键都必须在白名单里。
    ///
    /// 上面那条用例只覆盖 `finish_op` 与 `absorb_*` 两类函数——它是按**函数名**圈范围的，
    /// 于是任何新形状的读者都能绕开。`quality_for` 就是这么绕开的：
    ///
    /// ```ignore
    /// let reply = fetch(&cmd);
    /// let summary = reply.get("qualitySummary").cloned().unwrap_or(Value::Null);
    /// ```
    ///
    /// 它既不是 `finish_op`、也不叫 `absorb_*`，扫描看不见它，`qualitySummary` 掉出白名单
    /// 后**第九次**复发：后端 58 个采样、中位 122 ms，首页「线路响应」恒为「等待采样」。
    ///
    /// 这条用例改成按**形状**圈范围，六类形状都必须命中（QA 复核逐条实证过逃逸）：
    ///
    /// 1. `let n = fetch(…)` 之后 `n.get("k")` / `n["k"]`（下标写法）；
    /// 2. 键不是 ASCII 字面量（`n.get(kb)`、`n.get("中文键")`）→ 记 [`OpaqueRead`]，
    ///    必须登记进 [`OPAQUE_READS`]，**不许静默放过**；
    /// 3. 链式读 `fetch(…) .get("k")`（没有独立绑定）；
    /// 4. 转交一跳 `let n = fetch(…); callee(&n, …)` → 按实参位置映射到 callee 形参，
    ///    再在 callee 体内收 `param.get("k")`；
    /// 5. `{"cmd":"status"}` 只豁免 status 的**键**（那是合并结果的基线），
    ///    判定只认 `cmd` 的值，不整段 contains；
    /// 6. 关键键必须在结果集合里（下面 `REQUIRED_KEYS`）——谁删掉某个读者的读操作，
    ///    这条立刻红，真 bug 不会因为「读的人没了」变绿。
    ///
    /// 两条硬约束（不是风格偏好，撞上就红）：
    ///
    /// 1. `fetch(…)` 的结果**必须先起名**再用：`return fetch(&cmd);`、
    ///    `let x = &fetch(&cmd);`、`callee(fetch(&cmd));` 都会被判「未识别」。
    ///    要写成 `let reply = fetch(&cmd);`，把句柄交出去。
    /// 2. **函数体内的注释与字符串里不要出现 `fetch(`**（`fetch_uses` 是纯文本找
    ///    `fetch(`，不跳过注释/字符串）。写文档解释这条用例时最容易踩。
    ///
    /// 已知边界（挡不住，如实记录，别当成全覆盖）：`self.field = Some(reply)` 跨函数存值、
    /// `reply.as_object().and_then(|m| m.get(..))` 这类中间层、`pointer("/a/b")`、
    /// 同名 callee 歧义、`absorb`/`absorb_reply` 的 `Step::Sync` 通路（回包不合并，
    /// 白名单对它们无意义，只能靠接缝用例）。

    #[test]
    fn every_function_reading_a_fetch_reply_only_uses_whitelisted_keys() {
        let sources = [
            ("src/uiweb.rs", include_str!("uiweb.rs")),
            ("src/uiweb_form.rs", include_str!("uiweb_form.rs")),
        ];
        let problems = scan_fetch_reply_contract(&sources);
        assert!(problems.is_empty(), "fetch reply contract violations:\n{}", problems.join("\n"));
    }

    // These eight fields belong to the independently obtained status
    // baseline, not to the raw lines command's write permissions. See #92 C1.
    const SNAPSHOT_LINES_BASELINE_KEYS: [&str; 8] = [
        "action", "state", "exitAttribution", "exitEvidence",
        "exitObservedIp", "exitProbeAtUtc", "startedAt", "transportActual",
    ];

    // This is a deliberately narrow lexical contract for the one privileged
    // binding, not a replacement for the general fetch scanner. Accept only
    // the existing immutable root declaration, direct reads and the one
    // existing whole-value clone into the offline status selection. Any other
    // mention (including patterns, mutation, qualified names or aliases) is
    // an ambiguity, even if the general scanner deduplicates its keys.
    fn snapshot_lines_binding_identity(body: &str, fetch_at: usize) -> Result<(), &'static str> {
        const NAME: &str = "lines_raw";
        let declaration_at = fetch_at.checked_sub("lines_raw = ".len())
            .ok_or("missing declaration")?;
        // Lex only the forms used by this function: line comments, simple
        // raw/ordinary strings, words and punctuation. Unsupported lexical
        // forms fail closed here instead of trying to parse arbitrary Rust.
        let lexer = regex::Regex::new(
            r###"//[^\n]*|r#".*?"#|"(?:\\[^\r\n]|[^"\\\r\n])*"|\w+|[^\s]"###,
        ).expect("snapshot provenance lexer");
        let tokens: Vec<_> = lexer.find_iter(body)
            .filter(|token| !token.as_str().starts_with("//"))
            .collect();
        let word = |index: usize| tokens.get(index).map(|token| token.as_str());
        // The original scanner is textual. Do not grant provenance to
        // occurrences in strings/comments or substrings that it might see.
        if body.match_indices(NAME).count()
            != tokens.iter().filter(|token| token.as_str() == NAME).count()
        {
            return Err("non-token occurrence of lines_raw");
        }
        let mut delimiters = Vec::new();
        let mut declaration = None;
        let mut clone_count = 0;
        for (index, token) in tokens.iter().enumerate() {
            let text = token.as_str();
            if matches!(text, "\"" | "'" | "#" | "\\")
                || body[token.start()..].starts_with("/*")
                || body[token.start()..].starts_with("*/")
            {
                return Err("unsupported lexical form");
            }
            if text == NAME {
                if token.start() == declaration_at {
                    if delimiters.as_slice() != ["{"]
                        || index == 0 || word(index - 1) != Some("let")
                        || word(index + 1) != Some("=")
                        || word(index + 2) != Some("fetch")
                        || tokens[index + 2].start() != fetch_at
                    {
                        return Err("lines_raw declaration is not immutable function-root binding");
                    }
                    declaration = Some(index);
                } else {
                    let Some(declared) = declaration else {
                        return Err("lines_raw mention before original declaration");
                    };
                    let previous = index.checked_sub(1).and_then(word);
                    if matches!(previous, Some("." | ":" | "#")) {
                        return Err("qualified lines_raw is not the original binding");
                    }
                    let suffix = body[token.end()..].trim_start();
                    if suffix.starts_with(".get(") {
                        // Immutable Value::get, with the original scanner
                        // still checking literal/opaque keys and callee hops.
                    } else if suffix.starts_with(".clone()") {
                        // Only the existing tail clone of the status-selection
                        // then branch may transfer the whole value. Its let/if
                        // must begin immediately after the literal fetch;
                        // no intervening root statement may own the clone.
                        let start = declared + 7;
                        if word(start) != Some("let")
                            || word(start + 1) != Some("st")
                            || word(start + 2) != Some("=")
                            || word(start + 3) != Some("if")
                            || delimiters.as_slice() != ["{", "{"]
                            || previous != Some("{")
                            || !body[token.start()..].starts_with(
                                "lines_raw.clone()\n        } else {\n            st\n        };"
                            )
                            || tokens[start..index].iter().any(|t| t.as_str() == ";")
                        {
                            return Err("unproven lines_raw whole-value clone/alias");
                        }
                        clone_count += 1;
                    } else {
                        return Err("unproven use of lines_raw (shadow, rebind or alias)");
                    }
                }
            }
            match text {
                "{" | "(" | "[" => delimiters.push(text),
                "}" | ")" | "]" => {
                    let expected = match text { "}" => "{", ")" => "(", _ => "[" };
                    if delimiters.pop() != Some(expected) {
                        return Err("ambiguous delimiter scope");
                    }
                }
                _ => {}
            }
        }
        if declaration.is_none() || !delimiters.is_empty() || clone_count != 1 {
            return Err("missing original binding, balanced scope or unique approved clone");
        }
        Ok(())
    }

    // One checker path for real sources and mutation controls; collect all
    // failures including coverage, not an unrelated panic in negative cases.
    fn scan_fetch_reply_contract(sources: &[(&str, &str)]) -> Vec<String> {
        let functions: Vec<(usize, FnSource<'_>)> = sources
            .iter()
            .enumerate()
            .flat_map(|(index, (_, source))| {
                each_function(production_part(source))
                    .into_iter()
                    .map(move |item| (index, item))
            })
            .collect();

        let allowed = |key: &str| {
            super::UI_REPLY_KEYS.contains(&key)
                || super::MAINTENANCE_REPLY_KEYS.contains(&key)
                || FAILURE_KEYS.contains(&key)
        };

        let expected_baseline: std::collections::BTreeSet<String> =
            SNAPSHOT_LINES_BASELINE_KEYS.iter().map(|key| (*key).to_string()).collect();
        let mut baseline_keys = std::collections::BTreeSet::<String>::new();
        let mut baseline_sites = 0usize;
        let mut provenance_problems = Vec::new();
        let unique_snapshot = functions.iter().filter(|(_, item)| item.name == "snapshot").count() == 1;
        let mut fetches = 0usize;
        let mut identified = 0usize;
        let mut bindings = 0usize;
        let mut checked = 0usize;
        let mut statuses = 0usize;
        let mut hops = 0usize;
        let mut chains = 0usize;
        let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut opaque: Vec<OpaqueRead> = Vec::new();
        // 违反：(文件, 函数, 句柄, 键)。句柄写进消息，才看得出键是在哪一层读的。
        let mut violations: Vec<(String, String, String, String)> = Vec::new();
        // 没对上的 `fetch(`：(文件, 函数, 第几处, 调用原文)。
        let mut unmatched: Vec<(String, String, usize, String)> = Vec::new();

        for (file_index, (file, _)) in sources.iter().enumerate() {
            for item in functions.iter().filter(|(index, _)| *index == file_index) {
                let function = &item.1;
                // 1) 对账：`fetch(` 的每一处都要被分类，一处都不许含糊。
                for (position, use_site) in fetch_uses(function.body).into_iter().enumerate() {
                    fetches += 1;
                    // 链式那一半与类型无关：任何一处 `fetch(…)` 后面都可能当场取键。
                    if let Some(slot) = chain_slot(function.body, use_site.at) {
                        chains += 1;
                        match slot {
                            KeySlot::Key(key) => {
                                if !allowed(&key) {
                                    violations.push((
                                        file.to_string(),
                                        function.name.clone(),
                                        "fetch(…)".to_string(),
                                        key.clone(),
                                    ));
                                }
                                keys.insert(key);
                            }
                            KeySlot::Opaque(snippet) => opaque.push(OpaqueRead {
                                file: file.to_string(),
                                function: function.name.clone(),
                                snippet,
                            }),
                        }
                    }
                    let name = match &use_site.kind {
                        FetchKind::Binding(name) => name,
                        FetchKind::Chain => {
                            identified += 1;
                            continue;
                        }
                        FetchKind::Unmatched => {
                            unmatched.push((
                                file.to_string(),
                                function.name.clone(),
                                position + 1,
                                use_site.snippet.clone(),
                            ));
                            continue;
                        }
                    };
                    identified += 1;
                    bindings += 1;
                    // `{"cmd":"status"}` 豁免——**不是**「读状态的函数可以放水」，
                    // 而是这份回包根本不走白名单：宿主每次先
                    // `let mut state = status_state(&ctx)` 再 `merge_ui_command_reply`，
                    // 所以 status 的**每一个键**都是合并结果的基线，`state`/`Guard*`/
                    // `exitDailyMembers` 这些从来不需要出现在 `UI_REPLY_KEYS` 里。
                    // 判定只认 `cmd` 的**值**（见 `command_of`），不看函数名、
                    // 也不整段 contains——否则一个 `json!("status")` 参数就能免税。
                    if command_of(call_argument(function.body, use_site.at)).as_deref()
                        == Some("status")
                    {
                        statuses += 1;
                        continue;
                    }
                    checked += 1;
                    // One recognized, direct literal lines fetch in the actual
                    // WebUi::snapshot definition. Neither the permissive
                    // command parser nor the binding name alone grants provenance.
                    let signature = "    pub fn snapshot(&mut self, fetch: &dyn Fn(&str) -> Value) -> Value {";
                    let source = production_part(sources[file_index].1);
                    let snapshot_site = *file == "src/uiweb.rs"
                        && function.name == "snapshot"
                        && unique_snapshot
                        && source.match_indices(signature).count() == 1
                        && source.find(signature).is_some_and(|start| {
                            source[..start].rfind("\nimpl ").is_some_and(|owner| {
                                source[owner..].starts_with("\nimpl WebUi {")
                            }) && source[start + signature.len() - 1..].as_ptr() == function.body.as_ptr()
                        })
                        && name == "lines_raw"
                        && function.body[..use_site.at].ends_with(concat!(
                            r##"let st = fetch(r#"{"cmd":"status"}"#);"##,
                            "\n        let lines_raw = "
                        ))
                        && call_argument(function.body, use_site.at) == r##"(r#"{"cmd":"lines"}"#)"##
                        && function.body[use_site.at..].starts_with(r##"fetch(r#"{"cmd":"lines"}"#);"##);
                    let binding_proven = if snapshot_site {
                        baseline_sites += 1;
                        match snapshot_lines_binding_identity(function.body, use_site.at) {
                            Ok(()) => true,
                            Err(reason) => {
                                provenance_problems.push(format!(
                                    "{file} {} status baseline binding identity: {reason}",
                                    function.name
                                ));
                                false
                            }
                        }
                    } else {
                        false
                    };
                    // 从绑定开始做 BFS：本函数读它的键 → 它被交给谁 → callee 里拿它读什么。
                    let mut queue: Vec<(usize, String, String, usize, usize)> =
                        vec![(file_index, function.name.clone(), name.clone(), use_site.at, 0)];
                    let mut visited: std::collections::BTreeSet<(usize, String, String)> =
                        std::collections::BTreeSet::new();
                    while let Some((owner_file, owner, handle, from, depth)) = queue.pop() {
                        if !visited.insert((owner_file, owner.clone(), handle.clone())) {
                            continue;
                        }
                        let Some(owner_fn) =
                            find_callee(&functions, &owner, owner_file)
                        else {
                            continue;
                        };
                        let owner_path = sources[owner_file].0;
                        // 每个句柄单独收进一个局部集合：`keys` 是 `BTreeSet`（有序），
                        // 「跳过前 N 个就是新键」是错的——新键可能排在中间。
                        let mut read: std::collections::BTreeSet<String> =
                            std::collections::BTreeSet::new();
                        keys_read_from(
                            owner_fn.body,
                            &handle,
                            from,
                            &owner_fn.name,
                            owner_path,
                            &mut read,
                            &mut opaque,
                        );
                        for key in &read {
                            // Only the original direct binding has this
                            // provenance, never chain or callee reads.
                            if binding_proven && depth == 0
                                && owner_file == file_index
                                && std::ptr::eq(owner_fn, function)
                                && handle.as_str() == name.as_str() && from == use_site.at
                                && expected_baseline.contains(key)
                            {
                                baseline_keys.insert(key.clone());
                                continue;
                            }
                            if !allowed(key) {
                                violations.push((
                                    owner_path.to_string(),
                                    owner_fn.name.clone(),
                                    handle.clone(),
                                    key.clone(),
                                ));
                            }
                            keys.insert(key.clone());
                        }
                        if depth >= 3 {
                            continue;
                        }
                        for (callee, arguments) in call_sites(&owner_fn.body[from..]) {
                            for (position, argument) in arguments.iter().enumerate() {
                                // 「提到」即算转交：`&preview`、`preview.clone()`、
                                // `&*reply`、`reply.as_ref()` 都要跳得过去。
                                if !mentions_identifier(argument, &handle) {
                                    continue;
                                }
                                let Some(target) =
                                    find_callee(&functions, &callee, owner_file)
                                else {
                                    continue;
                                };
                                let Some(param) = target.params.get(position) else {
                                    continue;
                                };
                                hops += 1;
                                queue.push((
                                    functions
                                        .iter()
                                        .find(|(_, item)| std::ptr::eq(item, target))
                                        .map(|(index, _)| *index)
                                        .unwrap_or(owner_file),
                                    target.name.clone(),
                                    param.clone(),
                                    0,
                                    depth + 1,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // 扫不动的那一类：键在变量里、常量里、或者干脆是中文。不许静默放过。
        // 与「读到的键不在白名单」「fetch 没对上账」合并成**一份**报告：
        // 一次失败就把所有问题摊开，不要修一条、再跑一条、再看下一条。
        let mut problems: Vec<String> = Vec::new();
        problems.extend(provenance_problems);
        if baseline_sites != 1 {
            problems.push(format!("status baseline site count: expected 1, got {baseline_sites}"));
        }
        if baseline_keys != expected_baseline {
            problems.push(format!(
                "status baseline key set drift: expected {expected_baseline:?}, got {baseline_keys:?}"
            ));
        }
        for key in &expected_baseline {
            if allowed(key) {
                problems.push(format!("status baseline key overlaps command/failure allowlist: {key}"));
            }
        }
        for (file, function, handle, key) in &violations {
            problems.push(format!(
                "{file} 函数 {function} 从 `{handle}` 读了回包键 {key}，但它不在 \
                 UI_REPLY_KEYS：宿主的合并会把它丢掉，界面表现为「后端有数据、页面空白」。\
                 把 {key} 加进白名单，或改用 Step::Sync 路径。"
            ));
        }
        for item in &opaque {
            // 登记粒度是 (函数, snippet) **逐字相等**——不是「这个函数整体免税」。
            let registered = OPAQUE_READS
                .iter()
                .any(|(function, snippet, _)| {
                    *function == item.function.as_str() && *snippet == item.snippet.as_str()
                });
            if registered {
                continue;
            }
            problems.push(format!(
                "{} 函数 {} 的键不是字面量（{}），扫描无法确认它是否在白名单：\
                 把键写成字面量，或在 OPAQUE_READS 里登记理由",
                item.file, item.function, item.snippet
            ));
        }
        // 下限：同一个函数的 opaque 条数必须等于登记条数。
        // 只要「逐字相等」就能挡住另一条不同的快照键；这条挡的是「同一个 snippet 出现
        // 两次、只登记一次」和「登记了却没用到」两种漂移。
        {
            let mut actual: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for item in &opaque {
                *actual.entry(item.function.as_str()).or_insert(0) += 1;
            }
            let mut declared: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for (function, _, _) in OPAQUE_READS {
                *declared.entry(function).or_insert(0) += 1;
            }
            for (function, count) in &actual {
                let listed = declared.get(function).copied().unwrap_or(0);
                if *count != listed {
                    problems.push(format!(
                        "函数 {function} 有 {count} 条「扫不动」的读，但 OPAQUE_READS 里登记了 \
                         {listed} 条：条数必须一一对应，多一条就是没登记的动态键"
                    ));
                }
            }
        }
        for (file, function, ordinal, snippet) in &unmatched {
            // 形状登记也按原文逐字匹配：登记的是「这一处」，不是「这个函数」。
            if FETCH_SHAPES.iter().any(|(shape, _)| *shape == snippet.as_str()) {
                continue;
            }
            problems.push(format!(
                "{file} 函数 {function} 里有一处 fetch(…) 的结果没被识别（第 {ordinal} 处：\
                 {snippet}）：扫描无法确认读它的人是否把键加进了白名单。\
                 把它写成 let <名> = fetch(…)，或在 FETCH_SHAPES 里登记这种形状与理由"
            ));
        }
        // 而且形状登记**按出现次数**对账，不是「这个 snippet 出现过就全免」：
        // 同一个 helper 包装写两遍、只登记一条，两处会同时被豁免——那正是
        // `OPAQUE_READS` 刚被 QA 抓出来的同一个洞，这里一并堵掉。
        {
            // snippet → (出现次数, 第一处的函数名)。
            let mut actual: std::collections::BTreeMap<&str, (usize, &str)> =
                std::collections::BTreeMap::new();
            for (_, function, _, snippet) in &unmatched {
                let entry = actual.entry(snippet.as_str()).or_insert((0, function.as_str()));
                entry.0 += 1;
            }
            // 同一 snippet 在表里出现几次就豁免几处。
            let mut declared: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for (shape, _) in FETCH_SHAPES {
                *declared.entry(shape).or_insert(0) += 1;
            }
            for (snippet, (count, function)) in &actual {
                let listed = declared.get(snippet).copied().unwrap_or(0);
                if listed == 0 || listed == *count {
                    continue;
                }
                problems.push(format!(
                    "函数 {function} 里 {count} 处未识别的 fetch 用了同一种形状（{snippet}），\
                     但 FETCH_SHAPES 只登记了 {listed} 条：一处登记只豁免一处，\
                     请按出现次数登记，或把这处改成 let <名> = fetch(…)"
                ));
            }
        }

        // 扫描面自检：数字塌下来就说明扫描失效了（切错文件、函数解析不出来……），
        // 那种「零绑定零违反」的绿是假绿。数字只往下限卡，不比等号——
        // 以后多几个 `fetch` 读者不该让这条用例红。
        eprintln!(
            "fetch 回包扫描：fetch 调用 {fetches} 处 / 已识别 {identified}（绑定 {bindings}：\
             命令回包 {checked} + status 基线 {statuses}；链式 {chains}）/ 未识别 {} 处 \
             / {} 个命令键 + {} 个独立 status 基线键（{baseline_sites} 处） / {hops} 跳转交 / {} 条扫不动",
            fetches - identified,
            keys.len(),
            baseline_keys.len(),
            opaque.len(),
        );
        // 对账是硬要求：每一处 `fetch(` 要么被识别、要么在 `FETCH_SHAPES` 里登记。
        // 没登记的会作为 problem 列出来（见下），所以这里不断言「数字相等」——
        // 一旦有人按规矩登记了形状，数字本来就该不相等。
        if checked < 15 {
            problems.push(format!(
                "只扫到 {checked} 个命令回包绑定（共 {bindings} 个 fetch 绑定），扫描面塌了"
            ));
        }
        // Baseline reads cannot compensate for lost command-key coverage.
        if keys.len() < 12 {
            problems.push(format!(
                "只从回包里读到 {} 个键（{keys:?}），扫描面塌了", keys.len()
            ));
        }
        if hops < 1 {
            problems.push(format!("转交一跳一次都没找到（hops={hops}），扫描面塌了"));
        }

        // 关键键必须在集合里：每一条都有过真实事故。谁把某个读者的读操作删掉，
        // 上面那些断言就会跟着「没东西可断言」而变绿——这一条堵住那个口子。
        const REQUIRED_KEYS: [&str; 7] = [
            // 第九次同类缺陷：首页「线路响应」恒为「等待采样」。
            "qualitySummary",
            // 第五次：点「删除」永远说「这条线路现在不能删除」（转交一跳才看得到）。
            "deletePreview",
            // 部署中心：页面永远转圈。
            "deployment",
            // 测速/保存连接方式的结果永远不落回页面。
            "lineActions",
            // 「设为日常出口」后卡片停在「等待准备」。
            "providers",
            // 邀请按钮恒灰。
            "servers",
            // 线路卡片永远不进「使用中」分支。
            "selected",
        ];
        let lost: Vec<&str> = REQUIRED_KEYS
            .iter()
            .copied()
            .filter(|key| !keys.contains(*key))
            .collect();
        if !lost.is_empty() {
            problems.push(format!(
                "这些键本该被扫描抓到，却没有：{lost:?}。当前读到的全部命令键：{keys:?}"
            ));
        }
        problems.sort();
        problems.dedup();
        problems
    }

    #[test]
    fn snapshot_lines_baseline_provenance_keeps_fetch_contract_fail_closed() {
        let ui = production_part(include_str!("uiweb.rs"));
        let form = production_part(include_str!("uiweb_form.rs"));
        let scan = |source: &str| scan_fetch_reply_contract(&[
            ("src/uiweb.rs", source), ("src/uiweb_form.rs", form),
        ]);
        let positive = scan(ui);
        assert!(positive.is_empty(), "actual recognized snapshot and command reads: {positive:?}");

        let mutate = |old: &str, new: &str| {
            assert_eq!(ui.match_indices(old).count(), 1, "mutation anchor drift: {old}");
            ui.replacen(old, new, 1)
        };
        let reject = |label: &str, source: &str, expected: &[&str]| {
            let problems = scan(source);
            for marker in expected {
                assert!(problems.iter().any(|problem| problem.contains(marker)),
                    "{label}: expected {marker:?}, actual {problems:?}");
            }
        };
        let binding = r##"let lines_raw = fetch(r#"{"cmd":"lines"}"#);"##;
        for (label, replacement) in [
            ("wrong command", r##"let lines_raw = fetch(r#"{"cmd":"providers"}"#);"##),
            ("dynamic command", "let lines_raw = fetch(&cmd);"),
            ("ambiguous command", r##"let lines_raw = fetch(r#"{"cmd":"lines","cmd":"providers"}"#);"##),
        ] {
            reject(label, &mutate(binding, replacement),
                &["status baseline site count", "读了回包键 exitEvidence"]);
        }
        reject("wrong site", &mutate("pub fn snapshot(&mut self,", "pub fn c2_other_site(&mut self,"),
            &["status baseline site count", "读了回包键 exitEvidence"]);
        reject("wrong binding", &ui.replace("lines_raw", "c2_other_binding"),
            &["status baseline site count", "读了回包键 exitEvidence"]);

        let read = r#"lines_raw.get("exitEvidence")"#;
        reject("missing baseline class", &mutate(read, r#"lines_raw.get("selected")"#),
            &["status baseline key set drift"]);
        let after = r##"let providers_raw = fetch(r#"{"cmd":"providers"}"#);"##;
        let insert = |extra: &str| mutate(after, &format!("{extra}\n        {after}"));
        reject("extra unlisted key at authorized site",
            &insert(r#"let extra = lines_raw.get("c2Unknown");"#),
            &["读了回包键 c2Unknown"]);
        reject("extra status field outside the eight-key class",
            &insert(r#"let extra = lines_raw.get("Guard");"#),
            &["读了回包键 Guard"]);
        reject("opaque read", &insert("let extra = lines_raw.get(dynamic_key);"),
            &["键不是字面量", "dynamic_key"]);
        reject("unmatched fetch", &insert(r##"fetch(r#"{"cmd":"lines"}"#);"##),
            &["结果没被识别"]);
        reject("chain without provenance",
            &insert(r##"let extra = fetch(r#"{"cmd":"lines"}"#).get("state");"##),
            &["读了回包键 state"]);
        let hop = format!("{}\nfn c2_hop(reply: &Value) {{ let extra = reply.get(\"state\"); }}\n",
            insert("c2_hop(&lines_raw);"));
        reject("callee hop cannot inherit baseline provenance", &hop,
            &["函数 c2_hop", "读了回包键 state"]);

        // These mutations leave the actual recognized declaration and
        // eight original reads in place. The checker must reject ambiguous
        // binding identity itself, not merely an unrelated coverage failure.
        let after_providers = |extra: &str| mutate(after, &format!("{after}\n        {extra}"));
        for (label, extra, reason) in [
            ("nested same-name business payload",
                r#"{ let lines_raw = providers_raw["providers"].clone(); let extra = lines_raw.get("state"); }"#,
                "unproven use of lines_raw"),
            ("same-scope local rebinding",
                r#"let lines_raw = providers_raw["providers"].clone(); let extra = lines_raw.get("state");"#,
                "unproven use of lines_raw"),
            ("assignment to original handle",
                r#"lines_raw = providers_raw["providers"].clone(); let extra = lines_raw.get("state");"#,
                "unproven use of lines_raw"),
            ("unproven whole-value alias",
                r#"let alias = lines_raw.clone(); let extra = alias.get("state");"#,
                "unproven lines_raw whole-value clone/alias"),
            ("unproven borrowed alias",
                r#"let alias = &lines_raw; let extra = alias.get("state");"#,
                "unproven use of lines_raw"),
            ("qualified same-name field",
                r#"let extra = other.lines_raw.get("state");"#,
                "qualified lines_raw"),
            ("closure parameter shadow",
                r#"let inner = |lines_raw: Value| lines_raw.get("state").cloned();"#,
                "unproven use of lines_raw"),
        ] {
            reject(label, &after_providers(extra),
                &["status baseline binding identity", reason]);
        }

        let duplicate = format!("{binding}\n        let st = fetch(r#\"{{\"cmd\":\"status\"}}\"#);\n        {binding}");
        reject("duplicate provenance site", &mutate(binding, &duplicate),
            &["status baseline site count: expected 1, got 2"]);
        reject("required command key lost",
            &mutate(r#"reply.get("qualitySummary")"#, r#"reply.get("providers")"#),
            &["这些键本该被扫描抓到，却没有", "qualitySummary"]);

        // A deliberately collapsed scan exercises the same coverage verdicts.
        let collapsed = scan_fetch_reply_contract(&[("src/uiweb.rs", ""), ("src/uiweb_form.rs", "")]);
        for marker in ["只扫到", "只从回包里读到", "转交一跳一次都没找到", "这些键本该被扫描抓到，却没有"] {
            assert!(collapsed.iter().any(|problem| problem.contains(marker)),
                "coverage gate {marker:?} missing: {collapsed:?}");
        }
    }
}
