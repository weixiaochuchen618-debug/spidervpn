//! web 前端的表单工作流（旧版的`Form` 快照的最小实现）。
//!
//! 契约来自 `web\app.js` 的 `workflow()`/`formNode()`：宿主下发表单树，页面只负责渲染，
//! 交互回传 `{Type:'form', Generation, Id, Event, Value}`。本模块只负责「宿主这一侧」：
//! 保存字段草稿、按事件产出既有命令、吸收命令回包。业务判断仍在 `ipc`/`main`。
//!
//! M1 只覆盖 旧版前端真实存在的两个入口：
//! - `rename`：线路抽屉的「重命名」（对应 旧版的`ShowTCWebRename`）
//! - `lineSettings`：线路抽屉的「连接方式与网络…」（旧版是一整页，这里只保留
//!   连接方式这一段，并在页面里明说范围）

use serde_json::{json, Value};

use crate::uiweb::Step;

/// 宿主能下发的表单视图。M2 起加入记录、诊断与维护。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Rename,
    LineSettings,
    History,
    Diagnose,
    Maintenance,
    Providers,
    Split,
    /// 「自己搭服务器」：读指纹 → 核对 → 一键部署。
    Deploy,
    /// 「服务器与设备」：只读，列服务器信息与隧道上的设备。
    Devices,
    /// 「服务器」：这台电脑记录过的服务器一览（只读，本地数据）。
    ///
    /// 与 `Devices` 的区别：那个是「从某条线路进去，看这台服务器上的设备」，
    /// 这个是「这台电脑一共记了哪些服务器」——换了线路之后仍然找得到。
    Servers,
    /// 「AI 工具名单」：内置目录逐行添加/移除 + 自定义条目 + 走向。
    Agents,
    /// 「管理恢复资料」（r94，旧版的 `ShowManagementRecovery`）：
    /// 导出/导入加密恢复包。导入只登记待核验服务器，不启用线路。
    Recovery,
}

/// 代理软件的种类：与 `provider::normalize_kind` 接受的 id 一致。
const KIND_ITEMS: [(&str, &str); 2] = [("clashverge", "Clash Verge"), ("batvpn", "BatVPN")];

/// 部署向导的登录方式（旧版的`DeployLoginMethod` 的两项原文与顺序）。
/// 索引 0/1 与后端 `CredentialKind` 的 `"password"`/`"key"` 一一对应。
const DEPLOY_LOGIN_ITEMS: [(&str, &str); 2] = [("password", "服务器密码"), ("key", "SSH 私钥")];

/// 部署向导的「默认连接方式」（旧版的`DeployTransport` 的三项原文与顺序）。
/// 索引 0/1/2 与后端 `Plan.Transport` 的 `Auto`/`Udp`/`Tcp` 一一对应。
const DEPLOY_TRANSPORT_ITEMS: [(&str, &str); 3] = [
    ("auto", "自动选择（推荐）"),
    ("udp", "标准连接"),
    ("tcp", "兼容连接"),
];

/// 兼容连接的 TCP 首选端口（旧版的`DeployTcpPort` 的三个候选，默认 443）。
const DEPLOY_TCP_PORTS: [(&str, &str); 3] = [("443", "443"), ("8443", "8443"), ("2443", "2443")];

/// 兼容连接的默认握手域名（旧版的`DeployServerName` 的默认值）。
const DEPLOY_TLS_SERVER_NAME: &str = "www.bing.com";

/// AI 工具名单的**草稿**（可比对 → 判断「有没有改动」）。
///
/// 与 `config::AgentsConfig` 形状相同但**用途不同**：这一份在宿主内存里，用户勾一下就变；
/// 只有点「保存」时才会变成一条 `agents-save` 命令。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentsDraft {
    pub lane: crate::config::AgentsLane,
    /// 内置条目 id，**目录顺序**（与落盘一致，比较才有意义）。
    pub builtin: Vec<String>,
    pub programs: Vec<String>,
    pub sites: Vec<String>,
}

/// 名单页一个内置条目的**展示事实**（来自 IPC 回包：说明、域名、运行徽标——宿主侧不落盘）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentsEntryView {
    pub id: String,
    /// `program` / `web` / `service`（分组渲染顺序也由它决定）。
    pub kind: String,
    pub name: String,
    pub detail: String,
    pub domains: Vec<String>,
    /// `running` / `installed` / `notfound`（仅程序项；页面只显示前两档）。
    pub presence: String,
}

pub struct FormState {
    pub view: View,
    /// 结构变化时自增：页面按 `ViewKey:Generation` 决定整页重绘还是就地打补丁。
    /// 只改字段值时不动它，输入框的焦点与光标才不会被重绘吞掉。
    pub generation: u64,
    pub line_id: String,
    pub line_name: String,
    pub endpoint: String,
    /// "Udp" | "Tcp"
    pub method: String,
    /// 出口网卡：这条线路指定过的那张（空 = 跟随系统默认）。来自 `line-network` 回包。
    pub net_bound: String,
    /// 本机当前的默认出口网卡（空 = 读不到，此时「跟随默认」实际等于不绑）。
    pub net_default: String,
    /// 本机可用网卡名（下拉选项，不含「跟随系统默认」那一项）。
    pub net_interfaces: Vec<String>,
    /// 下拉选中项：0 = 跟随系统默认，1..=n 对应 `net_interfaces` 的顺序；
    /// `net_stale` 时最后一项是「已不在这台电脑上」的那张。
    pub net_pick: usize,
    /// 指定的网卡当前**不在这台电脑上**：连接会被拒绝，页面必须说清。
    pub net_stale: bool,
    /// 那个已经不在的网卡名（只在 `net_stale` 时有意义）。
    pub net_stale_name: String,
    /// 「补一条兼容连接」正在进行二次确认（写服务器配置，必须先问一句）。
    pub compat_confirm: bool,
    /// 「补一条兼容连接」的结果句（成功/失败原话）。
    pub compat_note: String,
    /// 上面那句话的语气：`muted` = 进行中，`warn` = 失败，`success` = 成功。
    pub compat_tone: &'static str,
    /// 重命名草稿。
    pub draft: String,
    /// 表单里的状态句子（校验失败、保存失败、空列表提示）。
    pub notice: String,
    pub notice_tone: &'static str,
    /// 记录/诊断的行（来自命令回包，本模块只负责渲染）。
    pub items: Vec<Value>,
    /// 记录页只显示失败。
    pub only_fail: bool,
    /// 操作记录的筛选（r87，对齐 旧版的「搜索 + 来源 + 状态」）。
    /// 三个都是**页面状态**：不发命令，切换时只收起已展开的详情（下标会错位）。
    pub history_search: String,
    pub history_src: usize,
    pub history_result: usize,
    /// 勾选的行（`items` 的下标，不是筛选后的序号——筛选一变序号就错位）。
    pub history_checked: Vec<usize>,
    /// 等用户确认的那批键；确认后随命令发出去。
    pub history_pending_keys: Vec<String>,
    /// 待宿主弹出的「确认删除」请求（条数）。宿主取走后清空。
    pub history_delete_request: Option<usize>,
    /// 「显示旧版隐藏记录」（r96，旧版的`ShowClearedHistory`）。
    ///
    /// 本版的「删除所选」是**隐藏**：`operations.jsonl` 一行不动，只把键记进
    /// `operations.hidden.json`。默认不显示，勾上之后再出现，并可逐条「恢复显示」。
    pub history_show_hidden: bool,
    /// 已发出 `history-restore`、还没回包的键：回包后按它把 `items` 的 `Hidden` 置回 false。
    pub history_restore_pending: Vec<String>,
    /// 记录页当前展开的那一条（`items` 里的下标）。`None` = 全部收起。
    ///
    /// 用**原始下标**而不是「筛选后的第几条」：切换筛选时列表会变短，
    /// 按显示序存会把详情挂到另一条记录上。筛选一改就清空（见 `filter-*` 分支）。
    pub history_open: Option<usize>,
    /// 诊断结论与运行态。
    pub verdict: Value,
    pub running: bool,
    /// 维护页的代理状态（`maintenance-status` 回包里的 maintenance）。
    pub maintenance: Value,
    /// 代理软件列表与添加草稿。
    pub providers: Vec<Value>,
    pub kind: usize,
    pub port: String,
    pub domains: String,
    pub pending_remove: Option<u64>,
    /// 维护页「解除交易保护」的表单内二次确认（A-9：FormState 弹不了宿主对话框）。
    pub guard_remove_pending: bool,
    /// 名单：交易程序与网站两组。
    pub processes: Vec<Value>,
    pub domain_rules: Vec<Value>,
    /// 程序输入框（旧版的`TradeProgramInput`）：路径或程序名，添加时才落盘。
    pub program_path: String,
    /// 最近一次「添加」是程序还是网站：回包成功后只清对应输入框。
    pub split_add_kind: String,
    /// 名单页「确认程序位置」：正在定位的条目下标（`processes` 里的位置）。
    ///
    /// 只对**交易落点且解析不出路径**的条目出现。定位分两步（选文件 → 保存位置）：
    /// 选完文件立刻写配置会让「点错文件」变成一次不可撤销的写入，而这条名单决定
    /// 哪些程序被阻断——宁可我多一次确认。
    pub locate_index: Option<usize>,
    /// 已经选好、等着应用到上面那条的绝对路径。
    pub locate_path: Option<String>,
    /// 自助部署的表单步骤。0 = 一页表单（用户看得见的那一页）、1 = 指纹已读到、
    /// 2 = 已交给引擎、4 = 没开始、5 = 正在读指纹。
    ///
    /// **0 与 1 是同一个页面的两种内部状态**：用户看到的始终是一整页
    /// （地址 / 账户 / 密码 / 两个勾 / 高级设置），不会有「先填地址、下一页再填密码」。
    /// 旧版 旧版就是一页，这里不为「向导更清晰」这种口味改交互。
    pub deploy_step: u8,
    pub deploy_spec: String,
    /// 线路名称（留空 → 后端按「自建 · 主机」自动命名）。
    pub deploy_label: String,
    /// 登录账户（地址里写了 `user@` 时以地址为准）。
    pub deploy_user: String,
    /// SSH 端口（地址里写了 `:port` 时以地址为准）。
    pub deploy_port: String,
    /// 登录方式索引：0 = 服务器密码、1 = SSH 私钥（旧版的 `DeployLoginMethod` 的 0/1）。
    pub deploy_login: usize,
    /// SSH 私钥文件路径（旧版的 `DeployKeyPath`）。**只记路径**：文件内容永远不进快照。
    pub deploy_key_path: String,
    /// 默认连接方式索引：0 = 自动、1 = 标准连接、2 = 兼容连接（旧版的 `DeployTransport`）。
    ///
    /// 与旧版一致：两只连接都会被准备，它只决定**登记完选中哪条**。
    pub deploy_transport: usize,
    /// 兼容连接的 TCP 首选端口（旧版的 `DeployTcpPort`，默认 443）。
    pub deploy_tcp_port: String,
    /// 兼容连接的 REALITY 握手域名（旧版的 `DeployServerName`，默认 `www.bing.com`）。
    pub deploy_server_name: String,
    /// 「使用这台服务器保存的登录资料」（r95，旧版的`DeployUseSaved`）。
    /// 默认勾上；只在**真的有长期信封**时显示。
    pub deploy_use_saved: bool,
    /// 「使用本任务保存的登录资料（重新输入会替换）」（r95，旧版的 `DeployUseTaskCredential`）。
    pub deploy_use_task: bool,
    /// `server-probe` 告诉页面：长期 / 任务级信封是否存在。
    pub deploy_saved_available: bool,
    pub deploy_task_available: bool,
    /// 「在这台电脑记住登录资料」（长期作用域，默认勾上）。
    pub deploy_remember_saved: bool,
    /// 「本任务中断后可用这份资料继续（最长 24 小时…）」（任务作用域，默认勾上）。
    pub deploy_remember_task: bool,
    /// 「已核对云端放行端口」（r91，对齐 旧版的 `LinuxCloudConfirmed`）。
    ///
    /// 默认**不勾**：这是一句承诺（云端安全组/防火墙已放行部署用的 UDP 端口，并保留 SSH
    /// 入口），替用户先勾上等于替他签字。它也不跟着草稿存——确认是「这一次部署」的前置，
    /// 不是账号级偏好；从草稿接着填的人应该再看一眼云端。
    pub deploy_cloud: bool,
    /// 读指纹回来之后的下一步。`Absorbed` 带不了命令，所以由宿主取走再发。
    pub deploy_followup: Option<DeployFollowUp>,
    /// **只在内存里**：render 时从不回填，只告诉页面「已经填过了」。
    pub deploy_password: String,
    pub deploy_fingerprint: String,
    /// 这台服务器是否已经有记录（有就跳过密码，用 DPAPI 里那份）。
    pub deploy_known: bool,
    /// 读到指纹时用的规范地址（`user@host:port`）。第二次点「开始部署」时用它判断
    /// 「地址没改，可以跳过重复 probe」。
    pub deploy_probed_spec: String,
    pub deploy_notice: String,
    /// 这句提示要活过「它自己引起的那一次记录变化」（归档/恢复会改记录）。
    /// 只保一帧：下一帧照常按「记录动了就清」处理。
    pub deploy_notice_pinned: bool,
    /// 部署任务详情：**非空时 Deploy 视图由这条记录驱动**，旧五步向导只用于新建。
    pub deploy_run_id: String,
    /// 正在填写的草稿（`State=="Draft"` 那条记录的 `RunId`）。**非空时这一页是
    /// 「接着填」的向导，不是详情页**（`deploy_run_id` 仍为空）。
    ///
    /// 它回答三件事：这次填写已经落过盘（所以多一颗「放弃这次填写」）、后续命令
    /// 要带 `runId`（否则每次点 probe 都会新建一条草稿）、以及丢弃成功后该关掉表单。
    pub deploy_draft_id: String,
    /// `deployment-get` 的 `Run` 投影（`deployrun::run_view`），原样保存不做二次加工。
    pub deploy_run: Value,
    /// 「取消这次部署」的表单内二次确认（FormState 弹不出宿主对话框）。
    pub deploy_cancel_pending: bool,
    /// 「暂停部署」已受理、还没落地：这一步做完之后才停。
    pub deploy_pause_pending: bool,
    /// 「服务器与设备」的回包（`serverDevices`）；`Null` = 还在读。
    pub devices: Value,
    /// 待确认撤销的设备公钥。非空时页面显示确认层——撤销是不可逆的写操作，
    /// 与「删除线路」同一条规矩：点一下就执行是回归。
    pub pending_revoke: Option<String>,
    /// 待确认删除的**名称记录**公钥（设备已撤销，只留下名字）。
    /// 与 `pending_revoke` 分开：一个动隧道上的 peer，一个只动服务器上的名字记录，
    /// 影响面完全不同，确认文案也不能共用。
    pub pending_forget: Option<String>,
    /// AI 工具名单：走向下拉的索引（0=跟随日常上网 1=使用交易线路）。
    pub agents_lane: usize,
    /// 草稿：已加入名单的内置条目 id（点行内的「添加 / 移除」当场切换）。
    pub agents_builtin: Vec<String>,
    /// 草稿：自定义程序。移除是**直接从这里删掉**，不设「保存后移除」标记；
    /// 行仍然留在页面上，是因为渲染按「基线 ∪ 草稿 ∪ 本轮见过」列（见 `agents_custom_values`）。
    pub agents_programs: Vec<String>,
    /// 草稿：自定义网站（同上）。
    pub agents_sites: Vec<String>,
    /// 本轮会话里**进入过草稿**的自定义值（`(kind, 值)`）。
    ///
    /// 只解决一个体验问题：新增项还没保存就被「移除」时，基线里没有、草稿里也没有，
    /// 只按「基线 ∪ 草稿」渲染的话整行会消失、用户只能重新打字；而**已保存过**的条目
    /// 移除后行还在。同一个「移除」两种结果会让人问为什么，所以这里补一份临时记忆，
    /// 让两种来源的行表现一致。
    ///
    /// 它是**临时**的：拿到新快照（`fill_agents`）与「放弃修改」（`discard`）都清空，
    /// 保存成功后同样清空——否则下次进来会看到一条早已不存在的幽灵行。
    pub agents_seen: Vec<(String, String)>,
    /// 网址输入框的草稿。**必须回填**：整页重绘时若写死空串，用户刚打的字会被一次点击吞掉。
    pub agents_site_draft: String,
    /// 当前线路有没有交易出口（来自回包，不在渲染时重新判断）。
    pub agents_trade_exit: bool,
    /// 全局覆盖：日常上网已经走交易线路，名单走向不可单独设置（PRD §7.1）。
    pub agents_global_override: bool,
    /// 打开页面时的连接状态；保存被拒（busy）后置位。
    pub agents_busy: bool,
    /// 进入页面 / 上次保存成功时的基线 → 「放弃修改」与「有没有改动」都对着它算。
    pub agents_base: AgentsDraft,
    /// 行内提示（校验失败、保存回话）。与 `notice` 分开：名单页的提示贴在保存条附近。
    pub agents_note: String,
    /// 回包带来的「这个值在交易名单里」事实（键 `builtin:<id>` / `program:<值>` / `site:<值>`）。
    /// 渲染层不持有配置事实，所以这一句只能由回包给。
    pub agents_in_trade: Vec<String>,
    /// 回包带来的内置条目展示事实（说明/域名/运行徽标），顺序即目录顺序。
    pub agents_entries: Vec<AgentsEntryView>,
    /// 服务器一览里正在改名的记录 id。`None` = 没在改名。
    ///
    /// 草稿名复用 [`FormState::draft`]：改名是同一个动作（输入 → 校验 → 发命令），
    /// 与线路改名共用同一套字段，不必再存一份。
    pub server_rename: Option<String>,
    /// 服务器一览里正在确认删除的记录 id。`None` = 没在确认。
    pub server_remove: Option<String>,
    /// 「删除本机部署资料」正在处理的记录 id。点完按钮就置位，回包到了才清。
    ///
    /// 单独一份而不是复用 [`FormState::server_remove`]：两个动作删的东西完全不同
    /// （一个只删记录，一个连部署记录、提醒、任务级凭据一起删），共用一个字段时
    /// 「刷新回包该清哪一个」会变成猜。
    pub server_cleanup: Option<String>,
    /// 预览结论变成的确认框，等宿主取走（`dialog` 归宿主）。
    pub server_cleanup_request: Option<Value>,
    /// 设备页正在改名的设备下标（`devices` 里的位置）。名字草稿同样用 `draft`。
    pub device_rename_index: Option<usize>,
    /// 卸载预览回包（`serverUninstallPreview`）；`Null` = 没在卸载流程里。
    pub uninstall_preview: Value,
    /// 卸载预览/执行正在进行：页面据此显示进度并禁用按钮。
    pub uninstall_running: bool,
    /// 管理恢复资料：`true` = 导入，`false` = 导出（旧版的`ShowManagementRecovery` 的两种 Mode）。
    pub recovery_mode_import: bool,
    /// 导出目标（从「服务器」页点进来时带上的那一条）。
    pub recovery_server_id: String,
    pub recovery_server_name: String,
    /// 恢复包密码（导出与导入共用一槽；两种模式不同时可见）。
    pub recovery_password: String,
    /// 「我选择把 SSH 管理密码 / 私钥也包含在加密包中」。
    pub recovery_include: bool,
    /// 要包含的 SSH 密码 / 私钥口令。
    pub recovery_credential_password: String,
    pub recovery_key_path: String,
    /// 导出成功后宿主生成的恢复包文本（**已加密**，可显示、可保存）。
    pub recovery_package: String,
    pub recovery_file_name: String,
    /// 导入页粘贴的恢复包文本。
    pub recovery_text: String,
    /// 保存成功后的路径。
    pub recovery_saved_path: String,
    /// 导入/导出的结果句子。
    pub recovery_notice: String,
    pub recovery_notice_tone: &'static str,
    /// 导入成功：页面显示「返回服务器」。
    pub recovery_done: bool,
}

impl FormState {
    pub fn rename(line_id: &str, name: &str) -> Self {
        Self {
            view: View::Rename,
            line_id: line_id.to_string(),
            line_name: name.to_string(),
            draft: name.to_string(),
            ..Self::blank()
        }
    }

    pub fn line_settings(line_id: &str, name: &str, endpoint: &str, method: &str) -> Self {
        Self {
            view: View::LineSettings,
            line_id: line_id.to_string(),
            line_name: name.to_string(),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            // 打开的同时就去读本机网卡（`Step::Sync(line-network)`）：列表空着会被
            // 读成「这台电脑只有「跟随默认」这一项」，所以先说清还在读。
            notice: LOADING_INTERFACES.into(),
            ..Self::blank()
        }
    }

    pub fn history() -> Self {
        Self {
            view: View::History,
            generation: 1,
            notice: "正在读取记录…".into(),
            ..Self::blank()
        }
    }

    /// 「服务器」一览：只读。数据来自 `servers` 命令（线路文件里的地址 ↔ 服务器记录）。
    pub fn servers() -> Self {
        Self {
            view: View::Servers,
            generation: 1,
            notice: "正在读取服务器记录…".into(),
            ..Self::blank()
        }
    }

    pub fn diagnose() -> Self {
        Self {
            view: View::Diagnose,
            generation: 1,
            notice: "正在诊断…".into(),
            running: true,
            ..Self::blank()
        }
    }

    pub fn maintenance() -> Self {
        Self {
            view: View::Maintenance,
            generation: 1,
            notice: "正在读取代理状态…".into(),
            ..Self::blank()
        }
    }

    pub fn providers() -> Self {
        Self {
            view: View::Providers,
            generation: 1,
            notice: "正在读取代理软件…".into(),
            ..Self::blank()
        }
    }


    /// 「服务器与设备」：先显示加载态，回包到了再填。
    pub fn devices(line_id: &str) -> Self {
        Self {
            view: View::Devices,
            line_id: line_id.to_string(),
            generation: 1,
            ..Self::blank()
        }
    }

    /// 「自己搭服务器」：从填地址开始。**不预填任何密码**。
    pub fn deploy() -> Self {
        Self {
            view: View::Deploy,
            generation: 1,
            ..Self::blank()
        }
    }

    /// 「部署任务详情」：从任务行 / 底部任务条点进来时用的表单。
    ///
    /// 与 [`FormState::deploy`] 的区别是**判断依据**：这一页的步骤、原因、主按钮
    /// 全部来自磁盘上的那条记录（`deployment-get` 的 `Run`），旧向导的五步状态机
    /// 一个都不参与。两套状态并存的代价是 `deploy_step` 在这一页恒为 0，
    /// 所以 `render_deploy` 的第一行就按 `deploy_run_id` 分流。
    pub fn deploy_run(run_id: &str, run: Value) -> Self {
        Self {
            view: View::Deploy,
            generation: 1,
            deploy_run_id: run_id.to_string(),
            deploy_run: run,
            ..Self::blank()
        }
    }

    /// 「继续填写」一条草稿：**同一页表单**，不是详情页。
    ///
    /// 与 [`FormState::deploy_run`] 的区别是判断依据：这一页读的是记录里的
    /// `Target` / `Label` / `Identity.Fingerprint`，然后把那一页填好；
    /// `deploy_run_id` 仍为空，所以 `render_deploy` 不会走详情页那条分支。
    ///
    /// **密码绝不取回**：记录里根本没有它（`FORBIDDEN_KEYS` 守着）。任务级凭据
    /// 在磁盘上，但那是宿主侧在 `deployment-start` 里解析的事——页面不该看见密码。
    /// 所以这里只如实说一句「密码由已保存的资料提供，或重新输入」。
    pub fn deploy_from_draft(run: &Value) -> Self {
        let target = run.get("Target").cloned().unwrap_or(Value::Null);
        let host = target
            .get("Host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let user = target
            .get("User")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let user = if user.is_empty() {
            "root".to_string()
        } else {
            user
        };
        let port = target
            .get("Port")
            .and_then(Value::as_u64)
            .unwrap_or(22) as u16;
        // 登录方式与私钥路径都是**非秘密**，草稿里存了（`Target.LoginMethod/IdentityFile`），
        // 恢复时照原样回填；旧记录缺这两键 → 当密码登录（与旧行为一致）。
        let login = target.get("LoginMethod").and_then(Value::as_str).unwrap_or("");
        let identity_file = target
            .get("IdentityFile")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        // 兼容连接的三个选择：`Plan` 里存的是批准过的值（旧记录没有 → 自动/443/www.bing.com）。
        let plan = run.get("Plan").cloned().unwrap_or(Value::Null);
        let transport = plan.get("Transport").and_then(Value::as_str).unwrap_or("");
        let deploy_transport = match transport {
            "Tcp" => 2,
            "Udp" => 1,
            _ => 0,
        };
        let tcp_port = plan
            .get("TcpPort")
            .and_then(Value::as_u64)
            .map(|value| value.to_string())
            .filter(|value| !value.is_empty() && value != "0")
            .unwrap_or_else(|| "443".to_string());
        let server_name = plan
            .get("ServerName")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEPLOY_TLS_SERVER_NAME)
            .to_string();
        // 地址栏只留**主机**：账户与端口现在有各自的输入框，地址里再写一遍
        // 就会变成两份真相（用户改了一个、另一个还在）。
        let spec = host.clone();
        let fingerprint = run
            .get("Identity")
            .and_then(|identity| identity.get("Fingerprint"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let draft_id = run
            .get("RunId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let label = run
            .get("Label")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let flag = |key: &str, fallback: bool| {
            run.get(key)
                .and_then(Value::as_bool)
                .unwrap_or(fallback)
        };
        Self {
            view: View::Deploy,
            generation: 1,
            deploy_step: 0,
            deploy_spec: spec,
            deploy_label: label,
            deploy_user: user,
            deploy_port: port.to_string(),
            deploy_login: usize::from(login == "key"),
            deploy_key_path: identity_file,
            deploy_transport,
            deploy_tcp_port: tcp_port,
            deploy_server_name: server_name,
            deploy_remember_saved: flag("RememberSaved", true),
            deploy_remember_task: flag("RememberTask", false),
            deploy_cloud: false,
            deploy_followup: None,
            deploy_fingerprint: fingerprint,
            deploy_draft_id: draft_id,
            deploy_notice: "已恢复上次没填完的内容；密码由已保存的登录资料提供，也可以重新输入。"
                .into(),
            deploy_notice_pinned: false,
            ..Self::blank()
        }
    }

    pub fn split() -> Self {
        Self {
            view: View::Split,
            generation: 1,
            notice: "正在读取交易名单…".into(),
            ..Self::blank()
        }
    }

    /// 宿主文件拖放（r100）：把 .exe 路径填进「程序」输入框。
    ///
    /// 只在这一页受理；填完**不立刻写配置**——与「浏览…」一致，点「添加程序」才落盘。
    /// 返回 `false` 表示当前不是这一页（宿主不该吞掉这次拖放）。
    pub fn fill_program_path(&mut self, path: &str) -> bool {
        let path = path.trim();
        if self.view != View::Split || path.is_empty() {
            return false;
        }
        self.program_path = path.to_string();
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path);
        self.notice = format!("已选择：{name}；点「添加程序」");
        self.restructure();
        true
    }

    /// 宿主文件拖放（r101）：这次拖进来的文件**换不出可用的程序**。
    ///
    /// 为什么非要单独说一句：用户拖的十有八九是桌面快捷方式，`.lnk` 本身不是交易程序。
    /// 静默丢掉就退化成「拖了没反应」——人只会以为程序坏了。这里只改提示，
    /// **不动 `program_path`**（没换出真程序就绝不往配置里填半条路径）。
    /// 返回 `false` 表示当前不是这一页（宿主不该吞掉这次拖放）。
    pub fn notice_program_unusable(&mut self, path: &str) -> bool {
        if self.view != View::Split {
            return false;
        }
        let path = path.trim();
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path)
            .trim();
        let name = if name.is_empty() { path } else { name };
        self.notice = format!("「{name}」找不到可用的程序；快捷方式要指向 .exe 才能填进来。");
        self.restructure();
        true
    }

    /// 「管理恢复资料 · 导出」：从服务器页某一条记录点进来。
    #[cfg(test)]
    pub fn recovery_export(server_id: &str, name: &str) -> Self {
        Self {
            view: View::Recovery,
            generation: 1,
            recovery_mode_import: false,
            recovery_server_id: server_id.to_string(),
            recovery_server_name: name.to_string(),
            ..Self::blank()
        }
    }

    /// 「管理恢复资料 · 导入」：不依赖任何一条已有记录。
    #[cfg(test)]
    pub fn recovery_import_form() -> Self {
        Self {
            view: View::Recovery,
            generation: 1,
            recovery_mode_import: true,
            ..Self::blank()
        }
    }

    /// 「AI 工具名单」：先显示加载态，`agents` 回包到了再填目录与草稿。
    pub fn agents() -> Self {
        Self {
            view: View::Agents,
            generation: 1,
            agents_note: "正在读取 AI 工具名单…".into(),
            ..Self::blank()
        }
    }

    fn blank() -> Self {
        Self {
            view: View::History,
            generation: 1,
            line_id: String::new(),
            line_name: String::new(),
            endpoint: String::new(),
            method: String::new(),
            net_bound: String::new(),
            net_default: String::new(),
            net_interfaces: Vec::new(),
            net_pick: 0,
            net_stale: false,
            net_stale_name: String::new(),
            compat_confirm: false,
            compat_note: String::new(),
            compat_tone: "muted",
            draft: String::new(),
            notice: String::new(),
            notice_tone: "muted",
            items: Vec::new(),
            only_fail: false,
            history_search: String::new(),
            history_src: 0,
            history_result: 0,
            history_checked: Vec::new(),
            history_pending_keys: Vec::new(),
            history_delete_request: None,
            // 旧版默认不显示隐藏记录（`HistoryIncludeHidden` 缺省 false）。
            history_show_hidden: false,
            history_restore_pending: Vec::new(),
            history_open: None,
            verdict: Value::Null,
            running: false,
            maintenance: Value::Null,
            providers: Vec::new(),
            kind: 0,
            port: String::new(),
            domains: String::new(),
            pending_remove: None,
            guard_remove_pending: false,
            processes: Vec::new(),
            domain_rules: Vec::new(),
            program_path: String::new(),
            split_add_kind: String::new(),
            locate_index: None,
            locate_path: None,
            deploy_step: 0,
            deploy_spec: String::new(),
            deploy_label: String::new(),
            deploy_user: "root".into(),
            deploy_port: "22".into(),
            // 默认密码登录（旧版的 `DeployLoginMethod` 的默认索引 0）。
            deploy_login: 0,
            deploy_key_path: String::new(),
            // 默认「自动选择」、TCP 443、握手域名 www.bing.com（旧版三处默认值）。
            deploy_transport: 0,
            deploy_tcp_port: "443".into(),
            deploy_server_name: DEPLOY_TLS_SERVER_NAME.into(),
            // 两个「使用已保存凭据」的勾默认也是 true（旧版缺省勾上）；
            // 「有没有那一档」由 `server-probe` 回包决定，未探测时两格都不画。
            deploy_use_saved: true,
            deploy_use_task: true,
            deploy_saved_available: false,
            deploy_task_available: false,
            // 两个勾的默认值照旧版：都是勾上的（`DeploymentPages.ps1` 里两处
            // `$form.ContainsKey(...) ? ... : $true`）。
            deploy_remember_saved: true,
            deploy_remember_task: true,
            // 云端放行要用户自己确认，不给默认值（见字段注释）。
            deploy_cloud: false,
            deploy_followup: None,
            deploy_password: String::new(),
            deploy_fingerprint: String::new(),
            deploy_known: false,
            deploy_probed_spec: String::new(),
            deploy_notice: String::new(),
            deploy_notice_pinned: false,
            deploy_run_id: String::new(),
            deploy_draft_id: String::new(),
            deploy_run: Value::Null,
            deploy_cancel_pending: false,
            deploy_pause_pending: false,
            devices: Value::Null,
            pending_revoke: None,
            pending_forget: None,
            agents_lane: 0,
            agents_builtin: Vec::new(),
            agents_programs: Vec::new(),
            agents_sites: Vec::new(),
            agents_seen: Vec::new(),
            agents_site_draft: String::new(),
            agents_trade_exit: false,
            agents_global_override: false,
            agents_busy: false,
            agents_base: AgentsDraft::default(),
            agents_note: String::new(),
            agents_in_trade: Vec::new(),
            agents_entries: Vec::new(),
            server_rename: None,
            server_remove: None,
            server_cleanup: None,
            server_cleanup_request: None,
            device_rename_index: None,
            uninstall_preview: Value::Null,
            uninstall_running: false,
            recovery_mode_import: false,
            recovery_server_id: String::new(),
            recovery_server_name: String::new(),
            recovery_password: String::new(),
            recovery_include: false,
            recovery_credential_password: String::new(),
            recovery_key_path: String::new(),
            recovery_package: String::new(),
            recovery_file_name: String::new(),
            recovery_text: String::new(),
            recovery_saved_path: String::new(),
            recovery_notice: String::new(),
            recovery_notice_tone: "muted",
            recovery_done: false,
        }
    }

    fn view_key(&self) -> &'static str {
        match self.view {
            View::Rename => "line-rename",
            View::LineSettings => "line-settings",
            View::History => "history",
            View::Diagnose => "diagnose",
            View::Maintenance => "maintenance",
            View::Providers => "providers",
            View::Split => "split",
            View::Deploy => "server-deploy",
            View::Devices => "server-devices",
            View::Servers => "servers",
            View::Agents => "agents",
            View::Recovery => "recovery",
        }
    }

    /// 结构变化：页面整页重绘（新增提示、按钮禁用态变化）。
    fn restructure(&mut self) {
        self.generation += 1;
    }

    /// 快照每帧重读回来的记录：变了就换掉并重绘。
    ///
    /// 返回 `true` 表示结构变了。**只在详情页调用**（`deploy_run_id` 非空），
    /// 否则每帧多读一份 JSON 没有任何意义。
    pub fn refresh_run(&mut self, run: Value) -> bool {
        if self.deploy_run == run {
            return false;
        }
        self.deploy_run = run;
        // 记录动了：「已受理…」那句提示已经过期，留着会让人以为还没开始。
        //
        // 例外：**动作自己的回包**（归档/恢复）必然引起一次记录变化，那句话必须活过
        // 这一帧——否则用户点了「归档」，屏幕上什么也没说，只有按钮悄悄换了文案。
        // 只保一帧：下一帧照常清。
        if self.deploy_notice_pinned {
            self.deploy_notice_pinned = false;
        } else {
            self.deploy_notice.clear();
        }
        // 暂停已落地（或引擎没了）：提示条不能继续挂着。
        if self.deploy_pause_pending {
            let running = self
                .deploy_run
                .get("Running")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !running {
                self.deploy_pause_pending = false;
            }
        }
        self.restructure();
        true
    }

    pub fn render(&self) -> Value {
        match self.view {
            View::Rename => self.render_rename(),
            View::LineSettings => self.render_line_settings(),
            View::History => self.render_history(),
            View::Diagnose => self.render_diagnose(),
            View::Maintenance => self.render_maintenance(),
            View::Providers => self.render_providers(),
            View::Split => self.render_split(),
            View::Deploy => self.render_deploy(),
            View::Devices => self.render_devices(),
            View::Servers => self.render_servers(),
            View::Agents => self.render_agents(),
            View::Recovery => self.render_recovery(),
        }
    }

    /// 「自己搭服务器」：**一页收完**（旧版版式「甲」）。
    ///
    /// 为什么是一页：旧版就是「地址 + 折叠的账户/端口 + 密码 + 两个勾 + 高级设置」，
    /// 点「开始部署」之后才去读指纹。r85 曾把它拆成「先填地址 → 下一页再填密码」，
    /// 用户明确不接受——多一页并没有让任何人更安全，只让同一次填写被切成了两半。
    ///
    /// 读指纹/确认身份仍然发生，但它们是**同一个页面的后台步骤**：用户看到的还是
    /// 这一页，`deploy_step = 5` 只是把按钮禁掉、在顶部说一句「正在核对服务器身份…」。
    fn render_deploy(&self) -> Value {
        // 从任务行 / 底部任务条进来的，一律由磁盘上那条记录驱动。
        if !self.deploy_run_id.is_empty() {
            return self.render_deploy_run();
        }
        let mut body: Vec<Value> = Vec::new();
        // 这一页是从任务列表「继续填写」进来的（草稿已落盘）：给一条退路
        // 「放弃这次填写」。一次点击、无二次确认——内容只是地址，没碰服务器。
        //
        // **不在读指纹/已受理时给**：那时候点放弃会删掉草稿，而 probe 的回包照样
        // 会把表单推进——接着点「开始部署」必然以「读不到这条部署任务」失败。
        let mut discard: Vec<Value> = Vec::new();
        if !self.deploy_draft_id.is_empty() && matches!(self.deploy_step, 0 | 1) {
            discard.push(button(
                "draft-discard",
                "DeployDraftDiscard",
                "放弃这次填写",
                "ghost",
                false,
            ));
        }
        // 已经交给引擎：这一页只留下一句进度与出口，表单本身不再可编辑。
        if self.deploy_step == 2 {
            body.push(muted(
                "正在把这次部署交给引擎，通常需要 1–3 分钟（要下载约 20 MB 的官方组件）。",
            ));
            body.push(muted(
                "接下来可以在任务详情里看每一步的进展；关掉窗口也不会中断。",
            ));
            if !self.deploy_notice.is_empty() {
                body.push(text_tone(&self.deploy_notice, "warn"));
            }
            return self.deploy_page(body);
        }
        // 没开始（校验失败/引擎拒收）：保留用户填过的内容，只换掉按钮区。
        let failed = self.deploy_step == 4;

        // 1. 服务器地址（旧版的 `DeployConnectionText`）。
        //    r105：控件只留动作，解释进 `Hint`（前端渲染成 ⓘ 悬停展开）——一页表单
        //    不该像说明书，每个框下面挂一两句解释会把「要填什么」压掉。
        //
        //    `Hint` 挂在**标签**上、并且**包进 `row`**：用户看的是「服务器地址」这四个字，
        //    ⓘ 要跟着它走。`hintFor()` 是追加在**同级**的，而 `.wf-stack` 是纵向堆叠，
        //    直接挂在标签上会让 ⓘ 掉到下一行、独占一行空白；`.wf-row` 是 `display:flex`
        //    （`web/forms.css:50`），ⓘ 才跟得在同一行。agents 页首那句也是这么包的。
        //    输入框自己**不挂** `Hint`——一个控件两个 ⓘ 比没有更糟。
        body.push(row(vec![with_hint(
            field_label("服务器地址"),
            "可以粘贴 IP，也可以粘贴完整登录地址（如 root@1.2.3.4:22）。",
        )]));
        body.push(input("spec", "DeploySpec", "服务器地址", &self.deploy_spec, 200));

        // 2. 账户/端口/名称收在同一个折叠区（旧版的 `DeployAccessAdvanced`）。
        let mut account: Vec<Value> = Vec::new();
        account.push(field_label("线路名称（留空自动命名）"));
        account.push(input(
            "name",
            "DeployName",
            "线路名称（留空自动命名）",
            &self.deploy_label,
            120,
        ));
        account.push(field_label("登录账户"));
        account.push(input("user", "DeployUser", "登录账户", &self.deploy_user, 64));
        account.push(field_label("SSH 端口"));
        account.push(input("port", "DeployPort", "SSH 端口", &self.deploy_port, 5));
        // 登录方式与私钥（旧版的 `DeployLoginMethod` / `DeployKeyPath`，同在
        // `DeployAccessAdvanced` 折叠区里）。两格**始终都在**：旧版也是同时显示，
        // 私钥路径在密码模式下留空即可。
        account.push(field_label("登录方式"));
        account.push(select(
            "login-method",
            "DeployLoginMethod",
            "登录方式",
            self.deploy_login,
            &DEPLOY_LOGIN_ITEMS,
            false,
        ));
        account.push(field_label("SSH 私钥文件（密码登录留空）"));
        account.push(row(vec![
            input(
                "key-path",
                "DeployKeyPath",
                "SSH 私钥文件（密码登录留空）",
                &self.deploy_key_path,
                260,
            ),
            button("pick-key", "DeployPickKey", "选择…", "ghost", false),
        ]));
        account.push(muted(
            "OpenSSH 新格式、PEM/PKCS#8 与 PuTTY .ppk（v2/v3）都能用；私钥只在本机读取，\
             口令与私钥内容都不会写进任务记录。",
        ));
        account.push(muted(
            "地址里写了 用户名@主机 或 主机:端口 时以地址为准；只写 IP 或域名时用上面这两项。",
        ));
        body.push(details(
            "deploy-access",
            "登录账户、密钥与名称",
            account,
            // 静态判据：切模式**不重绘**（重绘会让下一次 change 撞上代数闸门，
            // 见 r92 设计 §4.8），所以这里只在首次渲染时决定展开与否。
            self.deploy_login == 1 || !self.deploy_key_path.is_empty(),
        ));

        // 3. 服务器登录密码（旧版的 `DeployCredentialLabel` 的文案）+ 显示切换。
        //    前端把 `password` 节点渲染成「密码框 + 显示」，与旧版的
        //    `DeployPasswordReveal` / `DeployPasswordPlainText` 语义一致。
        //
        // r105：两段解释（私钥模式填什么、留空代表什么）合成**一条** `Hint`，挂在
        // 标签「服务器登录密码」上并包进 `row`（理由同第 1 段：不包 `row` 就独占一行）。
        // 标签仍**不随登录方式切换**（不重绘，r92 设计 §4.8），所以「填什么」这层信息
        // 只能挂在 `Hint` 上——这也是它必须留在页面里的原因（ⓘ 一点就能看到，不是删掉）。
        body.push(row(vec![with_hint(
            field_label("服务器登录密码"),
            "SSH 私钥方式填私钥口令（未加密就留空），服务器密码方式填登录密码；\
             留空表示沿用已保存的登录资料。",
        )]));
        body.push(secret(
            "password",
            "DeployPassword",
            "服务器登录密码",
            !self.deploy_password.is_empty(),
            200,
        ));

        // 4. 长期保存（紧邻密码框），5. 任务级保存——顺序照旧版，但两者之间的分隔线
        //    在 r105 删掉了（两个勾都只剩一行字，那条线没有分组意义，只有噪音）。
        //    勾选框包进 `row`：ⓘ 跟在文字右侧，而不是自己掉到下一行。
        body.push(row(vec![with_hint(
            check(
                "remember-saved",
                "DeployRememberSaved",
                "在这台电脑记住登录资料",
                self.deploy_remember_saved,
            ),
            "用当前 Windows 用户加密保存在本机；换电脑或换 Windows 用户要重新输入。\
             私钥同样加密保存，不写进任务记录，也不出现在导出文件里。",
        )]));
        // r95：只有**真的存在**长期信封时才画这个勾（旧版的 `DeployUseSaved` 也是条件出现）。
        if self.deploy_known && self.deploy_saved_available {
            body.push(check(
                "use-saved",
                "DeployUseSaved",
                "使用这台服务器保存的登录资料",
                self.deploy_use_saved,
            ));
        }
        // r105：这里原来有一条分隔线，把「长期保存」和「任务级保存」隔开。两个勾都
        // 只剩一行字之后，那条线成了两个勾之间唯一的装饰——删掉，靠间距分组。
        //
        // 标题只留「中断后可用这份资料继续」，24 小时的期限与清除时机进 `Hint`，
        // 同样包 `row`：ⓘ 贴在勾选框文字右侧。
        body.push(row(vec![with_hint(
            check(
                "remember-task",
                "DeployRemember",
                "中断后可用这份资料继续",
                self.deploy_remember_task,
            ),
            "最长 24 小时；任务完成或放弃时清除。",
        )]));
        // r95：任务级信封存在时才画（旧版的 `DeployUseTaskCredential`）。
        if self.deploy_task_available {
            body.push(check(
                "use-task",
                "DeployUseTaskCredential",
                "使用本任务保存的登录资料（重新输入会替换）",
                self.deploy_use_task,
            ));
        }

        // 7. 云端放行确认（r91，旧版的 `LinuxCloudConfirmed`）：不勾就点「开始部署」，
        //    由 `deploy_start_steps` 拦下来并说明原因。比让部署跑到连通性自检超时、
        //    再回来猜「是不是防火墙」便宜得多。
        //
        //    r105：勾选框只留「已核对」，端口号与「没放行会怎样」进 `Hint`——
        //    那两件事只在用户犹豫「我到底核对了没有」时才需要，不该常驻占两行。
        //    包 `row` 让 ⓘ 跟在勾选框文字右侧，不独占一行。
        //    **判据不变**：不勾时点「开始部署」照样拦，提示文案一个字没动。
        body.push(row(vec![with_hint(
            check(
                "deploy-cloud",
                "DeployCloudConfirmed",
                "已核对云端安全组与防火墙",
                self.deploy_cloud,
            ),
            "需要放行部署用的 UDP 端口入站，并保留 SSH 入口。默认 UDP 51820，\
             第一步检查服务器环境时会确认；没放行的话第一步会以「连不上服务器」结束\
             ——那不是密码错了。",
        )]));

        // 8. 高级部署设置：**逐项照旧版的 `DeploymentAdvanced`**。
        //    旧版只有三格：默认连接方式、TCP 首选端口、TCP 握手目标。
        //    「两只连接都会被准备，Transport 只选默认」——所以这里不是「只装一种」。
        let mut advanced: Vec<Value> = Vec::new();
        advanced.push(field_label("默认连接方式"));
        advanced.push(select(
            "transport",
            "DeployTransport",
            "默认连接方式",
            self.deploy_transport,
            &DEPLOY_TRANSPORT_ITEMS,
            false,
        ));
        advanced.push(muted(
            "标准与兼容连接都会准备；这里只决定完成后默认使用哪一条。",
        ));
        advanced.push(field_label("TCP 首选端口"));
        advanced.push(select(
            "tcp-port",
            "DeployTcpPort",
            "TCP 首选端口",
            self.deploy_tcp_port_index(),
            &DEPLOY_TCP_PORTS,
            false,
        ));
        advanced.push(muted(
            "服务器上已有兼容连接时沿用原端口；这里只在首次准备时使用。",
        ));
        advanced.push(field_label("TCP 握手目标"));
        advanced.push(input(
            "server-name",
            "DeployServerName",
            "TCP 握手目标",
            &self.deploy_server_name,
            200,
        ));
        advanced.push(muted(
            "兼容连接用它做 TLS 握手伪装；填一个真实存在、支持 TLS 1.3 的域名（默认 www.bing.com）。",
        ));
        body.push(details("deploy-advanced", "高级部署设置", advanced, false));

        // 8. 服务器要求与购买建议（旧版的 `$requirements` 展开区，文案取原文）。
        let requirements = vec![
            json!({"Kind":"text","Text":"推荐 Ubuntu 24.04 或 Debian 13（x64）的云服务器，使用 root 或有 sudo 权限的账户。"}),
            muted("选择完整 VPS；不选共享 NAT、仅 IPv6 或受限容器。"),
            muted("取得公网 IPv4、SSH 账户和密码或私钥；应具备管理员安装权限。"),
            muted("确认厂商有控制台等恢复入口，允许所需 UDP/TCP 入站。"),
        ];
        body.push(details(
            "deploy-requirements",
            "服务器要求与购买建议",
            requirements,
            false,
        ));

        // 9. 底部：两个按钮（旧版的 `DeploymentActions`）。
        //    r105：原来按钮上方那句「部署会自动完成安装、配置和检查。完成后可从首页
        //    连接新线路。」并进「开始部署」的 `Hint`——它是**按下去会发生什么**，
        //    挂在按钮上比铺在页面底部更贴题（正文少一行，动作本身更突出）。
        let busy = self.deploy_step == 5;
        body.push(row(vec![
            with_hint(
                button("start", "DeployStart", "开始部署", "primary", busy),
                "部署会自动完成安装、配置和检查；完成后从首页连接新线路。",
            ),
            button("back", "PageBack", "返回上一页", "ghost", false),
        ]));
        if busy {
            body.push(muted("正在核对服务器身份…"));
            body.push(muted(
                "这一步只读一次服务器的主机公钥：不发送密码，也不改动服务器。",
            ));
        }
        // 已经读到指纹（用户看得见的那一页不变，只是多了这一行事实）。
        if !self.deploy_fingerprint.is_empty() && !busy {
            body.push(muted(&format!("SSH 指纹：{}", self.deploy_fingerprint)));
        }
        if failed || !self.deploy_notice.is_empty() {
            body.push(text_tone(&self.deploy_notice, "warn"));
        }
        if !discard.is_empty() {
            body.push(row(discard));
        }
        self.deploy_page(body)
    }

    /// 这一页的外壳。**不要 PageActions**：前端把它渲染成一个吸底的独立容器，
    /// 只放一个「返回」就是页面下方一块突兀的空白卡片。返回由页面里的
    /// 「返回上一页」与面包屑共同承担。
    fn deploy_page(&self, body: Vec<Value>) -> Value {
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "home",
            "Generation": self.generation,
            "Title": "自己搭服务器",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [],
            "Actions": [],
        })
    }

    /// 本次登录方式给命令层的取值：`"password"` / `"key"`（与 `CredentialKind` 一致）。
    fn deploy_login_method(&self) -> &'static str {
        if self.deploy_login == 1 {
            "key"
        } else {
            "password"
        }
    }

    /// 默认连接方式给命令层的取值：`"Auto"` / `"Udp"` / `"Tcp"`。
    fn deploy_transport_word(&self) -> &'static str {
        match self.deploy_transport {
            1 => "Udp",
            2 => "Tcp",
            _ => "Auto",
        }
    }

    /// TCP 端口在当前候选里的下标（表外值按默认 443 显示）。
    fn deploy_tcp_port_index(&self) -> usize {
        let port = self.deploy_tcp_port.trim();
        DEPLOY_TCP_PORTS
            .iter()
            .position(|(id, _)| *id == port)
            .unwrap_or(0)
    }

    /// 地址/账户/端口改了：上一次读到的指纹与两个凭据勾的可用性都过期了。
    ///
    /// 不重绘（`change` 里重绘会吞掉后续输入）；下一次点「开始部署」自然会 probe。
    fn deploy_invalidate_probe(&mut self) {
        self.deploy_step = 0;
        self.deploy_fingerprint.clear();
        self.deploy_probed_spec.clear();
        self.deploy_followup = None;
        self.deploy_saved_available = false;
        self.deploy_task_available = false;
    }

    /// 兼容连接三格的页面判据（只碰非秘密）。后端仍会再判一次——页面这一道
    /// 只是为了在「读指纹之前」就把话说清楚，不必等一个网络往返。
    fn deploy_transport_precheck(&self) -> Result<(), String> {
        if !DEPLOY_TCP_PORTS
            .iter()
            .any(|(id, _)| *id == self.deploy_tcp_port.trim())
        {
            return Err("TCP 首选端口仅支持 443、8443、2443。".into());
        }
        let name = self.deploy_server_name.trim();
        if !crate::deploy::is_tls_server_name(name) {
            return Err(format!(
                "TCP 握手目标必须是一个域名（例如 www.bing.com），收到 {name}。"
            ));
        }
        Ok(())
    }

    /// 私钥模式的两条页面判据（只碰**非秘密**：路径是否为空、文件在不在）。
    ///
    /// 不读文件内容、不解析口令——那是后端 `ipc::credential_from_key_file` 的事，
    /// 页面抢着做只会出现两份判据。密码模式直接放行（空密码由命令层按三档凭据判）。
    fn deploy_key_precheck(&self) -> Result<(), String> {
        if self.deploy_login != 1 {
            return Ok(());
        }
        let path = self.deploy_key_path.trim();
        if path.is_empty() {
            return Err("请选择 SSH 私钥文件；服务器密码与私钥口令分别填写。".into());
        }
        if !std::path::Path::new(path).is_file() {
            return Err(format!(
                "找不到这个私钥文件：{path}。请重新选择，或改用服务器密码登录。"
            ));
        }
        Ok(())
    }

    /// 「开始部署」那一步要发的命令（宿主在读指纹回来之后调用）。
    ///
    /// 顺序不能反：`deployment-draft-save` 先（带 runId + 指纹），再
    /// `deployment-start`（同一个 runId，复用那条草稿）。反了就成了
    /// 「先投递、草稿里还留着空指纹」。
    ///
    /// 密码在这一刻离开表单内存：之后任何一帧快照里都不会再有它。
    pub fn deploy_start_steps(&mut self) -> Vec<Step> {
        // 云端没放行就别发命令：这条判定必须**早于**任何落盘/投递。
        // 旧版是把「开始部署」置灰（`LinuxApply.IsEnabled`），这里改成点了才拦：
        // 宿主渲染的按钮要用 disabled 就得重绘，而重绘会让下一次 `change` 撞上
        // `Generation` 闸门（r87 的同一个坑）。拦截的说法比灰按钮更清楚，也不丢输入。
        if !self.deploy_cloud {
            self.deploy_notice =
                "请先核对云端已放行部署端口（UDP 入站，并保留 SSH 入口），再开始部署。".into();
            self.restructure();
            return Vec::new();
        }
        let spec = match deploy_compose_target(&self.deploy_spec, &self.deploy_user, &self.deploy_port)
        {
            Ok(spec) => spec,
            Err(message) => {
                self.deploy_step = 0;
                self.deploy_notice = message;
                self.restructure();
                return Vec::new();
            }
        };
        // 与点「开始部署」时**同一条判据**：读指纹那一秒里文件可能被删/被移走，
        // 真正要动服务器之前必须再看一眼（只碰非秘密：路径存在性）。
        if let Err(message) = self.deploy_key_precheck() {
            self.deploy_step = 0;
            self.deploy_notice = message;
            self.restructure();
            return Vec::new();
        }
        // 与点「开始部署」时同一条判据：读指纹那一秒里用户可能把端口改成了
        // 不支持的值（页面不重绘，值仍在），真正要落盘之前再看一眼。
        if let Err(message) = self.deploy_transport_precheck() {
            self.deploy_step = 0;
            self.deploy_notice = message;
            self.restructure();
            return Vec::new();
        }
        let mut save = vec![
            ("spec", json!(spec)),
            ("fingerprint", json!(self.deploy_fingerprint)),
            ("label", json!(self.deploy_label.trim())),
            ("remember", json!(self.deploy_remember_saved)),
            ("rememberTask", json!(self.deploy_remember_task)),
            ("loginMethod", json!(self.deploy_login_method())),
            ("identityFile", json!(self.deploy_key_path.trim())),
            ("transport", json!(self.deploy_transport_word())),
            ("tcpPort", json!(self.deploy_tcp_port.trim())),
            ("serverName", json!(self.deploy_server_name.trim())),
            // 草稿也带上这两个勾（当前后端不落盘；「接着填」时页面按默认 true 重来）。
            ("useSaved", json!(self.deploy_use_saved)),
            ("useTask", json!(self.deploy_use_task)),
        ];
        let mut start = vec![
            ("spec", json!(spec)),
            ("fingerprint", json!(self.deploy_fingerprint)),
            ("label", json!(self.deploy_label.trim())),
            ("remember", json!(self.deploy_remember_saved)),
            ("rememberTask", json!(self.deploy_remember_task)),
            ("loginMethod", json!(self.deploy_login_method())),
            ("identityFile", json!(self.deploy_key_path.trim())),
            ("transport", json!(self.deploy_transport_word())),
            ("tcpPort", json!(self.deploy_tcp_port.trim())),
            ("serverName", json!(self.deploy_server_name.trim())),
            // r95：两个「使用已保存凭据」的勾。只影响信封那两档，typed 口令永远优先。
            ("useSaved", json!(self.deploy_use_saved)),
            ("useTask", json!(self.deploy_use_task)),
        ];
        if !self.deploy_draft_id.is_empty() {
            save.push(("runId", json!(self.deploy_draft_id)));
            start.push(("runId", json!(self.deploy_draft_id)));
        }
        if !self.deploy_password.is_empty() {
            start.push(("password", json!(self.deploy_password)));
        }
        self.deploy_password.clear();
        self.deploy_notice.clear();
        self.deploy_step = 2;
        self.restructure();
        vec![
            Step::Sync(cmd("deployment-draft-save", &save)),
            Step::Sync(cmd("deployment-start", &start)),
        ]
    }

    /// 读指纹之后的下一步（一次性取走）。宿主拿它决定「直接开始」还是「先问身份」。
    pub fn take_deploy_followup(&mut self) -> Option<DeployFollowUp> {
        self.deploy_followup.take()
    }

    /// 「确认首次服务器身份」对话框的内容（旧版的`OpenDialog` 的三个字段）。
    pub fn deploy_identity_dialog(&self) -> Value {
        let (user, host, port) =
            deploy_split_target(&self.deploy_spec, &self.deploy_user, &self.deploy_port);
        json!({
            "Id": "deploy-identity-confirm",
            "Title": "确认首次服务器身份",
            "Body": format!("目标：{user}@{host}:{port}\nSSH 指纹：{}", self.deploy_fingerprint),
            "Note": "请通过云控制台等可信来源确认指纹。没有可信来源时，继续即表示你决定首次信任此服务器。关闭窗口不会登录。",
            "Confirm": "确认指纹并信任",
            "Cancel": "取消",
            "Danger": true,
            "Details": "",
            "Progress": false,
            "Scope": "deploy-identity",
            "Target": "",
        })
    }

    /// 部署任务详情：**一切来自记录**，不重算。
    ///
    /// 为什么不再算一遍：任务名、`N/4`、原因、主动作都由 `deployrun::project_*` /
    /// `run_view` 算好，列表页用的也是同一份。这里若再推一次，就会出现
    /// 「列表说核对、详情说重试」——而用户只会相信自己眼睛看到的那一个。
    fn render_deploy_run(&self) -> Value {
        let run = &self.deploy_run;
        let state = run.get("State").and_then(Value::as_str).unwrap_or("");
        let next_action = run.get("NextAction").and_then(Value::as_str).unwrap_or("");
        let running = run.get("Running").and_then(Value::as_bool).unwrap_or(false);
        let can_background = run
            .get("CanBackground")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let done = run.get("StepsDone").and_then(Value::as_u64).unwrap_or(0);
        let terminal = matches!(state, "Complete" | "Cancelled");
        let state_word = deploy_state_word(state);

        let mut body: Vec<Value> = Vec::new();
        body.push(muted(&format!(
            "状态：{state_word}　进度：{done}/4 步{}",
            if running { "　（正在跑）" } else { "" }
        )));
        if !self.deploy_run_id.is_empty() {
            body.push(muted(&format!(
                "任务编号 {}",
                run.get("RunShort").and_then(Value::as_str).unwrap_or("—")
            )));
        }

        // 身份：TOFU（没人工核对、按设置自动记住）**替用户做了一次决定**，
        // 这一页必须说清是哪一枚指纹被记下了。以前 `Identity.AutoTrusted` 只写进
        // 记录、谁也读不到，用户看到的只有「部署完成」——好像身份是核对过的。
        let identity = run.get("Identity");
        let auto_trusted = identity
            .and_then(|value| value.get("AutoTrusted"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if auto_trusted {
            let fingerprint = identity
                .and_then(|value| value.get("Fingerprint"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            body.push(text_tone(
                &format!(
                    "身份：这台服务器的指纹是这次自动记住的（{}）。\
                     下次连接会按它核对；对不上会拒绝连接。",
                    if fingerprint.is_empty() { "—" } else { fingerprint }
                ),
                "warn",
            ));
        }

        // 四步清单（旧版的`DeployFourSteps`）：**横排一行**，状态词来自记录里的
        // `Status`，表外值一律说「未核实」。用 `row` 而不是竖排：旧版是 WrapPanel，
        // 窄窗口自动换行；颜色只做辅助，状态词本身必须在。
        if let Some(steps) = run.get("Steps").and_then(Value::as_array) {
            let cells: Vec<Value> = steps
                .iter()
                .map(|step| {
                    let index = step.get("Index").and_then(Value::as_u64).unwrap_or(0) + 1;
                    let name = step.get("Name").and_then(Value::as_str).unwrap_or("");
                    let status = step.get("Status").and_then(Value::as_str).unwrap_or("");
                    let tone = match status {
                        "Failed" => "bad",
                        "Pending" | "Skipped" | "Unknown" | "" => "muted",
                        _ => "",
                    };
                    text_tone(
                        &format!("{index} {name} · {}", deploy_step_word(status)),
                        tone,
                    )
                })
                .collect();
            if !cells.is_empty() {
                body.push(row(cells));
            }
        }

        // 技术详情与本次端口规则（旧版的`DeployTechnicalDetails`）：
        // 这里只列**记录里有的非秘密事实**，不重新推导。端口规则就是这次实际
        // 会用的那几个（UDP 入站 + TCP 兼容连接 + SSH 管理入口）。
        let plan = run.get("Plan").cloned().unwrap_or(Value::Null);
        let plan_text = |key: &str| {
            plan.get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let plan_port = |key: &str| {
            plan.get(key)
                .and_then(Value::as_u64)
                .filter(|value| *value > 0)
                .map(|value| value.to_string())
                .unwrap_or_default()
        };
        let transport_word = match plan_text("Transport").as_str() {
            "Tcp" => "兼容连接",
            "Udp" => "标准连接",
            _ => "自动选择",
        };
        // Step2 的证据是**服务器上实际生效**的兼容连接参数（已有身份时可能沿用旧端口），
        // 有就用它；没有才回落到这次计划里的选择。
        let step2_evidence = run
            .get("Steps")
            .and_then(Value::as_array)
            .and_then(|steps| steps.get(2))
            .and_then(|step| step.get("Evidence"))
            .cloned()
            .unwrap_or(Value::Null);
        let evidence_text = |key: &str| {
            step2_evidence
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let tcp_port = {
            let actual = step2_evidence
                .get("port")
                .and_then(Value::as_u64)
                .filter(|value| *value > 0)
                .map(|value| value.to_string())
                .unwrap_or_default();
            if !actual.is_empty() {
                actual
            } else {
                let port = plan_port("TcpPort");
                if port.is_empty() {
                    crate::deploy::TRANSPORT_PORT.to_string()
                } else {
                    port
                }
            }
        };
        let server_name = {
            let actual = evidence_text("serverName");
            if !actual.is_empty() {
                actual
            } else {
                let name = plan_text("ServerName");
                if name.is_empty() {
                    crate::deploy::TRANSPORT_SERVER_NAME.to_string()
                } else {
                    name
                }
            }
        };
        let udp_port = {
            let port = plan_port("UdpPort");
            if port.is_empty() {
                crate::deploy::DEFAULT_PORT.to_string()
            } else {
                port
            }
        };
        let interface = {
            let name = plan_text("Interface");
            if name.is_empty() {
                "—".to_string()
            } else {
                name
            }
        };
        let fingerprint = identity
            .and_then(|value| value.get("Fingerprint"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let mut technical: Vec<Value> = Vec::new();
        technical.push(muted(&format!(
            "默认连接方式：{transport_word}（标准与兼容连接都会准备）"
        )));
        technical.push(muted(&format!("WireGuard 接口：{interface}")));
        technical.push(muted(&format!("UDP 入站端口：{udp_port}")));
        technical.push(muted(&format!(
            "TCP 兼容连接：{tcp_port}，握手域名 {server_name}"
        )));
        technical.push(muted(&format!(
            "SSH 管理入口：{}:{}（保留，不随部署关闭）",
            run.get("Target")
                .and_then(|target| target.get("Host"))
                .and_then(Value::as_str)
                .unwrap_or("—"),
            run.get("Target")
                .and_then(|target| target.get("Port"))
                .and_then(Value::as_u64)
                .unwrap_or(22)
        )));
        if !fingerprint.is_empty() {
            technical.push(muted(&format!("服务器 SSH 指纹：{fingerprint}")));
        }
        if let Some(summary) = run.get("Summary").and_then(Value::as_str) {
            if !summary.trim().is_empty() {
                technical.push(muted(&format!("诊断摘要：{summary}")));
            }
        }
        body.push(details(
            "deploy-technical",
            "技术详情与本次端口规则",
            technical,
            false,
        ));

        // 原因：这是这一页最该被看见的一行。
        if let Some(reason) = run.get("Reason").filter(|value| !value.is_null()) {
            let text = reason.get("Text").and_then(Value::as_str).unwrap_or("");
            let category = reason.get("Category").and_then(Value::as_str).unwrap_or("");
            if !text.is_empty() {
                let tone = match category {
                    "OutcomeUnknown" | "NeedsRecovery" | "AccessRequired" | "Partial" => "warn",
                    _ => "muted",
                };
                body.push(text_tone(text, tone));
            }
        }

        // 尝试历史（P1-4）：只读。放在原因之后——先看「为什么停」，
        // 再看「这是第几次、前几次怎么结束的」。
        body.extend(attempt_history(run, running));

        // 决策说明（旧版的`DeployDecisionMessage`）：一句「现在能做什么」。
        // **不重复按钮文案**：按钮已经写着动作，这里说的是动作之后的去向。
        let decision = match state {
            "Complete" => "准备完成：可以从首页或线路页连接这条线路；连接方式随时可在线路里切换。",
            "Cancelled" => "这次部署已取消；已经装到服务器上的部分保留，不会影响现有连接。",
            "NeedsAttention" => "这一步的结果需要你先核对；核对之前不会重发任何写命令。",
            "WaitingUser" => "正在等你的输入或确认；补齐之后会从停下的那一步继续。",
            "Paused" => "已暂停：已经完成的步骤不会重做，继续时从下一步开始。",
            _ => "",
        };
        if !decision.is_empty() {
            body.push(muted(decision));
        }

        // 这里**不**再复述 `ActionLabel`：它是任务行/底部队列上那个动作（「打开这一页」），
        // 与这一页里的按钮（「在这一页里做什么」）不是同一件事。两句话挨在一起时
        // 只会让人问「到底按哪个」。按钮自己说明下一步。

        // 需要凭据时给输入框；密码只留内存，render 从不回填（只报「已填写」）。
        if next_action == "EnterCredentials" {
            body.push(secret(
                "run-password",
                "DeployRunPassword",
                "服务器登录密码",
                !self.deploy_password.is_empty(),
                200,
            ));
            body.push(muted(
                "密码只用于这次登录，之后封存在本机，不会写进任何日志。",
            ));
        }

        if state == "Paused" {
            body.push(muted(
                "已暂停：现在没有在写服务器。点「继续部署」会从下一步接着做。",
            ));
        }
        if self.deploy_pause_pending {
            body.push(text_tone(
                "已请求暂停：当前步骤做完之后生效。已经发出的写命令不会被打断。",
                "warn",
            ));
        }

        let mut actions: Vec<Value> = Vec::new();
        if !terminal {
            let (_, text) = deploy_primary(run);
            if !text.is_empty() {
                // 正在跑的时候主按钮禁用：点下去也只会被幂等逻辑吞掉，
                // 留一个能点的按钮等于骗人。
                actions.push(button("run-go", "DeployRunGo", text, "primary", running));
            }
            // 只有引擎里真有这一步在跑才给暂停：暂停是「做完这步再停」，
            // 没有在跑的步骤时按它只会被命令层拒绝。
            if running && !self.deploy_cancel_pending && !self.deploy_pause_pending {
                actions.push(button(
                    "run-pause",
                    "DeployRunPause",
                    "暂停部署",
                    "ghost",
                    false,
                ));
            }
        } else {
            actions.push(button("done", "DeployDone", "完成", "primary", false));
        }
        if can_background {
            actions.push(button(
                "run-background",
                "DeployRunBackground",
                "后台继续",
                "ghost",
                false,
            ));
        }
        if !terminal && !self.deploy_cancel_pending {
            actions.push(button(
                "run-cancel",
                "DeployRunCancel",
                "取消这次部署",
                "ghost",
                false,
            ));
        }
        // 导出诊断摘要（P2-3）：**只读**，任何状态都给——失败时最需要它。
        // 导出的是本机记录的白名单投影，不含秘密；写的是数据根 `logs\exports\`。
        actions.push(button(
            "run-export",
            "DeployRunExport",
            "导出诊断摘要",
            "ghost",
            false,
        ));
        // 归档 / 恢复（P2-2）：**归档不是删除**。只给「已经停下来」的记录——
        // 把一条在跑的任务藏起来，等于让用户失去对它唯一的入口。
        let archived = run
            .get("ArchivedAtUtc")
            .map(|value| !value.is_null())
            .unwrap_or(false);
        if archived {
            actions.push(button(
                "run-unarchive",
                "DeployRunUnarchive",
                "恢复这条记录",
                "ghost",
                false,
            ));
        } else if terminal || matches!(state, "NeedsAttention" | "Paused") {
            actions.push(button(
                "run-archive",
                "DeployRunArchive",
                "归档",
                "ghost",
                false,
            ));
        }
        if running && !self.deploy_pause_pending {
            body.push(muted(
                "暂停只在步骤之间生效：已经发出的写命令不会被打断。",
            ));
        }
        if !actions.is_empty() {
            body.push(row(actions));
        }

        // 表单内二次确认：取消是不可撤销的，点一下就执行是回归。
        if self.deploy_cancel_pending {
            body.push(text_tone(
                if run_holds_pending_write(run) {
                    // 已经发出的写命令不能中断：中断会留下「可能写了、也没人核对」的现场。
                    "取消会在这一步做完并核对完之后生效：已经发出的写命令不能中断。"
                } else {
                    "取消之后这条记录不能再继续，已经装到服务器上的部分会留在那里。"
                },
                "warn",
            ));
            body.push(row(vec![
                button(
                    "run-cancel-confirm",
                    "DeployRunCancelConfirm",
                    "确认取消",
                    "danger",
                    false,
                ),
                button("run-cancel-back", "DeployRunCancelBack", "不取消", "ghost", false),
            ]));
        }

        if !self.deploy_notice.is_empty() {
            body.push(text_tone(&self.deploy_notice, "warn"));
        }
        if terminal {
            body.push(muted("这次部署已经结束，只能查看。"));
        }

        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "home",
            "Generation": self.generation,
            // 标题用 `Name`（记录上的名字），**不能用 `Label`**：那是进度标签
            //（「0/4 · 检查服务器环境与身份：连不上服务器…」），拿来当标题是两行大字。
            "Title": run.get("Name").and_then(Value::as_str).unwrap_or("部署任务"),
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [],
            "Actions": [],
        })
    }

    /// 「服务器与设备」：只读。服务器信息 + 隧道状态 + 每台设备。
    ///
    /// 这一页回答的是「这台服务器上现在接了哪些电脑」——旧版的对应页有
    /// 邀请/改名/撤销/卸载，那些都要写操作；这一版先把**只读**这部分做实，
    /// 因为它是用户最先想确认的事，也是排障时唯一必须的信息。
    fn render_devices(&self) -> Value {
        let mut body: Vec<Value> = Vec::new();
        if self.devices.is_null() {
            body.push(muted("正在读取服务器与设备…"));
            body.push(muted("这一步只读：不改服务器、不动当前连接。"));
        } else if let Some(error) = self.devices.get("error").and_then(Value::as_str) {
            body.push(text_tone("读不到设备列表。", "warn"));
            body.push(muted(error));
            body.push(row(vec![button(
                "refresh",
                "DevicesRefresh",
                "重新读取",
                "primary",
                false,
            )]));
        } else {
            let server = self.devices.get("server").cloned().unwrap_or(Value::Null);
            let field = |key: &str| {
                server
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let port = server.get("port").and_then(Value::as_u64).unwrap_or(22);
            let udp = server.get("udpPort").and_then(Value::as_u64).unwrap_or(0);
            // 标题带上线路名：用户是从某条线路进来的，先确认「看到的是不是这台服务器」。
            if !field("name").is_empty() {
                body.push(json!({"Kind":"text","Level":3,"Text":field("name")}));
            }
            if !self.notice.is_empty() {
                body.push(text_tone(&self.notice, self.notice_tone));
            }
            body.push(muted(&format!(
                "服务器：{}@{}:{}（接口 {}，UDP {}，网段 {}）",
                field("user"),
                field("host"),
                port,
                field("interface"),
                udp,
                field("subnet")
            )));
            body.push(muted(&format!("主机指纹：{}", field("fingerprint"))));

            let tunnel_up = self
                .devices
                .get("tunnel")
                .and_then(|tunnel| tunnel.get("up"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match self.devices.get("tunnel").filter(|value| !value.is_null()) {
                None => body.push(text_tone(
                    "隧道：接口不存在（服务没起来）。",
                    "warn",
                )),
                Some(tunnel) => {
                    let up = tunnel.get("up").and_then(Value::as_bool).unwrap_or(false);
                    if !up {
                        body.push(text_tone("隧道：接口不存在（服务没起来）。", "warn"));
                    } else {
                        let handshake = tunnel
                            .get("latestHandshake")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                        let rx = tunnel.get("rxBytes").and_then(Value::as_u64).unwrap_or(0);
                        let tx = tunnel.get("txBytes").and_then(Value::as_u64).unwrap_or(0);
                        body.push(muted(&format!(
                            "隧道：运行中，{}，合计收 {} / 发 {}",
                            ago_text(handshake),
                            bytes_text(rx),
                            bytes_text(tx)
                        )));
                    }
                }
            }

            body.push(json!({"Kind":"rule"}));
            let devices = self
                .devices
                .get("devices")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            // 撤销确认层：撤销不可逆，先问一次。放在清单上方，别让人没看见就点了确认。
            if let Some(pending) = self.pending_revoke.clone() {
                let address = devices
                    .iter()
                    .find(|device| {
                        device.get("publicKey").and_then(Value::as_str) == Some(pending.as_str())
                    })
                    .and_then(|device| device.get("address").and_then(Value::as_str))
                    .unwrap_or("这台设备");
                body.push(text_tone(&format!("确定移除设备 {address} 吗？"), "warn"));
                body.push(muted(
                    "它会立刻失去访问权，要重新加入才能恢复。这台电脑与其它设备不受影响。",
                ));
                body.push(row(vec![
                    button("revoke-confirm", "RevokeConfirm", "确认移除", "danger", false),
                    button("revoke-cancel", "RevokeCancel", "取消", "ghost", false),
                ]));
                body.push(json!({"Kind":"rule"}));
            }
            // 服务没起来时设备清单根本读不到：不写「0 台」，那会被读成「一台都没接」。
            let listed: &[Value] = if tunnel_up { &devices } else { &[] };
            if tunnel_up {
                body.push(muted(&format!("已登记的设备（{} 台）", devices.len())));
                if devices.is_empty() {
                    body.push(muted("这台服务器上还没有任何设备。"));
                }
            } else {
                body.push(muted("服务没起来，读不到设备清单。"));
            }
            let names_available = self
                .devices
                .get("namesAvailable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if tunnel_up && !names_available {
                body.push(muted(
                    "这台服务器没有可用的设备命名服务（还没安装邀请服务），设备改名暂不可用。",
                ));
            }
            for (index, device) in listed.iter().enumerate() {
                let address = device.get("address").and_then(Value::as_str).unwrap_or("");
                let name = device.get("name").and_then(Value::as_str).unwrap_or("");
                let key = device.get("shortKey").and_then(Value::as_str).unwrap_or("");
                let mine = device.get("thisDevice").and_then(Value::as_bool).unwrap_or(false);
                let handshake = device.get("handshake").and_then(Value::as_i64).unwrap_or(0);
                let rx = device.get("rxBytes").and_then(Value::as_u64).unwrap_or(0);
                let tx = device.get("txBytes").and_then(Value::as_u64).unwrap_or(0);
                let endpoint = device.get("endpoint").and_then(Value::as_str).unwrap_or("");
                let title = if name.is_empty() {
                    format!("设备 {address}")
                } else {
                    format!("设备 {name}（{address}）")
                };
                body.push(muted(&format!(
                    "{title}{}",
                    if mine { "（本机）" } else { "" }
                )));
                let seen = if endpoint.is_empty() || endpoint == "(none)" {
                    String::new()
                } else {
                    format!("，对端 {endpoint}")
                };
                body.push(muted(&format!(
                    "  {key}… · {} · 收 {} / 发 {}{seen}",
                    ago_text(handshake),
                    bytes_text(rx),
                    bytes_text(tx)
                )));
                if self.pending_revoke.is_some() {
                    continue;
                }
                // 改名输入框：只替换这一行的按钮，其它设备照常显示。
                if self.device_rename_index == Some(index) {
                    body.push(input("name", "DeviceName", "新名称", &self.draft, 64));
                    body.push(row(vec![
                        button(
                            "save-device-rename",
                            "DeviceRenameSave",
                            "保存名称",
                            "primary",
                            false,
                        ),
                        button(
                            "cancel-device-rename",
                            "DeviceRenameCancel",
                            "取消",
                            "ghost",
                            false,
                        ),
                    ]));
                    continue;
                }
                let full_key = device.get("publicKey").and_then(Value::as_str).unwrap_or("");
                let mut actions = Vec::new();
                if names_available && !full_key.is_empty() {
                    actions.push(button(
                        &format!("device-rename:{index}"),
                        "DeviceRename",
                        "改名",
                        "ghost",
                        false,
                    ));
                }
                // 本机那一行不给「移除」：撤销自己等于把用户锁在外面。
                if !mine && !full_key.is_empty() {
                    actions.push(button(
                        &format!("revoke-{index}"),
                        "RevokeDevice",
                        "移除",
                        "ghost",
                        false,
                    ));
                }
                if !actions.is_empty() {
                    body.push(row(actions));
                }
            }
            // 已撤销设备留下的名称记录：peer 已经不在了，名字还挂在服务器上。
            // 只在隧道读到、命名服务可用时列——否则「孤儿」是算不准的。
            let orphans = self
                .devices
                .get("orphanNames")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if tunnel_up && names_available && !orphans.is_empty() {
                body.push(json!({"Kind":"rule"}));
                body.push(muted(&format!(
                    "已撤销设备的名称记录（{} 条）",
                    orphans.len()
                )));
                body.push(muted(
                    "这些设备已经不在隧道上，只是服务器上还留着名字。删除记录不会影响任何在线设备。",
                ));
                if let Some(pending) = self.pending_forget.clone() {
                    let label = orphans
                        .iter()
                        .find(|orphan| {
                            orphan.get("publicKey").and_then(Value::as_str)
                                == Some(pending.as_str())
                        })
                        .map(orphan_label)
                        .unwrap_or_else(|| "这条记录".to_string());
                    body.push(text_tone(&format!("确定删除「{label}」吗？"), "warn"));
                    body.push(muted("只删服务器上的名称记录，不触碰隧道与邀请审计。"));
                    body.push(row(vec![
                        button(
                            "forget-confirm",
                            "ForgetDeviceRecord",
                            "删除记录",
                            "danger",
                            false,
                        ),
                        button(
                            "forget-cancel",
                            "ForgetDeviceRecordCancel",
                            "取消",
                            "ghost",
                            false,
                        ),
                    ]));
                } else {
                    for (index, orphan) in orphans.iter().enumerate() {
                        let updated = orphan
                            .get("updatedAtUtc")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let seen = if updated.is_empty() {
                            String::new()
                        } else {
                            format!(" · 更新于 {}", updated.chars().take(19).collect::<String>())
                        };
                        body.push(muted(&format!("记录 {}{seen}", orphan_label(orphan))));
                        body.push(row(vec![button(
                            &format!("forget-{index}"),
                            "ForgetDeviceRecord",
                            "删除记录",
                            "ghost",
                            false,
                        )]));
                    }
                }
            }
            // 卸载通道服务：预览只读，确认后才真执行。入口放在设备清单下方，
            // 因为它影响的是这台服务器上的所有设备，而不只是本机。
            body.push(json!({"Kind":"rule"}));
            if self.uninstall_running {
                body.push(muted("正在处理服务器上的通道服务…"));
            } else if self.uninstall_preview.is_null() {
                body.push(muted(
                    "卸载会停止并移除这台服务器上的通道服务与规则（WireGuard、兼容连接、系统服务）；保留审计与身份。",
                ));
                body.push(muted("卸载不会退订云服务器，云服务商仍会计费。"));
                body.push(row(vec![button(
                    "uninstall-preview",
                    "UninstallPreview",
                    "卸载这台服务器的通道服务…",
                    "danger",
                    false,
                )]));
            } else if let Some(error) = self
                .uninstall_preview
                .get("error")
                .and_then(Value::as_str)
            {
                body.push(text_tone("卸载预览读不出来。", "warn"));
                body.push(muted(error));
                body.push(row(vec![
                    button(
                        "uninstall-preview",
                        "UninstallPreview",
                        "重试预览",
                        "primary",
                        false,
                    ),
                    button("uninstall-cancel", "UninstallCancel", "取消", "ghost", false),
                ]));
            } else {
                let affected = self
                    .uninstall_preview
                    .get("AffectedDevices")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let eligible = self
                    .uninstall_preview
                    .get("Eligible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                body.push(json!({
                    "Kind": "text",
                    "Level": 3,
                    "Text": "卸载这台服务器的通道服务？",
                }));
                body.push(muted(&format!(
                    "影响设备：{affected} 台。将停止并移除这台服务器上的通道服务与规则；保留审计与身份。"
                )));
                for field in ["Warnings", "Blocked"] {
                    if let Some(items) = self.uninstall_preview.get(field).and_then(Value::as_array)
                    {
                        for item in items {
                            if let Some(text) = item.get("Message").and_then(Value::as_str) {
                                body.push(text_tone(text, "warn"));
                            }
                        }
                    }
                }
                let mut buttons = Vec::new();
                if eligible {
                    buttons.push(button(
                        "uninstall-confirm",
                        "UninstallConfirm",
                        "确认卸载",
                        "danger",
                        false,
                    ));
                }
                buttons.push(button(
                    "uninstall-cancel",
                    "UninstallCancel",
                    "取消",
                    "ghost",
                    false,
                ));
                body.push(row(buttons));
            }
            body.push(row(vec![button(
                "refresh",
                "DevicesRefresh",
                "刷新",
                "ghost",
                false,
            )]));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "lines",
            "Generation": self.generation,
            "Title": "服务器与设备",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [],
            "Actions": [],
        })
    }

    /// 「交易软件名单」（旧版的`ShowTradeApplicationManager`）。
    ///
    /// **两张卡**：程序 / 交易网站，各自一个输入框。旧版这一页只管理交易出口的
    /// 程序与网站；直连/日常规则仍留在配置里，但不在这页出现（旧版没有那两档）。
    fn render_split(&self) -> Value {
        let mut program_body = vec![
            json!({"Kind": "text", "Level": 2, "Text": "程序"}),
            muted("程序的全部连接使用交易线路；断开时阻止它直接联网。"),
        ];
        let mut programs = 0usize;
        for (index, item) in self.processes.iter().enumerate() {
            if item.get("target").and_then(Value::as_str) != Some("trade") {
                continue;
            }
            programs += 1;
            program_body.push(split_program_row(
                index,
                item,
                self.locate_index,
                self.locate_path.is_some(),
            ));
        }
        if programs == 0 {
            program_body.push(muted("尚未添加程序；下方的网站名单仍可使用。"));
        }
        program_body.push(json!({
            "Kind": "grid",
            "Columns": 3,
            "Cols": ["*", "Auto", "Auto"],
            "Children": [
                input(
                    "program-path",
                    "TradeProgramInput",
                    "把程序文件拖到这里，或点「浏览…」",
                    &self.program_path,
                    1024,
                ),
                button("pick-program", "BrowseTradeProgram", "浏览…", "ghost", false),
                button("add-program", "AddTradeProgram", "添加程序", "primary", false),
            ],
        }));
        program_body.push(muted(
            "把 .exe 拖进输入框会自动填入路径；桌面快捷方式会换成它指向的程序。",
        ));

        let mut site_body = vec![
            json!({"Kind": "text", "Level": 2, "Text": "交易网站"}),
            muted("只调整这些网站的线路，不会限制整个浏览器。"),
        ];
        let mut sites = 0usize;
        for (index, item) in self.domain_rules.iter().enumerate() {
            if item.get("target").and_then(Value::as_str) != Some("trade") {
                continue;
            }
            sites += 1;
            site_body.push(split_site_row(index, item));
        }
        if sites == 0 {
            site_body.push(muted("还没有添加网站"));
        }
        site_body.push(json!({
            "Kind": "grid",
            "Columns": 2,
            "Cols": ["*", "Auto"],
            "Children": [
                input(
                    "site-domain",
                    "TradeDomainInput",
                    "填写网址或域名，子域名会一并加入",
                    &self.draft,
                    1024,
                ),
                button("add-site", "AddTradeDomain", "添加网站", "primary", false),
            ],
        }));
        site_body.push(button(
            "reset-trade-domains",
            "ResetTradeDomains",
            "恢复默认网站",
            "ghost",
            false,
        ));

        let mut nodes = vec![card(program_body), card(site_body)];
        if !self.notice.is_empty() {
            nodes.push(muted(&self.notice));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "apps",
            "Generation": self.generation,
            "Title": "交易软件名单",
            "Description": "",
            "Nodes": nodes,
            // 旧版只有页首「← 返回应用」，没有页底返回按钮；面包屑由父页自动生成。
            "PageActions": [],
            "Actions": [],
        })
    }

    /// 「AI 工具名单」：一行一个工具，右边一颗就地切换的「添加 / 移除」按钮；
    /// 自定义程序/网站同一形状；保存 / 放弃修改 / 返回仍在页脚。
    ///
    /// 只用前端**已支持**的节点种类：`text / card / row / button / input / details`
    /// （逐个在 `web/app.js::formNode` 里核过）。新增节点种类要先改前端，本轮不动 `web/`。
    ///
    /// 三条交互事实写死在这里：
    /// 1. 点「添加 / 移除」只改宿主内存草稿 —— 页面即时响应，写命令次数为 0；
    /// 2. 只有「保存」发**一条** `agents-save`（全量提交，不是逐项提交）；
    /// 3. 没有「保存后移除 / 撤销移除」这种中间态：草稿里当场翻转，反悔靠「放弃修改」。
    ///
    /// 页面形状（r104）：**名单 + 一个可收起的全目录**。
    /// - 「名单内」那一段才分组（桌面程序 / 网页版 / 模型 API 与下载平台，空类别不出现）；
    /// - 没进名单的内置项全部收进一台 `details`（`添加其他工具（n）`），默认收起，
    ///   名单为空时自动展开——否则首屏只剩一行「添加其他工具」要点一下才知道有什么；
    /// - 每条的说明并进名称文本的 `Hint`（ⓘ），不再各占一行正文。
    /// 之前那个「添加常用 AI 工具」一键按钮（`recommend`）失效且与逐项添加重复，已删掉：
    /// 目录的用途是「挑几个」，不是「全都要」。
    fn render_agents(&self) -> Value {
        let mut body: Vec<Value> = Vec::new();
        // 旧版的 SectionLabel：**页面正文只留一句话**，长解释挂在提示气泡上。
        // r101 之前这里有四段说明（名单随交易线路走 / 走向重复 / 没有交易出口…），
        // 讲的是同一件事三遍，把 22 行名单压到了首屏之外——信息密度不是靠句子堆出来的。
        let mut intro = muted("选择要跟随线路的工具，改完点保存，一次生效。");
        if let Some(object) = intro.as_object_mut() {
            object.insert(
                "Hint".to_string(),
                json!(
                    "桌面程序按程序识别，它访问的网址都随之走；网页版只匹配浏览器（Chrome、Edge、Firefox 等）访问所列网址。走交易线路时，名单网址也经交易线路解析，避免拿到被污染的地址。"
                ),
            );
        }
        body.push(row(vec![intro]));
        // 状态行四档（连接中最优先）：只在「现在改这个有没有用」需要解释时占一行。
        body.push(text_tone(
            self.agents_status_line(),
            if self.agents_busy { "warn" } else { "muted" },
        ));

        // 名单内：**只列已经在草稿里**的内置项，按目录顺序分组（桌面程序 → 网页版 →
        // 模型 API 与下载平台）。条目数据全部来自回包（agents_entries，顺序即目录顺序）
        // ——渲染层不持有目录事实。空类别连标题都不出现：一行空的「桌面程序」只是噪音。
        // 分组下不再挂一句 `kind.note()`：每条的说明已经在名称的 `Hint` 里。
        let mut in_list_count = 0usize;
        for kind in [
            crate::agents::AgentKind::Program,
            crate::agents::AgentKind::Web,
            crate::agents::AgentKind::Service,
        ] {
            let entries: Vec<&AgentsEntryView> = self
                .agents_entries
                .iter()
                .filter(|e| self.agents_in_draft(&e.id) && e.kind == kind.id())
                .collect();
            if entries.is_empty() {
                continue;
            }
            in_list_count += entries.len();
            body.push(json!({"Kind":"text","Level":3,"Text":kind.group_label()}));
            for entry in entries {
                body.push(self.agents_builtin_row(entry, true));
            }
        }

        // 全目录：没进名单的内置项收进一台折叠区（旧版的 Expander），**平的**、按目录
        // 顺序。22 条全铺在首屏等于把「已经选了什么」埋掉；收起来之后名单才是页面的主体。
        // 名单为空时自动展开——否则一个工具都没选的人首屏只看到一行「添加其他工具」。
        let others: Vec<&AgentsEntryView> = self
            .agents_entries
            .iter()
            .filter(|e| !self.agents_in_draft(&e.id))
            .collect();
        if !others.is_empty() {
            let rows: Vec<Value> = others
                .iter()
                .map(|entry| self.agents_builtin_row(entry, false))
                .collect();
            body.push(details(
                "more-builtin",
                &format!("添加其他工具（{}）", others.len()),
                rows,
                in_list_count == 0,
            ));
        }

        // 分组 3：自定义（程序 + 网站）。行按「基线 ∪ 草稿 ∪ 本轮见过」列出来：移除是
        // **从草稿 Vec 里删掉**，只按草稿渲染的话整行会消失，就再也没有地方点「添加」
        // 把它加回来了；还没保存过的新增项靠 `agents_seen` 留住（否则「已存的能回来、
        // 刚加的不能」，同一个动作两种结果）。
        body.push(json!({"Kind":"text","Level":3,"Text":"自定义"}));
        for (index, value) in self.agents_custom_values("program").iter().enumerate() {
            body.push(self.agents_custom_row("program", index, value, "所有网址随之走"));
        }
        for (index, value) in self.agents_custom_values("site").iter().enumerate() {
            body.push(self.agents_custom_row("site", index, value, "所有程序访问它都随名单"));
        }

        // 添加区：网址走输入框 + 按钮；程序走既有文件选择器（选完直接进草稿，没有中间态）。
        // 例子（「例如 perplexity.ai」）挂在输入框的提示气泡上，不再占正文一行。
        body.push(muted("添加网站或程序"));
        let mut site = input("site", "AgentsSite", "网址", &self.agents_site_draft, 120);
        if let Some(object) = site.as_object_mut() {
            object.insert(
                "Hint".to_string(),
                json!("网址填域名即可，例如 perplexity.ai，其子域名一并生效。"),
            );
        }
        body.push(site);
        body.push(row(vec![
            button("add-site", "AgentsAddSite", "添加网址", "ghost", false),
            button("pick-program", "AgentsPickProgram", "添加程序…", "ghost", false),
        ]));

        let dirty_line = self.agents_dirty_line();
        if !dirty_line.is_empty() {
            body.push(text_tone(&dirty_line, "warn"));
        }
        if !self.agents_note.is_empty() {
            body.push(muted(&self.agents_note));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "apps",
            "Generation": self.generation,
            "Title": "AI 工具名单",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [
                // 没改动时保存没有意义；连接中保存一定会被拒，所以直接禁掉并留一句话。
                button("save", "AgentsSave", "保存", "primary", !self.agents_dirty() || self.agents_busy),
                button("discard", "AgentsDiscard", "放弃修改", "ghost", !self.agents_dirty()),
                button("back", "PageBack", "返回", "ghost", false),
            ],
            "Actions": [],
        })
    }

    /// 内置项那一行的文字：名称 + 运行徽标（旧版的 AgentPresence：运行中/已安装）。
    /// 「未检测到」不显示——一列灰字比没有信息更糟。
    fn entry_label(&self, entry: &AgentsEntryView) -> String {
        let badge = match entry.presence.as_str() {
            "running" => "（运行中）",
            "installed" => "（已安装）",
            _ => "",
        };
        format!("{}{}", entry.name, badge)
    }

    /// 这个目录项现在**在草稿里**吗（决定它在「名单内」那一段还是折叠区里）。
    fn agents_in_draft(&self, id: &str) -> bool {
        self.agents_builtin.iter().any(|kept| kept == id)
    }

    /// 内置项的一行：名称（说明与域名并进 `Hint`，见 `entry_hint`）+ 右对齐的一颗按钮。
    ///
    /// 已经在名单里 → 「移除」，不在 → 「添加」。两种状态**共用同一个 `Id`**
    /// （`builtin-<id>`），所以按钮不会在行里左右跳，行也不会因为换了一颗字就换身份。
    fn agents_builtin_row(&self, entry: &AgentsEntryView, in_list: bool) -> Value {
        let mut label = self.entry_label(entry);
        if self
            .agents_in_trade
            .iter()
            .any(|key| key == &in_trade_key("builtin", &entry.id))
        {
            label.push_str("（已在交易名单）");
        }
        let mut name_node = json!({"Kind":"text","Text":label});
        // 说明与域名清单一起挂在**名称文本节点**的 `Hint` 上：前端把 `Hint` 渲染成 ⓘ
        // （`hintFor(node, text)` 对 `text` 节点有效），悬停/点击才展开。
        // r104 之前 `detail` 是独立的一行 `muted(...)`：22 行正文说明把名单本身埋掉，
        // 而它们讲的是「这条是什么」——想问的人才会去看，不问的人不该付这份版面税。
        if let Some(hint) = entry_hint(entry) {
            if let Some(object) = name_node.as_object_mut() {
                object.insert("Hint".to_string(), json!(hint));
            }
        }
        row(vec![
            name_node,
            align_end(button(
                &format!("builtin-{}", entry.id),
                &builtin_action_name(&entry.id),
                if in_list { "移除" } else { "添加" },
                "ghost",
                false,
            )),
        ])
    }

    /// 自定义条目的一行：左边「值 · 说明」，右边「移除 / 添加」。
    /// 旧版的 `CustomAgentRow` 是同一形状（Grid 的 Auto 列放按钮）——以前这里拆成
    /// 「一行文字 + 一行按钮」，两条自定义就要占四行。
    ///
    /// 「移除」= 从草稿 Vec 里删掉这一项；行本身不会消失（见 `agents_custom_values`），
    /// 只是文字弱化、按钮变成「添加」。这一页因此没有「保存后移除」这种中间态。
    fn agents_custom_row(&self, kind: &str, index: usize, value: &str, what: &str) -> Value {
        let in_list = self.agents_custom_in_draft(kind, value);
        let mut line = format!("{value} · {what}");
        if self
            .agents_in_trade
            .iter()
            .any(|key| key == &in_trade_key(kind, value))
        {
            line.push_str("；已在交易名单");
        }
        let mut text = json!({"Kind":"text","Text":line});
        if !in_list {
            if let Some(object) = text.as_object_mut() {
                object.insert("Tone".to_string(), json!("muted"));
            }
        }
        row(vec![
            text,
            align_end(button(
                &format!("toggle-{kind}-{index}"),
                if kind == "program" {
                    "AgentsToggleProgram"
                } else {
                    "AgentsToggleSite"
                },
                if in_list { "移除" } else { "添加" },
                "ghost",
                false,
            )),
        ])
    }

    /// 自定义条目要列在页面上的那些值：**基线 ∪ 草稿 ∪ 本轮见过**（去重，基线序在前，
    /// 其余按进入顺序）。
    ///
    /// 为什么不是直接遍历草稿：移除是真的从草稿 Vec 里删掉，只按草稿渲染的话
    /// 「移除」之后整行消失，「添加」就无处可点。
    /// 为什么还要 `agents_seen`：新增项还没保存过时基线里也没有，光靠「基线 ∪ 草稿」
    /// 两边都会空——那就成了「已保存的能加回来、刚加的不能」两种结果，而它们是同一个动作。
    ///
    /// 索引即这个列表的下标，渲染时现算，每次重绘都跟着当次列表走，不会串位。
    fn agents_custom_values(&self, kind: &str) -> Vec<String> {
        let (base, draft) = if kind == "program" {
            (&self.agents_base.programs, &self.agents_programs)
        } else {
            (&self.agents_base.sites, &self.agents_sites)
        };
        let mut out: Vec<String> = Vec::new();
        let put = |out: &mut Vec<String>, value: &str| {
            if !out.iter().any(|kept| kept.eq_ignore_ascii_case(value)) {
                out.push(value.to_string());
            }
        };
        // ① 已保存的按服务端顺序（基线的顺序就是用户上次保存的样子）。
        for value in base.iter() {
            put(&mut out, value);
        }
        // ② 本轮新加的值按**进入顺序**接在后面：移除之后行不会跳到列表末尾。
        for (seen_kind, value) in &self.agents_seen {
            if seen_kind == kind {
                put(&mut out, value);
            }
        }
        // ③ 兜底：草稿里也可能有没经过 add-site / pick-exe 的值（残页、改包、一次性回填）。
        for value in draft.iter() {
            put(&mut out, value);
        }
        out
    }

    /// 记一笔「这个自定义值本轮进入过草稿」（见 `agents_seen`）。口径与
    /// `agents_custom_values` 一致：同 kind 下大小写不敏感去重。
    fn note_agent_seen(&mut self, kind: &str, value: &str) {
        let known = self
            .agents_seen
            .iter()
            .any(|(kept_kind, kept)| kept_kind == kind && kept.eq_ignore_ascii_case(value));
        if !known {
            self.agents_seen.push((kind.to_string(), value.to_string()));
        }
    }

    /// 这个自定义值现在**在草稿里**吗（决定按钮是「移除」还是「添加」）。
    fn agents_custom_in_draft(&self, kind: &str, value: &str) -> bool {
        let draft = if kind == "program" {
            &self.agents_programs
        } else {
            &self.agents_sites
        };
        draft.iter().any(|kept| kept.eq_ignore_ascii_case(value))
    }

    /// 状态行（PRD 6.2 连接中那句优先；§7.1 全局覆盖时名单随交易线路走）。
    fn agents_status_line(&self) -> &'static str {
        if self.agents_busy {
            return "正在连接，名单要断开后才能保存";
        }
        if self.agents_global_override && self.agents_trade_exit {
            // 日常上网本身已走交易线路：名单跟着交易线路走，走向不再能单独设置。
            return "日常上网走交易线路，名单随交易线路生效";
        }
        if !self.agents_trade_exit {
            // 没有交易出口 = 名单此刻一定不生效。这条以前是单独一段，现在并进状态行。
            return "这条线路没有交易出口，名单暂不生效";
        }
        if self.agents_lane == 1 {
            "名单当前走交易线路"
        } else {
            "名单当前跟随日常上网，暂不生效"
        }
    }

    /// 当前草稿（内置按目录顺序）。与 `agents_base` 比对得到「有没有改动」。
    fn current_agents_draft(&self) -> AgentsDraft {
        let mut builtin: Vec<String> = self.agents_builtin.clone();
        builtin.sort_by_key(|id| crate::agents::catalog_index(id).unwrap_or(usize::MAX));
        builtin.dedup();
        AgentsDraft {
            lane: if self.agents_lane == 1 {
                crate::config::AgentsLane::Trade
            } else {
                crate::config::AgentsLane::Daily
            },
            builtin,
            // 移除已经从 Vec 里删掉了，这里不再需要过滤任何标记。
            programs: self.agents_programs.clone(),
            sites: self.agents_sites.clone(),
        }
    }

    fn agents_dirty(&self) -> bool {
        self.current_agents_draft() != self.agents_base
    }

    /// 保存条那一句「已改 N 项」。N 的口径 = 与基线不同的条目数（走向算一项）。
    fn agents_dirty_line(&self) -> String {
        if !self.agents_dirty() {
            return String::new();
        }
        let now = self.current_agents_draft();
        let base = &self.agents_base;
        let mut count = usize::from(now.lane != base.lane);
        count += now.builtin.iter().filter(|id| !base.builtin.contains(id)).count();
        count += base.builtin.iter().filter(|id| !now.builtin.contains(id)).count();
        for (a, b) in [(&now.programs, &base.programs), (&now.sites, &base.sites)] {
            count += a.iter().filter(|v| !b.contains(v)).count();
            count += b.iter().filter(|v| !a.contains(v)).count();
        }
        format!("已改 {count} 项，尚未生效")
    }

    /// 现在离开这一页会丢掉什么。`None` = 可以安静地走。
    ///
    /// 只有**草稿式保存**的表单需要拦：AI 工具名单的添加、移除、自定义项都先在内存里改，
    /// 点「返回」等于把「已改 N 项」直接扔掉。其余表单（线路设置、部署、名单增删）
    /// 都是改一项就落一项，返回不丢东西——那些页面多问一句只会变成噪音。
    pub fn leave_warning(&self) -> Option<String> {
        if self.view != View::Agents || !self.agents_dirty() {
            return None;
        }
        Some(format!("{}；返回后这些改动会丢失。", self.agents_dirty_line()))
    }

    /// 回包 → 草稿与基线。`agents` 与 `agents-save` 共用这一份填充。
    fn fill_agents(&mut self, reply: &Value) {
        if let Some(agents) = reply.get("agents") {
            let lane = agents.get("lane").and_then(Value::as_str).unwrap_or("daily");
            self.agents_lane = if lane.eq_ignore_ascii_case("trade") { 1 } else { 0 };
            self.agents_trade_exit =
                agents.get("tradeExitPresent").and_then(Value::as_bool).unwrap_or(false);
            self.agents_busy = agents.get("busy").and_then(Value::as_bool).unwrap_or(false);
            self.agents_global_override =
                agents.get("globalOverride").and_then(Value::as_bool).unwrap_or(false);
        }
        self.agents_builtin.clear();
        self.agents_in_trade.clear();
        self.agents_entries.clear();
        if let Some(list) = reply.get("builtin").and_then(Value::as_array) {
            for item in list {
                let id = item.get("id").and_then(Value::as_str).unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                if item.get("checked").and_then(Value::as_bool) == Some(true) {
                    self.agents_builtin.push(id.to_string());
                }
                if item.get("inTradeList").and_then(Value::as_bool) == Some(true) {
                    self.agents_in_trade.push(in_trade_key("builtin", id));
                }
                self.agents_entries.push(AgentsEntryView {
                    id: id.to_string(),
                    kind: item.get("kind").and_then(Value::as_str).unwrap_or("program").to_string(),
                    name: item.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                    detail: item.get("detail").and_then(Value::as_str).unwrap_or("").to_string(),
                    domains: item
                        .get("domains")
                        .and_then(Value::as_array)
                        .map(|list| {
                            list.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                    presence: item
                        .get("presence")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
        for (key, into) in [("programs", &mut self.agents_programs), ("sites", &mut self.agents_sites)] {
            into.clear();
            if let Some(list) = reply.get(key).and_then(Value::as_array) {
                for item in list {
                    let value = item.get("value").and_then(Value::as_str).unwrap_or("");
                    if !value.is_empty() {
                        into.push(value.to_string());
                    }
                }
            }
        }
        // 「在交易名单里」的事实按顺序再收一遍（程序与网站分开取，键要带类型）。
        for (key, kind) in [("programs", "program"), ("sites", "site")] {
            if let Some(list) = reply.get(key).and_then(Value::as_array) {
                for item in list {
                    if item.get("inTradeList").and_then(Value::as_bool) != Some(true) {
                        continue;
                    }
                    if let Some(value) = item.get("value").and_then(Value::as_str) {
                        self.agents_in_trade.push(in_trade_key(kind, value));
                    }
                }
            }
        }
        // 新快照到手 = 这一轮的「见过」记忆过期：不清就会留下一条早已不存在的幽灵行。
        self.agents_seen.clear();
        self.agents_base = self.current_agents_draft();
    }

    fn render_providers(&self) -> Value {
        let mut body = vec![muted(
            "接入本机的代理软件后，日常上网走它自己的出口；成交仍然走线路。",
        )];
        if self.providers.is_empty() {
            body.push(json!({"Kind":"text","Text":"还没有登记代理软件。"}));
        }
        for p in &self.providers {
            let field = |key: &str| p.get(key).and_then(Value::as_str).unwrap_or("");
            let slot = p.get("slot").and_then(Value::as_u64).unwrap_or(0);
            let name = if field("name").is_empty() { "未命名" } else { field("name") };
            let port = p.get("dailyPort").and_then(Value::as_u64).unwrap_or(0);
            body.push(json!({"Kind":"text","Text":format!("槽位 {slot} · {name} · 日常端口 {port}")}));
            let status = match field("effectiveState") {
                "effective" => {
                    let role = match field("effectiveRole") {
                        "daily+trade" => "日常与成交都走它",
                        "trade" => "只承接成交",
                        _ => "作为日常出口",
                    };
                    format!("已生效：{role}")
                }
                "pending" => "已登记，等待生效（需要重新连接一次）".to_string(),
                "unavailable" => format!(
                    "不可用：{}",
                    if field("effectiveReason").is_empty() {
                        "当前线路里找不到它的出站"
                    } else {
                        field("effectiveReason")
                    }
                ),
                other => format!("状态未知（{other}）"),
            };
            body.push(muted(&status));
            if self.pending_remove == Some(slot) {
                body.push(row(vec![
                    button("confirm-remove", "ConfirmRemove", "确认删除", "danger", false),
                    button("cancel-remove", "CancelRemove", "取消", "ghost", false),
                ]));
            } else {
                body.push(row(vec![button(
                    &format!("remove-{slot}"),
                    "RemoveProvider",
                    "删除",
                    "ghost",
                    false,
                )]));
            }
        }
        body.push(json!({"Kind":"rule"}));
        body.push(json!({"Kind":"text","Text":"添加代理软件"}));
        body.push(select("kind", "ProviderKind", "种类", self.kind, &KIND_ITEMS, false));
        body.push(input("name", "ProviderName", "名称", &self.draft, 60));
        body.push(input("port", "ProviderPort", "日常端口", &self.port, 5));
        body.push(multiline("domains", "ProviderDomains", "引导域名（逗号或换行分隔）", &self.domains));
        body.push(row(vec![
            button("discover", "DiscoverProvider", "扫描本机", "ghost", false),
            button("add-provider", "AddProvider", "添加", "primary", false),
        ]));
        if !self.notice.is_empty() {
            body.push(muted(&self.notice));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "lines",
            "Generation": self.generation,
            "Title": "代理软件",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [button("back", "PageBack", "返回", "ghost", false)],
            "Actions": [],
        })
    }

    fn render_maintenance(&self) -> Value {
        let m = &self.maintenance;
        let flag = |key: &str| m.get(key).and_then(Value::as_bool).unwrap_or(false);
        let text_of = |key: &str| m.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        let (journal, owned, can) = (flag("journal_present"), flag("proxy_owned"), flag("can_restore"));
        let endpoint = text_of("endpoint");
        let detail = text_of("detail");

        let summary = if self.running {
            "正在还原系统代理…".to_string()
        } else if can {
            "上次连接留下了还原凭据：可以把系统代理改回去。".to_string()
        } else if journal {
            if detail.is_empty() {
                "还原凭据还在，但当前不满足自动还原的条件。".to_string()
            } else {
                detail.clone()
            }
        } else if owned {
            "系统代理当前指向本机线路（连接进行中，无需还原）。".to_string()
        } else {
            "没有待还原的代理设置。".to_string()
        };

        let mut body = vec![
            json!({"Kind":"text","Text":summary}),
        ];
        if !endpoint.is_empty() {
            body.push(muted(&format!("凭据记录的原值：{endpoint}")));
        }
        if !self.notice.is_empty() {
            body.push(muted(&self.notice));
        }
        body.push(muted("还原只改系统代理并清理凭据，不改线路配置、不联网。"));
        body.push(muted(
            "「解除交易保护」只在准备停用本工具时使用；日常断开连接无需解除。",
        ));
        if self.guard_remove_pending {
            body.push(text_tone(
                "确认解除交易保护？这会删除本工具创建的 WFP 阻止规则；名单保持不变，下次连接会重新启用保护。",
                "warn",
            ));
        }

        let mut actions = vec![button(
            "restore-proxy",
            "RestoreProxy",
            if self.running { "正在还原…" } else { "还原系统代理" },
            "primary",
            self.running || !can,
        )];
        if self.guard_remove_pending {
            actions.push(button(
                "confirm-guard-remove",
                "ConfirmRemoveGuard",
                if self.running { "正在解除…" } else { "确认解除" },
                "danger",
                self.running,
            ));
            actions.push(button("cancel-guard-remove", "CancelRemoveGuard", "取消", "ghost", false));
        } else {
            actions.push(button(
                "guard-remove",
                "RemoveGuard",
                if self.running { "正在处理…" } else { "解除交易保护" },
                "danger",
                self.running,
            ));
        }
        actions.push(button("back", "PageBack", "返回", "ghost", false));

        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "settings",
            "Generation": self.generation,
            "Title": "维护与恢复",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": actions,
            "Actions": [],
        })
    }

    fn render_history(&self) -> Value {
        // 带原始下标筛选：展开状态按 `items` 的下标存，不能按「筛选后的第几条」。
        let events: Vec<(usize, &Value)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, event)| self.history_matches(event))
            .collect();
        let mut body = vec![
            muted("只记录这台电脑上的连接、配置与维护动作；按时间倒序，最新 200 条。"),
            row(vec![input(
                "history-search",
                "HistorySearch",
                "搜索（服务器名称或操作名称）",
                &self.history_search,
                120,
            )]),
            // 旧版用两个下拉 + 一颗「筛选」；这里保持同一组语义：
            // 来源（谁发起的）与结果（成没成），互不替代。
            row(vec![
                select(
                    "history-src",
                    "HistorySourceFilter",
                    "来源",
                    self.history_src,
                    &[
                        ("", "所有来源"),
                        ("ui", "界面"),
                        ("cli", "命令行"),
                        ("auto", "自动"),
                        ("other", "其他"),
                    ],
                    false,
                ),
                select(
                    "history-result",
                    "HistoryResultFilter",
                    "结果",
                    self.history_result,
                    &[("", "所有结果"), ("ok", "成功"), ("fail", "失败")],
                    false,
                ),
                button("apply-history", "ApplyHistoryFilters", "筛选", "ghost", false),
            ]),
        ];
        let checked_now = self
            .history_checked
            .iter()
            .filter(|index| self.items.get(**index).is_some())
            .count();
        body.push(row(vec![
            button("history-all", "HistorySelectAll", "全选当前结果", "ghost", false),
            button(
                "history-delete",
                "HistoryDeleteSelected",
                &format!("删除所选（{checked_now}）"),
                "danger",
                checked_now == 0,
            ),
        ]));
        // 旧版的 `ShowClearedHistory` 的原文与默认值：勾上才显示「已隐藏」的记录。
        body.push(row(vec![check(
            "history-show-hidden",
            "ShowClearedHistory",
            "显示旧版隐藏记录",
            self.history_show_hidden,
        )]));
        if events.is_empty() {
            let message = if !self.notice.is_empty() {
                self.notice.clone()
            } else if !self.history_show_hidden
                && self.items.iter().any(|event| {
                    event.get("Hidden").and_then(Value::as_bool) == Some(true)
                })
            {
                // 旧版同一句：列表空不等于没有记录，隐藏的那批要告诉用户怎么找。
                "没有符合当前筛选条件的记录。旧版隐藏的记录可打开上方开关后查看。".to_string()
            } else {
                "没有符合当前筛选条件的记录".to_string()
            };
            body.push(muted(&message));
        } else if events.len() > 100 {
            body.push(muted(&format!("共 {} 条，这里显示最近 100 条；导出可拿到全部。", events.len())));
        }
        for (index, event) in events.iter().take(100) {
            let open = self.history_open == Some(*index);
            let picked = self.history_checked.contains(index);
            let hidden = event.get("Hidden").and_then(Value::as_bool) == Some(true);
            let line = if hidden {
                format!("已隐藏（旧版） · {}", event_line(event))
            } else {
                event_line(event)
            };
            let mut cells = vec![
                check(
                    &format!("history-pick:{index}"),
                    "HistoryPick",
                    "",
                    picked,
                ),
                json!({"Kind":"text","Text":line}),
            ];
            // 隐藏行只给「恢复显示」与「详情」：再点「删除所选」对已隐藏的记录是空操作。
            if hidden {
                cells.push(button(
                    &format!("history-restore:{index}"),
                    "RestoreHistory",
                    "恢复显示",
                    "ghost",
                    false,
                ));
            }
            cells.push(button(
                &format!("history-detail:{index}"),
                "HistoryDetail",
                if open { "收起" } else { "详情" },
                "ghost",
                false,
            ));
            body.push(row(cells));
            if open {
                body.push(card(event_detail(event)));
            }
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "settings",
            "Generation": self.generation,
            "Title": "操作记录",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [
                button("export-history", "ExportHistory", "导出当前筛选", "primary", false),
                button("back", "PageBack", "返回", "ghost", false),
            ],
            "Actions": [],
        })
    }

    /// 当前筛选后可见的 `items` 下标（顺序与页面一致）。
    fn history_visible_indices(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, event)| self.history_matches(event))
            .map(|(index, _)| index)
            .collect()
    }

    /// 一条记录是否符合当前筛选（搜索 + 来源 + 结果 + 隐藏开关）。
    ///
    /// 渲染列表与「全选当前结果」共用这一份判据：两处各写一遍，迟早会
    /// 「看得见 A、全选选了 B」。
    fn history_matches(&self, event: &Value) -> bool {
        if !self.history_show_hidden
            && event.get("Hidden").and_then(Value::as_bool) == Some(true)
        {
            return false;
        }
        let search = self.history_search.trim().to_lowercase();
        if !search.is_empty() {
            let hay = ["action", "detail", "obj", "actor"]
                .iter()
                .filter_map(|key| event.get(*key).and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            if !hay.contains(&search) {
                return false;
            }
        }
        let src = history_src_value(self.history_src);
        if !src.is_empty()
            && event.get("src").and_then(Value::as_str).unwrap_or("") != src
        {
            return false;
        }
        match self.history_result {
            1 => event.get("ok").and_then(Value::as_bool) == Some(true),
            2 => event.get("ok").and_then(Value::as_bool) == Some(false),
            _ => true,
        }
    }

    /// 勾选行的删除键（`events::key` 的同一口径）。
    fn history_checked_keys(&self) -> Vec<String> {
        self.history_checked
            .iter()
            .filter_map(|index| self.items.get(*index))
            .map(|event| {
                let field = |key: &str| event.get(key).and_then(Value::as_str).unwrap_or("");
                crate::events::key(field("ts"), field("action"), field("detail"))
            })
            .collect()
    }

    /// 「确认删除」对话框的内容（宿主 `dialog` 直接吃这个结构）。
    ///
    /// r96：按钮仍叫「删除所选」（旧版原文），实际动作是**隐藏**——
    /// 审计行保留在本机日志里，勾上「显示旧版隐藏记录」还能看到并恢复。
    pub fn history_delete_dialog(&self, count: usize) -> Value {
        json!({
            "Id": "history-delete-confirm",
            "Title": "隐藏这些操作记录？",
            "Body": format!("将在这台电脑的记录列表里隐藏 {count} 条操作记录。"),
            "Note": "记录行仍保留在本机日志里，勾上「显示旧版隐藏记录」可再看到并恢复；不影响服务器上的任何东西。",
            "Confirm": "隐藏",
            "Cancel": "取消",
            "Danger": true,
            "Details": "",
            "Progress": false,
            "Scope": "history-delete",
            "Target": "",
        })
    }

    /// 宿主取走「要弹确认框」的请求。
    pub fn take_history_delete_request(&mut self) -> Option<usize> {
        self.history_delete_request.take()
    }

    /// 宿主取走待删除的键（确认之后才取，取消时留在原处没人读，下一轮覆盖）。
    pub fn take_history_pending_keys(&mut self) -> Vec<String> {
        std::mem::take(&mut self.history_pending_keys)
    }

    /// 「管理恢复资料」（旧版的`ShowManagementRecovery`）。
    ///
    /// 导出与导入在同一页、用 `recovery_mode_import` 分叉；两边的文案与旧版一致。
    /// 导出成功后**不自动落盘**：页面把加密后的文本显示出来，再让用户点
    /// 「保存到文件…」——保存对话框是宿主的事，命令层只负责加密。
    fn render_recovery(&self) -> Value {
        let mut body: Vec<Value> = Vec::new();
        body.push(muted(
            "保存加密资料，以便更换电脑后恢复管理；导入后仍需登录验证服务器身份。",
        ));
        if self.recovery_mode_import {
            body.push(json!({"Kind":"text","Level":2,"Text":"导入已有加密恢复包"}));
            body.push(muted("还原管理资料不会启用线路，也不能绕过管理授权。"));
            body.push(field_label("粘贴加密恢复资料"));
            body.push(json!({
                "Kind":"input",
                "Id":"recovery-text",
                "Name":"RecoveryText",
                "Label":"粘贴加密恢复资料",
                "Value": self.recovery_text,
                "MaxLength": crate::recovery::RECOVERY_MAX_BYTES,
                "Multiline": true,
            }));
            body.push(row(vec![button(
                "pick-recovery-file",
                "RecoveryChooseFile",
                "选择恢复包文件…",
                "ghost",
                false,
            )]));
            body.push(field_label("恢复包密码"));
            body.push(secret(
                "recovery-password",
                "RecoveryImportPassword",
                "恢复包密码",
                !self.recovery_password.is_empty(),
                256,
            ));
            body.push(muted(
                "密码至少 12 个字符。恢复包在解密前不会写入任何记录。",
            ));
            if self.recovery_done {
                body.push(muted("已登记，可点下方「返回」回到服务器列表。"));
            } else {
                body.push(button(
                    "recovery-import",
                    "RecoveryImport",
                    "解密并登记待核验服务器",
                    "primary",
                    false,
                ));
            }
            body.push(muted(
                "导入只会登记服务器身份，不会启用线路，也不会跳过管理授权或服务器身份核对。",
            ));
        } else {
            body.push(json!({"Kind":"text","Level":2,"Text":"导出当前服务器的管理恢复包"}));
            body.push(muted("不包含服务器私钥、其他电脑私钥或交易账户。"));
            let target = if self.recovery_server_name.trim().is_empty() {
                "（未选择服务器）".to_string()
            } else {
                self.recovery_server_name.trim().to_string()
            };
            body.push(json!({"Kind":"text","Text":format!("目标：{target}")}));
            body.push(field_label("恢复包密码（至少 12 个字符）"));
            body.push(secret(
                "recovery-password",
                "RecoveryExportPassword",
                "恢复包密码（至少 12 个字符）",
                !self.recovery_password.is_empty(),
                256,
            ));
            body.push(check(
                "recovery-include",
                "RecoveryIncludeCredential",
                "我选择把 SSH 管理密码 / 私钥也包含在加密包中",
                self.recovery_include,
            ));
            if self.recovery_include {
                body.push(field_label("SSH 私钥文件（包含密钥时填写，密码认证留空）"));
                body.push(row(vec![
                    input(
                        "recovery-key-path",
                        "RecoveryKeyPath",
                        "SSH 私钥文件（包含密钥时填写，密码认证留空）",
                        &self.recovery_key_path,
                        260,
                    ),
                    button("pick-recovery-key", "RecoveryPickKey", "选择…", "ghost", false),
                ]));
                body.push(field_label("要包含的 SSH 密码 / 私钥口令"));
                body.push(secret(
                    "recovery-credential",
                    "RecoveryCredential",
                    "要包含的 SSH 密码 / 私钥口令",
                    !self.recovery_credential_password.is_empty(),
                    256,
                ));
                body.push(muted(
                    "两项都留空时使用这台服务器在本机保存的登录资料（如果之前勾过「记住登录资料」）。",
                ));
            }
            if self.recovery_package.is_empty() {
                body.push(button(
                    "recovery-export",
                    "RecoveryExport",
                    "加密导出并保存…",
                    "primary",
                    false,
                ));
            } else {
                body.push(field_label("恢复包内容（已加密）"));
                body.push(json!({
                    "Kind":"input",
                    "Id":"recovery-package",
                    "Name":"RecoveryPackage",
                    "Label":"恢复包内容（已加密）",
                    "Value": self.recovery_package,
                    "MaxLength": crate::recovery::RECOVERY_MAX_BYTES,
                    "Multiline": true,
                    "ReadOnly": true,
                }));
                body.push(row(vec![
                    button(
                        "recovery-save",
                        "RecoverySave",
                        "保存到文件…",
                        "primary",
                        false,
                    ),
                    button("recovery-reset", "RecoveryReset", "重新生成", "ghost", false),
                ]));
                if !self.recovery_saved_path.is_empty() {
                    body.push(muted(&format!("已保存：{}", self.recovery_saved_path)));
                }
                body.push(muted(
                    "请把恢复包与密码分开保存。忘记密码无法恢复，本程序也不保存这个密码。",
                ));
            }
        }
        if !self.recovery_notice.is_empty() {
            body.push(text_tone(&self.recovery_notice, self.recovery_notice_tone));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "servers",
            "Generation": self.generation,
            "Title": "管理恢复资料",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [button("back", "PageBack", "返回", "ghost", false)],
            "Actions": [],
        })
    }

    /// 「服务器」一览：这台电脑记录过的服务器。
    ///
    /// 只做本机记录：改名只动本地显示名，不连服务器、不动凭据；服务器上的
    /// 服务与设备授权仍归服务器自己管。
    fn render_servers(&self) -> Value {
        let mut body = vec![muted(
            "这台电脑记录过的服务器。名称只改本机显示；指纹是这台服务器的身份。设备授权仍在服务器上。",
        )];
        // 「管理恢复资料」（r94）：导入入口与具体记录无关，放在页首。
        body.push(row(vec![button(
            "recovery-import-open",
            "RecoveryImportOpen",
            "导入管理恢复资料…",
            "ghost",
            false,
        )]));
        if self.items.is_empty() {
            let message = if self.notice.is_empty() {
                "还没有记录任何服务器。用「添加线路 → 自己搭服务器」部署一台之后，这里会出现。"
            } else {
                self.notice.as_str()
            };
            body.push(muted(message));
        }
        for item in &self.items {
            let id = item.get("Id").and_then(Value::as_str).unwrap_or("");
            let name = item.get("Name").and_then(Value::as_str).unwrap_or("");
            let host = item.get("Host").and_then(Value::as_str).unwrap_or("");
            let user = item.get("User").and_then(Value::as_str).unwrap_or("");
            let port = item.get("Port").and_then(Value::as_u64).unwrap_or(0);
            let fingerprint = item
                .get("Fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            let created = item
                .get("CreatedAtUtc")
                .and_then(Value::as_str)
                .unwrap_or("");
            let lines = item
                .get("LineIds")
                .and_then(Value::as_array)
                .map(|ids| ids.len())
                .unwrap_or(0);

            // 正在改这一条：把卡片换成输入框 + 保存/取消。其余记录保持原样。
            if self.server_rename.as_deref() == Some(id) {
                body.push(card(vec![
                    json!({
                        "Kind": "text",
                        "Text": format!("重命名「{}」", if name.is_empty() { host } else { name }),
                        "Level": 3,
                    }),
                    input("name", "ServerName", "新名称", &self.draft, 120),
                    muted("只改这台电脑上的显示名称；地址、指纹、登录凭据都不变。"),
                    row(vec![
                        json!({
                            "Kind": "button",
                            "Id": "save-server-rename",
                            "Name": "ServerRenameSave",
                            "Text": "保存名称",
                            "Tone": "primary",
                        }),
                        json!({
                            "Kind": "button",
                            "Id": "cancel-server-rename",
                            "Name": "ServerRenameCancel",
                            "Text": "取消",
                            "Tone": "ghost",
                        }),
                    ]),
                ]));
                continue;
            }

            // 正在确认删除这一条：只删本机记录与凭据，服务器不受影响。
            if self.server_remove.as_deref() == Some(id) {
                let mut confirm = vec![
                    json!({
                        "Kind": "text",
                        "Text": format!("删除「{}」的本机记录？", if name.is_empty() { host } else { name }),
                        "Level": 3,
                    }),
                    muted("只删除这台电脑上的记录与登录凭据；服务器、服务器上的设备与服务都不受影响。"),
                ];
                let mut buttons = Vec::new();
                if lines > 0 {
                    confirm.push(text_tone(
                        &format!(
                            "还有 {lines} 条线路用到它；请先删除这些线路，否则记录不能删。"
                        ),
                        "warn",
                    ));
                } else {
                    buttons.push(json!({
                        "Kind": "button",
                        "Id": "confirm-server-remove",
                        "Name": "ServerRemoveConfirm",
                        "Text": "删除记录",
                        "Tone": "danger",
                    }));
                }
                buttons.push(json!({
                    "Kind": "button",
                    "Id": "cancel-server-remove",
                    "Name": "ServerRemoveCancel",
                    "Text": "取消",
                    "Tone": "ghost",
                }));
                confirm.push(row(buttons));
                body.push(card(confirm));
                continue;
            }

            let address = if host.is_empty() {
                "（没有记录地址）".to_string()
            } else if user.is_empty() || port == 0 {
                host.to_string()
            } else {
                format!("{user}@{host}:{port}")
            };
            let mut lines_of_card = vec![
                json!({
                    "Kind": "text",
                    "Text": if name.is_empty() { host } else { name },
                    "Level": 3,
                }),
                muted(&format!(
                    "{} · {}",
                    address,
                    // 0 条不是错：刚部署完还没接入线路时就是这样。
                    match lines {
                        0 => "还没有线路用到它".to_string(),
                        n => format!("关联 {n} 条线路"),
                    }
                )),
            ];
            if !fingerprint.is_empty() {
                lines_of_card.push(muted(&format!("指纹 {fingerprint}")));
            }
            if !created.is_empty() {
                lines_of_card.push(muted(&format!("记录于 {created}")));
            }
            lines_of_card.push(row(vec![
                json!({
                    "Kind": "button",
                    "Id": format!("recovery-export:{id}"),
                    "Name": "RecoveryExportOpen",
                    "Text": "导出管理恢复包…",
                    "Tone": "ghost",
                }),
                json!({
                    "Kind": "button",
                    "Id": format!("server-rename:{id}"),
                    "Name": "ServerRename",
                    "Text": "改名",
                    "Tone": "ghost",
                }),
                // 「删除本机部署资料…」（旧版的那句）：比「删除记录」多删了部署记录、
                // 提醒与任务级凭据，所以先给它，危险动作排最后。
                json!({
                    "Kind": "button",
                    "Id": format!("server-cleanup:{id}"),
                    "Name": "ServerCleanup",
                    "Text": "删除本机部署资料…",
                    "Tone": "ghost",
                }),
                json!({
                    "Kind": "button",
                    "Id": format!("server-remove:{id}"),
                    "Name": "ServerRemove",
                    "Text": "删除记录",
                    "Tone": "ghost",
                }),
            ]));
            body.push(card(lines_of_card));
        }
        if !self.items.is_empty() && !self.notice.is_empty() {
            body.push(text_tone(&self.notice, self.notice_tone));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "settings",
            "Generation": self.generation,
            "Title": "服务器",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [button("back", "PageBack", "返回", "ghost", false)],
            "Actions": [],
        })
    }

    fn render_diagnose(&self) -> Value {
        let mut body = Vec::new();
        let code = self.verdict.get("code").and_then(Value::as_str).unwrap_or("");
        if self.running {
            body.push(json!({"Kind":"text","Text":"正在探测线路端点，最长约 30 秒；期间按钮不可点。"}));
        } else if code.is_empty() && self.items.is_empty() {
            body.push(muted("还没有诊断结果。点「重新诊断」跑一次。"));
        } else {
            let text = self.verdict.get("text").and_then(Value::as_str).unwrap_or("");
            if !text.is_empty() {
                body.push(text_tone(text, if code == "ok" { "muted" } else { "warn" }));
            }
            let next = self.verdict.get("next").and_then(Value::as_str).unwrap_or("");
            if !next.is_empty() {
                body.push(json!({"Kind":"text","Text":format!("下一步：{next}")}));
            }
        }
        for item in &self.items {
            let text = item.get("text").and_then(Value::as_str).unwrap_or("").to_string();
            if !text.is_empty() {
                body.push(json!({"Kind":"text","Text":text}));
            }
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "settings",
            "Generation": self.generation,
            "Title": "运行诊断",
            "Description": "",
            "Nodes": [card(body)],
            "PageActions": [
                button("run-diagnose", "RunDiagnose", if self.running { "正在诊断…" } else { "重新诊断" },
                       "primary", self.running),
                button("back", "PageBack", "返回", "ghost", false),
            ],
            "Actions": [],
        })
    }

    fn render_rename(&self) -> Value {
        let mut nodes = vec![
            muted("只改这台电脑上的显示名称；线路 ID、服务器地址、连接记录都不变。"),
            card(vec![
                json!({"Kind":"text","Text":"线路名称"}),
                input("name", "RenameLineName", "线路名称", &self.draft, 120),
            ]),
        ];
        if !self.notice.is_empty() {
            nodes.push(text_tone(&self.notice, self.notice_tone));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "lines",
            "Generation": self.generation,
            "Title": "重命名线路",
            "Description": "",
            "Nodes": nodes,
            "PageActions": [
                button("save-rename", "RenameLineSave", "保存名称", "primary", false),
                button("back", "RenameLineCancel", "取消", "ghost", false),
            ],
            "Actions": [],
        })
    }

    fn render_line_settings(&self) -> Value {
        let seg = |id: &str, label: &str, on: bool| {
            json!({
                "Kind": "button",
                "Id": id,
                "Name": id,
                "Text": label,
                // 选中的一档用 primary 标出，另一档保持普通按钮。两档都可点：
                // 重复点同一档会拿到「已经是这个方式」的回包，不静默失败。
                "Tone": if on { "primary" } else { "ghost" },
            })
        };
        let mut nodes = vec![card(vec![
            json!({
                "Kind": "text",
                "Text": format!("线路「{}」", self.line_name),
                "Level": 3,
            }),
            muted(&format!("服务器端点：{}", if self.endpoint.is_empty() { "（未读取）" } else { &self.endpoint })),
            json!({"Kind":"text","Text":"连接方式"}),
            row(vec![
                seg("method-udp", "标准（UDP）", self.method == "Udp"),
                seg("method-tcp", "兼容（TCP）", self.method == "Tcp"),
            ]),
            muted("标准走 UDP，速率更好；兼容走 TCP，适合 UDP 被限制的网络。切换只影响下次连接，当前连接保持。"),
            muted("本页覆盖连接方式、出口网卡与兼容连接的补充。服务器登录资料与端口改动在部署流程里。"),
        ])];
        // 出口网卡（A 组网卡绑定）：旧版在连接前用「选择本机连接网络」补这一步，
        // 这里并到同一页——默认跟随系统，指定后这条线路的引擎出站只走那张网卡。
        let mut items: Vec<(String, String)> = Vec::new();
        items.push((
            String::new(),
            if self.net_default.is_empty() {
                "跟随系统默认（默认网卡读不到）".to_string()
            } else {
                format!("跟随系统默认（当前：{}）", self.net_default)
            },
        ));
        for name in &self.net_interfaces {
            items.push((name.clone(), name.clone()));
        }
        if self.net_stale && !self.net_stale_name.is_empty() {
            items.push((
                self.net_stale_name.clone(),
                format!("{}（这台电脑上没有）", self.net_stale_name),
            ));
        }
        let options: Vec<(&str, &str)> = items
            .iter()
            .map(|(value, label)| (value.as_str(), label.as_str()))
            .collect();
        let picked = self.net_pick.min(options.len().saturating_sub(1));
        let mut net_nodes = vec![
            json!({"Kind":"text","Text":"出口网卡","Level":3}),
            muted(
                "默认跟随系统出口。指定后，这条线路的引擎出站只从这张网卡发出\
                 （例如网线走交易、Wi-Fi 走日常）。",
            ),
            // 「当前绑定」是这一页唯一的既成事实：它只来自 `line-network` 回包，
            // 也就是**磁盘上的那一条**。保存后我们立刻重读一次，页面靠它变化来
            // 证明「真的写进去了」——不靠一句可能到不了页面的「已保存」。
            text_tone(&self.bound_sentence(), "muted"),
            select(
                "net-interface",
                "LineNetworkInterfaces",
                "出口网卡",
                picked,
                &options,
                false,
            ),
            row(vec![button(
                "save-net",
                "LineNetworkSave",
                "保存出口网卡",
                "primary",
                false,
            )]),
            muted("保存只影响下次连接，当前连接保持。"),
        ];
        if self.net_stale {
            net_nodes.push(text_tone(
                &format!(
                    "这条线路指定的「{}」现在不在这台电脑上：连接会被拒绝。\
                     请重新选一张网卡，或改为跟随系统默认。",
                    self.net_stale_name
                ),
                "warn",
            ));
        }
        nodes.push(card(net_nodes));
        // 兼容连接（TCP）：给只有标准线路的老线路补一条备用。
        //
        // 这是本页唯一**会改服务器**的动作，所以：说明里写清前置（要本机保存着登录资料），
        // 点击后先问一句再发命令；补完不改当前连接方式，只是多一个可选。
        let mut compat_nodes = vec![
            json!({"Kind":"text","Text":"兼容连接（TCP）","Level":3}),
            muted(
                "兼容连接是**这条线路**的第二种连接方式（同一台服务器、同一份隧道），不是另一条线路。\
                 服务器只放行 TCP、或当初部署时没装上时，这里给这条线路补上：会登录服务器安装中转，\
                 当前连接不会断；补完在卡片上点「兼容」即可，两个方向随时能切。",
            ),
            muted("前提：本机保存着这台服务器的登录资料（部署时勾了「记住登录资料」，或用管理恢复包导入过）。"),
        ];
        if self.compat_confirm {
            compat_nodes.push(text_tone(
                "要在这台服务器上装兼容连接（TCP），挂到这条线路上。这会改服务器配置，确定继续吗？",
                "warn",
            ));
            compat_nodes.push(row(vec![
                button("compat-yes", "CompatYes", "确认补上", "primary", false),
                button("compat-no", "CompatNo", "取消", "ghost", false),
            ]));
        } else {
            compat_nodes.push(row(vec![button(
                "compat-add",
                "CompatAdd",
                "补一条兼容连接…",
                "ghost",
                false,
            )]));
        }
        if !self.compat_note.is_empty() {
            compat_nodes.push(text_tone(&self.compat_note, self.compat_tone));
        }
        nodes.push(card(compat_nodes));
        if !self.notice.is_empty() {
            nodes.push(text_tone(&self.notice, self.notice_tone));
        }
        json!({
            "ViewKey": self.view_key(),
            "ParentPage": "lines",
            "Generation": self.generation,
            "Title": "连接方式与网络",
            "Description": "",
            "Nodes": nodes,
            "PageActions": [button("back", "PageBack", "返回", "ghost", false)],
            "Actions": [],
        })
    }

    /// 页面事件 → 既有命令。`value_str`/`value_num` 分开取，因为 select 回传的是数字。
    pub fn event(&mut self, msg: &Value) -> Vec<Step> {
        let id = msg.get("Id").and_then(Value::as_str).unwrap_or("");
        let event = msg.get("Event").and_then(Value::as_str).unwrap_or("");
        let value = msg.get("Value").and_then(Value::as_str).unwrap_or("");
        let number = msg.get("Value").and_then(Value::as_i64);
        // 勾选框回包的 `Value` 是布尔（前端发 `target.checked`），既不是字符串也不是整数。
        let flag = msg.get("Value").and_then(Value::as_bool);
        let mut steps = Vec::new();
        // 名单页「确认程序位置」：按钮 id 是动态的（`locate-<下标>`），先按前缀处理。
        if event == "click" && self.view == View::Split && id != "locate-apply" {
            if let Some(rest) = id.strip_prefix("locate-") {
                if let Ok(index) = rest.parse::<usize>() {
                    self.locate_index = Some(index);
                    self.locate_path = None;
                    self.notice = "选择这个程序的实际位置".into();
                    self.restructure();
                    steps.push(Step::Sync(cmd("pick-exe", &[("target", json!("trade"))])));
                    return steps;
                }
            }
        }
        // 「删除槽位 N」的按钮 id 是动态的，先按前缀处理。
        if event == "click" && self.view == View::Providers {
            if let Some(rest) = id.strip_prefix("remove-") {
                if let Ok(slot) = rest.parse::<u64>() {
                    self.pending_remove = Some(slot);
                    self.restructure();
                    return steps;
                }
            }
        }
        // 服务器一览的「改名」按钮 id 带记录 id，先按前缀处理：这一步不发命令，
        // 只把那张卡片换成输入框；保存时才发 `server-rename`。
        if event == "click" && self.view == View::Servers {
            // 导出恢复包：从这一条服务器进入「管理恢复资料」页。
            if let Some(record_id) = id.strip_prefix("recovery-export:") {
                let record_id = record_id.to_string();
                let name = self
                    .items
                    .iter()
                    .find(|item| item.get("Id").and_then(Value::as_str) == Some(record_id.as_str()))
                    .and_then(|item| item.get("Name").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() && !self.items.iter().any(|item| {
                    item.get("Id").and_then(Value::as_str) == Some(record_id.as_str())
                }) {
                    self.notice = "找不到这条服务器记录，请返回后重试。".into();
                    self.notice_tone = "warn";
                } else {
                    self.view = View::Recovery;
                    self.recovery_mode_import = false;
                    self.recovery_server_id = record_id;
                    self.recovery_server_name = name;
                    self.recovery_password.clear();
                    self.recovery_include = false;
                    self.recovery_credential_password.clear();
                    self.recovery_key_path.clear();
                    self.recovery_package.clear();
                    self.recovery_file_name.clear();
                    self.recovery_saved_path.clear();
                    self.recovery_notice.clear();
                    self.recovery_done = false;
                }
                self.restructure();
                return steps;
            }
            if let Some(record_id) = id.strip_prefix("server-rename:") {
                let record_id = record_id.to_string();
                let current = self
                    .items
                    .iter()
                    .find(|item| item.get("Id").and_then(Value::as_str) == Some(record_id.as_str()))
                    .and_then(|item| item.get("Name").and_then(Value::as_str))
                    .map(str::to_string);
                match current {
                    Some(name) => {
                        self.server_rename = Some(record_id);
                        self.draft = name;
                        self.notice.clear();
                        self.notice_tone = "muted";
                    }
                    None => {
                        self.notice = "找不到这条服务器记录，请返回后重试。".into();
                        self.notice_tone = "warn";
                    }
                }
                self.restructure();
                return steps;
            }
            // 「删除本机部署资料…」：先发**只读**预览，看清要删什么再弹确认框。
            // 直接弹框等于让用户在不知道影响面的情况下点「删除」。
            if let Some(record_id) = id.strip_prefix("server-cleanup:") {
                let record_id = record_id.to_string();
                let exists = self
                    .items
                    .iter()
                    .any(|item| item.get("Id").and_then(Value::as_str) == Some(record_id.as_str()));
                if exists {
                    self.server_cleanup = Some(record_id.clone());
                    self.notice.clear();
                    self.notice_tone = "muted";
                    self.restructure();
                    steps.push(Step::Sync(cmd(
                        "server-cleanup-preview",
                        &[("id", json!(record_id))],
                    )));
                } else {
                    self.notice = "找不到这条服务器记录，请返回后重试。".into();
                    self.notice_tone = "warn";
                    self.restructure();
                }
                return steps;
            }
            if let Some(record_id) = id.strip_prefix("server-remove:") {
                let record_id = record_id.to_string();
                let exists = self
                    .items
                    .iter()
                    .any(|item| item.get("Id").and_then(Value::as_str) == Some(record_id.as_str()));
                if exists {
                    self.server_remove = Some(record_id);
                    self.notice.clear();
                    self.notice_tone = "muted";
                } else {
                    self.notice = "找不到这条服务器记录，请返回后重试。".into();
                    self.notice_tone = "warn";
                }
                self.restructure();
                return steps;
            }
        }
        // 设备页的「改名」按钮 id 带列表下标（公钥含 +//=，不适合放进选择器）。
        if event == "click" && self.view == View::Devices {
            if let Some(rest) = id.strip_prefix("device-rename:") {
                if let Ok(index) = rest.parse::<usize>() {
                    let devices = self
                        .devices
                        .get("devices")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(device) = devices.get(index) {
                        self.device_rename_index = Some(index);
                        self.draft = device
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        self.notice.clear();
                        self.notice_tone = "muted";
                        self.restructure();
                    }
                }
                return steps;
            }
        }
        // 名单的「移除」按索引定位，值从当前列表里取，不信任页面回传的值。
        if event == "click" && self.view == View::Split {
            let parsed = id
                .strip_prefix("remove-process-")
                .map(|index| ("process", index))
                .or_else(|| id.strip_prefix("remove-domain-").map(|index| ("domain", index)));
            if let Some((kind, index)) = parsed {
                if let Ok(index) = index.parse::<usize>() {
                    let list = if kind == "process" { &self.processes } else { &self.domain_rules };
                    if let Some(value) =
                        list.get(index).and_then(|v| v.get("value")).and_then(Value::as_str)
                    {
                        steps.push(Step::Sync(cmd(
                            "split-remove",
                            &[("kind", json!(kind)), ("value", json!(value))],
                        )));
                    }
                    return steps;
                }
            }
        }
        match (event, self.view) {
            ("change", View::Rename) if id == "name" => self.draft = value.to_string(),
            ("change", View::LineSettings) if id == "name" => self.draft = value.to_string(),
            // ---- 服务器一览：改名（本地记录） ----
            ("change", View::Servers) if id == "name" => self.draft = value.to_string(),
            ("click", View::Servers) if id == "save-server-rename" => {
                let name = self.draft.trim().to_string();
                if name.is_empty() || name.chars().count() > 120 {
                    self.notice = "请填写 1–120 个字的服务器名称".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                if name.chars().any(char::is_control) {
                    self.notice = "服务器名称不能包含换行、制表符等控制字符".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                match self.server_rename.clone() {
                    Some(record_id) => {
                        steps.push(Step::Sync(cmd(
                            "server-rename",
                            &[("id", json!(record_id)), ("name", json!(name))],
                        )));
                    }
                    None => {
                        self.notice = "没有正在改名的服务器记录。".into();
                        self.notice_tone = "warn";
                        self.restructure();
                    }
                }
            }
            ("click", View::Servers) if id == "cancel-server-rename" => {
                self.server_rename = None;
                self.draft.clear();
                self.notice.clear();
                self.notice_tone = "muted";
                self.restructure();
            }
            ("click", View::Servers) if id == "confirm-server-remove" => {
                match self.server_remove.clone() {
                    Some(record_id) => steps.push(Step::Sync(cmd(
                        "server-remove",
                        &[("id", json!(record_id))],
                    ))),
                    None => {
                        self.notice = "没有正在删除的服务器记录。".into();
                        self.notice_tone = "warn";
                        self.restructure();
                    }
                }
            }
            ("click", View::Servers) if id == "cancel-server-remove" => {
                self.server_remove = None;
                self.notice.clear();
                self.notice_tone = "muted";
                self.restructure();
            }
            // r94：导入恢复包与具体记录无关，直接从服务器页进入。
            ("click", View::Servers) if id == "recovery-import-open" => {
                self.view = View::Recovery;
                self.recovery_mode_import = true;
                self.recovery_password.clear();
                self.recovery_text.clear();
                self.recovery_package.clear();
                self.recovery_saved_path.clear();
                self.recovery_notice.clear();
                self.recovery_done = false;
                self.restructure();
            }
            // ---- 管理恢复资料（r94） ----
            ("change", View::Recovery) if id == "recovery-password" => {
                self.recovery_password = value.to_string()
            }
            ("change", View::Recovery) if id == "recovery-credential" => {
                self.recovery_credential_password = value.to_string()
            }
            ("change", View::Recovery) if id == "recovery-key-path" => {
                self.recovery_key_path = value.to_string()
            }
            ("change", View::Recovery) if id == "recovery-text" => {
                self.recovery_text = value.to_string()
            }
            // 勾选框回包是布尔，不能走 `value`（空串）。
            ("change", View::Recovery) if id == "recovery-include" => {
                self.recovery_include = flag.unwrap_or(false)
            }
            ("click", View::Recovery) if id == "pick-recovery-key" => {
                steps.push(Step::Sync(cmd("pick-file", &[("slot", json!("key"))])));
            }
            ("click", View::Recovery) if id == "pick-recovery-file" => {
                steps.push(Step::Sync(cmd("pick-file", &[("slot", json!("recovery"))])));
            }
            ("click", View::Recovery) if id == "recovery-export" => {
                let password = self.recovery_password.clone();
                if password.chars().count() < crate::recovery::PASSWORD_MIN {
                    self.recovery_notice = format!(
                        "恢复包密码至少 {} 个字符。",
                        crate::recovery::PASSWORD_MIN
                    );
                    self.recovery_notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                if self.recovery_server_id.is_empty() {
                    self.recovery_notice = "还没有选择要导出的服务器。".into();
                    self.recovery_notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                self.recovery_notice = "正在加密恢复包…".into();
                self.recovery_notice_tone = "muted";
                self.recovery_saved_path.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "recovery-export",
                    &[
                        ("serverId", json!(self.recovery_server_id)),
                        ("password", json!(password)),
                        ("includeCredential", json!(self.recovery_include)),
                        ("identityFile", json!(self.recovery_key_path.trim())),
                        ("credentialPassword", json!(self.recovery_credential_password)),
                    ],
                )));
            }
            ("click", View::Recovery) if id == "recovery-save" => {
                if self.recovery_package.is_empty() {
                    self.recovery_notice = "还没有生成恢复包。".into();
                    self.recovery_notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                steps.push(Step::Sync(cmd(
                    "save-file",
                    &[
                        ("slot", json!("recovery")),
                        ("text", json!(self.recovery_package)),
                        ("suggestedName", json!(self.recovery_file_name)),
                    ],
                )));
            }
            ("click", View::Recovery) if id == "recovery-reset" => {
                self.recovery_package.clear();
                self.recovery_file_name.clear();
                self.recovery_saved_path.clear();
                self.recovery_notice.clear();
                self.recovery_notice_tone = "muted";
                self.restructure();
            }
            ("click", View::Recovery) if id == "recovery-import" => {
                let package = self.recovery_text.trim().to_string();
                if package.is_empty() {
                    self.recovery_notice = "请粘贴恢复包内容，或选择恢复包文件。".into();
                    self.recovery_notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                if self.recovery_password.chars().count() < crate::recovery::PASSWORD_MIN {
                    self.recovery_notice = format!(
                        "恢复包密码至少 {} 个字符。",
                        crate::recovery::PASSWORD_MIN
                    );
                    self.recovery_notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                self.recovery_notice = "正在解密恢复包…".into();
                self.recovery_notice_tone = "muted";
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "recovery-import",
                    &[
                        ("package", json!(package)),
                        ("password", json!(self.recovery_password)),
                    ],
                )));
            }
            ("click", View::Rename) if id == "save-rename" => {
                let name = self.draft.trim().to_string();
                if name.is_empty() || name.chars().count() > 120 {
                    self.notice = "请填写 1–120 个字的线路名称".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                if name.chars().any(char::is_control) {
                    self.notice = "线路名不能包含换行、制表符等控制字符".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                steps.push(Step::Sync(cmd(
                    "rename-line",
                    &[("id", json!(self.line_id)), ("name", json!(name))],
                )));
            }
            ("click", View::LineSettings) if id == "method-udp" => steps.push(Step::Sync(
                cmd("set-transport", &[("id", json!(self.line_id)), ("transport", json!("udp"))]),
            )),
            ("click", View::LineSettings) if id == "method-tcp" => steps.push(Step::Sync(
                cmd("set-transport", &[("id", json!(self.line_id)), ("transport", json!("tcp"))]),
            )),
            // 出口网卡：下拉只记「选了哪一项」，点保存才真的写。
            // **不 `restructure()`**（r87 的教训）：那会把代数 +1、页面还拿着上一代，
            // 下一次输入被 `Generation` 闸门静默丢掉；下拉的值本来就由页面自己持有。
            ("click", View::LineSettings) if id == "compat-add" => {
                self.compat_confirm = true;
                self.compat_note.clear();
                self.restructure();
            }
            ("click", View::LineSettings) if id == "compat-no" => {
                self.compat_confirm = false;
                self.compat_note.clear();
                self.restructure();
            }
            ("click", View::LineSettings) if id == "compat-yes" => {
                self.compat_confirm = false;
                // 进行中就说清楚要等：这条命令会 SSH 到服务器，装组件时可能一两分钟。
                self.compat_note = "正在登录服务器补兼容连接（装组件时可能要一两分钟）…".into();
                self.compat_tone = "muted";
                self.restructure();
                steps.push(Step::Long(cmd(
                    "line-add-compatible",
                    &[("line", json!(self.line_id))],
                )));
            }
            ("change", View::LineSettings) if id == "net-interface" => {
                self.net_pick = number.unwrap_or(0).max(0) as usize;
                // 选了「跟随默认」就不再是「指定的那张不在了」——警告要跟着消失，
                // 否则用户会以为改了没生效。
                if self.net_pick == 0 {
                    self.net_stale = false;
                    self.net_stale_name.clear();
                }
            }
            ("click", View::LineSettings) if id == "save-net" => {
                let name = self.net_selected_name();
                steps.push(Step::Sync(cmd(
                    "line-network-set",
                    &[("Id", json!(self.line_id)), ("Interface", json!(name))],
                )));
                // 写完**立刻重读一次**：页面上的「当前绑定」只认这条读命令的回包，
                // 也就是磁盘上真正的那一条。这样即使保存回包在路上被别的逻辑吃掉，
                // 用户看到的仍然是事实（真机验收就是这么发现「写了但页面没反应」的）。
                steps.push(Step::Sync(cmd(
                    "line-network",
                    &[("Id", json!(self.line_id))],
                )));
            }
            // 筛选是页面状态：不发命令。切换时必须收起详情——列表长度变了，
            // 原来那个下标会挂到另一条记录上。
            ("change", View::History) if id == "history-search" => {
                self.history_search = value.to_string();
                self.history_open = None;
                // **不 `restructure()`**：那会把代数 +1，页面还拿着上一代，
                // 下一次输入就被宿主的 `Generation` 闸门当成过期事件静默丢掉
                // （r87 真机验收抓到的「一条都筛不掉」）。筛选结果靠下一帧快照重画。
            }
            ("change", View::History) if id == "history-src" => {
                self.history_src = number.unwrap_or(0).max(0) as usize;
                self.history_open = None;
            }
            ("change", View::History) if id == "history-result" => {
                self.history_result = number.unwrap_or(0).max(0) as usize;
                self.only_fail = self.history_result == 2;
                self.history_open = None;
            }
            // 旧版的 `ShowClearedHistory`：勾选是一个**结构变化**（列表长度变了，
            // 已勾选与展开的下标都会错位），所以清掉那两份状态再重绘。
            ("change", View::History) if id == "history-show-hidden" => {
                self.history_show_hidden = flag.unwrap_or(false);
                self.history_checked.clear();
                self.history_open = None;
                self.restructure();
            }
            ("click", View::History) if id == "history-all" => {
                // 只选「当前筛选后看得见的那几条」——全选把隐藏的也选上，
                // 用户按下删除时会删掉自己没看到的记录。
                self.history_checked = self.history_visible_indices();
            }
            ("click", View::History) if id == "history-delete" => {
                let keys = self.history_checked_keys();
                if !keys.is_empty() {
                    self.history_pending_keys = keys;
                    self.history_delete_request = Some(self.history_pending_keys.len());
                }
            }
            ("change", View::History) if id.starts_with("history-pick:") => {
                if let Ok(index) = id["history-pick:".len()..].parse::<usize>() {
                    if flag.unwrap_or(false) && self.items.get(index).is_some() {
                        if !self.history_checked.contains(&index) {
                            self.history_checked.push(index);
                        }
                    } else {
                        self.history_checked.retain(|item| *item != index);
                    }
                }
            }
            // 「恢复显示」：只对**已隐藏**的行有意义；键用回包给的 `Key`
            // （与 `events::key` 同一口径），旧数据没有它就现场算一份。
            ("click", View::History) if id.starts_with("history-restore:") => {
                let key = id["history-restore:".len()..]
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| self.items.get(index))
                    .filter(|event| {
                        event.get("Hidden").and_then(Value::as_bool) == Some(true)
                    })
                    .map(|event| {
                        event.get("Key").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| {
                            let field = |name: &str| {
                                event.get(name).and_then(Value::as_str).unwrap_or("")
                            };
                            crate::events::key(field("ts"), field("action"), field("detail"))
                        })
                    });
                if let Some(key) = key {
                    self.history_restore_pending = vec![key.clone()];
                    steps.push(Step::Sync(cmd(
                        "history-restore",
                        &[("keys", json!([key]))],
                    )));
                }
            }
            ("click", View::History) if id == "apply-history" => {
                self.history_open = None;
                self.restructure();
            }
            ("click", View::History) if id == "filter-fail" => {
                self.only_fail = true;
                self.history_open = None;
                self.restructure();
            }
            ("click", View::History) if id.starts_with("history-detail:") => {
                let index: Option<usize> = id["history-detail:".len()..].parse().ok();
                self.history_open = match index {
                    Some(open) if self.history_open != Some(open) => Some(open),
                    // 再点一次同一条 = 收起；索引解析不出来也当收起，不展开一条不存在的。
                    _ => None,
                };
                self.restructure();
            }
            // 后端读的是 `filter.onlyFail` / `filter.src`。以前发在顶层，筛选一个字都没生效
            // （r87 顺手修掉）。这里把当前的来源与结果一起带过去。
            ("click", View::History) if id == "export-history" => {
                let src_value = match history_src_value(self.history_src) {
                    "" => "all",
                    other => other,
                };
                steps.push(Step::Sync(cmd(
                    "export-history",
                    &[(
                        "filter",
                        json!({
                            "onlyFail": self.history_result == 2,
                            "src": src_value,
                            // r96：导出要跟着页面走——隐藏开关与搜索词都是「当前筛选」的一部分。
                            "includeHidden": self.history_show_hidden,
                            "search": self.history_search.trim(),
                        }),
                    )],
                )));
            }
            ("click", View::Diagnose) if id == "run-diagnose" => {
                self.running = true;
                self.notice = "正在诊断…".into();
                self.restructure();
                steps.push(Step::Long(cmd("diagnose", &[])));
            }
            ("click", View::Maintenance) if id == "restore-proxy" => {
                self.running = true;
                self.notice = "正在还原系统代理…".into();
                self.restructure();
                steps.push(Step::Long(cmd("restore", &[])));
            }
            // 解除是两段式：第一段只出后果文案，第二段才发长命令。FormState 弹不了
            // 宿主对话框，表单内确认是同层最小改动（架构 A-9）。
            ("click", View::Maintenance) if id == "guard-remove" => {
                self.guard_remove_pending = true;
                self.notice = "请先确认后果，再解除交易保护。".into();
                self.restructure();
            }
            ("click", View::Maintenance) if id == "confirm-guard-remove" => {
                self.running = true;
                self.notice = "正在解除交易保护…".into();
                self.restructure();
                steps.push(Step::Long(cmd("guard-remove", &[])));
            }
            ("click", View::Maintenance) if id == "cancel-guard-remove" => {
                self.guard_remove_pending = false;
                self.notice.clear();
                self.restructure();
            }
            ("change", View::Providers) if id == "kind" => {
                self.kind = number.unwrap_or(0).max(0) as usize;
            }
            ("change", View::Providers) if id == "name" => self.draft = value.to_string(),
            ("change", View::Providers) if id == "port" => self.port = value.to_string(),
            ("change", View::Providers) if id == "domains" => self.domains = value.to_string(),
            ("click", View::Providers) if id == "discover" => {
                steps.push(Step::Sync(cmd("provider-discover", &[])));
            }
            ("click", View::Providers) if id == "add-provider" => {
                let port = self.port.trim().parse::<u16>().ok().filter(|p| *p > 0);
                let name = self.draft.trim().to_string();
                if name.is_empty() {
                    self.notice = "请填写名称".into();
                    self.restructure();
                } else if port.is_none() {
                    self.notice = "端口要填 1–65535 的整数".into();
                    self.restructure();
                } else {
                    let kind = KIND_ITEMS.get(self.kind).map(|(id, _)| *id).unwrap_or("clashverge");
                    let domains: Vec<String> = self
                        .domains
                        .split(['，', ',', '\n'])
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                    steps.push(Step::Sync(cmd(
                        "provider-add",
                        &[
                            ("kind", json!(kind)),
                            ("name", json!(name)),
                            ("dailyPort", json!(self.port.trim())),
                            ("domains", json!(domains)),
                        ],
                    )));
                }
            }
            ("click", View::Providers) if id == "confirm-remove" => {
                if let Some(slot) = self.pending_remove {
                    steps.push(Step::Sync(cmd("provider-remove", &[("slot", json!(slot))])));
                    self.pending_remove = None;
                }
            }
            ("click", View::Providers) if id == "cancel-remove" => {
                self.pending_remove = None;
                self.restructure();
            }
            ("change", View::Split) if id == "program-path" => {
                self.program_path = value.to_string();
            }
            ("change", View::Split) if id == "site-domain" => self.draft = value.to_string(),
            ("click", View::Split) if id == "locate-apply" => {
                let apply = self.locate_index.and_then(|index| {
                    let name = self.processes.get(index)?.get("value")?.as_str()?.to_string();
                    let path = self.locate_path.clone()?;
                    Some((name, path))
                });
                match apply {
                    Some((name, path)) => steps.push(Step::Sync(cmd(
                        "split-add",
                        &[
                            ("kind", json!("process")),
                            ("value", json!(name)),
                            ("target", json!("trade")),
                            // 同名条目按名字去重并更新 path（`add_process` 的既有语义），
                            // 所以这里不是「再添加一条」，而是给这一条补上身份。
                            ("path", json!(path)),
                        ],
                    ))),
                    None => {
                        self.notice = "先选一个程序，再保存位置".into();
                        self.restructure();
                    }
                }
            }
            ("click", View::Split) if id == "pick-program" => {
                // 浏览只回填输入框；点「添加程序」才写配置（与旧版两步一致）。
                steps.push(Step::Sync(cmd("pick-exe", &[("target", json!("trade"))])));
            }
            ("click", View::Split) if id == "add-program" => {
                let raw = self.program_path.trim().to_string();
                if raw.is_empty() {
                    self.notice = "请选择程序文件，或把 .exe 拖进输入框".into();
                    self.restructure();
                } else {
                    // 粘贴完整路径时，配置里只存文件名；路径另走 `path` 字段（保护要用它定位）。
                    let looks_path = raw.contains('\\') || raw.contains('/');
                    let name = if looks_path {
                        raw.rsplit(['\\', '/']).next().unwrap_or("").trim().to_string()
                    } else {
                        raw.clone()
                    };
                    if !name.to_ascii_lowercase().ends_with(".exe") {
                        self.notice = "请选择 .exe 程序文件（只填名字时也要以 .exe 结尾）".into();
                        self.restructure();
                    } else {
                        self.split_add_kind = "process".into();
                        let mut fields = vec![
                            ("kind", json!("process")),
                            ("value", json!(name)),
                            ("target", json!("trade")),
                        ];
                        if looks_path {
                            fields.push(("path", json!(raw)));
                        }
                        steps.push(Step::Sync(cmd("split-add", &fields)));
                    }
                }
            }
            ("click", View::Split) if id == "add-site" => {
                let value = self.draft.trim().to_string();
                if value.is_empty() {
                    self.notice = "请填写网站域名".into();
                    self.restructure();
                } else {
                    self.split_add_kind = "domain".into();
                    steps.push(Step::Sync(cmd(
                        "split-add",
                        &[
                            ("kind", json!("domain")),
                            ("value", json!(value)),
                            ("target", json!("trade")),
                        ],
                    )));
                }
            }
            ("click", View::Split) if id == "reset-trade-domains" => {
                // 一条命令整体替换交易出口的网站名单：逐个 `split-add` 中途失败会留下半份默认值。
                steps.push(Step::Sync(cmd("split-reset-trade-domains", &[])));
            }
            ("change", View::Deploy) if id == "spec" => {
                self.deploy_spec = value.to_string();
                self.deploy_invalidate_probe();
            }
            ("change", View::Deploy) if id == "name" => self.deploy_label = value.to_string(),
            ("change", View::Deploy) if id == "user" => {
                self.deploy_user = value.to_string();
                self.deploy_invalidate_probe();
            }
            ("change", View::Deploy) if id == "port" => {
                self.deploy_port = value.to_string();
                self.deploy_invalidate_probe();
            }
            ("change", View::Deploy) if id == "password" => {
                self.deploy_password = value.to_string()
            }
            // 登录方式：切换即作废已输入的凭据（旧版的 `ClearDeploymentCredentialUI` 的前半）。
            // 不清的话「先填密码、再切私钥」会把那个密码当口令发出去。
            // **不 `restructure()`**：重绘会让接下来 ≤2 秒内的字段输入被 `Generation`
            // 闸门静默丢弃（r87 的坑；依据见 r92 设计 §4.8）。代价是标签不随动——
            // 所以密码框标签固定、私钥那句原文以常驻说明带出。
            ("change", View::Deploy) if id == "login-method" => {
                let next = if number.unwrap_or(0) == 1 { 1 } else { 0 };
                if next != self.deploy_login {
                    self.deploy_login = next;
                    self.deploy_password.clear();
                }
            }
            ("change", View::Deploy) if id == "key-path" => {
                self.deploy_key_path = value.to_string()
            }
            // 三个兼容连接选择：**只改内存、不重绘**（与登录方式同一条理由）。
            ("change", View::Deploy) if id == "transport" => {
                self.deploy_transport = number.unwrap_or(0).clamp(0, 2) as usize
            }
            ("change", View::Deploy) if id == "tcp-port" => {
                let next = if number.is_some() {
                    // 下拉回包是索引（0..2），换算成端口文本。
                    DEPLOY_TCP_PORTS
                        .get(number.unwrap_or(0).max(0) as usize)
                        .map(|(id, _)| (*id).to_string())
                } else {
                    Some(value.to_string())
                };
                if let Some(next) = next {
                    if DEPLOY_TCP_PORTS.iter().any(|(id, _)| *id == next) {
                        self.deploy_tcp_port = next;
                    }
                }
            }
            ("change", View::Deploy) if id == "server-name" => {
                self.deploy_server_name = value.to_string()
            }
            ("click", View::Deploy) if id == "pick-key" => {
                steps.push(Step::Sync(cmd("pick-file", &[("slot", json!("key"))])));
            }
            // 云端放行确认：只记状态，**不重绘**。
            // 重绘会把 `Generation` +1，页面还拿着上一代——下一次 `change` 会被闸门
            // 静默丢掉（r87 的坑）。按钮不做成 disabled（那需要重绘才能生效），
            // 改成点「开始部署」时校验，理由写在 `deploy_start_steps`。
            ("change", View::Deploy) if id == "deploy-cloud" => {
                self.deploy_cloud = flag.unwrap_or(false)
            }
            // 复选框回传的是**布尔**（`target.checked`），用 `as_str()` 取永远是空串。
            ("change", View::Deploy) if id == "remember-saved" => {
                self.deploy_remember_saved = msg.get("Value").and_then(Value::as_bool).unwrap_or(false)
            }
            ("change", View::Deploy) if id == "remember-task" => {
                self.deploy_remember_task = msg.get("Value").and_then(Value::as_bool).unwrap_or(false)
            }
            // r95：两个「使用已保存凭据」的勾只改内存、不重绘。
            ("change", View::Deploy) if id == "use-saved" => {
                self.deploy_use_saved = flag.unwrap_or(false)
            }
            ("change", View::Deploy) if id == "use-task" => {
                self.deploy_use_task = flag.unwrap_or(false)
            }
            ("click", View::Deploy) if id == "start" => {
                // 一页一按钮：先校验 → 落草稿 → 读指纹。指纹回来之后由宿主接着走
                // （`DeployFollowUp`）：已知身份直接投递，第一次接触先弹确认。
                //
                // **地址解析只在这里做一次**：`deploy_compose_target` 与后端
                // `ipc::deploy_target` 的判据一致（用户名缺省 root、端口缺省 22），
                // 区别只是它能用上旁边那两个输入框。
                if self.deploy_step == 5 {
                    // 已经有一次读指纹在路上：连点不该排队成两次握手。
                    return steps;
                }
                // 云端没放行就别往下走：这一步连指纹都不去读（读指纹要握手，握手本身
                // 没问题，但用户会以为「已经在部署了」）。判定必须**早于**任何落盘/投递。
                if !self.deploy_cloud {
                    self.deploy_notice =
                        "请先核对云端已放行部署端口（UDP 入站，并保留 SSH 入口），再开始部署。".into();
                    self.restructure();
                    return steps;
                }
                let spec = match deploy_compose_target(
                    &self.deploy_spec,
                    &self.deploy_user,
                    &self.deploy_port,
                ) {
                    Ok(spec) => spec,
                    Err(message) => {
                        self.deploy_notice = message;
                        self.restructure();
                        return steps;
                    }
                };
                // 私钥模式的两条前置（空路径 / 文件不在）：**连指纹都不读**。
                // 只碰非秘密；真正的私钥解析在后端。顺序在地址之后、落草稿之前。
                if let Err(message) = self.deploy_key_precheck() {
                    self.deploy_notice = message;
                    self.restructure();
                    return steps;
                }
                // 兼容连接三格（端口/握手域名）：同样在**读指纹之前**判。
                if let Err(message) = self.deploy_transport_precheck() {
                    self.deploy_notice = message;
                    self.restructure();
                    return steps;
                }
                // r95：已知服务器且有可复用凭据时，第一次点击停在「已读到指纹」的表单，
                // 让用户决定用不用保存的资料；地址没变就跳过重复 probe，直接投递。
                if self.deploy_step == 1
                    && !self.deploy_fingerprint.is_empty()
                    && self.deploy_probed_spec == spec
                {
                    return self.deploy_start_steps();
                }
                // 地址按规范串回填：用户写 `192.168.1.1` + 端口 2222 之后，
                // 页面上看到的就是真正会用的那个地址，不会有第二份真相。
                self.deploy_spec = spec.clone();
                self.deploy_notice = "正在核对服务器身份…".into();
                self.deploy_step = 5;
                self.restructure();
                // 草稿先落盘（不带指纹：还没读到）。`Absorbed` 带不了命令，
                // 所以这一批只能是「存草稿 + 读指纹」，投递留到回包之后。
                steps.push(Step::Sync(cmd(
                    "deployment-draft-save",
                    &[
                        ("spec", json!(spec)),
                        ("label", json!(self.deploy_label.trim())),
                        ("remember", json!(self.deploy_remember_saved)),
                        ("rememberTask", json!(self.deploy_remember_task)),
                        // 登录方式与路径都是非秘密，草稿里要存：从草稿接着填的人
                        // 不该回到「服务器密码」。
                        ("loginMethod", json!(self.deploy_login_method())),
                        ("identityFile", json!(self.deploy_key_path.trim())),
                        // 兼容连接选择随草稿一起留（旧版的 `TransportIndex` / `DeployTcpPort` /
                        // `DeployServerName`），「接着填」不会回到默认值。
                        ("transport", json!(self.deploy_transport_word())),
                        ("tcpPort", json!(self.deploy_tcp_port.trim())),
                        ("serverName", json!(self.deploy_server_name.trim())),
                        ("runId", json!(self.deploy_draft_id)),
                    ],
                )));
                // `runId` 让宿主判断「这条草稿自己有没有任务级信封」；新部署不带。
                steps.push(Step::Long(cmd(
                    "server-probe",
                    &[("spec", json!(spec)), ("runId", json!(self.deploy_draft_id))],
                )));
            }
            ("click", View::Deploy) if id == "draft-discard" => {
                // 放弃这次填写：删掉那条草稿（不写 `Cancelled`、不碰引擎）。
                // 没有 id 说明页面与后端已经脱节，此时什么都不发——发一条必然被拒的命令
                // 只会让按钮看起来「点了没反应」。
                if self.deploy_draft_id.is_empty() {
                    self.deploy_notice = "这次填写还没有保存成草稿，关掉窗口即可。".into();
                    self.restructure();
                    return steps;
                }
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-cancel",
                    &[("runId", json!(self.deploy_draft_id))],
                )));
            }
            ("click", View::Deploy) if id == "retry" => {
                self.deploy_step = 0;
                self.deploy_notice.clear();
                self.deploy_fingerprint.clear();
                self.deploy_password.clear();
                self.deploy_run_id.clear();
                self.deploy_draft_id.clear();
                self.deploy_run = Value::Null;
                self.deploy_pause_pending = false;
                self.restructure();
            }
            // ---- 部署任务详情（T07）：这一页由磁盘上的那条记录驱动 ----
            ("change", View::Deploy) if id == "run-password" => {
                self.deploy_password = value.to_string()
            }
            ("click", View::Deploy) if id == "run-go" => {
                // 与渲染按钮时**同一个判据**：有未决写就只能核对。这里若自己再判一次
                // 「是不是 Reconcile」，就会出现「按钮说核对、命令却重发写」。
                let (verify_only, text) = deploy_primary(&self.deploy_run);
                if text.is_empty() {
                    // 没有主动作时页面本来不该有按钮；真点到了就什么都不做。
                    return steps;
                }
                // 需要凭据这一步没填密码就不发：命令层也会拒，但让用户先看见输入框。
                let needs_password = !verify_only
                    && self
                        .deploy_run
                        .get("NextAction")
                        .and_then(Value::as_str)
                        == Some("EnterCredentials");
                if needs_password && self.deploy_password.is_empty() {
                    self.deploy_notice = "请先填写服务器登录密码。".into();
                    self.restructure();
                    return steps;
                }
                let mut fields = vec![
                    ("runId", json!(self.deploy_run_id)),
                    ("verifyOnly", json!(verify_only)),
                ];
                if !self.deploy_password.is_empty() {
                    fields.push(("password", json!(self.deploy_password)));
                }
                // 密码交给宿主后本机立刻丢掉：快照里再也拿不到它。
                self.deploy_password.clear();
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd("deployment-continue", &fields)));
            }
            ("click", View::Deploy) if id == "run-pause" => {
                // 页面给按钮时用的是同一条判据（`Running`）；这里再判一次，
                // 是因为点下去到宿主受理之间，这一步可能已经跑完了。
                let running = self
                    .deploy_run
                    .get("Running")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !running || self.deploy_pause_pending {
                    return steps;
                }
                self.deploy_pause_pending = true;
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-pause",
                    &[("runId", json!(self.deploy_run_id))],
                )));
            }
            ("click", View::Deploy) if id == "run-background" => {
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-background",
                    &[("runId", json!(self.deploy_run_id))],
                )));
            }
            ("click", View::Deploy) if id == "run-export" => {
                // 导出的是**这条记录**，不是「当前页面」。没打开记录就什么都不发：
                // 发出去必然被拒，只会让按钮看起来「点了没反应」。
                if self.deploy_run_id.is_empty() {
                    self.deploy_notice = "还没有打开任何部署任务。".into();
                    self.restructure();
                    return steps;
                }
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-export",
                    &[("runId", json!(self.deploy_run_id))],
                )));
            }
            ("click", View::Deploy) if id == "run-archive" || id == "run-unarchive" => {
                if self.deploy_run_id.is_empty() {
                    self.deploy_notice = "还没有打开任何部署任务。".into();
                    self.restructure();
                    return steps;
                }
                let archived = id == "run-archive";
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-archive",
                    &[("runId", json!(self.deploy_run_id)), ("archived", json!(archived))],
                )));
            }
            ("click", View::Deploy) if id == "run-cancel" => {
                self.deploy_cancel_pending = true;
                self.restructure();
            }
            ("click", View::Deploy) if id == "run-cancel-back" => {
                self.deploy_cancel_pending = false;
                self.restructure();
            }
            ("click", View::Deploy) if id == "run-cancel-confirm" => {
                self.deploy_cancel_pending = false;
                self.deploy_notice.clear();
                self.restructure();
                steps.push(Step::Sync(cmd(
                    "deployment-cancel",
                    &[("runId", json!(self.deploy_run_id))],
                )));
            }
            ("click", View::Devices) if id == "refresh" => {
                self.devices = Value::Null;
                self.pending_revoke = None;
                self.pending_forget = None;
                self.device_rename_index = None;
                self.draft.clear();
                self.uninstall_preview = Value::Null;
                self.uninstall_running = false;
                self.notice.clear();
                self.restructure();
                steps.push(Step::Long(cmd(
                    "server-devices",
                    &[("Id", json!(self.line_id))],
                )));
            }
            // 「移除」：先进入确认层。索引来自按钮 id，公钥从当前列表取——
            // 页面回传的值不参与判断（改一个数字就能删错设备）。
            ("click", View::Devices)
                if id
                    .strip_prefix("revoke-")
                    .map(|rest| rest.parse::<usize>().is_ok())
                    .unwrap_or(false) =>
            {
                if let Ok(index) = id.trim_start_matches("revoke-").parse::<usize>() {
                    let key = self
                        .devices
                        .get("devices")
                        .and_then(Value::as_array)
                        .and_then(|list| list.get(index))
                        .filter(|device| {
                            device.get("thisDevice").and_then(Value::as_bool) != Some(true)
                        })
                        .and_then(|device| device.get("publicKey"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if !key.is_empty() {
                        self.pending_revoke = Some(key);
                        self.notice.clear();
                        self.restructure();
                    }
                }
            }
            ("click", View::Devices) if id == "revoke-cancel" => {
                self.pending_revoke = None;
                self.restructure();
            }
            ("click", View::Devices) if id == "revoke-confirm" => {
                if let Some(key) = self.pending_revoke.take() {
                    self.notice = "正在移除…".into();
                    self.notice_tone = "muted";
                    self.restructure();
                    steps.push(Step::Long(cmd(
                        "server-revoke",
                        &[("Id", json!(self.line_id)), ("PublicKey", json!(key))],
                    )));
                }
            }
            // 「删除记录」：只清服务器上的孤儿名称。索引同样只当索引用，
            // 公钥一律从当前列表取——页面回传的值不参与判断。
            ("click", View::Devices)
                if id
                    .strip_prefix("forget-")
                    .map(|rest| rest.parse::<usize>().is_ok())
                    .unwrap_or(false) =>
            {
                if let Ok(index) = id.trim_start_matches("forget-").parse::<usize>() {
                    let key = self
                        .devices
                        .get("orphanNames")
                        .and_then(Value::as_array)
                        .and_then(|list| list.get(index))
                        .and_then(|orphan| orphan.get("publicKey"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if !key.is_empty() {
                        self.pending_forget = Some(key);
                        self.notice.clear();
                        self.restructure();
                    }
                }
            }
            ("click", View::Devices) if id == "forget-cancel" => {
                self.pending_forget = None;
                self.restructure();
            }
            ("click", View::Devices) if id == "forget-confirm" => {
                if let Some(key) = self.pending_forget.take() {
                    self.notice = "正在删除记录…".into();
                    self.notice_tone = "muted";
                    self.restructure();
                    steps.push(Step::Long(cmd(
                        "server-device-forget",
                        &[("Id", json!(self.line_id)), ("PublicKey", json!(key))],
                    )));
                }
            }
            ("change", View::Devices) if id == "name" && self.device_rename_index.is_some() => {
                self.draft = value.to_string();
            }
            ("click", View::Devices) if id == "save-device-rename" => {
                let name = self.draft.trim().to_string();
                if name.is_empty() || name.chars().count() > 64 {
                    self.notice = "请填写 1–64 个字的设备名称".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                if name.chars().any(char::is_control) {
                    self.notice = "设备名称不能包含换行、制表符等控制字符".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                let key = self
                    .device_rename_index
                    .and_then(|index| {
                        self.devices
                            .get("devices")
                            .and_then(Value::as_array)
                            .and_then(|list| list.get(index))
                    })
                    .and_then(|device| device.get("publicKey"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if key.is_empty() {
                    self.notice = "找不到这台设备，请刷新后再试。".into();
                    self.notice_tone = "warn";
                    self.restructure();
                    return steps;
                }
                steps.push(Step::Long(cmd(
                    "server-device-rename",
                    &[
                        ("Id", json!(self.line_id)),
                        ("PublicKey", json!(key)),
                        ("Name", json!(name)),
                    ],
                )));
            }
            ("click", View::Devices) if id == "cancel-device-rename" => {
                self.device_rename_index = None;
                self.draft.clear();
                self.notice.clear();
                self.notice_tone = "muted";
                self.restructure();
            }
            ("click", View::Devices)
                if id == "uninstall-preview" || id == "uninstall-confirm" =>
            {
                let server_id = self
                    .devices
                    .get("server")
                    .and_then(|server| server.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if server_id.is_empty() {
                    self.notice = "读不到服务器记录标识，请刷新后再试。".into();
                    self.notice_tone = "warn";
                    self.restructure();
                } else {
                    let command = if id == "uninstall-preview" {
                        "server-uninstall-preview"
                    } else {
                        "server-uninstall"
                    };
                    self.uninstall_running = true;
                    self.uninstall_preview = Value::Null;
                    self.notice.clear();
                    self.restructure();
                    steps.push(Step::Long(cmd(command, &[("id", json!(server_id))])));
                }
            }
            ("click", View::Devices) if id == "uninstall-cancel" => {
                self.uninstall_running = false;
                self.uninstall_preview = Value::Null;
                self.restructure();
            }
            // ---------- AI 工具名单：添加/移除/输入只改宿主草稿 ----------
            // 一行一颗按钮，`Id` 两种状态共用（`builtin-<id>`）——从 `Id` 认不出方向，
            // 方向由**草稿现状**决定：不在名单里就加、在名单里就去掉。
            // 走向**不在这一页改**（旧版同样）：它归应用页的「AI 工具」那一行，
            // 这里只按读到的走向决定状态行文案与保存内容。早先这一页也有个下拉，
            // 与设置页同一个值两处入口，用户要在两边找「到底哪个算数」。
            ("click", View::Agents) if id.starts_with("builtin-") => {
                let item = id.trim_start_matches("builtin-").to_string();
                if let Some(at) = self.agents_builtin.iter().position(|kept| kept == &item) {
                    self.agents_builtin.remove(at);
                } else {
                    self.agents_builtin.push(item);
                }
                // r104：一行会**换段**（名单内 ↔ 折叠区），整段结构都变了——
                // 必须重建页面，只打补丁会把行留在原地、把分组标题错位。
                self.restructure();
            }
            ("change", View::Agents) if id == "site" => self.agents_site_draft = value.to_string(),
            ("click", View::Agents) if id == "add-site" => {
                let normalized = crate::config::SplitConfig::normalize_domain(&self.agents_site_draft);
                if let Err(e) = crate::config::SplitConfig::validate_domain(&normalized) {
                    self.agents_note = e;
                    self.restructure();
                    return steps;
                }
                if self.agents_sites.iter().any(|kept| kept == &normalized) {
                    self.agents_note = format!("{normalized} 已经在名单里");
                } else {
                    // 记进「本轮见过」：这样它即使还没保存就被移除，行也还在（按钮翻「添加」）。
                    self.note_agent_seen("site", &normalized);
                    self.agents_sites.push(normalized);
                    self.agents_note.clear();
                }
                self.agents_site_draft.clear();
                self.restructure();
            }
            ("click", View::Agents) if id == "pick-program" => {
                // 复用既有文件选择器：`target` 沿用已存在的值（不扩枚举），
                // 真正要用的是回包里的 `processName`。选完**直接进草稿列表**，没有中间态。
                steps.push(Step::Sync(cmd("pick-exe", &[("target", json!("trade"))])));
            }
            // 自定义条目行上的「移除 / 添加」：行号指的是**当次渲染**里那份
            // 「基线 ∪ 草稿」列表（`agents_custom_values`），所以要先按同一份口径取值。
            ("click", View::Agents) if id.starts_with("toggle-") => {
                let rest = &id["toggle-".len()..];
                let parsed = rest
                    .strip_prefix("program-")
                    .map(|index| ("program", index))
                    .or_else(|| rest.strip_prefix("site-").map(|index| ("site", index)));
                if let Some((kind, index)) = parsed {
                    if let Ok(index) = index.parse::<usize>() {
                        let values = self.agents_custom_values(kind);
                        if let Some(value) = values.get(index).cloned() {
                            let draft = if kind == "program" {
                                &mut self.agents_programs
                            } else {
                                &mut self.agents_sites
                            };
                            if let Some(at) =
                                draft.iter().position(|kept| kept.eq_ignore_ascii_case(&value))
                            {
                                // 移除 = 真的从草稿里删掉（没有「保存后移除」这种中间态）。
                                draft.remove(at);
                            } else {
                                draft.push(value);
                            }
                            self.restructure();
                        }
                    }
                }
            }
            ("click", View::Agents) if id == "discard" => {
                let base = self.agents_base.clone();
                self.agents_lane = if base.lane == crate::config::AgentsLane::Trade { 1 } else { 0 };
                self.agents_builtin = base.builtin.clone();
                self.agents_programs = base.programs.clone();
                self.agents_sites = base.sites.clone();
                // 放弃修改 = 这一轮没发生过：连「见过」的记忆一起丢掉。
                self.agents_seen.clear();
                self.agents_note.clear();
                self.restructure();
            }
            ("click", View::Agents) if id == "save" => {
                // **一次保存 = 一条命令**，内容是当前草稿的全量（走向 + 三类条目）。
                let draft = self.current_agents_draft();
                steps.push(Step::Sync(cmd(
                    "agents-save",
                    &[
                        ("Lane", json!(draft.lane.id())),
                        ("Builtin", json!(draft.builtin)),
                        ("Programs", json!(draft.programs)),
                        ("Sites", json!(draft.sites)),
                    ],
                )));
            }
            ("click", _) if id == "back" => {
                // 关闭由调用方看 `closed()` 决定；这里只做一个不可再触发命令的空转。
            }
            _ => {}
        }
        steps
    }

    /// 读指纹的回包：成功就定下一步（直接开始 / 先确认身份），失败留在原地说明原因。
    ///
    /// 「下一步」用 [`DeployFollowUp`] 交出去而不是在这里发命令：吸收发生在合并
    /// 路径里，在那儿发命令会递归进合并。宿主 `finish_op` 取走后接着发。
    pub fn absorb_probe(&mut self, reply: &Value) -> Absorbed {
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
        if !ok {
            // 失败要回到「可以再点一次开始」的状态：地址、账户、密码一个都不许清，
            // 否则用户改一个字符就要从头再填一遍。
            self.deploy_step = 0;
            self.deploy_followup = None;
            self.deploy_notice = reply_message(reply, "读不到主机指纹");
            self.restructure();
            return Absorbed::Keep;
        }
        let probe = reply.get("serverProbe").cloned().unwrap_or(Value::Null);
        self.deploy_fingerprint = probe
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.deploy_known = probe.get("known").and_then(Value::as_bool).unwrap_or(false);
        // r95：两个「使用已保存凭据」的勾只在真的有那一档时出现。
        self.deploy_saved_available = probe
            .get("savedCredential")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        self.deploy_task_available = probe
            .get("taskCredential")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if self.deploy_fingerprint.is_empty() {
            self.deploy_step = 0;
            self.deploy_probed_spec.clear();
            self.deploy_followup = None;
            self.deploy_notice = "服务器没有回报主机指纹，请重试。".into();
        } else {
            self.deploy_step = 1;
            let host = probe
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("");
            let port = probe.get("port").and_then(Value::as_u64).unwrap_or(0);
            let user = probe
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or("");
            self.deploy_probed_spec = format!("{user}@{host}:{port}");
            self.deploy_notice.clear();
            // 已有记录 = 身份早核对过；没有记录才是「首次接触」，必须先确认指纹。
            // r95：已有记录且**有可复用凭据**时停在表单，让用户先决定用不用保存的资料；
            // 没有可复用凭据时保持旧行为（直接开始）。
            let has_choice = self.deploy_known
                && (self.deploy_saved_available || self.deploy_task_available);
            self.deploy_followup = if has_choice {
                None
            } else if self.deploy_known {
                Some(DeployFollowUp::Start)
            } else {
                Some(DeployFollowUp::ConfirmIdentity)
            };
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 「当前绑定」一句话：只说磁盘上的事实，不说「刚才点了什么」。
    fn bound_sentence(&self) -> String {
        if self.net_stale && !self.net_stale_name.is_empty() {
            return format!("当前绑定：{}（这台电脑上没有）", self.net_stale_name);
        }
        if self.net_bound.is_empty() {
            if self.net_default.is_empty() {
                return "当前绑定：跟随系统默认（默认网卡读不到）".to_string();
            }
            return format!("当前绑定：跟随系统默认（{}）", self.net_default);
        }
        format!("当前绑定：{}", self.net_bound)
    }

    /// 下拉当前选中的网卡名；空串 = 跟随系统默认。
    fn net_selected_name(&self) -> String {
        if self.net_pick == 0 {
            return String::new();
        }
        if let Some(name) = self.net_interfaces.get(self.net_pick - 1) {
            return name.clone();
        }
        // 越界且确实处在「指定了、但这台电脑上没有」的状态：把那个名字再发一次
        // （服务端会拦下并说明），而不是悄悄变成「跟随默认」——后者会让用户
        // 以为改了绑定，其实什么都没改。
        if self.net_stale {
            return self.net_stale_name.clone();
        }
        String::new()
    }

    /// `line-network` 的读与写共用一个 `lineNetwork` 键，所以只有一段吸收逻辑：
    /// 两边都必须同时刷新「本机有哪些网卡」与「这条线路指定了哪张」，
    /// 否则页面会拿旧列表去做下一次写。
    pub fn absorb_line_network(&mut self, state: &Value) -> Absorbed {
        let network = state.get("lineNetwork").cloned().unwrap_or(Value::Null);
        if !network.is_object() {
            // 失败回包（没有 `lineNetwork`）不许清掉用户已经选的项：清了他要重选一遍。
            self.notice = reply_message(state, "读不到本机网卡");
            self.notice_tone = "warn";
            self.restructure();
            return Absorbed::Keep;
        }
        self.net_default = network
            .get("Default")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.net_bound = network
            .get("Bound")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.net_stale = network.get("Stale").and_then(Value::as_bool).unwrap_or(false);
        self.net_stale_name = network
            .get("StaleName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.net_interfaces = network
            .get("Interfaces")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // 选中项跟着**回包里的绑定值**重算，不跟着页面刚才点的下标：保存成功后
        // 宿主会写回规范名（空格/大小写可能与用户点的那个不同），下标必须重算；
        // 指定了但不在列表里时，那一项排在下拉最后（`interfaces.len() + 1`）。
        self.net_pick = if self.net_bound.is_empty() {
            0
        } else if let Some(position) = self
            .net_interfaces
            .iter()
            .position(|name| name == &self.net_bound)
        {
            position + 1
        } else {
            self.net_interfaces.len() + 1
        };
        let ok = state.get("ok").and_then(Value::as_bool).unwrap_or(true);
        if !ok {
            self.notice = reply_message(state, "保存出口网卡失败");
            self.notice_tone = "warn";
        } else if let Some(message) = state
            .get("message")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
        {
            self.notice = message.to_string();
            self.notice_tone = "muted";
        } else if self.notice == LOADING_INTERFACES {
            // 读到结果了，那句「正在读取」要收掉。
            self.notice.clear();
        }
        // 其余情况**保留**原提示：成功回包会被吸收两次（一次是命令原文，一次是
        // 下一帧的合并状态，而 `merge_ui_command_reply` 成功时**不带** `message`）。
        // 第二次要是无条件清空，用户就看不到「已保存」——r89 真机验收抓到的就是这个：
        // 磁盘已经写进去了，页面上却像什么都没发生。
        self.restructure();
        Absorbed::Keep
    }

    /// 「服务器与设备」的回包。失败时也把错误留在表单里——页面不该只剩一句 Toast。
    pub fn absorb_devices(&mut self, reply: &Value) -> Absorbed {
        self.devices = reply
            .get("serverDevices")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"error": reply_message(reply, "读不到设备列表")}));
        // 改名成功后的整页刷新：收掉输入框并给一句结论。刷新按钮会先清掉
        // `device_rename_index`，所以这里只在「确实有改名在途」时触发。
        if self.device_rename_index.take().is_some() {
            self.draft.clear();
            self.notice = "设备名称已更新".into();
            self.notice_tone = "muted";
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 设备改名失败：保留输入框与草稿，只把原因贴在页面上。
    pub fn absorb_device_rename(&mut self, reply: &Value) -> Absorbed {
        let message = reply
            .get("serverDeviceRename")
            .and_then(|value| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("");
        self.notice = if message.is_empty() {
            reply_message(reply, "改名失败")
        } else {
            message.to_string()
        };
        self.notice_tone = "warn";
        self.restructure();
        Absorbed::Keep
    }

    /// 卸载预览回包：成功展示影响面；失败也留在页面上，让用户能重试或取消。
    pub fn absorb_uninstall_preview(&mut self, reply: &Value) -> Absorbed {
        self.uninstall_running = false;
        match reply.get("serverUninstallPreview") {
            Some(preview) => {
                let error = preview.get("error").and_then(Value::as_str).unwrap_or("");
                self.uninstall_preview = if error.is_empty() {
                    preview.clone()
                } else {
                    serde_json::json!({"error": error})
                };
            }
            None => {
                self.uninstall_preview =
                    serde_json::json!({"error": reply_message(reply, "读不到卸载预览")});
            }
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 卸载执行回包：成功就把设备区标成「已卸载」，避免继续显示过期的设备列表。
    pub fn absorb_uninstall(&mut self, reply: &Value) -> Absorbed {
        self.uninstall_running = false;
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(true);
        if ok {
            self.uninstall_preview = Value::Null;
            self.notice = "通道服务已卸载，云服务器未释放".into();
            self.notice_tone = "muted";
            self.devices = serde_json::json!({
                "error": "通道服务已卸载，云服务器未释放。重新部署后才能再次读取设备状态。",
            });
        } else {
            let message = reply
                .get("serverUninstall")
                .and_then(|value| value.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("");
            self.notice = if message.is_empty() {
                reply_message(reply, "卸载失败")
            } else {
                message.to_string()
            };
            self.notice_tone = "warn";
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 「删除本机部署资料」的预览回包 → 一张确认框。
    ///
    /// 预览一个字节都没写，所以这里除了给出结论什么都不改：列表与提示都保持原样。
    /// `Blocked` 非空时**不给危险按钮**，`Scope` 也不是 `server-cleanup`——否则那句
    /// 「知道了」会被宿主的 `confirmDialog` 当成确认，把删除命令发出去。
    pub fn absorb_server_cleanup_preview(&mut self, reply: &Value) -> Absorbed {
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let detail = reply.get("serverCleanup").cloned().unwrap_or(Value::Null);
        let target = detail
            .get("Id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| self.server_cleanup.clone())
            .unwrap_or_default();
        self.server_cleanup_request = Some(if !ok {
            let message = reply_message(reply, "读不出要删除的内容，请稍后重试。");
            server_cleanup_dialog(&target, &message, true)
        } else {
            let blocked = detail
                .get("Blocked")
                .and_then(Value::as_str)
                .unwrap_or("");
            if blocked.is_empty() {
                server_cleanup_dialog(&target, &server_cleanup_body(&detail), false)
            } else {
                server_cleanup_dialog(&target, blocked, true)
            }
        });
        self.restructure();
        Absorbed::Keep
    }

    /// 执行回包：成功刷新列表，被拦或读不出来就留原话。
    ///
    /// `Failed` 非空时**必须显眼**：那一句与「全部删干净」长得几乎一样，最容易被当成
    /// 成功——而文件其实还在磁盘上。
    pub fn absorb_server_cleanup(&mut self, reply: &Value) -> Absorbed {
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
        self.server_cleanup = None;
        if ok {
            if let Some(list) = reply.get("servers").and_then(Value::as_array) {
                self.items = list.clone();
            }
            let detail = reply
                .get("serverCleanupResult")
                .cloned()
                .unwrap_or(Value::Null);
            let message = detail.get("Message").and_then(Value::as_str).unwrap_or("");
            let failed = detail
                .get("Failed")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            self.notice = if message.is_empty() {
                "已删除这台服务器在本机的部署资料".to_string()
            } else {
                message.to_string()
            };
            self.notice_tone = if failed > 0 { "warn" } else { "muted" };
        } else {
            self.notice = reply_message(reply, "删除本机资料失败");
            self.notice_tone = "warn";
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 宿主取走「要弹的确认框」。
    pub fn take_server_cleanup_dialog(&mut self) -> Option<Value> {
        self.server_cleanup_request.take()
    }

    /// 撤销设备的回包。
    ///
    /// 成功就把这台设备从本地列表里摘掉——写操作真的发生了，列表不该还挂着它；
    /// 服务器回报的剩余台数与本地对不上时如实说，让人点「刷新」核对，而不是替它圆场。
    pub fn absorb_revoke(&mut self, reply: &Value) -> Absorbed {
        self.pending_revoke = None;
        if let Some(detail) = reply.get("serverRevoke") {
            if let Some(error) = detail.get("error").and_then(Value::as_str) {
                self.notice = format!("没有移除这台设备：{error}");
                self.notice_tone = "warn";
            } else {
                let key = detail.get("publicKey").and_then(Value::as_str).unwrap_or("");
                let peers = detail.get("peers").and_then(Value::as_u64).unwrap_or(0);
                // 撤销只摘 peer，服务器上的名字记录还在：把它移到孤儿区块，
                // 用户才能顺手清理。名字服务不可用时不做这一步。
                let names_available = self
                    .devices
                    .get("namesAvailable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let removed = self
                    .devices
                    .get_mut("devices")
                    .and_then(Value::as_array_mut)
                    .and_then(|list| {
                        let index = list.iter().position(|device| {
                            device.get("publicKey").and_then(Value::as_str) == Some(key)
                        })?;
                        Some(list.remove(index))
                    });
                if names_available {
                    if let Some(device) = removed {
                        let name = device.get("name").and_then(Value::as_str).unwrap_or("");
                        if !name.is_empty() {
                            if let Some(object) = self.devices.as_object_mut() {
                                let entry = object
                                    .entry("orphanNames")
                                    .or_insert_with(|| serde_json::json!([]));
                                if let Some(orphans) = entry.as_array_mut() {
                                    orphans.push(serde_json::json!({
                                        "publicKey": key,
                                        "shortKey": key.chars().take(8).collect::<String>(),
                                        "name": name,
                                        "updatedAtUtc": "",
                                    }));
                                }
                            }
                        }
                    }
                }
                let listed = self
                    .devices
                    .get("devices")
                    .and_then(Value::as_array)
                    .map(|list| list.len() as u64)
                    .unwrap_or(0);
                self.notice = if listed == peers {
                    format!("已移除这台设备，服务器上还剩 {peers} 台。")
                } else {
                    format!("已移除这台设备；服务器上还剩 {peers} 台，本页列 {listed} 台，可点刷新核对。")
                };
                self.notice_tone = "muted";
            }
        }
        self.restructure();
        Absorbed::Keep
    }

    /// 删除孤儿名称记录的回包：成功就从孤儿区块里摘掉那一条。
    pub fn absorb_device_forget(&mut self, reply: &Value) -> Absorbed {
        self.pending_forget = None;
        if let Some(detail) = reply.get("serverDeviceForget") {
            if let Some(error) = detail.get("error").and_then(Value::as_str) {
                self.notice = format!("没有删除这条记录：{error}");
                self.notice_tone = "warn";
            } else {
                let key = detail.get("publicKey").and_then(Value::as_str).unwrap_or("");
                let removed = detail
                    .get("removed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(orphans) = self
                    .devices
                    .get_mut("orphanNames")
                    .and_then(Value::as_array_mut)
                {
                    orphans.retain(|orphan| {
                        orphan.get("publicKey").and_then(Value::as_str) != Some(key)
                    });
                }
                self.notice = if removed {
                    "名称记录已删除。隧道与邀请审计不受影响。".into()
                } else {
                    "服务器上没有这条名称记录（可能已被删除）。".into()
                };
                self.notice_tone = "muted";
            }
        }
        self.restructure();
        Absorbed::Keep
    }

    pub fn absorb(&mut self, command: &str, reply: &Value) -> Absorbed {
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(true);
        match (command, self.view) {
            // ---- 服务器一览（只读）----
            ("servers", View::Servers) => {
                self.items = reply
                    .get("servers")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                // 读失败时把原话留在页面上：只弹一句 Toast，页面会显示成「还没有记录」，
                // 那是把「读不出来」说成「没有」。
                self.notice = if ok {
                    String::new()
                } else {
                    reply_message(reply, "读不到服务器记录")
                };
                self.restructure();
                Absorbed::Keep
            }
            ("server-rename", View::Servers) => {
                if ok {
                    let target = self.server_rename.clone();
                    let renamed = self.draft.trim().to_string();
                    match reply.get("servers").and_then(Value::as_array) {
                        Some(list) => self.items = list.clone(),
                        // 列表读不出来时改名本身已经成功：至少把本页的名称换掉。
                        None => {
                            if let (Some(id), false) = (target.as_deref(), renamed.is_empty()) {
                                if let Some(item) = self.items.iter_mut().find(|item| {
                                    item.get("Id").and_then(Value::as_str) == Some(id)
                                }) {
                                    item["Name"] = json!(renamed);
                                }
                            }
                        }
                    }
                    self.server_rename = None;
                    self.draft.clear();
                    // 成功回包的 `message` **不会**被宿主合并（`merge_ui_command_reply`
                    // 只在 ok:false 时带 message）。提示必须从刷新后的列表里取名字，
                    // 否则页面永远只显示兜底那句。
                    let shown = target
                        .as_deref()
                        .and_then(|id| {
                            self.items.iter().find(|item| {
                                item.get("Id").and_then(Value::as_str) == Some(id)
                            })
                        })
                        .and_then(|item| item.get("Name").and_then(Value::as_str))
                        .unwrap_or("");
                    self.notice = if shown.is_empty() {
                        "名称已经保存".to_string()
                    } else {
                        format!("已改名为「{shown}」")
                    };
                    self.notice_tone = "muted";
                } else {
                    // 失败时保留输入框与草稿：改一下再点保存，不必从头再来。
                    self.notice = reply_message(reply, "改名失败");
                    self.notice_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            ("server-remove", View::Servers) => {
                if ok {
                    if let Some(list) = reply.get("servers").and_then(Value::as_array) {
                        self.items = list.clone();
                    }
                    self.notice = "已删除服务器记录".into();
                    self.notice_tone = "muted";
                } else {
                    // 后端拒绝（例如刚好还有线路关联）时也要把原话留在页面上。
                    self.notice = reply_message(reply, "删除失败");
                    self.notice_tone = "warn";
                }
                self.server_remove = None;
                self.restructure();
                Absorbed::Keep
            }
            // ---- 管理恢复资料（r94） ----
            ("recovery-export", View::Recovery) => {
                let detail = reply.get("recovery").cloned().unwrap_or(Value::Null);
                if ok {
                    self.recovery_package = detail
                        .get("Package")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    self.recovery_file_name = detail
                        .get("FileName")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    self.recovery_notice = detail
                        .get("Message")
                        .and_then(Value::as_str)
                        .unwrap_or("恢复包已加密。")
                        .to_string();
                    self.recovery_notice_tone = "muted";
                    // 加密已经完成，密码不再需要留在内存里。
                    self.recovery_password.clear();
                    self.recovery_credential_password.clear();
                } else {
                    self.recovery_notice = reply_message(reply, "没能生成恢复包");
                    self.recovery_notice_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            ("recovery-import", View::Recovery) => {
                let detail = reply.get("recovery").cloned().unwrap_or(Value::Null);
                if ok {
                    self.recovery_done = true;
                    self.recovery_text.clear();
                    self.recovery_password.clear();
                    self.recovery_notice = detail
                        .get("Message")
                        .and_then(Value::as_str)
                        .unwrap_or("管理资料已登记，实际登录与服务器身份仍待核验。")
                        .to_string();
                    self.recovery_notice_tone = "muted";
                } else {
                    self.recovery_notice = reply_message(reply, "没能导入恢复包");
                    self.recovery_notice_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            ("save-file", View::Recovery) => {
                let detail = reply.get("fileSave").cloned().unwrap_or(Value::Null);
                if detail.is_null() {
                    self.recovery_notice = reply_message(reply, "保存没有完成");
                    self.recovery_notice_tone = "warn";
                } else if detail.get("cancelled").and_then(Value::as_bool).unwrap_or(true) {
                    // 取消：保留已生成的包，用户可以再点一次。
                } else if let Some(path) = detail
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                {
                    self.recovery_saved_path = path.to_string();
                    self.recovery_notice = format!("恢复包已保存到 {path}");
                    self.recovery_notice_tone = "muted";
                } else {
                    self.recovery_notice = reply_message(reply, "保存结果缺少路径");
                    self.recovery_notice_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            // 恢复资料页的两个「选择…」：`key` 填私钥路径，`recovery` 把文件内容读进来。
            ("pick-file", View::Recovery) => {
                let pick = reply.get("filePick").cloned().unwrap_or(Value::Null);
                if pick.is_null() {
                    self.recovery_notice = reply_message(reply, "选择文件没有完成");
                    self.recovery_notice_tone = "warn";
                } else if pick.get("cancelled").and_then(Value::as_bool).unwrap_or(true) {
                    // 取消：什么都不改。
                } else if pick.get("slot").and_then(Value::as_str) == Some("key") {
                    if let Some(path) = pick.get("path").and_then(Value::as_str) {
                        self.recovery_key_path = path.to_string();
                    }
                } else if let Some(text) = pick.get("text").and_then(Value::as_str) {
                    self.recovery_text = text.to_string();
                } else if let Some(path) = pick.get("path").and_then(Value::as_str) {
                    self.recovery_notice =
                        format!("读不到恢复包文件的内容：{path}。请直接粘贴恢复包文本。");
                    self.recovery_notice_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            // 部署向导里「选择…」私钥：宿主回的是整份状态 + `filePick`。
            // 取消**不清空旧值**（与分流/名单那两条同一条规矩）：用户选错了再点一次，
            // 不该把他已经填好的路径弄丢。
            ("pick-file", View::Deploy) => {
                let pick = reply.get("filePick").cloned().unwrap_or(Value::Null);
                if pick.is_null() {
                    // 选择器本身失败（宿主原话在 `error`/`message` 里）：照抄，
                    // 不能一律说成「没有选择私钥文件」。
                    self.deploy_notice = reply_message(reply, "选择私钥文件没有完成");
                } else if pick.get("cancelled").and_then(Value::as_bool).unwrap_or(true) {
                    // 取消：什么都不改。
                } else if let Some(path) = pick
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                {
                    self.deploy_key_path = path.to_string();
                    self.deploy_notice.clear();
                } else {
                    self.deploy_notice = reply_message(reply, "选择结果缺少路径，请重试");
                }
                self.restructure();
                Absorbed::Keep
            }
            // ---- 部署任务（T07）----
            ("deployment-start", View::Deploy) => {
                if !ok {
                    self.deploy_step = 4;
                    self.deploy_notice = reply_message(reply, "没能在磁盘上建立部署任务");
                    self.restructure();
                    return Absorbed::Keep;
                }
                let detail = reply.get("deployment").cloned().unwrap_or(Value::Null);
                let run_id = detail
                    .get("RunId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.deploy_notice = detail
                    .get("Message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.deploy_pause_pending = false;
                if run_id.is_empty() {
                    // 没有编号就跟不了这次部署：宁可如实说没开始，也不能让页面一直转圈。
                    self.deploy_step = 4;
                    self.deploy_notice = "服务器没有返回任务编号，无法跟踪这次部署。".into();
                } else {
                    // 记录已经落盘：从这里开始一律由记录驱动，旧五步状态机不再参与。
                    self.deploy_run_id = run_id.clone();
                    // 草稿已经变成一条真正的任务：那一格必须清掉。否则后面在**详情页**
                    // 点「取消这次部署」会命中「丢弃草稿」那条收尾，把详情页也关掉——
                    // 而详情页的取消只是「已受理」，页面得留着看接下来发生什么。
                    self.deploy_draft_id.clear();
                    self.deploy_run = json!({
                        "RunId": run_id,
                        "State": "Queued",
                        "StepsDone": 0,
                        "Steps": [],
                        "NextAction": "WaitQueue",
                        "Label": "新部署任务",
                    });
                    self.deploy_step = 2;
                }
                self.restructure();
                Absorbed::Keep
            }
            // 导出诊断摘要（P2-3）：回包是 `exportResult{path,bytes,format,message}`。
            // 这个键本来就在 `UI_REPLY_KEYS` 里（`export-history` 用的同一份），
            // 所以不需要再动白名单——但仍然要在这里登记，否则回包落不到页面上。
            ("deployment-export", View::Deploy) => {
                let message = reply
                    .get("exportResult")
                    .and_then(|result| result.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if ok {
                    self.deploy_notice = if message.is_empty() {
                        "已导出诊断摘要。".to_string()
                    } else {
                        message.to_string()
                    };
                } else {
                    self.deploy_notice = reply_message(reply, "导出没有完成");
                }
                self.restructure();
                Absorbed::Keep
            }
            // ---- 部署草稿（r69）：落盘结果只影响「有没有一条可以接着填的草稿」 ----
            //
            // 这个分支必须在这里登记：漏了它，回包落地失败、`deploy_draft_id` 永远为空，
            // 每点一次「读取指纹」都会新建一条草稿（上线第一天就把上限 3 撞满）。
            ("deployment-draft-save", View::Deploy) => {
                let detail = reply.get("deployment").cloned().unwrap_or(Value::Null);
                let run_id = detail
                    .get("Run")
                    .and_then(|run| run.get("RunId"))
                    .and_then(Value::as_str)
                    .or_else(|| detail.get("RunId").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string();
                if ok && !run_id.is_empty() {
                    self.deploy_draft_id = run_id;
                }
                if !ok {
                    // **不挡填写**：写不进去是小事，把用户弹回第 0 步才是大事。
                    // 只追加一句，`deploy_step` 一个字节都不动，紧随其后的 probe 照发。
                    let hint = "（这次没能保存草稿，关掉窗口后地址要重填）";
                    if !self.deploy_notice.contains(hint) {
                        self.deploy_notice.push_str(hint);
                    }
                }
                self.restructure();
                Absorbed::Keep
            }
            (
                "deployment-get" | "deployment-continue" | "deployment-cancel"
                | "deployment-background" | "deployment-pause" | "deployment-archive",
                View::Deploy,
            ) => {
                let detail = reply.get("deployment").cloned().unwrap_or(Value::Null);
                if let Some(run) = detail.get("Run").filter(|value| !value.is_null()) {
                    if self.deploy_run != *run {
                        self.deploy_run = run.clone();
                        // 记录动了：「已受理…」那句提示已经过期，留着会让人以为还没开始。
                        self.deploy_notice.clear();
                    }
                }
                if command == "deployment-pause" {
                    // 只有真的受理了才挂「已请求暂停」；失败就撤掉，别让页面停在假状态。
                    self.deploy_pause_pending = ok
                        && detail.get("PauseRequested").and_then(Value::as_bool) == Some(true);
                }
                if !ok {
                    self.deploy_notice = reply_message(reply, "这一步没有完成");
                } else if let Some(message) = detail.get("Message").and_then(Value::as_str) {
                    if !message.is_empty() {
                        self.deploy_notice = message.to_string();
                        // 归档/恢复会改记录：下一帧 `refresh_run` 会看到「记录动了」。
                        // 这句话必须活过那一帧，否则用户点了按钮什么也读不到。
                        if command == "deployment-archive" {
                            self.deploy_notice_pinned = true;
                        }
                    }
                }
                // 草稿丢弃成功：**关掉这一页**。判据是「命令是 cancel」+「当前是向导形态
                // （`deploy_draft_id` 非空）」+ `ok`——不读 `Discarded`：那份回包里的键没有
                // 登记进 `UI_REPLY_KEYS`，页面根本读不到它（详情页那条旧路径仍走下面
                // 的 `Absorbed::Keep`，一个字不改：`ok` 是标准键）。
                if command == "deployment-cancel" && !self.deploy_draft_id.is_empty() && ok {
                    return Absorbed::Close("已放弃这份草稿，没有留下任务记录。".to_string());
                }
                self.restructure();
                Absorbed::Keep
            }
            ("rename-line", View::Rename) => {
                if ok {
                    self.notice.clear();
                    Absorbed::Close(reply_message(reply, "线路名称已保存"))
                } else {
                    self.notice = reply_message(reply, "改名没有完成");
                    self.notice_tone = "warn";
                    self.restructure();
                    Absorbed::Keep
                }
            }
            // 出口网卡的读与写：同一段吸收（两边的回包长一个样）。
            ("line-network" | "line-network-set", View::LineSettings) => {
                let out = self.absorb_line_network(reply);
                if matches!(command, "line-network-set") && ok {
                    Absorbed::Toast(reply_message(reply, "出口网卡已保存，下次连接生效"))
                } else {
                    out
                }
            }
            // 补兼容连接：结论句由命令给（含端口与握手域名），页面贴在按钮下面。
            // 成功时**不**改当前连接方式：补一条线路只是多一个可选，替用户切过去是另一件事。
            ("line-add-compatible", View::LineSettings) => {
                let payload = reply.get("lineCompatible").cloned().unwrap_or(Value::Null);
                if ok {
                    self.compat_note = payload
                        .get("Message")
                        .and_then(Value::as_str)
                        .filter(|text| !text.trim().is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| "已补上兼容连接。".to_string());
                    self.compat_tone = "success";
                } else {
                    self.compat_note = reply_message(reply, "没有补上兼容连接");
                    self.compat_tone = "warn";
                }
                self.restructure();
                Absorbed::Keep
            }
            ("set-transport", View::LineSettings) => {
                if ok {
                    // 回包带线路列表：按 id 取回真实 transport，别拿点击的档位当事实。
                    if let Some(t) = reply
                        .get("lines")
                        .and_then(Value::as_array)
                        .and_then(|items| {
                            items
                                .iter()
                                .find(|l| l.get("id").and_then(Value::as_str) == Some(&self.line_id))
                        })
                        .and_then(|l| l.get("transport"))
                        .and_then(Value::as_str)
                    {
                        self.method = if t == "udp" { "Udp" } else { "Tcp" }.to_string();
                    }
                    self.notice.clear();
                    self.restructure();
                    Absorbed::Toast(reply_message(reply, "连接方式已保存，下次连接生效"))
                } else {
                    self.notice = reply_message(reply, "连接方式没有保存");
                    self.notice_tone = "warn";
                    self.restructure();
                    Absorbed::Keep
                }
            }
            ("history-delete", View::History) => {
                let hidden = reply
                    .get("historyDelete")
                    .and_then(|value| value.get("deleted"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                self.history_checked.clear();
                return if hidden == 0 {
                    Absorbed::Toast("没有隐藏任何记录（可能已经隐藏过了）。".into())
                } else {
                    Absorbed::Toast(format!("已隐藏 {hidden} 条操作记录。"))
                };
            }
            ("history-restore", View::History) => {
                let restored = reply
                    .get("historyRestore")
                    .and_then(|value| value.get("restored"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let pending = std::mem::take(&mut self.history_restore_pending);
                if restored > 0 {
                    // 就地改 `Hidden`：紧接着不会有 `history` 重读，不补这一步页面
                    // 会一直显示「已隐藏（旧版）」，直到用户重新进页面。
                    for item in self.items.iter_mut() {
                        let is_pending = item
                            .get("Key")
                            .and_then(Value::as_str)
                            .map(|key| pending.iter().any(|p| p == key))
                            .unwrap_or(false);
                        if is_pending {
                            if let Some(obj) = item.as_object_mut() {
                                obj.insert("Hidden".to_string(), json!(false));
                            }
                        }
                    }
                    self.history_checked.clear();
                    self.restructure();
                    Absorbed::Toast(format!("已恢复显示 {restored} 条记录。"))
                } else {
                    Absorbed::Toast("没有恢复任何记录（可能已经恢复了）。".into())
                }
            }
            ("history", View::History) => {
                self.items = reply
                    .get("events")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.notice = if self.items.is_empty() {
                    "还没有记录".into()
                } else {
                    String::new()
                };
                // 同理不自增代数：列表换了，但控件 id 一个没变。
                Absorbed::Keep
            }
            ("export-history", _) => {
                if ok {
                    Absorbed::Toast(reply_message(reply, "已导出当前筛选的记录"))
                } else {
                    Absorbed::Toast(reply_message(reply, "导出没有完成"))
                }
            }
            ("diagnose", View::Diagnose) => {
                self.absorb_diagnose(reply);
                Absorbed::Keep
            }
            ("maintenance-status", View::Maintenance) => {
                self.maintenance = reply.get("maintenance").cloned().unwrap_or(Value::Null);
                self.notice.clear();
                self.restructure();
                Absorbed::Keep
            }
            ("restore", View::Maintenance) => {
                self.absorb_restore(reply);
                Absorbed::Keep
            }
            ("providers", View::Providers) => {
                self.providers = reply
                    .get("providers")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.notice = if self.providers.is_empty() {
                    "还没有登记代理软件。".into()
                } else {
                    String::new()
                };
                self.restructure();
                Absorbed::Keep
            }
            ("provider-discover", View::Providers) => {
                let found = reply.get("found").and_then(Value::as_array).cloned().unwrap_or_default();
                let errors = reply.get("errors").and_then(Value::as_array).cloned().unwrap_or_default();
                match found.first() {
                    Some(d) => {
                        let kind = d.get("kind").and_then(Value::as_str).unwrap_or("");
                        self.kind = KIND_ITEMS.iter().position(|(id, _)| *id == kind).unwrap_or(0);
                        self.port = d
                            .get("dailyPort")
                            .and_then(Value::as_u64)
                            .map(|p| p.to_string())
                            .unwrap_or_default();
                        self.domains = d
                            .get("domains")
                            .and_then(Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join("，")
                            })
                            .unwrap_or_default();
                        self.notice = format!(
                            "已找到 {}：目录 {}，日常端口 {}。填名称后点添加。",
                            KIND_ITEMS.get(self.kind).map(|(_, l)| *l).unwrap_or("代理软件"),
                            d.get("directory").and_then(Value::as_str).unwrap_or(""),
                            d.get("dailyPort").and_then(Value::as_u64).unwrap_or(0)
                        );
                    }
                    None => {
                        let mut parts: Vec<String> = errors
                            .iter()
                            .map(|e| {
                                format!(
                                    "{}：{}",
                                    e.get("label").and_then(Value::as_str).unwrap_or(""),
                                    e.get("error").and_then(Value::as_str).unwrap_or("")
                                )
                            })
                            .collect();
                        if parts.is_empty() {
                            parts.push("没有找到已安装的代理软件".into());
                        }
                        self.notice = parts.join("；");
                    }
                }
                self.restructure();
                Absorbed::Keep
            }
            ("provider-add", View::Providers) => {
                if let Some(list) = reply.get("providers").and_then(Value::as_array) {
                    self.providers = list.clone();
                }
                if ok {
                    self.draft.clear();
                    self.port.clear();
                    self.domains.clear();
                }
                self.notice = reply_message(reply, if ok { "已登记代理软件" } else { "添加没有完成" });
                self.restructure();
                Absorbed::Toast(self.notice.clone())
            }
            ("provider-remove", View::Providers) => {
                if let Some(list) = reply.get("providers").and_then(Value::as_array) {
                    self.providers = list.clone();
                }
                self.pending_remove = None;
                self.notice = reply_message(reply, if ok { "已删除服务商" } else { "删除没有完成" });
                self.restructure();
                Absorbed::Toast(self.notice.clone())
            }
            ("split", View::Split)
            | ("split-add", View::Split)
            | ("split-remove", View::Split)
            | ("split-reset-trade-domains", View::Split) => {
                self.processes = reply
                    .get("processes")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.domain_rules = reply
                    .get("domains")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                // 名单重新载入 = 这次定位结束：成功已应用，失败也不该继续挂着旧路径。
                self.locate_index = None;
                self.locate_path = None;
                let host_said = reply.get("splitMessage").and_then(Value::as_str).unwrap_or("");
                if !host_said.is_empty() {
                    self.notice = host_said.to_string();
                } else if self.processes.is_empty() && self.domain_rules.is_empty() {
                    self.notice = "还没有添加任何条目".into();
                } else {
                    self.notice.clear();
                }
                if command == "split-add" && ok {
                    // 只清刚才那个输入框：添加网站不该把用户另一行没提交的程序路径抹掉。
                    match self.split_add_kind.as_str() {
                        "process" => self.program_path.clear(),
                        "domain" => self.draft.clear(),
                        _ => {}
                    }
                    self.split_add_kind.clear();
                }
                self.restructure();
                Absorbed::Keep
            }
            // AI 工具名单的回包：成功重填草稿、失败一个字段都不动（改动还在）。
            ("agents", View::Agents) => {
                self.fill_agents(reply);
                self.agents_note.clear();
                self.restructure();
                Absorbed::Keep
            }
            ("agents-save", View::Agents) => {
                if ok {
                    self.fill_agents(reply);
                    self.agents_note = reply
                        .get("agentsMessage")
                        .and_then(Value::as_str)
                        .unwrap_or("已保存")
                        .to_string();
                } else {
                    // **草稿一个字都不动**：用户的改动与输入还在，改完可以直接重试。
                    let said = reply
                        .get("error")
                        .and_then(Value::as_str)
                        .or_else(|| reply.get("message").and_then(Value::as_str))
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| reply_message(reply, "没有保存成功，改动还在"));
                    if reply.get("errorCode").and_then(Value::as_str) == Some("busy") {
                        // 连接中：保存按钮变成「请先断开再保存」并禁用，只留「放弃修改」。
                        self.agents_busy = true;
                    }
                    self.agents_note = said;
                }
                self.restructure();
                Absorbed::Keep
            }
            ("pick-exe", View::Agents) => {
                let pick = reply.get("filePick").cloned().unwrap_or(Value::Null);
                let cancelled = pick.get("cancelled").and_then(Value::as_bool).unwrap_or(true);
                if pick.is_null() {
                    // 选择失败（选中的不是 .exe / 选择器本身出错）：把宿主那句话照抄过来，
                    // 不能一律说成「没有选择程序」——那会把「选错了文件」说成「用户取消了」。
                    self.agents_note = reply_message(reply, "选择程序没有完成");
                } else if cancelled {
                    self.agents_note = "没有选择程序".into();
                } else if let Some(name) =
                    pick.get("processName").and_then(Value::as_str).map(str::to_string)
                {
                    // 选中的程序直接进草稿列表（名单页没有「目标出口」下拉，中间态没意义）。
                    // 与自定义网站同口径记进「本轮见过」：还没保存就被移除时行要还在。
                    self.note_agent_seen("program", &name);
                    if !self.agents_programs.iter().any(|kept| kept.eq_ignore_ascii_case(&name)) {
                        self.agents_programs.push(name.clone());
                    }
                    self.agents_note = format!("已添加：{name}；点保存后生效");
                } else {
                    self.agents_note = reply_message(reply, "选择结果缺少进程名，请重试");
                }
                self.restructure();
                Absorbed::Keep
            }
            ("pick-exe", View::Split) => {
                let pick = reply.get("filePick").cloned().unwrap_or(Value::Null);
                let cancelled = pick.get("cancelled").and_then(Value::as_bool).unwrap_or(true);
                let locating = self.locate_index.is_some();
                if cancelled {
                    self.locate_index = None;
                    self.locate_path = None;
                    self.notice = "没有选择程序".into();
                } else if locating {
                    // 「确认程序位置」：先记下路径，等用户点「保存位置」再写配置。
                    match pick.get("path").and_then(Value::as_str) {
                        Some(path) => {
                            let name = pick.get("processName").and_then(Value::as_str).unwrap_or("");
                            self.locate_path = Some(path.to_string());
                            self.notice = if name.is_empty() {
                                "已选择程序；点「保存位置」应用到这一条".to_string()
                            } else {
                                format!("已选择：{name}；点「保存位置」应用到这一条")
                            };
                        }
                        None => {
                            self.locate_index = None;
                            self.locate_path = None;
                            self.notice = reply_message(reply, "选择结果缺少路径，请重试");
                        }
                    }
                } else if let Some(path) =
                    pick.get("path").and_then(Value::as_str).filter(|p| !p.trim().is_empty())
                {
                    // 「浏览…」只回填输入框，不立刻写配置（旧版就是两步）。
                    self.program_path = path.to_string();
                    let name = pick.get("processName").and_then(Value::as_str).unwrap_or("");
                    self.notice = if name.is_empty() {
                        "已选择程序；点「添加程序」".to_string()
                    } else {
                        format!("已选择：{name}；点「添加程序」")
                    };
                } else if let Some(name) = pick.get("processName").and_then(Value::as_str) {
                    self.program_path = name.to_string();
                    self.notice = format!("已选择：{name}；点「添加程序」");
                } else {
                    self.notice = reply_message(reply, "选择结果缺少进程名，请重试");
                }
                self.restructure();
                Absorbed::Keep
            }
            _ => Absorbed::Keep,
        }
    }

    /// 还原也是长命令（30 秒预算），回包走 `finish_op`；同步路径复用同一份。
    pub fn absorb_restore(&mut self, state: &Value) {
        self.running = false;
        if let Some(m) = state.get("maintenance") {
            self.maintenance = m.clone();
        }
        self.notice = reply_message(state, "还原没有完成");
        self.notice_tone = "muted";
        self.restructure();
    }

    /// `guard-remove` 的长命令回包。只有回读通过（后端给出 `UserRemoved`）才许说「已解除」；
    /// 被拒 UAC、WFP 删除失败、回读失败都停在失败文案，绝不冒充成功。
    pub fn absorb_guard_remove(&mut self, state: &Value) {
        self.running = false;
        self.guard_remove_pending = false;
        let removed = state.get("guardRemove").cloned().unwrap_or(Value::Null);
        let ok = removed.get("ok").and_then(Value::as_bool) == Some(true);
        let guard = removed.get("guard").cloned().unwrap_or(Value::Null);
        let reason = guard
            .get("GuardEvidence")
            .and_then(|e| e.get("Reason"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if ok && reason == "UserRemoved" {
            self.notice = guard
                .get("GuardSummary")
                .and_then(Value::as_str)
                .unwrap_or("交易保护已解除；下次连接会重新启用。")
                .to_string();
            self.notice_tone = "muted";
        } else {
            self.notice = removed
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| removed.get("error").and_then(Value::as_str))
                .or_else(|| state.get("error").and_then(Value::as_str))
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("解除没有完成；规则可能仍在，需要管理员确认后才能解除。")
                .to_string();
            self.notice_tone = "warn";
        }
        self.restructure();
    }

    /// 诊断是长命令，回包走 `finish_op` 而不是 `absorb`。两条路径共用这一份填充。
    pub fn absorb_diagnose(&mut self, state: &Value) {
        self.running = false;
        match state.get("diagnose") {
            Some(d) => {
                self.items = d
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.verdict = d.get("verdict").cloned().unwrap_or(Value::Null);
                self.notice.clear();
            }
            None => {
                self.notice = reply_message(state, "诊断没有完成");
                self.notice_tone = "warn";
            }
        }
        self.restructure();
    }
}

/// 「自己搭服务器」读指纹回来之后要不要接着往下走、以及走哪条。
///
/// 为什么要这个枚举：`Absorbed` 的三个变体都带不了命令，而「读指纹 → 开始部署」
/// 必须在同一批里接上（否则用户会被要求点第二次「开始部署」，那就是 r85 那个
/// 被否掉的两次交互）。于是由宿主在 `finish_op` 之后取走它并执行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployFollowUp {
    /// 身份已知（这台服务器早就有记录）：直接落草稿 + 投递。
    Start,
    /// 第一次接触：先让用户确认指纹，确认后才投递。
    ConfirmIdentity,
}

/// `absorb` 的结论：表单继续显示、关闭（带一句成功话），或只弹一句。
pub enum Absorbed {
    Keep,
    Close(String),
    Toast(String),
}

/// 「正在读本机网卡」那一句。只有这一个来源：`line_settings` 拿它当开页提示，
/// `absorb_line_network` 拿它判「这句该收掉了」，测试拿它断言——三处各写一遍就会漂。
const LOADING_INTERFACES: &str = "正在读取本机网卡…";

/// 「删除本机部署资料」确认框的正文：逐项列出**真的会有**的东西（预览给的 `Items`）。
fn server_cleanup_body(detail: &Value) -> String {
    let name = detail.get("Name").and_then(Value::as_str).unwrap_or("");
    let items: Vec<&str> = detail
        .get("Items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let owner = if name.is_empty() {
        "这台服务器".to_string()
    } else {
        format!("「{name}」")
    };
    if items.is_empty() {
        // 预览至少会给「服务器记录」一项。拿不到就退一句实话，绝不自己编一份清单。
        format!("将删除这台电脑上属于{owner}的资料。")
    } else {
        format!("将删除这台电脑上属于{owner}的：{}。", items.join("；"))
    }
}

/// 一张确认框。`blocked = true` 时只有「知道了」。
///
/// `Confirm` 写空串会在页面上渲染成一个没有文字的按钮（`app.js` 的 `renderDialog`
/// 无条件渲染确认键），所以「只有知道了」按「删除线路被拦」那张卡的既有写法：
/// `Confirm` 是「知道了」、`Cancel` 空，并且 `Scope` 换一个——那条确认不做事。
fn server_cleanup_dialog(target: &str, body: &str, blocked: bool) -> Value {
    if blocked {
        return json!({
            "Id": "server-cleanup-blocked",
            "Title": "暂时不能删除这台服务器的本机资料",
            "Body": body,
            "Note": "",
            "Confirm": "知道了",
            "Cancel": "",
            "Danger": false,
            "Details": "",
            "Progress": false,
            "Scope": "server-cleanup-blocked",
            "Target": target,
        });
    }
    json!({
        "Id": "server-cleanup-confirm",
        "Title": "删除这台服务器在本机的部署资料？",
        "Body": body,
        "Note": "只删这台电脑上的记录与登录资料；服务器上的通道服务、线路与设备不受影响。",
        "Confirm": "删除本机资料",
        "Cancel": "先不删",
        "Danger": true,
        "Details": "",
        "Progress": false,
        "Scope": "server-cleanup",
        "Target": target,
    })
}

fn reply_message(reply: &Value, fallback: &str) -> String {
    reply
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| reply.get("detail").and_then(Value::as_str))
        .or_else(|| reply.get("error").and_then(Value::as_str))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn cmd(name: &str, fields: &[(&str, Value)]) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("cmd".into(), json!(name));
    for (k, v) in fields {
        obj.insert((*k).to_string(), v.clone());
    }
    Value::Object(obj).to_string()
}

/// 「多久以前」：握手时间是 unix 秒，界面上写绝对时间没人愿意换算。
fn ago_text(unix: i64) -> String {
    if unix <= 0 {
        return "从未握手".to_string();
    }
    let now = crate::model::now_epoch_secs_u64() as i64;
    let delta = now.saturating_sub(unix);
    match delta {
        d if d < 60 => "刚刚".to_string(),
        d if d < 3600 => format!("{} 分钟前", d / 60),
        d if d < 86_400 => format!("{} 小时前", d / 3600),
        d => format!("{} 天前", d / 86_400),
    }
}

/// 孤儿名称记录的一行标题：有名字写名字，没名字写短公钥。
fn orphan_label(orphan: &Value) -> String {
    let name = orphan.get("name").and_then(Value::as_str).unwrap_or("");
    let key = orphan.get("shortKey").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        format!("{key}…")
    } else {
        format!("{name}（{key}…）")
    }
}

/// 字节数按人读的单位写。用 1024 进制：这是流量统计的惯例，与磁盘厂商的 1000 不同。
fn bytes_text(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let value = bytes as f64;
    if value < KB {
        format!("{bytes} B")
    } else if value < MB {
        format!("{:.1} KB", value / KB)
    } else if value < GB {
        format!("{:.1} MB", value / MB)
    } else {
        format!("{:.2} GB", value / GB)
    }
}

fn muted(t: &str) -> Value {
    json!({"Kind":"text","Text":t,"Tone":"muted"})
}

/// 记录状态 → 人话。表外值一律「状态未知」，绝不猜成「进行中」或「已完成」。
fn deploy_state_word(state: &str) -> &'static str {
    match state {
        "Draft" => "草稿",
        "WaitingUser" => "等待确认",
        "Queued" => "排队中",
        "Running" => "正在部署",
        "NeedsAttention" => "需要处理",
        "Paused" => "已暂停",
        "Complete" => "已完成",
        "Cancelled" => "已取消",
        _ => "状态未知",
    }
}

fn deploy_step_word(status: &str) -> &'static str {
    match status {
        "Pending" => "待开始",
        "Running" => "进行中",
        "Done" => "已完成",
        "Failed" => "失败",
        "Skipped" => "已跳过",
        "Unknown" => "未核实",
        _ => "状态未知",
    }
}

/// 记录里的主行动作 → 这一次该按哪个按钮（唯一），以及是否只做只读核对。
///
/// **有未决写时只能核对**：这条优先级与 `deployrun::action_of` 一致（未决写 >
/// `NextAction`）。少了它，界面会给一个「重试」按钮，点下去就是「已经写出去的
/// 东西再写一遍」——`PendingOperation` 存在的全部意义就被抹掉了。
///
/// 第二个返回值是 `verify_only`：核对**只读**，绝不重发写命令。
/// 尝试历史（P1-4）：只读。
///
/// 三条口径：
/// - 只有**真有过一次结论**（`FinishedAtUtc` 非空）或**重试过**（`len >= 2`）才显示；
///   草稿、第一次还在跑的时候不显示，免得把「还没发生」写成历史。
/// - 没有结束时间的只有两种真相：最后一条且记录在跑 = 「正在进行」；其余 =
///   「没有拿到结论就停了」（崩溃/强杀留下的）。**不补假的结束时间**。
/// - 不给任何按钮：历史只读。重试永远是「按当前事实再做一次」，不是重放旧写命令。
fn attempt_history(run: &Value, running: bool) -> Vec<Value> {
    let Some(attempts) = run.get("Attempts").and_then(Value::as_array) else {
        return Vec::new();
    };
    if attempts.is_empty() {
        return Vec::new();
    }
    let concluded = attempts.iter().any(|item| {
        item.get("FinishedAtUtc")
            .map(|value| !value.is_null())
            .unwrap_or(false)
    });
    if attempts.len() < 2 && !concluded {
        return Vec::new();
    }

    let mut body = vec![muted(&format!("尝试历史（{} 次）", attempts.len()))];
    let last_index = attempts.len() - 1;
    for (index, item) in attempts.iter().enumerate() {
        let no = item
            .get("No")
            .and_then(Value::as_u64)
            .unwrap_or(index as u64 + 1);
        let started = item
            .get("StartedAtUtc")
            .and_then(Value::as_str)
            .unwrap_or("");
        let finished = item
            .get("FinishedAtUtc")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut line = if finished.is_empty() {
            let tail = if index == last_index && running {
                "正在进行"
            } else {
                "没有拿到结论就停了"
            };
            format!("#{no} · {} 开始 · {tail}", short_time(started))
        } else {
            format!(
                "#{no} · {} → {}",
                short_time(started),
                short_time(finished)
            )
        };
        if let Some(step) = item.get("FailedStep").and_then(Value::as_u64) {
            let name = run
                .get("Steps")
                .and_then(Value::as_array)
                .and_then(|steps| steps.get(usize::try_from(step).unwrap_or(0)))
                .and_then(|slot| slot.get("Name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if name.is_empty() {
                line.push_str(&format!(" · 失败在第 {} 步", step + 1));
            } else {
                line.push_str(&format!(" · 失败在第 {} 步（{}）", step + 1, name));
            }
        }
        let code = item
            .get("ErrorCode")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !code.is_empty() {
            line.push_str(&format!(" · 错误码 {code}"));
        }
        match item.get("Reconcile").and_then(Value::as_str).unwrap_or("") {
            "Needed" => line.push_str(" · 有未核对的写"),
            "Done" => line.push_str(" · 已核对"),
            _ => {}
        }
        body.push(muted(&line));
    }
    body.push(muted(
        "历史只读：重试是按当前事实再做一次，不会重放旧命令。",
    ));
    body
}

fn deploy_primary(run: &Value) -> (bool, &'static str) {
    // 草稿不是「进行中的任务」：它连地址与密码都还没确认完，这一页本来就该是向导。
    // 给它一个主按钮，点下去发的是 `deployment-continue`，而那条命令会让引擎把草稿
    // 直接推进队列（Draft→WaitingUser→Queued）——**一次没有密码的部署**。
    //
    // 这一支必须在最前面，早于 `OpenForm` 分支：草稿的默认 `NextAction` 正是 `OpenForm`。
    if run.get("State").and_then(Value::as_str) == Some("Draft") {
        return (false, "");
    }
    let next = run.get("NextAction").and_then(Value::as_str).unwrap_or("");
    if run_holds_pending_write(run) || next == "Reconcile" {
        return (true, "核对原操作");
    }
    // 暂停后记录把 `NextAction` 清成 `None`；「继续」必须重新排队。
    // 这一支放在未决写之后：暂停记录上若还挂着没核对的写，只能先核对。
    if run.get("State").and_then(Value::as_str) == Some("Paused") {
        return (false, "继续部署");
    }
    match next {
        "OpenForm" => (false, "开始部署"),
        "ConfirmPlan" => (false, "确认并开始"),
        "RetryStep" => (false, "重试这一步"),
        "EnterCredentials" => (false, "用这个密码继续"),
        "CompleteCompatible" => (false, "补齐兼容连接"),
        // `WaitQueue` / `None` / 表外：不给按钮——点了也不会发生任何事。
        _ => (false, ""),
    }
}

/// 有没有「已经发出去、还没核对」的写。取消时要把话说得不一样。
fn run_holds_pending_write(run: &Value) -> bool {
    run.get("PendingOperation")
        .and_then(|pending| pending.get("Outcome"))
        .and_then(Value::as_str)
        .map(|outcome| outcome == "Pending")
        .unwrap_or(false)
}

fn text_tone(t: &str, tone: &str) -> Value {
    json!({"Kind":"text","Text":t,"Tone":tone})
}

fn input(id: &str, name: &str, label: &str, value: &str, max: u32) -> Value {
    json!({
        "Kind": "input",
        "Id": id,
        "Name": name,
        "Label": label,
        "Value": value,
        "MaxLength": max,
    })
}

/// 密码框：**只回传「有没有填过」**，从不把值渲染回去。
///
/// 前端靠 `SecretPresent` 决定 placeholder（「已填写，重新输入可替换」）；
/// 把明文塞回 Value 会进快照、进 WebView 的 DOM、进而进崩溃转储。
fn secret(id: &str, name: &str, label: &str, present: bool, max: u32) -> Value {
    json!({
        "Kind": "password",
        "Id": id,
        "Name": name,
        "Label": label,
        "SecretPresent": present,
        "MaxLength": max,
    })
}

fn multiline(id: &str, name: &str, label: &str, value: &str) -> Value {
    json!({
        "Kind": "input",
        "Id": id,
        "Name": name,
        "Label": label,
        "Value": value,
        "Multiline": true,
        "MaxLength": 4096,
    })
}

/// 下拉：Value 是索引，与传进来的 items 顺序对齐。
fn select(
    id: &str,
    name: &str,
    label: &str,
    value: usize,
    items: &[(&str, &str)],
    disabled: bool,
) -> Value {
    let options: Vec<Value> = items
        .iter()
        .enumerate()
        .map(|(index, (_, text))| json!({"Index": index, "Label": text}))
        .collect();
    json!({
        "Kind": "select",
        "Id": id,
        "Name": name,
        "Label": label,
        "Value": value,
        "Items": options,
        "Disabled": disabled,
    })
}

fn button(id: &str, name: &str, text: &str, tone: &str, disabled: bool) -> Value {
    json!({
        "Kind": "button",
        "Id": id,
        "Name": name,
        "Text": text,
        "Tone": tone,
        "Disabled": disabled,
    })
}

fn row(children: Vec<Value>) -> Value {
    json!({"Kind": "row", "Children": children})
}

/// 右对齐：`.wf-row > [data-align="end"] { margin-left:auto }`。
/// 只能挂在**直接子节点**上——`row` 自己渲染时不带布局属性。
fn align_end(mut node: Value) -> Value {
    if let Some(obj) = node.as_object_mut() {
        obj.insert("Align".to_string(), json!("end"));
    }
    node
}

/// 给任意控件节点挂一条 `Hint`（0.22.0 的 `AutomationProperties.HelpText`）。
///
/// 前端把 `Hint` 统一渲染成一个 ⓘ：`hintFor(node, label)`（`web/app.js`）在
/// `text` / `button` / `input` / `password` / `select` / `check` / `details` 七种
/// `Kind` 上都接了它，所以「解释」不必再独占一行正文——控件只留动作，
/// 说明挂在控件自己身上，悬停/点开才展开。
///
/// 做成装饰器而不是给每个构造函数加一个 `Option<&str>` 参数：五处 `secret()`
/// 里只有一处需要提示，加参数会让另外四处各多一个 `None` 噪音；而且这套写法
/// 与上面的 `align_end` 一致（都是对已建好的节点补一个键）。
///
/// `Hint` 为空时不挂：一个点了没反应的 ⓘ 比没有更糟。
fn with_hint(mut node: Value, hint: &str) -> Value {
    let hint = hint.trim();
    if hint.is_empty() {
        return node;
    }
    if let Some(obj) = node.as_object_mut() {
        obj.insert("Hint".to_string(), json!(hint));
    }
    node
}

fn card(children: Vec<Value>) -> Value {
    json!({"Kind": "card", "Children": children})
}

/// 筛选用的分段按钮：当前档用 primary 标出。
fn tap(id: &str, label: &str, on: bool) -> Value {
    button(id, id, label, if on { "primary" } else { "ghost" }, false)
}

/// 复选框节点。前端把 `Value` 读成布尔（`node.Value ? 'checked' : ''`），
/// 勾选时回传的也是**布尔**（`submitForm(...,'change',target.checked)`）——
/// 宿主侧必须用 `as_bool()` 取值，用 `as_str()` 会永远拿到空串（「看起来做了但没生效」）。
fn check(id: &str, name: &str, text: &str, on: bool) -> Value {
    json!({
        "Kind": "check",
        "Id": id,
        "Name": name,
        "Text": text,
        "Value": on,
    })
}

/// 「在交易名单里」的键：同一句说明要区分程序与网站（`qq.com` 可能是程序名的一部分）。
fn in_trade_key(kind: &str, value: &str) -> String {
    format!("{kind}:{value}")
}

/// 字段标签。**输入框自己不带可见标签**（前端只把它当 `aria-label`），
/// 所以每颗输入框前面都得有这么一颗文本节点，否则页面上是一排没有标题的框。
fn field_label(t: &str) -> Value {
    json!({"Kind":"text","Text":t})
}

/// 折叠区（旧版的 `Expander`）。前端把它渲染成 `<details>`。
fn details(id: &str, title: &str, children: Vec<Value>, open: bool) -> Value {
    json!({
        "Kind": "details",
        "Id": id,
        "Name": id,
        "Text": title,
        "Open": open,
        "Children": children,
    })
}

/// 把「地址 + 账户 + 端口」拆成三元组。**规则只有一份**，`deploy_compose_target`
/// 与确认对话框都从这里拿，免得「对话框显示 root@host:22、实际发出去的是别的」。
///
/// 地址里写了的以地址为准（旧版的 `ConvertTo-TCDeploymentConnection` 同规则）；
/// 没写的用两个输入框的值，两者都空才落到 `root` / `22`。
fn deploy_split_target(spec: &str, user_field: &str, port_field: &str) -> (String, String, String) {
    let spec = spec.trim();
    let (user_in_spec, rest) = match spec.split_once('@') {
        Some((user, rest)) => (user.trim(), rest.trim()),
        None => ("", spec),
    };
    let fallback_user = {
        let user = user_field.trim();
        if user.is_empty() {
            "root"
        } else {
            user
        }
    };
    let user = if user_in_spec.is_empty() {
        fallback_user.to_string()
    } else {
        user_in_spec.to_string()
    };
    let (host, port_in_spec) = match rest.rsplit_once(':') {
        Some((host, port)) => (host.trim(), Some(port.trim())),
        None => (rest, None),
    };
    let fallback_port = {
        let port = port_field.trim();
        if port.is_empty() {
            "22"
        } else {
            port
        }
    };
    let port = match port_in_spec {
        Some(port) => port.to_string(),
        None => fallback_port.to_string(),
    };
    (user, host.to_string(), port)
}

/// 「地址 + 账户 + 端口」→ 后端认的那一串 `user@host:port`。
///
/// 校验放在这里而不是只靠 `ipc::deploy_target`：一次点击就该说清哪个字段不对，
/// 而不是等 probe 转 15 秒再回一句「地址有问题」。
fn deploy_compose_target(
    spec: &str,
    user_field: &str,
    port_field: &str,
) -> Result<String, String> {
    if spec.trim().is_empty() {
        return Err("请填写服务器地址，例如 root@203.0.113.10".to_string());
    }
    if spec.trim().contains(char::is_whitespace) {
        return Err("服务器地址里不能有空格。".to_string());
    }
    if spec.trim().starts_with('@') {
        return Err("服务器地址缺少用户名，例如 root@203.0.113.10".to_string());
    }
    let (user, host, port) = deploy_split_target(spec, user_field, port_field);
    if host.is_empty() {
        return Err("服务器地址缺少主机名，例如 root@203.0.113.10".to_string());
    }
    let parsed: u16 = port
        .parse()
        .map_err(|_| "SSH 端口必须是 1 到 65535 之间的数字。".to_string())?;
    if parsed == 0 {
        return Err("SSH 端口必须是 1 到 65535 之间的数字。".to_string());
    }
    if user.is_empty() {
        return Err("登录账户不能为空。".to_string());
    }
    Ok(format!("{user}@{host}:{parsed}"))
}

/// 内置项那一行的 `Hint` 文字：说明 + 域名清单合成**一条**（页面上只有一个 ⓘ）。
///
/// - 有说明有域名：`{detail}包含的网站：a、b、c`
/// - 只有说明：`{detail}`
/// - 只有域名：`包含的网站：a、b、c`
/// - 都没有：`None`（不挂 `Hint`，也就没有 ⓘ——一个点了没反应的图标比没有更糟）
///
/// 说明本身以「。」结尾时直接接「包含的网站」，不拼出两个句号。
fn entry_hint(entry: &AgentsEntryView) -> Option<String> {
    let mut hint = entry.detail.trim().to_string();
    if entry.domains.is_empty() {
        return if hint.is_empty() { None } else { Some(hint) };
    }
    if !hint.is_empty() && !hint.ends_with('。') && !hint.ends_with('.') {
        hint.push('。');
    }
    hint.push_str(&format!("包含的网站：{}", entry.domains.join("、")));
    Some(hint)
}

/// 内置项那行按钮的控件名：`claude-code` → `AgentsBuiltinClaudeCode`。
/// 控件名是自动化与页面调试的抓手，必须稳定且可读（不要用索引）。
fn builtin_action_name(id: &str) -> String {
    let mut out = String::from("AgentsBuiltin");
    for part in id.split('-') {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    out
}

/// 程序行（旧版「交易软件名单」）：名字 + 状态、路径，右侧「移除」。
///
/// 状态词来自回包，不在页面里猜：
/// - 没有路径 → `位置未确认`（并给「确认程序位置…」）；
/// - 路径存在为假 → `文件已移走`；
/// - 线路引擎配置里有这条进程规则 → `已生效`；
/// - 其余 → `未生效`。
fn split_program_row(
    index: usize,
    item: &Value,
    locate: Option<usize>,
    locate_ready: bool,
) -> Value {
    let value = item.get("value").and_then(Value::as_str).unwrap_or("");
    let path = item.get("path").and_then(Value::as_str).unwrap_or("");
    let exists = item.get("fileExists").and_then(Value::as_bool);
    let applied = item.get("applied").and_then(Value::as_bool).unwrap_or(false);
    let status = if path.is_empty() {
        "位置未确认"
    } else if exists == Some(false) {
        "文件已移走"
    } else if applied {
        "已生效"
    } else {
        "未生效"
    };

    let detail = if path.is_empty() {
        "位置未确认；点「确认程序位置…」补上".to_string()
    } else {
        path.to_string()
    };
    let mut cells = vec![json!({
        "Kind": "panel",
        "Children": [
            json!({"Kind":"text","Text": format!("{value} · {status}")}),
            muted(&detail),
        ],
    })];
    if path.is_empty() {
        if locate == Some(index) && locate_ready {
            cells.push(button("locate-apply", "LocateApply", "保存位置", "primary", false));
        } else if locate != Some(index) {
            cells.push(button(
                &format!("locate-{index}"),
                "LocatePick",
                "确认程序位置…",
                "ghost",
                false,
            ));
        }
    }
    cells.push(align_end(button(
        &format!("remove-process-{index}"),
        "RemoveSplit",
        "移除",
        "ghost",
        false,
    )));
    row(cells)
}

/// 网站行：域名在左，右侧「移除」。
fn split_site_row(index: usize, item: &Value) -> Value {
    let value = item.get("value").and_then(Value::as_str).unwrap_or("");
    row(vec![
        json!({"Kind":"text","Text": value}),
        align_end(button(
            &format!("remove-domain-{index}"),
            "RemoveSplit",
            "移除",
            "ghost",
            false,
        )),
    ])
}

/// 一条记录压成一行：时间 · 动作 · 结果 · 详情。
/// 操作记录页「来源」下拉的下标 → `events` 里的来源值。0 = 所有来源。
fn history_src_value(index: usize) -> &'static str {
    match index {
        1 => "ui",
        2 => "cli",
        3 => "auto",
        4 => "other",
        _ => "",
    }
}

fn event_line(event: &Value) -> String {
    let field = |key: &str| event.get(key).and_then(Value::as_str).unwrap_or("");
    let ok = event.get("ok").and_then(Value::as_bool).unwrap_or(true);
    let mut detail = field("detail").to_string();
    if detail.chars().count() > 60 {
        detail = detail.chars().take(60).collect::<String>() + "…";
    }
    let src = field("src");
    let when = short_time(field("ts"));
    let action = if field("action").is_empty() { "动作" } else { field("action") };
    let result = if ok { "成功" } else { "失败" };
    // 旧记录可能没有 `ts`：不要留一个开头的「 · 」。
    let mut line = if when.is_empty() {
        format!("{action} · {result}")
    } else {
        format!("{when} · {action} · {result}")
    };
    if !field("obj").is_empty() {
        line.push_str(&format!(" · {}", field("obj")));
    }
    if !detail.is_empty() {
        line.push_str(&format!(" · {detail}"));
    }
    if !src.is_empty() {
        line.push_str(&format!("（{src}）"));
    }
    line
}

/// 一条操作记录的完整字段（「详情」展开时用）。
///
/// 列表行把 `detail` 截到 60 字（一屏能扫），这里给**全文**：查「刚才那次为什么失败」
/// 的人要的正是那句没被截断的原话。空字段不渲染，免得一屏「对象：（空）」。
fn event_detail(event: &Value) -> Vec<Value> {
    let field = |key: &str| event.get(key).and_then(Value::as_str).unwrap_or("").trim();
    let mut out: Vec<Value> = Vec::new();
    // 除了「结果」这一行，还写出去了几个**有信息量**的字段。用它判断「是不是旧记录」：
    // 不能用 `out.len()`（旧记录只要带个 action，len 就 >1 了），也不把 `ts` / `action`
    // 算进来——那两项每条记录都有，真正的线索是「谁、对什么、发生了什么」。
    let mut extra = 0;
    let ts = field("ts");
    if !ts.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("时间：{ts}")}));
    }
    let action = field("action");
    if !action.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("动作：{action}")}));
        // `action` 不计入 `extra`：只有「动作 + 结果」的旧记录仍然算「没有更多字段」，
        // 那种记录对排查没有帮助，提示一句比让人对着两行发呆好。
    }
    let ok = event.get("ok").and_then(Value::as_bool);
    out.push(json!({
        "Kind": "text",
        "Text": format!(
            "结果：{}",
            match ok {
                Some(true) => "成功",
                Some(false) => "失败",
                // 旧记录没有这个字段：说「未记录」，不猜成成功。
                None => "未记录",
            }
        ),
    }));
    let src = field("src");
    if !src.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("来源：{}", source_word(src))}));
        extra += 1;
    }
    let actor = field("actor");
    if !actor.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("执行者：{actor}")}));
        extra += 1;
    }
    let obj = field("obj");
    if !obj.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("对象：{obj}")}));
        extra += 1;
    }
    let detail = field("detail");
    if !detail.is_empty() {
        out.push(json!({"Kind":"text","Text":format!("详情：{detail}")}));
        extra += 1;
    }
    // 一个额外字段都没有 ⇒ 这条记录确实没有别的信息（旧版本写的）。说清楚，
    // 别让人以为是详情没加载出来。
    if extra == 0 {
        out.push(muted("这条记录没有更多字段（可能是旧版本写的）。"));
    }
    out
}

/// 记录来源 → 人话。表外值原样给出：不认识就不翻译，也不丢。
fn source_word(src: &str) -> &str {
    match src {
        "ui" => "界面",
        "cli" => "命令行",
        "pipe" => "控制管道",
        "auto" => "自动收尾",
        other => other,
    }
}

/// RFC3339 → `MM-DD HH:MM`。只用于列表显示，不做时区换算（记录本来就是本地时间字符串）。
fn short_time(ts: &str) -> String {
    if ts.len() >= 16 && ts.as_bytes().get(10) == Some(&b'T') {
        format!("{} {}", &ts[5..10], &ts[11..16])
    } else {
        ts.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    /// 「补一条兼容连接」：默认只有一颗入口；点一下先问，确认后才发长命令。
    /// 这是本页唯一会改服务器的动作，必须两步。
    #[test]
    fn adding_a_compatible_line_asks_first_then_sends_the_command() {
        let mut form = FormState::line_settings("L1", "香港 01", "1.2.3.4:443", "Udp");
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("compat-add"), "默认要有入口：{text}");
        assert!(!text.contains("compat-yes"), "没点之前不该出现确认按钮：{text}");

        let steps = form.event(&json!({"Event": "click", "Id": "compat-add"}));
        assert!(steps.is_empty(), "点一下只改页面，不发命令：{steps:?}");
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("compat-yes") && text.contains("compat-no"), "{text}");
        assert!(text.contains("会改服务器配置"), "要先说清后果：{text}");

        // 取消：回到只有入口的状态，仍然不发命令。
        let steps = form.event(&json!({"Event": "click", "Id": "compat-no"}));
        assert!(steps.is_empty(), "{steps:?}");
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(!text.contains("compat-yes"), "{text}");

        form.event(&json!({"Event": "click", "Id": "compat-add"}));
        let steps = form.event(&json!({"Event": "click", "Id": "compat-yes"}));
        match steps.first() {
            Some(Step::Long(command)) => {
                assert!(command.contains("line-add-compatible"), "{command}");
                assert!(command.contains("L1"), "{command}");
            }
            other => panic!("必须走长命令（要 SSH）：{other:?}"),
        }
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("正在登录服务器补兼容连接"), "进行中要说清：{text}");
    }

    /// 回包落在按钮下面：成功贴命令原话（含端口），失败贴拒绝原因。
    #[test]
    fn the_compatible_line_reply_lands_on_the_page() {
        let mut form = FormState::line_settings("L1", "香港 01", "1.2.3.4:443", "Udp");
        form.absorb(
            "line-add-compatible",
            &json!({"ok": true, "lineCompatible": {"Message": "已补上兼容连接（TCP 8443，握手域名 www.bing.com）。"}}),
        );
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("已补上兼容连接（TCP 8443"), "{text}");

        form.absorb(
            "line-add-compatible",
            &json!({"ok": false, "error": "读不到这台服务器的隧道参数：这条线路不是在这台电脑上部署的。"}),
        );
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("读不到这台服务器的隧道参数"), "失败要把原话给用户：{text}");
    }

    #[test]
    fn durations_and_sizes_read_like_a_person_wrote_them() {
        assert_eq!(ago_text(0), "从未握手");
        let now = crate::model::now_epoch_secs_u64() as i64;
        assert_eq!(ago_text(now - 5), "刚刚");
        assert_eq!(ago_text(now - 125), "2 分钟前");
        assert_eq!(ago_text(now - 7300), "2 小时前");
        assert_eq!(ago_text(now - 200_000), "2 天前");

        assert_eq!(bytes_text(512), "512 B");
        assert_eq!(bytes_text(2048), "2.0 KB");
        assert_eq!(bytes_text(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(bytes_text(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    /// 尝试历史（P1-4）：两次尝试都上屏、只读、没有重放入口。
    #[test]
    fn the_detail_page_lists_attempt_history_read_only() {
        let run = serde_json::json!({
            "RunId": "r1",
            "State": "NeedsAttention",
            "StepsDone": 2,
            "Running": false,
            "NextAction": "RetryStep",
            "Name": "自建 · 203.0.113.10",
            "Label": "2/4 · 准备标准连接",
            "Steps": [
                {"Index":0,"Name":"检查服务器环境与身份","Status":"Done"},
                {"Index":1,"Name":"准备标准连接","Status":"Failed"},
                {"Index":2,"Name":"准备兼容连接","Status":"Pending"},
                {"Index":3,"Name":"登记线路并收尾","Status":"Pending"}
            ],
            "Reason": {"Category":"Failed","Code":"ListenFailed","Text":"端口被占用"},
            "Attempts": [
                {"No":1,"StartedAtUtc":"2026-11-12T10:00:00Z",
                 "FinishedAtUtc":"2026-11-12T10:03:00Z","FailedStep":1,
                 "ErrorCode":"ListenFailed","Reconcile":"NotNeeded"},
                {"No":2,"StartedAtUtc":"2026-11-12T10:10:00Z",
                 "FinishedAtUtc":null,"FailedStep":null,
                 "ErrorCode":"","Reconcile":"Needed"}
            ]
        });
        let text =
            serde_json::to_string(&FormState::deploy_run("r1", run).render()).unwrap_or_default();
        assert!(text.contains("尝试历史（2 次）"), "{text}");
        assert!(
            text.contains("#1 · 11-12 10:00 → 11-12 10:03"),
            "起止时间要能读：{text}"
        );
        assert!(
            text.contains("失败在第 2 步（准备标准连接）"),
            "失败步骤要带人话名：{text}"
        );
        assert!(text.contains("错误码 ListenFailed"), "{text}");
        assert!(
            text.contains("#2 · 11-12 10:10 开始 · 没有拿到结论就停了"),
            "没有结论的那次不许写「进行中」：{text}"
        );
        assert!(text.contains("有未核对的写"), "{text}");
        assert!(text.contains("历史只读"), "{text}");
        // 只读：历史里不许长出自己的动作（重试永远走主按钮）。
        assert!(!text.contains("retryAttempt"), "{text}");
        assert!(!text.contains("replayAttempt"), "{text}");
    }

    /// 旧版的`DeployFourSteps` 是**横排一行**：四步在同一 `row` 里，窄窗口由 CSS 换行。
    #[test]
    fn deploy_four_steps_render_as_one_horizontal_row_with_state_words() {
        let run = serde_json::json!({
            "RunId": "r1",
            "State": "NeedsAttention",
            "StepsDone": 1,
            "Running": false,
            "NextAction": "RetryStep",
            "Name": "自建 · 203.0.113.10",
            "Steps": [
                {"Index":0,"Name":"检查服务器环境与身份","Status":"Done"},
                {"Index":1,"Name":"准备标准连接","Status":"Failed"},
                {"Index":2,"Name":"准备兼容连接","Status":"Pending"},
                {"Index":3,"Name":"登记线路并收尾","Status":"Pending"}
            ],
            "Reason": {"Category":"Failed","Code":"ListenFailed","Text":"端口被占用"},
            "Attempts": []
        });
        let view = FormState::deploy_run("r1", run).render();
        let body = view["Nodes"][0]["Children"].as_array().expect("卡片正文");
        let steps_row = body
            .iter()
            .find(|node| {
                node["Kind"] == "row"
                    && node["Children"]
                        .as_array()
                        .map(|cells| cells.len() == 4 && cells.iter().all(|c| c["Kind"] == "text"))
                        .unwrap_or(false)
            })
            .expect("四步必须在同一行里");
        let texts: Vec<&str> = steps_row["Children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cell| cell["Text"].as_str().unwrap_or(""))
            .collect();
        let expected = ["检查服务器环境与身份", "准备标准连接", "准备兼容连接", "登记线路并收尾"];
        for (index, name) in expected.iter().enumerate() {
            assert!(texts[index].starts_with(&format!("{} {name}", index + 1)), "{texts:?}");
        }
        assert!(texts[0].contains("已完成"), "{texts:?}");
        assert!(texts[1].contains("失败"), "{texts:?}");
        assert!(texts[2].contains("待开始"), "{texts:?}");
        // 状态不能只靠颜色：失败那格必须是 bad，待开始那格是 muted。
        assert_eq!(steps_row["Children"][1]["Tone"], "bad");
        assert_eq!(steps_row["Children"][2]["Tone"], "muted");
    }

    /// 只有一次、且还没结论的尝试不该上屏：那时候「历史」还没发生。
    #[test]
    fn a_single_unfinished_attempt_has_no_history_block() {
        let run = serde_json::json!({
            "RunId": "r1",
            "State": "Running",
            "StepsDone": 0,
            "Running": true,
            "NextAction": "None",
            "Name": "自建 · 203.0.113.10",
            "Steps": [],
            "Attempts": [
                {"No":1,"StartedAtUtc":"2026-11-12T10:00:00Z","FinishedAtUtc":null,
                 "FailedStep":null,"ErrorCode":"","Reconcile":"NotNeeded"}
            ]
        });
        let text =
            serde_json::to_string(&FormState::deploy_run("r1", run).render()).unwrap_or_default();
        assert!(!text.contains("尝试历史"), "{text}");
    }

    /// 按 Id 在表单树里找节点：断言不该被「第几个孩子」这种脆弱索引钉住。
    fn node<'a>(nodes: &'a Value, id: &str) -> Option<&'a Value> {
        let list = nodes.as_array()?;
        for item in list {
            if item.get("Id").and_then(Value::as_str) == Some(id) {
                return Some(item);
            }
            if let Some(found) = item.get("Children").and_then(|c| node(c, id)) {
                return Some(found);
            }
        }
        None
    }

    /// 按**标签文字**找它的 `Hint`（r105 之后地址/密码的解释挂在标签上，
    /// 不在输入框上——输入框自己挂会变成两个 ⓘ）。
    fn hint_of_label(nodes: &Value, label: &str) -> String {
        fn walk(node: &Value, label: &str, out: &mut Option<String>) {
            if out.is_some() {
                return;
            }
            if node["Kind"] == "text" && node["Text"].as_str() == Some(label) {
                if let Some(hint) = node["Hint"].as_str() {
                    *out = Some(hint.to_string());
                    return;
                }
            }
            if let Some(children) = node["Children"].as_array() {
                for child in children {
                    walk(child, label, out);
                }
            }
        }
        let mut out = None;
        if let Some(list) = nodes.as_array() {
            for item in list {
                walk(item, label, &mut out);
            }
        }
        out.unwrap_or_default()
    }

    /// 「自己搭服务器」必须是**一页**：地址、账户/名称/端口、密码、两个勾、
    /// 三组折叠文案、两个按钮全在同一个渲染树里。
    ///
    /// 用户明确要求照旧版（旧版）的一页交互，所以「先填地址 → 下一页再填密码」
    /// 那种拆法在这条用例下会直接失败：任何一页的渲染树里都缺一半字段。
    ///
    /// r105 之后这条用例只列**正文里该在的短文案**；原来那些控件的长解释不再
    /// 铺在正文里（去处由 `the_deploy_page_explains_through_hints_not_body_text` 钉住）。
    #[test]
    fn the_deploy_page_is_one_page_with_the_old_wording() {
        let view = FormState::deploy().render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        for expected in [
            "服务器地址",
            "线路名称（留空自动命名）",
            "登录账户",
            "SSH 端口",
            "登录账户、密钥与名称",
            "登录方式",
            "SSH 私钥文件（密码登录留空）",
            "选择…",
            "OpenSSH 新格式、PEM/PKCS#8 与 PuTTY .ppk（v2/v3）都能用；私钥只在本机读取，口令与私钥内容都不会写进任务记录。",
            "服务器登录密码",
            "在这台电脑记住登录资料",
            "中断后可用这份资料继续",
            // r91：云端放行确认（旧版的 `LinuxCloudConfirmed`）；r105 只留「已核对」
            "已核对云端安全组与防火墙",
            "高级部署设置",
            "服务器要求与购买建议",
            "推荐 Ubuntu 24.04 或 Debian 13（x64）的云服务器，使用 root 或有 sudo 权限的账户。",
            "开始部署",
            "返回上一页",
        ] {
            assert!(text.contains(expected), "缺了「{expected}」：{text}");
        }
        let nodes = &view["Nodes"];
        // 两个勾都在，且默认都勾上（旧版两处缺省都是 $true）。
        assert_eq!(node(nodes, "remember-saved").unwrap()["Value"], json!(true));
        assert_eq!(node(nodes, "remember-task").unwrap()["Value"], json!(true));
        // 长期那一格紧邻密码框，任务那一格紧跟其后——**两者之间不再有分隔线**。
        // r105：两个勾都只剩一行字之后，那条线没有分组意义，只剩噪音（真机截图里
        // 它就是页面中间一根孤零零的横线）。这条断言原来要求「有」，现在要求「没有」。
        assert!(
            !text.contains("\"Kind\":\"rule\""),
            "两个勾之间不该再有分隔线：{text}"
        );
        // 密码框由前端渲染成「密码 + 显示」。
        assert_eq!(node(nodes, "password").unwrap()["Kind"], json!("password"));
        // 三个输入框（线路名称 / 账户 / 端口）与它们的缺省值。
        assert_eq!(node(nodes, "name").unwrap()["Value"], json!(""));
        assert_eq!(node(nodes, "user").unwrap()["Value"], json!("root"));
        assert_eq!(node(nodes, "port").unwrap()["Value"], json!("22"));
        // r92：登录方式下拉 + 私钥路径 + 「选择…」都在同一页的折叠区里。
        let method = node(nodes, "login-method").expect("要有登录方式下拉");
        assert_eq!(method["Kind"], json!("select"));
        let labels: Vec<&str> = method["Items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("Label").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(labels, vec!["服务器密码", "SSH 私钥"], "{method}");
        assert_eq!(method["Value"], json!(0), "默认是服务器密码");
        assert_eq!(node(nodes, "key-path").unwrap()["Value"], json!(""));
        assert_eq!(node(nodes, "pick-key").unwrap()["Text"], json!("选择…"));
        // 私钥路径与登录方式都在折叠区里（旧版的 `DeployAccessAdvanced`）。
        let access = node(nodes, "deploy-access").expect("折叠区要在");
        assert!(node(&access["Children"], "login-method").is_some(), "{access}");
        assert!(node(&access["Children"], "key-path").is_some(), "{access}");
        // 一页 = 没有「上一步」这种把用户推进下一页的按钮。
        assert!(node(nodes, "deploy-back").is_none(), "{text}");
    }

    /// 整页 JSON **摘掉所有 `Hint`** 之后的序列化结果。
    ///
    /// 「正文里不该再有这句」这条判据只能看它：`Hint` 也在整份 JSON 里，而 r105
    /// 正是把说明搬进 `Hint`，直接在整份字符串上 grep 会把两条通道混成一条
    /// （旧的长句查不到，新 `Hint` 里的短句却在，判据就失去意义）。
    fn body_without_hints(page: &Value) -> String {
        fn strip(value: &mut Value) {
            match value {
                Value::Array(list) => list.iter_mut().for_each(strip),
                Value::Object(map) => {
                    map.remove("Hint");
                    for (_, child) in map.iter_mut() {
                        strip(child);
                    }
                }
                _ => {}
            }
        }
        let mut copy = page.clone();
        strip(&mut copy);
        serde_json::to_string(&copy).unwrap_or_default()
    }

    /// r105：这一页的解释全部收进 ⓘ（`Hint`），正文里只留动作。
    ///
    /// 用户的原话是「一定要从一个产品化、用户使用的角度去思考」：每个控件下面挂
    /// 一到三句解释（地址下一句、密码下两句、「记住资料」下三句、云端放行下一句半），
    /// 整页就成了说明书——真正要填的东西被说明淹掉。做法是**控件只留动作，
    /// 解释进 `Hint`**（前端渲染成 ⓘ，悬停/点开展开）。
    ///
    /// 所以这条用例钉的是「解释的**去处**」，不是「字符串还在」：正文里查不到旧长句，
    /// 对应节点的 `Hint` 里查得到关键短语。把任意一条 `with_hint(...)` 摘掉，
    /// 对应断言立刻红。
    #[test]
    fn the_deploy_page_explains_through_hints_not_body_text() {
        let view = FormState::deploy().render();
        let body = body_without_hints(&view);
        let nodes = &view["Nodes"];

        // (节点 Id, 正文里不该再出现的旧长句, 该节点 `Hint` 里必须有的关键短语)
        let cases: [(&str, &str, &str); 6] = [
            (
                "spec",
                "支持粘贴 IP 或完整登录地址。",
                "可以粘贴完整登录地址",
            ),
            (
                "password",
                "留空则使用已保存的登录资料",
                "留空表示沿用已保存的登录资料",
            ),
            (
                "remember-saved",
                "只保存在这台电脑，用当前 Windows 用户解密",
                "用当前 Windows 用户加密保存在本机",
            ),
            (
                "remember-task",
                "本任务中断后可用这份资料继续（最长 24 小时",
                "最长 24 小时；任务完成或放弃时清除",
            ),
            (
                "deploy-cloud",
                "已核对云端安全组/防火墙：允许部署使用的 UDP 端口入站",
                "并保留 SSH 入口",
            ),
            (
                "start",
                "部署会自动完成安装、配置和检查。完成后可从首页连接新线路。",
                "完成后从首页连接新线路",
            ),
        ];
        for (id, gone, hint_phrase) in cases {
            assert!(!body.contains(gone), "「{gone}」不该再铺在正文里（{id}）：{body}");
            // 地址与密码的解释挂在**标签**上（输入框自己再挂一个就是两个 ⓘ），
            // 所以这两个按标签文字取，其余按控件 Id 取。
            let hint = match id {
                "spec" => hint_of_label(nodes, "服务器地址"),
                "password" => hint_of_label(nodes, "服务器登录密码"),
                other => node(nodes, other)
                    .unwrap_or_else(|| panic!("找不到节点 {other}"))
                    ["Hint"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            };
            assert!(
                hint.contains(hint_phrase),
                "{id} 的 Hint 里要有「{hint_phrase}」：{hint}"
            );
        }

        // 密码那条 `Hint` 要把「两种登录方式各填什么」讲全：标签不随方式切换
        // （不重绘，r92 设计 §4.8），这层信息只在这里出现。
        let pw_hint = hint_of_label(nodes, "服务器登录密码");
        assert!(pw_hint.contains("SSH 私钥方式填私钥口令"), "{pw_hint}");
        assert!(pw_hint.contains("服务器密码方式填登录密码"), "{pw_hint}");

        // 云端那条要带上端口号与「不是密码错了」——用户真正会卡住的两点。
        let cloud_hint = node(nodes, "deploy-cloud")
            .and_then(|cloud| cloud["Hint"].as_str())
            .unwrap_or("");
        assert!(cloud_hint.contains("UDP 51820"), "{cloud_hint}");
        assert!(cloud_hint.contains("连不上服务器"), "{cloud_hint}");

        // 勾选框自己的 `Text` 只剩动作（`check` 的正文就是这个字段）。
        assert_eq!(
            node(nodes, "remember-task").unwrap()["Text"],
            json!("中断后可用这份资料继续")
        );
        assert_eq!(
            node(nodes, "deploy-cloud").unwrap()["Text"],
            json!("已核对云端安全组与防火墙")
        );
        // 记住资料那条的三句合成**一条** `Hint`（页面上只有一个 ⓘ，不堆成一串）。
        let saved_hint = node(nodes, "remember-saved")
            .and_then(|saved| saved["Hint"].as_str())
            .unwrap_or("");
        assert!(saved_hint.contains("不写进任务记录"), "{saved_hint}");
        assert!(saved_hint.contains("也不出现在导出文件里"), "{saved_hint}");
    }

    /// ⓘ 必须和它说明的那一行在同一行里。
    ///
    /// `hintFor()` 是**追加在同级**的，而 `.wf-stack` 是纵向堆叠——带 `Hint` 的节点
    /// 若直接放进 stack，ⓘ 就掉到下一行、独占一行空白。真机第一版正是这样：六条解释
    /// 收进 ⓘ 之后，页面上多出 6 个孤零零的小图标，比原来的长句好不了多少。
    /// 修法是把带 `Hint` 的节点包进 `row`（`.wf-row` 是 `display:flex`，见
    /// `web/forms.css`）。这条用例钉的是**结构**，不是文案：部署页里每一个带
    /// `Hint` 的节点，父节点都必须是 `row`。
    #[test]
    fn every_deploy_hint_sits_in_a_row_so_the_icon_does_not_own_a_line() {
        fn walk(node: &Value, parent: Option<&str>, out: &mut Vec<(String, String)>) {
            if node["Hint"].as_str().map(|h| !h.is_empty()).unwrap_or(false) {
                out.push((
                    node["Id"].as_str().unwrap_or("<no-id>").to_string(),
                    parent.unwrap_or("<root>").to_string(),
                ));
            }
            if let Some(children) = node["Children"].as_array() {
                let kind = node["Kind"].as_str().unwrap_or("");
                for child in children {
                    walk(child, Some(kind), out);
                }
            }
        }
        let view = FormState::deploy().render();
        let mut hints = Vec::new();
        if let Some(list) = view["Nodes"].as_array() {
            for item in list {
                walk(item, None, &mut hints);
            }
        }
        assert!(hints.len() >= 5, "部署页至少五条说明进 ⓘ：{hints:?}");
        for (id, parent) in hints {
            assert_eq!(
                parent, "row",
                "{id} 的 ⓘ 没包在 row 里，会独占一行：{view}"
            );
        }
    }

    /// 云端放行那条：**文案收口但不许改行为**——没勾照样拦，拦下来的那句话一个字不动。
    ///
    /// r105 只动了这一格的标题与 `Hint`（长句进 ⓘ），闸门本身在 `deploy_start_steps`
    /// 里，判据还是 `deploy_cloud`。
    #[test]
    fn the_cloud_checkbox_keeps_its_gate_after_the_wording_change() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_password = "pw".into();
        let view = form.render();
        assert_eq!(
            node(&view["Nodes"], "deploy-cloud").unwrap()["Text"],
            json!("已核对云端安全组与防火墙"),
            "标题只留「已核对」"
        );
        assert_eq!(
            node(&view["Nodes"], "deploy-cloud").unwrap()["Value"],
            json!(false),
            "默认不许替用户勾上"
        );
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(
            steps.is_empty(),
            "没勾就不许发任何命令：{:?}",
            steps.iter().map(|s| s.command()).collect::<Vec<_>>()
        );
        assert_eq!(
            form.deploy_notice,
            "请先核对云端已放行部署端口（UDP 入站，并保留 SSH 入口），再开始部署。",
            "拦截提示保持原句"
        );
    }

    /// r91：没勾「云端已放行」就点开始部署——不发命令、不推进向导，并把原因说出来。
    ///
    /// 旧版是把按钮置灰（`LinuxApply.IsEnabled`）；我们改成点了才拦，理由写在
    /// `deploy_start_steps` 的注释里（宿主渲染的 disabled 要重绘，重绘会让下一次
    /// `change` 撞上 `Generation` 闸门）。
    #[test]
    fn starting_a_deployment_requires_the_cloud_checkbox() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_password = "pw".into();
        let view = form.render();
        let tick = node(&view["Nodes"], "deploy-cloud").expect("要有云端放行勾选");
        assert_eq!(tick["Value"], json!(false), "默认不许替用户勾上");

        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(
            steps.is_empty(),
            "没勾就不许发任何命令：{:?}",
            steps.iter().map(|s| s.command()).collect::<Vec<_>>()
        );
        assert!(form.deploy_notice.contains("云端"), "{}", form.deploy_notice);
        assert_eq!(form.deploy_step, 0, "不许把向导往前推");

        form.event(&json!({"Event":"change","Id":"deploy-cloud","Value":true}));
        assert!(form.deploy_cloud, "勾选要记下来");
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(
            matches!(&steps[..],
                [Step::Sync(a), Step::Long(b)]
                    if a.contains("deployment-draft-save") && b.contains("server-probe")),
            "勾了才允许开始（先落草稿再读指纹）：{:?}",
            steps.iter().map(|s| s.command()).collect::<Vec<_>>()
        );
        assert_eq!(form.deploy_step, 5, "进入「正在核对服务器身份」");
        assert!(form.deploy_notice.contains("核对服务器身份"), "{}", form.deploy_notice);

        // 第二条防线：真正发 `deployment-start` 的那一步（指纹确认之后）同样要拦。
        // 两处都判不是重复——一处挡在门口，一处挡在真正动服务器之前。
        let mut fresh = FormState::deploy();
        fresh.deploy_spec = "root@203.0.113.10".into();
        fresh.deploy_password = "pw".into();
        assert!(
            fresh.deploy_start_steps().is_empty(),
            "没勾就不许发 deployment-start"
        );
        assert!(fresh.deploy_notice.contains("云端"), "{}", fresh.deploy_notice);
    }

    /// r92：登录方式必须是**下拉**，两项原文与旧版的 `DeployLoginMethod` 一致。
    #[test]
    fn the_deploy_page_always_shows_the_login_method_and_the_key_row() {
        let view = FormState::deploy().render();
        let method = node(&view["Nodes"], "login-method").expect("要有登录方式下拉");
        assert_eq!(method["Kind"], json!("select"));
        let labels: Vec<&str> = method["Items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("Label").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(labels, vec!["服务器密码", "SSH 私钥"], "{method}");
        // 私钥那一行始终都在（密码模式下留空），不是切到私钥才出现。
        assert!(node(&view["Nodes"], "key-path").is_some());
        assert_eq!(node(&view["Nodes"], "pick-key").unwrap()["Text"], json!("选择…"));
    }

    /// r92：切登录方式**不重绘**——重绘会让下一次 `change` 撞上 `Generation` 闸门。
    #[test]
    fn choosing_the_key_method_does_not_re_render() {
        let mut form = FormState::deploy();
        let before = form.render()["Generation"].clone();
        let steps = form.event(&json!({"Event":"change","Id":"login-method","Value":1}));
        assert!(steps.is_empty(), "切方式不发命令");
        assert_eq!(form.deploy_login, 1);
        assert_eq!(
            form.render()["Generation"],
            before,
            "切方式不许 restructure（否则接下来的输入会被静默丢掉）"
        );
    }

    /// r92：切换登录方式即作废已输入的凭据（旧版的 `ClearDeploymentCredentialUI` 的前半）。
    #[test]
    fn switching_the_login_method_clears_the_typed_credential() {
        let mut form = FormState::deploy();
        form.event(&json!({"Event":"change","Id":"password","Value":"pw"}));
        assert_eq!(form.deploy_password, "pw");
        form.event(&json!({"Event":"change","Id":"login-method","Value":1}));
        assert!(form.deploy_password.is_empty(), "切换后旧密码不许留着");

        // 真的发命令时也不能带 `password`：那条口令属于上一种登录方式。
        let key = temp_key_file("switch");
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.deploy_key_path = key.to_string_lossy().to_string();
        let steps = form.deploy_start_steps();
        assert_eq!(steps.len(), 2, "落草稿 + 投递");
        for step in &steps {
            let sent: Value = serde_json::from_str(step.command()).unwrap_or(Value::Null);
            assert!(sent.get("password").is_none(), "不许带旧密码：{sent}");
        }
        let _ = std::fs::remove_file(&key);
    }

    /// r92：标签固定在密码模式的原文；私钥那句原文以常驻说明逐字带出。
    ///
    /// r105：那句说明从正文搬进了密码框的 `Hint`（ⓘ）。**判据不变**——它必须
    /// 在两种登录方式下都在，因为标签不随方式切换（不重绘，r92 设计 §4.8），
    /// 「私钥模式这一格填什么」只在这里说。
    #[test]
    fn the_credential_label_stays_stable_and_the_passphrase_hint_is_always_there() {
        for login in [0usize, 1] {
            let mut form = FormState::deploy();
            form.deploy_login = login;
            let view = form.render();
            let text = serde_json::to_string(&view).unwrap_or_default();
            assert!(text.contains("服务器登录密码"), "mode={login}：{text}");
            let hint = hint_of_label(&view["Nodes"], "服务器登录密码");
            assert!(
                hint.contains("SSH 私钥方式填私钥口令"),
                "mode={login} 缺私钥口令那句：{hint}"
            );
            assert!(
                hint.contains("服务器密码方式填登录密码"),
                "mode={login} 缺密码方式那句：{hint}"
            );
        }
    }

    /// r92：「选择…」要的是 `pick-file{slot:"key"}`，不是线路/引擎的过滤器。
    #[test]
    fn pick_key_asks_the_host_for_the_key_slot() {
        let mut form = FormState::deploy();
        let steps = form.event(&json!({"Event":"click","Id":"pick-key"}));
        let [Step::Sync(command)] = &steps[..] else {
            panic!("应发一条命令：{:?}", steps.iter().map(|s| s.command()).collect::<Vec<_>>());
        };
        let sent: Value = serde_json::from_str(command).unwrap_or(Value::Null);
        assert_eq!(sent["cmd"], json!("pick-file"), "{sent}");
        assert_eq!(sent["slot"], json!("key"), "{sent}");
    }

    /// r92：选中的路径进表单、能回填进下一次渲染；取消**不清空旧值**。
    #[test]
    fn a_picked_key_path_lands_in_the_form_and_survives_a_re_render() {
        let mut form = FormState::deploy();
        let path = r"C:\Users\demo\.ssh\id_ed25519";
        form.absorb(
            "pick-file",
            &json!({"ok":true,"filePick":{"slot":"key","path":path,"cancelled":false}}),
        );
        assert_eq!(form.deploy_key_path, path);
        assert_eq!(
            node(&form.render()["Nodes"], "key-path").unwrap()["Value"],
            json!(path)
        );
        // 取消：保留已经选好的路径，不把它变成空串。
        form.absorb(
            "pick-file",
            &json!({"ok":true,"filePick":{"slot":"key","cancelled":true}}),
        );
        assert_eq!(form.deploy_key_path, path, "取消不许清空旧值");
    }

    /// r92：私钥模式但没选文件（或文件不在）→ **连指纹都不读**，两个入口都要拦。
    #[test]
    fn starting_with_the_key_method_but_no_path_is_refused_before_probing() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.event(&json!({"Event":"change","Id":"login-method","Value":1}));
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(steps.is_empty(), "没选文件就不许读指纹");
        assert!(
            form.deploy_notice.contains("请选择 SSH 私钥文件"),
            "{}",
            form.deploy_notice
        );
        assert_eq!(form.deploy_step, 0);

        // 文件不存在（路径填了，但磁盘上没有）。
        form.deploy_key_path = std::env::temp_dir()
            .join("tc-rs-r92-not-there.pem")
            .to_string_lossy()
            .to_string();
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(steps.is_empty(), "文件不在也不许读指纹");
        assert!(
            form.deploy_notice.contains("找不到这个私钥文件"),
            "{}",
            form.deploy_notice
        );

        // 第二条防线：指纹回来之后、真正发 `deployment-start` 之前再判一次。
        let mut fresh = FormState::deploy();
        fresh.deploy_spec = "root@203.0.113.10".into();
        fresh.deploy_cloud = true;
        fresh.deploy_fingerprint = "SHA256:AAAA".into();
        fresh.deploy_login = 1;
        assert!(fresh.deploy_start_steps().is_empty(), "文件不在就不许动服务器");
        assert!(
            fresh.deploy_notice.contains("请选择 SSH 私钥文件"),
            "{}",
            fresh.deploy_notice
        );
    }

    /// r92：两批命令（草稿 + 投递）都带登录方式与私钥路径，页面不替后端猜。
    #[test]
    fn the_deploy_start_steps_carry_the_login_method_and_path() {
        let key = temp_key_file("carry");
        let key_text = key.to_string_lossy().to_string();
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.deploy_login = 1;
        form.deploy_key_path = key_text.clone();
        let steps = form.deploy_start_steps();
        assert_eq!(steps.len(), 2);
        for (index, step) in steps.iter().enumerate() {
            let sent: Value = serde_json::from_str(step.command()).unwrap_or(Value::Null);
            assert_eq!(sent["loginMethod"], json!("key"), "第 {index} 条：{sent}");
            assert_eq!(sent["identityFile"], json!(key_text), "第 {index} 条：{sent}");
        }
        let _ = std::fs::remove_file(&key);
    }

    /// r93：部署页的「高级部署设置」三格与旧版的 `DeploymentAdvanced` 对齐。
    #[test]
    fn the_deploy_page_shows_the_transport_tcp_port_and_handshake_target() {
        let view = FormState::deploy().render();
        let nodes = &view["Nodes"];
        let transport = node(nodes, "transport").expect("要有默认连接方式下拉");
        assert_eq!(transport["Kind"], json!("select"));
        let labels: Vec<&str> = transport["Items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("Label").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            labels,
            vec!["自动选择（推荐）", "标准连接", "兼容连接"],
            "{transport}"
        );
        assert_eq!(transport["Value"], json!(0), "默认是自动选择");

        let port = node(nodes, "tcp-port").expect("要有 TCP 首选端口");
        let port_labels: Vec<&str> = port["Items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("Label").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(port_labels, vec!["443", "8443", "2443"], "{port}");
        assert_eq!(port["Value"], json!(0), "默认是 443（旧版同一默认）");

        let target = node(nodes, "server-name").expect("要有 TCP 握手目标");
        assert_eq!(target["Value"], json!("www.bing.com"));

        // 三格都在「高级部署设置」折叠区里（旧版的 `DeploymentAdvanced`）。
        let advanced = node(nodes, "deploy-advanced").expect("折叠区要在");
        for id in ["transport", "tcp-port", "server-name"] {
            assert!(
                node(&advanced["Children"], id).is_some(),
                "「{id}」必须在高级部署设置里：{advanced}"
            );
        }
    }

    /// r93：三个选择只改内存、**不重绘**（重绘会吞掉接下来的输入）。
    #[test]
    fn choosing_the_transport_settings_does_not_re_render() {
        let mut form = FormState::deploy();
        let before = form.render()["Generation"].clone();
        form.event(&json!({"Event":"change","Id":"transport","Value":2}));
        assert_eq!(form.deploy_transport, 2);
        form.event(&json!({"Event":"change","Id":"tcp-port","Value":1}));
        assert_eq!(form.deploy_tcp_port, "8443");
        form.event(&json!({"Event":"change","Id":"server-name","Value":"www.example.com"}));
        assert_eq!(form.deploy_server_name, "www.example.com");
        assert_eq!(
            form.render()["Generation"],
            before,
            "这三个 change 不许 restructure"
        );
        assert_eq!(form.deploy_transport_word(), "Tcp");
    }

    /// r93：两批命令都带默认连接方式、TCP 端口与握手域名。
    #[test]
    fn the_deploy_start_steps_carry_the_transport_choices() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.deploy_password = "pw".into();
        form.deploy_transport = 2;
        form.deploy_tcp_port = "2443".into();
        form.deploy_server_name = "www.example.com".into();
        let steps = form.deploy_start_steps();
        assert_eq!(steps.len(), 2, "落草稿 + 投递");
        for (index, step) in steps.iter().enumerate() {
            let sent: Value = serde_json::from_str(step.command()).unwrap_or(Value::Null);
            assert_eq!(sent["transport"], json!("Tcp"), "第 {index} 条：{sent}");
            assert_eq!(sent["tcpPort"], json!("2443"), "第 {index} 条：{sent}");
            assert_eq!(
                sent["serverName"],
                json!("www.example.com"),
                "第 {index} 条：{sent}"
            );
        }
    }

    /// r93：握手域名不是域名（或端口不在候选里）→ 读指纹之前就拦下。
    #[test]
    fn an_invalid_handshake_target_is_refused_before_probing() {
        let mut form = FormState::deploy();
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.deploy_password = "pw".into();
        form.deploy_server_name = "not a domain".into();
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert!(steps.is_empty(), "坏域名不许读指纹");
        assert!(
            form.deploy_notice.contains("握手目标"),
            "{}",
            form.deploy_notice
        );
        assert_eq!(form.deploy_step, 0);

        // 第二条防线：指纹回来之后、真正投递之前再判一次。
        assert!(form.deploy_start_steps().is_empty());
        assert!(form.deploy_notice.contains("握手目标"));
    }

    /// r93：草稿里存的三项能在「接着填」时原样回填。
    #[test]
    fn a_draft_restores_the_transport_choices() {
        let run = json!({
            "RunId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "Label": "自建 · 203.0.113.10",
            "Target": {"Host":"203.0.113.10","Port":22,"User":"root","LoginMethod":"password"},
            "Plan": {"Transport":"Tcp","TcpPort":2443,"ServerName":"www.example.com"},
            "Identity": {"Fingerprint":"SHA256:AAAA","AutoTrusted":false},
            "RememberSaved": true,
            "RememberTask": false
        });
        let form = FormState::deploy_from_draft(&run);
        assert_eq!(form.deploy_transport, 2);
        assert_eq!(form.deploy_tcp_port, "2443");
        assert_eq!(form.deploy_server_name, "www.example.com");
        let view = form.render();
        assert_eq!(node(&view["Nodes"], "transport").unwrap()["Value"], json!(2));
        assert_eq!(node(&view["Nodes"], "tcp-port").unwrap()["Value"], json!(2));
        assert_eq!(
            node(&view["Nodes"], "server-name").unwrap()["Value"],
            json!("www.example.com")
        );
    }

    /// r95：两个「使用已保存凭据」的勾只在真的有那一档时出现，改勾不重绘。
    #[test]
    fn the_deploy_page_shows_the_saved_credential_switches_only_when_available() {
        let mut form = FormState::deploy();
        // 还没探测：两格都不画。
        let view = form.render();
        assert!(node(&view["Nodes"], "use-saved").is_none());
        assert!(node(&view["Nodes"], "use-task").is_none());

        form.absorb_probe(&json!({
            "ok":true,
            "serverProbe":{
                "fingerprint":"SHA256:AAAA","known":true,
                "savedCredential":true,"taskCredential":true
            }
        }));
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        assert!(node(&view["Nodes"], "use-saved").is_some(), "{text}");
        assert!(node(&view["Nodes"], "use-task").is_some(), "{text}");
        assert!(text.contains("使用这台服务器保存的登录资料"), "{text}");
        assert!(text.contains("使用本任务保存的登录资料（重新输入会替换）"), "{text}");
        assert_eq!(node(&view["Nodes"], "use-saved").unwrap()["Value"], json!(true));
        assert_eq!(node(&view["Nodes"], "use-task").unwrap()["Value"], json!(true));

        let before = form.render()["Generation"].clone();
        form.event(&json!({"Event":"change","Id":"use-saved","Value":false}));
        form.event(&json!({"Event":"change","Id":"use-task","Value":false}));
        assert!(!form.deploy_use_saved && !form.deploy_use_task);
        assert_eq!(form.render()["Generation"], before, "改勾不许重绘");

        // 两批命令都要带着这两个勾（typed 口令仍然优先，但开关必须送到后端）。
        form.deploy_spec = "root@203.0.113.10".into();
        form.deploy_cloud = true;
        form.deploy_password = "pw".into();
        let steps = form.deploy_start_steps();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            let sent: Value = serde_json::from_str(step.command()).unwrap_or(Value::Null);
            assert_eq!(sent["useSaved"], json!(false), "{sent}");
            assert_eq!(sent["useTask"], json!(false), "{sent}");
        }
    }

    /// r95：探测回包说没有信封时，两格不出现（不画假控件）。
    #[test]
    fn the_saved_credential_switches_stay_hidden_without_an_envelope() {
        let mut form = FormState::deploy();
        form.absorb_probe(&json!({
            "ok":true,
            "serverProbe":{
                "fingerprint":"SHA256:AAAA","known":true,
                "savedCredential":false,"taskCredential":false
            }
        }));
        let view = form.render();
        assert!(node(&view["Nodes"], "use-saved").is_none());
        assert!(node(&view["Nodes"], "use-task").is_none());
    }

    /// r93：部署详情页有「技术详情与本次端口规则」，且列出这次的实际端口。
    #[test]
    fn the_run_page_shows_the_technical_details_and_port_rules() {
        let run = json!({
            "RunId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "RunShort": "9f1c2a44",
            "Name": "自建 · 203.0.113.10",
            "State": "Complete",
            "StepsDone": 4,
            "NextAction": "None",
            "Running": false,
            "CanBackground": false,
            "Target": {"Host":"203.0.113.10","Port":22,"User":"root"},
            "Plan": {"Interface":"tc9f1c2a44","UdpPort":51820,"Transport":"Tcp","TcpPort":2443,"ServerName":"www.example.com"},
            "Identity": {"Fingerprint":"SHA256:AAAA","AutoTrusted":false},
            "Steps": [],
            "Summary": "4/4 步完成"
        });
        let form = FormState::deploy_run("9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b", run);
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        for expected in [
            "技术详情与本次端口规则",
            "默认连接方式：兼容连接",
            "UDP 入站端口：51820",
            "TCP 兼容连接：2443，握手域名 www.example.com",
            "SSH 管理入口：203.0.113.10:22",
            "准备完成：可以从首页或线路页连接这条线路",
        ] {
            assert!(text.contains(expected), "缺了「{expected}」：{text}");
        }
    }

    /// 测试用临时私钥文件：页面只判「文件存在」，不解析内容（解析在后端）。
    fn temp_key_file(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("tc-rs-r92-{tag}-{}.key", std::process::id()));
        std::fs::write(&path, b"placeholder").expect("写临时私钥文件");
        path
    }

    /// 地址与账户/端口的关系只有一套规则：**地址里写了的以地址为准**。
    #[test]
    fn the_address_wins_over_the_account_and_port_fields() {
        assert_eq!(
            deploy_compose_target("192.168.1.1", "root", "22").unwrap(),
            "root@192.168.1.1:22"
        );
        assert_eq!(
            deploy_compose_target("192.168.1.1", "ubuntu", "2222").unwrap(),
            "ubuntu@192.168.1.1:2222"
        );
        // 地址里带了用户：账户框里的值不再生效。
        assert_eq!(
            deploy_compose_target("ubuntu@example.com", "root", "22").unwrap(),
            "ubuntu@example.com:22"
        );
        // 地址里带了端口：端口框里的值不再生效。
        assert_eq!(
            deploy_compose_target("example.com:2200", "root", "22").unwrap(),
            "root@example.com:2200"
        );
        // 两个都带了：全部以地址为准。
        assert_eq!(
            deploy_compose_target("deploy@example.com:2200", "root", "22").unwrap(),
            "deploy@example.com:2200"
        );
        // 两个框都空：回到后端那一套缺省（root / 22）。
        assert_eq!(
            deploy_compose_target("203.0.113.10", "", "").unwrap(),
            "root@203.0.113.10:22"
        );
        for (spec, user, port) in [
            ("", "root", "22"),
            ("   ", "root", "22"),
            ("192.168.1.1", "root", "abc"),
            ("192.168.1.1", "root", "0"),
            ("192.168.1.1", "root", "70000"),
            ("@192.168.1.1", "root", "22"),
            ("192.168.1.1 :22", "root", "22"),
        ] {
            assert!(
                deploy_compose_target(spec, user, port).is_err(),
                "{spec:?} / {user:?} / {port:?} 应当被拒"
            );
        }
    }

    /// 线路名称 / 账户 / 端口改过之后，投递那两条命令必须带着它们出去。
    #[test]
    fn the_label_account_and_port_reach_the_command() {
        let mut form = FormState::deploy();
        form.event(&json!({"Event":"change","Id":"spec","Value":"203.0.113.10"}));
        form.event(&json!({"Event":"change","Id":"name","Value":"东京节点"}));
        form.event(&json!({"Event":"change","Id":"user","Value":"ubuntu"}));
        form.event(&json!({"Event":"change","Id":"port","Value":"2222"}));
        form.event(&json!({"Event":"change","Id":"remember-saved","Value":false}));
        form.event(&json!({"Event":"change","Id":"remember-task","Value":false}));
        form.event(&json!({"Event":"change","Id":"deploy-cloud","Value":true}));
        let steps = form.event(&json!({"Event":"click","Id":"start"}));
        assert_eq!(steps.len(), 2, "{steps:?}");
        // 取原始命令行：`{:?}` 会把引号转义掉，断言 `"remember":false` 那种串会假失败。
        let joined = steps
            .iter()
            .map(|step| step.command().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("东京节点"), "线路名称要进命令：{joined}");
        assert!(
            joined.contains("ubuntu@203.0.113.10:2222"),
            "账户与端口要合成地址：{joined}"
        );
        // 两个勾跟着走：不勾就不许在磁盘上留东西。
        assert!(joined.contains("\"remember\":false"), "{joined}");
        assert!(joined.contains("\"rememberTask\":false"), "{joined}");
        // 地址栏回填成真正会用的那个地址：页面上不许有第二份真相。
        assert_eq!(form.deploy_spec, "ubuntu@203.0.113.10:2222");
    }

    /// 勾选事件回传的是布尔：用 `as_str()` 取会永远得到空串，看起来勾了其实没生效。
    #[test]
    fn the_two_checkboxes_read_booleans_from_the_page() {
        let mut form = FormState::deploy();
        assert!(form.deploy_remember_saved, "默认勾上");
        assert!(form.deploy_remember_task, "默认勾上");
        form.event(&json!({"Event":"change","Id":"remember-saved","Value":false}));
        assert!(!form.deploy_remember_saved);
        form.event(&json!({"Event":"change","Id":"remember-saved","Value":true}));
        assert!(form.deploy_remember_saved);
        form.event(&json!({"Event":"change","Id":"remember-task","Value":false}));
        assert!(!form.deploy_remember_task);
    }

    /// r100：宿主 OS 拖放只填输入框，不直接写配置；别的页面不受理。
    #[test]
    fn dropping_an_exe_fills_the_program_input_only_on_the_split_page() {
        let mut form = FormState::split();
        assert!(form.fill_program_path(r"C:\Apps\NinjaTrader.exe"));
        assert_eq!(form.program_path, r"C:\Apps\NinjaTrader.exe");
        assert!(form.notice.contains("NinjaTrader.exe"), "{}", form.notice);
        assert!(!form.notice.contains("已生效"), "拖放不写配置：{}", form.notice);

        let mut history = FormState::history();
        assert!(
            !history.fill_program_path(r"C:\Apps\NinjaTrader.exe"),
            "别的页面不该吞掉拖放"
        );
        assert!(history.program_path.is_empty());
    }

    /// r101：快捷方式换不出程序时**不静默**，但也绝不往输入框里填半条路径。
    #[test]
    fn unusable_shortcut_gets_a_notice_and_leaves_the_input_empty() {
        let mut form = FormState::split();
        form.program_path = String::new();
        assert!(form.notice_program_unusable(r"C:\Users\me\Desktop\Mirasim.lnk"));
        assert!(
            form.notice.contains("Mirasim.lnk") && form.notice.contains("找不到可用的程序"),
            "要说清是哪个文件、为什么没填：{}",
            form.notice
        );
        assert!(
            form.program_path.is_empty(),
            "没有换出真程序就不许往配置里填：{}",
            form.program_path
        );

        // 别的页面不受理：宿主据此返回 false，不吞这次拖放。
        let mut history = FormState::history();
        let before = history.notice.clone();
        assert!(!history.notice_program_unusable(r"C:\Users\me\Desktop\Mirasim.lnk"));
        assert_eq!(history.notice, before, "不是这一页就一个字都不改：{}", history.notice);
    }

    #[test]
    fn split_page_adds_programs_and_sites_in_separate_inputs() {
        let mut form = FormState::split();
        form.absorb("split", &json!({"ok":true,
            "processes":[
                {"value":"TradingApp.exe","target":"trade","path":"C:\\Apps\\TradingApp.exe",
                 "fileExists":true,"applied":true},
                {"value":"Daily.exe","target":"daily"}
            ],
            "domains":[{"value":"example.com","target":"trade"},
                       {"value":"daily.com","target":"daily"}]}));
        let view = form.render().to_string();
        assert!(view.contains("交易软件名单"), "{view}");
        assert!(view.contains("TradingApp.exe · 已生效"), "{view}");
        assert!(view.contains("example.com"), "{view}");
        assert!(!view.contains("Daily.exe"), "非交易程序不在这一页：{view}");
        assert!(!view.contains("daily.com"), "非交易网站不在这一页：{view}");
        assert!(view.contains("TradeProgramInput"), "程序输入框要在：{view}");
        assert!(view.contains("TradeDomainInput"), "网站输入框要在：{view}");

        // 「浏览…」只回填程序输入框，不写配置、也不碰网站输入框。
        let steps = form.event(&json!({"Event":"click","Id":"pick-program"}));
        assert!(matches!(&steps[0], Step::Sync(c)
            if c.contains("pick-exe") && c.contains("\"target\":\"trade\"")));
        form.absorb("pick-exe", &json!({"ok":true,"filePick":{
            "slot":"process","target":"trade","processName":"Other.exe",
            "path":"C:\\Apps\\Other.exe","cancelled":false}}));
        assert_eq!(form.program_path, "C:\\Apps\\Other.exe");
        assert!(form.draft.is_empty(), "网站输入框不受影响");

        let steps = form.event(&json!({"Event":"click","Id":"add-program"}));
        let Step::Sync(add) = &steps[0] else { panic!("添加程序要发命令") };
        assert!(add.contains("split-add") && add.contains("Other.exe")
            && add.contains("\"target\":\"trade\""), "{add}");
        assert!(add.contains("\"path\":\"C:\\\\Apps\\\\Other.exe\""), "{add}");
        form.absorb("split-add", &json!({"ok":true,"changed":true,
            "splitMessage":"已加入：Other.exe → 交易出口",
            "processes":[{"value":"Other.exe","target":"trade","path":"C:\\Apps\\Other.exe",
                          "fileExists":true,"applied":true}],
            "domains":[]}));
        assert!(form.program_path.is_empty(), "成功后只清程序输入框");

        // 网站输入框独立提交，出口固定为交易出口。
        form.event(&json!({"Event":"change","Id":"site-domain","Value":"qq.com"}));
        let steps = form.event(&json!({"Event":"click","Id":"add-site"}));
        let Step::Sync(add) = &steps[0] else { panic!("添加网站要发命令") };
        assert!(add.contains("\"kind\":\"domain\"") && add.contains("qq.com")
            && add.contains("\"target\":\"trade\""), "{add}");

        // 移除按索引取当前列表里的值，不信任页面回传。
        let steps = form.event(&json!({"Event":"click","Id":"remove-process-0"}));
        assert!(matches!(&steps[0], Step::Sync(c)
            if c.contains("split-remove") && c.contains("Other.exe")));
    }

    #[test]
    fn split_page_offers_reset_default_sites_and_sends_one_command() {
        let mut form = FormState::split();
        let view = form.render().to_string();
        assert!(view.contains("恢复默认网站"), "{view}");

        let steps = form.event(&json!({"Event":"click","Id":"reset-trade-domains"}));
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("split-reset-trade-domains")),
            "{steps:?}"
        );

        form.absorb(
            "split-reset-trade-domains",
            &json!({"ok":true,"changed":true,"splitMessage":"已恢复默认交易网站（7 条）",
                "processes":[],
                "domains":[{"value":"tradingview.com","target":"trade"},
                           {"value":"tradovate.com","target":"trade"}]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("tradingview.com"), "{view}");
        assert!(view.contains("tradovate.com"), "{view}");
        assert!(view.contains("已恢复默认交易网站（7 条）"), "{view}");
    }

    #[test]
    fn split_rows_show_program_status_and_let_unresolved_entries_be_relocated() {
        let mut form = FormState::split();
        form.absorb("split", &json!({"ok":true,
            "processes":[
                {"value":"A.exe","target":"trade","path":"C:\\app\\a.exe",
                 "fileExists":true,"applied":true},
                {"value":"old.exe","target":"trade","path":null,
                 "fileExists":null,"applied":false},
                {"value":"B.exe","target":"daily","path":null}
            ],
            "domains":[{"value":"example.com","target":"trade"}]}));
        let view = form.render().to_string();
        assert!(view.contains("A.exe · 已生效"), "{view}");
        assert!(view.contains("old.exe · 位置未确认"), "{view}");
        assert!(!view.contains("B.exe"), "非交易程序不在这一页：{view}");
        assert!(view.contains("example.com"), "{view}");
        assert!(!view.contains("已保护"), "这一页说生效/未生效，不说保护状态：{view}");

        // 「确认程序位置」只给解析不出路径的那条（按按钮 Name 数，不数文本里出现的字）
        assert_eq!(view.matches("LocatePick").count(), 1, "只有未解析条目才有入口：{view}");

        let steps = form.event(&json!({"Event":"click","Id":"locate-1"}));
        assert!(matches!(&steps[0], Step::Sync(c)
            if c.contains("pick-exe") && c.contains("\"target\":\"trade\"")));

        // 选完文件**先不写**：只记下路径，等「保存位置」——这条名单决定谁被阻断
        form.absorb("pick-exe", &json!({"ok":true,"filePick":{
            "slot":"process","target":"trade","processName":"old.exe",
            "path":"C:\\app\\old.exe","cancelled":false}}));
        let view = form.render().to_string();
        assert!(view.contains("保存位置"), "{view}");
        assert_eq!(view.matches("LocateApply").count(), 1, "{view}");
        assert_eq!(view.matches("LocatePick").count(), 0, "同一条不许同时给两个入口：{view}");

        let steps = form.event(&json!({"Event":"click","Id":"locate-apply"}));
        let Step::Sync(apply) = &steps[0] else { panic!("保存位置要发命令") };
        assert!(apply.contains("split-add") && apply.contains("old.exe"), "{apply}");
        assert!(apply.contains("\"path\":\"C:\\\\app\\\\old.exe\""), "{apply}");
        assert!(apply.contains("\"target\":\"trade\""), "{apply}");
    }

    // ---------- AI 工具名单：草稿在宿主侧、一次保存一条命令 ----------

    /// `ipc::agents_payload` 的形状（生产者是 ipc；这里按契约造一份，钉的是表单的收发）。
    /// 目录数据（名称/说明/域名）取真实目录，运行徽标给两档真实值钉住徽标渲染。
    fn agents_reply(
        checked: &[&str],
        programs: &[&str],
        sites: &[&str],
        lane: &str,
        trade_exit: bool,
        busy: bool,
    ) -> Value {
        let builtin: Vec<Value> = crate::agents::BUILTIN
            .iter()
            .map(|item| {
                let presence = match item.id {
                    "claude-code" => "running",
                    "cursor" => "installed",
                    _ if item.kind == crate::agents::AgentKind::Program => "notfound",
                    _ => "",
                };
                json!({
                    "id": item.id,
                    "name": item.name,
                    "short": item.short,
                    "kind": item.kind.id(),
                    "detail": item.detail,
                    "domains": item.domains,
                    "presence": presence,
                    "checked": checked.contains(&item.id),
                    "inTradeList": false,
                    "note": item.kind.note(),
                })
            })
            .collect();
        json!({
            "ok": true,
            "agents": {
                "lane": lane,
                "laneEffective": lane,
                "globalOverride": false,
                "tradeExitPresent": trade_exit,
                "busy": busy,
                "count": checked.len() + programs.len() + sites.len(),
            },
            "builtin": builtin,
            "programs": programs.iter().map(|v| json!({"value": v, "inTradeList": false})).collect::<Vec<_>>(),
            "sites": sites.iter().map(|v| json!({"value": v, "inTradeList": false})).collect::<Vec<_>>(),
        })
    }

    fn form_of(value: &Value) -> String {
        value.to_string()
    }

    /// 行内按钮的文字（`添加` / `移除`）。按 Id 取，不按位置取。
    fn row_button_text(form: &FormState, id: &str) -> String {
        let page = form.render();
        node(&page["Nodes"], id)
            .and_then(|n| n.get("Text"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    /// 每次点击（添加或移除）只改宿主内存草稿：**写命令次数 = 0**
    /// （一次点击一条命令是回归）。
    #[test]
    fn ten_toggles_issue_zero_commands() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        for i in 0..10 {
            let steps = form.event(&json!({"Event": "click", "Id": "builtin-cursor"}));
            assert!(steps.is_empty(), "第 {i} 次点击不许发命令：{steps:?}");
        }
        // 10 次（偶数次）之后回到「不在名单里」
        assert!(!form.agents_builtin.iter().any(|id| id == "cursor"));
        assert!(form.event(&json!({"Event":"click","Id":"builtin-cursor"})).is_empty());
        assert_eq!(form.current_agents_draft().builtin, vec!["cursor"]);
        assert!(form.agents_dirty(), "加了一项就应该是「有改动」");
    }

    /// 行内按钮的文案跟着**草稿现状**走：在名单里 →「移除」，不在 →「添加」。
    ///
    /// 这一条同时钉住「移除真的从草稿里拿掉」与「添加真的能加回来」：
    /// 把 toggle 退回成「只会加、不会去」（r102 的行为）时，第一处断言就红。
    #[test]
    fn the_row_button_says_add_or_remove_by_what_the_draft_holds() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&["cursor"], &[], &[], "daily", true, false),
        );
        assert_eq!(row_button_text(&form, "builtin-cursor"), "移除", "已在名单里 → 移除");
        assert_eq!(
            row_button_text(&form, "builtin-claude-code"),
            "添加",
            "不在名单里 → 添加"
        );
        // 两种状态共用同一个 Id：按钮不会在行里跳来跳去（自动化与肉眼都好找）。
        let page = form_of(&form.render());
        assert!(page.contains(r#""Id":"builtin-cursor""#), "{page}");

        // 点「移除」：草稿里**当场**没了（没有「保存后移除」这种中间态）
        let steps = form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        assert!(steps.is_empty(), "移除不发命令：{steps:?}");
        assert!(
            !form.current_agents_draft().builtin.iter().any(|id| id == "cursor"),
            "点移除后草稿里真的没了：{:?}",
            form.current_agents_draft().builtin
        );
        assert_eq!(row_button_text(&form, "builtin-cursor"), "添加", "移除之后按钮变成「添加」");
        assert!(!page_has_text(&form, "保存后移除"), "不该再有这种中间态文案");

        // 再点一次「添加」：真的回到草稿里
        let steps = form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        assert!(steps.is_empty(), "加回不发命令：{steps:?}");
        assert_eq!(form.current_agents_draft().builtin, vec!["cursor"], "点添加后真的回来了");
        assert_eq!(row_button_text(&form, "builtin-cursor"), "移除");
    }

    /// 名字里带「域名清单」的那句提示是否出现在页面上（`Hint` 是 JSON 字符串，不走 innerText）。
    fn page_has_text(form: &FormState, needle: &str) -> bool {
        form_of(&form.render()).contains(needle)
    }

    /// 表单树里所有带 `Kind` 的节点（**按出现顺序**，深度优先）。
    ///
    /// 「第几个孩子」这种脆弱索引不能钉住结构；但「谁排在谁前面」是 r104 的真实契约
    /// （折叠区在名单之后），所以这里保留顺序。
    fn flat_nodes(value: &Value) -> Vec<Value> {
        fn walk(value: &Value, out: &mut Vec<Value>) {
            match value {
                Value::Array(list) => list.iter().for_each(|v| walk(v, out)),
                Value::Object(map) => {
                    if map.contains_key("Kind") {
                        out.push(value.clone());
                    }
                    // 键序由 `serde_json::Map` 决定，与「孩子顺序」无关；`Children` 自己
                    // 就是数组，按数组顺序递归即可。
                    for (_, v) in map {
                        walk(v, out);
                    }
                }
                _ => {}
            }
        }
        let mut out: Vec<Value> = Vec::new();
        walk(&value["Nodes"], &mut out);
        walk(&value["PageActions"], &mut out);
        out
    }

    /// 行内按钮的文字，按出现顺序（`添加` / `移除`）。
    fn builtin_button_texts(page: &Value) -> Vec<String> {
        flat_nodes(page)
            .iter()
            .filter(|n| n["Kind"] == json!("button"))
            .filter(|n| {
                n["Id"]
                    .as_str()
                    .map(|id| id.starts_with("builtin-"))
                    .unwrap_or(false)
            })
            .map(|n| n["Text"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// 页面上 `details` 折叠区的节点（r104 全目录用：正常 0 或 1 个）。
    fn details_nodes(page: &Value) -> Vec<Value> {
        flat_nodes(page)
            .into_iter()
            .filter(|n| n["Kind"] == json!("details"))
            .collect()
    }

    #[test]
    fn save_submits_the_whole_draft_in_one_command() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&[], &["old-scan.exe"], &["old.example.com"], "daily", true, false),
        );
        // 加 2 项、加 1 个网站、加 1 个程序（走向不在这页改，保存时按读到的值原样带上）
        form.event(&json!({"Event":"click","Id":"builtin-claude-code"}));
        form.event(&json!({"Event":"click","Id":"builtin-chatgpt-web"}));
        form.event(&json!({"Event":"change","Id":"site","Value":"*.Perplexity.AI"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        form.absorb(
            "pick-exe",
            &json!({"ok":true,"filePick":{"slot":"process","target":"trade",
                                           "processName":"my-scan.exe","cancelled":false}}),
        );
        let steps = form.event(&json!({"Event":"click","Id":"save"}));
        assert_eq!(steps.len(), 1, "一次保存只发**一条**命令：{steps:?}");
        let Step::Sync(command) = &steps[0] else { panic!("保存要发同步命令") };
        assert!(command.contains("agents-save"), "{command}");
        assert!(
            command.contains("\"Lane\":\"daily\""),
            "走向不在这一页改，保存照旧带上读到的值：{command}"
        );
        assert!(command.contains("claude-code") && command.contains("chatgpt-web"), "{command}");
        assert!(command.contains("my-scan.exe") && command.contains("old-scan.exe"), "{command}");
        assert!(command.contains("perplexity.ai") && command.contains("old.example.com"), "{command}");
    }

    #[test]
    fn discard_restores_the_baseline_and_sends_nothing() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&["cursor"], &[], &["qq.com"], "daily", true, false),
        );
        form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        form.event(&json!({"Event":"click","Id":"builtin-windsurf"}));
        form.event(&json!({"Event":"change","Id":"site","Value":"discard-me.example"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        assert!(form.agents_dirty());
        let steps = form.event(&json!({"Event":"click","Id":"discard"}));
        assert!(steps.is_empty(), "放弃修改不落盘：{steps:?}");
        assert!(!form.agents_dirty(), "草稿回到基线");
        assert_eq!(form.current_agents_draft().builtin, vec!["cursor"]);
        assert_eq!(form.current_agents_draft().sites, vec!["qq.com"]);
        // 刚加的那个网站属于「这一轮」，放弃修改之后连记忆一起丢掉（不该留下一条幽灵行）。
        assert!(form.agents_seen.is_empty(), "放弃修改要清掉本轮记忆：{:?}", form.agents_seen);
        assert!(!page_has_text(&form, "discard-me.example"), "{}", form_of(&form.render()));
    }

    /// 自定义行：点「移除」= 从草稿 Vec 里删掉（当场生效，没有「保存后移除」），
    /// 行还留在原处（否则「添加」无处可点），再点「添加」就加回来。
    #[test]
    fn removing_a_custom_site_takes_it_out_of_the_draft_and_adds_it_back_in_one_click() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&[], &["my-scan.exe"], &["qq.com"], "trade", true, false),
        );
        assert_eq!(row_button_text(&form, "toggle-site-0"), "移除", "在草稿里 → 移除");

        let steps = form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        assert!(steps.is_empty(), "移除不发命令：{steps:?}");
        assert!(form.agents_dirty(), "移除 = 有改动");
        // 草稿里真的没了（不是打标记）
        assert!(
            form.current_agents_draft().sites.is_empty(),
            "点移除后草稿里真的没了：{:?}",
            form.current_agents_draft().sites
        );
        assert!(form.agents_sites.is_empty(), "草稿 Vec 里也真的删掉了：{:?}", form.agents_sites);
        let rendered = form_of(&form.render());
        assert!(!rendered.contains("保存后移除"), "不该再有这种中间态文案：{rendered}");
        // 行还在原处、按钮换成「添加」——所以还能加回来
        assert!(rendered.contains(r#""Id":"toggle-site-0""#), "行必须留在原处：{rendered}");
        assert_eq!(row_button_text(&form, "toggle-site-0"), "添加");

        // 保存命令里的 Sites 直接是空的（没有待提交的「待移除」）
        let steps = form.event(&json!({"Event":"click","Id":"save"}));
        let Step::Sync(command) = &steps[0] else { panic!("保存要发同步命令") };
        assert!(command.contains("\"Sites\":[]"), "移除的项不能被提交：{command}");
        assert!(command.contains("my-scan.exe"), "没动的程序照旧提交：{command}");

        // 再点同一行 = 加回草稿
        let steps = form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        assert!(steps.is_empty(), "加回不发命令：{steps:?}");
        assert_eq!(form.current_agents_draft().sites, vec!["qq.com"], "点添加后真的回来了");
        assert_eq!(row_button_text(&form, "toggle-site-0"), "移除");
        let steps = form.event(&json!({"Event":"click","Id":"save"}));
        let Step::Sync(command) = &steps[0] else { panic!("保存要发同步命令") };
        assert!(command.contains("qq.com"), "加回来之后要重新提交：{command}");

        // 保存成功：回包重填（不含已删项）→ 不再有改动、列表里真的没了
        form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        form.absorb(
            "agents-save",
            &json!({
                "ok": true, "changed": true,
                "agentsMessage": "已保存：名单 1 项，使用交易线路。下次连接时生效。",
                "agents": {"lane": "trade", "laneEffective": "trade", "globalOverride": false,
                            "tradeExitPresent": true, "busy": false, "count": 1},
                "builtin": agents_reply(&[], &[], &[], "trade", true, false)["builtin"].clone(),
                "programs": [{"value": "my-scan.exe", "inTradeList": false}],
                "sites": [],
            }),
        );
        assert!(!form.agents_dirty(), "保存成功后基线跟着更新");
        assert!(!form_of(&form.render()).contains("qq.com"), "列表里真的没了");
        assert!(form.agents_note.contains("下次连接时生效"), "{}", form.agents_note);

        // ---- 还没保存过的**新增项**：移除后行也必须还在（否则「移除」两种结果） ----
        // 基线里没有、保存过的回包里也没有，只按「基线 ∪ 草稿」渲染时整行会消失，
        // 用户只能重新打字——而上面那条已存的条目却是「行还在、按钮翻添加」。
        form.event(&json!({"Event":"change","Id":"site","Value":"fresh.example"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        assert_eq!(form.agents_sites, vec!["fresh.example"]);
        assert_eq!(row_button_text(&form, "toggle-site-0"), "移除", "刚加的项也要有一行");

        let steps = form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        assert!(steps.is_empty(), "移除不发命令：{steps:?}");
        assert!(form.agents_sites.is_empty(), "草稿里真的删掉了：{:?}", form.agents_sites);
        let rendered = form_of(&form.render());
        assert!(
            rendered.contains(r#""Id":"toggle-site-0""#),
            "还没保存过的新增项，移除后行也要留在原处：{rendered}"
        );
        assert!(rendered.contains("fresh.example"), "{rendered}");
        assert_eq!(row_button_text(&form, "toggle-site-0"), "添加", "按钮翻回「添加」");

        // 点一下「添加」：真的回到草稿（与已保存过的那条完全同一条路径）
        let steps = form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        assert!(steps.is_empty(), "加回不发命令：{steps:?}");
        assert_eq!(form.agents_sites, vec!["fresh.example"], "点添加后草稿里真的回来了");
        assert_eq!(row_button_text(&form, "toggle-site-0"), "移除");
    }

    /// 保存之后必须清掉「本轮见过」：否则下次进来会看到一条早已不存在的幽灵行。
    #[test]
    fn a_removed_new_entry_does_not_come_back_as_a_ghost_after_saving() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        form.event(&json!({"Event":"change","Id":"site","Value":"ghost.example"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        form.event(&json!({"Event":"change","Id":"site","Value":"keep.example"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        assert_eq!(form.agents_seen.len(), 2, "两个都是本轮新加的：{:?}", form.agents_seen);

        // 移除还没保存过的 ghost：行留在原处（靠本轮记忆），按钮翻「添加」
        form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        assert_eq!(form.agents_sites, vec!["keep.example"]);
        assert!(
            page_has_text(&form, "ghost.example"),
            "移除后行还在：{}",
            form_of(&form.render())
        );

        // 保存成功：回包里只有 keep → 基线、草稿、本轮记忆一起回到「没有 ghost 这一条」
        form.absorb(
            "agents-save",
            &agents_reply(&[], &[], &["keep.example"], "daily", true, false),
        );
        assert!(!form.agents_dirty(), "保存成功后基线跟上");
        assert!(form.agents_seen.is_empty(), "保存后本轮记忆要清空：{:?}", form.agents_seen);
        let rendered = form_of(&form.render());
        assert!(!rendered.contains("ghost.example"), "不许留幽灵行：{rendered}");
        assert!(rendered.contains("keep.example"), "存下来的那条还在：{rendered}");
    }

    #[test]
    fn busy_refusal_keeps_the_draft() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        form.event(&json!({"Event":"change","Id":"site","Value":"perplexity.ai"}));
        form.event(&json!({"Event":"click","Id":"add-site"}));
        let before = form.current_agents_draft();

        form.absorb(
            "agents-save",
            &json!({"ok": false, "errorCode": "busy",
                     "error": "请先断开再保存 AI 工具名单：连接中改动配置会让引擎实际行为与配置不一致"}),
        );
        assert_eq!(form.current_agents_draft(), before, "被拒时草稿一个字都不许动");
        assert!(form.agents_busy, "连接中：保存按钮要变成不可用");
        assert!(form.agents_note.contains("请先断开"), "{}", form.agents_note);
        // 页面：状态行说明原因，保存按钮禁用，「放弃修改」还能点
        let page = form.render();
        assert!(form_of(&page).contains("正在连接，名单要断开后才能保存"), "{}", form_of(&page));
        assert_eq!(page["PageActions"][0]["Disabled"], true, "保存要禁用");
        assert_eq!(page["PageActions"][1]["Disabled"], false, "放弃修改仍可用");
    }

    #[test]
    fn pick_exe_lands_in_the_program_list_not_in_a_textbox() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        let steps = form.event(&json!({"Event":"click","Id":"pick-program"}));
        let Step::Sync(command) = &steps[0] else { panic!("选择程序要发命令") };
        assert!(command.contains("pick-exe"), "{command}");
        // `target` 沿用既有三值之一，不扩枚举
        assert!(command.contains("\"target\":\"trade\""), "{command}");

        form.absorb(
            "pick-exe",
            &json!({"ok":true,"filePick":{"slot":"process","target":"trade",
                                           "processName":"my-scan.exe","cancelled":false}}),
        );
        assert_eq!(form.current_agents_draft().programs, vec!["my-scan.exe"]);
        // 直接进草稿列表：输入框（`site`）保持原样，不被当成程序名
        assert!(form.agents_site_draft.is_empty(), "程序不该落进网址输入框");
        assert!(
            form_of(&form.render()).contains("my-scan.exe · 所有网址随之走"),
            "{}",
            form_of(&form.render())
        );

        // 取消选择：不改任何东西，只给一句话
        form.absorb("pick-exe", &json!({"ok":true,"filePick":{"cancelled":true}}));
        assert_eq!(form.current_agents_draft().programs, vec!["my-scan.exe"]);
        assert!(form.agents_note.contains("没有选择程序"), "{}", form.agents_note);
    }

    /// 整页重绘不能把用户正在输入的网址吞掉（勾一个框就会重绘）。
    #[test]
    fn the_site_draft_survives_a_toggle_redraw() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        form.event(&json!({"Event":"change","Id":"site","Value":"perple"}));
        form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        let page = form.render();
        assert_eq!(node(&page["Nodes"], "site").and_then(|n| n.get("Value")).and_then(|v| v.as_str()),
            Some("perple"), "输入框必须回填草稿：{page}");
        // 不合法的输入当场拒绝并说明原因，不发命令
        form.event(&json!({"Event":"change","Id":"site","Value":"abc"}));
        let steps = form.event(&json!({"Event":"click","Id":"add-site"}));
        assert!(steps.is_empty(), "{steps:?}");
        assert!(form.agents_note.contains("至少要有两级"), "{}", form.agents_note);
    }

    /// 页面只用前端**已支持**的节点种类：多一种就会渲染成空白，用户看到一行没内容的区域。
    ///
    /// r104 的白名单里**加回了 `details`**：这一页只有一台，就是「添加其他工具（n）」那个
    /// 全目录折叠区。`check`（勾选框）/ `select` / `rule` 仍然排除。
    #[test]
    fn the_agents_page_only_uses_node_kinds_the_page_already_renders() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&["cursor"], &["my-scan.exe"], &["qq.com"], "trade", true, false),
        );
        form.event(&json!({"Event":"click","Id":"toggle-site-0"}));
        let page = form.render();
        let nodes = flat_nodes(&page);
        assert!(!nodes.is_empty(), "页面必须有节点：{page}");
        for node in &nodes {
            let kind = node["Kind"].as_str().unwrap_or("");
            assert!(
                matches!(
                    kind,
                    "text" | "card" | "row" | "button" | "input" | "details"
                ),
                "前端不认这种节点：{kind}（全部：{nodes:?}）"
            );
        }
        // 名单内 1 行 + 折叠区内 21 行 = 22 行按钮：两段合起来才是整个目录。
        let buttons = builtin_button_texts(&page);
        assert_eq!(
            buttons.len(),
            22,
            "名单内行 + 折叠区内行 = 22 行「添加 / 移除」（11 程序 + 9 网页版 + 2 服务域名）：{buttons:?}"
        );
        assert_eq!(
            buttons.iter().filter(|t| *t == "移除").count(),
            1,
            "只在名单里的那 1 项是「移除」：{buttons:?}"
        );
        assert_eq!(
            buttons.iter().filter(|t| *t == "添加").count(),
            21,
            "折叠区里 21 项是「添加」：{buttons:?}"
        );
        assert!(
            !nodes.iter().any(|n| n["Kind"] == json!("check")),
            "这一页不该再有勾选框：{nodes:?}"
        );
        assert_eq!(
            details_nodes(&page).len(),
            1,
            "全目录是**一台**折叠区（不再每行一台抽屉）：{nodes:?}"
        );
        let text = form.render().to_string();
        assert!(text.contains("桌面程序"), "名单内那一段有分组标题：{text}");
        assert!(
            !text.contains("模型 API 与下载平台"),
            "这次只选了 1 个程序，空的类别不该出现标题：{text}"
        );
        assert!(text.contains("（运行中）") && text.contains("（已安装）"), "运行徽标要渲染：{text}");
        assert!(text.contains("添加其他工具（21）"), "折叠区要带条数：{text}");
        assert!(!text.contains("添加常用 AI 工具"), "一键添加按钮已删掉：{text}");
        assert!(!text.contains("勾选常用 AI 工具"), "旧文案「勾选…」要换掉：{text}");
        // 页头那一句必须与新的交互一致：页面上已经没有勾选框了。
        assert!(text.contains("选择要跟随线路的工具"), "页头那句要说「选择」：{text}");
        assert!(
            !text.contains("勾选要跟随线路的工具"),
            "页面上没有勾选框，不许再说「勾选要跟随线路」：{text}"
        );
        // 域名清单：挂在名称文本节点的 `Hint` 上，前端渲染成 ⓘ（全列，不截断）
        assert!(text.contains("包含的网站："), "域名要落在 Hint 上：{text}");
        let cursor_node = node(&page["Nodes"], "builtin-cursor").and_then(|n| n.get("Kind"));
        assert_eq!(cursor_node.and_then(Value::as_str), Some("button"), "内置项那一行是按钮：{text}");
        assert!(
            text.contains("cursor.com"),
            "Cursor 的域名要在提示里（全列）：{text}"
        );
    }

    // ---------- r104：名单 + 一个可收起的全目录 ----------

    /// 目录里某一项的静态数据：断言文案用**真数据**，不在这里再抄一份。
    fn catalog(id: &str) -> &'static crate::agents::BuiltinAgent {
        crate::agents::BUILTIN
            .iter()
            .find(|item| item.id == id)
            .expect("目录里必须有这一项")
    }

    /// 全部内置项 id，按目录顺序。
    fn all_builtin_ids() -> Vec<&'static str> {
        crate::agents::BUILTIN.iter().map(|item| item.id).collect()
    }

    /// 页面上所有 `text` 节点的**正文**（不含 `Hint`：`Hint` 是另一条通道，前端渲染成 ⓘ）。
    /// 「正文里不许再出现说明」这条判据只能看这里，看整份 JSON 会把 `Hint` 一起算进去。
    fn text_bodies(page: &Value) -> Vec<String> {
        flat_nodes(page)
            .into_iter()
            .filter(|n| n["Kind"] == json!("text"))
            .map(|n| n["Text"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// 某个 `Id` 的节点在整页里出现几次：一行只能出现在一个地方（名单内 **或** 折叠区）。
    fn node_occurrences(page: &Value, id: &str) -> usize {
        flat_nodes(page)
            .iter()
            .filter(|n| n["Id"].as_str() == Some(id))
            .count()
    }

    /// 说明与域名合成**一条** `Hint`（页面上只有一个 ⓘ）。四种组合逐条钉住。
    #[test]
    fn the_hint_joins_the_explanation_and_the_domains_in_one_line() {
        let make = |detail: &str, domains: Vec<String>| AgentsEntryView {
            id: "probe".to_string(),
            kind: "web".to_string(),
            name: "Probe".to_string(),
            detail: detail.to_string(),
            domains,
            presence: String::new(),
        };
        assert_eq!(entry_hint(&make("说明。", vec![])), Some("说明。".to_string()));
        assert_eq!(
            entry_hint(&make("", vec!["a.com".to_string(), "b.com".to_string()])),
            Some("包含的网站：a.com、b.com".to_string()),
            "没有说明时只报域名"
        );
        assert_eq!(
            entry_hint(&make("说明。", vec!["a.com".to_string()])),
            Some("说明。包含的网站：a.com".to_string()),
            "说明以「。」结尾时直接接「包含的网站」，不拼出两个句号"
        );
        assert_eq!(
            entry_hint(&make("没有句号", vec!["a.com".to_string()])),
            Some("没有句号。包含的网站：a.com".to_string()),
            "说明不带句号时补一个，别让两句粘在一起"
        );
        assert_eq!(entry_hint(&make("", vec![])), None, "都没有就不挂 Hint（也就没有 ⓘ）");
    }

    /// 空名单：一条「移除」都没有，22 条全在折叠区里，且折叠区**自动展开**
    /// （一个工具都没选的人，首屏得看得见有什么可选）。
    #[test]
    fn an_empty_agents_list_opens_the_whole_catalog() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        let page = form.render();
        let texts = builtin_button_texts(&page);
        assert_eq!(texts.len(), 22, "整个目录 22 项：{texts:?}");
        assert_eq!(
            texts.iter().filter(|text| *text == "移除").count(),
            0,
            "空名单里没有「移除」：{texts:?}"
        );
        assert_eq!(
            texts.iter().filter(|text| *text == "添加").count(),
            22,
            "22 项都是「添加」：{texts:?}"
        );
        let details = details_nodes(&page);
        assert_eq!(details.len(), 1, "只有一台全目录折叠区：{details:?}");
        assert_eq!(details[0]["Id"], json!("more-builtin"));
        assert_eq!(details[0]["Text"], json!("添加其他工具（22）"), "标题要带条数");
        assert_eq!(details[0]["Open"], json!(true), "名单为空 → 折叠区自动展开");
        // 名单为空时不许出现空的假标题（分组标题只在「名单内」那一段）
        let bodies = text_bodies(&page);
        for title in ["桌面程序", "网页版", "模型 API 与下载平台"] {
            assert!(
                !bodies.iter().any(|text| text == title),
                "名单为空时不该出现分组标题 {title}：{bodies:?}"
            );
        }
        assert!(!form_of(&page).contains("添加其他工具（0）"), "空目录不许出现（0）");
    }

    /// 全部在名单：22 条「移除」、**没有折叠区**；去掉一项之后那一行必须整行搬进折叠区，
    /// 不能在名单内和折叠区各留一行（「全列」的回归就红在这里）。
    #[test]
    fn a_full_agents_list_has_no_catalog_details() {
        let ids = all_builtin_ids();
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&ids, &[], &[], "trade", true, false));
        let page = form.render();
        let texts = builtin_button_texts(&page);
        assert_eq!(texts.len(), 22, "{texts:?}");
        assert_eq!(
            texts.iter().filter(|text| *text == "移除").count(),
            22,
            "全都在名单里：22 行「移除」：{texts:?}"
        );
        assert_eq!(details_nodes(&page).len(), 0, "没有名单外的东西 → 没有折叠区");
        assert!(!form_of(&page).contains("添加其他工具"), "也不许出现空标题");
        let bodies = text_bodies(&page);
        for title in ["桌面程序", "网页版", "模型 API 与下载平台"] {
            assert!(
                bodies.iter().any(|text| text == title),
                "三类的项都在名单里，标题 {title} 要出现：{bodies:?}"
            );
        }

        // 移除一项 → 它搬进折叠区（`node_occurrences` = 1：没有重复行）
        let steps = form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        assert!(steps.is_empty(), "点一行只动草稿，不发命令：{steps:?}");
        let page = form.render();
        assert_eq!(
            node_occurrences(&page, "builtin-cursor"),
            1,
            "同一行不能既在名单内又在折叠区：{}",
            form_of(&page)
        );
        let details = details_nodes(&page);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["Text"], json!("添加其他工具（1）"));
        assert_eq!(details[0]["Open"], json!(false), "还有 21 项在名单里 → 折叠区收起");
        let texts = builtin_button_texts(&page);
        assert_eq!(texts.len(), 22, "两段合起来仍然是 22 行：{texts:?}");
        assert_eq!(texts.iter().filter(|text| *text == "移除").count(), 21);
        assert_eq!(texts.iter().filter(|text| *text == "添加").count(), 1);
    }

    /// 部分在名单（2 项）：分组标题只出现有的那一类；折叠区默认收起、标题带剩余条数。
    #[test]
    fn a_partly_chosen_list_keeps_the_rest_collapsed() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&["cursor", "claude-code"], &[], &[], "trade", true, false),
        );
        let page = form.render();
        let texts = builtin_button_texts(&page);
        assert_eq!(texts.len(), 22, "名单内 2 行 + 折叠区 20 行：{texts:?}");
        assert_eq!(texts.iter().filter(|text| *text == "移除").count(), 2);
        assert_eq!(texts.iter().filter(|text| *text == "添加").count(), 20);
        let bodies = text_bodies(&page);
        assert_eq!(
            bodies.iter().filter(|text| *text == "桌面程序").count(),
            1,
            "只选了程序：这一类标题出现一次：{bodies:?}"
        );
        for title in ["网页版", "模型 API 与下载平台"] {
            assert!(
                !bodies.iter().any(|text| text == title),
                "这一类的项一个都没选，标题 {title} 不该出现：{bodies:?}"
            );
        }
        let details = details_nodes(&page);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["Text"], json!("添加其他工具（20）"));
        assert_eq!(details[0]["Open"], json!(false), "已经在用名单 → 默认收起");
    }

    /// 正文里**不再有**说明：`detail` 全部并进名称的 `Hint`（ⓘ）。
    /// 含域名的项，`Hint` 同时有说明与「包含的网站：」。
    #[test]
    fn the_row_explanation_lives_in_the_hint_not_in_the_body() {
        let mut form = FormState::agents();
        form.absorb(
            "agents",
            &agents_reply(&["cursor"], &[], &[], "trade", true, false),
        );
        let page = form.render();
        let bodies = text_bodies(&page);
        for item in crate::agents::BUILTIN.iter() {
            assert!(
                !bodies.iter().any(|text| text.contains(item.detail)),
                "「{}」的说明不该再占一行正文：{bodies:?}",
                item.name
            );
        }
        // 但 `Hint` 里必须有（只是不再铺在页面上）
        let rendered = form_of(&page);
        for item in crate::agents::BUILTIN.iter() {
            assert!(
                rendered.contains(item.detail),
                "「{}」的说明要留在 Hint 里：{rendered}",
                item.name
            );
        }
        // Cursor 有说明 + 域名：一条 Hint 里两样都在，且不拼出两个句号
        let cursor = catalog("cursor");
        let name_node = flat_nodes(&page)
            .into_iter()
            .find(|n| {
                n["Kind"] == json!("text")
                    && n["Text"]
                        .as_str()
                        .map(|text| text.starts_with(cursor.name))
                        .unwrap_or(false)
            })
            .expect("Cursor 那一行要有名称文本节点");
        let hint = name_node["Hint"].as_str().unwrap_or("");
        assert!(hint.contains(cursor.detail), "说明要在 ⓘ 里：{hint}");
        assert!(hint.contains("包含的网站："), "域名要在同一个 ⓘ 里：{hint}");
        assert!(hint.contains(cursor.domains[0]), "域名要全列：{hint}");
        assert!(!hint.contains("。。"), "说明已经以「。」结尾，不许再补一个：{hint}");
        assert!(
            name_node["Text"].as_str().unwrap_or("").contains("（已安装）"),
            "运行徽标还留在名称上：{name_node}"
        );
    }

    /// 点折叠区里的「添加」：那一行**当场**搬到名单内那一段（分组标题之后、折叠区之前），
    /// 草稿跟着变、一条命令都不发。
    #[test]
    fn clicking_add_inside_the_catalog_moves_the_row_into_the_list() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        let generation = form.generation;
        let page = form.render();
        let nodes = flat_nodes(&page);
        let at = |nodes: &[Value], wanted: &Value, key: &str| {
            nodes
                .iter()
                .position(|n| &n[key] == wanted)
                .unwrap_or_else(|| panic!("找不到 {key}={wanted}：{nodes:?}"))
        };
        assert!(
            at(&nodes, &json!("builtin-cursor"), "Id")
                > at(&nodes, &json!("details"), "Kind"),
            "点之前它在折叠区里面"
        );

        let steps = form.event(&json!({"Event":"click","Id":"builtin-cursor"}));
        assert!(steps.is_empty(), "点「添加」只动草稿，不发命令：{steps:?}");
        assert_eq!(
            form.current_agents_draft().builtin,
            vec!["cursor"],
            "草稿里真的多了这一项"
        );
        assert!(form.agents_dirty(), "改了一项就应该是「有改动」");
        assert!(
            form.generation > generation,
            "整段结构变了（换段 + 折叠区条数），必须整页重画，而不是就地打补丁"
        );

        let page = form.render();
        let nodes = flat_nodes(&page);
        let at_cursor = at(&nodes, &json!("builtin-cursor"), "Id");
        assert!(
            at_cursor < at(&nodes, &json!("details"), "Kind"),
            "同一帧重画后它已经在名单内那一段（折叠区之前）：{}",
            form_of(&page)
        );
        assert!(
            at(&nodes, &json!("桌面程序"), "Text") < at_cursor,
            "名单内的分组标题要排在它前面"
        );
        assert_eq!(row_button_text(&form, "builtin-cursor"), "移除", "按钮翻成「移除」");
        let details = details_nodes(&page);
        assert_eq!(details[0]["Text"], json!("添加其他工具（21）"));
        assert_eq!(details[0]["Open"], json!(false), "有了一项就不再自动展开");
    }

    /// 页面上不再有「添加常用 AI 工具」（那个一键按钮已经删掉，连控件名一起）。
    /// 旧页面/旧自动化万一还点 `recommend`：不发命令、也不许把草稿一键填满。
    #[test]
    fn the_page_offers_no_add_all_shortcut() {
        let mut form = FormState::agents();
        form.absorb("agents", &agents_reply(&[], &[], &[], "daily", true, false));
        let page = form.render();
        assert!(
            node(&page["Nodes"], "recommend").is_none(),
            "一键添加按钮已经从页面删掉：{}",
            form_of(&page)
        );
        let text = form_of(&page);
        assert!(!text.contains("添加常用 AI 工具"), "这几个字不该再出现：{text}");
        assert!(!text.contains("AgentsRecommend"), "控件名也不该再出现：{text}");

        let steps = form.event(&json!({"Event":"click","Id":"recommend"}));
        assert!(steps.is_empty(), "没有这个入口，也就不该发命令：{steps:?}");
        assert!(
            form.current_agents_draft().builtin.is_empty(),
            "更不该把 22 项一键塞进草稿：{:?}",
            form.current_agents_draft().builtin
        );
        assert!(
            !form.agents_note.contains("已添加常用 AI 工具"),
            "那句「已添加…保存后生效」一并删掉：{}",
            form.agents_note
        );
    }

    #[test]
    fn agents_page_does_not_claim_ineffective_under_global_override() {
        // PRD §7.1：日常上网=交易线路时，名单实际按交易线路走。
        // 页面不得说「跟随日常上网，暂不生效」——那句话在全局覆盖下是假话。
        let mut form = FormState::agents();
        let mut reply = agents_reply(&[], &[], &[], "daily", true, false);
        reply["agents"]["globalOverride"] = json!(true);
        reply["agents"]["laneEffective"] = json!("trade");
        form.absorb("agents", &reply);
        let page = form.render().to_string();
        assert!(!page.contains("跟随日常上网，暂不生效"), "全局覆盖下这句是假话：{page}");
        assert!(page.contains("名单当前走交易线路") || page.contains("日常上网走交易线路"), "{page}");
        // 走向**不在这页改**（旧版同）：没有下拉，也就没有「禁用态」要维护。
        // 改走向去应用页那一行；这一页只按读到的走向说实话。
        let lane = node(&form.render()["Nodes"], "lane").cloned().unwrap_or(Value::Null);
        assert_eq!(lane, Value::Null, "这一页不该再有走向控件：{lane}");
    }

    #[test]
    fn lane_change_is_ignored_under_global_override() {
        // 这一页没有走向控件；残页 / 改包把 change 送进来，宿主也不得改草稿
        // （走向归应用页那一行，两个入口改同一个值只会让人问「到底哪个算数」）。
        let mut form = FormState::agents();
        let mut reply = agents_reply(&[], &[], &[], "daily", true, false);
        reply["agents"]["globalOverride"] = json!(true);
        form.absorb("agents", &reply);
        let _ = form.event(&json!({"Event":"change","Id":"lane","Value":1}));
        assert_eq!(form.agents_lane, 0, "全局覆盖时走向改不动");
        assert!(!form.agents_dirty(), "被忽略的改动不应把页面弄脏");
    }

    #[test]
    fn providers_page_scans_adds_and_removes_through_existing_commands() {
        let mut form = FormState::providers();
        form.absorb("providers", &json!({"ok":true,"providers":[],"entryNote":""}));
        assert!(form.render().to_string().contains("还没有登记代理软件"));

        // 扫描：找到就把端口/域名/种类填好，名字要人自己确认。
        form.event(&json!({"Event":"click","Id":"discover"}));
        form.absorb("provider-discover", &json!({"ok":true,"found":[{
            "kind":"clashverge","directory":"C:\\Tools\\Clash Verge","dailyPort":7890,
            "domains":["a.com","b.com"],"entryNote":""}],"errors":[]}));
        assert_eq!(form.kind, 0);
        assert_eq!(form.port, "7890");
        assert!(form.notice.contains("已找到 Clash Verge"), "{}", form.notice);

        // 端口不合法时零写盘，只在页面里说清楚。
        form.event(&json!({"Event":"change","Id":"name","Value":"我的代理"}));
        form.event(&json!({"Event":"change","Id":"port","Value":"70000"}));
        assert!(form.event(&json!({"Event":"click","Id":"add-provider"})).is_empty());
        assert!(form.notice.contains("1–65535"));

        form.event(&json!({"Event":"change","Id":"port","Value":"7890"}));
        form.event(&json!({"Event":"change","Id":"domains","Value":"a.com，b.com"}));
        let steps = form.event(&json!({"Event":"click","Id":"add-provider"}));
        let Step::Sync(add) = &steps[0] else { panic!("添加要发命令") };
        assert!(add.contains("provider-add") && add.contains("clashverge")
            && add.contains("7890") && add.contains("b.com"), "{add}");

        form.absorb("provider-add", &json!({"ok":true,"message":"已登记槽位 1 的服务商",
            "providers":[{"slot":1,"name":"我的代理","kind":"clashverge","dailyPort":7890,
                          "effectiveState":"pending","effectiveReason":"尚未应用到当前线路",
                          "effectiveRole":"daily"}]}));
        assert!(form.draft.is_empty() && form.port.is_empty(), "添加成功后清空草稿");
        let view = form.render().to_string();
        assert!(view.contains("槽位 1 · 我的代理 · 日常端口 7890"), "{view}");
        assert!(view.contains("等待生效"), "{view}");

        // 删除要两步：先点亮确认，再真发命令。
        let steps = form.event(&json!({"Event":"click","Id":"remove-1"}));
        assert!(steps.is_empty(), "第一下只进入确认态");
        assert_eq!(form.pending_remove, Some(1));
        assert!(form.render().to_string().contains("确认删除"));
        let steps = form.event(&json!({"Event":"click","Id":"confirm-remove"}));
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("provider-remove") && c.contains("1")));
        assert!(form.pending_remove.is_none(), "发命令后不再显示确认按钮");
    }

    #[test]
    fn maintenance_shows_the_journal_state_and_restores_through_the_budget_channel() {
        let mut form = FormState::maintenance();
        assert_eq!(form.render()["ViewKey"], "maintenance");
        form.absorb("maintenance-status", &json!({"ok":true,"maintenance":{
            "journal_present":true,"proxy_owned":false,"can_restore":true,
            "endpoint":"127.0.0.1:9545"}}));
        let view = form.render();
        let text = view.to_string();
        assert!(text.contains("可以把系统代理改回去"), "{text}");
        assert!(text.contains("127.0.0.1:9545"), "{text}");
        assert_eq!(view["PageActions"][0]["Disabled"], false, "可还原时按钮要能点");

        let steps = form.event(&json!({"Event":"click","Id":"restore-proxy"}));
        assert!(matches!(&steps[0], Step::Long(c) if c.contains("\"restore\"")));
        assert!(form.running);

        form.absorb_restore(&json!({"ok":true,"message":"已按凭据还原系统代理。",
            "maintenance":{"journal_present":false,"proxy_owned":false,"can_restore":false}}));
        assert!(!form.running);
        let text = form.render().to_string();
        assert!(text.contains("已按凭据还原系统代理"), "{text}");
        assert!(text.contains("没有待还原的代理设置"), "{text}");
        assert_eq!(form.render()["PageActions"][0]["Disabled"], true, "没有凭据时按钮禁用");
    }

    #[test]
    fn maintenance_removes_guard_only_after_a_two_step_confirmation() {
        let mut form = FormState::maintenance();
        let text = form.render().to_string();
        assert!(text.contains("解除交易保护"), "维护页必须有显式入口：{text}");
        assert!(!text.contains("不在预览版范围"), "缺失不能再被说成范围外：{text}");
        assert!(!text.contains("确认解除"), "第一屏不该已经有确认按钮：{text}");

        // 第一步：只出后果，不发命令。
        form.event(&json!({"Event":"click","Id":"guard-remove"}));
        assert!(form.guard_remove_pending);
        let text = form.render().to_string();
        assert!(text.contains("确认解除交易保护"), "{text}");
        assert!(text.contains("下次连接会重新启用"), "{text}");

        // 取消回到第一屏。
        form.event(&json!({"Event":"click","Id":"cancel-guard-remove"}));
        assert!(!form.guard_remove_pending);
        assert!(!form.render().to_string().contains("确认解除交易保护"));

        // 第二步才发长命令。
        form.event(&json!({"Event":"click","Id":"guard-remove"}));
        let steps = form.event(&json!({"Event":"click","Id":"confirm-guard-remove"}));
        assert!(matches!(&steps[0], Step::Long(c) if c.contains("\"guard-remove\"")));
        assert!(form.running);

        // 回读通过（后端给出 UserRemoved）才许说「已解除」。
        form.absorb_guard_remove(&json!({
            "guardRemove": {"ok": true, "message": "交易保护已解除；下次连接会重新启用。",
                "guard": {"Guard": "Unprotected",
                          "GuardSummary": "交易保护已解除；下次连接会重新启用。",
                          "GuardEvidence": {"Reason": "UserRemoved"}}}
        }));
        assert!(!form.running);
        assert!(!form.guard_remove_pending);
        assert!(form.render().to_string().contains("交易保护已解除"));

        // 失败（例如交易软件还在运行）必须停在失败文案，不能冒充成功。
        form.event(&json!({"Event":"click","Id":"guard-remove"}));
        form.event(&json!({"Event":"click","Id":"confirm-guard-remove"}));
        form.absorb_guard_remove(&json!({
            "guardRemove": {"ok": false, "message": "请先退出交易软件再解除保护", "guard": Value::Null}
        }));
        let text = form.render().to_string();
        assert!(text.contains("请先退出交易软件"), "{text}");
        assert!(!text.contains("已解除"), "失败不得显示已解除：{text}");
    }

    #[test]
    fn history_form_lists_events_and_filters_failures() {
        let mut form = FormState::history();
        assert_eq!(form.render()["ViewKey"], "history");
        assert!(form.render().to_string().contains("正在读取记录"));
        assert!(matches!(
            form.event(&json!({"Event":"click","Id":"export-history"}))[0],
            Step::Sync(_)
        ));

        let reply = json!({"ok":true,"events":[
            {"ts":"2026-11-02T02:00:00Z","action":"连接","ok":true,"detail":"","obj":"线路","src":"ui"},
            {"ts":"2026-11-02T01:59:00Z","action":"导入","ok":false,"detail":"端口被占用","obj":"","src":"cli"}
        ]});
        form.absorb("history", &reply);
        let view = form.render().to_string();
        assert!(view.contains("11-02 02:00"), "时间要压成 MM-DD HH:MM：{view}");
        assert!(view.contains("成功") && view.contains("失败"), "{view}");
        assert!(view.contains("端口被占用"), "{view}");

        // 结果 = 失败（下拉下标 2）。
        form.event(&json!({"Event":"change","Id":"history-result","Value":2}));
        assert!(form.only_fail);
        let filtered = form.render().to_string();
        assert!(filtered.contains("端口被占用"), "{filtered}");
        assert!(!filtered.contains("11-02 02:00"), "只看失败时成功那条不该在：{filtered}");

        // 导出必须把筛选放进 `filter` 对象里——后端读的是 `filter.onlyFail`，
        // 发在顶层等于没筛（r87 之前就是这样）。
        let steps = form.event(&json!({"Event":"click","Id":"export-history"}));
        assert!(
            matches!(&steps[0], Step::Sync(c)
                if c.contains("export-history")
                    && c.contains("\"filter\"")
                    && c.contains("\"onlyFail\":true")),
            "{steps:?}"
        );
    }

    /// 搜索与来源筛选（r87，对齐 旧版那一排「搜索 + 来源 + 状态」）。
    #[test]
    fn history_filters_by_search_text_and_source() {
        let mut form = FormState::history();
        form.absorb(
            "history",
            &json!({"ok":true,"events":[
                {"ts":"2026-11-02T02:00:00Z","action":"连接","ok":true,"detail":"自建 · A","src":"ui"},
                {"ts":"2026-11-02T01:59:00Z","action":"导入","ok":false,"detail":"端口被占用","src":"cli"},
                {"ts":"2026-11-02T01:00:00Z","action":"自动切换","ok":true,"detail":"切到 B","src":"auto"}
            ]}),
        );

        // 搜索：按操作名
        form.event(&json!({"Event":"change","Id":"history-search","Value":"导入"}));
        let text = form.render().to_string();
        assert!(text.contains("端口被占用"), "{text}");
        assert!(!text.contains("自建 · A") && !text.contains("切到 B"), "{text}");

        // 清搜索，来源 = 命令行（下标 2）
        form.event(&json!({"Event":"change","Id":"history-search","Value":""}));
        form.event(&json!({"Event":"change","Id":"history-src","Value":2}));
        let text = form.render().to_string();
        assert!(text.contains("端口被占用"), "{text}");
        assert!(!text.contains("自建 · A") && !text.contains("切到 B"), "{text}");

        // 来源 = 自动（下标 3）→ 只剩自动那条
        form.event(&json!({"Event":"change","Id":"history-src","Value":3}));
        let text = form.render().to_string();
        assert!(text.contains("切到 B"), "{text}");
        assert!(!text.contains("端口被占用"), "{text}");

        // 导出要带上来源
        let steps = form.event(&json!({"Event":"click","Id":"export-history"}));
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("\"src\":\"auto\"")),
            "{steps:?}"
        );
    }

    #[test]
    fn servers_page_lists_every_recorded_server() {
        let mut form = FormState::servers();
        assert_eq!(form.render()["ViewKey"], "servers");
        assert!(form.render().to_string().contains("正在读取服务器记录"));

        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a","Name":"东京节点","Host":"203.0.113.10","LineIds":["hk","jp"]},
                {"Id":"b","Name":"","Host":"198.51.100.7","LineIds":[]}
            ]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("东京节点"), "{view}");
        assert!(view.contains("203.0.113.10"), "{view}");
        assert!(view.contains("关联 2 条线路"), "要给出关联线路数：{view}");
        assert!(view.contains("198.51.100.7"), "没有名字时用地址兜底：{view}");
        assert!(view.contains("还没有线路用到它"), "0 条线路不是错：{view}");
        assert!(
            !view.contains("正在读取服务器记录"),
            "拿到回包后不该还写着正在读取"
        );
    }

    /// r94：服务器页有「导出管理恢复包…」与「导入管理恢复资料…」两个入口。
    #[test]
    fn the_server_page_offers_recovery_export_and_import() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[{
                "Id":"a1","Name":"东京节点","Host":"203.0.113.10","Port":22,
                "User":"root","Fingerprint":"SHA256:AAAA","LineIds":[]
            }]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("recovery-import-open"), "{view}");
        assert!(view.contains("recovery-export:a1"), "{view}");
        assert!(view.contains("导入管理恢复资料…"), "{view}");
        assert!(view.contains("导出管理恢复包…"), "{view}");

        // 导入入口：进入导入页，页面上有粘贴框与密码框。
        let steps = form.event(&json!({"Event":"click","Id":"recovery-import-open"}));
        assert!(steps.is_empty(), "打开页面不发命令");
        assert_eq!(form.view, View::Recovery);
        assert!(form.recovery_mode_import);
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        assert!(text.contains("导入已有加密恢复包"), "{text}");
        assert!(node(&view["Nodes"], "recovery-text").is_some(), "{text}");
        assert!(node(&view["Nodes"], "recovery-password").is_some(), "{text}");
        assert!(node(&view["Nodes"], "recovery-import").is_some(), "{text}");
    }

    /// r94：从某条服务器进入导出页，目标名字与旧版三件套都在。
    #[test]
    fn the_recovery_export_page_has_the_old_controls() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[{
                "Id":"a1","Name":"东京节点","Host":"203.0.113.10","Port":22,
                "User":"root","Fingerprint":"SHA256:AAAA","LineIds":[]
            }]}),
        );
        form.event(&json!({"Event":"click","Id":"recovery-export:a1"}));
        assert_eq!(form.view, View::Recovery);
        assert!(!form.recovery_mode_import);
        assert_eq!(form.recovery_server_id, "a1");
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        assert!(text.contains("导出当前服务器的管理恢复包"), "{text}");
        assert!(text.contains("目标：东京节点"), "{text}");
        assert!(text.contains("恢复包密码（至少 12 个字符）"), "{text}");
        assert!(node(&view["Nodes"], "recovery-include").is_some(), "{text}");
        // 默认不含凭据：私钥/口令两格不出现。
        assert!(node(&view["Nodes"], "recovery-key-path").is_none(), "{text}");
        assert!(node(&view["Nodes"], "recovery-credential").is_none(), "{text}");

        form.event(&json!({"Event":"change","Id":"recovery-include","Value":true}));
        assert!(form.recovery_include);
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        assert!(text.contains("SSH 私钥文件"), "{text}");
        assert!(text.contains("要包含的 SSH 密码 / 私钥口令"), "{text}");
        assert!(node(&view["Nodes"], "recovery-key-path").is_some(), "{text}");
        assert!(node(&view["Nodes"], "recovery-credential").is_some(), "{text}");
        assert!(node(&view["Nodes"], "pick-recovery-key").is_some(), "{text}");
    }

    /// r94：短密码在页面上就被拦下，不发命令。
    #[test]
    fn a_short_recovery_password_is_refused_before_sending() {
        let mut form = FormState::recovery_export("a1", "东京节点");
        form.event(&json!({"Event":"change","Id":"recovery-password","Value":"short"}));
        let steps = form.event(&json!({"Event":"click","Id":"recovery-export"}));
        assert!(steps.is_empty(), "短密码不许发命令：{steps:?}");
        assert!(form.recovery_notice.contains("至少 12"), "{}", form.recovery_notice);
    }

    /// r94：导出回包把加密文本落到页面；「保存到文件…」发 save-file。
    #[test]
    fn the_recovery_export_reply_lands_in_the_page_and_can_be_saved() {
        let mut form = FormState::recovery_export("a1", "东京节点");
        form.event(&json!({"Event":"change","Id":"recovery-password","Value":"r94-recovery-pass"}));
        let steps = form.event(&json!({"Event":"click","Id":"recovery-export"}));
        let [Step::Sync(command)] = &steps[..] else {
            panic!("应发一条 recovery-export：{steps:?}");
        };
        assert!(command.contains("recovery-export"), "{command}");
        assert!(command.contains("\"serverId\":\"a1\""), "{command}");
        assert!(command.contains("\"includeCredential\":false"), "{command}");

        form.absorb(
            "recovery-export",
            &json!({"ok":true,"recovery":{
                "Package":"ENC-PACKAGE",
                "FileName":"management-recovery.tcrecovery",
                "Message":"恢复包已加密。请把它与密码分开保存。"
            }}),
        );
        assert_eq!(form.recovery_package, "ENC-PACKAGE");
        assert!(form.recovery_password.is_empty(), "加密完密码不该留在内存里");
        let view = form.render();
        let text = serde_json::to_string(&view).unwrap_or_default();
        assert!(text.contains("ENC-PACKAGE"), "{text}");
        assert!(node(&view["Nodes"], "recovery-package").is_some(), "{text}");
        assert!(node(&view["Nodes"], "recovery-save").is_some(), "{text}");

        let steps = form.event(&json!({"Event":"click","Id":"recovery-save"}));
        let [Step::Sync(command)] = &steps[..] else {
            panic!("应发一条 save-file：{steps:?}");
        };
        assert!(command.contains("save-file"), "{command}");
        assert!(command.contains("ENC-PACKAGE"), "{command}");
        assert!(command.contains("management-recovery.tcrecovery"), "{command}");
    }

    /// r94：导入页的空包 / 短密码都在页面上拦下；成功回包标记完成并清掉秘密。
    #[test]
    fn the_recovery_import_page_validates_and_finishes() {
        let mut form = FormState::recovery_import_form();
        let steps = form.event(&json!({"Event":"click","Id":"recovery-import"}));
        assert!(steps.is_empty(), "空包不许发命令");
        assert!(form.recovery_notice.contains("粘贴"), "{}", form.recovery_notice);

        form.event(&json!({"Event":"change","Id":"recovery-text","Value":"{}"}));
        form.event(&json!({"Event":"change","Id":"recovery-password","Value":"short"}));
        let steps = form.event(&json!({"Event":"click","Id":"recovery-import"}));
        assert!(steps.is_empty(), "短密码不许发命令");
        assert!(form.recovery_notice.contains("至少 12"), "{}", form.recovery_notice);

        form.event(&json!({"Event":"change","Id":"recovery-password","Value":"r94-recovery-pass"}));
        let steps = form.event(&json!({"Event":"click","Id":"recovery-import"}));
        let [Step::Sync(command)] = &steps[..] else {
            panic!("应发一条 recovery-import：{steps:?}");
        };
        assert!(command.contains("recovery-import"), "{command}");
        assert!(command.contains("\"package\":\"{}\""), "{command}");

        form.absorb(
            "recovery-import",
            &json!({"ok":true,"recovery":{
                "ServerId":"a1","Name":"恢复的服务器",
                "Message":"管理资料已登记，实际登录与服务器身份仍待核验。"
            }}),
        );
        assert!(form.recovery_done);
        assert!(form.recovery_text.is_empty(), "导入成功后清掉粘贴的密文");
        assert!(form.recovery_password.is_empty(), "导入成功后清掉密码");
        assert!(form.recovery_notice.contains("仍待核验"), "{}", form.recovery_notice);
        let text = serde_json::to_string(&form.render()).unwrap_or_default();
        assert!(text.contains("已登记"), "{text}");
        assert!(!text.contains("recovery-import\""), "完成后不再给重复导入按钮：{text}");
    }

    /// r94：从文件选择恢复包时，宿主把文件内容一起带回来。
    #[test]
    fn a_picked_recovery_file_lands_in_the_textarea() {
        let mut form = FormState::recovery_import_form();
        form.absorb(
            "pick-file",
            &json!({"ok":true,"filePick":{
                "slot":"recovery","path":r"C:\tmp\x.tcrecovery",
                "cancelled":false,"text":"ENC-FROM-FILE"
            }}),
        );
        assert_eq!(form.recovery_text, "ENC-FROM-FILE");
        let view = form.render();
        assert_eq!(
            node(&view["Nodes"], "recovery-text").unwrap()["Value"],
            json!("ENC-FROM-FILE")
        );

        // 取消不改旧值。
        form.absorb(
            "pick-file",
            &json!({"ok":true,"filePick":{"slot":"recovery","cancelled":true}}),
        );
        assert_eq!(form.recovery_text, "ENC-FROM-FILE");
    }

    /// r94：保存回包把路径显示出来；取消不清掉已生成的包。
    #[test]
    fn the_recovery_save_reply_records_the_path() {
        let mut form = FormState::recovery_export("a1", "东京节点");
        form.recovery_package = "ENC".into();
        form.absorb(
            "save-file",
            &json!({"ok":true,"fileSave":{"slot":"recovery","path":r"C:\tmp\x.tcrecovery","cancelled":false,"saved":true}}),
        );
        assert_eq!(form.recovery_saved_path, r"C:\tmp\x.tcrecovery");
        assert!(form.recovery_notice.contains("已保存"), "{}", form.recovery_notice);
        form.absorb(
            "save-file",
            &json!({"ok":true,"fileSave":{"slot":"recovery","cancelled":true,"saved":false}}),
        );
        assert_eq!(form.recovery_package, "ENC", "取消保存不该清掉已生成的包");
    }

    #[test]
    fn servers_page_says_read_failure_instead_of_showing_an_empty_list() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":false,"error":"凭据目录正忙","servers":[]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("凭据目录正忙"), "读不出来要说原因：{view}");
        assert!(
            !view.contains("还没有记录任何服务器"),
            "「读不出来」不许说成「没有」：{view}"
        );
    }

    /// C7：身份事实（地址/端口/指纹/记录时间）上屏；改名只发一条本地命令。
    #[test]
    fn servers_page_shows_identity_and_renames_the_record() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[{
                "Id":"a1","Name":"东京节点","Host":"203.0.113.10","Port":22,
                "User":"root","Fingerprint":"SHA256:AAAA",
                "CreatedAtUtc":"2026-11-11T10:00:00Z","LineIds":["hk"]
            }]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("root@203.0.113.10:22"), "身份要带登录目标：{view}");
        assert!(view.contains("指纹 SHA256:AAAA"), "身份要带指纹：{view}");
        assert!(view.contains("记录于 2026-11-11T10:00:00Z"), "{view}");
        assert!(view.contains("server-rename:a1"), "每条记录要有改名入口：{view}");

        // 点「改名」只把那一条换成输入框，不发命令。
        let steps = form.event(&json!({"Event":"click","Id":"server-rename:a1"}));
        assert!(steps.is_empty(), "打开改名不发命令");
        assert_eq!(form.server_rename.as_deref(), Some("a1"));
        let editing = form.render().to_string();
        assert!(editing.contains("保存名称"), "{editing}");
        assert!(editing.contains("东京节点"), "输入框要带当前名称：{editing}");

        form.event(&json!({"Event":"change","Id":"name","Value":"东京主力"}));
        let steps = form.event(&json!({"Event":"click","Id":"save-server-rename"}));
        assert!(matches!(
            &steps[0],
            Step::Sync(c) if c.contains("server-rename") && c.contains("\"a1\"") && c.contains("东京主力")
        ));

        // 生产上的形态：宿主合并**只带白名单键**，成功回包的 `message` 不会进来。
        // 提示必须能从刷新后的 `servers` 列表推出来——这里刻意不给 message。
        form.absorb(
            "server-rename",
            &json!({"ok":true,"servers":[{
                "Id":"a1","Name":"东京主力","Host":"203.0.113.10","Port":22,
                "User":"root","Fingerprint":"SHA256:AAAA","LineIds":["hk"]
            }]}),
        );
        assert_eq!(form.server_rename, None, "成功后收掉输入框");
        let done = form.render().to_string();
        assert!(done.contains("东京主力"), "{done}");
        assert!(done.contains("已改名为「东京主力」"), "{done}");
        assert!(!done.contains("保存名称"), "成功后不该还留着输入框：{done}");
    }

    /// 校验失败不发命令；回包失败保留草稿与输入框，让人改一改再保存。
    #[test]
    fn a_refused_server_rename_keeps_the_draft_and_says_why() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[{"Id":"a1","Name":"旧名","Host":"203.0.113.10","LineIds":[]}]}),
        );
        form.event(&json!({"Event":"click","Id":"server-rename:a1"}));
        form.event(&json!({"Event":"change","Id":"name","Value":"   "}));
        let steps = form.event(&json!({"Event":"click","Id":"save-server-rename"}));
        assert!(steps.is_empty(), "空名称不许发命令");
        assert!(form.render().to_string().contains("1–120"), "要说清为什么不让保存");

        form.event(&json!({"Event":"change","Id":"name","Value":"东京"}));
        form.absorb("server-rename", &json!({"ok":false,"error":"磁盘正忙"}));
        let view = form.render().to_string();
        assert!(view.contains("磁盘正忙"), "后端原话要上屏：{view}");
        assert!(view.contains("保存名称"), "失败后输入框要留着：{view}");
        assert_eq!(form.server_rename.as_deref(), Some("a1"));
        assert_eq!(form.draft, "东京");
    }

    /// 删除服务器记录：有线路时页面就挡住；确认后才发命令。
    #[test]
    fn servers_page_deletes_a_record_only_after_confirmation_and_without_lines() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a1","Name":"东京","Host":"203.0.113.10","LineIds":["L1"]}
            ]}),
        );
        form.event(&json!({"Event":"click","Id":"server-remove:a1"}));
        let blocked = form.render().to_string();
        assert!(blocked.contains("还有 1 条线路"), "{blocked}");
        assert!(
            !blocked.contains("confirm-server-remove"),
            "还有线路时不该给确认按钮：{blocked}"
        );
        form.event(&json!({"Event":"click","Id":"cancel-server-remove"}));
        assert_eq!(form.server_remove, None);

        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a1","Name":"东京","Host":"203.0.113.10","LineIds":[]}
            ]}),
        );
        form.event(&json!({"Event":"click","Id":"server-remove:a1"}));
        assert!(form.render().to_string().contains("confirm-server-remove"));
        let steps = form.event(&json!({"Event":"click","Id":"confirm-server-remove"}));
        assert!(matches!(
            &steps[0],
            Step::Sync(c) if c.contains("server-remove") && c.contains("\"a1\"")
        ));
        form.absorb("server-remove", &json!({"ok":true,"servers":[]}));
        assert_eq!(form.server_remove, None);
        assert!(form.render().to_string().contains("已删除服务器记录"));
    }

    /// 「删除本机部署资料…」：入口在「删除记录」**之前**（危险动作排最后），
    /// 点它先发只读预览，不直接弹框。
    #[test]
    fn servers_page_offers_the_cleanup_before_the_plain_delete() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a1","Name":"东京","Host":"203.0.113.10","LineIds":[]}
            ]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("删除本机部署资料…"), "{view}");
        let cleanup = view.find("server-cleanup:a1").expect("要有清理入口");
        let remove = view.find("server-remove:a1").expect("要有删除入口");
        assert!(cleanup < remove, "清理在前、删记录在后：{view}");

        let steps = form.event(&json!({"Event":"click","Id":"server-cleanup:a1"}));
        assert_eq!(form.server_cleanup.as_deref(), Some("a1"));
        assert!(matches!(
            &steps[0],
            Step::Sync(c) if c.contains("server-cleanup-preview") && c.contains("\"a1\"")
        ));
        assert!(
            form.take_server_cleanup_dialog().is_none(),
            "点了按钮还不该有框：结论要等预览回包"
        );
    }

    /// 预览回包 → 一张危险确认框：逐项列出要删什么，说清服务器不受影响。
    #[test]
    fn the_cleanup_preview_becomes_a_danger_dialog_listing_every_item() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a1","Name":"东京","Host":"203.0.113.10","LineIds":[]}
            ]}),
        );
        form.event(&json!({"Event":"click","Id":"server-cleanup:a1"}));
        form.absorb_server_cleanup_preview(&json!({"ok":true,"serverCleanup":{
            "Id":"a1","Name":"东京","Host":"203.0.113.10","Port":22,"User":"root",
            "Lines":0,"Runs":3,"Archived":1,"Active":0,"Reminders":2,"TaskCredentials":1,
            "SavedCredential":true,"Blocked":"",
            "Items":["服务器记录","部署任务记录 3 条（含已归档 1 条）","结果提醒 2 条",
                     "任务级登录资料 1 份","长期保存的登录资料"]
        }}));
        let dialog = form.take_server_cleanup_dialog().expect("预览要给一张确认框");
        assert_eq!(dialog["Scope"], "server-cleanup", "{dialog}");
        assert_eq!(dialog["Target"], "a1", "{dialog}");
        assert_eq!(dialog["Danger"], true, "{dialog}");
        assert_eq!(dialog["Title"], "删除这台服务器在本机的部署资料？", "{dialog}");
        assert_eq!(dialog["Confirm"], "删除本机资料", "{dialog}");
        assert_eq!(dialog["Cancel"], "先不删", "{dialog}");
        let body = dialog["Body"].as_str().unwrap_or_default();
        for item in [
            "服务器记录",
            "部署任务记录 3 条（含已归档 1 条）",
            "结果提醒 2 条",
            "任务级登录资料 1 份",
            "长期保存的登录资料",
        ] {
            assert!(body.contains(item), "正文要逐项列出「{item}」：{body}");
        }
        let note = dialog["Note"].as_str().unwrap_or_default();
        assert!(note.contains("服务器上的通道服务"), "要说清服务器不受影响：{note}");
        assert!(
            form.take_server_cleanup_dialog().is_none(),
            "取走之后就没了（免得每次刷新都重新弹）"
        );
    }

    /// 不能删时：正文直接说原因，**没有危险按钮**（`Scope` 也不是 `server-cleanup`，
    /// 否则那句「知道了」会被宿主当成确认）。
    #[test]
    fn a_blocked_cleanup_dialog_only_acknowledges() {
        let mut form = FormState::servers();
        form.server_cleanup = Some("a1".to_string());
        let reason = "这台服务器还有 2 个部署没有结束；请等它跑完（或先取消），再删除本机资料。";
        form.absorb_server_cleanup_preview(&json!({"ok":true,"serverCleanup":{
            "Id":"a1","Name":"东京","Host":"203.0.113.10","Port":22,"User":"root",
            "Lines":0,"Runs":2,"Archived":0,"Active":2,"Reminders":0,"TaskCredentials":0,
            "SavedCredential":false,"Blocked":reason,"Items":["服务器记录","部署任务记录 2 条"]
        }}));
        let dialog = form.take_server_cleanup_dialog().expect("被拦住也要说一句");
        assert_eq!(dialog["Scope"], "server-cleanup-blocked", "{dialog}");
        assert_eq!(dialog["Confirm"], "知道了", "{dialog}");
        assert_eq!(dialog["Cancel"], "", "只有「知道了」：{dialog}");
        assert_eq!(dialog["Danger"], false, "{dialog}");
        assert_eq!(dialog["Body"].as_str(), Some(reason), "{dialog}");
    }

    /// 预览本身读不出来也要有回话，而且不许变成「可以删」。
    #[test]
    fn a_failed_preview_never_looks_deletable() {
        let mut form = FormState::servers();
        form.server_cleanup = Some("a1".to_string());
        form.absorb_server_cleanup_preview(
            &json!({"ok":false,"errorCode":"config","error":"部署提醒不是合法 JSON"}),
        );
        let dialog = form.take_server_cleanup_dialog().expect("失败也要说一句");
        assert_eq!(dialog["Scope"], "server-cleanup-blocked", "{dialog}");
        assert_eq!(dialog["Danger"], false, "{dialog}");
        assert!(
            dialog["Body"]
                .as_str()
                .unwrap_or_default()
                .contains("部署提醒不是合法 JSON"),
            "{dialog}"
        );
    }

    /// 执行回包：成功刷新列表并说清结论；有没删掉的项要显眼；失败留原话。
    #[test]
    fn the_cleanup_result_is_reported_on_the_page() {
        let mut form = FormState::servers();
        form.absorb(
            "servers",
            &json!({"ok":true,"servers":[
                {"Id":"a1","Name":"东京","Host":"203.0.113.10","LineIds":[]}
            ]}),
        );
        form.event(&json!({"Event":"click","Id":"server-cleanup:a1"}));
        form.absorb_server_cleanup(&json!({"ok":true,"servers":[],
            "serverCleanupResult":{
                "RemovedRuns":3,"RemovedReminders":2,"RemovedCredentials":1,
                "Failed":[],
                "Message":"已删除这台服务器在本机的 3 条部署记录、2 条提醒与 1 份登录资料"
            }}));
        let done = form.render().to_string();
        assert!(
            done.contains("已删除这台服务器在本机的 3 条部署记录"),
            "{done}"
        );
        assert!(!done.contains("东京"), "列表要跟着刷新：{done}");
        assert_eq!(form.server_cleanup, None);
        assert_eq!(form.notice_tone, "muted");

        // 有没删掉的项：语气必须是警告，不能看起来像全部成功。
        form.absorb_server_cleanup(&json!({"ok":true,"servers":[],
            "serverCleanupResult":{
                "RemovedRuns":0,"RemovedReminders":0,"RemovedCredentials":0,
                "Failed":["部署任务记录 a.json（拒绝访问）"],
                "Message":"已删除这台服务器的本机记录（没有部署记录、提醒或登录资料）；另有 1 项没删掉：部署任务记录 a.json（拒绝访问）"
            }}));
        assert_eq!(form.notice_tone, "warn");
        assert!(
            form.render().to_string().contains("没删掉"),
            "没删掉要写在页面上"
        );

        // 被后端拒绝（例如刚好还有线路关联）：原话上屏。
        form.absorb_server_cleanup(&json!({"ok":false,"errorCode":"conflict",
            "error":"还有 1 条线路用到这台服务器；请先删除这些线路，再删服务器记录。"}));
        assert_eq!(form.notice_tone, "warn");
        assert!(
            form.render().to_string().contains("还有 1 条线路"),
            "后端原话要上屏"
        );
    }

    fn devices_page(names_available: bool) -> FormState {
        let mut form = FormState::devices("L1");
        form.absorb_devices(&json!({"ok":true,"serverDevices":{
            "server":{
                "id":"s1","name":"东京","host":"203.0.113.10","port":22,"user":"root",
                "fingerprint":"SHA256:AAAA","interface":"tcaaaaaaaa","udpPort":51820,
                "subnet":"10.66.0.0/24"
            },
            "tunnel":{"up":true,"latestHandshake":0,"rxBytes":0,"txBytes":0},
            "namesAvailable":names_available,
            "namesError": if names_available { "" } else { "没有命名服务" },
            "devices":[{
                "address":"10.66.0.2","name":"旧名",
                "publicKey":"yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
                "shortKey":"yAnz5TF","handshake":0,"rxBytes":0,"txBytes":0,
                "endpoint":"","thisDevice":true
            }]
        }}));
        form
    }

    /// 设备改名：名字上屏；保存发长命令；失败保留输入框与草稿。
    #[test]
    fn devices_page_renames_a_device_and_keeps_the_input_on_failure() {
        let mut form = devices_page(true);
        assert!(
            form.render().to_string().contains("设备 旧名（10.66.0.2）"),
            "名字要显示在设备行上"
        );
        form.event(&json!({"Event":"click","Id":"device-rename:0"}));
        assert_eq!(form.device_rename_index, Some(0));
        assert_eq!(form.draft, "旧名", "输入框要带当前名字");
        form.event(&json!({"Event":"change","Id":"name","Value":"东京本机"}));
        let steps = form.event(&json!({"Event":"click","Id":"save-device-rename"}));
        assert!(matches!(
            &steps[0],
            Step::Long(c) if c.contains("server-device-rename")
                && c.contains("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
                && c.contains("东京本机")
        ));
        form.absorb_device_rename(&json!({"ok":false,"serverDeviceRename":{"error":"公钥无效"}}));
        assert_eq!(form.device_rename_index, Some(0), "失败后输入框要留着");
        let view = form.render().to_string();
        assert!(view.contains("公钥无效"), "{view}");
        assert!(view.contains("保存名称"), "{view}");
    }

    /// 命名服务不可用：不给改名按钮，也不假装能改。
    #[test]
    fn devices_page_hides_rename_when_the_name_service_is_missing() {
        let form = devices_page(false);
        let view = form.render().to_string();
        assert!(view.contains("设备改名暂不可用"), "{view}");
        assert!(!view.contains("device-rename:0"), "不该给点不了的按钮：{view}");
    }

    /// 卸载：先预览影响面，再确认；成功后不再显示过期设备列表。
    #[test]
    fn devices_page_previews_then_confirms_uninstall() {
        let mut form = devices_page(true);
        let steps = form.event(&json!({"Event":"click","Id":"uninstall-preview"}));
        assert!(matches!(
            &steps[0],
            Step::Long(c) if c.contains("server-uninstall-preview") && c.contains("\"s1\"")
        ));
        form.absorb_uninstall_preview(&json!({"ok":true,"serverUninstallPreview":{
            "Id":"s1","Name":"东京","Host":"203.0.113.10","Interface":"tcaaaaaaaa",
            "TunnelUp":true,"AffectedDevices":2,"LocalLines":1,"Eligible":true,
            "Blocked":[],
            "Warnings":[{"Code":"CloudNotReleased","Message":"不会退订云服务器，云服务商仍会计费。"}]
        }}));
        let view = form.render().to_string();
        assert!(view.contains("影响设备：2 台"), "{view}");
        assert!(view.contains("不会退订云服务器"), "{view}");
        assert!(view.contains("uninstall-confirm"), "{view}");

        let steps = form.event(&json!({"Event":"click","Id":"uninstall-confirm"}));
        assert!(matches!(
            &steps[0],
            Step::Long(c) if c.contains("server-uninstall") && c.contains("\"s1\"")
        ));
        form.absorb_uninstall(&json!({"ok":true,"serverUninstall":{"Id":"s1"}}));
        let done = form.render().to_string();
        assert!(done.contains("通道服务已卸载，云服务器未释放"), "{done}");
        assert!(done.contains("重新部署后"), "过期设备列表要收掉：{done}");
    }

    /// 列表把 `detail` 截到 60 字（一屏能扫），详情要给全文——查「刚才那次为什么失败」
    /// 的人要的正是那句没被截断的原话。
    #[test]
    fn history_detail_shows_the_full_text_the_list_truncates() {
        let long = "引擎启动后立即退出（pid=8216）；系统代理已还原；".repeat(4);
        let mut form = FormState::history();
        form.absorb(
            "history",
            &json!({"ok":true,"events":[
                {"ts":"2026-11-10T10:27:14Z","action":"连接","ok":false,
                 "detail":long,"src":"ui","actor":"pid:24632","obj":"line:81ea5ef"}
            ]}),
        );

        let collapsed = form.render().to_string();
        assert!(collapsed.contains('…'), "列表行要截断：{collapsed}");
        assert!(!collapsed.contains(long.as_str()), "列表行不该给全文");

        // 点「详情」：全文与每个有值的字段都出来。
        form.event(&json!({"Event":"click","Id":"history-detail:0"}));
        assert_eq!(form.history_open, Some(0));
        let opened = form.render().to_string();
        assert!(opened.contains(long.as_str()), "详情必须给全文：{opened}");
        assert!(opened.contains("来源：界面"), "来源要人话化：{opened}");
        assert!(opened.contains("执行者：pid:24632"), "{opened}");
        assert!(opened.contains("对象：line:81ea5ef"), "{opened}");
        assert!(
            opened.contains("时间：2026-11-10T10:27:14Z"),
            "详情给完整时刻，不压缩：{opened}"
        );

        // 再点一次同一条 = 收起。
        form.event(&json!({"Event":"click","Id":"history-detail:0"}));
        assert_eq!(form.history_open, None);
        assert!(!form.render().to_string().contains(long.as_str()));
    }

    #[test]
    fn changing_the_filter_closes_the_open_detail() {
        let mut form = FormState::history();
        form.absorb(
            "history",
            &json!({"ok":true,"events":[
                {"ts":"2026-11-02T02:00:00Z","action":"连接","ok":true,"detail":"成功那次","src":"ui"},
                {"ts":"2026-11-02T01:59:00Z","action":"导入","ok":false,"detail":"端口被占用","src":"cli"}
            ]}),
        );
        form.event(&json!({"Event":"click","Id":"history-detail:1"}));
        assert_eq!(form.history_open, Some(1));
        form.event(&json!({"Event":"click","Id":"filter-fail"}));
        assert_eq!(
            form.history_open, None,
            "筛选变了必须收起，否则详情会挂到另一条记录上"
        );
    }

    #[test]
    fn hidden_records_stay_out_until_the_legacy_switch_is_checked() {
        let mut form = FormState::history();
        form.absorb(
            "history",
            &json!({"ok":true,"events":[
                {"ts":"2026-11-13T02:00:00Z","action":"连接","ok":true,"detail":"看得见","src":"ui","Key":"k1","Hidden":false},
                {"ts":"2026-11-13T01:59:00Z","action":"导入","ok":false,"detail":"藏起来了","src":"cli","Key":"k2","Hidden":true}
            ]}),
        );
        let view = form.render().to_string();
        assert!(view.contains("看得见"), "{view}");
        assert!(!view.contains("藏起来了"), "默认不显示隐藏记录：{view}");
        assert!(view.contains("显示旧版隐藏记录"), "开关必须画出来：{view}");

        // 全选只选屏幕上看得到的那条：隐藏的空操作不该被选中。
        form.event(&json!({"Event":"click","Id":"history-all"}));
        assert_eq!(form.history_checked, vec![0]);

        let before = form.generation;
        let steps =
            form.event(&json!({"Event":"change","Id":"history-show-hidden","Value":true}));
        assert!(steps.is_empty(), "开关是页面状态，不发命令：{steps:?}");
        assert!(form.history_show_hidden);
        assert!(form.generation > before, "列表长度变了要整页重绘");
        assert!(form.history_checked.is_empty(), "下标全变了，勾选必须清空");
        let view = form.render().to_string();
        assert!(view.contains("藏起来了"), "{view}");
        assert!(view.contains("已隐藏（旧版）"), "隐藏行要有标记：{view}");
        assert!(view.contains("history-restore:1"), "隐藏行要给「恢复显示」：{view}");
    }

    #[test]
    fn restoring_a_hidden_row_sends_its_key_and_clears_the_marker() {
        let mut form = FormState::history();
        form.history_show_hidden = true;
        form.absorb(
            "history",
            &json!({"ok":true,"events":[
                {"ts":"2026-11-13T02:00:00Z","action":"连接","ok":true,"detail":"甲","src":"ui","Key":"k1","Hidden":true}
            ]}),
        );
        let steps = form.event(&json!({"Event":"click","Id":"history-restore:0"}));
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("history-restore") && c.contains("k1")),
            "{steps:?}"
        );
        assert_eq!(form.history_restore_pending, vec!["k1".to_string()]);

        form.absorb("history-restore", &json!({"ok":true,"historyRestore":{"restored":1}}));
        let view = form.render().to_string();
        assert!(!view.contains("已隐藏（旧版）"), "恢复之后不该还挂着标记：{view}");
        assert!(view.contains("甲"), "{view}");
    }

    #[test]
    fn a_legacy_record_without_fields_says_so_instead_of_blank_rows() {
        let mut form = FormState::history();
        form.absorb("history", &json!({"ok":true,"events":[{"action":"旧动作"}]}));
        form.event(&json!({"Event":"click","Id":"history-detail:0"}));
        let view = form.render().to_string();
        assert!(view.contains("结果：未记录"), "缺 ok 字段不许猜成成功：{view}");
        assert!(view.contains("没有更多字段"), "{view}");
        assert!(!view.contains("来源："), "空字段不该渲染成空行：{view}");
    }

    #[test]
    fn diagnose_form_fills_items_and_verdict_from_the_long_reply() {
        let mut form = FormState::diagnose();
        assert!(form.running);
        assert!(form.render().to_string().contains("正在诊断"));

        form.absorb_diagnose(&json!({"ok":true,"diagnose":{
            "items":[{"target":"1.2.3.4","port":443,"purpose":"web","result":"ok","ms":5,
                      "text":"TCP 1.2.3.4:443  可建立连接，耗时 5 ms"}],
            "verdict":{"code":"ok","text":"线路端点可达","next":""}}}));
        assert!(!form.running);
        let view = form.render().to_string();
        assert!(view.contains("线路端点可达"), "{view}");
        assert!(view.contains("可建立连接"), "{view}");
        assert!(view.contains("重新诊断"), "{view}");

        let steps = form.event(&json!({"Event":"click","Id":"run-diagnose"}));
        assert!(matches!(&steps[0], Step::Long(c) if c.contains("diagnose")));
        assert!(form.running, "点了就要进入运行态，按钮随之禁用");
    }

    #[test]
    fn rename_form_carries_the_current_name_and_closes_on_success() {
        let mut form = FormState::rename("jp", "东京 02");
        let view = form.render();
        assert_eq!(view["ViewKey"], "line-rename");
        assert_eq!(view["ParentPage"], "lines");
        assert_eq!(node(&view["Nodes"], "name").unwrap()["Value"], "东京 02");
        assert_eq!(view["PageActions"][0]["Text"], "保存名称");

        // 草稿为空时不发命令，只在表单里给出原话。
        let steps = form.event(&json!({"Event":"change","Id":"name","Value":""}));
        assert!(steps.is_empty());
        let steps = form.event(&json!({"Event":"click","Id":"save-rename"}));
        assert!(steps.is_empty());
        assert!(form.notice.contains("1–120"));
        let bumped = form.generation;

        let steps = form.event(&json!({"Event":"change","Id":"name","Value":"东京 03"}));
        assert!(steps.is_empty());
        assert_eq!(form.draft, "东京 03");
        assert_eq!(form.generation, bumped, "改字段不能重绘整页");

        let steps = form.event(&json!({"Event":"click","Id":"save-rename"}));
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("rename-line") && c.contains("东京 03")));
        match form.absorb("rename-line", &json!({"ok":true,"message":"线路名称已保存"})) {
            Absorbed::Close(msg) => assert_eq!(msg, "线路名称已保存"),
            _ => panic!("成功后必须关闭表单"),
        }
    }

    #[test]
    fn rename_failure_keeps_the_form_and_shows_the_hosts_words() {
        let mut form = FormState::rename("jp", "东京 02");
        form.event(&json!({"Event":"change","Id":"name","Value":"香港 01"}));
        match form.absorb("rename-line", &json!({"ok":false,"message":"已经有名为「香港 01」的线路，请换一个名称"})) {
            Absorbed::Keep => {}
            _ => panic!("失败必须保持表单"),
        }
        assert!(form.notice.contains("已经有名为"));
        assert_eq!(form.render()["Nodes"][2]["Tone"], "warn");
    }

    #[test]
    fn line_settings_switches_transport_and_reads_back_the_real_value() {
        let mut form = FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp");
        let view = form.render();
        assert_eq!(view["ViewKey"], "line-settings");
        assert_eq!(node(&view["Nodes"], "method-udp").unwrap()["Tone"], "primary", "当前档位要标出来");

        let steps = form.event(&json!({"Event":"click","Id":"method-tcp"}));
        assert!(matches!(&steps[0], Step::Sync(c) if c.contains("set-transport") && c.contains("\"tcp\"")));

        // 回包里的 transport 才是事实：点击 udp 但宿主回 tcp，界面必须显示 tcp。
        let reply = json!({"ok":true,"message":"已改为兼容（TCP），下次连接生效",
                           "lines":[{"id":"hk","transport":"tcp"}]});
        match form.absorb("set-transport", &reply) {
            Absorbed::Toast(msg) => assert!(msg.contains("TCP")),
            _ => panic!("成功要给出提示"),
        }
        assert_eq!(form.method, "Tcp");
    }

    #[test]
    fn line_settings_failure_is_shown_in_place() {
        let mut form = FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp");
        match form.absorb("set-transport", &json!({"ok":false,"message":"请先断开再改连接方式"})) {
            Absorbed::Keep => {}
            _ => panic!("失败必须保持表单"),
        }
        assert!(form.notice.contains("请先断开"));
    }

    /// 出口网卡：本机有什么、这条线路选了哪张、以及「指定的那张不在了」怎么表示。
    #[test]
    fn line_settings_lists_machine_interfaces_and_saves_the_chosen_one() {
        let mut form = FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp");
        assert_eq!(form.notice, LOADING_INTERFACES, "打开时就说明在等什么，别让人以为没有这张卡");
        form.absorb(
            "line-network",
            &json!({"ok":true,"lineNetwork":{
                "Id":"hk","Default":"以太网","Interfaces":["以太网","WLAN"],
                "Bound":"WLAN","Effective":"WLAN","Stale":false,"StaleName":""}}),
        );
        let view = form.render();
        let picker = node(&view["Nodes"], "net-interface").expect("要有出口网卡下拉");
        let items = picker["Items"].as_array().expect("Items 必须是数组");
        assert_eq!(items.len(), 3, "跟随默认 + 两块网卡：{}", picker);
        assert!(
            items[0]["Label"].as_str().unwrap_or("").contains("以太网"),
            "第一项要说清「跟随默认」当前是哪张：{picker}"
        );
        assert_eq!(picker["Value"], 2, "选中的是第二块网卡（0 = 跟随默认）：{picker}");
        assert!(form.notice.is_empty(), "读到结果后那句「正在读取」要消失");

        // 换一张再保存：发给宿主的是**网卡名**，不是页面上的下标。
        form.event(&json!({"Event":"change","Id":"net-interface","Value":1}));
        let steps = form.event(&json!({"Event":"click","Id":"save-net"}));
        assert!(
            matches!(&steps[0], Step::Sync(c)
                if c.contains("line-network-set") && c.contains("以太网")),
            "保存要发 `line-network-set` 与选中的网卡名：{:?}",
            steps.iter().map(|s| s.command()).collect::<Vec<_>>()
        );
        assert!(
            matches!(&steps[1], Step::Sync(c) if c.contains("line-network") && !c.contains("set")),
            "写完必须再读一次：页面上的「当前绑定」只认磁盘回读，不认保存回包"
        );
    }

    /// 真机抓到的回归：成功回包会被吸收**两次**（命令原文一次，下一帧的合并状态一次），
    /// 而 `merge_ui_command_reply` 成功时**不带** `message`。第二次要是无条件清空提示，
    /// 用户看到的就是「点完保存，页面上什么都没发生」——而磁盘其实已经写进去了。
    #[test]
    fn a_second_projection_does_not_wipe_the_saved_notice() {
        let mut form = FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp");
        form.absorb(
            "line-network",
            &json!({"ok":true,"lineNetwork":{
                "Id":"hk","Default":"以太网","Interfaces":["以太网","WLAN"],
                "Bound":"","Effective":"以太网","Stale":false,"StaleName":""}}),
        );
        assert!(form.notice.is_empty(), "读到结果后那句「正在读取」要收掉");

        let saved = json!({"ok":true,
            "lineNetwork":{"Id":"hk","Default":"以太网","Interfaces":["以太网","WLAN"],
                           "Bound":"以太网","Effective":"以太网","Stale":false,"StaleName":""},
            "message":"已保存下次连接的出口网卡，当前连接保持"});
        form.absorb("line-network-set", &saved);
        assert!(form.notice.contains("已保存下次连接的出口网卡"), "{}", form.notice);

        // 第二次投影：同样的 `lineNetwork`，没有 `message`（合并状态就是这样）。
        let projected = json!({"ok":true,
            "lineNetwork":{"Id":"hk","Default":"以太网","Interfaces":["以太网","WLAN"],
                           "Bound":"以太网","Effective":"以太网","Stale":false,"StaleName":""}});
        form.absorb("line-network-set", &projected);
        assert!(
            form.notice.contains("已保存下次连接的出口网卡"),
            "重复投影不许把刚说的话吃掉：{}",
            form.notice
        );
    }

    #[test]
    fn a_vanished_interface_is_shown_as_such_instead_of_silently_becoming_default() {
        let mut form = FormState::line_settings("hk", "香港 01", "1.2.3.4:443", "Udp");
        form.absorb(
            "line-network",
            &json!({"ok":true,"lineNetwork":{
                "Id":"hk","Default":"以太网","Interfaces":["以太网"],
                "Bound":"雷雳网桥","Effective":"","Stale":true,"StaleName":"雷雳网桥"}}),
        );
        let view = form.render();
        let picker = node(&view["Nodes"], "net-interface").unwrap();
        let items = picker["Items"].as_array().unwrap();
        assert_eq!(items.len(), 3, "跟随默认 + 以太网 + 那块不在的：{picker}");
        assert_eq!(picker["Value"], 2, "那块不在的排最后并被选中，不能显示成「跟随默认」：{picker}");
        assert!(
            items[2]["Label"].as_str().unwrap_or("").contains("这台电脑上没有"),
            "要在选项上直接说明它不在了：{picker}"
        );

        // 再点保存：发的仍是那个名字（服务端会拒绝并给出路），不是悄悄改成空串。
        let steps = form.event(&json!({"Event":"click","Id":"save-net"}));
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("雷雳网桥")),
            "不许把「指定的网卡不在了」静默降级成「跟随默认」"
        );
        // 改成「跟随默认」后再保存：警告要跟着消失，发的是空串。
        form.event(&json!({"Event":"change","Id":"net-interface","Value":0}));
        assert!(!form.net_stale, "选了跟随默认，就不该还挂着「那张卡不在了」的警告");
        let steps = form.event(&json!({"Event":"click","Id":"save-net"}));
        assert!(
            matches!(&steps[0], Step::Sync(c) if c.contains("\"Interface\":\"\"")),
            "跟随默认 = 空串，而不是发一个不存在的名字"
        );
    }

    /// 服务没起来时，设备清单是「读不到」，不是「0 台」。
    /// 写成「已登记的设备（0 台）」会让人以为服务器上一台设备都没接。
    #[test]
    fn a_down_tunnel_reports_unreadable_instead_of_zero_devices() {
        let mut form = FormState::devices("hk");
        form.absorb_devices(&json!({"ok": true, "serverDevices": {
            "server": {
                "name": "自建 · 1.2.3.4", "host": "1.2.3.4", "port": 22, "user": "root",
                "fingerprint": "SHA256:x", "interface": "tc1", "udpPort": 51820,
                "subnet": "10.66.0.0/24",
            },
            "tunnel": Value::Null,
            "devices": [],
        }}));
        let text = form.render().to_string();
        assert!(text.contains("读不到设备清单"), "{text}");
        assert!(!text.contains("已登记的设备（0 台）"), "{text}");
        assert!(!text.contains("还没有任何设备"), "{text}");
    }

    /// 两台设备：一台是本机，一台是别的电脑。撤销只能作用于后者。
    fn two_devices() -> FormState {
        let mut form = FormState::devices("hk");
        form.absorb_devices(&json!({"ok": true, "serverDevices": {
            "server": {
                "name": "自建 · 1.2.3.4", "host": "1.2.3.4", "port": 22, "user": "root",
                "fingerprint": "SHA256:x", "interface": "tc1", "udpPort": 51820,
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
        }}));
        form
    }

    /// 撤销是不可逆的写操作：先问一次，且不给本机那行按钮。
    #[test]
    fn the_devices_page_asks_once_before_revoking_and_never_offers_it_for_this_device() {
        let mut form = two_devices();
        let text = form.render().to_string();
        assert!(text.contains("revoke-1"), "别的设备要有「移除」：{text}");
        assert!(!text.contains("revoke-0"), "本机不该有「移除」：{text}");

        let steps = form.event(&json!({"Event": "click", "Id": "revoke-1"}));
        assert!(steps.is_empty(), "确认之前不能发命令");
        assert!(form.pending_revoke.is_some());
        let text = form.render().to_string();
        assert!(text.contains("确定移除设备 10.66.0.3 吗？"), "{text}");
        assert!(!text.contains("revoke-1"), "确认层开着时不再列按钮：{text}");

        let steps = form.event(&json!({"Event": "click", "Id": "revoke-cancel"}));
        assert!(steps.is_empty(), "取消什么都不发");
        assert!(form.pending_revoke.is_none());
        assert!(form.render().to_string().contains("revoke-1"), "取消后按钮要回来");
    }

    /// 确认之后才发 `server-revoke`，带的是列表里的公钥（不是页面回传的值）。
    #[test]
    fn confirming_a_revoke_sends_the_key_from_the_list() {
        let mut form = two_devices();
        form.event(&json!({"Event": "click", "Id": "revoke-1"}));
        let steps = form.event(&json!({"Event": "click", "Id": "revoke-confirm"}));
        assert!(
            matches!(
                steps.first(),
                Some(Step::Long(command))
                    if command.contains("server-revoke")
                        && command.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            ),
            "{steps:?}"
        );
        assert!(form.pending_revoke.is_none());
        assert!(form.render().to_string().contains("正在移除"));
    }

    /// 成功后本地列表要摘掉那一台，剩余台数照服务器回报的写；失败则列表不动。
    #[test]
    fn a_revoked_device_leaves_the_list_and_failures_stay_on_the_page() {
        let mut form = two_devices();
        form.event(&json!({"Event": "click", "Id": "revoke-1"}));
        form.event(&json!({"Event": "click", "Id": "revoke-confirm"}));
        form.absorb_revoke(&json!({
            "ok": true,
            "serverRevoke": {
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "peers": 1,
            },
        }));
        let text = form.render().to_string();
        assert!(!text.contains("10.66.0.3"), "被撤销的设备不该还列着：{text}");
        assert!(text.contains("还剩 1 台"), "{text}");
        assert!(text.contains("10.66.0.2（本机）"), "本机那台必须在：{text}");

        let mut failed = two_devices();
        failed.absorb_revoke(&json!({
            "ok": false,
            "serverRevoke": {"error": "服务器上的隧道没有起来，等它恢复后再试"},
        }));
        let text = failed.render().to_string();
        assert!(text.contains("没有移除这台设备"), "{text}");
        assert!(text.contains("等它恢复后再试"), "{text}");
        assert!(text.contains("10.66.0.3"), "失败时列表不能被改动：{text}");
    }

    const ORPHAN_KEY: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    /// 两条设备的页面，再挂一条「已撤销设备的名称记录」。
    fn two_devices_with_orphan() -> FormState {
        let mut form = two_devices();
        if let Some(devices) = form.devices.as_object_mut() {
            devices.insert("namesAvailable".into(), json!(true));
            devices.insert(
                "orphanNames".into(),
                json!([{
                    "publicKey": ORPHAN_KEY,
                    "shortKey": "BBBBBBBB",
                    "name": "旧电脑",
                    "updatedAtUtc": "2026-11-01T10:00:00.0000000Z",
                }]),
            );
        }
        form
    }

    /// 孤儿名称记录可以单独删：只删名字，不碰隧道；同样先确认一次。
    #[test]
    fn an_orphan_name_record_can_be_forgotten_after_confirmation() {
        let mut form = two_devices_with_orphan();
        let text = form.render().to_string();
        assert!(text.contains("已撤销设备的名称记录（1 条）"), "{text}");
        assert!(text.contains("旧电脑"), "{text}");
        assert!(text.contains("forget-0"), "{text}");

        let steps = form.event(&json!({"Event": "click", "Id": "forget-0"}));
        assert!(steps.is_empty(), "确认之前不能发命令");
        assert_eq!(form.pending_forget.as_deref(), Some(ORPHAN_KEY));
        let text = form.render().to_string();
        assert!(text.contains("确定删除「旧电脑"), "{text}");
        assert!(!text.contains("forget-0"), "确认层开着时不再列按钮：{text}");

        let steps = form.event(&json!({"Event": "click", "Id": "forget-cancel"}));
        assert!(steps.is_empty(), "取消什么都不发");
        assert!(form.pending_forget.is_none());
        assert!(
            form.render().to_string().contains("forget-0"),
            "取消后按钮要回来"
        );
    }

    /// 确认后发 `server-device-forget`，公钥取自列表；成功后那一行消失。
    #[test]
    fn confirming_a_forget_sends_the_key_from_the_orphan_list() {
        let mut form = two_devices_with_orphan();
        form.event(&json!({"Event": "click", "Id": "forget-0"}));
        let steps = form.event(&json!({"Event": "click", "Id": "forget-confirm"}));
        assert!(
            matches!(
                steps.first(),
                Some(Step::Long(command))
                    if command.contains("server-device-forget") && command.contains(ORPHAN_KEY)
            ),
            "{steps:?}"
        );
        assert!(form.pending_forget.is_none());
        assert!(form.render().to_string().contains("正在删除记录"));

        form.absorb_device_forget(&json!({
            "ok": true,
            "serverDeviceForget": {"publicKey": ORPHAN_KEY, "removed": true},
        }));
        let text = form.render().to_string();
        assert!(!text.contains("已撤销设备的名称记录"), "{text}");
        assert!(text.contains("名称记录已删除"), "{text}");
        assert!(text.contains("10.66.0.2（本机）"), "设备列表不受影响：{text}");

        let mut failed = two_devices_with_orphan();
        failed.absorb_device_forget(&json!({
            "ok": false,
            "serverDeviceForget": {"error": "服务器上的名字文件读不出来"},
        }));
        let text = failed.render().to_string();
        assert!(text.contains("没有删除这条记录"), "{text}");
        assert!(text.contains("服务器上的名字文件读不出来"), "{text}");
        assert!(text.contains("旧电脑"), "失败时记录不能被摘掉：{text}");
    }

    /// 隧道没起来时服务器会回报空设备表：这时**不能**把名字全判成孤儿并给出删除按钮。
    #[test]
    fn orphan_names_are_not_offered_when_the_tunnel_is_down() {
        let mut form = FormState::devices("hk");
        form.absorb_devices(&json!({"ok": true, "serverDevices": {
            "server": {
                "name": "自建 · 1.2.3.4", "host": "1.2.3.4", "port": 22, "user": "root",
                "fingerprint": "SHA256:x", "interface": "tc1", "udpPort": 51820,
                "subnet": "10.66.0.0/24",
            },
            "tunnel": {"up": false, "latestHandshake": 0, "rxBytes": 0, "txBytes": 0},
            "namesAvailable": true,
            "devices": [],
            "orphanNames": [{
                "publicKey": ORPHAN_KEY, "shortKey": "BBBBBBBB",
                "name": "旧电脑", "updatedAtUtc": "2026-11-01T10:00:00Z",
            }],
        }}));
        let text = form.render().to_string();
        assert!(!text.contains("旧电脑"), "隧道没起来时不列孤儿：{text}");
        assert!(!text.contains("forget-0"), "{text}");
    }

    /// 撤销一台有名字的设备后，名字要挪进孤儿区块——服务器上那条记录还在。
    #[test]
    fn revoking_a_named_device_moves_its_name_into_the_orphan_block() {
        let mut form = two_devices();
        if let Some(devices) = form.devices.as_object_mut() {
            devices.insert("namesAvailable".into(), json!(true));
            if let Some(list) = devices.get_mut("devices").and_then(Value::as_array_mut) {
                list[1]["name"] = json!("办公室");
            }
        }
        form.event(&json!({"Event": "click", "Id": "revoke-1"}));
        form.event(&json!({"Event": "click", "Id": "revoke-confirm"}));
        form.absorb_revoke(&json!({
            "ok": true,
            "serverRevoke": {
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "peers": 1,
            },
        }));
        let text = form.render().to_string();
        assert!(text.contains("已撤销设备的名称记录（1 条）"), "{text}");
        assert!(text.contains("办公室"), "{text}");
        assert!(!text.contains("10.66.0.3"), "设备本身已经不在：{text}");
    }
}




