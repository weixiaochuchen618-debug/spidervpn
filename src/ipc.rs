//! 命名管道控制接口。
//!
//! 这一层存在两个理由：
//! 1. **`control_available` 需要有真实依据**。没有它，「已连接」的判据就只剩「进程还在」，
//!    那会把「进程活着但控制面失灵」误报成已连接。
//! 2. **名字必须落在自己的命名空间**。旧版用 `TradeChannel.*`，这里用 `SpiderVPN.*`；
//!    共用一个管道名，两个程序会互相把对方的请求当成自己的。
//!
//! 协议故意做得极简：一行 JSON 请求，一行 JSON 响应，一次连接一问一答。
//! 没有握手、没有版本协商——那是等有多个调用方之后再谈的事，现在加了只会是负债。
//!
//! 命令：`ping` / `status` / `connect` / `disconnect` / `plan` / `guard-*`。


use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{AppConfig, Transport};
use crate::deploystore::{
    DeploymentStore, ERROR_CLASS_CONFIG, ERROR_CLASS_CONFLICT, ERROR_CLASS_ENVIRONMENT,
    ERROR_CLASS_USAGE, NEXT_ACTION_CONFIRM_FINGERPRINT, REASON_IDENTITY_CHANGED,
};
use crate::guard;
use crate::guard::elevate::GuardAction;
use crate::pairhost;
use crate::serverstore;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ListenerOptions};

/// 管道名前缀。与 `isolation::Rewrite` 保持一致，且**不含旧版前缀**。
pub const NAME_PREFIX: &str = "SpiderVPN.";

/// 由数据根派生管道名：同一台机器上跑两份本程序（不同数据根）时，互不抢管道。
pub fn name_for(root: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in root.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{}{:016x}", NAME_PREFIX, h)
}

fn make_name(n: &str) -> Result<interprocess::local_socket::Name<'static>, String> {
    if !n.starts_with(NAME_PREFIX) {
        // 拒绝旧版前缀：宁可起不来，也不要和旧版抢同一个管道。
        return Err(format!("管道名必须以 {NAME_PREFIX} 开头：{n}"));
    }
    n.to_string()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| e.to_string())
}

/// 服务端上下文。
///
/// 命令需要的全部外部事实（线路配置、引擎设置、数据根、日志目录）都由 `serve` 的调用方注入。
/// 协议层一旦自己去读配置或探测系统，单测就只能依赖真实机器状态——那种「测试」等于没测。
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub legacy_running: bool,
    /// 线路 + 引擎配置。`None` 表示还没配置：此时连接必须失败，不能假装成功。
    pub cfg: Option<AppConfig>,
    /// 数据根：`runtime.json` 与 `proxy-journal.json` 都在这里。
    pub root: PathBuf,
    /// 引擎日志目录。
    pub log_dir: PathBuf,
    /// 这条请求由哪条通道进入：界面、命名管道或测试默认值。
    pub source: crate::events::Source,
    /// WebView 与命名管道共用的事务门。克隆 Ctx 时仍指向同一把锁，
    /// 防止两个入口同时连接/断开/导入/诊断/还原。
    pub transaction_gate: Arc<std::sync::Mutex<()>>,
    /// 部署引擎句柄。`None` = 没有引擎（测试、纯 CLI 命令）：此时所有
    /// `deployment-*` 一律回 `environment` 错误，**不会**退回去同步跑一遍旧流程。
    ///
    /// 源码里只有 `main` 一处注入；测试用 `Ctx { engine: None, .. }` 就能跑。
    pub engine: Option<crate::deployengine::EngineHandle>,
}

/// 处理一条请求，返回一行响应（不含换行）。
impl Ctx {
    /// 期望端点：**只从 cfg 取**。曾经它是个独立字段，导入后要手工两处同步，
    /// 忘一处就会出现「配置里是 A、计划里是 B」。
    pub fn endpoint(&self) -> String {
        self.cfg
            .as_ref()
            .and_then(|c| c.current_line())
            .map(|l| l.proxy_endpoint.clone())
            .unwrap_or_default()
    }

    pub fn origin(&self, obj: Option<&str>) -> crate::events::Origin {
        let mut origin = match self.source {
            crate::events::Source::Ui => crate::events::Origin::ui(),
            crate::events::Source::Pipe => crate::events::Origin::pipe(),
            crate::events::Source::Cli => crate::events::Origin::cli(),
            crate::events::Source::Auto => crate::events::Origin::auto(),
            crate::events::Source::Other => crate::events::Origin::other(),
        };
        if let Some(obj) = obj {
            origin = origin.with_obj(obj);
        }
        origin
    }
}

/// 「当前事实」的配置：**优先从磁盘读**。
///
/// `ctx.cfg` 是进程启动时的快照。`use`/`remove`/`import` 改的是磁盘，不回写快照——
/// 而管道每条连接拿到的又是 ctx 的克隆，回写也传不回服务端。所以凡是要「刚改完就该看见」
/// 的查询（`lines` / `status` / `connect` / `disconnect`）一律读磁盘：磁盘是唯一事实来源，
/// 不另存第二份内存副本，也就不会过期。
/// 读不到（文件不存在/损坏）时回落到快照：一次读失败不该让状态投影整体失效。
struct CfgRead {
    cfg: Option<AppConfig>,
    error: Option<String>,
}

fn read_cfg(ctx: &Ctx) -> CfgRead {
    match crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH)) {
        Ok(cfg) => CfgRead { cfg: cfg.or_else(|| ctx.cfg.clone()), error: None },
        Err(e) => CfgRead { cfg: ctx.cfg.clone(), error: Some(e.to_string()) },
    }
}

fn live_cfg(ctx: &Ctx) -> Option<AppConfig> {
    read_cfg(ctx).cfg
}

fn insert_lines_read(out: &mut serde_json::Value, error: &Option<String>) {
    if let Some(o) = out.as_object_mut() {
        o.insert(
            "linesRead".to_string(),
            serde_json::json!(if error.is_some() { "failed" } else { "ok" }),
        );
        o.insert(
            "linesReadError".to_string(),
            serde_json::json!(error.clone().unwrap_or_default()),
        );
    }
}

/// 从配置取当前端点（供各查询共用，避免又走一遍快照）。
fn endpoint_of(cfg: &Option<crate::config::AppConfig>) -> String {
    cfg.as_ref()
        .and_then(|c| c.current_line())
        .map(|l| l.proxy_endpoint.clone())
        .unwrap_or_default()
}

/// 不带上下文的便捷入口：只有单测在用，所以只在测试构建里编译（生产一律带 `Ctx`）。
#[cfg(test)]
pub fn handle_line(line: &str) -> String {
    handle_line_with(line, &Ctx::default())
}

/// 从一行请求取命令名。UI 调度与管道事务门共用同一解析，避免两处分类漂移。
pub fn command_name(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("cmd").and_then(|c| c.as_str()).map(str::to_string))
}

pub fn handle_line_with(line: &str, ctx: &Ctx) -> String {
    let cmd = command_name(line);
    match cmd.as_deref() {
        Some("ping") => r#"{"ok":true,"product":"SpiderVPN"}"#.to_string(),
        // 设置页「创建桌面快捷方式」（A7）：复用安装程序已经生成的 lnk，不碰 COM。
        Some("desktop-shortcut") => shortcut_json(),
        Some("status") => status_json(ctx),
        Some("measure-latency") => measure_latency_json(ctx, line),
        Some("measure-backup") => measure_backup_json(ctx, line),
        Some("connect") => connect_json(ctx),
        Some("disconnect") => disconnect_json(ctx),
        // 交易保护：读状态/预检是同步只读；核验/同步/解除是长命令（可能一次 UAC + WFP 事务）。
        Some("guard-status") => guard_status_json(ctx),
        Some("guard-precheck") => guard::precheck(
            live_cfg(ctx).as_ref(),
            &ctx.root,
            ctx.legacy_running,
        )
        .to_string(),
        Some("guard-verify") => guard_action_json(ctx, GuardAction::Verify, line),
        Some("guard-install") => guard_action_json(ctx, GuardAction::Install, line),
        Some("guard-sync") => guard_action_json(ctx, GuardAction::Sync, line),
        Some("guard-remove") => guard_action_json(ctx, GuardAction::Remove, line),
        // 维护状态与还原共用 proxy/connect 的现有事实和后端；restore 是执行，不是预览。
        Some("maintenance-status") => maintenance_status_json(ctx),
        Some("restore") => restore_json(ctx),
        // 线路列表/切换/删除是**独立命令**：状态投影已经够大，不再往里塞线路数组。
        Some("lines") => lines_json(ctx),
        // 自动选路（A8）：读是只读；`auto-route` 会用临时引擎真拨两个候选，走长命令。
        Some("auto-route-list") => autoroute_list_json(ctx),
        Some("auto-route") => auto_route_json(ctx, line),
        // 连接中的自动切换（A8 后续）：只在网络变化/连续变差时由宿主触发。
        Some("auto-reroute") => auto_reroute_json(ctx, line),
        Some("use") => edit_lines(ctx, line, false),
        Some("remove") => edit_lines(ctx, line, true),
        // 删除前的只读预览（A4 第一轮）：能不能删、删什么、保留什么。
        // 与 `remove` 共用同一条连接闸门，两边判据分叉会让预览说能删、确认后却被拒。
        Some("delete-preview") => delete_preview_json(ctx, line),
        // 删除线路后没清掉的本地文件：查看（只读）与重试（真的删）。
        // 两条都是短命令：只读写数据根里的一个小 JSON 和一个文件。
        Some("delete-cleanup") => delete_cleanup_json(ctx),
        Some("delete-cleanup-retry") => delete_cleanup_retry_json(ctx, line),
        Some("rename-line") => rename_line_json(ctx, line),
        // 服务器记录的显示名（C7）：只改本机 `servers\<id>\record.json` 的 Name，
        // 不连服务器、不动凭据（凭据熵不含 Name）。
        Some("server-rename") => server_rename_json(ctx, line),
        // 分流规则：同样独立于 status，且一律从磁盘读。
        Some("split") => split_json(ctx),
        Some("split-add") => edit_split(ctx, line, true),
        Some("split-remove") => edit_split(ctx, line, false),
        // 恢复默认交易网站（r97，旧版的`ResetTradeDomains`）：只替换交易出口那一组域名。
        Some("split-reset-trade-domains") => split_reset_trade_domains_json(ctx),
        // AI 工具名单：读 / 全量保存 / 只改走向。三条与分流同一道连接闸门。
        Some("agents") => agents_json(ctx),
        Some("agents-save") => save_agents(ctx, line),
        Some("agents-lane") => set_agents_lane(ctx, line),
        // 出口选择：与命令行同一条路径（写配置 + 立刻落到线路引擎配置）。
        Some("exit-set") => edit_exit(ctx, line),
        // 连接方式切换：语义与命令行 `--set-transport` 一致（只写配置、只影响下次连接）。
        Some("set-transport") => set_transport_json(ctx, line),
        // 出口网卡（A 组网卡绑定）：读是只读；写只改本机 `line-network.json`，
        // 同样只影响下次连接。真正的绑定在连接前由 `prepare_engine_config` 写进运行时配置。
        Some("line-network") => line_network_json(ctx, line),
        Some("line-network-set") => line_network_set_json(ctx, line),
        // 线路动作（测速 / 保存连接方式）的结果记录：读是只读；核对只查已有证据，
        // **绝不重新提交原操作**（那正是「核对」与「重试」的区别）。
        Some("line-action-list") => line_actions_json(ctx),
        Some("line-action-review") => line_action_review_json(ctx, line),
        // 界面长操作（连接/断开/诊断）的记录：读是只读；核对只按**当前**连接与代理
        // 事实下结论，绝不重新连接、也绝不重放原命令。
        Some("operation-list") => operation_list_json(ctx),
        Some("operation-review") => operation_review_json(ctx, line),
        // 按记录重试（A6）：只重做可安全重放的连接/断开/诊断，记录里没有命令原文。
        Some("operation-retry") => operation_retry_json(ctx, line),
        // 自检失败后的自救动作：保存兼容偏好只是第一步，随后必须真实断开、重连并核验。
        Some("use-compatible") => use_compatible_json(ctx),
        // 服务商接入：与 `--providers` / `--provider-discover` / `--provider-add` /
        // `--provider-remove` 一一对应，业务全走 provider.rs 的同一套函数。
        Some("providers") => providers_json(ctx),
        Some("provider-discover") => provider_discover_json(),
        Some("provider-add") => provider_add_json(ctx, line),
        Some("provider-remove") => provider_remove_json(ctx, line),
        // 操作记录：只读，与命令行 `--history` 读同一个文件。界面「记录」页据此渲染。
        Some("history") => history_json(ctx),
        // 响应曲线：只读 `perf\` 里的采样，按窗口聚合成 旧版的 QualityHistory 形状。
        Some("quality-history") => quality_history_json(ctx, line),
        Some("quality-summary") => quality_summary_json(ctx, line),
        // 加入流程的第一步：读邀请并验签。**只读**——不提交申请、不消费邀请。
        Some("pair-verify") => pair_verify_json(line),
        // 第二步：提交申请、取回授权、生成 client.conf **与线路**。这一步会消费邀请。
        Some("pair-join") => pair_join_json(ctx, line),
        // 离线交接（新电脑连不上 18443）：校验 → 生成申请 → 导入授权。
        // 前两步不联网；第三步只碰本机文件与配置，但会生成线路，所以走长命令。
        Some("pair-offline-inspect") => pair_offline_inspect_json(line),
        Some("pair-offline-request") => pair_offline_request_json(ctx, line),
        Some("pair-offline-complete") => pair_offline_complete_json(ctx, line),
        // 邀请其他电脑（管理端）：装管理身份、签发、查状态、作废。全部是服务器往返。
        Some("invite-init") => invite_init_json(ctx, line),
        Some("invite-create") => invite_create_json(ctx, line),
        Some("invite-status") => invite_status_json(ctx, line),
        Some("invite-cancel") => invite_cancel_json(ctx, line),
        // 离线邀请的管理端第二步：把新电脑交回的签名申请交给服务器批准。
        Some("invite-authorize") => invite_authorize_json(ctx, line),
        Some("invite-reachability") => invite_reachability_json(ctx, line),
        // 「重新开启接收服务」的自动判定：先量端口，必要时再 SSH 读服务状态并自动修。
        Some("invite-preflight") => invite_preflight_json(ctx, line),
        // 「哪些线路能邀请」：只读，把线路 → 服务器的归属一次算完给界面。
        Some("servers") => servers_json(ctx),
        // 自助部署第一步：**只读**主机指纹，不送密码、不改服务器。
        Some("server-probe") => server_probe_json(ctx, line),
        // 「服务器与设备」：只读。按线路找到服务器记录，读一次隧道与设备列表。
        Some("server-devices") => server_devices_json(ctx, line),
        // 设备改名（C1）：只写服务器上的 device-names.json，按公钥定位。
        Some("server-device-rename") => server_device_rename_json(ctx, line),
        // 删除已撤销设备的名称记录（C1）：只清服务器上的 device-names.json。
        Some("server-device-forget") => server_device_forget_json(ctx, line),
        // 「撤销设备」：删服务端那一个 [Peer] 段并热应用——同样是 SSH 往返，走长命令。
        Some("server-revoke") => server_revoke_json(ctx, line),
        // 删除本机服务器记录（C7）：只动 servers\<id>\，先拒绝「还有线路用到它」。
        Some("server-remove") => server_remove_json(ctx, line),
        // 「删除这台服务器在本机的部署资料」：预览**只读**，执行按同一套判据再判一次
        // （部署记录 / 任务级凭据 / 提醒 / 最后才是记录目录本体）。
        Some("server-cleanup-preview") => server_cleanup_preview_json(ctx, line),
        Some("server-cleanup") => server_cleanup_json(ctx, line),
        // 卸载服务器通道服务（C1）：预览只读；执行是 SSH 写操作。
        Some("server-uninstall-preview") => server_uninstall_preview_json(ctx, line),
        Some("server-uninstall") => server_uninstall_json(ctx, line),
        // 给已有线路补一条兼容连接（旧版的「旧线路维护：增加 TCP」）。
        // 一次 SSH：读/装服务器上的中转 + 把本机线路补齐；所以走长命令。
        Some("line-add-compatible") => line_add_compatible_json(ctx, line),
        // 管理恢复包（r94，旧版的「管理恢复资料」）：导出/导入都只动本机，
        // 不发 SSH；导入只登记一条记录，不启用线路、不跳过身份核对。
        Some("recovery-export") => recovery_export_json(ctx, line),
        Some("recovery-import") => recovery_import_json(ctx, line),
        // 部署中心（A2/A3）：10 条**短命令**。它们只「受理意图」——真正的 SSH 往返
        // 在进程内的部署引擎线程里跑，所以绝不进 `is_long_command`（那会让整个界面
        // 在部署的十几分钟里一直抢着事务门）。
        Some("deployment-start") => deployment_start_json(ctx, line),
        Some("deployment-draft-save") => deployment_draft_save_json(ctx, line),
        Some("deployment-list") => deployment_list_json(ctx),
        Some("deployment-get") => deployment_get_json(ctx, line),
        Some("deployment-continue") => deployment_continue_json(ctx, line),
        Some("deployment-pause") => deployment_pause_json(ctx, line),
        Some("deployment-cancel") => deployment_cancel_json(ctx, line),
        Some("deployment-background") => deployment_background_json(ctx, line),
        // 导出单任务诊断摘要（P2-3）：只读记录 + 写一个文件，不发网络请求。
        Some("deployment-export") => deployment_export_json(ctx, line),
        // 归档/恢复（P2-2）：只改记录上的 `ArchivedAtUtc`，不删文件、不碰引擎。
        Some("deployment-archive") => deployment_archive_json(ctx, line),
        // 自助部署的旧界面入口：已退役。命令行 `--server-setup` 仍然可用（不走这里）。
        Some("server-setup") => server_setup_retired_json(),
        // 导出当前筛选：只读记录文件，唯一写入是数据根下的导出文件。
        Some("export-history") => export_history_json(ctx, line),
        Some("history-delete") => history_delete_json(ctx, line),
        // 恢复一条被隐藏的记录（r96）：只改 hidden 键集合，不动审计文件。
        Some("history-restore") => history_restore_json(ctx, line),
        // 节点端口诊断：与命令行 `--diagnose` 共用 diagnose 模块（目标推导与措辞同一处）。
        Some("diagnose") => diagnose_json(ctx),
        // 接管方式切换：只写 config.json，连接前由 engine_config::apply_mode 真正落地。
        Some("set-mode") => set_mode_json(ctx, line),
        // 指定引擎程序：**真的跑一次** `version` 验明身份，通过才写 config.json。
        Some("set-engine") => set_engine_json(ctx, line),
        Some("plan") => {
            // 只读：读当前代理设置、算出变更，不写任何值。
            let snap = crate::proxy::ProxySnapshot::read();
            let plan = crate::proxy::plan_connect(&snap, &ctx.endpoint(), ctx.legacy_running);
            let changes: Vec<_> = plan
                .changes
                .iter()
                .map(|c| serde_json::json!({"key": c.key, "from": c.from, "to": c.to}))
                .collect();
            serde_json::json!({
                "ok": plan.blocked.is_none(),
                "dry_run": true,
                "changes": changes,
                "warnings": plan.warnings,
                "blocked": plan.blocked,
                "original": {
                    "enable": plan.original.enable,
                    "server": plan.original.server,
                    "bypass": plan.original.bypass,
                    "readable": plan.original.readable
                }
            })
            .to_string()
        }
        _ => r#"{"ok":false,"error":"unknown_command"}"#.to_string(),
    }
}

/// 状态证据：控制台「当前状态」、管道 `status`、界面首屏三处共用这一份。
/// 三处各写一遍，同一台机器就会有三种说法。
///
/// `configured` 由调用方按本程序自己的 config.json 判定。**不要改读 deployment.json**：
/// 那是旧版的记录，本程序永不写它，用它当依据会把「配好线路」显示成「尚未配置」。
pub fn evidence(
    root: &std::path::Path,
    configured: bool,
    control_available: bool,
) -> crate::presentation::Evidence {
    let runtime = match crate::model::load_runtime(&root.join("runtime.json")) {
        Ok(r) => r,
        // 记录坏掉不该让整块状态失效：按「无记录」处理，但要说出来。
        Err(e) => {
            eprintln!("运行时记录无法解析（按无记录处理）：{:?}", e);
            None
        }
    };
    let probe = crate::probe::SystemProbe { session_present: false, control_available };
    // 「是否已配置」直接传进去，调用方不再事后覆盖。
    crate::model::evidence_from(
        runtime.as_ref(),
        configured,
        &probe,
        crate::model::now_epoch_secs(),
    )
}

/// 当前状态的一行 JSON。界面按这些字段名取值，所以字段名一旦定下就是契约。
/// 线路列表的载荷：界面与管道共用这一份形状。
///
/// `selected` 取「实际生效的那条」（`current_line()`，`selected` 失效时会回退第一条），
/// 所以界面上的实心圆永远和真正在用的线路一致。
pub fn lines_payload(cfg: Option<&crate::config::AppConfig>) -> serde_json::Value {
    let lines: Vec<serde_json::Value> = match cfg {
        Some(c) => c
            .lines
            .iter()
            .map(|l| {
                serde_json::json!({
                    "id": l.id,
                    "name": l.name,
                    "endpoint": l.proxy_endpoint,
                    "selected": c.is_selected(l),
                    // 连接方式：id 是机器可用的值（udp/tcp），是否"用户显式选过"单独给一个布尔
                    // ——界面要把「默认」与「已选」分开说，不能只看当前值。
                    "transport": l.effective_transport().id(),
                    "transportSelected": l.transport.is_some(),
                    // 「自动」有没有依据：这条线路上真的连通过某种方式（自检通过才记）。
                    // 界面靠它决定要不要说「已选自动，请先测试线路以确定下次使用的方式」。
                    "transportVerified": l.verified_transport.is_some(),
                })
            })
            .collect(),
        None => Vec::new(),
    };
    let selected = cfg
        .and_then(|c| c.current_line())
        .map(|l| l.id.clone())
        .unwrap_or_default();
    serde_json::json!({ "lines": lines, "selected": selected })
}

/// 自动选路的证据投影：只读，不探测。
fn autoroute_list_json(ctx: &Ctx) -> String {
    let now = crate::model::now_epoch_secs_u64() as i64;
    serde_json::json!({
        "ok": true,
        "autoRoutes": crate::autoroute::list_view(&ctx.root, now),
    })
    .to_string()
}

/// `auto-route`：对一条线路真拨两个候选，写证据并给出排名。
///
/// `refresh=false` 时优先复用未过期且网络相同的证据；`refresh=true` 强制重测。
/// 连接中拒绝：探测要起临时引擎，会和正在跑的连接抢同一个 WireGuard 身份。
fn auto_route_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let requested = parsed
        .get("line")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let refresh = parsed
        .get("refresh")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let cfg = match live_cfg(ctx) {
        Some(cfg) => cfg,
        None => return refuse_with_code("找不到配置文件（config.json），请先导入线路", "config"),
    };
    let line = match if requested.is_empty() {
        cfg.current_line().cloned()
    } else {
        cfg.lines.iter().find(|line| line.id == requested).cloned()
    } {
        Some(line) => line,
        None => return refuse_with_code("找不到要自动选路的线路", "usage"),
    };
    let now = crate::model::now_epoch_secs_u64() as i64;
    if line.transport.is_some() {
        let choice = crate::autoroute::choose_transport(&ctx.root, &cfg, &line, None, false, now);
        let mut view = crate::autoroute::choice_view(&choice, now);
        view["LineId"] = serde_json::json!(line.id);
        view["Note"] = serde_json::json!("你已固定连接方式；「自动」档才会按探测结果选择。");
        return serde_json::json!({"ok": true, "autoRoute": view}).to_string();
    }
    if busy(ctx) {
        return refuse_with_code(
            "连接中不能自动选路：探测要起一个临时引擎，会打断正在使用的连接。请先断开。",
            "busy",
        );
    }
    // 未要求重测且证据仍新鲜：直接复用，避免每次打开页面都起两次引擎。
    if !refresh {
        let choice = crate::autoroute::choose_transport(&ctx.root, &cfg, &line, None, false, now);
        if choice.source == "Evidence" {
            let mut view = crate::autoroute::choice_view(&choice, now);
            view["LineId"] = serde_json::json!(line.id);
            view["Probed"] = serde_json::json!(false);
            return serde_json::json!({"ok": true, "autoRoute": view}).to_string();
        }
    }
    let configured = cfg.engine.as_ref().map(|engine| engine.binary.clone()).unwrap_or_default();
    let Some((binary, _origin)) = crate::engine::resolve_for(&ctx.root, &configured) else {
        return refuse_with_code(&engine_missing_message(&configured), "environment");
    };
    let evidence = crate::autoroute::probe_line(&ctx.root, &cfg, &line, &binary, now);
    let winner = evidence.winner;
    let transport = winner.unwrap_or_else(|| line.effective_transport());
    let choice = crate::autoroute::Choice {
        transport,
        source: if winner.is_some() { "Probe" } else { "Fallback" },
        evidence: Some(evidence),
        note: if winner.is_some() {
            "已按当前网络探测并选出连接方式".to_string()
        } else {
            "两种方式都没有通过探测，仍按上次成功的方式连接".to_string()
        },
    };
    let mut view = crate::autoroute::choice_view(&choice, now);
    view["LineId"] = serde_json::json!(line.id);
    view["Probed"] = serde_json::json!(true);
    serde_json::json!({"ok": true, "autoRoute": view}).to_string()
}

/// `auto-reroute`：连接中按需切换连接方式（A8 后续）。
///
/// 与 `auto-route` 的分工：那条是「连接前探测并选一次」，这条是「已经连着，
/// 网络变了或连续变差，换一种走法」。两条纪律：
/// 1. **连接中不测当前正在用的标准连接**：同一个 WireGuard 身份，探测会把服务端
///    记录的对端地址改到探测 socket 上，等于自己把自己的连接打断。
/// 2. 只在备选**真的更好**时才断开重连；否则保持现状，不为一次探测丢掉可用连接。
fn auto_reroute_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let requested = parsed
        .get("line")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let reason = parsed
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("manual")
        .trim()
        .to_string();
    let cfg = match live_cfg(ctx) {
        Some(cfg) => cfg,
        None => return refuse_with_code("找不到配置文件（config.json），请先导入线路", "config"),
    };
    let line = match if requested.is_empty() {
        cfg.current_line().cloned()
    } else {
        cfg.lines.iter().find(|line| line.id == requested).cloned()
    } {
        Some(line) => line,
        None => return refuse_with_code("找不到要切换的线路", "usage"),
    };
    if line.transport.is_some() {
        return refuse_with_code("这条线路固定了连接方式，自动切换不会覆盖你的选择", "state");
    }
    if !busy(ctx) {
        return refuse_with_code("当前没有连接，不需要自动切换", "state");
    }
    let from = crate::engine_config::actual_transport(&ctx.root.join("runtime-engine.json"))
        .unwrap_or_else(|| line.effective_transport());
    let alternate = match from {
        Transport::Udp => Transport::Tcp,
        Transport::Tcp => Transport::Udp,
    };
    let now = crate::model::now_epoch_secs_u64() as i64;
    let configured = cfg.engine.as_ref().map(|engine| engine.binary.clone()).unwrap_or_default();
    let Some((binary, _origin)) = crate::engine::resolve_for(&ctx.root, &configured) else {
        return refuse_with_code(&engine_missing_message(&configured), "environment");
    };
    let mut view = serde_json::json!({
        "LineId": line.id,
        "Reason": reason,
        "From": from.id(),
        "To": from.id(),
        "Alternate": alternate.id(),
        "Switched": false,
        "Note": "",
    });
    // 网络整体换了：必须断开后再测两个候选——连接中测当前标准连接会打断它自己。
    // 断开之后无论测出什么都要重连，所以这一条路径一定有一次短暂断线。
    if reason == "network" {
        let reply = reroute_probe_cycle(ctx, &cfg, &line, &binary, from, now);
        match reply {
            Err(error) => {
                view["Note"] = serde_json::json!(format!("切换没有完成：{error}"));
            }
            Ok(winner) => {
                view["To"] = serde_json::json!(winner.id());
                view["Switched"] = serde_json::json!(winner != from);
                view["Note"] = if winner == from {
                    serde_json::json!(format!(
                        "网络已变化，已重测并重新连接（仍使用{}）",
                        winner.label()
                    ))
                } else {
                    serde_json::json!(format!("网络已变化，已切换到{}", winner.label()))
                };
            }
        }
        return serde_json::json!({"ok": true, "autoReroute": view}).to_string();
    }

    // 质量差/手动：只测备选，且必须真的赢过当前这一种才重连。
    let candidate = crate::autoroute::probe_alternate(
        &ctx.root, &cfg, &line, &binary, alternate, now,
    );
    let winner = crate::autoroute::load_evidence(&ctx.root, &line.id)
        .and_then(|evidence| evidence.winner);
    if !candidate.reachable || winner != Some(alternate) {
        let why = if candidate.reachable {
            "备选已测通，但当前方式仍然更优，连接未改动"
        } else {
            "备选没有测通，保持当前连接"
        };
        view["Note"] = serde_json::json!(why);
        return serde_json::json!({"ok": true, "autoReroute": view}).to_string();
    }
    let reply = reroute_cycle(ctx);
    if let Some(error) = reply.get("error").and_then(serde_json::Value::as_str) {
        view["Note"] = serde_json::json!(format!("切换没有完成：{error}"));
    } else {
        view["To"] = serde_json::json!(alternate.id());
        view["Switched"] = serde_json::json!(true);
        view["Note"] = serde_json::json!(format!(
            "已切换到{}（{} ms）",
            alternate.label(),
            candidate.latency_ms.unwrap_or(0)
        ));
    }
    serde_json::json!({"ok": true, "autoReroute": view}).to_string()
}

/// 断开 → 探测两个候选 → 重连。返回重连实际使用的方式。
fn reroute_probe_cycle(
    ctx: &Ctx,
    cfg: &crate::config::AppConfig,
    line: &crate::config::LineConfig,
    binary: &std::path::Path,
    fallback: Transport,
    now_unix: i64,
) -> Result<Transport, String> {
    let reply_of = |text: String| {
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "宿主回包不是合法 JSON"}))
    };
    let disconnected = reply_of(disconnect_json(ctx));
    if disconnected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = disconnected
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("断开没有完成");
        return Err(format!("断开失败：{message}"));
    }
    let evidence = crate::autoroute::probe_line(&ctx.root, cfg, line, binary, now_unix);
    let winner = evidence.winner.unwrap_or(fallback);
    let connected = reply_of(connect_json(ctx));
    if connected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = connected
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("重连没有完成");
        return Err(format!("重连失败：{message}"));
    }
    Ok(winner)
}

/// 断开 → 连接。连接会复用刚落盘的证据（`connect` 走 `choose_transport`）。
fn reroute_cycle(ctx: &Ctx) -> serde_json::Value {
    let reply_of = |text: String| {
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "宿主回包不是合法 JSON"}))
    };
    let disconnected = reply_of(disconnect_json(ctx));
    if disconnected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = disconnected
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("断开没有完成");
        return serde_json::json!({"error": format!("断开失败：{message}")});
    }
    let connected = reply_of(connect_json(ctx));
    if connected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = connected
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("重连没有完成");
        return serde_json::json!({"error": format!("重连失败：{message}")});
    }
    serde_json::json!({"ok": true})
}

fn lines_json(ctx: &Ctx) -> String {
    // 同上：删完/切完之后立刻再查，必须看到新结果。
    let read = read_cfg(ctx);
    let mut v = lines_payload(read.cfg.as_ref());
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    insert_lines_read(&mut v, &read.error);
    v.to_string()
}

/// 现在是不是「有连接在跑」：引擎活着，或者还有还原凭据没清。
/// 半接管状态下换线路会让还原凭据里的端点与实际引擎对不上——必须拒绝。
fn busy(ctx: &Ctx) -> bool {
    connection_busy(&ctx.root)
}

/// 现在是不是「有连接在跑」：引擎活着，或者还有还原凭据没清。
/// 命令行的分流/线路改动与界面走同一个判定，避免两处口径分叉。
pub fn connection_busy(root: &std::path::Path) -> bool {
    let engine_alive = crate::model::load_runtime(&root.join("runtime.json"))
        .ok()
        .flatten()
        .and_then(|r| r.engine_pid)
        .map(crate::probe::pid_alive)
        .unwrap_or(false);
    engine_alive || root.join("proxy-journal.json").exists()
}

/// 切换 / 删除线路。写盘后把**新的**列表原样回推，界面不用再查一次。
fn edit_lines(ctx: &Ctx, raw: &str, remove: bool) -> String {
    let id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_default();
    if id.trim().is_empty() {
        return refuse("缺少线路 id（请求里没有 id 字段）");
    }
    if busy(ctx) {
        return refuse("请先断开再切换或删除线路：连接中改动配置会让还原凭据与实际引擎对不上");
    }

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    let Some(target) = cfg.find_line(&id).cloned() else {
        return refuse(&format!("找不到线路：{}", id.trim()));
    };

    let mut delete_result: Option<serde_json::Value> = None;
    if remove {
        cfg.lines.retain(|l| l.id != target.id);
        // 删的是当前选中（或选中已失效）→ 回退第一条；删空就清空 selected。
        if cfg.find_line(&cfg.selected).is_none() {
            cfg.selected = cfg.lines.first().map(|l| l.id.clone()).unwrap_or_default();
        }
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存线路配置失败：{e}"));
        }
        // 这条线路的出口网卡绑定跟着走：留着它只会让下一条同名重导入的线路
        // 莫名绑到一张用户从没为它选过的网卡上。删不掉不算失败（绑定不是秘密，
        // 也不是连接的判据），但不许把它变成「线路删了、绑定还在」的静默残留。
        if let Err(e) = crate::netbind::forget(&ctx.root, &target.id) {
            eprintln!("清理线路出口网卡绑定失败（不影响删除）：{e}");
        }
        // 引擎配置跟着删，而且**必须核对结果**：`remove_file` 失败却回包说“删了”，
        // 用户会以为含隧道私钥的文件已经不在本机。失败就落一条待清理记录——
        // 它要活过重启（用户可能过几天才回来处理），界面据此给「重试清理」。
        let engine_path = target.engine_config_path(&ctx.root);
        let file = relative_to_root(&ctx.root, &engine_path);
        let mut incomplete = false;
        let mut file_error = String::new();
        match std::fs::remove_file(&engine_path) {
            Ok(()) => {
                let _ = crate::cleanup::clear(&ctx.root, &target.id);
            }
            // 文件本来就不在（预览时说没有引擎配置）同样算删干净，顺手清掉旧记录。
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = crate::cleanup::clear(&ctx.root, &target.id);
            }
            Err(error) => {
                incomplete = true;
                file_error = error.to_string();
                let pending = crate::cleanup::Pending {
                    id: target.id.clone(),
                    name: target.name.clone(),
                    file: file.clone(),
                    error: file_error.clone(),
                };
                // 配置已经改了，这条命令不能因为写记录失败而变成失败；把记录失败
                // 一并写进事件与回包，让用户知道“下次重启后可能看不到这条提示”。
                let note = match crate::cleanup::upsert(&ctx.root, pending) {
                    Ok(()) => String::new(),
                    Err(e) => format!("；待清理记录也没写成：{e}"),
                };
                crate::events::record(
                    &ctx.root,
                    crate::events::CLEANUP,
                    false,
                    &format!(
                        "线路「{}」已从配置移除，但 {file} 没删掉：{file_error}{note}",
                        target.name
                    ),
                    &ctx.origin(Some(&format!("line:{}", target.id))),
                );
            }
        }
        delete_result = Some(serde_json::json!({
            "Id": target.id,
            "Name": target.name,
            "File": file,
            "Incomplete": incomplete,
            "Error": if incomplete {
                serde_json::Value::String(file_error)
            } else {
                serde_json::Value::Null
            },
        }));
    } else {
        cfg.selected = target.id.clone();
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存线路配置失败：{e}"));
        }
    }

    let mut v = lines_payload(Some(&cfg));
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        if let Some(result) = delete_result {
            o.insert("deleteResult".to_string(), result);
        }
    }
    v.to_string()
}

/// 删除线路前的只读预览：能不能删、删什么、保留什么。
///
/// **只读**：不写配置、不删文件、不留操作记录。`Eligible=false` 不是命令失败——
/// 「现在不能删」是预览的结论，`ok` 仍为 true；真正的命令错误（缺 id / 找不到线路 /
/// 配置读不出来）才回 `ok:false` + `errorCode`。
///
/// 连接闸门与 [`edit_lines`] 的 remove 分支共用 [`busy`]：预览说能删、确认后却被拒，
/// 等于让用户白点一次。
fn delete_preview_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(_) => return refuse_with_code("请求不是合法 JSON", "usage"),
    };
    let id = parsed
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if id.is_empty() {
        return refuse_with_code("缺少线路 id（请求里没有 id 字段）", "usage");
    }

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let cfg = match crate::config::load(&cfg_path) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return refuse_with_code("找不到配置文件（config.json），请先导入线路", "config")
        }
        Err(error) => return refuse_with_code(&error.to_string(), "config"),
    };
    let Some(line) = cfg.lines.iter().find(|item| item.id == id).cloned() else {
        return refuse_with_code(&format!("找不到线路：{id}"), "config");
    };

    let engine_path = line.engine_config_path(&ctx.root);
    let mut files = Vec::new();
    if engine_path.is_file() {
        files.push(relative_to_root(&ctx.root, &engine_path));
    }

    let mut blocked = Vec::new();
    if busy(ctx) {
        blocked.push(serde_json::json!({
            "Code": "Busy",
            "Message": "连接未断开：请先断开再删除（连接中改动配置会让还原凭据与实际引擎对不上）。",
        }));
    }

    let mut warnings = Vec::new();
    if files.is_empty() {
        warnings.push(serde_json::json!({
            "Code": "NoEngineConfig",
            "Message": "没有找到这条线路的引擎配置文件；删除只会移除 config.json 里的这一条。",
        }));
    }
    if cfg.lines.len() == 1 {
        warnings.push(serde_json::json!({
            "Code": "LastLine",
            "Message": "这是最后一条线路，删除后将没有可用线路。",
        }));
    } else if cfg.is_selected(&line) {
        warnings.push(serde_json::json!({
            "Code": "Selected",
            "Message": "这是当前选中的线路；删除后会自动切换到另一条线路。",
        }));
    }

    // 服务器记录是**保留**项，但归属仍要说准：读不出来时不能假装「没有记录」。
    let (server, server_error) = match crate::serverstore::list(&ctx.root) {
        Ok(records) => {
            let hosts = line_server_hosts(&ctx.root, &line);
            let record = records.into_iter().find(|record| {
                let host = record.host.trim().to_ascii_lowercase();
                hosts.iter().any(|wanted| *wanted == host)
            });
            (record, None)
        }
        Err(error) => (None, Some(error.message)),
    };
    if let Some(message) = server_error {
        warnings.push(serde_json::json!({
            "Code": "ServerUnknown",
            "Message": format!("读不出服务器记录，无法判断这条线路是否属于某台服务器：{message}"),
        }));
    }
    let server_json = server
        .as_ref()
        .map(|record| {
            serde_json::json!({
                "Id": record.id,
                "Name": record.name,
                "Host": record.host,
            })
        })
        .unwrap_or(serde_json::Value::Null);

    serde_json::json!({
        "ok": true,
        "deletePreview": {
            "Id": line.id,
            "Name": line.name,
            "Selected": cfg.is_selected(&line),
            "LastLine": cfg.lines.len() == 1,
            "Eligible": blocked.is_empty(),
            "Blocked": blocked,
            "Files": files,
            "Server": server_json,
            "Warnings": warnings,
        }
    })
    .to_string()
}

/// 数据根下的一条待清理记录 → 回包形状。
fn pending_to_json(pending: &[crate::cleanup::Pending]) -> Vec<serde_json::Value> {
    pending
        .iter()
        .map(|item| {
            serde_json::json!({
                "Id": item.id,
                "Name": item.name,
                "File": item.file,
                "Error": item.error,
            })
        })
        .collect()
}

/// 待清理记录（A4 第二轮）：只读。`ok:true` = 记录读到了——**空列表也是成功**；
/// 只有记录文件本身坏掉才 `ok:false`（`deleteCleanup.ReadError` 里带一句人话）。
/// 界面据 `ReadError` 说“不知道还有没有要清的文件”，而不是把读不出来显示成没有。
fn delete_cleanup_json(ctx: &Ctx) -> String {
    match crate::cleanup::load(&ctx.root) {
        Ok(pending) => serde_json::json!({
            "ok": true,
            "deleteCleanup": {
                "Pending": pending_to_json(&pending),
                "ReadError": "",
            }
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "ok": false,
            "error": error,
            "errorCode": "cleanup",
            "deleteCleanup": {
                "Pending": [],
                "ReadError": error,
            }
        })
        .to_string(),
    }
}

/// 重试的拒绝形状：`ok:false` 与 `deleteCleanupResult` **同时给**——
/// 页面只读结果那一份，缺了它，点「重试清理」失败后界面什么都不变。
fn cleanup_refuse(id: &str, message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "deleteCleanupResult": {
            "Id": id,
            "Name": "",
            "File": "",
            "Complete": false,
            "Removed": false,
            "Error": message,
            "Message": message,
        }
    })
    .to_string()
}

/// 重试清理一条线路的残留文件。
///
/// 三个前置判定都在动手之前：
/// 1. 线路**不能**还在配置里——同 id 又被导入过时，旧记录指向的是新线路的引擎配置，
///    照着删等于删掉一条正在用的线路的私钥文件；
/// 2. 待清理记录必须读得出来、且确实有这一条；
/// 3. 路径按 id 重算（与删除时同一条规则），不信任记录里的相对路径。
///
/// 文件已经不在了算**完成**（目的达到了），只是 `Removed=false`：如实说“已经不在了”，
/// 不说“刚刚删掉了”。
fn delete_cleanup_retry_json(ctx: &Ctx, raw: &str) -> String {
    let id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            v.get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if id.is_empty() {
        return cleanup_refuse("", "缺少线路 id（请求里没有 id 字段）", "usage");
    }
    match crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH)) {
        Ok(Some(cfg)) if cfg.find_line(&id).is_some() => {
            return cleanup_refuse(
                &id,
                &format!("线路「{id}」还在线路列表里：请先在界面上删除它，再来清理残留文件。"),
                "cleanup",
            );
        }
        Ok(_) => {}
        Err(error) => {
            return cleanup_refuse(
                &id,
                &format!("读不出线路配置，无法确认这条线路是否还在：{error}"),
                "config",
            );
        }
    }

    let mut pending = match crate::cleanup::load(&ctx.root) {
        Ok(pending) => pending,
        Err(error) => return cleanup_refuse(&id, &error, "cleanup"),
    };
    let Some(index) = pending.iter().position(|item| item.id == id) else {
        return cleanup_refuse(
            &id,
            &format!("没有线路「{id}」的待清理记录（可能已经清理过了）。"),
            "cleanup",
        );
    };
    let item = pending[index].clone();
    let engine_path = crate::config::engine_config_path_for(&ctx.root, &item.id);
    let file = relative_to_root(&ctx.root, &engine_path);
    let origin = ctx.origin(Some(&format!("line:{}", item.id)));
    let save_note = |result: Result<(), String>| match result {
        Ok(()) => String::new(),
        Err(error) => format!("；待清理记录没更新：{error}"),
    };

    let (complete, removed, message) = match std::fs::remove_file(&engine_path) {
        Ok(()) => {
            pending.remove(index);
            let note = save_note(crate::cleanup::save(&ctx.root, &pending));
            crate::events::record(
                &ctx.root,
                crate::events::CLEANUP,
                true,
                &format!("已删除线路「{}」的残留文件 {file}{note}", item.name),
                &origin,
            );
            (
                true,
                true,
                format!("已清理线路「{}」的残留文件 {file}。{note}", item.name),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            pending.remove(index);
            let note = save_note(crate::cleanup::save(&ctx.root, &pending));
            crate::events::record(
                &ctx.root,
                crate::events::CLEANUP,
                true,
                &format!("残留文件 {file} 已经不在，已清除待清理记录{note}"),
                &origin,
            );
            (
                true,
                false,
                format!("残留文件 {file} 已经不在了，已清除待清理记录。{note}"),
            )
        }
        Err(error) => {
            let text = error.to_string();
            if let Some(slot) = pending.get_mut(index) {
                slot.error = text.clone();
            }
            let note = save_note(crate::cleanup::save(&ctx.root, &pending));
            crate::events::record(
                &ctx.root,
                crate::events::CLEANUP,
                false,
                &format!("残留文件 {file} 还是没删掉：{text}{note}"),
                &origin,
            );
            (
                false,
                false,
                format!("残留文件 {file} 还是没删掉：{text}{note}"),
            )
        }
    };

    serde_json::json!({
        "ok": true,
        "deleteCleanupResult": {
            "Id": item.id,
            "Name": item.name,
            "File": file,
            "Complete": complete,
            "Removed": removed,
            "Error": if complete { serde_json::Value::Null } else { serde_json::Value::String(message.clone()) },
            "Message": message,
        }
    })
    .to_string()
}

/// 数据根下的相对路径：界面只展示 `lines\<id>.json`，不把用户的绝对目录带到对话框里。
fn relative_to_root(root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}


/// 线路引擎配置里出现过的出站地址（小写、trim）。与 `servers` 命令同一判据：
/// 字面地址相等才算归属，不做域名与 IP 的猜测。
fn line_server_hosts(root: &std::path::Path, line: &crate::config::LineConfig) -> Vec<String> {
    // **判据只有一份**：`pairhost::line_hosts`（出站 `server` + WireGuard 端点
    // `endpoints[].peers[].address`）。这里再写一遍「只扫 outbounds」，标准线路就会
    // 找不到自己的服务器——「服务器与设备」「卸载通道服务」「删除本机部署资料」
    // 三条路都从这个函数取身份，写错一处等于三条一起坏。
    crate::pairhost::line_hosts(root)
        .into_iter()
        .filter(|(id, _)| id == &line.id)
        .map(|(_, host)| host)
        .collect()
}

fn rename_line_refuse(message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "renameResult": {
            "ok": false,
            "changed": false,
            "name": serde_json::Value::Null,
            "message": message,
        }
    })
    .to_string()
}

/// 线路改名：只改 `config.json` 里那条线路的 `name`，不动 id、端点、选中项和
/// `data\lines\<id>.json`。**不复用 `--set-line`**：那个命令同时会更新端点并把线路
/// 设为选中，拿来改名会顺手改掉远比“名字”更多的状态。
fn rename_line_json(ctx: &Ctx, raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return rename_line_refuse("请求不是合法 JSON", "usage");
    };
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if id.is_empty() {
        return rename_line_refuse("缺少线路 id（请求里没有 id 字段）", "usage");
    }
    if name.is_empty() {
        return rename_line_refuse("线路名不能为空", "usage");
    }
    if name.chars().any(char::is_control) {
        return rename_line_refuse("线路名不能包含换行、制表符等控制字符", "usage");
    }
    if busy(ctx) {
        return rename_line_refuse("请先断开再改线路名：连接中改动配置会让还原凭据与实际引擎对不上", "environment");
    }

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return rename_line_refuse("找不到配置文件（config.json），请先导入线路", "config"),
        Err(e) => return rename_line_refuse(&e.to_string(), "config"),
    };
    let Some(target) = cfg.lines.iter().find(|l| l.id == id).cloned() else {
        return rename_line_refuse(&format!("找不到线路：{id}"), "config");
    };

    // 名称也是 `find_line` 的查找键。允许与别的线路名或 id 同名，会让 `--use 名称`
    // 和界面选中都出现两个候选；在写盘前直接拒绝，配置保持原样。
    let duplicate = cfg.lines.iter().any(|l| {
        l.id != target.id
            && (l.name.eq_ignore_ascii_case(&name) || l.id.eq_ignore_ascii_case(&name))
    });
    if duplicate {
        return rename_line_refuse(&format!("已经有名为「{name}」的线路，请换一个名称"), "conflict");
    }

    let changed = target.name != name;
    if changed {
        if let Some(l) = cfg.lines.iter_mut().find(|l| l.id == target.id) {
            l.name = name.clone();
        }
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return rename_line_refuse(&format!("保存线路配置失败：{e}"), "config");
        }
    }

    let mut out = lines_payload(Some(&cfg));
    if let Some(o) = out.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert(
            "renameResult".to_string(),
            serde_json::json!({
                "ok": true,
                "changed": changed,
                "name": name,
                "message": if changed { format!("已改名为「{name}」") } else { "名称没有变化，未写入配置".to_string() },
            }),
        );
    }
    out.to_string()
}

fn export_history_refuse(message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "exportResult": {
            "ok": false,
            "path": serde_json::Value::Null,
            "count": 0,
            "message": message,
        }
    })
    .to_string()
}

/// 导出当前筛选的操作记录。记录格式是 JSON Lines：一行一条，字段与记录文件一致，
/// 顺序与页面相同（新 → 旧）。只读记录本身；唯一写入是数据根 `logs\exports` 下的新文件，
/// 不发起网络请求，也不接受调用方指定任意路径。
fn export_history_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let filter = parsed.as_ref().and_then(|v| v.get("filter"));
    let only_fail = filter
        .and_then(|f| f.get("onlyFail"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let src = filter
        .and_then(|f| f.get("src"))
        .and_then(|x| x.as_str())
        .unwrap_or("all")
        .trim()
        .to_ascii_lowercase();
    if !matches!(src.as_str(), "all" | "ui" | "cli" | "pipe" | "auto" | "other" | "unknown") {
        return export_history_refuse(&format!("来源筛选只支持 all/ui/cli/pipe/auto/other/unknown（收到：{src}）"), "usage");
    }
    // r96：导出的必须就是页面看得见的那一批。隐藏开关与搜索词都随「当前筛选」过来；
    // 缺省（includeHidden=false）不导出隐藏记录——否则文件里会多出页面上不存在的行。
    let include_hidden = filter
        .and_then(|f| f.get("includeHidden"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let search = filter
        .and_then(|f| f.get("search"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let hidden = crate::events::hidden_keys(&ctx.root);

    let known = ["ui", "cli", "pipe", "auto", "other"];
    let events: Vec<crate::events::Event> = crate::events::read(&ctx.root, crate::events::READ_LIMIT)
        .into_iter()
        .filter(|e| !only_fail || !e.ok)
        .filter(|e| match src.as_str() {
            "all" => true,
            "unknown" => e.src.as_deref().map(|s| !known.contains(&s)).unwrap_or(true),
            want => e.src.as_deref() == Some(want),
        })
        .filter(|e| {
            include_hidden
                || !hidden.contains(&crate::events::key(&e.ts, &e.action, &e.detail))
        })
        .filter(|e| {
            if search.is_empty() {
                return true;
            }
            let hay = format!(
                "{} {} {} {}",
                e.action,
                e.detail,
                e.obj.as_deref().unwrap_or(""),
                e.actor.as_deref().unwrap_or("")
            )
            .to_lowercase();
            hay.contains(&search)
        })
        .collect();
    if events.is_empty() {
        return export_history_refuse("当前筛选没有记录，未导出", "environment");
    }

    let dir = ctx.root.join("logs").join("exports");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return export_history_refuse(&format!("创建导出目录失败：{e}"), "config");
    }
    let stamp = crate::model::now_epoch_secs();
    let mut path = None;
    for n in 0..1000u32 {
        let name = if n == 0 {
            format!("operations-{stamp}.jsonl")
        } else {
            format!("operations-{stamp}-{n}.jsonl")
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            path = Some(candidate);
            break;
        }
    }
    let Some(path) = path else {
        return export_history_refuse("导出目录里同名文件过多，请稍后重试", "config");
    };

    let mut text = String::new();
    for event in &events {
        match serde_json::to_string(event) {
            Ok(line) => {
                text.push_str(&line);
                text.push('\n');
            }
            Err(e) => return export_history_refuse(&format!("生成导出内容失败：{e}"), "internal"),
        }
    }
    let tmp = dir.join(format!(".operations-export-{}-{stamp}.tmp", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, text.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return export_history_refuse(&format!("写入导出文件失败：{e}"), "config");
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return export_history_refuse(&format!("保存导出文件失败：{e}"), "config");
    }

    let message = format!("已导出 {} 条记录到 {}", events.len(), path.display());
    serde_json::json!({
        "ok": true,
        "exportResult": {
            "ok": true,
            "path": path.to_string_lossy(),
            "count": events.len(),
            "message": message,
        }
    })
    .to_string()
}

/// 分流规则的载荷。数组顺序 = 用户添加顺序（界面按这个顺序展示，不排序）。
///
/// 每条带 `path`（程序绝对路径，可能为空）与 `guard`（这条在交易保护里的处境）：
/// - `Participated` / `Protected` / `UnresolvedReason` 三者**都来自后端判定**，
///   界面不许自己猜「这条有没有被保护」（PRD §7「名单页逐条保护状态」）。
/// - 非 `trade` 条目永远 `Participated=false` + 原因「不在交易名单」：它们本来就不该被阻断。
pub fn split_payload(
    cfg: Option<&crate::config::AppConfig>,
    root: &std::path::Path,
) -> serde_json::Value {
    fn target_name(target: crate::config::SplitTarget) -> &'static str {
        match target {
            crate::config::SplitTarget::Direct => "direct",
            crate::config::SplitTarget::Trade => "trade",
            crate::config::SplitTarget::Daily => "daily",
        }
    }

    /// 把判定结果投影成「这条条目现在被保护了吗」。
    ///
    /// 同一个名字可能出现在多个落点；这里按 (名字, 目标) 匹配，避免「直连条目借用了
    /// 交易条目的状态」这种张冠李戴。
    fn guard_of(
        name: &str,
        target: crate::config::SplitTarget,
        status: &crate::guard::GuardStatus,
    ) -> serde_json::Value {
        if target != crate::config::SplitTarget::Trade {
            return serde_json::json!({
                "Participated": false,
                "Protected": false,
                "Reason": "不在交易名单（这一条不受交易保护约束）",
            });
        }
        match status.programs.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
            Some(p) => serde_json::json!({
                "Participated": p.participated,
                "Protected": p.ok(),
                "Reason": p.unresolved_reason.as_deref().unwrap_or(""),
            }),
            // 名单里有、判定结果里没有：只可能是刚加进来还没解析过。
            // 这时的正确说法是「还没核验」，不是「已保护」。
            None => serde_json::json!({
                "Participated": false,
                "Protected": false,
                "Reason": "尚未核验",
            }),
        }
    }

    fn entries(
        list: &[crate::config::SplitEntry],
        status: &crate::guard::GuardStatus,
        applied: Option<&std::collections::HashSet<String>>,
    ) -> serde_json::Value {
        serde_json::Value::Array(
            list.iter()
                .map(|e| {
                    serde_json::json!({
                        "value": e.value(),
                        "target": target_name(e.target()),
                        // 路径进载荷：界面要能显示，重选程序时也要能带回去（T04 用）
                        "path": e.path(),
                        // 文件还在不在（r99，旧版「文件已移走」）：只有程序条目有路径。
                        "fileExists": e.path().map(|p| std::path::Path::new(p).is_file()),
                        // 当前线路的引擎配置里有没有这条进程规则（旧版「已生效」）。
                        "applied": applied.map(|set| set.contains(&e.value().to_ascii_lowercase())),
                        "guard": guard_of(e.value(), e.target(), status),
                    })
                })
                .collect(),
        )
    }
    match cfg {
        Some(c) => {
            // 判定只算一次：这条命令既不是状态刷新，也不该让它去碰两次文件系统。
            let status = crate::guard::status(Some(c), root, false);
            let applied = applied_process_names(c, root);
            serde_json::json!({
                "processes": entries(&c.split.processes, &status, Some(&applied)),
                "domains": entries(&c.split.domains, &status, None),
            })
        }
        None => serde_json::json!({ "processes": [], "domains": [] }),
    }
}

/// 线路页那块「交易名单」的只读投影。
///
/// **只取交易出口的条目**：那块说的是「这条线路在保护哪些程序与网站」，直连/日常条目
/// 一条都不能混进来——混进来就等于告诉用户「它走交易线路」，而实际并没有。
///
/// `aux` 恒为空数组：本版没有旧版 NinjaTrader 的「辅助解析」概念，但字段留着不删——
/// 页面按同一套分组逻辑渲染，空组自己会整行不显示，这样与旧版的版式同一套结构。
///
/// 读配置失败（`cfg` 为 `None`）时给三个空数组，与 status 里其它「读不出来」的处理
/// 一致：线路页空着，但整个 status 不因此变成错误。
pub fn trade_list_payload(cfg: Option<&crate::config::AppConfig>) -> serde_json::Value {
    let Some(c) = cfg else {
        return serde_json::json!({ "programs": [], "domains": [], "aux": [] });
    };
    let programs: Vec<serde_json::Value> = c
        .split
        .processes
        .iter()
        .filter(|e| e.target() == crate::config::SplitTarget::Trade)
        .map(|e| {
            serde_json::json!({
                "name": e.value(),
                // 老条目没记过位置：照实给空串（页面会照常显示名字），
                // 编一个看起来像路径的值比空着更糟。
                "path": e.path().unwrap_or(""),
            })
        })
        .collect();
    let domains: Vec<&str> = c
        .split
        .domains
        .iter()
        .filter(|e| e.target() == crate::config::SplitTarget::Trade)
        .map(|e| e.value())
        .collect();
    serde_json::json!({ "programs": programs, "domains": domains, "aux": [] })
}

/// 当前线路引擎配置里已经写进去的进程名（全小写）。
///
/// 「已生效」在 旧版里是**线路配置里有没有这条规则**，不是「现在有没有被 WFP 拦住」：
/// 断开时保护状态未知，但名单仍然可以是已写进线路的。只读，读不到就当空集。
fn applied_process_names(
    cfg: &crate::config::AppConfig,
    root: &std::path::Path,
) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let Some(path) = cfg.current_engine_path(root) else {
        return out;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    if let Some(rules) = value.pointer("/route/rules").and_then(serde_json::Value::as_array) {
        for rule in rules {
            if let Some(names) = rule.get("process_name").and_then(serde_json::Value::as_array) {
                for name in names {
                    if let Some(name) = name.as_str() {
                        out.insert(name.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    out
}

fn split_json(ctx: &Ctx) -> String {
    let mut v = split_payload(live_cfg(ctx).as_ref(), &ctx.root);
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    v.to_string()
}

/// 加/删一条分流规则。与命令行同一套语义：去重、域名去 `*.`、落盘后同步到线路引擎配置。
fn edit_split(ctx: &Ctx, raw: &str, is_add: bool) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let kind = parsed
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("")
        .to_string();
    let value = parsed
        .as_ref()
        .and_then(|v| v.get("value"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !matches!(kind.as_str(), "process" | "domain") {
        return refuse("kind 只能是 process 或 domain");
    }
    if value.is_empty() {
        return refuse("缺少要添加/删除的值（请求里没有 value）");
    }
    // 与命令行同一套格式校验：挡住"永远匹配不上却不报错"的写法（删除不做格式限制）。
    if is_add {
        let check = if kind == "process" {
            crate::config::SplitConfig::validate_process(&value)
        } else {
            crate::config::SplitConfig::validate_domain(&value)
        };
        if let Err(e) = check {
            return refuse(&e);
        }
    }
    if busy(ctx) {
        return refuse("请先断开再改分流规则：连接中改动配置会让引擎实际行为与配置不一致");
    }

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    // 界面可带 target（direct / trade / daily），缺省直连。
    let target = match parsed.as_ref().and_then(|v| v.get("target")).and_then(|t| t.as_str()) {
        None => crate::config::SplitTarget::Direct,
        Some(t) => match crate::config::SplitTarget::from_name(t) {
            Some(t) => t,
            None => return refuse(&format!("target 只支持 direct / trade / daily（收到：{t}）")),
        },
    };
    // 可选的程序**绝对路径**（界面 pick-exe 回来的那个）。
    // 只有「进程 + 交易落点」才存：别的落点不需要程序身份，存了只会让配置里多一份
    // 会过期的副本（PRD P0-9 只要求交易名单能被可靠定位）。
    let raw_path = parsed
        .as_ref()
        .and_then(|v| v.get("path"))
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty());
    let path = if kind == "process" && target == crate::config::SplitTarget::Trade {
        raw_path
    } else {
        None
    };
    if is_add {
        if let Some(p) = path.as_deref() {
            if let Err(e) = crate::config::SplitConfig::validate_process_path(p) {
                return refuse(&e);
            }
        }
    }
    // 交易名单在改动前后的快照：**只有它真的变了**才作废证据
    // （PRD §4.1.1：名单变更属强制失效事件；但改一条直连/域名不该让保护状态翻成 Unknown）。
    let trade_before = crate::guard::trade_program_entries(&cfg);
    let changed = if kind == "process" {
        if is_add {
            cfg.split.add_process_entry(&value, target, path.as_deref())
        } else {
            cfg.split.remove_process(&value)
        }
    } else if is_add {
        cfg.split.add_domain(&value, target)
    } else {
        cfg.split.remove_domain(&value)
    };
    if changed {
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存配置失败：{e}"));
        }
        // 名单（含解析结果）变了 → 旧证据立即作废（PRD §4.1.1 强制失效事件）。
        // 判据用**改动前后的交易名单快照**，不是「这次动了哪种 kind」：只有真正影响
        // 保护口径的改动才该让卡片翻成「待核验」。
        if crate::guard::trade_program_entries(&cfg) != trade_before {
            crate::guard::invalidate_evidence(&ctx.root, "list-changed");
        }
        // 与命令行一致：立刻把规则落到线路的引擎配置上，别等下次连接。
        // **两份名单一起传**：只传分流会把 AI 工具名单的规则删掉。
        if let Some(line_path) = cfg.current_engine_path(&ctx.root) {
            let _ = crate::engine_config::apply_rules_to_file(&line_path, &cfg.split, &cfg.agents);
        }
    }
    // 重复添加 / 删不存在的项：仍然 ok，列表不变；结果句明确说明真实目标出口。
    let mut v = split_payload(Some(&cfg), &ctx.root);
    if let Some(o) = v.as_object_mut() {
        let target_label = match target {
            crate::config::SplitTarget::Direct => "本地直连",
            crate::config::SplitTarget::Trade => "交易出口",
            crate::config::SplitTarget::Daily => "日常出口",
        };
        let shown_value = if kind == "domain" { value.trim_start_matches("*.") } else { &value };
        let split_message = if changed {
            if is_add {
                format!("已加入：{shown_value} → {target_label}")
            } else {
                format!("已移除：{shown_value}")
            }
        } else if is_add {
            "这条规则已存在，列表未变化".to_string()
        } else {
            "这条规则本来就没有，列表未变化".to_string()
        };
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert("changed".to_string(), serde_json::json!(changed));
        o.insert("splitMessage".to_string(), serde_json::json!(split_message));
    }
    v.to_string()
}

/// `split-reset-trade-domains`：把交易出口那一组网站恢复成 旧版的默认名单。
///
/// 影响面与旧版的 `ResetTradeDomains` 对齐：只动 `domains` 里 target=trade 的条目；
/// 程序名单、直连/日常域名的规则原样保留。保存与「落地到当前线路引擎配置」走
/// 与 `split-add` 同一条路径，避免列表已变、引擎还跑着旧规则。
fn split_reset_trade_domains_json(ctx: &Ctx) -> String {
    if busy(ctx) {
        return refuse("请先断开再改分流规则：连接中改动配置会让引擎实际行为与配置不一致");
    }
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    let trade_before = crate::guard::trade_program_entries(&cfg);
    let changed = cfg.split.reset_trade_domains();
    if changed {
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存配置失败：{e}"));
        }
        if crate::guard::trade_program_entries(&cfg) != trade_before {
            crate::guard::invalidate_evidence(&ctx.root, "list-changed");
        }
        if let Some(line_path) = cfg.current_engine_path(&ctx.root) {
            let _ = crate::engine_config::apply_rules_to_file(&line_path, &cfg.split, &cfg.agents);
        }
    }
    let mut v = split_payload(Some(&cfg), &ctx.root);
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert("changed".to_string(), serde_json::json!(changed));
        let message = if changed {
            format!(
                "已恢复默认交易网站（{} 条）",
                crate::config::SplitConfig::DEFAULT_TRADE_DOMAINS.len()
            )
        } else {
            "交易网站已经是默认名单，未变化".to_string()
        };
        o.insert("splitMessage".to_string(), serde_json::json!(message));
    }
    v.to_string()
}


// ---------- AI 工具名单（读 / 全量保存 / 走向） ----------

/// 连接中拒绝保存名单时那句话。界面直接把它显示在保存条上。
///
/// 为什么保存名单也要过这道闸门：引擎用的是**连接那一刻**生成的运行时配置，
/// 连接中改配置会让「配置文件里写的」与「引擎正在跑的行为」不一致——用户会以为已经改好了。
const AGENTS_BUSY_MSG: &str =
    "请先断开再保存 AI 工具名单：连接中改动配置会让引擎实际行为与配置不一致";

/// 带机器可读错误码的拒绝。界面据 `errorCode=="busy"` 把保存按钮变成「请先断开再保存」。
fn refuse_with_code(msg: &str, code: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg, "errorCode": code }).to_string()
}

/// 日常上网现在走什么（`Direct` / `Provider` / `Trade` / 空串）。
///
/// 与 `uiweb::exit_lane` 同一套取值：全球覆盖（日常上网=交易线路）时名单实际也走交易线路，
/// 两条投影必须用同一个判断，否则首页说一套、名单页说另一套。
fn daily_lane_of(ctx: &Ctx, cfg: Option<&AppConfig>) -> String {
    let Some(file) = cfg.and_then(|c| c.current_engine_path(&ctx.root)) else {
        return String::new();
    };
    let Ok(Some(info)) = crate::engine_config::read_exits_from_file(&file) else {
        return String::new();
    };
    if info.daily.is_empty() {
        return String::new();
    }
    match info.daily.as_str() {
        "direct" | "tc-direct" => "Direct".to_string(),
        v if v.starts_with("provider") => "Provider".to_string(),
        _ => "Trade".to_string(),
    }
}

/// 名单页与走向命令共用的载荷：目录（**永远给全 22 项**，含说明/域名/运行徽标）+ 自定义
/// 条目 + 走向 + 状态。
///
/// 为什么是独立命令而不是塞进快照：目录是几十 KB 级的静态数据（含域名清单），而快照
/// 每个事件都发一次。与交易名单页同一形状（`split_payload` + 打开页面时查一次）。
pub fn agents_payload(ctx: &Ctx, cfg: Option<&AppConfig>) -> serde_json::Value {
    let agents = cfg.map(|c| c.agents.clone()).unwrap_or_default();
    let split = cfg.map(|c| c.split.clone()).unwrap_or_default();
    let trade_exit_present = cfg
        .and_then(|c| c.current_engine_path(&ctx.root))
        .map(|p| crate::engine_config::has_trade_exit_file(&p))
        .unwrap_or(false);
    let daily_lane = daily_lane_of(ctx, cfg);
    let global_override = daily_lane == "Trade";
    // `laneEffective` 与快照里的 `Agents` 是同一个谓词：页面说「会生效」⟺ 生成时真会生成。
    let lane_effective =
        crate::agents::lane_effective_id(agents.lane.id(), &daily_lane, trade_exit_present);
    // 运行徽标：开页/保存时对**当前进程快照**求值一次（旧版的 AgentPresence 三档）。
    let running_paths = crate::agents::running_process_paths();
    let builtin: Vec<serde_json::Value> = crate::agents::BUILTIN
        .iter()
        .map(|item| {
            let presence = if item.kind == crate::agents::AgentKind::Program {
                crate::agents::presence_of(item, &running_paths).id()
            } else {
                ""
            };
            serde_json::json!({
                "id": item.id,
                "name": item.name,
                "short": item.short,
                "kind": item.kind.id(),
                "detail": item.detail,
                "domains": item.domains,
                "presence": presence,
                "checked": agents.builtin.iter().any(|id| id == item.id),
                "inTradeList": crate::agents::in_trade_list(&split, item),
                "note": item.kind.note(),
            })
        })
        .collect();
    let checked = builtin
        .iter()
        .filter(|b| b.get("checked").and_then(|v| v.as_bool()) == Some(true))
        .count();
    let programs: Vec<serde_json::Value> = agents
        .programs
        .iter()
        .map(|value| {
            serde_json::json!({
                "value": value,
                "inTradeList": split
                    .processes
                    .iter()
                    .any(|e| e.value().eq_ignore_ascii_case(value.trim())),
            })
        })
        .collect();
    let sites: Vec<serde_json::Value> = agents
        .sites
        .iter()
        .map(|value| {
            serde_json::json!({
                "value": value,
                "inTradeList": split
                    .domains
                    .iter()
                    .any(|e| e.value() == crate::config::SplitConfig::normalize_domain(value)),
            })
        })
        .collect();
    serde_json::json!({
        "agents": {
            "lane": agents.lane.id(),
            "laneEffective": lane_effective,
            "globalOverride": global_override,
            "tradeExitPresent": trade_exit_present,
            "busy": busy(ctx),
            // 名单规模 = 勾选的内置项 + 自定义（程序 + 网站）合计。
            "count": checked + agents.custom_count(),
        },
        "builtin": builtin,
        "programs": programs,
        "sites": sites,
    })
}

fn agents_json(ctx: &Ctx) -> String {
    let read = read_cfg(ctx);
    let Some(cfg) = read.cfg else {
        return refuse("找不到配置文件（config.json），请先导入线路");
    };
    let mut v = agents_payload(ctx, Some(&cfg));
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    v.to_string()
}

/// 从请求里取一个字符串数组。缺省 = 空数组（**全量语义**：省掉三个数组等于清空，不是「不改」）。
fn string_list(parsed: &serde_json::Value, key: &str) -> Result<Vec<String>, String> {
    match parsed.get(key).filter(|v| !v.is_null()) {
        None => Ok(Vec::new()),
        Some(value) => match value.as_array() {
            Some(list) => Ok(list
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect()),
            None => Err(format!("{key} 必须是字符串数组")),
        },
    }
}

/// 保存名单：**一条命令全量提交**（走向 + 内置勾选 + 自定义程序 + 自定义网站）。
///
/// 失败一律零副作用：格式校验、连接闸门都在写盘之前。
fn save_agents(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::Value::Null);
    // 走向可省（= 保持现值）；给了就必须认得出，认不出不许默默当成 daily。
    let lane = match parsed.get("Lane").filter(|v| !v.is_null()) {
        None => None,
        Some(value) => match value.as_str().and_then(crate::config::AgentsLane::from_value) {
            Some(lane) => Some(lane),
            None => {
                return refuse_with_code(
                    &format!(
                        "Lane 只支持 Daily / Trade（收到：{}）",
                        value.as_str().unwrap_or("")
                    ),
                    "invalid",
                )
            }
        },
    };
    let builtin = match string_list(&parsed, "Builtin") {
        Ok(v) => v,
        Err(e) => return refuse_with_code(&e, "invalid"),
    };
    let programs = match string_list(&parsed, "Programs") {
        Ok(v) => v,
        Err(e) => return refuse_with_code(&e, "invalid"),
    };
    let sites = match string_list(&parsed, "Sites") {
        Ok(v) => v,
        Err(e) => return refuse_with_code(&e, "invalid"),
    };
    // 格式校验：与交易名单同一套函数、同一套措辞（用户在两页看到同一种说法）。
    for value in &programs {
        if let Err(e) = crate::config::SplitConfig::validate_process(value) {
            return refuse_with_code(&e, "invalid");
        }
    }
    for value in &sites {
        let normalized = crate::config::SplitConfig::normalize_domain(value);
        if let Err(e) = crate::config::SplitConfig::validate_domain(&normalized) {
            return refuse_with_code(&e, "invalid");
        }
    }
    if programs.len() + sites.len() > crate::agents::MAX_CUSTOM {
        return refuse_with_code(
            &format!("最多 {} 项，请先移除一些", crate::agents::MAX_CUSTOM),
            "tooMany",
        );
    }
    if busy(ctx) {
        return refuse_with_code(AGENTS_BUSY_MSG, "busy");
    }

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    let before = cfg.agents.clone();
    if let Some(lane) = lane {
        cfg.agents.lane = lane;
    }
    cfg.agents.builtin = builtin;
    cfg.agents.programs = programs;
    cfg.agents.sites = sites;
    // 写盘形态永远规范（幂等）：不认识的内置 id 丢、重复项合并、超限截断。
    cfg.agents.sanitize();
    let changed = cfg.agents != before;
    if changed {
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存配置失败：{e}"));
        }
        // 与交易名单保存后同一行为：立刻写进当前线路的引擎配置（下次连接生效）。
        // **两份名单一起传**：只传名单会把交易名单的规则删掉。
        if let Some(line_path) = cfg.current_engine_path(&ctx.root) {
            let _ = crate::engine_config::apply_rules_to_file(&line_path, &cfg.split, &cfg.agents);
        }
    }
    let mut v = agents_payload(ctx, Some(&cfg));
    let count = v["agents"]["count"].as_u64().unwrap_or(0);
    let trade_exit_present = v["agents"]["tradeExitPresent"].as_bool().unwrap_or(false);
    let agents_message = if !changed {
        "名单没有变化".to_string()
    } else if cfg.agents.is_empty() {
        // 空名单是合法状态（等于「没有名单」），说清楚它现在是空的。
        format!("已保存：名单为空，{}。下次连接时生效。", cfg.agents.lane.label())
    } else {
        let mut msg = format!("已保存：名单 {count} 项，{}。", cfg.agents.lane.label());
        if cfg.agents.lane == crate::config::AgentsLane::Trade && !trade_exit_present {
            msg.push_str("这条线路没有交易出口，名单现在不会生效。");
        } else {
            msg.push_str("下次连接时生效。");
        }
        msg
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert("changed".to_string(), serde_json::json!(changed));
        o.insert("agentsMessage".to_string(), serde_json::json!(agents_message));
    }
    v.to_string()
}

/// 改走向。**只改 lane，不动名单**：应用页那一行改完立即生效，不能顺手把名单清掉。
fn set_agents_lane(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::Value::Null);
    let value = parsed.get("Value").and_then(|v| v.as_str()).unwrap_or("");
    // 前端发的是首字母大写（`state.Agents`），命令行/测试可能传小写：大小写不敏感。
    let Some(lane) = crate::config::AgentsLane::from_value(value) else {
        return refuse(&format!("Value 只支持 Daily / Trade（收到：{value}）"));
    };
    if busy(ctx) {
        return refuse_with_code(AGENTS_BUSY_MSG, "busy");
    }
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    let changed = cfg.agents.lane != lane;
    if changed {
        cfg.agents.lane = lane;
        if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
            return refuse(&format!("保存配置失败：{e}"));
        }
        if let Some(line_path) = cfg.current_engine_path(&ctx.root) {
            let _ = crate::engine_config::apply_rules_to_file(&line_path, &cfg.split, &cfg.agents);
        }
    }
    let message = if changed {
        format!("AI 工具已改为：{}", lane.label())
    } else {
        format!("AI 工具已经是：{}", lane.label())
    };
    serde_json::json!({
        "ok": true,
        "changed": changed,
        "agentsLane": lane.id(),
        "agentsMessage": message,
    })
    .to_string()
}


/// 连接结束后要不要丢弃运行时引擎配置。
///
/// **口径：`runtime-engine.json` 存在 ⟺ 连接正在运行。**
/// 所以只有"没进入运行态"（连接失败）才丢；自检结论不参与判断——那是 `last-check.json` 的职责。
/// 曾经的错误口径是"自检未通过也删"，结果是"引擎还在跑、代理已接管，却查不到引擎在用哪份配置"，
/// 而排查"交易出口为什么不通"恰恰要看这个文件（D8）。
pub fn should_discard_runtime_engine(outcome: &Result<crate::connect::Outcome, String>) -> bool {
    outcome.is_err()
}

/// 连接结束后按上面那条口径收尾。CLI 与界面都调这一个函数：
/// 「判定 + 删除」各写一遍，就是上一轮 D8 里两处条件长歪的原因。
pub fn settle_runtime_engine(
    root: &std::path::Path,
    outcome: &Result<crate::connect::Outcome, String>,
) {
    if should_discard_runtime_engine(outcome) {
        crate::connect::discard_runtime_config(root);
    }
}

/// 出口成员的内部值只用于 IPC 提交和引擎配置，页面文字统一在这里投影。
/// 服务商名称与端口来自注册表和真实引擎配置，不由前端根据 tag 猜。
fn exit_member_label(
    value: &str,
    engine: &serde_json::Value,
    registry: &crate::provider::ProviderRegistry,
    line_name: &str,
) -> String {
    let outbound = engine
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|o| o.get("tag").and_then(serde_json::Value::as_str) == Some(value))
        });
    if matches!(value, "direct" | "tc-direct")
        || outbound.and_then(|o| o.get("type")).and_then(serde_json::Value::as_str) == Some("direct")
    {
        return "本地直连".to_string();
    }
    if let Some(p) = registry
        .providers
        .iter()
        .find(|p| p.daily_tag() == value || p.trade_tag() == value)
    {
        let port = if p.trade_tag() == value { p.trade_port() } else { p.daily_port };
        return format!("代理软件（{} 127.0.0.1:{}）", p.name, port);
    }
    // 注册表已被外部删掉时，仍可用引擎里的 SOCKS 事实说明这是本机代理，
    // 但不能编造客户端名；也绝不能退回显示 provider2-trade 之类的内部标签。
    if outbound.and_then(|o| o.get("type")).and_then(serde_json::Value::as_str) == Some("socks") {
        let server = outbound
            .and_then(|o| o.get("server"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("127.0.0.1");
        let port = outbound.and_then(|o| o.get("server_port")).and_then(serde_json::Value::as_u64);
        return match port {
            Some(port) => format!("代理软件（本机客户端 {server}:{port}）"),
            None => "代理软件（本机客户端）".to_string(),
        };
    }
    let name = if line_name.trim().is_empty() { "当前线路" } else { line_name.trim() };
    format!("交易线路（{name}）")
}

/// 出口信息（界面下拉用）。成员保留真实 `value`，另给非空人话 `label`。
fn exits_payload(ctx: &Ctx, cfg: &Option<crate::config::AppConfig>) -> serde_json::Value {
    let engine = cfg
        .as_ref()
        .and_then(|c| c.current_engine_path(&ctx.root))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
        });
    let info = engine.as_ref().and_then(|e| e.as_object()).and_then(crate::engine_config::read_exits);
    // 这条线路有没有交易出口：名单规则只在有它的时候生成，页面据此说明「现在不会生效」。
    // 这里复用同一份已读进来的引擎配置，不新增 I/O，也不另算一个谓词。
    let trade_exit_present = engine
        .as_ref()
        .and_then(|e| e.as_object())
        .map(crate::engine_config::has_trade_exit)
        .unwrap_or(false);
    match (info, engine) {
        (Some(i), Some(engine)) => {
            let registry = crate::provider::load(&ctx.root);
            let line_name = cfg
                .as_ref()
                .and_then(|c| c.current_line())
                .map(|l| l.name.as_str())
                .unwrap_or("");
            let members = |values: Vec<String>| {
                values
                    .into_iter()
                    .map(|value| {
                        let label = exit_member_label(&value, &engine, &registry, line_name);
                        serde_json::json!({"value": value, "label": label})
                    })
                    .collect::<Vec<_>>()
            };
            serde_json::json!({
                "exitDaily": i.daily,
                "exitTrade": i.trade,
                "exitDailyMembers": members(i.daily_members),
                "exitTradeMembers": members(i.trade_members),
                "tradeExitPresent": trade_exit_present,
            })
        }
        _ => serde_json::json!({
            "exitDaily": serde_json::Value::Null,
            "exitTrade": serde_json::Value::Null,
            "exitDailyMembers": Vec::<serde_json::Value>::new(),
            "exitTradeMembers": Vec::<serde_json::Value>::new(),
            "tradeExitPresent": trade_exit_present,
        }),
    }
}

/// `{cmd:'exit-set', which:'trade'|'daily', member:'hk'}`：校验成员 → 写配置 → 应用到线路引擎配置。
fn edit_exit(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let which = parsed
        .as_ref()
        .and_then(|v| v.get("which"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let member = parsed
        .as_ref()
        .and_then(|v| v.get("member"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if which != "trade" && which != "daily" {
        return refuse("which 只能是 trade 或 daily");
    }
    if member.is_empty() {
        return refuse("缺少要设置的出口成员（请求里没有 member）");
    }
    if busy(ctx) {
        return refuse("请先断开再改出口：连接中改动配置会让引擎实际行为与配置不一致");
    }
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    if which == "trade" {
        cfg.exits.trade = Some(member.clone());
    } else {
        cfg.exits.daily = Some(member.clone());
    }
    // 先落到线路引擎配置：成员不合法就在这里被拒（此时配置还没写，零副作用）。
    if let Some(line_path) = cfg.current_engine_path(&ctx.root) {
        if let Err(e) = crate::engine_config::apply_exits_to_file(&line_path, &cfg.exits) {
            return refuse(&e);
        }
    }
    if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
        return refuse(&format!("保存配置失败：{e}"));
    }
    let mut v = exits_payload(ctx, &Some(cfg));
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    v.to_string()
}

/// 切换线路的连接方式。语义与命令行 `--set-transport` 完全一致：**只写 config.json**，
/// 正在跑的那份运行时配置一个字节都不动（连接中允许操作，旧版的原文：
/// 「已保存下次默认方式，当前连接保持」）。
///
/// 与 CLI 同一个 `check_transport` 做前置校验：这里说能切，下次连接就必须真的能派生。
/// `auto` 是唯一的例外——它没有具体方式可派生（等于取消固定），所以不校验。
fn set_transport_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let want = parsed
        .as_ref()
        .and_then(|v| v.get("transport"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    // `auto` = 取消固定，采用这条线路**已验证**的方式（旧版的「自动」）。
    // 它没有具体方式可校验，所以下面跳过 `check_transport`：没有依据时按标准连接兜底。
    let auto = want.trim().eq_ignore_ascii_case("auto");
    let transport = crate::config::Transport::from_name(&want);
    if !auto && transport.is_none() {
        return refuse(&format!(
            "连接方式只能是 {}、{} 或 auto（收到：{want}）",
            crate::config::Transport::Udp.id(),
            crate::config::Transport::Tcp.id()
        ));
    }
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    // 目标线路：带 id 就按 id 找（界面每一行各有一个下拉），否则当前选中的那条。
    let key = parsed
        .as_ref()
        .and_then(|v| v.get("id"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    // `source:"line-action"` = 界面上的「保存连接方式」（含按记录重试）。
    // 命令行 `--set-transport` 不带这个标记：它没有线路卡片要贴反馈。
    let line_action = parsed
        .as_ref()
        .and_then(|v| v.get("source"))
        .and_then(|x| x.as_str())
        .map(|s| s.eq_ignore_ascii_case("line-action"))
        .unwrap_or(false);
    let target = if key.is_empty() {
        cfg.current_line().cloned()
    } else {
        cfg.find_line(&key).cloned()
    };
    let Some(line) = target else {
        return refuse("未配置线路，无法设置连接方式");
    };
    // 从这里起动作可以归属到一条线路：先落 `Pending` 记录。
    // 下面的每个出口都必须给它一个结论，否则页面会永远停在「保存中」。
    let tracked = if line_action {
        let profile_id = match transport {
            Some(crate::config::Transport::Tcp) => "Tcp",
            Some(crate::config::Transport::Udp) => "Udp",
            None => match line.verified_transport.unwrap_or(crate::config::Transport::Udp) {
                crate::config::Transport::Tcp => "Tcp",
                crate::config::Transport::Udp => "Udp",
            },
        };
        let requested = match transport {
            Some(crate::config::Transport::Tcp) => "tcp",
            Some(crate::config::Transport::Udp) => "udp",
            None => "auto",
        };
        let action = crate::lineaction::started(
            &line.id,
            &line.name,
            crate::lineaction::PREFERENCE,
            profile_id,
            requested,
        );
        crate::lineaction::begin(&ctx.root, action).ok()
    } else {
        None
    };
    let finish = |ok: bool, message: &str, code: &str| {
        let Some(action) = tracked.as_ref() else { return };
        let _ = crate::lineaction::finish(
            &ctx.root,
            &action.line_id,
            crate::lineaction::PREFERENCE,
            if ok {
                crate::lineaction::SUCCEEDED
            } else {
                crate::lineaction::FAILED
            },
            message,
            code,
            None,
        );
    };
    if let Some(t) = transport {
        if let Err(e) =
            crate::engine_config::check_transport(&line.engine_config_path(&ctx.root), t)
        {
            finish(false, &e, "config");
            return refuse(&e);
        }
    }
    if let Some(l) = cfg.lines.iter_mut().find(|l| l.id == line.id) {
        // `None` 就是「自动」：不动 `verified_transport`，那是这条线路的既有依据。
        l.transport = transport;
    }
    if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
        let message = format!("保存配置失败：{e}");
        finish(false, &message, "config");
        return refuse(&message);
    }
    // 记录里放旧版卡片上的那句话，页面直接显示；回包那句「下次才生效」是另一件事。
    let recorded = if auto {
        "已恢复自动选择，下次连接生效。".to_string()
    } else {
        format!(
            "已固定为{}，下次连接生效。",
            if transport == Some(crate::config::Transport::Tcp) {
                "兼容连接"
            } else {
                "标准连接"
            }
        )
    };
    finish(true, &recorded, "");
    // 回包：新的线路列表 + 一句「下次才生效」的话，页面直接显示，不必再查一次。
    // `auto` 用它自己的话：说「已保存下次默认方式」会让用户以为固定住了某个方式。
    let mut v = lines_payload(Some(&cfg));
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert(
            "message".to_string(),
            serde_json::json!(if auto {
                "已改为自动选择（采用这条线路已验证的方式）"
            } else {
                "已保存下次默认方式，当前连接保持"
            }),
        );
    }
    v.to_string()
}

/// 目标线路：带 `Id` 就按 id 找（每一条线路各有一份绑定），否则当前选中的那条。
fn line_of_command(
    cfg: Option<&crate::config::AppConfig>,
    raw: &str,
) -> Result<crate::config::LineConfig, String> {
    let key = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .as_ref()
        .and_then(|v| v.get("Id").or_else(|| v.get("id")))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let Some(cfg) = cfg else {
        return Err("找不到配置文件（config.json），请先导入线路".into());
    };
    let target = if key.is_empty() {
        cfg.current_line().cloned()
    } else {
        cfg.find_line(&key).cloned()
    };
    target.ok_or_else(|| {
        if key.is_empty() {
            "未配置线路，无法设置出口网卡".to_string()
        } else {
            format!("找不到线路「{key}」，请刷新后重试")
        }
    })
}

/// 出口网卡的投影：这台电脑有哪些网卡、这条线路指定了哪张、这次连接会不会真的绑上。
///
/// 三个值必须一起给，页面才能说清话：
/// - `Default` 空 → 本机默认出口读不到（此时「跟随默认」实际等于不绑）；
/// - `Bound` 空 → 没指定过（跟随默认），而不是「指定了一个空名字」；
/// - `Stale=true` → 指定过、但那块网卡现在不在这台电脑上，**连接会被拒绝**。
fn line_network_payload(root: &std::path::Path, line_id: &str) -> serde_json::Value {
    let interfaces = crate::autoroute::interfaces();
    let default = crate::autoroute::network_info().interface;
    let bound = crate::netbind::load(root)
        .get(line_id)
        .unwrap_or("")
        .to_string();
    let chosen = if bound.is_empty() { None } else { Some(bound.as_str()) };
    let (effective, stale) = crate::netbind::resolve(chosen, &interfaces, &default);
    serde_json::json!({
        "lineNetwork": {
            "Id": line_id,
            "Default": default,
            "Interfaces": interfaces,
            "Bound": bound,
            "Effective": effective,
            "Stale": stale.is_some(),
            "StaleName": stale.unwrap_or_default(),
        }
    })
}

/// 「出口网卡」只读预览（A 组网卡绑定）。界面一打开「连接方式与网络」就调它。
///
/// **不许写任何文件**：这一条是页面每次进页面都会发的命令，写一下就变成
/// 「看一眼就改了配置」。
fn line_network_json(ctx: &Ctx, raw: &str) -> String {
    let cfg = match crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH)) {
        Ok(cfg) => cfg.or_else(|| ctx.cfg.clone()),
        Err(e) => return refuse(&e.to_string()),
    };
    let line = match line_of_command(cfg.as_ref(), raw) {
        Ok(line) => line,
        Err(message) => return refuse(&message),
    };
    let mut out = line_network_payload(&ctx.root, &line.id);
    if let Some(o) = out.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    out.to_string()
}

/// 改这条线路的出口网卡。`Interface` 空串 = 跟随系统默认（**删掉**这条绑定）。
///
/// 非空的必须是这台电脑上**现在就有**的网卡：存一个本机不存在的名字，
/// 下次连接要么绑不上（引擎直接起不来），要么被静默忽略（走了用户没选的出口）。
/// 所以这里先核对，不对就回 `usage`——判据早于落盘，与 `set-transport` 的
/// `check_transport` 同一个位置。
///
/// 与 `set-transport` 同一套语义：**只写本机绑定表，只影响下次连接**。
/// 当前连接用的运行时配置已经是生成好的那一份，改绑定不会去动它。
fn line_network_set_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let raw_interface = parsed
        .as_ref()
        .and_then(|v| v.get("Interface"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let interface = raw_interface.trim().to_string();
    if interface.chars().count() > 128 {
        return refuse_with_code(
            &format!("网卡名过长（{} 个字符），这不是一块网卡的名字", interface.chars().count()),
            "usage",
        );
    }
    let cfg = match crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH)) {
        Ok(cfg) => cfg.or_else(|| ctx.cfg.clone()),
        Err(e) => return refuse(&e.to_string()),
    };
    let line = match line_of_command(cfg.as_ref(), raw) {
        Ok(line) => line,
        Err(message) => return refuse_with_code(&message, "usage"),
    };
    // 存的就是下拉里那串规范写法：`bind_interface` 要的正是它，
    // 大小写不同的另一个写法会让「用户看到的」与「实际绑的」不是同一个字符串。
    let mut canonical = String::new();
    if !interface.is_empty() {
        let available = crate::autoroute::interfaces();
        let Some(found) = available
            .iter()
            .find(|name| name.trim().eq_ignore_ascii_case(&interface))
        else {
            let list = if available.is_empty() {
                "（一块也没读到，请检查网络适配器）".to_string()
            } else {
                available.join("、")
            };
            return refuse_with_code(
                &format!(
                    "这台电脑上没有网卡「{interface}」。当前可用：{list}。\
                     如果只想跟随系统默认出口，请选「跟随系统默认」。"
                ),
                "usage",
            );
        };
        canonical = found.clone();
    }
    if let Err(e) = crate::netbind::set(&ctx.root, &line.id, &canonical) {
        return refuse(&e);
    }
    let mut out = line_network_payload(&ctx.root, &line.id);
    if let Some(o) = out.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
        o.insert(
            "message".to_string(),
            serde_json::json!(if canonical.is_empty() {
                "已改为跟随系统默认出口，下次连接生效，当前连接保持"
            } else {
                "已保存下次连接的出口网卡，当前连接保持"
            }),
        );
    }
    out.to_string()
}

/// 线路动作记录（A6 第二轮）：只读。`ok:true` = 记录读到了——**空列表也是成功**；
/// 只有记录文件本身坏掉才 `ok:false`（`lineActions.ReadError` 里带一句人话）。
/// 与 `delete-cleanup` 同一套三态：页面必须能区分「没有动作」与「读不出来」。
fn line_actions_json(ctx: &Ctx) -> String {
    match crate::lineaction::load(&ctx.root) {
        Ok(actions) => serde_json::json!({
            "ok": true,
            "lineActions": {
                "ReadError": "",
                "Actions": actions.iter().map(crate::lineaction::to_json).collect::<Vec<_>>(),
            }
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "ok": false,
            "error": error,
            "errorCode": "line-action",
            "lineActions": {
                "ReadError": error,
                "Actions": [],
            }
        })
        .to_string(),
    }
}

/// 核对一条 `NeedsReview` 的线路动作：**只查已有证据，不重新提交原操作**。
/// 重试是另一个动作（界面上的「重新测试 / 重试保存」），两者不能混。
///
/// 结论写回记录（`Succeeded` / `Failed`），页面下一帧就能看到同一份事实。
/// 核对本身成功、但结论是「没落地」时仍回 `ok:true`：那是核对完成，
/// 失败的是被核对的那个动作——界面要显示它的原话，而不是一句「操作失败」。
fn line_action_review_json(ctx: &Ctx, raw: &str) -> String {
    let id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            v.get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if id.is_empty() {
        return refuse_with_code("缺少要核对的线路操作 id（请求里没有 id 字段）", "usage");
    }
    let action = match crate::lineaction::load(&ctx.root) {
        Ok(actions) => actions.into_iter().find(|action| action.id == id),
        Err(error) => return refuse_with_code(&error, "record"),
    };
    let Some(action) = action else {
        return refuse_with_code("这条线路操作记录已经不在了（可能已被新的操作取代）", "missing");
    };
    if action.phase != crate::lineaction::NEEDS_REVIEW {
        return refuse_with_code("这条线路操作不需要核对：结果已经确定", "state");
    }
    let reviewed = match action.kind.as_str() {
        crate::lineaction::PREFERENCE => review_preference(ctx, &action),
        crate::lineaction::CHECK => review_check(ctx, &action),
        _ => return refuse_with_code("这条线路操作的类型不认识，无法核对", "state"),
    };
    match reviewed {
        Ok(updated) => serde_json::json!({
            "ok": true,
            "message": updated.message,
            "lineActionReview": review_to_json(&updated),
        })
        .to_string(),
        Err(error) => refuse_with_code(&error, "record"),
    }
}

fn review_to_json(action: &crate::lineaction::Action) -> serde_json::Value {
    serde_json::json!({
        "Id": action.id,
        "LineId": action.line_id,
        "Kind": action.kind,
        "Phase": action.phase,
        "Message": action.message,
        "Code": action.code,
        "NeedsReview": action.phase == crate::lineaction::NEEDS_REVIEW,
        "CanRetry": action.phase == crate::lineaction::FAILED,
        "LatencyMs": action.latency_ms,
    })
}

/// 界面长操作记录（A5/A6）：只读。`ok:true` = 记录读到了——空列表也是成功；
/// 只有记录文件本身坏掉才 `ok:false`（`operations.ReadError` 里带一句人话）。
/// 与线路动作/待清理同一套三态：页面必须能区分「没有操作」与「读不出来」。
fn operation_list_json(ctx: &Ctx) -> String {
    match crate::oprecord::load(&ctx.root) {
        Ok(records) => serde_json::json!({
            "ok": true,
            "operations": {
                "ReadError": "",
                // `Retry` 是**安全描述**，不是命令：告诉页面能不能重试、重试会做什么。
                // 记录本身仍不含命令原文（那会把带参数的请求落进日志）。
                "Records": records
                    .iter()
                    .map(|record| {
                        let mut value = crate::oprecord::to_json(record);
                        value["Retry"] = crate::oprecord::retry_plan(record);
                        value
                    })
                    .collect::<Vec<_>>(),
            }
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "ok": false,
            "error": error,
            "errorCode": "operation-record",
            "operations": {
                "ReadError": error,
                "Records": [],
            }
        })
        .to_string(),
    }
}

/// 按记录重试（A6）：只接受 `Failed` 且类型可安全重放的记录。
///
/// 记录里**没有命令原文**，所以这里不是「重放」，而是「按当前事实再做一次同类操作」：
/// 连接用当前选中的线路，断开看当前状态，诊断重新跑一遍只读检查。重试本身会写一条
/// **新的**操作记录；同类已结束记录只留最新一条（这是记录文件的既有规则），
/// 所以重试后看到的就是这一次尝试的结果。
///
/// 交易保护、部署、邀请都不在这里：它们各有自己的恢复通道，重跑会叠加副作用。
fn operation_retry_json(ctx: &Ctx, raw: &str) -> String {
    let id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| {
            value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if id.is_empty() {
        return refuse_with_code("缺少要重试的界面操作 id（请求里没有 id 字段）", "usage");
    }
    let record = match crate::oprecord::load(&ctx.root) {
        Ok(records) => records.into_iter().find(|record| record.id == id),
        Err(error) => return refuse_with_code(&error, "record"),
    };
    let Some(record) = record else {
        return refuse_with_code("这条界面操作记录已经不在了", "missing");
    };
    let plan = crate::oprecord::retry_plan(&record);
    if plan.get("CanRetry").and_then(serde_json::Value::as_bool) != Some(true) {
        let note = plan
            .get("Note")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("这条操作不能重试");
        return refuse_with_code(note, "state");
    }
    let kind = record.kind.clone();
    // 先落新记录，再真的执行：与界面长命令同一条纪律——「做了但没记录」不许发生。
    let started = match crate::oprecord::begin(&ctx.root, &kind, "ui") {
        Ok(record) => record,
        Err(error) => {
            return refuse_with_code(
                &format!("无法写入操作记录：{error}；本次重试没有开始"),
                "record",
            )
        }
    };
    let reply_text = match kind.as_str() {
        crate::oprecord::CONNECT => connect_json(ctx),
        crate::oprecord::DISCONNECT => disconnect_json(ctx),
        crate::oprecord::DIAGNOSE => diagnose_json(ctx),
        _ => {
            let message = "这条操作的类型不认识，没有重试";
            let _ = crate::oprecord::finish(
                &ctx.root,
                &started.id,
                crate::oprecord::FAILED,
                message,
                "UnsupportedRetry",
            );
            return refuse_with_code(message, "state");
        }
    };
    let reply = serde_json::from_str::<serde_json::Value>(&reply_text)
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "宿主回包不是合法 JSON"}));
    let ok = reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true);
    let text_of = |key: &str| {
        reply
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    };
    let (phase, code, message) = if ok {
        (
            crate::oprecord::SUCCEEDED,
            "",
            format!("{}完成", crate::oprecord::label(&kind)),
        )
    } else {
        let message = text_of("error");
        let message = if message.is_empty() { text_of("detail") } else { message };
        (
            crate::oprecord::FAILED,
            text_of("errorCode"),
            if message.is_empty() {
                "重试没有完成".to_string()
            } else {
                message.to_string()
            },
        )
    };
    if let Err(error) = crate::oprecord::finish(&ctx.root, &started.id, phase, &message, code) {
        println!("  重试的操作记录未落盘：{error}");
    }
    let mut out = reply;
    out["operationRetry"] = serde_json::json!({
        "Id": id,
        "Kind": kind,
        "RecordId": started.id,
        "Message": if ok {
            match kind.as_str() {
                crate::oprecord::CONNECT => "已重新连接",
                crate::oprecord::DISCONNECT => "已重新断开",
                crate::oprecord::DIAGNOSE => "已重新运行诊断",
                _ => "重试完成",
            }
        } else {
            ""
        },
    });
    out.to_string()
}

/// 核对一条被中断的界面长操作：**只看当前事实，不重新执行**。
///
/// 判据只有两个磁盘事实：`runtime-engine.json` 是否存在（连接是否在跑）与还原凭据
/// 是否还在（系统代理有没有留下我们的改动）。两项都答得上来时才写结论；答不上来
/// （凭据读坏）就留在 `NeedsReview`，把「为什么核不了」如实告诉用户。
///
/// 结论写回记录（`Succeeded` / `Failed`），页面下一帧看到同一份事实。核对本身成功、
/// 但结论是「上次没生效」时仍回 `ok:true`——失败的是被核对的那个操作。
fn operation_review_json(ctx: &Ctx, raw: &str) -> String {
    let id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            v.get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if id.is_empty() {
        return refuse_with_code("缺少要核对的界面操作 id（请求里没有 id 字段）", "usage");
    }
    let record = match crate::oprecord::load(&ctx.root) {
        Ok(records) => records.into_iter().find(|record| record.id == id),
        Err(error) => return refuse_with_code(&error, "record"),
    };
    let Some(record) = record else {
        return refuse_with_code("这条界面操作记录已经不在了", "missing");
    };
    if record.phase != crate::oprecord::NEEDS_REVIEW {
        return refuse_with_code("这条界面操作不需要核对：结果已经确定", "state");
    }
    let running = ctx.root.join("runtime-engine.json").exists();
    let journal = match crate::proxy::read_journal(&ctx.root.join("proxy-journal.json")) {
        Ok(journal) => journal,
        // 读不出凭据就无法判断代理有没有残留：这条记录不能算「核对完」。
        Err(error) => {
            return operation_review_stays(
                &record,
                &format!(
                    "读不出系统代理的还原凭据，无法确认上次操作有没有留下代理改动：{error}"
                ),
            )
        }
    };
    let proxy_left = journal.is_some();
    let (phase, message, code) = match record.kind.as_str() {
        crate::oprecord::CONNECT => {
            if running {
                (
                    crate::oprecord::SUCCEEDED,
                    "上次连接已经生效：当前连接正在运行。".to_string(),
                    "ReviewedApplied",
                )
            } else if proxy_left {
                return operation_review_stays(
                    &record,
                    "上次连接没有跑完，但留下了系统代理改动（还原凭据还在）；请先在维护区还原系统代理，再重新连接。",
                );
            } else {
                (
                    crate::oprecord::FAILED,
                    "上次连接没有生效：现在没有连接，也没有残留的代理改动。可以重新连接。"
                        .to_string(),
                    "ReviewedNotApplied",
                )
            }
        }
        crate::oprecord::DISCONNECT => {
            if !running && !proxy_left {
                (
                    crate::oprecord::SUCCEEDED,
                    "上次断开已经完成：当前没有连接，系统代理也已还原。".to_string(),
                    "ReviewedApplied",
                )
            } else if !running {
                return operation_review_stays(
                    &record,
                    "上次断开没有跑完：引擎已经不在运行，但系统代理改动还在（还原凭据还在）；请先在维护区还原系统代理。",
                );
            } else {
                (
                    crate::oprecord::FAILED,
                    "上次断开没有完成：当前连接还在运行。可以再断开一次。".to_string(),
                    "ReviewedNotApplied",
                )
            }
        }
        // 只读操作没有需要核对的后果。走到这里说明记录是旧版本或人工改过：
        // 结论仍然是「没有拿到结果」，可以放心重跑。
        crate::oprecord::DIAGNOSE => (
            crate::oprecord::FAILED,
            "上次诊断没有拿到结果（只读操作，不会改动系统）；可以重新运行诊断。".to_string(),
            "InterruptedReadOnly",
        ),
        _ => return refuse_with_code("这条界面操作的类型不认识，无法核对", "state"),
    };
    match crate::oprecord::settle(&ctx.root, &record.id, phase, &message, code) {
        Ok(updated) => serde_json::json!({
            "ok": true,
            "message": updated.message,
            "operationReview": operation_review_to_json(&updated),
        })
        .to_string(),
        Err(error) => refuse_with_code(&error, "record"),
    }
}

/// 核对完成了，但结论只能是「仍然不知道」：记录保持 `NeedsReview`，不写盘。
fn operation_review_stays(record: &crate::oprecord::Record, message: &str) -> String {
    serde_json::json!({
        "ok": true,
        "message": message,
        "operationReview": {
            "Id": record.id,
            "Kind": record.kind,
            "Phase": record.phase,
            "Message": message,
            "Code": record.code,
            "NeedsReview": true,
            "Origin": record.origin,
        }
    })
    .to_string()
}

fn operation_review_to_json(record: &crate::oprecord::Record) -> serde_json::Value {
    serde_json::json!({
        "Id": record.id,
        "Kind": record.kind,
        "Phase": record.phase,
        "Message": record.message,
        "Code": record.code,
        "NeedsReview": record.phase == crate::oprecord::NEEDS_REVIEW,
        "Origin": record.origin,
    })
}

/// 保存连接方式的核对：配置里现在存的是不是当初请求的那一档。
/// `None`（自动）与「请求 auto」才算对上——「没固定」不等于「保存成了标准」。
fn review_preference(
    ctx: &Ctx,
    action: &crate::lineaction::Action,
) -> Result<crate::lineaction::Action, String> {
    let root = &ctx.root;
    let finish = |phase: &str, message: &str, code: &str| {
        crate::lineaction::update_phase(root, &action.id, phase, message, code, None)
    };
    let cfg = match crate::config::load(&root.join(crate::config::DEFAULT_PATH)) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return finish(
                crate::lineaction::FAILED,
                "找不到配置文件，无法确认上次保存是否生效；可以重试保存。",
                "ConfigMissing",
            )
        }
        Err(error) => {
            return finish(
                crate::lineaction::FAILED,
                &format!("读不出配置，无法确认上次保存是否生效：{error}"),
                "ConfigUnreadable",
            )
        }
    };
    let Some(line) = cfg.find_line(&action.line_id) else {
        return finish(
            crate::lineaction::FAILED,
            "这条线路已不在配置里，无法确认上次保存的结果。",
            "LineMissing",
        );
    };
    let (matches, actual) = match line.transport {
        None => (action.requested == "auto", "自动选择"),
        Some(crate::config::Transport::Udp) => (action.requested == "udp", "标准连接"),
        Some(crate::config::Transport::Tcp) => (action.requested == "tcp", "兼容连接"),
    };
    if matches {
        let message = if actual == "自动选择" {
            "已核对：这条线路现在采用自动选择。".to_string()
        } else {
            format!("已核对：连接方式已固定为{actual}。")
        };
        finish(crate::lineaction::SUCCEEDED, &message, "")
    } else {
        finish(
            crate::lineaction::FAILED,
            &format!("上次保存没有落地：这条线路现在仍是{actual}。可以重试保存。"),
            "NotApplied",
        )
    }
}

/// 测速的核对：只看这次动作的时间窗里有没有留下采样，**不重新发请求**。
///
/// 窗口只开 15 秒：一次界面测速的请求超时是 2 秒，动作自己的采样必然落在开始后
/// 几秒内；窗口再宽就会把「动作没跑成之后」的自动补测算到这次动作头上。
fn review_check(
    ctx: &Ctx,
    action: &crate::lineaction::Action,
) -> Result<crate::lineaction::Action, String> {
    let root = &ctx.root;
    let finish = |phase: &str, message: &str, code: &str, ms: Option<u64>| {
        crate::lineaction::update_phase(root, &action.id, phase, message, code, ms)
    };
    if action.at_unix <= 0 {
        return finish(
            crate::lineaction::FAILED,
            "记录里没有开始时间，无法核对上次测速；可以重新测速。",
            "NoWindow",
            None,
        );
    }
    let profile = if action.profile_id.eq_ignore_ascii_case("tcp") {
        "兼容"
    } else {
        "标准"
    };
    let samples = crate::perf::load(
        root,
        &action.line_id,
        action.at_unix.saturating_sub(2),
        action.at_unix.saturating_add(15),
    );
    let mine = samples
        .iter()
        .filter(|sample| sample.profile.is_empty() || sample.profile == profile);
    if let Some(sample) = mine.clone().find(|sample| sample.ms.is_some()) {
        let ms = sample.ms.unwrap_or(0);
        return finish(
            crate::lineaction::SUCCEEDED,
            &format!("已确认上次测速完成：{ms} ms。"),
            "",
            sample.ms,
        );
    }
    if let Some(sample) = mine.into_iter().find(|sample| !sample.reason.is_empty()) {
        return finish(
            crate::lineaction::FAILED,
            &format!("上次测速没有通过（{}）；可以重新测速。", sample.reason),
            &sample.reason,
            None,
        );
    }
    finish(
        crate::lineaction::FAILED,
        "上次测速没有留下结果，测量可能还没开始程序就退出了；可以重新测速。",
        "NoResult",
        None,
    )
}

/// `use-compatible` 的统一回包。`saved / reconnected / verified` 分别描述三个事实，
/// 不能用最外层的 ok 把部分完成压成“都成功了”或“什么都没发生”。
fn compatible_reply(
    stage: &str,
    saved: bool,
    reconnected: bool,
    verified: bool,
    message: &str,
    ok: bool,
) -> String {
    let mut out = serde_json::json!({
        "ok": ok,
        "message": message,
        "compatibleResult": {
            "stage": stage,
            "saved": saved,
            "reconnected": reconnected,
            "verified": verified,
            "message": message,
        }
    });
    if !ok {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("error".to_string(), serde_json::json!(message));
        }
    }
    out.to_string()
}

fn reply_error(reply: &serde_json::Value) -> String {
    reply
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("命令没有返回可读错误")
        .to_string()
}

/// 把“也许可以试试兼容连接”变成一个真实的复合事务。
///
/// 资格判定与提示共用 `transport_alternative_hint`，不满足时连配置都不写。事务严格按
/// 保存 TCP 偏好 → 断开 → 连接 → 核验运行时配置执行；任何失败都停在实际阶段，既不自动
/// 回退 UDP，也不把空步骤的幂等 connect 冒充成一次重连。
fn use_compatible_json(ctx: &Ctx) -> String {
    let cfg = live_cfg(ctx);
    let check = crate::selfcheck::load(&ctx.root);
    let eligible = check
        .as_ref()
        .and_then(|c| crate::selfcheck::transport_alternative_hint(cfg.as_ref(), &ctx.root, c))
        .is_some();
    if !eligible {
        return compatible_reply(
            "eligibility",
            false,
            false,
            false,
            "只有当前线路自检未通过、仍选择标准连接且兼容连接参数可用时，才能改用兼容连接并重连",
            false,
        );
    }

    let saved_reply = serde_json::from_str::<serde_json::Value>(&set_transport_json(
        ctx,
        r#"{"cmd":"set-transport","transport":"tcp"}"#,
    ))
    .unwrap_or_else(|e| serde_json::json!({"ok": false, "error": format!("保存回包无法解析：{e}")}));
    if saved_reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = format!("保存兼容连接偏好失败：{}", reply_error(&saved_reply));
        return compatible_reply("save", false, false, false, &message, false);
    }
    // 不以“保存函数回了 ok”代替落盘事实；当前选中线路必须真的读到 tcp。
    let saved = crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH))
        .ok()
        .flatten()
        .and_then(|c| c.current_line().map(|l| l.effective_transport()))
        == Some(crate::config::Transport::Tcp);
    if !saved {
        return compatible_reply(
            "save",
            false,
            false,
            false,
            "保存兼容连接偏好后未能在磁盘配置中核验，已停止，未执行断开或重连",
            false,
        );
    }

    let disconnected = serde_json::from_str::<serde_json::Value>(&disconnect_json(ctx))
        .unwrap_or_else(|e| serde_json::json!({"ok": false, "error": format!("断开回包无法解析：{e}")}));
    if disconnected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = format!("兼容连接偏好已保存，但断开失败：{}", reply_error(&disconnected));
        return compatible_reply("disconnect", true, false, false, &message, false);
    }

    let connected = serde_json::from_str::<serde_json::Value>(&connect_json(ctx))
        .unwrap_or_else(|e| serde_json::json!({"ok": false, "error": format!("连接回包无法解析：{e}")}));
    if connected.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = format!("兼容连接偏好已保存，但重新连接失败：{}", reply_error(&connected));
        return compatible_reply("connect", true, false, false, &message, false);
    }
    let has_actions = connected
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .map(|steps| !steps.is_empty())
        .unwrap_or(false);
    if !has_actions {
        return compatible_reply(
            "connect",
            true,
            false,
            false,
            "连接命令没有执行任何动作，不能把幂等回包冒充为已重连",
            false,
        );
    }

    // 到这里才确认发生了真实重连；但“起来了”与“确实按兼容连接起来”仍是两个事实。
    if crate::engine_config::actual_transport(&ctx.root.join("runtime-engine.json"))
        != Some(crate::config::Transport::Tcp)
    {
        return compatible_reply(
            "verify",
            true,
            true,
            false,
            "已完成断开和重新连接，但新运行时配置未能核验为兼容连接；未自动回退标准连接",
            false,
        );
    }
    compatible_reply(
        "done",
        true,
        true,
        true,
        "已保存兼容连接偏好，完成真实重连，并核验当前运行时为兼容连接",
        true,
    )
}

struct ProviderReadiness {
    state: &'static str,
    role: Option<&'static str>,
    reason: String,
}

fn provider_socks_issue(
    engine: &serde_json::Value,
    tag: &str,
    port: u16,
    role: &str,
) -> Option<String> {
    let outbounds = engine.get("outbounds").and_then(serde_json::Value::as_array);
    let Some(outbound) = outbounds
        .and_then(|items| items.iter().find(|o| o.get("tag").and_then(|t| t.as_str()) == Some(tag)))
    else {
        return Some(format!("当前线路没有这条服务商的{role}入口"));
    };
    if outbound.get("type").and_then(|t| t.as_str()) != Some("socks")
        || outbound.get("server").and_then(|s| s.as_str()) != Some("127.0.0.1")
    {
        return Some(format!("当前线路的{role}入口不是本机 SOCKS"));
    }
    if outbound.get("server_port").and_then(|p| p.as_u64()) != Some(port as u64) {
        return Some(format!("当前线路的{role}入口端口与登记不一致（登记 {port}）"));
    }
    None
}

fn provider_readiness(
    p: &crate::provider::Provider,
    engine: Option<&serde_json::Value>,
    exits: Option<&crate::engine_config::ExitInfo>,
    engine_error: Option<&str>,
) -> ProviderReadiness {
    let unavailable = |reason: String| ProviderReadiness {
        state: "unavailable",
        role: None,
        reason,
    };
    let Some(engine) = engine else {
        return unavailable(engine_error.unwrap_or("当前线路配置不可用").to_string());
    };
    let Some(exits) = exits else {
        return unavailable("当前线路缺少日常出口或交易出口选择器".to_string());
    };

    let daily_tag = p.daily_tag();
    let trade_tag = p.trade_tag();
    let daily_port = p.daily_port;
    let trade_port = p.trade_port();
    let daily_issue = provider_socks_issue(engine, &daily_tag, daily_port, "日常");
    let trade_issue = provider_socks_issue(engine, &trade_tag, trade_port, "交易");
    let daily_member = exits.daily_members.iter().any(|x| x == &daily_tag);
    let trade_member = exits.trade_members.iter().any(|x| x == &trade_tag);
    let daily_ready = daily_issue.is_none() && daily_member;
    let trade_ready = trade_issue.is_none() && trade_member;
    let daily_hit = daily_ready && exits.daily == daily_tag;
    let trade_hit = trade_ready && exits.trade == trade_tag;

    if daily_hit && trade_hit {
        ProviderReadiness {
            state: "effective",
            role: Some("daily+trade"),
            reason: "日常和交易出口都已指向它".to_string(),
        }
    } else if daily_hit {
        ProviderReadiness {
            state: "effective",
            role: Some("daily"),
            reason: "日常出口已指向它；交易出口没有使用它".to_string(),
        }
    } else if trade_hit {
        ProviderReadiness {
            state: "effective",
            role: Some("trade"),
            reason: "交易出口已指向它；日常上网不经过它".to_string(),
        }
    } else if daily_ready {
        ProviderReadiness {
            state: "pending",
            role: None,
            reason: "当前线路已接入；日常出口和交易出口都还没有选它".to_string(),
        }
    } else if trade_ready {
        ProviderReadiness {
            state: "pending",
            role: None,
            reason: "当前线路已有交易入口；日常出口和交易出口都还没有选它".to_string(),
        }
    } else {
        let reason = daily_issue
            .or_else(|| {
                trade_issue.map(|e| format!("日常入口可用，但{e}"))
            })
            .or_else(|| {
                if !daily_member {
                    Some("当前线路的日常出口选项里没有这条服务商".to_string())
                } else {
                    Some("当前线路的交易出口选项里没有这条服务商".to_string())
                }
            })
            .unwrap_or_else(|| "当前线路没有可用的服务商入口".to_string());
        unavailable(reason)
    }
}

/// 服务商列表载荷（界面卡片；`--providers` 是它的命令行形态）。
///
/// `entryNote` 说明这条服务商现在实际走哪个入口（TradeChannel 管理的独立 listener / 客户端
/// 混合端口 / BatVPN 的 SOCKS 入站），文案来自 `provider::entry_note` 一处。
/// `effectiveState` 只按当前线路的真实引擎配置与出口 selector 判定，不猜测客户端是否在线。
pub fn providers_payload(root: &std::path::Path) -> serde_json::Value {
    let reg = crate::provider::load(root);
    let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten();
    let engine_path = cfg.as_ref().and_then(|c| c.current_engine_path(root));
    let (engine, engine_error): (Option<serde_json::Value>, Option<String>) = match engine_path {
        None => (None, Some("尚未配置当前线路".to_string())),
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<serde_json::Value>(
                text.strip_prefix('\u{feff}').unwrap_or(&text),
            ) {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(format!("当前线路的引擎配置不可读：{e}"))),
            },
            Err(e) => (None, Some(format!("当前线路的引擎配置不可读：{e}"))),
        },
    };
    let exits = engine
        .as_ref()
        .and_then(|e| e.as_object())
        .and_then(crate::engine_config::read_exits);

    let list: Vec<serde_json::Value> = reg
        .providers
        .iter()
        .map(|p| {
            let readiness = provider_readiness(
                p,
                engine.as_ref(),
                exits.as_ref(),
                engine_error.as_deref(),
            );
            serde_json::json!({
                "slot": p.slot,
                "name": p.name,
                "kind": p.kind,
                "directory": p.directory,
                "dailyPort": p.daily_port,
                "tradePort": p.trade_port(),
                "domains": p.bootstrap_domains,
                "dailyTag": p.daily_tag(),
                "tradeTag": p.trade_tag(),
                "entryNote": crate::provider::entry_note(p),
                "effectiveState": readiness.state,
                "effectiveRole": readiness.role,
                "effectiveReason": readiness.reason,
            })
        })
        .collect();
    let entry = reg.providers.first().map(crate::provider::entry_note).unwrap_or_default();
    serde_json::json!({ "providers": list, "entryNote": entry })
}

/// 操作记录（`--history` 的管道形态）：只读，新 → 旧。
/// 一行记录就是一个对象：`{ts, action, ok, detail}`，字段与文件里的一致，界面不再做转换。
/// `{"cmd":"history-delete","keys":["ts\u0001action\u0001detail", …]}`。
///
/// 只删本机这份 `logs\operations.jsonl` 里的行；键由页面按它看到的记录算出来
/// （`events::key`），宿主不重新解释「哪一条」。
fn history_delete_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let keys: Vec<String> = parsed
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        return serde_json::json!({
            "ok": false,
            "errorCode": "usage",
            "error": "没有选中任何记录。",
        })
        .to_string();
    }
    // r96：旧版的「删除所选」是**隐藏**，不是销毁审计行。
    let hidden = crate::events::hide(&ctx.root, &keys);
    serde_json::json!({ "ok": true, "historyDelete": { "deleted": hidden, "hidden": true } })
        .to_string()
}

/// `history-restore`：把隐藏的记录放回列表（键由页面按 `events::key` 算）。
fn history_restore_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let keys: Vec<String> = parsed
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        return serde_json::json!({
            "ok": false,
            "errorCode": "usage",
            "error": "没有选中任何记录。",
        })
        .to_string();
    }
    let restored = crate::events::restore(&ctx.root, &keys);
    serde_json::json!({ "ok": true, "historyRestore": { "restored": restored } }).to_string()
}

fn history_json(ctx: &Ctx) -> String {
    let hidden = crate::events::hidden_keys(&ctx.root);
    let events: Vec<serde_json::Value> = crate::events::read(&ctx.root, crate::events::READ_LIMIT)
        .into_iter()
        .map(|e| {
            let key = crate::events::key(&e.ts, &e.action, &e.detail);
            serde_json::json!({
                "ts": e.ts, "action": e.action, "ok": e.ok, "detail": e.detail,
                "src": e.src, "actor": e.actor, "obj": e.obj,
                "Key": key, "Hidden": hidden.contains(&key)
            })
        })
        .collect();
    serde_json::json!({ "ok": true, "events": events }).to_string()
}

/// 响应曲线：`{"cmd":"quality-history","id":"…","window":"ThirtyMinutes"|"Day"}`。
/// 只读采样库，不做网络探测——曲线不该因为打开抽屉就发起测量。
fn quality_history_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    let id = field("id");
    let window = field("window");
    let history = crate::perf::history(&ctx.root, &id, &window, std::time::SystemTime::now());
    serde_json::json!({ "ok": true, "qualityHistory": history }).to_string()
}

/// 首页统计卡与「线路变差」提醒：`{"cmd":"quality-summary","id":"L1","profile":"标准"}`。
/// 只读采样库；曲线与统计都不因这次读取发起任何网络探测。
/// `pair-verify`：拿邀请码去服务器读邀请并验签，**不产生任何服务器侧状态**。
///
/// 形状固定为 `{"ok":true,"pairVerify":{...}}`：失败也走 `ok:true`，把错误码与
/// 人话放在 `pairVerify` 里——这样页面能按同一种形状渲染「哪一步没成」，
/// 而不是把「网络失败」和「操作失败」混成一条。
///
/// `PairId` 原样回显请求里的值：宿主用它把回包对到具体某一轮校验，
/// 连续校验两个邀请码时 A 的回包不会落进 B 的会话（空值也照实回显，由宿主判定不匹配）。
fn pair_verify_json(raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let code = parsed.get("code").and_then(serde_json::Value::as_str).unwrap_or("");
    let device = parsed.get("device").and_then(serde_json::Value::as_str).unwrap_or("");
    let pair_id = parsed
        .get("pairId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let now = crate::model::now_epoch_secs_u64() as i64;
    let timeout = std::time::Duration::from_secs(30);
    match crate::pairing::read_invitation(code, false, timeout, now) {
        Ok((status, descriptor)) => serde_json::json!({
            "ok": true,
            "pairVerify": {
                "Code": "",
                "Message": "",
                "PairId": pair_id,
                "Status": status,
                "NodeId": descriptor.invite.get("NodeId").and_then(serde_json::Value::as_str).unwrap_or(""),
                "NodeName": descriptor.invite.get("DeviceName").and_then(serde_json::Value::as_str).unwrap_or(""),
                "Host": descriptor.public_host,
                "ExpiresAtUtc": crate::pairing::rfc3339_micros(descriptor.expires_unix),
                "DeviceName": device,
            }
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "ok": true,
            "pairVerify": {
                "Code": error.code,
                "Message": error.message,
                "PairId": pair_id,
                "Status": "",
                "NodeId": "",
                "NodeName": "",
                "Host": "",
                "ExpiresAtUtc": "",
                "DeviceName": device,
            }
        })
        .to_string(),
    }
}

/// `pair-join`：真的把邀请码用掉——提交设备申请、取回授权、生成 `client.conf` 与线路。
///
/// 与 `pair-verify` 同一个形状（失败也走 `ok:true`，错误码与人话放在 `pairJoin` 里）：
/// 页面按同一种形状渲染「哪一步没成」，而不用把「网络失败」和「操作失败」混成一条。
///
/// `PairId` 是**回显**：页面在等待期间可能取消又重新开一轮，回包必须能对上它是哪一轮的。
fn pair_join_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let text = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let code = text("code");
    let device = text("device");
    let name = text("name");
    let pair_id = text("pairId");

    let reply = |code: &str, message: &str, done: Option<&crate::pairing::join::Outcome>| {
        let mut body = serde_json::json!({
            "ok": true,
            "pairJoin": {
                "Code": code,
                "Message": message,
                "PairId": pair_id,
                "LineId": "",
                "LineName": "",
                "Compatible": false,
                "State": "",
            }
        });
        if let Some(outcome) = done {
            body["pairJoin"] = serde_json::json!({
                "Code": "",
                "Message": "",
                "PairId": pair_id,
                "LineId": outcome.line_id,
                "LineName": outcome.line_name,
                "Compatible": outcome.supports_compatible,
                "State": outcome.state,
            });
        }
        body.to_string()
    };

    // 连接中加线路会改 `selected`：还原凭据与实际引擎会对不上，先拒绝。
    // 这个判断必须在**任何网络动作之前**——否则邀请码被消费掉了才发现不能加。
    if busy(ctx) {
        return reply(
            "ConnectionBusy",
            "请先断开再添加线路：连接中改动配置会让还原凭据与实际引擎对不上。",
            None,
        );
    }
    if code.is_empty() {
        return reply("InvalidOnlineCode", "请粘贴完整的一次性邀请码。", None);
    }
    let now = crate::model::now_epoch_secs_u64() as i64;
    let timeout = std::time::Duration::from_secs(30);
    match crate::pairing::join::run_with_line_name(
        &ctx.root,
        &code,
        &device,
        Some(name.as_str()),
        false,
        now,
        timeout,
        &ctx.origin(None),
    ) {
        Ok(outcome) => reply("", "", Some(&outcome)),
        Err(error) => reply(&error.code, &error.message, None),
    }
}

/// 离线交接：校验一张完整的（签过名的）邀请。**不联网、不落盘。**
///
/// 与 `pair-verify` 的区别：那个用 TCI1 码去服务器读描述符，这个只校验手上
/// 已有的邀请 JWS。新电脑连不上 18443 时，这是唯一能拿到「服务器身份、设备名、
/// 有效期」的路。返回的指纹要和管理端显示的那一串人工核对。
fn pair_offline_inspect_json(raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let invite_text = parsed
        .get("invite")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let pair_id = parsed
        .get("pairId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let now = crate::model::now_epoch_secs_u64() as i64;
    let reply = |code: &str, message: &str, data: Option<serde_json::Value>| {
        let mut body = serde_json::json!({
            "ok": true,
            "pairOffline": {
                "Stage": "Inspect",
                "PairId": pair_id,
                "Code": code,
                "Message": message,
                "Fingerprint": "",
                "InviteId": "",
                "DeviceName": "",
                "ExpiresAtUtc": "",
                "NodeName": "",
            }
        });
        if let Some(data) = data {
            body["pairOffline"] = data;
        }
        body.to_string()
    };
    if invite_text.is_empty() {
        return reply("InvalidOfflineInvite", "请粘贴管理端复制的完整离线邀请。", None);
    }
    if invite_text.len() > 32 * 1024 {
        return reply("InvalidOfflineInvite", "离线邀请内容过长，请确认复制的是完整一份。", None);
    }
    match crate::pairing::offline::inspect(&invite_text, now) {
        Ok(inspection) => {
            let mut data = crate::pairing::offline::inspection_view(&inspection);
            data["Stage"] = serde_json::json!("Inspect");
            data["PairId"] = serde_json::json!(pair_id);
            data["Code"] = serde_json::json!("");
            data["Message"] = serde_json::json!("");
            reply("", "", Some(data))
        }
        Err(error) => reply(&error.code, &error.message, None),
    }
}

/// 离线交接第二步：在本机生成（或复用）设备申请。
///
/// 这一步只写 `identities\`：密钥、登记、申请都在本机，**不消费邀请**，
/// 也还没有任何东西能连上服务器。管理端拿到的就是 `RequestText`。
fn pair_offline_request_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let text = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let invite_text = text("invite");
    let fingerprint = text("fingerprint");
    let device = text("device");
    let pair_id = text("pairId");
    let now = crate::model::now_epoch_secs_u64() as i64;
    let reply = |code: &str, message: &str, data: Option<serde_json::Value>| {
        let mut body = serde_json::json!({
            "ok": true,
            "pairOffline": {
                "Stage": "Request",
                "PairId": pair_id,
                "Code": code,
                "Message": message,
                "EnrollmentId": "",
                "InviteId": "",
                "RequestText": "",
                "PairingCode": "",
                "DeviceName": "",
                "ExpiresAtUtc": "",
                "Resumed": false,
            }
        });
        if let Some(data) = data {
            body["pairOffline"] = data;
        }
        body.to_string()
    };
    if invite_text.is_empty() || fingerprint.is_empty() {
        return reply(
            "InvalidOfflineInvite",
            "邀请还没读取或指纹还没核对，请先回到上一步。",
            None,
        );
    }
    match crate::pairing::offline::prepare(&ctx.root, &invite_text, &fingerprint, &device, now) {
        Ok(prepared) => {
            let mut data = crate::pairing::offline::prepared_view(&prepared);
            data["Stage"] = serde_json::json!("Request");
            data["PairId"] = serde_json::json!(pair_id);
            data["Code"] = serde_json::json!("");
            data["Message"] = serde_json::json!("");
            data["RequestText"] = serde_json::json!(prepared.request_text);
            reply("", "", Some(data))
        }
        Err(error) => reply(&error.code, &error.message, None),
    }
}

/// 离线交接第三步：导入管理端交回的加密授权，生成线路。
///
/// 与 `pair-join` 的落盘部分完全同一套（`pairing::offline::complete` 调到
/// `join::finish`）；连接中拒绝的理由也一样——改配置会让还原凭据对不上。
fn pair_offline_complete_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let text = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let enrollment_id = text("enrollmentId");
    let authorization = text("authorization");
    let name = text("name");
    let pair_id = text("pairId");
    let now = crate::model::now_epoch_secs_u64() as i64;
    let reply = |code: &str, message: &str, data: Option<serde_json::Value>| {
        let mut body = serde_json::json!({
            "ok": true,
            "pairOffline": {
                "Stage": "Complete",
                "PairId": pair_id,
                "Code": code,
                "Message": message,
                "LineId": "",
                "LineName": "",
                "Compatible": false,
                "State": "",
            }
        });
        if let Some(data) = data {
            body["pairOffline"] = data;
        }
        body.to_string()
    };
    if enrollment_id.is_empty() || authorization.is_empty() {
        return reply(
            "InvalidAuthorization",
            "缺少本机申请或管理端交回的授权。",
            None,
        );
    }
    if busy(ctx) {
        return reply(
            "ConnectionBusy",
            "请先断开再完成离线加入：连接中改动配置会让还原凭据与实际引擎对不上。",
            None,
        );
    }
    match crate::pairing::offline::complete(
        &ctx.root,
        &enrollment_id,
        &authorization,
        Some(name.as_str()).filter(|value| !value.is_empty()),
        now,
        &ctx.origin(None),
    ) {
        Ok(outcome) => {
            let mut data = serde_json::json!({
                "Stage": "Complete",
                "PairId": pair_id,
                "Code": "",
                "Message": "",
                "LineId": outcome.line_id,
                "LineName": outcome.line_name,
                "Compatible": outcome.supports_compatible,
                "State": outcome.state,
            });
            data["EnrollmentId"] = serde_json::json!(outcome.enrollment_id);
            reply("", "", Some(data))
        }
        Err(error) => reply(&error.code, &error.message, None),
    }
}

/// 邀请命令共用的目标解析：线路 → 服务器记录 → 凭据 → 入口。
///
/// 失败带 `(ErrorCode, ErrorMessage)`：这三种失败要分开说——「这条线路不是你自己的服务器」
/// 是选择问题、「凭据读不出来」要重新登录、「服务器写的是域名」要改记录。笼统一句
/// 「邀请失败」会让人以为是服务器坏了。
/// `servers`：线路 → 服务器的归属。只读。
///
/// 为什么要在服务器侧算：判断依据是**线路文件里出现的服务器地址**（出站的 `server`，
/// 或 WireGuard 端点 `endpoints[].peers[].address`）与服务器记录的 `host` 相等。
/// 界面拿不到线路文件（那是引擎的输入，不是页面的数据），所以由这里遍历一遍，页面只做查表。
fn servers_json(ctx: &Ctx) -> String {
    // 读不出来就如实说：吞掉错误会让界面显示「没有可邀请的线路」，
    // 而真实原因可能是凭据目录正忙——两种情况的处置完全不同。
    match server_items(ctx) {
        Ok(servers) => serde_json::json!({"ok": true, "servers": servers}).to_string(),
        Err(message) => {
            serde_json::json!({"ok": false, "servers": [], "error": message}).to_string()
        }
    }
}

/// 服务器记录 + 线路归属。**只含公开字段**（凭据在另一个文件里，永远不进回包）。
fn server_items(ctx: &Ctx) -> Result<Vec<serde_json::Value>, String> {
    let records = serverstore::list(&ctx.root).map_err(|error| error.message)?;
    // 线路 → 服务器地址的归属判据**只有一份**：`pairhost::line_hosts`。
    // 邀请那条路（`pairhost::server_for_line`）用它，服务器一览也用它——两处各写一遍
    // 就是两个结论（r105 真机上，标准线路的地址在 `endpoints[]` 里，两份判据都漏了它，
    // 于是刚部署完的标准线路「不属于任何服务器」，邀请按钮恒灰）。
    let hosts = crate::pairhost::line_hosts(&ctx.root);
    let servers: Vec<serde_json::Value> = records
        .iter()
        .map(|record| {
            let host = record.host.trim().to_ascii_lowercase();
            let line_ids: Vec<&String> = {
                // 同一条线路可能既在出站、又在端点里写了同一个地址（兼容线路就有两处），
                // 去重时按 id 收一次；用 BTreeSet 顺带给出稳定顺序，页面不会两帧排序不同。
                let mut seen = std::collections::BTreeSet::new();
                hosts
                    .iter()
                    .filter(|(_, address)| *address == host)
                    .filter(|(id, _)| seen.insert(id.as_str()))
                    .map(|(id, _)| id)
                    .collect()
            };
            serde_json::json!({
                "Id": record.id,
                "Name": record.name,
                "Host": record.host,
                // 公开记录里本来就有的事实：给「身份查看」用，不含密码。
                "Port": record.port,
                "User": record.user,
                "Fingerprint": record.fingerprint,
                "CreatedAtUtc": record.created_at,
                "UpdatedAtUtc": record.updated_at,
                // 空数组 = 这台服务器还没有线路用到它（例如刚部署完还没接入）。
                "LineIds": line_ids,
            })
        })
        .collect();
    Ok(servers)
}

fn server_rename_refuse(message: &str, code: &str) -> String {
    serde_json::json!({"ok": false, "error": message, "errorCode": code}).to_string()
}

/// 服务器记录改名（C7）。回包**复用已登记的 `servers` 键**给出刷新后的列表，
/// 不新开白名单键——页面只认 `servers` + `message`，宿主合并不会漏。
fn server_rename_json(ctx: &Ctx, raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return server_rename_refuse("请求不是合法 JSON", "usage");
    };
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if id.is_empty() {
        return server_rename_refuse("缺少服务器记录 id（请求里没有 id 字段）", "usage");
    }
    if name.is_empty() {
        return server_rename_refuse("服务器名称不能为空", "usage");
    }
    if name.chars().count() > 120 {
        return server_rename_refuse("服务器名称最多 120 个字", "usage");
    }
    if name.chars().any(char::is_control) {
        return server_rename_refuse("服务器名称不能包含换行、制表符等控制字符", "usage");
    }
    let now = crate::model::now_epoch_secs_u64() as i64;
    match serverstore::rename(&ctx.root, &id, &name, now) {
        Ok(record) => {
            let mut reply = serde_json::json!({
                "ok": true,
                "message": format!("已改名为「{}」", record.name),
            });
            // 列表读不出来不能把「改名已成功」说成失败：不给 `servers` 键，
            // 页面保留原列表，只是名字要等下一次刷新。
            if let Ok(servers) = server_items(ctx) {
                reply["servers"] = serde_json::json!(servers);
            }
            reply.to_string()
        }
        Err(error) => {
            let code = match error.code.as_str() {
                "ServerWriteFailed" => "environment",
                _ => "config",
            };
            server_rename_refuse(&error.message, code)
        }
    }
}

fn invite_target(
    ctx: &Ctx,
    raw: &str,
) -> Result<
    (
        serverstore::ServerRecord,
        crate::credential::Credential,
        String,
    ),
    (String, String),
> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let line_id = parsed
        .get("line")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let records = serverstore::list(&ctx.root)
        .map_err(|error| ("InviteUnavailable".to_string(), error.message))?;
    let record = match pairhost::server_for_line(&ctx.root, &line_id, &records) {
        Some(record) => record.clone(),
        // 线路文件里没有可直接比对的地址（还没生成、或被改过）时退回名称匹配——
        // 与「服务器与设备」用同一条判定，避免同一个页面说两套话。
        None => line_server(ctx, &line_id)
            .map(|server| server.record)
            .map_err(|message| ("InviteNeedsServer".to_string(), message))?,
    };
    let host = record.host.trim().to_string();
    let canonical = host
        .parse::<std::net::Ipv4Addr>()
        .map(|address| address.to_string())
        .unwrap_or_default();
    if canonical != host {
        return Err((
            "InviteNeedsIPv4".into(),
            format!("邀请码里的入口必须是 IPv4 地址，服务器记录里写的是 {host}。"),
        ));
    }
    let credential = serverstore::credential(&ctx.root, &record)
        .map_err(|error| ("InviteCredentialMissing".to_string(), error.message))?
        // 信封本身是好的、里面的私钥却坏了：同一句「凭据不可用」，别把解析细节
        // 抛给一个只想发邀请码的人。
        .into_credential()
        .map_err(|message| ("InviteCredentialMissing".to_string(), message))?;
    Ok((record, credential, format!("{host}:18443")))
}

fn fault_code(fault: &pairhost::Fault) -> String {
    match fault.code {
        crate::exit::NETWORK => "InviteNetwork",
        crate::exit::CONFLICT => "InviteConflict",
        crate::exit::ENVIRONMENT => "InviteUnavailable",
        crate::exit::CONFIG => "InviteNeedsSetup",
        _ => "InviteFailed",
    }
    .to_string()
}

/// 四条邀请命令统一成 `{ok:true, invite:{Section, Data}}`。
///
/// 失败也走 `ok:true`（错误码在人话字段里）：界面按同一种形状渲染「哪一步没成」，
/// 而不是把「网络不通」和「这台服务器不能邀请」混成一条通用提示。
fn invite_reply(section: &str, result: Result<serde_json::Value, (String, String)>) -> String {
    let payload = match result {
        Ok(data) => data,
        Err((code, message)) => serde_json::json!({"ErrorCode": code, "ErrorMessage": message}),
    };
    serde_json::json!({"ok": true, "invite": {"Section": section, "Data": payload}}).to_string()
}

/// `invite-init`：给这条线路的服务器装上（或确认已有）管理身份与 18443 接收服务。
fn invite_init_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Init", invite_init(ctx, raw))
}

fn invite_init(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let (record, credential, endpoint) = invite_target(ctx, raw)?;
    let interface = crate::deploy::Spec::for_record(&record.id).interface;
    let target = record.target();
    match pairhost::install(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        &interface,
        &endpoint,
    ) {
        Ok(identity) => {
            let path = pairhost::identity_path(&ctx.root, &record.id);
            pairhost::save_identity(&path, &identity)
                .map_err(|message| ("InviteUnavailable".to_string(), message))?;
            Ok(serde_json::json!({
                "ServerId": record.id,
                "ServerName": record.name,
                "Endpoint": identity.endpoint,
                "ManagementFingerprint": identity.management_fingerprint,
                "TlsSha256": identity.tls_sha256,
            }))
        }
        Err(fault) => Err((fault_code(&fault), fault.message)),
    }
}

/// `invite-create`：签一张邀请。有效期由页面给（秒），设备名由宿主给默认值。
fn invite_create_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Create", invite_create(ctx, raw))
}

fn invite_create(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let lifetime = parsed
        .get("lifetime")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1_800);
    if !(600..=86_400).contains(&lifetime) {
        return Err((
            "InviteBadLifetime".into(),
            "有效期必须是 10 分钟到 24 小时。".into(),
        ));
    }
    let device = parsed
        .get("device")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("新电脑")
        .to_string();

    let (record, credential, _endpoint) = invite_target(ctx, raw)?;
    let target = record.target();
    let path = pairhost::identity_path(&ctx.root, &record.id);
    // 身份还没装（用户直接点了「生成邀请码」）：先装一次。否则页面会停在
    // 「生成失败」，而用户并不知道自己漏掉的是「登录服务器」这一步。
    let identity = match pairhost::load_identity(&path) {
        Some(identity) => identity,
        None => {
            let setup = invite_init(ctx, raw)?;
            let _ = setup;
            pairhost::load_identity(&path).ok_or_else(|| {
                (
                    "InviteUnavailable".to_string(),
                    "邀请服务装好了，但本机没有记下它的身份。".to_string(),
                )
            })?
        }
    };
    let now = crate::model::now_epoch_secs_u64() as i64;
    match pairhost::create(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        lifetime,
        &device,
        &identity,
        now,
    ) {
        Ok(issued) => Ok(serde_json::json!({
            "ServerId": record.id,
            "Code": issued.invite.code,
            // 离线交接要交付的完整邀请（签名 JWS）。在线流程不使用它，
            // 但把两样放在同一个回包里，页面才能在「改用离线邀请」时不必再签发一次。
            "Invite": issued.invite_jws,
            "InviteId": issued.invite.invite_id,
            "ExpiresAtUtc": issued.expires_at_utc,
            "DeviceName": issued.device_name,
            "LifetimeSeconds": lifetime,
            "ManagementFingerprint": identity.management_fingerprint,
        })),
        Err(fault) => Err((fault_code(&fault), fault.message)),
    }
}

/// `invite-status`：查一张邀请现在的状态。页面「重新检查」走这一条。
fn invite_status_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Status", invite_status(ctx, raw))
}

fn invite_status(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let invite_id = parsed
        .get("inviteId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if invite_id.is_empty() {
        return Err((
            "InviteNotFound".into(),
            "没有记录这张邀请的编号，无法查询。".into(),
        ));
    }
    let (record, credential, _endpoint) = invite_target(ctx, raw)?;
    let target = record.target();
    match pairhost::status(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        &invite_id,
    ) {
        Ok(value) => Ok(serde_json::json!({
            "ServerId": record.id,
            "InviteId": invite_id,
            "State": value.get("state").and_then(serde_json::Value::as_str).unwrap_or(""),
            "DeviceName": value.get("deviceName").and_then(serde_json::Value::as_str).unwrap_or(""),
            "ExpiresAtUtc": value.get("expiresAtUtc").and_then(serde_json::Value::as_str).unwrap_or(""),
            // 消费之后才有这三项：撤设备要靠它们指认「是哪一台、占了哪个地址」。
            // 未消费时给 null，界面据此隐藏，而不是显示三行空白让人以为字段丢了。
            "DeviceId": value.get("deviceId").cloned().unwrap_or(serde_json::Value::Null),
            "ClientPublicKey": value.get("clientPublicKey").cloned().unwrap_or(serde_json::Value::Null),
            "ClientAddress": value.get("clientAddress").cloned().unwrap_or(serde_json::Value::Null),
        })),
        Err(fault) => Err((fault_code(&fault), fault.message)),
    }
}

/// `invite-cancel`：作废一张邀请。已经被用掉的不给作废（那要撤设备）。
fn invite_cancel_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Cancel", invite_cancel(ctx, raw))
}

/// `invite-authorize`：离线交接的管理端第二步——批准新电脑交回的设备申请。
///
/// 本地先验一遍申请（形状、签名、摘要），是为了把「粘贴少了半截」和
/// 「服务器拒绝」分开报；真正的身份绑定与地址分配在服务器侧，与在线
/// `/consume` 共用同一套 `authorize_invite`。
fn invite_authorize_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Authorize", invite_authorize(ctx, raw))
}

fn invite_authorize(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let request = parsed
        .get("request")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if request.is_empty() {
        return Err((
            "InviteBadRequest".into(),
            "请粘贴新电脑交回的完整申请。".into(),
        ));
    }
    if request.len() > 32 * 1024 {
        return Err((
            "InviteBadRequest".into(),
            "设备申请内容过长，请确认复制的是完整一份。".into(),
        ));
    }
    let now = crate::model::now_epoch_secs_u64() as i64;
    let payload = crate::pairing::request::verify(&request, now)
        .map_err(|error| (error.code, error.message))?;
    let inner = payload
        .get("ClientRequest")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            (
                "InviteBadRequest".to_string(),
                "设备申请里没有客户端请求。".to_string(),
            )
        })?;
    let digest = inner
        .get("RequestId")
        .and_then(serde_json::Value::as_str)
        .zip(inner.get("DeviceId").and_then(serde_json::Value::as_str))
        .zip(inner.get("CreatedAtUtc").and_then(serde_json::Value::as_str))
        .zip(inner.get("ClientPublicKey").and_then(serde_json::Value::as_str))
        .map(|(((request_id, device_id), created), public)| {
            crate::pairing::client_request::ClientRequest {
                request_id: request_id.to_string(),
                device_id: device_id.to_string(),
                created_at_utc: created.to_string(),
                client_public_key: public.to_string(),
            }
            .digest()
        })
        .transpose()
        .map_err(|error| (error.code, error.message))?
        .ok_or_else(|| {
            (
                "InviteBadRequest".to_string(),
                "设备申请缺少客户端请求字段。".to_string(),
            )
        })?;
    // 配对码规则只有一份（`pairing::pairing_code_of`）：这里以前又抄了一遍
    // `take(12).to_uppercase()`，改口径时两边会不一致。
    let pairing_code = crate::pairing::pairing_code_of(&digest);
    let device_name = payload
        .get("DeviceName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

    let (record, credential, _endpoint) = invite_target(ctx, raw)?;
    let target = record.target();
    match pairhost::authorize_request(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        &request,
    ) {
        Ok(value) => Ok(serde_json::json!({
            "ServerId": record.id,
            "InviteId": value.get("inviteId").and_then(serde_json::Value::as_str).unwrap_or(""),
            "RequestId": value.get("requestId").and_then(serde_json::Value::as_str).unwrap_or(""),
            "DeviceName": if device_name.is_empty() {
                value.get("deviceName").and_then(serde_json::Value::as_str).unwrap_or("").to_string()
            } else { device_name },
            "PairingCode": pairing_code,
            "Authorization": value.get("authorization").and_then(serde_json::Value::as_str).unwrap_or(""),
        })),
        Err(fault) => Err((fault_code(&fault), fault.message)),
    }
}

/// 18443 可达性自检（r37）。
///
/// 只回答一个问题：**另一台电脑现在能不能连上这台服务器的 18443**。用户在自己这台
/// 机器上点「生成邀请码」时，防火墙没放行是最常见的失败原因，而那种失败要等对方
/// 粘贴之后才暴露，中间还隔着一次口头沟通。
///
/// 判定分两步，因为两种失败要分开处置：
/// 1. TCP 连不上 → `Refused`（端口没开/被拒）或 `Timeout`（包被丢，多半是防火墙）；
/// 2. 连上了再走一次**带证书指纹校验**的 TLS 握手 → 指纹不符说明 18443 被别的服务占了，
///    这是「看起来通、其实不通」里最坏的一种。
///
/// 探针用的是一张**假邀请**（令牌、id 都是占位）：这里只验传输层，不碰邀请状态，
/// 所以不会消费任何东西，也不需要真实令牌。
fn invite_reachability_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Reachability", invite_reachability(ctx, raw))
}

fn invite_reachability(
    ctx: &Ctx,
    raw: &str,
) -> Result<serde_json::Value, (String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let line_id = parsed
        .get("line")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let records = serverstore::list(&ctx.root)
        .map_err(|error| ("InviteUnavailable".to_string(), error.message))?;
    let record = match pairhost::server_for_line(&ctx.root, &line_id, &records) {
        Some(record) => record.clone(),
        None => line_server(ctx, &line_id)
            .map(|server| server.record)
            .map_err(|message| ("InviteNeedsServer".to_string(), message))?,
    };
    let host = record.host.trim().to_string();
    let now = crate::provider::now_rfc3339();
    let status = |value: &str, port: u16| {
        serde_json::json!({
            "Status": value,
            "Port": port,
            "Host": host,
            "CheckedAtUtc": now,
        })
    };
    // 身份还没装：连端口号都不知道，如实说「还没准备好」，不拿 18443 去猜。
    let Some(identity) = pairhost::load_identity(&pairhost::identity_path(&ctx.root, &record.id))
    else {
        return Ok(status("NotInstalled", 18_443));
    };
    let port = identity
        .endpoint
        .rsplit_once(':')
        .and_then(|(_, tail)| tail.trim().parse::<u16>().ok())
        .unwrap_or(18_443);

    let Ok(_address) = format!("{host}:{port}").parse::<std::net::SocketAddr>() else {
        return Ok(status("Unavailable", port));
    };

    Ok(status(probe_pair_port(&host, port, &identity.tls_sha256), port))
}

/// 本地探测 18443 的传输层结论。返回与页面 `Status` 同名的一档。
///
/// 抽出来是给「自动判定」用的：`invite-preflight` 在自动重开服务前后各量一次，
/// 必须是同一段判断，否则「重开前说通、重开后说没通」会让人不知道该信哪一句。
fn probe_pair_port(host: &str, port: u16, tls_sha256: &str) -> &'static str {
    let Ok(address) = format!("{host}:{port}").parse::<std::net::SocketAddr>() else {
        return "Unavailable";
    };
    match std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(1_500)) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return "Refused",
        Err(_) => return "Timeout",
        Ok(stream) => drop(stream),
    }

    let probe = crate::pairing::Invite {
        code: String::new(),
        invite_id: "00000000-0000-0000-0000-000000000000".to_string(),
        host: host.to_string(),
        port,
        token: "probe".to_string(),
        tls_sha256: tls_sha256.to_string(),
        management_fingerprint: String::new(),
        expires_unix: 0,
    };
    match crate::pairing::http::get(&probe, std::time::Duration::from_secs(3)) {
        Ok(_) => "Reachable",
        Err(error) if error.code == "OnlineTlsPinMismatch" => "TlsMismatch",
        Err(_) => "TlsFailed",
    }
}

/// 服务器侧接收服务状态（只读，一次 SSH）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PairServiceState {
    installed: bool,
    active: bool,
    enabled: bool,
    listening: bool,
    /// `ufw status` 的首行原文（`Status: active` / `Status: inactive`）；没装 ufw = `absent`。
    ufw: String,
}

/// 读状态用的一段 shell。**不修改任何东西**：自动判定要先看清再动手，
/// 否则「重启一下」会把防火墙问题也一并掩盖成一次重启。
fn pair_service_script(port: u16) -> String {
    format!(
        "set -u\n\
         if [ -f /etc/systemd/system/tc-pair.service ]; then echo TC_UNIT=1; else echo TC_UNIT=0; fi\n\
         echo \"TC_ACTIVE=$(systemctl is-active tc-pair.service 2>/dev/null || true)\"\n\
         echo \"TC_ENABLED=$(systemctl is-enabled tc-pair.service 2>/dev/null || true)\"\n\
         if command -v ss >/dev/null 2>&1; then\n\
           if ss -ltn 2>/dev/null | grep -qE '[:.]{port}[[:space:]]'; then echo TC_LISTEN=1; else echo TC_LISTEN=0; fi\n\
         else\n\
           if command -v netstat >/dev/null 2>&1 && netstat -ltn 2>/dev/null | grep -qE '[:.]{port}[[:space:]]'; then echo TC_LISTEN=1; else echo TC_LISTEN=0; fi\n\
         fi\n\
         if command -v ufw >/dev/null 2>&1; then echo \"TC_UFW=$(ufw status 2>/dev/null | head -n 1 | tr -d '\\r')\"; else echo TC_UFW=absent; fi\n\
         echo TC_DONE=1\n"
    )
}

fn parse_pair_service(stdout: &str) -> Option<PairServiceState> {
    let mut done = false;
    let mut state = PairServiceState {
        installed: false,
        active: false,
        enabled: false,
        listening: false,
        ufw: "unknown".to_string(),
    };
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("TC_UNIT=") {
            state.installed = value == "1";
        } else if let Some(value) = line.strip_prefix("TC_ACTIVE=") {
            state.active = value == "active";
        } else if let Some(value) = line.strip_prefix("TC_ENABLED=") {
            state.enabled = matches!(value, "enabled" | "static" | "indirect");
        } else if let Some(value) = line.strip_prefix("TC_LISTEN=") {
            state.listening = value == "1";
        } else if let Some(value) = line.strip_prefix("TC_UFW=") {
            state.ufw = value.to_string();
        } else if line == "TC_DONE=1" {
            done = true;
        }
    }
    done.then_some(state)
}

fn preflight_reply(
    host: &str,
    port: u16,
    status: &str,
    verdict: &str,
    detail: &str,
    repaired: bool,
    facts: Option<&PairServiceState>,
) -> serde_json::Value {
    serde_json::json!({
        "Status": status,
        "Port": port,
        "Host": host,
        "CheckedAtUtc": crate::provider::now_rfc3339(),
        "Verdict": verdict,
        "Detail": detail,
        "Repaired": repaired,
        "Installed": facts.map(|facts| facts.installed),
        "Active": facts.map(|facts| facts.active),
        "Enabled": facts.map(|facts| facts.enabled),
        "PortListening": facts.map(|facts| facts.listening),
        "Firewall": facts.map(|facts| facts.ufw.clone()),
    })
}

/// 「重新开启接收服务」的自动判定（A8 后续）。
///
/// 以前这个按钮只会盲重装一次：防火墙没放行时，重装多少次都是同一句「连不上」。
/// 现在先量端口，再经一次 SSH 读服务状态，分成四档并只在**安全**时自动修：
/// - `NeedsInit` / `NeedsRestart`：装/重启（幂等，不改任何别人的服务）；
/// - `Firewall`：只报结论与端口，**不碰防火墙**；
/// - `TlsMismatch`：18443 被别的服务占着，重装只会把问题藏起来，不自动动。
fn invite_preflight_json(ctx: &Ctx, raw: &str) -> String {
    invite_reply("Preflight", invite_preflight(ctx, raw))
}

/// 由「端口探测结论 + 服务器侧状态」得到一档判定与一句人话。
///
/// 纯函数，不碰网络：这几档的分界线（谁该自动修、谁只能让人去改防火墙）
/// 是这块逻辑里最容易写错的地方，必须能单独测。
fn preflight_verdict(status: &str, port: u16, facts: &PairServiceState) -> (String, String) {
    if !facts.installed {
        return (
            "NeedsInit".to_string(),
            "服务器上还没装接收服务，现在自动安装。".to_string(),
        );
    }
    if !facts.active || !facts.listening {
        return (
            "NeedsRestart".to_string(),
            "接收服务已安装，但进程没有在监听端口，现在自动重启。".to_string(),
        );
    }
    if status == "TlsFailed" {
        return (
            "NeedsRestart".to_string(),
            "端口有响应但握手失败，现在自动重启接收服务。".to_string(),
        );
    }
    if status == "Timeout" || status == "Refused" {
        // `contains("active")` 会把 `Status: inactive` 也判成开着——这一条必须按前缀。
        let ufw_active = facts
            .ufw
            .trim()
            .to_ascii_lowercase()
            .starts_with("status: active");
        return if ufw_active {
            (
                "Firewall".to_string(),
                format!("服务在跑，但从这台电脑连不上 {port}；服务器防火墙开着，请在云防火墙放行 TCP {port}。"),
            )
        } else {
            (
                "Unknown".to_string(),
                format!("服务在跑，但从这台电脑连不上 {port}；请检查云服务商防火墙是否放行 TCP {port}。"),
            )
        };
    }
    (
        "Unhealthy".to_string(),
        "接收服务状态与探测结果不一致，现在自动重启。".to_string(),
    )
}

fn invite_preflight(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let (record, credential, fallback_endpoint) = invite_target(ctx, raw)?;
    let identity_path = pairhost::identity_path(&ctx.root, &record.id);
    let identity = pairhost::load_identity(&identity_path);
    let host = record.host.trim().to_string();
    let mut port = identity
        .as_ref()
        .and_then(|identity| {
            identity
                .endpoint
                .rsplit_once(':')
                .and_then(|(_, tail)| tail.trim().parse::<u16>().ok())
        })
        .unwrap_or(18_443);
    let mut status = match &identity {
        Some(identity) => probe_pair_port(&host, port, &identity.tls_sha256),
        None => "NotInstalled",
    };

    // 已能连通：不用登录服务器，直接给结论。
    if status == "Reachable" {
        return Ok(preflight_reply(
            &host,
            port,
            status,
            "Healthy",
            "接收服务正常，不需要重新开启。",
            false,
            None,
        ));
    }
    // 端口被别的服务占着：重装不会让它变好，反而会掩盖「证书不对」这条确定结论。
    if status == "TlsMismatch" {
        return Ok(preflight_reply(
            &host,
            port,
            status,
            "TlsMismatch",
            "端口上跑的不是这张邀请码对应的服务，未自动重装。请先确认端口没有被其他程序占用。",
            false,
            None,
        ));
    }

    let target = record.target();
    let facts = crate::ssh::exec(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        &pair_service_script(port),
        std::time::Duration::from_secs(20),
    )
    .ok()
    .and_then(|output| parse_pair_service(&output.stdout));

    let (mut verdict, mut detail) = match &facts {
        None => (
            "Unknown".to_string(),
            "能登录服务器，但读不到接收服务状态。".to_string(),
        ),
        Some(facts) => preflight_verdict(status, port, facts),
    };

    let mut repaired = false;
    if matches!(verdict.as_str(), "NeedsInit" | "NeedsRestart" | "Unhealthy") {
        let interface = crate::deploy::Spec::for_record(&record.id).interface;
        let endpoint = identity
            .as_ref()
            .map(|identity| identity.endpoint.clone())
            .filter(|endpoint| !endpoint.is_empty())
            .unwrap_or(fallback_endpoint);
        match pairhost::install(
            &target,
            &credential,
            Some(record.fingerprint.as_str()),
            &interface,
            &endpoint,
        ) {
            Ok(next) => {
                let _ = pairhost::save_identity(&identity_path, &next);
                port = next
                    .endpoint
                    .rsplit_once(':')
                    .and_then(|(_, tail)| tail.trim().parse::<u16>().ok())
                    .unwrap_or(port);
                status = probe_pair_port(&host, port, &next.tls_sha256);
                repaired = true;
                if status == "Reachable" {
                    verdict = "Healthy".into();
                    detail = format!("接收服务已重新开启，{port} 已能连通。");
                } else {
                    verdict = "StillDown".into();
                    detail = format!(
                        "接收服务已重启，但 {port} 仍然连不上；请在云服务器防火墙放行 TCP {port}。"
                    );
                }
            }
            Err(fault) => {
                verdict = "RepairFailed".into();
                detail = format!("自动重新开启失败：{}", fault.message);
            }
        }
    }

    Ok(preflight_reply(
        &host,
        port,
        status,
        &verdict,
        &detail,
        repaired,
        facts.as_ref(),
    ))
}

fn invite_cancel(ctx: &Ctx, raw: &str) -> Result<serde_json::Value, (String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let invite_id = parsed
        .get("inviteId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if invite_id.is_empty() {
        return Err((
            "InviteNotFound".into(),
            "没有记录这张邀请的编号，无法作废。".into(),
        ));
    }
    let (record, credential, _endpoint) = invite_target(ctx, raw)?;
    let target = record.target();
    match pairhost::cancel(
        &target,
        &credential,
        Some(record.fingerprint.as_str()),
        &invite_id,
    ) {
        Ok(value) => Ok(serde_json::json!({
            "ServerId": record.id,
            "InviteId": invite_id,
            "State": value.get("state").and_then(serde_json::Value::as_str).unwrap_or(""),
        })),
        Err(fault) => Err((fault_code(&fault), fault.message)),
    }
}

fn quality_summary_json(ctx: &Ctx, raw: &str) -> String {    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    let id = field("id");
    let profile = field("profile");
    let now = std::time::SystemTime::now();
    let mut summary = crate::perf::summary(&ctx.root, &id, &profile, now);
    // 新鲜度 75 秒与旧版一致：更旧的读数不能再当「当前响应」上屏，
    // 否则引擎停了十分钟，界面还在报十分钟前的数字。
    let fresh = crate::perf::recent(&ctx.root, &id, &profile, 1, now)
        .last()
        .map(|s| {
            let now_unix = now
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            now_unix - s.at_unix <= 75
        })
        .unwrap_or(false);
    let tail = crate::perf::recent(&ctx.root, &id, &profile, 3, now);
    let reason = if fresh { degraded_reason(&tail) } else { None };
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("Fresh".into(), serde_json::json!(fresh));
        obj.insert("Degraded".into(), serde_json::json!(reason.is_some()));
        obj.insert(
            "NotificationMessage".into(),
            serde_json::json!(reason.map(alert_message).unwrap_or("")),
        );
    }
    serde_json::json!({ "ok": true, "qualitySummary": summary }).to_string()
}

/// 连续变差的判定：最近 3 次**尝试**都差或都没读数。
///
/// 与旧版的差别写在明面上：旧版是带 5 分钟冷却的闩锁（恢复要连续两次
/// ≤350 ms），这里是一个纯滚动窗口——它不会在变好之后继续挂着，也不会在
/// 抖动时反复弹提醒。两者都会在页面上说同一句人话。
fn degraded_reason(tail: &[crate::perf::Sample]) -> Option<&'static str> {
    if tail.len() < 3 {
        return None;
    }
    let mut poor = 0;
    let mut failed = 0;
    for sample in tail {
        // 本机引擎没跑起来不是线路变差：旧版既不算坏样本也不清零计数。
        if sample.reason == "ControllerUnavailable" {
            return None;
        }
        match sample.quality() {
            "Poor" => poor += 1,
            "Unknown" => failed += 1,
            _ => return None,
        }
    }
    Some(match (poor, failed) {
        (3, _) => "ConsecutiveHighLatency",
        (_, 3) => "ConsecutiveMeasurementFailures",
        _ => "ConsecutiveDegradedSamples",
    })
}

/// 提醒文案与旧版的 `LQAlertMessage` 逐字一致：同一件事在两套界面说同一句话。
fn alert_message(reason: &str) -> &'static str {
    match reason {
        "ConsecutiveHighLatency" => "当前交易出口连续 3 次延迟较高，请检查线路；当前线路保持。",
        "ConsecutiveMeasurementFailures" => "当前交易出口连续 3 次无法取得延迟，质量未知；当前线路保持。",
        _ => "当前交易出口连续多次高延迟或测量不可用，请检查线路；当前线路保持。",
    }
}

fn providers_json(ctx: &Ctx) -> String {
    let mut v = providers_payload(&ctx.root);
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".to_string(), serde_json::json!(true));
    }
    v.to_string()
}

/// 只读发现（`--provider-discover` 的管道形态）：两个外部客户端各探一遍，**不登记**。
/// `errors` 带上"为什么没发现"——只回一个空列表等于让用户在界面上猜。
fn provider_discover_json() -> String {
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for (label, r) in [
        ("Clash Verge", crate::provider::discover_clash_verge()),
        ("BatVPN", crate::provider::discover_batvpn()),
    ] {
        match r {
            Ok(d) => found.push(serde_json::json!({
                "kind": d.kind,
                "directory": d.directory,
                "dailyPort": d.daily_port,
                "domains": d.bootstrap_domains,
                "entryNote": d.entry_note,
            })),
            Err(e) => errors.push(serde_json::json!({ "label": label, "error": e })),
        }
    }
    serde_json::json!({ "ok": true, "found": found, "errors": errors }).to_string()
}

/// 登记服务商。字段与 `--provider-add <kind> <名称> <目录> <端口> [域名]` 对齐，
/// 校验/查重/槽位/投影/落盘全在 `provider::register` 一处（与命令行同一条路径）。
fn provider_add_json(ctx: &Ctx, raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return refuse("请求不是合法 JSON");
    };
    let kind =
        crate::provider::normalize_kind(v.get("kind").and_then(|x| x.as_str()).unwrap_or(""));
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let directory =
        v.get("directory").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    // 端口：界面传数字，命令行形态是字符串——两种写法在这一处统一收口。
    let port = match v.get("dailyPort").or_else(|| v.get("port")) {
        Some(serde_json::Value::Number(n)) => {
            n.as_u64().filter(|p| (1..=65535).contains(p)).map(|p| p as u16)
        }
        Some(serde_json::Value::String(s)) => {
            s.trim().parse::<u16>().ok().filter(|p| *p > 0)
        }
        _ => None,
    };
    let Some(port) = port else {
        return refuse("端口必须是 1–65535 的数字");
    };
    let domains: Vec<String> = match v.get("domains") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Some(serde_json::Value::String(s)) => {
            s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
        }
        _ => Vec::new(),
    };
    if domains.iter().any(|d| d.contains("://")) {
        return refuse("不能填写订阅链接：这里只登记客户端已落地的本机端口与上游域名");
    }
    // 登记会改写当前线路的引擎配置（注入 socks 出站与域名直连规则），连接中拒绝。
    if busy(ctx) {
        return refuse("请先断开再登记服务商：登记会更新当前线路的引擎配置");
    }
    let Some(line_path) =
        live_cfg(ctx).as_ref().and_then(|c| c.current_engine_path(&ctx.root))
    else {
        return refuse(&format!("{}（先导入线路再登记服务商）", crate::NO_CONFIG_FOR_SETTINGS));
    };
    let input = crate::provider::RegisterInput {
        kind,
        name,
        directory,
        daily_port: port,
        bootstrap_domains: domains,
    };
    match crate::provider::register_with_origin(
        &ctx.root,
        &line_path,
        input,
        &ctx.origin(None),
    ) {
        Err(e) => refuse(&e),
        Ok(p) => {
            let mut out = providers_payload(&ctx.root);
            if let Some(o) = out.as_object_mut() {
                o.insert("ok".to_string(), serde_json::json!(true));
                o.insert("slot".to_string(), serde_json::json!(p.slot));
                // 与 CLI「已登记服务商：<名>（槽位 N）」同一句话。
                o.insert(
                    "message".to_string(),
                    serde_json::json!(format!("已登记服务商：{}（槽位 {}）", p.name, p.slot)),
                );
                // CLI 那句「设为日常出口：--exit-set daily provider」在界面里是一个按钮：
                // 把 tag 带回去，页面直接发现有的 exit-set 命令。
                o.insert("dailyTag".to_string(), serde_json::json!(p.daily_tag()));
            }
            out.to_string()
        }
    }
}

/// 删除服务商（`--provider-remove <槽位>` 的管道形态）：顺序与命令行一致——
/// 先从线路配置摘掉出站，再写注册表。
fn provider_remove_json(ctx: &Ctx, raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return refuse("请求不是合法 JSON");
    };
    let Some(slot) = v
        .get("slot")
        .and_then(|x| x.as_u64())
        .filter(|s| (1..=4).contains(s))
        .map(|s| s as u8)
    else {
        return refuse("槽位是数字 1–4");
    };
    if busy(ctx) {
        return refuse("请先断开再删除服务商");
    }
    let line_path = live_cfg(ctx).as_ref().and_then(|c| c.current_engine_path(&ctx.root));
    match crate::provider::unregister_with_origin(
        &ctx.root,
        line_path.as_deref(),
        slot,
        &ctx.origin(None),
    ) {
        Err(e) => refuse(&e),
        Ok(()) => {
            let mut out = providers_payload(&ctx.root);
            if let Some(o) = out.as_object_mut() {
                o.insert("ok".to_string(), serde_json::json!(true));
                o.insert(
                    "message".to_string(),
                    serde_json::json!(format!("已删除槽位 {slot} 的服务商")),
                );
            }
            out.to_string()
        }
    }
}

/// 节点端口诊断（`--diagnose` 的管道形态）。**只读、只探 TCP**，与命令行共用 `diagnose` 模块：
/// 同一套目标推导、同一句结论，界面上看到的就是命令行看到的。
fn diagnose_json(ctx: &Ctx) -> String {
    serde_json::json!({ "ok": true, "diagnose": diagnose_payload(ctx) }).to_string()
}

/// 诊断载荷：成功 `{ok:true,line,transport,lines,items,verdict,reachable}`，失败 `{ok:false,error}`。
/// `lines` 保留给旧页面；`items/verdict` 与 CLI 共用 `diagnose` 模块，不另写一套文案。
/// 单独包一层 `diagnose`，是为了与其它命令的 `error` 不混（页面只在诊断卡里显示它）。
fn diagnose_payload(ctx: &Ctx) -> serde_json::Value {
    let (line, plan) = match diagnose_plan(ctx) {
        Ok(v) => v,
        Err(error) => return error,
    };
    let probes = crate::diagnose::probe_all(&plan);
    // 交易保护小节：与首页/维护页**同一份** `guard::status`（判定只有一处）。
    let guard = crate::guard::status(ctx.cfg.as_ref(), &ctx.root, ctx.legacy_running);
    let mut lines = crate::diagnose::render(&plan, &probes);
    lines.extend(crate::diagnose::guard_lines(&guard));
    let mut items = crate::diagnose::items(&plan, &probes);
    items.extend(crate::diagnose::guard_items(&guard));
    serde_json::json!({
        "ok": true,
        "line": line.name,
        "transport": line.effective_transport().label(),
        "lines": lines,
        "items": items,
        "verdict": crate::diagnose::verdict(&plan, &probes),
        // 与 `--diagnose` 的退出码同义：有目标、且至少一个可达，才算"探通了"。
        "reachable": !plan.tcp.is_empty() && crate::diagnose::any_reachable(&probes),
    })
}

/// 只推导诊断计划，不做网络探测。执行与预算计算共用这一份目标列表。
fn diagnose_plan(ctx: &Ctx) -> Result<(crate::config::LineConfig, crate::diagnose::Plan), serde_json::Value> {
    let no_line = || {
        serde_json::json!({
            "ok": false,
            "error": "未配置线路，无法诊断。请先导入线路或用 --set-line。"
        })
    };
    let Some(cfg) = live_cfg(ctx) else { return Err(no_line()) };
    let Some(line) = cfg.current_line().cloned() else { return Err(no_line()) };
    let path = line.engine_config_path(&ctx.root);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        serde_json::json!({
            "ok": false,
            "error": format!("读不到线路的引擎配置（{}）：{e}", path.display())
        })
    })?;
    let obj = match serde_json::from_str::<serde_json::Value>(
        text.strip_prefix('\u{feff}').unwrap_or(&text),
    ) {
        Ok(serde_json::Value::Object(o)) => o,
        Ok(_) => {
            return Err(serde_json::json!({ "ok": false, "error": "线路的引擎配置顶层不是 JSON 对象" }))
        }
        Err(e) => {
            return Err(serde_json::json!({
                "ok": false, "error": format!("线路的引擎配置不是合法 JSON：{e}")
            }))
        }
    };
    let plan = crate::diagnose::plan(&obj, line.effective_transport());
    Ok((line, plan))
}

/// 长任务展示预算。预算是“何时给出路”，不是取消或伪造失败的截止时间。
pub fn operation_budget(raw: &str, ctx: &Ctx) -> f64 {
    match command_name(raw).as_deref() {
        // 连接前装保护、断开后重核验都可能等一次 UAC（最多 180 秒）；名单为空则完全不弹。
        Some("connect") | Some("disconnect") => {
            let has_trade_list = live_cfg(ctx)
                .map(|c| !crate::guard::trade_program_entries(&c).is_empty())
                .unwrap_or(false);
            30.0 + if has_trade_list { crate::guard::GUARD_ELEVATION_BUDGET_SECS } else { 0.0 }
        }
        // 显式交易保护动作：一次 UAC + 一次 WFP 事务 + 一次枚举读回。
        Some("guard-verify") | Some("guard-install") | Some("guard-sync")
        | Some("guard-remove") => crate::guard::GUARD_EXPLICIT_BUDGET_SECS,
        Some("restore") => 30.0,
        Some("import") | Some("use-compatible") => 60.0,
        // 补兼容连接：读不到就装（下载 + 起服务，install_transport 自己给 420 秒）。
        Some("line-add-compatible") => 480.0,
        Some("measure-latency") => 5.0,
        Some("pair-verify") => 40.0,
        // 加入比校验重得多：两次网络往返 + 3072 位密钥生成 + 解密验签 + 落两份文件。
        // 预算给足，别让「还在正常干活」的加入被页面说成卡住。
        Some("pair-join") => 60.0,
        // 离线：生成申请要造 3072 位密钥；完成要解封、验签、写线路。
        Some("pair-offline-request") | Some("pair-offline-complete") => 60.0,
        Some("invite-authorize") => 120.0,
        // 重试可能是连接：交易保护会等一次 UAC（最多 180 秒）。
        Some("operation-retry") => 30.0 + crate::guard::GUARD_ELEVATION_BUDGET_SECS,
        // 自动选路：两个候选各起一次临时引擎（每个最多约 8 秒），给足预算。
        Some("auto-route") => 90.0,
        // 连接中自动切换：断开 + 最多两个候选探测 + 重连，给足余量。
        Some("auto-reroute") => 240.0,
        // 探指纹只有一次握手。`server-setup` 不在这儿：界面路径已退役（现在只是
        // 一句 usage 引导），真正的部署走 `deployment-*` 短命令 + 引擎线程。
        Some("server-probe") => 30.0,
        // 邀请管理的第一步要上传脚本 + 生成 3072 位密钥 + 起服务，与装服务端同一量级；
        // 签发只是一次签名往返，但服务器慢时也不该被说成卡住。
        Some("invite-init") => 300.0,
        Some("invite-create") => 120.0,
        Some("invite-status") => 60.0,
        Some("invite-cancel") => 60.0,
        Some("invite-reachability") => 30.0,
        // 自动判定：一次本地探测 + 一次 SSH 读状态；若需要修复，内部还会完整装一次
        // （上传脚本 + 可能生成 3072 位密钥 + 重启服务），与 `invite-init` 同一量级。
        Some("invite-preflight") => 300.0,
        Some("server-devices") => 40.0,
        // 改名多一次推脚本 + 写名称文件；服务器慢时别让它被说成卡住。
        Some("server-device-rename") => 60.0,
        Some("server-device-forget") => 60.0,
        // 撤销只要一次 SSH 往返（改配置 + syncconf），但服务器慢时不至于让人以为卡死。
        Some("server-revoke") => 40.0,
        // 预览一次 SSH；卸载是停服务 + 改配置 + 删文件，给足预算。
        Some("server-uninstall-preview") => 60.0,
        Some("server-uninstall") => 120.0,
        Some("diagnose") => diagnose_plan(ctx)
            .map(|(_, plan)| plan.tcp.len() as f64 * 2.5 + 5.0)
            .unwrap_or(5.0),
        _ => 0.0,
    }
}

/// 指定引擎程序：界面「选择引擎程序」与脚本都走这里。
///
/// 三条纪律：
/// 1. **真的跑一次** `<path> version`，只认 sing-box 自己报的版本：`.exe` 后缀什么都不证明，
///    随手挑一个别的程序要等连接时才发现（那时报的是引擎启动失败，用户看不懂）；
/// 2. **验过了才写** `config.json`，走既有的操作记录（`ctx.origin`）——不许静默改配置；
/// 3. 连接中拒绝：换引擎会让还原凭据与实际引擎对不上（与切换接管方式同一个理由）。
fn set_engine_json(ctx: &Ctx, raw: &str) -> String {
    set_engine_json_in(ctx, raw, &probe_engine_binary)
}

/// 可测的核：探测动作由调用方注入，单测不必真的准备一份 sing-box。
fn set_engine_json_in(
    ctx: &Ctx,
    raw: &str,
    probe: &dyn Fn(&std::path::Path) -> Result<String, String>,
) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let path = parsed
        .as_ref()
        .and_then(|v| v.get("path"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    engine_reply(apply_engine_choice(ctx, &path, probe))
}

/// 把「用户挑中的那个 exe」验一遍并写进配置。
///
/// 返回 `Ok((binary, version))` 或一句人话；界面选择器与 `set-engine` 命令共用这一份，
/// 不然「对话框里能选通、脚本里报不可用」会变成两套判据。
pub(crate) fn apply_engine_choice(
    ctx: &Ctx,
    path: &str,
    probe: &dyn Fn(&std::path::Path) -> Result<String, String>,
) -> Result<(String, String), String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("缺少引擎程序路径（请选择 sing-box.exe）".to_string());
    }
    if busy(ctx) {
        return Err("请先断开再更换引擎程序：连接中换引擎会让还原凭据与实际引擎对不上".to_string());
    }
    let file = std::path::PathBuf::from(path);
    if !file.exists() {
        return Err(format!("找不到引擎程序：{path}"));
    }
    if !file.is_file() {
        return Err(format!("引擎程序必须是一个文件，不能是目录：{path}"));
    }
    let is_exe = file
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("exe"))
        .unwrap_or(false);
    if !is_exe {
        return Err(format!("引擎程序必须是 .exe 文件：{path}"));
    }
    let version = probe(&file)?;

    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return Err("找不到配置文件（config.json），请先加入或导入一条线路".to_string())
        }
        Err(e) => return Err(format!("读取配置失败：{e}")),
    };
    let binary = path.to_string();
    let unchanged = cfg
        .engine
        .as_ref()
        .map(|e| e.binary.trim() == binary.as_str())
        .unwrap_or(false);
    if !unchanged {
        cfg.engine = Some(crate::config::EngineSettings { binary: binary.clone() });
        crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(Some("engine")))
            .map_err(|e| format!("保存引擎设置失败：{e}"))?;
    }
    Ok((binary, version))
}

fn engine_reply(result: Result<(String, String), String>) -> String {
    match result {
        Ok((binary, version)) => serde_json::json!({
            "ok": true,
            "message": format!("已选用引擎：{version}"),
            "engine": { "binary": binary, "version": version },
        })
        .to_string(),
        Err(message) => refuse(&message),
    }
}

/// 跑一次 `<path> version`，要求退出码为 0 且输出里出现 `sing-box`。
///
/// 为什么要看输出而不是只看退出码：很多程序对不认识的参数照样返回 0。
/// 为什么自己轮询 `try_wait` 而不是 `output()`：用户可能随手挑一个 GUI 程序，
/// 那会一直不退出——直接用 `output()` 会把界面线程卡死。
pub(crate) fn probe_engine_binary(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let program = crate::engine::checked_engine_program(path)?;
    // Hold the same shared registration through real version execution/wait.
    let _runtime_occupancy = crate::runtime_occupancy::admit()?;
    let mut child = std::process::Command::new(&program)
        .arg("version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("这个程序跑不起来（{}）：{e}", path.display()))?;
    // 5 秒足够一个正常引擎打印版本号；超时就杀掉，别让界面一直等。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("这个程序没有响应 `version`（{path:?}），不是可用的引擎"));
            }
            Err(e) => return Err(format!("探测引擎失败（{}）：{e}", path.display())),
        }
    };
    let mut text = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut text);
    }
    let mut err_text = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut err_text);
    }
    let combined = format!("{text}{err_text}");
    if !status.success() {
        return Err(format!(
            "这个程序不接受 `version`（退出码 {:?}），不是可用的引擎",
            status.code()
        ));
    }
    if !combined.to_ascii_lowercase().contains("sing-box") {
        return Err(format!(
            "这个程序不是 sing-box（`version` 没有报出版本号）：{}",
            path.display()
        ));
    }
    // 只留第一行：版本号那一行才是「已选用什么」的证据。
    let line = combined.lines().next().unwrap_or("").trim().to_string();
    Ok(if line.is_empty() { "sing-box（版本未知）".to_string() } else { line })
}


/// 切换接管方式（代理 / TUN）。只写 `config.json` 的 `mode`——**只影响下一次连接**，
/// 当前连接不动（与 `--set-transport` 同一套语义）。真正的切换发生在连接前：
/// `engine_config::apply_mode` 按这个值拼装/裁剪入站（入站是导入时烤死的，光写配置不生效）。
///
/// 切 TUN 前先确认线路配置里真有 TUN 入站：没有就当场拒绝并指路，不留给引擎去报天书。
fn set_mode_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let want = parsed
        .as_ref()
        .and_then(|v| v.get("mode"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    // 严格解析：认不出就拒绝（`Mode::from_name` 会把乱填的当代理，那是静默改用户的设置）
    let mode = match want.as_str() {
        "proxy" => crate::config::Mode::Proxy,
        "tun" => crate::config::Mode::Tun,
        _ => {
            return refuse(&format!(
                "接管方式只能是 {} 或 {}（收到：{want}）",
                crate::config::Mode::Proxy.label(),
                crate::config::Mode::Tun.label()
            ))
        }
    };
    // 连接中拒绝：切换只影响下一次连接，连接时改它只会让用户以为"已经切了"。
    // （与 `--set-transport` 不同——那是"换条路自救"，必须在连着时也能点；接管方式是重启级操作。）
    if busy(ctx) {
        return refuse("请先断开再切换接管方式：切换只影响下一次连接");
    }
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let mut cfg = match crate::config::load(&cfg_path) {
        Ok(Some(c)) => c,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(e) => return refuse(&e.to_string()),
    };
    let Some(line) = cfg.current_line().cloned() else {
        return refuse("未配置线路，无法切换接管方式。请先导入线路或用 --set-line。");
    };
    if mode == crate::config::Mode::Tun {
        let path = line.engine_config_path(&ctx.root);
        if !path.exists() {
            return refuse(&format!("线路的引擎配置不存在（{}），请先导入线路", path.display()));
        }
        // 有 TUN 入站才谈得上切过去；`actual_mode` 就是"这份配置里有没有 tun 入站"。
        if crate::engine_config::actual_mode(&path) != Some(crate::config::Mode::Tun) {
            return refuse(crate::engine_config::NO_TUN_MSG);
        }
    }
    cfg.mode = mode;
    if let Err(e) = crate::config::save_with_origin(&cfg_path, &cfg, &ctx.origin(None)) {
        return refuse(&format!("保存配置失败：{e}"));
    }
    serde_json::json!({
        "ok": true,
        "mode": mode.label(),
        "modeChoice": mode.id(),
        "message": format!("已切换到 {}（下次连接生效）", mode.label()),
    })
    .to_string()
}

/// 手动测量当前通道。只在状态证据链明确为 Connected 时进入网络层；
/// `ping` 继续只做控制面存活探测，绝不复用为线路延迟。
fn measure_latency_json(ctx: &Ctx, raw: &str) -> String {
    let cfg = live_cfg(ctx);
    let requested_line = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("lineId").and_then(|x| x.as_str()).map(str::to_string));
    // 用户发起的测速（带 lineId）先落一条 `Pending` 记录——这是「这次点击有没有
    // 结果」的唯一凭据。自动采样（不带 lineId）不记录：每 30 秒一条会把用户
    // 真正点过的动作淹掉，也会让「核对」分不清哪一条是人的操作。
    let tracked: Option<crate::lineaction::Action> = requested_line.as_ref().and_then(|line_id| {
        let line = cfg
            .as_ref()
            .and_then(|c| c.lines.iter().find(|l| &l.id == line_id));
        let profile = line
            .map(|l| match l.effective_transport() {
                crate::config::Transport::Udp => "Udp",
                crate::config::Transport::Tcp => "Tcp",
            })
            .unwrap_or("");
        let action = crate::lineaction::started(
            line_id,
            line.map(|l| l.name.as_str()).unwrap_or(""),
            crate::lineaction::CHECK,
            profile,
            "",
        );
        crate::lineaction::begin(&ctx.root, action).ok()
    });
    // 每个出口都要给记录一个结论：漏一条，页面就会永远停在「测速中」。
    let finish = |reply: &serde_json::Value| {
        let Some(action) = tracked.as_ref() else { return };
        let ok = reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true);
        let ms = reply.get("latencyMs").and_then(serde_json::Value::as_u64);
        let message = if ok {
            match ms {
                Some(ms) => format!("测得当前响应 {ms} ms。"),
                None => "测量完成。".to_string(),
            }
        } else {
            reply
                .get("message")
                .and_then(serde_json::Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("测量没有完成")
                .to_string()
        };
        let code = reply
            .get("errorCode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let _ = crate::lineaction::finish(
            &ctx.root,
            &action.line_id,
            crate::lineaction::CHECK,
            if ok {
                crate::lineaction::SUCCEEDED
            } else {
                crate::lineaction::FAILED
            },
            &message,
            code,
            ms,
        );
    };
    let check = crate::selfcheck::load(&ctx.root);
    let ev = evidence(&ctx.root, cfg.is_some(), true);
    let pres = crate::presentation::present_with_check(
        &ev,
        check.as_ref().map(|c| c.sentence()).as_deref(),
    );
    if pres.key != crate::presentation::StateKey::Connected {
        let reply = serde_json::json!({
            "ok": false,
            "error": "连接后测量",
            "errorCode": "environment",
            "message": "连接后测量",
            "latencyError": "连接后测量"
        });
        finish(&reply);
        return reply.to_string();
    }
    if let Some(requested) = requested_line.as_ref() {
        let current = cfg.as_ref().and_then(|c| c.current_line()).map(|l| l.id.as_str());
        if current != Some(requested.as_str()) {
            let reply = serde_json::json!({
                "ok": false,
                "error": "请求测量的线路已不是当前连接，请刷新后重试",
                "errorCode": "conflict",
                "message": "请求测量的线路已不是当前连接，请刷新后重试",
                "latencyError": "请求测量的线路已不是当前连接，请刷新后重试"
            });
            finish(&reply);
            return reply.to_string();
        }
    }
    let reply = match crate::selfcheck::measure_latency_and_record(
        &ctx.root,
        crate::selfcheck::UI_TIMEOUT_MS,
    ) {
        Ok(measured) => serde_json::json!({
            "ok": true,
            "latencyMs": measured.latency_ms,
            "measuredAtUtc": crate::selfcheck::at_rfc3339(measured.at),
            "latencyError": serde_json::Value::Null,
            "message": "测量完成"
        }),
        Err(error) => {
            let message = error.message;
            serde_json::json!({
                "ok": false,
                "error": message.clone(),
                "errorCode": error.code,
                "message": message.clone(),
                "latencyError": message
            })
        }
    };
    finish(&reply);
    reply.to_string()
}

fn backup_refuse(
    line_id: &str,
    line_name: &str,
    message: &str,
    code: &str,
) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "message": message,
        "backupResult": {
            "ok": false,
            "lineId": line_id,
            "lineName": line_name,
            "reachable": serde_json::Value::Null,
            "latencyMs": serde_json::Value::Null,
            "atUtc": crate::provider::now_rfc3339(),
            "scope": "tcp-connect",
            "notCurrentLatency": true,
            "message": message,
        }
    })
    .to_string()
}

/// 用户点击后对另一条线路的兼容连接（TCP）中转做一次端口建连计时。
/// 不启动引擎、不改系统代理、不建立隧道，也不自动切换；当前连接为 TUN 时
/// 无法保证探测流量不经过当前 TUN，直接拒绝而不是给出可能失真的读数。
fn measure_backup_json(ctx: &Ctx, raw: &str) -> String {
    let cfg = live_cfg(ctx);
    let line_id = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("lineId").and_then(|x| x.as_str()).map(str::trim).map(str::to_string))
        .unwrap_or_default();
    if line_id.is_empty() {
        return backup_refuse("", "", "缺少要检查的备用线路 id", "usage");
    }
    let current = cfg.as_ref().and_then(|c| c.current_line()).cloned();
    if current.as_ref().map(|l| l.id.as_str()) == Some(line_id.as_str()) {
        return backup_refuse(&line_id, "", "这是当前线路，不需要作为备用线路检查", "usage");
    }
    let Some(target) = cfg
        .as_ref()
        .and_then(|c| c.lines.iter().find(|l| l.id == line_id).cloned())
    else {
        return backup_refuse(&line_id, "", &format!("找不到线路：{line_id}"), "config");
    };

    let check = crate::selfcheck::load(&ctx.root);
    let ev = evidence(&ctx.root, cfg.is_some(), true);
    let pres = crate::presentation::present_with_check(
        &ev,
        check.as_ref().map(|c| c.sentence()).as_deref(),
    );
    if pres.key != crate::presentation::StateKey::Connected {
        return backup_refuse(
            &target.id,
            &target.name,
            "连接后才能检查备用线路；未连接时不做任何网络探测",
            "environment",
        );
    }
    let mode = cfg
        .as_ref()
        .map(|c| crate::engine_config::shown_mode(&ctx.root, c.mode))
        .unwrap_or(crate::config::Mode::Proxy);
    if mode == crate::config::Mode::Tun {
        return backup_refuse(
            &target.id,
            &target.name,
            "当前是 TUN 接管，无法保证备用探测不经过当前隧道，本版不测",
            "environment",
        );
    }

    let engine_path = target.engine_config_path(&ctx.root);
    let text = match std::fs::read_to_string(&engine_path) {
        Ok(t) => t,
        Err(e) => {
            return backup_refuse(
                &target.id,
                &target.name,
                &format!("读不到备用线路的引擎配置：{e}"),
                "config",
            )
        }
    };
    let engine: serde_json::Value = match serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)) {
        Ok(v) => v,
        Err(e) => {
            return backup_refuse(
                &target.id,
                &target.name,
                &format!("备用线路的引擎配置不可读：{e}"),
                "config",
            )
        }
    };
    let Some(outbound) = engine
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find(|o| {
                o.get("tag").and_then(|x| x.as_str()) == Some(crate::engine_config::TRANSPORT_TAG)
                    && o.get("type").and_then(|x| x.as_str()) == Some("vless")
            })
        })
    else {
        return backup_refuse(
            &target.id,
            &target.name,
            "这条备用线路没有兼容连接（TCP）中转入口，本版不测",
            "environment",
        );
    };
    let Some(host) = outbound.get("server").and_then(|x| x.as_str()).and_then(|x| x.parse::<std::net::IpAddr>().ok()) else {
        return backup_refuse(
            &target.id,
            &target.name,
            "备用线路中转使用域名或非法地址；本版不做 DNS 路径探测",
            "environment",
        );
    };
    let Some(port) = outbound
        .get("server_port")
        .and_then(|x| x.as_u64())
        .and_then(|x| u16::try_from(x).ok())
        .filter(|p| *p > 0)
    else {
        return backup_refuse(
            &target.id,
            &target.name,
            "备用线路中转端口不可用",
            "config",
        );
    };

    let started = std::time::Instant::now();
    let addr = std::net::SocketAddr::new(host, port);
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1000)) {
        Ok(_stream) => {
            let latency = started.elapsed().as_millis() as u64;
            let message = format!(
                "备用线路「{}」TCP 端口可达（{latency} ms）；仅端口建连，未建立隧道，不等于当前响应",
                target.name
            );
            serde_json::json!({
                "ok": true,
                "backupResult": {
                    "ok": true,
                    "lineId": target.id,
                    "lineName": target.name,
                    "reachable": true,
                    "latencyMs": latency,
                    "atUtc": crate::provider::now_rfc3339(),
                    "scope": "tcp-connect",
                    "notCurrentLatency": true,
                    "message": message,
                }
            })
            .to_string()
        }
        Err(e) => {
            let message = format!(
                "备用线路「{}」TCP 端口不可达：{e}；此结果不等于当前响应",
                target.name
            );
            serde_json::json!({
                "ok": true,
                "backupResult": {
                    "ok": false,
                    "lineId": target.id,
                    "lineName": target.name,
                    "reachable": false,
                    "latencyMs": serde_json::Value::Null,
                    "atUtc": crate::provider::now_rfc3339(),
                    "scope": "tcp-connect",
                    "notCurrentLatency": true,
                    "message": message,
                }
            })
            .to_string()
        }
    }
}

/// 设置页「创建桌面快捷方式」。回包形状与其他动作一致：`ok` 决定颜色，`message` 原话上屏。
fn shortcut_json() -> String {
    match crate::shortcut::ensure_desktop_shortcut() {
        Ok(outcome) => serde_json::json!({"ok": true, "message": outcome.message()}).to_string(),
        Err(message) => serde_json::json!({"ok": false, "message": message}).to_string(),
    }
}

/// 当前连接下的出口观测记录：必须有原始认证会话、交易路由和当前线路绑定；
/// 旧 JSON 仍可读取，但无绑定时不可显示为当前已验证出口。
fn exit_probe_fresh(ctx: &Ctx) -> Option<crate::exit_probe::Record> {
    let rec = crate::exit_probe::load(&ctx.root)?;
    crate::exit_probe::belongs_to_current_connection(&rec, &ctx.root).then_some(rec)
}

/// One validated read produces all four exit status projections. This
/// prevents a single response from mixing multiple disk/session generations.
/// No guarantee is made about concurrent writers after this read.
struct ExitStatusSnapshot {
    evidence: &'static str,
    observed_ip: Option<String>,
    attribution: &'static str,
    probe_at_utc: Option<String>,
}

fn exit_status_snapshot(
    check_ok: bool,
    probe: Option<&crate::exit_probe::Record>,
) -> ExitStatusSnapshot {
    ExitStatusSnapshot {
        evidence: exit_evidence(check_ok, probe),
        observed_ip: probe.map(|r| r.ip.clone()),
        attribution: probe
            .map(|r| if r.attributed { "LineServer" } else { "Other" })
            .unwrap_or("Unknown"),
        probe_at_utc: probe.and_then(|r| crate::selfcheck::at_rfc3339(r.at)),
    }
}

/// 出口证据三档（界面按这个字符串选标签，见 `app.js::exitView`）。
///
/// 纯函数：输入只有「自检过没过」与「有没有一条属于当前连接的观测记录」，便于逐档钉住。
fn exit_evidence(check_ok: bool, probe: Option<&crate::exit_probe::Record>) -> &'static str {
    if !check_ok {
        // 自检没过：任何出口结论都是假的，包括「上次观测到的 IP」。
        return "unverified";
    }
    match probe {
        // 观测到出口 IP 且等于线路服务器地址：这才叫「出口已核验」。
        Some(r) if r.attributed => "verified",
        // 观测到了但判不了归属，或压根没观测：只能说到「转发已通，归属未验证」。
        _ => "Passed",
    }
}

/// 「没有可用引擎」的话要能指导下一步：分清「没配」和「配的那份没了」，并且说明
/// 安装目录里也没有自带副本——否则用户只会看到「连不上」。
pub(crate) fn engine_missing_message(configured: &str) -> String {
    match configured.trim() {
        "" => "未配置引擎（config.json 的 engine.binary），安装目录里也没有自带副本；请在设置页选择引擎程序。".to_string(),
        path => format!(
            "引擎程序不存在：{path}（安装目录里也没有自带副本）；请在设置页重新选择引擎程序。"
        ),
    }
}

fn status_json(ctx: &Ctx) -> String {
    // 配置以磁盘为准：`use`/`remove` 之后同进程再查状态，不能还报旧的选中线路。
    let read = read_cfg(ctx);
    let cfg = read.cfg;
    // 这条请求本身就是控制接口在回应，所以「可用」是观察到的事实，不是假设。
    let ev = evidence(&ctx.root, cfg.is_some(), true);
    // 引擎：配置里写的那个值，以及**真正会被执行**的那个路径（见 engine::resolve）。
    let engine_configured = cfg
        .as_ref()
        .and_then(|c| c.engine.as_ref())
        .map(|e| e.binary.clone())
        .unwrap_or_default();
    let engine_path = crate::engine::resolve_for(&ctx.root, &engine_configured);
    // 通道自检没过时，标题要标注「（通道未通）」并把动作换成「重新连接」：
    // 只看 state=Connected 用户会以为自己已经能用了。措辞与 CLI `--status` 同源。
    let check = crate::selfcheck::load(&ctx.root);
    let pres =
        crate::presentation::present_with_check(&ev, check.as_ref().map(|c| c.sentence()).as_deref());
    let compatible_hint = check
        .as_ref()
        .and_then(|c| crate::selfcheck::transport_alternative_hint(cfg.as_ref(), &ctx.root, c));
    // 只有完整连接证据成立时才读“实际生效”值；未连接时偏好不能被投影成运行时事实。
    let transport_actual = (pres.key == crate::presentation::StateKey::Connected)
        .then(|| crate::engine_config::actual_transport(&ctx.root.join("runtime-engine.json")))
        .flatten();
    let latency = (pres.key == crate::presentation::StateKey::Connected)
        .then(|| crate::selfcheck::load_current_latency(&ctx.root))
        .flatten();
    // 连接起点：`runtime.json` 的 `StartedAt`（守护进程拉起引擎的那一刻）。
    // **只在「已连接」时给**——记录可能比连接活得久（引擎已死、或上一次留下的残档），
    // 那种时候报一个起点，界面就会算出「已运行 3 小时」，而实际什么都没在跑。
    // 解析不出来（记录里时间坏了）同样给空串：宁可显示「—」，不要编一个时长。
    let started_at = (pres.key == crate::presentation::StateKey::Connected)
        .then(|| {
            ev.snapshot
                .started_at
                .and_then(|secs| crate::selfcheck::at_rfc3339(secs.max(0.0) as u64))
        })
        .flatten()
        .unwrap_or_default();
    let proxy_store = crate::proxy::ProxyStore::system();
    let snap = proxy_store.read();
    let maintenance = crate::proxy::maintenance_status_from(
        crate::proxy::read_journal(&ctx.root.join("proxy-journal.json")),
        &snap,
    );
    // 线路页的「交易名单」区块读它：只读投影，界面不自己从配置里拼。
    let trade_list = trade_list_payload(cfg.as_ref());
    // A single qualified disk record feeds the complete exit quartet.
    // Do not re-read exit-probe.json inside individual JSON fields.
    let exit_record = exit_probe_fresh(ctx);
    let exit_snapshot = exit_status_snapshot(
        check.as_ref().is_some_and(|c| c.ok),
        exit_record.as_ref(),
    );
    let mut out = serde_json::json!({
        "ok": true,
        "state": pres.key.as_str(),
        "title": pres.title,
        "detail": pres.detail,
        "action": pres.action.as_str(),
        "enabled": pres.enabled,
        "line": cfg
            .as_ref()
            .and_then(|c| c.current_line())
            .map(|l| l.name.as_str())
            .unwrap_or(""),
        // 线路数：界面/`--status` 都要能看出「一共有几条」，多线路下这是最基本的上下文。
        "lineCount": cfg.as_ref().map(|c| c.lines.len()).unwrap_or(0),
        "endpoint": endpoint_of(&cfg),
        "proxy_enabled": snap.enable,
        "proxy_server": snap.server.unwrap_or_default(),
        "maintenance": maintenance,
        "legacy_running": ctx.legacy_running,
        // 接管方式：与 `--status` 的「模式」行同源同词（代理 / TUN），空串表示还没配置。
        // 同样是"实际生效"的模式（见 `engine_config::mode_of_file` 的注释）。
        "mode": cfg
            .as_ref()
            .map(|c| crate::engine_config::shown_mode(&ctx.root, c.mode).label())
            .unwrap_or(""),
        // 两个开关给界面的复选框做初值；没配置时一律 false（不能默认打开自启）。
        "autoStart": cfg.as_ref().map(|c| c.auto_start).unwrap_or(false),
        "autoConnect": cfg.as_ref().map(|c| c.auto_connect).unwrap_or(false),
        // 关窗行为：界面第三个复选框的初值。缺省 false = 关窗即断开（历史行为）。
        "closeToTray": cfg.as_ref().map(|c| c.close_to_tray).unwrap_or(false),
        // 线路变差提醒：缺省 **开**（老配置没这一项也要开着，不能把提醒变成默认关闭）。
        "qualityWarning": cfg.as_ref().map(|c| c.quality_warning).unwrap_or(true),
        // 自动记住首次服务器身份：缺省 **开**，与旧版同一默认。
        "autoTrust": cfg
            .as_ref()
            .map(|c| c.auto_trust_first_connection)
            .unwrap_or(true),
        // 接管方式的**偏好**（config.json 里的 mode）：界面单选按它显示。
        // 上面那个 `mode` 是"实际生效值"（连接中读运行时、否则读线路文件），两者在切换后、
        // 重连前会不同——和 transport / transportSelected 是同一套区分，别合并。
        "modeChoice": cfg.as_ref().map(|c| c.mode.id()).unwrap_or_default(),
        // 标准/兼容是当前运行时形状，不是线路偏好，更不是上面的代理/TUN 接管方式。
        "transportActual": transport_actual.map(|t| t.label()),
        // 已连接的起点（RFC3339）；未连接或时间读不出来时是空串。
        // 界面据此说「引擎已运行 N 分」——空串就显示「—」，不猜。
        "startedAt": started_at,
        // 动作与提示共用同一资格事实，界面不能自行猜“有参数”或“自检失败”。
        "compatibleAction": compatible_hint.is_some(),
        // 这条线路**有没有 TUN 素材**（线路文件里有没有 tun 入站）：界面据此决定 TUN 单选能不能点。
        // 与 `modeChoice` 不是一回事：切过代理、还没重连时线路文件里仍有 TUN 入站，那时还能切回去。
        "tunAvailable": cfg
            .as_ref()
            .and_then(|c| c.current_engine_path(&ctx.root))
            .map(|p| crate::engine_config::tun_available(&p))
            .unwrap_or(false),
        // 空串表示「未检测」：界面据此显示「通道自检：未检测」，而不是留一个空行或假装通过。
        "check": check.as_ref().map(|c| c.verdict()).unwrap_or_default(),
        // AI 工具走向的**存储值**（daily / trade）：应用页那个下拉按它显示当前选的是哪一档。
        // 「实际生效值」是快照里的 `Agents`（还要看全局覆盖与这条线路有没有交易出口）。
        "agentsLane": cfg.as_ref().map(|c| c.agents.lane.id()).unwrap_or_default(),
        // 线路页「交易名单」：程序（带路径）/ 网站 / 辅助解析（本版恒空）。
        // 形状固定三个数组，页面按组渲染，空组整行不显示。
        "tradeList": trade_list,
        "checkAtUtc": check.as_ref().and_then(|c| crate::selfcheck::at_rfc3339(c.at)),
        // 只有当前连接才投影测量；完成时间非法时保留真实毫秒数但不伪造相对时间。
        "latencyMs": latency.as_ref().map(|m| m.latency_ms),
        "measuredAtUtc": latency.as_ref().and_then(|m| crate::selfcheck::at_rfc3339(m.at)),
        // All four fields describe precisely the SAME previously validated
        // exit record; no independent disk reads per field.
        "exitEvidence": exit_snapshot.evidence,
        "exitObservedIp": exit_snapshot.observed_ip,
        "exitAttribution": exit_snapshot.attribution,
        "exitProbeAtUtc": exit_snapshot.probe_at_utc,
        "isAdmin": crate::probe::elevated(),
        // 引擎程序：设置页要显示「已经选了哪一个 / 还没选」并给一个选择按钮。
        // **显示的是生效路径**（配置的那份存在就用它，否则是自带副本），因为这里要说的是
        // 「点连接会跑哪个程序」，而不是「配置里写了什么」。
        // `engineMissing` 也据此判断——原来只判字符串空，旧版卸载后仍显示正常，
        // 直到点连接才报「引擎程序不存在」。
        "engineBinary": engine_path
            .as_ref()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .unwrap_or_else(|| engine_configured.clone()),
        "engineMissing": engine_path.is_none(),
        // 结论行之外的一句自救话（见 selfcheck::transport_alternative_hint）。单独一个字段、
        // 不并进 check：结论是「未通过」这句定稿契约，提示是附加信息——与 CLI 连接输出的
        // 语义一致（结论行后另起一行）。两个入口共用同一个函数，措辞不可能分叉。
        "checkHint": compatible_hint.unwrap_or_default(),
    })
    .to_string();
    // 出口信息（界面下拉/状态展示都要）：合并进同一份 JSON，不另开命令。
    if let Some(o) = serde_json::from_str::<serde_json::Value>(&out)
        .ok()
        .and_then(|mut v| {
            insert_lines_read(&mut v, &read.error);
            let extra = exits_payload(ctx, &cfg);
            if let (Some(dst), Some(src)) = (v.as_object_mut(), extra.as_object()) {
                for (k, val) in src {
                    dst.insert(k.clone(), val.clone());
                }
            }
            // 交易保护：**唯一来源**是这里（guard::status）。界面只渲染，不本地推断。
            // 拿不到证据时它自己会给 `Unknown`——这里绝不兜底成 `Protected`。
            let guard = crate::guard::status(cfg.as_ref(), &ctx.root, ctx.legacy_running);
            if let (Some(dst), Some(src)) = (v.as_object_mut(), guard.to_json().as_object()) {
                for (k, val) in src {
                    dst.insert(k.clone(), val.clone());
                }
            }
            Some(v.to_string())
        })
    {
        out = o;
    }
    out
}

/// 连接：事务本体复用 `connect::connect`，这里只做两件事——
/// 把「没配置」翻译成人话，把结果翻译成 JSON。
fn connect_json(ctx: &Ctx) -> String {
    // Refusal before config preparation, journal, proxy or new spawn.
    // Do not clear prior self-check evidence or run cleanup on this refusal.
    let _runtime_occupancy = match crate::runtime_occupancy::admit() {
        Ok(held) => held,
        Err(reason) => return refuse(&reason),
    };
    // 连接根本不成立时也先把上次的「通过」清掉：留着它就是一条假证据。
    let refuse_now = |msg: &str| -> String {
        crate::selfcheck::clear(&ctx.root);
        // 没发起连接也要留痕：「还没配好」是最常见的失败，界面与命令行两边的说法必须一致。
        crate::events::record(&ctx.root, crate::events::CONNECT, false, msg, &ctx.origin(None));
        refuse(msg)
    };
    // 以磁盘为准：`use` 切过线路后，同一进程里的连接必须用新选中的那条。
    let live = live_cfg(ctx);
    let cfg = match &live {
        Some(c) => c,
        None => return refuse_now("找不到配置文件（config.json），请先导入线路"),
    };
    // 已连接时不能先重写 runtime-engine.json：sing-box 仍在用旧探测凭据，
    // 若磁盘被新凭据覆盖，就会变成「运行配置与记录不一致」。
    let preflight_store = crate::proxy::ProxyStore::system();
    match crate::connect::preflight_before_prepare(
        cfg, &ctx.root, &preflight_store, &crate::probe::pid_alive, ctx.legacy_running,
    ) {
        Ok(true) => {
            let outcome = crate::connect::record_already_connected(cfg, &ctx.root, &ctx.origin(None));
            return outcome_json(Ok(outcome));
        }
        Ok(false) => {}
        Err(e) => {
            // 预检拒绝时现有引擎仍可能在工作：不要用 refuse_now 清掉
            // 它的真实通道自检证据。只记录本次重连被拒，不动运行态。
            crate::events::record(&ctx.root, crate::events::CONNECT, false, &e, &ctx.origin(None));
            return refuse(&e);
        }
    }
    // 探测计划：探测端口（线路端口 +3）被占 → 摘掉探测入站再起引擎（引擎对绑不上的
    // 入站是整体 FATAL），自检届时报「自检跳过」。凭据在这里生成一次，两处共用。
    let endpoint = endpoint_of(&live);
    let probe_plan = crate::selfcheck::plan_probe(&endpoint);
    let probe_creds: Option<(&str, &str)> = match &probe_plan {
        crate::selfcheck::ProbePlan::Dial { username, password, .. } => {
            Some((username.as_str(), password.as_str()))
        }
        _ => None,
    };
    // 引擎要听在自检要拨的那个端口上（计划可能已从 `+3` 回落到动态端口）。
    let probe_port: Option<u16> = match &probe_plan {
        crate::selfcheck::ProbePlan::Dial { port, .. } => Some(*port),
        _ => None,
    };
    // 引擎二进制：配置的那份（存在才算）→ 随包自带的副本。**先解析再准备配置**：
    // 解析不出来就不该动线路文件，也不该让用户看到「启动后立即退出」。
    let configured_engine = cfg.engine.as_ref().map(|e| e.binary.clone()).unwrap_or_default();
    let Some((engine_binary, _origin)) = crate::engine::resolve_for(&ctx.root, &configured_engine) else {
        return refuse_now(&engine_missing_message(&configured_engine));
    };
    let engine_settings = crate::config::EngineSettings {
        binary: engine_binary.to_string_lossy().to_string(),
    };
    // A8：自动档先按「用户固定 → 新鲜证据 → 现场探测 → 已验证/标准」选一次。
    // 连接已经在跑时 `busy` 为真，只复用证据，绝不再起一个引擎去抢 WireGuard 身份。
    // 这个值必须在 `engine_cfg` 之外：连接成功后「已验证的方式」要记的就是它。
    let transport = match cfg.current_line() {
        Some(line) => crate::autoroute::choose_transport(
            &ctx.root,
            cfg,
            line,
            Some(engine_binary.as_path()),
            !busy(ctx),
            crate::model::now_epoch_secs_u64() as i64,
        )
        .transport,
        None => crate::config::Transport::Udp,
    };
    let engine_cfg = match cfg.current_engine_path(&ctx.root) {
        Some(p) => {
            // 连接前把分流规则应用一遍：界面上改了规则也可能还没同步到线路文件。
            // prepare 出错时不能退回线路文件起引擎：那上面的探测入站没有 users，
            // 直接起等于开一个无认证的口——宁可拒绝连接（没有探测入站的仍按原文件起）。
            // 已在外层按 A8 选好 transport，这里直接使用。
            // 与 `main.rs` 同一条口径：线路指定就绑它，否则绑系统默认。
            // 指定的网卡不在了 → 拒绝连接，**不许**静默退回默认（那会把交易流量
            // 放到用户没选的出口上），也不许把不存在的名字写进配置（引擎起不来）。
            let (bind_interface, stale_interface) = crate::netbind::for_connect(
                &ctx.root,
                cfg.current_line().map(|l| l.id.as_str()).unwrap_or(""),
            );
            if let Some(name) = stale_interface {
                return refuse_now(&format!(
                    "这条线路指定的出口网卡「{name}」不在这台电脑上。\
                     请在「连接方式与网络」里重新选择，或改为跟随系统默认。"
                ));
            }
            let effective = match crate::engine_config::prepare_engine_config(
                &p,
                &cfg.split,
                &cfg.agents,
                transport,
                cfg.mode,
                &ctx.root.join("runtime-engine.json"),
                &bind_interface,
                probe_creds,
                probe_port,
            ) {
                Ok(path) => path,
                // 配置准备失败不允许退回原线路文件。原文件可能缺少最新分流、
                // DNS 或接口约束；继续连接会使运行时行为与页面配置不一致。
                Err(err) => return refuse_now(&format!("引擎配置准备失败：{err}")),
            };
            engine_settings.to_engine(&effective)
        }
        None => return refuse_now("未配置线路：请先导入线路或用 --set-line 写入一条"),
    };
    let store = crate::proxy::ProxyStore::system();
    let log_dir = ctx.log_dir.clone();
    let journal_path = ctx.root.join("proxy-journal.json");
    let runtime_path = ctx.root.join("runtime.json");
    let guard = crate::guard::ProductionGuard::new(&ctx.root, ctx.legacy_running);
    let deps = crate::connect::Deps {
        store: &store,
        apply: &crate::connect::write_proxy,
        spawn: &|e: &crate::engine::EngineConfig| crate::engine::start(e, &log_dir).map(|h| h.pid),
        kill: &|pid: i64| crate::engine::stop(pid, 3_000),
        alive: &crate::probe::pid_alive,
        elevated: &crate::probe::elevated,
        journal_path: &journal_path,
        runtime_path: &runtime_path,
        now: crate::model::now_epoch_secs(),
        guard: guard.as_ref().map(|g| g.context()),
    };
    let outcome = crate::connect::connect_with_origin(
        cfg,
        &engine_cfg,
        &deps,
        ctx.legacy_running,
        &ctx.origin(None),
    )
        // TUN 起不来最常见的原因就是没提权：错误里补一句，别让用户对着「未知错误」猜。
        .map_err(|e| crate::connect::explain(e, cfg.mode));
    match &outcome {
        // 界面是主要入口：连接成功就顺手验通道并留下首个真实响应读数。
        // 本 handler 由 T-09 在工作线程执行；2 秒探测预算不会卡住 WebView UI。
        // 自检与测量分别落在 last-check.json / last-latency.json，随状态一起回推。
        Ok(crate::connect::Outcome::Done(_)) => {
            // 凭据记进 runtime.json：自检从那里取（凭据只落在运行时记录里，不进日志）。
            if let crate::selfcheck::ProbePlan::Dial { username, password, .. } = &probe_plan {
                if let Err(e) = crate::selfcheck::record_probe_creds(&runtime_path, username, password) {
                    eprintln!("探测凭据记录失败：{e}");
                }
            }
            let check = crate::selfcheck::check_and_record(
                &ctx.root,
                &probe_plan,
                crate::selfcheck::UI_TIMEOUT_MS,
            );
            // 出口 IP 观测（B1）：与自检**同一条**探测入站（路由写死 trade-exit），
            // 最多再花 2.5 秒。它只是证据采集——失败不写、不覆盖，也不改变连接结论。
            if check.ok {
                if let Some(line) = cfg.current_line() {
                    // 「自动」的依据：这条线路**真的**用当前方式连通过了。记不下来只写日志，
                    // 连接结论与退出码都不受影响（自检结论已经落在 last-check.json）。
                    let id = line.id.clone();
                    // A cached successful return is not sufficient to write
                    // transport evidence for a subsequently changed session.
                    if crate::selfcheck::current_qualified_trade_pass(&ctx.root) {
                        if let Err(e) = crate::config::record_verified_transport(
                            &ctx.root,
                            &id,
                            transport,
                        ) {
                            eprintln!("记录已验证的连接方式失败：{e}");
                        }
                    }
                    // Always keep a real returned-IP observation; the
                    // producer independently refuses stale current attribution.
                    // A cached check.ok is not sufficient after a reconnect.
                    let _ = crate::exit_probe::probe_and_record(
                        &ctx.root,
                        line,
                        &probe_plan,
                        2_500,
                    );
                }
            }
        }
        // 连接失败（代理已回滚）：上一次的「通过」在这个状态下就是假话。
        Err(_) => {
            crate::selfcheck::clear(&ctx.root);
            // 「已验证的连接方式」同理：这次没连上，它就只是一条旧证据，「自动」不该再拿它当依据。
            if let Some(line) = cfg.current_line() {
                let id = line.id.clone();
                if let Err(e) = crate::config::clear_verified_transport(&ctx.root, &id) {
                    eprintln!("清除已验证的连接方式失败：{e}");
                }
            }
            // 出口证据同理：连接都没起来，上一条连接的出口 IP 不能留着。
            crate::exit_probe::clear(&ctx.root);
        }
        // 已经是连接态、没做改动：现有结论就是这条连接的证据，留着。
        Ok(crate::connect::Outcome::AlreadyDone) => {}
    }
    // 口径：`runtime-engine.json` 存在 ⟺ 连接正在运行（自检结论归 last-check.json）。
    settle_runtime_engine(&ctx.root, &outcome);
    outcome_json(outcome)
}

/// 断开：同样复用 `connect::disconnect`。
///
/// 不要求配置里有引擎：引擎设置只用于启动，断开路径上根本用不到。CLI 与这里的断开都已经
/// 不看 engine（`main.rs` 的断开分支同样不看），删掉引擎配置也必须能断开。
fn disconnect_json(ctx: &Ctx) -> String {
    // 不再要求有配置：pid 在 runtime.json、还原值在凭据里。配置坏了也必须能断开。
    let store = crate::proxy::ProxyStore::system();
    let journal_path = ctx.root.join("proxy-journal.json");
    let runtime_path = ctx.root.join("runtime.json");
    let guard = crate::guard::ProductionGuard::new(&ctx.root, ctx.legacy_running);
    let deps = crate::connect::Deps {
        store: &store,
        apply: &crate::connect::write_proxy,
        // 断开流程不会调用 spawn；真被调用说明逻辑错了，直接报错而不是假装起过引擎。
        spawn: &|_e: &crate::engine::EngineConfig| Err::<i64, String>("断开流程不应启动引擎".to_string()),
        kill: &|pid: i64| crate::engine::stop(pid, 3_000),
        alive: &crate::probe::pid_alive,
        elevated: &crate::probe::elevated,
        journal_path: &journal_path,
        runtime_path: &runtime_path,
        now: crate::model::now_epoch_secs(),
        guard: guard.as_ref().map(|g| g.context()),
    };
    // 断开也以磁盘为准：与 status/lines 同一条 live_cfg，口径只有一套。
    let live = live_cfg(ctx);
    let outcome = crate::connect::disconnect_with_origin(
        live.as_ref(),
        &deps,
        &ctx.origin(None),
    );
    // 保留 last-check.json：概览要显示「上次结论 + 时间」，由状态字段标成（上次）。
    // 只清运行时引擎配置；把证据一并删掉会让断开后的卡片退回「未检测」。
    if outcome.is_ok() {
        crate::connect::discard_runtime_config(&ctx.root);
        crate::selfcheck::clear_latency(&ctx.root);
    }
    outcome_json(outcome)
}

/// 读交易保护状态：**只读**，不弹 UAC、不写 WFP、不写证据。
fn guard_status_json(ctx: &Ctx) -> String {
    let st = crate::guard::status(live_cfg(ctx).as_ref(), &ctx.root, ctx.legacy_running);
    guard_reply_payload(Ok(st), ctx, "guard-status").to_string()
}

/// 请求里的 `acknowledgeRunning`（P0-13）：用户在确认框里选了「仍要启用」。
///
/// 缺省 `false`——**不确认就是不放行**。漏读这个字段会让「仍要启用」按不动，
/// 多读（默认 true）则等于把提示关掉，两种都错，所以这里只认明确的 `true`。
fn acknowledge_running_of(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("acknowledgeRunning").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// 显式交易保护动作。长命令：可能一次 UAC + 一次 WFP 事务 + 一次证据写入。
fn guard_action_json(ctx: &Ctx, action: GuardAction, line: &str) -> String {
    let Some(cfg) = live_cfg(ctx) else {
        return refuse("找不到配置文件（config.json），无法确定交易保护名单");
    };
    // 闸门在 `guard` 模块里（CLI 与界面共用同一份判据），这里只负责把用户的确认带过去。
    let acknowledge_running = acknowledge_running_of(line);
    let result = match action {
        GuardAction::Verify => crate::guard::verify_status(&cfg, &ctx.root, ctx.legacy_running),
        GuardAction::Install => {
            crate::guard::install_explicit(&cfg, &ctx.root, ctx.legacy_running, acknowledge_running)
        }
        GuardAction::Sync => {
            crate::guard::sync_explicit(&cfg, &ctx.root, ctx.legacy_running, acknowledge_running)
        }
        GuardAction::Remove => crate::guard::remove_status(&cfg, &ctx.root, ctx.legacy_running),
    };
    guard_reply_payload(result, ctx, action.as_str()).to_string()
}

/// 统一回包：顶层放界面直接消费的字段，`guard` 里放同一份完整投影。
/// 失败时也带回当时能读到的状态——「动作失败」与「保护当前是什么样」是两个事实。
fn guard_reply_payload(
    result: Result<crate::guard::GuardStatus, String>,
    ctx: &Ctx,
    command: &str,
) -> serde_json::Value {
    match result {
        Ok(st) => {
            let summary = st.summary.clone();
            let mut out = st.to_json();
            if let Some(obj) = out.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::json!(true));
                obj.insert("message".to_string(), serde_json::json!(summary));
                obj.insert("guard".to_string(), st.to_json());
                if command == "guard-remove" {
                    obj.insert(
                        "guardRemove".to_string(),
                        serde_json::json!({"ok": true, "message": st.summary, "guard": st.to_json()}),
                    );
                }
            }
            out
        }
        Err(message) => {
            let st = crate::guard::status(live_cfg(ctx).as_ref(), &ctx.root, ctx.legacy_running);
            let mut out = st.to_json();
            if let Some(obj) = out.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::json!(false));
                obj.insert("error".to_string(), serde_json::json!(message.clone()));
                obj.insert("guard".to_string(), st.to_json());
                if command == "guard-remove" {
                    obj.insert(
                        "guardRemove".to_string(),
                        serde_json::json!({"ok": false, "message": message, "guard": st.to_json()}),
                    );
                }
            }
            out
        }
    }
}

fn maintenance_status_json(ctx: &Ctx) -> String {
    let store = crate::proxy::ProxyStore::system();
    let maintenance = crate::proxy::maintenance_status(&store, &ctx.root.join("proxy-journal.json"));
    serde_json::json!({"ok": true, "maintenance": maintenance}).to_string()
}

/// 界面/管道的执行还原。与 CLI `--restore-apply` 共用后端，不读取或改写线路配置。
fn restore_json(ctx: &Ctx) -> String {
    restore_with_store(ctx, &crate::proxy::ProxyStore::system())
}

fn restore_with_store(ctx: &Ctx, store: &crate::proxy::ProxyStore) -> String {
    let journal_path = ctx.root.join("proxy-journal.json");
    let had_journal = journal_path.exists();
    let outcome = crate::connect::restore_from_journal(store, &journal_path, "");
    let (ok, changed, message) = match outcome {
        Ok(changed) if had_journal && journal_path.exists() => (
            false,
            changed,
            "系统代理已处理，但还原凭据仍未清除；请检查文件权限后重试。".to_string(),
        ),
        Ok(true) => (true, true, "已按凭据还原系统代理。".to_string()),
        Ok(false) if had_journal => (
            true,
            false,
            "当前代理无需写回，残留凭据已清理。".to_string(),
        ),
        Ok(false) => (true, false, "没有待还原凭据，未执行任何写入。".to_string()),
        Err(e) => (
            false,
            false,
            format!("还原失败：{e}；凭据已保留，可修复后重试。"),
        ),
    };
    crate::events::record(
        &ctx.root,
        crate::events::RESTORE,
        ok,
        &message,
        &ctx.origin(Some("system-proxy")),
    );
    let maintenance = crate::proxy::maintenance_status(store, &journal_path);
    let mut out = serde_json::json!({
        "ok": ok,
        "message": message.clone(),
        "restoreResult": {"ok": ok, "changed": changed, "message": message.clone()},
        "maintenance": maintenance,
    });
    if !ok {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("error".to_string(), serde_json::json!(message));
            obj.insert("errorCode".to_string(), serde_json::json!("config"));
        }
    }
    out.to_string()
}

fn outcome_json(r: Result<crate::connect::Outcome, String>) -> String {
    match r {
        Ok(crate::connect::Outcome::Done(steps)) => {
            serde_json::json!({ "ok": true, "steps": steps }).to_string()
        }
        // 已经处于目标状态：是成功，只是没有动作可报。
        Ok(crate::connect::Outcome::AlreadyDone) => {
            serde_json::json!({ "ok": true, "steps": Vec::<String>::new() }).to_string()
        }
        Err(e) => refuse(&e),
    }
}

/// 这台服务器有没有「本任务保存的登录资料」可复用（r95）。
///
/// 判据与 [`deploy_task_credential`] 同一套：同一 `lane_key`、同一次部署记录、
/// 用记录里的目标拼 binding，能解开才算。只读，不产生任何副作用。
fn task_credential_available(
    root: &std::path::Path,
    target: &crate::ssh::Target,
    run_id: Option<&str>,
) -> bool {
    // 只有「这一次要复用的那条草稿」的任务级信封才算：新的部署不会去读旧任务的
    // 凭据（`deploy_resolve_credential` 只在 `existing` 非空时才看任务档）。
    let Some(run_id) = run_id.filter(|id| !id.is_empty()) else {
        return false;
    };
    let lane = format!("{}:{}", target.host.to_ascii_lowercase(), target.port);
    let loaded = crate::deploystore::DeploymentStore::open(root).load_all();
    loaded.runs.iter().any(|run| {
        if run.run_id != run_id || run.target.lane_key() != lane {
            return false;
        }
        let binding = crate::deploycred::binding_of(
            &run.run_id,
            &run.target.host,
            run.target.port,
            &run.target.user,
        );
        crate::deploycred::load(root, &run.run_id, &binding).is_some()
    })
}

/// 自助部署第一步：读主机指纹。**只读**——不送密码、不改服务器。
///
/// 界面靠它做「先核对身份、再交凭据」那一步。顺序不能反：先收密码再去连，
/// 等于让用户为一个可能发错地方的凭据白输一遍。
fn server_probe_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let spec = parsed
        .as_ref()
        .and_then(|v| v.get("spec"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if spec.is_empty() {
        return refuse("请填写服务器地址，例如 root@203.0.113.10");
    }
    let target = match crate::ssh::Target::parse(&spec) {
        Ok(target) => target,
        Err(message) => return refuse(&message),
    };
    // 已经有记录时，界面可以跳过密码直接部署（凭据在 DPAPI 里）。
    let record = crate::serverstore::find_by_target(&ctx.root, &target)
        .ok()
        .flatten();
    let known = record.is_some();
    // r95：两个「使用已保存凭据」的勾只在**真的有**那一档时出现。这里把「有没有」
    // 一次算清（长期信封只看文件在不在；任务级信封按同一台服务器找一条能解开的记录）。
    let saved_credential = record
        .as_ref()
        .map(|item| crate::serverstore::has_saved_credential(&ctx.root, &item.id))
        .unwrap_or(false);
    let requested_run = parsed
        .as_ref()
        .and_then(|value| value.get("runId"))
        .and_then(|value| value.as_str())
        .filter(|value| crate::deploystore::is_run_id(value));
    let task_credential = task_credential_available(&ctx.root, &target, requested_run);
    match crate::ssh::probe_host_key(&target, std::time::Duration::from_secs(15)) {
        Ok(fingerprint) => serde_json::json!({
            "ok": true,
            // 回包挂在命令自己的键下：`finish_op` 只看回包内容，靠这个键分辨是哪条命令。
            "serverProbe": {
                "spec": spec,
                "host": target.host,
                "port": target.port,
                "user": target.user,
                "fingerprint": fingerprint,
                "known": known,
                "savedCredential": saved_credential,
                "taskCredential": task_credential,
            },
        })
        .to_string(),
        Err(error) => refuse(&error.to_string()),
    }
}

// ---------------------------------------------------------------------------
// 部署中心（A2/A3）：8 条短命令
// ---------------------------------------------------------------------------
//
// 这一层**只做受理**：校验输入 → 记录落盘 → 投递给引擎。真正的 SSH 往返在引擎
// 线程里跑，所以每条命令都是毫秒级返回，绝不占 `transaction_gate`。
//
// 回包里 `ok:true` 只代表「已受理」，**不代表「已完成」**——文案也这么写。
// 想骗自己很容易：把 `ok` 当成功，于是界面弹「部署完成」而服务器上什么都还没做。

/// 引擎没起来（测试上下文、或启动失败）。如实拒绝，**不**退回去同步跑一遍旧流程
/// ——那正是「点了之后界面卡十几分钟」的来源。
const DEPLOY_NO_ENGINE: &str = "部署引擎没有启动，暂时无法执行部署操作。";

/// 取一个字符串字段（已 trim）。
fn deploy_field(raw: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 秘密字段（密码 / 私钥口令）：**不 trim**。
///
/// 口令的首尾空格是内容的一部分（用户自己定的口令里就可能有空格），`deploy_field`
/// 的 `trim()` 会把一个能用的口令改坏成一个不能用的。但「全是空白」仍然当没填——
/// 与密码框旧行为在这一点上保持一致（用户敲了几个空格 = 他没想填）。
///
/// 返回空串表示「没填」。
fn deploy_secret_field(raw: &str, key: &str) -> String {
    let text = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    if text.trim().is_empty() {
        String::new()
    } else {
        text
    }
}

fn deploy_flag(raw: &str, key: &str) -> bool {    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get(key).and_then(|item| item.as_bool()))
        .unwrap_or(false)
}

fn deploy_ok(section: serde_json::Value) -> String {
    serde_json::json!({ "ok": true, "deployment": section }).to_string()
}

/// `user@host:port` → `Target`。用户名缺省 `root`、端口缺省 22（与命令行一致）。
///
/// 只解析形状，**不联网**：地址写得不对要在用户点「开始」的那一瞬间就说，
/// 而不是等引擎转十秒再说「连不上」。
///
/// `login_method` / `identity_file` 由调用方**显式传入**（而不是事后再填）：
/// 目标是凭据解析链的输入，漏填一次就会变成「选了私钥、却按密码去解析」。
fn deploy_target(
    spec: &str,
    login_method: crate::credential::CredentialKind,
    identity_file: &str,
) -> Result<crate::deploystore::Target, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("请填写服务器地址，例如 root@203.0.113.10".to_string());
    }
    if spec.contains(char::is_whitespace) {
        return Err("服务器地址里不能有空格。".to_string());
    }
    let (user, rest) = match spec.split_once('@') {
        Some((user, rest)) => (user.trim(), rest.trim()),
        None => ("root", spec),
    };
    if user.is_empty() {
        return Err("服务器地址缺少用户名，例如 root@203.0.113.10".to_string());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (
            host.trim(),
            port.trim()
                .parse::<u16>()
                .map_err(|_| "端口必须是 1 到 65535 之间的数字。".to_string())?,
        ),
        None => (rest, 22u16),
    };
    if host.is_empty() {
        return Err("服务器地址缺少主机名，例如 root@203.0.113.10".to_string());
    }
    // `rsplit_once(':')` 会把 `2001:db8::1` 拆成 `2001:db8:` + `1`。与其猜，不如说清。
    if host.contains(':') {
        return Err("暂不支持 IPv6 地址，请填写 IPv4 或域名。".to_string());
    }
    Ok(crate::deploystore::Target {
        host: host.to_string(),
        port,
        user: user.to_string(),
        server_record_id: None,
        login_method: login_method.as_str().to_string(),
        identity_file: identity_file.trim().to_string(),
    })
}

fn deploy_run_id(raw: &str) -> Result<String, String> {
    let run_id = deploy_field(raw, "runId");
    if run_id.is_empty() {
        return Err("缺少 RunId。".to_string());
    }
    if !crate::deploystore::is_run_id(&run_id) {
        return Err("RunId 的形状不对（必须是 UUID）。".to_string());
    }
    Ok(run_id)
}

fn deploy_load(ctx: &Ctx, run_id: &str) -> Result<crate::deploystore::RunRecord, String> {
    DeploymentStore::open(&ctx.root)
        .load(run_id)
        .map_err(|error| format!("读不到这条部署任务：{}", error.message))
}

/// 引擎里有没有这条记录的**活动 pass**。`None` 引擎即没有。
fn deploy_is_active(ctx: &Ctx, run_id: &str) -> bool {
    ctx.engine
        .as_ref()
        .map(|engine| engine.is_active(run_id))
        .unwrap_or(false)
}

/// 这条记录现在是不是「停在等凭据」。
fn deploy_needs_credentials(run: &crate::deploystore::RunRecord) -> bool {
    run.state == crate::deploystore::STATE_WAITING_USER
        || run
            .reason
            .as_ref()
            .map(|reason| reason.category == crate::deploystore::REASON_ACCESS_REQUIRED
                || reason.code == "AccessRequired")
            .unwrap_or(false)
}

/// 这台服务器记录里封着的凭据（DPAPI）。没有记录、解不开、绑定对不上 → `None`。
///
/// 解不开**不是错误**：它就是「需要用户重新输一次」的一种表达，和没存过同义。
///
/// 注意：**凭据解析的唯一入口是 [`deploy_resolve_credential`]**。这个函数只是
/// 「长期这一档」的实现，别在调用点拿它当全套答案——那样任务级凭据就永远读不到。
fn deploy_stored_credential(
    ctx: &Ctx,
    run: &crate::deploystore::RunRecord,
) -> Option<crate::credential::StoredCredential> {
    let id = run.target.server_record_id.as_ref()?;
    let records = serverstore::list(&ctx.root).ok()?;
    let record = records.into_iter().find(|item| &item.id == id)?;
    serverstore::credential(&ctx.root, &record).ok()
}

/// 按**目标**找长期凭据。新任务还没有 `server_record_id`（要等 Step0 落记录），
/// 所以不能只按 id 找——那会让「这台服务器早就记住过」的用户被要求再输一次。
fn deploy_credential_for_target(
    ctx: &Ctx,
    target: &crate::deploystore::Target,
) -> Option<crate::credential::StoredCredential> {
    let wanted = crate::ssh::Target::new(&target.host, target.port, &target.user);
    let record = serverstore::find_by_target(&ctx.root, &wanted).ok().flatten()?;
    serverstore::credential(&ctx.root, &record).ok()
}

/// 这条任务自己保存的凭据（任务作用域，最长 24 小时）。读不到 = 没有。
fn deploy_task_credential(
    ctx: &Ctx,
    run: &crate::deploystore::RunRecord,
) -> Option<crate::credential::StoredCredential> {
    let binding = crate::deploycred::binding_of(
        &run.run_id,
        &run.target.host,
        run.target.port,
        &run.target.user,
    );
    crate::deploycred::load(&ctx.root, &run.run_id, &binding)
}

/// 本次输入的那一档。`error` 是「读私钥文件失败」的原话（私钥模式下才有）。
///
/// 为什么把错误一起带着走：三档都没命中时，最有用的那句话是「找不到这个私钥文件：
/// C:\…」而不是笼统的「请选择私钥」。但**它排在三档之后**——文件被删了、24 小时
/// 内的任务级信封或长期信封里还留着同一把钥，那时应该直接续跑，不该因为文件没了
/// 就把一次还能完成的部署变成失败。
#[derive(Default)]
struct TypedCredential {
    credential: Option<crate::credential::Credential>,
    error: Option<String>,
}

/// 凭据解析的**唯一**顺序：本次输入 → 任务级（未过期）→ 长期（DPAPI）。
///
/// 三处（起始 / 继续 / 补输）都调这一个函数，是为了让「刚输过凭据却还被要求再输
/// 一次」这类自相矛盾的界面不可能出现：优先级只有一份。
///
/// **Kind 不匹配就跳过并记账**——绝不拿旧密码去试私钥（或反过来）。跨方式尝试的
/// 结果一定是 `Error::Auth`，用户看到的是「服务器拒绝」，而真正该做的是重填凭据。
/// 所以这里不命中时宁可说「登录方式已变化」。
fn deploy_resolve_credential(
    ctx: &Ctx,
    run: Option<&crate::deploystore::RunRecord>,
    target: &crate::deploystore::Target,
    method: crate::credential::CredentialKind,
    typed: TypedCredential,
    // 界面上的两个勾（r95，旧版的`DeployUseTaskCredential` / `DeployUseSaved`）：
    // false = 这一档不许用；typed 永远优先，不受这两个开关影响。
    use_task: bool,
    use_saved: bool,
) -> Result<Option<crate::credential::Credential>, String> {
    use crate::credential::CredentialKind;

    // 本次输入：它的 Kind 必然等于本次选择的方法，不需要比。
    if let Some(credential) = typed.credential {
        return Ok(Some(credential));
    }
    // 记账：有没有哪一档的登录方式与这次选的不同。
    let mut mismatched: Option<CredentialKind> = None;
    let mut take = |stored: crate::credential::StoredCredential| -> Option<crate::credential::Credential> {
        if stored.kind() != method {
            mismatched = Some(stored.kind());
            return None;
        }
        // 信封本身是好的、里面的私钥却坏了：当成「这一档没有」，继续往下找。
        stored.into_credential().ok()
    };
    if let Some(run) = run {
        if use_task {
            if let Some(credential) = deploy_task_credential(ctx, run).and_then(&mut take) {
                return Ok(Some(credential));
            }
        }
        if use_saved {
            // 长期这一档按记录里钉住的服务器记录 id 找；新任务还没有 id，落到下面按目标找。
            if let Some(credential) = deploy_stored_credential(ctx, run).and_then(&mut take) {
                return Ok(Some(credential));
            }
        }
    }
    if use_saved {
        if let Some(credential) = deploy_credential_for_target(ctx, target).and_then(&mut take) {
            return Ok(Some(credential));
        }
    }
    if let Some(previous) = mismatched {
        return Err(format!(
            "登录方式已变化：上次用的是{}，这次选的是{}。请填写本次要用的凭据。",
            previous.label(),
            method.label()
        ));
    }
    // 三档都没有：把「读私钥文件失败」的原话递出去（它比笼统的提示有用得多）。
    match typed.error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// 布尔字段，缺省值由调用方给。
///
/// 为什么不用 [`deploy_flag`]：那一条把「没写」当 `false`，而这里两个勾的缺省值
/// 刚好相反（老行为是「记住」，24 小时续跑则是新承诺、默认不给）。
fn deploy_flag_or(raw: &str, key: &str, fallback: bool) -> bool {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get(key).and_then(|item| item.as_bool()))
        .unwrap_or(fallback)
}

/// 线路名称：留空就按「自建 · 主机」自动命名（旧版的 `DeploymentCreate` 同一句）。
///
/// 形状检查放在这里而不是渲染层：名字会进任务列表、进导出摘要，含换行/制表符的名字
/// 会把那些地方排版搞坏，而用户看不出来是自己填的。
fn deploy_label(raw: &str, target: &crate::deploystore::Target) -> Result<String, String> {
    let given = deploy_field(raw, "label");
    if given.is_empty() {
        return Ok(format!("自建 · {}", target.host));
    }
    if given.chars().count() > 120 {
        return Err("线路名称最多 120 个字。".to_string());
    }
    if given.chars().any(char::is_control) {
        return Err("线路名称不能包含换行、制表符等控制字符。".to_string());
    }
    Ok(given)
}

/// 身份还对不对（**只读本地记录，不联网**）。
///
/// 对不上时返回一句给人看的话；`None` 表示没发现问题。
/// 联网核对留给 pass 自己（`decide_resume`），这里只挡「记录都没了还往里冲」。
fn deploy_identity_changed(ctx: &Ctx, run: &crate::deploystore::RunRecord) -> Option<String> {
    let id = run.target.server_record_id.as_ref()?;
    let records = serverstore::list(&ctx.root).ok()?;
    let record = records.into_iter().find(|item| &item.id == id)?;
    let recorded = run.identity.fingerprint.trim();
    if !recorded.is_empty() && record.fingerprint != recorded {
        return Some("服务器的身份与记录不一致（指纹变了），请重新核对指纹再继续。".to_string());
    }
    None
}

/// 把请求里的**非秘密**字段写进一条已有草稿。
///
/// 指纹的覆盖规则只有一条（契约 §4.16.10 J5）：`lane_key` 变了就是另一台服务器，
/// 指纹按请求为准（**可以是空**，否则 A 的指纹会跟着带到 B 上去）；`lane_key` 没变时
/// 只有请求带了非空指纹才覆盖——用户点「上一步」重新读一遍指纹，不该把草稿里已有的
/// 那一份抹成空。
///
/// `Attempts` / `CreatedAtUtc` / `Revision` 一律不在这里动：`Revision` 由
/// `DeploymentStore::save` 递增，另两个是「这条任务经历过什么」的既有事实。
fn deploy_apply_draft_fields(
    run: &mut crate::deploystore::RunRecord,
    label: &str,
    target: crate::deploystore::Target,
    fingerprint: &str,
) {
    let lane_changed = run.target.lane_key() != target.lane_key();
    run.label = label.to_string();
    run.target = target;
    if lane_changed {
        // 换了服务器：旧的那份「自动记住」结论与这台机器无关。
        run.identity.auto_trusted = false;
    }
    if lane_changed || !fingerprint.is_empty() {
        run.identity.fingerprint = fingerprint.to_string();
    }
}

/// 草稿到顶时的那句话。**必须给出去路**：只说「不行」而不说去哪儿放弃，用户就卡住了。
const DEPLOY_DRAFT_FULL: &str = "已经留着 3 份没填完的草稿，请先在任务列表里放弃一条。";

/// 「默认连接方式」的规范词：`Auto` / `Udp` / `Tcp`（旧版的`DeployTransport`）。
///
/// 空串 = 自动（旧请求与旧草稿零迁移）；表外值直接拒绝，不猜成自动——
/// 用户明明选了「兼容连接」而页面/后端有一边拼错时，静默退回自动会让人
/// 以为「选了没用」，而不是看到一句能改的错。
fn deploy_transport_field(raw: &str) -> Result<String, String> {
    let text = deploy_field(raw, "transport");
    match text.to_ascii_lowercase().as_str() {
        "" | "auto" => Ok("Auto".to_string()),
        "udp" => Ok("Udp".to_string()),
        "tcp" => Ok("Tcp".to_string()),
        _ => Err(format!(
            "默认连接方式只能是「自动选择」「标准连接」「兼容连接」（收到 {text}）。"
        )),
    }
}

/// 兼容连接的 TCP 首选端口。空 = 默认值；只接受 旧版的三个候选。
fn deploy_tcp_port_field(raw: &str) -> Result<u16, String> {
    let text = deploy_field(raw, "tcpPort");
    if text.is_empty() {
        return Ok(crate::deploy::TRANSPORT_PORT);
    }
    let port: u16 = text
        .parse()
        .map_err(|_| format!("TCP 首选端口要填数字（收到 {text}）。"))?;
    if !matches!(port, 443 | 8443 | 2443) {
        return Err(format!("TCP 首选端口仅支持 443、8443、2443（收到 {port}）。"));
    }
    Ok(port)
}

/// 兼容连接的 REALITY 握手域名。空 = 默认值。
fn deploy_server_name_field(raw: &str) -> Result<String, String> {
    let text = deploy_field(raw, "serverName");
    if text.is_empty() {
        return Ok(crate::deploy::TRANSPORT_SERVER_NAME.to_string());
    }
    if !crate::deploy::is_tls_server_name(&text) {
        return Err(format!(
            "TCP 握手目标必须是一个域名（例如 www.bing.com），收到 {text}。"
        ));
    }
    Ok(text)
}

/// 把三个非秘密的兼容连接选择写进记录的 `Plan`。**在任何落盘之前调用**。
fn deploy_apply_transport_fields(
    run: &mut crate::deploystore::RunRecord,
    transport: &str,
    tcp_port: u16,
    server_name: &str,
) {
    run.plan.transport = transport.to_string();
    run.plan.tcp_port = tcp_port;
    run.plan.server_name = server_name.to_string();
}

/// `deployment-draft-save`：把向导当前的非秘密字段幂等写进一条 `Draft` 记录。
///
/// 判据只有一条（契约 §4.16.10 J1）：**地址能解析成一台服务器就写，解析不了就一个字都不写**。
/// 判据就是 [`deploy_target`] 的那几道形状检查（缺用户名、缺主机名、端口不是 1–65535、
/// 含空格、IPv6）。`root@` 这种半截地址不是一个目标，落盘只会制造一条点不开的假任务。
///
/// 这是短命令：只做「校验 → 落盘」，不发 SSH、不投递引擎，所以它**不进**
/// `is_long_command` / `operation_budget`。
///
/// 秘密：请求里根本没有 `password` 这个字段（读也不会去读），草稿 JSON 与它的
/// 落盘文本里都不存在任何口令。私钥**文件内容**也一样——草稿只记路径
/// （`IdentityFile`），绝不在这里读文件：草稿是短命令，读密钥解析（bcrypt 100–300ms）
/// 会把一次「填到一半自动保存」变成卡顿。
fn deployment_draft_save_json(ctx: &Ctx, raw: &str) -> String {
    let spec = deploy_field(raw, "spec");
    let method = crate::credential::CredentialKind::parse(&deploy_field(raw, "loginMethod"));
    let identity_file = deploy_field(raw, "identityFile");
    let target = match deploy_target(&spec, method, &identity_file) {
        Ok(target) => target,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let fingerprint = deploy_field(raw, "fingerprint");
    // 兼容连接的三个选择也随草稿留着（旧版的 `TransportIndex` / `DeployTcpPort` /
    // `DeployServerName`）。无效值在这里就拒绝：草稿是「填到一半」的存档，
    // 存进一个用户下次也改不了的坏值，比不存更糟。
    let transport = match deploy_transport_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let tcp_port = match deploy_tcp_port_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let server_name = match deploy_server_name_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    // 两档凭据作用域的选择跟着草稿一起留着：用户接着填的时候，勾选不该回到默认值。
    // 缺省值见 `deploy_flag_or`：记住（老行为）= 是，24 小时续跑 = 否。
    let remember_saved = deploy_flag_or(raw, "remember", true);
    let remember_task = deploy_flag_or(raw, "rememberTask", false);
    let label = match deploy_label(raw, &target) {
        Ok(label) => label,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let requested = deploy_field(raw, "runId");
    if !requested.is_empty() && !crate::deploystore::is_run_id(&requested) {
        return refuse_with_code("RunId 的形状不对（必须是 UUID）。", ERROR_CLASS_USAGE);
    }

    let store = DeploymentStore::open(&ctx.root);
    let loaded = store.load_all();
    // 只要不是 `ok` 就**拒绝写**——两种「不知道」都算：
    //
    // - `failed`：目录都读不出来；
    // - `partial`：有条记录读不出来。后者才是容易漏的那个：那条读不出来的记录**可能
    //   正是同一台服务器的草稿**，看不见它，按 `lane_key` 去重就会失手、新建第二份；
    //   上限 3 也只会数到能读的那几条。
    //
    // 这与「列表能不能渲染 `partial`」是**两把不同的尺**（`LoadResult::is_usable` 回答
    // 的是前者）。去重要求的是「知道**全部**草稿」，所以这里用 `tasks_read != ok`。
    //
    // 拒绝只影响「保存」：页面照常可以填、可以 probe（写不进去是小事，
    // 填到一半被弹回去才是大事）。
    if loaded.tasks_read != crate::deploystore::READ_OK {
        return refuse_with_code(
            &format!(
                "读不到全部部署任务记录，无法保存草稿（否则同一台服务器可能多出一份）：{}",
                loaded.error
            ),
            ERROR_CLASS_CONFIG,
        );
    }

    let mut run = if requested.is_empty() {
        // 没有 runId：按 `lane_key`（`lower(host):port`）找已有草稿，命中就复用。
        match loaded
            .runs
            .iter()
            .find(|item| item.is_draft() && item.target.lane_key() == target.lane_key())
        {
            Some(existing) => existing.clone(),
            None => {
                // 新建前查上限：不同服务器的草稿最多 `MAX_DRAFTS` 条。
                let drafts = loaded.runs.iter().filter(|item| item.is_draft()).count();
                if drafts >= crate::deploystore::MAX_DRAFTS {
                    return refuse_with_code(DEPLOY_DRAFT_FULL, ERROR_CLASS_CONFLICT);
                }
                let run_id = crate::pairing::random_uuid_v4();
                let mut fresh = crate::deployrun::new_draft(
                    &run_id,
                    &label,
                    target.clone(),
                    &fingerprint,
                    &crate::deploystore::now_utc(),
                );
                fresh.remember_saved = remember_saved;
                fresh.remember_task = remember_task;
                deploy_apply_transport_fields(&mut fresh, &transport, tcp_port, &server_name);
                // `create` 会把 `Revision` 置 1 并写 `UpdatedAtUtc`。
                if let Err(error) = store.create(&mut fresh) {
                    return refuse_with_code(
                        &format!("没能把这份草稿写到磁盘：{}", error.message),
                        ERROR_CLASS_CONFIG,
                    );
                }
                return deploy_ok(serde_json::json!({
                    "Run": crate::deployrun::run_view(&fresh, false),
                    "RunId": fresh.run_id,
                    "Created": true,
                    "Message": "已保存这份草稿，关掉窗口后可以从任务列表接着填。",
                }));
            }
        }
    } else {
        match store.load(&requested) {
            Ok(run) => run,
            Err(error) => {
                return refuse_with_code(
                    &format!("读不到这条部署任务：{}", error.message),
                    ERROR_CLASS_CONFIG,
                )
            }
        }
    };

    // 走到这里只剩「更新已有草稿」一条路。带 runId 指向一条已经开始过的记录时，
    // 拒绝得越早越好：草稿这条路只接受草稿。
    if !run.is_draft() {
        return refuse_with_code(
            "这条任务已经开始过，不能当草稿用。",
            ERROR_CLASS_CONFLICT,
        );
    }
    deploy_apply_draft_fields(&mut run, &label, target, &fingerprint);
    run.remember_saved = remember_saved;
    run.remember_task = remember_task;
    deploy_apply_transport_fields(&mut run, &transport, tcp_port, &server_name);
    if let Err(error) = store.save(&mut run) {
        return refuse_with_code(
            &format!("没能把这份草稿写到磁盘：{}", error.message),
            ERROR_CLASS_CONFIG,
        );
    }
    deploy_ok(serde_json::json!({
        "Run": crate::deployrun::run_view(&run, false),
        "RunId": run.run_id,
        "Created": false,
        "Message": "已经更新这份草稿。",
    }))
}

/// `deployment-start`：校验 → **先落盘** → 再投递。
///
/// 顺序不能反：先投递再落盘时，一旦落盘失败，引擎已经在跑一条磁盘上不存在的任务，
/// 界面刷新就看不到它了（幽灵任务）。
///
/// 带 `runId` 时走「草稿复用」这条路（契约 §4.16.10 J5）：同一份文件接着用，
/// 不新建第二条；`Draft→Queued` 由引擎的 `enqueue` 处理（Draft→WaitingUser→Queued
/// 两步校验），状态机白名单一个字不改。
///
/// 凭据的两档作用域（界面上的两个勾）：
/// - `remember`（长期）→ 写进记录的 `RememberSaved`，由引擎 Step0 决定要不要写信封；
/// - `rememberTask`（任务级）→ 密码 DPAPI 封在 `<数据根>\deployments\credentials\<RunId>.bin`，
///   24 小时后失效，任务完成/取消就删。
///
/// 请求里没有凭据时按「这次任务保存的 → 长期保存的」去找；都没有就当场拒绝——
/// 让引擎跑一趟再回一句「Authentication failed」是把我们的疏忽变成用户的困惑。
fn deployment_start_json(ctx: &Ctx, raw: &str) -> String {
    use crate::credential::{Credential, CredentialKind};

    let spec = deploy_field(raw, "spec");
    let method = CredentialKind::parse(&deploy_field(raw, "loginMethod"));
    let identity_file = deploy_field(raw, "identityFile");
    let target = match deploy_target(&spec, method, &identity_file) {
        Ok(target) => target,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let Some(engine) = ctx.engine.clone() else {
        return refuse_with_code(DEPLOY_NO_ENGINE, ERROR_CLASS_ENVIRONMENT);
    };
    let fingerprint = deploy_field(raw, "fingerprint");
    // 默认连接方式 / TCP 端口 / 握手域名：三个都**在落盘与投递之前**校验。
    // 一个非法端口到了服务器脚本里只会变成一句看不懂的失败。
    let transport = match deploy_transport_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let tcp_port = match deploy_tcp_port_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let server_name = match deploy_server_name_field(raw) {
        Ok(value) => value,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    // 两档凭据作用域（界面上的两个勾）。缺省值见 `deploy_flag_or`：
    // 「记住登录资料」缺省是（老行为就是无条件记住），「24 小时续跑」缺省否
    // （那是一个新增的承诺，不能替用户先答应下来）。
    let remember_saved = deploy_flag_or(raw, "remember", true);
    let remember_task = deploy_flag_or(raw, "rememberTask", false);
    // 两个「使用已保存凭据」的勾（r95）：缺省都是 true，与旧版默认勾选一致。
    // 它们只管信封那两档；用户这次输入的口令永远优先。
    let use_task = deploy_flag_or(raw, "useTask", true);
    let use_saved = deploy_flag_or(raw, "useSaved", true);
    let label = match deploy_label(raw, &target) {
        Ok(label) => label,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let requested = deploy_field(raw, "runId");
    if !requested.is_empty() && !crate::deploystore::is_run_id(&requested) {
        return refuse_with_code("RunId 的形状不对（必须是 UUID）。", ERROR_CLASS_USAGE);
    }

    let store = DeploymentStore::open(&ctx.root);
    // 先读已有草稿：下一句要用**这条记录**的目标去翻「任务级凭据」，
    // 凭据必须在写任何东西之前就解析出来——拿不到就别落盘，免得留下一条
    // 注定卡在第一步的任务记录。
    let existing = if requested.is_empty() {
        None
    } else {
        match store.load(&requested) {
            Ok(run) => Some(run),
            Err(error) => {
                return refuse_with_code(
                    &format!("读不到这条部署任务：{}", error.message),
                    ERROR_CLASS_CONFIG,
                )
            }
        }
    };
    if let Some(run) = existing.as_ref() {
        if !run.is_draft() {
            return refuse_with_code(
                "这条任务已经开始过，不能当草稿用。",
                ERROR_CLASS_CONFLICT,
            );
        }
    }
    // 凭据：用户这次输入的优先，其次是这 **一次任务** 保存过的那份，最后是长期保存的。
    // 三档都要试：用户完全可能什么都没填，只因为「上次已经记住了」。
    //
    // 秘密字段**不 trim**（口令可以有首尾空格），见 `deploy_secret_field`。
    let typed_text = deploy_secret_field(raw, "password");
    let cred_target = existing
        .as_ref()
        .map(|run| run.target.clone())
        .unwrap_or_else(|| target.clone());
    let typed = match method {
        CredentialKind::Password => TypedCredential {
            credential: (!typed_text.is_empty()).then(|| Credential::password(typed_text)),
            error: None,
        },
        CredentialKind::Key => {
            if identity_file.is_empty() {
                // 没选文件：这一次没有「本次输入」，接着翻两档信封。
                TypedCredential::default()
            } else {
                match crate::credential::credential_from_key_file(
                    &identity_file,
                    (!typed_text.is_empty()).then_some(typed_text.as_str()),
                ) {
                    Ok(credential) => TypedCredential {
                        credential: Some(credential),
                        error: None,
                    },
                    // 路径与记录里的**不同**（或这次是新任务、还没有记录）：读失败就立刻拒绝。
                    // 拿上一次的钥去连，用户会以为「我选的这把能用」。
                    Err(message) => {
                        let same_as_record = existing
                            .as_ref()
                            .map(|run| run.target.identity_file == identity_file)
                            .unwrap_or(false);
                        if !same_as_record {
                            return refuse_with_code(&message, ERROR_CLASS_USAGE);
                        }
                        // 同一把钥（文件被移动/删除了）：允许回落到两档信封，
                        // 但把那句原话带着——三档都不命中时它才是最有用的提示。
                        TypedCredential {
                            credential: None,
                            error: Some(message),
                        }
                    }
                }
            }
        }
    };
    let credential = match deploy_resolve_credential(
        ctx,
        existing.as_ref(),
        &cred_target,
        method,
        typed,
        use_task,
        use_saved,
    ) {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            // 一条记录都还没写：此刻拒绝，磁盘上不会多出一条注定失败的任务。
            return refuse_with_code(
                match method {
                    CredentialKind::Key => "请选择 SSH 私钥文件；服务器密码与私钥口令分别填写。",
                    CredentialKind::Password => "请提供服务器登录密码，或选择 SSH 私钥登录。",
                },
                ERROR_CLASS_USAGE,
            );
        }
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };

    let mut record = match existing {
        None => {
            let run_id = crate::pairing::random_uuid_v4();
            let mut run = crate::deployrun::new_draft(
                &run_id,
                &label,
                target,
                &fingerprint,
                &crate::deploystore::now_utc(),
            );
            run.remember_saved = remember_saved;
            run.remember_task = remember_task;
            deploy_apply_transport_fields(&mut run, &transport, tcp_port, &server_name);
            if let Err(error) = store.create(&mut run) {
                return refuse_with_code(
                    &format!("没能把这条部署任务写到磁盘：{}", error.message),
                    ERROR_CLASS_CONFIG,
                );
            }
            run
        }
        Some(mut run) => {
            deploy_apply_draft_fields(&mut run, &label, target, &fingerprint);
            run.remember_saved = remember_saved;
            run.remember_task = remember_task;
            deploy_apply_transport_fields(&mut run, &transport, tcp_port, &server_name);
            // 先把选择写进记录再投递：引擎按记录里的 `RememberSaved` 决定要不要写信封，
            // 这里漏写一步，用户勾掉的那个勾就白勾了。
            if let Err(error) = store.save(&mut run) {
                return refuse_with_code(
                    &format!("没能把这条部署任务写到磁盘：{}", error.message),
                    ERROR_CLASS_CONFIG,
                );
            }
            run
        }
    };
    let run_id = record.run_id.clone();

    // 任务级凭据：勾了「中断后继续」才写，最长 24 小时，任务一结束就删。
    //
    // 写失败**不让部署失败**：这只是「回来接着做时少输一次凭据」的便利，
    // 为它挡下一次部署是本末倒置。失败时把记录上的承诺一起撤掉，
    // 免得记录上说「可以续跑」而磁盘上什么都没有。
    if record.remember_task {
        let binding = crate::deploycred::binding_of(
            &run_id,
            &record.target.host,
            record.target.port,
            &record.target.user,
        );
        if crate::deploycred::save(&ctx.root, &run_id, &binding, &credential).is_err() {
            record.remember_task = false;
            let _ = store.save(&mut record);
        }
    }

    // 交给引擎的是一份副本：表单/正文那一份马上就要 drop（`Secret` 的 `Drop` 会清零），
    // 而引擎要用它跑完整个过程。私钥本体是 `Arc`，复制不重跑 bcrypt。
    engine.start_run(&run_id, Some(credential.duplicate()));
    deploy_ok(serde_json::json!({
        "RunId": run_id,
        "Accepted": true,
        "Queued": true,
        "Message": "已受理，正在部署。",
    }))
}

/// `deployment-archive`：归档 / 恢复一条结果（P2-2）。
///
/// 三条口径：
/// - **归档不是删除**：只写记录上的 `ArchivedAtUtc`，文件、尝试历史、提醒都在。
///   删除记录是另一条路（更危险），这里不做。
/// - **只归档已经停下来的**：`Complete` / `Cancelled` / `NeedsAttention` / `Paused`。
///   在跑/排队/草稿一律 `conflict`——把一条正在部署的任务藏起来，等于让用户失去
///   对它唯一的入口。
/// - 归档后**不参与裁剪**（见 `prune_terminal`）：否则「归档」会在 7 天后变成
///   「悄悄删除」，那正是这一条最不能出的事。
fn deployment_archive_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    // `archived` 既可能是 JSON 布尔（页面发的就是 `json!(true)`），也可能是字符串
    // （命令行/管道的人手写的 "true"）。**不能用 `deploy_field`**：它只读字符串，
    // 遇到布尔 `false` 会读成空串，于是「恢复」被当成「再归档一次」——r73 的用例
    // 抓到的就是这一条。
    let archived = match serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get("archived").cloned())
    {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Bool(flag)) => flag,
        Some(serde_json::Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "" | "true" | "1" => true,
            "false" | "0" => false,
            _ => {
                return refuse_with_code(
                    "archived 只支持 true / false。",
                    ERROR_CLASS_USAGE,
                )
            }
        },
        Some(_) => {
            return refuse_with_code("archived 只支持 true / false。", ERROR_CLASS_USAGE)
        }
    };
    let store = DeploymentStore::open(&ctx.root);
    let mut run = match deploy_load(ctx, &run_id) {
        Ok(run) => run,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_CONFIG),
    };
    if archived {
        let allowed = matches!(
            run.state.as_str(),
            crate::deploystore::STATE_COMPLETE
                | crate::deploystore::STATE_CANCELLED
                | crate::deploystore::STATE_NEEDS_ATTENTION
                | crate::deploystore::STATE_PAUSED
        );
        if !allowed {
            return refuse_with_code(
                "这条任务还在进行中，等它停下来再归档。",
                ERROR_CLASS_CONFLICT,
            );
        }
    }
    run.archived_at_utc = if archived {
        Some(crate::deploystore::now_utc())
    } else {
        None
    };
    if let Err(error) = store.save(&mut run) {
        return refuse_with_code(
            &format!("没能把这条记录写回磁盘：{}", error.message),
            ERROR_CLASS_CONFIG,
        );
    }
    if archived {
        // 收起来的结果不该继续在「部署结果」里催：归档即视为看过。
        // 写失败不影响归档本身（提醒是附加品）。
        let _ = crate::reminder::mark_read(&ctx.root, &run_id);
    }
    deploy_ok(serde_json::json!({
        "RunId": run.run_id,
        "Archived": archived,
        "Message": if archived {
            "已归档：列表里不再显示，记录还在，随时可以恢复。"
        } else {
            "已恢复：这条任务回到列表。"
        },
    }))
}

/// `deployment-export`：把一条记录导出成诊断摘要（Markdown 默认 / JSON）。
///
/// 三条口径：
/// - **只读记录**：唯一的写入是数据根 `logs\exports\` 下的新文件。不接受调用方指定
///   任意路径（那等于给页面一个「写到任意位置」的入口）。
/// - **白名单投影**（见 `deployexport::projection`）：秘密不因为「记录以后加字段」被
///   顺带导出去。
/// - 短命令：不发 SSH、不投递引擎，所以不进 `is_long_command`。
fn deployment_export_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let Some(format) = crate::deployexport::Format::parse(&deploy_field(raw, "format")) else {
        return refuse_with_code("导出格式只支持 markdown 或 json。", ERROR_CLASS_USAGE);
    };
    let run = match deploy_load(ctx, &run_id) {
        Ok(run) => run,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_CONFIG),
    };
    let text = match crate::deployexport::render(&run, format, &crate::deploystore::now_utc()) {
        Ok(text) => text,
        // 与 `export_history` 同一口径：内部渲染失败是 `internal`（不是用户的错，
        // 也不是配置问题——重试一次可能就好了）。
        Err(message) => return refuse_with_code(&message, "internal"),
    };

    let dir = ctx.root.join("logs").join("exports");
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return refuse_with_code(
            &format!("创建导出目录失败：{error}"),
            ERROR_CLASS_CONFIG,
        );
    }
    // 文件名带任务短码：同一个 RunId 导出多次也一眼能认出来是哪条任务。
    let stamp = crate::model::now_epoch_secs();
    let short = crate::deployrun::run_short(&run_id);
    let mut path = None;
    for n in 0..1000u32 {
        let name = if n == 0 {
            format!("deploy-{short}-{stamp}.{}", format.extension())
        } else {
            format!("deploy-{short}-{stamp}-{n}.{}", format.extension())
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            path = Some(candidate);
            break;
        }
    }
    let Some(path) = path else {
        return refuse_with_code("导出目录里同名文件过多，请稍后重试", ERROR_CLASS_CONFIG);
    };
    let tmp = dir.join(format!(
        ".deploy-export-{}-{stamp}.tmp",
        std::process::id()
    ));
    if let Err(error) = std::fs::write(&tmp, text.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return refuse_with_code(&format!("写入导出文件失败：{error}"), ERROR_CLASS_CONFIG);
    }
    if let Err(error) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return refuse_with_code(&format!("保存导出文件失败：{error}"), ERROR_CLASS_CONFIG);
    }

    let message = format!(
        "已导出诊断摘要（{}）到 {}",
        format.extension().to_uppercase(),
        path.display()
    );
    serde_json::json!({
        "ok": true,
        "exportResult": {
            "ok": true,
            "path": path.to_string_lossy(),
            "bytes": text.len(),
            "format": format.extension(),
            "message": message,
        }
    })
    .to_string()
}

/// `deployment-list`：任务列表 + 三态读取结论。
///
/// 读取失败时 `ok:false`，但**仍然带 `deployment`**：页面要能同时看到
/// 「读不出来」和「刷新」两个东西。只回一个 error，页面就只剩空白。
fn deployment_list_json(ctx: &Ctx) -> String {
    let mut loaded = DeploymentStore::open(&ctx.root).load_all();
    // 启动恢复写盘失败时，记录**原样留在** `Running`（没有改动 = 没有说谎）。
    // 但界面要是照常渲染，那一行就变成了「正在部署」——正是 T04 明令禁止的
    // 「先显示 Running 让它自己好」。所以这里把结论压成 `failed`：
    // 宁可让人看到「这次读不出来」，也不给一个假的进行中。
    if let Some(engine) = ctx.engine.as_ref() {
        let failure = engine.recover_error();
        if !failure.is_empty() {
            loaded.tasks_read = crate::deploystore::READ_FAILED.to_string();
            loaded.error = failure;
        }
    }
    let now = crate::deploystore::parse_stamp(&crate::deploystore::now_utc()).unwrap_or(0);
    let tasks = crate::deployrun::project_tasks(&loaded.runs, |id| deploy_is_active(ctx, id));
    let deployments =
        crate::deployrun::project_deployments(&loaded.runs, |id| deploy_is_active(ctx, id), now);
    // 结果提醒（P1-3）：只给未读的那几条。读不出来**照实说**——静默当空会让
    // 「有一条结果没看」永远消失，而用户根本不知道自己错过了什么。
    let (reminders, reminders_error) = match crate::reminder::unread(&ctx.root) {
        Ok(items) => (
            items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "Id": item.id,
                        "RunId": item.run_id,
                        "Name": item.name,
                        "State": item.state,
                        "StateText": crate::deployrun::state_text(&item.state),
                        // 筛选（P2-1）要按类别分「失败 / 结果未知 / 身份 / 凭据」。
                        "ReasonCategory": item.category,
                        "Text": item.text,
                        "CreatedAtUtc": item.created_at_utc,
                    })
                })
                .collect::<Vec<_>>(),
            String::new(),
        ),
        Err(error) => (Vec::new(), error),
    };
    let usable = loaded.is_usable();
    let mut reply = serde_json::json!({
        "ok": usable,
        "deployment": {
            "TasksRead": loaded.tasks_read,
            "TasksReadError": loaded.error,
            "UnreadableCount": loaded.unreadable.len(),
            "Tasks": tasks,
            "Deployments": deployments,
            "Reminders": reminders,
            "RemindersError": reminders_error,
            "Archived": crate::deployrun::project_archived(&loaded.runs),
            // 草稿总览（C6）：几条、最旧一份放了几天、要不要提醒。
            // **只是统计与提示**：本产品不做自动过期，删不删由用户按。
            "Drafts": crate::deployrun::draft_summary(&loaded.runs, now),
        },
    });
    if !usable {
        reply["errorCode"] = serde_json::json!(ERROR_CLASS_CONFIG);
        reply["error"] = serde_json::json!(if loaded.error.is_empty() {
            "任务记录暂时读不出来。"
        } else {
            loaded.error.as_str()
        });
    }
    reply.to_string()
}

/// `deployment-get`：一条记录的完整投影（含四步与证据）。
fn deployment_get_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    match deploy_load(ctx, &run_id) {
        Ok(run) => {
            // 打开这条任务 = 看过它的结果：把它名下的未读提醒标已读（P1-3）。
            // 写失败不挡打开——提醒是附加品，不能因为一条通知写不进去就打不开任务。
            let _ = crate::reminder::mark_read(&ctx.root, &run_id);
            deploy_ok(serde_json::json!({
                "Run": crate::deployrun::run_view(&run, deploy_is_active(ctx, &run_id)),
            }))
        }
        Err(message) => refuse_with_code(&message, ERROR_CLASS_CONFIG),
    }
}

/// `deployment-continue`：**唯一**的「重试 / 继续 / 核对」入口。
///
/// 六步准入（架构文档 §3.5）：从磁盘重读 → 终态只打开 → 已在跑就幂等 →
/// 凭据不足不执行 → 身份对不上不执行 → 否则入队。第 5 步的联网核对留在
/// pass 里做（`decide_resume`）：短命令里发 SSH 就把「毫秒回包」变成「转圈十秒」。
fn deployment_continue_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let verify_only = deploy_flag(raw, "verifyOnly");
    let run = match deploy_load(ctx, &run_id) {
        Ok(run) => run,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_CONFIG),
    };
    // ② 终态：只打开，不执行（否则「继续」会把一条已完成的记录改回 Running）。
    if crate::deployrun::is_terminal_state(&run.state) {
        return deploy_ok(serde_json::json!({
            "RunId": run_id,
            "Accepted": false,
            "Queued": false,
            "Message": "这次部署已经结束，只能查看。",
        }));
    }
    // ②' 草稿：**拒绝**。草稿连一次密码都没拿到过，而 `continue` 会让引擎把它
    // 直接推进队列（`enqueue` 走 Draft→WaitingUser→Queued）——那等于一次没有密码的
    // 部署：用户会看到「正在部署」，然后卡在第一步。草稿的出口只有两个：
    // 「继续填写」（打开向导，校验地址与密码）或「放弃这份草稿」。
    if run.is_draft() {
        return refuse_with_code(
            "这是一份草稿，请先打开表单确认地址和密码再开始。",
            ERROR_CLASS_CONFLICT,
        );
    }
    let Some(engine) = ctx.engine.clone() else {
        return refuse_with_code(DEPLOY_NO_ENGINE, ERROR_CLASS_ENVIRONMENT);
    };
    // ③ 幂等：连点「继续」只产生一个有效后续操作。
    if engine.is_active(&run_id) || engine.shared().is_queued(&run_id) {
        return deploy_ok(serde_json::json!({
            "RunId": run_id,
            "Accepted": true,
            "Queued": true,
            "Message": "这次部署已经在进行中。",
        }));
    }
    // ④ 凭据：这次输入的 → 这次任务保存的 → DPAPI 里长期封着的。
    //    登录方式以**记录**为准（`run.target.login_kind()`），续跑页不重新选方式。
    use crate::credential::{Credential, CredentialKind};
    let method = run.target.login_kind();
    let typed_text = deploy_secret_field(raw, "password");
    let typed = match method {
        CredentialKind::Password => TypedCredential {
            credential: (!typed_text.is_empty()).then(|| Credential::password(typed_text.as_str())),
            error: None,
        },
        CredentialKind::Key => {
            // 路径来自记录本身：文件被移动/删除时**允许回落**到两档信封
            // （「同一台服务器、同一把钥」，24 小时续跑正是为了应付这种情况）。
            if run.target.identity_file.is_empty() {
                TypedCredential::default()
            } else {
                match crate::credential::credential_from_key_file(
                    &run.target.identity_file,
                    (!typed_text.is_empty()).then_some(typed_text.as_str()),
                ) {
                    Ok(credential) => TypedCredential {
                        credential: Some(credential),
                        error: None,
                    },
                    Err(message) => TypedCredential {
                        credential: None,
                        error: Some(message),
                    },
                }
            }
        }
    };
    // 续跑页没有这两个勾（r95 只在起始页画），缺省 true = 旧行为。
    let use_task = deploy_flag_or(raw, "useTask", true);
    let use_saved = deploy_flag_or(raw, "useSaved", true);
    let credential = match deploy_resolve_credential(
        ctx,
        Some(&run),
        &run.target,
        method,
        typed,
        use_task,
        use_saved,
    ) {
        Ok(credential) => credential,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    if credential.is_none() && deploy_needs_credentials(&run) {
        return refuse_with_code(
            match method {
                CredentialKind::Key =>
                    "这次部署停在需要登录凭据的地方：请填写私钥口令后再继续（私钥文件路径以记录为准）。",
                CredentialKind::Password =>
                    "这次部署停在需要登录凭据的地方：请填写服务器密码后再继续。",
            },
            ERROR_CLASS_USAGE,
        );
    }
    // 用户在详情页补输了一次凭据、而这条任务当初答应用它续跑：顺手把任务级凭据
    // 换成新的。不换的话，「补过的密码」只在这一次有效，下次断了又要再补一遍——
    // 而记录上写着「中断后可用这份资料继续」。
    if run.remember_task && !typed_text.is_empty() {
        let binding = crate::deploycred::binding_of(
            &run.run_id,
            &run.target.host,
            run.target.port,
            &run.target.user,
        );
        if let Some(credential) = credential.as_ref() {
            let _ = crate::deploycred::save(&ctx.root, &run.run_id, &binding, credential);
        }
    }
    // ⑤ 身份（只读本地记录）。对不上就写进记录并拒绝——绝不能「先连上去看看」。
    if let Some(message) = deploy_identity_changed(ctx, &run) {
        engine.note_blocked(
            &run_id,
            REASON_IDENTITY_CHANGED,
            ERROR_CLASS_CONFLICT,
            "IdentityChanged",
            &message,
            NEXT_ACTION_CONFIRM_FINGERPRINT,
        );
        return refuse_with_code(&message, ERROR_CLASS_CONFLICT);
    }
    // ⑥ 入队。
    let queued = engine.shared().lane_busy(&run.target.lane_key());
    engine.continue_run(&run_id, credential, verify_only);
    deploy_ok(serde_json::json!({
        "RunId": run_id,
        "Accepted": true,
        "Queued": queued,
        "Message": if verify_only {
            "已受理：先做只读核对，不会重发任何写命令。"
        } else {
            "已受理，正在继续。"
        },
    }))
}

/// `deployment-pause`：只在步骤边界生效，这里只记意图。
fn deployment_pause_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let Some(engine) = ctx.engine.clone() else {
        return refuse_with_code(DEPLOY_NO_ENGINE, ERROR_CLASS_ENVIRONMENT);
    };
    if !engine.is_active(&run_id) {
        return refuse_with_code(
            "这次部署现在没有在跑的步骤，无法暂停。",
            ERROR_CLASS_ENVIRONMENT,
        );
    }
    engine.pause(&run_id);
    deploy_ok(serde_json::json!({
        "RunId": run_id,
        "PauseRequested": true,
        "Message": "已受理：当前步骤做完之后暂停。",
    }))
}

/// `deployment-cancel`：草稿走「删除」，其余终态拒绝；有未决写时受理但说清「要等这一步做完」。
fn deployment_cancel_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let run = match deploy_load(ctx, &run_id) {
        Ok(run) => run,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_CONFIG),
    };
    // ① 草稿：`store.remove`，**不碰引擎**。
    //
    // 为什么不是写 `Cancelled`：草稿没有检查点、没碰过服务器、没有证据可留。写成终态
    // 会让它挤进底部任务条（最近 24 小时终态）与 20 条保留名额，而用户要的是
    // 「当它没发生过」。也不存在与裁剪冲突的问题：文件没了就不在裁剪判据里。
    //
    // 这条分支必须在「有没有引擎」之前：草稿的丢弃是纯本地删除，没有引擎也该能做。
    if run.is_draft() {
        if let Err(error) = DeploymentStore::open(&ctx.root).remove(&run_id) {
            return refuse_with_code(
                &format!("没能丢掉这份草稿：{}", error.message),
                ERROR_CLASS_CONFIG,
            );
        }
        // 「放弃」也是任务结束：草稿上如果留着任务级凭据，跟着一起删。
        crate::deploycred::remove(&ctx.root, &run_id);
        return deploy_ok(serde_json::json!({
            "RunId": run_id,
            "CancelRequested": true,
            "Discarded": true,
            "Message": "已放弃这份草稿，没有留下任务记录。",
        }));
    }
    if crate::deployrun::is_terminal_state(&run.state) {
        return refuse_with_code("这次部署已经结束，无需取消。", ERROR_CLASS_CONFLICT);
    }
    let Some(engine) = ctx.engine.clone() else {
        return refuse_with_code(DEPLOY_NO_ENGINE, ERROR_CLASS_ENVIRONMENT);
    };
    // 已经发出写命令的那一步**不能中断**：中断会留下「可能写了、也没人核对」的现场。
    // 所以受理，但把话说明白——用户得知道按钮不是立即生效的。
    let pending_kind = run.pending_operation.as_ref().map(|pending| pending.outcome.clone());
    let holds_write = pending_kind
        .as_deref()
        .map(|outcome| outcome == crate::deploystore::OUTCOME_PENDING)
        .unwrap_or(false);
    engine.cancel(&run_id);
    // 受理即删任务级凭据：这条任务不会再需要它了（正在跑的那一步手里已经有一份
    // 内存里的密码）。留着等引擎写终态才删，中间就有一个「用户以为已经取消、
    // 密码还躺在磁盘上」的窗口。
    crate::deploycred::remove(&ctx.root, &run_id);
    deploy_ok(serde_json::json!({
        "RunId": run_id,
        "CancelRequested": true,
        "Message": if holds_write {
            "已受理：这一步已经发出写命令，要等它做完（并核对完）才会取消。"
        } else {
            "已受理：当前步骤做完之后取消。"
        },
    }))
}

/// `deployment-background`：把「用户可以关掉页面」这件事记进记录。
fn deployment_background_json(ctx: &Ctx, raw: &str) -> String {
    let run_id = match deploy_run_id(raw) {
        Ok(run_id) => run_id,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let Some(engine) = ctx.engine.clone() else {
        return refuse_with_code(DEPLOY_NO_ENGINE, ERROR_CLASS_ENVIRONMENT);
    };
    if !engine.is_active(&run_id) {
        // 没有活动 pass 时「转后台」是一句空话：页面会关掉，而没人接着跑。
        return refuse_with_code(
            "这次部署没有在后台运行的步骤，无法转入后台。",
            ERROR_CLASS_ENVIRONMENT,
        );
    }
    engine.background(&run_id);
    deploy_ok(serde_json::json!({
        "RunId": run_id,
        "Accepted": true,
        "Message": "已受理，部署在后台继续。",
    }))
}

/// 旧的「自助部署」界面入口：**已退役**。
///
/// 它不是被删掉，而是被 [`deployment-start`] 取代：旧实现把「检查 → 装服务端 →
/// 装兼容连接 → 接本机 → 登记线路」一口气跑在**一条长命令**里（事务门要占十几分钟），
/// 中途断网、关窗、崩溃之后没人知道到底做到哪一步。新流程把每一步的结论写进记录，
/// 所以这里只留一句引导——**不保留第二种行为**，否则同一次点击会有两条实现。
///
/// 命令行 `--server-setup` 仍然可用：它不经过 IPC，走的是 `servercmd::setup`。
fn server_setup_retired_json() -> String {
    refuse_with_code(
        "界面上的「自助部署」已改用部署任务（deployment-start）：每一步都会记下来，中断后可以接着做。命令行 --server-setup 仍然可用。",
        crate::deploystore::ERROR_CLASS_USAGE,
    )
}

/// 从线路名里取服务器主机：`自建 · 203.0.113.10（兼容连接）` → `203.0.113.10`。
///
/// 线路名是用户可改的，所以这只是**快路径**；取不到时退回「只有一条服务器记录就用它」。
fn host_from_line_name(name: &str) -> Option<String> {
    let rest = name.split('·').nth(1)?.trim();
    let host = rest
        .trim_end_matches("（兼容连接）")
        .trim_end_matches('）')
        .trim();
    (!host.is_empty()).then(|| host.to_string())
}

/// 「服务器与设备」：只读。列出这台服务器上登记的设备。
///
/// 数据源与服务端检查是**同一段脚本**（`deploy::inspect`），所以命令行
/// `--server-inspect` 与这个页面看到的设备列表不会给出两个答案。
fn refuse_devices(message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        // 与 `serverSetup` 同一条规矩：失败也要带自己的键，否则页面收不到错误，
        // 只会停在「正在读取…」。
        "serverDevices": {"error": message},
    })
    .to_string()
}

/// 线路 → 服务器记录 → 凭据 → 部署规格。设备页与「撤销设备」共用这一套判定，
/// 免得出现「能看不能改」或「能改不能看」两种答案。
struct LineServer {
    record: crate::serverstore::ServerRecord,
    spec: crate::deploy::Spec,
    credential: crate::credential::Credential,
}

/// 按服务器记录 id 取记录、凭据与部署规格（不依赖线路）。
///
/// 服务器页的「删除记录 / 卸载服务」都从记录本身进入：卸载后线路可能已经删掉，
/// 那时还要能删记录；反过来，只有线路能进的话，这两种操作就永远互相卡住。
fn server_by_id(ctx: &Ctx, id: &str) -> Result<LineServer, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("缺少服务器记录 id。".to_string());
    }
    let records = crate::serverstore::list(&ctx.root).map_err(|error| error.message)?;
    let record = records
        .iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "本机没有这条服务器记录。".to_string())?
        .clone();
    let credential = crate::serverstore::credential(&ctx.root, &record)
        .map_err(|error| error.message)?
        .into_credential()?;
    let spec = crate::deploy::Spec::for_record(&record.id);
    Ok(LineServer {
        record,
        spec,
        credential,
    })
}

fn line_server(ctx: &Ctx, line_id: &str) -> Result<LineServer, String> {
    let cfg_path = ctx.root.join(crate::config::DEFAULT_PATH);
    let cfg = match crate::config::load(&cfg_path) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return Err("还没有配置线路。".to_string()),
        Err(error) => return Err(error.to_string()),
    };
    let Some(line) = cfg
        .lines
        .iter()
        .find(|item| item.id == line_id)
        .or_else(|| cfg.current_line())
    else {
        return Err("找不到这条线路。".to_string());
    };
    let records = crate::serverstore::list(&ctx.root).map_err(|error| error.message)?;
    let wanted = host_from_line_name(&line.name);
    let record = records
        .iter()
        .find(|item| wanted.as_deref() == Some(item.host.as_str()))
        // 线路被改过名时退回「只有一条记录」：那是绝大多数情况，比直接报错有用。
        .or_else(|| (records.len() == 1).then(|| &records[0]))
        .ok_or_else(|| {
            "这条线路不是本机部署的服务器线路（找不到对应的服务器记录）。".to_string()
        })?
        .clone();
    let credential = crate::serverstore::credential(&ctx.root, &record)
        .map_err(|error| error.message)?
        .into_credential()?;
    let spec = crate::deploy::Spec::for_record(&record.id);
    Ok(LineServer {
        record,
        spec,
        credential,
    })
}

/// 给已有线路补一条兼容连接（旧版的「旧线路维护：增加 TCP」）。
///
/// 用途：服务器只放行 TCP、或当初部署时兼容连接没装上——这条线路在本机只有标准（UDP）
/// 一条，用户没有别的入口把它补成兼容。
///
/// 前置与旧版同一条：**要一次服务器管理登录**。凭据取本机保存的那份（`line_server`），
/// 没有就如实拒绝，不给「点一下试试看」的按钮。
///
/// 幂等：`install_transport_step` 对已装过的服务器回 `reused`；`register_lines_verified`
/// 按同一份 `client.conf` 复用已有线路，不会多出一条重复的兼容线。
fn line_add_compatible_json(ctx: &Ctx, raw: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let line_id = parsed
        .get("line")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if line_id.is_empty() {
        return refuse("缺少线路 id（请求里没有 line 字段）");
    }
    // 与切换/删除线路同一条规矩：连接中改配置会让还原凭据与实际引擎对不上。
    if busy(ctx) {
        return refuse("请先断开再改线路：连接中改动配置会让还原凭据与实际引擎对不上");
    }
    let server = match line_server(ctx, &line_id) {
        Ok(server) => server,
        Err(message) => return refuse(&message),
    };
    // 先读后装：已经装过就复用（不重装、不换身份），否则装一次。
    let installed = match crate::servercmd::install_transport_step(
        &server.record,
        crate::ssh::Auth::from_option(Some(&server.credential)),
        &server.spec,
        &mut |_| {},
    ) {
        Ok(Some(installed)) => installed,
        Ok(None) => return refuse("服务器上没有装成兼容连接：请稍后重试，或先跑一次诊断"),
        Err(error) => return refuse_with_code(&error.message, "environment"),
    };
    // 参数写进**这条线路自己的附属文件**（旧版是一条线路存两套方式）。
    // 不再登记第二条线路：同一台服务器出现两张卡片，卡片上的开关还会按不动。
    let cfg = match crate::config::load(&ctx.root.join(crate::config::DEFAULT_PATH)) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return refuse("找不到配置文件（config.json），请先导入线路"),
        Err(error) => return refuse(&format!("读取线路配置失败：{error}")),
    };
    let Some(line) = cfg.find_line(&line_id) else {
        return refuse("找不到这条线路（配置里没有它）");
    };
    let params = crate::config::LineCompatible {
        server: server.record.host.clone(),
        port: installed.port,
        uuid: installed.uuid.clone(),
        server_name: installed.server_name.clone(),
        reality_public_key: installed.public_key.clone(),
        reality_short_id: installed.short_id.clone(),
    };
    if let Err(error) = line.save_compatible(&ctx.root, &params) {
        return refuse_with_code(&format!("保存兼容连接参数失败：{error}"), "config");
    }
    let name = line.name.clone();
    let message = if installed.identity == "reused" {
        format!(
            "服务器上已经有兼容连接（TCP {}，握手域名 {}），已挂到线路「{name}」上。回线路页点「兼容」即可。",
            installed.port, installed.server_name
        )
    } else {
        format!(
            "已给线路「{name}」补上兼容连接（TCP {}，握手域名 {}）。回线路页点「兼容」即可。",
            installed.port, installed.server_name
        )
    };
    serde_json::json!({
        "ok": true,
        "lineCompatible": {
            "LineId": line_id,
            "Port": installed.port,
            "ServerName": installed.server_name,
            "Reused": installed.identity == "reused",
            "Message": message,
        }
    })
    .to_string()
}

fn server_devices_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let line_id = parsed
        .as_ref()
        .and_then(|v| v.get("Id"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let LineServer {
        record,
        spec,
        credential,
    } = match line_server(ctx, &line_id) {
        Ok(server) => server,
        Err(message) => return refuse_devices(&message),
    };
    let environment = match crate::deploy::inspect(
        &record.target(),
        &credential,
        Some(&record.fingerprint),
        Some(&spec.interface),
        std::time::Duration::from_secs(30),
    ) {
        Ok(environment) => environment,
        Err(error) => return refuse_devices(&error.to_string()),
    };

    // 设备显示名在服务器侧的 `device-names.json` 里（按公钥存）。读不到不影响
    // 设备列表：部署创建的设备本来就没有名字，旧服务器也可能没装这个子命令。
    let (names, names_error) = match crate::pairhost::device_names(
        &record.target(),
        &credential,
        Some(&record.fingerprint),
    ) {
        Ok(value) => (
            value
                .get("names")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            String::new(),
        ),
        Err(error) => (serde_json::json!({}), error.message),
    };
    let name_of = |key: &str| {
        names
            .get(key)
            .and_then(|entry| entry.get("Name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    // 本机是哪一台：拿 `client.conf` 的私钥算出公钥，与设备列表比对。
    // 这一步只在**本机**做，不需要额外 SSH。
    let own_key = std::fs::read_to_string(ctx.root.join("servers").join(&record.id).join("client.conf"))
        .ok()
        .and_then(|text| crate::pairing::line::parse_client_conf(&text).ok())
        .and_then(|conf| crate::pairing::keys::tunnel_public_from_private_b64(&conf.private_key).ok());

    let devices: Vec<serde_json::Value> = environment
        .tunnel
        .as_ref()
        .map(|tunnel| {
            tunnel
                .devices
                .iter()
                .map(|device| {
                    serde_json::json!({
                        "address": device.host(),
                        "name": name_of(&device.public_key),
                        "publicKey": device.public_key,
                        "shortKey": &device.public_key.chars().take(8).collect::<String>(),
                        "handshake": device.handshake,
                        "rxBytes": device.rx_bytes,
                        "txBytes": device.tx_bytes,
                        "endpoint": device.endpoint,
                        "thisDevice": own_key.as_deref() == Some(device.public_key.as_str()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // 名字还在、peer 已经不在了：这是撤销后留下的孤儿名称记录。
    // 设备页单独列出来，给一个「删除记录」；不能让它永远藏在服务器上。
    //
    // **只有隧道真的读到了才敢算孤儿**：接口没起来时 `devices` 是空数组，
    // 照着比对会把所有名字都判成孤儿——那时删一条就是删掉一台还在用的设备。
    let tunnel_listed = environment
        .tunnel
        .as_ref()
        .map(|tunnel| tunnel.up)
        .unwrap_or(false);
    let peer_keys: std::collections::HashSet<&str> = devices
        .iter()
        .filter_map(|device| device.get("publicKey").and_then(serde_json::Value::as_str))
        .collect();
    let orphan_names: Vec<serde_json::Value> = if tunnel_listed {
        names
            .as_object()
            .map(|map| {
                map.iter()
                    .filter(|(key, _)| !peer_keys.contains(key.as_str()))
                    .map(|(key, entry)| {
                        serde_json::json!({
                            "publicKey": key,
                            "shortKey": key.chars().take(8).collect::<String>(),
                            "name": entry.get("Name").and_then(serde_json::Value::as_str).unwrap_or(""),
                            "updatedAtUtc": entry.get("UpdatedAtUtc").and_then(serde_json::Value::as_str).unwrap_or(""),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    serde_json::json!({
        "ok": true,
        "serverDevices": {
            "server": {
                "id": record.id,
                "name": record.name,
                "host": record.host,
                "port": record.port,
                "user": record.user,
                "fingerprint": record.fingerprint,
                "interface": spec.interface,
                "udpPort": spec.port,
                "subnet": spec.subnet,
            },
            "tunnel": environment.tunnel.as_ref().map(|tunnel| serde_json::json!({
                "up": tunnel.up,
                "latestHandshake": tunnel.latest_handshake,
                "rxBytes": tunnel.rx_bytes,
                "txBytes": tunnel.tx_bytes,
            })),
            // 名字服务不可用时页面要如实说「改名不可用」，而不是给一个点了报错的按钮。
            "namesAvailable": names_error.is_empty(),
            "namesError": names_error,
            "devices": devices,
            "orphanNames": orphan_names,
        },
    })
    .to_string()
}

/// 撤销设备的失败回包：与设备页同一条规矩——失败也要带自己的键，
/// 否则页面只会停在「正在移除…」。
fn refuse_revoke(message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "serverRevoke": {"error": message},
    })
    .to_string()
}

/// 「撤销设备」：把一台设备从服务端摘掉（删它那一个 `[Peer]` 段 + `wg syncconf` 热应用）。
///
/// 两个前置拒绝都在**连服务器之前**做完：公钥形状不对、目标就是本机。
/// 本机那条尤其重要——撤销它等于把用户自己锁在外面，而页面上又看不出来是哪一台。
fn server_revoke_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let line_id = field("Id");
    let public_key = field("PublicKey");
    if public_key.len() != 44
        || !public_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return refuse_revoke("这台设备的公钥形状不对，无法撤销。请先刷新列表再试一次。");
    }
    let LineServer {
        record,
        spec,
        credential,
    } = match line_server(ctx, &line_id) {
        Ok(server) => server,
        Err(message) => return refuse_revoke(&message),
    };
    // 本机公钥从 client.conf 推：这一条判断只在本机做，不需要额外 SSH。
    let own_key = std::fs::read_to_string(
        ctx.root
            .join("servers")
            .join(&record.id)
            .join("client.conf"),
    )
    .ok()
    .and_then(|text| crate::pairing::line::parse_client_conf(&text).ok())
    .and_then(|conf| crate::pairing::keys::tunnel_public_from_private_b64(&conf.private_key).ok());
    if own_key.as_deref() == Some(public_key.as_str()) {
        return refuse_revoke(
            "这是本机正在用的密钥。撤销它会让这台电脑立刻失去隧道，请从别的设备上操作。",
        );
    }
    let ack = match crate::deploy::revoke_peer(
        &record.target(),
        &credential,
        &record.fingerprint,
        &spec,
        &public_key,
        std::time::Duration::from_secs(40),
    ) {
        Ok(ack) => ack,
        Err(error) => return refuse_revoke(&error.to_string()),
    };
    serde_json::json!({
        "ok": true,
        "serverRevoke": {
            "publicKey": ack.public_key,
            "peers": ack.peers,
            "address": record.address(),
        },
    })
    .to_string()
}

/// 删除已撤销设备的名称记录：失败也要带自己的键，设备页才不会把它当成整页读失败。
fn refuse_forget(message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "serverDeviceForget": {"error": message},
    })
    .to_string()
}

/// C1「设备记录删除」：设备撤销后 peer 消失了，但 `device-names.json` 里的名字
/// 条目还在。设备页从 `wg` 读列表，看不见它，于是永远清不掉。这里只删那条名称
/// 记录——不动 peer（撤销负责）、不动邀请审计（历史要留）。
fn server_device_forget_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let line_id = field("Id");
    let public_key = field("PublicKey");
    if public_key.len() != 44
        || !public_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return refuse_forget("这台设备的公钥形状不对，无法删除记录。请刷新列表再试。");
    }
    let LineServer {
        record,
        spec: _spec,
        credential,
    } = match line_server(ctx, &line_id) {
        Ok(server) => server,
        Err(message) => return refuse_forget(&message),
    };
    // 本机设备的名称记录绝不能删：它还在隧道上，删了只会让设备页少一个名字。
    let own_key = std::fs::read_to_string(
        ctx.root
            .join("servers")
            .join(&record.id)
            .join("client.conf"),
    )
    .ok()
    .and_then(|text| crate::pairing::line::parse_client_conf(&text).ok())
    .and_then(|conf| crate::pairing::keys::tunnel_public_from_private_b64(&conf.private_key).ok());
    if own_key.as_deref() == Some(public_key.as_str()) {
        return refuse_forget("这是本机正在用的设备，不能删除它的记录。");
    }
    match crate::pairhost::forget_device(
        &record.target(),
        &credential,
        Some(record.fingerprint.as_str()),
        &public_key,
    ) {
        Ok(value) => serde_json::json!({
            "ok": true,
            "serverDeviceForget": {
                "publicKey": public_key,
                "removed": value.get("removed").and_then(serde_json::Value::as_bool).unwrap_or(false),
            },
        })
        .to_string(),
        Err(error) => refuse_forget(&error.message),
    }
}

fn refuse(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

fn server_remove_refuse(message: &str, code: &str) -> String {
    serde_json::json!({"ok": false, "error": message, "errorCode": code}).to_string()
}

/// 设备命令失败也要带自己的键：长命令收尾时页面靠它区分「这条失败」与
/// 「设备列表整个读不出来」，后者才会把整页换成错误卡。
fn server_device_refuse(message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "serverDeviceRename": {"error": message},
    })
    .to_string()
}

/// 当前 Unix 秒。恢复包时间戳只需要「大概是什么时候」，不需要毫秒。
fn recovery_now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn recovery_ok(section: serde_json::Value) -> String {
    serde_json::json!({ "ok": true, "recovery": section }).to_string()
}

/// `recovery-export`：把一台服务器（可选带凭据）加密成恢复包。**不发 SSH。**
///
/// 凭据来源按「本次填写的 → 已保存的」两档：
/// - 填了私钥文件 → 读文件、按口令解析；
/// - 只填了口令 → 密码凭据；
/// - 都没填 → 用这台服务器保存的登录资料（没有就拒绝，不导出空凭据）。
fn recovery_export_json(ctx: &Ctx, raw: &str) -> String {
    use crate::credential::Credential;

    let server_id = deploy_field(raw, "serverId");
    if server_id.is_empty() {
        return refuse_with_code("请先选择一台服务器。", ERROR_CLASS_USAGE);
    }
    let records = match serverstore::list(&ctx.root) {
        Ok(items) => items,
        Err(error) => return refuse_with_code(&error.message, ERROR_CLASS_CONFIG),
    };
    let Some(record) = records.into_iter().find(|item| item.id == server_id) else {
        return refuse_with_code("找不到这台服务器记录，请刷新后再试。", ERROR_CLASS_USAGE);
    };
    let password = deploy_secret_field(raw, "password");
    if password.chars().count() < crate::recovery::PASSWORD_MIN {
        return refuse_with_code(
            &format!(
                "恢复包密码至少 {} 个字符。",
                crate::recovery::PASSWORD_MIN
            ),
            ERROR_CLASS_USAGE,
        );
    }
    let include = deploy_flag_or(raw, "includeCredential", false);
    let mut credential: Option<Credential> = None;
    if include {
        let identity_file = deploy_field(raw, "identityFile");
        let typed = deploy_secret_field(raw, "credentialPassword");
        if !identity_file.is_empty() {
            match crate::credential::credential_from_key_file(
                &identity_file,
                (!typed.is_empty()).then_some(typed.as_str()),
            ) {
                Ok(item) => credential = Some(item),
                Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
            }
        } else if !typed.is_empty() {
            credential = Some(Credential::password(typed));
        } else {
            match serverstore::credential(&ctx.root, &record) {
                Ok(stored) => match stored.into_credential() {
                    Ok(item) => credential = Some(item),
                    Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
                },
                Err(_) => {
                    return refuse_with_code(
                        "要包含登录资料，请填写 SSH 密码或选择 SSH 私钥文件；这台服务器当前也没有保存的登录资料。",
                        ERROR_CLASS_USAGE,
                    )
                }
            }
        }
    }
    let created_at = crate::deploystore::now_utc();
    let package = match crate::recovery::export(
        &record,
        credential.as_ref(),
        &password,
        &created_at,
    ) {
        Ok(package) => package,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let file_name = crate::recovery::default_file_name(recovery_now_unix());
    recovery_ok(serde_json::json!({
        "ServerId": record.id,
        "Name": record.name,
        "Address": record.address(),
        "IncludesCredential": include,
        "FileName": file_name,
        "Package": package,
        "Message": "恢复包已加密。请把它与密码分开保存。",
    }))
}

/// `recovery-import`：解密并登记一条待核验的服务器记录。**不启用线路、不发 SSH。**
fn recovery_import_json(ctx: &Ctx, raw: &str) -> String {
    let package = deploy_field(raw, "package");
    if package.is_empty() {
        return refuse_with_code("请粘贴恢复包内容，或选择恢复包文件。", ERROR_CLASS_USAGE);
    }
    let password = deploy_secret_field(raw, "password");
    let imported = match crate::recovery::import(&package, &password) {
        Ok(imported) => imported,
        Err(message) => return refuse_with_code(&message, ERROR_CLASS_USAGE),
    };
    let record = match crate::recovery::register(&ctx.root, &imported, recovery_now_unix()) {
        Ok(record) => record,
        Err(message) => {
            let code = if message.contains("不一致") {
                ERROR_CLASS_CONFLICT
            } else {
                ERROR_CLASS_CONFIG
            };
            return refuse_with_code(&message, code);
        }
    };
    recovery_ok(serde_json::json!({
        "ServerId": record.id,
        "Name": record.name,
        "Address": record.address(),
        "IncludesCredential": imported.includes_credential,
        "Message": "管理资料已登记，实际登录与服务器身份仍待核验。",
    }))
}

/// 删除本机服务器记录（C7）。**先拒绝「还有线路用到它」**：
/// 线路还在、凭据没了的现场，后续邀请/重新部署都会找不到记录，用户只会看到
/// 「这台线路不归你管」这类误报。宁可不删，也不留半套。
fn server_remove_json(ctx: &Ctx, raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return server_remove_refuse("请求不是合法 JSON", "usage");
    };
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if id.is_empty() {
        return server_remove_refuse("缺少服务器记录 id（请求里没有 id 字段）", "usage");
    }
    let items = match server_items(ctx) {
        Ok(items) => items,
        Err(message) => return server_remove_refuse(&message, "config"),
    };
    let Some(item) = items.iter().find(|item| {
        item.get("Id").and_then(serde_json::Value::as_str) == Some(id.as_str())
    }) else {
        return server_remove_refuse("本机没有这条服务器记录。", "config");
    };
    let lines = item
        .get("LineIds")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if lines > 0 {
        return server_remove_refuse(
            &format!("还有 {lines} 条线路用到这台服务器；请先删除这些线路，再删服务器记录。"),
            "conflict",
        );
    }
    match crate::serverstore::remove(&ctx.root, &id) {
        Ok(()) => {
            let servers = server_items(ctx).unwrap_or_default();
            serde_json::json!({"ok": true, "servers": servers}).to_string()
        }
        Err(error) => server_remove_refuse(&error.message, "environment"),
    }
}

fn server_cleanup_refuse(message: &str, code: &str) -> String {
    serde_json::json!({"ok": false, "error": message, "errorCode": code}).to_string()
}

/// 两条清理命令共用的请求解析：只要一个 `id`。
fn server_cleanup_id(raw: &str) -> Result<String, String> {
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|_| "请求不是合法 JSON".to_string())?;
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if id.is_empty() {
        return Err("缺少服务器记录 id（请求里没有 id 字段）".to_string());
    }
    Ok(id)
}

/// 记录本体 + 「有几条线路用到它」。
///
/// 两件事都从 `server_items` 那一份来源取：页面渲染的、判断时看的、要删的是**同一条**。
/// 线路归属只有那一处算法（比 `outbounds[].server` 的地址），这里不另写一套。
fn server_cleanup_target(
    ctx: &Ctx,
    id: &str,
) -> Result<(serverstore::ServerRecord, usize), String> {
    let items = server_items(ctx)?;
    let Some(item) = items
        .iter()
        .find(|item| item.get("Id").and_then(serde_json::Value::as_str) == Some(id))
    else {
        return Err("本机没有这条服务器记录。".to_string());
    };
    let lines = item
        .get("LineIds")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    // 回包要的是「给人看的身份字段」与「删哪个目录」，那只有类型化的记录给得准。
    let records = serverstore::list(&ctx.root).map_err(|error| error.message)?;
    let Some(record) = records.into_iter().find(|record| record.id == id) else {
        return Err("本机没有这条服务器记录。".to_string());
    };
    Ok((record, lines))
}

/// 「删除本机部署资料」的只读预览：**一个字节都不写**（不建目录、不删文件、
/// 不动提醒文件），只是把要删的东西数清楚。
fn server_cleanup_preview_json(ctx: &Ctx, raw: &str) -> String {
    let id = match server_cleanup_id(raw) {
        Ok(id) => id,
        Err(message) => return server_cleanup_refuse(&message, "usage"),
    };
    let (record, lines) = match server_cleanup_target(ctx, &id) {
        Ok(found) => found,
        Err(message) => return server_cleanup_refuse(&message, "config"),
    };
    match crate::servercleanup::assess(&ctx.root, &record, lines) {
        Ok(assessment) => serde_json::json!({
            "ok": true,
            "serverCleanup": assessment.to_json(),
        })
        .to_string(),
        // 读不出来就照实说：当成「0 条」继续走，下一步就是删掉一个我们并不了解的东西。
        Err(message) => server_cleanup_refuse(&message, "config"),
    }
}

/// 「删除本机部署资料」：真执行。
///
/// 有 `Failed` 时 `ok` 仍是 `true`：记录已经删了一半，把它报成「整体失败」会让用户
/// 以为什么都没发生，于是再点一次、再看到同一句失败。结论与没删掉的项都在
/// `serverCleanupResult` 里。
fn server_cleanup_json(ctx: &Ctx, raw: &str) -> String {
    let id = match server_cleanup_id(raw) {
        Ok(id) => id,
        Err(message) => return server_cleanup_refuse(&message, "usage"),
    };
    let (record, lines) = match server_cleanup_target(ctx, &id) {
        Ok(found) => found,
        Err(message) => return server_cleanup_refuse(&message, "config"),
    };
    match crate::servercleanup::cleanup(&ctx.root, &record, lines) {
        Ok(outcome) => {
            let servers = server_items(ctx).unwrap_or_default();
            serde_json::json!({
                "ok": true,
                "serverCleanupResult": outcome.to_json(),
                "servers": servers,
            })
            .to_string()
        }
        Err(crate::servercleanup::Refusal::Blocked(message)) => {
            server_cleanup_refuse(&message, "conflict")
        }
        Err(crate::servercleanup::Refusal::Config(message)) => {
            server_cleanup_refuse(&message, "config")
        }
    }
}

/// 设备改名（C1）：按公钥写服务器上的 `device-names.json`，成功后整页刷新。
fn server_device_rename_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let line_id = field("Id");
    let public_key = field("PublicKey");
    let name = field("Name");
    if public_key.len() != 44
        || !public_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return server_device_refuse("这台设备的公钥形状不对，无法改名。请先刷新列表再试一次。", "usage");
    }
    if name.is_empty() || name.chars().count() > 64 {
        return server_device_refuse("设备名称须为 1 至 64 个字符。", "usage");
    }
    if name.chars().any(char::is_control) {
        return server_device_refuse("设备名称不能包含换行、制表符等控制字符。", "usage");
    }
    let LineServer {
        record, credential, ..
    } = match line_server(ctx, &line_id) {
        Ok(server) => server,
        Err(message) => return server_device_refuse(&message, "config"),
    };
    match crate::pairhost::rename_device(
        &record.target(),
        &credential,
        Some(&record.fingerprint),
        &public_key,
        &name,
    ) {
        // 成功后重新读一遍设备页：名字来自服务器，不能让页面自己编。
        Ok(_) => server_devices_json(ctx, raw),
        Err(error) => server_device_refuse(&error.message, "environment"),
    }
}

fn server_uninstall_preview_refuse(message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "serverUninstallPreview": {"error": message},
    })
    .to_string()
}

fn server_uninstall_refuse(message: &str, code: &str) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "errorCode": code,
        "serverUninstall": {"error": message},
    })
    .to_string()
}

/// 卸载服务器通道服务（C1）：只读预览。算清影响面，**不在这一步动服务器**。
fn server_uninstall_preview_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let id = parsed
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let LineServer {
        record,
        spec,
        credential,
    } = match server_by_id(ctx, &id) {
        Ok(server) => server,
        Err(message) => return server_uninstall_preview_refuse(&message, "config"),
    };
    let local_lines = server_items(ctx)
        .ok()
        .and_then(|items| {
            items
                .iter()
                .find(|item| {
                    item.get("Id").and_then(serde_json::Value::as_str) == Some(record.id.as_str())
                })
                .and_then(|item| item.get("LineIds"))
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
        })
        .unwrap_or(0);
    let environment = match crate::deploy::inspect(
        &record.target(),
        &credential,
        Some(&record.fingerprint),
        Some(&spec.interface),
        std::time::Duration::from_secs(30),
    ) {
        Ok(environment) => environment,
        Err(error) => return server_uninstall_preview_refuse(&error.to_string(), "environment"),
    };
    let tunnel_up = environment
        .tunnel
        .as_ref()
        .map(|tunnel| tunnel.up)
        .unwrap_or(false);
    let affected = environment
        .tunnel
        .as_ref()
        .map(|tunnel| tunnel.devices.len())
        .unwrap_or(0);
    let mut blocked = Vec::new();
    if busy(ctx) {
        blocked.push(serde_json::json!({
            "Code": "Busy",
            "Message": "连接还在运行：请先断开再卸载，否则接口被停掉会立刻断线。",
        }));
    }
    let mut warnings = vec![serde_json::json!({
        "Code": "CloudNotReleased",
        "Message": "卸载不会退订云服务器，云服务商仍会计费。",
    })];
    if local_lines > 0 {
        warnings.push(serde_json::json!({
            "Code": "LocalLines",
            "Message": format!(
                "这台电脑还有 {local_lines} 条线路指向它；卸载后这些线路会连不上，不会自动切换或删除。"
            ),
        }));
    }
    serde_json::json!({
        "ok": true,
        "serverUninstallPreview": {
            "Id": record.id,
            "Name": record.name,
            "Host": record.host,
            "Interface": spec.interface,
            "TunnelUp": tunnel_up,
            "AffectedDevices": affected,
            "LocalLines": local_lines,
            "Eligible": blocked.is_empty(),
            "Blocked": blocked,
            "Warnings": warnings,
        },
    })
    .to_string()
}

/// 卸载服务器通道服务（C1）：真执行。**前置拒绝在连服务器之前**做完。
fn server_uninstall_json(ctx: &Ctx, raw: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let id = parsed
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let LineServer {
        record,
        spec,
        credential,
    } = match server_by_id(ctx, &id) {
        Ok(server) => server,
        Err(message) => return server_uninstall_refuse(&message, "config"),
    };
    if busy(ctx) {
        return server_uninstall_refuse(
            "连接还在运行：请先断开再卸载，否则接口被停掉会立刻断线。",
            "environment",
        );
    }
    let ack = match crate::deploy::uninstall(
        &record.target(),
        &credential,
        &record.fingerprint,
        &spec,
        std::time::Duration::from_secs(120),
    ) {
        Ok(ack) => ack,
        Err(error) => return server_uninstall_refuse(&error.to_string(), "environment"),
    };
    let servers = server_items(ctx).unwrap_or_default();
    serde_json::json!({
        "ok": true,
        "serverUninstall": {
            "Id": record.id,
            "Name": record.name,
            "Host": record.host,
            "TransportRemoved": ack.transport_removed,
            "InviteRemoved": ack.invite_removed,
            "InterfacePresent": ack.interface_present,
        },
        "servers": servers,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// 管道机械（从事故前备份原样恢复：纯传输层，与业务改动无关）。
// ---------------------------------------------------------------------------

/// 处理一条请求的函数。抽成类型是为了能在测试里换成「慢 handler」，
/// 验证长命令不会把 ping/status 一起堵住。
type Handler = dyn Fn(&str, &Ctx) -> String + Send + Sync + 'static;

/// 在后台线程里监听。`stop` 置位后退出 accept 循环。
///
/// 每个连接一个线程：请求是一问一答，很短，不值得搞线程池。**这点很关键**——
/// `connect` 在链路里要跑满「起引擎（含 800ms 存活宽限）+ 自检（最多 2s）」，
/// 如果在 accept 循环里同步做，`ping` 会跟着超时，`main` 里 1.5s 的 `wait_ready` 就会误判「控制接口不可用」。
pub fn serve(name: String, stop: Arc<AtomicBool>, ctx: Ctx) -> std::io::Result<()> {
    let handler: Arc<Handler> = Arc::new(handle_line_with);
    serve_with(name, stop, ctx, handler)
}

fn serve_with(
    name: String,
    stop: Arc<AtomicBool>,
    ctx: Ctx,
    handler: Arc<Handler>,
) -> std::io::Result<()> {
    let ns = make_name(&name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listener = ListenerOptions::new().name(ns).create_sync()?;
    // 串行闸门由 Ctx 注入并与 WebView 共享；只有长命令抢锁，ping/status 直接过。
    let gate = Arc::clone(&ctx.transaction_gate);
    for conn in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let h = Arc::clone(&handler);
        let c = ctx.clone();
        let g = Arc::clone(&gate);
        std::thread::spawn(move || {
            let _ = respond(&mut stream, &c, h.as_ref(), &g);
        });
    }
    Ok(())
}

/// 会长时间占住工作线程、并且会改「正在发生的事」的命令：连接/断开、导入、诊断、
/// 还原、以及配对的两步。
///
/// 它们必须**串行**：并发跑两个 `pair-join` 会撞同一批固定名的临时文件
/// （`lines/<id>.json.tmp`、`config.json.tmp`），rename 失败或互相覆盖配置——
/// 后写者赢、前一条线路凭空消失。`busy()` 只挡「已经连上」，挡不住「正在连」，
/// 所以配对这两条也必须在白名单里（界面走 `Step::Long`、管道走同一道门）。
/// 不属于长操作、但需要独占配置或本地记录读改写的命令。
///
/// 只在 UI/管道入口尝试 try_lock，锁被长操作持有时立即拒绝；
/// 不把这些即时操作升级为 is_long_command（否则会卡住 WebView UI）。
pub fn is_short_write_command(line: &str) -> bool {
    matches!(
        command_name(line).as_deref(),
        Some("use")
            | Some("remove")
            | Some("rename-line")
            | Some("split-add")
            | Some("split-remove")
            | Some("split-reset-trade-domains")
            | Some("agents-save")
            | Some("agents-lane")
            | Some("exit-set")
            | Some("set-transport")
            | Some("set-mode")
            | Some("set-engine")
            | Some("line-network-set")
            | Some("settings")
            | Some("delete-cleanup-retry")
            | Some("provider-add")
            | Some("provider-remove")
            | Some("server-rename")
            | Some("server-remove")
            | Some("server-cleanup")
            | Some("recovery-import")
    )
}

pub fn is_long_command(line: &str) -> bool {
    matches!(
        command_name(line).as_deref(),
        Some("connect")
            | Some("disconnect")
            | Some("diagnose")
            | Some("restore")
            | Some("import")
            | Some("measure-latency")
            | Some("use-compatible")
            | Some("pair-verify")
            | Some("pair-join")
            // 离线交接：生成 3072 位密钥 + 落登记；完成时要解封授权并写线路与配置。
            // 两步都可能几百毫秒到几秒，不能占 UI 线程，也必须与连接/断开串行。
            | Some("pair-offline-request")
            | Some("pair-offline-complete")
            // 离线批准：一次 SSH 往返（先推脚本再签发），与在线邀请同一条通道。
            | Some("invite-authorize")
            // 按记录重试（A6）：内部会真的再跑一次连接/断开/诊断，与它们同一条闸门。
            | Some("operation-retry")
            // 自动选路（A8）：会起两次临时引擎真拨候选，绝不能再让第二个连接并发跑。
            | Some("auto-route")
            // 连接中自动切换：内部会断开、探测、重连，必须与连接/断开同一条闸门。
            | Some("auto-reroute")
            // 自助部署：探指纹要一次 SSH 握手，装服务端要下载 20 MB 并起服务。
            // 走长命令通道而不是同步命令——同步会把界面卡死几分钟。
            //
            // 注意这里**没有** `server-setup`：界面那条路已退役（改成返回 usage 的
            // 一句引导），命令行走 `servercmd::setup`，不经过 IPC。留着它只会让人以为
            // 「还有一条会跑十几分钟的长命令」。
            | Some("server-probe")
            // 设备列表要一次 SSH 往返（读隧道与每台设备），不能同步做。
            | Some("server-devices")
            // 设备改名也要 SSH（推脚本 + 写服务器上的名字文件）。
            | Some("server-device-rename")
            | Some("server-device-forget")
            // 撤销设备也要 SSH：改服务端配置 + 热应用，同样不能阻塞 UI 线程。
            | Some("server-revoke")
            // 卸载预览要 SSH 读隧道状态；卸载本身是 SSH 写操作，都不能占 UI 线程。
            | Some("server-uninstall-preview")
            | Some("server-uninstall")
            // 补兼容连接：一次 SSH（可能还要装 20 MB 中转组件），与卸载同量级。
            | Some("line-add-compatible")
            // 邀请的四条全是服务器往返：装身份要上传脚本 + 生成密钥 + 起服务，
            // 签发要一次签名往返。放同步通道会把界面卡住十几秒。
            | Some("invite-init")
            | Some("invite-create")
            | Some("invite-status")
            | Some("invite-cancel")
            // 可达性自检要真连一次 18443（TCP + TLS 握手），不能占着 UI 线程。
            | Some("invite-reachability")
            // 自动判定还要 SSH 读服务状态，必要时在内部重装并重启接收服务。
            | Some("invite-preflight")
            // 交易保护显式动作：可能等 UAC + WFP 事务，不能卡 UI 线程。
            | Some("guard-verify")
            | Some("guard-install")
            | Some("guard-sync")
            | Some("guard-remove")
    )
}

fn respond(
    stream: &mut LocalSocketStream,
    ctx: &Ctx,
    handler: &Handler,
    gate: &std::sync::Mutex<()>,
) -> std::io::Result<()> {
    // 不克隆流：在作用域里借出去读一行，读完再把可变借用还回来写。
    // 协议是一问一答，不存在「读一半还要继续读」的情况。
    let reply = {
        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim();
        if is_long_command(line) {
            // 锁中毒也要继续服务：一个命令 panic 不该让控制接口从此不可用。
            let _guard = gate.lock().unwrap_or_else(|e| e.into_inner());
            handler(line, ctx)
        } else if is_short_write_command(line) {
            // 短命令必须立即响应：不能在 UI 上等一个可能花数分钟的 SSH 事务。
            match gate.try_lock() {
                Ok(_guard) => handler(line, ctx),
                Err(std::sync::TryLockError::Poisoned(e)) => {
                    let _guard = e.into_inner();
                    handler(line, ctx)
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    refuse("当前有其他操作正在进行，配置修改未执行，请稍后重试")
                }
            }
        } else {
            handler(line, ctx)
        }
    };
    stream.write_all(reply.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// 探测控制接口是否可用：连得上并拿到 `ok:true` 才算。
/// 任何失败（没监听、超时、响应不对）都返回 false——控制面不可用就是不可用。
pub fn ping(name: &str, timeout_ms: u64) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    let n = name.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(one_shot(&n));
    });
    matches!(rx.recv_timeout(Duration::from_millis(timeout_ms)), Ok(true))
}

fn one_shot(name: &str) -> bool {
    matches!(request(name, r#"{"cmd":"ping"}"#), Some(l) if l.contains("\"ok\":true"))
}

/// 发一条请求，读回一行响应。连不上/读不出就返回 None。
fn request(name: &str, body: &str) -> Option<String> {
    let ns = make_name(name).ok()?;
    let mut stream = LocalSocketStream::connect(ns).ok()?;
    stream.write_all(body.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader.read_line(&mut line).ok()?;
    }
    Some(line)
}

/// 等到管道真正可用（或超时）。启动期用，避免「刚 bind 就 ping 失败」。
pub fn wait_ready(name: &str, timeout_ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if ping(name, 100) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

// ---------------------------------------------------------------------------
// 单元测试：原用例随 13:53 的截断事故丢失，按既定契约重建。
// 回包形状/拒绝文案/零副作用断言与丢失前一致（见 bak\RECOVERY-ipc.md）。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// 两线路的 schema 2 配置，写进临时根的 config.json 并返回解析结果。
    /// 单测全部从这里出发：管道层读到什么、写回什么，都以这份磁盘文件为准。
    fn write_cfg(root: &PathBuf, selected: &str) -> AppConfig {
        let c = crate::config::parse(&format!(
            r#"{{"schema":2,"selected":"{selected}","lines":[
                {{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"}},
                {{"id":"L2","name":"线路乙","proxy_endpoint":"127.0.0.1:17902"}}
            ]}}"#
        ))
        .expect("测试配置必须是合法 JSON");
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &c).expect("写入测试配置");
        c
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-ipc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::create_dir_all(&p);
        p
    }

    /// `server-probe` 的坏输入必须在**连网之前**就被拒。
    #[test]
    fn the_probe_command_refuses_bad_input_before_touching_the_network() {
        let root = std::env::temp_dir().join(format!("tcrs-ipc-deploy-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);

        let reply = server_probe_json(&ctx, r#"{"cmd":"server-probe","spec":""}"#);
        assert!(reply.contains("服务器地址"), "{reply}");
        let reply = server_probe_json(&ctx, r#"{"cmd":"server-probe","spec":"root203.0.113.10"}"#);
        assert!(reply.contains("用户名@主机"), "{reply}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 旧的界面入口已退役：**任何**输入都回 `usage` 并指向 `deployment-start`。
    ///
    /// 这条用例的作用是防止「悄悄把旧实现放回来」——两条部署路径并存时，
    /// 同一次点击会有两种行为，而用户只看到其中一个。
    #[test]
    fn the_old_ui_deploy_entry_is_retired_with_a_pointer_to_the_new_one() {
        let root = tmp_root("setup-retired");
        let ctx = ctx_with(None, &root);

        for raw in [
            r#"{"cmd":"server-setup","spec":""}"#,
            r#"{"cmd":"server-setup","spec":"root@203.0.113.10","password":"x"}"#,
        ] {
            let reply = handle_line_with(raw, &ctx);
            let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(value["ok"], serde_json::json!(false), "{reply}");
            assert_eq!(value["errorCode"], serde_json::json!("usage"), "{reply}");
            let text = value["error"].as_str().unwrap_or("");
            assert!(text.contains("deployment-start"), "必须指向新入口：{reply}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 部署中心：8 条短命令 ----------

    fn draft_for(root: &PathBuf, run_id: &str, state: &str) -> crate::deploystore::RunRecord {
        let store = DeploymentStore::open(root);
        let mut run = crate::deployrun::new_draft(
            run_id,
            "自建 · 203.0.113.10",
            crate::deploystore::Target {
                host: "203.0.113.10".to_string(),
                port: 22,
                user: "root".to_string(),
                server_record_id: None,
                ..Default::default()
            },
            "SHA256:AAAA",
            "2026-11-09T00:00:00Z",
        );
        store.create(&mut run).expect("建记录必须成功");
        if state != crate::deploystore::STATE_DRAFT {
            let mut stored = store.load(run_id).unwrap();
            stored.state = state.to_string();
            if crate::deployrun::is_terminal_state(state) {
                stored.finished_at_utc = Some(crate::deploystore::now_utc());
            }
            store.save(&mut stored).unwrap();
        }
        store.load(run_id).unwrap()
    }

    /// 手写的提醒文件（不是 `note` 写的）也要能被列表读出来。
    ///
    /// 这条防的是「落盘格式只有写的那一半认」：脚本/旧版本/人工修过的文件
    /// 形状只要合法就必须能读——否则页面上永远看不到那条结果。
    #[test]
    fn a_handwritten_reminder_file_reaches_the_list() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-ipc-reminder-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("deployments")).unwrap();
        std::fs::write(
            root.join("deployments").join("reminders.json"),
            r#"{"Schema":1,"Kind":"TradeChannel.DeployReminders","Reminders":[
                {"Id":"r-1","RunId":"a7100000-1111-4111-8111-111111111111",
                 "Name":"自建 · 203.0.113.10","State":"Complete","Step":4,"Code":"",
                 "Text":"部署完成","CreatedAtUtc":"2026-11-12T11:00:00Z","ReadAtUtc":null}]}"#,
        )
        .unwrap();
        let ctx = ctx_with(None, &root);
        let listed = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(
            listed["deployment"]["Reminders"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        assert_eq!(
            listed["deployment"]["Reminders"][0]["StateText"],
            serde_json::json!("已完成")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P2-3：导出一份诊断摘要——文件在 `logs\exports\`，内容说清状态与失败点，且不含秘密。
    #[test]
    fn exporting_a_diagnostic_summary_writes_a_file_without_secrets() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let run_id = "d1000000-1111-4111-8111-111111111111";
        draft_for(&root, run_id, crate::deploystore::STATE_NEEDS_ATTENTION);
        // 让原因与失败步骤都出现（摘要才有可读的内容）。
        {
            let store = crate::deploystore::DeploymentStore::open(&root);
            let mut run = store.load(run_id).unwrap();
            run.step = Some(1);
            run.reason = Some(crate::deploystore::Reason::now(
                crate::deploystore::REASON_FAILED,
                crate::deploystore::ERROR_CLASS_ENVIRONMENT,
                "ListenFailed",
                "端口被占用",
            ));
            run.steps[1].status = crate::deploystore::STEP_STATUS_FAILED.to_string();
            store.save(&mut run).unwrap();
        }

        let reply = call(
            &format!(r#"{{"cmd":"deployment-export","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(reply["ok"], serde_json::json!(true), "{reply}");
        let path = reply["exportResult"]["path"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(path.ends_with(".md"), "默认导出 Markdown：{path}");
        assert!(
            path.contains(r"logs\exports") || path.contains("logs/exports"),
            "{path}"
        );
        let text = std::fs::read_to_string(&path).expect("导出文件必须真的存在");
        for needle in ["# 部署诊断摘要", run_id, "ListenFailed", "端口被占用"] {
            assert!(text.contains(needle), "摘要里缺 {needle}：
{text}");
        }
        for forbidden in ["password", "PRIVATE KEY", "private_key"] {
            assert!(
                !text.to_lowercase().contains(&forbidden.to_lowercase()),
                "摘要里出现了 {forbidden}"
            );
        }

        // 同一秒内再导出一次：文件名要退让，不能覆盖上一份。
        let again = call(
            &format!(r#"{{"cmd":"deployment-export","runId":"{run_id}"}}"#),
            &ctx,
        );
        let path2 = again["exportResult"]["path"].as_str().unwrap_or("");
        assert_ne!(path, path2, "同名文件不许互相覆盖");
        assert!(std::path::Path::new(path2).is_file());

        // JSON 格式。
        let as_json = call(
            &format!(r#"{{"cmd":"deployment-export","runId":"{run_id}","format":"json"}}"#),
            &ctx,
        );
        let json_path = as_json["exportResult"]["path"].as_str().unwrap_or("");
        assert!(json_path.ends_with(".json"), "{json_path}");
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();
        assert_eq!(parsed["Kind"], serde_json::json!("TradeChannel.DeployDiagnostic"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// P2-2：归档只写 `ArchivedAtUtc`——列表里消失、文件还在、裁剪跳过、随时能恢复。
    #[test]
    fn archiving_hides_a_result_without_deleting_it() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-archive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let run_id = "e1000000-1111-4111-8111-111111111111";
        let run = draft_for(&root, run_id, crate::deploystore::STATE_COMPLETE);
        // 顺手留一条未读提醒：归档应当把它标记成已读（收起来的结果不该继续催）。
        crate::reminder::note(&root, &run).expect("收提醒");
        assert_eq!(crate::reminder::unread(&root).unwrap().len(), 1);

        let reply = call(
            &format!(r#"{{"cmd":"deployment-archive","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(reply["ok"], serde_json::json!(true), "{reply}");
        assert_eq!(reply["deployment"]["Archived"], serde_json::json!(true));

        let listed = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(
            listed["deployment"]["Deployments"].as_array().map(Vec::len),
            Some(0),
            "归档的不进底部队列：{listed}"
        );
        assert_eq!(
            listed["deployment"]["Archived"].as_array().map(Vec::len),
            Some(1),
            "但「已归档」里要看得到：{listed}"
        );
        assert!(
            root.join("deployments")
                .join("runs")
                .join(format!("{run_id}.json"))
                .is_file(),
            "归档不是删除：文件必须还在"
        );
        assert!(
            crate::reminder::unread(&root).unwrap().is_empty(),
            "归档即视为看过"
        );

        // 裁剪（keep=0, 不按时间）会删掉所有**没归档**的终态，归档的要留着。
        let report = crate::deploystore::DeploymentStore::open(&root).prune_terminal(0, 0, |_| false);
        assert_eq!(report.removed, 0, "归档的记录不参与裁剪：{report:?}");
        assert!(root
            .join("deployments")
            .join("runs")
            .join(format!("{run_id}.json"))
            .is_file());

        // 恢复：回到列表。
        let back = call(
            &format!(r#"{{"cmd":"deployment-archive","runId":"{run_id}","archived":false}}"#),
            &ctx,
        );
        assert_eq!(back["ok"], serde_json::json!(true), "{back}");
        let listed = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(
            listed["deployment"]["Archived"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(
            listed["deployment"]["Deployments"].as_array().map(Vec::len),
            Some(1),
            "恢复后重新出现在底部队列：{listed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 还在跑的任务不许归档；参数只认 true/false。
    #[test]
    fn archiving_a_running_task_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-archive-running-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let run_id = "e2000000-1111-4111-8111-111111111111";
        draft_for(&root, run_id, crate::deploystore::STATE_RUNNING);

        let refused = call(
            &format!(r#"{{"cmd":"deployment-archive","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(refused["ok"], serde_json::json!(false), "{refused}");
        assert_eq!(refused["errorCode"], serde_json::json!("conflict"), "{refused}");
        // 记录一个字节没动。
        let stored = crate::deploystore::DeploymentStore::open(&root)
            .load(run_id)
            .unwrap();
        assert!(!stored.is_archived(), "拒绝时不许留下半个归档");

        let bad = call(
            &format!(r#"{{"cmd":"deployment-archive","runId":"{run_id}","archived":"maybe"}}"#),
            &ctx,
        );
        assert_eq!(bad["errorCode"], serde_json::json!("usage"), "{bad}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// C6：列表带出「几份草稿、最旧一份放了几天」——只是统计，不删任何东西。
    #[test]
    fn the_task_list_reports_draft_count_and_age() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-drafts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let fresh_id = "c1000000-1111-4111-8111-111111111111";
        let old_id = "c2000000-1111-4111-8111-111111111111";
        draft_for(&root, fresh_id, crate::deploystore::STATE_DRAFT);
        draft_for(&root, old_id, crate::deploystore::STATE_DRAFT);
        // 把其中一份改成「很久以前开始填的」。
        {
            let store = DeploymentStore::open(&root);
            let mut run = store.load(old_id).unwrap();
            run.created_at_utc = Some("2026-10-01T00:00:00Z".to_string());
            store.save(&mut run).unwrap();
        }

        let listed = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        let drafts = &listed["deployment"]["Drafts"];
        assert_eq!(drafts["Count"], serde_json::json!(2), "{listed}");
        assert_eq!(drafts["Max"], serde_json::json!(crate::deploystore::MAX_DRAFTS));
        assert_eq!(drafts["HasAge"], serde_json::json!(true));
        assert!(
            drafts["OldestDays"].as_u64().unwrap_or(0) >= 30,
            "40 多天前的草稿不许算成新的：{drafts}"
        );
        assert_eq!(drafts["Stale"], serde_json::json!(true));
        assert!(
            drafts["Summary"].as_str().unwrap_or("").contains("2 份"),
            "{drafts}"
        );
        assert!(
            drafts["Hint"].as_str().unwrap_or("").contains("不会自己消失"),
            "必须说清不自动过期：{drafts}"
        );
        // 统计不改变列表本身：两份草稿照样在「未完成的添加」里。
        assert_eq!(
            listed["deployment"]["Tasks"].as_array().map(Vec::len),
            Some(2),
            "{listed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 导出只认两种格式；格式不对时**一个文件都不写**。
    #[test]
    fn exporting_refuses_an_unknown_format_without_writing_a_file() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-export-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let run_id = "d2000000-1111-4111-8111-111111111111";
        draft_for(&root, run_id, crate::deploystore::STATE_COMPLETE);
        let reply = call(
            &format!(r#"{{"cmd":"deployment-export","runId":"{run_id}","format":"yaml"}}"#),
            &ctx,
        );
        assert_eq!(reply["ok"], serde_json::json!(false), "{reply}");
        assert_eq!(reply["errorCode"], serde_json::json!("usage"), "{reply}");
        let exports = root.join("logs").join("exports");
        let count = std::fs::read_dir(&exports)
            .map(|dir| dir.filter_map(Result::ok).count())
            .unwrap_or(0);
        assert_eq!(count, 0, "拒绝时不写盘（导出一半的文件比没有更糟）");

        // 缺 runId / 形状不对：同样是 usage，且不写盘。
        for raw in [
            r#"{"cmd":"deployment-export"}"#,
            r#"{"cmd":"deployment-export","runId":"not-a-uuid"}"#,
        ] {
            let reply = call(raw, &ctx);
            assert_eq!(reply["errorCode"], serde_json::json!("usage"), "{raw} → {reply}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P1-3：列表把未读提醒带出去；打开这条任务就把它标成已读。
    #[test]
    fn opening_a_task_clears_its_unread_reminder() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-ipc-reminder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = ctx_with(None, &root);
        let run_id = "c1000000-1111-4111-8111-111111111111";
        let run = draft_for(
            &root,
            run_id,
            crate::deploystore::STATE_NEEDS_ATTENTION,
        );
        crate::reminder::note(&root, &run).expect("收一条提醒");
        assert_eq!(crate::reminder::unread(&root).unwrap().len(), 1);

        // 列表：提醒带 RunId、状态词与人话原因，页面才画得出那张卡。
        let listed = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        let reminders = listed
            .get("deployment")
            .and_then(|value| value.get("Reminders"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(reminders.len(), 1, "{listed}");
        assert_eq!(reminders[0]["RunId"], serde_json::json!(run_id));
        assert_eq!(reminders[0]["StateText"], serde_json::json!("需要处理"));
        assert!(
            !reminders[0]["Text"].as_str().unwrap_or("").is_empty(),
            "人话原因不能是空串"
        );

        // 打开任务 → 提醒变已读（列表随之不再带它）。
        let opened = call(
            &format!(r#"{{"cmd":"deployment-get","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(opened["ok"], serde_json::json!(true), "{opened}");
        assert!(crate::reminder::unread(&root).unwrap().is_empty());
        let listed_again = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(
            listed_again["deployment"]["Reminders"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 八条部署命令**必须**是短命令：进了长命令白名单就会在整个部署期间抢着
    /// 事务门，界面点什么都排在那十几分钟后面——正是这一轮要消灭的那种手感。
    ///
    /// `deployment-draft-save`（r69）只做「校验 → 落盘」，连引擎都不投递，
    /// 更不该有同步预算。
    #[test]
    fn deployment_commands_are_short_and_free() {
        for raw in [
            r#"{"cmd":"deployment-start","spec":"root@203.0.113.10"}"#,
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            r#"{"cmd":"deployment-list"}"#,
            r#"{"cmd":"deployment-get","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-continue","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-pause","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-cancel","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-background","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-export","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            r#"{"cmd":"deployment-archive","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
        ] {
            assert!(
                !is_long_command(raw),
                "部署命令只受理、不执行，不许占事务门：{raw}"
            );
            assert_eq!(
                operation_budget(raw, &Ctx::default()),
                0.0,
                "部署命令不该有同步预算（受理是毫秒级的）：{raw}"
            );
        }
        // 反过来钉住：旧的界面入口退役之后也不该再是长命令。
        assert!(!is_long_command(r#"{"cmd":"server-setup","spec":"root@1.2.3.4"}"#));
    }

    /// 没有引擎时：`deployment-start` **不落盘**，回 `environment`。
    ///
    /// 「先落盘再动手」是 P0-1；反过来，动手前就知道动不了，那就不许留下记录。
    #[test]
    fn deployment_start_without_an_engine_writes_nothing() {
        let root = tmp_root("deploy-start-no-engine");
        let ctx = ctx_with(None, &root);

        let value = call(
            r#"{"cmd":"deployment-start","spec":"root@203.0.113.10","fingerprint":"SHA256:AAAA"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(
            value["errorCode"],
            serde_json::json!("environment"),
            "{value}"
        );
        assert!(
            DeploymentStore::open(&root).load_all().runs.is_empty(),
            "引擎没起来就不许留下记录"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 地址形状不对：在**建记录之前**就拒，回 `usage`。
    /// 只填 IP 就用 root 与 22 端口——命令行与界面必须同一口径（r85）。
    ///
    /// 界面曾经自己拦「没有 @」，于是同一串 `192.168.1.1` 命令行能跑、界面报
    /// 「要写成 用户名@主机」。解析规则只该有一处，就是这里。
    #[test]
    fn a_bare_address_means_root_and_port_22() {
        let password = crate::credential::CredentialKind::Password;
        let target = deploy_target("192.168.1.1", password, "").expect("只填 IP 应当能解析");
        assert_eq!(target.user, "root");
        assert_eq!(target.host, "192.168.1.1");
        assert_eq!(target.port, 22);

        let target =
            deploy_target("203.0.113.10:2222", password, "").expect("只填 IP 与端口也应当能解析");
        assert_eq!(target.user, "root");
        assert_eq!(target.port, 2222);

        let target = deploy_target("ubuntu@example.com", password, "").expect("域名");
        assert_eq!(target.user, "ubuntu");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 22);
    }

    #[test]
    fn deployment_start_refuses_a_bad_address_before_writing_anything() {
        let root = tmp_root("deploy-start-bad-spec");
        let ctx = ctx_with(None, &root);

        for (raw, needle) in [
            (r#"{"cmd":"deployment-start","spec":""}"#, "服务器地址"),
            (
                r#"{"cmd":"deployment-start","spec":"root@host:abc"}"#,
                "端口",
            ),
            (
                r#"{"cmd":"deployment-start","spec":"@203.0.113.10"}"#,
                "用户名",
            ),
        ] {
            let value = call(raw, &ctx);
            assert_eq!(value["ok"], serde_json::json!(false), "{value}");
            assert_eq!(value["errorCode"], serde_json::json!("usage"), "{value}");
            assert!(
                value["error"].as_str().unwrap_or("").contains(needle),
                "{needle} 没出现在回包里：{value}"
            );
        }
        assert!(DeploymentStore::open(&root).load_all().runs.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- r69：草稿的保存、复用、恢复与丢弃 ----------

    /// runs 目录里真正的记录文件（忽略临时文件与点号开头的崩溃残留）。
    fn record_files(root: &PathBuf) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(DeploymentStore::open(root).dir())
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
                    .filter(|name| name.ends_with(".json") && !name.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// 递归收集一份 JSON 的全部键名：秘密边界要**逐键**验，不能只看顶层。
    fn all_keys(value: &serde_json::Value) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        match value {
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    out.push(key.clone());
                    out.extend(all_keys(item));
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    out.extend(all_keys(item));
                }
            }
            _ => {}
        }
        out
    }

    /// 草稿新建：一条 `Draft`、`Revision=1`、四步全 `Pending`，且**记录里没有任何秘密**。
    ///
    /// 请求里故意塞一个 `password`：命令层根本不读这个字段（草稿没有它），
    /// 所以整份文件文本里都不该出现它的影子。
    #[test]
    fn saving_a_draft_writes_one_draft_and_no_secret_at_all() {
        let root = tmp_root("draft-save-new");
        let ctx = ctx_with(None, &root);

        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","password":"hunter2-draft"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        let section = &value["deployment"];
        assert_eq!(section["Created"], serde_json::json!(true), "{value}");
        assert_eq!(
            section["Run"]["State"],
            serde_json::json!("Draft"),
            "草稿就是 Draft 的那条记录：{value}"
        );
        assert_eq!(
            section["Run"]["Revision"],
            serde_json::json!(1),
            "create 置 1（不是 0）：{value}"
        );
        let run_id = section["RunId"].as_str().unwrap_or("").to_string();
        assert_eq!(
            run_id.len(),
            crate::deploystore::RUN_ID_LEN,
            "回包必须带上合法的 RunId：{value}"
        );
        assert_eq!(record_files(&root), vec![format!("{run_id}.json")]);

        let store = DeploymentStore::open(&root);
        let stored = store.load(&run_id).expect("刚写完必须读得回来");
        assert_eq!(stored.state, crate::deploystore::STATE_DRAFT);
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.label, "自建 · 203.0.113.10");
        assert_eq!(stored.target.lane_key(), "203.0.113.10:22");
        assert_eq!(stored.steps.len(), 4, "四步一个都不能少");
        assert!(
            stored
                .steps
                .iter()
                .all(|step| step.status == crate::deploystore::STEP_STATUS_PENDING),
            "草稿的每一步都必须是 Pending：{:?}",
            stored.steps
        );

        // 秘密边界：逐键过禁用键名单，再断言整份文件文本里没有那个密码。
        let text = std::fs::read_to_string(store.dir().join(format!("{run_id}.json"))).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        for key in all_keys(&parsed) {
            assert!(
                !crate::deploystore::is_forbidden_key(&key),
                "草稿里出现了禁用键 {key}：{text}"
            );
        }
        // 「键名里不许有 password」由上面的 `is_forbidden_key` 逐键覆盖。
        // 这里不能再用整份文本搜 `password`：r92 起 `Target.LoginMethod` 的**值**
        // 就是 `"password"`（说的是方式，不是秘密）。
        assert!(
            !text.contains("\"Password\""),
            "草稿文件里不该出现密码字段：{text}"
        );
        assert!(
            !text.contains("hunter2-draft"),
            "密码绝不能落进草稿：{text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 同一台服务器只留一份草稿：不带 `runId` 按 `lane_key` 找回，带 `runId` 直接更新。
    ///
    /// 两次都要走到 `save`（`Revision` 递增），而不是「新建一条、旧的留着」。
    #[test]
    fn the_same_server_never_gets_a_second_draft() {
        let root = tmp_root("draft-save-dedupe");
        let ctx = ctx_with(None, &root);

        let first = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        let run_id = first["deployment"]["RunId"].as_str().unwrap().to_string();
        assert_eq!(first["deployment"]["Created"], serde_json::json!(true));

        // ① 不带 runId，同一个 lane_key（把 `:22` 显式写出来也是同一台）。
        let second = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10:22"}"#,
            &ctx,
        );
        assert_eq!(second["ok"], serde_json::json!(true), "{second}");
        assert_eq!(
            second["deployment"]["Created"],
            serde_json::json!(false),
            "同一台服务器必须复用那条草稿：{second}"
        );
        assert_eq!(
            second["deployment"]["RunId"],
            serde_json::json!(run_id.clone()),
            "{second}"
        );

        // ② 带 runId：直接更新那一条。
        let third = call(
            &format!(
                r#"{{"cmd":"deployment-draft-save","runId":"{run_id}","spec":"root@203.0.113.10","fingerprint":"SHA256:BBBB"}}"#
            ),
            &ctx,
        );
        assert_eq!(third["deployment"]["Created"], serde_json::json!(false));
        assert_eq!(third["deployment"]["RunId"], serde_json::json!(run_id.clone()));

        assert_eq!(
            record_files(&root).len(),
            1,
            "复用的判据是磁盘上只有一份：{:?}",
            record_files(&root)
        );
        let stored = DeploymentStore::open(&root).load(&run_id).unwrap();
        assert_eq!(stored.revision, 3, "三次保存 = Revision 1,2,3（走的是 save）");
        assert_eq!(stored.identity.fingerprint, "SHA256:BBBB");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r93：兼容连接的三个选择随草稿落盘；三个坏值都在写任何东西之前被拒。
    #[test]
    fn a_draft_keeps_the_transport_choices_and_refuses_bad_ones() {
        let root = tmp_root("draft-transport");
        let ctx = ctx_with(None, &root);

        let saved = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","transport":"Tcp","tcpPort":"2443","serverName":"www.example.com"}"#,
            &ctx,
        );
        assert_eq!(saved["ok"], serde_json::json!(true), "{saved}");
        let run_id = saved["deployment"]["RunId"].as_str().unwrap().to_string();
        let stored = DeploymentStore::open(&root).load(&run_id).unwrap();
        assert_eq!(stored.plan.transport, "Tcp");
        assert_eq!(stored.plan.tcp_port, 2443);
        assert_eq!(stored.plan.server_name, "www.example.com");

        // 三个坏值：都不许落盘（record_files 仍然是 1 条，且值不变）。
        for body in [
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","transport":"Quic"}"#,
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","tcpPort":"8080"}"#,
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","serverName":"not a domain"}"#,
        ] {
            let refused = call(body, &ctx);
            assert_eq!(refused["ok"], serde_json::json!(false), "{refused}");
            assert_eq!(
                refused["errorCode"],
                serde_json::json!("usage"),
                "{refused}"
            );
        }
        assert_eq!(record_files(&root).len(), 1, "拒收不许新增记录");
        let stored = DeploymentStore::open(&root).load(&run_id).unwrap();
        assert_eq!(stored.plan.transport, "Tcp", "拒收不许改坏已有值");
        assert_eq!(stored.plan.tcp_port, 2443);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 指纹覆盖规则：`lane_key` 没变时，空请求**不许**把已有的指纹抹掉；
    /// 换成另一台服务器时，也不许把上一台的指纹带过去。
    #[test]
    fn a_draft_fingerprint_follows_its_own_server_and_is_never_wiped_by_silence() {
        let root = tmp_root("draft-fingerprint");
        let ctx = ctx_with(None, &root);

        let first = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10","fingerprint":"SHA256:AAAA"}"#,
            &ctx,
        );
        let run_id = first["deployment"]["RunId"].as_str().unwrap().to_string();

        // 同一台、请求不带指纹（「读取指纹」那一次点击就是这样）：保留。
        let again = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        assert_eq!(again["deployment"]["RunId"], serde_json::json!(run_id.clone()));
        let stored = DeploymentStore::open(&root).load(&run_id).unwrap();
        assert_eq!(
            stored.identity.fingerprint, "SHA256:AAAA",
            "同一台服务器上，不填指纹不等于「指纹是空的」"
        );

        // 换一台：新建，且**不得**继承 A 的指纹。
        let other = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@198.51.100.7"}"#,
            &ctx,
        );
        let other_id = other["deployment"]["RunId"].as_str().unwrap().to_string();
        assert_ne!(other_id, run_id, "另一台服务器是另一份草稿");
        let other_stored = DeploymentStore::open(&root).load(&other_id).unwrap();
        assert!(
            other_stored.identity.fingerprint.is_empty(),
            "A 的指纹不能跟着带到 B 上：{}",
            other_stored.identity.fingerprint
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 上限 3：第 4 条草稿被拒，磁盘仍然是 3 条；文案必须给出去路。
    #[test]
    fn a_fourth_draft_is_refused_and_nothing_is_written() {
        let root = tmp_root("draft-limit");
        let ctx = ctx_with(None, &root);
        for host in ["203.0.113.10", "203.0.113.11", "203.0.113.12"] {
            let value = call(
                &format!(r#"{{"cmd":"deployment-draft-save","spec":"root@{host}"}}"#),
                &ctx,
            );
            assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        }
        assert_eq!(record_files(&root).len(), crate::deploystore::MAX_DRAFTS);

        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.13"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");
        let message = value["error"].as_str().unwrap_or("");
        assert!(message.contains("3 份"), "要说清是满了 3 份：{value}");
        assert!(
            message.contains("放弃"),
            "拒绝时必须给出去路（去哪儿放弃一条）：{value}"
        );
        assert_eq!(
            record_files(&root).len(),
            3,
            "被拒的第 4 条一个字都不许落盘：{:?}",
            record_files(&root)
        );

        // 放弃一条之后就能再存一条：那句话不是空头支票。
        let first_id = record_files(&root)[0].trim_end_matches(".json").to_string();
        let discarded = call(
            &format!(r#"{{"cmd":"deployment-cancel","runId":"{first_id}"}}"#),
            &ctx,
        );
        assert_eq!(discarded["ok"], serde_json::json!(true), "{discarded}");
        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.13"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `spec` 形状不对 → `usage`，且**一个字都不写**（半截地址不是目标）。
    #[test]
    fn draft_save_refuses_a_bad_address_before_writing_anything() {
        let root = tmp_root("draft-bad-spec");
        let ctx = ctx_with(None, &root);
        for (raw, needle) in [
            (r#"{"cmd":"deployment-draft-save","spec":""}"#, "服务器地址"),
            (
                r#"{"cmd":"deployment-draft-save","spec":"root@host:abc"}"#,
                "端口",
            ),
            (
                r#"{"cmd":"deployment-draft-save","spec":"@203.0.113.10"}"#,
                "用户名",
            ),
            (
                r#"{"cmd":"deployment-draft-save","spec":"root@2001:db8::1"}"#,
                "IPv6",
            ),
        ] {
            let value = call(raw, &ctx);
            assert_eq!(value["ok"], serde_json::json!(false), "{value}");
            assert_eq!(value["errorCode"], serde_json::json!("usage"), "{value}");
            assert!(
                value["error"].as_str().unwrap_or("").contains(needle),
                "{needle} 没出现在回包里：{value}"
            );
        }
        assert!(
            record_files(&root).is_empty(),
            "形状不过关的地址不许落盘：{:?}",
            record_files(&root)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 已经开始过的记录不能当草稿用：`conflict`，且那条记录一个字不改。
    #[test]
    fn a_started_run_cannot_be_turned_back_into_a_draft() {
        let root = tmp_root("draft-not-a-draft");
        let ctx = ctx_with(None, &root);
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_COMPLETE);
        let before = DeploymentStore::open(&root).load(run_id).unwrap();

        let value = call(
            &format!(
                r#"{{"cmd":"deployment-draft-save","runId":"{run_id}","spec":"root@198.51.100.7"}}"#
            ),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");
        assert!(
            value["error"].as_str().unwrap_or("").contains("已经开始过"),
            "{value}"
        );
        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(after, before, "被拒的保存不许改动记录的任何字段");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 读不全（连 runs 目录都读不了）→ 拒绝写：不知道有哪些草稿就无法去重。
    ///
    /// 构造方式：把 `runs` 变成一个**普通文件**。`read_dir` 因此在任何平台上都
    /// 报 `NotADirectory`（不是 `NotFound`），`load_all` 的结论是 `failed`。
    #[test]
    fn draft_save_refuses_to_write_when_the_records_cannot_be_read() {
        let root = tmp_root("draft-unreadable");
        let ctx = ctx_with(None, &root);
        let runs_dir = DeploymentStore::open(&root).dir().to_path_buf();
        std::fs::create_dir_all(runs_dir.parent().unwrap()).unwrap();
        std::fs::write(&runs_dir, b"not a directory").unwrap();

        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("config"), "{value}");
        assert!(
            value["error"].as_str().unwrap_or("").contains("读不到"),
            "要说清是读不出来，而不是地址写错了：{value}"
        );
        assert!(
            std::fs::metadata(&runs_dir)
                .map(|meta| meta.is_file())
                .unwrap_or(false),
            "拒绝写的意思就是那个位置一个字节都没动"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `partial`（有记录文件读不出来）**同样**拒绝写：读不出来不等于没有。
    ///
    /// 现场：同一台服务器那份草稿文件被写坏（半截 JSON）→ 它读不出来、列表上看不见 →
    /// 按 `lane_key` 去重就会失手，新建**第二份同一台服务器**的草稿；上限 3 也只会数到
    /// 能读的那几条。`LoadResult::is_usable()`（`tasks_read != "failed"`）回答的是
    /// 「页面能不能渲染」，去重要的是「知道全部草稿」——两把尺不能混用。
    #[test]
    fn a_partial_read_refuses_the_draft_save_instead_of_duplicating_a_draft() {
        let root = tmp_root("draft-partial");
        let ctx = ctx_with(None, &root);
        let first = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        assert_eq!(first["ok"], serde_json::json!(true), "{first}");
        let run_id = first["deployment"]["RunId"].as_str().unwrap().to_string();
        let path = DeploymentStore::open(&root).dir().join(format!("{run_id}.json"));
        std::fs::write(&path, b"{ this is not json").unwrap();

        // 同一个 lane_key 再点一次「读取指纹」：不许造出第二份。
        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("config"), "{value}");
        assert!(
            value["error"].as_str().unwrap_or("").contains("读不出来"),
            "要说清是有记录读不出来，而不是地址写错了：{value}"
        );
        assert_eq!(
            record_files(&root),
            vec![format!("{run_id}.json")],
            "读不出来的那份还在磁盘上，就不许新建第二份：{:?}",
            record_files(&root)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 草稿不能被 `continue` 一键推进队列（那是一次没有密码的部署）。
    ///
    /// 两层断言：① 没有引擎时回的是 `conflict` 而不是 `environment` —— 说明判据在
    /// 「有没有引擎」之前；② 有引擎时队列里也没有它。
    #[test]
    fn a_draft_cannot_be_pushed_into_the_queue_by_continue() {
        let root = tmp_root("draft-continue");
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_DRAFT);
        let raw = format!(r#"{{"cmd":"deployment-continue","runId":"{run_id}"}}"#);

        let ctx = ctx_with(None, &root);
        let value = call(&raw, &ctx);
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(
            value["errorCode"],
            serde_json::json!("conflict"),
            "草稿的拒绝必须在引擎判空之前：{value}"
        );
        assert!(
            value["error"].as_str().unwrap_or("").contains("草稿"),
            "{value}"
        );

        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());
        let value = call(&raw, &ctx);
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");
        assert_eq!(
            engine.handle().shared().queued_count(),
            0,
            "被拒的草稿不许进引擎队列"
        );
        assert!(!engine.handle().is_active(run_id));
        let stored = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(
            stored.state,
            crate::deploystore::STATE_DRAFT,
            "被拒之后它还是草稿"
        );
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 丢弃草稿 = 删文件、**不碰引擎**。非草稿仍走原来的取消路径（要引擎）。
    ///
    /// 「不碰引擎」的证明方式是判据顺序：这条命令在**没有引擎**的上下文里能成功，
    /// 说明代码根本没走到 `DEPLOY_NO_ENGINE` 那一支；同一上下文里取消一条非草稿
    /// 记录则必须回 `environment`。
    #[test]
    fn discarding_a_draft_deletes_the_file_and_never_asks_the_engine() {
        let root = tmp_root("draft-discard");
        let ctx = ctx_with(None, &root);
        let draft_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let queued_id = "11111111-2222-3333-4444-555555555555";
        draft_for(&root, draft_id, crate::deploystore::STATE_DRAFT);
        draft_for(&root, queued_id, crate::deploystore::STATE_QUEUED);

        let value = call(
            &format!(r#"{{"cmd":"deployment-cancel","runId":"{draft_id}"}}"#),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        let section = &value["deployment"];
        assert_eq!(section["CancelRequested"], serde_json::json!(true));
        assert_eq!(
            section["Discarded"],
            serde_json::json!(true),
            "草稿是「丢掉」而不是「取消」：{value}"
        );
        assert!(
            section["Message"]
                .as_str()
                .unwrap_or("")
                .contains("没有留下任务记录"),
            "{value}"
        );
        assert!(
            !DeploymentStore::open(&root)
                .dir()
                .join(format!("{draft_id}.json"))
                .exists(),
            "丢弃必须把文件删掉（而不是写成 Cancelled）"
        );

        // 非草稿：同一条命令、同一个没有引擎的上下文 → 必须回 environment。
        let value = call(
            &format!(r#"{{"cmd":"deployment-cancel","runId":"{queued_id}"}}"#),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(
            value["errorCode"],
            serde_json::json!("environment"),
            "非草稿的取消仍然需要引擎：{value}"
        );
        assert!(
            DeploymentStore::open(&root)
                .dir()
                .join(format!("{queued_id}.json"))
                .exists(),
            "取消一条进行中的记录不许删文件"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 草稿在任务列表里是「未开始 / 继续填写」，且**不进**底部队列。
    #[test]
    fn a_draft_is_a_task_to_continue_and_never_shows_up_in_the_queue() {
        let root = tmp_root("draft-list");
        let ctx = ctx_with(None, &root);
        let value = call(
            r#"{"cmd":"deployment-draft-save","spec":"root@203.0.113.10"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");

        let value = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        let section = &value["deployment"];
        assert_eq!(section["TasksRead"], serde_json::json!("ok"), "{value}");
        assert_eq!(section["Tasks"].as_array().map(Vec::len), Some(1), "{value}");
        assert_eq!(section["Tasks"][0]["StateText"], serde_json::json!("未开始"));
        assert_eq!(
            section["Tasks"][0]["Action"],
            serde_json::json!("resume"),
            "草稿唯一的路是「继续填写」：{value}"
        );
        assert_eq!(section["Tasks"][0]["ActionLabel"], serde_json::json!("继续填写"));
        assert_eq!(
            section["Deployments"].as_array().map(Vec::len),
            Some(0),
            "草稿不许出现在底部任务条：{value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一个**不做任何远程动作**的 `Ops`：Step0 的第一件事就返回「明确没做成」。
    ///
    /// 用它起一个真引擎，就能断言「命令有没有被投递到引擎」（记录会离开 `Draft`），
    /// 而不必去连 `203.0.113.10` 那种不可路由的地址——那会让用例等上几分钟，
    /// 还会在测试进程退出时留着一条正在跑的 pass。
    struct NoNetworkOps;

    fn no_network() -> crate::deployengine::OpsError {
        crate::deployengine::OpsError::definite(
            crate::deploystore::ERROR_CLASS_ENVIRONMENT,
            "TestNoNetwork",
            "测试用：不做任何远程动作。",
        )
    }

    impl crate::deployengine::Ops for NoNetworkOps {
        fn resolve_identity(
            &self,
            _req: &crate::deployengine::OpsReq,
        ) -> Result<crate::deployengine::IdentityFacts, crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn check_environment(
            &self,
            _req: &crate::deployengine::OpsReq,
        ) -> Result<crate::deployengine::EnvFacts, crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn install_udp(
            &self,
            _req: &crate::deployengine::OpsReq,
            _tunnel_up: bool,
        ) -> Result<crate::deployengine::UdpInstallFacts, crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn probe_udp_state(
            &self,
            _req: &crate::deployengine::OpsReq,
        ) -> Result<crate::deployengine::ProbeFacts, crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn install_transport(
            &self,
            _req: &crate::deployengine::OpsReq,
        ) -> Result<Option<crate::deployengine::TransportFacts>, crate::deployengine::OpsError>
        {
            Err(no_network())
        }
        fn read_transport(
            &self,
            _req: &crate::deployengine::OpsReq,
        ) -> Result<Option<crate::deployengine::TransportFacts>, crate::deployengine::OpsError>
        {
            Err(no_network())
        }
        fn add_peer(
            &self,
            _req: &crate::deployengine::OpsReq,
            _client_public: &str,
        ) -> Result<crate::deployengine::PeerFacts, crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn write_client_conf(
            &self,
            _req: &crate::deployengine::OpsReq,
            _client_private: &str,
            _server_public: &str,
        ) -> Result<(), crate::deployengine::OpsError> {
            Err(no_network())
        }
        fn register_lines(
            &self,
            _req: &crate::deployengine::OpsReq,
            _compatible: Option<&crate::deployengine::TransportFacts>,
            _preferred: Option<crate::config::Transport>,
        ) -> Result<Vec<crate::deployengine::LineFacts>, crate::deployengine::OpsError> {
            Err(no_network())
        }
    }

    fn engine_over(root: &PathBuf) -> crate::deployengine::Engine {
        crate::deployengine::Engine::start(
            root.clone(),
            std::sync::Arc::new(NoNetworkOps),
            crate::events::Origin::auto(),
        )
    }

    /// 等记录离开 `Draft`：证明这条命令**真的被投递**给了引擎。
    ///
    /// 不等某个具体状态：投递之后状态会一路走（Queued → Running → NeedsAttention），
    /// 钉死其中一个是把用例变成竞态。「离开了 Draft」才是这条命令的语义。
    fn wait_until_it_leaves_draft(root: &PathBuf, run_id: &str) -> String {
        let store = DeploymentStore::open(root);
        let started = std::time::Instant::now();
        loop {
            let state = store.load(run_id).map(|run| run.state).unwrap_or_default();
            if state != crate::deploystore::STATE_DRAFT {
                return state;
            }
            if started.elapsed() > std::time::Duration::from_secs(20) {
                panic!("等不到引擎接手这条草稿，它还是 {state:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// `deployment-start{runId}` 复用那条草稿：RunId 不变、磁盘仍 1 条、
    /// `Attempts` / `CreatedAtUtc` 不重置、请求里的字段被覆盖上去。
    #[test]
    fn starting_from_a_draft_reuses_that_record() {
        let root = tmp_root("draft-start-reuse");
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let created = draft_for(&root, run_id, crate::deploystore::STATE_DRAFT);

        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());

        // 地址与指纹**故意**与草稿不同：复用时要按请求覆盖。
        let value = call(
            &format!(
                r#"{{"cmd":"deployment-start","runId":"{run_id}","spec":"root@198.51.100.7:2222","fingerprint":"SHA256:BBBB","password":"hunter2-start"}}"#
            ),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        assert_eq!(
            value["deployment"]["RunId"],
            serde_json::json!(run_id),
            "复用就必须是同一个 RunId（不许开新任务）：{value}"
        );
        assert_eq!(
            record_files(&root),
            vec![format!("{run_id}.json")],
            "复用不许落出第二条记录：{:?}",
            record_files(&root)
        );

        // 落盘发生在投递之前：命令刚回包时就该能读到请求里的地址。
        let stored = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(stored.target.host, "198.51.100.7");
        assert_eq!(stored.target.port, 2222);
        assert_eq!(stored.identity.fingerprint, "SHA256:BBBB");
        assert_eq!(
            stored.created_at_utc, created.created_at_utc,
            "CreatedAtUtc 是既有事实，不许重置"
        );
        assert_eq!(stored.attempts.len(), 1, "复用不是「新的一次尝试」");
        assert!(
            stored.revision > created.revision,
            "save 要递增 Revision：{} → {}",
            created.revision,
            stored.revision
        );
        // 密码不许落盘（这一批请求里带了它）。
        let text =
            std::fs::read_to_string(DeploymentStore::open(&root).dir().join(format!("{run_id}.json")))
                .unwrap();
        assert!(!text.contains("hunter2-start"), "密码绝不能落进记录：{text}");

        // 引擎真的接手了。
        let state = wait_until_it_leaves_draft(&root, run_id);
        assert_ne!(state, crate::deploystore::STATE_DRAFT);
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `deployment-start{runId}` 指向一条已经开始过的记录 → `conflict`，记录一个字不改。
    #[test]
    fn starting_from_a_finished_run_is_refused_without_touching_it() {
        let root = tmp_root("draft-start-finished");
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_COMPLETE);
        let before = DeploymentStore::open(&root).load(run_id).unwrap();

        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());

        let value = call(
            &format!(r#"{{"cmd":"deployment-start","runId":"{run_id}","spec":"root@198.51.100.7"}}"#),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");
        assert!(
            value["error"].as_str().unwrap_or("").contains("已经开始过"),
            "{value}"
        );
        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(after, before, "被拒的开始不许改动记录的任何字段");
        assert!(!engine.handle().is_active(run_id));
        assert_eq!(engine.handle().shared().queued_count(), 0, "也不许排队");

        // 不存在的 runId：`config`（不是 conflict）。
        let value = call(
            r#"{"cmd":"deployment-start","runId":"11111111-2222-3333-4444-555555555555","spec":"root@198.51.100.7"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("config"), "{value}");
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一条坏记录只让整体降级为 `partial`：其余任务照常给，且**必须**给出坏了几条。
    ///
    /// 最糟的退路是「有一条坏 → 整页显示没有任务」：用户会以为部署记录丢了。
    #[test]
    fn deployment_list_survives_one_unreadable_record() {
        let root = tmp_root("deploy-list-partial");
        let ctx = ctx_with(None, &root);
        draft_for(&root, "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f", "Draft");

        let runs_dir = DeploymentStore::open(&root).dir().to_path_buf();
        std::fs::write(runs_dir.join("bad.json"), b"{ this is not json").unwrap();

        let value = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(value["ok"], serde_json::json!(true), "partial 仍然可用：{value}");
        let section = &value["deployment"];
        assert_eq!(section["TasksRead"], serde_json::json!("partial"), "{value}");
        assert_eq!(section["UnreadableCount"], serde_json::json!(1), "{value}");
        assert_eq!(
            section["Tasks"].as_array().map(Vec::len),
            Some(1),
            "能读的那条必须照常返回：{value}"
        );
        assert_eq!(
            section["Tasks"][0]["State"],
            serde_json::json!("Draft"),
            "{value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `deployment-get`：不存在的 RunId 回 `config`；坏形状的 RunId 回 `usage`。
    #[test]
    fn deployment_get_refuses_missing_and_malformed_ids() {
        let root = tmp_root("deploy-get");
        let ctx = ctx_with(None, &root);

        let value = call(
            r#"{"cmd":"deployment-get","runId":"3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f"}"#,
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("config"), "{value}");

        let value = call(r#"{"cmd":"deployment-get","runId":"../../etc/passwd"}"#, &ctx);
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("usage"), "{value}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 终态记录：「继续」只打开，「取消」直接拒绝——两者都**不改**记录。
    #[test]
    fn a_finished_run_can_only_be_opened() {
        let root = tmp_root("deploy-terminal");
        let ctx = ctx_with(None, &root);
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_COMPLETE);

        let value = call(
            &format!(r#"{{"cmd":"deployment-continue","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(true), "{value}");
        assert_eq!(value["deployment"]["Accepted"], serde_json::json!(false));
        assert_eq!(value["deployment"]["Queued"], serde_json::json!(false));

        let value = call(
            &format!(r#"{{"cmd":"deployment-cancel","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");

        let after = DeploymentStore::open(&root).load(run_id).unwrap();
        assert_eq!(
            after.state,
            crate::deploystore::STATE_COMPLETE,
            "只读命令绝不能把终态改回去"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 没有活动 pass 时「暂停 / 转后台」都是空话：必须回 `environment`，且不回 `ok:true`
    /// ——否则页面会关掉表单说「已在后台继续」，而根本没人接着跑。
    #[test]
    fn pause_and_background_refuse_when_nothing_is_running() {
        let root = tmp_root("deploy-not-running");
        let ctx = ctx_with(None, &root);
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_RUNNING);

        for raw in [
            format!(r#"{{"cmd":"deployment-pause","runId":"{run_id}"}}"#),
            format!(r#"{{"cmd":"deployment-background","runId":"{run_id}"}}"#),
        ] {
            let value = call(&raw, &ctx);
            assert_eq!(value["ok"], serde_json::json!(false), "{value}");
            assert_eq!(
                value["errorCode"],
                serde_json::json!("environment"),
                "{value}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 状态写的是 `Running`、引擎里却没有它（崩溃后的现场）：快照里的 `Running`
    /// 必须是 `false`，任务条不许继续显示「正在跑」。
    #[test]
    fn a_record_left_running_after_a_crash_is_not_reported_as_running() {
        let root = tmp_root("deploy-crash-running");
        let ctx = ctx_with(None, &root);
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        draft_for(&root, run_id, crate::deploystore::STATE_RUNNING);

        let value = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(
            value["deployment"]["Deployments"][0]["Running"],
            serde_json::json!(false),
            "没有活动 pass 就不是 Running：{value}"
        );
        assert_eq!(
            value["deployment"]["Tasks"][0]["CanBackground"],
            serde_json::json!(false),
            "没有活动 pass 就不能转后台：{value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 启动恢复写盘失败时，列表必须说「读不出来」，**不许**照常显示「正在部署」。
    ///
    /// 现场：记录还留在 `Running`（写不进去就不改，这是对的），如果页面照常渲染，
    /// 用户看到的就是「还在部署」——T04 明令禁止的「先显示 Running 让它自己好」。
    #[cfg(windows)]
    #[test]
    fn a_failed_recovery_makes_the_list_unreadable_instead_of_running() {
        let root = tmp_root("deploy-recover-failed");
        let run_id = "3f2b9c1e-4a5d-4c8b-9e01-2d7a6b5c4e3f";
        let store = DeploymentStore::open(&root);
        draft_for(&root, run_id, crate::deploystore::STATE_RUNNING);
        let mut run = store.load(run_id).unwrap();
        run.executor = Some(crate::deploystore::Executor {
            instance_id: "dead-process".to_string(),
            pid: 999_999,
            heartbeat_at_utc: Some(crate::deploystore::stamp_utc(
                crate::model::now_epoch_secs_u64().saturating_sub(600),
            )),
            background: false,
        });
        store.save(&mut run).unwrap();

        let path = store.dir().join(format!("{run_id}.json"));
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        let engine = crate::deployengine::Engine::start(
            root.clone(),
            std::sync::Arc::new(crate::deployengine::ProdOps::new(
                crate::events::Origin::auto(),
            )),
            crate::events::Origin::auto(),
        );
        assert_eq!(engine.recover_all().failed, 1, "先确认这次恢复确实失败了");

        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());
        let value = call(r#"{"cmd":"deployment-list"}"#, &ctx);
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(
            value["deployment"]["TasksRead"],
            serde_json::json!("failed"),
            "留在 Running 的记录只能报「读不出来」：{value}"
        );
        assert!(
            value["deployment"]["TasksReadError"]
                .as_str()
                .unwrap_or("")
                .contains("写盘失败"),
            "要说清是改判写不进去，不是文件坏了：{value}"
        );

        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        drop(engine);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 线路名里带主机：`自建 · 203.0.113.10` 与兼容连接那条都要能取出来。
    #[test]
    fn a_line_name_yields_its_server_host() {
        assert_eq!(
            host_from_line_name("自建 · 203.0.113.10").as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            host_from_line_name("自建 · 203.0.113.10（兼容连接）").as_deref(),
            Some("203.0.113.10")
        );
        // 用户改过名的线路取不到主机——调用方要能识别这种「取不到」。
        assert_eq!(host_from_line_name("我的香港线路"), None);
    }

    fn ctx_with(cfg: Option<AppConfig>, root: &PathBuf) -> Ctx {
        Ctx {
            cfg,
            root: root.clone(),
            log_dir: root.join("logs"),
            source: crate::events::Source::Other,
            ..Ctx::default()
        }
    }

    fn call(cmd: &str, ctx: &Ctx) -> serde_json::Value {
        serde_json::from_str(&handle_line_with(cmd, ctx)).expect("响应必须是一行合法 JSON")
    }

    fn recovery_record(root: &PathBuf, name: &str) -> crate::serverstore::ServerRecord {
        crate::serverstore::register_recovered(
            root,
            name,
            &crate::ssh::Target::new("203.0.113.10", 22, "root"),
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            1_700_000_000,
        )
        .expect("先铺一条服务器记录")
    }

    /// r94：导出 → 导入到一个**全新的数据根**，记录里的身份原样回来。
    #[test]
    fn a_recovery_package_exports_and_imports_between_data_roots() {
        let source = tmp_root("recovery-export");
        let record = recovery_record(&source, "恢复源服务器");
        let ctx = ctx_with(None, &source);
        let exported = call(
            &serde_json::json!({
                "cmd": "recovery-export",
                "serverId": record.id,
                "password": "r94-recovery-pass",
                "includeCredential": false,
            })
            .to_string(),
            &ctx,
        );
        assert_eq!(exported["ok"], serde_json::json!(true), "{exported}");
        let package = exported["recovery"]["Package"]
            .as_str()
            .expect("要回恢复包文本")
            .to_string();
        assert!(!package.contains("203.0.113.10"), "外层不许出现服务器地址");

        let destination = tmp_root("recovery-import");
        let dest_ctx = ctx_with(None, &destination);
        let imported = call(
            &serde_json::json!({
                "cmd": "recovery-import",
                "package": package,
                "password": "r94-recovery-pass",
            })
            .to_string(),
            &dest_ctx,
        );
        assert_eq!(imported["ok"], serde_json::json!(true), "{imported}");
        assert_eq!(imported["recovery"]["IncludesCredential"], serde_json::json!(false));
        let records = crate::serverstore::list(&destination).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "恢复源服务器");
        assert_eq!(records[0].host, "203.0.113.10");
        assert_eq!(records[0].fingerprint, record.fingerprint);
        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&destination);
    }

    /// r94：包含已保存凭据的恢复包，导入后能读回同一个密码。
    #[test]
    fn a_recovery_package_can_carry_the_saved_credential() {
        let source = tmp_root("recovery-cred");
        let record = crate::serverstore::trust(
            &source,
            &crate::ssh::Target::new("203.0.113.10", 22, "root"),
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "s3cret-password",
            1_700_000_000,
        )
        .unwrap();
        let ctx = ctx_with(None, &source);
        let exported = call(
            &serde_json::json!({
                "cmd": "recovery-export",
                "serverId": record.id,
                "password": "r94-recovery-pass",
                "includeCredential": true,
            })
            .to_string(),
            &ctx,
        );
        assert_eq!(exported["ok"], serde_json::json!(true), "{exported}");
        let package = exported["recovery"]["Package"].as_str().unwrap().to_string();
        assert!(!package.contains("s3cret-password"), "密码不许明文出现");

        let destination = tmp_root("recovery-cred-import");
        let dest_ctx = ctx_with(None, &destination);
        let imported = call(
            &serde_json::json!({
                "cmd": "recovery-import",
                "package": package,
                "password": "r94-recovery-pass",
            })
            .to_string(),
            &dest_ctx,
        );
        assert_eq!(imported["ok"], serde_json::json!(true), "{imported}");
        let records = crate::serverstore::list(&destination).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            crate::serverstore::credential(&destination, &records[0])
                .unwrap()
                .password_text(),
            "s3cret-password"
        );
        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&destination);
    }

    /// r94：坏密码、短密码、坏包都在写任何记录之前被拒。
    #[test]
    fn a_bad_recovery_package_is_refused_without_writing_records() {
        let root = tmp_root("recovery-bad");
        let record = recovery_record(&root, "源");
        let ctx = ctx_with(None, &root);
        let short = call(
            &serde_json::json!({
                "cmd": "recovery-export",
                "serverId": record.id,
                "password": "short",
            })
            .to_string(),
            &ctx,
        );
        assert_eq!(short["ok"], serde_json::json!(false), "{short}");
        assert_eq!(short["errorCode"], serde_json::json!("usage"), "{short}");

        let destination = tmp_root("recovery-bad-import");
        let dest_ctx = ctx_with(None, &destination);
        for package in ["not-json", "{\"SchemaVersion\":1,\"Kind\":\"Nope\"}"] {
            let value = call(
                &serde_json::json!({
                    "cmd": "recovery-import",
                    "package": package,
                    "password": "r94-recovery-pass",
                })
                .to_string(),
                &dest_ctx,
            );
            assert_eq!(value["ok"], serde_json::json!(false), "{value}");
            assert_eq!(value["errorCode"], serde_json::json!("usage"), "{value}");
        }
        assert!(
            crate::serverstore::list(&destination).unwrap().is_empty(),
            "拒收不许留下记录"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&destination);
    }

    /// r94：包里的指纹与本机同一目标不一致 → conflict，记录不变。
    #[test]
    fn a_recovery_package_never_overwrites_a_different_server_identity() {
        let root = tmp_root("recovery-identity");
        let record = recovery_record(&root, "本机记录");
        let ctx = ctx_with(None, &root);
        let exported = call(
            &serde_json::json!({
                "cmd": "recovery-export",
                "serverId": record.id,
                "password": "r94-recovery-pass",
            })
            .to_string(),
            &ctx,
        );
        let package = exported["recovery"]["Package"].as_str().unwrap().to_string();

        // 在同一台机器上先把记录改成另一个指纹（模拟「服务器重装过」）。
        let cfg_path = root.join("servers").join(&record.id).join("record.json");
        let mut stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
        stored["Fingerprint"] =
            serde_json::json!("SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        std::fs::write(&cfg_path, stored.to_string()).unwrap();

        let value = call(
            &serde_json::json!({
                "cmd": "recovery-import",
                "package": package,
                "password": "r94-recovery-pass",
            })
            .to_string(),
            &ctx,
        );
        assert_eq!(value["ok"], serde_json::json!(false), "{value}");
        assert_eq!(value["errorCode"], serde_json::json!("conflict"), "{value}");
        let records = crate::serverstore::list(&root).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].fingerprint,
            "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "拒绝时一个字段都不许改"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// r95：`useSaved=false` 时不许再摸长期信封；`true` 时照旧能用。
    #[test]
    fn the_use_saved_switch_decides_whether_the_long_term_envelope_is_used() {
        let root = tmp_root("use-saved-switch");
        crate::serverstore::trust(
            &root,
            &crate::ssh::Target::new("203.0.113.10", 22, "root"),
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "s3cret-password",
            1_700_000_000,
        )
        .unwrap();
        let ctx = ctx_with(None, &root);
        let target = crate::deploystore::Target {
            host: "203.0.113.10".to_string(),
            port: 22,
            user: "root".to_string(),
            ..crate::deploystore::Target::default()
        };
        let kind = crate::credential::CredentialKind::Password;
        let refused = deploy_resolve_credential(
            &ctx,
            None,
            &target,
            kind,
            TypedCredential::default(),
            true,
            false,
        )
        .expect("解析本身不该失败");
        assert!(refused.is_none(), "没勾「使用这台服务器保存的登录资料」就不许用信封");

        let allowed = deploy_resolve_credential(
            &ctx,
            None,
            &target,
            kind,
            TypedCredential::default(),
            true,
            true,
        )
        .expect("解析本身不该失败")
        .expect("勾了就该找到长期信封");
        assert_eq!(allowed.password_text(), Some("s3cret-password"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pair_join_refuses_before_consuming_an_invite_when_a_connection_is_live() {
        // 连接中加线路会改 `selected`：还原凭据与实际引擎会对不上。
        // 关键是**必须在任何网络动作之前拒绝**——邀请码是一次性的，消费掉才发现不能加就晚了。
        let root = tmp_root("pair-join-busy");
        write_cfg(&root, "L1");
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"pair-join","code":"TCI1.abc","device":"本机","name":"香港"}"#, &ctx);
        assert_eq!(v["ok"], true, "失败也走 ok:true，错误码在 pairJoin 里：{v}");
        assert_eq!(v["pairJoin"]["Code"], "ConnectionBusy", "{v}");
        assert!(v["pairJoin"]["Message"].as_str().unwrap().contains("断开"), "{v}");
        // 一条线路都没多出来，登记目录也没被创建。
        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(cfg.lines.len(), 2, "既有两条线路不该被动：{:?}", cfg.lines);
        assert!(
            !cfg.lines.iter().any(|line| line.name == "香港"),
            "被拒绝的加入不该留下线路：{:?}",
            cfg.lines
        );
        assert_eq!(cfg.selected, "L1", "选中项也不能变");
        assert!(!root.join("identities").exists(), "拒绝时不该碰任何配对状态");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pair_join_reports_a_missing_code_without_touching_the_network() {
        let root = tmp_root("pair-join-empty");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let v = call(
            r#"{"cmd":"pair-join","code":"","device":"本机","name":"香港","pairId":"round-1"}"#,
            &ctx,
        );
        assert_eq!(v["pairJoin"]["Code"], "InvalidOnlineCode", "{v}");
        assert_eq!(v["pairJoin"]["LineId"], "", "{v}");
        // 回显 PairId：页面靠它把回包对到具体某一轮，取消之后迟到的回包不会被当成新的。
        assert_eq!(v["pairJoin"]["PairId"], "round-1", "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pair_offline_inspect_reports_a_missing_invite_without_touching_the_disk() {
        let root = tmp_root("pair-offline-empty");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let v = call(
            r#"{"cmd":"pair-offline-inspect","invite":"","pairId":"round-offline"}"#,
            &ctx,
        );
        assert_eq!(v["ok"], true, "失败也走 ok:true：{v}");
        assert_eq!(v["pairOffline"]["Stage"], "Inspect", "{v}");
        assert_eq!(v["pairOffline"]["Code"], "InvalidOfflineInvite", "{v}");
        assert_eq!(v["pairOffline"]["PairId"], "round-offline", "回包要对得上这一轮");
        assert!(!root.join("identities").exists(), "校验失败不该碰任何配对状态");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pair_offline_complete_refuses_while_connected_before_reading_the_enrollment() {
        let root = tmp_root("pair-offline-busy");
        write_cfg(&root, "L1");
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let ctx = ctx_with(None, &root);
        let v = call(
            r#"{"cmd":"pair-offline-complete","enrollmentId":"missing","authorization":"x","name":"离线","pairId":"r1"}"#,
            &ctx,
        );
        assert_eq!(v["pairOffline"]["Stage"], "Complete", "{v}");
        assert_eq!(v["pairOffline"]["Code"], "ConnectionBusy", "{v}");
        assert_eq!(v["pairOffline"]["PairId"], "r1", "{v}");
        assert!(!root.join("identities").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invite_authorize_rejects_a_bad_request_before_any_ssh() {
        let root = tmp_root("invite-authorize-bad");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        // 空申请：连服务器记录都不用找。
        let v = call(r#"{"cmd":"invite-authorize","line":"L1","request":""}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["invite"]["Section"], "Authorize", "{v}");
        assert_eq!(v["invite"]["Data"]["ErrorCode"], "InviteBadRequest", "{v}");
        // 不是三段式 JWS：本地就拒，绝不发起 SSH。
        let v = call(
            r#"{"cmd":"invite-authorize","line":"L1","request":"not-a-jws"}"#,
            &ctx,
        );
        // `request::verify` 先解 JWS 外壳，坏外壳报 `InvalidInvite`；两种都表示
        // 「这份申请本地就不成立」，重点是**没有发起 SSH**。
        let code = v["invite"]["Data"]["ErrorCode"].as_str().unwrap_or("");
        assert!(matches!(code, "InvalidPairRequest" | "InvalidInvite"), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preflight_judges_service_state_without_touching_the_firewall() {
        let service = |installed, active, listening, ufw: &str| PairServiceState {
            installed,
            active,
            enabled: true,
            listening,
            ufw: ufw.to_string(),
        };

        // 没装 → 自动装；装了没跑/没监听 → 自动重启。
        assert_eq!(
            preflight_verdict("NotInstalled", 18_443, &service(false, false, false, "Status: inactive")).0,
            "NeedsInit"
        );
        assert_eq!(
            preflight_verdict("Timeout", 18_443, &service(true, false, false, "Status: inactive")).0,
            "NeedsRestart"
        );
        assert_eq!(
            preflight_verdict("Timeout", 18_443, &service(true, true, false, "Status: inactive")).0,
            "NeedsRestart"
        );
        // 服务在跑、端口在听，但外面连不上且 ufw 开着：只报防火墙，不自动改。
        let (verdict, detail) =
            preflight_verdict("Timeout", 18_443, &service(true, true, true, "Status: active"));
        assert_eq!(verdict, "Firewall", "{detail}");
        assert!(detail.contains("18443"), "{detail}");
        // ufw 没开时不能冒充「防火墙」这条结论。
        assert_eq!(
            preflight_verdict("Refused", 18_443, &service(true, true, true, "Status: inactive")).0,
            "Unknown"
        );
        // 握手失败是服务自身的问题：重启一次。
        assert_eq!(
            preflight_verdict("TlsFailed", 18_443, &service(true, true, true, "Status: inactive")).0,
            "NeedsRestart"
        );
    }

    #[test]
    fn preflight_parses_only_a_complete_service_report() {
        let parsed = parse_pair_service(
            "TC_UNIT=1\nTC_ACTIVE=active\nTC_ENABLED=enabled\nTC_LISTEN=1\nTC_UFW=Status: active\nTC_DONE=1\n",
        )
        .expect("完整回包要能解析");
        assert!(parsed.installed && parsed.active && parsed.enabled && parsed.listening);
        assert_eq!(parsed.ufw, "Status: active");
        // 少 TC_DONE：脚本被截断，缺字段不能被当成「没装/没监听」。
        assert!(parse_pair_service("TC_UNIT=1\nTC_ACTIVE=active\n").is_none());
    }

    #[test]
    fn auto_reroute_refuses_before_touching_a_connection() {
        let root = tmp_root("auto-reroute-guard");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let missing = call(r#"{"cmd":"auto-reroute","line":"nope","reason":"quality"}"#, &ctx);
        assert_eq!(missing["ok"], false, "{missing}");
        assert_eq!(missing["errorCode"], "usage", "{missing}");

        // 没有连接：不探测、不重连，直接说清楚。
        let idle = call(r#"{"cmd":"auto-reroute","line":"L1","reason":"quality"}"#, &ctx);
        assert_eq!(idle["ok"], false, "{idle}");
        assert_eq!(idle["errorCode"], "state", "{idle}");
        assert!(
            idle["error"].as_str().unwrap_or("").contains("没有连接"),
            "{idle}"
        );

        // 固定了连接方式：后台不许改用户的选择。
        let fixed = crate::config::parse(
            r#"{"schema":2,"selected":"L1","lines":[
                {"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901","transport":"tcp"}
            ]}"#,
        )
        .unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &fixed).unwrap();
        let pinned = call(r#"{"cmd":"auto-reroute","line":"L1","reason":"quality"}"#, &ctx);
        assert_eq!(pinned["ok"], false, "{pinned}");
        assert!(
            pinned["error"].as_str().unwrap_or("").contains("固定"),
            "{pinned}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quality_history_reads_the_perf_store_without_touching_the_network() {
        let root = tmp_root("quality");
        write_cfg(&root, "L1");
        crate::perf::record(&root, "L1", "标准", 120, std::time::SystemTime::now());
        crate::perf::record(&root, "L1", "标准", 180, std::time::SystemTime::now());
        let v = call(
            r#"{"cmd":"quality-history","id":"L1","window":"ThirtyMinutes"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["qualityHistory"]["NodeId"], "L1");
        assert_eq!(
            v["qualityHistory"]["Series"][0]["Aggregate"]["Statistics"]["MeasuredCount"], 2,
            "{v}"
        );
        // 另一条线路没有采样：明说没有数据，不给空曲线冒充。
        let other = call(
            r#"{"cmd":"quality-history","id":"L2","window":"ThirtyMinutes"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(other["qualityHistory"]["Reason"], "NoSamples");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quality_summary_counts_failures_and_latches_three_bad_attempts() {
        let root = tmp_root("quality-summary");
        write_cfg(&root, "L1");
        let now = std::time::SystemTime::now();
        // 三次都差：首页要出「线路变差」提醒，文案与旧版逐字一致。
        for ms in [600u64, 640, 700] {
            crate::perf::record(&root, "L1", "标准", ms, now);
        }
        let v = call(
            r#"{"cmd":"quality-summary","id":"L1","profile":"标准"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        let s = &v["qualitySummary"];
        assert_eq!(s["MeasuredCount"], 3);
        assert_eq!(s["Degraded"], true, "{v}");
        assert_eq!(s["Fresh"], true);
        assert_eq!(s["LastLatencyMs"], 700);
        assert!(s["NotificationMessage"]
            .as_str()
            .unwrap_or("")
            .contains("连续 3 次延迟较高"));

        // 一次超时混进来：没读数也算一次坏尝试，但原因不同 → 用「连续多次」那句。
        crate::perf::record_failure(&root, "L1", "标准", "MeasurementTimeout", now);
        let v = call(
            r#"{"cmd":"quality-summary","id":"L1","profile":"标准"}"#,
            &ctx_with(None, &root),
        );
        let s = &v["qualitySummary"];
        assert_eq!(s["SampleCount"], 4);
        assert_eq!(s["UnavailableCount"], 1);
        assert_eq!(s["TimeoutCount"], 1);
        assert_eq!(s["Degraded"], true);
        assert!(s["NotificationMessage"]
            .as_str()
            .unwrap_or("")
            .contains("连续多次高延迟或测量不可用"));

        // 恢复一次读数：最近三次不再全差，提醒必须撤掉（滚动窗口，不闩死）。
        crate::perf::record(&root, "L1", "标准", 120, now);
        let v = call(
            r#"{"cmd":"quality-summary","id":"L1","profile":"标准"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["qualitySummary"]["Degraded"], false, "{v}");
        assert_eq!(v["qualitySummary"]["NotificationMessage"], "");

        // 引擎故障不算线路变差。
        for _ in 0..3 {
            crate::perf::record_failure(&root, "L2", "标准", "ControllerUnavailable", now);
        }
        let v = call(
            r#"{"cmd":"quality-summary","id":"L2","profile":"标准"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["qualitySummary"]["Degraded"], false, "{v}");
        assert_eq!(v["qualitySummary"]["ControllerUnavailableCount"], 3);
        let _ = std::fs::remove_dir_all(&root);
    }
    fn config_bytes(root: &PathBuf) -> Vec<u8> {
        std::fs::read(root.join(crate::config::DEFAULT_PATH)).expect("配置必须存在")
    }

    fn connected_runtime(root: &PathBuf, probe_port: u16) {
        let pid = std::process::id();
        std::fs::write(
            root.join("runtime.json"),
            format!(
                r#"{{"SchemaVersion":1,"SupervisorPid":{pid},"EnginePid":{pid},"StartedAt":"2026-01-01T00:00:00Z","State":"Running","Error":null,"ProbeUser":"u","ProbePass":"p"}}"#
            ),
        )
        .unwrap();
        // T-13 measures a *valid* trade probe, not a bare untrusted local
        // SOCKS listener. The original helper omitted outbounds, selector,
        // routing and users, which correctly fails the production evidence
        // guard; restore the complete safe synthetic runtime contract here.
        let engine = serde_json::json!({
            "inbounds": [{
                "type": "socks", "tag": "tc-check", "listen": "127.0.0.1",
                "listen_port": probe_port,
                "users": [{ "username": "u", "password": "p" }]
            }],
            "outbounds": [
                { "type": "vless", "tag": "hk" },
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "trade-exit",
                    "outbounds": ["hk"], "default": "hk" },
                { "type": "selector", "tag": "daily-exit",
                    "outbounds": ["direct", "hk"], "default": "direct" }
            ],
            "route": { "rules": [
                { "inbound": ["tc-check"], "outbound": "trade-exit" }
            ] }
        });
        std::fs::write(root.join("runtime-engine.json"), engine.to_string()).unwrap();
    }

    /// 单次认证的假 tc-check 入站；只用于临时根上的 IPC 测量测试。
    fn latency_probe(status: u16) -> u16 {
        use std::io::Read;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut greeting = [0u8; 4];
            if stream.read_exact(&mut greeting).is_err() { return; }
            if stream.write_all(&[0x05, 0x02]).is_err() { return; }
            let mut head = [0u8; 2];
            if stream.read_exact(&mut head).is_err() { return; }
            let mut user = vec![0u8; head[1] as usize];
            if stream.read_exact(&mut user).is_err() { return; }
            let mut plen = [0u8; 1];
            if stream.read_exact(&mut plen).is_err() { return; }
            let mut pass = vec![0u8; plen[0] as usize];
            if stream.read_exact(&mut pass).is_err() { return; }
            let authed = user == b"u" && pass == b"p";
            if stream.write_all(&[0x01, u8::from(!authed)]).is_err() || !authed { return; }
            let mut connect = [0u8; 5];
            if stream.read_exact(&mut connect).is_err() { return; }
            let mut rest = vec![0u8; connect[4] as usize + 2];
            if stream.read_exact(&mut rest).is_err() { return; }
            if stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).is_err() { return; }
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\n\r\n").as_bytes());
        });
        port
    }

    // ---------- 管道机械 ----------

    #[test]
    fn name_is_namespaced_and_not_legacy() {
        let n = name_for(r"C:\SpiderVPN\data");
        assert!(n.starts_with("SpiderVPN."), "前缀不对：{n}");
        assert!(!n.contains("TradeChannelGuard"), "不能沾旧版名字");
        // 不同数据根必须得到不同名字
        assert_ne!(n, name_for(r"C:\Other\data"));
    }

    #[test]
    fn legacy_prefixed_name_is_rejected() {
        assert!(make_name("TradeChannel.control").is_err());
    }

    #[test]
    fn protocol_answers_ping_and_rejects_others() {
        assert!(handle_line(r#"{"cmd":"ping"}"#).contains("\"ok\":true"));
        assert!(handle_line(r#"{"cmd":"shutdown"}"#).contains("unknown_command"));
        assert!(handle_line("not json").contains("unknown_command"));
    }

    #[test]
    fn ping_roundtrip_and_absence() {
        let name = name_for(&format!("test-{}", std::process::id()));
        assert!(!ping(&name, 200), "没有服务端时必须返回 false");

        let stop = Arc::new(AtomicBool::new(false));
        let n2 = name.clone();
        let s2 = stop.clone();
        // 用临时数据根：别让 CWD 里恰好存在的 runtime.json 影响这条断言。
        let root = tmp_root("pipe");
        let h = std::thread::spawn(move || {
            let _ = serve(
                n2,
                s2,
                Ctx {
                    root: root.clone(),
                    log_dir: root.join("logs"),
                    ..Ctx::default()
                },
            );
        });

        assert!(wait_ready(&name, 2_000), "服务端起来后应可 ping 通");
        // 新命令必须真的能穿过管道，而不只是在函数级单测里通过。
        let st = request(&name, r#"{"cmd":"status"}"#).expect("status 必须能通过管道应答");
        assert!(st.contains("\"state\":\"Unconfigured\""), "管道应答不对：{st}");
        stop.store(true, Ordering::Relaxed);
        let _ = ping(&name, 100); // 触发一次连接让 accept 返回，从而检查 stop
        let _ = h.join();
    }

    #[test]
    fn wait_ready_times_out_when_nothing_listens() {
        // wait_ready 的语义是「重试到超时」：立刻返回 false 说明重试循环根本没跑，
        // 启动期就会把正常的慢启动误判成「控制接口不可用」。
        let name = name_for(&format!("test-waitready-{}", std::process::id()));
        let t0 = Instant::now();
        assert!(!wait_ready(&name, 300), "没有服务端时必须以 false 结束");
        assert!(t0.elapsed().as_millis() >= 250, "必须真的等满窗口，而不是立刻 false");
    }

    #[test]
    fn ping_answers_while_a_long_command_is_running() {
        // connect 实际要跑「起引擎（含 800ms 宽限）+ 自检（最多 2s）」。
        // 如果它还堵在 accept 循环里，ping 会跟着超时，`wait_ready` 就会误判控制接口不可用。
        let name = name_for(&format!("test-slow-{}", std::process::id()));
        let root = tmp_root("slow");
        let ctx = Ctx {
            root: root.clone(),
            log_dir: root.join("logs"),
            ..Ctx::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        // 慢 handler：把 connect 拖成 1.5 秒，等价于真实链路的耗时。
        // 用一个标志确认它「真的进去了」，否则这条用例会退化成空跑。
        let entered = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let entered_in_handler = Arc::clone(&entered);
        let finished_in_handler = Arc::clone(&finished);
        let slow: Arc<Handler> = Arc::new(move |line: &str, c: &Ctx| {
            if line.contains("\"connect\"") {
                entered_in_handler.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1_500));
                finished_in_handler.store(true, Ordering::SeqCst);
            }
            handle_line_with(line, c)
        });
        let (n, s) = (name.clone(), Arc::clone(&stop));
        let h = std::thread::spawn(move || {
            let _ = serve_with(n, s, ctx, slow);
        });
        assert!(wait_ready(&name, 2_000), "服务端应当起来了");

        // 后台发一个长命令，并量出它真的占住了多久
        let n2 = name.clone();
        let client = std::thread::spawn(move || {
            let t0 = Instant::now();
            let _ = request(&n2, r#"{"cmd":"connect"}"#);
            t0.elapsed()
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !entered.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(entered.load(Ordering::SeqCst), "长命令没进 handler，这条用例会变成空跑");
        assert!(!finished.load(Ordering::SeqCst), "发 ping 前长命令就结束了，这条用例会退化成空跑");

        // 不以固定的 100ms 墙钟作判据：满载调度本身就可能超过它。给接收足够宽的窗口，
        // 再以长命令实际占用时间为尺度；若 accept 被长命令堵死，ping 会等到长命令结束，
        // 耗时约等于 held，不可能低于 held 的四分之一。
        let t0 = Instant::now();
        let ok = ping(&name, 5_000);
        let ping_elapsed = t0.elapsed();
        assert!(ok, "长命令执行中 ping 必须仍能应答（实测 {ping_elapsed:?}）");

        let held = client.join().expect("客户端线程");
        assert!(
            held.as_millis() >= 1_400,
            "长命令应当真的占住约 1.5 秒，实测 {held:?} —— 用例没测到东西"
        );
        assert!(
            ping_elapsed <= held / 4,
            "ping 不应排队等待长命令：ping 实测 {ping_elapsed:?}，长命令实测 {held:?}（判据：不超过其 1/4）"
        );

        stop.store(true, Ordering::Relaxed);
        let _ = ping(&name, 100);
        let _ = h.join();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 配对的两步必须与 connect/import 共用同一道事务门：并发跑会撞临时文件名
    /// （`lines/<id>.json.tmp`、`config.json.tmp`），后写者赢、前一条线路消失。
    ///
    /// 断言点名逐条列出（而不是 `assert!(is_long_command(...))` 一把梭）：
    /// 将来有人往白名单里加命令时，这条会逼他先想清楚「这条会不会并发撞文件」。
    #[test]
    fn pairing_commands_hold_the_transaction_gate() {
        for cmd in [
            r#"{"cmd":"pair-verify","code":"TCI1.x"}"#,
            r#"{"cmd":"pair-join","code":"TCI1.x","name":"香港"}"#,
            // 离线申请会造密钥并写登记；离线完成会解封授权并写线路与配置。
            r#"{"cmd":"pair-offline-request","invite":"a.b.c","device":"本机"}"#,
            r#"{"cmd":"pair-offline-complete","enrollmentId":"e","authorization":"x"}"#,
            // 离线批准要 SSH（先推脚本再签发），与在线邀请同一条事务门。
            r#"{"cmd":"invite-authorize","line":"L1","request":"a.b.c"}"#,
        ] {
            assert!(is_long_command(cmd), "配对命令必须在长命令白名单里：{cmd}");
        }
        // 反过来钉住：这些是同步小命令，加进白名单会让界面点击变慢，也一样要解释。
        //
        // `set-engine` 明确**不是**长命令，理由（值得写下来，因为它是「也会写 config.json」
        // 却不在门里的那一个）：
        // 1. 它是 `Step::Sync`——页面上点一下就要立刻回话。而 `main.rs` 里长命令的事务门是
        //    在 **UI 线程**上抢的（`ui::is_long_command(raw).then(|| gate.lock())`）；
        //    把它加进白名单等于「connect 进行中时，点一下引擎按钮就把 UI 线程堵到 connect
        //    结束」——正是这轮要消灭的那种「点了没反应」。
        // 2. 它与 connect 真正危险的重叠（引擎已经在跑）由 `apply_engine_choice` 里的
        //    `busy()` 拒绝掉了；`busy()` 判的是「引擎活着 / 还有还原凭据」。
        // 3. 这和既有写配置的同步命令是同一套做法：`use` / `remove` / `set-transport` /
        //    `settings` 全是 Sync + `busy()` 拒绝，没有一个是靠事务门互斥的。
        // 4. 它写文件走 `config::save_with_origin` 的「临时文件 + rename」，本身是原子的。
        for cmd in [
            r#"{"cmd":"status"}"#,
            r#"{"cmd":"lines"}"#,
            r#"{"cmd":"set-engine","path":"C:/x/sing-box.exe"}"#,
        ] {
            assert!(!is_long_command(cmd), "同步命令不该占事务门：{cmd}");
        }
        assert!(!is_long_command("not json"), "解析不出来就不是长命令");
    }

    #[test]
    fn set_engine_writes_the_binary_only_after_it_really_answers_version() {
        let root = tmp_root("set-engine");
        let cfg = write_cfg(&root, "L1");
        let ctx = ctx_with(Some(cfg), &root);
        // 造一个真的文件（内容无所谓，探测动作是注入的）。
        let fake = root.join("sing-box.exe");
        std::fs::write(&fake, b"stub").unwrap();
        let raw = serde_json::json!({"cmd":"set-engine","path": fake.to_string_lossy()}).to_string();

        // ① 探测通过 → 写进 config.json，并回报版本号（那就是「真的验过」的证据）。
        let ok = set_engine_json_in(&ctx, &raw, &|path: &std::path::Path| {
            assert_eq!(path, fake.as_path(), "探测的必须就是用户挑的那一个");
            Ok("sing-box version 1.14.2".to_string())
        });
        let v: serde_json::Value = serde_json::from_str(&ok).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        assert!(v["message"].as_str().unwrap().contains("1.14.2"), "{v}");
        assert_eq!(v["engine"]["binary"], fake.to_string_lossy().as_ref(), "{v}");
        let saved = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.engine.as_ref().map(|e| e.binary.as_str()),
            Some(fake.to_string_lossy().as_ref()),
            "探测通过却没写进配置"
        );

        // ② 探测失败（不是引擎）→ 拒绝，且配置里一个字节都不许动。
        let before = std::fs::read_to_string(root.join(crate::config::DEFAULT_PATH)).unwrap();
        let refused = set_engine_json_in(&ctx, &raw, &|_: &std::path::Path| {
            Err("这个程序不是 sing-box".to_string())
        });
        let v: serde_json::Value = serde_json::from_str(&refused).unwrap();
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap().contains("sing-box"), "{v}");
        assert_eq!(
            std::fs::read_to_string(root.join(crate::config::DEFAULT_PATH)).unwrap(),
            before,
            "探测失败之后配置被改动了"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_engine_refuses_bad_paths_and_never_runs_a_probe_for_them() {
        let root = tmp_root("set-engine-bad");
        let ctx = ctx_with(Some(write_cfg(&root, "L1")), &root);
        let calls = std::cell::Cell::new(0u32);
        let probe = |_: &std::path::Path| -> Result<String, String> {
            calls.set(calls.get() + 1);
            Ok("sing-box version 1.14.2".to_string())
        };
        let notes = root.join("notes.txt");
        std::fs::write(&notes, b"x").unwrap();
        let dir = root.join("folder.exe");
        std::fs::create_dir_all(&dir).unwrap();

        let cases = [
            ("空路径", String::new()),
            ("不存在", root.join("nope.exe").to_string_lossy().to_string()),
            ("不是 exe", notes.to_string_lossy().to_string()),
            ("是目录", dir.to_string_lossy().to_string()),
        ];
        for (label, path) in cases {
            let raw = serde_json::json!({"cmd":"set-engine","path": path}).to_string();
            let reply = set_engine_json_in(&ctx, &raw, &probe);
            let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(v["ok"], false, "{label}：{v}");
            assert!(!v["error"].as_str().unwrap_or_default().is_empty(), "{label}：{v}");
        }
        assert_eq!(calls.get(), 0, "路径都没过就先别去跑它——那等于执行用户随手填的任意程序");

        // 连接中拒绝：换引擎会让还原凭据与实际引擎对不上（且同样不许先去跑它）。
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let fake = root.join("sing-box.exe");
        std::fs::write(&fake, b"stub").unwrap();
        let raw = serde_json::json!({"cmd":"set-engine","path": fake.to_string_lossy()}).to_string();
        let v: serde_json::Value =
            serde_json::from_str(&set_engine_json_in(&ctx, &raw, &probe)).unwrap();
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap().contains("断开"), "{v}");
        assert_eq!(calls.get(), 0, "连接中就该拒绝，不该先跑一遍");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_engine_without_a_config_says_what_to_do_instead_of_creating_one() {
        let root = tmp_root("set-engine-nocfg");
        let ctx = ctx_with(None, &root);
        let fake = root.join("sing-box.exe");
        std::fs::write(&fake, b"stub").unwrap();
        let raw = serde_json::json!({"cmd":"set-engine","path": fake.to_string_lossy()}).to_string();
        let v: serde_json::Value = serde_json::from_str(&set_engine_json_in(
            &ctx,
            &raw,
            &|_: &std::path::Path| Ok("sing-box version 1.14.2".to_string()),
        ))
        .unwrap();
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap().contains("config.json"), "{v}");
        assert!(
            !root.join(crate::config::DEFAULT_PATH).exists(),
            "没有线路时不该凭空造一份配置"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 真探测：自己的测试二进制不是 sing-box，必须被拒（这条跑的是真实 `version` 路径）。
    #[test]
    fn the_real_probe_rejects_a_program_that_is_not_sing_box() {
        if crate::engine::tests::isolated_engine_entry(
            "ipc::tests::the_real_probe_rejects_a_program_that_is_not_sing_box",
            r"C:\Windows\System32\whoami.exe",
        ) { return; }
        let elevated = crate::engine::actual_process_elevation().expect("actual process token");
        assert_eq!(std::env::var("SPIDERVPN_FORCE_NONADMIN").as_deref(), Ok("1"));
        let exe = std::env::current_exe().expect("测试进程自己的路径");
        let root = exe.parent().unwrap();
        let bundled = root.join("sing-box.exe");
        let external = root.join("external");
        std::fs::create_dir(&external).unwrap();
        let foreign = external.join("sing-box.exe");
        std::fs::copy(&bundled, &foreign).unwrap();
        // A real, harmless external same-name executable must be rejected
        // at the entry gate, not merely after it ran its version command.
        for path in [&exe, &foreign] {
            let error = probe_engine_binary(path).expect_err("测试二进制不可能是 sing-box");
            if elevated {
                assert!(error.contains("同目录"), "{error}");
            }
            assert!(error.contains("sing-box") || error.contains("version"), "{error}");
        }
        if elevated {
            crate::engine::tests::with_engine_junction(root, |linked| {
                let error = probe_engine_binary(linked).expect_err("junction must be refused before spawn");
                assert!(error.contains("重解析"), "{error}");
            });
            let error = probe_engine_binary(&root.join("missing.exe")).unwrap_err();
            assert!(error.contains("存在"), "{error}");
        }
        // The trusted-directory policy positively permits this controlled
        // image to execute; its *actual version protocol* is not sing-box.
        // Retain the old real-exec negative rather than replacing it with
        // only a path-policy failure.
        let error = probe_engine_binary(&bundled).expect_err("测试二进制不可能是 sing-box");
        assert!(error.contains("version"), "must reach real version handling: {error}");
        assert!(!error.contains("同目录"), "{error}");
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={elevated} legacy_force_nonadmin=1 actual_probe=true external_rejected={elevated} junction_rejected={elevated} missing_rejected={elevated} non_sing_box_protocol_refused=true");
        assert!(
            error.contains("sing-box") || error.contains("version"),
            "拒绝理由要说清为什么不是引擎：{error}"
        );
    }

    #[test]
    fn pipe_waits_for_the_ui_transaction_gate_but_ping_still_answers() {
        let name = name_for(&format!("test-shared-gate-{}", std::process::id()));
        let root = tmp_root("shared-gate");
        let gate = Arc::new(std::sync::Mutex::new(()));
        let ctx = Ctx {
            root: root.clone(),
            log_dir: root.join("logs"),
            transaction_gate: Arc::clone(&gate),
            ..Ctx::default()
        };
        let entered = Arc::new(AtomicBool::new(false));
        let entered_handler = Arc::clone(&entered);
        let handler: Arc<Handler> = Arc::new(move |line: &str, c: &Ctx| {
            if line.contains("\"connect\"") {
                entered_handler.store(true, Ordering::SeqCst);
            }
            handle_line_with(line, c)
        });
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let (name, stop) = (name.clone(), Arc::clone(&stop));
            std::thread::spawn(move || { let _ = serve_with(name, stop, ctx, handler); })
        };
        assert!(wait_ready(&name, 2_000));

        // 模拟 WebView 工作线程已经持有同一把事务锁。
        let ui_guard = gate.lock().unwrap();
        let client = {
            let name = name.clone();
            std::thread::spawn(move || request(&name, r#"{"cmd":"connect"}"#))
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!entered.load(Ordering::SeqCst), "管道长命令不得越过 UI 已持有的事务门");
        assert!(ping(&name, 200), "长命令等待事务门时 ping 仍必须应答");
        drop(ui_guard);
        assert!(client.join().unwrap().is_some(), "释放事务门后管道命令必须完成");
        assert!(entered.load(Ordering::SeqCst));

        stop.store(true, Ordering::Relaxed);
        let _ = ping(&name, 100);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn short_configuration_writes_are_separate_from_long_commands() {
        for cmd in [
            "use", "remove", "split-add", "split-remove", "split-reset-trade-domains",
            "agents-save", "agents-lane", "exit-set", "set-transport", "set-mode",
            "set-engine", "rename-line", "line-network-set", "settings",
        ] {
            let line = serde_json::json!({"cmd": cmd}).to_string();
            assert!(is_short_write_command(&line), "写操作缺少互斥分类：{cmd}");
            assert!(!is_long_command(&line), "短操作不许变成长操作：{cmd}");
        }
        for cmd in ["status", "ping", "lines", "split", "agents", "guard-status"] {
            let line = serde_json::json!({"cmd": cmd}).to_string();
            assert!(!is_short_write_command(&line), "只读命令不许抢写入锁：{cmd}");
        }
    }

    #[test]
    fn only_long_commands_take_the_serial_gate() {
        assert!(is_long_command(r#"{"cmd":"connect"}"#));
        assert!(is_long_command(r#"{"cmd":"disconnect"}"#));
        assert!(is_long_command(r#"{"cmd":"diagnose"}"#));
        assert!(is_long_command(r#"{"cmd":"restore"}"#), "还原不能与连接/断开并发写代理");
        assert!(is_long_command(r#"{"cmd":"import"}"#), "导入不能与连接/断开并发改配置");
        assert!(is_long_command(r#"{"cmd":"measure-latency"}"#), "网络测量不得阻塞 WebView UI 或越过事务门");
        assert!(is_long_command(r#"{"cmd":"use-compatible"}"#), "兼容重连必须作为一个完整长事务串行执行");
        assert!(is_long_command(r#"{"cmd":"guard-verify"}"#), "显式核验可能等 UAC，不能占 UI 线程");
        assert!(is_long_command(r#"{"cmd":"guard-remove"}"#), "解除要 WFP 事务 + 回读，不能占 UI 线程");
        assert!(!is_long_command(r#"{"cmd":"guard-status"}"#), "只读状态必须同步快速返回");
        assert!(!is_long_command(r#"{"cmd":"guard-precheck"}"#), "预检不写任何东西，必须同步返回");
        assert!(!is_long_command(r#"{"cmd":"ping"}"#), "ping 不能被闸门拖住");
        assert!(!is_long_command(r#"{"cmd":"status"}"#));
        assert!(!is_long_command("not json"));
    }

    #[test]
    fn operation_budget_uses_the_read_only_diagnose_plan() {
        assert_eq!(operation_budget(r#"{"cmd":"connect"}"#, &Ctx::default()), 30.0);
        assert_eq!(operation_budget(r#"{"cmd":"disconnect"}"#, &Ctx::default()), 30.0);
        assert_eq!(operation_budget(r#"{"cmd":"restore"}"#, &Ctx::default()), 30.0);
        assert_eq!(operation_budget(r#"{"cmd":"import"}"#, &Ctx::default()), 60.0);
        assert_eq!(operation_budget(r#"{"cmd":"measure-latency"}"#, &Ctx::default()), 5.0);
        assert_eq!(operation_budget(r#"{"cmd":"use-compatible"}"#, &Ctx::default()), 60.0);
        assert_eq!(operation_budget(r#"{"cmd":"status"}"#, &Ctx::default()), 0.0);

        let root = tmp_root("operation-budget");
        let mut cfg = write_cfg(&root, "L1");
        cfg.lines[0].transport = Some(crate::config::Transport::Tcp);
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        write_line_file(&root, "L1", true);
        let line_path = root.join("lines").join("L1.json");
        let line = std::fs::read_to_string(&line_path).unwrap()
            .replace("\"provider-a\"", &format!("\"{}\"", crate::engine_config::TRANSPORT_TAG));
        std::fs::write(&line_path, line).unwrap();
        let ctx = ctx_with(None, &root);
        let (_, plan) = diagnose_plan(&ctx).expect("测试线路必须能生成诊断计划");
        assert!(!plan.tcp.is_empty(), "预算测试不能退化成空计划");
        assert_eq!(operation_budget(r#"{"cmd":"diagnose"}"#, &ctx), plan.tcp.len() as f64 * 2.5 + 5.0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn operation_budget_adds_guard_elevation_time_only_for_trade_lists() {
        let root = tmp_root("operation-budget-guard");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        // 没有交易名单：连接/断开都不该为保护预留 UAC 时间。
        assert_eq!(operation_budget(r#"{"cmd":"connect"}"#, &ctx), 30.0);
        assert_eq!(operation_budget(r#"{"cmd":"disconnect"}"#, &ctx), 30.0);

        let added = call(
            r#"{"cmd":"split-add","kind":"process","value":"TDXW.exe","target":"trade"}"#,
            &ctx,
        );
        assert_eq!(added["ok"], true, "{added}");
        // 有交易名单：连接前装保护、断开后重核验都可能等一次 UAC。
        assert_eq!(operation_budget(r#"{"cmd":"connect"}"#, &ctx), 210.0);
        assert_eq!(operation_budget(r#"{"cmd":"disconnect"}"#, &ctx), 210.0);
        assert_eq!(operation_budget(r#"{"cmd":"guard-verify"}"#, &ctx), 120.0);
        assert_eq!(operation_budget(r#"{"cmd":"guard-install"}"#, &ctx), 120.0);
        assert_eq!(operation_budget(r#"{"cmd":"guard-sync"}"#, &ctx), 120.0);
        assert_eq!(operation_budget(r#"{"cmd":"guard-remove"}"#, &ctx), 120.0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn guard_read_commands_stay_sync_and_actions_refuse_without_config() {
        let root = tmp_root("guard-commands-nocfg");
        let ctx = ctx_with(None, &root);
        let status = call(r#"{"cmd":"guard-status"}"#, &ctx);
        assert_eq!(status["ok"], true, "{status}");
        assert_eq!(status["Guard"], "Unknown", "{status}");
        assert_eq!(status["TradeProgramCount"], -1, "{status}");
        assert!(status["guard"].is_object(), "完整投影必须随回包带给界面：{status}");

        let precheck = call(r#"{"cmd":"guard-precheck"}"#, &ctx);
        assert_eq!(precheck["ok"], true, "{precheck}");
        assert_eq!(precheck["TradeProgramCount"], -1, "{precheck}");
        assert_eq!(precheck["WillPrompt"], false, "没有名单不许弹 UAC：{precheck}");

        for cmd in ["guard-verify", "guard-install", "guard-sync", "guard-remove"] {
            let reply = call(&format!(r#"{{"cmd":"{cmd}"}}"#), &ctx);
            assert_eq!(reply["ok"], false, "{cmd} 没配置必须拒绝：{reply}");
            assert!(
                reply["error"].as_str().unwrap_or_default().contains("config.json"),
                "{cmd} 的失败原因要说清缺什么：{reply}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P0-13 的**安全默认值**：`acknowledgeRunning` 只认明确的 `true`。
    ///
    /// 这条读法错了不会报错，只会让「提示」失效：默认 true = 白名单程序在跑也直接弹 UAC；
    /// 默认 false 但把 `"true"`（字符串）当真 = 页面改一个字就能绕过提示。两种都要钉住。
    #[test]
    fn guard_acknowledge_running_defaults_to_false() {
        // 缺失 → 不放行。
        assert!(!acknowledge_running_of(r#"{"cmd":"guard-install"}"#));
        // 明确的 true / false。
        assert!(acknowledge_running_of(r#"{"cmd":"guard-install","acknowledgeRunning":true}"#));
        assert!(!acknowledge_running_of(r#"{"cmd":"guard-install","acknowledgeRunning":false}"#));
        // 非布尔一律按「没确认」处理（字符串 "true" 也不算数）。
        assert!(!acknowledge_running_of(
            r#"{"cmd":"guard-install","acknowledgeRunning":"true"}"#
        ));
        assert!(!acknowledge_running_of(r#"{"cmd":"guard-install","acknowledgeRunning":1}"#));
        assert!(!acknowledge_running_of(r#"{"cmd":"guard-install","acknowledgeRunning":null}"#));
        // 同级不同名也不算（大小写/别名的宽容会把「确认」这件事做松）。
        assert!(!acknowledge_running_of(
            r#"{"cmd":"guard-install","acknowledgerunning":true}"#
        ));
        // 请求本身坏掉时同样不放行。
        assert!(!acknowledge_running_of("not json"));
        assert!(!acknowledge_running_of("{"));
        assert!(!acknowledge_running_of(""));
    }

    // ---------- status / connect / disconnect ----------

    // ---------- AI 工具名单：读 / 全量保存 / 走向 ----------

    /// 一条**有完整 route 与两个选择器**的线路文件：名单规则要落在这里。
    fn write_agents_line(root: &PathBuf, id: &str, with_trade_exit: bool) {
        let trade = if with_trade_exit {
            r#"{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"},"#
        } else {
            ""
        };
        let body = format!(
            r#"{{"endpoints":[{{"type":"wireguard","tag":"hk"}}],
                "route":{{"rules":[{{"action":"route","inbound":["egress-probe"],"outbound":"daily-exit"}}],"final":"daily-exit"}},
                "outbounds":[{trade}{{"type":"selector","tag":"daily-exit","outbounds":["direct"],"default":"direct"}},{{"type":"direct","tag":"direct"}}]}}"#
        );
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.json")), body).unwrap();
    }

    /// 数出线路文件里**名单产生的规则**条数（`outbound` + 选择条件、没有别的键）。
    fn agents_rule_count(path: &PathBuf) -> usize {
        let text = std::fs::read_to_string(path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["route"]["rules"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter(|r| {
                        r.get("outbound").is_some()
                            && (r.get("process_name").is_some()
                                || r.get("process_path_regex").is_some()
                                || r.get("domain_suffix").is_some())
                            && !r.as_object().map(|o| o.keys().any(|k| k != "outbound" && k != "process_name" && k != "process_path_regex" && k != "domain_suffix")).unwrap_or(true)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[test]
    fn agents_payload_lists_catalog_and_marks_trade_list_overlap() {
        let root = tmp_root("agents-payload");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        // 交易名单里已经有 claude.exe 与 qq.com（名单页那几行要如实标注）
        call(r#"{"cmd":"split-add","kind":"process","value":"claude.exe"}"#, &ctx);
        call(r#"{"cmd":"split-add","kind":"domain","value":"qq.com"}"#, &ctx);
        let saved = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":["cursor"],"Programs":["my-scan.exe"],"Sites":["qq.com","perplexity.ai"]}"#,
            &ctx,
        );
        assert_eq!(saved["ok"], true, "{saved}");

        let v = call(r#"{"cmd":"agents"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let builtin = v["builtin"].as_array().expect("builtin 必须是数组");
        assert_eq!(builtin.len(), 22, "目录**永远给全 22 项**（未勾选也要给）：{v}");
        let find = |id: &str| {
            builtin
                .iter()
                .find(|b| b.get("id").and_then(|x| x.as_str()) == Some(id))
                .cloned()
                .expect("目录项必须在")
        };
        assert_eq!(find("cursor")["checked"], true, "勾选态来自配置：{v}");
        assert_eq!(find("windsurf")["checked"], false, "{v}");
        assert_eq!(find("claude-code")["inTradeList"], true, "与交易名单重叠要标出来：{v}");
        assert_eq!(find("claude-web")["inTradeList"], false, "{v}");
        assert_eq!(find("claude-code")["kind"], "program");
        assert_eq!(find("chatgpt-web")["kind"], "web");
        assert!(find("chatgpt-web")["note"].as_str().unwrap_or("").contains("浏览器"), "{v}");
        // 自定义条目也带 inTradeList
        let programs = v["programs"].as_array().unwrap();
        assert_eq!(programs[0]["value"], "my-scan.exe");
        assert_eq!(programs[0]["inTradeList"], false);
        let sites = v["sites"].as_array().unwrap();
        assert_eq!(sites[0]["value"], "qq.com");
        assert_eq!(sites[0]["inTradeList"], true, "自定义网站与交易名单重叠：{v}");
        assert_eq!(v["agents"]["tradeExitPresent"], true);
        assert_eq!(v["agents"]["lane"], "trade");
        assert_eq!(v["agents"]["count"], 4, "1 个内置 + 1 个程序 + 2 个网站：{v}");
        assert_eq!(v["agents"]["busy"], false);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_save_persists_and_applies_immediately() {
        let root = tmp_root("agents-save");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let line = root.join("lines").join("L1.json");
        assert_eq!(agents_rule_count(&line), 0, "还没保存时一条名单规则都不该有");

        let v = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":["claude-code","chatgpt-web"],"Programs":["my-scan.exe"],"Sites":["perplexity.ai"]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["changed"], true, "{v}");
        assert_eq!(v["agents"]["count"], 4, "{v}");
        let message = v["agentsMessage"].as_str().unwrap_or("");
        assert!(message.contains("下次连接时生效"), "要写清什么时候生效：{message}");

        // 落盘：config.json 能读回来
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten().unwrap();
        assert_eq!(disk.agents.lane, crate::config::AgentsLane::Trade);
        assert_eq!(disk.agents.builtin, vec!["claude-code", "chatgpt-web"]);
        assert_eq!(disk.agents.programs, vec!["my-scan.exe"]);
        assert_eq!(disk.agents.sites, vec!["perplexity.ai"]);
        // 立刻落到线路引擎配置：程序 1 条 + 浏览器+域名 1 条 + 纯域名 1 条
        assert_eq!(agents_rule_count(&line), 3, "名单要立刻写进线路配置（三条）");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_save_is_refused_while_connected_without_side_effects() {
        let root = tmp_root("agents-busy");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        // 半接管状态：有还原凭据 = 有连接在跑
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let ctx = ctx_with(None, &root);
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let line_path = root.join("lines").join("L1.json");
        let cfg_before = std::fs::read(&cfg_path).unwrap();
        let line_before = std::fs::read(&line_path).unwrap();

        let v = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":["cursor"],"Programs":[],"Sites":[]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "busy", "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("请先断开"), "{v}");
        // **零副作用**：两份文件都必须一模一样（不能只断言第一份）
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before, "连接中保存不许改 config.json");
        assert_eq!(std::fs::read(&line_path).unwrap(), line_before, "连接中保存不许改线路配置");

        // 走向命令走同一道闸门
        let v = call(r#"{"cmd":"agents-lane","Value":"Trade"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "busy", "{v}");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before, "走向也要零副作用");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_save_rejects_bad_values() {
        let root = tmp_root("agents-bad");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let before = std::fs::read(&cfg_path).unwrap();

        let v = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":["not-an-exe"],"Sites":[]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "invalid", "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains(".exe"), "{v}");

        let v = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":[],"Sites":["https://qq.com/a"]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("协议或路径"), "{v}");

        let v = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":[],"Sites":["abc"]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("至少要有两级"), "{v}");

        // 超限：33 项
        let sites: Vec<String> = (0..33).map(|i| format!("\"s{i}.com\"")).collect();
        let over = format!(
            r#"{{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":[],"Sites":[{}]}}"#,
            sites.join(",")
        );
        let v = call(&over, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "tooMany", "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("32"), "{v}");

        // 非法走向也不许默默当 daily
        let v = call(
            r#"{"cmd":"agents-save","Lane":"direct","Builtin":[],"Programs":[],"Sites":[]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or("").contains("Daily / Trade"), "{v}");

        assert_eq!(std::fs::read(&cfg_path).unwrap(), before, "全部失败都不许改配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_save_while_connected_keeps_every_byte_and_says_how_to_retry() {
        // 先存一份基线（未连接时），再模拟连接中保存：两份文件都必须零字节变化。
        let root = tmp_root("agents-busy-qa");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let saved = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":["cursor"],"Programs":[],"Sites":["qq.com"]}"#,
            &ctx,
        );
        assert_eq!(saved["ok"], true, "{saved}");

        // 半接管状态（有还原凭据）= 有连接在跑；与既有 connection_busy 夹具同一做法。
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let line_path = root.join("lines").join("L1.json");
        let cfg_before = std::fs::read(&cfg_path).unwrap();
        let line_before = std::fs::read(&line_path).unwrap();

        // `Lane` 省略（= 保持现值）也必须被同一道闸门挡住；不许出现「改了一半」。
        let v = call(
            r#"{"cmd":"agents-save","Builtin":["windsurf"],"Programs":["new-scan.exe"],"Sites":["perplexity.ai"]}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "busy", "{v}");
        let said = v["error"].as_str().unwrap_or("");
        assert!(said.contains("请先断开") && said.contains("保存"), "文案要能照做：{said}");
        assert!(v.get("agentsMessage").is_none(), "被拒时不许回一句「已保存」：{v}");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before, "连接中保存不许改 config.json");
        assert_eq!(std::fs::read(&line_path).unwrap(), line_before, "连接中保存不许改线路配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn site_input_normalizes_star_and_case_and_refuses_url_or_bare_host() {
        // PRD P0-3-6 的三种输入：带协议/路径、单级域名要拒绝且文案可照做；`*.QQ.com` 归一成 qq.com。
        let root = tmp_root("agents-site-qa");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let before = std::fs::read(&cfg_path).unwrap();

        let url = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":[],"Sites":["http://x.com/a"]}"#,
            &ctx,
        );
        assert_eq!(url["ok"], false, "{url}");
        assert_eq!(url["errorCode"], "invalid", "{url}");
        let said = url["error"].as_str().unwrap_or("");
        assert!(said.contains("协议或路径"), "要说明拒绝原因：{said}");

        let bare = call(
            r#"{"cmd":"agents-save","Lane":"trade","Builtin":[],"Programs":[],"Sites":["abc"]}"#,
            &ctx,
        );
        assert_eq!(bare["ok"], false, "{bare}");
        assert_eq!(bare["errorCode"], "invalid", "{bare}");
        let said = bare["error"].as_str().unwrap_or("");
        assert!(said.contains("至少要有两级") && said.contains("qq.com"), "要给出可照做的例子：{said}");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), before, "被拒的输入零副作用");

        let ok = call(
            "{\"cmd\":\"agents-save\",\"Lane\":\"trade\",\"Builtin\":[],\"Programs\":[],\"Sites\":[\" *.QQ.com \"]}",
            &ctx,
        );
        assert_eq!(ok["ok"], true, "{ok}");
        let disk = crate::config::load(&cfg_path).ok().flatten().unwrap();
        assert_eq!(disk.agents.sites, vec!["qq.com"], "去 `*.`、转小写、去空白");
        assert_eq!(ok["sites"][0]["value"], "qq.com", "回包也要给归一后的值：{ok}");
        let line = root.join("lines").join("L1.json");
        assert_eq!(agents_rule_count(&line), 1, "一条网站只能生成一条域名规则");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn old_config_without_agents_section_reads_as_daily_and_empty() {
        // 老配置（write_cfg 不写 `agents` 节）→ 读入不报错、快照是 Daily + 空名单、只读不改盘。
        let root = tmp_root("agents-old");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let before = std::fs::read(&cfg_path).unwrap();

        let v = call(r#"{"cmd":"agents"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["agents"]["lane"], "daily", "缺省跟随日常上网：{v}");
        assert_eq!(v["agents"]["count"], 0, "空名单：{v}");
        assert_eq!(v["agents"]["busy"], false, "{v}");
        assert!(v["programs"].as_array().unwrap().is_empty());
        assert!(v["sites"].as_array().unwrap().is_empty());
        assert_eq!(v["builtin"].as_array().unwrap().len(), 22, "目录照样给全");
        assert!(
            v["builtin"].as_array().unwrap().iter().all(|b| b["checked"] == false),
            "一项都没勾：{v}"
        );
        assert_eq!(std::fs::read(&cfg_path).unwrap(), before, "只读命令不许把 agents 节写进老配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_lane_changes_only_the_lane() {
        let root = tmp_root("agents-lane");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        call(
            r#"{"cmd":"agents-save","Lane":"daily","Builtin":["cursor","chatgpt-web"],"Programs":["my-scan.exe"],"Sites":["perplexity.ai"]}"#,
            &ctx,
        );
        // 走向=daily 时一条规则都不该生成
        let line = root.join("lines").join("L1.json");
        assert_eq!(agents_rule_count(&line), 0, "跟随日常上网 = 不生成任何规则");

        let v = call(r#"{"cmd":"agents-lane","Value":"trade"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["changed"], true, "{v}");
        assert_eq!(v["agentsLane"], "trade", "{v}");
        assert!(v["agentsMessage"].as_str().unwrap_or("").contains("使用交易线路"), "{v}");
        assert_eq!(agents_rule_count(&line), 3, "改走向后规则要立刻生成三条");

        // 名单一个字都不许被走向命令改掉
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten().unwrap();
        assert_eq!(disk.agents.builtin, vec!["cursor", "chatgpt-web"], "走向命令不许动名单");
        assert_eq!(disk.agents.programs, vec!["my-scan.exe"]);
        assert_eq!(disk.agents.sites, vec!["perplexity.ai"]);
        assert_eq!(disk.agents.lane, crate::config::AgentsLane::Trade);
        // 重复设同一个值：ok 但 changed=false（与 split-add 的重复添加同一套口径）
        let v = call(r#"{"cmd":"agents-lane","Value":"trade"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["changed"], false, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_lane_accepts_capitalized_values() {
        // 前端传的是首字母大写（`state.Agents`）：这条路径上线第一次就得能通。
        let root = tmp_root("agents-lane-case");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        for value in ["Trade", "trade", "TRADE"] {
            let v = call(&format!(r#"{{"cmd":"agents-lane","Value":"{value}"}}"#), &ctx);
            assert_eq!(v["ok"], true, "「{value}」必须被接受：{v}");
        }
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten().unwrap();
        assert_eq!(disk.agents.lane, crate::config::AgentsLane::Trade);
        let v = call(r#"{"cmd":"agents-lane","Value":"Daily"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["agentsLane"], "daily", "{v}");
        // 认不出的值要如实报错（不能默默当成 Daily）
        let v = call(r#"{"cmd":"agents-lane","Value":"off"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_exposes_agents_lane_and_trade_exit_presence() {
        let root = tmp_root("agents-status");
        write_cfg(&root, "L1");
        write_agents_line(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["agentsLane"], "daily", "默认跟随日常上网：{v}");
        assert_eq!(v["tradeExitPresent"], true, "线路里有 trade-exit：{v}");
        call(r#"{"cmd":"agents-lane","Value":"Trade"}"#, &ctx);
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["agentsLane"], "trade", "{v}");
        // 没有交易出口的线路：如实报 false
        write_agents_line(&root, "L1", false);
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["tradeExitPresent"], false, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_every_field_the_window_reads() {
        let root = tmp_root("status");
        write_cfg(&root, "L2");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        // 字段名是契约：界面按这些名字取值，改名必须让这条先失败。
        for k in [
            "state", "title", "detail", "action", "enabled", "line", "endpoint",
            "proxy_enabled", "proxy_server", "legacy_running", "check", "checkHint", "mode", "modeChoice",
            "autoStart", "autoConnect", "closeToTray", "lineCount", "maintenance",
            "exitDaily", "exitTrade", "exitDailyMembers", "exitTradeMembers",
            "latencyMs", "measuredAtUtc", "transportActual", "compatibleAction",
            // AI 工具：存储的走向 + 这条线路有没有交易出口（页面据此说明「现在不会生效」）。
            "agentsLane", "tradeExitPresent",
            // 连接起点：界面算「引擎已运行 N 分」。**未连接时存在但为空串**，
            // 与「字段缺失」区分开——缺失会让页面去猜，空串明确表示「没有起点」。
            "startedAt",
        ] {
            assert!(v.get(k).is_some(), "status 缺少字段 {k}：{v}");
        }
        assert_eq!(v["line"], "线路乙", "选中线路的名字");
        assert_eq!(v["endpoint"], "127.0.0.1:17902");
        assert_eq!(v["lineCount"], 2);
        assert_eq!(v["mode"], "代理", "没写 mode 的配置按代理，界面据此显示模式");
        assert_eq!(v["autoStart"], false, "没写开关就不能默认自启");
        assert_eq!(v["autoConnect"], false);
        assert_eq!(v["closeToTray"], false, "没写开关就不能默认常驻");
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "Disconnected");
        assert_eq!(v["action"], "Connect");
        assert!(v["latencyMs"].is_null() && v["measuredAtUtc"].is_null(),
            "未连接不得投影上次测量：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 连接起点只在**真的连上**时给。
    ///
    /// 三档分开造，因为这个字段喂的是首页那句「引擎已运行 N 分」：
    /// ① 从没连过（没有运行记录）→ 空串；
    /// ② 有记录但没连上（引擎已死 / 上次崩了留下的残档）→ 还是空串；
    /// ③ 已连接 → 就是记录里的 `StartedAt`，逐字一致。
    ///
    /// ② 是关键：`runtime.json` 会活过连接（正常断开时删掉，进程被杀时留下）。
    /// 照抄 `StartedAt` 的话，界面会在什么都没跑的时候说「已运行 3 小时」。
    #[test]
    fn status_gives_a_start_time_only_while_connected() {
        let root = tmp_root("started-at");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);

        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["state"], "Disconnected", "{v}");
        assert_eq!(v["startedAt"], "", "没有连接就没有起点：{v}");

        // ② 记录在、引擎已死：把状态改成 Stopped，pid 保留（进程确实不在了才叫死，
        //    这里用「状态不是 Running」这一档来造，避免依赖某个 pid 恰好不存在）。
        connected_runtime(&root, 1080);
        let mut stopped: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("runtime.json")).unwrap())
                .unwrap();
        stopped["State"] = serde_json::json!("Stopped");
        std::fs::write(root.join("runtime.json"), stopped.to_string()).unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_ne!(v["state"], "Connected", "前提：这一档不算已连接：{v}");
        assert_eq!(v["startedAt"], "", "没连上就不许给起点：{v}");

        // ③ 真连上：起点就是记录里那一行。
        connected_runtime(&root, 1080);
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["state"], "Connected", "{v}");
        assert_eq!(v["startedAt"], "2026-01-01T00:00:00Z", "{v}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_measure_latency_refuses_when_disconnected_and_ping_stays_alive_probe() {
        let root = tmp_root("t13-disconnected");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let measured = call(r#"{"cmd":"measure-latency"}"#, &ctx);
        assert_eq!(measured["ok"], false, "未连接绝不能发网络测量：{measured}");
        assert_eq!(measured["errorCode"], "environment", "{measured}");
        assert!(measured["error"].as_str().unwrap_or_default().contains("连接后测量"), "{measured}");
        assert!(!root.join(crate::selfcheck::LATENCY_FILE_NAME).exists(), "拒绝不得生成测量记录");
        assert_eq!(handle_line_with(r#"{"cmd":"ping"}"#, &ctx),
            r#"{"ok":true,"product":"SpiderVPN"}"#, "ping 的实例存活语义不得改变");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_measure_latency_success_uses_runtime_probe_and_status_projects_same_reading() {
        let root = tmp_root("t13-success");
        write_cfg(&root, "L1");
        let port = latency_probe(204);
        connected_runtime(&root, port);
        crate::selfcheck::save(&root, &crate::selfcheck::Check {
            ok: true, status: Some(204), at: 42, ..Default::default()
        }).unwrap();
        let check_before = std::fs::read(root.join(crate::selfcheck::FILE_NAME)).unwrap();
        let ctx = ctx_with(None, &root);

        let measured = call(r#"{"cmd":"measure-latency"}"#, &ctx);
        assert_eq!(measured["ok"], true, "{measured}");
        assert!(measured["latencyMs"].as_u64().is_some(), "必须有真实毫秒数：{measured}");
        assert!(measured["measuredAtUtc"].as_str().is_some(), "必须有完成时间：{measured}");
        assert!(measured["latencyError"].is_null());
        assert_eq!(std::fs::read(root.join(crate::selfcheck::FILE_NAME)).unwrap(), check_before);

        let status = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(status["state"], "Connected", "测试前置必须是完整连接证据：{status}");
        assert_eq!(status["latencyMs"], measured["latencyMs"]);
        assert_eq!(status["measuredAtUtc"], measured["measuredAtUtc"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t13_measure_latency_network_failure_is_explicit_and_does_not_forge_a_reading() {
        let root = tmp_root("t13-failure");
        write_cfg(&root, "L1");
        let port = latency_probe(502);
        connected_runtime(&root, port);
        let previous = crate::selfcheck::Latency {
            latency_ms: 23, at: 1, connection_started_at: "2026-01-01T00:00:00Z".into(),
        };
        crate::selfcheck::save_latency(&root, &previous).unwrap();
        let ctx = ctx_with(None, &root);

        let failed = call(r#"{"cmd":"measure-latency"}"#, &ctx);
        assert_eq!(failed["ok"], false, "{failed}");
        assert_eq!(failed["errorCode"], "network");
        assert!(failed["latencyError"].as_str().unwrap_or_default().contains("HTTP 502"), "{failed}");
        assert_eq!(crate::selfcheck::load_latency(&root), Some(previous));
        let status = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(status["latencyMs"], 23, "状态只能保留上一次真实读数：{status}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_without_config_asks_to_setup() {
        let root = tmp_root("status-empty");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["state"], "Unconfigured");
        assert_eq!(v["action"], "Setup");
        assert_eq!(v["line"], "", "没配线路时线路名必须是空串，不能是占位符");
        assert_eq!(v["check"], "", "没自检记录时必须是空串（界面据此显示「未检测」）");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_last_selfcheck_conclusion() {
        let root = tmp_root("status-check");
        write_cfg(&root, "L1");
        crate::selfcheck::save(
            &root,
            &crate::selfcheck::Check { ok: true, status: Some(204), error: None, at: 1, skipped: None, via_trade_exit: false },
        )
        .unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["check"], "通过（HTTP 204）", "界面与 --status 必须说同一句话");
        assert_eq!(v["checkHint"], "", "结论通过就没有那句自救话");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 写一条线路的引擎配置：with_params 决定有没有兼容连接参数。
    fn write_line_file(root: &PathBuf, id: &str, with_params: bool) {
        let vless = if with_params {
            r#"{"type":"vless","tag":"provider-a","server":"203.0.113.7","server_port":443,
                "uuid":"11111111-2222-3333-4444-555555555555",
                "tls":{"enabled":true,"server_name":"cdn.example.com",
                       "reality":{"enabled":true,"public_key":"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1","short_id":"ab12"}}},"#
        } else {
            ""
        };
        let body = format!(
            r#"{{"endpoints":[{{"type":"wireguard","tag":"hk"}}],
                "outbounds":[{vless}
                    {{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"}},
                    {{"type":"direct","tag":"direct"}}]}}"#
        );
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.json")), body).unwrap();
    }

    // ---------- 连接方式：lines 载荷 / set-transport / 提示两路径一致 ----------

    #[test]
    fn lines_payload_carries_transport_and_whether_it_was_chosen() {
        let root = tmp_root("tr-payload");
        let mut cfg = write_cfg(&root, "L1");
        cfg.lines[0].transport = Some(crate::config::Transport::Tcp);
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        let v = lines_payload(Some(&cfg));
        let lines = v["lines"].as_array().expect("lines 数组");
        // L1：用户选了兼容连接
        assert_eq!(lines[0]["transport"], "tcp", "{v}");
        assert_eq!(lines[0]["transportSelected"], true, "「已选」必须如实上报：{v}");
        // L2：从没选过 → 当前值是 udp，但不是用户选的
        assert_eq!(lines[1]["transport"], "udp", "{v}");
        assert_eq!(lines[1]["transportSelected"], false, "没选过就是「默认」：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_transport_persists_and_replies_with_the_new_list() {
        let root = tmp_root("set-tr-ok");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        let line_file = root.join("lines").join("L1.json");
        let line_before = std::fs::read_to_string(&line_file).unwrap();

        let v = call(
            r#"{"cmd":"set-transport","transport":"tcp","id":"L1"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["message"], "已保存下次默认方式，当前连接保持", "文案照旧版：{v}");
        assert_eq!(v["lines"][0]["transport"], "tcp", "回包要带新列表：{v}");
        // 落盘：重读配置仍是新选择；线路文件与运行时配置一个字节都不动
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(disk.lines[0].transport, Some(crate::config::Transport::Tcp));
        assert_eq!(std::fs::read_to_string(&line_file).unwrap(), line_before, "线路文件不许动");
        assert!(!root.join("runtime-engine.json").exists(), "不该产出运行时配置");

        // 不带 id：作用在当前选中的那条上（L1）
        let v = call(r#"{"cmd":"set-transport","transport":"udp"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(disk.lines[0].transport, Some(crate::config::Transport::Udp), "显式选回标准连接要存下来");

        // 连接中允许切换（只影响下次连接）：这条语义与 --use/--remove 相反，值得钉住
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let v = call(r#"{"cmd":"set-transport","transport":"tcp"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "连接中必须能改下次默认方式：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 「自动」是**真命令**：取消固定（`transport = None`），但不动这条线路「已验证」的依据。
    #[test]
    fn set_transport_auto_clears_the_choice_and_keeps_the_verified_evidence() {
        let root = tmp_root("set-tr-auto");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        // 先摆一个真实的现场：用户固定了兼容连接，同时这条线路验证过标准连接。
        let mut cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .unwrap();
        cfg.lines[0].transport = Some(crate::config::Transport::Tcp);
        cfg.lines[0].verified_transport = Some(crate::config::Transport::Udp);
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();

        let v = call(
            r#"{"cmd":"set-transport","transport":"auto","id":"L1"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            v["message"], "已改为自动选择（采用这条线路已验证的方式）",
            "自动要用自己的文案，不能沿用「已保存下次默认方式」：{v}"
        );
        assert_eq!(v["lines"][0]["transport"], "udp", "自动 = 采用已验证的标准连接：{v}");
        assert_eq!(v["lines"][0]["transportSelected"], false, "自动不是「用户选的」：{v}");
        assert_eq!(v["lines"][0]["transportVerified"], true, "依据还在：{v}");

        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(disk.lines[0].transport, None, "自动必须落到 `transport = None`");
        assert_eq!(
            disk.lines[0].verified_transport,
            Some(crate::config::Transport::Udp),
            "`auto` 不许抹掉既有依据"
        );
        assert_eq!(disk.lines[0].effective_transport(), crate::config::Transport::Udp);

        // 没有依据的线路选「自动」也要成功：按标准连接兜底，并如实说「还没有依据」。
        let v = call(
            r#"{"cmd":"set-transport","transport":"auto","id":"L2"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["lines"][1]["transport"], "udp", "{v}");
        assert_eq!(v["lines"][1]["transportVerified"], false, "这条线路还没验证过：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 非法取值：报错必须把 `auto` 也算进可选值里，否则用户以为只有两种选择。
    #[test]
    fn set_transport_names_auto_in_the_rejection_message() {
        let root = tmp_root("set-tr-bad");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        let before = config_bytes(&root);
        let v = call(r#"{"cmd":"set-transport","transport":"quic"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        let error = v["error"].as_str().unwrap_or_default();
        assert!(error.contains("auto"), "报错里要有 auto：{v}");
        assert!(error.contains("udp") && error.contains("tcp"), "原有两种也不能少：{v}");
        assert_eq!(config_bytes(&root), before, "拒绝必须零副作用");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 出口网卡（A 组网卡绑定）：读、写、拒绝 ----------

    #[test]
    fn line_network_reads_the_binding_without_writing_anything() {
        let root = tmp_root("net-read");
        write_cfg(&root, "L1");
        let before = config_bytes(&root);
        let v = call(r#"{"cmd":"line-network","id":"L1"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let net = &v["lineNetwork"];
        assert_eq!(net["Id"], "L1", "{v}");
        assert_eq!(net["Bound"], "", "没指定过就是空串（跟随默认），不是「指定了一个空名字」");
        assert_eq!(net["Stale"], false, "{v}");
        // 没指定时**不绑**（`Effective` 为空）：把默认网卡名写进 `bind_interface`
        // 会让 sing-box 在 Windows 上解析不到接口（真机就是这样把出站全堵死的）。
        assert_eq!(net["Effective"], "", "没指定时不绑，交给引擎的 auto_detect_interface：{v}");
        assert!(net["Interfaces"].is_array(), "{v}");
        assert_eq!(config_bytes(&root), before, "只读命令不许改配置");
        assert!(
            !root.join(crate::netbind::FILE).exists(),
            "只读命令不许落一份绑定表出来"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn line_network_set_persists_a_real_interface_and_empty_clears_it() {
        let root = tmp_root("net-set");
        write_cfg(&root, "L1");
        let available = crate::autoroute::interfaces();
        let Some(name) = available.first().cloned() else {
            // 这台机器真的一块网卡都没读到：没有可测的东西。Windows 上不会发生。
            let _ = std::fs::remove_dir_all(&root);
            return;
        };
        let request = format!(
            r#"{{"cmd":"line-network-set","Id":"L1","Interface":{}}}"#,
            serde_json::json!(name)
        );
        let v = call(&request, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["lineNetwork"]["Bound"], name, "{v}");
        assert_eq!(v["lineNetwork"]["Stale"], false, "{v}");
        assert_eq!(v["lineNetwork"]["Effective"], name, "保存后这次连接就绑它：{v}");
        assert_eq!(
            crate::netbind::load(&root).get("L1"),
            Some(name.as_str()),
            "落盘要能读回来"
        );

        // 空串 = 跟随系统默认：这条绑定被删掉，只剩它时磁盘上不留文件。
        let v = call(
            r#"{"cmd":"line-network-set","Id":"L1","Interface":""}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["lineNetwork"]["Bound"], "", "{v}");
        assert!(crate::netbind::load(&root).get("L1").is_none());
        assert!(!root.join(crate::netbind::FILE).exists(), "空表不该留在磁盘上");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn line_network_set_refuses_an_interface_this_machine_does_not_have() {
        let root = tmp_root("net-refuse");
        write_cfg(&root, "L1");
        let v = call(
            r#"{"cmd":"line-network-set","Id":"L1","Interface":"不存在的网卡 XYZ"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "usage", "这是输入问题，不是环境问题：{v}");
        let error = v["error"].as_str().unwrap_or_default();
        assert!(error.contains("不存在的网卡 XYZ"), "要把那个名字说回去：{v}");
        assert!(
            error.contains("当前可用") || error.contains("一块也没读到"),
            "拒绝的同时要给出路（可用网卡或「跟随默认」）：{v}"
        );
        assert!(
            !root.join(crate::netbind::FILE).exists(),
            "拒绝必须零副作用：一个字节都不许写"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_binding_whose_interface_vanished_is_reported_and_not_bound() {
        let root = tmp_root("net-stale");
        write_cfg(&root, "L1");
        // 直接写一条「这块网卡现在不在这台电脑上」的绑定：不靠拔网线造现场。
        crate::netbind::set(&root, "L1", "雷雳网桥").unwrap();
        let v = call(r#"{"cmd":"line-network","id":"L1"}"#, &ctx_with(None, &root));
        let net = &v["lineNetwork"];
        assert_eq!(net["Bound"], "雷雳网桥", "{v}");
        assert_eq!(net["Stale"], true, "这块网卡不在了，必须如实上报：{v}");
        assert_eq!(net["StaleName"], "雷雳网桥", "{v}");
        assert_eq!(net["Effective"], "", "不绑一个不存在的名字（引擎会直接起不来）：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn line_network_on_an_unknown_line_is_a_usage_error() {
        let root = tmp_root("net-line-missing");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"line-network","Id":"nope"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        let error = v["error"].as_str().unwrap_or_default();
        assert!(error.contains("找不到线路"), "要说清是哪一类失败：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 线路动作记录：测速 / 连接方式的反馈、重试与核对 ----------

    fn actions_of(v: &serde_json::Value) -> &Vec<serde_json::Value> {
        v["lineActions"]["Actions"]
            .as_array()
            .expect("Actions 必须是数组")
    }

    /// 摆一条「上次进程退出了」的现场：先 `begin`（Pending），再走启动恢复。
    fn interrupted(
        root: &PathBuf,
        line_id: &str,
        line_name: &str,
        kind: &str,
        profile_id: &str,
        requested: &str,
    ) -> crate::lineaction::Action {
        let action =
            crate::lineaction::started(line_id, line_name, kind, profile_id, requested);
        let begun = crate::lineaction::begin(root, action).expect("开始记录必须落盘");
        crate::lineaction::recover_pending(root).expect("启动恢复必须成功");
        begun
    }

    #[test]
    fn a_user_measurement_on_a_disconnected_line_is_recorded_as_a_failed_check() {
        let root = tmp_root("la-check-offline");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);

        let measured = call(r#"{"cmd":"measure-latency","lineId":"L1"}"#, &ctx);
        assert_eq!(measured["ok"], false, "{measured}");
        let listed = call(r#"{"cmd":"line-action-list"}"#, &ctx);
        assert_eq!(listed["ok"], true, "{listed}");
        assert_eq!(listed["lineActions"]["ReadError"], "", "记录读得出来就不该报读错误");
        let actions = actions_of(&listed);
        assert_eq!(actions.len(), 1, "带 lineId 的用户测速必须留一条记录：{listed}");
        let action = &actions[0];
        assert_eq!(action["Kind"], "Check");
        assert_eq!(action["LineId"], "L1");
        assert_eq!(action["LineName"], "线路甲", "反馈要能贴回对应的线路卡片");
        assert_eq!(action["ProfileId"], "Udp");
        assert_eq!(action["Phase"], "Failed");
        assert_eq!(action["Code"], "environment");
        assert_eq!(action["Message"], "连接后测量", "失败的原话要留着，页面直接显示");
        assert_eq!(action["LatencyMs"], serde_json::Value::Null);

        // 自动采样（不带 lineId）不进记录：每 30 秒一条会把用户点过的动作淹掉，
        // 也会让「核对」分不清哪一条是人的操作。
        let auto = call(r#"{"cmd":"measure-latency"}"#, &ctx);
        assert_eq!(auto["ok"], false);
        assert_eq!(
            actions_of(&call(r#"{"cmd":"line-action-list"}"#, &ctx)).len(),
            1,
            "自动采样不许追加/覆盖用户动作"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_successful_user_measurement_is_recorded_with_the_reading() {
        let root = tmp_root("la-check-ok");
        write_cfg(&root, "L1");
        let port = latency_probe(204);
        connected_runtime(&root, port);
        let ctx = ctx_with(None, &root);

        let measured = call(r#"{"cmd":"measure-latency","lineId":"L1"}"#, &ctx);
        assert_eq!(measured["ok"], true, "{measured}");
        let listed = call(r#"{"cmd":"line-action-list"}"#, &ctx);
        let actions = actions_of(&listed);
        assert_eq!(actions.len(), 1, "{listed}");
        assert_eq!(actions[0]["Phase"], "Succeeded");
        assert_eq!(
            actions[0]["LatencyMs"], measured["latencyMs"],
            "记录与回包必须是同一次读数：{listed}"
        );
        let message = actions[0]["Message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("测得当前响应 {} ms", measured["latencyMs"])),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn saving_a_connection_method_from_a_line_card_leaves_a_preference_record() {
        let root = tmp_root("la-pref-ok");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        let ctx = ctx_with(None, &root);

        let saved = call(
            r#"{"cmd":"set-transport","transport":"tcp","id":"L1","source":"line-action"}"#,
            &ctx,
        );
        assert_eq!(saved["ok"], true, "{saved}");
        let listed = call(r#"{"cmd":"line-action-list"}"#, &ctx);
        let actions = actions_of(&listed);
        assert_eq!(actions.len(), 1, "卡片上的保存必须留反馈：{listed}");
        assert_eq!(actions[0]["Kind"], "Preference");
        assert_eq!(actions[0]["ProfileId"], "Tcp");
        assert_eq!(actions[0]["Requested"], "tcp");
        assert_eq!(actions[0]["Phase"], "Succeeded");
        assert_eq!(
            actions[0]["Message"], "已固定为兼容连接，下次连接生效。",
            "照旧版卡片原话：{listed}"
        );

        // 命令行/旧入口不带 source：行为不变，也不该凭空多出一条「用户动作」。
        let cli = call(r#"{"cmd":"set-transport","transport":"udp","id":"L1"}"#, &ctx);
        assert_eq!(cli["ok"], true, "{cli}");
        assert_eq!(
            actions_of(&call(r#"{"cmd":"line-action-list"}"#, &ctx)).len(),
            1,
            "不带 source 的切换不算界面动作"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_rejected_connection_method_change_still_closes_its_record() {
        let root = tmp_root("la-pref-bad");
        write_cfg(&root, "L1");
        // 不写线路引擎配置：`check_transport` 会拒绝「兼容连接」，保存不会落地。
        let before = config_bytes(&root);
        let ctx = ctx_with(None, &root);
        let v = call(
            r#"{"cmd":"set-transport","transport":"tcp","id":"L1","source":"line-action"}"#,
            &ctx,
        );
        assert_eq!(v["ok"], false, "{v}");
        let listed = call(r#"{"cmd":"line-action-list"}"#, &ctx);
        let actions = actions_of(&listed);
        assert_eq!(
            actions.len(), 1,
            "拒绝也要给记录一个结论，否则卡片永远停在「保存中」：{listed}"
        );
        assert_eq!(actions[0]["Phase"], "Failed");
        assert_eq!(actions[0]["Code"], "config");
        assert_eq!(actions[0]["Message"], v["error"], "记录里必须是同一条拒绝原话");
        assert_eq!(config_bytes(&root), before, "被拒绝的保存不许动配置");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_interrupted_preference_compares_with_the_saved_config_and_never_reapplies() {
        let root = tmp_root("la-review-pref");
        write_cfg(&root, "L1"); // 线路甲当前没有固定任何方式
        let ctx = ctx_with(None, &root);
        let before = config_bytes(&root);
        let action = interrupted(
            &root,
            "L1",
            "线路甲",
            crate::lineaction::PREFERENCE,
            "Tcp",
            "tcp",
        );

        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        assert_eq!(reviewed["ok"], true, "核对本身完成就是 ok：{reviewed}");
        let result = &reviewed["lineActionReview"];
        assert_eq!(result["Phase"], "Failed");
        assert_eq!(result["Code"], "NotApplied");
        assert_eq!(result["NeedsReview"], false);
        assert_eq!(result["CanRetry"], true, "没落地要能重试保存：{result}");
        assert!(
            result["Message"].as_str().unwrap_or("").contains("上次保存没有落地"),
            "{result}"
        );
        assert_eq!(config_bytes(&root), before, "核对只查证据，绝不重新提交原操作");

        // 结论已确定：再核对一次必须被拒，且不覆盖原结论。
        let again = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["errorCode"], "state");
        assert_eq!(
            actions_of(&call(r#"{"cmd":"line-action-list"}"#, &ctx))[0]["Phase"], "Failed",
            "被拒的核对不得改记录"
        );

        // 请求 auto、配置也没固定 → 对上。
        let auto = interrupted(
            &root,
            "L1",
            "线路甲",
            crate::lineaction::PREFERENCE,
            "Udp",
            "auto",
        );
        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, auto.id),
            &ctx,
        );
        assert_eq!(reviewed["lineActionReview"]["Phase"], "Succeeded", "{reviewed}");
        assert_eq!(
            reviewed["lineActionReview"]["Message"], "已核对：这条线路现在采用自动选择。",
            "{reviewed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_interrupted_check_reads_the_perf_window_instead_of_remeasuring() {
        let root = tmp_root("la-review-check-ok");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let action = interrupted(
            &root,
            "L1",
            "线路甲",
            crate::lineaction::CHECK,
            "Udp",
            "",
        );
        crate::perf::record(&root, "L1", "标准", 123, std::time::SystemTime::now());

        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        assert_eq!(reviewed["ok"], true, "{reviewed}");
        let result = &reviewed["lineActionReview"];
        assert_eq!(result["Phase"], "Succeeded");
        assert_eq!(result["LatencyMs"], 123, "毫秒数必须来自那次动作窗口里的采样：{result}");
        assert_eq!(result["Message"], "已确认上次测速完成：123 ms。");
        assert!(!root.join("runtime-engine.json").exists(), "核对绝不重新发测量请求");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_a_check_without_a_usable_sample_reports_the_real_reason() {
        // ① 窗口里有一条失败采样：结论要带采样库记的原因。
        let root = tmp_root("la-review-check-fail");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let action = interrupted(&root, "L1", "线路甲", crate::lineaction::CHECK, "Tcp", "");
        crate::perf::record_failure(
            &root,
            "L1",
            "兼容",
            "MeasurementTimeout",
            std::time::SystemTime::now(),
        );
        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        let result = &reviewed["lineActionReview"];
        assert_eq!(result["Phase"], "Failed", "{reviewed}");
        assert_eq!(result["Code"], "MeasurementTimeout");
        assert!(
            result["Message"].as_str().unwrap_or("").contains("MeasurementTimeout"),
            "{result}"
        );
        let _ = std::fs::remove_dir_all(&root);

        // ② 一条采样都没有：明说「没留下结果」，并允许重新测速。
        let root = tmp_root("la-review-check-none");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let action = interrupted(&root, "L1", "线路甲", crate::lineaction::CHECK, "Udp", "");
        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        let result = &reviewed["lineActionReview"];
        assert_eq!(result["Phase"], "Failed", "{reviewed}");
        assert_eq!(result["Code"], "NoResult");
        assert_eq!(result["CanRetry"], true, "{result}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_a_check_ignores_samples_recorded_outside_the_action_window() {
        let root = tmp_root("la-review-check-old");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let action = interrupted(&root, "L1", "线路甲", crate::lineaction::CHECK, "Udp", "");
        // 一小时前的采样不属于这次动作：窗口只有开始后十几秒。
        crate::perf::record(
            &root,
            "L1",
            "标准",
            120,
            std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
        );
        let reviewed = call(
            &format!(r#"{{"cmd":"line-action-review","id":"{}"}}"#, action.id),
            &ctx,
        );
        let result = &reviewed["lineActionReview"];
        assert_eq!(result["Phase"], "Failed", "{reviewed}");
        assert_eq!(result["Code"], "NoResult", "窗口外的旧读数不许算到这次动作头上：{result}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_unknown_or_broken_action_is_refused_by_code() {
        let root = tmp_root("la-review-bad");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let empty = call(r#"{"cmd":"line-action-review","id":""}"#, &ctx);
        assert_eq!(empty["ok"], false, "{empty}");
        assert_eq!(empty["errorCode"], "usage");
        let missing = call(r#"{"cmd":"line-action-review","id":"nope"}"#, &ctx);
        assert_eq!(missing["ok"], false, "{missing}");
        assert_eq!(missing["errorCode"], "missing");
        // 记录文件坏掉：拒绝且指向记录，不是「不需要核对」。
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("logs").join("line-actions.json"), b"{broken").unwrap();
        let broken = call(r#"{"cmd":"line-action-review","id":"nope"}"#, &ctx);
        assert_eq!(broken["ok"], false, "{broken}");
        assert_eq!(broken["errorCode"], "record");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_broken_line_action_store_is_reported_not_treated_as_empty() {
        let root = tmp_root("la-list-broken");
        write_cfg(&root, "L1");
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("logs").join("line-actions.json"), b"{not json").unwrap();
        let v = call(r#"{"cmd":"line-action-list"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "line-action");
        assert!(
            !v["lineActions"]["ReadError"].as_str().unwrap_or_default().is_empty(),
            "「读不出来」必须和「没有记录」分开：{v}"
        );
        assert!(actions_of(&v).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `transportVerified` 三态：没固定没验证 → false；验证过 → true；固定后仍是 true（依据还在）。
    #[test]
    fn lines_payload_reports_whether_auto_has_any_evidence() {
        let root = tmp_root("tr-verified");
        let mut cfg = write_cfg(&root, "L1");
        // L1：什么都没选过、也没验证过 → 自动但没有依据。
        cfg.lines[0].transport = None;
        cfg.lines[0].verified_transport = None;
        // L2：验证过兼容连接但没有固定 → 自动且有依据。
        cfg.lines[1].transport = None;
        cfg.lines[1].verified_transport = Some(crate::config::Transport::Tcp);
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();

        let v = lines_payload(Some(&cfg));
        let lines = v["lines"].as_array().expect("lines 数组");
        assert_eq!(lines[0]["transportSelected"], false, "{v}");
        assert_eq!(lines[0]["transportVerified"], false, "没有依据必须如实说：{v}");
        assert_eq!(lines[0]["transport"], "udp", "{v}");
        assert_eq!(lines[1]["transportSelected"], false, "{v}");
        assert_eq!(lines[1]["transportVerified"], true, "{v}");
        assert_eq!(lines[1]["transport"], "tcp", "自动采用已验证的方式：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_transport_refuses_without_parameters_and_keeps_config() {
        let root = tmp_root("set-tr-refuse");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", false);
        let before = config_bytes(&root);

        let v = call(r#"{"cmd":"set-transport","transport":"tcp"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "没有参数就不许切：{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("连接方式不可用"), "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("VLESS"), "要说清缺什么：{v}");
        assert_eq!(config_bytes(&root), before, "拒绝必须零副作用");

        let v = call(r#"{"cmd":"set-transport","transport":"quic"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("udp"), "要给可选值：{v}");
        assert_eq!(config_bytes(&root), before);

        // 标准连接永远可切
        let v = call(r#"{"cmd":"set-transport","transport":"udp"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_the_same_transport_hint_the_cli_prints() {
        // 两路径一致（D8 教训）：CLI 连接输出打的提示与界面 status 拿到的，
        // 必须出自同一个函数、一字不差——这里直接拿两边的源头对值。
        let root = tmp_root("hint-consistency");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        let failed = crate::selfcheck::Check { ok: false, ..Default::default() };
        crate::selfcheck::save(&root, &failed).unwrap();

        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(v["compatibleAction"], true, "同一份资格事实必须同时驱动提示和动作：{v}");
        assert!(v["transportActual"].is_null(), "未连接时没有“实际生效”的连接方式：{v}");
        let shared = crate::selfcheck::transport_alternative_hint(Some(&cfg), &root, &failed)
            .expect("这个现场该有提示");
        assert_eq!(
            v["checkHint"].as_str().unwrap_or_default(),
            shared.as_str(),
            "界面拿到的提示必须与 CLI 打印的一字不差"
        );
        assert_eq!(v["check"], failed.verdict(), "结论本身一个字不许变：{v}");
        // 切到兼容连接后提示必须消失（状态是实时算的，不是陈旧记录）
        let v = call(r#"{"cmd":"set-transport","transport":"tcp"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["checkHint"], "", "已切到兼容连接就不能再劝人切兼容连接：{v}");
        assert_eq!(v["compatibleAction"], false, "提示消失时动作也必须消失：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t14_compatible_action_refuses_without_evidence_and_never_fakes_reconnect() {
        let root = tmp_root("t14-guard");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        let before = config_bytes(&root);
        let ctx = ctx_with(None, &root);

        // 没有本次自检失败证据：动作不能被当作通用“重连”按钮，配置和运行时都不动。
        let v = call(r#"{"cmd":"use-compatible"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("自检未通过"), "{v}");
        assert_eq!(config_bytes(&root), before, "资格不满足时必须零副作用");
        assert!(!root.join("runtime.json").exists());

        // 有失败证据但没有兼容参数：仍须拒绝，不保存一个无法派生的选择。
        write_line_file(&root, "L1", false);
        crate::selfcheck::save(&root, &crate::selfcheck::Check {
            ok: false, at: 10, ..Default::default()
        }).unwrap();
        let v = call(r#"{"cmd":"use-compatible"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(config_bytes(&root), before, "缺兼容参数也不得写配置");

        // 参数与失败证据齐全、但引擎未配置：允许保存兼容偏好，随后真实连接阶段失败；
        // 绝不能把“已保存”冒充“已重连”。
        write_line_file(&root, "L1", true);
        let v = call(r#"{"cmd":"use-compatible"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["compatibleResult"]["stage"], "connect", "{v}");
        assert_eq!(v["compatibleResult"]["saved"], true, "{v}");
        assert_eq!(v["compatibleResult"]["reconnected"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("未配置引擎"), "{v}");
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(disk.lines[0].transport, Some(crate::config::Transport::Tcp));
        assert!(!root.join("runtime.json").exists(), "失败不得伪造运行时记录");
        assert!(!root.join("proxy-journal.json").exists(), "未进入连接事务不得写代理凭据");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_reports_the_engine_that_will_actually_run_not_just_the_configured_string() {
        // 旧实现的 `engineMissing` 只判「字符串空」：旧版卸掉后界面照样显示路径正常，
        // 直到点连接才报「引擎程序不存在」。这里按**文件是否真的在**判定。
        let root = tmp_root("engine-status");
        let engine = root.join("engine").join("sing-box.exe");
        let body = format!(
            r#"{{"schema":2,"selected":"L1","engine":{{"binary":"{}"}},
                "lines":[{{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"}}]}}"#,
            engine.to_string_lossy().replace('\\', "\\\\")
        );
        let cfg = crate::config::parse(&body).expect("配置要能解析");
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();

        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["engineMissing"], true, "文件不在就必须说缺：{v}");
        assert_eq!(
            v["engineBinary"].as_str().unwrap_or_default(),
            engine.to_string_lossy(),
            "说缺的时候仍要显示用户配的那个路径，否则他不知道该改哪里：{v}"
        );

        std::fs::create_dir_all(engine.parent().unwrap()).unwrap();
        std::fs::write(&engine, b"not really sing-box").unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["engineMissing"], false, "文件在了就要翻过来：{v}");
        assert_eq!(v["engineBinary"].as_str().unwrap_or_default(), engine.to_string_lossy());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t14_status_reads_actual_transport_from_runtime_not_preference_or_mode() {
        let root = tmp_root("t14-actual-transport");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", true);
        connected_runtime(&root, 17991);
        let ctx = ctx_with(None, &root);
        let runtime = root.join("runtime-engine.json");

        let udp = serde_json::json!({
            "inbounds": [{"type":"mixed","tag":"tc-mixed"}],
            "endpoints": [{"type":"wireguard","tag":"hk"}],
            "outbounds": [{"type":"direct","tag":"direct"}]
        });
        std::fs::write(&runtime, udp.to_string()).unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["transportActual"], "标准连接", "运行时 endpoint 未挂中转：{v}");
        assert_eq!(v["mode"], "代理", "接管方式仍是另一维度：{v}");

        let line = root.join("lines").join("L1.json");
        crate::engine_config::prepare_engine_config(
            &line,
            &Default::default(),
            &Default::default(),
            crate::config::Transport::Tcp,
            crate::config::Mode::Proxy,
            &runtime,
            "",
            None,
            None,
        ).unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(v["transportActual"], "兼容连接", "实际运行时带 tc-transport 才能这样显示：{v}");
        assert_eq!(v["mode"], "代理", "不得把代理/TUN 当成标准/兼容：{v}");

        std::fs::write(&runtime, "not json").unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert!(v["transportActual"].is_null(), "运行时证据不可读时必须未知：{v}");
        std::fs::remove_file(root.join("runtime.json")).unwrap();
        std::fs::remove_file(&runtime).unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        assert!(v["transportActual"].is_null(), "未连接不得把偏好当成已生效：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 服务商接入（providers / provider-discover / add / remove）----------

    /// 造一个存在的安装目录（`validate` 要求目录真实存在）。
    fn provider_dir(root: &PathBuf, name: &str) -> String {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    #[test]
    fn providers_payload_is_empty_before_anything_is_registered() {
        let root = tmp_root("prov-empty");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"providers"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["providers"].as_array().map(|a| a.len()), Some(0), "{v}");
        assert_eq!(v["entryNote"], "", "没有服务商就没有入口说明：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t18_provider_effective_state_follows_the_real_selector_not_just_registration() {
        let root = tmp_root("t18-provider-state");
        write_cfg(&root, "L1");
        let line_path = root.join("lines").join("L1.json");
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        let line = serde_json::json!({
            "outbounds": [
                {"type":"selector","tag":"daily-exit","outbounds":["direct","provider"],"default":"direct"},
                {"type":"selector","tag":"trade-exit","outbounds":["direct","provider-trade"],"default":"direct"},
                {"type":"direct","tag":"direct"},
                {"type":"socks","tag":"provider","server":"127.0.0.1","server_port":17895},
                {"type":"socks","tag":"provider-trade","server":"127.0.0.1","server_port":17896}
            ]
        });
        std::fs::write(&line_path, serde_json::to_string_pretty(&line).unwrap()).unwrap();
        std::fs::write(
            root.join("providers.json"),
            serde_json::json!({
                "version":1,
                "providers":[{
                    "id":"p1","slot":1,"name":"Clash 夹具","kind":"clashverge",
                    "directory":root.join("clash").to_string_lossy(),
                    "daily_port":17895,"trade_port":17896,"bootstrap_domains":[]
                }]
            })
            .to_string(),
        )
        .unwrap();
        let ctx = ctx_with(None, &root);

        let pending = call(r#"{"cmd":"providers"}"#, &ctx);
        let p = &pending["providers"][0];
        assert_eq!(p["effectiveState"], "pending", "只登记/投影，不能叫已生效：{pending}");
        assert!(p["effectiveReason"].as_str().unwrap_or_default().contains("还没有选它"), "{pending}");

        let daily = call(r#"{"cmd":"exit-set","which":"daily","member":"provider"}"#, &ctx);
        assert_eq!(daily["ok"], true, "{daily}");
        let effective = call(r#"{"cmd":"providers"}"#, &ctx);
        let p = &effective["providers"][0];
        assert_eq!(p["effectiveState"], "effective", "{effective}");
        assert_eq!(p["effectiveRole"], "daily", "{effective}");
        assert!(p["effectiveReason"].as_str().unwrap_or_default().contains("日常出口"), "{effective}");

        let trade = call(r#"{"cmd":"exit-set","which":"trade","member":"provider-trade"}"#, &ctx);
        assert_eq!(trade["ok"], true, "{trade}");
        let both = call(r#"{"cmd":"providers"}"#, &ctx);
        let p = &both["providers"][0];
        assert_eq!(p["effectiveRole"], "daily+trade", "{both}");
        assert!(p["effectiveReason"].as_str().unwrap_or_default().contains("日常和交易"), "{both}");

        // 回到直连，再破坏投影：必须给出不可用原因，而不是继续显示注册事实。
        let _ = call(r#"{"cmd":"exit-set","which":"daily","member":"direct"}"#, &ctx);
        let _ = call(r#"{"cmd":"exit-set","which":"trade","member":"direct"}"#, &ctx);
        let mut broken: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&line_path).unwrap()).unwrap();
        for o in broken["outbounds"].as_array_mut().unwrap() {
            if o["tag"] == "provider" || o["tag"] == "provider-trade" {
                o["server_port"] = serde_json::json!(1);
            }
        }
        std::fs::write(&line_path, serde_json::to_string_pretty(&broken).unwrap()).unwrap();
        let unavailable = call(r#"{"cmd":"providers"}"#, &ctx);
        let p = &unavailable["providers"][0];
        assert_eq!(p["effectiveState"], "unavailable", "{unavailable}");
        assert!(p["effectiveReason"].as_str().unwrap_or_default().contains("端口与登记不一致"), "{unavailable}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t18_backup_probe_is_connected_only_explicit_and_never_current_latency() {
        let root = tmp_root("t18-backup");
        write_cfg(&root, "L1");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let line_path = root.join("lines").join("L2.json");
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        std::fs::write(
            &line_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "outbounds":[{
                    "type":"vless","tag":"tc-transport","server":"127.0.0.1","server_port":port
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let ctx = ctx_with(None, &root);
        let disconnected = call(r#"{"cmd":"measure-backup","lineId":"L2"}"#, &ctx);
        assert_eq!(disconnected["ok"], false, "未连接不得探测：{disconnected}");
        assert_eq!(disconnected["errorCode"], "environment", "{disconnected}");
        assert!(disconnected["backupResult"]["notCurrentLatency"].as_bool() == Some(true), "{disconnected}");

        connected_runtime(&root, port);
        let current = call(r#"{"cmd":"measure-backup","lineId":"L1"}"#, &ctx);
        assert_eq!(current["ok"], false, "{current}");
        assert_eq!(current["errorCode"], "usage", "当前线路不能当备用线路：{current}");

        let config_before = config_bytes(&root);
        let line_before = std::fs::read(&line_path).unwrap();
        let measured = call(r#"{"cmd":"measure-backup","lineId":"L2"}"#, &ctx);
        assert_eq!(measured["ok"], true, "{measured}");
        assert_eq!(measured["backupResult"]["reachable"], true, "{measured}");
        assert!(measured["backupResult"]["latencyMs"].as_u64().is_some(), "{measured}");
        assert_eq!(measured["backupResult"]["notCurrentLatency"], true, "{measured}");
        assert!(measured["backupResult"]["message"].as_str().unwrap_or_default().contains("不等于当前响应"), "{measured}");
        assert_eq!(config_bytes(&root), config_before, "备用探测不许改当前线路选择");
        assert_eq!(std::fs::read(&line_path).unwrap(), line_before, "备用探测不许改目标线路文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn provider_add_persists_projects_and_replies_like_the_cli() {
        let root = tmp_root("prov-add");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", false);
        let dir = provider_dir(&root, "ClashVerge");
        let cmd = serde_json::json!({
            "cmd": "provider-add", "kind": "clashverge", "name": "甲",
            "directory": dir, "dailyPort": 7890, "domains": ["a.example.com"]
        })
        .to_string();
        let v = call(&cmd, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["slot"], 1, "{v}");
        // 文案与 CLI 同一句（旧版那套说法）
        assert_eq!(v["message"], "已登记服务商：甲（槽位 1）", "{v}");
        // 界面「设为日常出口」按钮靠 dailyTag 发 exit-set
        assert_eq!(v["dailyTag"], "provider", "{v}");
        let lines = v["providers"].as_array().expect("回包要带新列表");
        assert_eq!(lines[0]["dailyPort"], 7890);
        assert_eq!(lines[0]["tradePort"], 7890, "没单独配交易端口时复用日常端口");
        assert!(lines[0]["entryNote"].as_str().unwrap_or_default().contains("7890"), "{v}");
        // 落盘 + 投影到线路（注册不是只写注册表）
        assert!(root.join("providers.json").exists(), "注册表要落盘");
        let line_text = std::fs::read_to_string(root.join("lines").join("L1.json")).unwrap();
        assert!(line_text.contains("provider"), "socks 出站要投影进线路：{line_text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn provider_add_refuses_bad_input_busy_and_missing_line_without_side_effects() {
        let root = tmp_root("prov-add-refuse");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", false);
        let dir = provider_dir(&root, "ClashVerge");
        let mk = |extra: serde_json::Value| {
            let mut v = serde_json::json!({
                "cmd": "provider-add", "kind": "clashverge", "name": "甲",
                "directory": dir, "dailyPort": 7890, "domains": ["a.example.com"]
            });
            if let (Some(dst), Some(src)) = (v.as_object_mut(), extra.as_object()) {
                for (k, val) in src {
                    dst.insert(k.clone(), val.clone());
                }
            }
            v.to_string()
        };

        // 订阅链接：旧版与本版都不接受（只登记客户端已落地的端口与域名）
        let v = call(&mk(serde_json::json!({"domains": ["https://sub.example.com/x"]})), &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("订阅链接"), "{v}");
        // 端口非法
        let v = call(&mk(serde_json::json!({"dailyPort": 0})), &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("端口"), "{v}");
        // 连接中拒绝（登记会改写当前线路的引擎配置）
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let v = call(&mk(serde_json::json!({})), &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("请先断开"), "{v}");
        std::fs::remove_file(root.join("proxy-journal.json")).unwrap();
        // 没线路：拒绝并说清先导入
        let bare = tmp_root("prov-add-noline");
        let v = call(&mk(serde_json::json!({"directory": provider_dir(&bare, "ClashVerge")})), &ctx_with(None, &bare));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("未配置线路"), "{v}");

        // 以上全部零副作用：注册表一次都没写
        assert!(!root.join("providers.json").exists(), "拒绝时不许写注册表");
        assert!(!bare.join("providers.json").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[test]
    fn provider_remove_drops_the_slot_and_refuses_unknown_slots() {
        let root = tmp_root("prov-rm");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", false);
        let dir = provider_dir(&root, "ClashVerge");
        let add = serde_json::json!({
            "cmd": "provider-add", "kind": "clashverge", "name": "甲",
            "directory": dir, "dailyPort": 7890, "domains": ["a.example.com"]
        })
        .to_string();
        assert_eq!(call(&add, &ctx_with(None, &root))["ok"], true);

        let v = call(r#"{"cmd":"provider-remove","slot":1}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["message"], "已删除槽位 1 的服务商", "{v}");
        assert_eq!(v["providers"].as_array().map(|a| a.len()), Some(0), "{v}");

        let v = call(r#"{"cmd":"provider-remove","slot":1}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("没有已登记的服务商"), "{v}");
        let v = call(r#"{"cmd":"provider-remove","slot":9}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["error"].as_str().unwrap_or_default().contains("槽位"), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn provider_discover_is_read_only_and_reports_both_clients() {
        // 真机上装没装客户端都可能：这里只钉形状与"不登记"这条红线。
        let root = tmp_root("prov-discover");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"provider-discover"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert!(v["found"].is_array(), "found 必须是数组（没发现就是空数组）：{v}");
        assert!(v["errors"].is_array(), "没发现的原因要能说清：{v}");
        assert!(!root.join("providers.json").exists(), "发现只读，绝不许登记");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 接管方式（set-mode）----------

    /// 带 TUN 入站的线路文件（TUN 导入的形状）。
    fn write_tun_line_file(root: &PathBuf, id: &str) {
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{id}.json")),
            r#"{"inbounds":[{"type":"tun","tag":"trade-tun","address":["172.30.250.1/30"],"mtu":1380,"stack":"gvisor"},
                            {"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":17995}],
                "endpoints":[{"type":"wireguard","tag":"hk"}],
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"rules":[],"final":"direct"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn set_mode_switches_the_saved_preference_and_status_follows() {
        let root = tmp_root("set-mode-ok");
        write_cfg(&root, "L1");
        write_tun_line_file(&root, "L1");

        let v = call(r#"{"cmd":"set-mode","mode":"tun"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["mode"], "TUN", "{v}");
        assert_eq!(v["message"], "已切换到 TUN（下次连接生效）", "{v}");
        // 落盘：config.json 的 mode 真的变了，且 status 的 modeChoice 跟着走
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).ok().flatten().unwrap();
        assert_eq!(disk.mode, crate::config::Mode::Tun);
        let st = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(st["modeChoice"], "tun", "偏好要如实上报（界面单选按它）：{st}");
        assert_eq!(st["mode"], "TUN", "未连接时报的就是「下次连接会用哪种」：{st}");

        // 切回代理：**线路文件里仍然有 TUN 入站**（素材），但当前模式必须报代理——
        // 线路文件是原料，不是"当前模式"的声明（这条是上一版口径改回来的钉子）。
        let v = call(r#"{"cmd":"set-mode","mode":"proxy"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["message"], "已切换到 代理（下次连接生效）", "{v}");
        let st = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(st["modeChoice"], "proxy", "{st}");
        assert_eq!(st["mode"], "代理", "未连接时按配置里的偏好报，不许报线路文件里的素材：{st}");
        assert_eq!(st["tunAvailable"], true, "素材还在，TUN 单选仍可点（能切回去）：{st}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_mode_refuses_a_line_without_a_tun_inbound_and_keeps_config() {
        let root = tmp_root("set-mode-notun");
        write_cfg(&root, "L1");
        write_line_file(&root, "L1", false); // 代理形状：没有 TUN 入站
        let before = config_bytes(&root);
        let v = call(r#"{"cmd":"set-mode","mode":"tun"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "没有 TUN 素材就不许切：{v}");
        let err = v["error"].as_str().unwrap_or("");
        assert!(err.contains("没有 TUN 入站"), "文案要说清缺什么：{v}");
        assert!(err.contains("--import --tun"), "要给可执行的出路：{v}");
        assert_eq!(config_bytes(&root), before, "拒绝必须零副作用");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_mode_refuses_invalid_values_and_while_connected() {
        let root = tmp_root("set-mode-refuse");
        write_cfg(&root, "L1");
        write_tun_line_file(&root, "L1");
        let before = config_bytes(&root);

        let v = call(r#"{"cmd":"set-mode","mode":"quic"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        let err = v["error"].as_str().unwrap_or("");
        assert!(err.contains("接管方式只能是 代理 或 TUN"), "错误文案统一中文：{v}");
        assert_eq!(config_bytes(&root), before);

        // 连接中拒绝：切换只影响下一次连接，连着的时候改它只会让人以为"已经切了"
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let v = call(r#"{"cmd":"set-mode","mode":"tun"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("请先断开再切换接管方式"),
            "{v}"
        );
        assert_eq!(config_bytes(&root), before);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 操作记录（界面「记录」页用的管道命令，与 --history 同源）----------

    #[test]
    fn history_command_carries_the_same_records_as_the_cli() {
        let root = tmp_root("history");
        // 空根：合法回包、空列表——界面据此显示「还没有操作记录」，不能是错误
        let v = call(r#"{"cmd":"history"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["events"].as_array().map(|a| a.len()), Some(0), "{v}");

        crate::events::record(
            &root,
            crate::events::CONNECT,
            true,
            "线路甲（代理）",
            &crate::events::Origin::other(),
        );
        crate::events::record(
            &root,
            crate::events::CONNECT,
            false,
            "端口被占用",
            &crate::events::Origin::other(),
        );
        let v = call(r#"{"cmd":"history"}"#, &ctx_with(None, &root));
        let ev = v["events"].as_array().expect("要带 events 数组");
        assert_eq!(ev.len(), 2, "{v}");
        // 新 → 旧，字段名与文件里的一致（界面不再做转换）
        assert_eq!(ev[0]["ok"], false, "{v}");
        assert_eq!(ev[0]["detail"], "端口被占用", "{v}");
        assert_eq!(ev[1]["action"], "连接", "{v}");
        assert_eq!(ev[1]["detail"], "线路甲（代理）", "{v}");
        for k in ["ts", "action", "ok", "detail"] {
            assert!(ev[0].get(k).is_some(), "缺字段 {k}：{v}");
        }
        // v2 字段同源交给界面；旧字段与新字段都不许丢。
        assert_eq!(ev[0]["src"], "other", "{v}");
        assert!(ev[0].get("actor").is_some(), "{v}");
        assert!(ev[0].get("obj").is_some(), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn history_hide_is_soft_and_restore_puts_the_row_back() {
        let root = tmp_root("history-hide");
        crate::events::record(
            &root,
            crate::events::CONNECT,
            true,
            "线路甲（代理）",
            &crate::events::Origin::other(),
        );
        crate::events::record(
            &root,
            crate::events::CONNECT,
            false,
            "端口被占用",
            &crate::events::Origin::other(),
        );
        let v = call(r#"{"cmd":"history"}"#, &ctx_with(None, &root));
        let ev = v["events"].as_array().expect("要带 events 数组");
        assert_eq!(ev.len(), 2, "{v}");
        assert_eq!(ev[0]["Hidden"], false, "默认一条都没隐藏：{v}");
        let key = ev[0]["Key"].as_str().expect("每条记录都要带稳定键").to_string();

        let body = serde_json::json!({"cmd":"history-delete","keys":[key.clone()]}).to_string();
        let v = call(&body, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["historyDelete"]["deleted"], 1, "{v}");
        assert_eq!(v["historyDelete"]["hidden"], true, "删除必须是隐藏：{v}");
        // 审计文件一行不少：隐藏只写键集合。
        let audit = std::fs::read_to_string(root.join("logs").join(crate::events::FILE)).unwrap();
        assert_eq!(audit.trim().lines().count(), 2, "审计行被真的删掉了：{audit}");

        let v = call(r#"{"cmd":"history"}"#, &ctx_with(None, &root));
        let ev = v["events"].as_array().unwrap();
        assert_eq!(ev.iter().filter(|e| e["Hidden"] == true).count(), 1, "{v}");
        assert_eq!(ev[0]["Key"], key, "{v}");

        // 导出也必须跟着页面：默认不带隐藏行，勾上 includeHidden 才带；搜索词同样生效。
        let body = serde_json::json!({
            "cmd":"export-history",
            "filter":{"onlyFail":false,"src":"all"}
        })
        .to_string();
        let v = call(&body, &ctx_with(None, &root));
        assert_eq!(v["exportResult"]["count"], 1, "默认导出不该含隐藏行：{v}");
        let body = serde_json::json!({
            "cmd":"export-history",
            "filter":{"onlyFail":false,"src":"all","includeHidden":true}
        })
        .to_string();
        let v = call(&body, &ctx_with(None, &root));
        assert_eq!(v["exportResult"]["count"], 2, "勾上开关后导出全部：{v}");
        let body = serde_json::json!({
            "cmd":"export-history",
            "filter":{"onlyFail":false,"src":"all","includeHidden":true,"search":"端口"}
        })
        .to_string();
        let v = call(&body, &ctx_with(None, &root));
        assert_eq!(v["exportResult"]["count"], 1, "搜索词也要生效：{v}");

        let body = serde_json::json!({"cmd":"history-restore","keys":[key]}).to_string();
        let v = call(&body, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["historyRestore"]["restored"], 1, "{v}");
        let v = call(r#"{"cmd":"history"}"#, &ctx_with(None, &root));
        assert_eq!(
            v["events"].as_array().unwrap().iter().filter(|e| e["Hidden"] == true).count(),
            0,
            "恢复之后不该还有隐藏标记：{v}"
        );

        // 空键是用法错误：界面不该收到一个「成功了但什么也没做」的回包。
        let v = call(r#"{"cmd":"history-delete"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "usage", "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lines_read_failure_is_explicit_and_does_not_look_empty() {
        let root = tmp_root("lines-read-failed");
        let snapshot = write_cfg(&root, "L1");
        std::fs::write(root.join(crate::config::DEFAULT_PATH), b"{ broken").unwrap();
        let ctx = ctx_with(Some(snapshot), &root);
        let v = call(r#"{"cmd":"lines"}"#, &ctx);
        assert_eq!(v["linesRead"], "failed", "{v}");
        assert!(!v["linesReadError"].as_str().unwrap_or_default().is_empty(), "{v}");
        let s = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(s["linesRead"], "failed", "{s}");
        assert!(s["linesReadError"].as_str().unwrap_or_default().contains("配置"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_the_three_exit_evidence_levels_and_check_time() {
        let root = tmp_root("status-evidence");
        write_cfg(&root, "L1");
        let check = crate::selfcheck::Check {
            ok: true,
            status: Some(204),
            error: None,
            at: 1_700_000_000,
            skipped: None,
            via_trade_exit: false,
        };
        crate::selfcheck::save(&root, &check).unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["check"], "通过（HTTP 204）", "{v}");
        // B1 之后这档有了名字：`Passed` = 转发通了、出口归属还没证（界面说「转发已通，归属未验证」）。
        assert_eq!(v["exitEvidence"], "Passed", "只有自检通过时不能说已核验：{v}");
        assert!(v["checkAtUtc"].as_str().unwrap_or_default().starts_with("2023-"), "{v}");
        assert_eq!(v["exitObservedIp"], serde_json::Value::Null, "{v}");
        assert_eq!(v["exitAttribution"], "Unknown", "{v}");
        assert!(v["isAdmin"].is_boolean(), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// B1 的三档判定：**只有「自检通过 + 观测到出口 IP + 归属到线路服务器」才叫已核验**。
    /// 少任何一条都只能说到「转发已通」或「尚未核验」——这三格之间差一次假话。

    #[test]
    fn exit_status_quartet_comes_from_one_snapshot_even_if_disk_changes() {
        let root = tmp_root("exit-one-snapshot");
        let first = crate::exit_probe::Record {
            at: 1_700_000_000,
            ip: "8.8.8.8".into(),
            endpoint: "checkip.amazonaws.com".into(),
            attributed: true,
            line_id: "L1".into(),
            started_at: "t".into(),
            binding: None,
        };
        crate::exit_probe::save(&root, &first).unwrap();
        // The real IPC path validates a record BEFORE taking this snapshot;
        // this pure projection test isolates the four-field consistency.
        let captured = crate::exit_probe::load(&root).unwrap();
        let later = crate::exit_probe::Record {
            ip: "1.1.1.1".into(), attributed: false, at: 1_600_000_000,
            ..first
        };
        crate::exit_probe::save(&root, &later).unwrap();
        let fields = super::exit_status_snapshot(true, Some(&captured));
        assert_eq!(fields.evidence, "verified");
        assert_eq!(fields.observed_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(fields.attribution, "LineServer");
        assert!(fields.probe_at_utc.as_deref().unwrap_or("").starts_with("2023-"));
        let missing = super::exit_status_snapshot(true, None);
        assert_eq!(missing.evidence, "Passed");
        assert_eq!(missing.observed_ip, None);
        assert_eq!(missing.attribution, "Unknown");
        assert_eq!(missing.probe_at_utc, None);
        let failed_check = super::exit_status_snapshot(false, Some(&captured));
        assert_eq!(failed_check.evidence, "unverified",
            "old status semantics: failing check never verifies");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn status_legacy_unbound_exit_is_never_mixed_into_current_quartet() {
        let root = tmp_root("status-legacy-exit-quartet");
        write_cfg(&root, "L1");
        let check = crate::selfcheck::Check {
            ok: true, status: Some(204), via_trade_exit: false,
            at: 1_700_000_000, ..Default::default()
        };
        crate::selfcheck::save(&root, &check).unwrap();
        let legacy = crate::exit_probe::Record {
            at: 1_700_000_000, ip: "8.8.8.8".into(),
            endpoint: "checkip.amazonaws.com".into(),
            attributed: true, line_id: "L1".into(),
            started_at: "same-started-at".into(), binding: None,
        };
        crate::exit_probe::save(&root, &legacy).unwrap();
        std::fs::write(root.join("runtime.json"),
            r#"{"SchemaVersion":1,"StartedAt":"same-started-at"}"#).unwrap();
        std::fs::write(root.join("runtime-engine.json"), "{}").unwrap();
        assert!(crate::exit_probe::load(&root).is_some(), "legacy history retained");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["exitEvidence"], "Passed", "{v}");
        assert_eq!(v["exitObservedIp"], serde_json::Value::Null, "{v}");
        assert_eq!(v["exitAttribution"], "Unknown", "{v}");
        assert_eq!(v["exitProbeAtUtc"], serde_json::Value::Null, "{v}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exit_evidence_never_upgrades_without_an_attributed_observation() {
        let rec = |attributed: bool| crate::exit_probe::Record {
            at: 1,
            ip: "203.0.113.10".to_string(),
            endpoint: "checkip.amazonaws.com".to_string(),
            attributed,
            line_id: "hk".to_string(),
            started_at: "t".to_string(),
            binding: None,
        };
        // 自检没过：有观测记录（哪怕归属成立）也不许说已核验。
        assert_eq!(super::exit_evidence(false, Some(&rec(true))), "unverified");
        // 自检过了但没观测：只能说「转发已通」。
        assert_eq!(super::exit_evidence(true, None), "Passed");
        // 观测到了但归属不上：同样只能说「转发已通」。
        assert_eq!(super::exit_evidence(true, Some(&rec(false))), "Passed");
        // 观测到且等于线路服务器：这一格才叫已核验。
        assert_eq!(super::exit_evidence(true, Some(&rec(true))), "verified");
    }

    #[test]
    fn ui_origin_is_written_into_history() {
        let root = tmp_root("history-ui-src");
        write_cfg(&root, "L1");
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;
        let v = call(r#"{"cmd":"use","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let h = call(r#"{"cmd":"history"}"#, &ctx);
        let first = &h["events"].as_array().unwrap()[0];
        assert_eq!(first["src"], "ui", "界面写入必须记 ui：{h}");
        assert!(first["actor"].as_str().unwrap_or_default().starts_with("pid:"));
        assert!(first["obj"].as_str().unwrap_or_default().starts_with("line:"));

        let removed = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx);
        assert_eq!(removed["ok"], true, "{removed}");
        let h = call(r#"{"cmd":"history"}"#, &ctx);
        let deleted = h["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["action"] == "删除线路")
            .expect("删除线路必须留一条记录");
        assert_eq!(deleted["src"], "ui", "{h}");
        assert!(deleted["obj"].as_str().unwrap_or_default().starts_with("line:"), "{h}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 删除预览（A4 第一轮：只读）----------

    const SERVER_A: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const SERVER_B: &str = "1a2b3c4d-5e6f-4a8b-9c0d-e1f2a3b4c5d6";

    fn write_engine_cfg(root: &PathBuf, line: &str, server: &str) {
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{line}.json")),
            format!(r#"{{"outbounds":[{{"type":"wireguard","server":"{server}"}}]}}"#),
        )
        .unwrap();
    }

    fn write_server_record(root: &PathBuf, id: &str, host: &str) {
        let dir = root.join("servers").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("record.json"),
            serde_json::json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": id,
                "Name": format!("root@{host}"),
                "Host": host,
                "Port": 22,
                "User": "root",
                "Fingerprint": "SHA256:abcdefghijkl",
                "CreatedAtUtc": "2026-11-10T00:00:00Z",
                "UpdatedAtUtc": "2026-11-10T00:00:00Z",
            })
            .to_string(),
        )
        .unwrap();
    }

    // ---------- 服务器记录改名（C7）----------

    #[test]
    fn server_rename_updates_the_record_and_returns_the_refreshed_list() {
        let root = tmp_root("server-rename");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_engine_cfg(&root, "L1", "203.0.113.10");
        let ctx = ctx_with(None, &root);
        let body = format!(
            r#"{{"cmd":"server-rename","id":"{SERVER_A}","name":"  东京节点  "}}"#
        );
        let v = call(&body, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["message"], "已改名为「东京节点」", "{v}");
        let server = &v["servers"][0];
        assert_eq!(server["Name"], "东京节点");
        assert_eq!(server["Fingerprint"], "SHA256:abcdefghijkl", "身份字段要一起给：{v}");
        assert_eq!(server["Port"], 22, "{v}");
        assert_eq!(server["User"], "root", "{v}");
        assert_eq!(server["CreatedAtUtc"], "2026-11-10T00:00:00Z", "{v}");
        assert_eq!(server["LineIds"][0], "L1", "{v}");

        let path = root.join("servers").join(SERVER_A).join("record.json");
        let disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(disk["Name"], "东京节点", "磁盘记录要真的改：{disk}");

        // `servers` 命令的公开字段也要跟着有（页面「身份查看」的来源）。
        let listed = call(r#"{"cmd":"servers"}"#, &ctx);
        assert_eq!(listed["servers"][0]["Fingerprint"], "SHA256:abcdefghijkl", "{listed}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_wireguard_line_whose_address_lives_in_endpoints_still_belongs_to_its_server() {
        // 真机形状：标准线路没有 `outbounds[].server`，服务器地址在端点里。
        // 漏掉这一支的后果是「刚部署完的标准线路邀请按钮恒灰」——r105 真机撞到过。
        let root = tmp_root("server-items-endpoints");
        write_server_record(&root, SERVER_A, "198.51.100.30");
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("L-udp.json"),
            serde_json::json!({
                "endpoints": [{
                    "type": "wireguard",
                    "tag": "hk",
                    "address": ["10.66.0.2/32"],
                    "peers": [{"address": "198.51.100.30", "port": 51820}]
                }],
                "outbounds": [{"type": "selector", "tag": "trade-exit"}]
            })
            .to_string(),
        )
        .unwrap();
        // 兼容线路照旧：地址在出站里。两条都要算进同一台服务器。
        std::fs::write(
            dir.join("L-tcp.json"),
            serde_json::json!({
                "outbounds": [
                    {"type": "vless", "tag": "tc-transport", "server": "198.51.100.30", "server_port": 8443}
                ]
            })
            .to_string(),
        )
        .unwrap();
        // 端点里带端口的写法也要认（`host:51820`），不能被当成另一个 host。
        std::fs::write(
            dir.join("L-udp-port.json"),
            serde_json::json!({
                "endpoints": [{"type": "wireguard", "peers": [{"address": "198.51.100.30:51820"}]}]
            })
            .to_string(),
        )
        .unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"servers"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let mut ids: Vec<&str> = v["servers"][0]["LineIds"]
            .as_array()
            .expect("LineIds 必须是数组")
            .iter()
            .filter_map(|item| item.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["L-tcp", "L-udp", "L-udp-port"],
            "端点里的地址也必须算作这台服务器的线路：{v}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 补兼容连接：缺 `line`、或这条线路根本不在这台电脑上 → 立刻拒绝。
    /// 这两条都在**任何 SSH 之前**，所以能在没有服务器的环境里钉住。
    #[test]
    fn adding_a_compatible_line_refuses_before_any_ssh() {
        let root = tmp_root("line-add-compatible");
        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"line-add-compatible"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("line"),
            "要说清缺哪个字段：{v}"
        );

        let v = call(r#"{"cmd":"line-add-compatible","line":"nope"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert!(!v["error"].as_str().unwrap_or("").is_empty(), "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_rename_refuses_bad_input_without_touching_the_record() {
        let root = tmp_root("server-rename-bad");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        let ctx = ctx_with(None, &root);
        let cases = [
            (r#"{"cmd":"server-rename","name":"x"}"#.to_string(), "usage"),
            (
                format!(r#"{{"cmd":"server-rename","id":"{SERVER_A}","name":"   "}}"#),
                "usage",
            ),
            (
                format!(r#"{{"cmd":"server-rename","id":"{SERVER_A}","name":"a\nb"}}"#),
                "usage",
            ),
            (
                format!(
                    r#"{{"cmd":"server-rename","id":"9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b","name":"x"}}"#
                ),
                "config",
            ),
        ];
        for (body, code) in cases {
            let v = call(&body, &ctx);
            assert_eq!(v["ok"], false, "{body} {v}");
            assert_eq!(v["errorCode"], code, "{body} {v}");
        }
        let path = root.join("servers").join(SERVER_A).join("record.json");
        let disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(disk["Name"], "root@203.0.113.10", "拒绝时一个字节都不该改：{disk}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_remove_refuses_while_a_line_uses_it_and_deletes_afterwards() {
        let root = tmp_root("server-remove");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_engine_cfg(&root, "L1", "203.0.113.10");
        let ctx = ctx_with(None, &root);
        let body = format!(r#"{{"cmd":"server-remove","id":"{SERVER_A}"}}"#);
        let refused = call(&body, &ctx);
        assert_eq!(refused["ok"], false, "{refused}");
        assert_eq!(refused["errorCode"], "conflict", "{refused}");
        assert!(
            refused["error"].as_str().unwrap_or("").contains("1 条线路"),
            "要说清还有几条线路：{refused}"
        );
        let dir = root.join("servers").join(SERVER_A);
        assert!(dir.is_dir(), "被拒绝时记录必须还在");

        std::fs::remove_file(root.join("lines").join("L1.json")).unwrap();
        let done = call(&body, &ctx);
        assert_eq!(done["ok"], true, "{done}");
        assert!(done["servers"].as_array().unwrap().is_empty(), "{done}");
        assert!(!dir.exists(), "记录目录要真的删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_remove_reports_unknown_ids_and_bad_requests() {
        let root = tmp_root("server-remove-bad");
        let ctx = ctx_with(None, &root);
        let missing = call(r#"{"cmd":"server-remove"}"#, &ctx);
        assert_eq!(missing["ok"], false);
        assert_eq!(missing["errorCode"], "usage");
        let unknown = call(
            r#"{"cmd":"server-remove","id":"9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b"}"#,
            &ctx,
        );
        assert_eq!(unknown["ok"], false);
        assert_eq!(unknown["errorCode"], "config");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 删除本机部署资料（r90）----------

    const CLEAN_RUN_A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const CLEAN_RUN_B: &str = "bbbbbbbb-2222-4222-8222-222222222222";
    const CLEAN_RUN_C: &str = "cccccccc-3333-4333-8333-333333333333";

    fn run_file(root: &PathBuf, run_id: &str) -> PathBuf {
        root.join("deployments")
            .join("runs")
            .join(format!("{run_id}.json"))
    }

    fn credential_file(root: &PathBuf, run_id: &str) -> PathBuf {
        root.join("deployments")
            .join("credentials")
            .join(format!("{run_id}.bin"))
    }

    /// 造一条部署任务记录。只写「归属 / 状态 / 归档」三件事——`RunRecord::from_json`
    /// 对别的字段一律宽容，写多了反而是在替它编事实。
    fn write_run_record(
        root: &PathBuf,
        run_id: &str,
        record_id: Option<&str>,
        state: &str,
        archived: bool,
    ) {
        let dir = root.join("deployments").join("runs");
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = serde_json::json!({
            "SchemaVersion": 1,
            "Kind": "SpiderVPN.DeploymentRun",
            "RunId": run_id,
            "State": state,
            "Target": {
                "Host": "203.0.113.10",
                "Port": 22,
                "User": "root",
                "ServerRecordId": record_id,
            },
        });
        if archived {
            body["ArchivedAtUtc"] = serde_json::json!("2026-11-10T00:00:00Z");
        }
        std::fs::write(dir.join(format!("{run_id}.json")), body.to_string()).unwrap();
    }

    /// 预置提醒文件：`(RunId, 状态)`。
    fn write_reminders(root: &PathBuf, items: &[(&str, &str)]) {
        let dir = root.join("deployments");
        std::fs::create_dir_all(&dir).unwrap();
        let reminders: Vec<serde_json::Value> = items
            .iter()
            .map(|(run_id, state)| {
                serde_json::json!({
                    "Id": format!("{run_id}-{state}"),
                    "RunId": run_id,
                    "State": state,
                    "Step": 4,
                    "CreatedAtUtc": "2026-11-10T00:00:00Z",
                })
            })
            .collect();
        std::fs::write(
            dir.join("reminders.json"),
            serde_json::json!({
                "Schema": 1,
                "Kind": crate::reminder::KIND,
                "Reminders": reminders,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_task_credential(root: &PathBuf, run_id: &str) {
        let dir = root.join("deployments").join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{run_id}.bin")), "{}").unwrap();
    }

    fn write_saved_credential(root: &PathBuf, id: &str) {
        let dir = root.join("servers").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("credential.dpapi.json"), "{}").unwrap();
    }

    fn count_files(dir: &PathBuf) -> usize {
        std::fs::read_dir(dir)
            .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    }

    /// 预览：把要删的东西数清楚，**一个字节都不写**。
    ///
    /// 「只读」在这里是可验证的事：数据根里那三样东西（配置、任务记录目录、提醒文件）
    /// 跑完必须逐字节不变，服务器记录的目录也必须还在。少验一样，「预览」就可能
    /// 悄悄变成「先删一半再说」。
    #[test]
    fn server_cleanup_preview_counts_everything_and_writes_nothing() {
        let root = tmp_root("server-cleanup-preview");
        write_cfg(&root, "L1");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_saved_credential(&root, SERVER_A);
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Complete", false);
        write_run_record(&root, CLEAN_RUN_B, Some(SERVER_A), "Complete", true);
        // 同一台机器、但没写归属的那次部署：不是这条记录的资料。
        write_run_record(&root, CLEAN_RUN_C, None, "Complete", false);
        write_reminders(
            &root,
            &[
                (CLEAN_RUN_A, "Complete"),
                (CLEAN_RUN_B, "Cancelled"),
                (CLEAN_RUN_C, "Complete"),
            ],
        );
        write_task_credential(&root, CLEAN_RUN_A);

        let config_before = std::fs::read(root.join(crate::config::DEFAULT_PATH)).unwrap();
        let runs_before = count_files(&root.join("deployments").join("runs"));
        let reminders_before = std::fs::read(crate::reminder::path(&root)).unwrap();

        let ctx = ctx_with(None, &root);
        let body = format!(r#"{{"cmd":"server-cleanup-preview","id":"{SERVER_A}"}}"#);
        let v = call(&body, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let detail = &v["serverCleanup"];
        assert_eq!(detail["Id"], SERVER_A, "{v}");
        assert_eq!(detail["Host"], "203.0.113.10", "{v}");
        assert_eq!(detail["Port"], 22, "{v}");
        assert_eq!(detail["User"], "root", "{v}");
        assert_eq!(detail["Lines"], 0, "{v}");
        assert_eq!(detail["Runs"], 2, "只数写着归属的那两条：{v}");
        assert_eq!(detail["Archived"], 1, "{v}");
        assert_eq!(detail["Active"], 0, "{v}");
        assert_eq!(detail["Reminders"], 2, "{v}");
        assert_eq!(detail["TaskCredentials"], 1, "{v}");
        assert_eq!(detail["SavedCredential"], true, "{v}");
        assert_eq!(detail["Blocked"], "", "{v}");
        let items: Vec<&str> = detail["Items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect();
        assert_eq!(
            items,
            vec![
                "服务器记录",
                "部署任务记录 2 条（含已归档 1 条）",
                "结果提醒 2 条",
                "任务级登录资料 1 份",
                "长期保存的登录资料",
            ],
            "{v}"
        );

        // 零副作用：逐字节比对。
        assert_eq!(
            std::fs::read(root.join(crate::config::DEFAULT_PATH)).unwrap(),
            config_before,
            "预览不许改配置"
        );
        assert_eq!(
            count_files(&root.join("deployments").join("runs")),
            runs_before,
            "预览不许动任务记录目录"
        );
        assert_eq!(
            std::fs::read(crate::reminder::path(&root)).unwrap(),
            reminders_before,
            "预览不许重写提醒文件"
        );
        assert!(
            root.join("servers").join(SERVER_A).is_dir(),
            "预览结束时记录必须还在"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 线路还在用它：预览给理由，执行给 `conflict`，两边都不许删东西。
    #[test]
    fn server_cleanup_refuses_while_a_line_still_uses_the_server() {
        let root = tmp_root("server-cleanup-lines");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_engine_cfg(&root, "L1", "203.0.113.10");
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Complete", false);
        let ctx = ctx_with(None, &root);

        let preview = call(
            &format!(r#"{{"cmd":"server-cleanup-preview","id":"{SERVER_A}"}}"#),
            &ctx,
        );
        assert_eq!(preview["ok"], true, "{preview}");
        assert_eq!(preview["serverCleanup"]["Lines"], 1, "{preview}");
        let blocked = preview["serverCleanup"]["Blocked"]
            .as_str()
            .unwrap_or_default();
        assert!(blocked.contains("1 条线路"), "要说清还有几条线路：{preview}");

        let done = call(&format!(r#"{{"cmd":"server-cleanup","id":"{SERVER_A}"}}"#), &ctx);
        assert_eq!(done["ok"], false, "{done}");
        assert_eq!(done["errorCode"], "conflict", "{done}");
        assert!(
            done["error"].as_str().unwrap_or_default().contains("1 条线路"),
            "{done}"
        );
        assert!(run_file(&root, CLEAN_RUN_A).is_file(), "被拒绝时一个文件都不许删");
        assert!(root.join("servers").join(SERVER_A).is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 还有部署没结束：拒绝。判据是「非终态」，未知状态也算没结束。
    #[test]
    fn server_cleanup_refuses_while_a_deployment_is_still_running() {
        let root = tmp_root("server-cleanup-active");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Running", false);
        let ctx = ctx_with(None, &root);

        let preview = call(
            &format!(r#"{{"cmd":"server-cleanup-preview","id":"{SERVER_A}"}}"#),
            &ctx,
        );
        assert_eq!(preview["serverCleanup"]["Active"], 1, "{preview}");
        assert!(
            preview["serverCleanup"]["Blocked"]
                .as_str()
                .unwrap_or_default()
                .contains("没有结束"),
            "{preview}"
        );

        let done = call(&format!(r#"{{"cmd":"server-cleanup","id":"{SERVER_A}"}}"#), &ctx);
        assert_eq!(done["ok"], false, "{done}");
        assert_eq!(done["errorCode"], "conflict", "{done}");
        assert!(run_file(&root, CLEAN_RUN_A).is_file(), "{done}");
        assert!(root.join("servers").join(SERVER_A).is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 只删「写着这条记录」的运行记录：同 `host:port` 但没写归属的那条必须留着。
    ///
    /// 这是整个功能里最贵的一条：按地址猜归属，就会把用户手工建的另一次部署一起烧掉。
    #[test]
    fn server_cleanup_only_deletes_runs_that_name_this_record() {
        let root = tmp_root("server-cleanup-ownership");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Complete", false);
        write_run_record(&root, CLEAN_RUN_C, None, "Complete", false);
        let ctx = ctx_with(None, &root);

        let done = call(&format!(r#"{{"cmd":"server-cleanup","id":"{SERVER_A}"}}"#), &ctx);
        assert_eq!(done["ok"], true, "{done}");
        assert_eq!(done["serverCleanupResult"]["RemovedRuns"], 1, "{done}");
        assert!(!run_file(&root, CLEAN_RUN_A).exists(), "属于它的那条要删掉");
        assert!(
            run_file(&root, CLEAN_RUN_C).is_file(),
            "没写归属的那条不是它的资料，必须留着"
        );
        assert!(
            done["servers"].as_array().unwrap().is_empty(),
            "记录本身要删掉：{done}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 提醒与任务级凭据跟着一起删：别人的提醒一条都不许动。
    #[test]
    fn server_cleanup_removes_its_reminders_and_task_credentials() {
        let root = tmp_root("server-cleanup-reminders");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Complete", false);
        write_run_record(&root, CLEAN_RUN_C, None, "Complete", false);
        write_reminders(
            &root,
            &[
                (CLEAN_RUN_A, "Complete"),
                (CLEAN_RUN_A, "Cancelled"),
                (CLEAN_RUN_C, "Complete"),
            ],
        );
        write_task_credential(&root, CLEAN_RUN_A);
        let ctx = ctx_with(None, &root);

        let done = call(&format!(r#"{{"cmd":"server-cleanup","id":"{SERVER_A}"}}"#), &ctx);
        assert_eq!(done["ok"], true, "{done}");
        assert_eq!(done["serverCleanupResult"]["RemovedReminders"], 2, "{done}");
        assert_eq!(
            done["serverCleanupResult"]["RemovedCredentials"], 1,
            "{done}"
        );
        assert!(done["serverCleanupResult"]["Failed"].as_array().unwrap().is_empty());

        let left = crate::reminder::load(&root).expect("提醒文件还在");
        assert_eq!(left.len(), 1, "只剩不属于它的那条：{left:?}");
        assert_eq!(left[0].run_id, CLEAN_RUN_C);
        assert!(!credential_file(&root, CLEAN_RUN_A).exists(), "任务级凭据要删掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 删不掉必须如实列出：`ok` 仍是 true（记录已删了一半），但 `Message` 要说清
    /// 有几项没删掉。把「文件还在」报成成功是这个功能最不能犯的错。
    #[test]
    fn server_cleanup_reports_what_it_could_not_delete() {
        use std::os::windows::fs::OpenOptionsExt;
        // 只允许别人**读**、不允许删：真机上「杀毒/备份软件正拿着它」就是这种形状。
        // 用共享模式而不是只读属性——`fs::remove_file` 会自己把只读属性摘掉再删。
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let root = tmp_root("server-cleanup-failed");
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_run_record(&root, CLEAN_RUN_A, Some(SERVER_A), "Complete", false);
        let path = run_file(&root, CLEAN_RUN_A);
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .expect("要能独占住这个文件");

        let ctx = ctx_with(None, &root);
        let done = call(&format!(r#"{{"cmd":"server-cleanup","id":"{SERVER_A}"}}"#), &ctx);
        assert_eq!(done["ok"], true, "已经删了一半，不能报成整体失败：{done}");
        let result = &done["serverCleanupResult"];
        assert_eq!(result["RemovedRuns"], 0, "{done}");
        let failed = result["Failed"].as_array().unwrap();
        assert!(!failed.is_empty(), "删不掉必须列出来：{done}");
        assert!(
            result["Message"].as_str().unwrap_or_default().contains("没删掉"),
            "这句话必须说明有条数没删掉：{done}"
        );
        assert!(path.is_file(), "文件确实还在，就不许说删了");

        drop(holder);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_cleanup_reports_unknown_ids_and_bad_requests() {
        let root = tmp_root("server-cleanup-bad");
        let ctx = ctx_with(None, &root);
        for cmd in ["server-cleanup-preview", "server-cleanup"] {
            let missing = call(&format!(r#"{{"cmd":"{cmd}"}}"#), &ctx);
            assert_eq!(missing["ok"], false, "{cmd} {missing}");
            assert_eq!(missing["errorCode"], "usage", "{cmd} {missing}");
            let unknown = call(
                &format!(r#"{{"cmd":"{cmd}","id":"9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b"}}"#),
                &ctx,
            );
            assert_eq!(unknown["ok"], false, "{cmd} {unknown}");
            assert_eq!(unknown["errorCode"], "config", "{cmd} {unknown}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_device_rename_validates_before_connecting() {        let root = tmp_root("device-rename-bad");
        let ctx = ctx_with(None, &root);
        let good_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let bad_key = call(
            r#"{"cmd":"server-device-rename","Id":"L1","PublicKey":"short","Name":"东京"}"#,
            &ctx,
        );
        assert_eq!(bad_key["ok"], false);
        assert_eq!(bad_key["errorCode"], "usage");
        assert!(bad_key["serverDeviceRename"]["error"].is_string(), "{bad_key}");

        let empty_name = call(
            &format!(
                r#"{{"cmd":"server-device-rename","Id":"L1","PublicKey":"{good_key}","Name":"  "}}"#
            ),
            &ctx,
        );
        assert_eq!(empty_name["errorCode"], "usage", "{empty_name}");

        // 形状都对，但这台电脑没有线路/记录：在连服务器之前就该拒绝。
        let no_line = call(
            &format!(
                r#"{{"cmd":"server-device-rename","Id":"L1","PublicKey":"{good_key}","Name":"东京"}}"#
            ),
            &ctx,
        );
        assert_eq!(no_line["ok"], false, "{no_line}");
        assert_eq!(no_line["errorCode"], "config", "{no_line}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_device_forget_validates_before_connecting() {
        let root = tmp_root("device-forget-bad");
        let ctx = ctx_with(None, &root);
        // 公钥形状不对：连服务器之前就拒绝，回包必须带设备页自己的键。
        let bad_key = call(
            r#"{"cmd":"server-device-forget","Id":"L1","PublicKey":"short"}"#,
            &ctx,
        );
        assert_eq!(bad_key["ok"], false, "{bad_key}");
        assert!(
            bad_key["serverDeviceForget"]["error"].is_string(),
            "失败要带页面自己的键：{bad_key}"
        );

        // 形状都对，但这台电脑没有线路/记录：同样在连服务器之前拒绝。
        let good_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let no_line = call(
            &format!(
                r#"{{"cmd":"server-device-forget","Id":"L1","PublicKey":"{good_key}"}}"#
            ),
            &ctx,
        );
        assert_eq!(no_line["ok"], false, "{no_line}");
        assert!(
            no_line["serverDeviceForget"]["error"].is_string(),
            "{no_line}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn server_uninstall_preview_reports_unknown_records() {
        let root = tmp_root("server-uninstall-preview-bad");
        let ctx = ctx_with(None, &root);
        let unknown = call(
            r#"{"cmd":"server-uninstall-preview","id":"9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b"}"#,
            &ctx,
        );
        assert_eq!(unknown["ok"], false, "{unknown}");
        assert_eq!(unknown["errorCode"], "config", "{unknown}");
        assert!(
            unknown["serverUninstallPreview"]["error"].is_string(),
            "失败也要带页面自己的键：{unknown}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 预览要同时说清「删什么」与「留什么」，并且**一个字节都不动**。
    #[test]
    fn delete_preview_lists_what_goes_and_what_stays_without_side_effects() {
        let root = tmp_root("delete-preview-ok");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L2", "203.0.113.10");
        // 两条记录：只许归属到字面地址相等的那条，不做猜测。
        write_server_record(&root, SERVER_A, "203.0.113.10");
        write_server_record(&root, SERVER_B, "198.51.100.7");
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let cfg_before = std::fs::read(&cfg_path).unwrap();
        // 夹具的首次保存自己会记一条「导入线路」；要证明的是预览没有追加。
        let log_path = root.join("logs").join(crate::events::FILE);
        let log_before = std::fs::read(&log_path).ok();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-preview","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let p = &v["deletePreview"];
        assert_eq!(p["Name"], "线路乙", "{v}");
        assert_eq!(p["Eligible"], true, "{v}");
        assert!(p["Blocked"].as_array().unwrap().is_empty(), "{v}");
        assert_eq!(p["Selected"], false, "{v}");
        assert_eq!(p["LastLine"], false, "{v}");

        let files = p["Files"].as_array().unwrap();
        assert_eq!(files.len(), 1, "{v}");
        let file = files[0].as_str().unwrap();
        assert!(
            !file.contains(root.to_string_lossy().as_ref()),
            "对话框里不能出现用户的绝对目录：{v}"
        );
        assert!(file.ends_with("L2.json"), "{v}");

        assert_eq!(p["Server"]["Id"], SERVER_A, "归属判据必须与 servers 命令一致：{v}");
        assert_eq!(p["Server"]["Host"], "203.0.113.10", "{v}");

        // 只读：配置一字节没变、引擎文件还在、没追加操作记录。
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before);
        assert!(root.join("lines").join("L2.json").is_file());
        assert_eq!(
            std::fs::read(&log_path).ok(),
            log_before,
            "预览不能写操作记录"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 连接没断时预览必须说「不能删」，且要与 `remove` 的闸门同源——
    /// 预览说能删、确认后却被拒，等于让用户白点一次。
    #[test]
    fn delete_preview_refuses_to_promise_a_delete_while_connected() {
        let root = tmp_root("delete-preview-busy");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L2", "203.0.113.10");
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let cfg_before = std::fs::read(&cfg_path).unwrap();
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-preview","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "「现在不能删」是预览结论，不是命令失败：{v}");
        let p = &v["deletePreview"];
        assert_eq!(p["Eligible"], false, "{v}");
        let blocked = p["Blocked"].as_array().unwrap();
        assert_eq!(blocked[0]["Code"], "Busy", "{v}");
        assert!(
            blocked[0]["Message"].as_str().unwrap().contains("断开"),
            "阻塞原因要给出路：{v}"
        );
        // 同一时刻 `remove` 也必须拒；两边判据分叉就是缺陷。
        let removed = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx);
        assert_eq!(removed["ok"], false, "{removed}");
        assert_eq!(std::fs::read(&cfg_path).unwrap(), cfg_before);
        assert!(root.join("lines").join("L2.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 命令本身出错（缺 id / 找不到线路 / 没有配置）要回 `ok:false` + `errorCode`，
    /// 不能混成「预览结论是暂时不能删」——那会让人以为线路还在、只是被占用。
    #[test]
    fn delete_preview_separates_command_errors_from_a_blocked_preview() {
        let root = tmp_root("delete-preview-errors");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);

        let missing_id = call(r#"{"cmd":"delete-preview"}"#, &ctx);
        assert_eq!(missing_id["ok"], false, "{missing_id}");
        assert_eq!(missing_id["errorCode"], "usage", "{missing_id}");

        let not_found = call(r#"{"cmd":"delete-preview","id":"L9"}"#, &ctx);
        assert_eq!(not_found["ok"], false, "{not_found}");
        assert_eq!(not_found["errorCode"], "config", "{not_found}");
        assert!(not_found["error"].as_str().unwrap().contains("L9"), "{not_found}");

        let empty_root = tmp_root("delete-preview-no-cfg");
        let no_cfg = call(r#"{"cmd":"delete-preview","id":"L1"}"#, &ctx_with(None, &empty_root));
        assert_eq!(no_cfg["ok"], false, "{no_cfg}");
        assert_eq!(no_cfg["errorCode"], "config", "{no_cfg}");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty_root);
    }

    /// 最后一条线路：如实说「删完没有可用的了」；没有引擎文件也要如实说。
    /// 这两句都属于「预览的结论」，不阻止删除。
    #[test]
    fn delete_preview_warns_about_the_last_line_and_a_missing_engine_config() {
        let root = tmp_root("delete-preview-warnings");
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"only","lines":[
                {"id":"only","name":"唯一线路","proxy_endpoint":"127.0.0.1:17901"}
            ]}"#,
        )
        .unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-preview","id":"only"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let p = &v["deletePreview"];
        assert_eq!(p["LastLine"], true, "{v}");
        assert_eq!(p["Selected"], true, "{v}");
        assert_eq!(p["Eligible"], true, "{v}");
        assert!(p["Files"].as_array().unwrap().is_empty(), "{v}");

        let codes: Vec<&str> = p["Warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["Code"].as_str())
            .collect();
        assert!(codes.contains(&"LastLine"), "{v}");
        assert!(codes.contains(&"NoEngineConfig"), "{v}");
        assert!(
            !codes.contains(&"Selected"),
            "最后一条不该再叠「删除后自动切换」：{v}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 服务器记录读不出来时，只能说「不知道」，**不能**落成「没有记录」。
    #[test]
    fn delete_preview_says_server_unknown_instead_of_no_record() {
        let root = tmp_root("delete-preview-server-bad");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L2", "203.0.113.10");
        let dir = root.join("servers").join(SERVER_A);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("record.json"), b"{not json").unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-preview","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let p = &v["deletePreview"];
        assert_eq!(p["Server"], serde_json::Value::Null, "{v}");
        let codes: Vec<&str> = p["Warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["Code"].as_str())
            .collect();
        assert!(
            codes.contains(&"ServerUnknown"),
            "读不出记录时不能假装没有记录：{v}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 删除结果核对与待清理（A4 第二轮）----------

    fn pending_of(id: &str, file: &str) -> crate::cleanup::Pending {
        crate::cleanup::Pending {
            id: id.to_string(),
            name: "线路乙".to_string(),
            file: file.to_string(),
            error: "拒绝访问。".to_string(),
        }
    }

    fn history_rows(ctx: &Ctx) -> Vec<serde_json::Value> {
        call(r#"{"cmd":"history"}"#, ctx)["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    /// 正常删除：文件真的删掉、回包说 `Incomplete=false`、陈旧的待清理记录被清掉。
    #[test]
    fn removing_a_line_deletes_its_engine_file_and_reports_a_clean_delete() {
        let root = tmp_root("remove-clean");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L2", "203.0.113.10");
        // 上次失败留下的旧记录：这次删成功了必须一并清掉，否则页面永远挂着一条假待办。
        crate::cleanup::upsert(&root, pending_of("L2", "lines\\L2.json")).unwrap();
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;

        let v = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let result = &v["deleteResult"];
        assert_eq!(result["Id"], "L2", "{v}");
        assert_eq!(result["Incomplete"], false, "{v}");
        assert_eq!(result["Error"], serde_json::Value::Null, "{v}");
        let file = result["File"].as_str().unwrap_or("");
        assert!(file.ends_with("L2.json"), "{v}");
        assert!(!file.contains(root.to_string_lossy().as_ref()), "不许带回绝对路径：{v}");

        assert!(!root.join("lines").join("L2.json").exists(), "引擎配置必须真的删掉");
        assert!(crate::cleanup::load(&root).unwrap().is_empty(), "成功删除要清掉旧待办");
        assert!(!crate::cleanup::path(&root).exists());
        assert!(
            !history_rows(&ctx).iter().any(|row| row["action"] == crate::events::CLEANUP),
            "删干净了不该留一条清理记录"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 文件删不掉：配置照常删、命令仍算成功，但回包必须 `Incomplete=true`，
    /// 待清理记录要落盘（界面靠它给「重试清理」），操作记录里留一条失败。
    #[test]
    fn a_locked_engine_file_is_reported_and_remembered_for_retry() {
        let root = tmp_root("remove-locked");
        write_cfg(&root, "L1");
        // 目录占住 `lines\L2.json`：`remove_file` 在 Windows 上必定失败，
        // 这就是「文件被占着」的最小复现。
        std::fs::create_dir_all(root.join("lines").join("L2.json")).unwrap();
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;

        let v = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "线路已经删掉了，命令不该报失败：{v}");
        let result = &v["deleteResult"];
        assert_eq!(result["Incomplete"], true, "{v}");
        assert!(!result["Error"].as_str().unwrap_or("").is_empty(), "{v}");
        let file = result["File"].as_str().unwrap_or("");
        assert!(file.ends_with("L2.json") && !file.contains(root.to_string_lossy().as_ref()), "{v}");

        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert!(cfg.find_line("L2").is_none(), "线路必须已经从配置里消失");
        let pending = crate::cleanup::load(&root).unwrap();
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert_eq!(pending[0].id, "L2");
        assert_eq!(pending[0].file, file, "记录里的文件要与人看到的一致");
        let raw = std::fs::read_to_string(crate::cleanup::path(&root)).unwrap();
        assert!(!raw.contains(root.to_string_lossy().as_ref()), "绝对路径不许落盘：{raw}");

        let failed = history_rows(&ctx)
            .into_iter()
            .find(|row| row["action"] == crate::events::CLEANUP)
            .expect("清理失败要留一条操作记录");
        assert_eq!(failed["ok"], false, "{failed}");
        assert_eq!(failed["src"], "ui", "{failed}");
        assert_eq!(failed["obj"], "line:L2", "{failed}");

        let cleanup = call(r#"{"cmd":"delete-cleanup"}"#, &ctx);
        assert_eq!(cleanup["ok"], true, "{cleanup}");
        assert_eq!(cleanup["deleteCleanup"]["Pending"][0]["Id"], "L2", "{cleanup}");
        assert_eq!(cleanup["deleteCleanup"]["ReadError"], "", "{cleanup}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 重试：文件删得掉就真删、记录清空、操作记录说成功。
    #[test]
    fn retrying_cleanup_deletes_the_file_and_clears_the_record() {
        let root = tmp_root("cleanup-retry-ok");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L9", "203.0.113.10");
        crate::cleanup::upsert(&root, pending_of("L9", "lines\\L9.json")).unwrap();
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;

        let v = call(r#"{"cmd":"delete-cleanup-retry","id":"L9"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let result = &v["deleteCleanupResult"];
        assert_eq!(result["Complete"], true, "{v}");
        assert_eq!(result["Removed"], true, "{v}");
        assert_eq!(result["Error"], serde_json::Value::Null, "{v}");
        assert!(!root.join("lines").join("L9.json").exists(), "文件必须真的删掉");
        assert!(crate::cleanup::load(&root).unwrap().is_empty());
        assert!(!crate::cleanup::path(&root).exists());

        let done = history_rows(&ctx)
            .into_iter()
            .find(|row| row["action"] == crate::events::CLEANUP)
            .expect("清理成功也要留一条操作记录");
        assert_eq!(done["ok"], true, "{done}");
        assert_eq!(done["obj"], "line:L9", "{done}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 同 id 的线路又回到了配置里：旧记录指向的是**这条新线路**的引擎文件，不能照删。
    #[test]
    fn cleanup_retry_refuses_while_the_line_is_still_configured() {
        let root = tmp_root("cleanup-retry-live");
        write_cfg(&root, "L1");
        write_engine_cfg(&root, "L2", "203.0.113.10");
        crate::cleanup::upsert(&root, pending_of("L2", "lines\\L2.json")).unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-cleanup-retry","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "cleanup", "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("还在线路列表里"),
            "要说清为什么拒绝：{v}"
        );
        assert!(v["deleteCleanupResult"]["Message"].as_str().unwrap_or("").contains("还在线路列表里"), "{v}");
        assert!(root.join("lines").join("L2.json").is_file(), "在用的线路文件一个字节都不能动");
        assert_eq!(crate::cleanup::load(&root).unwrap().len(), 1);

        let missing = call(r#"{"cmd":"delete-cleanup-retry"}"#, &ctx);
        assert_eq!(missing["errorCode"], "usage", "{missing}");
        let unknown = call(r#"{"cmd":"delete-cleanup-retry","id":"L8"}"#, &ctx);
        assert_eq!(unknown["ok"], false, "{unknown}");
        assert!(unknown["error"].as_str().unwrap_or("").contains("没有线路"), "{unknown}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 文件已经不在：算完成，但如实说“已经不在了”，不说“刚刚删掉了”。
    #[test]
    fn cleanup_retry_says_already_gone_instead_of_pretending_it_deleted() {
        let root = tmp_root("cleanup-retry-gone");
        write_cfg(&root, "L1");
        crate::cleanup::upsert(&root, pending_of("L8", "lines\\L8.json")).unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-cleanup-retry","id":"L8"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["deleteCleanupResult"]["Complete"], true, "{v}");
        assert_eq!(v["deleteCleanupResult"]["Removed"], false, "{v}");
        assert!(
            v["deleteCleanupResult"]["Message"].as_str().unwrap_or("").contains("已经不在了"),
            "{v}"
        );
        assert!(crate::cleanup::load(&root).unwrap().is_empty(), "记录要清掉");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 记录文件坏掉：`delete-cleanup` 必须报错，`ReadError` 要能显示——
    /// 不能把“读不出来”显示成“没有待清理”。
    #[test]
    fn delete_cleanup_reports_a_corrupt_record_instead_of_an_empty_list() {
        let root = tmp_root("cleanup-corrupt");
        write_cfg(&root, "L1");
        let file = crate::cleanup::path(&root);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{ not json").unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"delete-cleanup"}"#, &ctx);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "cleanup", "{v}");
        assert!(
            !v["deleteCleanup"]["ReadError"].as_str().unwrap_or("").is_empty(),
            "页面要靠 ReadError 说“不知道”，不能显示成没有：{v}"
        );
        assert_eq!(v["deleteCleanup"]["Pending"].as_array().unwrap().len(), 0, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 维护与恢复（临时根 + 临时注册表键，不碰真实系统代理）----------

    #[test]
    fn maintenance_commands_are_exposed_and_empty_restore_is_idempotent() {
        let root = tmp_root("maintenance-empty");
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;

        let status = call(r#"{"cmd":"maintenance-status"}"#, &ctx);
        assert_eq!(status["ok"], true, "{status}");
        assert_eq!(status["maintenance"]["journalPresent"], false, "{status}");
        assert_eq!(status["maintenance"]["canRestore"], false, "{status}");
        let full = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(full["maintenance"]["journalPresent"], false, "status 与独立命令必须同源：{full}");

        // 空根在后端读取代理键之前就返回，不会写真实代理；两次结果必须一致。
        for _ in 0..2 {
            let restored = call(r#"{"cmd":"restore"}"#, &ctx);
            assert_eq!(restored["ok"], true, "{restored}");
            assert_eq!(restored["restoreResult"]["changed"], false, "{restored}");
            assert_eq!(restored["message"], "没有待还原凭据，未执行任何写入。", "{restored}");
            assert!(!root.join("proxy-journal.json").exists());
        }
        let history = call(r#"{"cmd":"history"}"#, &ctx);
        let events = history["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "两次 no-op 都是真实用户动作，应各留一条审计：{history}");
        for event in events {
            assert_eq!(event["action"], crate::events::RESTORE);
            assert_eq!(event["src"], "ui");
            assert_eq!(event["obj"], "system-proxy");
            assert_eq!(event["ok"], true);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_roundtrip_uses_scratch_key_and_never_overwrites_external_proxy() {
        let root = tmp_root("maintenance-roundtrip");
        let mut ctx = ctx_with(None, &root);
        ctx.source = crate::events::Source::Ui;
        let key = format!(r"Software\SpiderVPN\tests\ipc-maintenance-{}", std::process::id());
        let store = crate::proxy::ProxyStore { key_path: key.clone() };
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&key);
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &1u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:17890".to_string()).unwrap();
            k.set_value("ProxyOverride", &"localhost;<local>".to_string()).unwrap();
        }
        let saved = crate::proxy::ProxySnapshot {
            enable: false,
            server: Some("127.0.0.1:7897".into()),
            bypass: Some("localhost".into()),
            readable: true,
        };
        let journal_path = root.join("proxy-journal.json");
        let journal = crate::proxy::ProxyJournal::from_snapshot(&saved, "127.0.0.1:17890", 1.0);
        crate::proxy::write_journal(&journal_path, &journal).unwrap();
        let before = crate::proxy::maintenance_status(&store, &journal_path);
        assert!(before.journal_present && before.proxy_owned && before.can_restore, "{before:?}");

        let restored: serde_json::Value = serde_json::from_str(&restore_with_store(&ctx, &store)).unwrap();
        assert_eq!(restored["ok"], true, "{restored}");
        assert_eq!(restored["restoreResult"]["changed"], true, "{restored}");
        assert!(!journal_path.exists(), "正常还原后凭据必须消费");
        let after = store.read();
        assert_eq!(after.enable, saved.enable);
        assert_eq!(after.server, saved.server);
        assert_eq!(after.bypass, saved.bypass);
        assert_eq!(restored["maintenance"]["journalPresent"], false, "{restored}");
        let history = call(r#"{"cmd":"history"}"#, &ctx);
        assert_eq!(history["events"][0]["action"], crate::events::RESTORE, "{history}");
        assert_eq!(history["events"][0]["src"], "ui", "{history}");

        // 外部程序已改代理：只清残留凭据，三个当前值一律不覆盖。
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &1u32).unwrap();
            k.set_value("ProxyServer", &"10.1.2.3:8080".to_string()).unwrap();
            k.set_value("ProxyOverride", &"external-bypass".to_string()).unwrap();
        }
        let external_before = store.read();
        crate::proxy::write_journal(&journal_path, &journal).unwrap();
        let external: serde_json::Value = serde_json::from_str(&restore_with_store(&ctx, &store)).unwrap();
        assert_eq!(external["ok"], true, "{external}");
        assert_eq!(external["restoreResult"]["changed"], false, "{external}");
        assert_eq!(store.read(), external_before, "外部代理一个值都不许改");
        assert!(!journal_path.exists());

        let _ = hkcu.delete_subkey_all(&key);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 诊断（界面诊断卡用的管道命令，与 --diagnose 同源）----------

    #[test]
    fn diagnose_payload_carries_the_same_lines_as_the_cli() {
        let root = tmp_root("diag-ok");
        write_cfg(&root, "L1");
        std::fs::create_dir_all(root.join("lines")).unwrap();
        // 有 peer 地址的纯 UDP 线路：目标 22/443，UDP 端点只做说明
        std::fs::write(
            root.join("lines").join("L1.json"),
            r#"{"endpoints":[{"type":"wireguard","tag":"hk","peers":[{"address":"127.0.0.1","port":51820}]}],
                "outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"direct"}}"#,
        )
        .unwrap();
        let v = call(r#"{"cmd":"diagnose"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let d = &v["diagnose"];
        assert_eq!(d["ok"], true, "{v}");
        assert_eq!(d["line"], "线路甲", "{v}");
        assert_eq!(d["transport"], "标准连接", "{v}");
        let lines = d["lines"].as_array().expect("要带逐行结果");
        assert!(lines.iter().any(|l| l.as_str().unwrap_or("").contains("TCP 127.0.0.1:22")), "{v}");
        assert!(
            lines.iter().any(|l| l.as_str().unwrap_or("").contains("UDP 127.0.0.1:51820")),
            "UDP 端点要说明不适用：{v}"
        );
        assert!(lines.iter().any(|l| l.as_str().unwrap_or("").starts_with("结论：")), "{v}");
        assert!(d["reachable"].is_boolean(), "{v}");
        let items = d["items"].as_array().expect("T-10 必须带结构化诊断项");
        assert!(items.len() >= 3, "两个 TCP 项 + 一个 UDP 说明项：{v}");
        let tcp22 = items.iter().find(|i| i["port"] == 22).expect("缺 22 端口项");
        assert_eq!(tcp22["target"], "127.0.0.1", "{tcp22}");
        assert_eq!(tcp22["purpose"], "admin", "{tcp22}");
        assert!(tcp22["ms"].is_number(), "成功/失败都要带实际耗时：{tcp22}");
        assert!(tcp22["text"].as_str().unwrap_or("").contains("127.0.0.1:22"), "{tcp22}");
        assert!(d["verdict"]["text"].is_string(), "{v}");
        assert!(d["verdict"]["next"].as_str().unwrap_or("").len() > 0, "{v}");
        assert!(d["verdict"]["code"].is_string(), "{v}");
        // 只读：不许写任何文件
        assert!(!root.join("runtime.json").exists() && !root.join("last-check.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn diagnose_without_a_line_refuses_inside_the_payload() {
        let root = tmp_root("diag-none");
        let v = call(r#"{"cmd":"diagnose"}"#, &ctx_with(None, &root));
        // 外层 ok 仍为 true：页面要在诊断卡里渲染这条错误，而不是当成协议错误
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["diagnose"]["ok"], false, "{v}");
        assert!(
            v["diagnose"]["error"].as_str().unwrap_or("").contains("未配置线路"),
            "{v}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn connect_without_config_fails_with_readable_reason() {
        let root = tmp_root("connect-nocfg");
        let v = call(r#"{"cmd":"connect"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false);
        let e = v["error"].as_str().unwrap_or_default();
        assert!(e.contains("找不到配置文件"), "原因要能指导用户：{e}");
        assert!(!e.contains("未配置线路"), "文件缺失与线路缺失是两回事，不能混用一句话");
        // 什么都没配就不许留下任何痕迹
        assert!(!root.join("runtime.json").exists());
        assert!(!root.join("proxy-journal.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn connect_without_engine_fails_instead_of_pretending() {
        let root = tmp_root("connect-noengine");
        write_cfg(&root, "L1"); // 有线路、没有 engine
        let v = call(r#"{"cmd":"connect"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap_or_default().contains("引擎"));
        // 没有还原凭据就不允许动系统代理——顺序错了就再也退不回来
        assert!(!root.join("proxy-journal.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn disconnect_without_runtime_record_is_idempotent() {
        let root = tmp_root("disc-idem");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"disconnect"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "没有运行时记录时断开是幂等的，不是错误");
        assert_eq!(v["steps"].as_array().map(|a| a.len()), Some(0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn disconnect_keeps_the_last_selfcheck_evidence_for_the_stale_label() {
        let root = tmp_root("disc-keeps-check");
        write_cfg(&root, "L1");
        let passed = crate::selfcheck::Check { ok: true, status: Some(204), error: None, at: 1, skipped: None, via_trade_exit: false };
        crate::selfcheck::save(&root, &passed).unwrap();
        let v = call(r#"{"cmd":"disconnect"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true);
        let kept = crate::selfcheck::load(&root).expect("断开后仍保留上次结论供界面标注（上次）");
        assert!(kept.ok);
        assert_eq!(kept.at, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_connect_clears_the_selfcheck_record() {
        let root = tmp_root("conn-clears");
        write_cfg(&root, "L1"); // 有线路但没有引擎：连接根本发不出去
        let passed = crate::selfcheck::Check { ok: true, status: Some(204), error: None, at: 1, skipped: None, via_trade_exit: false };
        crate::selfcheck::save(&root, &passed).unwrap();
        let v = call(r#"{"cmd":"connect"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap_or_default().contains("引擎"));
        assert_eq!(crate::selfcheck::load(&root), None, "连接失败不能留下上一次的「通过」");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 线路：lines / use / remove ----------

    #[test]
    fn lines_command_returns_every_line_with_the_selected_flag() {
        let root = tmp_root("lines");
        write_cfg(&root, "L2");
        let v = call(r#"{"cmd":"lines"}"#, &ctx_with(None, &root));
        let arr = v["lines"].as_array().expect("lines 必须是数组");
        assert_eq!(arr.len(), 2);
        let selected: Vec<_> = arr.iter().filter(|l| l["selected"] == true).collect();
        assert_eq!(selected.len(), 1, "有且只有一条 selected=true：{v}");
        assert_eq!(selected[0]["id"], "L2");
        assert_eq!(v["selected"], "L2");
        assert_eq!(v["ok"], true);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn use_switches_the_selection_and_pushes_the_new_list() {
        let root = tmp_root("use");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"use","id":"L2"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["selected"], "L2");
        // 回包自带整份列表，且新选中那条打着标记
        let arr = v["lines"].as_array().expect("回包必须带 lines");
        assert_eq!(arr.len(), 2);
        let sel = arr.iter().find(|l| l["selected"] == true).expect("必须有一条选中");
        assert_eq!(sel["id"], "L2");
        // 落盘也要跟上：回包正确但没写盘等于白改
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .expect("磁盘配置必须还在");
        assert_eq!(disk.selected, "L2");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_changes_only_the_name_and_default_selection_persists_on_reload() {
        let root = tmp_root("rename-line");
        write_cfg(&root, "L1");
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let engine = root.join("lines").join("L1.json");
        std::fs::create_dir_all(engine.parent().unwrap()).unwrap();
        std::fs::write(&engine, b"{\"engine\":\"must-not-change\"}\n").unwrap();
        let engine_before = std::fs::read(&engine).unwrap();

        let v = call(
            r#"{"cmd":"rename-line","id":"L1","name":"线路甲-新"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["renameResult"]["changed"], true, "{v}");
        assert_eq!(v["renameResult"]["name"], "线路甲-新", "{v}");
        assert_eq!(v["selected"], "L1", "改名不能顺带切换默认线路：{v}");
        let row = v["lines"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["id"] == "L1")
            .expect("改名后的 L1 必须还在");
        assert_eq!(row["name"], "线路甲-新", "{v}");
        assert_eq!(row["endpoint"], "127.0.0.1:17901", "端点不能被改名改掉：{v}");

        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(disk.selected, "L1");
        assert_eq!(disk.lines[0].id, "L1");
        assert_eq!(disk.lines[0].name, "线路甲-新");
        assert_eq!(std::fs::read(&engine).unwrap(), engine_before, "线路引擎文件必须逐字节不变");
        let latest = crate::events::read(&root, 1).pop().expect("改名必须留下记录");
        assert_eq!(latest.action, crate::events::RENAME_LINE, "{latest:?}");
        assert!(latest.detail.contains("线路甲 → 线路甲-新"), "{latest:?}");

        let before_noop = config_bytes(&root);
        let noop = call(
            r#"{"cmd":"rename-line","id":"L1","name":"线路甲-新"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(noop["ok"], true, "{noop}");
        assert_eq!(noop["renameResult"]["changed"], false, "{noop}");
        assert_eq!(config_bytes(&root), before_noop, "名称没变时不许重写配置");

        let before_dup = config_bytes(&root);
        let dup = call(
            r#"{"cmd":"rename-line","id":"L1","name":"线路乙"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(dup["ok"], false, "{dup}");
        assert_eq!(dup["errorCode"], "conflict", "{dup}");
        assert!(dup["renameResult"]["message"].as_str().unwrap_or_default().contains("已经有"), "{dup}");
        assert_eq!(config_bytes(&root), before_dup, "冲突时配置必须保持原样");

        // 「设为默认」就是既有 use；换一个实例重新读盘等价于重启后仍生效。
        let used = call(r#"{"cmd":"use","id":"L2"}"#, &ctx_with(None, &root));
        assert_eq!(used["ok"], true, "{used}");
        let reloaded = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(reloaded.selected, "L2", "默认线路必须落盘：{reloaded:?}");
        assert_eq!(reloaded.current_line().map(|l| l.name.as_str()), Some("线路乙"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn export_history_writes_only_the_current_filter_under_the_data_root() {
        let root = tmp_root("export-history");
        std::fs::create_dir_all(root.join("logs")).unwrap();
        let rows = [
            serde_json::json!({"ts":"2026-11-01T01:00:00Z","action":"启动","ok":true,"detail":"界面旧记录","src":"ui","actor":"pid:1","obj":"app"}),
            serde_json::json!({"ts":"2026-11-01T01:01:00Z","action":"旧操作","ok":true,"detail":"没有来源字段"}),
            serde_json::json!({"ts":"2026-11-01T01:02:00Z","action":"连接","ok":false,"detail":"端口冲突","src":"cli","actor":"pid:2","obj":"line:L1"}),
        ];
        let raw: String = rows.iter().map(|v| v.to_string() + "\n").collect();
        std::fs::write(crate::events::path(&root), raw).unwrap();

        let v = call(
            r#"{"cmd":"export-history","filter":{"onlyFail":true,"src":"all"}}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["exportResult"]["ok"], true, "{v}");
        assert_eq!(v["exportResult"]["count"], 1, "{v}");
        let path = std::path::PathBuf::from(v["exportResult"]["path"].as_str().unwrap());
        assert!(path.starts_with(root.join("logs").join("exports")), "导出必须落在数据根：{path:?}");
        assert!(!path.display().to_string().contains("http"), "导出路径不能是网络地址：{path:?}");
        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(text.lines().count(), 1, "只导出筛选命中的一条：{text}");
        assert_eq!(line["action"], "连接");
        assert_eq!(line["src"], "cli");
        assert_eq!(line["obj"], "line:L1");

        // 同秒连续导出不能覆盖上一次文件。
        let again = call(
            r#"{"cmd":"export-history","filter":{"onlyFail":true,"src":"all"}}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(again["ok"], true, "{again}");
        assert_ne!(again["exportResult"]["path"], v["exportResult"]["path"], "同名导出要自动避让");

        let unknown = call(
            r#"{"cmd":"export-history","filter":{"onlyFail":false,"src":"unknown"}}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(unknown["ok"], true, "{unknown}");
        assert_eq!(unknown["exportResult"]["count"], 1, "{unknown}");
        let unknown_path = unknown["exportResult"]["path"].as_str().unwrap();
        let unknown_line: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(unknown_path).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(unknown_line["action"], "旧操作");
        assert!(unknown_line.get("src").is_none(), "旧记录没有来源时导出保持原样：{unknown_line}");

        let empty = call(
            r#"{"cmd":"export-history","filter":{"onlyFail":true,"src":"ui"}}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(empty["ok"], false, "{empty}");
        assert_eq!(empty["errorCode"], "environment", "{empty}");
        assert!(empty["exportResult"]["path"].is_null(), "没有记录时不得生成空文件：{empty}");
        assert_eq!(crate::events::read(&root, 10).len(), 3, "导出不能改写记录文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_keeps_selection_unless_the_selected_one_is_removed() {
        let root = tmp_root("remove-keep");
        write_cfg(&root, "L2");
        // 删的不是选中那条：选中保持 L2
        let v = call(r#"{"cmd":"remove","id":"L1"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["selected"], "L2");

        // 删的正是选中那条：回退到剩下里的第一条
        let v2 = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx_with(None, &root));
        assert_eq!(v2["ok"], true, "{v2}");
        let arr = v2["lines"].as_array().expect("回包必须带 lines");
        assert_eq!(arr.len(), 0, "最后一条也删掉了");
        assert_eq!(v2["selected"], "", "删空时 selected 是空串，不是 null");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn use_and_remove_are_refused_while_a_connection_is_live() {
        let root = tmp_root("lines-busy");
        write_cfg(&root, "L1");
        // 「连接中」的判据之一是还原凭据还在：造一个 journal 就等价于连接中（与 T32 同法）。
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let before = config_bytes(&root);
        for cmd in [
            r#"{"cmd":"use","id":"L2"}"#,
            r#"{"cmd":"remove","id":"L1"}"#,
            r#"{"cmd":"rename-line","id":"L1","name":"不该写入"}"#,
        ] {
            let v = call(cmd, &ctx_with(None, &root));
            assert_eq!(v["ok"], false, "{cmd} 连接中必须被拒：{v}");
            assert!(v["error"].as_str().unwrap_or_default().contains("请先断开"), "{v}");
        }
        assert_eq!(config_bytes(&root), before, "拒绝必须是零副作用：配置一个字节都不能变");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lines_is_fresh_after_remove_within_the_same_process() {
        let root = tmp_root("lines-fresh");
        let snapshot = write_cfg(&root, "L1");
        let ctx = ctx_with(Some(snapshot), &root);
        let v = call(r#"{"cmd":"remove","id":"L2"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        // 同一进程紧接着再查两次：都必须反映删除后的事实，而不是启动时的快照。
        for _ in 0..2 {
            let again = call(r#"{"cmd":"lines"}"#, &ctx);
            let arr = again["lines"].as_array().expect("lines 必须是数组");
            assert_eq!(arr.len(), 1, "删除后只剩 1 条：{again}");
            assert!(arr.iter().all(|l| l["id"] != "L2"), "被删的线路不能再出现：{again}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_after_use_reports_the_new_selection() {
        let root = tmp_root("status-after-use");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let u = call(r#"{"cmd":"use","id":"L2"}"#, &ctx);
        assert_eq!(u["ok"], true, "{u}");
        let s = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(s["line"], "线路乙", "status 必须报新选中：{s}");
        assert_eq!(s["endpoint"], "127.0.0.1:17902");
        assert_eq!(s["lineCount"], 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn external_config_change_is_visible_to_a_running_process() {
        let root = tmp_root("lines-external");
        let snapshot = write_cfg(&root, "L1"); // 进程「启动时」看到的是 L1
        let ctx = ctx_with(Some(snapshot), &root);
        // 模拟命令行 `--use L2`：进程运行中配置被外部改了
        let rewritten = crate::config::parse(
            r#"{"schema":2,"selected":"L2","lines":[
                {"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"},
                {"id":"L2","name":"线路乙","proxy_endpoint":"127.0.0.1:17902"}
            ]}"#,
        )
        .unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &rewritten).unwrap();
        let l = call(r#"{"cmd":"lines"}"#, &ctx);
        assert_eq!(l["selected"], "L2", "外部改动必须立即可见：{l}");
        let s = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(s["line"], "线路乙", "status 也一样：{s}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 分流：split / split-add / split-remove ----------

    #[test]
    fn runtime_engine_config_survives_a_failed_channel_check() {
        // D8 回归：判定只看"连接有没有失败"，**与自检结论无关**。
        // 场景：坏成员 → 引擎起来、代理已接管、连接在跑、自检未通过 → 文件必须留下
        //（排查"交易出口为什么不通"要看的就是它）。
        let done = Ok(crate::connect::Outcome::Done(vec!["启动引擎 pid=1".to_string()]));
        assert!(!should_discard_runtime_engine(&done), "连接进入运行态就要保留（自检好坏不参与）");
        assert!(!should_discard_runtime_engine(&Ok(crate::connect::Outcome::AlreadyDone)));
        assert!(
            should_discard_runtime_engine(&Err("端口被占".to_string())),
            "没进入运行态（连接失败）才丢"
        );
    }

    #[test]
    fn failed_channel_check_does_not_delete_the_runtime_config_file() {
        // 落盘层面再确认一次：自检失败的结论躺在 last-check.json 里，
        // 但 runtime-engine.json 只由"连接是否失败"决定去留。
        let root = tmp_root("d8-keep");
        let runtime_cfg = root.join("runtime-engine.json");
        std::fs::write(&runtime_cfg, "{}").unwrap();
        std::fs::write(
            root.join("last-check.json"),
            r#"{"ok":false,"status":null,"error":"交易出口没有连上","at":1}"#,
        )
        .unwrap();
        let done = Ok(crate::connect::Outcome::Done(Vec::new()));
        if should_discard_runtime_engine(&done) {
            crate::connect::discard_runtime_config(&root);
        }
        assert!(runtime_cfg.exists(), "自检未通过但连接在跑时，运行时配置必须保留：{done:?}");
        // 真正失败时才删
        if should_discard_runtime_engine(&Err("x".to_string())) {
            crate::connect::discard_runtime_config(&root);
        }
        assert!(!runtime_cfg.exists(), "连接失败后要删");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_title_is_the_same_projection_as_the_cli() {
        // 两路径一致性：CLI 的 `--status` 与界面的 `status` 都只从 present_with_check 取标题。
        // 谁要是又自己拼一句（上一轮 D8 就是这样），这里立刻红。
        let root = tmp_root("status-title");
        write_cfg(&root, "L1");
        // 「已连接」现场：运行记录里守护与引擎都是本进程（当然活着），状态 Running。
        std::fs::write(
            root.join("runtime.json"),
            serde_json::json!({
                "SchemaVersion": 1,
                "SupervisorPid": std::process::id(),
                "EnginePid": std::process::id(),
                "StartedAt": "2026-01-01T00:00:00Z",
                "State": "Running",
            })
            .to_string(),
        )
        .unwrap();
        crate::selfcheck::save(
            &root,
            &crate::selfcheck::Check {
                ok: false,
                status: None,
                error: Some("连 www.gstatic.com 失败：交易出口没有连上".to_string()),
                at: 1,
                via_trade_exit: true,
                skipped: None,
            },
        )
        .unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));

        let ev = evidence(&root, true, true);
        let check = crate::selfcheck::load(&root).map(|c| c.sentence());
        let want = crate::presentation::present_with_check(&ev, check.as_deref());
        assert_eq!(v["title"], want.title, "界面标题必须等于共用投影：{v}");
        assert_eq!(v["action"], want.action.as_str());
        // 光「已连接」不够：自检没过必须让用户看见「通道未通」。
        assert_eq!(want.title, "已连接（通道未通）");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 临时改环境变量：用例结束（含 panic）复原，别把测试键泄给同进程的其它用例。
    struct EnvGuard(Vec<(&'static str, Option<String>)>);

    impl EnvGuard {
        fn set(pairs: &[(&'static str, String)]) -> EnvGuard {
            let saved = pairs.iter().map(|(k, _)| (*k, std::env::var(k).ok())).collect();
            for (k, v) in pairs {
                std::env::set_var(k, v);
            }
            EnvGuard(saved)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    // Only used by these three original real IPC tests. The parent makes a
    // separate executable directory; confirm the actual running frontend
    // and its bundled copy before driving the real product path.
    fn isolated_ipc_engine() -> (PathBuf, PathBuf) {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(exe.file_name().and_then(|n| n.to_str()),
            Some("spidervpn-engine-entry-fixture.exe"));
        assert!(std::env::var_os("SPIDERVPN_FORCE_NONADMIN").is_none());
        let bin = exe.parent().unwrap();
        let engine = bin.join("sing-box.exe");
        assert_eq!(std::fs::read(&engine).unwrap(),
            std::fs::read(r"C:\Windows\System32\PING.EXE").unwrap());
        crate::engine::validate_privileged_engine(&engine, &exe).unwrap();
        let root = bin.join("data");
        std::fs::create_dir(&root).unwrap();
        (root, engine)
    }

    // Read back the actual process image, not just a PID or the configured
    // filename. Cleanup also restricts termination to this fixture image.
    fn ipc_engine_image(pid: i64) -> Option<PathBuf> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let pid = u32::try_from(pid).ok()?;
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() { return None; }
        let _handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(raw, 0, buffer.as_mut_ptr(), &mut size) } == 0
            || size == 0 || size as usize >= buffer.len()
        {
            return None;
        }
        use std::os::windows::ffi::OsStringExt;
        let name = std::ffi::OsString::from_wide(&buffer[..size as usize]);
        std::fs::canonicalize(PathBuf::from(name)).ok()
    }

    fn assert_ipc_fixture_image(pid: i64, engine: &std::path::Path) {
        assert_eq!(ipc_engine_image(pid), Some(std::fs::canonicalize(engine).unwrap()),
            "real engine PID {pid} must run the isolated same-directory image");
    }

    #[test]
    fn ipc_connect_keeps_runtime_engine_config_until_disconnect() {
        if crate::engine::tests::isolated_engine_entry(
            "ipc::tests::ipc_connect_keeps_runtime_engine_config_until_disconnect", r"C:\Windows\System32\PING.EXE",
        ) { return; }
        let elevated = crate::engine::actual_process_elevation().expect("actual primary token");
        let (root, fixture_engine) = isolated_ipc_engine();
        // 与 CLI 同一个不变量、同一个场景：坏成员（引擎活着、没有东西监听线路端口）→
        // 连接在跑 → runtime-engine.json 必须在；断开才删。收尾走 settle_runtime_engine，
        // 与 main.rs 是同一个函数。
        let key = format!(r"Software\SpiderVPN\tests\ipc-re-{}", std::process::id());
        let mut cleanup = RealEngineCleanup { root: root.clone(), key: key.clone(),
            pids: Vec::new(), engine: fixture_engine.canonicalize().unwrap() };
        // 代理键必须可读：读不到系统代理时连接会被拒绝（那是另一条用例的现场）。
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &0u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:7897".to_string()).unwrap();
            k.set_value("ProxyOverride", &"localhost;127.*".to_string()).unwrap();
        }
        // 假引擎靠测试缝隙活着；不设的话 PING.EXE 拿到 `run -c …` 会立刻退出。
        // 环境变量是全进程共享的，与 config 的参数派生用例及其它真实引擎用例串行。
        let _env_serial = crate::config::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvGuard::set(&[
            ("SPIDERVPN_PROXY_KEY", key.clone()),
            ("SPIDERVPN_ENGINE_ARGS", "-n 30 127.0.0.1".to_string()),
        ]);

        let port = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let cfg = crate::config::parse(
            &serde_json::json!({
                "schema": 2,
                "selected": "L1",
                "mode": "proxy",
                "lines": [{ "id": "L1", "name": "坏成员", "proxy_endpoint": format!("127.0.0.1:{port}") }],
                "engine": { "binary": fixture_engine.to_str().unwrap() }
            })
            .to_string(),
        )
        .unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        let profile = serde_json::json!({
            "inbounds": [{ "type": "mixed", "tag": "tc-mixed", "listen": "127.0.0.1", "listen_port": port }],
            "route": { "rules": [], "final": "daily-exit" },
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct" },
                { "type": "selector", "tag": "daily-exit", "outbounds": ["direct"], "default": "direct" }
            ]
        });
        let body = crate::engine_config::generate(
            &profile.to_string(),
            port,
            crate::config::Mode::Proxy,
            &Default::default(),
            // AI 工具名单：这里只验连接路径，名单为空（与「没有这份名单」等价）。
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let line_path = cfg.current_line().unwrap().engine_config_path(&root);
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        std::fs::write(&line_path, body).unwrap();

        let ctx = ctx_with(None, &root);
        let v = call(r#"{"cmd":"connect"}"#, &ctx);
        assert_eq!(v["ok"], true, "连接应当成功（假引擎活着）：{v}");
        let runtime_engine = root.join("runtime-engine.json");
        assert!(runtime_engine.exists(), "连接在跑，运行时配置必须在：{v}");
        // 「连接在跑」不是靠文件推断：运行记录里的引擎 pid 必须真的活着。
        let rec = crate::model::load_runtime(&root.join("runtime.json")).unwrap().unwrap();
        assert!(
            crate::probe::pid_alive(rec.engine_pid.expect("运行记录必须有引擎 pid")),
            "引擎必须还活着"
        );

        let pid = rec.engine_pid.expect("running engine PID");
        cleanup.pids.push(pid);
        assert_ipc_fixture_image(pid, &fixture_engine);
        let d = call(r#"{"cmd":"disconnect"}"#, &ctx);
        assert_eq!(d["ok"], true, "{d}");
        assert!(!runtime_engine.exists(), "断开后运行时配置必须删除");
        assert!(!crate::probe::pid_alive(pid), "disconnect must stop the actual engine");
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={elevated} ipc_runtime_engine_complete=true real_pid={pid}");

        drop(env);
        let _ = hkcu.delete_subkey_all(&key);
        let _ = std::fs::remove_dir_all(&root);
        drop(cleanup);
    }

    /// 失败也要收掉本次真实拉起的假引擎，并删除临时注册表键；不能靠断言全部通过才清理。
    struct RealEngineCleanup {
        root: PathBuf,
        key: String,
        pids: Vec<i64>,
        engine: PathBuf,
    }

    impl Drop for RealEngineCleanup {
        fn drop(&mut self) {
            if let Ok(Some(rec)) = crate::model::load_runtime(&self.root.join("runtime.json")) {
                if let Some(pid) = rec.engine_pid {
                    if ipc_engine_image(pid).as_ref() == Some(&self.engine) {
                        let _ = crate::engine::stop(pid, 100);
                    }
                }
            }
            for pid in self.pids.drain(..) {
                if ipc_engine_image(pid).as_ref() == Some(&self.engine) {
                    let _ = crate::engine::stop(pid, 100);
                }
            }
            let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.key);
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn t14_compatible_action_really_restarts_the_engine_and_restores_temporary_proxy() {
        if crate::engine::tests::isolated_engine_entry(
            "ipc::tests::t14_compatible_action_really_restarts_the_engine_and_restores_temporary_proxy", r"C:\Windows\System32\PING.EXE",
        ) { return; }
        let elevated = crate::engine::actual_process_elevation().expect("actual primary token");
        let (root, fixture_engine) = isolated_ipc_engine();
        let _env_serial = crate::config::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = format!(r"Software\SpiderVPN\tests\ipc-t14-reconnect-{}", std::process::id());
        let mut cleanup = RealEngineCleanup { root: root.clone(), key: key.clone(),
            pids: Vec::new(), engine: fixture_engine.canonicalize().unwrap() };
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &0u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:7897".to_string()).unwrap();
            k.set_value("ProxyOverride", &"localhost;127.*".to_string()).unwrap();
        }
        let env = EnvGuard::set(&[
            ("SPIDERVPN_PROXY_KEY", key.clone()),
            ("SPIDERVPN_ENGINE_ARGS", "-n 300 127.0.0.1".to_string()),
        ]);
        let store = crate::proxy::ProxyStore { key_path: key.clone() };
        let original_proxy = store.read();
        assert!(original_proxy.readable, "临时代理键必须可读：{original_proxy:?}");

        let port = loop {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port <= 60_000 {
                break port;
            }
        };
        let endpoint = format!("127.0.0.1:{port}");
        let mut cfg = write_cfg(&root, "L1");
        cfg.lines.truncate(1);
        cfg.lines[0].proxy_endpoint = endpoint.clone();
        cfg.engine = Some(crate::config::EngineSettings { binary: fixture_engine.to_str().unwrap().to_string() });
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        write_line_file(&root, "L1", true);
        let ctx = ctx_with(None, &root);

        let initial = call(r#"{"cmd":"connect"}"#, &ctx);
        assert_eq!(initial["ok"], true, "先建立标准连接：{initial}");
        let before = crate::model::load_runtime(&root.join("runtime.json")).unwrap().unwrap();
        let old_pid = before.engine_pid.expect("标准连接必须记录真实引擎 PID");
        cleanup.pids.push(old_pid);
        assert_ipc_fixture_image(old_pid, &fixture_engine);
        assert!(crate::probe::pid_alive(old_pid), "旧引擎必须真实存活");
        assert_eq!(
            crate::engine_config::actual_transport(&root.join("runtime-engine.json")),
            Some(crate::config::Transport::Udp),
            "重连前的运行时必须是标准连接"
        );
        // 不手写资格证据：PING 不监听探测口，首次连接留下的必须是真实自检失败。
        let failed = crate::selfcheck::load(&root).expect("首次连接必须留下自检结论");
        assert!(!failed.ok && failed.skipped.is_none(), "动作资格必须来自真实的自检未通过：{failed:?}");
        let before_status = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(before_status["transportActual"], "标准连接", "{before_status}");
        assert_eq!(before_status["compatibleAction"], true, "{before_status}");

        let changed = call(r#"{"cmd":"use-compatible"}"#, &ctx);
        assert_eq!(changed["ok"], true, "复合动作必须完成：{changed}");
        assert_eq!(changed["compatibleResult"]["stage"], "done", "{changed}");
        for field in ["saved", "reconnected", "verified"] {
            assert_eq!(changed["compatibleResult"][field], true, "{field} 必须为真：{changed}");
        }

        let after = crate::model::load_runtime(&root.join("runtime.json")).unwrap().unwrap();
        let new_pid = after.engine_pid.expect("重连后必须记录新引擎 PID");
        cleanup.pids.push(new_pid);
        assert_ipc_fixture_image(new_pid, &fixture_engine);
        assert_ne!(new_pid, old_pid, "重连不能沿用旧引擎 PID");
        assert!(!crate::probe::pid_alive(old_pid), "旧引擎 PID={old_pid} 必须已经停止");
        assert!(crate::probe::pid_alive(new_pid), "新引擎 PID={new_pid} 必须真实存活");
        assert_ne!(after.started_at, before.started_at, "必须产生新的连接会话");
        assert_eq!(
            crate::engine_config::actual_transport(&root.join("runtime-engine.json")),
            Some(crate::config::Transport::Tcp),
            "新运行时配置必须确实挂在兼容中转上"
        );
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(disk.lines[0].transport, Some(crate::config::Transport::Tcp));
        let during = store.read();
        assert!(during.enable && during.server.as_deref() == Some(endpoint.as_str()), "重连后临时代理必须指向本线路：{during:?}");
        let after_status = call(r#"{"cmd":"status"}"#, &ctx);
        assert_eq!(after_status["transportActual"], "兼容连接", "{after_status}");
        assert_eq!(after_status["compatibleAction"], false, "已选兼容后不能继续显示同一切换动作：{after_status}");

        let stopped = call(r#"{"cmd":"disconnect"}"#, &ctx);
        assert_eq!(stopped["ok"], true, "验收结束必须真实断开：{stopped}");
        assert!(!crate::probe::pid_alive(new_pid), "收尾后新引擎也必须停止");
        assert_eq!(store.read(), original_proxy, "最终必须还原临时键里的原始代理值");
        assert!(!root.join("runtime.json").exists());
        assert!(!root.join("runtime-engine.json").exists());
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={elevated} ipc_reconnect_complete=true old_pid={old_pid} new_pid={new_pid} proxy_restored=true");
        drop(env);
        drop(cleanup);
    }

    #[test]
    fn t14_verify_failure_is_reported_after_a_real_reconnect_without_rollback() {
        if crate::engine::tests::isolated_engine_entry(
            "ipc::tests::t14_verify_failure_is_reported_after_a_real_reconnect_without_rollback", r"C:\Windows\System32\PING.EXE",
        ) { return; }
        let elevated = crate::engine::actual_process_elevation().expect("actual primary token");
        let (root, fixture_engine) = isolated_ipc_engine();
        let _env_serial = crate::config::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = format!(r"Software\SpiderVPN\tests\ipc-t14-verify-{}", std::process::id());
        let mut cleanup = RealEngineCleanup { root: root.clone(), key: key.clone(),
            pids: Vec::new(), engine: fixture_engine.canonicalize().unwrap() };
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        {
            let (k, _) = hkcu.create_subkey(&key).unwrap();
            k.set_value("ProxyEnable", &0u32).unwrap();
            k.set_value("ProxyServer", &"127.0.0.1:7897".to_string()).unwrap();
            k.set_value("ProxyOverride", &"localhost;127.*".to_string()).unwrap();
        }
        let env = EnvGuard::set(&[
            ("SPIDERVPN_PROXY_KEY", key.clone()),
            ("SPIDERVPN_ENGINE_ARGS", "-n 300 127.0.0.1".to_string()),
        ]);
        let store = crate::proxy::ProxyStore { key_path: key.clone() };
        let original_proxy = store.read();
        let port = loop {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port <= 60_000 { break port; }
        };
        let endpoint = format!("127.0.0.1:{port}");
        let mut cfg = write_cfg(&root, "L1");
        cfg.lines.truncate(1);
        cfg.lines[0].proxy_endpoint = endpoint.clone();
        cfg.engine = Some(crate::config::EngineSettings {
            binary: fixture_engine.to_str().unwrap().to_string(),
        });
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        write_line_file(&root, "L1", true);
        let ctx = ctx_with(None, &root);
        let initial = call(r#"{"cmd":"connect"}"#, &ctx);
        assert_eq!(initial["ok"], true, "先建立标准连接：{initial}");
        let before = crate::model::load_runtime(&root.join("runtime.json")).unwrap().unwrap();
        let old_pid = before.engine_pid.expect("旧引擎 PID");
        cleanup.pids.push(old_pid);
        assert_ipc_fixture_image(old_pid, &fixture_engine);
        let failed = crate::selfcheck::load(&root).expect("真实自检结论");
        assert!(!failed.ok && failed.skipped.is_none(), "资格必须来自真实自检未通过：{failed:?}");
        assert_eq!(call(r#"{"cmd":"status"}"#, &ctx)["compatibleAction"], true);

        // 只让“重连后的运行时核验”返回未知；保存、断开和真实进程重连仍走产品原路径。
        let changed = {
            struct ResetActualTransport;
            impl Drop for ResetActualTransport {
                fn drop(&mut self) {
                    crate::engine_config::force_actual_transport_unknown_for_test(false);
                }
            }
            crate::engine_config::force_actual_transport_unknown_for_test(true);
            let _reset = ResetActualTransport;
            call(r#"{"cmd":"use-compatible"}"#, &ctx)
        };
        assert_eq!(changed["ok"], false, "核验失败不能报成功：{changed}");
        assert_eq!(changed["compatibleResult"]["stage"], "verify", "{changed}");
        assert_eq!(changed["compatibleResult"]["saved"], true, "{changed}");
        assert_eq!(changed["compatibleResult"]["reconnected"], true, "{changed}");
        assert_eq!(changed["compatibleResult"]["verified"], false, "{changed}");
        assert!(changed["message"].as_str().unwrap_or_default().contains("未自动回退标准连接"), "{changed}");

        let after = crate::model::load_runtime(&root.join("runtime.json")).unwrap().unwrap();
        let new_pid = after.engine_pid.expect("重连后的新引擎 PID");
        cleanup.pids.push(new_pid);
        assert_ipc_fixture_image(new_pid, &fixture_engine);
        assert_ne!(new_pid, old_pid);
        assert!(!crate::probe::pid_alive(old_pid), "即使核验失败，旧引擎也确实已停止");
        assert!(crate::probe::pid_alive(new_pid), "reconnected=true 必须有真实存活的新引擎");
        assert_ne!(after.started_at, before.started_at);
        assert_eq!(
            crate::engine_config::actual_transport(&root.join("runtime-engine.json")),
            Some(crate::config::Transport::Tcp),
            "故障注入只影响核验观察，不得篡改实际运行时；事务也不能自动回退"
        );
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert_eq!(disk.lines[0].transport, Some(crate::config::Transport::Tcp));
        let during = store.read();
        assert!(during.enable && during.server.as_deref() == Some(endpoint.as_str()));

        let stopped = call(r#"{"cmd":"disconnect"}"#, &ctx);
        assert_eq!(stopped["ok"], true, "{stopped}");
        assert!(!crate::probe::pid_alive(new_pid));
        assert_eq!(store.read(), original_proxy);
        assert!(!root.join("runtime.json").exists());
        assert!(!root.join("runtime-engine.json").exists());
        println!("ENGINE_ENTRY_ACTUAL_TOKEN elevated={elevated} ipc_verify_failure_no_rollback_complete=true old_pid={old_pid} new_pid={new_pid} proxy_restored=true");
        drop(env);
        drop(cleanup);
    }

    #[test]
    fn split_payload_lists_processes_then_domains_in_insertion_order() {
        let root = tmp_root("split-order");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        call(r#"{"cmd":"split-add","kind":"process","value":"a.exe"}"#, &ctx);
        call(r#"{"cmd":"split-add","kind":"process","value":"b.exe","target":"trade"}"#, &ctx);
        call(r#"{"cmd":"split-add","kind":"domain","value":"qq.com","target":"daily"}"#, &ctx);
        call(r#"{"cmd":"split-add","kind":"domain","value":"bilibili.com"}"#, &ctx);
        let v = call(r#"{"cmd":"split"}"#, &ctx);
        let ps = v["processes"].as_array().expect("processes 必须是数组");
        // 出口版：条目是 {value, target} 对象，顺序 = 添加顺序
        assert_eq!(ps[0]["value"], "a.exe");
        assert_eq!(ps[0]["target"], "direct", "不带 target 默认直连");
        assert_eq!(ps[1]["value"], "b.exe");
        assert_eq!(ps[1]["target"], "trade");
        let ds = v["domains"].as_array().expect("domains 必须是数组");
        assert_eq!(ds[0]["value"], "qq.com");
        assert_eq!(ds[0]["target"], "daily");
        assert_eq!(ds[1]["value"], "bilibili.com");
        assert_eq!(ds[1]["target"], "direct");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_trade_list_carries_only_trade_entries() {
        // 线路页那块写的是「这些流量始终走交易线路」：日常/直连的条目混进来
        // 就等于告诉用户「它走交易线路」，而实际并没有。
        let root = tmp_root("status-trade-list");
        // 配置里真正存的是一个反斜杠；JSON 字面量里写两个。
        let disk_path = r"C:\Users\x\Mirasim.exe";
        let json_path = r"C:\\Users\\x\\Mirasim.exe";
        let c = crate::config::parse(&format!(
            r#"{{"schema":2,"selected":"L1","lines":[
                {{"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"}}
            ],"split":{{
                "processes":[
                    {{"value":"Mirasim.exe","target":"trade","path":"{json_path}"}},
                    {{"value":"chrome.exe","target":"daily"}}
                ],
                "domains":[
                    {{"value":"tradingview.com","target":"trade"}},
                    {{"value":"bilibili.com","target":"daily"}}
                ]
            }}}}"#
        ))
        .expect("测试配置必须是合法 JSON");
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &c).expect("写入测试配置");

        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        let list = &v["tradeList"];
        let programs = list["programs"].as_array().expect("programs 必须是数组");
        assert_eq!(programs.len(), 1, "日常出口的进程不许出现：{list}");
        assert_eq!(programs[0]["name"], "Mirasim.exe");
        assert_eq!(programs[0]["path"], disk_path, "路径要原样给，不要二次处理");

        let domains = list["domains"].as_array().expect("domains 必须是数组");
        assert_eq!(
            domains.iter().filter_map(|d| d.as_str()).collect::<Vec<_>>(),
            vec!["tradingview.com"],
            "日常出口的域名不许出现：{list}"
        );
        assert_eq!(
            list["aux"].as_array().map(|a| a.len()),
            Some(0),
            "本版没有辅助解析，字段恒为空数组"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_trade_list_gives_an_empty_path_when_a_trade_entry_never_recorded_one() {
        // 「交易条目但没记过程序位置」是真实形态（旧版的名单只有名字，本版靠 `path`
        // 才能算 WFP 身份）。线路页要照常显示这个名字、路径给空串：编一个看起来像路径的
        // 值比空着更糟，因为界面会拿它当"已确认的位置"。
        //
        // 口径说明：**裸字符串恒为 direct**（`SplitEntry::target()` 对 `Plain` 返回 Direct），
        // 它永远不会进交易名单；所以「交易但没位置」在配置里只能写成
        // `{"value":"TDXW.exe","target":"trade"}`（`with_path(name, Trade, None)` 落盘就是这个
        // 形状，`path` 被 skip_serializing_if 省掉）。两种都造，顺带钉住这条语义：
        // 没路径不等于默认进交易名单。
        let root = tmp_root("status-trade-list-nopath");
        let c = crate::config::parse(
            r#"{"schema":2,"selected":"L1","lines":[
                {"id":"L1","name":"线路甲","proxy_endpoint":"127.0.0.1:17901"}
            ],"split":{
                "processes":[
                    {"value":"TDXW.exe","target":"trade"},
                    "curl.exe"
                ],
                "domains":[]
            }}"#,
        )
        .expect("测试配置必须是合法 JSON");
        // 先把"造出来的数据真的是这个形态"钉住，别让测试自己骗自己。
        assert_eq!(
            c.split.processes[0].target(),
            crate::config::SplitTarget::Trade,
            "这条必须是交易条目，否则它压根不该进名单"
        );
        assert_eq!(c.split.processes[0].path(), None, "这条就是没记位置的老形态");
        assert_eq!(
            c.split.processes[1].target(),
            crate::config::SplitTarget::Direct,
            "裸字符串恒为直连，不该出现在交易名单里"
        );
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &c).expect("写入测试配置");

        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        let programs = v["tradeList"]["programs"].as_array().expect("programs 必须是数组");
        assert_eq!(programs.len(), 1, "只有 target=trade 的条目进名单：{v}");
        assert_eq!(programs[0]["name"], "TDXW.exe", "名字要照实给：{v}");
        assert_eq!(programs[0]["path"], "", "没记位置就给空串，不要编造路径：{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_trade_list_is_three_empty_arrays_when_config_is_unreadable() {
        // 读配置失败不该让整个 status 变成错误：线路页空着，其余照常。
        let root = tmp_root("status-trade-list-nocfg");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        for key in ["programs", "domains", "aux"] {
            assert!(v["tradeList"][key].is_array(), "{key} 必须是数组：{v}");
            assert_eq!(v["tradeList"][key].as_array().map(|a| a.len()), Some(0), "{v}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resetting_trade_domains_replaces_only_the_trade_group_on_disk() {
        let root = tmp_root("split-reset-trade");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        call(
            r#"{"cmd":"split-add","kind":"domain","value":"custom-trade.com","target":"trade"}"#,
            &ctx,
        );
        call(r#"{"cmd":"split-add","kind":"domain","value":"bilibili.com"}"#, &ctx);
        call(
            r#"{"cmd":"split-add","kind":"process","value":"TDXW.exe","target":"trade"}"#,
            &ctx,
        );

        let v = call(r#"{"cmd":"split-reset-trade-domains"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["changed"], true, "{v}");
        assert!(
            v["splitMessage"].as_str().unwrap_or("").contains("已恢复默认交易网站（7 条）"),
            "{v}"
        );
        let ds = v["domains"].as_array().expect("domains 必须是数组");
        let values: Vec<&str> = ds.iter().filter_map(|d| d["value"].as_str()).collect();
        assert!(values.contains(&"tradingview.com"), "{v}");
        assert!(values.contains(&"ninjatrader.com"), "{v}");
        assert!(values.contains(&"bilibili.com"), "直连规则必须保留：{v}");
        assert!(!values.contains(&"custom-trade.com"), "自定义交易网站被默认名单替换：{v}");
        assert_eq!(v["processes"].as_array().map(|a| a.len()), Some(1), "程序名单不动：{v}");

        let saved = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .expect("配置要能重新读出来")
            .expect("配置必须存在");
        assert!(saved.split.domains.iter().any(|e| {
            e.value() == "tradingview.com" && e.target() == crate::config::SplitTarget::Trade
        }));
        assert!(saved.split.domains.iter().any(|e| {
            e.value() == "bilibili.com" && e.target() == crate::config::SplitTarget::Direct
        }));
        assert!(!saved.split.domains.iter().any(|e| e.value() == "custom-trade.com"));

        let v = call(r#"{"cmd":"split-reset-trade-domains"}"#, &ctx);
        assert_eq!(v["changed"], false, "再点一次不该说已恢复：{v}");
        assert!(
            v["splitMessage"].as_str().unwrap_or("").contains("已经是默认名单"),
            "{v}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_the_guard_fields_from_the_backend_not_from_a_constant() {
        // 契约（PRD §7）：`Guard`/`TradeProgramCount`/`GuardSummary`/`GuardEvidence`
        // 只能来自当次判定。这里断言的是「字段存在 + 取值与判定一致」，
        // 不是「一定等于某个状态」——没有证据时它必须是 Unknown。
        let root = tmp_root("status-guard");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], true, "{v}");
        let guard = v["Guard"].as_str().expect("Guard 必须是字符串");
        assert!(
            matches!(guard, "Protected" | "Unprotected" | "Unknown"),
            "三态之外不许出现别的值：{guard}"
        );
        // 空名单 → 0（不是 -1：配置读得到，就是一条都没有）
        assert_eq!(v["TradeProgramCount"], 0, "空名单的条数必须是 0：{v}");
        assert_ne!(guard, "Protected", "没有证据时不许说已保护");
        let summary = v["GuardSummary"].as_str().expect("GuardSummary 必须是字符串");
        assert!(!summary.is_empty(), "摘要不许是空串（PRD §7 明确禁止）");
        let ev = &v["GuardEvidence"];
        assert!(ev.is_object(), "GuardEvidence 必须是对象：{ev}");
        assert!(ev["Source"].is_string(), "来源必须标出来：{ev}");
        assert!(ev["Programs"].is_array(), "逐条明细必须在：{ev}");
        assert!(ev["Detection"].is_object());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_carries_the_evidence_age_and_source_fields() {
        // PRD §7 的五个新字段必须随三态一起出现在快照里（否则「已保护」没有时间锚）。
        let root = tmp_root("status-guard-age");
        write_cfg(&root, "L1");
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        for key in [
            "GuardVerifiedAtUtc",
            "GuardEvidenceAge",
            "GuardEvidenceSource",
            "GuardEvidenceBootId",
            "GuardConfigDigest",
        ] {
            assert!(v.get(key).is_some(), "缺字段：{key} → {v}");
        }
        // 没有证据时：来源是空串、时龄为空、时间戳为 null（**不许**给假值）
        assert_eq!(v["GuardEvidenceSource"], "", "{v}");
        assert_eq!(v["GuardEvidenceAge"], "", "{v}");
        assert_eq!(v["GuardVerifiedAtUtc"], serde_json::Value::Null, "{v}");
        assert_eq!(v["GuardEvidenceStale"], false, "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn changing_the_trade_list_invalidates_the_evidence() {
        // A16（名单维度）：名单变更属强制失效事件 → 旧证据必须立刻作废，
        // 状态从「已保护」回到「待核验」，而不是等到下一次刷新才发现摘要不符。
        let root = tmp_root("status-guard-invalidate");
        write_cfg(&root, "L1");
        let exe = root.join("fixture-trader.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let exe_text = exe.to_string_lossy().replace('\\', "\\\\");
        let ctx = ctx_with(None, &root);
        // 建一条交易名单
        let added = call(
            &format!(
                r#"{{"cmd":"split-add","kind":"process","value":"fixture-trader.exe","target":"trade","path":"{exe_text}"}}"#
            ),
            &ctx,
        );
        assert_eq!(added["ok"], true, "{added}");
        // 手工铺一份「两族都合格」的证据（本阶段没有写 WFP 的路径，只能造记录）
        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        let raw = crate::guard::trade_program_entries(&cfg);
        let refs: Vec<crate::guard::EntryRef<'_>> =
            raw.iter().map(|(n, p)| crate::guard::EntryRef::new(n, p.as_deref())).collect();
        let env = crate::guard::wfp_win::SystemIdentityEnv::new();
        let light = crate::guard::identity::resolve_all_light(&refs, &env);
        let good = crate::guard::FilterSlot {
            present: true,
            recognized: true,
            persistent: true,
            disabled: false,
            filter_id: Some(1),
        };
        let digest = crate::guard::config_digest_light(&light.entries, &light.unresolved, false);
        let ev = crate::guard::GuardEvidence {
            programs: vec![crate::guard::ProgramEvidence {
                name: "fixture-trader.exe".to_string(),
                path: exe.to_string_lossy().to_string(),
                app_id: vec![1, 0],
                ipv4: good,
                ipv6: good,
            }],
            detection: crate::guard::GuardDetection {
                provider_present: true,
                sublayer_present: true,
                infrastructure_verified: true,
                legacy_guard_present: false,
                bfe_ready: true,
            },
            read_error: None,
            verified_at_epoch: Some(crate::guard::now_epoch()),
            verified_at_tick_ms: Some(crate::guard::tick_ms()),
            source: crate::guard::GuardSource::ElevatedVerify,
            config_digest: digest,
            boot_id: crate::guard::boot_id(),
            extra_owned_filters: 0,
            legacy_running_at_verify: false,
            store_kind: crate::guard::StoreKind::IsolatedFile.as_str().to_string(),
        };
        let rec = crate::guard::GuardRecord::from_evidence(
            &ev,
            "ipc-test",
            std::process::id(),
            true,
            1,
        );
        crate::guard::write_evidence_record(&root, &rec).unwrap();
        if crate::guard::platform_supported() {
            let before = call(r#"{"cmd":"status"}"#, &ctx);
            assert_eq!(before["Guard"], "Protected", "{before}");
            assert_eq!(before["GuardEvidenceAge"], "刚刚核验", "{before}");
            // 再动一次名单 → 证据作废。第二条也给绝对路径：这条测试盯的是
            // 「名单变化导致证据失效」，不要被「路径未解析」抢走原因。
            let second = root.join("fixture-second.exe");
            std::fs::write(&second, b"MZ").unwrap();
            let second_text = second.to_string_lossy().replace('\\', "\\\\");
            let more = call(
                &format!(
                    r#"{{"cmd":"split-add","kind":"process","value":"fixture-second.exe","target":"trade","path":"{second_text}"}}"#
                ),
                &ctx,
            );
            assert_eq!(more["ok"], true, "{more}");
            let after = call(r#"{"cmd":"status"}"#, &ctx);
            assert_eq!(after["Guard"], "Unknown", "名单变了必须等重新核验（A16）：{after}");
            assert!(
                root.join("guard").join("evidence.invalid.json").exists(),
                "作废的证据要留审计副本"
            );
            // 反面对照：动一条**直连**条目不该作废交易证据（它不在保护口径里）。
            crate::guard::write_evidence_record(&root, &rec).unwrap();
            let before_digest = crate::guard::read_evidence_record(&root).unwrap().config_digest;
            let direct = call(r#"{"cmd":"split-add","kind":"process","value":"curl.exe"}"#, &ctx);
            assert_eq!(direct["ok"], true, "{direct}");
            let after = crate::guard::read_evidence_record(&root).expect("直连改动不该作废证据");
            assert_eq!(after.config_digest, before_digest, "证据内容一个字都不该动");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_with_unreadable_config_says_minus_one_not_zero() {
        // `-1` 只表示「读不到名单条数」，界面对它必须说「暂时无法核实」而不是「尚未添加」。
        let root = tmp_root("status-guard-nocfg");
        // 不写配置：`read_cfg` 读不到 → cfg=None
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["TradeProgramCount"], -1, "{v}");
        assert_eq!(v["Guard"], "Unknown", "{v}");
        assert!(!v["GuardSummary"].as_str().unwrap_or_default().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_running_downgrades_the_guard_state() {
        // 旧版在跑时我们不碰任何 WFP 对象，也就不可能给出可信结论。
        let root = tmp_root("status-guard-legacy");
        write_cfg(&root, "L1");
        let mut ctx = ctx_with(None, &root);
        ctx.legacy_running = true;
        let v = call(r#"{"cmd":"status"}"#, &ctx);
        if crate::guard::platform_supported() {
            assert_eq!(v["Guard"], "Unknown", "{v}");
            assert_eq!(v["GuardEvidence"]["Reason"], "LegacyConflict", "{v}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_payload_carries_path_and_a_backend_verdict_per_entry() {
        // 名单页要能显示「这一条被保护了吗 / 为什么不参与」，答案只能来自后端判定。
        let root = tmp_root("split-path");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        // 老条目：只有名字，没有路径 → 明确「不参与保护」并且给原因
        call(r#"{"cmd":"split-add","kind":"process","value":"TDXW.exe","target":"trade"}"#, &ctx);
        let v = call(r#"{"cmd":"split"}"#, &ctx);
        let ps = v["processes"].as_array().expect("processes 必须是数组");
        let entry = ps.iter().find(|e| e["value"] == "TDXW.exe").expect("条目必须在");
        assert_eq!(entry["path"], serde_json::Value::Null, "老条目没有路径");
        assert_eq!(entry["guard"]["Participated"], false, "{entry}");
        assert_eq!(entry["guard"]["Protected"], false, "{entry}");
        assert!(
            entry["guard"]["Reason"].as_str().unwrap_or_default().contains("程序位置"),
            "必须给可读原因：{entry}"
        );
        // 直连条目永远不参与交易保护（P0-1 的反面）
        call(r#"{"cmd":"split-add","kind":"process","value":"curl.exe"}"#, &ctx);
        let v = call(r#"{"cmd":"split"}"#, &ctx);
        let direct = v["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["value"] == "curl.exe")
            .cloned()
            .expect("直连条目必须在");
        assert_eq!(direct["guard"]["Participated"], false);
        assert_eq!(direct["guard"]["Protected"], false);
        assert!(direct["guard"]["Reason"].as_str().unwrap_or_default().contains("不在交易名单"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_add_stores_an_absolute_path_only_for_trade_processes() {
        let root = tmp_root("split-path-add");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let exe = root.join("fixture-trader.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let exe_text = exe.to_string_lossy().replace('\\', "\\\\");
        let cmd = format!(
            r#"{{"cmd":"split-add","kind":"process","value":"fixture-trader.exe","target":"trade","path":"{exe_text}"}}"#
        );
        let v = call(&cmd, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let ps = v["processes"].as_array().unwrap();
        let entry = ps
            .iter()
            .find(|e| e["value"] == "fixture-trader.exe")
            .expect("条目必须在");
        assert_eq!(entry["path"].as_str(), Some(exe.to_string_lossy().as_ref()), "{v}");
        // 落盘也一样（回包不是唯一事实）
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        let saved = disk
            .split
            .processes
            .iter()
            .find(|e| e.value() == "fixture-trader.exe")
            .expect("必须落盘");
        assert_eq!(saved.path(), Some(exe.to_string_lossy().as_ref()));

        // 直连条目不存路径（那个落点不需要程序身份）
        let direct = format!(
            r#"{{"cmd":"split-add","kind":"process","value":"curl.exe","path":"{exe_text}"}}"#
        );
        let v = call(&direct, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        let saved = disk.split.processes.iter().find(|e| e.value() == "curl.exe").unwrap();
        assert_eq!(saved.path(), None, "直连条目不该被塞一个路径");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_add_refuses_a_relative_or_non_exe_path() {
        let root = tmp_root("split-path-bad");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let rel = call(
            r#"{"cmd":"split-add","kind":"process","value":"a.exe","target":"trade","path":"a.exe"}"#,
            &ctx,
        );
        assert_eq!(rel["ok"], false, "相对路径必须拒绝：{rel}");
        assert!(rel["error"].as_str().unwrap_or_default().contains("绝对路径"), "{rel}");
        let dll = call(
            r#"{"cmd":"split-add","kind":"process","value":"b.exe","target":"trade","path":"C:\\x\\b.dll"}"#,
            &ctx,
        );
        assert_eq!(dll["ok"], false, "非 exe 必须拒绝：{dll}");
        // 被拒绝的条目一条都不该落盘
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        assert!(disk.split.processes.is_empty(), "拒绝时不许写任何东西");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_add_replies_with_the_new_list_and_persists() {
        let root = tmp_root("split-persist");
        write_cfg(&root, "L1");
        let v = call(
            r#"{"cmd":"split-add","kind":"process","value":"TDXW.exe","target":"trade"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["changed"], true);
        assert_eq!(v["splitMessage"], "已加入：TDXW.exe → 交易出口", "{v}");
        let ps = v["processes"].as_array().expect("回包必须带 processes");
        assert!(ps.iter().any(|e| e["value"] == "TDXW.exe"), "{v}");
        // 回包、磁盘、再查一次：三处必须是同一套事实
        let disk = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .ok()
            .flatten()
            .expect("磁盘配置必须还在");
        assert!(disk.split.processes.iter().any(|e| e.value() == "TDXW.exe"), "必须落盘");
        let again = call(r#"{"cmd":"split"}"#, &ctx_with(None, &root));
        assert_eq!(again["processes"], v["processes"], "再查必须与回包一致");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_add_duplicate_is_ok_and_does_not_duplicate() {
        let root = tmp_root("split-dup");
        write_cfg(&root, "L1");
        let ctx = ctx_with(None, &root);
        let first = call(r#"{"cmd":"split-add","kind":"process","value":"a.exe"}"#, &ctx);
        assert_eq!(first["changed"], true);
        // 大小写不同也算重复：去重在归一层做，不在界面做
        let dup = call(r#"{"cmd":"split-add","kind":"process","value":"A.EXE"}"#, &ctx);
        assert_eq!(dup["ok"], true, "重复添加是合法操作，不算错误：{dup}");
        assert_eq!(dup["changed"], false, "但必须报告「什么都没变」：{dup}");
        let ps = dup["processes"].as_array().expect("回包必须带 processes");
        assert_eq!(ps.len(), 1, "不能出现重复条目：{dup}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_edit_is_refused_while_connected_without_side_effects() {
        let root = tmp_root("split-busy");
        write_cfg(&root, "L1");
        std::fs::write(root.join("proxy-journal.json"), b"{}").unwrap();
        let before = config_bytes(&root);
        for cmd in [
            r#"{"cmd":"split-add","kind":"process","value":"a.exe"}"#,
            r#"{"cmd":"split-remove","kind":"process","value":"a.exe"}"#,
        ] {
            let v = call(cmd, &ctx_with(None, &root));
            assert_eq!(v["ok"], false, "{cmd} 连接中必须被拒：{v}");
            assert!(v["error"].as_str().unwrap_or_default().contains("请先断开"), "{v}");
        }
        assert_eq!(config_bytes(&root), before, "拒绝必须零副作用");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_remove_syncs_the_line_engine_config() {
        let root = tmp_root("split-sync");
        write_cfg(&root, "L1");
        // 造一份最小引擎配置放在线路位置：add 之后这份文件必须长出 process_name 规则。
        let line_path = root.join("lines").join("L1.json");
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        std::fs::write(
            &line_path,
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"daily-exit"}}"#,
        )
        .unwrap();
        let v = call(
            r#"{"cmd":"split-add","kind":"process","value":"curl.exe"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], true, "{v}");
        let text = std::fs::read_to_string(&line_path).expect("线路引擎配置必须还在");
        assert!(text.contains("process_name"), "规则必须同步进引擎配置：{text}");
        assert!(text.contains("curl.exe"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exit_set_with_an_unknown_member_is_refused_without_side_effects() {
        let root = tmp_root("exit-bad");
        write_cfg(&root, "L1");
        // 线路引擎配置：两个选择器，成员只有 hk / direct
        let line_path = root.join("lines").join("L1.json");
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        std::fs::write(
            &line_path,
            r#"{"outbounds":[
                {"type":"direct","tag":"direct"},
                {"type":"vless","tag":"hk","server":"198.51.100.10","server_port":443},
                {"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"},
                {"type":"selector","tag":"daily-exit","outbounds":["direct","hk"],"default":"direct"}],
                "route":{"rules":[],"final":"daily-exit"}}"#,
        )
        .unwrap();
        let before_cfg = config_bytes(&root);
        let before_line = std::fs::read(&line_path).unwrap();

        // 非法成员：ok:false，且 config 与线路引擎配置**一个字节都不变**
        let v = call(
            r#"{"cmd":"exit-set","which":"trade","member":"__no_such_member__"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(v["ok"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or_default().contains("不在交易出口的可选范围"),
            "{v}"
        );
        assert_eq!(config_bytes(&root), before_cfg, "非法成员必须零副作用：config 不许变");
        assert_eq!(std::fs::read(&line_path).unwrap(), before_line, "线路引擎配置也不许变");

        // 合法成员：写入生效、回包可回读
        let ok = call(
            r#"{"cmd":"exit-set","which":"daily","member":"hk"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(ok["exitDaily"], "hk", "回包要带新值：{ok}");
        assert_eq!(ok["exitDailyMembers"][0]["value"], "direct", "提交值仍是内部 value：{ok}");
        assert_eq!(ok["exitDailyMembers"][0]["label"], "本地直连", "显示值必须是人话：{ok}");
        assert_eq!(ok["exitDailyMembers"][1]["value"], "hk", "{ok}");
        assert!(ok["exitDailyMembers"][1]["label"].as_str().unwrap_or_default().starts_with("交易线路（"), "{ok}");
        let line_after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&line_path).unwrap()).unwrap();
        assert_eq!(line_after["outbounds"][3]["default"], "hk", "{line_after}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exit_projection_names_provider_from_registry_and_never_uses_slot_as_label() {
        let root = tmp_root("exit-human-labels");
        write_cfg(&root, "L1");
        let line_path = root.join("lines").join("L1.json");
        std::fs::create_dir_all(line_path.parent().unwrap()).unwrap();
        std::fs::write(
            &line_path,
            r#"{"outbounds":[
                {"type":"direct","tag":"direct"},
                {"type":"vless","tag":"hk","server":"198.51.100.10","server_port":443},
                {"type":"socks","tag":"provider","server":"127.0.0.1","server_port":17895},
                {"type":"socks","tag":"provider-trade","server":"127.0.0.1","server_port":17896},
                {"type":"selector","tag":"trade-exit","outbounds":["direct","hk","provider-trade"],"default":"provider-trade"},
                {"type":"selector","tag":"daily-exit","outbounds":["direct","provider"],"default":"direct"}],
                "route":{"rules":[],"final":"daily-exit"}}"#,
        )
        .unwrap();
        crate::provider::save(
            &root,
            &crate::provider::ProviderRegistry {
                version: 1,
                providers: vec![crate::provider::Provider {
                    id: "p1".into(),
                    slot: 1,
                    name: "Clash 测试".into(),
                    kind: "clashverge".into(),
                    directory: "C:\\fixtures\\clash".into(),
                    daily_port: 17895,
                    trade_port: Some(17896),
                    bootstrap_domains: vec![],
                    added_at: String::new(),
                }],
            },
        )
        .unwrap();
        let v = call(r#"{"cmd":"status"}"#, &ctx_with(None, &root));
        assert_eq!(v["exitDailyMembers"][0], serde_json::json!({"value":"direct","label":"本地直连"}), "{v}");
        assert_eq!(
            v["exitDailyMembers"][1]["label"],
            "代理软件（Clash 测试 127.0.0.1:17895）",
            "{v}"
        );
        assert_eq!(
            v["exitTradeMembers"][2]["label"],
            "代理软件（Clash 测试 127.0.0.1:17896）",
            "{v}"
        );
        assert!(v["exitTradeMembers"][1]["label"].as_str().unwrap_or_default().starts_with("交易线路（"), "{v}");
        for member in v["exitTradeMembers"].as_array().unwrap() {
            assert!(!member["label"].as_str().unwrap_or_default().is_empty(), "label 必须非空：{v}");
            assert_ne!(member["label"], member["value"], "label 不能回退成内部标识：{v}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---------- 界面长操作记录：连接 / 断开 / 诊断的待核对与结论 ----------

    fn operation_records(v: &serde_json::Value) -> &Vec<serde_json::Value> {
        v["operations"]["Records"]
            .as_array()
            .expect("Records 必须是数组")
    }

    /// 摆一条「上次进程退出了」的现场：先 `begin`（Pending），再走启动恢复。
    fn interrupted_operation(root: &PathBuf, kind: &str) -> crate::oprecord::Record {
        let record = crate::oprecord::begin(root, kind, "ui").expect("开始记录必须落盘");
        crate::oprecord::recover_pending(root).expect("启动恢复必须成功");
        record
    }

    #[test]
    fn operation_list_is_read_only_and_distinguishes_empty_from_unreadable() {
        let root = tmp_root("op-list");
        let ctx = ctx_with(None, &root);
        let empty = call(r#"{"cmd":"operation-list"}"#, &ctx);
        assert_eq!(empty["ok"], true, "{empty}");
        assert_eq!(empty["operations"]["ReadError"], "");
        assert!(operation_records(&empty).is_empty());
        assert!(
            !root.join("logs").join("ui-operations.json").exists(),
            "只读命令不许创建记录文件"
        );

        let record = interrupted_operation(&root, crate::oprecord::CONNECT);
        let listed = call(r#"{"cmd":"operation-list"}"#, &ctx);
        assert_eq!(listed["ok"], true, "{listed}");
        let records = operation_records(&listed);
        assert_eq!(records.len(), 1, "{listed}");
        assert_eq!(records[0]["Id"], record.id);
        assert_eq!(records[0]["Kind"], "Connect");
        assert_eq!(records[0]["Phase"], "NeedsReview");
        assert_eq!(records[0]["Origin"], "ui");
        assert!(
            !records[0]["StartedAtUtc"].as_str().unwrap_or("").is_empty(),
            "核对需要开始时间：{listed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_broken_operation_store_is_reported_not_treated_as_empty() {
        let root = tmp_root("op-list-broken");
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("logs").join("ui-operations.json"), b"{not json").unwrap();
        let v = call(r#"{"cmd":"operation-list"}"#, &ctx_with(None, &root));
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["errorCode"], "operation-record");
        assert!(
            !v["operations"]["ReadError"].as_str().unwrap_or_default().is_empty(),
            "「读不出来」必须和「没有记录」分开：{v}"
        );
        assert!(operation_records(&v).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_interrupted_connect_reads_the_live_state_and_never_reconnects() {
        let root = tmp_root("op-review-connect");
        let ctx = ctx_with(None, &root);
        let record = interrupted_operation(&root, crate::oprecord::CONNECT);

        // 没有连接、也没有残留凭据：如实说「没生效」，可以重新连接。
        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["ok"], true, "{reviewed}");
        let result = &reviewed["operationReview"];
        assert_eq!(result["Phase"], "Failed", "{reviewed}");
        assert_eq!(result["Code"], "ReviewedNotApplied");
        assert_eq!(result["NeedsReview"], false);
        assert!(
            result["Message"].as_str().unwrap_or("").contains("可以重新连接"),
            "{reviewed}"
        );
        assert!(!root.join("proxy-journal.json").exists(), "核对绝不写还原凭据");
        assert!(!root.join("runtime-engine.json").exists(), "核对绝不启动引擎");

        // 结论已定：再核对必须被拒，且不覆盖原结论。
        let again = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["errorCode"], "state");
        let stored = crate::oprecord::load(&root).unwrap();
        assert_eq!(stored[0].phase, crate::oprecord::FAILED);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_interrupted_connect_with_proxy_evidence_stays_pending_until_the_proxy_is_restored() {
        let root = tmp_root("op-review-connect-journal");
        let ctx = ctx_with(None, &root);
        let record = interrupted_operation(&root, crate::oprecord::CONNECT);
        crate::proxy::write_journal(
            &root.join("proxy-journal.json"),
            &crate::proxy::ProxyJournal {
                schema: 1,
                endpoint: "127.0.0.1:7890".to_string(),
                saved_at_secs: 0.0,
                saved: crate::proxy::SavedProxy {
                    enable: false,
                    server: None,
                    bypass: None,
                },
            },
        )
        .unwrap();

        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["ok"], true, "{reviewed}");
        let result = &reviewed["operationReview"];
        assert_eq!(result["Phase"], "NeedsReview", "代理改动还在，不能假装核对完：{reviewed}");
        assert_eq!(result["NeedsReview"], true);
        assert!(
            result["Message"].as_str().unwrap_or("").contains("还原系统代理"),
            "必须指出出路：{reviewed}"
        );
        assert_eq!(
            crate::oprecord::load(&root).unwrap()[0].phase,
            crate::oprecord::NEEDS_REVIEW,
            "核不了就不能改记录"
        );

        // 维护区还原了代理（凭据被清掉）后再核对：这次可以说「没生效」了。
        std::fs::remove_file(root.join("proxy-journal.json")).unwrap();
        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["operationReview"]["Phase"], "Failed", "{reviewed}");
        assert_eq!(reviewed["operationReview"]["Code"], "ReviewedNotApplied");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_interrupted_connect_that_is_now_running_is_confirmed_without_touching_anything() {
        let root = tmp_root("op-review-connect-live");
        let ctx = ctx_with(None, &root);
        let record = interrupted_operation(&root, crate::oprecord::CONNECT);
        connected_runtime(&root, 1);
        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["ok"], true, "{reviewed}");
        let result = &reviewed["operationReview"];
        assert_eq!(result["Phase"], "Succeeded", "{reviewed}");
        assert_eq!(result["Code"], "ReviewedApplied");
        assert!(
            result["Message"].as_str().unwrap_or("").contains("正在运行"),
            "{reviewed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_interrupted_disconnect_uses_the_same_two_facts() {
        let root = tmp_root("op-review-disconnect");
        let ctx = ctx_with(None, &root);

        // 引擎还在跑：断开没有完成。
        let record = interrupted_operation(&root, crate::oprecord::DISCONNECT);
        connected_runtime(&root, 1);
        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["operationReview"]["Phase"], "Failed", "{reviewed}");
        assert_eq!(reviewed["operationReview"]["Code"], "ReviewedNotApplied");
        assert!(
            reviewed["operationReview"]["Message"]
                .as_str()
                .unwrap_or("")
                .contains("再断开一次"),
            "{reviewed}"
        );

        // 断开完成：没有引擎、没有凭据。
        std::fs::remove_file(root.join("runtime-engine.json")).unwrap();
        let record = interrupted_operation(&root, crate::oprecord::DISCONNECT);
        let reviewed = call(
            &format!(r#"{{"cmd":"operation-review","id":"{}"}}"#, record.id),
            &ctx,
        );
        assert_eq!(reviewed["operationReview"]["Phase"], "Succeeded", "{reviewed}");
        assert_eq!(reviewed["operationReview"]["Code"], "ReviewedApplied");
        assert!(
            reviewed["operationReview"]["Message"]
                .as_str()
                .unwrap_or("")
                .contains("已经完成"),
            "{reviewed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reviewing_an_unknown_or_broken_operation_is_refused_by_code() {
        let root = tmp_root("op-review-bad");
        let ctx = ctx_with(None, &root);
        let empty = call(r#"{"cmd":"operation-review","id":""}"#, &ctx);
        assert_eq!(empty["ok"], false, "{empty}");
        assert_eq!(empty["errorCode"], "usage");
        let missing = call(r#"{"cmd":"operation-review","id":"nope"}"#, &ctx);
        assert_eq!(missing["ok"], false, "{missing}");
        assert_eq!(missing["errorCode"], "missing");
        // 记录文件坏掉：拒绝且指向记录，不是「不需要核对」。
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("logs").join("ui-operations.json"), b"{broken").unwrap();
        let broken = call(r#"{"cmd":"operation-review","id":"nope"}"#, &ctx);
        assert_eq!(broken["ok"], false, "{broken}");
        assert_eq!(broken["errorCode"], "record");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn auto_route_reuses_fresh_evidence_without_starting_an_engine() {
        let root = tmp_root("auto-route-evidence");
        write_cfg(&root, "L1");
        let fingerprint = crate::autoroute::network_fingerprint();
        if fingerprint.is_empty() {
            eprintln!("跳过：这台机器拿不到网络指纹");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        let now = crate::model::now_epoch_secs_u64() as i64;
        let evidence = serde_json::json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.AutoRoute",
            "Lines": {"L1": {
                "NetworkFingerprint": fingerprint,
                "CheckedAtUnix": now,
                "ExpiresAtUnix": now + 1_800,
                "Winner": "tcp",
                "Candidates": [
                    {"Transport":"udp","Reachable":true,"LatencyMs":80,"Error":"","CheckedAtUnix":now},
                    {"Transport":"tcp","Reachable":true,"LatencyMs":40,"Error":"","CheckedAtUnix":now}
                ]
            }}
        });
        std::fs::write(root.join("autoroute.json"), evidence.to_string()).unwrap();
        let ctx = ctx_with(None, &root);
        let listed = call(r#"{"cmd":"auto-route-list"}"#, &ctx);
        assert_eq!(listed["ok"], true, "{listed}");
        assert_eq!(listed["autoRoutes"]["Lines"]["L1"]["Winner"], "tcp", "{listed}");
        let v = call(r#"{"cmd":"auto-route","line":"L1"}"#, &ctx);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["autoRoute"]["Probed"], false, "新鲜证据不该再起引擎：{v}");
        assert_eq!(v["autoRoute"]["Transport"], "tcp", "{v}");
        assert_eq!(v["autoRoute"]["Source"], "Evidence", "{v}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn retrying_a_failed_operation_runs_it_and_writes_a_new_record() {
        let root = tmp_root("op-retry");
        let ctx = ctx_with(None, &root);
        let failed = crate::oprecord::begin(&root, crate::oprecord::CONNECT, "ui").unwrap();
        crate::oprecord::finish(
            &root,
            &failed.id,
            crate::oprecord::FAILED,
            "引擎没起来",
            "EngineStartFailed",
        )
        .unwrap();
        let reply = call(
            &format!(r#"{{"cmd":"operation-retry","id":"{}"}}"#, failed.id),
            &ctx,
        );
        let record_id = reply["operationRetry"]["RecordId"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(!record_id.is_empty(), "{reply}");
        assert_ne!(record_id, failed.id, "重试必须写一条新记录：{reply}");
        // 连接没有配置/引擎，必然失败；但记录必须有结论，不能停在 Pending。
        let records = crate::oprecord::load(&root).unwrap();
        let connects: Vec<_> = records
            .iter()
            .filter(|record| record.kind == crate::oprecord::CONNECT)
            .collect();
        assert_eq!(connects.len(), 1, "同类的已结束记录只留最新一条：{records:?}");
        assert_eq!(connects[0].id, record_id);
        assert!(
            matches!(
                connects[0].phase.as_str(),
                crate::oprecord::FAILED | crate::oprecord::SUCCEEDED
            ),
            "{records:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_that_still_needs_review_is_not_retried() {
        let root = tmp_root("op-retry-review");
        let ctx = ctx_with(None, &root);
        let pending = crate::oprecord::begin(&root, crate::oprecord::CONNECT, "ui").unwrap();
        crate::oprecord::recover_pending(&root).unwrap();
        let reply = call(
            &format!(r#"{{"cmd":"operation-retry","id":"{}"}}"#, pending.id),
            &ctx,
        );
        assert_eq!(reply["ok"], false, "{reply}");
        assert_eq!(reply["errorCode"], "state", "{reply}");
        assert!(
            reply["error"].as_str().unwrap_or("").contains("核对"),
            "{reply}"
        );
        let records = crate::oprecord::load(&root).unwrap();
        assert_eq!(records.len(), 1, "被拒绝的重试不许写新记录：{records:?}");
        assert_eq!(records[0].phase, crate::oprecord::NEEDS_REVIEW);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_reviewed_diagnose_record_is_closed_as_read_only_interrupted() {
        let root = tmp_root("op-review-diagnose");
        // 启动恢复会把中断的诊断直接标成 Failed（只读，不进待核对）。这里手工摆一条
        // 待核对的诊断，验证防御分支给出的仍是「只读、可重跑」，而不是要求用户去核对
        // 一个根本没有后果的操作。
        crate::oprecord::save(
            &root,
            &[crate::oprecord::Record {
                id: "diag-review".to_string(),
                kind: crate::oprecord::DIAGNOSE.to_string(),
                phase: crate::oprecord::NEEDS_REVIEW.to_string(),
                message: "中断".to_string(),
                code: "Interrupted".to_string(),
                started_at_utc: "2026-01-01T00:00:00Z".to_string(),
                started_at_unix: 0,
                finished_at_utc: String::new(),
                origin: "ui".to_string(),
            }],
        )
        .unwrap();
        let reviewed = call(
            r#"{"cmd":"operation-review","id":"diag-review"}"#,
            &ctx_with(None, &root),
        );
        assert_eq!(reviewed["ok"], true, "{reviewed}");
        assert_eq!(reviewed["operationReview"]["Phase"], "Failed");
        assert_eq!(reviewed["operationReview"]["Code"], "InterruptedReadOnly");
        assert!(
            reviewed["operationReview"]["Message"]
                .as_str()
                .unwrap_or("")
                .contains("只读"),
            "{reviewed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 任务级凭据（勾了「中断后继续」）：投递时写一份 DPAPI 信封，
    /// 取消之后必须消失。这是界面上的承诺（「任务完成或放弃时清除」）。
    #[test]
    fn a_task_credential_is_written_on_start_and_removed_on_cancel() {
        let root = tmp_root("task-cred");
        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());

        let started = call(
            r#"{"cmd":"deployment-start","spec":"root@203.0.113.10","fingerprint":"SHA256:AAAA","password":"s3cret","remember":false,"rememberTask":true}"#,
            &ctx,
        );
        assert_eq!(started["ok"], serde_json::json!(true), "{started}");
        let run_id = started["deployment"]["RunId"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(!run_id.is_empty(), "{started}");

        let binding = crate::deploycred::binding_of(&run_id, "203.0.113.10", 22, "root");
        assert_eq!(
            crate::deploycred::load(&root, &run_id, &binding)
                .map(|stored| stored.password_text().to_string())
                .as_deref(),
            Some("s3cret"),
            "勾了「中断后继续」就该有一份能读回来的任务凭据"
        );
        assert!(
            crate::deploycred::file_of(&root, &run_id).unwrap().exists(),
            "文件必须落在 deployments\\credentials 下"
        );

        // 取消 = 任务结束：凭据必须被删掉，不能等 24 小时。
        let cancelled = call(
            &format!(r#"{{"cmd":"deployment-cancel","runId":"{run_id}"}}"#),
            &ctx,
        );
        assert_eq!(cancelled["ok"], serde_json::json!(true), "{cancelled}");
        assert!(
            crate::deploycred::load(&root, &run_id, &binding).is_none(),
            "取消之后不许还留着一份能解开的密码"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 不勾「中断后继续」：磁盘上不许出现任何凭据文件（连目录都不建）。
    #[test]
    fn without_the_task_checkbox_no_credential_file_is_written() {
        let root = tmp_root("no-task-cred");
        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());

        let started = call(
            r#"{"cmd":"deployment-start","spec":"root@203.0.113.10","fingerprint":"SHA256:AAAA","password":"s3cret","remember":false,"rememberTask":false}"#,
            &ctx,
        );
        assert_eq!(started["ok"], serde_json::json!(true), "{started}");
        let run_id = started["deployment"]["RunId"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let binding = crate::deploycred::binding_of(&run_id, "203.0.113.10", 22, "root");
        assert!(crate::deploycred::load(&root, &run_id, &binding).is_none());
        assert!(
            !crate::deploycred::file_of(&root, &run_id).unwrap().exists(),
            "没勾的选项不许在磁盘上留下东西"
        );
        // 记录上也要如实写着「不存」——引擎按它决定要不要写信封。
        let stored = DeploymentStore::open(&root).load(&run_id).unwrap();
        assert!(!stored.remember_task, "{stored:?}");
        assert!(!stored.remember_saved, "长期这一档也没勾");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 没密码、也没有任何保存过的资料：**一个字都不落盘**，当场说清怎么办。
    #[test]
    fn a_start_without_any_credential_is_refused_before_anything_is_written() {        let root = tmp_root("no-cred");
        let engine = engine_over(&root);
        let mut ctx = ctx_with(None, &root);
        ctx.engine = Some(engine.handle());

        let refused = call(
            r#"{"cmd":"deployment-start","spec":"root@203.0.113.10","fingerprint":"SHA256:AAAA"}"#,
            &ctx,
        );
        assert_eq!(refused["ok"], serde_json::json!(false), "{refused}");
        assert_eq!(refused["errorCode"], serde_json::json!("usage"), "{refused}");
        assert!(
            refused["error"]
                .as_str()
                .unwrap_or("")
                .contains("登录密码"),
            "{refused}"
        );
        assert!(record_files(&root).is_empty(), "拒绝时不许留下任务记录");
        let _ = std::fs::remove_dir_all(&root);
    }
}