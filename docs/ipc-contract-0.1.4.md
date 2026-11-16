# SpiderVPN 0.1.4 → 后续版本 IPC / CLI / 记录契约

> **术语**：本文中的「旧版」指本项目的上一代实现（PowerShell 版，未随本仓库发布）。保留这些对照是为了说明某条规则为什么长这样；不了解旧版不影响阅读——每处结论都已在本版重新表述。

> 状态：S1 P0、S2 与 S3 已实施部分见 §3、§4、§5、§6 的“已落地”标记。**已落地**：`pick-file`、`inspect-import`、`linesRead` / `linesReadError`、`checkAtUtc` / `exitEvidence` / `exitObservedIp` / `isAdmin`、`operations.jsonl` v2 与记录页来源筛选、T-08 退出码、T-09 长任务调度与超预算出路、T-10 结构化诊断与复制、T-11 维护状态与执行还原、T-12 前端门控、T-13 `measure-latency` 与 `latencyMs` / `measuredAtUtc`、T-14 `use-compatible` 与 `compatibleAction` / `compatibleResult` / `transportActual`、T-15 `pick-exe`、`splitMessage`、三组分流与出口成员 `{value,label}` 人话投影、T-16 自启 × TUN 组合结论与权限三态、T-17 记录复制/导出与线路行内改名/设为默认、T-18 服务商三态结论与备用线路 TCP 建连检查、**A2/A3 部署中心（§4.16：十条 `deployment-*` 短命令、记录字段、8 态状态机、读取三态、保留裁剪、秘密边界、启动恢复、退出守卫；r69 加 `deployment-draft-save` 与草稿的保存/恢复/丢弃 §4.16.10）**。其余命令仍是目标契约，未实现，不得据此宣称功能已经存在。
>
> 基线：`src/ipc.rs`、`src/ui.rs`、`src/main.rs`、`src/events.rs`；实施计划 T-01…T-20。原始退出码证据：`reports-tmp/tcrs-audit/s0-exit-code-matrix-0.1.4.json`。

## 1. 传输与兼容原则

1. 页面 → 宿主：`window.ipc.postMessage(JSON.stringify(request))`，`request.cmd` 为必填字符串。
2. 宿主 → 页面：`window.__tcApply(state)`；除特别说明外，命令回包是**完整状态投影**，不是只含增量的另一套数据结构。
3. `ok` 只表示本次 IPC 命令是否成功，不代表通道已连接；连接状态仍读 `state/title/action/enabled`。
4. 新字段一律可选。旧宿主缺字段时，前端必须按本文“缺省/降级”列处理，禁止把缺字段猜成成功、已核验或空列表。
5. 新前端必须能读旧 `operations.jsonl`；新记录字段缺失不丢行。配置 `schema:2` 的新增字段只增不改，需要改结构时先写迁移和回退测试。
6. 每个回包只完成它自己的动作。无关 `status` 回包不得清除导入提示、冲突层、断开确认层或进行中状态。
7. 所有路径都只用于本机文件操作；文件选择、拖放、导出不得发起网络请求。
8. 所有自动化写入继续使用 `SPIDERVPN_ROOT`；涉及代理或自启时还必须设置 `SPIDERVPN_PROXY_KEY` / `SPIDERVPN_RUN_KEY` 为临时键。
9. **入站消息先过门控，再谈业务**（r56）：页面发来的每条 JSON 先过四道闸——长度、`Sequence` 单调、对话框 `Id`、表单 `Generation`。被丢弃的消息**不发命令、不改业务状态**，但必须推进 `ack`（页面按 `State.Ack >= Sequence` 判等待，静默丢一条会让按钮一直转圈）。

### 1.1 入站消息门控（**r56 落地**）

对齐 旧版的 `InvokeTCWebMessage`（`ui/WebShell.ps1:927-945`）。改动前本版解析完 JSON 直接分发，重放一条消息就再执行一次。

| 闸 | 判据 | 后果 |
|---|---|---|
| 总长度 | `> 1 MiB` | 不解析（解析本身就要几十毫秒） |
| 非 `form` 长度 | `> 4096` 字节 | 丢弃 |
| `pairOnline` / `invite` 长度 | `> 64 KiB` | 丢弃（r67 放宽；见下） |
| `Sequence` | `1..=2147483647` 的整数，且 `> 上次通过的序号` | 丢弃；通过则更新水位线 |
| 对话框 `Id` | `confirmDialog` / `cancelDialog` 的 `Id` 必须等于当前 `Dialog.Id` | 丢弃——过期事件不许关掉现在这个框 |
| 表单 `Generation` | `form` 且 `Event != "click"` 时必须等于 `Form.Generation` | 丢弃 |

三条**放宽**，都是故意的：

- **`Sequence` / `Id` / `Generation` 缺失 → 放行**：真实前端每条都带（`web/app.js` 的 `post` 与 `form` 分支），缺了只可能是内部调用或测试夹具；按「缺就拒」处理会让内部调用莫名其妙失效。
- **表单点击不校验 `Generation`**：状态推送有 2 秒节流，用户连点两下时页面还拿着上一代——严格挡就是「点了没反应」。字段编辑（`change`）才严格挡，因为落到错的一代会改错值。

`ready` 是唯一会**重置水位线**的消息：页面重载后 `sequence` 从 1 重新开始，不归零会把整页消息全部挡死（页面失去响应）。这一条比旧版多做一步——那边是 WPF 内嵌页、几乎不重载，本版 WebView2 会自己恢复。

**r67 放宽 `pairOnline` / `invite` 的理由**：离线交接的加密授权 JWE 实测约 4 KB（4000+ 字符），连同 JSON 包装刚越过 4 KiB。被这道闸丢掉时**页面不报错**——点击被静默吞掉，卡片停在原地；真机首轮就是卡在这里，单测的合成授权太短所以全绿。其余消息仍是 4 KiB，64 KiB 只是给这两种已知携带交接资料的消息一个明确硬上限。

`Sequence` 与 `Ack` 是两件事：`Ack` 是宿主的应答计数（每次 `bump()` 加一），`Sequence` 是来包序号。旧版用同一个 `$script:WebAck` 兼任两者，是因为它的 ack 只在收消息时变；本版 `bump()` 每帧都涨，混用会把页面消息全部挡掉。

## 2. 错误与退出码

### 2.1 IPC 错误形状

保留现有 `error: string`，新增可选 `errorCode`，不把 `error` 改成对象：

```json
{
  "ok": false,
  "error": "人话：发生了什么，下一步怎么做",
  "errorCode": "config"
}
```

`errorCode ∈ usage|config|environment|network|conflict|internal`。缺 `errorCode` 时页面只显示 `error`，不得从中文文案反推类别。CLI 与界面必须共用同一句 `error/message` 来源。

### 2.2 目标 CLI 退出码

| 码 | 类别 | 对应 errorCode | 示例 |
|---|---|---|---|
| 0 | 成功或已达目标状态 | 无 | 重复断开、无凭据还原 |
| 1 | 未分类内部错误 | internal | 无法归类的宿主故障 |
| 2 | 用法错误 | usage | 缺值、多值、枚举值非法 |
| 3 | 配置/文件需人工处理 | config | 配置损坏、线路文件不存在 |
| 4 | 环境不支持或前置状态不满足 | environment | 未连接时测量、TUN 无管理员权限 |
| 5 | 网络类，可重试 | network | 目标端口不可达、探测超时 |
| 6 | 冲突，需用户决策 | conflict | 同名导入、外部代理归属冲突 |

- 失败写 **stderr**，成功与人类可读结果写 stdout；T-08 完成前不宣称这一规则已生效。
- 目标版本退役旧码 `7` 与 `12`，`--help` 必须列出新表和退役说明。
- 2026-10-30 空临时根矩阵实测：37 个命令、0 超时，当前码集合为 `{0,7,8,12}`；37 个命令均有输出，但全部 stderr 字节数为 0。修饰参数 `--engine/--port/--line-name/--to/--tun` 搭配只读 `--status` 测量，避免落回 GUI。

## 3. 命令契约

### 3.1 保留命令的语义边界

- `ping`：**保留为实例存活探测**，现有回包 `{"ok":true,"product":"SpiderVPN"}` 不变；不得用于线路延迟。
- `restore`（新 IPC）：是**执行还原**，复用 CLI `--restore-apply` 的后端，不是 `--restore` 的只读预览。
- `use`：仍表示切换 `config.json:selected`。若“设为默认”确认就是同一字段，T-17 只显式化现有 `use`，不新增重复命令。
- `import`：旧调用未传 `onConflict` 时保持原兼容行为；新版 UI 必须显式传 `onConflict:"ask"`。
- `set-transport`：只保存下次连接偏好，不改变当前运行时；`use-compatible` 才是“保存偏好 → 断开 → 重连 → 运行时核验”的复合动作。页面不得用前一条加幂等 `connect` 冒充真实重连。取值 `udp|tcp|auto`：`auto` 表示**清掉用户固定**（`config.json` 里 `transport` 键整个消失，不写空串/null），改用这条线路**已验证过**的方式；因此 `auto` 不跑 `engine_config::check_transport`（没有具体方式可校验），也**不动** `verified_transport`。非法值退出码 2、配置零字节变化。三档判定顺序见 §4.13。

### 3.2 新命令总表

| cmd | 请求关键字段 | 成功回包新增内容 | 写者 / 读者 | 缺省与失败语义 | 真实落点 |
|---|---|---|---|---|---|
| `pick-file` **已落地** | `slot:"profile"|"engine"`；`pickId` 由宿主生成 | `filePick` | `ui.rs` 开系统选择器 / 页面表单 | 取消返回 `cancelled:true`，不报错、不改旧值；不得由页面猜路径 | `src/ui.rs` 的 `GetOpenFileNameW`；`src/main.rs::handle_ui_pick_file` |
| `drop-file` | `slot`, `path`, `pickId`；**仅宿主内部投递** | `filePick{source:"drag"}` | wry 原生拖放回调 / 页面表单 | 页面不直接发此命令；路径由宿主校验，页面 `File.path` 不存在也不影响 | `src/ui.rs` `with_drag_drop_handler`；`src/ipc.rs` |
| `inspect-import` **已落地** | `profile`, `engine` | `problems:[{field,why,fix}]` | 导入表单 | 只读，不写配置；缺 `problems` 等同空数组 | `src/main.rs::inspect_import_problems`（复用 `engine_config::generate` 只读解析） |
| `maintenance-status` **已落地** | 无 | `maintenance` | `proxy.rs` 读取凭据与代理投影 / 维护卡、横幅 | 读取失败必须给 `detail`，不得显示“未接管” | `src/ipc.rs`、`src/proxy.rs` |
| `restore` **已落地** | 无 | 完整状态 + `restoreResult` + `message` | `ipc.rs` 调还原后端 / 维护卡与记录页 | 无凭据也成功且零写入；执行失败 `ok:false`，不得消耗凭据 | `src/ipc.rs`、`src/connect.rs`、`src/proxy.rs` |
| `measure-latency` **已落地** | 可选 `lineId` | `latencyMs`, `measuredAtUtc`, `latencyError:null`, `message` | `selfcheck.rs` 经当前认证 `tc-check` 入站测量 / 概览当前线路卡 | 仅在连接后自检或用户点击时测；未连接返回 `environment`，线路代际冲突返回 `conflict`；缺字段显示尚未测量 | `src/ipc.rs::measure_latency_json`、`src/selfcheck.rs::measure_latency_and_record`、`src/main.rs::merge_ui_command_reply`、`src/ui.rs` |
| `measure-backup` **已落地** | `lineId`（必须是另一条线路） | `backupResult{ok,lineId,lineName,reachable,latencyMs,atUtc,scope,notCurrentLatency,message}` | `ipc.rs` 对目标线路的 `tc-transport` 做一次 TCP 建连 / 线路列表 | 仅在 Connected、非 TUN、目标非当前线路时执行；无 TCP 中转、域名目标、未连接、TUN 均拒绝或给出不可测原因；不启动引擎、不改代理、不切换、不持久化；结果明确不等于当前响应 | `src/ipc.rs::measure_backup_json`、`src/ui.rs` 线路行 |
| `use-compatible` **已落地** | 无；资格由宿主重新计算 | 完整状态 + `compatibleResult{stage,saved,reconnected,verified,message}` | `ipc.rs` 复合事务 / 概览自检自救按钮 | 只有自检确实未通过、非 skipped、当前选择 UDP 且 TCP 参数可派生才执行；部分失败保留真实阶段，不自动回退 | `src/ipc.rs::use_compatible_json`、`src/selfcheck.rs::transport_alternative_hint`、`src/engine_config.rs::actual_transport`、`src/main.rs::merge_ui_command_reply`、`src/ui.rs` |
| `pick-exe` **已落地** | `target:"trade"|"daily"|"direct"`；`pickId` 由宿主生成 | 完整状态 + `filePick{pickId,slot:"process",target,path,processName,source:"picker",cancelled:false}` | `main.rs` 调 `ui.rs` 的 exe 文件选择器 / 对应分流组 | 取消返回 `cancelled:true` 且不改旧值；非 exe 或进程名校验失败返回 `ok:false`、不投递 `filePick`；完整路径只作选择证据，规则提交只用 `processName` | `src/main.rs::handle_ui_pick_exe_with`、`src/ui.rs::pick_file`、分流前端 |
| `rename-line` **已落地** | `id`（精确线路 id）、`name`（新显示名） | 新 `lines` / `selected` + `renameResult{ok,changed,name,message}` | `ipc.rs` 写配置 / 线路行内输入框 | 连接中拒绝；空名、控制字符、与其他线路名或 id 冲突时拒绝且不写盘；名称未变不重写配置；只改 `name`，不改 id、端点、选中项和 `lines\<id>.json` | `src/ipc.rs::rename_line_json`、`src/ui.rs` 行内改名 |
| `export-history` **已落地** | 可选 `filter:{onlyFail,src}` | `exportResult{ok,path,count,message}` | `events.rs` 读取筛选结果 / 记录页 | 导出页面当前可见范围内（`READ_LIMIT=200`）的筛选结果，格式 JSON Lines；唯一写入是数据根 `logs\exports\operations-<时间>.jsonl`，不联网、不接受调用方路径；空结果或失败不生成半成品 | `src/ipc.rs::export_history_json`、`src/events.rs::read`、`src/ui.rs` |
| `set-default-line` | `id` | 当前 `selected` | `config.rs` / 线路列表 | **不实现别名**：T-17 已确认“设为默认”就是既有 `use` 写 `config.json:selected`，页面只把动作显式化，避免两套选中语义 | `src/ipc.rs::edit_lines`、`src/config.rs` |
| `deployment-start` **已落地** | `spec`（`[user@]host[:port]`，缺省 `root`/`22`）、`fingerprint`、`password`、`label`（全可选） | `deployment{RunId,Accepted,Queued,Message}` | `ipc.rs` 建记录 + 投递意图 / 部署表单 | **短命令：只代表受理**，不代表任何一步做成；`spec` 形状错 `usage`、写盘失败 `config`、无引擎 `environment` | `src/ipc.rs::deployment_start_json`、`src/deploystore.rs::create`、`src/deployengine.rs` |
| `deployment-list` **已落地** | 无 | `deployment{TasksRead,TasksReadError,UnreadableCount,Tasks,Deployments}` | `ipc.rs` 读磁盘并投影 / 任务条、快照 | `TasksRead=="failed"` 时 `ok:false` 但**仍带 `deployment`**；`partial` 必须给「有 N 条读不出来」；缺失 = 未知，不得当成空列表 | `src/ipc.rs::deployment_list_json`、`src/deployrun.rs::project_tasks`/`project_deployments` |
| `deployment-draft-save` **已落地（r69）** | `spec`、`runId`（可选）、`fingerprint`（可选）、`label`（可选）。**请求里没有 `password`** | `deployment{Run,RunId,Created,Message}` | `ipc.rs` 把向导的非秘密字段写进一条 `Draft` 记录 / 部署向导的两次单击 | **短命令**；`spec` 坏 → `usage`；`runId` 非草稿 → `conflict`；已有 3 份草稿 → `conflict`（文案给去路）；记录读不全 → `config`（**不挡填写**）；秘密一个字节都不许进记录 | `src/ipc.rs::deployment_draft_save_json`、`src/deploystore.rs::MAX_DRAFTS`、契约 §4.16.10 |
| `deployment-get` **已落地** | `runId` | `deployment{Run}` | `ipc.rs` / 详情页、`resume`、`resumeDeployment` | `runId` 非 36 位小写 UUID → `usage`（同时是路径穿越防线）；读不到 → `config` | `src/ipc.rs::deployment_get_json`、`src/deployrun.rs::run_view` |
| `deployment-continue` **已落地** | `runId`、`password`、`verifyOnly` | `deployment{RunId,Accepted,Queued,Message}` | `ipc.rs` 六步准入后入队 / 详情页主动作 | **短命令**；终态 `Accepted:false`（不是错误）；已在跑幂等；缺凭据 `usage`；身份不符 `conflict` 并写记录 | `src/ipc.rs::deployment_continue_json`、`src/deployrun.rs::decide_resume` |
| `deployment-pause` **已落地** | `runId` | `deployment{RunId,PauseRequested,Message}` | `ipc.rs` 记意图 / 详情页 | **短命令**；只在步骤边界生效；没有活动 pass → `environment` | `src/ipc.rs::deployment_pause_json`、`src/deployengine.rs` |
| `deployment-cancel` **已落地** | `runId` | `deployment{RunId,CancelRequested,Message}` | 同上 | **短命令**；终态 `conflict`；有未决写时受理但明说「要等它做完并核对完」 | `src/ipc.rs::deployment_cancel_json` |
| `deployment-background` **已落地** | `runId` | `deployment{RunId,Accepted,Message}` | 同上 / 「后台继续」 | **短命令**；没有活动 pass → `environment`（没执行上下文时「转后台」是空话） | `src/ipc.rs::deployment_background_json`、`src/uiweb.rs` |
| `deployment-export` **已落地（r72）** | `runId`、`format`（可选：`markdown`（缺省）/`json`） | `exportResult{ok,path,bytes,format,message}`（**顶层**，与 `export-history` 同一份键） | 「导出诊断摘要」（详情页，任何状态都给） | **短命令**；`runId` 坏 / `format` 不认识 → `usage` 且**一个文件都不写**；记录读不到 → `config`；只写 `<数据根>\logs\exports\`，不接受调用方指定路径 | `src/ipc.rs::deployment_export_json`、`src/deployexport.rs`、契约 §4.16.13 |
| `deployment-archive` **已落地（r73）** | `runId`、`archived`（缺省 `true`；`false` = 恢复） | `deployment{RunId,Archived,Message}` | 「归档 / 恢复这条记录」（详情页） | **短命令**；在跑/排队/草稿 → `conflict`；`archived` 非布尔、也不是 `true`/`false` 字符串 → `usage`；只写 `ArchivedAtUtc`，**不删文件、不碰引擎**；归档即把该任务的未读提醒标已读 | `src/ipc.rs::deployment_archive_json`、`src/deploystore.rs::is_archived`、契约 §4.16.14 |
| `server-setup` **界面路径已退役，CLI 仍用** | 旧向导的整段参数 | — | 旧布置向导 / — | 界面调用返回 `usage` + 一句引导（改用 `deployment-start`），**不保留第二种行为**；命令行 `--server-setup` 仍走 `servercmd::setup`，不经过 IPC | `src/ipc.rs::server_setup_retired_json`、`src/servercmd.rs` |
| `remove` **结果已核对（r60）** | `id` | 新 `lines`/`selected` + `deleteResult{Id,Name,File,Incomplete,Error}` | `ipc.rs` 改配置 + 删引擎配置 / 线路页删除 | 配置删除成功即 `ok:true`；引擎文件删不掉时 `Incomplete=true` 并落待清理记录，命令仍成功（配置确实已删）；文件本来就不在算删干净 | `src/ipc.rs::edit_lines`（remove 分支）、`src/cleanup.rs` |
| `delete-preview` **已落地（r59）** | `id` | `deletePreview{Id,Name,Selected,LastLine,Eligible,Blocked,Files,Server,Warnings}` | `ipc.rs` 只读计算 / 删除确认框 | 只读，不写配置、不删文件；`Eligible=false` 是结论不是命令失败；缺 id / 找不到线路 / 配置读不出才 `ok:false`（`usage`/`config`） | `src/ipc.rs::delete_preview_json`、契约 §4.19 |
| `delete-cleanup` **已落地（r60）** | 无 | `deleteCleanup{Pending[],ReadError}` | `ipc.rs` 读待清理记录 / 快照投影、提示卡 | 记录损坏时 `ok:false` + `errorCode:"cleanup"`，**仍带** `deleteCleanup{ReadError}`；不得静默当空 | `src/ipc.rs::delete_cleanup_json`、`src/cleanup.rs`、契约 §4.20 |
| `delete-cleanup-retry` **已落地（r60）** | `id` | `deleteCleanupResult{Id,Name,File,Complete,Removed,Error,Message}` | `ipc.rs` 删残留文件 + 清记录 / 提示卡「重试清理」 | 前置拒绝也同时给 `deleteCleanupResult`（页面只读这一份）；线路仍在配置里必须拒绝；文件已不在算完成（`Removed=false`） | `src/ipc.rs::delete_cleanup_retry_json`、契约 §4.20 |
| `line-action-list` **已落地（r61）** | 无 | `lineActions{ReadError,Actions[]}` | `ipc.rs` 读磁盘 / 线路反馈、待处理、快照 | 只读；`ok:true` 空列表也是成功；记录损坏时 `ok:false` + `errorCode:"line-action"`，**仍带** `lineActions{ReadError}`；不得静默当空 | `src/ipc.rs::line_actions_json`、`src/lineaction.rs`、契约 §4.21 |
| `line-action-review` **已落地（r61）** | `id`（动作记录 id） | 记录原话 `message` + `lineActionReview{Id,LineId,Kind,Phase,Message,Code,NeedsReview,CanRetry,LatencyMs}` | `ipc.rs` 只核对已有证据并写回记录 / 卡片「检查测试结果 / 确认保存结果」 | 只核对、**不重放原操作**；缺 id → `usage`，记录读不出 → `record`，找不到 → `missing`，不是 NeedsReview / 类型不认识 → `state`；核对结论是失败时仍 `ok:true`（核对完成，失败的是被核对的动作） | `src/ipc.rs::line_action_review_json`、契约 §4.21 |
| `operation-list` **已落地（r62）** | 无 | `operations{ReadError,Records[]}` | `ipc.rs` 读磁盘 / 快照「待处理」、记录投影 | 只读；`ok:true` 空列表也是成功；记录损坏时 `ok:false` + `errorCode:"operation-record"`，**仍带** `operations{ReadError}`；不得静默当空 | `src/ipc.rs::operation_list_json`、`src/oprecord.rs`、契约 §4.22 |
| `operation-review` **已落地（r62）** | `id`（操作记录 id） | 记录原话 `message` + `operationReview{Id,Kind,Phase,Message,Code,NeedsReview,Origin}` | `ipc.rs` 只读核对并写回记录 / 首页「查看并处理」 | 只核对、**不重放原操作**；缺 id → `usage`，记录读不出 → `record`，找不到 → `missing`，不是 NeedsReview / 类型不认识 → `state`；结论是「上次没生效」时仍 `ok:true`；无法判断时**不落盘**、记录保持 `NeedsReview` | `src/ipc.rs::operation_review_json`、契约 §4.22 |
| `server-rename` **已落地（r65）** | `id`（服务器记录 id）、`name` | 刷新后的 `servers` 列表 + `message` | `ipc.rs` 写 `servers\<id>\record.json` / 服务器页「改名」 | 只改本机显示名与 `UpdatedAtUtc`；空名 / 超 120 字 / 控制字符 → `usage`，记录缺失或损坏 → `config`；名字未变不写盘；**不连服务器、不动凭据**（凭据熵不含 `Name`）；连接中不拦——它不碰引擎 | `src/ipc.rs::server_rename_json`、`src/serverstore.rs::rename`、契约 §4.25 |
| `server-remove` **已落地（r66）** | `id` | 刷新后的 `servers` 列表 | `ipc.rs` 删 `servers\<id>\`（含凭据） / 服务器页「删除记录」 | 只删本机；**还有线路的 `outbounds[].server` 指向它时拒绝**（`conflict`，说明有几条）；缺 id → `usage`，记录不存在/目录读不出 → `config`；重复删不算错 | `src/ipc.rs::server_remove_json`、`src/serverstore.rs::remove`、契约 §4.26 |
| `server-device-rename` **已落地（r66）** | `Id`（线路 id）、`PublicKey`、`Name` | 刷新后的 `serverDevices` | `ipc.rs` 经 SSH 写服务器 `device-names.json` / 设备页「改名」 | **长命令**；公钥必须 44 位、名字 1–64 字且无控制字符（`usage`）；失败回包必须带 `serverDeviceRename{error}`，否则页面会把「这条失败」当成「整页读不出来」；成功后整页重读，名字以服务器为准 | `src/ipc.rs::server_device_rename_json`、`src/pairhost.rs::rename_device`、契约 §4.26 |
| `server-uninstall-preview` **已落地（r66）** | `id` | `serverUninstallPreview{Id,Name,Host,Interface,TunnelUp,AffectedDevices,LocalLines,Eligible,Blocked,Warnings}` | `ipc.rs` 只读 SSH 检查 / 设备页「卸载…」 | **只读**，不动服务器；`Eligible=false` 是结论不是命令失败（当前连接在跑 → `Busy`）；始终给「不释放云服务器」与「关联线路会断」两条警告 | `src/ipc.rs::server_uninstall_preview_json`、契约 §4.26 |
| `server-uninstall` **已落地（r66）** | `id` | `serverUninstall{Id,Name,Host,TransportRemoved,InviteRemoved,InterfacePresent}` + `servers` | `ipc.rs` 经 SSH 停服务/删配置 / 设备页「确认卸载」 | **长命令**；连接中拒绝（`environment`）；移除 transport 与 `tc-pair` 单元、WireGuard 配置与私钥、transport 配置；**保留** `transport.env`、pairing 状态与组件；不删本机记录、不释放云服务器 | `src/ipc.rs::server_uninstall_json`、`src/deploy.rs::uninstall`、契约 §4.26 |
| `pair-offline-inspect` **已落地（r67）** | `invite`（完整签名邀请 JWS）、`pairId` | `pairOffline{Stage:"Inspect",PairId,Code,Message,Fingerprint,InviteId,DeviceName,ExpiresAtUtc,NodeName}` | 新电脑「连不上 18443？用离线邀请」 | **同步只读**：不联网、不落盘；失败也 `ok:true`，错误码在 `Code`；指纹只做展示，必须由人与管理端核对 | `src/ipc.rs::pair_offline_inspect_json`、契约 §4.27 |
| `pair-offline-request` **已落地（r67）** | `invite`、`fingerprint`、`device`、`pairId` | `pairOffline{Stage:"Request",EnrollmentId,InviteId,RequestText,PairingCode,DeviceName,ExpiresAtUtc,Resumed}` | 新电脑「生成申请」 | **长命令**；只接受已核对指纹；同一邀请复用原申请，不变成第二台设备；只写 `identities\`，不消费邀请 | `src/pairing.rs::offline::prepare`、契约 §4.27 |
| `pair-offline-complete` **已落地（r67）** | `enrollmentId`、`authorization`、`name`、`pairId` | `pairOffline{Stage:"Complete",LineId,LineName,Compatible,State,EnrollmentId}` | 新电脑「完成加入」 | **长命令**；连接中拒绝（`ConnectionBusy`）；解封 JWE、验签、写 `client.conf` 与线路，与在线 `pair-join` 共用 `join::finish` | `src/pairing.rs::offline::complete`、契约 §4.27 |
| `invite-authorize` **已落地（r67）** | `line`、`request`（新电脑申请 JWS） | `invite{Section:"Authorize",Data{ServerId,InviteId,RequestId,DeviceName,PairingCode,Authorization}}` | 管理端「批准并生成授权」 | **长命令**；本地先验申请（`InvalidPairRequest`/`InvalidInvite` 不发起 SSH）；服务器 `authorize-request` 与在线 `/consume` 共用授权逻辑；地址在批准时分配；授权只经剪贴板交回，**不进快照** | `src/ipc.rs::invite_authorize_json`、`src/pairhost.rs::authorize_request`、契约 §4.27 |
| `operation-retry` **已落地（r67）** | `id`（界面操作记录 id） | 原命令回包 + `operationRetry{Id,Kind,RecordId,Message}` | 首页「重试连接 / 重试断开 / 重新诊断」 | **长命令**；只接受 `Failed` 的连接/断开/诊断；`Succeeded`/`Pending`/`NeedsReview` 一律 `state`；重试写**新记录**（同类已结束只留最新一条）；不重放旧命令原文 | `src/ipc.rs::operation_retry_json`、`src/oprecord.rs::retry_plan`、契约 §4.27 |
| `auto-route-list` **已落地（r67）** | 无 | `autoRoutes{NetworkFingerprint,Lines{<id>:{Summary,Winner,Expired,Candidates[]}}}` | 快照线路卡 | **同步只读**：只读 `autoroute.json`，不探测、不起引擎 | `src/autoroute.rs::list_view`、契约 §4.27 |
| `auto-route` **已落地（r67）** | `line`、`refresh` | `autoRoute{LineId,Transport,TransportLabel,Source,Note,Evidence,Probed}` | 线路抽屉「自动选择连接方式」/ 连接前自动应用 | **长命令**；连接中拒绝（`busy`）；临时引擎真拨标准/兼容两个候选；证据 30 分钟、网络指纹不符即重测；用户固定方式永远优先 | `src/autoroute.rs::probe_line`、契约 §4.27 |
| `auto-reroute` **已落地（r68）** | `line`、`reason`（`network`/`quality`/`manual`） | `autoReroute{LineId,Reason,From,To,Alternate,Switched,Note}` | 宿主 60 秒监测（网络变化/连续变差）自动触发 | **长命令**；只碰自动档；`network` 先断开再测两个候选后重连；`quality` 只测备选、备选不赢就不动连接；10 分钟冷却由宿主控制 | `src/ipc.rs::auto_reroute_json`、契约 §4.28 |
| `server-device-forget` **已落地（r68）** | `Id`（线路）、`PublicKey`（44 位） | `serverDeviceForget{publicKey,removed}` / 失败 `{error}` | 设备页「已撤销设备的名称记录 → 删除记录」 | **长命令**；只删服务器 `device-names.json` 的名称条目，不碰 peer/邀请审计；本机公钥拒绝 | `src/ipc.rs::server_device_forget_json`、契约 §4.28 |
| `invite-preflight` **已落地（r68）** | `line` | `invite{Section:"Preflight",Data:{Status,Verdict,Detail,Repaired,Installed,Active,PortListening,Firewall,Port,Host}}` | 邀请页「重新开启接收服务」 | **长命令**；先本地探测，未通则 SSH 读 `tc-pair.service` 状态；`NeedsInit`/`NeedsRestart` 自动装/重启，`Firewall`/`TlsMismatch` 只报结论不自动动 | `src/ipc.rs::invite_preflight`、契约 §4.28 |

**这十条 `deployment-*` 全部是短命令**，只做「校验 → 落盘 → 投递」，SSH 在引擎线程跑。它们**不得**进 `is_long_command` / `operation_budget`——进去就等于整个部署期间独占事务门。细节、字段表与词表见 §4.16。

`pickId` 是宿主生成的非敏感一次性标识。页面只消费尚未见过的 `filePick`，防止同一回包被重复应用；无关状态回包没有 `filePick` 时不得清空正在编辑的输入。

#### 3.2.1 长命令的全局闸门（**r76 落地**）

**管道/CLI 侧一直是单闸门**（`ipc::respond` 用一把 `Mutex` 串行），界面侧却按**命令名**去重：`connect` 与 `import` 可以同时跑——一个在拨号，另一个在重写 `config.json`，后写者赢，前一条线路凭空消失。r76 把界面的口径对齐到管道。

| 项 | 规则 |
|---|---|
| 清单 | `ipc::is_long_command` 是唯一事实；`deployment-*` 十条短命令**不在**闸门内（它们只受理，SSH 在引擎线程） |
| 占用者 | `ui::OperationBook.holder`：第一个被受理的长命令写进去，它的**终态事件**才会放开 |
| 同一条命令重复 | 仍是 single-flight：重发当前 `phase`，**不**算「忙」（用户看到的是同一件事） |
| 另一条命令 | `ok:false`、`errorCode:"busy"`、`op.phase:"refused"`，文案 `正在「X」，等它结束再试。`；`X` 来自 `uiweb::command_label` |
| 拒绝的代价 | **不调业务 handler、不写 `ui-operations.json`**；它没有开始过 |
| 页面对 `refused` | 只弹提示；**不许**清 `busy`/`operation`（那是正在跑的那条的）；若这条命令在发出时把操作条顶掉了（`begin_op` 无条件覆盖），按 `op_before_refusal` **还原** |
| 自动路径 | A5 等待态推进（每秒）与连接中自动切换**不弹**这句话：它们会自己重试，每秒弹一次是噪音。自动切换被挡只退避 30 秒，**不扣** 10 分钟冷却（`submit_operation` 返回「是否真的开始」） |
| 副作用顺序 | 一次点击里的 `Step::Sync` 先于 `Step::Long` 执行，所以「被拒的连接」可能已经把它前面的 `use`（选择线路）做掉了。这是既有顺序，不是本闸门引入的 |

**为什么不排队**：排队会让「断开」在「自动选路」后面等几十秒，而用户以为它已经开始；拒绝能立刻说清「正在做什么、该等谁」。等不了的时候，用户看得见的那句话就是全部价值。

**名字必须说全**：`uiweb::command_label` 覆盖 `is_long_command` 里的每一条（有源码扫描用例守），漏一条就退化成「正在操作，等它结束再试」——用户猜不出该等谁。


### 3.3 同名导入

新版 UI 首次提交：

```json
{"cmd":"import","profile":"…","engine":"…","lineName":"T2","onConflict":"ask"}
```

若同名，宿主在任何写入之前返回：

```json
{"ok":false,"errorCode":"conflict","conflict":{"id":"t2","name":"T2"}}
```

- **替换**：再次提交 `onConflict:"replace"`，宿主必须重新检查冲突后再写。
- **另存为**：提交 `onConflict:"save-as"` 与新 `lineName`；新名仍冲突则继续返回冲突。
- **取消**：仅前端撤销本次动作，不发写入命令。
- 确认前 `config.json` 与 `data/lines/<id>.json` 的内容和 mtime 均不得改变。

## 4. 状态字段契约

| 字段 | 类型 / 枚举 | 写者 | 读者 | 缺省 / 降级语义 |
|---|---|---|---|---|
| `linesRead` **已落地** | `ok|failed` | `ipc.rs` 从真实配置读取结果投影 | 线路列表 | 缺字段且已有列表可兼容显示；新版宿主总会给出该字段；失败态不得冒充“还没有线路” |
| `linesReadError` | string | 同上 | 读取失败卡、记录页入口 | 缺省为空；`linesRead=failed` 时必须给人话，不给开发路径 |
| `filePick` **已落地；T-15 扩展 process** | `{pickId,slot,target?,path?,processName?,source,cancelled}` | `main.rs` / `ui.rs` | 对应输入框 | 缺字段表示没有新选择，不能清空旧输入；`cancelled=true` 不改值；`slot="process"` 时按 `target` 回填，进程规则只提交 `processName` |
| `conflict` | `{id,name}` | 导入校验 | 同名冲突层 | 缺字段表示无待处理冲突；替换前必须重新核验 |
| `exitObservedIp` **已落地（当前恒 null）** | string|null | 自检证据层 | 概览出口行 | 缺失、空串、非法值或 `0.0.0.0` 一律按未观测到处理；当前尚未采集权威出口 IP |
| `exitEvidence` **已落地** | `verified|forwarded-unverified|unverified` | 自检证据层 | 概览出口行 | 缺字段=`unverified`；只有权威归属证据可用 `verified`；当前自检通过只给 `forwarded-unverified` |
| `checkAtUtc` **已落地** | RFC3339 string|null | 自检证据层 | 自检结论与时间 | 缺失或解析失败不显示时间，不得回填“现在” |
| `diagnose.items` **已落地** | `[{target,port,purpose,result,ms,text}]` | `diagnose.rs` / IPC | 设置页诊断行 | 缺字段回退旧 `lines`；TCP 成功与失败均有实际 `ms`，UDP 不适用与未探测为 null |
| `diagnose.verdict` **已落地** | `{code,text,next}` | `diagnose.rs` / IPC | 诊断末尾结论与下一步 | 缺字段显示旧 `lines` 中已有结论，不自行推断网络状态 |
| `isAdmin` **已落地** | boolean | `probe.rs` 写 HKLM 能力探测 | 设置页当前权限、自启 × TUN 结论 | 缺字段显示“当前权限：未知”，不得按 false 给出确定结论；true 只代表当前会话提权，不代表登录自启会继承 |
| `latencyMs` **已落地** | non-negative number|null | `measure-latency` 后端 / `status` 当前连接投影 | 当前响应 | 缺字段/ null = 尚未测量；仅当前 `Connected` 且连接启动标识匹配时给值；不得用诊断其他目标的 TCP 读数顶替 |
| `measuredAtUtc` **已落地** | RFC3339 string|null | 同上 | 当前响应相对时间、“较旧”标记 | 缺失或非法则不显示相对时间；未来时间不倒算；不得把发起时间冒充测量完成时间 |
| `transportActual` **已落地** | `标准连接` / `兼容连接` / null | `engine_config.rs` 读取当前 `runtime-engine.json` | 概览当前线路卡 | 只有完整连接证据成立才读取；未连接为 null；运行时缺失、形状混合或不可核验时显示未知，不拿下次偏好或代理/TUN 接管方式顶替 |
| `startedAt` **已落地** | RFC3339 string / `""` | `runtime.json` 的 `StartedAt`（守护拉起引擎那一刻） | 首页「引擎已运行 N 分」（快照字段名是 `ConnectedSince`） | **只在 `state=Connected` 时给**；未连接、无记录或时间解析失败一律空串。记录会活过连接（断开时删、被杀时留），照抄会显示一个不存在的时长；空串表示「没有起点」，界面显示「—」而不猜 |
| `compatibleAction` **已落地** | boolean | `selfcheck.rs` 与 `ipc.rs` 共用资格计算 | 自救按钮显隐 | 缺字段按 false；只有自检未通过、非 skipped、当前选择 UDP 且 TCP 参数可派生才为 true |
| `compatibleResult` **已落地** | `{stage,saved,reconnected,verified,message}` | `use-compatible` | 专用结果区 | 仅本命令回包携带；`stage ∈ eligibility|save|disconnect|connect|verify|done`；成功必须 stage=done 且三个事实均为 true；无关 status 不得清除部分失败 |
| `splitMessage` **已落地** | string | `split-add` / `split-remove`；`main.rs` 回包合并 | 分流组结果句 | 表示本次真实添加、删除或幂等无变化结果；缺字段时保留现有列表，不猜测成功；无关 `status` 不伪造新结果 |
| `renameResult` **已落地** | `{ok,changed,name,message}` | `rename-line`；成功和失败都携带 | 行内改名输入与提示 | 只有 `ok:true` 才能收起输入框；失败必须保留草稿并显示原因；无关 `status` 不清除或伪造结果 |
| `exportResult` **已落地** | `{ok,path,count,message}` | `export-history`；成功和失败都携带 | 记录页导出按钮与提示 | 只有本命令回包能结束导出等待；`path` 必须落在数据根 `logs\exports`；空结果 `ok:false,path:null`，无关 `status` 不得伪装成功 |
| `op` | `{cmd,phase,startedAtUtc?,budgetSec}` | 长任务宿主 | 导入/连接/诊断进行中 UI | 缺 `startedAtUtc` 只显示“仍在进行”，不显示伪造秒数 |
| `op.phase` | `queued|running|finished|failed` | 长任务宿主 | 同上 | 缺 `op` 用本端发起态兜底；无关回包不得结束它 |
| `exitDailyMembers` **已落地** | `[{value,label}]` | `ipc.rs` 读取真实引擎出站、服务商注册表与线路名后投影 | 日常出口选择器、汇总与概览 | 前端可接受旧 string[]；新宿主给非空人话 label；提交只提交 value；旧格式缺 label 时显示“本地直连”或“未命名出口”，不直接暴露 tag |
| `exitTradeMembers` **已落地** | `[{value,label}]` | 同上 | 交易出口选择器、汇总与概览 | 同上；缺字段等同空选项并禁用提交，不得把 label 当 value |
| `maintenance` **已落地** | `{journalPresent,proxyOwned,endpoint?,canRestore,detail?}` | `proxy.rs` / `ipc.rs` | 维护卡与概览横幅 | 缺字段表示维护状态未知；只有 `journalPresent/canRestore` 有证据时才显示可还原 |
| `restoreResult` **已落地** | `{ok,changed,message}` | `ipc.rs` / `main.rs` 回包合并 | 维护卡结果句与等待态 | 只有 `restore` 命令回包携带；无关 `status` 不得清除上次结果或结束本次等待 |
| `provider.effectiveState` **已落地** | `effective|pending|unavailable` | `ipc.rs::providers_payload` 读取当前线路引擎配置与 selector | 服务商列表与概览摘要 | 缺字段显示“状态未知”，不显示“已生效”；`effective` 仅表示配置和出口选择指向它，不证明客户端在线或流量出口归属 |
| `provider.effectiveRole` **已落地** | `daily|trade|daily+trade|null` | 同上 | 已生效范围 | 缺字段不推断；`trade` 必须显示“仅交易出口”，不能让用户误以为日常也经过它 |
| `provider.effectiveReason` **已落地** | string | 同上 | 状态原因 | 缺省为空；`pending/unavailable` 必须给原因；`effective` 说明哪些出口指向它 |
| `backupResult` **已落地** | `{ok,lineId,lineName,reachable,latencyMs,atUtc,scope,notCurrentLatency,message}` | `measure-backup`；成功和失败都携带 | 备用线路行内结果 | 只有本命令回包能结束检查；`latencyMs` 只在 TCP 连接成功时给值；`notCurrentLatency` 必须为 true，页面不得把它放进“当前响应” |

### 4.1 出口三档显示映射

| wire value | 页面中文 | 硬约束 |
|---|---|---|
| `verified` | 已核验 | 必须有权威出口归属证据；不能仅因 HTTP 自检通过就使用 |
| `forwarded-unverified` | 转发已通、归属未验证 | 自检通过但未取得权威归属证据 |
| `unverified` | 尚未核验 | 未连接、未自检、自检失败、字段缺失或证据无效 |

断开后可保留上次结论，但必须同时显示“（上次）”与 `checkAtUtc`；不得显示成刚刚重新测量。

### 4.2 T-12 门控与失效出口（**已落地**）

- `action` 只有 `None` 表示宿主的“请稍候”等待态。未映射的其他字符串不得猜测成写命令；主按钮显示“查看线路”，仅执行只读导航及 `lines` 查询。
- 当前出口值不在 `exitDailyMembers` / `exitTradeMembers` 中时，界面保留这个事实，但对应选项必须禁用并标注“已失效”；`exit-set` 不得提交该旧值。用户改选有效成员后仍可正常提交。
- 连接中分流的进程/域名输入、目标选择、添加、删除及出口改选均受忙态门控；除控件 `disabled` 外，提交函数和删除事件处理器也必须再次检查，且不得清空用户尚未提交的输入。
- 前端门控不是授权边界。`ipc::edit_exit()` 继续拒绝不存在的成员，`edit_split()` 继续拒绝连接中写入。当前未实现删除服务商后自动修复失效 `default`，不得宣称后端已自动清理。

### 4.3 T-10 结构化诊断与复制（**已落地**）

- `diagnose` 成功载荷保留旧 `lines`，新增 `items` 与 `verdict`。`items` 依次覆盖 TCP 探测、UDP 不适用说明和未探测原因；每行另带同源 `text`，CLI 的 `render()` 与页面都消费 `diagnose.rs`，不维护两套诊断文案。
- `purpose ∈ transport|admin|web|udp|configuration`。TCP `result ∈ reachable|timeout|refused|resolve-failed|unreachable`；说明项另用 `not-applicable|not-run`。`port` 对无目标说明为 null；`ms` 只对实际执行过的 TCP 探测为数字，成功失败都包含地址解析与连接等待的实际耗时，不能用 2500ms 上限冒充实测。
- `verdict.text` 复用既有 `summary()`；`next` 必须对应当前连接方式和失败用途。纯 UDP 的 22/443 不通只提示检查网络侧封禁、云安全组与防火墙，并明确不能据此判定离线；已经在兼容连接时不得再建议“改用兼容连接”。末尾一行同时含“结论”与“下一步”。
- 页面用 `[可达]`、`[超时]`、`[连接被拒绝]` 等文字标识，不只靠颜色。复制内容直接取诊断结果区的 `innerText`；只有 `navigator.clipboard.writeText` 的 Promise 兑现才提示“已复制”。权限拒绝或 API 缺失时用 `Selection.selectAllChildren` 全选并提示 Ctrl+C；全选也失败则明确要求手动选择，均不得误报复制成功。
### 4.4 T-09 长任务调度与超预算出路（**已落地**）

- `connect / disconnect / diagnose / restore / import / measure-latency / use-compatible` 在 WebView 与托盘入口统一进入后台调度；保留原同步业务 handler，由工作线程执行。协调线程每秒投递 `running` 心跳，`tao::EventLoopProxy<UiHostEvent>` 把事件送回 UI 线程，只有 UI 线程可以调用 `WebView::evaluate_script`。
- 每次操作回包携带 `op{cmd,phase,startedAtUtc,budgetSec}`。同命令重复提交只重发当前 `op`，不再次进入业务 handler；递增操作 ID 防止旧终态清除新操作。WebView 与管道继续共享 `Ctx.transaction_gate`，短命令 `ping/status` 不等待长事务。
- 连接/断开/还原预算 30 秒，导入与兼容重连 60 秒，测量 5 秒，诊断为 TCP 目标数 × 2.5 秒 + 5 秒。预算只开放“仍在进行 / 查看记录 / 重试”自救出口，不取消事务、不伪造 `failed`。宿主完全无回包时，前端只能在 60 秒后开放无秒数的重试与记录出口。
- 秒数只能由 `op.startedAtUtc` 计算；缺该字段只显示“仍在进行”。专用 1 秒定时器只刷新操作文案，不轮询 IPC、不做全量重绘。无关 `status` 不得结束导入、诊断或还原等待；终态先消费，再处理断开按钮的本地乐观态。
- 隔离宿主验收可同时设置 `SPIDERVPN_ROOT` 与 `SPIDERVPN_TEST_HOST_TRACE=1`，在 `<数据根>\logs\t09-host-events.jsonl` 留痕。记录仅含动作、线程、操作 ID/阶段、宿主时间、预算、诊断载荷存在位与脚本调用结果，不含配置或业务回包；默认启动与只设其中一个开关均不生成该文件。真实验收报告为 `reports-tmp/tcrs-audit/t09-webview-native-r7/t09-webview-runtime-0.1.4.json`。

### 4.5 T-11 维护状态与执行还原（**已落地**）

- `status` 与 `maintenance-status` 使用同一 `proxy::maintenance_status` 投影。无凭据为 `journalPresent=false, canRestore=false`；有效凭据为 `canRestore=true`；损坏凭据保留 `journalPresent=true`、给出 `detail` 并禁用按钮，不能冒充“未接管”。`proxyOwned` 只在当前代理键可读且 `ProxyServer` 仍等于凭据端点时为 true。
- `restore` 是执行命令，直接复用 `connect::restore_from_journal()`，不读取或改写线路配置。正常写回返回 `changed=true`；外部程序已改端点时零写回并清理残留凭据；无凭据返回成功、`changed=false`，且重复执行语义相同。凭据仍在时不得返回完整成功。
- 每次执行写入 `operations.jsonl`：`action="还原"`、`obj="system-proxy"`，来源按真实入口记录为 `ui` 或 `pipe`。界面只发送 `restore`，只有收到 `restoreResult` 才结束等待并显示结果；无关 `status` 不清空结果。
- 自动化写回仅使用临时数据根与 `Software\SpiderVPN\tests\...` 临时注册表键。T-11 未覆盖真实安装，也未对真实系统代理执行还原。CLI 损坏配置可能提前阻断 restore、`--restore-apply` 启动自愈顺序等既有边界不在本轮修复范围。

### 4.6 T-13 当前通道响应与手动测量（**已落地**）

- 只有完整证据链投影为 `Connected` 才允许测量。后端从当前 `runtime-engine.json` 读取唯一生效的 `tc-check` 入站，要求其为监听 `127.0.0.1` 的 `socks` 并取得实际 `listen_port`；不得重新执行连接前端口规划，也不得假定端口恒为线路端口 `+3`。
- 测量复用现有认证 SOCKS5 通路，经交易出口请求 `http://www.gstatic.com/generate_204`。这是 **HTTP 204 请求，不是 HTTPS 测速**；`Instant` 记录实际请求耗时，只接受 2xx，且响应后再次确认引擎仍存活。不得拿 `diagnose` 其他目标的 TCP `latency_ms` 冒充当前通道响应，`ping` 仍只返回 `{"ok":true,"product":"SpiderVPN"}`。
- 成功回包为 `{"ok":true,"latencyMs":37,"measuredAtUtc":"RFC3339","latencyError":null,"message":"测量完成"}`；`measuredAtUtc` 是响应完成后的真实时间。失败回包保留同源 `error/message/latencyError` 与 `errorCode`：未连接或缺当前连接证据为 `environment`，可选 `lineId` 已不是当前线路为 `conflict`，探测失败为 `network`，运行时配置或测量记录写入问题为 `config`。
- 当前测量独立保存为 `<数据根>\last-latency.json`，记录 `{latency_ms,at,connection_started_at}`；通道自检仍写 `last-check.json`。手动测量成功或失败均不重写自检文件；失败保留上一次真实成功读数和完成时间，不伪造新值。
- `connection_started_at` 必须与当前 `runtime.json:StartedAt` 精确匹配才投影到 `status`。新连接自检开始先清旧读数，成功才留下首个真实读数，失败或跳过不生成当前读数；断开成功清除测量，但仍按既有规则保留上次自检结论。
- 页面未连接显示“连接后测量”，已连接但无有效读数显示“尚未测量”。合法读数显示 `NN ms · N 秒前`，超过 300 秒追加“较旧”；时间缺失/非法不显示相对秒数，未来时间不倒算成“0 秒前”。点击只建立本地等待态，按钮禁用并显示“测量中…”；新读数只能来自宿主回包，无关 `status` 不结束等待，失败显示真实错误并恢复“测一次”，超预算只开放“重试”。
- 最终证据：debug/release 全量各 450 passed / 0 failed / 1 ignored；五页 DOM 5/5；真实 Edge 12/12 场景；隔离门 14/14；真实 WebView2 修正探针后连续两轮 17/17，最终报告 `reports-tmp/tcrs-audit/t13-final/webview-r3/t13-webview-runtime-0.1.4.json`。首轮 `webview-r1` 因探针在操作中进行 `PrintWindow` 同步抓屏、阻塞自身等待而失败，原始报告保留，不得描述成首轮即通过。

### 4.7 T-14 连接方式自救与真实重连（**已落地**）

- `checkHint` 与 `compatibleAction` 共用 `selfcheck::transport_alternative_hint()`：只有自检确实未通过、不是 `skipped`、当前线路仍选择标准连接且 `engine_config::check_transport(..., Tcp)` 能派生兼容参数时才成立。页面不自行推断资格。**（r31 起新增「自动」档，见 §4.13；它不改变本节的资格判定，`selfcheck::transport_alternative_hint()` 仍然只针对「标准连接失败 → 建议兼容」这一条自救路径。）**
- `use-compatible` 是后端单一复合事务：保存 TCP 偏好并重新读取 `config.json` 核验，随后执行真实断开和连接；连接回包必须有非空 `steps`，再核验 `runtime-engine.json` 的实际形状。`set-transport` 仍只影响下次连接，普通幂等 `connect` 的空步骤不能冒充重连。
- `compatibleResult.stage` 精确报告 `eligibility/save/disconnect/connect/verify/done`。保存、重连、运行时核验分别由 `saved/reconnected/verified` 表示；只有 `stage=done` 且三者全为 true 才成功。已重连但核验失败必须返回 `stage=verify, saved=true, reconnected=true, verified=false`，不自动回退 UDP。
- `transportActual` 只从当前运行时配置识别：至少一个 WireGuard endpoint 且全部无 `detour` 才是标准连接；全部挂在真实、参数完整的 `tc-transport` VLESS + REALITY 中转上才是兼容连接。空 endpoint、混合形状、外部或悬空 detour、缺文件及不可读 JSON 都为未知。它与 `transport` 下次偏好及 `mode` 代理/TUN 接管方式是三个不同维度。
- 页面只发送一次 `use-compatible`，按钮显隐由 `compatibleAction` 决定；等待期禁用并显示复合动作进度，60 秒预算只开放重试出路。专用 `compatibleResult` 由 `main.rs` 合并回完整状态，后续无关 `status` 不清除部分失败；成功后按新的资格事实收起按钮。
- 最终 Release 验收：debug/release 全量各 **457 passed / 0 failed / 1 ignored**，五页 DOM **5/5**、真实 Edge **13/13 场景**、隔离门 **14/14**、真实 WebView2 原生点击与真实重连 **25/25**。报告位于 `C:\tc-rs-build\t14-final-evidence\`；真实宿主报告确认旧 PID 停止、新 PID 存活且不同、`compatibleResult` 已回推 UI 线程、临时键精确还原。
- 运行期验收使用 `PING.EXE -n 300 127.0.0.1` 作为稳定假引擎，不证明真实隧道可用。测试专用核验故障注入、跨模块环境串行锁只存在于测试产物；真实安装与真实系统代理未被覆盖或写入。

### 4.8 T-15 三组分流、进程选择与出口人话命名（**已落地**）

- 页面请求 `{"cmd":"pick-exe","target":"trade|daily|direct"}`。宿主复用 Windows `GetOpenFileNameW` 的 exe 选择器，只接受 `.exe` 并继续调用 `SplitConfig::validate_process()`；成功回包带 `filePick{pickId,slot:"process",target,path,processName,source:"picker",cancelled:false}`。完整 `path` 是选择证据，`processName` 才是分流规则值。取消只返回 `cancelled:true`，不带路径或进程名、不清空旧输入；非 exe、无文件名或校验失败返回 `ok:false`，不投递伪造的 `filePick`。
- 文件选择本身不写分流规则。页面按 `target` 回填对应组的进程输入并提示目标出口，用户再点击“添加”发送 `split-add`；连接中输入、选择、添加、函数入口与删除事件仍全部门控。正在运行的程序列表未实现。
- 分流卡按每条规则的 `target` 分为交易、日常、直连三组，不再只改标题而保留平铺列表。交易组只显示 `target=trade` 的进程和域名，每组有独立规则类型、输入、程序选择、添加与组内删除。配置模型继续复用 `SplitTarget::{Direct,Trade,Daily}`，未另造隧道规则枚举。
- `split-add` / `split-remove` 成功回包新增 `splitMessage`：例如 `已加入：TDXW.exe → 交易出口`；删除、重复添加和删除不存在项也如实说明结果。`main.rs::merge_ui_command_reply()` 保留该字段，避免完整状态重建吞掉结果。概览覆盖范围追加“交易名单内 N 个程序”，只统计 `target=trade` 的进程。
- `exitDailyMembers` / `exitTradeMembers` 由宿主统一生成 `{value,label}`。`value` 继续用于 `exit-set` 和引擎配置，`label` 只用于选择器、汇总、交易链路证据与概览显示；后端 `edit_exit()` 仍按真实成员值校验。直连显示“本地直连”；注册表匹配的服务商显示“代理软件（客户端名 地址:端口）”；注册表缺失但真实 SOCKS 出站存在时显示“代理软件（本机客户端 地址:端口）”；其他线路成员显示“交易线路（线路名）”。前端不得根据内部 tag 猜客户端名。
- 迁移期前端兼容旧 `string[]`，但旧格式没有显示名时仅显示“本地直连”或“未命名出口”，不直接暴露内部标识。失效当前值显示“当前出口已失效”，仍不能提交。
- 概览“应用走向”固定三行：交易软件在已连接时显示交易出口人话名称，否则显示“未连接”；日常上网显示日常出口，缺省本地直连；其它与日常上网一致，因为引擎 `final` 指向 `daily-exit`。没有引入 PRD 已排除的 AI 名单。
- 最终验收：debug/release 全量各 **459 passed / 0 failed / 1 ignored**，真实 Edge **15/15 场景**，五页 DOM **5/5**，隔离门 **14/14**，真实 WebView2 的 T-14 原生点击与真实重连回归 **25/25**。报告位于 `C:\tc-rs-build\t15-evidence\`；旧 release 红测和五页 DOM 首轮过期断言均保留。
- **验收边界**：上述真实 WebView2 结果是 T-14 回归，不是 `pick-exe` 系统对话框原生验收。`pick-exe` 已由选择器注入单测与 Edge 回包场景验证，系统文件选择框仍需人工冒烟；拖放仍为 Pick Fail，假引擎不证明真实隧道可用，新 release 未覆盖真实安装。

### 4.9 T-16 自启 × TUN 结论与权限三态（**已落地**）

- 产品结论来自真实实现，不是前端猜测：`src/autostart.rs` 只写当前用户 HKCU Run 键，值指向安装根的普通启动入口 `.cmd`（缺失时退回 exe），没有 `runas`、计划任务或管理员 manifest；Windows 登录执行该入口时使用普通用户令牌。`src/connect.rs` 在 TUN 动手前检查 `probe::elevated()`，非管理员直接拒绝，不会启动引擎或改路由。
- 因此当 `autoStart===true && modeChoice==='tun'` 时，设置页“启动与托盘”与概览必须同时给出：“开机自动启动会以普通权限运行，无法启用 TUN”。该结论与当前 `isAdmin` 无关：即使本次以管理员启动，开机自启也不会继承提权。
- 设置页同时显示权限三态：`isAdmin===true` 为“当前权限：管理员”；`false` 为“当前权限：普通权限，要用 TUN 请以管理员身份启动”；字段缺失为“当前权限：未知；不能据此判断 TUN 是否可用”。不得把缺字段猜成 false。
- 两条出路都有真实动作，不串联连接：
  - “改用系统代理”只发送 `{"cmd":"set-mode","mode":"proxy"}`，连接中禁用；当前连接保持原方式，下次生效。
  - “关闭开机自动启动”发送完整 `settings` 事务且显式 `autoStart:false`，保留当前 `autoConnect` / `closeToTray`，不把另外两个开关重置。关闭后由用户每次用管理员入口打开。
- `autoStart` 变为 false，或 `modeChoice` 不再为 `tun` 时，设置页警告与概览横幅同时消失。没有新增命令，也没有把自启改造成管理员计划任务或自动 UAC 提权。
- 最终验收：debug/release 串行全量各 **460 passed / 0 failed / 1 ignored**，真实 Edge **16/16 场景**（T-16 自身 13/13），五页 DOM **5/5**，隔离门 **14/14**，真实 WebView2 的 T-14 回归 **25/25**。证据位于 `C:\tc-rs-build\t16-evidence\`。
- **边界**：未在关闭 UAC、内置 Administrator 等特殊账户策略下实测“登录后必为普通令牌”的平台前提；没有写真实 Run 键，也没有覆盖真实安装。普通用户下 TUN 失败的真实连接仍由既有前置拦截和单测覆盖，本轮只补组合结论与出路。

### 4.10 T-17 记录复制/导出与线路行内改名/设为默认（**已落地**）

- **单条复制是前端本地动作，不新增 IPC**：每条记录生成一行纯文本，字段顺序为“时间、动作、结果、详情、来源”，内部用制表符分隔，详情中的换行替换为空格。`navigator.clipboard.writeText()` 的 Promise 真正兑现后才显示“已复制”；API 缺失或拒绝时只全选该行并提示 `Ctrl+C`，不得把“已选中”说成已复制。
- **导出由宿主执行**。页面只发送 `{"cmd":"export-history","filter":{"onlyFail":bool,"src":"all|ui|cli|pipe|auto|other|unknown"}}`；宿主重读与页面相同的最近 `READ_LIMIT=200` 条记录，按同一语义筛选，以 JSON Lines 写入 `<数据根>\logs\exports\operations-<epoch>.jsonl`。同秒重复导出自动加序号，不覆盖旧文件；先写同目录临时文件再原子改名，失败不留下半成品。
- 导出文件内容与页面当前筛选的记录集合一致：`onlyFail` 只保留 `ok=false`；`src=unknown` 包含缺来源和无法识别的来源，与页面 `srcValue()` 同口径。空筛选不生成空文件，返回 `ok:false,errorCode=environment,exportResult.path=null`。导出不会改写 `operations.jsonl`，也不发起网络请求；页面静态断言不存在 `fetch` / `XMLHttpRequest`。
- **线路改名使用独立命令** `{"cmd":"rename-line","id":"…","name":"新名称"}`。它只改 `config.json` 中该线路的 `name`：id、端点、连接方式、选中项和 `data\lines\<id>.json` 全部保持不变；重名或其他线路 id 冲突返回 `errorCode=conflict` 且零写盘，名称未变不重写配置。连接中拒绝。
- **`--set-line` 不能当改名复用**：现有 CLI 命令实际是“新增/更新一条线路的 id、名称和端点，并把该线路设为选中”，使用它改名会顺带改端点/选中项并做端口占用检查。T-17 因此新增 IPC 改名，没有改变 `--set-line` 的既有语义，也没有新增 CLI 改名参数。
- **“设为默认”复用既有 `use`**：页面把非选中行的动作显式命名为“设为默认”，点击只发送 `{"cmd":"use","id":"…"}`；宿主写 `config.json:selected`，下次启动和自动连接按该字段选线路。没有新增 `set-default-line` 第二套语义；选中行只显示“当前默认”，不出现指向自己的重复按钮。
- 改名结果由 `renameResult` 结束行内编辑：成功才收起输入框，失败保留草稿和输入焦点上下文；导出结果由 `exportResult` 结束，两者都由 `main.rs::merge_ui_command_reply()` 保留，无关 `status` 不清除。
- 最终验收：debug/release 串行全量各 **464 passed / 0 failed / 1 ignored**；真实 Edge **18/18 场景**（记录动作 13/13、线路动作 11/11，含连接中写动作门控）；五页 DOM **5/5**；隔离门 **14/14**；真实 WebView2 的 T-14 回归 **25/25**。证据位于 `C:\tc-rs-build\t17-evidence\`。
- **边界**：真实 WebView2 的系统剪贴板写入仍未原生验收；T-17 的复制成功/拒绝由真实 Edge 的剪贴板桩覆盖。T-14 的 25 项是回归，不是改名/导出的原生点击验收。导出只覆盖页面可见的最近 200 条，不是 `operations.jsonl` 的 500 条全量。

### 4.11 T-18 服务商三态结论与备用线路检查（**已落地**）

- 服务商状态由 `ipc.rs::providers_payload` 从**当前线路的真实引擎配置**投影：必须存在匹配的本机 SOCKS 出站、对应 tag 在 selector members 中，才具备被选中的资格。只写注册表或只投影出站都不等于已生效。
  - `effective`：当前日常出口和/或交易出口确实指向它。`effectiveRole=daily|trade|daily+trade` 分别表示“日常出口”“仅交易出口”“日常+交易出口”。只有交易出口指向时必须明说“日常上网不经过它”。
  - `pending`：入口已写入当前线路，但当前两个出口都没有选它。登记后通常处于此态。
  - `unavailable`：没有当前线路、引擎配置不可读、缺少日常入口、端口与登记不一致、selector 缺成员等；必须给出具体原因。
- 字段缺失（旧宿主）时页面只显示“状态未知”，不推断为已生效，也不阻断原有的“设为日常出口”动作。设置页与概览摘要共用同一 `effectiveState/effectiveRole`，不各算一套。
- 切换日常/交易出口仍走既有 `exit-set`，且仍受连接中门禁：**本版没有实现运行时热切换**，不能宣称满足“切换日常出口不需要重启连接”。本轮只保证配置结论与出口选择一致；设为日常出口后宿主回包会重读并更新服务商结论。
- `measure-backup` 只在以下条件全部成立时执行：当前连接证据为 `Connected`；当前接管方式是系统代理而非 TUN；目标 id 存在且不是当前线路；目标线路有 `tc-transport` VLESS 出站且 `server` 是 IP 字面量、端口合法。它只对目标 TCP 端口做一次 `connect_timeout`（最多 1 秒），不启动引擎、不改系统代理、不建立隧道、不切换线路、不落盘、不新增常驻线程或进程。
- 未连接、TUN、域名目标、无 TCP 中转均返回 `environment` 及 `backupResult.message`，不伪造 `reachable`。成功只代表 TCP 端口可达，`scope=tcp-connect`、`notCurrentLatency=true`，页面必须显示“不等于当前响应”；它不能与当前线路的 HTTPS 响应直接比较，也不证明隧道认证或出口归属。
- 页面只为非当前线路显示备用检查按钮；未连接显示“连接后检查”并禁用，TUN 显示“TUN 下不可测”并禁用。检查结果只来自 `backupResult`，成功后保留在内存中，断开后清除。
- 最终验收：debug/release 串行全量各 **468 passed / 0 failed / 1 ignored**；真实 Edge **20/20 场景**（服务商 **9/9**、备用 **10/10**）；五页 DOM **5/5**；隔离门 **14/14**；真实 WebView2 的 T-14 回归 **25/25**。证据位于 `C:\tc-rs-build\t18-evidence\`。
- **边界**：`effective` 是配置级结论，不证明外部客户端在线、端口实际可服务或流量出口归属；没有做服务商端口的实时连通性探测。备用检查只支持 IP 字面量的 TCP 兼容中转，不支持域名、WireGuard/UDP 或 TUN 下的物理网卡绑定；没有自动切换编排，没有新增“检查并切换”按钮或确认层，也没有“变差横幅”。

### 4.12 T-19 主题三档、可访问性与小交互一致性（**已落地**）

- 主题是**页面本地显示偏好**，三档 `system|light|dark`，存在 `localStorage['tcrs.theme']`（落在 `data\WebView2` 的浏览器用户目录），不写 `config.json`、不进 `operations.jsonl`、不发 IPC。缺失或非法值一律按 `system` 处理；选中 `system` 时监听 `prefers-color-scheme` 变化并即时切换，同时说明当前实际是深色还是浅色。
- **页面必须从稳定 origin 提供**：宿主用自定义协议（Windows 映射为 `http://tc.ui`）伺服页面并导航到 `http://tc.ui/index.html`，不得改回 `with_html`——WebView2 的 `NavigateToString` 是 opaque origin（`origin=null`），`localStorage` 会抛 `SecurityError`，主题与页面记忆永远存不住，且被页面的 try/catch 吞掉、file:// 夹具测不出来。源级防回退断言 `t19_page_origin_is_stable_so_local_storage_works` 钉住这一约束。
- `data-theme` 必须由 `<head>` 内的引导脚本 `#tc-theme-boot` 在样式表之前设定，body 末尾只做同步与文案更新。判定标准不是“重载后是深色”，而是**设置 `data-theme` 时 `document.body` 仍为 null**：这样首帧不可能先用浅色画一遍。
- 可访问性：导航状态、概览状态标题、连接/自检/延迟/线路/分流/刷新/恢复等操作提示均为 `role=status`、`aria-live=polite`（状态标题带 `aria-atomic`）；纯装饰圆点 `aria-hidden=true`。TUN 不可用原因用可见文本说明并给出出路，不依赖 hover 或仅变灰。
- 托盘不可用时，“关窗后缩到托盘”开关必须禁用并写明“当前不生效；关窗仍会断开并退出”；托盘恢复后开关重新可用。禁用原因是可见文本，不是 tooltip。
- 记录页刷新：点击后 200 ms 内出现“刷新中…”并禁用按钮，只发一次 `history`；进行中连点不得产生第二次读取；`history` 回包后恢复。刷新是本地读取，不伪造新记录。
- 上次所在页存在 `localStorage['tcrs.page']`，重载后恢复；非法值回概览。切页必须清除线路页的内联删除确认、改名草稿和同名导入冲突层，避免回到线路页误点“确认删除”。
- 键盘：线路行删除确认与改名框按 `Esc` 取消并把焦点还给触发按钮，改名框按 `Enter` 提交；导入冲突层按 `Esc` 关闭并把焦点还给导入按钮；导入输入框按 `Enter` 提交。`Esc` 不得关闭正在进行的连接/断开确认之外的东西。
- 最终验收：debug/release 串行全量各 **470 passed / 0 failed / 1 ignored**；真实 Edge **22/22 场景 / 229 项断言**（主题 **10/10**、交互一致性 **17/17**）；五页 DOM **5/5**；隔离门 **14/14**；真实 WebView2 的 T-14 回归 **25/25**。真实宿主的持久化用「探针向 UDF 播种偏好 → 启动产品 → 截屏」证明：播种深色后窗口平均亮度 21.1 并停在记忆的记录页，全新 UDF 对照组 246.6 停在概览页。证据位于 `C:\tc-rs-build\t19-evidence\`。
- **边界**：这是页面级可访问性接线与抽样对比度（深色正文 17.01、主按钮 5.17），不是完整 WCAG 审计；没有跑屏幕阅读器，也没有验证 Windows 高对比度/强制色模式。主题与页面记忆按 Windows 用户 + 浏览器数据目录保存，清除 `data\WebView2` 会一起丢失；不跟随账号漫游。键盘路径只在真实 Edge 的夹具页验证，真实 WebView2 只回归了 T-14 的连接流程。

### 4.13 连接方式三档：自动 / 标准 / 兼容（**r31 落地**）

界面（旧版原样前端）一直有三段：自动、标准、兼容。r31 之前宿主只有两档，点「自动」只弹一句「预览版暂不支持」；同时线路卡片的 `ProfileSource` 被硬编码成 `""`，导致卡片副标题永远写「自动选择」、抽屉永远高亮「自动」——即使用户已经固定过连接方式。本节记录修正后的事实。

**判定顺序（唯一口径，`config::LineConfig::effective_transport()`）**

1. `config.json` 的 `lines[].transport`（用户固定，`udp|tcp`）——用户的选择永远优先；
2. 否则 `lines[].verified_transport`（**这条线路上真的连通过的方式**，只有连接成功且自检通过才写）；
3. 否则标准连接（Udp）。默认 Udp 是 旧版的 `PolicyDefault`：少一层中转、少一个服务器参数、失败面最小。

**字段**

| 字段 | 位置 | 语义 |
|---|---|---|
| `lines[].transport` | `config.json` | 用户固定。`skip_serializing_if=none`：没固定过就**不写这个键**（不能写空串/null） |
| `lines[].verified_transport` | `config.json` | 已验证依据。仅连接成功且 `selfcheck` 通过时写入（幂等：同值不写盘）；连接失败时清除；**重新导入同一条线路会清空**（线路参数换了，旧依据不成立），但不抹用户的 `transport` |
| `transportSelected` | `lines` 回包 | 是否有用户固定 |
| `transportVerified` | `lines` 回包 | 是否有已验证依据 |
| `Profile` | 快照 `Lines[]` | **生效值**（上面三步的结果），不是原始固定值 |
| `ProfileSource` | 快照 `Lines[]` | 固定 → `UserChoice`；否则 `Auto`。前端据此决定副标题「已固定/自动选择」与抽屉高亮 |
| `AutomaticNeedsCheck` | 快照 `Lines[]` | `自动 && 无依据`。此时页面那句「已选自动，请先测试线路以确定下次使用的方式」才是真话（本产品的测速必须先有连接，实际上就是「先连一次」） |

**边界（如实记录，不要当成已实现）**

- **不是 旧版的完整自动选路**：旧版的 `ProtocolSelection.psm1` 是候选探测 + 网络指纹 + 证据过期 + 成对性能排名；本实现只做「采用这条线路已验证成功的方式」。**换网络后不会自动重测**。
- `auto` + 已验证值为 Tcp、但线路文件此刻已不能派生兼容参数时，本次连接会明确报「连接方式不可用」并清掉依据，下一次回落到标准连接——不做静默降级。
- 「重新导入清依据」的写入口是 `upsert_line`（`src/main.rs`），新增字段必须在那里一并搬运，否则注释说的和做的不一致。
- 线路详情里的「连接方式与网络…」表单（`FormState::line_settings`）仍只有标准/兼容两档，没有「自动」段；它显示的是生效值，所以不会撒谎，但那里改不了自动。

### 4.14 邀请其他电脑：服务器侧的契约（**r32–r38 落地**）

「邀请」不是一个界面动作，而是**服务器上的一个身份 + 一个接收服务**。本版没有搬 旧版的 `linux/*.py`：那套依赖它自己的服务器状态模型（`/var/lib/tradechannel/manifest`、`management/state.json`、journal 与 plan 校验），而本版按 WireGuard 直管（`/etc/wireguard/tc*.conf`），两套账混用只会互相覆盖。落地的是**一份自包含脚本**（`assets/tc-pair.py`，只用 Python 标准库 + `openssl` 命令），由 `src/pairhost.rs` 经 SSH 上传并调用。

**服务器侧目录与文件**

| 路径 | 权限 | 作用 |
|---|---|---|
| `/var/lib/tradechannel/pairing-rs/` | 700 | 根。与旧版的 `pairing-online` **故意不同**，允许两版并存 |
| `signing.pem` | 600 | 管理私钥（RSA-3072）。**永不出这台机器**：客户端拿到的是签好的码，不是签名能力 |
| `signing-public.json` | 644 | 管理公钥 JWK（`{kty,n,e}`），作为 `ManagementSigningPublicKey` 写进两份 JWS |
| `tls.crt` / `tls.key` | 644 / 600 | 18443 用的自签证书，825 天。客户端只 pin 它的 DER 指纹，不看 CA 链 |
| `server.json` | 600 | 服务器身份：`Endpoint`、`NodeId`、`RemoteOwnerId`、`ServerPublicKey`、`ManagementFingerprint` |
| `invites.json` | 600 | 邀请记录：`State`（Open/Consumed/Cancelled/Expired）、`Token`、`SignedDescriptor`、`ServerBinding`；消费后再记 `RequestId`/`DeviceId`/`ClientPublicKey`/`ClientAddress`/`RecipientJwkDigest`/`SignedAuthorization` |
| `/etc/systemd/system/tc-pair.service` | 644 | 18443 接收服务。用 `restart` 而非 `start`：脚本升级后旧进程不会继续跑旧代码 |

**两个指纹（不要混）**

| 值 | 算法 | 用途 |
|---|---|---|
| `ManagementFingerprint` | `SHA256:` + **标准** base64（无填充，43 字符）的 `sha256('{"e":"…","kty":"RSA","n":"…"}')` | 邀请码里的 `m`，与 `RsaJwk::fingerprint()` 逐字节一致 |
| `TlsSha256` | 64 位小写 hex 的 **DER** 哈希 | 邀请码里的 `t`。**不是 PEM 文件的哈希**——客户端拿的是握手里的 DER，这个区别只有真连一次才会暴露 |

**邀请码与两份 JWS**

- 码 = `TCI1.` + base64url(JSON)，字段**恰好**八个：`v/h/p/i/k/t/m/e`（版本 / 主机 / 端口 / 邀请 id / 令牌 / 证书指纹 / 管理身份指纹 / 过期秒）。
- `TradeChannel.PairInvite`（13 个必填字段）与 `TradeChannel.OnlineInvite`（10 个必填字段，内嵌前者）都是 RS256 紧凑 JWS，签名者同一把管理私钥。
- `RetryUntilUtc` = 过期 + 120 秒，与 `descriptor::verify` 的容忍窗口一致。

**18443 的两个接口**

```
GET /v1/invitations/<邀请 id>
Authorization: Bearer <邀请码里的 k>
→ 200 {"Ok":true,"Data":{"Status":"InvitationReady|RetryOnly|Cancelled|Expired","SignedDescriptor":"<在线邀请 JWS>"}}
→ 失败 {"Ok":false,"Code":"InviteNotFound|Forbidden|InvalidState"}

POST /v1/invitations/<邀请 id>/consume
Authorization: Bearer <邀请码里的 k>
{"PairRequest":"<RS256 JWS>"}
→ 200 {"Ok":true,"Data":{"Status":"Authorized","RequestId","RequestDigest","EncryptedAuthorization"}}
→ 失败 {"Ok":false,"Code":"…"}（见 §4.15）
```

要求 `Content-Type: application/json`、必须有 `Content-Length`（**不允许 chunked**）、只走 TLS 1.2——三条都是客户端 `pairing::http` 的硬性判定。令牌比对用常数时间比较。

**HTTP 侧状态词表（r38 修正）**

状态文件里的 `State` 是服务器自己的状态机（`--invite-status` 与界面读它），HTTP 侧是另一套词，映射只在 `tc-pair.py::client_state` 一处：

| 状态文件 | HTTP `Status` | 客户端处置 |
|---|---|---|
| `Open`（未过期） | `InvitationReady` | 首次接入；没有原申请就新建一份 |
| `Consumed` | `RetryOnly` | 只允许**同一份申请**（同一 `RequestId`）重试；本机没有原申请时报 `InviteConsumed` |
| `Cancelled` | `Cancelled` | `InviteCancelled`：「这张邀请码已被服务器主人作废」 |
| `Expired` | `Expired` | `InviteExpired`：「邀请码已过期，请让对方重新生成一张」 |

认不出的词不猜：`pairing::join::check_status` 对表外状态一律报 `InvalidOnlineResponse`（「服务器返回了不认识的邀请状态：xxx」）。一次性由「服务器只接受同一 `RequestId` 重试」保证，不靠状态词自证。

**升级路径（r38 新增）**：`assets/tc-pair.py` 是 `include_str!` **编译期内嵌**的，服务器上跑的是上次 `--invite-init` 上传的那一份。所以「装了新客户端、没重开接收服务」是必然会出现的一种状态，那时对面回的还是旧词。客户端对旧词的处置必须能照做，不能是无解的协议错误：

| 旧脚本回的 | 客户端处置 | 页面上的出路 |
|---|---|---|
| `Open` | `InviteServerOutdated`：「服务器上的邀请服务还是旧版本，请在管理端重新执行一次「开启接收服务」，再回来点加入」 | 重试（码本身没错，别换码） |
| `Consumed` | 等同 `RetryOnly`：本机有原申请就继续，没有就报 `InviteConsumed` | 重新输入 / 回原申请电脑 |

`--invite-check` 不跑 `check_status`，它把服务器回的状态词原样打印；词表改名后它会直接显示 `InvitationReady` / `RetryOnly`，不需要适配。

**错误码分诊表（r41）**

同一个「加入失败」在页面上有不同的出路，不能都念成「这一步没有完成」。按**谁能产生**分组——这一点有实际用处：**跑出「服务器才能产生」的码，本身就说明这次真的联网成功了**（r41 之前有人拿回环地址当黑洞做超时实验，结果先被 `InvalidOnlineHost` 挡掉，得了个假绿灯）。

| 错误码 | 产生方 | 触发条件 | 页面出路 |
|---|---|---|---|
| `Forbidden` | 只有服务器 | 令牌不匹配（码里的 `k` 与记录不符） | 重新输入 |
| `InviteNotFound` | 只有服务器 | 这张码不在这台服务器上 | 重新输入 |
| `InviteCancelled` | 只有服务器 | 已被主人作废 | 重新输入 |
| `InviteMismatch` | 只有服务器 | 申请的 `InviteId` 或 `ServerBinding` 与这张码不一致 | 重新输入 |
| `PairingMismatch` | 只有服务器 | 申请摘要不符；重试时接收密钥换了 | 重新输入 |
| `InvalidPairRequest` | 只有服务器 | 申请不是三段式 RS256、编码不规范、字段缺失、id/公钥形状不对 | 重新输入 |
| `InvalidRequest` | 只有服务器 | 正文不是 JSON、缺 `Content-Length`、用了 chunked | 重新输入 |
| `WireGuardApplyFailed` | 只有服务器 | 改完 wg 配置后 `wg syncconf` 失败（**conf 已逐字节回滚**） | 重试 |
| `TunnelExhausted` | 只有服务器 | 网段内没有空闲地址了 | 找管理员 |
| `InvalidState` | 只有服务器 | 服务器记录残缺（如已标 `Consumed` 却缺原授权） | 找管理员 |
| `OnlineInviteExpired` | 只有本机 | 按码里的 `e` 判已过期（不联网就知道） | 重新输入 |
| `InviteExpired` | **两端** | 服务器按状态判过期；或本机时钟比服务器**慢 5 分钟以上**（`pairing.rs:808`：签发时间在未来超 300 秒，判「邀请时间不可信」） | 重新输入（若是后者，先校时） |
| `InviteConsumed` | **两端** | 服务器：已消费且 `RequestId` 不同；本机：GET 回 `RetryOnly` 但本机没有原申请（直接短路，不打服务器） | 回原申请电脑 |
| `InviteServerOutdated` | 本机综合 | 服务器回旧词 `Open`，说明对面还是旧脚本 | 重试（先重开接收服务） |
| `OnlineConnectionFailed` | 只有本机 | 连不上 18443（防火墙、丢包、端口被占） | 重试 |
| `OnlineTlsPinMismatch` | 只有本机 | 证书 DER 指纹与码里的 `t` 不一致 | 重新输入（码可能被换过） |
| `OnlineRedirectRefused` | 只有本机 | 服务器回了 3xx（固定指纹的传输层不接受重定向） | 找管理员 |
| `InvalidOnlineHost` | 只有本机 | 码里的入口是回环地址或非法 IPv4 | 重新输入 |
| `InvalidOnlineResponse` | 本机综合 | 回包不是本协议：表外状态词、缺 `Ok`/`Data`、JSON 不合法 | 重新输入 |

两条口径：

- **`NotFound` 客户端拿不到**：传输层先要求信封里的 `Ok` 是布尔，没有信封就落成 `InvalidOnlineResponse`。所以真看到 `NotFound`，一定是服务器回了信封锁——别把它当「路径写错了」。
- **过期有两条支路，别混**：本机按码里的 `e` 判（`OnlineInviteExpired`，不联网）；服务器按状态文件判（`InviteExpired`）。两者不一致只可能来自**本机时钟偏差**——先校时，再怀疑码。

**命令**

| 命令 | 写入 | 作用 |
|---|---|---|
| `--invite-init <spec>` | 服务器 + 本机 | 生成/复用管理身份与证书，装 `tc-pair.service`。**幂等**：私钥存在就不重建（重建等于把已发出的邀请码全作废）。**并打印这一次有没有重传脚本**（`已上传新脚本` / `已是最新，未重传`）——旧服务器上页面会提示「重新执行一次开启接收服务」，用户得能看出那一步到底成没成 |
| `--invite-create <spec> [--lifetime 秒] [--device 名字]` | 服务器 | 签一张邀请，回码。本机侧**再过一遍** `parse_code`，并比对本机记录的身份指纹 |
| `--invite-status <spec> --invite-id <id>` | — | 查状态。**已消费的邀请**还会给出 `deviceId`、`clientPublicKey`、`clientAddress`——撤设备就是靠这三项指认「是哪一台、占了哪个地址」；未消费时这几项不打印，免得留三行空白 |
| `--invite-cancel <spec> --invite-id <id>` | 服务器 | 作废。已消费的邀请不能作废（那要撤设备） |
| `--invite-check <邀请码>` | — | 去 18443 读一次并验签。**这是「这张码能不能用」的唯一权威判断** |

本机身份记录在 `data/invites/<服务器记录 id>.json`（**按服务器**，不按线路：一台机器多条线路共用一个管理身份）。

**界面接线（r33，r34/r35 修正）**

`Invite` 快照由宿主状态机投影，`invite` 意图收 15 种 `Phase`（`Begin`/`Target`/`Choose`/`CreateNew`/`Cancel`/`CancelRetry`/`Retry`/`Recheck`/`Refresh`/`Rearm`/`Copy`/`Reveal`/`Offline`/`OpenServer`/`Close`）。四条硬约定：

1. **完整邀请码不进快照**。快照里只有 `CodePreview`（前 18 个字符 + 总长度），完整码只在用户点「显示/复制」时经 `Step::Script` 单独递一次（`window.__tcPush({Type:'inviteCode',Code})`，复用页面既有的消息入口，r33 时 `web/` 零改动）。快照每秒重推、会进日志、会被截图，一次性凭据不该出现在那里。
2. **作废之后立刻丢掉码**：`Cancel` 回包成功即 `code.clear()`，再点「显示」拿不到东西——否则「复制」会复制出一张废码。
3. **`CanInvite` 是算出来的**，判据是 `servers` 命令给出的归属（线路文件 `outbounds[].server` == 服务器记录 `host`），缓存 **10 秒**，且**只缓存 `ok=true` 的结果**：失败回包里也有一个空 `servers` 数组，照抄会把「读失败」当成「真的没有服务器」，入口就灰了整整一个缓存周期（r34 修的就是这条）。没有归属的线路不给入口，因为点进去只会得到「这台服务器不归你管」。
4. **一次只认一台**：`Choose` 开一轮全新会话（旧 `InviteId`/`State`/码全部退出投影）；`Target` 的 `Id` 是线路、`Value` 是服务器记录，两个都存——`LineId` 决定 `invite-create` 签哪台，`ServerId` 决定结果卡挂在哪条归属上。失败后的 `Retry` 重发**失败的那一条命令**（签发失败再签、查状态失败再查），不是笼统换个动作。

r33 时 `web/` 零改动；**r35 的页面测试抓到 4 处前端真缺陷并修掉（`web/app.js` 首次改动）**：多服务器入口原来只发 `navigate`（宿主不建会话，页面可能沿用上一张邀请）→ 改发 `invite/Choose`；`Target` 原来只回服务器、`Id` 为空（宿主退回当前线路，多服务器时会签错）→ 成对回传；「隐藏」原来又向宿主发 `Reveal` → 只在页面里丢弃明文；收到一次性 `inviteCode` 原来只写 `input.value`（按钮停在「显示」）→ 改为 `render()`。

**UI 侧回包白名单（r36，真机才暴露的一类集成缺陷）**

宿主对页面的回包不是命令原样，而是「完整状态 + 白名单增量」（`main.rs::merge_ui_command_reply`）。新增命令时必须同时把回包键登记进白名单，否则**命令真的跑了、页面却永远收不到**：

- `servers` 漏登记 → 快照里的归属表恒为空 → 每条线路 `CanInvite=false`，邀请入口永远是灰的（页面测试用假 fetch，抓不到）。
- `invite` 漏登记 → 长命令回包进不了状态机 → 页面永远停在「正在生成邀请码」，不报错也不超时。

两条都在 r36 补齐，并由 `webview_merge_keeps_the_servers_payload_for_invite_ownership` 钉住回包形状。真机验收脚本 `tests/r35_invite_ui.py`（25 项：入口可点 → 生成 → 预览不泄码 → 显示拿到完整码 → 复制进剪贴板 → 隐藏回预览 → 作废 → 页面不再持有码）。

**18443 可达性自检（r37）**

进邀请页（`Begin` / `Target`）时宿主先跑一次 `invite-reachability`，结果进快照 `Invite.Reachability`：

| `Status` | 含义 | 页面 |
|---|---|---|
| `Checking` | 正在量（宿主刚发起） | 「正在检查 18443 能否连通」 |
| `Reachable` | TCP 通 + 带指纹校验的 TLS 握手成功 | 不显示横幅（没坏消息就不说话） |
| `Refused` | TCP 被拒 | 「连接被拒绝：请在云服务器防火墙放行 TCP 18443」 |
| `Timeout` | TCP 超时（包被丢） | 「没有响应：请检查防火墙」 |
| `TlsMismatch` | 握手证书与邀请码固定的 DER 指纹不符 | 「端口可能被其他服务占用」 |
| `TlsFailed` | 握手没完成 | 「加密握手没有完成」 |
| `NotInstalled` / `Unavailable` | 还没装邀请服务 / 地址解析不了 | 「检查没有完成，可以先复制邀请码试试」 |

三条边界：**只用假邀请探传输层**（令牌与 id 是占位），不读也不改邀请状态；**不通不挡生成**（码照样能出，页面只是先提醒）；`Recheck`/`Refresh`/`Rearm` 仍走各自命令，不自动重跑自检。

**边界（如实记录，不要当成已实现）**

- **`POST /v1/invitations/<id>/consume`** 已实现（r38）：见 §4.15。**但只在假 `wg` 上验过**——真机上「写 conf + `wg syncconf` + 新电脑真连上」这一段还没有人跑过。
- **离线邀请、「重新开启接收服务」的自动判定**：未做。`Recheck` 走的是 `invite-status`（真查服务器），`Rearm` 走 `invite-init`（真重装服务），但「防火墙没放行」这类失败仍要用户自己判断。`Offline` 只回一句「还没做」。
- `--invite-check` 判不了「主机是域名」的记录：邀请码里的入口只收规范写法 IPv4，服务器记录写域名时 `--invite-init` 会直接拒绝并让人改回 IP。

### 4.15 `POST /consume` 施工图（**r38 落地，仅在假 wg 上验过**）

客户端侧早就写好了（`pairing::join` + `pairing::http::post_consume`）；r38 补的是服务器那一段。下面这些数字都是客户端**硬校验**，错一个字节就报 `OnlineAuthorizationMismatch` / `InvalidEncryptedAuthorization`。

**请求**：`POST /v1/invitations/<id>/consume`，`Authorization: Bearer <码里的 k>`，正文 `{"PairRequest":"<RS256 JWS>"}`（必须有 `Content-Length`，不许分块）。

| 项 | 值 |
|---|---|
| 申请 JWS 载荷 | `SchemaVersion=1`、`Kind=TradeChannel.PairRequest`、`InviteId`、`ServerBinding`、`ClientRequest{RequestId,DeviceId,CreatedAtUtc,ClientPublicKey,AddressFamilies:["IPv4"]}`、`DeviceName`、`RecipientJwk{kty:RSA,n,e}`、`RequestDigest`、`RequestDigestAlgorithm=TC-ClientRequest-v1`、`CreatedAtUtc` |
| 申请签名 | RS256，验签公钥 = `RecipientJwk`（**先验签再算摘要**） |
| `RequestDigest` | `sha256("1\nTradeChannel.ClientRequest\n<RequestId>\n<DeviceId>\n<CreatedAtUtc>\n<ClientPublicKey>\nIPv4")` 的小写 hex |
| 回包信封 | `{"Ok":true,"Data":{"Status":"Authorized","RequestId","RequestDigest","EncryptedAuthorization"}}` |
| 授权明文 | RS256 JWS（管理私钥）：`Kind=TradeChannel.PairAuthorization`、`InviteId`、`RequestId`、`RequestDigest`、`ClientPublicKey`、`RequestDigestAlgorithm`、`ServerBinding`（**与邀请逐字节相同**）、`ClientResponse` |
| 授权封装 | JWE 紧凑 5 段：header `{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","cty":"TC-Pairing-v1"}`；CEK 64 字节（前 32 = HMAC-SHA512 密钥，后 32 = AES-256 密钥）；IV 16；`tag = HMAC-SHA512(mac, AAD‖IV‖CT‖AL)[:32]`，`AAD = b64u(header)`（RFC 7516 §5.1：只有受保护头参与认证；旧版的 jose-jwt 与服务器脚本同口径） |
| `ClientResponse` | `Kind=TradeChannel.ClientResponse`、`Status=Authorized`、`RequestId`/`DeviceId`/`ClientPublicKey` 与申请一致、`ServerPublicKey`、`ClientAddress=<网段内空闲>/32`、`ServerAddress=<网段+1>/<prefix>`、`TunnelSubnet`、`AllowedIPs=["0.0.0.0/0"]`、`AddressFamilies=["IPv4"]`、`PublicEndpoint`、`PersistentKeepalive=25` |

**批准模型**：自动批准。邀请码本身是一次性、带有效期、由管理私钥签发的授权凭据，签发它的就是设备主人；产品没有「等主人点同意」的通知通道，再插一步人工确认只会让邀请变成必须两人同时在线。边界写清楚：一次性（`Consumed` 后 GET 转 `RetryOnly`，只允许**同一份申请**重试）、到期即废、主人随时可撤设备。

**服务器要做四件事**：分配隧道地址（跳过网络/服务器/广播与已占用）、把公钥加进 `wg`（改 conf 后 `wg syncconf`，失败要回滚 conf）、把邀请标记 `Consumed` 并记下 `RequestId/DeviceId/ClientAddress`、回上面那个信封。

**r38 实现要点（`assets/tc-pair.py`）**

| 环节 | 做法 |
|---|---|
| 校验顺序 | 令牌 → 状态（`Cancelled`/`Expired` 提前拒）→ 正文长度与形状 → **先验签**（公钥取申请里的 `RecipientJwk`）→ 再算摘要 |
| 形状校验 | `RequestId`/`DeviceId` 必须是小写 UUID、`ClientPublicKey` 必须是 44 位 base64——这两个 id 与公钥会写进 `wg` 配置，验签只证明「出自持有该私钥的一方」，不证明它不含换行 |
| 地址分配 | 从网段+2 起（+0 网络、+1 服务端），到广播地址前止，跳过所有 peer 的 `AllowedIPs`；按低到高挑，不随机 |
| 改配置 | 按**公钥**删旧段再追加新段（不整段重写：整段重写会把别人的设备一起踢掉）；`wg-quick strip` → 临时文件 → `wg syncconf` 热更新，不重启接口 |
| 回滚 | `syncconf` 失败或状态没写成，都把 conf 逐字节还原：留下「配置里有、接口上没有」的设备会让重试误判为「已加过」 |
| 幂等 | 同一 `RequestId` 重试复用已分配的地址与已签的授权（JWS 确定性，重新封装只换 CEK/IV），配置里同一个公钥始终只有一段 |
| 并发 | 消费全程持一把锁：两个请求同时进来会分到同一个地址、或者互相覆盖配置 |

**服务器侧错误码**（客户端读 `Code`，不看状态码）

| `Code` | 场景 |
|---|---|
| `Forbidden` | 令牌与邀请码里的 `k` 不符 |
| `InviteNotFound` | 这张邀请码不在这台服务器上 |
| `InviteCancelled` / `InviteExpired` | 已作废 / 已过期 |
| `InviteConsumed` | 已被**另一台**电脑用掉（同一 `RequestId` 重试不算） |
| `PairingMismatch` | 摘要不符，或重试时的接收密钥与首次不同 |
| `InviteMismatch` | `InviteId` / `ServerBinding` 与这张邀请不一致 |
| `InvalidPairRequest` | 签名、字段、协议版本、标识形状不对 |
| `InvalidRequest` | 正文缺 `Content-Length` / 分块 / 不是 JSON / 过长 |
| `WireGuardApplyFailed` | `wg-quick strip` 或 `wg syncconf` 失败（配置已回滚） |
| `ServerSubnetMissing` / `TunnelExhausted` | 读不到网段 / 网段没有空闲地址 |
| `MissingWireGuard` / `NotInitialized` / `MissingOpenSSL` / `SigningOperationFailed` / `InvalidState` | 服务器自身的环境或状态问题 |

**自测**：`python tests/r38_consume.py`（Windows / Linux 均可，只需 python + openssl）。它在临时 `TC_PAIR_ROOT` 上用假 wg 服务跑主链路、重放、地址分配、失败回滚与十余种反向用例，并用**独立实现**的客户端解 JWE 验授权。四个覆盖点 `TC_PAIR_WG_ROOT` / `TC_PAIR_WG_BIN` / `TC_PAIR_WGQUICK_BIN` / `TC_PAIR_IP_BIN` 只用于让测试机跑起来，**生产默认值仍然是 `/etc/wireguard` 与 `wg`**。

**还没验的（别当成已验）**：真机 `wg syncconf`、真机 `wg-quick strip` 的输出形态、Rust 客户端对本服务的端到端加入（本轮不许跑 cargo）、地址耗尽（`/30` 网段）、并发两个请求。

**两条刻意的边界**：① 隧道接口没起来时 `wg syncconf` 会失败，consume 报 `WireGuardApplyFailed` 并回滚 conf，**不自动** `systemctl start`（那会把「服务器隧道坏了」变成「悄悄替你重启网络」；部署脚本 `deploy.rs` 才有权做这件事）。② 邀请过期后 `descriptor::verify` 先一步失败，所以 `RetryUntilUtc` 那 120 秒的宽限在客户端侧实际用不到——服务器侧同样按「过期即拒」处理，两边表现一致，但那个字段目前只是记录值。

**当前还差的一步（同一批修）**：GET 的状态词表必须是 `InvitationReady` / `RetryOnly`，而现在服务器回的是 `Open` / `Consumed` —— 客户端的 `check_status` 只认前两个，所以**新电脑今天连「校验邀请」这一步都过不了**。这条比 consume 更靠前，先改它。

### 4.16 部署中心：记录、状态与恢复（**r44–r50 落地**）

部署是这条产品里**唯一一件失败代价高于重连**的事：装错了要登服务器收拾。所以它不是一条长命令，而是**一份磁盘上的记录 + 一个进程内的引擎 + 十条短命令**。记录是唯一事实，页面、管道、命令行都只是它的读者。

以下每条都能在代码里对上（`src/deploystore.rs`、`src/deployrun.rs`、`src/deployengine.rs`、`src/ipc.rs`、`src/uiweb.rs`、`src/uiweb_form.rs`、`src/tray.rs`）。

#### 4.16.1 十条命令

回包统一是 `{ok, deployment:{…}}`。**`ok` 只表示这次请求被受理或读取成功，不表示部署已经做成任何事情。**

| cmd | 请求关键字段 | 成功回包 `deployment` 内容 | 落点 |
|---|---|---|---|
| `deployment-start` | `spec`（`[user@]host[:port]`，缺省 `root` / `22`）；`fingerprint` 可选；`password` 可选；`label` 可选（缺省「自建 · host」）；**`runId` 可选（r69：复用一条草稿，见 4.16.10）**；**`transport` / `tcpPort` / `serverName` 可选（r93，见 4.16.25）** | `RunId`、`Accepted:true`、`Queued:true`、`Message` | `src/ipc.rs::deployment_start_json` |
| `deployment-draft-save` **（r69）** | `spec`；`runId` 可选；`fingerprint` 可选；`label` 可选；**`transport` / `tcpPort` / `serverName` 可选（r93）**。**没有 `password` 这个字段** | `Run`、`RunId`、`Created`、`Message` | `src/ipc.rs::deployment_draft_save_json`、`src/deploystore.rs::MAX_DRAFTS`、契约 4.16.10 |
| `deployment-list` | 无 | `TasksRead`、`TasksReadError`、`UnreadableCount`、`Tasks[]`、`Deployments[]` | `deployment_list_json` |
| `deployment-get` | `runId` | `Run`（记录全字段 + 投影字段，见 4.16.4） | `deployment_get_json` |
| `deployment-continue` | `runId`；`password` 可选；`verifyOnly` 可选 | `RunId`、`Accepted`、`Queued`、`Message` | `deployment_continue_json` |
| `deployment-pause` | `runId` | `RunId`、`PauseRequested:true`、`Message` | `deployment_pause_json` |
| `deployment-cancel` | `runId` | `RunId`、`CancelRequested:true`、`Message`（**草稿另有 `Discarded:true`**） | `deployment_cancel_json` |
| `deployment-background` | `runId` | `RunId`、`Accepted:true`、`Message` | `deployment_background_json` |
| `deployment-export` **（r72）** | `runId`；`format` 可选（`markdown` 缺省 / `json`） | 顶层 `exportResult{ok,path,bytes,format,message}` | `src/ipc.rs::deployment_export_json`、`src/deployexport.rs` |
| `deployment-archive` **（r73）** | `runId`；`archived` 可选（缺省 `true`） | `RunId`、`Archived`、`Message` | `src/ipc.rs::deployment_archive_json`、`src/deploystore.rs::is_archived` |

**「短命令只代表受理」是这一节最重要的一条。** 这十条**全部**是短命令：只做「校验 → 落盘 → 投递意图」，SSH 由引擎线程去跑。因此：

- `ok:true` 不得被页面解读成「这一步做完了」「服务器已经改好了」「可以关窗了」。做成什么样，只能看 `deployment-get` / 快照里的 `Steps[].Status` 与 `State`。
- 反过来，**它们也不得被塞进 `is_long_command` / `operation_budget`**：进了长命令表就等于整个部署期间（十几分钟）独占事务门，其它所有命令排队等它。这是刻意的分层，不是漏配。
- 出现 `ok:true` 却什么都没发生（页面一直转圈）时，先查 `uiweb::UI_REPLY_KEYS` 里有没有 `deployment` —— 这个键漏登记已经犯过三次（`servers`、`invite`、`pairVerify`/`pairJoin`），表现都是一秒不报错地转圈。

**逐条的失败语义**

| cmd | 情况 | 回包 |
|---|---|---|
| `deployment-start` | `spec` 形状不对 | `ok:false` `errorCode:"usage"`，**不建记录** |
| | 写 `run.json` 失败 | `ok:false` `errorCode:"config"`，不投递 |
| | 宿主没有引擎句柄 | `ok:false` `errorCode:"environment"` |
| | 带 `runId` 但那条记录不是 `Draft` | `ok:false` `errorCode:"conflict"`（「这条任务已经开始过，不能当草稿用。」），记录一个字不改 |
| `deployment-draft-save` | `spec` 形状不对（含半截地址） | `ok:false` `errorCode:"usage"`，**一个字都不写**（见 4.16.10 J1） |
| | 带 `runId` 但那条记录不是 `Draft` | `ok:false` `errorCode:"conflict"` |
| | 已有 3 份不同服务器的草稿 | `ok:false` `errorCode:"conflict"`，文案「已经留着 3 份没填完的草稿，请先在任务列表里放弃一条。」 |
| | `load_all()` 不是 `ok`（含 `partial`） | `ok:false` `errorCode:"config"`：不知道**全部**草稿就无法去重（一条读不出来的记录可能就是同一台服务器的草稿）。**页面照常可以填** |
| | 写盘失败 | `ok:false` `errorCode:"config"`，页面**不阻断**填写，只追加一句提示 |
| `deployment-get` | `runId` 不是 36 位小写 UUID | `ok:false` `errorCode:"usage"`（形状校验同时是路径穿越防线：`../../etc/passwd` 走不到文件系统） |
| | 记录不存在 / 读不出来 / 命中禁用键 | `ok:false` `errorCode:"config"` |
| `deployment-continue` | 已是终态 | `ok:true`、`Accepted:false` —— **不是错误**：记录结束了，只能看 |
| | 已在 active 或 queued | `ok:true`、`Accepted:true`、`Queued:false` —— 幂等，连点只产生一次 |
| | 需要凭据且没有（本次没填、DPAPI 里也解不开） | `ok:false` `errorCode:"usage"`，不执行 |
| | 身份（指纹 / 计划摘要）与记录不符 | `ok:false` `errorCode:"conflict"`，同时把 `IdentityChanged` 写进记录；**绝不「先连上去看看」** |
| | **记录还是 `Draft`**（r69） | `ok:false` `errorCode:"conflict"`「这是一份草稿，请先打开表单确认地址和密码再开始。」——`continue` 会让引擎把它直接入队，那是一次没有密码的部署 |
| `deployment-pause` | 没有活动 pass | `ok:false` `errorCode:"environment"` |
| `deployment-cancel` | 已是终态 | `ok:false` `errorCode:"conflict"` |
| | **记录是 `Draft`**（r69） | `ok:true`、`CancelRequested:true`、`Discarded:true`：**删文件，不碰引擎**，也不写 `Cancelled`（见 4.16.10 J7）。删除失败 → `ok:false` `config` |
| | 有未决写 | `ok:true` 受理，`Message` 明说「要等它做完（并核对完）」——已发出的写命令不能中断 |
| `deployment-background` | 没有活动 pass | `ok:false` `errorCode:"environment"`：没有执行上下文时「转后台」是空话，页面会关掉而没人接着跑 |
| `deployment-export` | `format` 不是 `markdown`/`json` | `ok:false` `errorCode:"usage"`，**一个文件都不写**（导出一半的文件比没有更糟） |
| | 记录读不到 / 形状不对 | `ok:false` `errorCode:"config"`（同 `deployment-get`） |
| | 导出目录建不出来 / 写不进去 | `ok:false` `errorCode:"config"` |
| `deployment-archive` | 记录还在跑/排队/是草稿 | `ok:false` `errorCode:"conflict"`：把一条正在部署的任务藏起来，等于让用户失去对它唯一的入口 |
| | `archived` 不是布尔/`true`/`false` | `ok:false` `errorCode:"usage"`，记录一个字节不动 |
| | 写盘失败 | `ok:false` `errorCode:"config"` |

`deployment-continue` 的六步准入顺序（从磁盘重读 → 终态只打开 → 已在跑就幂等 → 凭据不足不执行 → 身份不符不执行 → 入队）见架构文档 §3.5。第 5 步的**联网**核对留在 pass 里（`deployrun::decide_resume`）：在短命令里发 SSH 就把「毫秒回包」变成「转圈十秒」。

#### 4.16.2 磁盘形状

一条记录一个文件：`<数据根>\deployments\runs\<RunId>.json`。`RunId` 是小写 UUID v4（36 位），**文件名就是它**，因此形状校验是写死的前置条件，不是建议。

写入走 `DeploymentStore::save`：临时文件（`.<name>.tmp-<pid>-<n>`，`create_new`）→ `write_all` → `sync_all` → `rename`，失败重试 8 次后报 `config`。单写者：只有引擎线程与创建/改判两处会写；页面永远不是写者。

| 字段 | 类型 | 缺省 | 语义 |
|---|---|---|---|
| `SchemaVersion` | 数字 | `1` | 结构版本。只增不改 |
| `Kind` | 字符串 | `"SpiderVPN.DeploymentRun"` | 记录类型。表外值不认 |
| `RunId` | 字符串 | 必填 | 小写 UUID，同时是文件名 |
| `AttemptNo` | 数字 | `1` | 第几次尝试。**重试不开新 RunId**，只加这个数 |
| `Label` | 字符串 | 「自建 · host」 | 记录名（页面标题用它） |
| `Target` | 对象 | — | `{Host, Port, User, ServerRecordId}`；`ServerRecordId` 可空 |
| `Identity` | 对象 | — | `{Fingerprint, AutoTrusted}`。`Fingerprint` 空 = 没核对过，**不是**「任意指纹都行」 |
| `Plan` | 对象 | — | `{Interface, UdpPort, Subnet, Mtu, ClientPublicKey}`。`ClientPublicKey` **非秘密** |
| `PlanDigest` | 字符串 | `""` | `sha256:…`，绑定「用户批准的就是这一份」 |
| `State` | 字符串 | `""` | 见 4.16.3。空/表外 = 未知 |
| `Step` | 数字或 null | `null` | `0..=4`。`null` = 步骤未知（界面不显示 `N/4`） |
| `Reason` | 对象或 null | `null` | `{Category, Class, Code, Text, At}`，见 4.16.3 |
| `NextAction` | 字符串 | `""` | 见 4.16.3。空/表外 = 没有可给的动作 |
| `Steps` | 数组 | `[]` | 四个 `StepRecord`（正常记录）；缺 `Steps` 时读成空数组，**不得**猜成 `Done`。见下 |
| `PendingOperation` | 对象或 null | `null` | 未决写，见下。**有它且 `Outcome:"Pending"` 时不得给任何重装入口** |
| `Attempts` | 数组 | `[]` | `{No, StartedAtUtc, FinishedAtUtc, FailedStep, ErrorCode, Reconcile}` |
| `Executor` | 对象或 null | `null` | `{InstanceId, Pid, HeartbeatAtUtc, Background}`。**它不是存活证据**，判活靠单实例互斥 |
| `CreatedAtUtc` / `StartedAtUtc` / `UpdatedAtUtc` / `FinishedAtUtc` | 字符串或 null | `null` | 秒级 RFC3339 UTC |
| `Revision` | 数字 | `0` | 单调递增。**`0` = 未知，不是「第 0 版」** |

`StepRecord`：`{Index, Name, Status, StartedAtUtc, FinishedAtUtc, Evidence, Error}`。`Evidence` 是非秘密证据（`arch` / `listenPort` / `lines` …），`null` = 没有证据、详情页那一行不显示，**不推断**。

`PendingOperation`：`{Kind, AttemptNo, StartedAtUtc, VerifyBy, PlanDigest, ClientPublicKey, Outcome}`。

`Reason`：`{Category, Class, Code, Text, At}`。`Text` 是人话，**不得含任何秘密与命令原文**；`Code` 是机器码（脚本 `TC_ERROR` 原值或内部码如 `TransportNotListening`）。

#### 4.16.3 词表（唯一定义处：`src/deploystore.rs`）

**`State`（8 个）**：`Draft`、`WaitingUser`、`Queued`、`Running`、`Paused`、`NeedsAttention`、`Complete`、`Cancelled`。

- `WaitingUser` 的判据是「**没有发生过失败**，只是在等人输入」；因为凭据失效导致一步失败，是 `NeedsAttention` + `AccessRequired`。
- `Running` 的唯一定义是 `run.state == "Running"` **且** 引擎 `active` 里有这个 `RunId`（`deployrun::is_running`）。崩溃之后引擎里必然没有它，所以崩溃后 `Running` 不可能为真 —— 这条判据存在的理由就是「不允许页面在崩溃后继续显示正在跑」。
- 终态只有 `Complete` / `Cancelled`。表外状态一律视为未知，**不得**当成 `Running` 或 `Complete`。

**转换白名单**（`deployrun::transition_ok`，表外一律拒绝）：

| 从 | 允许到 |
|---|---|
| `Draft` | `WaitingUser`、`Cancelled` |
| `WaitingUser` | `Queued`、`NeedsAttention`、`Draft`、`Cancelled` |
| `Queued` | `Running`、`NeedsAttention`、`Cancelled` |
| `Running` | `Complete`、`NeedsAttention`、`Paused`、`Cancelled` |
| `Paused` | `Queued`、`NeedsAttention`、`Cancelled` |
| `NeedsAttention` | `Queued`、`WaitingUser`、`Complete`、`Cancelled` |
| `Complete` / `Cancelled` | **无**（再添加是新 `RunId`，绝不复用旧 `RunId`） |

**`Reason.Category`（7 个）**：`Failed`（已知失败）、`OutcomeUnknown`（写过了但结论不知道，**不允许据此重放**）、`NeedsRecovery`（需修复，例如配置损坏，不猜不覆盖）、`IdentityChanged`（指纹/摘要与记录不符）、`AccessRequired`（凭据缺失或解不开）、`Interrupted`（检查点之间被打断，没有未决写）、`Partial`（部分完成）。

**`StepRecord.Status`（7 个）**：`Pending`、`Running`、`Done`、`Failed`、`Unknown`、`Partial`、`Skipped`。**只有 `Done` 计入 `N/4`**，而且 `N` 是 `Done` 的**个数**不是前缀长度——部分完成时可能 0、1、2 都是 `Done` 而中间某步 `Failed`，用前缀长度会把已经做成的步骤抹掉。

**`NextAction`（11 个）**：`OpenForm`、`EnterCredentials`、`ConfirmFingerprint`、`ConfirmPlan`、`RetryStep`、`Reconcile`、`CompleteCompatible`、`ViewLine`、`WaitQueue`、`RefreshRecords`、`None`。表外值 → 只允许「查看任务」，不给任何写动作入口。

**`PendingOperation` 三件事**

| 维度 | 取值 | 含义 |
|---|---|---|
| `Kind` | `UdpInstall` / `TransportInstall` / `AddPeer` | 哪一种写 |
| `VerifyBy` | `ProbeUdpState` / `ReadTransport` | 用哪个**只读**探针核对 |
| `Outcome` | `Pending` / `Applied` / `NotApplied` / `Unknown` | 结论。空/表外 = 不知道结论（不猜） |

`Outcome` 是「有没有**结论**」，不是「字段在不在」：核对成 `Applied` / `NotApplied` 的写叫「被打断」，只有 `Pending` 才叫「结果未知」。二者的区别决定下一步给「重试本步骤」还是「核对原操作」，合并就等于让用户去重放一条可能已经写成功的命令。

#### 4.16.4 只读投影

三个投影共用一份实现（`deployrun::project_tasks` / `project_deployments` / `run_view`），页面、管道、快照看到的必须是同一次计算的结果。

**`Tasks[]`**（未完成任务，终态不在此列）：`Id`、`Name`、`Label`、`State`、`StateText`、`Step`、`StepsDone`、`Host`、`Port`、`UpdatedAtUtc`、`Action`、`ActionLabel`、`RunShort`、`CanBackground`，另有可选的 `ReasonCategory` / `ReasonText`（**没有原因就真的不写这两个键**）。

**`Deployments[]`**（底部任务条：非 `Draft` 的全部 + 最近 24 小时内的终态）：`RunId`、`Name`、`State`、`StateText`、`Summary`、`Step`、`StepsDone`、`Host`、`Port`、`UpdatedAtUtc`、`Running`，可选 `ReasonCategory` / `FinishedAtUtc`。

**`Run`**（`deployment-get` 回包）：记录全部字段 + `StepsDone`、`Name`、`Label`、`Summary`、`Action`、`ActionLabel`、`Running`、`CanBackground`、`RunShort`。

**`Name` 与 `Label` 不是一回事，别互换。** `Name` 是记录名（「自建 · 203.0.113.10」），当标题用；`Label` 是**进度标签**（「3/4 · 准备兼容连接：…」）。r47 详情页把 `Label` 当标题，真机上渲染成两行大字——这个缺陷只有截图能发现。名称还重复出现在任务行与详情页两处，两处必须同名同义。

**`CanBackground` 的判据只有一份**（`deployrun::can_background`）：引擎里确有活动 pass **且** `State ∈ {Running, Queued}` **且** `Reason` 为空 **且**（无未决写 或 未决写仍是 `Pending`）。失败、结果未知、需修复、暂停、完成、取消、等新确认**全部**为假——这些情况下关掉页面等于让人以为「还在跑」。

#### 4.16.5 读取三态与缺失语义

`TasksRead` 只有三个合法值。**「读不出来」与「没有任务」是两件不同的事，任何一格被当成另一格，页面就会说谎。**

| `TasksRead` | `UnreadableCount` | 页面必须做什么 | 禁止做什么 |
|---|---|---|---|
| `"ok"` | `0` | 正常渲染列表 | — |
| `"partial"` | `>0` | 渲染能读到的记录，**并**单独说「有 N 条读不出来」+ 原因 | 说「0 条」；把 N 悄悄吞掉 |
| `"failed"` | — | 显示错误卡 + 「刷新」入口 | 渲染成空列表；显示任何 `Running` 的任务行 |

- **`TasksRead` 缺失（或为空串）= 未知**，不是 `ok`。页面这时说「状态未知，请刷新」，不能说「没有任务」。
- 表外值同样按未知处理，且**不渲染成空列表**。
- `"ok"` **且** `Tasks` 为空数组，才是唯一可以说「还没有任务」的组合。
- `deployment-list` 在 `TasksRead == "failed"` 时 `ok:false`，但**仍然带 `deployment`**：页面要能同时看到「读不出来」和「刷新」两样东西。只回一个 `error`，页面就只剩空白。
- 宿主启动恢复写盘失败时，记录**原样留在** `Running`（没改动 = 没说谎），但结论会写进 `EngineShared::recover_error`，`deployment-list` 据此把 `TasksRead` 压成 `failed`。**绝不「先显示 Running 让它自己好」。**

**`CanBackgroundRunId`**（快照 `State` 顶层）：指向**唯一**那条可以「后台继续」的 `RunId`。

- 空串 = 没有唯一候选（0 条或多条）。页面**不得**给「后台继续」按钮——按钮点下去会拿这个 `RunId` 调 `deployment-background`，指错就是「把别人的任务转后台」。
- 与 `CanBackground`（布尔，在 `Tasks[]` 每项上）**成对出现**：布尔回答「有没有」，`CanBackgroundRunId` 回答「是哪一条」。

#### 4.16.6 保留与裁剪

| 规则 | 值 | 位置 |
|---|---|---|
| 终态保留条数 | **20**（`KEEP_TERMINAL`） | `prune_terminal` |
| 终态保留时长 | **7 天**（`MAX_TERMINAL_AGE_SECS`） | 同上 |
| 底部任务条里的终态 | **最近 24 小时** | `project_deployments` |

- **未完成的记录永不自动删除**，只有 `Complete` / `Cancelled` 参与裁剪。裁剪按「新→旧」排序，同时满足「排名 ≥ 20」或「超过 7 天」即删。
- **`Draft` 不参与 `prune_terminal`**：它既不在 20 条名额里，也不按 7 天过期。草稿的清理只有一条路——用户在向导里点「放弃这次填写」，或从任务列表丢弃（§4.16.10 J7）。堆积由常数上限 `MAX_DRAFTS = 3` 压住，不新增第二条裁剪判据。
- `prune_terminal` **永不返回 Err**：启动清理失败不该拦住用户。它的报告是 `{removed, kept, error}`。
- `TasksRead == "failed"` 时**一个文件都不动**（连哪些是终态都不知道，删就是猜）。

#### 4.16.7 秘密边界

| 东西 | 在哪 | 规则 |
|---|---|---|
| 登录口令 | **只在内存**（`deployengine::Secret`） | `Drop` 时调 `pairing::zero` 清零；**永不进记录、日志、`operations.jsonl`** |
| 服务器管理私钥 | 服务器 `/var/lib/tradechannel/pairing-rs/signing.pem` | 永不出那台机器 |
| 本机隧道私钥 | `<数据根>\servers\<id>\tunnel.key` | 只在 `0600` / 收紧 DACL 的文件里；记录里只有 `Plan.ClientPublicKey` |
| 记录里的禁用键 | `deploystore::FORBIDDEN_KEYS`（9 条） | 读记录时**键名**命中即判 `Unreadable`；值是空串也算命中 |

`FORBIDDEN_KEYS` 的比较会先把键名规范化为「小写、去掉 `_` / `-` / 空格」再做**包含**判断，所以 `Password` / `PASSWORD` / `ssh_Password` / `ssh-Password` 命中同一条。值是任何形状都算命中——一条记录里出现这个键，本身就说明有人想往记录里存秘密。

#### 4.16.8 恢复与退出：两条不允许「聪明」的地方

**启动恢复（`deployrun::recover`，纯函数，只改判不执行）** 四条**同时**成立才动：记录非终态、引擎里没有它（active **或** queued）、`Executor.Pid` 不是本进程、心跳过期（`> 15s`）。

- 有**未核对结论**的写 → `NeedsAttention` / `OutcomeUnknown`，唯一动作 `Reconcile`
- 否则 → `NeedsAttention` / `Interrupted`，唯一动作 `RetryStep`
- 卡在 `Running` 的那一步标 `Unknown`（界面「未核实」）；已 `Done` / `Pending` 的一个不动
- **`Paused` 不碰**——那是用户按的，重启替它改判就是替用户做决定
- 写盘失败 → 记录原样留 `Running`，但结论进 `recover_error`，页面读成 `failed`（见 4.16.5）

为什么可以断定「执行者死了」：`instance::acquire` 的命名互斥覆盖整个进程，本进程持锁时，任何其它能写记录的实例都必然不在运行。这是**证明**，不是启发式。

**退出守卫（`tray::close_decision(close_to_tray, tray_available, deploying)`）**

| 有部署没跑完 | 托盘可用 | 关窗 / 托盘退出做什么 |
|---|---|---|
| 是 | 是 | 缩到托盘，部署继续；托盘提示「还有 N 个部署没有完成」 |
| 是 | 否 | **拒绝**，弹对话框说明出路（只有一个「知道了」，**没有「继续退出」**） |
| 否 | — | 老规则：`close_to_tray` 决定断开退出还是藏起来 |

**部署这一维优先于用户偏好**：部署不是连接，断了可以重连，部署打断就得重新核对。窗口能再叫出来，被打断的部署不能。`deploying` 数的是 active **+ queued**——排队那条退出同样等于丢掉，只数 active 会漏掉「刚点开始就关窗」这个最常见的时间点。

#### 4.16.9 边界（如实记录，不要当成已实现）

- **只支持一台服务器一次一个逻辑步骤**：同 `lower(host):port` 串行（`lane_key`），不同服务器并发，上限 3 个 pass。域名与 IP 视为不同服务器（无法可靠归并）。
- **CLI `--server-setup` 与界面部署没有跨进程互斥**：两者同时写同一台服务器，结果取决于运气。界面路径已退役，CLI 仍可用。
- **不自动续跑**：`recover` 只改判，`deployrun.rs` 里不出现任何执行意图（有源码扫描用例守）。
- **不做「仅 UDP 就归档」**：`Partial` 永远是 `NeedsAttention`，要人点一下。
- 架构文档 §5 的 A2 / A7 / A9 仍然有效（并发上限硬编码 3、没有气泡通知、不做仅 UDP 归档）。

#### 4.16.10 草稿的保存、恢复与丢弃（**r69 落地**）

**草稿不是第二种东西，它就是 `State=="Draft"` 的一条 `RunRecord`。** 不新建文件、不加字段、不动状态机白名单：`Draft`、`NEXT_ACTION_OPEN_FORM`、`action_of → ("resume","继续填写")`、`new_draft`、原子写、`Revision` 递增、`prune_terminal` 只裁终态——这些本来就在。单独存一份「部署草稿」会得到第二套形状**和**第二处「挑哪条草稿」的判据，直接违反「投影只写一份」。代价只有一个：`Draft` 永不自动裁剪，所以必须补丢弃路径（J7）与上限（J3）。

**J1 唯一判据：地址能解析成一台服务器就写，解析不了就一个字都不写。** 判据就是 `deploy_target` 那几道形状检查（缺用户名、缺主机名、端口不是 1–65535、含空格、IPv6）。`root@` 这种半截地址不是一个目标，落盘只会制造一条点不开的假任务。写失败（`config`）**不阻断填写**：不改 `deploy_step`、不拦 probe，只在向导里追加一句「（这次没能保存草稿，关掉窗口后地址要重填）」。

`load_all()` 的结论只要**不是 `ok`** 就拒绝写：`failed`（目录读不出来）与 **`partial`（有条记录读不出来）都要拒**。`partial` 是最容易漏的那个——那条读不出来的记录**可能正是同一台服务器的草稿**，看不见它就会新建第二份，上限 3 也只会数到能读的那几条。这与「列表能不能渲染 `partial`」（`LoadResult::is_usable`）是**两把不同的尺**：去重要求的是「知道全部草稿」。拒绝同样不挡填写。

**J3 按 `lane_key` 唯一，上限 3。** 去重键是 §4.16.9 定义的「同一台服务器」（`lower(host):port`），不新造判据。不带 `runId` 时按它找已有 `Draft`：命中就复用（`Created:false`），未命中就新建（`Created:true`）。不同服务器的草稿最多 `MAX_DRAFTS = 3` 份，第 4 份回 `conflict`「已经留着 3 份没填完的草稿，请先在任务列表里放弃一条。」——**不自动删最旧的那条**（删除是用户的决定，与「未完成的记录永不自动删除」这条既有承诺直接打架），**也不做时间过期**（另开 `prune_drafts` 就是第二条裁剪判据）。

**J4 恢复的唯一入口是任务列表里那张草稿卡的「继续填写」。** `uiweb` 的 `resume` 按 `State` 分流：`Draft` → 向导（`FormState::deploy_from_draft`，预填 `Target` 还原出的 `user@host[:port]`、`Label`、`Identity.Fingerprint`）；其余 → 详情页（旧行为逐字不变）。分流用的是 `deploy_primary` / `action_of` 同一个字段，三处口径不会漂。「自己搭服务器」永远空白向导、不预填——「哪条草稿」只在一个地方判。

**密码永不取回**：记录里根本没有它（`FORBIDDEN_KEYS` 守着），所以 `deploy_password` 恒空、`deploy_known` 恒假，恢复后必然要求重输。向导顶部必须写「已恢复上次没填完的地址；密码需要重新输入。」指纹为空时回第 0 步，非空时进「核对指纹并填密码」。

**J5 开始复用：`deployment-start` 的 `runId`。** 非空时 `load` → **必须是 `Draft`**（否则 `conflict`「这条任务已经开始过，不能当草稿用。」）→ 覆盖 `Label` / `Target` / `Identity.Fingerprint` / `UpdatedAtUtc` → `store.save`（`Revision` +1 由 save 递增）→ `engine.start_run`。**先落盘再投递**；`Attempts` / `CreatedAtUtc` / `Revision` 不重置。`Draft→Queued` 由引擎的 `enqueue` 走 `Draft→WaitingUser→Queued` 两步校验，白名单一个字不改。

指纹覆盖只有一条规则：`lane_key` **变了**就是另一台服务器，指纹按请求为准（**可以是空**，否则 A 的指纹会带到 B 上）；`lane_key` **没变**时请求非空才覆盖（用户点「上一步」重读指纹，不该把草稿里已有的抹成空）。

**J6 页面表现**：任务卡状态「未开始」+ 唯一按钮「继续填写」；底部队列 `Deployments[]` **不出现**草稿；详情页主按钮**没有**（`deploy_primary` 首行 `State=="Draft" → (false, "")`，早于 `OpenForm` 分支）；向导多一颗 ghost 按钮「放弃这次填写」。

任务卡的**标题行**（`Label`）对草稿必须是「未开始」，而不是 `0/4 · 检查服务器环境与身份`：`web/app.js` 的任务卡只渲染 `Label`、不渲染 `StateText`，而 `new_draft` 把 `Step` 设成 `0`，`progress_text` 会算出「0/4 · 检查服务器环境与身份」——那行字会让用户以为服务器已经在被检查，而这条记录一次握手都没发生。`deployrun::task_label` 因此对草稿直接返回「未开始」，与 `state_text` / `summary_of` 同一个词。记录名（`Name` / 详情页标题）仍是「自建 · host」，不受影响。

「放弃这次填写」只在向导的**第 0 / 1 步**出现。第 2 步（正在部署）与第 5 步（正在读指纹）都不给：第 5 步是两秒的等待态，那时点放弃会把草稿删掉，而 probe 的回包照样把表单推进到第 1 步、`deploy_draft_id` 仍指向一条已经不存在的记录——接着点「开始部署」必然以 `config`「读不到这条部署任务」失败（密码又已在点击时清空），那是一条自己造出来的死路。

`deploy_primary` 与 `deployment-continue` 两处前置是配对的硬要求。少了任何一处，点「开始部署 / 继续」都会走到 `continue`，让引擎把草稿直接入队——**一次没有密码的部署**，用户看到「正在部署」然后卡在第一步。所以 `continue` 对 `Draft` 只回 `conflict`。

**J7 丢弃 = 删除，不是 `Cancelled`。** `deployment-cancel` 对 `Draft`：`store.remove(run_id)`，**不碰引擎**，回 `{RunId, CancelRequested:true, Discarded:true, Message:"已放弃这份草稿，没有留下任务记录。"}`。

- 为什么不是写 `Cancelled`：草稿没有检查点、没碰过服务器、没有证据可留。写成终态会让它挤进底部任务条（最近 24 小时终态）和 20 条保留名额，而用户要的是「当它没发生过」。
- 与裁剪不冲突：文件没了就不在裁剪判据里。
- 删除失败 → `ok:false` `config`「没能丢掉这份草稿：…」，向导保住，可重试。
- 这条分支必须在「有没有引擎」之前：纯本地删除，没有引擎也该能做。
- 页面侧：向导里丢弃成功后**关掉表单**。判据是「命令是 `deployment-cancel`」+「当前是向导（`deploy_draft_id` 非空）」+ `ok:true`——不读 `Discarded`，因为那份回包里的键没有登记进 `UI_REPLY_KEYS`（页面读不到就等于不存在）。

**边界（明确取舍，不是缺陷）：指纹进草稿的时机被拆成两次点击各自成批。**

- 「读取指纹并继续」点击：同一批 `steps` 依次是 `deployment-draft-save{spec}` → `server-probe{spec}`（**先落草稿，再读指纹**）。
- 「开始部署」点击：同一批 `steps` 依次是 `deployment-draft-save{runId,spec,fingerprint,transport,tcpPort,serverName}` → `deployment-start{runId,spec,fingerprint,transport,tcpPort,serverName,password?}`（r93）。

原本想的是「probe 成功后再存一次指纹」，但**没有这个机制**：`Absorbed` 只有 `Keep` / `Close` / `Toast` 三个变体，吸收发生在命令回包的合并路径里，在那里再发命令会递归进合并。所以改成两次点击各自成批。后果如实记录：**读了指纹但还没点「开始部署」时，草稿里只有地址**；恢复后回第 0 步重读一次指纹（一次只读握手），换来的是「关掉窗口后地址还在」这件用户真正在意的事。`deploy_from_draft` 仍保留「指纹非空就预填且进第 1 步」的逻辑（点过「开始部署」但失败过的草稿会有指纹）。

**秘密边界（第二道防线之外的第一道）**：`deployment-draft-save` 的请求里**根本没有 `password` 这个字段**，代码也不去读它，所以草稿 JSON 与它的落盘文本里都不存在任何口令。`FORBIDDEN_KEYS` 仍然守着读取侧——往草稿里塞秘密会让那条记录直接读不出来。

#### 4.16.11 尝试历史（**r70 落地**）

记录里的 `Attempts[]` 从 r44 就在，但一直没有代码往里追加：**不管用户重试多少次，历史里永远只有第一次**。这一节把「尝试」的起止判据写死，并规定它怎么上屏。

**字段**（`AttemptRecord`，`Attempts[]` 的元素）：`No`（从 1 单调递增）、`StartedAtUtc`、`FinishedAtUtc`（**空 = 这次还没有结论**）、`FailedStep`（`null` = 没有哪一步失败）、`ErrorCode`（失败码；空 = 没有失败）、`Reconcile`（`NotNeeded` / `Needed` / `Done`）。

**开始一次新尝试的唯一判据（`deployrun::begin_attempt`）：上一次尝试已经有结论。** 即 `Attempts.last().FinishedAtUtc` 非空。它由 `deployengine::mark_running` 在每次 pass 真正进入 `Running` 时求值——那时状态已经是 `Queued`（`enqueue` 先写「排队中」），所以判据只能看记录本身，不能看状态：**暂停后继续、补密码后继续都不会多出一条**，它们上一次还没有结论。

**结束一次尝试的责任在每一条「会让 pass 停下」的路径上**，一个都不能漏：

| 路径 | 写入的 `FailedStep` / `ErrorCode` |
|---|---|
| `deployrun::settle_step`（某一步 `Failed` / `Unknown` / `Partial`） | 该步下标 / `Reason.Code` |
| `deployengine::settle_attention`（上游校验不过、核对连不上、身份变化） | `None`（没有哪一步失败）/ `Reason.Code` |
| `deployengine::finalize`（`Complete`） | `None` / 空 |
| `deployengine::finalize`（`Partial`，兼容连接没装上） | TCP 那一步 / `TcpFailed` |
| `deployengine::finish_cancelled` | `None` / 空 |
| `deployrun::recover`（被强杀） | `None` / `Interrupted` 或 `OutcomeUnknown` |

**已有结论的尝试不许被覆盖**（`finish_attempt` 第二道断言）：`settle_attention` 一次 pass 里可能被调用多次，第二次改写只会把失败步骤/错误码换成最后一次调用者的。**暂停不结束尝试**（`finish_paused` 不写 `FinishedAtUtc`）：暂停是用户按的，继续时还是同一次。

**被强杀的那次尝试按「最后一拍心跳」收尾**（`recover`）：能证明的最后时刻就是心跳时间；没有心跳才取判定时刻。**不补一个「跑到重启那一刻」的假结束时间**，也不留一条永远进行中的历史——否则重启后的第一次重试会把它和新的这次混成「跨了一次崩溃的尝试」。

**核对标记跟着真实的核对走**：`settle_attention` / `settle_step` 在留下未决写时置 `Needed`；`reconcile` 的 `Applied` / `NotApplied` 置 `Done`；`NotNeeded` 永远不会被改写成 `Done`（一次都没发生过，写「已核对」是编的）。

**上屏（只读）**：详情页在原因之后渲染「尝试历史（N 次）」，每行 `#N · MM-DD HH:MM → MM-DD HH:MM · 失败在第 X 步（步骤名）· 错误码 CODE · 有未核对的写/已核对`；没有结束时间的最后一条且记录在跑 → 「正在进行」，否则 → 「没有拿到结论就停了」。只显示在**有过结论**（任一条 `FinishedAtUtc` 非空）或**重试过**（`len >= 2`）时——草稿与第一次还在跑的记录不显示，免得把「还没发生」写成历史。**历史里没有任何按钮**：重试永远走主按钮，是「按当前事实再做一次」，不是重放旧写命令。

**不设条数上限，也不单独裁剪**：`Attempts` 只随用户显式重试增长（不是定时器），记录本身还受 §4.16.6 的 20 条 / 7 天终态裁剪约束。真正的增长源是「无人工干预的自动重试」，而这个产品里根本没有那种东西。

**草稿阶段的 `Attempts[0].StartedAtUtc`** 由 `new_draft` 写入（= 创建时刻），此时 `FinishedAtUtc` 为空；草稿详情页按 `deploy_primary` 不给按钮，也不会渲染历史块（没有结论）。这是如实记录，不是缺口。

#### 4.16.12 部署结果提醒（**r71 落地**）

部署是唯一一件「关掉窗口也在跑」的事。跑完之后如果用户不在电脑前，结论只在任务列表里——他得自己想起来去看。这一节定义一条**活过重启**的「还没看过」的记录。

**存储**：`<data root>\deployments\reminders.json`（与 `runs\` 同级）（`Kind:"TradeChannel.DeployReminders"`、`Schema:1`），临时文件 + 重命名。空列表 = 删文件（没有待办就不留空壳）。坏记录**照实报错**，不当空列表——静默清空会让「有一条结果没看」永远消失。

**只记四种状态**：`Complete` / `NeedsAttention` / `Paused` / `Cancelled`。`Queued` / `Running` / `WaitingUser` / `Draft` 不是结果，提醒它们只会变成噪音。

**去重键是 `RunId + State + Step + Code`**（PRD P1-3 原文）。同一次失败重试再失败**不重复提醒**；换了步骤（阶段）或换了错误码才算新的一条。`Step` 取记录上的 `run.step`（失败的那一步/M/4 里的 M），`Code` 取 `Reason.Code`（没有原因时为空串）。

**收提醒的时机**：`deployengine::Inner::save` —— 它是一切会让记录进入那四种状态的路径的汇合点（步骤落账、上游校验、暂停、取消、完成、核对）。幂等由去重键保证，所以每次 `save` 都调用是安全的。**写提醒失败不影响部署本身**：提醒是附加品，不能把一次成功的部署变成失败。注意它发生在记录落盘之后：记录先在磁盘上变 `Complete`、提醒才出现，中间有毫秒级窗口；判定「有没有提醒」必须重读文件，不能拿「状态已变」当依据。

**上限 50 条**，超了**先丢最旧的已读**，没有已读才丢最旧的未读。提醒是「最近发生了什么」，不是审计账本（那是 `operations.jsonl`）。

**读 = 打开任务**：`deployment-get` 成功读到记录后，把该 `RunId` 名下所有未读提醒标 `ReadAtUtc`。写失败不挡打开（同一条理由：附加品）。列表、快照都不标记已读——只有真的打开任务才算看过。

**投影**：`deployment-list` 的 `deployment` 里多两个字段：

| 字段 | 形状 | 语义 |
|---|---|---|
| `Reminders` | `[{Id, RunId, Name, State, StateText, ReasonCategory, Text, CreatedAtUtc}]`（新的在前，**只含未读**） | 页面据此画「部署结果」块；`RunId` 用来打开原任务 |
| `RemindersError` | 字符串 | 非空 = 提醒读不出来。此时 `Reminders` 是空数组，页面必须说「读不出来」，**不许**显示成「没有未读结果」 |

快照 `State.Reminders` / `State.RemindersError` 原样透传（与 `Tasks` / `Deployments` 同一口径：只透传，不在快照里重算）。

**页面**：线路页在「未完成的添加」上方渲染「部署结果」块，每条一行：名字 + `状态词 · 原因` + 相对时间 + 「查看」（`data-action=resume`，走既有 `resume` 路由打开该 RunId）。打开任务 → 已读 → 下一次快照里这一行消失。**托盘不可用也照样能发现**：这条链路只依赖任务列表与磁盘文件，不依赖托盘。

**托盘**：本轮**不**做系统通知气泡。理由：托盘通知在不同 Windows 版本上会被专注助手/通知设置静默吞掉，而「结果没人看」的代价远高于「少弹一个气泡」。列表 + 未读状态是可验证的那一份；气泡将来可以加，但不能成为唯一入口。


#### 4.16.13 单任务诊断摘要（**r72 落地**）

部署失败时最有用的信息散在记录的五六个字段上（状态、原因码、哪一步、未决写、尝试历史）。让用户自己去翻 `deployments\runs\<RunId>.json` 不现实，截图又说不清错误码。`deployment-export` 把一条记录投影成一份可以直接贴给别人的 Markdown（默认）或 JSON。

**字段是白名单**（`deployexport::projection`）：**不调 `run.to_json()`**。记录以后加字段时，秘密不能因为「忘了排除」被顺带导出去；新字段要进摘要，必须到那张表里来加一行。导出内容包括：记录名/任务编号（含短码）/状态（+状态词）/进度与停在哪一步/下一步动作/目标 `user@host:port`（**没有密码**）/指纹/计划摘要/版本/四个时间/原因（分类、错误类、错误码、人话、时刻）/四步（状态、起止、错误码与人话）/尝试历史（编号、起止、失败步骤、错误码、核对结论）/未决写（种类、结论、核对方式、计划摘要）/执行者（pid、是否后台、最后一拍心跳）/计划（接口、UDP 端口、子网、MTU）。**不导出** `Plan.ClientPublicKey`（公钥不是秘密，但诊断不需要它）与 `Executor.InstanceId`。

**落点**：`<数据根>\logs\exports\deploy-<RunId 前 8 位>-<epoch>.md|.json`。临时文件 + 重命名；同名退让 `-1`、`-2`…（同一秒内多次导出不互相覆盖）。**不接受调用方指定路径**——那等于给页面一个「写到任意位置」的入口。

**回包是顶层的 `exportResult{ok,path,bytes,format,message}`**，与 `export-history` 共用同一个键（本来就在 `UI_REPLY_KEYS` 里，本批不动白名单）。页面在详情页给一颗 ghost「导出诊断摘要」，任何状态都给（**完成/失败时最有用**）；点了只发这一条短命令，`exportResult.message` 落到页面提示上。

**只读**：导出不改记录、不碰引擎、不发网络请求。所以它也不进 `is_long_command` / `operation_budget`。


#### 4.16.14 归档与恢复（**r73 落地**）

任务列表会越用越长，但「删记录」是不可逆的，不该成为清理手段。归档是**第三种状态**：从列表里消失、**文件一直在**、随时可恢复。

**字段**：`RunRecord.ArchivedAtUtc: Option<String>`（磁盘形状同名，缺省 `null`）。判据只有一处：`RunRecord::is_archived()`（`Some` 且非空串）。旧版本读到这个字段会忽略它（向前兼容），旧记录读到 `null` 就是「没归档」。

**命令**：`deployment-archive{runId, archived}`（第 10 条短命令）。`archived` 缺省 `true`；**既接受 JSON 布尔也接受 `"true"/"false"` 字符串**——页面发的是布尔，命令行/管道是人手写的字符串。只写 `ArchivedAtUtc`，`Revision` 照常 +1。

**只归档已经停下来的**：`Complete` / `Cancelled` / `NeedsAttention` / `Paused`。在跑、排队、等人确认、草稿一律 `conflict`——把一条正在部署的任务藏起来，等于让用户失去对它唯一的入口。恢复（`archived:false`）不校验状态（归档态本来就是停下来的）。

**归档即视为看过**：归档会把该 `RunId` 名下未读提醒标已读（见 §4.16.12）。写提醒失败不影响归档本身。

**三处投影一致地排除归档**（同一个 `is_archived` 判据）：

| 投影 | 行为 |
|---|---|
| `project_tasks`（未完成的添加） | 不出现 |
| `project_deployments`（底部队列，24 小时终态） | 不出现 |
| `project_archived`（线路页「已归档」，最多 `MAX_ARCHIVED_SHOWN = 20` 条，按归档时刻新→旧） | 只在这里出现；字段含 `RunId/RunShort/Name/State/StateText/Summary/StepsDone/Host/Port/UpdatedAtUtc/ArchivedAtUtc/ReasonCategory/ReasonCode` |

**裁剪跳过归档**（`prune_terminal`）：归档 = 用户明确要留着。若照常参与 20 条 / 7 天裁剪，「归档」会在 7 天后变成「悄悄删除」——那正是这一条最不能出的事。代价是归档记录会一直占盘；这是用户按下的决定，不是系统替他做的。恢复归档后它重新进入裁剪范围（回到「结果」的队伍里）。

**页面**：详情页在结束态（或 `NeedsAttention`/`Paused`）给 ghost「归档」，归档态给「恢复这条记录」；线路页在任务列表下方多一块「已归档」，每条一行（名字 + 状态词 · 摘要 + 已归档时间 + 「查看」），点「查看」走既有 `resume` 打开详情页，恢复按钮在那里。

**归档不是删除**：本轮**不提供**「删除记录」的入口——那是比归档危险一个数量级的动作，要另立契约（确认、影响面、是否连带清理引用）。


#### 4.16.15 任务列表筛选（**r74 落地**）

列表长到扫不动时，用户需要的是「收窄」，不是「翻页」。线路页任务面板顶部三个下拉框：**状态、时间、原因**，外加一颗「清除筛选」（只在下拉框不是「全部」时出现）。

**筛选是页面状态**：不发命令、不改记录、不进快照。宿主每秒重推一次 `Tasks`/`Deployments`/`Reminders`/`Archived`，筛选条件必须活在页面里，否则每次推送都会被重置。

**三块共用一组筛选**（它们本来就是「一件事的不同阶段」）：

| 块 | 数据 | 时间字段 |
|---|---|---|
| 部署结果（未读提醒） | `Reminders[]` | `CreatedAtUtc` |
| 未完成的添加 | `Tasks[]` | `UpdatedAtUtc` |
| 已归档 | `Archived[]` | `ArchivedAtUtc`（缺则 `UpdatedAtUtc`） |

**状态桶**：`Queued` / `Running` / `WaitingUser` 对外都是「进行中」（用户不关心内部三个态的区别）；其余按 `State` 原样（需要处理 / 已完成 / 已取消）。「已暂停」不单列——它在「全部状态」里可见，要专门找它就是「需要处理」之外的事，本轮不增加桶。

**原因筛选按 `ReasonCategory`**：失败（`Failed`）/ 结果未知（`OutcomeUnknown`）/ 身份变化（`IdentityChanged`）/ 需要凭据（`AccessRequired`）。**没有类别的条目（完成、取消）只在「全部原因」下出现**——把它们算进「失败」是编的。为此提醒文件加了 `Category` 字段、归档投影加了 `ReasonCategory`：提醒要活过重启，类别必须跟它一起落盘。

**时间窗**：`day` = 24 小时、`week` = 7 天、`all` = 全部。没有可信时间戳的条目只在 `all` 下出现（不猜它的时间）。

**筛空**：三块都为空且筛选不是「全部」时，显示「没有符合筛选的任务。」+「清除筛选」。**有东西可筛时才显示筛选条**——一条任务都没有的时候，三个下拉框只是噪音。

**不发命令**：`clearDeployFilter` 是页面动作（与 `deploymentList` 同类），不产生 IPC；下拉框变化只触发一次本页重绘。


#### 4.16.16 草稿总览与超期提示（**r77 落地**）

草稿只有「上限 3 条」和「放弃这次填写」时，用户不知道还有几份没填完，也不知道最旧那份放了多久——两个月前建的和昨天建的在列表里长得一模一样。

**字段**：`deployment-list` 的 `deployment.Drafts`：

| 键 | 含义 |
|---|---|
| `Count` | 草稿条数（`State=="Draft"` 且未归档） |
| `OldestDays` | 最旧一份放了几天（向下取整）；`HasAge=false` 时为 `0`，**不代表刚建的** |
| `HasAge` | 是否拿到了可信的开始时戳 |
| `Stale` | `HasAge && OldestDays >= StaleDays` |
| `StaleDays` | 阈值常量 `DRAFT_STALE_DAYS = 7` |
| `Max` | `MAX_DRAFTS = 3`，仅用于展示「已用/上限」 |
| `Summary` | 宿主拼好的那句话：`2 份没填完的部署，最旧的一份放了 13 天。` |
| `Hint` | 超期时：`超过 7 天没动过。可以接着填，也可以放弃——草稿不会自己消失。` |

**三条口径**：

1. **时龄取 `CreatedAtUtc`**（开始填的那一刻），不是 `UpdatedAtUtc`——后者会被「又打开看了一次」刷新，那样任何草稿都永远看起来是新的。
2. **时间戳缺失 = 未知**：`HasAge=false`、文案里不出现天数。说「0 天」会被读成「刚建的」，猜一个数字更是编的。
3. **文案在宿主拼**，页面只负责显示（`esc` 之后放上去）：同一句话只有一处，改动不用两头找。

**不做自动过期**：这条与「未完成的记录不会被自己删掉」是同一条底线。到期的草稿只有两条路——用户接着填，或用户点「放弃这次填写」（对 `Draft` 是**删文件、不碰引擎**，见 §4.16.10）。`Stale` 只是提示，不是清理信号。

**页面**：线路页「未完成的添加」上方一行（`.draft-summary`）；**有筛选时不显示**——否则会出现「统计说有 2 份、列表里一条也没有」的自相矛盾。筛选是纯页面状态，宿主不知道它，所以这条判断只能放在页面。


#### 4.16.17 部署记录的保留策略（**r79 落地**）

`prune_terminal` 从 r44 就存在、也一直有测试，但**生产代码从没调用过**：`deployments\runs\` 只增不减，而快照每 1–2 秒要把其中**所有** JSON 读一遍。r79 把它接到启动流程。

**只在启动时跑一次**（`main` 里启动恢复之后），不是每帧、也不是每次列表。所以一个长期不关的进程不会中途丢记录；重启才会清。

**删谁**：

| 条件 | 结果 |
|---|---|
| 非终态（`Draft`/`Queued`/`Running`/`WaitingUser`/`Paused`/`NeedsAttention`） | 永不删 |
| 终态（`Complete`/`Cancelled`）但**已归档** | 不删（用户按过「留着」） |
| 终态但**还有未读提醒** | 不删（提醒里存着 `RunId`，删了「查看」指向空） |
| 终态、未归档、无未读提醒、最近 `KEEP_TERMINAL = 20` 条之内 | 不删 |
| 终态、未归档、无未读提醒、`finished` 在 `MAX_TERMINAL_AGE_SECS = 7 天` 之内 | 不删 |
| 以上都不满足 | **删文件** |

**读不到提醒就整轮不裁**：`reminder::unread` 失败时 `prune_records` 返回 `None`，一条都不删。不知道哪些记录还被引用时，宁可不删——这与「缺字段 = 未知」是同一条口径。

**用户看得到什么：什么也看不到**。底部队列只显示 24 小时内的终态，且这个版本**没有记录页**——被删的那批本来就不在任何界面上。所以这次删除是静默的。

**但必须可查**：真删了会往 `logs\operations.jsonl` 记一笔 `清理部署记录`（成功/失败各一种，`detail` 写「清理 N 条，保留 M 条」）。用户问「我的记录去哪了」，答案在这里。不弹气泡、不进快照——那会把一次维护变成打扰。

**失败不拦启动**：`prune_terminal` 从不返回 `Err`（`PruneReport.error` 里带人话），删不掉就照实记一笔失败，绝不让清理挡住用户连网。


#### 4.16.18 「这一次的指纹是自动记住的」必须被说出来（**r83 落地**）

部署记录里一直有 `Identity.AutoTrusted`（A9 起写入），但在 r83 之前**没有任何页面、命令或摘要读它**：TOFU（没人工核对、按设置自动记住）替用户做了一次身份决定，用户看到的只有「部署完成」——像是核对过一样。

**字段**：`RunRecord.Identity { Fingerprint, AutoTrusted }`。`AutoTrusted=true` 只在「这台服务器还没有记录、调用方没给指纹、设置里 `auto_trust_first_connection` 开着」这一条路径出现（`servercmd::first_trust` 的 `Remember` 分支）。

**三处口径**（同一句话的三个出口）：

| 出口 | 行为 |
|---|---|
| 部署详情页 | `AutoTrusted=true` 时一行 warn：`身份：这台服务器的指纹是这次自动记住的（SHA256:…）。下次连接会按它核对；对不上会拒绝连接。` |
| 诊断摘要（Markdown） | 指纹行后缀 `（这一次是自动记住的，没有人工核对）` |
| 诊断摘要（JSON） | `Run.AutoTrusted`（布尔） |

**`false` 时一个字都不多说**：人工核对过是常态，每次都提一句「已核对」会退化成噪音，真正需要被看见的那次反而没人看。

**澄清一处容易搞错的接线**（`ssh::Ran.fingerprint` 的旧注释就是错的）：AutoTrust **不**经过 `ssh::exec_with`。它走 `servercmd::resolve_identity` → `ssh::probe_host_key`（只读探一次拿到指纹）→ 钉住之后才发密码；生产侧的 SSH 执行只用 `ssh::exec`（`UnknownKey::Refuse`，永远不接受陌生身份）。`Ran.fingerprint` 今天只有用例读，**不等于** AutoTrust 没落记录。


#### 4.16.19 表单页的离开规则（**r84 落地**）

表单（`state.Form`）在前端是**整页**：只要快照里 `Form` 非空，`paint()` 就走 `workflow()`，左侧导航与面包屑就算点了也看不见效果。所以「能不能走掉」完全由宿主决定。

**规则（r84 起）**：

| 表单状态 | `navigate`（导航 / 面包屑） | 结果 |
|---|---|---|
| 没有未保存改动 | **关掉表单**，页面切到目标页 | 真的走掉 |
| 有未保存改动（目前只有 AI 工具名单的 A9 离页保护） | 保留表单 | 页面留在原地，由表单自己显示「已改 N 项，尚未生效」 |

**离开入口有两个，都必须能用**：

1. `PageActions` 里有 `back` 节点的表单 → 面包屑取那个节点（`data-wf="back"`）→ 宿主关表单；
2. 没有 `back` 的表单（「自己搭服务器」向导、部署详情）→ 面包屑由 `workflow()` 按 `ParentPage` 自动生成（`data-page` → `navigate`）→ 靠上表第一行关表单。

r84 之前第 2 类全是**死按钮**：`navigate` 只改 `self.page`、从不关表单，而「自己搭服务器」第 0 步又没有「关闭」按钮——用户被关在向导里，只能关窗口。`uiweb_form` 里那句「返回本来就有」的注释是错的，已改。

**边界**：有未保存改动的表单，导航仍然是「点了不动」。这是 A9 离页保护的本意（静默关掉等于丢改动），页面必须自己把警告显示出来。


#### 4.16.20 服务器地址的解析口径（**r85 落地**）

部署向导与 `--server-*` 系列命令共用一个地址语法，**解析只有一处**：`ipc::deploy_target`。

```
[用户名@]主机[:端口]
```

| 缺省 | 值 | 说明 |
|---|---|---|
| 用户名 | `root` | 不写 `@` 就是 `root` |
| 端口 | `22` | 不写端口就是 22 |

`主机` 可以是 IPv4 或域名；**IPv6 明确拒绝**（`rsplit_once(':')` 会把 `2001:db8::1` 拆错，猜不如说清）。

**拒绝的六种形状**（都在点「开始」之前给出，不联网）：空地址 / 含空格 / 留空用户名（`@host`）/ 端口不是 1–65535 / 缺主机名 / IPv6。

**界面不得再自行校验**：r85 之前向导多了一道 `!spec.contains('@')`，于是 `192.168.1.1` 在命令行能跑、在界面报「要写成 用户名@主机」——同一串地址两条入口两种结果。现在表单把原样地址交给 `server-probe`，写坏了由解析器回话（`absorb_probe` 退回第 0 步显示原因）。

**提示语**：`只写 IP 或域名（例如 192.168.1.1）时，用 root 账号、22 端口登录；要换账号就写 用户名@主机，换端口写 用户名@主机:2222。`——缺省必须写在用户看得见的地方，否则「只填 IP」看起来像少写了一项。


#### 4.16.21 部署向导的单页版式与两种凭据作用域（**r86 落地**）

r86 之前这一页被我改成了「先填地址 → 读指纹 → 再填密码」两步。用户明确要求按旧版复刻，已改回**一页收完**。

**版式**（对齐 `C://tradechannel//ui//DeploymentPages.ps1`）：

| 顺序 | 内容 |
|---|---|
| 1 | 服务器地址（`spec`；可只填 IP —— 见 §4.16.20） |
| 2 | 折叠区「登录账户、密钥与名称」：线路名称 / 登录账户（默认 `root`）/ SSH 端口（默认 `22`） |
| 3 | 服务器登录密码（前端渲染成「密码框 + 显示」） |
| 4 | 勾选「在这台电脑记住登录资料」（默认勾选）+ 一句「只保存在这台电脑，用当前 Windows 用户解密…」 |
| 5 | 分隔线 |
| 6 | 勾选「本任务中断后可用这份资料继续（最长 24 小时，任务完成或放弃时清除）」（默认勾选） |
| 7 | 折叠区「高级部署设置」：接口 / UDP 端口 / MTU / 子网（计划没给的显示「自动」） |
| 8 | 折叠区「服务器要求与购买建议」 |
| 9 | 一句「部署会自动完成安装、配置和检查。完成后可从首页连接新线路。」+「开始部署」/「返回上一页」 |

**两种凭据作用域**（互不替代）：

| 勾选 | 存在哪 | 何时清 |
|---|---|---|
| 记住登录资料 | `serverstore` 的服务器记录（DPAPI，当前 Windows 用户解密） | 用户取消勾选并成功部署一次，或服务器记录被删 |
| 中断后继续 | `<数据根>\\deployments\\credentials\\<RunId>.bin`（DPAPI + 收紧 ACL） | 任务完成 / 取消 / 放弃草稿；或超过 24 小时（读取时判定并删除） |

读取顺序：任务级（未过期）→ 长期 → 都没有就让用户输。**读不到/解不开一律当成"没有"**，不许因此让部署失败。

**指纹确认回到旧版的交互**：点「开始部署」先 `server-probe`；指纹未知时弹「确认首次服务器身份」对话框（`Scope=deploy-identity`，Body 含 `user@host:port` 与指纹，Note 照旧版），**确认之后才把密码交出去**；取消什么都不发。

**失败必须能重来**：`server-probe` 失败时命令层只回 `ok:false`，**没有 `serverProbe` 字段**。r86 真机验收发现只认字段的写法会让页面永远停在「正在核对服务器身份…」、开始部署恒灰。现在 `finish_op` 按 `op.cmd == "server-probe"` 兜住失败，退回第 0 步、地址与密码一个字不丢。

**未做（r87）**：登录方式「服务器密码 / SSH 私钥」。后端目前只有 `authenticate_password`、`Target` 里没有私钥字段；画一个只有一项的下拉是半成品，所以这一批**不画**，等私钥认证与测试服务端一起补。

#### 4.16.22 线路的出口网卡绑定（A 组，**r89 落地**）

对应 旧版的 `LineNetworkInterfaces`，以及它连接前的「预览所选网络 / 更新网络绑定」两步
（那两个名字只出现在旧版脚本里，本仓库没有同名标识符，故不加反引号）。
**位置不同**：旧版把这一步放在「连接前的补全流程」里（发现网络变了就让你重选），
本版放在线路的「连接方式与网络」页（`View::LineSettings`），一次性选定、下次连接生效。
理由是本版没有「按线路存一份可回退的网络版本」那套账，硬做一套半成品比不做更危险。

**存储**：`<数据根>\line-network.json`，与 `config.json` 同级、同属本机事实：

```json
{"schema": 1, "bindings": {"hk": "以太网"}}
```

- 键是线路 **id**（改名不丢绑定）；空表不落盘（删到一条不剩时把文件本身删掉）；
- 写盘 `tmp + rename`：半个文件等于「整张表读不出来」，那会让所有线路一起退回系统默认；
- 文件坏掉/形状不对一律当成**没指定**（`netbind::load`），不许因此挡住连接。

**两条命令**（都是短命令，都不连服务器）：

| 命令 | 写 | 回包 |
|---|---|---|
| `line-network` | 否 | `{ok, lineNetwork:{Id,Default,Interfaces,Bound,Effective,Stale,StaleName}}` |
| `line-network-set` | 是（只写上面那个文件） | 同上 + `message` |

`Interface` 为空串 = 跟随系统默认（**删掉**这条绑定）。非空必须是这台电脑**现在就有**的
网卡（大小写不敏感，落盘存下拉里的规范写法）；不是就回 `errorCode:"usage"` 并列出可用网卡，
**一个字节都不写**——存一个本机不存在的名字，下次连接要么绑不上（引擎直接起不来），
要么被静默忽略（走了用户没选的出口）。

**连接判据只有一处**：`netbind::resolve(指定的, 本机网卡, 默认网卡)`：

| 情况 | 绑谁 | `Stale` |
|---|---|---|
| 没指定 | 系统默认（读不到就空串 = 一个字段都不写） | false |
| 指定且本机有 | 指定的那张 | false |
| 指定但本机没有 | **空串**（不绑） | true + `StaleName` |

`Stale=true` 时**连接必须被拒绝**（`main.rs` 与 `ipc.rs` 两条连接路径同一个判据），
理由是把交易流量放到用户没选的出口上比「连不上」危险得多。探测路径
（`autoroute::probe_with_engine`）只用绑谁、不拒绝：探测是只读的。

**页面**：`View::LineSettings` 里的 `net-interface` 下拉（0 = 跟随系统默认）+
`save-net` 按钮；打开页面时发一次 `line-network`（现场读网卡，不拿快照里的旧列表）。
点保存发两条命令：`line-network-set` **紧跟**一条 `line-network` 回读。页面上那句
「当前绑定：…」只认回读的结果——r89 真机验收里保存回包没能回到表单（磁盘已写入、
页面像什么都没发生），回读把这件事变成不可能：**页面显示的一定是磁盘上的那一条**。
回包的键 `lineNetwork` 必须在 `UI_REPLY_KEYS` 里，否则命令跑完了页面仍停在
「正在读取本机网卡…」——这是白名单的又一次同类接缝，`the_line_network_reply_survives_the_host_side_merge` 守着。

**未做**：旧版的「预览所选网络」与「更新并保留原版本」（回退记录）、按网卡索引记账
（旧版按索引，本版按名字）、以及「连接前发现网卡变了就拦下来重选」（本版是连接时拒绝 + 页面上红字提示）。

#### 4.16.23 删除一台服务器在本机的部署资料（**r90 落地**）

对应 旧版的「删除本机部署资料…」。r90 之前这条路上只有一个 `server-remove`：它删掉
`serverstore` 的记录目录就完事，而这台服务器在本机的**部署任务记录、结果提醒、任务级登录资料**
全都留在磁盘上——记录没了，密码信封还在。

**判据只有一处**：`servercleanup::assess`。预览与执行都调它，所以「确认框里列的」与
「真的删掉的」是同一份清单；执行前**再判一次**（预览到确认之间可能已经过时）。

**归属判据**：`run.target.server_record_id == Some(这条记录的 id)`。
**绝不按 `host:port` 猜**——以地址手工建的任务（没有记录 id）不是这条记录的资料，
按地址匹配会把它一起删掉。同一台机器「有记录」与「没记录」的两次部署本来就允许并存。

**三条拦截**（`Blocked` 非空 = 不能删）：

| 条件 | 说法 |
|---|---|
| `Lines > 0` | 与 `server-remove` 原句一字不差：还有 N 条线路用到这台服务器 |
| `state` 是 `Queued` / `Running` | 还有 N 个部署没有结束（引擎可能还在写） |
| `state` 不在 `deploystore::STATES` 里 | 有一条部署的状态读不出来（读不懂的不动） |

第三句**单独说**，不混进「没有结束」：让人去找一个不存在的东西比拦下来更糟。
`NeedsAttention` / `Interrupted` / `OutcomeUnknown` / `Paused` / `Draft` / `WaitingUser` /
`Complete` / `Cancelled` **一律不拦**——它们都已经停下来了，正是用户要清的东西。
（「未知不是终态」是**裁剪**与**归档**的口径，不是删除的：自动删错一条是灾难，
用户明确要删时拦死他是「永远删不掉」的缺陷。）

**两条短命令**（都只动本机文件，不连服务器）：

| 命令 | 写 | 回包 |
|---|---|---|
| `server-cleanup-preview` | 否（零副作用：不建目录、不删文件、不写提醒） | `{ok, serverCleanup:{Id,Name,Host,Port,User,Lines,Runs,Archived,Active,Reminders,TaskCredentials,SavedCredential,Blocked,Items}}` |
| `server-cleanup` | 是 | `{ok, serverCleanupResult:{RemovedRuns,RemovedReminders,RemovedCredentials,Failed,Message}, servers}` |

`Items` 是给确认框逐项列出的短句，**只列真的有的项**（第一项恒为「服务器记录」）。
`Active` = `Queued`/`Running` 的条数（不是「非终态」的条数）。

**删除顺序是「先摘叶子、最后拔根」**：任务记录 → 任务级登录资料 → 提醒 → 最后记录目录
（里面躺着 `credential.dpapi.json`）。中途失败时留下的仍是「能看出这台服务器曾经存在」
的东西，而不是一堆认不出主人的孤儿文件。

- 单条删不掉（被别的进程独占、权限不足）→ 进 `Failed`，`ok` **仍为 true**：
  记录已经删了一半，报成整体失败会让用户以为什么都没发生；`Message` 必须说明有几项没删掉。
- 单条任务记录读不出来（目录状态 `partial`）→ 不报错、不计数、不删：认不出归属的东西留在原地。
- `reminders.json` **整份**读不懂 → 预览与执行都回 `errorCode:"config"`，一个文件都不删。
  说不清「要删几条提醒」就不能承诺「删干净」；代价是那份文件坏掉时这条清理不可用，
  直到用户手工处理它。
- 记录读不出来（`TasksRead` 为 `failed`）→ 同样是 `config`，**不许**当成「0 条」继续删。

**页面**：服务器一览每条记录多一个「删除本机部署资料…」（排在「删除记录」**之前**，
危险动作最后）。点击先发 `server-cleanup-preview`，回包变成确认框：

- 可删：`Scope="server-cleanup"`、`Danger:true`、`Confirm` 是「删除本机资料」；
  `Note` 写清「只删这台电脑上的记录与登录资料；服务器上的通道服务、线路与设备不受影响」。
- 被拦：`Scope="server-cleanup-blocked"`、`Confirm` 是「知道了」、没有取消键。
  **不能**把 `Confirm` 写成空串——`app.js` 的对话框无条件渲染确认键，空串会得到一个没有文字的按钮；
  也不能复用 `server-cleanup` 这个 `Scope`，否则「知道了」会触发真删。

两个回包键 `serverCleanup` / `serverCleanupResult` 必须在 `UI_REPLY_KEYS` 里
（漏了这页永远转圈，项目里已经犯过七次），`the_server_cleanup_replies_survive_the_host_side_merge` 守着。

**未做**：旧版里「清理服务器上残留的部署产物」（那是远端动作，本版的卸载走
`server-uninstall`）；也不做「按地址匹配的孤儿记录一并清理」——宁可留，不猜。

#### 4.16.24 部署前的「云端放行确认」（**r91 落地**）

对应 旧版的「已核对云端」勾选（旧版控件名只存在于老脚本里，本仓库没有同名标识符）：部署向导里必须勾一句「已核对云端安全组/防火墙：
允许部署使用的 UDP 端口入站，并保留 SSH 入口」，否则不许开始。

**为什么置前**：云端没放行时，第一步会以「连不上服务器」结束——那不是密码错了。
把这句话提前，比事后让用户猜「是不是被防火墙拦了」便宜得多。

**两处判据，一处语义**（不是重复）：

| 位置 | 时机 | 作用 |
|---|---|---|
| 点「开始部署」 | 校验完地址、**在读指纹之前** | 不勾就什么都不发——连握手都不做，页面上说清原因 |
| `deploy_start_steps` | 指纹确认之后、真正发 `deployment-start` 之前 | 同一条判定再判一次：这一段才是「动服务器」的入口 |

**与旧版的差异（有意）**：旧版把「开始部署」置灰（旧版设置的是那个应用按钮的可用性），本版改成
**点了才拦**。原因是宿主渲染的按钮要用 `disabled` 必须重绘，而重绘会把 `Generation` +1、
页面还拿着上一代——下一次 `change` 会被闸门静默丢掉（§4.16.19 的同一个坑）。拦截的说法
比灰按钮更清楚，也不丢输入。

**不持久化**：这个勾选**不跟着草稿存**（`deployment-draft-save` 不收这个字段，记录里也没有它）。
它是对「这一次」的确认，不是账号级偏好；从草稿接着填的人应该再看一眼云端。代价是恢复草稿后
要重新勾一次——这是有意的。


#### 4.16.25 部署页的兼容连接选择（C 组，**r93 落地**）

对应 旧版的 `DeployTransport` / `DeployTcpPort` / `DeployServerName`（`DeploymentPages.ps1:457-464`）。
在此之前，这一页只能准备标准连接——用户没有任何地方能表达「默认用兼容连接」，
TCP 端口与握手域名也写死为 8443 / `www.bing.com`。

**语义（与旧版一句对齐）**：标准与兼容连接**都会准备**；`Transport` 只决定登记完
**选中哪条线路**。不是「只装一种」。

| 页面控件 | 选项/默认 | 请求字段 | 记录字段 |
|---|---|---|---|
| 默认连接方式 | 自动选择（推荐）/ 标准连接 / 兼容连接；默认自动 | `transport` = `Auto`/`Udp`/`Tcp` | `Plan.Transport` |
| TCP 首选端口 | 443 / 8443 / 2443；默认 443 | `tcpPort` = 数字字符串 | `Plan.TcpPort` |
| TCP 握手目标 | 域名；默认 `www.bing.com` | `serverName` = 域名 | `Plan.ServerName` |

**校验**（`ipc`，落盘与投递之前；页面在**读指纹之前**再判一次）：

- `transport` 表外值 → `usage`「默认连接方式只能是「自动选择」「标准连接」「兼容连接」…」；
- `tcpPort` 不在 443/8443/2443 → `usage`「TCP 首选端口仅支持 443、8443、2443…」；
- `serverName` 不是「至少两段、每段 1–63 位、TLD 2–63 个字母」的域名 →
  `usage`「TCP 握手目标必须是一个域名（例如 www.bing.com）…」；
- 三个字段都**非秘密**，随草稿（`deployment-draft-save`）与记录落盘；
  旧记录缺这三键 → `Auto` / 默认端口 / 默认握手域名（零迁移）。

**引擎**：`spec_for_run` 用 `Plan` 覆盖 `deploy::Spec` 的 `transport_port` /
`transport_server_name`；`install_transport_step` 用 `new_identity_with` 生成身份。
服务器上**已有** `transport.env` 时脚本沿用原端口/域名（与旧版
PreserveExistingTransport=true 同义）；详情页的「TCP 兼容连接」优先读 Step2 证据里的
**实际**端口/域名，而不是这次请求值。

**登记**：`register_lines(..., preferred)`。`Tcp` → 选中兼容连接那条（没装上则标准）；
`Udp` → 选中标准；`Auto` → 沿用旧行为（用户已在这两条里选过就保留，否则标准）。
命令行 `--server-setup` / `--server-join` 没有这个选项，传 `None`。

**页面**：三格放进既有的「高级部署设置」折叠区（旧版的 `DeploymentAdvanced`）；
`change` **只改内存、不重绘**（重绘会让下一次 `change` 撞上 `Generation` 闸门，§4.16.19）。
详情页新增「技术详情与本次端口规则」（`DeployTechnicalDetails`）与决策说明
（`DeployDecisionMessage`）：列出 WireGuard 接口、UDP 入站端口、TCP 兼容连接端口/握手域名、
SSH 管理入口与指纹；`Complete` 时说「可以从首页或线路页连接这条线路」。

**验收**：`tests/r93_transport_ui.py`（19 项）——三格文案/默认值、改值不重绘、
草稿里 `Plan.Transport=Tcp / TcpPort=2443 / ServerName=www.example.com`、草稿无凭据字段、
真实数据根 `config.json` 未动。反向对照 r92 包 **6/17**（红的是这三格与落盘值）。


#### 4.16.26 管理恢复包（B 组，**r94 落地**）

对应 旧版的「管理恢复资料」（`ShowManagementRecovery`，`PairingPages.ps1:374-431`）。
服务器页新增两个入口：每条记录的「导出管理恢复包…」与页首的「导入管理恢复资料…」。

**两条命令**（都是短命令：只读/写本机文件，不发 SSH）：

| cmd | 请求 | 成功回包 |
|---|---|---|
| `recovery-export` | `serverId`；`password`（≥12 字符）；`includeCredential` 可选；`identityFile` / `credentialPassword` 可选 | `recovery{ServerId,Name,Address,IncludesCredential,FileName,Package,Message}` |
| `recovery-import` | `package`（≤128 KiB）；`password` | `recovery{ServerId,Name,Address,IncludesCredential,Message}` |

导出时的凭据来源：填了私钥文件 → 读文件解析（口令取 `credentialPassword`）；只填了口令 →
密码凭据；都没填 → 用这台服务器在本机保存的登录资料（没有就拒绝，不导出空凭据）。

**包格式**（本仓库自定义，与旧版的 .NET `PairCrypto` 不互通——隔离契约 D11）：

```
外层（明文）：{"SchemaVersion":1,"Kind":"SpiderVPN.ManagementRecovery",
  "Kdf":{"Algorithm":"PBKDF2-HMAC-SHA256","Salt":"<b64 16B>","Iterations":120000},
  "Cipher":{"Algorithm":"AES-256-GCM","Nonce":"<b64 12B>"},
  "Payload":"<b64 密文+标签>"}
内层（加密）：{"SchemaVersion":1,"Kind":"TradeChannel.ManagementRecovery",
  "Server":{"Name","Host","Port","User","Fingerprint"},
  "CreatedAtUtc":"…","IncludesCredential":bool,
  "Credential":{"Kind":"password","Password":"…"} |
               {"Kind":"key","PrivateKeyPem":"…","Passphrase":"…"}}
```

**安全判据**：AAD 绑定 `Kind/SchemaVersion/KDF 算法/迭代次数/盐/加密算法/随机数`，任一被改
都在解密时失败；口令错、包被改、KDF 参数被改统一回「密码不正确，或文件已损坏」，
不告诉试口令的人是哪一半错了；密码 12–256 字符；包 ≤128 KiB；私钥在包内**不出现明文**。

**导入语义**：只登记、不启用。`serverstore::register_recovered` 用包里的名字与指纹写一条
服务器记录（可选把凭据写进 DPAPI 信封）；同一目标 + 不同指纹 → `ServerIdentityChanged`；
包里不含凭据时**不动**本机已有的信封；导入成功后页面说的是「管理资料已登记，实际登录与
服务器身份仍待核验」。

**宿主**：`save-file{slot:"recovery",text,suggestedName}`（系统「另存为」+ 写文件）与
`pick-file{slot:"recovery"}`（选中即读回文本）。`recovery` 在 `UI_REPLY_KEYS` 里；
`fileSave` 走与 `filePick` 相同的整份状态回包，不进合并白名单。

**验收**：`tests/r94_recovery_ui.py`（21 项）——数据根 A 导出、关掉、全新数据根 B 导入，
断言 B 的 `record.json` 名字/地址/指纹与 A 一致、页面说「仍待核验」。反向对照 r93 包 **5/20**。


#### 4.16.27 部署页的两个「使用已保存凭据」勾（C 组，**r95 落地**）

对应 旧版的 `DeployUseSaved`（「使用这台服务器保存的登录资料」）与
`DeployUseTaskCredential`（「使用本任务保存的登录资料（重新输入会替换）」）。

**可见性**：只在**真的有那一档**时出现。

- `server-probe` 回包新增 `savedCredential` / `taskCredential`：
  - `savedCredential` = 同目标服务器记录存在且 `credential.dpapi.json` 在；
  - `taskCredential` = 请求带 `runId`（这次要复用的草稿）且该记录的任务级信封能解开。
    新建部署不带 `runId`，因此不会出现「勾了却用不上」的假控件。
- 页面在读到指纹后（`deploy_step=1`）才渲染这两个勾。

**请求字段**：`deployment-start` / `deployment-continue` 读 `useSaved` / `useTask`，缺省都是
`true`（旧行为）。`deploy_resolve_credential` 按开关跳过对应信封；**本次输入的口令永远优先**。
两个都关且没有输入 → 仍按原来的「请提供服务器登录密码…」拒绝。

**流程（r95 的唯一交互变化）**：已知服务器且 `savedCredential || taskCredential` 时，
第一次点「开始部署」只读指纹并**停在表单**（`deploy_followup=None`），让用户决定勾选；
地址没变时第二次点直接 `deployment-start`（`deploy_probed_spec` 相同，跳过重复 probe）。
没有可复用凭据时保持旧行为：读指纹后直接开始。改地址/账户/端口会清掉上次指纹与可用性，
下一次点击重新 probe。

**为什么不能更早显示**：本页是通用「自己搭服务器」表单，地址是用户输入的；在看到地址之前
无法知道目标服务器有没有信封——旧版是从服务器管理页进来的，所以它一开始就知道。r95 的
折中是「第一次点击只读身份、第二次投递」，比在 change 里发命令并重绘（会吞输入）安全。

**验收**：`tests/r95_use_saved_ui.py`（11 项）——本机 OpenSSH 只读主机键 + Python 真实
`CryptProtectData` 信封（绑定与 Rust 侧同一串），勾出现/默认勾上/取消不重绘/无任务信封时不出现；
反向对照 r94 包 **7/11**。

#### 4.16.28 操作记录：删除=隐藏 + 「显示旧版隐藏记录」（F 组，**r96 落地**）

对应 旧版操作记录页的 `ShowClearedHistory` 与「删除所选」的隐藏语义。

**存储**：`logs\operations.hidden.json`（UTF-8 JSON 数组；键 = `events::key` =
`ts\u0001action\u0001detail`）。`logs\operations.jsonl` **一行不动**；文件坏/不存在时按空集合读，
不让隐藏状态读失败拖垮整页记录。

**命令**：

- `history-delete {keys:[…]}`：语义改为**隐藏**，回
  `{"ok":true,"historyDelete":{"deleted":N,"hidden":true}}`（N = 新隐藏的条数，已隐藏的不重复计数；
  空 `keys` 仍是 `errorCode:"usage"`）。原 `events::remove` 只保留给单测，生产不再销毁审计行。
- `history-restore {keys:[…]}`：把键移出隐藏集合，回
  `{"ok":true,"historyRestore":{"restored":N}}`；空 `keys` 仍 `usage`。
- `history`：每条记录新增 `Key`（稳定键）与 `Hidden`（布尔）。`Key` 就是页面回传隐藏/恢复的键，
  宿主不重新解释「哪一条」。
- `export-history` 的 `filter` 新增 `includeHidden`（缺省 `false`）与 `search`：导出集合必须与页面
  看得见的那一批一致——默认不导出隐藏行，搜索词同样生效。

**页面**：

- 筛选行下新增 `ShowClearedHistory` 勾「显示旧版隐藏记录」，默认不勾；默认过滤 `Hidden=true`。
- 勾上后隐藏行以「已隐藏（旧版） · …」出现，并给「恢复显示」；恢复后就地改 `Hidden`，不必重读。
- 「删除所选」先弹确认框（标题「隐藏这些操作记录？」，确认按钮「隐藏」），确认后发
  `history-delete` 并立刻 `history` 重读；空列表且存在隐藏记录时提示「旧版隐藏的记录可打开上方开关后查看」。
- 「全选当前结果」与列表共用同一份筛选（含隐藏开关）：两处各写一遍判据，迟早会
  「看得见 A、全选选了 B」。

**验收**：`tests/r96_history_hidden_ui.py`（22 项）——预隐藏默认不显示 / 全选只选看得见的两条 /
隐藏提示与恢复提示 / 审计文件一行没少（含坏行）/ 隐藏键 +2 / 勾上三条都带标记回来 / 恢复一条 /
重进页面持久；反向对照 r95 **6/22**；回归 `tests/r87_history_ui.py` **27/27**。

#### 4.16.29 交易名单「恢复默认网站」（H 组，**r97 落地**）

对应 旧版「交易软件名单」页的 `ResetTradeDomains`。旧版把网站名单整体恢复成
`NodeStore.psm1::TCDefaultDomains`；本版按同一影响面映射到 `split.domains`。

**默认名单**（顺序与旧版一致）：`tradingview.com`、`tradingview-widget.com`、
`tradingviewusercontent.com`、`tvc-cdn.com`、`tradovate.com`、`tradovateapi.com`、
`ninjatrader.com`（`SplitConfig::DEFAULT_TRADE_DOMAINS`）。

**命令**：`{"cmd":"split-reset-trade-domains"}`（无参数）。

- 只替换 `domains` 里 `target=trade` 的条目；`processes`、`target=direct|daily` 的域名原样保留。
  默认值若被用户标成别的出口，会让位并回到 `trade`——恢复默认必须整组回到交易出口。
- 与 `split-add` 同一道连接闸门（连接中拒绝）、同一保存路径，并在成功后把规则落到当前线路的
  引擎配置（`apply_rules_to_file`）；交易名单真的变化时按 PRD §4.1.1 作废旧保护证据。
- 回包 = `split_payload` + `ok` + `changed` + `splitMessage`
  （`已恢复默认交易网站（7 条）` / `交易网站已经是默认名单，未变化`）；`changed:false` 时不写盘。

**页面**：`View::Split` 的「网站」分组下新增「恢复默认网站」（`ResetTradeDomains`），
旁边一句说明只替换交易出口的 7 个网站、程序与其它出口不动。

**验收**：`tests/r97_trade_domains_ui.py`（14 项）——初始自定义规则在 / 恢复提示 / 7 个默认值
进列表 / 自定义交易网站被替换 / 直连规则与程序名单保留 / 落盘一致 / 重复点击不写盘；
反向对照 r96 **5/14**；回归 `tests/r96_history_hidden_ui.py` **22/22**。

#### 4.16.30 部署详情四步横排（C 组，**r98 落地**）

对应 旧版部署进度控件（旧版的 `DeploymentPages.ps1` 里的四步 WrapPanel）：四步在**一行**
里，按步骤状态着色。

- 数据仍来自 `deployment-get` 的 `Run.Steps`（`Index` / `Name` / `Status`），不新增命令、不新增字段。
- 渲染改为一个 `row`：每格 `"{Index+1} {Name} · {状态词}"`，格与格由 CSS 自动换行；
  状态词沿用 `deploy_step_word`（`Pending→待开始 / Running→进行中 / Done→已完成 /
  Failed→失败 / Skipped→已跳过 / Unknown→未核实`）。
- `Failed` 用 `bad` 色、`Pending/Skipped/Unknown` 用 `muted`；**状态词本身必须在**，
  颜色不是唯一信息载体。
- 旧版竖排的 `"1. 名称 · 状态"` 文本不再出现。

**验收**：`tests/r98_deploy_steps_ui.py`（7 项）——预置一条第二步失败的记录，任务行 → 详情页，
四格在同一 `.wf-row`、顺序与状态词正确、失败格带 bad 色、竖排写法不存在；
反向对照 r97 **4/7**；回归 `tests/r97_trade_domains_ui.py` **14/14**。

#### 4.16.31 交易软件名单页按旧版重排（H 组，**r99 返工**）

对应 旧版「交易软件名单」页（旧版交易软件名单管理页）：**程序 / 交易网站两张卡**，
各自一个输入框；程序行是「名字 · 状态」+ 完整路径 + 右侧「移除」。

**载荷**：`split` 回包的每个条目新增两个只读字段（`processes` / `domains` 都带，但只有程序有值）：

- `fileExists`：`path` 存在时 `Path::is_file()`；没有路径为 `null`。
- `applied`：当前线路引擎配置（`<数据根>\lines\<id>.json` 的 `route.rules[].process_name`）
  里有没有这个进程名（大小写不敏感）。这就是旧版「已生效 / 未生效」的判据——断开时保护状态
  未知，但名单可以已经写进线路。

**页面**：

- 标题「交易软件名单」；两张卡「程序」「交易网站」，各带一句说明。
- 程序行状态优先级：无路径 → `位置未确认`；文件不存在 → `文件已移走`；`applied` → `已生效`；
  其余 → `未生效`。无路径的条目保留「确认程序位置…」修复入口（旧版没有，但名字条目否则无法修）。
- 程序输入：`TradeProgramInput`（1024）；「浏览…」只回填输入框，「添加程序」才发
  `split-add{kind:"process",value:<文件名>,target:"trade",path:<原路径>}`；只填名字时不带 `path`。
- 网站输入：`TradeDomainInput`（1024）；`split-add{kind:"domain",target:"trade"}`；
  「恢复默认网站」仍走 `split-reset-trade-domains`（§4.16.29）。
- **作用域**：这一页只显示与编辑 `target=trade` 的条目（旧版没有 direct/daily 两档）；
  配置里已有的其它出口规则**不删不动**，只是不在此页出现。

**验收**：`tests/r97_trade_domains_ui.py`（24 项，r99 扩展）——标题/两张卡/控件齐全、程序行状态、
浏览只回填、添加程序带路径落盘、添加网站、直连规则不显示、恢复默认网站与重复点击；
反向对照 r98 **11/24**。

#### 4.16.32 交易软件名单：OS 拖放 + 独立的程序选择器（H 组，**r100 修复**）

**拖放**（对齐旧版 WPF `DragDrop`）：

- HTML5 的 `File` 对象拿不到完整路径，`fileDrop` 网页消息在本版无法落成 `path`；改用 wry 的
  OS 级 drag-drop（`WebViewBuilder::with_drag_drop_handler`）。
- 只受理 `.exe`；只在 `View::Split` 受理，调用 `FormState::fill_program_path` 填
  `TradeProgramInput` 并自增 `Generation`，**不写配置**——与「浏览…」一致，点「添加程序」才落盘。
- 不在这一页时返回 `false`，不吃掉拖放；非 `.exe` 同样不处理。

**浏览对话框**：

- `pick-exe` 的 slot 从借用的 `engine` 改为 `process`：标题「选择交易程序」，过滤器仍 `*.exe`。
- `ui::pick_file("process")` 在**独立 STA 线程**上调用 `GetOpenFileNameW` 并 `CoInitializeEx`：
  对话框有自己的消息泵，不会被 Windows 标成「未响应」。
- `handle_ui_pick_exe_with` 先弹选择器、**后**计算 `status_state`；点按钮不再先卡几秒读线路/部署/保护证据。

**验收**：`tests/r97_trade_domains_ui.py`（30 项）——原 24 项 + 选择器窗口出现、标题正确、
没有「未响应」、线程有响应、关闭后页面恢复、拖放单元用例；反向对照 r99 **11/27**。

> r101 修正此处两条口径（详见 §4.16.33）：拖放**不再只受理 `.exe`**（`.lnk` 换成它指向的 exe），
> 换不出程序的 `.lnk` 也不再静默。

#### 4.16.33 拖放桌面快捷方式：`.lnk` 换成它指向的 exe（H 组，**r101 修复**）

r100 的拖放只挑 `.exe` 后缀，而桌面上的程序图标几乎都是 `.lnk`——于是用户拖桌面快捷方式
时被静默丢掉，看到的是「拖了没反应」。页面文案「桌面快捷方式会换成它指向的程序」
在这之前从未实现过（r100 验收只测了手动填路径）。

- 判据收敛到**一处** `shortcut::executable_target`：`.exe` 直通；`.lnk` 走 Shell COM
  （`CoCreateInstance(CLSID_ShellLink)` → `IPersistFile::Load(STGM_READ)` → `IShellLinkW::GetPath`）
  换成目标；组合出来的结果必须仍是 `.exe`。`GetPath` **用默认 flags，不用 `SLGP_RAWPATH`**：
  快捷方式里可能存的是 `%USERPROFILE%\…` 一类未展开串（本机 `Mirasim.lnk` 就是），raw 那条不是可用路径。
- **不要求目标此刻在盘上**：填进去的只是输入框草稿，页面本来就有「确认程序位置…」修复入口；
  在这里判「不存在」等于把「快捷方式有程序、只是此刻摸不到」说成「找不到可用的程序」。
- 换不出程序且拖的确实是 `.lnk` → `FormState::notice_program_unusable`：**只改提示**
  （「「X.lnk」找不到可用的程序；快捷方式要指向 .exe 才能填进来。」），不动输入框，这次拖放算已消费。
  不是快捷方式（`.txt` 等）或不在 `View::Split` → 返回 `false`，不接管、不吞。
- 仍然**只填输入框、不写配置**；点「添加程序」才落盘，落的是解析后的 exe 路径（不是 `.lnk` 路径）。
- COM 初始化的三种结果都按「可用」处理：`S_OK`（配对 `CoUninitialize`）、`S_FALSE`（wry 在 UI 线程
  `OleInitialize` 过）、`RPC_E_CHANGED_MODE`（MTA 线程）；其它失败 = 这次拖放没识别出来，不 panic。

**验收**：`tests/r101_drag_probe.py` + `tests/r101_qa_drag.py`（真 OLE 拖放，**不是** CDP 假拖放：
`tools\drag-file.ps1` 当拖放源、鼠标动作由 Python 驱动；CDP 的 `Input.dispatchDragEvent` 只走渲染进程，
测不到宿主这一层）。八条：`.lnk` 填入值精确等于目标 exe、
`.exe` 无退化、拖放不写配置、点「添加程序」才写且 path 是 exe、坏快捷方式给提示不填、
首页不吞、回归全量、单测变异红→绿。反向对照 r99（同一探测拖 `.lnk` → 输入框为空）；
r100（有 `.exe` 拖放、无 `.lnk` 解析）`.lnk` 红 / `.exe` 绿 —— 证明断言卡在本次改动上。

> **验收判据别拿 `DoDragDrop` 的 EFFECT 当证据**（r101 踩过）：wry 0.57.1 的 `Drop` 忽略 handler
> 返回值、也不设 `pdwEffect`（`drag_drop.rs` 230–254 行），`DragEnter` 只要有文件就无条件给
> `DROPEFFECT_COPY`（191–200 行）。所以「宿主吞没吞这次拖放」在 OLE 层看不出来，只能看页面状态
> （输入框 `value`、提示文案、`config.json` 是否被动过）。`ui.rs` 里 `return false` 表达的是
> 「**我们**不处理这次拖放」，不是「OLE 会把文件交还给页面」。



### 4.17 连接等待态：名单程序退出后自动连（A5，**r55 落地**）

> 对应 旧版的 `WebPendingConnection` + `ContinueTCWebConnection`。判据从
> 「NinjaTrader 在不在跑」换成 §8.6 的 `RunningPrograms`（名单内程序），
> 这样「交易软件」的定义只有一处。

**进入**：点「连接」→ `guard-precheck` 报出名单程序在跑 → 弹 `Scope=guard-running` 确认框
（r54 的连接侧）→ 用户点**「先退出程序」**（`cancelDialog`）。此时才进等待态；
点「仍要连接」（`confirmDialog`）走的是立即连接，不进等待态。

**快照字段**：

| 字段 | 类型 | 说明 |
|---|---|---|
| `PendingConnectionName` | string | 等待中的线路名。**空串 = 没有在等**（不是「未知」：等待态只存在于本进程内存里，进程重启就没了） |
| `Pending` | object/null | `{Name, DeadlineUtc, SecondsRemaining}`；`null` = 没有在等 |

`DeadlineUtc` 是**页面唯一认的钟**：前端只按它算倒计时，不自己存预算。
`SecondsRemaining` 只是同一件事的冗余读数，缺失不影响倒计时。

**自动连接**：宿主每次快照节拍问一次 `guard-precheck`（只在有等待态时才问）：
- `RunningPrograms` 非空 → 继续等；
- `RunningPrograms` 是空数组 → 清等待态，先 `use` 回**等待时记下的那条线路**（不是「当前线路」），再 `connect`；
- **`RunningPrograms` 缺失 → 不连**：读不出来不等于「程序都退出了」。
- 有长命令在跑（`Busy`）→ 继续等，自动连接不抢事务门。
- 连接只发起一次：等待态在发命令前就被消费掉。

**清掉等待态的四条路**：点「取消等待」（`cancelWaiting`，不发任何命令，toast「已取消等待」）、
超预算 **300 秒**（与旧版的 `WebPendingBudgetSeconds` 一致，toast「等待已结束，请重新选择线路」）、
或者做**任何别的动作**（改线路、断开、翻页、重新连接）——后者最容易出错：
留着它就会出现「我早就换线了，它却自己连了原来那条」。

**与旧版的差异（有意）**：旧版点连接发现有程序在跑就**直接等待**、不弹框；
本版多一次确认框。原因是 P0-13 要求把「已建立的连接不会被切断，只有新连接会被阻止」
说出来，而这句话只有在用户能选择「仍要连接」时才有意义。

### 4.18 服务器一览（C7，**r58 落地；r65 补改名与身份**）

设置页新增「服务器」入口（`{Type:"servers"}` → 表单视图 `ViewKey=servers`），
列出**这台电脑记录过的服务器**。数据复用 §3.2 已有的 `servers` 命令，不新增读取命令。

- r58 只读；**r65 起提供本机改名与身份事实**（见 §4.25）。删除记录、设备改名/卸载
  仍要连服务器改 wg 配置与设备授权，属于另一条路径，未做。
- `servers` 每条记录的字段：`Id` / `Name` / `Host` / `Port` / `User` / `Fingerprint` /
  `CreatedAtUtc` / `UpdatedAtUtc` / `LineIds`。**全部来自公开的 `record.json`**，
  凭据在 `credential.dpapi.json`，永远不进回包。
- 归属口径与 `servers` 命令完全一致：线路文件 `outbounds[].server` 的字面地址
  与服务器记录 `host` 相等即算关联。**不做模糊匹配、不猜域名与 IP 的对应**。
- **关联 0 条线路不是错**：刚部署完还没接入线路时就是这样，页面写「还没有线路用到它」。
- **读失败要说原因**：`ok:false` 时把后端原话留在页面上，不显示成「还没有记录任何服务器」——
  「读不出来」与「没有」是两件事，说错会让人以为记录丢了。

### 4.19 删除线路的只读预览（A4 第一轮，**r59 落地**）

新增短命令 `delete-preview`：`{"cmd":"delete-preview","id":"<线路 id>"}`。
**只读**——不写 `config.json`、不删文件、不写操作记录。

- 与 `remove` **共用同一条连接闸门**（`busy`：引擎存活或存在 `proxy-journal.json`）。
  预览说能删、确认后却被拒，等于让用户白点一次。
- `ok:true` 表示「预览算出来了」，**不是「已经删除」**；`Eligible=false` 是预览的结论
  （现在不能删），不是命令失败。缺 id / 找不到线路 / 配置读不出来才回 `ok:false` +
  `errorCode`（`usage` / `config`）。

```json
{
  "ok": true,
  "deletePreview": {
    "Id": "jp",
    "Name": "东京 02",
    "Selected": false,
    "LastLine": false,
    "Eligible": false,
    "Blocked": [{"Code": "Busy", "Message": "连接未断开：请先断开再删除……"}],
    "Files": ["lines\\jp.json"],
    "Server": {"Id": "0f8fad5b-…", "Name": "root@203.0.113.10", "Host": "203.0.113.10"},
    "Warnings": [{"Code": "NoEngineConfig", "Message": "……"}]
  }
}
```

| 字段 | 含义 |
|---|---|
| `Files` | 会被删除的引擎配置文件，**数据根相对路径**（不把用户的绝对目录带进对话框） |
| `Server` | 按 §4.18 同一判据归属到的服务器记录。删除线路**不会**删这条记录；`null` = 没有对应记录或读不出来，二者靠 `Warnings` 区分 |
| `Blocked[].Code` | 目前只有 `Busy`；有任何一条时 `Eligible=false` |
| `Warnings[].Code` | `NoEngineConfig`（只删 config 条目）、`LastLine`（删完没有可用线路）、`Selected`（删除后自动切换）、`ServerUnknown`（服务器记录读不出来，**不得**冒充「没有记录」） |

- **宿主合并**：界面里 `route` 收到的 `fetch` 是 `merge_ui_command_reply` 合并后的
  status，不是原始命令回包。`deletePreview` 必须登记在 `UI_REPLY_KEYS`；漏登记时
  单测（直接喂原始回包）全绿，真机上预览体被吞、`Eligible` 读不到默认 `false`，
  点「删除」永远弹「这条线路现在不能删除」。r59 真机验收抓到过一次，接缝用例：
  `the_delete_preview_survives_the_host_side_merge`。

界面（`src/uiweb.rs::delete_dialog`）按三种结论给三种框：

1. **可删**：`Scope=delete`，标题「删除线路」，确认按钮「删除」+ 危险样式；
   `Details` 列出「将删除」（config 条目 + `Files`）与「将保留」
   （服务器记录与登录凭据、服务端 WireGuard 服务与设备授权、其他线路与记录）。
2. **连接中不可删**：`Scope=delete-blocked`，标题「暂时无法删除线路」，只有「知道了」，
   没有取消/删除；`confirmDialog` 是一次 no-op。
3. **预览本身读失败**（`ok:false` 或无 `deletePreview`）：同样走 `delete-blocked`，
   正文保留后端原话；**不得落回旧的一键删除路径**——没有结论就不该出现可点的删除。

### 4.20 删除结果核对与待清理记录（A4 第二轮，**r60 落地**）

`remove` 的语义从「改完配置就算成功」改为**两步都核对**：配置保存后真的
`remove_file(lines\<id>.json)`，结果放进回包的 `deleteResult`：

| 字段 | 含义 |
|---|---|
| `Id` / `Name` | 被删线路 |
| `File` | 引擎配置的**数据根相对路径**（不落绝对目录） |
| `Incomplete` | `true` = 配置已删、文件没删掉 |
| `Error` | 失败原话；`Incomplete=false` 时为 `null` |

- 文件本来就不在（`NotFound`）算删干净；顺手清掉同 id 的旧待清理记录。
- 删不掉时：写 `logs\delete-cleanup.json`，并记一条 `清理本地文件` / `ok=false` /
  `obj=line:<id>` 的操作记录；`remove` 本身仍 `ok:true`——配置确实删了，不能骗人
  说整条命令失败；但回包说「删了」而文件还在，等于把含隧道私钥的文件悄悄留在本机。

**待清理记录**（`src/cleanup.rs`）— `logs\delete-cleanup.json`：

```json
{
  "SchemaVersion": 1,
  "Kind": "TradeChannel.DeleteCleanup",
  "Pending": [{"Id":"hk","Name":"香港 01","File":"lines\\hk.json","Error":"另一个程序正在使用此文件…"}]
}
```

- 只存重试需要的**最小事实**：id、名字、相对路径、错误原文。**绝对路径不落盘**；
  重试时按 id 用与生成时同一条规则重算（`config::engine_config_path_for`），
  一份被拷走的记录不能在另一个数据根上删到别的文件。
- 写入是「临时文件 + 重命名」；空列表 = 删除记录文件（不留空壳）。
- 记录读不出来（坏 JSON / `Kind` 不对 / 缺 id）**照实报错**，不得当成空列表——
  静默当空会让提示卡与重试按钮永远消失，而文件还在。

两条命令：

| cmd | 请求 | 回包 | 失败语义 |
|---|---|---|---|
| `delete-cleanup` | 无 | `ok:true` + `deleteCleanup{Pending[],ReadError}` | 记录损坏时 `ok:false` + `errorCode:"cleanup"`，**仍带** `deleteCleanup{Pending:[],ReadError}` |
| `delete-cleanup-retry` | `id` | `ok:true` + `deleteCleanupResult{Id,Name,File,Complete,Removed,Error,Message}` | 前置拒绝也**同时给** `deleteCleanupResult`（页面只读这一份）；缺 id → `usage` |

`delete-cleanup-retry` 的三个前置判定都在动手之前：

1. 线路**不能**还在配置里——同 id 又被导入过时，旧记录指向的是新线路的引擎配置，
   照着删等于删掉一条正在使用线路的私钥文件。拒绝理由点名 id，并让用户先到界面删除。
2. 记录必须读得出来、且确实有这一条。
3. 路径按 id 重算，不信任记录里的相对路径。

结果语义：删除成功 → `Complete=true,Removed=true`，清记录并记 `清理本地文件` / `ok=true`；
`NotFound` → `Complete=true,Removed=false`（说「已经不在了」，不说「刚刚删掉了」）；
其它错误 → `Complete=false`，更新记录里的 `Error` 并记 `ok=false`。

**宿主合并**：`deleteResult`、`deleteCleanup`、`deleteCleanupResult` 都必须登记在
`UI_REPLY_KEYS`。漏 `deleteResult` 时删完不提示残留（成功谎报）；漏 `deleteCleanup`
时提示卡永远不出现（静默留下文件）；漏 `deleteCleanupResult` 时点重试什么都不发生。
接缝用例：`the_delete_result_survives_the_host_side_merge`、
`a_pending_cleanup_survives_the_merge_and_is_projected`、
`the_cleanup_retry_reply_survives_the_host_side_merge`。

同一批还修了第六次同类旧账：`qualityHistory` 没在白名单里，响应历史抽屉在真机上
永远停在「正在读取历史…」（单测直接喂原始回包，所以全绿）。用例：
`the_quality_history_reply_survives_the_host_side_merge`。

界面投影：`State.DeleteOperation`（`Kind:"Cleanup"`、`Phase:"Blocked"`、`CanRetry:true`、
`CanCheck:false`）只显示**第一条**待清理，处理完自动落到下一条；记录读不出来时给
`CanRetry:false` 的说明卡（没有 id 可重试）。`State.DeleteRefresh` 恒为 `null`：
重试是同步的、列表每帧重读，没有「刷新列表」这一步。按钮文案「重试清理」。

### 4.21 线路动作记录、反馈与核对/重试（A6 第二轮，**r61 落地**）

「测试线路」与「保存连接方式」都不是一步完成的：前者要等一次网络往返，后者要等一次
落盘。进程在这中间被杀掉时**动作做没做成没人知道**——页面若悄悄把这次点击忘掉，
用户会以为「我保存过兼容连接」，而 `config.json` 里其实还是别的值。

**存储**（`src/lineaction.rs`）— `<数据根>\logs\line-actions.json`：

```json
{
  "SchemaVersion": 1,
  "Kind": "TradeChannel.LineActions",
  "Actions": [
    {
      "Id": "11111111-1111-4111-8111-111111111111",
      "LineId": "hk",
      "LineName": "香港 01",
      "Kind": "Preference",
      "ProfileId": "Tcp",
      "Requested": "tcp",
      "Phase": "NeedsReview",
      "Message": "上次操作还没拿到结果，程序就退出了；请先核对结果。",
      "Code": "Interrupted",
      "AtUtc": "2026-11-11T02:19:28Z",
      "AtUnix": 1794363568,
      "FinishedAtUtc": "2026-11-11T02:19:28.6290781Z",
      "LatencyMs": null
    }
  ]
}
```

- `Kind` 只有 `Check`（测速）与 `Preference`（保存连接方式）；`Phase` 只有
  `Pending` / `Succeeded` / `Failed` / `NeedsReview`。
- **动作开始就落 `Pending`**，每个出口把结论改写成 `Succeeded` / `Failed`；
  漏一个出口，页面就会永远停在「测速中 / 保存中」。
- 同一条线路的同一种动作只留**最新一条**（`begin` 按「线路 + 类型」替换）；
  一条线路的一张卡片只有一个结果位置，历史在 `history.json`，不在这里堆。
- 写入是「临时文件 + 重命名」；空列表 = 删除记录文件（不留空壳）。
- 记录读不出来（坏 JSON / `Kind` 不对 / 未知 Phase / 缺 `Id` / 缺 `LineId` /
  未知类型）**照实报错**，不得当成空列表——静默当空会让「核对结果」永远消失，
  而文件还在那里没被处理。
- **启动恢复**：单实例锁之后、界面第一次推送之前，`recover_pending` 把仍是
  `Pending` 的记录改判 `NeedsReview`，`Code:"Interrupted"`，消息「上次操作还没拿到
  结果，程序就退出了；请先核对结果。」。执行者不是本进程，没有第二种解释。
  结论已确定的 `Failed` 记录**不动**——明确的失败有「重试」，不需要再核对。

**记录时机**：

| 命令 | 记录条件 | 落什么 | 谁承担不记录 |
|---|---|---|---|
| `measure-latency` | 用户发起且带 `lineId`（界面测速） | `Check`；成功记 `LatencyMs`，未连接/失败也收口为 `Failed`（如 `environment`） | 自动采样（不带 `lineId`）**不记录**：每 30 秒一条会淹没真人动作，核对也分不清哪条是人的操作 |
| `set-transport` | `source:"line-action"`（界面「保存」与按记录重试） | `Preference`，`Requested` 为 `udp|tcp|auto`；成功与被拒都收口 | 命令行/旧入口不带 `source`：行为不变，也不凭空多出一条「用户动作」 |

**两条命令**：

| cmd | 请求 | 回包 | 失败语义 |
|---|---|---|---|
| `line-action-list` | 无 | `ok:true` + `lineActions{ReadError:"",Actions[]}` | 记录损坏时 `ok:false` + `errorCode:"line-action"`，**仍带** `lineActions{ReadError,Actions:[]}` |
| `line-action-review` | `id` | `ok:true` + `message` + `lineActionReview{Id,LineId,Kind,Phase,Message,Code,NeedsReview,CanRetry,LatencyMs}` | 缺 id → `usage`；记录读不出 → `record`；找不到 → `missing`；不是 `NeedsReview` / 类型不认识 → `state` |

`line-action-review` 是**核对**，不是重试：只查已有证据，**绝不重新提交原操作**。

- `Preference`：比对 `config.json` 里这条线路**现在存的方式**与当初 `Requested`。
  `None`（自动）只与请求 `auto` 对上——「没固定」不等于「保存成了标准」。
  不一致 → `Failed` / `NotApplied`，消息「上次保存没有落地：这条线路现在仍是{实际}。
  可以重试保存。」；核对过程本身不写配置。
- `Check`：只看 `[AtUnix-2, AtUnix+15]` 窗口内的 perf 采样（一次界面测速请求超时
  2 秒，窗口再宽会把动作之后的自动补测算到这次头上）；`ProfileId` 为 `Tcp` 时只认
  「兼容」，否则只认「标准」。有读数 → `Succeeded` + 「已确认上次测速完成：{ms} ms。」；
  有失败原因 → `Failed` + 原因原话；没有开始时间 → `NoWindow`；没有任何采样 →
  `NoResult`。核对**不重新发请求**。

**界面投影**（`State` 快照）：

- 每条线路 `Feedback`：非 `Pending` 的记录映射为 `Status`（`Succeeded` /
  `NeedsReview` / `Failed`）、`Message`、`Code`、`NeedsReview`、`CanRetry`
  （仅 `Failed`）、`CanDiagnose`（仅失败的 `Check`）、`ReviewLabel`
  （测速「检查测试结果」/ 保存「确认保存结果」）。
- `PendingOperations` **只收 `NeedsReview`**（`Kind:"LineAction"`、
  `Label:"{线路名} · {标准连接|兼容连接}测试/保存"`、`Target:LineId`）；
  失败但结论明确的有「重试」，不进待处理区。
- `LineActionsReadError`：记录读不出来时非空，页面必须说「不知道」；此时不得把
  线路显示成「从没测过/没保存过」，否则用户永远看不到还没核对的结果。
- 按钮：失败测速「重新测试」发真的 `measure-latency`（长命令）；失败保存
  「重试保存」重发 `set-transport{source:"line-action"}`；`NeedsReview`
  走 `line-action-review`。重试会生成**新的记录 id**，不复用旧记录。

**宿主合并**：`lineActions`、`lineActionReview` 都必须登记在 `UI_REPLY_KEYS`。
漏 `lineActions` 时快照里没有 `Feedback` / `PendingOperations`（页面看起来「什么都没发生」）；
漏 `lineActionReview` 时点「检查测试结果」什么都不发生。这是白名单**第七次**咬人；
源码扫描对 `absorb_reply`/`absorb` 整个函数免检，单测直接喂原始回包也不会红，
只能靠接缝用例：`the_line_actions_survive_the_host_side_merge`、
`the_line_action_review_reply_survives_the_host_side_merge`。

### 4.22 界面长操作记录与只读核对（A5/A6，**r62 落地**）

连接、断开、诊断是界面上副作用最大的三种长操作：连接/断开会起停引擎、改系统代理；
诊断只读但也要等网络往返。进程在中间被杀掉时，**动作做没做成没人知道**——现在是否
连接着、系统代理有没有留下我们的改动，全是未知。页面若把这次点击忘掉，用户只能猜。

**存储**（`src/oprecord.rs`）— `<数据根>\logs\ui-operations.json`：

```json
{
  "SchemaVersion": 1,
  "Kind": "TradeChannel.UiOperations",
  "Records": [
    {
      "Id": "11111111-1111-4111-8111-111111111111",
      "Kind": "Connect",
      "Phase": "NeedsReview",
      "Message": "上次「连接」没拿到结果，程序就退出了；请先核对当前连接状态与系统代理。",
      "Code": "Interrupted",
      "StartedAtUtc": "2026-11-11T04:28:05.0676741Z",
      "StartedAtUnix": 1794371285,
      "FinishedAtUtc": "2026-11-11T04:28:21.1180538Z",
      "Origin": "ui"
    }
  ]
}
```

- `Kind` 只有 `Connect` / `Disconnect` / `Diagnose`；`Phase` 只有
  `Pending` / `Succeeded` / `Failed` / `NeedsReview`。
- `Origin` 记录发起入口：`ui`（页面）、`tray`（托盘）、`poll`（空闲推进自动连接）。
  它只用于说明来源，**不参与核对判据**。
- **开始工作前就落 `Pending`**：记录写不进盘时，操作**拒绝开始**（`ok:false`、
  `errorCode:"record"`、「本次操作没有开始」），handler 一次都不调用——没有记录就不许有副作用。
- 每个终态出口把结论改写成 `Succeeded` / `Failed`；handler 异常结束也收口为 `Failed`。
  页面收到终态时，同一份事实已经写回磁盘（`EventSink` 在发终态前复核）。
- 同种操作只留最新一条，但 `NeedsReview` **保留**——还没人核对的事实不能被下一次点击掩埋。
  总量上限 200 条；裁剪先丢最早的已结束记录，**永不丢 `Pending`/`NeedsReview`**。
  单条 `Message` 截 300 字（超出加 `…`）。
- 写入是「临时文件 + 重命名」；空列表 = 删除记录文件（不留空壳）。
- 记录读不出来（坏 JSON / `Kind` 不对 / 未知 Phase / 缺 `Id` / 未知类型）**照实报错**，
  不得当成空列表——静默当空会让被中断的操作从页面上彻底消失。
- **记录里不存命令原文**：宿主从不回放原请求。重试只能由用户重新点一次连接/诊断，
  因此不存在「重试跑的是一份过期意图」这种问题，也不会把带参数的请求落进日志。

**启动恢复**：单实例锁之后、界面第一次推送之前执行。

| 原状态 | Kind | 改判 | Code | 说明 |
|---|---|---|---|---|
| `Pending` | `Connect` / `Disconnect` | `NeedsReview` | `Interrupted` | 副作用未知，必须核对当前连接状态与系统代理 |
| `Pending` | `Diagnose` | `Failed` | `InterruptedReadOnly` | 只读操作没有需要核对的后果，可以重新运行 |
| 其它 | — | 不动 | — | 已确定的结论不复核 |

**两条命令**：

| cmd | 请求 | 回包 | 失败语义 |
|---|---|---|---|
| `operation-list` | 无 | `ok:true` + `operations{ReadError:"",Records[]}` | 记录损坏时 `ok:false` + `errorCode:"operation-record"`，**仍带** `operations{ReadError,Records:[]}` |
| `operation-review` | `id` | `ok:true` + `message` + `operationReview{Id,Kind,Phase,Message,Code,NeedsReview,Origin}` | 缺 id → `usage`；记录读不出 → `record`；找不到 → `missing`；不是 `NeedsReview` / 类型不认识 → `state` |

`operation-review` 是**核对**，不是重试：只查当前磁盘事实，**绝不重新执行原操作**。

**判据只有两个磁盘事实**：`runtime-engine.json` 是否存在（连接是否在跑）与
`proxy-journal.json` 的还原凭据是否还在（系统代理有没有留下我们的改动）。

| 记录 | 事实 | 结论 | 消息口径 |
|---|---|---|---|
| 连接 | 引擎在跑 | `Succeeded` / `ReviewedApplied` | 「上次连接已经生效：当前连接正在运行。」 |
| 连接 | 没跑、无代理凭据 | `Failed` / `ReviewedNotApplied` | 「上次连接没有生效：现在没有连接，也没有残留的代理改动。可以重新连接。」 |
| 连接 | 没跑、凭据还在 | **维持 `NeedsReview`** | 「上次连接没有跑完，但留下了系统代理改动；请先在维护区还原系统代理，再重新连接。」 |
| 断开 | 没跑、无代理凭据 | `Succeeded` / `ReviewedApplied` | 「上次断开已经完成：当前没有连接，系统代理也已还原。」 |
| 断开 | 没跑、凭据还在 | **维持 `NeedsReview`** | 「引擎已经不在运行，但系统代理改动还在；请先在维护区还原系统代理。」 |
| 断开 | 引擎在跑 | `Failed` / `ReviewedNotApplied` | 「上次断开没有完成：当前连接还在运行。可以再断开一次。」 |
| 诊断 | 任意 | `Failed` / `InterruptedReadOnly` | 「上次诊断没有拿到结果（只读操作，不会改动系统）；可以重新运行诊断。」 |
| 任意 | 还原凭据读坏 | **维持 `NeedsReview`** | 说清读不出的原因，不得猜「代理已还原」 |

- 「维持 `NeedsReview`」是 `operation_review_stays`：核对本身成功（`ok:true`），但结论
  只能是「仍然不知道」，**不写盘**，下一帧页面仍显示待处理。
- 核对结论是「上次没生效」时仍 `ok:true`——失败的是被核对的那个操作，不是核对动作。
- 核对只允许写回这一条记录；不改引擎、不改代理、不改配置。

**界面投影**（`State` 快照）：

- `PendingOperations` 收 `Kind:"Connection"` 的记录（`Id` = 记录 id、`Target:""`），
  连接/断开/诊断靠 `Label` 区分，消息按类型说清「现在是否已连接、系统代理是否还原
  都还没确认」。线路动作仍用 `Kind:"LineAction"`，两本账在同一个数组里并存。
- 首页「查看并处理」发 `reviewOperation`。宿主按 id **归属哪本账**分流：
  `operation-list` 里有这个 id → `operation-review`；否则查线路动作 → `line-action-review`；
  两本都没有 → 明确说「记录已不在」，不猜。
- 核对回包的 `operationReview.Message` 走 Toast（`absorb_reply` 特判）；命令层拒绝
  （`ok:false`）走合并后的 `message`，不能一声不响。
- **会话不完整时的按钮**：`State.Action` / `State.StatusDetail` 由状态投影原样透传
  （旧宿主缺键给空串，不编造）。当 `State==="Fault" && Action==="Disconnect"` 时，
  首页主按钮必须是「断开」——状态卡已经写「请断开后重新连接」，按钮却给「连接」是死路。
  这条由 `snapshot_passes_the_status_action_and_detail_through` 钉住（删两个键必红）。

**宿主合并**：`operations`、`operationReview` 都必须登记在 `UI_REPLY_KEYS`。
漏 `operations` 时被中断的连接/断开在页面上彻底消失（待核对入口、读错误提示都没有）；
漏 `operationReview` 时核对完成后一句回话都没有。这是白名单**第八次**同类缺陷；
接缝用例：`the_operation_record_survives_the_host_side_merge`、
`the_operation_review_survives_the_host_side_merge`。

**边界（如实记录）**：本版只做「记录 + 启动改判 + 只读核对」。**按记录重试/重放未做**
（记录不含命令原文）；长操作的「取消等待」与 `resume` 仍回 toast；线路动作仍是独立账本
`logs\line-actions.json`，两本账不合并。

### 4.23 部署暂停与继续（A2/A3 P1-1，**r63 落地**）

引擎、状态机与 `deployment-pause` 命令在 r44/r52 就有；r63 补的是**界面入口**，
命令契约一个字没改（见 §2 的 `deployment-pause` / `deployment-continue` 行）。

**页面规则**（`src/uiweb_form.rs::render_deploy_run` / `deploy_primary`）：

- 「暂停部署」只在记录 `State=="Running"` **且** `Running==true`（引擎里真有活动 pass）
  时出现。排队、已暂停、已完成都不给；点了也不发命令——按钮与命令走同一条判据，
  因为从点下去到宿主受理之间，这一步可能已经跑完了。
- 页面给主按钮的是 `deploy_primary(run)`，优先级：
  **未核对的写 / `NextAction=="Reconcile"` → 核对原操作**；
  否则 `State=="Paused"` → **继续部署**；再否则按 `NextAction` 表。
  暂停记录上若还挂着 `PendingOperation{Outcome:"Pending"}`，「继续」绝不能抢在
  核对前面——那等于把「已经写出去但没人核对的东西」再写一遍。
- 点「暂停部署」发**一条**短命令 `deployment-pause{runId}`，同时挂一个**只在本表单内存里**
  的 `deploy_pause_pending`：页面显示「已请求暂停：当前步骤做完之后生效。已经发出的
  写命令不会被打断。」并撤掉暂停按钮，防连点。这个标志**不进快照、不落盘**。
- 回包 `deployment{PauseRequested:true,Message}` 到达后提示条保留原话；`ok:false`
  （没有活动 pass）必须把标志撤掉，页面不能停在「已请求暂停」的假状态。
  因此 `deployment-pause` 必须列入 `absorb` 的部署回包分组——漏了它，失败回包
  没人清标志，暂停按钮要等记录下一次变动才回来。
- 记录进入 `Paused`（每帧 `deployment-get` 刷新）后：标志清掉，状态词「已暂停」，
  正文说「现在没有在写服务器。点『继续部署』会从下一步接着做。」，
  主按钮等于 `deployment-continue{verifyOnly:false}`——与重试/补齐走同一个入口。
- `Paused` 是状态机里的暂停态（`Running → Paused → Queued`），不是终态：
  「取消这次部署」仍可用；「后台继续」不可用（`CanBackground` 对 Paused 为假）。

**暂停的生效边界**：只在两步之间落地。点暂停时正在执行的那一步会**做完并核对完**
才停；因此：

- 已经发出的写命令不会被打断，停下来时 `PendingOperation` 要么是 `null`，要么
  不是 `Pending`（真机验收：暂停后为 `null`）。
- 停在最后一步上时，暂停可能来不及生效——任务会直接 `Complete`。这是如实的：
  界面只说「当前步骤做完之后暂停」，没有承诺一定能停。
- 暂停意图只在进程内存里。请求后、落地前宿主被杀，重启恢复按 T11 kill 那条走：
  记录判 `NeedsAttention/OutcomeUnknown`，需要人核对原操作；不会自动续跑。

**测试**（`src/uiweb.rs`，4 条）：暂停按钮只在 Running 出现且点下去才发命令；
点一次命令 + 提示条 + 不许连点，失败回包撤标志；暂停落地后主按钮「继续部署」且
发 `verifyOnly:false`；暂停 + 未决写时主按钮仍是「核对原操作」（顺序变异必红）。
另有 6 处源码变异（去 Paused 主动作、去掉 Running 条件、去掉落地清标志、
调换核对优先级、失败不清标志、去掉命令侧 Running 闸门）全部先红后绿。
全量 `--bin` **1062 passed / 0 failed**（一次并行高负载下的配对重试用例偶发
`InvalidOnlineResponse`，单跑 1/1 与全量复跑均干净）。

**真机验收**：`tests/r63_deploy_pause_ui.py`，对真服务器完整部署中途暂停，
16/16 通过——点暂停后停在 `StepsDone=1`、`PendingOperation=null`，6 秒内不自动续跑，
点「继续部署」跑到 4/4，暂停前已 `Done` 的步骤 `StartedAtUtc` 一个没变（没有重跑写），
完成后暂停按钮消失。证据 `deliverables\software-company\tcrs-r63-deploy-pause\acceptance\`
（release 构建）。装机后再跑同一条：**16/16**（安装 exe 与包内构建产物 SHA256 一致，
`21BB7080…`；证据 `…\tcrs-r63-deploy-pause\acceptance-installed\`，RunId `36056788…`）。
反向对照 r62 装机版（同一驱动、干净服务器）：**7/16**——第一条「暂停部署」在
120 秒窗口内始终不出现（这段时间里部署健康跑到 4/4），后续暂停相关检查随之全红；
基线导航、完成态与两条线路仍绿。注意反向的第二条「暂停前记录是 Running」也会红，
原因是 120 秒按钮等待把部署等完了，不是独立缺陷；r62 没有暂停能力的实证是第一条。

**回归（r63 装机 exe，12 条界面脚本）**：r49 29/29、r50 17/17、r54 49/49、r57 26/26、
r58 15/15、r59 42/42、r60 65/65、r61 60/60、r62 78/78 全绿；r53 14/18、r55 32/36、
r56 15/16 的红不是 r63 回归——现场 `C:\SpiderVPN\data\config.json` 的 `lines`
已是空数组（`logs\operations.jsonl` 记 2026-11-11T03:32:38Z「删除线路」`src=ui`，
`data\lines\` 同刻清空），而 r53 直接读现场配置、r55/r56 从现场 `config.json`
复制隔离根，都要求现场有一条线路。11:27–11:29 同三脚本在 r61 批次（线路还在）为
**18/18、36/36、16/16**。合计 **442/451**；r63 只改部署详情页表单，不碰线路列表
与自动连接路径。

**边界**：不做「暂停/继续」以外的长操作控制；暂停不跨进程重启保留意图；
暂停状态下重启宿主后继续虽然走同一条 `deployment-continue`，本轮未做真机走查。

### 4.24 配对加密层的「对端口径」（r64 落地）

`pairing.rs` 的 `seal()` 只能证明「自己封、自己开」；旧版用的是 jose-jwt 与 .NET 的
RSA/AES/HMACSHA512（以及 Win32 DPAPI）。r64 补的是**别人做出来的信封**：
`tests/fixtures/pairing/` 里的向量由 .NET / Win32 产出，Rust 必须能解开；反向则由
`tests/r38_consume.py` 的独立客户端解服务器侧 `assets/tc-pair.py` 封的 JWE。

**JWE 口径（RFC 7516 §5.1 / RFC 7518 §5.2.2，两边逐字一致）**

| 项 | 规则 | 错法的后果 |
|---|---|---|
| AAD | 只取 `b64u(protected header)` 这一段，**`encrypted_key` 不参与认证** | 把第二段也拼进来 → MAC 必错（真机第一次加入就卡在这里） |
| `AL` | AAD 的**比特**长度，64 位大端 | 按字节长度算 → 整个 AL 字段错，负向量 `dotnet-jwe-4-wrong-al.json` 专门钉这一条 |
| `tag` | `HMAC-SHA512(CEK[0..32], AAD‖IV‖CT‖AL)` 取前 32 字节 | 用整段 HMAC 或错切法 → 长度/比较都不对 |
| 内容密钥 | CEK 64 字节：前 32 做 MAC key，后 32 做 AES-256-CBC 密钥，PKCS#7 填充 | 两半对调 → 解密/验签都失败 |
| `cty` | 有就必须等于 `TC-Pairing-v1`；**没有不惩罚**（jose-jwt 的 Decode 同样不看） | 强行要求 `cty` → 对端不带就解不开 |
| `alg`/`enc` | 固定 `RSA-OAEP-256` / `A256CBC-HS512`，不做协商 | 回落 SHA-1 OAEP → 解不开对端密文，且明文长度也不对 |

**DPAPI**：配对私钥的本机封装（`pairing` 的 `dpapi`）必须能解开 Win32
`CryptProtectData` 产出的当前用户信封；`dotnet-dpapi-2-foreign-entropy.json` 是负向量
（用别的熵封的），必须解不开。DPAPI 向量**绑定机器与账户**，换机/换账户跑测试会失败并
提示「夹具过期，重跑生成器」——那是环境变了，不是 `dpapi` 有 bug。

**邀请 JWT**：`dotnet-jwt-*.json` 的 RS256 签名由 .NET `RSA.SignData` 产出；验签公钥从
向量里的 `publicJwk` 解析，指纹按运行时同一条规则算出，再用它验签。载荷改一个字节必须
验签失败（「验签」不能是假动作），且解出的 `InviteId`/`NodeId`/`PublicEndpoint` 要与文件
记录逐字相等。

**生成与守门**

- JWE 与 DPAPI 走 tools\Gen-PairingFixtures.ps1：它先用 **RFC 7516 附录 A.3** 的公开向量自检口径，自检不过不生成任何夹具；邀请 JWT 走 tools\Gen-PairingJwt.ps1。
- DPAPI 部分需要 mingw-w64 的 gcc（默认在 C:\tc-rs-tools\winlibs\mingw64\bin，可用 -GccPath 指定）。
- 用例在 `pairing::crypto_tests`：`dotnet_produced_authorizations_open`、
  `dotnet_produced_dpapi_envelopes_open`、`dotnet_produced_invitations_verify_with_the_pinned_fingerprint`。
- 夹具**不是** Rust 生成的，也**不是**可跳过的可选项：目录里没有向量、或读不出来，用例直接报「夹具丢了」。
  一次性测试私钥，**绝不可用于真实配对**。

### 4.25 服务器记录改名与身份事实（C7，**r65 落地**）

命令 `server-rename`：`{"cmd":"server-rename","id":"<记录 id>","name":"<新显示名>"}`，同步短命令。

- **只改本机** `servers\<id>\record.json` 的 `Name` 与 `UpdatedAtUtc`；`Host` / `Port` /
  `User` / `Fingerprint` / `CreatedAtUtc` 一个字节不动，也不连服务器。
- **凭据不受影响**：`credential.dpapi.json` 的熵只绑定 id / host / port / user / 指纹，
  不含名字；改名后旧密码仍然解得开。若某次改名后要求重新输密码，那是回归。
- 校验：id 必须是小写 UUID（它会拼进路径）；名字去首尾空白后 1–120 字、不含控制字符，
  否则 `ok:false` + `errorCode:"usage"` 且不写盘；记录不存在或损坏 → `errorCode:"config"`。
- 名字没变时不写盘（`UpdatedAtUtc` 不变）。
- 回包**复用已登记的 `servers` 键**给出刷新后的列表，**不新增白名单键**。
  列表读不出来时改名仍算成功：页面保留原列表并在本页替换名称。
- **成功回包里的 `message` 到不了页面**：`merge_ui_command_reply` 只在 `ok:false` 时合并
  `message`。所以提示必须从刷新后的 `servers` 列表取名字生成；直接读回包 `message`
  会让页面永远停在兜底那句（r65 真机验收就是这么红的一条）。
- 页面：每条记录显示 `user@host:port`、指纹与记录时间（都是公开事实）；「改名」先把
  那一张卡换成输入框，保存才发命令；回包失败时保留草稿与输入框，让人改一改再保存。
- 边界：这是**本机显示名**，不是服务器上的设备名；设备改名、卸载通道服务与删除记录见 §4.26。

### 4.26 服务器运维：删除记录、设备改名、卸载通道服务（C1/C7，**r66 落地**）

**删除本机服务器记录** `server-remove`：

- 只删 `servers\<id>\`（记录 + 凭据 + client.conf + tunnel.key），不连服务器。
- **还有线路的 `outbounds[].server` 指向它时拒绝**（`conflict`，说明有几条）。线路在、
  凭据没了的现场，邀请/重新部署都会报「这条线路不归你管」，宁可不删。
- 页面两段式：点「删除记录」只出确认卡；有线路时只说明原因、**不给确认按钮**。

**设备改名**：名字存在服务器 `/var/lib/tradechannel/pairing-rs/device-names.json`，
按**公钥**索引（部署创建的设备没有邀请记录，但同样需要名字）。脚本子命令
`device-names`（只读）与 `rename-device --key --name`。

- `server-devices` 现在把名字合并进每台设备（`name`），并给 `namesAvailable` /
  `namesError`；名字服务不可用时页面说「设备改名暂不可用」，不给点不了的按钮。
- `server-device-rename` 是长命令；成功后整页重读，**名字以服务器为准**。失败回包带
  `serverDeviceRename{error}`——`finish_op` 靠它区分「这条失败」与「整页读不出来」。
- **读名字也要先推脚本**（r66 真机教训）：服务器上可能还是旧版的 `tc-pair.py`，
  没有 `device-names` 子命令；只读调用不推脚本时，页面永远显示「改名不可用」。

**卸载服务器通道服务** `server-uninstall-preview` / `server-uninstall`：

- 预览只读：`AffectedDevices`（隧道里的设备数）、`LocalLines`、`Eligible`、`Blocked`
  （当前连接在跑 → `Busy`）、`Warnings`（**不释放云服务器**；关联线路会连不上）。
- 执行前置：`busy` 时拒绝（接口被停会立刻断线）；只删正文里列出的东西。
- **移除**：`<iface>-transport.service`、`tc-pair.service`、WireGuard 配置/私钥/
  sync.conf、`transport.json`；WireGuard 接口会被 down。
- **保留**：`/etc/tradechannel/transport.env`（REALITY 身份）、
  `/var/lib/tradechannel/pairing-rs`（管理身份与审计）、`/usr/lib/tradechannel`
  （组件）。不删本机服务器记录，不自动切换线路，不释放云服务器。
- 页面：设备页底部入口 → 预览卡（影响设备数 + 两条警告）→「确认卸载」→ 成功提示；
  成功后设备区改为「已卸载，重新部署后才能再次读取」，不再展示过期设备。

**验收**：`tests/r66_device_actions_ui.py` 真机 24/24（改名 → 预览 → 卸载 →
`--server-inspect` 报接口不存在、本机记录仍在）；`tests/r66_server_remove_ui.py`
隔离根 21/21（有线路挡住 → 删线路后确认删除 → 目录消失）；回归 r58 15/15、
r59 42/42、r60 65/65、r65 38/38。

### 4.27 离线邀请、长操作停止等待、按记录重试、自动选路（**r67 落地**）

这一批把四个「界面点了没有下一步」的缺口接上，边界逐条写清。

#### 4.27.1 离线邀请（A1 补口）

新电脑连不上 TCP 18443 时，用两次人工复制完成同一份加入：

1. 管理端签发一张 24 小时邀请。服务器回包里除了 `Code`（TCI1）还带 **`Invite`**：
   服务器签名的邀请 JWS 本身。离线交付的是它，不是 TCI1 码——对方连不上服务器，
   没法用码去读描述符。邀请里**不含令牌**，单独拿到也消费不了邀请。
2. 新电脑 `pair-offline-inspect` 验签并显示**管理签名指纹**；用户必须与管理端显示
   的那一串人工核对。然后 `pair-offline-request` 生成密钥与 `PairRequest`，返回
   `RequestText`（公开资料）与 12 位申请识别码。
3. 管理端把申请粘回邀请页，`invite-authorize` 经 SSH 调服务器
   `tc-pair.py authorize-request`，换回 `Authorization`（JWE），由「复制授权」交回。
4. 新电脑 `pair-offline-complete` 用本机私钥解封、验签，生成 `client.conf` 与线路。

**码里不带预分配地址**：地址在管理端批准时由服务器从隧道网段分配（与旧版离线交接
一致）。好处是邀请过期不会占着地址，也不需要「预留/回收」状态。批准逻辑与在线
`/consume` 共用服务器脚本的 `authorize_invite`，同一份申请重放会拿回同一份签名授权
（JWE 每次重新封装），不会重新分配地址或堆第二个 peer。

失败语义：这三个客户端命令与 `pair-verify`/`pair-join` 同形状——`ok:true`，错误码
与人话在 `pairOffline.Code/Message`；`pairId` 原样回显，旧轮次回包不会推进已取消的会话。
管理端 `invite-authorize` 的 `Data.Authorization` **不进快照**，只经剪贴板。

#### 4.27.2 A5 长操作「停止等待」

**不是中止**：连接/断开/诊断跑在工作线程上，强杀会留下半完成的系统代理或引擎。
`cancelOperation` 只做三件事：

- 清 `busy` 与前台等待，操作条改成「后台继续：…」；
- 把命令名记进 `detached`；
- 终态到达时，如果没有更新的操作，正常收口并提示；如果用户已经开始了**另一个**
  操作（例如连接还在后台时点了断开），终态的「后台连接已完成/没有成功」只提示，
  **不清掉**正在进行的断开。

心跳（`op.phase = queued|running`）不再清等待态——以前每秒一条心跳会把操作条闪掉。
交易保护（`guard-*`）不提供「停止等待」：它要等 UAC/WFP 事务，停等只会让用户误以为
操作被取消。

#### 4.27.3 A6 按记录重试

`operation-list` 的每条记录多一个 `Retry{CanRetry,Label,Note}`：

- 只有 `Failed` 的连接/断开/诊断可以重试；
- `Succeeded`「已经成功」、`Pending`「还在进行」、`NeedsReview`「先核对当前连接与
  系统代理」都不行；
- `Note` 是给用户看的安全描述：**按当前线路/当前状态再做一次**，不是重放旧命令
  （记录里本来就没有命令原文）。

首页对每条可重试记录给「重试连接 / 重试断开 / 重新诊断」。`operation-retry` 先写一条
**新的** `Pending` 记录再执行，结论写回新记录；同类的已结束记录只留最新一条。
被拒绝的重试不写任何记录。

#### 4.27.4 A8 自动选路（第一阶段）

**证据**：`<data root>\autoroute.json`，每条线路一份：

```json
{"SchemaVersion":1,"Kind":"TradeChannel.AutoRoute",
 "Lines":{"L1":{"NetworkFingerprint":"10.1.2.3","CheckedAtUnix":0,"ExpiresAtUnix":0,
   "Winner":"udp","Candidates":[{"Transport":"udp","Reachable":true,"LatencyMs":31}]}}}
```

- **网络指纹**：本机到公网（UDP connect 1.1.1.1:80）的源地址。换网络/换网段会变；
  同一网段换 AP 不一定变——这是第一阶段的边界，写进证据字段，不假装能识别一切。
- **候选探测**：标准（UDP）与兼容（TCP）各起一次**临时引擎**，用带认证的 `tc-check`
  入站发一次 `checkip.amazonaws.com` 请求；拿到 2xx/3xx 才算通，耗时即 `LatencyMs`。
  单候选请求预算 8 s（真实 VPS 实测 UDP 5.3 s、TCP 2.0 s；4 s 会误判慢但可用的线路）。
  不接管系统代理、不写 `runtime.json`，停止后删临时配置。
- **排名**：可达优先；都可达时延迟低者；延迟相同选标准连接（少一层中转）；都不可达
  则没有赢家，回落到「已验证 → 标准」。
- **过期**：30 分钟；网络指纹不同或过期都视为无效，下次连接/`auto-route` 重测。
- **自动应用**：`connect` 选连接方式时按「用户固定 → 新鲜证据 → 现场探测 → 兜底」。
  连接已经在跑（`busy`）时**不探测**，只用证据/兜底——再起一个引擎会抢同一个
  WireGuard 身份。连接成功后 `verified_transport` 记的是**这次真正用的**方式。
- **界面**：线路卡显示 `AutoRoute.Summary`（如「自动：标准连接（31 ms）」）；抽屉在
  非固定档给「自动选择连接方式 / 重新自动选路」；证据过期会标注「下次连接会重测」。
- **明确不做**：连接中持续监测与自动切换、按网卡绑定探测、UDP 直探（无引擎时）、
  同网段换 AP 的指纹识别。这些留给后续阶段（r68 已补前三项，见 §4.28）。

**验收**：全量 `--bin` **1111 passed / 0 failed**（新增 24 条）。离线交接另有一条**真服务器脚本**端到端用例
（`r38_qa_tests::离线交接在本机与真服务器之间完成一次接入`）：真 `create` →
Rust 申请 → 真 `authorize-request` → Rust 解封落线路，并验证幂等与篡改拒绝。
本地界面验收 `tests/r67_offline_retry_autoroute_ui.py` **15/15**（自动选路摘要上卡、
首页「重试连接」真写新记录、抽屉自动选路入口、添加线路页离线入口与表单）。
**真机管理端离线交接 38/38**（真实 VPS：管理端生成邀请 → 离线复制 → 新电脑生成申请 →
管理端 `invite-authorize` 经 SSH 批准 → 新电脑 `pair-offline-complete` 落线路；
三次验收设备已按隧道地址撤权，服务器只剩本机 .2）。真机还抓到并修掉两处：
离线粘贴框未标 `data-secret` 会被快照清空；授权 JWE 约 4 KB 被非表单 4 KiB 闸门
静默丢弃（本版已把 `pairOnline`/`invite` 放宽到 64 KiB）。
**A8 真机候选探测 14/14**：真实 VPS 线路上标准 UDP **5266 ms**、兼容 TCP **1983 ms**，
自动选路选中兼容连接；证据 30 分钟、网络指纹 `192.168.31.91`，全程未改系统代理。
真机实测后单候选请求预算定为 8 s（4 s 会把 5.3 s 的可用 UDP 线路误判为不可达）。

### 4.28 设备记录删除、自动判定与 A8 后续（**r68 落地**）

#### 4.28.1 设备记录删除（C1）

撤销设备只删 WireGuard peer，服务器 `device-names.json` 里的名字条目会留下来。
设备页从 `wg` 读列表，看不见它，于是变成一条永远清不掉的孤儿记录。

- 设备页回包多一个 `orphanNames[]`：`{publicKey,shortKey,name,updatedAtUtc}`。
  **只有隧道真的读到（`tunnel.up=true`）才计算孤儿**——接口没起来时设备表为空，
  照着比对会把所有名字判成孤儿，删一条就是删一台还在用的设备。
- 界面在设备清单下方单列「已撤销设备的名称记录」；「删除记录」同样先确认一次。
- `server-device-forget` 只调服务器 `tc-pair.py forget-device --key`：删名称条目，
  不动 peer、不动邀请审计。本机公钥在本地就拒绝。
- 撤销成功后，被撤设备的名字会就地挪进孤儿区块，用户能顺手清理。

#### 4.28.2 「重新开启接收服务」自动判定

旧按钮是盲重装：防火墙没放行时，重装多少次都是同一句「连不上」。现在
`invite-preflight` 先本地量端口，未通再经一次 SSH 读服务状态，得到一档结论：

| Verdict | 判据 | 动作 |
| --- | --- | --- |
| `Healthy` | 18443 已能连通 | 不动 |
| `NeedsInit` | 服务器没有 `tc-pair.service` 单元 | 自动安装并启动 |
| `NeedsRestart` | 单元在，但进程没跑/没监听，或 TLS 握手失败 | 自动重启 |
| `Firewall` | 服务在跑、端口在听，但本机连不上；ufw 为 active | **不碰防火墙**，只给端口与结论 |
| `TlsMismatch` | 证书指纹不符（端口被别的服务占） | 不自动重装，避免掩盖确定结论 |
| `Unknown`/`StillDown` | 读不到状态或重启后仍不通 | 如实说明，指向云防火墙 |

`Repaired` 表示这次真的执行了安装/重启；`Detail` 是给用户的一句话，页面优先显示它。
`invite-init` 仍然存在（`invite-create` 在身份缺失时会内部调用），界面上的
「重新开启接收服务」改走 `invite-preflight`。

#### 4.28.3 A8 按网卡指纹与无引擎 UDP 直探

- **网络指纹**从「源地址」升级为 `源地址|默认网卡`（`GetBestInterface` +
  `if_indextoname`）。双网卡同网段、VPN 虚拟网卡抢默认路由时，源地址可能不变而
  出口已换；只比地址会把这种情况当成「网络没变」。
- **标准候选先走无引擎直探**（`src/wgprobe.rs`）：按 WireGuard 协议发一次 148 字节
  握手发起，收到 92 字节响应（或 64 字节 cookie 回复）即判通，耗时就是握手往返。
  真实 VPS 实测 **约 0.1 s**（引擎探测约 5.3 s）。直探失败会回落到临时引擎，
  避免「我们的字段没对上」被误报成「线路不可达」。
- 探测 socket 绑定默认出口的源地址（`UdpSocket::bind(源地址,0)`），即按网卡选路；
  绑定失败退回系统选路，不把可选优化变成「不可达」。
- 证据候选多一个 `Method`（`direct`/`engine`）；旧证据没有该字段时按 `engine` 读。

#### 4.28.4 连接中持续监测与自动切换

宿主在连接中每 60 秒看一次（与 30 秒质量采样分开）：

1. 只对**自动档**线路生效；用户固定了连接方式的一律不动。
2. `auto-route-list` 报 `NetworkChanged=true` → `reason=network`。
3. 否则 `quality-summary.Degraded=true`（最近 3 次都差/都没读数）→ `reason=quality`。
4. 触发后走 `auto-reroute` 长命令，**10 分钟冷却**：探测/重连本身有成本，
   不能让「还没恢复」变成每分钟断一次。

`auto-reroute` 的两条路径：

- `network`：先断开，再探测两个候选，然后重连（一定有一次短暂断线）。
- `quality`：连接中只测**备选**（测当前标准连接会把服务端记录的对端地址改到探测
  socket 上，等于自己打断自己）；备选可达且排名赢过当前方式才断开重连，否则保持
  现状。断开后 `connect` 直接复用刚落盘的证据，不再重复探测。

### 4.29 给已有线路补一条兼容连接（**r108 落地**）

对应 旧版的「旧线路维护：增加 TCP」（AutomaticTransportPages.ps1）。用途只有一个：
**这条线路在本机只有标准（UDP）一条，而服务器只放行 TCP、或当初部署时兼容连接没装上。**

- 命令：`line-add-compatible {"line":"<线路 id>"}`，**长命令**（`is_long_command`，预算 480 s）。
- 前置只有一条：本机保存着这台服务器的登录资料。取法复用 `line_server()`（线路 → 服务器记录 → 凭据），
  取不到就按原话拒绝；不新画「用户名 / SSH 端口 / 密码或私钥」四个输入（那是部署页的事）。
- 连接中拒绝：与 `use` / `remove` 同一条闸——改配置会让还原凭据与实际引擎对不上。
- **幂等**：`servercmd::install_transport_step` 对已装过的服务器回 `reused`（不重装、不换身份）；
  `servercmd::register_lines_verified` 按同一份 `servers\<id>\client.conf` 复用已有线路，
  不会多出一条重复的兼容线（真机复验：删掉后补回来，`LineId` 与删除前一致）。
- 没有 `client.conf` 的线路（别人邀请我加入的、手工拼的）**拒绝**：凭空补会造出一条客户端密钥
  与服务器 peer 对不上的死线。
- 回包：`{ok, lineCompatible:{LineId, Port, ServerName, Reused, Message}}`，键已登记在
  `uiweb::UI_REPLY_KEYS`（漏登记的后果是「点了确认什么都没发生」）。
- **不替用户切换连接方式**：`register_lines_verified` 的 `preferred` 传 `None`，补完只是多一个可选；
  要不要改用「兼容（TCP）」是用户在页面上决定。

**r110 起语义变了**：兼容参数不再登记第二条线路，而是写进**这条线路自己的附属文件**
（`lines\<id>.compatible.json`）——一台服务器只有一条线路，两种方式。`lineCompatible.LineId`
回的就是这条线路自己的 id，`lines` 里也不会多出「（兼容连接）」那一张卡。详见 §4.31。

真机证据（r108，两台卡的旧结构）：删掉兼容线 → `lines` 只剩一条 → `line-add-compatible` 回
`Reused:true`、`Port:8443` → `lines` 恢复两条 → 切过去 `connect` → `tc-check` 200。


### 4.30 交易名单：只读投影与线路页入口（**r109 落地**）

旧版的线路页底部有一块**只读**的「交易名单」（`Pages.ps1:398` 起）：按 程序 / 网站 /
辅助解析 三组列 chips，一颗「管理交易域名…」按钮打开名单页。本条只补**展示**，编辑仍在
「应用 → 交易软件与网站 → 管理交易名单」（`View::Agents`）。

- `status` 新增 `tradeList`：
  `{"programs":[{"name","path"}], "domains":["…"], "aux":[]}`。
  只含 **`target=Trade`** 的条目（`SplitEntry::target()`）；`path` 对老条目是**空串**而不是
  `null`（页面据此不渲染 `title`）；`aux` 本版**恒为 `[]`**——本版没有 NinjaTrader
  「辅助解析」这个概念，字段留着是为了页面只按数组判空组。
- 配置读不出来时：三个键都是空数组，`status` 其余字段不受影响（不许因此整个变 `ok:false`）。
- 快照新增 `TradeList`：`{"Programs":[{"Name","Path"}], "Domains":[…], "AuxDomains":[]}`。
  **PascalCase 在快照里、lowercase 在 status 里**——与文件内其它字段一致。`status` 缺
  `tradeList`（老快照/读失败）时三个键仍是空数组，不是 `null`。
- 页面：线路页「代理软件」之后，标题「交易名单」+ 副标题「这些流量始终走交易线路」+
  「管理交易域名…」（动作名 `domains`，与「管理交易名单」同一条命令、同一页）。空组整行不显示；
  **三组全空**时显示「连接后显示当前线路的交易名单。」。
  - 与旧版的一处**有意差异**：旧版只在交易域名为空时打那句提示，本版改成三组全空才打——
    本版 `aux` 恒空，实际只在「有程序、没网站」时有区别，那时给卡片比给一句「连接后显示」更准确。


### 4.31 一条线路、两种连接方式（**r110 落地**，修 r106-r109 的结构性错误）

**之前错在哪**：每台服务器登记两条线路（`自建 · host` 与 `自建 · host（兼容连接）`）。同一台
机器出现两张卡片，而卡片上的「标准/兼容」开关对前者**按不动**——标准线路文件里根本没有
VLESS 参数（`transport_params` 只从带 REALITY 的 vless 出站读），切兼容必然被拒。旧版是
一条线路两种方式（`DeploymentPages.ps1:877`「标准与兼容连接均已保存」）。

**现在的结构**：

- `config.json` 里每条线路仍是原来的字段；兼容参数存在**附属文件**
  `lines\<id>.compatible.json`（`LineCompatible{server,port,uuid,server_name,reality_public_key,reality_short_id}`）。
  **不写进线路文件**：标准态下线路文件必须是干净的，`engine_config::strip_transport` 会把
  没人引用的中转出站删掉，参数存进去下一次切标准就被抹了。
- `engine_config::compatible_at(line_file)` 读附属文件；`apply_transport_with(obj, transport, params)`
  在切兼容时**按需注入** `tc-transport` 出站，再走原来的 `apply_transport`。
  `prepare_engine_config` 与 `check_transport` 都走这条路：**说能切就必须真能连**。
- `servercmd::register_lines` 只登记一条线路：名字不带后缀；`preferred`（部署页的
  自动/标准/兼容）只决定这条线路的初始方式与线路文件初始形态；`preferred=None` 时**沿用**
  这条线路已有的方式（「自动」不是「改回标准」）。
- `line-add-compatible`（§4.29）改成把参数挂到既有线路上，不再新建线路。
- **老数据合并**：启动时 `servercmd::merge_compatible_lines(root)` 把成对线路并成一条
  （幂等）：从兼容那条的线路文件读出参数 → 落成标准那条的附属文件 → 若选中的是兼容那条，
  改成选中标准那条且方式设为 Tcp → **配置落盘成功后**才删旧线路文件与旧附属文件。
  名字不成对、读不到参数的，一律跳过，绝不猜。

**代价与边界**：切换方式只改「下次连接」用的运行时配置，当前连接不动（与旧版一致）；
附属文件丢了就等于这条线路回到「只能标准」，切兼容会被明确拒绝并说清缺什么。


## 5. `operations.jsonl` v2（**已落地**）
在现有 `{ts,action,ok,detail}` 上追加三个可选字段，不改旧字段含义。S1 实现在 `src/events.rs`：`Origin {source, actor, obj}`；界面、CLI、管道分别传 `ui/cli/pipe`，自动收尾传 `auto`；旧记录缺字段保留为 `null` 并在页面显示「未知来源」。

```json
{
  "ts":"2026-10-30T04:00:00Z",
  "action":"删除线路",
  "ok":true,
  "detail":"备用线路A",
  "src":"cli",
  "actor":"pid:12345",
  "obj":"line:t2"
}
```

| 字段 | 类型 / 枚举 | 写者 | 读者 | 旧记录降级 |
|---|---|---|---|---|
| `src` | `ui|cli|pipe|auto|other` | 各调用入口显式传入 | 记录页、CLI、导出 | 显示“未知来源”，不丢行、不报错 |
| `actor` | string，进程号或会话号 | 同上 | 区分同机发起者 | 显示“未知发起者” |
| `obj` | string，线路 id / 服务商槽位 / 规则值 | 同上 | 记录详情与筛选 | 显示“未知对象”；新删除类记录必须非空 |

- `src/events.rs::record` 不得自行猜测来源；`main.rs` 传 `cli`，`ipc.rs` 按真实入口传 `ui/pipe`，自动动作传 `auto`。
- 每行独立 JSON 解析，新字段可选；坏行跳过规则保持现状。
- 记录仍是 best-effort，写日志失败不得让已完成的连接或配置操作失败。
- 导出与界面筛选使用同一批记录；`src=cli` 的屏幕行数必须等于文件中筛选后的行数。

### 5.1 记录详情（**r57 落地**）

列表每行是**摘要**（`MM-DD HH:MM · 动作 · 结果 · 对象 · detail 前 60 字（来源）`）；
点「详情」展开完整字段，再点收起。

| 详情行 | 来源 | 缺字段时 |
|---|---|---|
| `时间：` | `ts` 原文（完整 ISO，**不压缩**） | 整行不出现 |
| `动作：` | `action` | 整行不出现 |
| `结果：` | `ok` → 成功 / 失败 | 写「未记录」，**不猜成成功** |
| `来源：` | `src` → 界面 / 命令行 / 控制管道 / 自动收尾；表外值原样给出 | 整行不出现 |
| `执行者：` | `actor` | 整行不出现 |
| `对象：` | `obj` | 整行不出现 |
| `详情：` | `detail` **全文**（列表里被截断的那句原话） | 整行不出现 |

- 一条记录若除了「时间/动作/结果」什么都没有（`src`/`actor`/`obj`/`detail` 全缺），
  补一句「这条记录没有更多字段（可能是旧版本写的）」——别让人以为详情没加载出来。
- 展开状态按 `items` 的**原始下标**存，不按「筛选后的第几条」：切换筛选会改变列表长度，
  按显示序存会把详情挂到另一条记录上。**筛选一改就收起**。

## 6. 前端本地状态的唯一例外

断开确认后、宿主首个回包到来前，前端可设置本地 `disconnecting`：按钮显示“断开中”并禁用。还原点击后也可设置本地等待态并暂时禁用按钮，但只有宿主 `restoreResult` 能结束等待和给出成败。测量点击后同样只建立本地等待态，按钮显示“测量中…”并禁用；只有 `measure-latency` 自身终态能恢复按钮、清除旧错误或提供新读数。兼容自救点击后只显示“正在切换并重连”，只有 `use-compatible` 自身终态与 `compatibleResult` 能结束等待或给出成败。除此之外，不得以本地乐观状态冒充宿主已完成的连接、导入、还原、测量或兼容重连。

- 断开确认层在真正发出 `disconnect` 前不得产生操作记录。
- 无关 `status` 回包不得撤层；真实状态变为 `Disconnecting` 或断开命令自身回包才可改变它。
- 超过预算后按 `op` 规则给“查看记录 / 重试”等出路，不得永久禁用。
- 主题（`tcrs.theme`）与上次页面（`tcrs.page`）属于**显示偏好**，只在本地 `localStorage`，不是连接/线路状态的来源；不得用它们推断“已连接”“已生效”或任何宿主事实。偏好值缺失或非法时回退 `system` / `overview`。

## 7. 实现顺序与回归门

1. T-03/T-04/T-05/T-06/T-07 先落实字段与旧记录兼容，再做界面。
2. T-08 统一 `errorCode`、stderr 与退出码；37 命令 × 4 夹具矩阵全部落在 `{0,1,2,3,4,5,6}`。
3. T-13 使用 `measure-latency`；任何改动不得改变现有 `ping` 存活探测。
4. T-15 先让前端兼容 string/object 两种成员，再切宿主到 `{value,label}`。
5. 每次功能修改后同时跑 debug/release 全量测试与隔离门；真实 `C:\SpiderVPN\data` 只读。

## 8. 交易保护（WFP 直连阻断）契约（**已落地**）

> 设计依据：`deliverables/software-company/tcrs-trade-guard-architecture-2026-11-05.md`（v4）。
> 这一段只写**对外可观察的行为**，不解释内部实现。

### 8.1 命令

| 命令 | 写系统 | 预算 | 语义 |
|---|---|---|---|
| `guard-status` | 否 | 同步 | 只读投影。**不建目录、不提权** |
| `guard-precheck` | 否 | 同步 | 连前预检：会不会弹 UAC、有没有名单程序在跑（`RunningPrograms`，见 §8.6） |
| `guard-verify` | **否** | 120 s | 提权**读取**现有规则并回读（只读动作，也要 UAC） |
| `guard-install` | **是** | 120 s | 安装/修复规则（「现在重新启用」走这条）。名单程序在跑时**默认拒绝**，需 `acknowledgeRunning`（见 §8.6） |
| `guard-sync` | **是** | 120 s | 一个事务内全量替换。同上，需 `acknowledgeRunning` |
| `guard-remove` | **是** | 120 s | 解除：删规则 + 写 `Removed` 标记 + 删证据值 |

CLI 同名旗标：`--guard-status` / `--guard-install` / `--guard-sync` / `--guard-remove` / `--guard-verify`，
另有 `--acknowledge-running`（P0-13 的确认凭据，只对 install/sync 有效，见 §8.6）。
`--guard-apply <req.json> <res.json>` 是**内部**提权子进程入口，不由用户手工执行。

- 名单里没有交易条目时，四个动作都**不弹 UAC**（无事可做不是失败）。
- 旧版 旧版正在运行时不碰任何 WFP 对象；连接照旧建立。
- 交易程序正在运行时 `guard-remove` 拒绝（exit 4），并指名程序。
- 同名互斥被占用时返回 exit 6（另一个交易保护操作正在进行）。

### 8.2 状态字段（快照 `State`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `Guard` | `Protected` / `Unprotected` / `Unknown` | 三态，**唯一来源**是 `guard::status` |
| `TradeProgramCount` | int | **实际参与保护**的条目数；`-1` = 读不到 |
| `TradeProgramListed` | int | 名单进程总条数（含直连/日常/未解析）；`-1` = 读不到 |
| `GuardSummary` | string | 后端句子，前端只渲染 |
| `GuardEvidence.Reason` | string | 机器可读原因（`Ok` / `MissingFilter` / `UserRemoved` / …） |
| `GuardEvidence.ReasonConclusive` | bool | 这个原因是「已确定」还是「还不知道」 |
| `GuardVerifiedAtUtc` | string/null | 证据产生时刻（UTC） |
| `GuardEvidenceAge` | string | 时龄文案：`刚刚核验` / `N 分钟前核验` / `较旧：…` |
| `GuardEvidenceAgeSeconds` | int/null | 时龄秒数（单调钟计算，抗改表） |
| `GuardEvidenceStale` | bool | `>= 20 分钟` |
| `GuardEvidenceFreshness` | string | `JustVerified` / `Recent` / `Aging` / `Expired` |
| `GuardVerifyPending` | string | `None` / `Declined` / `Failed` / `Unknown`。**不改三态** |
| `GuardEvidenceSource` | string | `ElevatedVerify` / `ElevatedInstallReadback` / `LiveRead` / 空 |
| `GuardEvidenceTrusted` | bool | 存储可信自检结果（false → `Unknown{EvidenceUnprotected}`） |
| `GuardEvidenceBootId` | bool | 开机标识是否匹配 |
| `GuardConfigDigest` | bool | 名单摘要是否匹配 |
| `GuardEvidence` | object | 明细：`Programs[]`（逐条 `Participated`/`Protected`/`IPv4`/`IPv6`）、`Detection` |

`GuardEvidence.Programs[].IPv4/IPv6` 每族五个字段：`Present` / `Recognized` / `Persistent` / `Disabled` / `FilterId`。

### 8.3 三态口径（不许乐观）

- `Protected` 的必要条件：基础设施核验通过 ∧ 名单非空 ∧ **每个参与程序 × 每个协议族**都是合格持久 block，且 `FilterId != 0`。
- `Unprotected` 只用于**确定**的事实：名单空、全设直连、有未解析条目、规则缺失/被禁用/非持久、基础设施冲突、用户主动解除。
- `Unknown` 用于**读不到或不可归属**：没权限、BFE 未就绪、旧版在跑、跨开机、名单变了、证据超 24 小时、存储不可信、存储串场。
- **时间只用于展示与 24 小时兜底**：10 分钟、25 分钟都不降级。禁止任何「N 秒后失效」的写法。
- 缺字段一律兜底为 `Unknown`，**绝不**兜底成 `Protected`。

### 8.4 证据落点

- 生产：`HKLM\SOFTWARE\SpiderVPN\Guard` 的 `Evidence` 值（`REG_BINARY`，UTF-8 JSON，含 `Sha256`）。
  `Users` 只读；未提权会话里 `Administrators` 是 deny-only，所以同用户的普通进程写不进去。
- 隔离（`SPIDERVPN_ROOT` 存在时）：`<root>\guard\evidence.json`，状态里 `Store=IsolatedFile`。
- 记录里的 `StoreKind` 与本次所选存储不一致 → `Unknown{StoreMismatch}`（生产/测试串场不成立）。
- `Sha256` **只挡损坏，不挡管理员**；不引入签名（签名在这里是安全剧场）。

### 8.5 与旧版的关系

- 只**识别**旧版对象（`LegacyGuardPresent`），**不接管、不删除**。
- 旧版正在运行时不动 WFP、不改系统代理。
- `TradeProgramCount`/`Guard` 不再有「恒 -1 / 恒 Unknown」的占位值；断开确认文案按当次 `Guard` 说话。

### 8.6 安装前置提示：名单程序正在运行（P0-13，**r54 落地**）

> 需求：名单内程序正在运行时，安装前必须先说「请先退出交易软件」；用户坚持继续时，必须如实说明「已建立的连接不会被切断，只有新连接会被阻止」。

**判据只有一处**：`guard::reject_running_unacknowledged(cfg, hooks, acknowledge)`。命令行（`--guard-install` / `--guard-sync`）与界面（`guardEnable`）共用这一份，任何一侧都不许另写一遍。

**预检回包**（`guard-precheck`，只读、同步、不弹 UAC）新增：

| 字段 | 类型 | 说明 |
|---|---|---|
| `RunningPrograms` | string[] | 名单内、且**按完整路径**匹配到活进程的程序名。空数组 = 没有在跑 |

- 只算 `target==Trade` 且解析出唯一绝对路径的条目；未解析 / 直连 / 日常条目一律不算。
- 配置读不到（`TradeProgramCount=-1`）时给空数组：**「不知道名单」不等于「有程序在跑」**，不能凭这个拦人。
- 比对用**完整路径**，不是镜像名。`C:\WINDOWS\System32\notepad.exe` 在 Win11 上只是启动器，真正常驻的是 `WindowsApps\…\Notepad.exe`——起一个记事本造不出「名单程序在跑」（r54 真机验收实测）。

**拒绝语义**：

| 场景 | 结果 |
|---|---|
| 名单为空 | 放行（没有对象要保护，谈不上「先退出」） |
| 名单非空、没有程序在跑 | 放行 |
| 名单非空、有程序在跑、未确认 | **拒绝**：exit 4，**不弹 UAC、不建证据存储、不碰 WFP** |
| 同上、已确认 | 放行，按正常安装流程走 |

拒绝文案固定为「请先退出交易软件再启用交易保护（正在运行：A、B）。已建立的连接不会被切断，只有新连接会被阻止。确实仍要启用时，请在界面里确认；命令行可加 `--acknowledge-running`。」——安全说明必须与提示同句出现，不许只写在文档里、界面上不说。

**确认通道（唯一凭据）**：

- 界面：`guardEnable` 先发 `guard-precheck`；`RunningPrograms` 非空就弹 `Scope=guard-enable` 确认框（标题「交易程序正在运行」、主按钮「仍要启用」、次按钮「先退出程序」），**这一步一条命令都不发**。点「仍要启用」才发 `guard-install {"acknowledgeRunning":true}`；点「先退出程序」只收框。
- 命令行：`--acknowledge-running`。
- 字段缺省 `false`：**不确认就是不放行**。只认明确的 `true`——漏读会让「仍要启用」按不动，默认 `true` 等于把提示关掉，两种都错。
- `guard-remove` 不走这条闸门，它有自己的拒绝（名单程序在跑时 exit 4，见 §8.1）：解除保护不需要「程序在跑」这个前提。

**为什么必须前置而不是装完再说**：阻断是**前向**的——规则只拦新连接，已经建立的连接照旧。装完再提示，用户会以为「一装就立刻生效」，而他的交易程序其实还在裸奔。

**宿主侧白名单（实现约束，不是对外契约）**：`RunningPrograms` 必须进 `UI_REPLY_KEYS`。r54 第一版漏了这一条，真机上确认框永远不出现、单测全绿——同一个坑第四次（前三次见 r36 / r39）。现由「原始回包穿过 `merge_ui_command_reply`」的接线测试钉住。
