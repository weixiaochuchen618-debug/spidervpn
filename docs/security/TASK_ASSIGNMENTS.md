# SpiderVPN COORD-01 任务分配与迁移快照
2026-11-18 Asia/Singapore。此文档记录所有权和快照，不将候选升级为已修复。关联 [总 Issue #5](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5)及 https://github.com/weixiaochuchen618-debug/spidervpn/issues/2 。原三份核心文档及全部历史证据完整保留。规则见 [AGENT_COLLABORATION](AGENT_COLLABORATION.md)。
## 1. 初始化历史核查结果（当前状态见第 3、4、6 节）
- main `857ea7593941ce79f6507db5b1ced076c3a077ba`；#1 已合并于该 SHA（B/C/D/E 先期 Rust 连接配置、代理恢复、IPC、重连修复；不等于这 16 项 DoD）。main SHA 查询未返回直接 workflow，不借其他 SHA 证明。
- #3 Draft 独立 WFP，`2045acd42554b1ad1472ae41ab247b42d8df5655`，Issue #2 Open。#4 文档 PR Open；初始化前文档 HEAD `5d5bd2205b34dcde3223edee196f628e79425fc4`。
- #6→#7→#8→#9→#10→#11→#12→#13→#14→#15→#16→#17→#18→#19→#20→#21→#22→#23→#24→#25→#26→#27→#28 为逐层依赖 Draft（均未合 main）。#6 同时包含 Windows 候选与服务器前期核心，不能视作单纯 SEC-10 或随意改其祖先。
- 发现活跃未交接分支 `fix/sec01-verified-fresh-consume-gate-20261118`，从 #28 HEAD `16bd83adf2f26eac783c68a413e9304313943219` 继承；首次见 `9f02e8d39a1649bf0e3a000c1ef7c5f38c50b42d`，复核变为 `5c8df55582caf68050759b19d03fea4577d4bbae`，最近采样 `21ddfc34ef059158fd1c79f67170944f32e83398`（领先 #28 7 commits）。该采样没有关联 PR 和 CI Run。存在并发写入，禁止覆盖、禁止抢占，未创建 PR；待原执行者退出再核定最终 HEAD/PR，优先继承。
- CI 查询到以下精确 SHA 的完整 workflow conclusion success（仅查询元数据，原始日志复核交 REVIEW-01）：
| PR | SHA | MSVC | GNU | Linux |
|---|---|---|---|---|
| #3 | 2045acd42554b1ad1472ae41ab247b42d8df5655 | 43990452983 | 43990452791 | N/A |
| #6 | e380e82056c6eecbf237f5661b50af52964c8b9d | 44049296975 | 44049297040 | 44049297016 |
| #27 | 19765b4c72ac0e2c1902c8646f3a57febe434b44 | 44255321332 | 44255321600 | 44255321383 |
| #28 | 16bd83adf2f26eac783c68a413e9304313943219 | 44256588132 | 44256587905 | 44256587840 |
Run 链接前缀 https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/ 。旧的 in_progress 记录为历史快照，以上更新不代表真实安全验收。
## 2. 全部缺陷/范围（以原账本完整 DoD 为准）
| ID | 状态 | 下一步/阻塞 |
|---|---|---|
| SEC-01 P0 | 在研，生产未修复 | Rust ledger/WG/撤销/可信 fresh gate，既有链；历史可信迁移、真实授权/撤销和 VPS |
| SEC-02 P0 | 候选 denial-only TLS/降权/停机，生产未修复 | #19–28，实际成功授权、专用服务身份、systemd/切换、VPS 慢连接并发 |
| SEC-03 P0 | #6 ACL/特权目标候选，待真实验收 | Win11 A/B/C、安装/升级/路径劫持/包可信；不改祖先 |
| SEC-04 P1 | 部分 DACL 基础 | 导出/旧文件覆盖与 SEC-03 信任边界，排队 |
| SEC-05 P1 | 未完成 | PID HANDLE/创建时间/镜像、自愈，涉及 engine/connect 共享，排队 |
| SEC-06 P1 | 未完成 | 443/8443/2443 全链路统一，deploy/UI 与已有分支重叠，排队 |
| SEC-07 P1 | TLS pin/兼容候选，未闭环 | 证书有效期/轮换/重新签发和真实 VPS，依赖 SEC-02 |
| SEC-08 P1 | 锁/事务/WG候选，生产未接入 | 与 SEC-01 同锁/事务及故障恢复；并发 50–200、kill -9、真实迁移 |
| SEC-09 P1 | #6 安全卸载候选，待实机 | exit3/UAC拒绝/KeepGuard/相邻路径、真实持久 BLOCK |
| SEC-10 P0 | #6 一次性提权 IPC 候选，待真实验收 | A/B/C UAC-01–12、长租约另审，不改祖先 |
| SEC-11 P1 | #6 UTF-8/密钥形状修复候选 | 生产 panic 可触发性/Unicode fuzz、完整验收未闭环 |
| WFP-01 P0 | #3 精确许可候选 | 仲裁、撤销、真实网络 |
| WFP-02 P0 | #3 长期 helper/默认关闭试验候选 | DEV-02 先做隔离 IPC/生命周期硬化；生产接线另安排 |
| WFP-03 P0 | TUN/Wintun 未生产完成 | 真实 LUID/路由/重授权与断线/重拨，依赖 lease |
| WFP-04 P0 | v1 证据/归属基础，v2未闭环 | 证据同步/回滚/provider，依赖 lease |
| WFP-05 P0 | 未完成 | 真 Win11/sing-box/Wintun IPv4/V6 防泄漏/故障注入，最终发布门槛 |
| AUX-01/02/03 P2 | 未完成 | 双栈兼容/许可证与来源合规/审查覆盖，排队 |
本轮 16 项完整 DoD 为 0；不关闭 Issue #2/#5，不将 #1 先期修复重复开发。
## 3. 任务与独占文件锁
### COORD-D01 / DEV-01 — SEC-01 P0（与 SEC-02/08/07 共享研发依赖）
- Issue #5，继承 [Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29) 与唯一现有分支 `fix/sec01-verified-fresh-consume-gate-20261118`。直接父基准 commit `16bd83adf2f26eac783c68a413e9304313943219` (#28)；**最终接管基准 HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`；ACTIVE，COORD-01 已解除 HANDOFF_BLOCKED，DEV-01 为该分支唯一业务代码写入角色**（2026-11-18 16:27 Asia/Singapore 用户确认旧 Agent 已停写；GitHub 多次 HEAD 核对一致，无其他认领证据）。不得新建分支/PR、重写祖先或改其他 Agent 分支。GitHub 共享凭据不能证明所有外部进程已停止，任何非预期 HEAD 变化须立即停写上报。
- 继承相对 #28 的全部 10 commits，先核对已有通过的专项与缺口，fresh consume gate/feature wiring/RSA 测试，以及可信 Open 邀请 metadata（不是不可信 invites.json）、独立 bearer、Host、管理/服务 pin、签名 JWS、唯一 JSON、完整 Claims、同一个独占 LedgerStore。不得将只读 VerifiedFreshConsume 当已授权 Grant；不得增加生产 caller、签发器或 WG mutation 直到总控安排下一阶段。先核对现有 gate 真实旧版失败/候选正反对照与严格编译，不重复已有测试。可信历史来源不足默认拒绝。按交接 §83 优先梳理可信 metadata/bearer provenance 持久层与有限只读 retry；在现有授权文件范围推进可独立验证的部分，若需要新模块、ledger mutation、CI 或签名/生产事务接线，先提交最小范围及依赖给 COORD-01 解锁，不越权。
- 接管后允许写的精确路径：`server-rs/src/fresh_consume_gate.rs`、`server-rs/src/fresh_consume_gate/tests.rs`、`server-rs/src/http_one_request.rs`、`server-rs/src/legacy_request_proof.rs`、`server-rs/src/lib.rs`、`server-rs/Cargo.toml`、必要锁定依赖时 `server-rs/Cargo.lock`。其他路径（含 CI workflows、WG/ledger mutation、生产 Python、Windows src/、WFP、UI、部署、其他分支、全局文档）禁止写；扩范围由总控批准。
- 验收：Linux cargo build/test --locked，原有 feature 与新 feature 两路径、-D warnings、独立 RSA 金样本、正确请求、篡改 bearer/host/签名/指纹/recipient、重复字段、过期/撤销/已消费不得恢复 peer、锁/generation 变化负例；确保没有授权副作用。MSVC/GNU/Linux 同 HEAD workflow 绿，若新 feature 未被 CI 实际覆盖须报总控调整 CI 所有权；原生产 SEC-01/02/08/07 仍需可信历史/真实授权和 isolated VPS 完整 DoD。
- **第 8 节新增授权（当前有效，优先于本节早期禁止范围）：** COORD-D01-A / R01-007，允许仅在现有 #29 分支修改 `server-rs/src/wg_readonly.rs`、`server-rs/src/wg_conf_audit.rs`、`server-rs/tests/wg_namespace_e2e.rs` 与 `.github/workflows/security-pairing-rust-linux.yml` 中专用真实 netns 构建/执行段（仅增加此专项必要覆盖）。原 gate 文件锁继续有效；其他 CI、ledger_disk.rs、lock/transaction、WG 写入模块及生产入口仍禁止。第 8 节具体范围与验收为准。
### COORD-D02 / DEV-02 — WFP-02 P0 独立长期 helper 安全边界（WFP-01 相关）
- Issue #2，继承 Draft PR #3，分支 `fix/wfp-trade-egress-p0-20261116`，原接管基准 `2045acd42554b1ad1472ae41ab247b42d8df5655`；**ACTIVE，唯一执行窗口 DEV-02-W01（逻辑窗口标识，非新增 Agent）**，本轮正式恢复基准 `af57e8f2a4a4ca77686b75bb5ad5a912df551531`。仅指已提交 Issue #2 评论 6974171595 / PR #3 评论 6974172494 的窗口；另一窗口（认领 6973377869、停写 6973410973/6973412275）不得恢复写入。R01-006 协作暂停已由总控解除，权限细则见 §7。不重新建 WFP 分支。先聚焦长期 helper 的 IPC 创建/请求与 ACK 绑定/路径及进程身份、取消超时与失败释放；依据 SEC-10 同类威胁模型但不直接合入 #6。生产连接接线、TUN、v2 schema 留总控以后授权，不能仅为并行扩大范围。
- 允许写 `src/guard/lease_helper.rs`、`src/guard/proxy_identity.rs`、`src/guard/egress_policy.rs`、`src/guard/wfp_win.rs`（仅 scoped 动态 lease/测试，不改持久 BLOCK）、`tests/wfp_proxy_canary.rs`、`tests/guard_wfp_layout.rs`。不许改 `src/connect.rs`、`src/main.rs`、`src/guard/mod.rs`、`src/guard/elevate.rs`、`src/guard/evidence.rs`、`src/secretfile.rs`、`src/guard/wfp.rs`、Cargo/workflows、Windows 其他模块、server-rs、文档及其他分支。所需跨文件 ACL helper 若不在现有分支，报告总控；禁止复制不可信实现或降标准。与 DEV-01 写文件集合不相交；与 #6/main 的集成冲突另调度（connect/main/guard mod/MSVC workflow 等）。
- 验收：Windows MSVC/GNU 精确 HEAD、现有 WFP tests/canary 全保留；证明默认 OFF、未授权请求/伪造 Ready/ACK/PID、reparse/硬链接、取消/UAC拒绝/超时/控制及引擎退出后无遗留动态许可，v1 持久 BLOCK/provider 未受影响，正负例真实可复现。隔离 A/B/C UAC、真实 Proxy/TUN sing-box/Wintun、IPv4/IPv6、端口劫持/断网/重授权/崩溃/重启抓包和过滤器读回仍为 WFP-05 发布门槛，未达到不能合并或称零泄漏。
### COORD-R01 / REVIEW-01 — 独立安全审查与验收
- Issue #5 / #2、PR #6、#27、#28、#3，后续 DEV-01 接管 PR。REVIEW_PENDING；无需远程代码分支：每个 SHA 使用隔离本地 detached checkout，只读。审查基准 #6 `e380e82056c6eecbf237f5661b50af52964c8b9d`、#27 `19765b4c72ac0e2c1902c8646f3a57febe434b44`、#28 `16bd83adf2f26eac783c68a413e9304313943219`、#3 `2045acd42554b1ad1472ae41ab247b42d8df5655`；新增 #29 最终交接审查基准 `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`；后续 HEAD 变化重新审查。
- 允许读取全部相关源/测试/历史文档/CI，允许本地临时测试且不推送；GitHub 写范围仅对应 PR review/comment 与 Issue 评论，禁止提交任何仓库文件、修改分支、关闭 Issue、擅自批准/合并。优先复核五组 CI 原始 job/log、失败/既有 skip、实际专项覆盖，检查 Linux denial 并非生产授权；按 SEC03_INSTALL_ACL_ACCEPTANCE / SEC10_WINDOWS_UAC_ACCEPTANCE / SEC09_UNINSTALL_ACCEPTANCE 手册收集三账户结果；WFP-05 验收网络矩阵；记录真实 VPS 迁移/撤销/并发/rollback/reboot 阻塞。没有目标机器不执行生产验证，明确 NOT RUN，完成不依赖实机的审核。
- 输出每个 PR 精确 SHA、Run ID/job/日志链接、实测命令、正负例、隔离环境、PASS/PARTIAL/FAIL/BLOCKED 和缺口；不得将自己未执行的命令或 CI metadata 伪称实测；HEAD 变化重新审查。共享账号时只写署名 REVIEW-01 评论，不假冒独立 GitHub 批准。
## 4. 交接与调度
DEV-01 已正式 ACTIVE 并独占 #29 分支；DEV-02 保持 ACTIVE、独占 #3 分支；REVIEW-01 保持 REVIEW_PENDING，独立只读。三个角色可按现有范围并行；先在相应 Issue/PR 发布开工记录，不因任务已分配就声称实际开发或审查已完成。#6 的 Windows 候选不再抢占开发，实机结果先审查、发现问题由总控在独立后续分支调度。新任务不得跨过同一文件锁、不能强拆。COORD-01 每次恢复更新此表，核对最新 PR/CI/Issue；所有合并必须经完整安全 DoD 和用户明确授权。

## 5. 初始化回读期间发现的新恢复点（历史记录，已由第 6 节正式接管替代）
- 原执行线已创建 [Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29)，base #28 `16bd83adf2f26eac783c68a413e9304313943219`，HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`。原执行者仍可能正在写入，COORD-D01 继续 HANDOFF_BLOCKED；停止旧执行者并由总控锁定最终 SHA 后，DEV-01 直接继承 #29，不新建分支/PR。
- #29 已新增 Linux CI gate 专项（现有差异还含 `.github/workflows/security-pairing-rust-linux.yml`；作为历史已存在改动保留，DEV-01 无该文件写权限）。当前精确 SHA Linux [44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843)、GNU [44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885)、MSVC [44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) 均 In Progress，不能标绿。核对 feature 是否真正覆盖，不能将候选当 Grant，生产状态仍不改变。REVIEW-01 增加 #29 只读审查，结论锚定该 SHA；待最终 HEAD 重验。
- 初始化 commit `d1f3addd67976e1360a52a32d180e4d13116234b` 已读回，唯一新增两份协作文档，无源代码修改；main/WFP HEAD 均保持不变。

## 6. COORD-01 正式独占接管与调度更新（2026-11-18 16:27 Asia/Singapore，历史快照；最新见 §7）
- 用户确认原串行开发 Agent 完成最终交接并停止开发及 GitHub 写入。核对 AGENT_HANDOFF §82–83、Backlog D.84–86、原分支/PR/Issue 评论和 review；最终文档快照 `7aee63d283769c66ff779411ef20c5fc5e08c049`。没有发现新业务提交或其他Agent认领。再次读取分支与 PR #29 HEAD 均 `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`，与初始化最终观察相同；#28 对比 ahead 10/behind 0、7 文件 +712/-7，采样 `21ddfc34ef059158fd1c79f67170944f32e83398` 是祖先（一脉相承 ahead 3/behind 0）。保留全部历史。共享 GitHub 账号不能直接检测其他聊天或后台进程；独占依据用户确认及可观察仓库状态，不是服务端权限撤销。
- PR #29 仍 open/Draft/未合并，base #28 `16bd83adf2f26eac783c68a413e9304313943219`。准确 SHA 全部 workflow Completed/Success：Linux [44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843) job 134646769263/134646769792；GNU [44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885) job 134646769104；MSVC [44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) job 134646769473。已核对 workflow 和 job/step metadata，Linux fresh gate 专项步骤成功；D.86 原交接记录 8/8、旧 parser 9/9、HTTP 14/14、core 121/121。原始日志独立复核归 REVIEW-01；真实 VPS/历史迁移/授权事务尚未完成，非生产安全验收。原 §5 in_progress 仅为历史状态。
| Agent | 任务 | 最新调度状态 | 下一步 |
|---|---|---|---|
| DEV-01 | COORD-D01 | **ACTIVE**；PR #29 唯一代码写入角色 | 先认领留痕，继承最终 SHA；可信 scope/token 来源和只读 retry 优先，已有预认证不得重复开发；超范围先报总控 |
| DEV-02 | COORD-D02 | ACTIVE；PR #3 HEAD `2045acd42554b1ad1472ae41ab247b42d8df5655` 未动 | MSVC 43990452983、GNU 43990452791 仍成功；未发现 DEV-02 新提交/认领评论，先按已有 WFP helper 任务执行并留痕 |
| REVIEW-01 | COORD-R01 | REVIEW_PENDING；独立只读 | 未查到相关 PR 独立 review 或 REVIEW-01 审查报告；核查 #29 三平台原始日志，继续 #3/#6/#27/#28 和实机验收矩阵，缺环境标 NOT RUN |
- 两开发 Agent 写路径无交集；禁止擅自接入生产授权或连接、改变 UI/WFP persistent BLOCK、跳过失败测试。共享 CI/模块锁不变。main `857ea7593941ce79f6507db5b1ced076c3a077ba`、Issue #2/#5 Open；所有候选继续 Draft，未经真实验收和用户合并授权不得进入 main。

## 7. COORD-01 核定 DEV-02 唯一执行窗口（2026-11-18 17:50 Asia/Singapore）
- **R01-006 协作冲突处置：ACTIVE / DEV-02-W01，解除业务代码写入暂停**。根据用户提交的窗口截图及 GitHub 实际记录，唯一获授权窗口是原认领 Issue #2 [6973373563](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2#issuecomment-6973373563) / PR #3 [6973374526](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-6973374526)，且最后主动暂停并提交 Issue #2 [6974171595](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2#issuecomment-6974171595) / PR #3 [6974172494](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-6974172494) 的持续开发窗口。另一 DEV-02 窗口的认领 Issue #2 6973377869 / PR #3 6973378695 已由其停写声明 [6973410973](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2#issuecomment-6973410973) / [6973412275](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-6973412275) 终止；该窗口不得写入源码或重新认领，不得与 DEV-02-W01 并行。DEV-02-W01 只是同一个 Agent 的唯一逻辑会话标签，不新增 Agent。共享账号无法技术性证明其他会话停止，故遵守逻辑锁；恢复先核对任务表、HEAD 及记录，任何未知移动马上停写上报。若更换窗口须总控重新核定、旧窗口先停写。
- PR #3 open/Draft，分支 `fix/wfp-trade-egress-p0-20261116`，本轮恢复 HEAD `af57e8f2a4a4ca77686b75bb5ad5a912df551531`；与原接管 `2045acd42554b1ad1472ae41ab247b42d8df5655` compare ahead5/behind0，只有 `src/guard/lease_helper.rs`（+291/-50）及 `src/guard/proxy_identity.rs`（+24/-8）变化，符合六文件锁。保留五个已有 commit：2139a3c8a30736b081a92db5642cb0e7b5f5a362、faf4b1a2cf8c4ed537416d5c5b53a7ac00cb88b8、5838909043187e6d70e79ed89a17ac6e22f4712f、1285d986316628111b5871f93e89d6f7280ca65f、af57e8f2a4a4ca77686b75bb5ad5a912df551531。不新建分支/PR、不重写历史。
- 最新准确 SHA MSVC [44273663008](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44273663008) job 134696292474 和 GNU [44273662970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44273662970) job 134696276741 均 Completed/Success；实际读取 workflow/job/step 元数据，MSVC build、BFE canary、integration、regression、portable suite（既有8排除）全成功，GNU build.ps1 及专项步骤成功。本轮未取得最新 SHA 原始日志，交 DEV-02 / REVIEW-01 分别核查；旧 58389090 日志数不视为最新测试结果。
- DEV-02 下一步：先按唯一窗口 ID 认领留痕，核对最新精确 SHA 原始日志与回归，继续 R01-002 可信 IPC 对端/安全目录与文件发布、实际 helper 消费 ACK 的确认、取消/失败清理，R01-003 跨账户 temp 路径信任。PID/nonce 仅绑定线索，不代替认证；不能简单放宽 ACL。仍限 §3 六文件；SEC-03/10 共享 ACL/进程身份基础若确实需要跨模块，提交具体最小改动/测试方案待总控授权，不擅自合入 #6 或改共享文件。R01-002/003 与 WFP-05 尚未验收。真实 A/B/C、Proxy/TUN/Wintun、IPv4/IPv6、故障抓包/过滤器读回 NOT RUN，保持默认 OFF、持久 BLOCK、UI/连接、Draft；禁止合并 main。
- DEV-01 保持 ACTIVE，PR #29 最新采样 `e6de962deccb0b66adbec87180f29abf6db84f1c`，准确 SHA Linux 44274284944 / GNU 44274285104 / MSVC 44274284861 已 Completed/Success（元数据）；已见 [DEV-01 增量报告 6974207160](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-6974207160)。原始日志与 R01-005/007 可信 pin、kernel/config 公钥身份及防回滚仍需验证。新增文件锁申请待总控后续单独核定，本次不扩大范围。
- REVIEW-01 保持 REVIEW_PENDING（已实际开展），已见 [第一轮报告 6973462825](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5#issuecomment-6973462825)、[第二轮报告 6973542187](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5#issuecomment-6973542187) 和 [WFP 增量审查 6973536881](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-6973536881)。R01-006 的协作核定现完成，其他安全发现不关闭；按最新 #3/#29 SHA 继续独立审查与实际 CI 原始日志、实机验收。无真实环境不得宣称 PASS。
- 本次总控仅更新任务表，不写业务源码、不修改开发分支/CI、不关闭 Issue，main 仍 `857ea7593941ce79f6507db5b1ced076c3a077ba`。

## 8. COORD-01 增量任务解锁：COORD-D01-A / R01-007（2026-11-18）
- 依据 [DEV-01 最小扩锁申请 6975548265](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-6975548265) 及 [Issue #5 6975549236](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5#issuecomment-6975549236)，结合 [REVIEW-01 R01-005/007 6973538481](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-6973538481)，读取准确 HEAD 的 wg_readonly.rs / wg_conf_audit.rs / ledger_disk.rs / fresh_consume_gate.rs、现有 netns 测试和 Linux CI。当前只读 adapter 比对 live/durable peers 并复读，但尚无由可信 metadata 固定的 kernel/durable server public key 身份证明；ledger_disk 明确不是 anti-rollback store。
- **DEV-01 ACTIVE；解除 A 子阶段文件权限阻塞，继承 PR #29 原分支，恢复基准 `530f11168d8707e04543fc968c245c5e76243852`（父 #28 不变）。** 相对交接 81b2f57e ahead6/behind0，仅 gate.rs、tests.rs 变化；完整保留。三 CI 同 SHA Completed/Success：Linux [44281653867](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44281653867)、GNU [44281654075](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44281654075)、MSVC [44281654168](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44281654168)。DEV-01 已记录 Linux gate 14/14、GNU 14组零失败；COORD-01 本轮直接读取 MSVC job 134723617995 原始日志 1432 passed/0 failed/1 ignored/8 filtered（既有）。未重跑本地测试。
- **新增精确文件锁（仅 #29）：** `server-rs/src/wg_readonly.rs`、`server-rs/src/wg_conf_audit.rs`（只读接口身份和完整 snapshot 绑定、内联测试），`server-rs/tests/wg_namespace_e2e.rs`（仅隔离 netns 增量），`.github/workflows/security-pairing-rust-linux.yml`（仅既有真实 kernel netns 专用 compile/execute 段，为新专项增加 feature/fixture 或串行执行；不能删除/跳过旧测试、改触发器/权限/其他 job、使用真实密钥或生产主机）。原 §3 gate/tests/lib/Cargo 范围保持；依赖变化仅必要且已锁定安全依赖，未经总控批准不新增第三方依赖。DEV-01 独占新增路径；DEV-02 不接触 server-rs 或该 CI，祖先 #6–#28 不改。
- **实施边界：** 对 independently pinned WgInterface 及 ServerPublicKey 校验真实 kernel server public key，持有原账本锁时核对 protected wg.conf 对应的公钥身份（必要时使用固定受信 WG 工具、受保护输入、严格边界与保密处理；不把私钥写到 argv、日志或回包）；现有 peer inventory 和前后读回不能被绕开。任何身份/库存/世代/时钟不一致、缺失、解析歧义、超时即拒绝；不能仅凭名称、同文件 hash 或调用者自证授权。保持所有既有公开 API 调用点安全语义；必要时新增仅限此阶段的验证接口，不弱化旧审计。生产 caller、WG/ledger mutation、签发、JWE、迁移/切换和部署均禁止。非合作外部 writer/ABA 与真实 VPS 保留阻塞，不夸大重复读取证据。
- **A 验收：** 现有全部测试及 --locked/-D warnings；新增真实 disposable kernel netns 正确身份、同名不同 key、protected config 与 kernel 不一致、错误/缺失/歧义 key、完整 inventory 漂移/无授权拒绝、锁内验证等正负例；确保真实 public gate/adapter 验证链覆盖而非仅 mock，测试 secrets 不输出。MSVC/GNU/Linux exact SHA 全部成功，原始 job/log 与独立 REVIEW-01 验证；旧版可复现失败、候选成功、真实 VPS NOT RUN。净增测试、不重复已通过的 14 gate 测试。
- **COORD-D01-B / R01-005 持久 pin/防回滚：QUEUED（仍须可信来源设计核定，和 A 串行）。** 暂不授权 ledger_disk.rs 或账本 schema/写入改动。DEV-01 可只读核查并在 #29 提交最小信任模型：独立受信根、checkpoint/世代与 revocation tombstones 的抗回滚来源、生存期、缺失/降级/旧数据失效、崩溃重启与恢复策略，不记录秘密；不能把同一可回滚文件内的 hash/generation 当外部信任锚。A 完成后总控依据设计再核定 B，避免假装存在生产信任锚；不阻塞 A。R01-005/007 均未关闭。
- **DEV-02-W01 ACTIVE：** 唯一窗口已在 [Issue #2 6975205429](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2#issuecomment-6975205429) / [PR #3 6975206428](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-6975206428) 实际恢复认领，#3 当前采样 `af57e8f2a4a4ca77686b75bb5ad5a912df551531` 未新增提交。MSVC 44273663008/job134696292474 原始日志 1430 passed/0 failed/1 ignored/8 filtered、BFE 10项专项已运行；GNU 44273662970/job134696276741 原始日志 lease_helper 10/10、无失败。COORD-01 本轮直接读取上述两份日志。R01-002/003 继续按 §7 原六文件锁处理可信 IPC/ACK 消费与跨账户授权；尚未收到具体跨文件最小 patch/接口方案，暂不扩锁；R01-006 已解除且另一窗口不得写入。
- **REVIEW-01 REVIEW_PENDING：** 继续最新 #3/#29 增量审查，优先 A 的真实 key/inventory 验证负例及 CI 改动是否只增覆盖；跟踪 R01-005/007；#6 R01-008/009 与 UAC/卸载、#28 R01-004 仍为候选缺口，等待真实环境，禁止合并。未授权新的业务写入角色。main 857ea7593941ce79f6507db5b1ced076c3a077ba、PR #3/#29 Draft，不关 Issue #2/#5。
