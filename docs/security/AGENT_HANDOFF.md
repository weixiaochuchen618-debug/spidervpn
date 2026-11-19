# SpiderVPN 新对话 / 新 Agent 交接说明（从这里开始）

> **交接快照**：初始 2026-11-17，Asia/Singapore。**最新恢复入口见 §84、[TASK_ASSIGNMENTS.md](./TASK_ASSIGNMENTS.md) §23 及后续授权、[REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md) D.87；前述历史SHA/CI状态不得当作实时指令。**  
> **必须先读**：  
> 1. [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md) —— **唯一任务状态来源**，含 9 项原审查 + 2 项补充 + 5 项 WFP P0；  
> 2. [SECURITY_REMEDIATION_PLAN.md](./SECURITY_REMEDIATION_PLAN.md) —— 逐项 Rust 实施技术方案、测试与发布门槛；  
> 3. [PR #3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) —— 原 WFP 防泄漏候选代码，**仍为 Draft**；[Issue #2](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2) —— 原 WFP 目标。

## 1. 项目与当前版本

- 项目：`https://github.com/weixiaochuchen618-debug/spidervpn`
- 正式 `main`：`857ea7593941ce79f6507db5b1ced076c3a077ba`。
- WFP P0 开发分支：`fix/wfp-trade-egress-p0-20261116`，截至快照 HEAD `2045acd42554b1ad1472ae41ab247b42d8df5655`。
- PR #3：未合并、Draft；对应 [MSVC](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452983) / [GNU](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452791) CI 都成功，**不证明真实断线零泄漏**。
- 本文档分支：`docs/security-remediation-handoff-20261117`，从 main 分出，只保存执行方案，不修改产品源码。其他 Agent 必须根据当前 GitHub 最新状态更新 SHA，不得把本日期快照当实时事实。

## 2. 用户的硬性要求（不得擅自变更）

1. 新增产品功能与安全修复必须以 **Rust 编译**；服务器旧 Python 邀请服务考虑 Rust Linux daemon 兼容替换；现有 PowerShell 安装/卸载可保留薄入口，不得把新增特权安全决策放在脚本里。
2. 不改变现有 UI、正常下单/连接交互、代理/TUN 默认行为、原持久交易程序 WFP BLOCK 的语义；不得因为测试难通过就取消安全断言、私自删除保护或改变关键指标。
3. 先做对抗式审查、最小变更和专项复现，再落地；Windows MSVC/GNU 双构建、Linux Rust 服务测试及隔离真机验证必须与实际改动对应。
4. **不能未经完整 P0 验收合并 PR #3 到 main**。WFP lease 的实验开关 `SPIDERVPN_WFP_LEASE_EXPERIMENT=1` 默认关闭。
5. 如需用户执行 PowerShell，提供**完整可复制粘贴的 PowerShell 代码块**，不要拼字式指令；但当前交接优先让 Agent 在 GitHub 修改并通过 CI，不能要求用户手工替代可自动完成的工作。
6. 用户要求的是可持续交接、实际提交与准确的测试状态；不得说“后台会继续执行”或把未完成事项说成已完成。

## 3. 已知 9 项与额外 2 项（全部未闭环）

| 编号 | 问题简述 | 状态 | 关联代码 |
|---|---|---|---|
| SEC-01 | 已撤销 WG 设备可通过已消费邀请旧请求重放重新加回 | 未修复 | `assets/tc-pair.py:1230`，`deploy.rs:849` |
| SEC-02 | 单空闲 TCP 连接阻塞 TLS 监听握手 | 未修复 | `tc-pair.py:1456` |
| SEC-03 | 可写安装目录 + 可写引擎配置 + 管理员执行边界 | 未修复 | `install.ps1`，`engine.rs:163`，`isolation.rs:37` |
| SEC-04 | 私钥文件 DACL 仅覆盖部分，REALITY 导出走普通 write | 部分修复 | `secretfile.rs:91`，`main.rs:692` |
| SEC-05 | 引擎停止/代理自愈只核 PID，可能误杀复用 PID | 未修复 | `engine.rs:100`，`connect.rs:689` |
| SEC-06 | UI 默认 443 与 `validate_identity` 拒绝小于 1024 冲突 | 未修复 | `uiweb_form.rs:705`，`deploy.rs:1933` |
| SEC-07 | 邀请 TLS 证书只初始化不续期，过期误报 pin 错 | 未修复 | `tc-pair.py:352`，`pairing.rs:4556` |
| SEC-08 | 邀请状态/WG 配置无跨进程锁，固定 tmp | 未修复 | `tc-pair.py:82,238,1286,1333` |
| SEC-09 | 卸载 Guard exit 3 仍删 exe、残留 sing-box、路径子串匹配 | 未修复 | `uninstall.ps1:90-141` |
| SEC-10 | 旧 `--guard-apply` 提权请求临时文件/输入信任边界 | **PR #6 开发中，部分候选已推送，待 CI/双账户验收** | `guard/elevate.rs`、`secretfile.rs` |
| SEC-11 | UTF-8 `&ts[5..10]`、`value[..43]` 和生产 panic | 未修复 | `uiweb_form.rs:6828`，`pairing.rs:2072` |

**服务器端两个漏洞的旧版复现来自另一 Agent 的离线报告；这次快照确认危险代码仍在，但尚未在最新代码做实机动态利用复现。** 不要声称已实测新版本。

**PR #3 WFP 另外还没完成**：WFP-01 代理精确许可生产仲裁、WFP-02 长期 helper 正式生命周期接入/IPC 权限、WFP-03 Wintun/TUN 故障退出放行、WFP-04 v2 证据/同步/回滚、WFP-05 真机网络泄漏验收。当前只是候选与隔离实验代码，详见 Backlog。

## 3.1 最新活动修复恢复点（SEC-10，2026-11-17）

- 独立 Rust 修复 [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，从 main `857ea759` 开始；最新已推送提交 `3f0ef0c5`，Draft，不影响 main 或 WFP PR #3。
- 已做：提权子进程二次核验 WFP AppId/device path、拒绝虚假 StoreKind；guard 请求使用随机独立 DACL 目录，UAC 启动参数携带请求 SHA256 内容绑定，固定文件名/路径验证，主程序预建空回执避免不同进程文件 owner 权限问题；Rust 回归测试增加被修改的请求和未知 StoreKind 在调用 WFP 后端之前即拒绝；提权辅助进程超时尝试终止。
- 待做：**必须先检查**最新 [MSVC CI](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44008388149) 与 [GNU CI](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44008388178) 的状态及失败日志。然后完成 Windows 非管理员与管理员不同账户的实机 ACL/UAC 验收、可信安装目录和配置引擎路径等 SEC-03 工作。没有通过前不得称为 P0 已修复。
- 旧版 Windows GNU 运行 `44002952064` 的 14 项专项单测只有 1 项失败：测试没有先按真实路径创建 `req.json` / `res.json`，却期望 Windows reparse 校验放行不存在文件；已在 `a357668d` 修正测试先确认缺失文件必须拒绝、真实两文件创建后通过，**没有放松安全判断**。`7f0b65af` 增加回执失败不得返回 exit 0 的保证。最新 CI 仍待验证。
- `7f0b65af` 的 GNU 测试 15 项 Guard + 11 项身份全部通过，但 `secretfile` 中两项默认继承 ACL 测试因为 CI Runner `%TEMP%` 本身受保护而失败；`707f6ef3` 已在隔离目录显式构造旧版宽松权限，再验证收紧与非私钥文件不误改。`5f3a4726` 新增按 Windows 打开句柄检查硬链接数，拒绝请求/回执硬链接，测试不跳过。当前最新 CI 未完成，不能合并 PR #6。**跨账户 UAC 的真实可用性和权限隔离仍未验收**。
- 最新活动提交 `94affb04`：发布版 Rust 不再接受 `SPIDERVPN_ROOT` 控制安装根/HKLM Guard 证据，提权端拒绝格式正确但与运行环境不符的 StoreKind；GNU CI 新增无 test/debug 编译配置的 Release 根覆盖检测；Windows 测试直接读回 SDDL，验证受保护的 IPC 目录与两个文件显式 BA、SY、OW 且没有 AU/BU。最新两套 CI **等待结果**。
- 实机跨账户测试（A 普通用户、B 独立管理员、C 第二普通用户）必须按照 [SEC10_WINDOWS_UAC_ACCEPTANCE.md](./SEC10_WINDOWS_UAC_ACCEPTANCE.md) 的 UAC-01～12 执行，当前**尚未完成**；成功的代码静态/单测不得称为跨账户 UAC 已验收。
- **新的真实风险及修复**：旧版 Guard 请求/回执及随机目录先创建后 SetNamedSecurityInfoW，存在低权限进程在 DACL 收紧前抢占句柄的窗口；Rust 最新 `3f0ef0c5` 用原生 Win32 CreateDirectoryW/CreateFileW 在对象创建时直接附加保护 DACL，创建失败拒绝，禁止重用预占目录/文件，并增加宽权限父目录下的创建瞬间 ACL 验证。最新 CI **待完成**，仍需独立 Windows A/B/C 账户真实 UAC/ACL 验证，不得宣布漏洞全闭环。
- **SEC-03 本轮新增候选**：PR #6 head `a81da3e1` 使发布版 Rust 忽略 `SPIDERVPN_ENGINE_ARGS` 测试环境钩子；管理员 TUN 引擎启动前检查配置所选 EXE 实际指向 SpiderVPN exe 同目录的 `sing-box.exe`，拒绝任意目录 exe，普通代理模式不更改；新增 Rust 负向测试。**尚未证明随包文件不可被标准用户替换**，安装器保护 root/bin、升级/卸载兼容与真实 UAC 测试必须继续完成。提交 CI [MSVC](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44009947271) / [GNU](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44009947357) 待验证。
- **本轮最新 SEC-03 状态**：PR #6 HEAD `7298bfc4`（[MSVC](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010183604) / [GNU](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010183550) 最新 CI 待完成）。修复了只检查管理员 TUN 会被管理员 Proxy 绕过的逻辑，现只要 `probe::is_elevated()` 真提权，无论模式都要求 bundled `sing-box.exe` 与前端同目录且无 reparse；正常非管理员代理自定义引擎不变。**管理员自定义外部引擎会被拒绝，记录兼容影响，不要偷偷改回去。** 同目录文件/安装根 ACL 尚未证明防低权限篡改，SEC-03 不可关闭。
- **当前最新交接锚点**：SEC-10/SEC-03 [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6) head `5bbf743a`；[MSVC 44010494382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010494382)、[GNU 44010491449](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010491449) 待此 SHA 验证。上轮把管理员 TUN 限制提升为**所有实际提权 Proxy/TUN** 都验证 `sing-box.exe` 与 SpiderVPN 同目录（禁止配置指向任意 EXE），普通用户代理保留自定义引擎；GNU 新增精确回归过滤。中间 `a5f1389e` 由于两个源码文件分开提交出现旧函数名 E0425，最新已统一命名。这仅修复“任意外部 EXE”入口，受保护安装 bin 与真正跨账户 UAC 仍缺，不能标已验收。
- 真正任务状态写在 [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md) 的 “D.1 最新恢复点”。更换 Agent 直接从该条开始，不需要用户重新说明。

## 4. 新 Agent 首次执行的标准流程（无需用户再解释需求）

1. GitHub 读 PR #3、main 最新 HEAD 和正在进行/失败的 CI；确认文档分支与当前分支差异。不因之前的聊天记录猜最新状态。
2. 打开 `docs/security/REMEDIATION_BACKLOG.md`，找尚未关闭且依赖满足的最高优先级任务，**向用户说明这轮选择的具体 ID**。若用户明确指定 ID，以指定为准。
3. 读取该任务的完整源文件及调用链，特别是不能只看一个 grep 片段；复现/编写负对照。安全链应同时检查低权限输入、提权端执行和持久化修改。
4. 只开一个逻辑清晰的修复 PR；所有新生产逻辑用 Rust；对旧 HTTP/JSON/CLI / 用户界面兼容做显式回归。
5. 在 CI 完成前仅报告“已推送，待验证”；失败时读日志修复，不删测试；成功后核验 commit/分支与通过运行一致。
6. 真机验收尚缺时标记“待实机”，不合并/不开生产功能，记录回滚步骤与已知限制。
7. 更新唯一 Backlog 的任务卡证据，并在 PR 描述链接此文档，方便下一个 Agent 接着做。

## 5. 最适合下一轮开工的任务

**安全优先**：SEC-03 + SEC-10（可信提权链）与 SEC-01 + SEC-08（Rust 邀请状态机和撤销防重放）是两个可并行开发流；先处理哪条须以用户当轮指示和实际环境为准。SEC-02 依赖服务端 Rust 守护进程，不能只给 Python 原服务加“超时”就宣布符合 Rust 约束。

**快速低风险闭环**：SEC-06（443 端口一致性）与 SEC-11（UTF-8 切片）适合小 PR，能快速建立清晰的红转绿测试，但它们不等于 P0 完成。

**原则**：优先封堵能造成越权/重新入网的缺陷；不要用大量 UI 改动遮盖安全问题。

## 6. 可直接复制到新对话的任务指令

> 我们继续开发 GitHub 仓库 `weixiaochuchen618-debug/spidervpn`。请先通过 GitHub 读取文档分支 `docs/security-remediation-handoff-20261117` 中的 `docs/security/AGENT_HANDOFF.md`、`REMEDIATION_BACKLOG.md`、`SECURITY_REMEDIATION_PLAN.md`，并核对仓库最新 main、PR #3 和 CI。按唯一任务清单选择下一个未完成的高优先级修复；新增产品安全/功能逻辑只能用 Rust 编译。必须保留现有交互和 WFP 持久 BLOCK，不要过度设计、不要跳过失败测试、不允许未验收就合并 main。执行前说明本轮处理的任务编号；完成后推送代码，提供准确 commit/CI/风险/下一步，并更新任务账本。此前 SEC-01～SEC-09 尚未完整解决、SEC-04 只是部分修复；WFP P0 的 Draft PR #3 与这 9 项分别管理。请直接按文档开展，无需让我重复解释。

## 7. 记录本轮恢复点

- 审查参考基准：另一 Agent 旧 main `077b760` 的 9 项报告（非最新）；本次已对照 PR #3 HEAD `2045acd4`，发现 **8 项未修复、1 项部分修复**。
- 新审查进一步标记 SEC-10 一次性提权 IPC 与 SEC-11 UTF-8 索引。
- 文档交付：三份持久 GitHub 文档；**尚未写入任何修复源码、尚未完成这些项目的新动态利用测试**。
- 每次对话结束前应更新本节的“当前 SHA、已做、未做、下一动作”；禁止让用户在另一个对话里重新复述项目背景。



## 8. 最新续接补充（2026-11-17，SEC-03/SEC-10）

- **以 [Backlog D.2](./REMEDIATION_BACKLOG.md) 为准**：PR #6 开发头已推进到 `c72ea692`（实时请核对完整 SHA），仍 Draft。新增 Rust 特权 IPC 对象 DACL 现场读回，在目录、请求、回复任一 DACL 被放宽时执行 WFP 前拒绝。新 Windows 负对照需要确认在不同 CI ABI 下真的通过。
- 历史红例不是被跳过：原 MSVC [44010494382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010494382) 的 `mode-e2e` 被管理员严格引擎校验拦住；旧 [44011375375](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44011375375) 又定位 `runtime-engine-e2e` 两个相同夹具问题；已改用隔离 bin 中的实际客户端和拷贝为 `sing-box.exe` 的系统 ping 假引擎，另同步处理 `transport-e2e`。不取消任何连接行为断言。
- 本轮代码提交顺序：`8262db63`（mode 测试）、`253392e8`（SEC-10 DACL 读回）、`a5eebd39`（提权端校验与宽 ACL 负对照）、`31d9e55c`（MSVC 前置专项）、`87a7cd34`（runtime 测试）、`c72ea692`（transport 测试）。
- **实际状态仍为 P0 候选，尚未安全验收**：下轮必须检查 PR #6 最新 SHA 的 MSVC 与 GNU workflow 运行及失败日志；缺少 Windows A/B/C 跨账户 UAC-01～12、可信安装根 `bin` 安全权限及真实攻击验证。原 main、WFP PR #3 的持久 BLOCK 不受影响，严禁未验收合并。


## 9. SEC-10 诊断修正后的可靠恢复点（2026-11-17）

- **继续工作必须先 fetch** [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6) 的 head：本次候选 `0690cba5774c715255fb7c4fe55c92a2728b30d5`。`main` 与 PR #3 没有被本次合并或变更，PR #6 仍 Draft。
- **事实与修复**：受保护 IPC 的正常 Windows SDDL 是 `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)`，原 API 附带三个末尾 UTF-16 NUL；新 Rust 解析器一度误拒绝正常请求。提交 `0690cba5` 只移除尾部 NUL，其他授权严格拒绝。必须保留正常成功路径 + AU 可写负路径两类测试。
- **CI 证据**：[Windows GNU 44012868496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868496) 与当前 HEAD 完全一致，最终 Success；[Windows MSVC 44012868490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868490) 已成功运行 build、SEC-10 提权专项、全部 `tests/*.rs` 集成目标、各变更 Rust 模块回归；截至交接时最后的便携单元 suite 仍显示 In Progress，不能写成整个 MSVC CI Success。原配置有 8 个环境依赖排除项，本轮没加 skip。
- **正式安全结论：未完成 / 不可合并**。缺少可信安装 `C:\SpiderVPN\bin` 安全 ACL / 标准用户可写路径拒绝、A/B/C 多账户真实 UAC-01～12、升级/卸载迁移、WFP 持久 BLOCK 实机验证。下轮续接按 [Backlog D.2-D.3](./REMEDIATION_BACKLOG.md) 和 [实机 UAC 验收表](./SEC10_WINDOWS_UAC_ACCEPTANCE.md) 做，不能用单机 CI 抹去 P0。


## 10. 最新续接：SEC-03 安装 DACL 与真实安全验收（2026-11-17）

- **选定任务 P0 SEC-03（SEC-10 同一权限边界依赖）**。本次活动 Rust PR 仍为 [Draft PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，从 main 857ea759 分出；提交候选截止 a14016cd4a921b2e8639de22ab9f70add9d62a17，实时 HEAD 须再次核对。PR #3 未合并，WFP 持久 BLOCK 与原 UI/连接路径未修改。
- **已落地候选**：src/install_trust.rs 的 Win32 SECURITY_ATTRIBUTES 原子目录创建、已有目录/EXE/DLL/启动脚本 DACL 收紧与现场读回、Owner Rights/Users RX，数据根独立 AU Modify，拒绝 reparse、路径跳转、未知 bin 文件、外部硬链接。package-files/install.ps1 只在复制前和复制后调用 Rust --install-seal，权限规则不得移回 PS；正式版只允许 C:\SpiderVPN，管理员权限安装是新的明确要求。
- **测试和 CI 现状**：tests/install-seal-e2e.rs + install_trust::tests::；MSVC/GNU 专项均已注册。旧 MSVC [44017844701](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44017844701) 有 2/4 正常路径 ACL 单测因 Windows D:PAI 标记被误拒，提交 c4b9618b 修正只接受 D:P / D:PAI 两种受保护控制标记（其余 ACE 逐字比对）；新增硬链接拒绝提交 d4bf342a；旧 data 升级时显式保护目录为 AU Modify 且保留内容提交 a14016cd。**这些提交之后的当前 SHA CI 仍需终态核对**：[MSVC 44018620435](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620435)、[GNU 44018620441](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620441)。不能引用旧 SHA 的成功或取消。
- **实机 DoD 缺失**：[SEC03_INSTALL_ACL_ACCEPTANCE.md](./SEC03_INSTALL_ACL_ACCEPTANCE.md) I01–I12，A 普通/B 独立管理员/C 第二普通用户的实际覆盖/改 ACL/UAC/升级/卸载与 WFP 持久阻断。完整 A/B/C 测试前 SEC-03 保持橙色“候选开发中”，SEC-10 也未完成。特别注意既有卸载脚本 SEC-09 与受保护 bin 新管理员权限要求的兼容，不能在 Guard 未核验解除时删除 EXE。安装包来源/签名、旧安装 TOCTOU、真实跨用户 ACL 尚未证明，绝不可合并 main。
- **唯一任务状态**：继续看 [REMEDIATION_BACKLOG.md §D.4-D.5](./REMEDIATION_BACKLOG.md)。新 Agent 若见 CI 红例必须读失败 job logs 修 Rust/测试（不删断言、不增 skip），红例修复后重新匹配最新 SHA 的 MSVC/GNU。后续优先收口 SEC-03 安装、卸载和 A/B/C 实机，再推进 SEC-01 Rust 服务安全。


## 11. 本轮最终 CI 结果 / 不可越过的安全门槛（2026-11-17）

- **最新活动 Rust PR #6 HEAD**：a14016cd4a921b2e8639de22ab9f70add9d62a17，依旧 Draft / Open / 未合并；正式 main 仍为 857ea7593941ce79f6507db5b1ced076c3a077ba，PR #3 WFP 亦仍 Draft / 未合并。
- **同一 HEAD 已有两套 CI 成功证据**：[MSVC 44018620435](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620435) Completed / Success（Build、SEC-03/SEC-10 专项、全部 Rust integration 目标、模块回归、便携单元 suite 各步骤均绿）；[GNU 44018620441](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620441) Completed / Success（GNU release 构建、环境覆盖隔离、安装 ACL / Guard / WFP 专项）。**MSVC 便携单元 suite 仍有原始 8 项环境依赖排除**，本轮未新增 skip。
- **代码和设计恢复点**：src/install_trust.rs Rust Win32 安装 ACL（含 D:PAI、硬链接、已有 data 独立 AU Modify）、tests/install-seal-e2e.rs，以及 package-files/install.ps1 的复制前后 Rust --install-seal 调用；本轮没有改变 UI、连接编排或持久 WFP BLOCK 代码。对旧数据仅改变根目录权限，不重写配置内容。
- **当前仍不通过实机安全 DoD**：缺少 Win11 A/B/C 不同账户的真实 UAC/修改和所有者验证 [SEC03 I01–I12](./SEC03_INSTALL_ACL_ACCEPTANCE.md)，安装包来源/签名、执行对象句柄绑定、既有安装文件竞争、真实升级卸载回滚，及 [SEC10 UAC-01～12](./SEC10_WINDOWS_UAC_ACCEPTANCE.md)。下一轮先做隔离 Windows VM 安全验收，再推进 SEC-09 卸载兼容及 SEC-01 Rust 服务器漏洞；**SEC-03 和 SEC-10 不能宣称完全修复，更不能合并 PR 到 main**。
- **任务清单唯一真相**：[REMEDIATION_BACKLOG.md D.4–D.6](./REMEDIATION_BACKLOG.md)。旧 SHA 54f09333 MSVC 红例 D:PAI 的根因和修复必须保留，不能抹除失败记录。


## 12. 新增 SEC-09 Rust 安全卸载候选与当前恢复点（2026-11-17）

- **本轮任务**：SEC-09（P1，但 Guard exit3 误删有高影响），依赖 SEC-03 受保护安装 root/bin。活动分支 fix/sec10-guard-elevation-identity-p0-20261117 / [Draft PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，最终候选最新提交 15079f9184de6bffa8beb66546cc3996c528c6c9。main 不变、PR #3 不合并，SEC-03/SEC-10 P0 实机未验收。
- **修复内容**：src/uninstall_safety.rs 新增 Rust --uninstall-preflight 和 --uninstall-owns-shortcut（管理员身份、运行二进制与固定根一致、拒绝 reparse，先验证 proxy-journal 已清除）。没有 config.json 时也必须通过 WFP backend 原生 remove/回读确认 provider/sublayer 都不存在；读写 HKLM Removed 标记与废弃 Evidence，任何失败保留 exe。显式 --keep-guard 不改变原 WFP BLOCK，但 journal 未还原不允许卸载。Rust 精确匹配安装器生成的 .cmd 内容，代替 PS 的 Contains(TargetDir)；PowerShell 仅调用 Rust 并清理固定清单，补删 sing-box.exe、LICENSE，目录中未知文件不会递归删。
- **测试设计**：src/uninstall_safety.rs 测试没有 config.json/失败不删/保护残留/keep guard/journal/路径误匹配/manifest；tests/uninstall-preflight-e2e.rs 真 CLI 不可信安装根和缺参拒绝、对包内 PS 的 Rust 安全闸门静态契约。MSVC/GNU workflow 直接跑 Rust uninstall_safety::tests，MSVC 另用 pwsh 语法解析器检查脚本但绝不执行真实卸载。MSVC workflow 新增与 GNU 一致的“只取消旧 SHA PR 运行”，最新 SHA 不增删任何既有测试。
- **CI 仍待终态**：本轮最新 SHA 15079f91 的 [MSVC 44025960134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44025960134) / [GNU 44025961008](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44025961008)，必须查看最终 workflow conclusion，若失败读 job logs 修复，保留测试断言，绝不以旧 SHA 成功冒充。前一基线 a14016cd 的双 CI 成功仅可证明 SEC-03 候选。
- **真实安全验收**：新增 [SEC09_UNINSTALL_ACCEPTANCE.md](./SEC09_UNINSTALL_ACCEPTANCE.md) U01–U14，需要隔离 Windows 11 A 普通/B 独立管理员/C 第二普通用户；WFP 持久 BLOCK readback、UAC、旧数据恢复、完整卸载残留和回滚均未验证。默认拒绝带未还原 journal 的强制卸载是有意安全收紧；普通用户双击“卸载”入口在受保护安装后需要管理员权限，必须实机验证兼容，不得称完全无变化。
- **精确恢复顺序**：先读 [REMEDIATION_BACKLOG D.7](./REMEDIATION_BACKLOG.md) → 核对 PR6 HEAD/MSVC/GNU 终态 → 如果 CI 失败修 Rust → 对照新 U01–U14 复审未测项目。SEC-09 暂标橙色“部分候选”，PR #6 继续 Draft、不能合并 main。


## 13. SEC-09 最新代码/CI 恢复锚点（2026-11-17）

- **最新代码 HEAD**：4a063de4fbb49debd7c8f04d6072ba99be3c9326，仍是 Draft PR #6 未合并；请根据 GitHub 实时 HEAD 核对。main 857ea759、PR #3 Draft 不变。
- **本轮最后两个对抗修正**：78a25ac0 防止 proxy-journal.json 的 PermissionDenied/元数据读取错误被 Path::exists() 错当不存在，符号链接/硬链接记录不得通过；4a063de4 用隔离假 backend 验证 WFP 删除虽成功但 Removed 标记不能写时，程序文件仍必须保留，不得误报卸载成功。没有更改原持久 BLOCK 的 WFP 代码。
- **最新测试**：[MSVC 44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209) / [GNU 44026418218](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418218)；写入时尚无最终绿/红结论，先读失败 Job logs，禁止删安全断言、增加 skip、把旧 SHA 当最新验收。安全脚本仅作为 Rust --uninstall-preflight / --uninstall-owns-shortcut 的薄入口。
- **状态约束**：SEC-09 是部分候选，不能宣称实机安全卸载已通过。U01–U14、SEC-03 I01–I12、SEC-10 UAC-01～12 和 WFP 真实断线检查缺失；仍不合并 main、PR #6/#3 持续 Draft。任务账本 D.7–D.8 为主。

## 14. SEC-11 UTF-8 及 SEC-09 安装/卸载清单一致性（2026-11-17）

- 活动 Rust 开发分支 fix/sec10-guard-elevation-identity-p0-20261117 / Draft PR #6；**最新候选代码 SHA d4f7feb8b5aed21759704b318121e2bfd8972934**。main 857ea759、PR #3 Draft 未更改。新旧任务继承 docs/security/REMEDIATION_BACKLOG.md D.4–D.10，绝不能将旧版双 CI 绿冒充最新候选通过。
- 先复核上轮 Rust SEC-09 SHA 4a063de4 的 CI：[MSVC 44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209)、[GNU 44026418218](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418218) 均最终 Completed/Success。MSVC 沿用原 8 项环境依赖测试排除，本次未新增 skip。SEC-09 依旧未完成 Windows A/B/C 安全验收。
- SEC-11 已复现的真正崩溃点：src/uiweb_form.rs::short_time 原先 len≥16 且 byte[10]==T 即切片 [5..10]，攻击者构造 aaaa你bbbT... 时 byte5 在汉字内部而 byte10 为 T，导致 panic；提交 d90df394 使用 str::get(..16) 并严格验证 ASCII 日期时间格式，非标准值原样显示，新增确定性单测。
- SEC-11 WireGuard shape 加固提交 ac282e43：src/pairing.rs::tunnel::wireguard_key 改为纯字节、严格 ASCII/44 字节/末尾 = 验证，新增 emoji/中文/错误填充测试。**旧代码的第43字节切片在 len=44 且 ends_with('=') 条件下事实上始终落在字符边界，不应将其伪称已复现 panic**。
- SEC-09 清单一致性候选：Rust src/install_trust.rs::BIN_FILES 为唯一代码目录允许清单，src/uninstall_safety.rs::code_file_manifest 复用它。测试用 include_str 解析 package-files/uninstall.ps1 的清理列表，确保不缺、不重复和主 exe 最后删除；包装器则先删引擎/DLL/许可证，最后删 exe 及 uninstall.ps1，失败时尽可能保留重新卸载的能力。提交 b839dace、0d3bbc69、f9d7dbbc。
- 两个 Rust CI 已加 SEC-11 独立过滤，最新 SHA d4f7feb8 对应 [MSVC 44030514834](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514834) / [GNU 44030514840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514840)，本条写入时正在运行。后续先查终态及失败 job logs，不删测试、不加 skip；CI 即便全绿也不能关闭 SEC-11 的其他生产 panic/unwrap 审查，也不能视作 SEC-03/09/10 真实 Windows/WFP 安全验收。
- 继续任务优先级：完成最新 SHA 自动化回归后，SEC-11 生产 unwrap/expect 与其它 UTF-8 截断点、SEC-01/02 Linux Rust 服务端核心漏洞；实机 A/B/C 与 WFP 仍是明确人工验收阻塞。PR #6 与 PR #3 保持 Draft，不合并 main。

## 15. SEC-11 测试编译红例与最新重跑（2026-11-17）

- **本轮真实失败**：候选 Rust SHA d4f7feb8 的 [MSVC 44030514834](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514834) 与 [GNU 44030514840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514840) 均 Failure；原因是我将 SEC-11 WireGuard key 单元测试误放在 pairing::line::tests 内，它无法调用 pairing::tunnel::wireguard_key，rustc E0425。Rust 生产 Build 已通过但 test-bin 未编译。此错误是新增测试作用域问题，不是旧版 WireGuard 逻辑引发的新漏洞。
- **修正**：ce3c00fe 将同样的 7 条测试断言整体移到 pairing::tunnel::sec11_key_tests；e32c7567/c658c122 改正 MSVC/GNU 显式 test filter，**不跳过失败、不删除断言**。上次 SEC-09 SHA 4a063de4 双 CI Success 仍有效，但不能用于证明新代码。
- **最新恢复点**：活动 Draft PR #6 源码 HEAD c658c12249568ccbfe02c13a436cdaa27ffe5776；对应 [MSVC 44031103332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103332) / [GNU 44031103722](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103722) 当前尚无完整结论。先检查双方 workflow 状态和失败日志再做下一次写码，只有 head_sha 一致且 Completed/Success 才更新验收。
- **仍须保留**：SEC-11 short_time 确实能因为 UTF-8 非边界 panic、wireguard_key 旧版在 44 字节与结尾 ASCII 等号约束下不一定能 panic；错误性质应分开。实机 SEC-03/09/10、真实 WFP 阻断、SEC-11 剩余生产 unwrap/expect 与服务器 P0 SEC-01/02 全部未验收。维持 PR #6/#3 Draft，main 857ea759 不动。
- 任务账本详细证据见 REMEDIATION_BACKLOG.md D.10–D.11。

## 16. SEC-01/SEC-08 Linux Rust 策略核心与下一步 Rust daemon 迁移（2026-11-17）

- **先核实上轮**：SEC-09/11 Windows 源码 SHA c658c12249568ccbfe02c13a436cdaa27ffe5776 的 [MSVC 44031103332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103332) 与 [GNU 44031103722](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103722) 现均是 Completed/Success；MSVC 原有 8 项环境依赖排除未变。此证据不能冒充 Windows A/B/C WFP 真实安全验收。
- **新 SRC 开发分支**仍为 fix/sec10-guard-elevation-identity-p0-20261117 / Draft PR #6，2026-11-17 新增 Rust files server-rs/src/lib.rs（无依赖、纯内存授权/撤销状态机）与 server-rs/src/lock.rs（Linux x86_64 owner-only flock 互斥）。本阶段代码 HEAD **8e4a2356f93dd456158e30881ab114c96699e238**，接手先核对 GitHub 实时 HEAD。main 857ea759 / PR #3 Draft 未改。
- **漏洞核实**：Python assets/tc-pair.py:1230–1246 在 Consumed 重试时核对 RequestId/JwkDigest，却仍用当前新 public_key 为旧 IP 调 attach_client；Rust Windows 管理端 src/deploy.rs::revoke_script 只删除 WG 公钥，不写 invites.json Revoked。已撤销 peer 因旧邀请重放可能复活。Python CONSUME_LOCK 只线程内，不保护跨进程 HTTP/SSH。
- **Rust 迁移核心**：状态 Open→Pending（先持久预留）→Consumed（真实 WG 身份/IP readback）→Revoking（先持久拒绝重放）→Revoked（确认 WG 旧 key/IP 消失）。对旧 Consumed 的任何重试，仅当请求六字段完全一致，且全量 WG live peer 恰好匹配才只读返回原授权，不允许再次 attach_client。被撤销 DeviceId/公钥跨新邀请也拒绝；地址分配考虑 Pending/Consumed/Revoking 与 live peers。未知 live WG 一律失败。外层 Linux flock 必须跨整个 ledger+wg transaction；锁目录与文件 owner-only、拒绝 hardlink/symlink；独立子进程单测覆盖。
- **新独立 Linux 工作流** .github/workflows/security-pairing-rust-linux.yml 用 rustc --crate-type lib 与 rustc --test 编译，不改变 Windows 客户端依赖；[Linux CI 44033771424](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771424) 已证实 **Completed/Success：13/13 tests passed，0 ignored**。同时 SHA 的 [MSVC 44033771576](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771576) / [GNU 44033771443](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771443) 写本节时未终态，应随后核查，失败读取日志。
- **最关键的边界**：此 Rust core 未被运行时调用，Python `src/pairhost.rs::UNIT` 仍启动 `tc-pair.py serve` 且默认 root；未完成 Rust 加密验签/JWE、JSON schema 及原子持久迁移、WG 实际 sync/readback、TLS 非 root 资源限流、管理端 revoke 接线/隔离 Linux 端到端。**SEC-01/02 P0 仍未修复生产，SEC-08 P1 也仅候选**。不能因为 Linux CI 绿标 completed。
- **后续六阶段完整规格**：[SEC01_LINUX_RUST_MIGRATION.md](./SEC01_LINUX_RUST_MIGRATION.md) S01–S06。优先从旧 invites.json 持久迁移和跨进程 Rust 事务完整接线开始，后续服务端 TLS 并发/超时管理为 SEC-02 独立 P0。不要直接把 Python 换成 Rust 而丢掉当前客户端的 RSA-3072、RS256、RSA-OAEP-256/A256CBC-HS512 字节兼容性。
- **保留发布冻结**：SEC-03/09/10 Windows A/B/C UAC/WFP 实机与原持久 BLOCK 回归尚缺；WFP 实验 PR #3 默认关闭；PR #6 仍 Draft，main 不合并，Issue #5 open。

## 17. SEC-01 Rust Cargo 旧邀请审计与 19 项 Linux 绿（2026-11-17）

- **当前最新 Rust 源码 SHA**：3d01dda610d33f38cb5f7aa7e95479ecf97b9ac4，活动分支 fix/sec10-guard-elevation-identity-p0-20261117，Draft PR #6；main 仍 857ea7593941ce79f6507db5b1ced076c3a077ba，PR #3 仍未合并。
- **上一阶段**：server-rs/src/lib.rs 是 SEC-01 无副作用授权状态机，server-rs/src/lock.rs 是 SEC-08 Linux x86_64 跨进程 lock。最新独立 Cargo 包 server-rs/Cargo.toml/Cargo.lock 锁定 serde 1.0.229、serde_json 1.0.154。代码的主 Windows Cargo.toml 不变，服务端依赖独立。
- **新增只读审计**：server-rs/src/legacy.rs::audit_legacy_json（4MiB / 4096 邀请上限，schema 校验，未知 state fail closed，无 Token 或签名正文泄露）。旧 Python Consumed 记录没有 RequestDigest，因此 Rust 必须真实验证原授权 JWS 才能回填；未知与缺字段不允许自动迁移，不能伪造已授权身份。Cancelled/Expired 永不被视作 Open。
- **最新 Linux 构建/测试证据**：[Linux Cargo #44034700193](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700193)，head_sha=3d01dda6，Completed/Success；19 tests passed、0 failed、0 ignored，含原 13 条重放/锁测试与新增 6 条旧 JSON audit，`cargo --locked` 和 `RUSTFLAGS=-D warnings`。此前单独 rustc 无法链接 serde_json 的过渡红例现已修正，不得删除/跳过测试。
- **最新 Windows 客户端回归**：[MSVC 44034700266](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700266)、[GNU 44034700188](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700188) 同源码 SHA，写入时未拿到终态；先检查 GitHub Actions 实际结果。Windows 即使全绿也不能证明 Linux 接收服务安全。
- **要谨记的 P0 停止线**：当前服务端仍通过 `src/pairhost.rs` 的 systemd UNIT 使用 `/usr/bin/python3 -I .../tc-pair.py serve`，重放漏洞生产路径未替换；Rust 尚无正式 JSON 持久迁移、WG 真实增删与事务回滚、签名/JWE 密文互操作、TLS 限并发/超时、非 root 账户和客户端管理端撤销接线。这些缺失时 SEC-01/02/08 不能关；不得将 19 tests 当作零风险证明。
- **后续详细方案**：[SEC01_LINUX_RUST_MIGRATION.md](./SEC01_LINUX_RUST_MIGRATION.md) S01–S06，结合 [REMEDIATION_BACKLOG D.13–D.14](./REMEDIATION_BACKLOG.md)。优先补专用 Rust disk ledger 的原子/fsync 落盘与老 JSON 格式可信重验，然后 Linux WG 真实事务、TLS 的 Rust 认证握手。对恶意重新发放全新 InviteId+DeviceId+Key 的攻击者无法凭旧墓碑识别真人，需严格审批控制，不要宣称百分百阻断。
- 另有 SEC-03/09/10 Windows A/B/C UAC/WFP 现场验收未完成；WFP PR #3 实验默认关闭。Issue #5 不关，PR #3/#6 继续 Draft、main 不合并。

## 18. SEC-01 Linux Rust 持久化账本 + 故障注入事务（2026-11-17）

- **活动 HEAD** `07dc06f83d3f14361f822f4a519203eddc96c987`；活动分支 `fix/sec10-guard-elevation-identity-p0-20261117` / Draft PR #6。主分支 main=857ea7593941ce79f6507db5b1ced076c3a077ba 未变；切勿合并。
- **最新代码** `server-rs/src/ledger_disk.rs` 是 Linux Rust owner-only 文件系统持久账本（schema/generation/严格 serde/invariant/信任存储路径，临时文件 0600 单硬链接+O_NOFOLLOW+sync_all+rename+parent fsync）。仅已有完整经过验证的账本可 open_existing，缺文件 fail closed；初始化仅 cfg(test)，防止真实服务无旧状态时自动重置为空。
- **安全关键故障**：目录 fsync 在原子 rename 后失败，磁盘可能已替换 Pending，但内存仍是 Open。最新 LedgerStore 有 `Poisoned`：在提交 I/O 不确定后禁止 view/generation/update，要求关闭重开、重验磁盘和可信 live WG；cfg(test) 注入 rename 后失败并验证旧 Open 不能写回。不能把 disk sync 失败当成可以继续操作。
- **WG 事务编排测试** `server-rs/src/transaction.rs` 通过 Rust trait PeerControl 注入假的 WG：先持久化 Pending/Revoking、再 add/remove、再 fresh snapshot 和 commit Consumed/Revoked；失败仍保留 Pending/Revoking，带旧令牌 retry_read_only 不能再次调用 add。它**并没有真实 wg/ssh TLS 适配器**，不能冒充 SEC-01 生产代码已替换。
- **编译与测试** 最新 [Linux Rust #44036991021](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991021) 是同 SHA Completed/Success，**32 tests passed / 0 failed / 0 ignored**（在前 19 基础上新增 7 条 ledger + 5 条 fake WG + 1 条 post-rename 硬故障测试）。`--locked`、`-D warnings` 均通过；独立 Cargo 包与 Windows 桌面主依赖隔离。最新同 SHA [MSVC #44036991126](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991126)、[GNU #44036991031](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991031) 写入时未终态，接手先查两项真实状态。
- **外部进度同步** 详见 [SEC01_LINUX_RUST_MIGRATION.md](./SEC01_LINUX_RUST_MIGRATION.md) 第三阶段、[REMEDIATION_BACKLOG.md D.16](./REMEDIATION_BACKLOG.md)，以及 Issue #5。本轮无任何 Python 生产行为改动。
- **不能关闭的项目**：SEC-01 P0 真实设备撤销重放线上路径仍是 Python `tc-pair.py`，Windows `deploy.rs::revoke_script` 未接 Rust Ledger，真实 WG/Linux TLS 权限控制/签名/JWE/旧数据可信迁移/反回滚未做。SEC-02 P0 亦未修；Windows SEC-03/09/10 A/B/C UAC/WFP 实机未验收，PR #3/#6 Draft、main 未合并。下一次继续优先做真实可信 WG 只读快照协议与 shell 注入安全的 Linux Rust adapter、签名互操作，禁止直接运行在用户生产机。

## 19. SEC-01 Rust WireGuard 只读现场读取（2026-11-17）

- 活动代码分支 `fix/sec10-guard-elevation-identity-p0-20261117` / Draft PR #6，本轮最新 HEAD `e4ec09e46631139d0900a9c4872770f92958b175`。此前 Rust 账本 SHA 07dc06f8 的 MSVC/GNU/Linux 三套 CI 均最终 Success（Linux 32/32）；不能替代当前 SHA。
- `server-rs/src/wg_readonly.rs` 是独立 Linux Rust **只读** live peer 查询：固定 root-owned、不可组写和不可 symlink 的 `/usr/bin/wg`，执行 `show <iface> allowed-ips`，不用 shell/动态 PATH，不触碰 `wg show dump`（避免接口私钥进入程序输出）。接口名严格 1–15 ASCII 白名单、排除 `all/interfaces`。命令自带有限输出 512KiB、3 秒限时、非零退出/截断/异常都拒绝；空表只允许命令成功且 stdout 真空。
- 全量 peer 解析要求每行唯一合法公钥 + 单个 RFC1918 IPv4 /32；多网段、IPv6、(none)、重复公钥/IP、坏 UTF-8、附加字段、无尾行 LF、>4096 peers 均失败关闭。目的在于防止错误遗漏 peer 后认为旧已撤销。调用者不得把 `Err` 强转 `Vec::new()`。
- 最新 [Linux Cargo CI #44038827553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827553) 已核对 head_sha 相同，Completed/Success，**39 tests passed, 0 failed, 0 ignored**。安全回归包含 7 条新 WG 输入/命令时间与退出码约束，CI 仅运行 /bin/sleep、/usr/bin/false 等本地测试工具，**无真实 WG/network 副作用**。对应 Windows [MSVC #44038827565](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827565) 和 [GNU #44038827585](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827585) 记录时仍需查结果。
- **绝不能说 SEC-01 线上已修复**：此读取器**没有实现** transaction::PeerControl（它要求 add/remove），仅提供 snapshot；未核对 `/etc/wireguard/<iface>.conf` 磁盘配置、真实 WG 原子更新和恢复、旧 JSON/JWS 签名与 JWE 互操作、非 root Rust TLS、Windows 管理端 revoke 切换。线上 systemd `ExecStart` 仍是 Python 旧接收器，SEC-01/02 P0 及 SEC-08 P1 均开放。
- **后续恢复顺序**：核对当前 PR6 HEAD 与 MSVC/GNU 最新工作流 → 按 [SEC01_LINUX_RUST_MIGRATION.md 第四阶段](./SEC01_LINUX_RUST_MIGRATION.md) 增加 wg.conf 安全只读检查和 mock 对齐 → 隔离 Linux WG namespace 下实现 Rust wg.conf/peer add/remove/回读，再推进 RSA/JWE+TLS 接线。始终不碰用户真机、不合并 main、PR #6/#3 Draft。

## 20. SEC-01 Rust Live/Config 双核对及并发三重只读验证（2026-11-17）

- 活动代码分支 `fix/sec10-guard-elevation-identity-p0-20261117` / [Draft PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，**当前 HEAD `714674bf827d84c62e24bcbd627ad980e90ead67`**。main 857ea759 / PR #3 Draft 未改。
- 上轮 `wg_readonly.rs` 仅验证 `/usr/bin/wg show IFACE allowed-ips` 的 live peer，不能断言磁盘 wg.conf 一致。现新增 `server-rs/src/wg_conf_audit.rs`，通过固定 `/etc/wireguard/<interface>.conf` 只读解析受保护 root-owned 配置，要求 0700/0600、single-link、O_NOFOLLOW，限制大小、验证文件身份/修改时间前后一致；不打印 Interface PrivateKey/Peer PresharedKey、绝不执行 PostUp/PreUp。
- `parse_wg_quick_conf` 仅允许完整合法每 peer 一公钥+单一 RFC1918 IPv4/32；未知 section、损坏 UTF-8、重复公钥/IP、多 CIDR、IPv6、字段缺失直接拒绝。`require_exact_match` 对 live/config 公钥+IP+数量做逐一严格核对；即使 live 接口中已看不到某 peer，只要 wg.conf 还有它仍拒绝。`read_verified_snapshot` 先 live、再 config、再 live，三份有差异拒绝；尚不能提供对外部 root 不受锁约束修改的原子保证。
- 新增 `wg_conf_audit` 7 项配置/不一致回归及 2 项并发变化/超大 peer 输入拒绝测试。过渡 SHA 9f8266dc 在 Linux CI `-D warnings` 因 import/mut 冗余红，已经删除冗余代码，**没有加 allow、skip 或放宽断言**。最新 [Linux CI #44039882060](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882060) 同 HEAD **Completed/Success：48 tests passed、0 failed、0 ignored**；最新 [Windows MSVC #44039882064](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882064) 与 [GNU #44039881955](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039881955) 写入时未终态，先查运行结论。
- **闭环仍不成立**：新增代码全是 Linux Rust read-only 安全预接线，既无真实增删 WG、也没有在线 Python receiver 替换、JWS/JWE/旧邀请可信迁移、非 root TLS、Win revoke 管理端接线。SEC-01/02/08 生产风险仍存在，SEC-03/09/10 Windows 多账户实机仍未验收。**不能将 Rust 48 项测试说成真实生产安全已修复**。
- 下一 Agent 恢复顺序：对照 [REMEDIATION_BACKLOG D.18](./REMEDIATION_BACKLOG.md) → 核对 PR6 HEAD/MSVC/GNU 最终同 SHA CI → 在不碰用户真实机器的隔离环境构建 Rust WG 无 shell 事务 adapter，并引入真实 `wg.conf` 原子同步及 fake/namespace 故障注入 → Rust RS256/JWE 互操作 → TLS/管理端迁移，期间 main 不变、PR Draft。

## 21. SEC-01 Linux Rust 目标 peer 安全原子写入与故障事务闭环（2026-11-17）

- 活动代码分支 `fix/sec10-guard-elevation-identity-p0-20261117` / Draft [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，**HEAD `468af9e675bbf118464e1094306c6a055039324d`**。前一阶段只读模块 `wg_readonly`/`wg_conf_audit` 仍在；本阶段新增 Rust `server-rs/src/wg_peer_plan.rs`, `wg_atomic.rs`, `wg_live_set.rs`。没有更改 Python 线上接收器、Windows UI/交易网络、WFP、主分支 main。
- **配置计划**：`wg_peer_plan::plan_change` 从已通过解析的原始配置中只添加一段 peer 或移除完全匹配 PublicKey + IPv4/32 的段，保留非目标 peer 的内容（以及接口密钥、hooks 和注释），拒绝重复 key/IP、非法配置和非法 grant。可安全计划 NoOp 撤销，仅当 key/IP 都不存在。因为 Plan 包含服务器 PrivateKey，`Debug` 自定义脱敏，`config_bytes` 改为 pub(crate)，不可当日志输出。
- **文件原子写**：`wg_atomic::write_pinned_config` 现在只允许 crate 内的完整 Rust 事务调用，检查 `LedgerStore.view()` 中 Add 必须 Pending / Remove 必须 Revoking，且 grant 完全一致；固定 `/etc/wireguard` 的 root 私有目录与 0600 常规非链接 conf，保留其他内容，temp 同目录 0600 exclusive→sync_all→rename→父目录 sync_all，变化中有异常立即拒绝。后 rename fsync 故障测试证实，配置可能已变化但 Ledger 仍 Pending。不会隐式重置账本或自动补授权。
- **内核**：`wg_live_set::apply_and_confirm` 是当前 Rust 暴露的完整 peer 变更流程：先 verified live/config→持久 conf→通过严格 `Command` argv 定向 `wg set IFACE peer KEY allowed-ips IPv4/32` 或 `... remove`→双重 live/config 回读→比较目标及所有其他 peers→最终 `store.update(confirm_consumed/confirm_revocation)`。裸 `set_one_peer` 私有且无 shell，3 秒超时、返回无敏感日志。这一方案有意不用原整体 `wg syncconf` 以减少误伤别的设备。不可调用它传入未经 JWS 验签的 Claims。
- **最新 Linux CI**：[Linux #44042690148](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690148) 与 HEAD 相符，**Completed/Success：71 passed、0 failed、0 ignored**；包括纯配置增删、防覆盖、symlink/0600、持久 Ledger 阶段保护、假内核操作失败、读取失败、撤销失败后继续拒绝、部分提交崩溃、后 rename fsync 模糊结果、Revoking 状态下目标已双端移除避免重复 WG set。曾因 Plan.bytes dead_code/Read::by_ref E0034 在过渡 SHA 出现 Linux CI 红，后更改实际代码恢复，不降低 -D warnings 或删除单测。
- **Windows 同 SHA**：[MSVC #44042690238](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690238)、[GNU #44042690146](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690146) 记录时未整体终态。后续先核对 HEAD/SHA/run 结论；MSVC 自带 8 项原有环境依赖排除未增加 skip。Linux 完整 71 项通过不代表 Windows 或真实服务全绿。
- **重要 P0 闸门**：当前 systemd 仍调用 Python `tc-pair.py serve`，原 `deploy.rs::revoke_script` 仍只操作 WG peer 而不写 Rust tombstone；任何入网请求的 RS256/JWE 实际可信验证、旧邀请签名/RequestDigest/Revoked 安全迁移、SEC-02 Linux Rust TLS + 账号权限、真实 WireGuard namespace/断电/并发测试，全部未完成。配置先落盘但内核更改失败时会使 conf/live 暂时不一致并保持 Pending/Revoking，**不能自动盲目 retry**；须实现由可信 Ledger+现场快照约束的显式 reconciliation 才能恢复。**SEC-01/02/08 生产仍 Open**，PR #3/#6 Draft、main 不合并、Issue #5 Open。
- 后续方案见 [SEC01_LINUX_RUST_MIGRATION 第六阶段](./SEC01_LINUX_RUST_MIGRATION.md)、[REMEDIATION_BACKLOG D.19](./REMEDIATION_BACKLOG.md)。可在 GitHub Linux CI 中继续测试 fake WG 与 Linux 临时目录；真实内核必须先用隔离 VM/namespace、受控 root 与可回滚镜像，不操作用户真服务器。

## 22. 本轮最新 CI 终态交接（2026-11-17）

- Rust 源码最新 HEAD `468af9e675bbf118464e1094306c6a055039324d` / Draft PR #6。Linux [#44042690148](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690148)：Completed/Success、**71 passed / 0 failed / 0 ignored**；Windows GNU [#44042690146](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690146)：同 SHA **Completed/Success**。
- Windows MSVC [#44042690238](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690238)：同 SHA 的 Rust build、SEC-09/10/11 专项、集成和变更模块测试已经成功，**最后 Portable Rust unit suite（原 8 项环境依赖排除）仍在执行**。下一代理先核对终态，不得将 GNU/Linux 成功说成 MSVC 成功。
- 继续行动的 P0 优先级：SEC-01 部分成功/部分失败后的 **受信任显式 reconcile**（读 durable Pending/Revoking、固定 WG config+kernel 双快照、证明 expected grant、不在普通申请 retry 时悄悄重附 peer）；真实 WG Linux namespace 适配测试；RS256/JWE、旧 Consumed 遗留 RequestDigest 信任迁移；后续 SEC-02 非特权 Rust TLS HTTP 与 Windows 管理端 revoke 联动。当前 Python systemd 不可虚报迁移，SEC-01/02/08 仍 Open。main 未动，PR #3/#6 Draft，Issue #5 Open。

## 23. SEC-01 WG 中断状态只读恢复与终态核验（2026-11-17）

- **最新开发 HEAD** `0f4f87b92372561475afa790e3c27ba68d89823c`，活动分支 `fix/sec10-guard-elevation-identity-p0-20261117`、Draft PR #6。前一个 `468af9e6` 的 Linux 71/71、Windows MSVC 和 GNU workflow 已经全部 Completed/Success。main 857ea759 不动，PR #3 独立 WFP 实验仍 Draft。
- **本轮新增** `server-rs/src/recovery_inspect.rs`：只根据已有 Rust `LedgerStore` 的 `Pending/Revoking` 状态及当前安全 live/config 全量快照，做四态组合分析。凡 Open、Consumed、Revoked、未知邀请/损坏/不符 grant、目标 key/IP 被其他 peer 占用、无关 peer 漂移、输入超限/异常，都不能自动恢复。过期 Pending 一侧不完整时不允许再次创建旧 peer；不使用任意用户传来的请求 JSON 宣称身份。
- **安全读取** `inspect_pinned_recovery`：在 caller 持有 Rust authority cross-process flock 的整个生命周期里，LiveWgReader 先读 live，再 `read_pinned_conf` 读 owner-only `/etc/wireguard/<iface>.conf`，再读 live，两份 live 必须匹配；在仅目标 peer 发生内核与磁盘差异时报告应该修复哪一侧，不修改文件、接口或路由。这里不能保证抵御不合作外部 root。
- **仅终态补写** `finalize_stable_prepared`：只调用此前已通过测试的 `read_verified_snapshot`（live/config/live 全部一致），并用 `LedgerStore.update` fsync 最终 Pending→Consumed 或 Revoking→Revoked 与墓碑；只在双方已达到目标一致终态才可调用，不会调用 `wg set`，缺失任何目标/过期不完整/错误状态都会拒绝。**尚无经过批准的部分状态写操作**，不可将四态分析报告当作 HTTP 自动动作。下一步如增加本地 CLI，必须明确定义管理员身份、双确认、快照重读和不可自动 reattach 规则。
- **最新同 SHA CI**：[Linux #44045613147](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613147) HEAD `0f4f87b9` **Completed/Success：85/85 tests、0 failed、0 ignored**；[Windows GNU #44045613264](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613264) **Completed/Success**；[Windows MSVC #44045613185](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613185) Rust 编译、安全专项、集成测试已通过，最后查询时回归仍运行，未获得整个 workflow 终态。严格 `cargo --locked` / `RUSTFLAGS=-D warnings`，无新增 skip。
- **阻塞与路线**：真实 Linux network namespace WG 读写/断线恢复、具有管理员审批能力的显式部分修复入口、old Python `tc-pair.py` 到 Rust TLS/身份/RS256-JWE 的可信迁移以及 Windows revoke 管理端联动均未完成。SEC-01/02 P0、SEC-08 P1 **生产仍未修复**。PR #3/#6 Draft、Issue #5 Open，不合并 main。完整说明见 [迁移方案第七阶段](./SEC01_LINUX_RUST_MIGRATION.md) 和 [Backlog D.21](./REMEDIATION_BACKLOG.md)。

## 24. SEC-01 Rust 审核绑定单次批准 + 恢复模拟执行（2026-11-17）

- **最新代码** `663cc4e6d01579f04cb70be721ca3c3a2e66720d`，活动 Draft PR #6，`fix/sec10-guard-elevation-identity-p0-20261117`。新增 `server-rs/src/recovery_apply.rs`。上一轮 `0f4f87b9` Linux 85/85、Windows GNU 成功；最新独立 Linux [#44048267737](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267737) 同 SHA **Completed/Success：91 passed / 0 failed / 0 ignored**，Cargo --locked/-D warnings。
- **安全设计**：`RecoveryReview` 固定 InviteId、Ledger generation、RecoveryInspection action、全部 live/durable peer 列表。`AdministratorApproval` 字段私有，没有生产 constructor、无法被普通 HTTP 配对调用；只有 Rust cfg(test) 提供 `approve_for_test`。`apply_approved` 通过按值转移一次性消耗批准，先核对批准与审查绑定的对象和最新 Ledger generation，再重新读取 live-before/config/live-after 与当初审查数据逐项比较。任何状态漂移或审批动作不符返回 StaleReview/WrongApproval，**不调用磁盘或内核修改**。
- **恢复执行模拟**：`RecoveryIo` trait 当前只存在 CI fake 适配，演练 Pending/Revoking 各四种磁盘/内核状态，分别只修实际缺失的一侧；磁盘变更后再次核对全部无关 peer 未动及目标达到预期，内核变更后同样重新读回，然后才允许 durable Ledger Consumed/Revoked。内核失败或 fsync 失败留 Pending/Revoking，不允许普通邀请自动重新附加；过期未完成 Pending 直接拒绝。审查函数可公开供未来本地 CLI 显示，但**不能据此称真实管理员审批/网络修改已完成**。
- **CI 过渡失败及修复**：`0301b343` Linux 因 `confirm_consumed -> Grant` 和 `confirm_revocation -> ()` 的 match 类型不一致 E0308 失败，修正为分别返回 unit；`64ab0a99` Linux 因批准按值消耗后，单元测试仍尝试旧 approval E0382 失败，已在测试再次显式签发模拟批准；不屏蔽 warning，不删除测试。最新同 SHA [Windows GNU #44048267756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267756) **Completed/Success**；[Windows MSVC #44048267726](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267726) 构建和安全专项已通过，记录时仍在集成/后续单元回归阶段，接手须查最终结论。
- **下一阶段**：实现正式 Linux root-only 本地审批 CLI 和不可重放 ticket（避免将签发入口暴露 HTTP）、在同一 trust boundary 中将 RecoveryIo 与已验证 `wg_atomic` / `wg_live_set` 真实执行器适配，并用 Linux 网络命名空间进行内核 `wg set` 负例与中断恢复测试。之后才是老 Python `tc-pair.py` 可信迁移 RS256/JWE/旧缺 RequestDigest 的 Consumed 和 Rust TLS SEC-02；Windows revoke_script 也需同一 Rust tombstone 联动。当前 main 未合并、PR #3/#6 Draft、Issue #5 Open，SEC-01/02/08 不关闭。
- 完整说明：[SEC01 Linux Rust Migration 第八阶段](./SEC01_LINUX_RUST_MIGRATION.md)、[Remediation Backlog D.22](./REMEDIATION_BACKLOG.md)。

## 25. Windows MSVC 固定测试端口 10013 故障及源码最小修复（2026-11-17）

- **最新候选源码 SHA** `e380e82056c6eecbf237f5661b50af52964c8b9d`。上次 `663cc4e6` Linux 91/91 + Windows GNU 通过，但 MSVC [#44048267726](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267726) **失败**，确切日志：`connect::tests::second_connect_is_idempotent_when_already_connected` 固定测试端口 `127.0.0.1:50018` 在 Windows Runner 被拒绝（`os error 10013`）。此前安全专项、Rust build 和 integration tests 均通过，故不能误归因到 Linux Rust 恢复模块，也不能把该 SHA 的 MSVC 称为绿色。
- `src/connect.rs` 的 `#[cfg(test)] next_test_port()` 从固定 PID 派生 50000+区间改为由 OS 原生 `TcpListener::bind("127.0.0.1:0")` 分配可绑定的 loopback 测试端口，再从 local_addr 获取。**只有测试辅助函数变更**；正式连接参数和默认端口、UI、WFP、权限模块未变。没有禁用任何断言、重试掩盖失败或跳过测试。
- 新 SHA 对应 Linux [#44049297016](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297016) **Completed/Success：91 tests**。同 SHA Windows MSVC [#44049296975](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049296975) 和 GNU [#44049297040](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297040) 记录时尚在执行；下一个 Agent 必须比对真实 head_sha 和最终 conclusion。详细见 [Backlog D.23](./REMEDIATION_BACKLOG.md)。
- 即使 MSVC 测试绿，SEC-01/02/08 生产仍未修复：Python 接收器未迁 Rust、RSA/JWE 可信迁移、root-only 管理批准和真实 WG adapter/namespace、TLS 非特权及 Win revoke tombstone 未完成。main 857ea759 仍不动，Issue #5 Open，PR #3/#6 Draft。


## 26. SEC-01 root-only Linux Rust 只读诊断入口（2026-11-17，最新恢复点）

- 本轮独立分支 `fix/sec01-root-only-audit-cli-20261117`，基于 PR #6 的 `e380e82056c6eecbf237f5661b50af52964c8b9d` 建立**叠加 Draft PR #7**；代码提交 `1224512392e95f0e17d70b9160817ba323a41207`，不碰正式 main、WFP PR #3、原有 Rust WFP 持久 BLOCK、UI 和 Windows 连接交互。
- 新增 Linux Rust `server-rs/src/bin/spidervpn-pair-audit.rs`，只支持 root 本地 `inspect`：读取已有保护账本及三份 live/config 快照，输出 Safe `stage/action/flags`；无 `approve`/恢复写入命令，不能代替旧 Python 接收器的安全迁移。现有 `AdministratorApproval` 仍无生产颁发入口，不能说已完成提权授权。
- **Linux 同 SHA 证据** [CI #44051677137](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677137) Completed/Success：91 库测试 + 5 二进制测试、0 failed/ignored；非 root 调用 Rust CLI 的拒绝 E2E 成功，严格 `--locked`/`-D warnings` 编译通过。Windows 同 SHA [MSVC #44051677144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677144) / [GNU #44051677093](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677093) 仍须查询最终运行结果。旧基线 `e380e820` 的 Linux/MSVC/GNU 三条 CI 均已核对 Completed/Success。
- **状态不得关闭**：本轮只有受限只读审查 CLI 候选。真实 root/Linux namespace/WireGuard、管理员审批与实际恢复、RS256/JWE 兼容可信迁移、生产 Python 替换、SEC-02 TLS 限流、Windows revoke tombstone 与 WFP/多账户真机验收均缺。SEC-01/02/08 继续 Open，Issue #5 Open，PR #7/#6/#3 Draft，main `857ea759` 不合并。详见 [Backlog D.24](./REMEDIATION_BACKLOG.md)。


## 27. SEC-01 真 Linux WireGuard netns 专项验收（2026-11-17）

- **恢复锚点**：Rust 修复分支 `fix/sec01-root-only-audit-cli-20261117` / [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7) HEAD `5a8eb6047c1f1e3074fe66a075e9d295c0054a32`（base 为 Draft PR #6 的 `e380e820...`）。文档为独立分支，main `857ea759` 不动、WFP PR #3 不动。
- 新增 `server-rs/tests/wg_namespace_e2e.rs` 与 Rust Cargo 测试 feature，GitHub Actions 增加独立临时 Ubuntu root Linux network namespace job，在真实 `wg set`/内核接口和 root 0600 wg.conf/账本下，检验只读 `spidervpn-pair-audit inspect` 对 Pending/Revoking/Consumed/Revoked 的处理、撤销后 replay 拒绝、报表不泄密、审查不改变实际 peer/账本。生产命令依然只有 inspect，并无修改 WG/HTTP/管理员批准入口。
- 当前 SHA [Linux #44062802733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802733) Completed/Success：库 91、CLI 5、真实 WG netns E2E 1 均 passed（0 failed/ignored），RUSTFLAGS=-D warnings，Cargo --locked。旧红 CI [#44062350952](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062350952) 为猜错 Cargo 测试 exe 路径；旧红 [#44062535111](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062535111) 为 E2E 夹具过期时间（真实 CLI 正确 fail-closed）。后续均只修正测试/CI 配置，没有删除、屏蔽任何保护断言。
- 同 SHA Windows [MSVC #44062802742](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802742) 与 [GNU #44062802774](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802774) 尚未获得最终终态；继续查。
- **下一步**：独立审核的 root-only 管理审批/不可重放 ticket、安全 WG 原生恢复执行适配与 Linux kill -9/power-loss 注入；随后旧 Python 服务 JWS/JWE/RequestDigest 可信迁移、SEC-02 Rust TLS 与 Windows revoke 连通；不能将 CI netns 验收等同于生产 VPS 迁移验收。SEC-01/02/08 Open，PR #3/#6/#7 Draft、Issue #5 Open、不合并 main。详见 [Backlog D.25](./REMEDIATION_BACKLOG.md)。


## 28. SEC-01 可选 Rust root TTY 终态确认（2026-11-17）

- 本次活动 **Draft PR #8**（[链接](https://github.com/weixiaochuchen618-debug/spidervpn/pull/8)）在 PR #7 的 `5a8eb604` 之上叠加；代码 HEAD `b8cac95971ca468948c401f4ebce2b961989f0c4`，新增 `linux-admin-finalize` 显式 opt-in 编译 feature，默认功能/CLI/UI/Windows WFP 不变。新 Rust `admin_terminal.rs` 只允许 root 在 /dev/tty 输入精确绑定 InviteId+Ledger generation+Pending/Revoking stage 的挑战（45秒超时），只对 live WG 与 `wg.conf` 已经**完全达到终态**的事务做二次读回、磁盘账本补写。部分状态不执行修复和重新加 peer。
- 新专项包括非 root/非 TTY、非终态、不同代数、快照漂移、非法输入、真实 Linux WG netns root PTY 模拟确认及重复使用拒绝；CI 保留早期 `-D warnings` 红例 [#44069828605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069828605)，`e2e86e00` 修正无用导入后的 [Linux #44069971535](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069971535) Success；最新 `b8cac959` 三 CI [Linux #44070249998](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249998) / [MSVC #44070249845](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249845) / [GNU #44070249876](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249876) 在写入时仍须查最终状态，不能借旧 SHA。
- **不可发布结论**：PTY 挑战不证明物理人在场；Linux root/磁盘持有者是安全边界。真实隔离 VPS / 管理员验收、复合状态下经批准 WG 修复和在线 Rust pairing 服务都缺；SEC-01 P0 保持 Open，PR 全部 Draft，main 不合并。持续记录见 [Backlog D.26](./REMEDIATION_BACKLOG.md)。


## 29. SEC-01 root-only TTY 最终 Linux CI 结果（2026-11-17）

- 当前活动 [Draft PR #8](https://github.com/weixiaochuchen618-debug/spidervpn/pull/8) HEAD `b8cac95971ca468948c401f4ebce2b961989f0c4`。同 SHA [Linux #44070249998](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249998) 两 job 均 Completed/Success：常规 91 library + 5 CLI；增加 feature `linux-admin-finalize` 下 `admin_terminal` 5 + CLI 5；真实隔离 Linux WG netns 根终端 PTY 的 Pending/Revoking 终态确认 1 passed、0 failed/ignored。此前旧 SHA 的 `-D warnings` 无用导入失败已代码修正，不曾 skip。
- Windows 当前 SHA [MSVC #44070249845](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249845)、[GNU #44070249876](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249876) 写入时尚未最终核对；不得宣称三绿。下一 Agent 先重新读取 PR #8 当前 HEAD 与三 workflow 的最终 conclusions。
- 安全分界仍为 root 权限 + 持有 SEC-08 flock + live/config/live 严格核验，TTY 只是显式确认，不是强认证或不可由 root 模拟的终端；默认功能没有 finalize。**未迁移生产 Python / 未完整用户实机安全验收，SEC-01 保持 Open，Issue #5 Open，PR #3/#6/#7/#8 均不合并**。详细归档 [Backlog D.27](./REMEDIATION_BACKLOG.md)。


## 30. SEC-01 旧 Consumed 授权离线 RS256 签名审计候选（2026-11-17）

- 活动 [Draft PR #9](https://github.com/weixiaochuchen618-debug/spidervpn/pull/9) stack base 为 PR #8；当前 Rust SHA `4ca1c308688af5e9ce3785dd0da3fcac711de4bf`。新增 Rust `server-rs/src/legacy_signed.rs`，纯离线验证旧 `tc-pair.py` 签发 `SignedAuthorization` RS256 JWS；信任锚须为另行认证的管理员 JWK/ServerBinding。没有更改 Python 正式接收器或任何 Windows UI/WFP。锁定 `ring 0.17.14` 与对应独立 server-rs Cargo.lock。返回的 `ProofReport` 绝不等同授权 Grant，不能写 ledger、挂 WG peer 或从本地不可信旧邀请记录回填缺失请求摘要。
- 跨实现测试独立 Python RS256 正向签名只用于 CI fixture（不上传私钥）、已有 .NET RS256 signed invite 互操作、错误签名/错误合法管理密钥/记录置换/foreign server/错误协议头等 negative cases。先 [Linux #44072177072](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072177072) 因 Rust E0502 测试借用错失败、再 [Linux #44072328377](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072328377) 因复制签名 payload 少 12 字符被真验签拒绝；两者仅修测试与夹具，没有取消 Rust `-D warnings` 或禁验签。 [Linux #44072627523](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072627523) 97 library + 5 CLI + 真 WG namespace 1 + root TTY feature 测试均完成成功。最终 `4ca1c308` 的 [Linux #44072823025](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823025)、[Windows MSVC #44072823427](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823427) / [GNU #44072823056](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823056) 须继续查完整结果。
- 下一段真正 P0 闭环是 **旧 PairRequest JWS/RecipientJwkDigest 可信迁移 + tombstone + Rust TLS HTTP 替代 Python**；仅旧 SignedAuthorization 有效不能判断设备尚未撤销。Issue #5 / SEC-01/02/08 仍 Open，PR #3/#6/#7/#8/#9 Draft，main `857ea759` 不动。详情 [Backlog D.28](./REMEDIATION_BACKLOG.md)。


## 31. SEC-01 原始签名 PairRequest 证据验证（2026-11-17）

- 本轮 [Draft PR #10](https://github.com/weixiaochuchen618-debug/spidervpn/pull/10) 基于 Draft #9 的 `4ca1c308` 新建，代码 HEAD `e4b8b62fbec4e30bfb10c15f107bb21e2fe1f55f`；新增 Rust `legacy_request_proof.rs` 与独立测试使用的 `legacy_request_proof.json`。真实 Windows UI、连接流程、WFP 常驻 BLOCK、旧 Python HTTP 不变，main `857ea759` 不动。
- Rust 离线双重证据验收：**管理端独立可信 JWK** 验 `SignedAuthorization` + **原设备 PairRequest JWS** 验签，同时检查真正**独立**的原设备 RSA JWK 摘要与旧 RecipientJwkDigest、原请求签名及管理授权签名的共同 ClientRequest SHA-256 七行摘要、RequestId/DeviceId/WG Key/InviteId/ServerBinding。注意客户端的自签请求不能自带唯一信任锚；`independently_pinned_recipient_digest` 必须从旧 JSON 之外经过独立认证的事实获得，缺了便拒绝。所有正向返回报告 **still blocks import**，绝不调 LedgerStore/WG。
- [Linux #44074337077](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337077) 当前 SHA 普通核心 job 已通过 102 lib + 5 CLI、5 独立新的双签名测试、5 原 root-only 终态测试；同 SHA 独立 real WG kernel/netns job 与 Windows MSVC [#44074337005](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337005) GNU [#44074337010](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337010) 写入时尚未取得最终结果。下个 Agent **先查最新 HEAD/CI 完整状态，失败不跳过**。
- 下一阶段**不是**基于本报告自动切换服务；必须获取独立历史 revoke/设备接收私钥所有权证据和真实不可重放迁移事务，替换旧 Python 权限写路径并做真实 VPS A/B/断电回滚。SEC-01/02/08、Issue #5 仍 Open，PR #3/#6/#7/#8/#9/#10 Draft；依据 [Backlog D.29](./REMEDIATION_BACKLOG.md) 续作。


## 32. PR #10 Linux 全工作流 Success，Windows 仍待最终结果（2026-11-17）

- 当前 Rust HEAD `e4b8b62fbec4e30bfb10c15f107bb21e2fe1f55f`。同 SHA [Linux #44074337077](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337077) 两 Job Completed/Success，102 Rust library + 5 CLI + 5 feature admin + 1 real kernel netns E2E 均通过，0 failed/ignored，严格 --locked/-D warnings。
- 同 SHA [MSVC #44074337005](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337005)、[GNU #44074337010](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337010) 还没完成，后续必须核查终态。没有改变 UI、连接流程、WFP Persistent BLOCK、Python 生产配对 receiver、main。
- **非常关键的不可发布点**：原 Python 持久旧记录并不等于独立可信的客户端密钥证明；即使有双签名的测试样本与成功审计，也不能将过往 Consumed 授权静默导入、补建 peer、恢复已撤销设备。无可信历史证据需拒绝/人工重新配对，SEC-01 P0 不得关闭。详见 [D.30](./REMEDIATION_BACKLOG.md)。


## 33. SEC-01 Python→Rust 服务退场只读预检候选（2026-11-17）

- 新的活动代码 [Draft PR #11](https://github.com/weixiaochuchen618-debug/spidervpn/pull/11)，base 为 PR #10 的 `fix/sec01-original-request-proof-20261117`，HEAD `cd3cd51f53ff1df55d67150d89d3601eb1cfcd47`。本轮精确定位到 `src/pairhost.rs` 安装的 `tc-pair.service` (Python root), 其旧写入口不服从 Rust SEC-08 flock。没有更改原生产服务或 UI/Guard/WFP。
- `legacy_cutover.rs` 新增 root-only 检查 + 单独 opt-in 的 `spidervpn-pair-cutover`，必须是持久 `/etc/systemd/system/tc-pair.service -> /dev/null`、mask/inactive/dead/zero PIDs+Job、`/proc` 中不见任何 tc-pair.py（不止 serve），两次重复读 mask/服务/进程，所有缺失或不可读 fail-closed。**通过也不是授权：不导入旧 Grant、不开放新监听、不操作 WG**，不能防止脚本以别名重启或不协作 root 写者。
- Linux [CI #44075947553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947553) 两 Job Completed/Success，同 SHA：109 library + 5 CLI，新增 7 preflight unit tests + 原 5 admin TTY tests + 1 real kernel WG netns test，0 failed/ignored，Cargo --locked/-D warnings。新 CLI 的真实非 root 拒绝 exit2 已执行。**真实 root 且无 mask 场景暂未在 CI E2E 验证**，不能推断系统级服务迁移成功。
- 同 SHA Windows [MSVC #44075947516](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947516)、[GNU #44075947502](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947502) 还需核对最终状态；不要把旧 SHA 绿色当最新绿。下一步继续设计**真正不可并行的 root/systemd 切换栅栏**、真实 Linux root 服务 stop/mask/reboot 验证和 trusted revoke/tombstone 迁移；没有这条完整链不许启用 Rust 消费接口。
- 此 PR 仅预集成，SEC-01/02/08 与 Issue #5 继续 Open，相关 #3/#6/#7/#8/#9/#10/#11 全部 Draft，正式 main `857ea759` 不合并。详情见 [Backlog D.31](./REMEDIATION_BACKLOG.md)。


## 34. SEC-01 旧服务端口监听否决新增 PR #12（2026-11-17）

- 续作 [Draft PR #12](https://github.com/weixiaochuchen618-debug/spidervpn/pull/12)（base #11），HEAD `16c4176ed302871e2cb41787954a0f667f90d202`。保留 PR #11 系统层 root mask/inactive/dead 和 `/proc/<pid>/cmdline` 双重只读预检，进一步通过旧 Python root-only `server.json` 中规范的真实 `Port` 与 `Endpoint` 映射，前后两次读取完整 `/proc/net/tcp`、`/proc/net/tcp6`，凡 LIVE LISTEN socket 命中端口（即便脚本已改名）就拒绝。任意文件、所有权、字节长度、格式或快照漂移也拒绝。
- `legacy_cutover.rs` 默认发版无此命令，opt-in `linux-cutover-preflight` 的报告依然不授予导入/新 HTTP 监听或 WireGuard 写操作；更不可信地推断旧 revoke 历史。新增实际 Linux `TcpListener` 动态端口内核观察 + 假 IPv4/IPv6 及坏记录和旧配置端口测试。Linux [#44077594144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077594144) 核心 Job 113 library + 5 CLI + 5 admin policy + 11 cutover policy success（0 failed/ignored，`--locked`/`-D warnings`）；该工作流 netns Job 以及 [MSVC #44077593890](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593890)、[GNU #44077593911](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593911) 仍需查最终结论。
- **下一优先项**：确立真正可审计的 root/systemd 切换栅栏，停止且防重启旧 Python 任何写入口，完成独立 revoke/tombstone 证据和旧账本转换逻辑的 fail-closed 设计；仅快照没有解决真实排他。当前 PR #12 不能合并 main 或关闭 SEC-01。主分支 main `857ea759`，Issue #5 OPEN，PR #3/#6/#7/#8/#9/#10/#11/#12 Draft。


## 35. PR #12 真实内核双路径 Linux CI 完成验收（2026-11-17）

- 当前 HEAD `16c4176ed302871e2cb41787954a0f667f90d202`，同 SHA [Linux #44077594144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077594144) 两 Job Completed/Success。113 Rust lib tests、5 CLI、5 root TTY admin、11 cutover tests，内含 **真实 Linux `TcpListener`/proc/net/tcp 内核 LISTEN 检查**；另独立 WG netns 1 passed/0 failed/0 ignored。没有任何 WFP/UI 修改或 Python 生产接入。
- 本轮 Windows [MSVC #44077593890](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593890) / [GNU #44077593911](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593911) 当时仍运行中，须用 exact SHA 查询终态。下一工作重点是 root 测试 VPS 的 systemd 真实 mask + 同时阻断**旧 Python HTTP 和 SSH CLI**两种写者、旧 systemd unit 文件恢复/回滚，不能将双次只读快照变成不可重放切换审批。
- 历史进度索引 [Backlog D.32-D.33](./REMEDIATION_BACKLOG.md)，Issue #5 Open，SEC-01/02/08 未完成，main `857ea759` 不合并。


## 36. SEC-01 原子交换旧 Python 脚本退役路径，依旧不开放迁移（2026-11-17）

- 当前活动为依赖式 [Draft PR #13](https://github.com/weixiaochuchen618-debug/spidervpn/pull/13)，base PR #12，Rust HEAD **`6295b6c87e36ba9c1df2d906f56e021302905d0c`**。根因是 Windows SSH `pairhost.rs::push` 可在旧 systemd receiver 停止后通过 `> tc-pair.py` 重新上传并调用 Python；PR #11/#12 的 root systemd、进程、端口预检**不是**阻断 SSH 路径的栅栏。不能把原脚本 symlink 到 `/dev/null`（后续 `chmod 600` 可能改坏 /dev/null）。
- 代码新增 opt-in `linux-legacy-retire` Rust `legacy_retire.rs`（默认关闭，尚无 CLI/HTTP 或生产调用）：受限 root-owned 0700 legacy 目录/0600 单链接脚本检查、旧服务永久 mask + inactive + 无进程 + 无 TCP4/TCP6 socket 预检；先构建 root-only 临时目录，用 Linux `renameat2(RENAME_EXCHANGE)` **一次原子交换**旧脚本与私有目录，旧固定脚本路径当下成为不能被 shell `>` 重新建立的目录；原字节通过 `RENAME_NOREPLACE` 转存受保护的 `.tc-pair.py.retired`，fsync。交换后出错不自动恢复，避免重新开放旧写者。证明仅说明旧固定路径暂时退役，不等于 root 不可重写或生产用户授权。
- [Linux #44079535756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535756) 与该 SHA 一致，两 Job Completed/Success：113 常规 Rust library、5 CLI、5 terminal policy、11 cutover + 新 **5 真实文件系统原子交换/失败恢复专项**通过，real Linux kernel WG netns 1 passed/0 failed/ignored，严格 --locked/-D warnings。Windows [MSVC #44079535866](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535866) / [GNU #44079535704](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535704) 下次须核对同 SHA 全终态。
- 当前 **尚未**在 Linux root 真实 server 将脚本替换，也未隔离旧 Python HTTP 与 SSH 全写路径；不自动导入旧 Consumed、不开 Rust HTTP listener、不改 UI/连接/WFP。真正上线需可信旧身份/撤销历史、root 管理审核、完整 A/B 与回滚演练，SEC-01/02/08 + Issue #5 仍 Open，全 PR Draft、main `857ea759` 不动。细节 [Backlog D.34](./REMEDIATION_BACKLOG.md)。


## 37. PR #13 原子退役真实 root Linux 通过，Windows 待验（2026-11-17）

- 代码 HEAD 更新为 **`0fed0b6488de0656d2455a5b0bc1ce90328c7b9f`**。原子交换只是进程运行时没有路径缺失窗口；只有成功 `fsync` 后才可把对应目录更新作为持久事实，若之前断电仍可能回滚，重启必须 fresh inspect。早期文档的“交换即使瞬间断电也必然保持退役”不是经过验证的结论，已在迁移文档修正。
- 同 SHA [Linux workflow #44080116892](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116892) 两 Job Completed/Success：113 library + 5 CLI + 5 root TTY + 11 cutover + 5 offline retire 通过；真实 WG netns 1 pass，**额外 Linux runner sudo/root 运行实际文件系统原子退役专项 5 pass**，0 failed/ignored；strict --locked / -D warnings。测试只操作 CI /tmp 临时目录，**并非真实 VPS 生产退役/真实电源故障**。
- 本 SHA Windows [MSVC #44080116790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116790)、[GNU #44080116766](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116766) 当时尚未 Completed/Success；继续跟进。PR #13 Draft，base #12，main 未改；可信旧撤销/tombstone、旧 SSH 客户端禁写、正式 Rust TLS 配对与生产重启/rollback 全部依然阻塞 SEC-01/02/08。


## 38. SEC-01 Windows 旧 SSH 写入禁用分支与测试（2026-11-17）

- 活动分支 `fix/sec01-ssh-legacy-writer-gate-20261117` / [Draft PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14)，base 为 PR #13，当前 Rust HEAD **`5652e64cf5f8ccf726b624bd5bd9da52aeeb9452`**。旧 PR #13 `0fed0b...` Linux/MSVC/GNU 三 CI 最终均 Success；不得拿旧 SHA 的绿抵新 PR #14。
- 最新代码 `src/legacy_writer_fence.rs` 把 shell deny 固定前置于原 Windows `pairhost::run` **所有 SSH 子命令**：自动上传、初始化、旧 Python CLI、邀请码创建/取消、离线批准、设备名和 unit restart 都受限；又在 `deploy::peer_script`、`revoke_script`、`uninstall_script` 的直接 WG 写入前置同策略。只有 server 上明确存在 root 运维的 `.spidervpn-legacy-writes-disabled`（包括悬空 symlink）、旧 `tc-pair.py` 变成原子退役目录或原 `tc-pair.service` 变成 symlink（如 systemd mask）才触发；正常未迁移服务器原代码/交互保持不变。命中则退出码 73、`TC_ERROR=LegacyWriterFenced`，原命令不得执行。Windows 本身不创建标志，也不开放新 UI/API 管理入口，**不是旧 Python 全局封锁或恢复批准**。
- 安全回归：MSVC 新专项 4 项 Rust 策略检查及 1 项 deploy 原脚本守护；Linux server-rs `#[cfg(test)]` 直接引入**这份 Windows Rust 代码**，并且使用 `/bin/sh` 在隔离临时目录实际执行，确保原样运行/marker、dangling symlink、旧脚本目录、systemd unit symlink 四条 DENY，没有因测试写错伪造脚本而出现假阳性。同 SHA 待终态 Linux [#44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095)、MSVC [#44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101)、GNU [#44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202)；禁止忽略失败。后续先查准确 SHA / CI，失败要修复后重测。
- 后续**硬阻塞**：旧 Python 不遵守 Rust flock，老客户端/SSH/root 不遵守本新策略，marker 尚无人证明正确创建；不能据任何本机 SSH 前置检查启用在线 Rust TLS receiver、自动导入历史授权或恢复已撤销 peer。需真实 root/systemd 持久隔离、审批/回滚、历史 revoke 证据及完整新服务验收。SEC-01/02/08、Issue #5 Open，全 PR Draft，main `857ea759` 不动。详细见 [Backlog D.36](./REMEDIATION_BACKLOG.md)。


## 39. SEC-01 新客户端 SSH gate 真实 POSIX shell Linux 验收（2026-11-17）

- [Draft PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14) HEAD `5652e64cf5f8ccf726b624bd5bd9da52aeeb9452`；同 SHA [Linux #44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095) 完整 workflow 两 job **Completed/Success**。118 library、5 CLI、5 admin TTY、11 legacy cutover、5 offline retire tests + 1 真 WG netns + 5 真 root 文件系统退役全 pass，0 failed/ignored。新增 5 个 cross-crate Windows Rust SSH guard tests 真正在 Linux test-only 引入原 Windows Rust 源文件编译，包含真实 `/bin/sh` 执行，验证标志缺失时仍执行旧正文，有标志时 exit73 且**原命令的副作用未发生**。
- Windows [MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101)、[GNU #44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202) 在最后查询时仍进行中，后续精确 HEAD 再查，不可声称三 CI 全绿。当前管理侧还没有把真实 VPS root cutover marker 经独立授权安装，所有 Python 非协作写入口仍然可能不遵守此协议。ISSUE #5 / SEC-01/02/08 仍 Open，PR #14 Draft，不合并 main。索引 [Backlog D.36-D.37](./REMEDIATION_BACKLOG.md)。


## 40. PR #14 同 SHA GNU Success、MSVC 新专项 Success 但完整工作流未终态（2026-11-17）

- Linux [#44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095) 与 GNU [#44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202) 对最新 `5652e64cf5f8ccf726b624bd5bd9da52aeeb9452` 均 Completed/Success。MSVC [#44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101) 的 `Build with Rust`、旧 SEC-10、**新增 SEC-01 writer gate 定向用例**、Rust integration tests 已标 Completed/Success，但整条 workflow 仍 in_progress，下一 Agent 首先核验最终结论。无 UI/WFP 改动，无真实 Linux / Windows 配对服务迁移。
- 已更新 [Issue #5](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5) 留存与 CI SHA 一一对应的证据。SEC-01/02/08 和 Issue #5 仍 Open，Draft PR #14 保持 Draft，main `857ea759` 无修改；后续必须解决非协作旧写者的服务器级真实栅栏、可信历史撤销与 Rust TLS/HTTP 接管，不能将客户端协作拒绝当成安全生产验收。


## 41. SEC-01 Windows 旧 SSH 完整部署/恢复写者门禁，以及 PR #14 MSVC 真实失败复现（2026-11-17）

- 接着 PR #14 做 [Draft PR #15](https://github.com/weixiaochuchen618-debug/spidervpn/pull/15)，HEAD `6ab33a77d0ef2582dc6026535ca9f0c61f5dbc8c`，base = `fix/sec01-ssh-legacy-writer-gate-20261117`。审查完整 `src/deploy.rs` 发现原有直接 WG add/revoke/uninstall 之外的 `install_script`、`transport_script`、`identity_restore_script` 同样有 root SSH config/credential/service 写入能力，PR #14 未保护。新代码使用已有纯 Rust immutable opt-in prelude，自动放在 `set -eu` 后面且在第一条写命令之前；普通未退役服务器旧正文原样、无 UI/WFP/连接改动。
- 精确复核 PR #14 原 HEAD `5652e64cf...` 的 [MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101) **最终 FAILURE**，此前“MSVC 目标专项成功”不等于全流程通过。失败因现有卸载测试把只读 marker 检查引用的 `/var/lib/tradechannel` 误认作卸载触碰审计目录。严格更新测试为“确认为唯一且完全相同的只读门禁 + 原卸载正文完全不引用该目录”，**仍约束身份、审计、WFP 不得误删，没有新增 ignore/skip**。PR #14 同步独立修复 `c322ef2c3fc397231ad433132d7bbc116a9f2459`；PR #15 包含相同修复，两个分支需要各自准确 SHA CI。
- 新 [Linux #44086373715](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373715) 对 PR #15 `6ab33a77...` 两 Job Completed/Success，120 lib+5 CLI+5 TTY+11 cutover+5 offline retire+1 WG real kernel netns+5 real root retire tests（0 failed/ignored）；test-only 真正编译 Windows `legacy_writer_fence.rs` 并用 `/bin/sh` 对照退役 marker 拒绝和无 marker 正常写临时文件。Windows [MSVC #44086373583](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373583) / [GNU #44086373609](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373609) 在记录时仍运行中；不要套用旧 CI 结果。PR #14 新 CI 同样需要最终验收。
- 后续必须继续服务器 root 级真实**多版本旧 SSH 写者**隔离、systemd/重启/回滚、撤销账本可信迁移与 Rust TLS，并确认真实 Windows 多账户安全；没有完成就保持 SEC-01/02/08、Issue #5 Open，所有 PR Draft，main 不合并。见 [Backlog D.39](./REMEDIATION_BACKLOG.md)。


## 42. PR #15 GNU Success、MSVC 新专项成功但 full unit 终态尚未取得（2026-11-17）

- 最新 [Draft PR #15](https://github.com/weixiaochuchen618-debug/spidervpn/pull/15) Rust HEAD `6ab33a77d0ef2582dc6026535ca9f0c61f5dbc8c`，同 SHA Linux #44086373715、Windows GNU #44086373609 **Completed/Success**。Windows MSVC #44086373583 当前 **in_progress**，Rust build、SEC-10、SEC-01 新 writer gate 和全部 integration suites 都已各自 Completed/Success，**full unit suite 仍要跟进**；切勿提前宣称三 CI 全绿。相关 GitHub PR #15 `files` 对比 base #14 仅改 Rust `src/deploy.rs`、`src/legacy_writer_fence.rs`、MSVC/GNU CI yaml，未动 UI/连接/WFP/原 Python 接收端。
- 旧 #14 MSVC 失败不是可忽略测试；已在父 [PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14) HEAD `c322ef2c3fc397231ad433132d7bbc116a9f2459` 独立修复，原安全卸载断言仍然有效，Linux 新 SHA #44086538302 Success，双 Windows 工作流待验。后续检查这四个 Windows runs 的完整结论，如红就看日志定位并修复，不增 skip。
- Issue #5 已注释，Backlog D.39–40 保持完整上下文。SEC-01/02/08 不能因客户端旧 SSH 协作拒绝通过而关闭；生产上仍没有受信的全写者隔离、Revoked tombstone 权威迁移、Rust TLS 接管、VPS 真实电源故障或 WFP/UAC 跨账户验收。主分支与原 UI/连接/WFP 不变，PR #14/#15 Draft。


## 43. PR #14/#15 最终双 Windows + Linux CI 全绿；PR #16 源码型“只读”旧 SSH 漏路（2026-11-17）

- 经过精确 commit SHA 核对，PR #15 `6ab33a77` 的 [MSVC #44086373583](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373583)、[GNU #44086373609](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373609)、[Linux #44086373715](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373715) 最终 **Completed/Success**；PR #14 `c322ef2c` 的 [MSVC #44086538267](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538267)、[GNU #44086538320](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538320)、[Linux #44086538302](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538302) 同样成功。旧 SHA `5652e64` MSVC 确实失败后修复，不能改写历史。
- 本轮新 [Draft PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16) base #15，branch `fix/sec01-transport-source-retirement-gate-20261117`，最新代码 HEAD `ed8d7a9817998fabebdb05d7dc40a9ac8a034804`。在 `src/deploy.rs` 为 `read_transport` / `export_transport` 的两个 `source transport.env` 旧 SSH “只读”路径附上 Rust 退役门禁，未退役情况下原脚本正文严格不变。两组 Windows Rust 定向脚本检查和 Linux 真 `/bin/sh` side-effect 拒绝测试已写入；MSVC CI 强制每一条测试独立检查退出码，不跳过失败。
- **交接下一步**：首先读取 PR #16 最新 HEAD 的同 SHA [Actions](https://github.com/weixiaochuchen618-debug/spidervpn/actions)，逐一确认 Linux core/netns、MSVC/GNU 编译/专项/全量测试；若红，查真实 job logs 修 Rust 后再次编译，切不可引用第一次 SHA 的运行记录。随后重点是服务器 root 级不可并行旧写者、真实 systemd 持久 mask/retire/reboot、可信 revoke/tombstone + Rust TLS 迁移；没有生产隔离与可信历史不得启用 Rust 授权/导入。
- 详情见 [Backlog D.41](./REMEDIATION_BACKLOG.md)。SEC-01/02/08 与 Issue #5 Open，PR #16 和父级均 Draft，main 不动，WFP 旧持久 BLOCK 不动。源文件 `transport.env` 在未退役旧端依然作为 shell code 执行，PR #16 不宣称已对不可信文件的通用执行风险进行修复。


## 44. PR #16 新 SHA Linux 双 Job Success；MSVC/GNU 等完整结论（2026-11-17）

- PR #16 Rust HEAD `ed8d7a9817998fabebdb05d7dc40a9ac8a034804`，同 SHA [Linux #44100469714](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469714) 完整 Completed/Success，两个 Job 均通过：**121 Rust library / 0 failed / 0 ignored**、新真 POSIX shell / sourceable transport.env 防副作用拒绝测试通过、真实 WG netns 和 root 离线退役通过。
- 新 [MSVC #44100469733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469733) 与 [GNU #44100469724](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469724) **仍在运行**，需复核编译、专项和完整结果，任何失败都要修 Rust / CI 本身后新 SHA 重跑，不能跳过。原首版 PR #16 `11155352` 的 MSVC 逐项检查遗漏已在当前 HEAD 补正。
- 主干 main `857ea759` 不改，WFP 持久 BLOCK / 原 UI、正常连接流程不改；无 VPS 真实 root 迁移/可信撤销/正式 Rust TLS，PR Draft、Issue #5 Open。详见 [Backlog D.42](./REMEDIATION_BACKLOG.md)。


## 45. PR #16 同一 HEAD 三工作流均终态 Success；生产验收仍关闭禁止（2026-11-17）

- 代码 [Draft PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16) HEAD `ed8d7a9817998fabebdb05d7dc40a9ac8a034804`。**同一 SHA** 的 [Linux #44100469714](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469714)、[Windows GNU #44100469724](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469724)、[Windows MSVC #44100469733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469733) 全部 **Completed/Success**，日志确证本次 `read_transport` / `export_transport` sourceable 脚本门禁 Rust 用例在 GNU/MSVC 正式跑过，Linux 在真实 `/bin/sh` 复现了侧作用并在 marker 后拒绝。
- Linux 121 library passed、0 failed/ignored，并通过实际 WG netns 和 root 退役测试。MSVC 最后一轮 1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered out（原有环境依赖）；GNU 编译成功、专项 pass，但已有 Rust warnings，不是 `-D warnings` 零告警认证。没有跳过新失败，MSVC 的前后两次专测已加独立 `$LASTEXITCODE` 判断。
- 当前项目安全账本状态仍为 **SEC-01/02/08 未通过生产 DoD、Issue #5 Open、PR #16 Draft、不合并 main**。下一步集中于 Linux root 级旧 Python/SSH 非协作写者、服务切换与重启回滚、可信撤销历史及真实 TLS/HTTP 接管；不能把这个客户端 opt-in 检查充当服务器级独占锁。main `857ea759`、UI/正常连接及 WFP persistent BLOCK 均未改；[Backlog D.43](./REMEDIATION_BACKLOG.md) 为详细证据。



## 46. 新 Draft PR #17：受控 root TTY 离线旧 Python 脚本退役 CLI（2026-11-18）

- 继续 SEC-01/SEC-08 P0，在 [PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16) 成功的 `ed8d7a9817998fabebdb05d7dc40a9ac8a034804` 上创建 [Draft PR #17](https://github.com/weixiaochuchen618-debug/spidervpn/pull/17)，代码 HEAD `45c5f86fae1c55d7eb2418b589b4f32f4f530557`。新 Rust feature-gated `spidervpn-pair-retire` CLI 要 root、固定 verb、预检、真实控制终端 45s 限时精确确认、确认后再次预检，再调用既有只在 opt-in 编译的 Linux atomic retired-path primitive；不开放默认执行路径、网络/API/WireGuard、UI/WFP、生产 Python 或 main。
- **新 CI 正在执行，绝不提前宣称绿**：[Linux #44203320571](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320571)、[MSVC #44203320563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320563)、[GNU #44203320555](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320555)。优先按准确 SHA 查询 Linux `spidervpn-pair-retire` compile + six new tests + 非 root CLI、WG real netns/root temp filesystem；失败必须修复源码再测，所有已有测试保留。Windows CI 需要确认完整 MSVC/GNU；即使三绿也不能等同 VPS 实机 root 退役。
- 这不是完整服务器端 writer fence：真正 root/老版 SSH 可绕过、unit mask 是独立前提，撤销历史/tombstone 不可信仍不能迁入，Rust TLS 未接管。发行/合并闸门原样：SEC-01/02/08 / Issue #5 未验收、所有 PR Draft，main `857ea759` 未变。参见 [Backlog D.44](./REMEDIATION_BACKLOG.md)。



## 47. PR #17 Linux CI 首 SHA 红例、E0382 修复与新三平台验证（2026-11-18）

- 首 SHA `45c5f86` 的 [Linux #44203320571](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320571) core **Failure**，root netns Job Success：新增 CLI Rust unit test 连续两次 `unwrap()` 移动同一 `Result`，真实 E0382 编译错误。已修复为 `as_deref()` 保留两个原始断言，不删除/skip 任何测试；[Draft PR #17](https://github.com/weixiaochuchen618-debug/spidervpn/pull/17) 新代码 HEAD **`de8e2e222a31c0290385a0126c0f2538571c33d0`**。
- 新 SHA [Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974)、[MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970)、[GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) **需要重新查询终态及原始日志**。保留前轮失败记录，不把父 PR #16 绿套用到此 SHA。真实 root/systemd VPS 退役和撤销迁移仍未验收，Issue #5 Open / PR Draft，main/UI/WFP 不动；见 Backlog D.45。



## 48. PR #17 新 SHA Linux Core/Netns 完整 Success 与 6 项新 CLI 真实执行（2026-11-18）

- 代码 `de8e2e222a31c0290385a0126c0f2538571c33d0` 的 [Linux workflow #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974) **两个 Job Completed/Success**；121 lib/0 failed/ignored、六个新增 `spidervpn-pair-retire` binary unit tests/0 failed/ignored、真实非 root 运行 exit2，真 WG kernel netns 与 sudo root 临时目录退役原子文件系统回归都通过。旧首版 `45c5f86` E0382 红已按事实记录并保留。
- [MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) / [GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) 还需查询**同一 SHA**最终完整 Job；不要用旧 PR #16 的结果替代。详见 [Backlog D.46](./REMEDIATION_BACKLOG.md)。
- 绝不能把 opt-in root 离线退役候选解释成生产的 Rust daemon/security DoD：真实 root 的 systemd 停服/持久 mask/reboot/故障回滚、老版 SSH 与其它 root 隔离、受信撤销 tombstone 与 TLS 监听接管均未验收；Issue #5 Open，PR #17 Draft，main 不变。



## 49. PR #17 GNU 全 CI Success，MSVC 完整便携 Rust suite 尚未终态（2026-11-18）

- HEAD 仍是 `de8e2e222a31c0290385a0126c0f2538571c33d0`。同 SHA [GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) **Completed/Success**；[Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974) 两 Job **Completed/Success**，6 新 Rust CLI test/0 fail/ignore、121 lib、真 WG netns 和 root /tmp retirement 全绿。与父 PR #16 差异精确三文件：新 Rust CLI、独立 `required-features` manifest、Linux 工作流。
- 同 SHA [MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) Rust build、SEC-10/SEC-01、integration、模块回归均已单独 Success，但 `Portable Rust unit suite` 最后查仍 `in_progress`；不可借用旧 SHA 或已成功步骤称整个 MSVC 工作流完成。交接接手必须查最后 Job 状态/原始日志、若失败则修复并重跑。
- PR #17/Issue #5 状态、生产安全阻塞仍见 [Backlog D.44–D.47](./REMEDIATION_BACKLOG.md)。没有本机或 VPS 真实 root 切换/回滚，不合并 main，不改变旧 UI、连接交互或 WFP 持久 BLOCK。



## 50. PR #17 三平台最终 Success 核证（2026-11-18）

- 在同一代码 SHA `de8e2e222a31c0290385a0126c0f2538571c33d0`：[Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974) / [GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) / [MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) 三个工作流全部 **Completed/Success**。MSVC 原始日志最终 1429 passed/0 failed/1 ignored（原有）/8 filtered out（原有环境依赖）。新 root-only Rust CLI 6 tests、Linux kernel WG netns 和 root /tmp 原子退役测试均已通过。首轮旧 SHA Linux E0382 Failure 在 Backlog D.45 如实保留。PR #17 仍 Draft，未部署 VPS、没有真正全写者排他或撤销历史认证。

## 51. 新 Draft PR #18：只读 verify 旧 Python 入口重启后退役状态（2026-11-18）

- [PR #18](https://github.com/weixiaochuchen618-debug/spidervpn/pull/18) stacked on #17，分支 `fix/sec01-postboot-offline-retire-verification-20261118`，初始代码 SHA `72533502c1e361d6d1a3d029b5da99cb7499f57f`。扩展**仅 Linux opt-in Rust** `spidervpn-pair-retire` 二进制 `verify` 固定动词：root-only、无 TTY、只读，对已停机/持久 mask/无旧端口监听进行前后确认，并且严格核实旧脚本 root-only 空目录 + 隔离备份原脚本 + 无遗留 staging；任何不符 fail-closed。**绝不自动执行 retire/restore，不导入邀请、不启动 listener、不修改 WireGuard**；原 `retire` 路径不变。
- 新 Rust binary 三组正反向测试、root 临时目录两组断电/重启情境模拟回归、Linux CI 非 root `verify`/ `retire` 真执行拒绝均已提交，**还未证明 CI 通过**。交接下一步：先按此 SHA 查看完整 Linux / Windows MSVC / Windows GNU workflow 终态和原始失败日志；一旦有红必须修代码、推新 SHA、重测，更新 docs/Issue。禁止将模拟 reboot 说成 VPS 实机 power-loss 验收。详见 [Backlog D.49](./REMEDIATION_BACKLOG.md)。main/UI/WFP 不动，SEC-01/02/08 与 Issue #5 OPEN。



## 52. PR #18 Linux 同 SHA 根目录 / 退役复核回归全绿，Windows 正在执行（2026-11-18）

- 新 [Draft PR #18](https://github.com/weixiaochuchen618-debug/spidervpn/pull/18) Rust HEAD `72533502c1e361d6d1a3d029b5da99cb7499f57f`，同 SHA [Linux #44205893006](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205893006) **2 Jobs Completed/Success**：121 lib/0 failed/ignored、9 CLI tests（新 3）全绿、真实非 root 两个动词 exit 2、7 real root /tmp atomic retire/readback fs tests（新 2）、真实 WireGuard kernel netns 通过，`--locked` / `RUSTFLAGS=-D warnings`。
- 同 SHA [Windows MSVC #44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) 与 [GNU #44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961) 此刻 **in_progress**；完整终态必须另查，不能继承 #17 绿或 Linux 绿。GitHub compare 只有 3 个 Linux 文件，旧 `retire` / Windows UI/WFP 交互不改；参见 [Backlog D.50](./REMEDIATION_BACKLOG.md)。
- 仍无用户服务器真实 root mask/retire/reboot/power-loss/recovery 或全跨代 SSH/root 写者排他与可信 revocation tombstone、Rust TLS；Issue #5 Open、全部安全 PR Draft，main 不变。



## 53. PR #18 Windows GNU 完整通过、MSVC 最后一轮仍待终态（2026-11-18）

- 同一代码 `72533502c1e361d6d1a3d029b5da99cb7499f57f`，Linux [#44205893006](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205893006) 双 Job Success；GNU [#44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961) 整个 workflow Completed/Success，原始日志核验 SEC-01 旧门禁在 GNU 运行成功（有已有 Rust warnings）。MSVC [#44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) Rust Build + SEC-10 + SEC-01 + integration + changed modules 全部单独 Success，最后 Portable Rust unit suite 仍 in_progress；**必须再查最终 Job**，不可将部分成功说成全绿。
- 只读 postboot 验证并**无可信原文件内容哈希、无跨时段或跨 root 的独占性证明**，只能作为 opt-in root 管理工具观察事实，不可作为 Rust listener/历史 revoked 迁移或旧写者排他授权。真实 VPS 仍须独立人工/运维验收；SEC-01/02/08 / Issue #5 Open、PR #18 Draft、main/WFP/UI 不动，详见 [Backlog D.51](./REMEDIATION_BACKLOG.md)。



## 54. PR #18 Linux + GNU + MSVC 同一新 HEAD 终态 Success，未通过生产 DoD（2026-11-18）

- 代码提交 `72533502c1e361d6d1a3d029b5da99cb7499f57f` 的 [Linux #44205893006](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205893006)（2/2 Jobs）、[Windows GNU #44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961)、[Windows MSVC #44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) **均 Completed/Success**，MSVC 原始日志末尾 `1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered out（原有环境依赖）`，所有步骤 Success。Linux 121 lib/0 fail/ignore、9 Rust CLI + 7 root 临时目录 FS + real WG kernel netns、非 root 真实 `retire` 与 `verify` exit2 全通过，`--locked` / `-D warnings` 保留。未掩盖旧 #17 原 E0382 失败，该失败早已在后续 PR #17 修复并复测。
- 新增只读 opt-in root CLI `verify` 只能复核快照：systemd mask/停机、进程、旧端口、旧脚本 0700 空目录 + quarantine 0600 文件是否**存在和元数据可靠**，没有可信字节内容对比/签名历史或阻止旧 root/SSH 写者后续重启的能力。模拟 reboot/fs 篡改回归通过 **不等于** VPS 真实 power-loss/reboot/rollback 验收；仍禁止启用 Rust API/迁入旧 Consumed/Revoked 记录。完整细节和未完成清单见 [Backlog D.49–D.52](./REMEDIATION_BACKLOG.md)。
- [Draft PR #18](https://github.com/weixiaochuchen618-debug/spidervpn/pull/18) base #17，不合并 main，不改现有 UI、连接交互、WFP persistent BLOCK。SEC-01/02/08 / Issue #5 继续 OPEN。下一步 P0 应优先推进**服务器可信全旧写者排他策略、撤销历史可信 tombstone、root systemd 真实停服/重启回滚演练、Rust TLS 并发接管**，而不是在 CI 绿时宣称生产修复。



## 55. PR #19：转向 SEC-02 真 TLS 阻塞风险的 Rust 有界握手政策（2026-11-18）

- 已审查旧 Python `assets/tc-pair.py::command_serve`：`ThreadingHTTPServer` 监听 socket **先执行 TLS wrap_socket 再 serve_forever**，所以未完成握手可阻塞 accept loop；不能把 Python ThreadingHTTPServer 字样误判为 handshake 并发已经安全。
- 新独立 [Draft PR #19](https://github.com/weixiaochuchen618-debug/spidervpn/pull/19) stacked on #18，初始 Rust HEAD `6ec1f401ddbc5bc19b82fa62a36c61ee20890b28`，默认禁用 `linux-handshake-admission` feature。仅 Rust Linux policy：AtomicUsize 有界抢占 handshake worker，`DeadlineIo` 总时限下的读写接口（包括慢滴答），RAII 释放失败/崩溃槽位；测试是真实 loopback socket，**尚未实现 TLS/HTTPS 或服务端真实 cutover**。本轮未改旧 Python、Windows UI/连接/WFP 或 main。具体见 [Backlog D.53](./REMEDIATION_BACKLOG.md)。
- 新 CI [Linux #44211032490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032490)、[MSVC #44211032535](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032535)、[GNU #44211032519](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032519) **最初仍 in_progress**。按最新实际代码 SHA 查询；若 Linux Rust E0382/E0277、线程/套接字超时测试红，必须真实定位修 Rust 再重跑，不能忽略/skip；后查 MSVC/GNU 整条工作流而非一个 Build 步骤。
- 重要不夸大：此模块只生成将来 Rust TLS 接收器必须接线的安全基础；普通合法客户端在 Worker 饱和时仍可能被拒绝，外部 TLS 库绕开 DeadlineIo 或 CPU 占满需实际评估。**SEC-02/SEC-01/SEC-08 P0 未生产验收、Issue #5 Open、所有安全 PR Draft**；真实 VPS root、systemd/reboot/rollback、可信撤销历史、真正 Rust TLS/HTTPS 并发慢握手回归仍待做。PR #18 已完成全平台绿但不代表 SEC-02 可合并。



## 56. PR #19 初始 Linux 全绿后主动补正 Rust 握手 deadline 起点（2026-11-18）

- SEC-02 初始代码 `6ec1f401ddbc5bc19b82fa62a36c61ee20890b28` 的 [Linux #44211032490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032490) 双 Job Success，六项 TCP slow drip/idle 并发/slots/panic 真实 Rust 回归成功、121 library + 真实 WG/netns 也通过。
- **随后对抗复审发现 worker 调度延迟能推迟 deadline 起点**，主动在第二 commit `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34` 修为 admission 时生成全局绝对截止时刻，再传递进 `DeadlineIo`；新增一条延迟启动、已有连接字节也不允许超时读取/回复的否定测试，共 7 条，之前测试没有删/跳。最新 Draft PR #19 head 为 `1fcda2dc`，base #18；见 [Backlog D.54](./REMEDIATION_BACKLOG.md)。
- **新 SHA 三 CI 待全程复核**：[Linux #44211428730](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428730)、[Windows MSVC #44211428496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428496)、[GNU #44211428529](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428529)。初版 Linux 绿不能替代。它是默认禁用、暂未接真实 TLS 的 admission policy；即使 CI 全绿，生产 Python 的监听 socket TLS 阻塞仍存在，SEC-02 OPEN，Issue #5 Open、main 未变、不得合并/启用。



## 57. PR #19 重新按正确 deadline 起点通过最新 SHA Linux 七项真实 TCP tests（2026-11-18）

- 当前 [Draft PR #19](https://github.com/weixiaochuchen618-debug/spidervpn/pull/19) Rust HEAD `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34`；新 [Linux #44211428730](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428730) **两 Job 全部 Completed/Success**，库 121 / 0 failed/ignored，握手 policy 新增**七项真实 loopback TCP** tests / 0 failed/ignored，root 临时目录与真实 WG kernel/netns 也保持 Success。测试强制 worker 延迟启动后，连接即使已发送有效字节，IO 也不得越过 admission 时建立的 deadline。
- 精确同 SHA [Windows MSVC #44211428496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428496) 与 [GNU #44211428529](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428529) 仍需核对**整条 CI 终态**。父 PR #18 全绿不等于 #19 已验收。原 Python 仍处于 TLS listener wrap 的单连接阻塞风险；Rust feature 默认 OFF，未上线 TLS 并发或 HTTP handler，不能关闭 SEC-02 / Issue #5 或合并 main。见 [Backlog D.55](./REMEDIATION_BACKLOG.md)。



## 58. PR #19 第三个 Rust SHA：补齐握手无 I/O 回调末尾 deadline 校验（2026-11-18）

- 新审查漏洞：原 `DeadlineIo` 只保证 I/O 操作在时限内；如果最后一次 TLS read 后验签 CPU 计算拖延，callback 可晚于 budget 却 `Ok`。现提交 `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b` 在 return 前验证 admission 计算的**绝对 deadline**，过期转为 `TimedOut`，新增第八条（真 TCP 上不 I/O 但超时返回成功必须被拦截）Rust 回归，旧七条没删除。
- 最新 [Linux #44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) core Job **Completed/Success**：121 lib / 0 failed/ignored；SEC-02 **8/8 loopback Rust tests / 0 failed/ignored**；kernel/netns root job 还需查最终终态。准确同 SHA [MSVC #44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) / [GNU #44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) 仍在运行。必须依每一条最终 Job 和失败日志作证，不把旧 `1fcda2dc` 7 tests 绿写成新 HEAD 全绿；[Backlog D.56](./REMEDIATION_BACKLOG.md)。
- 产品安全范围不变：Rust 限时/有界线程只是**默认关闭的独立策略核心**，没有真实 TLS 证书、握手和 HTTP 的服务端生产路径，更无持续活跃连接、公网慢握手对抗验收；SEC-02 不可关闭，Issue #5/SEC-01/08/Win UAC/WFP 等仍在阻塞。PR #19 Draft、不并 main。



## 59. PR #19 最新 SHA Linux + GNU 完整绿，Windows MSVC 最终仍待核实（2026-11-18）

- Rust HEAD `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b` 精确同 SHA [Linux #44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) **双 Job Completed/Success**：真实 kernel WG netns + 7 root temp retire、原 121 lib 和新 **8 SEC-02 loopback TCP tests** 全 pass，无 ignore/fail；新 `callback_cannot_report_success_after_deadline_without_more_io` 真执行 ok。[GNU #44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) 也 **全 workflow Completed/Success**，含旧 SSH sourced transport、Guard/身份 Rust tests，保留原 GNU warnings。
- [MSVC #44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) Rust Build + SEC-10/01 分别 Success，当前在 integration tests，后续 changed-module/full portable suite 必须等所有 job 完成并查失败日志。不能拿 GNU/Linux 绿当 Windows full green。详细见 [Backlog D.57](./REMEDIATION_BACKLOG.md)。
- 新 SEC-02 Rust policy feature 默认关闭，没有生产真实 TLS/HTTPS 端口或前后兼容验收，不能声称 Python 旧漏洞已修、不能合并 main，SEC-02/SEC-01/SEC-08 / Issue #5 Open。



## 60. PR #19 同一最终 SHA 三平台成功，下一步接握手后的 HTTP 资源边界（2026-11-18）

- 精确 Rust HEAD `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b`：Linux [#44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) 2/2 Jobs Success，8 新 Rust true-TCP tests/0 failed/ignored、121 库 tests/0 failed/ignored，真实 WG kernel/netns 和 root /tmp；GNU [#44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) Success；MSVC [#44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) **Completed/Success**，末尾完整便携 unit 日志 `1429 passed; 0 failed; 1 ignored; 8 filtered`，原有环境排除，全部 6 个主要 CI 阶段成功。
- 当前模块 `HandshakeAdmission::spawn` 成功后可返回任何 `R`，但没有全局**握手后 HTTP 请求阶段**的并发名额与独立绝对 deadline；不得假定只限制 handshake 就能防止后续无限 HTTP worker/慢请求。可独立开发下一张默认关闭的 Rust 有界 request handoff 候选，保持旧 `spawn` 不变，不接生产 TLS/HTTP，设计每一连接一请求/关闭与 session 容量。具体见 Backlog D.58。
- 生产 SEC-02 不通过：旧 Python TLS on listening socket 尚未替换，真实证书/TLS1.2 compatibility 与 HTTP/撤销状态无法自动迁移；Issue #5 OPEN，全部安全 PR Draft，main/UI/WFP 持久 BLOCK 保持原样。



## 61. PR #20 握手后单请求容量与独立期限 Rust 安全候选（2026-11-18）

- 新 [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20) 叠 #19，初始代码 SHA `a773fe881eb02954279d068d2c7d05dacbab5a3e`；仅改 `server-rs/src/handshake_admission.rs` 和现有 Linux CI。新增 `RequestAdmission` 共享 HTTP 配额和 `HandshakeAdmission::spawn_one_request`：握手成功、原 absolute deadline 校验后，**在释放 handshake permit 前先 reserve request permit**，失败直接关闭，成功仅处理一次请求 + 强制总 deadline、无 socket 返回。已有 `spawn` 不动，feature 仍 OFF，根本没有真正 TLS 或 HTTP parser。见 [Backlog D.59](./REMEDIATION_BACKLOG.md)。
- 五组新真 TCP 正反向回归与原 8 条 handshake tests 都须在 Linux `--locked` / `-D warnings` 执行，真实 WG netns、root fs 不删。首 SHA [Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337) netns Job 已 Success、core 正在运行；[MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354)、[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) 仍要读终态。新 agent 先查这三条精确 SHA 工作流，红例不可 skip。
- 即使所有测试绿，生产 `tc-pair.py` 还是 TLS wrap listening socket 旧实现，未切换 Rust server，更未完成证书/握手/HTTP/Revoked data 的安全验收；SEC-02、SEC-01、SEC-08、Issue #5 OPEN、PR #20/全部父 PR Draft，main/UI/连接/WFP persistent BLOCK 不变。



## 62. PR #20 精确 SHA Linux Core + 真 WG netns 全部 Success，Windows 待终态（2026-11-18）

- [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20) HEAD `a773fe881eb02954279d068d2c7d05dacbab5a3e` 的 [Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337) **两个 Job Completed/Success**。原始日志新旧 13 项 Rust TCP handshake + posthandshake bounded callback 测试和 121 lib test 0 failed/ignored，真 WG kernel/netns 及 root 临时目录 FS 均成功，Linux locked + deny warnings 保留。代码相对 #19 仅 Rust 新模块和 Linux workflow 两文件，旧 Windows/UI/WFP/连接与 Python 无变更。
- **重要验收限制**：Rust handoff 保证一个 handler callback、容量、绝对时限和完成后关闭 socket，**不是真 HTTP parser**，不能证明一个 callback 内绝不处理多 HTTP 请求；今后必须添加真实 TLS、HTTP1.1 协议解析/长度限制、可信 token/证书绑定。它不修复生产 Python listener DoS，不在 main。当前 [MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354)、[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) 需核对整个相同 SHA 的 Job 终态，红则修、不 skip。See [Backlog D.60](./REMEDIATION_BACKLOG.md)。SEC-02/01/08 Issue #5 OPEN，PR #20 Draft。



## 63. PR #20 GNU 全绿、MSVC 末轮待结束与未来 TLS1.2/HTTP1.1 真实协议测试矩阵（2026-11-18）

- PR #20 SHA `a773fe881eb02954279d068d2c7d05dacbab5a3e`，[Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337) 2/2 Jobs Success，121 lib + 13 新旧 real-loopback Rust TCP tests 0 fail/ignore、real kernel netns 和 root fs；[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) **完整 workflow Completed/Success**，有原有 GNU warnings；[MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354) 编译、SEC-10/01、integration、changed module 单步成功，最后 portable full suite **仍在运行**，务必继续查准确 SHA 终态与 log。详见 [Backlog D.61](./REMEDIATION_BACKLOG.md)。
- 下一项真正 SEC-02 Rust 接收器必须对齐旧 `assets/tc-pair.py`：TLS1.2（当前 minimum==maximum）、HTTP1.1、旧 JSON response `Content-Length`、`Connection: close`、POST body 1..131072 字节且禁止 Transfer-Encoding。增加真实 TLS 握手、空闲/慢流隔离、请求 header/body size/timeouts、重复 `Content-Length`、无/错误 bearer token、HTTP pipelining/长连接、证书/指纹兼容验收，不能把 `spawn_one_request` 当前“一次 callback”说成真正单条 HTTP wire request。
- 新候选仅默认禁用的 server-rs policy，原生产 Python DoS 尚未修复。SEC-01/02/08 / Issue #5 Open，所有 PR Draft，main/UI/连接/WFP 不动。



## 64. PR #20 最新提交三平台最终通过、生产 SEC-02 仍不可关闭（2026-11-18）

- [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20)，代码 `a773fe881eb02954279d068d2c7d05dacbab5a3e` 精确对应 [Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337)（2/2 Jobs Success）、[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452)（Success）、[MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354)（Success）。Linux 121 lib + 13 handshake/request-loopback tests/0 failed/ignored，真 WG netns + root FS，`--locked`、`-D warnings`。MSVC 全量 unit 原日志 **1429 passed / 0 failed / 1 previously ignored / 8 existing environment-filtered**，GNU 原有编译 warnings 未称消除；不掩盖失败也未加 skip。
- 此 PR **只有两个 Linux Rust/CI 文件改变**、默认 feature OFF；没有现役 Python、HTTP parser、真正 TLS、Windows UI/connection/WFP 或 main 改动。类型上只执行**一次 handler callback** 并防无限线程和慢连接超时，不证明严格一个 HTTP wire request；未来必须加真实 TLS1.2/证书与指纹验证，符合旧协议的 HTTP1.1 单请求（header/body/错误分支/POST 131072 大小/anti-pipelining）和有效 token/撤销 ledger，真实 VPS 端口监听并发 + rollback 演练。详见 [Backlog D.59–62](./REMEDIATION_BACKLOG.md)。
- SEC-01/02/08 和 Issue #5 Open，PR #20 与父级 Draft 不合并。main/UI/正常连接/WFP 持久 BLOCK 不变。安全整改下一轮可以由这些 evidence 接着做真实 TLS/HTTP 接收候选，但不得自动迁移旧 Consumed/Revoked 数据或宣称已上线。



## 65. PR #21 严格 Rust HTTP1.1 decoder，首 CI 失败已定位并重新提修（2026-11-18）

- 从三平台同 SHA 全绿的 [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20) `a773fe881eb02954279d068d2c7d05dacbab5a3e` 叠新 [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21)，首 `9e392b84122569e0375f0e6afb0a09470369bf80`，现在 Rust HEAD `4f770d2f90686785d99f31e41b60ca71e6d3c48f`。只有 Rust 新 `http_one_request.rs`、`lib.rs` feature gate 与原 Linux CI 共 3 文件，default OFF，main、旧 Python、Windows UI/连接/WFP 不改。详见 [Backlog D.63](./REMEDIATION_BACKLOG.md)。
- 新 Rust `read_one_request(&mut DeadlineIo)` 在既有 request-stage 有界资源名额和绝对时限下解析**唯一一条**未认证的 HTTP/1.1 GET/POST message：POST 1..131072 字节，header block 16384，header line 4096，request line 2048，header fields 64，拒绝 CL 重复/不合法、TE/CL+TE、obs-fold、Host/Auth 重复、CRLF 等畸形；并且不得把 token/POST body 打在 Debug。**没有真实 TLS、接口身份与权限校验，也不构成配对 server / HTTP endpoint。**
- **确切第一轮失败**：首 SHA [Linux #44224651210](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224651210) core Failed，8/9 新 parser 测试通过，`pipelined_second_request_unread_and_socket_closed` 对未读第二 request 的 TCP 关闭错误地只接受 EOF，Linux 真实返回 `ConnectionReset`；后续 Rust commit `4f770d2f...` 精确修此测试为接受 EOF 或 RST，仍必须 assert 第二 request 无处理且 request/handshake permit 清零。此前旧 13 tests 均 pass，未 skip/删用例。
- **下一步先复核新 SHA 三条 CI 终态**：[Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790)、[GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789)、[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780)。如果 Linux/Windows 有任何红，立即定位新 SHA 原始 logs、修 Rust 且不忽略失败测试。SEC-02 部署 Python TLS listener 仍未修、SEC-01/08 与 Issue #5 OPEN、PR Draft、main/WFP/UI 不变。



## 66. PR #21 最新新 SHA Linux + GNU 全绿，MSVC 全量最后待核（2026-11-18）

- [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21) HEAD `4f770d2f90686785d99f31e41b60ca71e6d3c48f`，[Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790) **两 Job Completed/Success**：121 lib、13 old handshake/request tests、9 new Rust strict HTTP1.1 parser real TCP tests 全 pass / 0 ignored/fail，root tmp 与真 WireGuard netns。首 SHA `9e392b84` 原 Linux 8/9 的管线连接 EOF-only 测试 FAILED，已改成 Linux 合法 EOF **或** RST 才是关闭，原测试未删除/skip。见 [Backlog D.63–64](./REMEDIATION_BACKLOG.md)。
- [GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789) 同新 SHA **整个 workflow Completed/Success**（原有 compiler warnings），Guard/身份、SEC-01 sourced transport SSH tests 实测通过。[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780) 同新 SHA Build、SEC-10/01 已 Success，继续等待 integration/changed-module/full portable unit 的**完整终态**和真实日志；禁止提前记三平台 CI 成功。
- 对接真正 TLS 的技术缺口：当前 `http_one_request::read_one_request` 接受 `&mut DeadlineIo`，真实 TLS1.2 端必须先将 rustls/验证通过的 TLS 解密层实现为**独立受时限约束的读取接口**再交给 parser；直接把 TLS raw ciphertext 交给当前 parser 是错误的。尚无生产 listener、HTTP response、可信 token/Revoked 数据。Issue #5/SEC-01/02/08 Open，PR #21 Draft，main/UI/WFP 不变。



## 67. PR #21 同最终代码 SHA 三平台成功；仍不是生产 TLS/HTTP 安全收口（2026-11-18）

- [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21) Rust HEAD `4f770d2f90686785d99f31e41b60ca71e6d3c48f`，精确对应 [Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790) **2/2 Success**（121 lib + 13 旧 admission + **9 新 HTTP parser localhost TCP** /0 failed/ignored、真实 WG kernel netns 和 root FS），[GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789) **Completed/Success**（有旧 warnings），[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780) **Completed/Success**：所有 Windows 构建/权限/集成/变更模块/全量 Rust 步骤成功，最后原日志 `1429 passed; 0 failed; 1 ignored; 8 filtered`（已有）。无新 skip/ignore，首 SHA 真实 Linux pipelined EOF-only 失败记录保留于 [Backlog D.63–65](./REMEDIATION_BACKLOG.md)。
- 改动只含 3 个 Linux Rust/CI 文件，feature 默认 OFF。新 `read_one_request(&mut DeadlineIo)` 是**未认证的明文 HTTP1.1 报文解码**，不能据此断言在真正 Rust TLS1.2 加密连接上收到了/解析了正确 HTTP 数据；必须先对接 TLS 已解密流且继续有界 timeout、完成 X509/legacy fingerprint 兼容及可信 PairRequest 授权，再用真实 client/server TLS1.2 的 wire 对抗测试和 HTTP1.1 边界测试确认。原 Python 生产/旧撤销历史、所有 root 旧写者、VPS 实机 rollback 和 Win UAC/WFP 仍是阻塞项。SEC-01/02/08 + Issue #5 Open，PR #21/父 PR 都 Draft，main/WFP/UI/连接交互不动。



## 68. PR #22 默认禁用 Rustls TLS1.2 真握手→解密 HTTP，首 Linux lint 红已修（2026-11-18）

- 先核对父 [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21) `4f770d2f...` 同 SHA Linux/GNU/MSVC 三平台全绿；新 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) stacked on #21，branch `fix/sec02-rustls-tls12-decrypted-http-lab-20261118`，当前 Rust HEAD **`63f84bce9c75865727d2d8b409d08b4198d4d181`**。六个文件只涉及 Linux server-rs module/Cargo pinned deps/CI，无 Windows UI/连接/WFP、原 Python/main 变更。
- 这是此前“HTTP parser 只能读明文 TCP”问题的直接实码补齐：默认禁用 `linux-tls-wire-lab = [linux-handshake-admission,dep:rustls]`，重用客户端锁定的 rustls 0.23.46 ring provider，只允许 TLS1.2；HandshakeAdmission 仍必须保留前置 CAS slot、各阶段单调 deadline。Rustls `ServerConnection.complete_io(&mut DeadlineIo)` 真执行服务器 TLS 协议；通过后 `Stream::new(&mut ServerConnection, &mut DeadlineIo)` 交**已解密**的 HTTP1.1 application bytes 给泛型 `Read` 的严格 parser；每一 callback 后立即关闭，**解析输出仅 Untrusted**，无鉴权、HTTP response 或公网端口。七个真实 TLS encrypted loopback tests 包括证书验证失败/TLS1.3 拒绝、慢握手阻塞隔离、解密慢 header 绝对超时等；OpenSSL 仅在测试中为 localhost 生成临时 CA/leaf/key，不提供生产安全逻辑。见 [Backlog D.66](./REMEDIATION_BACKLOG.md)。
- **首轮 Linux #44227662295 真实 FAILED**：原 121/13/9 已 PASS，Rustls 新测试编译因为 `-D warnings` 报一个 `unused import Read`，未跑新七条；新 commit `63f84bce...` 删除此导入，不改告警门槛、不跳过任何单测。必须立即查新 [Linux #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860)、[GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808)、[MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692) 准确 SHA 各 Job 终态，再用日志证明真实 TLS crypto/wire tests 是否 pass；失败再修 Rust、完整复跑。不得称 SEC-02 production fixed/合并 main。
- 仍缺真实 Linux TLS 接受端 daemon 与 root-only PEM 证书、身份认证及可信 Revoked/Consumed 状态、HTTP1.1 JSON 合规响应、实际 Python 退出/systemd/reboot/rollback 与真实 Windows WFP/UAC 演练。SEC-01/02/08/Issue #5 OPEN、PR Draft，WFP 持久 BLOCK不动。



## 69. PR #22 同新 SHA 真 TLS1.2 Rustls wire / 解密 HTTP 测试 Linux 完整绿（2026-11-18）

- 新 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) 继承 #21 三平台同 SHA 全绿基线，在 `server-rs` 新增默认关闭 `linux-tls-wire-lab` feature + pinned rustls 0.23.46/ring/TLS1.2（主客户端 lock 精确相同版本和依赖校验），以真实 `ServerConnection.complete_io(DeadlineIo)` 完成加密握手，交给 `rustls::Stream` 已**解密**的 HTTP1.1 数据进入泛型 `Read` 严格 parser。现有 handshake CAS slot/绝对 deadline、独立 request slot/绝对 deadline 都保留。编译来源是 Rust，OpenSSL 仅作为临时 localhost cert fixture generator，**无** Python 生产重写、HTTP response/任何凭证授权、VPS listener 上线。见 [Backlog D.66–67](./REMEDIATION_BACKLOG.md)。
- 首代码 `d205763fe8e4eb774a9be1ed216fc8105f56d41c` [Linux #44227662295](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227662295) **core Failure**（`-D warnings` 拦 unused Read，7 条真 TLS 当时尚未执行），新 commit **`63f84bce9c75865727d2d8b409d08b4198d4d181`** 删除 unused import，保留 `-D warnings` 和全部测试。新 [Linux #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860) **两 Job Completed/Success**，原日志证明 **7/7 新 TLS1.2 真加密/解密回归** + 13 旧 handshake/request + 9 旧 HTTP parser、121 库 test 全通过/0 fail/ignore，真实 WG netns + root fs tests 继续通过。
- [MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692)、[GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808) 同新 SHA 在执行，必须继续查全量编译、SEC-01/SEC-10、安全与集成测试**终态/日志**，禁止称三平台完成或借 #21 成绩。
- 安全等级不变：此功能是 default-off 真实 TLS protocol **实验测试**，不包含 production root-owned PEM loading、证书旧指纹兼容验证、实际 HTTP response、可信 Token/撤销历史、全 root 写者禁用或 VPS systemd/重启/rollback 演练。旧 Python 接收线程仍可被慢 TLS 卡住，SEC-02 **生产未修**；Issue #5/SEC-01/02/08 Open，PR #22 Draft，main/Windows UI/连接/WFP persistent BLOCK 不动。



## 70. PR #22 最新 TLS1.2 加密/解密 Rust lab 全三平台 CI Success；继续严守生产验收（2026-11-18）

- 当前 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) Rust HEAD **`63f84bce9c75865727d2d8b409d08b4198d4d181`**；[Linux #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860) **2/2 Jobs Success**（121 lib、13 handshake/HTTP admission、9 HTTP1.1 parser 真实 TCP、**7 真实 rustls TLS1.2 encrypted/decrypted wire tests** 全 pass/0 fail/ignored，真 WG kernel netns/root tmp fs 成功，`--locked` `-D warnings`）；[GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808) **Completed/Success**（原既有 warnings）；[MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692) **Completed/Success**，全部 Build/Guard/SSH/Integrations/changed-module/full portable suite 真执行，原始总结 `1429 passed; 0 failed; 1 ignored; 8 filtered`（全部原有）。三条相同代码 SHA。详见 [Backlog D.66–68](./REMEDIATION_BACKLOG.md)。
- 首 SHA `d205763f` [Linux #44227662295](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227662295) 真实 core Failed：strict deny-warning 的 unused import，原旧用例正常，新 TLS tests 没执行；`63f84bce` 删掉 unused import 后完整重跑，未 skip。该历史应保留。
- **下一高优先级生产前步骤**：原 Python `assets/tc-pair.py` 默认 `CERT=ROOT/tls.crt` 和 `TLSKEY=ROOT/tls.key`，`ROOT` 默认 `/var/lib/tradechannel/pairing-rs` 但受旧 `TC_PAIR_ROOT` 环境影响；新 Rust 端必须固定 trusted root path/文件所有权、禁止 symlink 与低权限可写父目录，采用**原证书且保持已有客户端 pin**；随后真实 TLS1.2 单请求 HTTP JSON/Content-Length/Connection close 响应 + 可信 bearer/Revoked 授权 integration（未可信迁移只返回 fail-closed 错误），最后 Linux VPS 系统服务切换和可回滚重启/故障注入真实验证。不能使用刚测试过的**临时 CA/leaf**替换生产证书。
- PR #22 只是默认关闭的 rustls TLS1.2 真实加密测试模块；仍无可用公网 listener、PEM loader/旧指纹确认、实际 HTTP response、root writer 阻断/撤销历史迁移与 VPS 实机验收；SEC-02/01/08、Issue #5 OPEN，不并 main。原 Windows UI/正常连接及 WFP persistent BLOCK 未变。



## 71. PR #23 旧 TLS 根证书文件读取/指纹校验 Rust 候选与 Linux 真实 root 测试（2026-11-18）

- 从同 SHA Linux/GNU/MSVC CI 全绿的 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) `63f84bce...` 叠新 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23)，branch `fix/sec02-trusted-tls-cert-pin-loader-20261118` 当前 Rust HEAD **`5c4b9a16d08f96c3501aa5876a48e644a3d55cdf`**。变化仅服务端 Rust 新 `tls_identity.rs`、lib.rs feature gate、Cargo.toml/Cargo.lock（现有锁中已存在 zeroize 1.9.1 加 optional direct dep）、Linux CI。新 `linux-tls-identity-lab` 默认关闭，不使用用户真实证书、端口，不改 Python/Windows UI/连接/WFP persistent BLOCK/main。
- **旧证书保持原 pin 契约**：`tc-pair.py::cert_sha256` 与 `src/pairing.rs::PinnedCert` 都用**叶子 DER 而非 PEM 文本**的 SHA256 小写 64 位十六进制；新 `read_existing_production_identity(expected_pin)` 仅接受 **外部独立可信**的旧 pin（不能从不可信 server.json 自证），真实 euid0，固定原目录 `/var/lib/tradechannel/pairing-rs`；openat 逐路径组件、no symlink/no group or world writable ancestors、叶子 key 0600、root owner、single inode link、限幅读取、PEM/证书链校验/私钥 PEM zeroize，pin 不符拒绝配置；只生成禁用实验 feature 下 Rustls TLS1.2 ServerConfig。**成功绝不等于 PairRequest 已授权**。真实旧 X509 selfsigned 扩展/时效及真实 VPS 文件状态尚未核实。
- **明确失败史**：[Linux #44232824851](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44232824851) 首 `03f1cccc` Rustls 私有 `ServerConfig.versions` 编译 E0616；[Linux #44233060733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233060733) 第二 `ed69fc02` 编译绿但 X509 测试 fixture `CA:TRUE` 被 rustls 拒 `CaUsedAsEndEntity`，root tests 7/8，**真实失败不得抹去**。第三 `5c4b9a16` 修测试证书为独立 CA:TRUE issuer、SAN localhost/CA:FALSE leaf，不减测试、不放宽证书校验，和原证书自签兼容尚未实际验证。
- 最新 [Linux #44233312502](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312502) **两 Job Completed/Success**，normal + **真正 root uid=0** 各 **8/8** TLS identity tests；原 121 library、13 handshake/request、9 HTTP1.1、7 Rustls TLS1.2 encrypted tests、真实 WG kernel/netns 与 root 脚本退役均 Success，`--locked`、Linux `-D warnings`。新 [Windows GNU #44233312449](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312449)、[MSVC #44233312496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312496) 继续查**精确新 SHA 的最终 Job 和日志**；红则修、不 skip，不提前称三平台。
- 下阶段强制闸门：核验**旧生产自签证书 X509 extensions** 与现客户端 `PinnedCert` 证书 pin+有效期/签名行为兼容，不能把现 CA:FALSE 实验签发的证书当旧客户端原证书；真实 VPS 只读检查原 root owner、mode 和已有 invite pin（不可传新 config 自己生产 pin），再做真实服务端授权与 HTTP response、SEC01/08 root writer/Revoked ledger、systemd 受控切换/回滚演练。**SEC-01/02/08 与 Issue #5 OPEN，PR #23 Draft，不合 main，UI/连接/WFP 不改。** 详见 [Backlog D.69](./REMEDIATION_BACKLOG.md)。



## 72. PR #23 非测试 Feature 编译闸门、最新 Linux/GNU 同 SHA 全绿（2026-11-18）

- 新 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23) 最新代码 SHA **`163ef8fecbe5216b758da4794966700b5f6d38ae`**，对在 `5c4b9a16` 上已绿的 Linux PEM/DER pin/security root tests 新增**实际非测试 library cargo build** `--features linux-tls-identity-lab --lib --locked` `RUSTFLAGS=-D warnings` 并移走测试专用 import；测试和原强制门禁未删改。精确新 SHA [Linux #44234674040](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674040) 2/2 Jobs **Completed/Success**、真实 non-test build 成功，121 lib、13 handshake、9 HTTP parser、7 真 TLS1.2 encrypted wire、8 新证书安全测试在普通+真实 root 下各通过/0 fail/ignore，真 WG netns、root fs 原回归通过。[GNU #44234674093](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674093) 同 SHA **Completed/Success**，原有 warnings 存在。[MSVC #44234674573](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674573) 同新 SHA 构建、SEC-10/01、integration 已 Success，changed modules/full Portable suite 还必须看终态与原日志。详见 [Backlog D.69–D.70](./REMEDIATION_BACKLOG.md)。
- 此 PR 仍是默认为 OFF、没有上线 listener 的证书文件 **read-only Rust 候选**，从 root-owned 固定目录/无符号链接/无低权限写/私钥单链接+0600/受限大小读取原 PEM，比较叶子 DER SHA256 与**独立可信**旧邀 pin，零化私钥 PEM 内存；不读取原线上数据、不生成新证书、不做 Bearer 授权。原 `tc-pair.py` 监听 TLS blocking bug 未从生产移除；原 Python `openssl req -x509` 可能产生有 CA:TRUE 扩展的自签 leaf，真实客户端 `PinnedCert` 证书 pin + 有效期/签名兼容仍需真实旧证书单独做对照，不能把这次 CA:FALSE 测试叶子当生产证据。SEC-01/02/08、Issue #5 OPEN，PR #23 + parents Draft，不合 main，原 UI/连接/WFP 不动。
- 第一、二轮失败（`03f1cccc` 私有 rustls 字段编译 E0616；`ed69fc02` 生成 CA:TRUE fixture 触发 Rustls CaUsedAsEndEntity）与修复历史保存于 D.69 / §71，不得称初始两个 SHA 曾通过。



## 73. PR #24 Rust TLS1.2 HTTP 旧协议仅拒绝 JSON 响应、安全不放行（2026-11-18）

- 实际仓库已存在由前一工作继续推进的 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23) `163ef8fecbe5216b758da4794966700b5f6d38ae`，Linux #44234674040、GNU #44234674093、MSVC #44234674573 精确 SHA **全部 Completed/Success**（MSVC 1429 passed/0 failed/1 原有 ignored/8 原有 filtered）。#23 root-only no-symlink PEM/pin loader 已实现/校验，本轮**没有覆盖该工作**。
- 新 [Draft PR #24](https://github.com/weixiaochuchen618-debug/spidervpn/pull/24) parent #23，branch `fix/sec02-failclosed-tls-http-response-20261118`，Rust HEAD **`4f1c13715e5eb734879a1212377fb53b60e7ce6d`**，5 个 Rust/Cargo/CI 文件，默认 feature `linux-http-deny-response-lab` OFF。真实 TLS1.2 Rustls handshake/原 CAS slots 与绝对 deadlines 均重用，不提供生产 TLS listener。Rust `http_fail_closed::serve_denial_only` 解析已解密严格单 HTTP1.1 request：无 SEC01/08 可信 auth ledger 一律 `500 {"Code":"InvalidState","Ok":false}`，坏 HTTP framing `400 {"Code":"InvalidRequest","Ok":false}`；固定 `Content-Type: application/json`、`Content-Length`、`Connection: close`，不能回显令牌/正文、不能 `Ok:true`、禁止路由到真实邀请/WG/撤销状态。TLS close_notify 后关闭 connection，保留一次 callback 限额。见 [Backlog D.71](./REMEDIATION_BACKLOG.md)。
- 新 SHA [Linux #44241916382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916382) **2/2 Jobs Success**，5/5 新真 TLS JSON response + 既有 121 lib、13 admission、9 parser、7 rustls TLS、8 PEM pin 普通+root、真实 WG netns/root fs 成功；`--locked` `RUSTFLAGS=-D warnings`、真实 non-test Rust feature Build 均绿。最新 [GNU #44241916434](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916434)、[MSVC #44241916397](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916397) 继续查确切 SHA **完整 Job 终态与原始日志**，不借用父 PR CI。
- 仍非生产 SEC-02 修复：旧 Python wrap(listener) TLS accept DoS 正在生产，缺真实 root PEM/cert pin CA:TRUE 兼容、可信 Invites/Revoked ledger、HTTP authorized success、全 SSH/root writer shutdown、VPS controlled cutover/rollback & Win UAC/WFP 真机验收。SEC-01/02/08 与 Issue #5 OPEN，PR #24 Draft，不改 main/UI/连接/WFP persistent BLOCK。



## 74. PR #24 真 TLS1.2 旧客户端 JSON 错误信封已三平台同 SHA CI 完成（2026-11-18）

- 目前新 [Draft PR #24](https://github.com/weixiaochuchen618-debug/spidervpn/pull/24) 是 #23 叠加候选，代码 HEAD `4f1c13715e5eb734879a1212377fb53b60e7ce6d`，仅 5 个 server-rs Rust/Cargo/CI 文件；无需重做 #23 已三平台全绿的 root-only PEM 读与证书 pin test。新的 `linux-http-deny-response-lab` 仍 default OFF，无生产服务入口/授权，更未动 Windows UI/连接/WFP 或旧 Python。
- 此 Rust 特性是真正 rustls TLS1.2 加密 TCP 与**已解密** HTTP1.1 framing 的**仅失败响应**：正常 GET/POST（即使附带伪/真 Bearer）不允许任何配对，固定旧客户端 JSON 信封 `500 {"Code":"InvalidState","Ok":false}`；invalid framing 固定 `400 {"Code":"InvalidRequest","Ok":false}`；正确 HTTP `Content-Type`、`Content-Length`、`Connection: close`，单一 capped worker 后发送 close_notify、没有 keepalive/第二响应。未知 authority 不能 `Ok:true`、不能进行 WG 或 invitation mutation。见 [Backlog D.71–72](./REMEDIATION_BACKLOG.md)。
- 精确同代码 SHA [Linux #44241916382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916382) **两 Job Completed/Success**（新 5 TLS JSON tests、原 121 lib+13 admission+9 strict HTTP+7 TLS crypto+8 PEM normal/root，真 kernel WG netns、root FS，非测试 Rust feature build、`--locked` `-D warnings`）；[Windows GNU #44241916434](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916434) **Completed/Success**（原有 warnings）；[MSVC #44241916397](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916397) **Completed/Success**，Build/SEC-10/SEC-01/integration/changed module/portable final 全 success，原日志 `1429 passed; 0 failed; 1 ignored; 8 filtered`（原有）。没有 skip 掩盖失败。
- 安全验收仍 **BLOCKED**：旧线上 Python `SSLContext.wrap_socket(listener)` DoS 尚未切换；此前实验 TLS fixture 不是 VPS 旧 CA:TRUE 自签 leaf/客户端 PinnedCert，有证书 X509/legacy compatibility 未验；历史 Revoked/Consumed/邀请 token 真实可信迁移、旧 root/SSH writers 排他、具有真实鉴权的 HTTP 成功 JSON 和真实 root 配对服务、VPS systemd/重启回滚、Windows UAC/WFP real-host tests 均未完成。**SEC-01/02/08 和 Issue #5 保持 OPEN，PR #24+所有父 PR Draft、不合 main。**



## 75. 当前最新：SEC-02 真实有界 localhost accept + TLS1.2 拒绝链 PR #25（2026-11-18）

- **先以 [Backlog D.73](./REMEDIATION_BACKLOG.md) 与最新 GitHub CI 为准**。最新工作 Draft [PR #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25) stacked on Draft #24，代码 HEAD `b2f6a19356dfc1ee90db734586151d79ebaf7df2`；仅 5 个 Rust server-rs/CI 文件，主线 main `857ea7593941ce79f6507db5b1ced076c3a077ba`、Windows UI/连接/WFP persistent BLOCK 与现役 Python 无变更。新 Cargo `linux-bounded-accept-lab` **default OFF**，没有公开监听/生产 entry point。
- 新 Rust `loopback_denial_lab.rs` 只允许 loopback、数量和 accept window 有界，每个真实 accept socket 复用 TLS1.2/HTTP1.1/deny-only JSON 与 CAS admission permits；测试添加四种反例（慢客户不阻塞健康客户、满载关闭并恢复、拒绝 `0.0.0.0`、拒绝无限数量/等待时间）。仍绝不返回成功授权或读写 WireGuard/ledger。
- **准确 CI**：该 SHA 的 [Linux #44249576605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576605) 2/2 Jobs **Completed/Success**，原始 core logs：新四条 `loopback_accept_*` 均 ok，含旧五条的 HTTP deny 9/9、真实 rustls TLS 7/7、原 Rust lib 121/121、root-only PEM 8/8 与真 WG netns 1/1；零新增 fail/ignore，`--locked` / `RUSTFLAGS=-D warnings` 和非测试 feature library build 未放松。 [GNU #44249576563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576563) 与 [MSVC #44249576553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576553) 当前仍在执行，下一 Agent 需查完整 workflow 和 Job logs，**不能提前宣称三平台全绿**。
- 生产 SEC-01/02/08 和 Issue #5 仍 OPEN，全部修复 PR Draft/unmerged。旧 Python TLS listener accept blocking **仍存在**。缺真实旧证书指纹双端、可信 revoked/consumed 历史和 root writers 迁移、HTTP 成功授权安全闭环、VPS systemd/rollback/reboot、真机 Windows UAC 与 WFP 持久零泄漏。禁止在缺失这些验收条件时合 main。


## 76. 最新交接：PR #25 三平台全绿；PR #26 旧证书兼容实测正在 CI（2026-11-18）

- [Draft PR #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25) HEAD `b2f6a19356dfc1ee90db734586151d79ebaf7df2` 同 SHA 的 [Linux #44249576605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576605)、[GNU #44249576563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576563)、[MSVC #44249576553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576553) 均 Completed/Success，MSVC portable 原始日志 1429 passed / 0 failed / 1 ignored / 8 filtered（原有）。
- 新 [Draft PR #26](https://github.com/weixiaochuchen618-debug/spidervpn/pull/26) stacked on #25，HEAD `1f5ee14500fe4f424555078ef0748a93a0c28024`，branch `fix/sec02-legacy-selfsigned-rsa-tls-compat-20261118`。改动只包含 Rust test-only（server-rs TLS 身份 + Windows pairing HTTP）及三条 CI，无新增依赖或生产逻辑改动。
- Linux 重新执行旧 Python OpenSSL RSA2048 / SHA256 / 825 天 CN-only 自签生成命令；实测 CA:TRUE、无 SAN、DER pin、protected loader 与真实 Rustls TLS1.2 listener 的 JSON denial；另在 Windows 复用真实客户端 get/data/PinnedCert 测试同类 RSA 自签证书、错误 pin 与证书有效期边界。**端点互补证据，不是真实用户 Windows→VPS 端到端证据。**
- 新 SHA [Linux #44253155134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155134)、[GNU #44253155155](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155155)、[MSVC #44253155258](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155258) 尚待核对终态；若失败检查原始日志和不通过的测试，修复后复跑，不得跳过。
- 详见 [Backlog D.75–D.76](./REMEDIATION_BACKLOG.md)。main 仍 `857ea7593941ce79f6507db5b1ced076c3a077ba`；SEC-01/02/08、Issue #5 OPEN，SEC-07 生命周期未闭环；PR #26 Draft/unmerged，不进入真实部署。生产 Python 阻塞风险未修复；实际 VPS 证书兼容、授权/撤销历史、旧写入者退场、切换回滚、真机 UAC/WFP 持久零泄漏仍是安全验收门槛。


## 77. PR #26 Linux 生产旧证书形状回归完全通过；Windows 待终态（2026-11-18）

- [Backlog D.77](./REMEDIATION_BACKLOG.md) 为当前证据。最新 Draft [PR #26](https://github.com/weixiaochuchen618-debug/spidervpn/pull/26) HEAD `1f5ee14500fe4f424555078ef0748a93a0c28024`，对应 [Linux #44253155134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155134) **2/2 Jobs Completed/Success**。普通 core 原日志新 `sec02_legacy_openssl_rsa_identity_serves_real_tls12_denial ... ok` 1/1，root 身份回归含新测试 9/9；真实 WG netns 1/1、既有 Rust 测试继续通过，无新增失败/忽略，严格 `--locked`/`-D warnings`。
- 真 RSA 2048 CA:TRUE、无 SAN 旧 OpenSSL 生成形状与独立 DER pin、受保护 Rust loader、真实 TLS1.2/deny-only 互通，在隔离 temp root 测试验证；Windows 现有客户端 pinned verifier 三项 Rust tests 待 [GNU #44253155155](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155155) / [MSVC #44253155258](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155258) 完整结果，不提前标三平台绿。区别互补测试与用户 VPS 实机端到端。
- 下一轮先检查这两个准确 SHA CI 终态及原始专项/完整日志，失败必须修复不跳过；再推进 SEC-02 长期服务生命周期、跨源资源限制与可信授权等依赖；生产 SEC-01/02/08、SEC-07、Issue #5 未关闭，所有安全 PR Draft，main、原 UI/连接交互、WFP persistent BLOCK 不动。线上 Python 慢握手 accept DoS 仍在。


## 78. 最新：PR #26 全绿；PR #27 可持续接收器与来源/总量额度（2026-11-18）

- [Backlog D.78–79](./REMEDIATION_BACKLOG.md) 为当前证据。PR #26 HEAD `1f5ee14500fe4f424555078ef0748a93a0c28024`：Linux #44253155134、GNU #44253155155、MSVC #44253155258 全 Completed/Success；Windows 新 legacy RSA pin 三项均 3/3，MSVC 1432 passed/0 failed/1 ignored/8 filtered（既有）。
- 新 [Draft PR #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27)，HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`，branch `fix/sec02-persistent-bounded-listener-20261118`，6 个 server-rs Rust/Cargo/CI 文件。default-off `linux-persistent-listener-lab`；可长期循环 accept、全生命周期含 HTTP 的全局及每真实来源 IP 限额，IPv4 映射规范化，无无限线程句柄/来源表；stop flag 下先关 listener 后 drain，保留握手和单请求 deadline。仍 loopback/deny-only/无 service 或授权。
- 真实 TCP/TLS 回归：源阻塞后第二真实源正常、全局限额及断开恢复、80 次连续、stop 后拒绝新连接仍 drain、非法容量与 wildcard；仅代码提交，待 [Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383)、[GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600)、准确 SHA MSVC workflow/原始日志；不允许 skip/ignore 新失败。下一步优先查 CI 终态、真实专项与根因修复，随后推进信号生命周期/授权依赖、真实迁移阻塞。
- main `857ea7593941ce79f6507db5b1ced076c3a077ba` 固定；WFP #3 Draft，Issue #5 OPEN；不动 UI/连接/WFP；实际生产旧 Python TLS accept DoS 仍存在。不得把实验 CA/loopback/安全拒绝等同现网正常授权、VPS 安全切换和 UAC/WFP 实机验收，不合 main。


## 79. PR #27 Linux 完整通过，Windows 待终态（2026-11-18）

- 最新 [Draft PR #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27) HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`。[Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383) 2/2 Jobs Completed/Success；实际日志：新 1 个来源规范化 + 5 个真实 TLS 长期接收器测试通过，HTTP 相关 14/14，root TLS identity 9/9、实际 WG netns 1/1、root FS 7/7、既有 Rust 121/121 等通过。严格编译 `--locked`/`-D warnings`。详见 [Backlog D.80](./REMEDIATION_BACKLOG.md)。
- 下一轮先核对精确 SHA 的 [GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600) 与 [MSVC #44255321332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321332) 完整终态及原始日志；失败先修不跳过。然后推进可执行服务的可信启动和信号退出、授权/状态迁移阻塞。不能将实验 localhost denial 当生产功能，main/UI/连接/WFP persistent BLOCK 不动，PR #27 Draft；Issue #5 与生产 SEC-01/02/08 仍 OPEN，旧 Python accept 风险仍存在。


## 80. 最新：PR #28 独立 Rust 隔离进程可信启动/永久降权与信号生命周期（2026-11-18）

- [Backlog D.81–D.82](./REMEDIATION_BACKLOG.md)。PR #27 HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44` Linux #44255321383 与 GNU #44255321600 Completed/Success，MSVC #44255321332 最终 portable suite 在执行。先核对完整终态并记录。
- 新 [Draft PR #28](https://github.com/weixiaochuchen618-debug/spidervpn/pull/28) HEAD `16bd83adf2f26eac783c68a413e9304313943219`，branch `fix/sec02-denial-service-process-lifecycle-20261118`。default-OFF `linux-denial-process-lab` 独立 Rust bin/test，复用锁定 libc，不动生产路径。仅普通 root 启动、精确 pin、固定隔离 /run 根目录、现有 no-follow loader；关闭非 stdio 继承 FD 后永久降 UID/GID 65534，空 groups、零 CapInh/Prm/Eff/Amb、NoNewPrivs/non-dumpable，随后只绑定本机随机端口。真实 SIGTERM/SIGINT 关闭 listener 并 drain。数字 UID、Linux 5.9+ 与16/4/3s是隔离实验选择，不是正式部署政策。
- 实际子进程测试验证普通用户拒绝、root 启动拒绝错误 pin/不安全 key/任意地址、真实 /proc 身份与 capability readback、真实 TLS1.2 否决 JSON、TERM/INT 停机及已有 idle worker 清理。等待 [Linux #44256587840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587840)、[GNU #44256587905](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587905)、[MSVC #44256588132](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256588132) 全 workflow 原始证据。新测试不 skip。若失败优先修复。
- 下一步：真实授权协议和可信历史状态的接入设计与实现，正式低权限身份/实际 VPS 切换。旧生产 Python TLS accept DoS 仍存在，SEC-01/02/08、SEC-07 未闭环，Issue #5 OPEN，所有 PR Draft。main 与 Windows UI/连接/WFP persistent BLOCK 未变，不合并、不在用户 VPS 运行 CI fixture。


## 81. 最新 PR #28 真实进程 Linux 已全绿；两 Windows workflow 尚待完成（2026-11-18）

- [Backlog D.83](./REMEDIATION_BACKLOG.md)：[Draft PR #28](https://github.com/weixiaochuchen618-debug/spidervpn/pull/28) HEAD `16bd83adf2f26eac783c68a413e9304313943219`，[Linux #44256587840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587840) 完整 Completed/Success，2/2 Jobs。原始日志新增 bin 严格 argv 1/1、真实非 root exit 2、实际 root 子进程 `real_root_startup_refuses_unsafe_identity_and_term_int_drain_after_privilege_drop ... ok` 1/1，6.33s，错误 pin/不安全密钥拒绝、永久降权内核读回、真实 TLS1.2 denial、实际 TERM/INT 有序停机均通过；原 14 HTTP、9 root TLS、WG netns、root FS 等全绿，无新增 ignore/skip，严格 Rust 编译。
- 待核对三条准确 SHA Windows workflows：父 #27 MSVC #44255321332；#28 [GNU #44256587905](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587905) 和 [MSVC #44256588132](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256588132)。当前 in_progress，不借用其他 SHA 的绿灯。
- 后续应优先推进实际授权协议与可信历史状态，明确生产专用低权限账号与部署切换阻塞，避免反复只扩展 denial lab。没有真实 VPS 证书/历史撤销/WG 授权/systemd/rollback/reboot/Windows UAC/WFP DoD；旧 Python 风险仍在，SEC-01/02/08/07 未闭环、Issue #5 OPEN，PR #28 Draft，main/UI/连接交互/WFP persistent BLOCK 不动。


## 82. 最新：PR #27/#28 三平台全绿；PR #29 真实授权协议预校验候选（2026-11-18）

- [Backlog D.84–D.85](./REMEDIATION_BACKLOG.md)：PR #27 HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`（Linux #44255321383、GNU #44255321600、MSVC #44255321332）、PR #28 HEAD `16bd83adf2f26eac783c68a413e9304313943219`（Linux #44256587840、GNU #44256587905、MSVC #44256588132）均同 SHA 完整 Completed/Success；MSVC 两轮均1432/0 failed，既有1 ignored/8 filtered。
- 新 [Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29)，HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`，branch `fix/sec01-verified-fresh-consume-gate-20261118`。default-OFF `linux-fresh-consume-gate`：真实 signed descriptor/nested invite/独立 bearer/Host/management fingerprint/TLS pin + 当前 locked durable Open；GET 真实协议准备数据，POST 验签/摘要/身份/UTC/递归 duplicate JSON/撤销状态，返回借用当前 store 的候选而非 grant。无 ledger mutation、WG 或授权签名、无实际 HTTP success endpoint。独立 RSA 测试与原请求 golden fixture，详 Backlog。
- 等待同 SHA [Linux #44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843)、[GNU #44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885)、[MSVC #44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) 最新状态和原始日志，失败先修不 skip。下一步重点不是否决 lab，而是有独立可信来源的邀请 metadata/token 持久层、可信旧 revoked/consumed 历史、锁内实际事务和签名/JWE、有限 read-only retry，确保不复活已撤销设备。旧 signed descriptor 不签 bearer，不能以旧 JSON 自证。仍无真实 VPS/Windows UAC/WFP DoD，main/UI/连接/WFP 不动，Issue #5 OPEN，SEC-01/02/08/07 未闭环。


## 83. 最新 PR #29 Linux 8/8 专项及全 workflow 通过（2026-11-18）

- [Backlog D.86](./REMEDIATION_BACKLOG.md)：[Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29) HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`；[Linux #44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843) 完整 Completed/Success，2/2 Jobs，实际 fresh_consume_gate 专项8/8，旧 parser9/9、HTTP14/14、core121/121、root/actual process/WG netns 继续通过；无新 skip，严格编译。同 SHA [GNU #44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885)、[MSVC #44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) in_progress 待核实。
- 下一 Agent：先核对 Windows 完整结果；优先设计并完成可持久校验的可信 invitation metadata/bearer provenance、历史撤销门槛、有限只读 retry 及安全成功事务/签名加密回包，而非继续扩展否决监听器。#29 只实现真实 fresh 预认证和库内 GET 数据，明确不是生产授予网络访问，不可信旧数据不得自证；SEC-01/02/08/07 OPEN、#5 OPEN，main 固定、UI/连接/WFP 不变，DoD 未完成禁止合并。


## 84. COORD-01 当前恢复入口（2026-11-19）：§23 已生效，D2失败整改仍在执行
- 固定四窗口 A=COORD-01、B=DEV-01、C=DEV-02、D=REVIEW-01；接续窗口继承原身份，不增加Agent。先读 [AGENT_COLLABORATION.md](./AGENT_COLLABORATION.md)、[TASK_ASSIGNMENTS.md](./TASK_ASSIGNMENTS.md) 最新节，再核对PR HEAD、精确CI、实际原日志及最新Issue/PR评论；旧窗口停止由用户确认、共享账号无法技术证明其停写；未知HEAD移动停写上报，不抢占/改其他分支。总控授权 [3992eba87e297eaa98ab53341775db3fbb602633](https://github.com/weixiaochuchen618-debug/spidervpn/commit/3992eba87e297eaa98ab53341775db3fbb602633)，当前全局缺陷状态见 [Backlog D.87](./REMEDIATION_BACKLOG.md)，补充提交 [e1b60b6a1dfd2826c5ea40e8a7dcc7ca57b344f4](https://github.com/weixiaochuchen618-debug/spidervpn/commit/e1b60b6a1dfd2826c5ea40e8a7dcc7ca57b344f4)。
- B目前唯一ACTIVE：COORD-D01-D2-LAB / R01-009 FAIL，#29 `fix/sec01-verified-fresh-consume-gate-20261118` HEAD `f3b92e920a52f7689f159e9599abb8c1401d8b05`。MSVC44486609014/GNU44486609016各11通过5失败，Linux44486608927 success；后续Windows全量未运行。原日志与 [D 7003940517](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-7003940517)；B按 [A 7004129376](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-7004129376) 仅原test-only范围定位真实路径不一致，维持D1严格判据、同handle证据与全部测试，完成新SHA三平台全CI和D独立复核。不允许A代写B或放宽判据。
- C生命周期隔离PASS冻结，#3 `fix/wfp-trade-egress-p0-20261116` HEAD `bde8e360f8aa1d89db130e968e1bc896bc7664ca`，MSVC44486688478/GNU44486688576 success；D独立 [7004080316](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-7004080316)，总控 [7004130171](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-7004130171) 正式冻结。仅同SID隔离实验及真实fixture取消，非生产门/跨SID/UAC/实际WFP05。C停止本阶段源码写入，不复做已冻结阶段，不开启unknown history许可。D只读审查B新SHA、不重复C。
- 共同门方案 [7003665885](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5#issuecomment-7003665885) 已核定接线清单，不再循环重设计；B隔离验收后A一次性核定生产范围及串行写锁，覆盖可信对象来源、实际写端生命周期→短Guard→BFE、退出取消不依赖外锁、独立可信bootstrap及恢复入口；008-B/D2/D3生产实现仍QUEUED，尚无集成候选。
- §14本地Agent及独立电脑/服务器资源为用户计划，非已运行。真实外部供应链材料、独立恢复域L2/L3、实际生产UAC/跨SID/WFP05/安装卸载/VPS验收仍阻塞；没有授权部署或合并，不要求用户提供密码。实机准入前按原DoD与完整集成候选确认基准、回滚与测试指令。main `857ea7593941ce79f6507db5b1ced076c3a077ba`、#3/#29 Draft、#6/#28依赖不动。当前仅总控同步全局文档，没有新增代码、CI/实机测试或安全关闭。两次HEAD复核一致，无新的D2整改提交，不重复验收旧SHA。
