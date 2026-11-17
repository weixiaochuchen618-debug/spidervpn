# SpiderVPN 新对话 / 新 Agent 交接说明（从这里开始）

> **交接快照**：2026-11-17，Asia/Singapore。  
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
