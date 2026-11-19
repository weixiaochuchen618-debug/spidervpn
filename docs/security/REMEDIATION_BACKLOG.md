# SpiderVPN 安全修复任务账本（唯一状态清单）

> 版本 v1.0 · 初始基准 2026-11-17；**最新状态看 D.87 与 [任务分配表](./TASK_ASSIGNMENTS.md) §23 及后续增量，以下早期快照保留历史，不作为当前HEAD。文档提交不是修复完成证明**。  
> **主方案**：[SECURITY_REMEDIATION_PLAN.md](./SECURITY_REMEDIATION_PLAN.md) · **交接入口**：[AGENT_HANDOFF.md](./AGENT_HANDOFF.md)。  
> [仓库](https://github.com/weixiaochuchen618-debug/spidervpn) · [PR #3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) · [既有 WFP Issue #2](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2)

## A. 版本、证据与变更边界

- **正式代码**：main = `857ea7593941ce79f6507db5b1ced076c3a077ba`。
- **当前 WFP 候选**：`fix/wfp-trade-egress-p0-20261116` HEAD = `2045acd42554b1ad1472ae41ab247b42d8df5655`，PR #3 Draft、未合并。
- **基线 CI**：该 SHA 的 [Windows MSVC](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452983) 成功；[Windows GNU](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452791) 成功。仅覆盖已写进 CI 的功能；未完成真实 TUN/Wintun 防泄漏验收。
- **审查状态口径**：`未修复`=危险代码路径在 PR3 HEAD 仍存在；`部分修复`=有保护基础但覆盖不全；`候选实现`=代码提交但未生产集成/未全部验收；`已完成`=完整 DoD 通过并附 commit/CI/真实验证证据。
- **2026-11-17 本账本创建时没有完成以下 9 项中的任何一项**；不能因为 PR #3 green 就把其勾选。
- **语言约束**：任何新增产品修复与安全决策用 Rust 实现/编译；Python 服务以兼容的 Rust Linux daemon 替换；原 PowerShell 只作为安装/卸载薄包装器及测试辅助。
- **合并约束**：不变更现有 UI 与正常连接交互；禁止将未验收的 WFP 租约直接合并到 main。

## B. 原始审查九项（SEC-01～SEC-09）

| ID | 级别 | 当前状态 | 模块与证据 | 首要下一动作 | 关闭条件（简） |
|---|---|---|---|---|---|
| **SEC-01** | **P0 / 高** | 🟠 Rust 策略核心候选（13/13 Linux 单测绿）；**生产漏洞未修复** | `assets/tc-pair.py:1195,1230-1246`; `src/deploy.rs:849-891` | Rust 邀请授权/撤销状态机 + 旧记录迁移，拒绝重放 | 撤销后原/换公钥不能复入网，地址无重叠，HTTP 与 CLI 一致 |
| **SEC-02** | **P0 / 高** | 🔴 未修复（旧版曾复现） | `assets/tc-pair.py:1453-1456`; `src/pairhost.rs:36-47` | Rust TLS daemon 并发握手 + 超时 + 低权限服务 | 一条/多条空闲连接不堵塞正常 HTTPS，服务资源可控 |
| **SEC-03** | **P0 / 高（本地威胁前提）** | 🟠 Rust ACL 候选开发中（未实机安全验收） | `package-files/install.ps1`; `src/engine.rs:163-191`; `src/isolation.rs:31-45` | Rust 安装可信边界/受保护 bin 与特权引擎路径策略 | 非管理员不可替换特权执行目标，配置篡改不能导致任意提权执行 |
| **SEC-04** | **P1 / 中** | 🟠 部分修复 | `src/secretfile.rs:91-116`; `src/main.rs:642-705` | Rust 密钥导出与敏感文件 ACL 全覆盖，区分保密/防篡改 | 导出私钥无宽 ACL、旧文件迁移、运行正常 |
| **SEC-05** | **P1 / 中** | 🔴 未修复 | `src/engine.rs:100-136`; `src/connect.rs:531-535,689-720` | Rust 引擎 HANDLE + 创建时间/路径/会话 ID 校验 | PID 复用不误杀陌生进程、不阻塞代理自愈 |
| **SEC-06** | **P1 / 中** | 🔴 未修复 | `src/uiweb_form.rs:57,705`; `src/deploy.rs:1933,3326` | Rust 单一 TCP 端口白名单 | 443/8443/2443 部署、导出、导入、恢复一致通过 |
| **SEC-07** | **P1 / 中** | 🔴 未修复 | `assets/tc-pair.py:68,352-357`; `src/pairing.rs:4556-4581` | Rust 证书到期管理/代际轮换，区分 expired 与 pin mismatch | 到期提前预警；不接受过期证书；轮换后新旧邀请有明确语义 |
| **SEC-08** | **P1 / 中低（可放大 SEC-01）** | 🟠 Linux Rust flock 锁核心已测；**生产 Python 仍未接线** | `assets/tc-pair.py:82,235-243,1286,1333` | Rust daemon 同一跨进程锁/交易日志 + 原子更新 | 多进程请求不丢状态、不复活已撤销设备、无相同 IP 双 peer |
| **SEC-09** | **P1 / 中低（Guard 失控影响高）** | 🟠 Rust 安全卸载候选已推送，待最终 CI / 实机 | `package-files/uninstall.ps1:90-101,108-133,133-141` | Rust 卸载预检查/精确清单/Guard 读回 | exit 3 不误删 exe、残留可清、相邻目录不误删 |

### 必须补的复现/回归清单

- [ ] **SEC-01** 首次授权→撤销→原申请重放不能加 peer
- [ ] **SEC-01** 首次授权→撤销→相同 RequestId 但更换 ClientPublicKey 不能加 peer
- [ ] **SEC-01** 未撤销且处于有界重试窗口的完全相同请求仍幂等，不新增第二 peer
- [ ] **SEC-02** 单空闲 TCP/慢 TLS 握手期间正常 HTTPS 仍可响应；并发连接上限有效
- [ ] **SEC-03** Windows 非管理员篡改安装 exe/DLL/管理员启动脚本/引擎配置/软链接均不能得到特权执行
- [ ] **SEC-04** 旧版与新导出的 REALITY 私钥文件在未授权账户下不可读取
- [ ] **SEC-05** 断电后 PID 被复用：不误杀别的进程，仍能恢复系统代理
- [ ] **SEC-06** 443/8443/2443 完整走通部署、身份导出/导入/恢复
- [ ] **SEC-07** 自签名证书过期返回明确错误，管理侧提前提示、轮换可恢复
- [ ] **SEC-08** 50–200 个跨进程操作 + kill -9 故障注入，状态无丢失/倒退
- [ ] **SEC-09** Guard 解除退出码 3、UAC 被拒、`-KeepGuard`、完整 bin 清理与相邻路径匹配

## C. 补充发现（不并入九项编号，不能漏掉）

| ID | 级别 | 当前状态 | 证据 | 首要下一动作 |
|---|---|---|---|---|
| **SEC-10** | **P0 / 高（本地攻击者）** | 🟠 开发中：PR #6 提权身份 + IPC 部分候选；待 CI/双账户实机 | `src/guard/elevate.rs`、`src/secretfile.rs` | 继续验证 IPC ACL/不同 UAC 账户、进程归属与真正安装权限边界；见下方恢复点 |
| **SEC-11** | **P1 / 中** | 🟠 Rust UTF-8 边界修复候选已提交；待最新 CI 与余下 panic 审查 | `src/uiweb_form.rs:6828-6834`；`src/pairing.rs:2068-2074` | 处理 UTF-8 字节下标/shape 验证；对生产 `unwrap/expect` 做有根据的回归 |
| **AUX-01** | P2 | 未完成 | `assets/tc-pair.py:303-311,692-711` | Rust 服务支持合法双栈 `Address = IPv4, IPv6` 输入，正确提取 IPv4 |
| **AUX-02** | P2 / 合规 | 未完成 | `vendor/sing-box.LICENSE.txt` | 核实发行版本许可条款，补完整文本、源码获取说明 |
| **AUX-03** | P2 / 审查覆盖 | 未完成 | `src/ipc.rs`、`uiweb*.rs`、`config.rs` 等 | 增加 fuzz、输入边界、未审部分的安全核查，不宣称已全库逐行 |

### SEC-10/11 回归清单

- [ ] `--guard-apply` 请求存储只有受信主体可修改，随机唯一目录，不接受 reparse/重放。
- [ ] 提权侧重新验证所有 ProgramIdentity 的可执行路径/WFP AppId，拒绝篡改请求；`lease_helper.rs` 也接受同样审查。
- [ ] 中文/emoji/组合字符传入 `short_time` 和 WireGuard key 校验不能 panic，仍返回符合原交互的错误。
- [ ] 生产 `expect/unwrap` 必须记录是否真实可触发，不能无依据地全部称为高危。

## D. PR #3 的 WFP 剩余任务（独立于九项）

> **重要**：这些任务不是“SEC-01～09 的附属项”。已有候选代码 ≠ 已经启用。当前实验通过环境变量 `SPIDERVPN_WFP_LEASE_EXPERIMENT=1` 打开，默认关闭。

| ID | 现有进展 | 仍未完成的核心工作 | 验收条件 |
|---|---|---|---|
| **WFP-01** 代理精确放行 / 默认阻断 | 🟠 候选：WFP v1 持久 BLOCK、局部 v2/scoped 规则及内核 canary；CI 绿 | 明确生产规则优先级、受保护端点和连接授权后撤销的一致性；原子变更 | 只允许已验证本地代理路径，未经授权不能直连 |
| **WFP-02** 长期提权 lease | 🟠 候选：`lease_helper.rs`，Ready/ACK、进程句柄监控，隔离试验入口 | 正式连接/断开时的 lease 归属、取消/超时、IPC ACL 可信性、进程关闭清理、异步失败报告；消除重复 UAC 与实验特有泄漏窗口 | 断开/拒绝/崩溃后无动态 PERMIT 遗留，不能误报已保护 |
| **WFP-03** TUN/Wintun 安全通道 | 🔴 未完成生产路径；有候选 LUID 身份和过滤器测试 | 精确接口 LUID、路由/next-hop、Wintun 生命周期、隧道断开/重拨不绕过 | 故障注入无未授权外网直连；持续 BLOCK |
| **WFP-04** 证据、同步、回滚 | 🟠 v1 持久规则与读取证据/回归测试已存在 | v2 证据 schema、同步与 provider 归属隔离、异常事务/长期进程跨会话恢复和重授权一致性 | 不破坏旧规则，不产生误报/多余规则，不删外部 provider 规则 |
| **WFP-05** 真机验收与发布闸门 | 🔴 未完成 | 两 Windows ABI + 隔离 Win11/真实 sing-box/Wintun + 多账户/崩溃/断网/端口劫持测试；最后审查 | 完整证据包、可回滚后才将 PR #3 从 Draft 改为可合并 |

### WFP 安全冻结条款

- [ ] 在 WFP-05 完成前，`SPIDERVPN_WFP_LEASE_EXPERIMENT` 保持默认关闭。
- [ ] 不修改原系统代理与 TUN 下单交互，不删除任何原有持久 BLOCK 以换取“连接成功”。
- [ ] 单独回归多次启动/退出、UAC 点否、代理端口被接管、sing-box 崩溃、主程序退出、Windows 重启、网络重连。
- [ ] 任何发布宣称必须给出真实用户配置和抓包/路由/过滤器读回的证据；“CI success”不构成零泄漏证明。

## D.1 最新恢复点（2026-11-17：SEC-10 第一阶段候选）

- **当前活动任务**：SEC-10（关联 SEC-03），代码 [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，修复分支 `fix/sec10-guard-elevation-identity-p0-20261117`，**从 main `857ea759` 分出**，没有引入 PR #3 的 WFP 实验代码。最新候选提交 `3f0ef0c5`；PR Draft。
- **新增反向验证**：带计数假 WFP 后端的专项回归，直接调用 `guard_apply_main`，确保篡改请求和未知 StoreKind 在任何 WFP 调用前返回失败；超时后父进程尝试终止失控的提权辅助进程。
- **已写入 Rust 候选**：提权后使用 Windows WFP `SystemIdentityEnv` 重新派生并比对 ProgramIdentity 路径/AppId/device path、拒绝重复或伪造身份、未知证据 StoreKind；Remove 仍不依赖已经删除的 exe。旧 `--guard-apply` 的单次 IPC 建目录改为 ring SystemRandom 128-bit 随机目录、受保护 DACL、空白受保护回执预创建、文件拒绝覆盖；请求内容 SHA-256 绑定在 UAC argv 路径并在子进程内按相同字节核验；限定固定文件名、无路径跳转和 reparse。修复读/写句柄在识别普通文件前不能越权跟随链接或提前截断文件。
- **待最新 SHA 验证**：MSVC [Run 44008388149](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44008388149)；Windows GNU [Run 44008388178](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44008388178)。**记录创建时两套均未宣称成功**，新 Agent 必须重新查询运行结果及日志（失败需要修复）。
- **仍需处理/验收**：不同用户 UAC 凭据提升时请求/回执可访问性、非管理员写入受保护 IPC 的拒绝测试、进程句柄退出和超时清理、完整权限凭据与 root/engine 可执行文件的可信边界、硬链接/TOCTOU 验证。SEC-03 安装目录可写与任意引擎 exe 提权路径尚未修复；PR #6 **不能合并 main，也不能把 SEC-10/03 标记完成**。
- **已诊断/修复的 CI 问题**：旧 SHA `b353d284` Windows GNU [Run 44002952064](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44002952064) 构建成功，14 项 `guard::elevate::tests` 中 13 通过、1 失败。`guarded_ipc_rejects_arbitrary_paths_and_reused_names` 测试在创建目录但尚未创建请求/回执文件时调用 Windows 路径检查，导致 fail-closed 的缺失文件判断返回错误；已在 `a357668d` 修复为先验证缺文件必拒、再按真实 `apply` 顺序建立受保护文件并验证通过，未放宽生产安全检查。`7f0b65af` 还修复成功 WFP 之后回执写失败却仍返回 0 的问题并增加测试；**最新 CI 仍需重新确认**。
- **GNU 新失败与修复**：`7f0b65af` 的 [GNU Run 44004013537](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44004013537) 证明 15 个 Guard 测试与 11 个身份测试通过，但 `secretfile` 的 7 项中 2 项失败：旧测试假定 `%TEMP%` 新建文件必带继承 ACE，而 GitHub runner 的临时目录本身已经被收紧。`707f6ef3` 在隔离测试目录显式 grant `Authenticated Users` 可继承 `(OI)(CI)(M)`，再次验证 Rust 收紧保密文件、保留普通 config 文件权限；**保留安全断言，没有跳过**。之前提交 `5f3a4726` 还对提权请求/回执文件的已打开 Windows 句柄检验硬链接数必须为 1，并增加对抗测试。最新 MSVC/GNU **待验证**，不能将较早成功等同于当前 SHA。
- **已完成的上一基线**：`707f6ef3` 的 [MSVC Run 44004838338](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44004838338) 与 [GNU Run 44004838372](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44004838372) 均为 Success（Rust Guard/ACL/硬链接针对性测试通过）。
- **本轮 SEC-10 / SEC-03 边界候选**：Release 编译禁止环境变量 `SPIDERVPN_ROOT` 重定向安装根或 Guard 注册表证据；提权端要求 `StoreKind` 与运行环境严格一致，不能通过低权限 JSON 指定 IsolatedFile。GNU CI 添加非测试/非 debug 的 `rustc` 模块级发布门槛探针；Windows `GetNamedSecurityInfoW` + SDDL 读回测试要求 IPC 目录、请求、回执都有受保护 DACL 与显式 SY/BA/OW，拒绝宽松 AU/BU。最新 Rust head `94affb04` CI **尚未确认通过**。
- **跨账户 UAC 验收手册**：[SEC10_WINDOWS_UAC_ACCEPTANCE.md](./SEC10_WINDOWS_UAC_ACCEPTANCE.md)，UAC-01～12；明确要求 A 标准用户、B 独立管理员、C 第二普通用户在隔离 Win11 实机/VM 复现。**当前未执行**，不可将自动化 SDDL 读回等同于 UAC 全链路通过。
- **本轮 SEC-10 真正竞态修复**：`src/secretfile.rs` 新增 Rust Win32 `CreateDirectoryW`/`CreateFileW` 自带保护 DACL 的原子创建，`src/guard/elevate.rs` 的随机 IPC 目录、req.json 与 res.json 已接入；不再先建宽权限对象再 `SetNamedSecurityInfoW`。新增“父目录为 Authenticated Users 可继承修改权限，但子 IPC 对象从创建起 DACL 即受保护、不可重复创建”的 Windows 安全回归。最新 HEAD `3f0ef0c5` MSVC/GNU CI **等待完成**。跨账户 UAC 实机测试仍缺，PR #6 保持 Draft。
- **上一提交 GNU 结果**：`94affb04` [GNU Run 44006981900](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44006981900) Success，Release 环境变量覆盖拒绝模块级验证通过；当时 [MSVC Run 44006982192](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44006982192) 的完整单测仍运行中，不可用来代替最新 SHA。
- **SEC-03 第一层引擎执行防护候选（2026-11-17）**：`d13540f8` 在 Rust `config.rs` 把 `SPIDERVPN_ENGINE_ARGS` 调试测试钩子排除出生产 Release；`52615672` 新增 `engine::validate_privileged_tun_engine()` 对同目录随包 `sing-box.exe` 做 canonical 路径与 reparse 检查、拒绝 `config.json` 指向其它可执行文件；`a81da3e1` 将校验接到生产 `main` 的管理员实际 TUN spawn 闭包，正常非提权代理模式仍能使用用户自定义引擎。已有 Rust 负向单测，**当前 SHA CI 未全部完成**。必须明确：此修复阻止“配置直接指定其它 EXE”，**不保证同目录 `sing-box.exe` 和 `spidervpn.exe` 无法被普通用户替换**；SEC-03 安全安装器、受保护安装 root/bin、原有升级/卸载兼容、可信文件签名/身份检查与真机验收仍未完成。自定义引擎在管理员 TUN 模式会被拒绝，需专项兼容验收和清晰提示。
- **最新修复 HEAD**：SEC-10/03 候选 [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6) `a81da3e1`。当前 CI： [MSVC 44009947271](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44009947271)、[GNU 44009947357](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44009947357)，尚待对应 SHA 完整验证；上一完整 GNU 通过 SHA 为 `3f0ef0c5`。
- **SEC-03 对抗复核升级（2026-11-17）**：上一轮只在管理员 TUN 核验引擎路径会被“切换 Proxy 再由管理员执行”绕过。已在 Rust `main.rs` 中改为只要 **实际拥有 HKLM 提权权限（`probe::is_elevated()`）**，不论 Proxy/TUN，都必须经 `engine::validate_privileged_engine()` 比对 exe 与 SpiderVPN 同目录 `sing-box.exe` 的 canonical 路径并拒绝 reparse；不信任可由环境变量强制的 `probe::elevated()`。普通用户代理的自定义引擎保持不变；**管理员身份下的自定义外部引擎将被拒绝**，这是明确的安全收紧，验收时应记录兼容影响。最新代码 [PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6) HEAD `7298bfc4`，对应 [MSVC 44010183604](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010183604) / [GNU 44010183550](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010183550) **尚未完成 CI**。该检查**不能**证明同目录可执行文件不可被普通用户修改；安装器 DACL、安装升级迁移与低权限攻击者改写同目录 EXE 的真机验收仍属 P0 未完成。`
- **最新候选 Head 与 CI**：PR #6 `5bbf743a`，GNU 新增 `engine::tests::privileged_engine_cannot_be_selected_from_arbitrary_config_path` 与 `config::tests::engine_command_line_is_derived_per_line_and_the_hook_overrides_it` 两项精确过滤回归。对应 [MSVC 44010494382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010494382) 与 [GNU 44010491449](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010491449) **待全部完成**。中间提交 `a5f1389e` 的 MSVC 编译失败 E0425（前端调用旧名字 `validate_privileged_tun_engine`，而引擎模块已改名），最新 `7298bfc4` 已同步修复两个文件，不得把中间 SHA 的失败误认为最新还留相同调用错误。
- **下一步单步操作**：读取 PR #6 最新 SHA 与 MSVC/GNU CI，针对失败先修 Rust；若 CI 绿，补 Windows 双账户/UAC 故障注入和拒绝路径，继续审查提权 helper 的输入信任与安装目录隔离。
- **完成统计不变**：原九项=0 已验收；SEC-10 只是候选；SEC-11 未开始；WFP-01～05 仍未完成生产实机验收。

## E. 按依赖推进的顺序（每次新 Agent 只选一个最小安全单元）

| 顺序 | 任务组合 | 下一步可直接开展的具体工作 | 是否能与其它项并行 |
|---|---|---|---|
| 0 | 基线 | 检查 main、PR #3 最新 SHA、现有测试、实机环境、旧复现、回滚脚本；建立当前工作 PR | 必须先做 |
| 1A | **SEC-03 + SEC-10** | Windows Rust 可信安装/提权 IPC 方案 + 双账户攻击回归 | 可与 1B 并行 |
| 1B | **SEC-01 + SEC-08** | Rust Linux `spidervpn-paird` 状态机/存储/撤销事务及协议金样本 | 可与 1A 并行 |
| 2 | **SEC-02 + SEC-07** | Rust 服务端 TLS 握手超时、证书治理、systemd sandbox | 依赖 1B 服务端骨架 |
| 3 | **SEC-04 + SEC-05 + SEC-09** | 数据根 ACL、进程身份核验、安全卸载；避免主连接行为变化 | 建议依赖 1A |
| 4 | **SEC-06 + SEC-11** | 端口统一、UTF-8 / panic 拒绝路径（可提前单独 PR） | 独立可并行 |
| 5 | **WFP-01～05** | 统一长期 lease 生产集成、TUN、证据、实机故障注入 | 需先解决 SEC-03/10 的特权边界 |
| 6 | AUX | 双栈、许可证、扩展审查 | 可并行，不能抢占 P0 资源 |

### 当前完成统计（本次审查截至 2026-11-17）

- 原九项：**0 已完整验收 / 1 部分修复 / 8 未修复**。
- 额外两项：**0 已完整验收 / 2 未修复**。
- WFP：有候选代码及通过的 CI，但**0 项已通过生产级故障注入与发布验收**。
- 本次仅形成计划和交接记录；未修改产品源代码，不能把文档提交算成漏洞修复。

## F. 每项任务卡统一交接格式（严禁只写“已修复”）

```text
ID: SEC-__ 或 WFP-__
状态: 未开始 / 开发中 / 待CI / 待实机 / 已验收 / 阻塞（含原因）
基准: main SHA=...; PR3 SHA=...; 当前修复分支 SHA=...
变更文件: ...
修复前复现: 用例及证据路径...
修复思路: ...（Rust 编译模块及接口）
已做: ...
未做: ...
编译/测试: MSVC=... GNU=... Linux=... 专项=...
新旧版本差异: ...
风险与回滚: ...
下一条具体操作: ...
PR/commit/CI: ...
更新时间/责任方: ...
```

## G. 更新规范

1. **先更新此任务账本，再对外宣告完成。** 每次状态变化写精确 commit 和 CI URL；旧 SHA 的通过记录不能算新 SHA 验收。
2. 任何任务只要缺实机/攻击回归，最多标注“候选实现”或“待实机”，不能打 `[x]`。
3. 审查发现新漏洞使用 `SEC-12+`，不要重排原九项编号；关联 PR #3 的问题使用 `WFP-06+`。
4. 以此文件作为唯一权威任务状态；技术方案更改附日期/理由/风险；新 Agent 的第一条提交只允许当前选中的任务及其回归测试。
5. **不要在新会话单凭过去总结“已推送”或“已修复”**：先从 GitHub 重新读 HEAD、CI、文件和未合并 PR。



## D.2 本次续接（2026-11-17：SEC-03/SEC-10 特权 IPC DACL 读回与连接回归）

- **活动 PR 不变**：[PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，分支 `fix/sec10-guard-elevation-identity-p0-20261117`，最新本轮提交 `c72ea69260bd195a192ef0fa2565b825f6a89364`（以 GitHub 实时 HEAD 为准），**Draft、不合并 main**。main 仍为 `857ea759`；WFP [PR #3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) 持续 Draft，默认关闭实验、持久 BLOCK 不变。
- **旧 MSVC 红例**：[44010494382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010494382) 的 `mode-e2e` 两项失败：Windows Runner 有管理员权限，旧测试导入系统 `PING.EXE`；而 SEC-03 管理员引擎白名单正确拒绝外部 EXE。没有禁用校验或放松安全断言。
- **真实测试夹具变更**：`8262db63` 修改 `tests/mode-e2e.rs`，在隔离测试根创建 `bin/spidervpn.exe`，并将系统 ping 复制为 `bin/sing-box.exe`，依然由真实 Rust 二进制运行 `--connect/--disconnect`。后续 [MSVC 44011375375](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44011375375) 运行到 `runtime-engine-e2e` 后又失败两项同类型夹具，说明先前 `mode-e2e` 已通过，**不是所有集成测试都通过**。`87a7cd34` 同样修正 `runtime-engine-e2e` 的隔离随包引擎，仍验证“引擎秒退”和“坏成员连接时运行时文件保留”；`c72ea692` 处理 `transport-e2e` 的正常重连场景。纯测试布局变更，不修改正式连接交互。
- **SEC-10 Rust 候选增强**：`253392e8` 在 `src/secretfile.rs` 新增 `verify_private_ipc_acl`，通过 Windows 原生 API 读取对象当前 DACL 并严格解析，只允许受保护的 SY、BA、OW 全控制 ACE，拒绝多余继承/宽权限；`a5eebd39` 让 `guard::elevate::validate_guard_ipc_paths` 在执行任何 WFP backend 前核验随机目录及 req/res 三个对象的真实 DACL；新反向测试故意通过 `icacls` 为回执加入 AU 修改权限，要求 `guard_apply_main` 返回失败，计数后端 0 次调用。这是候选边界加固，**不能替代 A/B/C 不同 Windows 账户 ACL/UAC 测试**。
- **专项 CI 保障**：`31d9e55c` 将 Guard/受保护 IPC/引擎白名单专项 Rust MSVC 测试前置在全量集成测试之前。GNU 专项仍包含 `guard::elevate::tests::`、`secretfile::tests::`。新 SHA 的完整 CI 结果尚待读取，之前 GNU Success（`5bbf743a` [44010491449](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44010491449)）**不能用于声明新候选已验证**。新运行在 GitHub Actions 的 `Rust Windows build and tests` / `SEC-10 Windows GNU Rust privilege-boundary validation` 下，以 workflow run 的 `head_sha` 匹配最终提交。
- **仍然阻塞 P0 完成**：受保护安装 `C:\SpiderVPN\bin`、旧安装升级/卸载迁移、标准账户 A / 独立管理员 B / 第二普通账户 C 的 UAC-01～12 [真实验收](./SEC10_WINDOWS_UAC_ACCEPTANCE.md)、不同账户可执行文件替换与 DLL/脚本劫持测试。未通过前 SEC-03/SEC-10 状态保持 **P0 开发中 / 未完整安全验收**，不得勾选 Issue #5 或合并 main。
- **下一操作**：查询最新 PR #6 HEAD 的 Windows MSVC/GNU 运行结果；失败读取 job 日志并继续修 Rust 或保持原断言修正隔离夹具；待 CI 全绿再做受保护安装根安全实现与实机 A/B/C 验收。保持 WFP v1 持久 BLOCK、UI 和生产连接流程原样。


## D.3 SEC-10 实际 SDDL 根因、专项成功证据（2026-11-17）

- **最终候选 Rust SHA**：`0690cba5774c715255fb7c4fe55c92a2728b30d5`（仍在 [Draft PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，不是 main）。
- **正常 ACL 被误拒的真实根因**：MSVC [44012356666](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012356666) 的受保护目录/请求/回执 DACL 现场读回为 `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)`，但 Win32 SDDL API 返回的 UTF-16 长度还含三个末尾 `NUL`。旧严格解析器把这些尾零误认作“额外控制标记”；确诊来自专门打印原始 SDDL 的失败日志，**不能跳过这两条正常路径单测**。
- **最终修正**：`0690cba5` 在 `src/secretfile.rs` 仅使用 `trim_end_matches('\0')` 去掉 SDDL 返回值的末尾终止符；不删除字符串内部非法字符，不放宽受保护 `D:P` 或 ACE 的 SY/BA/OW 精确授权白名单。负向 ACL 降级测试仍必须以 `backend calls = 0` 拒绝。
- **Windows GNU 当前 SHA Success**：[44012868496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868496)，head_sha `0690cba5...`：通过 `build.ps1` GNU 构建、Release 根目录覆写保护、Guard elevate/identity、私钥 IPC ACL、WFP 布局、引擎身份等 Rust 专项回归。
- **Windows MSVC 当前 SHA**：[44012868490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868490)：已显示 `cargo build --locked`、SEC-10 专项、全部 Rust 集成测试目标、相关模块回归步骤 Success；`Portable Rust unit suite` 在本条记录写入时仍未给出最终结论。原工作流保留 **8 条已有的环境依赖单测排除项**，此次没有增加 `--skip`，不能把该便携单元套件称为无排除的“全量”。GNU 专项里的 `secretfile::tests::` 真实执行，不被 MSVC 便携套件的排除项代替。
- **安全验收状态仍然不变**：SEC-03 / SEC-10 **P0 OPEN / 候选未完结**。真实多账户 UAC/独立管理员、普通账户改写安装 bin 与引擎、DLL/脚本劫持、安装/升级/卸载迁移、Windows WFP 持久阻断实机验证缺失；CI 成功并不等于这类安全验收。保持 UI、连接交互、WFP v1 持久 BLOCK 不变，PR #6 与 PR #3 均不合并。


## D.4 SEC-03 Rust 可信安装 ACL（2026-11-17，本轮进行中）

- **活动候选**：[PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，修复分支 fix/sec10-guard-elevation-identity-p0-20261117；当前 Rust 代码提交截止 54f0933386fdb531a7285def24c551552debf18c。main 仍不合并。最先复核上一候选 0690cba5 的 [MSVC 44012868490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868490) 和 [GNU 44012868496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44012868496) 已 **Success**；MSVC 仍保留既有 8 项环境依赖测试排除，不等于无排除全量通过。
- **高风险缺口**：旧安装器默认 C:\SpiderVPN 及其 bin 仍有普通用户写入风险，“管理员只执行同目录 sing-box.exe”不足以阻断替换攻击。一次安装时 SHA256 比对也不能阻断之后替换。
- **Rust 安全候选**：src/install_trust.rs 新增原生 Win32 ACL 保护（创建时 SECURITY_ATTRIBUTES、既有路径 SetNamedSecurityInfoW、立即 GetNamedSecurityInfoW / SDDL 读回）。保护 root、bin、exe、sing-box、WebView2Loader.dll、管理员启动脚本及卸载脚本；仅 Administrators/SYSTEM 全控制，Users/Owner Rights 仅 RX；新建 data 独立赋予 Authenticated Users 修改权限，既有 data 不改写；拒绝 reparse、路径跳转和 bin 中未知 DLL/文件。正式 Release 的 --install-seal 拒绝 C:\SpiderVPN 之外的自定义安装根，防止变成通用管理员 ACL 修改工具。**不证明恶意包签名/来源，或所有 TOCTOU 已封闭**。
- **安装器仅作薄入口**：package-files/install.ps1 在复制前调用可信包里的 Rust --install-seal，复制后从目标 exe 再运行一次进行权限重验；任何失败返回错误且不能打印“安装成功”。**安装现在需要提升权限**，这是本地安全信任边界变更，须有实机兼容验收，不能将普通用户无感安装描述为保持不变。正式 Release 的自定义 -TargetDir 不再被安全密封功能接受；如果确需自定义目录，应另设计安全可信路径与数据分离，而不是绕开 Rust 校验。
- **专项回归**：install_trust::tests::（新装、旧宽 ACL 收紧、未知 DLL 拒绝、拒绝卷根/相对路径）与 tests/install-seal-e2e.rs（真实 CLI 管理员门槛、数据写入、危险目标拒绝）；Windows MSVC / GNU 工作流已加 install_trust::tests:: 专项过滤，不能跳过失败测试。候选 SHA 54f09333 的 [MSVC 44017844701](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44017844701) / [GNU 44017844745](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44017844745) 截至写入时仍在执行，**不得宣称当前候选已编译成功**。
- **新增实机验收矩阵**：[SEC03_INSTALL_ACL_ACCEPTANCE.md](./SEC03_INSTALL_ACL_ACCEPTANCE.md) I01–I12，严格分为 A 标准用户 / B 独立管理员 / C 第二标准用户，需要记录真实写入和改 ACL 的拒绝、升级/回滚、完整用户配置可写及 WFP 持久 BLOCK 不变。SEC-03 与 SEC-10 仍 **P0 OPEN / 未完成真实安全验收**；PR #6、PR #3 都保持 Draft。安装来源验证、现有路径竞争、WFP 真机认证与 SEC-09 卸载安全待继续。


## D.5 SEC-03 ACL 兼容性、硬链接及旧数据升级补充（2026-11-17）

- **活动代码 SHA**：a14016cd4a921b2e8639de22ab9f70add9d62a17，仍在 Draft PR #6 / main 未变。前一份 D.4 是提交当时快照；以此条作为最新恢复点。
- **真实 CI 红例与根因**：旧 SHA 54f09333 的 [MSVC 44017844701](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44017844701) 中 Rust 安装 ACL 的 4 个专项测试有 2 个失败，两个都是正常权限生成的 D:PAI（Windows AUTO_INHERITED + PROTECTED）被旧 D:P 精确对照误拒。提交 c4b9618b 仅允许 D:PAI 与 D:P 的控制位差异，所有 ACE 仍按原字节匹配；明确新增额外 AU/WD/Owner ACE 被拒测试，没有跳过/删减红例。候选中的 CI 正在重新跑。
- **硬链接防护**：提交 d4bf342a 增加 Rust FILE_INFORMATION_BY_HANDLE 真实硬链接计数核验，已存在的 bin/sing-box.exe 或其它代码文件如有外部硬链接就拒绝安装（防覆盖到目录外/通过别名改写）；用真实 NTFS std::fs::hard_link 负向测试，保留外部目标字节不变。
- **旧数据写入回归**：提交 a14016cd 将现有 data 目录也单独设置明确的 Authenticated Users Modify ACL，保留内部现有 config 与私钥文件内容，防止只改 root 的继承策略让旧 data 变为只读。新增旧版 config 逐字节保留且可以继续编辑测试。此处改变 data 目录本身 DACL，但不修改用户配置内容；私钥子文件独立保护由 secretfile.rs 管理，SEC-04 全覆盖仍未验收。
- **新候选 CI**：[MSVC 44018620435](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620435) / [GNU 44018620441](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620441)，以 head_sha = a14016cd 完全一致且 workflow completed/success 为门槛，写入时尚未得到完整结果。不得使用早先被取消的 GNU run 或历史绿色 SHA 宣称成功。
- **剩余阻塞**：A/B/C 账户 I01–I12，实际文件覆盖/变更 Owner/更换 UAC 管理员/安装包来源验证、既有文件句柄竞争、失败回滚及 SEC-09 安全卸载；因此 SEC-03 状态只是 **P0 部分候选，未达到安全 DoD**，PR #6 不合并 main。


## D.6 SEC-03 双编译最新验收（2026-11-17）

- **最新代码 HEAD**：a14016cd4a921b2e8639de22ab9f70add9d62a17；PR #6 仍 Draft，main 857ea759 未动。最终候选包含 D:PAI Win32 SDDL 表示修正、硬链接数量检查、已有 data 目录单独保护以及旧 config 内容保留回归。
- **Windows GNU [44018620441](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620441)**：head_sha 与此提交一致、**Completed / Success**。包括 build.ps1 GNU 编译、Release SPIDERVPN_ROOT 不可信环境覆盖拒绝和 Rust install_trust / Guard IPC / identity / WFP 等专项过滤。
- **Windows MSVC [44018620435](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44018620435)**：head_sha = a14016cd；**Completed / Success**，Rust Build、SEC-10+SEC-03 专项、全部独立 tests/*.rs 集成目标、相关模块回归、便携 Rust 单元 suite 各步骤均 Success。便携 suite 保留原有的 8 条环境依赖排除，**本轮未添加任何 skip**；不得据此宣称“无排除、跨账户真实 Windows 测试全通过”。
- **本轮确定保留的失败证据**：54f09333 的 MSVC 44017844701 2/4 因 D:PAI 控制标记误拒，修复后在当前 SHA 的 SEC-03 专项已通过；未删除测试、未放宽额外 AU/WD/OW ACE。
- **仍未完成**：Win11 A/B/C 三账户 I01–I12、真实安装/升级/卸载/回滚、源包签名与信任、现有文件句柄竞争、普通用户拥有旧目录的 Owner Rights 实际测试、WFP 持久 BLOCK 实机不退化。SEC-03/SEC-10 仍 P0 未完成安全验收，PR #6 与 PR #3 不合并到 main。


## D.7 SEC-09 Rust 卸载 fail-closed 候选（2026-11-17）

- **任务选择**：SEC-09（P1），依赖之前 SEC-03 受保护 bin 安装根。活动 Rust 分支 fix/sec10-guard-elevation-identity-p0-20261117 / [Draft PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)，从 main 857ea759 分出、**尚未合并**。本轮最新候选提交 15079f9184de6bffa8beb66546cc3996c528c6c9；后续 Agent 先核对 GitHub 实时 SHA。
- **真实风险**：旧 package-files/uninstall.ps1 在 guard-remove exit 3（配置缺失、无法断言持久 BLOCK 已解除）仍继续删除 EXE；只删除 spidervpn.exe/WebView2Loader.dll，留下 sing-box.exe；PointsHere 采用 Contains(TargetDir) 可能把 C:\SpiderVPN2 当作本安装并递归删整个开始菜单目录。
- **Rust 代码候选**：src/uninstall_safety.rs 新增 --uninstall-preflight <TargetDir> [--keep-guard]，管理员身份、真实运行 exe 安装路径、reparse/卷根验证、proxy-journal.json 必须已消失（无 FORCE 绕过）；默认直接调用现有 WindowsWfp::remove() 事务**只解除本程序 Provider 所属对象，不以 config.json 是否存在推断**，并要求 BFE ready、Provider 和 SubLayer 均不存在、无 read_error；写 HKLM Removed 标记、invalidate 旧 Evidence，读回确认。任何步骤失败返回非零且 PowerShell **不删除任何 EXE/入口**。显式 --keep-guard 不触碰 WFP，但仍检查代理 journal。
- **精确归属和残留**：--uninstall-owns-shortcut <path> <TargetDir> 只按安装器实际产生的完整 .cmd 模板判断，取消旧 Contains(TargetDir)；PowerShell 只删被 Rust 认定属于本次安装的快捷方式，不递归删除含其他文件的开始菜单目录。固定 bin 清单补 sing-box.exe 及 sing-box.LICENSE.txt，未知文件/data 默认保留，删除操作仍由薄 PowerShell 入口实施。
- **专项测试**：Rust uninstall_safety::tests::（无配置、WFP 失败/回读残留、KeepGuard/journal、模板严格比较、manifest）+ tests/uninstall-preflight-e2e.rs（真实 Rust CLI 拒绝错根/缺参，不碰 WFP + 旧脚本静态契约），Windows MSVC/GNU 专项已接入；MSVC CI 新增仅解析而不执行 PowerShell 脚本语法的步骤，旧八项环境依赖排除未变。为了减少多次开发提交造成 CI runner 堆积，MSVC 流水线现在与 GNU 一样取消较早 SHA 的并发跑次，**不取消最新 SHA 的测试**。
- **CI 待终态**：本轮 SHA 15079f91 的 [MSVC 44025960134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44025960134) / [GNU 44025961008](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44025961008) 写入时仍在运行。不能宣称最终 SHA 通过；失败必须读 job logs 修复，不新增 skip 或弱化安全判断。
- **安全边界未闭环**：需要 [SEC09_UNINSTALL_ACCEPTANCE.md](./SEC09_UNINSTALL_ACCEPTANCE.md) U01–U14 的隔离 Windows A/B/C 卸载/重复安装/旧 owner/UAC/WFP 过滤器现场和异常退出试验。单一 CI admin Runner 不能替代实机；普通用户双击卸载入口在 SEC-03 管理员安装后可能要求明确管理员提权，**不得宣称 UX 完全不变**。WFP remove 与脚本删除之间仍有潜在竞态；-KeepGuard 则明确选择保留阻断规则及相应恢复风险。
- **状态**：SEC-09 P1 部分候选、未完成实机 DoD；SEC-03/SEC-10 P0 仍开放，PR #3/#6 Draft，main 不变。


## D.8 SEC-09 失效分支补测与最新 Rust HEAD（2026-11-17）

- **新修复**：安全卸载预检查原本使用 Path::exists() 判断 proxy-journal.json，Windows 上访问拒绝/读取元数据失败有可能被当作“不存在”。提交 78a25ac0 改为 std::fs::symlink_metadata() 明确区分 NotFound（可继续）与 PermissionDenied/其它 I/O 错误（fail closed），并严格处理路径各段元数据读取失败，添加带符号链接/硬链接的代理恢复记录负测试。
- **新负例**：提交 4a063de4 进一步模拟 WFP 事务已经成功删除 Provider，但 HKLM Removed 标记存储失败；Rust preflight 必须返回错误，不能让 PowerShell 删除最后一个可修复的 EXE。此测试使用隔离文件证据 Store/假 WFP backend，无需实机调用 WFP。
- **最新候选 SHA**：4a063de4fbb49debd7c8f04d6072ba99be3c9326；与此前 D.7 的 15079f91 比多了上面两组 fail-closed 检查。正式 CI 请核对 head_sha 一致：[MSVC 44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209)、[GNU 44026418218](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418218)，写入时仍在执行。多个此前较早 SHA 的 CI 因仅保留最新 PR 验证而取消，它们不能算失败也不能算通过。
- **安全验收状态不变**：I01–I14 Windows 实机未执行，SEC-09 仍为橙色候选、不是“已验证安全卸载”；SEC-03/SEC-10 P0 仍未实机过关。main 不合并，PR #3/#6 Draft。


## D.9 SEC-09 最新双 CI 自动回归结果（2026-11-17）

- **代码 HEAD**：4a063de4fbb49debd7c8f04d6072ba99be3c9326；main 与 PR #3 未动，PR #6 仍 Draft，SEC-09 仍为部分候选。
- **Windows GNU [44026418218](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418218)**：核对 head_sha 匹配，**Completed/Success**，包括 Rust GNU 编译、发布安装根拒绝环境覆盖、Rust uninstall_safety / Guard IPC / WFP identity 专项。
- **Windows MSVC [44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209)**：核对 head_sha 匹配，Rust 构建、PowerShell 卸载脚本语法解析、SEC-09/10 安全专项、所有 Rust 集成目标、模块回归已经分别 **Success**；便携单元 suite 后续也已成功，整个 **MSVC workflow Completed / Success**（GitHub 2026-11-17 05:59 UTC）；便携 suite 保留原先 8 项环境依赖排除，本轮没有新增跳过。
- **不等于实机验收**：所有 WFP 删除/异常注入测试采用 fake backend，不曾在 CI Runner 上真的删除持久 WFP。Windows A/B/C 权限与 I01–I12、U01–U14、UAC-01～12、TUN 断线与真实交易程序网络仍未验收；不合并 main。

## D.10 SEC-11 UTF-8 输入边界与 SEC-09 卸载清单防漂移（2026-11-17）

- **上轮闭环复核**：PR #6 旧 SHA 4a063de4 对应 [MSVC 44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209) 与 [GNU 44026418218](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418218) 均最终 **Completed/Success**（MSVC 仍沿用 8 项环境依赖测试排除），不能替代真实安全验收。
- **SEC-11 已证实的崩溃边界**：src/uiweb_form.rs::short_time 原仅检查 byte[10] 为 T、len≥16，再用 [5..10]/[11..16] 截取；当索引 5 落入 CJK/emoji 字节内部时会 panic。提交 d90df394 先用 str::get(..16) 安全判断边界，再验证 ASCII 数字与日期定界符；异常值保持原文本，不 panic；合法时间列表外观不变。包含 index 5 非字符边界且 index 10 为 T 的回归反例。
- **SEC-11 WireGuard key 形状防回归**：提交 ac282e43 将 pairing::tunnel::wireguard_key 改为原始字节 ASCII + 44 字节 + 结尾 = 检查，拒绝非法 Unicode 与填充。注意：旧实现 len()==44、ends_with('=') 本身会保证切片位置 43 为字符边界，不能虚报该旧实现已经复现 panic；本项是健壮性加固和防回归。
- **SEC-09 清单归一**：install_trust.rs::BIN_FILES 为唯一 Rust 包文件白名单，uninstall_safety.rs 直接复用；Rust 新测试解析 package-files/uninstall.ps1 固定删除清单，确保没有缺项/重复，并确认主程序 spidervpn.exe 位于最后，uninstall.ps1 留到其余文件成功移除后才清理。提交 b839dace、0d3bbc69、f9d7dbbc。未改 UI、连接或 WFP 持久 BLOCK 实现。
- **最新同 SHA CI 未决**：Windows MSVC/GNU 都显式运行 SEC-11 UTF-8 和密钥形状测试，最新 Rust 代码 HEAD d4f7feb8b5aed21759704b318121e2bfd8972934；[MSVC 44030514834](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514834) 与 [GNU 44030514840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514840) 写入时未获得终态；必须核对最终 head_sha/结论，不得援引旧 SHA。
- **未完成**：SEC-11 生产 unwrap/expect 逐项可触发性审查、更多 Unicode/fuzz；SEC-09/03/10 的 A/B/C 真机权限、安装/升级/卸载、WFP 持久 BLOCK 网络验证和包来源签名均没有完整证据。SEC-09/11 仍部分候选，PR #6 Draft 不合并 main，Issue #5 保持 Open。

## D.11 SEC-11 专项红例与修正（2026-11-17）

- 初版候选 d4f7feb8 的 [MSVC CI 44030514834](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514834) / [GNU CI 44030514840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44030514840) **Completed/Failure**：生产 Rust build 已成功，但 test-bin 编译 E0425 七次，因为 WireGuard key 测试被错误插进 pairing::line::tests 里，无法解析私有 pairing::tunnel::wireguard_key。**这是本轮测试放错作用域，不是一个新增产品漏洞，也不能将旧 SHA 视为 CI 绿。**
- 提交 ce3c00fe 将原断言原样移至 pairing::tunnel::sec11_key_tests；提交 e32c7567/c658c122 同步 MSVC/GNU 两工作流的精确过滤名，不删、不 skip 测试。此前中间候选因仅保留最新 SHA 自动取消，不能计入成功/失败。
- **当前最新 Rust HEAD**：c658c12249568ccbfe02c13a436cdaa27ffe5776；对应 [MSVC CI 44031103332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103332) / [GNU CI 44031103722](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103722) 写入时仍在运行。最新 SHA 双 CI 必须 Completed/Success 才能把本轮自动化验证标为完成。
- 手工 Windows A/B/C 实机 SEC-03/09/10、WFP 真机网络、SEC-11 生产 unwrap/expect 审计和 Linux P0 SEC-01/02 仍待处理；main 不动、PR #6 保持 Draft、Issue #5 Open。

## D.12 SEC-11 测试作用域重跑后自动化验收（2026-11-17）

- 当前代码 PR #6 HEAD c658c12249568ccbfe02c13a436cdaa27ffe5776。此前 E0425 测试作用域失败已由 ce3c00fe + 两工作流过滤器更新修复；原 Unicode/emoji 断言没有减少。
- [Windows GNU 44031103722](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103722) 已核对 head_sha 一致，**Completed/Success**：Rust GNU 构建、release 安装根保护、Guard/卸载/SEC11 专项全部成功。
- [Windows MSVC 44031103332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44031103332) 已成功完成 Rust Build、PowerShell 脚本语法、SEC09/10/11 专项、全部独立 Rust integration 目标，正在运行模块回归/便携 unit suite；截至写入时 workflow 未终态，**不得提前宣称 MSVC 全绿**。旧 MSVC 原有 8 项环境依赖排除仍保留、无新增 skip。
- 严禁把 d4f7feb8 的红例删除/改写为成功。SEC-09/11 仅候选、实机 WFP/Windows A/B/C 与生产 unwrap/expect 审查仍未完成，PR6 Draft 不合并 main。

## D.13 SEC-01/SEC-08 Linux Rust 迁移核心第一阶段（2026-11-17）

- **真实根因**：assets/tc-pair.py::authorize_invite(Consumed) 只比 RequestId/JwkDigest 后仍调用 attach_client，缺失原 ClientPublicKey、DeviceId、RequestDigest 一致性与现存 peer 验证；管理端 src/deploy.rs::revoke_script 仅删除 WG 公钥，不给 invites.json 写 Revoked 墓碑。旧邀请可通过申请重放再次写回已被撤销的 WG peer；CONSUME_LOCK 为单 Python 进程锁，不覆盖 SSH/多 HTTP 进程。
- **仅 Rust 候选，未替代 Python**：新增 server-rs/src/lib.rs 的纯 Rust Open→Pending→Consumed→Revoking→Revoked/Cancelled 状态机，要求重新签名验真后才可调用策略、live WG key+IP 严格匹配后才允许幂等只读重试、撤销前先持久拒绝、后验 WG absence；同邀请换公钥/DeviceId/RequestDigest 拒绝，跨邀请复用已撤销 DeviceId 或原 key 拒绝，未知 live inventory 失败，租约/待撤销 IP 不重复分配。新增 server-rs/src/lock.rs Linux x86_64 基于 flock 的文件锁，受保护 UID/0600/0700、超时、符号链接及硬链接拒绝；独立子进程验证锁。
- **CI 证据**：[Linux Rust authority 44033771424](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771424) 的 head_sha=8e4a2356f93dd456158e30881ab114c96699e238，**Completed/Success，13 passed/0 failed/0 ignored**。工作流 `security-pairing-rust-linux.yml` 使用 rustc 编译 rlib 和 Rust 测试，不执行或更改 Python 接收服务。源文件由 Rust 编译，不引入新 Python 逻辑。
- **同一 SHA Windows 旧客户端兼容 CI**：当前 [MSVC 44033771576](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771576) / [GNU 44033771443](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771443) 写入时还在运行；它们是客户端 ABI 回归，不能替代 Linux 真实 WireGuard/TLS 运行。
- **明确未完成、不能宣称 SEC-01 修复**：当前 src/pairhost.rs 的 systemd ExecStart 仍 `/usr/bin/python3 -I .../tc-pair.py serve`；Rust authority 还没有密码学验签/JWE、生产 JSON schema 与 fsync 事务、旧 invites.json 持久迁移、WG config/wg syncconf 真实操作、Linux TLS、权限分离、恢复流程、Windows 管理端撤销入口接线。所有对在线攻击者的生产风险仍未正式关闭。详细步骤与 S01–S06 见 [SEC01_LINUX_RUST_MIGRATION.md](./SEC01_LINUX_RUST_MIGRATION.md)。
- **下一步**：采用独立 Linux Rust server Cargo 包，先建旧 records 迁移/严格 schema、跨进程原子 Ledger（必须锁住整个 WG transaction），再做 Rust TLS 与真机虚拟化验收。若采用另一个实现策略仍须保证老邀请消费路径不可再 attach 已撤销的 peer。SEC-01 P0、SEC-02 P0、SEC-08 P1 仍 open，PR #6/#3 Draft、main 不动。

## D.14 SEC-01 独立 Linux Rust Cargo + 旧邀请只读审计（2026-11-17）

- **代码 HEAD**：3d01dda610d33f38cb5f7aa7e95479ecf97b9ac4，活动分支 fix/sec10-guard-elevation-identity-p0-20261117 / Draft PR #6。新增独立 server-rs/Cargo.toml 与锁定的 server-rs/Cargo.lock（原仓库已经使用的 serde 1.0.229、serde_json 1.0.154 及同版本依赖），不修改桌面客户端的 Cargo.toml/原版 WFP/连接逻辑。
- **Rust 旧记录审计**：server-rs/src/legacy.rs::audit_legacy_json 只在内存解析 SchemaVersion=1、Invites 对象且限制输入 4MiB / 4096 邀请。`Consumed` 旧记录本来**没有保存 RequestDigest**，所以即使有 RequestId/JwkDigest/Signature，也不能自动移入可信 Consumed；回报 MissingRequestDigest、NeedsSignatureVerification、NeedsLiveWireGuardReadback，绝不合成或接受未经验证的摘要。无效 ID/公钥/网段、未知 State、已 Cancelled/Expired、秘密 Token 不写入报告，均有专门测试。
- **最新 Linux CI**：[security-pairing-rust-linux #44034700193](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700193) head_sha=3d01dda6，**Completed/Success，19 tests passed、0 failed、0 ignored**，Cargo --locked + RUSTFLAGS -D warnings。包含 SEC01/08 原核心 13 + Legacy audit 6。工作流验证运行时仍使用 Python，**这是预迁移安全基础，不是生产修复**。
- **暂存过渡故障记录**：新增 serde JSON 源码后、旧工作流仍使用原生 rustc 未加依赖时 CI 红（过渡 SHA），现按单独 Cargo 包和锁定依赖修复，并保留所有测试；不得把过渡红例算成漏洞加剧或伪造 green。
- **最新 Windows 同 SHA 回归**：[MSVC 44034700266](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700266) / [GNU 44034700188](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700188) 写入时在运行。即便双绿也仅证明现有客户端不受影响；不能覆盖 Linux WG/TLS 真机。
- **后续 P0 核心**：实现受保护 Linux 持久 JSON 原子落盘+真实旧记录迁移/墓碑迁移（不可静默重置权限），RSA-3072 / RS256 / RSA-OAEP-256 / A256CBC-HS512 协议兼容 Rust 接口；实现 WG 本机状态只读/事务增删+回读；迁移 18443 TLS Rust daemon 和非特权服务/限时限并发（SEC-02），Windows 撤销 CLI 接入 Rust Revoking→Revoked。详见 SEC01_LINUX_RUST_MIGRATION.md S01–S06。
- **状态冻结**：SEC-01 P0/SEC-08 P1 均部分候选（生产缺陷仍存在），SEC-02 P0 未修复，SEC-03/09/10 Windows 实机仍未验收，main 不合并，PR #3/#6 Draft，Issue #5 保持 Open。

## D.15 SEC-01 Rust Cargo 最新跨平台回归（2026-11-17）

- **最新 Rust 候选 HEAD**：3d01dda610d33f38cb5f7aa7e95479ecf97b9ac4。Linux [#44034700193](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700193) **Completed/Success，19/19 Rust tests 0 skipped**。
- **Windows GNU [#44034700188](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700188)**：head_sha 匹配、**Completed/Success**，包括原 Rust build.ps1、release SPIDERVPN_ROOT 隔离和原 SEC-09/10/11 专项；独立 Linux 代码暂未进入 Windows 客户端进程。
- **Windows MSVC [#44034700266](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700266)**：同 HEAD 的 Rust 编译、SEC-09/10/11 安全专项、全部独立 Rust integration 测试已 Success，记录时模块回归/Portable unit suite 未全部完成，**不得提前声明整个 MSVC Workflow Success**。保留原先 8 项环境依赖排除，未新增 skip。下一 Agent 请先核对 CI 终态并补记。
- **安全状态**：这些自动回归都不代表旧 Python pairing receiver 已换 Rust 或真实 WG/TLS/设备撤销安全验收；SEC-01/02/08 生产条件未满足，SEC-03/09/10 Windows A/B/C 实机也未完成。PR #3/#6 Draft、main 857ea759 未合并、Issue #5 Open。

## D.16 SEC-01 Rust 持久授权事务与故障后禁止旧内存重放（2026-11-17）

- **代码分支 HEAD** `07dc06f83d3f14361f822f4a519203eddc96c987`、Draft PR #6；client/main 未改，PR #3 WFP 实验未改。
- **新 Rust 服务端组件**：`server-rs/src/ledger_disk.rs`（只从已有受保护磁盘账本开启，缺失/异常不默认空；限定 0700 目录/0600 账本、单硬链接、拒绝软链接、严格版本 generation/状态/DeviceId/Key/IP/tombstone 约束；create_new 临时文件→数据 fsync→原子 rename→父目录 fsync）和 `server-rs/src/transaction.rs`（Rust fake PeerControl 的可替换编排）。前者 7 项，后者 5 项回归，均未与 Python/真实 WG/Windows 原连接代码接线。
- **事务安全不变式**：在外部 WireGuard add/remove 前**已经写盘并 fsync** Pending/Revoking；新鲜 WG readback 成功后才落 Consumed/Revoked；失败永久保留阻断状态待人工/可信恢复，用户重复点击或断网不能直接再调用 add。`retry_read_only` 不允许重附 peer。跨进程 flock 必须覆盖全部步骤，不能只在 JSON 保存时锁。
- **发现并修复的故障窗口**：rename 成功但父目录 fsync 失败，磁盘有可能是新 Pending，内存依然是旧 Open。最新 LedgerStore 在任何存储提交错误后变成 `Poisoned`，同一 store 的 view/generation/update 全部返回错误，必须关闭并重新读取/检验磁盘状态，阻止旧内存状态覆盖已落盘的撤销记录。cfg(test) 注入 post-rename 故障并证明了 fail closed；未加入生产可开关后门。
- **最新 Linux Rust CI**：[44036991021](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991021) 与 HEAD 07dc06f8 匹配，Completed/Success，**32 passed/0 failed/0 ignored**（旧安全测试 19 + ledger/txn/poison 13）。版本演化证据：[26 测试 #44036202223](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036202223)、[31 测试 #44036699347](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036699347)，仅最终 32 项用于当前 HEAD。
- **Windows 同 SHA**：[MSVC #44036991126](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991126) 与 [GNU #44036991031](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991031) 写入时仍未得到最终双结论，需以后续实际 workflow head_sha + completed/success 更新。
- **未修复生产风险**：在线服务仍为 Python `tc-pair.py serve`，Windows revoke_script 仍直接删 WG Peer，无 Rust/TLS/真正 WireGuard 系统进程；旧邀请可信迁移、JWS/JWE 验签、反回滚外部锚定、非特权服务、真实 Linux kill -9/断电/WG 操作和 Windows A/B/C 验收均未完成。SEC-01/02/08 仍为仅 Rust 候选、不得标完成；PR #6 Draft，不合并 main，Issue #5 Open。

## D.17 SEC-01 Rust WireGuard 只读安全快照（2026-11-17）

- **代码 HEAD** `e4ec09e46631139d0900a9c4872770f92958b175` / Draft PR #6；新增 `server-rs/src/wg_readonly.rs`，只读固定 `/usr/bin/wg show <经验证接口> allowed-ips`，Rust 直启无 shell。拒绝恶意接口名/特殊选择器、危险二进制 owner/mode/symlink、超时（3s）、非零退出、输出超长（512KiB）；彻底不使用 `wg dump`（因为 `dump` 第一行含接口私钥）。
- **解析合同**：全部 peer 必须具有有效 WG 公钥、且只有单一 RFC1918 IPv4/32；不完整/多 CIDR/IPv6/重复公钥或 IP/损坏 UTF-8/不规范地址/错误末行/超 4096 行一律返回错误，不允许忽略坏行导致错误认为 peer 不存在。CI 不触碰真实 WireGuard，仅用本地 Rust 假输出及非特权进程验证 timeout、exit code。
- **Linux 结果**：[CI #44038827553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827553) head_sha=e4ec09e4，**Completed/Success，39 passed/0 failed/0 ignored**，新增加 7 条 WG 输入和执行约束测试。上次 SHA `07dc06f8` 的 [MSVC #44036991126](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991126) 和 [GNU #44036991031](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991031) 均最终 Completed/Success（另含 Linux 32 绿），但不作为当前 SHA 的凭据。最新同 SHA [MSVC #44038827565](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827565) / [GNU #44038827585](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827585) 写入时仍在运行，需按实际 HEAD 核对。
- **实现的严格边界**：新 Rust live snapshot reader 未接 `PeerControl::add/remove`，不验证服务器持久 `wg.conf`，不能保证与磁盘 config 一致、不能处理任意 IPv6 或多个 AllowedIPs。它只是 **SEC-01 的只读适配器候选**，Python `tc-pair.py` 仍在生产路径执行，Windows revoke_script 仍未迁移。SEC-01/02/08 均不关闭；后续处理 `wg.conf` 只读核对、Rust 安全事务执行和真实 Linux VM/网络命名空间端到端。
- **状态不变**：Issue #5 Open，PR #3/#6 Draft，main `857ea759` 未改；Windows SEC-03/09/10 A/B/C 实机和真实 WFP 仍未验收。详细方案 [SEC01_LINUX_RUST_MIGRATION.md 第四阶段](./SEC01_LINUX_RUST_MIGRATION.md)。

## D.18 SEC-01 WireGuard 持久配置双核对与三份只读快照（2026-11-17）

- 活动 Draft PR #6 代码 HEAD `714674bf827d84c62e24bcbd627ad980e90ead67`。在 `server-rs/src/wg_readonly.rs`（只读 live stdout）基础上新增 `server-rs/src/wg_conf_audit.rs`（只读磁盘 wg-quick config），从固定 `/etc/wireguard/<iface>.conf` 读配置并要求 root 0700/0600、单链接普通文件、O_NOFOLLOW，限制大小、检查 inode/dev/mtime/ctime 前后一致。服务器 PrivateKey/Peer PresharedKey 只存在局部内存，不返回、不打印；PreUp/PostUp 不执行。
- **安全不变式**：磁盘与 live 都必须完整列出同一组公钥/单一 RFC1918 IPv4/32。任何 config peer 漏字段、多网段、IPv6、未知节、重复 key/IP、live 与 disk 设备/地址不一致都拒绝，尤其不能把“live 缺失、磁盘仍有”的 peer 错误当成释放地址。`read_verified_snapshot` 连续执行 live-before→durable-conf→live-after 三份核验，任何变化导致拒绝。调用时仍需要整个授权事务期间持有跨进程 Rust flock；不能防护不遵守锁的 root 进程或磁盘反回滚。
- **新负例**：`wg_conf_audit::tests::*` 七项解析/不一致测试，加双活快照变化与超大传入 peer 验证，共比先前 39 项增加 9。过渡源码 SHA 9f8266dc 的 Linux CI 因 unused import/unused mut 在 `-D warnings` 下失败，随后删去无效导入和多余 mut，保持严格 warnings-as-errors，未跳过单测。正确承认过渡红例，不以旧 SHA 冒充新绿。
- **最终 Linux Rust**：[CI #44039882060](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882060) head_sha=714674bf，**Completed/Success，48 passed、0 failed、0 ignored**，独立 server-rs Cargo --locked，未触碰真实 wg、网络、用户服务器。当前 SHA Windows [MSVC #44039882064](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882064) / [GNU #44039881955](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039881955) 写入时尚未全部终态，需核对。
- **下一阶段仍未完成**：真实 `wg.conf` Rust 原子写入和 `wg syncconf` 无 shell 提权 helper、旧邀请 RS256/JWE 可信迁移/反回滚、接管 Python TLS 在线 receiver、Linux 真网络命名空间 WG 读回及 Windows 管理端 revoke 联动。SEC-01/02/08 **生产未修复**，PR #3/#6 Draft、main 857ea759 不合并；Windows SEC-03/09/10 实机仍开放。细节参见 [SEC01_LINUX_RUST_MIGRATION.md 第五阶段](./SEC01_LINUX_RUST_MIGRATION.md)。

## D.19 SEC-01 Rust 单 peer 定向写入、原子持久化与读回事务（2026-11-17）

- **活动代码 SHA** `468af9e675bbf118464e1094306c6a055039324d` / Draft PR #6，main 不变。新增 `server-rs/src/wg_peer_plan.rs`：精确按公钥+IP 增删单 peer，原文保存所有其他 peers、comments、[Interface]，禁止公钥/IP 冲突，撤销目标已从 config 和 live 都缺失时允许只读确认 no-op；Plan Debug 不输出原配置（含私钥）。
- **受保护原子写入** `server-rs/src/wg_atomic.rs`：只在已持久 Pending/Revoking 且 grant 匹配的 LedgerStore 下修改 `/etc/wireguard/<iface>.conf`；仅 root 0700/0600/单硬链接，O_NOFOLLOW，核对现存文件内容+inode/time，temp 0600 create_new→fsync→rename→目录 fsync。测试在拥有私有权限的 Linux 临时目录进行，未对真实系统文件动手；目录 fsync 不确定时保留原 Pending/Revoking，不误报最终成功。直接写配置接口已改为 pub(crate)。
- **内核定向操作与闭环** `server-rs/src/wg_live_set.rs`：相较原先整组 `wg syncconf` 方案，改用 Rust `Command` 固定 argv 调 `/usr/bin/wg set IFACE peer KEY allowed-ips IP/32` 或 `wg set ... peer KEY remove`，只影响目标 peer；无 shell，exec/root-owned/模式检查，3s timeout、非零拒绝、无 stdout/stderr 泄露。裸 `set_one_peer` 私有。`apply_and_confirm` 必须先做 live/config 严格核验与磁盘 fsync，再操作内核、重读完整 peers，最后才提交 `Consumed/Revoked`；注入配置写失败、内核失败、回读失败、撤销失败及跨重启已移除后避免重复删除。
- **CI 证据**：[Linux Rust #44042690148](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690148) 与上述 SHA 一致 **Completed/Success：71 Rust tests passed，0 failed，0 ignored**，`cargo --locked`、`RUSTFLAGS=-D warnings` 均保留。基线 48 项 + 本轮 23 项。过渡 SHA `7a6231a1` 因 Plan.bytes 只被测试使用触发 dead_code、`e41f400c` 因 Read/Write::by_ref 歧义 E0034 未通过，均在后续 SHA 修改代码修复，未添加警告豁免或跳过测试。
- **当前 Windows 同 SHA**：[MSVC 44042690238](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690238)、[GNU 44042690146](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690146)，写入时仍在运行；不可借旧版成功宣称当前客户端双绿。
- **阻塞/风险仍存在**：这套 Rust 更新流程未由 Python server 或 Windows 管理端调用，JWS/RS256/JWE/旧记录信任迁移与 TLS 非 root 未完成；只在 fake WG/临时文件中测试，**未在真实 Linux WG namespace 跑内核变更**。配置落盘但 `wg set` 失败会留下 Pending/Revoking + live/disk 暂时失配；下一步需要安全且显式授权的 reconciliation/migration 入口，禁止无脑重试。SEC-01/02/08 生产漏洞仍 Open，SEC-03/09/10 Windows 真机 UAC/WFP 验收仍未完成，main 未动，PR #3/#6 Draft，Issue #5 Open。详见 [SEC01_LINUX_RUST_MIGRATION 第六阶段](./SEC01_LINUX_RUST_MIGRATION.md)。

## D.20 同 SHA Windows 兼容性结果（Rust 单 peer 事务）（2026-11-17）

- 代码 `468af9e675bbf118464e1094306c6a055039324d` 的 [Linux #44042690148](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690148) **Completed/Success：71/71，0 ignored**。
- 同一 SHA 的 [Windows GNU #44042690146](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690146) **Completed/Success**（Rust GNU 构建、Release SPIDERVPN_ROOT 隔离、原 SEC-09/10/11 安全专项）。
- 同一 SHA 的 [Windows MSVC #44042690238](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690238)：Rust 构建、PowerShell 语法、安全专项、全部集成测试、变更模块回归均已 Success；记录时正在跑最后 `Portable Rust unit suite`，保留原先 8 项环境依赖排除，本轮无新增 skip。必须查询最终 workflow `Completed/Success` 后才可宣称完整 MSVC 绿。
- 此证据仅表明 Linux Rust 候选单测与现有 Windows 桌面程序自动化兼容，**不是 Linux 线上 Python 接收器、真实 wg set、Windows UAC/WFP 实机安全验收**。发布约束仍不变，Issue #5 Open，PR #3/#6 Draft，不合并 main。

## D.21 SEC-01 中断 WG 事务四态诊断及可信终态补写（2026-11-17）

- **活动 Rust 代码 HEAD** `0f4f87b92372561475afa790e3c27ba68d89823c`、Draft PR #6。原 `468af9e6` Linux 71/71 + Windows MSVC/GNU 同 SHA 均 **Completed/Success**；此次在此基础上新增 `server-rs/src/recovery_inspect.rs`，不修改旧生产 Python、Windows UI/Guard/WFP。
- 新 Rust 恢复检查器从**持久 LedgerStore 的 Pending/Revoking** 而非任意网络请求字段识别状态；对新增和撤销分别处理“磁盘/内核两侧都完成、仅磁盘完成、仅内核完成、两侧都未完成”四种组合。只返回 `VerifyAndFinalize` / `RepairConfigWithApproval` / `RepairKernelWithApproval` / `RepairBothWithApproval` 供未来本地管理员使用，**不执行修复命令或自动 reattach**；`Open` / `Consumed` / `Revoked` 无法进入恢复。
- `inspect_pinned_recovery` 真实 Rust 只读入口在 LedgerStore 跨进程锁生效时依次读取 live-before、受保护 root-only `wg.conf`、live-after；前后 live 需一致，可容许**仅目标 peer** 的磁盘/live 差异。目标公钥/IP 任一被其他设备占用、无关 peer 变化、快照损坏或重复、过期未完成 Pending，均 fail closed。
- `finalize_stable_prepared` 只允许真正已达双方一致终态时，在重新核实 live+config 后持久补写 Pending→Consumed 或 Revoking→Revoked（包括墓碑）。**若还需要修改 WG 内核或 wg.conf，它直接拒绝**，普通 replay 不允许通过此功能补增 peer。
- **最新 Linux CI**：[44045613147](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613147)，head_sha=`0f4f87b9`，**Completed/Success：85 passed / 0 failed / 0 ignored**，继续 `cargo --locked` + `RUSTFLAGS=-D warnings`，新增 14 条 recovery 状态组合、冲突、漂移、只读和终态落盘回归；**没有执行真实 WireGuard 命令或修改服务器**。
- **最新 Windows 同 SHA**：[GNU #44045613264](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613264) **Completed/Success**；[MSVC #44045613185](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613185) 目前已完成 Rust 编译、安全专项、集成测试，尚需确认整体回归的最终状态。均匹配 `0f4f87b9`，绝不借旧版 CI 冒充当前 SHA。
- **后续阻塞**：只有恢复诊断和“已完成则安全补写账本”已候选通过；管理员显示批准/二次读回的有写副作用的部分修复、真实 Linux WG namespace 测试、旧邀请 RSA/JWE 验签/RequestDigest 迁移、SEC-02 Linux TLS 非特权服务、Windows 管理端 revoke 接线仍未完成。旧 Python 接收器线上路径仍可能重放被撤销设备：SEC-01/02/08 **生产未修复**。继续 Issue #5 Open、PR #3/#6 Draft、main 857ea759 未合并。

## D.22 SEC-01 管理员单次批准的 Rust 恢复执行模拟（2026-11-17）

- Rust 活动开发分支 `fix/sec10-guard-elevation-identity-p0-20261117`、Draft PR #6，**代码 HEAD `663cc4e6d01579f04cb70be721ca3c3a2e66720d`**，main 保持 `857ea759`。新增 `server-rs/src/recovery_apply.rs`，以 `RecoveryReview` 绑定 InviteId、Ledger generation、只读审批动作和完整 live/config 快照；批准对象 `AdministratorApproval` 只能在测试代码 `#[cfg(test)]` 中签发，**未开放生产身份验证/远程触发入口**。
- `apply_approved` **按值消耗一次批准**，严格重读现场和 Ledger generation，在快照/授权动作/邀请状态有任何变化时拒绝。用于模拟的 `RecoveryIo` trait 分别对配置与内核做精确目标操作，模拟并拒绝无关 peer 漂移、过期 Pending、重复授权、磁盘写失败、内核写失败；每次操作后两次 live+一次 disk 读回，最后才 commit Consumed/Revoked，全部失败后保持原 Pending/Revoking 拒绝重放。
- 证据：[Linux Rust #44048267737](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267737) 同 SHA **Completed/Success：91 passed / 0 failed / 0 ignored**、`cargo --locked`/`RUSTFLAGS=-D warnings`，较此前 85 项新 6 项回归。源码过渡提交 `0301b343` 因 `Grant/()` match 不一致 E0308 红，后修；`64ab0a99` 因单次批准通过 move 后旧测试重用 E0382 红，后修；未屏蔽错误或跳过测试。
- **同 SHA Windows 最新结果**：[GNU #44048267756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267756) 已 **Completed/Success**；[MSVC #44048267726](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267726) 已通过 Rust 构建、安全专项，写入时集成测试执行中，仍需核对整个 workflow 的终态。旧 SHA 三绿不能代替本 SHA 验证。
- **关键尚未完成**：真实 root-only CLI 可信管理员身份+二次确认+不可重放 ticket、真实受限 wg.conf/write + wg set adapter + 系统级中断恢复和隔离 Linux WG namespace 运行测试、旧 Python receiver 可信迁移（RS256/JWE/RequestDigest）、Rust 非特权 TLS 服务、Windows revoke 管理端接线仍未完成。因此 SEC-01/02/08 仍为生产待修，PR #3/#6 Draft、Issue #5 Open，不合并 main。完整技术说明见 [SEC01_LINUX_RUST_MIGRATION 第八阶段](./SEC01_LINUX_RUST_MIGRATION.md)。

## D.23 同 SHA Windows 测试端口碰撞及最小修复（2026-11-17）

- 最新 Rust 源码 HEAD 已从 `663cc4e6` 前进至 **`e380e82056c6eecbf237f5661b50af52964c8b9d`**（活动 Draft PR #6）。原 `663cc4e6` 的 Linux Rust [#44048267737](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267737) **91/91 Success**，Windows GNU [#44048267756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267756) **Success**，但 Windows MSVC [#44048267726](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267726) **Completed/Failure**：集成测试/SEC 安全专项成功后，在 `connect::tests::second_connect_is_idempotent_when_already_connected` 遇到 Windows 套接字 `10013`，固定 PID 派生的测试端口 `127.0.0.1:50018` 位于 Runner 不允许绑定区间。**不可写成旧版本 MSVC 三绿。**
- 最小修复仅限 `src/connect.rs` Rust `#[cfg(test)] next_test_port()`：由 `TcpListener::bind("127.0.0.1:0")` 请求操作系统分配未保留的环回测试端口，读取实际 port 后释放；删除固定 50000+pid%200*60 分配，以避开 Windows excluded port range。**没有修改**正式客户端的任何默认端口、连接/断线逻辑、WFP、Guard、权限边界、UI 或 Python 服务。未跳过、未隔离、未弱化失败测试。
- 本轮已验证新源码 SHA `e380e820` 的 [Linux #44049297016](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297016) **Completed/Success**（91 tests）；新 [Windows MSVC #44049296975](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049296975) 与 [GNU #44049297040](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297040) 写入时仍在执行，只有查同 SHA 完成结论才能关闭 CI 闸门。
- 该变更属于 CI 环境隔离修正，不意味着真实 Windows WFP/UAC 网络验收已完成；SEC-01/02/08 生产漏洞、主分支 main 未合并及 Draft PR 约束维持不变。


## D.24 SEC-01 Linux Rust root-only 只读恢复诊断 CLI（2026-11-17）

- **本轮 P0 增量**：基于已验证的 PR #6 HEAD `e380e82056c6eecbf237f5661b50af52964c8b9d`，新建依赖式 [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7)，分支 `fix/sec01-root-only-audit-cli-20261117`，代码 commit `1224512392e95f0e17d70b9160817ba323a41207`。PR #7 的 base 明确为 PR #6 的安全开发分支，而非 main；仅新增独立 Rust 二进制和 Linux CI 检查。原 main `857ea759`、WFP Draft PR #3、Rust Draft PR #6 均未合并或改动。
- **候选实现**：`server-rs/src/bin/spidervpn-pair-audit.rs` 新增 `inspect <绝对私有账本目录> <interface> <invite-uuid>`。Linux 有效 UID 必须为 0；在进入任何存储/WG 读取前拒绝非 root、错误命令、路径 `..`/`.`、非法 WG interface、非小写规范 UUID 和异常时间。用 `LedgerStore::open_existing` 取得 owner-only 账本与 SEC-08 flock，再复用 `inspect_pinned_recovery` 的 live-before → protected wg.conf → live-after 完整读取；仅输出 InviteId、阶段、建议动作、两侧存在布尔值，不打印私钥/旧申请 JSON/原始配置。锁实现可能在受保护目录创建 0600 lock inode；**不写 authority ledger、wg.conf，不运行 wg set、不颁发管理员批准、不调用恢复事务**。
- **同 HEAD 可追溯专项证据**：[Linux Rust CI #44051677137](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677137)，head_sha 精确匹配 `12245123`，Completed/Success；`cargo build --locked --all-targets` 和 `RUSTFLAGS=-D warnings` 成功；**Rust library 91/91 + binary 5/5 = 96/96，0 failed / 0 ignored**。CI 在非 root runner 实际调用 Rust 可执行文件并断言 exit 2 和 `root privileges required`；拒绝路径不会创建预设测试账本 lock；现有 Python 服务依旧由 systemd 调用的防误称检查通过。未跳过已有测试。
- **Windows 同 HEAD**：[MSVC #44051677144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677144)、[GNU #44051677093](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677093) 在本记录时仍未得到最终结论，必须重新核对 head_sha/status/conclusion；不能用基线成功当新 SHA 成功。基线 `e380e820` 对应 [MSVC #44049296975](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049296975)、[GNU #44049297040](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297040)、[Linux #44049297016](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44049297016) 已统一核对为 Completed/Success。
- **验收仍未完成**：仅本地诊断路径有自动化负对照；Linux CI 没有在 root 真实 WireGuard network namespace 验证正向读取；没有可信审批、不可重放票据、approved 实际恢复执行器和 kill -9/断电测试；没有旧 Python 接收器 RS256/JWE/RequestDigest 可信迁移和 Windows revoke tombstone 联动。**SEC-01/02/08 生产未修复，Issue #5 保持 Open，PR #7/#6/#3 保持 Draft，不合并 main**。下一步应做 root+真实隔离 WG 接口读取/故障验收，再逐步完善 Rust 授权身份与管理审批；严禁将 audit 的文本报告作为允许自动恢复 peer 的凭据。


## D.25 SEC-01 隔离 Linux 真 WireGuard 内核及只读 CLI 正向验收（2026-11-17）

- **目标与代码**：本轮继续 [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7)，从上一 `12245123` 追加专门 Rust 测试 `server-rs/tests/wg_namespace_e2e.rs`、Cargo feature `linux-netns-acceptance`、Linux 工作流独立 root/netns job；当前最新 HEAD **`5a8eb6047c1f1e3074fe66a075e9d295c0054a32`**。新 feature 仅用于隔离 CI 编译测试，不改变 `server-rs` 的生产库接口或 Windows 源码。原 main `857ea759`、WFP PR #3、Rust PR #6 均未合并或修改。
- **真实系统级覆盖（GitHub 临时 Ubuntu 24.04 VM，不是用户 VPS）**：CI 使用真实 Linux WireGuard kernel interface `spiderci0`，位于 disposable network namespace，自动生成临时 server/client WG 密钥，以 root 0700 的 `/etc/wireguard` + 0600 `spiderci0.conf`、独立 0700/0600 测试 ledger 检查 `spidervpn-pair-audit inspect`。执行真实 `wg set` 更新临时 peer（**仅 Rust 集成测试/CI fixture 动作，生产 CLI 从不调用 wg set**），验证 Pending 两侧缺失→仅 config→两侧具备、Consumed 只读不可恢复、Revoking 两侧具备→仅 config→两侧都缺、写入 Revoked tombstone 以及原签名 claims replay 仍被拒。断言每次 CLI 调用前后 ledger 原始字节和 live WG peer 列表均不变，CLI 输出不泄漏 key/private config。
- **失败记录不得删除/虚报**：初次 [Linux #44062350952](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062350952) Rust 编译/原有单测成功，内核 fixture 创建成功，**因固定猜测 Cargo 测试 binary 路径失败，test 未真正运行**；改为从 `--message-format=json` 读取 compiler-artifact executable。第二轮 [Linux #44062535111](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062535111) Rust 编译、真实 kernel/netns 创建成功，**测试真的执行但失败**：夹具采用 `ExpiresAt=600` 旧 Unix 时间戳，生产 CLI 正确拒绝已过期 Pending；提交 `5a8eb604` 将测试发行期设为当前 Unix 时间 +600秒，未放宽过期拒绝策略、不 skip 单测。
- **本 SHA 专项成功证据**：[Linux Rust #44062802733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802733)，head_sha `5a8eb604...`、Completed/Success：常规 91 lib + 5 CLI 测试、非 root 拒绝 E2E 均成功；独立 `linux-kernel-netns-sec01-acceptance` job 编译 `-D warnings --locked` 成功，**真实 WireGuard 单个端到端测试 1 passed、0 failed、0 ignored**。不以初次/第二次红例冒充成功；新 job 没有 `ignore`/fail-open 环境跳过。
- **Windows 本 SHA CI**：[MSVC #44062802742](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802742)、[GNU #44062802774](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802774) 写入时仍在运行，不得提前标记为成功；上一 `12245123` 对应的 Linux/MSVC/GNU 已完整成功，但不能代替 `5a8eb604`。
- **保留红色阻塞**：这只验收了真实 Linux 内核环境下的 **读状态/已完成终态补写**。仍无可用的生产管理员审批发行器、真实受限 wg.conf+wg set 恢复适配（本 CI 的 wg set 只是测试 fixture）、旧 Python receiver RS256/JWE/RequestDigest 信任迁移、Linux TLS/SEC-02、Windows revoke 与 tombstone 联动、真实 VPS 断电/升级/回滚、安全双账户 WFP/UAC 验收。SEC-01/02/08 **生产未修复**，Issue #5 继续 Open，PR #3/#6/#7 保持 Draft，不合并 main。


## D.26 SEC-01 root-only TTY 显式确认与终态补写候选（2026-11-17）

- **代码位置和版本**：以 [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7) 的已通过三 CI SHA `5a8eb6047c1f1e3074fe66a075e9d295c0054a32` 为基线，另建 [Draft PR #8](https://github.com/weixiaochuchen618-debug/spidervpn/pull/8)，分支 `fix/sec01-tty-terminal-finalize-20261117`，本轮当前 HEAD `b8cac95971ca468948c401f4ebce2b961989f0c4`。PR #8 的 base 是 PR #7 的安全开发分支，**未合并 main**。既有 Windows UI、Proxy/TUN、Guard/WFP 持久 BLOCK、现有 Python pairing receiver 未修改。
- **新增 Rust 受限入口**：`server-rs/src/admin_terminal.rs`、`spidervpn-pair-audit finalize` 均受非默认 Cargo feature `linux-admin-finalize` 控制；默认发版的 audit 仍只有 inspect，没有恢复/写入口。正式编译该 feature 后也必须有效 UID==0，existing protected LedgerStore + SEC-08 flock，live→root-only wg.conf→live 全量严格一致、状态仅 Pending/Revoking 的 `VerifyAndFinalize`。任何不完整 peer、碰撞、过期部分 Pending、外部漂移均不能触发二次确认；**只在原 WG 内核+磁盘已经达到终态时补写 LedgerStore（Revoked 墓碑或 Consumed）**，不执行 wg set、不更改 wg.conf、不开放 HTTP。
- **操作员确认**：真实 Linux 控制终端 `/dev/tty`（绝无 stdin 替代）；显示 `FINALIZE <InviteId> <Generation> <PendingAdd/RevokingRemove>`，要求 45 秒内逐字输入；poll 有超时、有界 160 ASCII 字节，拒绝 Unicode、额外数据和未知 tty。确认后再次读取可信三份快照、核对完整 peer 列表、账本 generation 和 stage，最终 `finalize_stable_prepared` 再进行一次现场三重读取才允许落盘。审批输入不写入文件、无 API token、不可由普通配对请求回放。**root 本身可信，PTY 可由 root 脚本模拟，不把 TTY 误当可证明人类身份的密码学认证**。实现未达到抵御不合作外部恶意 root 的硬保证。
- **专项测试**：`admin_terminal::tests` 覆盖拒绝非 root、只接受双侧终态、generation 与 stage 绑定、全量库存/ledger 漂移拒绝、有界 ASCII 输入；CLI 在普通账户和 root 无 tty 时均须拒绝；`server-rs/tests/wg_namespace_e2e.rs` 扩展实际 Linux WireGuard 隔离 netns，在 root 无 TTY 先拒绝，再用 CI 专属伪终端驱动两种终态确认、验证原 peer 和其他磁盘配置不变、不可再次确认。此 CI PTY 只作为 root 行为验证测试夹具，**生产逻辑仍只使用 Rust**。
- **失败和修正**：原初版 [Linux #44069828605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069828605) 在 `RUSTFLAGS=-D warnings` 下拒绝 `admin_terminal.rs` 无用 `std::io::self` 引入；提交 `e2e86e00` 仅删该导入，未取消 `-D warnings` / 禁测。修正后 [Linux #44069971535](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069971535) Completed/Success：原 Linux 核心和真实 WG netns 正常，feature-gated Rust module tests 成功。随后新增真实 root PTY **正向**验证提交 `b8cac959`；同 SHA [Linux #44070249998](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249998) / [Windows MSVC #44070249845](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249845) / [GNU #44070249876](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249876) 本条记录时尚未三条 Completed/Success，**不得提前声称绿**。任何后续 CI 失败应分析日志修正，禁止删测试或标安全完成。
- **未完成的安全闸门**：实机独立 root 操作者 + VPS 审批、系统级 kill -9/断电、真实管理根和权限迁移、JWS/RS256/JWE/旧 RequestDigest 可信升级、受限 TLS Rust 服务/SEC-02、Windows revoke 写入 Revoked tombstone、SEC-08 多进程协调与本地 WFP/UAC 真实攻击验证仍欠缺。**SEC-01/02/08 都未生产修复**，Issue #5 Open；PR #3/#6/#7/#8 Draft，不合并 main。


## D.27 SEC-01 本地 root TTY 确认 Linux 核心及真内核回归最终结果（2026-11-17）

- **候选代码 SHA**：`b8cac95971ca468948c401f4ebce2b961989f0c4`，独立 [Draft PR #8](https://github.com/weixiaochuchen618-debug/spidervpn/pull/8)，基线 [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7)。已单独核对 GitHub [Linux CI #44070249998](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249998)：该工作流的两个 Job **均 Completed/Success**，head_sha 与候选完全一致。
- **自动验证明细**：默认 Rust 库 91 项 + CLI 5 项，通过；feature-gated `admin_terminal::tests` 5/5 + CLI 5/5，通过；非 root `finalize` 命令拒绝通过；独立 root Linux WG netns 真实内核单项 E2E **1 passed、0 failed、0 ignored**，包含 root 无 TTY 必须拒绝、root 测试伪终端明确确认 Pending→Consumed 与 Revoking→Revoked、两侧快照及账本一致性、撤销后无法复活。保持 `cargo --locked` / `RUSTFLAGS=-D warnings`；无新 skip，不取代 Windows CI。
- **早期失败不隐藏**：此轮初始 [Linux #44069828605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069828605) 因 `unused std::io::self` 在严格警告下红；`e2e86e00` 删除该未使用 import（不放松编译/测试）后 [Linux #44069971535](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44069971535) 两 Job success；最后增加真实 PTY 正向测试提交 `b8cac959` 获得上述最新版绿。
- **仍待同 SHA Windows 双 CI 终态**：[MSVC #44070249845](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249845) / [GNU #44070249876](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44070249876) 记录时未获得最终结论。严禁将旧 SHA 的绿色用于本 SHA。
- **完成状态**：只读诊断+默认关闭的本地 root TTY **终态账本补写**在隔离内核 CI 条件下通过；不等于 root 真实 VPS 审批、Linux 真 kill-9/断电/迁移安全验收、可信签名与 Python 接收器替换、Windows revoke 写 tombstone、SEC-02 TLS / SEC-08 全流程。**SEC-01/02/08 保持未完成，Issue #5 Open，PR #3/#6/#7/#8 Draft，main 不合并**。


## D.28 SEC-01 旧版授权 RS256 签名证据离线 Rust 审计（2026-11-17）

- **最新候选代码**：基于已通过 Linux/Windows MSVC/GNU 三 CI 的 Draft PR #8 (`b8cac95971ca468948c401f4ebce2b961989f0c4`) 新建 [Draft PR #9](https://github.com/weixiaochuchen618-debug/spidervpn/pull/9)；分支 `fix/sec01-legacy-signed-grant-audit-20261117`，当前 HEAD **`4ca1c308688af5e9ce3785dd0da3fcac711de4bf`**。PR #9 的 base 为 PR #8，不直接合并 main。原 main `857ea759`、WFP PR #3、Windows UI/连接交互和既有 WFP 持久 BLOCK 均未触动。
- **严格编译与内容**：新增 `server-rs/src/legacy_signed.rs`，使用项目客户端 `Cargo.lock` 已锁定的 `ring =0.17.14` RSA_PKCS1_SHA256 组件验证旧 `tc-pair.py` RS256 JWS，`server-rs/Cargo.lock` 连依赖按精确版本补齐；**没有把 Python 或 openssl 当作新上线安全逻辑**。Rust 函数 `audit_signed_consumed` 要求调用者另行提供受信的管理员 RSA JWK 与远端服务器绑定（不得从旧记录/JWS 自身提取当信任锚）；算法头仅接收 RS256/JWT，严格无填充 base64url 和大小上限、签名先验证后信任 JSON 载荷，再逐项核对 InviteId/RequestId/DeviceId/WG 公钥/IP/RequestDigest/ServerBinding 与旧 Consumed 记录。签名无效、合法但其他管理密钥签名、记录串换、foreign node、错误算法或 base64 非规范均拒绝。
- **审计 ≠ 授权**：返回 `ProofReport`（明确不是 `Grant`），没有写入 LedgerStore、import、new peer、wg set、HTTP 接收或再次授权。旧 `invites.json` 缺 `RequestDigest` 时**不得**从签名正文静默补齐然后直接转 Consumed；即使签名有效，仍须真实原签名设备请求的接收密钥绑定、可信撤销墓碑历史与最新 live/config/WG 验收。JWS 里不包含经过签名的旧 `RecipientJwkDigest`，不能只凭旧记录该字段通过身份恢复。签名旧授权过期也不赋予新的连接权。
- **跨实现安全向量**：新增一次性外部 Python cryptography 生成的*测试专用*已签 RS256 授权（只提交管理公钥、签名与伪设备记录；不含私钥），以及项目已有 .NET `tests/fixtures/pairing/dotnet-jwt-1.json` 的独立 RS256 向量正向测试；再覆盖签名篡改、合法其他 RSA 公钥、损坏公钥、错误服务器绑定、设备和摘要字段串换、状态不合法、alg-none 与非规范 base64url。
- **早期失败保留**：[Linux CI #44072177072](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072177072) 首次因测试 Rust E0502 借用编译错误失败，未禁警告/删测试；`3ef84346` 修复借用并加 .NET 互操作。随后 [Linux #44072328377](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072328377) 旧测试夹具因在复制 Base64URL payload 时丢了 12 字符，真实验签正确拒绝签名；原始签名不变，`3ff51bf3` 依据原始测试授权正文严格重编码 959 字符，未放宽验签。修正的 [Linux #44072627523](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072627523) 两个 job Success，**97 Rust library + 5 CLI tests**、真实 WG netns 1 pass、旧 feature TTY tests 全绿，无 failed/ignored。最终 `4ca1c308` 进一步新增另一把**合法** RSA 外来签名密钥拒绝用例；需用同 SHA [Linux #44072823025](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823025) 与 Windows [MSVC #44072823427](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823427)/[GNU #44072823056](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823056) 最终完成结论判定，写入时未核对 Windows 全终态，**绝不借旧 SHA 的绿代替最新 SHA**。
- **生产阻塞**：尚无经过可信原设备 JWS + recipient JWK 摘要核验的迁移器、带撤销历史的旧账本认证导入、正式 Rust HTTP/TLS daemon、Python 旧 receiver 停机排他、Windows 管理撤销同步、实际 VPS 断电/回滚测试。SEC-01/02/08 仍 OPEN，Issue #5 OPEN，PR #3/#6/#7/#8/#9 Draft，不合并 main。下一步应补齐旧签名 PairRequest 验真/RequestDigest 与 RecipientJwk 绑定以及可信迁移事务的 fail-closed 设计（不得简单复活 peer）。


## D.29 SEC-01 原始 PairRequest JWS + RecipientJwkDigest 双签名离线证明（2026-11-17）

- **本轮真实代码提交**：从 [Draft PR #9](https://github.com/weixiaochuchen618-debug/spidervpn/pull/9) HEAD `4ca1c308688af5e9ce3785dd0da3fcac711de4bf` 新建分支 `fix/sec01-original-request-proof-20261117` / [Draft PR #10](https://github.com/weixiaochuchen618-debug/spidervpn/pull/10)，最新 HEAD `e4b8b62fbec4e30bfb10c15f107bb21e2fe1f55f`。PR #10 base 为 PR #9，不触碰 main `857ea759`、原 Windows UI/连接交互、WFP 持久 BLOCK、上线 `tc-pair.py` 接收器、WG 配置和服务端部署。
- **新增代码**：`server-rs/src/legacy_request_proof.rs` 使用既有 Rust `ring`/严格 RS256 JWS 验证程序；先调用上一阶段 `audit_signed_consumed` 以**独立可信管理 RSA JWK + ServerBinding** 验证旧 `SignedAuthorization`；再从原设备保存的 `PairRequest` JWS 提取候选 RSA RecipientJwk，进行 RSA RS256 自签名验证；新输入参数 **`independently_pinned_recipient_digest`** 必须来自另行验真的可信见证，不能直接从可篡改的旧 `invites.json` 或自签 JWS 中“自证可信”。严格核对该独立 digest、原 JWS 的规范 RecipientJwk SHA256 与旧 `RecipientJwkDigest` 三者；使用 `TC-ClientRequest-v1` 的七行原始字段按原字节/时间戳 SHA-256 重算 RequestDigest，核对同时被客户端 JWS 与管理端授权 JWS 签入的值；还比对 RequestId、DeviceId、ClientPublicKey、InviteId、ServerBinding、协议版本及单一 IPv4。
- **不可越权**：返回 `RequestProofReport`，字段 `blocks_any_authorization_import()==true` 始终为真；API **不**返回 Grant/Claims，不读取/更新 durable ledger，不同步 WireGuard，不触发 HTTP/JWE/新授权；签名真不能证明旧设备**没有被撤销**、旧脚本已经停止或当前 WG 配置可信。即使旧 `RequestDigest` 原本缺失，**不能**静默写回旧记录后允许重试。对缺少原始 PairRequest 或独立接收摘要的生产记录应标记“缺失可信见证”，严格拒绝自动迁移。
- **跨实现测试数据**：`server-rs/tests/fixtures/legacy_request_proof.json` 由独立 Python `cryptography` 一次性签发**两个** RSA-PKCS1-SHA256 测试 JWS（原设备申请 + 管理端授权），只提交公开 JWK/JWS 和测试字段，**没有任何私钥**、生产密钥或可用生产 token。Rust 新 5 个用例：双签名及 RequestDigest 正向；缺失原始请求/错误签名；错误独立 RecipientJwkDigest/可变旧摘要；不可信管理 JWK/设备/服务器变更；七行摘要与双 JWS 同时一致。保留已有 97 库测试、5 CLI、root-only TTY 审批、真实 Linux WG netns。
- **自动验证阶段**：当前 SHA [Linux CI #44074337077](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337077) 的 `linux-pairing-authority-core` 已 Completed/Success：**102 Rust library tests passed，0 failed/ignored，5 CLI passed**，新 `legacy_request_proof::tests` 全 5 通过、opt-in 终态 5 tests 通过，严格 `--locked`/`RUSTFLAGS=-D warnings`；独立 real WG netns job 记录时仍在执行，**不能提前宣称整个 Linux workflow 成功**。同 SHA Windows [MSVC #44074337005](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337005) 和 [GNU #44074337010](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337010) 尚需最终状态。上一 PR #9 的 [Linux #44072823025](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823025) Success，MSVC/GNU 需另行复核最终。
- **仍未解决**：要真正迁移必须先有**可独立验真的原 PairRequest 证据及第三方可信的 RecipientJwk 身份绑定**（旧服务一般不持有），可信历史 revoke/tombstone + WG live/config 全量读回、停用旧 Python 写路径、root-only 导入事务、可信签名/Rust JWE/TLS/SEC-02、Windows 撤销打通与真实 VPS 故障/升级回退。**SEC-01/02/08 未修复生产漏洞**、Issue #5 Open、PR #3/#6/#7/#8/#9/#10 Draft 不合并 main。只有满足原总计划统一 DoD 才能关卡。


## D.30 SEC-01 PairRequest 离线双签名候选 Linux 真实内核 CI 终态（2026-11-17）

- **新候选 PR #10 当前 HEAD `e4b8b62fbec4e30bfb10c15f107bb21e2fe1f55f`**，与 [Linux CI #44074337077](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337077) 的 `head_sha` 完全一致。工作流已 **Completed / Success**，Job `linux-pairing-authority-core` 和 `linux-kernel-netns-sec01-acceptance` 均 Completed / Success；不是引用旧 PR9 的结果。
- 核心 Rust `cargo --locked` + `RUSTFLAGS=-D warnings`：**102 library tests passed，0 failed、0 ignored**，其中原有库 97 + 新的五项 `legacy_request_proof` 用例均 passed；原 5 CLI tests + 5 root-TTY opt-in regression tests 全部 passed；root 非权限入口拒绝原位通过。独立 Ubuntu 真实 WireGuard kernel/netns 执行完成并成功，没有代替/跳过该专项。
- 测试同时验证两个由独立 Python cryptography 工具生成的**仅测试用途** RS256 JWS（设备请求/管理授权），Rust 严格验签并核对被双方签入的同一 SHA256 七行 ClientRequest 摘要；缺少原 JWS、修改签名、错误独立 recipient 摘要、修改旧设备/服务器标识必须拒绝。无新生产 Python 安全判定逻辑和私钥入库。
- **Windows 同 SHA 仍待终态**：[MSVC #44074337005](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337005) 已成功完成 Windows Rust 构建，但相关完整 tests 尚在执行；[GNU #44074337010](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44074337010) 至此仍在构建/检查，不能宣称最新 SHA 已三 CI 通过。下次接手**先再次核对三条 workflow 及 exact SHA**。
- **严格限制/真正阻塞**：本审计 API 的 `independently_pinned_recipient_digest` 只是**调用方必须另行提供真实可信见证**的必要条件，Rust 函数无法证明其来源。如果旧 Python 不保存原 PairRequest JWS/有效接收密钥证明，不能仅从可变 `invites.json` 自造“独立受信”摘要；应明确拒绝旧迁移并要求管理员重新配对/重新签发。旧撤销墓碑状态不可由 RS256 历史授权推断，也不能据本报告创建 WG peer。
- **SEC-01/SEC-02/SEC-08 未闭环**；旧 Python receiver 当前正式生产路径未替换，root-only 防多进程并发、完整历史 revoke/tombstones 认证、Rust TLS/JWE、VPS 断电与回滚及 Windows 真实双账户 UAC/WFP 验收尚未完成。main `857ea759` 不动，Issue #5 Open，PR #3/#6/#7/#8/#9/#10 均 Draft、未合并。


## D.31 SEC-01 / SEC-08 旧 Python 服务停用的 root-only Rust 只读预检（2026-11-17）

- **代码与 PR**：基于 [Draft PR #10](https://github.com/weixiaochuchen618-debug/spidervpn/pull/10) 的 Rust HEAD `e4b8b62fbec4e30bfb10c15f107bb21e2fe1f55f` 建立依赖式 [Draft PR #11](https://github.com/weixiaochuchen618-debug/spidervpn/pull/11)；分支 `fix/sec01-legacy-python-cutover-preflight-20261117`，代码 HEAD **`cd3cd51f53ff1df55d67150d89d3601eb1cfcd47`**。原 `main=857ea759` 不变，不修改生产 `tc-pair.py`、Windows UI/连接、Guard/WFP Persistent BLOCK、VPS、WireGuard。
- **真实危险边界**：`src/pairhost.rs` 当前确实安装 root systemd `tc-pair.service`，`ExecStart=/usr/bin/python3 -I /var/lib/tradechannel/pairing-rs/tc-pair.py serve`。该 Python 的线上/CLI create、cancel、authorize、retry 等均**没有**遵守 Rust `SEC-08` 的 `flock`；因此「Rust ledger 锁获取成功」不能证明旧 Python 已停止写入；直接新旧服务并发切换会出现复活已撤销 peer、丢失 tombstone 或交错写入。
- **新增 Rust 只读模块**：`server-rs/src/legacy_cutover.rs` 和受**默认关闭** Cargo feature `linux-cutover-preflight` 约束的 `spidervpn-pair-cutover` 新二进制。唯一公开动作是 Linux euid0 的 `observe_old_python_shutdown()`。要求真正 `/etc/systemd/system/tc-pair.service` 持久遮蔽为 root 所有、父目录不可 group/other write、symlink 指向 `/dev/null`；拒绝仅 `/run` 暂时遮蔽。以固定绝对 `/usr/bin/systemctl`（owner/mode 与可执行验证）、不经 shell、清理环境、3 秒超时、4 KiB 有界读输出采集 `LoadState=masked`、`UnitFileState=masked`、`ActiveState=inactive`、`SubState=dead`、`MainPID=ControlPID=0`、`Job=0/空`，缺失/重复/未知字段拒绝。遍历可见 `/proc/*/cmdline`，**任何** `tc-pair.py` 命令（不止 serve）都拒绝；/proc 不可读或单进程数据超限拒绝。mask、服务状态、进程库存复核两次，漂移拒绝。结果从来不是 `Grant`、`AdministratorApproval` 或迁移票据，报告 `authorizes_legacy_import()==false` 与 `authorizes_new_pairing_listener()==false` 始终成立；**完全无写入、无服务启停、无 WireGuard 命令、无导入**。
- **精确 SHA 的 CI**：[Linux Rust #44075947553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947553) HEAD `cd3cd51...`，**Completed/Success**、两个 job 全成功。Rust core **109 passed / 0 failed / 0 ignored**（原 102 + 新 preflight 7），CLI 5 passed，feature TTY admin 5 passed；独立 Linux kernel WireGuard namespace **1 passed / 0 failed / 0 ignored**；新 feature 专项 7 passed，实际非 root 新 CLI 执行 exit 2 且返回明确拒绝；`cargo --locked` + `RUSTFLAGS=-D warnings` 没跳过失败测试。
- **本 SHA Windows**：[MSVC #44075947516](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947516) 和 [GNU #44075947502](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44075947502) 写入时尚未最终 completed-success，**不可提前宣称三 CI 全绿**；此前 PR #10 的 GNU 已成功但 MSVC 在检索时还未结束。注意 Linux 的真实 root **未持久遮蔽旧服务的 E2E** 尚未新增，不得暗示已通过；正式在 VPS 上取得 root/停服可重复验收仍未进行。
- **最关键限制/未完成**：本工具只是「当时可见的旧 systemd 和进程状态」。管理员 root 可重新开启/另起别名脚本；不同 PID namespace、非协作进程、扫描前后竞态无法由两次快照证明绝无写者。绝不能用此报告当作安全切换授权；仍缺可信的 old-writer 持久 fence、签名及可信 revoke 历史、原请求与接收私钥身份、持久 tombstone 导入/撤销、Rust TLS/JWE 服务替代旧 Python、真实 VPS 断电/回滚，Linux 管理员及 Windows WFP/UAC 双账户真机验收。**SEC-01/02/08 未完成；Issue #5 Open；PR #3/#6/#7/#8/#9/#10/#11 均 Draft，不合并 main**。


## D.32 SEC-01 旧配对 TLS 端口真实 IPv4/IPv6 内核监听否决检查（2026-11-17）

- **新增代码位置**：在 [Draft PR #11](https://github.com/weixiaochuchen618-debug/spidervpn/pull/11) 的 `cd3cd51f53ff1df55d67150d89d3601eb1cfcd47` 上建立 [Draft PR #12](https://github.com/weixiaochuchen618-debug/spidervpn/pull/12) / 分支 `fix/sec01-legacy-listener-proof-20261117`，本阶段 SHA **`16c4176ed302871e2cb41787954a0f667f90d202`**，base 为 PR #11。只修改 Rust 模块 `server-rs/src/legacy_cutover.rs`（默认关闭的 `linux-cutover-preflight`），不修改在役 Python `tc-pair.py`、`tc-pair.service`、Windows UI/连接流程、Guard/WFP 持久 BLOCK 或正式 `main`。
- **真实攻击面**：旧 Python 可以被重命名、包装执行，进程 `cmdline` 中不一定含 `tc-pair.py`；仅根据 PR #11 的 systemd mask/停止和进程字符串扫描无法排除**还有旧配对端口监听**。本阶段从固定的 `/var/lib/tradechannel/pairing-rs/server.json`（独立的 old service 根，非 Rust LedgerStore）读取**真正配置的** `Port`（1024–65535），不盲猜默认 18443；要求该配置所在父目录为 root 所有且非其他用户可写、server.json 为 root 拥有、单硬链接、0600 常规文件、O_NOFOLLOW、最多 64KiB、`SchemaVersion==1`、规范 IPv4 PublicHost 与 `Endpoint=host:Port` 一致。不满足任何条件则拒绝安全预检。
- **内核监听否决**：严格限长读取 Linux `/proc/net/tcp` 和 `/proc/net/tcp6`，验证标题、行及十六进制字段；只要任一 IPv4/IPv6 套接字状态为 `0A`（LISTEN）且本地端口等于受信旧服务配置端口，**无论进程名称是什么**一律拒绝；库存文件缺失、不可解析、太大或提前截断也拒绝。新增真实系统入口在两轮 mask/systemd/process 预检前后分别读取旧配置端口和全量 socket 表，端口漂移拒绝。功能**只读、无停服/导入/授权/关闭监听/写 WG**；返回报告必须仍有 `authorizes_legacy_import=false` 与 `authorizes_new_pairing_listener=false`。即使所有快照暂时干净，仍不等于系统级排他写者栅栏。
- **专项测试**：新增 4 个 Rust 回归：配置端口和 Endpoint 异常拒绝；IPv4/IPv6 伪造 LISTEN socket 表拒绝；坏/截断 /proc socket 库存拒绝；真实 Linux `TcpListener::bind(127.0.0.1:0)` 动态端口的**内核** `/proc/net/tcp` 必须识别为 LISTEN，关闭后不再被认定监听。这一内核 TCP 断言在常规 Linux Rust CI 实际执行，独立 WireGuard netns 测试不被删除或忽略。
- **同 HEAD CI 初步证据**：[Linux #44077594144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077594144) 的 `linux-pairing-authority-core` Job 已 Completed/Success，**113 library + 5 CLI passed**（102 旧核心 + PR #11 七项 + 本轮四项），原 5 admin TTY policy 与新 `legacy_cutover` 的 11 项 feature tests 通过，0 failed/ignored；保留 `cargo --locked` 和 `RUSTFLAGS=-D warnings`。同运行的独立 `linux-kernel-netns-sec01-acceptance` Job 在此段记录时尚未核对最终；Windows [MSVC #44077593890](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593890)、[GNU #44077593911](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593911) 同 SHA 亦须核对最终结果。**不使用旧 SHA 绿色替代新 SHA**。
- **尚存关键阻塞**：`/proc/net` 仅当前 netns 的瞬时快照；无法排除外部 root 在两次观察之外开启/关闭服务、在其他 netns/端口部署、用未登记旧配置运行克隆脚本、修改已验证配置或不合作写者。原旧 Python 的 CLI/HTTP 仍不遵从 Rust flock，**真正排他切换、安全 legacy tombstone 迁移、Rust TLS/JWE HTTP 正式接管、Windows revoke 同步和 VPS 断电回滚均未完成**。Linux root+真实 systemd 长时状态演练、Windows 实机 WFP/UAC 验收也未完成。SEC-01/02/08、Issue #5 仍 OPEN；PR #3/#6/#7/#8/#9/#10/#11/#12 Draft，main `857ea759` 保持不动。


## D.33 PR #12 真实 Linux 内核测试与完整工作流最终结论（2026-11-17）

- 代码 HEAD **`16c4176ed302871e2cb41787954a0f667f90d202`** 对应 [Linux CI #44077594144](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077594144) 已核对 **Completed/Success**；两个 Job `linux-pairing-authority-core` 和 `linux-kernel-netns-sec01-acceptance` 均 Success，与本 SHA 完全一致。Rust 113 library + 5 CLI + 5 TTY admin + 11 feature legacy-cutover tests 通过（0 failed / 0 ignored）；真正 Linux TCP 内核动态监听用例 `real_kernel_ipv4_listener_is_observed_without_executing_old_python` 已出现在日志且通过；真正 WireGuard netns 测试 `root_audit_observes_real_wireguard_and_refuses_revoked_replay` **1 passed、0 failed、0 ignored**。严格 cargo --locked / -D warnings 不变，生产配对仍由 Python 驱动、无跳过安全断言。
- 同 SHA Windows [MSVC #44077593890](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593890) / [GNU #44077593911](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44077593911) 更新此段时尚无 Completed/Success，不能用相邻 HEAD 的绿色结论冒充。
- **下轮审计动作**：验证旧系统安装在 `/etc/systemd/system/tc-pair.service` 的实装 unit 文件如何安全迁移为持久 `/dev/null` mask；不能假定在本机已有常规 unit 文件上直接执行 systemctl mask 成功。需要独立 root/test-VPS 演练 start/restart/mask/rollback 并发竞态、所有旧 CLI 执行链退出与 reboot 后拒绝写。无确认的全局写者栅栏就不能授予 Rust 旧邀请导入或 TLS 监听开启；SEC-01/02/08 继续 OPEN，Issue #5 Open，相关 PR 仍 Draft、main 未修改。


## D.34 SEC-01/SEC-08 原子退役旧 Python SSH 写入脚本入口候选（2026-11-17）

- **本轮代码/PR**：基于 PR #12 `16c4176ed302871e2cb41787954a0f667f90d202` 新建 [Draft PR #13](https://github.com/weixiaochuchen618-debug/spidervpn/pull/13)（base PR #12），分支 `fix/sec01-legacy-script-retirement-20261117`；当前 HEAD **`6295b6c87e36ba9c1df2d906f56e021302905d0c`**。原 `main=857ea759` 不变；不改生产 Python、客户端 UI/连接流程、Windows Guard/WFP Persistent BLOCK，不触碰用户真实服务器。
- **新确认的攻击/故障路径**：旧 Windows `src/pairhost.rs::push` 的脚本更新通过 `base64 -d ... > /var/lib/tradechannel/pairing-rs/tc-pair.py`、`chmod 600` 及 `python3 -I` 使用固定路径；`enable_service` 仍会通过 SSH 执行 `systemctl restart tc-pair.service`。即使 PR #11/#12 已观察旧 systemd 关闭、进程/监听 socket 消失，普通 Windows 管理流程仍可能通过 SSH 重新部署、调用旧脚本来写 legacy invites/WG。**不能以停止 HTTP 监听等同旧写者全面停服**。
- **实现边界**：新增 `server-rs/src/legacy_retire.rs`，只在显式启用、**默认关闭**的 Cargo 特性 `linux-legacy-retire` 下编译；没有任何生产 CLI/HTTP 入口，不在 `pairhost.rs` 或 `tc-pair.service` 里调用。root-only 的独立离线候选 `stage_offline_legacy_retirement` 必须先后通过旧 root systemd 永久 mask+进程+真实端口只读预检。仅允许原 root 0700 目录和原 root 单链接常规 0600 `tc-pair.py`。先创建 root 私有 0700 临时空目录并 fsync parent，然后以 Linux 原生 `renameat2(RENAME_EXCHANGE)` 对**旧脚本文件与暂存目录做原子交换**：交换之后固定 `tc-pair.py` 路径原子变为不可用 `>` 覆写的目录；原文件暂存再由 `RENAME_NOREPLACE` 移入 root-only `.tc-pair.py.retired`，fsync parent；备份存在、硬链接/符号链接/不安全 ACL 一律拒绝。**不使用 `/dev/null` symlink**，因为 Windows 更新脚本中的 `chmod 600` 会跟随 symlink 改坏 `/dev/null`。任何交换后失败不自动恢复可执行入口，必须管理员复核；`RetirementWitness` 永远不能授权 import 或新 TLS listener。
- **精确 SHA Linux 证据**：[Linux #44079535756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535756) `head_sha=6295b6...`，**两 Job Completed/Success**：默认库 113 passed、CLI 5 passed、原 TTY 5、旧 cutover 11；新增 opt-in **5 个 `legacy_retire` tests passed、0 failed/ignored**，含真实 Linux 文件系统原子交换、旧 `>` redirection 失败、备份原字节保持、模拟交换前/交换后中断、硬/符号链接、旧备份保护、权限篡改及重复退役拒绝；独立真 Linux WireGuard netns **1 passed、0 failed/ignored**。`cargo --locked`、`RUSTFLAGS=-D warnings` 仍启用，未跳测。Windows 同 SHA [MSVC #44079535866](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535866) / [GNU #44079535704](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44079535704) 尚需核验完整终态，不使用旧 SHA 绿。
- **绝不视作生产栅栏**：本模块默认根本不会出现在正常 Rust server binary；未向用户开放/执行，在真实旧 root 服务器执行 `systemctl mask`、验证原脚本退役、核对 SSH 自动重传及重启恢复均未发生。退役前空窗期间不合作 root 写者/其他脚本副本仍可写；退役后 root 可重建脚本/从隔离备份显式调用，跨 namespace/未知 port 仍不可由两次观察全面证明。缺 real VPS A/B、生产关停审批、Windows 客户端禁用旧 SSH 写操作、不可回放撤销 tombstone 完整迁移、Rust TLS/JWE 接收器、跨端拒绝重放和实机断电回滚。**SEC-01、SEC-02、SEC-08 继续 Open；Issue #5 Open；PR #3/#6/#7/#8/#9/#10/#11/#12/#13 全 Draft，main 不动。**
- **下一高优先级**：为受信 root 操作员提供可审核的显式切换审批与正式旧 SSH writer 禁写策略（客户端需 opt-in 迁移状态，不得改变普通未迁移用户的现有交互），真实 systemd stop/mask/restart 与原子交换/回滚故障测试；必须先把旧 TCP receiver 与 SSH writer 都关停，再考虑上线新 Rust TLS pairing 与可信旧状态导入。


## D.35 SEC-01 真 root 原子交换专项与断电边界修正（2026-11-17）

- **最新代码 SHA**：依赖式 [Draft PR #13](https://github.com/weixiaochuchen618-debug/spidervpn/pull/13) HEAD **`0fed0b6488de0656d2455a5b0bc1ce90328c7b9f`**（在初版 `6295b6...` 之后增加代码注释中对 fsync 条件的严格限定，以及 Linux root 测试作业）。PR #13 base 为 PR #12；`main=857ea7593941ce79f6507db5b1ced076c3a077ba` 未触动。
- **防止错误发布结论**：Linux 原生 `renameat2(RENAME_EXCHANGE)` 保障**进程运行时**的文件/目录交换原子性，不存在退役路径先被删除造成普通 SSH `>` 重新上传的空窗期。但**系统崩溃/断电持久性不能在 `fsync(parent)` 成功前声称保证**；交换后但 fsync 前突然断电，目录状态可能回退，未来重启必须由 root 对原路径的安全空目录、.retired 备份、旧服务停止/遮蔽、旧脚本进程、旧监听套接字重新取证，禁止凭上次操作记录做授权或切换。测试中所谓“交换前/交换后中断”是**Rust 文件系统状态/进程级故障模拟**，不是实机突然断电演练。
- **新增真正 Linux root 文件系统回归**：在独立 Ubuntu 临时 Runner 的 WireGuard kernel/netns CI job 额外编译同一 Rust `linux-legacy-retire` 功能，用 `sudo` 在 **CI 自建 /tmp 且 root 持有的 0700 目录**运行 5 项实际 `renameat2` 文件系统测试；未写用户 VPS、未碰真实 `tc-pair.service`，无永久系统变更。root 专项覆盖原脚本 0600 保留、不允许 `>` 重建、交换后中断 tombstone 仍在、交换前中断不误报已完成、权限/链接/备份冲突拒绝。
- **匹配 SHA 的完整 Linux 证据**：[Linux workflow #44080116892](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116892) `head_sha=0fed0b...`，两个 Job **Completed/Success**：常规 113 Rust library / 5 CLI tests、5 TTY admin、11 cutover 及普通用户下 5 script-retire 测试均通过；`linux-kernel-netns-sec01-acceptance` 的真正 WG kernel/netns **1 passed/0 failed/0 ignored**，并在同 Job 由真实 root 执行 5 script-retire tests **5 passed/0 failed/0 ignored**。全部保持 `cargo --locked` 和 `RUSTFLAGS=-D warnings`。Windows [MSVC #44080116790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116790)、[GNU #44080116766](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116766) 在此记载时**仍待最终结果**，严格不得宣称当前 SHA 三绿；早期 `6295b6` 的 Windows CI 因更新提交按并发策略 cancelled，不当作编译失败也不可取代新 HEAD 结果。
- **生产 DoD 不变**：root CI 实测只证明文件系统 primitive，不证明真实生产 systemd mask/restart、两端客户端 SSH writer 已隔离、真实断电时目录项生存、被撤销身份能否安全导入、TLS/JWE/HTTP Rust 代替 Python 或 Windows WFP 真机。生产 Rust `linux-legacy-retire` **feature 默认关闭且无 CLI/HTTP/UI 路由**，不能误将 Rust public 函数等同已执行迁移。SEC-01/SEC-02/SEC-08、Issue #5 仍 OPEN；PR #3/#6/#7/#8/#9/#10/#11/#12/#13 全 Draft，不合并 main。


## D.36 SEC-01 Windows 旧 SSH writer 明确退役标志拒绝（2026-11-17）

- **此前 CI 终态补证**：上一项 [Draft PR #13](https://github.com/weixiaochuchen618-debug/spidervpn/pull/13) HEAD `0fed0b6488de0656d2455a5b0bc1ce90328c7b9f` 的三条独立 CI 最终均 **Completed/Success**：[Linux #44080116892](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116892)、[MSVC #44080116790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116790)、[GNU #44080116766](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44080116766)。此证据只归属于该旧 SHA，不能替代 PR #14 的 CI。
- **本次活动**：在 PR #13 上建立独立 [Draft PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14)，分支 `fix/sec01-ssh-legacy-writer-gate-20261117`，当前 HEAD **`5652e64cf5f8ccf726b624bd5bd9da52aeeb9452`**，base `fix/sec01-legacy-script-retirement-20261117`。主 `main=857ea7593941ce79f6507db5b1ced076c3a077ba` 原地不动，WFP PR #3 不动，不更改 Windows HTML/UI、普通 VPN 连接交互和 Guard WFP persistent BLOCK。
- **发现的特定漏路**：原 `src/pairhost.rs` 的 `push`、`call`、`enable_service` 每次经 `ssh::exec` 发起旧脚本上传、`python3 -I tc-pair.py` 执行、邀请码创建/取消/离线批准、以及旧 systemd 重启；`src/deploy.rs` 还可以不经过 Rust SEC-08 LedgerStore，直接追加/撤销 WG peer 或卸载旧配置。即使管理员已经开启退役流程，如果**新版 Windows 客户端依然自动执行这些命令**，会破坏新旧服务切换和撤销账本完整性。
- **新增便携纯 Rust 策略/实装**：`src/legacy_writer_fence.rs` 提供固定的、没有用户输入的 POSIX shell 前置拒绝语句。`pairhost::run` 在**同一次 SSH exec** 内将其放在原命令之前；`deploy::peer_script/revoke_script/uninstall_script` 在任何 WG/config 写操作前内嵌同一条 Rust 固定前置判断。遇到 root 运维预留的服务端 opt-in `/var/lib/tradechannel/pairing-rs/.spidervpn-legacy-writes-disabled`（普通文件/目录/有效或悬空符号链接）、Linux 原子退役留下的原路径 `tc-pair.py` **目录**、或 `tc-pair.service` **符号链接**（含永久 mask 到 `/dev/null`），旧 SSH 写者直接输出固定 `TC_ERROR=LegacyWriterFenced`，退出码 73，客户端 pairhost 报明确 Conflict，**不会发送原旧写命令正文**。不会创建或删除该 opt-in marker；marker 缺失、原 unit 常规文件且脚本未退役时，原脚本操作、UI/网络流程保持不变。
- **专项安全验收设计**：MSVC 工作流新增直接执行 `legacy_writer_fence::tests` 与旧 peer/revoke/uninstall 三脚本前置保护专测，保留全部原有 MSVC 安全回归和 GNU CI；新增 Linux server-rs 的 `#[cfg(test)]` **只在测试时编译根 Windows Rust 源模块**，借以在真实 `/bin/sh`、独立临时目录内测试无 marker 保持执行、常规 marker、悬空 symlink、旧脚本目录 tombstone 和 systemd mask 分别令 `sh` 在原命令产生任何写入之前 exit 73；不是复制/重写一套假 shell gate。Linux 仍运行 Rust `--locked`/`-D warnings`、原 root 文件系统 5 项、真 WG netns 1。**本段记录时同 SHA CI 尚在运行，禁止提前宣称成功**： [Linux #44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095)、[MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101)、[GNU #44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202)。
- **安全等级仍不达 production DoD**：这个保护只约束采用了**此最新代码**的 Windows 客户端，而且 POSIX 检查与后续原命令之间仍有 TOCTOU 竞态。旧版本客户端、复制 Python、外部 root、其他 ssh 写命令、服务端旧进程以及未纳入保护的部署路径均未被阻断；marker 的 root 创建/独立审批/真实远程配置/防重启并未实现或部署。它不是服务器级独占锁，不能直接授权把已签旧 Consumed 记录导入 Rust、开放 Rust TLS/JWE 或恢复已撤销 WG peer。真正全写者栅栏、可信 tombstone 历史、Linux 真 systemd/root VPS 恢复与 Windows 双账户 WFP UAC 验收依然待做。**SEC-01/02/08 / Issue #5 均 OPEN，PR #3/#6～#14 持续 Draft、无 main merge。**


## D.37 PR #14 Linux 两 Job 全绿，真 shell 拒绝已实际执行（2026-11-17）

- 最新代码 HEAD `5652e64cf5f8ccf726b624bd5bd9da52aeeb9452`；完全同 SHA 的 [Linux workflow #44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095) 已确认 **Completed/Success，两个 job 均 Success**。新增的 `server-rs` test-only cross-crate 编译确实运行了 Windows `src/legacy_writer_fence.rs` 当前源码的 5 项 Rust tests，包括真实 `/bin/sh`、临时 0700 目录、无 marker 原命令执行、marker 文件、悬空符号链接、旧脚本目录和 systemd unit mask 四种拒绝且目标文件未创建。日志显示 `windows_legacy_ssh_guard_tests::tests::actual_posix_shell_blocks_each_retired_server_marker_before_side_effects ... ok`。
- 本 SHA Rust library **118 passed / 0 failed / 0 ignored**（113 原有 + 5 个 Windows gate 源码 tests），CLI 5、root TTY 5、旧服务 cutover 11、普通文件系统 retire 5；独立实际 Linux WG kernel/netns 1 passed/0 failed/0 ignored；同一临时 Linux root job 中再次运行原子脚本退役 5/5。严格 `cargo --locked` 和 `RUSTFLAGS=-D warnings` 全部保持；没有跳过/隐藏新失败。
- Windows 的完整 CI 按当前同 SHA 仍需最终核对：[MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101) / [GNU #44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202)。Linux 通过不能替代 Windows 实际客户端的编译/专项；必须检查 MSVC 中的 `legacy_writer_fence::tests` 和 `old_wireguard_writers_refuse_retired_pairing_host_before_side_effects` 成功后再标记。
- **依然不能关闭 SEC-01/02/08**：没有真实 VPS root stop/mask/retire/重启/回滚，未证明其他旧客户端/SSH 写者也会遵从此项 Windows 客户端新策略；测试临时 marker 不等于实机独立可信管理证据。Issue #5 Open，PR #14 Draft，main `857ea759` 未变。


## D.38 PR #14 Windows GNU 终态与 MSVC 专项通过（2026-11-17）

- **最新 Rust HEAD 不变：`5652e64cf5f8ccf726b624bd5bd9da52aeeb9452`**。这一 SHA [Windows GNU #44083063202](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063202) 已 **Completed/Success**，包括 Win GNU 原构建/权限边界专项，没有跳过新增目标；同 SHA [Linux #44083063095](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063095) 两 Jobs Success / 118 lib passed / 1 真 WG netns / 5 真 root 原子退役。
- 同 SHA [MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101) **完整 workflow 尚未完成**，但 Job 内已逐项取得 `Build with Rust`、`SEC-10 protected IPC and privileged engine regressions (MSVC)`、新 `SEC-01 legacy Python SSH writer retirement gate (MSVC)`、`Rust integration tests (each integration target, no duplicate binary unit tests)` 的 **Completed/Success**。不得据成功的专项推定整个 MSVC workflow 成功，后续仍需查完整 Rust unit tests 与 Job 终态。原 MSVC 工作流既有 8 个需专用 DPAPI/engine/ACL 等 fixture 的环境依赖测试维持原本的非 portable 说明；本轮没有新增 skip 或删掉保护专项。
- 已在 [Issue #5](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5) 留下本轮未完成安全修复的证据与阻塞项，Issue 仍 Open；[Draft PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14) 不合并。现实 root/旧 Python+SSH 多写者完全隔离、旧邀请可信撤销导入、Linux systemd 与真 VPS/reboot 断电 A/B、Rust TLS/JWE 与 Windows 双账户 UAC/WFP 还没通过。严禁将此项称为“SEC-01/02/08 已修复”。


## D.39 SEC-01/SEC-08 旧部署及身份恢复绕过禁写闸门的补齐（2026-11-17）

- **新代码**：[Draft PR #15](https://github.com/weixiaochuchen618-debug/spidervpn/pull/15)，branch `fix/sec01-deploy-restore-writer-gate-20261117`，叠加 PR #14，现 HEAD **`6ab33a77d0ef2582dc6026535ca9f0c61f5dbc8c`**。此轮精准审查发现 PR #14 虽约束 `pairhost.rs`、`deploy::peer_script/revoke_script/uninstall_script`，仍未约束三个**实际 Linux SSH 写入口**：`deploy::install_script`（写 WireGuard 配置、密钥、nft、重启 wg-quick）；`deploy::transport_script`（写 REALITY/transport 身份及 systemd）；`deploy::identity_restore_script`（覆盖 transport.env 私钥及恢复身份）。旧版用户操作均不变，已退役服务不应通过这些路径重新写入。
- **Rust 实现**：`src/legacy_writer_fence.rs::guard_legacy_mutation_script` 在原始 `set -eu\n` **之后**添加现有不可由用户自定义的只读 `SHELL_DENY_PRELUDE`，严禁将旧服务 marker、脚本目录 tombstone、systemd mask 当成可忽略警告。全部三种脚本由 Rust **生成脚本时**直接嵌入，而不是只在某个调用点包围；未退役服务器的旧命令正文和顺序完整保留，没有额外 SSH 往返、没有 UI/WFP/连接流程更改。新增严格字节对照、before-write 顺序检查，Windows MSVC 与 GNU 直接编译测试；Linux server-rs `#[cfg(test)]` 包含实际 Windows 源码，并以真实 `/bin/sh` 和受保护临时目录验证“无标志执行、有标志退出 73 且未写文件”。
- **补救旧 PR #14 的真实 CI 失败**：旧 SHA `5652e64cf...` 的 [MSVC #44083063101](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44083063101) **Completed/Failure**，不是全绿：原有 `deploy::tests::uninstall_script_removes_our_units_and_keeps_identity` 因只读 SEC-01 gate 中含 `/var/lib/tradechannel` 被旧 `!script.contains` 误报，日志结果 1425 passed、1 failed（1 ignored，为既有 probe fixture）。真正卸载正文并无新写入审计目录。修复**不删除测试/不加 skip**：只将恰好一份经过独立测试的 `SHELL_DENY_PRELUDE` 从源码字符串中剥离，再严格断言剩余卸载正文绝不引用/修改审计身份根；新增真 shell 拒绝测试继续验证 prelude 不带写副作用。相同修复分别推送 [PR #14](https://github.com/weixiaochuchen618-debug/spidervpn/pull/14) 最新 HEAD **`c322ef2c3fc397231ad433132d7bbc116a9f2459`** 和 PR #15 上述 HEAD，两个 PR 都在重新跑自己的 MSVC/GNU/Linux，未得到新 SHA 的 full green 前不得将 #14 红色视作关闭。
- **精确 SHA Linux 验收**：[PR #15 Linux #44086373715](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373715) **Completed/Success、两个 Job 均绿**。`server-rs` **120 library tests passed / 0 failed / 0 ignored**（相对前轮 118 新增两项），包含 `actual_strict_posix_shell_will_not_run_deployment_body_when_retired` 真实 /bin/sh 双向对照；原 5 CLI、5 TTY、11 cutover、5 offline retirement、1 真实 Linux WireGuard netns、5 真实 Linux root 原子退役均通过；`cargo --locked` 和 `RUSTFLAGS=-D warnings` 不变。当前 SHA [MSVC #44086373583](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373583)、[GNU #44086373609](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373609) 仍待最终完整结论；PR #14 修正后的独立 CI 亦待核对。
- **生产边界仍未闭环**：此规则只约束编译了新版本的 Windows 客户端，遇到 root-controlled opt-in 退役标志才拒绝；旧版本客户端/外部 SSH/root/被复制的 Python 仍可绕过，命令间可能 TOCTOU；没有真实 VPS 服务器级所有入口排他、持久重启/断电回滚、可信撤销 tombstone 导入、Rust TLS/JWE 在线替换或 Windows 实机双账户 WFP/UAC 验收。**SEC-01/SEC-02/SEC-08 及 Issue #5 继续 Open；所有安全 PR Draft，不合并 main。** `main=857ea7593941ce79f6507db5b1ced076c3a077ba` 保持不变。


## D.40 PR #15 Windows GNU 终态与 MSVC 专项、差异审查（2026-11-17）

- **同代码 HEAD** `6ab33a77d0ef2582dc6026535ca9f0c61f5dbc8c` 的 [Windows GNU #44086373609](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373609) 已最终 **Completed/Success**；[Linux #44086373715](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373715) 两 Job **Completed/Success** / 120 Rust library tests / 真 `/bin/sh` / 真 WG kernel netns、root 原子退役全绿。完整 [MSVC #44086373583](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373583) 更新记录时仍在运行，但 `Build with Rust`、SEC-10 专项、SEC-01 writer gate（包含新三条 deploy 路径）专项和**全部集成测试**步骤已各自 Completed/Success；后续必须复核 `Regression tests` 和 `Portable Rust unit suite` 的全流程结论。
- **代码差异复核**：GitHub [PR #15 files](https://github.com/weixiaochuchen618-debug/spidervpn/pull/15/files) 与当前 base #14 仅四个文件变化：`src/deploy.rs`（三处旧安装/恢复路径加入既有 Rust 退役检查与安全定向回归、保留卸载审计数据断言）、`src/legacy_writer_fence.rs`（严格保持 `set -eu` 的 shell 包装和真实 POSIX /bin/sh 双向测试），及 MSVC、GNU 两份已有工作流的专项过滤器。**未修改** `src/ui*`、`src/connect*`、Guard/WFP、`assets/tc-pair.py` 或服务端生产启动；没有更改 `main`。
- **父 PR #14 也已独立修复失败**：`c322ef2c3fc397231ad433132d7bbc116a9f2459` 的 [Linux #44086538302](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538302) **Completed/Success**；[MSVC #44086538267](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538267) / [GNU #44086538320](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538320) 仍要查最新终态。前版 #14 MSVC 红已诚实记录 D.39；不能因后续分支绿而把前版红写成全绿。
- [Issue #5](https://github.com/weixiaochuchen618-debug/spidervpn/issues/5) 已留本次进度与 MSVC 红因、补救和阻塞评论；Issue 仍 Open，SEC-01/02/08 仍在开发，所有 PR Draft，正式服务器 root 及跨代 Windows 客户端旧写者排他/可信撤销/tombstone / Rust TLS 以及 VPS power-loss、WFP/UAC 真机验收均未完成。


## D.41 旧 PR 全流程 CI 追认；PR #16 补齐“只读却执行 shell”的旧 SSH 漏路（2026-11-17）

- **父级全部 CI 终态确证**：PR #15 HEAD `6ab33a77d0ef2582dc6026535ca9f0c61f5dbc8c` 对应 [Windows MSVC #44086373583](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373583)、[Windows GNU #44086373609](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373609)、[Linux #44086373715](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086373715) **均 Completed/Success**。PR #14 修复后的 HEAD `c322ef2c3fc397231ad433132d7bbc116a9f2459` 的 [MSVC #44086538267](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538267)、[GNU #44086538320](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538320)、[Linux #44086538302](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44086538302) **亦均 Completed/Success**。原始 PR #14 `5652e64c` 的 MSVC Failure 仍是历史真实失败，已修复重测；不能改写为绿。
- **新修复候选**：叠加在 PR #15 上的 [Draft PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16)，分支 `fix/sec01-transport-source-retirement-gate-20261117`，首次 Rust commit `11155352574aefb5f1951fd9947f8ed50d53cf7a`；之后 MSVC 代码审查发现相邻 `cargo test` 之间缺 `$LASTEXITCODE` 断言，立即以 `ed8d7a9817998fabebdb05d7dc40a9ac8a034804` 补齐，避免第一组失败被第二组成功掩盖。**新 SHA 必须单独查 Linux/MSVC/GNU 全流程，不能使用 11155352 或前代绿色替代**。
- **漏洞链解释**：`deploy::read_transport` 和 `deploy::export_transport` 认为是只读，但 `TRANSPORT_PROBE_SCRIPT` / `TRANSPORT_EXPORT_SCRIPT` 均通过 `. "$IDENTITY"` **执行**远端 `transport.env` shell 内容。PR #15 只封堵 install/restore/peer/revoke/uninstall，不封堵这两条可能有副作用的旧执行入口。PR #16 以 Rust 在同一个 SSH 命令、任何 `source` 之前附加已有 `SHELL_DENY_PRELUDE`；当受信 root 已启用退役标志/脚本目录 tombstone/systemd mask，先退出 73 + `TC_ERROR=LegacyWriterFenced`。非退役路径剥除不可变前置检查后，旧命令正文逐字节不变，旧 UI/网络交互不改。
- **专项测试**：新的 Windows Rust `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host` 测两条**实际生产脚本生成器**、顺序、原始字节保持；Linux `server-rs` test-only 继续直接编译同一份 `src/legacy_writer_fence.rs`，用真 `/bin/sh` source 含写文件命令的 `transport.env`，确认无 marker 时保持旧行为，有 marker 时明确 exit73、无副作用。Windows MSVC/GNU 新增显式 Rust 过滤器；原单测和构建未删除、未跳过。
- **已知不安全边界**：这仅避免**新版客户端**在**服务端已经主动退役**时经旧读入口执行脚本；非退役端仍会 `source` 文件，不能声称通用不可信 shell 环境安全，也不能阻断旧客户端、其它 root/SSH、别名 Python 或跨进程 TOCTOU。Linux 生产接收器不改、Rust TLS 未接管、旧 Revoked tombstone 无可信导入、无真实 VPS systemd/reboot/power-loss/回滚或 Win11 多账户验收；SEC-01/02/08 + Issue #5 仍 OPEN，全部安全 PR Draft，WFP 持久 BLOCK / main `857ea7593941ce79f6507db5b1ced076c3a077ba` 无变更。


## D.42 PR #16 Linux 同 SHA 121 库测试与真内核/netns 验收（2026-11-17）

- 代码 HEAD `ed8d7a9817998fabebdb05d7dc40a9ac8a034804` 的 [Linux workflow #44100469714](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469714) 两 Job 均 **Completed/Success**。核心 **121 Rust library tests / 0 failed / 0 ignored**，5 CLI 和先前 opt-in 管理、cutover、退役测试均保持成功，`--locked` / `RUSTFLAGS=-D warnings` 不变；真实内核 WG netns 与 root-owned 隔离退役 Job 成功。Linux 原始日志证实 `windows_legacy_ssh_guard_tests::tests::actual_shell_denies_sourceable_read_only_transport_before_side_effects ... ok`，在真 `/bin/sh` 内有 / 无受信 marker 的对抗对照已实际运行。
- 对应同 SHA [MSVC #44100469733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469733) / [GNU #44100469724](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469724) **此刻仍 in_progress**，不能当作成功；新 Agent 应核对各自 Build、明确新增 Rust tests 和完整 Job 终态。旧 SHA `11155352` 的运行结果不可替代当前 SHA。
- PR #16、父级 PR 仍是 Draft、main 不动；Linux 内核 CI 是隔离 runner 而不是 VPS 实际退役。SEC-01/02/08 / Issue #5 未关闭。


## D.43 PR #16 最新 SHA Linux / GNU / MSVC 完整成功与实际日志核证（2026-11-17）

- **当前 Rust HEAD**：`ed8d7a9817998fabebdb05d7dc40a9ac8a034804`，独立 [Draft PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16)，base PR #15，未合并 main。
- 精确同 SHA [Linux #44100469714](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469714) **Completed/Success**，两个 Job 均 Success。121 Rust library passed / 0 failed / 0 ignored，新的 Windows Rust 源码在 Linux test-only 通过真实 `/bin/sh` sourceable transport.env 拒绝前执行副作用与 marker 后零副作用对照；真实 WG kernel/netns 与 root 退役专项通过，保留 `--locked`、Linux `RUSTFLAGS=-D warnings`。
- 精确同 SHA [Windows GNU #44100469724](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469724) **Completed/Success**；原始日志确认 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok`。存在原仓既有 Rust warnings（例如 unused、duplicated attribute），不是零 warnings 承诺；本次没有忽略失败测试。
- 精确同 SHA [Windows MSVC #44100469733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44100469733) **Completed/Success**：Rust build、SEC-10、SEC-01 新旧门禁专项、全部 integration targets、变更模块回归和最后 Portable unit suite 步骤均 Success；实际单测末行 **1429 passed, 0 failed, 1 ignored, 8 filtered out**。1 ignored 与 8 个环境依赖过滤来自**原有** CI/fixture 范围，不是本轮新增跳过，更不能称为未经排除的全部 Windows 实机安全验收。
- **回归与差异确认**：相对父 PR #15 仅修改 `src/deploy.rs`、`src/legacy_writer_fence.rs`、`.github/workflows/rust-windows.yml`、`.github/workflows/security-guard-gnu.yml`。MSVC 现在对每一条单独 `cargo test` 后都检查 `$LASTEXITCODE`。无 UI、连接/代理、`assets/tc-pair.py` 或 WFP 持久 BLOCK 改动；main `857ea7593941ce79f6507db5b1ced076c3a077ba` 未变。
- **SEC-01/02/08 不关闭**：通过的只是新版 Windows 客户端在**已独立启动退役条件**的旧 SSH 入口拒绝；真实生产 Linux root、旧客户端与非协作写者、systemd/mask/reboot/power-loss、可信撤销/tombstone 迁移、Rust TLS 监听服务接管均未通过，无法凭 CI 推断零漏洞或安全合并。Issue #5 Open，全部相关 PR Draft，WFP-05 真机未验收。



## D.44 SEC-01/08 受控 root TTY 离线退役 CLI 候选（2026-11-18）

- **活动候选**：[Draft PR #17](https://github.com/weixiaochuchen618-debug/spidervpn/pull/17)，base [PR #16](https://github.com/weixiaochuchen618-debug/spidervpn/pull/16)，branch `fix/sec01-root-tty-offline-retire-cli-20261118`，首个 Rust HEAD `45c5f86fae1c55d7eb2418b589b4f32f4f530557`。从已验证的 PR #16 `ed8d7a98` 分出，正式 main 不变；代码改动仅 `server-rs/Cargo.toml`、`server-rs/src/bin/spidervpn-pair-retire.rs` 及原 Linux CI workflow。
- **具体问题与新代码**：此前 `legacy_retire::stage_offline_legacy_retirement` 虽已有 root-only 原子 RENAME_EXCHANGE + quarantine + fsync，但没有带人类确认与终态检查的独立可执行运维入口。新增 **default-disabled** `linux-legacy-retire-cli` feature 及其 required-features bin `spidervpn-pair-retire`，只接受固定 `retire` 参数，不收用户路径、`--yes` 或环境 token。先检查有效 root UID，然后 Rust 只读 preflight 证明旧 unit 永久 mask/inactive/dead/zero PID、旧 Python 进程不存在、旧 TCP4/TCP6 端口无监听；接着通过真实 `/dev/tty` 在 45s 内读取精确 ASCII 确认文本，不接受 stdin；确认后第二次重新观察，最后才调用已有 retire primitive 自身的前后重复检查和文件系统原子退役。未知/错误/中断状态全部拒绝并要求人工检查，不自动打开旧脚本。
- **明确权限边界**：该 CLI 是**离线退役能力候选而非可信 server cutover 或生产修复**。必须先由独立 root 运维确认 stop/mask，且相同 root/旧客户端仍可手动改目录、调用别名脚本、绕过 Rust flock。成功返回不导入旧 Consumed/Revoked、不会创建 peer、监听 TLS、变更 WireGuard、放行 HTTP 或自动授权新客户端。root + 控制 TTY 不证明所有 SSH 写者受控；不能把它当成 server 侧真正的全局锁。
- **新增验收**：Rust CLI 六类定向单测覆盖非 root/多余参数在任何 IO 前拒绝、首轮 shutdown 失败、空 TTY/错误同意不执行、人工停留后的第二次 shutdown 失败、retire 结果不授权迁移、失败/不完整 witness、UTF-8/CRLF/超长/EOF 终端输入。Linux CI 用 `--locked`、`RUSTFLAGS=-D warnings` 编译 bin、运行全部测试，并由 CI 非 root 调用同一 binary 验证 exit 2；原 WG netns、sudo 临时目录 root filesystem 退役测试保留，不删除/跳过任何测试。
- **本条建立时 CI 仍运行**：精确 SHA [Linux #44203320571](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320571)、[MSVC #44203320563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320563)、[GNU #44203320555](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320555)，必须逐个检查最终状态与失败日志；不能继承 PR #16 绿。无真实 VPS root/stop/mask/reboot/power-loss/rollback 或历史 revocation 可信迁移；SEC-01/02/08 和 Issue #5 OPEN、全部安全 PR Draft，main `857ea759` / UI / WFP 持久 BLOCK 均不变。



## D.45 PR #17 Rust E0382 真实 CI 红例、不跳过修正与新 HEAD（2026-11-18）

- 首次代码 SHA `45c5f86fae1c55d7eb2418b589b4f32f4f530557` 的 [Linux workflow #44203320571](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203320571) **最终 Failure**，不能称为全绿。两个 Job 中真实 Linux WG kernel netns + root /tmp filesystem 退役 Job 为 Success；core Job 前置 Rust authority、legacy preflight/retire 全通过，但新增 `spidervpn-pair-retire` binary TEST 构建发生 Rust E0382：新测试 `line.unwrap()` 两次移动同一 `Result<String, ()>`。失败测试未忽略、未删除。
- 已在同一 Draft PR #17 修正为两个借用的 `line.as_deref()` 断言，不改产品/退役决策或测试范围；当前代码 HEAD **`de8e2e222a31c0290385a0126c0f2538571c33d0`**。旧红结果必须保留历史，且其 CI 不得替代新 SHA 的验证。
- 新准确 SHA 已触发 [Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974)、[MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970)、[GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991)，**本条记录时仍在运行**；必须核查每条 Job / 新 CLI six tests / 既有全量回归终态。
- 不构成 production 安全验收；不可自动在实际 VPS 上停止旧 Python、打开新 Rust TLS、导入旧 revoked/consumed 或合并 main。SEC-01/02/08、Issue #5 OPEN，PR #17 Draft。详细见 D.44。



## D.46 PR #17 E0382 修复后 Linux 全流程双 Job 成功（2026-11-18）

- 精确 Rust HEAD `de8e2e222a31c0290385a0126c0f2538571c33d0`，[Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974) **Completed/Success 两 Job**：真实 WireGuard netns 与 root 临时目录文件系统原子退役验收 Success，Rust core 全流程 Success（121 library pass/0 failed/ignored、5 CLI pass、既有管理 TTY + legacy cutover/retire 专项通过，保持 `cargo --locked` / `RUSTFLAGS=-D warnings`）。
- Linux 原始日志确认新 `spidervpn-pair-retire` **6 项 Rust CLI tests 全部通过、0 failed、0 ignored**，包括拒绝非 root、错误参数、缺授权、重复 shutdown 检查、故障后 fail-closed、非 ASCII/CRLF/EOF；普通 Linux runner 真执行同一 CLI `retire` 后 exit2、`root privileges required`，未在生产 VPS 上执行改动。旧首 SHA `45c5f86` 的 Rust E0382 red 继续按 D.45 真实保留，没有跳过。
- 同 SHA [MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) / [GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) 本条记录时仍在运行；不能当作 full success。SEC-01/02/08、Issue #5 OPEN，PR #17 Draft、main/UI/WFP 不改。Linux CI **不等于**在真实 VPS root stop/mask/reboot/rollback 或绝对隔离非协作 root writer。



## D.47 PR #17 GNU 完整 Success，MSVC 已通过构建/权限/集成/模块回归（2026-11-18）

- 与 PR #17 最新代码 HEAD `de8e2e222a31c0290385a0126c0f2538571c33d0` 精确匹配的 [GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) **Completed/Success**：Windows GNU Rust 编译、Release 不接受 `SPIDERVPN_ROOT` 覆盖、提权 Guard IPC 与身份单测均成功，日志确认 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok`；旧 Rust warnings 未宣称为全部消除。
- 同 SHA [MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) 已核查 `Build with Rust`、SEC-10 权限边界、SEC-01 SSH guard、所有 integration targets、changed Rust module regression **分别 Completed/Success**；最后 `Portable Rust unit suite` 仍在运行，**整条 MSVC workflow 不能提前写 Success**。保留既有 1 ignored/8 环境依赖过滤，不为本轮失败加 ignore/skip。
- GitHub compare `ed8d7a98...de8e2e22` 只涉及 `server-rs/Cargo.toml`、新 `server-rs/src/bin/spidervpn-pair-retire.rs` 和 `.github/workflows/security-pairing-rust-linux.yml`。没有 Windows UI/connection/Guard/WFP、旧 Python 服务的产品变动。Linux 完整成功详见 D.46，旧首次红例详见 D.45。
- 当前功能候选及本地 CI 在隔离环境通过 ≠ 真实 root VPS systemd mask、旧 SSH writer 隔离、可信 revoke/tombstone 迁移、Rust TLS 生产接管通过；SEC-01/02/08 / Issue #5 OPEN，PR #17 Draft，main 不动。



## D.48 PR #17 同一代码 SHA 三平台终态全绿，原始 MSVC 全量测试日志核对（2026-11-18）

- 最新 PR #17 代码 SHA `de8e2e222a31c0290385a0126c0f2538571c33d0`：[Linux #44203644974](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644974) 双 Job **Completed/Success**；[Windows GNU #44203644991](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644991) **Completed/Success**；[Windows MSVC #44203644970](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44203644970) 终态也已核实 **Completed/Success**。MSVC 原始日志最后一轮 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered out（原有环境依赖）**；实际 Build、SEC-10、SEC-01、全部集成测试、changed Rust module regression 和 Portable Rust unit suite 所有步骤 Success，不跳过失败项。Linux 真 kernel/netns、root 隔离文件系统、121 lib + 六条新 CLI、非 root 实际拒绝通过。
- 前一失败 SHA `45c5f86` Linux Rust E0382 编译错误仍真实保留在 D.45；改为 `as_deref()` 后的上述结果**只属于新 SHA**。PR #17 保持 Draft/unmerged，main `857ea759` 与 WFP 持久 BLOCK、旧 UI/连接不变，真实 Linux VPS 退役 / root 写者排他未验收。

## D.49 PR #18 新增重启后只读 Rust 退役复核入口（2026-11-18）

- 新代码 [Draft PR #18](https://github.com/weixiaochuchen618-debug/spidervpn/pull/18) 叠在 [PR #17](https://github.com/weixiaochuchen618-debug/spidervpn/pull/17) 之上，branch `fix/sec01-postboot-offline-retire-verification-20261118`，首 HEAD `72533502c1e361d6d1a3d029b5da99cb7499f57f`。旧 root TTY CLI 有 `retire`，但没有只读 post-reboot 确认，容易误拿重跑变更命令代替核验。新增同一默认禁用的 Rust CLI `verify` 固定动词：**euid root、无可控路径、无需 tty（只读），前后真实 systemd 持久 mask + inactive + 无旧 Python 进程 + 真实旧端口监听快照**，中间调用已有 `observe_offline_retired_entrypoint()` 再观察完整旧脚本目录 tombstone / protected quarantine / 无暂存；任何失败、失踪、symlink、残留 stage、被恢复的旧 Python 脚本都拒绝，不自动恢复/回滚或写 WireGuard。
- 额外三组 Rust CLI tests（正确确认调用顺序、非 root/多余参数/第一次或第二次 shutdown 失败、损坏 witness 拒绝）+ 两组真实 Linux owner-only 临时目录根文件系统回归（模拟 reboot 后复核成功、丢失隔离源/伪 symlink/重入 stage/重建可执行路径均 fail-closed）。Linux CI 现同时调用真实非 root `retire` 与 `verify` 两条路径，均需 exit2；既有 root WireGuard netns 与 legacy_retire 真实 fs 测试保留。不更改默认构建、Windows UI/连接、WFP、旧 Python 生产服务和 main。
- **新 SHA 尚未完成 CI**：必须从 [PR #18 Actions](https://github.com/weixiaochuchen618-debug/spidervpn/actions) 精确取 Linux/MSVC/GNU runs，逐一核对 Rust 编译、3+2 定向、真实 root /tmp 文件系统、完整 MSVC/GNU 回归；不能拿父 PR #17 已绿替代。该只读核验**不是**真实服务器 reboot/power-loss 证据，更不能排除其它 root/SSH writer；SEC-01/02/08、Issue #5 均 OPEN，PR Draft，不合并 main。



## D.50 PR #18 新 SHA Linux 双 Job Success、真实 root 和伪重启验证（2026-11-18）

- 精确 Rust HEAD `72533502c1e361d6d1a3d029b5da99cb7499f57f` 的 [Linux #44205893006](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205893006) **Completed/Success（2/2 Jobs）**：Linux core `121 library passed / 0 failed / 0 ignored`；`spidervpn-pair-retire` 现在共 **9 binary unit tests / 0 failed/ignored**，原始日志确认三条新 `postboot_verify_...` 全部 ok；`legacy_retire` 原有 5 + 新增 2 共 **7 项 root 临时目录 FS 测试**，同时通过 Linux 特定 root netns job；真正 Linux WG kernel netns 一项通过。普通 runner 以非 root 身份真运行 `retire` + `verify` 均 exit2，`root privileges required`，未触发任何正式 VPS 路径变更。Linux 保留 `--locked`、`RUSTFLAGS=-D warnings`，未增加忽略。
- GitHub compare `de8e2e22..72533502` **仅三个文件**：Linux opt-in Rust CLI、Linux Rust `legacy_retire` 模块单测和现有 Linux CI workflow（9/111/42 行左右变更）；完全没有 Windows UI/交互/连接/Guard/WFP 的 Rust 产品代码、现役 Python 端、release 默认编译或 main 改动。
- 同 SHA [Windows MSVC #44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) / [Windows GNU #44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961) 本条书写时 **仍在运行**，不能提前当作全绿。后续核对两者准确 SHA 的完整工作流及原始日志；如失败必须修复，不可 skip。
- 重启后核验所覆盖的是**runner 内的模拟状态与只读现场检查代码**，不是实测生产 VPS 真实重启、断电恢复或非协作 root/旧 SSH 写者。仍不可导入历史 Consumed/Revoked / 绑定 Rust TLS / 合并 main；SEC-01/02/08 与 Issue #5 OPEN，PR #18 Draft。



## D.51 PR #18 GNU 同 SHA 全绿，MSVC 原专项通过但全量还在进行（2026-11-18）

- 精确代码 SHA `72533502c1e361d6d1a3d029b5da99cb7499f57f` 的 [Windows GNU #44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961) **Completed/Success**，Rust GNU 构建、Release 禁止 `SPIDERVPN_ROOT` 测试、Guard/身份权限、旧 SEC-01 guard Rust 专项均成功，原始日志确认 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok` 和 `sec01_install_transport_restore_are_guarded_before_all_mutations ... ok`。GNU 有原仓既有 unused 等 warnings，不能说零 warnings。
- 同 SHA [Windows MSVC #44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) Build、SEC-10 protected IPC、SEC-01 SSH writer gate、全量 integration targets、changed-module regression 步骤先后 **Success**；最后 Portable Rust unit suite **尚在运行，整体 MSVC 不提前记全绿**。Linux 两 Job Success 见 D.50。
- **精确的验证上限**：`verify` 只能检查当下 root-controlled 路径类型/权限、原隔离文件存在与 systemd/进程/socket 快照；没有独立受信 SHA256 对比或历史时序证据，不能证明原始隔离**内容在重启期间从未遭别的 root 进程篡改**。亦不能证明另一个 root/SSH 写者之后绝不会启动服务。真实 VPS reboot/power-loss/rollback、跨代写者隔离及撤销历史可信性仍未验证；SEC-01/02/08 / Issue #5 OPEN，PR #18 Draft，main/UI/WFP 不动。



## D.52 PR #18 同代码 SHA Linux / Windows GNU / Windows MSVC 全流程 Success（2026-11-18）

- **新 Rust HEAD 不变**：`72533502c1e361d6d1a3d029b5da99cb7499f57f`，叠加 [Draft PR #18](https://github.com/weixiaochuchen618-debug/spidervpn/pull/18) base PR #17。精确同 SHA [Linux #44205893006](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205893006)、[GNU #44205892961](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892961)、[MSVC #44205892936](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44205892936) **全部 Completed/Success**。完整 MSVC Job 原始日志最终 `test result: ok. 1429 passed; 0 failed; 1 ignored; 0 measured; 8 filtered out`；1 ignored、8 filtered 为仓库原环境依赖/fixture 策略，并非本轮为通过新增的跳过。MSVC Build Rust、SEC-10、SEC-01、all integrations、changed modules 与最终 portable 全部步骤真实 Success；GNU 旧门禁与提权 identity 实测成功，但有原仓既有 compiler warnings，不能称 GNU 0 warnings。
- Linux Rust `--locked`、`RUSTFLAGS=-D warnings` 保持不变：121 lib/0 failed/ignored、opt-in retire CLI 9 binary tests（含新增 3 verify）、真实 Linux root 隔离临时路径原子退役与 postboot 二项（总计 7）和内核 netns 完整通过，普通用户真执行 `retire`、`verify` 都拒绝退出 2。未为 CI 跳过一条新增失败测试。PR #18 相比父 PR #17 仅 3 个 Linux 文件：Rust opt-in CLI、Linux Rust retire module、原有 Linux CI workflow；默认关闭，无生产 Python / Windows UI/连接/WFP 变动。
- **风险/验收状态没有因全绿改变**：本次 `verify` 是时间点 root 级别的**只读**旧入口目录和隔离文件**类型、owner、权限与存在**验证，配合 systemd/process/socket 快照，**不是隔离文件内容的独立哈希真实性、跨 root/跨时间全写者排他的证据**，更不是实际 VPS reboot/power loss、可信历史 revoke tombstone、Rust TLS / API 服务接管或 Windows UAC/WFP 真机安全验收。SEC-01/02/08 和 Issue #5 仍 OPEN，PR #18 及祖先 PR 都 Draft、未合并 main。main `857ea7593941ce79f6507db5b1ced076c3a077ba` 未变。



## D.53 SEC-02 Rust 有界并行握手 + 不可延长绝对时限基础（2026-11-18）

- 新 [Draft PR #19](https://github.com/weixiaochuchen618-debug/spidervpn/pull/19) 叠加在 #18 `72533502c1e361d6d1a3d029b5da99cb7499f57f`，分支 `fix/sec02-bounded-tls-handshake-admission-20261118`，初始 Rust HEAD **`6ec1f401ddbc5bc19b82fa62a36c61ee20890b28`**。选项 `linux-handshake-admission` **默认关闭**，不接 production receiver，也不暴露新的公网端口。
- **真实风险链**：当前生产 Python `assets/tc-pair.py` 的 `command_serve` 在 `ThreadingHTTPServer` 的**监听套接字**上先 `ssl.SSLContext.wrap_socket(...,server_side=True)`，再 `serve_forever`；未完成 TLS handshake 可能在主 accept 线程阻塞，后续合法连接排队。将来 Rust 服务端必须在 accept 后对**单条**连接独立握手并限时，不能将 TLS 放回监听 socket。
- **本轮 Rust 交付**：仅新增 feature-gated `server-rs/src/handshake_admission.rs`，`HandshakeAdmission` 使用 `AtomicUsize` CAS 抢占槽位再启动线程、最多 64 并行，不足时立即 `WouldBlock` 拒绝；`DeadlineIo` 对底层 TcpStream 的**整个**握手使用 monotonic `Instant` 绝对 deadline（100ms–30s），按剩余时间逐次设定 read/write 超时，连续小字节流无法刷新窗口；RAII 在成功/错误/panic 后释放槽位。该基础组件没有 TLS 协议栈/HTTP parser 或监听绑定，不能视为已修复生产 SEC-02；受恶意占满全部槽位时仍可拒绝正常用户，CPU 忙循环/绕过 DeadlineIo 的外部库调用不在约束范围，未来必须以真实 TLS + HTTP 集成复核。
- **专项测试**：六组 Rust 真实 loopback TCP（非模拟）回归覆盖边界配置拒绝、单空闲/另一健康连接独立握手、满槽立即拒绝及回收、慢滴答数据不可延长总 deadline、超时后不可写入、错误与 panic 后槽位释放；Linux CI 保持 `--locked`、`RUSTFLAGS=-D warnings` 新增独立专项，而原有状态机、Root 隔离文件系统、真实 WG kernel/netns 均保留。无 Windows UI、连接/WFP、旧 Python 生产启动、main 变更。
- **本条代码尚未通过同 SHA CI**：正在运行 [Linux #44211032490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032490)、[MSVC #44211032535](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032535)、[GNU #44211032519](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032519)；必须查终态及新 Rust 单测/回归日志，失败即修正重跑，不可跳过。SEC-02 **P0 OPEN / 生产未修**；SEC-01/08、Issue #5 OPEN，PR Draft，不合并 main。



## D.54 PR #19 Rust 对抗复查：阻止工作线程晚启动刷新握手截止时间（2026-11-18）

- 初版 `6ec1f401ddbc5bc19b82fa62a36c61ee20890b28` 的 [Linux #44211032490](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211032490) **双 Job Completed/Success**：121 库测试/0 failed/ignored，6 条新增真实 loopback TCP handshake policy 测试/0 failed/ignored，旧 server-rs 管理/legacy-retire 与真实 kernel netns 全绿（`--locked`, `-D warnings`）。此结论**不能替代新代码 SHA**。
- 自我对抗式检查找到绝对时限的时钟起点：虽然 `DeadlineIo` 使用固定 `Instant`，但原实现只在工作线程被 OS 调度**之后**才生成 deadline。恶意卡顿/系统负载可能无意延长握手占用。本轮第二个 Rust commit `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34` 改为**在 CAS 槽位预留、线程 spawn 前**生成绝对 deadline 并传入 IO wrapper；新增第 7 条 Rust 测试，特意延迟 worker 建立，预先送入字节，确认已过 deadline 的读和写都必须 TimedOut。旧六条测试仍完整保留，没有 skip。
- **PR #19 最新代码 HEAD `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34` 的新三平台 CI 正在运行**：[Linux #44211428730](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428730)、[MSVC #44211428496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428496)、[GNU #44211428529](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428529)。必须分别检查完整结论，任何失败都按当时 SHA 修复，不能套用旧版初次全绿。
- 仍只属默认禁用的 SEC-02 pre-integration Rust TCP/handshake worker foundation，未实现真正 Rust TLS 证书验证/HTTP，未在 VPS 部署或接管旧 Python。**SEC-02 未修复生产路径**，SEC-01/08 真 root 全写者隔离/撤销历史迁移与 WFP 实机验收仍阻塞，Issue #5 Open、PR #19 Draft、main/UI/连接/WFP 持久 BLOCK 不动。



## D.55 PR #19 最新 Rust SHA Linux 所有 Job 及七条真实 loopback TCP 回归成功（2026-11-18）

- **代码 HEAD `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34`**：同 SHA [Linux workflow #44211428730](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428730) **2/2 Jobs Completed/Success**。原 Rust 库 121 passed / 0 failed / 0 ignored；新 SEC-02 `handshake_admission::tests` **7 passed / 0 failed / 0 ignored**，真实本地 TCP 涵盖正常并行、恶意 idle、慢字节 trickle、满槽拒绝、槽位重用、panic 回收、在 worker 启动前截止时间已过的 read/write 拒绝，均在 Linux `--locked` / `RUSTFLAGS=-D warnings` 下运行。原 root /tmp 隔离退役、Linux WG kernel/netns 与其他 Rust 回归仍 Success；未跳过失败。
- **严格限定差异**：GitHub compare parent #18 `72533502` 到 #19 新 HEAD 仅 4 个文件：`server-rs/Cargo.toml`（feature **默认关闭**）、`server-rs/src/lib.rs`（条件编译入口）、`server-rs/src/handshake_admission.rs`（新 Rust 非 TLS 策略）、原 Linux CI workflow。没有改变 `assets/tc-pair.py`、`src/pairhost.rs`、Windows UI/连接/WFP；main 未变。
- 精确同 SHA [Windows MSVC #44211428496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428496) / [GNU #44211428529](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44211428529) **本条书写时仍在执行**，不能提前声称全绿；如红需查 logs 并修复重跑。SEC-02 仍未接入真正 TLS/HTTP 端口和旧 Python 迁移，**状态不变：P0 OPEN / production vulnerable**；SEC-01/08 和 Issue #5 亦 OPEN、PR #19 Draft、生产安全验收未完成。



## D.56 PR #19 第二轮对抗修正：CPU-only 回调不能在超时后返回成功；新 Linux 八条测试（2026-11-18）

- 在 HEAD `1fcda2dcbc1941b4f2b644641ed3e18450ed1e34` 成功 Linux 7 tests 之后，独立复查发现：`DeadlineIo` 在每次 read/write 都检查绝对截止时间，但 TLS 验签等 **最后一次 I/O 之后的纯 CPU 工作** 若耗时超限，其回调原可不再读取 socket 而返回 `Ok`。此漏洞不应以“IO 有 deadline”等同“整个握手成功必须未超时”。
- **第三个 Rust commit HEAD `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b`**：在握手回调完成后**再次检查之前在 admission 时固定的截止时间**，超时一律 `TimedOut` 而不是返回成功，RAII Permit 不变。新增第八条 Rust `callback_cannot_report_success_after_deadline_without_more_io`：真实 TCP connection，callback 不做 IO、故意 sleep 超时，确认不得 `Ok`。之前 7 条都保留、没有 skip/ignore。
- 对此最新 SHA [Linux #44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) **core Job Completed/Success**，原始日志确认 **121 Rust lib / 0 failed / 0 ignored、SEC-02 8/8 真实 TCP tests / 0 failed / 0 ignored**，并且已有管理/旧脚本回归成功；独立 kernel/netns Job 本条写入时还在运行，不能提前称整个 Linux workflow 完整全绿。
- 本 SHA [MSVC #44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) / [GNU #44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) 同样 **进行中**，完整成功必须查同 SHA 每个 Job 和原始日志；原前两个 SHA 绿只能当历史，不可替代。无生产 TLS 接收器；对于无限 CPU 自旋/绕过 wrapper 的外部函数仍无法预先强制中断，未来服务还需隔离处理。
- SEC-02 **生产 P0 仍 OPEN**，SEC-01/08 / Issue #5 OPEN；PR #19 Draft/unmerged，Windows UI/连接/WFP persistent BLOCK、现役 Python 和 main `857ea759` 均不动。



## D.57 PR #19 最终代码 SHA Linux 两 Job 与 GNU 全流程成功；MSVC 原步骤成功但完整尚待（2026-11-18）

- **代码 HEAD `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b`** 不变；[Linux #44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) 现已核对 **两 Job Completed/Success**。独立真实 kernel WG netns Job 成功，7 条 Linux root-only 临时目录退役与后验收 Rust tests 成功；core Job 121 lib/0 failed/ignored + 新 **8 条 SEC-02 真实 loopback TCP/0 failed/ignored**，真实日志显示 `callback_cannot_report_success_after_deadline_without_more_io ... ok`，且已有严格 `--locked`、`RUSTFLAGS=-D warnings` 未改变。
- 同 SHA [Windows GNU #44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) **Completed/Success**：Rust GNU 编译、Release `SPIDERVPN_ROOT` 信任边界、SEC-10 Guard/身份与 SEC-01 原 SSH writers 回归全部通过；原始 GNU 日志 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok`，仓库既有编译 warnings（如 unused）仍在，不能称零 warning。
- 同 SHA [Windows MSVC #44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) **Build / SEC-10 / SEC-01 工作流步骤均已 Success**，正在执行 integration/changed-module/full portable unit；其**完整终态仍须验证**，不能称三平台全面成功，更不能引用旧 head `1fcda2dc` 的 Windows 测试。
- 即使三平台 CI 全部成功，**仍无 Rust TLS 协议栈/HTTP endpoint，生产 Python 监听 socket 慢握手堵塞未修复**；原 server root 全写者/受信撤销 tombstone、Windows UAC/WFP 实机未验收，Issue #5/SEC-01/02/08 OPEN，PR #19 Draft，main/UI/WFP 仍不变。



## D.58 PR #19 同 SHA Linux/GNU/MSVC 三平台 CI 终态全部 Success（2026-11-18）

- 最终 [Draft PR #19](https://github.com/weixiaochuchen618-debug/spidervpn/pull/19) Rust HEAD **`9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b`**。同 SHA [Linux #44212209581](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209581) 两 Job **Completed/Success**：121 Rust lib / 0 failed / 0 ignored；新增 **8 条**真实 TCP 握手并发/慢速限时专项 / 0 failed / 0 ignored；root 临时目录退役、真实 WG kernel/netns 全绿，Linux `--locked`、`RUSTFLAGS=-D warnings`。
- 同 SHA [GNU #44212209522](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209522) **Completed/Success**，旧源码 SSH gate 与 Guard/身份测试成功；有原仓已有 Rust warnings。 [MSVC #44212209567](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44212209567) **Completed/Success**：Rust Build、SEC-10、SEC-01、全部 integrations、changed-module regression、Portable Rust unit suite 均成功。原始日志末尾 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered（原有环境依赖）**，未隐瞒失败测试或借用其它 SHA。
- 本轮两次后置补丁（`1fcda2dc` 在 admission 预定绝对时限；`9cc7ab6b` 回调返回前二次检查）均由新 SHA 真编译测试；差异仅 4 个 Linux 服务端 Rust/feature/CI 文件，无 Windows UI、连接、WFP、现役 Python 或 main 改动。
- **安全验收仍 BLOCKED**：这是默认禁用、**没有真实 TLS 协议栈、HTTP reader 或生产监听接管**的 Rust policy；完全无法证明生产 Python TLS wrap(listener) 的 P0 缺陷已消除，也无 VPS 实机/多账户/证书兼容/旧 revocation 数据等验收。SEC-02、SEC-01/08 和 Issue #5 OPEN；PR #19 Draft，不合 main。



## D.59 PR #20 独立握手后 HTTP 单请求容量/期限安全边界（2026-11-18）

- 在 #19 `9cc7ab6b5fcdf087eec2f80e92ef7581ebe4fe0b` 同 SHA Linux/GNU/MSVC 全绿之后，新增 stacked [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20)，base #19，branch `fix/sec02-bounded-http-handoff-20261118`，首 Rust HEAD **`a773fe881eb02954279d068d2c7d05dacbab5a3e`**。仅改 `server-rs/src/handshake_admission.rs`、Linux CI yaml；原 `HandshakeAdmission::spawn` 不改、`linux-handshake-admission` 默认关闭、不接旧 Python 或任何公网端口、main/UI/连接/WFP 不动。
- **P0 子风险**：旧 #19 限制握手并发和绝对 deadline，但还没有限制**握手成功之后**的 HTTP request/handler worker。新 Rust `RequestAdmission` 另有跨连接共享 CAS 配额（1..64）、请求阶段不可由慢字节进度延长的绝对时间（100ms..30s），`spawn_one_request` 在旧握手槽位**尚未释放前**预留 HTTP 请求 slot；请求满额时直接 fail-closed + 关闭 socket，不能启动无界 handler。成功时释放握手槽，单一工作线程处理**严格一次**请求，然后关闭连接，不暴露 socket；callback 失败/过时/崩溃均 RAII 释放两个 permit。HTTP 末尾无 I/O CPU 工作仍需在 return 前重新核对 deadline，防回调延长总时间。
- **测试**：新增五组**真实 Linux loopback TCP**测试，覆盖成功握手→单请求→关闭、慢 HTTP 不占握手槽但占请求配额且次连接在满额时拒绝、握手验证失败不得调用 HTTP、HTTP trickle 慢流总 deadline、无 I/O late callback / panic 不得泄漏配额；原八组 SEC-02、121 旧 Rust 核心、root 临时目录原子退役、真 WG kernel/netns 均必须保留。CI 用 `--locked`、Linux `RUSTFLAGS=-D warnings`，GNU/MSVC 仍自动构建与安全回归。
- **首次 SHA CI 待验证终态**：[Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337)、[MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354)、[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452)。本条书写时 Linux netns Job Success、core 正在编译；不能借父 PR #19 的成功冒充此 SHA；一旦失败须修 Rust 而不是跳过测试。
- **真实安全验收上限**：这还只是默认关闭的 Rust callback + TCP 资源策略，未实现加密 TLS 1.2 服务端、证书/指纹兼容、正式 HTTP parser、身份验证/撤销历史、global root writer 排他或 VPS 实机部署；用户服务仍使用有慢握手 DoS 缺陷的 Python 端。CPU 无限阻塞也无法由纯 socket wrapper 中断。故 SEC-02/SEC-01/08、Issue #5 **OPEN**，PR #20 Draft、不合并 main。



## D.60 PR #20 Linux 同一 SHA 两 Job Success 与 13 项真实 socket 回归（2026-11-18）

- 新代码 HEAD `a773fe881eb02954279d068d2c7d05dacbab5a3e`，[Linux CI #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337) **两个 Job 均 Completed/Success**，原始 core 日志：**121 library passed / 0 failed / 0 ignored**、`handshake_admission::tests` **13 passed / 0 failed / 0 ignored**（包含新增五组）；原旧脚本隔离/CLI 回归、真实 root owner-only 临时目录原子退役与独立真 WG kernel/netns Job 都完成成功。保留 `cargo --locked`、Linux `RUSTFLAGS=-D warnings`，没有移除或忽略任何失败测试。
- 与父 PR #19 的 `9cc7ab6b` GitHub compare 精确**只有两个文件**：新 Rust 服务端 `server-rs/src/handshake_admission.rs` 和原 Linux CI yaml。新 `spawn_one_request` 对成功握手后**单个请求处理回调**做第二配额和总期限保护；当前没有 HTTP parser，**无法以这段源码证明网络上严格解析/限制为恰好一条 HTTP/1.1 请求**。未来 TLS + HTTP 服务接线时必须独立验证 headers/body bounds、Transfer-Encoding/Content-Length、keepalive 拒绝、授权 token 与恶意输入；纯 CPU 无限循环/阻塞外部调用也未被强制中断。
- 同 SHA [MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354) Rust 编译和现有部分回归已在运行，[GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) 仍在编译，**需核实最终完整 Job**；不能借用父 #19 已绿冒充新 SHA 的全部绿。真正 Python `wrap_socket(listener)` 慢握手 P0 风险仍在 production；SEC-02/01/08、Issue #5 Open，PR #20 Draft，main/UI/连接/WFP 保持原样。



## D.61 PR #20 GNU 完整 Success、MSVC 专项与模块回归成功；旧 Python HTTP 兼容边界（2026-11-18）

- 代码最新 HEAD 仍为 `a773fe881eb02954279d068d2c7d05dacbab5a3e`。同 SHA [Windows GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) **Completed/Success**，Rust Build、Release root trust guard、SEC-10 IPC identity、SEC-01 SSH `source transport.env` tests 均在原始日志实际成功（仓库已有 GNU compiler warnings，不能称 0 warnings）。
- 同 SHA [Windows MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354) 的 Rust Build、SEC-10/SEC-01 安全专项、全部 integration、changed-module regression **分别 Completed/Success**，最后 `Portable Rust unit suite` **本条记录时仍 in_progress**，整个 MSVC 尚不能声称完成。Linux 两 Job 完整 Success、13 新旧 TCP 资源测试参见 D.60。若 MSVC 最终失败，必须取日志、修 Rust、按新 SHA 全部重测；不可 skip。
- 经源文件逐项复核：目前现役 `assets/tc-pair.py` 只使用 TLS1.2（`SSLContext.minimum_version/maximum_version` 均设 TLSv1_2）；HTTP/1.1 旧 JSON 响应带 `Content-Type: application/json`、`Content-Length` 与 `Connection: close`，请求 POST body 允许 1..**131072 字节**，必须具备数字 `Content-Length`，拒绝任何 `Transfer-Encoding`。未来真正的 Rust TLS/HTTP 迁移必须以协议金样本验证这些兼容边界，并增加 header 整体/单字段大小限制、短读/slowloris/重复长度/请求重放/超时/keepalive/HTTP pipelining 反例；本 PR #20 没有实现/声称已实现真实 TLS/HTTP parser/授权。
- 因旧 Python 接收端没改、生产 SEC-02 仍存在，当前 PR #20 **Draft**、Issue #5 和 SEC-01/02/08 OPEN，不合 main，不更改 UI/连接/WFP 持久 BLOCK。



## D.62 PR #20 同一新 SHA Linux / GNU / MSVC 三平台全部 Success，生产 SEC-02 仍未验收（2026-11-18）

- Rust HEAD **`a773fe881eb02954279d068d2c7d05dacbab5a3e`** 的 [Linux #44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337) **两 Job Completed/Success**，121 Rust library/0 failed/ignored，13 条 SEC-02 真实 TCP handshake+posthandler 配额/绝对 deadline tests /0 failed/ignored、真 kernel WG netns 与 root temp FS 回归通过，Linux `--locked`、`RUSTFLAGS=-D warnings`。同 SHA [Windows GNU #44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452) **Completed/Success**（原仓已有 warnings）；[Windows MSVC #44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354) **Completed/Success**：真实 Build、SEC-10、SEC-01、全部 integration、changed modules、Portable full suite 各步骤成功。MSVC 原始最后总结 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered（原有环境依赖）**。无新增 skip/ignore，未混用旧 SHA 结果。
- 此 PR 精确 compare 父 #19 只有两文件：`server-rs/src/handshake_admission.rs` + `.github/workflows/security-pairing-rust-linux.yml`；默认关闭的 Rust `RequestAdmission` + `spawn_one_request` 完成**一次 handler callback** 资源限额和结束关闭，**不保证 HTTP wire 只收到/解析一条 request**。HTTP1.1 parser/headers/POST size/pipelining/认证未实现，也没有 TLS1.2 crypto、客户端真实证书指纹兼容、服务器 TLS 监听上线、旧 Python 退役/撤销数据迁移。因此成功的只是隔离候选代码与现有 Windows回归，**不是生产 P0 SEC-02 缺陷的修复认证**。
- 安全账本：**SEC-01 / SEC-02 / SEC-08 / Issue #5 仍 OPEN**，全部安全 PR（含 [Draft #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20)）维持 Draft/unmerged；main `857ea7593941ce79f6507db5b1ced076c3a077ba`、原 UI、正常连接/代理、WFP persistent BLOCK 无改动。实际 VPS systemd/reboot/rollback 与 Windows UAC/WFP 多账户安全验收缺失，不得以 CI Success 自行放行。



## D.63 PR #21 默认禁用的 Rust HTTP/1.1 严格单报文解码与真实 TCP 负例（2026-11-18）

- 已检查 [Draft PR #20](https://github.com/weixiaochuchen618-debug/spidervpn/pull/20) 的 head `a773fe881eb02954279d068d2c7d05dacbab5a3e` 在 Linux [#44218336337](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336337)、GNU [#44218336452](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336452)、MSVC [#44218336354](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44218336354) **同 SHA 全部 Completed/Success**：Linux 121 lib + 13 真实 TCP requests/handshake policy，真实 WG netns/root temp FS；MSVC 1429 pass/0 fail，1 原有 ignored、8 原有 environment-filtered。此为 #21 的父基线，不自动继承新 PR 的验证结论。
- 新 [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21)，分支 `fix/sec02-strict-http11-request-framing-20261118`，叠加 #20，首 Rust commit `9e392b84122569e0375f0e6afb0a09470369bf80`，第二修正 HEAD **`4f770d2f90686785d99f31e41b60ca71e6d3c48f`**。仅三 Linux/server 文件：新增 `server-rs/src/http_one_request.rs`、`server-rs/src/lib.rs` 现有 feature-gated module 注册、Linux CI 新专项。`linux-handshake-admission` 默认 OFF，不接生产监听/现役 Python；main、Windows UI/连接/WFP persistent BLOCK 不变。
- Rust `read_one_request(&mut DeadlineIo)` 对**未认证**的 HTTP/1.1 原始请求施加固定资源上限：request line≤2048、header line≤4096、header block≤16384、≤64 headers、POST Content-Length 必须是唯一十进制且 body 1..131072（匹配旧 Python `PAIR_LIMIT`）、GET 不允许非空 body。拒绝重复 Host/Authorization/Content-Length、TE（含 chunked 与 CL+TE）、Expect、Upgrade、obs-fold、CRLF 错误、NUL/control 和异常 HTTP Method/version。默认不用/不解析外部请求得到的 authorization 授权，返回数据标注 untrusted；Debug 不打印 Bearer 或 POST body。恰好读一条 HTTP message，不预读 pipelined 第二条；实际关闭由上一 PR #20 一次 callback 的 worker 生命周期负责。
- **真实错误及修正不可隐瞒**：首 SHA [Linux #44224651210](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224651210) core Job **Failure**，13/13 原 handshake 回归通过，但新 9 组 Rust localhost TCP parser 测试 **8 pass / 1 fail**：`pipelined_second_request_unread_and_socket_closed` 错误地假设关闭未读 socket 必须返回 EOF；Linux TCP 对未读管线字节可正确返回 RST/`ConnectionReset`。新 commit `4f770d2f...` **保留原测试**，断言必须出现 EOF 或 ConnectionReset 且没有第二请求分派/permit 泄漏，并补单字节读、双 permit 验证，未跳过任何失败用例。禁止把原首 SHA 写成全绿。
- 最新 HEAD 的新 CI 已启动：[Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790)、[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780)、[GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789)，本条撰写时均**in_progress**，须核对准确 SHA 原始日志并修复任何再次失败；不能借父 #20 的成功。
- 验收上限：这还不是 TLS-decrypted HTTP 接收器/证书与身份绑定/授权 token/真实路由和 JSON response/Revoked 历史可信性，也**没有通过网络端到端验证真正的 TLS1.2**；请求 parser 单次调用不能限制未来错误的重复调用方。旧 Python listening TLS wrap DoS 仍在，SEC-01/SEC-02/SEC-08、Issue #5 OPEN，PR #21 Draft，不合 main。



## D.64 PR #21 新 HEAD Linux+GNU 完整 Success，Windows MSVC 全量仍待（2026-11-18）

- 实际代码 HEAD **`4f770d2f90686785d99f31e41b60ca71e6d3c48f`**（修复首 SHA 测试断言，不删除反例）。[Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790) **两个 Job Completed/Success**：库 121 passed / 0 failed / 0 ignored；旧握手+请求两阶段 **13/13**、新 `http_one_request::tests` **9/9** 真实 TCP tests / 0 failed/ignored，含修正后的 pipelined 第二请求拒绝；独立 root netns 真实 WireGuard kernel 1 test、root-only tmp 退役 FS 7 tests Success。保留 Linux `--locked`、`RUSTFLAGS=-D warnings`，没有忽略失败。
- [Windows GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789) 同 SHA **Completed/Success**：Rust build、Release environment root boundary、Guard IPC/身份、旧 SEC-01 SSH writer gate 实测通过；原始日志 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok`。GNU 有原仓既有 unused warning，不能称 0 warning。
- [Windows MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780) 同 SHA **Build、SEC-10 和 SEC-01 已成功**，后续 integrations、changed modules、portable Rust 全量正在执行；整个 MSVC 未完整完成前，不得声称三平台全绿。父 PR #20 的 1429 pass 不可当新 SHA 的证据。
- GitHub compare `a773fe88..4f770d2f` **仅三文件**：`.github/workflows/security-pairing-rust-linux.yml`、`server-rs/src/lib.rs` 和新 Rust `server-rs/src/http_one_request.rs`（默认 feature 禁用）。现 `read_one_request(&mut DeadlineIo)` 仅针对**Rust 有界明文字节流/真实 TCP 测试**，不是 TLS 解密后的 Rustls/HTTP 整合接口；未来真正 Rust TLS 服务必须确保解析读取的是**已解密且经验证的 TLS application data**、底层 IO 仍受限、一个客户端连接只允许一次 handler，不能把当前 plaintext 套在 TLS ciphertext 上。旧 `assets/tc-pair.py` 仍是生产，TLS accept DoS 未修，旧撤销历史与跨 root 写者未验收。SEC-01/02/08、Issue #5 OPEN，PR #21 Draft，不合 main/UI/连接/WFP 均不动。



## D.65 PR #21 最终同 SHA Linux / GNU / MSVC 完整 Success（2026-11-18）

- **最终 Rust HEAD `4f770d2f90686785d99f31e41b60ca71e6d3c48f`**，叠加 [Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21) base #20。精确同 SHA [Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790) **两 Job Completed/Success**：121 library/0 fail/ignore、原握手/HTTP 资源 13/13、**新增 9/9 真实 TCP HTTP/1.1 严格解码负例 / 0 fail/ignore**，真实 WireGuard Linux kernel/netns + root-only temporary FS 隔离 7 tests 完整成功，保持 `--locked`、`RUSTFLAGS=-D warnings`；[GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789) **Completed/Success**（旧 source transport / Guard/identity tests 真运行成功，GNU 原仓 warnings 仍存在）；[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780) **Completed/Success**，Rust Build、SEC-10、SEC-01、all integration、changed module、Portable unit suite 各步骤 Success，原始最后测试结果 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered（原有环境依赖）**，未新增忽略、跳过或减少失败测试。
- **历史失败不得抹掉**：本 PR 首 SHA `9e392b84122569e0375f0e6afb0a09470369bf80` 的 Linux #44224651210 core 真实 Failed（parser 8/9，pipelined close EOF-only 错误断言）。同一反例保留于后续修正 SHA `4f770d2f`：Linux 关闭带未读第二条管线字节的连接可能返回 RST/`ConnectionReset` 而非 FIN/EOF；修正断言只接受两种确实关闭状态，并验证只执行一个解析回调、没有泄漏 handshake/request permit。最新 Linux 9/9 true TCP tests 已重新通过，不继承旧 CI 结果。
- 本 PR 相对父 #20 仅 3 个服务端 Rust/CI 文件：新 `server-rs/src/http_one_request.rs`、`server-rs/src/lib.rs` 有条件模块注册、原 Linux CI yaml。无生产 Python、Windows UI、正常连接交互或 WFP 持久 BLOCK 变更，main 仍 `857ea7593941ce79f6507db5b1ced076c3a077ba`。
- **安全结论仍是候选/未生产验收**：新 parser 只能在测试中对有 deadline 的**明文** TCP 读请求，不是实际 Rust TLS1.2 加密服务的已解密 HTTP reader；未实现证书/指纹校验、历史 revocation 可信迁移、Bearer token/真实 HTTP endpoint 响应或 root writer 全排他，也没有真正 VPS systemd/reboot/rollback 和 Windows 真机 WFP/UAC 演练。线上 `tc-pair.py` TLS 在 listening socket 上阻塞 accept 的 SEC-02 DoS 仍存在。**SEC-01/SEC-02/SEC-08、Issue #5 保持 OPEN，全部安全 PR（含 #21）Draft/unmerged，不得合 main。** 下一项应优先构建真实 Rust TLS/HTTP 服务与 wire 兼容、慢握手攻击测试，仍需先满足 authority/old writer 迁移闸门。



## D.66 PR #22 真实 Rustls TLS1.2 加密握手→解密 HTTP 实验链（2026-11-18）

- 审查基线：main `857ea7593941ce79f6507db5b1ced076c3a077ba`；[Draft PR #21](https://github.com/weixiaochuchen618-debug/spidervpn/pull/21) `4f770d2f90686785d99f31e41b60ca71e6d3c48f` 的 [Linux #44224794790](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794790)、[GNU #44224794789](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794789)、[MSVC #44224794780](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44224794780) 全部 **Completed/Success**，Linux 121 lib + 13 handshake + 9 parser 真 TCP、真实 WG kernel netns 与 root fs，MSVC 1429 pass/0 failed/1 原有 ignored/8 原有 environment-filtered。Issue #5 OPEN，PR 仍 Draft。
- 新 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) stacked on #21，分支 `fix/sec02-rustls-tls12-decrypted-http-lab-20261118`，首 Rust SHA `d205763fe8e4eb774a9be1ed216fc8105f56d41c`，第二 HEAD **`63f84bce9c75865727d2d8b409d08b4198d4d181`**。只改 `server-rs/Cargo.toml` / `Cargo.lock`、`server-rs/src/lib.rs`、`server-rs/src/http_one_request.rs`、新 `server-rs/src/tls_wire.rs`、Linux CI 六文件；旧 Python/Windows UI/连接/WFP 持久 BLOCK/main 未改；`linux-tls-wire-lab` feature 默认 OFF、不接公网监听。
- 核心 Rust：新增 optional pinned `rustls =0.23.46`，显式 `ring,std,tls12,logging`、禁 default AWS-LC，版本与原客户端锁一致；服务器独立 Cargo.lock 仅补充 7 个原客户端已锁版本/校验的直接及传递依赖，保留原版本，Linux `--locked` `RUSTFLAGS=-D warnings`。新 `tls12_server_config` 构建仅 TLS1.2 rustls；`spawn_tls12_decrypted_one_request` 在原 CAS bounded handshake worker 内对底层 `DeadlineIo` 做 **真实 ServerConnection TLS 握手**，握手成功才预留 posthandshake request slot 并释放 handshake slot；使用 `rustls::Stream` 将已解密的 TLS application data 传给严格 HTTP parser。Parser 改从 `&mut DeadlineIo` 到泛型 `Read`，原明文 TCP 负例不变，新的 Rustls Stream 作为输入。整个请求阶段继续受原绝对时限与配额保护，socket callback 结束即关闭，未提供任何 Bearer/Revoked 授权。
- 新增七组 Rust **真实加密 loopback TCP**：TLS1.2 server cert chain 合法情况下 GET/POST 解密成功（Authorization 只作为 untrusted、Debug 遮盖）、TLS1.3-only 拒绝、错误 DNS 证书校验拒绝、一个 idle TLS 客户端不堵另一个合法握手、TLS1.2 解密 header 慢速滴答总时限、加密 duplicate Content-Length 拒绝、无效证书/私钥拒绝。仅测试用 OpenSSL CLI 临时生成 localhost CA/leaf/PKCS8 DER fixtures，TLS 加解密/证书验证均由编译 Rustls 实施；测试材料不用于生产。新代码**没有** public listener、root PEM 加载、HTTP 响应、已授权会话、旧撤销迁移或 VPS 部署。
- **第一轮真实失败**：首 SHA [Linux #44227662295](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227662295) core FAILED：原 121 + 13 + 9 回归全部通过，但新增 Rustls 模块被 `RUSTFLAGS=-D warnings` 拦下一个未用 `Read` import，**协议测试尚未执行**；第二 commit `63f84bce...` 只删除无用 import、未关闭 `-D warnings`、未 skip/ignore 任一测试。
- 最新 SHA CI [Linux #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860)、[GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808)、[MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692) **本节书写时在执行**，必须逐一检查新 SHA 的完整 Jobs/原始 Rust logs；红例必须追踪修正后重新完整跑 CI，不得借用父 #21 绿。
- 即使 TLS lab 回归全绿，**生产 SEC-02 P0 仍 OPEN**：原 Python `context.wrap_socket(httpd.socket)` 位于 listening socket accept 前仍在生产；Rust 实验模块无真实服务端 listener/证书部署/授权/HTTP response，也未完成 SEC-01/08 Revoked tombstone 独立可信迁移、root/SSH 多写者排他、VPS root systemd/reboot/rollback、Windows 真机 UAC/WFP 验收。SEC-01/02/08 和 Issue #5 OPEN、全部安全 PR Draft/unmerged。



## D.67 PR #22 正式 Rustls TLS1.2 实际 wire CI（新 SHA Linux 两 Job 全绿）（2026-11-18）

- **精确代码 SHA `63f84bce9c75865727d2d8b409d08b4198d4d181`**；[Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) 叠 #21；[Linux workflow #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860) **两个 Jobs Completed/Success**，原始 core 日志 **121 library / 0 failed/ignored、13 既有 handshake/request + 9 严格 HTTP TCP 回归 /0 failed/ignored、7 条真实 TLS1.2 加密握手+解密后 HTTP 测试 /0 failed/ignored**；在 TLS feature 下还重跑九条 HTTP parser。另一个真实 Linux WireGuard kernel/netns Job 1 test 和 root-owned tmp FS 原子退役 7 tests 成功。Linux 维持 `--locked`、`RUSTFLAGS=-D warnings`，不是 fake handshake。
- 新七项真实 TLS 测试原始日志各为 `... ok`：`tls12_real_encrypted_get_and_post_reach_only_decrypted_http_parser`、`tls12_wrong_server_name_fails_certificate_validation`、`tls13_only_client_rejected_without_http_request_handler`、`idle_tls_client_times_out_but_healthy_tls12_peer_is_independent`、`tls12_decrypted_slow_header_trickle_cannot_extend_request_deadline`、`tls12_malformed_content_length_is_rejected_after_decryption`、`invalid_empty_certificate_and_key_rejected_before_network_accept`。OpenSSL 仅测试生成短期本地测试 CA + leaf/cert/PKCS8，真实 TLS1.2 双端/证书链验证由 Rustls 0.23.46 ring 完成，非用 Python/OpenSSL 进程跑 TLS 服务端。
- **首 SHA 真实 CI 故障保留**：`d205763fe8e4eb774a9be1ed216fc8105f56d41c` 的 [Linux #44227662295](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227662295) core **Failure**：Rustls 新实验单测因一个 `unused import Read` 在严苛 `-D warnings` 阶段未能编译执行；旧 121/13/9 已通过。新 `63f84bce...` 仅删除未使用的 Rust import，不允许警告、不忽略单测，Linux 全量复跑成功。不能把首 SHA 写成全绿。
- 对父 PR #21 精确 compare 6 个文件：server-rs `Cargo.toml` + `Cargo.lock`（追加 7 个与主客户端现有 lock 完全一致的 rustls 0.23.46 依赖版本校验，旧独立包原内容除新增 rustls direct dep 外未修改）、`src/lib.rs`、`src/http_one_request.rs` 改用泛型 Read、`src/tls_wire.rs`（新真实 rustls TLS 模块）、现有 Linux CI。所有 feature 默认禁用；不改 Windows 产品模块、旧 Python 或 main。
- 新 SHA [MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692) 已完成 Rust Build 正在 SEC-10 测试；[GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808) 仍在 GNU Rust 构建；**必须核实两套完整 CI 终态后才能声称三平台 Success**。父 #21 的 CI 不得移植到新 SHA。
- 即使三平台全绿，用户线上 `assets/tc-pair.py` 仍是在 listening socket 先 `SSLContext.wrap_socket` 后 accept，SEC-02 P0 生产 slow TLS DoS 仍暴露；新 Rust lab **没有** root PEM 证书部署、公网 listener、任何 HTTP JSON response、Bearer/PairRequest 可信授权、Revoked tombstone/Consumed 历史全写者隔离或服务器 VPS cutover/rollback。测试信任的是临时 CA，不是用户已 pin 的生产证书。SEC-01/02/08、Issue #5 OPEN，所有 PR（包括 #22）Draft/unmerged；Windows UI、连接/WFP persistent BLOCK/main 完全保持原状态。



## D.68 PR #22 最终代码 SHA Linux/GNU/MSVC 三平台全绿，SEC-02 生产仍阻塞（2026-11-18）

- 新 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) Rust HEAD **`63f84bce9c75865727d2d8b409d08b4198d4d181`**；按此准确 SHA 核验 [Linux #44227864860](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864860) **两个 Job Completed/Success**（121 Rust lib/0 fail/ignored；旧 13 handshake/request、9 HTTP parser 原生 TCP tests/0 fail/ignored；**7 个真实 Rustls TLS1.2 加密证书/解密后 HTTP loopback tests /0 fail/ignored**；独立内核 WG netns 和 owner-only tmp 退役回归 Success），`--locked`、`RUSTFLAGS=-D warnings` 未放宽。
- 同新 SHA [Windows GNU #44227864808](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864808) **Completed/Success**，原始日志 Rust GNU 构建、Release `SPIDERVPN_ROOT` 信任检查、Guard IPC/身份和旧 SSH `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok`；有原仓既存 unused import/unused mut 编译 warnings（不能称 0 警告）。[Windows MSVC #44227864692](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227864692) **Completed/Success**：Rust Build、SEC-10、SEC-01、全部 integrations、changed Rust modules、final portable Rust suite **各步完整 Success**，原始终态为 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered（原有环境依赖）**，无新跳过失败测试。三 CI 的 `head_sha` 均精确等于 `63f84bce...`，不借用父 PR/旧 commit。
- 保留历史首 SHA `d205763fe8e4eb774a9be1ed216fc8105f56d41c` [Linux #44227662295](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44227662295) core **Failure**：严格 `-D warnings` 下 Rustls test-only unused `Read` import，旧 121/13/9 均 pass，新 TLS tests 当时没运行。Rust 第二 commit `63f84bce` 只删无用 import，没改掉 `-D warnings` 或删/skip 用例；新 SHA 真 TLS 全部通过。
- 与 #21 的差异仅六个服务端 Rust/manifest/lock/CI 文件。服务器 `Cargo.lock` 原有 31 个 package blocks **无一修改**（独立 server 根包只追加 `rustls` direct dep），仅加入与客户端同版本及 checksum 的 `log, once_cell, rustls, rustls-pki-types, rustls-webpki, subtle, zeroize` 7 crate；真实 TLS1.2 使用 Rustls 0.23.46 ring backend，无客户端与生产 Windows/WFP 代码更改。旧 Python `tc-pair.py` 仍在生产，root-only TLS cert/key 默认为 `/var/lib/tradechannel/pairing-rs/tls.crt` 和 `tls.key`；新测试只信临时 CA，**不证明原证书/指纹与客户端兼容**，也**不执行实际服务端监听/HTTP 回应/邀请授权**。
- **生产 DoD 未完成，不得合 main**：老 Python 在 listener 上完成 TLS handshake 前仍可能堵 accept（SEC-02 P0）。还需受信且拒 symlink 的 root-only PEM 文件读取与既有指纹不变证明、真正 Rust TLS1.2/HTTP JSON 响应端（默认禁止未经可信撤销历史授权）、SEC-01/08 可信 Revoked/Consumed ledger + 全 root SSH writers 禁止、VPS systemd/端口迁移/重启/回滚和 Windows 双账户 UAC/WFP 实机测试。SEC-01/02/08 和 Issue #5 继续 OPEN；PR #22 与所有祖先 **Draft/unmerged**，main/UI/连接/WFP persistent BLOCK 不动。



## D.69 PR #23 旧证书可信 root 读取与 DER 指纹门禁（2026-11-18）

- 旧代码核对：`assets/tc-pair.py::cert_sha256` 的 `sha256_hex(openssl(["x509","-in",CERT,"-outform","DER"]))`、`src/pairing.rs::PinnedCert::verify_server_cert` 的 `super::jwk::sha256_hex(der)==self.pin` 完全一致：**对服务器叶子证书 DER 求 SHA256、64 位小写 hex**（不是 PEM 文件 hash）；客户端同时验证叶子证书有效期。现役旧 Python `ROOT=/var/lib/tradechannel/pairing-rs`（旧服务可能受 `TC_PAIR_ROOT` env 影响）、`CERT=ROOT/tls.crt`、`TLSKEY=ROOT/tls.key`；新 Rust 模块**固定**生产路径且完全不信外部 ROOT/config。
- 新 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23) stacked on **三平台 CI 完整 green** 的 [Draft PR #22](https://github.com/weixiaochuchen618-debug/spidervpn/pull/22) `63f84bce9c75865727d2d8b409d08b4198d4d181`；branch `fix/sec02-trusted-tls-cert-pin-loader-20261118`，代码 commits: `03f1cccc056e7cee52f6ed8588b0167d351bc618`（最初新增），`ed69fc02f76f864e718042537a7b8f78e8616084`（修编译），当前 **`5c4b9a16d08f96c3501aa5876a48e644a3d55cdf`**（修真实 X509 测试 CA/leaf）。只有服务端 Rust 新 `tls_identity.rs`、Cargo.toml/Cargo.lock 可选直连 `zeroize=1.9.1`、lib.rs feature gate 和 Linux CI 共五文件；`linux-tls-identity-lab` **default OFF**、不接生产 TLS listener，不改 main、Windows UI/连接/WFP persistent BLOCK 或 Python 服务。
- Rust 实现 `read_existing_production_identity(expected_pin)` **只读**，需真实有效 UID 0，`File::open("/")` 固定组件 `var/lib/tradechannel/pairing-rs` 逐段用 Linux `openat(O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC|O_NONBLOCK)` + post-open FD 元数据校验 root 属主、父目录不可组/世界写、末目录 0700；各私钥/证书单组件 `openat(O_NOFOLLOW|O_NONBLOCK)`，严格普通文件 root owner、`nlink=1`、私钥必须 0600、证书不可低权限写、证书 PEM ≤128 KiB、私钥 PEM ≤32 KiB；允许早期旧 RSA 私钥 PKCS1/PKCS8 PEM，由已锁定的 rustls-pki-types `PemObject` 解析，不手写 Base64；私钥 PEM RAM 通过 `zeroize::Zeroizing` 自动擦除。**要求传入独立可信**旧 invite/操作员 pin：原始叶子 DER SHA256 不匹配、格式非法、证书/密钥不成对则 fail-closed；加载成功只生成 TLS1.2 Rustls config，**不是已授权 PairRequest**。未认证 token/Revoked/Consumed 不会迁移/读取，绝不签发或授权隧道。
- Linux 首 SHA [#44232824851](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44232824851) 因新测试直接读取 rustls 私有 `ServerConfig.versions` 字段 **E0616 两处编译失败**；`ed69fc02...` 改由公开 `ServerConnection::new` + 真 TLS loopback 验证，未抑制编译错误或 skip。第二新 SHA [#44233060733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233060733) Linux root tests **7/8 PASS、1 FAIL**：测试生成的 self-signed 叶子错误带 `CA:TRUE`，标准 rustls verifier 正确拒为 `CaUsedAsEndEntity`；`5c4b9a16...` 仅修**测试材料**：独立 CA:TRUE 签发 CA:FALSE、SAN=localhost 叶子，**没有**放宽 rustls 证书验证；历史真实失败保留。注意：旧 Python `openssl req -x509` 自签证书的真实 X509 extension 需要未来**单独核对**；本 PR 临时 CA:FALSE 测试不能宣称用户旧证书/客户端 pin 在现机已兼容。
- 最新新 SHA [Linux #44233312502](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312502) **两 Jobs Completed/Success**：原 core **121 library +13 handshake/request +9 HTTP parser +7 真实 TLS rustls tests** 均 pass/0 fail/ignore；**8/8 新 TLS PEM/DER pin/permission/symlink/hardlink/ancestor/size/real TLS cert+key 测试**在 normal runner 与 **真实 UID=0** 隔离 runner 各执行成功，root job 真 WireGuard kernel/netns 1 test 和原 root retirement 7 tests 成功，`--locked`、`RUSTFLAGS=-D warnings` 不降低。原始新 root 8/8 与 original root WG 1/1 logs 已核对，未跳过任何旧失败。
- 同新 SHA [GNU #44233312449](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312449)、[MSVC #44233312496](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44233312496) **此文撰写时仍 in_progress**，必须查最终完整 Job 和原始日志；父 #22 三平台已绿不能借作 #23 的结果。
- 即使所有 CI 成功，SEC-02 生产 **OPEN**：旧 Python 仍对 listening socket `wrap_socket` 引发慢 TLS accept DoS；新 Rust 默认关闭的只读 root loader 从未在用户真实 VPS 上验证过证书 owner/mode/指纹/到期/实际 pin 来源，也没有安全全局 root writers/旧 Revoked tombstones、HTTP JSON 响应、独立最小权限 listener 和 TLS 切换 rollback，Windows 真机 UAC/WFP 持久阻断接受测试也缺失。SEC-01/02/08 和 Issue #5 OPEN，PR #23 及全部父 PR Draft，不合 main。



## D.70 PR #23 非测试 Rust 编译审查 + 最新 SHA Linux/GNU 完整成功（2026-11-18）

- 在 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23) 之前成功的 `5c4b9a16d08f96c3501aa5876a48e644a3d55cdf` 基础上自审查：Rust `#[cfg(test)]` 的 `std::fs` import 可能掩盖 `--features linux-tls-identity-lab` **非测试库**编译告警。新 Rust commit **`163ef8fecbe5216b758da4794966700b5f6d38ae`** 将 `fs` import 移进测试模块，同时增强现有 Linux CI 在严格 `RUSTFLAGS=-D warnings` 下运行 `cargo build --locked --manifest-path server-rs/Cargo.toml --features linux-tls-identity-lab --lib`，与旧所有编译/专项回归并存；无 test skip/ignore、无警告放宽、default-off 仍不变。与父 #22 比较总计仅五个服务器端 `server-rs` Rust/Cargo/CI 文件。先前 PR #23 两次失败见 D.69，不得删。
- 此新 SHA [Linux #44234674040](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674040) **两 Jobs Completed/Success**，原始日志 feature-enabled **non-test library Build 成功**，原核心 121 lib + 13 handshake/request + 9 HTTP1.1 parser + 7 真实 Rustls TLS1.2 encrypted/decrypted wire 回归全部通过/0 failed/ignored；新增 8/8 TLS key/root/DER pin 安全测试在普通用户 & **真实 root UID=0** CI VM 也各通过/0 failed/ignored，root 真 WG netns 1 test 和原 root-only Python writer 退役 FS 7 tests 成功，`--locked`、`-D warnings` 强制保留。
- 同新 SHA [GNU #44234674093](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674093) **Completed/Success**，Rust GNU 真实构建、Release root env 信任、防护 Guard IPC/身份、原旧 SSH writer 门禁 `deploy::tests::sec01_sourced_transport_reads_refuse_retired_pairing_host ... ok` 均成功；原仓的 GNU unused import/unused mut/unused variable 编译 warnings 仍存在，不得称零 warnings。[Windows MSVC #44234674573](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44234674573) 此节书写时 Rust 编译、SEC-10、SEC-01、integrations **各步 Success**，changed-modules regression 与 Portable Rust 全量 **仍待完整最终结果**；不能称三平台 CI 已全绿。
- SEC-02 仍在生产中暴露：旧 Python TLS 包监听 socket 阻塞 accept；尚未在用户实际 VPS 用原 `tls.crt`/`tls.key` 与**独立可信旧邀请码 pin** 验证 owner/mode/X509 扩展/到期/指纹/客户端握手。尤其旧 Python `openssl req -x509` 自签叶子可能与本 PR 标准 CA:FALSE 测试叶子不同，真实既有邀请码兼容验证需独立补齐。无可信授权的请求不能访问生产状态、无 Rust 响应与 port/service cutover、无 SEC-01/08 legacy revoked ledger 全 root 写者排他、无 Windows UAC/WFP 真机验收。SEC-01/SEC-02/SEC-08 + Issue #5 OPEN，PR #23 Draft/unmerged，main/UI/连接/WFP persistent BLOCK 不动。



## D.71 PR #24 真实 TLS1.2 后只拒绝、不授权的旧协议 JSON 响应（2026-11-18）

- 审查最新 `main=857ea7593941ce79f6507db5b1ced076c3a077ba`、Issue #5 Open，父 [Draft PR #23](https://github.com/weixiaochuchen618-debug/spidervpn/pull/23) 真实 HEAD `163ef8fecbe5216b758da4794966700b5f6d38ae` **Linux/GNU/MSVC 同 SHA Completed/Success**：Linux #44234674040 真实 root PEM 8 tests（普通+root）、7 TLS12 加密、旧 13 admission+9 parser、121 lib、真 WireGuard kernel netns/root FS success；GNU #44234674093 complete success；MSVC #44234674573 complete success，原始 portable `1429 passed; 0 failed; 1 ignored; 8 filtered`（原有）。其他 Agent 已完成 root certificate read-only loader，禁止重复改动/覆盖。
- 当前 stacked [Draft PR #24](https://github.com/weixiaochuchen618-debug/spidervpn/pull/24) 在 #23 上，branch `fix/sec02-failclosed-tls-http-response-20261118`，初次 Rust HEAD **`4f1c13715e5eb734879a1212377fb53b60e7ce6d`**。仅更改 5 个 server-rs Rust/CI 文件：新增 `server-rs/src/http_fail_closed.rs`、`server-rs/src/tls_wire.rs` 复用相同实际 TLS12 握手/增加拒绝响应路径、`server-rs/src/lib.rs` feature-gated 模块、`server-rs/Cargo.toml` opt-in `linux-http-deny-response-lab`、原 Linux CI 步骤。默认 OFF、不接生产 Python/UI/连接/WFP。
- 漏洞边界：在可信 SEC-01/08 Revoked/Consumed 状态、真实 Bearer checker 尚未安全迁移前，不能把 TLS1.2 握手通过和解析到 `Authorization: Bearer` 视为配对授权。新 `serve_denial_only` 在真实 `rustls::Stream` **解密后的 HTTP/1.1** 数据上严格解析一条请求，合法请求一律返回旧客户端认可的 `HTTP/1.1 500` + `{"Code":"InvalidState","Ok":false}`，请求格式 InvalidData 返回 `HTTP/1.1 400` + `{"Code":"InvalidRequest","Ok":false}`；其他 IO 错误/超时直接失败关闭。响应 `Content-Type: application/json`、精确 `Content-Length`、`Connection: close`，不回显原 bearer / body、不返回 `Ok:true`、从不读取/更新 invite 或 WG，单个受限 request worker 响应后发送 TLS close_notify 并关闭，没有 keepalive 或第二个 handler。HTTP 500/400 envelope 和生产 200 success routing 尚未得到真实授权支持，不得把本 PR 叫正式 listener。
- **初始代码 SHA Linux 真验证成功**：[Linux #44241916382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916382) **2/2 Jobs Completed/Success**，新 `http_fail_closed::tests` **5/5** /0 failed/ignored（旧 JSON envelope、真加密 TLS12 GET+POST deny、加密重复 CL malformed 400、pipelined 第二请求不分派、错误请求不可成功）；Rust `--locked`、`-D warnings` 严格非测试 library feature 编译通过；原 121 lib、13 admission、9 parser、7 Rustls TLS、8 root PEM 在普通用户及 real UID=0 下、真实 WG kernel netns/root FS 继续通过，无跳过失败 tests。
- 同 SHA [Windows MSVC #44241916397](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916397)、[GNU #44241916434](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916434) 初始记录时仍在 Rust 编译；**需先查新 SHA 完整 CI 终态与 Windows 原始日志再宣布三平台全绿**。父 #23 已绿不可代替新 PR #24 结论。未做真实 production JSON HTTP client 证书 pin 与 SSL1.2 现役双端测试。
- **安全 DoD 仍 BLOCKED**：线上的 `assets/tc-pair.py` TLS `context.wrap_socket(httpd.socket)` 仍可能阻塞 accept；无安全授权方即一律拒绝，不能签发/消费邀请。还缺老自签生产证书 CA:TRUE 与客户端 pinned cert 实机兼容、独立可信旧 Invites/Revoked/Consumed ledger 状态及全 root SSH writer 排他、实际 Rust HTTP JSON success/拒绝路由、root 最小权限安全服务监听、VPS 端口切换/停用 Python/reboot/rollback、真 Windows UAC/WFP fail closed 实机证明。SEC-01/02/08、Issue #5 OPEN，PR #24 及全部父 PR Draft/unmerged，不得合 main。



## D.72 PR #24 同最终 Rust SHA Linux/GNU/MSVC 完整 Success，生产认证仍不开放（2026-11-18）

- 最终最新 Rust HEAD **`4f1c13715e5eb734879a1212377fb53b60e7ce6d`**，新 stacked [Draft PR #24](https://github.com/weixiaochuchen618-debug/spidervpn/pull/24) 相对 #23 的 GitHub 精确 compare 仅 5 个 Linux server Rust/feature/CI 文件（新 `server-rs/src/http_fail_closed.rs`、`server-rs/src/tls_wire.rs`、`server-rs/src/lib.rs`、`server-rs/Cargo.toml`、原 Linux CI yaml）。默认 `linux-http-deny-response-lab` OFF；没有对现役 Python、main、Windows UI、连接、WFP permanent BLOCK 修改。
- 精确同一 SHA 的 [Linux #44241916382](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916382) **2/2 Jobs Completed/Success**：新 **5/5** 真实 TLS1.2 JSON error-envelope 测试/0 failed/ignored，正常 GET/POST（包括任意 Bearer）一律 `500 {"Code":"InvalidState","Ok":false}`，恶意重复 Content-Length `400 {"Code":"InvalidRequest","Ok":false}`，精确 `Content-Length`、`Connection: close`、TLS close_notify，pipelined 无第二个响应，Bearer 不回显；新 feature 的**非测试 Rust library cargo build** 在 `--locked` / `RUSTFLAGS=-D warnings` 下成功。原 121 lib、13 handshake+request admission、9 HTTP framing、7 rustls TLS1.2 crypto wire、8 root-owned TLS PEM/pin 普通用户+真实 root UID=0、Linux 真 WG/netns + owner-only root FS regressions 均成功/0 newly failed/ignored。
- 同 SHA [GNU #44241916434](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916434) **Completed/Success**，Rust GNU 编译、Release inherited root env 防护、Guard IPC/身份与旧 SEC-01 SSH writer gate 的原始日志均通过；既存 GNU compiler warnings（unused imports/mut）没有声称消除。 [Windows MSVC #44241916397](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44241916397) **Completed/Success**：Rust Build、SEC-10、SEC-01、all integrations、changed-module regressions、最终 portable unit suite 全部 steps Success；原始末行 **1429 passed / 0 failed / 1 ignored（原有）/ 8 filtered（原有环境依赖）**。不冒用父 PR/其它 SHA 的 CI，无 skip/allow 绕过失败。
- 注意 **TLS 握手只是验证服务器身份，不是验证请求者配对资格**。由于缺 SEC-01/08 可信旧 `Invites`、Consumed、Revoked ledger 与全 root writer 隔离，本 PR 新 Rust 测试路径无任何成功配对授权，`Ok:true` 永不会返回，也不读写任意 WG/邀请状态；此特性禁止直接充当正常用户接收服务。现役 Python listener 上的 TLS `wrap_socket` 慢握手 accept DoS 仍存在，**SEC-02 P0 生产风险没有因本 PR CI 成功而解除**。
- 真实 DoD 未完成：旧自签 CA:TRUE 生产 leaf + 现有客户端 PinnedCert/历史邀请码 pin 兼容、可信 read-only root cert 来源证据、正式授权与 JSON success/deny HTTP 路由、真正 Rust listener/systemd/root 最小权限 + VPS 系统迁移与 reboot/rollback 反向验证、SEC-01/08 全 root SSH 写者停止及历史撤销数据迁移、Windows 真机 UAC/WFP persistent kill switch。**SEC-01/02/08、Issue #5 OPEN，PR #24 与父 PR 均 Draft/unmerged；main `857ea7593941ce79f6507db5b1ced076c3a077ba` 未变。**



## D.73 PR #25 有界真实 localhost TLS accept 链（2026-11-18，CI 进行中）

- **选择的未闭环 P0：SEC-02**；当前正式生产 Python listener 仍有 TLS 握手阻塞 accept 风险，**不称已修复**。[Draft PR #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25) 叠在 [Draft #24](https://github.com/weixiaochuchen618-debug/spidervpn/pull/24) `4f1c13715e5eb734879a1212377fb53b60e7ce6d` 上，新 Rust HEAD **`b2f6a19356dfc1ee90db734586151d79ebaf7df2`**，branch `fix/sec02-loopback-bounded-tls-listener-lab-20261118`。主仓 `main=857ea7593941ce79f6507db5b1ced076c3a077ba` 未改，WFP Draft #3 保持持久 BLOCK 原样，Windows UI/连接交互和部署中的 Python 也未更改。
- 精确 compare 仅五个文件：`server-rs/src/loopback_denial_lab.rs`（新 Rust finite accept）、`server-rs/src/http_fail_closed.rs`（新增四个真实 localhost 对抗测试）、`server-rs/src/lib.rs`（条件模块）、`server-rs/Cargo.toml`（`linux-bounded-accept-lab` 默认 OFF）、`.github/workflows/security-pairing-rust-linux.yml`（严格 lint / 非测试 Build / 专项 Rust tests）。没有 Python/PowerShell 新安全逻辑、新 bin/service/public bind、没有 WG/ledger 读写或授权成功路由。
- 有界 accept 仅接受调用者传入的 **loopback 监听 socket**，拒绝 `0.0.0.0`/公网通配地址；数量 1..64、受限 100ms..5s accept window；真实 `accept` 每连接走既有独立 Rustls TLS1.2 handshake permit + request permit + 严格 HTTP1.1 一次解密解析 + 固定 JSON fail-closed response；超额连接直接丢弃，所有接受/拒绝/worker 失败分别计数，结束 join、不得假报成功。未接公开监听进程，不能用作生产。
- 新测试包含：① 空闲 TLS 与健康 TLS1.2 并行 accept、请求仅返回 `500 {"Code":"InvalidState","Ok":false}` 且 Bearer 不回显；② permit=1 满载立即拒绝，超时后重新接入健康 TLS，不泄漏 permits；③ 拒绝 wildcard/public bind；④ 拒绝无限数量/窗口，没客户端时会有限超时。旧 TLS、HTTP、权限、WireGuard netns 测试仍运行，**未 skip/ignore**。
- 当前同 SHA CI 首次已生成：[Linux #44249576605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576605)、[GNU #44249576563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576563)、[MSVC #44249576553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576553)。**此节记录时三个 workflow 均为 In Progress，不得标记成功**。下一步检查每条完整 Job/SHA 和原始日志；任何红例先修源码/测试真实缺陷、不要降低 `-D warnings` 或删 assert，再重跑所有目标。
- **必须维持 SEC-01/02/08、Issue #5 OPEN 和 PR #25 Draft/unmerged**。仍缺：现役 Python 服务安全退场、legacy 真实 X509/DER pin 与客户端双端兼容、可信 Revoked/Consumed 历史/全旧 SSH writers 排他及鉴权、真实 Rust HTTP 成功/拒绝路由、root-only systemd/VPS 端口 cutover+reboot+rollback、Windows 多账户 UAC/WFP 持久零泄漏验收。实验测试全绿不满足生产 DoD。


## D.74 PR #25 Linux 原始日志确认：真实 TLS accept 四项全部绿（2026-11-18）

- **Rust HEAD 精确 `b2f6a19356dfc1ee90db734586151d79ebaf7df2`**，[Draft #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25)；[Linux #44249576605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576605) 的 `head_sha` 与其完全一致，两个 Jobs `linux-pairing-authority-core` 和 `linux-kernel-netns-sec01-acceptance` 均 **Completed/Success**。核心 Job 原始 logs 的 `--features linux-bounded-accept-lab --lib` **非测试 build 通过**，Rust `-D warnings`、`--locked` 严格保留。
- 新 `http_fail_closed::tests::loopback_accept_capacity_exhaustion_closes_socket_and_recovers`、`loopback_accept_handles_idle_and_healthy_tls12_independently`、`loopback_accept_has_finite_count_and_timeout_without_clients`、`loopback_accept_rejects_wildcard_public_binding_before_accept` **全部输出 ok**；加原有五条 TLS deny 测试共 **9 passed / 0 failed / 0 ignored**。同一新 feature 下原 Rustls TLS true encrypted wire **7 passed / 0 failed / 0 ignored**，既有原基础库 **121 passed / 0 failed / 0 ignored**；root-only TLS PEM 8/8、Linux 真 WG kernel/netns 1/1、原 root FS 7/7 仍绿。没有增加测试 skip/ignore，也没有修改生产 listener/授权路径。
- Windows [GNU #44249576563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576563) 与 [MSVC #44249576553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576553) 在本节核查时同 SHA、仍执行 Rust 构建，不能提前认定绿色。必须核查最后的全 Job 终态和非跳过日志；原有 GNU warnings 和 MSVC 既有环境依赖过滤不得误称新增测试失败/修好。
- **SEC-02 P0 持续 OPEN：这不是正在服务的 TLS listener**。新 accept loop 仅本地、默认编译关闭且没有 binary/systemd；现役 `assets/tc-pair.py` 的握手阻塞接收器没有被替换。历史 revoked/consumed 状态真伪/授权验证、生产 TLS X509 pin、VPS root systemd+重启回滚与 Windows UAC/WFP 实机 DoD 未满足，Draft PR #25 不可合 main；Issue #5、SEC-01/02/08 不关闭。


## D.75 PR #25 同 SHA 三平台完整 Success，生产 P0 仍 OPEN（2026-11-18）

- [Draft PR #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25) 的代码 HEAD `b2f6a19356dfc1ee90db734586151d79ebaf7df2` 对应 [Linux #44249576605](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576605) 2/2 jobs、[GNU #44249576563](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576563)、[MSVC #44249576553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44249576553) 全部 **Completed/Success**。核验 MSVC 真日志为 `1429 passed; 0 failed; 1 ignored; 8 filtered out`（原有排除保持不增）；所有 build/SEC-10/SEC-01/integration/changed modules/portable suite 步骤 success；GNU 正常构建、release root 防护和专项原日志通过，仍有既存 warnings。
- SPEC：仅 loopback、有限接入数与时间、TLS1.2、无授权 HTTP JSON denial；新四项 Linux accept tests 全通过，不能代替生产接收器、实际 VPS 证书/授权/切换验收。main `857ea7593941ce79f6507db5b1ced076c3a077ba` 不动；SEC-01/02/08 与 Issue #5 OPEN，WFP 持久 BLOCK 不改，所有安全候选 Draft/unmerged。

## D.76 新 PR #26：旧自签 RSA X509 证书与真实客户端 pin 边界互补验证（2026-11-18）

- **P0 SEC-02 迁移兼容证据（关联 SEC-07 有效期）**。[Draft PR #26](https://github.com/weixiaochuchen618-debug/spidervpn/pull/26) 叠 [Draft #25](https://github.com/weixiaochuchen618-debug/spidervpn/pull/25) 已全绿 SHA；branch `fix/sec02-legacy-selfsigned-rsa-tls-compat-20261118`，新 head **`1f5ee14500fe4f424555078ef0748a93a0c28024`**。精确 compare 仅 5 文件：`server-rs/src/tls_identity.rs` 内 test-only 新测试、`src/pairing.rs` 内 test-only 三项，以及 Linux/MSVC/GNU workflow。无新增 dependencies、无生产逻辑/Windows UI/连接/WFP/Python 改动；绝不降低 TLS 验证。
- 旧 Python `ensure_cert` 使用 `openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes -keyout tls.key -out tls.crt -subj /CN=...`。Linux test 复制同命令在隔离 owner-only temp dir 生成短期测试材料，核查实际 CA:TRUE、无 SAN、RSA，独立 OpenSSL DER SHA256 比对 Rust hash，错误 pin 拒绝；由既有 Rust protected loader + bounded loopback TLS1.2 denial 服务真实监听，OpenSSL **正常证书验证**的测试客户端实际握手及 GET，验证仅返回 InvalidState/Ok:false。普通 Linux 和真实 root runner 均安排执行；不读取生产证书或密钥。
- Windows 三项针对 **既有实际** `pairing::http::get/data/PinnedCert`：利用既有 rsa+rcgen 生成等价自签 RSA CA:TRUE/CN-only/no SAN 测试 fixture，真实 TLS 正确 DER pin 通过但 InvalidState 仍拒绝授权，错误 pin 真实握手失败；使用实际 X509 verifier 的 notBefore-1、notBefore、notAfter-1、notAfter、notAfter+1 时钟边界，匹配 pin 也拒绝未生效或过期证书。**Linux 和 Windows 是互补端点测试**，不冒充 Windows actual client → 用户 VPS 或同一真实证书双端验证。OpenSSL 仅测试工具，所有产品安全逻辑仍 Rust。
- 新 SHA CI 首轮 [Linux #44253155134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155134)、[GNU #44253155155](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155155)、[MSVC #44253155258](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155258)，**当前 queued，未验收**。必须核对三条准确 SHA 的完整 workflows/原始测试输出；任何真实失败不跳过，修测试或 Rust 后重新执行。Linux `--locked`/`-D warnings` 与全部既有 tests 保留，Windows 旧排除不新增。
- SEC-02 现役 Python 监听握手阻塞漏洞仍未修，SEC-07 证书生命周期/轮换及准确错误分类未完成；缺实际 VPS TLS 文件权限/历史 pin 移交、真正 Windows-to-Linux 认证通信、可信 revoked/consumed 全写者排他及授权、服务切换/reboot/rollback、Windows UAC/WFP 实机验收。SEC-01/02/08、Issue #5 OPEN，PR #26 Draft/unmerged，main 不合并。


## D.77 PR #26 同 SHA Linux 完整通过：旧 OpenSSL 自签证书真实 TLS1.2（2026-11-18）

- [Draft PR #26](https://github.com/weixiaochuchen618-debug/spidervpn/pull/26) 精确代码 `1f5ee14500fe4f424555078ef0748a93a0c28024`，对应 [Linux #44253155134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155134) **Completed/Success**，两 Jobs 均 Success（core 134628444416、real kernel/root 134628445015）。Linux 原始日志明确显示 `tls_identity::tests::sec02_legacy_openssl_rsa_identity_serves_real_tls12_denial ... ok`，普通用户新专项 **1 passed / 0 failed / 0 ignored**，真实 UID=0 环境身份文件回归含新测试共 **9 passed / 0 failed / 0 ignored**。真实使用旧 `openssl req -x509` 命令生成 RSA 2048 自签 CA:TRUE、无 SAN 的 fixture，独立 DER SHA256 比对、错误 pin 拒绝、既有 Rust 安全文件加载→真实 Rustls TLS1.2 有界接收→OpenSSL 正常验证的测试客户端→HTTP500 JSON denial 通过，未弱化验证。
- 既有 Linux 核心库 121/121、admission 13/13、HTTP framing 9/9、TLS wire 7/7、bounded HTTP denial 9/9、loopback TLS、root WG/netns 1/1 及原 root FS 7/7 等测试保持成功；`--locked`、`-D warnings` 保留。没有新增 skip/ignore。Windows [GNU #44253155155](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155155)、[MSVC #44253155258](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155258) **同 SHA 尚 in_progress**，不能提前宣称通过；待核对三项实际 pinned-client Rust tests 和整个 CI 终态。
- 本轮仅补回归证据（测试和 CI，无生产行为、依赖或 UI 改动），不是实际 Windows 客户端→VPS 端到端，更未核验用户历史真实 TLS cert/key 与 pin。线上 Python 握手阻塞漏洞未修，SEC-07 证书生命周期亦未完成。仍须真实 VPS 证书/权限/授权与全写者排他、服务切换和 rollback/reboot，以及 Windows 实机 UAC/WFP，严禁宣称 SEC-01/02/08、SEC-07 已闭环或合并 main。Issue #5 OPEN，PR #26 Draft。


## D.78 PR #26 三平台同 SHA 完整通过（2026-11-18）

- [Draft PR #26](https://github.com/weixiaochuchen618-debug/spidervpn/pull/26) HEAD `1f5ee14500fe4f424555078ef0748a93a0c28024` 对应 [Linux #44253155134](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155134)、[GNU #44253155155](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155155)、[MSVC #44253155258](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44253155258) 均 Completed/Success。Windows 原始日志三项 `pairing::http::tests::sec02_legacy_rsa_*` GNU、MSVC 各 3 passed/0 failed/0 ignored；MSVC 全量 portable 1432 passed/0 failed/1 ignored/8 filtered（原有排除）。Linux 旧证书形状的真实 TLS1.2 独立端点试验与 root 9/9 见 D.77。证据不等于用户真实 Windows 客户端→实际 VPS 历史证书的完整双端验证。
- main `857ea7593941ce79f6507db5b1ced076c3a077ba`、WFP #3 Draft/unmerged 保持不动；SEC-01/02/08、SEC-07 未关闭、Issue #5 OPEN。

## D.79 PR #27 长期运行接收器 + 双阶段总量/来源额度 + 有序停机（2026-11-18）

- **P0 SEC-02 候选实现**：[Draft PR #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27) stacked on #26 已全绿 SHA，branch `fix/sec02-persistent-bounded-listener-20261118`，HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`。6 个 server-rs Rust/Cargo/CI 文件；新增 `linux-persistent-listener-lab` feature default OFF，不新增依赖、二进制、公开 bind 或 systemd 入口。
- `persistent_listener_lab::run_persistent_denial_lab`：无累计 64 次连接上限，可持续 accept；在 accept owner 线程内有界保存 <=64 个 live/unreaped JoinHandle，连同 TLS handshake 和单 HTTP request 全生命周期占用一个连接配额，再按真实 kernel peer IP 独立限制来源（IPv4-mapped IPv6 规范化、不得由 forwarded header/端口扩大配额）。完成立即在循环内回收，无无限 source history/app queue；现有独立握手/请求 deadline 不放宽。饱和连接直接关闭，计数饱和算术，关闭 flag 后先 drop listener 再 drain 有界 worker，旧有限 listener 也修正先关监听再 join。未实现 systemd 信号/强制取消，真实公网 DDoS/IPv6 前缀攻击/NAT 公平性不在此证据内。
- 专项 Rust tests：①源地址规范化；②同一来源完成 TLS 后停留 HTTP 阶段，多连接立即 EOF/RST，新真实 127.0.0.2 源经独立正常验签 OpenSSL TLS1.2 客户端完成固定拒绝，释放后原来源恢复；③全局额度饱和/断开恢复；④80 次连续 TLS 连接（突破旧 64 次生命周期上限），峰值有界；⑤停止时监听 FD 先释放，旧 worker 仍可在时限内 drain；⑥无效容量、wildcard 和预先 stop。未改变任何授权逻辑或生产 Windows UI/连接交互/WFP persistent BLOCK。
- 新 SHA CI 已触发：[Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383)、[GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600)，初次查询 queued，MSVC 后续按精确 SHA 查询（不可拿父 SHA 充当）；新增非 test library build、`--locked`/`-D warnings`，全部原 TLS/HTTP/Rust/root/netns tests 保留，不删失败/不跳过。
- 仍只限本地 fail-closed HTTP JSON denial；线上 Python handshake accept DoS 仍未修复。缺可信现网证书和邀请/撤销历史迁移、所有旧 writers 排他、成功授权路由、实际服务最小权限、VPS 真机切换/reboot/rollback、Windows UAC/WFP real-host DoD。PR #27 Draft，不合 main，Issue #5 OPEN。


## D.80 PR #27 Linux 同 SHA 完整通过（2026-11-18）

- [Draft #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27) HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44` 对应 [Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383) **Completed/Success，2/2 Jobs**（core 134635523525 和 real-root 134635523950）。实际 core 日志：新 mapped IPv4 来源规范化 1/1；新 5 项 persistent_tests 全 ok，含旧 9 项 HTTP denial/有限接收器合集 **14 passed / 0 failed / 0 ignored**。真实跨 kernel source TLS1.2、全阶段来源限制、全局限制与 EOF/RST、80 次连续连接、停止先释放端口、新旧监听器回收通过。非 test Rust library build、`--locked`/`-D warnings` 均绿。既有基本库 121/121、握手/请求 13/13、framing 9/9、TLS wire 7/7、旧证书专项 1/1、root TLS identity 9/9、实际 WG netns 1/1、root FS 7/7 继续成功。
- 准确同 SHA 的 [GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600)、[MSVC #44255321332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321332) 当前 in_progress，待核对完整 workflow 与日志，不冒称通过。新测试没有 skip/ignore。
- 候选只支持 loopback 默认关闭的受限拒绝路径；没有公网、systemd、信号处理/强制取消、真实鉴权、可信生产历史状态和部署切换。SEC-01/02/08 与 Issue #5 OPEN；旧 Python 风险仍未消除、SEC-07 生命周期未闭环，PR #27 Draft，main 和 WFP #3 保持原状。未获得真实验收，不合并。


## D.81 PR #27 GNU 完整通过，MSVC 最终全量测试尚未收口（2026-11-18）

- [Draft #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27) 精确 HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`，[Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383) 与 [GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600) Completed/Success；GNU 完整构建和专项原始日志，RSA pin 3/3，0 failed/ignored。[MSVC #44255321332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321332) 同 SHA 最后一项 portable suite 正在运行，未获得完整终态前不得标绿。#27 本身不改 Windows 产品。
- main `857ea7593941ce79f6507db5b1ced076c3a077ba` 未变，Issue #5 OPEN，所有候选 Draft。实际生产 SEC-02 未修复。

## D.82 PR #28 隔离 Rust 可执行进程可信启动、永久降权与实际信号退出（2026-11-18）

- **P0 SEC-02**：[Draft PR #28](https://github.com/weixiaochuchen618-debug/spidervpn/pull/28) 基于 #27（Linux/GNU 已全绿；MSVC 尚待最终结果），branch `fix/sec02-denial-service-process-lifecycle-20261118`，HEAD `16bd83adf2f26eac783c68a413e9304313943219`。精确 compare 6 文件新增 474 行，无 Windows UI/连接交互/WFP/生产 Python 修改。新 feature `linux-denial-process-lab` default OFF，显式编译 `spidervpn-pair-denial-lab`；仅复用现有锁定 libc 0.2.191（原 transitive，锁文件只新增直接依赖引用）。
- 仅 root 正常启动、精确 `serve-denial-lab <64 小写 DER pin>`，无路径/端口/环境 override；固定隔离 `/run/spidervpn-pair-denial-lab` 中受保护 root-only identity，复用原 openat 无 symlink/单硬链接/严格权限与独立 pin 校验；不访问实际生产 TLS 文件或邀请账本。关闭所有继承非 stdio FD（Linux 5.9+ close_range，失败拒绝），在绑定 socket 前永久降权为数字 UID/GID 65534（仅隔离实验，**不代表正式服务账户政策**），清空补充组，全 real/effective/saved ID 读回，禁止新 privilege、禁止 dump、核查 /proc CapInh/Prm/Eff/Amb 全零，才绑定 127.0.0.1:0。总量16/单源4、握手/HTTP 各3s 实验参数，不改变部署设定。
- 真实 SIGTERM/SIGINT handler 仅存储 atomic stop 标志；绑定前安装 handler 并解除继承屏蔽，停止时复用现有 persistent listener 获得关闭监听→有界 drain→退出。没有 systemd install/signal integration 到现役服务、公开接入、成功授权或 WireGuard mutation；任何响应均 deny-only。
- 测试新二进制严格 argv、真实普通账户拒绝启动；隔离 root CI 子进程验证错误 DER pin、任意地址参数、key 0644 和 symlink 拒绝、真实 /proc UID/GID/Cap/NoNewPrivs 读回、正常验证 TLS1.2 JSON denial，真实 SIGTERM 与 SIGINT 分别触发监听关闭且空闲握手资源排空，退出码0。仅 disposable CI 临时目录，不复用已有目录；成功与否以原始 CI 日志为准。
- 新 SHA [Linux #44256587840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587840)、[GNU #44256587905](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587905)、[MSVC #44256588132](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256588132) 已触发，初次 queued、未验收；核对全部同 SHA workflow、真实子进程专项和原始日志，失败修复不可跳过。旧 Rust library、root、netns 与 Windows 测试继续保留。
- 生产安全验收尚缺：正式低权限专用账户和可信部署配置/VPS 内核兼容、历史真实证书与可信 revocation/consumed ledger、旧 root/SSH 写入者排他、受控授权 HTTP 路径和系统服务切换/reboot/rollback、Windows UAC/WFP 真机。SEC-01/02/08、SEC-07 未关闭；Issue #5 OPEN，PR #28 Draft/unmerged，main 不动。禁止在用户真实 VPS 执行隔离 CI fixture。


## D.83 PR #28 Linux 完整通过：实际 Rust 进程降权、TLS 和两种 OS 信号（2026-11-18）

- [Draft PR #28](https://github.com/weixiaochuchen618-debug/spidervpn/pull/28) 精确代码 `16bd83adf2f26eac783c68a413e9304313943219` 对应 [Linux #44256587840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587840) **Completed/Success，2/2 Jobs**（core 134639626861、privileged runner 134639627340）。实际 core 日志显示非 test Rust bin build 与 `tests::only_exact_command_with_lowercase_der_pin_is_accepted ... ok`，1 passed/0 failed/0 ignored；普通账户实际启动拒绝 exit 2、无 READY。Root job 真子进程测试 `real_root_startup_refuses_unsafe_identity_and_term_int_drain_after_privilege_drop ... ok`，1 passed/0 failed/0 ignored，实际耗时 6.33s，包含两个信号与空闲握手排空；实际 /proc UID/GID/Groups/Cap/NoNewPrivs 验证，错误 pin/不安全 key/任意 bind 拒绝，独立正常验证 TLS client 只收 InvalidState；测试隔离 /run 文件夹已清理。严格 `--locked`/`-D warnings`，所有既有 core、HTTP 14/14、root identity 9/9、real WG netns 1/1 与 root FS 7/7 均成功。无新增 skip/ignore。
- 同 SHA [GNU #44256587905](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587905)、[MSVC #44256588132](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256588132) 尚 In Progress；父 #27 的 MSVC #44255321332 仍待 terminal result，不冒称三平台完成。后续逐一核对相应准确 SHA 的全 workflow 和原始日志。
- 成功证据仅为 disposable CI 实机进程，不是用户真实 VPS，尚未接入生产配对授权、历史撤销状态、正式专用服务账户及部署切换，未满足 VPS rollback/reboot 或 Windows UAC/WFP 实机 DoD。SEC-01/02/08、SEC-07 未关闭，Issue #5 OPEN，PR #28 Draft，main 不变。旧 Python accept 阻塞仍在生产。


## D.84 PR #27 与 #28 同 SHA 三平台已完整通过（2026-11-18）

- [Draft PR #27](https://github.com/weixiaochuchen618-debug/spidervpn/pull/27) HEAD `19765b4c72ac0e2c1902c8646f3a57febe434b44`：[Linux #44255321383](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321383)、[GNU #44255321600](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321600)、[MSVC #44255321332](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44255321332) 全部 Completed/Success，MSVC 原始 1432 passed/0 failed/1 ignored/8 filtered（既有）。
- [Draft PR #28](https://github.com/weixiaochuchen618-debug/spidervpn/pull/28) HEAD `16bd83adf2f26eac783c68a413e9304313943219`：[Linux #44256587840](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587840)、[GNU #44256587905](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256587905)、[MSVC #44256588132](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44256588132) 全部 Completed/Success，Windows 原始专项三项 RSA 通过、MSVC 1432 passed/0 failed/1 ignored/8 filtered。真实降权/进程信号证据见 D.83。二者仍未证明真实用户 VPS 或正常成功授权。

## D.85 PR #29 真实新邀请签名认证与锁内申请验证（2026-11-18）

- **P0 SEC-01/02**：[Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29) stacked on 已全绿 #28，branch `fix/sec01-verified-fresh-consume-gate-20261118`，HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`，7 files +712/-7，无新增依赖、Windows UI/连接/WFP 或生产 Python 变动。新 feature `linux-fresh-consume-gate` default OFF。
- `fresh_consume_gate`：按现有客户端精确 HTTP routes、Host（不再丢弃 parser host）、32-byte canonical bearer 和 ring HMAC 常时比对；独立可信管理 JWK、计算的原 SHA256: fingerprint、绑定/host/port/TLS DER pin；验证旧版双层 RS256 SignedDescriptor + Invite，核对独立信任输入、ledger expiry 与 RetryUntilUtc=expiry+120。锁内仅接受 Open；拒绝过期/取消/Consumed/Pending/Revoking/Revoked。库内实际读成功返回 legacy `InvitationReady/SignedDescriptor` 数据，不是公网 HTTP success。
- POST 必须唯一 PairRequest JSON 字段，递归拒绝重复 JSON keys（包括合法签名中的歧义）；实际 recipient RSA 私钥持有证明 + 严格版本/协议/字段/服务器与邀请绑定；复用实际 TC-ClientRequest-v1 digest/RecipientJwk digest，检查 UTC 日历及未来5分钟（原字符串参加摘要），规范非零 WG 公钥，拒绝不可可信规范化旧撤销键，检查跨邀请 revoke tombstones；产生借用当前锁内 LedgerStore 的 `VerifiedFreshConsume`，**不是 Grant/Pending/授权签名/WG 操作**。无持久状态写入与网络接线。
- 测试使用独立生成的测试 RSA 管理/recipient 两把密钥（OpenSSL 仅 fixture signer，安全判断仍全 Rust）、实际 Rust parser、临时 owner-only durable LedgerStore；GET/POST 正路径、错误 token/Host/route/过期、真实签名 descriptor 与 nested invite 篡改、错误 signer/binding/digest/时间、公钥、重复 JSON、Pending/Consumed/Revoking/Revoked 状态和跨邀请已撤销身份、UTC、既有 golden PairRequest。CI 用 `--locked`/`-D warnings` 非 test 库编译，全部原测试不放宽。
- 新 SHA [Linux #44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843)、[GNU #44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885)、[MSVC #44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) 已触发，未获终态前不得标绿。若失败不跳过，修复后按新 SHA 核对。
- **重要边界/下一步**：旧 SignedDescriptor 并未签名 bearer token，旧邀请文件、签名本身也不能证明未撤销。当前 `TrustedOpenInvite` 是独立已认证可信输入契约，不是可直接信任旧 JSON 的生产 loader；尚须正式认证状态来源、历史撤销/消费证据、全部旧 writers 排他、锁内 Pending→真实 WG→读回→签名/加密结果的完整事务、有限只读 retry、低权限 service/helper 通道与真实 VPS 部署验证。不可因预认证通过就开放生产。main `857ea7593941ce79f6507db5b1ced076c3a077ba`、WFP #3 Draft 保留，Issue #5 OPEN，SEC-01/02/08/07 未关闭，所有修复候选未合并。


## D.86 PR #29 Linux 同 SHA 全量通过（2026-11-18）

- [Draft PR #29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29) HEAD `81b2f57ea8a3779aff3aebb4216e16e12dda0e89`，[Linux #44258780843](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780843) **Completed/Success，2/2 Jobs**（core 134646769263、root/netns 134646769792）。原始 core log `fresh_consume_gate::tests` **8 passed / 0 failed / 0 ignored**，实际 RSA scope/descriptor/inner request 兼容、真实 locked ledger 正路径无写入、token/Host/route/expiry、错误签名者/绑定/摘要/时间/WG 键、签名内外重复 JSON、真实持久账本 Pending/Consumed/Revoking/Revoked 以及跨邀请码撤销拒绝、UTC、原请求 golden fixture 全通过。解析器原 9/9、HTTP TLS 14/14、基础库121/121、真实进程/root/WG netns 同步通过。严格非 test Rust build、`--locked`/`-D warnings`，未增加跳过。
- [GNU #44258780885](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780885)、[MSVC #44258780872](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44258780872) 均准确 SHA in_progress，待完整终态及日志。未部署，无真实授权成功事务或历史迁移。下一步优先可信 scope/token 持久层及有限 retry/真实事务。SEC-01/02/08/07、Issue #5 OPEN，main/WFP/UI 保持，所有候选 Draft。


## D.87 COORD-01 整改账本补充：2026-11-19 §23 当前状态与冻结证据索引
本节替代前述历史快照中的当前HEAD/CI_PENDING描述，不删除历史证据，不替代原DoD；具体任务归属、写锁、授权基准及恢复步骤以 [TASK_ASSIGNMENTS.md](./TASK_ASSIGNMENTS.md) §11–23 为准。依据总控授权 [3992eba87e297eaa98ab53341775db3fbb602633](https://github.com/weixiaochuchen618-debug/spidervpn/commit/3992eba87e297eaa98ab53341775db3fbb602633)、本轮两次PR HEAD复核及准确SHA的CI状态，无新候选变动。

| 缺陷/跟踪项 | 当前证据边界 | 尚未达到的条件 |
|---|---|---|
| SEC-01/08、R01-005/007/010 | #29 Rust fresh gate、WG只读/真实netns及L1本地锁内证据隔离候选，任务表§8–13已有验收 | L2/L3独立撤销历史/恢复域与实际执行隔离、真实成功授权事务/WG/迁移；生产Python未替换 |
| SEC-02/07、R01-004 | #28 denial-only TLS/降权/停机及#29继承FD/stdio隔离候选，§15–16 | 实际合法成功授权、证书轮换、独立服务身份、VPS切换/回滚及生产并发验收 |
| SEC-03/10、R01-008/012 | #6候选、#29 R01-012实际启动/探测门隔离PASS及A1候选构建/打包验证器隔离PASS（§19/21） | 实际独立可信工具/引擎/DLL/license/包外approval、固定Rust release及完整真实打包、受保护stage/旧写者/UAC/安装升级；008-B仍QUEUED |
| SEC-09、R01-009 D1/D2/D3 | D1有界同句柄只读隔离PASS；D2-LAB FAIL/ACTIVE；C生命周期锁原语隔离PASS | D2实际同对象删除隔离尚失败；实际可信恢复入口、共同生命周期门及真实安装/卸载未接线或未验 |
| WFP-01/02/04、R01-002 | #3 A2/A3a/A3b-LAB和DENY及生命周期隔离实证，§13–23；真实unknown history gate拒绝新许可 | 全机可信历史及旧writer/迟到RPC、实际产品跨进程接线、跨SID/UAC、持久BLOCK/recovery |
| WFP-03/05 | 未完成生产TUN/Wintun及实机零泄漏 | 真实Proxy/TUN IPv4/IPv6故障、端口劫持、断网/重启及抓包/独立BFE读回 |
| SEC-04/05/06/11、AUX | 保留原任务表§2及本账本全部风险与既有候选，不在本轮宣称新增完成 | 与既有权限/共享文件边界及完整原DoD相符的后续整改/审查 |

**当前复核恢复点**：
- [#29](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29) `fix/sec01-verified-fresh-consume-gate-20261118`：`f3b92e920a52f7689f159e9599abb8c1401d8b05`。D2-LAB新增五项在 [MSVC 44486609014](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44486609014) 和 [GNU 44486609016](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44486609016) 均11 passed/5 failed， [Linux 44486608927](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44486608927) success，Windows后续未跑不能算绿。实际报告 [D 7003940517](https://github.com/weixiaochuchen618-debug/spidervpn/pull/29#issuecomment-7003940517)。路径一致性拒绝已确认，具体根因未确认；B仅原test-only范围整改，不改变D1严格生产判据，不减测试。冻结A1准确SHA096e2c9ff91d01bcec71dd99ab6a22d9b0edd30a的绿灯不能替代当前失败HEAD。
- [#3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) `fix/wfp-trade-egress-p0-20261116`：`bde8e360f8aa1d89db130e968e1bc896bc7664ca`，[MSVC 44486688478](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44486688478)/[GNU 44486688576](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44486688576) success。独立 [D 7004080316](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3#issuecomment-7004080316)，MSVC1448/0fail/2原ignored/8原filtered，实际同SID不同进程互斥、Token/DACL、预创建/abandoned拒绝、外锁持有时真实动态fixture许可撤销；新增TCP10=5允许/5拒绝10013。跨SID、生产门、产品持久BLOCK未证明；GNU特权父NOT RUN。冻结已验收实验，不重新开启许可或重复实验。保留旧失败。
- main仍 `857ea7593941ce79f6507db5b1ced076c3a077ba`，#3/#29 Draft、#6/#28依赖链不重写，Issue #2/#5保持OPEN；无新增合并准入，**16项原完整DoD仍无新增关闭**。先B D2整改与D独立验收，再统一串行生产门/可信bootstrap/恢复入口，真实外部材料及跨SID/UAC/WFP05/Windows/VPS环境仍BLOCKED_REAL_ACCEPTANCE。§14用户已计划提供独立电脑/服务器，不视为已连接或已验证独立历史域。当前无新编译/实机执行。
