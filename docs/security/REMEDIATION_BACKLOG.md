# SpiderVPN 安全修复任务账本（唯一状态清单）

> 版本 v1.0 · 更新基准 2026-11-17；**文档提交不是修复完成证明**。  
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
| **SEC-01** | **P0 / 高** | 🔴 未修复（旧版曾复现） | `assets/tc-pair.py:1195,1230-1246`; `src/deploy.rs:849-891` | Rust 邀请授权/撤销状态机 + 旧记录迁移，拒绝重放 | 撤销后原/换公钥不能复入网，地址无重叠，HTTP 与 CLI 一致 |
| **SEC-02** | **P0 / 高** | 🔴 未修复（旧版曾复现） | `assets/tc-pair.py:1453-1456`; `src/pairhost.rs:36-47` | Rust TLS daemon 并发握手 + 超时 + 低权限服务 | 一条/多条空闲连接不堵塞正常 HTTPS，服务资源可控 |
| **SEC-03** | **P0 / 高（本地威胁前提）** | 🟠 Rust ACL 候选开发中（未实机安全验收） | `package-files/install.ps1`; `src/engine.rs:163-191`; `src/isolation.rs:31-45` | Rust 安装可信边界/受保护 bin 与特权引擎路径策略 | 非管理员不可替换特权执行目标，配置篡改不能导致任意提权执行 |
| **SEC-04** | **P1 / 中** | 🟠 部分修复 | `src/secretfile.rs:91-116`; `src/main.rs:642-705` | Rust 密钥导出与敏感文件 ACL 全覆盖，区分保密/防篡改 | 导出私钥无宽 ACL、旧文件迁移、运行正常 |
| **SEC-05** | **P1 / 中** | 🔴 未修复 | `src/engine.rs:100-136`; `src/connect.rs:531-535,689-720` | Rust 引擎 HANDLE + 创建时间/路径/会话 ID 校验 | PID 复用不误杀陌生进程、不阻塞代理自愈 |
| **SEC-06** | **P1 / 中** | 🔴 未修复 | `src/uiweb_form.rs:57,705`; `src/deploy.rs:1933,3326` | Rust 单一 TCP 端口白名单 | 443/8443/2443 部署、导出、导入、恢复一致通过 |
| **SEC-07** | **P1 / 中** | 🔴 未修复 | `assets/tc-pair.py:68,352-357`; `src/pairing.rs:4556-4581` | Rust 证书到期管理/代际轮换，区分 expired 与 pin mismatch | 到期提前预警；不接受过期证书；轮换后新旧邀请有明确语义 |
| **SEC-08** | **P1 / 中低（可放大 SEC-01）** | 🔴 未修复 | `assets/tc-pair.py:82,235-243,1286,1333` | Rust daemon 同一跨进程锁/交易日志 + 原子更新 | 多进程请求不丢状态、不复活已撤销设备、无相同 IP 双 peer |
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
| **SEC-11** | **P1 / 中** | 🔴 未修复 | `src/uiweb_form.rs:6828-6834`；`src/pairing.rs:2068-2074` | 处理 UTF-8 字节下标/shape 验证；对生产 `unwrap/expect` 做有根据的回归 |
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
- **Windows MSVC [44026418209](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44026418209)**：核对 head_sha 匹配，Rust 构建、PowerShell 卸载脚本语法解析、SEC-09/10 安全专项、所有 Rust 集成目标、模块回归已经分别 **Success**；写入时便携单元 suite 仍在执行，**不可宣称整个 workflow 终态 Success**。便携 suite 保留原先 8 项环境依赖排除，本轮未新增跳过。需重新查询最终结论并补录。
- **不等于实机验收**：所有 WFP 删除/异常注入测试采用 fake backend，不曾在 CI Runner 上真的删除持久 WFP。Windows A/B/C 权限与 I01–I12、U01–U14、UAC-01～12、TUN 断线与真实交易程序网络仍未验收；不合并 main。
