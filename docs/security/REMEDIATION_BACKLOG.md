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

