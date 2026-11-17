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
