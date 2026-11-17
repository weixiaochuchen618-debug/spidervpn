# SpiderVPN 安全修复任务账本（唯一状态清单）

> 版本 v1.0 · 更新基准 2026-11-17；**文档提交不是修复完成证明**。  
> **主方案**：[SECURITY_REMEDIATION_PLAN.md](./SECURITY_REMEDIATION_PLAN.md) · **交接入口**：[AGENT_HANDOFF.md](./AGENT_HANDOFF.md)。  
> [仓库](https://github.com/weixiaochuchen618-debug/spidervpn) · [PR #3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) · [既有 WFP Issue #2](https://github.com/weixiaochuchen618-debug/spidervpn/issues/2)

## A. 版本、证据与变更边界

- **正式代码**：main = \`857ea7593941ce79f6507db5b1ced076c3a077ba\`。
- **当前 WFP 候选**：\`fix/wfp-trade-egress-p0-20261116\` HEAD = \`2045acd42554b1ad1472ae41ab247b42d8df5655\`，PR #3 Draft、未合并。
- **基线 CI**：该 SHA 的 [Windows MSVC](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452983) 成功；[Windows GNU](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/43990452791) 成功。仅覆盖已写进 CI 的功能；未完成真实 TUN/Wintun 防泄漏验收。
- **审查状态口径**：\`未修复\`=危险代码路径在 PR3 HEAD 仍存在；\`部分修复\`=有保护基础但覆盖不全；\`候选实现\`=代码提交但未生产集成/未全部验收；\`已完成\`=完整 DoD 通过并附 commit/CI/真实验证证据。
- **2026-11-17 本账本创建时没有完成以下 9 项中的任何一项**；不能因为 PR #3 green 就把其勾选。
- **语言约束**：任何新增产品修复与安全决策用 Rust 实现/编译；Python 服务以兼容的 Rust Linux daemon 替换；原 PowerShell 只作为安装/卸载薄包装器及测试辅助。
- **合并约束**：不变更现有 UI 与正常连接交互；禁止将未验收的 WFP 租约直接合并到 main。

## B. 原始审查九项（SEC-01～SEC-09）

| ID | 级别 | 当前状态 | 模块与证据 | 首要下一动作 | 关闭条件（简） |
|---|---|---|---|---|---|
| **SEC-01** | **P0 / 高** | 🔴 未修复（旧版曾复现） | \`assets/tc-pair.py:1195,1230-1246\`; \`src/deploy.rs:849-891\` | Rust 邀请授权/撤销状态机 + 旧记录迁移，拒绝重放 | 撤销后原/换公钥不能复入网，地址无重叠，HTTP 与 CLI 一致 |
| **SEC-02** | **P0 / 高** | 🔴 未修复（旧版曾复现） | \`assets/tc-pair.py:1453-1456\`; \`src/pairhost.rs:36-47\` | Rust TLS daemon 并发握手 + 超时 + 低权限服务 | 一条/多条空闲连接不堵塞正常 HTTPS，服务资源可控 |
| **SEC-03** | **P0 / 高（本地威胁前提）** | 🔴 未修复 | \`package-files/install.ps1\`; \`src/engine.rs:163-191\`; \`src/isolation.rs:31-45\` | Rust 安装可信边界/受保护 bin 与特权引擎路径策略 | 非管理员不可替换特权执行目标，配置篡改不能导致任意提权执行 |
| **SEC-04** | **P1 / 中** | 🟠 部分修复 | \`src/secretfile.rs:91-116\`; \`src/main.rs:642-705\` | Rust 密钥导出与敏感文件 ACL 全覆盖，区分保密/防篡改 | 导出私钥无宽 ACL、旧文件迁移、运行正常 |
| **SEC-05** | **P1 / 中** | 🔴 未修复 | \`src/engine.rs:100-136\`; \`src/connect.rs:531-535,689-720\` | Rust 引擎 HANDLE + 创建时间/路径/会话 ID 校验 | PID 复用不误杀陌生进程、不阻塞代理自愈 |
| **SEC-06** | **P1 / 中** | 🔴 未修复 | \`src/uiweb_form.rs:57,705\`; \`src/deploy.rs:1933,3326\` | Rust 单一 TCP 端口白名单 | 443/8443/2443 部署、导出、导入、恢复一致通过 |
| **SEC-07** | **P1 / 中** | 🔴 未修复 | \`assets/tc-pair.py:68,352-357\`; \`src/pairing.rs:4556-4581\` | Rust 证书到期管理/代际轮换，区分 expired 与 pin mismatch | 到期提前预警；不接受过期证书；轮换后新旧邀请有明确语义 |
| **SEC-08** | **P1 / 中低（可放大 SEC-01）** | 🔴 未修复 | \`assets/tc-pair.py:82,235-243,1286,1333\` | Rust daemon 同一跨进程锁/交易日志 + 原子更新 | 多进程请求不丢状态、不复活已撤销设备、无相同 IP 双 peer |
| **SEC-09** | **P1 / 中低（Guard 失控影响高）** | 🔴 未修复 | \`package-files/uninstall.ps1:90-101,108-133,133-141\` | Rust 卸载预检查/精确清单/Guard 读回 | exit 3 不误删 exe、残留可清、相邻目录不误删 |

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
- [ ] **SEC-09** Guard 解除退出码 3、UAC 被拒、\`-KeepGuard\`、完整 bin 清理与相邻路径匹配

## C. 补充发现（不并入九项编号，不能漏掉）

| ID | 级别 | 当前状态 | 证据 | 首要下一动作 |
|---|---|---|---|---|
| **SEC-10** | **P0 / 高（本地攻击者）** | 🔴 未修复 | \`src/guard/elevate.rs:208-256,361-407\` | Rust 一次性提权 IPC 可信目录、身份派生/请求重放防护，统一与长期 lease 的权限边界 |
| **SEC-11** | **P1 / 中** | 🔴 未修复 | \`src/uiweb_form.rs:6828-6834\`；\`src/pairing.rs:2068-2074\` | 处理 UTF-8 字节下标/shape 验证；对生产 \`unwrap/expect\` 做有根据的回归 |
| **AUX-01** | P2 | 未完成 | \`assets/tc-pair.py:303-311,692-711\` | Rust 服务支持合法双栈 \`Address = IPv4, IPv6\` 输入，正确提取 IPv4 |
| **AUX-02** | P2 / 合规 | 未完成 | \`vendor/sing-box.LICENSE.txt\` | 核实发行版本许可条款，补完整文本、源码获取说明 |
| **AUX-03** | P2 / 审查覆盖 | 未完成 | \`src/ipc.rs\`、\`uiweb*.rs\`、\`config.rs\` 等 | 增加 fuzz、输入边界、未审部分的安全核查，不宣称已全库逐行 |

### SEC-10/11 回归清单

- [ ] \`--guard-apply\` 请求存储只有受信主体可修改，随机唯一目录，不接受 reparse/重放。
- [ ] 提权侧重新验证所有 ProgramIdentity 的可执行路径/WFP AppId，拒绝篡改请求；\`lease_helper.rs\` 也接受同样审查。
- [ ] 中文/emoji/组合字符传入 \`short_time\` 和 WireGuard key 校验不能 panic，仍返回符合原交互的错误。
- [ ] 生产 \`expect/unwrap\` 必须记录是否真实可触发，不能无依据地全部称为高危。

## D. PR #3 的 WFP 剩余任务（独立于九项）

> **重要**：这些任务不是“SEC-01～09 的附属项”。已有候选代码 ≠ 已经启用。当前实验通过环境变量 \`SPIDERVPN_WFP_LEASE_EXPERIMENT=1\` 打开，默认关闭。

| ID | 现有进展 | 仍未完成的核心工作 | 验收条件 |
|---|---|---|---|
| **WFP-01** 代理精确放行 / 默认阻断 | 🟠 候选：WFP v1 持久 BLOCK、局部 v2/scoped 规则及内核 canary；CI 绿 | 明确生产规则优先级、受保护端点和连接授权后撤销的一致性；原子变更 | 只允许已验证本地代理路径，未经授权不能直连 |
| **WFP-02** 长期提权 lease | 🟠 候选：\`lease_helper.rs\`，Ready/ACK、进程句柄监控，隔离试验入口 | 正式连接/断开时的 lease 归属、取消/超时、IPC ACL 可信性、进程关闭清理、异步失败报告；消除重复 UAC 与实验特有泄漏窗口 | 断开/拒绝/崩溃后无动态 PERMIT 遗留，不能误报已保护 |
| **WFP-03** TUN/Wintun 安全通道 | 🔴 未完成生产路径；有候选 LUID 身份和过滤器测试 | 精确接口 LUID、路由/next-hop、Wintun 生命周期、隧道断开/重拨不绕过 | 故障注入无未授权外网直连；持续 BLOCK |
| **WFP-04** 证据、同步、回滚 | 🟠 v1 持久规则与读取证据/回归测试已存在 | v2 证据 schema、同步与 provider 归属隔离、异常事务/长期进程跨会话恢复和重授权一致性 | 不破坏旧规则，不产生误报/多余规则，不删外部 provider 规则 |
| **WFP-05** 真机验收与发布闸门 | 🔴 未完成 | 两 Windows ABI + 隔离 Win11/真实 sing-box/Wintun + 多账户/崩溃/断网/端口劫持测试；最后审查 | 完整证据包、可回滚后才将 PR #3 从 Draft 改为可合并 |

### WFP 安全冻结条款

- [ ] 在 WFP-05 完成前，\`SPIDERVPN_WFP_LEASE_EXPERIMENT\` 保持默认关闭。
- [ ] 不修改原系统代理与 TUN 下单交互，不删除任何原有持久 BLOCK 以换取“连接成功”。
- [ ] 单独回归多次启动/退出、UAC 点否、代理端口被接管、sing-box 崩溃、主程序退出、Windows 重启、网络重连。
- [ ] 任何发布宣称必须给出真实用户配置和抓包/路由/过滤器读回的证据；“CI success”不构成零泄漏证明。

## E. 按依赖推进的顺序（每次新 Agent 只选一个最小安全单元）

| 顺序 | 任务组合 | 下一步可直接开展的具体工作 | 是否能与其它项并行 |
|---|---|---|---|
| 0 | 基线 | 检查 main、PR #3 最新 SHA、现有测试、实机环境、旧复现、回滚脚本；建立当前工作 PR | 必须先做 |
| 1A | **SEC-03 + SEC-10** | Windows Rust 可信安装/提权 IPC 方案 + 双账户攻击回归 | 可与 1B 并行 |
| 1B | **SEC-01 + SEC-08** | Rust Linux \`spidervpn-paird\` 状态机/存储/撤销事务及协议金样本 | 可与 1A 并行 |
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

\`\`\`text
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
\`\`\`

## G. 更新规范

1. **先更新此任务账本，再对外宣告完成。** 每次状态变化写精确 commit 和 CI URL；旧 SHA 的通过记录不能算新 SHA 验收。
2. 任何任务只要缺实机/攻击回归，最多标注“候选实现”或“待实机”，不能打 \`[x]\`。
3. 审查发现新漏洞使用 \`SEC-12+\`，不要重排原九项编号；关联 PR #3 的问题使用 \`WFP-06+\`。
4. 以此文件作为唯一权威任务状态；技术方案更改附日期/理由/风险；新 Agent 的第一条提交只允许当前选中的任务及其回归测试。
5. **不要在新会话单凭过去总结“已推送”或“已修复”**：先从 GitHub 重新读 HEAD、CI、文件和未合并 PR。

