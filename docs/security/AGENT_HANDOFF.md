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
| SEC-10 | 旧 `--guard-apply` 提权请求临时文件/输入信任边界 | 未修复 | `guard/elevate.rs:208-256,361` |
| SEC-11 | UTF-8 `&ts[5..10]`、`value[..43]` 和生产 panic | 未修复 | `uiweb_form.rs:6828`，`pairing.rs:2072` |

**服务器端两个漏洞的旧版复现来自另一 Agent 的离线报告；这次快照确认危险代码仍在，但尚未在最新代码做实机动态利用复现。** 不要声称已实测新版本。

**PR #3 WFP 另外还没完成**：WFP-01 代理精确许可生产仲裁、WFP-02 长期 helper 正式生命周期接入/IPC 权限、WFP-03 Wintun/TUN 故障退出放行、WFP-04 v2 证据/同步/回滚、WFP-05 真机网络泄漏验收。当前只是候选与隔离实验代码，详见 Backlog。

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

