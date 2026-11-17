# SEC-01 / SEC-08 Linux Rust 邀请授权、撤销及事务锁迁移方案

> 状态（2026-11-17）：**仅有隔离 Rust 策略核心和 Linux 互斥锁候选，尚未接入服务端生产运行路径**。现有 src/pairhost.rs 的 systemd ExecStart 仍为 /usr/bin/python3 .../tc-pair.py serve。**禁止将 SEC-01 或 SEC-08 标为已修复**；不要把纯函数 13 项 CI 结果冒充 WireGuard 真实验收。

## 原始缺陷的可核对证据

- assets/tc-pair.py::authorize_invite 的 Consumed 分支只核对 RequestId 与 RecipientJwkDigest，直接用本次请求的 ClientPublicKey 配合旧 ClientAddress 调用 attach_client；未校验旧 ClientPublicKey、DeviceId、RequestDigest 的全字段一致性。
- src/deploy.rs::revoke_script 只删除 WireGuard 的某个公钥并热同步，不向邀请状态存储写 Revoked 墓碑。旧 Consumed 的记录可继续按“重试”请求触发 attach_client，于是之前被撤销的 peer 可能复活。
- assets/tc-pair.py::CONSUME_LOCK 是 threading.Lock，仅串行化一个 Python 进程的 consume；另一 HTTP 进程、SSH authorize-request、cancel/create 等跨进程不共享此锁。不能保证同一地址不被重复分配或更新丢失。
- assets/tc-pair.py::command_serve 当前采用 ThreadingHTTPServer 且 TLS 握手在 socket accept 层处理，未形成受控的非 root Rust 服务，因此 SEC-02 依然 P0 未修复。

## 第一阶段已提交的 Rust 候选（非生产接线）

- 代码在 fix/sec10-guard-elevation-identity-p0-20261117 / Draft PR #6，新增 server-rs/src/lib.rs（纯 std Rust、无 TLS/WG/磁盘副作用）和 server-rs/src/lock.rs（Linux x86_64 flock、owner-only 目录及 O_NOFOLLOW / hardlink 限制）。
- **状态机**：Open → Pending(持久预留公钥与 IP) → Consumed(真实 WG peer 严格读回) → Revoking(先写入拒绝状态) → Revoked(确认旧公钥与 IP 都从 live WG 消失)；Cancelled/Expired 为终止状态。Pending/Revoking 中断后必须明确恢复，不允许无条件重试。
- **旧 Consumed 重试**：请求的 InviteId、RequestId、DeviceId、ClientPublicKey、RequestDigest、RecipientJwkDigest 必须完整一致，且新鲜 WG 快照里必须有且仅有匹配公钥 + 匹配 IP 的 peer；不满足即拒绝、**不能调用 attach_client/syncconf**。没有快照也一律拒绝。
- **撤销**：必须在实际 WireGuard 删除前持久提交 Revoking 状态以拒绝重放；删除/同步/读回失败保留 Revoking 供重试而不是回退到 Consumed；确认 peer 与 IP 均不存在后提交 Revoked 并登记 device/key 墓碑。跨邀请复用同一 DeviceId 或公钥必须拒绝；同一邀请换公钥也必须拒绝。
- **地址与并发**：新请求只从网段合法 host 可用区间 +2 至广播前分配；同时考虑实时 WG peer、Pending/Consumed/Revoking 的保留 IP 与已存在公钥/DeviceId；未知 live 快照禁止分配；同一交易外层必须获取跨进程 Linux flock 并覆盖 ledger+wg.conf+wg sync/readback 的整个生命周期，失败超时拒绝。
- **Linux 守护进程用户/文件所有者**：锁目录须为进程有效 UID 持有、group/other 无权限；锁文件必须为受保护普通单硬链接文件，拒绝符号链接、硬链接与权限降级。不得删除 lock 文件；否则 inode 置换可能使不同进程各持有自己的“成功锁”。

## 自动化证据

- [Linux Rust CI #44033771424](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44033771424)：编译独立 Rust rlib + rustc --test；实际 13 tests passed、0 failed、0 ignored，含进程间锁拒绝、旧 Consumed 迁移后缺 peer 拒绝、RequestId 相同换公钥拒绝、撤销墓碑、新旧身份跨邀请、冲突地址及非法网段。
- Windows MSVC/GNU 是现有客户端 ABI 回归；新增 Linux core 文件暂不接入 Windows spidervpn.exe。其工作流仅证明项目其他模块未被本候选意外破坏，**不能证明服务端线上行为**。

## 关键限制：为什么现在不能直接替换 Python 服务

1. **密码学与协议**：Python 目前使用 RSA-3072 管理身份、RS256 邀请/申请签验、RSA-OAEP-256/A256CBC-HS512 JWE 授权；Rust daemon 必须逐字节兼容客户端 `src/pairing.rs` 的全部字段、摘要和密文算法。
2. **持久化/迁移**：Rust core 目前只提供内存 Ledger，无生产 JSON 解析、旧记录完整迁移、损坏 fail-closed、原子 fsync + rename + 目录 fsync、崩溃恢复/一致性约束。不能假装 Pending/Revoking 已经落盘。
3. **真实 WG 操作**：尚未有 Rust 对 WG peers、wg.conf、wg-quick strip 与 wg syncconf 的受控执行、目录身份校验、超时、回滚、读回确认。不能让已撤销公钥被旧 Python 接收器重放。
4. **TLS/资源限制 SEC-02**：尚未有 Linux Rust TLS 1.2 HTTP endpoint、握手超时/并发上限、body 长度上限和非特权账号部署。不能称 SEC-02 已修复。
5. **撤销接线**：Windows 管理端 `src/deploy.rs::revoke_script` 仍仅删除 WG peer，待 Rust CLI/daemon 接管并保证**先写 Revoking，后删除 peer，最后读回写 Revoked**；旧 Python HTTP 在线/离线消费在迁移之前仍可能重放。
6. **新邀请与新身份**：如果一个人获得全新、独立签发的邀请并同时更换公钥与 DeviceId，服务器无法从密码学上推断这与已撤销者是同一人；阻止此类情况必须靠邀请审批/设备身份治理，不能虚称“靠墓碑自动识别同一真人”。

## 后续 Agent 按顺序推进（不可跳过红色验收）

| 顺序 | 任务 | 合格条件 |
|---|---|---|
| S01 | 增加 Rust Linux daemon 独立 Cargo 包及依赖锁，受控 JSON schema 与旧 invite 记录只读迁移/异常兼容 | 真实旧 `invites.json` 测试样本覆盖 Open/Consumed/Cancelled/损坏记录；禁止因未知状态自动放行 |
| S02 | Rust 端签名与 JWE 互操作（对应 Rust 客户端 fixture） | 与旧服务端生成协议的密钥、签名、字段、跨时区时间戳兼容 |
| S03 | 可重启/原子事务 Ledger + WG config 及进程互斥锁实际接线 | 多进程 50–200 并发/kill -9 时，不重复 IP、不丢 tombstone，不允许 reattach |
| S04 | Rust TLS daemon 接管 18443，非特权服务账号和 root-only WG helper 权限分离（SEC-02） | 100+ 空闲 TLS/慢请求时合法请求仍能处理，连接/头/体有明确超时、上限 |
| S05 | Rust CLI 管理端撤销接线 + 老 Python 服务停用/迁移切换 + 回滚 | 管理端撤销后旧 HTTP/离线申请不复活 peer；新/旧公钥替换同邀请不能获得授权 |
| S06 | 隔离 Linux VM + Windows 客户端真实端到端、安全性/兼容性验收 | 申请、撤销、重放、断电、并发、签名和 TLS 都有日志+WG/config 证据 |

**发布闸门**：任何模块“单测绿色”仅代表迁移工作进度。S01–S06 缺失任一项，SEC-01/02/08 仍 Open；Draft PR #6 不合并 main、不可声称生产漏洞已被修复。
## 第二阶段：只读旧邀请记录审计器（Rust，未迁移）

- 最新候选在 Rust 开发分支 fix/sec10-guard-elevation-identity-p0-20261117 的 SHA 3d01dda610d33f38cb5f7aa7e95479ecf97b9ac4。独立 server-rs/Cargo.toml + Cargo.lock 使用原桌面仓库锁定的 serde 1.0.229 / serde_json 1.0.154 及相同依赖闭包；独立 Linux workflow 从直接 rustc 改为 cargo --locked、RUSTFLAGS=-D warnings。Windows 客户端未改依赖与运行时。
- 新增 server-rs/src/legacy.rs::audit_legacy_json（**纯内存只读**，不读磁盘、不写邀请、不变更 WG），严格检查 SchemaVersion=1、Invites 对象、最大 4MiB / 最多 4096 邀请以及 UUID、密钥、RFC1918 /32 地址、客户端身份与请求摘要形状；不识别的状态不猜作 Open，已取消与已过期邀请保持终止状态；审计报告绝不输出 Token 或 SignedAuthorization 原文。
- **必须正视旧格式缺陷**：assets/tc-pair.py::authorize_invite 新 Consumed 状态在记录里保存 RequestId/DeviceId/ClientPublicKey/ClientAddress/RecipientJwkDigest/SignedAuthorization，**没有保存原 RequestDigest**。Rust 不允许用猜测值伪造它；即使旧记录被人工补填 RequestDigest，Rust 仍要求实际 RS256 验签、授权绑定验证及实时 WG peer readback，才能导入为可信 Consumed。
- [Linux Cargo CI #44034700193](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44034700193) head_sha=3d01dda6，Completed/Success，合计 **19 passed、0 failed、0 ignored**（旧 SEC01/08 13 项与只读 migration audit 6 项），脚本还明确核对生产 `pairhost.rs` 的 systemd ExecStart **仍为 Python**，不会虚报线上迁移。
- **过渡红例**：在新增 serde_json 模块后、切换工作流至 Cargo 之前，直接 rustc 命令无法链接独立 crate 的新依赖，旧 SHA 的 Linux workflow 出现 Failed；以当前独立 Cargo `--locked` 同 SHA 成功为准，**没有删测试或 skip**。
- 当前生产持久化、原子迁移、签名验证、Linux 真 WG 和在线 TLS daemon 均未完成，S01 仍是第一步的一部分，SEC-01/02/08 不能关闭。

## 第三阶段：Rust 事务账本和可注入 WireGuard 事务编排（预接线）

- **Rust 代码**：活动 Draft PR #6 新增 server-rs/src/ledger_disk.rs（version=1、generation 持续递增、serde 严格解码、只接受 owner-only Linux 0700 根与 0600 普通单链接文件、O_NOFOLLOW，临时文件 create_new+fsync+rename+父目录 fsync），并在 server-rs/src/lib.rs 将 Ledger/Claims/Grant 等模型支持严格持久格式。缺文件、未知 schema、无效 grant/UUID、公钥/身份重复、地址冲突、Revoked 缺墓碑、权限过宽、symlink/hardlink 都 fail closed，不恢复默认空账本。**生产初始化仅允许未来经过原始 JWS/WG 可信迁移的导入器做**；现在只有 cfg(test) 内的 bootstrap。
- **重要模糊 fsync 故障**：如果原子 rename 已替换成功、但目录 fsync 返回错误，磁盘可能已是 Pending，新版 LedgerStore 在任何存储写失败后 `poisoned = true`；同一对象的 view/generation/update 全部拒绝，防止旧 Open/Consumed 内存状态覆盖新持久状态。只有关闭并重新打开、重验全盘账本后才能恢复。cfg(test) 的 post-rename 故障注入证明了这一边界，正式运行代码没有可由用户开启的绕过旋钮。
- **事务编排**：server-rs/src/transaction.rs 定义抽象 PeerControl {snapshot, add, remove}，enroll 必须先 snapshot→durably commit Pending→add peer→重新 snapshot→durably commit Consumed；revoke 必须先 durably commit Revoking→remove peer→重新 snapshot→durably commit Revoked；retry_read_only 只读严格身份+WG live match，**绝不 add peer**。所有操作借 LedgerStore 的同一把 Linux 跨进程锁保持事务边界。PeerControl 当前仅用 CI fake-WG，**没有真实 Linux wg 命令调用**。
- **自动化证据**：[Linux Rust #44036202223](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036202223) SHA 95d69ec9、26 tests passed；[Linux Rust #44036699347](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036699347) SHA bbb23e43、31 tests passed；**最新** [Linux Rust #44036991021](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44036991021) SHA 07dc06f8，Completed/Success，**32 tests passed、0 failed、0 ignored**，含重启/revoke、错误 readback、真实跨进程文件锁、权限/链接拒绝和 post-rename 失败后拒绝旧内存状态。
- **明确未覆盖的安全事实**：原子文件落盘不等于抗恶意回滚（有权写目录者仍可能恢复旧有效文件）；待实现签名绑定/可信导入及外部锚点、完整真实 WG 接口和同机多进程极端压力测试。暂不保证突然断电/磁盘故障之后的全部真实 Linux 服务器网络行为。Python systemd 仍是生产接收器，SEC-01 P0 保持 Open。

## 下一步代码/验收门槛（不需要用户本地协助的部分）

1. Rust 接口绑定实际可信 WG live snapshot、wg-quick strip/wg syncconf（不得调用 shell 拼接用户参数），构造不会泄漏机密的错误码和恢复诊断。首次只能在容器/虚拟 WireGuard 测试环境执行，不能操作真实用户的服务器。
2. 实现完整 RS256/JWE 合法性和与已有客户端 `pairing.rs` 的互操作，然后写入经过验签的旧授权与 tombstone。不能仅凭旧 JSON 字段或 SessionId 合成缺失的 RequestDigest。
3. 最后把 Python HTTP 接收器/Windows revoke 管理入口与 Rust 单元实机双向接通，保证从不可知旧状态迁移到新状态过程中不会有同时工作的旧消费服务。
4. 完成非 root Linux systemd TLS/HTTP 连接限时限并发，真实 WFP/Windows A/B/C 另行验收；所有门槛未完成前保持 PR Draft，不合并 main。

## 第四阶段：只读 WireGuard 现场快照适配器（无生产接线）

- **当前候选 Rust 代码 HEAD** `e4ec09e46631139d0900a9c4872770f92958b175`，活动 Draft PR #6：新增 `server-rs/src/wg_readonly.rs`，仅通过 Rust `std::process::Command` 直接调用固定绝对路径 `/usr/bin/wg`，参数固定为 `show <validated interface> allowed-ips`，无 shell、无外部输入拼接、无动态 PATH 执行。执行前检查文件必须是 root 持有的普通可执行文件，拒绝符号链接、组/其他账户可写的二进制；不接受特殊接口 `all`、`interfaces`、选项形式、空白、非 ASCII、超长接口。
- **读取来源的隐私约束**：WireGuard 官方 `wg(8)` 文档明确 `dump` 包含接口私钥字段，因此本模块**禁止调用 `wg ... dump`**，只读取 peer 公钥和 AllowedIPs；可核对 [wg(8) 官方说明](https://man7.org/linux/man-pages/man8/wg.8.html)。命令清空继承环境、禁用 stdin、忽略 stderr、限制最长 3s、最多 512 KiB stdout，以并行读取 stdout 避免阻塞管道。命令超时、退出非零、不可读或超限直接拒绝，不得视为空列表。
- **严格解析与失败关闭**：`parse_allowed_ips` 只接收完整 `公钥<TAB>RFC1918单一IPv4/32<LF>` 行。重复公钥/IP、无换行、损坏 UTF-8、额外字段、`(none)`、IPv6、多 CIDR、/24 或 /0、非私有地址、非规范 IP、超 4096 peer 都拒绝，**不会跳过坏记录后把缺失 peer 误报为撤销成功**。空输出仅在外部 `wg` 命令明确成功后可作为 live 空接口解释。
- **Linux 自动验证**：[Rust #44038827553](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827553) head_sha=e4ec09e4，**Completed/Success，39 passed、0 failed、0 ignored**（前 32 + WG 读取器 7 项）。CI 用假输出/本地 `sleep`/`false` 测超时与非零退出，**不会执行真实 `/usr/bin/wg`、修改网络配置或用户服务器**。Windows 同 SHA [MSVC #44038827565](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827565) / [GNU #44038827585](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44038827585)，记录时仍需查询最终状态。
- **不可越过的限制**：模块只有 `LiveWgReader::snapshot`，刻意不实现带 `add/remove` 的 Rust `transaction::PeerControl`；仅能证明 live 内核表里的已知 IPv4/32 peer，不证明磁盘 `wg.conf`、旧授权签名、外部并发更改或服务器防火墙/路由正确。后续需要验证实际 `wg.conf` 内容、安全地实现固定参数的增删 peer 和回滚/读回，并做隔离 Linux 网络命名空间测试；不能直接用于生产授权或改动当前 Python receiver。SEC-01/02/08 仍未生产修复，PR Draft，main 不合并。
