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
