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

## 第五阶段：三份只读快照一致性与并发否决（未接生产）

- 源码在活动 Rust Draft PR #6，最新 HEAD `714674bf827d84c62e24bcbd627ad980e90ead67`。新增纯 Rust `server-rs/src/wg_conf_audit.rs`：只读检查固定 `/etc/wireguard/<iface>.conf`，严格 owner=root、目录 0700、conf 普通文件 0600 单硬链接、O_NOFOLLOW，最大 1MiB；文件前后 inode/dev/size/mtime/ctime 必须稳定；私钥与 PresharedKey **不会出现在返回值或错误诊断中**，也不执行其中的 PreUp/PostUp。
- 解析 `[Interface]`/`[Peer]` 后，跨 peer 只允许唯一公钥 + 唯一 RFC1918 IPv4/32 地址。缺 PublicKey/AllowedIPs、重复或多范围、IPv6、未知区段与损坏 Unicode 均拒绝。对比运行时 live `wg show <iface> allowed-ips` 结果时，peer 公钥/地址/数量必须完全相同（排序可不同），否则明确 `SnapshotMismatch`。比如 `wg.conf` 仍有旧 peer、但 wg 内核没有时，**绝不能把该地址认为彻底释放或撤销成功**。
- 对抗式新增 `read_verified_snapshot(interface)`：live 前快照 → 受保护的磁盘配置快照 → live 后快照；任一不一致拒绝，防止常见竞态将局部更新误读为稳定状态。未来调用方仍必须在整个检验/变更期间持有 SEC-08 Linux authority lock；对不遵守锁的外部 root 命令及恶意回滚并不提供绝对安全保证。新代码未接 `PeerControl::add/remove`。
- 源码测试包括 peer 差异、IP/public key 置换、独立设备残留、字段/章节丢失、非 ASCII、重复地址、并发快照变化，以及未验证上游提供的 4097+ peer 输入预先拒绝。过渡 SHA `9f8266dc` 的 [Linux 44039517579](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039517579) 因未使用导入与无必要 `mut` 在 `-D warnings` 下红，修正为 `51c6e235`，**没有降低警告级别或删测试**。
- CI：`51c6e235` 的 [Linux 44039613988](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039613988) 是 46/46 全绿；**当前** `714674bf` 的 [Linux 44039882060](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882060) **Completed/Success，48 passed / 0 failed / 0 ignored**，`cargo --locked` / `-D warnings` 均过。与最新代码对应的 Windows [MSVC 44039882064](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039882064) / [GNU 44039881955](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44039881955) 在记录时仍需核对完整结论。
- 线上状况不变：`pairhost.rs` 的 systemd 单元仍调用 Python tc-pair.py；Rust 尚未实现真实 `wg.conf` 安全修改、wg syncconf 错误恢复、RS256/JWE 验签、旧 JSON 可信迁移、SEC-02 非 root Rust TLS 及 Windows 管理端撤销接线。真实服务器/网络命名空间尚无验收。SEC-01/02/08 继续 open，PR Draft、main 不合并。

## 第六阶段：单 peer Rust 写入/内核更新的安全闭环候选（未上线）

- 最新 Rust 开发分支 `fix/sec10-guard-elevation-identity-p0-20261117` / Draft PR #6，**HEAD 468af9e675bbf118464e1094306c6a055039324d**。新增 `server-rs/src/wg_peer_plan.rs`、`server-rs/src/wg_atomic.rs`、`server-rs/src/wg_live_set.rs`，共用既有 `wg_readonly`/`wg_conf_audit`/`ledger_disk`。所有代码为 Rust 编译；没有修改现有 Windows UI/连接/WFP，也没有切换服务端 Python。
- **规划阶段** `plan_change(before, authenticated_grant, Add/Remove)`：先完整验证已有 wg.conf；仅追加一个新 [Peer] 或精确删除公钥+IPv4/32 同时匹配的一个 `[Peer]`，保留其他 peer 的原始字节、注释和 [Interface] 配置；新增 peer 公钥或 IP 与现有冲突即拒绝。撤销时如公钥和地址在磁盘都已不存在，可安全 no-op 以处理已删除但尚未写 Revoked 的中断。Plan::Debug 对包含服务端 PrivateKey/PresharedKey 的原始配置完全脱敏，原始 bytes 只允许 crate 内受保护写入器访问。
- **持久阶段** `wg_atomic::write_pinned_config`（**仅 pub(crate)，禁止外部直接调用**）：要求 LedgerStore 中当前邀请已成功 fsync 为 **Pending(Add) / Revoking(Remove)** 且 grant 完全一致；校验固定根 `/etc/wireguard` owner/root + 私有目录、0600 单硬链接 conf、O_NOFOLLOW、合法接口；先核对 live+disk，读取前后 inode/dev/size/mtime/ctime，写 0600 create_new 同目录 temp → fsync → 复核源文件未变 → rename → 父目录 fsync。不用 glob、不覆盖其他 peer。rename 后父目录 fsync 失败返回 CommitUncertain，旧授权 ledger 保持 Pending/Revoking，不自动标完成；对应 fault injection 已覆盖。
- **内核阶段** 为降低整组 peer 重写影响，使用 **有界的 Rust `Command` 直接执行固定绝对路径 root-owned `/usr/bin/wg`**，不启动 shell：`wg set IFACE peer KEY allowed-ips IPv4/32` 或 `wg set IFACE peer KEY remove`。仅变更一个 peer，不运行 wg-quick hooks，也不使用包含私钥的 `wg show dump`；清空环境和标准流，3 秒超时后 kill/wait；非零退出一律停止。`set_one_peer` 为私有函数，外部不能绕过账本直接调用。这里**没有使用 wg syncconf**，这是为降低干扰其他设备而有意改变先前技术路线。
- **联合事务** `wg_live_set::apply_and_confirm(store, iface, grant, change)`：LedgerStore 持跨进程 flock 的整个生命周期；先校验 grant 和 live-before+config → 用受保护写入器 fsync 配置 → 单 peer wg set → live-after+disk 三重核验且目标及其他 peer 列表精确一致 → **最后** `LedgerStore.update(confirm_consumed/confirm_revocation)`。任何文件、内核、回读、最终 ledger fsync 失败都不会把失配状态误提升成已授权/已撤销；重试不直接重新添加 peer。仅供未来经 RS256/JWS 验真的 Rust 管理流程使用，当前在线 Python 接收器完全未调用。
- **Linux CI**：[本轮最终 #44042690148](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690148) head_sha=468af9e6，**Completed/Success：71 passed，0 failed，0 ignored**，`cargo build --locked --all-targets`/`cargo test --locked` 且 `RUSTFLAGS=-D warnings`。新增 23 项配置规划/保护文件写入/定向命令/完整事务模拟/异常重启及模糊 fsync 故障注入；所有外部动作由 fake 执行器模拟，CI 不操作 Linux 真接口或真实用户数据。期间 `7a6231a1` 因配置字段只在测试被引用导致 -D warnings 失败、`e41f400c` 因 Read/Write::by_ref 重载导致 Rust E0034，均已用真实代码修正、不加 allow、不删测试。
- 当前同 SHA Windows [MSVC #44042690238](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690238) 和 [GNU #44042690146](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44042690146) 写入时仍未终态；必须核对 workflow 的 SHA 和结论才能宣称客户端回归通过。
- **生产发布仍禁止**：现有 Linux systemd 仍运行 `tc-pair.py serve`，Windows `deploy.rs::revoke_script` 未关联 Rust；Rust 仍无旧邀请签名/JWE 可信迁移、SEC-02 TLS 非特权 daemon、反回滚锚点。真实 Linux WG namespace/权限、网络断连/恢复、多账户与电源中断尚无验收；外部 root 不守 authority lock 的并发写入不完全可防范；配置已提交、内核 wg set 失败造成 live/conf 不一致时**仍缺经过独立审核的显式可信 reconcile 接口**，必须保持 Pending/Revoking 阻断并等待恢复，不可自动重试。SEC-01/02/08 不能关闭。

## 第七阶段：中断事务的只读诊断与仅终态可确认的恢复（预上线）

- **代码 HEAD**：`0f4f87b92372561475afa790e3c27ba68d89823c`，当前活动 Draft PR #6。新增独立 Linux Rust `server-rs/src/recovery_inspect.rs`，既不执行 `wg set`，也不通过 HTTP 接受恢复命令。只接受已持久落盘并经过严格格式校验的 LedgerStore 内 `Pending`（新增中断）或 `Revoking`（撤销中断），不允许针对 `Open` / `Consumed` / `Revoked` 进入恢复流程。
- **八种状态模型**：对 Pending(Add) 和 Revoking(Remove) 分别列举磁盘与 live 两侧各自存在/缺失的 4 种组合，输出 `VerifyAndFinalize` / `RepairConfigWithApproval` / `RepairKernelWithApproval` / `RepairBothWithApproval`。这些是给未来**本地受信任管理员**的诊断建议，不是免授权自动修复。老签名请求不能触发重新附加设备；存在重复公钥、IP 被他人占用或与目标公钥不一致时，直接 `IdentityCollision`。
- **全量对抗检查**：在只排除目标 peer 前，先分别完整验证 live/disk 的 peer 公钥、唯一 IP、单个 RFC1918 IPv4/32、最多 4096；排除目标后，剩余所有无关 peer 在两侧必须精确一致，哪怕只有一个无关设备变化也拒绝。超时/未知状态不能误判成空列表。过期的 Pending 只要任一侧还缺目标就拒绝重新创建（`ExpiredPending`），双侧原本已经存在的可在管理员核验后仅补写最终 ledger。
- **真实读取入口** `inspect_pinned_recovery` 采用 `LiveWgReader.snapshot` → 受 root-only ACL 保护的 `read_pinned_conf` → 再一次 `LiveWgReader.snapshot`。前后两次 live 必须严格一致；允许**仅目标 peer** 与磁盘存在差异，以发现中断的写配置/写内核状态。不能用 HTTP 传入的虚假 live/disk 对象取代这些读取。需继续遵守 SEC-08 Rust flock 事务锁，不能声称抵御外部不守锁的 root actor。
- **安全终态补写** `finalize_stable_prepared` 仅在重新读取完整 live/config 三重快照并验证已处于目标最终状态时，把已有 Pending→Consumed 或 Revoking→Revoked 写入受保护 Rust LedgerStore（包含 tombstone）；如果还需要补写 wg.conf 或修改 WG 内核则明确拒绝，绝不在此入口执行 `wg set`。已是 Revoked 的状态不能二次被视作 Pending。
- **验收证据**：[Linux Rust CI #44045613147](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44045613147) 与 `0f4f87b9` 源码 SHA 一致，Completed/Success、**85 passed / 0 failed / 0 ignored**，Cargo --locked、RUSTFLAGS=-D warnings。由原 71 增加 14 条针对四态组合、冲突、无关漂移、过期、重启/最终补写、只读与 live 前后变化的回归。全部由 Rust 模拟文件和 fake live 状态验证；**没有真实 WireGuard namespace/断电验收**。
- **阻塞状态不变**：尚无可供普通使用的管理员显式审批 CLI 与已批准部分修复动作的受保护执行器；不允许让普通 pairing/retry 自动重附旧设备。线上 Linux systemd 仍由 Python `tc-pair.py serve` 处理邀请，Windows `deploy.rs::revoke_script` 仍未写 Rust tombstone；RSA/RS256/JWE/旧 Consumed `RequestDigest` 可信迁移、SEC-02 非 root Rust TLS、真正 Linux WG namespace/kill -9/网络实测尚未完成。SEC-01/02 P0 与 SEC-08 P1 均不应关闭，PR #3/#6 Draft、main 不合并。

## 第八阶段：绑定快照与代数的单次管理员批准恢复执行器（模拟后端，未上线）

- **代码候选 HEAD** `663cc4e6d01579f04cb70be721ca3c3a2e66720d`，仍在 Draft PR #6，main 未改。新增纯 Rust `server-rs/src/recovery_apply.rs`，保留原 `recovery_inspect.rs` 只读诊断，将管理员审查后的恢复动作分为 `RecoveryReview`（含具体 InviteId、Ledger generation、诊断动作、完整 live/disk 快照）与不可被网络层随便构造的 `AdministratorApproval`。**当前只有 `#[cfg(test)] approve_for_test` 能签发批准，没有生产管理员登录或 HTTP 接线，不能宣称审批系统已上线**。
- `prepare_review` 在同一 LedgerStore 持有的 SEC-08 跨进程锁下两次读取 live、一次 disk，严格检查完整快照与原邀请 `Pending/Revoking`；`apply_approved` 按值**消耗单次批准**，首先核对批准绑定的 InviteId、Ledger generation、审批动作，重新读取现场并与审查时的原 live/disk 全量比对，只有一切未变才允许执行。审批不能是普通配对请求的 boolean 参数或复制的旧 token。
- **只修改批准的单一目标 peer**：该 Rust 执行器的 RecoveryIo trait 可注入未来 Linux 管理工具，新增中的四种组合选择仅磁盘、仅内核、两侧都改或无需改；撤销中的四种组合也按需删除，绝不使用 Revoked/Consumed 旧状态再添加。每一个有副作用步骤之后必须重新读取两次 live + 一次 disk，核对其他设备完整不变、目标精确达到预期，**最后**才允许持久写入 `Consumed/Revoked`（包括撤销墓碑）。任何写入、内核、回读、失配异常都保留 `Pending/Revoking`。
- **自动化**：[Linux CI #44048267737](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267737) 与最新 SHA 匹配，**Completed/Success：91 tests passed、0 failed、0 ignored**，`cargo --locked`、`RUSTFLAGS=-D warnings`。新 6 项测试覆盖 Pending/Revoking 八种组合、单侧修复及不误伤其他 peer、错误批准、代数或快照变化、配置写失败先阻断内核、内核写失败仍留 Revoking、过期 Pending 拒绝。过渡 SHA `0301b343` 因 final-state match 返回类型不一致 E0308 红，已修；过渡 `64ab0a99` 因单次批准消费后测试旧变量再次使用 E0382 红，已修。未降低严格警告或删测试。
- 同 SHA Windows [MSVC #44048267726](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267726) 与 [GNU #44048267756](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44048267756) 记录时仍运行中，待核对最终结果。
- **仍未实现的生产边界**：RecoveryIo 当前仅在 Rust CI 以 fake 内核/文件状态执行；尚未实现具有可审核身份和双确认的真实 root-only 管理 CLI，也未把 trait 接入真实 `/etc/wireguard` 原子写入/`wg set`，也未在 Linux network namespace 做端到端测试；不能将 test-only approval 放进 Python server。主生产服务仍为 `tc-pair.py serve`，老设备 revoke_script 未记持久 Rust tombstone，缺 RS256/JWE/旧邀请可信迁移、SEC-02 非 root Rust TLS。SEC-01/02/08 继续 Open，PR #3/#6 Draft，main 不合并。


## 第九阶段：Linux root-only Rust 只读恢复检查 CLI（无生产接线）

- [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7) 是基于 PR #6 HEAD `e380e820` 的**依赖式差异 PR**，新增可编译 Rust binary `spidervpn-pair-audit`。命令只含 root-only `inspect`，绝不将 `recovery_apply::AdministratorApproval` 的测试签发函数开放给 HTTP/CLI；没有 `approve`、`repair` 和自动 `wg set`。
- CLI 使用原 SEC-08 进程互斥锁、保护的 LedgerStore、Linux `wg show ... allowed-ips` 和仅 root 可读的 `wg.conf` 三份读回；出错统一拒绝，合法结果只显示 InviteId、Pending/Revoking 阶段、只读恢复建议和 live/config 存在布尔值。保护锁文件可能会在受保护目录内新建，其他持久状态和 WG 不修改；不声称是真正的零写入进程。
- 同代码 HEAD `1224512392e95f0e17d70b9160817ba323a41207` 的 [Linux Rust CI #44051677137](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44051677137)：Completed/Success，91 现有库回归+5 CLI 测试成功，非 root 真实 binary 运行收到 exit 2 / root required；没有演练 root+真实 WG 的成功路径，也没有测试真实设备撤销防重放。
- 上线前必须另行完成真实隔离 Linux namespace 中 root 读回、权限/失败注入、显式二次审批+不可重放 ticket、可信签名/迁移以及实际 Python receiver 替换；不合并到 main、不关闭 SEC-01 P0。


## 第十阶段：真实 Linux WG netns 内核读回专项（CI 隔离，无生产部署）

- 独立 Rust root-only 诊断功能 [Draft PR #7](https://github.com/weixiaochuchen618-debug/spidervpn/pull/7) 新增 `server-rs/tests/wg_namespace_e2e.rs`，编译由 `linux-netns-acceptance` feature 和专属工作流 job 明确开启，防止常规非 root 运行尝试修改宿主网卡。此 job 在 GitHub 临时 VM 上创建 disposable netns+WG 接口，受保护 `/etc/wireguard/spiderci0.conf`，测试结束移除。Rust CLI 本身只读、需 root；写状态/内核 peer 的部分全部仅由专属测试夹具和已有经验证测试 API 执行。
- [Linux CI #44062802733](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44062802733) 与 `5a8eb6047c1f1e3074fe66a075e9d295c0054a32` 一致，Completed/Success：lib 91 + CLI 5 + actual kernel netns 1，均 0 failed/0 ignored；此前因 Cargo 可执行文件自定义目录定位错误与真实日期期满夹具而失败的 CI 被完整保留，未跳过失败。严格 `--locked`/`-D warnings`。
- **仍不具备生产可操作的安全修复链**：本集成测试证实只读诊断+已完成终态补写在真实内核 fixture 可运行，不能证明 root-only 显式审批身份、安全 `RecoveryIo` 生产实现、真服务器 TLS/旧消费请求迁移、Windows 管理端同步或外部 root 不合作并发安全。先完善审核与可信迁移，再安排隔离 VPS 部署/回滚。SEC-01 P0 保持未修复。


## 第十一阶段：默认关闭的 root-only 本地终态确认与 Ledger 补写（生产未接）

- 基于 PR #7 的真实 Linux kernel/netns 绿色回归，单独建立 [Draft PR #8](https://github.com/weixiaochuchen618-debug/spidervpn/pull/8)。Rust 新 `admin_terminal` 模块只编译在 opt-in `linux-admin-finalize` 下。root + 控制终端 `/dev/tty` 才允许 45s 内确认，请求为 `FINALIZE InviteId Generation Stage`；不支持标准输入重定向、HTTP 或自动授权。再次严格三重 WG live/config/live readback + 重查代数和其它 peer，无偏差才调用原 `finalize_stable_prepared`。**只能补写已发生的终态，不运行 wg set、不修订 wg.conf**，且全部时间等待持有 SEC-08 独占 flock。
- Rust 测试包含拒绝路径、不可回放的 generation/stage challenge、短输入超时和漂移的 fail-closed；CI 的 root/PTy 测试由测试代码生成专用伪终端，只证明 root 可以进行真实 TTY 交互，**不证明 root 是自然人、不能防恶意 root**。最新候选 HEAD `b8cac95971ca468948c401f4ebce2b961989f0c4`，同 SHA Linux/MSVC/GNU CI 尚需最终结果。过渡红例 `-D warnings` 无用 import 已由 `e2e86e00` 删除，未跳测。
- 本能力不等于生产管理员审批/可恢复任意中断状态，更不等于 Python receiver 安全迁移。必须继续实机授权、可信签名迁移、真实 root/I/O 容错/断电以及 Windows revoke 同步验收，SEC-01 仍为未修复。


## 第十二阶段：旧 RS256 授权独立离线验签（不迁移线上授权）

- 基于 PR #8 安全候选，继续 [Draft PR #9](https://github.com/weixiaochuchen618-debug/spidervpn/pull/9)，`server-rs/src/legacy_signed.rs` 增加使用已锁定 ring 0.17.14 的纯 Rust 验签。它把旧 `tc-pair.py SignedAuthorization` 的签名验证与完整请求/设备/地址/server identity field binding 分离。签名来源必须是**独立可信的管理公钥**，不能自信任来自 JWS 或旧 JSON 的密钥字段；算法严格 RS256，拒绝 JWT alg 混淆、非规范编码、错签名/错服务器/旧记录字段替换。
- 输出仅 `ProofReport`，无新 `Grant`、no import、no WG mutation。旧记录缺 RequestDigest、签名未覆盖 RecipientJwkDigest 及旧撤销状态不能从旧授权凭空推断；仍需原签名设备请求和可信实时 WG/ledger 迁移。Python 只用于生成跨实现的独立测试签名夹具，绝不作为新生产验签。
- 当前候选 HEAD `4ca1c308688af5e9ce3785dd0da3fcac711de4bf`，对应 Linux [#44072823025](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823025) 与 Windows [MSVC #44072823427](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823427) [GNU #44072823056](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072823056) 必须按同 SHA 完成结果登记。之前因测试 E0502 与签名夹具 12 字符丢失的两个红 CI 保留；修正后 `3ff51bf3` 的 [Linux #44072627523](https://github.com/weixiaochuchen618-debug/spidervpn/actions/runs/44072627523) 已两 Job Success、97 library + 5 CLI + 1 真实 WG netns 通过。
- 真安全验收尚远：RS256 正向用例不代表能将旧 Python receiver 安全升级；需分离签名授权、设备原始请求、权限和实机撤销 readback 的各自证据链，完成 root-only 可信导入与完整在线 Rust TLS/HTTP 切换之后才可收 SEC-01。
