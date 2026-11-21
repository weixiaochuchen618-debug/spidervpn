# SpiderVPN 九项安全缺陷：分阶段修复技术实施方案

> **文档版本**：Plan v1.0 · 2026-11-17（Asia/Singapore）  
> **性质**：审查后的执行设计，**不是已实施的补丁或已通过的安全验收**。  
> **代码基准**：正式 `main` = `857ea7593941ce79f6507db5b1ced076c3a077ba`；候选 WFP PR [#3](https://github.com/weixiaochuchen618-debug/spidervpn/pull/3) HEAD = `2045acd42554b1ad1472ae41ab247b42d8df5655`，Draft、未合并。  
> **状态基准**：PR #3 的 Windows MSVC / GNU 工作流对上述 HEAD 都为 success；**仅证明该 SHA 覆盖的自动化检查通过**，不证明九项缺陷修复或真实 VPN 防泄漏验收。  
> **唯一任务账本**：[REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md)；**新 Agent 先读**：[AGENT_HANDOFF.md](./AGENT_HANDOFF.md)。

## 0. 不可改变的工程约束和范围

1. **全部新增安全核心逻辑、修复逻辑与产品功能使用 Rust 实现和编译。** 服务器现有 `assets/tc-pair.py` 的安全业务逻辑迁到单独的 Rust Linux 服务，而不是继续给生产 Python 逻辑叠补丁。原有 PowerShell 安装/卸载入口可以作为**无安全决策能力的薄包装器**，真正的校验、授权决策、状态迁移由 Rust 可执行文件负责。保留已有测试脚本作为对照工具并不意味着用 Python 开发新生产功能。
2. **不擅自改变原有 UI、连接/断开顺序、交易保护策略的含义、用户数据路径和默认行为。** 必须修改时，提供兼容迁移、回滚和对照测试，不做过度设计。尤其不能为了“安全”偷偷删除/放松已有的持久 WFP BLOCK。
3. **服务端发布协议兼容优先**：现有邀请码 `TCI1.`、JWS/JWE、请求/回包字段、错误码、WireGuard peer 与 `invites.json` 格式应通过金样本对照；不得在升级中让合法旧邀请或旧记录静默丢失。涉及已撤销设备的重放请求，**拒绝优先于兼容**。
4. **安全失败默认拒绝（fail-closed）**：未能确认身份、权限、连接目标、锁、事务、临时 WFP lease 时，不允许意外授予网络权限、删除陌生进程或擦除证据。区分“禁止进一步开放权限”和“是否允许原始 UI 连接继续”，具体遵守现有产品契约并明确回报“直连受阻/保护不完整”。
5. **PR 拆分**：一项/一组强相关缺陷一个独立 Rust 修复分支；PR #3 仅承载原始 WFP P0 候选，不把九项无关重构混进去。总验收通过后才能准备合并；用户未要求前不得把未验收代码合入 `main`。
6. **不要以 CI green 代替复现**：每项必须包含“修复前失败（或旧版已复现且可复跑）→ 修复后通过”的专门回归用例，覆盖拒绝路径、异常中断与历史数据兼容。实际机器的 ACL/UAC、网络中断和服务端并发必须单独测。

### 分支与流水线建议

- 文档基准：`docs/security-remediation-handoff-20261117`（从 `main` 分出，**文档专用**）。
- 修复分支举例：`fix/sec01-revocation-rust-paird`、`fix/sec03-privilege-boundary-rust`、`fix/sec05-pid-identity`；启动工作前先比较当前 `main` 与 PR #3 是否已有文件冲突。
- Windows：`Rust Windows build and tests`（MSVC）、`Windows GNU Rust release-path validation` 两套均必须成功；测试不得为了 green 而 `ignore` 或跳过安全断言。
- Linux 服务器：新增针对 Rust pairing daemon 的 x86_64 Linux build/test、协议 golden fixtures、真实 WireGuard/HTTP(S) 临时网络命名空间测试；最后做隔离 VPS 上的服务升级/回滚演练。按实际生产架构选择工具链，避免 Windows UI 依赖被 Linux crate 强制编译。
- 所有完成记录应写回任务账本：PR、commit、CI 链接、测试名称、实机验证记录、验收人和日期。

## 1. 服务端 Rust 迁移的共同架构（SEC-01/02/07/08）

**约束**：不以删除旧 Python 服务来假装漏洞已修复。先做兼容的 Rust Linux 服务器端候选，再通过部署入口切换；旧 Python 作为升级回滚前的兼容对象，正式切换前仍是**有风险的旧服务**。

建议新建独立 `server/paird` Cargo 包，二进制 `spidervpn-paird`，必要时把纯协议模型拆成不依赖 Windows UI 的 Rust 库；**不要直接让 Linux 构建整个 Windows `src/main.rs`**。

候选模块与职责：
- `api.rs`：现有 HTTP 路由与 `TCI1` 请求/回复模型；有界请求体、超时、显式状态码。
- `tls.rs`：rustls 受保护监听、握手超时、会话限制与证书有效期/固定指纹兼容。
- `store.rs`：邀请状态持久化，单实例/跨进程锁、原子更新、完整性验证和故障恢复。
- `policy.rs`：邀请状态机、首次 Consume、幂等重试、已撤销终态、重放窗口、身份一致性。
- `wg.rs`：经白名单校验的 WG 命令参数、peer 读回、配置原子提交、热同步和逆向恢复；不要把外部字符串原样拼 shell。
- `cli.rs`：与现有 `tc-pair.py init/create/status/cancel/authorize-request/serve` 对齐的管理 CLI；增加 `revoke-device` 原子撤销接口。
- `migration.rs`：旧 `invites.json`、证书、公钥、已消费记录兼容加载，必要时显式版本迁移和备份。

**状态与权限边界**：主服务尽可能在专用低权限 `spidervpn-pair` 用户下运行；WireGuard 高权限操作交给固定命令的受限本机 helper（也由 Rust 编译），不把通用 shell 或 root 权限暴露给 HTTP。systemd 使用 `NoNewPrivileges`、`ProtectSystem`、`PrivateTmp`、限制写路径、能力集和地址族，**必须验证 WG 更新需要的能力与 sandbox 相容**。改动前先记录实际现网依赖。

**切换步骤**：读取旧状态 → Rust dry-run 解码/对照 → 临时端口完整协议验收 → 暂停旧服务写入并锁定状态 → 备份 → 单次迁移 → 原子切换 systemd ExecStart → 健康检查 → 恢复写入；失败必须可回滚到数据兼容状态，**不得两套服务同时写同一邀请状态**。

## 2. SEC-01｜撤销设备后通过旧申请重新入网（P0，高）

**证据路径**：`assets/tc-pair.py:1195-1277`，尤其 `1230-1246` 的 `Consumed` 重试分支；`src/deploy.rs:849-891` 现有撤销只移除 peer。旧版审查已离线复现；当前 HEAD 的危险分支仍存在，**本轮没有新实机利用演示**。

**修复设计**：
1. Rust 状态机为每次授权保存不可变元组 `(InviteId, RequestId, DeviceId, ClientPublicKey, RecipientJwkDigest, AssignedAddress, ConsumedAtUtc, State)`，对历史数据使用可复核的兼容读取器。
2. 将撤销写为服务端**不可逆终态 `Revoked`**，保留撤销时间、对应公钥及审计记录；旧的 `Consumed` 不能再因为“重试”恢复 peer。移除 WG peer 与标记 `Revoked` 走单个受锁操作，有失败日志和崩溃恢复方案。
3. `Consumed` 幂等重试只接受 **RequestId + DeviceId + ClientPublicKey + RecipientJwkDigest 全部一致**、授权未撤销、原 peer 存在且对应原地址、处于明确有限的重试窗口内。窗口采用已签发的 `RetryUntilUtc` 或有版本的同义策略；禁止继续用不限期 `Consumed` 重放。
4. 若状态显示 `Consumed` 但 WG peer 不在：**不得自动“补回”已撤销设备**。需要服务端凭审计/撤销日志确认处于“首次提交未完成”的内部事务后才能重试，否则拒绝并要求新邀请。历史无法证明的情况拒绝。
5. 禁止同一个分配地址对应两个不同公钥；发现冲突直接拒绝并报警，不继续写入配置。

**必须补的回归测试**：首办成功；同请求在允许窗口内幂等且没有第二 peer；改 `ClientPublicKey` 或 `DeviceId` 的重放被拒；撤销后原公钥重放被拒；撤销后替换公钥被拒；时间过期被拒；撤销写状态失败/配置变更失败不产生“peer 已移除却仍可自动恢复”的状态；HTTP 和离线管理 CLI 走同一状态机。

**验收完成条件**：至少两个旧版可复现用例变为拒绝；重放不恢复任何 WG peer、无地址冲突；断电故障注入后可自洽；受限 VPS 审计确认。

## 3. SEC-02｜空闲 TCP 连接阻塞 TLS 邀请服务（P0，高）

**证据**：`assets/tc-pair.py:1450-1457` 在监听 socket 调用阻塞 `wrap_socket(...)`；`pairhost.rs:36-47` root systemd 单元。

**修复设计**：Rust `TcpListener` 先 accept、每条连接交由异步任务/工作线程，再执行 rustls TLS handshake；**设置 3–5 秒可配置的握手超时**、总连接并发 semaphore、每来源并发限制、读写/headers/body 超时和大小上限，超时后释放资源。不能在全局 accept loop 同步阻塞 TLS。将服务基础权限降到最小，管理更新由受限 helper 完成。注意 HTTPS TLS 1.2 与当前客户端 pin 兼容性，变更协议版本须有对照测试。

**测试**：1 条空闲 TCP socket 不妨碍第二条合法 HTTPS 请求；多条慢连接不耗尽线程/FD；手动断开后无挂起；正常获取描述符/消费不受影响；重启/崩溃可恢复。

**DoD**：隔离 VPS 并发故障注入、延迟与资源限额达到基线，服务不会被单个慢握手串行卡死。

## 4. SEC-03｜安装与提权信任边界（P0，高，视本地威胁模型）

**证据**：`package-files/install.ps1` 默认 `C:\SpiderVPN` 且说明普通用户可写；`src/engine.rs:163-191` 优先选 `config.json` 指定的现存 exe；`src/isolation.rs:31-45` 正式构建允许 `SPIDERVPN_ROOT`；管理员启动整个程序。

**修复设计**：
1. 首选安装可执行文件到 `%ProgramFiles%\SpiderVPN`（或原目录但用 Rust 安装器设置并读回**受保护 DACL**），仅 Administrators/SYSTEM 有修改权限；同一设计覆盖 exe、`sing-box.exe`、DLL、管理员 .cmd、卸载组件和升级路径。避免安装目录“目录被保护但子文件可替换”的 ACL 漏洞。
2. 用户配置与特权程序分离：普通用户可管理偏好，不可凭篡改 `engine.binary` 就决定一个提升权限的进程执行什么。特权路径从受信程序目录的 canonical/safe handle 解析，核验签名/预置哈希或严格 allowlist；手选第三方引擎的兼容性要求单独明确，不允许静默提升任意路径。
3. 管理员端所有 action **重新派生和验证交易程序身份、路径、请求类型、资源所有权**，不可仅凭普通用户写的配置或 JSON 请求授权。Windows 下检查 reparse point、junction、硬链接、父目录 ACL；文件验证与执行之间避免 TOCTOU（尽可能通过已打开句柄/身份和不可写目录绑定）。
4. 将 `SPIDERVPN_ROOT` 测试覆盖只编进测试/明确的开发配置；生产环境不接受此钩子。逐步迁移 `C:\SpiderVPN\data`，保留原配置与回滚记录；数据路径变化不影响用户线路。
5. 不把“管理员启动当前用户可写 exe”当作安全保障；测试覆盖本地低权限账户、普通恶意进程和 UAC 被拒情况。

**回归**：非管理员不能替换受信 exe/DLL/脚本；篡改配置引擎路径不会得到管理员执行；符号链接/目录联接/跨卷重定向被拒；升级及回滚仍可启动；无需改变原 UI 按钮。

**DoD**：Windows 多账户测试、ACL 逐文件读回、进程实际镜像路径核验和 UAC 提升链检查通过。

## 5. SEC-04｜私钥与敏感状态文件 DACL 覆盖不足（P1，中，已有部分基础）

**证据**：`secretfile.rs:91-116` 仅覆盖 `servers/*/client.conf`、`tunnel.key` 和 `lines/*.json`；`main.rs:642-705` 的身份导出使用 `std::fs::write`，可能含 REALITY 私钥。

**修复设计**：
- 重用/扩展 Rust `secretfile` 的“临时文件首先加 DACL → 写入 → flush/sync → 原子替换”机制；所有私钥导出/备份（用户指定路径也必须拒绝宽 ACL 或收紧后读回）归此管理。
- 将**机密性**和**完整性**分级：`exports/*.json`、`client.conf`、`tunnel.key`、`lines/*.json` 是保密文件；`config.json`、`runtime.json`、`proxy-journal.json`、服务器 SSH 指纹记录等主要保障特权逻辑的**防篡改**，不能一律剥夺合法普通用户读写；在程序与提权 broker 之间重新划分有权修改的数据。
- 根目录和所有父目录的 ACL、junction/reparse 逐级验收；避免同用户恶意程序能篡改提权请求的缺陷（需要 SEC-03/SEC-10 的额外信任边界）。

**测试**：非授权用户读取 REALITY 导出失败；已有旧导出扫描/升级可收紧；自定义导出目标宽 ACL 时拒绝或正确收紧；普通用户配置、导入恢复、代理恢复不退化。

**DoD**：Windows ACL 实机双账户验证 + 关键凭据全覆盖清单 + 启动后扫描对历史文件生效。

## 6. SEC-05｜PID 复用误杀与自愈误判（P1，中）

**证据**：`engine.rs:100-136` 通过 `taskkill /PID ... /T /F` 停止，`connect.rs:531-535` 按 `runtime.json` 的 `EnginePid` 调用 kill，`connect.rs:689-720` 自愈只判断 PID 存活。

**修复设计**：
- Rust `EngineHandle` 在生命周期内保留 Windows 内核进程 HANDLE，spawn 后记录 `pid + process creation time(FILETIME) + canonical image path + session/generation nonce` 到带版本的运行记录；关闭时使用同一个 HANDLE 等待/终止，禁止直接信任可能复用的 pid。
- 程序重启后不能复用 HANDLE：重新以 `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` 打开 PID，核对**创建时间 + 完整镜像路径**（必要时镜像签名/文件 ID），不一致时拒绝 kill 并把记录标记为 stale/未知。
- `heal_stale` 以“原引擎身份是否仍存活”为准，而不是“这个 PID 是否有人在用”；身份不符应按过期引擎进行安全恢复，但不得碰陌生进程。先保证代理可恢复，保留错误记录以便诊断；注意升级前无 creation time 的旧 `runtime.json` 必须采用保守兼容处理。

**测试**：模拟 PID 复用不误杀，旧 PID 对应陌生 exe 时不阻止代理恢复；优雅和强制停止真实子进程；重启后使用创建时间匹配；失败不删全部证据。

**DoD**：Windows 子进程/跨启动实机回归通过，连接/断开、异常退出不改变原有交互。

## 7. SEC-06｜TCP 443 与身份校验互相冲突（P1，中）

**证据**：`uiweb_form.rs:57,705` 默认 443；`deploy.rs:1933-1934` `validate_identity` 拒绝小于 1024；`deploy.rs:3325-3340` 部署只允许 443/8443/2443。

**修复设计**：Rust 新增单一 `validate_transport_tcp_port` / `AllowedTransportPort` 类型，明确允许集合 `443 | 8443 | 2443`（保持当前 UI/部署范围），部署、导出、导入、恢复、服务端回读、UI 校验共享相同逻辑。**不要仅简单放开任意 1..65535**，避免与原部署规范冲突。

**测试**：三种允许端口全链路往返；0、非白名单端口拒绝；旧版本 443 数据无迁移问题；导出/恢复均通过；不额外修改 UI 默认值。

**DoD**：同一输入在各路径判断一致，复现原 443 导出失败用例转绿。

## 8. SEC-07｜固定 TLS 证书过期与错误提示（P1，中）

**证据**：`tc-pair.py:68` `CERT_DAYS=825`；`ensure_cert:352-357` 仅缺文件时生成；Rust 客户端 `pairing.rs:4556-4581` 同时检验固定指纹与有效期，失败统一 `ApplicationVerificationFailure`。

**修复设计**：
- Rust daemon 在启动和健康状态中检查 `notBefore/notAfter`，提前 30/14/7 天分级告警；由管理员明确确认并触发证书轮换。**不能静默换证使已签发、固定证书指纹的邀请码突然失效**：将新 TLS 指纹与管理签名身份、邀请码重新签发/发布，保存清晰的代际边界。
- 客户端单独区分“指纹不符”“证书过期”“尚未生效”“格式无效”，仍全部拒绝握手；**绝不以允许过期证书代替续期**。
- 服务端证书轮换和邀请码重新发布构成一个管理事务，有回滚和迁移提示；签名身份与 TLS 身份不是同一把密钥。

**测试**：时钟前移模拟即将过期/过期；pin 匹配但过期返回 expired；pin 不匹配返回 mismatch；正常证书不断线；轮换前后新旧邀请得到明确结果。

**DoD**：隔离服务端证书轮换演练及客户端错误码回归通过，提醒可由 UI/CLI 观察。

## 9. SEC-08｜邀请与 WG 状态跨进程竞争（P1，中低，但可放大 SEC-01）

**证据**：`tc-pair.py:82` 只有 `threading.Lock()`；`create/cancel/authorize-request` 独立进程；`write_json:238-242` 固定 `.tmp` 名称。

**修复设计**：
- Rust `store.rs` 使用系统范围独占锁（Linux `flock` 或明确的跨进程 fd 文件锁）；**锁域必须涵盖读取邀请状态 → 查 WG peer/地址分配 → 配置更新 → 状态提交**，所有入口 `create/cancel/consume/authorize/revoke` 共用一把锁序，不允许只锁文件写入。
- 临时文件采用随机唯一名/同一文件系统、`create_new`、权限 0600、`sync_all`、原子 rename、目录 fsync；拒绝符号链接，固定目录所有权/权限。旧 `.tmp` 恢复策略需要版本号/校验而不是盲目覆盖。
- 对 `wg0.conf` 与 `invites.json` 的跨文件事务实现**日志式意图记录/恢复**或可重放阶段状态，并有故障注入；仅靠两个原子 rename 不是跨文件原子事务。
- 若旧 Python CLI 仍运行，应先统一到 Rust CLI；禁止不同实现同时直接改相同状态文件。此项与 SEC-01 同一 Rust daemon 迁移中解决。

**测试**：多进程并发 50–200 次 create/consume/cancel/revoke，保持地址唯一、邀请终态单调；kill -9 在不同阶段恢复；固定 tmp 不相互覆盖；权限/锁超时失败拒绝。

**DoD**：并发及崩溃恢复测试通过，旧状态迁移后无已撤销邀请复活。

## 10. SEC-09｜卸载残留/Guard 解除失败仍删除程序（P1，中低，含高影响分支）

**证据**：`package-files/uninstall.ps1:90-101` 退出码 3 继续；`133-141` 只删除 exe 和 WebView DLL；`PointsHere` 用 `Contains` 检查入口归属。

**修复设计**：
- 将卸载预检查和 Guard 状态判定封装到 Rust `uninstall` 子命令；原 PowerShell 只负责调用 Rust 预检查与按返回 manifest 执行不涉及授权判断的清理、提示和自删除。
- 默认**先证明持久 WFP BLOCK 已解除**（包括“config 缺失且不能确定是否有规则”的情况），否则必须拒绝删 exe；用户明确选择 `KeepGuard` 例外时记录风险、留下可修复路径。
- 清理安装器记录的**文件 manifest**：`spidervpn.exe`、`sing-box.exe`、WebView DLL、许可证、脚本以及仅属于当前安装的入口；先验证真实安装目录范围/文件 ID，禁止误删相邻目录/其他版本。
- 用 Windows 规范化路径、组件比较、忽略大小写的精确归属代替子串 `.Contains()`，同时防 `C:\SpiderVPN` 错匹配 `C:\SpiderVPN2`；最小权限原则，保留用户数据默认行为。
- 覆盖用户取消、代理 journal 未恢复、引擎仍运行、Guard 中断时的中止/回滚。

**测试**：Guard exit 0/3/权限拒绝/读回失败；`-KeepGuard`；安装目录大小写变化与相邻目录；完整 bin 清理；默认保留 data；多版本共存不相互影响。

**DoD**：临时 Windows VM 安装—升级—卸载实际走通；任何未确认的持久阻断都不因默认卸载遗留成“无程序可清理”状态。

## 11. 审查额外发现的风险（不计入原始九项，但必须进入工作清单）

### SEC-10｜旧 `--guard-apply` 提权请求可信性（P0）

**证据**：`guard/elevate.rs:208-256,361-407`，父进程在 `temp_dir()/SpiderVPN-guard-<nonce>` 建目录写 JSON，子进程仅反序列化动作/数量便执行 WFP 操作；**注释声称私有 ACL，但实际创建代码没有明确设置与读回 DACL**。PR #3 新增 `lease_helper.rs` 的身份复核并不覆盖这条旧路径。

**技术方案**：把一次性 Guard 和长期 lease 的 IPC 放到同一个可复用 **Rust 特权 IPC 安全基础库**：随机不可预测会话 ID、拒绝重用现有目录、仅当前允许主体和 Admin/SYSTEM 的 DACL、子进程打开文件时拒绝 reparse/hardlink/TOCTOU，原子写入与严格大小限制；最重要的是提权子进程**重新派生程序的 Windows AppId、校验本次动作和资源所有权**，不信任 JSON 自称权限。必要时以命名管道+客户端 token/进程句柄身份替代可变临时文件；选择哪条须根据实机威胁测试决定。不得让合法 non-admin Guard Install/Verify 失去可用性。

**DoD**：同机其他普通账户无法写/替换请求或启动劫持；模拟临时请求被替换、伪造 AppId、重放旧 nonce 必须拒绝；WFP 不增加陌生规则。此项应与 SEC-03 同一安全审查 PR 组织。

### SEC-11｜UTF-8 byte slicing / 生产 panic（P1）

**已定位**：`uiweb_form.rs:6828-6834` 的 `short_time` 用 `&ts[5..10]` 和 `&ts[11..16]`，只检查字节长度和第 10 字节；多字节字符可触发 panic。`pairing.rs:2068-2074` 的 `wireguard_key` 用 `value[..43]`，长度/末尾字节满足但 43 不在字符边界时可能 panic。其他固定形状 hex 切片应证明 ASCII 来源或改用字节数组。生产 `engine.rs` 日志文件复制与 `deployengine.rs` 监督线程 `expect` 应审查是否能被实际故障触发。

**修复**：时间先 RFC3339/ASCII 形状验证，再安全 `get(..)`；WireGuard 公钥 `as_bytes()` 逐字节检查，不对任意 UTF-8 用固定字节下标；失败报告错误/原样回退，不 panic。生产 `unwrap/expect` 走合理 Result/错误记录；新增随机 Unicode 和 fuzz/proptest 风格输入回归，禁止把正常非法输入变成程序退出。

**DoD**：中文、emoji、组合字符、无效时间戳、44 字节边界输入不 panic，继续保留正确 ASCII 解析。

### 附带任务（BACKLOG 标记 AUX）

- `tc-pair.py:303-311` 的 WireGuard 双栈 `Address = IPv4, IPv6` 解析：在 Rust daemon 移植时先提取 IPv4 CIDR，不误处理 IPv6 或失效的地址；单元测试覆盖多地址和空值。
- `vendor/sing-box.LICENSE.txt` 不包含完整 GPL-3.0 文本：依实际发布合规要求补齐许可证文本、来源和源码获取/构建说明；合规项非已证实的软件漏洞，需要明确核查依赖分发义务。
- `pairhost.rs` systemd root 与沙箱缺失纳入 SEC-02/SEC-03 的最小权限设计。
- 扩大对 `src/ipc.rs`、`src/uiweb*.rs`、`src/config.rs` 等未完全细审范围的 fuzz、边界与权限审查，不能仅凭 grep 宣称全库没有 panic。

## 12. 实际执行顺序、依赖与交付物

| 阶段 | 工作内容 | 依赖 | 阶段交付门槛 |
|---|---|---|---|
| M0 基线与复现 | 固定 main/PR3 SHA、旧版失败用例、CI、回滚材料和测试环境 | 无 | 文档和复现记录可追溯 |
| M1 权限边界 | SEC-03 + SEC-10；先修一次性 Guard IPC、安装/引擎路径信任 | M0 | 双账户/UAC/伪造请求测试通过，不破坏现有操作 |
| M2 Rust 服务安全核心 | SEC-01 + SEC-08，Rust daemon 与状态机/跨进程事务 | M0（可与 M1 并行） | 旧请求重放/撤销/并发/崩溃回归通过 |
| M3 Rust TLS 与迁移 | SEC-02 + SEC-07，服务端超时/最低权限/证书代际 | M2 的服务端候选 | 慢连接攻击阻断 + 邀请/TLS 兼容 + VPS 迁移演练 |
| M4 本地数据/运行时 | SEC-04 + SEC-05 + SEC-09，ACL/PID/卸载安全 | M1 的权限设计 | Windows 双账户、异常恢复、卸载演练 |
| M5 兼容性与稳定性 | SEC-06 + SEC-11 + AUX | 可独立提前做小 PR | 443、Unicode、双栈、许可证交付物验收 |
| M6 WFP P0 收口 | WFP-01～05，长期 helper、动态许可、TUN 生命周期与证据/回滚 | M1、M4 的可信边界 | 真实 Windows TUN 断线/进程崩溃/端口劫持零非预期直连；再评估合并 |

**依赖说明**：可以先做 SEC-06/SEC-11 两个小 PR 取得易验证成果，但不能用它们代替 P0。服务器端 SEC-01 的交付不能只说“Rust 状态机写好了”——**实际部署的服务仍是 Python 时，漏洞仍在生产路径中**。任何代码迁移都必须先留下回退方式。

## 13. 统一 DoD / 不可绕过的发布闸门

每张 SEC/WFP 任务卡只有在全部条件满足时才能打 `[x]`：
- [ ] 对应的风险用例能在旧版/故障注入中失败，修复版通过；同时保存正常场景对照。
- [ ] 生产安全逻辑由 Rust 编译；必要的 Powershell/Python 仍只是包装或测试，不承载新的安全决策。
- [ ] 代码变更最小化、旧交互不变、数据格式兼容/迁移/回滚证据完整。
- [ ] 目标平台的编译和针对性测试绿；Windows 项同时核对 MSVC/GNU，不把已取消或旧 SHA 的 CI 当最终证据。
- [ ] 安全否定路径（撤销、恶意输入、管理员拒绝、低权限修改、断线/崩溃）完整通过。
- [ ] 独立复审“新功能是否破坏原功能”；对 WFP 还要核对现有持久 BLOCK 不被移除或错误放行。
- [ ] PR 合并准入明确；没有真实验收的 P0 保持 Draft；任务账本填入 commit、链接和验收记录。

**任何新 Agent 接手：先读 HANDOFF → BACKLOG → 本方案 → 按当时最新 SHA 核对源文件与 CI → 只选择一张任务卡推进。**
