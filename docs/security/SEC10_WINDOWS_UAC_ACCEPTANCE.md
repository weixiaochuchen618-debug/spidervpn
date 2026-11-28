# SEC-10 Windows 跨账户 UAC / ACL 实机验收矩阵

> 更新：2026-11-17。**以下是待执行测试方案，不是已通过记录。**  
> 关联：[PR #6](https://github.com/weixiaochuchen618-debug/spidervpn/pull/6)、[任务账本](./REMEDIATION_BACKLOG.md)、[详细方案](./SECURITY_REMEDIATION_PLAN.md)

## 0. 安全前提

- 在有快照/回滚能力的独立 Windows 11 虚拟机中执行。禁止直接在正常交易机器上尝试持久 WFP 或攻击故障注入。
- 建立独立的 A 标准用户、B 本地管理员、C 第二个标准用户。使用临时测试账号，不保存测试密码。
- 记录精确 Rust commit、MSVC/GNU CI、Windows 构建号、WFP Provider/filter 前后读回及回滚快照。
- 仅测试 SpiderVPN 自有 WFP Provider 和临时测试程序，绝不能写入其他安全厂商的规则。

## 1. 必须实际执行的验收矩阵

| ID | 场景 | 正确结果 |
|---|---|---|
| UAC-01 | A 创建受保护随机 Guard IPC 目录及空白回执，读取三者 DACL | 禁继承；原所有者 A、BA Administrators、SY SYSTEM 的显式权限保留；没有 AU/BU 组的宽松访问 |
| UAC-02 | A 标准用户发起原有 Guard 操作，在 UAC 输入独立管理员 B 的凭据 | B 可以读取请求、写入 A 所有的回执；A 可读取回执；不会因 ACL 加固破坏原有 Verify/Install/Sync/Remove |
| UAC-03 | A 在 UAC 对话框取消 | 明确 Declined；不新增 WFP 权限；不冒充成功 |
| UAC-04 | B 自身登录后以管理员方式执行 Guard | 正常读回、安装、同步和解除自有规则，保持旧交互 |
| UAC-05 | 其他低权限账户 C 尝试编辑 A 的请求/回执/目录，插入文件或创建 hard link | 拒绝写入、拒绝替换，不影响 A/B 正常协作 |
| UAC-06 | A 发起 UAC 后改写请求动作/AppId/设备路径/nonce/StoreKind | 被原始请求内容 SHA-256 与 UAC 启动参数绑定校验拒绝，不调用 WFP 后端 |
| UAC-07 | 不存在请求/回执、路径重解析点、符号链接、目录联接、硬链接 | 在 WFP backend 之前拒绝；不能利用回执路径替换其他文件 |
| UAC-08 | 事先向回执写入非空内容，或重复提交同一回执 | 拒绝覆盖；不得返回成功退出码 |
| UAC-09 | WFP、证据或回执写入失败，辅助进程崩溃 | 返回实际失败；保留诊断；持久规则状态可以重新读回 |
| UAC-10 | 人工造成一次性提权辅助进程 120 秒超时 | 父进程尝试终止并等待；任何不确定结果不得宣称保护成功 |
| UAC-11 | Release 版继承恶意 SPIDERVPN_ROOT 变量 | 正式安装根与 Guard HKLM 证据存储不被环境变量重定向；Debug/Test 环境仍可运行夹具 |
| UAC-12 | A 修改 config.json 的 engine.binary 为恶意 exe 再走提权连接模式 | 不可信引擎不得在管理员上下文执行；此项属于 SEC-03，目前仍未完成 |

## 2. CI 能证明什么、不能证明什么

- 自动化 Rust DACL SDDL 读回：可以核查显式 Owner Rights (OW)、Administrators (BA)、SYSTEM (SY) 和无宽松继承，但**不能代替**独立管理员账户 B 的真实 UAC 试验。
- 环境变量实验：应对不带 test/debug_assertions 配置的正式 Rust 模块做 Release 验证，不能用 cargo test 的 test cfg 冒充生产模式。
- 各项负对照在 Rust 中编写；不为让 CI 变绿而跳过 ACL、nonce、SHA256、硬链接或回执拒绝断言。
- A 用户的 TEMP 父目录在企业策略下可能不允许 B 管理员遍历；这种情况应 fail-closed，绝不能临时把目录权限改成 Authenticated Users 可写。
- 原有一次性提权通道是 PR #6；WFP 长期 lease 属于独立的 Draft PR #3。
- 在 UAC-02、05、06、11 取得真实证据前，SEC-10 只能写候选/待实机，不得勾选完成。

## 3. 每项实际验收记录模板

- 时间 / 时区 / Windows 版本 / VM 快照：
- 测试 commit SHA / MSVC + GNU CI：
- 测试 A/B/C 账户 SID（不存密码）：
- UAC-01～12 各自 Pass、Fail、Blocked 及原因：
- 请求/回执原始 SHA-256（不上传密码、私钥或敏感配置）：
- 相关文件 SDDL 读回及 WFP 自有 Provider 前后对照：
- 异常恢复/回滚结果：
- 剩余风险与下一步：
- SEC-10 和 SEC-03 是否分别达到 DoD：
