# SEC-09 Windows 卸载安全修复候选与实机验收

> 状态：Rust 候选开发中；实机未验收。不要在日常交易主机上首先执行卸载测试。
> 关联 [REMEDIATION_BACKLOG](./REMEDIATION_BACKLOG.md) 和 SEC-03 安装 ACL / SEC-10 UAC 清单。

## 修复目标和不变契约

默认卸载时先证明持久 WFP 规则已真正解除，且系统代理已经还原，然后才删除任何入口与二进制。**配置缺失绝不能把 exit 3 当成“无规则”。** 由 Rust 通过现有 WindowsWfp backend 的 remove() 事务删除**本产品拥有的 Provider / SubLayer / Filter**，并检查现场读回结果；同时在 HKLM 写入 Removed 标记，作废旧 Evidence，再读回确认。任何一步错误都保留 EXE 和卸载能力。

保留原有显式 -KeepGuard（用户确认保留持久阻断），其含义和风险必须可见；即使显式保留也不得绕过未还原的系统代理 journal。不得改变平时的连接、断开、正常 Guard 维护、UI 或 WFP BLOCK 持久性。

卸载器以管理员权限执行是 SEC-03 安装 DACL 保护后的要求；保留原卸载 cmd/脚本入口，但需要实际验证普通用户启动到 UAC 的可用性。旧版脚本会让用户输 FORCE 忽略代理未还原；SEC-09 将默认收紧为拒绝，直至正常断开恢复。

## Rust 实现与自动验证

- src/uninstall_safety.rs：--uninstall-preflight <目标安装目录> [--keep-guard]，强制管理员、正在运行的 EXE 必须位于目标 bin、拒绝目录联接/不安全目标、检查代理 journal，默认走实际 WFP remove/回读、写 Removed 标记并废弃旧证据。
- --uninstall-owns-shortcut <cmd文件> <目标安装目录>：严格匹配安装器生成的完整模板；陌生快捷方式或者其他路径一律不删。相比旧 Contains(TargetDir) 拦截 C:\SpiderVPN2 前缀误删。
- package-files/uninstall.ps1：只负责调用 Rust 和执行固定文件清单删除。Rust 非零退出不删程序；bin 清理含 spidervpn.exe、sing-box.exe、WebView2Loader.dll、sing-box.LICENSE.txt，不递归删未知 DLL，data 默认保留。
- Rust 单测：无 config.json 仍触发 WFP remove；失败/回读 provider 仍在拒绝且无 Removed 标记；即使 KeepGuard 遇到 journal 也拒绝；显式保留不触及 WFP；快捷方式精确匹配/邻近目录；清单正确。
- Rust 集成测试：CLI 在错误根、错误参数下 fail closed，无真实 WFP 调用；静态审查入口先于文件删除；CI 在 pwsh 仅解析脚本语法而不执行卸载。
- **CI 状态必须按最新 commit 的 MSVC 与 GNU 同一 SHA 核对**。通过自动化测试不等于真实安装/卸载/网络验证。

## 隔离 Win11 实机验收矩阵（当前全部未执行）

| ID | 操作 | 预期 |
|---|---|---|
| U01 | A 普通用户从原卸载入口启动 | 提权请求/提示清晰；UAC 拒绝不删除文件、入口和 data |
| U02 | B 管理员、config.json 缺失、WFP 规则确实存在 | Rust 不靠配置猜测，删除自有过滤器并读回确认后才能删 EXE |
| U03 | B、模拟 WFP BFE 不可用 / 访问拒绝 | 默认卸载 fail closed、程序及恢复入口还在 |
| U04 | B、WFP 仍有 Provider/SubLayer / 事务 commit/close 失败 | 卸载拒绝，不得报告“已解除” |
| U05 | A/B、proxy-journal.json 存在 | 无论是否 KeepGuard 都中止，原网络设置可恢复 |
| U06 | B、Guard 从未安装且无配置 | 幂等默认卸载仍需 WFP 实际查证，不误报错误 |
| U07 | B、使用 -KeepGuard | WFP 持久阻断不动；用户看到明确风险提示，仍保留相应恢复路径说明 |
| U08 | B、用 C:\SpiderVPN2 的桌面/菜单快捷方式伪装本安装 | 绝对不误删相邻版本 |
| U09 | B、启动菜单目录有额外自定义文件或快捷方式 | 只删本安装拥有的模板文件，不整目录递归删除 |
| U10 | B、完整安装包卸载 | spidervpn.exe、sing-box.exe、WebView2Loader.dll、LICENSE、脚本入口按清单处理，未报成功却残留主要引擎 |
| U11 | B、删除途中某文件被占用或拒绝访问 | 不谎报成功，保留可重试的诊断与恢复途径 |
| U12 | B、保留 data 卸载然后重装 | 用户配置、线路、凭据和原行为不变 |
| U13 | B、仅显式选择 DeleteData | 再次确认范围；不会删除相邻目录 |
| U14 | B、真实 Proxy/TUN / WFP Persistent BLOCK 回归 | 连接时持久 BLOCK 不被本修复意外删除，卸载前的解除步骤真实可观察 |

A = 普通账户；B = 独立管理员；C = 其他普通账户（参考 SEC-03 / SEC-10）。每项保存时间、SHA、SDDL、WFP Provider/SubLayer/Filter 读回、退出码、脚本 stdout/stderr、系统代理 before/after、回滚。

## 已知尚需审查

- WFP 确认与 PowerShell 实际删除之间仍是两个阶段；竞态/并发卸载与正在运行的其它进程需要隔离 VM 验收。
- 受保护目录要求管理员执行清理；普通用户双击卸载 cmd 是否顺利发起 UAC 必须验证，不能声称旧 UX 无变化。
- 默认阻断有未还原 journal 的强制卸载，是刻意的安全收紧；真实异常恢复路径需验收。
- -KeepGuard 明确保留 BLOCK，卸载后必须由重装或系统管理员才可解除；不得将此选项描述为安全的默认行为。
- 本候选只服务于 SEC-09；SEC-03 安装来源、SEC-10 跨账户 UAC 和 PR #3 WFP 动态租约仍独立未闭环。

**缺少实机证据前：SEC-09 仅标记“候选已提交/待真实验收”，Issue #5 不关闭，PR #6 保持 Draft，main 不合并。**
