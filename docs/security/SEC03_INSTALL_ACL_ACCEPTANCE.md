# SEC-03 安装目录可信边界：Windows 实机验收清单

> 状态：P0 未完成实机安全验收；不能合并 main。与 [SEC10_WINDOWS_UAC_ACCEPTANCE.md](./SEC10_WINDOWS_UAC_ACCEPTANCE.md) 联合执行。

## 候选能力与不能替代的证据

Rust 安装阶段负责 Win32 受保护 DACL 的创建、收紧与现场读回；原 PowerShell 安装器只在复制前后调用 Rust 的 --install-seal。root、bin、程序 EXE、随包引擎、DLL 与启动/卸载脚本只允许管理员修改；data 保持既有路径及普通用户写权限。任何权限步骤失败不得输出“安装成功”。本轮不修改 UI、Proxy/TUN 操作或 WFP 持久 BLOCK。

当前并不证明安装包来源、签名可信、恶意预置文件处理无竞态、跨账户 OWNER RIGHTS 行为或真实 WFP 网络安全。发布包只能来自可信来源，不能把可能被篡改的 expected.sha256 与二进制放在同一信任等级。真实验收缺失时任务仍必须 Open。

## 环境

准备独立 Windows 11 VM 快照，A 为普通用户，B 为不同账户的本机管理员，C 为第三个普通账户。保存安装前的 data、Guard 证据、程序 SHA256 和 Windows 版本。不可在日常交易主机上直接演练破坏性操作。

## 必须逐项填写结果（全部暂未执行）

| ID | 发起账户 | 验收动作 | 必须得到的结果 |
|---|---|---|---|
| I01 | A | 未提权运行安装程序 | Rust 在复制前拒绝，未留下未保护的新代码目录 |
| I02 | B | 新装 C:\SpiderVPN | root、bin、EXE、引擎、DLL、.cmd、uninstall.ps1 读回受保护 ACL |
| I03 | A | 修改、覆盖、重命名、删除三种 bin 核心文件 | 均 Access Denied；原文件 SHA256 不变 |
| I04 | C | 改写 bin、管理员启动脚本与卸载脚本 | 均拒绝；原文件 SHA256 不变 |
| I05 | A | 编辑 data/config.json、导入线路、连接/断开 | 数据可正常读写，代理连接与还原逻辑不变 |
| I06 | B | 管理员 Proxy/TUN 分别选择其他目录的 EXE | 拒绝任意引擎提权执行，不启动外部程序 |
| I07 | A/B | 预置 junction/symlink/未知 DLL 后安装 | 拒绝链接/未知执行代码，不自动删除未知文件 |
| I08 | A/B | A 拥有旧版宽权限 bin，B 升级收紧 | A 即使仍是历史 Owner 也无法恢复写权限 |
| I09 | B | 重复安装与升级 | 二进制更新、data 完整、ACL 继续受保护、程序能启动 |
| I10 | A/B | 原 Proxy/TUN、Guard install/verify、异常退出 | WFP 持久 BLOCK 与 Proxy 恢复不变 |
| I11 | B | 缺包文件、改包 SHA、破坏 DLL | 安装中止，无假成功 |
| I12 | B | 卸载/回滚 | 需先完成 SEC-09 的 Guard 安全卸载，不能删掉仍需解除持久 BLOCK 的唯一客户端 |

每项要记录时间、账户 Token/角色、前后 SDDL、SHA256、实际写删操作及错误码、预期/实际、回滚证据。测试失败不能跳过。

## Rust 自动回归的覆盖边界

- install_trust::tests::：新装权限、历史宽权限、异常 DLL 与危险路径；不模拟不同 Windows 身份。
- tests/install-seal-e2e.rs：真实 Rust 命令入口、Admin gate、data 可写及拒绝卷根。
- Windows MSVC 与 GNU 需针对同一最终 HEAD SHA 编译和运行上述用例；已取消或旧 SHA CI 不作验收。

A/B/C 未完成前，SEC-03 与 SEC-10 均不能以自动化 CI 绿色视为真正安全修复完成；PR #6 继续 Draft，Issue #5 不关闭。