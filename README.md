# SpiderVPN

Windows 桌面 VPN 客户端。自带服务器部署、线路管理、交易程序直连阻断，单文件可执行程序，装完即用。

> 当前版本：**0.1.4**（Windows 10/11 x64）

SpiderVPN 不绑定任何服务商。它管理的是**你自己的服务器**：一台 Linux VPS、一份 WireGuard 配置，或者任意支持 socks 的本地客户端。所有线路、密钥、连接记录都留在本机 `C:\SpiderVPN\data`，程序不向任何第三方上报。

---

## 它解决什么问题

普通 VPN 客户端只管「把流量送出去」。真正在交易、办公环境里用，还会碰到三类麻烦，SpiderVPN 针对它们做了专门处理：

| 麻烦 | SpiderVPN 的做法 |
|---|---|
| 交易终端不读系统代理，直连就绕过了隧道 | **交易程序直连阻断**：用 Windows 过滤平台（WFP）在内核层拦掉名单内程序的直连，只放行隧道 |
| UDP 线路在部分网络被限速或阻断，TCP 又慢 | **线路级三档连接方式**：标准（WireGuard UDP 直连）/ 兼容（WireGuard over VLESS+REALITY）/ 自动（采用这条线路验证成功过的方式） |
| 换电脑、加设备要重新配一遍 | **邀请码**：在已连通的电脑上生成一次性邀请码，新电脑输入即可加入同一张网，地址与密钥自动分配 |

---

## 功能

### 线路

- 导入标准 sing-box 配置，一条线路一个文件，互不影响
- 多线路并存，随时切换；每条线路独立记录连接方式、出口网卡、最近一次成功时间
- 三档连接方式（标准 / 兼容 / 自动），只影响下次连接，不打断当前会话
- 线路测速与延迟曲线，历史记录落盘
- 出口证据分级：只有「自检通过 + 观测到出口 IP + 归属到该线路服务器」才显示「已核验」，其余如实说「转发已通」或「尚未核验」

### 连接

- 一键连接 / 断开，连接前自检（端口占用、引擎可用性、旧连接残留）
- 系统代理接管前先写还原日志；断开时按日志还原，且**当前值已被别人改过就不覆盖**
- 关闭窗口默认收进托盘，连接继续；托盘菜单可退出
- 开机自启（可选）、登录后自动连接（默认关闭）
- 引擎（sing-box）随包分发，装完就能连，不需要另外找程序

### 交易保护

- 名单内程序（交易终端、行情软件、浏览器）在内核层阻断直连，只允许走隧道
- 名单支持进程名、路径、域名三类规则
- 保护状态三态可见（已保护 / 部分保护 / 未保护），带证据时龄；未能重新核验时如实标注
- 未提权时**不阻断连接**，但会在首页明确写出「本次未启用交易保护」
- 卸载默认解除保护（`-KeepGuard` 可保留）

### 分流

- 三条出口线：**交易** / **日常上网** / **AI 助手**
- 每个程序、每个域名可单独指定走哪条线；日常与 AI 切换即时生效，不影响交易连接
- 内置常见交易软件、行情站点、AI 服务的规则目录，可逐项勾选

### 服务商

- 自动发现本机已落地的 Clash Verge / BatVPN 配置，登记为可用出口
- 优先使用服务商托管块里的独立入口，没有才退回 mixed-port
- 只读发现，不保存订阅、不碰节点密码

### 服务器部署

- 从本机 SSH 直连自己的 Linux VPS，一条命令完成部署并接入本机
- 首次连接核对 SSH 主机指纹，之后指纹变化即拒绝
- 部署过程有检查点，中断后可续；已部署的服务器可再次维护（换协议、导出/恢复身份备份、清理资料）
- 服务器侧组件全部为纯 Python + systemd，不依赖容器

### 设备与邀请

- 生成一次性邀请码（默认 30 分钟），新电脑输入即加入
- 离线邀请（24 小时有效），适合对方暂时连不上管理端的情况
- 设备列表可改名、撤销；撤销前先给权威预览，确认后才真的动服务器
- 邀请码只显示前 18 字符预览，点「显示」才取完整码，取完即从页面状态里清掉

### 诊断与记录

- 结构化诊断：TCP 可达、UDP 端点、DNS、HTTPS、出口归属，每项给结论与下一步
- 操作记录（连接 / 断开 / 线路改动 / 部署）落盘，可筛选、复制、导出
- 性能采样：启动耗时、空闲 CPU，历史可查

---

## 安装

### 方式一：安装包（推荐）

1. 到 [Releases](https://github.com/weixiaochuchen618-debug/spidervpn/releases) 下载 `SpiderVPN-0.1.4-windows-x64.zip`
2. 解压到任意目录
3. 双击 **一键安装.cmd**
4. 双击桌面「启动SpiderVPN.cmd」

安装位置 `C:\SpiderVPN`，普通权限即可，不需要管理员。TUN 模式（接管不读系统代理的程序）需要用「以管理员身份启动SpiderVPN.cmd」。

> 程序没有代码签名。Windows 第一次运行会提示「已保护你的电脑」，点「更多信息 → 仍要运行」即可。

### 方式二：免安装

解压后直接双击 **直接运行（免安装）.cmd**。数据仍固定在 `C:\SpiderVPN\data`，与程序放哪无关，换目录不会丢配置。

### 系统要求

- Windows 10 1809 及以上 / Windows 11，x64
- WebView2 运行时（Win10/11 一般自带；没有时界面无法启动）
- TUN 模式与交易保护需要管理员权限

---

## 快速上手

### 有现成服务器

线路页 →「添加线路」→ 导入 sing-box 配置（JSON）→ 点「连接」。

### 没有服务器

在一台 Linux VPS 上（Debian/Ubuntu，root 或 sudo）：

```powershell
spidervpn.exe --server-setup root@203.0.113.10
```

程序会核对指纹、上传组件、配置 WireGuard、把本机接进去，最后在本地生成一条可用线路。

### 加一台新电脑

已连通的电脑上：线路页 →「邀请其他电脑」→ 生成邀请码 → 新电脑输入。

### 保护交易终端

应用页勾选交易终端（或手动添加进程名/路径）→ 用管理员身份启动 → 连接。首页会显示「交易保护」状态。

---

## 命令行

不带参数运行会打开界面。常用命令：

```text
spidervpn.exe --status              查看连接状态
spidervpn.exe --lines               列出线路（含连接方式）
spidervpn.exe --connect             连接当前线路
spidervpn.exe --disconnect          断开
spidervpn.exe --diagnose            诊断当前线路
spidervpn.exe --history             操作记录（最新在前）
spidervpn.exe --guard-status        交易保护状态
spidervpn.exe --providers           服务商出口列表
spidervpn.exe --help                全部命令
```

服务器与邀请：

```text
spidervpn.exe --server-inspect  root@HOST     只读检查（不改服务器）
spidervpn.exe --server-setup    root@HOST     部署并接入本机
spidervpn.exe --server-deploy   root@HOST     只打印部署计划
spidervpn.exe --invite-init     root@HOST     初始化邀请服务
spidervpn.exe --invite-create   root@HOST     生成邀请码
spidervpn.exe --invite-check    TCI1.xxx      校验邀请码（只读）
```

完整参数、退出码与记录格式见 [`docs/ipc-contract-0.1.4.md`](docs/ipc-contract-0.1.4.md)。

---

## 数据与隐私

| 位置 | 内容 |
|---|---|
| `C:\SpiderVPN\data\config.json` | 线路索引、当前选择、偏好 |
| `C:\SpiderVPN\data\lines\` | 每条线路的引擎配置（含私钥，DACL 收紧到 SYSTEM + Administrators + 所有者） |
| `C:\SpiderVPN\data\servers\` | 服务器记录、部署资料、长期凭据 |
| `C:\SpiderVPN\data\logs\` | 操作记录、运行日志 |
| `C:\SpiderVPN\data\WebView2\` | 界面缓存 |

- 程序**不向任何厂商服务器上报**：没有账号体系、没有遥测、没有云端配置
- 唯一的对外连接是**你自己填的服务器**，以及连接后为了验证出口而请求的公共 IP 回显服务
- 密码、私钥在落盘前收紧访问控制；任务级凭据最长保存 24 小时，任务结束即删
- 卸载默认保留数据目录，要一起删必须手工输入 `DELETE`

---

## 从源码构建

工具链是 **GNU 目标 + Rust 自带 lld**，不需要 Visual Studio 或 Windows SDK。

```powershell
# 1. 装 Rust（GNU 目标）
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal

# 2. 装完整 MinGW-w64（rustup 自带的不全，缺 dlltool）
winget install BrechtSanders.WinLibs.POSIX.UCRT
# 或解压到 C:\tc-rs-tools\winlibs，build.ps1 会自动找到

# 3. 构建
powershell -NoProfile -File build.ps1 -Release
```

产物：`C:\tc-rs-build\release\spidervpn.exe`（同级自动带 `WebView2Loader.dll`）。

打包成可分发的 ZIP：

```powershell
# 需要先把 sing-box.exe 与许可证放到 vendor\
powershell -NoProfile -File package.ps1 -Version 0.1.4
```

产物：`dist\SpiderVPN-0.1.4-windows-x64.zip` 与 `.sha256`。

### 为什么不用 MSVC

开发机上 VS Build Tools 安装器自身崩溃（`0x138a`），系统也没有 Windows SDK 导入库。GNU 目标 + lld 全程不需要外部编译器，且产物行为一致。

### 已知的构建坑

| 现象 | 原因 | 处理 |
|---|---|---|
| `dlltool.exe: program not found` | rustup 自带 binutils 不全 | 装 WinLibs，`build.ps1` 会自动加 PATH |
| `ld: cannot find ...rcgu.o` | 仓库在非 ASCII 路径下 | 产物放纯英文目录（`CARGO_TARGET_DIR`），从 `C:\` 调用 |
| 启动即 `0xC0000135` | 缺 `WebView2Loader.dll` | 复制 x64 那份到 exe 同级 |
| `0xC000007B` | 拷了 arm64 的加载器 | 只用 x64 |

裸 `cargo build` 需要自己把 WinLibs 的 `bin` 放进 PATH（`dlltool` 是编译期依赖，漏了直接报错，不会静默降级）。

---

## 测试

```powershell
# 单元测试（含内嵌的契约、界面、部署用例）
cargo test --bin spidervpn -- --test-threads=1

# 集成测试
cargo test --tests

# 隔离检查：确认与旧版客户端不共享任何运行时资源
powershell -NoProfile -File Test-Isolation.ps1
```

`tests\` 下另有 Python 端到端脚本（需要 Python 3.10+），按文件名对应各自覆盖的页面与流程。

---

## 目录

```text
src\            程序源码（63 个模块）
web\            界面（HTML/CSS/JS，编译期嵌入 exe）
assets\         服务器侧组件（tc-pair.py，编译期嵌入）
docs\           契约文档、用户速查
tests\          Rust 集成测试 + Python 端到端脚本
fixtures\       固定测试夹具
package-files\  安装/卸载脚本素材
build.ps1       构建
package.ps1     打包
```

---

## 许可

本程序源码采用 [MIT License](LICENSE)。

随包分发的隧道引擎 [sing-box](https://github.com/SagerNet/sing-box) 采用 GPL-3.0，许可证见包内 `sing-box.LICENSE.txt`。二者相互独立：本程序通过命令行调用 sing-box，不链接其代码。

---

## English

SpiderVPN is a Windows desktop VPN client for **your own servers**. It imports sing-box configurations, manages multiple lines with three transport modes (WireGuard UDP / WireGuard-over-VLESS-REALITY / auto), deploys to your Linux VPS over SSH, and enforces a kernel-level direct-connection block (Windows Filtering Platform) for programs you designate — useful when a trading terminal ignores the system proxy.

No account, no telemetry, no vendor lock-in. All data stays in `C:\SpiderVPN\data`.

Download the latest `SpiderVPN-*-windows-x64.zip` from Releases, unzip, run `一键安装.cmd` (one-click install), then launch from the desktop shortcut.
