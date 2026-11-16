# tests/ — 测试与验收脚本

这里是**验收脚本的集合**，不是构建产物的一部分：不参与编译、不进安装包、不随发布分发。

产品本体是 `src/` 下的 Rust。测试分四层，从「克隆下来就能跑」到「需要一台真服务器」：

| 层 | 需要什么 | 跑什么 | 规模 |
|---|---|---|---|
| **L1 单元测试** | 只要 Rust 工具链 | `cargo test --bin spidervpn` | 1390 项 |
| **L2 集成测试** | 只要 Rust 工具链 | `cargo test --tests` | 10 套（`tests/*.rs`） |
| **L3 界面/流程验收** | 编好的 exe + Python 3.10+ | `tests/*.py --exe <路径>` | 80 余个脚本 |
| **L4 真机验收** | 一台可重置的 Linux VPS | `tests/t11_real_deploy_ui.py --host <地址>` 等 | 4 个脚本 |

**第一次接触这个仓库，只需要跑 L1 + L2。** 两层的失败都指向产品缺陷，不需要任何外部环境。

---

## L1 / L2：单元与集成测试

```powershell
# 单元测试（含 UI 快照、IPC 协议、部署状态机、WFP 规则布局、邀请协议验签）
cargo test --bin spidervpn -- --test-threads=1

# 集成测试：argv / import / lines / mode / split / transport / settings /
#             status-check / single-instance / runtime-engine
cargo test --tests
```

`--test-threads=1` 不是性能选择：多条用例会抢同一个单实例锁和临时注册表键，并行跑会互相干扰。

另有隔离门（确认与旧版客户端不共享任何运行时资源）：

```powershell
powershell -NoProfile -File ..\Test-Isolation.ps1
```

## L3：界面与流程验收（`tests/*.py`）

这些脚本驱动**真实的 exe**：启动进程、通过命名管道发命令、用无头浏览器读页面 DOM，断言「界面上看到的东西」与「宿主真实状态」一致。统一入口是 `--exe`：

```powershell
python tests\r42_revoke_ui.py --exe C:\SpiderVPN\bin\spidervpn.exe
python tests\m1_page_behaviors.py --exe C:\tc-rs-build\release\spidervpn.exe
```

按覆盖范围分组（每组举几个代表，`--help` 可看每个脚本自己的参数）：

| 范围 | 脚本 |
|---|---|
| 页面渲染与行为 | `m1_form_render.py`、`m1_page_behaviors.py`、`m1_render_smoke.py`、`m1_webview_*.py`、`s0_page_fixtures.py`、`audit_ui.py` |
| 首页与状态栏 | `t20_statusbar_matrix.py`、`t20_capture_compare.py`、`t20_probe_external_resize.py` |
| 线路 / 分流 / 连接方式 | `r107_daily_ui.py`、`r108_compat_ui.py`、`r109_tradelist_ui.py`、`r93_transport_ui.py`、`r97_trade_domains_ui.py`、`r89_network_ui.py`、`r61_line_actions_ui.py` |
| 部署中心 | `m5_deploy_ui.py`、`r46_tasks_ui.py`、`r69_draft_ui.py`、`r79_prune_startup.py`、`r98_deploy_steps_ui.py`、`r105_deploy_copy.py` |
| 设备与邀请 | `m5_devices_ui.py`、`r35_invite_ui.py`、`r38_join_ui.py`、`r38_consume.py`、`r42_revoke_ui.py` |
| 记录 / 历史 / 恢复 | `r57_history_detail_ui.py`、`r62_operation_review_ui.py`、`r70_attempt_history_ui.py`、`r73_archive_ui.py`、`r87_history_ui.py`、`r94_recovery_ui.py` |
| 交易保护 | `r50_exit_guard_ui.py`、`r54_p013_guard_ui.py`、`r83_autotrust_ui.py` |
| 设置 / 自启 / 拖放 | `r91_cloud_ui.py`、`r92_key_ui.py`、`r101_qa_drag.py`、`r102_agents_density.py` |
| 性能基线 | `perf_startup.py`、`s0_startup_baseline.py`、`s0_fixtures.py` |

## L4：真机验收（需要 Linux VPS）

这几个脚本会真的 SSH 到一台服务器上部署、签发邀请、撤销设备。**不要指向生产服务器**，用一次性机器：

| 脚本 | 作用 |
|---|---|
| `t11_real_deploy_ui.py --host <地址>` | 完整部署向导 + 接入本机 |
| `r63_deploy_pause_ui.py --host <地址>` | 部署中断与续跑 |
| `r66_device_actions_ui.py --host <地址>` | 设备改名 / 撤销 |
| `..\tools\vps_reset.py` | 把测试机重置回干净状态（**会删服务器上的部署资料**） |

## legacy/：历史轮次脚本

`tests/legacy/` 下是早期迭代轮的对比脚本（`round2-*` / `round3-*`），依赖当时的固定环境和旧版引擎路径，公众环境跑不起来。保留它们是为了留下当时的对照方法，**不保证可运行**。

---

# 写新脚本前先读：四条硬规则

每条都是踩过的坑。

## 1. 调用被测 exe：只认这一种写法

```powershell
$p = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -PassThru `
     -RedirectStandardOutput $out -RedirectStandardError "$out.err"
if (-not $p.WaitForExit(120000)) {
    Write-Host 'TIMEOUT 被测程序 120 秒未退出'
    exit 3          # 挂死必须和「断言失败」分开报，否则永远查不出是卡住还是真挂
}
$code = $p.ExitCode  # 必须在 WaitForExit 之后读，见第 2 条
```

**不要**用下面三种，它们都会被引擎子进程占住，等到引擎退出才返回（实测卡 103 秒，看上去像产品假死）：

- `& $exe --connect`：引擎是它的子进程，继承并占住控制台的 stdout 写端；
- `& $exe --connect | Out-Null` / `| Out-String`：同一个原因，管道要等所有写端关闭才算 EOF；
- `Start-Process -Wait`：PS 的 `-Wait` 等的是**整棵进程树**，引擎不退它就不返回。

## 2. `ExitCode` 要在 `WaitForExit` 之后读

PS 5.1 下 `Start-Process -PassThru` 返回的对象，在进程还没退出时读 `ExitCode` 可能取不到（空值）。先 `WaitForExit(ms)`，再读。

## 3. 取「真直连」出口必须 `curl.exe -s --noproxy '*'`

机器上若有平台代理（`http_proxy` / `HTTPS_PROXY` 环境变量或系统代理），普通请求所谓的「直连」其实走了它，于是会得出「经代理的出口 == 直连出口」的假结论——这一条踩过一次。

```powershell
$direct = & curl.exe -s --noproxy '*' https://api.ipify.org
```

PS 5.1 的 `Invoke-WebRequest` **没有** `-NoProxy` 参数（那是 PS 7 才有的），写了会直接报「找不到参数」，别写。

## 4. 写文件的用例只准用临时根 + 临时键

```powershell
$env:SPIDERVPN_ROOT       = 'C:\tc-rs-build\<临时目录>'      # 数据根
$env:SPIDERVPN_PROXY_KEY  = 'Software\SpiderVPN\tests\<用例名>'  # 系统代理指向临时键，真实键一个字节都不写
```

- 默认数据根 `C:\SpiderVPN\data` **只读**：里面有用户的线路配置。
- 脚本里任何删除路径，若可能指向默认数据根，必须先抛异常退出。历史事故：两次把用户线路配置删了。
- 端口：单测用 `50_000 + (pid%200)*60 + n`，脚本别占这一段；真实引擎用例要独占 17890（被占就 SKIP，不要硬跑）。

## 5. 测试钩子（只在验证时设置，产品默认不设）

| 环境变量 | 作用 |
|---|---|
| `SPIDERVPN_PROXY_KEY` | 系统代理读写指向临时注册表键，真实键一个字节都不动 |
| `SPIDERVPN_ROOT` | 数据根换成临时目录 |
| `SPIDERVPN_FORCE_NONADMIN=1` | 把「本进程是否提权」判定强制为 false。验收机通常是提权会话，靠它才能跑到「TUN 无管理员权限必须拒绝」那条分支 |
| `SPIDERVPN_ENGINE_ARGS` | 覆盖引擎参数（空格分隔）。schema 2 起引擎命令是派生的 `run -c <数据根>\lines\<id>.json`，只有真引擎看得懂；用假引擎（如 `PING.EXE`）验证「连接成功」路径时，靠它把参数换成假引擎认识的形状（例：`-n 300 127.0.0.1`） |

`SPIDERVPN_FORCE_NONADMIN` 只影响一个布尔判定（`probe::elevated`），不做任何特权操作；产品的其他行为不变。除非验证需要，不要设在常驻环境里。

## 6. 两条硬规矩（都是踩过坑才加的）

**夹具：做任何写操作前先断言 `SPIDERVPN_ROOT` 非空。**

漏设或忘设它，命令就会落到真实数据根 `C:\SpiderVPN\data`：轻则把测试线路写进用户的线路表并切走选中项，
重则删掉用户配置。夹具开头加一句守卫，缺了就直接抛错、别继续跑：

```powershell
if (-not $env:SPIDERVPN_ROOT) { throw '没有设置 SPIDERVPN_ROOT：拒绝在默认根上做写操作' }
```

（真实事故：探测脚本把 `--import --line-name leak` 写在了设置 root 之前，默认根被写入 `leak` 并被切成选中。）

**探测脚本必须给全参数，否则会留下占着 exe 的窗口进程。**

命令带了参数但少了值时，旧版本不会报错，而是**直接进入图形界面**：那个窗口没有任何提示、
会一直等着人关窗，并且**占着 `spidervpn.exe`** —— 后续升级 `Copy-Item` 全部失败，
看起来像"装成功了但版本没变"。

现在这条已经在代码里堵住：带值的命令（`--use` / `--remove-line` / `--set-line` / `--import` /
`--split-add-process` / `--split-add-domain` / `--split-remove-process` / `--split-remove-domain` 等）
少了值会打印「需要参数：…」+ 用法示例并 **exit 12**；未知参数报「未知参数：…」；无值命令多给值报「多余参数：…」。
用例在 `tests/argv-e2e.rs`（每条都断言"2 秒内退出"，证明没进 GUI）。

所以写探测/冒烟脚本时：**每个 flag 都补齐它要的值**；跑完确认没有残留 `spidervpn` 再装。

**安装：升级前确认没有 `spidervpn` 在跑，装完校验哈希。**

有进程占用时 `Copy-Item` 会失败，而安装脚本通常只在 `SizeMB` 那行打印"成功"——
结果是**装上去的还是旧 exe，看起来却正常**。所以两条都要有：

1. 复制前 `Get-Process spidervpn`，有就拒绝并提示先退出（含托盘里的常驻）；
2. 复制后比较目标与源的 `Length` 与 SHA256，不一致就报错退出，别只打印大小。

## 7. 贴着地雷的一个能力：`process_name` 在**系统代理模式**下也生效

**实测 sing-box 1.14.2（Windows）：**

```
proxy 模式（不带 TUN），经本程序代理取出口：
  无规则             → 198.51.100.7（节点）
  process_name:curl.exe → 203.0.113.77（直连基线）
```

也就是说 sing-box 会按「源地址 + 端口」反查发起进程，`process_name` 在 mixed 入站上同样命中——
**不是只有 TUN 模式才支持进程分流**。

**为什么记在这里**：这个能力依赖引擎内部的反查行为，不是我们的代码保证的。
**引擎升级后必须重测这一条**——一旦新版本不再反查，用户会**静默失去进程分流**（规则还在配置里、就是不生效）。
静态那半由 `split_rules_are_generated_in_proxy_mode_too` 钉住（proxy 模式也必须把规则写进引擎配置），
行为那半只能靠上面这套 IP 对照重跑，没有自动化替代。

复跑方法：临时根 + 临时代理键 → `--set-line`（proxy 模式）→ `--split-add-process curl.exe`
→ `--import`（**不带** `--tun`）→ `--connect` → `curl --proxy 127.0.0.1:<端口> https://ifconfig.me/ip`
→ 期望出口等于 `curl --noproxy '*'` 的直连基线。

---

本文是 `.md` 而不是 `.ps1`：隔离门会扫 `*.ps1` 里的旧版路径字面量，注释文件没必要引入这个风险。
