#requires -Version 5.1
<#
.SYNOPSIS
SpiderVPN 卸载：删程序与入口，数据默认保留。

.DESCRIPTION
顺序是「先确认没在跑 → Rust 提权安全预检/WFP 回读 → 删本安装入口 → 删固定程序清单 → 问数据」。
任何预检失败都必须保留 EXE，供后续修复与解除持久阻断。
数据目录（`C:\SpiderVPN\data`）里有线路、配置、操作记录，默认**一律保留**：
要删必须自己输入 DELETE，避免手滑把用户的线路删掉（这个项目为此出过事故）。

参数：
  -TargetDir <路径>  安装位置（默认 C:\SpiderVPN）
  -KeepData          不问，直接保留数据
  -KeepGuard         保留交易保护（WFP 阻止规则 + 核验记录），默认是解除
  -NoPrompt          不问；数据按「保留」处理（除非同时给 -DeleteData）
  -DeleteData        连数据一起删（危险，等价于手输 DELETE）

退出码：0 完成；1 拒绝执行（权限不够 / 程序在跑 / 代理没还原 / WFP 解除未核实）。
#>
[CmdletBinding()]
param(
    [string]$TargetDir = 'C:\SpiderVPN',
    [switch]$KeepData,
    [switch]$KeepGuard,
    [switch]$NoPrompt,
    [switch]$DeleteData
)
$ErrorActionPreference = 'Stop'

function Say([string]$m) { Write-Host "  $m" }
function Bad([string]$m) { Write-Host "  $m" -ForegroundColor Red; exit 1 }

if ($TargetDir -notmatch '^[A-Za-z]:\\') { Bad "安装目录必须是绝对路径，收到：$TargetDir" }
if ($TargetDir -match '^[A-Za-z]:\\?$') { Bad "安装目录不能是盘符根：$TargetDir" }
$bin = Join-Path $TargetDir 'bin'
$data = 'C:\SpiderVPN\data'

Say 'SpiderVPN 卸载'
Say "  安装位置：$TargetDir"

$running = @(Get-Process spidervpn -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    $pids = ($running | ForEach-Object { $_.Id }) -join ','
    Bad "程序正在运行（pid=$pids）。请先退出：关窗即可；缩在托盘里的用托盘菜单「退出」。"
}

# 代理未还原、UAC 不足或 WFP 清除/核验失败由 Rust fail-closed 拒绝。
# 不再接受脚本输入 FORCE 绕过；旧版 guard exit 3 也绝不能继续删除程序。
# 权限信任边界全部由当前安装的 Rust EXE 校验；本脚本只负责后续清理。
$exe = Join-Path $bin 'spidervpn.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Bad "找不到已安装的 SpiderVPN 程序：$exe。无法独立确认持久 WFP 规则已解除，不进行任何卸载清理。"
}
Say '正在执行 Rust 安全卸载预检（管理员权限、系统代理还原与 WFP 现场核验）…'
if ($KeepGuard) {
    & $exe --uninstall-preflight $TargetDir --keep-guard
} else {
    & $exe --uninstall-preflight $TargetDir
}
$preflightCode = $LASTEXITCODE
if ($preflightCode -ne 0) {
    Bad "安全卸载预检失败（exit=$preflightCode）：未删除程序或入口。请先从客户端断开连接，确认系统代理已还原；必要时以管理员身份运行卸载器。"
}
if ($KeepGuard) {
    Say '已明确选择 -KeepGuard：持久 WFP 阻断保留，卸载后交易程序可能继续被阻断！'
} else {
    Say 'Rust 已删除本程序 WFP 对象并核验 Provider/SubLayer 不存在。'
}

# 2) 入口（桌面 / 开始菜单 / 安装目录里的三个 .cmd）
#
# 只删**确实指向这个安装位置**的入口：入口是全局的（一台机器只有一个桌面），
# 而卸载可能针对的是另一个目录。实测踩过：卸载临时目录时把默认安装的桌面图标删了。
function PointsHere([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    # Rust 校验整份安装器生成的 .cmd 模板与目标路径，拒绝模糊子串匹配。
    # exit 0 = 属于本安装；3 = 不是；其余失败必须停止清理（不误删）。
    & $exe --uninstall-owns-shortcut $path $TargetDir | Out-Null
    $ownedCode = $LASTEXITCODE
    if ($ownedCode -eq 0) { return $true }
    if ($ownedCode -eq 3) { return $false }
    Bad "无法确认快捷入口的归属：$path（Rust exit=$ownedCode）。停止卸载，避免误删其他安装。"
}
$desk = [Environment]::GetFolderPath('Desktop')
if ($desk) {
    $p = Join-Path $desk '启动SpiderVPN.cmd'
    if (PointsHere $p) { Remove-Item -LiteralPath $p -Force; Say "  已删：$p" }
}
$sm = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SpiderVPN'
if (Test-Path -LiteralPath $sm) {
    $owned = @(Get-ChildItem -LiteralPath $sm -File -ErrorAction SilentlyContinue | Where-Object { PointsHere $_.FullName })
    foreach ($item in $owned) {
        Remove-Item -LiteralPath $item.FullName -Force
        Say "  已删：$($item.FullName)"
    }
    # 只在目录真正为空时删目录；保留其他安装/用户创建的快捷入口。
    if (-not (Get-ChildItem -LiteralPath $sm -Force -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $sm -Force
    }
}
# 保留卸载脚本到最后；删除中途出错时仍有可重复执行的恢复入口。
foreach ($n in @('启动SpiderVPN.cmd', '以管理员身份启动SpiderVPN.cmd', '卸载SpiderVPN.cmd', '用户速查.md')) {
    $p = Join-Path $TargetDir $n
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

# 3) 只清理本安装的固定 bin 文件清单，不递归删除未知文件或用户数据
# 先移除引擎/DLL/许可证，最后才移除主 EXE；
# 任一 Remove-Item 失败都会立即停止，保留尚未删的 EXE 便于安全重试。
foreach ($n in @('sing-box.exe', 'WebView2Loader.dll', 'sing-box.LICENSE.txt', 'spidervpn.exe')) {
    $p = Join-Path $bin $n
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; Say "  已删：$p" }
}
if (Test-Path -LiteralPath $bin) {
    $left = @(Get-ChildItem -LiteralPath $bin -Force -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) { Remove-Item -LiteralPath $bin -Force }
}

# 删除完主程序之后才移除卸载脚本本身：中途失败保留救援入口。
$uninstaller = Join-Path $TargetDir 'uninstall.ps1'
if (Test-Path -LiteralPath $uninstaller) {
    Remove-Item -LiteralPath $uninstaller -Force
}

# 4) 数据：默认保留；要删必须明确表示
$dataExists = Test-Path -LiteralPath $data
$drop = $false
if ($dataExists) {
    if ($DeleteData) { $drop = $true }
    elseif ($KeepData -or $NoPrompt) { $drop = $false }
    else {
        Write-Host "  数据目录：$data" -ForegroundColor Yellow
        Write-Host '  里面有线路配置、分流规则、操作记录。删除后无法恢复。' -ForegroundColor Yellow
        $ans = Read-Host '  要一起删除数据目录吗？输入 DELETE 删除（直接回车＝保留）'
        if ($ans -eq 'DELETE') { $drop = $true }
    }
}
if ($dataExists -and $drop) {
    Remove-Item -LiteralPath $data -Recurse -Force
    Say "  已删数据：$data"
} elseif ($dataExists) {
    Say "  数据保留：$data（下次装回来还能接着用）"
}

Say ''
Say '已卸载。'
if (-not $dataExists) { Say '  （本来就没有数据目录）' }
elseif (-not $drop) { Say '  重装后线路与记录都还在。' }
exit 0
