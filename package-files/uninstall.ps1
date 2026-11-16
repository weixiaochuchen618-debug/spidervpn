#requires -Version 5.1
<#
.SYNOPSIS
SpiderVPN 卸载：删程序与入口，数据默认保留。

.DESCRIPTION
顺序是「先确认没在跑 → 删入口 → 删程序 → 问数据」。
数据目录（`C:\SpiderVPN\data`）里有线路、配置、操作记录，默认**一律保留**：
要删必须自己输入 DELETE，避免手滑把用户的线路删掉（这个项目为此出过事故）。

参数：
  -TargetDir <路径>  安装位置（默认 C:\SpiderVPN）
  -KeepData          不问，直接保留数据
  -KeepGuard         保留交易保护（WFP 阻止规则 + 核验记录），默认是解除
  -NoPrompt          不问；数据按「保留」处理（除非同时给 -DeleteData）
  -DeleteData        连数据一起删（危险，等价于手输 DELETE）

退出码：0 完成；1 拒绝执行（程序在跑 / 代理没还原 / 交易保护没解除成功）。
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

# 代理没还原就卸载 = 系统代理还指着已经不存在的引擎，网络会断。
# 这件事必须挡在前面：程序下次启动本来会自愈，卸载之后就没人修了。
$journal = Join-Path $data 'proxy-journal.json'
if (Test-Path -LiteralPath $journal) {
    Write-Host '  检测到上次连接没有还原系统代理（数据目录里有 proxy-journal.json）。' -ForegroundColor Yellow
    Write-Host '  请先启动一次程序点「断开」，或手动把系统代理改回去，然后再卸载。' -ForegroundColor Yellow
    if ($NoPrompt -and -not $DeleteData) { Bad '为安全起见，先不卸载（避免把网络留在一个坏状态）。' }
    if ($NoPrompt) { } else {
        $ans = Read-Host '  确实要继续卸载吗？输入 FORCE 继续'
        if ($ans -ne 'FORCE') { Bad '已取消（系统代理仍未还原）。' }
    }
}

# 1) 交易保护（WFP 阻止规则）：默认解除，而且必须赶在删 exe 之前。
#
# 为什么顺序不能反：那些规则是**持久**的（FWPM_FILTER_FLAG_PERSISTENT），exe 一删就再没有
# 谁能删它们——名单里的交易程序会被永久挡住直连，而用户已经找不到这个程序了。
# 解除失败时**不继续删程序**：把「还能修」的状态留给人，比删完留一堆没人管的规则强。
$exe = Join-Path $bin 'spidervpn.exe'
if ($KeepGuard) {
    Say '交易保护：按 -KeepGuard 保留（阻止规则与核验记录都不动）'
    Say '  以后要解除：装回来后用「维护 → 解除交易保护」，或先重新安装再卸载。'
} elseif (-not (Test-Path -LiteralPath $exe)) {
    Say '交易保护：没有找到程序文件，跳过解除（可能已经删过）'
} else {
    Say '正在解除交易保护（可能弹出一次管理员确认）…'
    # 程序把控制台切到 UTF-8；不显式对齐解码，失败时打印出来的原因会是乱码。
    $oldEnc = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false) } catch { }
    $guardOut = & $exe --guard-remove 2>&1 | Out-String
    $guardCode = $LASTEXITCODE
    try { [Console]::OutputEncoding = $oldEnc } catch { }
    if ($guardCode -eq 0) {
        Say '交易保护已解除（阻止规则已删除）'
        # 核验记录键：解除成功后里面只剩一个「已解除」标记，不含任何证据。
        # 删它需要管理员（键在 HKLM，普通用户只读）——删不掉不算失败，如实说出来。
        $guardKey = 'HKLM\SOFTWARE\SpiderVPN\Guard'
        & reg.exe delete $guardKey /f *> $null
        if ($LASTEXITCODE -eq 0) {
            Say "  已清理核验记录：$guardKey"
        } else {
            Say "  核验记录键保留（需要管理员才能删）：$guardKey"
            Say '  它不含证据，只有一个「已解除」标记；不影响下次安装。'
        }
    } elseif ($guardCode -eq 3) {
        # 没有 config.json：判定层拒绝猜名单（这是设计，不是故障）。
        Write-Host '  找不到配置文件，无法确定要解除哪些保护规则。' -ForegroundColor Yellow
        Write-Host '  如果你曾经连接过，请先启动一次程序再卸载；或手动删除 WFP 规则。' -ForegroundColor Yellow
    } else {
        Write-Host $guardOut
        Bad @"
解除交易保护失败（exit=$guardCode），没有删除任何程序文件。
  处理办法：
    1. 关掉名单里的交易软件后重试；
    2. 或先启动程序，在「维护」页点「解除交易保护」；
    3. 确实要保留保护规则直接卸载：加 -KeepGuard。
"@
    }
}

# 2) 入口（桌面 / 开始菜单 / 安装目录里的三个 .cmd）
#
# 只删**确实指向这个安装位置**的入口：入口是全局的（一台机器只有一个桌面），
# 而卸载可能针对的是另一个目录。实测踩过：卸载临时目录时把默认安装的桌面图标删了。
function PointsHere([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    # 入口是 GBK 写的（cmd 按 OEM 代码页解析），这里也按 936 读，别让中文路径读成乱码
    $t = [IO.File]::ReadAllText($path, [Text.Encoding]::GetEncoding(936))
    return ($null -ne $t) -and $t.Contains($TargetDir)
}
$desk = [Environment]::GetFolderPath('Desktop')
if ($desk) {
    $p = Join-Path $desk '启动SpiderVPN.cmd'
    if (PointsHere $p) { Remove-Item -LiteralPath $p -Force; Say "  已删：$p" }
}
$sm = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SpiderVPN'
if (Test-Path -LiteralPath $sm) {
    $owned = @(Get-ChildItem -LiteralPath $sm -File -ErrorAction SilentlyContinue | Where-Object { PointsHere $_.FullName })
    if ($owned.Count -gt 0) { Remove-Item -LiteralPath $sm -Recurse -Force; Say "  已删：$sm" }
}
foreach ($n in @('启动SpiderVPN.cmd', '以管理员身份启动SpiderVPN.cmd', '卸载SpiderVPN.cmd', 'uninstall.ps1', '用户速查.md')) {
    $p = Join-Path $TargetDir $n
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

# 3) 程序文件（只删 bin 下这两个，不递归删整个目录）
foreach ($n in @('spidervpn.exe', 'WebView2Loader.dll')) {
    $p = Join-Path $bin $n
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; Say "  已删：$p" }
}
if (Test-Path -LiteralPath $bin) {
    $left = @(Get-ChildItem -LiteralPath $bin -Force -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) { Remove-Item -LiteralPath $bin -Force }
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
