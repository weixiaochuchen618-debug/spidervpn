#requires -Version 5.1
<#
.SYNOPSIS
SpiderVPN 一键安装：把程序放到固定位置，并建好启动与卸载入口。

.DESCRIPTION
数据根是程序里的**常量** `C:\SpiderVPN\data`，与安装目录无关——
所以升级只要覆盖 bin 下的文件，配置、线路、记录都不会丢。

默认装到 `C:\SpiderVPN`。安装阶段要求管理员权限，权限策略由 Rust
`--install-seal` 原生命令设置并读回；`bin`/启动脚本只允许管理员写，
`data` 保留普通用户配置写入。TUN 模式仍需管理员入口启动。
参数是给测试与高级用法留的：
  -TargetDir <路径>   仅开发/调试版支持临时测试目录；正式 Release 固定 C:\SpiderVPN
  -NoDesktop          不建桌面入口（测试用）
  -NoStartMenu        不建开始菜单入口（测试用）

退出码：0 成功；1 失败（原因打在屏幕上）。
#>
[CmdletBinding()]
param(
    [string]$SourceDir = '',
    [string]$TargetDir = 'C:\SpiderVPN',
    [switch]$NoDesktop,
    [switch]$NoStartMenu
)
$ErrorActionPreference = 'Stop'

function Say([string]$m) { Write-Host "  $m" }
function Bad([string]$m) { Write-Host "  $m" -ForegroundColor Red; exit 1 }

if (-not $SourceDir) { $SourceDir = Split-Path -Parent $PSScriptRoot }
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path
$srcExe = Join-Path $SourceDir 'spidervpn.exe'
$srcDll = Join-Path $SourceDir 'WebView2Loader.dll'
foreach ($f in @($srcExe, $srcDll)) {
    if (-not (Test-Path -LiteralPath $f)) { Bad "安装包不完整：缺 $f" }
}

# 安装位置必须是绝对路径、且不能是盘符根（防止把整个盘当安装目录）
if ($TargetDir -notmatch '^[A-Za-z]:\\') { Bad "安装目录必须是绝对路径（例如 C:\SpiderVPN），收到：$TargetDir" }
if ($TargetDir -match '^[A-Za-z]:\\?$') { Bad "安装目录不能是盘符根：$TargetDir" }

Say 'SpiderVPN 安装'
Say "  安装包：$SourceDir"
Say "  目标  ：$TargetDir"

# 正在运行时 exe 会被占用，复制会失败——先说清楚，别让用户对着「拒绝访问」猜
$running = @(Get-Process spidervpn -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    $pids = ($running | ForEach-Object { $_.Id }) -join ','
    Bad "程序正在运行（pid=$pids）。请先退出：关窗即可；缩在托盘里的用托盘菜单「退出」。"
}

# 包内哈希：防「复制被拦/被杀软改写」，也防拿到半截文件
$expectedFile = Join-Path $PSScriptRoot 'expected.sha256'
$expected = @{}
if (Test-Path -LiteralPath $expectedFile) {
    foreach ($line in (Get-Content -LiteralPath $expectedFile -Encoding ASCII)) {
        # 格式：`<HASH>  <文件名>`，一行一个。只有一串哈希（老包）就当成 exe 的。
        $t = @(($line -split '\s+') | Where-Object { $_ })
        if ($t.Count -ge 2) {
            $expected[$t[1].ToLowerInvariant()] = $t[0].ToUpperInvariant()
        } elseif ($t.Count -eq 1) {
            $expected['spidervpn.exe'] = $t[0].ToUpperInvariant()
        }
    }
}
function Verify-Packed([string]$path, [string]$name) {
    if (-not $expected.ContainsKey($name.ToLowerInvariant())) { return }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expected[$name.ToLowerInvariant()]) {
        Bad "安装包里的 $name 与清单不一致（可能复制不完整或被改动）。`n    清单：$($expected[$name.ToLowerInvariant()])`n    实际：$actual"
    }
}
Verify-Packed $srcExe 'spidervpn.exe'
$srcEngine = Join-Path $SourceDir 'sing-box.exe'
if (Test-Path -LiteralPath $srcEngine) { Verify-Packed $srcEngine 'sing-box.exe' }

# SEC-03：先在 Rust/Win32 里原子创建或收紧程序根与 bin 的 ACL，
# 再复制文件。普通用户未提权直接拒绝，不能装出“成功但 bin 可改”的版本。
# 此脚本不决定谁可写、也不直接使用 icacls 改安全权限。
& $srcExe --install-seal $TargetDir
if ($LASTEXITCODE -ne 0) {
    Bad 'Rust 安装权限预检失败：未复制任何新程序文件。请以管理员身份运行可信安装包。'
}
$bin = Join-Path $TargetDir 'bin'
$dstExe = Join-Path $bin 'spidervpn.exe'
try {
    Copy-Item -LiteralPath $srcExe -Destination $dstExe -Force
    Copy-Item -LiteralPath $srcDll -Destination (Join-Path $bin 'WebView2Loader.dll') -Force
    # 引擎跟程序放一起：**不再指向安装时那台机器上的路径**（旧版客户端的 assets 目录）。
    # 没有这份也能装，只是第一次连接前要在设置页选一次引擎。
    if (Test-Path -LiteralPath $srcEngine) {
        Copy-Item -LiteralPath $srcEngine -Destination (Join-Path $bin 'sing-box.exe') -Force
    }
    $srcLicense = Join-Path $SourceDir 'sing-box.LICENSE.txt'
    if (Test-Path -LiteralPath $srcLicense) {
        Copy-Item -LiteralPath $srcLicense -Destination (Join-Path $bin 'sing-box.LICENSE.txt') -Force
    }
} catch {
    Bad "复制失败：$($_.Exception.Message)`n    如果提示被占用，请先退出正在运行的 SpiderVPN。"
}

# 装完必须自己验一遍：只比大小证明不了装的是新文件
$dstHash = (Get-FileHash -LiteralPath $dstExe -Algorithm SHA256).Hash.ToUpperInvariant()
if ($dstHash -ne (Get-FileHash -LiteralPath $srcExe -Algorithm SHA256).Hash.ToUpperInvariant()) {
    Bad "安装校验失败：目标程序与安装包不一致。"
}
if ((Test-Path -LiteralPath $srcEngine) -and `
    ((Get-FileHash -LiteralPath (Join-Path $bin 'sing-box.exe') -Algorithm SHA256).Hash -ne
     (Get-FileHash -LiteralPath $srcEngine -Algorithm SHA256).Hash)) {
    Bad "安装校验失败：引擎与安装包不一致。"
}

# 启动脚本用 GBK + CRLF：cmd 按 OEM 代码页解析，UTF-8 会让中文变乱码
$gbk = [Text.Encoding]::GetEncoding(936)
$startBody = "@echo off`r`nchcp 65001 >nul`r`ncd /d `"%~dp0bin`"`r`nstart `"`" `"spidervpn.exe`"`r`n"
$adminBody = "@echo off`r`npowershell -NoProfile -Command `"Start-Process '$dstExe' -Verb RunAs`"`r`n"
$uninstBody = "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"%~dp0uninstall.ps1`"`r`npause`r`n"

$startCmd = Join-Path $TargetDir '启动SpiderVPN.cmd'
$adminCmd = Join-Path $TargetDir '以管理员身份启动SpiderVPN.cmd'
$uninstCmd = Join-Path $TargetDir '卸载SpiderVPN.cmd'
[IO.File]::WriteAllText($startCmd, $startBody, $gbk)
[IO.File]::WriteAllText($adminCmd, $adminBody, $gbk)
[IO.File]::WriteAllText($uninstCmd, $uninstBody, $gbk)

# 卸载器跟着装进去：以后不需要安装包也能卸
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'uninstall.ps1') -Destination (Join-Path $TargetDir 'uninstall.ps1') -Force
$guide = Join-Path $SourceDir '用户速查.md'
if (Test-Path -LiteralPath $guide) { Copy-Item -LiteralPath $guide -Destination (Join-Path $TargetDir '用户速查.md') -Force }

# 快捷入口：桌面 + 开始菜单。用 .cmd 而不是 .lnk——.lnk 要走 COM，
# 在受限机器上会被拦；.cmd 在任何机器上都能双击。
#
# 桌面/开始菜单那份**必须写绝对路径**：`%~dp0` 在桌面会解析成桌面目录，
# 照抄安装目录里那份（相对 `%~dp0bin`）会得到一个点了没反应的图标。
$launcherAbs = "@echo off`r`nstart `"`" `"$dstExe`"`r`n"
$made = New-Object 'Collections.Generic.List[string]'
if (-not $NoDesktop) {
    $desk = [Environment]::GetFolderPath('Desktop')
    if ($desk) {
        $p = Join-Path $desk '启动SpiderVPN.cmd'
        [IO.File]::WriteAllText($p, $launcherAbs, $gbk)
        $made.Add($p)
    }
}
if (-not $NoStartMenu) {
    $sm = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SpiderVPN'
    $null = New-Item -ItemType Directory -Path $sm -Force
    $p1 = Join-Path $sm '启动SpiderVPN.cmd'
    $p2 = Join-Path $sm '卸载SpiderVPN.cmd'
    [IO.File]::WriteAllText($p1, $launcherAbs, $gbk)
    [IO.File]::WriteAllText($p2, "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"$TargetDir\uninstall.ps1`"`r`npause`r`n", $gbk)
    $made.Add($p1)
    $made.Add($p2)
}

# 复制后的完整程序文件、DLL、启动脚本与卸载入口二次读回安全 ACL。
# 不允许“前置 ACL 成功，后续文件仍继承宽权限”便宣称安全安装。
& $dstExe --install-seal $TargetDir
if ($LASTEXITCODE -ne 0) {
    Bad 'Rust 安装权限最终验收失败：程序目录未确认安全，不能宣称安装成功。'
}

# WebView2 运行时：缺了界面起不来。只提示，不拦（Win10/11 一般自带）
$wv2 = @(
    'C:\Program Files (x86)\Microsoft\EdgeWebView\Application',
    'C:\Program Files\Microsoft\EdgeWebView\Application'
) | Where-Object { Test-Path -LiteralPath $_ }
if (-not $wv2) {
    Write-Host '  注意：没有检测到 WebView2 运行时。界面可能无法启动，'
    Write-Host '        可到 Microsoft 官网装「WebView2 Runtime」（Win10/11 通常已自带）。' -ForegroundColor Yellow
}

$size = (Get-Item -LiteralPath $dstExe).Length
Say ''
Say '已安装。'
Say ("  程序：{0}（{1:N0} B）" -f $dstExe, $size)
Say "  SHA256：$dstHash"
Say "  数据：C:\SpiderVPN\data（升级不会动它）"
Say '  权限：程序及引擎由 Rust 验证为受保护；数据目录保留普通用户写入'
Say "  启动：双击桌面「启动SpiderVPN.cmd」"
Say '        TUN 模式要接管全部流量（含不读系统代理的交易终端），请用「以管理员身份启动SpiderVPN.cmd」'
Say "  卸载：$uninstCmd"
if ($made.Count -gt 0) { Say "  入口：$($made -join '；')" }
exit 0
