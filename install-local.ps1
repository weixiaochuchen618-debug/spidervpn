#requires -Version 5.1
<#
.SYNOPSIS
把当前构建装到固定位置，并同步启动入口。重复执行即为升级。

.DESCRIPTION
构建产物在 `C:\tc-rs-build\debug`，那是 cargo 的输出目录，不适合当安装位置：
清理 target 就会把程序一起删掉，而且里面混着中间文件。

安装位置固定为 `C:\SpiderVPN\bin`：
- 数据根由代码里的常量决定（`C:\SpiderVPN\data`），与 exe 放哪无关，所以搬动 exe 不会丢配置
- `WebView2Loader.dll` 必须和 exe 同级，否则启动即 0xC0000135

用法：powershell -NoProfile -File install-local.ps1
#>
[CmdletBinding()]
param([switch]$Release)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = if ($Release) { 'C:\tc-rs-build\release' } else { 'C:\tc-rs-build\debug' }
$exe = Join-Path $src 'spidervpn.exe'
if (-not (Test-Path $exe)) { throw "找不到产物：$exe（先跑 build.ps1）" }

$dest = 'C:\SpiderVPN\bin'
$null = [IO.Directory]::CreateDirectory($dest)

# 正在运行时 exe 会被占用，Copy-Item 会失败——但脚本原来只打印一行大小，
# 看起来像装成功了，实际还是旧文件。所以先探测，再拷后校验，两步都不能省。
$running = @(Get-Process spidervpn -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    throw ("程序正在运行（pid=" + (($running | ForEach-Object { $_.Id }) -join ',') + "），先关掉再升级：" +
        "关窗即可；若已缩到托盘，用托盘菜单的「退出」。")
}

$destExe = Join-Path $dest 'spidervpn.exe'
Copy-Item $exe $destExe -Force

# 只比大小证明不了装的是新文件（同版本体积可能相同）。比哈希才算数。
$srcHash = (Get-FileHash $exe -Algorithm SHA256).Hash
$dstHash = (Get-FileHash $destExe -Algorithm SHA256).Hash
if ($srcHash -ne $dstHash) {
    throw "安装校验失败：目标文件与构建产物不一致（可能是复制被拦或磁盘问题）。源=$srcHash 目标=$dstHash"
}

$loader = Join-Path $src 'WebView2Loader.dll'
if (Test-Path $loader) {
    Copy-Item $loader (Join-Path $dest 'WebView2Loader.dll') -Force
} else {
    Write-Warning '缺 WebView2Loader.dll，启动会报 0xC0000135'
}

# 引擎跟程序放一起（vendor\ 是打包素材；release 目录里也可能有一份）。
# 装好后程序优先用这份，不再依赖 旧版的 assets 目录——旧版一卸载，借来的那份就没了。
$engineSrc = @(
    (Join-Path $src 'sing-box.exe'),
    (Join-Path $here 'vendor\sing-box.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($engineSrc) {
    Copy-Item $engineSrc (Join-Path $dest 'sing-box.exe') -Force
    $lic = Join-Path (Split-Path -Parent $engineSrc) 'sing-box.LICENSE.txt'
    if (Test-Path -LiteralPath $lic) { Copy-Item $lic (Join-Path $dest 'sing-box.LICENSE.txt') -Force }
} else {
    Write-Warning '安装包里没有 sing-box.exe；装完需要在设置页选择引擎程序'
}

# exe 是 console 子系统（CLI 要输出），直接 `start` 会给它开一个随程序存活的
# 控制台窗口——用户误关窗口会连程序一起关掉。经 wscript 以窗口样式 0 拉起：
# 控制台创建即不可见，没有可误关的窗口；CLI 用法（--status 等）不受影响。
# vbs 内容纯 ASCII，无编码问题。
$vbsPath = Join-Path $dest 'start-hidden.vbs'
$vbsBody = ('CreateObject("WScript.Shell").Run "{0}", 0, False' -f $destExe) + "`r`n"
[IO.File]::WriteAllText($vbsPath, $vbsBody, [Text.Encoding]::ASCII)

# 启动脚本用 GBK + CRLF：cmd 按 OEM 代码页解析，UTF-8 会让中文变成乱码。
$cmdBody = @"
@echo off
wscript.exe "%~dp0bin\start-hidden.vbs"
"@
$cmdPath = 'C:\SpiderVPN\启动SpiderVPN.cmd'
[IO.File]::WriteAllText($cmdPath, $cmdBody, [Text.Encoding]::GetEncoding(936))

# TUN 模式要管理员权限（会创建虚拟网卡、改路由表）。给一个提权入口：
# 双击即走 UAC，起来的还是同一个 exe，数据根不变（数据根由常量决定，与启动方式无关）。
# -WindowStyle Hidden：提权后创建的控制台同样不可见。
$adminBody = @"
@echo off
powershell -NoProfile -Command "Start-Process '$dest\spidervpn.exe' -Verb RunAs -WindowStyle Hidden"
"@
$adminCmd = 'C:\SpiderVPN\以管理员身份启动SpiderVPN.cmd'
[IO.File]::WriteAllText($adminCmd, $adminBody, [Text.Encoding]::GetEncoding(936))

# 桌面/开始菜单快捷方式。
# 上一版这里写的是「不做 .lnk：这台机器上建快捷方式要走 COM，被安全策略拦」——那是开发时
# Agent 沙箱的限制（COM 实例化会执行任意代码，被拦），而用户终端里 COM 完全可用。
# 用 .cmd 兜底的代价是双击先闪一下黑框，用户看到的第一眼就是个命令行窗口，不像产品。
# 所以这里优先建 .lnk（目标 wscript.exe + vbs，控制台不可见，图标用 exe 自身的）；
# 只有 COM 确实不可用时才退回 .cmd。
function New-Shortcut {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TargetPath,
        [string]$Arguments = '',
        [string]$WorkingDirectory = '',
        [string]$IconLocation = '',
        [string]$Description = ''
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { $null = [IO.Directory]::CreateDirectory($dir) }
    $shell = New-Object -ComObject WScript.Shell
    try {
        $lnk = $shell.CreateShortcut($Path)
        $lnk.TargetPath = $TargetPath
        if ($Arguments) { $lnk.Arguments = $Arguments }
        if ($WorkingDirectory) { $lnk.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $lnk.IconLocation = $IconLocation }
        if ($Description) { $lnk.Description = $Description }
        $lnk.WindowStyle = 1
        $lnk.Save()
    } finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

$wscriptPath = Join-Path $env:SystemRoot 'System32\wscript.exe'
$desktopDir = [Environment]::GetFolderPath('Desktop')
$desktopLnk = Join-Path $desktopDir '交易通道.lnk'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SpiderVPN'
$startLnk = Join-Path $startMenuDir '交易通道.lnk'
$deskCmd = Join-Path $desktopDir '启动SpiderVPN.cmd'

$shortcutMode = 'lnk'
try {
    foreach ($lnkPath in @($desktopLnk, $startLnk)) {
        New-Shortcut -Path $lnkPath -TargetPath $wscriptPath `
            -Arguments ('"{0}"' -f $vbsPath) `
            -WorkingDirectory $dest `
            -IconLocation ('{0},0' -f $destExe) `
            -Description '交易通道'
    }
} catch {
    $shortcutMode = 'cmd'
    Write-Warning ("快捷方式创建失败，回退到 .cmd 入口：" + $_.Exception.Message)
}

if ($shortcutMode -eq 'lnk') {
    # 清掉上一版留下的 .cmd 兜底入口：桌面上两个图标指向同一个程序，只会让人不知道该点哪个。
    # 先确认内容是自己写的那份再删，避免误删用户自己的脚本。
    if (Test-Path $deskCmd) {
        $existing = Get-Content $deskCmd -Raw -ErrorAction SilentlyContinue
        if ($existing -match 'start-hidden\.vbs') {
            Remove-Item $deskCmd -Force -ErrorAction SilentlyContinue
        }
    }
} else {
    [IO.File]::WriteAllText($deskCmd, "@echo off`r`nwscript.exe `"$dest\start-hidden.vbs`"`r`n", [Text.Encoding]::GetEncoding(936))
}

# 安装日志：只靠控制台输出查不到"什么时候装的、装的是哪一份"。
# 上一轮就出过事——验收跑到一半我又装了一次包，SHA 变了，验收方那条 SHA 核对格直接变红，
# 而没人能从现场看出"中途被换过"。append 不覆盖，历史可追。
$logPath = Join-Path $dest 'install.log'
$logLine = '{0}  bytes={1}  sha256={2}  src={3}' -f `
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Get-Item $destExe).Length, $dstHash, $exe
try {
    Add-Content -Path $logPath -Value $logLine -Encoding utf8
} catch {
    # 日志写不进去不该让安装失败——它只是辅助证据，不是安装的一部分。
    Write-Warning ("安装日志写入失败：" + $_.Exception.Message)
}

[pscustomobject]@{
  Exe = (Join-Path $dest 'spidervpn.exe')
  SizeMB = [math]::Round((Get-Item (Join-Path $dest 'spidervpn.exe')).Length / 1MB, 1)
  Launcher = $cmdPath
  AdminLauncher = $adminCmd
  Desktop = if ($shortcutMode -eq 'lnk') { $desktopLnk } else { $deskCmd }
  StartMenu = if ($shortcutMode -eq 'lnk') { $startLnk } else { '' }
  ShortcutMode = $shortcutMode
}
