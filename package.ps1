#requires -Version 5.1
<#
.SYNOPSIS
把 release 产物打成可分发的 zip（含依赖 DLL、安装说明、用户速查），并生成 SHA256。

.DESCRIPTION
只打包真正要分发的东西：
- spidervpn.exe（release）
- WebView2Loader.dll（必须与 exe 同级，否则启动即 0xC0000135）
- 一键安装.cmd / 一键卸载.cmd / 直接运行（免安装）.cmd（素材在 package-files\）
- install\install.ps1 / uninstall.ps1 / expected.sha256（安装时核对哈希）
- INSTALL.txt（安装、卸载、数据位置、常用命令、排错）
- 用户速查（一页纸）

数据目录固定在 C:\SpiderVPN\data（代码里的常量），与 exe 放哪无关——
所以这个包解压到任意目录都能用，不会污染或迁移用户数据。

用法：powershell -NoProfile -File package.ps1 [-Version 0.1.0]
#>
[CmdletBinding()]
param([string]$Version = '0.1.0')

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = 'C:\tc-rs-build\release'
# 输出到仓库自己的 dist\（与源码同级，便于 .gitignore 一把排除）。
$dist = Join-Path $here 'dist'

$exe = Join-Path $src 'spidervpn.exe'
$dll = Join-Path $src 'WebView2Loader.dll'
foreach ($f in @($exe, $dll)) { if (-not (Test-Path $f)) { throw "缺产物：$f（先 cargo build --release）" } }

$name = "SpiderVPN-$Version-windows-x64"
$stage = Join-Path $dist $name
$zip = Join-Path $dist "$name.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
$null = New-Item -ItemType Directory -Path $stage -Force
$null = New-Item -ItemType Directory -Path $dist -Force

Copy-Item $exe (Join-Path $stage 'spidervpn.exe')
Copy-Item $dll (Join-Path $stage 'WebView2Loader.dll')

# 引擎随包分发，装到 bin\ 与程序同级：不带引擎的包落到一台全新机器上，
# 用户连第一次连接都做不了。
# 许可：sing-box 是 GPL-3.0，声明必须跟着二进制一起走。
$vendorEngine = Join-Path $here 'vendor\sing-box.exe'
$vendorLicense = Join-Path $here 'vendor\sing-box.LICENSE.txt'
if (-not (Test-Path $vendorEngine)) {
    throw "缺引擎：$vendorEngine（把 sing-box.exe 放到 vendor\ 下再打包）"
}
Copy-Item $vendorEngine (Join-Path $stage 'sing-box.exe')
if (Test-Path $vendorLicense) { Copy-Item $vendorLicense (Join-Path $stage 'sing-box.LICENSE.txt') }

# 一键安装 / 一键卸载 / 免安装直接运行：交给别人的包必须双击就能用，
# 不能要求对方「打开终端敲命令」。脚本源在 package-files\（都是 UTF-8 BOM / GBK+CRLF 的成品）。
$files = Join-Path $here 'package-files'
foreach ($f in @('install-once.cmd', 'uninstall-once.cmd', 'run-portable.cmd', 'install.ps1', 'uninstall.ps1')) {
    if (-not (Test-Path (Join-Path $files $f))) { throw "缺打包素材：$f" }
}
$stageInstall = Join-Path $stage 'install'
$null = New-Item -ItemType Directory -Path $stageInstall -Force
Copy-Item (Join-Path $files 'install-once.cmd')   (Join-Path $stage '一键安装.cmd')
Copy-Item (Join-Path $files 'uninstall-once.cmd') (Join-Path $stage '一键卸载.cmd')
Copy-Item (Join-Path $files 'run-portable.cmd')   (Join-Path $stage '直接运行（免安装）.cmd')
Copy-Item (Join-Path $files 'install.ps1')        (Join-Path $stageInstall 'install.ps1')
Copy-Item (Join-Path $files 'uninstall.ps1')      (Join-Path $stageInstall 'uninstall.ps1')

# 包内哈希清单：安装时核对，防「复制不完整 / 被杀软改写」
$exeHashInPack = (Get-FileHash (Join-Path $stage 'spidervpn.exe') -Algorithm SHA256).Hash
$engineHashInPack = (Get-FileHash (Join-Path $stage 'sing-box.exe') -Algorithm SHA256).Hash
Set-Content -Path (Join-Path $stageInstall 'expected.sha256') -Encoding ASCII -Value @(
    ("{0}  spidervpn.exe" -f $exeHashInPack),
    ("{0}  sing-box.exe" -f $engineHashInPack)
)

$install = @'
SpiderVPN 0.1.4（Windows x64）

一、怎么装（推荐，一次就好）
  1. 把整个文件夹解压到任意位置（桌面、D 盘都行）。
  2. 双击「一键安装.cmd」。
     它会：复制程序到 C:\SpiderVPN\bin、在桌面和开始菜单建启动入口、
     校验文件哈希。普通权限即可，不需要管理员。
     如果 Windows 弹出「已保护你的电脑」（程序没有代码签名，第一次运行常见），
     点「更多信息」→「仍要运行」即可；杀软误报同理，加信任即可。
  3. 双击桌面「启动SpiderVPN.cmd」→ 添加线路 → 点连接。
     要接管不读系统代理的程序（TUN 模式）：用「以管理员身份启动SpiderVPN.cmd」。
     引擎（sing-box）随包装在 bin\sing-box.exe，装完就能连，不用先去别处找程序。

二、不想装也行（免安装）
  双击「直接运行（免安装）.cmd」即可。
  注意：数据仍固定在 C:\SpiderVPN\data，与程序放在哪里无关——
  「免安装」只是不建入口，配置位置不变，换目录也不会丢配置。

三、卸载
  双击安装目录里的「卸载SpiderVPN.cmd」，或本文件夹里的「一键卸载.cmd」。
  数据目录默认保留；要一起删必须自己输入 DELETE。
  若上次连接没还原系统代理，卸载器会先拦住你——先打开程序点「断开」。

四、数据放哪
  C:\SpiderVPN\data
    线路文件 data\lines\、配置 config.json、操作记录 data\logs\operations.jsonl

  程序目录 C:\SpiderVPN\bin
    spidervpn.exe、WebView2Loader.dll
    sing-box.exe（隧道引擎；GPL-3.0，声明见同目录 sing-box.LICENSE.txt）

五、常用命令（在 C:\SpiderVPN\bin 打开终端）
  spidervpn.exe --status      查看状态
  spidervpn.exe --lines       列出线路（含连接方式）
  spidervpn.exe --diagnose    诊断当前线路
  spidervpn.exe --history     操作记录（连接/断开/线路改动，最新在前）
  spidervpn.exe --help        全部用法（不带参数＝打开界面）

六、第一次上手
  · 有现成服务器：线路页「添加线路」→ 导入 sing-box 配置，或填 socks 端点。
  · 没有服务器：线路页「添加线路 → 我有邀请码」；或在一台 Linux VPS 上
    执行 spidervpn.exe --server-setup root@你的服务器地址，一路部署并接入本机。
  · 需要防误连：应用页勾选交易终端，连接后会阻断这些程序的直连（WFP 过滤）。

七、排错
  启动报 0xC0000135  → WebView2Loader.dll 没和 exe 放在一起（一键安装会自动放好）。
  界面打不开         → 装 WebView2 运行时（Win10/11 一般自带）。
  「端口已被占用」    → 换一个线路端口重新导入，或先关掉占用者。
  标准连接自检不通    → 照结论后的提示执行 --set-transport tcp。
  交易保护装不上      → 需要管理员权限；未提权时连接照常，只是不阻断直连。
'@
Set-Content -Path (Join-Path $stage 'INSTALL.txt') -Value $install -Encoding UTF8

$guide = Join-Path $here 'docs\用户速查.md'
if (Test-Path $guide) { Copy-Item $guide (Join-Path $stage '用户速查.md') }

# 自己写条目而不是 Compress-Archive / ZipFile.CreateFromDirectory：
# .NET Framework 那两个在 Windows 上会把条目名写成反斜杠（`a\b.txt`），
# 标准 unzip 与部分解压工具会判成非法条目。ZIP 规范要求正斜杠。
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stageFull = (Resolve-Path -LiteralPath $stage).Path
$zipStream = [System.IO.File]::Open($zip, [System.IO.FileMode]::Create)
try {
    # 第 4 个参数传 UTF8：.NET 才会给条目置「UTF-8 名称」标志位。
    # 不传的话中文文件名（一键安装.cmd 等）在非 Windows 的解压工具里会变乱码。
    $archive = New-Object System.IO.Compression.ZipArchive(
        $zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $false,
        [System.Text.Encoding]::UTF8)
    try {
        Get-ChildItem -LiteralPath $stageFull -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($stageFull.Length).TrimStart('\', '/').Replace('\', '/')
            $entry = $archive.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
            $out = $entry.Open()
            try {
                $in = [System.IO.File]::OpenRead($_.FullName)
                try { $in.CopyTo($out) } finally { $in.Dispose() }
            } finally { $out.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $zipStream.Dispose() }

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
Set-Content -Path "$zip.sha256" -Value ("{0}  {1}" -f $hash, (Split-Path -Leaf $zip)) -Encoding ASCII
$exeHash = (Get-FileHash (Join-Path $stage 'spidervpn.exe') -Algorithm SHA256).Hash

[pscustomobject]@{
    Name = $name
    Zip = $zip
    ZipBytes = (Get-Item $zip).Length
    ZipSha256 = $hash
    ExeSha256 = $exeHash
    ExeBytes = (Get-Item (Join-Path $stage 'spidervpn.exe')).Length
} | Format-List
