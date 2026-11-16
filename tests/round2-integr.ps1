#requires -Version 5.1
# SpiderVPN（Rust 版）第二轮「六项改动」集成核验 —— 集成发布工程师自用脚本
# （第三轮在原文件上增量，未另起脚本：用例是同一套现场，拆开只会让守卫和清理逻辑分叉）
#
# 覆盖：① 端口+3 试绑（exit 12 + 文案 + 零副作用）② 探测端口 bind 重试（瞬时占用可恢复 / 持续占用判跳过）
#       ③ 「跳过」独占（跳过 ⟺ 探测端口被占用；第三轮起「未做自检」那条死分支已从 selfcheck 删除，
#          该措辞在产物里必须 0 处，见 R3-2a）
#       ④ 引擎秒退时 runtime-engine.json 不得存在（口径：文件存在 ⟺ 连接正在运行）
#       ⑤ 第三轮 item2：`未做自检` 归零（产物 + 行为双钉）
#       ⑥ 第三轮 item3：事务摘要行带跳过原因，而**结论行一字未动**
# 不覆盖（需真引擎/真网络/GUI，由人工按报告附 I 步骤跑）：A–E 全量、D7 五格、D8 双路径、界面管道。
# 界面端口（第三轮 item1）不在本脚本：那条要用产物里的 HTML 在浏览器里跑，见 tests\round3-page.mjs。
#
# 三条硬规则（与 acceptance-cli.ps1 一致）：
# 1. 只碰临时注册表键（SPIDERVPN_PROXY_KEY），真实系统代理一个字节都不写；
# 2. 默认数据根 C:\SpiderVPN\data 只读，写文件的用例一律跑临时根；
# 3. 不改产品代码，不 build。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tests\round2-integr.ps1
# 退出码：0 全通过 / 1 有 FAIL / 2 未能完整验证（环境被占用或 SKIP）/ 3 脚本自身异常

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Exe        = 'C:\SpiderVPN\bin\spidervpn.exe'
$DefaultData = 'C:\SpiderVPN\data'
$Fixture    = Join-Path $PSScriptRoot 'fixtures\engine-no-split.json'
$FakeEngine = 'C:\Windows\System32\PING.EXE'   # 只被写进 config，本脚本不靠它连
$DeadEngine = 'C:\Windows\System32\cmd.exe'    # 秒退引擎：cmd 不认识 `run -c <file>`，立刻退出

$ScenRoot = Join-Path $env:TEMP ('tc-integr2-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Cfg      = Join-Path $Data 'config.json'
$RtEng    = Join-Path $Data 'runtime-engine.json'

$env:SPIDERVPN_ROOT = $ScenRoot
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\integr-r2'
$env:SPIDERVPN_RUN_KEY   = 'Software\SpiderVPN\tests\run-r2'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY
Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue   # 假引擎参数缝隙不许留在环境里

$RealKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

$script:pass = 0; $script:fail = 0; $script:skip = 0
$script:held = @()          # 本脚本占着的 TcpListener，Cleanup 里统一释放
$script:log  = @()          # 结论另存 UTF-8 文件：控制台是 OEM 代码页，中文经管道会变乱码
$LogPath = Join-Path $env:TEMP ('tc-integr2-log-' + $PID + '.txt')

function Add-Log { param($Line) $script:log += $Line; Write-Host $Line }

function Case {
    param($Id, $Desc, $Ok, $Actual)
    if ($Ok) { $script:pass++; Add-Log ("PASS  {0}  {1}" -f $Id, $Desc) }
    else     { $script:fail++; Add-Log ("FAIL  {0}  {1} :: {2}" -f $Id, $Desc, $Actual) }
}
function Skip { param($Id, $Desc, $Why) $script:skip++; Add-Log ("SKIP  {0}  {1} :: {2}" -f $Id, $Desc, $Why) }

# 能绑就立刻放掉（不占用户的端口）
function Test-PortBindable {
    param([int]$Port)
    if ($Port -le 0 -or $Port -gt 65535) { return $false }
    $l = $null
    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $l.Start(); return $true
    } catch { return $false }
    finally { if ($l) { try { $l.Stop() } catch { } } }
}

# 在整份产物文本里数一个措辞出现几次（序数比较，不走正则、不看区域设置）。
# 为什么不用 [regex]::Matches：77MB 取成字符串后对 5 个模式做正则要 40 秒，IndexOf 只要 0.5 秒。
function Count-Str {
    param([string]$Hay, [string]$Needle)
    if ([string]::IsNullOrEmpty($Needle)) { return 0 }
    $n = 0; $i = 0
    while (($i = $Hay.IndexOf($Needle, $i, [System.StringComparison]::Ordinal)) -ge 0) { $n++; $i += $Needle.Length }
    return $n
}

# 占住端口，返回 listener（持有引用 = 一直占着）。用完必须 Release-Lock。
function Lock-Port {
    param([int]$Port)
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
    $l.Start()
    $script:held += $l
    return $l
}
function Release-Lock {
    param($L)
    if ($L) { try { $L.Stop() } catch { } }
}

# 找一对「P 与 P+3 都能绑」的基端口：本轮 --import/--set-line 会试绑 P+3，
# 基端口空闲但 P+3 被占，产品会**正确**拒绝，用例就假红了。
function Find-FreePair {
    param([int]$From = 48200)
    for ($p = $From; $p -lt ($From + 400); $p++) {
        if ((Test-PortBindable $p) -and (Test-PortBindable ($p + 3))) { return $p }
    }
    throw "找不到可用的端口对（$From 起试了 400 个）"
}

# 输出一律走「cmd 重定向到文件」，不用管道。
# 为什么：--connect 拉起的引擎会**继承 stdout 写端**，管道要等引擎退出才 EOF，
# 于是「连接成功、引擎在跑」时管道里读到的是空字符串。第一版把"读不到输出"当成
# "产品没输出那句话"，连造了三条假红；读取也必须用 FileShare.ReadWrite（引擎正持着那个句柄）。
function New-Runner { param($ArgList)
    $out = Join-Path $env:TEMP ('r2-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bat = Join-Path $env:TEMP ('r2-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $argStr = (($ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    Set-Content -Path $bat -Encoding OEM -Value ("@echo off`r`n`"$Exe`" $argStr > `"$out`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c "' + $bat + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    return [pscustomobject]@{ Bat = $bat; OutFile = $out; Psi = $psi } }

function Read-OutFile { param($Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        $t = $sr.ReadToEnd(); $sr.Close(); $fs.Close(); return $t
    } catch { return '' } }

function RunTimed {
    param($ArgList, [int]$TimeoutMs = 40000)
    $r = New-Runner $ArgList
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($r.Psi)
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; $sw.Stop(); return [pscustomobject]@{ Code = -9; Out = '（超时）'; Ms = $sw.ElapsedMilliseconds } }
    $sw.Stop()
    $txt = Read-OutFile $r.OutFile
    Remove-Item $r.Bat, $r.OutFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $txt; Ms = $sw.ElapsedMilliseconds }
}

# 异步起（用于「先占端口 → 起 CLI → 150ms 后放端口」的竞态用例）
function Start-Cli {
    param($ArgList)
    $r = New-Runner $ArgList
    $p = [System.Diagnostics.Process]::Start($r.Psi)
    return [pscustomobject]@{ P = $p; Bat = $r.Bat; OutFile = $r.OutFile; Sw = [System.Diagnostics.Stopwatch]::StartNew() }
}
function Finish-Cli {
    param($H, [int]$TimeoutMs = 40000)
    if (-not $H.P.WaitForExit($TimeoutMs)) { try { $H.P.Kill() } catch { }; $H.Sw.Stop(); return [pscustomobject]@{ Code = -9; Out = '（超时）'; Ms = $H.Sw.ElapsedMilliseconds } }
    $H.Sw.Stop()
    $txt = Read-OutFile $H.OutFile
    Remove-Item $H.Bat, $H.OutFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $H.P.ExitCode; Out = $txt; Ms = $H.Sw.ElapsedMilliseconds }
}

# 文件签名：长度 + mtime + SHA256（「零副作用」要三者都比）
function Get-Sig {
    param($Path)
    if (-not (Test-Path $Path)) { return '(不存在)' }
    $i = Get-Item $Path
    return ('{0}|{1}|{2}' -f $i.Length, $i.LastWriteTimeUtc.Ticks, (Get-FileHash $Path -Algorithm SHA256).Hash)
}

function Get-DataManifest {
    param($Root)
    # 递归列（第三轮从"只看顶层 + lines\"改成递归）：默认根里可能被别的脚本留下嵌套目录
    # （本轮实测根下多了个 data\data\，是一个把 SPIDERVPN_ROOT 指到默认根的运行留下的），
    # 只扫顶层会看不见它，那样"零写入"就成了只说了一半的话。
    if (-not (Test-Path $Root)) { return @('(根不存在)') }
    return @(Get-ChildItem $Root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            "$($_.FullName.Substring($Root.Length + 1))|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
        } | Sort-Object)
}

# 清单太长（WebView2 子树），比对用指纹；差异明细单独取。
function Get-ManifestSig {
    param($Manifest)
    $t = ($Manifest -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($t))).Replace('-', '') }
    finally { $sha.Dispose() }
}

# 按 runtime-engine.json / runtime.json 记录的 pid 精确清理本轮拉起的引擎
# （按进程名杀会牵连用户自己的 PING/curl，上一轮已因此定规矩）
function Stop-RecordedEngine {
    foreach ($f in @($RtEng, (Join-Path $Data 'runtime.json'))) {
        if (Test-Path $f) {
            try {
                $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($j.EnginePid) { Stop-Process -Id $j.EnginePid -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
    }
}

# 清空场景数据根（只删自己的临时根）。删之前先按记录杀引擎，否则假引擎会活到自然退出。
function Reset-Data {
    Stop-RecordedEngine
    if (Test-Path $Data) { Remove-Item $Data -Recurse -Force -ErrorAction SilentlyContinue }
}

function New-ScenRoot {
    New-Item -ItemType Directory -Path $Data -Force | Out-Null
}

# 铺一份合法的 schema 2 配置（用于「已有配置」格的零副作用比对）
function Write-GoodCfg {
    param([int]$Port)
    New-ScenRoot
    $o = @{ schema = 2; mode = 'proxy'; auto_start = $false; auto_connect = $false; close_to_tray = $false
            selected = 'L1'
            lines = @(@{ id = 'L1'; name = '核验线路'; proxy_endpoint = ('127.0.0.1:' + $Port) })
            engine = @{ binary = 'C:\\Windows\\System32\\PING.EXE' } }
    [System.IO.File]::WriteAllText($Cfg, ($o | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
}

function Remove-TempOnly {
    param($Path)
    if (-not $Path) { return }
    $full = [System.IO.Path]::GetFullPath($Path).ToLower()
    if ($full.StartsWith('c:\tradechannelrs\data')) {
        throw "拒绝删除用户数据根下的路径：$Path"
    }
    if (Test-Path $full) { Remove-Item $full -Recurse -Force -ErrorAction SilentlyContinue }
}

function Cleanup {
    if (Test-Path $RtEng) {
        try { $old = (Get-Content $RtEng -Raw -Encoding UTF8 | ConvertFrom-Json).EnginePid; if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue } } catch { }
    }
    foreach ($l in $script:held) { try { $l.Stop() } catch { } }
    $script:held = @()
    Remove-TempOnly $ScenRoot
    Remove-Item Env:SPIDERVPN_RUN_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue
    if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path ('HKCU:\' + $env:SPIDERVPN_RUN_KEY)) { Remove-Item ('HKCU:\' + $env:SPIDERVPN_RUN_KEY) -Recurse -Force -ErrorAction SilentlyContinue }
}

# ---------- 前置守卫 ----------
if (-not (Test-Path $Exe)) { Write-Host "FAIL  G0  被测程序不存在 :: $Exe"; exit 1 }
if (-not (Test-Path $Fixture)) { Write-Host "FAIL  G0  缺少线路 fixture :: $Fixture"; exit 1 }

# 并发守卫：别的实例在跑 → 互斥/端口/键都会互抢，结论不可信。
# 但验收脚本每跑一条用例都会起一个短命 exe，光"看到过实例"就退出会永远等不到窗口。
# 所以改成「等到连续 3 秒没有实例」再开工，最多等 90 秒；等不到才 SKIP。
$quietWaited = 0
while ($quietWaited -lt 90) {
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) {
        Start-Sleep -Milliseconds 1500
        if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { break }
        $quietWaited += 1.5; continue
    }
    Start-Sleep -Seconds 1; $quietWaited += 1
}
if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Host "SKIP  等了 90 秒仍检测到另一个 spidervpn 实例：本轮结果不可信，未验证。"
    Remove-TempOnly $ScenRoot
    exit 2
}
Write-Host ("（等空闲窗口用了约 {0:N1} 秒）" -f $quietWaited)

$exeMtime = (Get-Item $Exe).LastWriteTime
Add-Log ("被测产物：{0}  {1:N0} 字节  改动于 {2}" -f $Exe, (Get-Item $Exe).Length, $exeMtime)
Add-Log ("SHA256  ：{0}" -f (Get-FileHash $Exe -Algorithm SHA256).Hash)

# ===== 第三轮 item2 的钉子（纯读产物，不起进程）=====
# 「未做自检」那条死分支（selfcheck.rs 原 389-396）已删除。第二轮报告里"该措辞存在于二进制唯一 1 处"
# 的依据已过期——现在必须是 0 处。这条放在最前面：它是"有没有人把死分支加回来"的便宜钉子。
$exeText = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($Exe))
$nDead  = Count-Str $exeText '未做自检'
$nStep  = Count-Str $exeText '通道自检跳过（'
$nSkipped = Count-Str $exeText '自检跳过：'
$nUiPort = Count-Str $exeText '端口要填 1~65532 的整数'
$nBadIn = Count-Str $exeText 'badInput'
Case 'R3-2a' '产物里「未做自检」为 0 处（死分支确实删了，没被加回来）' ($nDead -eq 0) ("出现次数=$nDead")
Case 'R3-2b' '产物里「通道自检跳过（」唯一 1 处（摘要行格式串只有一份实现）' ($nStep -eq 1) ("出现次数=$nStep")
Case 'R3-2c' '产物里「自检跳过：」唯一 1 处（结论行格式串只有一份实现）' ($nSkipped -eq 1) ("出现次数=$nSkipped")
Case 'R3-2d' '产物里带第三轮界面端口提示文案（界面那条改动确实进了这个产物）' ($nUiPort -eq 1) ("出现次数=$nUiPort")
Case 'R3-2e' '产物里有 badInput 判据（B 方案已编入：非数字不再静默回落成 17890）' ($nBadIn -ge 1) ("出现次数=$nBadIn")
$exeText = $null

$realBefore = (Get-ItemProperty -Path $RealKey -ErrorAction SilentlyContinue)
$realSig = '{0}|{1}|{2}' -f $realBefore.ProxyEnable, $realBefore.ProxyServer, $realBefore.ProxyOverride
$defaultBefore = Get-DataManifest $DefaultData

Cleanup
# Cleanup 会删临时键，所以键必须**在 Cleanup 之后**铺（上一版顺序反了，导致 --connect 读不到代理设置，
# 直接 exit 13「拒绝接管」，而"连接失败"也满足"输出里没有跳过"——那会造出一批假绿）。
New-Item -Path $TmpKey -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyEnable   -Value 0 -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyServer   -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyOverride -Value 'localhost;127.*' -PropertyType String -Force | Out-Null
New-ScenRoot

try {
    # ================= 第 1 项：端口+3 试绑 =================
    Write-Host ''
    Write-Host '=== 第 1 项：导入/改线路时试绑「线路端口+3」 ==='

    # --- 1a 空闲对：反向对照（防止「永远拒绝」的假通过）---
    $base = Find-FreePair
    $o = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$base", '--line-name', '核验线路A')
    $cfgSig1 = Get-Sig $Cfg
    Case 'R2-1a' "探测端口空闲时 --import 必须成功并真的写入（对照 $base/$($base+3)）" `
        ($o.Code -eq 0 -and (Test-Path $Cfg) -and $o.Out -match '已生成引擎配置') `
        ("退出码=$($o.Code) 配置=$((Test-Path $Cfg)) 输出=$($o.Out -replace '\s+',' ')")
    # 第三轮 item1 的"合法端口真的被采纳"：界面与命令行共用同一个 import_profile，
    # 界面侧只是把表单里的 port 解析出来传进去（main.rs::handle_ui_import）。
    # 命令行这条能证明"传进去的端口确实变成了端点"，界面侧的传参由 round3-page.mjs 的 P2e* 钉住。
    $cfgTxt1 = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '' }
    Case 'R3-1h' "指定的端口真的被用作端点（配置里出现 127.0.0.1:$base）" `
        ($cfgTxt1 -match ('127\.0\.0\.1:' + $base)) ("配置=$($cfgTxt1 -replace '\s+',' ')")

    # --- 1b 空根 + P+3 被占：exit 12 + 定稿文案 + 零副作用 ---
    Reset-Data; New-ScenRoot
    $base2 = Find-FreePair
    $probe2 = $base2 + 3
    $lk = Lock-Port $probe2
    $o = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$base2", '--line-name', '被拒线路')
    $expect = "端口 $base2 不可用：它的自检探测端口 $probe2 已被占用或被系统预留。请换一个线路端口。"
    Case 'R2-1b' "探测端口 $probe2 被占 → --import exit 12 + 定稿文案" `
        ($o.Code -eq 12 -and $o.Out.Contains($expect)) `
        ("退出码=$($o.Code)（期望 12） 文案命中=$($o.Out.Contains($expect)) 实际=$($o.Out -replace '\s+',' ')")

    $leftover = @(Get-ChildItem $Data -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName.Substring($Data.Length + 1) })
    Case 'R2-1c' '空根被拒后「零副作用」：无 config.json / 无 lines\ / 无 *.tmp' `
        ((-not (Test-Path $Cfg)) -and (-not (Test-Path (Join-Path $Data 'lines'))) -and (@($leftover | Where-Object { $_ -like '*.tmp' }).Count -eq 0)) `
        ("配置=$((Test-Path $Cfg)) lines目录=$((Test-Path (Join-Path $Data 'lines'))) 残留=[$($leftover -join ','))]")
    Release-Lock $lk

    # --- 1d 已有配置 + P+3 被占：--set-line exit 12 且配置一个字节不改 ---
    $base3 = Find-FreePair
    Write-GoodCfg $base3
    $sigBefore = Get-Sig $Cfg
    $base4 = Find-FreePair -From ($base3 + 10)
    $lk2 = Lock-Port ($base4 + 3)
    $o = RunTimed @('--set-line', 'L2', '核验线路B', "127.0.0.1:$base4")
    $expect2 = "端口 $base4 不可用：它的自检探测端口 $($base4+3) 已被占用或被系统预留。请换一个线路端口。"
    $sigAfter = Get-Sig $Cfg
    Case 'R2-1d' "--set-line 探测端口被占 → exit 12 + 定稿文案" `
        ($o.Code -eq 12 -and $o.Out.Contains($expect2)) `
        ("退出码=$($o.Code)（期望 12） 文案命中=$($o.Out.Contains($expect2))")
    Case 'R2-1e' '已有配置（schema 2）被拒后 config.json 长度/mtime/SHA256 三者全不变' `
        ($sigBefore -eq $sigAfter) ("前=$sigBefore 后=$sigAfter")
    Release-Lock $lk2

    # --- 1f 同一根上再给一个空闲对：--set-line 必须真的写进去（对照）---
    $base5 = Find-FreePair -From ($base4 + 10)
    $o = RunTimed @('--set-line', 'L3', '核验线路C', "127.0.0.1:$base5")
    $cfgTxt = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '' }
    Case 'R2-1f' "探测端口空闲时 --set-line 成功且配置里真的出现 L3（对照 $base5）" `
        ($o.Code -eq 0 -and $cfgTxt -match '核验线路C') `
        ("退出码=$($o.Code) 配置含线路C=$([bool]($cfgTxt -match '核验线路C'))")

    # ================= 第 2 项：探测端口 bind 重试 =================
    Write-Host ''
    Write-Host '=== 第 2 项：探测端口 bind 失败重试（3 次尝试 / 2 次 200ms 间隔） ==='

    # 这一步要用「活着的假引擎」：PING 会活 300 秒且不监听任何端口。
    # 为什么必须活着——第三轮起 selfcheck 里「未做自检」那条分支已经删了，引擎起不来时
    # connect 会在 `引擎启动后立即退出` 处当场 exit 13，**根本走不到自检**，输出里既没有「跳过」
    # 也没有任何结论。那样「瞬时占用恢复成拨号」与「恢复不了」在输出上就无法区分，用例会变成假绿。
    # （旧注释说"引擎不在时报「未做自检」"——该措辞在 0B60720A… 上已是 0 处，不再成立。）
    $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'

    # --- 2a 瞬时占用：占 → 起 CLI → 150ms 后放 → 必须恢复成「拨号」 ---
    # 修（第三轮发现，两处）：
    #  (1) 占位必须是**独立进程**：本进程 TcpListener 的句柄会被 Process.Start(UseShellExecute=false)
    #      起出来的 cmd 继承，端口被钉死到子进程退出，于是永远判「跳过」（0/5）。
    #  (2) 判据不能看结论文案：假引擎 PING 活着但不监听探测端口，Dial 计划的拨号必然 NotListening，
    #      第三轮把它归成「跳过：探测端口 X 被占用」。所以改成看「计划是不是 Dial」的落盘证据：
    #      runtime.json 里有 ProbeUser/ProbePass（record_probe_creds 只在 Dial 时写）、
    #      runtime-engine.json 里有该探测端口。
    $HoldScript = Join-Path $env:TEMP ('integr-hold-' + $PID + '.ps1')
    [System.IO.File]::WriteAllText($HoldScript, @'
param([int]$Port,[string]$StopFile,[string]$ReadyFile)
$l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback,$Port)
$l.Start()
[IO.File]::WriteAllText($ReadyFile,'ready',(New-Object Text.UTF8Encoding($false)))
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path $StopFile) -and $sw.ElapsedMilliseconds -lt 60000) { Start-Sleep -Milliseconds 10 }
$l.Stop()
'@, (New-Object System.Text.UTF8Encoding($false)))

    $raceOk = 0; $raceN = 5; $raceLog = @()
    for ($i = 1; $i -le $raceN; $i++) {
        $b = Find-FreePair -From (48300 + ($i * 10))
        Reset-Data; New-ScenRoot
        $imp = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$b", '--line-name', '竞态线路')
        if ($imp.Code -ne 0) { $raceLog += "第${i}次:导入失败($($imp.Code))"; continue }
        $pr = $b + 3
        $stopFile  = Join-Path $env:TEMP ('integr-stop-' + $PID + '-' + $i)
        $readyFile = Join-Path $env:TEMP ('integr-rdy-' + $PID + '-' + $i)
        if (Test-Path $stopFile)  { Remove-Item $stopFile -Force }
        if (Test-Path $readyFile) { Remove-Item $readyFile -Force }
        $hpsi = New-Object System.Diagnostics.ProcessStartInfo
        $hpsi.FileName = 'powershell.exe'
        $hpsi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $HoldScript + '" -Port ' + $pr + ' -StopFile "' + $stopFile + '" -ReadyFile "' + $readyFile + '"'
        $hpsi.UseShellExecute = $false; $hpsi.CreateNoWindow = $true
        $holder = [System.Diagnostics.Process]::Start($hpsi)
        $w = 0; while (-not (Test-Path $readyFile) -and $w -lt 120) { Start-Sleep -Milliseconds 25; $w++ }
        if (-not (Test-Path $readyFile)) { $raceLog += "第${i}次:占位进程没起来"; if (-not $holder.HasExited) { try { $holder.Kill() } catch { } }; continue }
        $h = Start-Cli @('--connect')
        Start-Sleep -Milliseconds 150
        New-Item -ItemType File -Path $stopFile -Force | Out-Null
        $r = Finish-Cli $h
        if (-not $holder.HasExited) { try { [void]$holder.WaitForExit(6000) } catch { try { $holder.Kill() } catch { } } }
        Remove-Item $stopFile, $readyFile -Force -ErrorAction SilentlyContinue
        # Dial 证据：凭据落盘（只在 Dial 时写）
        $hasCred = $false
        $rtPath = Join-Path $Data 'runtime.json'
        if (Test-Path $rtPath) {
            try { $jj = Get-Content $rtPath -Raw -Encoding UTF8 | ConvertFrom-Json
                  $hasCred = [bool]($jj.ProbeUser) -and [bool]($jj.ProbePass) } catch { } }
        $cfgHasProbe = $false
        if (Test-Path $RtEng) { try { $cfgHasProbe = ((Get-Content $RtEng -Raw -Encoding UTF8) -match ([string]$pr)) } catch { } }
        if ($r.Code -eq 0 -and $hasCred -and $cfgHasProbe) { $raceOk++ }
        $raceLog += ("第{0}次:exit={1} 有凭据={2} 引擎配置含探测端口={3} {4}ms" -f $i, $r.Code, $hasCred, $cfgHasProbe, $r.Ms)
        try { RunTimed @('--disconnect') 25000 | Out-Null } catch { }
    }
    Case 'R2-2a' "瞬时占用（150ms 后由独立进程释放）必须恢复成拨号：$raceN 次里 $raceOk 次恢复（看 ProbeUser/ProbePass 与引擎配置里的探测端口）" `
        ($raceOk -eq $raceN) ($raceLog -join ' / ')
    Remove-Item $HoldScript -Force -ErrorAction SilentlyContinue

    # --- 2b 持续占用（第四轮改口径）：+3 全程被占 → 回落动态端口，不再判「跳过」---　　
    # 【第四轮口径变更 2026-10-28】旧断言「全程被占 → 自检跳过（探测端口 X 被占用）」已随产品变更失效：
    # plan_probe 在 +3 绑不上时回落到系统分配的空闲端口；「跳过」只剩「系统连一个空闲端口都分不出来」
    # 那一条（运行时不可构造）。本格改断言新口径 + 关键不变量：
    #   ① connect 成功；② 不出现「跳过」/「被占用」；③ 结论「未通过（…探测端口 D 上没有监听）」；
    #   ④ runtime-engine.json 的 tc-check.listen_port == D ≠ +3。
    $b2 = Find-FreePair -From 48400
    Reset-Data; New-ScenRoot
    $imp = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$b2", '--line-name', '占用线路')
    $pr2 = $b2 + 3
    $lk4 = Lock-Port $pr2
    $o = RunTimed @('--connect')
    $tcPort2 = -1
    if (Test-Path $RtEng) {
        try {
            $j2 = Get-Content $RtEng -Raw -Encoding UTF8 | ConvertFrom-Json
            $tc2 = @($j2.inbounds | Where-Object { $_.tag -eq 'tc-check' })
            if ($tc2.Count -eq 1) { $tcPort2 = [int]$tc2[0].listen_port }
        } catch { }
    }
    Release-Lock $lk4
    $dyn2 = -1
    if ($o.Out -match '探测端口 (\d+) 上没有监听') { $dyn2 = [int]$matches[1] }
    Case 'R2-2b' "探测端口 $pr2 全程被占 → 回落动态端口：connect 成功、不判「跳过」、结论「未通过（探测端口 D 上没有监听）」" `
        ($o.Code -eq 0 -and $o.Out -notmatch '跳过' -and $o.Out -notmatch '被占用' -and $dyn2 -gt 0 -and $dyn2 -eq $tcPort2 -and $dyn2 -ne $pr2) `
        ("退出码=$($o.Code) 自检报的端口=$dyn2 引擎配置=$tcPort2 +3=$pr2 输出=$($o.Out -replace '\s+',' ')")
    Case 'R2-2c' "耗时 $($o.Ms)ms 落在 [350ms, 5000ms]：证明 +3 上真的按 3 次 × 200ms 重试过才回落（不是立刻换口）；上限 5000ms 用来兜住「拨号挂死」" `
        ($o.Ms -ge 350 -and $o.Ms -le 5000) ("实际=$($o.Ms)ms")

    # ================= 第三轮 item3（第四轮改口径）：摘要行/结论行一致性 =================
    # 【口径变更】原目标「摘要行写『通道自检跳过（探测端口 X 被占用）』」在可达路径上已不存在；
    # 本段改为断言新口径下两行必须一致（摘要行「通道自检未通过」、结论行「未通过（经交易出口…）」）。
    # 原「跳过带原因」的验证改由产物字符串（通道自检跳过（ 唯一 1 处）+ selfcheck 单测覆盖，本段不声称验证它。
    Write-Host ''
    Write-Host '=== 第三轮 item3（第四轮改口径）：摘要行/结论行在新口径下必须一致 ==='
    $sumLine = (@($o.Out -split "`r?`n" | Where-Object { $_ -match '完成：' }) -join ' | ')
    $conLine = (@($o.Out -split "`r?`n" | Where-Object { $_ -match '通道自检（经交易出口）' }) -join ' | ')
    $sumOk = ($sumLine -match '通道自检未通过')
    $conOk = ($conLine -match ('（经交易出口）未通过：探测端口 ' + $dyn2 + ' 上没有监听'))
    Case 'R3-3a' '摘要行写「通道自检未通过」（不再写「通道自检跳过（探测端口 X 被占用）」）' $sumOk ("完成行=$sumLine")
    Case 'R3-3b' "结论行写「通道自检（经交易出口）未通过：探测端口 $dyn2 上没有监听…」（与落盘端口同一个）" $conOk ("结论行=$conLine")
    Case 'R3-3c' '两行说同一件事：都不含「跳过」，且结论行端口 == 引擎配置 tc-check 端口' `
        ($sumOk -and $conOk -and $dyn2 -eq $tcPort2) ("摘要命中=$sumOk 结论命中=$conOk D=$dyn2 引擎配置=$tcPort2")
    Case 'R3-3d' '整个输出里不出现已删除的「未做自检」' (-not $o.Out.Contains('未做自检')) ("输出=$($o.Out -replace '\s+',' ')")
    Case 'R3-3e' '摘要行确实在「完成：…」事务摘要行里（不是别处拼出来的字符串）' ($sumOk) ("完成行=$sumLine")

    # ================= 第 3 项（第四轮改口径）：「跳过」的可达范围 =================
    Write-Host ''
    Write-Host '=== 第 3 项（第四轮改口径）：+3 被占不产生「跳过」；跳过只留给「拿不到可用探测端口」 ==='

    $lines = $o.Out -split "`r?`n"
    $skipLines = @($lines | Where-Object { $_ -match '跳过' })
    $badSkip = @($skipLines | Where-Object { -not ($_ -match '探测端口' -and $_ -match '被占用') })
    # 旧不变式「含跳过 ⇒ 必含『探测端口…被占用』且 ≥2 行」在新口径下已无从构造（跳过分支不可达）。
    # 改成：本现场必须 0 行「跳过」；同时保留「若出现跳过则必带原因」这条不变式（空集也成立）。
    Case 'R2-3a' '本现场（+3 全程被占）产生的「跳过」行必须为 0（新口径）；若出现则必带原因（不变式保留）' `
        ($skipLines.Count -eq 0 -and $badSkip.Count -eq 0) ("跳过行数=$($skipLines.Count) 违规=$($badSkip.Count) 行=[$($skipLines -join ' / ')]")
    Case 'R2-3b' '不得出现旧口径「引擎进程不在…跳过」' `
        ($o.Out -notmatch '引擎进程不在[^\r\n]*跳过') ("输出=$($o.Out -replace '\s+',' ')")

    # --- 3c 引擎秒退：必须报「未做自检」（未通过类），不得出现「跳过」；且不得留下 runtime-engine.json ---
    # 先把假引擎参数缝隙撤掉：这一格要的就是「引擎一起来就死」。
    Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue
    Reset-Data
    $b3 = Find-FreePair -From 48500
    New-ScenRoot
    $imp = RunTimed @('--import', $Fixture, '--engine', $DeadEngine, '--port', "$b3", '--line-name', '秒退线路')
    $o3 = RunTimed @('--connect')
    Case 'R2-3c' '引擎秒退 → connect 当场失败（exit 13）并在文案里如实说明' `
        ($o3.Code -eq 13 -and $o3.Out -match '引擎启动后立即退出' -and $o3.Out -notmatch '跳过') `
        ("退出码=$($o3.Code) 输出=$($o3.Out -replace '\s+',' ')")
    Case 'R2-3d' '引擎秒退 → runtime-engine.json 不存在（口径：文件存在 ⟺ 连接正在运行）' `
        (-not (Test-Path $RtEng)) ("存在=$((Test-Path $RtEng))")

    # ================= 收尾 =================
    Write-Host ''
    Write-Host '=== 收尾三项 ==='
    $realAfter = (Get-ItemProperty -Path $RealKey -ErrorAction SilentlyContinue)
    $realSig2 = '{0}|{1}|{2}' -f $realAfter.ProxyEnable, $realAfter.ProxyServer, $realAfter.ProxyOverride
    Case 'R2-Z1' '真实系统代理前后完全一致（零写入）' ($realSig -eq $realSig2) ("前=$realSig 后=$realSig2")

    $defaultAfter = Get-DataManifest $DefaultData
    $defaultDiff = @(Compare-Object -ReferenceObject $defaultBefore -DifferenceObject $defaultAfter)
    Case 'R2-Z2' "用户默认根零写入（递归清单指纹一致，前后各 $($defaultBefore.Count)/$($defaultAfter.Count) 个文件）" `
        ((Get-ManifestSig $defaultBefore) -eq (Get-ManifestSig $defaultAfter)) `
        ("差异：" + ((@($defaultDiff | Select-Object -First 5 | ForEach-Object { "$($_.SideIndicator)$($_.InputObject)" })) -join ' ; '))

    $leftProcs = @(Get-Process spidervpn -ErrorAction SilentlyContinue).Count
    if ($leftProcs -gt 0) { Start-Sleep -Seconds 1; $leftProcs = @(Get-Process spidervpn -ErrorAction SilentlyContinue).Count }
    Case 'R2-Z3' '零残留：无 spidervpn 进程存活' ($leftProcs -eq 0) ("存活=$leftProcs")
}
catch {
    Write-Host ("异常：{0}`n{1}" -f $_.Exception.Message, $_.ScriptStackTrace)
    Cleanup
    Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    exit 3
}
finally {
    Cleanup
    $script:log += ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    try { [System.IO.File]::WriteAllText($LogPath, (($script:log -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false))) } catch { }
}

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
Write-Host ("结论明细（UTF-8）：{0}" -f $LogPath)
if ($script:fail -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }
exit 0
