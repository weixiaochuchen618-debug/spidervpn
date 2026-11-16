#requires -Version 5.1
# 第三轮核验 · 新增用例
#   N0 产物指纹（SHA / 字符串证据）
#   N1 --connect 摘要行 = 「通道自检跳过（探测端口 X 被占用）」
#   N2 删「未做自检」分支后：引擎秒退仍 exit 13 且无「跳过」
#   N3 界面导入端口：页面逐字节取自产物内嵌 PAGE，在 Chromium 里真实渲染执行
#      （badInput 这条要「键入」而不是直接赋 .value：用浏览器编辑管线的 insertText，
#        实测只有 e / - / . / + 这类「部分合法」字符会置 badInput；纯字母会被浏览器直接丢弃）
#   N5 宿主侧端口回落/采纳：CLI --import 不给 --port / 给 --port（同一 import_profile）
#   N6 Dial 计划下的 NotListening 必须报「未通过：探测端口 X 上没有监听」，不得报「跳过/被占用」
#   N4 三项复核（默认根只读 / 真实代理零写入 / 产物稳定）
#
# 纪律：
#  1. 只碰临时数据根 + 临时代理键；默认根 C:\SpiderVPN\data 只读（前后比清单）
#  2. 造「端口被占」必须用**独立进程**占位（同进程占位会被子进程继承句柄，把端口钉死）
#  3. 不 build、不装机
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tests\round3-new.ps1

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Exe         = 'C:\SpiderVPN\bin\spidervpn.exe'
$DefaultData = 'C:\SpiderVPN\data'
$ExpectSha   = 'C65B591B8585ED89279751FF4312496F7B0696668705D1E03E3465E3CE7BE36D'
$FakeEngine  = 'C:\Windows\System32\PING.EXE'
$DeadEngine  = 'C:\Windows\System32\cmd.exe'
$Fixture     = Join-Path $PSScriptRoot 'fixtures\engine-no-split.json'
$Edge        = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

$ScenRoot = Join-Path $env:TEMP ('tc-r3-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Cfg      = Join-Path $Data 'config.json'
$Rt       = Join-Path $Data 'runtime.json'
$RtEng    = Join-Path $Data 'runtime-engine.json'
$LastChk  = Join-Path $Data 'last-check.json'
$Hold     = Join-Path $env:TEMP ('tc-r3-hold-' + $PID + '.ps1')
$LogPath  = Join-Path $env:TEMP ('tc-r3-log-' + $PID + '.txt')

$env:SPIDERVPN_ROOT      = $ScenRoot
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\r3new'
$env:SPIDERVPN_RUN_KEY   = 'Software\SpiderVPN\tests\run-r3new'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY
[Environment]::SetEnvironmentVariable('SPIDERVPN_ENGINE_ARGS', $null)

$RealKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

$script:pass = 0; $script:fail = 0; $script:skip = 0; $script:log = @()
function Add-Log { param($L) $script:log += $L; Write-Host $L }
function Case { param($Id,$Desc,$Ok,$Actual)
    if ($Ok) { $script:pass++; Add-Log ("PASS  {0}  {1}" -f $Id,$Desc) }
    else     { $script:fail++; Add-Log ("FAIL  {0}  {1} :: {2}" -f $Id,$Desc,$Actual) } }
function Skip { param($Id,$Desc,$Why) $script:skip++; Add-Log ("SKIP  {0}  {1} :: {2}" -f $Id,$Desc,$Why) }

# ---------------- 通用夹具 ----------------
function Snap3 { param($Path)
    $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if (-not $p) { return '(键不存在)' }
    return ('{0}|{1}|{2}' -f $p.ProxyEnable, $p.ProxyServer, $p.ProxyOverride) }

function Get-Manifest { param($Root)
    $i = @()
    $i += @(Get-ChildItem $Root -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
    $ln = Join-Path $Root 'lines'
    if (Test-Path $ln) { $i += @(Get-ChildItem $ln -File -ErrorAction SilentlyContinue | ForEach-Object { "lines\$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) }
    return @($i | Sort-Object) }

function New-Runner { param($ArgList,[string]$Tag='r3')
    $out = Join-Path $env:TEMP ($Tag + '-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bat = Join-Path $env:TEMP ($Tag + '-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $argStr = (($ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    Set-Content -Path $bat -Encoding OEM -Value ("@echo off`r`n`"$Exe`" $argStr > `"$out`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c "' + $bat + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    return [pscustomobject]@{ Bat = $bat; OutFile = $out; Psi = $psi } }

function Read-OutFile { param($P)
    try {
        $fs = [IO.File]::Open($P, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        $t = $sr.ReadToEnd(); $sr.Close(); $fs.Close(); return $t
    } catch { return '' } }

function RunTimed { param($ArgList, [int]$TimeoutMs = 90000)
    $r = New-Runner $ArgList
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($r.Psi)
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Code = -9; Out = '（超时）'; Ms = $sw.ElapsedMilliseconds } }
    $sw.Stop(); $t = Read-OutFile $r.OutFile
    Remove-Item $r.Bat, $r.OutFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $t; Ms = $sw.ElapsedMilliseconds } }

function Test-PortFree { param([int]$Port)
    $l = $null
    try { $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port); $l.Start(); return $true }
    catch { return $false } finally { if ($l) { try { $l.Stop() } catch { } } } }

function Find-FreePair { param([int]$From = 48300)
    for ($p = $From; $p -lt ($From + 300); $p++) {
        if ((Test-PortFree $p) -and (Test-PortFree ($p + 3))) { return $p } }
    throw "找不到可用端口对（从 $From 起试了 300 个）" }

function Start-Holder { param([int]$Port, [string]$Tag)
    $stop  = Join-Path $env:TEMP ('hold-stop-' + $Tag + '-' + $PID)
    $ready = Join-Path $env:TEMP ('hold-rdy-' + $Tag + '-' + $PID)
    if (Test-Path $stop)  { Remove-Item $stop -Force }
    if (Test-Path $ready) { Remove-Item $ready -Force }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $Hold + '" -Port ' + $Port + ' -StopFile "' + $stop + '" -ReadyFile "' + $ready + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $w = 0
    while (-not (Test-Path $ready) -and $w -lt 160) { Start-Sleep -Milliseconds 25; $w++ }
    return [pscustomobject]@{ Proc = $p; Stop = $stop; Ready = $ready; Ok = (Test-Path $ready) } }

function Stop-Holder { param($H)
    if (-not $H) { return }
    if ($H.Stop) { New-Item -ItemType File -Path $H.Stop -Force | Out-Null }
    if ($H.Proc -and -not $H.Proc.HasExited) { try { [void]$H.Proc.WaitForExit(6000) } catch { try { $H.Proc.Kill() } catch { } } }
    Remove-Item $H.Stop, $H.Ready -Force -ErrorAction SilentlyContinue }

function Reset-Scen {
    try { RunTimed @('--disconnect') 25000 | Out-Null } catch { }
    foreach ($f in @($Rt, $RtEng)) {
        if (Test-Path $f) { try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.EnginePid) { Stop-Process -Id $j.EnginePid -Force -ErrorAction SilentlyContinue } } catch { } } }
    Get-Process sing-box -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $ScenRoot) { Remove-Item $ScenRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $Data -Force | Out-Null }

function Remove-TempOnly { param($Path)
    if (-not $Path) { return }
    $full = [System.IO.Path]::GetFullPath($Path).ToLower()
    if ($full -eq 'c:\tradechannelrs\data' -or $full.StartsWith('c:\tradechannelrs\data\')) { throw "拒绝删除用户数据根：$Path" }
    if (Test-Path $full) { Remove-Item $full -Recurse -Force -ErrorAction SilentlyContinue } }

# ---------------- 无头 Chromium：--dump-dom（批量、无需键入的场景） ----------------
function Get-DomDump { param([string]$HtmlPath, [int]$TimeoutMs = 90000)
    $prof = Join-Path $env:TEMP ('edge-' + $PID + '-' + [guid]::NewGuid().ToString('N'))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Edge
    $psi.Arguments = '--headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="' + $prof + '" --dump-dom "file:///' + ($HtmlPath -replace '\\','/') + '"'
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $so = $p.StandardOutput.ReadToEnd(); $se = $p.StandardError.ReadToEnd()
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { } }
    if (Test-Path $prof) { Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue }
    return [pscustomobject]@{ Dom = $so; Err = $se; Code = $p.ExitCode } }

# ---------------- 无头 Chromium：CDP（需要真键盘事件时用） ----------------
function Http-GetLocal { param([int]$Port, [string]$Path)
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $Port)
    $s = $c.GetStream()
    $req = "GET $Path HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n`r`n"
    $b = [Text.Encoding]::ASCII.GetBytes($req)
    $s.Write($b, 0, $b.Length); $s.Flush()
    $ms = New-Object IO.MemoryStream
    $buf = New-Object byte[] 8192
    while (($n = $s.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
    $c.Close()
    $all = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    $i = $all.IndexOf("`r`n`r`n")
    if ($i -lt 0) { return '' }
    return $all.Substring($i + 4) }

function Connect-Cdp { param([string]$Url)
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $ws.ConnectAsync([Uri]$Url, [Threading.CancellationToken]::None).Wait(10000) | Out-Null
    return $ws }

function Cdp-Call { param($Ws, [int]$Id, [string]$Method, $Params)
    $payload = @{ id = $Id; method = $Method; params = $Params } | ConvertTo-Json -Depth 8 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $seg = New-Object 'System.ArraySegment[byte]' -ArgumentList @(,$bytes)
    $Ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait(10000) | Out-Null
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        $sb = New-Object Text.StringBuilder
        do {
            $buf = New-Object byte[] 65536
            $rs = $Ws.ReceiveAsync((New-Object 'System.ArraySegment[byte]' -ArgumentList @(,$buf)), [Threading.CancellationToken]::None)
            $rs.Wait(15000) | Out-Null
            $res = $rs.Result
            [void]$sb.Append([Text.Encoding]::UTF8.GetString($buf, 0, $res.Count))
        } while (-not $res.EndOfMessage)
        try { $o = $sb.ToString() | ConvertFrom-Json } catch { continue }
        if ($o.id -eq $Id) { return $o }
    }
    return $null }

function Cdp-Eval { param($Ws, [int]$Id, [string]$Expr)
    $o = Cdp-Call -Ws $Ws -Id $Id -Method 'Runtime.evaluate' -Params @{ expression = $Expr; returnByValue = $true; awaitPromise = $true }
    if (-not $o) { return $null }
    if ($o.result.exceptionDetails) { return $null }
    return $o.result.result.value }

# ---------------- 守卫 ----------------
if (-not (Test-Path $Exe)) { Write-Host "FAIL G0 被测程序不存在：$Exe"; exit 1 }
if (-not (Test-Path $Fixture)) { Write-Host "FAIL G0 缺少 fixture：$Fixture"; exit 1 }
$waited = 0
while ($waited -lt 90) {
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { Start-Sleep -Milliseconds 1500; if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { break } }
    Start-Sleep -Seconds 1; $waited += 1 }
if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Host 'SKIP 等不到空闲窗口（已有 spidervpn 实例）'; exit 2 }

$i = Get-Item $Exe
$shaStart = (Get-FileHash $Exe -Algorithm SHA256).Hash
Add-Log ("被测产物：{0}  {1:N0} 字节  改动于 {2}" -f $Exe, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
Add-Log ("SHA256  ：{0}（开头核一次）" -f $shaStart)

$realBefore    = Snap3 $RealKey
$defaultBefore = Get-Manifest $DefaultData

$holderScript = @'
param([int]$Port,[string]$StopFile,[string]$ReadyFile)
$l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback,$Port)
$l.Start()
[IO.File]::WriteAllText($ReadyFile,'ready',(New-Object Text.UTF8Encoding($false)))
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path $StopFile) -and $sw.ElapsedMilliseconds -lt 60000) { Start-Sleep -Milliseconds 10 }
$l.Stop()
'@

function Cleanup {
    try { RunTimed @('--disconnect') 25000 | Out-Null } catch { }
    foreach ($f in @($Rt, $RtEng)) {
        if (Test-Path $f) { try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.EnginePid) { Stop-Process -Id $j.EnginePid -Force -ErrorAction SilentlyContinue } } catch { } } }
    Get-Process sing-box -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-TempOnly $ScenRoot
    [Environment]::SetEnvironmentVariable('SPIDERVPN_RUN_KEY', $null)
    if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue } }

try {
    Cleanup
    [IO.File]::WriteAllText($Hold, $holderScript, (New-Object Text.UTF8Encoding($false)))
    New-Item -ItemType Directory -Path $Data -Force | Out-Null
    New-Item -Path $TmpKey -Force | Out-Null
    New-ItemProperty -Path $TmpKey -Name ProxyEnable   -Value 0 -PropertyType DWord  -Force | Out-Null
    New-ItemProperty -Path $TmpKey -Name ProxyServer   -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $TmpKey -Name ProxyOverride -Value 'localhost;127.*' -PropertyType String -Force | Out-Null

    # ======================= N0 产物指纹 =======================
    Write-Host ''
    Add-Log '=== N0 产物指纹与字符串证据 ==='
    Case 'N0a' "SHA256 与交付基准一致（C65B591B…E36D）" ($shaStart -eq $ExpectSha) ("实际=$shaStart 期望=$ExpectSha 长度=$($i.Length) 改动于=$($i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))")

    $bytes = [IO.File]::ReadAllBytes($Exe)
    $enc = New-Object Text.UTF8Encoding($false, $false)
    $txt = $enc.GetString($bytes)
    function Count-Str { param($Hay, $Needle) return ([regex]::Matches($Hay, [regex]::Escape($Needle))).Count }
    Case 'N0b' '二进制里「未做自检」0 处（改前 1 处）' ((Count-Str $txt '未做自检') -eq 0) ("实际=$(Count-Str $txt '未做自检') 处")
    Case 'N0c' '二进制里「引擎进程不在」0 处（旧死分支的另一半文案）' ((Count-Str $txt '引擎进程不在') -eq 0) ("实际=$(Count-Str $txt '引擎进程不在') 处")
    Case 'N0d' '摘要行模板「通道自检跳过（」仍在（1 处）' ((Count-Str $txt '通道自检跳过（') -eq 1) ("实际=$(Count-Str $txt '通道自检跳过（') 处")
    Case 'N0e' '第五项文案「上没有监听」在产物里（1 处）' ((Count-Str $txt '上没有监听') -eq 1) ("实际=$(Count-Str $txt '上没有监听') 处")
    Case 'N0f' '页面 badInput 守卫在产物里（validity.badInput 至少 1 处）' ((Count-Str $txt 'validity.badInput') -ge 1) ("实际=$(Count-Str $txt 'validity.badInput') 处")

    # ======================= N1（第四轮改口径）+3 被占 → 动态端口 =======================
    # 【第四轮口径变更 2026-10-28】旧断言是「占住 +3 → 摘要行/结论行写『跳过（探测端口 X 被占用）』」。
    # 现在 plan_probe 在 +3 绑不上时回落到系统分配的空闲端口；「跳过」只剩「系统连一个空闲端口都
    # 分不出来」那一条路（运行时不可构造）。因此本段按新口径断言：
    #   ① connect 仍成功；② 结论是「未通过（经交易出口：探测端口 D 上没有监听…）」；
    #   ③ 全文不出现「跳过」；④ D（结论行报的端口）== runtime-engine.json 里 tc-check 的 listen_port，
    #      且 D ≠ +3 —— 这是本轮的关键不变量：引擎必须听在自检要拨的那个口上。
    # 原目标「摘要行带跳过原因」在可达路径上已不存在：改由产物字符串证据（N0d/N0e 等）与
    # selfcheck 单测覆盖，本段**不再声称**验证了「跳过带原因」。
    Write-Host ''
    Add-Log '=== N1（第四轮口径）+3 被占 → 动态端口：tc-check.listen_port == 自检拨的端口 ≠ +3 ==='
    $base = Find-FreePair 48300
    $probe = $base + 3
    $imp = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$base", '--line-name', 'r3-skip')
    Case 'N1a' "前置：导入线路（port $base，探测端口 $probe 导入时为空闲）" ($imp.Code -eq 0) ("退出码=$($imp.Code) 输出=$($imp.Out -replace '\s+',' ')")
    $h = Start-Holder -Port $probe -Tag 'n1'
    Case 'N1b' "前置：独立进程占住探测端口 $probe（可绑应为 False）" ($h.Ok -and -not (Test-PortFree $probe)) ("ready=$($h.Ok) 可绑=$(Test-PortFree $probe)")
    if ($h.Ok -and -not (Test-PortFree $probe)) {
        # 假引擎必须稳活：PING 在派生参数（run -c …）下靠 DNS 解析挂着，时序不稳，显式给 -n。
        $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        $o = RunTimed @('--connect')
        Stop-Holder $h
        [Environment]::SetEnvironmentVariable('SPIDERVPN_ENGINE_ARGS', $null)
        $lines = $o.Out -split "`r?`n"
        $dynPort = -1
        if ($o.Out -match '探测端口 (\d+) 上没有监听') { $dynPort = [int]$matches[1] }
        $tcPort = -1
        if (Test-Path $RtEng) {
            try {
                $j = Get-Content $RtEng -Raw -Encoding UTF8 | ConvertFrom-Json
                $tc = @($j.inbounds | Where-Object { $_.tag -eq 'tc-check' })
                if ($tc.Count -eq 1) { $tcPort = [int]$tc[0].listen_port }
            } catch { }
        }
        Case 'N1c' '摘要行写「通道自检未通过」（不再出现「跳过（探测端口 X 被占用）」）' `
            ($o.Code -eq 0 -and (@($lines | Where-Object { $_ -match '完成：' -and $_ -match '通道自检未通过' }).Count -ge 1)) `
            ("退出码=$($o.Code) 完成行=[$((@($lines | Where-Object { $_ -match '完成：' }) -join ' / '))]")
        Case 'N1d' '结论行是「通道自检（经交易出口）未通过：探测端口 D 上没有监听…」' `
            ($o.Out -match '（经交易出口）未通过：探测端口 \d+ 上没有监听') `
            ("结论行=[$((@($lines | Where-Object { $_ -match '通道自检' }) -join ' / '))]")
        Case 'N1e' '全文不出现「跳过」（+3 被占不再等于没验成）' ($o.Out -notmatch '跳过') ("输出=$($o.Out -replace '\s+',' ')")
        Case 'N1f' "关键不变量：结论行报的端口 D=$dynPort == 引擎配置 tc-check=$tcPort，且 D ≠ +3($probe)" `
            ($dynPort -gt 0 -and $dynPort -eq $tcPort -and $dynPort -ne $probe) `
            ("自检报的=$dynPort 引擎配置里的=$tcPort +3=$probe")
        Case 'N1g' '失败结论不得写成「通过（HTTP」' ($o.Out -notmatch '通过（HTTP') ("输出=$($o.Out -replace '\s+',' ')")
        $dis = RunTimed @('--disconnect')
        Case 'N1h' '收尾：断开成功（exit 0）' ($dis.Code -eq 0) ("退出码=$($dis.Code)")
    } else {
        Skip 'N1c' '第四轮口径：+3 被占 → 动态端口' '占位进程没起来或端口没被占住，本段无法构造「探测端口被占」'
        Stop-Holder $h
    }
    # ======================= N2 引擎秒退 =======================
    Write-Host ''
    Add-Log '=== N2 引擎秒退（引擎换 cmd.exe）==='
    Reset-Scen
    $b2 = Find-FreePair 48360
    $imp2 = RunTimed @('--import', $Fixture, '--engine', $DeadEngine, '--port', "$b2", '--line-name', 'r3-dead')
    Case 'N2a' "前置：导入秒退引擎线路（port $b2）" ($imp2.Code -eq 0) ("退出码=$($imp2.Code) 输出=$($imp2.Out -replace '\s+',' ')")
    $o2 = RunTimed @('--connect')
    Case 'N2b' '引擎秒退 → connect 当场失败（exit 13）且说明「引擎启动后立即退出」' `
        ($o2.Code -eq 13 -and $o2.Out -match '引擎启动后立即退出') ("退出码=$($o2.Code) 输出=$($o2.Out -replace '\s+',' ')")
    Case 'N2c' '引擎秒退 → 输出里不出现「跳过」' ($o2.Out -notmatch '跳过') ("输出=$($o2.Out -replace '\s+',' ')")
    Case 'N2d' '引擎秒退 → runtime-engine.json 不存在' (-not (Test-Path $RtEng)) ("存在=$((Test-Path $RtEng))")
    Case 'N2e' '引擎秒退 → 输出里不出现「未做自检」' ($o2.Out -notmatch '未做自检') ("输出=$($o2.Out -replace '\s+',' ')")

    # ======================= N6 Dial 计划的 NotListening 归因 =======================
    Write-Host ''
    Add-Log '=== N6 引擎活着但不监听探测端口：Dial 必须报「未通过：…上没有监听」，不得报「跳过/被占用」 ==='
    Reset-Scen
    $b6 = Find-FreePair 48700
    $p6 = $b6 + 3
    $imp6 = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$b6", '--line-name', 'r3-nolisten')
    Case 'N6a' "前置：导入线路（port $b6，探测端口 $p6 空闲）" ($imp6.Code -eq 0 -and (Test-PortFree $p6)) ("退出码=$($imp6.Code) 探测端口可绑=$(Test-PortFree $p6)")
    # 必须让假引擎活 300 秒（PING），否则 connect 会在「引擎启动后立即退出」处失败，走不到自检
    $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
    $o6 = RunTimed @('--connect')
    Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue
    $hasCred = $false
    if (Test-Path $Rt) { try { $jj = Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json; $hasCred = [bool]($jj.ProbeUser) -and [bool]($jj.ProbePass) } catch { } }
    Case 'N6b' '前提：plan 真的是 Dial（runtime.json 里写了 ProbeUser/ProbePass）' ($o6.Code -eq 0 -and $hasCred) ("退出码=$($o6.Code) 有凭据=$hasCred 输出=$($o6.Out -replace '\s+',' ')")
    Case 'N6c' 'Dial + 不监听 → 结论是「未通过：探测端口 N 上没有监听」' `
        ($o6.Out -match ('未通过：探测端口 ' + $p6 + ' 上没有监听')) ("输出=$($o6.Out -replace '\s+',' ')")
    Case 'N6d' 'Dial + 不监听 → 输出里不出现「跳过」' ($o6.Out -notmatch '跳过') ("输出=$($o6.Out -replace '\s+',' ')")
    Case 'N6e' 'Dial + 不监听 → 输出里不出现「被占用」' ($o6.Out -notmatch '被占用') ("输出=$($o6.Out -replace '\s+',' ')")
    Case 'N6f' 'Dial + 不监听 → 摘要行写「通道自检未通过」（不是跳过）' ($o6.Out -match '通道自检未通过') ("输出=$($o6.Out -replace '\s+',' ')")
    $lc = if (Test-Path $LastChk) { Get-Content $LastChk -Raw -Encoding UTF8 } else { '' }
    Case 'N6g' 'last-check.json 里 ok=false 且没有 skipped 字段值' ($lc -match '"ok":\s*false' -and $lc -notmatch '"skipped":\s*"') ("last-check=$($lc -replace '\s+',' ')")
    $engAlive6 = $false
    if (Test-Path $Rt) { try { $eid = (Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json).EnginePid; $engAlive6 = [bool](Get-Process -Id $eid -ErrorAction SilentlyContinue) } catch { } }
    Case 'N6h' 'Dial + 不监听 → 连接本身仍成立（runtime-engine.json 在、引擎在跑）' `
        ((Test-Path $RtEng) -and $engAlive6) ("runtime-engine.json=$((Test-Path $RtEng)) 引擎存活=$engAlive6")
    Case 'N6i' '收尾：断开成功（exit 0）' ((RunTimed @('--disconnect')).Code -eq 0) 'ok'

    # ======================= N3 界面导入端口（页面取自产物） =======================
    Write-Host ''
    Add-Log '=== N3 页面导入表单：逐字节取自产物内嵌 PAGE，Chromium 真实渲染执行 ==='
    if (-not (Test-Path $Edge)) {
        Skip 'N3' '界面端口用例整组' "本机没有 Edge：$Edge"
    } else {
        $pageStart = $txt.IndexOf('<!DOCTYPE html>')
        $pageEnd   = if ($pageStart -ge 0) { $txt.IndexOf('</html>', $pageStart) } else { -1 }
        $page = ''
        if ($pageStart -ge 0 -and $pageEnd -gt $pageStart) { $page = $txt.Substring($pageStart, $pageEnd - $pageStart + 7) }
        Case 'N3a' '能从产物里取出内嵌页面（PAGE）' ($page.Length -gt 10000 -and $page.Contains('id="port"')) ("长度=$($page.Length)")

        if ($page.Length -gt 10000) {
            $prof2 = Join-Path $ScenRoot 'profile.json'
            Copy-Item $Fixture $prof2 -Force
            $pJs = ($prof2 -replace '\\','\\\\')
            $eJs = ($FakeEngine -replace '\\','\\\\')
            $harness = @"
<script>
(function(){
  var R={},q=function(id){return document.getElementById(id);};
  window.__sent=[];
  window.ipc={postMessage:function(s){window.__sent.push(String(s));}};
  var p=q('port'), imp=document.querySelector('.imp'), cs=imp?getComputedStyle(imp):{};
  R.hasPort=!!p; R.type=p?p.type:null; R.min=p?p.getAttribute('min'):null; R.max=p?p.getAttribute('max'):null;
  R.ph=p?p.getAttribute('placeholder'):null; R.title=p?p.getAttribute('title'):null;
  R.wrap=cs.flexWrap; R.kids=imp?imp.children.length:-1; R.kidIds=[];
  if(imp){for(var i=0;i<imp.children.length;i++){R.kidIds.push(imp.children[i].id||imp.children[i].tagName);}}
  q('profile').value='$pJs'; q('engine').value='$eJs'; q('mode').value='proxy';
  function run(name,portVal,ln){
    q('linename').value=ln; q('port').value=portVal;
    var before=window.__sent.length; q('msg').textContent='';
    var b=q('doImport'); b.disabled=false; b.click();
    R[name]={portValue:q('port').value,sent:window.__sent.slice(before),msg:q('msg').textContent,disabled:b.disabled};
  }
  run('empty','','r3-empty');
  run('p17890','17890','r3-p17890');
  run('pmax','65532','r3-pmax');
  run('zero','0','r3-zero');
  run('over','65533','r3-over');
  run('float','1.5','r3-float');
  run('neg','-1','r3-neg');
  run('exp','1e5','r3-exp');
  // 「键入」而不是直接赋 .value：只有走浏览器编辑管线才会置 validity.badInput
  // （实测：e / - / . 这类部分合法字符 → value='' 且 badInput=true；纯字母被浏览器丢弃 → badInput=false）
  function typed(name,txt){
    p.value=''; p.focus();
    try{ document.execCommand('insertText',false,txt); }catch(e){}
    var bad=!!p.validity.badInput, v=p.value;
    var before=window.__sent.length; q('msg').textContent=''; q('linename').value='r3-'+name;
    var b=q('doImport'); b.disabled=false; b.click();
    R[name]={typed:txt,value:v,bad:bad,sent:window.__sent.slice(before),msg:q('msg').textContent};
  }
  typed('badE','e');
  typed('badMinus','-');
  typed('letters','abc');
  var pre=document.createElement('pre'); pre.id='__r3'; pre.textContent=JSON.stringify(R); document.body.appendChild(pre);
})();
</script>
</body>
"@
            $htmlPath = Join-Path $ScenRoot 'page-under-test.html'
            [IO.File]::WriteAllText($htmlPath, $page.Replace('</body>', $harness), (New-Object Text.UTF8Encoding($false)))
            $d = Get-DomDump $htmlPath
            $m = [regex]::Match($d.Dom, '(?s)<pre id="__r3">(.*?)</pre>')
            $R = $null
            if ($m.Success) { try { $R = ([System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)) | ConvertFrom-Json } catch { } }
            Case 'N3b' '在 Chromium 里加载页面并拿到自检结果块' ([bool]$R) ("退出码=$($d.Code) 结果块=$(if($m.Success){'有'}else{'无'}) stderr=$($d.Err -replace '\s+',' ')")

            if ($R) {
                Case 'N3c' '页面有端口输入框：type=number，min=1 / max=65532，placeholder=17890' `
                    ($R.hasPort -and $R.type -eq 'number' -and $R.min -eq '1' -and $R.max -eq '65532' -and $R.ph -eq '17890') `
                    ("port 元素：type=$($R.type) min=$($R.min) max=$($R.max) placeholder=$($R.ph) title=$($R.title)")
                Case 'N3d' '.imp 是 flex-wrap，六样控件同容器（多一个端口框也不压坏线路名）' `
                    ($R.wrap -eq 'wrap' -and $R.kids -eq 6 -and (@($R.kidIds) -contains 'port')) `
                    ("flexWrap=$($R.wrap) 子元素数=$($R.kids) ids=[$(@($R.kidIds) -join ',')]")

                $sentEmpty = @($R.empty.sent)
                Case 'N3e' '留空点击：发出一条 import 命令，且命令里**没有** port 字段' `
                    ($sentEmpty.Count -eq 1 -and $sentEmpty[0] -match '"cmd":"import"' -and $sentEmpty[0] -notmatch '"port"') `
                    ("命令数=$($sentEmpty.Count) 内容=$(if($sentEmpty.Count -gt 0){$sentEmpty[0]}else{'(无)'})")

                $s17890 = @($R.p17890.sent)
                Case 'N3f' '填 17890：发命令且带 "port":17890' `
                    ($s17890.Count -eq 1 -and $s17890[0] -match '"port":17890') `
                    ("命令数=$($s17890.Count) 内容=$(if($s17890.Count -gt 0){$s17890[0]}else{'(无)'})")

                $sMax = @($R.pmax.sent)
                Case 'N3g' '填 65532（上边界）：发命令且带 "port":65532' `
                    ($sMax.Count -eq 1 -and $sMax[0] -match '"port":65532') `
                    ("命令数=$($sMax.Count) 内容=$(if($sMax.Count -gt 0){$sMax[0]}else{'(无)'})")

                $badCells = @(
                    @{ Id = 'N3h'; Key = 'zero';  V = '0' },
                    @{ Id = 'N3i'; Key = 'over';  V = '65533' },
                    @{ Id = 'N3j'; Key = 'float'; V = '1.5' },
                    @{ Id = 'N3k'; Key = 'neg';   V = '-1' },
                    @{ Id = 'N3l'; Key = 'exp';   V = '1e5' }
                )
                foreach ($bc in $badCells) {
                    $cell = $R.($bc.Key)
                    Case $bc.Id "填「$($bc.V)」：页面黄字提示且**不发命令**" `
                        (@($cell.sent).Count -eq 0 -and $cell.msg -match '端口要填 1~65532 的整数') `
                        ("输入框取值=[$($cell.portValue)] 命令数=$(@($cell.sent).Count) msg=[$($cell.msg)]")
                }

                # ---- badInput：控件里「看着有字、value 却是空串」的那条路（本轮第五项前的坑）----
                $tE = $R.badE
                Case 'N3m' '键入「e」：控件进入 badInput（value 为空但 badInput=true）' `
                    ($tE -and $tE.bad -eq $true -and $tE.value -eq '') `
                    ("键入后：value=[$($tE.value)] badInput=$($tE.bad)")
                Case 'N3n' 'badInput 时点导入：黄字提示且**不发命令**（不再静默回落 17890）' `
                    ($tE -and @($tE.sent).Count -eq 0 -and $tE.msg -match '端口要填 1~65532 的整数') `
                    ("命令数=$(@($tE.sent).Count) msg=[$($tE.msg)]")
                $tM = $R.badMinus
                Case 'N3o' '键入「-」：同样 badInput → 提示且不发命令' `
                    ($tM -and $tM.bad -eq $true -and @($tM.sent).Count -eq 0 -and $tM.msg -match '端口要填 1~65532 的整数') `
                    ("value=[$($tM.value)] badInput=$($tM.bad) 命令数=$(@($tM.sent).Count) msg=[$($tM.msg)]")
                $tL = $R.letters
                Case 'N3p' '键入「abc」：浏览器把字母整个丢弃（value=""、badInput=false）→ 按留空处理，命令里不带 port（绝不传非法值）' `
                    ($tL -and $tL.value -eq '' -and $tL.bad -eq $false -and
                     (@($tL.sent).Count -eq 0 -or (@($tL.sent | Where-Object { $_ -match '"port"' }).Count -eq 0))) `
                    ("value=[$($tL.value)] badInput=$($tL.bad) 命令=$(if(@($tL.sent).Count -gt 0){@($tL.sent)[-1]}else{'(无)'}) msg=[$($tL.msg)]")
            }

        }
    }

    # ======================= N5 宿主侧端口回落/采纳 =======================
    Write-Host ''
    Add-Log '=== N5 宿主侧：不给端口 = 17890 / 给端口 = 用该端口（CLI 与界面共用 import_profile）==='
    Reset-Scen
    $okDef = (Test-PortFree 17890) -and (Test-PortFree 17893)
    if (-not $okDef) {
        Skip 'N5a' '不给端口 → 端点 127.0.0.1:17890' '17890/17893 不是都空闲'
    } else {
        $impD = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--line-name', 'r3-defaultport')
        $txtD = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '' }
        Case 'N5a' '--import 不给 --port → 端点落到 127.0.0.1:17890（界面留空的回落值）' `
            ($impD.Code -eq 0 -and $txtD -match '127\.0\.0\.1:17890') `
            ("退出码=$($impD.Code) 配置含17890=$([bool]($txtD -match '127\.0\.0\.1:17890')) 输出=$($impD.Out -replace '\s+',' ')")
    }
    $b5 = Find-FreePair 48420
    $impP = RunTimed @('--import', $Fixture, '--engine', $FakeEngine, '--port', "$b5", '--line-name', 'r3-givenport')
    $txtP = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '' }
    Case 'N5b' "--import 给 --port $b5 → 端点就是 127.0.0.1:$b5（填了就采纳）" `
        ($impP.Code -eq 0 -and $txtP -match ('127\.0\.0\.1:' + $b5)) `
        ("退出码=$($impP.Code) 配置含$($b5)=$([bool]($txtP -match ('127\.0\.0\.1:' + $b5)))")

    # ======================= N4 三项复核 =======================
    Write-Host ''
    Add-Log '=== N4 三项复核（默认根只读 / 真实代理零写入 / 产物稳定） ==='
    Reset-Scen
    Case 'N4a' '真实系统代理三元组前后完全一致' ($realBefore -eq (Snap3 $RealKey)) ("前=$realBefore 后=$(Snap3 $RealKey)")
    $defaultAfter = Get-Manifest $DefaultData
    Case 'N4b' '用户默认根零写入（文件清单 长度/mtime 全一致）' `
        ((($defaultBefore -join ';') -eq ($defaultAfter -join ';'))) ("前=[$($defaultBefore -join ',')] 后=[$($defaultAfter -join ',')]")
    $shaEnd = (Get-FileHash $Exe -Algorithm SHA256).Hash
    Case 'N4c' '产物稳定：收尾 SHA256 与开头一致（且 == 交付基准）' ($shaEnd -eq $shaStart -and $shaEnd -eq $ExpectSha) ("开头=$shaStart 结尾=$shaEnd 基准=$ExpectSha")
    $r1 = @(Get-Process sing-box -ErrorAction SilentlyContinue).Count
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) { Start-Sleep -Seconds 1 }
    Case 'N4d' '零残留：无 spidervpn / sing-box 进程' `
        ((@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) -and (@(Get-Process sing-box -ErrorAction SilentlyContinue).Count -eq 0)) `
        ("spidervpn=$(@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count) sing-box=$(@(Get-Process sing-box -ErrorAction SilentlyContinue).Count)（收尾前 sing-box=$r1）")
}
catch {
    Add-Log ("异常：{0}" -f $_.Exception.Message)
    Add-Log ($_.ScriptStackTrace)
}
finally {
    Cleanup
    Remove-Item $Hold -Force -ErrorAction SilentlyContinue
    $script:log += ("TOTAL PASS={0} FAIL={1} SKIP={2}  SHA={3}" -f $script:pass, $script:fail, $script:skip, $shaStart)
    try { [IO.File]::WriteAllText($LogPath, (($script:log -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false))) } catch { }
}

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
Write-Host ("明细：{0}" -f $LogPath)
if ($script:fail -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }
exit 0
