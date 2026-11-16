#requires -Version 5.1
# 第二轮集成核验 · 独占段 B：界面/管道路径（item 5 两路径一致 + item 6 措辞同源 + 新增两处互斥/自愈）
#
# 覆盖：
#   G2 只读命令旁路单实例互斥（--status/--lines/--exits/--plan/--headless 在界面运行时 exit 0）
#   G3 反方向：--restore 仍 exit 4（证明互斥没被整体删掉）
#   G4 不持锁不自愈：界面在跑时 --status 不得自愈、不得删 last-cleanup-error.txt
#   G5 item6 + D8 界面路径：连上但自检未通过 → 管道 title 与 CLI --status 同一句话
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tests\round2-exclusive-b.ps1

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Exe      = 'C:\SpiderVPN\bin\spidervpn.exe'
$UserData = 'C:\SpiderVPN\data'
$ScenRoot = Join-Path $env:TEMP ('tc-excl-b-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Rt       = Join-Path $Data 'runtime.json'
$RtEng    = Join-Path $Data 'runtime-engine.json'
$Jn       = Join-Path $Data 'proxy-journal.json'
$ErrTxt   = Join-Path $Data 'last-cleanup-error.txt'
$LogPath  = Join-Path $env:TEMP ('tc-excl-b-log-' + $PID + '.txt')

$env:SPIDERVPN_ROOT = $ScenRoot
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\integr-r2b'
$env:SPIDERVPN_RUN_KEY   = 'Software\SpiderVPN\tests\run-r2b'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY
Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue

# 用户可能正开着 旧版的 TUN——它的引擎也叫 sing-box.exe。先记下"不是我起的"那几个 pid：
# 清理只杀我起的，否则一次核验就会把用户的网拔掉。
$script:foreignEngine = @(Get-Process sing-box -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })

$script:pass = 0; $script:fail = 0; $script:skip = 0; $script:log = @()
function Add-Log { param($L) $script:log += $L; Write-Host $L }
function Case { param($Id,$Desc,$Ok,$Actual)
    if ($Ok) { $script:pass++; Add-Log ("PASS  {0}  {1}" -f $Id,$Desc) }
    else { $script:fail++; Add-Log ("FAIL  {0}  {1} :: {2}" -f $Id,$Desc,$Actual) } }
function Skip { param($Id,$Desc,$Why) $script:skip++; Add-Log ("SKIP  {0}  {1} :: {2}" -f $Id,$Desc,$Why) }

function Snap3 { param($P)
    $x = Get-ItemProperty -Path $P -ErrorAction SilentlyContinue
    if (-not $x) { return '(键不存在)' }
    return ('{0}|{1}|{2}' -f $x.ProxyEnable, $x.ProxyServer, $x.ProxyOverride) }

function New-Runner { param($ArgList)
    $out = Join-Path $env:TEMP ('r2b-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bat = Join-Path $env:TEMP ('r2b-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $argStr = (($ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    Set-Content -Path $bat -Encoding OEM -Value ("@echo off`r`n`"$Exe`" $argStr > `"$out`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c "' + $bat + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    return [pscustomobject]@{ Bat = $bat; OutFile = $out; Psi = $psi } }

function Read-OutFile { param($P)
    try { $fs = [IO.File]::Open($P,'Open','Read','ReadWrite'); $sr = New-Object IO.StreamReader($fs,[Text.Encoding]::UTF8); $t = $sr.ReadToEnd(); $sr.Close(); $fs.Close(); return $t } catch { return '' } }

function Run { param($ArgList, [int]$TimeoutMs = 60000)
    $r = New-Runner $ArgList
    $p = [Diagnostics.Process]::Start($r.Psi)
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Code = -9; Out = '（超时）' } }
    $t = Read-OutFile $r.OutFile
    Remove-Item $r.Bat, $r.OutFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $t } }

function Pipe-Cmd { param($Name, $Json)
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut)
    $c.Connect(4000)
    $sw = New-Object System.IO.StreamWriter($c, (New-Object System.Text.UTF8Encoding($false)))
    $sw.AutoFlush = $true
    $sw.WriteLine($Json)
    $sr = New-Object System.IO.StreamReader($c)
    $line = $sr.ReadLine()
    $sw.Dispose(); $sr.Dispose(); $c.Dispose()
    return $line }

# 管道名 = "SpiderVPN." + FNV-1a64(数据根)。界面**不写日志**（实测 data\logs 为空，
# 只有 --headless 才打印管道名），自己算又在 PowerShell 里踩了 BigInteger 补码/取模的坑，
# 所以改用最笨也最可靠的办法：**起界面前先记下已有管道，起完再差集**——安静的窗口里新出现的那个就是我的。
function Get-RsPipes {
    # 注意：不要把 '\\.\pipe\Xxx' 丢给 Split-Path -Leaf（它按盘符/UNC 解析，会返回空串，
    # 症状是"管道名拿到空字符串"，看着像界面没建管道）。直接用正则取名字。
    $names = @()
    foreach ($f in [System.IO.Directory]::GetFiles('\\.\pipe\')) {
        if ($f -match '(SpiderVPN\.[0-9a-fA-F]+)$') { $names += $Matches[1] }
    }
    return $names }

function Wait-NewPipe { param($Before, [int]$Seconds = 30)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        foreach ($n in (Get-RsPipes)) { if ($Before -notcontains $n) { return $n } }
        Start-Sleep -Milliseconds 300
    }
    return $null }

# ---------- 守卫 ----------
if (-not (Test-Path $Exe)) { Write-Host "FAIL G0 被测程序不存在"; exit 1 }
$waited = 0
while ($waited -lt 90) {
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { Start-Sleep -Milliseconds 1500; if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { break } }
    Start-Sleep -Seconds 1; $waited += 1 }
if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) { Write-Host 'SKIP 等不到空闲窗口'; exit 2 }

$i = Get-Item $Exe
Add-Log ("被测产物：{0}  {1:N0} 字节  改动于 {2}" -f $Exe, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
Add-Log ("SHA256  ：{0}" -f (Get-FileHash $Exe -Algorithm SHA256).Hash)

$gui = $null
function Cleanup {
    if ($gui -and -not $gui.HasExited) { try { $gui.Kill() } catch { } }
    try { New-Runner @('--disconnect') | Out-Null } catch { }
    foreach ($f in @($RtEng, $Rt)) {
        if (Test-Path $f) { try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.EnginePid) { Stop-Process -Id $j.EnginePid -Force -ErrorAction SilentlyContinue } } catch { } } }
    foreach ($p in @(Get-Process sing-box -ErrorAction SilentlyContinue)) {
        if ($script:foreignEngine -notcontains $p.Id) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path $ScenRoot) { Remove-Item $ScenRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:SPIDERVPN_RUN_KEY -ErrorAction SilentlyContinue }

Cleanup
New-Item -ItemType Directory -Path (Join-Path $Data 'lines') -Force | Out-Null
New-Item -Path $TmpKey -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyEnable   -Value 0 -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyServer   -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyOverride -Value 'localhost;127.*' -PropertyType String -Force | Out-Null

# 真线路副本（真引擎、真节点），并把交易出口换成必然不通的成员 → 连上但自检未通过
Copy-Item (Join-Path $UserData 'config.json') (Join-Path $Data 'config.json') -Force
Get-ChildItem (Join-Path $UserData 'lines') -File | ForEach-Object { Copy-Item $_.FullName (Join-Path (Join-Path $Data 'lines') $_.Name) -Force }

try {
    Write-Host ''
    Add-Log '=== G0 先改交易出口（必须在起界面之前：--exit-set 是写命令，界面起来后会 exit 4）==='
    $r0 = Run @('--exit-set','trade','provider2-trade')
    Case 'G0a' '交易出口换成必然不通的成员 provider2-trade' ($r0.Code -eq 0 -and $r0.Out -match 'provider2-trade') ("退出码=$($r0.Code) 输出=$($r0.Out -replace '\s+',' ')")
    $r0b = Run @('--exits')
    Case 'G0b' '--exits 确认交易出口已是 provider2-trade' ($r0b.Out -match 'provider2-trade') ("输出=$($r0b.Out -replace '\s+',' ')")

    Write-Host ''
    Add-Log '=== G1 起界面并拿到控制管道 ==='
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe; $psi.Arguments = ''; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $false
    $pipesBefore = Get-RsPipes
    $gui = [Diagnostics.Process]::Start($psi)
    $pipe = Wait-NewPipe $pipesBefore 30
    Case 'G1a' '界面进程存活' (-not $gui.HasExited) ("pid=$($gui.Id) exited=$($gui.HasExited)")
    Case 'G1b' "起界面后新出现一个控制管道（$pipe）" ([bool]$pipe) ("管道=$pipe 起前已有=[$($pipesBefore -join ',')]")
    if (-not $pipe) { throw '拿不到控制管道，界面路径无法验证' }
    $p = Run @('--ping')
    Case 'G1c' '--ping 返回控制接口可用（exit 0）' ($p.Code -eq 0 -and $p.Out -match '控制接口可用') ("退出码=$($p.Code) 输出=$($p.Out -replace '\s+',' ')")

    Write-Host ''
    Add-Log '=== G2 新增①：只读命令旁路单实例互斥（界面在跑时应 exit 0）==='
    foreach ($cmd in @('--status','--lines','--exits','--plan','--headless')) {
        $r = Run @($cmd)
        Case ("G2" + $cmd) "$cmd 在界面运行时 exit 0" ($r.Code -eq 0) ("退出码=$($r.Code) 输出=$($r.Out -replace '\s+',' ')")
    }

    Write-Host ''
    Add-Log '=== G3 反方向：--restore 仍独占（exit 4），证明互斥没被整体删掉 ==='
    $r = Run @('--restore')
    Case 'G3' '--restore 在界面运行时 exit 4（独占语义保留）' ($r.Code -eq 4) ("退出码=$($r.Code) 输出=$($r.Out -replace '\s+',' ')")

    Write-Host ''
    Add-Log '=== G4 新增②：界面在跑时 --status 不得自愈、不得删启动记录 ==='
    $snapBefore = Snap3 $TmpKey
    $deadPid = 999999
    $stale = @{ EnginePid = $deadPid; ProbeUser = 'x'; ProbePass = 'y'; ProxyEnable = 1; ProxyServer = '127.0.0.1:17890' } | ConvertTo-Json
    [IO.File]::WriteAllText($Rt, $stale, (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($Jn, '{"ProxyEnable":0,"ProxyServer":"127.0.0.1:7897"}', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($ErrTxt, '上次退出未完成清理（核验用样本）', (New-Object Text.UTF8Encoding($false)))
    $r = Run @('--status')
    $snapAfter = Snap3 $TmpKey
    Case 'G4a' '界面在跑时 --status 不改系统代理（自愈未被触发）' ($snapBefore -eq $snapAfter) ("前=$snapBefore 后=$snapAfter 输出=$($r.Out -replace '\s+',' ')")
    Case 'G4b' 'proxy-journal.json 仍在（没被自愈消费）' (Test-Path $Jn) ("存在=$((Test-Path $Jn))")
    Case 'G4c' 'runtime.json 仍在（残留凭据没被清）' (Test-Path $Rt) ("存在=$((Test-Path $Rt))")
    Case 'G4d' 'last-cleanup-error.txt 仍在（take_startup_issue 未被调用）' (Test-Path $ErrTxt) ("存在=$((Test-Path $ErrTxt))")
    Remove-Item $Rt,$Jn,$ErrTxt -Force -ErrorAction SilentlyContinue

    Write-Host ''
    Add-Log '=== G5 item6 + D8 界面路径：连上但自检未通过，两处同一句话 ==='
    $c1 = Pipe-Cmd $pipe '{"cmd":"connect"}'
    Add-Log ('     connect 应答 → ' + $c1)
    Start-Sleep -Milliseconds 800
    $engOn = Test-Path $RtEng
    # 引擎 pid 在 runtime.json（EnginePid）；runtime-engine.json 是**引擎配置**，里面没有 pid。
    $engPid = $null
    if (Test-Path $Rt) { try { $engPid = (Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json).EnginePid } catch { } }
    $engAlive = ($engPid -and (Get-Process -Id $engPid -ErrorAction SilentlyContinue))
    Case 'G5b' '界面路径连接后 runtime-engine.json 存在且引擎确实在跑（口径 A）' ($engOn -and [bool]$engAlive) ("文件=$engOn 引擎pid=$engPid 存活=$([bool]$engAlive)")
    $st = Pipe-Cmd $pipe '{"cmd":"status"}'
    Add-Log ('     status 应答 → ' + $st)
    Case 'G5c' '管道 status 的 title = 已连接（通道未通）' ($st -match '已连接（通道未通）') ("应答=$st")
    $cli = Run @('--status')
    $stLine = ($cli.Out -split "`r?`n" | Where-Object { $_ -match '^\s*状态' } | Select-Object -First 1)
    Add-Log ("     CLI --status 状态行：{0}" -f "$stLine".Trim())
    Case 'G5d' 'item6：界面在跑时 CLI --status 与管道同词（已连接（通道未通））' ($cli.Code -eq 0 -and "$stLine" -match '已连接（通道未通）') ("退出码=$($cli.Code) 状态行=$("$stLine".Trim())")
    Case 'G5e' '两路径口径一致：CLI 与管道都判「连接在运行」（文件在、引擎在）' ($engOn -and [bool]$engAlive -and $cli.Code -eq 0) 'ok'
    $d = Pipe-Cmd $pipe '{"cmd":"disconnect"}'
    Add-Log ('     disconnect 应答 → ' + $d)
    Start-Sleep -Milliseconds 500
    Case 'G5f' '断开后 runtime-engine.json 消失（两条路径同一收尾函数）' (-not (Test-Path $RtEng)) ("存在=$((Test-Path $RtEng))")
}
catch {
    Add-Log ("异常：{0}" -f $_.Exception.Message)
}
finally {
    Cleanup
    $script:log += ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    try { [IO.File]::WriteAllText($LogPath, (($script:log -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false))) } catch { }
}

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
Write-Host ("明细：{0}" -f $LogPath)
if ($script:fail -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }
exit 0
