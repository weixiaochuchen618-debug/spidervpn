#requires -Version 5.1
# 第二轮集成核验 · 独占段 A：真引擎端到端（item 4 落盘口径 + A/C/D/E 回归 + 引擎秒退）
#
# 前置：另一个 spidervpn 实例必须为 0（本脚本自己也守这条）。
# 用**用户那条真线路的只读副本**（config.json + lines\____.json）连真实节点，
# 全程临时根 + 临时代理键，默认数据根与真实系统代理零写入。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tests\round2-exclusive-a.ps1

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Exe       = 'C:\SpiderVPN\bin\spidervpn.exe'
$UserData  = 'C:\SpiderVPN\data'
$DefaultData = 'C:\SpiderVPN\data'
$SingBox   = 'C:\tradechannel\assets\sing-box.exe'
$DeadEngine = 'C:\Windows\System32\cmd.exe'

$ScenRoot = Join-Path $env:TEMP ('tc-excl-a-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Cfg      = Join-Path $Data 'config.json'
$Rt       = Join-Path $Data 'runtime.json'
$RtEng    = Join-Path $Data 'runtime-engine.json'
$Jn       = Join-Path $Data 'proxy-journal.json'
$LastCheck = Join-Path $Data 'last-check.json'
$LogPath  = Join-Path $env:TEMP ('tc-excl-a-log-' + $PID + '.txt')

$env:SPIDERVPN_ROOT = $ScenRoot
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\integr-r2a'
$env:SPIDERVPN_RUN_KEY   = 'Software\SpiderVPN\tests\run-r2a'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY
Remove-Item Env:SPIDERVPN_ENGINE_ARGS -ErrorAction SilentlyContinue

$RealKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

# 用户可能正开着 旧版的 TUN——它的引擎**也叫 sing-box.exe**。
# 所以跑之前先记下"不是我起的"那几个 pid：清理只杀我起的那些。
# 旧写法 `Get-Process sing-box | Stop-Process -Force` 会顺手拔掉用户正在用的网，
# 而且 X6b/X8c 的"零残留"还会因为用户那个进程而假红。
$script:foreignEngine = @(Get-Process sing-box -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
function Count-MyEngine {
    return @(Get-Process sing-box -ErrorAction SilentlyContinue | Where-Object { $script:foreignEngine -notcontains $_.Id }).Count
}

$script:pass = 0; $script:fail = 0; $script:skip = 0; $script:log = @()
function Add-Log { param($L) $script:log += $L; Write-Host $L }
function Case { param($Id,$Desc,$Ok,$Actual)
    if ($Ok) { $script:pass++; Add-Log ("PASS  {0}  {1}" -f $Id,$Desc) }
    else { $script:fail++; Add-Log ("FAIL  {0}  {1} :: {2}" -f $Id,$Desc,$Actual) } }
function Skip { param($Id,$Desc,$Why) $script:skip++; Add-Log ("SKIP  {0}  {1} :: {2}" -f $Id,$Desc,$Why) }

function Snap3 { param($Path)
    $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if (-not $p) { return '(键不存在)' }
    return ('{0}|{1}|{2}' -f $p.ProxyEnable, $p.ProxyServer, $p.ProxyOverride) }

function Get-Manifest { param($Root)
    $i = @()
    $i += @(Get-ChildItem $Root -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
    if (Test-Path (Join-Path $Root 'lines')) {
        $i += @(Get-ChildItem (Join-Path $Root 'lines') -File -ErrorAction SilentlyContinue | ForEach-Object { "lines\$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) }
    return @($i | Sort-Object) }

# 关键：不能用管道捕获输出。--connect 拉起的引擎会**继承 stdout 写端**，管道要等引擎退出才 EOF，
# 于是「连接成功、引擎还在跑」时读到的永远是空字符串（第一版就栽在这里：X2c/X4a/X5b 全假红，
# 因为把"没读到输出"当成了"产品没输出那句话"）。改成 cmd 重定向到文件，读文件。
function RunTimed { param($ArgList, [int]$TimeoutMs = 90000)
    $out = Join-Path $env:TEMP ('r2a-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bat = Join-Path $env:TEMP ('r2a-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $argStr = (($ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    Set-Content -Path $bat -Encoding OEM -Value ("@echo off`r`n`"$Exe`" $argStr > `"$out`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c "' + $bat + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; $sw.Stop(); return [pscustomobject]@{ Code=-9; Out='（超时）'; Ms=$sw.ElapsedMilliseconds } }
    $sw.Stop()
    $txt = ''
    # 用 FileShare.ReadWrite 读：连接成功时引擎进程**继承着这个文件句柄**，
    # 默认共享模式下 ReadAllText 会因共享冲突抛异常 → 又被 catch 成空串（第二版就栽在这，
    # 症状是"只有失败路径有输出、成功路径全空"）。
    try {
        $fs = [System.IO.File]::Open($out, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        $txt = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
    } catch { $txt = '（读输出失败：' + $_.Exception.Message + '）' }
    Remove-Item $bat,$out -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code=$p.ExitCode; Out=$txt; Ms=$sw.ElapsedMilliseconds } }

function Stop-Engines {
    foreach ($f in @($RtEng,$Rt)) {
        if (Test-Path $f) { try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.EnginePid) { Stop-Process -Id $j.EnginePid -Force -ErrorAction SilentlyContinue } } catch { } } }
    foreach ($p in @(Get-Process sing-box -ErrorAction SilentlyContinue)) {
        if ($script:foreignEngine -notcontains $p.Id) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    } }

function Remove-TempOnly { param($Path)
    if (-not $Path) { return }
    $full = [System.IO.Path]::GetFullPath($Path).ToLower()
    if ($full.StartsWith('c:\tradechannelrs\data') -and $full -eq 'c:\tradechannelrs\data') { throw "拒绝删除用户数据根：$Path" }
    if (Test-Path $full) { Remove-Item $full -Recurse -Force -ErrorAction SilentlyContinue } }

function Cleanup {
    # 尽力断开（会还原临时键里的代理），再杀引擎、删临时根与临时键
    try { RunTimed @('--disconnect') 30000 | Out-Null } catch { }
    Stop-Engines
    Remove-TempOnly $ScenRoot
    Remove-Item Env:SPIDERVPN_RUN_KEY -ErrorAction SilentlyContinue
    if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue } }

function Test-PortFree { param([int]$Port)
    $l = $null
    try { $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port); $l.Start(); return $true }
    catch { return $false } finally { if ($l) { try { $l.Stop() } catch { } } } }

function Lock-Port { param([int]$Port)
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port); $l.Start(); return $l }

function Release-Lock { param($L) if ($L) { try { $L.Stop() } catch { } } }

function CurlIp { param([string[]]$CurlArgs)
    $out = & curl.exe @CurlArgs 2>&1 | Out-String
    $ip = ($out -split "`r?`n" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
    return [pscustomobject]@{ Ip = "$ip".Trim(); Raw = ($out -replace '\s+',' ') } }

# ---------- 守卫 ----------
if (-not (Test-Path $Exe)) { Write-Host "FAIL G0 被测程序不存在"; exit 1 }
if (-not (Test-Path $SingBox)) { Write-Host "SKIP G0 真引擎不存在：$SingBox"; exit 2 }
if (-not (Test-Path (Join-Path $UserData 'lines'))) { Write-Host "SKIP G0 用户线路目录不存在，无法做真引擎段"; exit 2 }
if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Host "SKIP 检测到另一个 spidervpn 实例在跑：本轮不硬跑。"; Remove-TempOnly $ScenRoot; exit 2 }

$i = Get-Item $Exe
Add-Log ("被测产物：{0}  {1:N0} 字节  改动于 {2}" -f $Exe, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
Add-Log ("SHA256  ：{0}" -f (Get-FileHash $Exe -Algorithm SHA256).Hash)

$realBefore = Snap3 $RealKey
$defaultBefore = Get-Manifest $DefaultData

Cleanup
New-Item -ItemType Directory -Path (Join-Path $Data 'lines') -Force | Out-Null
New-Item -Path $TmpKey -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyEnable   -Value 0 -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyServer   -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyOverride -Value 'localhost;127.*' -PropertyType String -Force | Out-Null

# 真线路：用户 config.json + lines\*.json 的只读副本（不 import、不改用户文件）
Copy-Item (Join-Path $UserData 'config.json') $Cfg -Force
Get-ChildItem (Join-Path $UserData 'lines') -File | ForEach-Object { Copy-Item $_.FullName (Join-Path (Join-Path $Data 'lines') $_.Name) -Force }

try {
    Write-Host ''
    Add-Log '=== X1 前置：真线路副本与端口 ==='
    $o = RunTimed @('--lines')
    Case 'X1a' '复制用户线路后 --lines 能读到（示例线路）' ($o.Code -eq 0 -and $o.Out -match '示例线路') ("退出码=$($o.Code) 输出=$($o.Out -replace '\s+',' ')")
    $mixedOk = Test-PortFree 17890
    $probeOk = Test-PortFree 17893
    if (-not ($mixedOk -and $probeOk)) { Skip 'X1b' '17890/17893 空闲' "混合端口空闲=$mixedOk 探测端口空闲=$probeOk（被占则本段无法执行）"; throw '端口被占' }
    Case 'X1b' '混合端口 17890 与探测端口 17893 均空闲（避免"产品正确拒绝"造成假红）' $true 'ok'

    Write-Host ''
    Add-Log '=== X2 CLI 路径：真引擎连接 → 自检 204 → 落盘 ==='
    $o = RunTimed @('--connect')
    $eng = Count-MyEngine
    $engOn = Test-Path $RtEng
    Case 'X2a' '--connect 成功（exit 0）且引擎进程在跑' ($o.Code -eq 0 -and $eng -ge 1) ("退出码=$($o.Code) sing-box=$eng 输出=$($o.Out -replace '\s+',' ')")
    Add-Log ("     自检结论：{0}" -f (($o.Out -split "`r?`n" | Where-Object { $_ -match '通道自检' }) -join ' / '))
    Case 'X2b' 'runtime-engine.json 存在（口径：连接正在运行 ⇒ 文件在）' $engOn ("存在=$engOn")
    Case 'X2c' 'B 段：通道自检经交易出口通过（HTTP 204）' ($o.Out -match '通过（HTTP 204') ("输出=$($o.Out -replace '\s+',' ')")

    Write-Host ''
    Add-Log '=== X3 A 段：经代理出口 IP == 真直连 IP（curl -4 强制 IPv4）==='
    $viaProxy = CurlIp @('-4','-s','--max-time','25','-x','http://127.0.0.1:17890','https://ifconfig.me/ip')
    $direct   = CurlIp @('-4','-s','--max-time','25','--noproxy','*','https://ifconfig.me/ip')
    Add-Log ("     经 mixed(17890) → {0}" -f $viaProxy.Raw)
    Add-Log ("     真直连(-4,--noproxy) → {0}" -f $direct.Raw)
    if ($viaProxy.Ip -and $direct.Ip) {
        Case 'X3' "A 段：两条独立路径给出同一 IPv4（$($viaProxy.Ip)）" ($viaProxy.Ip -eq $direct.Ip) ("经代理=$($viaProxy.Ip) 直连=$($direct.Ip)")
    } else {
        Skip 'X3' 'A 段出口 IP 比对' "取不到出口 IP（经代理=$($viaProxy.Ip) 直连=$($direct.Ip)），网络不可达时不判结论"
    }

    Write-Host ''
    Add-Log '=== X4 D 段（第四轮改口径）：探测端口被占 → 回落动态端口，仍须「通过(204)」，不得出现「跳过」==='
    # 【第四轮口径变更 2026-10-28】旧断言是「17893 被占 → 自检跳过：探测端口 17893 被占用」。
    # 现在 +3 绑不上会回落到系统分配的空闲端口，「跳过」只剩「系统分不出空闲端口」那条（不可构造）。
    # 新断言：真引擎在动态端口上起来并真检通过（204）；tc-check.listen_port ≠ 17893 且引擎确实监听它。
    $o = RunTimed @('--disconnect')
    $lk = Lock-Port 17893
    $o2 = RunTimed @('--connect')
    $tcPort4 = -1
    if (Test-Path $RtEng) {
        try {
            $j4 = Get-Content $RtEng -Raw -Encoding UTF8 | ConvertFrom-Json
            $tc4 = @($j4.inbounds | Where-Object { $_.tag -eq 'tc-check' })
            if ($tc4.Count -eq 1) { $tcPort4 = [int]$tc4[0].listen_port }
        } catch { }
    }
    $dynBindable4 = Test-PortFree $tcPort4     # 引擎正监听它 ⇒ 应为 False
    Release-Lock $lk
    Case 'X4a' 'D 段：探测端口 17893 被占 → 自检仍「通道自检（经交易出口）：通过（HTTP 204）」' `
        ($o2.Code -eq 0 -and $o2.Out -match '通道自检（经交易出口）：通过（HTTP 204）') ("退出码=$($o2.Code) 输出=$($o2.Out -replace '\s+',' ')")
    Case 'X4b' 'D 段：不出现「跳过」（旧口径「跳过+被占用」已不可能）' ($o2.Out -notmatch '跳过') ("输出=$($o2.Out -replace '\s+',' ')")
    $engAfterSkip = Count-MyEngine
    Case 'X4c' 'D 段：连接本身仍可用（引擎在跑）' ($engAfterSkip -ge 1) ("sing-box=$engAfterSkip")
    $daily = CurlIp @('-4','-s','--max-time','25','-x','http://127.0.0.1:17890','https://ifconfig.me/ip')
    Case 'X4d' 'D 段：此时经 mixed 仍能出网（回落不等于坏）' ([bool]$daily.Ip) ("出口=$($daily.Ip)")
    # 关键不变量：引擎配置里的探测端口 ≠ 17893，且引擎真的听在它上面（该端口绑不上 = 有人在听）
    Case 'X4e' 'D 段：tc-check.listen_port ≠ 17893，且引擎确实监听在那个端口上（不是只在配置里写着）' `
        ($tcPort4 -gt 0 -and $tcPort4 -ne 17893 -and -not $dynBindable4) `
        ("listen_port=$tcPort4 可绑=$dynBindable4（应为 False）")

    Write-Host ''
    Add-Log '=== X5 C 段 + item4：坏成员 → 未通过且 runtime-engine.json 保留（CLI 路径）==='
    $o = RunTimed @('--disconnect')
    $o = RunTimed @('--exit-set','trade','provider2-trade')
    Case 'X5a' '把交易出口换成必然不通的成员（provider2-trade）' ($o.Code -eq 0 -and $o.Out -match 'provider2-trade') ("退出码=$($o.Code) 输出=$($o.Out -replace '\s+',' ')")
    $o = RunTimed @('--connect')
    $eng5 = Count-MyEngine
    $eng5On = Test-Path $RtEng
    Case 'X5b' 'C 段：坏成员 → 自检未通过（不得吞成跳过）' ($o.Out -match '未通过' -and $o.Out -notmatch '自检跳过') ("输出=$($o.Out -replace '\s+',' ')")
    Case 'X5c' 'item4：引擎在跑 + 自检未通过 → runtime-engine.json 必须存在（口径 A）' ($eng5On -and $eng5 -ge 1) ("文件存在=$eng5On sing-box=$eng5")
    $daily2 = CurlIp @('-4','-s','--max-time','25','-x','http://127.0.0.1:17890','https://ifconfig.me/ip')
    Case 'X5d' 'C 段反例：交易出口不通但日常仍能上网' ([bool]$daily2.Ip) ("出口=$($daily2.Ip)")
    $st = RunTimed @('--status')
    $titleLine = ($st.Out -split "`r?`n" | Where-Object { $_ -match '状态' } | Select-Object -First 1)
    Add-Log ("     CLI --status（无界面在跑）状态行：{0}" -f "$titleLine".Trim())
    Case 'X5e' 'CLI 单独跑时如实报「需要处理」（无控制接口 ⇒ 不算 Connected）' ($st.Out -match '连接需要处理') ("状态行=$("$titleLine".Trim())")

    Write-Host ''
    Add-Log '=== X6 E 段：断开清理 ==='
    $o = RunTimed @('--disconnect')
    $eng6 = Count-MyEngine
    $snap6 = Snap3 $TmpKey
    $left = @(); foreach ($f in @($Rt,$RtEng)) { if (Test-Path $f) { $left += (Split-Path $f -Leaf) } }
    Case 'X6a' 'E 段：断开后 runtime.json / runtime-engine.json 均不存在' ($left.Count -eq 0) ("仍存在=[$($left -join ',')]")
    Case 'X6b' 'E 段：断开后引擎进程 0 个' ($eng6 -eq 0) ("sing-box=$eng6")
    Case 'X6c' 'E 段：临时键里的代理设置已还原为原值（0 / 127.0.0.1:7897）' ($snap6 -match '^0\|127\.0\.0\.1:7897\|') ("实际=$snap6 输出=$($o.Out -replace '\s+',' ')")

    Write-Host ''
    Add-Log '=== X7 引擎秒退：engine 指向 cmd.exe ==='
    $cfgTxt = Get-Content $Cfg -Raw -Encoding UTF8
    $cfgTxt2 = $cfgTxt -replace '"binary"\s*:\s*"[^"]*"', '"binary": "C:/Windows/System32/cmd.exe"'
    [System.IO.File]::WriteAllText($Cfg, $cfgTxt2, (New-Object System.Text.UTF8Encoding($false)))
    $o = RunTimed @('--connect')
    # 实测口径：秒退是**连接失败**（exit 13，文案「引擎启动后立即退出…；系统代理已还原」），
    # 不是"连上了但自检没过"。所以这里断言的是"当场失败 + 如实说明 + 不吞成跳过 + 不落盘"。
    Case 'X7a' '引擎秒退 → connect 当场失败（exit 13）且如实说明「引擎启动后立即退出」' `
        ($o.Code -eq 13 -and $o.Out -match '引擎启动后立即退出') ("退出码=$($o.Code) 输出=$($o.Out -replace '\s+',' ')")
    Case 'X7b' '引擎秒退 → runtime-engine.json 不存在（没有"正在运行的连接"）' (-not (Test-Path $RtEng)) ("存在=$((Test-Path $RtEng))")
    Case 'X7c' '引擎秒退 → 输出里不出现「跳过」（跳过只留给「拿不到可用探测端口」）' ($o.Out -notmatch '跳过') ("输出=$($o.Out -replace '\s+',' ')")
    $snap7 = Snap3 $TmpKey
    Case 'X7d' '引擎秒退 → 系统代理已还原（不把用户留在指向空端口的状态）' ($snap7 -match '^0\|127\.0\.0\.1:7897\|') ("实际=$snap7")

    Write-Host ''
    Add-Log '=== X7e/X7f 「未做自检」已随死分支删除：杀引擎再自检，该措辞必须不再出现 ==='
    [System.IO.File]::WriteAllText($Cfg, $cfgTxt, (New-Object System.Text.UTF8Encoding($false)))   # 恢复真引擎
    $oc = RunTimed @('--connect')
    # 修（第三轮发现）：pid 在 runtime.json（运行记录），**不在** runtime-engine.json（那是引擎配置 json）。
    # 上一版从这里取 pid 永远取不到 → 引擎没被杀 → X7e 只断言"输出里没有跳过"于是假绿，引擎活到 X8c 判残留。
    $engPid = $null
    foreach ($f in @($Rt, $RtEng)) {
        if (-not $engPid -and (Test-Path $f)) {
            try { $cand = (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).EnginePid; if ($cand) { $engPid = $cand } } catch { } } }
    if ($engPid) { Stop-Process -Id $engPid -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 400
    $killed = -not (Get-Process -Id $engPid -ErrorAction SilentlyContinue)
    Case 'X7d2' '前提：真的取到了引擎 pid 并把它杀掉了（没有这一步，X7e 就是假绿）' `
        ([bool]$engPid -and $killed) ("pid=$engPid 已消失=$killed")
    $oh = RunTimed @('--headless')
    Add-Log ("     --headless 输出：{0}" -f ($oh.Out -replace '\s+',' '))
    Case 'X7e' '引擎被杀后 --headless 的结论里不出现「跳过」（跳过只留给「拿不到可用探测端口」）' `
        ($oh.Out -notmatch '跳过') ("退出码=$($oh.Code) 输出=$($oh.Out -replace '\s+',' ')")
    # 第三轮：selfcheck 的「未做自检」死分支已删除（原 selfcheck.rs:389-396），产物里 0 处。
    # 上一轮这里是 SKIP（"未能构造出现场，但措辞在二进制唯一 1 处"）——那个依据**已过期**。
    # 改成反向钉子：该措辞再出现就是回归，直接判 FAIL，不再 SKIP。
    Case 'X7f' '引擎被杀后不得出现已删除的「未做自检」措辞（第三轮删除的回归钉子）' `
        ($oh.Out -notmatch '未做自检') ("退出码=$($oh.Code) 输出=$($oh.Out -replace '\s+',' ')")
    if (Test-Path $LastCheck) { Add-Log ("     last-check.json：{0}" -f ((Get-Content $LastCheck -Raw -Encoding UTF8) -replace '\s+',' ')) }

    Write-Host ''
    Add-Log '=== X8 收尾：真实代理与默认根零写入 && 零残留 ==='
    Case 'X8a' '真实系统代理三元组前后完全一致' ($realBefore -eq (Snap3 $RealKey)) ("前=$realBefore 后=$(Snap3 $RealKey)")
    Case 'X8b' '用户默认根文件清单前后一致（零写入）' ((($defaultBefore -join ';') -eq ((Get-Manifest $DefaultData) -join ';'))) ("前=[$($defaultBefore -join ',')]")
    $r1 = @(Get-Process spidervpn -ErrorAction SilentlyContinue).Count
    $s1 = Count-MyEngine
    if (($r1 + $s1) -gt 0) { Start-Sleep -Seconds 1 }   # 进程退出有延迟，别把"正在退出"判成残留
    $r2 = @(Get-Process spidervpn -ErrorAction SilentlyContinue).Count
    $s2 = Count-MyEngine
    Case 'X8c' '零残留：无 spidervpn / sing-box 进程' (($r2 -eq 0) -and ($s2 -eq 0)) ("spidervpn=$r2 sing-box=$s2（初始 $r1/$s1）")
}
catch {
    if ($_.Exception.Message -ne '端口被占') { Add-Log ("异常：{0}" -f $_.Exception.Message) }
}
finally {
    Cleanup
    $script:log += ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    try { [System.IO.File]::WriteAllText($LogPath, (($script:log -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false))) } catch { }
}

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
Write-Host ("明细：{0}" -f $LogPath)
if ($script:fail -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }
exit 0
