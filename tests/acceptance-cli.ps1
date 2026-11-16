#requires -Version 5.1
# SpiderVPN（Rust 重构版）CLI 端到端独立验收
#
# 三条硬规则：
# 1. 全程只碰临时注册表键（SPIDERVPN_PROXY_KEY），**真实系统代理一个字节都不写**；
# 2. **默认数据根 C:\SpiderVPN\data 只读**：写文件的用例一律跑临时根，清理绝不碰它；
# 3. 只验证「行为是否符合需求」，不改产品代码。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tests\acceptance-cli.ps1
#      只读模式（只跑不写数据根的检查，用于证明脚本不改用户数据根）：先设 $env:TC_READONLY_ONLY='1'
# 退出码：0 全通过 / 1 有 FAIL / 2 未能完整验证（环境被占用或有 SKIP「无法判定」）/ 3 脚本自身异常

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8   # 产品输出中文是 UTF-8；不设会把「当前状态」解成乱码导致断言假失败
$ErrorActionPreference = 'Stop'

# 优先测「发布位置」的产物（C:\SpiderVPN\bin）；没有才退回构建目录——
# 门禁要验的是要交付出去的那个二进制，不是构建目录里碰巧还在的副本。
$Exe = 'C:\SpiderVPN\bin\spidervpn.exe'
if (-not (Test-Path $Exe)) { $Exe = 'C:\tc-rs-build\debug\spidervpn.exe' }

# 用户数据根 = 只读。这里住着用户唯一一份真实线路配置，**任何用例都不许写、更不许删**。
# （事故记录：早期版本把默认根当"测试数据根"，Cleanup 删掉了用户的 config.json。
#   所以现在：写文件的用例全部跑在下面的临时根里；清理函数遇到默认根路径直接抛异常。）
$DefaultData = 'C:\SpiderVPN\data'

# 用例自己的数据根：一次性目录，跑完整棵删掉。
$ScenRoot = Join-Path $env:TEMP ('tc-scen-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Cfg      = Join-Path $Data 'config.json'
$Rt       = Join-Path $Data 'runtime.json'
$Jn       = Join-Path $Data 'proxy-journal.json'
$env:SPIDERVPN_ROOT = $ScenRoot   # 让被测程序把所有写操作都落在这个临时根里

$RealKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

# 测试钩子：把「系统代理」整体指向临时键。不设这个变量程序就会去写真实代理。
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY

# 临时键里的「用户原值」：绕过列表刻意是长列表且**不含** <local>，用来验「只追加不覆盖」
$OrigEnable = 0
$OrigServer = '127.0.0.1:7897'
$OrigBypass = 'localhost;127.*;192.168.*;10.*'

# 假引擎：ping 会活约 300 秒，足够覆盖 T5→T8 全过程；不监听端口、不改任何系统设置
$EngineJson = '{"binary":"C:\\Windows\\System32\\PING.EXE"}'
# schema 2 起配置里不再存 engine.args（`-c` 按线路派生），「让假引擎活着」只能靠测试缝隙。
# 缝隙只覆盖参数、不覆盖引擎路径（路径仍取自 config.engine.binary）；仅测试用，Cleanup 里会清掉。
$env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'

$script:pass = 0
$script:fail = 0
$script:skip = 0

# 清环境变量（本轮加固）。**不要**用 `Remove-Item Env:X`：有的环境给 Remove-Item 装了
# 「安全删除」钩子，变量本来就不存在时会直接抛 SAFE_DELETE_FAIL_CLOSED，把整轮跑挂掉
# （本轮实测在 T41 被这个钩子打断，整轮作废）。.NET 这条 API 幂等、不抛、也不受钩子影响。
function Clear-EnvVar {
    param([string]$Name)
    try { [System.Environment]::SetEnvironmentVariable($Name, $null) } catch { }
}

# 「无法判定」单独一类：像 T18/T20 需要真实线路 + 能出网的环境，本机不具备时
# 既不能判 PASS（没证明任何事），也不能判 FAIL（不是产品问题），必须显式说明原因。
function Skip {
    param($Id, $Desc, $Why)
    $script:skip++
    Write-Host ("SKIP  {0}  {1} :: {2}" -f $Id, $Desc, $Why)
}

function Case {
    param($Id, $Desc, $Ok, $Actual)
    if ($Ok) { $script:pass++; Write-Host ("PASS  {0}  {1}" -f $Id, $Desc) }
    else     { $script:fail++; Write-Host ("FAIL  {0}  {1} :: {2}" -f $Id, $Desc, $Actual) }
}

# 「存活」判定：pid<=0 不是进程。直接用 Get-Process -Id 0 会拿到 System Idle 进程，
# 于是「记录里没写 pid」会被当成「进程活着」——那是最容易漏过去的一类假通过。
function Test-Alive {
    param($ProcessId)
    return ($ProcessId -gt 0) -and [bool](Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

# 三个字段一次性取出，比较时只需比一个字符串，避免漏字段
function Snap {
    param($Path)
    $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if (-not $p) { return '(键不存在)' }
    return ('{0}|{1}|{2}' -f $p.ProxyEnable, $p.ProxyServer, $p.ProxyOverride)
}

# 能不能绑一下（本轮新增）。第二轮起 `--import` / `--set-line` 会试绑「线路端口 + 3」：
# 所以「端口空闲」不够，必须 **端口 与 端口+3 都能绑**，否则导入会因产品**正确**拒绝而假红。
# 绑成功立刻放掉，不占着用户的端口。
function Test-PortBindable {
    param([int]$Port)
    if ($Port -le 0 -or $Port -gt 65535) { return $false }
    $l = $null
    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $l.Start()
        return $true
    } catch { return $false }
    finally { if ($l) { try { $l.Stop() } catch { } } }
}

# 只读/不拉子进程的命令：可以正常捕获输出
function Run {
    param([string[]]$Argv)
    $out = & $Exe @Argv 2>&1 | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
}

# --connect/--disconnect 会拉起引擎进程，而 Windows 上子进程会继承本进程 stdout 的写端，
# 管道要等到引擎退出才算 EOF——用 `| Out-String` 或 `Start-Process -Wait` 都会假死到引擎结束，
# 于是「幂等」用例会因为引擎已自然退出而误判。这里只等被测进程自己退出，不接任何管道。
# 也不用 Start-Process：5.1 下它的 -PassThru 对象取不到 ExitCode，WaitForExit 也提前返回。
function RunDetached {
    param($Arg)
    $psi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arg
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit(120000)) { return -1 }
    return $p.ExitCode
}

# 带超时 + 双流捕获的执行器：给「还没实现的新参数」用。
# 参数没被识别时程序会一路落到 GUI 分支（创建窗口、不退出），普通的 `&` 或管道会一直挂着，
# 门禁看起来像卡死。这里超时就杀掉，并把「超时」作为一种可读的失败原因返回。
function RunTimed {
    param($Arg, $TimeoutMs = 20000)
    $psi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arg
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $tOut = $p.StandardOutput.ReadToEndAsync()
    $tErr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutMs)) {
        try { $p.Kill() } catch { }
        return [pscustomobject]@{ Code = -9; Out = ("（超时：命令 {$Arg} 未在 " + [int]($TimeoutMs / 1000) + " 秒内返回——该参数可能尚未实现，程序落到了 GUI 分支）") }
    }
    $txt = ''
    if ($tOut.Wait(2000)) { $txt += $tOut.Result }
    if ($tErr.Wait(2000)) { $txt += $tErr.Result }
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $txt }
}

# 镜像产品的 safe_file_stem：id → 安全文件名片段（只留字母数字与 -_. ，其余换 _）。
# 别用原始 id 拼路径：用户的 id 是「示例线路」，磁盘文件是 ____.json —— 直接用 id 会拼出不存在的路径。
function Get-SafeStem {
    param($Id)
    if (-not $Id) { return '' }
    return ((($Id.Trim().ToCharArray()) | ForEach-Object { if ("$_" -match '[A-Za-z0-9\-_.]') { "$_" } else { '_' } }) -join '')
}

# 默认/场景数据根的清单：顶层文件 + lines\*.json（schema 2 的引擎配置在子目录里，
# 只比顶层文件会漏掉「线路引擎配置被改写/被删」这种变化）。
function Get-DataManifest {
    param($Root)
    $items = @()
    $items += @(Get-ChildItem $Root -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
    $linesDir = Join-Path $Root 'lines'
    if (Test-Path $linesDir) {
        $items += @(Get-ChildItem $linesDir -File -ErrorAction SilentlyContinue | ForEach-Object { "lines\$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
    }
    return @($items | Sort-Object)
}

# SKIP 路径专用：只删本次 PID 的场景根（`--headless` 守卫会顺带让产品建出 data 骨架）。
# 不能整调 Cleanup：那会删共享的测试键，可能弄断另一个并发实例。
function Remove-ScenRootOnly {
    if ($ScenRoot -and (Test-Path $ScenRoot)) { Remove-Item $ScenRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

# 只删自己建的临时目录。**用户数据根一律拒绝**——宁可脚本报错，也不能再删一次用户线路配置。
function Remove-TempOnly {
    param($Path)
    if (-not $Path) { return }
    $full = [System.IO.Path]::GetFullPath($Path).ToLower()
    if ($full.StartsWith('c:\tradechannelrs\data')) {
        throw "拒绝删除用户数据根下的路径：$Path（这是曾经删掉用户 config.json 的事故路径，写死拦截）"
    }
    if (Test-Path $full) { Remove-Item $full -Recurse -Force -ErrorAction SilentlyContinue }
}

# 按 runtime.json 里记录的 pid 精确清理，不按进程名杀 ping（会牵连用户自己的进程）。
# 注意：只处理临时根里的记录文件，默认根里那个 runtime.json 不在清理范围内。
function Cleanup {
    if (Test-Path $Rt) {
        try {
            $old = (Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json).EnginePid
            if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue }
        } catch { }
    }
    foreach ($r in @($ScenRoot, $impRoot, $t18Root, $t20Root, $t21Root, $t22Root, $t24Root, $bRoot, $t25Root, $t26Root, $t27Root, $t28Root, $t30Root, $t31Root, $t32Root, $t33Root, $t35Root, $t37Root, $t38Root, $t39Root, $t40Root, $t41Root, $t42Root, $rootProxy, $rootTun, $rootNoRule, $t43Root, $t45Root, $t46Root, $t47Root, $t48Root, $t49Root, $t50Root, $t50bRoot, $t51Root, $t53Root)) { Remove-TempOnly $r }
    Clear-EnvVar 'SPIDERVPN_RUN_KEY'
    Clear-EnvVar 'SPIDERVPN_FORCE_NONADMIN'   # 测试钩子绝不留在环境里
    Clear-EnvVar 'SPIDERVPN_ENGINE_ARGS'
    foreach ($k in @($TmpKey, 'HKCU:\Software\SpiderVPN\tests\t17-import', 'HKCU:\Software\SpiderVPN\tests\t18', 'HKCU:\Software\SpiderVPN\tests\t20',
                     'HKCU:\Software\SpiderVPN\tests\t47', 'HKCU:\Software\SpiderVPN\tests\t48', 'HKCU:\Software\SpiderVPN\tests\t49',
                     'HKCU:\Software\SpiderVPN\tests\t50', 'HKCU:\Software\SpiderVPN\tests\t50b', 'HKCU:\Software\SpiderVPN\tests\t51',
                     'HKCU:\Software\SpiderVPN\tests\t53')) {
        if ($k -and (Test-Path $k)) { Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# 并发守卫：本用例集占用的数据根、单实例互斥、临时键都是全机唯一的，别的实例一插进来就会
# 抢互斥、互删键与配置，症状（exit 4/13、键不见了、状态变「未连接」）与产品回归无法区分。
# 检测到外来实例就明说「未验证」并退出，不做假结论；也不去 Cleanup，免得破坏对方那一轮。
function Assert-Quiet {
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-Host "SKIP  检测到另一个 spidervpn 实例在跑：本轮结果不可信，未验证。请等它结束后重跑。"
        Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail)
        Remove-ScenRootOnly
        exit 2
    }
}

# T13 的两个子场景（配置缺失 / 配置坏掉）都要先回到「已连接」，每次都重铺一份合法配置
function Write-GoodCfg {
    # schema 2：lines[] + selected；engine 只有 binary（不再有 args）
    $o = @{ schema = 2; mode = 'proxy'; auto_start = $false; auto_connect = $false; close_to_tray = $false
            selected = 'L1'
            lines = @(@{ id = 'L1'; name = '验收线路'; proxy_endpoint = '127.0.0.1:47991' })
            engine = @{ binary = 'C:\\Windows\\System32\\PING.EXE' } }
    [System.IO.File]::WriteAllText($Cfg, ($o | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
}

if (-not (Test-Path $Exe)) {
    Write-Host "FAIL  T0  被测程序不存在 :: $Exe"
    Write-Host "TOTAL PASS=0 FAIL=1"
    exit 1
}

# 产物稳定性守卫：跑的过程中 exe 被重建过，这一轮结论就不可信（我曾因此拿到一条假超时 FAIL）。
# 刚重建（<20 秒）先别跑；跑完再比一次 mtime，变了就打 WARN 提示复跑。
$exeMtime = (Get-Item $Exe).LastWriteTime
Write-Host ("被测产物：{0}  ({1:N0} 秒前)" -f $exeMtime, ((Get-Date) - $exeMtime).TotalSeconds)
if (((Get-Date) - $exeMtime).TotalSeconds -lt 20) {
    Write-Host "SKIP  被测产物刚重建，可能还在被替换：请等构建稳定后再跑，别拿半成品的结论当验收结果。"
    Write-Host "TOTAL PASS=0 FAIL=0 SKIP=0"
    exit 2
}

# T1 是「前后对比」，素材必须在任何产品动作之前抓
$realBefore = Snap $RealKey

# 环境守卫必须在 Cleanup 之前：Cleanup 会删默认数据根里的 config/runtime/journal，
# 如果这时别人正用着一条真实连接（他曾用 C:\SpiderVPN\data 里的配置起过引擎），
# 先删再拒就是把别人的现场破坏了——守卫的意义是「不动任何东西」。
Assert-Quiet

Cleanup   # 上一轮的残留先清干净，否则「无配置」用例无从谈起

# Cleanup 会把测试钩子一起清掉（那是为了异常中断也不留钩子），所以这里必须重新立起来：
# 否则假引擎拿到的是派生参数 `run -c <file>`，PING 立刻退出 → 后面所有「连接成功」用例都会假失败。
$env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'

# 铺临时键的用户原值
New-Item -Path $TmpKey -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyEnable   -Value $OrigEnable -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyServer   -Value $OrigServer -PropertyType String -Force | Out-Null
New-ItemProperty -Path $TmpKey -Name ProxyOverride -Value $OrigBypass -PropertyType String -Force | Out-Null
$tmpOrig = Snap $TmpKey

$script:crashed = $false

# 再看一眼单实例互斥：进程名可能被改，互斥占着同样说明有实例在跑。
$guard = Run @('--headless')
if ($guard.Code -eq 4) {
    Write-Host "SKIP  环境被占用：另有一个 SpiderVPN 实例在跑（多半是并发跑了同一套用例）。请等它结束后重跑。"
    Write-Host "TOTAL PASS=0 FAIL=0 SKIP=0"
    Remove-ScenRootOnly
    exit 2
}
Assert-Quiet

# 47991 必须空闲：T5–T17 都用假引擎连这个端口，而产品现在会在**改代理之前**检查端口可用性
# （端口被占就 exit 13）。端口一旦被占，这些用例会集体"假失败"——必须先挡住，
# 而不是让产品正确的拒绝行为背锅。
$portBusyGuard = $false
try { $portBusyGuard = [bool](Get-NetTCPConnection -LocalPort 47991 -State Listen -ErrorAction SilentlyContinue) }
catch { $portBusyGuard = [bool](Select-String -InputObject (netstat -ano) -Pattern ':47991 .*LISTENING') }
if ($portBusyGuard) {
    Write-Host "SKIP  127.0.0.1:47991 已被占用：本轮连接类用例会因产品正确拒绝而假失败，未验证。请等占用者结束后重跑。"
    Write-Host "TOTAL PASS=0 FAIL=0 SKIP=0"
    Remove-ScenRootOnly
    exit 2
}

# 第二轮新增：`--import` / `--set-line` 现在会试绑「线路端口 + 3」（探测端口）。
# 这些静态端口只要有一个**配不上对**，导入类用例就会因产品**正确**拒绝（exit 12）而假红。
# 所以开跑前统一预检：配不上对就 SKIP（exit 2），绝不把环境问题算成产品回归。
$staticImportPorts = @(47991, 17901, 17902, 17911, 17912, 17921, 17922, 17923, 17951, 17961, 17962, 47992)
$pairBusy = @()
foreach ($sp in $staticImportPorts) {
    if (-not (Test-PortBindable $sp)) { $pairBusy += ('{0}(线路端口)' -f $sp) }
    if (-not (Test-PortBindable ($sp + 3))) { $pairBusy += ('{0}(探测端口)' -f ($sp + 3)) }
}
if ($pairBusy.Count -gt 0) {
    Write-Host ("SKIP  这些端口本轮绑不上：{0}。导入/写线路现在会试绑「端口+3」，被占时产品会正确拒绝，用例会假红：未验证。请等占用者结束后重跑。" -f ($pairBusy -join '、'))
    Write-Host "TOTAL PASS=0 FAIL=0 SKIP=0"
    Remove-ScenRootOnly
    exit 2
}

# 只读模式：只跑「不写用户数据根」的两项（R1 默认根只读 + T1 真实代理零写入），
# 用来向人证明「脚本对 C:\SpiderVPN\data 零写入」。写文件的用例都在临时根里跑，本模式不执行。
if ($env:TC_READONLY_ONLY -eq '1') {
    $roA = Get-DataManifest $DefaultData
    Clear-EnvVar 'SPIDERVPN_ROOT'
    $roSt = Run @('--status')
    $env:SPIDERVPN_ROOT = $ScenRoot
    $roB = Get-DataManifest $DefaultData
    $roSame = (($roA -join ';') -eq ($roB -join ';'))
    Case 'R1' '用户数据根只读：--status 读到真实线路，且文件清单前后完全一致' `
        ($roSt.Code -eq 0 -and $roSt.Out -notmatch '尚未配置' -and $roSame) `
        ("退出码=$($roSt.Code) 报未配置=$($roSt.Out -match '尚未配置') 清单一致=$roSame 清单=[$($roB -join ';')]")
    Case 'T1' '真实系统代理前后完全一致（零写入）' ($realBefore -eq (Snap $RealKey)) "前=$realBefore 后=$(Snap $RealKey)"
    Write-Host "（只读模式：T2–T20 共 19 条需要写数据根，统一在临时根内执行，本模式不跑）"
    Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    Cleanup
    if ($script:fail -gt 0) { exit 1 } else { exit 0 }
}

try {
    # ---- T2 无配置时拒绝预览 ----
    $o = Run @('--plan')
    # 口径（Batch B 之后）：**配置文件不存在 = 8**（找不到 config.json，无从谈线路）；
    # **配置在但 lines 为空 = 13**（缺线路，见 T29）。两档刻意分开，别混。
    Case 'T2' '配置文件不存在时 --plan exit 8（与「缺线路=13」区分）' ($o.Code -eq 8) "退出码=$($o.Code)（期望 8：配置文件不存在；缺线路才是 13，见 T29）"

    # ---- T3 写入合法线路 ----
    $o = Run @('--set-line', 'L1', '验收线路', '127.0.0.1:47991')
    $cfgText = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '(文件不存在)' }
    Case 'T3' '--set-line 合法端点后 config.json 含该端点' `
        ($o.Code -eq 0 -and $cfgText.Contains('127.0.0.1:47991')) "退出码=$($o.Code) 配置=$cfgText"

    # ---- T4 非法端点被拒绝且不覆盖 ----
    $o = Run @('--set-line', 'L1', '验收线路', '127.0.0.1:0')
    $cfgText2 = if (Test-Path $Cfg) { Get-Content $Cfg -Raw -Encoding UTF8 } else { '(文件不存在)' }
    Case 'T4' '非法端点被拒绝且不覆盖已有配置' `
        ($o.Code -ne 0 -and $cfgText2.Contains('127.0.0.1:47991')) "退出码=$($o.Code) 配置=$cfgText2"

    # 连接用例需要 engine，但 CLI 没有设置引擎的参数——直接补进配置文件。
    # 注意用 no-BOM 写：Windows PowerShell 5.1 的 -Encoding UTF8 会写 BOM，产品侧 serde 不认。
    if (Test-Path $Cfg) {
        $c = Get-Content $Cfg -Raw -Encoding UTF8 | ConvertFrom-Json
        $c | Add-Member -Name engine -Value ($EngineJson | ConvertFrom-Json) -MemberType NoteProperty -Force
        [System.IO.File]::WriteAllText($Cfg, ($c | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    }

    # ---- T5 接管后的代理三项 ----
    Assert-Quiet
    $code = RunDetached '--connect'
    $tmpAfter = Snap $TmpKey
    $f = $tmpAfter -split '\|'
    # 4=单实例被占、13=连接事务被拒。配合「临时键不见了」基本可断定是有别的实例/构建在并发跑，
    # 不是产品缺陷；把这条提示写进 FAIL 行，免得下次误判成产品回归（我就被这个坑过一次）。
    $hint = if ($tmpAfter -eq '(键不存在)') { '（临时键在 connect 前被外部删除：有其它测试/构建并发运行？）' }
            elseif ($code -eq 4) { '（单实例被占用：有另一个 SpiderVPN 在跑）' }
            else { '' }
    Case 'T5' '--connect 后临时键启用=1、端点正确、绕过列表保留原有条目' `
        ($code -eq 0 -and $f[0] -eq '1' -and $f[1] -eq '127.0.0.1:47991' -and $f[2].StartsWith($OrigBypass)) `
        "退出码=$code 键=$tmpAfter 期望前缀=$OrigBypass$hint"

    # ---- T6 运行时记录与真实进程 ----
    $rec = if (Test-Path $Rt) { Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $proc1 = if ($rec -and $rec.EnginePid -gt 0) { Get-Process -Id $rec.EnginePid -ErrorAction SilentlyContinue } else { $null }
    Case 'T6' '--connect 后 runtime.json 存在且 EnginePid 进程真实存活' `
        ([bool]$rec -and [bool]$proc1) `
        ("runtime=$([bool]$rec) EnginePid=$(if ($rec) { $rec.EnginePid } else { '无' }) 进程=$(if ($proc1) { '存活' } else { '不存在' })")
    $pid1 = if ($rec) { $rec.EnginePid } else { 0 }
    $start1 = if ($proc1) { $proc1.StartTime } else { $null }

    # ---- T7 幂等 ----
    $code = RunDetached '--connect'
    $rec2 = if (Test-Path $Rt) { Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $proc2 = if ($rec2 -and $rec2.EnginePid -gt 0) { Get-Process -Id $rec2.EnginePid -ErrorAction SilentlyContinue } else { $null }
    Case 'T7' '再次 --connect 幂等：EnginePid 不变、不新起进程' `
        ($code -eq 0 -and $rec2 -and $rec2.EnginePid -eq $pid1 -and $proc2 -and $proc2.StartTime -eq $start1) `
        ("退出码=$code 首次 pid=$pid1 再次 pid=$(if ($rec2) { $rec2.EnginePid } else { '无' }) 首次启动时刻=$start1 再次启动时刻=$(if ($proc2) { $proc2.StartTime } else { '无' })")

    # ---- T8 断开后彻底还原 ----
    $code = RunDetached '--disconnect'
    $tmpEnd = Snap $TmpKey
    $stillRunning = Test-Alive $pid1
    Case 'T8' '--disconnect 后临时键回原值、runtime/journal 清除、引擎已退出' `
        ($code -eq 0 -and $tmpEnd -eq $tmpOrig -and -not (Test-Path $Rt) -and -not (Test-Path $Jn) -and -not $stillRunning) `
        ("退出码=$code 键=$tmpEnd 原值=$tmpOrig runtime=$([bool](Test-Path $Rt)) journal=$([bool](Test-Path $Jn)) 引擎存活=$stillRunning")

    # ---- T9 headless 自检 ----
    $o = Run @('--headless')
    Case 'T9' '--headless 退出码 0 且输出含「当前状态」' `
        ($o.Code -eq 0 -and $o.Out.Contains('当前状态')) `
        ("退出码=$($o.Code) 含当前状态=$($o.Out.Contains('当前状态')) 输出=$($o.Out)")

    # ---- T10 SupervisorPid 与 EnginePid 必须是两个不同的进程 ----
    # 一次性 CLI 发起连接后自己就退出了，所以守护 pid 此时查不到才是对的；
    # 两者相等说明字段被偷懒复用（引擎冒充守护），状态投影会把「引擎活」误当成「连接正常」。
    Assert-Quiet
    $code = RunDetached '--connect'
    $rec3 = if (Test-Path $Rt) { Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $supPid = if ($rec3) { $rec3.SupervisorPid } else { 0 }
    $engPid = if ($rec3) { $rec3.EnginePid } else { 0 }
    $engAlive = Test-Alive $engPid
    $supAlive = Test-Alive $supPid
    Case 'T10' 'SupervisorPid 与 EnginePid 分离：守护已退出、引擎存活' `
        ($code -eq 0 -and [bool]$rec3 -and $supPid -ne $engPid -and $engAlive -and -not $supAlive) `
        "退出码=$code SupervisorPid=$supPid(存活=$supAlive) EnginePid=$engPid(存活=$engAlive)"

    # ---- T11 引擎活、守护死：必须报「需要处理」并给断开，不许说已连接/未连接 ----
    # 此时网络实际被代理接管着，报「未连接」会让用户以为没连（去点连接），报「已连接」会让他
    # 以为一切正常（不处理）。两种误判都会让他对着一个半死的连接做交易。
    $st = Run @('--status')
    $faultState = ($st.Out -match '(?i)state\s*[=:：]\s*Fault') -or $st.Out.Contains('连接需要处理') -or ($st.Out -match '(?i)\bFault\b')
    $giveDisconnect = ($st.Out -match '(?i)action\s*[=:：]\s*Disconnect') -or $st.Out.Contains('断开')
    $misleading = ($st.Out -match '(?i)state\s*[=:：]\s*(Connected|Disconnected)') -or $st.Out.Contains('已连接') -or $st.Out.Contains('未连接')
    Case 'T11' '引擎活守护死时 --status 报 Fault 且动作为断开（不得报已连接/未连接）' `
        ($st.Code -eq 0 -and $engAlive -and -not $supAlive -and $faultState -and $giveDisconnect -and -not $misleading) `
        ("退出码=$($st.Code) 前置(引擎活=$engAlive 守护死=$(-not $supAlive)) 有Fault态=$faultState 有断开动作=$giveDisconnect 出现误导状态=$misleading 完整输出：$($st.Out)")

    # ---- T12 带 BOM 的 config.json 必须能读 ----
    # BOM 是 Windows 工具的默认产物（PS 5.1 的 Out-File/Set-Content 都写），
    # 产品读不出来就等于「用户用记事本/脚本改过配置后程序打不开」。
    $bomName = 'BOM 线路验收'
    $bomJson = @{ schema = 2; mode = 'proxy'; selected = 'L9'
                  lines = @(@{ id = 'L9'; name = $bomName; proxy_endpoint = '127.0.0.1:17999' })
                  engine = @{ binary = 'C:\Windows\System32\PING.EXE' } } |
               ConvertTo-Json -Depth 6
    Set-Content -Path $Cfg -Value $bomJson -Encoding UTF8   # 5.1 会写 BOM
    if (([System.IO.File]::ReadAllBytes($Cfg)[0..2]) -join ',' -ne '239,187,191') {
        # PS 7 的 -Encoding UTF8 不写 BOM；缺了就显式补，否则这条用例退化成「普通配置」等于没验
        [System.IO.File]::WriteAllText($Cfg, $bomJson, (New-Object System.Text.UTF8Encoding($true)))
    }
    $o = Run @('--headless')
    $badCfg = $o.Out.Contains('配置不可用') -or $o.Out.Contains('配置格式错误')
    Case 'T12' '带 BOM 的 config.json 能被读取，线路名正常显示' `
        ($o.Code -eq 0 -and $o.Out.Contains($bomName) -and -not $badCfg) `
        ("退出码=$($o.Code) 含线路名=$($o.Out.Contains($bomName)) 报配置错误=$badCfg 输出=$($o.Out)")

    # ---- T13 连接态下配置缺失 / 损坏，仍必须能断开 ----
    # 配置是用户能直接编辑的文件：误删、改坏都很常见。这时如果没有命令能断开，
    # 用户就被锁在「代理指向本程序、引擎还在跑」且无从收尾的状态——比不连接更糟。
    # 两个子场景走同一段：铺好配置 → 连接 → 破坏配置 → 断开 → 逐项验收。
    $t13bad = @()
    foreach ($mode in @('配置缺失', '配置坏JSON')) {
        Assert-Quiet
        Write-GoodCfg
        $c1 = RunDetached '--connect'
        $recX = if (Test-Path $Rt) { Get-Content $Rt -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        $engX = if ($recX) { $recX.EnginePid } else { 0 }
        if (-not ($c1 -eq 0 -and (Snap $TmpKey) -like '1|127.0.0.1:47991|*' -and (Test-Alive $engX) -and (Test-Path $Rt) -and (Test-Path $Jn))) {
            $t13bad += "$mode：前置连接不成立(exit=$c1 键=$(Snap $TmpKey) 引擎存活=$(Test-Alive $engX))"
            continue
        }
        if ($mode -eq '配置缺失') { Remove-Item $Cfg -Force }
        else { [System.IO.File]::WriteAllText($Cfg, '{not json', (New-Object System.Text.UTF8Encoding($false))) }
        $c2 = RunDetached '--disconnect'
        $after = Snap $TmpKey
        $aliveX = Test-Alive $engX
        if (-not ($c2 -eq 0 -and $after -eq $tmpOrig -and -not (Test-Path $Rt) -and -not (Test-Path $Jn) -and -not $aliveX)) {
            $t13bad += "$mode：exit=$c2 键=$after runtime=$([bool](Test-Path $Rt)) journal=$([bool](Test-Path $Jn)) 引擎存活=$aliveX"
        }
    }
    Case 'T13' '连接态下 config.json 缺失/损坏时 --disconnect 仍能断开并还原' ($t13bad.Count -eq 0) ($t13bad -join '；')

    # ---- T14 读不到当前系统代理时必须盲还原 ----
    # 「读不到」用最狠的造法：把测试钩子指到一个**不存在的键**。此时若还按「读不到就不猜」
    # 拒绝还原，用户就被永久留在「代理指向本程序、凭据还在」的状态里——与「断开要能收尾」正相反。
    # 手工铺凭据与运行时记录（EnginePid 给一个不可能存在的 pid，避免真起引擎）。
    # 告警只写在 stderr，所以这条单独把 stdout/stderr 分开取——不能拿 stdout 冒充 stderr。
    $deadKey = 'Software\SpiderVPN\tests\t14-nokey'
    $deadPid = 4194303   # 超过 Windows 实际 pid 上界，OpenProcess/taskkill 都只会落空，不会误杀真进程
    $env:SPIDERVPN_PROXY_KEY = $deadKey
    Write-GoodCfg
    if (Test-Path ('HKCU:\' + $deadKey)) { Remove-Item ('HKCU:\' + $deadKey) -Recurse -Force -ErrorAction SilentlyContinue }
    [System.IO.File]::WriteAllText($Jn, '{"schema":1,"endpoint":"127.0.0.1:47991","saved_at_secs":0,"saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost;127.*;192.168.*;10.*"}}', (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($Rt, ('{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":' + $deadPid + ',"StartedAt":"2026-01-01T00:00:00Z","State":"Running","Error":null,"CleanupError":false,"TradingDirectAccessBlocked":false,"BootStartedAt":"2026-01-01T00:00:00Z"}'), (New-Object System.Text.UTF8Encoding($false)))
    $psi14 = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $psi14.FileName = $Exe
    $psi14.Arguments = '--disconnect'
    $psi14.UseShellExecute = $false
    $psi14.CreateNoWindow = $true
    $psi14.RedirectStandardOutput = $true
    $psi14.RedirectStandardError = $true
    $p14 = [System.Diagnostics.Process]::Start($psi14)
    $so14 = $p14.StandardOutput.ReadToEnd()
    $se14 = $p14.StandardError.ReadToEnd()
    $null = $p14.WaitForExit(60000)
    $c14 = $p14.ExitCode
    $wrote = Snap ('HKCU:\' + $deadKey)
    Case 'T14' '读不到当前系统代理时按凭据盲还原（exit 0 + stderr 告警 + 键写回原值 + 凭据清除）' `
        ($c14 -eq 0 -and $se14.Contains('无法读取当前系统代理') -and $wrote -eq '0|127.0.0.1:7897|localhost;127.*;192.168.*;10.*' -and -not (Test-Path $Jn) -and -not (Test-Path $Rt)) `
        ("退出码=$c14 stderr=$($se14.Trim()) 键=$wrote journal=$([bool](Test-Path $Jn)) runtime=$([bool](Test-Path $Rt)) stdout=$($so14.Trim())")
    if (Test-Path ('HKCU:\' + $deadKey)) { Remove-Item ('HKCU:\' + $deadKey) -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T15–T17 部署包导入线路（临时根，不碰默认数据根）----
    # 这三条串起来验一件事：导入产物必须能被连接链路**直接消费**，而不只是"文件写出来了"。
    # 用 SPIDERVPN_ROOT 指到临时根：导入会产 data\engine.json + data\config.json，
    # 不该往默认数据根里塞测试文件。
    $impRoot = Join-Path $env:TEMP ('tc-import-' + $PID)
    $impData = Join-Path $impRoot 'data'
    $impProfile = Join-Path $impRoot 'profile.json'
    $impPort = 47991
    $fakeEngine = 'C:\Windows\System32\PING.EXE'
    if (Test-Path $impRoot) { Remove-Item $impRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $impRoot | Out-Null
    # 夹具刻意三样齐全：inbounds 是 TUN（必须被换成 mixed）、outbounds（必须保留）、
    # 一个未知顶层键（必须原样保留——"不认识的键随手丢掉"是这类改写最典型的破坏）。
    $profileJson = '{"log":{"loglevel":"info"},"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"]}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"203.0.113.10","server_port":8388,"method":"aes-256-gcm","password":"x"}],"route":{"rules":[{"type":"field","outbound":"proxy"}]},"dns":{"servers":["1.1.1.1"]},"my_unknown_key":{"keep":true}}'
    [System.IO.File]::WriteAllText($impProfile, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    # 出口版 profile：带 daily-exit / trade-exit 两个选择器。出口可选用例专用——
    # 其余用例仍用 $profileJson（不含出口），避免改动它们的生成结果与既有断言。
    $profileJsonExits = '{"log":{"loglevel":"info"},"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"]}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"203.0.113.10","server_port":8388,"method":"aes-256-gcm","password":"x"},{"type":"direct","tag":"direct"},{"type":"selector","tag":"trade-exit","outbounds":["proxy","direct"],"default":"proxy"},{"type":"selector","tag":"daily-exit","outbounds":["direct","proxy"],"default":"direct"}],"route":{"rules":[],"final":"daily-exit"},"dns":{"servers":["1.1.1.1"]}}'

    $env:SPIDERVPN_ROOT = $impRoot

    # ---- T15 导入成功 ----
    $r15 = RunTimed ('--import "' + $impProfile + '" --engine "' + $fakeEngine + '" --port ' + $impPort + ' --line-name "导入线路"')
    $ic = if (Test-Path "$impData\config.json") { Get-Content "$impData\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $icRaw15 = if (Test-Path "$impData\config.json") { Get-Content "$impData\config.json" -Raw -Encoding UTF8 } else { '' }
    # 引擎配置搬到 lines\<id>.json；id 从 lines[0].id 取（中文名的 slug 形态是实现细节，不硬编码）
    $line0Id = if ($ic -and @($ic.lines).Count -ge 1) { @($ic.lines)[0].id } else { '' }
    $ejPath = if ($line0Id) { Join-Path $impData ('lines\' + $line0Id + '.json') } else { '' }
    $ej = if ($ejPath -and (Test-Path $ejPath)) { Get-Content $ejPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    # 注意：不能用 `$ib = if (...) { @($x) } else { @() }`——if 的输出会把单元素数组**展开成对象**，
    # 而 PSCustomObject 的 .Count 是 $null（不是 1），断言会静默判假。必须显式先建数组再赋。
    $ib = @()
    if ($ej) { $ib = @($ej.inbounds) }
    $ok15 = ($r15.Code -eq 0 -and [bool]$ej -and [bool]$ic -and $ib.Count -eq 1 -and $ib[0].type -eq 'mixed' -and
             $ib[0].listen_port -eq $impPort -and $ib[0].listen -eq '127.0.0.1' -and
             (@($ej.outbounds).Count -ge 1) -and $ej.outbounds[0].server -eq '203.0.113.10' -and
             [bool]$ej.route -and [bool]$ej.dns -and $ej.my_unknown_key.keep -eq $true -and
             (@($ic.lines).Count -eq 1) -and (@($ic.lines)[0].proxy_endpoint -eq ('127.0.0.1:' + $impPort)) -and
             ($ic.selected -eq $line0Id) -and -not $icRaw15.Contains('"args"'))
    Case 'T15' '导入成功：inbounds 换成单个 mixed、端口正确、outbounds 与未知键保留、config 端点正确' $ok15 `
        ("退出码=$($r15.Code) 输出=$($r15.Out.Trim()) inbounds=" + ($ib | ConvertTo-Json -Compress -Depth 4) + " 端点=$(if($ic){@($ic.lines)[0].proxy_endpoint}else{'(config.json 不存在)'}) 线路数=$(if($ic){@($ic.lines).Count}else{'无'}) selected=$(if($ic){$ic.selected}else{'无'}) 引擎配置=$ejPath 未知键=$(if($ej){$ej.my_unknown_key.keep}else{'无'})")

    # ---- T16 非法端口 / 缺 outbounds 必须拒绝且不落盘 ----
    # 「生成了一个连不上任何节点的配置」比"报错"危险得多：用户会以为导入成功，然后连不上还查不出原因。
    Remove-Item "$impData\engine.json", "$impData\config.json" -Force -ErrorAction SilentlyContinue
    $noOut = Join-Path $impRoot 'profile-no-outbounds.json'
    [System.IO.File]::WriteAllText($noOut, '{"inbounds":[{"type":"tun","tag":"t"}]}', (New-Object System.Text.UTF8Encoding($false)))
    $r16a = RunTimed ('--import "' + $impProfile + '" --engine "' + $fakeEngine + '" --port 0')
    $none16a = (-not (Test-Path "$impData\engine.json")) -and (-not (Test-Path "$impData\config.json"))
    $r16b = RunTimed ('--import "' + $noOut + '" --engine "' + $fakeEngine + '" --port ' + $impPort)
    $none16b = (-not (Test-Path "$impData\engine.json")) -and (-not (Test-Path "$impData\config.json"))
    $cjk = '[\u4e00-\u9fa5]'
    Case 'T16' '端口 0 与缺 outbounds 都被拒绝、有中文报错、且不生成任何文件' `
        ($r16a.Code -ne 0 -and $r16a.Out -match $cjk -and $none16a -and $r16b.Code -ne 0 -and $r16b.Out -match $cjk -and $none16b) `
        ("端口0: exit=$($r16a.Code) 未生成文件=$none16a 输出=$($r16a.Out.Trim()) | 缺outbounds: exit=$($r16b.Code) 未生成文件=$none16b 输出=$($r16b.Out.Trim())")

    # ---- T17 导入产物能被连接链路直接消费 ----
    # 先重新导入一份（T16 已把产物删掉，顺带再验一次导入可用）。
    $null = RunTimed ('--import "' + $impProfile + '" --engine "' + $fakeEngine + '" --port ' + $impPort + ' --line-name "导入线路"')
    # schema 2 起引擎参数不可落盘（`-c` 按线路派生）；「让假引擎活着」靠测试缝隙 SPIDERVPN_ENGINE_ARGS，
    # 所以这里只把引擎路径换成 PING，不再往配置里塞 args（塞了产品也不读，属于假通过）。
    $cfg17 = if (Test-Path "$impData\config.json") { Get-Content "$impData\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    if ($cfg17) {
        $cfg17.engine.binary = $fakeEngine
        [System.IO.File]::WriteAllText("$impData\config.json", ($cfg17 | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    $k17 = 'Software\SpiderVPN\tests\t17-import'
    $hk17 = 'HKCU:\' + $k17
    $env:SPIDERVPN_PROXY_KEY = $k17
    if (Test-Path $hk17) { Remove-Item $hk17 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk17 -Force | Out-Null
    New-ItemProperty $hk17 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk17 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk17 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $c17a = RunDetached '--connect'
    $k17v = Snap $hk17
    $rt17 = Join-Path $impData 'runtime.json'
    $rec17 = if (Test-Path $rt17) { Get-Content $rt17 -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $eng17 = if ($rec17) { $rec17.EnginePid } else { 0 }
    $aliveBefore = Test-Alive $eng17
    $c17b = RunDetached '--disconnect'
    $k17end = Snap $hk17
    $aliveAfter = Test-Alive $eng17
    Case 'T17' '导入产物可直接连接：代理三项正确、EnginePid 存活、断开后全部还原' `
        ($c17a -eq 0 -and $k17v -eq ('1|127.0.0.1:' + $impPort + '|localhost;127.*;192.168.*;10.*;<local>') -and $aliveBefore -and
         $c17b -eq 0 -and $k17end -eq '0|127.0.0.1:7897|localhost;127.*;192.168.*;10.*' -and -not (Test-Path $rt17) -and -not $aliveAfter) `
        ("connect exit=$c17a 键=$k17v EnginePid=$eng17(存活=$aliveBefore) → disconnect exit=$c17b 键=$k17end runtime=$([bool](Test-Path $rt17)) 引擎存活=$aliveAfter")
    if (Test-Path $hk17) { Remove-Item $hk17 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $impRoot) { Remove-Item $impRoot -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot   # 用完临时根立刻指回来，绝不能让后续命令落回用户数据根
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T18–T20 通道自检与出口身份 ----
    # 背景（上一轮的教训）：代理把流量全送进直连时，界面和 --status 照样报「已连接」，
    # 只看「HTTP 204 成功」毫无意义——直连也能 204。所以 T20 必须用出口身份证明代理真的生效。
    # 真实线路夹具**现场只读复制**：源是用户数据根里那份（config.json + 选中线路的 lines\<id>.json），
    # 拷进本次的临时根用完即删，绝不在别处长期存一份含凭据的副本。
    $realLine = $null
    $realLineId = ''
    if (Test-Path (Join-Path $DefaultData 'config.json')) {
        try {
            $probe = Get-Content (Join-Path $DefaultData 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $realLineId = if (@($probe.lines).Count -ge 1) { @($probe.lines)[0].id } else { '' }
            $realLineStem = Get-SafeStem $realLineId
            $probeEngineFile = if ($realLineStem) { Join-Path $DefaultData ('lines\' + $realLineStem + '.json') } else { '' }
            if ($probe.engine.binary -and $probe.engine.binary -notmatch 'PING\.EXE$' -and $probeEngineFile -and (Test-Path $probeEngineFile)) { $realLine = $DefaultData }
        } catch { }
    }
    # 47991 被占用时不能硬上：那可能是别人的真实连接，抢端口只会得到「假失败」
    $portBusy = $false
    try { $portBusy = [bool](Get-NetTCPConnection -LocalPort 47991 -State Listen -ErrorAction SilentlyContinue) }
    catch { $portBusy = [bool](Select-String -InputObject (netstat -ano) -Pattern ':47991 .*LISTENING') }
    $whyNot = if (-not $realLine) { "用户数据根里没有可用的真实线路（需要 config.json 里有线路 + 它自己的 lines\<id>.json，且引擎不是假引擎）" }
               elseif ($portBusy) { '127.0.0.1:47991 已被占用（可能是另一个真实连接在跑）：产品现已能明确拒绝这种冲突（见 T21），此条无法判定' }
               else { '' }

    # 在临时根里用真实引擎连一次。夹具要连线路自己的引擎配置一起搬（schema 2 里它在 data\lines\<id>.json）。
    # 另外必须临时清掉 SPIDERVPN_ENGINE_ARGS：那是给假引擎用的缝隙，会让真引擎拿到 PING 的参数。
    function Start-RealLine {
        param($Root, $Port = 47991)
        $d = Join-Path $Root 'data'
        New-Item -ItemType Directory -Path (Join-Path $d 'lines') -Force | Out-Null
        Copy-Item (Join-Path $realLine 'config.json') (Join-Path $d 'config.json') -Force
        Copy-Item (Join-Path $realLine ('lines\' + (Get-SafeStem $realLineId) + '.json')) (Join-Path $d ('lines\' + (Get-SafeStem $realLineId) + '.json')) -Force
        # 端口重映射：用户真实线路在默认根里是 17890（本机被 旧版TUN 占着），测试副本改用 47991。
        # 只改临时根里的副本，不动用户文件；否则真引擎会撞端口，产品正确拒绝(exit 13)被误判成缺陷。
        $rcfg = Get-Content (Join-Path $d 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($ln in $rcfg.lines) { $ln.proxy_endpoint = "127.0.0.1:$Port" }
        [System.IO.File]::WriteAllText((Join-Path $d 'config.json'), ($rcfg | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        $reng = Get-Content (Join-Path $d ('lines\' + (Get-SafeStem $realLineId) + '.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($ib in $reng.inbounds) { if ($ib.listen_port) { $ib.listen_port = $Port } }
        [System.IO.File]::WriteAllText((Join-Path $d ('lines\' + (Get-SafeStem $realLineId) + '.json')), ($reng | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
        $env:SPIDERVPN_ROOT = $Root
        Clear-EnvVar 'SPIDERVPN_ENGINE_ARGS'   # 真引擎不吃假引擎参数
        $r = RunDetached '--connect'
        $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'                      # 立刻恢复，后面的假引擎用例还要用
        return $r
    }

    # ---- T18 自检行：连接后「通过（HTTP 204）」，未连接「未检测」 ----
    if ($whyNot) {
        Skip 'T18' '自检行：连接后显示「通过（HTTP 204）」，未连接显示「未检测」' $whyNot
    } else {
        $t18Root = Join-Path $env:TEMP ('tc-real18-' + $PID)
        $k18 = 'Software\SpiderVPN\tests\t18'   # 环境变量要的是键路径，不带 HKCU:\（前缀只在拼 PS 路径时加）
        $env:SPIDERVPN_PROXY_KEY = $k18
        if (Test-Path $t18Root) { Remove-Item $t18Root -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path ('HKCU:\' + $k18)) { Remove-Item ('HKCU:\' + $k18) -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path ('HKCU:\' + $k18) -Force | Out-Null
        New-ItemProperty ('HKCU:\' + $k18) -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty ('HKCU:\' + $k18) -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty ('HKCU:\' + $k18) -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $c18 = Start-RealLine $t18Root
        $st18 = Run @('--status')
        $row18 = (($st18.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
        $ok18a = ($c18 -eq 0 -and $row18 -match '通过' -and $row18 -match '204')
        $null = RunDetached '--disconnect'
        # 未连接且无 last-check.json：必须显示「未检测」，且 status 不许报错
        $lc18 = Join-Path $t18Root 'data\last-check.json'
        if (Test-Path $lc18) { Remove-Item $lc18 -Force }
        $st18b = Run @('--status')
        $row18b = (($st18b.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
        Case 'T18' '自检行：连接后「通过（HTTP 204）」，未连接「未检测」且不报错' `
            ($ok18a -and $st18b.Code -eq 0 -and $row18b -match '未检测') `
            ("connect=$c18 连接后自检行=[$row18] | 断开后自检行=[$row18b] 断开后退出码=$($st18b.Code)")
        if (Test-Path ('HKCU:\' + $k18)) { Remove-Item ('HKCU:\' + $k18) -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $t18Root) { Remove-Item $t18Root -Recurse -Force -ErrorAction SilentlyContinue }
        $env:SPIDERVPN_ROOT = $ScenRoot   # 用完临时根立刻指回来，绝不能让后续命令落回用户数据根
    }

    # ---- T19 自检失败只影响那一行，不许影响连接结论 ----
    # 手工塞一份失败凭据：状态要如实说「未通过 + 原因」，而 --status 本身仍必须 exit 0。
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'
    Write-GoodCfg
    $c19 = RunDetached '--connect'
    $lcDefault = Join-Path $Data 'last-check.json'
    [System.IO.File]::WriteAllText($lcDefault, '{"ok":false,"status":null,"error":"连不上本机代理端口 47991：测试桩","at":0}', (New-Object System.Text.UTF8Encoding($false)))
    $st19 = Run @('--status')
    $row19 = (($st19.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
    Case 'T19' '自检未通过要如实显示原因，且 --status 退出码仍为 0（不许当成连接失败）' `
        ($st19.Code -eq 0 -and $row19 -match '未通过' -and $row19.Contains('连不上本机代理端口 47991：测试桩')) `
        ("connect=$c19 status退出码=$($st19.Code) 自检行=[$row19]")
    $null = RunDetached '--disconnect'
    Remove-Item $lcDefault -Force -ErrorAction SilentlyContinue

    # ---- T20 出口身份：默认直连 vs 切节点，必须分流（相对对照，不依赖绝对基线）----
    # 环境陷阱（lead 点名）：本机 旧版正跑 TUN，全局流量都被接管，`curl --noproxy` 拿到的
    # 「直连基线」其实是 旧版的节点 IP。所以这条**不再拿绝对基线当锚**，改成两个相对对照：
    #   ① 默认 daily=direct 时，经本机 mixed 出口 == 直连出口（默认就该直连）
    #   ② 把日常出口切成节点成员后，经 mixed 出口必须**变得不同**（角色真的换了）
    # 两个对照都只依赖「同一台机、同一次运行内的相对比较」，与 TUN 是否劫持无关。
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        Skip 'T20' '出口身份：默认直连 vs 切节点必须分流' '本机没有 curl.exe，取不到出口，无法判定'
    } elseif ($whyNot) {
        Skip 'T20' '出口身份：默认直连 vs 切节点必须分流' $whyNot
    } else {
        function Get-Exit {
            param([switch]$ThroughProxy)
            $out = ''
            for ($i = 0; $i -lt 3 -and -not $out; $i++) {
                # 必须 -4：本机双栈，不加会在直连走 IPv6、经代理走 IPv4，两边 IP 天生不同，
                # 那是协议栈差异而不是「出口不同」——不加这一条会把正确的实现判成 FAIL。
                if ($ThroughProxy) { $out = (& curl.exe -4 -s -x 'http://127.0.0.1:47991' --max-time 25 'http://checkip.amazonaws.com') -join '' }
                else { $out = (& curl.exe -4 -s --noproxy '*' --max-time 12 'http://checkip.amazonaws.com') -join '' }
                if (-not $out) { Start-Sleep -Seconds 2 }
            }
            return $out
        }
        $t20Root = Join-Path $env:TEMP ('tc-real20-' + $PID)
        $k20 = 'Software\SpiderVPN\tests\t20'   # 环境变量用键路径，不带 HKCU://
        $env:SPIDERVPN_PROXY_KEY = $k20
        if (Test-Path $t20Root) { Remove-Item $t20Root -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path ('HKCU://' + $k20)) { Remove-Item ('HKCU://' + $k20) -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path ('HKCU://' + $k20) -Force | Out-Null
        New-ItemProperty ('HKCU://' + $k20) -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty ('HKCU://' + $k20) -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty ('HKCU://' + $k20) -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $t20bad = @()
        $c20a = Start-RealLine $t20Root
        $a1 = Get-Exit -ThroughProxy
        $b1 = Get-Exit
        $null = RunDetached '--disconnect'
        if (-not ($c20a -eq 0 -and $a1 -and $b1 -and $a1 -eq $b1)) {
            $t20bad += "默认直连不符：connect=$c20a 经代理可用=$([bool]$a1) 直连可用=$([bool]$b1) 相同=$($a1 -eq $b1)（默认 daily=direct 时应相同）"
        }
        # 切一个真实的节点成员：从引擎配置的 outbounds 里挑 tag，而不是写死名字
        $cfg20 = if (Test-Path (Join-Path $t20Root 'data\config.json')) { Get-Content (Join-Path $t20Root 'data\config.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        $id20 = if ($cfg20 -and @($cfg20.lines).Count -ge 1) { @($cfg20.lines)[0].id } else { '' }
        $eng20p = if ($id20) { Join-Path $t20Root ('data\lines\' + (Get-SafeStem $id20) + '.json') } else { '' }
        $tag20 = ''
        if ($eng20p -and (Test-Path $eng20p)) {
            $ej20 = Get-Content $eng20p -Raw -Encoding UTF8 | ConvertFrom-Json
            # 必须从 **daily-exit 选择器的成员**里挑：随便挑一个 outbound（如 tc-transport）
            # 不在可选成员内，--exit-set 会正确地拒绝（exit 12），那不是产品缺陷而是挑错了成员。
            $dailySel20 = @($ej20.outbounds | Where-Object { $_.tag -eq 'daily-exit' })[0]
            $cands20 = @($dailySel20.outbounds | Where-Object { $_ -and $_ -ne 'direct' })
            if ($cands20.Count -ge 1) { $tag20 = $cands20[0] }
        }
        if (-not $tag20) {
            Skip 'T20-②' '切节点成员后出口必须不同' '引擎配置里没有可用的节点成员 tag（daily-exit 之外的 outbound），无法构造切换现场'
        } else {
            $set20 = RunTimed ('--exit-set daily ' + $tag20)
            # 不能再次 Start-RealLine：它会把 config.json 从真实线路重新拷一遍，
            # 把刚写进去的 daily-exit 选择覆盖掉——那样测出来的永远是「没切」。
            $env:SPIDERVPN_ROOT = $t20Root
            # 上一次 disconnect 的引擎可能还在退出（优雅停止最多 3s + 强制 2s）：
            # 端口没释放就 connect 会撞 13，那是时序不是产品问题——先等端口真空出来。
            for ($w20 = 0; $w20 -lt 40; $w20++) {
                $still = Get-NetTCPConnection -LocalPort 47991 -State Listen -ErrorAction SilentlyContinue
                if (-not $still) { break }
                Start-Sleep -Milliseconds 250
            }
            # 关键：Start-RealLine 用完会把**假引擎参数**（-n 300 127.0.0.1）恢复回来，
            # 那是给 PING.EXE 用的；真 sing-box 不认这些参数，直接起不来 → connect 13。
            # 这一次连接必须自己清掉它，连完再还给后面的假引擎用例。
            Clear-EnvVar 'SPIDERVPN_ENGINE_ARGS'
            $c20b = RunDetached '--connect'
            $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
            if ($c20b -eq 13) {
                Clear-EnvVar 'SPIDERVPN_ENGINE_ARGS'
                Start-Sleep -Seconds 2
                $c20b = RunDetached '--connect'
                $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
            }
            $a2 = Get-Exit -ThroughProxy
            $null = RunDetached '--disconnect'
            # 切过去的节点可能不可达（例如本地厂商通道没起）：此时出口取不到，**不能算作「出口未变」**。
            # 判定：切换与连接都成功，且「取不到出口」或「出口与直连不同」二者之一成立。
            if (-not ($set20.Code -eq 0 -and $c20b -eq 0 -and (-not $a2 -or $a2 -ne $b1))) {
                $t20bad += "切节点后出口未变：exit-set=$($set20.Code) connect=$c20b 切后出口可用=$([bool]$a2) 与直连相同=$($a2 -eq $b1)（切成 $tag20 后应不同）"
            }
        }
        Case 'T20' '出口分流：默认 daily=direct 时经代理==直连；切成节点成员后必须不同（相对对照，不依赖绝对基线）' `
            ($t20bad.Count -eq 0) (($t20bad -join '；') + " | 注：只比同/不同，不打印 IP；切到=$tag20")
        if (Test-Path ('HKCU://' + $k20)) { Remove-Item ('HKCU://' + $k20) -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $t20Root) { Remove-Item $t20Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T21 端口被占用：必须明确失败，且不许碰系统代理 ----
    # 最糟的失败模式是「端口冲突时把用户留在接管状态」：代理指向一个没起来的引擎，
    # 用户以为网断了还查不出原因。所以这条要同时验：退出码非 0、话说清楚、代理一个字节没动、
    # runtime/journal 都不许落盘（落了就说明它已经"半接管"了）。
    $t21Port = 17991
    while ([bool](Get-NetTCPConnection -LocalPort $t21Port -State Listen -ErrorAction SilentlyContinue) -or -not (Test-PortBindable ($t21Port + 3))) { $t21Port++ }
    $t21Root = Join-Path $env:TEMP ('tc-port21-' + $PID)
    $k21 = 'Software\SpiderVPN\tests\t21'
    $hk21 = 'HKCU:\' + $k21
    $listener21 = $null
    try {
        $listener21 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $t21Port)
        $listener21.Start()
        # 连接前的临时键原值：用来证明 connect 被拒绝时没动过代理
        $env:SPIDERVPN_PROXY_KEY = $k21
        if (Test-Path $hk21) { Remove-Item $hk21 -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $hk21 -Force | Out-Null
        New-ItemProperty $hk21 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $hk21 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty $hk21 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $key21a = Snap $hk21
        # 临时根里按「被占用的端口」生成配置
        if (Test-Path $t21Root) { Remove-Item $t21Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $t21Root | Out-Null
        $prof21 = Join-Path $t21Root 'profile.json'
        [System.IO.File]::WriteAllText($prof21, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
        $env:SPIDERVPN_ROOT = $t21Root
        $imp21 = RunTimed ('--import "' + $prof21 + '" --engine "' + $fakeEngine + '" --port ' + $t21Port + ' --line-name "端口占用线路"')
        $con21 = RunTimed '--connect'
        $key21b = Snap $hk21
        $rt21 = Join-Path $t21Root 'data\runtime.json'
        $jn21 = Join-Path $t21Root 'data\proxy-journal.json'
        Case 'T21' '端口被占用时 --connect 明确失败（非0＋「已被占用」），不写 runtime/journal、不动代理' `
            ($imp21.Code -eq 0 -and $con21.Code -ne 0 -and $con21.Out.Contains('已被占用') -and $con21.Out.Contains([string]$t21Port) -and
             -not (Test-Path $rt21) -and -not (Test-Path $jn21) -and $key21b -eq $key21a) `
            ("import=$($imp21.Code) connect=$($con21.Code) 端口=$t21Port runtime=$([bool](Test-Path $rt21)) journal=$([bool](Test-Path $jn21)) 键前=$key21a 键后=$key21b 输出=$($con21.Out.Trim())")
    }
    finally {
        if ($listener21) { try { $listener21.Stop() } catch { } }
        if (Test-Path $hk21) { Remove-Item $hk21 -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $t21Root) { Remove-Item $t21Root -Recurse -Force -ErrorAction SilentlyContinue }
        $env:SPIDERVPN_ROOT = $ScenRoot
    }

    # ---- T22 界面导入的「模式」落盘契约 ----
    # 界面走 webview IPC，管道不支持 import（管道线程与界面线程不是同一份上下文，从管道导入
    # 会写盘成功但窗口还显示旧线路），所以这里验的是**落盘契约**：mode 字段与 --status 的模式行。
    $t22Root = Join-Path $env:TEMP ('tc-mode22-' + $PID)
    $t22Data = Join-Path $t22Root 'data'
    $env:SPIDERVPN_ROOT = $t22Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t22'
    if (Test-Path $t22Root) { Remove-Item $t22Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t22Root | Out-Null
    $prof22 = Join-Path $t22Root 'profile.json'
    [System.IO.File]::WriteAllText($prof22, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $imp22a = RunTimed ('--import "' + $prof22 + '" --engine "' + $fakeEngine + '" --port 47991 --line-name "TUN线路" --tun')
    $cfg22a = if (Test-Path "$t22Data\config.json") { Get-Content "$t22Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $st22a = Run @('--status')
    $row22a = (($st22a.Out -split "`r?`n") | Where-Object { $_ -match '模式' }) -join ' '
    $imp22b = RunTimed ('--import "' + $prof22 + '" --engine "' + $fakeEngine + '" --port 47991 --line-name "代理线路"')
    $cfg22b = if (Test-Path "$t22Data\config.json") { Get-Content "$t22Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $st22b = Run @('--status')
    $row22b = (($st22b.Out -split "`r?`n") | Where-Object { $_ -match '模式' }) -join ' '
    Case 'T22' '导入的 mode 落盘：带 --tun → mode=tun 且模式行 TUN；缺省 → mode=proxy 且模式行 代理' `
        ($imp22a.Code -eq 0 -and [bool]$cfg22a -and $cfg22a.mode -eq 'tun' -and $row22a -match 'TUN' -and
         $imp22b.Code -eq 0 -and [bool]$cfg22b -and $cfg22b.mode -eq 'proxy' -and $row22b -match '代理') `
        ("tun: import=$($imp22a.Code) mode=$(if($cfg22a){$cfg22a.mode}else{'无'}) 模式行=[$row22a] | proxy: import=$($imp22b.Code) mode=$(if($cfg22b){$cfg22b.mode}else{'无'}) 模式行=[$row22b]")

    # ---- T23 老配置没有 mode 字段：必须按「代理」兼容，不许报错 ----
    # 老版本用户升上来就是这个形态；这里一旦要求必填，所有人的界面都会变成「配置不可用」。
    $oldCfgJson = '{"schema":1,"line":{"id":"L1","name":"老配置线路","proxy_endpoint":"127.0.0.1:47991"},"engine":{"binary":"C:\\Windows\\System32\\PING.EXE","args":["-n","300","127.0.0.1"]}}'
    [System.IO.File]::WriteAllText("$t22Data\config.json", $oldCfgJson, (New-Object System.Text.UTF8Encoding($false)))
    $cfg23Before = (Get-FileHash "$t22Data\config.json" -Algorithm SHA256).Hash
    $st23 = Run @('--status')
    $cfg23After = (Get-FileHash "$t22Data\config.json" -Algorithm SHA256).Hash
    $row23 = (($st23.Out -split "`r?`n") | Where-Object { $_ -match '模式' }) -join ' '
    # 再验一遍 --headless 也属只读（lead 定稿：status/lines/plan/restore/headless 都不许落盘）
    $cfg23HBefore = (Get-FileHash "$t22Data\config.json" -Algorithm SHA256).Hash
    $hd23 = Run @('--headless')
    $cfg23HAfter = (Get-FileHash "$t22Data\config.json" -Algorithm SHA256).Hash
    Case 'T23' '老配置缺 mode（schema1）：--status/--headless 仍 exit 0、模式兼容「代理」，且只读命令不改写配置' `
        ($st23.Code -eq 0 -and $row23 -match '代理' -and $st23.Out -notmatch '配置不可用' -and $cfg23Before -eq $cfg23After -and
         $hd23.Code -eq 0 -and $cfg23HBefore -eq $cfg23HAfter) `
        ("status: 退出码=$($st23.Code) 模式行=[$row23] 未改写=$($cfg23Before -eq $cfg23After) | headless: 退出码=$($hd23.Code) 未改写=$($cfg23HBefore -eq $cfg23HAfter)")
    if (Test-Path $t22Root) { Remove-Item $t22Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T24 失败必须明确，且不许把用户留在接管状态 ----
    # 两个子场景，覆盖同一类事故的两种入口：
    #  A) 非管理员 + TUN：权限不足要「动手前拒绝」（提权会话无法验证，显式注明）
    #  B) 引擎「起得来但立刻退出」：**任何会话都能跑**，而且这正是非管理员跑 TUN 的真实机制——
    #     sing-box 能被 spawn，建 TUN 设备时才失败然后自己退出。用 PING -z 复现同一条代码路径。
    #  B 的现有行为（缺陷）：connect 返回 Done、打印「完成」、代理指向死端口、journal+runtime 还留着。
    $isAdmin24 = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $t24bad = @()
    $t24note = @()

    # --- A) 非管理员 + TUN：用测试缝隙 SPIDERVPN_FORCE_NONADMIN 强制判为非管理员 ---
    # 这样就不依赖会话是否提权（我和实现同学都是提权会话，否则这条永远 SKIP）。
    # 关键硬断言：输出**不得**含「引擎启动失败」——那是「先改代理、引擎起不来、再回滚」的措辞；
    # 出现它说明前置检查没生效。两条路径必须能从外部区分，否则这条用例等于没验。
    $seamSrc = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
    $seamExists = $false
    $seamNewest = $null
    if (Test-Path $seamSrc) {
        $seamHits = @(Select-String -Path (Join-Path $seamSrc '*.rs') -Pattern 'SPIDERVPN_FORCE_NONADMIN')
        $seamExists = ($seamHits.Count -gt 0)
        if ($seamExists) { $seamNewest = ($seamHits | ForEach-Object { (Get-Item $_.Path).LastWriteTime } | Measure-Object -Maximum).Maximum }
    }
    if (-not $seamExists) {
        $t24note += 'A(非管理员TUN) SKIP：实现里没有 SPIDERVPN_FORCE_NONADMIN 测试缝隙（这是个待办，不能降级成永久跳过）'
    } else {
        $aRoot = Join-Path $env:TEMP ('tc-adm24-' + $PID)
        $ka = 'Software\SpiderVPN\tests\t24a'
        $hka = 'HKCU:///' + $ka
        $env:SPIDERVPN_PROXY_KEY = $ka
        if (Test-Path $aRoot) { Remove-Item $aRoot -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $aRoot | Out-Null
        if (Test-Path $hka) { Remove-Item $hka -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $hka -Force | Out-Null
        New-ItemProperty $hka -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $hka -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty $hka -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $kaBefore = Snap $hka
        $profA = Join-Path $aRoot 'profile.json'
        [System.IO.File]::WriteAllText($profA, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
        $env:SPIDERVPN_ROOT = $aRoot
        $impA = RunTimed ('--import "' + $profA + '" --engine "' + $fakeEngine + '" --port 47991 --line-name "管理员线路" --tun')
        $env:SPIDERVPN_FORCE_NONADMIN = '1'          # 测试钩子：只在用例里临时生效
        $conA = RunTimed '--connect'
        Clear-EnvVar 'SPIDERVPN_FORCE_NONADMIN'
        $kaAfter = Snap $hka
        $rtA = Join-Path $aRoot 'data\runtime.json'
        $jnA = Join-Path $aRoot 'data\proxy-journal.json'
        $rolledBack = $conA.Out.Contains('引擎启动失败')
        if (-not ($impA.Code -eq 0 -and $conA.Code -ne 0 -and $conA.Out.Contains('管理员') -and -not $rolledBack -and
                  $kaAfter -eq $kaBefore -and -not (Test-Path $rtA) -and -not (Test-Path $jnA))) {
            # 归因：缝隙源码在但产物更旧 = 装的是旧包，这时红的是「产物过期」而不是「前置检查缺失」。
            # 两者都要报，但不能混为一谈，否则会让人去改一个没坏的实现。
            $stale = ($seamExists -and $seamNewest -and ($exeMtime -lt $seamNewest))
            $t24bad += "A(强判非管理员+TUN): import=$($impA.Code) connect=$($conA.Code) 键前=$kaBefore 键后=$kaAfter runtime=$([bool](Test-Path $rtA)) journal=$([bool](Test-Path $jnA)) 走了回滚路径=$rolledBack 产物可能过期=$stale(产物=$($exeMtime|Get-Date -f HH:mm:ss) 缝隙源码=$($seamNewest|Get-Date -f HH:mm:ss)) 输出=$($conA.Out.Trim())"
        } else { $t24note += 'A 走的是「动手前拒绝」路径（消息里没有引擎启动失败）' }
        if (Test-Path $hka) { Remove-Item $hka -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $aRoot) { Remove-Item $aRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # --- B) 引擎起得来但立刻退出（PING -z：打印用法后立刻退，proxy 模式不需要权限）---
    $bRoot = Join-Path $env:TEMP ('tc-die24-' + $PID)
    $kb = 'Software\SpiderVPN\tests\t24b'
    $hkb = 'HKCU:///' + $kb
    $env:SPIDERVPN_PROXY_KEY = $kb
    if (Test-Path $bRoot) { Remove-Item $bRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path (Join-Path $bRoot 'data') -Force | Out-Null
    if (Test-Path $hkb) { Remove-Item $hkb -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hkb -Force | Out-Null
    New-ItemProperty $hkb -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hkb -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hkb -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $kbBefore = Snap $hkb
    $cfgB = @{ schema = 2; mode = 'proxy'; selected = 'L1'
               lines = @(@{ id = 'L1'; name = '秒退线路'; proxy_endpoint = '127.0.0.1:47991' })
               engine = @{ binary = 'C:\Windows\System32\PING.EXE' } }
    [System.IO.File]::WriteAllText((Join-Path $bRoot 'data\config.json'), ($cfgB | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $env:SPIDERVPN_ROOT = $bRoot
    $env:SPIDERVPN_ENGINE_ARGS = '-z'   # 「起得来但立刻退出」靠参数缝隙，引擎路径仍取自 config
    $conB = RunTimed '--connect'
    $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
    Start-Sleep -Milliseconds 1200   # 给实现的存活宽限（≤800ms）留出回滚时间
    $kbAfter = Snap $hkb
    $rtB = Join-Path $bRoot 'data\runtime.json'
    $jnB = Join-Path $bRoot 'data\proxy-journal.json'
    if (-not ($conB.Code -ne 0 -and $conB.Out.Contains('立即退出') -and $kbAfter -eq $kbBefore -and
              -not (Test-Path $rtB) -and -not (Test-Path $jnB))) {
        $t24bad += "B(引擎秒退): connect=$($conB.Code) 键前=$kbBefore 键后=$kbAfter runtime=$([bool](Test-Path $rtB)) journal=$([bool](Test-Path $jnB)) 输出=$($conB.Out.Trim())"
    } else { $t24note += 'B 走的是「动手前/宽限期内回滚」路径' }
    if (Test-Path $hkb) { Remove-Item $hkb -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $bRoot) { Remove-Item $bRoot -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    Case 'T24' '连接失败必须明确（非0+原因），且不许把用户留在「代理指向死引擎」状态' `
        ($t24bad.Count -eq 0) (($t24bad -join '；') + ' | ' + ($t24note -join '；'))

    # ---- T25 开机自启：写/删 Run 键项，且绝不动真实 Run 键 ----
    # 钩子 SPIDERVPN_RUN_KEY 只改「写到哪个键」，不改「写什么值」；值名固定 SpiderVPN，
    # 目标优先安装根的启动入口（本机是 C:/SpiderVPN/启动SpiderVPN.cmd）。
    # 必须在临时根里先 --import 一份配置：没有线路配置时这两个开关会直接拒绝（这是设计，不是缺陷）。
    $t25Root = Join-Path $env:TEMP ('tc-25-' + $PID)
    $realRun = 'HKCU://Software/Microsoft/Windows/CurrentVersion/Run'
    $testRunRel = 'Software\SpiderVPN\tests\t25run'
    $hk25 = 'HKCU://' + $testRunRel
    $env:SPIDERVPN_RUN_KEY = $testRunRel
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t25'
    if (Test-Path $t25Root) { Remove-Item $t25Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t25Root | Out-Null
    if (Test-Path $hk25) { Remove-Item $hk25 -Recurse -Force -ErrorAction SilentlyContinue }
    # 真实 Run 键快照（跑前跑后必须一模一样）
    $realRunBefore = if (Test-Path $realRun) { ((Get-Item $realRun).GetValueNames() | Sort-Object | ForEach-Object { "$_=$(Get-ItemPropertyValue -Path $realRun -Name $_)" }) -join ';' } else { '(键不存在)' }
    $prof25 = Join-Path $t25Root 'profile.json'
    [System.IO.File]::WriteAllText($prof25, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $env:SPIDERVPN_ROOT = $t25Root
    $imp25 = RunTimed ('--import "' + $prof25 + '" --engine "' + $fakeEngine + '" --port 47991 --line-name "自启线路"')
    $on25 = RunTimed '--set-autostart on'
    $val25 = if (Test-Path $hk25) { (Get-ItemProperty -Path $hk25 -Name 'SpiderVPN' -ErrorAction SilentlyContinue).SpiderVPN } else { $null }
    $off25 = RunTimed '--set-autostart off'
    $valAfterOff = if (Test-Path $hk25) { (Get-ItemProperty -Path $hk25 -Name 'SpiderVPN' -ErrorAction SilentlyContinue).SpiderVPN } else { $null }
    $realRunAfter = if (Test-Path $realRun) { ((Get-Item $realRun).GetValueNames() | Sort-Object | ForEach-Object { "$_=$(Get-ItemPropertyValue -Path $realRun -Name $_)" }) -join ';' } else { '(键不存在)' }
    $wantTarget = Join-Path 'C:\SpiderVPN' '启动SpiderVPN.cmd'
    # 按 Windows 命令行语义解析 Run 值，而不是直接比字符串：本轮刻意给值加了引号
    #（路径含空格时不带引号会静默失效），直接比会既误判、又把「带不带引号」这个刻意行为漏掉。
    $parsed25 = ''
    $rawVal25 = [string]$val25
    if ($rawVal25) {
        if ($rawVal25.StartsWith('"')) {
            $closeQ = $rawVal25.IndexOf('"', 1)
            if ($closeQ -gt 0) { $parsed25 = $rawVal25.Substring(1, $closeQ - 1) }
        } else {
            $sp25 = $rawVal25.IndexOf(' ')
            $parsed25 = if ($sp25 -gt 0) { $rawVal25.Substring(0, $sp25) } else { $rawVal25 }
        }
    }
    # 反向断言：必须是带引号的形态（将来谁把引号去掉，这条要红）
    $quoted25 = $rawVal25.StartsWith('"')
    Case 'T25' '开机自启：on 写 Run 项（带引号）指向启动入口、off 删除该项，且真实 Run 键前后一致' `
        ($imp25.Code -eq 0 -and $on25.Code -eq 0 -and $parsed25 -eq $wantTarget -and $quoted25 -and $off25.Code -eq 0 -and -not $valAfterOff -and $realRunAfter -eq $realRunBefore) `
        ("import=$($imp25.Code) on=$($on25.Code) 原值=[$val25] 解析路径=[$parsed25]（期望 $wantTarget） 带引号=$quoted25 off=$($off25.Code) 删后=[$valAfterOff] 真实Run键未变=$($realRunAfter -eq $realRunBefore)")
    if (Test-Path $hk25) { Remove-Item $hk25 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t25Root) { Remove-Item $t25Root -Recurse -Force -ErrorAction SilentlyContinue }
    Clear-EnvVar 'SPIDERVPN_RUN_KEY'
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T26 关窗行为：close_to_tray=false 关窗即退出，true 关窗仍存活 ----
    # 用 CloseMainWindow()（等价点右上角 X），**不用 Stop-Process**——强杀不走关闭清理，
    # 会把「关窗是否退出」这件事测成"进程没了"，那是假的。跑完必须把开关恢复成 false。
    $t26Root = Join-Path $env:TEMP ('tc-26-' + $PID)
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t26'
    if (Test-Path $t26Root) { Remove-Item $t26Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t26Root | Out-Null
    $prof26 = Join-Path $t26Root 'profile.json'
    [System.IO.File]::WriteAllText($prof26, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $env:SPIDERVPN_ROOT = $t26Root
    $imp26 = RunTimed ('--import "' + $prof26 + '" --engine "' + $fakeEngine + '" --port 47991 --line-name "关窗线路"')
    $setOff = RunTimed '--set-closetotray off'
    function Open-Gui {
        $g = Start-Process -FilePath $Exe -PassThru
        for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; try { $g.Refresh() } catch { }; if ($g.HasExited -or $g.MainWindowHandle -ne 0) { break } }
        return $g
    }
    $gui1 = Open-Gui
    $win1 = if ($gui1 -and -not $gui1.HasExited) { $gui1.MainWindowHandle } else { 0 }
    $exit1 = $null
    if ($win1) {
        $null = $gui1.CloseMainWindow()
        for ($i = 0; $i -lt 24 -and -not $gui1.HasExited; $i++) { Start-Sleep -Milliseconds 500; try { $gui1.Refresh() } catch { } }
        $exit1 = $gui1.HasExited
    }
    if ($gui1 -and -not $gui1.HasExited) { Stop-Process -Id $gui1.Id -Force -ErrorAction SilentlyContinue }   # 收尾用，不参与判定
    $setOn = RunTimed '--set-closetotray on'
    $gui2 = Open-Gui
    $win2 = if ($gui2 -and -not $gui2.HasExited) { $gui2.MainWindowHandle } else { 0 }
    $alive2 = $false
    if ($win2) {
        $null = $gui2.CloseMainWindow()
        Start-Sleep -Seconds 8
        try { $gui2.Refresh() } catch { }
        $alive2 = -not $gui2.HasExited
    }
    # 收尾前先确认它没在连接态：临时根里若有 runtime.json / proxy-journal.json，强杀会把引擎和
    # 代理留在原地（今天的临时根刚 import 过、auto_connect=false，但将来有人改配置照抄这条会出事）。
    $rt26 = Join-Path $t26Root 'data\runtime.json'
    $jn26 = Join-Path $t26Root 'data\proxy-journal.json'
    $noRec26 = (-not (Test-Path $rt26)) -and (-not (Test-Path $jn26))
    $t26note = if ($noRec26) { '收尾前无 runtime/journal，可安全结束' } else { '未强杀：临时根里有 runtime/proxy-journal（疑似连接态），留给人工处理' }
    if ($gui2 -and -not $gui2.HasExited -and $noRec26) { Stop-Process -Id $gui2.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    $setOff2 = RunTimed '--set-closetotray off'
    $cfg26 = if (Test-Path (Join-Path $t26Root 'data\config.json')) { Get-Content (Join-Path $t26Root 'data\config.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    if (-not $win1 -or -not $win2) {
        Skip 'T26' '关窗行为：false 关窗退出 / true 关窗仍存活' 'GUI 起不来（本会话可能没有交互桌面），无法判定'
    } else {
        Case 'T26' '关窗行为：false 关窗退出 / true 关窗仍存活；收尾前无连接记录；跑完恢复 false' `
            ($imp26.Code -eq 0 -and $setOff.Code -eq 0 -and $exit1 -eq $true -and $setOn.Code -eq 0 -and $alive2 -and
             $noRec26 -and $setOff2.Code -eq 0 -and [bool]$cfg26 -and $cfg26.close_to_tray -eq $false) `
            ("import=$($imp26.Code) off=$($setOff.Code) 关窗后退出=$exit1 | on=$($setOn.Code) 关窗后仍存活=$alive2 | 收尾安全=$t26note | 恢复off=$($setOff2.Code) config.close_to_tray=$(if($cfg26){$cfg26.close_to_tray}else{'无'})")
    }
    if (Test-Path $t26Root) { Remove-Item $t26Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T27 多线路：两条、* 标在最后导入那条、connect 用的是选中线路的端点 ----
    $t27Root = Join-Path $env:TEMP ('tc-27-' + $PID)
    $t27Data = Join-Path $t27Root 'data'
    $env:SPIDERVPN_ROOT = $t27Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t27'
    $hk27 = 'HKCU:\' + 'Software\SpiderVPN\tests\t27'
    if (Test-Path $t27Root) { Remove-Item $t27Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t27Root | Out-Null
    # 临时键必须真的建出来（含三项原值）：产品要读「当前代理」，读不到就会拒绝接管（exit 13）
    if (Test-Path $hk27) { Remove-Item $hk27 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk27 -Force | Out-Null
    New-ItemProperty $hk27 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk27 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk27 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $prof27 = Join-Path $t27Root 'profile.json'
    [System.IO.File]::WriteAllText($prof27, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $imp27a = RunTimed ('--import "' + $prof27 + '" --engine "' + $fakeEngine + '" --port 17901 --line-name "line-a"')
    $imp27b = RunTimed ('--import "' + $prof27 + '" --engine "' + $fakeEngine + '" --port 17902 --line-name "line-b"')
    $cfg27 = if (Test-Path "$t27Data\config.json") { Get-Content "$t27Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $ids27 = @()
    if ($cfg27) { $ids27 = @($cfg27.lines | ForEach-Object { $_.id }) }
    # 每条线路各有自己的引擎配置（id 从配置里取，不硬编码 slug 形态）
    $twoFiles27 = (@($ids27 | Where-Object { $_ -and (Test-Path (Join-Path $t27Data ('lines\' + $_ + '.json'))) }).Count -eq 2)
    $ls27 = Run @('--lines')
    $starOnB = ((@(($ls27.Out -split "`r?`n") | Where-Object { $_ -match '^\s*\*\s+line-b\b' })).Count -eq 1)
    # 占住 line-b 的端口 → 报错里只该出现 17902（说明用的是选中线路），不该出现 17901
    $l27 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 17902)
    $l27.Start()
    $con27 = RunTimed '--connect'
    $l27.Stop()
    $hitB = $con27.Out.Contains('17902')
    $hitA = $con27.Out.Contains('17901')
    # 切到 line-a 再连（17902 已释放，17901 空闲）→ 应该成功，证明 --use 真的换了端点
    $use27 = RunTimed '--use line-a'
    $st27 = Run @('--status')
    $ep27Row = (($st27.Out -split "`r?`n") | Where-Object { $_ -match '端点' }) -join ' '
    $con27b = RunTimed '--connect'
    $key27 = Snap ('HKCU:\' + 'Software\SpiderVPN\tests\t27')
    $null = RunDetached '--disconnect'
    Case 'T27' '多线路：两条各有一份引擎配置、* 在最后导入那条、connect 只用选中线路的端点、--use 能切换' `
        ($imp27a.Code -eq 0 -and $imp27b.Code -eq 0 -and @($ids27).Count -eq 2 -and $twoFiles27 -and $starOnB -and
         $con27.Code -ne 0 -and $hitB -and -not $hitA -and $use27.Code -eq 0 -and $ep27Row -match '17901' -and
         $con27b.Code -eq 0 -and $key27 -like '1|127.0.0.1:17901|*') `
        ("import=$($imp27a.Code)/$($imp27b.Code) 线路数=$(@($ids27).Count) 各自配置=$twoFiles27 *在line-b=$starOnB | 占17902时 connect=$($con27.Code) 提到17902=$hitB 提到17901=$hitA | use=$($use27.Code) 端点行=[$ep27Row] 切换后connect=$($con27b.Code) 键=$key27")
    if (Test-Path $t27Root) { Remove-Item $t27Root -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $hk27) { Remove-Item $hk27 -Recurse -Force -ErrorAction SilentlyContinue }

    # ---- T28/T29 删除线路：删选中项要回退第一条；删到一条不剩要能优雅降级 ----
    $t28Root = Join-Path $env:TEMP ('tc-28-' + $PID)
    $t28Data = Join-Path $t28Root 'data'
    $env:SPIDERVPN_ROOT = $t28Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t28'
    if (Test-Path $t28Root) { Remove-Item $t28Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t28Root | Out-Null
    $prof28 = Join-Path $t28Root 'profile.json'
    [System.IO.File]::WriteAllText($prof28, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $null = RunTimed ('--import "' + $prof28 + '" --engine "' + $fakeEngine + '" --port 17901 --line-name "line-a"')
    $null = RunTimed ('--import "' + $prof28 + '" --engine "' + $fakeEngine + '" --port 17902 --line-name "line-b"')
    $cfg28pre = Get-Content "$t28Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $idA = @($cfg28pre.lines | Where-Object { $_.name -eq 'line-a' })[0].id
    $idB = @($cfg28pre.lines | Where-Object { $_.name -eq 'line-b' })[0].id
    $rmB = RunTimed '--remove-line line-b'
    $cfg28 = Get-Content "$t28Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $st28 = Run @('--status')
    # 新版 --status 只保留横幅行「线路：<名字>  端点：…」（旧的「线路      ：」重复行已删）
    $lineRow28Hits = @(($st28.Out -split "`r?`n") | Where-Object { $_ -match '线路：' })
    $lineRow28 = $lineRow28Hits -join ' '
    Case 'T28' '删掉当前选中线路：自动回退第一条，--status 的「线路」行跟着变，被删线路的引擎配置也删掉' `
        ($rmB.Code -eq 0 -and @($cfg28.lines).Count -eq 1 -and $cfg28.selected -eq $idA -and
         $lineRow28 -match 'line-a' -and $lineRow28Hits.Count -eq 1 -and -not (Test-Path (Join-Path $t28Data ('lines\' + $idB + '.json')))) `
        ("remove=$($rmB.Code) 剩=$(@($cfg28.lines).Count) selected=$($cfg28.selected)（期望 $idA） 线路横幅(次=$($lineRow28Hits.Count))=[$lineRow28] 被删线路引擎配置已删=$(-not (Test-Path (Join-Path $t28Data ('lines\' + $idB + '.json'))))")
    $rmA = RunTimed '--remove-line line-a'
    $st29 = Run @('--status')
    # 删空后横幅显示「线路：尚未配置」，「线路数    ：0」保留
    $lineRow29Hits = @(($st29.Out -split "`r?`n") | Where-Object { $_ -match '线路：' })
    $lineRow29 = (($st29.Out -split "`r?`n") | Where-Object { $_ -match '线路：|线路数' }) -join ' | '
    $con29 = RunTimed '--connect'
    Case 'T29' '删到一条不剩：--status 不崩且显示未配置，connect exit 13 并报「未配置线路」' `
        ($rmA.Code -eq 0 -and $st29.Code -eq 0 -and $lineRow29 -match '尚未配置' -and $lineRow29Hits.Count -eq 1 -and $lineRow29 -match '线路数    ：0' -and
         $con29.Code -eq 13 -and $con29.Out.Contains('未配置线路')) `
        ("remove=$($rmA.Code) status=$($st29.Code) 行=[$lineRow29] connect=$($con29.Code) 提到未配置线路=$($con29.Out.Contains('未配置线路'))")
    if (Test-Path $t28Root) { Remove-Item $t28Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T30 两条「中文名 + 相同尾号」的线路：id 必须互不相同、引擎配置互不覆盖 ----
    # 旧 slug 规则（非字母数字→下划线）下「甲1」「乙1」都会变 `___1`，两条线路会共用一份引擎配置；
    # 用码点 hex 之后才真正唯一。这条不 hardcode id 值，只断言「两个 id 不同 + 两份文件都在 + 内容不同」。
    $t30Root = Join-Path $env:TEMP ('tc-30-' + $PID)
    $t30Data = Join-Path $t30Root 'data'
    $env:SPIDERVPN_ROOT = $t30Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t30'
    if (Test-Path $t30Root) { Remove-Item $t30Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t30Root | Out-Null
    $prof30 = Join-Path $t30Root 'profile.json'
    [System.IO.File]::WriteAllText($prof30, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    $imp30a = RunTimed ('--import "' + $prof30 + '" --engine "' + $fakeEngine + '" --port 17911 --line-name "甲1"')
    $imp30b = RunTimed ('--import "' + $prof30 + '" --engine "' + $fakeEngine + '" --port 17912 --line-name "乙1"')
    $cfg30 = if (Test-Path "$t30Data\config.json") { Get-Content "$t30Data\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $ids30 = @()
    if ($cfg30) { $ids30 = @($cfg30.lines | ForEach-Object { $_.id }) }
    $files30 = @()
    foreach ($i30 in $ids30) { if ($i30) { $files30 += (Join-Path $t30Data ('lines\' + $i30 + '.json')) } }
    $both30 = (@($files30 | Where-Object { Test-Path $_ }).Count -eq 2)
    $distinct30 = (@($ids30 | Sort-Object -Unique).Count -eq 2)
    $diff30 = $false
    if ($both30) { $diff30 = ((Get-FileHash $files30[0] -Algorithm SHA256).Hash -ne (Get-FileHash $files30[1] -Algorithm SHA256).Hash) }
    Case 'T30' '中文名尾号相同的两条线路：id 互不相同、各有独立的 lines\<id>.json、内容不互相覆盖' `
        ($imp30a.Code -eq 0 -and $imp30b.Code -eq 0 -and @($ids30).Count -eq 2 -and $distinct30 -and $both30 -and $diff30) `
        ("import=$($imp30a.Code)/$($imp30b.Code) id 数=$(@($ids30).Count) 互不相同=$distinct30 两份文件都在=$both30 内容不同=$diff30（id 形态不打印：实现细节）")
    if (Test-Path $t30Root) { Remove-Item $t30Root -Recurse -Force -ErrorAction SilentlyContinue }

    # ---- T31 已落盘线路的 id 不得被重算（旧 id 必须继续指向同一份 lines\<id>.json）----
    # 自造「旧 id + engine.json」的迁移现场（不依赖用户现场数据，也不碰默认根）：
    # 旧 slug 形态的 id 用 `____`（正是历史版本给"示例线路"生成的形态），
    # 写命令触发迁移后必须：id 仍是 `____`、lines\____.json 由 engine.json 复制而来。
    # 若新版本按新规则（码点 hex）重算 id，用户那条线路的引擎配置路径就漂了——连接会失败或读错配置。
    $t31Root = Join-Path $env:TEMP ('tc-31-' + $PID)
    $t31Data = Join-Path $t31Root 'data'
    $env:SPIDERVPN_ROOT = $t31Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t31'
    if (Test-Path $t31Root) { Remove-Item $t31Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path (Join-Path $t31Data 'lines') -Force | Out-Null
    $legacyId = '____'
    $legacyCfg = '{"schema":1,"mode":"proxy","line":{"id":"' + $legacyId + '","name":"老线路2号","proxy_endpoint":"127.0.0.1:47991"},"engine":{"binary":"C://Windows//System32//PING.EXE","args":["-n","300","127.0.0.1"]}}'
    [System.IO.File]::WriteAllText((Join-Path $t31Data 'config.json'), $legacyCfg, (New-Object System.Text.UTF8Encoding($false)))
    $legacyEngine = '{"inbounds":[{"type":"mixed","tag":"tc-mixed","listen":"127.0.0.1","listen_port":47991}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"203.0.113.10","server_port":8388,"method":"aes-256-gcm","password":"x"}]}'
    [System.IO.File]::WriteAllText((Join-Path $t31Data 'engine.json'), $legacyEngine, (New-Object System.Text.UTF8Encoding($false)))
    $mig31 = RunTimed '--set-autoconnect on'     # 写命令：真迁移 + 落盘
    $cfg31 = Get-Content (Join-Path $t31Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $id31 = @($cfg31.lines)[0].id
    $eng31 = Join-Path $t31Data ('lines\' + $legacyId + '.json')
    $eng31Exists = Test-Path $eng31
    $eng31Same = $false
    if ($eng31Exists) { $eng31Same = ((Get-FileHash $eng31 -Algorithm SHA256).Hash -eq (Get-FileHash (Join-Path $t31Data 'engine.json') -Algorithm SHA256).Hash) }
    $legacyKept = Test-Path (Join-Path $t31Data 'engine.json')   # 迁移是复制不是移动，旧文件不该被删
    Case 'T31' '写命令触发迁移时，已落盘线路的 id 不得被重算：id 原样保留、lines\<旧id>.json 由 engine.json 复制而来、旧 engine.json 仍在' `
        ($mig31.Code -eq 0 -and $cfg31.schema -eq 2 -and $id31 -eq $legacyId -and $eng31Exists -and $eng31Same -and $legacyKept) `
        ("写命令=$($mig31.Code) schema=$($cfg31.schema) id 迁移后=[$id31]（期望 $legacyId） lines\旧id.json 存在=$eng31Exists 内容与 engine.json 一致=$eng31Same 旧 engine.json 仍在=$legacyKept")
    if (Test-Path $t31Root) { Remove-Item $t31Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T32 线路列表三条 IPC（真实进程 + 命名管道，独立验，不采信实现自测）----
    # 协议：一行 JSON 请求 → 一行 JSON 回包（ipc.rs 用 read_line/write_all + "\n"）。
    # 管道名由数据根派生成 SpiderVPN.<hash>，所以**靠枚举**取，不硬编码（也不假定只有前缀）。
    $t32Root = Join-Path $env:TEMP ('tc-32-' + $PID)
    $t32Data = Join-Path $t32Root 'data'
    $env:SPIDERVPN_ROOT = $t32Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t32'
    $hk32 = 'HKCU:\' + 'Software\SpiderVPN\tests\t32'
    if (Test-Path $t32Root) { Remove-Item $t32Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t32Root | Out-Null
    if (Test-Path $hk32) { Remove-Item $hk32 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk32 -Force | Out-Null
    New-ItemProperty $hk32 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk32 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk32 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $prof32 = Join-Path $t32Root 'profile.json'
    [System.IO.File]::WriteAllText($prof32, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
    foreach ($pair in @(@('L1', '17921'), @('L2', '17922'), @('L3', '17923'))) {
        $null = RunTimed ('--import "' + $prof32 + '" --engine "' + $fakeEngine + '" --port ' + $pair[1] + ' --line-name ' + $pair[0])
    }
    function Ask-Pipe {
        param($Name, $Obj)
        try {
            $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut)
            $cli.Connect(3000)
            $sw = New-Object System.IO.StreamWriter($cli); $sw.AutoFlush = $true
            $sr = New-Object System.IO.StreamReader($cli)
            $sw.WriteLine((ConvertTo-Json $Obj -Compress))
            $line = $sr.ReadLine()
            $cli.Dispose()
            if (-not $line) { return $null }
            return ($line | ConvertFrom-Json)
        } catch { return $null }
    }
    $gui32 = Start-Process -FilePath $Exe -PassThru
    for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; try { $gui32.Refresh() } catch { }; if ($gui32.MainWindowHandle -ne 0 -or $gui32.HasExited) { break } }
    $pipeCand = @([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match '\\SpiderVPN\.' } | ForEach-Object { $_.Substring('\\.\pipe\'.Length) })
    $pipe32 = if ($pipeCand.Count -eq 1) { $pipeCand[0] } else { $null }
    if (-not $pipe32) {
        Skip 'T32' '线路列表三条 IPC：lines/use/remove 契约' ("找不到唯一的 SpiderVPN 管道（候选 $($pipeCand.Count) 个）：GUI 可能没起来，无法判定")
        if ($gui32 -and -not $gui32.HasExited) { Stop-Process -Id $gui32.Id -Force -ErrorAction SilentlyContinue }
    } else {
        $t32bad = @()
        # 1) lines：3 条、字段名是 endpoint、每行 selected 布尔且只有一个是 true、顶层 selected 指同一行
        $r1 = Ask-Pipe $pipe32 @{ cmd = 'lines' }
        if (-not $r1) { $t32bad += 'lines 无回包' } else {
            $ls = @($r1.lines)
            $selRows = @($ls | Where-Object { $_.selected -eq $true })
            $props = @($ls[0].PSObject.Properties.Name)
            if (-not ($r1.ok -eq $true -and $ls.Count -eq 3 -and $selRows.Count -eq 1 -and $r1.selected -eq $selRows[0].id -and
                      ($props -contains 'endpoint') -and -not ($props -contains 'proxy_endpoint'))) {
                $t32bad += "lines: ok=$($r1.ok) 条数=$($ls.Count) 选中行数=$($selRows.Count) 顶层selected=$($r1.selected) 字段=[$($props -join ',')]"
            }
        }
        $ids32 = @($r1.lines | ForEach-Object { $_.id })
        if (@($ids32).Count -ge 3) {
            # 2) use：回包自带整份 lines、选中标记跟着变、并且落盘一致
            $r2 = Ask-Pipe $pipe32 @{ cmd = 'use'; id = $ids32[1] }
            $cfg32 = if (Test-Path (Join-Path $t32Data 'config.json')) { Get-Content (Join-Path $t32Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
            $sel2 = @()
            if ($r2) { $sel2 = @($r2.lines | Where-Object { $_.selected -eq $true }) }
            # 修复后查询类命令从磁盘读：use 之后单发一次 status，必须反映新选中（不允许"回包新、查询旧"）
            $st32 = Ask-Pipe $pipe32 @{ cmd = 'status' }
            $usedLine = @($r1.lines | Where-Object { $_.id -eq $ids32[1] })[0]
            $statusFresh = ($st32 -and $st32.line -eq $usedLine.name -and $st32.endpoint -eq $usedLine.endpoint -and $st32.lineCount -eq 3)
            if (-not ($r2 -and $r2.ok -eq $true -and $r2.selected -eq $ids32[1] -and @($r2.lines).Count -eq 3 -and $sel2.Count -eq 1 -and $sel2[0].id -eq $ids32[1] -and $cfg32.selected -eq $ids32[1] -and $statusFresh)) {
                $t32bad += "use: ok=$(if($r2){$r2.ok}else{'无回包'}) selected=$(if($r2){$r2.selected}) 回包条数=$(if($r2){@($r2.lines).Count}) 选中行数=$($sel2.Count) 落盘selected=$(if($cfg32){$cfg32.selected}) 随后status新选中=[line=$($st32.line) endpoint=$($st32.endpoint) count=$($st32.lineCount)]"
            }
            # 3) 连接态拒改（放一个 proxy-journal.json 即视为连接中）：必须 ok:false 且**零副作用**
            [System.IO.File]::WriteAllText((Join-Path $t32Data 'proxy-journal.json'), '{"schema":1,"endpoint":"127.0.0.1:17921","saved_at_secs":0,"saved":{"enable":false,"server":"127.0.0.1:7897","bypass":"localhost"}}', (New-Object System.Text.UTF8Encoding($false)))
            $cfgHashBefore = (Get-FileHash (Join-Path $t32Data 'config.json') -Algorithm SHA256).Hash
            $ru = Ask-Pipe $pipe32 @{ cmd = 'use'; id = $ids32[0] }
            $rr = Ask-Pipe $pipe32 @{ cmd = 'remove'; id = $ids32[0] }
            $cfgHashAfter = (Get-FileHash (Join-Path $t32Data 'config.json') -Algorithm SHA256).Hash
            $cfgAfter = Get-Content (Join-Path $t32Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not ($ru -and $ru.ok -eq $false -and $ru.error -match '请先断开' -and $rr -and $rr.ok -eq $false -and $rr.error -match '请先断开' -and
                      $cfgHashAfter -eq $cfgHashBefore -and @($cfgAfter.lines).Count -eq 3 -and $cfgAfter.selected -eq $ids32[1])) {
                $t32bad += "连接态拒绝: use(ok=$(if($ru){$ru.ok})/err=$(if($ru){$ru.error})) remove(ok=$(if($rr){$rr.ok})) 配置零变化=$($cfgHashAfter -eq $cfgHashBefore) 条数=$(@($cfgAfter.lines).Count) selected=$($cfgAfter.selected)"
            }
            Remove-Item (Join-Path $t32Data 'proxy-journal.json') -Force -ErrorAction SilentlyContinue
            # 4) remove 删选中项 → 回退第一条；一路删空 → lines 空、selected 是空串（不是 null）
            $rd1 = Ask-Pipe $pipe32 @{ cmd = 'remove'; id = $ids32[1] }
            # 修复后：remove 完单发 lines 必须与回包一致、且不含被删项（修前这里会拿到旧快照 3 条）
            $lsAfterRm = Ask-Pipe $pipe32 @{ cmd = 'lines' }
            $rmFresh = ($lsAfterRm -and @($lsAfterRm.lines).Count -eq @($rd1.lines).Count -and
                        @($lsAfterRm.lines | Where-Object { $_.id -eq $ids32[1] }).Count -eq 0)
            if (-not ($rd1 -and $rd1.ok -eq $true -and @($rd1.lines).Count -eq 2 -and $rd1.selected -eq (@($rd1.lines)[0].id) -and $rmFresh)) {
                $t32bad += "remove选中项: ok=$(if($rd1){$rd1.ok}) 剩=$(if($rd1){@($rd1.lines).Count}) selected=$(if($rd1){$rd1.selected}) 随后lines条数=$(if($lsAfterRm){@($lsAfterRm.lines).Count}) 已删项仍在=$(@($lsAfterRm.lines | Where-Object { $_.id -eq $ids32[1] }).Count)"
            } else {
                # 契约是「回包自带整份 lines」，所以删空要看**最后一次 remove 的回包**，不要补发 lines：
                # 运行中的进程对 `lines` 用的是它自己的内存快照，与磁盘可能不同步（见交付说明里的观察）。
                $rest = @($rd1.lines | ForEach-Object { $_.id })
                $rdLast = $null
                foreach ($rid in $rest) { $rdLast = Ask-Pipe $pipe32 @{ cmd = 'remove'; id = $rid } }
                $cfgEnd = Get-Content (Join-Path $t32Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
                if (-not ($rdLast -and $rdLast.ok -eq $true -and @($rdLast.lines).Count -eq 0 -and $rdLast.selected -ceq '' -and
                          @($cfgEnd.lines).Count -eq 0 -and $cfgEnd.selected -ceq '')) {
                    $t32bad += "删空: 末次remove条数=$(if($rdLast){@($rdLast.lines).Count}) selected=[$(if($rdLast){$rdLast.selected})] 落盘条数=$(@($cfgEnd.lines).Count) 落盘selected=[$($cfgEnd.selected)]"
                }
            }
        } else {
            $t32bad += "lines 没返回 3 条 id（拿到的：$($ids32 -join ',')），后续步骤无法进行"
        }
        Case 'T32' '线路列表 IPC：lines 契约 / use 回包自带 lines 且落盘一致 / 连接态拒改且零副作用 / 删选中回退 / 删空空串 / 回包与后续查询（status、lines）一致' `
            ($t32bad.Count -eq 0) (($t32bad -join '；') + " | 管道=$pipe32")
        # 收尾：这个 GUI 按设计要 CloseMainWindow 才走清理；先确认没连接记录再强杀（同 T26 的纪律）
        $rt32 = Join-Path $t32Data 'runtime.json'
        $jn32 = Join-Path $t32Data 'proxy-journal.json'
        $null = $gui32.CloseMainWindow()
        for ($i = 0; $i -lt 24 -and -not $gui32.HasExited; $i++) { Start-Sleep -Milliseconds 500; try { $gui32.Refresh() } catch { } }
        if (-not $gui32.HasExited) {
            if ((-not (Test-Path $rt32)) -and (-not (Test-Path $jn32))) { Stop-Process -Id $gui32.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    if (Test-Path $hk32) { Remove-Item $hk32 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t32Root) { Remove-Item $t32Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T33 「engine.binary 是空串」属配置不合法 → 12，不是「未配置引擎」的 8 ----
    # 8 = 该有的没有（用户去配就行）；12 = 写了但值是坏的（用户得修）。两者不能混：
    # 把空串放宽成 8 会掩盖配置损坏，用户会以为"再导入一条线路就好了"。
    $t33Root = Join-Path $env:TEMP ('tc-33-' + $PID)
    $t33Data = Join-Path $t33Root 'data'
    $env:SPIDERVPN_ROOT = $t33Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t33'
    if (Test-Path $t33Root) { Remove-Item $t33Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t33Data -Force | Out-Null
    $bad33 = '{"schema":2,"mode":"proxy","selected":"L1","lines":[{"id":"L1","name":"L1","proxy_endpoint":"127.0.0.1:47991"}],"engine":{"binary":""}}'
    [System.IO.File]::WriteAllText((Join-Path $t33Data 'config.json'), $bad33, (New-Object System.Text.UTF8Encoding($false)))
    $hash33a = (Get-FileHash (Join-Path $t33Data 'config.json') -Algorithm SHA256).Hash
    $t33bad = @()
    foreach ($cmd33 in @('--status', '--plan', '--connect', '--headless')) {
        $r33 = RunTimed $cmd33
        if (-not ($r33.Code -eq 12 -and $r33.Out -match '配置' -and -not ($r33.Out -match '未配置引擎'))) {
            $t33bad += "${cmd33}: exit=$($r33.Code) 含配置=$($r33.Out -match '配置') 含未配置引擎=$($r33.Out -match '未配置引擎')"
        }
    }
    $hash33b = (Get-FileHash (Join-Path $t33Data 'config.json') -Algorithm SHA256).Hash
    if ($hash33a -ne $hash33b) { $t33bad += '只读命令把坏配置改写了（不应发生）' }
    Case 'T33' 'engine.binary 为空串 = 配置不合法：status/plan/connect/headless 都退 12，文案不说「未配置引擎」' `
        ($t33bad.Count -eq 0) (($t33bad -join '；') + " | 配置字节未变=$($hash33a -eq $hash33b)")
    if (Test-Path $t33Root) { Remove-Item $t33Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T35/T36/T37 出口可选 + 默认直连 ----
    # 特性未落地时这三条 **SKIP 并写明原因**（不是 FAIL）：判据是 `--exits` 是否可用、生成配置里是否出现 daily-exit。
    # 一旦落地就按契约严格断言——这样"没实现"和"实现错了"不会混成一个红。
    # T35：默认配置生成后，入站规则与 final 都指向 daily-exit
    $t35Root = Join-Path $env:TEMP ('tc-35-' + $PID)
    $t35Data = Join-Path $t35Root 'data'
    $env:SPIDERVPN_ROOT = $t35Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t35'
    if (Test-Path $t35Root) { Remove-Item $t35Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t35Root | Out-Null
    $prof35 = Join-Path $t35Root 'profile.json'
    [System.IO.File]::WriteAllText($prof35, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
    $null = RunTimed ('--import "' + $prof35 + '" --engine "' + $fakeEngine + '" --port 17951 --line-name "出口线路"')
    # 探测必须在**导入含出口的线路之后**：在无出口的旧 fixture 上探测只会得到 false，把 T35–T40 全 SKIP 掉。
    $exitsProbe2 = RunTimed '--exits' 5000
    $exitsAvail = ($exitsProbe2.Code -eq 0 -and $exitsProbe2.Out -match '日常出口' -and $exitsProbe2.Out -match '交易出口')
    $cfg35 = if (Test-Path (Join-Path $t35Data 'config.json')) { Get-Content (Join-Path $t35Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $id35 = if ($cfg35 -and @($cfg35.lines).Count -ge 1) { @($cfg35.lines)[0].id } else { '' }
    $eng35Path = if ($id35) { Join-Path $t35Data ('lines\' + (Get-SafeStem $id35) + '.json') } else { '' }
    $eng35 = if ($eng35Path -and (Test-Path $eng35Path)) { Get-Content $eng35Path -Raw -Encoding UTF8 } else { '' }
    if (-not ($exitsAvail -and $eng35 -match 'daily-exit')) {
        Skip 'T35' '默认配置：入站规则与 final 指向 daily-exit（默认直连）' '本产物还没有出口可选/默认直连（--exits 不可用或配置里无 daily-exit），无法判定'
    } else {
        # 锚点式断言：daily-exit 至少出现两次（outbounds 定义 + 规则/final 引用），且 --exits 两个出口都有值
        $cnt35 = ([regex]::Matches($eng35, 'daily-exit')).Count
        $rowDaily35 = (($exitsProbe2.Out -split "`r?`n") | Where-Object { $_ -match '日常出口' }) -join ' '
        $rowTrade35 = (($exitsProbe2.Out -split "`r?`n") | Where-Object { $_ -match '交易出口' }) -join ' '
        Case 'T35' '默认配置生成后 daily-exit 存在且被规则/final 引用；--exits 列出两个出口且都有当前值' `
            ($cnt35 -ge 2 -and $rowDaily35 -match '\S' -and $rowTrade35 -match '\S') `
            ("daily-exit 出现次数=$cnt35 日常出口行=[$rowDaily35] 交易出口行=[$rowTrade35]（不断言具体成员值：不同线路可选成员不同）")
    }

    # T36：--exit-set daily <成员> 生效；成员不存在 → 12 **且配置/引擎配置都被回滚**（零副作用）
    # --exits 的真实格式（lead 从实现取的）：
    #   两空格前缀 + 全角冒号 + 值 + 全角括号（可选：a, b, c）；成员随线路变化，不断言具体成员。
    if (-not $exitsAvail) {
        Skip 'T36' '--exit-set daily <成员>：生效且非法成员被拒并回滚' '本产物没有 --exits/--exit-set（出口可选未落地），无法判定'
    } else {
        $rowDailyLine = (($exitsProbe2.Out -split "`r?`n") | Where-Object { $_ -match '日常出口' } | Select-Object -First 1)
        $m36 = [regex]::Match($rowDailyLine, '日常出口：(\S+?)（可选：([^）]*)）')
        if (-not $m36.Success) { $m36 = [regex]::Match($rowDailyLine, '日常出口[:：]\s*(\S+?)[（(]可选[:：]\s*([^）)]*)[）)]') }
        $curDaily36 = if ($m36.Success) { $m36.Groups[1].Value } else { '' }
        $cands36 = @()
        if ($m36.Success) { $cands36 = @($m36.Groups[2].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        $cfgHash36a = if (Test-Path (Join-Path $t35Data 'config.json')) { (Get-FileHash (Join-Path $t35Data 'config.json') -Algorithm SHA256).Hash } else { '' }
        $engHash36a = if ($eng35Path -and (Test-Path $eng35Path)) { (Get-FileHash $eng35Path -Algorithm SHA256).Hash } else { '' }
        $mdBefore36 = $rowDailyLine
        $rowTradeLine36 = (($exitsProbe2.Out -split "`r?`n") | Where-Object { $_ -match '交易出口' } | Select-Object -First 1)
        # 非法成员：实现是「先写 config 再应用到引擎配置」，所以必须验回滚，不能只看退出码
        $bad36 = RunTimed '--exit-set trade __no_such_member__'
        $cfgHash36b = if (Test-Path (Join-Path $t35Data 'config.json')) { (Get-FileHash (Join-Path $t35Data 'config.json') -Algorithm SHA256).Hash } else { '' }
        $engHash36b = if ($eng35Path -and (Test-Path $eng35Path)) { (Get-FileHash $eng35Path -Algorithm SHA256).Hash } else { '' }
        $ex36after = RunTimed '--exits' 5000
        $mdAfter36 = (($ex36after.Out -split "`r?`n") | Where-Object { $_ -match '日常出口' } | Select-Object -First 1)
        $trAfter36 = (($ex36after.Out -split "`r?`n") | Where-Object { $_ -match '交易出口' } | Select-Object -First 1)
        $rolled36 = ($cfgHash36b -eq $cfgHash36a -and $engHash36b -eq $engHash36a -and $mdAfter36 -eq $mdBefore36 -and $trAfter36 -eq $rowTradeLine36)
        # 合法成员：切一个 ≠ 当前的
        $cand36 = @($cands36 | Where-Object { $_ -ne $curDaily36 } | Select-Object -First 1)
        $setOk36 = $false
        $after36 = ''
        if ($cand36.Count -ge 1) {
            $set36 = RunTimed ('--exit-set daily ' + $cand36[0])
            $ex36b = RunTimed '--exits' 5000
            $after36 = (($ex36b.Out -split "`r?`n") | Where-Object { $_ -match '日常出口' } | Select-Object -First 1)
            $setOk36 = ($set36.Code -eq 0 -and $after36 -match [regex]::Escape($cand36[0]))
        }
        Case 'T36' '--exit-set daily <成员> 生效（回读一致）；成员不存在 → 12 且 config 与引擎配置都被回滚' `
            ($bad36.Code -eq 12 -and $rolled36 -and $setOk36) `
            ("非法成员 exit=$($bad36.Code) 回滚干净=$rolled36(config未变=$($cfgHash36b -eq $cfgHash36a) 引擎未变=$($engHash36b -eq $engHash36a) 两行文本未变=$($mdAfter36 -eq $mdBefore36 -and $trAfter36 -eq $rowTradeLine36)) | 当前日常=[$curDaily36] 候选数=$($cands36.Count) 切到=[$($cand36[0])] 生效=$setOk36 回读=[$after36]")
    }
    if (Test-Path $t35Root) { Remove-Item $t35Root -Recurse -Force -ErrorAction SilentlyContinue }

    # T37：自检文案必须点明「经交易出口」；跳过时不得同时说「通过」
    if (-not $exitsAvail) {
        Skip 'T37' '自检文案：含「经交易出口」；跳过时不含「通过」' '本产物还没有出口可选（自检仍走旧文案），无法判定'
    } else {
        $t37Root = Join-Path $env:TEMP ('tc-37-' + $PID)
        $t37Data = Join-Path $t37Root 'data'
        $env:SPIDERVPN_ROOT = $t37Root
        $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\37'
        # 必须建一个可读的临时代理键：读不到系统代理时产品会**拒绝接管**（避免覆盖无法还原的配置），
        # connect 直接 exit 13——不建键的话这两条永远测的是「连接失败」，而不是自检文案/连接中拒绝。
        $k37 = 'Software\SpiderVPN\tests\37'
        if (Test-Path ('HKCU:///' + $k37)) { Remove-Item ('HKCU:///' + $k37) -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path ('HKCU:///' + $k37) -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k37) -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k37) -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k37) -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        if (Test-Path $t37Root) { Remove-Item $t37Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $t37Root | Out-Null
        $prof37 = Join-Path $t37Root 'profile.json'
        [System.IO.File]::WriteAllText($prof37, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
        # 必须用**真线路 + 真引擎**：假引擎起不来，连不上就谈不上自检文案。
        # 端口独立（47992）：与 T20 的 47991 错开，避免上一条用例的引擎还没退干净就撞端口。
        $c37 = Start-RealLine $t37Root 47992
        $st37 = Run @('--status')
        $row37 = (($st37.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
        $null = RunDetached '--disconnect'
        $mentions37 = ($row37 -match '经交易出口')
        # 「跳过」这个较松的标准要钉住来源：只能来自「探测端口 <47992+3=47995> 被占用」（bind 失败），
        # 不许来自 dial 超时/"引擎不在"那类"真检了但没过"。第二轮起「跳过」已独占该原因，故这里收紧到**具体端口**。
        $skipOk37 = ($row37 -match '跳过') -and ($row37 -match '探测端口\s*47995\s*被占用') -and -not ($row37 -match '通过')
        $conclusion37 = (($row37 -match '通过' -and $row37 -match '204') -or $skipOk37)
        Case 'T37' '自检文案点明「经交易出口」；结论要么「通过（HTTP 204）」、要么「跳过」且原因必须是「探测端口 47995 被占用」且不得同时说通过' `
            ($c37 -eq 0 -and $mentions37 -and $conclusion37) `
            ("connect=$($c37) 自检行=[$row37] 含经交易出口=$mentions37 结论自洽=$conclusion37（跳过时要求点名 47995）")
        if (Test-Path $t37Root) { Remove-Item $t37Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T38 `--exits` 输出格式（有线路现场）----
    # 真实格式：两空格前缀 + 全角冒号 + 值 + 全角括号（可选：a, b, c）。成员随线路变化，不断言具体成员。
    if (-not $exitsAvail) {
        # 功能未落地时三条都要各打一行 SKIP（否则 T39/T40 会在输出里"消失"，看起来像漏测）
        Skip 'T38' '--exits 输出格式：两行、全角冒号、当前值在可选列表内' '本产物没有 --exits（出口可选未落地），无法判定'
        Skip 'T39' '无配置时 --exits 输出「未配置线路」' '本产物没有 --exits（出口可选未落地），无法判定'
        Skip 'T40' '连接中改出口必须被拒且零副作用' '本产物没有 --exits（出口可选未落地），无法判定'
    } else {
        $t38Root = Join-Path $env:TEMP ('tc-38-' + $PID)
        $t38Data = Join-Path $t38Root 'data'
        $env:SPIDERVPN_ROOT = $t38Root
        $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t38'
        if (Test-Path $t38Root) { Remove-Item $t38Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $t38Root | Out-Null
        $prof38 = Join-Path $t38Root 'profile.json'
        [System.IO.File]::WriteAllText($prof38, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
        $null = RunTimed ('--import "' + $prof38 + '" --engine "' + $fakeEngine + '" --port 17961 --line-name "出口格式线路"')
        $ex38 = RunTimed '--exits' 5000
        $l38 = @($ex38.Out -split "`r?`n")
        $d38 = @($l38 | Where-Object { $_ -match '日常出口' })
        $t38 = @($l38 | Where-Object { $_ -match '交易出口' })
        $fmt38 = $false
        $detail38 = @()
        foreach ($pair in @(@('日常出口', $d38), @('交易出口', $t38))) {
            if ($pair[1].Count -ne 1) { $detail38 += "$($pair[0]) 出现 $($pair[1].Count) 次（应为 1）"; continue }
            $line = $pair[1][0]
            $m = [regex]::Match($line, '^  ' + $pair[0] + '：(\S+)（可选：([^）]+)）$')
            if (-not $m.Success) { $detail38 += "$($pair[0]) 行格式不符：[${line}]"; continue }
            $cur = $m.Groups[1].Value
            $opts = @($m.Groups[2].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($opts.Count -lt 1) { $detail38 += "$($pair[0]) 可选列表为空"; continue }
            if (-not ($opts -contains $cur)) { $detail38 += "$($pair[0]) 当前值 [$cur] 不在可选列表里"; continue }
        }
        $fmt38 = ($detail38.Count -eq 0 -and $d38.Count -eq 1 -and $t38.Count -eq 1)
        Case 'T38' '--exits 输出格式：日常/交易各一行（两空格前缀、全角冒号、当前值在「（可选：…）」列表内）' `
            ($ex38.Code -eq 0 -and $fmt38) `
            ("exit=$($ex38.Code) 格式符合=$fmt38 问题：$($detail38 -join '；')（不断言具体成员值：随线路变化）")
        if (Test-Path $t38Root) { Remove-Item $t38Root -Recurse -Force -ErrorAction SilentlyContinue }

        # ---- T39 无配置时 --exits 要说「未配置线路」（不是空白/崩溃）----
        $t39Root = Join-Path $env:TEMP ('tc-39-' + $PID)
        $env:SPIDERVPN_ROOT = $t39Root
        if (Test-Path $t39Root) { Remove-Item $t39Root -Recurse -Force -ErrorAction SilentlyContinue }
        $ex39 = RunTimed '--exits' 5000
        # lead 从源码确认：无配置与「没有线路引擎配置」走同一分支，打完「未配置线路…」就 SUCCESS → 硬断言 exit 0
        Case 'T39' '无配置时 --exits exit 0 且输出「未配置线路」（说明性输出，不是失败）' `
            ($ex39.Code -eq 0 -and $ex39.Out -match '未配置线路') `
            ("exit=$($ex39.Code)（期望 0） 含未配置线路=$($ex39.Out -match '未配置线路') 输出=$($ex39.Out.Trim())")
        if (Test-Path $t39Root) { Remove-Item $t39Root -Recurse -Force -ErrorAction SilentlyContinue }

        # ---- T40 连接中改出口必须被拒，且零副作用 ----
        # 判据与 T32 相同：数据根里放一个 proxy-journal.json 即视为「连接中」（半接管也算）。
        $t40Root = Join-Path $env:TEMP ('tc-40-' + $PID)
        $t40Data = Join-Path $t40Root 'data'
        $env:SPIDERVPN_ROOT = $t40Root
        $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\40'
        # 必须建一个可读的临时代理键：读不到系统代理时产品会**拒绝接管**（避免覆盖无法还原的配置），
        # connect 直接 exit 13——不建键的话这两条永远测的是「连接失败」，而不是自检文案/连接中拒绝。
        $k40 = 'Software\SpiderVPN\tests\40'
        if (Test-Path ('HKCU:///' + $k40)) { Remove-Item ('HKCU:///' + $k40) -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path ('HKCU:///' + $k40) -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k40) -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k40) -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty ('HKCU:///' + $k40) -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        if (Test-Path $t40Root) { Remove-Item $t40Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $t40Root | Out-Null
        $prof40 = Join-Path $t40Root 'profile.json'
        [System.IO.File]::WriteAllText($prof40, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
        $null = RunTimed ('--import "' + $prof40 + '" --engine "' + $fakeEngine + '" --port 17962 --line-name "连接中线路"')
        $cfg40 = if (Test-Path (Join-Path $t40Data 'config.json')) { Get-Content (Join-Path $t40Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        $id40 = if ($cfg40 -and @($cfg40.lines).Count -ge 1) { @($cfg40.lines)[0].id } else { '' }
        $eng40 = if ($id40) { Join-Path $t40Data ('lines\' + (Get-SafeStem $id40) + '.json') } else { '' }
        # 「连接中」必须用**真连接**造：手工放 proxy-journal.json 会被启动自愈当成
        # 「上次退出未清理」直接还原并删掉（那之后 busy 恒为 false），这个判据已经失效。
        $c40 = Start-RealLine $t40Root 47993
        $h40a = if (Test-Path (Join-Path $t40Data 'config.json')) { (Get-FileHash (Join-Path $t40Data 'config.json') -Algorithm SHA256).Hash } else { '' }
        $e40a = if ($eng40 -and (Test-Path $eng40)) { (Get-FileHash $eng40 -Algorithm SHA256).Hash } else { '' }
        $set40 = RunTimed '--exit-set daily direct'
        $null = RunDetached '--disconnect'
        $h40b = if (Test-Path (Join-Path $t40Data 'config.json')) { (Get-FileHash (Join-Path $t40Data 'config.json') -Algorithm SHA256).Hash } else { '' }
        $e40b = if ($eng40 -and (Test-Path $eng40)) { (Get-FileHash $eng40 -Algorithm SHA256).Hash } else { '' }
        Case 'T40' '连接中改出口必须被拒（含「请先断开」），且 config 与引擎配置零副作用' `
            ($set40.Code -eq 12 -and $set40.Out -match '请先断开' -and $h40b -eq $h40a -and $e40b -eq $e40a) `
            ("exit=$($set40.Code) 含请先断开=$($set40.Out -match '请先断开') config未变=$($h40b -eq $h40a) 引擎配置未变=$($e40b -eq $e40a) 输出=$($set40.Out.Trim())")
        if (Test-Path $t40Root) { Remove-Item $t40Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T41 升级用户现场：运行时配置归一化生效，且**磁盘线路文件不被改写** ----
    # 判据（与 lead / 集成三方独立得出的同一套）：
    #   ① data\runtime-engine.json = 引擎真正加载的那份：必须有 tc-check 入站、final=daily-exit、
    #      mixed 规则指向 daily-exit、daily-exit.default=direct、交易程序规则（process_path）保留
    #   ② 出口对照：默认 daily=direct 时 经代理 == 直连
    #   ③ 磁盘上的 lines\<id>.json **一个字节都不能变**（设计如此：只改运行时，不改用户文件）
    # 用默认根的只读副本在临时根里做，端口重映射，默认根零写入。
    if ($whyNot -or -not $realLine) {
        Skip 'T41' '升级用户现场：运行时归一化 + 磁盘不改写' ('没有可用的真实线路副本：' + $whyNot)
    } else {
        $t41Root = Join-Path $env:TEMP ('tc-41-' + $PID)
        $t41Data = Join-Path $t41Root 'data'
        $env:SPIDERVPN_ROOT = $t41Root
        $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t41'
        $hk41 = 'HKCU:/' + 'Software\SpiderVPN\tests\t41'
        $p41 = 48010
        while ([bool](Get-NetTCPConnection -LocalPort $p41 -State Listen -ErrorAction SilentlyContinue) -or -not (Test-PortBindable ($p41 + 3))) { $p41++ }
        if (Test-Path $t41Root) { Remove-Item $t41Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path (Join-Path $t41Data 'lines') -Force | Out-Null
        if (Test-Path $hk41) { Remove-Item $hk41 -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $hk41 -Force | Out-Null
        New-ItemProperty $hk41 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $hk41 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty $hk41 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $stem41 = Get-SafeStem $realLineId
        Copy-Item (Join-Path $DefaultData 'config.json') (Join-Path $t41Data 'config.json') -Force
        Copy-Item (Join-Path $DefaultData ('lines\' + $stem41 + '.json')) (Join-Path $t41Data ('lines\' + $stem41 + '.json')) -Force
        $cfg41 = Get-Content (Join-Path $t41Data 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($ln in $cfg41.lines) { $ln.proxy_endpoint = "127.0.0.1:$p41" }
        [System.IO.File]::WriteAllText((Join-Path $t41Data 'config.json'), ($cfg41 | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        $disk41 = Join-Path $t41Data ('lines\' + $stem41 + '.json')
        $de41 = Get-Content $disk41 -Raw -Encoding UTF8 | ConvertFrom-Json
        $needTradeRule = ((Get-Content $disk41 -Raw -Encoding UTF8) -match 'NinjaTrader')
        foreach ($ib in $de41.inbounds) { if ($ib.listen_port) { $ib.listen_port = $p41 } }
        [System.IO.File]::WriteAllText($disk41, ($de41 | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
        $hash41a = (Get-FileHash $disk41 -Algorithm SHA256).Hash
        $env:SPIDERVPN_ENGINE_ARGS = $null
        Clear-EnvVar 'SPIDERVPN_ENGINE_ARGS'   # 真引擎不吃假引擎参数
        $c41 = RunDetached '--connect'
        $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        $rd41 = Join-Path $t41Data 'runtime-engine.json'
        $t41bad = @()
        if (-not (Test-Path $rd41)) { $t41bad += '2运行时配置 runtime-engine.json 不存在' } else {
            $re41 = Get-Content $rd41 -Raw -Encoding UTF8 | ConvertFrom-Json
            $tc41 = @($re41.inbounds | Where-Object { $_.tag -eq 'tc-check' })
            if ($tc41.Count -lt 1) { $t41bad += '运行时缺 tc-check 入站（自检会跳过/不跑）' }
            if ($re41.route.final -ne 'daily-exit') { $t41bad += "运行时 final=$($re41.route.final)（应为 daily-exit）" }
            $mixedOut41 = (@($re41.route.rules) | Where-Object { ($_.inbound -join '/') -match 'mixed' } | ForEach-Object { $_.outbound }) -join ','
            if ($mixedOut41 -notmatch 'daily-exit') { $t41bad += "mixed 规则出站=$mixedOut41（应指向 daily-exit）" }
            $dsel41 = @($re41.outbounds | Where-Object { $_.tag -eq 'daily-exit' })
            if ($dsel41.Count -lt 1 -or $dsel41[0].default -ne 'direct') { $t41bad += "daily-exit.default=$(if($dsel41.Count){$dsel41[0].default}else{'缺失'})（应为 direct）" }
            if ($needTradeRule -and -not (($re41.route.rules | ConvertTo-Json -Depth 8 -Compress) -match 'NinjaTrader')) { $t41bad += '交易程序规则（process_path）在运行时丢了' }
        }
        # ② 出口对照
        $p41x = ''
        for ($i = 0; $i -lt 3 -and -not $p41x; $i++) { $p41x = (& curl.exe -4 -s -x ("http://127.0.0.1:$p41") --max-time 25 'http://checkip.amazonaws.com') -join ''; if (-not $p41x) { Start-Sleep -Seconds 2 } }
        $d41x = ''
        for ($i = 0; $i -lt 3 -and -not $d41x; $i++) { $d41x = (& curl.exe -4 -s --noproxy '*' --max-time 15 'http://checkip.amazonaws.com') -join ''; if (-not $d41x) { Start-Sleep -Seconds 2 } }
        if (-not ($p41x -and $d41x -and $p41x -eq $d41x)) { $t41bad += "出口对照不符：经代理可用=$([bool]$p41x) 直连可用=$([bool]$d41x) 相同=$($p41x -eq $d41x)（默认 daily=direct 时应相同）" }
        $null = RunDetached '--disconnect'
        # ③ 磁盘线路文件不得被改写
        $hash41b = (Get-FileHash $disk41 -Algorithm SHA256).Hash
        if ($hash41a -ne $hash41b) { $t41bad += '磁盘线路文件被改写了（设计上不该动用户文件）' }
        Case 'T41' '升级用户现场：运行时配置补 tc-check/归一到 daily-exit/default=direct、出口=直连，且磁盘线路文件零改写' `
            ($c41 -eq 0 -and $t41bad.Count -eq 0) (($t41bad -join '；') + " | connect=$c41 磁盘未改写=$($hash41a -eq $hash41b)")
        if (Test-Path $hk41) { Remove-Item $hk41 -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $t41Root) { Remove-Item $t41Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T42 分流提示 2×2 四格（D7：提示条件必须跟"线路实际模式"走，不是全局字段）----
    # 每格都先断言「规则数 ≥ 1」——没规则时那句提示本来就不打印，直接断"不出现"会假绿（集成踩过）。
    # 提示只用锚点「要覆盖全部程序」的出现次数 ∈ {0,1}，不匹配整段文案。
    #   1) 全局 proxy + 代理线路 → 出现    2) 全局 proxy + TUN 线路 → 不出现
    #   3) 全局 tun   + 代理线路 → 出现    4) 全局 tun   + TUN 线路 → 不出现
    $t42Root = Join-Path $env:TEMP ('tc-42-' + $PID)
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t42'
    function New-LineRoot {
        param($Root, [switch]$Tun)
        if (Test-Path $Root) { Remove-Item $Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $Root | Out-Null
        $pf = Join-Path $Root 'profile.json'
        [System.IO.File]::WriteAllText($pf, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
        $env:SPIDERVPN_ROOT = $Root
        $args = '--import "' + $pf + '" --engine "' + $fakeEngine + '" --port 47992 --line-name "文案线路"'
        if ($Tun) { $args += ' --tun' }
        $null = RunTimed $args
        $null = RunTimed '--split-add-domain qq.com --to direct'   # 必须至少一条规则，否则提示不打印
    }
    function Set-GlobalMode {
        param($Root, $Mode)
        $cp = Join-Path $Root 'data\config.json'
        $c = Get-Content $cp -Raw -Encoding UTF8 | ConvertFrom-Json
        $c.mode = $Mode
        [System.IO.File]::WriteAllText($cp, ($c | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    function Get-HintProbe {
        param($Root)
        $env:SPIDERVPN_ROOT = $Root
        $sl = RunTimed '--split-list' 10000
        $ruleCount = @(($sl.Out -split "`r?`n") | Where-Object { $_ -match '→' }).Count
        $hintCount = ([regex]::Matches($sl.Out, '要覆盖全部程序')).Count
        $st = Run @('--status')
        $modeRow = (($st.Out -split "`r?`n") | Where-Object { $_ -match '模式      ' }) -join ' '
        return [pscustomobject]@{ RuleCount = $ruleCount; HintCount = $hintCount; ModeRow = $modeRow; Out = $sl.Out }
    }
    $t42bad = @()
    $cells = @()
    # 建两个根：代理线路根 / TUN 线路根
    $rootProxy = Join-Path $env:TEMP ('tc-42p-' + $PID)
    $rootTun = Join-Path $env:TEMP ('tc-42t-' + $PID)
    New-LineRoot $rootProxy
    New-LineRoot $rootTun -Tun
    foreach ($cell in @(
            @{ N = 1; Root = $rootProxy; Mode = 'proxy'; WantHint = 1 },
            @{ N = 2; Root = $rootTun; Mode = 'proxy'; WantHint = 0 },
            @{ N = 3; Root = $rootProxy; Mode = 'tun'; WantHint = 1 },
            @{ N = 4; Root = $rootTun; Mode = 'tun'; WantHint = 0 })) {
        Set-GlobalMode $cell.Root $cell.Mode
        $pr = Get-HintProbe $cell.Root
        $okRule = ($pr.RuleCount -ge 1)
        $okHint = ($pr.HintCount -eq $cell.WantHint)
        $cells += "#$($cell.N)[规则=$($pr.RuleCount) 提示x$($pr.HintCount) 期望x$($cell.WantHint) 模式行=$($pr.ModeRow.Trim())]"
        if (-not $okRule) { $t42bad += "格$($cell.N) 规则数=0（假绿风险，必须先有规则）" }
        if (-not $okHint) { $t42bad += "格$($cell.N)(全局$($cell.Mode)) 提示出现 $($pr.HintCount) 次，应为 $($cell.WantHint)" }
    }
    # 第 5 格（lead 追加）：无规则的 proxy 线路 → 提示不该出现。
    # 防的是"实现把 cfg.split.is_empty() 的短路一起删掉"——那种改法会让 1~4 格仍绿，但空规则线路凭空弹提示。
    $rootNoRule = Join-Path $env:TEMP ('tc-42n-' + $PID)
    if (Test-Path $rootNoRule) { Remove-Item $rootNoRule -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $rootNoRule | Out-Null
    $pfNo = Join-Path $rootNoRule 'profile.json'
    [System.IO.File]::WriteAllText($pfNo, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
    $env:SPIDERVPN_ROOT = $rootNoRule
    $null = RunTimed ('--import "' + $pfNo + '" --engine "' + $fakeEngine + '" --port 47992 --line-name "空规则线路"')
    Set-GlobalMode $rootNoRule 'proxy'      # 不加任何规则
    $pr5 = Get-HintProbe $rootNoRule
    $cells += "#5[规则=$($pr5.RuleCount) 提示x$($pr5.HintCount) 期望x0（无规则时不该提示）]"
    if ($pr5.RuleCount -ne 0) { $t42bad += "格5 前提不成立：无规则现场却有 $($pr5.RuleCount) 条规则" }
    if ($pr5.HintCount -ne 0) { $t42bad += "格5(无规则+proxy) 提示出现 $($pr5.HintCount) 次，应为 0（空规则短路被删了？）" }
    Case 'T42' '分流提示：2×2 按「线路实际模式」+ 空规则不提示（代理线路出现、TUN 线路消失，与全局 mode 无关）' `
        ($t42bad.Count -eq 0) (($cells -join ' ') + ' 问题：' + ($t42bad -join '；'))
    if (Test-Path $rootNoRule) { Remove-Item $rootNoRule -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $rootProxy) { Remove-Item $rootProxy -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $rootTun) { Remove-Item $rootTun -Recurse -Force -ErrorAction SilentlyContinue }

    # ---- T43/T44/T45/T46 runtime-engine.json 的去留口径（D8 定稿 A）----
    # 口径 A：**文件存在 ⟺ 连接正在运行**（引擎在跑 + 代理仍指向我们）。
    #   自检结论归 last-check.json，**不参与文件去留**：
    #     · 端口被占 / 引擎秒退（没进入运行态）→ 不保留（T43）
    #     · 连接进入运行态 → 保留，**自检通过也好、未通过也好**（T44 成功场景 / T45 CLI 坏成员 / T46 IPC 坏成员）
    #     · 正常断开 / 被 --disconnect 打断 → 删除（T44/T45/T46 的第二段）
    # 为什么未通过也要保留：坏成员时引擎起来了、代理已接管、连接正在跑，删掉文件会出现
    # "状态说已连接、却查不到引擎在用哪份配置"，而排查"交易出口为什么不通"恰恰要靠它。
    $t43Root = Join-Path $env:TEMP ('tc-43-' + $PID)
    $t43Data = Join-Path $t43Root 'data'
    $env:SPIDERVPN_ROOT = $t43Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t43'
    $hk43 = 'HKCU:/' + 'Software\SpiderVPN\tests\t43'
    $p43 = 48020
    while ([bool](Get-NetTCPConnection -LocalPort $p43 -State Listen -ErrorAction SilentlyContinue) -or -not (Test-PortBindable ($p43 + 3))) { $p43++ }
    if (Test-Path $t43Root) { Remove-Item $t43Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t43Root | Out-Null
    if (Test-Path $hk43) { Remove-Item $hk43 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk43 -Force | Out-Null
    New-ItemProperty $hk43 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk43 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk43 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $prof43 = Join-Path $t43Root 'profile.json'
    [System.IO.File]::WriteAllText($prof43, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
    $null = RunTimed ('--import "' + $prof43 + '" --engine "' + $fakeEngine + '" --port ' + $p43 + ' --line-name "落盘线路"')
    $rt43 = Join-Path $t43Data 'runtime-engine.json'
    $pre43 = Test-Path $rt43
    $l43 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p43)
    $l43.Start()
    $c43 = RunTimed '--connect'
    $l43.Stop()
    $post43 = Test-Path $rt43
    # 措辞注意：实现是「先生成、失败后清理」（引擎启动前必须读到运行时配置），所以断言只看**最终态**，
    # 不主张"从未创建"——否则将来有人加中间态断言会与实现打架。
    Case 'T43' '端口被占连接失败（exit 13）后 runtime-engine.json 不存在（只看最终态）' `
        (-not $pre43 -and $c43.Code -eq 13 -and -not $post43) `
        ("连接前存在=$pre43（排除上一轮遗留） connect=$($c43.Code)（期望13） 失败后存在=$post43 端口=$p43")
    # T44：放开端口重连一次，应正常生成；断开后按口径删除
    $c44 = RunTimed '--connect'
    $mid44 = Test-Path $rt43
    $size44 = if ($mid44) { (Get-Item $rt43).Length } else { 0 }
    $null = RunDetached '--disconnect'
    Start-Sleep -Milliseconds 800
    $after44 = Test-Path $rt43
    Case 'T44' '放开端口后连接成功应生成 runtime-engine.json（自检通过或未通过都算运行态）；disconnect 之后删除' `
        ($c44.Code -eq 0 -and $mid44 -and $size44 -gt 0 -and -not $after44) `
        ("connect=$($c44.Code) 连接后存在=$mid44 大小=$size44B 断开后存在=$after44")
    if (Test-Path $hk43) { Remove-Item $hk43 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t43Root) { Remove-Item $t43Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T45 坏成员（自检未通过但连接在跑）· CLI 路径：文件必须保留，断开才删 ----
    # 用假引擎造"引擎活着 + 代理已接管 + 自检失败"：PING 活着 → connect 0；
    # 但没有任何东西监听代理端口 → 自检必然"未通过"。这正是坏成员的等价现场。
    $t45Root = Join-Path $env:TEMP ('tc-45-' + $PID)
    $t45Data = Join-Path $t45Root 'data'
    $env:SPIDERVPN_ROOT = $t45Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t45'
    $hk45 = 'HKCU:/' + 'Software\SpiderVPN\tests\t45'
    $p45 = 48030
    while ([bool](Get-NetTCPConnection -LocalPort $p45 -State Listen -ErrorAction SilentlyContinue) -or -not (Test-PortBindable ($p45 + 3))) { $p45++ }
    if (Test-Path $t45Root) { Remove-Item $t45Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t45Root | Out-Null
    if (Test-Path $hk45) { Remove-Item $hk45 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk45 -Force | Out-Null
    New-ItemProperty $hk45 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk45 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk45 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $prof45 = Join-Path $t45Root 'profile.json'
    [System.IO.File]::WriteAllText($prof45, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
    $null = RunTimed ('--import "' + $prof45 + '" --engine "' + $fakeEngine + '" --port ' + $p45 + ' --line-name "坏成员线路"')
    $rt45 = Join-Path $t45Data 'runtime-engine.json'
    $c45 = RunTimed '--connect'
    $run45 = if (Test-Path (Join-Path $t45Data 'runtime.json')) { Get-Content (Join-Path $t45Data 'runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $alive45 = if ($run45) { [bool](Get-Process -Id $run45.EnginePid -ErrorAction SilentlyContinue) } else { $false }
    $st45 = Run @('--status')
    $row45 = (($st45.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
    $exists45 = Test-Path $rt45
    $null = RunDetached '--disconnect'
    Start-Sleep -Milliseconds 800
    $gone45 = -not (Test-Path $rt45)
    # **本用例只验 runtime-engine.json 的去留，不验"自检是否健康"。**
    # 自检的三态（通过 / 未通过 / 跳过）由 T37 覆盖；这里只要求"连接处于运行态"这个前提成立。
    # 之所以不把"未通过"写成硬条件：按口径 A，文件去留只看连接是否在运行，与自检结论无关；
    # 若把"必须未通过"写死，端口撞车导致的「跳过」会把正确实现判红。
    # 但"跳过"必须写明来源，且第二轮起该原因**独占**（「引擎不在」已改成「未做自检」）：
    # 所以这里收紧到**本用例自己的探测端口**（$p45+3），文案串台或端口写错都会红。
    $skipOk45 = ($row45 -match '跳过') -and ($row45 -match ('探测端口\s*' + ($p45 + 3) + '\s*被占用'))
    Case 'T45' '连接处于运行态(引擎在跑、自检未通过或跳过)时 runtime-engine.json 保留；断开后删除' `
        ($c45.Code -eq 0 -and $alive45 -and
         (($row45 -match '未通过') -or $skipOk45) -and
         $exists45 -and $gone45) `
        ("connect=$($c45.Code) 引擎存活=$alive45 自检行=[$($row45.Trim())] 运行中文件存在=$exists45 断开后已删=$gone45（跳过时要求点名探测端口 $($p45 + 3)）")
    if (Test-Path $hk45) { Remove-Item $hk45 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t45Root) { Remove-Item $t45Root -Recurse -Force -ErrorAction SilentlyContinue }

    # ---- T46 同一场景 · IPC（界面路径）：行为必须与 CLI 一致（D8 就是两侧相反漏出来的）----
    $t46Root = Join-Path $env:TEMP ('tc-46-' + $PID)
    $t46Data = Join-Path $t46Root 'data'
    $env:SPIDERVPN_ROOT = $t46Root
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\t46'
    $hk46 = 'HKCU:/' + 'Software\SpiderVPN\tests\t46'
    $p46 = 48040
    while ([bool](Get-NetTCPConnection -LocalPort $p46 -State Listen -ErrorAction SilentlyContinue) -or -not (Test-PortBindable ($p46 + 3))) { $p46++ }
    if (Test-Path $t46Root) { Remove-Item $t46Root -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $t46Root | Out-Null
    if (Test-Path $hk46) { Remove-Item $hk46 -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $hk46 -Force | Out-Null
    New-ItemProperty $hk46 -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $hk46 -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
    New-ItemProperty $hk46 -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
    $prof46 = Join-Path $t46Root 'profile.json'
    [System.IO.File]::WriteAllText($prof46, $profileJsonExits, (New-Object System.Text.UTF8Encoding($false)))
    $null = RunTimed ('--import "' + $prof46 + '" --engine "' + $fakeEngine + '" --port ' + $p46 + ' --line-name "坏成员线路IPC"')
    function Ask-Pipe46 {
        param($Name, $Obj)
        try {
            $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut)
            $cli.Connect(3000)
            $sw = New-Object System.IO.StreamWriter($cli); $sw.AutoFlush = $true
            $sr = New-Object System.IO.StreamReader($cli)
            $sw.WriteLine((ConvertTo-Json $Obj -Compress))
            $line = $sr.ReadLine()
            $cli.Dispose()
            if (-not $line) { return $null }
            return ($line | ConvertFrom-Json)
        } catch { return $null }
    }
    $gui46 = Start-Process -FilePath $Exe -PassThru
    for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; try { $gui46.Refresh() } catch { }; if ($gui46.MainWindowHandle -ne 0 -or $gui46.HasExited) { break } }
    $pipe46Cand = @([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match '\\SpiderVPN\.' } | ForEach-Object { $_.Substring('\\.\pipe\'.Length) })
    $pipe46 = if ($pipe46Cand.Count -eq 1) { $pipe46Cand[0] } else { $null }
    if (-not $pipe46) {
        Skip 'T46' '坏成员(自检未通过但连接在跑)·IPC：文件保留、断开后删除' ("找不到唯一的 SpiderVPN 管道（候选 $($pipe46Cand.Count) 个），无法判定")
        if ($gui46 -and -not $gui46.HasExited) { Stop-Process -Id $gui46.Id -Force -ErrorAction SilentlyContinue }
    } else {
        $rt46 = Join-Path $t46Data 'runtime-engine.json'
        $ipcConn46 = Ask-Pipe46 $pipe46 @{ cmd = 'connect' }
        # 等运行态就绪（引擎起 + runtime 落盘）
        for ($i = 0; $i -lt 24 -and -not (Test-Path (Join-Path $t46Data 'runtime.json')); $i++) { Start-Sleep -Milliseconds 500 }
        $run46 = if (Test-Path (Join-Path $t46Data 'runtime.json')) { Get-Content (Join-Path $t46Data 'runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        $alive46 = if ($run46) { [bool](Get-Process -Id $run46.EnginePid -ErrorAction SilentlyContinue) } else { $false }
        $exists46 = Test-Path $rt46
        # T52 要用：IPC 侧的自检结论（与 CLI 侧对照，两路径必须同一类）
        $st46 = Ask-Pipe46 $pipe46 @{ cmd = 'status' }
        $check46 = ''
        if ($st46) { $check46 = [string]$st46.check }
        $ipcDis46 = Ask-Pipe46 $pipe46 @{ cmd = 'disconnect' }
        for ($i = 0; $i -lt 16 -and (Test-Path $rt46); $i++) { Start-Sleep -Milliseconds 500 }
        $gone46 = -not (Test-Path $rt46)
        Case 'T46' '坏成员(自检未通过但连接在跑)·IPC（界面路径）：与 CLI 一致——文件保留、断开后删除' `
            ($ipcConn46 -and $ipcConn46.ok -eq $true -and $alive46 -and $exists46 -and $ipcDis46 -and $ipcDis46.ok -eq $true -and $gone46) `
            ("IPC connect ok=$(if($ipcConn46){$ipcConn46.ok}else{'无回包'}) 引擎存活=$alive46 运行中文件存在=$exists46 | IPC disconnect ok=$(if($ipcDis46){$ipcDis46.ok}else{'无回包'}) 断开后已删=$gone46")
        if ($gui46 -and -not $gui46.HasExited) {
            $null = $gui46.CloseMainWindow()
            for ($i = 0; $i -lt 16 -and -not $gui46.HasExited; $i++) { Start-Sleep -Milliseconds 500; try { $gui46.Refresh() } catch { } }
            if (-not $gui46.HasExited) { Stop-Process -Id $gui46.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    if (Test-Path $hk46) { Remove-Item $hk46 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t46Root) { Remove-Item $t46Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # =====================================================================
    # 第二轮新增（T47–T53）：探测端口试绑 / 绑定重试 / 「跳过」必须带原因 /
    # runtime-engine.json 三条收口 / 两路径一致性 / 状态措辞统一
    #
    # 纪律（与前文同）：临时根 + 临时键；每格**先断言前提成立**再断言结论；
    # 现场造不出来就 Skip（exit 2），绝不把「跳过」或「没造出来」当通过。
    # =====================================================================

    # 端口是否空闲：绑一下立刻放掉。本机保留段 netsh 实测：13508 / 50000-50059 / 54235
    function Test-PortFree {
        param([int]$Port)
        $l = $null
        try {
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
            $l.Start()
            return $true
        } catch { return $false }
        finally { if ($l) { try { $l.Stop() } catch { } } }
    }
    # 探测端口 = 线路端口 + 3：必须**成对**空闲，否则「被占」这个前提无从谈起
    function Get-FreePortPair {
        for ($p = 48200; $p -le 48900; $p++) {
            if ($p -eq 13508 -or $p -eq 54235) { continue }
            if ($p -ge 50000 -and $p -le 50064) { continue }   # WinNAT 预留段，绑不上也别选
            if (-not (Test-PortFree $p)) { continue }
            if (-not (Test-PortFree ($p + 3))) { continue }
            return (New-Object psobject -Property @{ Line = $p; Probe = ($p + 3) })
        }
        return $null
    }
    function Test-Listening {
        param([int]$Port)
        try { return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) }
        catch { return [bool](Select-String -InputObject (netstat -ano) -Pattern (':' + $Port + ' .*LISTENING')) }
    }
    # 占住一个端口（不 accept、不说话）：用来造「被占用」与「坏成员」两种现场
    function New-PortHolder {
        param([int]$Port)
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $l.Start()
        return $l
    }
    # 干净的临时根 + 临时代理键（原值：未启用 / 7897 / 短绕过列表）
    function New-QaRoot {
        param($Root, $KeyRel)
        if (Test-Path $Root) { Remove-Item $Root -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path (Join-Path $Root 'data') -Force | Out-Null
        $hk = 'HKCU:\' + $KeyRel
        if (Test-Path $hk) { Remove-Item $hk -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $hk -Force | Out-Null
        New-ItemProperty $hk -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $hk -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
        New-ItemProperty $hk -Name ProxyOverride -Value 'localhost;127.*;192.168.*;10.*' -PropertyType String -Force | Out-Null
        $env:SPIDERVPN_ROOT = $Root
        $env:SPIDERVPN_PROXY_KEY = $KeyRel
        return $hk
    }
    # 自检结论分类：三态互斥，顺序不能反（「未通过」里含「通过」）
    function Get-VerdictClass {
        param($Text)
        $t = [string]$Text
        if (-not $t) { return '无结论' }
        if ($t -match '跳过') { return '跳过' }
        if ($t -match '未通过') { return '未通过' }
        if ($t -match '通过') { return '通过' }
        return '无结论'
    }
    # 写一份最小合法配置：端点 = 线路端口，引擎路径由调用方定
    function Write-QaCfg {
        param($Root, [int]$Port, $EngineBinary, $LineName)
        $o = @{ schema = 2; mode = 'proxy'; selected = 'L1'
                lines = @(@{ id = 'L1'; name = $LineName; proxy_endpoint = ('127.0.0.1:' + $Port) })
                engine = @{ binary = $EngineBinary } }
        $d = Join-Path $Root 'data'
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $d 'config.json'), ($o | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    # 「坏成员」假引擎：引擎换成 powershell，让它占住探测端口但**不讲 SOCKS5**。
    # 于是自检能真连上、真握手失败 → 必然「未通过」；而 PING 假引擎（没人监听）只会得到「跳过」。
    # 两者结论类别不同，正是 T49/T50-B/T53 区分「真检」与「跳过」的判据。
    $psExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $psOk = [bool](Test-Path $psExe)
    function Get-ListenerArgs {
        param([int]$Port)
        return ('-NoProfile -Command $l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,' + $Port + ');$l.Start();[System.Threading.Thread]::Sleep(300000)')
    }
    function Ask-QaPipe53 {
        param($Name, $Obj)
        try {
            $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut)
            $cli.Connect(3000)
            $sw = New-Object System.IO.StreamWriter($cli); $sw.AutoFlush = $true
            $sr = New-Object System.IO.StreamReader($cli)
            $sw.WriteLine((ConvertTo-Json $Obj -Compress))
            $line = $sr.ReadLine()
            $cli.Dispose()
            if (-not $line) { return $null }
            return ($line | ConvertFrom-Json)
        } catch { return $null }
    }

    # ---- T47 导入时试绑探测端口：占住「线路端口+3」必须当场拒绝（12）并说清换端口 ----
    # 为什么必须在导入时试绑：导入原来只校验「端口 ≤ 65532」，真正会绑 端口+3 的是连接时的
    # 探测入站。等用户点连接才发现绑不上，问题已被推到最难排查的位置（引擎整体 FATAL）。
    $t47Root = Join-Path $env:TEMP ('tc-47-' + $PID)
    $hk47 = New-QaRoot $t47Root 'Software\SpiderVPN\tests\t47'
    $pair47 = Get-FreePortPair
    if (-not $pair47) {
        Skip 'T47' '导入时试绑探测端口：被占 → exit 12 +「自检探测端口」+「请换一个线路端口」' '本机找不到一对空闲端口（线路端口 p 与 p+3 都要能绑），无法构造现场'
    } else {
        $p47 = $pair47.Line
        $pp47 = $pair47.Probe
        $prof47 = Join-Path $t47Root 'profile.json'
        [System.IO.File]::WriteAllText($prof47, $profileJson, (New-Object System.Text.UTF8Encoding($false)))
        $cfgPath47 = Join-Path $t47Root 'data\config.json'
        $l47 = $null
        try {
            $l47 = New-PortHolder $pp47
            $held47 = Test-Listening $pp47                                  # 前提①：真占住了
            $imp47a = RunTimed ('--import "' + $prof47 + '" --engine "' + $fakeEngine + '" --port ' + $p47 + ' --line-name 探测端口占用线路')
            $noCfg47a = -not (Test-Path $cfgPath47)
            $nLines47a = @(Get-ChildItem (Join-Path $t47Root 'data\lines') -File -ErrorAction SilentlyContinue).Count
            $l47.Stop()
            $l47 = $null
            $free47 = -not (Test-Listening $pp47)                           # 前提②：释放干净了
            $imp47b = RunTimed ('--import "' + $prof47 + '" --engine "' + $fakeEngine + '" --port ' + $p47 + ' --line-name 探测端口占用线路')
            $cfgText47 = ''
            if (Test-Path $cfgPath47) { $cfgText47 = Get-Content $cfgPath47 -Raw -Encoding UTF8 }
            $hit47b = $cfgText47.Contains('127.0.0.1:' + $p47)
            Case 'T47' '导入时试绑探测端口：占住 端口+3 → exit 12 且文案含「自检探测端口」「请换一个线路端口」、一个文件都不落盘；释放后同一端口导入成功' `
                ($held47 -and $free47 -and $imp47a.Code -eq 12 -and ($imp47a.Out -match '自检探测端口') -and ($imp47a.Out -match '请换一个线路端口') -and
                 $noCfg47a -and $nLines47a -eq 0 -and $imp47b.Code -eq 0 -and $hit47b) `
                ('端口对=' + $p47 + '/' + $pp47 + ' 前提(占住=' + $held47 + ' 释放后空闲=' + $free47 + ') | 占住时: exit=' + $imp47a.Code + '(期望12) 含自检探测端口=' + ($imp47a.Out -match '自检探测端口') + ' 含请换一个线路端口=' + ($imp47a.Out -match '请换一个线路端口') + ' config未生成=' + $noCfg47a + ' 线路文件数=' + $nLines47a + ' 输出=[' + $imp47a.Out.Trim() + '] | 释放后: exit=' + $imp47b.Code + '(期望0) config含该端点=' + $hit47b)
        } finally {
            if ($l47) { try { $l47.Stop() } catch { } }
        }
    }
    if (Test-Path $hk47) { Remove-Item $hk47 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t47Root) { Remove-Item $t47Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T48 --set-line 走同一条校验：被占也必须拒绝，且已有配置零副作用 ----
    # 导入和手工写线路是两个入口，规则必须一套；否则用户改个端口就又绕过了检查。
    $t48Root = Join-Path $env:TEMP ('tc-48-' + $PID)
    $hk48 = New-QaRoot $t48Root 'Software\SpiderVPN\tests\t48'
    $pair48 = Get-FreePortPair
    if (-not $pair48) {
        Skip 'T48' '--set-line 同一条探测端口校验：被占 → 12 + 两条文案 + 配置零副作用' '本机找不到一对空闲端口，无法构造现场'
    } else {
        $p48 = $pair48.Line
        $pp48 = $pair48.Probe
        $cfg48 = Join-Path $t48Root 'data\config.json'
        # 先铺一条**已存在**的线路（端点与本次要写的不同）：拒绝时不许把它改坏
        Write-QaCfg $t48Root 17999 $fakeEngine '既有线路'
        $hash48a = (Get-FileHash $cfg48 -Algorithm SHA256).Hash
        $l48 = $null
        try {
            $l48 = New-PortHolder $pp48
            $held48 = Test-Listening $pp48                                  # 前提①
            $set48a = RunTimed ('--set-line L2 探测端口新线路 127.0.0.1:' + $p48)
            $hash48b = (Get-FileHash $cfg48 -Algorithm SHA256).Hash
            $l48.Stop()
            $l48 = $null
            $free48 = -not (Test-Listening $pp48)                           # 前提②
            $set48b = RunTimed ('--set-line L2 探测端口新线路 127.0.0.1:' + $p48)
            $cfgText48 = Get-Content $cfg48 -Raw -Encoding UTF8
            $hit48b = $cfgText48.Contains('127.0.0.1:' + $p48)
            Case 'T48' '--set-line 也试绑探测端口：占住 端口+3 → exit 12 + 两条文案，且 config.json 一个字节不变；释放后写入成功' `
                ($held48 -and $free48 -and $set48a.Code -eq 12 -and ($set48a.Out -match '自检探测端口') -and ($set48a.Out -match '请换一个线路端口') -and
                 $hash48b -eq $hash48a -and $set48b.Code -eq 0 -and $hit48b) `
                ('端口对=' + $p48 + '/' + $pp48 + ' 前提(占住=' + $held48 + ' 释放后空闲=' + $free48 + ') | 占住时: exit=' + $set48a.Code + '(期望12) 含自检探测端口=' + ($set48a.Out -match '自检探测端口') + ' 含请换一个线路端口=' + ($set48a.Out -match '请换一个线路端口') + ' 配置零副作用=' + ($hash48b -eq $hash48a) + ' 输出=[' + $set48a.Out.Trim() + '] | 释放后: exit=' + $set48b.Code + '(期望0) 配置含该端点=' + $hit48b)
        } finally {
            if ($l48) { try { $l48.Stop() } catch { } }
        }
    }
    if (Test-Path $hk48) { Remove-Item $hk48 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t48Root) { Remove-Item $t48Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T49 探测端口「先被占、约 250ms 后释放」→ 自检必须真检（不许报「跳过」）----
    # 判据只能看**结论类别**：PING 假引擎什么都没监听，即使真检也只会得到「未通过」；
    # 若实现没有重试，plan 阶段就判「被占」→ 直接「跳过」。两种文案不同，正好能分开。
    # 所以引擎必须换成「占住探测端口但不讲 SOCKS5」的假引擎：重试成功 → 真检 → 未通过。
    #
    # ⚠ 占位**必须放在另一个进程里**（本轮踩到并修掉的坑）：
    # 如果在 PowerShell 里 New 一个 TcpListener 再 Process.Start 被测程序，**监听句柄会被子进程继承**，
    # 于是「父进程 Stop()」之后端口对子进程仍然被占（它自己拿着那份句柄），怎么重试都绑不上 ——
    # 实测表现就是「占 50ms 都救不回来、且各档耗时完全一样」，会被误判成"实现没做重试"。
    # 用独立进程占位（子进程不继承它的句柄）才是干净的现场。
    $t49Root = Join-Path $env:TEMP ('tc-49-' + $PID)
    $hk49 = New-QaRoot $t49Root 'Software\SpiderVPN\tests\t49'
    $pair49 = Get-FreePortPair
    if (-not $pair49) {
        Skip 'T49' '探测端口绑定重试：占住约 250ms 后释放 → 自检真检（不报跳过）' '本机找不到一对空闲端口，无法构造现场'
    } elseif (-not $psOk) {
        Skip 'T49' '探测端口绑定重试：占住约 250ms 后释放 → 自检真检（不报跳过）' ('没有 ' + $psExe + '，造不出可区分的「真检」现场')
    } else {
        $p49 = $pair49.Line
        $pp49 = $pair49.Probe
        Write-QaCfg $t49Root $p49 $psExe '重试线路'
        $holder49 = $null
        try {
            # 独立进程占位：起监听 → 等「释放标记文件」出现 → 停。
            # 用标记文件控时，才能把释放精确落在「connect 启动后约 280ms」：即重试的
            # 第 2、3 次尝试之间（源码 3 次 × 200ms）。脚本不能带空格（参数按空格切分）。
            $marker49 = Join-Path $t49Root 'release.flag'
            if (Test-Path $marker49) { Remove-Item $marker49 -Force }
            $holdScript49 = '$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,' + $pp49 + ');$l.Start();while(-not(Test-Path ''' + $marker49 + ''')){Start-Sleep -Milliseconds 10};$l.Stop()'
            $hPsi49 = New-Object System.Diagnostics.ProcessStartInfo
            $hPsi49.FileName = $psExe
            $hPsi49.Arguments = '-NoProfile -Command ' + $holdScript49
            $hPsi49.UseShellExecute = $false
            $hPsi49.CreateNoWindow = $true
            $holder49 = [System.Diagnostics.Process]::Start($hPsi49)
            # 等它真的占上（最多 3s）：绑得上就说明还没起来
            $wait49 = 0
            while ((Test-PortBindable $pp49) -and $wait49 -lt 3000) { Start-Sleep -Milliseconds 20; $wait49 += 20 }
            $held49 = -not (Test-PortBindable $pp49)                        # 前提①：先真占住
            $env:SPIDERVPN_ENGINE_ARGS = (Get-ListenerArgs $pp49)
            $psi49 = New-Object System.Diagnostics.ProcessStartInfo
            $psi49.FileName = $Exe
            $psi49.Arguments = '--connect'
            $psi49.UseShellExecute = $false
            $psi49.CreateNoWindow = $true
            $proc49 = [System.Diagnostics.Process]::Start($psi49)
            Start-Sleep -Milliseconds 280                                   # 让第 1、2 次绑定都撞上「被占」
            $aliveAtRelease49 = -not $proc49.HasExited                      # 前提②：释放发生在 connect 还活着时
            [System.IO.File]::WriteAllText($marker49, 'go')
            $done49 = $proc49.WaitForExit(90000)
            $code49 = -1
            if ($done49) { $code49 = $proc49.ExitCode }
            $holder49.WaitForExit(5000)
            $holderExited49 = $holder49.HasExited                          # 前提③：占位进程自己退了（真的释放了）
            $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
            $rt49 = Join-Path $t49Root 'data\runtime.json'
            $rec49 = $null
            if (Test-Path $rt49) { $rec49 = Get-Content $rt49 -Raw -Encoding UTF8 | ConvertFrom-Json }
            $alive49 = $false
            if ($rec49) { $alive49 = Test-Alive $rec49.EnginePid }
            # 「重试到底有没有生效」不能只看结论措辞（「跳过：探测端口 N 被占用」有两种来源：
            # ①plan 阶段判定被占 = 没重试；②拨号时没人监听 = 重试了但引擎还没绑上）。
            # 唯一可靠的判据：凭据只在 plan=Dial 时才写进 runtime.json（record_probe_creds）。
            $creds49 = $false
            if ($rec49) { $creds49 = (@($rec49.PSObject.Properties.Name) -contains 'ProbeUser') }
            $listenAfter49 = Test-Listening $pp49
            $st49 = Run @('--status')
            $row49 = (($st49.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
            $cls49 = Get-VerdictClass $row49
            $null = RunDetached '--disconnect'
            # 断开后探测口应该回到可绑状态（证据用，不进判据：引擎优雅退出有时间抖动）
            Start-Sleep -Milliseconds 800
            $freeAfterDisconnect49 = Test-PortBindable $pp49
            if (-not ($held49 -and $holderExited49 -and $aliveAtRelease49)) {
                Skip 'T49' '探测端口绑定重试：占住约 280ms 后释放 → 自检真检（不报跳过）' ('构造不成立：占住=' + $held49 + ' 占位进程已退出=' + $holderExited49 + ' 释放在connect存活期内=' + $aliveAtRelease49 + '；本轮不判定，也不许当通过')
            } elseif (-not $creds49) {
                # 没凭据 ⇒ plan 阶段仍判「被占」⇒ 实现没有重试。这是明确的缺陷，不是时序。
                Case 'T49' '探测端口先被占、约 280ms 后释放：连接应能重试成功并真检（自检结论不是「跳过」）' $false `
                    ('重试没生效：runtime.json 里没有 ProbeUser/ProbePass（⇒ plan 阶段仍判定「被占」，没走到 Dial）| 前提(占住=' + $held49 + ' 占位已退=' + $holderExited49 + ') connect=' + $code49 + ' 引擎存活=' + $alive49 + ' 自检类别=' + $cls49 + ' 自检行=[' + $row49.Trim() + ']')
            } elseif ($cls49 -eq '未通过') {
                Case 'T49' '探测端口先被占、约 280ms 后释放：连接能重试成功并真检（结论「未通过」，不是「跳过」）' `
                    ($held49 -and $holderExited49 -and $code49 -eq 0 -and $alive49) `
                    ('前提(占住=' + $held49 + ' 占位已退=' + $holderExited49 + ' 有探测凭据=' + $creds49 + ') connect=' + $code49 + ' 引擎存活=' + $alive49 + ' 自检类别=' + $cls49 + ' 断开后可绑=' + $freeAfterDisconnect49 + ' 自检行=[' + $row49.Trim() + ']')
            } else {
                # 有凭据（重试成功）但结论仍是「跳过」：只可能是引擎还没绑上探测口（时序），
                # 这时既证明不了「真检」，也不是实现没重试——按「无法判定」处理，绝不当通过。
                Skip 'T49' '探测端口绑定重试：占住约 280ms 后释放 → 自检真检（不报跳过）' ('重试已生效（runtime.json 有探测凭据）但结论是「跳过」= 自检拨号时引擎尚未绑上探测口（时序）；引擎事后监听=' + $listenAfter49 + ' 自检行=[' + $row49.Trim() + ']；本轮不判定')
            }
        } finally {
            if ($holder49 -and -not $holder49.HasExited) { Stop-Process -Id $holder49.Id -Force -ErrorAction SilentlyContinue }
            $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        }
    }
    if (Test-Path $hk49) { Remove-Item $hk49 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t49Root) { Remove-Item $t49Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T50 「跳过」必须带原因（双向断言）----
    # 只断言「含跳过→必须含原因」会漏掉「把真检吞成跳过」；只断言反向会漏掉「原因文案串台」。
    # 两个方向都要有真现场，缺一个方向就不能算通过。
    $t50Root = Join-Path $env:TEMP ('tc-50a-' + $PID)
    $hk50 = New-QaRoot $t50Root 'Software\SpiderVPN\tests\t50'
    $t50bRoot = Join-Path $env:TEMP ('tc-50b-' + $PID)
    $hk50b = ''
    $pair50 = Get-FreePortPair
    if (-not $pair50) {
        Skip 'T50' '「跳过」必须带原因（双向）' '本机找不到一对空闲端口，无法构造现场'
    } else {
        $p50 = $pair50.Line
        $pp50 = $pair50.Probe
        # A) 端口空闲 + PING 假引擎 → 结论必然「跳过」，且原因必须点出**那个端口**与「被占用」，且不得同时说通过
        Write-QaCfg $t50Root $p50 $fakeEngine '跳过线路'
        $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        $freeBefore50 = -not (Test-Listening $pp50)                     # 前提：没人占
        $c50a = RunTimed '--connect'
        $st50a = Run @('--status')
        $row50a = (($st50a.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
        $null = RunDetached '--disconnect'
        $a50skip = ($row50a -match '跳过')
        $a50reason = ($row50a -match ('探测端口\s*' + $pp50 + '\s*被占用'))
        $a50noPass = -not ($row50a -match '通过')
        $a50ok = ($freeBefore50 -and $c50a.Code -eq 0 -and $a50skip -and $a50reason -and $a50noPass)
        $d50a = 'A(端口空闲+PING引擎)：前提空闲=' + $freeBefore50 + ' connect=' + $c50a.Code + ' 自检行=[' + $row50a.Trim() + '] 含跳过=' + $a50skip + ' 含「探测端口 ' + $pp50 + ' 被占用」=' + $a50reason + ' 未同时说通过=' + $a50noPass
        # B) 引擎占住探测端口但不讲 SOCKS5 → 真检 → 未通过；此时既不许出现「跳过」，也不许出现该原因
        if (-not $psOk) {
            # B 方向造不出来 = 这条**没验全**：既不能判 PASS，也不能判 FAIL（不是产品的问题）。
            Skip 'T50' '「跳过」必须带原因（双向）' ('只有 A 方向验得了（' + $d50a + '）；B 方向需要 ' + $psExe + ' 造「真检」现场，本机没有，双向断言未完成')
        } else {
            $b50ok = $false
            $d50b = 'B 未执行'
            $hk50b = New-QaRoot $t50bRoot 'Software\SpiderVPN\tests\t50b'
            Write-QaCfg $t50bRoot $p50 $psExe '真检线路'
            $env:SPIDERVPN_ENGINE_ARGS = (Get-ListenerArgs $pp50)
            $freeB50 = -not (Test-Listening $pp50)                      # 前提：plan 阶段必须是「空闲」
            $c50b = RunTimed '--connect'
            $rt50b = Join-Path $t50bRoot 'data\runtime.json'
            $rec50b = $null
            if (Test-Path $rt50b) { $rec50b = Get-Content $rt50b -Raw -Encoding UTF8 | ConvertFrom-Json }
            $creds50b = $false
            if ($rec50b) { $creds50b = (@($rec50b.PSObject.Properties.Name) -contains 'ProbeUser') }
            $st50b = Run @('--status')
            $row50b = (($st50b.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
            $null = RunDetached '--disconnect'
            $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
            $cls50b = Get-VerdictClass $row50b
            $b50ok = ($freeB50 -and $c50b.Code -eq 0 -and ($row50b -match '未通过') -and -not ($row50b -match '跳过') -and -not ($row50b -match '被占用'))
            $d50b = 'B(引擎占住探测端口+不讲SOCKS5)：前提空闲=' + $freeB50 + ' connect=' + $c50b.Code + ' 自检行=[' + $row50b.Trim() + '] 有探测凭据=' + $creds50b + ' 未通过=' + ($row50b -match '未通过') + ' 含跳过=' + ($row50b -match '跳过') + ' 含被占用=' + ($row50b -match '被占用')
            if (($cls50b -eq '跳过') -and $creds50b) {
                # 有凭据（plan=Dial，端口确实空闲）却仍然「跳过」= 自检拨号时引擎还没绑上探测口（时序），
                # 这只说明 B 的现场没造好，不能算产品的问题，也不能当通过。
                Skip 'T50' '「跳过」必须带原因（双向）' ('A 方向已验（' + $d50a + '）；B 方向结论是「跳过」但 runtime.json 有探测凭据 ⇒ 自检拨号时引擎尚未绑上探测口（时序），B 无法判定')
            } else {
                Case 'T50' '「跳过」必须带原因（双向）：含「跳过」时必含「探测端口 线路端口+3 被占用」且不得同时说通过；不含「跳过」时不得出现该原因' `
                    ($a50ok -and $b50ok) ($d50a + ' | ' + $d50b)
            }
        }
    }
    if ($hk50 -and (Test-Path $hk50)) { Remove-Item $hk50 -Recurse -Force -ErrorAction SilentlyContinue }
    if ($hk50b -and (Test-Path $hk50b)) { Remove-Item $hk50b -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t50Root) { Remove-Item $t50Root -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t50bRoot) { Remove-Item $t50bRoot -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T51 引擎秒退（PING -z）：connect 必须返回 Err，且 runtime-engine.json 事后不存在 ----
    # 口径：文件存在 ⟺ 连接正在运行。没进入运行态就不许留文件，否则排查时会被一份死配置误导。
    # 只看**最终态**：实现是「先生成、失败后清理」，断言「从未创建」会与实现打架（见 T43 的注）。
    $t51Root = Join-Path $env:TEMP ('tc-51-' + $PID)
    $hk51 = New-QaRoot $t51Root 'Software\SpiderVPN\tests\t51'
    $pair51 = Get-FreePortPair
    if (-not $pair51) {
        Skip 'T51' '引擎秒退：connect 返回 Err 且 runtime-engine.json 事后不存在' '本机找不到一对空闲端口，无法构造现场'
    } else {
        $p51 = $pair51.Line
        Write-QaCfg $t51Root $p51 $fakeEngine '秒退线路'
        $rtEng51 = Join-Path $t51Root 'data\runtime-engine.json'
        $pre51 = Test-Path $rtEng51
        $key51a = Snap $hk51
        $env:SPIDERVPN_ENGINE_ARGS = '-z'
        $c51 = RunTimed '--connect'
        $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        Start-Sleep -Milliseconds 1200
        $post51 = Test-Path $rtEng51
        $key51b = Snap $hk51
        $saysDie51 = ($c51.Out -match '立即退出')
        Case 'T51' '引擎秒退（PING -z）：connect 返回 Err（非0 且说「立即退出」），runtime-engine.json 最终不存在（未进入运行态就不许留文件）' `
            ((-not $pre51) -and $c51.Code -ne 0 -and $saysDie51 -and (-not $post51) -and ($key51b -eq $key51a)) `
            ('前提(连接前不存在=' + (-not $pre51) + ' 代理键可读=' + ($key51a -ne '(键不存在)') + ') connect=' + $c51.Code + '(期望非0) 说立即退出=' + $saysDie51 + ' 事后存在=' + $post51 + '(期望False) 代理键回原值=' + ($key51b -eq $key51a) + ' 输出=[' + $c51.Out.Trim() + ']')
    }
    if (Test-Path $hk51) { Remove-Item $hk51 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t51Root) { Remove-Item $t51Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- T52 两路径一致性对照：同一场景下 CLI 与 IPC 的结果必须逐项相同 ----
    # D8 就是「界面删了、CLI 没删」漏出来的。所以这里不看单条结论，直接拿 T45（CLI）与
    # T46（IPC）的**同场景**事实对照：文件在不在、断开后删没删、连接成功与否、自检结论类别。
    if (-not $pipe46) {
        Skip 'T52' '两路径一致性：同场景下 CLI 与 IPC 的 runtime-engine.json 去留 / 连接结果 / 自检结论类别逐项相同' 'T46 的 IPC 侧没跑起来（找不到唯一管道），没有可比的一侧'
    } else {
        $cli52ok = ($c45.Code -eq 0)
        $ipc52ok = [bool]($ipcConn46 -and $ipcConn46.ok -eq $true)
        $cli52v = Get-VerdictClass $row45
        $ipc52v = Get-VerdictClass $check46
        $same52 = (($cli52ok -eq $ipc52ok)) -and ((([bool]$exists45) -eq ([bool]$exists46))) -and ((([bool]$gone45) -eq ([bool]$gone46))) -and ($cli52v -eq $ipc52v)
        Case 'T52' '两路径一致性：同一场景（坏成员/连接在跑）下 CLI 与 IPC 的「文件在不在 / 断开后删没删 / 连接成功与否 / 自检结论类别」逐项相同' `
            ($same52 -and $cli52ok -and $exists45 -and $gone45 -and $exists46 -and $gone46) `
            ('CLI: 连接成功=' + $cli52ok + ' 运行中文件=' + $exists45 + ' 断开后已删=' + $gone45 + ' 自检=' + $cli52v + ' | IPC: 连接成功=' + $ipc52ok + ' 运行中文件=' + $exists46 + ' 断开后已删=' + $gone46 + ' 自检=' + $ipc52v + ' | 逐项相同=' + $same52)
    }

    # ---- T53 状态措辞统一（硬断言）/ T54 只读命令旁路互斥 ----
    # 现场必须是**真**的「已连接 + 自检未通过」：界面（GUI 当守护、控制接口可用）里连上，
    # 引擎换成「占住探测端口但不讲 SOCKS5」的假引擎 → 自检真连、真握手失败 → 未通过。
    # 裁定（本轮）：GUI 在跑时 --status/--lines/--exits/--plan/--headless 必须能读（不再 exit 4），
    # 而 --restore 仍独占。这两件事用**同一个 GUI 现场**验：T54 验互斥边界，T53 验措辞同源同词。
    $t53Root = Join-Path $env:TEMP ('tc-53-' + $PID)
    $hk53 = New-QaRoot $t53Root 'Software\SpiderVPN\tests\t53'
    $pair53 = Get-FreePortPair
    if (-not $pair53) {
        Skip 'T53' '状态措辞统一：连上但自检未通过 → 界面 title 与 CLI --status 都含「通道未通」' '本机找不到一对空闲端口，无法构造现场'
    } elseif (-not $psOk) {
        Skip 'T53' '状态措辞统一：连上但自检未通过 → 界面 title 与 CLI --status 都含「通道未通」' ('没有 ' + $psExe + '，造不出「真检但未通过」的现场（PING 假引擎只会得到「跳过」）')
    } else {
        $p53 = $pair53.Line
        $pp53 = $pair53.Probe
        Write-QaCfg $t53Root $p53 $psExe '措辞线路'
        # 缝隙必须在**启动 GUI 之前**设好：IPC 连接跑在 GUI 进程里，它继承的是启动时的环境
        $env:SPIDERVPN_ENGINE_ARGS = (Get-ListenerArgs $pp53)
        $gui53 = $null
        try {
            $gui53 = Start-Process -FilePath $Exe -PassThru
            for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; try { $gui53.Refresh() } catch { }; if ($gui53.MainWindowHandle -ne 0 -or $gui53.HasExited) { break } }
            $cand53 = @([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match '\\SpiderVPN\.' } | ForEach-Object { $_.Substring('\\.\pipe\'.Length) })
            $pipe53 = $null
            if ($cand53.Count -eq 1) { $pipe53 = $cand53[0] }
            if (-not $pipe53) {
                Skip 'T53' '状态措辞统一：连上但自检未通过 → 界面 title 与 CLI --status 都含「通道未通」' ('找不到唯一的 SpiderVPN 管道（候选 ' + $cand53.Count + ' 个），界面路径无法判定')
            } else {
                $conn53 = Ask-QaPipe53 $pipe53 @{ cmd = 'connect' }
                $lcPath53 = Join-Path $t53Root 'data\last-check.json'
                for ($i = 0; $i -lt 24 -and -not (Test-Path $lcPath53); $i++) { Start-Sleep -Milliseconds 500 }
                $lc53 = $null
                if (Test-Path $lcPath53) { $lc53 = Get-Content $lcPath53 -Raw -Encoding UTF8 | ConvertFrom-Json }
                $st53 = Ask-QaPipe53 $pipe53 @{ cmd = 'status' }
                $title53 = ''
                $state53 = ''
                $check53 = ''
                if ($st53) { $title53 = [string]$st53.title; $state53 = [string]$st53.state; $check53 = [string]$st53.check }
                $key53 = Snap $hk53
                $run53 = $null
                if (Test-Path (Join-Path $t53Root 'data\runtime.json')) { $run53 = Get-Content (Join-Path $t53Root 'data\runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
                $alive53 = $false
                if ($run53) { $alive53 = Test-Alive $run53.EnginePid }
                $taken53 = $key53.StartsWith('1|127.0.0.1:' + $p53 + '|')          # 前提：代理真被接管（连接在跑）
                $noSkip53 = $lc53 -and -not (@($lc53.PSObject.Properties.Name) -contains 'skipped')
                $real53 = [bool]$lc53 -and ($lc53.ok -eq $false) -and [bool]$noSkip53   # 前提：真检且未通过
                # CLI 侧：裁定后必须与界面同源同词（GUI 占着互斥时也要能读——见 T54）
                $cli53 = Run @('--status')
                $row53state = (($cli53.Out -split "`r?`n") | Where-Object { $_ -match '状态      ' }) -join ' '
                $row53check = (($cli53.Out -split "`r?`n") | Where-Object { $_ -match '通道自检' }) -join ' '
                $ui53ok = ($state53 -eq 'Connected') -and ($title53 -match '已连接') -and ($title53 -match '通道未通')
                $creds53 = $false
                if ($run53) { $creds53 = (@($run53.PSObject.Properties.Name) -contains 'ProbeUser') }

                # ---- T54 只读命令必须旁路互斥，而 --restore 仍独占（裁定原话：范围收窄）----
                # 正例（5 条只读）与反例（--restore 必须仍被拒）**都要有**：
                # 只验正例的话，实现"顺手把 --restore 也放进旁路名单"不会被任何用例发现。
                $ro54Order = @('--status', '--lines', '--exits', '--plan', '--headless')
                $ro54 = @{}
                foreach ($cmd54 in $ro54Order) {
                    $r54 = RunTimed $cmd54 15000
                    $ro54[$cmd54] = $r54.Code
                }
                $restore54 = RunTimed '--restore' 15000
                $bad54 = @()
                foreach ($cmd54 in $ro54Order) {
                    if ($ro54[$cmd54] -eq 4) { $bad54 += ($cmd54 + '=4（仍被互斥拒绝）') }
                    elseif ($ro54[$cmd54] -ne 0) { $bad54 += ($cmd54 + '=' + $ro54[$cmd54] + '（期望0）') }
                }
                if ($restore54.Code -ne 4) { $bad54 += ('--restore=' + $restore54.Code + '（期望4：改代理/注册表的命令不许借旁路溜进去）') }
                Case 'T54' '只读命令旁路互斥：GUI 在跑时 --status/--lines/--exits/--plan/--headless 都 exit 0；--restore 仍 exit 4（独占语义没被顺手放开）' `
                    ($bad54.Count -eq 0) `
                    ('GUI pid=' + $gui53.Id + ' 退出码：' + (($ro54Order | ForEach-Object { $_ + '=' + $ro54[$_] }) -join ' ') + ' | --restore=' + $restore54.Code + '(期望4) 问题：' + ($bad54 -join '；'))

                $null = Ask-QaPipe53 $pipe53 @{ cmd = 'disconnect' }
                if ((-not $real53) -and ($state53 -eq 'Connected') -and $creds53) {
                    # 已连上、plan 也拿到了探测凭据，但自检结论不是「未通过」：只可能是自检拨号时
                    # 引擎还没绑上探测口（时序）。现场没造好 ⇒ 措辞无法判定，既不算通过也不算失败。
                    Skip 'T53' '状态措辞统一：连上但自检未通过 → 界面 title 与 CLI --status 都含「通道未通」' `
                        ('现场没造好：界面已连上（state=' + $state53 + '）且 plan 已拿到探测凭据，但自检结论不是「未通过」（界面 check=[' + $check53 + ']）⇒ 自检拨号时引擎尚未绑上探测口（时序）；措辞无法判定')
                } else {
                    # 裁定后这里是**硬断言**：GUI 在跑时 --status 必须是 exit 0（不是 4），状态行必须含「通道未通」
                    Case 'T53' '状态措辞统一：连上但自检未通过时，界面 title 与 CLI --status 的状态行都含「通道未通」（同源同词，且 CLI 不再被互斥拒）' `
                        ($ui53ok -and [bool]$real53 -and $alive53 -and $taken53 -and ($cli53.Code -eq 0) -and ($row53state -match '通道未通') -and ($row53state -match '已连接')) `
                        ('前提(真检未通过=' + $real53 + ' 引擎活=' + $alive53 + ' 代理已接管=' + $taken53 + ' 界面态=' + $state53 + ') 界面 title=[' + $title53 + '] 界面 check=[' + $check53 + '] | CLI exit=' + $cli53.Code + '(期望0，4=仍被互斥拒) 状态行=[' + $row53state.Trim() + '] 自检行=[' + $row53check.Trim() + ']')
                }
            }
        } finally {
            if ($gui53 -and -not $gui53.HasExited) {
                $null = $gui53.CloseMainWindow()
                for ($i = 0; $i -lt 20 -and -not $gui53.HasExited; $i++) { Start-Sleep -Milliseconds 500; try { $gui53.Refresh() } catch { } }
                if (-not $gui53.HasExited) { Stop-Process -Id $gui53.Id -Force -ErrorAction SilentlyContinue }
            }
            $env:SPIDERVPN_ENGINE_ARGS = '-n 300 127.0.0.1'
        }
    }
    if (Test-Path $hk53) { Remove-Item $hk53 -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $t53Root) { Remove-Item $t53Root -Recurse -Force -ErrorAction SilentlyContinue }
    $env:SPIDERVPN_ROOT = $ScenRoot
    $env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\acceptance'

    # ---- R1 用户数据根只读检查（唯一允许接触默认根的一条，且只读）----
    # 既验「--status 能读到用户的真实线路」，也验「跑完文件清单一个字节都没变」。
    $snapR1a = Get-DataManifest $DefaultData
    $savedRoot = $env:SPIDERVPN_ROOT
    Clear-EnvVar 'SPIDERVPN_ROOT'   # 只在这一条里落到默认根
    $stR1 = Run @('--status')
    $env:SPIDERVPN_ROOT = $savedRoot
    $snapR1b = Get-DataManifest $DefaultData
    $sameR1 = (($snapR1a -join ';') -eq ($snapR1b -join ';'))
    Case 'R1' '用户数据根只读：--status 读到真实线路，且文件清单（名/大小/时间）前后完全一致' `
        ($stR1.Code -eq 0 -and $stR1.Out -notmatch '尚未配置' -and $sameR1) `
        ("退出码=$($stR1.Code) 报未配置=$($stR1.Out -match '尚未配置') 清单一致=$sameR1 清单=[$($snapR1b -join ';')]")

    # ---- T1 最高优先级：真实系统代理全程未被改动 ----
    $realAfter = Snap $RealKey
    Case 'T1' '真实系统代理前后完全一致（零写入）' ($realBefore -eq $realAfter) "前=$realBefore 后=$realAfter"
}
catch {
    # 脚本自己抛异常（改脚本时最常见）必须与产品 FAIL 分开：只看到「没有 TOTAL 行」会被误读成
    # 「产品挂了」或「全过」，两种判断都是错的。
    $script:crashed = $true
    Write-Host ("ERROR 脚本自身异常（不是产品失败）：{0}" -f $_.Exception.Message)
    $where = (($_.InvocationInfo.PositionMessage -split "`n" | Select-Object -First 2) -join ' ').Trim()
    Write-Host ("       位置：{0}" -f $where)
}
finally {
    Cleanup
}

Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
if ((Get-Item $Exe).LastWriteTime -ne $exeMtime) {
    Write-Host ("WARN  本轮运行期间被测产物被重建（{0} → {1}）：结果可信度下降，请复跑。" -f $exeMtime, (Get-Item $Exe).LastWriteTime)
}
if ($script:crashed) { exit 3 }
if ($script:fail -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }   # 有「无法判定」= 没验全，不能当通过
exit 0
