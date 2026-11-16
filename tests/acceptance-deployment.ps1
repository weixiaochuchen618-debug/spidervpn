#requires -Version 5.1
# SpiderVPN（Rust 重构版）· A2/A3 部署中心 P0 验收主链路
#
# 对应 PRD §9 的五条主链路 + 架构 T11。**这个脚本不碰真实服务器**：
# 五条链路全部由 `deployengine` 的假 Ops 驱动（`FakeOps` 可按序喂探针、注入失败），
# 真机三条（一次完整部署 / 一次关窗转托盘 / 一次强杀重启）必须人工执行，
# 结果写进 `-RealEvidence` 指向的 JSON，本脚本只校验它齐不齐。
#
# 为什么把验收做成「跑 cargo test 的若干筛选集」而不是驱动 exe：
#   这五条链路的判据几乎全是**记录上的状态**（Revision 单调、StepsDone 变化、
#   NextAction、PendingOperation.Outcome），而不是界面像素。用假 Ops 能把
#   「写成功但核对说不清」这种真实环境里可遇不可求的时刻精确造出来；
#   界面层的证据由 r46–r50 那几个 CDP 脚本负责，两边不重叠。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\acceptance-deployment.ps1
#   powershell ... -ReportDir D:\vpn构建\deliverables\software-company\tcrs-r51-t11 `
#                  -RealEvidence D:\vpn构建\deliverables\software-company\tcrs-r51-t11\real.json
#
# 退出码：0 全通过 / 1 有 FAIL / 2 有 SKIP（含真机证据缺项，= 没验全）/ 3 脚本自身异常

param(
    [string]$ReportDir = '',
    [string]$RealEvidence = '',
    [string]$TargetDir = 'D:\tc-rs-build'
)

# `param` 必须是脚本里第一条**语句**（`#requires` 与注释可以排在它前面）。
# 所以编码与偏好设置一律放在它之后：写在前面的后果是整份脚本连解析都过不去。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Project = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Project

$Cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $Cargo)) { $Cargo = 'cargo' }

$env:CARGO_TARGET_DIR = $TargetDir
$env:CARGO_BUILD_JOBS = '1'

if ([string]::IsNullOrWhiteSpace($ReportDir)) {
    $ReportDir = Join-Path $env:TEMP ('tc-deploy-accept-' + $PID)
}
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$script:rows = @()
$script:fail = 0
$script:skip = 0
$script:crash = $false

# 一次验收 = 一组用例筛选 + 一句给人看的判据。
# `Filters` 里给的是 libtest 的子串过滤，多个是「或」。
function Invoke-Link {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Criterion,
        [string[]]$Filters
    )

    $argList = @('test', '--bin', 'spidervpn', '--')
    $argList += $Filters

    # `2>&1` 配 `$ErrorActionPreference='Stop'` 会把子进程写在 stderr 的**任何**
    # 一行（哪怕只是编译警告）变成 terminating error，整轮跑到这里就崩。
    # 这里临时降级，只为把两股输出合起来数 `test result` 那一行。
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = (& $Cargo @argList 2>&1 | Out-String)
    }
    finally {
        $ErrorActionPreference = $previous
    }
    $passed = 0
    $failed = 0
    $parsed = $false
    foreach ($line in ($output -split "`r?`n")) {
        if ($line -match '^test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed') {
            $passed += [int]$matches[2]
            $failed += [int]$matches[3]
            $parsed = $true
        }
    }

    $ok = $parsed -and ($failed -eq 0) -and ($passed -gt 0)
    if (-not $ok) {
        if (-not $parsed) {
            # 一行 test result 都没有：编译失败或参数不对。这是脚本自身的问题，
            # 不能记成产品 FAIL——否则「编译不过」会被读成「功能坏了」。
            $script:crash = $true
            Write-Host ("ERROR {0} 没跑出任何 test result（编译失败或筛选参数不对）" -f $Id)
            Write-Host (($output -split "`r?`n" | Select-Object -Last 12) -join "`n")
            $script:rows += [pscustomobject]@{
                Id = $Id; Title = $Title; Criterion = $Criterion
                Passed = 0; Failed = 0; Status = 'ERROR'
            }
            return
        }
        $script:fail++
    }
    if ($passed -eq 0) { $script:crash = $true }

    $status = 'PASS'
    if ($failed -gt 0) { $status = 'FAIL' }
    Write-Host ("{0,-4} {1}  {2}（{3} passed / {4} failed）" -f $status, $Id, $Title, $passed, $failed)
    if ($failed -gt 0) {
        $bad = ($output -split "`r?`n" | Where-Object { $_ -match '^test .* FAILED$' }) -join '; '
        if ($bad) { Write-Host ("      失败用例：{0}" -f $bad) }
    }

    $script:rows += [pscustomobject]@{
        Id = $Id; Title = $Title; Criterion = $Criterion
        Passed = $passed; Failed = $failed; Status = $status
    }
}

try {
    Write-Host '=== A2/A3 部署中心 · P0 验收主链路（PRD §9 / T11）==='
    Write-Host ("    工程：{0}" -f $Project)
    Write-Host ("    构建目录：{0}" -f $env:CARGO_TARGET_DIR)
    Write-Host ''

    # 链路 1：新部署开始后出现真实任务；转后台、离页、重新打开都是同一 RunId，步骤持续推进。
    Invoke-Link 'L1' '同一 RunId 贯穿转后台与离页，Revision 单调、StepsDone 递增' `
        '记录不得换 RunId；Revision 严格递增；StepsDone 单调不减且真的变过；转后台不重发写' `
        @('one_run_id_survives_background_and_keeps_moving', 'the_ipc_start_command_really_enqueues_a_pass')

    # 链路 2：两台不同服务器可同时部署；同服务器第二个排队；重复点击不重复执行。
    Invoke-Link 'L2' '两台并发 / 同服务器串行 / 连点幂等 / 取消排队出队' `
        '并发峰值 >= 2；同 lane 不重叠；重复 continue 只产生一次写；取消的排队项必须出队' `
        @('two_servers_can_run_at_the_same_time', 'two_runs_on_the_same_server_never_overlap',
          'repeated_continue_clicks_do_not_duplicate_work', 'cancelling_a_queued_run_removes_it_from_the_queue')

    # 链路 3：四类故障各自的下一步；未知写结果没有直接重装入口。
    Invoke-Link 'L3' '四类故障只给允许的下一步；结果未知只能核对' `
        '只读失败/明确写失败 → RetryStep；结果未知 → Reconcile 且保留未决写；身份变化 → ConfirmFingerprint；核对不重发写' `
        @('four_fault_classes_offer_only_their_allowed_action',
          'an_unknown_write_is_reconciled_then_continues_without_replaying_it',
          'a_reconcile_that_stays_unknown_never_touches_the_server')

    # 链路 4：托盘隐藏后继续；异常结束后重启，原任务仍在、未决状态被标为需处理且没有自动续跑。
    Invoke-Link 'L4' '重启恢复只改判不重跑；退出守卫三态；有部署时快照 1 秒' `
        '死记录改判为 NeedsAttention；活记录不动；写盘失败报 failed 而不是留 Running；有部署不许完整退出' `
        @('startup_recovery_judges_a_dead_record_without_rerunning_anything',
          'startup_recovery_leaves_a_live_record_alone',
          'a_failed_recovery_write_is_reported_instead_of_left_looking_alive',
          'close_decision', 'a_running_deployment_keeps', 'busy_sentence')

    # 链路 5：完成后线路可见但连接不变；仅 UDP 成功不显示全完成；读取失败不显示空列表。
    Invoke-Link 'L5' '完成态 Running=false / 仅 UDP 是 Partial / 坏记录是 partial 且列表非空' `
        'Complete 后 Running 为假且线路登记一次；Partial 给「补齐兼容连接」；一条坏文件 → partial 且其余记录照常' `
        @('a_completed_run_is_never_running_and_registers_its_lines',
          'every_fixture_projects_to_the_documented_action_and_progress',
          'the_fixture_set_loads_as_partial_with_one_unreadable_file',
          'a_record_without_steps_is_unknown_not_done_and_not_zero_of_four',
          'an_unverifiable_write_offers_reconcile_and_no_background')

    # 契约：文档与代码不许各说各话（T10）。
    Invoke-Link 'C1' '契约 §4.16 的每个标识符都能在源码里找到' `
        '前向 92 个标识符 + 反向 5 个骨架概念 + 七条命令两处都在 + 三张图入库' `
        @('deployrun::contract_tests')

    # ---------------------------------------------------------------------
    # 真机三条：**必须人工执行**，脚本只校验证据齐不齐。
    # ---------------------------------------------------------------------
    $real = $null
    if (-not [string]::IsNullOrWhiteSpace($RealEvidence) -and (Test-Path $RealEvidence)) {
        $real = Get-Content -Raw -Encoding UTF8 $RealEvidence | ConvertFrom-Json
    }

    $realCases = @(
        @{ Key = 'complete'; Title = '真实服务器上一次完整部署' },
        @{ Key = 'tray';     Title = '一次中途关窗转托盘（部署在后台跑完）' },
        @{ Key = 'kill';     Title = '一次 Stop-Process 后重启核对（原任务仍在、Running=false、无自动续跑）' }
    )
    foreach ($case in $realCases) {
        $entry = $null
        if ($null -ne $real) { $entry = $real.($case.Key) }
        $present = ($null -ne $entry) -and
                   ($null -ne $entry.runId) -and
                   (-not [string]::IsNullOrWhiteSpace([string]$entry.runId))
        if ($present) {
            Write-Host ("PASS R-{0}  {1}（RunId {2}）" -f $case.Key, $case.Title, $entry.runId)
        } else {
            $script:skip++
            Write-Host ("SKIP R-{0}  {1}：没有人工证据（-RealEvidence 缺这一项）" -f $case.Key, $case.Title)
        }
        $script:rows += [pscustomobject]@{
            Id = 'R-' + $case.Key; Title = $case.Title
            Criterion = '真机证据（人工执行）'
            Passed = 0; Failed = 0
            Status = if ($present) { 'PASS' } else { 'SKIP' }
        }
    }
}
catch {
    $script:crash = $true
    Write-Host ("ERROR 脚本自身异常（不是产品失败）：{0}" -f $_.Exception.Message)
    $where = (($_.InvocationInfo.PositionMessage -split "`n" | Select-Object -First 2) -join ' ').Trim()
    Write-Host ("       位置：{0}" -f $where)
}

# ---------------- 报告 ----------------
$totalPassed = ($script:rows | Measure-Object -Property Passed -Sum).Sum
$totalFailed = ($script:rows | Measure-Object -Property Failed -Sum).Sum
$report = [pscustomobject]@{
    product = 'SpiderVPN'
    scope = 'A2/A3 deployment center P0 acceptance (PRD §9 / T11)'
    atUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    targetDir = $env:CARGO_TARGET_DIR
    passed = [int]$totalPassed
    failed = [int]$totalFailed
    skipped = $script:skip
    crashed = $script:crash
    rows = $script:rows
}
$reportPath = Join-Path $ReportDir 'report.json'
$report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $reportPath

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $totalPassed, $totalFailed, $script:skip)
Write-Host ("REPORT {0}" -f $reportPath)

if ($script:crash) { exit 3 }
if ($script:fail -gt 0 -or $totalFailed -gt 0) { exit 1 }
if ($script:skip -gt 0) { exit 2 }
exit 0
