#requires -Version 5.1
<#
.SYNOPSIS
交易保护（WFP）验收：能自动跑的部分全在隔离数据根里跑，不碰 HKLM、不弹 UAC、不动真实交易程序。

.DESCRIPTION
为什么要隔离根：生产证据写在 HKLM\SOFTWARE\SpiderVPN\Guard，非提权进程只读。
测试若碰它，就会「读到上一轮的真实记录」或「写坏用户的记录」。设了 SPIDERVPN_ROOT
之后 `evidence::select()` 只会用 <root>\guard\evidence.json，状态里的 `证据存储` 必须是
IsolatedFile——脚本把这一条当硬断言：它同时证明「没有偷偷打开生产键」。

自动项只覆盖**不需要管理员**的判定分支（PRD A1/A24/A25/A12/A13/A14）。
需要 UAC 或真实 WFP 的项列在 MANUAL 段，每项写明要留什么证据。

.PARAMETER Exe
被测程序。默认 debug 构建。

.PARAMETER WithCargo
额外跑 `cargo test --test guard_state`（判定层全分支）。需要本机 cargo 环境，约 1 分钟。

退出码：0 全过；1 有失败。
#>
[CmdletBinding()]
param(
    [string]$Exe = 'C:\tc-rs-build\debug\spidervpn.exe',
    [switch]$WithCargo
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$repo = Split-Path -Parent $here
$script:pass = 0
$script:fail = 0
$script:fails = New-Object System.Collections.ArrayList

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) {
        $script:pass++
        Write-Host ('  [自动] {0,-44} PASS' -f $name)
    } else {
        $script:fail++
        [void]$script:fails.Add("$name：$detail")
        Write-Host ('  [自动] {0,-44} FAIL  {1}' -f $name, $detail) -ForegroundColor Red
    }
}

function Field([string]$text, [string]$label) {
    $m = [regex]::Match($text, '(?m)^\s*' + [regex]::Escape($label) + '\s*：\s*(.+?)\s*$')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

# 跑一次 --guard-status：隔离根 + 现写 config.json。
function Get-GuardStatus([string]$root, [string]$configJson) {
    $data = Join-Path $root 'data'
    $null = New-Item -ItemType Directory -Force -Path $data
    [IO.File]::WriteAllText(
        (Join-Path $data 'config.json'),
        $configJson,
        (New-Object Text.UTF8Encoding($false))
    )
    $old = $env:SPIDERVPN_ROOT
    $env:SPIDERVPN_ROOT = $root
    # 程序把控制台切到 UTF-8；PowerShell 5.1 默认按 OEM 代码页解码原生命令输出，
    # 不显式对齐就会把「状态」读成乱码，断言全假失败。
    $oldEnc = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        $out = & $Exe --guard-status 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally {
        [Console]::OutputEncoding = $oldEnc
        if ($null -eq $old) {
            Remove-Item Env:\SPIDERVPN_ROOT -ErrorAction SilentlyContinue
        } else {
            $env:SPIDERVPN_ROOT = $old
        }
    }
    return @{ Text = $out; Code = $code }
}

Write-Host ''
Write-Host 'SpiderVPN · 交易保护验收' -ForegroundColor Cyan
Write-Host "  被测程序：$Exe"
Write-Host "  仓库：$repo"

if (-not (Test-Path -LiteralPath $Exe)) {
    Write-Host "  找不到被测程序：$Exe（先构建，或用 -Exe 指定）" -ForegroundColor Red
    exit 1
}

$root = Join-Path $env:TEMP ("tcrs-guard-accept-" + $PID)
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
$null = New-Item -ItemType Directory -Force -Path $root
Write-Host "  隔离根：$root"
Write-Host ''

try {
    # ---- A1 空名单：不是故障，也不能说「已保护」 ----
    $r = Get-GuardStatus $root '{"schema":2,"split":{"processes":[]}}'
    Check 'A1 空名单 → EmptyProgramList' ($r.Code -eq 0 -and (Field $r.Text '状态') -like '*EmptyProgramList*') `
        "exit=$($r.Code) 状态=$(Field $r.Text '状态')"
    Check 'A1 名单进程=0（不是 -1）' ((Field $r.Text '名单进程') -eq '0') "名单进程=$(Field $r.Text '名单进程')"

    # ---- A24 名单里全是直连：用户没做错事，不得红告警 ----
    $r = Get-GuardStatus $root '{"schema":2,"split":{"processes":[{"value":"a.exe","target":"direct"}]}}'
    Check 'A24 全设直连 → NoTradePrograms' ((Field $r.Text '状态') -like '*NoTradePrograms*') `
        "状态=$(Field $r.Text '状态')"
    Check 'A24 参与程序=0、名单进程=1' `
        (((Field $r.Text '参与程序') -eq '0') -and ((Field $r.Text '名单进程') -eq '1')) `
        "参与=$(Field $r.Text '参与程序') 名单=$(Field $r.Text '名单进程')"

    # ---- A25 混合名单：有交易条目但没路径 → 确定的不参与，不是「无法确认」 ----
    $r = Get-GuardStatus $root '{"schema":2,"split":{"processes":[{"value":"a.exe","target":"trade"},{"value":"b.exe","target":"daily"}]}}'
    Check 'A25 混合名单 → ProgramUnresolved' ((Field $r.Text '状态') -like '*ProgramUnresolved*') `
        "状态=$(Field $r.Text '状态')"
    Check 'A25 计数：参与 0 / 名单 2' `
        (((Field $r.Text '参与程序') -eq '0') -and ((Field $r.Text '名单进程') -eq '2')) `
        "参与=$(Field $r.Text '参与程序') 名单=$(Field $r.Text '名单进程')"

    # ---- 隔离硬断言：全程只碰隔离存储 ----
    Check 'A14 证据存储 = IsolatedFile（没开生产键）' ((Field $r.Text '证据存储') -eq 'IsolatedFile') `
        "存储=$(Field $r.Text '证据存储')"

    # ---- 可解析条目 + 没有任何证据 → Unknown(NotVerifiedYet)，绝不是 Protected ----
    #
    # 用系统自带的一个 exe 当「能解析出身份的程序」：这一步只读状态，不写 WFP、不启动它。
    $probeExe = Join-Path $env:SystemRoot 'System32\notepad.exe'
    if (-not (Test-Path -LiteralPath $probeExe)) {
        $probeExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
    }
    $jsonPath = $probeExe.Replace('\', '\\')
    $cfg = '{"schema":2,"split":{"processes":[{"value":"probe.exe","target":"trade","path":"' + $jsonPath + '"}]}}'
    $r = Get-GuardStatus $root $cfg
    Check '可解析条目：参与程序=1（身份真的算出来了）' ((Field $r.Text '参与程序') -eq '1') `
        "参与=$(Field $r.Text '参与程序') 程序=$probeExe"
    Check '无证据 → 绝不出现 Protected' (-not ($r.Text -match '状态\s*：\s*Protected')) `
        "状态=$(Field $r.Text '状态')"
    Check '无证据 → Unknown(NotVerifiedYet)' ((Field $r.Text '状态') -like '*NotVerifiedYet*') `
        "状态=$(Field $r.Text '状态')"

    # ---- A13 文案：用户可见的前端资产里不许出现这些句子 ----
    $banned = @('交易保护仍然生效', '不在预览版范围', '正在实时保护', '一切正常')
    $hits = @()
    $webDir = Join-Path $repo 'web'
    if (Test-Path -LiteralPath $webDir) {
        foreach ($f in Get-ChildItem -LiteralPath $webDir -File) {
            $t = [IO.File]::ReadAllText($f.FullName)
            foreach ($b in $banned) {
                if ($t.Contains($b)) { $hits += "$($f.Name): $b" }
            }
        }
    }
    Check 'A13 前端无禁用话术' ($hits.Count -eq 0) ($hits -join '；')

    # ---- 可选：判定层全分支（cargo） ----
    if ($WithCargo) {
        $env:PATHEXT = '.COM;.EXE;.BAT;.CMD'
        $env:CARGO_TARGET_DIR = 'C:\tc-rs-build'
        $env:PATH = "$env:USERPROFILE\.cargo\bin;C:\tc-rs-tools\winlibs\mingw64\bin;$env:PATH"
        Push-Location $repo
        try {
            $log = & cargo test --offline --test guard_state -- --test-threads=1 2>&1 | Out-String
            $ok = $LASTEXITCODE -eq 0
        } finally {
            Pop-Location
        }
        Check 'A19/A20 判定层全分支（cargo test guard_state）' $ok `
            ((($log -split "`n") | Select-Object -Last 3) -join ' ')
    }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 手工项：需要管理员会话 / 真实 WFP / 真实交易程序。脚本不替你做，也不假装做过。
# ---------------------------------------------------------------------------
$manual = @(
    @('A2', '非提权读到的是可信状态（trusted = 不可写证据）→ Protected，不是 NoPermission', '装完后普通 PowerShell 跑 --guard-status，留状态行与「证据存储」行'),
    @('A3', '证据键读取被拒 → 唯一入口 Unknown{NoPermission}（RecordError::AccessDenied）', '把证据键 BU 读权限 deny 后用普通 PowerShell 跑 --guard-status，留状态行；结束前按原 SDDL 还原'),
    @('A5', '安装后 provider/subLayer/filter 真实存在且持久', '管理员跑 --guard-install，再跑 --guard-status 与诊断页「交易保护」小节截图'),
    @('A6', '名单程序被真实阻断（IPv4+IPv6）', '名单放一个测试 exe，连接后用该程序直连目标 IP，留失败现象'),
    @('A7', '断开后规则仍在（持久）', '断开后重跑 --guard-status，状态仍 Protected 且时龄增长'),
    @('A8', '重启后规则仍在、开机标识变化 → Unknown{BootChanged}', '重启后再看状态与诊断页「开机标识 不匹配」'),
    @('A9', '解除后规则消失、状态 Unprotected{UserRemoved}', '维护页点「解除交易保护」，留回读结果与状态行'),
    @('A10', '交易软件在跑时拒绝解除', '打开名单内程序后点解除，必须被拒且文案指名程序'),
    @('A17', '20 分钟后显示「较旧」且给「重新核验」', '等待或改系统时间后看首页卡片'),
    @('A21', '防伪：非提权写 HKLM 必须被拒；把键 ACL 改宽后状态必须 Unknown{EvidenceUnprotected}', 'reg add 被拒的输出；改 ACL 后刷新界面截图；结束前恢复 ACL 并记录恢复命令'),
    @('A22', '真实解除入口与标记状态机', '解除 → 重开程序 → 状态仍是 UserRemoved（不是 Unknown）'),
    @('A23', '真实 UAC 被拒 → 仍 Protected + 「本次未能重新核验」', '前置：UAC 必须处于会提示的档位（ConsentPromptBehaviorAdmin ≠ 0）——「从不通知」时 runas 静默提权成功、没有可点的「否」，本条无法执行。验证：点首页卡片「重新核验」→ UAC 点「否」→ 看卡片必须仍写「直连保护已启用」，并在末尾追加「本次未能重新核验（管理员确认被取消）。」。警告：本条只能看界面，不能看命令行——verify_pending 存在进程级内存 cache（guard::cache() 是 OnceLock），CLI 另起进程恒读到 None')
)
Write-Host ''
Write-Host '  以下项需要管理员 / 真实 WFP，脚本不执行：' -ForegroundColor Yellow
foreach ($m in $manual) {
    Write-Host ('    [{0}] {1}' -f $m[0], $m[1])
    Write-Host ('          证据：{0}' -f $m[2]) -ForegroundColor DarkGray
}

Write-Host ''
if ($script:fail -eq 0) {
    Write-Host "  汇总：自动 $($script:pass) 项全过；手工 $($manual.Count) 项待人工确认。" -ForegroundColor Green
    exit 0
}
Write-Host "  汇总：自动 $($script:pass) 过 / $($script:fail) 失败；手工 $($manual.Count) 项待人工确认。" -ForegroundColor Red
foreach ($f in $script:fails) { Write-Host "    - $f" -ForegroundColor Red }
exit 1
