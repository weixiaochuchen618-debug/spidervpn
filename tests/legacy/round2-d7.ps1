#requires -Version 5.1
# 第二轮回归 · D7 五格（分流页「请用 TUN 模式」提示是否跟着**线路实际模式**走）
# 口径：提示出现 ⟺ 选中线路的实际模式是「代理」；且**必须先有 ≥1 条分流规则**（否则提示短路不打印 → 假绿）

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$Exe      = 'C:\SpiderVPN\bin\spidervpn.exe'
$ScenRoot = Join-Path $env:TEMP ('tc-d7-' + $PID)
$Data     = Join-Path $ScenRoot 'data'
$Cfg      = Join-Path $Data 'config.json'
$LogPath  = Join-Path $env:TEMP ('tc-d7-log-' + $PID + '.txt')
$Fixture  = Join-Path $PSScriptRoot 'fixtures\engine-no-split.json'

$env:SPIDERVPN_ROOT = $ScenRoot
$env:SPIDERVPN_PROXY_KEY = 'Software\SpiderVPN\tests\integr-d7'
$env:SPIDERVPN_RUN_KEY   = 'Software\SpiderVPN\tests\run-d7'
$TmpKey = 'HKCU:\' + $env:SPIDERVPN_PROXY_KEY

$script:pass = 0; $script:fail = 0; $script:skip = 0; $script:log = @()
function Add-Log { param($L) $script:log += $L; Write-Host $L }
function Case { param($Id,$Desc,$Ok,$Actual)
    if ($Ok) { $script:pass++; Add-Log ("PASS  {0}  {1}" -f $Id,$Desc) }
    else { $script:fail++; Add-Log ("FAIL  {0}  {1} :: {2}" -f $Id,$Desc,$Actual) } }

function Run { param($ArgList, [int]$TimeoutMs = 60000)
    $out = Join-Path $env:TEMP ('d7-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bat = Join-Path $env:TEMP ('d7-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $argStr = (($ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    Set-Content $bat -Encoding OEM -Value ("@echo off`r`n`"$Exe`" $argStr > `"$out`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c "' + $bat + '"'
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi); $p.WaitForExit($TimeoutMs) | Out-Null
    $t = ''; try { $fs = [IO.File]::Open($out,'Open','Read','ReadWrite'); $sr = New-Object IO.StreamReader($fs,[Text.Encoding]::UTF8); $t = $sr.ReadToEnd(); $sr.Close(); $fs.Close() } catch { }
    Remove-Item $bat,$out -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $t } }

function Set-Mode { param($Mode)
    $o = Get-Content $Cfg -Raw -Encoding UTF8 | ConvertFrom-Json
    $o.mode = $Mode
    [IO.File]::WriteAllText($Cfg, ($o | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false))) }

function Count-Hint { param($Text)
    return ([regex]::Matches($Text, '请用 TUN 模式')).Count }

if (-not (Test-Path $Exe)) { Write-Host 'FAIL G0 被测程序不存在'; exit 1 }
$waited = 0
while ($waited -lt 90) {
    if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { Start-Sleep -Milliseconds 1500; if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -eq 0) { break } }
    Start-Sleep -Seconds 1; $waited += 1 }
if (@(Get-Process spidervpn -ErrorAction SilentlyContinue).Count -gt 0) { Write-Host 'SKIP 等不到空闲窗口'; exit 2 }

$i = Get-Item $Exe
Add-Log ("被测产物：{0}  SHA256={1}" -f $i.Length, (Get-FileHash $Exe -Algorithm SHA256).Hash)

if (Test-Path $ScenRoot) { Remove-Item $ScenRoot -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $Data -Force | Out-Null
New-Item $TmpKey -Force | Out-Null
New-ItemProperty $TmpKey -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty $TmpKey -Name ProxyServer -Value '127.0.0.1:7897' -PropertyType String -Force | Out-Null
New-ItemProperty $TmpKey -Name ProxyOverride -Value 'localhost;127.*' -PropertyType String -Force | Out-Null

try {
    # 两条线路：proxy 线路 与 TUN 线路（不同端口，探测端口 +3 都要空闲）
    $p1 = 48600; $p2 = 48620
    $r = Run @('--import', $Fixture, '--engine', 'C:\Windows\System32\PING.EXE', '--port', "$p1", '--line-name', '线路P1')
    Case 'D7-0a' "导入 proxy 线路（port $p1）" ($r.Code -eq 0) ("退出码=$($r.Code) 输出=$($r.Out -replace '\s+',' ')")
    $r = Run @('--import', (Join-Path $PSScriptRoot 'fixtures\engine-tun.json'), '--engine', 'C:\Windows\System32\PING.EXE', '--port', "$p2", '--line-name', '线路TUN', '--tun')
    Case 'D7-0b' "导入 TUN 线路（port $p2）" ($r.Code -eq 0) ("退出码=$($r.Code) 输出=$($r.Out -replace '\s+',' ')")

    # 加一条分流规则（没有规则时提示会短路，五格全会变假绿）
    $r = Run @('--use', '线路P1')
    $r = Run @('--split-add-domain', 'example.com', '--to', 'direct')
    Case 'D7-0c' '先加 1 条分流域名（否则提示不打印）' ($r.Code -eq 0) ("退出码=$($r.Code)")

    function Cell { param($Id, $Mode, $Line, $ExpectHint)
        $null = Run @('--use', $Line)
        Set-Mode $Mode
        $sl = Run @('--split-list')
        $st = Run @('--status')
        $n = Count-Hint $sl.Out
        $rules = ([regex]::Matches($sl.Out, '(进程|域名)')).Count
        $shownMode = (($st.Out -split "`r?`n" | Where-Object { $_ -match '^\s*模式' } | Select-Object -First 1) -replace '\s+',' ').Trim()
        Case $Id ("全局 mode={0} × 选中={1} → 提示应出现={2}（实际 {3} 次，规则数 {4}，{5}）" -f $Mode,$Line,$ExpectHint,$n,$rules,$shownMode) `
            ($n -eq $(if ($ExpectHint) {1} else {0})) ("提示次数=$n 规则数=$rules 状态行=$shownMode") }

    Cell 'D7-1' 'proxy' '线路P1'  $true
    Cell 'D7-2' 'proxy' '线路TUN' $false
    Cell 'D7-3' 'tun'   '线路P1'  $true
    Cell 'D7-4' 'tun'   '线路TUN' $false

    # 第 5 格：无规则时必须不打印（防"修 D7 时把空规则短路一起删掉"）
    $null = Run @('--use', '线路P1')
    Set-Mode 'proxy'
    $null = Run @('--split-remove-domain', 'example.com')
    $sl = Run @('--split-list')
    $n5 = Count-Hint $sl.Out
    $rules5 = ([regex]::Matches($sl.Out, '(进程|域名)')).Count
    Case 'D7-5' "无分流规则时提示不得打印（规则数 $rules5）" ($n5 -eq 0) ("提示次数=$n5 输出=$($sl.Out -replace '\s+',' ')")
}
catch { Add-Log ("异常：{0}" -f $_.Exception.Message) }
finally {
    if (Test-Path $ScenRoot) { Remove-Item $ScenRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $TmpKey) { Remove-Item $TmpKey -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:SPIDERVPN_RUN_KEY -ErrorAction SilentlyContinue
    $script:log += ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
    try { [IO.File]::WriteAllText($LogPath, (($script:log -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false))) } catch { }
}

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1} SKIP={2}" -f $script:pass, $script:fail, $script:skip)
Write-Host ("明细：{0}" -f $LogPath)
if ($script:fail -gt 0) { exit 1 }
exit 0
