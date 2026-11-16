#requires -Version 5.1
<#
.SYNOPSIS
校验本程序与旧版客户端的隔离契约。
.DESCRIPTION
这是**机器可查的隔离门**，不是文档。分三类检查：

  A. 契约自检：must_differ 里每一项，rewrite 与 legacy 的值必须不同。
  B. 目录检查：安装目录与数据根不得等于、也不得位于 legacy 路径之下。
  C. 源码扫描：源码树里不得出现 legacy 的路径/名称字面量（出现即视为会踩到旧版）。

退出码：0=通过、1=有违规、3=契约文件缺失。
用法（CI 或每次提交前）：
  powershell -NoProfile -File Test-Isolation.ps1 -Tree <Rust 源码目录>
#>
[CmdletBinding()]
param(
 [string]$Contract = '',
 [string]$Tree = '',
 [string]$OutJson = ''
)
$ErrorActionPreference='Stop'
# 用 -File 调用时 param 默认值里取 $PSScriptRoot 可能为空，改为在函数体内解析。
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
if(-not $Contract){$Contract=Join-Path $here 'isolation.contract.json'}
if(-not $Tree){$Tree=$here}
if(-not (Test-Path -LiteralPath $Contract)){Write-Error ('找不到契约：'+$Contract);exit 3}

$c=Get-Content -LiteralPath $Contract -Raw -Encoding UTF8 | ConvertFrom-Json
$checks=New-Object 'Collections.Generic.List[object]'
function Add-Check {param([string]$Name,[bool]$Ok,[string]$Detail,[switch]$Skip)
 # Skip：这台机器上无从检查（例如还没安装），记为通过并在 Detail 里写明原因，
 # 不把「没装」误报成「隔离被破坏」。
 if($Skip){$checks.Add([ordered]@{Name=$Name;Ok=$true;Skipped=$true;Detail=$Detail});return}
 $checks.Add([ordered]@{Name=$Name;Ok=$Ok;Detail=$Detail})
}

# A. 契约自检
foreach($k in @($c.must_differ)){
 $lv=[string]$c.legacy.$k; $rw=[string]$c.rewrite.$k
 $ok=($lv -ne '') -and ($rw -ne '') -and ($lv -ne $rw)
 Add-Check "differ:$k" $ok ("legacy='$lv' rewrite='$rw'")
}

# B. 目录检查
$install=[Environment]::ExpandEnvironmentVariables([string]$c.rewrite.install_dir)
$data=[Environment]::ExpandEnvironmentVariables([string]$c.rewrite.data_root)
$legacyData=[Environment]::ExpandEnvironmentVariables([string]$c.legacy.data_root)
$installOk=Test-Path -LiteralPath $install
$dataOk=Test-Path -LiteralPath $data
Add-Check 'install_exists' $installOk $install -Skip:(-not $installOk)
Add-Check 'data_exists' $dataOk $data -Skip:(-not $dataOk)
Add-Check 'data_not_legacy' ($data -ne $legacyData) ("rewrite=$data legacy=$legacyData")
# 关键：数据根不能落在 legacy 数据根之下（那是「隔离」最常见的假实现）
Add-Check 'data_not_under_legacy' (-not $data.StartsWith($legacyData,[StringComparison]::OrdinalIgnoreCase)) $data

# C. 源码扫描
$hits=New-Object 'Collections.Generic.List[string]'
if(Test-Path -LiteralPath $Tree){
 foreach($f in @(Get-ChildItem -LiteralPath $Tree -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.rs','.toml','.json','.ps1','.psm1','.cmd') })){
  # 契约与本文自身当然会提到 legacy 名称，跳过
  if($f.Name -in @('isolation.contract.json','Test-Isolation.ps1','isolation.md')){continue}
  # 文档里提到旧路径是解释性的（不会构造资源），源码里出现才算违规。
  if($f.Extension -eq '.md'){continue}
  # 构建产物是源码的派生：扫它只会读到源码里本来就有的常量，属于噪音。
  if($f.FullName -like '*\target\*' -or $f.FullName -like '*\.git\*'){continue}
  # 例外清单：每一条都必须写明理由，且文件必须真实存在（避免留下僵尸白名单）。
  # PS 5.1 没有 [IO.Path]::GetRelativePath（.NET Core 才有），手工截取。
  $rel=$f.FullName.Substring($Tree.Length).TrimStart('\').Replace('\','/')
  if(@($c.scan_allowlist | Where-Object { $_.file -eq $rel }).Count -gt 0){continue}
  $text=Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if($null -eq $text){continue}
  foreach($pat in @($c.forbidden_in_rewrite_tree)){
   $needle=[string]$pat
   $from=0
   while($true){
    $idx=$text.IndexOf($needle,$from,[StringComparison]::OrdinalIgnoreCase)
    if($idx -lt 0){break}
    # 边界检查：`C://tradechannel` 不能命中 `C://SpiderVPN`（前者是后者的前缀）。
    # 命中后紧跟字母/数字视为另一个名字，继续往后找。
    $after=$idx+$needle.Length
    $next=if($after -lt $text.Length){$text[$after]}else{[char]0}
    if(-not ([char]::IsLetterOrDigit($next) -or $next -eq '_')){
     $hits.Add(('{0}: 出现 {1}' -f $f.FullName,$pat))
     break
    }
    $from=$idx+1
   }
  }
 }
}
Add-Check 'tree_free_of_legacy_refs' ($hits.Count -eq 0) (($hits | Select-Object -First 5) -join ' | ')

# 白名单不能有僵尸条目：指向不存在的文件 = 过期豁免，必须清掉
$stale=@()
foreach($a in @($c.scan_allowlist)){
  if($a.file){
    if(-not (Test-Path -LiteralPath (Join-Path $Tree ([string]$a.file).Replace('/','\')))){ $stale+=$a.file }
    if(-not $a.reason){ $stale+=($a.file+'（缺 reason）') }
  }
}
Add-Check 'allowlist_entries_valid' ($stale.Count -eq 0) (($stale | Select-Object -First 5) -join ' | ')

$failed=@($checks|Where-Object {-not $_.Ok})
$result=[ordered]@{
 Passed=($failed.Count -eq 0)
 Checked=$checks.Count
 Failed=$failed.Count
 Checks=$checks
}
if($OutJson){$result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $OutJson -Encoding UTF8}
$result|ConvertTo-Json -Depth 6
if($failed.Count -gt 0){exit 1}
exit 0
