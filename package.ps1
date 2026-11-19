#requires -Version 5.1
# Candidate packaging only; never fall back to shared legacy build output.
# Invoke from the same reviewed clean source worktree:
# package.ps1 -Version <version> -SourceSha <full SHA> -BuildDir <candidate output>
#   -BuildEvidenceSha256 <independently retained reviewed build record hash>
#   -ApprovalFile <external approved input JSON> -ApprovalSha256 <external hash>
#   -EnginePath <approved engine> -LicensePath <approved license> -OutputDir <new ASCII directory> -GitPath <audited git.exe>
# The resulting ZIP and manifest hashes require independent review. Never
# run the package's own scripts to establish initial trust. 008-B is pending.
[CmdletBinding()]
param([string]$Version,[string]$SourceSha,[string]$BuildDir,[string]$BuildEvidenceSha256,
    [string]$ApprovalFile,[string]$ApprovalSha256,[string]$EnginePath,[string]$LicensePath,[string]$OutputDir,[string]$GitPath)
$ErrorActionPreference='Stop'
$here=$PSScriptRoot
# Forward shared names because dot-source imports functions in this scope.
. (Join-Path $here 'build.ps1') -SourceSha $SourceSha -ApprovalFile $ApprovalFile -ApprovalSha256 $ApprovalSha256 -GitPath $GitPath

function Read-CandidateBuild([string]$Dir,[string]$Digest,[string]$Root,[string]$Sha,[string]$ApprovalDigest,$Approval,[string]$Lock) {
    if ($Dir -ieq 'C:\tc-rs-build\release') { throw 'Shared legacy output refused' }
    $null=Assert-LocalPath $Dir -Directory
    $allowed=@('spidervpn.exe','WebView2Loader.dll','build.log','build-evidence.json')
    $items=@(Get-ChildItem -LiteralPath $Dir -Force)
    if ($items.Count -ne $allowed.Count) { throw 'Unexpected build output set' }
    foreach ($item in $items) {
        if ($item.PSIsContainer -or $item.Name -cnotin $allowed) { throw 'Unknown build output' }
        $null=Assert-LocalPath $item.FullName
    }
    $record=Join-Path $Dir 'build-evidence.json'
    Assert-FileDigest $record $Digest
    $e=Get-Content -LiteralPath $record -Raw | ConvertFrom-Json
    if ($e.schema -ne 1 -or $e.kind -cne 'client-candidate-build' -or $e.sourceSha -cne $Sha -or
        $e.repository -cne $Approval.repository -or $e.sourceRoot -cne $Root -or $e.outputDir -cne $Dir -or
        $e.cargoLockSha256 -cne $Lock -or $e.approvalSha256 -ine $ApprovalDigest -or $e.target -cne $Approval.target -or
        $e.toolchain -cne '1.100.0-x86_64-pc-windows-gnu' -or $e.exitCode -ne 0) { throw 'Build evidence scope mismatch' }
    Assert-RustVersion $e.rustc $e.cargo
    $expected=@(Candidate-CargoArguments $Root $e.targetDir)
    $got=@($e.command)
    if ($got.Count -ne $expected.Count+1) { throw 'Build command mismatch' }
    for ($n=0;$n -lt $expected.Count;$n++) {
        if ($got[$n+1] -cne $expected[$n]) { throw 'Build command or locked dependency mismatch' }
    }
    Assert-Separate $Root $e.targetDir
    Assert-Separate $Dir $e.targetDir
    if ($got[0] -cne $e.tools.rustup.path) { throw 'Build executable path mismatch' }
    foreach ($key in @('git','rustup','gcc','dlltool','ld')) {
        if ($e.tools.$key.sha256 -ine $Approval.$key.sha256 -or $e.tools.$key.source -cne $Approval.$key.source -or
            -not ([string]$e.tools.$key.version).Contains([string]$Approval.$key.version)) { throw 'Tool evidence mismatch' }
    }
    Assert-FileDigest (Join-Path $Dir 'spidervpn.exe') $e.exeSha256
    Assert-FileDigest (Join-Path $Dir 'WebView2Loader.dll') $e.loaderSha256
    Assert-FileDigest (Join-Path $Dir 'WebView2Loader.dll') $Approval.loader.sha256
    Assert-FileDigest (Join-Path $Dir 'build.log') $e.buildLogSha256
    Assert-X64Pe (Join-Path $Dir 'spidervpn.exe')
    Assert-X64Pe (Join-Path $Dir 'WebView2Loader.dll') -Dll
    $e
}
function Candidate-Names {
    @('spidervpn.exe','WebView2Loader.dll','sing-box.exe','sing-box.LICENSE.txt',
      '一键安装.cmd','一键卸载.cmd','直接运行（免安装）.cmd','install/install.ps1','install/uninstall.ps1',
      'install/expected.sha256','INSTALL.txt','用户速查.md')
}
function Assert-FileSet([string]$Stage,[string[]]$Names) {
    $null=Assert-LocalPath $Stage -Directory
    # Do not recurse into arbitrary directories or reparse points.
    $dirs=@(Get-ChildItem -LiteralPath $Stage -Directory -Force)
    if ($dirs.Count -ne 1 -or $dirs[0].Name -cne 'install') { throw 'Unexpected package directory' }
    $null=Assert-LocalPath $dirs[0].FullName -Directory
    $top=@(Get-ChildItem -LiteralPath $Stage -File -Force)
    $inside=@(Get-ChildItem -LiteralPath $dirs[0].FullName -Force)
    if (@($inside | Where-Object {$_.PSIsContainer}).Count -ne 0) { throw 'Unknown nested directory' }
    $items=$top+$inside
    if ($items.Count -ne $Names.Count) { throw 'Incomplete or extra file set' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $items) {
        $name=$item.FullName.Substring($Stage.Length+1).Replace('\','/')
        if ($name -cnotin $Names -or -not $seen.Add($name)) { throw "Unknown or duplicate file: $name" }
        $null=Assert-LocalPath $item.FullName
    }
}
function New-CandidateManifest([string]$Stage) {
    $names=@(Candidate-Names)
    Assert-FileSet $Stage $names
    foreach ($name in $names) {
        $file=Join-Path $Stage $name.Replace('/','\')
        [pscustomobject]@{path=$name;size=(Get-Item -LiteralPath $file).Length;sha256=(Candidate-Hash $file)}
    }
}
function Assert-CandidateManifest($Entries) {
    $names=@(Candidate-Names)
    if (@($Entries).Count -ne $names.Count) { throw 'Manifest count mismatch' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Entries) {
        if ($entry.path -cnotin $names -or -not $seen.Add([string]$entry.path) -or
            $entry.size -isnot [ValueType] -or $entry.size -lt 0 -or [decimal]$entry.size -ne [long]$entry.size) {
            throw 'Invalid, duplicate or unknown manifest entry'
        }
        Assert-Digest $entry.sha256
    }
}
function Assert-StageManifest([string]$Stage,$Entries,[string]$ManifestHash) {
    Assert-CandidateManifest $Entries
    Assert-FileSet $Stage (@(Candidate-Names)+@('manifest.json'))
    Assert-FileDigest (Join-Path $Stage 'manifest.json') $ManifestHash
    foreach ($entry in $Entries) {
        $file=Join-Path $Stage $entry.path.Replace('/','\')
        if ((Get-Item -LiteralPath $file).Length -ne $entry.size) { throw 'Manifest size mismatch' }
        Assert-FileDigest $file $entry.sha256
    }
}
function Write-CandidateZip([string]$Stage,[string]$Zip,$Entries,[string]$ManifestHash) {
    Assert-StageManifest $Stage $Entries $ManifestHash
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream=[IO.File]::Open($Zip,[IO.FileMode]::CreateNew)
    try {
        $archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$false,[Text.Encoding]::UTF8)
        try {
            foreach ($name in (@(Candidate-Names)+@('manifest.json'))) {
                $entry=$archive.CreateEntry($name,[IO.Compression.CompressionLevel]::Optimal)
                $out=$entry.Open()
                try {
                    $in=[IO.File]::OpenRead((Join-Path $Stage $name.Replace('/','\')))
                    try { $in.CopyTo($out) } finally { $in.Dispose() }
                } finally { $out.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}
function Assert-CandidateZip([string]$Zip,$Entries,[string]$ManifestHash,[long]$ManifestSize) {
    Assert-CandidateManifest $Entries
    Assert-Digest $ManifestHash
    $null=Assert-LocalPath $Zip
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expected=@{}
    foreach ($entry in $Entries) { $expected[$entry.path]=$entry }
    $expected['manifest.json']=@{size=$ManifestSize;sha256=$ManifestHash}
    $names=@(Candidate-Names)+@('manifest.json')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $stream=[IO.File]::OpenRead($Zip)
    try {
        $archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$false,[Text.Encoding]::UTF8)
        try {
            if ($archive.Entries.Count -ne $names.Count) { throw 'ZIP count mismatch' }
            foreach ($entry in $archive.Entries) {
                $name=$entry.FullName
                if ($name -cnotin $names -or -not $seen.Add($name)) { throw "ZIP unknown/duplicate/path escape: $name" }
                if ((($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000 -or ($entry.ExternalAttributes -band 0x400) -ne 0) { throw 'ZIP link entry' }
                $want=$expected[$name]
                if ($entry.Length -ne $want.size) { throw "ZIP size mismatch: $name" }
                $in=$entry.Open()
                try {
                    if ((Get-FileHash -InputStream $in -Algorithm SHA256).Hash -ine $want.sha256) { throw "ZIP hash mismatch: $name" }
                } finally { $in.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}

# Functions may be used by isolated TEST-ONLY integrity checks; the actual
# package command has no fixture bypass and requires approved input digests.
if ($MyInvocation.InvocationName -eq '.') { return }
if ($Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$' -or -not $SourceSha -or -not $BuildDir -or
    -not $BuildEvidenceSha256 -or -not $ApprovalFile -or -not $ApprovalSha256 -or -not $EnginePath -or -not $LicensePath -or -not $OutputDir -or -not $GitPath) {
    throw 'Explicit version, SHA, build evidence, external approval, engine/license and new output required'
}
$a=Read-CandidateApproval $ApprovalFile $ApprovalSha256 $SourceSha
$gitEvidence=Read-AuditedApplication 'git.exe' $GitPath $a.git
$lock=Assert-CandidateSource $here $SourceSha $gitEvidence.path
Assert-Separate $here $ApprovalFile
Assert-Separate $here $BuildDir
$e=Read-CandidateBuild $BuildDir $BuildEvidenceSha256 $here $SourceSha $ApprovalSha256 $a $lock
Assert-FileDigest $EnginePath $a.engine.sha256
Assert-FileDigest $LicensePath $a.license.sha256
Assert-X64Pe $EnginePath
Assert-NewDirectory $OutputDir
foreach ($path in @($here,$BuildDir,$e.targetDir,$ApprovalFile,$EnginePath,$LicensePath)) { Assert-Separate $OutputDir $path }
$name="SpiderVPN-$Version-$($SourceSha.Substring(0,12))-windows-x64-CANDIDATE-NOT-APPROVED"
$null=New-Item -ItemType Directory -Path $OutputDir
$stage=Join-Path $OutputDir $name
$null=New-Item -ItemType Directory -Path $stage
$stageInstall=Join-Path $stage 'install'
$null=New-Item -ItemType Directory -Path $stageInstall
$copies=@(
    ,@((Join-Path $BuildDir 'spidervpn.exe'),'spidervpn.exe',$e.exeSha256)
    ,@((Join-Path $BuildDir 'WebView2Loader.dll'),'WebView2Loader.dll',$a.loader.sha256)
    ,@($EnginePath,'sing-box.exe',$a.engine.sha256)
    ,@($LicensePath,'sing-box.LICENSE.txt',$a.license.sha256)
)
$sourceFiles=[ordered]@{
    'package-files\install-once.cmd'='一键安装.cmd'
    'package-files\uninstall-once.cmd'='一键卸载.cmd'
    'package-files\run-portable.cmd'='直接运行（免安装）.cmd'
    'package-files\install.ps1'='install\install.ps1'
    'package-files\uninstall.ps1'='install\uninstall.ps1'
    'docs\用户速查.md'='用户速查.md'
}
foreach ($file in $sourceFiles.Keys) {
    $src=Assert-LocalPath (Join-Path $here $file)
    $copies+=,@($src,$sourceFiles[$file],(Candidate-Hash $src))
}
foreach ($copy in $copies) {
    Assert-FileDigest $copy[0] $copy[2]
    $dest=Join-Path $stage $copy[1]
    Copy-Item -LiteralPath $copy[0] -Destination $dest
    Assert-FileDigest $dest $copy[2]
}
# Compatibility only; covered by full inventory, no source authentication.
Set-Content -LiteralPath (Join-Path $stageInstall 'expected.sha256') -Encoding ASCII -Value @(
    ("{0}  spidervpn.exe" -f $e.exeSha256),("{0}  sing-box.exe" -f $a.engine.sha256)
)

$install = @'
SpiderVPN（Windows x64）候选包 — 未批准发布或安装

一、怎么装（推荐，一次就好）
  先通过独立可信渠道核验 ZIP 与完整清单。008-B尚未验收，当前不得安装。
  以下仅保留正式获准后的原使用说明。
  1. 把整个文件夹解压到任意位置（桌面、D 盘都行）。
  2. 双击「一键安装.cmd」。
     它会：复制程序到 C:\SpiderVPN\bin、在桌面和开始菜单建启动入口、
     校验文件哈希。安装需要管理员权限。
     遇到 Windows 或安全软件警告请停止并核实来源，不要绕过保护。
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
Set-Content -LiteralPath (Join-Path $stage 'INSTALL.txt') -Value $install -Encoding UTF8
if ((Assert-CandidateSource $here $SourceSha $gitEvidence.path) -cne $lock) { throw 'Source changed during packaging' }
Assert-FileDigest $ApprovalFile $ApprovalSha256
Assert-FileDigest (Join-Path $BuildDir 'build-evidence.json') $BuildEvidenceSha256
$entries=@(New-CandidateManifest $stage)
$manifest=Join-Path $stage 'manifest.json'
[ordered]@{schema=1;kind='unapproved-client-candidate';sourceSha=$SourceSha;files=$entries} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
$mh=Candidate-Hash $manifest
$partial=Join-Path $OutputDir "$name.zip.partial"
Write-CandidateZip $stage $partial $entries $mh
Assert-CandidateZip $partial $entries $mh (Get-Item -LiteralPath $manifest).Length
Assert-StageManifest $stage $entries $mh
$zip=Join-Path $OutputDir "$name.zip"
Move-Item -LiteralPath $partial -Destination $zip
$hash=Candidate-Hash $zip
[ordered]@{
    schema=1;kind='unapproved-client-candidate';sourceSha=$SourceSha;repository=$a.repository
    buildEvidenceSha256=$BuildEvidenceSha256.ToLowerInvariant();approvalSha256=$ApprovalSha256.ToLowerInvariant()
    cargoLockSha256=$lock;target=$e.target;toolchain=$e.toolchain;zip=(Split-Path -Leaf $zip)
    zipSha256=$hash;manifestSha256=$mh;engineSource=$a.engine.source;engineVersion=$a.engine.version
    engineSha256=$a.engine.sha256;loaderSource=$a.loader.source;loaderSha256=$a.loader.sha256
    licenseSource=$a.license.source;licenseSha256=$a.license.sha256
    status='AWAIT INDEPENDENT APPROVAL; no publisher authentication or installation approval'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDir 'candidate-evidence.json') -Encoding UTF8
Set-Content -LiteralPath "$zip.sha256" -Value ("{0}  {1}" -f $hash,(Split-Path -Leaf $zip)) -Encoding ASCII
[pscustomobject]@{Zip=$zip;ZipSha256=$hash;ManifestSha256=$mh;SourceSha=$SourceSha;Status='NOT APPROVED FOR INSTALLATION'}
