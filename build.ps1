#requires -Version 5.1
<#
.SYNOPSIS
构建 SpiderVPN。把本机这套「非标准但能跑」的工具链组合固化下来。

.DESCRIPTION
为什么需要这个脚本，而不是直接 `cargo build`：

1. msvc 目标不可用：VS Build Tools 安装器在本机崩溃（退出码 5002），也没有 Windows SDK。
2. gnu 工具链自带的 binutils 不完整（dlltool 被 rustc 唤起时报 CreateProcess 失败），
   所以要借 WinLibs 提供的完整 MinGW-w64（dlltool + 导入库齐全）。
3. 仓库位于中文路径下，MinGW 的 ld/dlltool 处理非 ASCII 路径会失败，
   因此构建产物与工作目录都必须在纯英文路径。
4. exe 依赖 WebView2Loader.dll（x64），必须复制到 exe 同级，否则启动即
   0xC0000135（找不到 DLL）。

用法：powershell -NoProfile -File build.ps1 [-Release]

候选构建（仅 GNU x64；需要可信操作者已核验工具链与离线依赖缓存）：
  build.ps1 -Candidate -Release -SourceSha <完整40位SHA> -CandidateTarget <新ASCII目录>
    -CandidateOutput <另一个新ASCII目录> -ApprovalFile <包外JSON>
    -ApprovalSha256 <通过独立可信渠道取得的64位摘要> -MingwBin <已审核MinGW bin>
Approval JSON schema 1: repository (固定GitHub URL), sourceSha, rustVersion ("1.100.0"),
target ("x86_64-pc-windows-gnu"), gcc/dlltool/ld/loader/engine/license objects.
每个对象必须由可信操作者核定 source、version、sha256；loader/engine/license
另须 platform="windows-x64"，license.version=engine.version。
DLL/引擎/许可证和工具摘要必须来自独立审核，不从待验证目录自采作为信任依据。
先审阅 build-evidence.json，再独立保管其摘要；package.ps1 要求该摘要与同一审批记录。
此模式不安装工具、下载未知引擎、不签名、不批准发布。
#>
[CmdletBinding()]
param([switch]$Release,[switch]$Candidate,[string]$SourceSha,
  [string]$CandidateTarget,[string]$CandidateOutput,[string]$ApprovalFile,
  [string]$ApprovalSha256,[string]$MingwBin)

$ErrorActionPreference='Stop'
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest=Join-Path $here 'Cargo.toml'

# Candidate helpers: trusted operator/worktree/tools/caches/ACLs are
# prerequisites. An external digest is independently supplied, never
# inferred from a sibling file. This is not an installation trust root.
function Candidate-Hash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-Digest([string]$Digest) {
    if ($Digest -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'Missing or invalid external SHA256' }
}
function Assert-LocalPath([string]$Path, [switch]$Directory) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
        $Path -match '[*?<>|"]' -or [IO.Path]::GetFullPath($Path) -cne $Path) {
        throw "Noncanonical local path: $Path"
    }
    if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path)).DriveType -ne [IO.DriveType]::Fixed) { throw 'Fixed local disk required' }
    $item = Get-Item -LiteralPath $Path -Force
    if ([bool]$item.PSIsContainer -ne [bool]$Directory) { throw "Unexpected object kind: $Path" }
    $cursor = $item
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse path: $Path" }
        $cursor = if ($cursor.PSIsContainer) { $cursor.Parent } else { $cursor.Directory }
    }
    $item.FullName
}
function Assert-FileDigest([string]$Path, [string]$Digest) {
    Assert-Digest $Digest
    $null = Assert-LocalPath $Path
    if ((Candidate-Hash $Path) -ine $Digest) { throw "External digest mismatch: $Path" }
}
function Assert-NewDirectory([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\[ -~]+$' -or $Path.Substring(2).Contains(':') -or
        $Path -match '[*?<>|"]' -or [IO.Path]::GetFullPath($Path) -cne $Path) { throw 'Canonical ASCII directory required' }
    $null = Assert-LocalPath (Split-Path -Parent $Path) -Directory
    if (Test-Path -LiteralPath $Path) { throw "Existing candidate directory refused: $Path" }
}
function Assert-Separate([string]$First, [string]$Second) {
    $a = $First.TrimEnd('\') + '\'
    $b = $Second.TrimEnd('\') + '\'
    if ($a.StartsWith($b,[StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith($a,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Candidate paths overlap'
    }
}
function Invoke-CheckedNative([string]$Exe,[string[]]$Arguments) {
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $lines = @(& $Exe @Arguments 2>&1); $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $prior }
    if ($code -ne 0) { throw "Native command failed ($code): $Exe $Arguments" }
    @($lines | ForEach-Object { $_.ToString() })
}
function Assert-CandidateSource([string]$Root,[string]$Sha) {
    if ($Sha -cnotmatch '^[a-f0-9]{40}$') { throw 'Exact lowercase source SHA required' }
    $null = Assert-LocalPath $Root -Directory
    if ($Root -notmatch '^[A-Za-z]:\\[ -~]+$') { throw 'ASCII source directory required' }
    $git = (Get-Command git.exe -CommandType Application).Source
    if (((Invoke-CheckedNative $git @('-C',$Root,'remote','get-url','origin')) -join '') -cnotmatch '^https://github\.com/weixiaochuchen618-debug/spidervpn(?:\.git)?$') { throw 'Unexpected repository' }
    if (((Invoke-CheckedNative $git @('-C',$Root,'rev-parse','HEAD')) -join '') -cne $Sha) { throw 'Source SHA mismatch' }
    $top = (Invoke-CheckedNative $git @('-C',$Root,'rev-parse','--show-toplevel')) -join ''
    if ($top.Replace('/','\') -ine $Root) { throw 'Not exact worktree root' }
    if (@(Invoke-CheckedNative $git @('-C',$Root,'status','--porcelain=v1','--untracked-files=all','--ignore-submodules=none')).Count -ne 0 -or
        @(Invoke-CheckedNative $git @('-C',$Root,'ls-files','--others')).Count -ne 0) { throw 'Dirty or untracked (including ignored) source inputs' }
    $cursor = Get-Item -LiteralPath $Root
    while ($null -ne $cursor) {
        foreach ($name in @('.cargo\config','.cargo\config.toml')) {
            if (Test-Path -LiteralPath (Join-Path $cursor.FullName $name)) { throw 'Implicit Cargo configuration refused' }
        }
        $cursor = $cursor.Parent
    }
    $lock = Join-Path $Root 'Cargo.lock'
    $null = Assert-LocalPath $lock
    Candidate-Hash $lock
}
function Read-CandidateApproval([string]$Path,[string]$Digest,[string]$Sha) {
    Assert-FileDigest $Path $Digest
    $a = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($a.schema -ne 1 -or $a.sourceSha -cne $Sha -or
        $a.repository -cne 'https://github.com/weixiaochuchen618-debug/spidervpn' -or
        $a.rustVersion -cne '1.100.0' -or $a.target -cne 'x86_64-pc-windows-gnu') { throw 'Approval scope mismatch' }
    foreach ($key in @('gcc','dlltool','ld','loader','engine','license')) {
        $entry = $a.$key
        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace($entry.source) -or [string]::IsNullOrWhiteSpace($entry.version)) { throw "Audited external source/version required: $key" }
        Assert-Digest $entry.sha256
    }
    if ($a.loader.platform -cne 'windows-x64' -or $a.engine.platform -cne 'windows-x64' -or
        $a.license.platform -cne 'windows-x64' -or $a.license.version -cne $a.engine.version) { throw 'Vendor/platform/license scope mismatch' }
    $a
}
function Assert-X64Pe([string]$Path,[switch]$Dll) {
    $null = Assert-LocalPath $Path
    $stream = [IO.File]::OpenRead($Path)
    $rd = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $rd.ReadUInt16() -ne 0x5a4d) { throw 'Not PE' }
        $stream.Position=60; $offset=$rd.ReadUInt32()
        if ($offset -lt 64 -or [long]$offset+26 -gt $stream.Length) { throw 'Invalid PE header' }
        $stream.Position=$offset
        if ($rd.ReadUInt32() -ne 0x4550 -or $rd.ReadUInt16() -ne 0x8664) { throw 'Not x64 PE' }
        $stream.Position=[long]$offset+20
        $size=$rd.ReadUInt16(); $flags=$rd.ReadUInt16()
        if ($size -lt 2 -or [long]$offset+24+$size -gt $stream.Length -or $rd.ReadUInt16() -ne 0x20b -or
            ($flags -band 2) -eq 0 -or [bool]($flags -band 0x2000) -ne [bool]$Dll) { throw 'Wrong PE architecture or kind' }
    } finally { $rd.Dispose(); $stream.Dispose() }
}
function Select-CandidateLoader([string]$Target,[string]$Digest) {
    $candidates = @(Get-ChildItem -LiteralPath $Target -Recurse -File -Force -Filter 'WebView2Loader.dll' | Where-Object { $_.FullName -match '\\x64\\' })
    if ($candidates.Count -ne 1) { throw "Missing or ambiguous current x64 loader: $($candidates.Count)" }
    $loader=$candidates[0].FullName
    Assert-FileDigest $loader $Digest
    Assert-X64Pe $loader -Dll
    $loader
}
function Assert-RustVersion([string]$Rust,[string]$Cargo) {
    if ($Rust -cnotmatch '(?m)^rustc 1\.100\.0(?: |$)' -or $Rust -cnotmatch '(?m)^host: x86_64-pc-windows-gnu\r?$' -or
        $Cargo -cnotmatch '^cargo 1\.100\.0(?: |$)') { throw 'Wrong fixed Rust candidate toolchain' }
}
function Candidate-CargoArguments([string]$Root,[string]$Target) {
    @('run','1.100.0-x86_64-pc-windows-gnu','cargo','build','--locked','--offline','--release',
      '--target','x86_64-pc-windows-gnu','--manifest-path',(Join-Path $Root 'Cargo.toml'),'--target-dir',$Target)
}
function Invoke-CandidateBuild {
    if (-not $Release -or -not $SourceSha -or -not $CandidateTarget -or -not $CandidateOutput -or
        -not $ApprovalFile -or -not $ApprovalSha256 -or -not $MingwBin) { throw 'Candidate requires Release, SHA, new target/output, external approval and explicit MinGW bin' }
    $root=$here
    $lock=Assert-CandidateSource $root $SourceSha
    $a=Read-CandidateApproval $ApprovalFile $ApprovalSha256 $SourceSha
    Assert-Separate $root $ApprovalFile
    Assert-NewDirectory $CandidateTarget
    Assert-NewDirectory $CandidateOutput
    Assert-Separate $root $CandidateTarget
    Assert-Separate $root $CandidateOutput
    Assert-Separate $CandidateTarget $CandidateOutput
    foreach ($var in Get-ChildItem Env:) {
        if ($var.Name -match '^(CARGO_|RUSTC|RUSTFLAGS|RUSTDOC|RUSTUP_TOOLCHAIN|CC$|CXX$|AR$|CFLAGS$|CXXFLAGS$|LDFLAGS$)' -and $var.Name -ne 'CARGO_HOME') {
            throw "Ambient build override: $($var.Name)"
        }
    }
    $cargoHome=if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $null=Assert-LocalPath $cargoHome -Directory
    foreach ($name in @('config','config.toml')) {
        if (Test-Path -LiteralPath (Join-Path $cargoHome $name)) { throw 'Implicit Cargo home config refused' }
    }
    $null=Assert-LocalPath $MingwBin -Directory
    $tools=@{}
    $names=@{gcc='x86_64-w64-mingw32-gcc.exe';dlltool='dlltool.exe';ld='ld.exe'}
    foreach ($key in @('gcc','dlltool','ld')) {
        $tool=Join-Path $MingwBin $names[$key]
        Assert-FileDigest $tool $a.$key.sha256
        $version=(Invoke-CheckedNative $tool @('--version')) -join [Environment]::NewLine
        if (-not $version.Contains([string]$a.$key.version)) { throw "Wrong audited tool version: $key" }
        $tools[$key]=@{path=$tool;sha256=(Candidate-Hash $tool);version=$version;source=$a.$key.source}
    }
    $rustup=(Get-Command rustup.exe -CommandType Application).Source
    $tc='1.100.0-x86_64-pc-windows-gnu'
    $rust=(Invoke-CheckedNative $rustup @('run',$tc,'rustc','-Vv')) -join [Environment]::NewLine
    $cargo=(Invoke-CheckedNative $rustup @('run',$tc,'cargo','-V')) -join [Environment]::NewLine
    Assert-RustVersion $rust $cargo
    $null=New-Item -ItemType Directory -Path $CandidateTarget
    $null=New-Item -ItemType Directory -Path $CandidateOutput
    $null=Assert-LocalPath $CandidateTarget -Directory
    $null=Assert-LocalPath $CandidateOutput -Directory
    $buildArgs=@(Candidate-CargoArguments $root $CandidateTarget)
    $oldPath=$env:Path
    Push-Location $root
    try {
        $env:Path="$MingwBin;$oldPath"
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=$tools.gcc.path
        $log=Invoke-CheckedNative $rustup $buildArgs
        $log | Set-Content -LiteralPath (Join-Path $CandidateOutput 'build.log') -Encoding UTF8
    } finally {
        $env:Path=$oldPath
        Remove-Item Env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER -ErrorAction SilentlyContinue
        Pop-Location
    }
    if ((Assert-CandidateSource $root $SourceSha) -cne $lock) { throw 'Source changed during build' }
    Assert-FileDigest $ApprovalFile $ApprovalSha256
    foreach ($key in @('gcc','dlltool','ld')) { Assert-FileDigest $tools[$key].path $a.$key.sha256 }
    $exe=Join-Path $CandidateTarget 'x86_64-pc-windows-gnu\release\spidervpn.exe'
    Assert-X64Pe $exe
    $loader=Select-CandidateLoader $CandidateTarget $a.loader.sha256
    $destExe=Join-Path $CandidateOutput 'spidervpn.exe'
    $destDll=Join-Path $CandidateOutput 'WebView2Loader.dll'
    Copy-Item -LiteralPath $exe -Destination $destExe
    Copy-Item -LiteralPath $loader -Destination $destDll
    Assert-FileDigest $destExe (Candidate-Hash $exe)
    Assert-FileDigest $destDll $a.loader.sha256
    $receipt=[ordered]@{
        schema=1;kind='client-candidate-build';sourceSha=$SourceSha;repository=$a.repository
        sourceRoot=$root;cargoLockSha256=$lock;approvalSha256=$ApprovalSha256.ToLowerInvariant()
        rustc=$rust;cargo=$cargo;target=$a.target;targetDir=$CandidateTarget;outputDir=$CandidateOutput
        toolchain=$tc;tools=$tools;command=@($rustup)+$buildArgs;exitCode=0
        exeSha256=(Candidate-Hash $destExe);loaderSha256=(Candidate-Hash $destDll)
        loaderSource=$loader;buildLogSha256=(Candidate-Hash (Join-Path $CandidateOutput 'build.log'))
        serverBuild='NOT RUN in client script; separate server-rs/Cargo.lock and Linux CI'
    }
    $record=Join-Path $CandidateOutput 'build-evidence.json'
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $record -Encoding UTF8
    [pscustomobject]@{BuildEvidence=$record;BuildEvidenceSha256=(Candidate-Hash $record);SourceSha=$SourceSha;Status='UNAPPROVED CANDIDATE BUILD; independent review required'}
}

if ($MyInvocation.InvocationName -eq '.') { return }
if ($Candidate) { Invoke-CandidateBuild; return }
if ($SourceSha -or $CandidateTarget -or $CandidateOutput -or $ApprovalFile -or $ApprovalSha256 -or $MingwBin) { throw 'Candidate inputs require -Candidate' }
$targetDir='C:\tc-rs-build'

# 1. 找到完整 MinGW-w64（WinLibs）。查找顺序：PATH → 便携目录 → WinGet 包。
#    便携目录是为了「解压即用」的机器：不需要改系统 PATH。
$gccCommand=Get-Command 'x86_64-w64-mingw32-gcc.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if($gccCommand){
  $mingwBin=Split-Path -Parent $gccCommand.Source
}elseif(Test-Path 'C:\tc-rs-tools\winlibs\mingw64\bin\x86_64-w64-mingw32-gcc.exe'){
  $mingwBin='C:\tc-rs-tools\winlibs\mingw64\bin'
}else{
  $gcc=Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter 'x86_64-w64-mingw32-gcc.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if(-not $gcc){
    throw ('找不到 MinGW-w64（WinLibs）。三种办法任选一种：' + [Environment]::NewLine +
      '  1) winget install BrechtSanders.WinLibs.POSIX.UCRT' + [Environment]::NewLine +
      '  2) 把 WinLibs 解压到 C:\tc-rs-tools\winlibs（本脚本会自动找到）' + [Environment]::NewLine +
      '  3) 把它的 bin 目录加入 PATH')
  }
  $mingwBin=$gcc.DirectoryName
}

$cargoBin=Join-Path $env:USERPROFILE '.cargo\bin'
if(-not (Test-Path (Join-Path $cargoBin 'cargo.exe'))){ throw '找不到 cargo，先装 rustup' }

$env:Path="$cargoBin;$mingwBin;$env:Path"
$env:CARGO_TARGET_DIR=$targetDir

# 2. 在纯英文目录下调用，避开非 ASCII 路径
Push-Location 'C:\'
try{
  # cargo 把「Compiling …」这类进度写到 stderr。PowerShell 5.1 在
  # $ErrorActionPreference='Stop' 下会把原生程序写的 stderr 包成
  # NativeCommandError 直接抛，于是构建明明还在跑、脚本却已经判失败
  # （本机实测：22 秒就退出，只报一句 Compiling spidervpn）。
  # 这里局部放宽，成败只认退出码。
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try{
    if($Release){
      & cargo +stable-x86_64-pc-windows-gnu build --locked --release --manifest-path $manifest
    }else{
      & cargo +stable-x86_64-pc-windows-gnu build --locked --manifest-path $manifest
    }
  }finally{
    $ErrorActionPreference = $eap
  }
  if($LASTEXITCODE -ne 0){ throw ("构建失败，退出码 " + $LASTEXITCODE) }
}finally{ Pop-Location }

$outDir = if($Release){Join-Path $targetDir 'release'}else{Join-Path $targetDir 'debug'}
$exe=Join-Path $outDir 'spidervpn.exe'
if(-not (Test-Path $exe)){ throw ('构建成功但找不到产物：'+$exe) }

# 3. 复制 x64 的 WebView2 加载器（arm64/x86 的不能混用，否则 0xC000007B）
$loader=Get-ChildItem $targetDir -Recurse -Filter 'WebView2Loader.dll' -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if($loader){ Copy-Item $loader.FullName (Join-Path $outDir 'WebView2Loader.dll') -Force }
else { Write-Warning '未找到 x64 的 WebView2Loader.dll，程序启动会报 0xC0000135' }

[pscustomobject]@{
  Exe=$exe
  SizeMB=[math]::Round((Get-Item $exe).Length/1MB,1)
  Loader=($null -ne $loader)
}
