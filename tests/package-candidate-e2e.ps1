#requires -Version 5.1
# Actual disposable PE files and ZIPs, never an approved build/release.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'package.ps1')
function Refuse([string]$Name,[scriptblock]$Action) {
    $refused=$false
    try { & $Action | Out-Null } catch { $refused=$true; Write-Host "CANDIDATE_TEST_REFUSED $Name" }
    if (-not $refused) { throw "Unexpected acceptance: $Name" }
}
$temp=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ("spider-candidate-TEST-ONLY-"+[guid]::NewGuid().ToString('N'))))
$null=New-Item -ItemType Directory -Path $temp
try {
    $stage=Join-Path $temp 'TEST-ONLY-stage'
    $null=New-Item -ItemType Directory -Path $stage
    $null=New-Item -ItemType Directory -Path (Join-Path $stage 'install')
    foreach ($name in (Candidate-Names)) {
        Set-Content -LiteralPath (Join-Path $stage $name.Replace('/','\')) -Value "TEST ONLY $name" -Encoding UTF8
    }
    $exe=Join-Path $stage 'spidervpn.exe'
    $dll=Join-Path $stage 'WebView2Loader.dll'
    Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination $exe -Force
    Copy-Item -LiteralPath "$env:SystemRoot\System32\kernel32.dll" -Destination $dll -Force
    Copy-Item -LiteralPath $exe -Destination (Join-Path $stage 'sing-box.exe') -Force
    Assert-X64Pe $exe
    Assert-X64Pe $dll -Dll
    Refuse 'wrong-pe-kind' { Assert-X64Pe $exe -Dll }
    $bad=Join-Path $temp 'bad-machine.dll'
    Copy-Item -LiteralPath $dll -Destination $bad
    $stream=[IO.File]::Open($bad,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
    try {
        $rd=[IO.BinaryReader]::new($stream,[Text.Encoding]::UTF8,$true)
        $stream.Position=60; $offset=$rd.ReadUInt32(); $rd.Dispose()
        $stream.Position=[long]$offset+4; $stream.WriteByte(0x4c); $stream.WriteByte(1)
    } finally { $stream.Dispose() }
    Refuse 'wrong-x64' { Assert-X64Pe $bad -Dll }
    $hash=Candidate-Hash $dll
    Refuse 'wrong-hash' { Assert-FileDigest $dll ('0'*64) }
    $target=Join-Path $temp 'empty-target'
    Assert-NewDirectory $target
    $null=New-Item -ItemType Directory -Path $target
    Refuse 'old-target' { Assert-NewDirectory $target }
    Refuse 'overlap' { Assert-Separate $target (Join-Path $target 'output') }
    Refuse 'missing-loader' { Select-CandidateLoader $target $hash }
    $x64=Join-Path $target 'first\x64'
    $null=New-Item -ItemType Directory -Path $x64 -Force
    Copy-Item -LiteralPath $dll -Destination (Join-Path $x64 'WebView2Loader.dll')
    $null=Select-CandidateLoader $target $hash
    $second=Join-Path $target 'second\x64'
    $null=New-Item -ItemType Directory -Path $second -Force
    Copy-Item -LiteralPath $dll -Destination (Join-Path $second 'WebView2Loader.dll')
    Refuse 'ambiguous-loader' { Select-CandidateLoader $target $hash }
    $buildArgs=@(Candidate-CargoArguments $repo $target)
    if ($buildArgs -cnotcontains '--locked' -or $buildArgs -cnotcontains '--offline' -or
        $buildArgs -cnotcontains '1.100.0-x86_64-pc-windows-gnu') { throw 'Missing fixed locked build command' }
    Refuse 'wrong-toolchain' { Assert-RustVersion ('rustc 1.99.0'+[Environment]::NewLine+'host: x86_64-pc-windows-gnu') 'cargo 1.99.0' }
    Refuse 'wrong-source-sha' { Assert-CandidateSource $repo ('0'*40) }
    Refuse 'legacy-output' { Read-CandidateBuild 'C:\tc-rs-build\release' ('0'*64) $repo ('0'*40) ('0'*64) @{} ('0'*64) }
    Refuse 'missing-approval' { Read-CandidateApproval (Join-Path $temp 'absent.json') ('0'*64) ('0'*40) }
    $approval=Join-Path $temp 'TEST-ONLY-approval.json'
    $record=[ordered]@{schema=1;sourceSha=('a'*40);repository='https://github.com/weixiaochuchen618-debug/spidervpn';rustVersion='1.100.0';target='x86_64-pc-windows-gnu'}
    foreach ($key in @('gcc','dlltool','ld','loader','engine','license')) {
        $record[$key]=@{source='TEST ONLY system fixture, not vendor';version='fixture';platform='windows-x64';sha256=$hash}
    }
    $record.engine.sha256=''
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $approval -Encoding UTF8
    Refuse 'missing-engine-digest' { Read-CandidateApproval $approval (Candidate-Hash $approval) ('a'*40) }
    $record.engine.sha256=$hash; $record.Remove('license')
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $approval -Encoding UTF8
    Refuse 'missing-license-approval' { Read-CandidateApproval $approval (Candidate-Hash $approval) ('a'*40) }
    $license=Join-Path $stage 'sing-box.LICENSE.txt'
    $saved=[IO.File]::ReadAllBytes($license)
    Remove-Item -LiteralPath $license
    Refuse 'missing-license-file' { New-CandidateManifest $stage }
    [IO.File]::WriteAllBytes($license,$saved)
    $extra=Join-Path $stage 'unknown.exe'
    Copy-Item -LiteralPath $exe -Destination $extra
    Refuse 'unknown-file' { New-CandidateManifest $stage }
    Remove-Item -LiteralPath $extra
    $entries=@(New-CandidateManifest $stage)
    Refuse 'manifest-duplicate' { Assert-CandidateManifest (@($entries[0])+@($entries[0])+@($entries | Select-Object -Skip 2)) }
    Refuse 'manifest-missing' { Assert-CandidateManifest @($entries | Select-Object -Skip 1) }
    $escape=@($entries | ForEach-Object { [pscustomobject]@{path=$_.path;size=$_.size;sha256=$_.sha256} })
    $escape[0].path='../escape.exe'
    Refuse 'manifest-escape' { Assert-CandidateManifest $escape }
    $case=@($entries | ForEach-Object { [pscustomobject]@{path=$_.path;size=$_.size;sha256=$_.sha256} })
    $case[1].path=$case[0].path.ToUpperInvariant()
    Refuse 'manifest-case-collision' { Assert-CandidateManifest $case }
    $manifest=Join-Path $stage 'manifest.json'
    @{kind='TEST-ONLY-NOT-RELEASE';files=$entries} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
    $mh=Candidate-Hash $manifest; $ms=(Get-Item -LiteralPath $manifest).Length
    $zip=Join-Path $temp 'TEST-ONLY.zip'
    Write-CandidateZip $stage $zip $entries $mh
    Assert-CandidateZip $zip $entries $mh $ms
    Add-Content -LiteralPath $license -Value 'replacement'
    Refuse 'stage-replaced' { Assert-StageManifest $stage $entries $mh }
    [IO.File]::WriteAllBytes($license,$saved)
    foreach ($mode in @('zip-escape','zip-duplicate','zip-content')) {
        $badzip=Join-Path $temp "$mode.zip"
        Copy-Item -LiteralPath $zip -Destination $badzip
        $zs=[IO.File]::Open($badzip,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        $za=[IO.Compression.ZipArchive]::new($zs,[IO.Compression.ZipArchiveMode]::Update)
        try {
            if ($mode -eq 'zip-escape') {
                $za.GetEntry('sing-box.LICENSE.txt').Delete(); $null=$za.CreateEntry('../escape.txt')
            } elseif ($mode -eq 'zip-duplicate') {
                $za.GetEntry('sing-box.LICENSE.txt').Delete(); $null=$za.CreateEntry('SPIDERVPN.EXE')
            } else {
                $zout=$za.GetEntry('sing-box.LICENSE.txt').Open()
                try { $zout.Position=0; $zout.WriteByte(0xff) } finally { $zout.Dispose() }
            }
        } finally { $za.Dispose(); $zs.Dispose() }
        Refuse $mode { Assert-CandidateZip $badzip $entries $mh $ms }
    }
    $j=Join-Path $temp 'junction'
    & "$env:SystemRoot\System32\cmd.exe" /D /C mklink /J $j $stage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create required junction fixture' }
    try { Refuse 'reparse-path' { Assert-LocalPath (Join-Path $j 'spidervpn.exe') } }
    finally { [IO.Directory]::Delete($j) }
    Write-Host 'PACKAGE_CANDIDATE_TEST_COMPLETE actual_fixture_zip=true actual_pe=true external_vendor_verified=false actual_candidate_build=false release=false'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
