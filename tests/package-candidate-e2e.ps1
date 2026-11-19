#requires -Version 5.1
# Actual disposable PE files and ZIPs, never an approved build/release.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'package.ps1')
function Refuse([string]$Name,[string]$Reason,[scriptblock]$Action) {
    $refused=$false
    try { & $Action | Out-Null } catch {
        if (-not $_.Exception.Message.StartsWith($Reason,[StringComparison]::Ordinal)) {
            throw "Unexpected refusal for ${Name}: expected '$Reason'; actual '$($_.Exception.Message)'"
        }
        $refused=$true
        Write-Host "CANDIDATE_TEST_REFUSED $Name reason=$($_.Exception.Message)"
    }
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
    Refuse 'wrong-pe-kind' 'Wrong PE architecture or kind' { Assert-X64Pe $exe -Dll }
    $bad=Join-Path $temp 'bad-machine.dll'
    Copy-Item -LiteralPath $dll -Destination $bad
    $stream=[IO.File]::Open($bad,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
    try {
        $rd=[IO.BinaryReader]::new($stream,[Text.Encoding]::UTF8,$true)
        $stream.Position=60; $offset=$rd.ReadUInt32(); $rd.Dispose()
        $stream.Position=[long]$offset+4; $stream.WriteByte(0x4c); $stream.WriteByte(1)
    } finally { $stream.Dispose() }
    Refuse 'wrong-x64' 'Not x64 PE' { Assert-X64Pe $bad -Dll }
    $hash=Candidate-Hash $dll
    Refuse 'wrong-hash' 'External digest mismatch:' { Assert-FileDigest $dll ('0'*64) }
    $target=Join-Path $temp 'empty-target'
    Assert-NewDirectory $target
    $null=New-Item -ItemType Directory -Path $target
    Refuse 'old-target' 'Existing candidate directory refused:' { Assert-NewDirectory $target }
    Refuse 'overlap' 'Candidate paths overlap' { Assert-Separate $target (Join-Path $target 'output') }
    Refuse 'missing-loader' 'Missing or ambiguous current x64 loader: 0' { Select-CandidateLoader $target $hash }
    $x64=Join-Path $target 'first\x64'
    $null=New-Item -ItemType Directory -Path $x64 -Force
    Copy-Item -LiteralPath $dll -Destination (Join-Path $x64 'WebView2Loader.dll')
    $null=Select-CandidateLoader $target $hash
    $second=Join-Path $target 'second\x64'
    $null=New-Item -ItemType Directory -Path $second -Force
    Copy-Item -LiteralPath $dll -Destination (Join-Path $second 'WebView2Loader.dll')
    Refuse 'ambiguous-loader' 'Missing or ambiguous current x64 loader: 2' { Select-CandidateLoader $target $hash }
    $buildArgs=@(Candidate-CargoArguments $repo $target)
    if ($buildArgs -cnotcontains '--locked' -or $buildArgs -cnotcontains '--offline' -or
        $buildArgs -cnotcontains '1.100.0-x86_64-pc-windows-gnu') { throw 'Missing fixed locked build command' }
    Refuse 'wrong-toolchain' 'Wrong fixed Rust candidate toolchain' { Assert-RustVersion ('rustc 1.99.0'+[Environment]::NewLine+'host: x86_64-pc-windows-gnu') 'cargo 1.99.0' }
    # Genuine local disposable git tree; not a SpiderVPN release or an
    # external source proof. Verify correct HEAD then wrong HEAD/dirty
    # tracked/ignored inputs separately so a universal refusal cannot pass.
    $fixtureRepo=Join-Path $temp 'source-TEST-ONLY'
    $null=New-Item -ItemType Directory -Path $fixtureRepo
    # For this disposable fixture only, use the runner's actual PATH
    # precedence explicitly. This is not a production approval.
    $matches=@(Get-Command git.exe -CommandType Application -All)
    if ($matches.Count -eq 0) { throw 'Git fixture tool missing' }
    $git=Resolve-CandidateApplication 'git.exe' $matches[0].Source
    $gitVersion=(Invoke-CheckedNative $git @('--version')) -join ''
    if ($gitVersion -notmatch '^git version ') { throw 'Git fixture version missing' }
    $toolA=Join-Path $temp 'toolA'; $toolB=Join-Path $temp 'toolB'
    $null=New-Item -ItemType Directory -Path $toolA,$toolB
    # Only discover these harmless copies; do not execute them as git.
    Copy-Item -LiteralPath $exe -Destination (Join-Path $toolA 'git.exe')
    Copy-Item -LiteralPath $exe -Destination (Join-Path $toolB 'git.exe')
    $oldPath=$env:Path
    try {
        $env:Path="$toolA;$toolB;$oldPath"
        Refuse 'multiple-git-paths' 'Native application missing or ambiguous: git.exe' { Resolve-CandidateApplication 'git.exe' '' }
        if ((Resolve-CandidateApplication 'git.exe' $git) -cne $git) { throw 'Explicit git selection failed' }
    } finally { $env:Path=$oldPath }
    $LASTEXITCODE=0
    Refuse 'native-missing-stale-zero' 'Native application missing:' { Invoke-CheckedNative (Join-Path $temp 'missing.exe') @() }
    $notExe=Join-Path $temp 'not-an-image.exe'
    Set-Content -LiteralPath $notExe -Value 'TEST ONLY not executable'
    $LASTEXITCODE=0
    Refuse 'native-launch-stale-zero' 'Native application launch failed:' { Invoke-CheckedNative $notExe @() }
    Refuse 'native-nonzero' 'Native command failed (' { Invoke-CheckedNative $git @('--not-a-real-git-option') }

    $null=Invoke-CheckedNative $git @('-C',$fixtureRepo,'init','-q')
    $null=Invoke-CheckedNative $git @('-C',$fixtureRepo,'remote','add','origin','https://github.com/weixiaochuchen618-debug/spidervpn')
    Set-Content -LiteralPath (Join-Path $fixtureRepo 'Cargo.lock') -Value 'TEST ONLY lock bytes'
    Set-Content -LiteralPath (Join-Path $fixtureRepo '.gitignore') -Value 'ignored.txt'
    $null=Invoke-CheckedNative $git @('-C',$fixtureRepo,'add','--','Cargo.lock','.gitignore')
    $null=Invoke-CheckedNative $git @('-C',$fixtureRepo,'-c','user.name=Test Only','-c','user.email=test-only@example.invalid','-c','commit.gpgsign=false','commit','-qm','disposable fixture')
    $fixtureSha=(Invoke-CheckedNative $git @('-C',$fixtureRepo,'rev-parse','HEAD')) -join ''
    if ((Assert-CandidateSource $fixtureRepo $fixtureSha $git) -cne (Candidate-Hash (Join-Path $fixtureRepo 'Cargo.lock'))) { throw 'Clean source positive failed' }
    Refuse 'wrong-source-sha' 'Source SHA mismatch' { Assert-CandidateSource $fixtureRepo ('0'*40) $git }
    Add-Content -LiteralPath (Join-Path $fixtureRepo 'Cargo.lock') -Value 'dirty'
    Refuse 'dirty-tracked' 'Dirty or untracked (including ignored) source inputs' { Assert-CandidateSource $fixtureRepo $fixtureSha $git }
    $null=Invoke-CheckedNative $git @('-C',$fixtureRepo,'restore','Cargo.lock')
    Set-Content -LiteralPath (Join-Path $fixtureRepo 'ignored.txt') -Value 'unknown ignored build input'
    Refuse 'ignored-untracked' 'Dirty or untracked (including ignored) source inputs' { Assert-CandidateSource $fixtureRepo $fixtureSha $git }
    Remove-Item -LiteralPath (Join-Path $fixtureRepo 'ignored.txt')
    $null=Assert-CandidateSource $fixtureRepo $fixtureSha $git
    Refuse 'actual-build-entry-no-approval' 'Candidate requires Release, SHA, new target/output, external approval and explicit tools' { & (Join-Path $repo 'build.ps1') -Candidate -Release }
    Refuse 'actual-package-entry-no-input' 'Explicit version, SHA, build evidence, external approval, engine/license and new output required' { & (Join-Path $repo 'package.ps1') }

    Refuse 'legacy-output' 'Shared legacy output refused' { Read-CandidateBuild 'C:\tc-rs-build\release' ('0'*64) $repo ('0'*40) ('0'*64) @{} ('0'*64) }
    Refuse 'missing-approval' 'Missing local object:' { Read-CandidateApproval (Join-Path $temp 'absent.json') ('0'*64) ('0'*40) }
    $approval=Join-Path $temp 'TEST-ONLY-approval.json'
    $record=[ordered]@{schema=1;sourceSha=('a'*40);repository='https://github.com/weixiaochuchen618-debug/spidervpn';rustVersion='1.100.0';target='x86_64-pc-windows-gnu'}
    foreach ($key in @('git','rustup','gcc','dlltool','ld','loader','engine','license')) {
        $record[$key]=@{source='TEST ONLY system fixture, not vendor';version='fixture';platform='windows-x64';sha256=$hash}
    }
    $record.engine.sha256=''
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $approval -Encoding UTF8
    Refuse 'missing-engine-digest' 'Missing or invalid external SHA256' { Read-CandidateApproval $approval (Candidate-Hash $approval) ('a'*40) }
    $record.engine.sha256=$hash; $record.Remove('license')
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $approval -Encoding UTF8
    Refuse 'missing-license-approval' 'Audited external source/version required: license' { Read-CandidateApproval $approval (Candidate-Hash $approval) ('a'*40) }
    $record.license=@{source='TEST ONLY';version='fixture';platform='windows-x64';sha256=$hash}
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $approval -Encoding UTF8
    $null=Read-CandidateApproval $approval (Candidate-Hash $approval) ('a'*40)
    Refuse 'external-approval-hash-mismatch' 'External digest mismatch:' { Read-CandidateApproval $approval ('0'*64) ('a'*40) }

    # Full evidence-directory validation, deliberately TEST ONLY. No
    # compiler claim: the images are known harmless system copies.
    $buildDir=Join-Path $temp 'build-TEST-ONLY'
    $null=New-Item -ItemType Directory -Path $buildDir
    Copy-Item -LiteralPath $exe -Destination (Join-Path $buildDir 'spidervpn.exe')
    Copy-Item -LiteralPath $dll -Destination (Join-Path $buildDir 'WebView2Loader.dll')
    $log=Join-Path $buildDir 'build.log'
    Set-Content -LiteralPath $log -Value 'TEST ONLY: no candidate compiler invoked'
    $ad=Candidate-Hash $approval
    $approved=Read-CandidateApproval $approval $ad ('a'*40)
    $receiptPath=Join-Path $buildDir 'build-evidence.json'
    $tools=@{}
    foreach ($key in @('git','rustup','gcc','dlltool','ld')) {
        $tools[$key]=@{path=(Join-Path $temp "$key.exe");source=$approved.$key.source;version=$approved.$key.version;sha256=$approved.$key.sha256}
    }
    $receipt=[ordered]@{
        schema=1;kind='client-candidate-build';sourceSha=('a'*40);repository=$approved.repository
        sourceRoot=$fixtureRepo;outputDir=$buildDir;targetDir=$target;cargoLockSha256=(Candidate-Hash (Join-Path $fixtureRepo 'Cargo.lock'))
        approvalSha256=$ad;target=$approved.target;toolchain='1.100.0-x86_64-pc-windows-gnu';exitCode=0
        rustc=('rustc 1.100.0 TEST ONLY'+[Environment]::NewLine+'host: x86_64-pc-windows-gnu');cargo='cargo 1.100.0 TEST ONLY'
        tools=$tools;command=@($tools.rustup.path)+@(Candidate-CargoArguments $fixtureRepo $target)
        exeSha256=(Candidate-Hash $exe);loaderSha256=$hash;buildLogSha256=(Candidate-Hash $log)
    }
    function Save-TestReceipt {
        $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
        Candidate-Hash $receiptPath
    }
    function Read-TestReceipt([string]$Digest) {
        Read-CandidateBuild $buildDir $Digest $fixtureRepo ('a'*40) $ad $approved $receipt.cargoLockSha256
    }
    $rdigest=Save-TestReceipt
    $null=Read-TestReceipt $rdigest
    Refuse 'build-record-external-hash' 'External digest mismatch:' { Read-TestReceipt ('0'*64) }
    $receipt.sourceSha='b'*40
    $changed=Save-TestReceipt
    Refuse 'build-record-wrong-source' 'Build evidence scope mismatch' { Read-TestReceipt $changed }
    $receipt.sourceSha='a'*40
    $savedCommand=$receipt.command
    $receipt.command=@($savedCommand | Where-Object {$_ -cne '--locked'})
    $changed=Save-TestReceipt
    Refuse 'build-record-unlocked' 'Build command mismatch' { Read-TestReceipt $changed }
    $receipt.command=$savedCommand
    $rdigest=Save-TestReceipt
    $artifact=Join-Path $buildDir 'spidervpn.exe'
    Add-Content -LiteralPath $artifact -Value 'replacement'
    Refuse 'build-artifact-replaced' 'External digest mismatch:' { Read-TestReceipt $rdigest }
    Copy-Item -LiteralPath $exe -Destination $artifact -Force
    $savedLog=[IO.File]::ReadAllBytes($log)
    Add-Content -LiteralPath $log -Value 'replacement'
    Refuse 'build-log-replaced' 'External digest mismatch:' { Read-TestReceipt $rdigest }
    [IO.File]::WriteAllBytes($log,$savedLog)
    Remove-Item -LiteralPath (Join-Path $buildDir 'WebView2Loader.dll')
    Refuse 'build-missing-loader' 'Unexpected build output set' { Read-TestReceipt $rdigest }
    Copy-Item -LiteralPath $dll -Destination (Join-Path $buildDir 'WebView2Loader.dll')
    Set-Content -LiteralPath (Join-Path $buildDir 'extra.txt') -Value 'unexpected'
    Refuse 'build-extra-file' 'Unexpected build output set' { Read-TestReceipt $rdigest }
    Remove-Item -LiteralPath (Join-Path $buildDir 'extra.txt')
    $null=Read-TestReceipt $rdigest
    Write-Host 'CANDIDATE_BUILD_EVIDENCE_FIXTURE_COMPLETE actual_files=true real_build=false'
    $license=Join-Path $stage 'sing-box.LICENSE.txt'
    $saved=[IO.File]::ReadAllBytes($license)
    Remove-Item -LiteralPath $license
    Refuse 'missing-license-file' 'Incomplete or extra file set' { New-CandidateManifest $stage }
    [IO.File]::WriteAllBytes($license,$saved)
    $extra=Join-Path $stage 'unknown.exe'
    Copy-Item -LiteralPath $exe -Destination $extra
    Refuse 'unknown-file' 'Incomplete or extra file set' { New-CandidateManifest $stage }
    Remove-Item -LiteralPath $extra
    $entries=@(New-CandidateManifest $stage)
    Refuse 'manifest-duplicate' 'Invalid, duplicate or unknown manifest entry' { Assert-CandidateManifest (@($entries[0])+@($entries[0])+@($entries | Select-Object -Skip 2)) }
    Refuse 'manifest-missing' 'Manifest count mismatch' { Assert-CandidateManifest @($entries | Select-Object -Skip 1) }
    $escape=@($entries | ForEach-Object { [pscustomobject]@{path=$_.path;size=$_.size;sha256=$_.sha256} })
    $escape[0].path='../escape.exe'
    Refuse 'manifest-escape' 'Invalid, duplicate or unknown manifest entry' { Assert-CandidateManifest $escape }
    $case=@($entries | ForEach-Object { [pscustomobject]@{path=$_.path;size=$_.size;sha256=$_.sha256} })
    $case[1].path=$case[0].path.ToUpperInvariant()
    Refuse 'manifest-case-collision' 'Invalid, duplicate or unknown manifest entry' { Assert-CandidateManifest $case }
    $manifest=Join-Path $stage 'manifest.json'
    @{kind='TEST-ONLY-NOT-RELEASE';files=$entries} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
    $mh=Candidate-Hash $manifest; $ms=(Get-Item -LiteralPath $manifest).Length
    $zip=Join-Path $temp 'TEST-ONLY.zip'
    Write-CandidateZip $stage $zip $entries $mh
    Assert-CandidateZip $zip $entries $mh $ms
    Add-Content -LiteralPath $license -Value 'replacement'
    Refuse 'stage-replaced' 'Manifest size mismatch' { Assert-StageManifest $stage $entries $mh }
    [IO.File]::WriteAllBytes($license,$saved)
    foreach ($mode in @('zip-escape','zip-duplicate','zip-content','zip-missing','zip-link')) {
        $badzip=Join-Path $temp "$mode.zip"
        Copy-Item -LiteralPath $zip -Destination $badzip
        $zs=[IO.File]::Open($badzip,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        $za=[IO.Compression.ZipArchive]::new($zs,[IO.Compression.ZipArchiveMode]::Update)
        try {
            if ($mode -eq 'zip-escape') {
                $za.GetEntry('sing-box.LICENSE.txt').Delete(); $null=$za.CreateEntry('../escape.txt')
            } elseif ($mode -eq 'zip-duplicate') {
                $za.GetEntry('sing-box.LICENSE.txt').Delete(); $null=$za.CreateEntry('SPIDERVPN.EXE')
            } elseif ($mode -eq 'zip-missing') {
                $za.GetEntry('sing-box.LICENSE.txt').Delete()
            } elseif ($mode -eq 'zip-link') {
                $za.GetEntry('sing-box.LICENSE.txt').ExternalAttributes=0x400
            } else {
                $zout=$za.GetEntry('sing-box.LICENSE.txt').Open()
                try { $zout.Position=0; $zout.WriteByte(0xff) } finally { $zout.Dispose() }
            }
        } finally { $za.Dispose(); $zs.Dispose() }
        $why= switch ($mode) {
            'zip-content' {'ZIP hash mismatch: sing-box.LICENSE.txt'}
            'zip-missing' {'ZIP count mismatch'}
            'zip-link' {'ZIP link entry'}
            default {'ZIP unknown/duplicate/path escape:'}
        }
        Refuse $mode $why { Assert-CandidateZip $badzip $entries $mh $ms }
    }
    $j=Join-Path $temp 'junction'
    & "$env:SystemRoot\System32\cmd.exe" /D /C mklink /J $j $stage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create required junction fixture' }
    try { Refuse 'reparse-path' 'Reparse path:' { Assert-LocalPath (Join-Path $j 'spidervpn.exe') } }
    finally { [IO.Directory]::Delete($j) }
    Write-Host 'PACKAGE_CANDIDATE_TEST_COMPLETE actual_fixture_zip=true actual_pe=true external_vendor_verified=false actual_candidate_build=false release=false'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
