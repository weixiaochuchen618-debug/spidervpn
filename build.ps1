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
#>
[CmdletBinding()]
param([switch]$Release)

$ErrorActionPreference='Stop'
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest=Join-Path $here 'Cargo.toml'
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
      & cargo +stable-x86_64-pc-windows-gnu build --release --manifest-path $manifest
    }else{
      & cargo +stable-x86_64-pc-windows-gnu build --manifest-path $manifest
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
