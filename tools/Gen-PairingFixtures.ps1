<#
.SYNOPSIS
    重新生成 tests/fixtures/pairing 下的「对端口径」向量（JWE 与 DPAPI）。

.DESCRIPTION
    这些向量刻意**不由 Rust 侧生成**：

      * JWE：用 .NET 的 RSA / AES / HMACSHA512 按 RFC 7518 手工组装紧凑序列化，
        原语与对端 jose-jwt 相同，代码与 src/pairing.rs 的 jwe 模块没有任何共享。
        它能证明的是「别人做出来的信封本实现能解开」，而不是「实现与自己的封装器自洽」。
      * DPAPI：用 Win32 CryptProtectData / CryptUnprotectData（tools/dpapi_tool.c，
        mingw gcc 编译）。不用 [System.Security.Cryptography.ProtectedData] 的原因：
        PowerShell 5.1 跑在 .NET Framework 上，System.Security.dll 不在默认加载集，
        而本机策略禁止 Add-Type / Assembly.Load。

    注意：DPAPI 信封绑定「当前 Windows 账户 + 当前机器」。把仓库换一台机器或换一个
    账户跑测试，dotnet-dpapi-*.json 会解不开——那说明夹具过期，不是实现有 bug，
    重跑本脚本即可（见 tests/fixtures/pairing/README.md）。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\Gen-PairingFixtures.ps1

.NOTES
    这里生成的所有私钥/密钥都是**一次性测试夹具**，绝不可用于真实配对。
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$GccPath = ''
)

$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'

if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$fixtureDir = Join-Path $RepositoryRoot 'tests\fixtures\pairing'
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null

# ---------------------------------------------------------------- 编码工具

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertTo-DerLength {
    param([int]$Length)
    if ($Length -lt 0x80) {
        return , ([byte[]]@([byte]$Length))
    }
    $tail = New-Object System.Collections.Generic.List[byte]
    $n = $Length
    while ($n -gt 0) {
        $tail.Insert(0, [byte]($n -band 0xFF))
        $n = $n -shr 8
    }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte](0x80 -bor $tail.Count))
    $out.AddRange($tail)
    return , $out.ToArray()
}

function New-DerTlv {
    param([byte]$Tag, [byte[]]$Content)
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add($Tag)
    $out.AddRange([byte[]](ConvertTo-DerLength -Length $Content.Length))
    $out.AddRange($Content)
    return , $out.ToArray()
}

function New-DerInteger {
    param([byte[]]$Value)
    $start = 0
    while ($start -lt ($Value.Length - 1) -and $Value[$start] -eq 0) { $start++ }
    $trimmed = New-Object System.Collections.Generic.List[byte]
    for ($i = $start; $i -lt $Value.Length; $i++) { $trimmed.Add($Value[$i]) }
    if (($trimmed[0] -band 0x80) -ne 0) { $trimmed.Insert(0, [byte]0) }
    return , (New-DerTlv -Tag 0x02 -Content $trimmed.ToArray())
}

# .NET Framework 的 RSA 没有 ExportPkcs8PrivateKey()/ExportPkcs8PrivateKeyPem()（.NET 5+ 才有），
# 所以这里按 RFC 5208 + RFC 8017 自己拼 DER：PrivateKeyInfo { 0, {rsaEncryption,NULL}, OCTET STRING(RSAPrivateKey) }。
function New-Pkcs8Pem {
    param([System.Security.Cryptography.RSAParameters]$Parameters)

    $version = New-DerInteger -Value ([byte[]]@(0))
    $algorithm = New-DerTlv -Tag 0x30 -Content ([byte[]](
            (New-DerTlv -Tag 0x06 -Content ([byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01))) +
            (New-DerTlv -Tag 0x05 -Content ([byte[]]@()))))

    $rsa = New-Object System.Collections.Generic.List[byte]
    $rsa.AddRange($version)
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.Modulus)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.Exponent)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.D)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.P)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.Q)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.DP)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.DQ)))
    $rsa.AddRange([byte[]](New-DerInteger -Value ([byte[]]$Parameters.InverseQ)))
    $pkcs1 = New-DerTlv -Tag 0x30 -Content $rsa.ToArray()

    $info = New-Object System.Collections.Generic.List[byte]
    $info.AddRange($version)
    $info.AddRange($algorithm)
    $info.AddRange([byte[]](New-DerTlv -Tag 0x04 -Content $pkcs1))
    $der = New-DerTlv -Tag 0x30 -Content $info.ToArray()

    $base64 = [Convert]::ToBase64String($der)
    $lines = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
        $lines.Add($base64.Substring($i, [Math]::Min(64, $base64.Length - $i)))
    }
    return "-----BEGIN PRIVATE KEY-----`n" + ($lines -join "`n") + "`n-----END PRIVATE KEY-----"
}

function New-TestRsa {
    param([int]$Bits)
    # 必须是 RSACng：RSA.Create() 在 .NET Framework 上返回 RSACryptoServiceProvider，
    # 它的 KeySize 只读、且 OAEP 只支持 SHA-1（用不了 RSA-OAEP-256）。
    $rsa = New-Object System.Security.Cryptography.RSACng
    $rsa.KeySize = $Bits   # 首次使用前设定才会生效（CNG 按需生成密钥）
    return $rsa
}

function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return , $bytes
}

function Add-Pkcs7Padding {
    param([byte[]]$Plain)
    $pad = 16 - ($Plain.Length % 16)
    $out = New-Object byte[] ($Plain.Length + $pad)
    [Array]::Copy($Plain, 0, $out, 0, $Plain.Length)
    for ($i = $Plain.Length; $i -lt $out.Length; $i++) { $out[$i] = [byte]$pad }
    return , $out
}

# ---------------------------------------------------------------- JWE（RFC 7516/7518）

function New-JweCompact {
    param(
        [System.Security.Cryptography.RSA]$Rsa,
        [string]$HeaderJson,
        [byte[]]$Plain,
        # 故意的错误变体：AL 写成 AAD 的字节长度而不是比特长度。
        # 用来生成「必须被拒」的负向量——实现若也按字节长度算，就会接受它。
        [switch]$BitLengthAl
    )

    # RFC 7518 §5.2.2.1：64 字节 CEK，前半 MAC key、后半 ENC key。
    $cek = New-RandomBytes -Count 64
    $iv = New-RandomBytes -Count 16
    $macKey = New-Object byte[] 32
    $encKey = New-Object byte[] 32
    [Array]::Copy($cek, 0, $macKey, 0, 32)
    [Array]::Copy($cek, 32, $encKey, 0, 32)

    $head = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($HeaderJson))
    $wrapped = $Rsa.Encrypt($cek, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $keyB64 = ConvertTo-Base64Url $wrapped

    $padded = Add-Pkcs7Padding -Plain $Plain
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $encKey
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()
    $cipher = $encryptor.TransformFinalBlock($padded, 0, $padded.Length)
    $encryptor.Dispose()
    $aes.Dispose()

    $aadText = $head
    $aad = [System.Text.Encoding]::ASCII.GetBytes($aadText)
    $alValue = if ($BitLengthAl) { [uint64]$aad.Length } else { [uint64]($aad.Length * 8) }
    $al = [BitConverter]::GetBytes($alValue)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($al) }

    $macInput = New-Object byte[] ($aad.Length + $iv.Length + $cipher.Length + 8)
    [Array]::Copy($aad, 0, $macInput, 0, $aad.Length)
    [Array]::Copy($iv, 0, $macInput, $aad.Length, $iv.Length)
    [Array]::Copy($cipher, 0, $macInput, $aad.Length + $iv.Length, $cipher.Length)
    [Array]::Copy($al, 0, $macInput, $aad.Length + $iv.Length + $cipher.Length, 8)

    $hmac = New-Object System.Security.Cryptography.HMACSHA512
    $hmac.Key = $macKey
    $digest = $hmac.ComputeHash($macInput)
    $hmac.Dispose()
    $tag = New-Object byte[] 32
    [Array]::Copy($digest, 0, $tag, 0, 32)

    return "$head.$keyB64.$(ConvertTo-Base64Url $iv).$(ConvertTo-Base64Url $cipher).$(ConvertTo-Base64Url $tag)"
}

# 生成器的自检：按同一条 RFC 反着走一遍，确认拼出来的串至少在自己的口径下是自洽的。
# 这不是「验证」——验证由 Rust 测试完成；它只保证夹具本身没拼错。
function Test-JweCompact {
    param(
        [System.Security.Cryptography.RSA]$Rsa,
        [byte[]]$Expected,
        [string]$Compact
    )
    $parts = $Compact.Split('.')
    if ($parts.Length -ne 5) { throw "自检失败：段数 $($parts.Length)" }

    function From-B64Url([string]$Text) {
        $b64 = $Text.Replace('-', '+').Replace('_', '/')
        while ($b64.Length % 4 -ne 0) { $b64 += '=' }
        return , ([Convert]::FromBase64String($b64))
    }

    $cek = $Rsa.Decrypt((From-B64Url $parts[1]), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $macKey = New-Object byte[] 32
    $encKey = New-Object byte[] 32
    [Array]::Copy($cek, 0, $macKey, 0, 32)
    [Array]::Copy($cek, 32, $encKey, 0, 32)

    $aad = [System.Text.Encoding]::ASCII.GetBytes($parts[0])
    $iv = From-B64Url $parts[2]
    $cipher = From-B64Url $parts[3]
    $tag = From-B64Url $parts[4]
    $al = [BitConverter]::GetBytes([uint64]($aad.Length * 8))
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($al) }

    $macInput = New-Object byte[] ($aad.Length + $iv.Length + $cipher.Length + 8)
    [Array]::Copy($aad, 0, $macInput, 0, $aad.Length)
    [Array]::Copy($iv, 0, $macInput, $aad.Length, $iv.Length)
    [Array]::Copy($cipher, 0, $macInput, $aad.Length + $iv.Length, $cipher.Length)
    [Array]::Copy($al, 0, $macInput, $aad.Length + $iv.Length + $cipher.Length, 8)
    $hmac = New-Object System.Security.Cryptography.HMACSHA512
    $hmac.Key = $macKey
    $digest = $hmac.ComputeHash($macInput)
    $hmac.Dispose()
    $expectedTag = New-Object byte[] 32
    [Array]::Copy($digest, 0, $expectedTag, 0, 32)
    for ($i = 0; $i -lt 32; $i++) {
        if ($tag[$i] -ne $expectedTag[$i]) { throw "自检失败：标签不一致（第 $i 字节）" }
    }

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $encKey
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    $decryptor.Dispose()
    $aes.Dispose()

    $pad = [int]$plain[$plain.Length - 1]
    if ($pad -lt 1 -or $pad -gt 16) { throw "自检失败：填充长度 $pad" }
    for ($i = $plain.Length - $pad; $i -lt $plain.Length; $i++) {
        if ($plain[$i] -ne $pad) { throw "自检失败：填充内容不对" }
    }
    $body = New-Object byte[] ($plain.Length - $pad)
    [Array]::Copy($plain, 0, $body, 0, $body.Length)
    if ([Convert]::ToBase64String($body) -ne [Convert]::ToBase64String($Expected)) {
        throw "自检失败：解出的明文与输入不一致"
    }
}

# ---------------------------------------------------------------- 生成器口径自检（RFC 7516 附录 A.3）

# RFC 7516 附录 A.3 是 A128CBC-HS256 的完整公开示例，CEK 与 IV 都是固定的。
# 它校验的是**口径**：CEK 前半当 MAC key、AL 用比特长度、标签截断到摘要长度的一半。
# 三处错任何一处，标签就不等于 RFC 印出来的那个值——实测按字节长度算 AL（51 而不是
# 408）得到的是 OLu/aL2gYgjG1Ker13G8ZA==，与 RFC 的 U0m/YmjN04DJvceFICbCVQ 不符。
function Test-Rfc7516Construction {
    $cek = [byte[]](4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207)
    $iv = [byte[]](3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101)
    $aad = [System.Text.Encoding]::ASCII.GetBytes('eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0')
    $plain = [System.Text.Encoding]::ASCII.GetBytes('Live long and prosper.')
    $expectedCipher = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY'
    $expectedTag = 'U0m/YmjN04DJvceFICbCVQ=='

    $macKey = New-Object byte[] 16
    $encKey = New-Object byte[] 16
    [Array]::Copy($cek, 0, $macKey, 0, 16)
    [Array]::Copy($cek, 16, $encKey, 0, 16)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()
    $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length)
    $encryptor.Dispose()
    $aes.Dispose()
    if ((ConvertTo-Base64Url $cipher) -ne $expectedCipher) {
        throw "口径自检失败：A.3 的密文与 RFC 7516 不一致（得到 $(ConvertTo-Base64Url $cipher)）"
    }

    $al = [BitConverter]::GetBytes([uint64]($aad.Length * 8))
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($al) }
    $input = New-Object byte[] ($aad.Length + $iv.Length + $cipher.Length + 8)
    [Array]::Copy($aad, 0, $input, 0, $aad.Length)
    [Array]::Copy($iv, 0, $input, $aad.Length, $iv.Length)
    [Array]::Copy($cipher, 0, $input, $aad.Length + $iv.Length, $cipher.Length)
    [Array]::Copy($al, 0, $input, $aad.Length + $iv.Length + $cipher.Length, 8)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $macKey
    $digest = $hmac.ComputeHash($input)
    $hmac.Dispose()
    $tag = New-Object byte[] 16
    [Array]::Copy($digest, 0, $tag, 0, 16)
    if ([Convert]::ToBase64String($tag) -ne $expectedTag) {
        throw "口径自检失败：A.3 的标签与 RFC 7516 不一致（得到 $([Convert]::ToBase64String($tag))）"
    }
    Write-Output 'RFC 7516 A.3 口径自检通过：密文与标签都与 RFC 原文逐字节一致。'
}

Test-Rfc7516Construction

# ---------------------------------------------------------------- 写文件（UTF-8 无 BOM）

function Write-JsonFixture {
    param([string]$Path, [System.Collections.Specialized.OrderedDictionary]$Record)
    $json = $Record | ConvertTo-Json -Depth 6
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + "`n", $utf8)
}

# ---------------------------------------------------------------- JWE 向量

$warning = 'test fixture, never use for real pairing'
$generatedBy = 'tools/Gen-PairingFixtures.ps1: .NET RSA-OAEP-SHA256 + AES-256-CBC + HMAC-SHA-512, 按 RFC 7518 手工组装'
$headerWithCty = '{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","cty":"TC-Pairing-v1"}'
$headerNoCty = '{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512"}'

$asciiBody = 'TradeChannel.PairAuthorization v1; node=node-1; owner=owner-1; issued=2026-11-02T09:00:00.0000000Z; key-slot=primary'
$chineseBody = @'
{"SchemaVersion":1,"Kind":"TradeChannel.PairAuthorization","InviteId":"9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b","DeviceId":"1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d","DeviceName":"管理电脑","TunnelPrivateKey":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----","Note":"隧道私钥只在本机解封，用完即弃。"}
'@
$chineseBody = $chineseBody.Trim()

$vectors = @(
    @{ File = 'dotnet-jwe-1.json'; Bits = 2048; Header = $headerWithCty; Body = $asciiBody; Name = 'ascii-2048-with-cty'; ErrorCode = $null },
    @{ File = 'dotnet-jwe-2.json'; Bits = 3072; Header = $headerWithCty; Body = $chineseBody; Name = 'chinese-json-3072-with-cty'; ErrorCode = $null },
    @{ File = 'dotnet-jwe-3.json'; Bits = 2048; Header = $headerNoCty; Body = $asciiBody; Name = 'ascii-2048-without-cty'; ErrorCode = $null },
    @{ File = 'dotnet-jwe-4-wrong-al.json'; Bits = 2048; Header = $headerWithCty; Body = $asciiBody; Name = 'negative-al-in-bytes'; ErrorCode = 'InvalidEncryptedAuthorization'; BitLengthAl = $true }
)

foreach ($vector in $vectors) {
    $rsa = New-TestRsa -Bits $vector.Bits
    try {
        $pem = New-Pkcs8Pem -Parameters $rsa.ExportParameters($true)
        $body = [System.Text.Encoding]::UTF8.GetBytes($vector.Body)
        $compact = New-JweCompact -Rsa $rsa -HeaderJson $vector.Header -Plain $body -BitLengthAl:([bool]$vector.BitLengthAl)
        if (-not $vector.ErrorCode) {
            Test-JweCompact -Rsa $rsa -Expected $body -Compact $compact
        }
        $record = [ordered]@{
            name        = $vector.Name
            warning     = $warning
            generatedBy = $generatedBy
            keyBits     = $vector.Bits
            header      = $vector.Header
            privateKeyPem = $pem
            compact     = $compact
        }
        if ($vector.ErrorCode) {
            $record['description'] = 'AL 按字节长度而不是比特长度计算：RFC 7518 §5.2.2.1 要求比特长度，实现必须拒绝这条。'
            $record['expectedErrorCode'] = $vector.ErrorCode
            $record['expected'] = $vector.Body
        } else {
            $record['expected'] = $vector.Body
        }
        Write-JsonFixture -Path (Join-Path $fixtureDir $vector.File) -Record $record
        Write-Output ("JWE  {0,-26} {1,5} bit  {2} 字节明文  {3}" -f $vector.File, $vector.Bits, $body.Length, $vector.Name)
    } finally {
        $rsa.Dispose()
    }
}

# ---------------------------------------------------------------- DPAPI 向量

$gcc = $GccPath
if (-not $gcc) {
    $command = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $gcc = $command.Source }
}
if (-not $gcc) {
    $fallback = 'C:\tc-rs-tools\winlibs\mingw64\bin\gcc.exe'
    if (Test-Path $fallback) { $gcc = $fallback }
}
if (-not $gcc) {
    throw '找不到 gcc.exe：DPAPI 夹具无法生成。用 -GccPath 指定 mingw-w64 的 gcc。'
}

$toolDir = Join-Path $env:TEMP 'tc-dpapi-tool'
New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
$tool = Join-Path $toolDir 'dpapi_tool.exe'
$source = Join-Path $PSScriptRoot 'dpapi_tool.c'
& $gcc -O2 -o $tool $source -lcrypt32
if ($LASTEXITCODE -ne 0) { throw "gcc 编译 dpapi_tool.c 失败（退出码 $LASTEXITCODE）" }

$entropyText = 'TradeChannel.Pairing.v1'
$plainText = '{"TunnelPrivateKey":"-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7 -----END PRIVATE KEY-----","RetryInvite":"TCI1.test"}'

function Invoke-DpapiTool {
    # 参数名不能叫 -Input：那会遮蔽自动变量 $input（管道输入枚举器），绑定时报类型错。
    param([string]$Action, [byte[]]$Entropy, [byte[]]$Data, [string]$Label)
    $entropyFile = Join-Path $toolDir "$Label.entropy"
    $inputFile = Join-Path $toolDir "$Label.in"
    $outputFile = Join-Path $toolDir "$Label.out"
    [System.IO.File]::WriteAllBytes($entropyFile, $Entropy)
    [System.IO.File]::WriteAllBytes($inputFile, $Data)
    & $tool $Action $entropyFile $inputFile $outputFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "dpapi_tool $Action 失败（退出码 $LASTEXITCODE）" }
    return , ([System.IO.File]::ReadAllBytes($outputFile))
}

$entropyBytes = [System.Text.Encoding]::UTF8.GetBytes($entropyText)
$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
$protectedBytes = Invoke-DpapiTool -Action 'protect' -Entropy $entropyBytes -Data $plainBytes -Label 'pairing'
$protectedB64 = [System.Text.Encoding]::ASCII.GetString($protectedBytes)

# 自检：同一个工具立刻解回来，确认写进夹具的确实是这份明文的信封。
$roundTrip = [System.Text.Encoding]::UTF8.GetString(
    (Invoke-DpapiTool -Action 'unprotect' -Entropy $entropyBytes -Data $protectedBytes -Label 'pairing-check'))
if ($roundTrip -ne $plainText) { throw '自检失败：DPAPI 往返明文不一致' }

Write-JsonFixture -Path (Join-Path $fixtureDir 'dotnet-dpapi-1.json') -Record ([ordered]@{
        name         = 'dpapi-current-user'
        warning      = $warning
        machineBound = $true
        generatedBy  = 'tools/dpapi_tool.c（Win32 CryptProtectData，CRYPTPROTECT_UI_FORBIDDEN，当前用户作用域）'
        generatedOn  = "$env:COMPUTERNAME\$env:USERNAME"
        entropyUtf8  = $entropyText
        plain        = $plainText
        protectedB64 = $protectedB64
    })

$foreignEntropy = [System.Text.Encoding]::UTF8.GetBytes('SomeOther.App.v1')
$foreignBytes = Invoke-DpapiTool -Action 'protect' -Entropy $foreignEntropy -Data $plainBytes -Label 'foreign'
Write-JsonFixture -Path (Join-Path $fixtureDir 'dotnet-dpapi-2-foreign-entropy.json') -Record ([ordered]@{
        name         = 'dpapi-foreign-entropy'
        warning      = $warning
        machineBound = $true
        generatedBy  = 'tools/dpapi_tool.c（熵是 SomeOther.App.v1，不是本程序的固定熵）'
        generatedOn  = "$env:COMPUTERNAME\$env:USERNAME"
        entropyUtf8  = 'SomeOther.App.v1'
        plain        = $plainText
        protectedB64 = [System.Text.Encoding]::ASCII.GetString($foreignBytes)
        expectedErrorCode = 'PairingPrivateUnavailable'
    })

Write-Output ("DPAPI dotnet-dpapi-1.json  {0} 字节 base64；dotnet-dpapi-2-foreign-entropy.json {1} 字节 base64" -f $protectedB64.Length, ([System.Text.Encoding]::ASCII.GetString($foreignBytes)).Length)
Write-Output "夹具目录：$fixtureDir"
