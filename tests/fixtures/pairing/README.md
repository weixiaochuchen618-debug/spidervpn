# tests/fixtures/pairing —— 配对加密层的「对端口径」向量

这些文件**不是** Rust 侧生成的。它们由另一套实现（.NET 的 RSA/AES/HMACSHA512 与
Win32 的 DPAPI）按 RFC 7516/7518 产出，用来证明 `src/pairing.rs` 的 `jwe` / `dpapi`
能解开「别人做出来的信封」。仓库里自己写的那套 `seal()` 只能证明实现自洽，
证明不了与旧版对端（jose-jwt）互通。

> 所有私钥都是一次性测试夹具。**绝不可用于真实配对**。

## 文件

| 文件 | 内容 | 对应测试 |
| --- | --- | --- |
| `dotnet-jwe-1.json` | 纯 ASCII 明文，2048 位 RSA，头部带 `cty=TC-Pairing-v1` | `pairing::crypto_tests::dotnet_produced_authorizations_open` |
| `dotnet-jwe-2.json` | 中文 JSON 授权体（375 字节，跨多个分组），3072 位 RSA | 同上 |
| `dotnet-jwe-3.json` | 头部**没有** `cty`：不出现的字段不惩罚 | 同上 |
| `dotnet-jwe-4-wrong-al.json` | 负向量：`AL` 按字节长度而不是比特长度算，必须被拒 | 同上 |
| `dotnet-dpapi-1.json` | Win32 `CryptProtectData` 的当前用户信封 | `pairing::crypto_tests::dotnet_produced_dpapi_envelopes_open` |
| `dotnet-dpapi-2-foreign-entropy.json` | 负向量：用别的熵封的信封，必须解不开 | 同上 |
| `dotnet-jwt-1.json` | .NET `RSA.SignData` 签的 RS256 邀请（公钥 JWK + compact + 载荷） | `pairing::crypto_tests::dotnet_produced_invitations_verify_with_the_pinned_fingerprint` |

## 怎么重新生成

```powershell
powershell -ExecutionPolicy Bypass -File tools\Gen-PairingFixtures.ps1   # JWE + DPAPI
powershell -ExecutionPolicy Bypass -File tools\Gen-PairingJwt.ps1        # 邀请 JWT
```

脚本开头会先用 **RFC 7516 附录 A.3** 的公开向量自检口径（CEK 前半当 MAC key、
`AL` 是比特长度、标签截断），自检不过就不生成任何夹具。DPAPI 部分需要
mingw-w64 的 `gcc`（默认在 `C:\tc-rs-tools\winlibs\mingw64\bin`，可用
`-GccPath` 指定）。

## 注意：DPAPI 夹具绑定机器与账户

`dotnet-dpapi-*.json` 是「当前 Windows 账户 + 当前机器」封出来的。换一台机器或换一个
账户跑 `cargo test`，`dotnet_produced_dpapi_envelopes_open` 会失败并明确提示
「夹具过期，重跑生成器」——那是环境变了，不是 `dpapi` 有 bug。JWE 向量没有这个限制。

## JWE 向量的构造（RFC 7518 §5.2.2）

```
CEK  = 64 字节随机；mac_key = CEK[0..32]，enc_key = CEK[32..64]
头部 = {"alg":"RSA-OAEP-256","enc":"A256CBC-HS512"[,"cty":"TC-Pairing-v1"]}
AAD  = ASCII(base64url(头部))            # RFC 7516 §5.1：不含 encrypted_key 段
M    = AAD ‖ IV ‖ ciphertext ‖ AL        # AL = AAD 的比特长度，64 位大端
tag  = HMAC-SHA-512(mac_key, M)[0..32]
```
