//! 在线配对（M4 第一块）：`TCI1` 邀请码的契约与校验。
//!
//! 逐条对齐 旧版的 `PairingOnline.psm1::ConvertFrom-TCPairOnlineCode`：
//! 码是 `TCI1.` + base64url(JSON)，JSON **必须恰好** 八个字段
//! `v/h/p/i/k/t/m/e`（版本、主机、端口、邀请 id、令牌、TLS 指纹、管理签名指纹、过期秒）。
//!
//! 这里只解析与校验，不发起任何网络请求：邀请码本身就是「谁来连、连哪里、连谁」
//! 的全部证据，把它判对是第一道闸——判错的话后面每一步都在给错的目标签名。

// M4 在建：契约与传输层已就位并通过测试，接线（pairOnline 意图）在下一块完成。
// 在那之前这个模块只有测试在用，允许「暂时没人调用」，但功能本身是真的。

use base64::Engine;
use serde_json::Value;

/// 配对失败的原因码与中文句子。码沿用 旧版的原词，界面/日志/测试共用一套。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairError {
    /// 错误码。服务器下发的码是运行期字符串，所以这里不能钉成 `&'static str`
    /// （否则为了塞进静态生命周期只能泄漏内存）。
    pub code: String,
    pub message: String,
}

impl PairError {
    fn new(code: &str, message: &str) -> Self {
        Self { code: code.to_string(), message: message.to_string() }
    }

    /// 给传输层用的构造器（`http` 子模块在别的文件段里）。
    pub(crate) fn new_pub(code: &str, message: &str) -> Self {
        Self::new(code, message)
    }

    pub fn invalid_code() -> Self {
        Self::new("InvalidOnlineCode", "邀请码版本或身份字段无效。")
    }

    pub fn bad_encoding() -> Self {
        Self::new("InvalidOnlineCode", "邀请码编码无效。")
    }

    pub fn bad_host() -> Self {
        Self::new("InvalidOnlineHost", "邀请码服务器地址无效。")
    }

    pub fn expired() -> Self {
        Self::new("OnlineInviteExpired", "邀请码已过期；原申请和离线交接资料仍保留。")
    }

    pub fn loopback() -> Self {
        Self::new("InvalidOnlineHost", "回环邀请码只用于隔离测试。")
    }

    pub fn bad_device_name() -> Self {
        Self::new("InvalidDeviceName", "设备名称须为 1 至 64 个可显示字符，首尾不能有空格。")
    }

    pub fn too_long() -> Self {
        Self::new("InvalidOnlineJson", "邀请码数据为空或过长。")
    }

    pub fn bad_json() -> Self {
        Self::new("InvalidOnlineJson", "邀请码数据无法解析。")
    }

    pub fn bad_fields() -> Self {
        Self::new("InvalidOnlineInput", "邀请码字段不完整。")
    }

    pub fn unsupported_field() -> Self {
        Self::new("InvalidOnlineInput", "邀请码包含不支持的字段。")
    }
}

/// 解析好的邀请码。
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// 原始码（调用方要把它存进 DPAPI 信封，供重试使用）。
    pub code: String,
    pub invite_id: String,
    pub host: String,
    pub port: u16,
    pub token: String,
    /// 服务器证书 DER 的 SHA-256（小写十六进制，64 位）。
    pub tls_sha256: String,
    /// 管理签名公钥的 JWK 指纹（`SHA256:` + 43 位 base64）。
    pub management_fingerprint: String,
    pub expires_unix: i64,
}

impl std::fmt::Debug for Invite {
    /// 令牌与整条码不进日志：只打出「连谁、什么时候过期」。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("invite_id", &self.invite_id)
            .field("expires_unix", &self.expires_unix)
            .finish_non_exhaustive()
    }
}

impl Invite {
    /// 邀请详情地址（完整 URL）。旧版的 POST 在这个地址后追加 `/consume`。
    ///
    /// 生产侧发请求时只拼**路径**（见 `http` 模块），完整 URL 只有用例拿它核对拼法。
    #[cfg(test)]
    pub fn url(&self) -> String {
        format!("https://{}:{}/v1/invitations/{}", self.host, self.port, self.invite_id)
    }

    /// 邀请码里自带的身份信息，用于和服务器签名逐字段比对。
    pub fn matches_descriptor(&self, descriptor: &Value) -> bool {
        let text = |key: &str| descriptor.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        text("InviteId") == self.invite_id
            && text("PublicHost") == self.host
            && text("TlsSha256") == self.tls_sha256
            && text("ManagementFingerprint") == self.management_fingerprint
            && descriptor.get("Port").and_then(Value::as_i64) == Some(i64::from(self.port))
    }
}

const FIELDS: [&str; 8] = ["v", "h", "p", "i", "k", "t", "m", "e"];
/// 旧版的上限：管理电脑最长可开 24 小时；这里多给 300 秒容忍两台机器的时钟偏差。
const MAX_LIFETIME_SECS: i64 = 86_400 + 300;

/// 解析 `TCI1.*` 邀请码。`now_unix` 由调用方给，测试可以钉死时间。
pub fn parse_code(raw: &str, allow_loopback: bool, now_unix: i64) -> Result<Invite, PairError> {
    let code = raw.trim();
    if code.len() > 2_048 || !code.starts_with("TCI1.") {
        return Err(PairError::invalid_code());
    }
    let payload = &code[5..];
    // 码只允许 base64url 的字符：出现别的东西直接判编码无效，不尝试「容错修复」。
    if payload.is_empty()
        || !payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PairError::invalid_code());
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| PairError::bad_encoding())?;
    if bytes.len() > 256 * 1024 {
        return Err(PairError::too_long());
    }
    let text = String::from_utf8(bytes).map_err(|_| PairError::bad_encoding())?;
    let value: Value = serde_json::from_str(&text).map_err(|_| PairError::bad_json())?;
    let object = value.as_object().ok_or_else(PairError::bad_fields)?;

    // 字段集合必须**恰好**是这八个：多一个少一个都拒绝，避免「看起来能用」
    // 的码把未定义的语义带进后面的签名比对。
    if object.len() != FIELDS.len() {
        return Err(PairError::bad_fields());
    }
    for key in object.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(PairError::unsupported_field());
        }
    }

    let version = object.get("v").and_then(Value::as_i64);
    let port = object.get("p").and_then(Value::as_i64);
    let expires = object.get("e").and_then(Value::as_i64);
    let invite_id = object.get("i").and_then(Value::as_str).unwrap_or("");
    let host = object.get("h").and_then(Value::as_str).unwrap_or("");
    let token = object.get("k").and_then(Value::as_str).unwrap_or("");
    let tls = object.get("t").and_then(Value::as_str).unwrap_or("");
    let fingerprint = object.get("m").and_then(Value::as_str).unwrap_or("");

    if version != Some(1)
        || !(1024..=65_535).contains(&port.unwrap_or(0))
        || !is_uuid_v4_shape(invite_id)
        || !is_base64url(token, 43)
        || !is_lower_hex(tls, 64)
        || !is_thumbprint(fingerprint)
        || expires.is_none()
    {
        return Err(PairError::invalid_code());
    }

    // 主机必须是**规范写法**的 IPv4：`1.2.3.04`、`::1`、域名都不收。
    // 否则同一个地址会有多种写法，指纹绑定就没法做等值比较。
    let addr: std::net::Ipv4Addr = host.parse().map_err(|_| PairError::bad_host())?;
    if addr.to_string() != host {
        return Err(PairError::bad_host());
    }
    if addr.is_loopback() && !allow_loopback {
        return Err(PairError::loopback());
    }

    let expires = expires.unwrap_or(0);
    if expires <= now_unix {
        return Err(PairError::expired());
    }
    if expires > now_unix + MAX_LIFETIME_SECS {
        return Err(PairError::invalid_code());
    }

    Ok(Invite {
        code: code.to_string(),
        invite_id: invite_id.to_string(),
        host: host.to_string(),
        port: port.unwrap_or(0) as u16,
        token: token.to_string(),
        tls_sha256: tls.to_string(),
        management_fingerprint: fingerprint.to_string(),
        expires_unix: expires,
    })
}

/// 设备名：1–64 个字符，首尾无空格，不含控制字符与行/段分隔符。
/// 这句话会写进服务器上的设备清单，不能带不可见字符。
pub fn validate_device_name(name: &str) -> Result<(), PairError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || name.chars().count() > 64 || trimmed != name {
        return Err(PairError::bad_device_name());
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    {
        return Err(PairError::bad_device_name());
    }
    Ok(())
}

pub(crate) fn is_uuid_v4_shape(value: &str) -> bool {
    // 旧版只校验「8-4-4-4-12 的小写十六进制」，不校验版本位；照着做。
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
        && parts.iter().all(|p| is_lower_hex(p, p.len()))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_base64url(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_thumbprint(value: &str) -> bool {
    value.starts_with("SHA256:") && is_base64_std(&value[7..], 43)
}

fn is_base64_std(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

#[cfg(test)]
pub(crate) mod test_tls {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use rustls::pki_types::CertificateDer;

    use super::Invite;

    /// 一次性的本地 TLS 服务：返回状态行/头/体完全由用例给定。
    pub(crate) fn serve(cert: Vec<u8>, key: Vec<u8>, response: String) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let config = Arc::new(config);
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut buffer = [0u8; 4096];
                let _ = tls.read(&mut buffer);
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.flush();
            }
        });
        (port, handle)
    }

    /// 先占端口、后给响应体：邀请码里要写端口，而响应体又要用到这个端口。
    pub(crate) fn serve_later_with(
        cert: Vec<u8>,
        key: Vec<u8>,
    ) -> (
        u16,
        std::sync::mpsc::Sender<String>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let config = Arc::new(config);
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let Ok(response) = rx.recv() else { return };
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut buffer = [0u8; 4096];
                let _ = std::io::Read::read(&mut tls, &mut buffer);
                let _ = std::io::Write::write_all(&mut tls, response.as_bytes());
                let _ = std::io::Write::flush(&mut tls);
            }
        });
        (port, tx, handle)
    }

    /// 按「请求内容」应答的本地 TLS 服务，用来当假服务器。
    ///
    /// 与 `serve` 的区别是：响应体由闭包在**收到请求之后**决定。配对流程要
    /// 先读邀请再提交申请，而提交的响应必须绑回这次申请，事先烤不出来。
    pub(crate) fn serve_handler<F>(
        cert: Vec<u8>,
        key: Vec<u8>,
        handler: F,
    ) -> (u16, std::thread::JoinHandle<()>)
    where
        F: Fn(usize, &str) -> Option<String> + Send + 'static,
    {
        let listener = bind_local();
        let port = listener.local_addr().unwrap().port();
        (port, serve_on(listener, cert, key, handler))
    }

    /// 先绑端口再起服务：假服务器的应答要引用这个端口（邀请码里写的就是它），
    /// 所以端口必须先于应答内容确定。
    pub(crate) fn bind_local() -> std::net::TcpListener {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap()
    }

    pub(crate) fn serve_on<F>(
        listener: std::net::TcpListener,
        cert: Vec<u8>,
        key: Vec<u8>,
        handler: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: Fn(usize, &str) -> Option<String> + Send + 'static,
    {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let config = Arc::new(config);
        let handle = std::thread::spawn(move || {
            let mut index = 0usize;
            loop {
                let Ok((stream, _)) = listener.accept() else { return };
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let request = read_request(&mut tls);
                let Some(response) = handler(index, &request) else { return };
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.flush();
                index += 1;
            }
        });
        handle
    }

    /// 读完一整个请求（头 + 按 `Content-Length` 读正文）。只读半个请求就去
    /// 比对正文，会得到随机性的失败。
    fn read_request(
        tls: &mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
    ) -> String {
        let mut raw: Vec<u8> = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = tls.read(&mut buffer).unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
            let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if raw.len() >= end + 4 + length {
                break;
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    pub(crate) fn keypair() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    }

    pub(crate) fn invite_for(port: u16, pin: String) -> Invite {
        Invite {
            code: "TCI1.test".into(),
            invite_id: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".into(),
            host: "127.0.0.1".into(),
            port,
            token: "A".repeat(43),
            tls_sha256: pin,
            management_fingerprint: format!("SHA256:{}", "B".repeat(43)),
            expires_unix: 4_000_000_000,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        1_800_000_000
    }

    fn encode(value: Value) -> String {
        format!(
            "TCI1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        )
    }

    fn good() -> Value {
        serde_json::json!({
            "v": 1,
            "h": "203.0.113.10",
            "p": 18443,
            "i": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "k": "A".repeat(43),
            "t": "a".repeat(64),
            "m": format!("SHA256:{}", "B".repeat(43)),
            "e": now() + 1800,
        })
    }

    #[test]
    fn a_complete_code_parses_into_every_bound_field() {
        let invite = parse_code(&encode(good()), false, now()).expect("应当可以解析");
        assert_eq!(invite.host, "203.0.113.10");
        assert_eq!(invite.port, 18443);
        assert_eq!(invite.invite_id, "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        assert_eq!(invite.url(), "https://203.0.113.10:18443/v1/invitations/9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        assert_eq!(invite.expires_unix, now() + 1800);
        // 前后空格是粘贴带来的，允许；码本身要原样保留（重试要用）。
        let padded = format!("  {}  ", invite.code);
        assert_eq!(parse_code(&padded, false, now()).unwrap().code, invite.code);
    }

    #[test]
    fn the_code_format_is_enforced_before_anything_else() {
        for bad in [
            "",
            "TCI1",
            "TCI2.AAAA",
            "TCI1.",
            "TCI1.abc def",
            "TCI1.中文",
        ] {
            let error = parse_code(bad, false, now()).expect_err(bad);
            assert_eq!(error.code, "InvalidOnlineCode", "{bad}");
        }
        // 超过 2048 字符的码不进 base64 解码。
        let long = format!("TCI1.{}", "A".repeat(2_050));
        assert_eq!(parse_code(&long, false, now()).unwrap_err().code, "InvalidOnlineCode");
    }

    #[test]
    fn the_field_set_is_exactly_eight_names() {
        let mut extra = good();
        extra["x"] = serde_json::json!(1);
        assert_eq!(parse_code(&encode(extra), false, now()).unwrap_err().code, "InvalidOnlineInput");

        let mut missing = good();
        missing.as_object_mut().unwrap().remove("m");
        assert_eq!(parse_code(&encode(missing), false, now()).unwrap_err().code, "InvalidOnlineInput");
    }

    #[test]
    fn identity_fields_must_match_their_exact_shape() {
        let cases: [(&str, Value); 6] = [
            ("v", serde_json::json!(2)),
            ("p", serde_json::json!(80)),          // 小于 1024
            ("i", serde_json::json!("9f1c2a44-0b7d-4c1e-9a2b")),
            ("k", serde_json::json!("short")),
            ("t", serde_json::json!("A".repeat(64))), // 必须小写十六进制
            ("m", serde_json::json!("SHA256:short")),
        ];
        for (field, value) in cases {
            let mut code = good();
            code[field] = value;
            assert_eq!(
                parse_code(&encode(code), false, now()).unwrap_err().code,
                "InvalidOnlineCode",
                "{field}"
            );
        }
    }

    #[test]
    fn hosts_must_be_canonical_ipv4_and_loopback_is_test_only() {
        for host in ["localhost", "203.0.113.010", "::1", "203.0.113.10 "] {
            let mut code = good();
            code["h"] = serde_json::json!(host);
            let error = parse_code(&encode(code), false, now()).expect_err(host);
            assert_eq!(error.code, "InvalidOnlineHost", "{host}");
        }
        let mut loopback = good();
        loopback["h"] = serde_json::json!("127.0.0.1");
        assert_eq!(parse_code(&encode(loopback.clone()), false, now()).unwrap_err().code, "InvalidOnlineHost");
        // 隔离测试显式允许时才收。
        assert_eq!(parse_code(&encode(loopback), true, now()).unwrap().host, "127.0.0.1");
    }

    #[test]
    fn expiry_is_checked_in_both_directions() {
        let mut expired = good();
        expired["e"] = serde_json::json!(now());
        assert_eq!(parse_code(&encode(expired), false, now()).unwrap_err().code, "OnlineInviteExpired");

        let mut too_far = good();
        too_far["e"] = serde_json::json!(now() + 86_400 + 301);
        assert_eq!(parse_code(&encode(too_far), false, now()).unwrap_err().code, "InvalidOnlineCode");

        // 上限本身（24 小时 + 300 秒）是收的。
        let mut edge = good();
        edge["e"] = serde_json::json!(now() + 86_400 + 300);
        assert!(parse_code(&encode(edge), false, now()).is_ok());
    }

    #[test]
    fn the_signed_descriptor_must_agree_with_every_bound_field() {
        let invite = parse_code(&encode(good()), false, now()).unwrap();
        let mut descriptor = serde_json::json!({
            "InviteId": invite.invite_id,
            "PublicHost": invite.host,
            "Port": invite.port,
            "TlsSha256": invite.tls_sha256,
            "ManagementFingerprint": invite.management_fingerprint,
        });
        assert!(invite.matches_descriptor(&descriptor));
        descriptor["Port"] = serde_json::json!(18444);
        assert!(!invite.matches_descriptor(&descriptor), "端口换一个就不算同一张邀请");
        descriptor["Port"] = serde_json::json!(invite.port);
        descriptor["TlsSha256"] = serde_json::json!("b".repeat(64));
        assert!(!invite.matches_descriptor(&descriptor));
    }

    #[test]
    fn device_names_reject_invisible_or_padded_text() {
        assert!(validate_device_name("交易机-01").is_ok());
        for bad in ["", " 交易机", "交易机 ", &"a".repeat(65), "交易\u{7}机", "交易\u{2028}机"] {
            assert_eq!(validate_device_name(bad).unwrap_err().code, "InvalidDeviceName", "{bad:?}");
        }
    }
}

/// 逐字节用 volatile 写 0，抹掉一块装过密钥/明文的内存。
///
/// **必须是 volatile**：普通赋值写的是「这行之后就不再被读」的内存，优化器有权
/// 把它当成死存储（dead store）整条删掉——那样注释里承诺的「用完清零」只是空话，
/// 密钥会一直躺在堆上，直到被同一块内存的下一个使用者覆盖。volatile 写对外是
/// 可观测的副作用，编译器不能删。
///
/// jwe（CEK）与 dpapi（明文/熵/信封）共用这一份：清零这种东西一旦有两份实现，
/// 迟早只有一份是对的。
pub(crate) fn zero(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // SAFETY: `byte` 是这块内存在本次借用期内独占的引用，写 0 不改变长度、
        // 不让任何别名失效；`write_volatile` 要求的「可写 + 对齐」都由 `&mut u8` 保证。
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

/// 服务器公钥（JWK）与 RS256 签名校验，对齐 旧版的 `PairCrypto`：
/// 公钥是 RSA（`{"kty":"RSA","n":…,"e":…}`），签名是 RS256 JWT，
/// 身份指纹是**规范化 JWK 的 SHA-256**（`SHA256:` + 43 位 base64）。
pub mod jwk {
    use super::PairError;
    use base64::Engine;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{BigUint, RsaPublicKey};
    use serde_json::Value;
    use sha2::Sha256;

    const URL_SAFE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RsaJwk {
        /// 规范化后的 base64url 模数（无填充）。
        pub n: String,
        /// 规范化后的 base64url 指数（无填充）。
        pub e: String,
    }

    fn invalid() -> PairError {
        PairError::new_pub("InvalidInvite", "邀请签名、算法或服务器公钥校验失败。")
    }

    /// 解 base64url（无填充为标准形态）。
    ///
    /// 收到带 `=` 填充的也照收：填充不携带信息，指纹只该取决于密钥本身。
    /// 反过来，输出永远是规范的无填充形态——同一个密钥无论怎么编码，身份相同。
    fn decode_part(text: &str) -> Result<Vec<u8>, PairError> {
        URL_SAFE
            .decode(text.trim_end_matches('='))
            .map_err(|_| invalid())
    }

    impl RsaJwk {
        pub fn parse(value: &Value) -> Result<Self, PairError> {
            let object = value.as_object().ok_or_else(invalid)?;
            if object.get("kty").and_then(Value::as_str) != Some("RSA") {
                return Err(invalid());
            }
            let n = object.get("n").and_then(Value::as_str).ok_or_else(invalid)?;
            let e = object.get("e").and_then(Value::as_str).ok_or_else(invalid)?;
            let modulus = decode_part(n)?;
            let exponent = decode_part(e)?;
            if modulus.len() < 256 || exponent.is_empty() || exponent.len() > 8 {
                // 比 2048 位还短的模数直接拒：协议固定 3072 位，这里只留出测试余量。
                return Err(invalid());
            }
            // 重新编码成规范形式：指纹与公钥都基于这个形式，收到的字符串带不带
            // 填充、有没有前导零都不该改变身份。
            Ok(Self {
                n: URL_SAFE.encode(&modulus),
                e: URL_SAFE.encode(&exponent),
            })
        }

        /// 从一把公钥建 JWK：编码成**规范形态**（无填充 base64url），
        /// 与 `parse` 的输出一致，这样指纹只取决于密钥本身。
        pub fn from_public(key: &RsaPublicKey) -> Self {
            use rsa::traits::PublicKeyParts;
            Self {
                n: URL_SAFE.encode(key.n().to_bytes_be()),
                e: URL_SAFE.encode(key.e().to_bytes_be()),
            }
        }

        pub fn public_key(&self) -> Result<RsaPublicKey, PairError> {
            let n = decode_part(&self.n)?;
            let e = decode_part(&self.e)?;
            RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                .map_err(|_| invalid())
        }

        /// 规范化 JSON（**键顺序固定** `e, kty, n`）的 SHA-256。
        pub fn fingerprint(&self) -> String {
            use sha2::Digest;
            let canonical = format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", self.e, self.n);
            let digest = Sha256::digest(canonical.as_bytes());
            format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
            )
        }
    }

    /// 小写十六进制 SHA-256。指纹、摘要、证书 pin 共用一份实现。
    pub fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// 验证 RS256 紧凑 JWT，返回载荷 JSON。
    ///
    /// 只认 `alg=RS256`：任何别的算法（尤其 `none`）都当签名失败——
    /// 允许「由报文自己声明算法」是 JWT 最典型的那类漏洞。
    pub fn verify_rs256(compact: &str, key: &RsaJwk) -> Result<Value, PairError> {
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(invalid());
        }
        let header_bytes = URL_SAFE.decode(parts[0]).map_err(|_| invalid())?;
        let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| invalid())?;
        let object = header.as_object().ok_or_else(invalid)?;
        if object.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err(invalid());
        }
        if let Some(typ) = object.get("typ").and_then(Value::as_str) {
            if typ != "JWT" {
                return Err(invalid());
            }
        }
        let signature_bytes = URL_SAFE.decode(parts[2]).map_err(|_| invalid())?;
        let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| invalid())?;
        let signed = format!("{}.{}", parts[0], parts[1]);
        VerifyingKey::<Sha256>::new(key.public_key()?)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| invalid())?;
        let payload = URL_SAFE.decode(parts[1]).map_err(|_| invalid())?;
        serde_json::from_slice(&payload).map_err(|_| invalid())
    }
}

/// 邀请（服务器签名的 JWT）校验，对齐 `DeploymentPairing.psm1::Get-TCPairInvite`。
pub mod invite {
    use super::{jwk::RsaJwk, PairError};
    use serde_json::Value;

    /// 邀请载荷里必须出现的字段（旧版的 `Assert-TCPairFields`，去掉 DeviceName：
    /// 旧版的 PS 服务器把设备名留在邀请码外，被签名的邀请里没有这个字段）。
    const FIELDS: [&str; 12] = [
        "SchemaVersion",
        "Kind",
        "InviteId",
        "RemoteOwnerId",
        "NodeId",
        "ServerPublicKey",
        "ManagementSigningPublicKey",
        "PublicEndpoint",
        "IssuedAtUtc",
        "ExpiresAtUtc",
        "Capabilities",
        "ServerBinding",
    ];

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidInvite", message)
    }

    /// 校验一张邀请：签名者必须就是邀请码里固定的那个身份。
    ///
    /// 顺序很重要——先拿**未验证载荷**里的公钥算指纹与邀请码比对，再用这把公钥
    /// 验签。先验签再比指纹等于让攻击者自带公钥来签自己的邀请。
    pub fn verify(compact: &str, confirmed_fingerprint: &str, now_unix: i64) -> Result<Value, PairError> {
        let unverified = unverified_payload(compact)?;
        let key_value = unverified
            .get("ManagementSigningPublicKey")
            .ok_or_else(|| invalid("邀请缺少服务器公钥。"))?;
        let key = RsaJwk::parse(key_value)?;
        let fingerprint = key.fingerprint();
        if confirmed_fingerprint != fingerprint {
            return Err(PairError::new_pub(
                "InviteTrustRequired",
                "邀请签名身份与邀请码固定的身份不一致，请重新取得邀请码。",
            ));
        }
        let payload = super::jwk::verify_rs256(compact, &key)?;
        let object = payload.as_object().ok_or_else(|| invalid("邀请载荷格式无效。"))?;
        for field in FIELDS {
            if !object.contains_key(field) {
                return Err(invalid("邀请字段不完整。"));
            }
        }
        // 设备名可缺省（旧版服务器不签它）；带了就必须是合法设备名。
        if let Some(name) = object.get("DeviceName") {
            let text = name.as_str().ok_or_else(|| invalid("邀请里的设备名称无效。"))?;
            if super::validate_device_name(text).is_err() {
                return Err(invalid("邀请里的设备名称无效。"));
            }
        }
        if object.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
            || object.get("Kind").and_then(Value::as_str) != Some("TradeChannel.PairInvite")
        {
            return Err(invalid("邀请协议版本无效。"));
        }
        if let Some(endpoint) = object.get("PublicEndpoint").and_then(Value::as_str) {
            if !valid_endpoint(endpoint) {
                return Err(invalid("邀请入口格式无效。"));
            }
        } else {
            return Err(invalid("邀请入口格式无效。"));
        }
        let expires = parse_time(object.get("ExpiresAtUtc")).ok_or_else(|| invalid("邀请有效期无效。"))?;
        let issued = parse_time(object.get("IssuedAtUtc")).ok_or_else(|| invalid("邀请签发时间无效。"))?;
        if expires <= now_unix {
            return Err(PairError::new_pub("InviteExpired", "邀请已过期，请重新取得邀请。"));
        }
        if issued > now_unix + 300 {
            // 签发时间在未来超过 5 分钟：两台机器时钟不可信，按旧版拒绝。
            return Err(PairError::new_pub("InviteExpired", "邀请时间不可信，请重新取得邀请。"));
        }
        Ok(payload)
    }

    /// 只解出载荷、不验签。唯一合法用途就是拿里面的公钥去比指纹（见上）。
    pub fn unverified_payload(compact: &str) -> Result<Value, PairError> {
        use base64::Engine;
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(invalid("邀请签名格式无效。"));
        }
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| invalid("邀请载荷无法解析。"))?;
        serde_json::from_slice(&payload).map_err(|_| invalid("邀请载荷无法解析。"))
    }

    fn valid_endpoint(value: &str) -> bool {
        let Some((host, port)) = value.rsplit_once(':') else {
            return false;
        };
        let Ok(address) = host.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        if address.to_string() != host || address.is_loopback() || address.is_unspecified() {
            return false;
        }
        matches!(port.parse::<u16>(), Ok(p) if p >= 1024)
    }

    /// RFC 3339 → Unix 秒。只接受 `Z` 结尾的 UTC 形式（协议里只有这一种）。
    pub(super) fn parse_time(value: Option<&Value>) -> Option<i64> {
        let text = value?.as_str()?;
        let stamp = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
        Some(stamp.unix_timestamp())
    }
}

/// 接入用的本机密钥对：RSA（接收授权密文）+ X25519（隧道握手）。
///
/// 两把钥匙的用途完全不同，不能混用：RSA 私钥只用来解服务器回的
/// `EncryptedAuthorization`，X25519 私钥只用于隧道。旧版把它们放在同一个
/// DPAPI 信封里；这里沿用同样的分组，但字段分开命名，免得接线时拿错。
pub mod keys {
    use super::jwk::RsaJwk;
    use super::PairError;
    use base64::Engine;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    use rsa::rand_core::{OsRng, RngCore};
    use rsa::RsaPrivateKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// 旧版的 `PairCrypto.NewPrivateKey` 固定 3072 位；这里对齐，不为了测试快而降规格。
    pub const RSA_BITS: usize = 3072;
    /// WireGuard 的密钥固定 32 字节。
    pub const TUNNEL_KEY_LEN: usize = 32;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    pub struct PairingKeys {
        /// 接收 RSA 私钥（只在本进程里用来解授权）。
        pub recipient_private: RsaPrivateKey,
        /// 对应的公开 JWK，要放进 `PairRequest.RecipientJwk`。
        pub recipient_jwk: RsaJwk,
        /// PKCS#8 DER 的 base64——DPAPI 信封里存的就是它。
        pub recipient_pkcs8_b64: String,
        /// 隧道私钥（已 clamp）的 base64。
        pub tunnel_private_b64: String,
        /// 隧道公钥的 base64（标准字母表，44 位带 `=`），即 `ClientPublicKey`。
        pub tunnel_public_b64: String,
    }

    impl std::fmt::Debug for PairingKeys {
        /// 同上：`RsaPrivateKey` 自带的 Debug 会打印密钥分量，绝不能让它随日志出去。
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PairingKeys")
                .field("recipient_jwk_fingerprint", &self.recipient_jwk.fingerprint())
                .field("tunnel_public_b64", &self.tunnel_public_b64)
                .field("recipient_pkcs8_b64", &format_args!("<{} 字符>", self.recipient_pkcs8_b64.len()))
                .field("tunnel_private_b64", &format_args!("<{} 字符>", self.tunnel_private_b64.len()))
                .finish()
        }
    }

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidPairingKey", message)
    }

    /// WireGuard 的私钥要先 clamp：`k[0] &= 248; k[31] = (k[31] & 127) | 64`。
    /// X25519 在标量乘时自己也会 clamp，但配置文件里存的是这串字节，
    /// 存成已 clamp 的形态才能和 `wg pubkey` 算出来的结果对得上。
    fn clamp(mut bytes: [u8; TUNNEL_KEY_LEN]) -> [u8; TUNNEL_KEY_LEN] {
        bytes[0] &= 248;
        bytes[31] = (bytes[31] & 127) | 64;
        bytes
    }

    /// 只生成一把 WireGuard 隧道密钥（不起 RSA）。
    ///
    /// 部署自建服务器时用：那条路上没有 JWE、没有签名，只需要一对 X25519。
    /// 复用这里的 `clamp`，免得两处对「合法私钥」的理解慢慢漂开。
    pub fn tunnel_keypair() -> (String, String) {
        let mut raw = [0u8; TUNNEL_KEY_LEN];
        OsRng.fill_bytes(&mut raw);
        let private = clamp(raw);
        let public = PublicKey::from(&StaticSecret::from(private));
        (B64.encode(private), B64.encode(public.as_bytes()))
    }

    // 仅测试可见的位数钩子。
    //
    // 存在的理由：3072 位在 debug 构建下生成一次要几十秒，而「流程能不能跑通」
    // 与「规格是不是 3072」是两件事。规格由
    // generated_pairing_keys_are_3072_bit_and_self_consistent 单独钉住；
    // 流程用例只需一把能用的密钥。生产路径没有这个开关。
    // （用 // 而不是 ///：文档注释挂在宏调用上会被 rustc 判为无效。）
    #[cfg(test)]
    thread_local! {
        static TEST_BITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    fn bits() -> usize {
        #[cfg(test)]
        {
            let override_bits = TEST_BITS.with(|cell| cell.get());
            if override_bits > 0 {
                return override_bits;
            }
        }
        RSA_BITS
    }

    /// 用例开头拿一个守卫，函数结束自动恢复，避免把「小密钥」漏给同线程后续代码。
    #[cfg(test)]
    pub(crate) struct TestBits(usize);

    #[cfg(test)]
    impl Drop for TestBits {
        fn drop(&mut self) {
            TEST_BITS.with(|cell| cell.set(self.0));
        }
    }

    #[cfg(test)]
    pub(crate) fn test_bits(value: usize) -> TestBits {
        TestBits(TEST_BITS.with(|cell| cell.replace(value)))
    }

    pub fn generate() -> Result<PairingKeys, PairError> {
        let recipient_private = RsaPrivateKey::new(&mut OsRng, bits())
            .map_err(|_| invalid("生成接收密钥失败。"))?;
        let der = recipient_private
            .to_pkcs8_der()
            .map_err(|_| invalid("导出接收密钥失败。"))?;
        let recipient_jwk = RsaJwk::from_public(&recipient_private.to_public_key());
        let mut raw = [0u8; TUNNEL_KEY_LEN];
        OsRng.fill_bytes(&mut raw);
        let tunnel_private = clamp(raw);
        let public = PublicKey::from(&StaticSecret::from(tunnel_private));
        Ok(PairingKeys {
            recipient_jwk,
            recipient_pkcs8_b64: B64.encode(der.as_bytes()),
            tunnel_private_b64: B64.encode(tunnel_private),
            tunnel_public_b64: B64.encode(public.as_bytes()),
            recipient_private,
        })
    }

    /// 从信封里读回来的 PKCS#8 解出私钥。解不开要能说清是「记录坏了」而不是「配对失败」。
    pub fn recipient_from_pkcs8_b64(text: &str) -> Result<RsaPrivateKey, PairError> {
        let der = B64
            .decode(text.trim())
            .map_err(|_| invalid("本机接收密钥不是合法的 base64。"))?;
        RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|_| invalid("本机接收密钥无法解析，可能已损坏。"))
    }

    /// 由私钥重算公钥：写隧道配置时用，也用来校验存下来的两份材料是同一对。
    pub fn tunnel_public_from_private_b64(text: &str) -> Result<String, PairError> {
        let raw = B64
            .decode(text.trim())
            .map_err(|_| invalid("本机隧道密钥不是合法的 base64。"))?;
        let bytes: [u8; TUNNEL_KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| invalid("本机隧道密钥长度不是 32 字节。"))?;
        Ok(B64.encode(PublicKey::from(&StaticSecret::from(bytes)).as_bytes()))
    }
}

/// 服务器签名的在线邀请描述符，对齐 `Get-TCPairOnlineInvitation`。
///
/// 描述符把「邀请码里的入口」和「服务器签名的邀请」缝在一起：
/// 只要有一项对不上，就说明入口或身份被换过，必须整体拒绝——不能只挑对得上的用。
pub mod descriptor {
    use super::{jwk::RsaJwk, Invite, PairError};
    use serde_json::Value;

    /// 描述符里必须出现的字段（旧版的 `Assert-TCPairOnlineFields`）。
    const FIELDS: [&str; 10] = [
        "SchemaVersion",
        "Kind",
        "InviteId",
        "Invite",
        "PublicHost",
        "Port",
        "TlsSha256",
        "ManagementFingerprint",
        "ExpiresAtUtc",
        "RetryUntilUtc",
    ];

    /// 校验通过的描述符。`invite` 是**已验签**的邀请载荷，调用方可以直接用。
    #[derive(Debug, Clone)]
    pub struct Descriptor {
        // 服务器签名里带过来的核对证据：生产侧不再读，但要留着和旧版逐字段对照。
        #[allow(dead_code)]
        pub invite_jwt: String,
        pub invite: Value,
        #[allow(dead_code)]
        pub invite_id: String,
        pub public_host: String,
        pub port: u16,
        #[allow(dead_code)]
        pub tls_sha256: String,
        pub management_fingerprint: String,
        pub expires_unix: i64,
        /// 过期后还能用原申请重试的截止时间（旧版固定为过期 + 120 秒）。
        #[allow(dead_code)]
        pub retry_until_unix: i64,
    }

    fn mismatch() -> PairError {
        PairError::new_pub(
            "OnlineInviteIdentityMismatch",
            "服务器签名与邀请码固定的身份不一致。",
        )
    }

    /// 旧版的 `RetryUntilUtc` 固定是过期 + 120 秒；别的值说明这不是同一个协议。
    const RETRY_GRACE_SECS: i64 = 120;

    pub fn verify(compact: &str, code: &Invite, now_unix: i64) -> Result<Descriptor, PairError> {
        // 旧版的描述符不带公钥，管理公钥只在被签名的邀请里；本版自建服务器
        // 两份 JWS 都带。信任锚始终是邀请码固定的指纹：先验邀请，再从**已验签**
        // 的邀请里取公钥，最后用这把公钥验描述符。
        let unverified = super::invite::unverified_payload(compact)?;
        let invite_jwt = unverified
            .get("Invite")
            .and_then(Value::as_str)
            .ok_or_else(mismatch)?;
        let invite = super::invite::verify(invite_jwt, &code.management_fingerprint, now_unix)?;
        let key = RsaJwk::parse(
            invite
                .get("ManagementSigningPublicKey")
                .ok_or_else(mismatch)?,
        )
        .map_err(|_| mismatch())?;
        if key.fingerprint() != code.management_fingerprint {
            return Err(mismatch());
        }
        // 描述符若自带公钥，必须和邀请里的那一把是同一个身份；不允许换钥匙。
        if let Some(embedded) = unverified.get("ManagementSigningPublicKey") {
            let embedded = RsaJwk::parse(embedded).map_err(|_| mismatch())?;
            if embedded.fingerprint() != key.fingerprint() {
                return Err(mismatch());
            }
        }
        let body = super::jwk::verify_rs256(compact, &key).map_err(|_| mismatch())?;
        let object = body.as_object().ok_or_else(mismatch)?;
        for field in FIELDS {
            if !object.contains_key(field) {
                return Err(mismatch());
            }
        }
        if object.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
            || object.get("Kind").and_then(Value::as_str) != Some("TradeChannel.OnlineInvite")
        {
            return Err(mismatch());
        }
        let invite_jwt = object
            .get("Invite")
            .and_then(Value::as_str)
            .ok_or_else(mismatch)?
            .to_string();
        // 内嵌的邀请要单独验一次：描述符的签名者与邀请的签名者必须都是同一个身份。
        let invite = super::invite::verify(&invite_jwt, &code.management_fingerprint, now_unix)?;

        let text = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or("");
        if text("InviteId") != code.invite_id
            || invite.get("InviteId").and_then(Value::as_str) != Some(code.invite_id.as_str())
        {
            return Err(mismatch());
        }
        // 入口必须是邀请码里的那一个：主机、端口、证书指纹、管理身份，逐项等值。
        if !code.matches_descriptor(&body) {
            return Err(mismatch());
        }
        let expires = super::invite::parse_time(object.get("ExpiresAtUtc")).ok_or_else(mismatch)?;
        let retry = super::invite::parse_time(object.get("RetryUntilUtc")).ok_or_else(mismatch)?;
        let invite_expires = super::invite::parse_time(invite.get("ExpiresAtUtc"))
            .ok_or_else(mismatch)?;
        // 有效期三处必须完全一致：邀请码、描述符、被签名的邀请。
        if expires != code.expires_unix
            || retry != expires + RETRY_GRACE_SECS
            || invite_expires != expires
        {
            return Err(mismatch());
        }
        Ok(Descriptor {
            invite_jwt,
            invite,
            invite_id: code.invite_id.clone(),
            public_host: code.host.clone(),
            port: code.port,
            tls_sha256: code.tls_sha256.clone(),
            management_fingerprint: code.management_fingerprint.clone(),
            expires_unix: expires,
            retry_until_unix: retry,
        })
    }
}

/// 设备公开申请（`TradeChannel.ClientRequest`）。摘要算法是
/// `TC-ClientRequest-v1`：把七个字段按固定顺序用换行拼起来做 SHA-256，
/// **时间戳字符串必须原样参与**（格式化一次就不再改，否则服务器算出的摘要不同）。
/// 配对码：申请摘要（64 位小写十六进制）的前 12 位大写，人工核对用。
///
/// **只此一份**：在线加入、离线交接与 `ipc` 的回包里原来各写了一遍同样的
/// `take(12).to_uppercase()`，改口径时漏一处就会出现「页面上的码和服务器上的不一样」。
pub fn pairing_code_of(digest: &str) -> String {
    digest.chars().take(12).collect::<String>().to_ascii_uppercase()
}

pub mod client_request {
    use super::PairError;

    /// WireGuard 公钥是 32 字节的 base64，固定 43 位 + 一个 `=`。
    pub const PUBLIC_KEY_LEN: usize = 44;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ClientRequest {
        pub request_id: String,
        pub device_id: String,
        /// RFC 3339，参与摘要，签完不能再格式化。
        pub created_at_utc: String,
        /// 本机隧道公钥（base64，44 位）。
        pub client_public_key: String,
    }

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidPairing", message)
    }

    fn is_uuid(text: &str) -> bool {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return false;
        }
        for (index, byte) in bytes.iter().enumerate() {
            let dash = matches!(index, 8 | 13 | 18 | 23);
            if dash {
                if *byte != b'-' {
                    return false;
                }
            } else if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
                return false;
            }
        }
        true
    }

    /// 七个字段的规范元组。**不要在这里做任何格式化或大小写归一**。
    fn tuple(request: &ClientRequest) -> String {
        [
            "1",
            "TradeChannel.ClientRequest",
            &request.request_id,
            &request.device_id,
            &request.created_at_utc,
            &request.client_public_key,
            "IPv4",
        ]
        .join("\n")
    }

    impl ClientRequest {
        pub fn validate(&self) -> Result<(), PairError> {
            if !is_uuid(&self.request_id) || !is_uuid(&self.device_id) {
                return Err(invalid("设备申请的标识不是标准 UUID。"));
            }
            let key = &self.client_public_key;
            if key.len() != PUBLIC_KEY_LEN
                || !key.ends_with('=')
                || !key[..PUBLIC_KEY_LEN - 1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            {
                return Err(invalid("设备公开密钥不是 32 字节的 base64。"));
            }
            // 时间戳要能被解析，但**不能用解析结果回写**：摘要认的是原始字符串。
            if super::invite::parse_time(Some(&serde_json::Value::String(
                self.created_at_utc.clone(),
            )))
            .is_none()
            {
                return Err(invalid("设备申请的时间格式无效。"));
            }
            Ok(())
        }

        /// `TC-ClientRequest-v1` 摘要（64 位小写十六进制）。
        pub fn digest(&self) -> Result<String, PairError> {
            self.validate()?;
            Ok(super::jwk::sha256_hex(tuple(self).as_bytes()))
        }

        /// 配对码：摘要前 12 位大写，人工核对用。规则只有一份（[`pairing_code_of`]）。
        #[cfg(test)]
        pub fn pairing_code(&self) -> Result<String, PairError> {
            Ok(super::pairing_code_of(&self.digest()?))
        }
    }
}

/// 设备申请（`TradeChannel.PairRequest`）：本机签名后交给服务器。
pub mod request {
    use super::client_request::ClientRequest;
    use super::{jwk::RsaJwk, Invite, PairError};
    use base64::Engine;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use serde_json::{json, Value};
    use sha2::Sha256;

    const URL_SAFE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidPairRequest", message)
    }

    /// 用自己的私钥签一张 RS256 JWT。
    pub fn sign_rs256(payload: &Value, key: &RsaPrivateKey) -> String {
        let header = json!({"alg": "RS256", "typ": "JWT"});
        let head = URL_SAFE.encode(serde_json::to_vec(&header).unwrap_or_default());
        let body = URL_SAFE.encode(serde_json::to_vec(payload).unwrap_or_default());
        let signed = format!("{head}.{body}");
        let signature = SigningKey::<Sha256>::new(key.clone()).sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE.encode(signature.to_vec()))
    }

    /// 组装并签名设备申请。字段集合与顺序无关，但**字段集合必须完全一致**：
    /// 服务器按白名单校验，多一个少一个都算协议无效。
    pub fn build(
        invite: &Invite,
        invite_payload: &Value,
        client: &ClientRequest,
        device_name: &str,
        recipient: &RsaJwk,
        key: &RsaPrivateKey,
        created_at_utc: &str,
    ) -> Result<String, PairError> {
        if device_name.is_empty()
            || device_name.chars().count() > 64
            || device_name.trim() != device_name
            || device_name.chars().any(|c| c.is_control())
        {
            return Err(PairError::bad_device_name());
        }
        let binding = invite_payload
            .get("ServerBinding")
            .cloned()
            .ok_or_else(|| invalid("邀请缺少服务器绑定信息。"))?;
        let body = json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairRequest",
            "InviteId": invite.invite_id,
            "ServerBinding": binding,
            "ClientRequest": {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": client.request_id,
                "DeviceId": client.device_id,
                "CreatedAtUtc": client.created_at_utc,
                "ClientPublicKey": client.client_public_key,
                "AddressFamilies": ["IPv4"],
            },
            "DeviceName": device_name,
            "RecipientJwk": {
                "kty": "RSA",
                "n": recipient.n,
                "e": recipient.e,
            },
            "RequestDigest": client.digest()?,
            "RequestDigestAlgorithm": "TC-ClientRequest-v1",
            "CreatedAtUtc": created_at_utc,
        });
        Ok(sign_rs256(&body, key))
    }

    /// 把申请解回来校验一遍（对应 旧版的 `Get-TCPairRequestInfo`）。
    ///
    /// 服务器与命令行都要做这一步：本地签完不验，等于把错的东西发出去。
    pub fn verify(compact: &str, now_unix: i64) -> Result<Value, PairError> {
        let unverified = super::invite::unverified_payload(compact)?;
        let key = RsaJwk::parse(
            unverified
                .get("RecipientJwk")
                .ok_or_else(|| invalid("设备申请缺少接收密钥。"))?,
        )?;
        let body = super::jwk::verify_rs256(compact, &key)
            .map_err(|_| invalid("设备申请签名、接收密钥或算法校验失败。"))?;
        let object = body.as_object().ok_or_else(|| invalid("设备申请格式无效。"))?;
        for field in [
            "SchemaVersion",
            "Kind",
            "InviteId",
            "ServerBinding",
            "ClientRequest",
            "DeviceName",
            "RecipientJwk",
            "RequestDigest",
            "RequestDigestAlgorithm",
            "CreatedAtUtc",
        ] {
            if !object.contains_key(field) {
                return Err(invalid("设备申请字段不完整。"));
            }
        }
        if object.get("SchemaVersion").and_then(Value::as_i64) != Some(1)
            || object.get("Kind").and_then(Value::as_str) != Some("TradeChannel.PairRequest")
            || object.get("RequestDigestAlgorithm").and_then(Value::as_str)
                != Some("TC-ClientRequest-v1")
        {
            return Err(invalid("设备申请协议无效。"));
        }
        let inner = object
            .get("ClientRequest")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("设备申请缺少客户端请求。"))?;
        let client = ClientRequest {
            request_id: inner
                .get("RequestId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            device_id: inner
                .get("DeviceId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            created_at_utc: inner
                .get("CreatedAtUtc")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            client_public_key: inner
                .get("ClientPublicKey")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        };
        let digest = client.digest()?;
        if object.get("RequestDigest").and_then(Value::as_str) != Some(digest.as_str()) {
            return Err(PairError::new_pub("PairingMismatch", "设备申请摘要不匹配。"));
        }
        let created = super::invite::parse_time(object.get("CreatedAtUtc"))
            .ok_or_else(|| invalid("设备申请时间无效。"))?;
        if created > now_unix + 300 {
            return Err(invalid("设备申请时间在未来，请检查本机时钟。"));
        }
        Ok(body)
    }
}

/// 授权回包的形状校验（对齐 `Complete-TCPairOnlineEnrollment` 的三项比对）。
///
/// 只做「是不是给我的」这一步：内容解封要等隧道私钥那一块。
pub mod authorize_reply {
    use super::PairError;

    #[derive(Debug, Clone)]
    pub struct Reply {
        // 核对过的三项标识：只作为回包的证据保留，解封只读 `encrypted_authorization`。
        #[allow(dead_code)]
        pub status: String,
        #[allow(dead_code)]
        pub request_id: String,
        #[allow(dead_code)]
        pub request_digest: String,
        /// RSA-OAEP 密文（base64），只有本机私钥能解。
        pub encrypted_authorization: String,
    }

    /// 三个标识必须同时对上：状态是 `Authorized`、申请 id 与摘要都是本机这份。
    /// 少对一项就说明这次回包不是给这台电脑的。
    pub fn check(
        data: &serde_json::Value,
        expected_request_id: &str,
        expected_digest: &str,
    ) -> Result<Reply, PairError> {
        let invalid = |message: &str| PairError::new_pub("OnlineAuthorizationMismatch", message);
        let text = |key: &str| data.get(key).and_then(serde_json::Value::as_str).unwrap_or("");
        let status = text("Status");
        let request_id = text("RequestId");
        let digest = text("RequestDigest");
        let cipher = text("EncryptedAuthorization");
        if status != "Authorized"
            || request_id != expected_request_id
            || digest != expected_digest
            || cipher.is_empty()
        {
            return Err(invalid("授权返回不属于本机原申请。"));
        }
        Ok(Reply {
            status: status.to_string(),
            request_id: request_id.to_string(),
            request_digest: digest.to_string(),
            encrypted_authorization: cipher.to_string(),
        })
    }
}

/// 授权密文（`EncryptedAuthorization`）的解封：那是一段 **5 段 JWE 紧凑序列化**。
///
/// 对齐 旧版的 `PairCrypto.Decrypt`：
/// `Header(compact, 5, "RSA-OAEP-256", "A256CBC-HS512")` +
/// `JWT.Decode(compact, rsa, RSA_OAEP_256, A256CBC_HS512)`。
///
/// 算法在本模块里写死，**不从报文中读**。让「报文自己声明算法」去决定怎么解，
/// 就是把算法协商权交给发报文的一方——那是 JWT 里 `alg=none`、RS256/HS256 混淆
/// 这一类漏洞的同一个根：解析器比校验者更宽容。这里反过来，只认唯一一对算法。
pub mod jwe {
    use super::PairError;
    use aes::cipher::block_padding::NoPadding;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use rsa::{Oaep, RsaPrivateKey};
    use serde_json::Value;
    use sha2::{Sha256, Sha512};

    const URL_SAFE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// 密钥封装算法（旧版的 `JweAlgorithm.RSA_OAEP_256`）。
    const ALG: &str = "RSA-OAEP-256";
    /// 内容加密算法（旧版的 `JweEncryption.A256CBC_HS512`）。
    const ENC: &str = "A256CBC-HS512";
    /// 旧版加密时会带头 `cty`；值固定，别的值说明这不是同一份协议。
    const CTY: &str = "TC-Pairing-v1";
    /// 紧凑序列化的段数：header / encrypted_key / iv / ciphertext / tag。
    const PARTS: usize = 5;
    /// A256CBC-HS512 的 CEK 是 64 字节：前 32 字节是 MAC key，后 32 字节是 AES-256 key。
    const CEK_LEN: usize = 64;
    const MAC_KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;
    const TAG_LEN: usize = 32;
    const BLOCK_LEN: usize = 16;
    /// 旧版对整条串的上限（`PairingTooLarge`）。
    const MAX_LEN: usize = 131_072;

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidEncryptedAuthorization", message)
    }

    /// 解密一段 JWE 紧凑序列化，返回明文（UTF-8 字符串）。
    ///
    /// 整个过程的顺序是硬性的：**先验完整性，再解密**。反过来（先解出明文再验 MAC）
    /// 就意味着每一条伪造的密文都会走一遍 CBC 解密与填充检查，把「填充对不对」
    /// 变成可观测量——那正是 padding oracle 的入口。先验 MAC 之后，凡是通过了
    /// 那一步的密文都出自持有密钥的一方，解密的任何失败都不再携带信息。
    pub fn decrypt(compact: &str, key: &RsaPrivateKey) -> Result<String, PairError> {
        let compact = compact.trim();
        if compact.is_empty() || compact.len() > MAX_LEN {
            return Err(invalid("授权密文为空或过长。"));
        }
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != PARTS {
            return Err(invalid("授权密文不是 5 段的 JWE 紧凑序列化。"));
        }
        let mut raw: Vec<Vec<u8>> = Vec::with_capacity(PARTS);
        for (index, part) in parts.iter().enumerate() {
            // 空段等于缺字段。ciphertext 至少有填充块、tag 固定 32 字节，
            // 所以任何一段为空都只能说明这条串被截断了。
            if part.is_empty() {
                return Err(invalid(&format!("授权密文第 {} 段为空。", index + 1)));
            }
            let decoded = URL_SAFE
                .decode(part)
                .map_err(|_| invalid(&format!("授权密文第 {} 段不是合法 base64url。", index + 1)))?;
            raw.push(decoded);
        }

        let header: Value = serde_json::from_slice(&raw[0])
            .map_err(|_| invalid("授权密文头部不是合法 JSON。"))?;
        let object = header
            .as_object()
            .ok_or_else(|| invalid("授权密文头部不是 JSON 对象。"))?;
        if object.get("alg").and_then(Value::as_str) != Some(ALG) {
            return Err(invalid("授权密文的密钥封装算法不是 RSA-OAEP-256。"));
        }
        if object.get("enc").and_then(Value::as_str) != Some(ENC) {
            return Err(invalid("授权密文的内容加密算法不是 A256CBC-HS512。"));
        }
        // `cty` 有就必须对：对端会带，带了别的类型说明拿错了一份信封。
        // 没有则不惩罚——jose-jwt 的 Decode 同样不看它，这里的容忍度与对端一致。
        if let Some(cty) = object.get("cty") {
            if cty.as_str() != Some(CTY) {
                return Err(invalid("授权密文的内容类型不是 TC-Pairing-v1。"));
            }
        }

        // 密钥封装：只有本机私钥能解。OAEP 的摘要固定 SHA-256（`RSA-OAEP-256`），
        // 用默认的 SHA-1 会解不开对端的密文，而且解出来的长度也不会对。
        //
        // 走 `decrypt_blinded` 而不是 `decrypt`：`decrypt` 的私钥运算是**未盲化**的
        // （rsa crate 在文档里明说），模幂耗时与输入相关；而这条路径上的输入完全由
        // 发报文的一方控制——服务器、或者任何能反复投喂 `EncryptedAuthorization` 的人，
        // 都能让我们做任意多次私钥运算，慢慢把「密文 → 耗时」采成一张表。盲化在每次
        // 运算前把密文乘一个随机因子，把这个关系打散。
        //
        // 这条路只有一种失败：密文不合法（含「不是给本机密钥的」）→ `rsa::Error`。
        // 盲化本身没有「失败」这种返回值：`decrypt_blinded` 收的是 `CryptoRngCore`
        // （infallible），`OsRng` 取不到随机数时是 **panic** 而不是 `Err`。这是刻意
        // 的——系统随机源都取不到数，早就超出「这次配对失败」这个量级，静默降级成
        // 「解不开」只会把真正的问题藏起来。所以这里不需要、也不该为它加分支。
        let cek = Cek::new(
            key.decrypt_blinded(&mut rsa::rand_core::OsRng, Oaep::new::<Sha256>(), &raw[1])
                .map_err(|_| invalid("授权密文的密钥封装解不开：这段密文不是给本机密钥的。"))?,
        );
        // 长度校验放在 guard 之后：这样连「长度不对」这种最怪的早退也走 Drop 清零。
        if cek.len() != CEK_LEN {
            return Err(invalid("授权密文的内容密钥长度不是 64 字节。"));
        }
        let (mac_key, enc_key) = cek.split();

        let iv = raw[2].as_slice();
        let ciphertext = raw[3].as_slice();
        let tag = raw[4].as_slice();
        if iv.len() != IV_LEN {
            return Err(invalid("授权密文的 IV 长度不是 16 字节。"));
        }
        if tag.len() != TAG_LEN {
            return Err(invalid("授权密文的认证标签长度不是 32 字节。"));
        }
        if ciphertext.is_empty() || ciphertext.len() % BLOCK_LEN != 0 {
            return Err(invalid("授权密文的正文长度与分组不对齐。"));
        }

        // AAD 只取受保护头那一段（RFC 7516 §5.1）：加密密钥段不参与认证。
        // 旧版的 jose-jwt 与服务器脚本都按这个口径算；把第二段也拼进来会算出
        // 另一个 MAC——真机第一次加入就卡在这里。
        let aad = parts[0];
        let expected = tag_for(mac_key, aad.as_bytes(), iv, ciphertext)?;
        if !constant_time_eq(tag, &expected) {
            // 这一句必须与「解不开」分开：MAC 不符说明密文被动过（或密钥不对），
            // 而填充/UTF-8 失败只在 MAC 通过之后才可能出现，两者的排障方向不同。
            return Err(invalid("授权密文的完整性校验失败：密文或标签与本机申请不匹配。"));
        }

        let plaintext = decrypt_cbc(enc_key, iv, ciphertext)?;
        // 不用在这里手动清零：`cek` 离开作用域时 `Cek::drop` 会抹掉它，
        // 上面那六条早退路径同样如此。解出来的明文归调用方，清零时机也归调用方。
        String::from_utf8(plaintext)
            .map_err(|_| invalid("授权密文解出的内容不是合法 UTF-8。"))
    }

    /// 内容密钥（CEK）的持有者：只为保证一件事——**任何退出路径都会清零**。
    ///
    /// 这个函数里 CEK 拿到手之后还有六条早退（长度、IV、标签、正文对齐、MAC、
    /// 解密/填充/UTF-8），而早退只会随需求增加、不会减少。手写「每个 return 前清一次」
    /// 迟早漏一条——漏掉的往往正是「验签失败」这种最需要清干净的路径。所以把所有权
    /// 交给这个类型，靠 `Drop` 兜底：只要它离开作用域，无论从哪一行返回都会被抹掉。
    ///
    /// 刻意**不实现** `Clone`（能复制就能绕开 Drop）、不是 `Copy`、也**不实现**
    /// `Deref<Target = [u8]>`（那会让引用到处漏出去，同样绕开这层保证）。
    /// 要数据只能显式调 `split()` / `len()`。
    struct Cek(Vec<u8>);

    impl Cek {
        /// 接管密钥材料。构造即负责：从这里开始，任何路径都不会漏掉清零。
        fn new(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }

        fn len(&self) -> usize {
            self.0.len()
        }

        /// 按 A256CBC-HS512 的切法分开：前 32 字节算 MAC，后 32 字节做 AES-256 密钥。
        fn split(&self) -> (&[u8], &[u8]) {
            self.0.split_at(MAC_KEY_LEN)
        }
    }

    impl Drop for Cek {
        fn drop(&mut self) {
            super::zero(&mut self.0);
            #[cfg(test)]
            DROPS.with(|count| count.set(count.get() + 1));
        }
    }

    // 测试用的 Drop 计数器，用来证明「走 Err 早退时 CEK 也被清零了」。
    //
    // 留着它不是为了调试，而是一条防回归的锚点：如果有人把 `Cek` 改成不持所有权、
    // 或者在早退分支里把密钥 `clone()` 出去（副本不经过 Drop），计数就对不上，
    // 对应用例会挂。用 thread-local 而不是全局静态，是因为用例默认并行跑，
    // 全局计数会被别的用例干扰，断言也就不成立了。
    // （写成普通注释而不是文档注释：文档注释挂在宏调用上会被判为 unused doc comment。）
    #[cfg(test)]
    thread_local! {
        static DROPS: std::cell::Cell<usize> = std::cell::Cell::new(0);
    }

    /// 本线程上 `Cek` 被 drop 过多少次（只在测试编译里存在）。
    #[cfg(test)]
    pub(super) fn drops() -> usize {
        DROPS.with(|count| count.get())
    }

    /// A256CBC-HS512 的认证标签：`HMAC-SHA-512(mac_key, aad ‖ iv ‖ ciphertext ‖ AL)`
    /// 截断到 32 字节。`AL` 是 AAD 的**比特**长度（64 位大端）。
    ///
    /// `AL` 不能省：它是「AAD 有多长」这件事的唯一绑定。少了它，一条 AAD 只要
    /// 尾部内容不同、长度没被覆盖，改过的头部仍能算出同一个 MAC——那等于让
    /// header 里的 alg/enc 可以被人随便换掉而不被发现。
    fn tag_for(
        mac_key: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; TAG_LEN], PairError> {
        let mut mac = Hmac::<Sha512>::new_from_slice(mac_key)
            .map_err(|_| invalid("授权密文的认证密钥无效。"))?;
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        mac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&digest[..TAG_LEN]);
        Ok(tag)
    }

    /// AES-256-CBC 解密 + PKCS#7 去填充。
    ///
    /// 解填充交给 [`strip_pkcs7`] 自己算，不用库里的 `Pkcs7`：这条路径上
    /// 「填充不对」与「MAC 不对」要报成不同的句子，所以填充的判据必须看得见。
    fn decrypt_cbc(enc_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PairError> {
        let mut buffer = ciphertext.to_vec();
        let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(enc_key, iv)
            .map_err(|_| invalid("授权密文的内容密钥无效。"))?;
        let plain_len = cipher
            .decrypt_padded_mut::<NoPadding>(&mut buffer)
            .map_err(|_| invalid("授权密文的正文长度与分组不对齐。"))?
            .len();
        buffer.truncate(plain_len);
        strip_pkcs7(buffer)
    }

    /// 严格按 RFC 5652 去 PKCS#7 填充：填充长度 1..=16，且末尾每个字节都等于这个长度。
    ///
    /// 只看最后一个字节就截断是不行的：末尾字节落进 1..=16 的「假填充」会直接把
    /// 随机内容当明文交出去（约 1/256 的情况下会发生）。MAC 已经先验过、这条路径
    /// 上的攻击者并不掌握密钥，但严格校验是这层自己的契约——它不该靠「上游已经拦过」
    /// 才成立，否则改一处顺序就会静默退化成不安全。
    fn strip_pkcs7(mut buffer: Vec<u8>) -> Result<Vec<u8>, PairError> {
        let pad = match buffer.last() {
            Some(byte) => usize::from(*byte),
            None => return Err(invalid("授权密文解密后为空，缺少填充。")),
        };
        if pad == 0 || pad > BLOCK_LEN || pad > buffer.len() {
            return Err(invalid("授权密文解密后的填充长度无效。"));
        }
        if buffer[buffer.len() - pad..]
            .iter()
            .any(|byte| usize::from(*byte) != pad)
        {
            return Err(invalid("授权密文解密后的填充内容无效。"));
        }
        buffer.truncate(buffer.len() - pad);
        Ok(buffer)
    }

    /// 常量时间比较：逐字节异或累加，全程不提前返回。
    ///
    /// 认证标签是「这段密文没被改过」的唯一证据。用 `==` 比会在第一个不同的字节
    /// 上返回，比较耗时随「前多少个字节对上了」变化——反复试探就能一位一位地
    /// 把正确标签拼出来，等于给 MAC 开了一条逐字节试错的路。
    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            // 长度是公开信息（报文里看得见），提前返回不泄漏任何秘密。
            return false;
        }
        let mut difference = 0u8;
        for (a, b) in left.iter().zip(right.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

/// Windows DPAPI 信封：配对私钥（隧道私钥、重试用的原申请）落盘前的最后一道封装。
///
/// 不起新依赖：直接声明 `crypt32` 的两个入口。密钥由 Windows 按**当前用户**托管，
/// 别的账户、别的机器拿着这份文件也解不开——这是「文件被拷走」时的兜底。
/// 它不替代传输侧的 TLS pin 与 JWE：两条线一个管「线上别被看」，一个管「盘上别被看」。
pub mod dpapi {
    use super::PairError;

    /// 固定熵（salt）：同一个账户下，只有带着这串 bytes 的本程序能解开信封。
    /// 改掉它等于让所有已经存下来的信封作废，所以它是一个契约常量，不是可调参数。
    const ENTROPY: &[u8] = b"TradeChannel.Pairing.v1";
    /// 信封的合理上限。配对私钥的 XML 约几 KB，留到 128 KiB 已经很宽松；
    /// 超过这个长度的输入不是本程序写出来的，早拒比让 DPAPI 去啃一大块内存好。
    const MAX_B64: usize = 131_072;

    fn unavailable(message: &str) -> PairError {
        PairError::new_pub("PairingPrivateUnavailable", message)
    }

    /// 把系统错误码带进句子：账户、服务上下文、DLL 缺失这几类问题只能靠这个码定位
    /// （DPAPI 的失败原因不会体现在返回值里，只有 GetLastError 说得清）。
    fn describe(error: &std::io::Error) -> String {
        match error.raw_os_error() {
            Some(code) => format!("系统错误 {code}，{error}"),
            None => format!("{error}"),
        }
    }

    /// 清零只有一份实现，在 `pairing` 顶层（volatile 写，理由见那里的注释）；
    /// jwe 的 CEK 清零也走它。`cfg` 跟着使用点走，免得非 Windows 上变成未使用的导入。
    #[cfg(windows)]
    use super::zero;

    #[cfg(windows)]
    mod sys {
        use std::ffi::c_void;

        /// Win32 的 `DATA_BLOB`。字段顺序与 `cbData` 的类型必须与 SDK 一致。
        #[repr(C)]
        pub struct DataBlob {
            pub cb_data: u32,
            pub pb_data: *mut u8,
        }

        /// `CRYPTPROTECT_UI_FORBIDDEN`：不许弹任何 UI。
        /// 后台进程里弹框会把调用方卡死（而且没人能点）。
        ///
        /// 刻意**不用** `CRYPTPROTECT_LOCAL_MACHINE`：那会让同一台机器上任何账户
        /// 都能解开，等于把「谁的私钥」这件事抹掉。
        pub const UI_FORBIDDEN: u32 = 0x1;

        #[link(name = "crypt32")]
        extern "system" {
            pub fn CryptProtectData(
                data_in: *const DataBlob,
                description: *const u16,
                entropy: *const DataBlob,
                reserved: *mut c_void,
                prompt: *mut c_void,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;
            /// 第二个参数是 `LPWSTR*`（描述串出参），我们不需要，传 null。
            pub fn CryptUnprotectData(
                data_in: *const DataBlob,
                description: *mut *mut u16,
                entropy: *const DataBlob,
                reserved: *mut c_void,
                prompt: *mut c_void,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;
        }

        #[link(name = "kernel32")]
        extern "system" {
            /// DPAPI 的输出用 `LocalAlloc` 分配，只能用 `LocalFree` 归还。
            pub fn LocalFree(memory: *mut c_void) -> *mut c_void;
        }
    }

    /// 把明文封装成 DPAPI 信封（标准 base64）。同一份明文每次的结果都不同
    /// （DPAPI 自带随机 salt），这正是它可以当「不可比对」的封条用的原因。
    ///
    /// 固定熵：配对私钥专用。要按记录绑定熵的调用方用 [`protect_with`]。
    #[cfg(windows)]
    pub fn protect(plain: &str) -> Result<String, PairError> {
        protect_with(plain, ENTROPY)
    }

    /// 按调用方给的熵封装。
    ///
    /// **熵不是秘密**（部署凭据用的是 host/port/user/指纹，都在公开的 `record.json` 里），
    /// 它起的作用是「把信封钉在这条记录上」：记录身份一变，同一个账户也解不开。
    /// 真正的保护来自 DPAPI 的用户作用域密钥，不是这串 bytes。
    #[cfg(windows)]
    pub fn protect_with(plain: &str, entropy_seed: &[u8]) -> Result<String, PairError> {
        use base64::Engine;
        if plain.is_empty() {
            return Err(unavailable("待封装的配对私钥为空。"));
        }
        // 明文自己用 Vec 承载：调用结束后要能把它清零，String 的内部缓冲不归我们管。
        let mut input = plain.as_bytes().to_vec();
        let mut entropy = entropy_seed.to_vec();
        let mut output = sys::DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
        let ok = unsafe {
            let data_in = sys::DataBlob { cb_data: input.len() as u32, pb_data: input.as_mut_ptr() };
            let entropy_blob =
                sys::DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_mut_ptr() };
            sys::CryptProtectData(
                &data_in,
                std::ptr::null(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sys::UI_FORBIDDEN,
                &mut output,
            )
        };
        // 先取错误码再清零：清零本身不会再碰 GetLastError，但顺序写死了不必去想。
        let error = std::io::Error::last_os_error();
        zero(&mut input);
        zero(&mut entropy);
        if ok == 0 {
            return Err(unavailable(&format!("DPAPI 加密失败（{}）。", describe(&error))));
        }
        if output.pb_data.is_null() || output.cb_data == 0 {
            return Err(unavailable("DPAPI 加密没有产出任何数据。"));
        }
        // SAFETY: 成功返回时 DPAPI 保证 `pb_data` 指向 `cb_data` 个可写字节，
        // 且这块内存归调用方所有（必须 LocalFree）。
        let bytes = unsafe {
            let slice = std::slice::from_raw_parts_mut(output.pb_data, output.cb_data as usize);
            let copy = slice.to_vec();
            // 密文本身不算秘密，但清零的成本近乎为零，也免得有人在这里复用缓冲。
            zero(slice);
            sys::LocalFree(output.pb_data as *mut std::ffi::c_void);
            copy
        };
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// 解开 DPAPI 信封。base64 解不开、系统解密失败都返回错误；这里没有任何 `panic!`：
    /// 信封可能是别的账户写的、被截断的、或者根本不是本程序写的，都是正常输入。
    #[cfg(windows)]
    pub fn unprotect(protected_b64: &str) -> Result<String, PairError> {
        unprotect_with(protected_b64, ENTROPY)
    }

    /// 按调用方给的熵解开（与 [`protect_with`] 配对）。
    #[cfg(windows)]
    pub fn unprotect_with(protected_b64: &str, entropy_seed: &[u8]) -> Result<String, PairError> {
        use base64::Engine;
        let text = protected_b64.trim();
        if text.is_empty() {
            return Err(unavailable("DPAPI 信封为空。"));
        }
        if text.len() > MAX_B64 {
            return Err(unavailable("DPAPI 信封过长，不像是本程序写出来的。"));
        }
        let mut cipher = base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| unavailable("DPAPI 信封不是合法的 base64。"))?;
        if cipher.is_empty() {
            return Err(unavailable("DPAPI 信封解出来是空的。"));
        }
        let mut entropy = entropy_seed.to_vec();
        let mut output = sys::DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
        let ok = unsafe {
            let data_in =
                sys::DataBlob { cb_data: cipher.len() as u32, pb_data: cipher.as_mut_ptr() };
            let entropy_blob =
                sys::DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_mut_ptr() };
            sys::CryptUnprotectData(
                &data_in,
                std::ptr::null_mut(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sys::UI_FORBIDDEN,
                &mut output,
            )
        };
        let error = std::io::Error::last_os_error();
        zero(&mut cipher);
        zero(&mut entropy);
        if ok == 0 {
            return Err(unavailable(&format!(
                "DPAPI 解密失败（{}）：信封不属于当前账户或已被截断。",
                describe(&error)
            )));
        }
        if output.pb_data.is_null() || output.cb_data == 0 {
            return Err(unavailable("DPAPI 解密没有产出任何数据。"));
        }
        // SAFETY: 成功返回时 `pb_data` 指向 `cb_data` 个可读字节，内存归调用方。
        let plain = unsafe {
            let slice = std::slice::from_raw_parts_mut(output.pb_data, output.cb_data as usize);
            let copy = slice.to_vec();
            zero(slice);
            sys::LocalFree(output.pb_data as *mut std::ffi::c_void);
            copy
        };
        // 交给调用方的 String 缓冲不受我们控制，解不开时把缓冲清零再报错。
        match String::from_utf8(plain) {
            Ok(text) => Ok(text),
            Err(error) => {
                let mut bytes = error.into_bytes();
                zero(&mut bytes);
                Err(unavailable("DPAPI 解出的内容不是合法 UTF-8。"))
            }
        }
    }

    /// 非 Windows 平台：DPAPI 不存在，如实报不可用，而不是偷偷退回明文。
    #[cfg(not(windows))]
    pub fn protect(_plain: &str) -> Result<String, PairError> {
        Err(unavailable("DPAPI 只在 Windows 上可用。"))
    }

    /// 非 Windows 平台：同上。
    #[cfg(not(windows))]
    pub fn protect_with(_plain: &str, _entropy_seed: &[u8]) -> Result<String, PairError> {
        Err(unavailable("DPAPI 只在 Windows 上可用。"))
    }

    /// 非 Windows 平台：同上。
    #[cfg(not(windows))]
    pub fn unprotect(_protected_b64: &str) -> Result<String, PairError> {
        Err(unavailable("DPAPI 只在 Windows 上可用。"))
    }

    /// 非 Windows 平台：同上。
    #[cfg(not(windows))]
    pub fn unprotect_with(
        _protected_b64: &str,
        _entropy_seed: &[u8],
    ) -> Result<String, PairError> {
        Err(unavailable("DPAPI 只在 Windows 上可用。"))
    }
}

/// 在线登记的第一步：拿邀请码去服务器读邀请，并验证签名与绑定。
///
/// 对应 旧版的 `Get-TCPairOnlineInvitation`。失败时给的是能直接显示给用户的
/// 错误码与句子；调用方不需要再判断「是不是网络问题」——指纹不符单独成码。
/// 时间戳：`YYYY-MM-DDTHH:MM:SS.ffffffZ`。
///
/// 刻意用 **6 位**小数而不是 .NET `o` 的 7 位：服务端用 Python
/// `datetime.fromisoformat` 解析，老版本只认 3/6 位。这个字符串还会参与
/// `TC-ClientRequest-v1` 摘要，所以格式必须一次定死、之后不再变。
pub fn rfc3339_micros(unix: i64) -> String {
    let Ok(stamp) = time::OffsetDateTime::from_unix_timestamp(unix) else {
        return "1970-01-01T00:00:00.000000Z".to_string();
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        stamp.year(),
        u8::from(stamp.month()),
        stamp.day(),
        stamp.hour(),
        stamp.minute(),
        stamp.second(),
        stamp.microsecond()
    )
}

/// 服务端要求的 36 位小写 UUID（v4 形状）。只用于 RequestId / DeviceId，
/// 不参与任何安全判断，所以这里用 `OsRng` 生成即可。
pub fn random_uuid_v4() -> String {
    use rsa::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// 由服务器的 `ClientResponse` 渲染 WireGuard 客户端配置。
///
/// 逐项对齐 旧版的 `Complete-TCClientConfig`：地址必须是专用网段里的单个
/// `/32`、服务器地址必须恰为网段首地址 +1、`AllowedIPs` 只接受 `0.0.0.0/0`、
/// `PersistentKeepalive` 只接受 25。这些都是**契约**而不是建议——服务器给错了，
/// 生成出来的配置就是一条连不通或把全网流量送错地方的隧道。
pub mod tunnel {
    use serde_json::Value;

    use super::PairError;

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidClientResponse", message)
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value.get(key).and_then(Value::as_str).unwrap_or("")
    }

    fn ipv4(text: &str) -> Option<u32> {
        let address: std::net::Ipv4Addr = text.parse().ok()?;
        // 只收规范写法：`10.0.0.010` 这类别的写法会让下面的网段比较失去意义。
        if address.to_string() != text {
            return None;
        }
        Some(u32::from(address))
    }

    fn is_private(start: u32, end: u32) -> bool {
        let inside = |from: u32, to: u32| start >= from && end <= to;
        inside(0x0a00_0000, 0x0aff_ffff)      // 10.0.0.0/8
            || inside(0xac10_0000, 0xac1f_ffff) // 172.16.0.0/12
            || inside(0xc0a8_0000, 0xc0a8_ffff) // 192.168.0.0/16
    }

    /// 专用隧道网段：必须是 RFC1918 的**网络地址**，前缀 /16–/30。
    fn subnet(cidr: &str) -> Result<(u32, u32, u8), PairError> {
        let (host, prefix) = cidr.split_once('/').ok_or_else(|| invalid("隧道网段不是 IPv4 CIDR。"))?;
        let address = ipv4(host).ok_or_else(|| invalid("隧道网段不是规范的 IPv4。"))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid("隧道网段前缀无效。"))?;
        if !(16..=30).contains(&prefix) {
            return Err(invalid("隧道网段前缀必须在 /16 到 /30 之间。"));
        }
        let size = 1u32 << (32 - prefix as u32);
        let start = address & !(size - 1);
        if address != start {
            return Err(invalid("隧道网段必须是网络地址本身。"));
        }
        let end = start + size - 1;
        if !is_private(start, end) {
            return Err(invalid("隧道网段必须是 RFC1918 私有网段。"));
        }
        Ok((start, end, prefix))
    }

    /// 43 位 base64 + `=`（32 字节）。与 `ClientPublicKey` 同一个形状。
    fn wireguard_key(value: &str) -> bool {
        // SEC-11: validate the *byte shape* of an external WireGuard key.
        // UTF-8 multibyte sequences, malformed padding and overlong values
        // are not permitted; do not slice a &str at arbitrary byte offsets.
        let bytes = value.as_bytes();
        bytes.len() == 44
            && bytes[43] == b'='
            && bytes[..43]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    }

    /// 渲染配置。返回的字符串用 **CRLF** 分行并以单个 CRLF 结尾——与旧版
    /// 逐字节一致；换成 LF 会让「已存在的配置是否相同」这类比较永远不成立。
    pub fn render(
        response: &Value,
        tunnel_private_b64: &str,
        client_request: &Value,
    ) -> Result<String, PairError> {
        if !wireguard_key(tunnel_private_b64) {
            return Err(invalid("本机隧道私钥形状无效。"));
        }
        if text(response, "Kind") != "TradeChannel.ClientResponse"
            || text(response, "Status") != "Authorized"
        {
            return Err(invalid("服务器响应不是已授权的设备响应。"));
        }
        // 响应必须绑回**这一份**申请：换一个字段就是别人的设备。
        for key in ["RequestId", "DeviceId", "ClientPublicKey"] {
            if text(response, key) != text(client_request, key) {
                return Err(PairError::new_pub(
                    "ResponseMismatch",
                    "服务器响应与本机设备申请不匹配。",
                ));
            }
        }
        let families = response
            .get("AddressFamilies")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if families != ["IPv4"] {
            return Err(invalid("只支持 IPv4 隧道。"));
        }

        let server_key = text(response, "ServerPublicKey");
        if !wireguard_key(server_key) {
            return Err(invalid("服务器公钥形状无效。"));
        }
        if server_key == text(client_request, "ClientPublicKey") {
            return Err(invalid("服务器公钥不能与本机公钥相同。"));
        }
        let allowed = response
            .get("AllowedIPs")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if allowed != ["0.0.0.0/0"] {
            return Err(invalid("路由必须是 0.0.0.0/0。"));
        }
        if response.get("PersistentKeepalive").and_then(Value::as_i64) != Some(25) {
            return Err(invalid("保活间隔必须是 25 秒。"));
        }

        let (start, end, prefix) = subnet(text(response, "TunnelSubnet"))?;
        // 服务器地址固定是网段首地址 +1；对不上说明网段和地址来自两套配置。
        let server_expected = format!(
            "{}/{}",
            std::net::Ipv4Addr::from(start + 1),
            prefix
        );
        if text(response, "ServerAddress") != server_expected {
            return Err(invalid("服务器地址不是网段内约定的那一个。"));
        }

        // 设备地址：允许带 `/32`，但必须是网段内、且不占网络/服务器/广播地址。
        let raw = text(response, "ClientAddress");
        let host = raw.strip_suffix("/32").unwrap_or(raw);
        if raw.contains('/') && !raw.ends_with("/32") {
            return Err(invalid("设备地址必须是单个 /32。"));
        }
        let number = ipv4(host).ok_or_else(|| invalid("设备地址不是规范的 IPv4。"))?;
        if number <= start + 1 || number >= end {
            return Err(invalid("设备地址必须落在隧道网段内，且不能是网络/服务器/广播地址。"));
        }

        let endpoint = text(response, "PublicEndpoint");
        let (endpoint_host, endpoint_port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| invalid("服务器入口格式无效。"))?;
        if ipv4(endpoint_host).is_none() {
            return Err(invalid("服务器入口必须是 IPv4。"));
        }
        match endpoint_port.parse::<u16>() {
            Ok(port) if port >= 1024 => {}
            _ => return Err(invalid("服务器入口端口无效。")),
        }

        let mut lines: Vec<String> = vec![
            "[Interface]".to_string(),
            format!("PrivateKey = {tunnel_private_b64}"),
            format!("Address = {host}/32"),
        ];
        if let Some(mtu) = response.get("MTU") {
            match mtu.as_i64() {
                Some(value) if (1280..=1420).contains(&value) => {
                    lines.push(format!("MTU = {value}"));
                }
                _ => return Err(invalid("服务器返回的 MTU 必须在 1280–1420 之间。")),
            }
        }
        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {server_key}"));
        lines.push("AllowedIPs = 0.0.0.0/0".to_string());
        lines.push(format!("Endpoint = {endpoint}"));
        lines.push("PersistentKeepalive = 25".to_string());
        lines.push(String::new());
        Ok(lines.join("\r\n"))
    }
}

/// 把 `client.conf` 变成一条**真正可连接的线路**。
///
/// 为什么要这一层：[`tunnel::render`] 只产出 WireGuard 原生配置——那是给 wg 客户端看的，
/// 本程序的引擎（sing-box）不认。要让「用邀请码加入」真的能用，必须把它变成引擎的
/// `wireguard` endpoint，再补上引擎起得来所需的 `dns` / `route` / `outbounds` 骨架，
/// 最后交给 `engine_config::generate` 焙进本程序自己的入站与分流。
///
/// 三个刻意的取舍，写在这里而不是散在代码里：
/// 1. **落盘的那份永远是标准档（Udp）**。兼容档（Tcp）由 `engine_config::apply_transport`
///    在连接前现场派生——一份事实、两种用法。若这里直接写 Tcp 形状，`actual_transport`
///    会认为「用户选了兼容连接」，而 `LineConfig.transport` 却是 `None`，两处事实互相打架；
///    而 `tcp_shaped()` 还会让下一次 `--import`/`--set-line` 把这份文件读成「用户已选 Tcp」。
/// 2. **兼容参数仍然要落到线路文件里**（一条 `tag=tc-transport` 的 vless 出站）：
///    `engine_config::transport_params` 只从线路文件读参数。旧版把这个信息放在
///    manifest 里，本版没有那个字段，所以只能放这里。标准档下它不被任何东西引用，
///    引擎允许存在未使用的出站，行为一个字节都不受影响。
/// 3. **骨架自己造，但不发明参数**：`dns` / `outbounds` / `route` 的字段名与形状照旧版的
///    `New-TCRoutingPolicy`（`NodeStore.psm1:1003-1015`），但**不抄它那套分流规则**——
///    那些规则依赖 rule_set 文件，本工程未必有；抄半套只会让引擎起不来。最小骨架 = 一条直连
///    DNS + 一条 `direct` 出站 + 两个选择器 + 路由兜底，其余（入站、我们的路由规则、分流、
///    出口选择）由 `generate` 焙进去，与 `--import` 走同一条路。
///
/// **已知边界（不是 bug，别再反复查）**：配对生成的线路**不带 `process_path → trade-exit`
/// 规则**。旧版靠部署时的 `ClientInspection` 自动识别交易程序、再把它们的路径写进候选
/// 配置；本版没有进程识别能力，所以邀请接入后「哪些程序走交易出口」要由用户在界面的分流页
/// 配（配过之后 `engine_config::normalize_split` 会在连接前把它们写进运行时配置，所以不是
/// 死路）。在那之前，走节点的只有自检探测流量。
pub mod line {
    use serde_json::{json, Value};
    use std::path::Path;

    use crate::config::{self, AppConfig, Exits, LineConfig, Mode, SplitConfig};
    use crate::engine_config;

    use super::PairError;

    /// 第一条线路的默认本机代理端口，与 `--import` 的 `DEFAULT_PORT` 同口径
    /// （也就是 旧版线路文件里那个 mixed 端口）。后续线路从这里往上找空位。
    pub const FIRST_PORT: u16 = 17_890;

    /// 端口上限：65532，给自检探测端口（+3）留出空间（`engine_config::validate_probe_room`）。
    pub const LAST_PORT: u16 = 65_532;

    /// WireGuard endpoint 的 tag。旧版的 `New-TCNode` 就写死 `hk`
    /// （`NodeStore.psm1:1091`），本仓也有按它找的地方，别改。
    pub const ENDPOINT_TAG: &str = "hk";

    /// 谁都没给出名字时的线路名。写在最前面的兜底：没有名字的线路在界面上点不动。
    pub const FALLBACK_NAME: &str = "邀请接入的线路";

    /// 线路名的长度上限：与页面输入框（`maxlength="64"`）和旧版的设备名上限一致。
    const NAME_MAX_CHARS: usize = 64;

    /// TUN 入站的地址，与旧版的 `New-TCNode` 同值。只在 `Mode::Tun` 时进骨架。
    const TUN_ADDRESS: &str = "172.30.250.1/30";

    /// 服务器没给 MTU 时 TUN 入站用的值：与 sing-box 里 wireguard endpoint 的默认 MTU 一致，
    /// 免得隧道两侧 MTU 不同、大包被分片丢掉（那种故障看起来像「网页打得开、行情连不上」）。
    const DEFAULT_MTU: u32 = 1408;

    #[cfg(test)]
    thread_local! {
        /// 只给「端口全被占」这类用例把扫描区间收窄用；线程局部，发布产物不包含。
        /// 与 `engine_config::ACTUAL_TRANSPORT_UNKNOWN` 同一个套路：测试要能逼出终点分支，
        /// 但不许为了它把生产区间改成可配置的运行时状态（那会变成一个新的可被误用的旋钮）。
        static PORT_WINDOW: std::cell::Cell<Option<(u16, u16)>> = const { std::cell::Cell::new(None) };
    }

    /// 把端口扫描区间临时收窄到 `first..=last`（只在本线程、只在测试构建里有效）。
    ///
    /// 返回一个**必须持有到用例结束**的守卫：`Drop` 时把区间还原成生产值。
    /// 用守卫而不是「用例末尾手动还原」，是因为 `--test-threads=1` 时所有用例跑在
    /// 同一个线程上，漏还原会让后面那些用例莫名其妙地只扫一小段端口（而且看起来像真 bug）。
    #[cfg(test)]
    pub(crate) fn force_port_window_for_test(first: u16, last: u16) -> PortWindowGuard {
        PORT_WINDOW.with(|window| window.set(Some((first, last))));
        PortWindowGuard
    }

    #[cfg(test)]
    pub(crate) struct PortWindowGuard;

    #[cfg(test)]
    impl Drop for PortWindowGuard {
        fn drop(&mut self) {
            PORT_WINDOW.with(|window| window.set(None));
        }
    }

    /// 兼容连接（旧版的 `tcp-reality`）参数。
    ///
    /// **只从服务器下发的 `ClientResponse.Transport` 读，不做任何猜测**：
    /// 参数错了就是一条连不通（或把交易流量导到别人机器上）的线路。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Compatible {
        pub server: String,
        pub port: u16,
        pub uuid: String,
        pub server_name: String,
        pub reality_public_key: String,
        pub reality_short_id: String,
    }

    /// 解析出来的 WireGuard 客户端配置。字段与 [`super::tunnel::render`] 逐项对应。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ClientConf {
        pub private_key: String,
        /// 已归一成不带前缀的 `a.b.c.d`（引擎侧要自己补 `/32`）。
        pub address: String,
        pub mtu: Option<u32>,
        pub public_key: String,
        pub endpoint_host: String,
        pub endpoint_port: u16,
        pub persistent_keepalive: u32,
        pub allowed_ips: Vec<String>,
    }

    fn invalid_conf(message: &str) -> PairError {
        PairError::new_pub("InvalidClientConfig", message)
    }

    fn invalid_transport(message: &str) -> PairError {
        PairError::new_pub("InvalidTransport", message)
    }

    /// 44 位 base64（32 字节 + `=`）。与 `tunnel::wireguard_key` 同一个形状。
    ///
    /// 按**字节**判，不切片：`&value[..43]` 遇到多字节字符会 panic，而这个函数的输入
    /// 是可以被手改的文件内容——「形状不对」必须是错误消息，不是崩溃。
    fn is_wireguard_key(value: &str) -> bool {
        let bytes = value.as_bytes();
        bytes.len() == 44
            && bytes[43] == b'='
            && bytes[..43]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    }

    fn canonical_ipv4(text: &str) -> Option<std::net::Ipv4Addr> {
        let addr: std::net::Ipv4Addr = text.trim().parse().ok()?;
        // 只收规范写法：`10.0.0.010` 这类别的写法会让后面的字符串比较失去意义。
        (addr.to_string() == text.trim()).then_some(addr)
    }

    /// INI 段。键一律小写（WireGuard 的键与段名都不区分大小写），重复键取最后一个——
    /// 与 wireguard 工具链一致，也免得为了一个「写了两次 MTU」的配置报一堆错。
    fn sections(text: &str) -> Result<Vec<(String, Vec<(String, String)>)>, PairError> {
        let body = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
        for (index, raw) in body.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                let name = rest
                    .strip_suffix(']')
                    .ok_or_else(|| {
                        invalid_conf(&format!("隧道配置第 {} 行的段名没有闭合（应为 [Interface] 这类形式）。", index + 1))
                    })?
                    .trim()
                    .to_ascii_lowercase();
                out.push((name, Vec::new()));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(invalid_conf(&format!(
                    "隧道配置第 {} 行既不是 [段名] 也不是 `键 = 值`：{line}",
                    index + 1
                )));
            };
            let Some(current) = out.last_mut() else {
                return Err(invalid_conf(&format!(
                    "隧道配置第 {} 行的键不在任何段里（缺 [Interface]）。",
                    index + 1
                )));
            };
            current.1.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
        Ok(out)
    }

    fn get<'a>(section: &'a [(String, String)], key: &str) -> Option<&'a str> {
        section
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// 解析 `client.conf`。
    ///
    /// 严格程度与 [`super::tunnel::render`] 对齐：那份文件是本程序刚渲染出来的，
    /// 任何形状不对都说明契约变了或被手改过，宁可当场报明白话，也不要带着一条
    /// 「看起来能跑」的隧道走到引擎启动失败。
    pub fn parse_client_conf(text: &str) -> Result<ClientConf, PairError> {
        let sections = sections(text)?;
        let find = |name: &str| {
            sections
                .iter()
                .find(|(section, _)| section == name)
                .map(|(_, fields)| fields.as_slice())
                .ok_or_else(|| invalid_conf(&format!("隧道配置缺少 [{name}] 段。")))
        };
        let interface = find("interface")?;
        let peer = find("peer")?;

        let private_key = get(interface, "privatekey")
            .ok_or_else(|| invalid_conf("隧道配置缺少 Interface/PrivateKey。"))?
            .to_string();
        if !is_wireguard_key(&private_key) {
            return Err(invalid_conf("隧道配置的 Interface/PrivateKey 不是 44 位 base64 密钥。"));
        }

        let address_raw = get(interface, "address")
            .ok_or_else(|| invalid_conf("隧道配置缺少 Interface/Address。"))?;
        // 只接受单个 `/32`：整段网段写进来会让引擎把整个网段挂在本机，等于替服务器转包。
        let (host, prefix) = address_raw
            .split_once('/')
            .ok_or_else(|| invalid_conf("隧道配置的 Interface/Address 必须是单个 /32 地址。"))?;
        if prefix.trim() != "32" {
            return Err(invalid_conf("隧道配置的 Interface/Address 必须是单个 /32 地址。"));
        }
        let address = canonical_ipv4(host)
            .ok_or_else(|| invalid_conf("隧道配置的 Interface/Address 不是规范的 IPv4。"))?
            .to_string();

        // MTU 与服务器给的那一份走同一个区间：1280 以下必然分片，1420 以上会超出物理链路。
        let mtu = match get(interface, "mtu") {
            None => None,
            Some(raw) => match raw.parse::<u32>() {
                Ok(value) if (1280..=1420).contains(&value) => Some(value),
                _ => {
                    return Err(invalid_conf(&format!(
                        "隧道配置的 Interface/MTU 必须是 1280–1420 之间的整数（收到：{raw}）。"
                    )))
                }
            },
        };

        let public_key = get(peer, "publickey")
            .ok_or_else(|| invalid_conf("隧道配置缺少 Peer/PublicKey。"))?
            .to_string();
        if !is_wireguard_key(&public_key) {
            return Err(invalid_conf("隧道配置的 Peer/PublicKey 不是 44 位 base64 密钥。"));
        }
        if public_key == private_key {
            // 同一个密钥出现在两侧：服务器把本机公钥又下发了回来，隧道根本建不起来。
            return Err(invalid_conf("隧道配置的服务器公钥与本机私钥相同。"));
        }

        let endpoint_raw = get(peer, "endpoint")
            .ok_or_else(|| invalid_conf("隧道配置缺少 Peer/Endpoint。"))?;
        let (endpoint_host, endpoint_port_raw) = endpoint_raw
            .rsplit_once(':')
            .ok_or_else(|| invalid_conf("隧道配置的 Peer/Endpoint 必须是 主机:端口。"))?;
        let endpoint_host = canonical_ipv4(endpoint_host)
            .ok_or_else(|| invalid_conf("隧道配置的 Peer/Endpoint 主机必须是 IPv4。"))?
            .to_string();
        let endpoint_port: u16 = endpoint_port_raw
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| invalid_conf("隧道配置的 Peer/Endpoint 端口必须是 1–65535。"))?;

        let allowed_ips: Vec<String> = get(peer, "allowedips")
            .ok_or_else(|| invalid_conf("隧道配置缺少 Peer/AllowedIPs。"))?
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect();
        if allowed_ips != ["0.0.0.0/0"] {
            return Err(invalid_conf("隧道配置的 Peer/AllowedIPs 必须是 0.0.0.0/0。"));
        }

        // 缺省按 25 处理：`render` 永远会写它，服务器契约也把它钉成 25
        // （旧版的 `PersistentKeepalive`）；引擎默认是 0，直接透传会让 NAT 把你的口提前关掉。
        let persistent_keepalive = match get(peer, "persistentkeepalive") {
            None => 25,
            Some(raw) => match raw.parse::<u32>() {
                Ok(25) => 25,
                _ => return Err(invalid_conf("隧道配置的 PersistentKeepalive 必须是 25 秒。")),
            },
        };

        Ok(ClientConf {
            private_key,
            address,
            mtu,
            public_key,
            endpoint_host,
            endpoint_port,
            persistent_keepalive,
            allowed_ips,
        })
    }

    /// 从 `ClientResponse.Transport` 读兼容连接参数。
    ///
    /// 三种结果，**都如实区分**：
    /// - `Ok(None)`：服务器没有兼容档（字段缺失，或老服务器给的是 `"udp"` 这类字符串）
    ///   → 只能生成标准档，这不是错误；
    /// - `Ok(Some(_))`：参数齐全且合法 → 线路文件里带上中转出站，用户之后可以切兼容档；
    /// - `Err(_)`：服务器说自己是 `tcp-reality` 却给了不合法的参数 → **拒绝**。
    ///   这种线路的兼容档一定连不上，而静默降级成标准档会让「用户选了兼容却还是走 UDP」，
    ///   那是最难查的一类事故。
    pub fn compatible(response: &Value) -> Result<Option<Compatible>, PairError> {
        let Some(value) = response.get("Transport") else {
            return Ok(None);
        };
        // 老服务器 / 老夹具里这个字段可能是 `"udp"` 这样的字符串：那是「没有兼容档」，不是错误。
        let Some(raw) = value.as_object() else {
            return Ok(None);
        };
        let field = |key: &str| -> String {
            raw.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };

        // Type：旧版允许省略（默认就是 tcp-reality），但**写了就必须是我们支持的那一种**。
        match raw.get("Type") {
            None => {}
            Some(Value::String(kind)) if kind.trim() == "tcp-reality" => {}
            Some(other) => {
                return Err(invalid_transport(&format!(
                    "服务器下发的兼容连接类型不受支持（Type={other}，本版只支持 tcp-reality）。"
                )))
            }
        }

        let server = field("Server");
        if server.is_empty() {
            return Err(invalid_transport("服务器下发的兼容连接参数缺少 Server。"));
        }
        // Server 可以是 IP 也可以是域名；两种都必须看着像个主机名，别把 URL 带进引擎。
        if server.contains("://") || server.contains('/') || server.chars().any(char::is_whitespace) {
            return Err(invalid_transport("服务器下发的兼容连接参数 Server 不是合法的主机名。"));
        }
        if server.parse::<std::net::IpAddr>().is_err() && !server.contains('.') {
            return Err(invalid_transport("服务器下发的兼容连接参数 Server 既不是 IP 也不是域名。"));
        }

        // 端口只允许 443 / 8443 / 2443：部署规划阶段就只在这三个里选（`ConnectionMethods.psm1:246`），
        // 别处给的端口说明部署和客户端不同源，连上去只会被中间设备掐掉。
        let port = match raw.get("Port") {
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
            _ => None,
        }
        .filter(|p| matches!(p, 443 | 8443 | 2443));
        let Some(port) = port else {
            return Err(invalid_transport(
                "服务器下发的兼容连接参数 Port 只能是 443 / 8443 / 2443。",
            ));
        };

        let uuid = field("Uuid");
        if !is_guid(&uuid) {
            return Err(invalid_transport("服务器下发的兼容连接参数 Uuid 不是合法的 GUID。"));
        }

        let server_name = field("ServerName");
        if server_name.is_empty() {
            return Err(invalid_transport("服务器下发的兼容连接参数缺少 ServerName。"));
        }
        if server_name.contains("://") || server_name.contains('/') || server_name.chars().any(char::is_whitespace) {
            return Err(invalid_transport("服务器下发的兼容连接参数 ServerName 不是合法的主机名。"));
        }

        let reality_public_key = field("RealityPublicKey");
        if reality_public_key.len() != 43
            || !reality_public_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(invalid_transport(
                "服务器下发的兼容连接参数 RealityPublicKey 必须是 43 位 base64url。",
            ));
        }

        // ShortId 可以省略（旧版允许空串），但给了就必须是最多 16 位的偶数长度十六进制。
        let reality_short_id = field("RealityShortId").to_ascii_lowercase();
        if reality_short_id.len() > 16
            || reality_short_id.len() % 2 != 0
            || !reality_short_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(invalid_transport(
                "服务器下发的兼容连接参数 RealityShortId 必须是最多 16 位的偶数长度十六进制。",
            ));
        }

        Ok(Some(Compatible {
            server,
            port: port as u16,
            uuid,
            server_name,
            reality_public_key,
            reality_short_id,
        }))
    }

    /// `8-4-4-4-12` 的十六进制 GUID（旧版的 `[guid]::TryParseExact(...,'D',...)`）。
    fn is_guid(value: &str) -> bool {
        value.len() == 36
            && value.char_indices().all(|(index, c)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    c == '-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
    }

    /// 兼容连接的中转出站。形状与旧版的 `New-CMConfiguration`
    /// （`ConnectionMethods.psm1:222-226`）一字不差：换形状等于换协议，服务端就不认了。
    fn transit_outbound(params: &Compatible) -> Value {
        json!({
            "type": "vless",
            "tag": engine_config::TRANSPORT_TAG,
            "server": params.server,
            "server_port": params.port,
            "uuid": params.uuid,
            // 中转服务器可能是个域名，而那时隧道还没建立：必须用直连 DNS 解析它，
            // 否则就是「要用隧道才能解析出隧道服务器」的死循环。
            "domain_resolver": { "server": "dns-direct", "strategy": "prefer_ipv4" },
            "tls": {
                "enabled": true,
                "server_name": params.server_name,
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": {
                    "enabled": true,
                    "public_key": params.reality_public_key,
                    "short_id": params.reality_short_id
                }
            }
        })
    }

    /// 引擎侧的 wireguard endpoint（旧版的 `NodeStore.psm1:1087-1091` 一字对齐）。
    ///
    /// `system` 必须是 `false`：那是「用用户态 wireguard」，`CandidateProbe.psm1:57`
    /// 明确拒绝 `system=true`（它要管理员装内核驱动，而本程序不装驱动）。
    fn wireguard_endpoint(conf: &ClientConf) -> Value {
        let peer = json!({
            "address": conf.endpoint_host,
            "port": conf.endpoint_port,
            "public_key": conf.public_key,
            "allowed_ips": conf.allowed_ips,
            "persistent_keepalive_interval": conf.persistent_keepalive,
        });
        let mut endpoint = json!({
            "type": "wireguard",
            "tag": ENDPOINT_TAG,
            "system": false,
            "address": [format!("{}/32", conf.address)],
            "private_key": conf.private_key,
            "peers": [peer],
        });
        // 服务器没给 MTU 就不写：让引擎用它自己的默认值，比替它猜一个更好。
        if let Some(mtu) = conf.mtu {
            endpoint["mtu"] = json!(mtu);
        }
        endpoint
    }

    /// 骨架：交给 `engine_config::generate` 之前的最小完整配置。
    ///
    /// 「最小」= 只写引擎非它不可的顶层键（`log` / `dns` / `outbounds` / `route` / `endpoints`）；
    /// 「不残缺」= 出站里有 `trade-exit` / `daily-exit` 两个选择器与一条 `direct`
    /// （`generate` 要按它们插路由与探测入站，`read_exits` 要按它们报出口），
    /// 路由有兜底 `final`，DNS 有一个真有实现的服务端（`local` = 用系统解析器，
    /// 不编一个可能根本不存在的 DNS 地址），`route.default_domain_resolver` 指同一个标签，
    /// 否则引擎会因为「引用了不存在的 DNS」整体起不来。
    fn skeleton(conf: &ClientConf, compatible: Option<&Compatible>, mode: Mode) -> Value {
        let mut outbounds: Vec<Value> = Vec::new();
        if let Some(params) = compatible {
            // 放在最前面，与旧版的 `@($transit)+$outbounds` 一致。
            outbounds.push(transit_outbound(params));
        }
        outbounds.push(json!({
            "type": "selector",
            "tag": engine_config::TRADE_EXIT,
            "outbounds": [ENDPOINT_TAG],
            "default": ENDPOINT_TAG,
        }));
        outbounds.push(json!({
            "type": "selector",
            "tag": engine_config::DAILY_EXIT,
            // 日常出口默认直连（旧版的 PolicyDefault），但**成员里带上本节点**：
            // 旧版的 `daily` 只有 `direct` + 代理软件的出站，而本版没有「代理软件」
            // 这类出站，只留 direct 的话界面的日常出口下拉会只有一个选项——用户没有任何
            // 办法让非交易流量走这条线路。带上节点只是多一个可选成员，默认值不动。
            "outbounds": ["direct", ENDPOINT_TAG],
            "default": "direct",
        }));
        outbounds.push(json!({ "type": "direct", "tag": "direct" }));

        // TUN 入站只有选 TUN 模式时才进骨架：`generate` 在代理模式下会把它整个丢掉，
        // 而在 TUN 模式下它必须先在文件里（参数是 旧版调好的，本程序一字不改）。
        let inbounds = match mode {
            Mode::Tun => json!([{
                "type": "tun",
                "tag": "trade-tun",
                "address": [TUN_ADDRESS],
                "mtu": conf.mtu.unwrap_or(DEFAULT_MTU),
                "auto_route": true,
                "strict_route": true,
                "stack": "gvisor",
            }]),
            Mode::Proxy => json!([]),
        };

        json!({
            "log": { "level": "warn", "timestamp": true },
            "dns": {
                // `local` = 用系统解析器：不需要编一个 DNS 地址，也不依赖任何 rule_set 文件。
                "servers": [{ "type": "local", "tag": "dns-direct" }],
                "final": "dns-direct",
                // 隧道只有 IPv4（`tunnel::render` 就只接受 IPv4）：DNS 也只问 A 记录，
                // 免得解析出 AAAA 之后一路走 IPv6 绕过隧道。
                "strategy": "ipv4_only",
            },
            "inbounds": inbounds,
            "endpoints": [wireguard_endpoint(conf)],
            "outbounds": outbounds,
            "route": {
                "rules": [],
                "final": engine_config::DAILY_EXIT,
                "auto_detect_interface": true,
                "default_domain_resolver": { "server": "dns-direct", "strategy": "prefer_ipv4" },
            },
        })
    }

    /// 生成落盘的线路文件正文（**标准档**）。
    ///
    /// `generate` 在这一步做三件我们不想重复实现的事：按模式拼入站（mixed + 自检探测）、
    /// 插「入站 → 出口」的路由规则、按当前配置焙入分流规则。与 `--import` 完全同一条路，
    /// 两条入口就不可能出现两种口径。
    pub fn build(
        conf: &ClientConf,
        compatible: Option<&Compatible>,
        port: u16,
        mode: Mode,
        split: &SplitConfig,
        agents: &crate::config::AgentsConfig,
    ) -> Result<String, PairError> {
        engine_config::validate_port(port)
            .map_err(|e| PairError::new_pub("LinePortUnavailable", &e))?;
        engine_config::validate_probe_room(port)
            .map_err(|e| PairError::new_pub("LinePortUnavailable", &e))?;
        let base = skeleton(conf, compatible, mode);
        // 出口选择传默认值（= 不动选择器自带的 default）。全局 `exits` 是「在某条线路的
        // 可选成员里挑一个」，而这条线路刚生成、成员只有自己的节点：把别的线路的选择套上来
        // 只会让 `apply_exits` 报「出口不在可选范围」——而那时邀请已经被消费掉了。
        // `agents` 也要传：`generate` 会先删掉上一轮生成的规则再按两份名单重建，
        // 只传分流会在「加入一条新线路」时把用户配好的 AI 工具名单规则漏生成。
        let text = engine_config::generate(
            &base.to_string(),
            port,
            mode,
            split,
            agents,
            &Exits::default(),
        )
        .map_err(|e| PairError::new_pub("LineGenerationFailed", &format!("生成线路配置失败：{e}")))?;
        // 兼容档的自检：**用连接时那一段代码**试派生一次。上面 `compatible()` 的逐字段校验
        // 是为了给出「哪个字段不对」的人话，这里的试派生才是权威判据——两者要是漂移了，
        // 用户会变成「加入时一切正常、切换兼容连接时才失败」，那是最难查的一种。
        // 试派生用的是内存里的一份拷贝，一个字节都不落盘。
        if compatible.is_some() {
            let mut value: Value = serde_json::from_str(&text)
                .map_err(|e| PairError::new_pub("LineGenerationFailed", &format!("线路配置无法回读：{e}")))?;
            let obj = value
                .as_object_mut()
                .ok_or_else(|| PairError::new_pub("LineGenerationFailed", "线路配置顶层必须是对象"))?;
            engine_config::apply_transport(obj, crate::config::Transport::Tcp).map_err(|e| {
                PairError::new_pub(
                    "InvalidTransport",
                    &format!("服务器下发的兼容连接参数无法用于这份线路：{e}"),
                )
            })?;
        }
        Ok(text)
    }

    /// 给新线路挑一个不与既有线路冲突的本机端口。
    ///
    /// `keep`：这条线路**自己**上一次用的端口（重试/重新加入）。必须沿用——否则用户的
    /// 系统代理设置会在重试之后指向另一个口，而那看起来就像「重试之后连不上了」。
    ///
    /// 除了「别的线路没占」，还要试绑一次 `端口+3`（自检探测端口）：绑不上的话这条线路
    /// 连上之后自检永远是「跳过」，用户看不到任何通道结论。与 `--import` 的判据同一套。
    ///
    /// **已知限制（与 `--import` 同一套判据，本轮不改行为）**：只试绑 `端口+3`，
    /// **主端口自己从未被试绑**。「别人占着 17890 主口、17893 空着」时会返回 17890，
    /// 连接时引擎的 mixed 入站绑不上，整体 FATAL。要彻底解决得在挑选阶段试绑主端口
    /// （并处理「自检端口让路」的取舍），那会改变 `--import` 的既有行为，另开一轮。
    pub fn choose_port(cfg: &AppConfig, id: &str, keep: Option<u16>) -> Result<u16, PairError> {
        choose_port_within(cfg, id, keep, port_window())
    }

    /// 扫描区间。生产固定 `FIRST_PORT..=LAST_PORT`；测试可以用
    /// [`force_port_window_for_test`] 收到一小段，避免为了构造「全被占」而塞 4.7 万条线路
    /// （那会跑两分钟，还拖慢同一个进程里的其它用例）。
    fn port_window() -> std::ops::RangeInclusive<u16> {
        #[cfg(test)]
        if let Some((first, last)) = PORT_WINDOW.with(std::cell::Cell::get) {
            return first..=last;
        }
        FIRST_PORT..=LAST_PORT
    }

    /// 真正干活的版本：区间由调用方给。跳过逻辑与终点错误与生产完全同一段代码。
    fn choose_port_within(
        cfg: &AppConfig,
        id: &str,
        keep: Option<u16>,
        range: std::ops::RangeInclusive<u16>,
    ) -> Result<u16, PairError> {
        let used: Vec<u16> = cfg
            .lines
            .iter()
            .filter(|line| line.id != id)
            .filter_map(|line| crate::selfcheck::port_from_endpoint(&line.proxy_endpoint))
            .collect();
        if let Some(port) = keep {
            // 端口本身合法、且没有别的线路在用它就**原样沿用**。这里既不重试绑 `端口+3`，
            // 也**不看扫描区间**：`--import --port 7890` 是合法配置（`validate_port` 只拒绝 0），
            // 区间只用来约束「新挑一个端口」，不该把用户已经配好的端口挪走——
            // 系统代理还指着 7890，挪走之后它指向一个没人监听的口。
            // （Q1 复核抓到的回归：这里曾经加过 `range.contains(&port)`。）
            if !used.contains(&port) && engine_config::validate_probe_room(port).is_ok() {
                return Ok(port);
            }
        }
        for port in range.clone() {
            if used.contains(&port) {
                continue;
            }
            if engine_config::validate_probe_port_free(port).is_err() {
                continue;
            }
            return Ok(port);
        }
        Err(PairError::new_pub(
            "LinePortUnavailable",
            &format!(
                "找不到可用的本机端口（{} 起的 {} 个端口都被占用），请先关掉占用这些端口的程序再重试。",
                range.start(),
                u32::from(*range.end()) - u32::from(*range.start()) + 1
            ),
        ))
    }

    /// 线路名：用户改过的 > 服务器给的节点名 > 邀请里的设备名 > 固定文案。
    ///
    /// 名字直接投影到界面上，所以顺手把控制字符换成空格、并截到 64 个字符：
    /// 一个带换行的名字会让线路卡片整块排版塌掉，而用户根本没地方改它。
    pub fn line_name(response: &Value, wanted: Option<&str>, invite_device_name: &str) -> String {
        let clean = |text: &str| -> Option<String> {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            let flat: String = trimmed
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(NAME_MAX_CHARS)
                .collect();
            let flat = flat.trim().to_string();
            (!flat.is_empty()).then_some(flat)
        };
        wanted
            .and_then(clean)
            .or_else(|| response.get("NodeName").and_then(Value::as_str).and_then(clean))
            .or_else(|| clean(invite_device_name))
            .unwrap_or_else(|| FALLBACK_NAME.to_string())
    }

    /// 从名字派生线路 id：同名 = 同一条线路（与 `--import` 一致，重复加入就是「更新」）。
    ///
    /// 不同名却撞上同一个 id（`slug` 会把大小写、标点归一）时**另起一个 id**：
    /// 覆盖别人的线路比多一条线路坏得多——用户会发现自己那条线突然指向另一台服务器。
    pub fn line_id(cfg: &AppConfig, name: &str) -> String {
        let base = config::slug(name);
        match cfg.lines.iter().find(|line| line.id == base) {
            None => base,
            Some(existing) if existing.name == name => base,
            Some(_) => {
                let mut suffix = 2u32;
                loop {
                    let candidate = format!("{base}-{suffix}");
                    if !cfg.lines.iter().any(|line| line.id == candidate) {
                        return candidate;
                    }
                    suffix += 1;
                }
            }
        }
    }

    /// 空配置：第一次接入（本机还没有 `config.json`）时用它起头。
    ///
    /// `engine` 留空——本程序不从路径猜引擎在哪，用户得自己指一次（与 `--import` 之前
    /// 的状态一样）。**不替用户打开任何开关**：自启、自动连接、关窗常驻都是 false。
    ///
    /// 两个 `true` 是**产品默认值**，不是「替用户打开」：线路变差提醒、
    /// 自动记住首次服务器身份在 旧版里就是默认开的，读到老配置也必须是开的。
    pub fn empty_config() -> AppConfig {
        AppConfig {
            schema: config::SCHEMA,
            mode: Mode::Proxy,
            auto_start: false,
            auto_connect: false,
            close_to_tray: false,
            quality_warning: true,
            auto_trust_first_connection: true,
            selected: String::new(),
            lines: Vec::new(),
            split: SplitConfig::default(),
            agents: crate::config::AgentsConfig::default(),
            exits: Exits::default(),
            engine: None,
        }
    }

    /// 写线路文件，成功后才把这条线路登记进配置。
    ///
    /// 顺序与 `pairstore`「先私钥后登记」同一条道理：**宁可留一份没人引用的文件，
    /// 也不要出现「配置里有这条线路、文件却没有」**——后者在连接时表现为引擎启动失败，
    /// 用户看到的是「连不上」，而不是「少了一份配置」。
    pub fn register(
        root: &Path,
        cfg: &mut AppConfig,
        line: &LineConfig,
        body: &str,
        origin: &crate::events::Origin,
    ) -> Result<(), PairError> {
        let path = line.engine_config_path(root);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                PairError::new_pub("LineWriteFailed", &format!("创建线路目录失败（{}）：{e}", dir.display()))
            })?;
        }
        // 先临时文件再改名：引擎读到半截 JSON 会直接崩，而用户只看到「连不上」。
        // 同时由 secretfile 收紧访问权限：线路 json 里有 WireGuard 私钥（F1）。
        crate::secretfile::write(&path, body).map_err(|e| {
            PairError::new_pub(
                "LineWriteFailed",
                &format!("写入线路文件失败（{}）：{e}", path.display()),
            )
        })?;

        if let Some(existing) = cfg.lines.iter_mut().find(|item| item.id == line.id) {
            existing.name = line.name.clone();
            existing.proxy_endpoint = line.proxy_endpoint.clone();
            existing.transport = line.transport;
        } else {
            cfg.lines.push(line.clone());
        }
        // 刚加入的线路就是用户接下来要用的那条：`--import` 也是这么做的。
        cfg.selected = line.id.clone();
        config::save_with_origin(&root.join(config::DEFAULT_PATH), cfg, origin)
            .map_err(|e| PairError::new_pub("LineConfigSaveFailed", &format!("保存线路配置失败：{e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::{AppConfig, Transport};

        #[test]
        fn sec11_wireguard_key_shape_rejects_multibyte_and_bad_padding() {
            assert!(wireguard_key(&format!("{}=", "A".repeat(43))));
            assert!(wireguard_key(&format!("{}=", "A".repeat(40) + "+/A")));
            assert!(!wireguard_key(&format!("{}😀=", "A".repeat(39))));
            assert!(!wireguard_key(&format!("{}=", "é".repeat(21) + "A")));
            assert!(!wireguard_key(&format!("{}!", "A".repeat(43))));
            assert!(!wireguard_key(&"A".repeat(44)));
            assert!(!wireguard_key("你好"));
        }

        use crate::engine_config;

        const PRIVATE: &str = "d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=";
        const SERVER_PUBLIC: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        const CLIENT_PUBLIC: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        const SERVER_UUID: &str = "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b";

        fn temp_root(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "tcrs-line-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn client_request() -> Value {
            serde_json::json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                "DeviceId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
                "CreatedAtUtc": "2026-11-02T09:00:00.000000Z",
                "ClientPublicKey": CLIENT_PUBLIC,
                "AddressFamilies": ["IPv4"],
            })
        }

        /// 服务器响应：字段取 `tunnel::render` 会逐项校验的那一套（否则渲染就过不了）。
        fn response(request: &Value) -> Value {
            serde_json::json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientResponse",
                "Status": "Authorized",
                "RequestId": request["RequestId"],
                "DeviceId": request["DeviceId"],
                "NodeId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                "NodeName": "香港 01",
                "ClientPublicKey": request["ClientPublicKey"],
                "ServerPublicKey": SERVER_PUBLIC,
                "ClientAddress": "10.66.0.2/32",
                "ServerAddress": "10.66.0.1/24",
                "TunnelSubnet": "10.66.0.0/24",
                "AllowedIPs": ["0.0.0.0/0"],
                "AddressFamilies": ["IPv4"],
                "PublicEndpoint": "203.0.113.10:18443",
                "PersistentKeepalive": 25,
                "ConfigRevision": 1,
                "MTU": 1380,
                // 老服务器给的是字符串：那不是兼容参数，只是「本版没有兼容档」。
                "Transport": "udp",
            })
        }

        fn rendered() -> String {
            super::super::tunnel::render(&response(&client_request()), PRIVATE, &client_request())
                .expect("夹具应当能渲染")
        }

        fn compatible_fixture() -> Compatible {
            Compatible {
                server: "node.example.com".to_string(),
                port: 443,
                uuid: SERVER_UUID.to_string(),
                server_name: "node.example.com".to_string(),
                reality_public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".to_string(),
                reality_short_id: "0123abcd".to_string(),
            }
        }

        /// 一个「有另一条线路占了 17890」的配置，用来验证端口不会撞。
        fn cfg_with_line(port: u16) -> AppConfig {
            let mut cfg = empty_config();
            cfg.lines.push(LineConfig {
                id: "existing".to_string(),
                name: "既有线路".to_string(),
                proxy_endpoint: format!("127.0.0.1:{port}"),
                transport: None,
                verified_transport: None,
            });
            cfg.selected = "existing".to_string();
            cfg
        }

        fn wireguard_endpoints(value: &Value) -> Vec<&Value> {
            value
                .get("endpoints")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter(|item| item.get("type").and_then(Value::as_str) == Some("wireguard"))
                        .collect()
                })
                .unwrap_or_default()
        }

        #[test]
        fn client_conf_round_trips_field_by_field() {
            let text = rendered();
            let conf = parse_client_conf(&text).expect("自己渲染的配置必须能解析回来");
            assert_eq!(conf.private_key, PRIVATE);
            assert_eq!(conf.address, "10.66.0.2");
            assert_eq!(conf.mtu, Some(1380));
            assert_eq!(conf.public_key, SERVER_PUBLIC);
            assert_eq!(conf.endpoint_host, "203.0.113.10");
            assert_eq!(conf.endpoint_port, 18443);
            assert_eq!(conf.persistent_keepalive, 25);
            assert_eq!(conf.allowed_ips, vec!["0.0.0.0/0".to_string()]);

            // 没有 MTU 的那一份：仍要能解析，且引擎侧不写这个字段。
            let mut without_mtu = response(&client_request());
            without_mtu.as_object_mut().unwrap().remove("MTU");
            let text = super::super::tunnel::render(&without_mtu, PRIVATE, &client_request()).unwrap();
            let conf = parse_client_conf(&text).unwrap();
            assert_eq!(conf.mtu, None);
            let endpoint = wireguard_endpoint(&conf);
            assert!(endpoint.get("mtu").is_none(), "服务器没给 MTU 就别替它猜：{endpoint}");
        }

        #[test]
        fn a_broken_client_conf_is_reported_not_panicked() {
            let good = rendered();
            // 44 字节、但第 43 个字节落在多字节字符中间：按字节判才是安全的（切片会 panic）。
            let multibyte_key = format!("{}é", "ä".repeat(21));
            assert_eq!(multibyte_key.len(), 44, "夹具必须是 44 字节");
            let cases: Vec<(&str, String)> = vec![
                ("缺 [Peer]", good.split("[Peer]").next().unwrap().to_string()),
                ("私钥形状", good.replace(PRIVATE, "not-a-key")),
                ("私钥含多字节字符", good.replace(PRIVATE, &multibyte_key)),
                ("地址不是 /32", good.replace("10.66.0.2/32", "10.66.0.2/24")),
                ("地址不是 IPv4", good.replace("10.66.0.2/32", "6633::2/32")),
                ("AllowedIPs", good.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8")),
                ("MTU 越界", good.replace("MTU = 1380", "MTU = 9000")),
                ("Endpoint 端口", good.replace("Endpoint = 203.0.113.10:18443", "Endpoint = 203.0.113.10")),
                ("保活间隔", good.replace("PersistentKeepalive = 25", "PersistentKeepalive = 60")),
                ("段名没闭合", good.replace("[Interface]", "[Interface")),
            ];
            for (label, text) in cases {
                let error = parse_client_conf(&text).expect_err(label);
                assert!(
                    error.code == "InvalidClientConfig",
                    "{label} 必须报 InvalidClientConfig，实际 {}",
                    error.code
                );
                assert!(
                    error.message.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                    "{label} 的错误必须是中文人话：{}",
                    error.message
                );
            }
        }

        /// 给线路加上第二个 wireguard endpoint（旧版的多节点形态）。
        ///
        /// **为什么夹具必须有两个**：「每个 endpoint 都要挂 detour」这类断言在只有一个
        /// 元素的夹具上是**测不出**「漏挂第一个」的变异（全挂 == 挂了第一个）。QA 抓到的
        /// 那次假通过就是这么来的，所以这一层判断只允许在双节点夹具上做。
        fn with_second_endpoint(text: &str) -> String {
            let mut value: Value = serde_json::from_str(text).expect("线路必须是合法 JSON");
            let mut second = value["endpoints"][0].clone();
            second["tag"] = serde_json::json!("hk-2");
            second["address"] = serde_json::json!(["10.66.0.3/32"]);
            value["endpoints"].as_array_mut().unwrap().push(second);
            // 选择器也要能选到第二个节点，否则这份夹具不像一条真线路（引擎会认不出来）。
            for outbound in value["outbounds"].as_array_mut().unwrap() {
                if outbound["tag"] == engine_config::TRADE_EXIT {
                    outbound["outbounds"] = serde_json::json!([ENDPOINT_TAG, "hk-2"]);
                }
            }
            serde_json::to_string_pretty(&value).unwrap()
        }

        #[test]
        fn the_saved_line_is_standard_and_the_compatible_tier_is_derived() {
            let root = temp_root("tiers");
            let conf = parse_client_conf(&rendered()).unwrap();
            let params = compatible_fixture();
            let single = build(&conf, Some(&params), 17_890, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            // 落盘前加第二个节点：少了一个元素，「每个」就没有意义。
            let body = with_second_endpoint(&single);
            let path = root.join("line.json");
            std::fs::write(&path, &body).unwrap();

            assert_eq!(engine_config::actual_transport(&path), Some(Transport::Udp));
            assert!(!engine_config::tcp_shaped(&body), "标准档不许长成兼容档的样子");
            // 标准档：两个 endpoint 都不许有 detour（否则就是「半个兼容档」）。
            let standard_value: Value = serde_json::from_str(&body).unwrap();
            let standard = wireguard_endpoints(&standard_value);
            assert_eq!(standard.len(), 2, "夹具必须有两个 wireguard endpoint");
            for endpoint in &standard {
                assert!(
                    endpoint.get("detour").is_none(),
                    "标准档的 endpoint 不许挂 detour：{}",
                    endpoint["tag"]
                );
            }

            // 现场派生兼容档：与连接前 `prepare_engine_config` 做的是同一件事。
            let mut value: Value = serde_json::from_str(&body).unwrap();
            let obj = value.as_object_mut().unwrap();
            assert!(engine_config::apply_transport(obj, Transport::Tcp).unwrap());
            let derived = root.join("derived.json");
            std::fs::write(&derived, serde_json::to_string(&value).unwrap()).unwrap();
            assert_eq!(engine_config::actual_transport(&derived), Some(Transport::Tcp));
            assert!(
                engine_config::tcp_shaped(&std::fs::read_to_string(&derived).unwrap()),
                "派生出来的那份必须被认成兼容档"
            );

            // **每个** wireguard endpoint 都要挂上中转——「存在一条」不算，
            // 「只挂了第一个」也不算（断言逐个落到具体 tag 上）。
            let endpoints = wireguard_endpoints(&value);
            assert_eq!(endpoints.len(), 2, "派生之后节点数不该变");
            for endpoint in &endpoints {
                assert_eq!(
                    endpoint.get("detour").and_then(Value::as_str),
                    Some(engine_config::TRANSPORT_TAG),
                    "每个 wireguard endpoint 都必须挂 detour（漏挂的 endpoint：{}）：{endpoint}",
                    endpoint["tag"]
                );
            }
            let tagged: Vec<&str> = endpoints
                .iter()
                .filter_map(|endpoint| endpoint["tag"].as_str())
                .collect();
            assert_eq!(tagged, vec!["hk", "hk-2"], "夹具的两个节点都要在：{tagged:?}");
            // 中转出站要在数组最前面（旧版是 `@($transit)+$outbounds`）。
            let outbounds = value["outbounds"].as_array().unwrap();
            assert_eq!(outbounds[0]["tag"], engine_config::TRANSPORT_TAG, "中转出站必须排在最前");
            assert_eq!(outbounds[0]["type"], "vless");
            assert_eq!(outbounds[0]["server_port"], 443);
            assert_eq!(outbounds[0]["tls"]["reality"]["short_id"], "0123abcd");
            assert_eq!(outbounds[0]["domain_resolver"]["server"], "dns-direct");
            assert_eq!(
                outbounds
                    .iter()
                    .filter(|o| o["tag"] == engine_config::TRANSPORT_TAG)
                    .count(),
                1,
                "中转出站不许重复"
            );

            // 退回标准档：detour 摘掉、中转出站删掉。
            let obj = value.as_object_mut().unwrap();
            assert!(engine_config::apply_transport(obj, Transport::Udp).unwrap());
            for endpoint in wireguard_endpoints(&value) {
                assert!(endpoint.get("detour").is_none(), "{}", endpoint["tag"]);
            }
            assert!(
                !value["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| o["tag"] == engine_config::TRANSPORT_TAG),
                "标准档不该留一条没人引用的中转出站"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// 变异保护：`detour` 只挂在**部分** endpoint 上时，`actual_transport` 必须说「不知道」。
        ///
        /// 这里的前半段**真的走 `install_transport`**（先证明它会把两个都挂上），
        /// 再手工摘掉一个去验解析——两边都盯着，才不会出现「用例只测了一半」。
        #[test]
        fn a_half_installed_detour_is_not_a_compatible_line() {
            let root = temp_root("half-detour");
            let conf = parse_client_conf(&rendered()).unwrap();
            let params = compatible_fixture();
            let single = build(&conf, Some(&params), 17_890, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let mut value: Value = serde_json::from_str(&with_second_endpoint(&single)).unwrap();

            // ① 先证明正规派生是全挂的（否则下面那半截夹具是自己手搓的假象）。
            assert!(engine_config::apply_transport(value.as_object_mut().unwrap(), Transport::Tcp).unwrap());
            let derived = root.join("derived.json");
            std::fs::write(&derived, serde_json::to_string(&value).unwrap()).unwrap();
            assert_eq!(engine_config::actual_transport(&derived), Some(Transport::Tcp));

            // ② 再摘掉其中一个 endpoint 的 detour：半个兼容档既不是标准也不是兼容。
            let endpoints = value["endpoints"].as_array_mut().unwrap();
            let victim = endpoints
                .iter_mut()
                .find(|endpoint| endpoint["tag"] == "hk-2")
                .expect("第二个节点必须在");
            victim.as_object_mut().unwrap().remove("detour");

            let path = root.join("half.json");
            std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
            assert_eq!(
                engine_config::actual_transport(&path),
                None,
                "半个 detour 不是任何一档，绝不能猜成标准或兼容"
            );
            let with_detour = wireguard_endpoints(&value)
                .into_iter()
                .filter(|e| e.get("detour").is_some())
                .count();
            let total = wireguard_endpoints(&value).len();
            assert_eq!((with_detour, total), (1, 2), "夹具形状必须准确：只挂了一个");
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn a_server_without_compatible_parameters_only_gets_the_standard_line() {
            // 字符串 `"udp"` / 字段缺失 / null 都表示「没有兼容档」，不是错误。
            for transport in [serde_json::json!("udp"), Value::Null] {
                let mut payload = response(&client_request());
                payload["Transport"] = transport;
                assert_eq!(compatible(&payload).unwrap(), None);
            }
            let mut missing = response(&client_request());
            missing.as_object_mut().unwrap().remove("Transport");
            assert_eq!(compatible(&missing).unwrap(), None);

            let conf = parse_client_conf(&rendered()).unwrap();
            let body = build(&conf, None, 17_890, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let value: Value = serde_json::from_str(&body).unwrap();
            let outbounds = value["outbounds"].as_array().unwrap();
            assert!(
                !outbounds.iter().any(|o| o["tag"] == engine_config::TRANSPORT_TAG),
                "没有兼容参数就不该写中转出站：{outbounds:?}"
            );
            // 两个选择器与直连出站必须都在：少了它们 `generate` 会插不出路由。
            for tag in [engine_config::TRADE_EXIT, engine_config::DAILY_EXIT, "direct"] {
                assert!(outbounds.iter().any(|o| o["tag"] == tag), "缺出站 {tag}：{outbounds:?}");
            }
            assert!(conforms_to_dns_contract(&value), "DNS 骨架必须自洽：{}", value["dns"]);
        }

        /// 骨架自洽：`route.default_domain_resolver` 指向的 DNS 必须真的存在，
        /// 否则引擎会整体起不来（这类错在 check 阶段才暴露，用户看不懂）。
        fn conforms_to_dns_contract(value: &Value) -> bool {
            let Some(servers) = value["dns"]["servers"].as_array() else { return false };
            let has = |tag: &str| servers.iter().any(|s| s["tag"] == tag);
            // 落盘的**标准档**线路保持原样：隧道 DNS 是运行时在 prepare 里按
            // 「有没有中转出站」加的，不写进线路文件（写了就会有指向不存在出站的引用）。
            value["dns"]["final"].as_str() == Some("dns-direct")
                && has("dns-direct")
                && value["route"]["default_domain_resolver"]["server"].as_str() == Some("dns-direct")
        }

        #[test]
        fn invalid_compatible_parameters_are_refused() {
            let base = response(&client_request());
            let with = |mutate: &dyn Fn(&mut Value)| {
                let mut payload = base.clone();
                let mut transport = serde_json::json!({
                    "Type": "tcp-reality",
                    "Server": "node.example.com",
                    "Port": 443,
                    "Uuid": SERVER_UUID,
                    "ServerName": "node.example.com",
                    "RealityPublicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    "RealityShortId": "0123abcd",
                });
                mutate(&mut transport);
                payload["Transport"] = transport;
                compatible(&payload)
            };

            // 正例先行：不合法的那些断言才有意义（否则「一律拒绝」也能全绿）。
            let ok = with(&|_| {}).expect("合法参数不该报错").expect("应当读到兼容参数");
            assert_eq!(ok.port, 443);
            assert_eq!(ok.reality_short_id, "0123abcd");

            let cases: Vec<(&str, &dyn Fn(&mut Value))> = vec![
                ("端口不在 443/8443/2443", &|t| t["Port"] = serde_json::json!(8444)),
                ("端口不是数字", &|t| t["Port"] = serde_json::json!("https")),
                ("Type 不是 tcp-reality", &|t| t["Type"] = serde_json::json!("tcp-xtls")),
                ("Type 为空", &|t| t["Type"] = serde_json::json!("")),
                ("Server 为空", &|t| t["Server"] = serde_json::json!("")),
                ("Server 是 URL", &|t| t["Server"] = serde_json::json!("https://node.example.com")),
                ("Uuid 不是 GUID", &|t| t["Uuid"] = serde_json::json!("node-1")),
                ("ServerName 为空", &|t| t["ServerName"] = serde_json::json!("")),
                ("RealityPublicKey 长度不对", &|t| t["RealityPublicKey"] = serde_json::json!("short")),
                ("RealityShortId 奇数长度", &|t| t["RealityShortId"] = serde_json::json!("abc")),
                ("RealityShortId 非十六进制", &|t| t["RealityShortId"] = serde_json::json!("zz")),
            ];
            for (label, mutate) in cases {
                let error = with(mutate).expect_err(label);
                assert_eq!(error.code, "InvalidTransport", "{label}");
                assert!(
                    error.message.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                    "{label} 的错误必须是中文人话：{}",
                    error.message
                );
            }
            // 8443 / 2443 是另外两个合法端口。
            for port in [8443u64, 2443] {
                let got = with(&|t| t["Port"] = serde_json::json!(port)).unwrap().unwrap();
                assert_eq!(got.port, port as u16);
            }
            // ShortId 可以省略（旧版允许空串）。
            let got = with(&|t| {
                t.as_object_mut().unwrap().remove("RealityShortId");
            })
            .unwrap()
            .unwrap();
            assert_eq!(got.reality_short_id, "");
        }

        #[test]
        fn a_port_used_by_another_line_is_never_reused() {
            let mut cfg = cfg_with_line(FIRST_PORT);
            // 别的线路已经占了 17890：新线路必须换一个。
            let picked = choose_port(&cfg, "new-line", None).unwrap();
            assert_ne!(picked, FIRST_PORT, "不许和既有线路撞端口");
            assert!(engine_config::validate_probe_room(picked).is_ok());

            // 同一条线路重新加入（重试）：端口必须沿用，否则系统代理会指向另一个口。
            assert_eq!(choose_port(&cfg, "existing", Some(FIRST_PORT)).unwrap(), FIRST_PORT);

            // keep 指向别人正在用的端口时不许沿用（那是被占的，不是「我们的」）。
            let other = choose_port(&cfg, "new-line", Some(FIRST_PORT)).unwrap();
            assert_ne!(other, FIRST_PORT, "别的线路占着的端口不能靠 keep 抢回来");

            // 再来一条：两条既有线路占着两个口，新线路的口不能是任何一个。
            cfg.lines.push(LineConfig {
                id: "second".to_string(),
                name: "第二条".to_string(),
                proxy_endpoint: format!("127.0.0.1:{picked}"),
                transport: None,
                verified_transport: None,
            });
            let third = choose_port(&cfg, "third", None).unwrap();
            assert_ne!(third, FIRST_PORT);
            assert_ne!(third, picked);
        }

        /// `keep` 的语义是「沿用这条线路原来的端口」，**与扫描区间无关**。
        ///
        /// 回归用例（QA/lead 复核抓到）：`--import --port 7890` 是合法配置
        /// （`validate_port` 只拒绝 0），而扫描区间是 17890..=65532。曾经在 keep 分支上
        /// 加了 `range.contains(&port)`，于是重新加入时这条线路会被**静默挪到 17890**，
        /// 而系统代理还指着 7890——指向一个没人监听的口。
        #[test]
        fn keeping_a_low_port_never_moves_it() {
            const LOW: u16 = 7_890; // 区间之外，但完全合法（--import --port 7890）
            let mut cfg = empty_config();
            cfg.lines.push(LineConfig {
                id: "low".to_string(),
                name: "低位端口线路".to_string(),
                proxy_endpoint: format!("127.0.0.1:{LOW}"),
                transport: None,
                verified_transport: None,
            });
            assert_eq!(
                choose_port(&cfg, "low", Some(LOW)).unwrap(),
                LOW,
                "同一条线路重新加入时必须沿用原端口，不许被扫描区间挪走"
            );
            // 别人占着这个口时仍然不许抢（沿用只对「我们自己的」成立）。
            cfg.lines.push(LineConfig {
                id: "other".to_string(),
                name: "另一条".to_string(),
                proxy_endpoint: format!("127.0.0.1:{LOW}"),
                transport: None,
                verified_transport: None,
            });
            let picked = choose_port(&cfg, "other", Some(LOW)).unwrap();
            assert_ne!(picked, LOW, "被别的线路占着的端口不能靠 keep 拿回来");
            assert!(picked >= FIRST_PORT, "新挑的端口仍然落在扫描区间里：{picked}");
        }

        #[test]
        fn the_line_id_never_overwrites_a_different_line() {
            let mut cfg = empty_config();
            cfg.lines.push(LineConfig {
                id: crate::config::slug("Hong Kong 01"),
                name: "Hong Kong 01".to_string(),
                proxy_endpoint: "127.0.0.1:17890".to_string(),
                transport: None,
                verified_transport: None,
            });
            // 同名 → 同一条线路（与 --import 一致：重复加入是「更新」）。
            assert_eq!(line_id(&cfg, "Hong Kong 01"), crate::config::slug("Hong Kong 01"));
            // 不同名但归一后撞了 id → 另起一个，别覆盖别人的线路。
            let other = line_id(&cfg, "hongkong01");
            assert_ne!(other, crate::config::slug("Hong Kong 01"));
            assert_eq!(other, format!("{}-2", crate::config::slug("Hong Kong 01")));
        }

        #[test]
        fn a_line_file_write_failure_leaves_the_config_untouched() {
            let root = temp_root("write-fail");
            let mut cfg = cfg_with_line(FIRST_PORT);
            crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
            // 把 `lines` 造成一个**文件**：`create_dir_all` 必然失败。
            std::fs::write(root.join("lines"), b"not a directory").unwrap();

            let new_line = LineConfig {
                id: "fresh".to_string(),
                name: "新线路".to_string(),
                proxy_endpoint: "127.0.0.1:17891".to_string(),
                transport: None,
                verified_transport: None,
            };
            let error = register(
                &root,
                &mut cfg,
                &new_line,
                "{\"outbounds\":[]}",
                &crate::events::Origin::other(),
            )
            .expect_err("线路文件写不下去时必须报错");
            assert_eq!(error.code, "LineWriteFailed");

            // 配置里绝不能留下这条线路：否则用户会看到一条「连不上」的线路。
            let saved = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
                .unwrap()
                .expect("配置还在");
            assert!(!saved.lines.iter().any(|line| line.id == "fresh"), "{:?}", saved.lines);
            assert_eq!(saved.lines.len(), 1, "既有的那条线路也不该被动");
            assert_eq!(saved.selected, "existing", "选中项同样不能被半成品改掉");
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn a_line_becomes_a_runtime_config_in_both_tiers() {
            let root = temp_root("prepare");
            let conf = parse_client_conf(&rendered()).unwrap();
            let params = compatible_fixture();
            let body = build(&conf, Some(&params), 17_895, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let path = root.join("line.json");
            std::fs::write(&path, &body).unwrap();

            for transport in [Transport::Udp, Transport::Tcp] {
                let out = root.join(format!("runtime-{}.json", transport.id()));
                let prepared = engine_config::prepare_engine_config(
                    &path,
                    &SplitConfig::default(),
                    &crate::config::AgentsConfig::default(),
                    transport,
                    Mode::Proxy,
                    &out,
                    "",
                    None,
                    None,
                )
                .expect("这份线路必须能生成引擎配置");
                let text = std::fs::read_to_string(&prepared).unwrap();
                let value: Value = serde_json::from_str(&text).unwrap();
                // 入站是我们自己的 mixed（端口来自配置），并且有兜底 final。
                assert!(
                    value["inbounds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|i| i["tag"] == engine_config::MIXED_TAG),
                    "{transport:?} 少了 mixed 入站：{}",
                    value["inbounds"]
                );
                assert_eq!(
                    engine_config::actual_transport(&prepared),
                    Some(transport),
                    "{transport:?} 的运行时配置必须还是那一档"
                );
                // 隧道 endpoint 必须活到运行时配置里：`prepare_engine_config` 只重建入站与路由，
                // 一旦把 `endpoints` 弄丢，两个选择器就指向不存在的出站，引擎直接起不来。
                let endpoints = value["endpoints"].as_array().expect("运行时配置必须有 endpoints");
                assert!(
                    endpoints.iter().any(|e| e["tag"] == ENDPOINT_TAG),
                    "{transport:?} 丢了隧道 endpoint：{}",
                    value["endpoints"]
                );
                // 入站规则要指向一个真实存在的出站，否则引擎起不来。
                let tags: Vec<&str> = value["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|o| o["tag"].as_str())
                    .collect();
                for rule in value["route"]["rules"].as_array().unwrap() {
                    if let Some(tag) = rule["outbound"].as_str() {
                        assert!(tags.contains(&tag), "规则指向了不存在的出站 {tag}：{rule}");
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn a_tun_line_only_carries_the_tun_inbound_in_tun_mode() {
            let conf = parse_client_conf(&rendered()).unwrap();
            let proxy = build(&conf, None, 17_890, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let value: Value = serde_json::from_str(&proxy).unwrap();
            assert!(
                !value["inbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["type"] == "tun"),
                "代理模式的线路文件里不该留 TUN 入站：{}",
                value["inbounds"]
            );

            let tun = build(&conf, None, 17_890, Mode::Tun, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let value: Value = serde_json::from_str(&tun).unwrap();
            let inbounds = value["inbounds"].as_array().unwrap();
            let tun_inbound = inbounds.iter().find(|i| i["type"] == "tun").expect("TUN 模式必须留 TUN 入站");
            assert_eq!(tun_inbound["interface_name"], engine_config::TUN_INTERFACE);
            assert_eq!(tun_inbound["mtu"], 1380, "MTU 取服务器给的那一个");
            assert!(
                inbounds.iter().any(|i| i["tag"] == engine_config::MIXED_TAG),
                "TUN 模式下 mixed 入站也要在：{}",
                value["inbounds"]
            );
        }

        /// 防伪：`build` 的输出必须带着引擎非它不可的那几块，不能是「看起来像」。
        #[test]
        fn the_generated_line_carries_everything_the_engine_insists_on() {
            let conf = parse_client_conf(&rendered()).unwrap();
            let body = build(&conf, None, 17_890, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let value: Value = serde_json::from_str(&body).unwrap();
            for key in ["dns", "endpoints", "inbounds", "log", "outbounds", "route"] {
                assert!(value.get(key).is_some(), "线路文件缺顶层键 {key}");
            }
            let endpoint = &wireguard_endpoints(&value)[0];
            assert_eq!(endpoint["tag"], ENDPOINT_TAG);
            assert_eq!(endpoint["system"], false, "用户态 wireguard，绝不能写 system=true");
            assert_eq!(endpoint["address"][0], "10.66.0.2/32");
            assert_eq!(endpoint["private_key"], PRIVATE);
            assert_eq!(endpoint["peers"][0]["address"], "203.0.113.10");
            assert_eq!(endpoint["peers"][0]["port"], 18443);
            assert_eq!(endpoint["peers"][0]["allowed_ips"][0], "0.0.0.0/0");
            assert_eq!(endpoint["peers"][0]["persistent_keepalive_interval"], 25);
            assert_eq!(endpoint["mtu"], 1380);
            assert!(conforms_to_dns_contract(&value));
        }

        /// 找一对「主端口 + 自检端口（+3）」都空着的端口。
        ///
        /// 不能只挑主端口：`build` 会把 `端口+3` 烤成自检入站，两个都得能绑，
        /// 否则引擎起来后自检那条入站绑不上，整体 FATAL。
        fn free_port_pair() -> u16 {
            for port in 20_000u16..30_000 {
                let Ok(main) = std::net::TcpListener::bind(("127.0.0.1", port)) else { continue };
                let Ok(probe) = std::net::TcpListener::bind(("127.0.0.1", port + 3)) else {
                    continue;
                };
                drop((main, probe));
                return port;
            }
            panic!("20000–30000 里找不到一对空闲端口");
        }

        /// 起起来的引擎必须在用例结束（含 panic）时被收掉，否则会占着端口跑一整天。
        struct EngineGuard(std::process::Child);

        impl Drop for EngineGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        /// 把一份配置交给真引擎：先 `check` 语法/初始化，再真起一次等 mixed 入站监听。
        ///
        /// `check` 只回答「配置能被解析、组件能初始化」；`run` 到端口开始监听才证明
        /// 入站真的绑上了（端口被占、权限不足这类问题只在第二步暴露）。
        /// 两步都必须过——只做 `check` 会放过「配置合法但起不来」。
        fn engine_accepts_and_listens(
            engine: &str,
            config: &std::path::Path,
            port: u16,
            label: &str,
        ) {
            // 上一档的引擎刚被收掉，端口可能还在 TIME_WAIT 里。先等它真的能绑，
            // 否则第二档会以「address in use」失败——那是测试自己的时序问题，不是配置问题。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                    drop(listener);
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    panic!("{label}：端口 {port} 在 10 秒内没有释放");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            let check = std::process::Command::new(engine)
                .args(["check", "-c"])
                .arg(config)
                .output()
                .expect("引擎应当能被执行");
            assert!(
                check.status.success(),
                "{label}：引擎拒绝了这份配置：{}",
                String::from_utf8_lossy(&check.stderr)
            );

            let child = std::process::Command::new(engine)
                .args(["run", "-c"])
                .arg(config)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("引擎应当能启动");
            let mut guard = EngineGuard(child);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while std::time::Instant::now() < deadline {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return;
                }
                if let Ok(Some(status)) = guard.0.try_wait() {
                    let mut err = String::new();
                    if let Some(mut pipe) = guard.0.stderr.take() {
                        use std::io::Read;
                        let _ = pipe.read_to_string(&mut err);
                    }
                    panic!("{label}：引擎提前退出（{status}）：{err}");
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("{label}：引擎没有在 15 秒内监听 127.0.0.1:{port}");
        }

        /// 真实引擎的验收：`build` 生成的线路文件必须**被引擎接受、并且真的起得来**。
        ///
        /// 为什么非要真引擎：字段级断言全过、引擎仍然拒绝配置的情况是存在的（类型名、必填项、
        /// DNS 引用这些由引擎自己的 schema 决定）。那种错误在用户眼里就是「点连接没反应」，
        /// 而它只有真引擎能提前发现。
        ///
        /// 三步：
        /// 1. `check -c` 校验线路文件本身；
        /// 2. 校验**连接时真正交给引擎的那一份**（`prepare_engine_config` 的产物，
        ///    带上了本次连接的探测凭据），线路文件与运行时配置是两份东西；
        /// 3. 真起一次进程，等 mixed 入站开始监听——这一步证明隧道 endpoint 能初始化
        ///    （用户态 wireguard，不需要管理员），不只是 JSON 合法。
        ///
        /// 只有设了 `SPIDERVPN_ENGINE_BIN` 才跑：引擎是外部依赖（装在 `C:\SpiderVPN\bin`），
        /// 普通 `cargo test` 不该因为没装引擎而红。
        /// **它不能替代真机握手**：没有服务器，这里只到「起得来、在监听」为止。
        #[test]
        fn the_real_engine_accepts_the_generated_line_when_one_is_available() {
            let Ok(engine) = std::env::var("SPIDERVPN_ENGINE_BIN") else {
                eprintln!("跳过：未设置 SPIDERVPN_ENGINE_BIN（真实引擎验收只在有引擎的机器上跑）");
                return;
            };
            assert!(
                std::path::Path::new(&engine).exists(),
                "SPIDERVPN_ENGINE_BIN 指向的文件不存在：{engine}"
            );

            let root = temp_root("engine");
            let conf = parse_client_conf(&rendered()).unwrap();
            let port = free_port_pair();

            // 1) 标准档：线路文件本身 → 运行时配置 → 真起一次。
            let body = build(&conf, None, port, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let line = root.join("line.json");
            std::fs::write(&line, &body).unwrap();
            engine_accepts_and_listens(&engine, &line, port, "标准档（线路文件）");
            let runtime = root.join("runtime-standard.json");
            let prepared = engine_config::prepare_engine_config(
                &line,
                &SplitConfig::default(),
                &crate::config::AgentsConfig::default(),
                Transport::Udp,
                Mode::Proxy,
                &runtime,
                "",
                Some(("tc-check", "secret")),
                Some(port + 3),
            )
            .expect("这份线路必须能生成运行时配置");
            engine_accepts_and_listens(&engine, &prepared, port, "标准档（运行时配置）");

            // 2) 兼容档：多一条 vless+REALITY 中转、endpoint 挂在 `detour` 上。
            //    这是用户点「兼容连接」之后真正交给引擎的那一份，形状与标准档完全不同，
            //    只验标准档等于放过了这条路上最可能出错的配置。
            let params = compatible_fixture();
            let body = build(&conf, Some(&params), port, Mode::Proxy, &SplitConfig::default(), &crate::config::AgentsConfig::default()).unwrap();
            let line = root.join("line-compatible.json");
            std::fs::write(&line, &body).unwrap();
            engine_accepts_and_listens(&engine, &line, port, "兼容档（线路文件）");
            let runtime = root.join("runtime-compatible.json");
            let prepared = engine_config::prepare_engine_config(
                &line,
                &SplitConfig::default(),
                &crate::config::AgentsConfig::default(),
                Transport::Tcp,
                Mode::Proxy,
                &runtime, "" ,
                Some(("tc-check", "secret")),
                Some(port + 3),
            )
            .expect("兼容档必须能生成运行时配置");
            engine_accepts_and_listens(&engine, &prepared, port, "兼容档（运行时配置）");

            let _ = std::fs::remove_dir_all(&root);
        }
    }
}

/// 一次完整的「用邀请码加入」。
///
/// 顺序是有讲究的：**先把登记写盘，再去消费邀请**。反过来的话，网络一断就会
/// 出现「服务器已记为这台设备、本机什么都没有」——那是最难收拾的状态。
pub mod join {
    use serde_json::{json, Value};
    use std::path::Path;
    use std::time::Duration;

    use crate::pairstore::{self, Enrollment, PrivateKeys};
    use crate::pairing::{client_request::ClientRequest, descriptor::Descriptor, jwk::RsaJwk};

    use super::{http, jwe, keys, line, request, tunnel, PairError};

    /// 只含公开信息与服务器签名，**不含任何私钥**，所以可以 derive Debug。
    #[derive(Debug)]
    pub struct Outcome {
        pub enrollment_id: String,
        // 接入结果的证据字段：生产侧只读 state / line_id，其余留给用例与排障核对。
        #[allow(dead_code)]
        pub invite_id: String,
        #[allow(dead_code)]
        pub node_id: String,
        /// 本机这次申请里的 **RequestId**（不是 DeviceId）。
        ///
        /// 这个字段曾经叫 `device_id`，但装的是 `request_id_of(&enrollment)`——两个 id
        /// 都会写进授权，混着叫会让人拿它们互相比对，而它们本来就是不同的值
        /// （真机日志里看到「DeviceId 与 RequestId 一模一样」就是这么来的）。
        /// 真正的设备 id 在登记记录的 `client_request["DeviceId"]` 里。
        #[allow(dead_code)]
        pub request_id: String,
        /// `Completed` = 授权已验、隧道配置与线路都已落盘。只有走到这一步才叫完成。
        pub state: String,
        /// 生成的 `client.conf` 路径。
        #[allow(dead_code)]
        pub config_path: String,
        /// 是否复用了本机已有的申请（重试路径）。
        #[allow(dead_code)]
        pub resumed: bool,
        /// 这次接入生成/更新的线路 id（`<数据根>/lines/<id>.json`）。
        pub line_id: String,
        /// 这条线路的名字（界面上显示的那一个）。
        pub line_name: String,
        /// 服务器有没有下发兼容连接参数。`false` = 这条线路只能走标准连接。
        pub supports_compatible: bool,
        #[allow(dead_code)]
        pub signed_authorization: String,
        #[allow(dead_code)]
        pub authorization: Value,
    }

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidAuthorization", message)
    }

    /// 服务器给的邀请状态 → 「这一步能不能继续」。
    ///
    /// 服务器侧的词表是 `InvitationReady` / `RetryOnly` / `Cancelled` / `Expired`
    /// （`assets/tc-pair.py::client_state`）。但**服务器上跑的那份脚本是上次
    /// `--invite-init` 上传的**，装完新版客户端后如果没重跑「开启接收服务」，对面
    /// 还是旧脚本、还会回 `Open` / `Consumed`——这两句话必须给得能照做，否则升级后
    /// 第一次试就是个无解的错误。
    ///
    /// 表外的值仍然拒绝：把不认识的状态猜成「可以继续」等于把所有状态校验作废。
    fn check_status(status: &str) -> Result<(), PairError> {
        match status {
            // 新脚本（r38 起）。
            "InvitationReady" | "RetryOnly" => Ok(()),
            // 旧脚本的 `Consumed`：语义与 `RetryOnly` 完全相同（已被用掉，只允许原
            // 申请重试），交给下游按「本机有没有原申请」给出那句准确的话。
            "Consumed" => Ok(()),
            // 旧脚本的 `Open`：这张码本身没问题，是服务器上的**脚本**还没升级。
            // 码不用换，所以出路是「让对方重开一次接收服务」，不是「重新输入」。
            "Open" => Err(PairError::new_pub(
                "InviteServerOutdated",
                "服务器上的邀请服务还是旧版本，请在管理端重新执行一次「开启接收服务」，再回来点加入。",
            )),
            "Cancelled" => Err(PairError::new_pub(
                "InviteCancelled",
                "这张邀请码已被服务器主人作废，请让对方重新生成一张。",
            )),
            "Expired" => Err(PairError::new_pub(
                "InviteExpired",
                "邀请码已过期，请让对方重新生成一张。",
            )),
            other => Err(PairError::new_pub(
                "InvalidOnlineResponse",
                &format!("服务器返回了不认识的邀请状态：{other}"),
            )),
        }
    }
    /// 与 [`run`] 同一件事，但允许界面把用户改过的线路名带进来。
    ///
    /// 页面上「线路名（可以改）」那个输入框是用户唯一能表达名字的地方；忽略它就等于
    /// 让输入框变成摆设。没给（或给了空白）时才走
    /// 「服务器节点名 → 邀请里的设备名 → 固定文案」这条链。
    ///
    /// `origin` 是这次写入的操作来源：配置落盘会记一条操作记录，来源不许在这里猜
    /// （界面、管道、命令行有各自的说法）。
    #[allow(clippy::too_many_arguments)]
    /// 加入的短名字（不知道用户想给线路起什么名字时用它，交给优先级链自己挑）。
    ///
    /// **只有用例在用**：生产侧一律走 `run_with_line_name`（命令行要能指定名字）。
    /// 放进 `cfg(test)` 是为了让 release 里不出现一个没人调用的入口。
    #[cfg(test)]
    pub fn run(
        root: &Path,
        raw_code: &str,
        device_name: &str,
        allow_loopback: bool,
        now_unix: i64,
        timeout: Duration,
    ) -> Result<Outcome, PairError> {
        run_with_line_name(
            root,
            raw_code,
            device_name,
            None,
            allow_loopback,
            now_unix,
            timeout,
            &crate::events::Origin::ui(),
        )
    }

    pub fn run_with_line_name(
        root: &Path,
        raw_code: &str,
        device_name: &str,
        wanted_line_name: Option<&str>,
        allow_loopback: bool,
        now_unix: i64,
        timeout: Duration,
        origin: &crate::events::Origin,
    ) -> Result<Outcome, PairError> {
        let code = super::parse_code(raw_code, allow_loopback, now_unix)?;
        let (status, descriptor) = super::read_invitation(raw_code, allow_loopback, timeout, now_unix)?;
        check_status(&status)?;

        let existing = pairstore::find_by_invite(root, &code.invite_id)?;
        let (enrollment, recipient_private, tunnel_private_b64, resumed) = match existing {
            Some(current) => {
                // 复用原申请前先确认「还是同一个服务器身份」：指纹变了说明这是另一台
                // 服务器用了同一个邀请 id，继续用旧申请就等于把设备交给陌生服务器。
                if current.confirmed_fingerprint != descriptor.management_fingerprint {
                    return Err(PairError::new_pub(
                        "OnlineInviteIdentityMismatch",
                        "原申请已固定另一个管理签名身份，未复用。",
                    ));
                }
                let stored = pairstore::load_private(root, &current.enrollment_id)?;
                let private = keys::recipient_from_pkcs8_b64(&stored.recipient_pkcs8_b64)?;
                // 重试时隧道私钥也要从信封里取回来：配置里写的是它。
                (current, private, stored.tunnel_private_b64, true)
            }
            None => {
                // 没有原申请却拿到 RetryOnly：说明邀请已被别的电脑消费掉了。
                if status != "InvitationReady" {
                    return Err(PairError::new_pub(
                        "InviteConsumed",
                        "邀请码已被使用；请在原申请电脑上完成接入。",
                    ));
                }
                create(root, raw_code, &code, &descriptor, device_name, now_unix)?
            }
        };

        // 提交申请并取回授权密文。
        let body = json!({ "PairRequest": enrollment.pair_request }).to_string();
        let reply = http::post_consume(&code, &body, timeout)?;
        let data = http::data(&reply)?;
        let accepted = super::authorize_reply::check(
            &data,
            &request_id_of(&enrollment),
            &enrollment.request_digest,
        )?;

        // 解封：只有本机私钥能开，开出来的还必须由邀请里固定的管理公钥签过名。
        let signed = jwe::decrypt(&accepted.encrypted_authorization, &recipient_private)?;
        let management_key = RsaJwk::parse(
            descriptor
                .invite
                .get("ManagementSigningPublicKey")
                .ok_or_else(|| invalid("邀请缺少管理签名公钥。"))?,
        )?;
        let authorization = super::jwk::verify_rs256(&signed, &management_key)
            .map_err(|_| invalid("授权签名与邀请固定的身份不一致。"))?;
        let binding = descriptor.invite.get("ServerBinding").cloned().unwrap_or(Value::Null);
        check_authorization(&authorization, &enrollment, &binding)?;

        let device_hint = descriptor
            .invite
            .get("DeviceName")
            .and_then(Value::as_str)
            .unwrap_or("");
        finish(
            root,
            &enrollment,
            &tunnel_private_b64,
            &signed,
            &authorization,
            device_hint,
            wanted_line_name,
            now_unix,
            origin,
            resumed,
        )
    }

    /// 授权已验过之后的所有落盘动作。在线加入与离线交接共用这一段：
    /// 两者只有「授权怎么拿到的」不同，生成 `client.conf`、登记线路、写配置必须同一套。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish(
        root: &Path,
        enrollment: &Enrollment,
        tunnel_private_b64: &str,
        signed: &str,
        authorization: &Value,
        device_hint: &str,
        wanted_line_name: Option<&str>,
        now_unix: i64,
        origin: &crate::events::Origin,
        resumed: bool,
    ) -> Result<Outcome, PairError> {
        pairstore::save_authorization(root, &enrollment.enrollment_id, signed, authorization)?;

        // 拿到授权不等于能用：必须把隧道配置与线路**都**真正生成出来，这一步失败就不能说自己完成。
        let response = authorization
            .get("ClientResponse")
            .ok_or_else(|| invalid("授权里缺少服务器响应，无法生成隧道配置。"))?;
        let config_text = tunnel::render(response, tunnel_private_b64, &enrollment.client_request)?;
        // 先把自己刚渲染的那份解析回来：渲染与解析对不上说明契约变了，
        // 那种错误必须在这里暴露，而不是等引擎起来之后变成「连不上」。
        let conf = line::parse_client_conf(&config_text)?;
        // 兼容参数要在写任何文件之前验完：非法就当场拒绝，别留下一条半成品线路。
        let compatible = line::compatible(response)?;

        // 线路要登记进配置，所以先把当前配置读出来（端口唯一性、分流、接管方式都在里面）。
        let cfg_path = root.join(crate::config::DEFAULT_PATH);
        let mut cfg = match crate::config::load(&cfg_path) {
            Ok(Some(cfg)) => cfg,
            Ok(None) => line::empty_config(),
            // 配置坏了不能硬写：那样会把用户其它线路一起抹掉。让它先被修好。
            Err(e) => {
                return Err(PairError::new_pub(
                    "LineConfigUnavailable",
                    &format!("读取线路配置失败（请先修好 config.json 再加入）：{e}"),
                ))
            }
        };
        let name = line::line_name(response, wanted_line_name, device_hint);
        let id = line::line_id(&cfg, &name);
        // 同一条线路重新加入（重试）时端口必须沿用，否则系统代理设置会指向另一个口。
        let keep = cfg
            .lines
            .iter()
            .find(|item| item.id == id)
            .and_then(|item| crate::selfcheck::port_from_endpoint(&item.proxy_endpoint));
        let port = line::choose_port(&cfg, &id, keep)?;
        let body_text = line::build(&conf, compatible.as_ref(), port, cfg.mode, &cfg.split, &cfg.agents)?;

        // 落盘顺序：`client.conf` → 线路文件 → 配置。每一步都「先有物、后有引用」。
        let config_path = pairstore::write_config(root, &enrollment.enrollment_id, &config_text)?;
        let new_line = crate::config::LineConfig {
            id,
            name,
            proxy_endpoint: format!("127.0.0.1:{port}"),
            // `None` = 用户还没选过连接方式（等价标准连接）。服务器给了兼容参数也不等于
            // 用户选了兼容：默认该是标准那一条（旧版的 `PolicyDefault`），
            // 由 `effective_transport()` 兜底成 Udp。
            transport: None,
            // 刚加入的线路没有任何「已验证」依据。
            verified_transport: None,
        };
        line::register(root, &mut cfg, &new_line, &body_text, origin)?;
        let completed =
            pairstore::mark_completed(root, &enrollment.enrollment_id, &super::rfc3339_micros(now_unix))?;

        Ok(Outcome {
            enrollment_id: enrollment.enrollment_id.clone(),
            invite_id: enrollment.invite_id.clone(),
            node_id: authorization
                .get("NodeId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            request_id: request_id_of(enrollment),
            state: completed.state.clone(),
            config_path: config_path.to_string_lossy().to_string(),
            resumed,
            line_id: new_line.id,
            line_name: new_line.name,
            supports_compatible: compatible.is_some(),
            signed_authorization: signed.to_string(),
            authorization: authorization.clone(),
        })
    }

    fn request_id_of(enrollment: &Enrollment) -> String {
        enrollment
            .client_request
            .get("RequestId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    /// 首次接入：生成密钥、组申请、**先写登记**，再把申请交回去。
    ///
    /// 离线交接也走这一份：申请的形状、密钥的存放、复用的判据都必须相同，
    /// 否则「在线能做、离线做不了」会变成两套协议。
    pub(super) fn create(
        root: &Path,
        raw_code: &str,
        code: &super::Invite,
        descriptor: &Descriptor,
        device_name: &str,
        now_unix: i64,
    ) -> Result<(Enrollment, rsa::RsaPrivateKey, String, bool), PairError> {
        let generated = keys::generate()?;
        let created_at = super::rfc3339_micros(now_unix);
        let client = ClientRequest {
            request_id: super::random_uuid_v4(),
            device_id: super::random_uuid_v4(),
            created_at_utc: created_at.clone(),
            client_public_key: generated.tunnel_public_b64.clone(),
        };
        let digest = client.digest()?;
        let signed = request::build(
            code,
            &descriptor.invite,
            &client,
            device_name,
            &generated.recipient_jwk,
            &generated.recipient_private,
            &created_at,
        )?;
        // 本地先验一遍：签坏了就不该发出去，更不该落盘。
        request::verify(&signed, now_unix)?;

        let enrollment = Enrollment {
            enrollment_id: super::random_uuid_v4(),
            invite_id: code.invite_id.clone(),
            invite_code: raw_code.to_string(),
            server_binding: descriptor
                .invite
                .get("ServerBinding")
                .cloned()
                .unwrap_or(Value::Null),
            management_signing_public_key: descriptor
                .invite
                .get("ManagementSigningPublicKey")
                .cloned()
                .unwrap_or(Value::Null),
            confirmed_fingerprint: descriptor.management_fingerprint.clone(),
            client_request: json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": client.request_id,
                "DeviceId": client.device_id,
                "CreatedAtUtc": client.created_at_utc,
                "ClientPublicKey": client.client_public_key,
                "AddressFamilies": ["IPv4"],
            }),
            request_digest: digest,
            pair_request: signed,
            state: pairstore::STATE_REQUESTED.to_string(),
            created_at_utc: created_at,
            completed_at_utc: None,
        };
        pairstore::save_new(
            root,
            &enrollment,
            &PrivateKeys {
                recipient_pkcs8_b64: generated.recipient_pkcs8_b64.clone(),
                tunnel_private_b64: generated.tunnel_private_b64.clone(),
            },
        )?;
        Ok((
            enrollment,
            generated.recipient_private,
            generated.tunnel_private_b64.clone(),
            false,
        ))
    }

    /// 授权体必须绑回这一份申请：换一个字段就说明这密文不是给我们的。
    ///
    /// `binding` 是邀请里那一份 `ServerBinding`（在线来自描述符，离线来自登记），
    /// 不与 `descriptor` 绑定——离线完成时手上只有登记，没有描述符。
    pub(super) fn check_authorization(
        authorization: &Value,
        enrollment: &Enrollment,
        binding: &Value,
    ) -> Result<(), PairError> {
        let text = |key: &str| authorization.get(key).and_then(Value::as_str).unwrap_or("");
        let expected_public = enrollment
            .client_request
            .get("ClientPublicKey")
            .and_then(Value::as_str)
            .unwrap_or("");
        // **v1 与 v2 都要认**。真服务器（旧版那一代）发的是 v2：
        // 公钥、地址、传输参数全部缩进 `ClientResponse` 里，顶层没有
        // `ClientPublicKey`。只认 v1 的写法会把每一份合法授权都判成
        // 「授权内容不属于本机这份申请」——真机上邀请码加入从来没成功过，
        // 而单测用的是扁平 v1，全绿。
        let nested_public = authorization
            .get("ClientResponse")
            .and_then(|response| response.get("ClientPublicKey"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let public_key = if text("ClientPublicKey").is_empty() {
            nested_public
        } else {
            text("ClientPublicKey")
        };
        let schema = authorization.get("SchemaVersion").and_then(Value::as_i64);
        // **只要求「是个正版本号」，不锁死具体数字**。
        //
        // 出事现场（2026-11-16）：服务器升到 0.23.4，授权体随时可能再跳一版；
        // 而这里的旧写法把版本写死成 1/2，一旦跳版就整份拒绝。代价不只是报错——
        // 邀请码是**一次性**的，服务器在那之前已经授权并把码消费掉了，
        // 用户会白丢一张码，还得重新去服务器上签发。
        //
        // 真正的契约不是版本号，是下面那几个绑票字段（InviteId / RequestId /
        // RequestDigest / ServerBinding / ClientPublicKey）：它们对不上就说明
        // 这份授权不是给这台机器这一次申请的。版本号只用来描述形状，
        // 而形状的兼容由「顶层取不到就取 ClientResponse 里那份」来兜。
        if !matches!(schema, Some(v) if v >= 1)
            || text("Kind") != "TradeChannel.PairAuthorization"
            || text("InviteId") != enrollment.invite_id
            || text("RequestId") != request_id_of(enrollment)
            || text("RequestDigest") != enrollment.request_digest
            || public_key != expected_public
            || text("RequestDigestAlgorithm") != "TC-ClientRequest-v1"
        {
            eprintln!(
                "AUTH_DEBUG auth={} expected_invite={} expected_request={} expected_digest={} expected_pub={}",
                authorization,
                enrollment.invite_id,
                request_id_of(enrollment),
                enrollment.request_digest,
                expected_public
            );
            return Err(PairError::new_pub(
                "OnlineAuthorizationMismatch",
                "授权内容不属于本机这份申请。",
            ));
        }
        // 绑定关系要三方一致：邀请描述符、登记、授权里的服务器标识。
        if authorization.get("ServerBinding") != Some(binding) {
            return Err(invalid("授权里的服务器绑定与邀请不一致。"));
        }
        Ok(())
    }
}

/// 离线交接：新电脑连不上 18443 时，用两次人工传递完成同一份加入。
///
/// 与在线 [`join`] 的协议完全相同，只是把两次网络往返换成两次复制粘贴：
/// 1. [`inspect`] / [`prepare`]：新电脑校验**签过名的邀请**（不是 TCI1 码），
///    在本机生成密钥与 `TradeChannel.PairRequest`；
/// 2. 管理端把申请交给服务器（`tc-pair.py authorize-request`），换回 JWE；
/// 3. [`complete`]：新电脑用本机私钥解封，生成 `client.conf` 与线路。
///
/// 邀请里**不带**客户端隧道地址：地址在管理端批准时由服务器从隧道网段分配，
/// 与旧版 旧版的离线交接一致。这样邀请过期不会占着地址，也不会出现
/// 「签了一张邀请，网段里就少一个地址」这种要回收的状态。
pub mod offline {
    use serde_json::{json, Value};
    use std::path::Path;

    use crate::pairstore::{self, Enrollment};

    use super::join::{self, Outcome};
    use super::{invite, jwe, keys, PairError, Invite};

    /// 离线邀请的公开事实：新电脑先看到这些，再决定要不要生成申请。
    #[derive(Debug, Clone)]
    pub struct Inspection {
        pub fingerprint: String,
        pub invite_id: String,
        pub device_name: String,
        pub expires_at_utc: String,
        pub node_name: String,
    }

    /// 新电脑生成好的申请。`request_text` 就是交给管理端的全部内容。
    #[derive(Debug)]
    pub struct Prepared {
        pub enrollment_id: String,
        pub invite_id: String,
        pub request_text: String,
        pub pairing_code: String,
        pub device_name: String,
        pub expires_at_utc: String,
        pub resumed: bool,
    }

    fn invalid(message: &str) -> PairError {
        PairError::new_pub("InvalidOfflineInvite", message)
    }

    /// 只校验邀请本身，不联网、不落盘。
    ///
    /// 指纹从**未验证载荷**里的公钥算出来，再用同一把公钥验签：这是「这张邀请
    /// 完整且没被改过」，不是「它来自你以为的那台服务器」。后者要靠人比对
    /// [`Inspection::fingerprint`] 与管理端显示的那一串——离线交接的信任锚就是这一步。
    pub fn inspect(compact: &str, now_unix: i64) -> Result<Inspection, PairError> {
        let unverified = invite::unverified_payload(compact)?;
        let key = super::jwk::RsaJwk::parse(
            unverified
                .get("ManagementSigningPublicKey")
                .ok_or_else(|| invalid("邀请缺少服务器公钥。"))?,
        )?;
        let fingerprint = key.fingerprint();
        let payload = invite::verify(compact, &fingerprint, now_unix)?;
        let expires_unix = invite::parse_time(payload.get("ExpiresAtUtc"))
            .ok_or_else(|| invalid("邀请有效期无效。"))?;
        Ok(Inspection {
            fingerprint,
            invite_id: text_of(&payload, "InviteId"),
            device_name: text_of(&payload, "DeviceName"),
            expires_at_utc: super::rfc3339_micros(expires_unix),
            node_name: payload
                .get("ServerBinding")
                .and_then(|binding| binding.get("NodeId"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    /// 生成（或复用）本机申请。
    ///
    /// `fingerprint` 必须是用户与管理端核对过的那一串（来自 [`inspect`] 的显示）。
    /// 同一个邀请已经申请过时复用原申请：重试不应该在服务器上变成第二台设备。
    pub fn prepare(
        root: &Path,
        compact: &str,
        fingerprint: &str,
        device_name: &str,
        now_unix: i64,
    ) -> Result<Prepared, PairError> {
        let payload = invite::verify(compact, fingerprint, now_unix)?;
        let invite_id = text_of(&payload, "InviteId");
        if invite_id.is_empty() {
            return Err(invalid("邀请缺少编号。"));
        }
        let expires_unix = invite::parse_time(payload.get("ExpiresAtUtc"))
            .ok_or_else(|| invalid("邀请有效期无效。"))?;
        let endpoint = text_of(&payload, "PublicEndpoint");
        let (host, port) = endpoint_parts(&endpoint)?;

        if let Some(existing) = pairstore::find_by_invite(root, &invite_id)? {
            if existing.confirmed_fingerprint != fingerprint {
                return Err(PairError::new_pub(
                    "InviteTrustChanged",
                    "原申请已固定另一个管理签名身份，未复用。",
                ));
            }
            if existing.state == pairstore::STATE_COMPLETED {
                return Err(PairError::new_pub(
                    "EnrollmentCompleted",
                    "这份邀请已经完成接入，不需要再生成申请。",
                ));
            }
            return Ok(Prepared {
                enrollment_id: existing.enrollment_id,
                invite_id,
                request_text: existing.pair_request,
                pairing_code: pairing_code(&existing.request_digest),
                device_name: device_name.to_string(),
                expires_at_utc: super::rfc3339_micros(expires_unix),
                resumed: true,
            });
        }

        // 与在线加入共用同一份 `create`：密钥、申请形状、登记落盘都不另写一套。
        let code = Invite {
            code: compact.to_string(),
            invite_id: invite_id.clone(),
            host,
            port,
            token: String::new(),
            // 离线邀请没有 TCI1 码里的 TLS 指纹；完整邀请本身也不带它。
            tls_sha256: String::new(),
            management_fingerprint: fingerprint.to_string(),
            expires_unix,
        };
        let descriptor = super::descriptor::Descriptor {
            invite_jwt: compact.to_string(),
            invite: payload,
            invite_id: invite_id.clone(),
            public_host: code.host.clone(),
            port: code.port,
            tls_sha256: String::new(),
            management_fingerprint: fingerprint.to_string(),
            expires_unix,
            retry_until_unix: expires_unix + 120,
        };
        let (enrollment, _recipient_private, _tunnel_private, _resumed) =
            join::create(root, compact, &code, &descriptor, device_name, now_unix)?;
        Ok(Prepared {
            enrollment_id: enrollment.enrollment_id.clone(),
            invite_id,
            request_text: enrollment.pair_request.clone(),
            pairing_code: pairing_code(&enrollment.request_digest),
            device_name: device_name.to_string(),
            expires_at_utc: super::rfc3339_micros(expires_unix),
            resumed: false,
        })
    }

    /// 导入管理端交回的加密授权，生成隧道配置与线路。
    pub fn complete(
        root: &Path,
        enrollment_id: &str,
        encrypted_authorization: &str,
        wanted_line_name: Option<&str>,
        now_unix: i64,
        origin: &crate::events::Origin,
    ) -> Result<Outcome, PairError> {
        let enrollment = pairstore::load(root, enrollment_id)?;
        if enrollment.state == pairstore::STATE_COMPLETED {
            return Err(PairError::new_pub(
                "EnrollmentCompleted",
                "这份申请已经完成接入，不需要再导入授权。",
            ));
        }
        let stored = pairstore::load_private(root, enrollment_id)?;
        let private = keys::recipient_from_pkcs8_b64(&stored.recipient_pkcs8_b64)?;
        let signed = jwe::decrypt(encrypted_authorization, &private)?;
        let management_key = super::jwk::RsaJwk::parse(&enrollment.management_signing_public_key)?;
        let authorization = super::jwk::verify_rs256(&signed, &management_key)
            .map_err(|_| PairError::new_pub("InvalidAuthorization", "授权签名与管理身份不一致。"))?;
        join::check_authorization(&authorization, &enrollment, &enrollment.server_binding)?;
        // 离线完成时手上没有邀请原文（它可能已经过期），线路名交给用户输入或
        // 服务器响应里的节点名，不用邀请里的设备名兜底。
        join::finish(
            root,
            &enrollment,
            &stored.tunnel_private_b64,
            &signed,
            &authorization,
            "",
            wanted_line_name,
            now_unix,
            origin,
            false,
        )
    }

    /// 申请摘要的前 12 位大写：与旧版「申请识别码」同一口径，人工核对用。
    /// 规则本体在 [`super::pairing_code_of`]，这里只是本模块内的短名字。
    fn pairing_code(digest: &str) -> String {
        super::pairing_code_of(digest)
    }

    fn text_of(value: &Value, key: &str) -> String {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    /// `1.2.3.4:18443` → `(host, port)`。`invite::verify` 已经验过形状，
    /// 这里只负责拆开；拆不开就说明协议漂了，照实拒绝。
    fn endpoint_parts(endpoint: &str) -> Result<(String, u16), PairError> {
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| invalid("邀请入口格式无效。"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| invalid("邀请入口端口无效。"))?;
        Ok((host.to_string(), port))
    }

    /// 只给界面用的投影：不含私钥、不含申请原文。
    pub fn prepared_view(prepared: &Prepared) -> Value {
        json!({
            "EnrollmentId": prepared.enrollment_id,
            "InviteId": prepared.invite_id,
            "PairingCode": prepared.pairing_code,
            "DeviceName": prepared.device_name,
            "ExpiresAtUtc": prepared.expires_at_utc,
            "Resumed": prepared.resumed,
        })
    }

    /// 未使用的公开字段：`Inspection` 的投影（界面只读，不做判断）。
    pub fn inspection_view(inspection: &Inspection) -> Value {
        json!({
            "Fingerprint": inspection.fingerprint,
            "InviteId": inspection.invite_id,
            "DeviceName": inspection.device_name,
            "ExpiresAtUtc": inspection.expires_at_utc,
            "NodeName": inspection.node_name,
        })
    }

    /// 编译期保证：`Enrollment` 的公开字段足够完成离线完成路径。
    #[allow(dead_code)]
    fn _assert_enrollment_shape(enrollment: &Enrollment) -> (&str, &str, &Value) {
        (
            &enrollment.enrollment_id,
            &enrollment.request_digest,
            &enrollment.server_binding,
        )
    }
}

pub fn read_invitation(
    raw_code: &str,
    allow_loopback: bool,
    timeout: std::time::Duration,
    now_unix: i64,
) -> Result<(String, descriptor::Descriptor), PairError> {
    let code = parse_code(raw_code, allow_loopback, now_unix)?;
    let reply = http::get(&code, timeout)?;
    let data = http::data(&reply)?;
    let status = data
        .get("Status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PairError::new_pub("InvalidOnlineResponse", "服务器未返回邀请状态。")
        })?
        .to_string();
    let compact = data
        .get("SignedDescriptor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PairError::new_pub("InvalidOnlineResponse", "服务器未返回签名的邀请描述。")
        })?;
    let descriptor = descriptor::verify(compact, &code, now_unix)?;
    Ok((status, descriptor))
}

/// 固定证书的 HTTPS 传输层，逐条对齐 旧版的 `PairingOnlineTransport.Request`：
/// 只走 TLS 1.2、信任锚是邀请码里的**证书 DER 指纹**（不是 CA 链）、
/// 拒绝 3xx、拒绝 chunked、必须 `Content-Type: application/json`、响应体 ≤ 128 KiB。
pub mod http {
    use super::{Invite, PairError};
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// 旧版的 `Limit`：请求体与响应体共用这个上限。
    pub const MAX_BODY: usize = 131_072;
    /// 响应头上限（旧版读头时按 16 KiB 截断）。
    const MAX_HEAD: usize = 16_384;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Reply {
        pub status: u16,
        pub body: String,
    }

    fn connection_failed() -> PairError {
        PairError::new_pub("OnlineConnectionFailed", "连不上服务器：网络不通或对方没有在监听。")
    }

    fn pin_mismatch() -> PairError {
        PairError::new_pub("OnlineTlsPinMismatch", "服务器证书与邀请码固定的指纹不一致，已中止。")
    }

    fn bad_response() -> PairError {
        PairError::new_pub("InvalidOnlineResponse", "服务器返回了无法验证的内容。")
    }

    /// 证书指纹不符要能和「网络不通」分开报：前者是安全问题，后者是环境问题。
    struct PinnedCert {
        pin: String,
        rejected: Arc<AtomicBool>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl std::fmt::Debug for PinnedCert {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("PinnedCert")
        }
    }

    impl ServerCertVerifier for PinnedCert {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            let der = end_entity.as_ref();
            // 两件事都成立才收：**逐字节**等于邀请码里的那张证书，且当前时间在有效期内。
            // 指纹相同但已过期，说明服务器该换证书了——按旧版的处理，这是拒绝。
            let same = super::jwk::sha256_hex(der) == self.pin;
            let valid = match x509_parser::parse_x509_certificate(der) {
                Ok((_, cert)) => {
                    let at = now.as_secs() as i64;
                    cert.validity().not_before.timestamp() <= at
                        && at < cert.validity().not_after.timestamp()
                }
                Err(_) => false,
            };
            if same && valid {
                return Ok(ServerCertVerified::assertion());
            }
            self.rejected.store(true, Ordering::SeqCst);
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes()
        }
    }

    /// 邀请详情（GET）。`/consume` 由 [`post_consume`] 发。
    pub fn get(invite: &Invite, timeout: Duration) -> Result<Reply, PairError> {
        send(invite, "GET", None, timeout)
    }

    /// 提交本机申请并取回授权（POST `…/consume`）。旧版不许空响应体。
    pub fn post_consume(invite: &Invite, body: &str, timeout: Duration) -> Result<Reply, PairError> {
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(PairError::new_pub("InvalidOnlineRequest", "请求体为空或过长。"));
        }
        send(invite, "POST", Some(body), timeout)
    }

    /// CLI 的善后建议必须按服务器错误码分诊：邀请码本身失效时，沿用原申请重试只会再次失败。
    /// UI 在 `check_status` 阶段另有分诊；这里只负责 `--invite-check` 等经过 `http::data` 的路径。
    pub(super) fn explain_server_code(code: &str) -> &'static str {
        match code {
            // 码本身不可用：唯一出路是让对方重新生成。建议「重试」会害人——
            // r41 真机上就验到过：把码里的 `k` 改一位得到 `Forbidden`，
            // 而当时那句建议是「重试会沿用原申请」，用户只会拿一张废码反复点。
            "Forbidden" | "InviteNotFound" | "InviteCancelled" | "InviteExpired"
            | "InviteMismatch" | "PairingMismatch" | "InvalidPairRequest" | "InvalidRequest" => {
                "这张邀请码不能再用；请让对方重新生成一张，再回来输入新的码。"
            }
            // 服务器这次没做成（改配置失败、地址用尽、记录残缺、环境缺件）：
            // 重试是对的，而且要说清重试沿用的是原申请、不会多出一台设备。
            "WireGuardApplyFailed" | "TunnelExhausted" | "InvalidState" | "ServerKeyMissing"
            | "ServerSubnetMissing" | "MissingWireGuard" | "MissingOpenSSL" | "NotInitialized" => {
                "服务器这次没处理成功；可以重试，重试会沿用原申请，不会新建设备。"
            }
            // 没见过的码不猜：保留原来那句通用说明。
            _ => "在线登记未完成；重试会沿用原申请，不会新建设备。",
        }
    }

    /// 拆 `{Ok, Code?, Data}` 信封（旧版的 `Invoke-TCPairOnlineHttp`）。
    ///
    /// 判定顺序是硬性的：先看 `Ok` 是不是布尔（不是就说明这根本不是本协议的回包），
    /// 再看 `Ok == false` 带来的服务器错误码，最后才要求 200 + 有 `Data`。
    pub fn data(reply: &Reply) -> Result<Value, PairError> {
        let envelope: Value = serde_json::from_str(&reply.body).map_err(|_| {
            PairError::new_pub("InvalidOnlineResponse", "服务器未返回可验证的登记结果。")
        })?;
        let ok = envelope.get("Ok").and_then(Value::as_bool).ok_or_else(|| {
            PairError::new_pub("InvalidOnlineResponse", "服务器未返回可验证的登记结果。")
        })?;
        if !ok {
            // 服务器自己给了码就用它（限定字符集，避免把任意文本当错误码）；
            // 没给或不合规才落到通用的 OnlineOperationFailed。
            let code = envelope
                .get("Code")
                .and_then(Value::as_str)
                .filter(|text| {
                    let bytes = text.as_bytes();
                    !bytes.is_empty()
                        && bytes.len() <= 64
                        && bytes[0].is_ascii_alphabetic()
                        && bytes.iter().all(|b| b.is_ascii_alphanumeric())
                })
                .unwrap_or("OnlineOperationFailed");
            return Err(PairError::new_pub(code, explain_server_code(code)));
        }
        if reply.status != 200 || envelope.get("Data").is_none() {
            return Err(PairError::new_pub(
                "InvalidOnlineResponse",
                "在线登记返回状态不一致。",
            ));
        }
        Ok(envelope.get("Data").cloned().unwrap_or(Value::Null))
    }

    fn send(
        invite: &Invite,
        method: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<Reply, PairError> {
        if !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&timeout) {
            return Err(PairError::new_pub("InvalidOnlineRequest", "超时取值范围是 1–60 秒。"));
        }
        let addr = format!("{}:{}", invite.host, invite.port)
            .parse()
            .map_err(|_| super::PairError::bad_host())?;
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout)
            .map_err(|_| connection_failed())?;
        stream.set_read_timeout(Some(timeout)).map_err(|_| connection_failed())?;
        stream.set_write_timeout(Some(timeout)).map_err(|_| connection_failed())?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let rejected = Arc::new(AtomicBool::new(false));
        let verifier = Arc::new(PinnedCert {
            pin: invite.tls_sha256.clone(),
            rejected: Arc::clone(&rejected),
            provider: Arc::clone(&provider),
        });
        let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(|_| connection_failed())?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let name = ServerName::try_from(invite.host.clone()).map_err(|_| super::PairError::bad_host())?;
        let connection = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|_| connection_failed())?;
        let mut tls = rustls::StreamOwned::new(connection, stream);

        let path = if method == "POST" {
            format!("/v1/invitations/{}/consume", invite.invite_id)
        } else {
            format!("/v1/invitations/{}", invite.invite_id)
        };
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
            invite.host, invite.port, invite.token
        );
        let payload = body.unwrap_or("").as_bytes();
        if method == "POST" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                payload.len()
            ));
        }
        head.push_str("\r\n");
        tls.write_all(head.as_bytes()).map_err(|_| map_io(&rejected))?;
        if !payload.is_empty() {
            tls.write_all(payload).map_err(|_| map_io(&rejected))?;
        }
        tls.flush().map_err(|_| map_io(&rejected))?;

        let mut reader = BufReader::new(tls);
        let mut status_line = Vec::new();
        read_line(&mut reader, &mut status_line, 0, &rejected)?;
        let status_text = String::from_utf8_lossy(&status_line);
        let status = parse_status(status_text.trim_end())?;
        let mut head_bytes = status_line.len();
        let mut content_length: Option<usize> = None;
        let mut content_type = String::new();
        let mut chunked = false;
        loop {
            let mut line = Vec::new();
            read_line(&mut reader, &mut line, head_bytes, &rejected)?;
            head_bytes += line.len();
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end();
            if text.is_empty() {
                break;
            }
            let (name, value) = text
                .split_once(':')
                .ok_or_else(bad_response)?;
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = true;
            } else if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(bad_response());
                }
                content_length = Some(value.parse::<usize>().map_err(|_| bad_response())?);
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type = value.to_string();
            }
        }
        if (300..400).contains(&status) {
            return Err(PairError::new_pub("OnlineRedirectRefused", "服务器要求跳转，已拒绝。"));
        }
        // 分块传输、缺长度、非 JSON 类型：一律不猜，按旧版判无效。
        if chunked || !content_type.to_ascii_lowercase().starts_with("application/json") {
            return Err(bad_response());
        }
        let length = content_length.ok_or_else(bad_response)?;
        if length > MAX_BODY {
            return Err(bad_response());
        }
        let mut body_bytes = vec![0u8; length];
        reader.read_exact(&mut body_bytes).map_err(|_| map_io(&rejected))?;
        let body = String::from_utf8(body_bytes).map_err(|_| bad_response())?;
        Ok(Reply { status, body })
    }

    fn read_line(
        reader: &mut BufReader<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>,
        into: &mut Vec<u8>,
        already: usize,
        rejected: &Arc<AtomicBool>,
    ) -> Result<(), PairError> {
        if already > MAX_HEAD {
            return Err(bad_response());
        }
        reader.read_until(b'\n', into).map_err(|_| map_io(rejected))?;
        if into.is_empty() {
            return Err(bad_response());
        }
        Ok(())
    }

    fn parse_status(line: &str) -> Result<u16, PairError> {
        let rest = line
            .strip_prefix("HTTP/1.1 ")
            .or_else(|| line.strip_prefix("HTTP/1.0 "))
            .ok_or_else(bad_response)?;
        let code = rest.get(..3).ok_or_else(bad_response)?;
        if !rest.is_char_boundary(3) {
            return Err(bad_response());
        }
        code.parse::<u16>().map_err(|_| bad_response())
    }

    fn map_io(rejected: &Arc<AtomicBool>) -> PairError {
        if rejected.load(Ordering::SeqCst) {
            pin_mismatch()
        } else {
            connection_failed()
        }
    }


    #[cfg(test)]
    mod tests {
        use super::super::test_tls::{invite_for, keypair, serve};
        use super::*;

            /// 真服务器发的是 **v2**：`ClientPublicKey` 等全在 `ClientResponse` 里，
    /// 顶层没有这个字段。旧实现只认 v1 扁平形状，于是每一份合法授权都被判成
    /// 「授权内容不属于本机这份申请」——邀请码加入在真机上从来没成功过。
    /// 这条用真实形状钉住它。
    #[test]
    fn a_v2_authorization_with_a_nested_client_response_is_accepted() {
        use crate::pairstore::Enrollment;
        let enrollment = Enrollment {
            enrollment_id: "e-1".into(),
            invite_id: "inv-1".into(),
            invite_code: "TCI1.fake".into(),
            server_binding: serde_json::json!({"NodeId": "node-1"}),
            management_signing_public_key: serde_json::Value::Null,
            confirmed_fingerprint: "SHA256:fake".into(),
            client_request: serde_json::json!({
                "SchemaVersion": 1, "Kind": "TradeChannel.ClientRequest",
                "RequestId": "req-1", "ClientPublicKey": "PUB-CLIENT",
            }),
            request_digest: "digest-1".into(),
            pair_request: String::new(),
            state: "pending".into(),
            created_at_utc: "2026-11-16T00:00:00Z".into(),
            completed_at_utc: None,
        };
        let authorization = serde_json::json!({
            "SchemaVersion": 2,
            "Kind": "TradeChannel.PairAuthorization",
            "InviteId": "inv-1",
            "RequestId": "req-1",
            "RequestDigest": "digest-1",
            "RequestDigestAlgorithm": "TC-ClientRequest-v1",
            "ServerBinding": {"NodeId": "node-1"},
            "ClientResponse": {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientResponse",
                "ClientPublicKey": "PUB-CLIENT",
            },
        });
        crate::pairing::join::check_authorization(
            &authorization,
            &enrollment,
            &serde_json::json!({"NodeId": "node-1"}),
        )
        .expect("v2 授权必须被接受");
    }

#[test]
        fn a_matching_pin_fetches_the_json_body() {
            let (cert, key) = keypair();
            let pin = crate::pairing::jwk::sha256_hex(&cert);
            let (port, server) = serve(
                cert,
                key,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"Ok\":true,\"x\":1}".to_string(),
            );
            let reply = get(&invite_for(port, pin), Duration::from_secs(5)).expect("应当成功");
            assert_eq!(reply.status, 200);
            assert_eq!(reply.body, "{\"Ok\":true,\"x\":1}");
            let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
        }

        #[test]
        fn a_foreign_certificate_is_rejected_as_a_pin_mismatch() {
            let (cert, key) = keypair();
            let (port, server) = serve(
                cert,
                key,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_string(),
            );
            // 指纹故意写错一位：必须报「指纹不一致」，不能报「连不上」。
            let wrong = "0".repeat(64);
            let error = get(&invite_for(port, wrong), Duration::from_secs(5)).unwrap_err();
            assert_eq!(error.code, "OnlineTlsPinMismatch", "{error:?}");
            let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
        }

        #[test]
        fn redirects_and_non_json_answers_are_refused() {
            let (cert, key) = keypair();
            let pin = crate::pairing::jwk::sha256_hex(&cert);
            let (port, server) = serve(cert, key, "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".to_string());
            let error = get(&invite_for(port, pin.clone()), Duration::from_secs(5)).unwrap_err();
            assert_eq!(error.code, "OnlineRedirectRefused");
            let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收

            let (cert, key) = keypair();
            let pin = crate::pairing::jwk::sha256_hex(&cert);
            let (port, server) = serve(
                cert,
                key,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}".to_string(),
            );
            let error = get(&invite_for(port, pin), Duration::from_secs(5)).unwrap_err();
            assert_eq!(error.code, "InvalidOnlineResponse");
            let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
        }
    }

    /// 服务器错误码的善后建议必须分诊。
    ///
    /// 这条盯的是一个具体的误导：`Forbidden`（码里令牌不对）、`InviteNotFound`
    /// （这台服务器上没这张码）这类码，唯一出路是**让对方重新生成一张**；
    /// 如果建议「重试会沿用原申请」，用户会拿一张废码反复点，每次都是同一个错。
    #[test]
    fn server_code_advice_separates_dead_codes_from_transient_ones() {
        let dead = super::http::explain_server_code("Forbidden");
        assert!(
            dead.contains("重新生成"),
            "码本身失效时应当让对方重新生成，实际：{dead}"
        );
        assert!(
            !dead.contains("重试会沿用原申请"),
            "码本身失效时不该建议重试（那是这台服务器没做成时的说法），实际：{dead}"
        );

        let transient = super::http::explain_server_code("WireGuardApplyFailed");
        assert!(
            transient.contains("重试"),
            "服务器这次没做成时应当建议重试，实际：{transient}"
        );
        assert!(
            transient.contains("沿用原申请"),
            "重试要说明沿用原申请、不会多出一台设备，实际：{transient}"
        );

        assert_ne!(
            dead, transient,
            "两类码的建议必须不同，否则分诊等于没做"
        );

        // 没见过的码不猜：保留通用说明，别硬塞进任何一组。
        let unknown = super::http::explain_server_code("SomeFutureCode");
        assert!(
            unknown.contains("在线登记未完成"),
            "未知码应保留通用说明，实际：{unknown}"
        );
        assert_ne!(unknown, dead, "未知码不能被当成「码失效」");
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::*;
    use base64::Engine;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::{json, Value};
    use sha2::Sha256;

    const URL_SAFE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn now() -> i64 {
        1_800_000_000
    }

    fn stamp(unix: i64) -> String {
        time::OffsetDateTime::from_unix_timestamp(unix)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    /// 测试用密钥对（2048 位够用：这里验的是签名链路，不是强度）。
    ///
    /// 只生成一次并共享：每对约一秒，逐用例重复生成会让整个套件白白慢十几秒。
    fn keypair() -> RsaPrivateKey {
        static KEY: std::sync::OnceLock<RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("生成测试密钥"))
            .clone()
    }

    /// 另一把「别人的」密钥：只用于证明外来签名会被拒。
    fn other_keypair() -> RsaPrivateKey {
        static KEY: std::sync::OnceLock<RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("生成测试密钥"))
            .clone()
    }

    fn jwk_value(key: &RsaPrivateKey) -> Value {
        let public = key.to_public_key();
        json!({
            "kty": "RSA",
            "n": URL_SAFE.encode(public.n().to_bytes_be()),
            "e": URL_SAFE.encode(public.e().to_bytes_be()),
        })
    }

    fn sign(payload: &Value, key: &RsaPrivateKey) -> String {
        let header = json!({"alg": "RS256", "typ": "JWT"});
        let head = URL_SAFE.encode(serde_json::to_vec(&header).unwrap());
        let body = URL_SAFE.encode(serde_json::to_vec(payload).unwrap());
        let signed = format!("{head}.{body}");
        let signature = SigningKey::<Sha256>::new(key.clone()).sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE.encode(signature.to_vec()))
    }

    fn invite_payload(key: &RsaPrivateKey) -> Value {
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairInvite",
            "InviteId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "RemoteOwnerId": "owner-1",
            "NodeId": "node-1",
            "ServerPublicKey": "server-key",
            "ManagementSigningPublicKey": jwk_value(key),
            "PublicEndpoint": "203.0.113.10:18443",
            "IssuedAtUtc": stamp(now() - 60),
            "ExpiresAtUtc": stamp(now() + 1800),
            "Capabilities": [],
            "ServerBinding": {"RemoteOwnerId": "owner-1", "NodeId": "node-1", "ServerPublicKey": "server-key"},
            "DeviceName": "管理电脑",
        })
    }

    #[test]
    fn a_signed_invitation_verifies_against_the_pinned_fingerprint() {
        let key = keypair();
        let compact = sign(&invite_payload(&key), &key);
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        assert!(fingerprint.starts_with("SHA256:"));
        assert_eq!(fingerprint.len(), "SHA256:".len() + 43, "指纹是 43 位无填充 base64");

        let payload = invite::verify(&compact, &fingerprint, now()).expect("应当验签通过");
        assert_eq!(payload["InviteId"], "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
    }

    #[test]
    fn an_invitation_without_the_device_name_still_verifies_like_0_23_1() {
        let key = keypair();
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        let mut payload = invite_payload(&key);
        payload.as_object_mut().unwrap().remove("DeviceName");
        let verified = invite::verify(&sign(&payload, &key), &fingerprint, now())
            .expect("旧版的邀请不带 DeviceName，必须能通过");
        assert_eq!(verified["NodeId"], "node-1");

        // 带了但不合法 → 仍是坏邀请，不能当成缺省放过去。
        let mut broken = invite_payload(&key);
        broken["DeviceName"] = json!(5);
        assert_eq!(
            invite::verify(&sign(&broken, &key), &fingerprint, now()).unwrap_err().code,
            "InvalidInvite"
        );
    }

    #[test]
    fn the_fingerprint_is_stable_no_matter_how_the_jwk_was_encoded() {
        let key = keypair();
        let plain = jwk_value(&key);
        let parsed = jwk::RsaJwk::parse(&plain).unwrap();
        // 带填充、改写大小写无关的 base64url（补 '=' 再解）都应算出同一个身份。
        let padded_n = format!("{}==", parsed.n);
        let with_padding = json!({"kty": "RSA", "n": padded_n, "e": parsed.e});
        let again = jwk::RsaJwk::parse(&with_padding).unwrap();
        assert_eq!(again.fingerprint(), parsed.fingerprint());
    }

    #[test]
    fn a_tampered_payload_or_a_foreign_key_is_rejected() {
        let key = keypair();
        let other = other_keypair();
        let good = sign(&invite_payload(&key), &key);
        let parts: Vec<&str> = good.split('.').collect();

        // 1) 换了载荷、签名不变 → 验签失败。
        let mut payload = invite_payload(&key);
        payload["NodeId"] = json!("node-2");
        let swapped = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE.encode(serde_json::to_vec(&payload).unwrap()),
            parts[2]
        );
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        assert_eq!(invite::verify(&swapped, &fingerprint, now()).unwrap_err().code, "InvalidInvite");

        // 2) 签名者不是邀请码固定的那个身份 → 在验签之前就被指纹拦下。
        let foreign = sign(&invite_payload(&other), &other);
        let error = invite::verify(&foreign, &fingerprint, now()).unwrap_err();
        assert_eq!(error.code, "InviteTrustRequired", "{error:?}");

        // 3) alg 被改成 none → 直接拒，不去「按声明算法」验。
        let header = URL_SAFE.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let unsigned = format!("{header}.{}.", parts[1]);
        assert_eq!(invite::verify(&unsigned, &fingerprint, now()).unwrap_err().code, "InvalidInvite");
    }

    #[test]
    fn expiry_and_future_issue_times_are_both_rejected() {
        let key = keypair();
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();

        let mut expired = invite_payload(&key);
        expired["ExpiresAtUtc"] = json!(stamp(now()));
        let error = invite::verify(&sign(&expired, &key), &fingerprint, now()).unwrap_err();
        assert_eq!(error.code, "InviteExpired");

        let mut future = invite_payload(&key);
        future["IssuedAtUtc"] = json!(stamp(now() + 600));
        let error = invite::verify(&sign(&future, &key), &fingerprint, now()).unwrap_err();
        assert_eq!(error.code, "InviteExpired", "签发时间在 5 分钟后的算时钟不可信");
    }

    #[test]
    fn the_invitation_endpoint_must_be_a_public_ipv4() {
        let key = keypair();
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        for endpoint in ["127.0.0.1:18443", "203.0.113.10:80", "example.com:18443", "203.0.113.010:18443"] {
            let mut payload = invite_payload(&key);
            payload["PublicEndpoint"] = json!(endpoint);
            let error = invite::verify(&sign(&payload, &key), &fingerprint, now()).unwrap_err();
            assert_eq!(error.code, "InvalidInvite", "{endpoint}");
        }
    }

    // ---- 描述符 / 设备申请 / 授权回包 的契约测试 ----

    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn code_for(key: &RsaPrivateKey, expires: i64) -> Invite {
        Invite {
            code: "TCI1.test".into(),
            invite_id: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".into(),
            host: "203.0.113.10".into(),
            port: 18443,
            token: "A".repeat(43),
            tls_sha256: PIN.to_string(),
            management_fingerprint: jwk::RsaJwk::parse(&jwk_value(key)).unwrap().fingerprint(),
            expires_unix: expires,
        }
    }

    fn descriptor_payload(key: &RsaPrivateKey, code: &Invite, invite_jwt: &str) -> Value {
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.OnlineInvite",
            "InviteId": code.invite_id,
            // 描述符自带它声称的身份：验签前先用这个公钥算指纹与邀请码比对。
            "ManagementSigningPublicKey": jwk_value(key),
            "Invite": invite_jwt,
            "PublicHost": code.host,
            "Port": code.port,
            "TlsSha256": code.tls_sha256,
            "ManagementFingerprint": code.management_fingerprint,
            "ExpiresAtUtc": stamp(code.expires_unix),
            "RetryUntilUtc": stamp(code.expires_unix + 120),
        })
    }

    fn client_for(at: &str) -> client_request::ClientRequest {
        client_request::ClientRequest {
            request_id: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".into(),
            device_id: "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d".into(),
            created_at_utc: at.into(),
            client_public_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into(),
        }
    }

    #[test]
    fn the_client_request_digest_matches_the_frozen_v1_tuple() {
        let at = "2026-11-02T09:00:00.0000000Z";
        // 期望值由独立实现（Python sha256）算出：证明字段顺序与分隔符没跑偏。
        assert_eq!(
            client_for(at).digest().unwrap(),
            "8f7ff27d234e21f7f89d4a604bf4c40ae9e2aa2f4c32a82053d357826039bb8a"
        );
        assert_eq!(client_for(at).pairing_code().unwrap(), "8F7FF27D234E");
    }

    #[test]
    fn the_digest_uses_the_exact_timestamp_string() {
        // 同一时刻、不同写法：摘要必须不同。若实现里把时间重排过，这条会挂。
        let with_zeros = client_for("2026-11-02T09:00:00.0000000Z").digest().unwrap();
        let with_offset = client_for("2026-11-02T09:00:00+00:00").digest().unwrap();
        assert_ne!(with_zeros, with_offset);
    }

    #[test]
    fn malformed_client_requests_are_rejected_before_signing() {
        let mut request = client_for("2026-11-02T09:00:00Z");
        request.client_public_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk".into();
        assert_eq!(request.digest().unwrap_err().code, "InvalidPairing", "缺 '=' 应拒");

        let mut request = client_for("2026-11-02T09:00:00Z");
        request.request_id = "9F1C2A44-0B7D-4C1E-9A2B-3C4D5E6F7A8B".into();
        assert_eq!(request.digest().unwrap_err().code, "InvalidPairing", "大写 UUID 不在契约内");

        let mut request = client_for("2026-11-02T09:00:00Z");
        request.created_at_utc = "2026/11/02 09:00".into();
        assert_eq!(request.digest().unwrap_err().code, "InvalidPairing");
    }

    #[test]
    fn a_signed_pair_request_verifies_back_with_all_its_bindings() {
        let key = keypair();
        let expires = now() + 1800;
        let code = code_for(&key, expires);
        let payload = invite_payload(&key);
        let at = "2026-11-02T09:00:00.0000000Z";
        let client = client_for(at);
        let recipient = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap();

        let signed = request::build(&code, &payload, &client, "管理电脑", &recipient, &key, at).unwrap();
        let body = request::verify(&signed, now()).unwrap();
        assert_eq!(body["Kind"], "TradeChannel.PairRequest");
        assert_eq!(body["InviteId"], code.invite_id);
        assert_eq!(body["RequestDigest"], client.digest().unwrap());
        assert_eq!(body["DeviceName"], "管理电脑");
        assert_eq!(body["ServerBinding"]["NodeId"], "node-1");

        // 设备名不合规：签名前就拒，不生成一份废申请。
        assert_eq!(
            request::build(&code, &payload, &client, " 带空格 ", &recipient, &key, at)
                .unwrap_err()
                .code,
            "InvalidDeviceName"
        );
    }

    #[test]
    fn a_tampered_pair_request_is_rejected_by_digest_or_signature() {
        let key = keypair();
        let expires = now() + 1800;
        let code = code_for(&key, expires);
        let payload = invite_payload(&key);
        let at = "2026-11-02T09:00:00.0000000Z";
        let client = client_for(at);
        let recipient = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap();
        let signed = request::build(&code, &payload, &client, "管理电脑", &recipient, &key, at).unwrap();

        // 改载荷不重签 → 验签失败。
        let parts: Vec<&str> = signed.split('.').collect();
        let mut tampered = serde_json::from_str::<Value>(
            &String::from_utf8(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        tampered["DeviceName"] = json!("另一台");
        let swapped = format!(
            "{}.{}.{}",
            parts[0],
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&tampered).unwrap()),
            parts[2]
        );
        assert_eq!(request::verify(&swapped, now()).unwrap_err().code, "InvalidPairRequest");

        // 签名有效但摘要指向别的内容 → 摘要不匹配。
        let crossed = request::build(
            &code,
            &payload,
            &client_for("2026-11-02T09:30:00.0000000Z"),
            "管理电脑",
            &recipient,
            &key,
            at,
        )
        .unwrap();
        let mut body = request::verify(&crossed, now()).unwrap();
        body["RequestDigest"] = json!(client.digest().unwrap());
        let resign = request::sign_rs256(&body, &key);
        assert_eq!(request::verify(&resign, now()).unwrap_err().code, "PairingMismatch");
    }

    #[test]
    fn a_signed_descriptor_has_to_match_the_code_field_by_field() {
        let key = keypair();
        let expires = now() + 1800;
        let code = code_for(&key, expires);
        let invite_jwt = sign(&invite_payload(&key), &key);

        let good = sign(&descriptor_payload(&key, &code, &invite_jwt), &key);
        let descriptor = descriptor::verify(&good, &code, now()).expect("应当通过");
        assert_eq!(descriptor.expires_unix, expires);
        assert_eq!(descriptor.retry_until_unix, expires + 120);
        assert_eq!(descriptor.invite_id, code.invite_id);
        assert_eq!(descriptor.invite["NodeId"], "node-1");

        // 每一项都要单独对得上；改任何一项都必须整体拒。
        let cases: [(&str, Value); 4] = [
            ("PublicHost", json!("203.0.113.99")),
            ("Port", json!(18444)),
            ("TlsSha256", json!("f".repeat(64))),
            ("RetryUntilUtc", json!(stamp(expires + 121))),
        ];
        for (field, value) in cases {
            let mut payload = descriptor_payload(&key, &code, &invite_jwt);
            payload[field] = value;
            let error = descriptor::verify(&sign(&payload, &key), &code, now()).unwrap_err();
            assert_eq!(error.code, "OnlineInviteIdentityMismatch", "{field}");
        }

        // 有效期与邀请码不一致：即使描述符自己签名有效也拒。
        let mut payload = descriptor_payload(&key, &code, &invite_jwt);
        payload["ExpiresAtUtc"] = json!(stamp(expires + 600));
        payload["RetryUntilUtc"] = json!(stamp(expires + 720));
        assert_eq!(
            descriptor::verify(&sign(&payload, &key), &code, now()).unwrap_err().code,
            "OnlineInviteIdentityMismatch"
        );
    }

    #[test]
    fn a_0_23_1_descriptor_without_its_own_key_uses_the_verified_invite_key() {
        // 旧版的服务器把管理公钥只写进邀请，描述符里没有这一项；
        // 客户端必须从已验签的邀请里取公钥，否则真机邀请一律被拒。
        let key = keypair();
        let expires = now() + 1800;
        let code = code_for(&key, expires);
        let invite_jwt = sign(&invite_payload(&key), &key);
        let mut payload = descriptor_payload(&key, &code, &invite_jwt);
        payload
            .as_object_mut()
            .unwrap()
            .remove("ManagementSigningPublicKey");
        let descriptor =
            descriptor::verify(&sign(&payload, &key), &code, now()).expect("旧版形状必须通过");
        assert_eq!(descriptor.invite_id, code.invite_id);
        assert_eq!(descriptor.invite["NodeId"], "node-1");
        assert_eq!(descriptor.expires_unix, expires);
    }

    #[test]
    fn a_descriptor_that_swaps_the_key_is_rejected() {
        let key = keypair();
        let other = other_keypair();
        let expires = now() + 1800;
        let code = code_for(&key, expires);
        let invite_jwt = sign(&invite_payload(&key), &key);

        // 签名者仍是邀请固定的身份，但描述符里自称另一把公钥：不许换钥匙。
        let mut payload = descriptor_payload(&key, &code, &invite_jwt);
        payload["ManagementSigningPublicKey"] = jwk_value(&other);
        assert_eq!(
            descriptor::verify(&sign(&payload, &key), &code, now())
                .unwrap_err()
                .code,
            "OnlineInviteIdentityMismatch"
        );

        // 旧版形状由陌生身份签名：描述符验签直接失败。
        let mut payload = descriptor_payload(&key, &code, &invite_jwt);
        payload
            .as_object_mut()
            .unwrap()
            .remove("ManagementSigningPublicKey");
        assert_eq!(
            descriptor::verify(&sign(&payload, &other), &code, now())
                .unwrap_err()
                .code,
            "OnlineInviteIdentityMismatch"
        );
    }

    #[test]
    fn a_descriptor_signed_by_a_foreign_identity_never_reaches_signature_checks() {
        let key = keypair();
        let foreign = other_keypair();
        let code = code_for(&key, now() + 1800);
        let invite_jwt = sign(&invite_payload(&key), &key);
        // 用别人的密钥签一份「自己的」描述符：指纹这一关就拦下。
        let forged = sign(&descriptor_payload(&foreign, &code, &invite_jwt), &foreign);
        assert_eq!(
            descriptor::verify(&forged, &code, now()).unwrap_err().code,
            "OnlineInviteIdentityMismatch"
        );
    }

    #[test]
    fn an_authorization_reply_must_belong_to_this_exact_request() {
        let data = json!({
            "Status": "Authorized",
            "RequestId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "RequestDigest": "8f7ff27d234e21f7f89d4a604bf4c40ae9e2aa2f4c32a82053d357826039bb8a",
            "EncryptedAuthorization": "base64-cipher",
        });
        let reply = authorize_reply::check(
            &data,
            "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "8f7ff27d234e21f7f89d4a604bf4c40ae9e2aa2f4c32a82053d357826039bb8a",
        )
        .unwrap();
        assert_eq!(reply.status, "Authorized");

        // 换申请 id、换摘要、换状态、空密文：四种都不是给本机的回包。
        for patch in [
            json!({"RequestId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"}),
            json!({"RequestDigest": "f".repeat(64)}),
            json!({"Status": "Pending"}),
            json!({"EncryptedAuthorization": ""}),
        ] {
            let mut broken = data.clone();
            for (key, value) in patch.as_object().unwrap() {
                broken[key] = value.clone();
            }
            assert_eq!(
                authorize_reply::check(
                    &broken,
                    "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                    "8f7ff27d234e21f7f89d4a604bf4c40ae9e2aa2f4c32a82053d357826039bb8a",
                )
                .unwrap_err()
                .code,
                "OnlineAuthorizationMismatch"
            );
        }
    }

    #[test]
    fn the_envelope_follows_ok_then_code_then_status() {
        let reply = |status: u16, body: &str| http::Reply {
            status,
            body: body.to_string(),
        };
        // 正常：取 Data。
        let data = http::data(&reply(200, r#"{"Ok":true,"Data":{"Status":"InvitationReady"}}"#)).unwrap();
        assert_eq!(data["Status"], "InvitationReady");

        // 服务器给了错误码：原样透传，不包装成通用失败。
        let error = http::data(&reply(
            200,
            r#"{"Ok":false,"Code":"InvitationConsumed","Data":null}"#,
        ))
        .unwrap_err();
        assert_eq!(error.code, "InvitationConsumed");

        // 码不符合字符集：退回通用码，不把任意文本当错误码往外传。
        let error = http::data(&reply(200, r#"{"Ok":false,"Code":"<script>"}"#)).unwrap_err();
        assert_eq!(error.code, "OnlineOperationFailed");

        // 缺 Ok / Ok 不是布尔：这不是本协议的回包。
        assert_eq!(
            http::data(&reply(200, r#"{"Data":{}}"#)).unwrap_err().code,
            "InvalidOnlineResponse"
        );
        assert_eq!(
            http::data(&reply(200, r#"{"Ok":"yes","Data":{}}"#)).unwrap_err().code,
            "InvalidOnlineResponse"
        );

        // 200 但没有 Data，或状态码不是 200：都不算成功。
        assert_eq!(
            http::data(&reply(200, r#"{"Ok":true}"#)).unwrap_err().code,
            "InvalidOnlineResponse"
        );
        assert_eq!(
            http::data(&reply(500, r#"{"Ok":true,"Data":{}}"#)).unwrap_err().code,
            "InvalidOnlineResponse"
        );
    }

    #[test]
    fn server_error_messages_distinguish_unusable_invites_from_retryable_failures() {
        let error_for = |code: &str| {
            let reply = http::Reply {
                status: 200,
                body: format!(r#"{{"Ok":false,"Code":"{code}","Data":null}}"#),
            };
            let error = http::data(&reply).unwrap_err();
            assert_eq!(error.code, code, "服务器错误码必须原样保留");
            error
        };

        let unusable_codes = [
            "Forbidden",
            "InviteNotFound",
            "InviteCancelled",
            "InviteExpired",
            "InviteMismatch",
            "PairingMismatch",
            "InvalidPairRequest",
            "InvalidRequest",
        ];
        let unusable_message = error_for(unusable_codes[0]).message;
        assert!(unusable_message.contains("重新生成"));
        for code in &unusable_codes[1..] {
            assert_eq!(error_for(code).message, unusable_message, "码不可用组文案漂移：{code}");
        }

        let retryable_codes = [
            "WireGuardApplyFailed",
            "TunnelExhausted",
            "InvalidState",
            "ServerKeyMissing",
            "ServerSubnetMissing",
            "MissingWireGuard",
            "MissingOpenSSL",
            "NotInitialized",
        ];
        let retryable_message = error_for(retryable_codes[0]).message;
        assert!(retryable_message.contains("重试"));
        for code in &retryable_codes[1..] {
            assert_eq!(error_for(code).message, retryable_message, "暂时失败组文案漂移：{code}");
        }

        assert_ne!(unusable_message, retryable_message, "两类错误不能给同一条善后建议");
        assert_eq!(
            error_for("InvitationConsumed").message,
            "在线登记未完成；重试会沿用原申请，不会新建设备。",
            "未列出的错误码必须保留原文案"
        );
    }

    #[test]
    fn an_invitation_is_read_over_pinned_tls_and_its_descriptor_verified() {
        // 整条读邀请链路：真 TLS + 真证书 pin + 真签名描述符。
        // 端口先绑好（邀请码要写它），响应体后填（要用端口算进描述符）。
        let (cert, tls_key) = test_tls::keypair();
        let cert_pin = jwk::sha256_hex(&cert);
        let (port, respond, server) = test_tls::serve_later_with(cert, tls_key);
        let signing = keypair();
        let expires = now() + 1800;
        let code = Invite {
            code: "TCI1.test".into(),
            invite_id: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".into(),
            host: "127.0.0.1".into(),
            port,
            token: "A".repeat(43),
            tls_sha256: cert_pin,
            management_fingerprint: jwk::RsaJwk::parse(&jwk_value(&signing))
                .unwrap()
                .fingerprint(),
            expires_unix: expires,
        };
        // pin 就是上面那张证书算出来的；换成别的证书这条用例会以指纹不符失败。
        let invite_jwt = sign(&invite_payload(&signing), &signing);
        let descriptor = descriptor_payload(&signing, &code, &invite_jwt);
        let envelope = json!({
            "Ok": true,
            "Data": {"Status": "InvitationReady", "SignedDescriptor": sign(&descriptor, &signing)},
        })
        .to_string();
        respond
            .send(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                envelope.len(),
                envelope
            ))
            .expect("服务端应当还在等响应体");

        let reply = http::get(&code, std::time::Duration::from_secs(5)).expect("应当读到回包");
        let data = http::data(&reply).expect("信封应当有效");
        assert_eq!(data["Status"], "InvitationReady");
        let verified = descriptor::verify(
            data["SignedDescriptor"].as_str().unwrap(),
            &code,
            now(),
        )
        .expect("描述符应当通过校验");
        assert_eq!(verified.invite["NodeId"], "node-1");
        let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
    }

    #[test]
    fn a_code_string_is_parsed_read_and_verified_in_one_step() {
        // 从「用户手里那串 TCI1.…」开始，走到「已验证的邀请」：中间不跳过任何环节。
        use base64::Engine;
        let (cert, tls_key) = test_tls::keypair();
        let cert_pin = jwk::sha256_hex(&cert);
        let (port, respond, server) = test_tls::serve_later_with(cert, tls_key);
        let signing = keypair();
        let expires = now() + 1800;
        let invite_id = "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b";
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&signing)).unwrap().fingerprint();
        let raw_code = format!(
            "TCI1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "v": 1, "h": "127.0.0.1", "p": port, "i": invite_id,
                    "k": "A".repeat(43), "t": cert_pin, "m": fingerprint, "e": expires,
                }))
                .unwrap()
            )
        );
        let code = parse_code(&raw_code, true, now()).expect("邀请码应当解析成功");
        let invite_jwt = sign(&invite_payload(&signing), &signing);
        let descriptor = descriptor_payload(&signing, &code, &invite_jwt);
        let envelope = json!({
            "Ok": true,
            "Data": {"Status": "InvitationReady", "SignedDescriptor": sign(&descriptor, &signing)},
        })
        .to_string();
        respond
            .send(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                envelope.len(),
                envelope
            ))
            .unwrap();

        let (status, verified) =
            read_invitation(&raw_code, true, std::time::Duration::from_secs(5), now())
                .expect("整条链路应当成功");
        assert_eq!(status, "InvitationReady");
        assert_eq!(verified.port, port);
        assert_eq!(verified.invite["DeviceName"], "管理电脑");
        let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
    }

    #[test]
    fn a_wrong_certificate_on_a_real_code_fails_as_a_pin_mismatch() {
        // 同一个邀请码，服务器换成另一张证书：必须报「指纹不一致」，不能报「连不上」。
        use base64::Engine;
        // 服务器用 A 证书，邀请码钉的是 B 证书——指纹必然不符。
        let (cert, tls_key) = test_tls::keypair();
        let (other_cert, _) = test_tls::keypair();
        let pinned = jwk::sha256_hex(&other_cert);
        let (port, respond, server) = test_tls::serve_later_with(cert, tls_key);
        let signing = keypair();
        let expires = now() + 1800;
        let raw_code = format!(
            "TCI1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "v": 1, "h": "127.0.0.1", "p": port, "i": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                    "k": "A".repeat(43), "t": pinned, "m": jwk::RsaJwk::parse(&jwk_value(&signing)).unwrap().fingerprint(),
                    "e": expires,
                }))
                .unwrap()
            )
        );
        respond
            .send("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_string())
            .unwrap();
        let error = read_invitation(&raw_code, true, std::time::Duration::from_secs(5), now())
            .unwrap_err();
        assert_eq!(error.code, "OnlineTlsPinMismatch", "{error:?}");
        let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
    }

    // ---- 授权密文（JWE 紧凑序列化）的解封 ----

    /// 测试专用的 JWE 封装器：照旧版的对端契约独立造一条紧凑序列化。
    ///
    /// 这里**另写一遍**，不复用 `jwe` 内部的实现：同一份代码既封又解，往返通过
    /// 只能证明它自洽。真正要证明的是「对端用 RFC 7518 写出来的东西能解开」，
    /// 所以封装侧必须自己算 RSA-OAEP、CBC 与 HMAC，任何一步算错都会让用例挂掉。
    fn seal_blocks(body: &[u8], key: &RsaPrivateKey, header: &Value) -> String {
        seal_to_public(body, &key.to_public_key(), header)
    }

    /// 只有对方公钥时也能封：服务器收到 `RecipientJwk` 后就是这种处境。
    fn seal_to_public(body: &[u8], public: &rsa::RsaPublicKey, header: &Value) -> String {
        use aes::cipher::block_padding::NoPadding;
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use rsa::rand_core::{OsRng, RngCore};

        assert!(
            !body.is_empty() && body.len() % 16 == 0,
            "正文必须是整数个分组，长度 {}",
            body.len()
        );
        let mut cek = [0u8; 64];
        OsRng.fill_bytes(&mut cek);
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let head = URL_SAFE.encode(serde_json::to_vec(header).unwrap());
        let wrapped = public
            .encrypt(&mut OsRng, rsa::Oaep::new::<Sha256>(), &cek)
            .expect("封装内容密钥");
        let key_b64 = URL_SAFE.encode(&wrapped);
        let mut buffer = body.to_vec();
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&cek[32..], &iv)
            .expect("CEK 后半段就是 AES-256 密钥")
            .encrypt_padded_mut::<NoPadding>(&mut buffer, body.len())
            .expect("正文已对齐")
            .to_vec();
        let aad = &head;
        let tag = {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&cek[..32]).expect("MAC key 32 字节");
            mac.update(aad.as_bytes());
            mac.update(&iv);
            mac.update(&ciphertext);
            mac.update(&((aad.len() as u64) * 8).to_be_bytes());
            mac.finalize().into_bytes()[..32].to_vec()
        };
        format!(
            "{head}.{key_b64}.{}.{}.{}",
            URL_SAFE.encode(iv),
            URL_SAFE.encode(&ciphertext),
            URL_SAFE.encode(&tag)
        )
    }

    /// PKCS#7 填充（RFC 5652）：补到分组倍数，补几个字节就填几。
    fn pad_pkcs7(plain: &[u8]) -> Vec<u8> {
        let pad = 16 - plain.len() % 16;
        let mut out = plain.to_vec();
        out.extend(std::iter::repeat(pad as u8).take(pad));
        out
    }

    /// 按旧版的`PairCrypto.Encrypt` 的头部封装一段明文。
    fn seal(plain: &str, key: &RsaPrivateKey) -> String {
        let header = json!({"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", "cty": "TC-Pairing-v1"});
        seal_blocks(&pad_pkcs7(plain.as_bytes()), key, &header)
    }

    #[test]
    fn an_encrypted_authorization_opens_with_the_pairing_key() {
        let key = keypair();
        // 内容刻意长一点、带中文与换行：往返要能穿过非 ASCII 与多个分组。
        let plain = json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairAuthorization",
            "DeviceId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
            "TunnelPrivateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----",
            "Note": "这台的隧道私钥只在本机解封；授权内容不落盘，用完即弃。",
        })
        .to_string();
        assert!(plain.len() > 200, "明文要跨多个分组，才能验到 CBC 的链式部分");

        let compact = seal(&plain, &key);
        assert_eq!(compact.split('.').count(), 5, "紧凑序列化必须是 5 段");
        assert_eq!(jwe::decrypt(&compact, &key).expect("应当能解开"), plain);

        // 别人的密钥解不开：证明 RSA-OAEP 那一步真的在认密钥，不是摆设。
        let error = jwe::decrypt(&compact, &other_keypair()).unwrap_err();
        assert_eq!(error.code, "InvalidEncryptedAuthorization");
        assert!(error.message.contains("密钥封装"), "{error:?}");
    }

    #[test]
    fn a_tampered_authorization_body_iv_or_tag_is_rejected() {
        let key = keypair();
        let compact = seal("授权内容：隧道私钥与本机标识。", &key);
        let parts: Vec<&str> = compact.split('.').collect();
        let rebuild = |index: usize, bytes: &[u8]| {
            let mut out: Vec<String> = parts.iter().map(|part| part.to_string()).collect();
            out[index] = URL_SAFE.encode(bytes);
            out.join(".")
        };

        // 正文、IV、标签各改一个字节：三者都在 MAC 的覆盖范围里，必须全拒，
        // 且都要报「完整性」——IV 不进 MAC 的话，改 IV 会变成别的错误；
        // 正文不进 MAC 的话，改正文根本不会拒。
        for (index, name) in [(3usize, "正文"), (2, "IV"), (4, "标签")] {
            let mut bytes = URL_SAFE.decode(parts[index]).unwrap();
            bytes[0] ^= 0x01;
            let error = jwe::decrypt(&rebuild(index, &bytes), &key).unwrap_err();
            assert_eq!(error.code, "InvalidEncryptedAuthorization", "{name}");
            assert!(error.message.contains("完整性"), "{name}: {error:?}");
        }

        // 反过来：密文整段换成另一条合法的密文（留给它的标签不动）同样拒。
        let other = seal("另一段内容", &key);
        let other_parts: Vec<&str> = other.split('.').collect();
        let crossed = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], other_parts[3], parts[4]
        );
        assert_eq!(
            jwe::decrypt(&crossed, &key).unwrap_err().code,
            "InvalidEncryptedAuthorization"
        );
    }

    #[test]
    fn the_envelope_algorithm_is_pinned_not_negotiated() {
        let key = keypair();
        let body = pad_pkcs7("授权内容".as_bytes());
        let header = |alg: &str, enc: &str, cty: &str| {
            json!({"alg": alg, "enc": enc, "cty": cty})
        };

        // enc 降级成 A128CBC-HS256：即便正文是合法 CBC 密文，也必须按「算法不符」拒。
        let downgraded =
            seal_blocks(&body, &key, &header("RSA-OAEP-256", "A128CBC-HS256", "TC-Pairing-v1"));
        let error = jwe::decrypt(&downgraded, &key).unwrap_err();
        assert!(error.message.contains("A256CBC-HS512"), "{error:?}");

        // alg 换成不带摘要后缀的 RSA-OAEP（历史上默认 SHA-1）：不许自适应。
        let sha1 = seal_blocks(&body, &key, &header("RSA-OAEP", "A256CBC-HS512", "TC-Pairing-v1"));
        let error = jwe::decrypt(&sha1, &key).unwrap_err();
        assert!(error.message.contains("RSA-OAEP-256"), "{error:?}");

        // cty 是别的协议：这不是给配对的信封。
        let foreign_cty =
            seal_blocks(&body, &key, &header("RSA-OAEP-256", "A256CBC-HS512", "TC-ManagementRecovery-v1"));
        let error = jwe::decrypt(&foreign_cty, &key).unwrap_err();
        assert!(error.message.contains("TC-Pairing-v1"), "{error:?}");

        // 结构：段数不是 5、某段为空、某段不是 base64url，都要在解密钥之前拒掉。
        let good = seal("授权内容", &key);
        let parts: Vec<&str> = good.split('.').collect();
        let four = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
        assert!(jwe::decrypt(&four, &key).unwrap_err().message.contains("5 段"));

        let empty_key = format!("{}.{}.{}.{}.{}", parts[0], "", parts[2], parts[3], parts[4]);
        assert!(jwe::decrypt(&empty_key, &key).unwrap_err().message.contains("第 2 段为空"));

        let not_base64 = format!("{}.{}.{}.{}.{}", parts[0], "!!!", parts[2], parts[3], parts[4]);
        assert!(jwe::decrypt(&not_base64, &key)
            .unwrap_err()
            .message
            .contains("第 2 段不是合法 base64url"));

        // 长度定死：IV 必须是 16、标签必须是 32，短一点都不行。
        let short_iv = format!("{}.{}.{}.{}.{}", parts[0], parts[1], URL_SAFE.encode(&[0u8; 8]), parts[3], parts[4]);
        assert!(jwe::decrypt(&short_iv, &key).unwrap_err().message.contains("IV"));
    }

    #[test]
    fn a_broken_tag_is_reported_differently_from_broken_padding() {
        let key = keypair();
        let compact = seal("授权内容", &key);
        let parts: Vec<&str> = compact.split('.').collect();

        // 1) 标签被动过：命中的是完整性校验。
        let mut tag = URL_SAFE.decode(parts[4]).unwrap();
        tag[31] ^= 0xff;
        let broken_tag = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            URL_SAFE.encode(&tag)
        );
        let error = jwe::decrypt(&broken_tag, &key).unwrap_err();
        assert_eq!(error.code, "InvalidEncryptedAuthorization");
        assert!(error.message.contains("完整性"), "{error:?}");

        // 2) 标签是对的（MAC 过得去）、但正文里的填充本身不合法：
        //    错在去填充这一步，句子必须指向填充，且不能与上面那条混成一句。
        let header = json!({"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", "cty": "TC-Pairing-v1"});
        let mut bad_block = [0u8; 16];
        bad_block[15] = 0x05; // 声称补了 5 个字节，可前面 4 个不是 0x05
        let bad_padding = seal_blocks(&bad_block, &key, &header);
        let error = jwe::decrypt(&bad_padding, &key).unwrap_err();
        assert_eq!(error.code, "InvalidEncryptedAuthorization");
        assert!(error.message.contains("填充"), "{error:?}");
        assert!(!error.message.contains("完整性"), "填充失败不能报成 MAC 失败：{error:?}");

        // 3) 填充长度声明为 0：RFC 5652 里 0 不合法，同样落到填充类错误。
        let mut zero_pad = [0u8; 16];
        zero_pad[15] = 0x00;
        let error = jwe::decrypt(&seal_blocks(&zero_pad, &key, &header), &key).unwrap_err();
        assert!(error.message.contains("填充长度"), "{error:?}");

        // 4) 顺序：填充不合法 **并且** 标签也不对时，报的必须是「完整性」。
        //
        //    这一条是唯一能观察到「先验 tag、后解密」的地方：CBC 解密与去填充会写
        //    同一块缓冲，只要先解密就必然先撞上填充错误，句子也就变成填充类的。
        //    若实现把两步的顺序调过来，这条会挂——而第 2 条（填充坏、标签对）不会。
        let bad_parts: Vec<&str> = bad_padding.split('.').collect();
        let mut stale_tag = URL_SAFE.decode(bad_parts[4]).unwrap();
        stale_tag[0] ^= 0xff;
        let both_broken = format!(
            "{}.{}.{}.{}.{}",
            bad_parts[0],
            bad_parts[1],
            bad_parts[2],
            bad_parts[3],
            URL_SAFE.encode(&stale_tag)
        );
        let error = jwe::decrypt(&both_broken, &key).unwrap_err();
        assert!(error.message.contains("完整性"), "先验 tag 的顺序被打乱了：{error:?}");
    }

    #[test]
    fn the_content_key_is_wiped_on_an_early_return_too() {
        // 防回归：CEK 的清零靠 `Cek::drop`，不是靠成功路径末尾那一行手动清零。
        // 这里各走一条**不同的**早退路径——验签失败、IV 长度、填充非法——每条都必须
        // 让 guard drop 恰好一次。若 guard 被去掉、或者有人把密钥 clone 出去
        // （副本不经过 Drop，清零漏在副本上），计数就对不上。
        let key = keypair();
        let header = json!({"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", "cty": "TC-Pairing-v1"});
        let good = seal("授权内容", &key);
        let parts: Vec<&str> = good.split('.').collect();

        let mut bad_tag = URL_SAFE.decode(parts[4]).unwrap();
        bad_tag[0] ^= 0xff;
        let tag_broken = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            URL_SAFE.encode(&bad_tag)
        );
        let short_iv = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE.encode(&[0u8; 8]),
            parts[3],
            parts[4]
        );
        let mut bad_block = [0u8; 16];
        bad_block[15] = 0x05;
        let bad_padding = seal_blocks(&bad_block, &key, &header);

        for (name, compact, needle) in [
            ("验签失败", tag_broken.as_str(), "完整性"),
            ("IV 长度", short_iv.as_str(), "IV"),
            ("填充非法", bad_padding.as_str(), "填充"),
        ] {
            let before = jwe::drops();
            let error = jwe::decrypt(compact, &key).unwrap_err();
            assert!(error.message.contains(needle), "{name} 走错了分支：{error:?}");
            assert_eq!(
                jwe::drops(),
                before + 1,
                "{name} 提前返回时 CEK 没经过 Drop —— 清零又被漏在异常路径上了"
            );
        }
    }

    // ---- DPAPI 信封 ----

    #[cfg(windows)]
    #[test]
    fn the_pairing_private_survives_a_dpapi_round_trip() {
        let plain = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n隧道私钥\n-----END PRIVATE KEY-----";
        let sealed = dpapi::protect(plain).expect("应当能封装");
        // 标准 base64（不是 URL 变体），且比明文长——多出来的是 DPAPI 的头。
        assert!(sealed.len() > plain.len(), "{} / {}", sealed.len(), plain.len());
        assert!(!sealed.contains('-') && !sealed.contains('_'));
        assert_eq!(dpapi::unprotect(&sealed).expect("应当能解开"), plain);

        // 空明文不是合法输入：要报错，不能产出一个空信封。
        assert_eq!(dpapi::protect("").unwrap_err().code, "PairingPrivateUnavailable");
    }

    #[cfg(windows)]
    #[test]
    fn each_dpapi_envelope_carries_fresh_randomness() {
        let plain = "同一份明文";
        let first = dpapi::protect(plain).unwrap();
        let second = dpapi::protect(plain).unwrap();
        // DPAPI 每次都会重新随机化（它自带 salt）。两次一致只能说明实现把盐钉死了，
        // 那样同样的私钥在任何机器上都产出同一份密文，等于给出一个可比对的特征。
        assert_ne!(first, second);
        assert_eq!(dpapi::unprotect(&first).unwrap(), plain);
        assert_eq!(dpapi::unprotect(&second).unwrap(), plain);
    }

    #[cfg(windows)]
    #[test]
    fn a_damaged_dpapi_envelope_is_an_error_not_a_panic() {
        let sealed = dpapi::protect("不该被解开的私钥").unwrap();

        // 1) 截断：这条路径必须返回 Err。若实现里用了 unwrap/expect，这条会直接 panic。
        let truncated = &sealed[..sealed.len() / 3];
        assert_eq!(
            dpapi::unprotect(truncated).unwrap_err().code,
            "PairingPrivateUnavailable"
        );

        // 2) 合法 base64、但内容不是信封（随便一段字节）。
        assert_eq!(
            dpapi::unprotect("QUJDREVGR0hJSktMTU5PUA==").unwrap_err().code,
            "PairingPrivateUnavailable"
        );

        // 3) 压根不是 base64，以及空串。
        assert_eq!(
            dpapi::unprotect("这不是 base64").unwrap_err().code,
            "PairingPrivateUnavailable"
        );
        assert_eq!(dpapi::unprotect("").unwrap_err().code, "PairingPrivateUnavailable");
    }

    // ---- 独立实现产出的夹具（tools/Gen-PairingFixtures.ps1）----
    //
    // 上面的 `seal_blocks` 是本仓库自己写的封装器：它和 `jwe::decrypt` 只要对 RFC 7518
    // 犯同一个理解错误，往返测试就会一起通过——那只能证明自洽。这里换成**另一套实现**
    // 产出的字节：.NET 的 RSA-OAEP-SHA256 / AES-256-CBC / HMACSHA512 按规范手工组装，
    // 与对端 jose-jwt 用同一组原语。能解开它们，才说明「别人做出来的信封」是通的。
    //
    // 夹具里的私钥是一次性的：文件头写着 test fixture，别拿去给真配对用。

    fn fixture_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pairing")
    }

    #[derive(serde::Deserialize)]
    struct JweVector {
        #[allow(dead_code)]
        name: String,
        #[serde(rename = "privateKeyPem")]
        private_key_pem: String,
        compact: String,
        expected: String,
        #[serde(default, rename = "expectedErrorCode")]
        expected_error_code: Option<String>,
        #[serde(default, rename = "keyBits")]
        key_bits: usize,
    }

    #[test]
    fn dotnet_produced_authorizations_open() {
        use rsa::pkcs8::DecodePrivateKey;

        let dir = fixture_dir();
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| {
                panic!("夹具目录读不到（{}）：{error}。跑 tools/Gen-PairingFixtures.ps1 重新生成。", dir.display())
            })
            .map(|entry| entry.expect("目录项应当可读").path())
            .filter(|path| {
                let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
                name.starts_with("dotnet-jwe-") && name.ends_with(".json")
            })
            .collect();
        files.sort();
        // 空目录不是「没有用例」，是夹具丢了：这里必须炸，不能静默跳过。
        assert!(
            files.len() >= 3,
            "至少要 3 条 .NET 生成的 JWE 向量，实际 {} 条（{}）",
            files.len(),
            dir.display()
        );

        let mut opened = 0usize;
        let mut rejected = 0usize;
        for path in &files {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("{} 读不到：{error}", path.display()));
            let vector: JweVector = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{} 不是合法向量：{error}", path.display()));
            let key =
                RsaPrivateKey::from_pkcs8_pem(&vector.private_key_pem).unwrap_or_else(|error| {
                    panic!("{} 的私钥不是合法 PKCS#8 PEM：{error}", path.display())
                });
            if vector.key_bits != 0 {
                assert_eq!(
                    key.size() * 8,
                    vector.key_bits,
                    "{} 的密钥位数与文件记录不符",
                    path.display()
                );
            }

            match jwe::decrypt(&vector.compact, &key) {
                Ok(plain) => {
                    assert!(
                        vector.expected_error_code.is_none(),
                        "{} 应当被拒（{}），却解开了",
                        path.display(),
                        vector.expected_error_code.as_deref().unwrap_or("")
                    );
                    // 逐字符相等：多一个空格、少一个换行都算没解开。
                    assert_eq!(plain, vector.expected, "{} 的明文与 .NET 侧不一致", path.display());
                    opened += 1;
                }
                Err(error) => {
                    let expected_error = vector.expected_error_code.as_deref().unwrap_or_else(|| {
                        panic!("{} 解不开（.NET 侧生成，Rust 侧应当能解）：{error:?}", path.display())
                    });
                    assert_eq!(error.code, expected_error, "{} 的错误码不对", path.display());
                    rejected += 1;
                }
            }
        }
        assert!(opened >= 3, "正向向量应当至少 3 条，实际 {opened}");
        assert!(
            rejected >= 1,
            "负向量（AL 按字节长度算的那一条）必须存在且被拒，实际 {rejected}"
        );
        assert_eq!(opened + rejected, files.len(), "每条向量都要走一个明确的分支");
    }

    #[derive(serde::Deserialize)]
    struct DpapiVector {
        #[allow(dead_code)]
        name: String,
        #[serde(rename = "protectedB64")]
        protected_b64: String,
        plain: String,
        #[serde(default, rename = "generatedOn")]
        generated_on: String,
        #[serde(default, rename = "expectedErrorCode")]
        expected_error_code: Option<String>,
    }

    #[cfg(windows)]
    #[test]
    fn dotnet_produced_dpapi_envelopes_open() {
        let dir = fixture_dir();
        let read = |name: &str| -> DpapiVector {
            let path = dir.join(name);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} 读不到：{error}", path.display()));
            serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{} 不是合法向量：{error}", path.display()))
        };

        // 1) 正向：Win32 CryptProtectData 封出来的信封，dpapi::unprotect 必须解回原文。
        let native = read("dotnet-dpapi-1.json");
        assert!(native.expected_error_code.is_none(), "正向夹具不该带 expectError");
        match dpapi::unprotect(&native.protected_b64) {
            Ok(plain) => assert_eq!(plain, native.plain, "DPAPI 解出的明文与 Win32 侧不一致"),
            Err(error) => {
                let host = format!(
                    "{}\\{}",
                    std::env::var("COMPUTERNAME").unwrap_or_default(),
                    std::env::var("USERNAME").unwrap_or_default()
                );
                // 区分两种失败：同一账户下解不开是实现的缺陷；换机器/换账户是夹具过期。
                let hint = if host.eq_ignore_ascii_case(&native.generated_on) {
                    "本机就是生成这条夹具的账户，仍然解不开：dpapi::unprotect 与 Win32 的 CryptProtectData 不兼容。"
                } else {
                    "DPAPI 信封绑定生成它的账户与机器，当前已不是同一账户：跑 tools/Gen-PairingFixtures.ps1 重新生成夹具。"
                };
                panic!(
                    "dotnet-dpapi-1.json 解不开（夹具生成于 {}，本机 {}）：{error:?}。{hint}",
                    native.generated_on, host
                );
            }
        }

        // 2) 反向：用别的熵封出来的信封必须拒——证明 ENTROPY 真的参与了密钥派生，
        //    而不是「反正都是 DPAPI，谁封的都能解」。
        let foreign = read("dotnet-dpapi-2-foreign-entropy.json");
        assert_eq!(
            foreign.expected_error_code.as_deref(),
            Some("PairingPrivateUnavailable"),
            "反向夹具应当声明期望错误码"
        );
        let error = dpapi::unprotect(&foreign.protected_b64)
            .expect_err("别的熵封出来的信封不该被解开");
        assert_eq!(error.code, "PairingPrivateUnavailable");
    }

    #[test]
    fn generated_pairing_keys_are_3072_bit_and_self_consistent() {
        let generated = shared_keys();

        // 1) 规格与旧版对齐：3072 位（模数 384 字节）。
        use rsa::traits::PublicKeyParts;
        assert_eq!(generated.recipient_private.n().bits(), keys::RSA_BITS, "不是 3072 位");
        assert_eq!(generated.recipient_private.n().to_bytes_be().len(), 384);

        // 2) JWK 与私钥是同一把：指纹往返不变。
        let reparsed = jwk::RsaJwk::parse(&jwk_value(&generated.recipient_private)).unwrap();
        assert_eq!(reparsed.fingerprint(), generated.recipient_jwk.fingerprint());

        // 3) PKCS#8 能存能读，读回来还是同一把公钥。
        let restored = keys::recipient_from_pkcs8_b64(&generated.recipient_pkcs8_b64).unwrap();
        assert_eq!(restored.to_public_key().n(), generated.recipient_private.to_public_key().n());

        // 4) 隧道密钥：clamp 过、公钥可复算、长度是 base64(32B) 的 44 位。
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&generated.tunnel_private_b64)
            .unwrap();
        assert_eq!(raw.len(), keys::TUNNEL_KEY_LEN);
        assert_eq!(raw[0] & 0b0000_0111, 0, "私钥未 clamp（低 3 位）");
        assert_eq!(raw[31] & 0b1000_0000, 0, "私钥未 clamp（最高位）");
        assert_eq!(raw[31] & 0b0100_0000, 0b0100_0000, "私钥未 clamp（次高位）");
        assert_eq!(generated.tunnel_public_b64.len(), 44);
        assert!(generated.tunnel_public_b64.ends_with('='));
        assert_eq!(
            keys::tunnel_public_from_private_b64(&generated.tunnel_private_b64).unwrap(),
            generated.tunnel_public_b64,
            "公钥必须能由私钥复算出来"
        );
    }

    /// 3072 位在 debug 下生成一次要几十秒：两条用例共用同一对，只额外造一对
    /// 用于「不会重复」的对比。三条断言共用一次生成，是这里唯一省得起的开销。
    fn shared_keys() -> &'static keys::PairingKeys {
        static KEYS: std::sync::OnceLock<keys::PairingKeys> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| keys::generate().expect("应当能生成密钥对"))
    }

    #[test]
    fn generated_keys_do_not_repeat_and_debug_never_prints_secrets() {
        let a = shared_keys();
        let b = keys::generate().expect("第二对");
        assert_ne!(a.tunnel_private_b64, b.tunnel_private_b64);
        assert_ne!(a.recipient_jwk.n, b.recipient_jwk.n);

        // 脱敏 Debug：任何一份密钥内容都不许出现在调试输出里。
        let printed = format!("{a:?}");
        assert!(!printed.contains(&a.tunnel_private_b64), "Debug 打印了隧道私钥：{printed}");
        assert!(!printed.contains(&a.recipient_pkcs8_b64), "Debug 打印了接收私钥：{printed}");
        assert!(printed.contains(&a.tunnel_public_b64), "公开部分应当可见：{printed}");
    }

    // ---- 「用邀请码加入」端到端：本地假服务器按服务端契约应答 ----

    /// 假服务器的一段应答。状态与字段名照 `linux/pairing_online.py`：
    /// GET 只有 `InvitationReady` / `RetryOnly`，POST 成功是 `Authorized`。
    fn envelope_ok(data: Value) -> String {
        let body = json!({"Ok": true, "Data": data}).to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    /// 假服务器要按「这次申请」生成授权，所以必须从原始请求里取正文。
    fn request_body(raw: &str) -> String {
        raw.split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
            .unwrap_or_default()
    }

    /// 组装假服务器的授权载荷。字段照 `Assert-TCPairAuthorization` 的最小可用集，
    /// 关键是四项绑定：InviteId / RequestId / RequestDigest / ClientPublicKey。
    ///
    /// `transport` 原样塞进 `ClientResponse.Transport`：
    /// - `json!("udp")`：老服务器/没有兼容档（默认）；
    /// - `json!({...})`：一份 `tcp-reality` 参数，用来验证兼容档真的落到线路文件里。
    fn authorization_for(payload: &Value, now_unix: i64) -> Value {
        authorization_with_transport(payload, now_unix, json!("udp"))
    }

    fn authorization_with_transport(payload: &Value, now_unix: i64, transport: Value) -> Value {
        let inner = payload.get("ClientRequest").cloned().unwrap_or(Value::Null);
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairAuthorization",
            "InviteId": payload.get("InviteId").cloned().unwrap_or(Value::Null),
            "ServerBinding": payload.get("ServerBinding").cloned().unwrap_or(Value::Null),
            "RemoteOwnerId": "owner-1",
            "NodeId": "node-1",
            "DeviceId": inner.get("DeviceId").cloned().unwrap_or(Value::Null),
            "ClientPublicKey": inner.get("ClientPublicKey").cloned().unwrap_or(Value::Null),
            "ClientAddress": "10.66.0.2/32",
            "ConfigRevision": 1,
            "ClientResponse": {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientResponse",
                "Status": "Authorized",
                "RequestId": inner.get("RequestId").cloned().unwrap_or(Value::Null),
                "DeviceId": inner.get("DeviceId").cloned().unwrap_or(Value::Null),
                "NodeId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
                "NodeName": "香港 01",
                "ClientPublicKey": inner.get("ClientPublicKey").cloned().unwrap_or(Value::Null),
                "ServerPublicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                "ClientAddress": "10.66.0.2/32",
                "ServerAddress": "10.66.0.1/24",
                "TunnelSubnet": "10.66.0.0/24",
                "AllowedIPs": ["0.0.0.0/0"],
                "AddressFamilies": ["IPv4"],
                "PublicEndpoint": "203.0.113.10:18443",
                "PersistentKeepalive": 25,
                "ConfigRevision": 1,
                "Transport": transport,
            },
            "IssuedAtUtc": stamp(now_unix),
            "ExpiresAtUtc": stamp(now_unix + 3600),
            "RequestDigest": payload.get("RequestDigest").cloned().unwrap_or(Value::Null),
            "RequestDigestAlgorithm": "TC-ClientRequest-v1",
            "RequestId": inner.get("RequestId").cloned().unwrap_or(Value::Null),
        })
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tcrs-join-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 起一个只服务一次加入流程的假服务器。
    ///
    /// `status` 是 GET 返回的状态；`signer` 决定授权由谁签名（默认就是管理身份，
    /// 传别人的密钥用于「外来签名必须被拒」）。
    fn start_join_server(
        status: &'static str,
        signer: Option<RsaPrivateKey>,
        management: &RsaPrivateKey,
        now_unix: i64,
        max_requests: usize,
    ) -> (u16, String, std::thread::JoinHandle<()>) {
        start_join_server_with(
            status,
            signer,
            management,
            now_unix,
            max_requests,
            json!("udp"),
        )
    }

    /// 同上，但由调用方决定服务器下发哪一份 `Transport`
    /// （字符串 `"udp"` = 没有兼容档；对象 = 一份 tcp-reality 参数）。
    fn start_join_server_with(
        status: &'static str,
        signer: Option<RsaPrivateKey>,
        management: &RsaPrivateKey,
        now_unix: i64,
        max_requests: usize,
        transport: Value,
    ) -> (u16, String, std::thread::JoinHandle<()>) {
        use base64::Engine;
        let (cert, tls_key) = test_tls::keypair();
        let pin = jwk::sha256_hex(&cert);
        let listener = test_tls::bind_local();
        let port = listener.local_addr().unwrap().port();

        let mut code = code_for(management, now_unix + 1800);
        code.host = "127.0.0.1".into();
        code.port = port;
        // 描述符里的证书指纹必须就是这张证书的：夹具默认值只是占位。
        code.tls_sha256 = pin.clone();
        let invite_jwt = sign(&invite_payload(management), management);
        let descriptor = sign(&descriptor_payload(management, &code, &invite_jwt), management);

        let raw_code = format!(
            "TCI1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "v": 1,
                    "h": "127.0.0.1",
                    "p": port,
                    "i": code.invite_id,
                    "k": code.token,
                    "t": pin,
                    "m": code.management_fingerprint,
                    "e": code.expires_unix,
                }))
                .unwrap()
            )
        );

        let signer = signer.unwrap_or_else(|| management.clone());
        let handle = test_tls::serve_on(listener, cert, tls_key, move |index, raw| {
            // 每轮加入固定两次请求（读邀请 + 提交申请），偶数次是 GET。
            // `max_requests` 由用例给：重试场景同一个服务器要服务两轮。
            if index >= max_requests {
                return None;
            }
            if index % 2 == 0 {
                return Some(envelope_ok(json!({
                    "Status": status,
                    "SignedDescriptor": descriptor,
                })));
            }
            // 只处理第二次（提交申请）：把授权封回这次申请的 RecipientJwk。
            let body = request_body(raw);
            let Ok(value) = serde_json::from_str::<Value>(&body) else {
                return Some(envelope_ok(json!({"Status": "Authorized"})));
            };
            let pair_request = value
                .get("PairRequest")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Ok(payload) = request::verify(pair_request, now_unix) else {
                return Some(envelope_ok(json!({"Status": "Authorized"})));
            };
            let authorization = authorization_with_transport(&payload, now_unix, transport.clone());
            let signed = sign(&authorization, &signer);
            let recipient = jwk::RsaJwk::parse(
                payload.get("RecipientJwk").unwrap_or(&Value::Null),
            )
            .expect("申请里应当带接收公钥");
            let sealed = seal_to_public(
                &pad_pkcs7(signed.as_bytes()),
                &recipient.public_key().unwrap(),
                &json!({"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", "cty": "TC-Pairing-v1"}),
            );
            Some(envelope_ok(json!({
                "Status": "Authorized",
                "RequestId": payload["ClientRequest"]["RequestId"],
                "RequestDigest": payload["RequestDigest"],
                "EncryptedAuthorization": sealed,
            })))
        });
        (port, raw_code, handle)
    }

    #[test]
    fn joining_an_invitation_stores_both_the_request_and_the_authorization() {
        let now_unix = now();
        let management = keypair();
        let (_port, raw_code, server) =
            start_join_server("InvitationReady", None, &management, now_unix, 2);
        // 流程用例用小密钥：规格（3072 位）另有专门用例钉住。
        let _bits = keys::test_bits(2048);
        let root = temp_root("happy");

        let outcome = join::run(&root, &raw_code, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect("整条加入流程应当成功");
        assert_eq!(outcome.invite_id, "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        assert_eq!(outcome.node_id, "node-1");
        assert!(!outcome.resumed, "首次接入不该标成复用");
        assert_eq!(outcome.state, "Completed", "授权 + 配置都完成才算完成");
        assert!(crate::pairstore::has_config(&root, &outcome.enrollment_id));
        let config = std::fs::read_to_string(&outcome.config_path).expect("配置应当可读");
        assert!(config.starts_with("[Interface]\r\nPrivateKey = "), "{config}");
        assert!(config.contains("\r\nAddress = 10.66.0.2/32\r\n"), "{config}");
        assert!(config.contains("\r\nEndpoint = 203.0.113.10:18443\r\n"), "{config}");
        assert!(config.ends_with("PersistentKeepalive = 25\r\n"), "{config}");
        assert_eq!(outcome.authorization["Kind"], "TradeChannel.PairAuthorization");

        // 登记 + 私钥 + 授权三样都要在；且授权能原样读回。
        let stored = crate::pairstore::load(&root, &outcome.enrollment_id).unwrap();
        assert_eq!(stored.invite_id, outcome.invite_id);
        assert!(crate::pairstore::has_authorization(&root, &outcome.enrollment_id));
        let saved = crate::pairstore::load_authorization(&root, &outcome.enrollment_id)
            .unwrap()
            .expect("授权应当已落盘");
        assert_eq!(saved["Signed"].as_str().unwrap(), outcome.signed_authorization);
        assert_eq!(saved["Authorization"]["NodeId"], "node-1");

        // 私钥必须能读回来，且与登记里记的公钥是同一对。
        let keys = crate::pairstore::load_private(&root, &outcome.enrollment_id).unwrap();
        let recomputed = keys::tunnel_public_from_private_b64(&keys.tunnel_private_b64).unwrap();
        assert_eq!(
            recomputed,
            stored.client_request["ClientPublicKey"].as_str().unwrap(),
            "存下来的隧道私钥与申请里的公钥不是同一对"
        );
        let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_retry_reuses_the_original_request_instead_of_creating_a_device() {
        let now_unix = now();
        let management = keypair();
        // 第二次进来时服务器已消费过邀请，GET 只会给 RetryOnly。
        let (_port, raw_code, server) =
            start_join_server("RetryOnly", None, &management, now_unix, 2);
        // 流程用例用小密钥：规格（3072 位）另有专门用例钉住。
        let _bits = keys::test_bits(2048);
        let root = temp_root("retry");

        let first = join::run(&root, &raw_code, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect_err("没有原申请却拿到 RetryOnly：应当拒绝");
        assert_eq!(first.code, "InviteConsumed");
        assert!(crate::pairstore::list(&root).unwrap().is_empty(), "拒绝时不该留下登记");

        // 先造出一份「原申请」，再重试：这次必须复用，不能新增设备。
        let (_port2, raw_code2, server2) =
            start_join_server("InvitationReady", None, &management, now_unix, 4);
        let first = join::run(&root, &raw_code2, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect("首次应当成功");
        let second = join::run(&root, &raw_code2, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect("重试应当成功");
        assert_eq!(second.enrollment_id, first.enrollment_id, "重试不该新建登记");
        assert_eq!(crate::pairstore::list(&root).unwrap().len(), 1);
        let _ = (server, server2); // 同上：不等服务线程退出
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 服务器给的**状态词**要各自给出准确处置：作废、过期、旧脚本的两种词，以及
    /// 「不认识的词」。
    ///
    /// 前两种对应完全不同的动作（找服务器主人重发 vs 重新生成一张），混成「协议
    /// 不对」会让人一直在错误的地方排查。旧脚本那两个词是**升级路径**：服务器上跑的
    /// 是上次上传的那份脚本，装完客户端没重开接收服务时对面还会回 `Open`/`Consumed`，
    /// 这时候必须给一句能照做的话（去重开接收服务），而不是一个无解的协议错误。
    /// 最后一条钉住边界：认不出来的词不许被猜成「可以继续」。
    #[test]
    fn invitation_status_words_map_to_their_own_error_codes() {
        let now_unix = now();
        let management = keypair();
        // 流程用例用小密钥：规格（3072 位）另有专门用例钉住。
        let _bits = keys::test_bits(2048);
        for (status, expected) in [
            ("Cancelled", "InviteCancelled"),
            ("Expired", "InviteExpired"),
            // 旧脚本回 `Open`：说清「服务器该升级了」。
            ("Open", "InviteServerOutdated"),
            // 旧脚本回 `Consumed`：等同于 `RetryOnly`，本机没有原申请 → 已被使用。
            ("Consumed", "InviteConsumed"),
            // 谁也没定义过的词：拒绝，不许猜。
            ("SomethingElse", "InvalidOnlineResponse"),
        ] {
            let root = temp_root(&format!("status-{status}"));
            let (_port, raw_code, server) = start_join_server(status, None, &management, now_unix, 1);
            let error = join::run(
                &root,
                &raw_code,
                "管理电脑",
                true,
                now_unix,
                std::time::Duration::from_secs(5),
            )
            .expect_err("这几种状态都不该继续");
            assert_eq!(error.code, expected, "状态 {status} 的处置不对");
            assert!(!error.message.is_empty(), "错误必须带一句人话");
            assert!(
                crate::pairstore::list(&root).unwrap().is_empty(),
                "拒绝时不该留下登记"
            );
            let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn an_authorization_signed_by_a_foreign_identity_is_refused_and_not_stored() {
        let now_unix = now();
        let management = keypair();
        let foreign = other_keypair();
        let (_port, raw_code, server) =
            start_join_server("InvitationReady", Some(foreign), &management, now_unix, 2);
        // 流程用例用小密钥：规格（3072 位）另有专门用例钉住。
        let _bits = keys::test_bits(2048);
        let root = temp_root("foreign");

        let error = join::run(&root, &raw_code, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect_err("外来签名必须被拒");
        assert_eq!(error.code, "InvalidAuthorization", "{error:?}");

        // 申请已经发出去了，所以登记应当留下（这是可重试的正常状态）；
        // 但**授权绝不能落盘**，否则等于把陌生服务器的授权当成真的。
        let items = crate::pairstore::list(&root).unwrap();
        assert_eq!(items.len(), 1);
        assert!(!crate::pairstore::has_authorization(&root, &items[0].enrollment_id));
        let _ = server; // 服务线程阻塞在 accept 上，不等它退出；进程结束时自然回收
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 「用邀请码加入」走完之后必须**真的多了一条能连的线路**，而不只是一份 `client.conf`。
    ///
    /// 这条用例盯的是收口：登记 → client.conf → 线路文件 → 配置里那条线路，四样齐。
    #[test]
    fn joining_an_invitation_leaves_a_connectable_standard_line() {
        let now_unix = now();
        let management = keypair();
        let (_port, raw_code, server) =
            start_join_server("InvitationReady", None, &management, now_unix, 2);
        let _bits = keys::test_bits(2048);
        let root = temp_root("line-standard");

        let outcome = join::run(&root, &raw_code, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect("整条加入流程应当成功");
        // 服务器给的是字符串 `"udp"`：只能生成标准档，这不叫失败。
        assert!(!outcome.supports_compatible, "没有兼容参数时不该声称支持兼容档");
        assert_eq!(outcome.line_name, "香港 01", "线路名取服务器节点名");

        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .unwrap()
            .expect("加入之后必须有配置文件");
        let line = cfg
            .lines
            .iter()
            .find(|item| item.id == outcome.line_id)
            .unwrap_or_else(|| panic!("配置里没有这条线路：{:?}", cfg.lines));
        assert_eq!(cfg.selected, outcome.line_id, "刚加入的线路就是接下来要用的那条");
        assert_eq!(line.name, "香港 01");
        crate::config::validate_endpoint(&line.proxy_endpoint).expect("代理端点必须合法");
        // `None` = 用户还没选过连接方式。服务器给了参数不等于用户选了兼容。
        assert_eq!(line.transport, None);
        assert_eq!(line.effective_transport(), crate::config::Transport::Udp);

        // 线路文件必须真的是标准档，而且引擎能拿它生成运行时配置。
        let path = line.engine_config_path(&root);
        assert!(path.exists(), "线路文件没写出来：{}", path.display());
        assert_eq!(
            crate::engine_config::actual_transport(&path),
            Some(crate::config::Transport::Udp)
        );
        let runtime = crate::engine_config::prepare_engine_config(
            &path,
            &cfg.split,
            &cfg.agents,
            crate::config::Transport::Udp,
            cfg.mode,
            &root.join("runtime-engine.json"), "" ,
            None,
            None,
        )
        .expect("这份线路必须能生成引擎配置");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&runtime).unwrap()).unwrap();
        assert!(
            value["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["tag"] == crate::engine_config::MIXED_TAG),
            "运行时配置少了我们自己的入站：{}",
            value["inbounds"]
        );

        let _ = server;
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 服务器开兼容档时：参数要落到线路文件里（否则连接前派生不出兼容档），
    /// 但**落盘的仍是标准档**，`LineConfig.transport` 也仍是 `None`。
    #[test]
    fn a_server_offering_compatibility_puts_the_transit_into_the_line() {
        let now_unix = now();
        let management = keypair();
        let transport = json!({
            "Type": "tcp-reality",
            "Server": "node.example.com",
            "Port": 443,
            "Uuid": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "ServerName": "node.example.com",
            "RealityPublicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
            "RealityShortId": "0123abcd",
        });
        let (_port, raw_code, server) = start_join_server_with(
            "InvitationReady",
            None,
            &management,
            now_unix,
            2,
            transport.clone(),
        );
        let _bits = keys::test_bits(2048);
        let root = temp_root("line-compatible");

        let outcome = join::run(&root, &raw_code, "管理电脑", true, now_unix, std::time::Duration::from_secs(5))
            .expect("服务器开了兼容档时加入也应当成功");
        assert!(outcome.supports_compatible, "服务器确实给了 tcp-reality 参数");

        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH)).unwrap().unwrap();
        let line = cfg.lines.iter().find(|item| item.id == outcome.line_id).unwrap().clone();
        assert_eq!(line.transport, None, "服务器给了参数不等于用户选了兼容连接");

        let path = line.engine_config_path(&root);
        let text = std::fs::read_to_string(&path).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        // 中转出站必须在（否则连接前派生不出兼容档），且参数就是服务器给的那份。
        let transit = value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == crate::engine_config::TRANSPORT_TAG)
            .expect("线路文件里应当有中转出站");
        assert_eq!(transit["server"], "node.example.com");
        assert_eq!(transit["server_port"], 443);
        assert_eq!(transit["uuid"], transport["Uuid"]);
        assert_eq!(transit["tls"]["reality"]["short_id"], "0123abcd");

        // 但**落盘的这一份仍是标准档**：兼容档在连接前现场派生。
        assert_eq!(
            crate::engine_config::actual_transport(&path),
            Some(crate::config::Transport::Udp),
            "线路文件本身必须是标准档，否则 actual_transport 会以为用户选了 Tcp"
        );
        // 派生用的夹具刻意做成**两个**节点：只有一个节点时，「每个 endpoint 都挂上了中转」
        // 与「只挂第一个」看不出区别（QA 抓到过这种假通过）。
        let mut derived: Value = serde_json::from_str(&text).unwrap();
        let mut second = derived["endpoints"][0].clone();
        second["tag"] = serde_json::json!("hk-2");
        second["address"] = serde_json::json!(["10.66.0.3/32"]);
        derived["endpoints"].as_array_mut().unwrap().push(second);
        crate::engine_config::apply_transport(
            derived.as_object_mut().unwrap(),
            crate::config::Transport::Tcp,
        )
        .expect("这份线路必须能派生兼容档");
        let derived_path = root.join("derived-tcp.json");
        std::fs::write(&derived_path, serde_json::to_string(&derived).unwrap()).unwrap();
        assert_eq!(
            crate::engine_config::actual_transport(&derived_path),
            Some(crate::config::Transport::Tcp)
        );
        let wireguard: Vec<&Value> = derived["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|endpoint| endpoint["type"] == "wireguard")
            .collect();
        assert_eq!(wireguard.len(), 2, "夹具必须有两个 wireguard endpoint");
        for endpoint in &wireguard {
            assert_eq!(
                endpoint["detour"], crate::engine_config::TRANSPORT_TAG,
                "每个 wireguard endpoint 都必须挂中转（漏挂的是 {}）：{endpoint}",
                endpoint["tag"]
            );
        }

        let _ = server;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[derive(serde::Deserialize)]
    struct JwtVector {
        #[serde(rename = "publicJwk")]
        public_jwk: Value,
        compact: String,
        payload: Value,
    }

    /// 邀请 JWT 必须能用**外部实现**（.NET `RSA.SignData`）签出的东西验过。
    ///
    /// 没有这条，`verify_rs256` 只被我自己的签名器验过——那是「我的理解 vs 我的实现」。
    #[test]
    fn dotnet_produced_invitations_verify_with_the_pinned_fingerprint() {
        let dir = fixture_dir();
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| {
                panic!("夹具目录读不到（{}）：{error}。跑 tools/Gen-PairingJwt.ps1 重新生成。", dir.display())
            })
            .map(|entry| entry.expect("目录项应当可读").path())
            .filter(|path| {
                let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
                name.starts_with("dotnet-jwt-") && name.ends_with(".json")
            })
            .collect();
        files.sort();
        assert!(
            !files.is_empty(),
            "没有 .NET 生成的邀请向量（{}）。这不是「跳过」，是夹具丢了。",
            dir.display()
        );

        for path in &files {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("{} 读不到：{error}", path.display()));
            let vector: JwtVector = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{} 不是合法向量：{error}", path.display()));
            let key = jwk::RsaJwk::parse(&vector.public_jwk)
                .unwrap_or_else(|error| panic!("{} 的公钥不是合法 JWK：{error:?}", path.display()));

            // 指纹由公钥算出（和运行时一样），再用它验签。
            let fingerprint = key.fingerprint();
            let verified = invite::verify(&vector.compact, &fingerprint, now())
                .unwrap_or_else(|error| panic!("{} 验签失败：{error:?}", path.display()));
            assert_eq!(
                verified["InviteId"], vector.payload["InviteId"],
                "{} 解出的载荷与文件记录不符",
                path.display()
            );
            assert_eq!(verified["NodeId"], vector.payload["NodeId"]);
            assert_eq!(verified["PublicEndpoint"], vector.payload["PublicEndpoint"]);

            // 换一个字节的载荷，签名必须失效——否则「验签」是假动作。
            let parts: Vec<&str> = vector.compact.split('.').collect();
            assert_eq!(parts.len(), 3);
            let mut tampered_payload = parts[1].to_string();
            let last = tampered_payload.pop().unwrap();
            tampered_payload.push(if last == 'A' { 'B' } else { 'A' });
            let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
            assert!(
                invite::verify(&tampered, &fingerprint, now()).is_err(),
                "{} 的载荷被改过却仍然验签通过",
                path.display()
            );
        }
    }

    // ---- 隧道配置：逐字节对齐 旧版的 Complete-TCClientConfig ----

    const CLIENT_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const SERVER_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn response_ok() -> Value {
        json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.ClientResponse",
            "Status": "Authorized",
            "RequestId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "DeviceId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
            "NodeId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "ClientPublicKey": CLIENT_KEY,
            "ServerPublicKey": SERVER_KEY,
            "ClientAddress": "10.66.0.2/32",
            "ServerAddress": "10.66.0.1/24",
            "TunnelSubnet": "10.66.0.0/24",
            "AllowedIPs": ["0.0.0.0/0"],
            "AddressFamilies": ["IPv4"],
            "PublicEndpoint": "203.0.113.10:18443",
            "PersistentKeepalive": 25,
        })
    }

    fn request_ok() -> Value {
        json!({
            "RequestId": "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b",
            "DeviceId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
            "ClientPublicKey": CLIENT_KEY,
        })
    }

    #[test]
    fn the_tunnel_config_is_rendered_byte_for_byte() {
        let text = tunnel::render(&response_ok(), CLIENT_KEY, &request_ok()).expect("应当渲染成功");
        // 逐字节钉死：CRLF、空行位置、结尾一个 CRLF。换行风格一变，
        // 「已存在配置是否相同」的比较就永远不成立。
        let expected = concat!(
            "[Interface]\r\n",
            "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\r\n",
            "Address = 10.66.0.2/32\r\n",
            "\r\n",
            "[Peer]\r\n",
            "PublicKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\r\n",
            "AllowedIPs = 0.0.0.0/0\r\n",
            "Endpoint = 203.0.113.10:18443\r\n",
            "PersistentKeepalive = 25\r\n",
        );
        assert_eq!(text, expected);

        // MTU 是可选字段：出现就必须在 1280–1420，并且排在 Address 之后。
        let mut with_mtu = response_ok();
        with_mtu["MTU"] = json!(1380);
        let text = tunnel::render(&with_mtu, CLIENT_KEY, &request_ok()).unwrap();
        assert!(text.contains("Address = 10.66.0.2/32\r\nMTU = 1380\r\n\r\n[Peer]"), "{text}");
    }

    #[test]
    fn a_response_that_breaks_the_tunnel_contract_is_refused() {
        let cases: [(&str, Value); 8] = [
            ("客户端公钥被换", json!({"ClientPublicKey": SERVER_KEY})),
            ("服务器地址不是网段首 +1", json!({"ServerAddress": "10.66.0.2/24"})),
            ("设备地址是网络地址", json!({"ClientAddress": "10.66.0.0/32"})),
            ("设备地址是服务器地址", json!({"ClientAddress": "10.66.0.1"})),
            ("设备地址不在网段", json!({"ClientAddress": "10.67.0.2/32"})),
            ("路由不是全量", json!({"AllowedIPs": ["10.0.0.0/8"]})),
            ("保活不是 25", json!({"PersistentKeepalive": 30})),
            ("MTU 越界", json!({"MTU": 1500})),
        ];
        for (reason, patch) in cases {
            let mut response = response_ok();
            for (key, value) in patch.as_object().unwrap() {
                response[key] = value.clone();
            }
            let error = tunnel::render(&response, CLIENT_KEY, &request_ok()).unwrap_err();
            assert!(
                error.code == "InvalidClientResponse" || error.code == "ResponseMismatch",
                "{reason}：{error:?}"
            );
        }

        // 网段本身不合规：公网网段、/31、非网络地址。
        for cidr in ["8.8.8.0/24", "10.66.0.0/31", "10.66.0.7/24"] {
            let mut response = response_ok();
            response["TunnelSubnet"] = json!(cidr);
            assert!(
                tunnel::render(&response, CLIENT_KEY, &request_ok()).is_err(),
                "{cidr} 不该通过"
            );
        }

        // 服务器公钥与本机相同 = 自环，必须拒。
        let mut same = response_ok();
        same["ServerPublicKey"] = json!(CLIENT_KEY);
        assert!(tunnel::render(&same, CLIENT_KEY, &request_ok()).is_err());
    }

    /// ================= QA 独立复核：配对 → 线路 =================
    ///
    /// 这一组用例刻意与 `line::tests` / `join` 的用例**不同源**：夹具自建（`qa_*`），
    /// 每条断言都指向一条设计主张或一个失败面。特别地：
    ///
    /// - `qa_the_engine_*` 用**真引擎** `sing-box check` 验证「线路文件里有一条没人引用的
    ///   中转出站」这个状态到底能不能启动；
    /// - `qa_a_two_node_line_*` 是给「只给第一个 endpoint 挂 detour」「把中转出站插到末尾」
    ///   这两次变异准备的探针：夹具里有**两个** wireguard endpoint，且对顺序有硬断言；
    /// - `qa_*_failure_*` 盯半成品：写线路失败 / 写配置失败 / 端口全占之后，
    ///   `config.json` 必须逐字节不变。
    ///
    /// 「文件存在」这类永远为真的断言一条都不写：要么断言内容（tag/端口/参数），
    /// 要么断言另一处引用（`actual_transport` 的结论）。
    ///
    /// 不需要额外 `#[cfg(test)]`：它本来就嵌在 `#[cfg(test)] mod crypto_tests` 里，
    /// 发布产物从来不含它。（我一度以为它没 gate、加过一个冗余属性，QA 复核指出是误判，
    /// 已撤——`#![allow(dead_code)]` 只压未使用告警，不会把代码带进产物。）
    mod qa_line {
        use super::*;
        use crate::config::{AppConfig, LineConfig, Mode, SplitConfig, SplitTarget, Transport};
        use crate::engine_config;
        use crate::pairing::line::{self, ClientConf, Compatible};

        /// 与 `line::tests` 里那三个常量同值：它们是一对**真的** x25519 密钥，
        /// 能过 `tunnel::render` 的公私钥一致性校验。测试数据，不是逻辑。
        const QA_PRIVATE: &str = "d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=";
        const QA_CLIENT_PUBLIC: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        const QA_SERVER_PUBLIC: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        /// 兼容参数全用「另一套」值（IP、8443、另一个 short_id）：实现若把参数写死成
        /// 某个固定形状，断言会红。
        const QA_TRANSIT_KEY: &str = "Zx9vQ2mK8pL4tR6sW1yB3nC5jH7gF0dA2eS4uI6oM8k";
        const QA_TRANSIT_UUID: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";
        /// 假服务器（`authorization_with_transport`）里写死的节点名：端到端用例的线路名就是它。
        /// 不使用本模块自己的 `qa_response()`——端到端走的是服务器下发的那一份。
        const QA_FIXTURE_NODE_NAME: &str = "香港 01";

        fn qa_request() -> Value {
            json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientRequest",
                "RequestId": "0f0e0d0c-0b0a-4908-8706-050403020100",
                "DeviceId": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                "CreatedAtUtc": "2026-11-03T00:00:00.000000Z",
                "ClientPublicKey": QA_CLIENT_PUBLIC,
                "AddressFamilies": ["IPv4"],
            })
        }

        fn qa_response(request: &Value) -> Value {
            json!({
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ClientResponse",
                "Status": "Authorized",
                "RequestId": request["RequestId"],
                "DeviceId": request["DeviceId"],
                "NodeId": "0f0e0d0c-0b0a-4908-8706-050403020100",
                "NodeName": "东京 02",
                "ClientPublicKey": request["ClientPublicKey"],
                "ServerPublicKey": QA_SERVER_PUBLIC,
                "ClientAddress": "10.99.7.2/32",
                "ServerAddress": "10.99.7.1/24",
                "TunnelSubnet": "10.99.7.0/24",
                "AllowedIPs": ["0.0.0.0/0"],
                "AddressFamilies": ["IPv4"],
                "PublicEndpoint": "198.51.100.9:51820",
                "PersistentKeepalive": 25,
                "ConfigRevision": 3,
                "MTU": 1360,
                // 字符串 = 老服务器/没有兼容档。要用兼容档的分支自己换成对象。
                "Transport": "udp",
            })
        }

        /// 本模块专用的 `client.conf`（渲染 → 解析），夹具坏了就地报清楚。
        fn qa_conf() -> ClientConf {
            let request = qa_request();
            let text = tunnel::render(&qa_response(&request), QA_PRIVATE, &request)
                .expect("QA 夹具的 ClientResponse 必须能过 tunnel::render");
            line::parse_client_conf(&text).expect("自己渲染的 client.conf 必须能解析回来")
        }

        fn qa_compatible() -> Compatible {
            Compatible {
                server: "198.51.100.9".to_string(),
                port: 8443,
                uuid: QA_TRANSIT_UUID.to_string(),
                server_name: "gate.example.net".to_string(),
                reality_public_key: QA_TRANSIT_KEY.to_string(),
                reality_short_id: "9f8e7d6c".to_string(),
            }
        }

        /// 服务器下发的 `Transport` 对象（与 `qa_compatible()` 同一份值）。
        fn qa_transport_payload() -> Value {
            json!({
                "Type": "tcp-reality",
                "Server": "198.51.100.9",
                "Port": 8443,
                "Uuid": QA_TRANSIT_UUID,
                "ServerName": "gate.example.net",
                "RealityPublicKey": QA_TRANSIT_KEY,
                "RealityShortId": "9f8e7d6c",
            })
        }

        fn qa_line_id() -> String {
            crate::config::slug(QA_FIXTURE_NODE_NAME)
        }

        fn wireguard_of(value: &Value) -> Vec<&Value> {
            value["endpoints"]
                .as_array()
                .map(|items| items.iter().filter(|e| e["type"] == "wireguard").collect())
                .unwrap_or_default()
        }

        fn read(path: &std::path::Path) -> String {
            std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()))
        }

        // ---------- 真引擎 ----------

        fn engine_exe() -> std::path::PathBuf {
            // 查找顺序：环境变量 → 仓库 vendor\（打包用的那一份）→ 已安装目录。
            // 仓库里没有引擎时这条测试会失败而不是跳过：跳过会让验证变成永远为真。
            if let Ok(value) = std::env::var("TC_SING_BOX") {
                return std::path::PathBuf::from(value);
            }
            let vendored = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("vendor")
                .join("sing-box.exe");
            if vendored.exists() {
                return vendored;
            }
            std::path::PathBuf::from(r"C:\SpiderVPN\bin\sing-box.exe")
        }

        /// 跑真引擎的 `check`，返回退出码与输出。
        ///
        /// 引擎不在就**当场失败**——「跳过」会让这条验证变成永远为真。
        fn engine_check(path: &std::path::Path) -> (i32, String) {
            let exe = engine_exe();
            assert!(
                exe.exists(),
                "找不到引擎 {}（可用环境变量 TC_SING_BOX 指定）。没有引擎就无法验「未引用的中转出站能不能启动」。",
                exe.display()
            );
            let out = std::process::Command::new(&exe)
                .arg("check")
                .arg("-c")
                .arg(path)
                .output()
                .unwrap_or_else(|error| panic!("跑不起引擎 {}：{error}", exe.display()));
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.code().unwrap_or(-1), text)
        }

        /// 把配置改成「适合启动一次」的形态：入站端口 0（引擎自己挑），日志级别 info
        /// （线路文件里是 warn，那样连 `sing-box started` 都不会打印）。
        ///
        /// 启动用例验的是「出站引用能不能解析」，所以这两处改动都不碰被测的东西。
        fn with_ephemeral_inbounds(text: &str) -> Value {
            let mut value: Value = serde_json::from_str(text).expect("配置必须能解析");
            if let Some(items) = value["inbounds"].as_array_mut() {
                for inbound in items.iter_mut() {
                    inbound["listen_port"] = json!(0);
                }
            }
            value["log"]["level"] = json!("info");
            value
        }

        /// 真启动一次引擎，看它到底起不起得来。
        ///
        /// `check` 只做结构校验：实测它连「detour 指向不存在的出站」都判 exit 0。
        /// 所以「这份配置能不能用」的唯一判据是 `run` 有没有走到 `sing-box started`。
        fn engine_starts(path: &std::path::Path) -> (bool, String) {
            let exe = engine_exe();
            assert!(
                exe.exists(),
                "找不到引擎 {}（可用环境变量 TC_SING_BOX 指定）。",
                exe.display()
            );
            let log_path = path.with_extension("engine.log");
            let log = std::fs::File::create(&log_path).expect("建引擎日志文件");
            let mut child = std::process::Command::new(&exe)
                .arg("run")
                .arg("-c")
                .arg(path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::from(
                    log.try_clone().expect("克隆日志句柄"),
                ))
                .stderr(std::process::Stdio::from(log))
                .spawn()
                .unwrap_or_else(|error| panic!("起不来引擎 {}：{error}", exe.display()));

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut started = false;
            let mut text = String::new();
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(100));
                text = std::fs::read_to_string(&log_path).unwrap_or_default();
                if text.contains("sing-box started") {
                    started = true;
                    break;
                }
                if text.contains("FATAL") {
                    break;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            (started, text)
        }

        /// 主张核心：线路文件里有一条 `tag=tc-transport` 的 vless+REALITY 出站、
        /// **没有任何 endpoint 引用它**时，引擎到底认不认？
        ///
        /// 三份配置（标准档原文件 / `apply_transport(Tcp)` 派生 / TUN 模式线路）都必须 exit 0。
        /// 第一份若被判无效，整条「落盘标准档 + 文件里塞未引用中转」的设计就塌了。
        #[test]
        fn qa_the_engine_accepts_a_transit_outbound_nobody_references() {
            let root = temp_root("qa-engine");
            let conf = qa_conf();
            let params = qa_compatible();
            let split = SplitConfig::default();

            let standard = line::build(
                &conf,
                Some(&params),
                17_890,
                Mode::Proxy,
                &split,
                &crate::config::AgentsConfig::default(),
            )
                .expect("标准档必须能生成");
            let saved = root.join("standard.json");
            std::fs::write(&saved, &standard).unwrap();

            // ① 前提事实：中转出站在，且**没人引用**（不是「碰巧被引用」才跑得起来）。
            let value: Value = serde_json::from_str(&standard).unwrap();
            let transit = value["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == engine_config::TRANSPORT_TAG)
                .expect("标准档里也要保留中转出站：兼容参数只有这里能放")
                .clone();
            assert_eq!(transit["type"], "vless");
            assert_eq!(transit["server"], "198.51.100.9");
            assert_eq!(transit["server_port"], 8443);
            assert_eq!(transit["uuid"], QA_TRANSIT_UUID);
            assert_eq!(transit["tls"]["reality"]["public_key"], QA_TRANSIT_KEY);
            assert_eq!(transit["tls"]["reality"]["short_id"], "9f8e7d6c");
            let wg = wireguard_of(&value);
            assert_eq!(wg.len(), 1, "隧道本体应当只有一个 wireguard endpoint");
            for endpoint in &wg {
                assert!(
                    endpoint.get("detour").is_none(),
                    "标准档里不该有 detour：{endpoint}"
                );
            }
            // 路由/选择器/终结点都不许提到它，否则「未引用」这个前提就是假的。
            let route_text = value["route"].to_string();
            assert!(
                !route_text.contains(engine_config::TRANSPORT_TAG),
                "路由里引用了中转出站：{route_text}"
            );
            for outbound in value["outbounds"].as_array().unwrap() {
                if outbound["tag"] == engine_config::TRANSPORT_TAG {
                    continue;
                }
                let members = outbound["outbounds"].to_string() + &outbound["default"].to_string();
                assert!(
                    !members.contains(engine_config::TRANSPORT_TAG),
                    "选择器引用了中转出站：{outbound}"
                );
            }

            // ② 连接方式的识别必须如实。
            assert_eq!(
                engine_config::actual_transport(&saved),
                Some(Transport::Udp),
                "带未引用中转出站的标准档必须认成 Udp，不能认成 None/Tcp"
            );
            assert!(
                !engine_config::tcp_shaped(&standard),
                "标准档不许被认成兼容档（有参数没 detour 也不行）"
            );

            // ③ 现场派生兼容档：结构必须精确，不只是「跑得起来」。
            let mut derived: Value = serde_json::from_str(&standard).unwrap();
            assert!(engine_config::apply_transport(derived.as_object_mut().unwrap(), Transport::Tcp)
                .expect("这份线路必须能派生兼容档"));
            let tcp = root.join("derived-tcp.json");
            std::fs::write(&tcp, serde_json::to_string(&derived).unwrap()).unwrap();
            assert_eq!(engine_config::actual_transport(&tcp), Some(Transport::Tcp));
            assert!(engine_config::tcp_shaped(&read(&tcp)));
            let outbounds = derived["outbounds"].as_array().unwrap();
            assert_eq!(
                outbounds[0]["tag"], engine_config::TRANSPORT_TAG,
                "中转出站必须排在最前面（旧版是 @($transit)+$outbounds）：{outbounds:?}"
            );
            assert_eq!(
                outbounds
                    .iter()
                    .filter(|o| o["tag"] == engine_config::TRANSPORT_TAG)
                    .count(),
                1,
                "不许出现两份中转出站：{outbounds:?}"
            );
            for endpoint in wireguard_of(&derived) {
                assert_eq!(
                    endpoint["detour"], engine_config::TRANSPORT_TAG,
                    "每个 wireguard endpoint 都必须挂中转：{endpoint}"
                );
            }

            // ④ TUN 模式的线路（join 时 `cfg.mode == Tun` 走的就是这条），以及它的兼容档。
            let tun_body = line::build(
                &conf,
                Some(&params),
                17_891,
                Mode::Tun,
                &split,
                &crate::config::AgentsConfig::default(),
            )
                .expect("TUN 模式的线路必须能生成");
            let tun_line = root.join("tun-line.json");
            std::fs::write(&tun_line, &tun_body).unwrap();
            let tun = root.join("derived-tun.json");
            let prepared = engine_config::prepare_engine_config(
                &tun_line,
                &split,
                &crate::config::AgentsConfig::default(),
                Transport::Tcp,
                Mode::Tun,
                &tun, "" ,
                None,
                None,
            )
            .expect("TUN 线路的兼容档必须能生成");
            assert_eq!(prepared, tun, "派生有变化时必须写运行时配置");
            assert_eq!(engine_config::actual_transport(&tun), Some(Transport::Tcp));

            // ⑤ 真引擎 `check`：四份都必须是 exit 0（结构/语义层）。
            let mut codes = Vec::new();
            for path in [&saved, &tcp, &tun_line, &tun] {
                let (code, output) = engine_check(path);
                codes.push(format!("{} => exit {code} {output}", path.display()));
                assert_eq!(
                    code,
                    0,
                    "引擎不接受这份配置：{}\n{}",
                    path.display(),
                    output
                );
            }

            // ⑥ 但 `check` **不解析引用**（实测：detour 指向不存在的出站，check 仍然 exit 0），
            //    所以「能不能用」必须用 `run` 验。启动一次，看到 `sing-box started` 才算数。
            //    入站端口改成 0（引擎自己挑一个）：这条验的是出站引用，不是端口占用。
            let runnable = with_ephemeral_inbounds(&standard);
            let run_ok = root.join("run-standard.json");
            std::fs::write(&run_ok, serde_json::to_string(&runnable).unwrap()).unwrap();
            let (started, log) = engine_starts(&run_ok);
            assert!(
                started,
                "带「未引用的中转出站」的标准档在真引擎里起不来——这条设计主张不成立：\n{log}"
            );

            // 反向对照：同一个形状，只把 detour 指向不存在的出站。引擎必须 FATAL，
            // 否则上面那句「起来了」就不能证明任何事。
            let mut broken: Value = serde_json::from_str(&standard).unwrap();
            broken["endpoints"][0]["detour"] = json!("no-such-outbound");
            let broken = with_ephemeral_inbounds(&broken.to_string());
            let broken_path = root.join("run-broken.json");
            std::fs::write(&broken_path, serde_json::to_string(&broken).unwrap()).unwrap();
            let (broken_started, broken_log) = engine_starts(&broken_path);
            assert!(
                !broken_started,
                "引擎接受了指向不存在出站的 detour：「启动成功」就不再是证据：\n{broken_log}"
            );
            assert!(
                broken_log.contains("FATAL"),
                "反向对照必须留下引擎的 FATAL 结论：\n{broken_log}"
            );

            println!(
                "sing-box check: {codes:#?}\nsing-box run: 标准档 started={started}；坏引用 started={broken_started}"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        // ---------- 端到端（假服务器） ----------

        /// 服务器**给了**兼容参数：线路文件必须带中转出站，但落盘的仍是标准档；
        /// 配置里其它线路、其它字段一个都不许被动。
        #[test]
        fn qa_joining_with_compatibility_writes_a_standard_line_and_keeps_the_rest() {
            let now_unix = now();
            let management = keypair();
            let (_port, raw_code, server) = start_join_server_with(
                "InvitationReady",
                None,
                &management,
                now_unix,
                2,
                qa_transport_payload(),
            );
            let _bits = keys::test_bits(2048);
            let root = temp_root("qa-join-compatible");

            // 预先放一份「用户已有的配置」：两条线路 + 一堆非默认字段。
            let mut before = cfg_with_existing(17_955);
            before.mode = Mode::Proxy;
            crate::config::save(&root.join(crate::config::DEFAULT_PATH), &before).unwrap();
            let before_text = read(&root.join(crate::config::DEFAULT_PATH));

            let outcome = join::run(
                &root,
                &raw_code,
                "管理电脑",
                true,
                now_unix,
                std::time::Duration::from_secs(5),
            )
            .expect("服务器开了兼容档时加入必须成功");
            assert!(outcome.supports_compatible, "服务器确实给了 tcp-reality 参数");
            assert_eq!(outcome.state, "Completed");
            assert_eq!(outcome.line_name, QA_FIXTURE_NODE_NAME, "线路名取服务器给的节点名");

            // 配置：新线路在、选中它，别的字段原封不动。
            let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
                .unwrap()
                .expect("加入之后必须有配置");
            assert_eq!(cfg.selected, outcome.line_id, "刚加入的线路就该是选中项");
            assert_eq!(cfg.lines.len(), before.lines.len() + 1, "只许多一条线路");
            assert_eq!(cfg.mode, before.mode, "接管方式不该被这次加入改掉");
            assert_eq!(cfg.auto_start, before.auto_start);
            assert_eq!(cfg.auto_connect, before.auto_connect);
            assert_eq!(cfg.close_to_tray, before.close_to_tray);
            assert_eq!(cfg.quality_warning, before.quality_warning);
            assert_eq!(cfg.split, before.split, "分流规则不该被动");
            assert_eq!(cfg.exits, before.exits, "出口选择不该被动");
            for kept in &before.lines {
                let now_line = cfg
                    .lines
                    .iter()
                    .find(|line| line.id == kept.id)
                    .unwrap_or_else(|| panic!("既有线路 {} 不见了：{:?}", kept.id, cfg.lines));
                assert_eq!(now_line, kept, "既有线路被改写了");
            }
            let line_cfg = cfg
                .lines
                .iter()
                .find(|line| line.id == outcome.line_id)
                .expect("配置里必须有这条新线路")
                .clone();
            assert_eq!(
                line_cfg.transport, None,
                "服务器给了参数不等于用户选了兼容连接：落盘必须是 None"
            );
            assert_eq!(line_cfg.effective_transport(), Transport::Udp);

            // 线路文件：标准档 + 中转出站，且真的从配置里被引用到。
            let path = line_cfg.engine_config_path(&root);
            assert_eq!(
                path,
                root.join("lines").join(format!("{}.json", qa_line_id())),
                "线路文件路径必须是 <数据根>/lines/<id>.json"
            );
            let text = read(&path);
            let value: Value = serde_json::from_str(&text).unwrap();
            assert!(
                value["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| o["tag"] == engine_config::TRANSPORT_TAG && o["type"] == "vless"),
                "线路文件里必须留着中转出站，否则连接前派生不出兼容档"
            );
            assert_eq!(wireguard_of(&value).len(), 1);
            for endpoint in wireguard_of(&value) {
                assert!(endpoint.get("detour").is_none(), "{endpoint}");
            }
            assert_eq!(
                engine_config::actual_transport(&path),
                Some(Transport::Udp),
                "落盘的是标准档：认成 Tcp 会让连接方式显示错"
            );

            // 派生出来的兼容档必须真的可用（结构 + 真引擎）。
            let runtime = engine_config::prepare_engine_config(
                &path,
                &cfg.split,
                &cfg.agents,
                Transport::Tcp,
                cfg.mode,
                &root.join("runtime-tcp.json"), "" ,
                None,
                None,
            )
            .expect("这份线路必须能派生兼容档");
            let runtime_value: Value = serde_json::from_str(&read(&runtime)).unwrap();
            for endpoint in wireguard_of(&runtime_value) {
                assert_eq!(
                    endpoint["detour"], engine_config::TRANSPORT_TAG,
                    "运行时的每个 endpoint 都必须走中转：{endpoint}"
                );
            }
            for path in [&path, &runtime] {
                let (code, output) = engine_check(path);
                assert_eq!(code, 0, "引擎不接受 {}：\n{output}", path.display());
            }

            // 配置里写进去的和磁盘上的一致：不会出现「配置有线路、文件没有」。
            assert_ne!(before_text, read(&root.join(crate::config::DEFAULT_PATH)));
            let _ = server;
            let _ = std::fs::remove_dir_all(&root);
        }

        /// 服务器**没给**兼容参数：只出标准档，而且不许假装支持兼容（切换时必须是硬拒绝）。
        #[test]
        fn qa_joining_without_compatibility_never_pretends_to_support_it() {
            let now_unix = now();
            let management = keypair();
            let (_port, raw_code, server) =
                start_join_server("InvitationReady", None, &management, now_unix, 2);
            let _bits = keys::test_bits(2048);
            let root = temp_root("qa-join-standard");

            let outcome = join::run(
                &root,
                &raw_code,
                "管理电脑",
                true,
                now_unix,
                std::time::Duration::from_secs(5),
            )
            .expect("没有兼容档不是错误");
            assert!(!outcome.supports_compatible, "没有参数却声称支持兼容档");

            let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
                .unwrap()
                .unwrap();
            let line_cfg = cfg.lines.iter().find(|l| l.id == outcome.line_id).unwrap();
            let path = line_cfg.engine_config_path(&root);
            let text = read(&path);
            let value: Value = serde_json::from_str(&text).unwrap();
            assert!(
                !value["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| o["tag"] == engine_config::TRANSPORT_TAG),
                "没有兼容参数就不该写中转出站：{}",
                value["outbounds"]
            );
            assert!(!engine_config::tcp_shaped(&text));
            // 硬判据：切换到兼容档必须**明确拒绝**，不是悄悄按标准档连。
            let refusal = engine_config::check_transport(&path, Transport::Tcp)
                .expect_err("没有参数时切兼容档必须报错");
            assert!(
                engine_config::is_transport_refusal(&refusal),
                "拒绝的原因必须是「连接方式不可用」，实际：{refusal}"
            );
            let (code, output) = engine_check(&path);
            assert_eq!(code, 0, "引擎不接受 {}：\n{output}", path.display());
            let _ = server;
            let _ = std::fs::remove_dir_all(&root);
        }

        /// 兼容参数非法：必须拒，且**一个文件都不许落**（连 config.json 都不该出现）。
        ///
        /// 两次完整的加入（端口/类型各一次）验「拒绝发生在写盘之前」；
        /// 其余畸形形状在组件级补齐——每跑一次加入都要现生一对 RSA 密钥，
        /// 没必要为了同一句话重复跑五遍。
        #[test]
        fn qa_illegal_compatibility_parameters_are_refused_before_anything_is_written() {
            let _bits = keys::test_bits(2048);
            let mut wrong_port = qa_transport_payload();
            wrong_port["Port"] = json!(9443);
            let mut wrong_type = qa_transport_payload();
            wrong_type["Type"] = json!("tcp-xtls");

            for (label, transport) in [
                ("端口不在 443/8443/2443", wrong_port),
                ("Type 不是 tcp-reality", wrong_type),
            ] {
                let now_unix = now();
                let management = keypair();
                let (_port, raw_code, server) =
                    start_join_server_with("InvitationReady", None, &management, now_unix, 2, transport);
                let root = temp_root("qa-bad-transport");

                let error = join::run(
                    &root,
                    &raw_code,
                    "管理电脑",
                    true,
                    now_unix,
                    std::time::Duration::from_secs(5),
                )
                .expect_err(label);
                assert_eq!(error.code, "InvalidTransport", "{label}：{error:?}");
                assert!(
                    error.message.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                    "{label} 的错误必须是中文人话：{}",
                    error.message
                );

                // 不落盘：没有配置、没有线路目录、没有 client.conf。
                assert!(
                    !root.join(crate::config::DEFAULT_PATH).exists(),
                    "{label}：被拒之后不该有 config.json"
                );
                assert!(!root.join("lines").exists(), "{label}：被拒之后不该有 lines 目录");
                // 登记还在（申请已经发出去了，这是可重试的正常状态），但绝不能有配置。
                for enrollment in crate::pairstore::list(&root).unwrap() {
                    assert!(
                        !crate::pairstore::has_config(&root, &enrollment.enrollment_id),
                        "{label}：被拒之后不该有 client.conf"
                    );
                    assert_ne!(enrollment.state, "Completed", "{label}：不该标成已完成");
                }
                let _ = server;
                let _ = std::fs::remove_dir_all(&root);
            }

            // 组件级：逐字段的畸形形状都必须落到 InvalidTransport（而不是静默降级成标准档）。
            let request = qa_request();
            let cases: Vec<(&str, &dyn Fn(&mut Value))> = vec![
                ("Server 为空", &|t| t["Server"] = json!("")),
                ("Server 是 URL", &|t| t["Server"] = json!("https://gate.example.net")),
                ("Server 有空白", &|t| t["Server"] = json!("gate example")),
                ("Uuid 不是 GUID", &|t| t["Uuid"] = json!("node-7")),
                ("ServerName 为空", &|t| t["ServerName"] = json!("")),
                ("RealityPublicKey 长度不对", &|t| t["RealityPublicKey"] = json!("too-short")),
                ("RealityPublicKey 非 base64url", &|t| t["RealityPublicKey"] = json!("!".repeat(43))),
                ("RealityShortId 奇数长度", &|t| t["RealityShortId"] = json!("abc")),
                ("RealityShortId 非十六进制", &|t| t["RealityShortId"] = json!("zz")),
                ("Port 是字符串", &|t| t["Port"] = json!("https")),
                ("Port 是 1", &|t| t["Port"] = json!(1)),
            ];
            let mut ok = qa_response(&request);
            ok["Transport"] = qa_transport_payload();
            let parsed = line::compatible(&ok).expect("正例先行：合法参数必须能读出来").expect("应当读到兼容参数");
            assert_eq!(parsed.port, 8443);
            assert_eq!(parsed.reality_short_id, "9f8e7d6c");
            for (label, mutate) in cases {
                let mut transport = qa_transport_payload();
                mutate(&mut transport);
                let mut response = qa_response(&request);
                response["Transport"] = transport;
                let error = line::compatible(&response).expect_err(label);
                assert_eq!(error.code, "InvalidTransport", "{label}：{error:?}");
                assert!(
                    error.message.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                    "{label} 的错误必须是中文人话：{}",
                    error.message
                );
            }
        }

        // ---------- 半成品防护 ----------

        /// 用户已有的配置：两条线路 + 一堆非默认字段（`register` 必须一个都不动）。
        fn cfg_with_existing(port: u16) -> AppConfig {
            let mut cfg = line::empty_config();
            cfg.mode = Mode::Proxy;
            cfg.auto_start = true;
            cfg.auto_connect = true;
            cfg.close_to_tray = true;
            cfg.quality_warning = false;
            cfg.split.add_domain("qy.example", SplitTarget::Trade);
            cfg.split.add_process("trade.exe", SplitTarget::Trade);
            cfg.exits.trade = Some("hk".to_string());
            cfg.lines.push(LineConfig {
                id: "keep-a".to_string(),
                name: "既有 A".to_string(),
                proxy_endpoint: format!("127.0.0.1:{port}"),
                transport: Some(Transport::Tcp),
                verified_transport: None,
            });
            cfg.lines.push(LineConfig {
                id: "keep-b".to_string(),
                name: "既有 B".to_string(),
                proxy_endpoint: format!("127.0.0.1:{}", port + 1),
                transport: None,
                verified_transport: None,
            });
            cfg.selected = "keep-b".to_string();
            cfg
        }

        /// 线路文件写不下去：配置必须逐字节不变（既不能多出线路，也不能动 selected）。
        #[test]
        fn qa_a_failed_line_write_leaves_config_byte_identical() {
            let _bits = keys::test_bits(2048);

            // 变体一：`lines` 被一个**文件**占着 → create_dir_all 必然失败。
            // 变体二：临时文件名被一个**目录**占着 → 写临时文件必然失败，目标文件不会出现。
            for variant in ["lines-is-a-file", "temp-name-is-taken"] {
                let now_unix = now();
                let management = keypair();
                let (_port, raw_code, server) =
                    start_join_server("InvitationReady", None, &management, now_unix, 2);
                let root = temp_root("qa-line-write-fail");
                let cfg_path = root.join(crate::config::DEFAULT_PATH);
                crate::config::save(&cfg_path, &cfg_with_existing(17_955)).unwrap();
                let before = read(&cfg_path);

                match variant {
                    "lines-is-a-file" => {
                        std::fs::write(root.join("lines"), b"not a directory").unwrap();
                    }
                    _ => {
                        std::fs::create_dir_all(root.join("lines")).unwrap();
                        // 占住 secretfile 的临时文件名（`.<name>.tmp-<pid>`）：`create_new`
                        // 必然失败，而目标文件始终没被创建，下面「线路文件不该存在」才成立。
                        let stem = crate::config::safe_file_stem(&qa_line_id());
                        let blocked = root
                            .join("lines")
                            .join(format!(".{stem}.json.tmp-{}", std::process::id()));
                        std::fs::create_dir_all(&blocked).unwrap();
                    }
                }

                let error = join::run(
                    &root,
                    &raw_code,
                    "管理电脑",
                    true,
                    now_unix,
                    std::time::Duration::from_secs(5),
                )
                .expect_err(variant);
                assert_eq!(error.code, "LineWriteFailed", "{variant}：{error:?}");

                // 配置逐字节不变：多一条线路 / 换个 selected 都是半成品。
                assert_eq!(read(&cfg_path), before, "{variant}：失败的加入改了 config.json");
                let after = crate::config::load(&cfg_path).unwrap().unwrap();
                assert_eq!(after.lines.len(), 2, "{variant}：多出了线路");
                assert!(
                    !after.lines.iter().any(|line| line.id == qa_line_id()),
                    "{variant}：配置里留下了写不出文件的线路"
                );
                assert_eq!(after.selected, "keep-b", "{variant}：selected 被改掉了");
                assert!(
                    !root.join("lines").join(format!("{}.json", qa_line_id())).exists(),
                    "{variant}：线路文件不该存在"
                );
                let _ = server;
                let _ = std::fs::remove_dir_all(&root);
            }
        }

        /// 写 `config.json` 失败：线路文件留在盘上是允许的，但**不许**出现
        /// 「配置里有线路、文件却没有」。配置本身必须逐字节不变。
        #[test]
        fn qa_a_failed_config_write_keeps_the_disk_consistent() {
            let now_unix = now();
            let management = keypair();
            let (_port, raw_code, server) =
                start_join_server("InvitationReady", None, &management, now_unix, 2);
            let _bits = keys::test_bits(2048);
            let root = temp_root("qa-config-write-fail");
            let cfg_path = root.join(crate::config::DEFAULT_PATH);
            crate::config::save(&cfg_path, &cfg_with_existing(17_955)).unwrap();
            let before = read(&cfg_path);

            // 只读的 config.json：临时文件能写，替换（rename）必然失败。
            let mut perms = std::fs::metadata(&cfg_path).unwrap().permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&cfg_path, perms).unwrap();

            let error = join::run(
                &root,
                &raw_code,
                "管理电脑",
                true,
                now_unix,
                std::time::Duration::from_secs(5),
            )
            .expect_err("配置写不下去时必须报错");
            let mut perms = std::fs::metadata(&cfg_path).unwrap().permissions();
            perms.set_readonly(false);
            std::fs::set_permissions(&cfg_path, perms).unwrap();

            assert_eq!(error.code, "LineConfigSaveFailed", "{error:?}");
            assert_eq!(read(&cfg_path), before, "写失败之后 config.json 必须原样");

            let after = crate::config::load(&cfg_path).unwrap().unwrap();
            assert_eq!(after.selected, "keep-b");
            assert_eq!(after.lines.len(), 2);

            // 反方向的一致性检查：配置里**没有**这条线路，所以「有文件没配置」是允许的；
            // 但绝不允许出现「配置里有、文件没有」——这里再确认一次配置真的没写进去。
            assert!(
                !after.lines.iter().any(|line| line.id == qa_line_id()),
                "配置写失败却把线路记进了内存/磁盘：{:?}",
                after.lines
            );
            let line_path = root.join("lines").join(format!("{}.json", qa_line_id()));
            if line_path.exists() {
                // 文件留下来了就必须是**完整、可解析、可派生**的一份，不能是半截。
                let value: Value = serde_json::from_str(&read(&line_path))
                    .expect("留下的线路文件必须是完整 JSON");
                assert_eq!(wireguard_of(&value).len(), 1);
                assert_eq!(
                    engine_config::actual_transport(&line_path),
                    Some(Transport::Udp)
                );
            }
            let _ = server;
            let _ = std::fs::remove_dir_all(&root);
        }

        /// 端口全被占：必须有明确错误码（不是 panic），且**不写出半份配置**。
        ///
        /// 「全被占」用扫描区间收窄到 17890..=17920 来构造（见 `force_port_window_for_test`）：
        /// 走的是**同一段**跳过循环与**同一个**终点错误，只是区间短——如果按生产区间构造，
        /// 要塞 4.7 万条线路、跑两分多钟，还把同进程其它用例的端口空间拖慢。
        /// 这条用例仍然端到端跑 `join::run`：错误码、消息、以及「一个字节都没写」都是真的。
        #[test]
        fn qa_exhausted_ports_fail_with_a_code_and_write_nothing() {
            let now_unix = now();
            let management = keypair();
            let (_port, raw_code, server) =
                start_join_server("InvitationReady", None, &management, now_unix, 2);
            let _bits = keys::test_bits(2048);
            let root = temp_root("qa-ports");
            let cfg_path = root.join(crate::config::DEFAULT_PATH);

            // 生产区间的两头必须还是那个定稿值（收窄只是测试手段，不许改口径）。
            assert_eq!(line::FIRST_PORT, 17_890, "起始端口是定稿口径");
            assert_eq!(line::LAST_PORT, 65_532, "上限要给自检探测端口留 +3");

            const LAST: u16 = line::FIRST_PORT + 30;
            let _window = line::force_port_window_for_test(line::FIRST_PORT, LAST);
            let mut full = line::empty_config();
            for port in line::FIRST_PORT..=LAST {
                full.lines.push(LineConfig {
                    id: format!("taken-{port}"),
                    name: format!("占位 {port}"),
                    proxy_endpoint: format!("127.0.0.1:{port}"),
                    transport: None,
                    verified_transport: None,
                });
            }
            full.selected = format!("taken-{}", line::FIRST_PORT);
            crate::config::save(&cfg_path, &full).unwrap();
            let before = read(&cfg_path);

            let error = join::run(
                &root,
                &raw_code,
                "管理电脑",
                true,
                now_unix,
                std::time::Duration::from_secs(5),
            )
            .expect_err("扫描区间内都被占时必须报错");
            assert_eq!(error.code, "LinePortUnavailable", "{error:?}");
            assert!(
                error.message.contains("端口"),
                "错误信息要说清是端口问题：{}",
                error.message
            );

            // 不写半份配置：config.json 逐字节不变、没有 lines 目录、没有 client.conf。
            assert_eq!(read(&cfg_path), before, "报错之后 config.json 被改动了");
            assert!(!root.join("lines").exists(), "报错之后不该有线路目录");
            for enrollment in crate::pairstore::list(&root).unwrap() {
                assert!(!crate::pairstore::has_config(&root, &enrollment.enrollment_id));
                assert_ne!(enrollment.state, "Completed");
            }
            let _ = server;
            let _ = std::fs::remove_dir_all(&root);
        }

        /// 收窄区间之后，「跳过已占端口、挑到那个空位」这件事必须仍然成立
        /// （否则上面那条「全占就报错」可能只是因为区间内本来就挑不出来）。
        #[test]
        fn qa_a_narrow_window_still_picks_the_one_free_port() {
            const LAST: u16 = line::FIRST_PORT + 10;
            let _window = line::force_port_window_for_test(line::FIRST_PORT, LAST);
            let hole = line::FIRST_PORT + 4;
            let mut cfg = line::empty_config();
            for port in line::FIRST_PORT..=LAST {
                if port == hole {
                    continue;
                }
                cfg.lines.push(LineConfig {
                    id: format!("taken-{port}"),
                    name: format!("占位 {port}"),
                    proxy_endpoint: format!("127.0.0.1:{port}"),
                    transport: None,
                    verified_transport: None,
                });
            }
            let picked = line::choose_port(&cfg, "fresh", None).expect("区间里留了一个空位");
            assert!(
                (line::FIRST_PORT..=LAST).contains(&picked),
                "只能在扫描区间里挑：{picked}"
            );
            assert_ne!(picked, line::FIRST_PORT, "第一个端口被占了，不该再选它");
            assert!(
                !cfg.lines.iter().any(|l| l.proxy_endpoint.ends_with(&format!(":{picked}"))),
                "挑到了别的线路正在用的端口：{picked}"
            );
        }

        /// `choose_port` 必须**真的试绑**（不是只看配置里记的端口），
        /// 且两条既有线路本来就撞端口时不许静默放过。
        ///
        /// 注意它承诺的只是「探测端口（+3）能绑」——**主端口自己从来没有被试绑过**。
        /// 这不是本用例的猜测，是实现的事实（`validate_probe_port_free` 只 bind `port+3`）；
        /// 所以这里只断言它能保证的那一条，另把「主端口可能已被别人占着」作为已知缺口回报。
        #[test]
        fn qa_choose_port_really_trial_binds_and_never_returns_a_taken_port() {
            const WINDOW: u16 = 40;
            // 把 17890..=17890+WINDOW 的探测端口（+3）全占住，即 17893..=17933。
            let mut held = Vec::new();
            for port in line::FIRST_PORT..=line::FIRST_PORT + WINDOW {
                let listener = std::net::TcpListener::bind(("127.0.0.1", port + 3))
                    .unwrap_or_else(|error| panic!("夹具绑不上 {}：{error}", port + 3));
                held.push(listener);
            }
            let highest_held = line::FIRST_PORT + WINDOW + 3;
            let highest_blocked_candidate = line::FIRST_PORT + WINDOW;

            // 配置里**没有**任何线路：让 choose_port 跳过前面那些候选口的唯一理由就是试绑失败。
            let cfg = line::empty_config();
            let picked = line::choose_port(&cfg, "fresh", None).expect("应当能找到空口");
            assert!(
                picked > highest_blocked_candidate,
                "试绑没生效：把 17890..={highest_blocked_candidate} 的探测端口（17893..={highest_held}）占住之后，仍然选了 {picked}"
            );
            // 它承诺的那一条必须成立：探测端口真的能绑（这就是「自检会不会永远跳过」的判据）。
            std::net::TcpListener::bind(("127.0.0.1", picked + 3))
                .expect("选出来的探测端口必须真的能绑");

            // 两条既有线路本来就撞同一个端口：新线路不许挑同一个。
            let mut clash = line::empty_config();
            for id in ["dup-a", "dup-b"] {
                clash.lines.push(LineConfig {
                    id: id.to_string(),
                    name: id.to_string(),
                    proxy_endpoint: format!("127.0.0.1:{}", line::FIRST_PORT + WINDOW + 10),
                    transport: None,
                    verified_transport: None,
                });
            }
            let other = line::choose_port(&clash, "fresh", None).expect("应当能找到空口");
            assert_ne!(
                other,
                line::FIRST_PORT + WINDOW + 10,
                "既有线路占着的端口被新的线路抢走了"
            );
            let taken: Vec<u16> = clash
                .lines
                .iter()
                .filter_map(|l| crate::selfcheck::port_from_endpoint(&l.proxy_endpoint))
                .collect();
            assert!(
                !taken.contains(&other),
                "新线路挑了一个已被占的口：{other}（已占：{taken:?}）"
            );
            // 同一条线路重试必须沿用原端口（否则系统代理会指向另一个口）。
            let existing = cfg_with_existing(17_955);
            assert_eq!(
                line::choose_port(&existing, "keep-a", Some(17_955)).unwrap(),
                17_955,
                "同一条线路重试必须沿用原端口"
            );
            // keep 指向别人正在用的端口时不许沿用。
            let stolen = line::choose_port(&existing, "keep-a", Some(17_956));
            assert!(
                !matches!(stolen, Ok(17_956)),
                "别的线路占着的端口被 keep 抢了回来：{stolen:?}"
            );
            drop(held);
        }

        /// `register` 只该改三件事：这条线路的内容、`selected`、以及（必要时）新增。
        /// 用户已有的其它线路与字段一个都不许动；同 id 再注册是**更新**不是新增。
        #[test]
        fn qa_register_updates_in_place_and_never_clobbers_other_fields() {
            let root = temp_root("qa-register");
            let mut cfg = cfg_with_existing(17_955);
            crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
            let body = line::build(
                &qa_conf(),
                None,
                17_960,
                Mode::Proxy,
                &SplitConfig::default(),
                &crate::config::AgentsConfig::default(),
            )
                .unwrap();

            let fresh = LineConfig {
                id: "new-line".to_string(),
                name: "新线路".to_string(),
                proxy_endpoint: "127.0.0.1:17960".to_string(),
                transport: None,
                verified_transport: None,
            };
            line::register(&root, &mut cfg, &fresh, &body, &crate::events::Origin::other())
                .expect("注册应当成功");

            let saved = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
                .unwrap()
                .unwrap();
            assert_eq!(saved.lines.len(), 3, "应当只多一条");
            assert_eq!(saved.selected, "new-line");
            assert_eq!(saved.mode, Mode::Proxy);
            assert_eq!(saved.auto_start, true);
            assert_eq!(saved.auto_connect, true);
            assert_eq!(saved.close_to_tray, true);
            assert_eq!(saved.quality_warning, false);
            assert_eq!(saved.split.domains.len(), 1, "分流规则被改动了：{:?}", saved.split);
            assert_eq!(saved.split.processes.len(), 1);
            assert_eq!(saved.exits.trade.as_deref(), Some("hk"));
            let keep_a = saved.lines.iter().find(|l| l.id == "keep-a").unwrap();
            assert_eq!(keep_a.proxy_endpoint, "127.0.0.1:17955");
            assert_eq!(keep_a.transport, Some(Transport::Tcp), "既有线路的连接方式被改掉了");
            assert_eq!(saved.lines.iter().filter(|l| l.id == "keep-b").count(), 1);

            // 同一条线路再注册（重试）：更新内容，不新增，也不动别人。
            let mut cfg = saved.clone();
            let mut updated = fresh.clone();
            updated.name = "改过的名字".to_string();
            updated.proxy_endpoint = "127.0.0.1:17961".to_string();
            updated.transport = Some(Transport::Tcp);
            line::register(
                &root,
                &mut cfg,
                &updated,
                &body,
                &crate::events::Origin::other(),
            )
            .expect("重复注册应当成功");
            let again = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
                .unwrap()
                .unwrap();
            assert_eq!(again.lines.len(), 3, "重复注册不该新增线路");
            let line = again.lines.iter().find(|l| l.id == "new-line").unwrap();
            assert_eq!(line.name, "改过的名字");
            assert_eq!(line.proxy_endpoint, "127.0.0.1:17961");
            assert_eq!(line.transport, Some(Transport::Tcp));
            assert_eq!(again.lines.iter().filter(|l| l.id == "keep-a").count(), 1);
            let _ = std::fs::remove_dir_all(&root);
        }

        // ---------- 畸形 client.conf ----------

        /// 畸形输入：要么拒（`InvalidClientConfig`），要么**按声明的语义**接受。
        /// 「静默接受一个错的值」是缺陷，所以每条接受的分支都断言解析结果本身。
        #[test]
        fn qa_malformed_client_conf_is_never_silently_accepted() {
            let request = qa_request();
            let good = tunnel::render(&qa_response(&request), QA_PRIVATE, &request).unwrap();
            let lf = good.replace("\r\n", "\n");

            // 只把**键与段名**写成大写：值本身（base64 密钥）区分大小写，不能跟着变。
            let upper_keys = format!(
                "[INTERFACE]\r\nPRIVATEKEY = {QA_PRIVATE}\r\nADDRESS = 10.99.7.2/32\r\n\
                 MTU = 1360\r\n\r\n[PEER]\r\nPUBLICKEY = {QA_SERVER_PUBLIC}\r\n\
                 ALLOWEDIPS = 0.0.0.0/0\r\nENDPOINT = 198.51.100.9:51820\r\n\
                 PERSISTENTKEEPALIVE = 25\r\n"
            );

            // 1) 换行风格与大小写：WireGuard 自己的工具链就是不区分，这里必须照办。
            for (label, text) in [
                ("CRLF", good.clone()),
                ("LF", lf.clone()),
                ("混合换行", good.replacen("\r\n", "\n", 2)),
                ("BOM", format!("\u{feff}{good}")),
                ("键与段名全大写", upper_keys),
                (
                    "注释与空行",
                    format!("# 头注释\r\n\r\n; 另一行注释\r\n{good}"),
                ),
            ] {
                let conf = line::parse_client_conf(&text)
                    .unwrap_or_else(|error| panic!("{label} 应当能解析：{error:?}"));
                assert_eq!(conf.address, "10.99.7.2", "{label}");
                assert_eq!(conf.endpoint_port, 51820, "{label}");
                assert_eq!(conf.public_key, QA_SERVER_PUBLIC, "{label}");
                assert_eq!(conf.allowed_ips, vec!["0.0.0.0/0".to_string()], "{label}");
            }

            // 2) 重复键：取最后一个（与 wireguard 工具链一致）。这条是「接受的语义」，
            //    所以断言到底取了哪一个，而不是只断言不报错。
            let duplicated = good.replace(
                QA_PRIVATE,
                &format!("{QA_PRIVATE}\r\nPrivateKey = {QA_CLIENT_PUBLIC}"),
            );
            let conf = line::parse_client_conf(&duplicated).expect("重复键应当能解析");
            assert_eq!(
                conf.private_key, QA_CLIENT_PUBLIC,
                "重复键必须取最后一个（wireguard 的语义）"
            );

            // 3) 必须拒的：错的地址/端口/路由形状、域名端点、IPv6 端点、畸形结构。
            let cases: Vec<(&str, String)> = vec![
                ("端点写成域名", good.replace("198.51.100.9:51820", "vpn.example.net:51820")),
                ("端点写成 IPv6", good.replace("198.51.100.9:51820", "[2001:db8::9]:51820")),
                ("端点缺端口", good.replace("198.51.100.9:51820", "198.51.100.9")),
                ("AllowedIPs 多段", good.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8")),
                ("地址多段", good.replace("10.99.7.2/32", "10.99.7.2/32, 10.99.7.3/32")),
                ("地址带前导零", good.replace("10.99.7.2/32", "10.99.7.02/32")),
                ("私钥为空", good.replace(&format!("PrivateKey = {QA_PRIVATE}"), "PrivateKey = ")),
                ("键在段外", format!("PrivateKey = {QA_PRIVATE}\r\n{good}")),
                ("空文件", String::new()),
                ("只有注释", "; 什么都没有\r\n".to_string()),
                ("非 INI 的垃圾", "{\"a\": 1}\r\n".to_string()),
                ("超长垃圾行", "A".repeat(1024 * 1024)),
                ("段名没闭合", good.replace("[Peer]", "[Peer")),
            ];
            for (label, text) in cases {
                let error = line::parse_client_conf(&text).expect_err(label);
                assert_eq!(error.code, "InvalidClientConfig", "{label}：{error:?}");
            }

            // 4) 两个 [Interface] 段：只认第一个（`sections()` 取第一个同名段）。
            //    同样是可接受的 INI 语义，但要钉住——否则改成「合并」没人发现。
            let two_interfaces = format!("{good}\r\n[Interface]\r\nMTU = 9000\r\n");
            let conf = line::parse_client_conf(&two_interfaces).expect("第二个 [Interface] 只被忽略");
            assert_eq!(conf.mtu, Some(1360), "必须只认第一个 [Interface] 的 MTU");

            // 4) 两个 [Peer] 段：只认第一个。这是「静默忽略第二段」，属于可接受的 INI 语义
            //    （本产品的 client.conf 由服务器生成，只有一个 peer），但**必须钉住**，
            //    否则哪天实现改成「合并两个 peer」没人发现。
            let two_peers = format!(
                "{good}\r\n[Peer]\r\nPublicKey = {QA_PRIVATE}\r\nAllowedIPs = 10.0.0.0/8\r\nEndpoint = 203.0.113.1:1\r\n"
            );
            let conf = line::parse_client_conf(&two_peers).expect("第二个 [Peer] 只被忽略");
            assert_eq!(conf.public_key, QA_SERVER_PUBLIC, "必须只认第一个 [Peer]");
            assert_eq!(conf.endpoint_host, "198.51.100.9");
        }

        // ---------- 变异探针 ----------

        /// 两个 wireguard endpoint 的线路（旧版的多节点形态）。
        ///
        /// 这条用例的价值全在两个断言上：
        /// - 「**每个** endpoint 都有 detour」→ 变异「只给第一个挂」必须红；
        /// - 「中转出站在数组**第一个**」→ 变异「插到末尾」必须红。
        #[test]
        fn qa_a_two_node_line_puts_the_transit_first_and_on_every_endpoint() {
            let root = temp_root("qa-two-nodes");
            let split = SplitConfig::default();
            let body = line::build(
                &qa_conf(),
                Some(&qa_compatible()),
                17_892,
                Mode::Proxy,
                &split,
                &crate::config::AgentsConfig::default(),
            )
                .expect("两节点线路必须能生成");
            let mut value: Value = serde_json::from_str(&body).unwrap();
            let mut second = value["endpoints"][0].clone();
            second["tag"] = json!("hk-2");
            second["address"] = json!(["10.99.7.3/32"]);
            second["peers"][0]["allowed_ips"] = json!(["0.0.0.0/0"]);
            value["endpoints"].as_array_mut().unwrap().push(second);
            // 选择器也要能选到第二个节点，否则这份夹具不像真线路。
            for outbound in value["outbounds"].as_array_mut().unwrap() {
                if outbound["tag"] == engine_config::TRADE_EXIT {
                    outbound["outbounds"] = json!(["hk", "hk-2"]);
                }
            }
            let line_path = root.join("two.json");
            std::fs::write(&line_path, serde_json::to_string(&value).unwrap()).unwrap();

            let runtime = engine_config::prepare_engine_config(
                &line_path,
                &split,
                &crate::config::AgentsConfig::default(),
                Transport::Tcp,
                Mode::Proxy,
                &root.join("runtime.json"), "" ,
                None,
                None,
            )
            .expect("两节点线路必须能派生兼容档");
            let rt: Value = serde_json::from_str(&read(&runtime)).unwrap();

            let wg = wireguard_of(&rt);
            assert_eq!(wg.len(), 2, "夹具必须有两个 wireguard endpoint，否则「只挂第一个」测不出来");
            for endpoint in &wg {
                assert_eq!(
                    endpoint["detour"], engine_config::TRANSPORT_TAG,
                    "每个 endpoint 都必须挂中转（只挂一部分的线路是半个兼容档）：{endpoint}"
                );
            }
            let outbounds = rt["outbounds"].as_array().unwrap();
            assert_eq!(
                outbounds[0]["tag"], engine_config::TRANSPORT_TAG,
                "中转出站必须在数组第一个：{}",
                outbounds[0]
            );
            assert_eq!(
                outbounds
                    .iter()
                    .filter(|o| o["tag"] == engine_config::TRANSPORT_TAG)
                    .count(),
                1,
                "中转出站不许重复"
            );
            assert_eq!(
                engine_config::actual_transport(&runtime),
                Some(Transport::Tcp),
                "派生出来的必须是完整的兼容档"
            );
            let (code, output) = engine_check(&runtime);
            assert_eq!(code, 0, "引擎不接受两节点兼容档：\n{output}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    // ---- 离线交接（r67） ----

    /// `seal_to_public` 用的是 NoPadding，测试要自己按 PKCS#7 补齐——
    /// 生产服务器由 openssl 默认补，客户端解封时只认 PKCS#7。
    fn pkcs7(mut body: Vec<u8>) -> Vec<u8> {
        let pad = 16 - body.len() % 16;
        body.extend(std::iter::repeat(pad as u8).take(pad));
        body
    }

    fn offline_authorization(
        key: &RsaPrivateKey,
        enrollment: &crate::pairstore::Enrollment,
        recipient: &jwk::RsaJwk,
        request_id_override: Option<&str>,
    ) -> String {
        let text = |value: &Value, key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let client_public = text(&enrollment.client_request, "ClientPublicKey");
        let device = text(&enrollment.client_request, "DeviceId");
        let request_id = request_id_override
            .map(str::to_string)
            .unwrap_or_else(|| text(&enrollment.client_request, "RequestId"));
        let mut response = response_ok();
        response["RequestId"] = json!(request_id);
        response["DeviceId"] = json!(device);
        response["ClientPublicKey"] = json!(client_public);
        response["NodeId"] = json!("node-1");
        let authorization = json!({
            "SchemaVersion": 1,
            "Kind": "TradeChannel.PairAuthorization",
            "InviteId": enrollment.invite_id,
            "ServerBinding": enrollment.server_binding,
            "RemoteOwnerId": "owner-1",
            "NodeId": "node-1",
            "RequestId": request_id,
            "DeviceId": device,
            "ClientPublicKey": client_public,
            "RequestDigest": enrollment.request_digest,
            "RequestDigestAlgorithm": "TC-ClientRequest-v1",
            "ClientAddress": "10.66.0.2/32",
            "ConfigRevision": 1,
            "ClientResponse": response,
        });
        let signed = sign(&authorization, key);
        let header = json!({
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "cty": "TC-Pairing-v1",
        });
        seal_to_public(&pkcs7(signed.into_bytes()), &recipient.public_key().unwrap(), &header)
    }

    #[test]
    fn offline_prepare_verifies_the_invitation_and_reuses_the_request() {
        let key = keypair();
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        let invite = sign(&invite_payload(&key), &key);
        let root = temp_root("offline-prepare");

        let prepared = offline::prepare(&root, &invite, &fingerprint, "新电脑", now())
            .expect("离线申请应当生成");
        assert!(!prepared.enrollment_id.is_empty());
        assert_eq!(prepared.invite_id, "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        assert_eq!(prepared.pairing_code.len(), 12);
        assert_eq!(prepared.pairing_code, prepared.pairing_code.to_ascii_uppercase());
        let payload = request::verify(&prepared.request_text, now()).expect("申请必须自洽");
        assert_eq!(payload["InviteId"], "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b");
        assert_eq!(payload["DeviceName"], "新电脑");

        // 同一个邀请再申请一次必须复用原申请：不能在服务器上变成第二台设备。
        let again = offline::prepare(&root, &invite, &fingerprint, "新电脑", now()).unwrap();
        assert!(again.resumed);
        assert_eq!(again.enrollment_id, prepared.enrollment_id);
        assert_eq!(again.request_text, prepared.request_text);

        // 指纹不对/邀请过期都必须拒绝。
        let wrong = offline::prepare(&root, &invite, "SHA256:wrong", "新电脑", now()).unwrap_err();
        assert_eq!(wrong.code, "InviteTrustRequired");
        let mut expired = invite_payload(&key);
        expired["IssuedAtUtc"] = json!(stamp(now() - 7200));
        expired["ExpiresAtUtc"] = json!(stamp(now() - 60));
        let expired = sign(&expired, &key);
        let error = offline::inspect(&expired, now()).unwrap_err();
        assert_eq!(error.code, "InviteExpired");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn offline_complete_opens_only_an_authorization_for_this_request() {
        let key = keypair();
        let fingerprint = jwk::RsaJwk::parse(&jwk_value(&key)).unwrap().fingerprint();
        let invite = sign(&invite_payload(&key), &key);
        let root = temp_root("offline-complete");
        let prepared = offline::prepare(&root, &invite, &fingerprint, "新电脑", now()).unwrap();
        let enrollment = crate::pairstore::load(&root, &prepared.enrollment_id).unwrap();
        let request_payload = request::verify(&prepared.request_text, now()).unwrap();
        let recipient = jwk::RsaJwk::parse(&request_payload["RecipientJwk"]).unwrap();

        // 先喂一份「申请编号被换掉」的授权：必须被拒，且不能写任何线路。
        let tampered = offline_authorization(&key, &enrollment, &recipient, Some("other-request"));
        let error = offline::complete(
            &root,
            &prepared.enrollment_id,
            &tampered,
            Some("离线线路"),
            now(),
            &crate::events::Origin::ui(),
        )
        .unwrap_err();
        assert_eq!(error.code, "OnlineAuthorizationMismatch");
        assert!(!root.join("identities").join(&prepared.enrollment_id).join("client.conf").exists());

        let sealed = offline_authorization(&key, &enrollment, &recipient, None);
        let outcome = offline::complete(
            &root,
            &prepared.enrollment_id,
            &sealed,
            Some("离线线路"),
            now(),
            &crate::events::Origin::ui(),
        )
        .expect("离线授权应当完成加入");
        assert_eq!(outcome.line_name, "离线线路");
        assert!(!outcome.line_id.is_empty());
        assert!(root
            .join("identities")
            .join(&prepared.enrollment_id)
            .join("client.conf")
            .exists());
        let cfg = crate::config::load(&root.join(crate::config::DEFAULT_PATH))
            .unwrap()
            .expect("加入后必须留下配置");
        assert!(cfg.lines.iter().any(|line| line.id == outcome.line_id));
        assert_eq!(
            crate::pairstore::load(&root, &prepared.enrollment_id).unwrap().state,
            crate::pairstore::STATE_COMPLETED
        );

        // 已经完成的申请不能重复导入。
        let again = offline::complete(
            &root,
            &prepared.enrollment_id,
            &sealed,
            Some("离线线路"),
            now(),
            &crate::events::Origin::ui(),
        )
        .unwrap_err();
        assert_eq!(again.code, "EnrollmentCompleted");
        let _ = std::fs::remove_dir_all(&root);
    }
}
