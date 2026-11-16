//! 无引擎 UDP 直探：发一次真实的 WireGuard 握手，按有没有回包判断标准连接通不通。
//!
//! 为什么要它：`autoroute` 原来靠临时引擎探测，一次约 5 秒（引擎启动 + 握手 + HTTP）。
//! 判断「UDP 端口有没有人应答」根本不需要引擎：WireGuard 的握手本身就是一次
//! 148 字节的 UDP 请求，服务端验完 MAC1 与密钥后必回 92 字节响应。
//!
//! 只做到「收到响应」为止：不解析响应密钥、不建隧道、不发数据。收到响应说明
//! 对端在、密钥对得上、路径没被拦——这正是候选探测需要的全部事实。
//!
//! 绑定网卡：调用方给一个本机源地址时，探测 socket 绑到这个地址上。Windows 上
//! 绑定源地址等价于指定出口网卡；换网卡（Wi-Fi/有线切换）会得到不同的探测路径。

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use blake2::digest::{consts::U16, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard 握手消息的固定前缀。两串都来自协议白皮书，不能改。
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// HMAC-BLAKE2s（块长 64）。WireGuard 的 KDF 就是 HMAC-BLAKE2s，没有别的花样。
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block.copy_from_slice(&hash(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(data);
    let inner_hash = hash(&[&inner]);
    let outer: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    hash(&[&outer, &inner_hash])
}

/// KDF1：先 HMAC 出 prk，再 `HMAC(prk, 0x1)`。返回的是**第二次** HMAC。
///
/// 这一步不能靠直觉写：WireGuard 的 KDF 是带计数器的两段/三段 HKDF，
/// 第一段 `HMAC(key, input)` 只是 prk，从不直接作为输出。
fn kdf1(chaining: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let prk = hmac(chaining, input);
    hmac(&prk, &[0x01])
}

/// KDF2：返回两个 32 字节值——新的链键 `HMAC(prk, 0x01)` 与 AEAD 密钥
/// `HMAC(prk, T0 || 0x02)`。
fn kdf2(chaining: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac(chaining, input);
    let t0 = hmac(&prk, &[0x01]);
    let mut message = Vec::with_capacity(33);
    message.extend_from_slice(&t0);
    message.push(0x02);
    let t1 = hmac(&prk, &message);
    (t0, t1)
}

fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| "WireGuard 握手密钥长度不对".to_string())?;
    let key = LessSafeKey::new(unbound);
    // 握手阶段所有 AEAD 的计数器都是 0；协议规定 nonce 是 12 字节小端计数。
    let nonce = [0u8; 12];
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut buffer,
    )
    .map_err(|_| "WireGuard 握手加密失败".to_string())?;
    Ok(buffer)
}

fn mac1(key: &[u8], data: &[u8]) -> Result<[u8; 16], String> {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .map_err(|_| "WireGuard MAC1 密钥长度不对".to_string())?;
    Mac::update(&mut mac, data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// TAI64N 时间戳（12 字节）。服务端只用它做单调性检查，取系统时间即可。
fn tai64n_now() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = 0x4000_0000_0000_000a_u64
        .wrapping_add(now.as_secs());
    let mut stamp = [0u8; 12];
    stamp[..8].copy_from_slice(&seconds.to_be_bytes());
    stamp[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    stamp
}

fn decode_key(text: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| "WireGuard 密钥不是合法的 base64".to_string())?;
    if bytes.len() != 32 {
        return Err("WireGuard 密钥不是 32 字节".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// 构造一条握手发起消息。分离出来是为了单测能在不联网的情况下检查字段。
///
/// `sender_index` / `ephemeral` 由调用方给：真实探测用随机值，单测用固定值才能断言。
pub fn build_initiation(
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    sender_index: u32,
    ephemeral_private: &[u8; 32],
) -> Result<Vec<u8>, String> {
    build_initiation_at(
        client_private,
        server_public,
        sender_index,
        ephemeral_private,
        tai64n_now(),
    )
}

/// 与 [`build_initiation`] 相同，但时间戳由调用方给：单测要固定输入才能对齐参考实现。
pub fn build_initiation_at(
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    sender_index: u32,
    ephemeral_private: &[u8; 32],
    timestamp: [u8; 12],
) -> Result<Vec<u8>, String> {
    let client_secret = StaticSecret::from(*client_private);
    let client_public = PublicKey::from(&client_secret);
    let server = PublicKey::from(*server_public);
    let ephemeral_secret = StaticSecret::from(*ephemeral_private);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // 初始化两条派生（与 wireguard-go 的 init() 逐行对齐）：
    // - 链键 = HASH(construction)；
    // - 握手哈希 = HASH(链键 || identifier)。
    let mut chaining = hash(&[CONSTRUCTION]);
    let mut handshake = hash(&[&chaining, IDENTIFIER]);
    // 发起方的第一件事是把对端静态公钥混进哈希（wireguard-go 的 mixHash(remoteStatic)）。
    handshake = hash(&[&handshake, server.as_bytes()]);

    // KDF1 只前进一步链键（与 wireguard-go 的 mixKey 一致）。
    chaining = kdf1(&chaining, ephemeral_public.as_bytes());

    let mut message = vec![0u8; INITIATION_LEN];
    message[0] = 1;
    message[4..8].copy_from_slice(&sender_index.to_le_bytes());
    message[8..40].copy_from_slice(ephemeral_public.as_bytes());
    handshake = hash(&[&handshake, ephemeral_public.as_bytes()]);

    let (next, key) = kdf2(&chaining, ephemeral_secret.diffie_hellman(&server).as_bytes());
    chaining = next;
    let encrypted_static = seal(&key, client_public.as_bytes(), &handshake)?;
    message[40..88].copy_from_slice(&encrypted_static);
    handshake = hash(&[&handshake, &encrypted_static]);

    let (_, key) = kdf2(&chaining, client_secret.diffie_hellman(&server).as_bytes());
    let encrypted_time = seal(&key, &timestamp, &handshake)?;
    message[88..116].copy_from_slice(&encrypted_time);

    let key = hash(&[LABEL_MAC1, server.as_bytes()]);
    let tag = mac1(&key, &message[..116])?;
    message[116..132].copy_from_slice(&tag);
    // mac2 保持全零：没有 cookie 时协议就是这么要求的。
    Ok(message)
}

/// 判断一段回包是不是对 `sender_index` 的响应（或 cookie 回复）。
///
/// 只认这两种：其余长度/类型的包一律当作噪声，不能凭「收到过任何 UDP 包」就判通。
pub fn accepts_response(bytes: &[u8], sender_index: u32) -> bool {
    match bytes.len() {
        RESPONSE_LEN if bytes[0] == 2 => {
            let receiver = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            receiver == sender_index
        }
        COOKIE_REPLY_LEN if bytes[0] == 3 => {
            let receiver = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            receiver == sender_index
        }
        _ => false,
    }
}

/// 发一次握手并等响应，返回耗时（毫秒）。
///
/// `bind_ip` 是探测 socket 的本机源地址；为 `None` 时由系统选路。绑定失败会退回
/// 系统选路——宁可测到，也不要因为一个可选优化把探测变成「不可达」。
pub fn handshake(
    host: &str,
    port: u16,
    client_private_b64: &str,
    server_public_b64: &str,
    bind_ip: Option<IpAddr>,
    timeout: Duration,
) -> Result<u64, String> {
    let client_private = decode_key(client_private_b64)?;
    let server_public = decode_key(server_public_b64)?;
    let address: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|_| format!("WireGuard 端点不是合法的 IPv4 地址：{host}:{port}"))?;

    let mut random = [0u8; 36];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "取不到随机数，无法发起 WireGuard 握手".to_string())?;
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&random[..32]);
    let sender_index = u32::from_le_bytes([random[32], random[33], random[34], random[35]]);

    let message = build_initiation(&client_private, &server_public, sender_index, &ephemeral)?;

    let bind = match bind_ip {
        Some(IpAddr::V4(ip)) => SocketAddr::from((ip, 0)),
        _ => SocketAddr::from(([0, 0, 0, 0], 0)),
    };
    let socket = UdpSocket::bind(bind)
        .or_else(|_| UdpSocket::bind(("0.0.0.0", 0)))
        .map_err(|error| format!("建不了 UDP 探测 socket：{error}"))?;
    socket
        .connect(address)
        .map_err(|error| format!("UDP 探测连不上 {address}：{error}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("设置探测超时失败：{error}"))?;

    let started = Instant::now();
    let deadline = started + timeout;
    let mut buffer = [0u8; 256];
    // 首次发送后没回就每 800 ms 再发一次：UDP 丢一个包不等于端口不通，
    // 而「判不可达」的代价是让用户白等一次完整引擎探测。
    loop {
        socket
            .send(&message)
            .map_err(|error| format!("WireGuard 握手发不出去：{error}"))?;
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(800));
        if wait.is_zero() {
            return Err(format!(
                "WireGuard 握手在 {} ms 内没有响应",
                timeout.as_millis()
            ));
        }
        socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("设置探测超时失败：{error}"))?;
        match socket.recv(&mut buffer) {
            Ok(size) if accepts_response(&buffer[..size], sender_index) => {
                return Ok(started.elapsed().as_millis() as u64);
            }
            // 不是我们的包（或长度不对）：继续等/重发，直到超时。
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("WireGuard 握手失败：{error}")),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "WireGuard 握手在 {} ms 内没有响应",
                timeout.as_millis()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const SERVER_PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    /// 与一份**独立实现**逐字节对齐：Python `cryptography`（X25519 + ChaCha20Poly1305）
    /// 加 `hashlib.blake2s`/`hmac` 对同一组固定输入算出的完整 148 字节。
    ///
    /// 这条用例的代价很小，但它能把「服务端不回」从真机猜测变成一次本地断言：
    /// 派生顺序、KDF 计数器、AEAD 的 AAD、MAC1 任何一处写错都会在这里红。
    #[test]
    fn matches_an_independent_reference_vector() {
        const EXPECTED: &str = "01000000443322118f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285fb8cd7c9e33b45255a30ae670d54d230ecf22fb78b9db46f431877d26114944820d77e8a2a30c90873377cb233a608100ff1433bdd691cec5e95c0a1b78262060d5bdca827c3f395ea668d80537160d1a5f9656bca6178be4dfca2c3000000000000000000000000000000000";
        let client = decode_key(CLIENT_PRIVATE).unwrap();
        let server = decode_key(SERVER_PUBLIC).unwrap();
        let ephemeral: [u8; 32] = core::array::from_fn(|index| index as u8);
        let timestamp: [u8; 12] = core::array::from_fn(|index| (index + 1) as u8);
        let message =
            build_initiation_at(&client, &server, 0x11223344, &ephemeral, timestamp).unwrap();
        let hex: String = message
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, EXPECTED);
    }

    #[test]
    fn a_handshake_initiation_has_the_fields_the_protocol_requires() {
        let client = decode_key(CLIENT_PRIVATE).unwrap();
        let server = decode_key(SERVER_PUBLIC).unwrap();
        let eph = [7u8; 32];
        let message = build_initiation(&client, &server, 0x11223344, &eph).unwrap();
        assert_eq!(message.len(), INITIATION_LEN);
        assert_eq!(message[0], 1, "类型必须是握手发起");
        assert_eq!(&message[1..4], &[0, 0, 0], "保留位必须为零");
        assert_eq!(
            u32::from_le_bytes([message[4], message[5], message[6], message[7]]),
            0x11223344
        );
        let ephemeral_public = PublicKey::from(&StaticSecret::from(eph));
        assert_eq!(&message[8..40], ephemeral_public.as_bytes());
        // 前三段可复现（时间戳那一段每次不同，不能拿来比较）。
        let again = build_initiation(&client, &server, 0x11223344, &eph).unwrap();
        assert_eq!(message[..88], again[..88], "固定输入应可复现");
        assert_ne!(&message[40..72], PublicKey::from(&StaticSecret::from(client)).as_bytes());
        // mac1 非零、mac2 全零。
        assert!(message[116..132].iter().any(|byte| *byte != 0), "{message:?}");
        assert!(message[132..148].iter().all(|byte| *byte == 0), "{message:?}");
    }

    #[test]
    fn changing_the_ephemeral_key_changes_the_whole_body() {
        let client = decode_key(CLIENT_PRIVATE).unwrap();
        let server = decode_key(SERVER_PUBLIC).unwrap();
        let first = build_initiation(&client, &server, 1, &[1u8; 32]).unwrap();
        let second = build_initiation(&client, &server, 1, &[2u8; 32]).unwrap();
        assert_ne!(first[8..116], second[8..116], "临时密钥必须真正参与加密");
    }

    #[test]
    fn only_a_response_for_our_index_counts() {
        let mut response = vec![0u8; RESPONSE_LEN];
        response[0] = 2;
        response[8..12].copy_from_slice(&42u32.to_le_bytes());
        assert!(accepts_response(&response, 42));
        assert!(!accepts_response(&response, 43), "别人的响应不能算通");
        assert!(!accepts_response(&[0u8; 12], 42), "长度不对的包不能算通");
        response[0] = 4;
        assert!(!accepts_response(&response, 42), "未知类型不能算通");
        let mut cookie = vec![0u8; COOKIE_REPLY_LEN];
        cookie[0] = 3;
        cookie[4..8].copy_from_slice(&42u32.to_le_bytes());
        assert!(accepts_response(&cookie, 42), "cookie 回复也证明对端在");
    }

    #[test]
    fn tai64n_is_twelve_bytes_and_monotonic_enough() {
        let first = tai64n_now();
        assert_eq!(first.len(), 12);
        let seconds = u64::from_be_bytes(first[..8].try_into().unwrap());
        assert!(seconds > 0x4000_0000_0000_000a, "秒域要带 TAI64 偏移");
    }

    /// 对真实服务器发一次握手。默认忽略：它需要一份本机才有的 `client.conf`。
    ///
    /// 运行方式（PowerShell）：
    ///   $env:TC_WG_PROBE_CONF="...\client.conf"
    ///   cargo test --bin spidervpn -- --ignored real_handshake_against_the_server
    #[test]
    #[ignore]
    fn real_handshake_against_the_server() {
        let path = std::env::var("TC_WG_PROBE_CONF").expect("要设置 TC_WG_PROBE_CONF");
        let text = std::fs::read_to_string(path).expect("读不到 client.conf");
        let conf = crate::pairing::line::parse_client_conf(&text).expect("client.conf 不合法");
        let bind = if std::env::var("TC_WG_PROBE_BIND").is_ok() {
            crate::autoroute::network_info()
                .source_ip
                .parse::<std::net::IpAddr>()
                .ok()
        } else {
            None
        };
        println!("BIND={bind:?}");
        let elapsed = handshake(
            &conf.endpoint_host,
            conf.endpoint_port,
            &conf.private_key,
            &conf.public_key,
            bind,
            Duration::from_secs(8),
        )
        .expect("服务器应该回一条握手响应");
        assert!(elapsed < 8_000, "握手耗时异常：{elapsed} ms");
    }
}
