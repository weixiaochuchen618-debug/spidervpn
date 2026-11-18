//! SEC-02 untrusted one-message HTTP/1.1 framing on an existing DeadlineIo.
//! NOT a TLS listener, HTTP responder, authentication or import authority.
//! The caller must provide real independently validated TLS and close after
//! exactly one response. Bytes after one parsed request are never dispatched.
//! Limits are fixed, not drawn from a legacy JSON config or remote request.
#![cfg(all(target_os = "linux", feature = "linux-handshake-admission"))]

use crate::handshake_admission::DeadlineIo;
use std::fmt;
use std::io::{self, Read};

pub const MAX_BODY_BYTES: usize = 131_072; // deployed Python PAIR_LIMIT
pub const MAX_HEADER_BYTES: usize = 16_384;
pub const MAX_HEADER_LINE: usize = 4_096;
pub const MAX_REQUEST_LINE: usize = 2_048;
pub const MAX_HEADER_FIELDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method { Get, Post }

/// Explicitly untrusted data. In particular Authorization is NOT verified.
/// Debug redacts bearer token and raw POST body to avoid accidental logging.
pub struct ParsedRequest {
    pub method: Method,
    pub target: String,
    pub body: Vec<u8>,
    pub authorization: Option<String>,
}
impl fmt::Debug for ParsedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("body_len", &self.body.len())
            .field("authorization_present", &self.authorization.is_some())
            .finish()
    }
}
fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// No read-ahead into pipelined request bytes; rejects bare LF and embedded CR.
fn crlf_line(io: &mut DeadlineIo, max: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut b = [0u8];
        io.read_exact(&mut b)?;
        match b[0] {
            b'\r' => {
                io.read_exact(&mut b)?;
                if b[0] != b'\n' { return Err(invalid("SEC-02 invalid CRLF")); }
                return Ok(line);
            }
            b'\n' | 0 => return Err(invalid("SEC-02 bare LF/NUL")),
            v => {
                if line.len() == max { return Err(invalid("SEC-02 line over limit")); }
                line.push(v);
            }
        }
    }
}
fn request_line(line: &[u8]) -> io::Result<(Method, String)> {
    let parts: Vec<_> = line.split(|c| *c == b' ').collect();
    if parts.len() != 3 || parts[2] != b"HTTP/1.1" || parts[1].first() != Some(&b'/')
        || parts[1].iter().any(|b| !b.is_ascii_graphic() || *b == b'#' || *b == b'\\')
    { return Err(invalid("SEC-02 malformed HTTP/1.1 request line")); }
    let method = match parts[0] {
        b"GET" => Method::Get,
        b"POST" => Method::Post,
        _ => return Err(invalid("SEC-02 unsupported method")),
    };
    let target = String::from_utf8(parts[1].to_vec())
        .map_err(|_| invalid("SEC-02 non-ASCII target"))?;
    Ok((method, target))
}
fn header(line: &[u8]) -> io::Result<(&[u8], &[u8])> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(invalid("SEC-02 obs-fold denied"));
    }
    let pos = line.iter().position(|b| *b == b':')
        .ok_or_else(|| invalid("SEC-02 header lacks colon"))?;
    let name = &line[..pos];
    if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric()
        || *b == b'-' || *b == b'_')
    { return Err(invalid("SEC-02 invalid header name")); }
    let value = &line[pos + 1..];
    if value.iter().any(|b| !(*b == b'\t' || (0x20..=0x7e).contains(b))) {
        return Err(invalid("SEC-02 invalid header controls/characters"));
    }
    Ok((name, value.strip_prefix(b" ").unwrap_or(value)))
}
fn parse_length(raw: &[u8]) -> io::Result<usize> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return Err(invalid("SEC-02 nondecimal Content-Length"));
    }
    let mut len = 0usize;
    for b in raw {
        len = len.checked_mul(10)
            .and_then(|x| x.checked_add(usize::from(*b - b'0')))
            .ok_or_else(|| invalid("SEC-02 Content-Length overflow"))?;
        if len > MAX_BODY_BYTES { return Err(invalid("SEC-02 body too long")); }
    }
    Ok(len)
}

/// Decode exactly one bounded HTTP/1.1 message from already protected IO.
/// A real caller must complete TLS authentication first, reject invalid Host
/// binding, verify bearer/Revoked state and emit one JSON response then close.
/// This pure decoder neither grants privileges nor generates responses.
///
/// POST: exactly one Content-Length in 1..=131072; Transfer-Encoding denied.
/// GET: no body (Content-Length absent or 0). HTTP Host exactly once.
/// Duplicate CL/Host/Auth, obs-fold, Expect, Upgrade and malformed CRLF fail.
/// An extra pipelined request is left unread and must be dropped on close.
pub fn read_one_request(io: &mut DeadlineIo) -> io::Result<ParsedRequest> {
    let (method, target) = request_line(&crlf_line(io, MAX_REQUEST_LINE)?)?;
    let mut bytes = 0usize;
    let mut fields = 0usize;
    let mut host = false;
    let mut length = None;
    let mut authorization = None;
    loop {
        let line = crlf_line(io, MAX_HEADER_LINE)?;
        bytes = bytes.checked_add(line.len() + 2)
            .ok_or_else(|| invalid("SEC-02 header length overflow"))?;
        if bytes > MAX_HEADER_BYTES { return Err(invalid("SEC-02 header block too long")); }
        if line.is_empty() { break; }
        fields += 1;
        if fields > MAX_HEADER_FIELDS { return Err(invalid("SEC-02 too many headers")); }
        let (name, value) = header(&line)?;
        if name.eq_ignore_ascii_case(b"host") {
            if host || value.is_empty() || !value.iter().all(u8::is_ascii_graphic) {
                return Err(invalid("SEC-02 duplicate/bad Host"));
            }
            host = true;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() { return Err(invalid("SEC-02 duplicate Content-Length")); }
            length = Some(parse_length(value)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(invalid("SEC-02 transfer encoding disallowed"));
        } else if name.eq_ignore_ascii_case(b"expect")
            || name.eq_ignore_ascii_case(b"upgrade") {
            return Err(invalid("SEC-02 expectation/upgrade disallowed"));
        } else if name.eq_ignore_ascii_case(b"authorization") {
            if authorization.is_some() || value.is_empty() {
                return Err(invalid("SEC-02 duplicate/empty Authorization"));
            }
            authorization = Some(std::str::from_utf8(value)
                .map_err(|_| invalid("SEC-02 invalid Authorization"))?.to_owned());
        }
    }
    if !host { return Err(invalid("SEC-02 missing Host")); }
    let count = match method {
        Method::Get => {
            if length.unwrap_or(0) != 0 {
                return Err(invalid("SEC-02 GET with body"));
            }
            0
        }
        Method::Post => match length {
            Some(1..=MAX_BODY_BYTES) => length.unwrap_or(0),
            _ => return Err(invalid("SEC-02 POST requires bounded nonempty body")),
        },
    };
    let mut body = vec![0u8; count];
    io.read_exact(&mut body)?;
    Ok(ParsedRequest { method, target, body, authorization })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
    use std::io::Write;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::time::Duration;
    fn connection() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (l.accept().unwrap().0, c)
    }
    /// Real loopback TCP, actual worker permits, actual request deadlines.
    /// Handshake closure is intentionally a stub: NOT a TLS protocol test.
    fn parse_wire(wire: &[u8]) -> io::Result<ParsedRequest> {
        let hand = HandshakeAdmission::new(1, Duration::from_secs(3)).unwrap();
        let req = RequestAdmission::new(1, Duration::from_secs(3)).unwrap();
        let (server, mut client) = connection();
        let work = hand.spawn_one_request(
            &req, server, |_io| Ok::<(), io::Error>(()),
            |io, ()| read_one_request(io),
        ).unwrap();
        client.write_all(wire).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let result = work.join().unwrap();
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(req.active_requests(), 0);
        result
    }
    fn rejects(wire: &[u8]) {
        assert!(parse_wire(wire).is_err(), "unsafe request accepted");
    }
    #[test]
    fn get_and_post_real_tcp_preserve_untrusted_bounded_input_redact_secret() {
        let get = parse_wire(b"GET /v1/invitations/abc?status=1 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret123\r\nConnection: keep-alive\r\n\r\n").unwrap();
        assert_eq!(get.method, Method::Get);
        assert_eq!(get.target, "/v1/invitations/abc?status=1");
        assert_eq!(get.authorization.as_deref(), Some("Bearer secret123"));
        assert!(!format!("{get:?}").contains("secret123"));
        let post = parse_wire(b"POST /v1/invitations/x/consume HTTP/1.1\r\nhOsT: server.test\r\nCONTENT-Length: 4\r\nContent-Type: application/json\r\n\r\nABCD").unwrap();
        assert_eq!(post.method, Method::Post);
        assert_eq!(post.body, b"ABCD");
        assert!(post.authorization.is_none());
    }
    #[test]
    fn ambiguous_content_length_duplicate_empty_negative_or_overflow_denied() {
        for wire in [
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1,1\r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1 \r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 184467440737095516160\r\n\r\na"[..],
        ] { rejects(wire); }
    }
    #[test]
    fn chunked_expect_upgrade_and_http_smuggling_rejected() {
        for wire in [
            &b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\r\nContent-Length: 1\r\n\r\na"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\na"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"[..],
        ] { rejects(wire); }
    }
    #[test]
    fn request_line_and_crlf_malformed_methods_and_versions_denied() {
        for wire in [
            &b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"[..],
            &b"DELETE / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"GET https://example.test/ HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"GET /#fragment HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"GET / HTTP/1.1\nHost: x\n\n"[..],
            &b"GET / HTTP/1.1\rHost: x\r\n\r\n"[..],
            &b"GET  / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nBad :foo\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\n\tFold: bad\r\n\r\n"[..],
        ] { rejects(wire); }
    }
    #[test]
    fn missing_duplicate_invalid_host_and_authorization_denied() {
        for wire in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nHOST: y\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: \r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: A\r\nAuthorization: B\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization:\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nX-Field: \x01\r\n\r\n"[..],
        ] { rejects(wire); }
    }
    #[test]
    fn body_bound_empty_missing_short_and_get_body_denied_at_legacy_limit() {
        for wire in [
            &b"POST / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 131073\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nABC"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nA"[..],
        ] { rejects(wire); }
        let mut wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 131072\r\n\r\n".to_vec();
        wire.extend(vec![b'x'; MAX_BODY_BYTES]);
        assert_eq!(parse_wire(&wire).unwrap().body.len(), MAX_BODY_BYTES);
    }
    #[test]
    fn request_line_header_line_block_and_field_count_limits_work() {
        let long_uri = "/".to_owned() + &"a".repeat(MAX_REQUEST_LINE);
        rejects(format!("GET {long_uri} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
        rejects(format!("GET / HTTP/1.1\r\nHost: x\r\nX-A: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_LINE)).as_bytes());
        let mut fields = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
        for n in 0..MAX_HEADER_FIELDS { fields.push_str(&format!("X-{n}: a\r\n")); }
        fields.push_str("\r\n");
        rejects(fields.as_bytes());
        let mut block = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
        for n in 0..10 { block.push_str(&format!("X-{n}: {}\r\n", "z".repeat(2000))); }
        block.push_str("\r\n");
        rejects(block.as_bytes());
    }
    #[test]
    fn pipelined_second_request_unread_and_socket_closed() {
        let hand = HandshakeAdmission::new(1, Duration::from_secs(2)).unwrap();
        let req = RequestAdmission::new(1, Duration::from_secs(2)).unwrap();
        let (server, mut client) = connection();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let work = hand.spawn_one_request(&req, server, |_io| Ok::<(), io::Error>(()),
            |io, ()| Ok(read_one_request(io)?.target)).unwrap();
        client.write_all(b"GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(work.join().unwrap().unwrap(), "/first");
        assert_eq!(client.read(&mut [0u8]).unwrap(), 0);
        assert_eq!(req.active_requests(), 0);
    }
    #[test]
    fn slow_header_trickle_cannot_extend_absolute_request_deadline() {
        use std::thread;
        let hand = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let req = RequestAdmission::new(1, Duration::from_millis(170)).unwrap();
        let (server, mut client) = connection();
        let work = hand.spawn_one_request(&req, server, |_io| Ok::<(), io::Error>(()),
            |io, ()| read_one_request(io)).unwrap();
        let sender = thread::spawn(move || {
            for _ in 0..12 {
                thread::sleep(Duration::from_millis(25));
                if client.write_all(b"G").is_err() { break; }
            }
        });
        assert_eq!(work.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        sender.join().unwrap();
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(req.active_requests(), 0);
    }
}
