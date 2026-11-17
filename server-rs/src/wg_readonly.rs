//! SEC-01 S03: read-only Linux WireGuard live peer inventory.
//!
//! Independent Rust pre-integration module. It does not change the Python
//! receiver, WireGuard configuration or live network in CI.
//!
//! NEVER use wg show IFACE dump: the first line contains the interface
//! PRIVATE KEY. The allowed-ips query returns peer public keys and prefixes.
//! A complete successful live snapshot still does not prove persistent
//! wg.conf matches the interface: the future mutating adapter must also
//! validate the durable configuration.
//!
//! Current authority models exactly one RFC1918 IPv4 /32 per peer. Valid
//! WireGuard setups with IPv6/multiple prefixes are deliberately rejected,
//! not silently omitted as "no peers".

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{wg_key, Peer};

const WG_BINARY: &str = "/usr/bin/wg";
const MAX_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_PEERS: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    InvalidInterface,
    UnsafeExecutable,
    CommandFailed,
    TimedOut,
    OutputTooLarge,
    InvalidUtf8,
    MalformedOutput,
    InvalidPublicKey,
    UnsupportedAllowedIps,
    DuplicatePeer,
    DuplicateAddress,
    TooManyPeers,
}

/// Never pass a special selector (all/interfaces) or option-like token to wg.
/// Valid names are restricted to a conservative wg-quick compatible subset.
pub fn valid_interface(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b.len() <= 15
        && !matches!(name, "." | ".." | "all" | "interfaces")
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric()
            || matches!(*c, b'_' | b'=' | b'+' | b'.' | b'-'))
}

/// Parse full output of wg show IFACE allowed-ips. Never infer a missing
/// peer from a subset of output or drop a malformed row.
pub fn parse_allowed_ips(bytes: &[u8]) -> Result<Vec<Peer>, ReadError> {
    if bytes.len() > MAX_OUTPUT_BYTES { return Err(ReadError::OutputTooLarge); }
    if bytes.is_empty() { return Ok(Vec::new()); }
    if bytes.last() != Some(&b'\n') { return Err(ReadError::MalformedOutput); }
    let text = std::str::from_utf8(bytes).map_err(|_| ReadError::InvalidUtf8)?;
    let mut peers = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut seen_ips = BTreeSet::new();
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.ends_with('\r') {
            return Err(ReadError::MalformedOutput);
        }
        let mut fields = line.split('\t');
        let key = fields.next().ok_or(ReadError::MalformedOutput)?;
        let cidr = fields.next().ok_or(ReadError::MalformedOutput)?;
        if fields.next().is_some() || cidr.is_empty()
            || cidr.contains(char::is_whitespace)
        {
            return Err(ReadError::MalformedOutput);
        }
        if !wg_key(key) { return Err(ReadError::InvalidPublicKey); }
        let (host, mask) = cidr.split_once('/')
            .ok_or(ReadError::UnsupportedAllowedIps)?;
        if mask != "32" || host.contains('/') {
            return Err(ReadError::UnsupportedAllowedIps);
        }
        let ip: Ipv4Addr = host.parse().map_err(|_| ReadError::UnsupportedAllowedIps)?;
        if !ip.is_private() || ip.to_string() != host {
            return Err(ReadError::UnsupportedAllowedIps);
        }
        if !seen_keys.insert(key.to_owned()) { return Err(ReadError::DuplicatePeer); }
        if !seen_ips.insert(ip) { return Err(ReadError::DuplicateAddress); }
        if peers.len() >= MAX_PEERS { return Err(ReadError::TooManyPeers); }
        peers.push(Peer { public_key: key.to_string(), address: ip });
    }
    Ok(peers)
}

/// Explicit absolute executable, root owned, normal file, not group/other
/// writable. Never resolve from PATH and never invoke a shell.
pub(crate) fn trusted_wg_binary(path: &Path) -> Result<(), ReadError> {
    if path != Path::new(WG_BINARY) { return Err(ReadError::UnsafeExecutable); }
    let meta = fs::symlink_metadata(path).map_err(|_| ReadError::UnsafeExecutable)?;
    if !meta.file_type().is_file() || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.mode() & 0o111 == 0
    {
        return Err(ReadError::UnsafeExecutable);
    }
    Ok(())
}

/// Bounded stdout reader runs alongside try_wait to avoid pipe deadlocks.
/// The production caller executes only the pinned WG binary, which does
/// not intentionally spawn background descendants retaining stdout handles.
fn execute_bounded(program: &Path, args: &[&str], timeout: Duration)
    -> Result<Vec<u8>, ReadError>
{
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ReadError::CommandFailed)?;
    let pipe = child.stdout.take().ok_or(ReadError::CommandFailed)?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = pipe.take((MAX_OUTPUT_BYTES + 1) as u64).read_to_end(&mut output);
        (result, output)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(ReadError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(ReadError::CommandFailed);
            }
        }
    };
    let (read_result, bytes) = reader.join().map_err(|_| ReadError::CommandFailed)?;
    read_result.map_err(|_| ReadError::CommandFailed)?;
    if bytes.len() > MAX_OUTPUT_BYTES { return Err(ReadError::OutputTooLarge); }
    if !status?.success() { return Err(ReadError::CommandFailed); }
    Ok(bytes)
}

/// Read-only and intentionally NOT an implementation of PeerControl,
/// whose add/remove methods are not yet safe to perform on real wg.conf.
pub struct LiveWgReader {
    interface: String,
}

impl LiveWgReader {
    pub fn new(interface: &str) -> Result<Self, ReadError> {
        if !valid_interface(interface) { return Err(ReadError::InvalidInterface); }
        Ok(Self { interface: interface.to_string() })
    }
    pub fn snapshot(&self) -> Result<Vec<Peer>, ReadError> {
        trusted_wg_binary(Path::new(WG_BINARY))?;
        let output = execute_bounded(Path::new(WG_BINARY),
            &["show", &self.interface, "allowed-ips"], COMMAND_TIMEOUT)?;
        parse_allowed_ips(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(c: char) -> String { format!("{}=", c.to_string().repeat(43)) }
    fn row(k: &str, ip: &str) -> String { format!("{k}\t{ip}/32\n") }

    #[test]
    fn exact_live_rows_and_explicit_empty_are_valid() {
        assert_eq!(parse_allowed_ips(b""), Ok(vec![]));
        let body = format!("{}{}", row(&key('A'), "10.66.0.2"),
            row(&key('B'), "10.66.0.3"));
        assert_eq!(parse_allowed_ips(body.as_bytes()), Ok(vec![
            Peer { public_key: key('A'), address: Ipv4Addr::new(10,66,0,2) },
            Peer { public_key: key('B'), address: Ipv4Addr::new(10,66,0,3) },
        ]));
    }

    #[test]
    fn rejects_shell_syntax_special_selectors_and_invalid_interface() {
        for bad in ["", "--help", "all", "interfaces", ".", "..", "wg0;id",
            "wg0\nrm", "/tmp/x", "隧道0", "wg0 a", "wg0\0x"] {
            assert!(!valid_interface(bad));
            assert!(matches!(LiveWgReader::new(bad), Err(ReadError::InvalidInterface)));
        }
        assert!(!valid_interface(&"a".repeat(16)));
        for good in ["wg0", "wgvpn0", "wg.test", "wg_mgmt-0"] {
            assert!(valid_interface(good), "{good}");
        }
    }

    #[test]
    fn rejects_incomplete_or_unrepresentable_peers() {
        let k = key('A');
        for body in [
            format!("{k}\t(none)\n"),
            format!("{k}\t10.66.0.2/24\n"),
            format!("{k}\t10.66.0.2/32 10.66.0.3/32\n"),
            format!("{k}\t10.66.0.2/32,10.66.0.3/32\n"),
            format!("{k}\t::1/128\n"),
            format!("{k}\t0.0.0.0/0\n"),
            format!("{k}\t8.8.8.8/32\n"),
            format!("{k}\t10.66.0.02/32\n"),
        ] {
            assert!(parse_allowed_ips(body.as_bytes()).is_err(), "{body}");
        }
    }

    #[test]
    fn rejects_duplicate_address_key_and_missing_terminator() {
        let first = row(&key('A'), "10.66.0.2");
        let duplicate_key = format!("{first}{}", row(&key('A'), "10.66.0.3"));
        let duplicate_ip = format!("{first}{}", row(&key('B'), "10.66.0.2"));
        assert_eq!(parse_allowed_ips(duplicate_key.as_bytes()), Err(ReadError::DuplicatePeer));
        assert_eq!(parse_allowed_ips(duplicate_ip.as_bytes()), Err(ReadError::DuplicateAddress));
        assert_eq!(parse_allowed_ips(first.trim_end().as_bytes()), Err(ReadError::MalformedOutput));
    }

    #[test]
    fn rejects_untrusted_utf8_key_field_and_malformed_records() {
        for body in [
            format!("{}\t10.66.0.2/32\n", "A".repeat(44)),
            format!("{}\t10.66.0.2/32\n", "😈".repeat(11)),
            format!("{}\t10.66.0.2/32\n", key('A')).replace('\t', "  "),
            format!("{}\t10.66.0.2/32\n", key('A')).replace('\n', "\r\n"),
            format!("{}\t10.66.0.2/32\n\n", key('A')),
        ] {
            assert!(parse_allowed_ips(body.as_bytes()).is_err());
        }
        assert_eq!(parse_allowed_ips(&[0xff, b'\n']), Err(ReadError::InvalidUtf8));
        assert_eq!(parse_allowed_ips(&vec![b'A'; MAX_OUTPUT_BYTES + 1]), Err(ReadError::OutputTooLarge));
    }

    #[test]
    fn refuses_oversized_peer_inventory() {
        let mut body = String::new();
        for i in 0..=MAX_PEERS {
            let ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(10,66,0,0)) + i as u32 + 2);
            body.push_str(&row(&(format!("{i:043}") + "="), &ip.to_string()));
        }
        assert_eq!(parse_allowed_ips(body.as_bytes()), Err(ReadError::TooManyPeers));
    }

    #[test]
    fn subprocess_timeout_nonzero_and_executable_pin_are_enforced() {
        assert_eq!(trusted_wg_binary(Path::new("/bin/sh")), Err(ReadError::UnsafeExecutable));
        if Path::new("/bin/sleep").exists() {
            assert_eq!(execute_bounded(Path::new("/bin/sleep"), &["1"],
                Duration::from_millis(30)), Err(ReadError::TimedOut));
        }
        if Path::new("/usr/bin/false").exists() {
            assert_eq!(execute_bounded(Path::new("/usr/bin/false"), &[],
                Duration::from_secs(1)), Err(ReadError::CommandFailed));
        }
    }
}
