//! SEC-01 S03: read-only, secret-redacting persistent WireGuard config audit.
//!
//! A peer absent from the live kernel snapshot may still be present in the
//! future wg-quick configuration. Failing to compare both views can lead to
//! duplicate address allocation or resurrection after interface restart.
//!
//! This module NEVER writes wg.conf or invokes wg/shell. It only parses the
//! [Interface] and [Peer] sections required by the SpiderVPN /32 model,
//! and demands exact equality with the separately verified live inventory.
//! Interface PrivateKey/PresharedKey contents are never returned/logged.
//!
//! It is a migration candidate, NOT a deployed authorization adapter.

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::Peer;
use crate::wg_readonly::{parse_allowed_ips, valid_interface, LiveWgReader, ReadError};

const ROOT: &str = "/etc/wireguard";
const MAX_CONF_BYTES: usize = 1024 * 1024;
const O_NOFOLLOW: i32 = 0o400000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidInterface,
    InvalidPath,
    InvalidPermissions,
    Io,
    TooLarge,
    Utf8,
    InvalidSection,
    MalformedLine,
    IncompletePeer,
    UnsupportedField,
    InvalidPeers(ReadError),
    SnapshotMismatch,
}

#[derive(Default)]
struct PendingPeer {
    key: Option<String>,
    ips: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section { None, Interface, Peer }

fn flush_peer(pending: &mut PendingPeer, lines: &mut String)
    -> Result<(), ConfigError>
{
    let key = pending.key.take().ok_or(ConfigError::IncompletePeer)?;
    let ips = pending.ips.take().ok_or(ConfigError::IncompletePeer)?;
    lines.push_str(&key);
    lines.push('\t');
    lines.push_str(&ips);
    lines.push('\n');
    Ok(())
}

/// Reads a wg-quick server config without leaking its interface private key.
/// Only an exact single private IPv4 /32 per peer is representable by this
/// pairing service. If metadata/format is ambiguous, reject rather than
/// skipping that peer and falsely claiming the identity is absent.
pub fn parse_wg_quick_conf(bytes: &[u8]) -> Result<Vec<Peer>, ConfigError> {
    if bytes.len() > MAX_CONF_BYTES { return Err(ConfigError::TooLarge); }
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::Utf8)?;
    let mut section = Section::None;
    let mut saw_interface = false;
    let mut pending = PendingPeer::default();
    let mut public_lines = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if section == Section::Peer {
                flush_peer(&mut pending, &mut public_lines)?;
            }
            section = match line {
                "[Interface]" if !saw_interface && section == Section::None => {
                    saw_interface = true;
                    Section::Interface
                }
                "[Peer]" if saw_interface => Section::Peer,
                _ => return Err(ConfigError::InvalidSection),
            };
            continue;
        }
        let (raw_name, raw_value) = line.split_once('=')
            .ok_or(ConfigError::MalformedLine)?;
        let name = raw_name.trim();
        let value = raw_value.trim();
        if value.is_empty() { return Err(ConfigError::MalformedLine); }
        match section {
            Section::None => return Err(ConfigError::InvalidSection),
            Section::Interface => {
                // Explicitly ignore interface-only fields, including its
                // private key. Never return these strings in diagnostics.
                // Do not execute PreUp/PostUp or any other script field.
                match name {
                    "PrivateKey" | "Address" | "ListenPort" | "MTU" |
                    "DNS" | "Table" | "SaveConfig" | "FwMark" |
                    "PreUp" | "PostUp" | "PreDown" | "PostDown" =>
                        {}
                    _ => return Err(ConfigError::UnsupportedField),
                }
            }
            Section::Peer => match name {
                "PublicKey" => {
                    if pending.key.replace(value.to_string()).is_some() {
                        return Err(ConfigError::MalformedLine);
                    }
                }
                "AllowedIPs" => {
                    if pending.ips.replace(value.to_string()).is_some() {
                        return Err(ConfigError::MalformedLine);
                    }
                }
                "Endpoint" | "PresharedKey" | "PersistentKeepalive" => {
                    // These do not alter key/address ownership, but they
                    // must be parsed only inside a complete Peer section.
                }
                _ => return Err(ConfigError::UnsupportedField),
            },
        }
    }
    if !saw_interface { return Err(ConfigError::InvalidSection); }
    if section == Section::Peer {
        flush_peer(&mut pending, &mut public_lines)?;
    }
    parse_allowed_ips(public_lines.as_bytes()).map_err(ConfigError::InvalidPeers)
}

/// Every live and durable peer must have the same key and assigned address.
/// Order is irrelevant, but duplicated keys or IPs and missing records are
/// never accepted as a valid matching snapshot.
pub fn require_exact_match(live: &[Peer], durable: &[Peer])
    -> Result<(), ConfigError>
{
    if live.len() > 4096 || durable.len() > 4096 {
        return Err(ConfigError::InvalidPeers(ReadError::TooManyPeers));
    }
    for peer in live.iter().chain(durable.iter()) {
        if peer.public_key.len() != 44 || !peer.address.is_private() {
            return Err(ConfigError::InvalidPeers(ReadError::InvalidPublicKey));
        }
    }
    if live.len() != durable.len() { return Err(ConfigError::SnapshotMismatch); }
    let to_lines = |peers: &[Peer]| -> String {
        let mut out = String::new();
        for p in peers {
            out.push_str(&p.public_key);
            out.push('\t');
            out.push_str(&p.address.to_string());
            out.push_str("/32\n");
        }
        out
    };
    let left = parse_allowed_ips(to_lines(live).as_bytes())
        .map_err(ConfigError::InvalidPeers)?;
    let right = parse_allowed_ips(to_lines(durable).as_bytes())
        .map_err(ConfigError::InvalidPeers)?;
    let mut left = left;
    let mut right = right;
    left.sort_by(|a,b| a.public_key.cmp(&b.public_key));
    right.sort_by(|a,b| a.public_key.cmp(&b.public_key));
    if left != right { return Err(ConfigError::SnapshotMismatch); }
    Ok(())
}

fn validate_root() -> Result<(), ConfigError> {
    let meta = fs::symlink_metadata(ROOT).map_err(|_| ConfigError::InvalidPath)?;
    if !meta.file_type().is_dir()
        || meta.uid() != 0 || meta.mode() & 0o077 != 0
    {
        return Err(ConfigError::InvalidPermissions);
    }
    Ok(())
}

/// This uses the existing (fixed) /etc/wireguard root, never an arbitrary
/// request-supplied path. A malicious symlink/hardlink or permissions drift
/// is an ERROR, not evidence of an absent peer.
pub fn read_pinned_conf(interface: &str) -> Result<Vec<Peer>, ConfigError> {
    if !valid_interface(interface) { return Err(ConfigError::InvalidInterface); }
    validate_root()?;
    let path: PathBuf = Path::new(ROOT).join(format!("{interface}.conf"));
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW)
        .open(&path).map_err(|_| ConfigError::Io)?;
    let before = file.metadata().map_err(|_| ConfigError::Io)?;
    if !before.file_type().is_file() || before.uid() != 0
        || before.nlink() != 1 || before.mode() & 0o777 != 0o600
    {
        return Err(ConfigError::InvalidPermissions);
    }
    if before.len() > MAX_CONF_BYTES as u64 { return Err(ConfigError::TooLarge); }
    let mut data = Vec::new();
    file.take((MAX_CONF_BYTES + 1) as u64)
        .read_to_end(&mut data).map_err(|_| ConfigError::Io)?;
    if data.len() > MAX_CONF_BYTES { return Err(ConfigError::TooLarge); }

    // Fail if a root-level installer replaced or changed the file while
    // reading. There is no claim to resist a hostile privileged root actor.
    let after = fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?;
    if !after.file_type().is_file()
        || before.ino() != after.ino()
        || before.dev() != after.dev()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ConfigError::Io);
    }
    parse_wg_quick_conf(&data)
}

/// Separate snapshots are not an atomic joint read. The caller must hold the
/// authority transaction lock across the live and disk checks; future WG
/// update code must still verify both again after each mutation.
pub fn verify_live_config(interface: &str, live: &[Peer])
    -> Result<(), ConfigError>
{
    let durable = read_pinned_conf(interface)?;
    require_exact_match(live, &durable)
}

/// Compare live-before, durable config and live-after snapshots. A peer
/// inserted/removed or a route changed during the read must fail, not be
/// mistaken for a stable empty interface. The caller must still hold the
/// transaction lock; this does not defend against malicious root-level
/// changes or a root actor not honoring that lock.
fn require_stable_views(
    before: &[Peer], durable: &[Peer], after: &[Peer],
) -> Result<Vec<Peer>, ConfigError> {
    require_exact_match(before, durable)?;
    require_exact_match(before, after)?;
    Ok(after.to_vec())
}

/// The strongest available pre-integration read-only API. It does not
/// perform any WG mutations, and is deliberately not PeerControl.
pub fn read_verified_snapshot(interface: &str) -> Result<Vec<Peer>, ConfigError> {
    if !valid_interface(interface) { return Err(ConfigError::InvalidInterface); }
    let reader = LiveWgReader::new(interface).map_err(ConfigError::InvalidPeers)?;
    let before = reader.snapshot().map_err(ConfigError::InvalidPeers)?;
    let durable = read_pinned_conf(interface)?;
    let after = reader.snapshot().map_err(ConfigError::InvalidPeers)?;
    require_stable_views(&before, &durable, &after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    fn key(c: char) -> String { format!("{}=", c.to_string().repeat(43)) }
    fn conf(peers: &str) -> String {
        format!("# server setup\n[Interface]\nPrivateKey = VERY_SECRET_NEVER_LOG\nAddress = 10.66.0.1/24\nListenPort = 51820\nPostUp = echo safe\n{peers}")
    }

    #[test]
    fn parses_two_peers_ignores_private_key_and_comments() {
        let body = conf(&format!(
            "\n[Peer]\n# device A\nPublicKey = {}\nAllowedIPs = 10.66.0.2/32\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.66.0.3/32\nPersistentKeepalive = 25\n",
            key('A'), key('B')));
        let parsed = parse_wg_quick_conf(body.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].address, Ipv4Addr::new(10,66,0,2));
        assert_eq!(parsed[1].public_key, key('B'));
        assert!(!format!("{parsed:?}").contains("VERY_SECRET_NEVER_LOG"));
        assert!(require_exact_match(&parsed, &parsed).is_ok());
    }

    #[test]
    fn detects_durable_peer_absent_in_live_kernel() {
        let disk = parse_wg_quick_conf(
            conf(&format!("\n[Peer]\nPublicKey={}\nAllowedIPs=10.66.0.2/32\n",key('A')))
                .as_bytes()).unwrap();
        assert_eq!(require_exact_match(&[], &disk), Err(ConfigError::SnapshotMismatch));
        let live = vec![Peer {
            public_key: key('B'), address: Ipv4Addr::new(10,66,0,2),
        }];
        assert_eq!(require_exact_match(&live, &disk), Err(ConfigError::SnapshotMismatch));
    }

    #[test]
    fn mismatch_address_or_extra_live_peer_refused() {
        let disk = vec![Peer {public_key:key('A'),address:Ipv4Addr::new(10,66,0,2)}];
        let different = vec![Peer {public_key:key('A'),address:Ipv4Addr::new(10,66,0,3)}];
        assert_eq!(require_exact_match(&different, &disk), Err(ConfigError::SnapshotMismatch));
        let mut extra = disk.clone();
        extra.push(Peer{public_key:key('B'),address:Ipv4Addr::new(10,66,0,4)});
        assert_eq!(require_exact_match(&extra, &disk), Err(ConfigError::SnapshotMismatch));
    }

    #[test]
    fn missing_or_duplicate_peer_fields_and_unknown_sections_refused() {
        for raw in [
            conf(&format!("\n[Peer]\nPublicKey={}\n",key('A'))),
            conf("\n[Peer]\nAllowedIPs=10.66.0.2/32\n"),
            conf(&format!("\n[Peer]\nPublicKey={}\nPublicKey={}\nAllowedIPs=10.66.0.2/32\n",key('A'),key('B'))),
            conf(&format!("\n[Peer]\nPublicKey={}\nAllowedIPs=10.66.0.2/32\nAllowedIPs=10.66.0.3/32\n",key('A'))),
            conf("\n[Secret]\nPrivateKey=abc\n"),
            conf(&format!("\n[Peer]\nPublicKey={}\nAllowedIPs=10.66.0.2/32\nNotRecognized=1\n",key('A'))),
            "[Peer]\nPublicKey=abc\nAllowedIPs=10.66.0.2/32\n".into(),
        ] {
            assert!(parse_wg_quick_conf(raw.as_bytes()).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn multiple_ip_ranges_ipv6_and_duplicate_addresses_refused() {
        let a = key('A');
        let b = key('B');
        for raw in [
            conf(&format!("\n[Peer]\nPublicKey={a}\nAllowedIPs=10.66.0.2/32,10.66.0.3/32\n")),
            conf(&format!("\n[Peer]\nPublicKey={a}\nAllowedIPs=2001:db8::2/128\n")),
            conf(&format!("\n[Peer]\nPublicKey={a}\nAllowedIPs=10.66.0.2/24\n")),
            conf(&format!("\n[Peer]\nPublicKey={a}\nAllowedIPs=10.66.0.2/32\n[Peer]\nPublicKey={b}\nAllowedIPs=10.66.0.2/32\n")),
        ] {
            assert!(parse_wg_quick_conf(raw.as_bytes()).is_err());
        }
    }

    #[test]
    fn order_is_irrelevant_but_unauthorized_duplicate_is_rejected() {
        let a=Peer{public_key:key('A'),address:Ipv4Addr::new(10,66,0,2)};
        let b=Peer{public_key:key('B'),address:Ipv4Addr::new(10,66,0,3)};
        assert_eq!(require_exact_match(&[a.clone(),b.clone()], &[b.clone(),a.clone()]),Ok(()));
        assert!(require_exact_match(&[a.clone(),a], &[b.clone(),b]).is_err());
    }

    #[test]
    fn concurrent_live_snapshot_change_is_a_denial_not_a_verified_absence() {
        let first = vec![Peer { public_key: key('A'), address: Ipv4Addr::new(10, 66, 0, 2) }];
        let added = vec![
            first[0].clone(),
            Peer { public_key: key('B'), address: Ipv4Addr::new(10, 66, 0, 3) },
        ];
        assert_eq!(require_stable_views(&first, &first, &added),
            Err(ConfigError::SnapshotMismatch));
        assert_eq!(require_stable_views(&first, &[], &[]),
            Err(ConfigError::SnapshotMismatch));
        assert_eq!(require_stable_views(&first, &first, &first), Ok(first.clone()));
    }

    #[test]
    fn forged_overlarge_live_snapshot_is_rejected_before_allocation() {
        let peer = Peer { public_key: key('A'), address: Ipv4Addr::new(10, 66, 0, 2) };
        let oversized = vec![peer; 4097];
        assert_eq!(require_exact_match(&oversized, &oversized),
            Err(ConfigError::InvalidPeers(ReadError::TooManyPeers)));
    }

    #[test]
    fn oversized_config_and_bad_unicode_are_rejected() {
        assert_eq!(parse_wg_quick_conf(&vec![b'X'; MAX_CONF_BYTES+1]), Err(ConfigError::TooLarge));
        assert_eq!(parse_wg_quick_conf(&[0xff]), Err(ConfigError::Utf8));
    }
}
