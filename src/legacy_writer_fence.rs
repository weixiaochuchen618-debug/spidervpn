//! SEC-01/SEC-08 migration compatibility: fail closed on the OLD SSH writer
//! commands after an independently administered server-side retirement.
//!
//! Every previously deployed, unfenced server continues to follow the exact
//! same UI and network workflow. The server-side marker is opt-in and root-
//! controlled, not a user-config flag and not derived from legacy invites.
//!
//! This guard provides a denial signal for this updated Windows client ONLY.
//! It is not a cross-process lock: older clients, a different SSH script,
//! and root actors do not honor it. No importer or new authorization endpoint
//! may use it as proof of safe cutover.

/// This path is reserved for a future, independently approved root cutover.
/// This client NEVER creates or deletes the marker.
pub(crate) const CUTOVER_MARKER: &str =
    "/var/lib/tradechannel/pairing-rs/.spidervpn-legacy-writes-disabled";
pub(crate) const OLD_SCRIPT: &str =
    "/var/lib/tradechannel/pairing-rs/tc-pair.py";
pub(crate) const SERVICE_UNIT: &str =
    "/etc/systemd/system/tc-pair.service";

/// POSIX shell prelude, no untrusted inputs. Must appear BEFORE any redirect,
/// Python call, systemd restart or WireGuard peer mutation in protected paths.
///
/// -e catches regular files/directories and live symlinks; -L also catches
/// a dangling symlink (absence is never inferred from a broken link).
/// A directory at the script path is the Linux atomic retirement tombstone.
/// A symlinked old unit is incompatible with the installed regular unit, and
/// may be the persistent systemd mask (/dev/null).
pub(crate) const SHELL_DENY_PRELUDE: &str = "\
if [ -e '/var/lib/tradechannel/pairing-rs/.spidervpn-legacy-writes-disabled' ] \
|| [ -L '/var/lib/tradechannel/pairing-rs/.spidervpn-legacy-writes-disabled' ] \
|| [ -d '/var/lib/tradechannel/pairing-rs/tc-pair.py' ] \
|| [ -L '/etc/systemd/system/tc-pair.service' ]; then
  printf '%s\\n' 'TC_ERROR=LegacyWriterFenced' >&2
  exit 73
fi
";

pub(crate) const FENCED_EXIT_CODE: u32 = 73;
pub(crate) const FENCED_ERROR: &str = "TC_ERROR=LegacyWriterFenced";

pub(crate) fn guard_ssh_command(original: &str) -> String {
    let mut safe = String::with_capacity(SHELL_DENY_PRELUDE.len() + original.len());
    safe.push_str(SHELL_DENY_PRELUDE);
    safe.push_str(original);
    safe
}

pub(crate) fn remote_says_fenced(exit_code: u32, stderr: &str) -> bool {
    exit_code == FENCED_EXIT_CODE
        && stderr.lines().any(|line| line.trim() == FENCED_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_ssh_commands_are_denied_before_any_original_operation() {
        for original in [
            "cat /var/lib/tradechannel/pairing-rs/tc-pair.sha256",
            "base64 -d tc-pair.py.b64 > /var/lib/tradechannel/pairing-rs/tc-pair.py",
            "python3 -I /var/lib/tradechannel/pairing-rs/tc-pair.py create",
            "systemctl restart tc-pair.service",
            "wg syncconf wg0 somefile",
        ] {
            let guarded = guard_ssh_command(original);
            assert!(guarded.starts_with("if [ -e "), "{guarded}");
            assert!(guarded.contains("exit 73\nfi\n"), "{guarded}");
            assert!(guarded.ends_with(original), "{guarded}");
            assert!(guarded.find("exit 73").unwrap() < guarded.find(original).unwrap());
        }
    }

    #[test]
    fn fail_closed_on_stale_symlinks_and_retired_directory_without_modifying_them() {
        assert!(SHELL_DENY_PRELUDE.contains(&format!("-e '{CUTOVER_MARKER}'")));
        assert!(SHELL_DENY_PRELUDE.contains(&format!("-L '{CUTOVER_MARKER}'")));
        assert!(SHELL_DENY_PRELUDE.contains(&format!("-d '{OLD_SCRIPT}'")));
        assert!(SHELL_DENY_PRELUDE.contains(&format!("-L '{SERVICE_UNIT}'")));
        assert!(!SHELL_DENY_PRELUDE.contains("rm -"));
        assert!(!SHELL_DENY_PRELUDE.contains("systemctl stop"));
        assert!(!SHELL_DENY_PRELUDE.contains("chmod "));
        assert!(!SHELL_DENY_PRELUDE.contains("mv "));
    }

    #[test]
    fn explicit_remote_denial_requires_exit_code_and_exact_sentinel_line() {
        assert!(remote_says_fenced(73, "TC_ERROR=LegacyWriterFenced\n"));
        assert!(!remote_says_fenced(0, "TC_ERROR=LegacyWriterFenced\n"));
        assert!(!remote_says_fenced(73, "TC_ERROR=Other\n"));
        assert!(!remote_says_fenced(73, "prefixTC_ERROR=LegacyWriterFencedpost"));
    }

    #[test]
    fn no_server_marker_creation_or_implicit_migration_authority() {
        // Marker existence is supplied ONLY by independently managed root
        // state. The Windows client has no create/remove migration API.
        assert!(CUTOVER_MARKER.starts_with("/var/lib/tradechannel/pairing-rs/."));
        assert!(!SHELL_DENY_PRELUDE.contains("touch "));
        assert!(!SHELL_DENY_PRELUDE.contains("mkdir "));
        assert!(!SHELL_DENY_PRELUDE.contains("enable "));
    }
}
