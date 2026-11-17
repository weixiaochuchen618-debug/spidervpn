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

/// Keep the original shell strict-mode declaration first, placing the
/// retirement denial before any prior command, config write or service
/// restart. No new SSH round-trip and no server-side state mutation.
pub(crate) fn guard_legacy_mutation_script(original: &str) -> String {
    if let Some(body) = original.strip_prefix("set -eu\n") {
        let mut guarded = String::with_capacity(original.len() + SHELL_DENY_PRELUDE.len());
        guarded.push_str("set -eu\n");
        guarded.push_str(SHELL_DENY_PRELUDE);
        guarded.push_str(body);
        guarded
    } else {
        // A changed template must not silently lose the gate.
        guard_ssh_command(original)
    }
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


    #[cfg(target_os = "linux")]
    #[test]
    fn actual_posix_shell_blocks_each_retired_server_marker_before_side_effects() {
        use std::fs::{self, Permissions};
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::path::Path;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "spidervpn-ssh-guard-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        let marker = root.join("marker");
        let script = root.join("tc-pair.py");
        let unit = root.join("tc-pair.service");
        let output = root.join("ran");
        // Substitute only the fixed system paths, never a user's input.
        // This executes the EXACT Rust shell prelude against isolated test
        // paths and checks its effects, instead of testing string matching.
        let prelude = SHELL_DENY_PRELUDE
            .replace(CUTOVER_MARKER, marker.to_str().unwrap())
            .replace(OLD_SCRIPT, script.to_str().unwrap())
            .replace(SERVICE_UNIT, unit.to_str().unwrap());
        let command = format!("{prelude}printf ran > '{}'\n", output.display());
        let run = || {
            Command::new("/bin/sh").arg("-c").arg(&command)
                .output().unwrap()
        };

        // Existing unretired deployments continue unchanged.
        assert!(run().status.success());
        assert_eq!(fs::read(&output).unwrap(), b"ran");
        fs::remove_file(&output).unwrap();

        // Root-created marker file, even if it has no payload.
        fs::write(&marker, b"retired").unwrap();
        let result = run();
        assert_eq!(result.status.code(), Some(73));
        assert_eq!(result.stderr, b"TC_ERROR=LegacyWriterFenced\n");
        assert!(!output.exists());
        fs::remove_file(&marker).unwrap();

        // A dangling symlink is NOT accepted as absence.
        symlink(root.join("missing"), &marker).unwrap();
        assert_eq!(run().status.code(), Some(73));
        assert!(!output.exists());
        fs::remove_file(&marker).unwrap();

        // The Linux atomic-retirement directory tombstone blocks old SSH.
        fs::create_dir(&script).unwrap();
        assert_eq!(run().status.code(), Some(73));
        assert!(!output.exists());
        fs::remove_dir(&script).unwrap();

        // Permanent systemd mask is a real symlink to /dev/null.
        symlink(Path::new("/dev/null"), &unit).unwrap();
        assert_eq!(run().status.code(), Some(73));
        assert!(!output.exists());
        fs::remove_file(&unit).unwrap();

        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn existing_posix_deployment_body_is_unchanged_after_retirement_gate() {
        let original = "set -eu\numask 077\nmkdir -p /var/tmp/old-peer-writer\n";
        let guarded = guard_legacy_mutation_script(original);
        assert!(guarded.starts_with("set -eu\nif [ -e "), "{guarded}");
        assert!(guarded.contains("exit 73\nfi\numask 077\nmkdir -p"), "{guarded}");
        assert_eq!(guarded.matches("TC_ERROR=LegacyWriterFenced").count(), 1);
        assert_eq!(guarded.replacen(SHELL_DENY_PRELUDE, "", 1), original);
        let unexpected = guard_legacy_mutation_script("touch /tmp/old-writer\n");
        assert!(unexpected.starts_with("if [ -e "));
        assert!(unexpected.ends_with("touch /tmp/old-writer\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_strict_posix_shell_will_not_run_deployment_body_when_retired() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        let root = std::env::temp_dir().join(format!(
            "spider-deploy-guard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = root.join("marker");
        let executed = root.join("executed");
        let prelude = SHELL_DENY_PRELUDE.replace(CUTOVER_MARKER, marker.to_str().unwrap())
            .replace(OLD_SCRIPT, root.join("tc-pair.py").to_str().unwrap())
            .replace(SERVICE_UNIT, root.join("tc-pair.service").to_str().unwrap());
        let original = format!("set -eu\nprintf created > '{}'\n", executed.display());
        let wrapped = guard_legacy_mutation_script(&original)
            .replacen(SHELL_DENY_PRELUDE, &prelude, 1);
        assert_eq!(Command::new("/bin/sh").arg("-c").arg(&wrapped)
            .status().unwrap().code(), Some(0));
        assert_eq!(fs::read(&executed).unwrap(), b"created");
        fs::remove_file(&executed).unwrap();
        fs::write(&marker,b"root-retired").unwrap();
        let refused = Command::new("/bin/sh").arg("-c").arg(&wrapped).output().unwrap();
        assert_eq!(refused.status.code(), Some(73));
        assert_eq!(refused.stderr, b"TC_ERROR=LegacyWriterFenced\n");
        assert!(!executed.exists());
        fs::remove_dir_all(&root).unwrap();
    }


    #[cfg(target_os = "linux")]
    #[test]
    fn actual_shell_denies_sourceable_read_only_transport_before_side_effects() {
        use std::fs::{self, Permissions};
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "spider-legacy-source-fence-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        let identity = root.join("transport.env");
        let marker = root.join("retired-marker");
        let side_effect = root.join("executed");
        // An "identity file" is shell code when sourced: nominal reads can write.
        fs::write(&identity, format!("printf sourced > '{}'\n", side_effect.display())).unwrap();
        let original = format!("set -eu\nIDENTITY='{}'\n. \"$IDENTITY\"\necho TC_DONE=1\n",
            identity.display());
        let guarded = guard_legacy_mutation_script(&original);
        let script = guarded
            .replace(CUTOVER_MARKER, marker.to_str().unwrap())
            .replace(OLD_SCRIPT, root.join("tc-pair.py").to_str().unwrap())
            .replace(SERVICE_UNIT, root.join("tc-pair.service").to_str().unwrap());
        let execute = || Command::new("/bin/sh").arg("-c").arg(&script).output().unwrap();

        // Before a separately managed cutover the original read is unchanged.
        let permitted = execute();
        assert!(permitted.status.success(), "{:?}", permitted.stderr);
        assert_eq!(fs::read(&side_effect).unwrap(), b"sourced");
        fs::remove_file(&side_effect).unwrap();

        // Retirement prevents executing sourced shell contents at all.
        fs::write(&marker, b"retired").unwrap();
        let denied = execute();
        assert_eq!(denied.status.code(), Some(73));
        assert_eq!(denied.stderr, b"TC_ERROR=LegacyWriterFenced\n");
        assert!(denied.stdout.is_empty());
        assert!(!side_effect.exists());
        fs::remove_dir_all(&root).unwrap();
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
