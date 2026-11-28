# Stage 4A: local pairing process (candidate, not deployed)

Build the exact reviewed source with `cargo build --locked --release --manifest-path server-rs/Cargo.toml --features linux-pairing-process --bin spidervpn-pair-service`. Record the commit and executable SHA-256; the feature is off by default. This is a foreground loopback-only process, not an installer or replacement for the existing Python service.

An authorized operator must independently establish current trusted history, exclusive privileged writer discipline, the existing Rust ledger and the exact WireGuard server identity before launch. Do not initialize missing state or convert legacy JSON. Provide an absolute root-owned directory mode 0700, with root-owned non-writable ancestors and fixed regular single-link files: `authority-ledger.json`, `invite-metadata.json`, `authorization-config.json`, `management.key` (PKCS#8 PEM), `tls.key` (PEM) all 0600; `tls.crt` (PEM, no group/world write). Metadata/config pins are SHA-256 of exact record bytes, TLS pin is SHA-256 of original leaf DER. Obtain pins independently from the trusted provisioning decision, not by trusting adjacent files or an incoming request. No bearer/key in argv, environment or logs.

Explicit invocation (placeholders, not a production command):

```text
/path/to/verified/spidervpn-pair-service serve /protected/current-root 18443 WG_INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256
```

Run only with explicit authorization in an isolated network namespace. Existing accepted WG adapter and protected root/config require effective UID 0 and CAP_NET_ADMIN; the process currently retains root privileges (no new privileges, no dumpable core). Do not expose the port, forward it publicly, run setuid, or add a production unit. Privilege separation and trusted production provisioning/old-writer fencing need separate approval before public deployment. The fixed listener is 127.0.0.1, not the advertised tunnel endpoint.

Observe static READY/STOPPED markers, process exit, exact executable identity and actual local TLS responses. SIGTERM or SIGINT closes the accept loop and drains admitted workers within existing network budgets; local disk/transaction failures can delay drain. Restart with the same current trusted root and pins only after the previous process has exited. GET returns InvitationReady for Open and RetryOnly for eligible Consumed; identical authenticated POST returns the original signed authorization. No state creation or expiry extension on GET.

## Revoke a registered device

Run as root in the same authorized namespace with the current root, interface and trusted pins from `serve`. Use the exact `DeviceId` of the registered device, including devices carried forward by `init-existing`.

```text
/path/to/verified/spidervpn-pair-service revoke /protected/current-root WG_INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256 DEVICE_ID
```

The command persists `Revoking` before changing WireGuard, then records `Revoked` only after readback confirms absence from the live interface and protected config. Exit 0 with `PAIR_DEVICE_REVOKED` confirms completion. Repeating a completed revocation checks absence without rewriting state. On failure, inspect current state and use the existing recovery procedure if the config and live interface diverge. Authenticated GET and POST for the revoked invitation return `403 Revoked`, including after restart with the current ledger.

## Restart and rollback

Rollback: stop and verify exit, preserve the current durable ledger, protected WG config and live peers, and verify identity/inventory. An earlier executable/unit may be restored only if separately proven compatible with the current durable state and writer fence. Never restore an older ledger, delete Pending/Revoking, recreate missing state or reactivate the legacy writer after Rust mutation. If compatibility/history cannot be established, leave the service stopped and request explicit recovery authorization. No real VPS rollout, Windows pairing or legacy migration is authorized by this document.

## Stage 4B: first-time authority only (not migration)

Build with `--features linux-fresh-provisioning --bin spidervpn-pair-service` in the locked command above. The operator must independently attest a genuinely new isolated node/interface, newly generated WG/management/TLS keys, no previous invitations, grants or revocations, and no other privileged writers. Empty peers or an absent directory do not prove this. Never repair a missing ledger, restart a node with history, rotate an old identity, or migrate Python data with this command.

Prepare a protected material directory (0700, trusted root-owned ancestors) containing `authorization-config.json`, `management.key` (PKCS#8 PEM), `tls.crt` and `tls.key`, all 0600. Independently pin the exact config bytes, management JWK fingerprint and TLS leaf DER. The already-provisioned WG interface and protected config must have the pinned new server public key and empty matching live/config peers. The command does not modify the interface/config.

```text
/path/to/verified/spidervpn-pair-service init-fresh attest-new-node-no-history MATERIAL_ROOT NEW_ROOT WG_INTERFACE ADVERTISED_IPV4 PORT CONFIG_SHA256 MANAGEMENT_FINGERPRINT TLS_SHA256 LIFETIME_SECONDS NAME
```

NEW_ROOT must be a nonexistent child of an existing trusted root-owned 0700 parent, separate from material root, never a current or historical authority location. Lifetime 60–86400 seconds; canonical non-loopback IPv4, port 1024–65535; name 1–64 valid characters. The exact TCI1 code is in `invitation-code.txt` (0600); never log or pass it through argv or environment. Only after successful exit and FRESH_AUTHORITY_READY, transfer the code privately to the intended client. `metadata-pin.txt` contains the new metadata digest for the trusted operator to record and pass to unchanged serve with original config/TLS pins. It is a trusted local creation handoff, not independent provisioning on another host. Keep the code file protected; never include it in shared diagnostics/backups. Serve remains loopback-only.

All output uses exclusive creation; the durable validated Open ledger is published last without replacement, with an incomplete marker blocking serve until state is synced. Existing roots, including partial state, reject init. On failure leave root/marker untouched, never retry under another name or remove marker; seek explicit recovery authority. If final marker removal sync fails, ledger bytes were already synced, but publication is uncertain: stop. No anti-rollback or privileged adversary guarantee. The initializer issues one invitation. Rollout, public exposure and actual Windows pairing require separate approval.

## Initialize from verified TradeChannel history

The `linux-fresh-provisioning` build also accepts a snapshot from a previously verified, frozen TradeChannel authority. Establish the original deployment, all registrations, revocations and invitation history independently. Obtain the snapshot SHA-256 from that decision. Both the legacy online service and the legacy SSH administration path must be fenced before a cutover snapshot is taken.

Put `existing-history.json` in the same protected material directory with mode 0600. It is a normalized snapshot with `schema_version` 1, `server_binding` matching the trusted config, `config_revision`, `management_revision`, `devices` and `invitations`. Each device has its original `request` (the TradeChannel ClientRequest object), IPv4 `address`, boolean `revoked` and `origin`. The original deployed device uses `{"kind":"deployment","plan_id":"..."}`. A paired device uses `{"kind":"signed_v2","authorization":"<original compact JWS>"}`. Invitation rows contain `id`, `expires_unix` and the original `state`. Keep private keys and invitation bearers outside this archive.

```text
/path/to/verified/spidervpn-pair-service init-existing attest-verified-frozen-tradechannel HISTORY_SHA256 MATERIAL_ROOT NEW_ROOT WG_INTERFACE ADVERTISED_IPV4 PORT CONFIG_SHA256 MANAGEMENT_FINGERPRINT TLS_SHA256 LIFETIME_SECONDS NAME
```

Run against the isolated interface and protected `/etc/wireguard/WG_INTERFACE.conf`. Initialization checks the exact server identity and active peer set in both kernel and config. It verifies the original V2 signatures and request bindings, archives the snapshot unchanged, and publishes separate device records and a fresh Rust invitation. Previously consumed invitations stay closed and expired invitations retain their expiry. A still-valid legacy Open invitation blocks initialization.

Use the current data root on restart. If a revocation leaves the kernel and config divergent, the device remains `Revoking` and the command reports failure. Reconcile the isolated peer views before retry. An earlier binary that cannot read the device records is ineligible for rollback. The old TradeChannel boot config path and its writer handoff require separate live cutover validation.

## Issue another invitation from the current authority

With the `linux-fresh-provisioning` build, an authorized root operator can issue a new TCI1 invitation from the existing authority. Use the trusted pins from a successful initialization or previous issuance. Keep the writer fence in place. The command reuses the signed pairing address and TLS port and checks the current WireGuard server binding, live peers and protected config while holding the ledger lock.

```text
/path/to/verified/spidervpn-pair-service issue-invite ROOT WG_INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256 LIFETIME_SECONDS NAME
```

On exit 0, `PAIR_INVITATION_READY <new-metadata-pin>` identifies the new invitation. Transfer the code from `ROOT/invite-<new-metadata-pin>/invitation-code.txt` (0600) privately. Use the new pin in the existing `serve` and `revoke` commands for this invitation. The listener handles the invitation selected by its pin. To serve the new invitation on the same loopback port, stop the previous listener, verify it exited, and start the listener with the new pin. The ledger, keys and WireGuard configuration remain shared across invitations.

If issuance fails, inspect the current root before issuing again. An unpublished `.invite-*.pending` directory may accompany an unused Open record. Keep it private and use a code only after successful publication. Earlier executables that only read the initial metadata cannot serve new invitation pins. Preserve the current ledger across any binary change.
