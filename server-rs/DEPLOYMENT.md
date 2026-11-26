# Stage 4A: local pairing process (candidate, not deployed)

Build the exact reviewed source with `cargo build --locked --release --manifest-path server-rs/Cargo.toml --features linux-pairing-process --bin spidervpn-pair-service`. Record the commit and executable SHA-256; the feature is off by default. This is a foreground loopback-only process, not an installer or replacement for the existing Python service.

An authorized operator must independently establish current trusted history, exclusive privileged writer discipline, the existing Rust ledger and the exact WireGuard server identity before launch. Do not initialize missing state or convert legacy JSON. Provide an absolute root-owned directory mode 0700, with root-owned non-writable ancestors and fixed regular single-link files: `authority-ledger.json`, `invite-metadata.json`, `authorization-config.json`, `management.key` (PKCS#8 PEM), `tls.key` (PEM) all 0600; `tls.crt` (PEM, no group/world write). Metadata/config pins are SHA-256 of exact record bytes, TLS pin is SHA-256 of original leaf DER. Obtain pins independently from the trusted provisioning decision, not by trusting adjacent files or an incoming request. No bearer/key in argv, environment or logs.

Explicit invocation (placeholders, not a production command):

```text
/path/to/verified/spidervpn-pair-service serve /protected/current-root 18443 WG_INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256
```

Run only with explicit authorization in an isolated network namespace. Existing accepted WG adapter and protected root/config require effective UID 0 and CAP_NET_ADMIN; the process currently retains root privileges (no new privileges, no dumpable core). Do not expose the port, forward it publicly, run setuid, or add a production unit. Privilege separation and trusted production provisioning/old-writer fencing need separate approval before public deployment. The fixed listener is 127.0.0.1, not the advertised tunnel endpoint.

Observe static READY/STOPPED markers, process exit, exact executable identity and actual local TLS responses. SIGTERM or SIGINT closes the accept loop and drains admitted workers within existing network budgets; local disk/transaction failures can delay drain. Restart with the same current trusted root and pins only after the previous process has exited. GET returns InvitationReady for Open and RetryOnly for eligible Consumed; identical authenticated POST returns the original signed authorization. No state creation or expiry extension on GET.

Rollback: stop and verify exit, preserve the current durable ledger, protected WG config and live peers, and verify identity/inventory. An earlier executable/unit may be restored only if separately proven compatible with the current durable state and writer fence. Never restore an older ledger, delete Pending/Revoking, recreate missing state or reactivate the legacy writer after Rust mutation. If compatibility/history cannot be established, leave the service stopped and request explicit recovery authorization. No real VPS rollout, Windows pairing or legacy migration is authorized by this document.
