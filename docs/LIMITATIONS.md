# LIMITATIONS.md — known limitations (v1.0.0-rc.1)

1. Ubuntu/Debian-family Linux with apt, systemd user manager, and Git assumed;
   other distros degrade to `UNSUPPORTED`/`UNKNOWN` rather than guessing.
2. `systemd --user` only; no system units.
3. Managed file targets must live under `$HOME`.
4. Package rollback is report-only (no auto-remove/downgrade).
5. Service/git rollback is report-only (prior states not snapshotted).
6. Backups are not encrypted (`0700` dir, `0600` files).
7. No Secret Service ⇒ secret commands unavailable (exit 6); no fallback.
8. No runtime secret injection into `.env` files (references validated only).
9. Secret detection is heuristic; misses are possible.
10. Profile `[[files]]` / `[[services]]` / `[[variables]]` use array-of-tables
    form (the map forms shown in early drafts are rejected — fail closed).
11. Supply-chain: dependencies audited with `cargo audit` at release time;
    `cargo-deny` policy is future work.
12. No containers/VMs/remote targets, no GUI, no AI features, no telemetry —
    all deferred (see DEFERRED_FEATURES.md).
