# LIMITATIONS.md — known limitations (v1.0.0-rc.1; v1.1 additions in §2)

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

## v1.1 additions (hardcore mapping)

13. Capture is broader than apply: `packages.other`, `[[toolchains]]`,
    `[[executables]]`, `[[mounts]]`, `[[directories]]`, `[machine]`, and
    `[hardware]` are recorded (schema v2) but not reproduced. `apply` manages
    apt packages, files, non-secret environment literals, `systemd --user`
    enable/disable, and git `user.name`/`user.email` only.
14. System-scope services are captured but classified `PRIVILEGED`; `apply`
    refuses them even with `--yes`.
15. Discovery runs under governor budgets (defaults: 10 min wall clock, 5M
    files, 256 subprocesses — see RESOURCE_GOVERNOR.md). A budget stop reports
    `PARTIAL` with the named reason, never a false `COMPLETE`, and resources
    beyond the stop point are simply not discovered.
16. Multi-manager package and toolchain discovery is observational; only apt
    installation is executable.
17. Informational v2 sections are not diffed yet: `plan` does not warn about
    recorded resources it cannot reproduce. Reporting them explicitly as
    `UNSUPPORTED`/`MANUAL` is a v1.1 close-out item.
