# SECURITY.md — security guarantees and honest limitations (P8)

## Guarantees (each with test/code evidence)

1. **No secret values in output.** `SecretValue` has no value-revealing
   `Debug`/`Display`/`Serialize`; plans carry hashes/refs only; every JSON
   and human sink passes the redaction layer. Evidence: `canary_e2e.rs`
   (canaries through scan/capture/plan/apply/verify/env/secrets/rollback/
   errors/JSON/verbose + state-dir byte scan), `capture` leak checks.
2. **No secret values in argv.** `secrets set` refuses argv values; apt/dnf/
   pacman/apk/git/systemctl argv contain names only; values travel on stdin (secret-tool
   store) or hidden prompts. Evidence: `secrets_e2e.rs`, `plan.rs`
   (fixed-argv assertions), `native_packages.rs` (elevation argv exactness).
3. **No silent mutation.** Discovery/capture/plan/verify are read-only
   (source-tree snapshot tests). Apply executes exactly the approved plan;
   stale plans are refused by hash. Evidence: `plan_e2e.rs`
   (`plan_never_writes_to_home`), apply staleness tests.
4. **Ownership protects unmanaged files.** Desired ≠ permission to write.
   Evidence: conflict tests, `--adopt` tests, `filesystem_attack.rs`.
5. **Atomic writes + backups + journal.** Temp + fsync + rename; CAS backups
   `0600`; full phase journal. Evidence: `apply.rs` phase tests, backup
   permission tests.
6. **Single mutator.** `flock` on the state dir; contention fails closed.
   Evidence: lock contention tests.
7. **Fail closed.** Malformed profiles, traversal, symlinks, TOCTOU drift,
   unavailable backends all stop with classified errors. Evidence:
   `fuzz_profile.rs`, attack suite, backend-unavailable tests.
8. **No network, no telemetry, no custom crypto.** The core performs no
   network I/O (only `sudo apt-get` / `sudo dnf` / `sudo pacman` / `sudo apk` fetch, as explicit plan-visible
   package ops). Secret storage delegates to the Secret Service.

## Honest limitations

- Backups are **not encrypted** (`0700`/`0600`, local-only).
- Heuristic secret detection can miss things; clean output is not proof.
- `sudo -n` for system packages (apt/dnf/pacman/apk) is a real privilege boundary (plan-visible, approved).
- Secret Service absent ⇒ secret features unavailable (exit 6); no fallback.
- Packages are non-transactional; rollback there is report-only.
- Same-UID attackers, compromised OS/keyring, and swap/core dumps are
  outside the boundary. `SecretValue` zeroizes on drop (best effort).
- v1 writes no secret values into files at all (no runtime `.env`
  materialization) — intentional; see DEFERRED_FEATURES.md.
