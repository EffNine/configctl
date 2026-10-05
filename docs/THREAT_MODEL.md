# THREAT_MODEL.md — configctl

Status: **Implemented (v1.0.0-rc.1).** Dispositions for every threat are recorded in §7a with evidence. v1.1 broadens discovery under central `ResourceGovernor` budgets and gates execution by `PlanActionClass`; the register below remains the v1.0 baseline (see `V1_1_HARDCORE.md`, `RESOURCE_GOVERNOR.md`).

Method: asset-driven threat model with STRIDE-style classification per
component, plus an explicit threat register (T-IDs) that maps to the safety
tests required in `TESTING_STRATEGY.md`.

---

## 1. Scope

In scope:

- the `configctl` binary and all crates in this workspace
- the profile bundle format and its files
- the state directory (ownership DB, backups, plans, journal, audit log)
- interactions with: user files under `$HOME`, `apt-get` / `dnf` / `pacman` /
  `apk` (system package managers), `systemctl --user`,
  the Git CLI, the Linux Secret Service over D-Bus
- discovery of *untrusted* content (arbitrary repos under scan roots may be
  attacker-controlled)

Out of scope:

- kernel, init, apt and systemd themselves
- root/sudo compromise after elevation is granted
- physical access and hardware attacks
- D-Bus daemon compromise
- upstream supply-chain compromise of dependencies (mitigated procedurally,
  see §7)

---

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Secret values | Highest-impact asset; credential theft | Secret Service keyring (external), transiently in process memory |
| User configuration files | Integrity and availability; lockout risk | `$HOME` |
| Ownership/state history | Correctness of plan/apply/rollback; auditability | `$STATE`, SQLite |
| Backups | Recovery from failed or malicious changes | `$STATE/backups` |
| Profile bundles | Desired-state integrity; may be shared/committed | user-chosen path |
| Audit trail | Non-repudiation of changes | `$STATE/audit.log`, `history` table |
| User's time/attention | Approval fatigue is a real attack vector | UX |

---

## 3. Trust boundaries

```
[user: approves plans]
        │
        ▼
┌───────────────┐   untrusted input   ┌──────────────────────────────┐
│ configctl CLI │◄────────────────────│ scan roots: repos, .env files│
│               │                     │ profiles from third parties  │
│               │                     └──────────────────────────────┘
│               │   privileged/system  ┌──────────────────────────────┐
│               │◄────────────────────►│ apt-get, systemctl --user,   │
│               │                     │ git CLI, Secret Service DBus │
└──────┬────────┘                     └──────────────────────────────┘
       │ writes
       ▼
┌───────────────┐
│ $HOME files   │
│ $STATE        │
└───────────────┘
```

Key insight: **everything discovered is untrusted input**. A `.env` file in a
cloned repo, a symlink in a project tree, and a shared profile are all
attacker-influenced data that must not steer the tool into reading, writing,
or printing anything outside its declared scope.

---

## 4. Adversaries

| Adversary | Capability | Primary goals |
|---|---|---|
| A1: Malicious repo/content author | Controls files under a scan root (e.g. a cloned project), may include crafted `.env`, symlinks, huge files, malformed text | Exfiltrate other secrets via output, cause writes outside scope, crash/hang the tool |
| A2: Malicious profile author | Controls a profile bundle the user is asked to apply | Path traversal, write sensitive files, install packages, enable services, exfiltrate secrets |
| A3: Local unprivileged attacker (same machine) | Reads world-accessible files, observes process args/environment, races files | Read secrets, tamper with state/backups, hijack apply |
| A4: Shoulder-surfer / terminal capture | Reads screen and command output, shell history, redirected logs | Learn secret values |
| A5: Network observer | Sees network traffic | Nothing — the tool performs no network I/O in v0.1 |
| A6: Accidental user error (not an attacker, but a primary failure mode) | Approves without reading, applies to wrong machine, reruns stale plan | Unintended modifications |

---

## 5. Security requirements

1. Secret values never reach stdout, stderr, JSON, logs, plan documents, audit
   trails, state metadata, error messages, or profile files.
2. No network I/O from the core; no telemetry, no accounts, no external calls.
3. All mutations require a plan and approval bound to that exact plan.
4. Paths in profiles and plans are contained: sources inside the bundle,
   targets under `$HOME`, no traversal, no symlink following for writes.
5. Subprocesses are invoked with fixed argv arrays (never a shell), bounded
   output, timeouts, and no inherited secret environment values.
6. The state directory is user-only (`0700`) with `0600` files; secrets never
   enter the state store.
7. Fail closed: malformed, unknown, or ambiguous inputs stop the operation.
8. The audit trail records what changed, when, by which plan — without values.
9. Heuristic results are labeled as heuristics, never as guarantees.

---

## 6. STRIDE analysis per component

### 6.1 Discovery

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Crafted project markers misrepresent a project | Evidence recorded; confidence levels; no destructive action derives from detection alone |
| Tampering | Scanned files change mid-scan (TOCTOU) | Read-only; findings are a snapshot; verification/apply re-reads and re-fingerprints |
| Repudiation | — | Findings not persisted unless requested; scan log records roots and counts |
| Information disclosure | Secret values leak through findings/output | Values never leave the parser; `SecretRegistry` redaction; bounded reads |
| Denial of service | Huge trees, deep nesting, giant files, symlink loops | Explicit roots, hard deny-list, depth/size/finding caps, `follow_links(false)`, parallel walker |
| Elevation of privilege | Parsing a crafted `.env` triggers expansion/exec | Parser is pure text: no shell expansion, no command substitution, no variable interpolation |

### 6.2 Profile loading and validation

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | `name`/paths impersonate another profile | Name must match bundle directory; paths canonicalized and validated |
| Tampering | Malicious `source` paths escape bundle | Containment check after canonicalization; reject symlinks in bundle traversal |
| Information disclosure | Profile contains a pasted secret | Validation rejects literal secret-shaped values; `audit` reports |
| Denial of service | Unbounded/deep TOML, extension abuse | Size cap, depth cap, unknown keys rejected, `x-*` never interpreted |
| Elevation of privilege | Path traversal, absolute source, `..` | Rejected in validation (§7 PROFILE_SCHEMA) before planning |

### 6.3 Planning

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | A plan is presented as current when it is stale | Plan bound to `profile_hash` + state fingerprint; apply refuses stale plans |
| Tampering | Plan document edited on disk | Plan hash verified at apply; plan files `0600`; mismatch = conflict (exit 5) |
| Information disclosure | Plan contains env values | Operations carry names/refs only; `OperationDetails` has no value fields |
| Denial of service | Exponential operation/size explosion | Operation caps; deterministic sort; bounded findings input |
| Elevation of privilege | Plan includes operations outside profile scope | Planner only emits operations derived from the profile; provider capability checks |

### 6.4 Approval UX

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Approval of plan A silently applies plan B | Approval bound to plan hash; any re-plan invalidates approval |
| Repudiation | "I never approved that" | Approval recorded in history with plan id, timestamp, and `--yes` origin |
| Denial of service (of attention) | Approval fatigue from noisy plans | Concise grouped output; `requires_approval` reserved for genuinely risky ops; no confirm-spam |

### 6.5 Apply

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Symlink at target redirects a write | `lstat` + `O_NOFOLLOW`; parent directory checks; refusal on any symlink component for managed targets |
| Tampering | Concurrent writer changes target between precheck and write | Precheck immediately before write; atomic temp+rename; journal + expected hash; conflict abort |
| Tampering | Another configctl instance applies concurrently | `flock` single-instance lock for apply/rollback |
| Repudiation | Change made without a trace | Journal INTENT before, DONE/FAILED after; audit log; history table |
| Information disclosure | Secrets in argv of `sudo apt-get` / `sudo dnf` / `sudo pacman` / `sudo apk` | Package-manager argv contains package names only; env is scrubbed; `sudo -n` avoids password prompts on stdin |
| Denial of service | Partial apply leaves inconsistent state | Journaled recovery; explicit rollback; `doctor` surfaces partial states |
| Elevation of privilege | Malicious package/unit names injected into argv | Strict name grammars; argv arrays; never a shell |

### 6.6 State store and backups

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Attacker plants ownership records to legitimize overwrites | State dir `0700`; records also cross-checked against disk fingerprints before destructive ops |
| Tampering | Journal/DB edited to hide or fake history | SQLite transactions; plan hash checks; `doctor` integrity check; audit log append-only best-effort |
| Information disclosure | Backups contain secrets from managed files | Managed files are dotfiles, not secret files by default; state dir `0700`; limitation documented; encrypted backups deferred |
| Denial of service | Disk exhaustion from backups | Backup retention policy (keep N versions per resource, configurable); size caps |
| Elevation of privilege | Restoring a backup into an unintended path | Restore targets come from history records with validated containment, not from paths in backup metadata |

### 6.7 Secrets subsystem

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Rogue D-Bus service impersonates Secret Service | Session-bus peer verification is delegated to the `keyring`/Secret Service stack; documented dependency; no custom D-Bus code |
| Tampering | Another local process modifies keyring entries | Outside our boundary; `verify` compares existence, not values |
| Information disclosure | Values printed by `secrets get`, leaked via args, env, logs | `get` requires `--show` and a TTY (or `--force`); values never passed as argv; redaction registry; no logging of values |
| Information disclosure | Value captured in core dump / swap | `SecretValue` zeroized on drop where practical; limitation documented (OS swap not controlled) |
| Denial of service | Locked/absent keyring blocks work | Exit 6 with remediation; non-secret commands unaffected |
| Elevation of privilege | Secret refs used to read unintended keyring entries | Namespace/key grammar validated; no path syntax; exact-match lookup only |

### 6.8 Git integration and audit

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | `git` binary shadowed on PATH | Prefer absolute path from `PATH` resolution but never pass user data as config; audit is advisory only |
| Tampering | Audit auto-fixes (e.g. `git rm --cached`) | v0.1 audit is strictly read-only; remediation is printed for the user to run |
| Information disclosure | Audit prints tracked secret values | Audit reports file + key name + signal, never the matched value |
| Denial of service | Huge repos slow audit | Bounded file list, size caps, timeout; limits reported |

---

## 7. Threat register

| ID | Threat | Mitigation summary | Residual risk | Verified by |
|---|---|---|---|---|
| T1 | Secret value printed by any command | Type-level `SecretValue`, registry + pattern redaction at all sinks | Medium — unknown formats may not match patterns | Canary leak suite (all commands, all output modes) |
| T2 | Secret written into profile by capture/validation | Validation rejects literal secret-shaped values; capture emits refs only | Low | Unit + integration tests on capture output |
| T3 | Secret in error message or panic | Static error templates; no value interpolation; panic path reviewed | Low | Fuzz + canary tests with forced errors |
| T4 | Path traversal via profile `source` | Containment after canonicalization; `..` and absolute rejected | Low | Property tests with adversarial paths |
| T5 | Write outside `$HOME` via target path | Target must be `~/...`; canonical containment re-checked at apply | Low | Integration tests with crafted profiles |
| T6 | Symlink redirection on write | `lstat`/`O_NOFOLLOW`; refuse symlinked targets and parents | Low | Symlink attack test suite |
| T7 | TOCTOU between plan and apply | Expected-before fingerprints checked immediately before each operation | Medium — tiny race window remains for non-atomic provider ops | Race tests where feasible; design review |
| T8 | Concurrent applies | `flock` single-instance lock | Low | Concurrency integration test |
| T9 | Stale/forged plan applied | Plan hash + profile/state hashes verified at apply | Low | Unit tests on staleness |
| T10 | Secret in CLI argv (`secrets set X=value`) | Values accepted only via hidden prompt or `--stdin`; argv form rejected | Low | CLI parse tests |
| T11 | Secret in `secrets get` redirected to a file | `--show` required; non-TTY requires `--force`; warning on stderr | Medium — user can force | CLI tests; docs |
| T12 | Offline brute force of stored fingerprints | Hash redacted structural form for secret-containing files | Low | Unit tests on fingerprint function |
| T13 | Secret in state backups | State dir `0700`; backups `0600`; secret-bearing files excluded from default managed set; documented | Medium — local attacker with same UID | Permission tests; docs |
| T14 | Malicious `.env` triggers code execution | Pure bounded parser; no expansion/interpolation; fuzzed | Low | Fuzz target; parser unit tests |
| T15 | Oversized/deep inputs cause DoS | Size/depth/finding caps; deny-list; timeouts on subprocesses | Low | Performance tests with adversarial fixtures |
| T16 | apt/dnf/pacman/apk/systemctl argv injection | Strict name grammars; argv arrays; no shell | Low | Unit tests on command construction |
| T17 | Rogue profile enables unwanted service/package | Plan visible; approval required; only profile-declared resources; user services only | Medium — user approves | Integration tests; docs |
| T18 | Audit misreports safety (false negative on tracked `.env`) | Conservative checks; report uncertainty; `git` required | Medium — heuristic | Audit fixture tests |
| T19 | Supply-chain compromise of dependencies | Minimal dependency set; `cargo-deny` advisories/licenses; review before adding | Medium | CI |
| T20 | Interrupted apply leaves unknown state | Journaled INTENT/DONE; `doctor` detects; rollback restores | Medium — packages non-transactional | Failpoint integration tests |

---

## 7a. v1.0.0-rc.1 dispositions (with evidence)

| ID | Disposition | Evidence |
|---|---|---|
| T1 | MITIGATED | Type-level `SecretValue`, registry+pattern redaction at all sinks; `canary_e2e.rs` asserts absence across scan/capture/plan/apply/verify/env/secrets/rollback/errors/JSON/verbose + state-dir byte scan. Residual: unknown formats rely on registry layer. |
| T2 | MITIGATED | Capture emits refs only; validation rejects secret-like literals; post-write leak check; `capture` + canary tests. |
| T3 | MITIGATED | Static error templates, no value interpolation; error-path canary assertions. |
| T4 | MITIGATED | Bundle containment + `..`/absolute/symlink rejection at load; `fuzz_profile.rs`, attack suite. |
| T5 | MITIGATED | Targets must be `~/...`, expanded against `$HOME` and re-checked at apply; traversal rejected in validation. |
| T6 | MITIGATED | `lstat`/`O_NOFOLLOW` discipline, parent-component checks at precheck and pre-write; `filesystem_attack.rs` (incl. a parent-symlink create that was caught and fixed in P8). |
| T7 | MITIGATED (partial) | `expected_before` prechecks + atomic rename narrow the window; TOCTOU abort tests. Tiny race remains for non-atomic provider ops — documented. |
| T8 | MITIGATED | `flock` single-instance lock for apply/rollback; contention test. |
| T9 | MITIGATED | Plan hash + profile/state binding verified at apply; tamper/staleness tests. |
| T10 | MITIGATED | argv values refused (exit 2); hidden prompt / `--stdin` only; test. |
| T11 | PARTIALLY MITIGATED | `--show` needs TTY or `--force` + stderr warning; `--show --json` refused. A user can still force output — documented, accepted. |
| T12 | MITIGATED | Plan/state store hashes of redacted structural forms and content hashes of non-secret dotfiles; no brute-forceable secret hashes by design (values never hashed). |
| T13 | ACCEPTED | Backups `0600` in a `0700` dir; secret-bearing files excluded from capture; unencrypted backups documented in SECURITY.md/LIMITATIONS.md. |
| T14 | MITIGATED | Pure bounded `.env` parser (no expansion/interpolation/exec); fuzz tests. |
| T15 | MITIGATED | Size/depth/finding caps, deny-list, subprocess timeouts+caps; oversized/broad fixtures tested. |
| T16 | MITIGATED | Strict grammars (package/unit/env/secret-ref), argv arrays, no shell; argv-construction tests. |
| T17 | PARTIALLY MITIGATED | Plan-visible ops + approval binding + user-services-only scope; a user can still approve a malicious profile — approval UX groups destructive ops. Documented. |
| T18 | PARTIALLY MITIGATED | Conservative read-only checks with confidence labels; fixture tests. Heuristics documented as non-guarantees. |
| T19 | MITIGATED (procedural) | Minimal deps (rusqlite/sha2/hex/fs2/rpassword + existing); `cargo audit` clean at RC (see P8 report); no build scripts in new deps. |
| T20 | MITIGATED | Full phase journal + backups + explicit recovery classification; failpoint tests for every phase; `doctor` surfaces state. Packages inherently non-transactional — documented. |

---

## 7b. `dnf`/`pacman`/`apk` delta (no new T-ID)

Shipping the Fedora/RHEL (`dnf`), Arch (`pacman`), and Alpine (`apk`)
providers adds no new threat class, so no new T-ID is opened; coverage stays
under the existing package-manager IDs:

- **No new elevation path (T16/T17).** Installs elevate only via `sudo -n`
  with fixed argv (`dnf install -y`, `pacman -S --noconfirm`, `apk add` —
  plain `apk add` is non-interactive by default, verified on apk-tools
  2.14.4 and 3.0.6), the same discipline as `apt-get install -y`. Unknown
  providers in a hand-edited plan fail closed (`ProviderUnavailable`,
  exit 7) instead of running.
- **New subprocess argv, same shape (T16).** `rpm -qa --queryformat
  '%{NAME}\t%{EVR}\t%{ARCH}\n'` (pinned format string), `rpm -q <name>`,
  `pacman -Q[. <name>]`, `apk info -v` / `apk info -e <name>`, plus
  `dnf --version` / `pacman --version` / `apk --version` binary probes. All
  fixed argv through `CommandRunner` (bounded output, timeout, scrubbed
  env, never a shell); package names are grammar-validated and hostile
  manager output lines are skipped, with argv-construction tests.
- **No new secret surface (T1/T10).** Argv carries package names only; distro
  detection reads `/etc/os-release` (world-readable machine facts, no
  secrets); nothing new enters plans, state, logs, or error text.
- **Rollback stays report-only (T20).** Packages are non-transactional on
  every manager; rollback prints `dnf remove` / `pacman -R` / `apk del`
  manual hints and never auto-removes — the same accepted residual as apt.

Verified by: `configctl-core/tests/native_packages.rs` (probe matrix,
golden-output parsing incl. rpm epochs and real-container `apk info -v`
captures, elevation argv exactness, unavailable paths, live negative probe)
and the extended `configctl-discovery/tests/packages.rs` inventory tests.
The `apk` parser and argv were additionally verified against real
`alpine:3.19` (apk-tools 2.14.4) and `alpine:latest` (3.24.1, apk-tools
3.0.6) containers.

---

## 7c. TUI delta (no new T-ID)

Phase T1 of the interactive dashboard (`configctl tui`, docs/TUI.md) adds no
new threat class, so no new T-ID is opened. It is strictly read-only: the
TUI calls only `status` state queries, `verify`, `env explain`, and `doctor`
— never `plan`/`apply`/`rollback`/`capture` — and renders the same
value-redacted data as the CLI (secret declarations never carry values, and
the render layer redacts them again), so the display/redaction dispositions
(T1/T10) are unchanged. The terminal is entered through `ratatui::run`,
which restores the alternate screen and raw mode on normal exit *and* on
panic; a non-TTY stdin/stdout is refused up front (exit 2, one line) instead
of writing escape sequences into pipes. No new privilege, no network, no
persistence. Mutating TUI flows (T2+) require their own threat review before
implementation, exactly like move mode's promotion rule.

---

## 8. Security non-goals and honest limitations

- **No guarantee against a compromised host.** If the OS, keyring daemon, or
  same-UID attacker is compromised, configctl cannot protect secrets.
- **Backups are not encrypted in v0.1.** They live in a `0700` directory and
  contain copies of managed files. Encrypted backups are deferred.
- **Heuristic secret detection can always miss things.** Findings are labeled
  with confidence; a clean scan is not proof of secret safety.
- **`sudo` for system packages is a real privilege boundary.** Only
  apt/dnf/pacman/apk install operations may elevate, only via `sudo -n`, and
  only after a plan that shows them. Everything
  else runs as the user.
- **v0.1 writes no secret values to disk at all**, so it also cannot fix a
  project's `.env` for you; that limitation is intentional and deferred.

---

## 9. Open security questions

1. Should backups of files flagged as secret-containing be refused outright in
   v0.1 rather than stored `0600`?
2. Should `secrets get --show` be disallowed without an interactive TTY in all
   cases (no `--force`)?
3. Is `sudo -n apt-get` acceptable for v1.0, or should v1.0 be plan-only for
   packages and defer elevation entirely?
4. Retention policy numbers for backups (count, age, total size).
5. Whether to add `mlock`/`zeroize` guarantees or document "best effort" only.
