# TESTING_STRATEGY.md — Testing and verification strategy

Status: **Implemented (v1.0.0-rc.1).** Gates: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build --release`, plus canary/attack/fuzz/idempotency/E2E suites.

Because `configctl` modifies developer machines and handles secrets, testing is
a first-class requirement, not an afterthought. Every safety claim in
`THREAT_MODEL.md` maps to an executable test.

---

## 1. Non-negotiable rules

1. **Never touch the real `$HOME`.** Tests run with `HOME`, `XDG_CONFIG_HOME`,
   `XDG_STATE_HOME`, and `--state-dir` pointed at disposable temp directories.
   A test-process guard asserts this before any test body runs.
2. **Never invoke real apt/systemctl against the host.** All subprocess use in
   tests goes through `FakeCommandRunner`, which records argv and returns
   canned outputs. A dedicated opt-in suite (`slow-tests`) may exercise real
   binaries inside a disposable container in CI only.
3. **Never use real secrets in tests.** Canary values are synthetic strings
   with the same shapes as production tokens.
4. **No secret value may appear** in stdout, stderr, JSON, logs, plan files,
   state metadata, or error messages — verified by the canary suite.
5. **No test may be skipped silently.** Safety tests are `#[must_pass]`
   (not `#[ignore]`) and run in the default `cargo test` invocation.

---

## 2. Test pyramid

| Layer | Scope | Count target (v1.0) |
|---|---|---|
| Unit | parsers, redaction, detection, path logic, planner diff, state | ≥ 300 |
| Integration | per-crate with fakes: plan→apply→verify→rollback cycles | ≥ 80 |
| End-to-end (CLI) | `assert_cmd` against the real binary in a temp HOME | ≥ 60 |
| Safety / adversarial | threat-register driven (T1–T20) | ≥ 50, one per mitigation |
| Property / fuzz | parsers, redaction, path containment, CLI args | 6 fuzz targets + ~15 properties |
| Performance | large synthetic trees, bounded memory/time | ≥ 8 benchmarks |

Reported counts at milestone gates state exact numbers; no "looks fine"
claims.

---

## 3. Test infrastructure (as built)

No `TestEnv` builder or `xtask` exists in v1; fixtures are constructed inline
per test file with `tempfile::tempdir()`:

- isolated homes, bundles, and state dirs per test (correct `0700`/`0600`
  permissions asserted, not assumed);
- `FakeCommandRunner` for all subprocesses (scripted outputs, argv
  recording) — except one read-only audit test that runs real `git` in a
  disposable repo;
- `MemoryBackend` / gated `FileTestBackend` (`CONFIGCTL_SECRET_TEST_DIR`)
  standing in for the Secret Service; `secret-tool` is never invoked in
  tests;
- `CONFIGCTL_FAIL_AFTER=<op>:<PHASE>` failpoints for crash simulation
  (test-only, serialized with a mutex, always cleared);
- read-only commands prove non-mutation by snapshotting the fixture tree
  before and after;
- command handlers are exercised as library calls (`run_plan`, `run_apply`,
  …) with JSON outputs parsed by `serde_json` in the same test.

### 3.2 Fakes (actual)

| Fake | Replaces | Behavior |
|---|---|---|
| `FakeCommandRunner` | real subprocesses | scripted responses, argv recording, failure injection |
| `MemoryBackend` | Secret Service | in-memory refs; `unavailable` mode for exit-6 tests |
| `FileTestBackend` | Secret Service | file store gated by `CONFIGCTL_SECRET_TEST_DIR` (tests/canary only) |
| Failpoints | process crashes | `CONFIGCTL_FAIL_AFTER` stops apply after a journaled phase |

---

## 4. Unit test matrix (selection)

| Module | Cases |
|---|---|
| `.env` parser | quotes (single/double), escapes, `export ` prefix, comments, inline comments, empty values, multiline quoted, `=` in values, CRLF, BOM, duplicate keys, invalid UTF-8, NUL bytes, 256 KiB cap, 10k-line cap |
| Profile loader | every PROFILE_SCHEMA.md rule; unknown keys; `x-*` passthrough; schema-version too new; duplicate targets; traversal (`..`, absolute, symlink escape); literal-secret rejection |
| Env schema | type checks, enum membership, defaults type-check, required missing, unmanaged keys |
| Secret detection | positive fixtures per signal (name, format, entropy, context); negative fixtures (`PORT`, `NODE_ENV`, `LOG_LEVEL`, UUIDs, base64 config, hashes, URLs without creds); classification always one of the four values |
| Redaction | registry exact match, pattern masking keeps prefix only, byte-safe at UTF-8 boundaries, idempotent, works on JSON strings |
| Fingerprints | normal files vs secret-containing files (redacted structural hash, T12) |
| Path safety | containment check, symlink parents, `..` components, NUL, Unicode normalization edge cases |
| Planner | idempotency (second plan = empty), deterministic ordering, conflict detection, stale-plan hashes, operation caps |
| State store | transactions, journal INTENT/DONE, crash simulation (kill between steps), history queries, ownership adoption |
| Backup store | CAS dedup, retention pruning, permission 0600, restore byte-equality |
| Verify | all six statuses, strict mode, provider unavailable → UNKNOWN |
| Git audit | tracked `.env` detection, untracked env, no-git repo, git missing |

---

## 5. Property-based and fuzz testing

| Target | Property / oracle |
|---|---|
| `env_parse` (fuzz) | never panics, never allocates beyond cap, always returns structured result or clean error |
| `profile_parse` (fuzz) | never panics; any accepted profile has sources inside bundle and targets under HOME |
| `redact` (property) | for any input containing canary `C`, output contains no occurrence of `C`; masking never increases length beyond O(n) |
| `path_containment` (property) | if containment check passes, canonicalized path is inside root |
| planner convergence (property) | apply(plan(profile)) then plan again ⇒ zero operations |
| adoption idempotency | adopt same unmanaged file twice ⇒ second adopt conflicts, no data loss |

Fuzz targets use `cargo-fuzz`; a fixed seed corpus lives in
`fixtures/` so regressions are reproducible.

---

## 6. End-to-end (CLI) test scenarios

1. `scan` on `fixtures/projects` → expected counts; HOME tree unchanged
   (byte-level snapshot proof).
2. `capture work` → bundle contains zero canary values (grep over every file).
3. `plan` → JSON schema validated; no canary values; deterministic (run twice,
   byte-identical with fixed clock).
4. `apply --dry-run` → no writes; same operation list as real apply.
5. `apply --yes` → files written; ownership recorded; backups exist.
6. Re-run `apply` → zero operations (idempotency).
7. `verify` → all `MATCH`; manually corrupt a file → `DRIFT`, exit 3.
8. `rollback` → bytes restored; verify returns `MATCH`.
9. Interrupted apply (failpoint between backup and write) → next command
   detects partial state; rollback restores; journal consistent.
10. Conflicting unmanaged file → apply exits 5 with adoption hint; `--adopt`
    then succeeds with backup.
11. `secrets set` / `list` / `get` flows with `FakeKeyring`; `--show` behavior
    with and without TTY.
12. `env verify` with valid/invalid schemas → correct severities and exit 3.
13. `audit git` on a repo with a tracked `.env` → warning; repo untouched.
14. Missing systemd / missing git → exit 7 with honest messaging, no crash.
15. Malicious profile corpus (`fixtures/profiles/malicious/`) → every bundle
    rejected at validation with exit 2; nothing written.

---

## 7. Safety test matrix (threat register → test)

| Threat | Test |
|---|---|
| T1 secret in output | Canary suite: run every command × {human, JSON, quiet, verbose} with canary fixtures; assert canary absent from all sinks |
| T2 secret in profile | Capture test + deliberate literal-secret profile ⇒ validation error |
| T3 secret in errors | Force provider/parse failures with canary fixtures; assert absent from stderr/JSON errors |
| T4/T5 traversal | Adversarial profile corpus (absolute source, `..`, symlink-in-bundle) |
| T6 symlink redirect | Symlink target/parent scenarios; assert refusal, target outside HOME untouched |
| T7 TOCTOU | Failpoint test mutating target after precheck; assert conflict abort, no partial write |
| T8 concurrency | Lock-contention test: held `flock` + apply ⇒ conflict (exit 5) |
| T9 stale plan | Plan, modify profile, apply ⇒ exit 5 with re-plan hint |
| T10 argv secrets | `secrets set X=value` rejected by parser |
| T11 get redirect | Non-TTY `secrets get --show` without `--force` ⇒ refusal |
| T12 fingerprint brute force | Values never hashed into plans/state (hashes cover refs and non-secret content only); canary byte-scan of the state dir |
| T13 backups perms | Assert `0700` state dir / `0600` backups; documented exception test |
| T14 malicious env | Fuzz + fixture corpus (expansion syntax, backticks, `$()`, deep nesting) ⇒ no execution |
| T15 DoS | Oversized payloads, deep nesting, malformed corpora ⇒ bounded, no panic, no unbounded reads |
| T16 argv injection | Package/unit names with metacharacters rejected at validation; runner test sees only safe argv |
| T17 profile scope | Profile cannot name resources not in its declared sections |
| T18 audit false negative | Real disposable git repo: tracked `.env` flagged; missing `.env.example` flagged |
| T19 dependencies | `cargo audit` clean at RC + minimal-dependency review (no `cargo-deny` policy yet — deferred) |
| T20 interrupted apply | Failpoint suite at every journal boundary |

---

## 8. Performance and bounds tests (actual)

No RSS harness or `xtask` fixtures in v1; bounds are enforced by unit-level
tests: oversized files rejected at load/capture (`256 KiB` caps), walker
depth/file/total caps, subprocess output caps and timeouts, and malformed
`.env`/profile corpora that must never panic. Full-scale benchmark fixtures
are deferred.

## 9. CI gates per milestone (actual)

| Gate | Requirement |
|---|---|
| Every change | `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, canary suite |
| P3 exit | deterministic plan/hash tests, persistence + approval tests |
| P4 exit | journaled apply tests, fail-stop, lock, TOCTOU, adopt |
| P5 exit | full status matrix + exit-code tests |
| P6 exit | secret discipline suite (argv refusal, backend gating, import) |
| P7 exit | rollback + failpoint recovery matrix + doctor |
| P8 exit | attack suite, fuzz corpus, idempotency/determinism proofs, `cargo audit` clean, `cargo build --release`, docs complete |

---

## 10. Definition of "verified"

A claim is verified only when:

1. a test exists that fails if the claim is false,
2. the test ran in CI on the current revision,
3. the exact count of passing tests is reported at the milestone gate,
4. known limitations are stated alongside the claim (no implied coverage).

No feature is declared complete on the basis of manual inspection alone.
