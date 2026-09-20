# TESTING_STRATEGY.md — Testing and verification strategy

Status: **P0 draft. No implementation exists yet.**

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

## 3. Test infrastructure

### 3.1 `TestEnv` fixture builder (core, feature `test-fakes`)

```rust
let env = TestEnv::builder()
    .home_tempdir()                          // isolated HOME
    .project("conductor", |p| p
        .file(".env", "PORT=3000\nAGNES_API_KEY=sk-test-CANARY123\n")
        .file(".env.example", "PORT=\nAGNES_API_KEY=\n")
        .marker("Cargo.toml"))
    .dotfile(".gitconfig", "[user]\n\tname = Test\n")
    .fake_apt().installed(["git", "curl"]).available(["ripgrep"])
    .fake_systemd().unit("docker", enabled: false, running: false)
    .fake_keyring().with("secret://work/dev/X", "CANARY")
    .build();
```

The builder:

- creates a temp HOME and temp state dir with correct permissions,
- installs fakes into the provider registry,
- exposes `env.run(["plan", "work"])` returning structured output for
  assertions,
- snapshots the entire HOME tree (path + mode + hash) before and after any
  read-only command to prove nothing changed.

### 3.2 Fakes

| Fake | Replaces | Behavior |
|---|---|---|
| `FakeCommandRunner` | real subprocesses | scripted responses, argv recording, timeout/failure injection, output-cap tests |
| `FakeApt` | apt provider backend | in-memory package DB |
| `FakeSystemd` | systemctl backend | in-memory unit states |
| `FakeKeyring` | Secret Service | in-memory store, `Unavailable` mode for exit-6 tests |
| `FakeStateStore` | SQLite | in-memory maps; SQLite itself tested separately against real temp files |
| `ScriptedWalker` | filesystem walker | deterministic entries, adversarial paths, symlinks |

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
| T8 concurrency | Two `apply` processes on same state dir; second exits 5 |
| T9 stale plan | Plan, modify profile, apply ⇒ exit 5 with re-plan hint |
| T10 argv secrets | `secrets set X=value` rejected by parser |
| T11 get redirect | Non-TTY `secrets get --show` without `--force` ⇒ refusal |
| T12 fingerprint brute force | Assert stored fingerprint of secret-containing file is not sha256(raw bytes) |
| T13 backups perms | Assert `0700` state dir / `0600` backups; documented exception test |
| T14 malicious env | Fuzz + fixture corpus (expansion syntax, backticks, `$()`, deep nesting) ⇒ no execution |
| T15 DoS | Giant file, 100k-dir tree, symlink loop ⇒ bounded time/memory, no panic |
| T16 argv injection | Package/unit names with metacharacters rejected at validation; runner test sees only safe argv |
| T17 profile scope | Profile cannot name resources not in its declared sections |
| T18 audit false negative | Fixture repo matrix (tracked/untracked/ignored/submodule) |
| T19 dependencies | `cargo-deny` + review checklist |
| T20 interrupted apply | Failpoint suite at every journal boundary |

---

## 8. Performance tests

Fixtures generated by `xtask fixtures`:

- flat: 10,000 files across 500 projects
- deep: depth 50, with symlink loops
- large: single 100 MiB file (must be skipped by cap, not read)
- many-env: 2,000 `.env` files with 20 variables each

Budgets (to be calibrated at P1, tracked as regressions afterwards): scan of
the flat fixture under a few seconds; memory ceiling enforced by a test harness
that watches RSS; `verify` scales linearly with managed resources.

---

## 9. CI gates per milestone

| Gate | Requirement |
|---|---|
| Every PR | fmt, clippy `-D warnings`, tests, dependency-direction check, canary suite |
| P1 exit | scan tests + redaction suite + performance budget on flat fixture |
| P2 exit | capture leak test (bundle grep = zero canaries) |
| P3 exit | deterministic plan tests (byte-identical repeated runs) |
| P4 exit | apply/rollback filesystem tests + failpoint suite |
| P5 exit | full status matrix tests |
| P6 exit | secret suite + FakeKeyring + real Secret Service smoke test (containerized, opt-in) |
| P7 exit | interrupted-operation recovery matrix |
| P8 exit | fuzz targets clean for a fixed duration, cargo-deny clean, docs complete |

---

## 10. Definition of "verified"

A claim is verified only when:

1. a test exists that fails if the claim is false,
2. the test ran in CI on the current revision,
3. the exact count of passing tests is reported at the milestone gate,
4. known limitations are stated alongside the claim (no implied coverage).

No feature is declared complete on the basis of manual inspection alone.
