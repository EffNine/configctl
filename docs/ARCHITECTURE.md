# ARCHITECTURE.md — configctl

Status: **P0 design draft. No implementation exists yet.**
Scope of this document: the v0.1 architecture (milestones P0–P8). Anything not
needed for v1.0 is listed in `DEFERRED_FEATURES.md` and deliberately not designed
in detail here.

---

## 1. Purpose

`configctl` is a Linux-first environment management tool. It discovers the
configuration a developer machine already has, lets the user declare a desired
state as a **profile**, shows exactly what would change in a **plan**, applies
only after explicit approval, and verifies that the machine still matches the
profile.

The tool manages, in v1.0:

- installed packages (apt)
- dotfiles and managed configuration files
- non-secret environment variables
- project `.env` files (discovery, schema validation, secret classification)
- `systemd --user` services
- Git configuration metadata (read-only discovery + audit)
- secrets — through references to a native Linux secret store, never as values

Everything in v0.1 targets Ubuntu/Debian-family Linux with systemd and apt on
x86_64. Future platforms are enabled by provider boundaries, not by pretending
the core is portable today.

---

## 2. v0.1 scope

**In scope**

| Area | v0.1 behavior |
|---|---|
| Discovery | Explicit scan roots, gitignore-style excludes, bounded parsing, secret classification |
| Projects | Marker-based detection with recorded evidence, `.env*` discovery |
| Profiles | TOML bundles, schema versioning, validation, capture from a live machine |
| Planning | Deterministic operation list, conflicts, diff, machine-readable output |
| Apply | Files, env variables (literals), apt packages, `systemd --user` units |
| Verify | `MATCH` / `DRIFT` / `MISSING` / `UNMANAGED` / `UNKNOWN` per resource |
| Rollback | File content rollback from a content-addressed backup store; conservative package behavior |
| Secrets | `SecretProvider` abstraction; Linux Secret Service backend; references only; redaction everywhere |
| Audit | tracked `.env`, secret-like content in tracked files, unsafe permissions |
| Output | human + `--json`, stable exit codes, redaction at every sink |

**Out of scope for v0.1** (see `DEFERRED_FEATURES.md`): macOS/Windows, non-apt
package managers, non-systemd init, system-level units, sudo-managed resources
beyond apt, containers/VMs/remote targets, GUI, AI/LLM features, telemetry,
cloud services, custom cryptography, package downgrades, runtime secret
injection, templating.

---

## 3. Design principles

1. **Never silently modify.** Discovery is read-only. Mutation requires a plan
   and an explicit approval that is bound to that exact plan.
2. **The plan is the unit of change.** `apply` executes exactly the operations
   in the approved plan; it never invents operations at execution time.
3. **Secrets are values with no voice.** A secret value may enter the process
   only through the secret backend and is never serialized, rendered, logged,
   diffed, or written into a profile. Profiles carry `secret://` references.
4. **Local-first and offline.** The core performs no network I/O. There is no
   account, no telemetry, no external API dependency.
5. **Provider boundaries.** The core knows traits and domain types; apt,
   systemd, filesystem, and env details live in provider crates.
6. **Deterministic and idempotent.** Re-running `plan`, or `apply` after
   convergence, produces no changes. Ordering is stable and specified.
7. **Fail closed on ambiguity.** Conflicts, stale plans, malformed profiles,
   symlinked targets, or unexpected state stop execution with a clear error
   rather than guessing.
8. **Ownership is explicit.** A resource is *managed* only if the state store
   says so. Unmanaged files are never overwritten without an adoption flow.
9. **Bounded everything.** Scanning, parsing, file reads, subprocess output,
   and retention are bounded. No whole-filesystem walks.
10. **Honest heuristics.** Secret detection and project detection return
    confidence levels and evidence; the tool never claims certainty it does
    not have.

---

## 4. Lifecycle

```
        DISCOVER            read-only
            │                (findings, no mutation)
            ▼
        UNDERSTAND          classification, project association,
            │                confidence, risk, ownership
            ▼
          PLAN              desired state vs actual state
            │                → operations + conflicts  (persisted)
            ▼
     USER APPROVES          plan-bound, interactive or --yes
            │
            ▼
          APPLY             journaled, backed up, idempotent
            │
            ▼
         VERIFY             MATCH / DRIFT / MISSING /
            │                UNMANAGED / UNKNOWN
            ▼
       ROLLBACK             (on demand, from history)
```

Guarantees per phase:

| Phase | Guarantee |
|---|---|
| Discover | No writes outside the state dir. Secrets never rendered. |
| Understand | Every inferred attribute carries confidence + evidence. |
| Plan | No mutation. Plan is serializable, redacted, reproducible. |
| Approve | Approval is invalidated if the profile or relevant state changed after planning. |
| Apply | Every operation is journaled before execution; every modified file has a backup; single-instance lock. |
| Verify | Read-only. Never repairs. |
| Rollback | File-first; package rollback is conservative and never promises downgrades. |

---

## 5. Component view

```
┌────────────────────────────────────────────────────────────────────┐
│ configctl-cli                                                      │
│   clap parsing · command handlers · human/JSON rendering · exit codes │
└──────────────┬─────────────────────────────────────────────────────┘
               │ depends on
┌──────────────▼─────────────────────────────────────────────────────┐
│ configctl-core                                                     │
│   domain types · provider traits · profile load/validate · planner │
│   state store (SQLite) · verifier · env parsing · redaction        │
│   (platform-independent; no apt/systemd/filesystem specifics)      │
└───┬───────────────┬───────────────┬───────────────┬────────────────┘
    │               │               │               │
┌───▼─────┐  ┌──────▼──────┐  ┌─────▼──────┐  ┌─────▼──────────────┐
│config-  │  │configctl-   │  │configctl-  │  │configctl-          │
│ctl-     │  │provider-    │  │provider-   │  │provider-env        │
│discovery│  │apt          │  │systemd     │  │(.env parsing/verify)│
└─────────┘  └─────────────┘  └────────────┘  └────────────────────┘
    │               │               │               │
    └───────────────┴───────┬───────┴───────────────┘
                            │
              ┌─────────────▼─────────────┐   ┌──────────────────────┐
              │ configctl-secret          │   │ configctl-audit      │
              │ SecretProvider impls      │   │ git/permission/secrets│
              │ (Linux Secret Service)    │   │ audit checks         │
              └───────────────────────────┘   └──────────────────────┘
```

Dependency direction: **providers → core**, never the reverse. The CLI crate is
the only place that knows the concrete provider set (composition root). See
`WORKSPACE_STRUCTURE.md` for crate-by-crate rules.

---

## 6. Core domain model

Illustrative Rust shapes (design, not final code):

```rust
// ---- identity ----
pub struct ProfileId(String);
pub struct ProviderId(&'static str);
pub struct PlanId(String);          // ULID
pub struct OperationId(String);     // stable within a plan

// ---- discovery ----
pub enum FindingKind {
    Project, ConfigFile, EnvFile, EnvVar,
    Package, Service, GitConfig, SshConfig, ShellConfig,
    SecretCandidate, Tool,
}

pub enum Confidence { Certain, Likely, Unknown }   // kind/project inference
pub enum RiskLevel  { None, Low, Medium, High }
pub enum Ownership  { Unmanaged, Managed { profile: ProfileId }, Foreign }

pub struct Finding {
    pub kind: FindingKind,
    pub path: Option<PathBuf>,
    pub project: Option<ProjectRef>,
    pub source: &'static str,        // discoverer id
    pub confidence: Confidence,
    pub risk: RiskLevel,
    pub ownership: Ownership,
    pub evidence: Vec<Evidence>,     // e.g. markers found, detection signals
    pub metadata: FindingMeta,       // typed, redaction-safe (never values)
}

// ---- secrets ----
pub struct SecretRef { /* parsed from secret://<namespace>/<path...> */ }
pub struct SecretValue(/* private; no Display, no Serialize */);

// ---- profile ----
pub struct Profile {
    pub schema_version: u32,
    pub name: String,
    pub packages: PackageSpec,
    pub files: Vec<FileSpec>,
    pub environment: Vec<EnvEntry>,   // literal | SecretRef
    pub services: Vec<ServiceSpec>,
    pub projects: Vec<ProjectSpec>,
}

// ---- planning ----
pub enum OperationKind {
    FileCreate, FileWrite, FileDelete,
    PackageInstall, PackageRemove,
    ServiceEnable, ServiceDisable, ServiceStart, ServiceStop,
    EnvSet, EnvUnset,
}

pub struct Operation {
    pub id: OperationId,
    pub provider: ProviderId,
    pub kind: OperationKind,
    pub target: ResourceRef,
    pub summary: String,             // human text, redaction-safe
    pub risk: RiskLevel,
    pub requires_approval: bool,
    pub expected_before: Option<Fingerprint>,
    pub desired_after: Fingerprint,
    pub details: OperationDetails,   // typed per provider, redaction-safe
}

pub struct Plan {
    pub id: PlanId,
    pub profile: String,
    pub profile_hash: String,        // profile bundle content hash
    pub operations: Vec<Operation>,
    pub conflicts: Vec<Conflict>,    // blocking
    pub warnings: Vec<Warning>,
    pub created_at: SystemTime,
}

// ---- state ----
pub struct ManagedRecord {
    pub resource: ResourceRef,
    pub profile: ProfileId,
    pub fingerprint: Option<Fingerprint>,
    pub backup: Option<BackupRef>,
    pub updated_at: SystemTime,
}

// ---- verification ----
pub enum CheckStatus { Match, Drift, Missing, Unmanaged, Unknown, Error }
```

`FindingMeta`, `OperationDetails`, and `Warning` are closed enums/tables with
no free-form value fields, which is how redaction by construction is achieved
(see §13).

---

## 7. Planning model

**Inputs**

1. Profile bundle (validated, hashed).
2. Current machine state as reported by provider `discover`/`probe`.
3. Ownership records from the state store.

**Process**

1. Canonicalize the profile: sort collections, resolve defaults, expand `~`,
   validate every path and reference.
2. Each provider independently emits candidate operations for its slice of the
   desired state (`packages`, `files`, `environment`, `services`, project env
   schemas).
3. The planner merges operations, then:
   - drops operations that are already satisfied (**idempotency**),
   - detects conflicts: unmanaged file at a managed target, duplicate targets,
     stale expected fingerprints, path escapes, unavailable providers,
   - sorts deterministically (see below),
   - assigns stable `OperationId`s and a plan hash.
4. The plan (redacted document + hash) is persisted in the state store; the
   latest plan per profile is retrievable.

**Deterministic sort order**

Apply order (creates/enables first):

1. `PackageInstall`
2. `FileCreate` / `FileWrite` (sorted by lexicographic target path)
3. `EnvSet`
4. `ServiceEnable` / `ServiceStart` (sorted by unit name)

Rollback/removal order is the reverse. This ordering keeps dependencies
(package → file → env → service) sane without claiming a real dependency solver.

**Plan binding and staleness**

- A plan records `profile_hash`, a state fingerprint (ownership + relevant
  resource fingerprints), tool version, and schema version.
- `apply` refuses to run if the current profile hash or state fingerprint
  differs from the recorded plan, unless the user re-plans. There is **no
  automatic re-plan inside apply**.
- Approval is bound to the plan hash; approving one plan never approves a
  later one.

---

## 8. Apply model

Execution protocol per operation:

```
1. INTENT      journal(plan_id, op_id, phase=INTENT, expected_before, backup_ref)
2. PRECHECK    re-read current state; must equal expected_before
                 ├─ already satisfied  → mark NOOP, journal DONE
                 └─ mismatch           → abort with conflict (exit 5)
3. BACKUP      (mutating file ops) copy previous content into CAS, journal ref
4. EXECUTE     provider-specific action (atomic write, apt-get, systemctl)
5. POSTCHECK   re-read state; must equal desired_after
6. DONE        journal(phase=DONE, result)
```

- **Failures stop the run.** No best-effort continuation. The plan is marked
  `partial`, and `configctl rollback` / `configctl doctor` surface recovery
  options. Recovery is explicit, never automatic.
- **Atomic file writes**: write to a temp file in the target directory, `fsync`,
  `rename(2)`, then fsync the directory. Symlinked targets are rejected
  (`O_NOFOLLOW` on open; `lstat` checks on parents).
- **Single instance**: `flock` on `$STATE/.lock` for `apply` and `rollback`.
- **Privileges**: configctl itself never runs as root and never calls `sudo`
  silently. The apt provider may invoke `sudo -n apt-get …` as a distinct,
  plan-visible operation class only if the user approved a plan that contains
  it; if privileges are unavailable, the operation fails with exit code 8 and
  a human-readable hint. File, env, and `systemd --user` operations never
  require elevation.
- **No secret writes**: v0.1 does not write secret values into any file
  (`environment:` entries backed by `secret://` are validated for existence in
  the keyring and recorded as references only). Runtime injection and
  materialization are deferred (`DEFERRED_FEATURES.md`).

---

## 9. State management

**Layout** (XDG compliant, overridable in `config.toml`):

```
$XDG_STATE_HOME/configctl/            # default ~/.local/state/configctl
├── state.db                          # SQLite: ownership, plans, journal, history
├── backups/
│   └── objects/<sha256>              # content-addressed file backups (0600)
├── plans/
│   └── <plan-id>.json                # redacted plan documents (0600)
├── audit.log                         # append-only human-readable audit trail (0600)
└── .lock                             # flock target (apply/rollback)
```

Directory is created `0700`; all files `0600` except the SQLite db (0600 too).

**SQLite schema (sketch)**

```sql
CREATE TABLE meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);

CREATE TABLE resources (
  id            INTEGER PRIMARY KEY,
  kind          TEXT NOT NULL,            -- file | package | service | env_ref
  locator       TEXT NOT NULL,            -- normalized absolute path / name
  owner_profile TEXT,
  fingerprint   TEXT,                     -- sha256 or provider-specific
  updated_at    INTEGER NOT NULL,
  UNIQUE(kind, locator)
);

CREATE TABLE plans (
  id            TEXT PRIMARY KEY,
  profile       TEXT NOT NULL,
  profile_hash  TEXT NOT NULL,
  state_hash    TEXT NOT NULL,
  status        TEXT NOT NULL,            -- planned | applying | applied | partial | rolled_back
  created_at    INTEGER NOT NULL,
  doc_path      TEXT NOT NULL
);

CREATE TABLE journal (
  id           INTEGER PRIMARY KEY,
  plan_id      TEXT NOT NULL REFERENCES plans(id),
  op_id        TEXT NOT NULL,
  phase        TEXT NOT NULL,             -- INTENT | BACKUP | DONE | FAILED
  backup_sha   TEXT,
  detail       TEXT,                      -- redaction-safe
  recorded_at  INTEGER NOT NULL
);

CREATE TABLE history (
  id           INTEGER PRIMARY KEY,
  plan_id      TEXT,
  op_id        TEXT,
  action       TEXT NOT NULL,             -- apply | rollback | adopt | import ...
  result       TEXT NOT NULL,
  recorded_at  INTEGER NOT NULL,
  detail       TEXT
);

CREATE INDEX journal_by_plan ON journal(plan_id);
```

**Ownership rules**

- A resource is managed iff `resources.owner_profile` is set for it.
- Plan targets an unmanaged existing resource → **conflict** (exit 5). The
  resolution path is explicit: `configctl apply --adopt <target>` (backup +
  take ownership + proceed) or `plan --ignore <target>` to exclude it, in a
  **new** plan.
- Removing a managed resource from the profile does not delete it silently; it
  produces a `FileDelete`/`PackageRemove` operation only when the profile
  explicitly asks for removal, and it remains restorable from history.

**Secrets in state**: the state store never contains secret values. Fingerprints
for files that contain secret candidates are computed over a **redacted
structural form** (sorted key names + non-secret values), not over raw bytes,
so that low-entropy secrets cannot be brute-forced from a stored hash
(see `THREAT_MODEL.md` T12).

---

## 10. Secrets architecture

```
Profile / env schema          SecretRef ("secret://ns/path")
        │                              │
        ▼                              ▼
   Planner/Verifier  ──────────►  SecretProvider (trait, core)
                                       ├── LinuxSecretService  (v0.1, keyring crate)
                                       └── future: pass, 1Password, Bitwarden, age vault
```

- `SecretValue` is a private newtype: no `Display`, no `Serialize`, no `Debug`
  that prints content. Explicit `expose()` is the only read path and is used
  only by the secret backend call and (with explicit flags) `secrets get`.
- `secrets list` shows references + metadata (exists / not found / backend),
  never values.
- `secrets set` reads the value from a hidden prompt or `--stdin`; it never
  accepts the value as a CLI argument (argv is world-readable in `/proc`).
- `secrets import` is interactive: candidates are shown **redacted** with
  per-item approval (Review / Import / Ignore / Abort). Originals are never
  deleted or rewritten in v0.1.
- Secret Service is the v0.1 backend (via the `keyring` crate → Secret Service
  on Linux). If no unlocked Secret Service is reachable, secret-dependent
  commands fail with exit 6 and a remediation hint; non-secret functionality
  is unaffected. No custom encryption exists anywhere in the project.

---

## 11. Discovery architecture

- **Roots** come from (1) positional CLI paths, (2) `--root` flags, (3)
  `scan.roots` in `config.toml`. If none are given, `scan` errors with guidance
  rather than defaulting to the whole filesystem.
- **Traversal** uses the `ignore` crate (gitignore semantics, parallel walker,
  `follow_links(false)`). A hard deny-list applies before any user rules:
  `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `$XDG_CACHE_HOME`, `/var/lib`,
  `/var/cache`, `/lost+found`, and any path outside the configured roots.
  Default performance excludes: `.git/objects`, `.git/modules`, `node_modules`,
  `target`, `.venv`, `venv`, `dist`, `build`, `.cache`.
- **Bounded reads**: per-file read cap (default 256 KiB, configurable), max
  files visited, max findings; detectors stream and never load whole trees into
  memory. Checksums are computed lazily (verify/apply only), not during scan.
- **Deduplication**: canonicalized paths are deduplicated, so overlapping roots
  are scanned once.
- **Discoverers** are independent, read-only modules (`EnvFileDiscoverer`,
  `DotfileDiscoverer`, `PackageDiscoverer`, `GitDiscoverer`,
  `SystemdDiscoverer`, `ShellDiscoverer`, `ProjectDiscoverer`,
  `SecretPatternDetector`). Each emits `Finding`s tagged with source,
  confidence, risk, and ownership.
- **Project detection** records evidence: any of `.git/`, `Cargo.toml`,
  `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Makefile`,
  `CMakeLists.txt`. One marker yields `Likely`; `.git/` plus a manifest yields
  `Certain`. Nested/monorepo cases produce multiple candidates; the tool does
  not force a single answer.
- **Secret detection** is multi-signal, in-memory only:
  1. variable-name lexicon (`API_KEY`, `TOKEN`, `PASSWORD`, `PRIVATE_KEY`, …),
  2. value shape / known token formats (AWS, GitHub, Slack, Stripe, Google,
     PEM headers, JWTs, credentials-in-URL),
  3. Shannon entropy with length floor,
  4. context (file name layer, neighboring variables, file type).
  Output classification: `secret` | `likely_secret` | `config` | `unknown`,
  with the contributing signals as evidence. Matched values are held only in a
  process-local registry for the duration of the command and are never written
  to files, JSON, logs, or the state store.

---

## 12. Verification

`configctl verify` compares the profile's desired state with reality and emits
per-resource results:

| Status | Meaning |
|---|---|
| `MATCH` | Present and identical to desired state (fingerprint equal). |
| `DRIFT` | Present but different, and managed or claimed by the profile. |
| `MISSING` | Desired but absent. |
| `UNMANAGED` | Present on disk but not referenced by the profile or state store. |
| `UNKNOWN` | Cannot be determined (provider unavailable, permission denied, unreadable). |

Summary counts per category (`Packages 47/47 PASS`, `Dotfiles 128/128 PASS`, …).
Verification never mutates anything. Exit code 3 when any `DRIFT` or `MISSING`
is found; `UNMANAGED`/`UNKNOWN` are reported but are not failures unless
`--strict` is passed.

---

## 13. Output, redaction, and rendering

Every user-visible byte flows through one renderer with one redaction layer:

```
command handler ──► Renderer ──┬──► HumanRenderer (stdout/stderr)
                              └──► JsonRenderer  (stdout, --json)
                 ──► AuditLog  (state dir, redacted)
                 ──► PlanDoc   (state dir, redacted)
```

Redaction is layered and fail-closed:

1. **Type-level**: `SecretValue` cannot be formatted; `FindingMeta`,
   `OperationDetails`, and `Warning` have no free-form value fields.
2. **Registry-level**: values detected during the current command are held in a
   process-local `SecretRegistry`; the redactor replaces exact occurrences with
   `<redacted>` before any write to any sink.
3. **Pattern-level**: known token shapes are masked even if not registry-known,
   preserving only a short prefix (`sk-****`, `ghp_****`). Redaction is
   irreversible and never logged about.
4. **Error-level**: error messages are built from static templates plus
   non-secret arguments (paths, names, exit codes). Values are never
   interpolated into errors.

JSON output uses a stable envelope:

```json
{
  "schema_version": 1,
  "command": "plan",
  "status": "ok",
  "data": { },
  "warnings": [{ "code": "secret_duplicated", "message": "..." }],
  "errors": []
}
```

---

## 14. Error model and exit codes

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | Usage or configuration error (bad flags, malformed config/profile) |
| 3 | Verification failed (`DRIFT` / `MISSING`, or `--strict` with findings) |
| 4 | Aborted: user declined approval |
| 5 | Conflict or unsafe state (ownership conflict, stale plan, tampering) |
| 6 | Secret backend unavailable |
| 7 | Provider unavailable (e.g. systemd not present) |
| 8 | Required privilege missing (e.g. apt without sudo rights) |

Error text answers three questions: **what failed**, **why**, **what the user
can do next**. Errors never include secret values, environment values, or file
contents.

---

## 15. configctl's own configuration

`$XDG_CONFIG_HOME/configctl/config.toml` (default `~/.config/configctl/`),
separate from any managed profile:

```toml
schema_version = 1
default_profile = "work"

[scan]
roots = ["~/projects", "~/work"]
ignore_files = [".configctlignore"]     # gitignore syntax
max_file_bytes = 262144
max_findings = 10000

[secrets]
provider = "secret-service"

[secret_detection]
entropy_threshold = 4.2
min_length = 12
name_lexicon_extra = []

[state]
directory = "~/.local/state/configctl"

[environment]
target_file = "~/.config/environment.d/90-configctl.conf"
```

Profiles live in `$XDG_CONFIG_HOME/configctl/profiles/<name>/` by default and
are safe to commit: they must never contain secret values (enforced by
validation). `--config`, `--state-dir`, and `--profile` override these paths.

---

## 16. Extensibility

Adding a future provider means implementing the traits in
`PROVIDER_INTERFACES.md`, registering it in the CLI composition root, and
declaring capabilities/availability via `probe()`. The core does not change.

Future reproduction targets are deliberately shaped as a **target adapter**
boundary:

```
profile ──► resolver ──► target adapter ──┬── local        (v1.0)
                                          ├── container    (deferred)
                                          ├── VM           (deferred)
                                          └── remote       (deferred)
```

v1.0 implements only the local adapter; no abstraction is added that the local
adapter does not already need.

---

## 17. Key decisions

| # | Decision | Rationale | Status |
|---|---|---|---|
| D1 | Rust, single workspace, stable toolchain | Linux-native, single binary, strong FS/process APIs, testable boundaries | Proposed |
| D2 | Profile + config format is **TOML** | Maintained Rust tooling (`toml`), deterministic, no YAML deserialization footguns; final call pending review | Proposed |
| D3 | 9 crates: cli, core, discovery, secret, audit, 4 providers | Provider boundary without premature micro-crates; profile/planner/state live in core | Proposed |
| D4 | State store is SQLite (`rusqlite`, bundled) behind `StateStore` | ACID, crash-safe journal for interrupted apply, queryable history | Proposed |
| D5 | Secret backend v0.1 = Linux Secret Service via `keyring` crate | Native storage, no custom crypto | Proposed |
| D6 | Secrets addressed as `secret://<namespace>/<path>` | Profile-safe references, provider-agnostic | Proposed |
| D7 | Synchronous core; parallelism only inside discovery | Simplicity; avoids async runtime in a CLI | Proposed |
| D8 | Apply executes the exact approved plan; no auto re-plan | Safety, auditability | Proposed |
| D9 | Providers shell out to `apt-get` / `systemctl --user` via an injected `CommandRunner` | Testable, no heavy D-Bus dependency; parsing is isolated and version-checked | Proposed |
| D10 | Env-file parsing is an in-core, bounded, pure parser | Shared by discovery and validation; full control over safety limits | Proposed |
| D11 | v0.1 does not write secret values to disk at all | Avoids the highest-risk behavior until runtime injection is designed | Proposed |
| D12 | Managed files only under `$HOME` (user services only) | Keeps privilege surface out of v0.1 | Proposed |
| D13 | Apt operations may use `sudo -n` after plan approval; nothing else elevates | Realistic package management with explicit, visible privilege boundary | Proposed |
| D14 | License, MSRV, CI matrix to be finalized before P1 | Open-source release requirements | Open |

---

## 18. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Secret leakage through an unforeseen output path | High | Layered redaction, type discipline, canary-based leak tests in CI |
| Heuristic detection false negatives | Medium | Multi-signal detection, visible confidence, `audit` overlaps, user review in `secrets import` |
| Secret Service absent (headless/server) | Medium | Graceful degradation, exit 6 with hint; fallback backend deferred |
| apt/systemctl output parsing drifts across versions | Medium | Isolated parsers, version probe, fake-runner tests, `UNKNOWN` instead of guessing |
| Interrupted apply leaves partial state | High | Journal + backups + explicit recovery; packages are inherently non-transactional and reported as such |
| Scope is large (P0–P8) | High | Milestone gates with acceptance criteria; v0.1 surface frozen in this doc |
| Ubuntu/Debian assumptions leak into core | Medium | Provider traits + `PlatformInfo`; core has no distro/init dependencies |
| Plaintext backups in state dir | Medium | `0700`/`0600`, local-only, documented; encrypted backups deferred |
| Profile bundles accidentally committed with secrets | High | Validation rejects literal secret-like values; audit git; capture never writes values |
| Users trusting heuristics as guarantees | Medium | Confidence language in all output; docs state limits |

---

## 19. Milestone map (condensed)

| Milestone | Deliverable | Acceptance gate |
|---|---|---|
| P0 | This document set | Docs reviewed; open decisions resolved |
| P1 | Discovery + scan | Realistic tree scanned read-only; redaction tests pass |
| P2 | Profile + capture | Machine represented as a profile with zero secret values |
| P3 | Planner + diff + dry-run | Plan shows exactly what apply would do; JSON stable |
| P4 | Apply (files, env, apt, user services) | Controlled environment reproduced from profile |
| P5 | Verify + drift report | MATCH/DRIFT/MISSING/UNMANAGED/UNKNOWN accurate |
| P6 | Secrets + env schemas + import + audit | Secrets managed without entering profiles/logs |
| P7 | Rollback + recovery | Failed changes recoverable; interrupted apply detectable |
| P8 | Hardening | Security tests, fuzzing, docs, release readiness |

---

## 20. Open questions

1. Profile format TOML vs YAML (D2) — TOML recommended.
2. Project/binary name `configctl` (tentative).
3. License (MIT/Apache-2.0 dual recommended).
4. Whether apt should be usable at all behind `sudo -n` in v1.0, or limited to
   `plan`-only with instructions for manual installation.
5. Fallback secret policy for machines without Secret Service.
6. Whether `packages.lock` pins or merely records versions.
7. Backup encryption for the state directory.
8. Exact MSRV and CI matrix.

These are tracked in the P0 report; no code may assume an answer before it is
decided.
