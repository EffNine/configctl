# PROVIDER_INTERFACES.md — Core traits and provider design

Status: **Implemented (v1.0.0-rc.1).** Provider logic lives in `configctl-core` modules behind narrow traits; the CLI crate is the composition root. Sketches below are
illustrative Rust; exact signatures are finalized at P1/P3.

---

## 1. Overview

Two kinds of extension points:

| Kind | Direction | Purpose | Examples |
|---|---|---|---|
| **Discoverer** | read-only | Find things on the machine and report `Finding`s | `EnvFileDiscoverer`, `PackageDiscoverer` |
| **Provider** | read/write | Plan, apply, and verify a slice of desired state | `AptProvider`, `FilesProvider`, `SystemdProvider`, `EnvProvider` |

A provider *may* internally use discoverers (e.g. the apt provider checks
installed packages), but the scan pipeline and the plan pipeline stay
separate: scan never mutates, and apply never explores beyond what the plan
declares.

`SecretProvider` is a separate, narrower trait because secret access has its
own discipline and failure modes.

The core crate defines all traits and domain types and depends on **none** of
the implementations. The CLI crate wires concrete providers into a registry
(composition root).

---

## 2. Platform and availability

```rust
pub struct PlatformInfo {
    pub os: OsId,                 // Linux (v0.1: Linux-only)
    pub arch: Arch,               // X86_64 (v0.1)
    pub distro: Option<DistroId>, // Debian / Ubuntu (+ version)
    pub init: InitSystem,         // Systemd | Other
    pub home: PathBuf,
    pub xdg_config: PathBuf,
    pub xdg_state: PathBuf,
    pub is_root: bool,
}

pub enum Availability {
    Available,
    Unavailable { reason: String, hint: String }, // e.g. systemd not running
    Degraded { reason: String },                  // works with limits
}

pub trait Probe {
    fn probe(&self, platform: &PlatformInfo) -> Availability;
}
```

Rules:

- A provider must never assume its platform; `probe()` is always called before
  planning, and the planner records `Unavailable` providers as conflicts
  (exit 5/7) rather than skipping them silently.
- `Degraded` is surfaced in plans and verification as `UNKNOWN` results.
- v0.1 hard-codes Linux family checks in the CLI composition root; the core
  itself is platform-agnostic.

---

## 3. `Provider` trait

```rust
pub trait Provider: Probe + Send + Sync {
    fn id(&self) -> ProviderId;                       // "apt", "files", "systemd", "env"
    fn capabilities(&self) -> Capabilities;           // what kinds of ops it can emit

    /// Read current state relevant to the desired state. Read-only.
    fn observe(&self, ctx: &ObserveContext, desired: &DesiredState)
        -> Result<Observation, ProviderError>;

    /// Emit candidate operations for this provider's slice of the profile.
    /// MUST be side-effect free.
    fn plan(&self, ctx: &PlanContext, desired: &DesiredState)
        -> Result<Vec<Operation>, ProviderError>;

    /// Execute the already-approved operations for this provider, in order.
    /// Called only by the apply engine; providers do not journal themselves,
    /// the engine wraps each call (INTENT → execute → DONE/FAILED).
    fn apply(&self, ctx: &ApplyContext, ops: &[Operation])
        -> Result<ApplyReport, ProviderError>;

    /// Compare desired vs actual. MUST be side-effect free.
    fn verify(&self, ctx: &VerifyContext, desired: &DesiredState)
        -> Result<Vec<CheckResult>, ProviderError>;
}

pub struct Capabilities {
    pub operation_kinds: Vec<OperationKind>,
    pub requires_elevation: bool,     // apt: true (sudo -n), others: false
    pub touches_network: bool,        // apt: true (fetch), others: false
    pub supports_rollback: bool,      // files/env: true; apt: false (report-only)
}
```

### 3.1 Contexts (capability injection)

Contexts carry only what a provider needs; this is what makes fake providers
trivial in tests:

```rust
pub struct ObserveContext<'a> {
    pub platform: &'a PlatformInfo,
    pub command: &'a dyn CommandRunner,   // fixed-argv subprocess runner
    pub limits: &'a Limits,               // timeouts, output caps
}

pub struct PlanContext<'a> {
    pub platform: &'a PlatformInfo,
    pub state: &'a dyn StateStore,        // read-only ownership lookups
    pub command: &'a dyn CommandRunner,
}

pub struct ApplyContext<'a> {
    pub platform: &'a PlatformInfo,
    pub state: &'a mut dyn StateStore,    // journal + ownership writes
    pub backup: &'a mut dyn BackupStore,  // content-addressed backups
    pub command: &'a dyn CommandRunner,
    pub dry_run: bool,
}

pub struct VerifyContext<'a> {
    pub platform: &'a PlatformInfo,
    pub command: &'a dyn CommandRunner,
    pub state: &'a dyn StateStore,
}
```

### 3.2 `CommandRunner` — the only way to run subprocesses

```rust
pub trait CommandRunner: Send + Sync {
    /// Runs a program with an explicit argv (never a shell string).
    /// - environment is scrubbed: no inherited secret-looking vars (allow-list)
    /// - stdout/stderr captured with a hard byte cap
    /// - hard timeout; killed on expiry
    fn run(&self, req: &CommandRequest) -> Result<CommandOutput, CommandError>;
}

pub struct CommandRequest {
    pub program: PathBuf,          // resolved absolute path
    pub args: Vec<OsString>,       // no shell interpolation, ever
    pub cwd: Option<PathBuf>,
    pub stdin: Option<StdinData>,  // secret bytes allowed here only
    pub timeout: Duration,
    pub output_cap: usize,
}
```

Design guarantees enforced by the runner: no shell, no argv built from
user-controlled strings without grammar validation, bounded output, timeout,
and no secret values in argv.

---

## 4. `Discoverer` trait

```rust
pub trait Discoverer: Send + Sync {
    fn id(&self) -> &'static str;
    fn scope(&self) -> DiscoveryScope;   // roots/kinds it handles
    fn discover(&self, ctx: &DiscoverContext)
        -> Result<Vec<Finding>, DiscoverError>;
}

pub struct DiscoverContext<'a> {
    pub roots: &'a [PathBuf],
    pub walker: &'a dyn FileWalker,      // bounded traversal, no symlink follow
    pub platform: &'a PlatformInfo,
    pub limits: &'a Limits,
    pub registry: &'a mut SecretRegistry, // in-memory only, for redaction
}
```

Rules:

- Discoverers are strictly read-only.
- They never read file contents beyond the configured byte cap.
- They emit `Finding`s with evidence and confidence; they do not make policy
  decisions (risk classification and issue summaries are composed by the scan
  service in `configctl-discovery`).
- Subprocess use (git, apt) goes through `CommandRunner`.

---

## 5. `SecretProvider` trait

```rust
pub trait SecretProvider: Probe + Send + Sync {
    fn id(&self) -> SecretProviderId;                    // "secret-service"

    fn exists(&self, r: &SecretRef) -> Result<bool, SecretError>;
    fn get(&self, r: &SecretRef) -> Result<SecretValue, SecretError>;
    fn set(&self, r: &SecretRef, v: &SecretValue) -> Result<(), SecretError>;
    fn delete(&self, r: &SecretRef) -> Result<(), SecretError>;

    /// List known references if the backend supports enumeration.
    /// Returns refs only — never values.
    fn list(&self, namespace: Option<&str>) -> Result<Vec<SecretRef>, SecretError>;
}
```

Rules:

- The only trait that ever sees `SecretValue` values; the value never crosses
  back into rendering/serialization types.
- `get` is called by exactly two flows: `secrets get --show` and (future)
  runtime injection. No other code path may call it.
- `list` is best-effort: not all backends enumerate; `None` capability means
  `secrets list` falls back to the profile/manifest-known references.
- v1 implementation: Linux Secret Service via the `secret-tool` CLI
  (fixed argv through `CommandRunner` for lookup/clear; piped stdin for store;
  hidden prompt values passed via prompt/stdin, never argv).
- Deferred backends: `pass`, 1Password, Bitwarden, encrypted age vault
  (see `DEFERRED_FEATURES.md`). No custom cryptography is ever permitted.

---

## 6. `StateStore`, `BackupStore`, and other core traits

```rust
pub trait StateStore: Send {
    fn lookup(&self, res: &ResourceRef) -> Result<Option<ManagedRecord>>;
    fn record_owned(&mut self, rec: ManagedRecord) -> Result<()>;
    fn release(&mut self, res: &ResourceRef) -> Result<()>;

    fn save_plan(&mut self, plan: &PlanRecord) -> Result<()>;
    fn latest_plan(&self, profile: &str) -> Result<Option<PlanRecord>>;
    fn plan_by_id(&self, id: &PlanId) -> Result<Option<PlanRecord>>;

    fn journal(&mut self, entry: JournalEntry) -> Result<()>;
    fn unfinished_journal(&self) -> Result<Vec<JournalEntry>>;

    fn history(&self, filter: HistoryFilter) -> Result<Vec<HistoryEntry>>;
}

pub trait BackupStore: Send {
    /// Stores content atomically, returns a content-addressed ref.
    fn put(&mut self, content: &[u8], meta: BackupMeta) -> Result<BackupRef>;
    fn get(&self, r: &BackupRef) -> Result<Vec<u8>>;
    fn prune(&mut self, policy: &RetentionPolicy) -> Result<PruneReport>;
}

pub trait FileWalker: Send + Sync {
    /// Bounded, deterministic traversal; symlinks not followed.
    fn walk(&self, root: &Path, rules: &WalkRules, f: &mut dyn FnMut(&WalkEntry) -> WalkDecision)
        -> Result<WalkStats>;
}

pub trait Renderer {
    fn render(&mut self, out: &Renderable) -> Result<()>;
}
```

- `StateStore` and `BackupStore` are implemented by the SQLite/CAS layer in
  core; tests substitute in-memory fakes.
- `FileWalker` is implemented in `configctl-discovery` on top of the `ignore`
  crate; tests substitute a scripted walker.

---

## 7. Operation model (shared by all providers)

```rust
pub enum OperationKind {
    // files
    FileCreate, FileWrite, FileDelete,
    // packages
    PackageInstall, PackageRemove,
    // services
    ServiceEnable, ServiceDisable, ServiceStart, ServiceStop,
    // environment
    EnvSet, EnvUnset,
}

pub struct Operation {
    pub id: OperationId,
    pub provider: ProviderId,
    pub kind: OperationKind,
    pub target: ResourceRef,               // canonical, unique within a plan
    pub summary: String,                   // redaction-safe human text
    pub risk: RiskLevel,
    pub requires_approval: bool,           // forces interactive confirmation even with --yes
    pub expected_before: Option<Fingerprint>,
    pub desired_after: Fingerprint,
    pub idempotency_key: String,           // stable: provider+kind+target+desired hash
    pub details: OperationDetails,         // typed enum; no free-form value fields
}

pub enum OperationDetails {
    File { source: Option<PathBuf>, mode: Option<u32>, backup: bool, content_hash: String },
    Package { name: String, manager: AptId, action: PackageAction },
    Service { unit: String, scope: ServiceScope },  // ServiceScope::User in v0.1
    Env { name: String, target_file: PathBuf, secret_ref: Option<SecretRef> },
}
```

Provider obligations:

1. **Pure planning** — `plan()` performs no writes.
2. **Stable keys** — the same desired state yields the same `idempotency_key`.
3. **Honest fingerprints** — `desired_after` must be computable before apply.
4. **No hidden operations** — anything a provider does at apply time must have
   appeared as an `Operation` in the plan.
5. **Bounded scope** — providers only touch resources declared by the profile.
6. **Rollback disclosure** — `supports_rollback = false` must be reflected in
   plan output (e.g. package operations are marked "not automatically
   revertible").

---

## 8. Error taxonomy

```rust
pub enum ProviderError {
    Unavailable { reason: String },
    PermissionDenied { op: OperationId, hint: String },
    CommandFailed { program: String, exit: i32, stderr_excerpt: String }, // stderr redacted
    Conflict { target: ResourceRef, detail: String },
    PostconditionFailed { op: OperationId, expected: Fingerprint, actual: Fingerprint },
    Internal { detail: String },   // redaction-safe
}
```

Rules:

- No error variant carries a secret value, environment value, or file content.
- `stderr_excerpt` is capped, redaction-filtered, and never contains stdin.
- Every variant maps to a CLI exit code (ARCHITECTURE.md §14).

---

## 9. Provider catalog (v0.1)

| Provider | Crate | Ops | Elevation | Rollback | Notes |
|---|---|---|---|---|---|
| files | `configctl-provider-files` | FileCreate/Write/Delete | no | full | atomic writes, backups, symlink-safe |
| apt | `configctl-provider-apt` | PackageInstall/Remove | `sudo -n` only | report-only | fixed argv, no shell, output parsing version-checked |
| systemd | `configctl-provider-systemd` | ServiceEnable/Disable/Start/Stop | no | full (state revert) | `systemctl --user` only |
| env | `configctl-provider-env` | EnvSet/EnvUnset | no | full | writes `environment.d` file; secret refs validated, never written |

Deferred providers: `dnf`, `pacman`, `apk`, `brew`, `nix`, system-scope systemd,
and non-systemd init (`DEFERRED_FEATURES.md`).

---

## 10. Registration and composition

Static, compile-time registration in `configctl-cli`:

```rust
fn registry(platform: &PlatformInfo) -> ProviderRegistry {
    let mut r = ProviderRegistry::new();
    r.add(Box::new(FilesProvider::new()));
    r.add(Box::new(AptProvider::new()));
    r.add(Box::new(SystemdProvider::new()));
    r.add(Box::new(EnvProvider::new()));
    r
}
```

- No dynamic plugin loading in v0.1 (a plugin ABI would be a security surface).
- Adding a provider requires: implement traits, add to registry, add fixture
  tests, and declare its `Capabilities` honestly.
- The core never imports provider crates; this is enforced by CI (dependency
  check on `configctl-core`).

---

## 11. Future-provider checklist (for P8+)

1. `probe()` implemented with honest `Unavailable`/`Degraded` behavior.
2. Operation kinds either reused or added to the shared enum with pure-planning
   semantics.
3. All subprocess traffic through `CommandRunner` with fixed argv.
4. No new behavior outside declared operations.
5. Rollback capability declared; if false, plan text says so.
6. Fake implementation + fixture tests added to the test suite.
7. Threat model updated (new attack surface? new privileges?).
