# PLANNING.md — deterministic plan/diff engine (P3)

`configctl plan <profile>` is completely non-mutating. The only write is the
persisted plan document inside the state directory.

## Pipeline

```text
PROFILE + OBSERVED MACHINE STATE → NORMALIZE → DIFF → PLAN → PERSIST → HASH
```

## Plan model

```text
Plan
├── schema_version (= 1)
├── plan_id
├── profile_identity
├── profile_hash
├── observed_state_fingerprint
├── created_at (informational; excluded from the hash)
├── operations[] (deterministic order, stable ids op-0001…)
├── warnings[]
├── conflicts[]
└── plan_hash
```

Operation kinds: `PackageInstall`, `PackageVersionMismatch` (report-only),
`FileCreate`, `FileUpdate`, `FileConflict`, `EnvironmentSchemaChange`,
`ServiceEnable`, `ServiceDisable`, `GitConfigChange`, `NoOp`, `Unsupported`.
Unsupported providers are represented honestly — never silently skipped.

## Diff rules

A resource is not safe to update merely because desired ≠ current. Ownership
comes from the state store:

- target absent → `CREATE`
- target present + content equal → `MATCH` (no op; idempotency)
- target present + managed by this profile → `UPDATE`
- target present + **not** managed → `CONFLICT` (never overwrite; `--adopt`
  takes ownership explicitly, backed up and recorded)
- symlink / non-regular at target → `CONFLICT`
- provider unavailable → `UNSUPPORTED`
- unobservable → `UNKNOWN`

## Determinism

Identical profile + observed state ⇒ semantically identical operations and
plan hash. Timestamps and plan ids are excluded from the hash. Operations are
sorted by (provider rank, target): packages → files → env → services → git.
Canonical JSON is hashed with SHA-256.

## Persistence and approval

Plans live in `~/.local/state/configctl/` (SQLite row + `plans/<id>.json`,
both `0600`). Plans are immutable: reloading recomputes the hash and refuses
tampered documents. `apply` takes a plan ID — never a profile path — and
approval binds to the exact plan hash. Re-planning after any profile or state
change produces a new plan; the old approval never transfers.
