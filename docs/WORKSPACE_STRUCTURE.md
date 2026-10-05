# WORKSPACE_STRUCTURE.md — Repository layout

Status: **Implemented (v1.0.0-rc.1); 1.1.0–1.4.0 released.** The workspace has three crates (core, discovery, cli); provider logic lives in core modules.

Language: Rust (edition 2021). Toolchain: stable; MSRV pinned in
`rust-toolchain.toml` and CI (exact value decided at P1).

> P0 intentionally creates **documentation only**. The tree below is the
> proposed structure that P1 will scaffold; it is not present as code yet.

---

## 1. Actual tree (v1.0.0-rc.1)

The workspace was built with **three crates**, not nine: provider logic lives
in focused `configctl-core` modules (files/apt/systemd/env/secrets/audit as
`apply`/`observe`/`rollback`/`secrets`/`verify` code paths behind narrow
traits), keeping the provider→core direction without premature micro-crates.

```
configctl/
├── Cargo.toml                      # virtual workspace (version 1.4.0)
├── Cargo.lock                      # committed
├── rust-toolchain.toml             # pinned stable toolchain (1.97)
├── README.md
├── LICENSE-MIT / LICENSE-APACHE
├── docs/                           # …plus PLANNING/APPLY/VERIFY/SECRETS/
│                                   # ROLLBACK/STATE/SECURITY/LIMITATIONS
├── crates/
│   ├── configctl-cli/              # binary `configctl` + command handlers
│   │   ├── src/main.rs             # clap surface, exit codes
│   │   ├── src/commands/           # scan/capture/plan/apply/verify/env/
│   │   │                           # secrets/audit/rollback/doctor/init/profile
│   │   ├── src/tui/                # T1 read-only dashboard (app/ui/run)
│   │   ├── src/render.rs           # P0 JSON envelope
│   │   ├── src/guidance.rs         # guide topics, --explain notes, hints
│   │   ├── src/guide/              # plain-language topic texts (*.md)
│   │   └── tests/                  # *_e2e CLI suites (disposable fixtures)
│   ├── configctl-core/             # domain; NO provider-crate deps
│   │   └── src/
│   │       ├── profile(_load).rs   # typed model, load/validate/canonicalize
│   │       ├── plan.rs / observe.rs# diff engine + read-only observation
│   │       ├── state.rs            # SQLite store + plans/journal/history
│   │       ├── apply.rs            # journaled execution (INTENT…DONE)
│   │       ├── rollback.rs         # restore + recovery classification
│   │       ├── verify.rs           # drift detection
│   │       ├── secrets.rs          # refs, SecretValue, backends
│   │       ├── env_verify.rs       # schema verification
│   │       ├── backup.rs / lock.rs # CAS backups, flock
│   │       ├── command.rs          # CommandRunner (only subprocess path)
│   │       ├── governor.rs         # v1.1: central resource budgets
│   │       ├── inventory.rs        # v1.1: resource inventory model
│   │       ├── classify.rs         # v1.1: classes + PlanActionClass
│   │       ├── capture_policy.rs   # v1.1: capture action decisions
│   │       ├── hash.rs             # canonical SHA-256
│   │       ├── envmap.rs           # v1.2: shell env source map + composers
│   │       ├── envmove.rs          # v1.2 E5: move-mode eligibility + patch rendering
│   │       └── redact.rs / envfile.rs / paths.rs / files.rs / ...
│   └── configctl-discovery/        # bounded walkers, detectors, scanner
└── target/                         # build artifacts (gitignored)
```

## 2. Crate responsibilities and dependency rules

| Crate | Type | Responsibility | May depend on |
|---|---|---|---|
| `configctl-cli` | bin+lib | arg parsing, command handlers, rendering, exit codes | core, discovery, clap, serde, rpassword |
| `configctl-core` | lib | domain types, plan/apply/verify/rollback, state, secrets, parsers, redaction | std + `serde`, `toml`, `rusqlite` (bundled), `sha2`, `hex`, `fs2`, `thiserror` |
| `configctl-discovery` | lib | bounded traversal, discoverers, secret detection, project detection | core |

**Hard rules:**

1. `configctl-core` must not depend on any provider implementation crate
   (there are none), `clap`, or D-Bus crates.
2. Only `configctl-cli` wires concrete backends (composition root).
3. No crate performs network I/O.
4. Subprocess execution goes through `CommandRunner` (fixed argv, caps,
   timeouts); the single exception is the `secret-tool store` stdin path,
   which keeps the same guarantees (fixed argv, no shell) and is documented
   in `secrets.rs`.
5. Secret values never cross into rendering/serialization/state types.

---

## 3. Naming and module conventions

- Crates: `configctl-<role>`; internal modules short and single-purpose.
- Errors: value-free by construction (no value-carrying fields; messages are
  static templates plus names/paths).
- Serde: value-holding types (`SecretValue`, `ParsedVariable`) never serialize
  values; plan/state/verify types carry hashes/refs only.
- Paths: `PathBuf` internally; `~` only in profile text, expanded by one
  function per use site.
- Time: unix seconds in state; RFC 3339 informational stamps in profiles.
- IDs: timestamp+random plan ids; stable `op-NNNN` operation ids in plan order.

## 4. Feature flags

None in v1. Test-only behavior is gated by environment (`CONFIGCTL_*`),
never by features; no flag changes security behavior.

## 5. Quality gates (local; no CI configured in v1)

```
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo audit                      # clean at v1.0.0-rc.1
cargo build --release
```

Matrix: Linux x86_64. MSRV 1.97 (pinned toolchain in `rust-toolchain.toml`).

## 6. Versioning

- Workspace crates share one version; the binary reports it via
  `configctl --version` (`configctl 1.4.0`).
- `schema_version` values (profile/config/JSON output) are independent of the
  crate version and only bump on breaking format changes, with documented
  migration.
- `Cargo.lock` is committed; dependency additions require a short rationale
  (attack surface review, per THREAT_MODEL.md T19).

## 7. Local development workflow

```
cargo test --workspace
cargo run -p configctl-cli -- scan ./fixture --json
```

Manual testing always uses `--state-dir` and temp homes. Running the binary
against the developer's real `$HOME` for destructive commands during
development is prohibited by the testing strategy.
