# WORKSPACE_STRUCTURE.md — Repository layout

Status: **P0 design draft. No code or scaffolding exists yet.**

Language: Rust (edition 2021). Toolchain: stable; MSRV pinned in
`rust-toolchain.toml` and CI (exact value decided at P1).

> P0 intentionally creates **documentation only**. The tree below is the
> proposed structure that P1 will scaffold; it is not present as code yet.

---

## 1. Proposed tree

```
configctl/
├── Cargo.toml                      # virtual workspace manifest
├── Cargo.lock                      # committed (binary project)
├── rust-toolchain.toml             # pinned stable toolchain
├── README.md
├── LICENSE-MIT / LICENSE-APACHE    # pending license decision
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROFILE_SCHEMA.md
│   ├── THREAT_MODEL.md
│   ├── CLI_SPEC.md
│   ├── PROVIDER_INTERFACES.md
│   ├── WORKSPACE_STRUCTURE.md
│   ├── TESTING_STRATEGY.md
│   └── DEFERRED_FEATURES.md
├── crates/
│   ├── configctl-cli/              # binary: `configctl`
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── commands/           # one module per command
│   │   │   ├── registry.rs         # composition root (concrete providers)
│   │   │   └── render/             # human + JSON renderers
│   │   └── tests/                  # end-to-end CLI tests (assert_cmd)
│   ├── configctl-core/             # domain; NO platform/provider deps
│   │   └── src/
│   │       ├── domain/             # Finding, Profile, Operation, Plan, secret types
│   │       ├── traits/             # Provider, Discoverer, SecretProvider, stores
│   │       ├── profile/            # load, validate, canonicalize, migrate
│   │       ├── planner/            # diff, conflicts, deterministic ordering
│   │       ├── state/              # SQLite StateStore + BackupStore (CAS)
│   │       ├── verify/             # check aggregation, statuses
│   │       ├── envfile/            # bounded .env + schema parsers
│   │       └── redact/             # SecretRegistry, redaction layer
│   ├── configctl-discovery/        # walkers, discoverers, detection
│   ├── configctl-secret/           # SecretProvider impl: Linux Secret Service
│   ├── configctl-provider-files/   # managed files
│   ├── configctl-provider-apt/     # apt-get via CommandRunner
│   ├── configctl-provider-systemd/ # systemctl --user via CommandRunner
│   ├── configctl-provider-env/     # environment.d management
│   └── configctl-audit/            # git + permission + leak audit checks
├── fixtures/                       # static test fixtures (fake projects)
│   ├── projects/                   # .env files, configs, fake markers
│   ├── profiles/                   # valid + malicious profile bundles
│   └── canaries/                   # known secret values for leak tests
└── xtask/                          # dev automation (optional, P1+)
```

---

## 2. Crate responsibilities and dependency rules

| Crate | Type | Responsibility | May depend on |
|---|---|---|---|
| `configctl-cli` | bin | arg parsing, command handlers, rendering, exit codes, provider composition | all crates |
| `configctl-core` | lib | domain types, traits, profile, planner, state, verifier, env parsers, redaction | std + a small vetted set (`serde`, `toml`, `rusqlite`, `sha2`, `thiserror`) |
| `configctl-discovery` | lib | bounded traversal, discoverers, secret detection, project detection | core |
| `configctl-secret` | lib | Linux Secret Service backend via `keyring` | core |
| `configctl-provider-files` | lib | atomic managed-file operations | core |
| `configctl-provider-apt` | lib | apt-get via `CommandRunner` | core |
| `configctl-provider-systemd` | lib | systemctl --user via `CommandRunner` | core |
| `configctl-provider-env` | lib | environment.d file management | core |
| `configctl-audit` | lib | git/permission/secret-leak audit checks | core (+ discovery) |
| `xtask` | bin | dev tasks (fixture gen, release checks) | dev-only |

**Hard rules (enforced in CI):**

1. `configctl-core` must not depend on any provider crate, `clap`, `keyring`,
   or platform-specific crates. A CI dependency check fails the build on
   violation.
2. Providers depend on core, never on each other.
3. Only `configctl-cli` constructs concrete providers (composition root).
4. No crate performs network I/O; CI greps for networking crates in
   `Cargo.lock` denials.
5. Subprocess execution exists only behind `CommandRunner`; CI greps for
   direct `std::process::Command` outside the runner implementation and tests.

---

## 3. Naming and module conventions

- Crates: `configctl-<role>`; internal modules short and single-purpose.
- Public items documented; `#![deny(missing_docs)]` in library crates.
- Errors: `thiserror` enums per crate; core error types are value-free by
  construction (no `String` fields that could hold content).
- Serde: domain types do not derive `Serialize` directly for output; dedicated
  redaction-safe view types do (prevents accidental value serialization).
- Paths: `PathBuf` everywhere internally; `~` only exists in profile text and
  is expanded at load time by one function.
- Time: `SystemTime` in domain, rendered as RFC 3339.
- IDs: ULIDs (`ulid` crate) for plans; stable derived strings for operations.

---

## 4. Feature flags

| Feature | Crate | Purpose |
|---|---|---|
| `test-fakes` | core, discovery, providers | in-memory fakes and scripted runners for tests |
| `slow-tests` | cli (dev) | opt-in large-fixture/performance tests |
| `fuzzing` | core | `arbitrary` derives for fuzz targets |

No feature may change security behavior at runtime; flags gate test/build
extras only.

---

## 5. CI outline

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p configctl-cli --test e2e
cargo deny check advisories licenses bans sources
cargo audit
# dependency-direction check (core has no provider deps; no direct Command outside runner)
```

Matrix: Linux (ubuntu-latest) only for v0.1. MSRV job runs the workspace with
the pinned minimum toolchain.

---

## 6. Versioning

- Workspace crates share one version; the binary reports it via
  `configctl --version` (`configctl 0.1.0`).
- `schema_version` values (profile/config/JSON output) are independent of the
  crate version and only bump on breaking format changes, with documented
  migration.
- `Cargo.lock` is committed; dependency additions require a short rationale in
  the PR (attack surface review, per THREAT_MODEL.md T19).

---

## 7. Local development workflow (target state)

```
cargo xtask fixtures          # regenerate fixture trees
cargo test --workspace        # unit + integration
cargo test -p configctl-cli --test e2e
cargo run -p configctl-cli -- scan fixtures/projects --json
```

Manual testing always uses `--state-dir` and `HOME` overrides pointing at a
temporary directory. Running the binary against the developer's real `$HOME`
during development is prohibited by the testing strategy.
