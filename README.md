# configctl — Linux Environment Manager

> Discover, organize, reproduce, and verify everything a Linux development
> environment depends on: packages, dotfiles, `.env` schemas, services, Git
> config, and secrets (by reference only).

**Status: v1.1.0 released (hardcore mapping); `main` tracks `1.2.0-dev`.**
The full lifecycle is implemented:

```console
$ configctl scan ~/projects          # read-only discovery
$ configctl capture --output ./work  # declarative profile bundle (no secrets)
$ configctl profile validate ./work  # all errors listed, no mutation
$ configctl plan ./work              # deterministic diff, persisted + hashed
$ configctl apply --last --yes       # newest plan: journaled, locked, backed up
$ configctl verify ./work            # MATCH / DRIFT / MISSING / ...
$ configctl status [profile]         # one-page state + drift summary
$ configctl why ~/.gitconfig         # ownership, last operation, backup
$ configctl rollback --plan <plan-id> --yes   # restore from backups
$ configctl doctor                   # state + interrupted-apply diagnostics
$ configctl guide [topic]            # plain-language help while you work
$ configctl env explain              # where env settings live + which wins (v1.2)
$ configctl env consolidate --dry-run # preview one managed env file (v1.2)
$ configctl env consolidate          # plan it; `apply` writes, `rollback` undoes
```

Local-first, offline-capable, no accounts, no telemetry, no cloud dependency.
Secrets are referenced (`secret://…`) and stored in the Linux Secret Service
— never written into profiles, logs, diffs, plans, or state.

### v1.1 direction — hardcore mapping

v1.1 inverts the default from "not allowlisted → exclude" to "discover
broadly → classify with evidence → capture what is reproducible → reference
secrets → record the rest". Safety comes from a single `ResourceGovernor`
(wall time, CPU pressure, memory, I/O, files, directory entries,
subprocesses, output, recursion, symlink depth, concurrency) rather than
conservative discovery; execution stays gated by per-operation
`PlanActionClass` — `PRIVILEGED`, `DESTRUCTIVE`, and `UNSUPPORTED` operations
are refused by `apply` even after approval. Capture emits profile schema v2;
v1 bundles keep loading. See [docs/V1_1_HARDCORE.md](docs/V1_1_HARDCORE.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, lifecycle, state, decisions, risks |
| [docs/PROFILE_SCHEMA.md](docs/PROFILE_SCHEMA.md) | Profile bundle format v1 (TOML), validation rules, examples |
| [docs/CLI_SPEC.md](docs/CLI_SPEC.md) | Command reference, flags, JSON output, exit codes |
| [docs/PROVIDER_INTERFACES.md](docs/PROVIDER_INTERFACES.md) | Core traits and provider obligations |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, threat dispositions with evidence |
| [docs/WORKSPACE_STRUCTURE.md](docs/WORKSPACE_STRUCTURE.md) | Crate layout and dependency rules |
| [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) | Test pyramid, fixtures, safety tests, gates |
| [docs/DEFERRED_FEATURES.md](docs/DEFERRED_FEATURES.md) | Explicit out-of-scope list for v1 |
| [docs/DISCOVERY.md](docs/DISCOVERY.md) | Discovery engine: what scan finds, limits, redaction |
| [docs/CAPTURE.md](docs/CAPTURE.md) | Capture: what gets captured, policies, secret handling |
| [docs/PROFILE.md](docs/PROFILE.md) | Profile bundle format v1 (TOML), validation rules, examples |
| [docs/PLANNING.md](docs/PLANNING.md) | Plan/diff engine: determinism, ownership, approval |
| [docs/APPLY.md](docs/APPLY.md) | Apply: journal, lock, ordering, atomic writes, failure |
| [docs/VERIFY.md](docs/VERIFY.md) | Verification and drift detection |
| [docs/SECRETS.md](docs/SECRETS.md) | Secret backend, input/output discipline, import |
| [docs/ROLLBACK.md](docs/ROLLBACK.md) | Rollback scope, backups, crash recovery |
| [docs/STATE.md](docs/STATE.md) | State directory layout and SQLite schema |
| [docs/SECURITY.md](docs/SECURITY.md) | Security guarantees and honest limitations |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Known limitations and deferred features |
| [docs/ENV_CONSOLIDATION.md](docs/ENV_CONSOLIDATION.md) | Env consolidation design (proposed v1.2): sources, canonical file, include lines, beginner guide |
| [docs/V1_1_HARDCORE.md](docs/V1_1_HARDCORE.md) | v1.1 direction: hardcore discovery, governance, execution classes |
| [docs/RESOURCE_GOVERNOR.md](docs/RESOURCE_GOVERNOR.md) | v1.1 execution budgets: defaults, ceilings, CLI overrides |
| [docs/RESOURCE_CLASSIFICATION.md](docs/RESOURCE_CLASSIFICATION.md) | v1.1 classification: classes, evidence, capture actions |
| [docs/DISCOVERY_MODEL.md](docs/DISCOVERY_MODEL.md) | v1.1 discovery pipeline: mounts, walk, probes, completeness |

## Build and test

```console
$ cargo fmt --check
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo test --workspace
$ cargo build --release
```

## License

MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
