# configctl — Linux Environment Manager

> Discover, organize, reproduce and verify your Linux development environment:
> dotfiles, packages, project `.env` files, configuration, and secrets.

**Status: P1 — read-only discovery engine implemented.**
`configctl scan` performs a bounded, read-only discovery of projects, `.env`
files, config files, git tracking, and system metadata. No mutation.
Capture/plan/apply/rollback are not yet implemented (P2+).

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, lifecycle, planning/applying, state, decisions, risks |
| [docs/PROFILE_SCHEMA.md](docs/PROFILE_SCHEMA.md) | Profile bundle format v1 (TOML), validation rules, examples |
| [docs/CLI_SPEC.md](docs/CLI_SPEC.md) | Command reference, flags, JSON output, exit codes |
| [docs/PROVIDER_INTERFACES.md](docs/PROVIDER_INTERFACES.md) | Core traits: Provider, Discoverer, SecretProvider, stores |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, threat register, mitigations, limitations |
| [docs/WORKSPACE_STRUCTURE.md](docs/WORKSPACE_STRUCTURE.md) | Crate layout and dependency rules |
| [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) | Test pyramid, fixtures, safety tests, CI gates |
| [docs/DEFERRED_FEATURES.md](docs/DEFERRED_FEATURES.md) | Explicit out-of-scope list for v0.1 |
| [docs/DISCOVERY.md](docs/DISCOVERY.md) | P1 discovery engine: what scan finds, limits, redaction |

## Build and test

```console
$ cargo build -p configctl-cli
$ cargo test --workspace
```

## Intended usage

```console
$ configctl scan ~/projects          # read-only discovery
$ configctl scan ~/projects --json   # machine-readable envelope
$ configctl scan ~/projects -v       # verbose details
$ configctl capture work             # not yet implemented (P2)
$ configctl plan work                # not yet implemented (P3)
$ configctl apply work               # not yet implemented (P4)
```

Local-first, offline-capable, no accounts, no telemetry, no cloud dependency.
Secrets are referenced (`secret://…`) and stored in the native Linux secret
store — never written into profiles, logs, or diffs. `configctl scan` never
prints secret values; detected secret-like values are redacted at every sink.
