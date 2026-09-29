# Changelog

All notable changes to configctl are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
semantic. Dates are ISO-8601.

## [Unreleased] — 1.2.0-dev

Environment consolidation (v1.2), phase E1.

### Added

- `configctl env explain` — read-only map of environment declarations across
  `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zshenv`,
  `~/.xprofile`, and `~/.config/environment.d/*.conf`, with a conservative,
  non-evaluating parser. Lines are classified `managed`/`special`/`manual`/
  `secret`/`structure`; secret-like values are never retained. Reports
  conflicts and effective precedence. Backed by a new `configctl_core::envmap`
  module (17 unit tests) and an e2e canary test.
- `configctl env consolidate --dry-run` / `--var NAME` — previews the canonical
  `~/.config/configctl/env.sh` content and the marker include block that would
  be appended to each participating rc file, plus a shadowing report. Writes
  nothing yet (the journaled write engine is phase E2).

### Changed

- Renamed the core scan-view adapter module `configctl_discovery_stub` →
  `scan_view` so its name no longer implies a core→discovery dependency.

## [1.1.0] — 2026-09-30

Hardcore mapping: discovery breadth is inverted from "not allowlisted →
exclude" to "discover broadly → classify with evidence → capture what is
reproducible → reference secrets → record the rest", bounded by one central
`ResourceGovernor`.

### Added

- **Resource inventory (V1.1-P1)** and a central **`ResourceGovernor`**
  (V1.1-P2) bounding wall time, CPU pressure, memory, I/O, files, directory
  entries, subprocesses, output, recursion, symlink depth, and concurrency.
- **Package and toolchain provenance (V1.1-P3)** across multiple managers,
  recorded observationally.
- **Filesystem and project mapping (V1.1-P4)**; **services, environment, and
  hardware inventory (V1.1-P5)**.
- **Profile schema v2 (V1.1-P6)** — new `[[directories]]`, `[[executables]]`,
  `[[toolchains]]`, `[[mounts]]`, hardware, and `packages.other` sections; v1
  bundles keep loading.
- **Hardcore capture and reproduction (V1.1-P7)**; **hardened discovery and
  reproduction (V1.1-P8)** with completeness reporting (`PARTIAL` + named
  reasons, never a silent `COMPLETE`).
- CLI: plain-language guidance (`configctl guide`, `--explain`, next-step
  hints, error help).
- CLI: `configctl status` (one-page state + drift) and `configctl why <target>`
  (ownership, last operation, backup, rollback command).
- CLI: `--last` for `apply` and `rollback` (newest plan without a plan id).
- v1.1 resource-control flags on `scan`/`capture` (`--max-time`, `--max-files`,
  `--max-bytes`, `--max-memory`, `--workers`, `--follow-mounts`,
  `--scan-network`).

### Fixed

- `apply --dry-run` never requires approval.
- Plan-load errors are classified instead of collapsed to a single conflict.
- Correct file rollback content identity.
- Canary and permission suites are environment-independent.

## [1.0.0-rc.1] — 2026-09-20

First release candidate. Complete local-first lifecycle: `scan`, `capture`,
`profile validate/migrate`, `plan`, `apply` (journaled, locked, backed up),
`verify`, `rollback` (crash recovery), `env`, `secrets`, `audit`, `doctor`.
Secrets are referenced (`secret://…`) and never written into profiles, logs,
diffs, plans, or state.
