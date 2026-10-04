# Changelog

All notable changes to configctl are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
semantic. Dates are ISO-8601.

## [Unreleased]

v1.3 UX polish batch (still E5 for move mode — no automatic apply path, no
plan/state format changes, all defaults backward compatible).

### Added

- Native `dnf` (Fedora/RHEL) and `pacman` (Arch) package providers, mirroring
  the apt discipline: distro-gated probes (`/etc/os-release` `ID`/`ID_LIKE`
  plus the manager binary — non-matching platforms record `Unavailable`, never
  a silent skip), fixed-argv `CommandRunner` calls only, version-checked
  output parsing (rpm epochs preserved via a pinned
  `--queryformat '%{NAME}\t%{EVR}\t%{ARCH}\n'`; `pacman -Q` two-field lines),
  elevation via `sudo -n` only (`dnf install -y`, `pacman -S --noconfirm`),
  and report-only rollback (`dnf remove` / `pacman -R` manual hints;
  `supports_rollback: false`, like apt). Profiles gain first-class
  `[packages].dnf` / `[packages].pacman` keys plus matching
  `packages.lock.toml` sections (unknown managers such as `apk` are still
  rejected); `doctor` reports the native manager; `plan` renders per-manager
  package groups. Only the `dnf` binary is ever invoked (on Fedora 41+ it is
  the DNF5 symlink, so one binary covers both generations).
- `env consolidate --mode move --emit-patch` accepts `--backup-dir <DIR>`:
  all timestamped backups go there as `<rc-basename>.configctl-bak-<ts>`
  (`0600`, byte-identical, verified; restore commands point at the new
  locations) instead of landing adjacent to each rc file. The directory
  (and parents) is created when missing; a non-directory or non-writable
  dir is refused (exit 2 + guidance). The move JSON carries `backup_dir`
  (dir, or null for adjacent).
- `--home <DIR>` on `apply`, `verify`, `rollback`, and `undo`, matching the
  existing flag on `env consolidate`/`env explain`/`onboard` (and honoring
  `$HOME` when absent), so one flag threaded through the whole lifecycle
  keeps plan paths consistent — a plan built against `$T/home` and applied
  against another home is refused as stale (exit 5). `export HOME=$T/home`
  is the documented equivalent (see `CLI_SPEC.md` §2.9.1 temp-HOME recipe).

### Changed

- Move-mode tombstones are deterministic: the UTC timestamp moved out of
  the per-line tombstone (`# configctl-move <NAME> consolidated to
  ~/.config/configctl/env.sh`) into a single patch-header line (`#
  Generated <UTC> by configctl env consolidate --mode move`). Re-emitting
  to the same path with an unchanged eligible set + file hashes is now
  idempotent (exit 0, header refreshed; comparison excludes the header
  line) instead of refused; a genuinely different eligible set still
  refuses (exit 5).

### Robustness

- Timing-flake hardening (no behavior change): the subprocess wait loop no
  longer busy-spins (steady 5 ms polls, same kill deadline and bounded 2 s
  reap), the `sleep`-kill test SKIPs cleanly when `sleep` is absent and
  asserts the deadline was honored (lower bound) as well as the generous
  kill ceiling, the `yes` ceiling is documented as hang-catch only, bench
  suites now assert work-done counts (files/projects/symlinks, depth-limit
  engagement) alongside their 120 s ceilings, and the `yes`-cap unit test
  SKIPs when `yes` is absent. Proven with 20/20 green repeats of the
  `stress`, `bench`, and command-runner suites plus 3 full-workspace runs.
- Envmap parser corpus (`configctl-core/tests/fixtures/envmap/` + golden
  snapshot tests): Ubuntu `.bashrc`, zsh `.zshrc`, PATH-mangling
  `.profile`, CRLF, BOM + non-ASCII, near-limit (~1 MiB, generated), and a
  permission-denied case pin exact classification sequences, prove secret
  values reach no output (structured, JSON, or `Debug`), and prove
  determinism (parse twice → identical); a dependency-free fuzz-lite test
  feeds adversarial fragments (unclosed quotes, lone `\`, NUL bytes,
  10k-char lines, `$(…)`/backticks/`${…}`) asserting no panic and exactly
  one classification per substantive line. One consistency fix: a leading
  BOM is now stripped (same discipline as the `.env` parser) instead of
  corrupting the first line's name.
- Exit-code conformance (CLI_SPEC §1.1 is the contract): `capture` refusing
  a non-empty output directory without `--force` now exits 5 (was 2),
  matching the documented code and `onboard`; a plan that builds but fails
  to persist now exits 1 instead of a false 0. New
  `crates/configctl-cli/tests/exit_codes_e2e.rs` pins usage (2), verify
  drift (3), approval decline (4), stale/tampered/unknown plans (5),
  secret-backend-unavailable (6), secrets-list degradation (0 +
  `backend_error`), and success paths (0).

## [1.2.0] — 2026-09-30

Environment consolidation (v1.2), phases E1–E5.

### Added

- `configctl env explain` — read-only map of environment declarations across
  `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zshenv`,
  `~/.xprofile`, and `~/.config/environment.d/*.conf`, with a conservative,
  non-evaluating parser. Lines are classified `managed`/`special`/`manual`/
  `secret`/`structure`; secret-like values are never retained. Reports
  conflicts and effective precedence. Backed by a new `configctl_core::envmap`
  module and an e2e canary test.
- `configctl env consolidate` — plans (and, with `--dry-run`, previews) one
  managed shell env file plus a marker include block per participating shell
  startup file. The plan is applied through the normal journaled `apply` path
  and undone by `rollback`; `expected_before` guards make apply refuse a stale
  plan instead of overwriting a hand edit. Secret entries never reach the
  canonical file, which is additionally screened for secret-like values.
  Every still-declared site is reported as a non-blocking
  `shadowed_declaration` plan warning naming the file and line.
- `configctl env consolidate --mode move` — assisted manual removal of the
  now-shadowed original lines (E5). `--dry-run` prints a per-file per-line
  tombstone preview and writes nothing; `--emit-patch <file>` writes a
  unified diff (hand-applied from `$HOME` with `patch -p0 < <file>`) plus one
  adjacent timestamped backup per touched file
  (`<rc-file>.configctl-bak-<UTC-seconds>`, `0600`, byte-identical, verified
  after write) and prints the exact `cp -p` restore commands (`rollback`
  cannot restore an out-of-band patch). Only `managed` lines whose value
  byte-equals the canonical entry are eligible; a missing/stale canonical
  file, a secret trip, or an existing differing patch file fails closed
  (exit 5). There is no automatic apply path; promotion would need its own
  threat review (recorded as T26 in `ENV_CONSOLIDATION.md` §11).
- Two new plan operation kinds, `EnvFileWrite` and `IncludeLineAdd`, both
  `SAFE_REPRODUCE`, backed up, and rollback-supported (byte-exact restore).
- `verify` checks the canonical shell env file under a new `envfile` provider
  when it exists; `plan` renders an "Environment (shell files)" group.
- `env consolidate` also keeps `~/.config/environment.d/90-configctl.conf` in
  sync from the same profile data, so both env artifacts land in one plan.
- `configctl onboard` — guided first run that composes a read-only scan, the
  environment explanation, and a capture summary, then writes the profile
  bundle (default `~/.config/configctl/profiles/this-machine`). It never plans,
  applies, or changes configuration, and refuses to overwrite a non-empty
  output directory (exit 5) unless `--force`.
- `configctl undo` — alias for `rollback --last`, undoing the most recent plan
  with the same approval, lock, journal, and fail-closed guards.

### Changed

- Renamed the core scan-view adapter module `configctl_discovery_stub` →
  `scan_view` so its name no longer implies a core→discovery dependency.
- `has_symlink_parent` now distinguishes a non-existent ancestor (cannot be a
  symlink; apply creates it) from an unknowable one (still fails closed).

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
