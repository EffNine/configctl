# DISCOVERY.md — P1 read-only discovery engine

Status: **Implemented in P1.** This document describes the behavior of
`configctl scan`.

The discovery engine establishes a factual, read-only inventory of a Linux
development machine. Its lifecycle is:

```
SCAN → DISCOVER → CLASSIFY → REDACT → REPORT
```

It never writes, chmods, installs, starts/stops services, invokes a shell,
or modifies git state. It scans only the roots you give it (or the configured
defaults); it never walks the whole filesystem.

---

## 1. What `scan` discovers

| Capability | Module | Notes |
|---|---|---|
| Project discovery | `project` | marker-based, confidence + evidence |
| Recursive `.env` discovery | `env` | bounded parsing, per-variable classification |
| Config-file discovery | `config` | registry + generic extensions |
| Secret detection | `secret` | multi-signal, deterministic |
| Git tracking | `git` | via `CommandRunner`, no shell |
| System metadata | `system` | distro/arch/kernel/tools |

## 2. Default roots

When no roots are supplied, `scan` uses a conservative, explicit set under
`$HOME` (only those that actually exist are walked):

```
~/projects  ~/src  ~/workspace  ~/work
```

Pass positional paths or `--root` to override. `~` and `~/...` are expanded.
A nonexistent root is recorded as a warning; it does not fail the scan.

## 3. Exclusions

A hard deny-list is applied before any user rule. These directory names are
never entered (symlinks are never followed, regardless):

```
/proc  /sys  /dev  /run  /tmp  ~/.cache
node_modules  target  build  dist  __pycache__
```

`.git/` is not a deny-listed directory (project detection needs it); it is
skipped as a file-read target but its presence marks a project. Excluded
paths are counted in `statistics.excluded_paths` — they are never silently
hidden.

## 4. `.env` handling

Recognized environment files:

```
.env  .env.local  .env.development  .env.test  .env.production
.env.example  .env.sample  .env.<layer>   (layer = [a-z0-9_-]+)
<name>.env    (dotfiles ending in .env, e.g. db.env)
```

The parser is a bounded, pure-text reader:

- supports `FOO=bar`, `FOO="bar"`, `FOO='bar'`, `FOO=`, `export FOO=bar`,
  comments, blank lines, CRLF, BOM, and `=` inside values
- **never executes** anything — no shell expansion, no command
  substitution, no variable interpolation
- malformed lines yield a structured warning and scanning continues
- per-file read cap (default 256 KiB) and variable cap (default 10,000)

Per file the result records: path, project, size, permissions, owner, variable
names, variable count, per-variable classification, git status, and warnings.
Raw values are never stored in the result.

## 5. Secret classification

Each variable is classified into one of `secret` | `likely_secret` | `config`
| `unknown` using four signals:

| Signal | What it uses |
|---|---|
| A — name | extensible name lexicon (`API_KEY`, `PASSWORD`, `SECRET_KEY`, …) |
| B — pattern | known token shapes (PEM, JWT-like, `sk-`, `ghp_`, AWS key) |
| C — entropy | Shannon entropy, supporting evidence only (never a sole signal) |
| D — context | file-name layer |

The result carries the contributing signals (e.g. `variable_name: SECRET_KEY`,
`high_entropy(4.4)`) but never the value.

## 6. Redaction guarantees

All user-visible bytes pass through the redaction layer before any sink
(terminal, JSON, log, error). Layers:

1. **Type-level** — value-bearing types (`SecretValue`, `ParsedVariable`)
   do not format their content in `Debug`/`Display`/`Serialize`.
2. **Registry** — exact detected values are registered and replaced with
   `<redacted>` before output.
3. **Pattern** — known token families are masked to a short prefix.
4. **Error** — error text is static; values are never interpolated.

Regression tests prove the canary values `super-secret-test-value` and
`another-secret-value` never appear in scan output, JSON, errors, or `Debug`
repr.

## 7. Git tracking detection

For discovered `.env` and config files, tracking is determined via `CommandRunner`
(fixed argv, no shell) using `git rev-parse`, `git status`, `git ls-files`, and
`git check-ignore`. Result per file: `tracked` | `untracked` | `ignored` |
`unknown`. A tracked `.env` emits a high-visibility warning and a `git_findings`
entry with `risk: HIGH`. No credential contents are ever extracted.

## 8. Resource limits (DoS protection)

| Limit | Default |
|---|---|
| max recursion depth | 32 |
| max files per root | 20,000 |
| max files total | 100,000 |
| max file bytes inspected | 256 KiB |
| max total bytes inspected | 256 MiB |
| max findings retained | 10,000 |
| subprocess output cap | 256 KiB |
| subprocess timeout | 30 s |

When a limit is hit, `statistics.stop_reasons` records why (`depth_limit`,
`file_count_limit`, `byte_limit`, `finding_limit`, `permission_denied`).

## 9. JSON output

`--json` emits the P0 envelope on stdout:

```json
{
  "schema_version": 1,
  "command": "scan",
  "status": "ok",
  "data": { "roots": [], "projects": [], "env_files": [],
            "config_files": [], "git_findings": [], "system": {},
            "statistics": {} },
  "warnings": [],
  "errors": []
}
```

`data` is the redacted `ScanResult`. Raw secret values never appear in the
envelope.

## 10. Known limitations

- Secret detection is heuristic; a clean scan is not proof of secret safety.
- The walker is iterative and bounded; extremely wide trees may hit
  `file_count_limit` or `finding_limit` and report partial results.
- Git tracking is only as good as the local `git` binary; a missing git yields
  `unknown`, not a crash.
- Hostname is read from `/etc/hostname` when present; it is included only
  because it is useful scan context, and is not sent anywhere.
- The walker's `permission_denied` accounting depends on the running user;
  root can read 0o000 directories, so the stat may be 0 under root.
