# CLI_SPEC.md — configctl command-line interface

Status: **P0 draft. No implementation exists yet.**

Binary name: `configctl` (tentative; see ARCHITECTURE.md open questions).

---

## 1. Global conventions

```
configctl [GLOBAL OPTIONS] <COMMAND> [ARGS]
```

| Option | Description |
|---|---|
| `--config <FILE>` | Path to `config.toml` (default `$XDG_CONFIG_HOME/configctl/config.toml`). |
| `--profile <NAME>` | Profile to operate on, overriding `default_profile`. |
| `--state-dir <DIR>` | Override the state directory. |
| `--json` | Machine-readable JSON on stdout. Conflicts with human rendering; warnings still go to stderr. |
| `-q, --quiet` | Suppress non-essential human output. Errors always shown. |
| `-v, --verbose` | Increase diagnostic detail (repeatable: `-vv`). |
| `--no-color` | Disable ANSI color (also honors `NO_COLOR`). |
| `-y, --yes` | Approve the current plan non-interactively. Only meaningful for mutating commands. |
| `--dry-run` | Perform all reads and checks, produce all output, change nothing. Never prompts. |
| `-h, --help` / `-V, --version` | Standard. |

### 1.1 Exit codes (stable contract)

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | Usage or configuration error |
| 3 | Verification failed (`verify`, `env verify --strict`, `audit --fail-on`) |
| 4 | Aborted by user (approval declined) |
| 5 | Conflict or unsafe state (ownership conflict, stale plan, tampered plan) |
| 6 | Secret backend unavailable |
| 7 | Provider unavailable (systemd absent, git missing, …) |
| 8 | Required privilege missing |

### 1.2 Safety defaults

- Read-only commands (`scan`, `capture`, `plan`, `verify`, `env *`, `audit`,
  `doctor`, `profile *`) never mutate anything, even if `--yes` is passed.
- Mutating commands (`apply`, `rollback`, `secrets set`, `secrets import`)
  require either an interactive confirmation or `--yes`. In `--json` mode a
  confirmation is impossible, so `--yes` is **required** and its absence is a
  usage error (exit 2).
- `--dry-run` is accepted by mutating commands and always short-circuits
  before any write.
- Secrets are never accepted as command-line arguments.

---

## 2. Command reference

### 2.1 `configctl init`

```
configctl init [--profile <NAME>] [--force]
```

Creates `~/.config/configctl/config.toml`, the profiles directory, and the
state directory (`0700`). Does not touch anything else. `--force` overwrites an
existing config (refused otherwise, exit 2).

Example:

```
$ configctl init
Created  ~/.config/configctl/config.toml
Created  ~/.config/configctl/profiles/
Created  ~/.local/state/configctl/          (0700)
```

### 2.2 `configctl scan`

```
configctl scan [PATH...] [--root <PATH>]... [--depth <N>]
               [--include-kind <KIND>]... [--exclude <GLOB>]...
               [--max-file-bytes <N>] [--json]
```

Read-only discovery. Positional paths define scan roots; `--root` appends to
configured roots. With no roots from CLI or config, exits 2 with guidance.
Never modifies, never prints secret values.

Human output:

```
Environment Scan

Projects                  23
Config files              184
Environment files          31
Variables                 247
Potential secrets          48
System services            12

Potential issues:

! 7 secrets duplicated
! 3 .env files appear tracked by Git
! 4 projects missing .env.example
! 2 configuration files have weak permissions
! 5 projects use inconsistent tool versions

Scan complete in 1.8s — no changes made.
```

JSON (`--json`) shape:

```json
{
  "schema_version": 1,
  "command": "scan",
  "status": "ok",
  "data": {
    "roots": ["/home/user/projects"],
    "counts": {
      "projects": 23, "config_files": 184, "environment_files": 31,
      "variables": 247, "potential_secrets": 48, "system_services": 12
    },
    "issues": [
      { "code": "secret_duplicated", "severity": "warning", "count": 7, "message": "7 secrets duplicated" }
    ],
    "findings": [
      { "kind": "environment_file", "path": "projects/foo/.env", "project": "foo",
        "risk": "secret-containing", "confidence": "likely" }
    ]
  },
  "warnings": [], "errors": []
}
```

### 2.3 `configctl capture`

```
configctl capture <NAME> [--from <PATH>]... [--out <DIR>]
                 [--include-files <SPEC>]... [--no-files] [--json]
```

Inspects the live machine and writes a profile bundle. Never captures secret
values: secret-bearing variables are recorded in `secrets.manifest.toml` as
references only. Writes only inside `--out` (default
`$XDG_CONFIG_HOME/configctl/profiles/<NAME>`); refuses to overwrite a non-empty
directory without `--force` (exit 5).

Example:

```
$ configctl capture work --from ~/projects
Captured profile work

  Packages           47
  Dotfiles           12
  Environment refs    9   (values not captured)
  Projects            6
  Service intents     2

Wrote ~/.config/configctl/profiles/work/
  profile.toml
  secrets.manifest.toml
  env/conductor.toml
  files/gitconfig
```

### 2.4 `configctl profile list|show|validate|migrate`

```
configctl profile list [--json]
configctl profile show <NAME|PATH> [--json]
configctl profile validate <NAME|PATH> [--json]
configctl profile migrate <NAME> --to <SCHEMA_VERSION> [--yes]
```

- `list` — name, path, last used, schema version, description.
- `show` — canonical, redacted rendering of the profile (never values; refs
  shown as `secret://…`).
- `validate` — parse + semantic validation only. Exit 2 on invalid, with
  all errors listed (not just the first). No mutation.
- `migrate` — explicit one-way migration; writes a new bundle and keeps the
  original unless `--replace` is added to a future version.

### 2.5 `configctl plan`

```
configctl plan [NAME] [--json] [--out <FILE>] [--verbose]
```

Produces and persists a plan. No mutation. Conflicts are reported but exit is
0 (the plan was produced); scripts that want failure on conflicts use exit code
5 by adding `--fail-on-conflict`.

Human output:

```
PLAN work

Packages:
  + ripgrep
  + jq
  + tmux

Files:
  ~ ~/.gitconfig
  + ~/.config/nvim/init.lua

Environment:
  + EDITOR=nvim

Services:
  docker -> enable, start

3 conflicts:
  ! ~/.config/nvim exists and is not managed (use --adopt to take ownership)
  ! plan is missing secret ref secret://work/dev/github/GITHUB_TOKEN

No changes made. Run `configctl apply work` to execute this plan (id: 01J...).
```

### 2.6 `configctl apply`

```
configctl apply [NAME] [--plan <PLAN_ID>] [--yes] [--dry-run]
                [--adopt <TARGET>]... [--json]
```

- Defaults to the latest valid plan for the profile. Refuses stale plans
  (profile or state changed since planning) with exit 5 and a re-plan hint.
- Executes **exactly** the planned operations, in plan order.
- Prompts for approval unless `--yes`; declines exit 4.
- `--dry-run` prints the same execution preview without writing; never prompts.
- `--adopt <TARGET>` resolves ownership conflicts for the listed targets by
  backing up and taking ownership as part of this apply (targets must appear
  as conflicts in the current plan; otherwise exit 2).

Human output:

```
Applying plan 01J8Z... (work)

  [ok]  apt install ripgrep
  [ok]  apt install jq
  [ok]  write ~/.gitconfig (backup 3f9a…)
  [ok]  create ~/.config/nvim/init.lua
  [ok]  set EDITOR=nvim in ~/.config/environment.d/90-configctl.conf
  [ok]  systemd --user enable docker

6 operations applied, 0 failed. Verify with `configctl verify work`.
```

Failure behavior: stop at first failure, mark plan `partial`, print exactly
which operation failed and how to recover:

```
  [fail] apt install tmux — exit 100
         apt-get reported: Unable to locate package tmux

Apply stopped. 2 of 6 operations applied; plan marked partial.
Recover with: configctl rollback 01J8Z...   (file changes only)
              configctl doctor              (show current state)
```

### 2.7 `configctl verify`

```
configctl verify [NAME] [--json] [--strict] [-v]
```

Read-only comparison of profile vs machine. Exit 3 when any `DRIFT`/`MISSING`
exists; with `--strict`, `UNMANAGED`/`UNKNOWN` also fail.

Human output:

```
Environment Verification — work

Packages       47/47    PASS
Dotfiles      128/128   PASS
Environment     9/9     PASS
Secrets         7/9     DEGRADED
Services        6/6     PASS

Drift detected:

  ~ ~/.gitconfig
  ~ ~/.config/nvim/init.lua
  - ripgrep package
  ! secret://work/dev/github/GITHUB_TOKEN  MISSING
  ? docker.service                          UNKNOWN (systemd not running)
```

JSON: one record per resource with `status` in
`match|drift|missing|unmanaged|unknown|error`.

### 2.8 `configctl rollback`

```
configctl rollback [NAME|TARGET] [--plan <PLAN_ID>] [--list]
                   [--yes] [--dry-run] [--json]
```

- `--list` shows rollback candidates from history (plan id, time, files).
- Default: roll back the most recent applied plan for the profile.
- Targeted: `configctl rollback ~/.gitconfig` restores that file from the most
  recent backup before its last change.
- File/config rollback is fully supported. Package rollback is **report-only**
  in v0.1: it lists packages that would need manual removal; it never
  downgrades or removes packages automatically.
- Rollback never writes secret values into files (backups are of actual
  previous file content; if the previous content contained secrets, the
  operation is flagged and requires explicit `--yes` plus a permission
  warning).

### 2.9 `configctl env scan|list|verify`

```
configctl env scan [PATH...] [--json]
configctl env list [--project <P>] [--json]
configctl env verify [NAME] [--project <P>] [--schema <FILE>] [--strict] [--json]
```

`env scan` example:

```
17 environment files found
83 variables found
31 likely secrets
52 non-secret configuration values

No values were read into output.
```

`env list` example:

```
project             variable              type

conductor           AGNES_API_KEY         secret
conductor           PORT                  config
atlas               HF_TOKEN              secret
novel-translator    MAX_CHARS             config
```

`env verify` reports missing/invalid/unknown variables per the project schema
(see PROFILE_SCHEMA.md §4.2). Exit 3 on errors.

### 2.10 `configctl secrets list|set|get|import`

```
configctl secrets list [--project <P>] [--json]
configctl secrets set <secret://ns/path> [--stdin] [--json]
configctl secrets get <secret://ns/path> [--show] [--force] [--json]
configctl secrets import [PATH...] [--dry-run] [--json]
```

- `list` — references + status (`present` / `missing` / `backend_error`).
  Never values.
- `set` — reads the value from a hidden interactive prompt or `--stdin`.
  Rejects `--value`; argv is visible in `/proc`. Confirms overwrite.
- `get` — defaults to metadata only. `--show` prints the value to stdout;
  if stdout is not a TTY, `--force` is additionally required. Prints a one-line
  warning to stderr when showing.
- `import` — interactive workflow:

```
Found 31 potential secrets.

[1/31] conductor/.env
  AGNES_API_KEY          likely_secret   (matched name + format, entropy 4.6)
  JEV_API_KEY            likely_secret   (matched name)

  Review value? [s]how masked  [i]mport  [k]ignore  [q]uit
  > i
  Imported as secret://work/dev/conductor/AGNES_API_KEY

  Database password for db.internal? (hidden input)
  > ********
  Imported as secret://work/dev/conductor/DATABASE_PASSWORD

Never deletes or rewrites originals. Nothing leaves this machine.
```

Non-interactive `import` requires `--yes` and imports only `secret`
(high-confidence) classifications; `likely_secret` requires explicit review.
`--dry-run` lists candidates without prompts and without imports.

### 2.11 `configctl audit` and `configctl audit git`

```
configctl audit [PATH...] [--fail-on <SEVERITY>] [--json]
configctl audit git [PATH...] [--json]
```

Checks:

- tracked `.env`/`.env.*` files (warning)
- files matching secret patterns that are tracked by Git (warning/high)
- private keys with permissions broader than `0600` (high)
- world-readable secret-like files (high)
- duplicated secret values across projects (warning)
- missing `.env.example` for projects with `.env` (info)

Strictly read-only. Prints suggested commands, never runs them. Exit 3 with
`--fail-on warning|error`.

Example:

```
! conductor/.env is tracked by Git
  Suggested: git rm --cached conductor/.env   (then rotate if it was pushed)

! ~/.ssh/id_rsa is world-readable (0644)
  Suggested: chmod 600 ~/.ssh/id_rsa
```

### 2.12 `configctl doctor`

```
configctl doctor [--json]
```

Diagnostics only; always exit 0 unless the state directory is unusable.

```
Platform              Ubuntu 26.04
Architecture          x86_64
Init                  systemd (user manager available)
Package manager       apt
Secret backend        Secret Service (unlocked)
Configctl state       OK  (last integrity check: pass)
Profile               work
Last verification     PASS (2h ago)
Interrupted apply     none
```

---

## 3. Output rules

1. Human output goes to stdout; diagnostics/warnings to stderr; `--quiet`
   suppresses progress but never errors or warnings.
2. `--json` emits exactly one JSON document on stdout; warnings/errors are
   fields inside the envelope and also mirrored to stderr (redacted).
3. Every JSON document has `schema_version`, `command`, `status`, `data`,
   `warnings`, `errors`.
4. Colors are used only for human TTY output.
5. All output paths pass through the redaction layer (ARCHITECTURE.md §13).
6. Success output ends with the next suggested command where useful.

---

## 4. Confirmation UX

Interactive mutations show the plan summary and ask:

```
Apply 6 operations to this machine? [y/N]
```

- Anything other than `y`/`yes` → exit 4.
- Destructive operations (delete, disable, overwrite unmanaged with `--adopt`)
  are grouped and called out before the prompt.
- `--yes` approves the *current plan only*; a re-planned or regenerated plan
  requires a new approval.
- Non-interactive sessions without `--yes` → exit 4 (not a hang), with a hint
  to re-run with `--yes`.

---

## 5. Command → milestone mapping

| Command | First delivered in |
|---|---|
| `init`, `scan`, `doctor` (partial) | P1 |
| `capture`, `profile list/show/validate` | P2 |
| `plan` | P3 |
| `apply` | P4 |
| `verify` | P5 |
| `env *`, `secrets *`, `audit *` | P6 |
| `rollback` | P7 |
| hardening, JSON stability guarantees | P8 |

Until a command's milestone lands, invoking it exits 2 with
`not implemented until milestone P<n>`.
