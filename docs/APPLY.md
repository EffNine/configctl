# APPLY.md — journaled apply engine (P4)

P4 is the first milestone allowed to modify the machine. `configctl apply`
executes **exactly** the persisted approved plan. It never re-plans: if the
profile hash differs from the plan's recorded hash, apply refuses (exit 5).

## Pre-execution gate

```text
load plan → verify hash → verify execution state → conflict/adopt gate
→ profile-hash staleness check → approval (--yes or TTY prompt)
→ dry-run short-circuit → global lock → status=applying → execute
```

`apply <plan-id>` only. A profile path is refused (exit 2): silently
generating a plan inside apply would break approval binding.

## Journal

Every operation follows `INTENT → PRECHECK → BACKUP → EXECUTE → POSTCHECK →
DONE`, with each transition persisted in SQLite before the next step. `FAILED`
is recorded on failure. A crash leaves enough durable state for `doctor` to
classify recovery.

## Execution order

Packages → files → environment → services → git → shell env artifacts.
Rollback order is the reverse.

## Shell env artifacts (v1.2)

Two additional operation kinds write shell environment state, both
`SAFE_REPRODUCE`, backed up, and rollback-supported:

| Kind | Target | Behavior |
|---|---|---|
| `EnvFileWrite` | `~/.config/configctl/env.sh` | Full-content replace with the canonical file composed from the profile's `[environment]` literals. Secret entries stay references and are never written; the composed content is screened for secret-like values and a trip is a hard error. Op order is identical to the existing managed env file. |
| `IncludeLineAdd` | a `~/` shell startup file | Appends the marker-delimited include block at the end of the file, idempotently. Only the two markers are added; nothing else is edited. A file that is a symlink, non-regular, or larger than 1 MiB is refused. |

Both carry `expected_before` (the file-content hash observed at plan time), so
apply refuses a plan whose target changed since planning (exit 5) instead of
overwriting the user's edit.

## Files

Validate target → expand against `$HOME` → refuse symlinks (target and every
parent, re-checked immediately before write) → ownership check → TOCTOU
precheck (`expected_before` hash must still match) → backup existing bytes to
the content-addressed store → write temp file in the target directory →
fsync → atomic rename → fsync directory → verify content hash → record
ownership → `DONE`. The destination is never truncated directly. Unmanaged
files are never overwritten; `--adopt` backs up and records ownership first.

## Packages

Native system managers only — `apt` via `sudo -n apt-get install -y <name>`,
`dnf` via `sudo -n dnf install -y <name>`, `pacman` via
`sudo -n pacman -S --noconfirm <name>` (fixed argv,
no shell, no password prompts). Each provider probes its native distro
(`ID`/`ID_LIKE`) plus its binary before planning; anything else is recorded
`Unavailable`, never silently skipped. Privilege failure fails safely (exit 8)
without faking success. No downgrades/removals: rollback is report-only.

## Services

`systemctl --user` only (enable/disable/start/stop per the recorded scope).
Final state is verified. No system scope in v1.

## Lock and failure

One mutating process at a time (`flock` on the state dir; contention fails
fast with exit 5). Fail-stop: the first failure marks the plan `partial` and
stops; later operations are never executed. Recovery is explicit (`rollback`,
`doctor`) — never automatic.
