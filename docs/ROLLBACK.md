# ROLLBACK.md — rollback and crash recovery (P7)

## Backups

Content-addressed under `~/.local/state/configctl/backups/objects/<sha256>`.
State root is `0700`; backup objects are `0600`. Backups are **not encrypted**
in v1 — documented limitation (see SECURITY.md). Secret values are never
backed up: configctl manages references, and managed files are dotfiles.

## Scope honesty

| Resource | Rollback |
|---|---|
| Files (`FileCreate`/`FileUpdate`) | `ROLLBACK_SUPPORTED` — atomic restore, or removal of a created file when current content still matches. |
| Managed env literals | `ROLLBACK_SUPPORTED` — whole-file restore from backup. |
| Packages | `ROLLBACK_UNSUPPORTED` — report-only; v1 never auto-removes or downgrades (manual `apt remove` printed). |
| Services, git | `ROLLBACK_PARTIAL` — prior states are not snapshotted; reported for manual verification. |

Rollback runs in reverse execution order under the mutation lock, requires
explicit approval (`--yes` or TTY prompt), and marks the plan `rolled_back`.
`--dry-run` previews without writing. `rollback --list` shows candidates;
`rollback ~/.file` restores one file from its most recent backup.

## Crash recovery

Every mutating op journals `INTENT → PRECHECK → BACKUP → EXECUTE →
POSTCHECK → DONE` (`FAILED` on failure). `doctor` classifies each
interrupted op:

| Last phase | Classification | Meaning |
|---|---|---|
| none / `INTENT` / `PRECHECK` | safe to resume | Nothing was written; an explicit re-`apply` is accepted (prechecks re-run). |
| `BACKUP` | safe to resume | Backup taken, target verified untouched. |
| `EXECUTE` / `POSTCHECK` | requires rollback | Target may be written; `rollback` restores the backup. |
| `FAILED` / ambiguous | requires manual intervention | Never guessed; human decides. |

Recovery is always explicit. Apply refuses plans with unfinished journals
except the safe-to-resume case above; rollback refuses `requires_manual`
plans. Failpoint simulation (`CONFIGCTL_FAIL_AFTER=<op>:<PHASE>`, test-only)
proves every row of this table in the integration suite.
