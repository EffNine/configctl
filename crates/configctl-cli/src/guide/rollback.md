# rollback — undo file changes from backups

What it does: restores files that apply changed, from content-addressed
backups. Package and service changes are report-only: configctl tells you what
changed but does not remove or downgrade packages.

Touches: the machine. Requires approval.

Commands:

    configctl rollback --list                 # what can be rolled back
    configctl rollback --plan <plan-id>       # roll back that plan
    configctl rollback --last                 # newest plan; no need to copy an ID
    configctl rollback --plan <plan-id> --dry-run
    configctl rollback --plan <plan-id> --yes

Good to know:
  - Every file write during apply is backed up first, so rollback is exact.
  - If apply crashed halfway, run `configctl doctor` first; it reports
    interrupted applies and what can be recovered.
  - Rolling back does not "un-plan"; after rollback the machine simply
    differs from the profile again.

Next:
    configctl doctor
