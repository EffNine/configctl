# start — what configctl is and where to begin

configctl keeps a Linux machine's setup in one place: packages, dotfiles,
environment values, and services. It never changes anything without showing
you a plan and asking for approval.

The lifecycle:

    scan      look around (read-only)
    capture   write what you have into a profile
    plan      show exactly what would change
    apply     do it (approved plan only, backed up)
    verify    check the machine still matches
    rollback  undo file changes from backups

First run:

    configctl init                  create config + state directories
    configctl guide                 list every topic
    configctl scan ~/projects       safe: nothing is modified

Safety in one sentence: read-only commands never write; mutating commands
(apply, rollback, secrets set/import) require your confirmation, and are
journaled with backups.

Common confusion:
  - "scan" does not change anything, even if you pass --yes.
  - "apply" takes a plan ID, not a profile name. Run plan first.
  - Secrets are stored as references (secret://...), never as values in
    profiles or logs.

Next:
    configctl guide capture
    configctl guide plan
