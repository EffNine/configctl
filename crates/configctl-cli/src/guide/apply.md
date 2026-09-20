# apply — make the plan real (the only mutating path)

What it does: executes exactly the operations in the approved plan, in order,
with a journal (INTENT/DONE) and content-addressed backups.

Touches: the machine. Requires explicit approval.

Commands:

    configctl apply <plan-id>              # interactive: asks y/N
    configctl apply <plan-id> --yes        # non-interactive approval
    configctl apply <plan-id> --dry-run    # preview, never writes
    configctl apply <plan-id> --adopt <target>   # take ownership of a conflict

Good to know:
  - apply refuses profile paths, stale plans, and PRIVILEGED/DESTRUCTIVE/
    UNSUPPORTED operations. It never re-plans.
  - If an operation fails, apply stops, marks the plan partial, and tells you
    which operation failed and how to recover.
  - Files it writes are backed up; rollback restores them.

Common confusion:
  - "Nothing happened" usually means the plan had no operations (already
    converged) — check the plan output.
  - --yes approves this plan only. After any change, re-plan and approve again.

Next:
    configctl verify ./work
    configctl guide rollback
