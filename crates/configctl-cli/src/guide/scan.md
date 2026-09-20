# scan — look around (read-only)

What it does: walks the paths you give it and records projects, config files,
.env files, packages, services, and hardware facts. Nothing is written to the
machine; the only output is a report (and JSON with --json).

Touches: nothing.

When to use it:
  - Before capturing, to see what configctl would find.
  - To answer "where does all this live?".

Examples:

    configctl scan ~/projects                 # human report
    configctl scan ~/projects --json          # machine-readable
    configctl scan ~/projects --max-time 2m   # bounded search

Long scans are budgeted (time, files, subprocesses). If a budget is reached
the report says PARTIAL with the reason — it never pretends the scan was
complete.

Common confusion:
  - Huge roots (/, /home) are slow even when bounded. Point it at projects.
  - Symlinks are not followed by default.
  - Mounts outside your roots are recorded, not traversed.

Next:
    configctl guide capture
