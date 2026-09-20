# exit codes — what the number means

    0  success
    1  unexpected internal error
    2  usage or configuration error (bad input, bad flag)
    3  verification failed (drift/missing, or --strict findings)
    4  aborted: you (or non-interactive mode) did not approve
    5  conflict or unsafe state: unmanaged target, stale or tampered plan
    6  secret backend unavailable (no keyring)
    7  provider unavailable (apt/systemd/git missing)
    8  required privilege missing

Rules of thumb:
  - 4 and 5 mean nothing changed.
  - 5 usually means: re-run `configctl plan <profile>`, review the conflicts,
    and use `--adopt <target>` only for files you want configctl to own.
  - 3 is not "broken"; it means the machine differs from the profile.
  - Every error line should tell you the next command. If not, run
    `configctl doctor`.

Next:
    configctl guide start
