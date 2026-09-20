# status — one-page summary (read-only)

What it does: reports the health of the state store and, when you pass a
profile, the same counts as `verify` in one screen. Nothing is changed.

Commands:

    configctl status                 # state store overview
    configctl status ./work          # state + drift counts for a profile
    configctl status ./work --json

What the counts mean:
    MATCH      managed resource is as desired
    DRIFT      managed resource differs on disk
    MISSING    expected but not present
    UNMANAGED  present but not owned by the profile
    UNKNOWN    could not be determined
    unsupported provider cannot check it

status always exits 0 when it can read things — it is information, not a
verdict. Use `verify` in scripts when you need exit 3 on drift.

Common confusion:
  - "Newest plan" is not the same as "applied": a planned-but-not-applied
    plan still shows up.
  - status without a profile does not check any files; pass the bundle.

Next:
    configctl guide why
