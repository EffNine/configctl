# verify — does the machine still match? (read-only)

What it does: compares the profile against the machine and reports one status
per resource. It never repairs anything.

Status meanings:
    MATCH      as desired
    DRIFT      exists but differs (someone edited it, or an update changed it)
    MISSING    expected but absent
    UNMANAGED  present but not owned by this profile
    UNKNOWN    could not be determined (provider missing, permissions)

Example:

    configctl verify ./work
    configctl verify ./work --strict    # also fail on UNMANAGED/UNKNOWN

Exit codes: 0 all good, 3 drift/missing (or any finding with --strict).

Common confusion:
  - DRIFT is information, not damage. To fix: plan, review, apply.
  - Verification checks files, values, packages, and services as far as the
    providers allow; it does not read your current shell session.

Next:
    configctl plan ./work
