# plan — see exactly what would change

What it does: compares the profile (desired) with this machine (actual) and
writes a plan: a numbered list of operations, plus conflicts and warnings.
Nothing is modified.

Touches: only the state directory (the plan is persisted and hashed).

Example:

    configctl plan ./work              # human view
    configctl plan ./work --json       # for scripts
    configctl plan ./work --fail-on-conflict   # exit 5 if conflicts exist

Reading the output:
    + create / install      ~ update        - disable
    ? unsupported           ! conflict      = no change needed
    [SAFE_REPRODUCE]  safe to automate
    [PRIVILEGED]      would need root; apply refuses
    [MANUAL]          needs a human decision

Every plan has an ID and a hash. Approval binds to that exact hash, so a plan
made before a change can never be applied afterwards (it is refused as stale).

Common confusion:
  - Conflicts are not errors: they mean "the target exists but configctl does
    not own it". They are never overwritten; use --adopt, deliberately.
  - A plan with no conflicts and no operations means you are already converged.

Next:
    configctl apply --last
