# audit — safety check for a repository (read-only)

What it does: looks for secrets tracked by git, world-readable key files, and
.env files that should be examples, and reports findings with severities.

Commands:

    configctl audit                # scan current directory
    configctl audit git ~/proj     # git-specific checks
    configctl audit --fail-on high # exit 3 when findings >= severity

Nothing is modified; no secret values are printed.

Common confusion:
  - audit is not a malware scanner; it checks configuration hygiene.
  - A finding is a prompt to review, not proof of a leak.

Next:
    configctl guide secrets
