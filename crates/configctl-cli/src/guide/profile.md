# profile — inspect and validate bundles (read-only except migrate)

Commands:

    configctl profile list                     known profiles
    configctl profile show <name|path>         canonical view (never values)
    configctl profile validate <name|path>     all errors, no changes
    configctl profile migrate <name|path> --to 2   rewrite schema v1 -> v2

What it is: a profile is the desired state — the thing plan and apply compare
against. Treat it like source code: review it, commit it, copy it to a new
machine.

Validation is fail-closed: unknown keys, secret values, absolute source paths,
or malformed entries are refused with an explanation, before anything else
runs.

Common confusion:
  - `show` never prints secret values; you will see references only.
  - `migrate` rewrites profile.toml in place only after the migrated profile
    validates. Commit your bundle first if you want a before/after diff.

Next:
    configctl guide plan
