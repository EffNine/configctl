# capture — turn your machine into a profile

What it does: writes a profile bundle: a directory of TOML files describing
packages, managed files, environment values, services, and projects. Secret
values are never copied — only secret:// references.

Touches: one new directory (the bundle). Your machine is not modified.

Example:

    configctl capture --output ./work
    configctl capture work --from ~/projects --output ./work

What ends up in the bundle:
    profile.toml          packages, files, environment, services, projects
    files/                copies of managed config files (dotfiles)
    secrets.manifest.toml references only — never values
    env/                  per-project .env schemas

Common confusion:
  - "capture" copies config files into the bundle; it does not yet manage
    them on the machine. That happens at apply time, after a plan.
  - Files that look secret are skipped or referenced, never copied.
  - Capturing the same machine twice produces the same semantic result;
    timestamps are ignored when comparing.

Next:
    configctl profile validate ./work
    configctl plan ./work
