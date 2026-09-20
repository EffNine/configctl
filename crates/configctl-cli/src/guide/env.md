# env — environment files and variables (read-only today)

What it does: finds .env files in your projects, classifies every variable
(secret, path, machine-specific, literal), and verifies project env schemas.

Commands:

    configctl env scan ~/projects      # find .env files, names only
    configctl env list ~/projects      # variables with classifications
    configctl env verify <profile>     # check .env files against a schema

Values of secret-like variables are never printed — only names and
classifications.

Where settings live on a Linux machine (the messy part):

    ~/.bashrc  ~/.profile  ~/.zshrc    shell startup files
    ~/.config/environment.d/*.conf     systemd user session
    project .env files                 per-project values

A plain terminal may not see values set in environment.d. Consolidating all of
this into one managed file (with a marked include line in your shell files) is
specified in docs/ENV_CONSOLIDATION.md and will arrive as
`configctl env explain` / `configctl env consolidate`.

Common confusion:
  - env scan is read-only; it does not import anything.
  - "secret" is a classification, not a value store.

Next:
    configctl guide secrets
