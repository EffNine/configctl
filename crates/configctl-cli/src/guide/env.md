# env — environment files and variables (read-only today)

What it does: finds .env files in your projects, classifies every variable
(secret, path, machine-specific, literal), and verifies project env schemas.

Commands:

    configctl env scan ~/projects      # find .env files, names only
    configctl env list ~/projects      # variables with classifications
    configctl env verify <profile>     # check .env files against a schema
    configctl env explain              # where shell settings live, which wins (v1.2)
    configctl env consolidate --dry-run # preview one managed env file (v1.2)

Values of secret-like variables are never printed — only names and
classifications.

Where settings live on a Linux machine (the messy part):

    ~/.bashrc  ~/.profile  ~/.zshrc    shell startup files
    ~/.config/environment.d/*.conf     systemd user session
    project .env files                 per-project values

A plain terminal may not see values set in environment.d. `configctl env
explain` maps every declaration, flags conflicts, and says which value wins;
`configctl env consolidate --dry-run` previews putting them into one managed
file (`~/.config/configctl/env.sh`) with a marked include line in your shell
files. Writing is not enabled yet (phase E2 in docs/ENV_CONSOLIDATION.md).

Common confusion:
  - env scan is read-only; it does not import anything.
  - "secret" is a classification, not a value store.

Next:
    configctl guide secrets
