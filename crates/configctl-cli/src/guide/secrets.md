# secrets — references, never values

What it does: stores secret values in the Linux Secret Service (GNOME
Keyring/KWallet) and keeps only references like
secret://work/project/GITHUB_TOKEN in profiles and plans.

Commands:

    configctl secrets list <profile>           refs + backend status
    configctl secrets set secret://...         value via hidden prompt/stdin
    configctl secrets get secret://...         metadata; --show prints value (TTY only)

Rules that protect you:
  - Values never appear in argv, logs, plans, JSON, or state files.
  - `secrets get --show --json` is refused by design.
  - No keyring available -> secret commands exit 6; nothing is stored in a
    fallback plaintext file.

Common confusion:
  - If `secrets list` shows "unavailable", you are probably in a non-graphical
    session. Run it from your desktop session or unlock the keyring.
  - Losing the keyring means losing the values; profiles only hold references.

Next:
    configctl guide env
