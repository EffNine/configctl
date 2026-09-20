# doctor — what is the state of things? (read-only)

What it does: reports platform facts, provider availability (apt, systemd,
git, keyring), state directory health, and interrupted applies that need
recovery.

Commands:

    configctl doctor
    configctl doctor --json

Run it when:
  - something failed and you want to know why,
  - apply was interrupted (power loss, kill),
  - secret commands report "unavailable".

Next:
    configctl guide exit-codes
