# why — who owns this file? (read-only)

What it does: for one file target, shows whether configctl manages it, the
recorded content fingerprint, and the most recent plan operation that touched
it — plus the backup you would restore it from.

Commands:

    configctl why ~/.gitconfig
    configctl why ~/.config/nvim/init.lua --json

What you get:
    file         exists? size? symlink?
    managed by   the profile that owns it (from the state store)
    fingerprint  hash recorded when it was written
    last op      plan id, operation, journal phase, backup hash
    rollback     the exact command to undo it

Common confusion:
  - "managed by nothing" does not mean broken: it means no profile owns the
    file. A plan targeting it will report a conflict, and configctl will not
    touch it unless you adopt it deliberately.
  - The fingerprint is of the content configctl recorded, not a live diff.
    For "does it still match?", use `configctl verify`.

Next:
    configctl guide verify
