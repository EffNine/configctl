# glossary

backup      content-addressed copy of a file made before apply writes it;
            rollback restores from these.
bundle      the profile directory: profile.toml + payload files + schemas.
conflict    the target exists but configctl does not own it; never
            overwritten without --adopt.
drift       the machine differs from the profile (verify status DRIFT).
journal     the INTENT/DONE record apply writes before/after each operation.
managed     a resource this profile owns, per the state store.
plan        the numbered, hashed list of operations between profile and
            machine. Approval binds to the plan hash.
profile     your desired state, declared in TOML.
provider    the layer that talks to a subsystem (apt, systemd, files, env).
reference   secret:// pointer to a value stored in the Secret Service.
scan        read-only discovery pass.
state dir   ~/.local/state/configctl: plans, journal, backups, audit log.
