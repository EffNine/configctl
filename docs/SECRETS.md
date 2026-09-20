# SECRETS.md — secrets and environment management (P6)

## Backend

v1 uses the Linux Secret Service via the `secret-tool` CLI (fixed argv,
bounded output, scrubbed environment; no custom crypto, no D-Bus code).
Items are stored with attribute `configctl-ref = <secret://…>`. Profiles
carry references only:

```text
secret://namespace/project/NAME
```

When no Secret Service is reachable, secret-dependent commands fail closed
with exit 6 and a remediation hint. **There is no plaintext fallback.**
(`CONFIGCTL_SECRET_TEST_DIR` selects an isolated file store for tests and
the canary suite only — never production.)

## Input discipline

Values enter only through a hidden interactive prompt or `--stdin`.
`secrets set REF value` (argv) is refused: argv is world-readable in
`/proc`. Inherited environment variables are not a transport.

## Output discipline

`secrets list` shows references + status (`present`/`missing`/
`backend_error`) — never values. `secrets get` shows metadata by default;
`--show` prints the value only with an explicit TTY (or `--force` with a
stderr warning). `--show --json` is refused: plaintext never enters
machine-readable output, logs, errors, plans, or state.

## Import

`secrets import [PATH...]` parses `.env` files locally (bounded parser),
classifies with the multi-signal detector, and shows **names only**.
Interactive review is per-item (import/ignore/quit); `--yes` imports only
high-confidence `secret` classifications; `--dry-run` imports nothing. The
source file is never rewritten and no temporary plaintext copy is kept —
values are read, stored, and dropped.

## Environment schemas

`env scan` / `env list` report names and classifications (never values).
`env verify` checks live `.env` files against `env/<project>.toml` schemas:
missing required variables, wrong types, enum violations, required secrets
without manifest references, and undeclared variables (warnings). Exit 3 on
errors.
