# Resource Classification (v1.1)

First-class model (`configctl-core/src/classify.rs`): every discovered
resource gets an identity, a type, a classification **with evidence**,
a reproducibility state, and an explicit capture decision.

## Classes

| Class | Meaning | Typical members |
|---|---|---|
| `portable` | Safe to copy across machines | shell/editor configs, manifests |
| `reproducible` | Regenerable from a recipe | lockfiles, user units |
| `machine_specific` | Tied to this machine | hostnames, `$HOME` paths |
| `generated` | Build output | `target/`, `node_modules/`, `dist/` |
| `cache` | Cache content | `.cache/`, `__pycache__/` |
| `dependency` | Third-party / VCS content | vendored deps, `.git/`, executables |
| `secret` | Secret material itself | private keys, tokens, `.env` values |
| `credential` | Credential metadata/containers | `.ssh/config`, `*.pub`, helpers |
| `privileged` | Needs privilege | system units |
| `unsupported` | Observed, not representable | sockets, FIFOs, devices |
| `unknown` | Observed, not yet understood | everything else (preserved!) |

`unknown` is a first-class bucket meaning "metadata preserved", never
"ignored". Every verdict carries `signals` (e.g. `generated_dir:target`,
`secret_name:id_rsa`, `extension:.dat`) and a human `reason`.

## Reproducibility

`reproduce` (bytes) · `reference` (`secret://`, value from backend) ·
`observe` (metadata only) · `manual` (documented human step) ·
`unsupported` (cannot be reproduced).

## Capture actions

`capture` · `reference` · `observe` · `exclude` — always paired with a
reason. Capture summaries aggregate `action → count` so broad capture
stays auditable.

## Environment variables

Classified by name only (never values): `public_config`, `path`,
`runtime`, `secret`, `machine_specific`, `unknown`. PATH-like variables
add entry analysis (ordering, duplicates, missing entries, user vs
system origin).

## Execution policy

Discovery breadth never implies execution recklessness. Each planned
operation carries a `PlanActionClass`:

```text
SAFE_REPRODUCE | PRIVILEGED | DESTRUCTIVE |
MACHINE_SPECIFIC | SECRET_REQUIRED | UNSUPPORTED | MANUAL
```

The apply engine refuses `PRIVILEGED`, `DESTRUCTIVE`, and `UNSUPPORTED`
operations with a journaled reason — even when their kind would otherwise
dispatch. Secrets reproduce only via backend references; machine-specific
and unknown resources resolve to explicit human steps.
