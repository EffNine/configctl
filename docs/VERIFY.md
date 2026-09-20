# VERIFY.md — verification and drift detection (P5)

`configctl verify <profile> [--strict]` is strictly read-only. It never
repairs.

## Statuses

| Status | Meaning |
|---|---|
| `MATCH` | Present and identical to desired state. |
| `DRIFT` | Present but different (managed or profile-claimed). |
| `MISSING` | Desired but absent. |
| `UNMANAGED` | Present but not declared (env extras, optional secrets). |
| `UNKNOWN` | Cannot be determined (permission, symlink, backend gone). |
| `UNSUPPORTED` | Provider unavailable (no package manager, no user manager). |

## Coverage

- Packages (installed; version vs `packages.lock.toml` when present).
- Managed files (content hash vs bundle payload).
- Environment literals (managed env file) and secret references
  (**existence only** — values are never read or compared).
- Project env schemas (`missing` / `invalid` / `secret_ref_missing` /
  `unknown` per variable; see `env verify`).
- Git `user.name` / `user.email`.
- `systemd --user` enabled/running state.

## Exit codes

- `0` — everything matches (`UNMANAGED`/`UNKNOWN`/`UNSUPPORTED` tolerated).
- `3` — any `DRIFT`/`MISSING`; with `--strict`, `UNMANAGED`/`UNKNOWN` too.
- `2` — malformed profile or usage error.

Human output groups per-category `ok/total PASS|FAIL` plus findings;
`--json` emits one record per resource with a `status` field. The JSON
document parses with any conforming parser and contains no values.
