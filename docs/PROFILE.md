# PROFILE.md — P2 declarative profile format (implemented)

Status: **Implemented in P2; extended by schema v2 in v1.1.** This document
describes the v1 profile bundle that `configctl capture` produced up to
`v1.0.0-rc.1`. Since v1.1, capture emits schema v2, and
`docs/PROFILE_SCHEMA.md` (§2.7) is authoritative for the current bundle; where
the two differ, `PROFILE_SCHEMA.md` wins.

Format: **TOML**. Every file declares `schema_version` (`1` as documented
here; v1.1 capture emits `2`). Unknown keys are rejected
(`deny_unknown_fields`), including `x-*` (reserved, not yet accepted).

---

## 1. Bundle layout

```text
<output>/
├── profile.toml            # manifest: metadata, platform, packages, files, git, projects
├── secrets.manifest.toml   # secret references only — never values
├── packages.lock.toml      # recorded versions (record-and-report; optional)
├── env/                    # per-project env schemas
│   ├── project-a.toml
│   └── project-b.toml
└── files/                  # managed file payloads (dotfiles only)
    └── home/
        ├── gitconfig
        └── editorconfig
```

Rules:

- `profile.toml` is the only required file.
- All `source = ...` paths are relative to the bundle and must stay inside it
  (no `..`, no absolute paths).
- The whole bundle must be safe to commit to a public repository. Secret
  values are forbidden by validation, not merely discouraged.
- File payloads are byte-exact copies of validated sources; configctl does not
  template them in P2.

---

## 2. `profile.toml`

```toml
schema_version = 1
name = "my-linux-dev"
description = "Captured development environment"
configctl_version = "0.1.0"

[metadata]
captured_at = "2026-09-20T12:00:00Z"
package_policy = "tooling-allowlist-v1"

[platform]
os = "linux"
arch = "x86_64"
distro = "ubuntu noble"

[packages]
apt = ["curl", "git", "ripgrep"]

[[files]]
target = "~/.gitconfig"
source = "files/home/gitconfig"
mode = "0644"

[git]
user_name = "Test"
user_email = "test@example.com"
credential_helper = "store"

[[projects]]
name = "project-a"
path = "~/projects/project-a"
vcs = "git"
ecosystems = ["rust"]
env_schema = "env/project-a.toml"
env_files = [".env", ".env.example"]
config_files = ["Cargo.toml"]
```

### 2.1 Fields

| Field | Required | Rules |
|---|---|---|
| `schema_version` | yes | Must equal `1`. Anything else is refused. |
| `name` | yes | `[a-z0-9][a-z0-9-_]{0,63}`. |
| `description` | no | Free text, ≤ 512 chars. |
| `configctl_version` | no | Informational; ignored for semantics. |
| `metadata` | no | Informational (`captured_at`, `package_policy`); excluded from reproducibility. |
| `platform` | no | `os` must be `linux`; `arch` one of `x86_64 aarch64 x86 arm riscv64`. |
| `packages.apt` | no | Sorted unique names, `[a-z0-9][a-z0-9+.-]*`. No shell syntax. |
| `packages.dnf` | no | Sorted unique Fedora/RHEL names (broader alphabet, may start uppercase). No shell syntax. |
| `packages.pacman` | no | Sorted unique Arch names (same broader alphabet). No shell syntax. |
| `packages.apk` | no | Sorted unique Alpine names (same broader alphabet). No shell syntax. |
| `[[files]]` | no | `target` must start with `~/`, no `..`; `source` bundle-relative, no `..`; `mode` 3–4 digit octal. Duplicate targets rejected. |
| `[git]` | no | Allowlisted metadata only (see §4). |
| `[[projects]]` | no | `path` portable (`~/...` preferred; traversal-free absolute accepted for fixtures); `env_schema` must be `env/*.toml`. Duplicate paths/names rejected. |
| `environment` | no | Reserved; P2 emits none (global literals deferred to P3+). Literals that look secret-bearing are a validation error. |
| `services` | no | Reserved; P2 emits none (service discovery is not in P1). |

Divergence from the P0 draft: P0 sketches `[files."~/..."]` tables and
`[variables.NAME]` tables; P2 uses `[[files]]` / `[[variables]]` arrays
(semantically equivalent, easier to validate and order deterministically).
P0's `packages = [...]` string list is kept; versions live in
`packages.lock.toml`.

---

## 3. `env/<project>.toml`

```toml
schema_version = 1

[project]
name = "project-a"

[[variables]]
name = "DATABASE_URL"
type = "string"
secret = true
required = true

[[variables]]
name = "PORT"
type = "integer"
secret = false
required = false
```

| Field | Rules |
|---|---|
| `type` | One of `string`, `integer`, `boolean`, `enum`. Safe default `string`. |
| `secret` | Default `false`; `true` on name-lexicon or observed `secret`/`likely_secret` evidence. |
| `required` | Default `false`; `true` when the variable appears in `.env.example` / `.env.sample`. |
| `values` | Required non-empty unique list for `enum`; forbidden otherwise. |

Type inference is conservative: `integer` only when every observed value
parses as `i64`; `boolean` only for boolean-like values; `enum` only for
`NODE_ENV`/`APP_ENV`/`ENVIRONMENT` with values drawn from
`development/test/production`. Everything else is `string` — never invented.

---

## 4. `secrets.manifest.toml`

Metadata only. Values can never be represented.

```toml
schema_version = 1

[[secrets]]
name = "OPENAI_API_KEY"
project = "project-a"
source = ".env"
classification = "secret"
backend = "secret-service"
ref = "secret://my-linux-dev/project-a/OPENAI_API_KEY"
required = true
```

Rules: `ref` must parse as `secret://<namespace>/<path>`; duplicate refs or
duplicate `(project, name)` pairs are rejected; `backend` is always
`secret-service` in v1. Deduplication: the same logical secret in several
files yields one entry keyed by `(project, name)` with the lexicographically
smallest source filename recorded as `source` and the strongest observed
classification kept.

---

## 5. `packages.lock.toml`

```toml
schema_version = 1

[apt]
git = "1:2.43.0-1ubuntu7.2"
```

Record-and-report only (P0 §5 semantics): versions are recorded at capture
time; no pinning or enforcement exists in P2.

---

## 6. Validation (`Profile::validate()`)

Every generated profile is validated before capture reports success. All
errors are returned (not just the first); a failing profile is never reported
as captured. Checks: schema version, required fields, duplicate entries,
invalid paths, path traversal, absolute file targets, invalid modes, invalid
env names, duplicate secrets, malformed `secret://` refs, inconsistent
project refs, unsupported platforms, secret-like literals.

---

## 7. Path rules

- Machine targets use portable `~/...` (expanded to `$HOME` at plan time).
  The current username is never hard-coded; capture converts `$HOME`-prefixed
  paths to `~/...` by prefix replacement.
- Bundle sources are always relative (`files/...`, `env/...`).
- `..`, NUL bytes, and (for file targets) shell metacharacters are rejected.
- Source payload paths and target machine paths are kept separate by
  construction.

---

## 8. Determinism

Capture sorts projects, files, packages, variables, secrets, and warnings.
Filesystem traversal order never leaks into output. Two captures of an
unchanged environment produce semantically identical bundles (modulo the
informational `metadata.captured_at` timestamp, which is excluded from
reproducibility comparisons).

---

## 9. Known limitations (P2)

- Service capture is empty (P1 has no service probing yet).
- Global environment literals are not captured (project schemas only).
- Project-local config files are recorded as metadata (basenames); only home
  dotfiles have payloads copied (source repos are never copied).
- `x-*` extension keys are rejected (deferred to P3+).
- Package capture covers native system managers (`apt` via `dpkg-query`,
  `dnf` via `rpm -qa`, `pacman` via `pacman -Q`, `apk` via `apk info -v`); other
  managers yield `unsupported` (not an error).
