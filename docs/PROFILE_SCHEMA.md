# PROFILE_SCHEMA.md — Profile format v1 (draft)

Status: **P0 draft. No implementation exists yet. Format is not frozen.**

This document defines the profile bundle format that `configctl capture`
produces and `configctl plan/apply/verify` consumes.

Format: **TOML v1.0** (see ARCHITECTURE.md D2). Every file declares
`schema_version`. Unknown top-level keys are rejected. Unknown keys inside
known tables are rejected unless prefixed with `x-` (extension namespace).

> Rationale for TOML over YAML: maintained Rust tooling, unambiguous parsing,
> no anchor/alias deserialization pitfalls, and no indentation-sensitive
> semantics for a file that is validated by a security-sensitive tool.

---

## 1. Bundle layout

```
profiles/work/
├── profile.toml            # manifest: packages, files, environment, services, projects
├── packages.lock.toml      # optional resolved package versions (P4+)
├── secrets.manifest.toml   # secret references only — never values
├── env/                    # per-project env schemas
│   └── conductor.toml
└── files/                  # managed file payloads (dotfiles)
    ├── gitconfig
    └── nvim/
        └── init.lua
```

Rules:

- `profile.toml` is the only required file.
- All `source = ...` paths in `files/` are **relative to the profile directory**
  and must resolve inside it (no `..`, no absolute paths, no symlinks escaping
  the bundle).
- The whole bundle must be safe to commit to a public repository. Secret values
  are forbidden by validation, not merely discouraged.
- File payloads are byte-exact; `configctl` does not template them in v0.1.

---

## 2. `profile.toml` — full schema

```toml
schema_version = 1              # required, integer, must equal 1 for this spec
name = "work"                   # required, [a-z0-9][a-z0-9-_]{0,63}
description = "Work laptop baseline"
configctl_version = "0.1.0"     # optional, informational (producer version)

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
[packages]
apt = [
  "git",
  "curl",
  "ripgrep",
  "jq",
  "tmux",
  "neovim",
]

# ---------------------------------------------------------------------------
# Managed files and directories
# Each key is the absolute target path ("~/" is expanded to $HOME at plan time).
# Values are tables with a required `source`.
# ---------------------------------------------------------------------------
[files."~/.gitconfig"]
source = "files/gitconfig"

[files."~/.config/nvim"]
source = "files/nvim"
mode = "0755"                   # optional; default preserved/dir 0755, file 0644

# ---------------------------------------------------------------------------
# Environment variables (non-secret literals, or secret references)
# Values are either a string (literal) or a table with `secret`.
# Literal values that trip secret detection are a validation error.
# ---------------------------------------------------------------------------
[environment]
EDITOR = "nvim"
LANG = "en_US.UTF-8"
DATABASE_URL = { secret = "secret://work/dev/DATABASE_URL", required = true }

# ---------------------------------------------------------------------------
# systemd --user services (user units only in v1.0)
# ---------------------------------------------------------------------------
[services.docker]
enabled = true
running = true                  # optional; default: leave running state alone

# ---------------------------------------------------------------------------
# Projects associated with this profile
# ---------------------------------------------------------------------------
[[projects]]
path = "~/projects/conductor"
env_schema = "env/conductor.toml"
env_files = [".env", ".env.local", ".env.test"]   # optional; default: all discovered
```

### 2.1 Top-level fields

| Field | Type | Required | Rules |
|---|---|---|---|
| `schema_version` | integer | yes | Must be exactly `1` for this spec. Newer values are refused with a clear error, never guessed. |
| `name` | string | yes | Pattern `[a-z0-9][a-z0-9-_]{0,63}`. Must match the directory name when loaded by name. |
| `description` | string | no | Free text, ≤ 512 chars. |
| `configctl_version` | string | no | Informational; ignored for semantics. |
| `packages` | table | no | See §2.2. |
| `files` | table | no | See §2.3. |
| `environment` | table | no | See §2.4. |
| `services` | table | no | See §2.5. |
| `projects` | array of tables | no | See §2.6. |

### 2.2 `[packages]`

| Key | Type | Rules |
|---|---|---|
| `apt` | array of strings | Package names matching `[a-z0-9][a-z0-9+.-]*`. Duplicates rejected. Shell metacharacters rejected. Versions are not specified here; see `packages.lock.toml`. |

Unknown package-manager keys (`dnf`, `pacman`, …) are rejected in schema v1 —
they are deferred features, and accepting-and-ignoring them would be dishonest.

### 2.3 `[files]`

| Field | Type | Required | Rules |
|---|---|---|---|
| `source` | string | yes | Relative path inside the bundle; must exist and stay inside the bundle. |
| `mode` | string | no | Octal string (`"0644"`). Applied on create; on modification the existing mode is preserved unless specified. |
| `owner` | string | no | **Reserved, rejected in v1** (would require privilege). |
| `backup` | boolean | no | Default `true`. `false` requires explicit user confirmation at plan time and is marked high risk. |

Target path rules:

- Must start with `~/` (expanded to the user's home) — absolute paths outside
  `$HOME` are rejected in v1.
- Must not contain `..` components or NUL bytes.
- Must not be a symlink at apply time (conflict with clear error).
- Duplicate targets across the profile are rejected.

### 2.4 `[environment]`

Two value forms:

```toml
[environment]
EDITOR = "nvim"                                        # literal, non-secret
DATABASE_URL = { secret = "secret://work/dev/DATABASE_URL" }
LOG_LEVEL = "debug"
```

| Field | Type | Required | Rules |
|---|---|---|---|
| `secret` | string | one of | Must parse as `secret://<namespace>/<path>`. |
| `required` | boolean | no | Default `true`. `false` allows a missing secret in non-strict verification. |

Rules:

- A variable is either a literal string or a `{ secret = ... }` table. Mixed
  forms per key are rejected.
- Literal values matching high-confidence secret patterns are a **validation
  error** (not a warning): `error: environment.LOGIN_TOKEN looks like a secret;
  use `secret = "secret://…"` instead`.
- Variable names must match `[A-Za-z_][A-Za-z0-9_]*`.
- Applying a `secret://` environment entry in v0.1 means: verify the reference
  exists in the secret backend and record ownership of the reference. It does
  **not** write or export the value anywhere (see ARCHITECTURE.md §10, D11).

### 2.5 `[services.<unit>]`

| Field | Type | Required | Rules |
|---|---|---|---|
| `enabled` | boolean | no | Enable/disable at boot for `systemd --user`. |
| `running` | boolean | no | Start/stop now; omitted means "do not manage running state". |

- Unit names must match `[A-Za-z0-9:_.@-]+\.service` (v1 restricts to
  `.service` units for `--user` manager).
- Service targets outside the user manager (`systemctl` system scope, other
  unit types, `--user` template instances beyond a literal name) are rejected
  in v1.

### 2.6 `[[projects]]`

| Field | Type | Required | Rules |
|---|---|---|---|
| `path` | string | yes | `~/...` path; must exist at verify time or report `MISSING`. |
| `env_schema` | string | no | Relative path to a schema file in `env/`. |
| `env_files` | array of strings | no | Explicit file list. Default: discovered `.env*` files per §4. |

---

## 3. `secrets.manifest.toml`

Captures *which* secrets a profile depends on, never values. Generated by
`configctl capture`; editable by hand; validated by `plan`/`verify`.

```toml
schema_version = 1

[[secrets]]
project = "conductor"
ref = "secret://work/dev/conductor/AGNES_API_KEY"
required = true
description = "Agnes API key"

[[secrets]]
project = "conductor"
ref = "secret://work/dev/conductor/JEV_API_KEY"
required = true

[[secrets]]
project = "atlas"
ref = "secret://work/dev/atlas/HF_TOKEN"
required = false
```

Rules:

- `ref` must parse as a `secret://` URI; values are rejected.
- A `[[secrets]]` entry with a value-looking literal (anything that is not a
  `secret://` URI) is a hard validation error.
- Verification checks existence only (SecretProvider `exists`), never reads
  values.
- Duplicate `ref`s are rejected.

---

## 4. Project env schema (`env/<project>.toml`)

Optional but recommended. Describes expected variables for validation. It
records expectations, not semantics: configctl does not claim to know how a
framework loads `.env` files.

```toml
schema_version = 1

[project]
name = "conductor"

[variables.DATABASE_URL]
type = "string"
secret = true
required = true

[variables.PORT]
type = "integer"
required = false
default = 3000

[variables.NODE_ENV]
type = "enum"
values = ["development", "test", "production"]

[variables.DEBUG]
type = "boolean"
default = false
```

### 4.1 Variable fields

| Field | Type | Required | Rules |
|---|---|---|---|
| `type` | string | yes | One of `string`, `integer`, `boolean`, `enum`. |
| `secret` | boolean | no | Default `false`. `true` means values are expected to be secret-classified; a **literal** value in a discovered file is reported, and the key must be present in `secrets.manifest.toml` when `required = true`. |
| `required` | boolean | no | Default `false` for schema entries; missing required variables produce `MISSING`. |
| `default` | depends on `type` | no | Must type-check against `type`. |
| `values` | array of strings | for `enum` | Non-empty, unique. |
| `description` | string | no | Free text, ≤ 512 chars. |
| `pattern` | string | no | **Reserved, rejected in v1** (regex engine and safety not yet designed). |

### 4.2 Validation behavior (`configctl env verify`)

| Finding | Severity |
|---|---|
| Required variable absent from all env files | error (`MISSING`) |
| Variable present with wrong type | error (`DRIFT`) |
| Enum value outside `values` | error (`DRIFT`) |
| Required `secret = true` variable with no `secrets.manifest.toml` entry | error |
| Variable in files but not in schema | warning (`UNMANAGED`) |
| Schema variable absent from `.env.example` while present elsewhere | info |
| Key present in some layers but not others | info (reported, never rewritten) |

`.env` file discovery defaults (per project root): `.env`, `.env.local`,
`.env.development`, `.env.test`, `.env.production`, `.env.example`,
`.env.sample`. Each discovered file records a **layer** (`base`, `local`,
`development`, `test`, `production`, `example`) as metadata only. Precedence is
*reported*, never simulated: the application's framework decides semantics.

---

## 5. `packages.lock.toml` (defined now, emitted at P4+)

```toml
schema_version = 1

[apt]
git = "1:2.43.0-1ubuntu7.2"
ripgrep = "14.1.0-1"
```

- Records the exact version observed at capture/apply time.
- v0.1 semantics: **record and report**; version pinning/downgrade enforcement
  is deferred. `verify` reports version drift when a lock entry exists.

---

## 6. Schema versioning and migration

- `schema_version` is mandatory in every profile file.
- Loading a file whose version is **greater** than the tool supports is a hard
  error: `unsupported profile schema_version 2 (this build supports 1)`.
- Migrations are explicit, one-way, and non-destructive:
  `configctl profile migrate <name> --to <version>` writes a new bundle and
  keeps a copy of the original. No silent in-place interpretation.
- Extension keys (`x-*`) are allowed only at top level and inside known tables;
  they are preserved on read and never interpreted.

---

## 7. Security invariants (enforced by validation)

1. No secret values — only `secret://` references (in `environment`,
   `secrets.manifest.toml`, and env schemas' `secret = true` metadata).
2. No absolute `files.*.source` paths; sources must be contained in the bundle.
3. No `..` traversal in any path; no NUL bytes; no shell metacharacters in
   package or unit names.
4. Every target path is under `$HOME`.
5. Literal environment values that match high-confidence secret patterns are
   rejected.
6. Reject-and-explain on any unknown key (except `x-*`), any unsupported type,
   and any unsupported schema version. A malicious or malformed profile fails
   before planning, never mid-apply.

---

## 8. Worked example

`profiles/work/profile.toml`

```toml
schema_version = 1
name = "work"
description = "Work laptop base environment"

[packages]
apt = ["git", "curl", "ripgrep", "jq", "tmux", "neovim"]

[files."~/.gitconfig"]
source = "files/gitconfig"

[files."~/.config/nvim"]
source = "files/nvim"

[environment]
EDITOR = "nvim"
LANG = "en_US.UTF-8"
GITHUB_TOKEN = { secret = "secret://work/dev/github/GITHUB_TOKEN" }

[services.docker]
enabled = true
running = true

[[projects]]
path = "~/projects/conductor"
env_schema = "env/conductor.toml"
```

`profiles/work/env/conductor.toml`

```toml
schema_version = 1

[project]
name = "conductor"

[variables.PORT]
type = "integer"
default = 3000

[variables.AGNES_API_KEY]
type = "string"
secret = true
required = true
```

`profiles/work/secrets.manifest.toml`

```toml
schema_version = 1

[[secrets]]
project = "conductor"
ref = "secret://work/dev/conductor/AGNES_API_KEY"
required = true

[[secrets]]
project = "github"
ref = "secret://work/dev/github/GITHUB_TOKEN"
required = true
```

Nothing in this bundle can leak a secret by construction, because values cannot
be represented.
