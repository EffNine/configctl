# DEFERRED_FEATURES.md — Explicitly deferred scope

Status: **Current (v1.0.0-rc.1).** Deferred items remain out of scope; see also LIMITATIONS.md.

This list is normative: features here are **not implemented in v0.1** and must
not be partially implemented, half-wired, or hinted at in output. Deferring
without promising is the point. New ideas go here first.

Deferral states: **Post-v1.0** (planned direction), **Unscheduled** (no
commitment), **Rejected** (will not be built as described).

---

## 1. Platforms and init systems

| Feature | State | Rationale |
|---|---|---|
| macOS support | Post-v1.0 | Different package/secret/init model; needs its own provider work |
| Windows support | Unscheduled | No plan; POSIX assumptions are deep |
| Arch / Fedora / Alpine package managers (`pacman`, `dnf`, `apk`) | Post-v1.0 | Provider boundary exists; implementation is real work |
| Homebrew on Linux (`brew`) | Unscheduled | Overlaps user-space package managers; unclear value |
| Nix / NixOS integration | Unscheduled | Different philosophy; would require a fundamentally different provider |
| Non-systemd init (OpenRC, runit, sysvinit) | Unscheduled | Service provider would be a separate backend |
| ARM64 and other architectures | Post-v1.0 | Should mostly work through providers, untested |
| WSL-specific behavior | Unscheduled | Not a target platform in this plan |

## 2. Execution targets and reproduction

| Feature | State | Rationale |
|---|---|---|
| `configctl reproduce` to local machine | v0.1 (already planned as plan/apply) | Local only |
| Container target (Docker/Podman) | Post-v1.0 | Requires target adapter boundary; designed but not built |
| VM target | Unscheduled | Heavy, provider-specific |
| Remote Linux host | Unscheduled | Introduces network, auth, and trust model — explicitly out of v0.1 |
| Cloud environments / sandboxes | Unscheduled | Violates local-first v0.1 scope |
| `profile → target adapter` abstraction beyond local | Post-v1.0 | Interface reserved; no premature abstraction in v0.1 |

## 3. Secrets

| Feature | State | Rationale |
|---|---|---|
| Additional backends: `pass`, 1Password, Bitwarden | Post-v1.0 | SecretProvider boundary exists; each is a separate adapter |
| Encrypted local vault (e.g. age-based) | Post-v1.0 | Not custom crypto; needs a real design review |
| Custom encryption / password manager | Rejected | Explicit non-goal |
| Runtime secret injection (`export: runtime`, `persist: false`) | Post-v1.0 | Needs target adapters and trust model |
| Materializing secret values into `.env` files | Post-v1.0 | Explicitly avoided in v0.1 (highest-risk behavior) |
| Secret rotation, expiry, TTL | Unscheduled | Requires backend support matrix |
| Hardware tokens / FIDO / smartcards | Unscheduled | Backend concern |
| Secure secret sharing between machines | Rejected | Would require a hosted service or network protocol — out of scope |
| Automatic secret deletion of originals after import | Rejected (v0.1) / Post-v1.0 | Originals are never deleted or rewritten in v0.1 |
| Secret values in `--json` output under a flag | Rejected | Contradicts the redaction-by-construction design |

## 4. Packages and privileges

| Feature | State | Rationale |
|---|---|---|
| Package version pinning enforcement | Post-v1.0 | `packages.lock` records and reports only in v0.1 |
| Package downgrade / rollback | Rejected for v1.0 | Not reliable with apt; misleading to promise |
| Automatic `sudo` password prompting | Rejected for v0.1 | Uses `sudo -n` only; interactive elevation is a user decision |
| System-level systemd units | Post-v1.0 | Requires root/PolicyKit design |
| Snap / Flatpak / AppImage management | Unscheduled | Each is a separate provider |
| Language-level package managers (npm/pip/cargo global) | Unscheduled | Unbounded surface; project-local concerns are handled via project detection only |
| Dependency graph solving between packages | Rejected | Not a package manager |

## 5. Files, profiles, templates

| Feature | State | Rationale |
|---|---|---|
| Templating engine (Handlebars, Jinja-like) | Post-v1.0 | Adds an execution surface inside profiles; needs a security design |
| Conditional/dynamic sections in profiles | Post-v1.0 | Same as above |
| Replacing `.env` files with references automatically | Post-v1.0 | Explicit user confirmation + recoverable backup required first |
| Profile inheritance / composition | Post-v1.0 | Needs schema thought; not required for v1.0 |
| Profile registry / marketplace / sharing service | Rejected | Hosted service; contradicts local-first |
| Encrypted backups in the state store | Post-v1.0 | Plaintext `0600`/`0700` documented in v0.1 |
| Multi-user / shared machine support | Unscheduled | Per-user model in v0.1 |
| Managing files outside `$HOME` | Post-v1.0 | Privilege and containment design needed |

## 6. Interfaces and integrations

| Feature | State | Rationale |
|---|---|---|
| GUI / TUI / web dashboard | Rejected for v1.0 | CLI only |
| AI / LLM features of any kind | Rejected | Explicit non-goal |
| Telemetry / analytics | Rejected | Explicit non-goal |
| User accounts / hosted configctl service | Rejected | Explicit non-goal |
| Cloud secret managers (Vault, AWS SM, …) | Post-v1.0 | Backend adapters only, if ever |
| Editor/IDE plugins | Unscheduled | Out of scope |
| Shell prompt integration / watch mode | Unscheduled | Out of scope |
| Scheduled/daemonized verification | Rejected for v1.0 | configctl is request-driven; no daemon |
| Dynamic plugin loading (`.so`/WASM) | Rejected | New security surface; add providers as crates instead |
| Import from Ansible / Homebrew Bundle / Nix expressions | Post-v1.0 | Conversion tooling, not core |
| Export to other formats | Unscheduled | Out of scope |
| Remote multi-machine sync | Rejected | Network + trust model out of scope |

## 7. Environment semantics

| Feature | State | Rationale |
|---|---|---|
| Simulating framework-specific `.env` precedence | Rejected | configctl reports precedence; the application framework defines it |
| Running project tooling (build scripts, migrations) | Rejected | Not a task runner |
| Validating values against `pattern` regex in env schemas | Post-v1.0 | Regex engine/safety design needed; reserved field rejected in v1 |
| Detecting "inconsistent tool versions" beyond reporting | Post-v1.0 | v0.1 reports observations only |

---

## 8. Ground rules for this list

1. A deferred feature must not appear in `--help` output, JSON schemas, or
   docs as if it existed.
2. Reserving a field or a key (`owner`, `pattern`) means **rejecting it with a
   clear "not supported in schema v1" error**, never silently ignoring it.
3. Moving an item out of this list requires: an agreed milestone, threat-model
   delta, test plan, and explicit authorization.
4. Adding an item is free; removing one is a scope decision, not a code change.
