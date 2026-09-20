# CAPTURE.md — P2 declarative profile capture (implemented)

Status: **Implemented in P2.** `configctl capture` transforms observed local
environment state into a declarative, portable profile bundle. It is
**non-mutating** w.r.t. the source environment: it reads the machine and
writes exactly one new artifact (the output bundle), and nothing else.

```text
P1:  Machine → DISCOVER → Observed State
P2:  Observed State → CAPTURE → Declarative Profile
```

Pipeline:

```text
READ MACHINE (P1 scan + package/git probes)
→ SELECT MANAGED STATE (allowlist policies)
→ REDACT SECRET MATERIAL (metadata only)
→ GENERATE PROFILE (typed model)
→ VALIDATE PROFILE (fail-closed)
→ WRITE PROFILE (atomic, inside --output only)
```

---

## 1. What capture means

Capture answers: *"what would I need to reproduce this machine's development
setup elsewhere?"* The output is desired reproducible state — not an exact
dump. Base-OS packages, caches, build outputs, and secret values are
deliberately left out (see §3).

Capture consumes P1 discovery results (it never re-implements discovery) plus
two narrow live probes: installed packages (`dpkg-query`) and global Git
config (`git config --global --list`). Both go through `CommandRunner` with
fixed argv — never a shell.

---

## 2. What gets captured

| Area | Source | Output |
|---|---|---|
| Packages | `dpkg-query -W` intersected with the tooling allowlist | `[packages].apt` + `packages.lock.toml` |
| Home dotfiles | `$HOME` allowlist (`HOME_ALLOWLIST`) passing all safety checks | `[[files]]` + `files/home/*` payloads |
| Project metadata | P1 `projects` + env/config associations | `[[projects]]` (portable paths, ecosystems, env/config basenames) |
| Environment schemas | P1 `env_files` + re-parsed in-memory values (never persisted) | `env/<project>.toml` |
| Secrets | P1 classifications (`secret`/`likely_secret`) | `secrets.manifest.toml` (refs only) |
| Git metadata | `git config --global --list` allowlist | `[git]` (names, emails, helper metadata, aliases) |
| Platform | P1 system info | `[platform]` |

---

## 3. What is excluded (never silently)

Capture distinguishes `captured / excluded / redacted / unsupported / unknown`
and prints the breakdown in every summary:

- **Excluded by policy**: non-tooling OS packages (hundreds of base-system
  packages are not reproducible intent); project-local files are metadata-only
  (repos are never copied); oversized files; files outside approved roots.
- **Redacted**: every `secret`/`likely_secret` variable (values never stored);
  secret-bearing file payloads (the whole file is excluded, never copied).
- **Unsupported**: symlinks (P0 requires rejection), non-regular files,
  unavailable package manager, unknown service state.
- **Unknown**: unreadable paths, missing `git`/`dpkg-query`.

The package summary always reports `N installed observed, M selected by
tooling-allowlist-v1, K excluded`, so the set is never pretended complete.
Walker deny-list counts (build artifacts, caches, symlinks) are surfaced too.

### Package selection policy: `tooling-allowlist-v1`

Only installed packages on the explicit `TOOLING_ALLOWLIST` (git, curl, jq,
ripgrep, tmux, neovim, build-essential, python3, nodejs, …) are captured.
Rationale: a profile with every OS package is enormous and non-portable.
The list is extensible by appending to one constant; the policy id is
recorded in profile metadata.

### File selection policy

- Home payloads: exactly the `HOME_ALLOWLIST` names (`.gitconfig`,
  `.gitignore`, `.editorconfig`, `.tool-versions`, `.nvmrc`, `.node-version`,
  `.python-version`, `.rust-toolchain[.toml]`). Each must additionally pass
  symlink/type/size/root/secret checks.
- Project-local files: only P1-registry names are considered, and they are
  recorded as metadata (basenames in `[[projects]]`), never copied as
  payloads. Build outputs (`.git/objects`, `node_modules/`, `target/`,
  `dist/`, `build/`, `.cache/`) are never captured (the P1 walker already
  excludes them).

---

## 4. Secret handling

Capture **never** places secret values into `profile.toml`,
`secrets.manifest.toml`, `env/*.toml`, `files/*`, logs, errors, stdout,
stderr, or JSON output. Verified by:

1. **Type discipline**: the profile model has no value-bearing field.
2. **Registry redaction**: every discovered value is registered and replaced
   with `<redacted>` before any sink.
3. **Post-write leak check**: after writing, every bundle file is scanned for
   every registered value; any hit aborts capture as failed (fail-closed).

`.env` families contribute names + classifications only. `.env.example` /
`.env.sample` additionally mark variables `required = true` (they are the
project's declared public schema). Git credential contents, `http.*`, and
`url.*` keys are never captured (only `credential.helper` metadata is kept).

---

## 5. Environment schema generation

Per project with env files, one `env/<project>.toml` is generated (safe
defaults `string / secret=false / required=false` unless stronger evidence):

- `secret = true` on name-lexicon or observed classification evidence;
- `required = true` for variables present in example files;
- `type` inferred conservatively from in-memory values only (integer /
  boolean / NODE_ENV-enum), else `string`.

Values are held only for the inference step and never serialized.

---

## 6. File safety

Before any byte is copied: symlink rejection via `symlink_metadata`,
approved-root containment (`scan roots + $HOME`, canonicalized parents),
regular-file check, size cap (256 KiB), permission recording (`"0600"`-style
octal strings), secret-content screening (PEM markers, token prefixes,
`password|secret` assignments). Copies use atomic writes (temp file in the
target dir + `fsync` + rename). Bundle writes refuse paths outside `--output`
and refuse non-empty directories without `--force`.

---

## 7. CLI

```console
$ configctl capture --output ./my-profile
$ configctl capture my-name --from ~/projects --output ./my-profile
$ configctl capture --output ./my-profile --json
$ configctl capture --output ./my-profile --verbose
$ configctl capture --output ./my-profile --dry-run
$ configctl capture --output ./my-profile --force
```

- `--output` / `--out`: destination bundle dir (default `./configctl-profile`).
- `--from` / `--root`: scan roots (default: P1 scan defaults, else cwd).
- `--dry-run`: discovery + analysis + validation, no writes.
- `--json`: one P0-envelope JSON document on stdout (redacted).
- `--verbose`: per-file written list + warnings.
- `--force`: allow writing into a non-empty directory.
- Positional `NAME`: profile name (default: output basename, else `captured`).

Only the output directory is created/modified. Exit `0` on success, `2` on
usage/validation errors (with all validation errors listed, redacted).

Example summary:

```text
Capture summary

Profile:        my-linux-dev
Projects:       2
Files:          2
Packages:       7
Env schemas:    2
Secrets:        4

Excluded:
  packages: 941 installed observed, 7 selected by tooling-allowlist-v1, 934 excluded

Redacted:
  4 secret variables (values never stored)

Wrote ./my-profile
  profile.toml
  secrets.manifest.toml
  env/project-a.toml
  files/home/gitconfig
```

---

## 8. Determinism

All collections are sorted before serialization; traversal order never leaks
into output. Two captures of an unchanged environment are semantically
identical (compare with `captured_at` ignored — it is informational
metadata, not reproducible content).

---

## 9. Known limitations

- No `plan` / `apply` / `rollback` / mutation of any kind (later milestones).
- No Secret Service writes; no remote/sandbox/container/VM execution; no AI.
- Services and global env literals are empty in P2 (no P1 service probing).
- Non-apt platforms: packages `unsupported`, not an error.
- Secret detection is heuristic; a clean bundle is not proof of secret safety
  (see `docs/THREAT_MODEL.md`).
- Profiles with `schema_version != 1`, `x-*` extensions, or non-`linux`
  platforms are rejected (deferred features fail closed).
