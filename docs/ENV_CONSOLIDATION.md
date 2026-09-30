# ENV_CONSOLIDATION.md — user-driven environment consolidation

Status: **Phases E1, E2, and E4 implemented (v1.2).** `configctl env explain`
(mode 1, read-only), `configctl env consolidate` — which persists a journaled
plan writing the canonical `~/.config/configctl/env.sh` plus one marker include
block per participating rc file, applied through the normal `apply` and undone
by `rollback` — and `configctl onboard` (guided read-only first run that writes
only the profile bundle) are implemented. Mode 3 (`--mode move`, phase E5) is
not implemented: promoting it to an automatic path requires its own threat
review, per §7. Current behavior otherwise: `capture` records non-secret
environment literals in the profile, and `apply` writes them to
`~/.config/environment.d/90-configctl.conf` (see `APPLY.md`). This document
specifies how configctl can additionally find environment declarations
scattered across shell startup files, explain them in plain language, and —
only with explicit approval — consolidate them into one managed file that every
shell reads.

Audience: §1 is written for people who have never thought about `~/.bashrc`.
Everything after it is an engineering specification.

---

## 1. For beginners (plain language)

### 1.1 What is an environment variable?

An environment variable is a named setting that programs read when they start.
Examples:

- `EDITOR=nano` — "when a program needs a text editor, use nano"
- `PATH=/usr/bin:/usr/local/bin` — "look for programs in these folders"
- `LANG=en_US.UTF-8` — "my language and character set"

You can see all of yours by running `printenv` in a terminal. You can set one
for the current terminal with `export EDITOR=nano`, but it disappears when the
terminal closes. To make it permanent, it has to be written into a **startup
file** that your shell reads every time it starts.

### 1.2 Where do they hide?

| File | Read when | Typical contents |
|---|---|---|
| `~/.bashrc` | Every interactive Bash shell | aliases, `export`s added by tutorials |
| `~/.profile` | Login sessions (desktop login, SSH) | `PATH` additions |
| `~/.bash_profile` | Login Bash (if it exists, `.profile` is often skipped) | `PATH`, environment |
| `~/.zshrc` / `~/.zshenv` | Zsh shells | everything Zsh |
| `~/.config/environment.d/*.conf` | systemd user session (desktop apps, user services) | graphical session variables |
| `~/.xprofile` | Some X11 desktop sessions | legacy session variables |
| `/etc/environment` | System-wide, all users | admin-managed (not yours to edit) |

Two consequences beginners hit constantly:

1. The same variable is set in three different files, and the value you get
   depends on which file was read last.
2. A variable set in a config tool's file (for example
   `environment.d/90-configctl.conf`) may **not** appear in a plain terminal
   window, because terminals don't all read that file.

That mismatch — "I set it, but my terminal doesn't see it" — is the core
problem this feature solves.

### 1.3 What configctl will do about it

1. **Look** at every startup file and list what it finds, in plain language.
2. **Explain** where each value lives and which value would win today.
3. **Propose** one tidy managed file, `~/.config/configctl/env.sh`, containing
   the values you choose to consolidate.
4. **Ask before changing anything.** It adds one clearly marked block to each
   shell file so the managed file is read. Nothing else is edited.
5. **Keep backups and let you undo.** `configctl rollback` restores every file
   it touched.

### 1.4 Safety promises

- Your startup files are never rewritten silently; every change is planned,
  shown, approved, journaled, and backed up.
- Anything conditional or complicated (`if`, `$PATH`, command substitution) is
  reported, **not touched**.
- The managed file contains no secrets — secret values stay in the secret
  store as references, exactly as they do today.
- "Remove the old lines" (mode 3) is a *guided manual step*, not something
  configctl does behind your back. See §5.

### 1.5 Glossary

- **Shell** — the program that reads your typed commands (Bash, Zsh, …).
- **rc file** — a startup file read by a shell ("run commands").
- **source** — to execute another file's contents inside the current shell.
- **export** — mark a variable so child programs can see it.
- **PATH** — the list of folders the shell searches for commands.
- **undo** — in configctl, `rollback --plan <id>` (a future `configctl undo`
  alias, §7).

---

## 2. Goals and non-goals

**Goals**

1. Make every environment declaration on the machine discoverable and
   explainable (mode 1), safely consolidatable into one managed file
   (mode 2), and — later — removable from its original location (mode 3).
2. Never change shell semantics silently: if the effective value could change,
   say so or refuse.
3. Keep the beginner path one command long (`configctl onboard`) and the
   intermediate path scriptable (`--json`, stable exit codes).
4. Reuse existing guarantees: plan → hash-bound approval → journal → backup →
   rollback → verify.

**Non-goals (v1.2)**

- Parsing arbitrary shell (no evaluator, no `sh -c`, no expression expansion).
- Managing `PATH` automatically (see §6.4).
- System-wide files (`/etc/environment`, `/etc/profile.d/*`) — observe only.
- Secrets in the canonical file — never.
- Editing shell files with anything other than the marked include block in
  mode 2.

---

## 3. Model

### 3.1 Sources and declarations

A **source** is a file that a shell may read. A **declaration** is one
`NAME=VALUE` assignment found in a source. The model records, per
declaration: source path, line number, name, value (redacted when
secret-like), line classification, and the shell family the source belongs to.

New profile-adjacent artifact (read-only discovery output, not persisted
state): `EnvSourceMap`, produced by `configctl env explain`.

### 3.2 Managed artifacts

| Artifact | Path | Purpose | Mode |
|---|---|---|---|
| Canonical shell env | `~/.config/configctl/env.sh` | values for interactive/login shells | 2 |
| systemd user env | `~/.config/environment.d/90-configctl.conf` | session/services values (existing behavior) | already shipped |
| Include block | marker-delimited block in each participating rc file | makes shells read the canonical file | 2 |

Both env artifacts are generated from the same profile `[environment]` data,
so there is exactly one source of truth. `apply` keeps them in sync; `verify`
checks both.

### 3.3 Include block format

```sh
# >>> configctl env >>>
# Managed by configctl. Edit values with `configctl env consolidate`; this
# block itself is replaced on apply, not appended.
if [ -f "$HOME/.config/configctl/env.sh" ]; then
    . "$HOME/.config/configctl/env.sh"
fi
# <<< configctl env <<<
```

Rules: exactly one block per file; idempotent (content-equal = no-op);
inserted at the **end** of the file unless the user picks a position; if a
foreign block with the same markers exists, refuse (fail closed) rather than
guessing.

---

## 4. Mode 1 — observe and explain

### 4.1 Conservative parser

Only simple, single-line, top-level assignments are recognized:

```
^export\s+NAME=VALUE$          # POSIX/Bash/Zsh export
^NAME=VALUE$                   # plain assignment (Bash/Zsh)
```

Rejected (recorded as `manual` with a reason, never interpreted):

- lines inside `if`/`for`/`while`/`case`/function bodies (keyword depth > 0)
- line continuations (`\` at end of line)
- any `$`, backtick, `$(`, `${`, or history/glob expansion in VALUE
- `PATH`, `LD_LIBRARY_PATH`, `LD_PRELOAD`, `IFS`, `BASH_ENV`, `ENV`,
  `PROMPT_COMMAND`, `PS1` (behavior-defining; see §6.4)
- source/`.`/`eval`/`alias` lines (reported as structure, not declarations)
- values whose names or shapes trip secret detection → `secret`, value never
  stored (existing redaction layer)

Values are unquoted with a small, deterministic rule set (strip one layer of
matching `'` or `"`; no escape processing beyond `\"`/`\\`). Anything else →
`manual`.

### 4.2 Output (human, beginner-facing)

```
$ configctl env explain

Your shell settings live in 3 files.

  ~/.bashrc (read by every Bash terminal)
    line 42   export EDITOR=nano            overridden by line 57 (later line wins)
    line 57   export EDITOR=vim             currently wins
    line 71   export WORK_API=https://…     looks like a secret — managed by reference

  ~/.profile (read at login)
    line 12   export PATH="$PATH:$HOME/.local/bin"   left alone (PATH is special)

  ~/.config/environment.d/90-configctl.conf (read by desktop apps)
    EDITOR=vim

A plain terminal sees EDITOR=vim; a desktop app may see EDITOR=nano.
configctl can put EDITOR in one managed file (→ ~/.config/configctl/env.sh)
and add a small, marked block to ~/.bashrc so every terminal reads it.
Nothing has been changed. To see the exact changes: configctl env consolidate --dry-run
```

Exact precedence claims are computed by source read-order rules (§6), not
guessed; where order cannot be determined, say so.

### 4.3 Output (JSON)

One envelope, `command: "env explain"`, `data.sources[]`,
`data.declarations[]` (with `classification`, `reason`, `secret` bool,
never values when secret), `data.conflicts[]`, `data.precedence[]`.

---

## 5. Modes at a glance

| Mode | CLI | Engine work | Risk class |
|---|---|---|---|
| 1 observe/explain | `env explain` | parser + report | none (read-only) — **implemented** |
| 2 canonical + include | `env consolidate` | two op kinds, both backed up and rollback-supported | medium — **implemented** |
| 3 move/remove | `env consolidate --mode move` | **no new engine op**: emits an assisted manual patch + backup | high → deliberately manual — **not implemented (E5)** |

---

## 6. Mode 2 — canonical file + include line

### 6.1 Operations

| Kind | Target | Action class | Rollback | Notes |
|---|---|---|---|---|
| `EnvFileWrite` | `~/.config/configctl/env.sh` | `SAFE_REPRODUCE` | supported (backup + prior content) | managed file; full-content replace with hash guard |
| `IncludeLineAdd` | each participating rc file | `SAFE_REPRODUCE` | supported (remove block; restore prior content) | marker block; one per file; idempotent |
| `EnvFileRemove` | managed file | `MANUAL` | n/a | only when the last managed variable is removed; user deletes or approves a gated removal |

`IncludeLineAdd` is deliberately *not* class `DESTRUCTIVE`: it is additive,
marker-delimited, backed up, and fully reversible. It is still shown with
`risk: medium` because it changes shell startup.

### 6.2 Contributing shells

A file participates if it exists and matches a known shell family:
`~/.bashrc`, `~/.bash_profile`, `~/.profile` (bash/login sh), `~/.zshrc`
(zsh), `~/.zshenv` (zsh). `~/.xprofile` is offered but off by default.
System files never participate.

The user picks which files get the block; the default for beginners is
"every file that currently declares a variable you chose to consolidate".

### 6.3 Precedence policy

- The managed file is sourced by the include block, placed at the **end** of
  each rc file, so managed values win over earlier declarations in that file.
- If a consolidated variable is still declared elsewhere, plan output prints a
  shadowing report: "old line in `~/.bashrc:42` is now overridden by the
  managed value `vim`". No automatic removal (mode 3 handles that).
- If two *unmanaged* sources define the same variable with different values,
  `env explain` lists the conflict. `env consolidate` does not guess: the
  profile's `[environment]` value is the explicit choice, and every site that
  still declares the variable is reported as a non-blocking
  `shadowed_declaration` plan warning naming the file and line.

### 6.4 PATH and other special variables

`PATH` is never consolidated in v1.2. It is order-sensitive, often assembled
conditionally, and a mistake bricks the user's terminals. `env explain` shows
PATH lines and says why they are left alone. A future mode may manage PATH
*additions* (prepend/append whole directories) as a separate, explicitly
designed feature.

### 6.5 Secrets

Variables classified `secret` are never written to `env.sh` or
`environment.d`. They remain `secret://` references in the profile;
`env explain` shows only the name, source, and that a secret is involved. The
canonical file is treated as world-readable content (even when `0600`) and is
screened with the same secret detector before write; a trip is a hard error.

---

## 7. Mode 3 — move/remove (assisted manual)

Purpose: remove the now-shadowed original lines so the environment stops being
ambiguous. This is the only mode that can change semantics, so it is **not an
automatic apply path** in v1.2.

Flow:

1. `configctl env consolidate --mode move --dry-run` prints a per-line patch:
   which lines would be commented out or deleted, and why it is safe.
2. With `--emit-patch <file>` it writes a unified diff plus a timestamped
   backup of every file involved (content-addressed, same backup store as
   apply).
3. The user applies it manually (`patch -p0 < file`) or with an explicit
   `--paste` confirm in the TUI/CLI; `configctl rollback` cannot restore an
   out-of-band patch, so the tool prints the exact restore command.

Hard exclusions (never eligible for removal): PATH/special variables,
conditional or nested lines, any line whose evaluation the parser could not
fully prove, the include block itself, and anything not byte-for-byte
reproduced in the canonical file.

If, after a release of field data, mode 3 proves safe, it can be promoted to
a journaled `SAFE_REPRODUCE` op pair (`RcLineCommentOut` +
`RcLineRestore`). That decision requires its own threat review — deliberately
not now.

---

## 8. Beginner onboarding (`configctl onboard`)

One guided command that composes existing read-only steps:

```
$ configctl onboard

Step 1/4  Looking around…        (scan: read-only)
Step 2/4  Understanding         (env explain + capture summary)
Step 3/4  Proposals
  We found 14 settings in 3 files. 9 can be managed; 5 are special or secret.
  Manage EDITOR, LANG, RIPGREP_CONFIG_PATH … ? [y/N/choose]
Step 4/4  Your profile is ready: ~/.config/configctl/profiles/this-machine
          Review changes:  configctl plan this-machine
          Apply safely:    configctl apply --last
          Undo anytime:    configctl rollback --plan <id>
```

Design rules: every screen answers "what is this, what will change, how do I
undo"; no jargon without a one-line definition (§1.5 doubles as the string
table for the tool); default answer is always "do nothing"; `onboard` itself
is read-only apart from writing the profile bundle.

---

## 9. CLI surface (proposed)

| Command | Purpose |
|---|---|
| `configctl env explain [--json] [--home DIR]` | mode 1 report |
| `configctl env consolidate [--mode include\|move] [--dry-run] [--home DIR] [--json] [PROFILE]` | modes 2/3 |
| `configctl env verify [--system]` | extend existing verify: canonical file hash, include blocks present, shadowed declarations reported |
| `configctl onboard` | guided first run (§8) |
| `configctl status` | one-line summary across profile + env (`verify` rollup) |
| `configctl why <target\|VAR>` | state-store explanation: who owns it, when, last backup |
| `configctl undo` | alias for `rollback` with the last plan by default |
| `configctl apply --last` / `plan --apply` | plan-id handoff removal |

Exit codes follow the existing contract (CLI_SPEC §1.1). `env explain` is
exit 0 with empty data when nothing is found.

---

## 10. Verification semantics (implemented state)

- File-level (**implemented**): the canonical file content hash matches the
  profile, and include blocks are present and byte-identical in each planned
  rc file — enforced by plan `expected_before`/`desired_after` guards at apply
  time and by rollback's file-content identity guard.
- Value-level (**implemented**): canonical values equal the profile's
  `[environment]`; `verify` reports findings under the `envfile` provider when
  the canonical file exists, alongside the existing `env` (session artifact)
  provider.
- Shadowing (**implemented as reporting**): `env consolidate` emits one
  `shadowed_declaration` warning per still-declared site; automatic removal is
  mode 3 (not implemented).
- Session-level (**not claimed**): the tool does not claim to know what your
  current terminal sees. `env explain` computes the *expected* precedence from
  the documented file read order and says so explicitly.

---

## 11. Threat-model additions (proposed T-IDs)

| ID | Threat | Mitigation |
|---|---|---|
| T21 | Malicious/incorrect rc edit breaks login shell | additive marker block only; backup; rollback; no evaluator |
| T22 | Value sneaks a secret into the canonical file | existing detector at capture + hard error before write |
| T23 | Precedence claim causes wrong value to win | explicit shadowing report; managed block at end; conflicts refuse to auto-pick |
| T24 | TOCTOU on rc file between plan and apply | existing hash guard + stale-plan refusal; apply re-reads and verifies `expected_before` per operation before write |
| T25 | Symlinked rc target attacks | existing symlink refusal at managed targets applies unchanged |

---

## 12. Testing strategy

- Parser corpus: fixture rc files (bash/zsh, nested blocks, continuations,
  quotes, secrets, PATH) with golden `EnvSourceMap` snapshots.
- Idempotency: consolidate twice → second plan is empty.
- Rollback: remove/restore of include blocks and canonical file byte-exact.
- Canary: secret-shaped values never appear in any file or output.
- Precedence: table-driven tests computing expected winner per source order.
- Adversarial: hostile rc files (marker spoofing, partial blocks, CRLF,
  huge files, permission denied) must fail closed.
- E2E (CLI): temp HOME with messy fixtures → explain → consolidate → apply →
  verify → rollback.

---

## 13. Rollout phases (each independently shippable)

| Phase | Deliverable | Exit criteria |
|---|---|---|
| E1 ✅ | `env explain` (parser + human/JSON report) | delivered in v1.2: core `envmap` parser + 17 unit tests, `env explain` human/JSON, `env consolidate --dry-run` preview, e2e canary clean |
| E2 | `EnvFileWrite` + `IncludeLineAdd` ops, plan/apply/rollback/verify | delivered in v1.2: both kinds wired end to end (`SAFE_REPRODUCE`, backed up, rollback byte-exact), `expected_before` TOCTOU guards, canonical file + `environment.d` kept in sync from one profile, `verify` checks the canonical file (`envfile` provider); idempotency + stale-plan refusal + rollback tests green |
| E3 | `env consolidate` CLI + shadowing report | e2e on messy fixture home |
| E4 | `onboard` + `status` + `why` + `undo`/`--last` | delivered in v1.2: `onboard` (read-only + bundle only, refuses to overwrite), `status`/`why` shipped earlier, `apply --last`/`rollback --last` shipped earlier |
| E5 | mode 3 assisted manual (patch emission) + threat review | design sign-off; opt-in only |

E1–E2 are the core; E4 is where the beginner value lands. E5 ships only after
E1–E4 are in real use.

---

## 14. Open questions

1. Should `~/.profile` participate by default given `~/.bash_profile`
   shadowing rules? (Proposal: participate only if it is the file a login
   shell actually reads; detect via file presence.)
2. Canonical file name: `env.sh` vs `env` with a shebang-less POSIX subset.
   (Proposal: `env.sh`, POSIX-safe subset, no Bash-isms.)
3. Should `environment.d` and `env.sh` always be kept in sync, or should the
   user choose targets? (Proposal: sync both; `environment.d` remains for
   session/services, `env.sh` for shells.)
4. Move mode: comment-out ("tombstone") vs delete originals. (Proposal:
   tombstone by default; deletion only via the emitted patch.)
