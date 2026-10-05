# TUI.md — configctl interactive dashboard

Status: **Phase T1 implemented (v1.4): a read-only dashboard.** Mutating TUI
flows (T2+) are not implemented: they require their own threat review, exactly
like move mode's promotion rule (ENV_CONSOLIDATION.md §7).

Audience: §1 is plain language; everything after is an engineering spec.

---

## 1. For beginners (plain language)

The TUI is the same `configctl`, with a screen instead of scrolling text.

```console
$ configctl tui
```

You get five tabs (switch with `1`–`5` or `Tab`):

- **Overview** — one page: where your state lives, how many plans exist, what
  the newest one did, and (when you pass a profile) whether your machine
  matches it.
- **Verify** — the `verify` results for a profile, grouped by category, with
  the findings listed and explained.
- **Environment** — where your shell settings live and which value wins
  today (the same map `configctl env explain` prints).
- **Doctor** — platform, package managers, state health, interrupted applies.
- **Help** — every key, and the equivalent CLI command for each tab.

Nothing on any screen changes your machine. Every tab tells you the exact
CLI command that *would* make a change, so the TUI teaches the CLI rather
than hiding it. Press `q` to leave; your terminal is restored exactly as it
was.

---

## 2. Goals and non-goals

**Goals**

1. One command, one screen: make the read-only half of configctl (status,
   verify, env explain, doctor) glanceable without memorizing flags.
2. Teach the CLI: every tab names its equivalent command.
3. Zero new risk: T1 is strictly read-only — the same engines, the same
   redaction, no new privilege, no network, no file writes.
4. Terminal citizenship: alternate screen, restored on quit and on panic;
   refuse to run without a TTY (exit 2) instead of corrupting pipes.

**Non-goals (T1)**

- No mutations, no approval dialogs, no editors (T2+; threat review first).
- No mouse support, no theming/config file, no animations.
- No `--json` (the TUI is a human view; scripts keep using the CLI).
- No network, no telemetry, no background refresh loops beyond a 250 ms
  input tick while waiting for keys.

---

## 3. Screens (T1)

Data is loaded lazily per tab with the same library functions the CLI uses
(`status`, `verify`, `env explain`, `doctor`); `r` re-loads the current tab.
Nothing is cached to disk.

| Tab | Key | Content | Equivalent command |
|---|---|---|---|
| Overview | `1` | State dir + plan counts by status; newest plan (id, profile, status, age); profile drift summary when a profile is given | `configctl status [PROFILE]` |
| Verify | `2` | Per-category `ok/total` rows (`env`, `envfile`, `file`, `git`, `package`, `secret`, `service`), findings list with reasons | `configctl verify PROFILE` |
| Environment | `3` | Sources with line numbers and classifications (`managed`/`special`/`manual`/`secret`/`structure`), conflicts, precedence note | `configctl env explain` |
| Doctor | `4` | Platform, distro, package manager, systemd/secret backends, state health, interrupted applies | `configctl doctor` |
| Help | `5` | Key table + per-tab CLI equivalents + safety note | `configctl guide` |

Tabs that need a profile (Verify; Overview drift summary) show a short
instruction when no profile was given: "pass a profile: `configctl tui
<PROFILE>`".

## 4. Keys

| Key | Action |
|---|---|
| `1`–`5`, `Tab`/`Shift+Tab` | Switch tabs |
| `j`/`k`, `↓`/`↑` | Move selection in a list |
| `r` | Re-load the current tab |
| `?` | Help tab |
| `q`, `Esc`, `Ctrl+C` | Quit |

## 5. Safety and threat notes (T1 delta)

- **Read-only by construction**: the TUI calls only read paths
  (`status`/`verify`/`explain`/`doctor`); it never reaches `plan`/`apply`/
  `rollback`/`capture` code paths. No new operation kinds, no new engine
  surface.
- **Redaction unchanged**: rendered strings pass through the same secret
  discipline as CLI output (values are never loaded for display; the env map
  is value-redacted by construction).
- **Terminal handling**: alternate screen + raw mode via `ratatui::run`,
  which restores the terminal on exit *and* on panic; a non-TTY stdout/stdin
  is refused up front (exit 2, one-line error).
- **No new privilege, no network, no persistence.** Threat register: no new
  T-ID; covered by the existing display/redaction dispositions.

## 6. Rollout phases

| Phase | Deliverable | Gate |
|---|---|---|
| T1 ✅ | Read-only dashboard (this document) | shipped in v1.4 |
| T2 | Plan review + apply approval inside the TUI (reuses plan/apply engines, explicit per-plan confirmation) | threat review first (new: interactive approval path) |
| T3 | Env consolidation wizard (explain → consolidate preview → apply) | threat review; reuses E2 engine |
| T4 | Move-mode assisted flow (patch emission inside the TUI) | threat review; stays assisted-manual |

## 7. Testing

- **App model** (`tui::app`): pure state machine — tab switching, selection
  clamping, data states — unit-tested without a terminal.
- **Rendering** (`ratatui::backend::TestBackend`): each tab renders fixture
  data; assertions check key strings per screen, and a canary test proves
  secret values never reach the buffer.
- **CLI e2e**: `configctl tui` without a TTY exits 2 with a clear message
  and writes nothing.
- **Interactive smoke (dev/verification)**: driven under `tmux` — start,
  switch tabs, quit — asserting the captured pane shows the expected
  content and the terminal is restored.

## 8. CLI surface

```
configctl tui [PROFILE] [--state-dir <DIR>] [--home <DIR>]
```

Exit codes: 0 normal quit; 2 usage / not a TTY. No `--json`.
