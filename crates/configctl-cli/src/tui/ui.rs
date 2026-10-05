//! Rendering for the T1 read-only dashboard.
//!
//! Every tab is a stack of titled, bordered sections (grouping + hierarchy):
//! a tab bar names all five tabs, the body groups the current tab's data
//! into sections (one of which may scroll), and the footer repeats the tab's
//! equivalent CLI command plus the global keys. Colors carry the hierarchy:
//! section titles are accented, statuses are green/red/yellow, hints are dim.
//! No mouse, no theming, no persistence.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Paragraph};

use super::app::{App, EnvData, EnvDeclRow, EnvSourceRow, Loadable, OverviewData, Tab, VerifyData};

// --- Style palette ----------------------------------------------------------

fn accent() -> Style {
    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}
fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}
fn border_style() -> Style {
    Style::new().fg(Color::DarkGray)
}
fn ok_style() -> Style {
    Style::new().fg(Color::Green)
}
fn bad_style() -> Style {
    Style::new().fg(Color::Red)
}
fn warn_style() -> Style {
    Style::new().fg(Color::Yellow)
}
fn selected_style() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

/// One bordered, titled group of lines.
struct Section {
    title: String,
    lines: Vec<Line<'static>>,
    /// Flex sections absorb the leftover height (at most one per tab).
    flex: bool,
}

fn section(title: impl Into<String>, lines: Vec<Line<'static>>) -> Section {
    Section {
        title: title.into(),
        lines,
        flex: false,
    }
}

/// Draw one frame: header (tab bar), body (grouped sections), footer.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(frame.area());
    draw_header(frame, chunks[0], app);
    draw_body(frame, chunks[1], app);
    draw_footer(frame, chunks[2], app);
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans: Vec<Span> = vec![Span::styled(" configctl ", accent()), Span::raw(" ")];
    for tab in Tab::ALL {
        let style = if tab == app.tab {
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            dim()
        };
        spans.push(Span::styled(format!(" {} ", tab.title()), style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let command = Line::from(Span::styled(
        format!("command: {}", app.tab.cli_command()),
        dim(),
    ));
    let keys = Line::from(Span::styled(
        "keys: 1-5 / Tab switch tabs · j/k move · r reload · ? help · q quit",
        dim(),
    ));
    frame.render_widget(Paragraph::new(vec![command, keys]), area);
}

/// Height a fixed section needs (content + two border rows).
fn fixed_height(s: &Section) -> u16 {
    (s.lines.len() as u16).saturating_add(2).max(3)
}

/// Render sections top-down; the flex section takes the remainder.
fn render_sections(frame: &mut Frame, area: Rect, sections: Vec<Section>) {
    let constraints: Vec<Constraint> = sections
        .iter()
        .map(|s| {
            if s.flex {
                Constraint::Min(3)
            } else {
                Constraint::Length(fixed_height(s))
            }
        })
        .collect();
    let chunks = Layout::vertical(constraints).split(area);
    for (s, chunk) in sections.iter().zip(chunks.iter()) {
        let block = Block::bordered()
            .border_style(border_style())
            .title(Line::from(Span::styled(format!(" {} ", s.title), accent())));
        frame.render_widget(Paragraph::new(s.lines.clone()).block(block), *chunk);
    }
}

/// Inner height a flex section will receive given the fixed sections.
fn flex_inner_height(area_height: u16, sections: &[Section]) -> usize {
    let fixed: u16 = sections.iter().filter(|s| !s.flex).map(fixed_height).sum();
    area_height.saturating_sub(fixed).saturating_sub(2).max(1) as usize
}

fn draw_body(frame: &mut Frame, area: Rect, app: &App) {
    match app.tab {
        Tab::Overview => overview_body(frame, area, app),
        Tab::Verify => verify_body(frame, area, app),
        Tab::Environment => environment_body(frame, area, app),
        Tab::Doctor => doctor_body(frame, area, app),
        Tab::Help => help_body(frame, area),
    }
}

fn loading_body(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line<'static>>) {
    render_sections(frame, area, vec![section(title, lines)]);
}

/// First index of a scroll window that keeps `sel` visible in `max_rows`.
fn window_start(sel: usize, len: usize, max_rows: usize) -> usize {
    let max_rows = max_rows.max(1);
    if len <= max_rows || sel < max_rows {
        0
    } else {
        sel + 1 - max_rows
    }
}

// --- Overview ---------------------------------------------------------------

fn overview_body(frame: &mut Frame, area: Rect, app: &App) {
    let (state_lines, drift_lines, drift_flex) = match app.overview() {
        Loadable::NotLoaded => {
            loading_body(frame, area, "Overview", vec![Line::from("loading…")]);
            return;
        }
        Loadable::Failed(e) => {
            loading_body(
                frame,
                area,
                "Overview",
                vec![Line::from(format!("could not read state: {e}"))],
            );
            return;
        }
        Loadable::Ready(d) => overview_sections(d),
    };
    let mut sections = vec![section("State", state_lines)];
    let flex = Section {
        title: "Drift".into(),
        lines: drift_lines,
        flex: drift_flex,
    };
    sections.push(flex);
    render_sections(frame, area, sections);
}

fn overview_sections(d: &OverviewData) -> (Vec<Line<'static>>, Vec<Line<'static>>, bool) {
    let mut state = vec![Line::from(format!("{:<16} {}", "State dir", d.state_dir))];
    if !d.state_initialized {
        state.push(Line::from(Span::styled(
            "not initialized yet — run `configctl init`",
            dim(),
        )));
    } else {
        let breakdown = d
            .by_status
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        state.push(Line::from(format!(
            "{:<16} {} total ({breakdown})",
            "Plans",
            d.plans.len()
        )));
        if let Some(p) = d.plans.first() {
            state.push(Line::from(format!(
                "{:<16} {} ({}, {}, {})",
                "Newest plan", p.id, p.profile, p.status, p.age
            )));
            if let Some(n) = d.newest_ops {
                state.push(Line::from(format!("{:<16} {n} operation(s)", "Operations")));
            }
            if let Some(note) = &d.newest_note {
                state.push(Line::from(Span::styled(
                    format!("  note: {note}"),
                    warn_style(),
                )));
            }
        }
    }

    let mut drift = Vec::new();
    match (&d.drift, &d.drift_error) {
        (Some(s), _) => {
            drift.push(Line::from(format!("Profile {}", s.profile)));
            let row = |label: &str, n: usize, style: Style| {
                let style = if n == 0 { dim() } else { style };
                Line::from(vec![
                    Span::raw(format!("  {label:<12} ")),
                    Span::styled(n.to_string(), style),
                ])
            };
            drift.push(row("MATCH", s.match_count, ok_style()));
            drift.push(row("DRIFT", s.drift, bad_style()));
            drift.push(row("MISSING", s.missing, bad_style()));
            drift.push(row("UNMANAGED", s.unmanaged, warn_style()));
            drift.push(row("UNKNOWN", s.unknown, warn_style()));
            drift.push(row("unsupported", s.unsupported, warn_style()));
            if s.clean() {
                drift.push(Line::from(Span::styled(
                    "  All managed resources match.",
                    ok_style(),
                )));
            } else {
                drift.push(Line::from(Span::styled(
                    "  Next: `configctl plan <profile>` shows how to fix the differences.",
                    dim(),
                )));
            }
        }
        (None, Some(e)) => drift.push(Line::from(Span::styled(
            format!("profile drift unavailable: {e}"),
            warn_style(),
        ))),
        (None, None) => drift.push(Line::from(Span::styled(
            "pass a profile: `configctl tui <PROFILE>`",
            dim(),
        ))),
    }
    (state, drift, true)
}

// --- Verify -----------------------------------------------------------------

fn verify_body(frame: &mut Frame, area: Rect, app: &App) {
    match app.verify() {
        Loadable::Ready(d) => {
            let categories = section("Categories", verify_category_lines(d));
            let fixed = vec![Section {
                title: "Categories".into(),
                lines: categories.lines.clone(),
                flex: false,
            }];
            let inner = flex_inner_height(area.height, &fixed);
            let findings = Section {
                title: "Findings".into(),
                lines: verify_finding_lines(d, app.selection, inner),
                flex: true,
            };
            render_sections(frame, area, vec![categories, findings]);
        }
        Loadable::Failed(e) => loading_body(
            frame,
            area,
            "Verify",
            vec![Line::from(format!("could not verify: {e}"))],
        ),
        Loadable::NotLoaded => {
            if app.verify_needs_profile() {
                loading_body(
                    frame,
                    area,
                    "Verify",
                    vec![
                        Line::from(
                            "Verify compares this machine with a profile. It never repairs.",
                        ),
                        Line::from(Span::styled(
                            "pass a profile: `configctl tui <PROFILE>`",
                            dim(),
                        )),
                    ],
                );
            } else {
                loading_body(frame, area, "Verify", vec![Line::from("loading…")]);
            }
        }
    }
}

fn verify_category_lines(d: &VerifyData) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(format!(
        "Environment Verification — {}",
        d.profile
    ))];
    for c in &d.categories {
        let (verdict, style) = if c.pass() {
            ("PASS", ok_style())
        } else {
            ("FAIL", bad_style())
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{:<12} {}/{}    ", c.category, c.ok, c.total)),
            Span::styled(verdict, style),
        ]));
    }
    lines
}

fn verify_finding_lines(d: &VerifyData, selection: usize, inner: usize) -> Vec<Line<'static>> {
    if d.all_match {
        return vec![Line::from(Span::styled("All resources match.", ok_style()))];
    }
    let max_rows = inner.max(1);
    let start = window_start(selection, d.findings.len(), max_rows);
    let mut lines = Vec::new();
    for (i, f) in d.findings.iter().enumerate().skip(start).take(max_rows) {
        let marker = if i == selection { ">" } else { " " };
        let row = Line::from(format!(
            "{marker} {:<8} {:<8} {} — {}",
            f.status, f.resource, f.target, f.detail
        ));
        lines.push(if i == selection {
            row.style(selected_style())
        } else {
            row
        });
    }
    if d.findings.len() > max_rows {
        lines.push(Line::from(Span::styled(
            format!(
                "  … {}/{} findings (j/k to move)",
                selection + 1,
                d.findings.len()
            ),
            dim(),
        )));
    }
    lines
}

// --- Environment ------------------------------------------------------------

fn environment_body(frame: &mut Frame, area: Rect, app: &App) {
    match app.environment() {
        Loadable::NotLoaded => {
            loading_body(frame, area, "Environment", vec![Line::from("loading…")])
        }
        Loadable::Failed(e) => loading_body(
            frame,
            area,
            "Environment",
            vec![Line::from(format!(
                "could not read the environment map: {e}"
            ))],
        ),
        Loadable::Ready(d) => {
            if d.sources.is_empty() {
                loading_body(
                    frame,
                    area,
                    "Environment",
                    vec![
                        Line::from("No shell startup files were found under $HOME."),
                        Line::from(Span::styled(
                            "Add settings to ~/.bashrc (or ~/.zshrc) and press r to reload.",
                            dim(),
                        )),
                    ],
                );
                return;
            }
            let mut fixed = vec![
                section("Effective values", effective_lines(d)),
                section("Consolidation", consolidation_lines(d)),
            ];
            let inner = flex_inner_height(area.height, &fixed);
            let settings = Section {
                title: "Settings".into(),
                lines: settings_lines(d, app.selection, inner),
                flex: true,
            };
            let mut sections = vec![settings];
            sections.append(&mut fixed);
            render_sections(frame, area, sections);
        }
    }
}

/// One display row of the grouped settings list.
enum EnvRow {
    Header(usize), // index into d.sources
    Decl(usize),   // index into the flattened declaration list
}

fn env_rows(d: &EnvData) -> Vec<EnvRow> {
    let mut rows = Vec::new();
    let mut decl_idx = 0;
    for (si, s) in d.sources.iter().enumerate() {
        rows.push(EnvRow::Header(si));
        for _ in &s.declarations {
            rows.push(EnvRow::Decl(decl_idx));
            decl_idx += 1;
        }
    }
    rows
}

fn source_header_line(s: &EnvSourceRow) -> Line<'static> {
    Line::from(vec![
        Span::styled(s.path.clone(), Style::new().add_modifier(Modifier::BOLD)),
        Span::styled(format!("  ({})", source_read_when(&s.kind)), dim()),
    ])
}

/// Plain-language "when is this read" text for a source kind. Mirrors
/// `configctl_core::envmap::SourceKind::read_when` (the TUI receives the
/// serialized kind string through the env-explain JSON).
fn source_read_when(kind: &str) -> &'static str {
    match kind {
        "bashrc" => "read by every Bash terminal",
        "bash_profile" => "read by login Bash shells",
        "profile" => "read at login",
        "zshrc" => "read by every Zsh terminal",
        "zshenv" => "read by every Zsh shell",
        "xprofile" => "read by some X11 desktop sessions",
        "environment_d" => "read by desktop apps and user services",
        _ => "read by a shell",
    }
}

fn settings_lines(d: &EnvData, selection: usize, inner: usize) -> Vec<Line<'static>> {
    let decls = d.declarations();
    let rows = env_rows(d);
    let sel_row = rows
        .iter()
        .position(|r| matches!(r, EnvRow::Decl(i) if *i == selection))
        .unwrap_or(0);
    // Reserve one row for the count line at the top and one for the window
    // footer when the list is truncated.
    let list_rows = inner.saturating_sub(2).max(1);
    let start = window_start(sel_row, rows.len(), list_rows);
    let mut lines = vec![Line::from(Span::styled(
        format!("Your shell settings live in {} file(s).", d.sources.len()),
        dim(),
    ))];
    for r in rows.iter().skip(start).take(list_rows) {
        match r {
            EnvRow::Header(si) => lines.push(source_header_line(&d.sources[*si])),
            EnvRow::Decl(i) => {
                let decl = decls[*i];
                let marker = if *i == selection { ">" } else { " " };
                let row = Line::from(vec![
                    Span::raw(format!(
                        "  {marker} line {:<4} {:<18} {:<20} ",
                        decl.line,
                        decl.name,
                        display_value(decl)
                    )),
                    Span::styled(class_label(decl), class_style(decl)),
                ]);
                lines.push(if *i == selection {
                    row.style(selected_style())
                } else {
                    row
                });
            }
        }
    }
    if rows.len() > list_rows {
        lines.push(Line::from(Span::styled(
            format!("  … {}/{} lines (j/k to move)", selection + 1, decls.len()),
            dim(),
        )));
    }
    lines
}

/// Bound the fixed sections so small terminals stay usable; the CLI shows
/// everything.
const EFFECTIVE_CAP: usize = 6;
const CONFLICT_CAP: usize = 3;

fn effective_lines(d: &EnvData) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Effective values (which wins today):")];
    for p in d.precedence.iter().take(EFFECTIVE_CAP) {
        lines.push(Line::from(vec![
            Span::raw(format!("  {}=", p.name)),
            Span::styled(p.value.clone(), Style::new().add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ({})", p.source), dim()),
        ]));
    }
    if d.precedence.len() > EFFECTIVE_CAP {
        lines.push(Line::from(Span::styled(
            format!("  … and {} more", d.precedence.len() - EFFECTIVE_CAP),
            dim(),
        )));
    }
    lines
}

fn consolidation_lines(d: &EnvData) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if !d.conflicts.is_empty() {
        lines.push(Line::from(Span::styled(
            "Conflicts (same variable, different values):",
            warn_style(),
        )));
        for c in d.conflicts.iter().take(CONFLICT_CAP) {
            lines.push(Line::from(format!(
                "  {} is set to \"{}\" in {} but \"{}\" in {}",
                c.name, c.winner_value, c.winner, c.shadowed_value, c.shadowed
            )));
        }
        if d.conflicts.len() > CONFLICT_CAP {
            lines.push(Line::from(Span::styled(
                format!("  … and {} more", d.conflicts.len() - CONFLICT_CAP),
                dim(),
            )));
        }
    }
    lines.push(Line::from(format!(
        "{} setting(s) could be consolidated into one managed file; {} look like secrets and stay referenced.",
        d.managed_count,
        d.secret_names.len()
    )));
    lines.push(Line::from(Span::styled(
        "Nothing has been changed. This command is read-only.",
        ok_style(),
    )));
    lines
}

/// The value cell: `<redacted>` for secret rows, even if a value somehow
/// reached the model. Managed/special values are shown exactly as the CLI
/// shows them.
fn display_value(decl: &EnvDeclRow) -> String {
    if decl.secret {
        "<redacted>".to_string()
    } else {
        decl.value.clone().unwrap_or_default()
    }
}

fn class_label(decl: &EnvDeclRow) -> String {
    match decl.classification.as_str() {
        "managed" => {
            if decl.currently_wins {
                "managed — currently wins".to_string()
            } else {
                "managed — overridden".to_string()
            }
        }
        "special" => "special — left alone".to_string(),
        "secret" => "secret — value never shown".to_string(),
        "structure" => "structure — not a setting".to_string(),
        "manual" => format!(
            "manual — left alone ({})",
            decl.reason.as_deref().unwrap_or("conditional")
        ),
        other => other.to_string(),
    }
}

fn class_style(decl: &EnvDeclRow) -> Style {
    match decl.classification.as_str() {
        "managed" if decl.currently_wins => ok_style(),
        "secret" => warn_style(),
        _ => dim(),
    }
}

// --- Doctor -----------------------------------------------------------------

fn doctor_body(frame: &mut Frame, area: Rect, app: &App) {
    match app.doctor() {
        Loadable::NotLoaded => loading_body(frame, area, "Doctor", vec![Line::from("loading…")]),
        Loadable::Failed(e) => loading_body(
            frame,
            area,
            "Doctor",
            vec![Line::from(format!("could not run diagnostics: {e}"))],
        ),
        Loadable::Ready(d) => {
            let platform = section(
                "Platform",
                vec![
                    Line::from(format!("{:<18} {} {}", "OS", d.os, d.arch)),
                    Line::from(format!("{:<18} {}", "Distribution", d.distro)),
                ],
            );
            let backends = section(
                "Backends",
                vec![
                    Line::from(format!("{:<18} {}", "Package manager", d.package_manager)),
                    Line::from(format!("{:<18} {}", "Systemd user", d.systemd_user)),
                    Line::from(format!("{:<18} {}", "Secret backend", d.secret_backend)),
                ],
            );
            let mut state = vec![Line::from(vec![
                Span::raw(format!("{:<18} ", "State")),
                Span::styled(
                    if d.state_ok { "OK" } else { "UNUSABLE" },
                    if d.state_ok { ok_style() } else { bad_style() },
                ),
                Span::styled(format!(" ({})", d.state_dir), dim()),
            ])];
            state.push(Line::from(format!("{:<18} {}", "Plans", d.plans)));
            if d.interrupted.is_empty() {
                state.push(Line::from(Span::styled(
                    format!("{:<18} none", "Interrupted apply"),
                    dim(),
                )));
            } else {
                state.push(Line::from(Span::styled("Interrupted apply:", bad_style())));
                for p in &d.interrupted {
                    state.push(Line::from(format!(
                        "  plan {} ({}, {})",
                        p.plan_id, p.profile, p.status
                    )));
                    for op in &p.ops {
                        state.push(Line::from(format!(
                            "    {} {} [{} after {}] — {}",
                            op.op_id,
                            op.target,
                            recovery_class(op.class),
                            op.last_phase.as_deref().unwrap_or("never started"),
                            op.reason
                        )));
                    }
                    state.push(Line::from(format!(
                        "  Recover with: configctl rollback --plan {}",
                        p.plan_id
                    )));
                }
            }
            if let Some(e) = &d.error {
                state.push(Line::from(Span::styled(format!("error: {e}"), bad_style())));
            }
            let mut sections = vec![platform, backends];
            sections.push(Section {
                title: "State".into(),
                lines: state,
                flex: true,
            });
            render_sections(frame, area, sections);
        }
    }
}

fn recovery_class(class: configctl_core::rollback::RecoveryClass) -> &'static str {
    match class {
        configctl_core::rollback::RecoveryClass::SafeToResume => "safe to resume",
        configctl_core::rollback::RecoveryClass::RequiresRollback => "requires rollback",
        configctl_core::rollback::RecoveryClass::RequiresManual => "requires manual intervention",
        configctl_core::rollback::RecoveryClass::Unknown => "unknown",
    }
}

// --- Help -------------------------------------------------------------------

fn help_body(frame: &mut Frame, area: Rect) {
    let keys = section(
        "Keys",
        vec![
            Line::from("  1-5, Tab / Shift+Tab   switch tabs"),
            Line::from("  j / k, Down / Up       move the selection"),
            Line::from("  r                      reload the current tab"),
            Line::from("  ?                      open this help"),
            Line::from("  q, Esc, Ctrl+C         quit (terminal restored)"),
        ],
    );
    let mut commands = Vec::new();
    for tab in Tab::ALL {
        commands.push(Line::from(vec![
            Span::styled(
                format!("  {:<12}", tab.title()),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {}", tab.cli_command())),
        ]));
    }
    let cli = section("Equivalent CLI commands", commands);
    let safety = Section {
        title: "Safety".into(),
        lines: vec![
            Line::from(
                "Nothing here changes your machine. Every tab shows the command that would.",
            ),
            Line::from(Span::styled(
                "Mutating flows (plan review, apply approval) are not part of T1.",
                dim(),
            )),
        ],
        flex: true,
    };
    render_sections(frame, area, vec![keys, cli, safety]);
}
