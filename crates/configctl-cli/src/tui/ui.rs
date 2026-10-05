//! Rendering for the T1 read-only dashboard.
//!
//! Every screen is plain `Paragraph` text (no mouse, no theming): the tab
//! bar names all five tabs, the body shows the current tab's data, and the
//! footer repeats the tab's equivalent CLI command plus the global keys.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use super::app::{App, EnvData, EnvDeclRow, Loadable, OverviewData, Tab, VerifyData};

/// Draw one frame: header (tab bar), body (current tab), footer (command+keys).
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
    let mut spans: Vec<Span> = vec![
        Span::styled(" configctl ", Style::new().add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ];
    for tab in Tab::ALL {
        let style = if tab == app.tab {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        spans.push(Span::styled(format!(" {} ", tab.title()), style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let command = Line::from(format!("command: {}", app.tab.cli_command()));
    let keys = Line::from("keys: 1-5 / Tab switch tabs · j/k move · r reload · ? help · q quit");
    frame.render_widget(Paragraph::new(vec![command, keys]), area);
}

fn draw_body(frame: &mut Frame, area: Rect, app: &App) {
    let lines = body_lines(app, area.height);
    frame.render_widget(Paragraph::new(lines), area);
}

fn body_lines(app: &App, height: u16) -> Vec<Line<'static>> {
    match app.tab {
        Tab::Overview => match app.overview() {
            Loadable::NotLoaded => vec![Line::from("loading…")],
            Loadable::Failed(e) => vec![Line::from(format!("could not read state: {e}"))],
            Loadable::Ready(d) => overview_lines(d),
        },
        Tab::Verify => verify_lines(app, height),
        Tab::Environment => environment_lines(app, height),
        Tab::Doctor => match app.doctor() {
            Loadable::NotLoaded => vec![Line::from("loading…")],
            Loadable::Failed(e) => vec![Line::from(format!("could not run diagnostics: {e}"))],
            Loadable::Ready(d) => doctor_lines(d),
        },
        Tab::Help => help_lines(),
    }
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

fn overview_lines(d: &OverviewData) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(format!("{:<16} {}", "State", d.state_dir))];
    if !d.state_initialized {
        lines.push(Line::from("not initialized yet — run `configctl init`"));
    } else {
        let breakdown = d
            .by_status
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(Line::from(format!(
            "{:<16} {} total ({breakdown})",
            "Plans",
            d.plans.len()
        )));
        if let Some(p) = d.plans.first() {
            lines.push(Line::from(format!(
                "{:<16} {} ({}, {}, {})",
                "Newest plan", p.id, p.profile, p.status, p.age
            )));
            if let Some(n) = d.newest_ops {
                lines.push(Line::from(format!("{:<16} {n} operation(s)", "Operations")));
            }
            if let Some(note) = &d.newest_note {
                lines.push(Line::from(format!("  note: {note}")));
            }
        }
    }
    match (&d.drift, &d.drift_error) {
        (Some(s), _) => {
            lines.push(Line::from(""));
            lines.push(Line::from(format!("Profile {}", s.profile)));
            lines.push(Line::from(format!("  MATCH        {}", s.match_count)));
            lines.push(Line::from(format!("  DRIFT        {}", s.drift)));
            lines.push(Line::from(format!("  MISSING      {}", s.missing)));
            lines.push(Line::from(format!("  UNMANAGED    {}", s.unmanaged)));
            lines.push(Line::from(format!("  UNKNOWN      {}", s.unknown)));
            lines.push(Line::from(format!("  unsupported  {}", s.unsupported)));
            if s.clean() {
                lines.push(Line::from("  All managed resources match."));
            } else {
                lines.push(Line::from(
                    "  Next: `configctl plan <profile>` shows how to fix the differences.",
                ));
            }
        }
        (None, Some(e)) => {
            lines.push(Line::from(""));
            lines.push(Line::from(format!("profile drift unavailable: {e}")));
        }
        (None, None) => {
            lines.push(Line::from(""));
            lines.push(Line::from("pass a profile: `configctl tui <PROFILE>`"));
        }
    }
    lines
}

fn verify_lines(app: &App, height: u16) -> Vec<Line<'static>> {
    match app.verify() {
        Loadable::Ready(d) => verify_ready_lines(d, app.selection, height),
        Loadable::Failed(e) => vec![Line::from(format!("could not verify: {e}"))],
        Loadable::NotLoaded => {
            if app.verify_needs_profile() {
                vec![
                    Line::from("Verify compares this machine with a profile. It never repairs."),
                    Line::from("pass a profile: `configctl tui <PROFILE>`"),
                ]
            } else {
                vec![Line::from("loading…")]
            }
        }
    }
}

fn verify_ready_lines(d: &VerifyData, selection: usize, height: u16) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("Environment Verification — {}", d.profile)),
        Line::from(""),
    ];
    for c in &d.categories {
        lines.push(Line::from(format!(
            "{:<12} {}/{}    {}",
            c.category,
            c.ok,
            c.total,
            if c.pass() { "PASS" } else { "FAIL" }
        )));
    }
    lines.push(Line::from(""));
    if d.all_match {
        lines.push(Line::from("All resources match."));
        return lines;
    }
    lines.push(Line::from("Findings:"));
    // Fixed rows above the findings list: title + blank + categories + blank
    // + "Findings:".
    let fixed = 4 + d.categories.len();
    let max_rows = (height as usize).saturating_sub(fixed).max(1);
    let start = window_start(selection, d.findings.len(), max_rows);
    for (i, f) in d.findings.iter().enumerate().skip(start).take(max_rows) {
        let marker = if i == selection { ">" } else { " " };
        lines.push(Line::from(format!(
            "{marker} {:<8} {:<8} {} — {}",
            f.status, f.resource, f.target, f.detail
        )));
    }
    if d.findings.len() > max_rows {
        lines.push(Line::from(format!(
            "  … {}/{} findings (j/k to move)",
            selection + 1,
            d.findings.len()
        )));
    }
    lines
}

fn environment_lines(app: &App, height: u16) -> Vec<Line<'static>> {
    match app.environment() {
        Loadable::NotLoaded => vec![Line::from("loading…")],
        Loadable::Failed(e) => {
            vec![Line::from(format!(
                "could not read the environment map: {e}"
            ))]
        }
        Loadable::Ready(d) => environment_ready_lines(d, app.selection, height),
    }
}

fn environment_ready_lines(d: &EnvData, selection: usize, height: u16) -> Vec<Line<'static>> {
    if d.sources.is_empty() {
        return vec![
            Line::from("No shell startup files were found under $HOME."),
            Line::from("Add settings to ~/.bashrc (or ~/.zshrc) and press r to reload."),
        ];
    }
    let mut lines = vec![
        Line::from(format!(
            "Your shell settings live in {} file(s).",
            d.sources.len()
        )),
        Line::from(""),
        Line::from(format!(
            "{:<18} {:>4}  {:<18} {:<20} {}",
            "SOURCE", "LINE", "NAME", "VALUE", "CLASS"
        )),
    ];
    let decls = d.declarations();
    let max_rows = (height as usize).saturating_sub(8).max(1);
    let start = window_start(selection, decls.len(), max_rows);
    for (i, decl) in decls.iter().enumerate().skip(start).take(max_rows) {
        let marker = if i == selection { ">" } else { " " };
        lines.push(Line::from(format!(
            "{marker}{:<18} {:>4}  {:<18} {:<20} {}",
            decl.source,
            decl.line,
            decl.name,
            display_value(decl),
            class_label(decl)
        )));
    }
    if decls.len() > max_rows {
        lines.push(Line::from(format!(
            "  … {}/{} lines (j/k to move)",
            selection + 1,
            decls.len()
        )));
    }
    lines.push(Line::from(""));
    if !d.conflicts.is_empty() {
        lines.push(Line::from("Conflicts (same variable, different values):"));
        for c in &d.conflicts {
            lines.push(Line::from(format!(
                "  {} is set to \"{}\" in {} but \"{}\" in {}",
                c.name, c.winner_value, c.winner, c.shadowed_value, c.shadowed
            )));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from("Effective values (which wins today):"));
    for p in &d.precedence {
        lines.push(Line::from(format!(
            "  {}={}  ({})",
            p.name, p.value, p.source
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "{} setting(s) could be consolidated into one managed file; {} look like secrets and stay referenced.",
        d.managed_count,
        d.secret_names.len()
    )));
    lines.push(Line::from(
        "Nothing has been changed. This command is read-only.",
    ));
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

fn doctor_lines(d: &crate::commands::doctor::DoctorOutput) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("Platform              {} {}", d.os, d.arch)),
        Line::from(format!("Distribution          {}", d.distro)),
        Line::from(format!("Package manager       {}", d.package_manager)),
        Line::from(format!("Systemd user          {}", d.systemd_user)),
        Line::from(format!("Secret backend        {}", d.secret_backend)),
        Line::from(format!(
            "State                 {} ({})",
            if d.state_ok { "OK" } else { "UNUSABLE" },
            d.state_dir
        )),
        Line::from(format!("Plans                 {}", d.plans)),
    ];
    if d.interrupted.is_empty() {
        lines.push(Line::from("Interrupted apply     none"));
    } else {
        lines.push(Line::from("Interrupted apply:"));
        for p in &d.interrupted {
            lines.push(Line::from(format!(
                "  plan {} ({}, {})",
                p.plan_id, p.profile, p.status
            )));
            for op in &p.ops {
                lines.push(Line::from(format!(
                    "    {} {} [{} after {}] — {}",
                    op.op_id,
                    op.target,
                    recovery_class(op.class),
                    op.last_phase.as_deref().unwrap_or("never started"),
                    op.reason
                )));
            }
            lines.push(Line::from(format!(
                "  Recover with: configctl rollback --plan {}",
                p.plan_id
            )));
        }
    }
    if let Some(e) = &d.error {
        lines.push(Line::from(format!("error: {e}")));
    }
    lines
}

fn recovery_class(class: configctl_core::rollback::RecoveryClass) -> &'static str {
    match class {
        configctl_core::rollback::RecoveryClass::SafeToResume => "safe to resume",
        configctl_core::rollback::RecoveryClass::RequiresRollback => "requires rollback",
        configctl_core::rollback::RecoveryClass::RequiresManual => "requires manual intervention",
        configctl_core::rollback::RecoveryClass::Unknown => "unknown",
    }
}

fn help_lines() -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Keys"),
        Line::from("  1-5, Tab / Shift+Tab   switch tabs"),
        Line::from("  j / k, Down / Up       move the selection"),
        Line::from("  r                      reload the current tab"),
        Line::from("  ?                      open this help"),
        Line::from("  q, Esc, Ctrl+C         quit (terminal restored)"),
        Line::from(""),
        Line::from("Equivalent CLI commands"),
    ];
    for tab in Tab::ALL {
        lines.push(Line::from(format!(
            "  {:<12} {}",
            tab.title(),
            tab.cli_command()
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Nothing here changes your machine. Every tab shows the command that would.",
    ));
    lines.push(Line::from(
        "Mutating flows (plan review, apply approval) are not part of T1.",
    ));
    lines
}
