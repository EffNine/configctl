//! `TestBackend` render tests for the T1 dashboard (docs/TUI.md §7).
//!
//! Each tab is rendered at 100×30 from fixture data (never a real terminal);
//! assertions check the key strings per screen. A canary test feeds a
//! secret-shaped value where the data model allows one and proves it never
//! reaches the buffer.

use configctl_cli::commands::doctor::DoctorOutput;
use configctl_cli::tui::app::{
    App, CategoryRow, DriftSummary, EnvData, EnvDeclRow, EnvPrecedenceRow, EnvSourceRow,
    FindingRow, OverviewData, PlanRow, Tab, VerifyData,
};
use configctl_cli::tui::ui;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

const CANARY: &str = "CANARY-SECRET-123";

fn render(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| ui::draw(frame, app)).expect("draw");
    let buf = terminal.backend().buffer();
    let area = buf.area;
    let mut out = String::new();
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn app_with(tab: Tab) -> App {
    let mut app = App::new(None, None, None);
    app.set_tab(tab);
    app
}

fn overview_fixture() -> OverviewData {
    OverviewData {
        state_dir: "/home/u/.local/state/configctl".into(),
        state_initialized: true,
        plans: vec![PlanRow {
            id: "plan-1".into(),
            profile: "work".into(),
            status: "applied".into(),
            age: "2h ago".into(),
        }],
        by_status: vec![("applied".into(), 1)],
        newest_ops: Some(4),
        newest_note: None,
        drift: Some(DriftSummary {
            profile: "work".into(),
            match_count: 5,
            drift: 1,
            missing: 0,
            unmanaged: 1,
            unknown: 0,
            unsupported: 0,
        }),
        drift_error: None,
    }
}

fn verify_fixture() -> VerifyData {
    VerifyData {
        profile: "work".into(),
        categories: vec![
            CategoryRow {
                category: "env".into(),
                ok: 2,
                total: 2,
            },
            CategoryRow {
                category: "file".into(),
                ok: 1,
                total: 2,
            },
        ],
        findings: vec![FindingRow {
            status: "Missing".into(),
            resource: "file".into(),
            target: "~/.gitconfig".into(),
            detail: "target does not exist".into(),
        }],
        all_match: false,
    }
}

fn env_fixture() -> EnvData {
    EnvData {
        sources: vec![EnvSourceRow {
            path: "~/.bashrc".into(),
            kind: "bashrc".into(),
            declarations: vec![
                EnvDeclRow {
                    source: "~/.bashrc".into(),
                    line: 3,
                    name: "EDITOR".into(),
                    classification: "managed".into(),
                    reason: None,
                    value: Some("vim".into()),
                    secret: false,
                    currently_wins: true,
                },
                EnvDeclRow {
                    source: "~/.bashrc".into(),
                    line: 4,
                    name: "PATH".into(),
                    classification: "special".into(),
                    reason: Some("behaviour-defining".into()),
                    value: Some("/usr/bin".into()),
                    secret: false,
                    currently_wins: false,
                },
                EnvDeclRow {
                    source: "~/.bashrc".into(),
                    line: 5,
                    name: "API_TOKEN".into(),
                    classification: "secret".into(),
                    reason: None,
                    value: None,
                    secret: true,
                    currently_wins: false,
                },
            ],
        }],
        conflicts: vec![],
        precedence: vec![EnvPrecedenceRow {
            name: "EDITOR".into(),
            value: "vim".into(),
            source: "~/.bashrc".into(),
        }],
        managed_count: 1,
        secret_names: vec!["API_TOKEN".into()],
    }
}

fn doctor_fixture() -> DoctorOutput {
    DoctorOutput {
        os: "linux".into(),
        arch: "x86_64".into(),
        distro: "Ubuntu 24.04".into(),
        package_manager: "apt (dpkg-query available)".into(),
        systemd_user: "available".into(),
        secret_backend: "Secret Service (secret-tool)".into(),
        state_dir: "/home/u/.local/state/configctl".into(),
        state_ok: true,
        plans: 3,
        interrupted: vec![],
        error: None,
    }
}

#[test]
fn overview_tab_renders_state_plans_and_drift() {
    let mut app = app_with(Tab::Overview);
    app.set_overview(overview_fixture());
    let text = render(&app, 100, 30);
    for needle in [
        "State",
        "/home/u/.local/state/configctl",
        "Plans",
        "1 total (1 applied)",
        "Newest plan",
        "plan-1",
        "applied",
        "2h ago",
        "MATCH",
        "DRIFT",
        "UNMANAGED",
        "configctl status [PROFILE]",
    ] {
        assert!(text.contains(needle), "overview missing {needle:?}\n{text}");
    }
}

#[test]
fn overview_without_profile_says_how_to_pass_one() {
    let mut app = app_with(Tab::Overview);
    app.set_overview(OverviewData {
        state_initialized: false,
        ..OverviewData::default()
    });
    let text = render(&app, 100, 30);
    assert!(text.contains("not initialized yet"), "{text}");
    assert!(
        text.contains("pass a profile: `configctl tui <PROFILE>`"),
        "{text}"
    );
}

#[test]
fn verify_tab_renders_categories_findings_and_pass_fail() {
    let mut app = app_with(Tab::Verify);
    app.set_verify(verify_fixture());
    let text = render(&app, 100, 30);
    for needle in [
        "Environment Verification",
        "work",
        "env",
        "2/2",
        "PASS",
        "file",
        "1/2",
        "FAIL",
        "Findings",
        "Missing",
        "~/.gitconfig",
        "target does not exist",
        "configctl verify PROFILE",
    ] {
        assert!(text.contains(needle), "verify missing {needle:?}\n{text}");
    }
}

#[test]
fn verify_tab_without_profile_shows_instruction() {
    let app = app_with(Tab::Verify);
    let text = render(&app, 100, 30);
    assert!(
        text.contains("pass a profile: `configctl tui <PROFILE>`"),
        "{text}"
    );
    assert!(text.contains("configctl verify PROFILE"), "{text}");
}

#[test]
fn environment_tab_renders_sources_and_classifications() {
    let mut app = app_with(Tab::Environment);
    app.set_environment(env_fixture());
    let text = render(&app, 100, 30);
    for needle in [
        "Your shell settings live in 1 file(s).",
        "~/.bashrc",
        "EDITOR",
        "vim",
        "managed — currently wins",
        "PATH",
        "special — left alone",
        "API_TOKEN",
        "secret — value never shown",
        "Effective values (which wins today):",
        "configctl env explain",
    ] {
        assert!(
            text.contains(needle),
            "environment missing {needle:?}\n{text}"
        );
    }
}

/// Canary: a secret declaration that (hypothetically) carries a value must
/// never render it — not even if a future upstream regression smuggles one
/// past the loader.
#[test]
fn environment_canary_secret_value_never_reaches_buffer() {
    let mut data = env_fixture();
    data.sources[0].declarations.push(EnvDeclRow {
        source: "~/.bashrc".into(),
        line: 6,
        name: "DB_PASSWORD".into(),
        classification: "secret".into(),
        reason: None,
        value: Some(CANARY.into()), // forced past the loader on purpose
        secret: true,
        currently_wins: false,
    });
    let mut app = app_with(Tab::Environment);
    app.set_environment(data);
    let text = render(&app, 100, 30);
    assert!(
        !text.contains(CANARY),
        "canary secret value reached the buffer\n{text}"
    );
    assert!(text.contains("<redacted>"), "{text}");
}

/// The JSON boundary drops secret values as well, so even `data` produced by
/// a hypothetical buggy `env explain` cannot reach the render model.
#[test]
fn environment_canary_from_json_is_dropped() {
    let json = serde_json::json!({
        "sources": [{
            "path": "~/.bashrc",
            "kind": "bashrc",
            "declarations": [{
                "name": "DB_PASSWORD",
                "line": 6,
                "classification": "secret",
                "reason": null,
                "value": CANARY,
                "secret": true,
            }],
        }],
        "conflicts": [],
        "precedence": [],
        "secret_names": ["DB_PASSWORD"],
        "managed_count": 0,
    });
    let data = EnvData::from_json(&json);
    let decl = &data.sources[0].declarations[0];
    assert!(decl.secret);
    assert!(decl.value.is_none(), "secret value must be dropped");
    let mut app = app_with(Tab::Environment);
    app.set_environment(data);
    let text = render(&app, 100, 30);
    assert!(
        !text.contains(CANARY),
        "canary secret value reached the buffer\n{text}"
    );
}

#[test]
fn doctor_tab_renders_diagnostics() {
    let mut app = app_with(Tab::Doctor);
    app.set_doctor(doctor_fixture());
    let text = render(&app, 100, 30);
    for needle in [
        "Platform",
        "linux x86_64",
        "Distribution",
        "Ubuntu 24.04",
        "Package manager",
        "apt (dpkg-query available)",
        "Systemd user",
        "Secret backend",
        "State",
        "OK",
        "Plans",
        "Interrupted apply",
        "none",
        "configctl doctor",
    ] {
        assert!(text.contains(needle), "doctor missing {needle:?}\n{text}");
    }
}

#[test]
fn help_tab_lists_keys_and_commands() {
    let app = app_with(Tab::Help);
    let text = render(&app, 100, 30);
    for needle in [
        "Keys",
        "1-5, Tab / Shift+Tab",
        "j / k, Down / Up",
        "r                      reload",
        "q, Esc, Ctrl+C",
        "Equivalent CLI commands",
        "configctl status [PROFILE]",
        "configctl verify PROFILE",
        "configctl env explain",
        "configctl doctor",
        "configctl guide",
        "Nothing here changes your machine",
    ] {
        assert!(text.contains(needle), "help missing {needle:?}\n{text}");
    }
}

#[test]
fn header_names_every_tab() {
    let app = app_with(Tab::Overview);
    let text = render(&app, 100, 30);
    for tab in Tab::ALL {
        assert!(
            text.contains(tab.title()),
            "tab bar missing {tab:?}\n{text}"
        );
    }
    assert!(text.contains("configctl"), "{text}");
}

#[test]
fn failed_tab_renders_a_readable_error_not_a_panic() {
    let mut app = app_with(Tab::Verify);
    app.set_failed("profile bundle not found");
    let text = render(&app, 100, 30);
    assert!(
        text.contains("could not verify: profile bundle not found"),
        "{text}"
    );
    // The footer still names the command and the keys still work.
    assert!(text.contains("configctl verify PROFILE"), "{text}");
    assert!(text.contains("q quit"), "{text}");
}

/// v1.4.1: content is grouped into titled, bordered sections (visual
/// hierarchy), not a flat wall of text.
#[test]
fn tabs_are_grouped_into_titled_bordered_sections() {
    // Overview: State + Drift sections.
    let mut app = app_with(Tab::Overview);
    app.set_overview(overview_fixture());
    let text = render(&app, 100, 30);
    for needle in ["┌", "┐", "└", "┘", "│", " State ", " Drift "] {
        assert!(text.contains(needle), "overview missing {needle:?}\n{text}");
    }

    // Environment: Settings grouped per file, plus fixed sections.
    let mut app = app_with(Tab::Environment);
    app.set_environment(env_fixture());
    let text = render(&app, 100, 30);
    for needle in [
        " Settings ",
        " Effective values ",
        " Consolidation ",
        "(read by every Bash terminal)", // per-file group header
    ] {
        assert!(
            text.contains(needle),
            "environment missing {needle:?}\n{text}"
        );
    }

    // Doctor: Platform / Backends / State sections.
    let mut app = app_with(Tab::Doctor);
    app.set_doctor(doctor_fixture());
    let text = render(&app, 100, 30);
    for needle in [" Platform ", " Backends ", " State "] {
        assert!(text.contains(needle), "doctor missing {needle:?}\n{text}");
    }

    // Verify: Categories + Findings sections.
    let mut app = app_with(Tab::Verify);
    app.set_verify(verify_fixture());
    let text = render(&app, 100, 30);
    for needle in [" Categories ", " Findings "] {
        assert!(text.contains(needle), "verify missing {needle:?}\n{text}");
    }

    // Help: Keys / CLI / Safety sections.
    let app = app_with(Tab::Help);
    let text = render(&app, 100, 30);
    for needle in [" Keys ", " Equivalent CLI commands ", " Safety "] {
        assert!(text.contains(needle), "help missing {needle:?}\n{text}");
    }
}
