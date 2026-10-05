//! TUI state machine (T1): tabs, selection, and lazily loaded per-tab data.
//!
//! This module is deliberately terminal-free: it is the model that
//! `tui::ui` renders and `tui::run` drives. Data loading goes through the
//! same read-only command functions the CLI uses (`status` state queries,
//! `verify`, `env explain`, `doctor`), so the TUI never grows a second
//! engine and never touches a mutating code path.

use configctl_core::command::CommandRunner;
use configctl_core::state;
use configctl_core::verify::{CheckStatus, VerifyReport};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::commands::{doctor, env, status, verify};

/// The five T1 tabs, in `1`–`5` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Verify,
    Environment,
    Doctor,
    Help,
}

impl Tab {
    /// Every tab, in display order.
    pub const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Verify,
        Tab::Environment,
        Tab::Doctor,
        Tab::Help,
    ];

    /// 0-based position (also the `1`–`5` key minus one).
    pub fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Verify => 1,
            Tab::Environment => 2,
            Tab::Doctor => 3,
            Tab::Help => 4,
        }
    }

    /// Tab selected by the `1`–`5` keys.
    pub fn from_number(n: u8) -> Option<Tab> {
        Tab::ALL.get(n.checked_sub(1)? as usize).copied()
    }

    /// Short title used in the tab bar.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Verify => "Verify",
            Tab::Environment => "Environment",
            Tab::Doctor => "Doctor",
            Tab::Help => "Help",
        }
    }

    /// The equivalent read-only CLI command shown in the footer.
    pub fn cli_command(self) -> &'static str {
        match self {
            Tab::Overview => "configctl status [PROFILE]",
            Tab::Verify => "configctl verify PROFILE",
            Tab::Environment => "configctl env explain",
            Tab::Doctor => "configctl doctor",
            Tab::Help => "configctl guide",
        }
    }

    /// Next tab, wrapping (Tab key).
    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    /// Previous tab, wrapping (Shift+Tab key).
    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

/// Lazily loaded data for one tab. Loading is synchronous, so there is no
/// `Loading` variant: a tab is either untouched, ready, or failed.
#[derive(Debug, Clone, PartialEq)]
pub enum Loadable<T> {
    NotLoaded,
    Ready(T),
    Failed(String),
}

impl<T> Loadable<T> {
    /// True until the tab has been loaded at least once (or failed).
    pub fn is_not_loaded(&self) -> bool {
        matches!(self, Loadable::NotLoaded)
    }
}

/// One persisted plan, as shown on the Overview tab.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanRow {
    pub id: String,
    pub profile: String,
    pub status: String,
    pub age: String,
}

/// Profile drift counts (the `status [PROFILE]` rollup).
#[derive(Debug, Clone, PartialEq)]
pub struct DriftSummary {
    pub profile: String,
    pub match_count: usize,
    pub drift: usize,
    pub missing: usize,
    pub unmanaged: usize,
    pub unknown: usize,
    pub unsupported: usize,
}

impl DriftSummary {
    fn from_report(report: &VerifyReport) -> Self {
        let s = &report.summary;
        DriftSummary {
            profile: report.profile.clone(),
            match_count: s.match_count,
            drift: s.drift,
            missing: s.missing,
            unmanaged: s.unmanaged,
            unknown: s.unknown,
            unsupported: s.unsupported,
        }
    }

    /// True when nothing needs attention.
    pub fn clean(&self) -> bool {
        self.drift + self.missing + self.unmanaged == 0
    }
}

/// Overview tab data (state store + newest plan + optional drift).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OverviewData {
    pub state_dir: String,
    pub state_initialized: bool,
    pub plans: Vec<PlanRow>,
    pub by_status: Vec<(String, usize)>,
    /// Operation count of the newest plan, when its document loads.
    pub newest_ops: Option<usize>,
    /// Why the newest plan document could not be loaded (e.g. tampered).
    pub newest_note: Option<String>,
    pub drift: Option<DriftSummary>,
    pub drift_error: Option<String>,
}

/// One per-category verify row (`env 2/2 PASS`).
#[derive(Debug, Clone, PartialEq)]
pub struct CategoryRow {
    pub category: String,
    pub ok: usize,
    pub total: usize,
}

impl CategoryRow {
    pub fn pass(&self) -> bool {
        self.ok == self.total
    }
}

/// One non-matching verify result.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingRow {
    pub status: String,
    pub resource: String,
    pub target: String,
    pub detail: String,
}

/// Verify tab data, derived from a `VerifyReport` exactly like
/// `commands::verify::render_human` (same categories, same verdict rule,
/// same non-match finding filter) so the two views never disagree.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VerifyData {
    pub profile: String,
    pub categories: Vec<CategoryRow>,
    pub findings: Vec<FindingRow>,
    pub all_match: bool,
}

impl VerifyData {
    pub fn from_report(report: &VerifyReport) -> Self {
        let mut cats: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for r in &report.results {
            let e = cats.entry(r.resource.as_str()).or_insert((0, 0));
            e.1 += 1;
            if r.status == CheckStatus::Match {
                e.0 += 1;
            }
        }
        let categories = cats
            .into_iter()
            .map(|(category, (ok, total))| CategoryRow {
                category: category.to_string(),
                ok,
                total,
            })
            .collect();
        let findings: Vec<FindingRow> = report
            .results
            .iter()
            .filter(|r| r.status != CheckStatus::Match)
            .map(|r| FindingRow {
                // Same rendering as `render_human` (`{:?}`), so statuses are
                // never re-derived differently.
                status: format!("{:?}", r.status),
                resource: r.resource.clone(),
                target: r.target.clone(),
                detail: r.detail.clone(),
            })
            .collect();
        let all_match = findings.is_empty();
        VerifyData {
            profile: report.profile.clone(),
            categories,
            findings,
            all_match,
        }
    }
}

/// One declaration line in the Environment tab (values never present for
/// secret-classified lines).
#[derive(Debug, Clone, PartialEq)]
pub struct EnvDeclRow {
    pub source: String,
    pub line: usize,
    pub name: String,
    pub classification: String,
    pub reason: Option<String>,
    /// Present for `managed`/`special` only; always `None` for secrets.
    pub value: Option<String>,
    pub secret: bool,
    pub currently_wins: bool,
}

/// One parsed source file (for the source count and per-file listing).
#[derive(Debug, Clone, PartialEq)]
pub struct EnvSourceRow {
    pub path: String,
    pub kind: String,
    pub declarations: Vec<EnvDeclRow>,
}

/// A same-name collision between two sources.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvConflictRow {
    pub name: String,
    pub winner: String,
    pub winner_value: String,
    pub shadowed: String,
    pub shadowed_value: String,
}

/// One effective (winning) value.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvPrecedenceRow {
    pub name: String,
    pub value: String,
    pub source: String,
}

/// Environment tab data, built from `env explain`'s structured `data`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EnvData {
    pub sources: Vec<EnvSourceRow>,
    pub conflicts: Vec<EnvConflictRow>,
    pub precedence: Vec<EnvPrecedenceRow>,
    pub managed_count: usize,
    pub secret_names: Vec<String>,
}

impl EnvData {
    /// Convert `commands::env::run_env_explain(...).data` into render rows.
    ///
    /// Secret values are dropped here as well as at render time: the CLI
    /// never loads them, and this boundary guarantees a future upstream
    /// regression cannot smuggle one into the TUI buffer.
    pub fn from_json(data: &serde_json::Value) -> Self {
        let precedence: Vec<EnvPrecedenceRow> = data["precedence"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| EnvPrecedenceRow {
                name: p["name"].as_str().unwrap_or_default().to_string(),
                value: p["value"].as_str().unwrap_or_default().to_string(),
                source: p["source"].as_str().unwrap_or_default().to_string(),
            })
            .collect();
        let mut winners: BTreeMap<String, (String, String)> = BTreeMap::new();
        for p in &precedence {
            winners.insert(p.name.clone(), (p.value.clone(), p.source.clone()));
        }

        let mut sources = Vec::new();
        for s in data["sources"].as_array().into_iter().flatten() {
            let path = s["path"].as_str().unwrap_or_default().to_string();
            let mut declarations = Vec::new();
            for d in s["declarations"].as_array().into_iter().flatten() {
                let classification = d["classification"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                let secret = d["secret"].as_bool().unwrap_or(false) || classification == "secret";
                let value = if secret {
                    None
                } else {
                    d["value"].as_str().map(str::to_owned)
                };
                let name = d["name"].as_str().unwrap_or_default().to_string();
                let currently_wins = value
                    .as_deref()
                    .map(|v| {
                        winners
                            .get(&name)
                            .map(|(wv, ws)| wv == v && ws == &path)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                declarations.push(EnvDeclRow {
                    source: path.clone(),
                    line: d["line"].as_u64().unwrap_or(0) as usize,
                    name,
                    classification,
                    reason: d["reason"].as_str().map(str::to_owned),
                    value,
                    secret,
                    currently_wins,
                });
            }
            sources.push(EnvSourceRow {
                path,
                kind: s["kind"].as_str().unwrap_or_default().to_string(),
                declarations,
            });
        }

        let conflicts = data["conflicts"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| EnvConflictRow {
                name: c["name"].as_str().unwrap_or_default().to_string(),
                winner: c["winner"].as_str().unwrap_or_default().to_string(),
                winner_value: c["winner_value"].as_str().unwrap_or_default().to_string(),
                shadowed: c["shadowed"].as_str().unwrap_or_default().to_string(),
                shadowed_value: c["shadowed_value"].as_str().unwrap_or_default().to_string(),
            })
            .collect();
        let secret_names = data["secret_names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_str().map(str::to_owned))
            .collect();
        EnvData {
            sources,
            conflicts,
            precedence,
            managed_count: data["managed_count"].as_u64().unwrap_or(0) as usize,
            secret_names,
        }
    }

    /// Every declaration in source order (the Environment tab's list).
    pub fn declarations(&self) -> Vec<&EnvDeclRow> {
        self.sources
            .iter()
            .flat_map(|s| s.declarations.iter())
            .collect()
    }
}

/// The application state: current tab, list selection, and per-tab data.
pub struct App {
    pub tab: Tab,
    pub selection: usize,
    pub should_quit: bool,
    pub profile: Option<String>,
    pub home: Option<PathBuf>,
    pub state_dir_override: Option<String>,
    overview: Loadable<OverviewData>,
    verify: Loadable<VerifyData>,
    environment: Loadable<EnvData>,
    doctor: Loadable<doctor::DoctorOutput>,
}

impl App {
    pub fn new(
        profile: Option<&str>,
        state_dir_override: Option<&str>,
        home: Option<&Path>,
    ) -> Self {
        App {
            tab: Tab::Overview,
            selection: 0,
            should_quit: false,
            profile: profile.map(str::to_owned),
            home: home.map(Path::to_path_buf),
            state_dir_override: state_dir_override.map(str::to_owned),
            overview: Loadable::NotLoaded,
            verify: Loadable::NotLoaded,
            environment: Loadable::NotLoaded,
            doctor: Loadable::NotLoaded,
        }
    }

    /// Switch tabs. Selection resets because lists differ per tab.
    pub fn set_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.selection = 0;
        }
    }

    /// Number of selectable rows on the current tab.
    pub fn selectable_len(&self) -> usize {
        match self.tab {
            Tab::Verify => match &self.verify {
                Loadable::Ready(d) => d.findings.len(),
                _ => 0,
            },
            Tab::Environment => match &self.environment {
                Loadable::Ready(d) => d.declarations().len(),
                _ => 0,
            },
            _ => 0,
        }
    }

    /// Move the selection down, clamped to the last row.
    pub fn select_next(&mut self) {
        let len = self.selectable_len();
        if len == 0 {
            self.selection = 0;
        } else if self.selection + 1 < len {
            self.selection += 1;
        }
    }

    /// Move the selection up, clamped at the first row.
    pub fn select_prev(&mut self) {
        self.selection = self.selection.saturating_sub(1);
    }

    /// True when the Verify tab (or the Overview drift section) cannot run
    /// because no profile was passed.
    pub fn verify_needs_profile(&self) -> bool {
        self.profile.is_none()
    }

    /// Load the current tab's data if it has never been loaded.
    pub fn ensure_loaded(&mut self, runner: &dyn CommandRunner) {
        match self.tab {
            Tab::Overview if self.overview.is_not_loaded() => {
                self.overview = self.load_overview(runner);
            }
            Tab::Verify if self.verify.is_not_loaded() && self.profile.is_some() => {
                self.verify = self.load_verify(runner);
            }
            Tab::Environment if self.environment.is_not_loaded() => {
                self.environment = self.load_environment();
            }
            Tab::Doctor if self.doctor.is_not_loaded() => {
                self.doctor = Loadable::Ready(doctor::run_doctor(
                    self.state_dir_override.as_deref(),
                    runner,
                ));
            }
            _ => {}
        }
    }

    /// Re-load the current tab (`r`): forget the data, then load again.
    pub fn force_reload(&mut self, runner: &dyn CommandRunner) {
        match self.tab {
            Tab::Overview => self.overview = Loadable::NotLoaded,
            Tab::Verify => self.verify = Loadable::NotLoaded,
            Tab::Environment => self.environment = Loadable::NotLoaded,
            Tab::Doctor => self.doctor = Loadable::NotLoaded,
            Tab::Help => {}
        }
        self.selection = 0;
        self.ensure_loaded(runner);
    }

    /// Apply one key event. Only `Press` events are handled, so `Release`
    /// and `Repeat` (Kitty keyboard protocol) never double-fire.
    pub fn handle_key(
        &mut self,
        key: ratatui::crossterm::event::KeyEvent,
        runner: &dyn CommandRunner,
    ) {
        use ratatui::crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
        if key.kind != KeyEventKind::Press {
            return;
        }
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('1') => self.jump(Tab::Overview, runner),
            KeyCode::Char('2') => self.jump(Tab::Verify, runner),
            KeyCode::Char('3') => self.jump(Tab::Environment, runner),
            KeyCode::Char('4') => self.jump(Tab::Doctor, runner),
            KeyCode::Char('5') => self.jump(Tab::Help, runner),
            KeyCode::Tab => self.jump(self.tab.next(), runner),
            KeyCode::BackTab => self.jump(self.tab.prev(), runner),
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_prev(),
            KeyCode::Char('r') => self.force_reload(runner),
            KeyCode::Char('?') => self.jump(Tab::Help, runner),
            _ => {}
        }
    }

    fn jump(&mut self, tab: Tab, runner: &dyn CommandRunner) {
        self.set_tab(tab);
        self.ensure_loaded(runner);
    }

    /// Overview data as loaded (or not).
    pub fn overview(&self) -> &Loadable<OverviewData> {
        &self.overview
    }

    /// Verify data as loaded (or not).
    pub fn verify(&self) -> &Loadable<VerifyData> {
        &self.verify
    }

    /// Environment data as loaded (or not).
    pub fn environment(&self) -> &Loadable<EnvData> {
        &self.environment
    }

    /// Doctor data as loaded (or not).
    pub fn doctor(&self) -> &Loadable<doctor::DoctorOutput> {
        &self.doctor
    }

    /// Test/fixture hook: install Overview data directly.
    pub fn set_overview(&mut self, data: OverviewData) {
        self.overview = Loadable::Ready(data);
    }

    /// Test/fixture hook: install Verify data directly.
    pub fn set_verify(&mut self, data: VerifyData) {
        self.verify = Loadable::Ready(data);
    }

    /// Test/fixture hook: install Environment data directly.
    pub fn set_environment(&mut self, data: EnvData) {
        self.environment = Loadable::Ready(data);
    }

    /// Test/fixture hook: install Doctor data directly.
    pub fn set_doctor(&mut self, data: doctor::DoctorOutput) {
        self.doctor = Loadable::Ready(data);
    }

    /// Test/fixture hook: put the current tab into a failed state.
    pub fn set_failed(&mut self, message: &str) {
        match self.tab {
            Tab::Overview => self.overview = Loadable::Failed(message.to_string()),
            Tab::Verify => self.verify = Loadable::Failed(message.to_string()),
            Tab::Environment => self.environment = Loadable::Failed(message.to_string()),
            Tab::Doctor => self.doctor = Loadable::Failed(message.to_string()),
            Tab::Help => {}
        }
    }

    // ---- loading (read-only; the same functions the CLI commands use) ----

    fn load_overview(&self, runner: &dyn CommandRunner) -> Loadable<OverviewData> {
        let state_dir = state::resolve_state_dir(self.state_dir_override.as_deref());
        let now = state::now_secs();
        let mut data = OverviewData {
            state_dir: state_dir.display().to_string(),
            state_initialized: state_dir.is_dir(),
            ..OverviewData::default()
        };
        if state_dir.is_dir() {
            match state::list_plans(&state_dir) {
                Ok(plans) => {
                    let mut by_status: BTreeMap<String, usize> = BTreeMap::new();
                    for (_, _, status, _) in &plans {
                        *by_status.entry(status.clone()).or_default() += 1;
                    }
                    data.by_status = by_status.into_iter().collect();
                    data.plans = plans
                        .into_iter()
                        .map(|(id, profile, status, created_at)| PlanRow {
                            id,
                            profile,
                            status,
                            age: status::age(now, created_at),
                        })
                        .collect();
                    if !data.plans.is_empty() {
                        match state::newest_plan_id(&state_dir) {
                            Ok(Some(id)) => match state::load_plan(&state_dir, &id) {
                                Ok((plan, _, _)) => data.newest_ops = Some(plan.operations.len()),
                                Err(e) => data.newest_note = Some(e.to_string()),
                            },
                            Ok(None) => {}
                            Err(e) => data.newest_note = Some(e.to_string()),
                        }
                    }
                }
                Err(e) => return Loadable::Failed(e),
            }
        }
        if let Some(profile) = &self.profile {
            let out = verify::run_verify(profile, self.home.as_deref(), false, runner);
            match out.report {
                Some(report) => data.drift = Some(DriftSummary::from_report(&report)),
                None => {
                    data.drift_error = Some(
                        out.error
                            .unwrap_or_else(|| "verify produced no report".into()),
                    )
                }
            }
        }
        Loadable::Ready(data)
    }

    fn load_verify(&self, runner: &dyn CommandRunner) -> Loadable<VerifyData> {
        let Some(profile) = &self.profile else {
            return Loadable::Failed("no profile given".into());
        };
        let out = verify::run_verify(profile, self.home.as_deref(), false, runner);
        match out.report {
            Some(report) => Loadable::Ready(VerifyData::from_report(&report)),
            None => Loadable::Failed(
                out.error
                    .unwrap_or_else(|| "verify produced no report".into()),
            ),
        }
    }

    fn load_environment(&self) -> Loadable<EnvData> {
        let out = env::run_env_explain(self.home.as_deref());
        match out.error {
            Some(e) => Loadable::Failed(e),
            None => Loadable::Ready(EnvData::from_json(&out.data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use configctl_core::command::FakeCommandRunner;

    fn app(profile: Option<&str>, home: &Path) -> App {
        App::new(profile, None, Some(home))
    }

    fn empty_home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn bundle_with_file(tmp: &Path) -> PathBuf {
        let bundle = tmp.join("work");
        std::fs::create_dir_all(bundle.join("files")).unwrap();
        std::fs::write(bundle.join("files/g"), b"v1\n").unwrap();
        std::fs::write(
            bundle.join("profile.toml"),
            "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n",
        )
        .unwrap();
        bundle
    }

    #[test]
    fn tabs_cycle_and_numbers_map() {
        assert_eq!(Tab::from_number(1), Some(Tab::Overview));
        assert_eq!(Tab::from_number(5), Some(Tab::Help));
        assert_eq!(Tab::from_number(0), None);
        assert_eq!(Tab::from_number(6), None);
        assert_eq!(Tab::Overview.next(), Tab::Verify);
        assert_eq!(Tab::Help.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Help);
        assert_eq!(Tab::Doctor.prev(), Tab::Environment);
    }

    #[test]
    fn key_tab_switching_and_quit() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let tmp = empty_home();
        let mut app = app(None, tmp.path());
        let runner = FakeCommandRunner::new();
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.handle_key(press(KeyCode::Char('4')), &runner);
        assert_eq!(app.tab, Tab::Doctor);
        app.handle_key(press(KeyCode::Tab), &runner);
        assert_eq!(app.tab, Tab::Help);
        app.handle_key(press(KeyCode::BackTab), &runner);
        assert_eq!(app.tab, Tab::Doctor);
        app.handle_key(press(KeyCode::Char('?')), &runner);
        assert_eq!(app.tab, Tab::Help);
        app.handle_key(press(KeyCode::Esc), &runner);
        assert!(app.should_quit);
    }

    #[test]
    fn release_and_repeat_events_are_ignored() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        let tmp = empty_home();
        let mut app = app(None, tmp.path());
        let runner = FakeCommandRunner::new();
        let mut key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        key.kind = KeyEventKind::Release;
        app.handle_key(key, &runner);
        let mut key = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        key.kind = KeyEventKind::Repeat;
        app.handle_key(key, &runner);
        assert!(!app.should_quit);
        assert_eq!(app.tab, Tab::Overview);
    }

    #[test]
    fn selection_clamps_to_available_rows() {
        let tmp = empty_home();
        let mut app = app(None, tmp.path());
        app.set_tab(Tab::Verify);
        app.set_verify(VerifyData {
            profile: "work".into(),
            findings: (0..3)
                .map(|i| FindingRow {
                    status: "Drift".into(),
                    resource: "file".into(),
                    target: format!("~/.f{i}"),
                    detail: "differs".into(),
                })
                .collect(),
            ..VerifyData::default()
        });
        assert_eq!(app.selectable_len(), 3);
        app.select_next();
        app.select_next();
        app.select_next();
        app.select_next(); // clamped
        assert_eq!(app.selection, 2);
        app.select_prev();
        app.select_prev();
        app.select_prev(); // clamped
        assert_eq!(app.selection, 0);
        // Switching tabs resets the selection.
        app.set_tab(Tab::Doctor);
        assert_eq!(app.selection, 0);
        // An empty list keeps the selection at zero.
        app.set_tab(Tab::Verify);
        app.set_verify(VerifyData::default());
        app.select_next();
        assert_eq!(app.selection, 0);
    }

    #[test]
    fn profile_missing_states() {
        let tmp = empty_home();
        let mut app = app(None, tmp.path());
        let runner = FakeCommandRunner::new();
        app.set_tab(Tab::Verify);
        app.ensure_loaded(&runner);
        assert!(app.verify_needs_profile());
        assert!(app.verify().is_not_loaded());
        assert_eq!(app.selectable_len(), 0);
        // Overview still loads: the drift section just stays absent.
        app.set_tab(Tab::Overview);
        app.ensure_loaded(&runner);
        match app.overview() {
            Loadable::Ready(d) => {
                assert!(d.drift.is_none());
                assert!(d.drift_error.is_none());
            }
            other => panic!("overview should load without a profile: {other:?}"),
        }
    }

    #[test]
    fn load_transitions_and_reload() {
        let tmp = empty_home();
        let bundle = bundle_with_file(tmp.path());
        let mut app = app(Some(bundle.to_str().unwrap()), tmp.path());
        let runner = FakeCommandRunner::new();
        app.set_tab(Tab::Verify);
        assert!(app.verify().is_not_loaded());
        app.ensure_loaded(&runner);
        match app.verify() {
            Loadable::Ready(d) => {
                assert_eq!(d.profile, "work");
                assert!(d.categories.iter().any(|c| c.category == "file"));
            }
            other => panic!("verify should load: {other:?}"),
        }
        // A reload of a now-broken profile surfaces the failure, not a panic.
        std::fs::remove_file(bundle.join("profile.toml")).unwrap();
        app.force_reload(&runner);
        assert!(matches!(app.verify(), Loadable::Failed(_)));
        // Fixing it and reloading recovers to Ready.
        std::fs::write(
            bundle.join("profile.toml"),
            "schema_version = 1\nname = \"work\"\n",
        )
        .unwrap();
        app.force_reload(&runner);
        assert!(matches!(app.verify(), Loadable::Ready(_)));
    }

    #[test]
    fn overview_loads_state_and_newest_plan() {
        let tmp = empty_home();
        let home = tmp.path().join("home");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&home).unwrap();
        // Empty state directory: "not initialized", no plans.
        let mut app = App::new(None, Some(state_dir.to_str().unwrap()), Some(&home));
        app.ensure_loaded(&FakeCommandRunner::new());
        match app.overview() {
            Loadable::Ready(d) => {
                assert!(!d.state_initialized);
                assert!(d.plans.is_empty());
            }
            other => panic!("overview should load: {other:?}"),
        }
    }

    #[test]
    fn environment_loads_and_doctor_loads() {
        let tmp = empty_home();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".bashrc"),
            "export EDITOR=vim\nexport API_TOKEN=abc123\n",
        )
        .unwrap();
        let mut app = app(None, &home);
        let runner = FakeCommandRunner::new();
        app.set_tab(Tab::Environment);
        app.ensure_loaded(&runner);
        match app.environment() {
            Loadable::Ready(d) => {
                assert!(!d.sources.is_empty());
                let decls = d.declarations();
                assert!(decls.iter().any(|x| x.name == "EDITOR"));
                let secret = decls.iter().find(|x| x.secret).expect("secret line");
                assert!(secret.value.is_none(), "secret values must not load");
            }
            other => panic!("environment should load: {other:?}"),
        }
        app.set_tab(Tab::Doctor);
        app.ensure_loaded(&runner);
        assert!(matches!(app.doctor(), Loadable::Ready(_)));
    }

    #[test]
    fn env_from_json_drops_secret_values() {
        let json = serde_json::json!({
            "sources": [{
                "path": "~/.bashrc",
                "kind": "bashrc",
                "declarations": [
                    {"name": "EDITOR", "line": 1, "classification": "managed", "reason": null, "value": "vim", "secret": false},
                    {"name": "API_TOKEN", "line": 2, "classification": "secret", "reason": null, "value": "CANARY-SECRET-123", "secret": true},
                ],
            }],
            "conflicts": [],
            "precedence": [{"name": "EDITOR", "value": "vim", "source": "~/.bashrc"}],
            "secret_names": ["API_TOKEN"],
            "managed_count": 1,
        });
        let data = EnvData::from_json(&json);
        let decls = data.declarations();
        let editor = decls.iter().find(|d| d.name == "EDITOR").unwrap();
        assert_eq!(editor.value.as_deref(), Some("vim"));
        assert!(editor.currently_wins);
        let secret = decls.iter().find(|d| d.name == "API_TOKEN").unwrap();
        assert!(secret.secret);
        assert!(
            secret.value.is_none(),
            "secret values must be dropped at the JSON boundary"
        );
    }
}
