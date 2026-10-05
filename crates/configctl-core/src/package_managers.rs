//! Native system package managers beyond apt: `dnf` (Fedora/RHEL),
//! `pacman` (Arch), and `apk` (Alpine).
//!
//! Mirrors the apt discipline exactly:
//! - fixed argv through [`CommandRunner`], never a shell;
//! - version-checked output parsing (malformed lines skipped, never guessed);
//! - elevation via `sudo -n` only (no prompting, no new elevation path);
//! - `supports_rollback = false`: installs are report-only on rollback, the
//!   plan text carries `RollbackSupport::Unsupported` exactly like apt.
//!
//! ## Selection policy
//!
//! Capture intersects the installed set with the same
//! [`TOOLING_ALLOWLIST`](crate::packages::TOOLING_ALLOWLIST) as apt
//! (`tooling-allowlist-v1`): names that match across ecosystems (`git`,
//! `curl`, `jq`, …) carry over; distro-specific renames are future work and
//! are reported via `excluded_by_policy`, never silently pretended complete.
//!
//! ## `dnf` vs `dnf5`
//!
//! Only the `dnf` binary is ever invoked. Since Fedora 41 `/usr/bin/dnf` is a
//! symlink to DNF5, so probing `dnf` covers both generations; `dnf5` is never
//! named directly (ONE binary keeps the subprocess surface minimal).
//!
//! ## `pacman` flags (`man pacman` semantics)
//!
//! - `-Q` (query): list installed packages (`pacman -Q` prints
//!   `name version` per line; `pacman -Q <name>` exits 0 iff installed).
//! - `-S` (sync): install from the configured repos.
//! - `--noconfirm`: answer "no configuration, no prompt" — the pacman
//!   counterpart of apt's `-y` non-interactive discipline.
//! - Rollback hints print `pacman -R <name>` (`-R`: remove a single package).
//!   `-R` (not `-Rns`) is the closest mirror of `apt remove`: it removes the
//!   package without cascading into dependencies or wiping configuration,
//!   which a report-only manual hint must never do behind the user's back.
//!
//! ## `rpm` query format
//!
//! Discovery pins `--queryformat '%{NAME}\t%{EVR}\t%{ARCH}\n'`:
//! `%{EVR}` is `[epoch:]version-release`, so epochs (`1:2.3.4-5.fc40`) are
//! preserved verbatim for lock comparison instead of being silently dropped.
//!
//! ## `apk` flags (Alpine; verified against apk-tools 2.14.4 and 3.0.6)
//!
//! - `info -v`: list installed packages (`name-version-rN` per line, sorted,
//!   exit 0). The command is read-only and needs no network (verified with
//!   `--network none`).
//! - `info -e <name>`: exit 0 (and print the name) iff installed; exit 1
//!   otherwise. The read-only installed probe, mirroring `rpm -q` /
//!   `pacman -Q`.
//! - `add <name>`: install from the configured repos. Plain `apk add` is
//!   non-interactive by default (verified inside real Alpine containers:
//!   no prompt with stdin closed and no TTY; `CommandRunner` always runs
//!   with `stdin(Stdio::null())` and pipe fds), so there is no `-y`
//!   counterpart to add — the argv stays minimal. `--no-interactive`
//!   (accepted by both apk-tools generations) remains the explicit escape
//!   hatch if a prompting case is ever observed.
//! - Rollback hints print `apk del <name>` (the removal counterpart).
//!
//! ### `apk info -v` parsing (right-to-left)
//!
//! Lines are `name-version-rN`. Names may contain hyphens; versions start
//! with a digit and never contain a hyphen except the trailing `-rN`
//! revision. Parse from the right: strip the trailing `-r<digits>`,
//! require the remaining string to split at a hyphen whose suffix starts
//! with a digit, and reject anything else (never guessed). The stored
//! version is the full manager-reported version including the revision
//! (`3.7.2-r1`), mirroring pacman's pkgrel and dnf's release segment.

use crate::command::{CommandRequest, CommandRunner};
use crate::packages::{self, InstalledPackage, PackageCapture};

/// Parsed `/etc/os-release` identity (only the fields providers gate on).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    /// Lowercased `ID=` value (`fedora`, `arch`, `ubuntu`, …).
    pub id: String,
    /// Lowercased `ID_LIKE=` tokens (`rhel centos fedora`, `arch`, …).
    pub id_like: Vec<String>,
}

/// Parse `/etc/os-release` content into [`OsRelease`].
///
/// Quoted values, comments, and blank lines are handled; unknown keys are
/// ignored. Missing `ID`/`ID_LIKE` yield empty fields (never guessed).
pub fn parse_os_release(text: &str) -> OsRelease {
    let mut os = OsRelease::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match key.trim() {
            "ID" => os.id = value.to_ascii_lowercase(),
            "ID_LIKE" => {
                os.id_like = value
                    .split_whitespace()
                    .map(|t| t.to_ascii_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect();
            }
            _ => {}
        }
    }
    os
}

/// Read the live `/etc/os-release`. `None` when unreadable (fail-closed:
/// callers treat unknown distros as non-matching).
pub fn read_os_release() -> Option<OsRelease> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    let os = parse_os_release(&text);
    if os.id.is_empty() && os.id_like.is_empty() {
        return None;
    }
    Some(os)
}

/// Native manager families beyond apt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFamily {
    /// Fedora/RHEL-likes (`dnf` + `rpm`).
    Fedora,
    /// Arch-likes (`pacman`).
    Arch,
    /// Alpine (`apk`).
    Alpine,
}

/// True when `os` belongs to `family` (via `ID` or any `ID_LIKE` token).
pub fn family_matches(os: &OsRelease, family: NativeFamily) -> bool {
    // Fedora/RHEL family IDs seen in the wild (`os-release(5)` `ID=`).
    const FEDORA_IDS: &[&str] = &[
        "fedora",
        "rhel",
        "redhat",
        "centos",
        "rocky",
        "almalinux",
        "ol",
        "oracle",
        "scientific",
    ];
    const FEDORA_LIKES: &[&str] = &["fedora", "rhel", "redhat", "centos"];
    match family {
        NativeFamily::Fedora => {
            FEDORA_IDS.contains(&os.id.as_str())
                || os
                    .id_like
                    .iter()
                    .any(|t| FEDORA_LIKES.contains(&t.as_str()))
        }
        NativeFamily::Arch => os.id == "arch" || os.id_like.iter().any(|t| t == "arch"),
        NativeFamily::Alpine => os.id == "alpine" || os.id_like.iter().any(|t| t == "alpine"),
    }
}

/// Pure probe gate shared by both providers: distro family first (no
/// subprocess), then binary presence. Returns `Err(reason)` when unavailable
/// — the caller records `Unavailable`, never a silent skip.
fn probe_gate(
    os: Option<&OsRelease>,
    family: NativeFamily,
    manager: &str,
    binary_present: bool,
) -> Result<(), String> {
    let matched = os.map(|o| family_matches(o, family)).unwrap_or(false);
    if !matched {
        return Err(format!(
            "{manager}: unsupported platform (not a native distro)"
        ));
    }
    if !binary_present {
        return Err(format!("{manager}: binary not present"));
    }
    Ok(())
}

/// Validate a `dnf`/`rpm`/`pacman`/`apk` package name (see
/// [`crate::paths::validate_native_package_name`]).
pub fn validate_native_package_name(name: &str) -> Result<(), String> {
    crate::paths::validate_native_package_name(name)
}

/// Sanitize a reported version: trimmed, non-empty, no control characters,
/// capped (hostile manager output can never inject garbage into the lock).
fn sanitize_native_version(raw: &str) -> Option<String> {
    let s: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    Some(s)
}

/// Parse one pinned `rpm -qa` line (`NAME\tEVR[\tARCH]`). `None` when the
/// line is malformed or fails validation (skipped, never guessed).
fn parse_rpm_line(line: &str) -> Option<InstalledPackage> {
    let mut parts = line.split('\t');
    let name = parts.next()?.trim();
    let evr = parts.next()?.trim();
    let arch = parts.next().map(str::trim).filter(|s| !s.is_empty());
    if validate_native_package_name(name).is_err() {
        return None;
    }
    let version = sanitize_native_version(evr)?;
    // Architecture uses the same safe alphabet (checked, not trusted).
    let architecture = match arch {
        Some(a) => {
            if a.len() > 64
                || !a
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                None
            } else {
                Some(a.to_string())
            }
        }
        None => None,
    };
    Some(InstalledPackage {
        name: name.to_string(),
        version,
        architecture,
    })
}

/// Parse one `pacman -Q` line (`name version`, exactly two fields).
fn parse_pacman_line(line: &str) -> Option<InstalledPackage> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if validate_native_package_name(name).is_err() {
        return None;
    }
    Some(InstalledPackage {
        name: name.to_string(),
        version: sanitize_native_version(version)?,
        architecture: None,
    })
}

/// Parse one `apk info -v` line (`name-version-rN`), right-to-left.
///
/// Alpine names may contain hyphens, so the name/version boundary is the
/// *last* hyphen after stripping the trailing `-r<digits>` revision;
/// versions start with a digit and contain no other hyphen. Lines that do
/// not match this shape are skipped, never guessed (the stored version is
/// the full manager-reported version, revision included).
fn parse_apk_line(line: &str) -> Option<InstalledPackage> {
    let line = line.trim();
    // Trailing package revision: `-r<digits>`.
    let (rest, revision) = line.rsplit_once('-')?;
    let revision_digits = revision.strip_prefix('r')?;
    if revision_digits.is_empty() || !revision_digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Name/version boundary: last hyphen, whose suffix starts with a digit.
    let (name, version) = rest.rsplit_once('-')?;
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if validate_native_package_name(name).is_err() {
        return None;
    }
    let full_version = format!("{version}-{revision}");
    Some(InstalledPackage {
        name: name.to_string(),
        version: sanitize_native_version(&full_version)?,
        architecture: None,
    })
}

fn finalize(mut all: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    // Deterministic: sort by name, dedupe (first version wins after sort).
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all.dedup_by(|a, b| a.name == b.name);
    all
}

/// Capture knobs for one native manager.
struct ManagerSpec {
    id: &'static str,
    family: NativeFamily,
    version_program: &'static str,
    list_program: &'static str,
    list_args: &'static [&'static str],
    parse: fn(&str) -> Vec<InstalledPackage>,
}

const DNF_SPEC: ManagerSpec = ManagerSpec {
    id: "dnf",
    family: NativeFamily::Fedora,
    version_program: "dnf",
    list_program: "rpm",
    list_args: &["-qa", "--queryformat", "%{NAME}\t%{EVR}\t%{ARCH}\n"],
    parse: parse_rpm_output,
};

const PACMAN_SPEC: ManagerSpec = ManagerSpec {
    id: "pacman",
    family: NativeFamily::Arch,
    version_program: "pacman",
    list_program: "pacman",
    list_args: &["-Q"],
    parse: parse_pacman_output,
};

const APK_SPEC: ManagerSpec = ManagerSpec {
    id: "apk",
    family: NativeFamily::Alpine,
    version_program: "apk",
    list_program: "apk",
    list_args: &["info", "-v"],
    parse: parse_apk_output,
};

fn parse_rpm_output(text: &str) -> Vec<InstalledPackage> {
    finalize(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(parse_rpm_line)
            .collect(),
    )
}

fn parse_pacman_output(text: &str) -> Vec<InstalledPackage> {
    finalize(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(parse_pacman_line)
            .collect(),
    )
}

fn parse_apk_output(text: &str) -> Vec<InstalledPackage> {
    finalize(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(parse_apk_line)
            .collect(),
    )
}

fn version_request(spec: &ManagerSpec) -> CommandRequest {
    CommandRequest::new(spec.version_program, ["--version"]).output_cap(8 * 1024)
}

fn list_request(spec: &ManagerSpec) -> CommandRequest {
    CommandRequest::new(spec.list_program, spec.list_args.iter().copied()).output_cap(512 * 1024)
}

/// Full probe with an injectable os-release identity: distro gate on the
/// given `os` AND binary presence (`<manager> --version` exit 0).
fn probe_with_os(
    spec: &ManagerSpec,
    os: Option<&OsRelease>,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    if !os.map(|o| family_matches(o, spec.family)).unwrap_or(false) {
        return Err(format!(
            "{}: unsupported platform (not a native distro)",
            spec.id
        ));
    }
    match runner.run(&version_request(spec)) {
        Ok(o) if o.status == Some(0) => Ok(()),
        _ => Err(format!("{}: binary not present", spec.id)),
    }
}

/// Full probe: distro gate (live `/etc/os-release`, no subprocess) AND
/// binary presence (`<manager> --version` exit 0 through `runner`).
fn probe_impl(spec: &ManagerSpec, runner: &dyn CommandRunner) -> Result<(), String> {
    probe_with_os(spec, read_os_release().as_ref(), runner)
}

/// Pure probe gate for tests: distro fixture + binary presence, no I/O.
fn probe_with_impl(
    spec: &ManagerSpec,
    os: Option<&OsRelease>,
    binary_present: bool,
) -> Result<(), String> {
    probe_gate(os, spec.family, spec.id, binary_present)
}

/// Capture installed packages for one native manager using the shared
/// `tooling-allowlist-v1` selection policy (mirrors [`packages`]).
fn capture_impl(spec: &ManagerSpec, runner: &dyn CommandRunner) -> PackageCapture {
    let out = match runner.run(&list_request(spec)) {
        Ok(o) if o.status == Some(0) => o,
        _ => {
            return PackageCapture {
                unavailable: true,
                ..PackageCapture::default()
            };
        }
    };
    let all = (spec.parse)(&out.stdout);
    let installed_total = all.len();
    let mut selected: Vec<InstalledPackage> = all
        .into_iter()
        .filter(|p| packages::is_tooling_package(&p.name))
        .collect();
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    let excluded_by_policy = installed_total.saturating_sub(selected.len());
    PackageCapture {
        selected,
        installed_total,
        excluded_by_policy,
        unavailable: false,
    }
}

/// Observe exactly the wanted names for one native manager.
/// Returns `(installed name → version, unavailable)`.
fn observe_impl(
    spec: &ManagerSpec,
    runner: &dyn CommandRunner,
    os: Option<&OsRelease>,
    wanted: &[String],
) -> (std::collections::BTreeMap<String, String>, bool) {
    let mut map = std::collections::BTreeMap::new();
    if wanted.is_empty() {
        return (map, false);
    }
    // Distro gate first: non-matching platforms record `Unavailable` with
    // zero subprocess calls (never a silent skip, never wasted probes).
    if probe_with_os(spec, os, runner).is_err() {
        return (map, true);
    }
    let out = match runner.run(&list_request(spec)) {
        Ok(o) if o.status == Some(0) => o,
        _ => return (map, true),
    };
    let want: std::collections::BTreeSet<&str> = wanted.iter().map(|s| s.as_str()).collect();
    for p in (spec.parse)(&out.stdout) {
        if want.contains(p.name.as_str()) {
            map.insert(p.name, p.version);
        }
    }
    (map, false)
}

// ---------------------------------------------------------------------------
// `DnfProvider` (`dnf` / `rpm` on Fedora/RHEL-likes)
// ---------------------------------------------------------------------------

/// Fedora/RHEL system-package provider (`dnf`).
///
/// Capabilities (honest, mirrors apt): `requires_elevation: true`
/// (`sudo -n` only), `touches_network: true` (fetch on install),
/// `supports_rollback: false` (report-only).
pub struct DnfProvider;

impl DnfProvider {
    /// Provider id used in plans (`provider: "dnf"`).
    pub const ID: &'static str = "dnf";
    /// Installs elevate via `sudo -n` (never interactive prompting).
    pub const REQUIRES_ELEVATION: bool = true;
    /// Installs fetch from the configured repos.
    pub const TOUCHES_NETWORK: bool = true;
    /// Installs are never auto-reverted (report-only rollback, like apt).
    pub const SUPPORTS_ROLLBACK: bool = false;

    /// Full probe: Fedora/RHEL-like distro AND `dnf` binary present.
    pub fn probe(runner: &dyn CommandRunner) -> Result<(), String> {
        probe_impl(&DNF_SPEC, runner)
    }

    /// Pure probe gate for tests (distro fixture + binary presence, no I/O).
    pub fn probe_with(os: Option<&OsRelease>, binary_present: bool) -> Result<(), String> {
        probe_with_impl(&DNF_SPEC, os, binary_present)
    }

    /// Fixed argv for the installed-set query
    /// (`rpm -qa --queryformat <pinned>`).
    pub fn list_request() -> CommandRequest {
        list_request(&DNF_SPEC)
    }

    /// Version-checked parse of `rpm -qa` output (epochs preserved via
    /// `%{EVR}`, malformed lines skipped).
    pub fn parse_list(stdout: &str) -> Vec<InstalledPackage> {
        parse_rpm_output(stdout)
    }

    /// Capture installed tooling packages (allowlist policy, like apt).
    pub fn capture(runner: &dyn CommandRunner) -> PackageCapture {
        capture_impl(&DNF_SPEC, runner)
    }

    /// Fixed argv for the installed probe (`rpm -q <name>`: exit 0 iff
    /// installed; read-only, no network).
    pub fn is_installed_request(name: &str) -> CommandRequest {
        CommandRequest::new("rpm", ["-q", name]).output_cap(8 * 1024)
    }

    /// True when `rpm -q` reported the package installed.
    pub fn parse_installed(out: &crate::command::CommandOutput) -> bool {
        out.status == Some(0) && !out.stdout.trim().is_empty()
    }

    /// Fixed argv for installation (`sudo -n dnf install -y <name>`:
    /// non-interactive like apt's `-y`, bounded output, scrubbed env).
    pub fn install_request(name: &str) -> CommandRequest {
        CommandRequest::new("sudo", ["-n", "dnf", "install", "-y", name]).output_cap(128 * 1024)
    }

    /// Plan summary for a missing package (mirrors apt's `install via …`).
    pub fn install_summary(name: &str) -> String {
        format!("package {name}: install via dnf")
    }

    /// Report-only rollback hint (mirrors apt's `manual: apt remove …`).
    pub fn rollback_hint(name: &str) -> String {
        format!(
            "package {name}: installed by apply; v1 never auto-removes (manual: dnf remove {name})"
        )
    }
}

// ---------------------------------------------------------------------------
// `PacmanProvider` (`pacman` on Arch-likes)
// ---------------------------------------------------------------------------

/// Arch system-package provider (`pacman`).
///
/// Capabilities (honest, mirrors apt): `requires_elevation: true`
/// (`sudo -n` only), `touches_network: true` (sync on install),
/// `supports_rollback: false` (report-only).
pub struct PacmanProvider;

impl PacmanProvider {
    /// Provider id used in plans (`provider: "pacman"`).
    pub const ID: &'static str = "pacman";
    /// Installs elevate via `sudo -n` (never interactive prompting).
    pub const REQUIRES_ELEVATION: bool = true;
    /// Installs sync from the configured repos.
    pub const TOUCHES_NETWORK: bool = true;
    /// Installs are never auto-reverted (report-only rollback, like apt).
    pub const SUPPORTS_ROLLBACK: bool = false;

    /// Full probe: Arch-like distro AND `pacman` binary present.
    pub fn probe(runner: &dyn CommandRunner) -> Result<(), String> {
        probe_impl(&PACMAN_SPEC, runner)
    }

    /// Pure probe gate for tests (distro fixture + binary presence, no I/O).
    pub fn probe_with(os: Option<&OsRelease>, binary_present: bool) -> Result<(), String> {
        probe_with_impl(&PACMAN_SPEC, os, binary_present)
    }

    /// Fixed argv for the installed-set query (`pacman -Q`).
    pub fn list_request() -> CommandRequest {
        list_request(&PACMAN_SPEC)
    }

    /// Version-checked parse of `pacman -Q` output (epochs preserved
    /// verbatim, malformed lines skipped).
    pub fn parse_list(stdout: &str) -> Vec<InstalledPackage> {
        parse_pacman_output(stdout)
    }

    /// Capture installed tooling packages (allowlist policy, like apt).
    pub fn capture(runner: &dyn CommandRunner) -> PackageCapture {
        capture_impl(&PACMAN_SPEC, runner)
    }

    /// Fixed argv for the installed probe (`pacman -Q <name>`: exit 0 iff
    /// installed; read-only, no network).
    pub fn is_installed_request(name: &str) -> CommandRequest {
        CommandRequest::new("pacman", ["-Q", name]).output_cap(8 * 1024)
    }

    /// True when `pacman -Q` reported the package installed.
    pub fn parse_installed(out: &crate::command::CommandOutput) -> bool {
        out.status == Some(0) && !out.stdout.trim().is_empty()
    }

    /// Fixed argv for installation (`sudo -n pacman -S --noconfirm <name>`:
    /// `--noconfirm` is the non-interactive counterpart of apt's `-y`).
    pub fn install_request(name: &str) -> CommandRequest {
        CommandRequest::new("sudo", ["-n", "pacman", "-S", "--noconfirm", name])
            .output_cap(128 * 1024)
    }

    /// Plan summary for a missing package (mirrors apt's `install via …`).
    pub fn install_summary(name: &str) -> String {
        format!("package {name}: install via pacman")
    }

    /// Report-only rollback hint (mirrors apt's `manual: apt remove …`;
    /// `-R` removes the package alone, like `apt remove`).
    pub fn rollback_hint(name: &str) -> String {
        format!(
            "package {name}: installed by apply; v1 never auto-removes (manual: pacman -R {name})"
        )
    }
}

// ---------------------------------------------------------------------------
// `ApkProvider` (`apk` on Alpine)
// ---------------------------------------------------------------------------

/// Alpine system-package provider (`apk`).
///
/// Capabilities (honest, mirrors apt): `requires_elevation: true`
/// (`sudo -n` only), `touches_network: true` (fetch on install),
/// `supports_rollback: false` (report-only).
pub struct ApkProvider;

impl ApkProvider {
    /// Provider id used in plans (`provider: "apk"`).
    pub const ID: &'static str = "apk";
    /// Installs elevate via `sudo -n` (never interactive prompting; Alpine
    /// commonly runs as root, but the elevation contract stays uniform).
    pub const REQUIRES_ELEVATION: bool = true;
    /// Installs fetch from the configured repos.
    pub const TOUCHES_NETWORK: bool = true;
    /// Installs are never auto-reverted (report-only rollback, like apt).
    pub const SUPPORTS_ROLLBACK: bool = false;

    /// Full probe: Alpine distro AND `apk` binary present.
    pub fn probe(runner: &dyn CommandRunner) -> Result<(), String> {
        probe_impl(&APK_SPEC, runner)
    }

    /// Pure probe gate for tests (distro fixture + binary presence, no I/O).
    pub fn probe_with(os: Option<&OsRelease>, binary_present: bool) -> Result<(), String> {
        probe_with_impl(&APK_SPEC, os, binary_present)
    }

    /// Fixed argv for the installed-set query (`apk info -v`).
    pub fn list_request() -> CommandRequest {
        list_request(&APK_SPEC)
    }

    /// Version-checked parse of `apk info -v` output (right-to-left; the
    /// full `version-rN` is preserved, malformed lines skipped).
    pub fn parse_list(stdout: &str) -> Vec<InstalledPackage> {
        parse_apk_output(stdout)
    }

    /// Capture installed tooling packages (allowlist policy, like apt).
    pub fn capture(runner: &dyn CommandRunner) -> PackageCapture {
        capture_impl(&APK_SPEC, runner)
    }

    /// Fixed argv for the installed probe (`apk info -e <name>`: exit 0 iff
    /// installed; read-only, no network, no elevation).
    pub fn is_installed_request(name: &str) -> CommandRequest {
        CommandRequest::new("apk", ["info", "-e", name]).output_cap(8 * 1024)
    }

    /// True when `apk info -e` reported the package installed (it prints the
    /// name and exits 0; absent packages exit 1 with empty stdout).
    pub fn parse_installed(out: &crate::command::CommandOutput) -> bool {
        out.status == Some(0) && !out.stdout.trim().is_empty()
    }

    /// Fixed argv for installation (`sudo -n apk add <name>`). Plain
    /// `apk add` is non-interactive by default (verified on apk-tools
    /// 2.14.4 and 3.0.6: no prompt with stdin closed and no TTY), so unlike
    /// apt's `-y` there is no no-prompt flag to add — argv stays minimal.
    pub fn install_request(name: &str) -> CommandRequest {
        CommandRequest::new("sudo", ["-n", "apk", "add", name]).output_cap(128 * 1024)
    }

    /// Plan summary for a missing package (mirrors apt's `install via …`).
    pub fn install_summary(name: &str) -> String {
        format!("package {name}: install via apk")
    }

    /// Report-only rollback hint (mirrors apt's `manual: apt remove …`).
    pub fn rollback_hint(name: &str) -> String {
        format!(
            "package {name}: installed by apply; v1 never auto-removes (manual: apk del {name})"
        )
    }
}

/// Observe exactly the wanted `dnf` names. Distro-gated (zero subprocess
/// calls off-platform), then binary-probed, then listed.
pub fn observe_dnf_packages(
    runner: &dyn CommandRunner,
    os: Option<&OsRelease>,
    wanted: &[String],
) -> (std::collections::BTreeMap<String, String>, bool) {
    observe_impl(&DNF_SPEC, runner, os, wanted)
}

/// Observe exactly the wanted `pacman` names. Distro-gated (zero subprocess
/// calls off-platform), then binary-probed, then listed.
pub fn observe_pacman_packages(
    runner: &dyn CommandRunner,
    os: Option<&OsRelease>,
    wanted: &[String],
) -> (std::collections::BTreeMap<String, String>, bool) {
    observe_impl(&PACMAN_SPEC, runner, os, wanted)
}

/// Observe exactly the wanted `apk` names. Distro-gated (zero subprocess
/// calls off-platform), then binary-probed, then listed.
pub fn observe_apk_packages(
    runner: &dyn CommandRunner,
    os: Option<&OsRelease>,
    wanted: &[String],
) -> (std::collections::BTreeMap<String, String>, bool) {
    observe_impl(&APK_SPEC, runner, os, wanted)
}

/// Names for `profile.toml [packages].dnf` / `[packages].pacman` /
/// `[packages].apk` (sorted, unique) — same shape as [`packages::apt_names`].
pub fn selected_names(capture: &PackageCapture) -> Vec<String> {
    let mut names: Vec<String> = capture.selected.iter().map(|p| p.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}
