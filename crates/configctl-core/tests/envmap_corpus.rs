//! envmap parser corpus: the conservative shell parser must never panic, never
//! hang, never retain secret values, and always classify — on real-world rc
//! files, not just unit one-liners.
//!
//! Fixture discipline: real rc files live in `tests/fixtures/envmap/` (this
//! crate previously built parser fixtures inline; on-disk files are the honest
//! form for "never breaks on real files"). Golden tests pin the exact
//! classification sequence per fixture; a separate fuzz-lite test hammers the
//! parser with adversarial fragments using only `std` (no new dependencies).

use configctl_core::envmap::{self, LineClass, SourceKind};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/envmap")
}

fn fixture(name: &str) -> String {
    let bytes = std::fs::read(fixtures_dir().join(name))
        .unwrap_or_else(|e| panic!("fixture {name} unreadable: {e:?}"));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `(line, name, class)` for every declaration, in order.
fn classes(src: &envmap::EnvSource) -> Vec<(usize, String, LineClass)> {
    src.declarations
        .iter()
        .map(|d| (d.line, d.name.clone(), d.class))
        .collect()
}

fn assert_sequence(src: &envmap::EnvSource, expected: &[(usize, &str, LineClass)]) {
    let got = classes(src);
    let want: Vec<(usize, String, LineClass)> = expected
        .iter()
        .map(|(l, n, c)| (*l, n.to_string(), *c))
        .collect();
    assert_eq!(got, want, "classification sequence mismatch");
}

fn assert_deterministic(name: &str, content: &str, kind: SourceKind) {
    let a = envmap::parse_source(name, content, kind, 1);
    let b = envmap::parse_source(name, content, kind, 1);
    let va = serde_json::to_value(&a).unwrap();
    let vb = serde_json::to_value(&b).unwrap();
    assert_eq!(va, vb, "parse must be deterministic for {name}");
}

/// Secret canary values used inside fixtures. They must appear NOWHERE in any
/// parser output — structured, serialized, or `Debug`-formatted.
const CANARIES: &[&str] = &["ghp_TESTCANARY0000000001", "wJalrXUtnFEMI_TESTCANARY2"];

fn assert_no_secret_retained(src: &envmap::EnvSource) {
    for d in &src.declarations {
        if d.class == LineClass::Secret {
            assert!(d.secret, "secret class must set the secret flag");
            assert!(
                d.value.is_none(),
                "secret {} must not retain a value",
                d.name
            );
        }
    }
    let debug_src = format!("{src:?}");
    let json = serde_json::to_string(src).unwrap();
    for c in CANARIES {
        assert!(
            !debug_src.contains(c),
            "canary leaked into Debug output: {c}"
        );
        assert!(!json.contains(c), "canary leaked into JSON output: {c}");
    }
}

#[test]
fn bashrc_ubuntu_golden_sequence() {
    let content = fixture("bashrc_ubuntu");
    let src = envmap::parse_source("~/.bashrc", &content, SourceKind::Bashrc, 1);
    use LineClass::{Managed as M, Manual as N, Secret as S, Special as P, Structure as T};
    assert_sequence(
        &src,
        &[
            (3, "case", N),
            (4, "*i*)", N),
            (5, "*)", N),
            (6, "esac", N),
            (7, "HISTCONTROL", M),
            (8, "shopt", N),
            (9, "HISTSIZE", M),
            (10, "HISTFILESIZE", M),
            (11, "shopt", N),
            (12, "[", N),
            (13, "if", N),
            (14, "debian_chroot=$(cat", N),
            (15, "fi", N),
            (16, "case", N),
            (17, "xterm-color|*-256color)", N),
            (18, "esac", N),
            (19, "if", N),
            (20, "if", N),
            (21, "color_prompt=yes", N),
            (22, "else", N),
            (23, "color_prompt=", N),
            (24, "fi", N),
            (25, "fi", N),
            (26, "PS1", P),
            (27, "EDITOR", M),
            (28, "LANG", M),
            (29, "alias", T),
            (30, "alias", T),
            (31, "if", N),
            (32, ".", N),
            (33, "fi", N),
            (34, "GITHUB_TOKEN", S),
        ],
    );
    // Spot-check values and reasons: PS1 keeps its expansion-laden value
    // because behaviour-defining variables are reported, never moved.
    let ps1 = src.declarations.iter().find(|d| d.name == "PS1").unwrap();
    assert_eq!(
        ps1.value.as_deref(),
        Some("${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ ")
    );
    let editor = src
        .declarations
        .iter()
        .find(|d| d.name == "EDITOR")
        .unwrap();
    assert_eq!(editor.value.as_deref(), Some("vim"));
    assert_no_secret_retained(&src);
    assert_deterministic("~/.bashrc", &content, SourceKind::Bashrc);
}

#[test]
fn zshrc_golden_sequence() {
    let content = fixture("zshrc");
    let src = envmap::parse_source("~/.zshrc", &content, SourceKind::Zshrc, 4);
    use LineClass::{Managed as M, Manual as N, Secret as S, Structure as T};
    assert_sequence(
        &src,
        &[
            (2, "if", N),
            // Indented `source` inside the if-block is manual (nested), not
            // structure — nesting always wins over the keyword.
            (3, "source", N),
            (4, "fi", N),
            // Expansion-bearing assignment: reported, never consolidated.
            (5, "ZSH", N),
            (6, "ZSH_THEME", M),
            // `plugins=(git docker)` (zsh array) parses as a plain
            // `NAME=VALUE` assignment with value `(git docker)`: pinned
            // deliberately unchanged. It is safe by construction — the value
            // is non-secret, and consolidation only touches names the profile
            // literally declares (move mode additionally requires byte-equal
            // values; include mode leaves the line in place and reports it
            // as shadowed). Reclassifying array syntax is deferred feature
            // work, not robustness.
            (7, "plugins", M),
            // Top-level `source` is structure, not a declaration.
            (8, "source", T),
            (9, "EDITOR", M),
            (10, "precmd()", N),
            (11, "print", N),
            (12, "}", N),
            (13, "setopt", N),
            (14, "autoload", N),
            (15, "AWS_SECRET_ACCESS_KEY", S),
        ],
    );
    let theme = src
        .declarations
        .iter()
        .find(|d| d.name == "ZSH_THEME")
        .unwrap();
    assert_eq!(theme.value.as_deref(), Some("robbyrussell"));
    assert_no_secret_retained(&src);
    assert_deterministic("~/.zshrc", &content, SourceKind::Zshrc);
}

#[test]
fn profile_path_mangling_golden() {
    let content = fixture("profile_path");
    let src = envmap::parse_source("~/.profile", &content, SourceKind::Profile, 3);
    use LineClass::{Managed as M, Manual as N, Special as P};
    assert_sequence(
        &src,
        &[
            (2, "if", N),
            (3, "if", N),
            (4, ".", N),
            (5, "fi", N),
            (6, "fi", N),
            // PATH with expansion is still special: behaviour-defining
            // variables are reported with their value, never moved.
            (7, "PATH", P),
            (8, "EDITOR", M),
            (9, "LANG", M),
            (10, "JAVA_HOME", M),
        ],
    );
    let path = src.declarations.iter().find(|d| d.name == "PATH").unwrap();
    assert_eq!(
        path.value.as_deref(),
        Some("$HOME/bin:$HOME/.local/bin:$PATH")
    );
    assert_no_secret_retained(&src);
    assert_deterministic("~/.profile", &content, SourceKind::Profile);
}

#[test]
fn crlf_endings_parse_like_lf() {
    let content = fixture("crlf_bashrc");
    assert!(content.contains("\r\n"), "fixture must be real CRLF");
    let src = envmap::parse_source("~/.bashrc", &content, SourceKind::Bashrc, 1);
    use LineClass::{Managed as M, Special as P};
    assert_sequence(&src, &[(1, "EDITOR", M), (2, "LANG", M), (5, "PATH", P)]);
    // No stray `\r` may survive into names or values.
    for d in &src.declarations {
        assert!(!d.name.contains('\r'), "CR leaked into name");
        if let Some(v) = &d.value {
            assert!(!v.contains('\r'), "CR leaked into value");
        }
    }
    assert_deterministic("~/.bashrc", &content, SourceKind::Bashrc);
}

#[test]
fn bom_and_non_ascii_values_parse() {
    let content = fixture("bom_utf8_bashrc");
    assert!(content.starts_with('\u{FEFF}'), "fixture must carry a BOM");
    let src = envmap::parse_source("~/.bashrc", &content, SourceKind::Bashrc, 1);
    use LineClass::Managed as M;
    assert_sequence(
        &src,
        &[(1, "EDITOR", M), (2, "GREETING", M), (3, "LANG", M)],
    );
    // The BOM must not corrupt the first name, and non-ASCII values round-trip.
    assert_eq!(src.declarations[0].name, "EDITOR");
    assert_eq!(
        src.declarations[1].value.as_deref(),
        Some("h\u{e9}llo w\u{f6}rld")
    );
    assert_deterministic("~/.bashrc", &content, SourceKind::Bashrc);
}

#[test]
fn near_limit_size_parses_without_hang() {
    // Just under 1 MiB, generated deterministically (no megabyte blob in git).
    // Every line is a plain managed assignment.
    const LIMIT: usize = 1024 * 1024;
    let mut content = String::new();
    let mut i = 0u32;
    while content.len() + 30 < LIMIT - 2048 {
        content.push_str(&format!("export FILLER_{i:06}={i:06}\n"));
        i += 1;
    }
    assert!(
        content.len() < LIMIT && content.len() >= LIMIT - 4096,
        "near-limit body must sit just under 1 MiB, got {}",
        content.len()
    );
    // Generous ceiling only (typical is milliseconds; 30s catches hangs, not
    // variance) — the proof is the assertions below, not the clock.
    let start = std::time::Instant::now();
    let src = envmap::parse_source("~/.bashrc", &content, SourceKind::Bashrc, 1);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "near-limit parse hung: {elapsed:?}"
    );
    assert_eq!(src.declarations.len(), i as usize);
    assert!(
        src.declarations
            .iter()
            .all(|d| d.class == LineClass::Managed),
        "plain assignments must all classify managed"
    );
    assert_deterministic("~/.bashrc", &content, SourceKind::Bashrc);
}

/// Hand-rolled adversarial corpus (no new dependencies): every fragment must
/// parse without panic and every substantive line must yield exactly one
/// classification.
#[test]
fn fuzz_lite_adversarial_fragments_never_panic_and_always_classify() {
    // NUL byte inside a quoted value (Rust &str carries NUL fine).
    let nul = "export NUL_BYTE=\"a\0b\"\n".to_string();
    let big = format!("export BIG={}\n", "x".repeat(10_000));
    let fragments: Vec<String> = vec![
        "export UNCLOSED=\"oops\n".into(),
        "export SINGLE='oops\n".into(),
        "export LONE_BACKSLASH=\\\n".into(),
        "\\\n".into(),
        nul,
        big,
        "export CMD=$(hostname)\n".into(),
        "export TICK=`hostname`\n".into(),
        "export P=${PATH:+/x}\n".into(),
        "export D=${X:-default}\n".into(),
        "export GLOB=*.txt\n".into(),
        "export Q=file?.txt\n".into(),
        // Block closers at depth zero must not underflow (saturating).
        "}\n".into(),
        "fi\n".into(),
        "esac\n".into(),
        "myfunc() {\n".into(),
        "function deploy {\n".into(),
        "export =novalue\n".into(),
        "=orphan\n".into(),
        "export BARE\n".into(),
        "export EMPTY=\n".into(),
        "export TWO WORDS=x\n".into(),
        "export DASHED-NAME=1\n".into(),
        "export \u{dc}NICODE=1\n".into(),
        "export PATH=/usr/bin:/bin\n".into(),
        "export PS1='$ '\n".into(),
        "export SECRET_CANARY=sk-canary-fuzz-0001\n".into(),
        "if\n".into(),
        "else\n".into(),
        ";;\n".into(),
        // Multi-line nesting and continuations: one decl per physical line.
        "if [ x ]; then\nexport INSIDE=1\nfi\n".into(),
        "export A=1 \\\ncontinued\n".into(),
        // Vacuous inputs classify to zero declarations, not an error.
        "".into(),
        "# just a comment\n\n".into(),
    ];
    for frag in &fragments {
        let src = envmap::parse_source("~/.bashrc", frag, SourceKind::Bashrc, 1);
        let expected = frag
            .lines()
            .filter(|l| {
                let t = l.strip_suffix('\r').unwrap_or(l).trim();
                !(t.is_empty() || t.starts_with('#'))
            })
            .count();
        assert_eq!(
            src.declarations.len(),
            expected,
            "every substantive line must classify exactly once in {frag:?}"
        );
        for d in &src.declarations {
            let s = d.class.as_str();
            assert!(
                ["managed", "special", "manual", "secret", "structure"].contains(&s),
                "unknown class {s}"
            );
            if d.class == LineClass::Secret {
                assert!(d.value.is_none(), "secret value retained for {}", d.name);
            }
        }
    }
    // Spot checks pin the interesting corners (the count invariant above is
    // structural; these prove the semantics did not drift).
    let spot = |body: &str| envmap::parse_source("~/.bashrc", body, SourceKind::Bashrc, 1);
    assert_eq!(
        spot("export PATH=/usr/bin:/bin\n").declarations[0].class,
        LineClass::Special
    );
    assert_eq!(
        spot("export PS1='$ '\n").declarations[0].class,
        LineClass::Special
    );
    let sec = &spot("export SECRET_CANARY=sk-canary-fuzz-0001\n").declarations[0];
    assert_eq!(sec.class, LineClass::Secret);
    assert!(sec.value.is_none());
    assert_eq!(
        spot("export EMPTY=\n").declarations[0].class,
        LineClass::Managed
    );
    assert_eq!(spot("}\n").declarations[0].class, LineClass::Manual);
    // The fuzz canary must not leak into Debug or JSON either.
    let src = spot("export SECRET_CANARY=sk-canary-fuzz-0001\n");
    assert!(!format!("{src:?}").contains("sk-canary-fuzz-0001"));
    assert!(!serde_json::to_string(&src)
        .unwrap()
        .contains("sk-canary-fuzz-0001"));
}
