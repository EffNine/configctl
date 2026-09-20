//! Tests for the bounded `.env` parser.

use configctl_core::envfile::{parse_env, parse_file, variable_names, MalformedKind, ParseLimits};

fn limits() -> ParseLimits {
    ParseLimits::default()
}

#[test]
fn parses_plain_key_value() {
    let p = parse_env("FOO=bar\n", &limits());
    assert_eq!(p.variables.len(), 1);
    assert_eq!(p.variables[0].name, "FOO");
    assert!(!p.variables[0].value_is_empty());
    assert_eq!(p.variables[0].value_len(), 3);
}

#[test]
fn parses_double_quoted_value() {
    let p = parse_env(r#"FOO="bar baz""#, &limits());
    assert_eq!(p.variables.len(), 1);
    assert_eq!(
        p.variables[0].value_len(),
        7,
        "quoted value keeps inner spaces"
    );
    p.variables[0].with_value(|v| {
        assert_eq!(v, "bar baz");
    });
}

#[test]
fn parses_single_quoted_value() {
    let p = parse_env("FOO='bar baz'", &limits());
    assert_eq!(p.variables[0].value_len(), 7);
}

#[test]
fn parses_empty_value() {
    let p = parse_env("FOO=\n", &limits());
    assert_eq!(p.variables.len(), 1);
    assert!(p.variables[0].value_is_empty());
}

#[test]
fn parses_export_prefix() {
    let p = parse_env("export FOO=bar\n", &limits());
    assert_eq!(p.variables.len(), 1);
    assert_eq!(p.variables[0].name, "FOO");
}

#[test]
fn skips_comments_and_blank_lines() {
    let p = parse_env("# a comment\n\nFOO=bar\n# another\n", &limits());
    assert_eq!(p.variables.len(), 1);
    assert_eq!(p.skipped, 3);
}

#[test]
fn records_malformed_missing_separator() {
    let p = parse_env("JUST_A_WORD\nFOO=bar\n", &limits());
    assert_eq!(p.malformed.len(), 1);
    assert_eq!(p.malformed[0].1, MalformedKind::MissingSeparator);
    assert_eq!(p.variables.len(), 1, "scan continues after malformed line");
}

#[test]
fn records_malformed_invalid_name() {
    let p = parse_env("1BAD=x\nFOO=bar\n", &limits());
    assert_eq!(p.malformed.len(), 1);
    assert_eq!(p.malformed[0].1, MalformedKind::InvalidName);
    assert_eq!(p.variables.len(), 1);
}

#[test]
fn records_malformed_too_long_line() {
    let long = format!("FOO={}", "x".repeat(5000));
    let p = parse_env(&long, &limits());
    assert_eq!(p.malformed.len(), 1);
    assert_eq!(p.malformed[0].1, MalformedKind::TooLong);
}

#[test]
fn supports_equals_in_value() {
    let p = parse_env("CONN=a=b=c\n", &limits());
    assert_eq!(p.variables.len(), 1);
    p.variables[0].with_value(|v| {
        assert_eq!(v, "a=b=c");
    });
}

#[test]
fn crlf_and_bom_handled() {
    let p = parse_env("\u{feff}FOO=bar\r\nBAZ=qux\r\n", &limits());
    assert_eq!(p.variables.len(), 2);
    assert_eq!(p.variables[0].name, "FOO");
    assert_eq!(p.variables[1].name, "BAZ");
}

#[test]
fn duplicates_are_preserved_in_order() {
    let p = parse_env("FOO=1\nFOO=2\n", &limits());
    assert_eq!(p.variables.len(), 2);
    assert_eq!(variable_names(&p), vec!["FOO".to_string()]);
}

#[test]
fn byte_cap_limits_content() {
    let limits = ParseLimits {
        max_bytes: 8,
        ..ParseLimits::default()
    };
    let p = parse_env("AAAA=longvalue\nBBBB=x\n", &limits);
    // Only the first 8 bytes are visible: "AAAA=lon"
    assert!(p.variables.len() <= 1);
}

#[test]
fn variable_count_cap_respected() {
    let limits = ParseLimits {
        max_variables: 3,
        ..ParseLimits::default()
    };
    let content = "A=1\nB=2\nC=3\nD=4\nE=5\n";
    let p = parse_env(content, &limits);
    assert_eq!(p.variables.len(), 3);
}

#[test]
fn no_execution_of_shell_syntax() {
    // Adversarial content: must be treated as inert text.
    let p = parse_env(
        r#"CMD=`rm -rf /`
EXP=$(echo pwned)
EVT=ev;touch /tmp/x
"#,
        &limits(),
    );
    assert_eq!(p.variables.len(), 3);
    p.variables[0].with_value(|v| {
        assert!(v.contains("rm -rf /"), "value stored inert, never executed");
    });
}

#[test]
fn unterminated_quotes_do_not_crash() {
    let p = parse_env(
        r#"FOO="unterminated
BAR=ok
"#,
        &limits(),
    );
    assert!(!p.variables.is_empty());
}

#[test]
fn parse_file_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(".env");
    std::fs::write(&path, "FOO=bar\n# c\n").unwrap();
    let p = parse_file(&path, &limits()).unwrap();
    assert_eq!(p.variables.len(), 1);
}
