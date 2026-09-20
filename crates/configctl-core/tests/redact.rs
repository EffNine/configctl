//! Tests for the redaction subsystem.

use configctl_core::redact::{redact_with_patterns, SecretRegistry, REDACTED};

#[test]
fn exact_value_redacted() {
    let reg = SecretRegistry::default();
    reg.register("super-secret-test-value");
    let out = reg.redact("value is super-secret-test-value ok");
    assert!(!out.contains("super-secret-test-value"));
    assert!(out.contains(REDACTED));
}

#[test]
fn short_values_not_registered() {
    let reg = SecretRegistry::default();
    reg.register("ab");
    let out = reg.redact("ab remains");
    assert!(out.contains("ab"));
}

#[test]
fn pattern_prefix_masks_tokens() {
    let reg = SecretRegistry::default();
    reg.register_pattern_prefix("sk-");
    let out = reg.redact("key sk-abcdef1234567890 shown");
    assert!(!out.contains("sk-abcdef1234567890"));
    assert!(out.contains("sk-****"));
}

#[test]
fn redaction_is_idempotent() {
    let reg = SecretRegistry::default();
    reg.register("topsecretvalue123");
    reg.register_pattern_prefix("ghp_");
    let once = reg.redact("topsecretvalue123 and ghp_abcdefgh");
    let twice = reg.redact(&once);
    assert_eq!(once, twice);
}

#[test]
fn pattern_layer_masks_registered_prefix_tokens() {
    let reg = SecretRegistry::default();
    let out = redact_with_patterns(&reg, "token sk-test-xyz present", &[("sk-test-xyz", "sk-")]);
    assert!(!out.contains("sk-test-xyz"));
    assert!(out.contains("sk-****"));
}

#[test]
fn json_string_redaction() {
    let reg = SecretRegistry::default();
    reg.register("secret-in-json");
    let json = r#"{"path":"/x","note":"contains secret-in-json inside"}"#;
    let out = reg.redact(json);
    assert!(!out.contains("secret-in-json"));
}
