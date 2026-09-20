//! Rollback content-identity regression tests (v1.1 rollback fix).
//!
//! Proves that the same bytes produce the same identity through every
//! lifecycle stage — capture/profile content → plan → apply → postcheck →
//! verify → rollback — with no representation mismatch:
//!
//! - file bytes always hash via `hash::file_content_hash` (observe, payload
//!   hashes, plan `desired_after`, apply postcheck, rollback guards);
//! - env literal values always hash via `hash::env_value_hash`;
//! - a value hash is never equal to the file-content hash of a file that
//!   merely contains that value (different canonical byte representations).

use configctl_core::hash;
use configctl_core::observe::ObservedState;
use configctl_core::plan::{self, OperationKind};

/// Every lifecycle stage must agree on the identity of the same bytes.
fn assert_file_identity_roundtrip(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    let canonical = hash::file_content_hash(bytes);
    // Bounded file read uses the same primitive.
    assert_eq!(hash::sha256_file(path, 256 * 1024).unwrap(), canonical);
    // Observation uses the same primitive.
    let obs = configctl_core::observe::observe_file(path);
    assert!(obs.exists && !obs.is_symlink && !obs.is_non_regular);
    assert_eq!(obs.content_hash.as_deref(), Some(canonical.as_str()));
}

#[test]
fn file_content_identity_is_stable_across_representations() {
    let tmp = tempfile::tempdir().unwrap();
    // Empty file, UTF-8 text, newline variants, binary, large (within caps).
    let mut cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        "EDITOR=nvim\n".as_bytes().to_vec(),
        "line1\nline2\n".as_bytes().to_vec(),
        "line1\r\nline2\r\n".as_bytes().to_vec(),
        "héllo wörld ☃\n".as_bytes().to_vec(),
        vec![0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, b'\n'],
    ];
    let mut large = Vec::with_capacity(200 * 1024);
    for i in 0..(200 * 1024) {
        large.push((i % 251) as u8);
    }
    cases.push(large);
    for (i, bytes) in cases.iter().enumerate() {
        let p = tmp.path().join(format!("case-{i}"));
        assert_file_identity_roundtrip(&p, bytes);
    }
    // Newline differences are significant: no normalization, exact bytes rule.
    assert_ne!(
        hash::file_content_hash(b"a\n"),
        hash::file_content_hash(b"a\r\n")
    );
    assert_ne!(
        hash::file_content_hash(b"a\n"),
        hash::file_content_hash(b"a")
    );
}

#[test]
fn single_algorithm_no_duplicate_logic() {
    // Both named primitives are SHA-256 over explicit byte strings (one
    // algorithm, two documented domains — no duplicated hashing logic).
    assert_eq!(hash::file_content_hash(b"abc"), hash::sha256_hex(b"abc"));
    assert_eq!(hash::env_value_hash("abc"), hash::sha256_str("abc"));
    assert_eq!(hash::file_content_hash(b""), hash::sha256_hex(b""));
}

#[test]
fn value_hash_never_equals_containing_file_hash() {
    // The regression: rollback compared `desired_after` (a VALUE hash)
    // against a FILE CONTENT hash. These domains must differ whenever the
    // file holds more than the bare value — which is always the case for
    // the managed env file (header + `KEY=value` rendering).
    let value = "nvim";
    let file_bytes =
        format!("# Managed by configctl (do not hand-edit managed entries)\nEDITOR={value}\n");
    assert_ne!(
        hash::env_value_hash(value),
        hash::file_content_hash(file_bytes.as_bytes()),
        "value identity must differ from the file identity that contains it"
    );
}

fn make_file_bundle(bundle: &std::path::Path, target: &str, body: &[u8]) {
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    let stem = target.trim_start_matches("~/").replace(['/', '.'], "_");
    let rel = format!("files/{stem}");
    std::fs::write(bundle.join(&rel), body).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        format!("schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"{target}\"\nsource = \"{rel}\"\n"),
    )
    .unwrap();
}

#[test]
fn plan_desired_after_matches_file_identity() {
    // Plan `desired_after` for file ops is the payload's file-content hash,
    // identical to what observe/apply/rollback compute for the same bytes.
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("work");
    let bodies: Vec<&[u8]> = vec![
        b"",
        "hello\n".as_bytes(),
        "a\r\n".as_bytes(),
        &[0x00, 0xff, 0x42],
    ];
    for (i, body) in bodies.iter().enumerate() {
        let target = format!("~/.f{i}");
        make_file_bundle(&bundle, &target, body);
        let loaded = configctl_core::profile_load::load_profile_dir(&bundle).unwrap();
        let canonical = hash::file_content_hash(body);
        let stem = target.trim_start_matches("~/").replace(['/', '.'], "_");
        assert_eq!(
            loaded.payload_hashes.get(&format!("files/{stem}")).unwrap(),
            &canonical
        );
        let mut st = ObservedState::default();
        st.files.insert(
            target.clone(),
            configctl_core::observe::FileObs {
                exists: false,
                is_symlink: false,
                is_non_regular: false,
                content_hash: None,
                len: None,
            },
        );
        let owned = std::collections::BTreeSet::new();
        let plan = plan::build_plan(&loaded, &st, &owned, &format!("id-{i}"), 1000);
        let op = plan
            .operations
            .iter()
            .find(|o| o.target == target && o.kind == OperationKind::FileCreate)
            .expect("FileCreate op");
        assert_eq!(op.desired_after.as_deref(), Some(canonical.as_str()));
    }
}

#[test]
fn plan_env_desired_after_matches_value_identity() {
    // Plan `desired_after` for env ops is the literal's value hash — the
    // same identity apply postchecks and rollback guards compare against.
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("work");
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[environment]\nEDITOR = \"nvim\"\nEMPTY_OK = \"\"\n",
    )
    .unwrap();
    let loaded = configctl_core::profile_load::load_profile_dir(&bundle).unwrap();
    let plan = plan::build_plan(
        &loaded,
        &ObservedState::default(),
        &std::collections::BTreeSet::new(),
        "env-id",
        1000,
    );
    for (var, value) in [("EDITOR", "nvim"), ("EMPTY_OK", "")] {
        let op = plan
            .operations
            .iter()
            .find(|o| o.target == var && o.kind == OperationKind::EnvironmentSchemaChange)
            .unwrap_or_else(|| panic!("env op for {var}"));
        assert_eq!(
            op.desired_after.as_deref(),
            Some(hash::env_value_hash(value).as_str()),
            "env desired_after must be the value identity for {var}"
        );
    }
}

#[test]
fn env_parse_roundtrip_is_shared_between_apply_and_rollback() {
    // The parser rollback guards use interprets bytes exactly like apply's
    // postcheck reader: first occurrence wins, comments/blanks skipped.
    let bytes = b"# Managed by configctl\nEDITOR=nvim\nEDITOR=shadowed\n\n# comment\nEMPTY=\n";
    let map = configctl_core::apply::parse_env_bytes(bytes).unwrap();
    assert_eq!(map.get("EDITOR").map(String::as_str), Some("nvim"));
    assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
    assert_eq!(map.len(), 2);
    // Non-UTF-8 is fail-closed (None), never guessed.
    assert!(configctl_core::apply::parse_env_bytes(&[0xff, 0xfe]).is_none());
}
