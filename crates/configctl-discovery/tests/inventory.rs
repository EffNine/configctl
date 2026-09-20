//! Inventory collector tests: symlinks, cycles, special files, evidence.

use configctl_discovery::inventory::InventoryCollector;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;

fn meta_of(p: &std::path::Path) -> (std::fs::FileType, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).unwrap();
    (m.file_type(), Some(m.mode()))
}

#[test]
fn symlink_chain_resolves_with_bounded_depth() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&b, b"real").unwrap();
    symlink(&b, &a).unwrap();
    let (ft, mode) = meta_of(&a);
    assert!(ft.is_symlink());
    let mut col = InventoryCollector::new();
    col.observe(&a, &ft, mode);
    assert_eq!(col.counters().symlinks, 1);
    let rec = &col.symlinks()[0];
    assert!(rec.target_exists);
    assert_eq!(rec.cycle, None);
}

#[test]
fn symlink_cycle_terminates_and_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    let (ft, mode) = meta_of(&a);
    let mut col = InventoryCollector::new();
    col.observe(&a, &ft, mode);
    let rec = &col.symlinks()[0];
    assert_eq!(rec.cycle, Some(true));
}

#[test]
fn dangling_symlink_is_recorded_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("dangling");
    symlink("/nonexistent-target-xyz", &a).unwrap();
    let (ft, mode) = meta_of(&a);
    let mut col = InventoryCollector::new();
    col.observe(&a, &ft, mode);
    assert_eq!(col.counters().symlinks, 1);
    assert!(!col.symlinks()[0].target_exists);
}

#[test]
fn socket_is_counted_as_special() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let (ft, mode) = meta_of(&sock);
    let mut col = InventoryCollector::new();
    col.observe(&sock, &ft, mode);
    assert_eq!(col.counters().sockets, 1);
    assert_eq!(col.completeness().observed, 1);
    assert_eq!(col.completeness().mapped, 1);
}

#[test]
fn skips_require_explicit_reasons() {
    let mut col = InventoryCollector::new();
    col.record_skip("permission_denied", 3);
    col.record_skip("external_mount", 2);
    let mut r = col.completeness().clone();
    r.finalize(false);
    assert_eq!(r.skipped, 5);
    assert_eq!(r.status, Some(configctl_core::inventory::ScanStatus::Partial));
}

#[test]
fn file_classification_counts_accumulate() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("Cargo.lock");
    std::fs::write(&lock, b"x").unwrap();
    let mut col = InventoryCollector::new();
    let entry = col.observe_file(&lock, Some(1), false);
    assert_eq!(
        entry.classification,
        configctl_core::classify::ResourceClass::Reproducible
    );
    assert!(!entry.reason.is_empty());
    assert_eq!(col.class_counts().get("reproducible"), Some(&1));
}
