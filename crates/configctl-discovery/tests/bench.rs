//! v1.1 performance benchmarks (bounded fixtures, printed measurements).
//!
//! These are correctness-bounded perf tests, not criterion benches: each
//! builds a realistic fixture, scans it, prints throughput, and asserts a
//! generous wall-clock ceiling so regressions hang the suite loudly instead
//! of silently. Run with `-- --nocapture` to see the numbers.

use configctl_core::command::FakeCommandRunner;
use configctl_core::governor::GovernorBudgets;
use configctl_discovery::scanner::{ScanOptions, Scanner};
use std::time::Instant;

fn bench_scan(label: &str, root: &std::path::Path, ceiling_secs: u64) {
    let runner = FakeCommandRunner::new();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![root.to_path_buf()],
        limits: Default::default(),
        governor: GovernorBudgets::default(),
    };
    let start = Instant::now();
    let result = scanner.scan(&opts, &runner);
    let elapsed = start.elapsed();
    let files = result.filesystem.counters.files
        + result.filesystem.counters.directories
        + result.filesystem.counters.symlinks;
    let rate = files as f64 / elapsed.as_secs_f64().max(0.001);
    eprintln!(
        "BENCH {label}: files={files} elapsed={elapsed:?} rate={rate:.0}/s \
         bytes={} subprocesses={} completeness={:.2}% status={:?}",
        result.governor.bytes_read,
        result.governor.subprocesses_total,
        result.completeness.completeness_pct(),
        result.completeness.status,
    );
    assert!(
        elapsed.as_secs() < ceiling_secs,
        "{label} exceeded {ceiling_secs}s: {elapsed:?}"
    );
}

#[test]
fn bench_10k_files() {
    let tmp = tempfile::tempdir().unwrap();
    for d in 0..100 {
        let dir = tmp.path().join(format!("pkg{d:03}"));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        for f in 0..100 {
            std::fs::write(dir.join(format!("mod{f:03}.rs")), b"pub fn x() {}\n").unwrap();
        }
        std::fs::write(dir.join("Cargo.toml"), b"[package]\n").unwrap();
    }
    bench_scan("10k-files", tmp.path(), 120);
}

#[test]
fn bench_many_small_projects() {
    let tmp = tempfile::tempdir().unwrap();
    for p in 0..50 {
        let proj = tmp.path().join(format!("proj{p:02}"));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("package.json"), b"{}\n").unwrap();
        std::fs::write(proj.join(".env"), b"PORT=3000\n").unwrap();
        std::fs::write(proj.join("README.md"), b"# hi\n").unwrap();
    }
    bench_scan("50-projects", tmp.path(), 120);
}

#[test]
fn bench_symlink_heavy_tree() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("target.txt"), b"data\n").unwrap();
    for i in 0..2000 {
        std::os::unix::fs::symlink(
            tmp.path().join("target.txt"),
            tmp.path().join(format!("l{i:04}")),
        )
        .unwrap();
    }
    bench_scan("2000-symlinks", tmp.path(), 120);
}

#[test]
fn bench_deep_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let mut p = tmp.path().to_path_buf();
    for i in 0..200 {
        p = p.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("leaf.txt"), b"x\n").unwrap();
    bench_scan("200-deep", tmp.path(), 120);
}
