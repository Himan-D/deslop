//! End-to-end checks of the `deslop` binary: SARIF output, baseline gating,
//! and that `prune` emits patches that `git apply` accepts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn deslop() -> Command {
    Command::new(env!("CARGO_BIN_EXE_deslop"))
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app")
}

/// A fresh, empty directory unique to this test run.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("deslop-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> Output {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.email=test@example.com", "-c", "user.name=test"])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&dest).unwrap();
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn sarif_output_is_valid_and_lists_cycles() {
    let out = deslop()
        .args(["scan", fixture_dir().to_str().unwrap(), "--format", "sarif"])
        .output()
        .expect("deslop runs");
    assert!(out.status.success());
    let log: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(log["version"], "2.1.0");
    let results = log["runs"][0]["results"].as_array().expect("results array");
    assert!(
        results.iter().any(|r| r["ruleId"] == "Cycle"),
        "fixture contains a cycle, so SARIF should report a Cycle result"
    );
}

#[test]
fn scan_rejects_unknown_format() {
    let out = deslop()
        .args(["scan", fixture_dir().to_str().unwrap(), "--format", "xml"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn json_scan_marks_small_projects_as_low_confidence() {
    let out = deslop()
        .args(["scan", fixture_dir().to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["score_reliable"], false);
    let index = report["slop_index"].as_f64().unwrap();
    assert!(
        index < 100.0,
        "the score floor should keep a 50-line fixture off the saturated 100"
    );
}

#[test]
fn prune_patch_applies_with_git_apply() {
    let dir = scratch("prune");
    // Two files: a dead function in one, nothing referencing it anywhere.
    fs::write(
        dir.join("lib.rs"),
        "fn live() -> u32 {\n    7\n}\n\nfn dead_helper() -> u32 {\n    3\n}\n\nfn main() {\n    live();\n}\n",
    )
    .unwrap();
    git(&dir, &["init", "-q"]);

    let out = deslop()
        .args(["prune", dir.to_str().unwrap(), "--diff"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains("--- a/lib.rs"),
        "expected a real patch, got:\n{text}"
    );
    assert!(text.contains("-fn dead_helper() -> u32 {"));

    let patch_path = dir.join("prune.patch");
    fs::write(&patch_path, &text).unwrap();
    let check = Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["apply", "--check", "prune.patch"])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "git apply --check rejected the patch: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn baseline_reports_no_new_findings_when_tree_matches_ref() {
    let dir = scratch("baseline-same");
    copy_dir(&fixture_dir(), &dir);
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "fixture"]);

    let out = deslop()
        .args(["check", dir.to_str().unwrap(), "--base", "HEAD"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "identical tree should pass the baseline gate: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn baseline_gate_fails_when_change_introduces_a_cycle() {
    let dir = scratch("baseline-cycle");
    // Base: a clean codebase with no cycles.
    fs::write(dir.join("util.rs"), "pub fn leaf() -> u32 {\n    1\n}\n").unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "clean base"]);

    // Working tree: the fixture, which contains a dependency cycle.
    copy_dir(&fixture_dir(), &dir);

    let out = deslop()
        .args(["check", dir.to_str().unwrap(), "--base", "HEAD"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a change that adds a cycle must fail the gate: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let scan = deslop()
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--base",
            "HEAD",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(report["baseline"]["git_ref"], "HEAD");
    assert!(report["baseline"]["new_findings"].as_u64().unwrap() > 0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn invalid_baseline_ref_is_a_clear_error() {
    let dir = scratch("baseline-bad-ref");
    fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "init"]);
    let out = deslop()
        .args(["scan", dir.to_str().unwrap(), "--base", "no-such-ref"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-such-ref"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn apply_rolls_back_on_failed_verification_and_prunes_on_success() {
    let original = "fn live() -> u32 {\n    7\n}\n\nfn dead_helper() -> u32 {\n    3\n}\n\nfn main() {\n    live();\n}\n";

    // Failing verification: the dead function must come back out of the file.
    let dir = scratch("apply-rollback");
    fs::write(dir.join("lib.rs"), original).unwrap();
    let out = deslop()
        .args(["apply", dir.to_str().unwrap(), "--verify", "exit 1"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "failed verification must exit non-zero"
    );
    assert_eq!(fs::read_to_string(dir.join("lib.rs")).unwrap(), original);
    let _ = fs::remove_dir_all(&dir);

    // Passing verification: the dead function is removed.
    let dir = scratch("apply-prune");
    fs::write(dir.join("lib.rs"), original).unwrap();
    let out = deslop()
        .args(["apply", dir.to_str().unwrap(), "--verify", "true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = fs::read_to_string(dir.join("lib.rs")).unwrap();
    assert!(!after.contains("dead_helper"));
    assert!(after.contains("fn live()"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn project_under_a_tests_parent_is_not_treated_as_test_code() {
    // Regression: directory roles must be judged relative to the scan root.
    let root = scratch("tests-parent").join("tests").join("app");
    fs::create_dir_all(&root).unwrap();
    copy_dir(&fixture_dir(), &root);

    let out = deslop()
        .args(["scan", root.to_str().unwrap(), "--format", "sarif"])
        .output()
        .unwrap();
    let log: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert!(
        results.iter().any(|r| r["ruleId"] == "Cycle"),
        "a cycle must still be reported when the project lives under a tests/ parent"
    );
    let _ = fs::remove_dir_all(root.parent().unwrap().parent().unwrap());
}
