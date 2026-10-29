//! Baseline diffing: report only findings that a change introduced relative to a git ref.
//!
//! Findings are matched by a fingerprint of kind, relative file path, and title.
//! Line numbers are deliberately excluded so that unrelated edits above a
//! finding do not make it look new.

use super::common::scan_and_analyze;
use anyhow::{bail, Context};
use deslop_core::{Severity, SlopFinding, SlopKind};
use deslop_detector::SlopDetectorEngine;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The result of comparing the current tree against a git ref.
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    pub git_ref: String,
    pub base_slop_index: f64,
    /// Findings present now but absent at the ref.
    pub new: Vec<SlopFinding>,
    /// Findings present at the ref but gone now.
    pub resolved_count: usize,
}

/// Writes `git_ref` of the repository containing `target` (restricted to the
/// `target` subtree) into a fresh temp directory and returns that directory.
pub fn checkout_ref(target: &Path, git_ref: &str) -> anyhow::Result<PathBuf> {
    let tmp = std::env::temp_dir();
    let stamp = format!("{}-{}", std::process::id(), sanitize(git_ref));
    let dir = tmp.join(format!("deslop-base-{stamp}"));
    let tar = tmp.join(format!("deslop-base-{stamp}.tar"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let archive = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(["archive", "--format=tar", "-o"])
        .arg(&tar)
        .arg(git_ref)
        .arg(".")
        .output()
        .context("failed to run git (is git installed?)")?;
    if !archive.status.success() {
        let _ = fs::remove_dir_all(&dir);
        bail!(
            "git archive failed for ref '{}': {}",
            git_ref,
            String::from_utf8_lossy(&archive.stderr).trim()
        );
    }
    let extract = Command::new("tar")
        .arg("-xf")
        .arg(&tar)
        .arg("-C")
        .arg(&dir)
        .status()
        .context("failed to run tar")?;
    let _ = fs::remove_file(&tar);
    if !extract.success() {
        let _ = fs::remove_dir_all(&dir);
        bail!("failed to extract ref '{}'", git_ref);
    }
    Ok(dir)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A path relative to `root`, using forward slashes, for stable fingerprints.
pub fn relative_key(file: &Path, root: &Path) -> String {
    let abs_file = absolute(file);
    let abs_root = absolute(root);
    abs_file
        .strip_prefix(&abs_root)
        .unwrap_or(&abs_file)
        .to_string_lossy()
        .replace('\\', "/")
}

fn absolute(p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    joined.canonicalize().unwrap_or(joined)
}

/// Line-independent identity of a finding within a repository.
pub fn fingerprint(f: &SlopFinding, root: &Path) -> String {
    format!(
        "{:?}|{}|{}",
        f.kind,
        relative_key(&f.file_path, root),
        f.title
    )
}

/// Scans the tree at `git_ref` and diffs it against `current`.
pub fn diff_against(
    target: &Path,
    git_ref: &str,
    current: &[SlopFinding],
) -> anyhow::Result<BaselineDiff> {
    let base_root = checkout_ref(target, git_ref)?;
    let result = scan_and_analyze(&base_root);
    let outcome = match result {
        Ok((parsed, _graph, base_findings, _elapsed)) => {
            let base_slop_index = SlopDetectorEngine::calculate_slop_index(
                parsed.stats.total_lines_of_code,
                &base_findings,
            );
            let base_keys: HashSet<String> = base_findings
                .iter()
                .map(|f| fingerprint(f, &base_root))
                .collect();
            let current_keys: HashSet<String> =
                current.iter().map(|f| fingerprint(f, target)).collect();
            let new = current
                .iter()
                .filter(|f| !base_keys.contains(&fingerprint(f, target)))
                .cloned()
                .collect();
            let resolved_count = base_keys.difference(&current_keys).count();
            Ok(BaselineDiff {
                git_ref: git_ref.to_string(),
                base_slop_index,
                new,
                resolved_count,
            })
        }
        Err(e) => Err(e),
    };
    let _ = fs::remove_dir_all(&base_root);
    outcome
}

/// Whether a set of new findings should fail a gate: any new cycle, or any
/// new finding at High severity or above.
pub fn blocks_gate(new: &[SlopFinding]) -> bool {
    new.iter()
        .any(|f| f.kind == SlopKind::Cycle || f.severity >= Severity::High)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: SlopKind, file: &str, title: &str, line: usize) -> SlopFinding {
        SlopFinding {
            kind,
            symbol_id: format!("{file}::x"),
            file_path: PathBuf::from(file),
            line,
            severity: Severity::Medium,
            confidence: 0.9,
            title: title.to_string(),
            description: String::new(),
            remediation: String::new(),
            estimated_lines_saved: 0,
        }
    }

    #[test]
    fn fingerprint_ignores_line_numbers() {
        let root = Path::new(".");
        let a = finding(
            SlopKind::DeadOrphan,
            "src/a.rs",
            "Unreachable Symbol: `f`",
            3,
        );
        let b = finding(
            SlopKind::DeadOrphan,
            "src/a.rs",
            "Unreachable Symbol: `f`",
            90,
        );
        assert_eq!(fingerprint(&a, root), fingerprint(&b, root));
        let c = finding(
            SlopKind::DeadOrphan,
            "src/a.rs",
            "Unreachable Symbol: `g`",
            3,
        );
        assert_ne!(fingerprint(&a, root), fingerprint(&c, root));
    }

    #[test]
    fn gate_blocks_new_cycles_and_high_findings_only() {
        let mut medium = finding(SlopKind::GodObject, "a.rs", "t", 1);
        medium.severity = Severity::Medium;
        assert!(!blocks_gate(&[medium.clone()]));

        let mut high = medium.clone();
        high.severity = Severity::High;
        assert!(blocks_gate(&[high]));

        let cycle = finding(SlopKind::Cycle, "a.rs", "loop", 1);
        assert!(blocks_gate(&[cycle]));
    }

    #[test]
    fn sanitize_keeps_refs_path_safe() {
        assert_eq!(sanitize("feature/x y"), "feature_x_y");
    }
}
