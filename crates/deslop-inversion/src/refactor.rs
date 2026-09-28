use deslop_core::{SlopFinding, SlopKind, Symbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefactorResult {
    pub files_modified: Vec<PathBuf>,
    pub lines_deleted: usize,
    pub items_pruned: usize,
    pub loops_broken: usize,
    pub verified: bool,
    pub error: Option<String>,
}

pub struct RefactorEngine;

/// One planned file deletion (nothing written yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedDeletion {
    pub file: PathBuf,
    pub symbol_name: String,
    pub start_line: usize,
    pub lines_removed: usize,
}

/// One planned wrapper->target callsite rewrite (nothing written yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedInline {
    pub wrapper: String,
    pub target: String,
}

/// Read-only preview of what [`RefactorEngine::apply`] would change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefactorPlan {
    pub deletions: Vec<PlannedDeletion>,
    pub inlines: Vec<PlannedInline>,
}

impl RefactorPlan {
    pub fn is_empty(&self) -> bool {
        self.deletions.is_empty() && self.inlines.is_empty()
    }
}

impl RefactorEngine {
    /// Findings that `apply` physically removes (dead symbols, wrappers).
    pub fn is_prunable(finding: &SlopFinding) -> bool {
        matches!(
            finding.kind,
            SlopKind::DeadOrphan | SlopKind::TollboothWrapper
        )
    }

    /// Parses a tollbooth finding into its (wrapper, target) pair.
    pub fn inline_target(finding: &SlopFinding) -> Option<(String, String)> {
        if finding.kind != SlopKind::TollboothWrapper {
            return None;
        }
        let target = finding
            .description
            .split("forwarding calls directly to `")
            .nth(1)
            .and_then(|s| s.split('`').next())?;
        let wrapper = finding
            .title
            .trim_start_matches("Tollbooth Wrapper: `")
            .trim_end_matches('`');
        Some((wrapper.to_string(), target.to_string()))
    }

    /// Computes exactly what [`RefactorEngine::apply`] would change, without
    /// writing anything. Reads files only to measure deletion bounds.
    pub fn plan(findings: &[SlopFinding], symbols: &[Symbol]) -> anyhow::Result<RefactorPlan> {
        let mut plan = RefactorPlan::default();
        let mut seen_inline = std::collections::HashSet::new();

        for f in findings {
            if let Some((wrapper, target)) = Self::inline_target(f) {
                if seen_inline.insert((wrapper.clone(), target.clone())) {
                    plan.inlines.push(PlannedInline { wrapper, target });
                }
            }
            if !Self::is_prunable(f) {
                continue;
            }
            let content = match fs::read_to_string(&f.file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            if let Some(sym) = symbols.iter().find(|s| s.id == f.symbol_id) {
                let (start, end) = crate::lossless::LosslessRewriter::compute_symbol_pruning_bounds(
                    &lines, &sym.span,
                );
                if start < end {
                    plan.deletions.push(PlannedDeletion {
                        file: f.file_path.clone(),
                        symbol_name: sym.name.clone(),
                        start_line: start + 1,
                        lines_removed: end - start,
                    });
                }
            }
        }

        Ok(plan)
    }

    /// Applies surgical de-slopping and pruning directly to files, with automatic rollback if verification fails
    pub fn apply(
        root_dir: &Path,
        findings: &[SlopFinding],
        symbols: &[Symbol],
        test_command: Option<&str>,
    ) -> anyhow::Result<RefactorResult> {
        // Step 1: Snapshot all files for instant rollback if anything fails
        let mut snapshot: HashMap<PathBuf, String> = HashMap::new();
        for finding in findings {
            if finding.file_path.exists() && !snapshot.contains_key(&finding.file_path) {
                if let Ok(content) = fs::read_to_string(&finding.file_path) {
                    snapshot.insert(finding.file_path.clone(), content);
                }
            }
        }

        let mut modified_files = Vec::new();
        let mut lines_deleted = 0;
        let mut items_pruned = 0;
        let mut loops_broken = 0;

        // Group findings by file
        let mut file_findings: HashMap<PathBuf, Vec<&SlopFinding>> = HashMap::new();
        for f in findings {
            file_findings
                .entry(f.file_path.clone())
                .or_default()
                .push(f);
        }

        // Collect tollbooths for call-site inlining: wrapper_name -> target_name
        let mut inline_map: HashMap<String, String> = HashMap::new();
        for f in findings {
            if let Some((wrapper, target)) = Self::inline_target(f) {
                inline_map.insert(wrapper, target);
            }
        }

        // Step 2: Apply file-level modifications
        for (file_path, f_list) in &file_findings {
            let original_content = match snapshot.get(file_path) {
                Some(c) => c.clone(),
                None => continue,
            };

            let lines: Vec<String> = original_content.lines().map(|s| s.to_string()).collect();
            let original_line_count = lines.len();

            // Find symbols in this file to prune
            let mut lines_to_remove = Vec::new();
            for f in f_list {
                if Self::is_prunable(f) {
                    if let Some(sym) = symbols.iter().find(|s| s.id == f.symbol_id) {
                        let (start, end) =
                            crate::lossless::LosslessRewriter::compute_symbol_pruning_bounds(
                                &lines, &sym.span,
                            );
                        if start < end {
                            for line_idx in start..end {
                                lines_to_remove.push(line_idx);
                            }
                            items_pruned += 1;
                        }
                    }
                } else if f.kind == SlopKind::BarrelBloat {
                    loops_broken += 1;
                }
            }

            lines_to_remove.sort_unstable();
            lines_to_remove.dedup();

            // Reconstruct content without deleted lines
            let mut new_lines = Vec::new();
            for (idx, line) in lines.iter().enumerate() {
                if !lines_to_remove.contains(&idx) {
                    let mut modified_line = line.clone();
                    // Inline any known tollbooth wrappers
                    for (wrapper, target) in &inline_map {
                        modified_line = crate::lossless::LosslessRewriter::inline_callsite(
                            &modified_line,
                            wrapper,
                            target,
                        );
                    }
                    new_lines.push(modified_line);
                }
            }

            let new_content = new_lines.join("\n") + "\n";
            if new_content != original_content {
                fs::write(file_path, &new_content)?;
                modified_files.push(file_path.clone());
                let delta = original_line_count.saturating_sub(new_lines.len());
                lines_deleted += delta;
            }
        }

        // Step 3: Run Verification Command (if supplied)
        let mut verification_passed = true;
        let mut verification_error = None;

        if let Some(cmd) = test_command {
            let output = if cfg!(target_os = "windows") {
                Command::new("cmd")
                    .args(["/C", cmd])
                    .current_dir(root_dir)
                    .output()
            } else {
                Command::new("sh")
                    .args(["-c", cmd])
                    .current_dir(root_dir)
                    .output()
            };

            match output {
                Ok(out) if out.status.success() => {
                    verification_passed = true;
                }
                Ok(out) => {
                    verification_passed = false;
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    verification_error =
                        Some(format!("Test verification failed:\n{}\n{}", stderr, stdout));
                }
                Err(e) => {
                    verification_passed = false;
                    verification_error = Some(format!("Failed to execute test command: {}", e));
                }
            }
        }

        // Step 4: If verification failed, execute rollback!
        if !verification_passed {
            for (path, content) in &snapshot {
                let _ = fs::write(path, content);
            }
            return Ok(RefactorResult {
                files_modified: Vec::new(),
                lines_deleted: 0,
                items_pruned: 0,
                loops_broken: 0,
                verified: false,
                error: verification_error,
            });
        }

        Ok(RefactorResult {
            files_modified: modified_files,
            lines_deleted,
            items_pruned,
            loops_broken,
            verified: true,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{Severity, SourceSpan, SymbolKind, Visibility};

    fn finding(
        kind: SlopKind,
        file: &Path,
        symbol_id: &str,
        title: &str,
        desc: &str,
    ) -> SlopFinding {
        SlopFinding {
            kind,
            symbol_id: symbol_id.to_string(),
            file_path: file.to_path_buf(),
            line: 1,
            severity: Severity::Low,
            confidence: 0.9,
            title: title.to_string(),
            description: desc.to_string(),
            remediation: String::new(),
            estimated_lines_saved: 3,
        }
    }

    fn sym(id: &str, name: &str, file: &Path) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: file.to_path_buf(),
            span: SourceSpan::new(1, 1, 3, 2),
            visibility: Visibility::Private,
            loc: 3,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {name}()"),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    #[test]
    fn inline_target_parses_wrapper_and_target() {
        let f = finding(
            SlopKind::TollboothWrapper,
            Path::new("x.rs"),
            "x.rs::scan",
            "Tollbooth Wrapper: `scan`",
            "Function `scan` is a thin pass-through forwarding calls directly to `scan_cached` with negligible logic.",
        );
        assert_eq!(
            RefactorEngine::inline_target(&f),
            Some(("scan".to_string(), "scan_cached".to_string()))
        );
        assert!(RefactorEngine::is_prunable(&f));

        let other = finding(
            SlopKind::GodObject,
            Path::new("x.rs"),
            "x.rs::Big",
            "God",
            "",
        );
        assert_eq!(RefactorEngine::inline_target(&other), None);
        assert!(!RefactorEngine::is_prunable(&other));
    }

    #[test]
    fn plan_reports_deletions_without_writing() {
        let dir = std::env::temp_dir().join(format!("deslop-plan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sample.rs");
        fs::write(&file, "fn dead() {\n    1\n}\nfn live() {\n    2\n}\n").unwrap();

        let findings = vec![finding(
            SlopKind::DeadOrphan,
            &file,
            &format!("{}::dead", file.display()),
            "Unreachable Symbol: `dead`",
            "dead",
        )];
        let symbols = vec![sym(&format!("{}::dead", file.display()), "dead", &file)];

        let plan = RefactorEngine::plan(&findings, &symbols).unwrap();
        assert_eq!(plan.deletions.len(), 1);
        assert_eq!(plan.deletions[0].symbol_name, "dead");
        assert_eq!(plan.deletions[0].start_line, 1);
        assert!(plan.deletions[0].lines_removed >= 3);
        assert!(plan.inlines.is_empty());

        // Nothing was written.
        let after = fs::read_to_string(&file).unwrap();
        assert!(after.contains("fn dead()"));
        let _ = fs::remove_dir_all(&dir);
    }
}
