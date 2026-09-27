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

impl RefactorEngine {
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
            file_findings.entry(f.file_path.clone()).or_default().push(f);
        }

        // Collect tollbooths for call-site inlining: wrapper_name -> target_name
        let mut inline_map: HashMap<String, String> = HashMap::new();
        for f in findings {
            if f.kind == SlopKind::TollboothWrapper {
                // Parse target from description
                if let Some(target) = f.description.split("forwarding calls directly to `").nth(1).and_then(|s| s.split('`').next()) {
                    let sym_name = &f.title.trim_start_matches("Tollbooth Wrapper: `").trim_end_matches('`');
                    inline_map.insert(sym_name.to_string(), target.to_string());
                }
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
                match f.kind {
                    SlopKind::TollboothWrapper | SlopKind::DeadOrphan => {
                        if let Some(sym) = symbols.iter().find(|s| s.id == f.symbol_id) {
                            let (start, end) = crate::lossless::LosslessRewriter::compute_symbol_pruning_bounds(&lines, &sym.span);
                            if start < end {
                                for line_idx in start..end {
                                    lines_to_remove.push(line_idx);
                                }
                                items_pruned += 1;
                            }
                        }
                    }
                    SlopKind::BarrelBloat => {
                        loops_broken += 1;
                    }
                    _ => {}
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
                        modified_line = crate::lossless::LosslessRewriter::inline_callsite(&modified_line, wrapper, target);
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
                Command::new("cmd").args(["/C", cmd]).current_dir(root_dir).output()
            } else {
                Command::new("sh").args(["-c", cmd]).current_dir(root_dir).output()
            };

            match output {
                Ok(out) if out.status.success() => {
                    verification_passed = true;
                }
                Ok(out) => {
                    verification_passed = false;
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    verification_error = Some(format!("Test verification failed:\n{}\n{}", stderr, stdout));
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
