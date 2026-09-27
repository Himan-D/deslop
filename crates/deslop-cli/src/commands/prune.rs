use super::common::scan_and_analyze;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, diff: bool, output: Option<PathBuf>) -> anyhow::Result<()> {
    println!("{}", "deslop: automated refactor & prune preview".bold());
    println!("target: {}\n", path.display());

    let (_parsed, _graph, findings, _elapsed) = scan_and_analyze(path)?;
    let prunable: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                deslop_core::SlopKind::DeadOrphan | deslop_core::SlopKind::TollboothWrapper
            )
        })
        .collect();

    if prunable.is_empty() {
        println!("{}", "No dead code or tollbooth wrappers to prune.".green());
        return Ok(());
    }

    let mut patch = String::new();
    patch.push_str("# Deslop Refactoring Patch\n");
    patch.push_str(&format!("# Target: {}\n", path.display()));
    patch.push_str(&format!("# Prunable Items: {}\n\n", prunable.len()));

    for p in &prunable {
        patch.push_str(&format!("--- a/{}\n", p.file_path.display()));
        patch.push_str(&format!("+++ b/{}\n", p.file_path.display()));
        patch.push_str(&format!(
            "@@ -{},{} +{},0 @@ # Prune {}\n",
            p.line, p.estimated_lines_saved, p.line, p.title
        ));
        patch.push_str(&format!(
            "- // Deleted {} (~{} LOC)\n\n",
            p.title, p.estimated_lines_saved
        ));
    }

    if let Some(out_path) = output {
        fs::write(&out_path, &patch)?;
        println!("Saved patch file to: {}", out_path.display());
    } else if diff {
        println!("{}", patch);
    }
    Ok(())
}
