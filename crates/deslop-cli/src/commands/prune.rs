use super::baseline::relative_key;
use super::common::{callsite_index, scan_and_analyze};
use colored::*;
use deslop_inversion::{FileRewrite, RefactorEngine};
use similar::TextDiff;
use std::fs;
use std::path::{Path, PathBuf};

/// Renders real unified-diff hunks for each rewritten file. Paths are relative
/// to `root`, so the patch applies with `git apply` run from that directory.
pub fn unified_patch(root: &Path, rewrites: &[FileRewrite]) -> String {
    let mut out = String::new();
    for r in rewrites {
        let rel = relative_key(&r.path, root);
        let diff = TextDiff::from_lines(&r.original, &r.updated);
        out.push_str(
            &diff
                .unified_diff()
                .context_radius(3)
                .header(&format!("a/{rel}"), &format!("b/{rel}"))
                .to_string(),
        );
    }
    out
}

pub fn run(path: &Path, diff: bool, output: Option<PathBuf>) -> anyhow::Result<()> {
    println!("{}", "deslop: automated refactor & prune preview".bold());
    println!("target: {}\n", path.display());

    let (parsed, _graph, findings, _elapsed) = scan_and_analyze(path)?;
    let callsites = callsite_index(&parsed);
    let set = RefactorEngine::rewrite_set(&findings, &parsed.symbols, &callsites)?;

    for skipped in &set.plan.skipped {
        eprintln!(
            "{} {} ({}): {}",
            "skipped".yellow(),
            skipped.symbol_name,
            skipped.file.display(),
            skipped.reason
        );
    }

    if set.rewrites.is_empty() {
        println!("{}", "No dead code or tollbooth wrappers to prune.".green());
        return Ok(());
    }

    let patch = unified_patch(path, &set.rewrites);
    if let Some(out_path) = output {
        fs::write(&out_path, &patch)?;
        println!(
            "Saved patch ({} file(s)) to: {}",
            set.rewrites.len(),
            out_path.display()
        );
        println!("Apply with: git apply {}", out_path.display());
    } else if diff {
        print!("{}", patch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_inversion::FileRewrite;

    #[test]
    fn unified_patch_has_real_hunks() {
        let rewrite = FileRewrite {
            path: PathBuf::from("/nonexistent-root/src/a.rs"),
            original: "fn dead() {\n    1\n}\nfn live() {}\n".to_string(),
            updated: "fn live() {}\n".to_string(),
            items_pruned: 1,
        };
        let patch = unified_patch(Path::new("/nonexistent-root"), &[rewrite]);
        assert!(patch.contains("--- a/src/a.rs"));
        assert!(patch.contains("+++ b/src/a.rs"));
        assert!(patch.contains("-fn dead() {"));
        assert!(patch.contains("-}"));
        assert!(patch.contains("+fn live() {}") || patch.contains(" fn live() {}"));
    }
}
