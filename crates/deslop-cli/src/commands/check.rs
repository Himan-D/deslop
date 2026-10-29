use super::baseline;
use super::common::scan_and_analyze;
use colored::*;
use deslop_detector::SlopDetectorEngine;
use std::path::Path;

/// Default absolute slop threshold when no baseline is given.
pub const DEFAULT_MAX_SLOP: f64 = 25.0;

/// CI gate. Without `base`: fails on an absolute slop index above `max_slop`
/// or any dependency cycle. With `base`: fails only when this change introduces
/// a new cycle or a new High/Critical finding; the absolute threshold applies
/// only if `max_slop` is given explicitly.
pub fn run(path: &Path, max_slop: Option<f64>, base: Option<&str>) -> anyhow::Result<()> {
    let (parsed, graph, findings, _elapsed) = scan_and_analyze(path)?;
    let slop_score =
        SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);

    let Some(git_ref) = base else {
        let threshold = max_slop.unwrap_or(DEFAULT_MAX_SLOP);
        let has_cycles = !graph.find_circular_dependencies().is_empty();
        println!(
            "Codebase Slop Index: {:.1} (Threshold: {:.1})",
            slop_score, threshold
        );
        if slop_score > threshold || has_cycles {
            eprintln!("{}", "error: ci gate failed: codebase exceeds allowable slop threshold or contains circular dependencies".red());
            std::process::exit(1);
        }
        println!(
            "{}",
            "ci gate passed: codebase architectural health verified.".green()
        );
        return Ok(());
    };

    let diff = baseline::diff_against(path, git_ref, &findings)?;
    println!(
        "Codebase Slop Index: {:.1} (ref '{}' was {:.1})",
        slop_score, git_ref, diff.base_slop_index
    );
    println!(
        "Changes since '{}': {} new finding(s), {} resolved",
        git_ref,
        diff.new.len(),
        diff.resolved_count
    );
    for f in diff
        .new
        .iter()
        .filter(|f| baseline::blocks_gate(std::slice::from_ref(f)))
    {
        println!(
            "  blocking: [{:?}] {} ({}:{})",
            f.severity,
            f.title,
            f.file_path.display(),
            f.line
        );
    }

    let absolute_exceeded = max_slop.is_some_and(|t| slop_score > t);
    if baseline::blocks_gate(&diff.new) || absolute_exceeded {
        eprintln!(
            "{}",
            "error: ci gate failed: this change introduces new architectural debt.".red()
        );
        std::process::exit(1);
    }
    println!("{}", "ci gate passed: no new architectural debt.".green());
    Ok(())
}
