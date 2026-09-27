use super::common::scan_and_analyze;
use colored::*;
use deslop_detector::SlopDetectorEngine;
use std::path::Path;

pub fn run(path: &Path, max_slop: f64) -> anyhow::Result<()> {
    let (parsed, graph, findings, _elapsed) = scan_and_analyze(path)?;
    let slop_score =
        SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);

    let has_cycles = !graph.find_circular_dependencies().is_empty();

    println!(
        "Codebase Slop Index: {:.1} (Threshold: {:.1})",
        slop_score, max_slop
    );

    if slop_score > max_slop || has_cycles {
        eprintln!("{}", "error: ci gate failed: codebase exceeds allowable slop threshold or contains circular dependencies".red());
        std::process::exit(1);
    } else {
        println!(
            "{}",
            "ci gate passed: codebase architectural health verified.".green()
        );
    }
    Ok(())
}
