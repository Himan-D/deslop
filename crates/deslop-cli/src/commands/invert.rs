use super::common::{print_llm_status, scan_and_analyze};
use colored::*;
use deslop_inversion::InversionEngine;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, output: Option<PathBuf>) -> anyhow::Result<()> {
    println!("{}", "deslop: architecture inversion synthesizer".bold());
    println!("target: {}\n", path.display());

    let (parsed, graph, findings, _elapsed) = scan_and_analyze(path)?;

    let codebase_name = path
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "Project".to_string());

    let inverted = InversionEngine::synthesize_spec(
        &codebase_name,
        &parsed.stats,
        &parsed.symbols,
        &parsed.edges,
        &graph,
        &findings,
    );

    let out_file = output.unwrap_or_else(|| PathBuf::from("ARCHITECTURE_SPEC.md"));
    fs::write(&out_file, &inverted.spec_markdown)?;

    println!("{}", "Architectural inversion successful.".green().bold());
    println!("--------------------------------------------------");
    println!(
        "{:<28} {} LOC -> {} LOC ({})",
        "Transformation:",
        inverted.original_loc,
        inverted.projected_loc,
        format!("-{} LOC", inverted.lines_reduced_estimate).green()
    );
    println!(
        "{:<28} {}%",
        "Abstraction Reduction:",
        format!("-{:.1}", inverted.abstraction_reduction_pct).green()
    );
    println!("{:<28} {}", "Resolved Cycles:", inverted.deloop_plans.len());
    println!(
        "{:<28} {}",
        "Target Components:",
        inverted.target_components.len()
    );
    print_llm_status();
    println!("{:<28} {}", "Output Specification:", out_file.display());
    println!("--------------------------------------------------\n");
    println!("Wrote specification to: {}", out_file.display());
    Ok(())
}
