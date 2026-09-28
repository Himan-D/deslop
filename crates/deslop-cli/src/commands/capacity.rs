use super::common::scan_and_analyze;
use colored::*;
use deslop_graph::{CapacityAnalyzer, GraphAnalyzer};
use std::path::Path;

pub fn run(path: &Path) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: heuristic capacity & failure point estimator".bold()
    );
    println!("target: {}\n", path.display());

    let (_parsed, graph, _findings, elapsed) = scan_and_analyze(path)?;

    let report = CapacityAnalyzer::analyze(&graph);

    println!("--------------------------------------------------");
    println!(
        "{:<28} {}",
        "Scalability Grade:",
        report.scalability_grade.green()
    );
    println!(
        "{:<28} {}",
        "Complexity Class:", report.estimated_complexity_class
    );
    println!(
        "{:<28} {}",
        "Detected Breaking Risks:",
        report.breaking_risks.len()
    );
    println!(
        "{:<28} {}",
        "Analysis Latency:",
        format!("{:.2?}", elapsed).green()
    );
    println!("--------------------------------------------------\n");

    println!("Heuristic device concurrency projections (order-of-magnitude only):\n");
    println!(
        "{:<36} {:<16} {:<14} {:<24}",
        "Hardware Device Profile", "~Est. CCU*", "~Est. RPS*", "Primary Bottleneck"
    );
    println!(
        "-----------------------------------------------------------------------------------------"
    );
    for est in &report.estimates {
        println!(
            "{:<36} {:<16} {:<14} {:<24}",
            est.device.name,
            format!("~{} users", est.max_concurrent_users).green(),
            format!("{} req/s", est.max_requests_per_sec),
            est.bottleneck_resource
        );
    }
    println!(
        "-----------------------------------------------------------------------------------------"
    );
    println!("* Static-analysis heuristic, not a load test. Validate with real benchmarks.\n");

    if !report.breaking_risks.is_empty() {
        println!("Potential failure points under load (heuristic):\n");
        for (i, risk) in report.breaking_risks.iter().enumerate() {
            println!("--------------------------------------------------");
            println!(
                "{}. {} ({})",
                i + 1,
                risk.trigger_pattern.bold().red(),
                risk.failure_mode.yellow()
            );
            println!("   {:<22} {}", "Location:", risk.file_location);
            let sym_display = if risk.affected_symbol.len() > 70 {
                format!("{}...", &risk.affected_symbol[..67])
            } else {
                risk.affected_symbol.clone()
            };
            println!("   {:<22} {}", "Symbol / Chain:", sym_display);
            println!(
                "   {:<22} {}",
                "Heuristic Threshold:",
                risk.estimated_breaking_threshold.red()
            );
            println!("   {:<22} {}", "Remediation:", risk.recommendation);
        }
        println!("--------------------------------------------------\n");
    } else {
        println!(
            "{}",
            "No critical saturation or unbounded memory breaking points detected.".green()
        );
    }
    Ok(())
}
