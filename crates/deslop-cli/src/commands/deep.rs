use super::common::scan_and_analyze;
use colored::*;
use deslop_graph::{DeepAnalyzer, GraphAnalyzer};
use std::path::Path;

pub fn run(path: &Path) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: deep architectural analysis & module physics".bold()
    );
    println!("target: {}\n", path.display());

    let (_parsed, graph, _findings, elapsed) = scan_and_analyze(path)?;
    let report = DeepAnalyzer::analyze(&graph);

    println!("--------------------------------------------------");
    println!(
        "{:<28} {:.2}",
        "Average Module Depth Ratio:", report.average_depth_ratio
    );
    println!(
        "{:<28} {}",
        "Analyzed Modules:",
        report.module_metrics.len()
    );
    println!(
        "{:<28} {}",
        "Architectural Chokepoints:",
        report.bottlenecks.len()
    );
    println!(
        "{:<28} {}",
        "Analysis Latency:",
        format!("{:.2?}", elapsed).green()
    );
    println!("--------------------------------------------------\n");

    println!("Package coupling & main sequence metrics:\n");
    println!(
        "{:<24} {:<6} {:<6} {:<8} {:<8} {:<8} {:<32}",
        "Module", "Ca", "Ce", "Instab", "Abstr", "Dist (D)", "Classification"
    );
    println!("--------------------------------------------------------------------------------------------------");
    for m in &report.module_metrics {
        let class_color = if m.classification.starts_with("Main Sequence") {
            m.classification.green()
        } else if m.classification.starts_with("Zone of Pain") {
            m.classification.red().bold()
        } else if m.classification.starts_with("Zone of Uselessness") {
            m.classification.yellow()
        } else {
            m.classification.cyan()
        };
        println!(
            "{:<24} {:<6} {:<6} {:<8.2} {:<8.2} {:<8.2} {:<32}",
            m.module_name,
            m.afferent_coupling,
            m.efferent_coupling,
            m.instability,
            m.abstractness,
            m.distance_from_main_seq,
            class_color
        );
    }
    println!("--------------------------------------------------------------------------------------------------\n");

    if !report.bottlenecks.is_empty() {
        println!("Architectural bottlenecks & single points of failure:\n");
        for (i, b) in report.bottlenecks.iter().enumerate() {
            let sev = if b.is_critical_chokepoint {
                "CRITICAL CHOKEPOINT".red().bold().to_string()
            } else {
                "MODERATE CHOKEPOINT".yellow().to_string()
            };
            println!(
                "  {}. [{}] {} (reaches {:.1}% of graph, {} nodes) at {}",
                i + 1,
                sev,
                b.symbol_name.bold(),
                b.downstream_reach_pct,
                b.dominated_node_count,
                b.file_path
            );
        }
        println!();
    }

    if !report.deep_module_scores.is_empty() {
        println!("Deep module index (highest implementation power / interface complexity):\n");
        let mut top_deep: Vec<_> = report
            .deep_module_scores
            .iter()
            .filter(|s| s.is_deep)
            .collect();
        top_deep.sort_by(|a, b| {
            b.depth_ratio
                .partial_cmp(&a.depth_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for s in top_deep.iter().take(5) {
            println!(
                "  * {} (depth ratio: {:.1}x - LOC: {}, power: {})",
                s.symbol_name.green().bold(),
                s.depth_ratio,
                s.implementation_power,
                s.interface_complexity
            );
        }
        println!();
    }
    Ok(())
}
