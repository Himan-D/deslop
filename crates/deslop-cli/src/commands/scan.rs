use super::common::{print_llm_status, scan_and_analyze, FindingRow};
use colored::*;
use deslop_core::format_location;
use deslop_core::Severity;
use deslop_detector::SlopDetectorEngine;
use deslop_llm::LlmClient;
use std::path::Path;
use tabled::Table;

pub fn run(path: &Path, detailed: bool, explain: bool) -> anyhow::Result<()> {
    println!("{}", "deslop: codebase architectural scanner".bold());
    println!("target: {}\n", path.display());

    let (parsed, _graph, findings, elapsed) = scan_and_analyze(path)?;

    let slop_score =
        SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);

    let score_colored = if slop_score < 15.0 {
        format!("{:.1} / 100 [clean]", slop_score).green().bold()
    } else if slop_score < 35.0 {
        format!("{:.1} / 100 [moderate debt]", slop_score)
            .yellow()
            .bold()
    } else {
        format!("{:.1} / 100 [high slop / over-engineered]", slop_score)
            .red()
            .bold()
    };

    let loc_per_sec = if elapsed.as_secs_f64() > 0.0 {
        (parsed.stats.total_lines_of_code as f64 / elapsed.as_secs_f64()) as usize
    } else {
        parsed.stats.total_lines_of_code * 1000
    };

    println!("--------------------------------------------------");
    println!("{:<28} {}", "Total Source Files:", parsed.stats.total_files);
    println!(
        "{:<28} {}",
        "Lines of Code (LOC):", parsed.stats.total_lines_of_code
    );
    println!("{:<28} {}", "Parsed Symbols:", parsed.stats.total_symbols);
    println!("{:<28} {}", "Architectural Slop Index:", score_colored);
    let total_saved: usize = findings.iter().map(|f| f.estimated_lines_saved).sum();
    println!(
        "{:<28} {}",
        "Prunable Bloat:",
        format!("~{} lines", total_saved).green()
    );
    println!(
        "{:<28} {} ({} LOC/s)",
        "Analysis Latency:",
        format!("{:.2?}", elapsed).green(),
        loc_per_sec
    );
    print_llm_status();
    println!("--------------------------------------------------\n");

    if findings.is_empty() {
        println!(
            "{}",
            "No slop or architectural anti-patterns detected.".green()
        );
        return Ok(());
    }

    println!("Findings: {}", findings.len());

    let rows: Vec<FindingRow> = findings
        .iter()
        .take(if detailed { findings.len() } else { 15 })
        .map(|f| {
            let sev_str = match f.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".cyan().to_string(),
            };
            let title_trunc = if f.title.len() > 48 {
                format!("{}...", &f.title[..45])
            } else {
                f.title.clone()
            };
            FindingRow {
                severity: sev_str,
                kind: format!("{:?}", f.kind),
                title: title_trunc,
                location: format_location(f),
                saved: format!("~{} LOC", f.estimated_lines_saved),
            }
        })
        .collect();

    let table = Table::new(rows).to_string();
    println!("{}\n", table);

    if !detailed && findings.len() > 15 {
        println!(
            "Note: showing top 15 of {} findings. Use --detailed to view all.\n",
            findings.len()
        );
    }

    if explain {
        let llm = LlmClient::auto_detect();
        if llm.is_offline() {
            println!("Explanations (deterministic — no API key):\n");
        } else {
            println!("Explanations:\n");
        }
        for f in findings.iter().take(5) {
            println!("--- {} ---", f.title.bold());
            println!(
                "{}\n",
                llm.explain(&f.title, &f.description, &f.remediation)
            );
        }
    }

    println!("Run 'deslop deloop' to inspect cycle breaking strategies.");
    println!("Run 'deslop invert' to synthesize a de-slopped architectural specification.\n");

    Ok(())
}
