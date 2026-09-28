use super::common::{print_llm_status, scan_and_analyze, FindingRow};
use colored::*;
use deslop_core::format_location;
use deslop_core::Severity;
use deslop_detector::SlopDetectorEngine;
use deslop_llm::LlmClient;
use serde::Serialize;
use std::path::Path;
use tabled::Table;

/// Machine-readable scan result for CI pipelines and coding agents.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target: String,
    pub slop_index: f64,
    pub total_files: usize,
    pub total_lines_of_code: usize,
    pub total_symbols: usize,
    pub prunable_lines: usize,
    pub finding_count: usize,
    pub findings: Vec<deslop_core::SlopFinding>,
}

pub fn build_scan_report(
    path: &Path,
    parsed: &deslop_parser::ParsedCodebase,
    findings: Vec<deslop_core::SlopFinding>,
) -> ScanReport {
    let slop_index =
        SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);
    ScanReport {
        target: path.display().to_string(),
        slop_index,
        total_files: parsed.stats.total_files,
        total_lines_of_code: parsed.stats.total_lines_of_code,
        total_symbols: parsed.stats.total_symbols,
        prunable_lines: findings.iter().map(|f| f.estimated_lines_saved).sum(),
        finding_count: findings.len(),
        findings,
    }
}

pub fn run(path: &Path, detailed: bool, explain: bool, format: &str) -> anyhow::Result<()> {
    let (parsed, _graph, findings, elapsed) = scan_and_analyze(path)?;

    if format == "json" {
        // JSON mode emits everything; consumers slice client-side.
        let report = build_scan_report(path, &parsed, findings);
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "deslop: codebase architectural scanner".bold());
    println!("target: {}\n", path.display());

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

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{Severity, SlopFinding, SlopKind};
    use std::path::PathBuf;

    fn finding(lines_saved: usize) -> SlopFinding {
        SlopFinding {
            kind: SlopKind::TollboothWrapper,
            symbol_id: "lib.rs::scan".to_string(),
            file_path: PathBuf::from("lib.rs"),
            line: 1,
            severity: Severity::Low,
            confidence: 0.85,
            title: "Tollbooth Wrapper: `scan`".to_string(),
            description: "thin wrapper".to_string(),
            remediation: "inline".to_string(),
            estimated_lines_saved: lines_saved,
        }
    }

    #[test]
    fn scan_report_aggregates_score_and_savings() {
        let parsed = deslop_parser::ParsedCodebase {
            root_dir: PathBuf::from("."),
            symbols: Vec::new(),
            edges: Vec::new(),
            imports: Default::default(),
            stats: deslop_core::CodebaseStats {
                total_files: 2,
                total_lines_of_code: 1000,
                total_symbols: 10,
                languages: Vec::new(),
            },
        };
        let report = build_scan_report(Path::new("."), &parsed, vec![finding(3), finding(7)]);
        assert_eq!(report.finding_count, 2);
        assert_eq!(report.prunable_lines, 10);
        assert_eq!(report.total_files, 2);
        // 2 LOW findings = 3.0 penalty over 1000 LOC -> 3.0 index.
        assert_eq!(report.slop_index, 3.0);
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(json.contains("\"slop_index\":3.0"));
        assert!(json.contains("\"finding_count\":2"));
    }
}
