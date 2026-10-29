use super::baseline::{self, BaselineDiff};
use super::common::{print_llm_status, scan_and_analyze, FindingRow};
use super::sarif::to_sarif;
use colored::*;
use deslop_core::format_location;
use deslop_core::Severity;
use deslop_detector::{score_is_reliable, SlopDetectorEngine, MIN_SCORED_LOC};
use deslop_llm::LlmClient;
use serde::Serialize;
use std::path::Path;
use tabled::Table;

/// Baseline comparison details, present when `--base` was used.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineSummary {
    pub git_ref: String,
    pub base_slop_index: f64,
    pub new_findings: usize,
    pub resolved_findings: usize,
}

/// Machine-readable scan result for CI pipelines and coding agents.
///
/// `slop_index` always describes the whole tree. When a baseline is in use,
/// `findings` lists only the findings that are new relative to that ref.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target: String,
    pub slop_index: f64,
    /// False below `MIN_SCORED_LOC`; the index is then low-confidence.
    pub score_reliable: bool,
    pub total_files: usize,
    pub total_lines_of_code: usize,
    pub total_symbols: usize,
    pub prunable_lines: usize,
    pub finding_count: usize,
    pub findings: Vec<deslop_core::SlopFinding>,
    pub baseline: Option<BaselineSummary>,
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
        score_reliable: score_is_reliable(parsed.stats.total_lines_of_code),
        total_files: parsed.stats.total_files,
        total_lines_of_code: parsed.stats.total_lines_of_code,
        total_symbols: parsed.stats.total_symbols,
        prunable_lines: findings.iter().map(|f| f.estimated_lines_saved).sum(),
        finding_count: findings.len(),
        findings,
        baseline: None,
    }
}

pub fn run(
    path: &Path,
    detailed: bool,
    explain: bool,
    format: &str,
    base: Option<&str>,
) -> anyhow::Result<()> {
    if !matches!(format, "table" | "json" | "sarif") {
        anyhow::bail!(
            "unknown --format '{}': expected table, json, or sarif",
            format
        );
    }
    let (parsed, _graph, all_findings, elapsed) = scan_and_analyze(path)?;
    let slop_score =
        SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &all_findings);

    let diff: Option<BaselineDiff> = match base {
        Some(git_ref) => Some(baseline::diff_against(path, git_ref, &all_findings)?),
        None => None,
    };
    let findings = match &diff {
        Some(d) => d.new.clone(),
        None => all_findings,
    };

    match format {
        "json" => {
            let mut report = build_scan_report(path, &parsed, findings);
            report.slop_index = slop_score;
            report.baseline = diff.as_ref().map(|d| BaselineSummary {
                git_ref: d.git_ref.clone(),
                base_slop_index: d.base_slop_index,
                new_findings: d.new.len(),
                resolved_findings: d.resolved_count,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        "sarif" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&to_sarif(&findings, path))?
            );
            return Ok(());
        }
        _ => {}
    }

    println!("{}", "deslop: codebase architectural scanner".bold());
    println!("target: {}\n", path.display());

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
    if !score_is_reliable(parsed.stats.total_lines_of_code) {
        println!(
            "{:<28} {}",
            "",
            format!(
                "low confidence: under {} LOC, score uses a {} LOC floor",
                MIN_SCORED_LOC, MIN_SCORED_LOC
            )
            .yellow()
        );
    }
    if let Some(d) = &diff {
        println!(
            "{:<28} {} (index {:.1} at ref)",
            "Baseline:",
            d.git_ref.cyan(),
            d.base_slop_index
        );
        println!(
            "{:<28} {} new, {} resolved",
            "Changes since baseline:",
            d.new.len().to_string().bold(),
            d.resolved_count
        );
    }
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
    print_llm_status(explain);
    println!("--------------------------------------------------\n");

    if findings.is_empty() {
        if diff.is_some() {
            println!("{}", "No new slop relative to the baseline.".green());
        } else {
            println!(
                "{}",
                "No slop or architectural anti-patterns detected.".green()
            );
        }
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
            let title_trunc = if f.title.chars().count() > 48 {
                format!("{}...", f.title.chars().take(45).collect::<String>())
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
            files: Vec::new(),
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
        assert!(report.score_reliable);
        // 2 LOW findings = 3.0 penalty over 1000 LOC -> 3.0 index.
        assert_eq!(report.slop_index, 3.0);
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(json.contains("\"slop_index\":3.0"));
        assert!(json.contains("\"finding_count\":2"));
    }
}
