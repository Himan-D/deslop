use super::baseline::{self, BaselineDiff};
use super::common::{
    git_toplevel, print_llm_status, scan_and_analyze, severity_weight, FindingRow,
};
use super::sarif::to_sarif;
use colored::*;
use deslop_core::format_location;
use deslop_core::{Severity, SlopFinding};
use deslop_detector::{score_is_reliable, SlopDetectorEngine, MIN_SCORED_LOC};
use deslop_graph::{churn::ChurnAnalysisReport, GitChurnAnalyzer};
use deslop_llm::LlmClient;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use tabled::{Table, Tabled};

/// Baseline comparison details, present when `--base` was used.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineSummary {
    pub git_ref: String,
    pub base_slop_index: f64,
    pub new_findings: usize,
    pub resolved_findings: usize,
}

/// File-level risk combining git commit churn and slop severity weight.
#[derive(Debug, Clone, Serialize)]
pub struct HotspotEntry {
    pub file: String,
    pub commits: usize,
    pub finding_count: usize,
    pub hotspot_score: f64,
}

#[derive(Tabled)]
struct HotspotRow {
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Commits")]
    commits: usize,
    #[tabled(rename = "Findings")]
    finding_count: usize,
    #[tabled(rename = "Hotspot Score")]
    hotspot_score: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspots: Option<Vec<HotspotEntry>>,
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
        hotspots: None,
    }
}

fn compute_hotspots_from_report(
    churn: Option<&ChurnAnalysisReport>,
    git_root: &Path,
    findings: &[SlopFinding],
) -> Vec<HotspotEntry> {
    let Some(report) = churn else {
        return Vec::new();
    };

    let mut per_file: HashMap<String, (usize, f64)> = HashMap::new();
    for f in findings {
        let key = baseline::relative_key(&f.file_path, git_root);
        let entry = per_file.entry(key).or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += severity_weight(f.severity);
    }

    let mut entries: Vec<HotspotEntry> = report
        .top_hotspots
        .iter()
        .filter_map(|h| {
            let normalized = h.file_path.replace('\\', "/");
            let &(finding_count, file_slop_weight) = per_file.get(&normalized)?;
            if finding_count == 0 {
                return None;
            }
            Some(HotspotEntry {
                file: normalized,
                commits: h.commit_count,
                finding_count,
                hotspot_score: h.commit_count as f64 * file_slop_weight,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        b.hotspot_score
            .partial_cmp(&a.hotspot_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.commits.cmp(&a.commits))
            .then_with(|| a.file.cmp(&b.file))
    });
    entries.truncate(10);
    entries
}

fn compute_hotspots(path: &Path, findings: &[SlopFinding]) -> Vec<HotspotEntry> {
    let churn = GitChurnAnalyzer::analyze(path, 200);
    let root = git_toplevel(path).unwrap_or_else(|| path.to_path_buf());
    compute_hotspots_from_report(churn.as_ref(), &root, findings)
}

pub fn run(
    path: &Path,
    detailed: bool,
    explain: bool,
    format: &str,
    base: Option<&str>,
    hotspots: bool,
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

    let hotspot_entries = if hotspots && format != "sarif" {
        Some(compute_hotspots(path, &findings))
    } else {
        None
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
            report.hotspots = hotspot_entries;
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

    if let Some(entries) = hotspot_entries {
        println!("{}", "Hotspots (Churn × Slop)".bold());
        if entries.is_empty() {
            println!("No churn hotspots with slop findings (or not a git repository).\n");
        } else {
            let hotspot_rows: Vec<HotspotRow> = entries
                .into_iter()
                .map(|e| HotspotRow {
                    file: e.file,
                    commits: e.commits,
                    finding_count: e.finding_count,
                    hotspot_score: format!("{:.1}", e.hotspot_score),
                })
                .collect();
            println!("{}\n", Table::new(hotspot_rows));
        }
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
            inline_target: None,
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
        assert!(!json.contains("\"hotspots\""));
    }

    fn finding_with(file: &str, severity: Severity) -> SlopFinding {
        SlopFinding {
            kind: SlopKind::TollboothWrapper,
            symbol_id: format!("{file}::sym"),
            file_path: PathBuf::from(file),
            line: 1,
            severity,
            confidence: 0.9,
            title: "finding".to_string(),
            description: "desc".to_string(),
            remediation: "fix".to_string(),
            estimated_lines_saved: 5,
            inline_target: None,
        }
    }

    #[test]
    fn hotspots_none_for_non_git_dir() {
        let entries = compute_hotspots_from_report(None, Path::new("."), &[finding(3)]);
        assert!(entries.is_empty());
    }

    #[test]
    fn hotspots_scores_sorts_and_truncates_top_10() {
        use deslop_graph::churn::GitHotspot;

        let mut top_hotspots = Vec::new();
        let mut findings = Vec::new();
        // 11 files with findings + 1 churn-only file with no findings.
        for i in 0..11 {
            let file = format!("src/f{i}.rs");
            top_hotspots.push(GitHotspot {
                file_path: file.clone(),
                commit_count: i + 1,
                churn_risk: "Low".to_string(),
            });
            findings.push(finding_with(&file, Severity::Low));
        }
        top_hotspots.push(GitHotspot {
            file_path: "src/clean_churn.rs".to_string(),
            commit_count: 100,
            churn_risk: "Critical".to_string(),
        });
        // Give src/f0.rs a Critical + High finding (15 + 8 = 23) * 1 commit = 23.0,
        // beating src/f10.rs (1.5 * 11 = 16.5).
        findings.push(finding_with("src/f0.rs", Severity::Critical));
        findings.push(finding_with("src/f0.rs", Severity::High));
        // Give src/f1.rs a Medium finding (1.5 + 4.0 = 5.5) * 2 commits = 11.0.
        findings.push(finding_with("src/f1.rs", Severity::Medium));

        let churn = ChurnAnalysisReport {
            total_commits_analyzed: 50,
            sufficient_history: true,
            top_hotspots,
            temporal_couplings: Vec::new(),
        };

        let entries = compute_hotspots_from_report(Some(&churn), Path::new("."), &findings);
        assert_eq!(entries.len(), 10);
        assert!(entries.iter().all(|e| e.file != "src/clean_churn.rs"));
        // Top entry: src/f0.rs with 1 commit, 3 findings (Low 1.5 + Critical 15 + High 8 = 24.5).
        assert_eq!(entries[0].file, "src/f0.rs");
        assert_eq!(entries[0].commits, 1);
        assert_eq!(entries[0].finding_count, 3);
        assert!((entries[0].hotspot_score - 24.5).abs() < 1e-9);
        // Second entry: src/f10.rs with 11 commits, 1 Low finding -> 16.5.
        assert_eq!(entries[1].file, "src/f10.rs");
        assert!((entries[1].hotspot_score - 16.5).abs() < 1e-9);
        // Sorted descending.
        for w in entries.windows(2) {
            assert!(w[0].hotspot_score >= w[1].hotspot_score);
        }
    }
}
