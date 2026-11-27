use super::baseline::relative_key;
use super::common::{git_toplevel, scan_and_analyze, severity_weight};
use colored::*;
use deslop_core::{Severity, SlopFinding, SlopKind};
use deslop_detector::SlopDetectorEngine;
use deslop_graph::GitChurnAnalyzer;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

const VERIFICATION_COMMAND: &str = "deslop check .";

#[derive(Debug, Serialize)]
pub struct NextItem {
    pub rank: usize,
    pub priority_score: f64,
    pub kind: String,
    pub severity: Severity,
    pub confidence: f64,
    pub file: String,
    pub line: usize,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub snippet: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NextReport {
    pub target: String,
    pub slop_index: f64,
    pub remaining_count: usize,
    pub items: Vec<NextItem>,
    pub verification_command: &'static str,
}

fn category_boost(kind: SlopKind) -> f64 {
    if kind.is_security() || matches!(kind, SlopKind::Cycle | SlopKind::LayerViolation) {
        1.5
    } else {
        1.0
    }
}

fn read_snippet(file_path: &Path, line: usize) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(file_path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return Vec::new();
    }
    let target_idx = line.saturating_sub(1).min(lines.len() - 1);
    let start = target_idx.saturating_sub(1);
    let end = (start + 3).min(lines.len());
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(offset, text)| format!("{:>4} | {}", start + offset + 1, text))
        .collect()
}

pub fn compute_next_report(path: &Path, count: usize) -> anyhow::Result<NextReport> {
    let (parsed, _graph, findings, _elapsed) = scan_and_analyze(path)?;
    let total_loc = parsed.stats.total_lines_of_code;
    let slop_index = SlopDetectorEngine::calculate_slop_index(total_loc, &findings);
    let remaining_count = findings.len();

    let commit_counts: HashMap<String, usize> = GitChurnAnalyzer::analyze(path, 200)
        .map(|report| {
            report
                .top_hotspots
                .into_iter()
                .map(|h| (h.file_path.replace('\\', "/"), h.commit_count))
                .collect()
        })
        .unwrap_or_default();

    let git_root = git_toplevel(path).unwrap_or_else(|| path.to_path_buf());

    struct ScoredFinding<'a> {
        finding: &'a SlopFinding,
        score: f64,
    }

    let mut scored: Vec<ScoredFinding<'_>> = findings
        .iter()
        .map(|f| {
            let churn_key = relative_key(&f.file_path, &git_root);
            let commits = commit_counts.get(&churn_key).copied().unwrap_or(0);
            let score = severity_weight(f.severity)
                * category_boost(f.kind)
                * (1.0 + (commits as f64).ln_1p());
            ScoredFinding { finding: f, score }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.finding.severity.cmp(&a.finding.severity))
            .then_with(|| a.finding.file_path.cmp(&b.finding.file_path))
            .then_with(|| a.finding.line.cmp(&b.finding.line))
            .then_with(|| a.finding.title.cmp(&b.finding.title))
    });

    let limit = count.max(1);
    let items = scored
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(idx, entry)| {
            let f = entry.finding;
            NextItem {
                rank: idx + 1,
                priority_score: entry.score,
                kind: format!("{:?}", f.kind),
                severity: f.severity,
                confidence: f.confidence,
                file: relative_key(&f.file_path, path),
                line: f.line,
                title: f.title.clone(),
                description: f.description.clone(),
                remediation: f.remediation.clone(),
                snippet: read_snippet(&f.file_path, f.line),
            }
        })
        .collect();

    Ok(NextReport {
        target: path.display().to_string(),
        slop_index,
        remaining_count,
        items,
        verification_command: VERIFICATION_COMMAND,
    })
}

pub fn run(path: &Path, format: &str, count: usize) -> anyhow::Result<()> {
    if !matches!(format, "table" | "json") {
        anyhow::bail!("unknown --format '{}': expected table or json", format);
    }

    let report = compute_next_report(path, count)?;

    if format == "json" {
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }

    if report.items.is_empty() {
        println!("Zero findings — codebase is clean.");
        return Ok(());
    }

    for item in &report.items {
        let header = format!(
            "[{}/{}] error[{}]: {}",
            item.rank, report.remaining_count, item.kind, item.title
        );
        println!("{}", header.red().bold());
        println!("  {} {}:{}", "-->".blue().bold(), item.file, item.line);
        if !item.snippet.is_empty() {
            println!("     {}", "|".blue().bold());
            for line in &item.snippet {
                println!("  {}", line);
            }
            println!("     {}", "|".blue().bold());
        }
        println!("   {} {}", "=".blue().bold(), item.remediation);
        println!(
            "   {} next: run {}\n",
            "=".blue().bold(),
            report.verification_command
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sloppy_app_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("workspace root")
            .join("tests/fixtures/sloppy_app")
    }

    #[test]
    fn compute_next_report_returns_top_item_with_snippet() {
        let fixture = sloppy_app_fixture();
        let report = compute_next_report(&fixture, 1).expect("next report should succeed");
        assert!(report.remaining_count >= 1);
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].rank, 1);
        assert!(!report.items[0].snippet.is_empty());
        assert_eq!(report.verification_command, "deslop check .");
    }

    #[test]
    fn run_rejects_unknown_format() {
        let fixture = sloppy_app_fixture();
        let err = run(&fixture, "sarif", 1).expect_err("unknown format should fail");
        assert!(err.to_string().contains("expected table or json"));
    }
}
