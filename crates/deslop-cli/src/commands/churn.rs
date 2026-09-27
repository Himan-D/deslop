use super::common::create_spinner;
use colored::*;
use deslop_graph::GitChurnAnalyzer;
use std::path::Path;

pub fn run(path: &Path, commits: usize) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: behavioral git churn & temporal coupling analysis".bold()
    );
    println!("target repository: {}", path.display());
    println!("max commits: {}\n", commits);

    let pb = create_spinner("Analyzing git commit history and co-change frequency...");
    let report_opt = GitChurnAnalyzer::analyze(path, commits);
    pb.finish_and_clear();

    match report_opt {
        Some(report) => {
            println!(
                "Total Commits Analyzed: {}\n",
                report.total_commits_analyzed.to_string().cyan().bold()
            );

            println!("{}", "Top Churn Hotspots (High Change Frequency):".bold());
            println!("--------------------------------------------------");
            for (i, h) in report.top_hotspots.iter().take(10).enumerate() {
                let risk_colored = if h.churn_risk.contains("Critical") {
                    h.churn_risk.red().bold()
                } else if h.churn_risk.contains("Moderate") {
                    h.churn_risk.yellow()
                } else {
                    h.churn_risk.green()
                };
                println!(
                    "{:<3} {:<45} {:>4} commits  [{}]",
                    i + 1,
                    h.file_path,
                    h.commit_count,
                    risk_colored
                );
            }
            println!();

            println!("{}", "Hidden Temporal Couplings (Co-change >40%):".bold());
            println!("--------------------------------------------------");
            if report.temporal_couplings.is_empty() {
                println!("  No hidden temporal couplings detected above 40% threshold.");
            } else {
                for (i, c) in report.temporal_couplings.iter().take(10).enumerate() {
                    println!(
                        "{:<3} {} <-> {}",
                        i + 1,
                        c.file_a.yellow().bold(),
                        c.file_b.yellow().bold()
                    );
                    println!(
                        "    Co-commits: {} ({:.1}% co-change rate)",
                        c.co_commit_count, c.coupling_pct
                    );
                    println!("    Risk: {}", c.description);
                }
            }
            println!();
        }
        None => {
            println!(
                "{}",
                "Warning: No git history found or failed to execute git log on target path."
                    .yellow()
            );
        }
    }
    Ok(())
}
