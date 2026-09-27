use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCoupling {
    pub file_a: String,
    pub file_b: String,
    pub co_commit_count: usize,
    pub coupling_pct: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHotspot {
    pub file_path: String,
    pub commit_count: usize,
    pub churn_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChurnAnalysisReport {
    pub total_commits_analyzed: usize,
    pub top_hotspots: Vec<GitHotspot>,
    pub temporal_couplings: Vec<TemporalCoupling>,
}

pub struct GitChurnAnalyzer;

impl GitChurnAnalyzer {
    /// Analyzes git history to extract commit frequency and hidden temporal couplings
    pub fn analyze(repo_root: &Path, max_commits: usize) -> Option<ChurnAnalysisReport> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args([
                "log",
                "--name-only",
                "--pretty=format:COMMIT:%H",
                "-n",
                &max_commits.to_string(),
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let log_text = String::from_utf8_lossy(&output.stdout);
        let mut commits: Vec<HashSet<String>> = Vec::new();
        let mut current_files = HashSet::new();

        for line in log_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("COMMIT:") {
                if !current_files.is_empty() {
                    commits.push(current_files);
                    current_files = HashSet::new();
                }
            } else if !trimmed.is_empty() {
                current_files.insert(trimmed.to_string());
            }
        }
        if !current_files.is_empty() {
            commits.push(current_files);
        }

        let total_commits = commits.len();
        if total_commits == 0 {
            return None;
        }

        // 1. File commit frequencies (Hotspots)
        let mut file_counts: HashMap<String, usize> = HashMap::new();
        for commit in &commits {
            for file in commit {
                *file_counts.entry(file.clone()).or_insert(0) += 1;
            }
        }

        let mut hotspots: Vec<GitHotspot> = file_counts
            .iter()
            .map(|(file, &count)| {
                let risk = if count > total_commits / 3 {
                    "Critical Churn Hotspot".to_string()
                } else if count > total_commits / 8 {
                    "Moderate Churn".to_string()
                } else {
                    "Low Churn / Stable".to_string()
                };
                GitHotspot {
                    file_path: file.clone(),
                    commit_count: count,
                    churn_risk: risk,
                }
            })
            .collect();
        hotspots.sort_by_key(|h| std::cmp::Reverse(h.commit_count));

        // 2. Co-change matrix (Temporal Coupling)
        let mut co_changes: HashMap<(String, String), usize> = HashMap::new();
        for commit in &commits {
            let files_vec: Vec<&String> = commit.iter().collect();
            for i in 0..files_vec.len() {
                for j in (i + 1)..files_vec.len() {
                    let a = files_vec[i];
                    let b = files_vec[j];
                    let key = if a < b {
                        (a.clone(), b.clone())
                    } else {
                        (b.clone(), a.clone())
                    };
                    *co_changes.entry(key).or_insert(0) += 1;
                }
            }
        }

        let mut temporal_couplings = Vec::new();
        for ((file_a, file_b), co_count) in co_changes {
            if co_count >= 3 {
                let count_a = *file_counts.get(&file_a).unwrap_or(&1);
                let count_b = *file_counts.get(&file_b).unwrap_or(&1);
                let min_count = count_a.min(count_b) as f64;
                let ratio = (co_count as f64) / min_count;

                if ratio >= 0.40 {
                    temporal_couplings.push(TemporalCoupling {
                        file_a: file_a.clone(),
                        file_b: file_b.clone(),
                        co_commit_count: co_count,
                        coupling_pct: ratio * 100.0,
                        description: format!(
                            "{} and {} change together in {:.0}% of their commits. High invisible coupling risk.",
                            file_a, file_b, ratio * 100.0
                        ),
                    });
                }
            }
        }
        temporal_couplings.sort_by(|a, b| b.coupling_pct.partial_cmp(&a.coupling_pct).unwrap_or(std::cmp::Ordering::Equal));

        Some(ChurnAnalysisReport {
            total_commits_analyzed: total_commits,
            top_hotspots: hotspots.into_iter().take(15).collect(),
            temporal_couplings: temporal_couplings.into_iter().take(10).collect(),
        })
    }
}
