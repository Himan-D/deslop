use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind};
use std::collections::HashMap;

/// Matches `path_or_module` against `pattern`.
///
/// When `pattern` contains `*`, normalizes backslashes to `/` and performs glob
/// matching where `*` matches within a single path segment and `**` matches zero
/// or more segments. When `pattern` has no `*`, falls back to substring matching
/// (after `/` normalization) for backward compatibility with layer names such as
/// `["controller", "service", "repo"]`.
pub fn matches_pattern(path_or_module: &str, pattern: &str) -> bool {
    let normalized_path = path_or_module.replace('\\', "/");
    let normalized_pat = pattern.replace('\\', "/");

    if !normalized_pat.contains('*') {
        return normalized_path.contains(&normalized_pat);
    }

    let path_segs: Vec<&str> = normalized_path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let pat_segs: Vec<&str> = normalized_pat
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    match_segments(&path_segs, &pat_segs)
}

fn match_segments(path_segs: &[&str], pat_segs: &[&str]) -> bool {
    let n = path_segs.len();
    let m = pat_segs.len();
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[0][0] = true;

    for j in 1..=m {
        if pat_segs[j - 1] == "**" {
            dp[0][j] = dp[0][j - 1];
        }
    }

    for i in 1..=n {
        for j in 1..=m {
            if pat_segs[j - 1] == "**" {
                dp[i][j] = dp[i][j - 1] || dp[i - 1][j];
            } else if match_single_segment(path_segs[i - 1], pat_segs[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[n][m]
}

fn match_single_segment(seg: &str, pat: &str) -> bool {
    let s: Vec<char> = seg.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut si, mut pi) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while si < s.len() {
        if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = si;
            pi += 1;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_idx += 1;
            si = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

/// Evaluates ArchUnit-style declarative architectural rules and forbidden dependencies
pub struct ArchitectureViolationRule;

impl DetectionRule for ArchitectureViolationRule {
    fn rule_name(&self) -> &'static str {
        "architecture-violation"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let Some(config) = ctx.config else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        let sym_files: HashMap<&str, (&std::path::Path, usize)> = ctx
            .symbols
            .iter()
            .map(|s| (s.id.as_str(), (s.file_path.as_path(), s.span.start_line)))
            .collect();

        for edge in ctx.edges {
            let from_path = sym_files
                .get(edge.from_symbol.as_str())
                .map(|(p, _)| p.to_string_lossy())
                .unwrap_or_default();
            let to_path = sym_files
                .get(edge.to_symbol.as_str())
                .map(|(p, _)| p.to_string_lossy())
                .unwrap_or_default();
            let (file_path, line) = sym_files
                .get(edge.from_symbol.as_str())
                .map(|(p, l)| (p.to_path_buf(), *l))
                .unwrap_or_default();

            if config.allow_exceptions.iter().any(|ex| {
                matches_pattern(&from_path, &ex.from) && matches_pattern(&to_path, &ex.to)
            }) {
                continue;
            }

            // Check forbidden rules
            for rule in &config.forbidden_rules {
                if matches_pattern(&from_path, &rule.from) && matches_pattern(&to_path, &rule.to) {
                    let desc = rule.description.clone().unwrap_or_else(|| {
                        format!("Dependency from '{}' to '{}' is explicitly forbidden by architecture policy.", rule.from, rule.to)
                    });
                    findings.push(SlopFinding {
                        kind: SlopKind::LayerViolation,
                        symbol_id: edge.from_symbol.clone(),
                        file_path: file_path.clone(),
                        line,
                        severity: Severity::Critical,
                        confidence: 1.0,
                        title: format!("Architectural Rule Violation: {} -> {}", rule.from, rule.to),
                        description: desc,
                        remediation: "Invert dependency or extract a common interface into a lower domain layer.".to_string(),
                        estimated_lines_saved: 0,
                    });
                }
            }

            // Check strict monotonic layer ordering
            if !config.layers.is_empty() {
                let from_layer_idx = config
                    .layers
                    .iter()
                    .position(|l| matches_pattern(&from_path, l));
                let to_layer_idx = config
                    .layers
                    .iter()
                    .position(|l| matches_pattern(&to_path, l));

                if let (Some(f_idx), Some(t_idx)) = (from_layer_idx, to_layer_idx) {
                    if f_idx > t_idx {
                        findings.push(SlopFinding {
                            kind: SlopKind::LayerViolation,
                            symbol_id: edge.from_symbol.clone(),
                            file_path: file_path.clone(),
                            line,
                            severity: Severity::Critical,
                            confidence: 1.0,
                            title: format!("Layer Inversion: Layer '{}' imports upper Layer '{}'", config.layers[f_idx], config.layers[t_idx]),
                            description: format!("Module '{}' in layer '{}' illegally depends on '{}' in higher layer '{}'. Strict monotonic DAG violated.", from_path, config.layers[f_idx], to_path, config.layers[t_idx]),
                            remediation: "Apply Dependency Inversion Principle (DIP): higher layers should depend on abstractions in lower layers.".to_string(),
                            estimated_lines_saved: 0,
                        });
                    }
                }
            }
        }

        findings
    }
}
