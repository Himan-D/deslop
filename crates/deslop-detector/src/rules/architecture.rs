use crate::{DetectionContext, DetectionRule};
use deslop_core::{ArchitectureConfig, DependencyEdgeKind, Severity, SlopFinding, SlopKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

/// Returns `(pattern, sibling_name)` if `path` falls inside an `isolated`
/// directory pattern such as `src/features/*` or `crates/*`.
pub fn isolated_group(path: &str, pattern: &str) -> Option<(String, String)> {
    let normalized_path = path.replace('\\', "/");
    let normalized_pat = pattern.replace('\\', "/");

    let path_segs: Vec<&str> = normalized_path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let pat_segs: Vec<&str> = normalized_pat
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    let star_idx = pat_segs.iter().position(|&s| s == "*")?;
    if path_segs.len() <= star_idx {
        return None;
    }
    if !match_segments(&path_segs[..star_idx], &pat_segs[..star_idx]) {
        return None;
    }
    if pat_segs.len() > star_idx + 1
        && !match_segments(&path_segs[star_idx + 1..], &pat_segs[star_idx + 1..])
    {
        return None;
    }

    Some((normalized_pat, path_segs[star_idx].to_string()))
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
        let mut reported_pairs: HashSet<(String, String)> = HashSet::new();

        let sym_files: HashMap<&str, (&Path, usize)> = ctx
            .symbols
            .iter()
            .map(|s| (s.id.as_str(), (s.file_path.as_path(), s.span.start_line)))
            .collect();

        // Symbol-level edges first (preferred for exact symbol_id and line).
        for edge in ctx
            .edges
            .iter()
            .filter(|e| e.kind != DependencyEdgeKind::Imports)
        {
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

            if check_edge_violations(
                config,
                &from_path,
                &to_path,
                &edge.from_symbol,
                &file_path,
                line,
                &mut findings,
            ) {
                reported_pairs.insert((from_path.into_owned(), to_path.into_owned()));
            }
        }

        // Raw file-to-module Imports edges (from universal_parser / rust_parser).
        for edge in ctx
            .edges
            .iter()
            .filter(|e| e.kind == DependencyEdgeKind::Imports)
        {
            let pair = (edge.from_symbol.clone(), edge.to_symbol.clone());
            if reported_pairs.contains(&pair) {
                continue;
            }

            let file_path = PathBuf::from(&edge.from_symbol);
            if check_edge_violations(
                config,
                &edge.from_symbol,
                &edge.to_symbol,
                &edge.from_symbol,
                &file_path,
                1,
                &mut findings,
            ) {
                reported_pairs.insert(pair);
            }
        }

        findings
    }
}

fn check_edge_violations(
    config: &ArchitectureConfig,
    from_path: &str,
    to_path: &str,
    symbol_id: &str,
    file_path: &Path,
    line: usize,
    findings: &mut Vec<SlopFinding>,
) -> bool {
    if config
        .allow_exceptions
        .iter()
        .any(|ex| matches_pattern(from_path, &ex.from) && matches_pattern(to_path, &ex.to))
    {
        return false;
    }

    let before = findings.len();

    // Check forbidden rules
    for rule in &config.forbidden_rules {
        if matches_pattern(from_path, &rule.from) && matches_pattern(to_path, &rule.to) {
            let desc = rule.description.clone().unwrap_or_else(|| {
                format!(
                    "Dependency from '{}' to '{}' is explicitly forbidden by architecture policy.",
                    rule.from, rule.to
                )
            });
            findings.push(SlopFinding {
                kind: SlopKind::LayerViolation,
                symbol_id: symbol_id.to_string(),
                file_path: file_path.to_path_buf(),
                line,
                severity: Severity::Critical,
                confidence: 1.0,
                title: format!("Architectural Rule Violation: {} -> {}", rule.from, rule.to),
                description: desc,
                remediation:
                    "Invert dependency or extract a common interface into a lower domain layer."
                        .to_string(),
                estimated_lines_saved: 0,
                inline_target: None,
            });
        }
    }

    // Check strict monotonic layer ordering
    if !config.layers.is_empty() {
        let from_layer_idx = config
            .layers
            .iter()
            .position(|l| matches_pattern(from_path, l));
        let to_layer_idx = config
            .layers
            .iter()
            .position(|l| matches_pattern(to_path, l));

        if let (Some(f_idx), Some(t_idx)) = (from_layer_idx, to_layer_idx) {
            if f_idx > t_idx {
                findings.push(SlopFinding {
                    kind: SlopKind::LayerViolation,
                    symbol_id: symbol_id.to_string(),
                    file_path: file_path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    confidence: 1.0,
                    title: format!(
                        "Layer Inversion: Layer '{}' imports upper Layer '{}'",
                        config.layers[f_idx], config.layers[t_idx]
                    ),
                    description: format!(
                        "Module '{}' in layer '{}' illegally depends on '{}' in higher layer '{}'. Strict monotonic DAG violated.",
                        from_path, config.layers[f_idx], to_path, config.layers[t_idx]
                    ),
                    remediation: "Apply Dependency Inversion Principle (DIP): higher layers should depend on abstractions in lower layers.".to_string(),
                    estimated_lines_saved: 0,
                    inline_target: None,
                });
            }
        }
    }

    // Check isolated feature/module boundaries
    for pat in &config.isolated {
        if let (Some((pat_key, from_group)), Some((_, to_group))) =
            (isolated_group(from_path, pat), isolated_group(to_path, pat))
        {
            if from_group != to_group {
                findings.push(SlopFinding {
                    kind: SlopKind::LayerViolation,
                    symbol_id: symbol_id.to_string(),
                    file_path: file_path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    confidence: 0.95,
                    title: format!(
                        "Isolated Feature Violation: '{}' -> '{}' ({})",
                        from_group, to_group, pat_key
                    ),
                    description: format!(
                        "Module '{}' in isolated group '{}' illegally imports '{}' from sibling group '{}' under '{}'.",
                        from_path, from_group, to_path, to_group, pat_key
                    ),
                    remediation: "Extract shared types or logic into a common shared module outside the isolated boundary, or communicate via an explicit public interface.".to_string(),
                    estimated_lines_saved: 0,
                    inline_target: None,
                });
            }
        }
    }

    findings.len() > before
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{
        AllowException, DependencyEdge, ForbiddenRule, SourceSpan, Symbol, SymbolKind, Visibility,
    };
    use deslop_graph::SymbolGraph;

    fn make_ctx<'a>(
        symbols: &'a [Symbol],
        edges: &'a [DependencyEdge],
        graph: &'a SymbolGraph,
        config: &'a ArchitectureConfig,
    ) -> DetectionContext<'a> {
        DetectionContext {
            symbols,
            edges,
            graph,
            config: Some(config),
            callsites: None,
        }
    }

    #[test]
    fn raw_imports_edge_triggers_forbidden_rule() {
        let symbols = Vec::new();
        let edges = vec![DependencyEdge {
            from_symbol: "src/domain/order.ts".to_string(),
            to_symbol: "prisma".to_string(),
            kind: DependencyEdgeKind::Imports,
            count: 1,
        }];
        let config = ArchitectureConfig {
            forbidden_rules: vec![ForbiddenRule {
                from: "src/domain/**".into(),
                to: "prisma".into(),
                description: None,
            }],
            ..Default::default()
        };
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = make_ctx(&symbols, &edges, &graph, &config);

        let findings = ArchitectureViolationRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SlopKind::LayerViolation);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, 1.0);
        assert_eq!(findings[0].symbol_id, "src/domain/order.ts");
        assert_eq!(findings[0].file_path, PathBuf::from("src/domain/order.ts"));
    }

    #[test]
    fn allow_exceptions_suppresses_raw_import_violation() {
        let symbols = Vec::new();
        let edges = vec![
            DependencyEdge {
                from_symbol: "src/domain/legacy.ts".to_string(),
                to_symbol: "prisma".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
            DependencyEdge {
                from_symbol: "src/domain/order.ts".to_string(),
                to_symbol: "prisma".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
        ];
        let config = ArchitectureConfig {
            forbidden_rules: vec![ForbiddenRule {
                from: "src/domain/**".into(),
                to: "prisma".into(),
                description: None,
            }],
            allow_exceptions: vec![AllowException {
                from: "src/domain/legacy.ts".into(),
                to: "prisma".into(),
                reason: "Legacy adapter".into(),
            }],
            ..Default::default()
        };
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = make_ctx(&symbols, &edges, &graph, &config);

        let findings = ArchitectureViolationRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].symbol_id, "src/domain/order.ts");
    }

    fn make_symbol(id: &str, name: &str, file_path: &str, line: usize) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: PathBuf::from(file_path),
            span: SourceSpan {
                start_line: line,
                end_line: line + 5,
                start_col: 0,
                end_col: 1,
            },
            visibility: Visibility::Public,
            loc: 5,
            cyclomatic_complexity: 1,
            doc: None,
            signature: String::new(),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    #[test]
    fn raw_imports_edge_triggers_layer_inversion_and_deduplicates_with_symbol_edge() {
        let symbols = vec![
            make_symbol(
                "src/domain/order.ts::create",
                "create",
                "src/domain/order.ts",
                12,
            ),
            make_symbol("src/infra/db.ts::save", "save", "src/infra/db.ts", 5),
        ];
        let edges = vec![
            DependencyEdge {
                from_symbol: "src/domain/order.ts".to_string(),
                to_symbol: "src/infra/db.ts".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
            DependencyEdge {
                from_symbol: "src/domain/order.ts::create".to_string(),
                to_symbol: "src/infra/db.ts::save".to_string(),
                kind: DependencyEdgeKind::Calls,
                count: 1,
            },
        ];
        let config = ArchitectureConfig {
            layers: vec!["src/infra/**".into(), "src/domain/**".into()],
            ..Default::default()
        };
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = make_ctx(&symbols, &edges, &graph, &config);

        let findings = ArchitectureViolationRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].symbol_id, "src/domain/order.ts::create");
        assert_eq!(findings[0].line, 12);
    }

    #[test]
    fn isolated_group_extracts_prefix_and_sibling() {
        assert_eq!(
            isolated_group("src/features/billing/api.ts", "src/features/*"),
            Some(("src/features/*".to_string(), "billing".to_string()))
        );
        assert_eq!(
            isolated_group("src/shared/utils.ts", "src/features/*"),
            None
        );
    }

    #[test]
    fn isolated_features_flag_cross_feature_and_allow_intra_feature() {
        let symbols = Vec::new();
        let edges = vec![
            DependencyEdge {
                from_symbol: "src/features/billing/a.ts".to_string(),
                to_symbol: "src/features/auth/b.ts".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
            DependencyEdge {
                from_symbol: "src/features/billing/a.ts".to_string(),
                to_symbol: "src/features/billing/b.ts".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
        ];
        let config = ArchitectureConfig {
            isolated: vec!["src/features/*".into()],
            ..Default::default()
        };
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = make_ctx(&symbols, &edges, &graph, &config);

        let findings = ArchitectureViolationRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SlopKind::LayerViolation);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, 0.95);
        assert!(findings[0].title.contains("Isolated Feature Violation"));
        assert_eq!(findings[0].symbol_id, "src/features/billing/a.ts");
    }
}
