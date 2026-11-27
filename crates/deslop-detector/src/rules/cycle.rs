use crate::{bare_name, DetectionContext, DetectionRule};
use deslop_core::{DependencyEdgeKind, Severity, SlopFinding, SlopKind, Symbol};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Detect circular dependency cycles
pub struct CircularDependencyRule;

impl DetectionRule for CircularDependencyRule {
    fn rule_name(&self) -> &'static str {
        "circular-dependency"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let cycles = ctx.graph.find_circular_dependencies_with_confidence();
        let sym_map: HashMap<&str, &Symbol> =
            ctx.symbols.iter().map(|s| (s.name.as_str(), s)).collect();
        let mut bare_counts: HashMap<&str, usize> = HashMap::new();
        for s in ctx.symbols {
            *bare_counts.entry(bare_name(&s.name)).or_insert(0) += 1;
        }
        let mut findings = Vec::new();
        let mut reported_symbol_cycle_files: Vec<HashSet<PathBuf>> = Vec::new();

        for (cycle, uses_bare_heuristic) in cycles {
            let cycle_repr = cycle.join(" -> ");
            if let Some(first_sym_name) = cycle.first() {
                if let Some(first_sym) = sym_map.get(first_sym_name.as_str()) {
                    // Test fixtures may wire types into deliberate loops.
                    if first_sym.is_test_entrypoint() {
                        continue;
                    }
                    // Severity follows how far the loop reaches: a loop inside
                    // one file is cheap to fix, a loop across three or more
                    // files is a layering problem.
                    let files: HashSet<&Path> = cycle
                        .iter()
                        .filter_map(|n| sym_map.get(n.as_str()))
                        .map(|s| s.file_path.as_path())
                        .collect();
                    reported_symbol_cycle_files
                        .push(files.iter().map(|p| p.to_path_buf()).collect());
                    let has_bare_collision = cycle
                        .iter()
                        .any(|n| bare_counts.get(bare_name(n)).copied().unwrap_or(0) > 1);
                    let ambiguous = uses_bare_heuristic && has_bare_collision;
                    let severity = match (ambiguous, files.len()) {
                        (true, _) => Severity::Low,
                        (false, 0 | 1) => Severity::Medium,
                        (false, 2) => Severity::High,
                        (false, _) => Severity::Critical,
                    };
                    let confidence = if ambiguous { 0.5 } else { 0.95 };
                    findings.push(SlopFinding {
                        kind: SlopKind::Cycle,
                        symbol_id: first_sym.id.clone(),
                        file_path: first_sym.file_path.clone(),
                        line: first_sym.span.start_line,
                        severity,
                        confidence,
                        title: format!("Circular Dependency Loop: {}", cycle_repr),
                        description: format!(
                            "A circular dependency loop spans {} file(s): {} -> {}. This tight coupling leads to initialization order bugs and prevents modular compilation.",
                            files.len(), cycle_repr, first_sym_name
                        ),
                        remediation: if ambiguous {
                            "Verify the loop first: it passes through names shared by several symbols, so the static graph may have merged unrelated calls.".to_string()
                        } else {
                            "Break the cycle by extracting shared data/types into an independent leaf module or applying dependency inversion.".to_string()
                        },
                        estimated_lines_saved: 0,
                        inline_target: None,
                    });
                }
            }
        }

        // File-level import cycle detection (catches type-only TS/JS cycles with no Calls edges).
        detect_file_import_cycles(ctx, &reported_symbol_cycle_files, &mut findings);

        findings
    }
}

fn normalize_rel_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in normalized.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|&p| p != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn resolve_import_target(
    from_file: &str,
    target: &str,
    stem_to_file: &HashMap<String, PathBuf>,
    exact_to_file: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let norm_target = target.replace('\\', "/");
    let candidate = if norm_target.starts_with("./") || norm_target.starts_with("../") {
        let parent = Path::new(from_file)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if parent.is_empty() {
            normalize_rel_path(&norm_target)
        } else {
            normalize_rel_path(&format!("{}/{}", parent, norm_target))
        }
    } else {
        normalize_rel_path(&norm_target)
    };

    if let Some(found) = exact_to_file.get(&candidate) {
        return Some(found.clone());
    }
    if let Some(found) = stem_to_file.get(&candidate) {
        return Some(found.clone());
    }
    let index_candidate = format!("{}/index", candidate);
    stem_to_file.get(&index_candidate).cloned()
}

fn detect_file_import_cycles(
    ctx: &DetectionContext,
    reported_symbol_cycle_files: &[HashSet<PathBuf>],
    findings: &mut Vec<SlopFinding>,
) {
    let mut exact_to_file: HashMap<String, PathBuf> = HashMap::new();
    let mut stem_to_file: HashMap<String, PathBuf> = HashMap::new();

    for sym in ctx.symbols {
        let norm = normalize_rel_path(&sym.file_path.to_string_lossy());
        exact_to_file.insert(norm.clone(), sym.file_path.clone());
        if let Some(stem) = Path::new(&norm).with_extension("").to_str() {
            stem_to_file
                .entry(stem.to_string())
                .or_insert_with(|| sym.file_path.clone());
        }
    }

    let mut file_adj_map: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut all_files: BTreeSet<PathBuf> = BTreeSet::new();

    for edge in ctx
        .edges
        .iter()
        .filter(|e| e.kind == DependencyEdgeKind::Imports)
    {
        let from_norm = normalize_rel_path(&edge.from_symbol);
        let Some(from_file) = exact_to_file.get(&from_norm).cloned() else {
            continue;
        };
        let Some(to_file) =
            resolve_import_target(&from_norm, &edge.to_symbol, &stem_to_file, &exact_to_file)
        else {
            continue;
        };
        if from_file == to_file {
            continue;
        }
        all_files.insert(from_file.clone());
        all_files.insert(to_file.clone());
        file_adj_map.entry(from_file).or_default().insert(to_file);
    }

    if all_files.is_empty() {
        return;
    }

    let files_vec: Vec<PathBuf> = all_files.into_iter().collect();
    let file_to_idx: HashMap<&Path, usize> = files_vec
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_path(), i))
        .collect();

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); files_vec.len()];
    for (from, targets) in &file_adj_map {
        let u = file_to_idx[from.as_path()];
        for to in targets {
            adj[u].push(file_to_idx[to.as_path()]);
        }
    }

    for mut scc in tarjan_scc(files_vec.len(), &adj) {
        if scc.len() < 2 {
            continue;
        }
        scc.sort_unstable();
        let scc_files: HashSet<PathBuf> = scc.iter().map(|&i| files_vec[i].clone()).collect();
        if reported_symbol_cycle_files
            .iter()
            .any(|existing| existing == &scc_files)
        {
            continue;
        }

        let cycle_names: Vec<String> = scc
            .iter()
            .map(|&i| files_vec[i].to_string_lossy().into_owned())
            .collect();
        let cycle_repr = cycle_names.join(" -> ");
        let first_file = &files_vec[scc[0]];
        let first_file_str = &cycle_names[0];
        let severity = match scc.len() {
            2 => Severity::High,
            _ => Severity::Critical,
        };

        findings.push(SlopFinding {
            kind: SlopKind::Cycle,
            symbol_id: first_file_str.clone(),
            file_path: first_file.clone(),
            line: 1,
            severity,
            confidence: 0.9,
            title: format!("Circular Import Loop: {}", cycle_repr),
            description: format!(
                "A circular file-level import loop spans {} file(s): {} -> {}. This tight coupling leads to initialization order bugs and prevents modular compilation.",
                scc.len(),
                cycle_repr,
                first_file_str
            ),
            remediation: "Break the import cycle by extracting shared types/interfaces into an independent leaf module or applying dependency inversion.".to_string(),
            estimated_lines_saved: 0,
            inline_target: None,
        });
    }
}

fn tarjan_scc(node_count: usize, adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct State<'a> {
        adj: &'a [Vec<usize>],
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    fn strongconnect(v: usize, state: &mut State<'_>) {
        state.indices[v] = Some(state.index);
        state.lowlink[v] = state.index;
        state.index += 1;
        state.stack.push(v);
        state.on_stack[v] = true;

        for &w in &state.adj[v] {
            if state.indices[w].is_none() {
                strongconnect(w, state);
                state.lowlink[v] = state.lowlink[v].min(state.lowlink[w]);
            } else if state.on_stack[w] {
                if let Some(w_idx) = state.indices[w] {
                    state.lowlink[v] = state.lowlink[v].min(w_idx);
                }
            }
        }

        if Some(state.lowlink[v]) == state.indices[v] {
            let mut scc = Vec::new();
            while let Some(w) = state.stack.pop() {
                state.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            state.sccs.push(scc);
        }
    }

    let mut state = State {
        adj,
        index: 0,
        indices: vec![None; node_count],
        lowlink: vec![0; node_count],
        on_stack: vec![false; node_count],
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    for v in 0..node_count {
        if state.indices[v].is_none() {
            strongconnect(v, &mut state);
        }
    }

    state.sccs
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{DependencyEdge, SourceSpan, SymbolKind, Visibility};
    use deslop_graph::SymbolGraph;

    fn make_symbol(id: &str, name: &str, file_path: &str) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::TypeAlias,
            file_path: PathBuf::from(file_path),
            span: SourceSpan {
                start_line: 1,
                end_line: 3,
                start_col: 0,
                end_col: 1,
            },
            visibility: Visibility::Public,
            loc: 3,
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
    fn detects_type_only_import_cycle_without_call_edges() {
        let symbols = vec![
            make_symbol("src/a.ts::TypeA", "TypeA", "src/a.ts"),
            make_symbol("src/b.ts::TypeB", "TypeB", "src/b.ts"),
        ];
        let edges = vec![
            DependencyEdge {
                from_symbol: "src/a.ts".to_string(),
                to_symbol: "./b".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
            DependencyEdge {
                from_symbol: "src/b.ts".to_string(),
                to_symbol: "./a".to_string(),
                kind: DependencyEdgeKind::Imports,
                count: 1,
            },
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };

        let findings = CircularDependencyRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SlopKind::Cycle);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Circular Import Loop"));
        assert!(findings[0].title.contains("src/a.ts"));
        assert!(findings[0].title.contains("src/b.ts"));
    }
}
