pub mod capacity;
pub mod churn;
pub mod deep_analyzer;
pub mod profiler;
pub mod scip;
pub mod trace;

pub use capacity::{
    BreakdownRisk, CapacityAnalyzer, CapacityEstimate, CapacityReport, DeviceProfile,
};
pub use churn::{ChurnAnalysisReport, GitChurnAnalyzer, GitHotspot, TemporalCoupling};
pub use deep_analyzer::DeepAnalyzer;
pub use profiler::{CallStackPath, StackProfileReport, StackProfiler};
pub use scip::{ScipGenerator, ScipIndex};
pub use trace::{DynamicRescue, OtelSpan, TraceCorrelationReport, TraceIngestionEngine};

use deslop_core::{DependencyEdge, DependencyEdgeKind, Import, Symbol, Visibility};
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

/// Abstraction over whole-graph analyzers. New analyses implement this trait
/// instead of growing ad-hoc inherent methods, so callers and tests can be
/// generic over the analysis being run.
pub trait GraphAnalyzer {
    type Report;
    fn analyze(graph: &SymbolGraph) -> Self::Report;
}

pub struct SymbolGraph {
    pub graph: DiGraph<Symbol, DependencyEdgeKind>,
    pub node_indices: HashMap<String, NodeIndex>,
}

impl SymbolGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    pub fn from_parsed(symbols: &[Symbol], edges: &[DependencyEdge]) -> Self {
        Self::from_parsed_with_imports(symbols, edges, &HashMap::new())
    }

    /// Builds the graph, consulting per-file `use` imports to resolve
    /// aliased and module-prefixed callees before falling back to
    /// name heuristics.
    pub fn from_parsed_with_imports(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
        imports: &HashMap<std::path::PathBuf, Vec<Import>>,
    ) -> Self {
        let mut sg = Self::new();

        // Indexes for scoped callee resolution:
        // - file_scoped: (file, short name) -> candidates (caller's own file wins)
        // - global: short name -> candidates (only used when unambiguous)
        let mut file_scoped: HashMap<(&std::path::Path, &str), Vec<NodeIndex>> =
            HashMap::with_capacity(symbols.len());
        let mut global: HashMap<&str, Vec<NodeIndex>> = HashMap::with_capacity(symbols.len());
        for sym in symbols {
            let idx = sg.graph.add_node(sym.clone());
            sg.node_indices.insert(sym.id.clone(), idx);
            let short = short_name(&sym.name);
            file_scoped
                .entry((sym.file_path.as_path(), short))
                .or_default()
                .push(idx);
            global.entry(short).or_default().push(idx);
        }

        for edge in edges {
            let from_opt = sg.node_indices.get(&edge.from_symbol).copied();
            let to_opt = sg.node_indices.get(&edge.to_symbol).copied().or_else(|| {
                let caller_file = from_opt.map(|u| sg.graph[u].file_path.as_path());
                let file_imports: &[Import] = caller_file
                    .and_then(|f| imports.get(f))
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let normalized = normalize_callee(&edge.to_symbol, file_imports);
                let globs: Vec<&str> = file_imports
                    .iter()
                    .filter(|i| i.is_glob)
                    .map(|i| i.path.as_str())
                    .collect();
                resolve_callee(
                    &normalized,
                    caller_file,
                    &file_scoped,
                    &global,
                    &sg.graph,
                    &globs,
                )
            });

            if let (Some(u), Some(v)) = (from_opt, to_opt) {
                // One edge per ordered pair: callers often reference the same
                // symbol several ways (call + type mention), and degrees
                // should count unique relationships, not mentions.
                if u != v && !sg.graph.contains_edge(u, v) {
                    sg.graph.add_edge(u, v, edge.kind);
                }
            }
        }

        sg
    }

    /// Tarjan's SCC to identify circular dependency loops (length > 1)
    pub fn find_circular_dependencies(&self) -> Vec<Vec<String>> {
        let sccs = tarjan_scc(&self.graph);
        let mut cycles = Vec::new();

        for scc in sccs {
            if scc.len() > 1 {
                let cycle_names: Vec<String> = scc
                    .into_iter()
                    .map(|idx| self.graph[idx].name.clone())
                    .collect();
                cycles.push(cycle_names);
            }
        }

        cycles
    }

    /// Identify dead/orphan symbols: symbols unreachable from any public entrypoint
    pub fn find_unreachable_orphans(&self) -> Vec<Symbol> {
        let mut reachable = HashSet::new();

        // Entrypoints: public symbols, well-known roots (main/handler/...),
        // test symbols, and trait-impl methods (dispatched through the trait,
        // invisible to static call edges).
        let mut roots = Vec::new();
        for idx in self.graph.node_indices() {
            let sym = &self.graph[idx];
            if sym.visibility == Visibility::Public
                || sym.is_trait_impl
                || sym.is_test_entrypoint()
                || sym.is_implicit_entrypoint()
                || sym.name == "main"
                || sym.name.ends_with("::main")
                || sym.name.contains("handler")
                || sym.name.contains("Route")
            {
                roots.push(idx);
            }
        }

        for root in roots {
            let mut bfs = Bfs::new(&self.graph, root);
            while let Some(visited) = bfs.next(&self.graph) {
                reachable.insert(visited);
            }
        }

        let mut orphans = Vec::new();
        for idx in self.graph.node_indices() {
            if !reachable.contains(&idx) {
                let sym = &self.graph[idx];
                // Only flag private or internal symbols that aren't reachable
                if sym.visibility != Visibility::Public {
                    orphans.push(sym.clone());
                }
            }
        }

        orphans
    }

    /// Computes (in_degree, out_degree) for each symbol
    pub fn compute_degrees(&self) -> HashMap<String, (usize, usize)> {
        let mut res = HashMap::new();
        for idx in self.graph.node_indices() {
            let sym = &self.graph[idx];
            let in_deg = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count();
            let out_deg = self
                .graph
                .neighbors_directed(idx, Direction::Outgoing)
                .count();
            res.insert(sym.id.clone(), (in_deg, out_deg));
        }
        res
    }

    /// Export top architecture components to a clean Mermaid diagram
    pub fn to_mermaid(&self, max_nodes: usize) -> String {
        let mut lines = Vec::new();
        lines.push("flowchart TD".to_string());

        let degrees = self.compute_degrees();
        let mut sorted_nodes: Vec<_> = self.graph.node_indices().collect();
        // Sort by total connectivity (fan-in + fan-out)
        sorted_nodes.sort_by(|a, b| {
            let deg_a = degrees
                .get(&self.graph[*a].id)
                .map(|(i, o)| i + o)
                .unwrap_or(0);
            let deg_b = degrees
                .get(&self.graph[*b].id)
                .map(|(i, o)| i + o)
                .unwrap_or(0);
            deg_b.cmp(&deg_a)
        });

        let selected_indices: HashSet<NodeIndex> =
            sorted_nodes.into_iter().take(max_nodes).collect();

        // Node definitions
        for idx in &selected_indices {
            let sym = &self.graph[*idx];
            let safe_id = format!("node_{}", idx.index());
            let clean_name = sym.name.replace('"', "'");
            let kind_tag = format!("{:?}", sym.kind);
            lines.push(format!(
                "    {}[\"{}\\n<i>({})</i>\"]",
                safe_id, clean_name, kind_tag
            ));
        }

        // Edges
        for edge in self.graph.edge_indices() {
            if let Some((u, v)) = self.graph.edge_endpoints(edge) {
                if selected_indices.contains(&u) && selected_indices.contains(&v) {
                    let weight = self.graph[edge];
                    let label = match weight {
                        DependencyEdgeKind::Calls => "calls",
                        DependencyEdgeKind::Implements => "impl",
                        DependencyEdgeKind::Inherits => "inherits",
                        DependencyEdgeKind::Instantiates => "news",
                        _ => "uses",
                    };
                    lines.push(format!(
                        "    node_{} -->|{}| node_{}",
                        u.index(),
                        label,
                        v.index()
                    ));
                }
            }
        }

        lines.join("\n")
    }
}

impl Default for SymbolGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Short name: last segment after `::` or `.` (`Self::foo` -> `foo`,
/// `obj.method` -> `method`).
fn short_name(qualified: &str) -> &str {
    qualified
        .rsplit([':', '.'])
        .find(|s| !s.is_empty())
        .unwrap_or(qualified)
}

/// Rewrites a callee through the caller's `use` imports: strips
/// module-relative heads (`crate::`, `self::`, `super::`) and expands the
/// head segment through renames (`PStore::charge` with
/// `use payments::Store as PStore` becomes `payments::Store::charge`).
/// Single-level only; alias chains are not followed.
fn normalize_callee(callee: &str, imports: &[Import]) -> String {
    let mut norm = callee.replace('.', "::");
    loop {
        if let Some(rest) = norm
            .strip_prefix("crate::")
            .or_else(|| norm.strip_prefix("self::"))
            .or_else(|| norm.strip_prefix("super::"))
        {
            norm = rest.to_string();
            continue;
        }
        break;
    }
    if let Some((head, tail)) = norm.split_once("::") {
        if let Some(imp) = imports.iter().find(|i| !i.is_glob && i.local == head) {
            let rewritten = format!("{}::{}", imp.path, tail);
            return normalize_callee(&rewritten, &[]);
        }
    }
    norm
}

/// Resolves a callee reference to a graph node without guessing:
/// 1. `Self::` references resolve same-file only (they are always same-impl).
/// 2. Same-file short-name match (a call most likely targets its own file).
/// 3. Qualified `Type::member` match by suffix, else a link to the enclosing
///    type itself (an associated call still uses the type).
/// 4. Bare-name global match only when exactly one candidate exists, or when
///    a glob import disambiguates to exactly one file.
///
/// Anything ambiguous resolves to `None` rather than a wrong node.
fn resolve_callee(
    callee: &str,
    caller_file: Option<&std::path::Path>,
    file_scoped: &HashMap<(&std::path::Path, &str), Vec<NodeIndex>>,
    global: &HashMap<&str, Vec<NodeIndex>>,
    graph: &DiGraph<Symbol, DependencyEdgeKind>,
    globs: &[&str],
) -> Option<NodeIndex> {
    let short = short_name(callee);
    let is_self = callee == "Self" || callee.starts_with("Self::");

    if let Some(file) = caller_file {
        if let Some(cands) = file_scoped.get(&(file, short)) {
            if cands.len() == 1 {
                return Some(cands[0]);
            }
            if let Some(hit) = match_qualified(callee, cands, graph) {
                return Some(hit);
            }
            // Same file, same short name (e.g. two `new()` methods): pick the
            // first deterministically rather than leaking across files.
            return cands.first().copied();
        }
        if is_self {
            return None;
        }
    } else if is_self {
        return None;
    }

    let cands = global.get(short);
    if callee.contains("::") {
        // Qualified: exact qualifier match, file-hint disambiguation, or
        // enclosing-type fallback only. Never an unrelated same-named symbol.
        if let Some(cands) = cands {
            if let Some(hit) = match_qualified(callee, cands, graph) {
                return Some(hit);
            }
            if cands.len() > 1 {
                if let Some(head) = callee.split("::").next() {
                    if let Some(hit) = disambiguate_by_file(cands, graph, head) {
                        return Some(hit);
                    }
                }
            }
        }
        return resolve_enclosing_type(callee, caller_file, file_scoped, global, graph);
    }

    if let Some(cands) = cands {
        if cands.len() == 1 {
            return Some(cands[0]);
        }
        for glob in globs {
            let seg = glob.rsplit("::").next().unwrap_or(glob);
            if let Some(hit) = disambiguate_by_file(cands, graph, seg) {
                return Some(hit);
            }
        }
        if let Some(hit) = match_qualified(callee, cands, graph) {
            return Some(hit);
        }
    }
    None
}

/// Narrows same-named candidates to the one living in the hinted file or
/// directory (file stem or parent dir name). Returns `None` unless exactly
/// one candidate matches: unique evidence or nothing.
fn disambiguate_by_file(
    candidates: &[NodeIndex],
    graph: &DiGraph<Symbol, DependencyEdgeKind>,
    hint: &str,
) -> Option<NodeIndex> {
    let matches: Vec<NodeIndex> = candidates
        .iter()
        .copied()
        .filter(|idx| {
            let path = &graph[*idx].file_path;
            path.file_stem().is_some_and(|s| s == hint)
                || path
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_some_and(|n| n == hint)
        })
        .collect();
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

/// Links `Type::assoc_item` to the `Type` symbol itself when the member has no
/// parsed definition (e.g. derive-generated `Cli::parse`). Only fires when the
/// qualifier names a real parsed type.
fn resolve_enclosing_type(
    callee: &str,
    caller_file: Option<&std::path::Path>,
    file_scoped: &HashMap<(&std::path::Path, &str), Vec<NodeIndex>>,
    global: &HashMap<&str, Vec<NodeIndex>>,
    graph: &DiGraph<Symbol, DependencyEdgeKind>,
) -> Option<NodeIndex> {
    let qualifier = callee.rsplit_once("::").map(|(q, _)| q)?;
    if qualifier.is_empty()
        || matches!(
            qualifier,
            "Self" | "self" | "crate" | "super" | "Self::Self"
        )
        || qualifier.contains("Self::")
    {
        return None;
    }
    let type_short = short_name(qualifier);

    let mut matches: Vec<NodeIndex> = Vec::new();
    if let Some(file) = caller_file {
        if let Some(cands) = file_scoped.get(&(file, type_short)) {
            matches.extend(
                cands
                    .iter()
                    .filter(|idx| type_name_matches(&graph[**idx].name, qualifier))
                    .copied(),
            );
        }
    }
    if matches.is_empty() {
        if let Some(cands) = global.get(type_short) {
            matches.extend(
                cands
                    .iter()
                    .filter(|idx| type_name_matches(&graph[**idx].name, qualifier))
                    .copied(),
            );
        }
    }
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

fn type_name_matches(symbol_name: &str, qualifier: &str) -> bool {
    symbol_name == qualifier
        || qualifier.ends_with(&format!("::{}", symbol_name))
        || symbol_name.ends_with(&format!("::{}", qualifier))
}

/// Among candidates sharing a short name, find the one whose qualified symbol
/// name matches the callee reference: exact match, symbol-name-is-suffix
/// (`mcp::McpServer::start` matches `McpServer::start`), or `Self::` treated
/// as a wildcard receiver. Multiple hits mean ambiguity: `None`.
fn match_qualified(
    callee: &str,
    candidates: &[NodeIndex],
    graph: &DiGraph<Symbol, DependencyEdgeKind>,
) -> Option<NodeIndex> {
    let callee_norm = callee.replace('.', "::");
    let short = short_name(&callee_norm).to_string();
    let mut hits = candidates.iter().filter(|idx| {
        let name = &graph[**idx].name;
        name == &callee_norm
            || name.ends_with(&format!("::{}", callee_norm))
            // Module-prefixed callee matching a qualified symbol tail
            // (`mcp::McpServer::start` vs `McpServer::start`). Single-segment
            // names are excluded: `Cli::parse` must never link a free `parse`.
            || (name.contains("::") && callee_norm.ends_with(&format!("::{}", name)))
            || (callee_norm.starts_with("Self::") && name.ends_with(&format!("::{}", short)))
    });
    let first = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(*first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{SourceSpan, SymbolKind};
    use std::path::PathBuf;

    fn sym(id: &str, name: &str, file: &str, vis: Visibility) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: PathBuf::from(file),
            span: SourceSpan::new(1, 1, 5, 2),
            visibility: vis,
            loc: 5,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {}", name),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    fn method(id: &str, name: &str, file: &str, vis: Visibility, trait_impl: bool) -> Symbol {
        let mut s = sym(id, name, file, vis);
        s.kind = SymbolKind::Method;
        s.is_trait_impl = trait_impl;
        s
    }

    fn edge(from: &str, to: &str) -> DependencyEdge {
        DependencyEdge {
            from_symbol: from.to_string(),
            to_symbol: to.to_string(),
            kind: DependencyEdgeKind::Calls,
            count: 1,
        }
    }

    fn outgoing_names(sg: &SymbolGraph, from_id: &str) -> Vec<String> {
        let idx = sg.node_indices[from_id];
        sg.graph
            .neighbors_directed(idx, Direction::Outgoing)
            .map(|n| sg.graph[n].id.clone())
            .collect()
    }

    #[test]
    fn same_name_cross_file_prefers_caller_file() {
        let symbols = vec![
            sym("orders.rs::run", "run", "orders.rs", Visibility::Public),
            sym(
                "orders.rs::process",
                "process",
                "orders.rs",
                Visibility::Private,
            ),
            sym(
                "payments.rs::process",
                "process",
                "payments.rs",
                Visibility::Private,
            ),
        ];
        let edges = vec![edge("orders.rs::run", "process")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(
            outgoing_names(&sg, "orders.rs::run"),
            vec!["orders.rs::process"]
        );
    }

    #[test]
    fn ambiguous_bare_name_resolves_to_nothing() {
        let symbols = vec![
            sym("third.rs::run", "run", "third.rs", Visibility::Public),
            sym(
                "orders.rs::process",
                "process",
                "orders.rs",
                Visibility::Private,
            ),
            sym(
                "payments.rs::process",
                "process",
                "payments.rs",
                Visibility::Private,
            ),
        ];
        let edges = vec![edge("third.rs::run", "process")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert!(outgoing_names(&sg, "third.rs::run").is_empty());
    }

    #[test]
    fn qualified_callee_matches_across_files() {
        let symbols = vec![
            sym("main.rs::run", "run", "main.rs", Visibility::Public),
            method(
                "orders.rs::OrderStore::charge",
                "OrderStore::charge",
                "orders.rs",
                Visibility::Private,
                false,
            ),
            method(
                "payments.rs::PaymentStore::charge",
                "PaymentStore::charge",
                "payments.rs",
                Visibility::Private,
                false,
            ),
        ];
        let edges = vec![edge("main.rs::run", "PaymentStore::charge")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(
            outgoing_names(&sg, "main.rs::run"),
            vec!["payments.rs::PaymentStore::charge"]
        );
    }

    #[test]
    fn qualified_callee_never_falls_back_to_unrelated_namesake() {
        let symbols = vec![
            sym("main.rs::run", "run", "main.rs", Visibility::Public),
            method(
                "other.rs::Other::parse",
                "Other::parse",
                "other.rs",
                Visibility::Private,
                false,
            ),
        ];
        // `Cli::parse` must not link to `Other::parse`, and there is no `Cli`
        // type symbol for the enclosing-type fallback either.
        let edges = vec![edge("main.rs::run", "Cli::parse")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert!(outgoing_names(&sg, "main.rs::run").is_empty());
    }

    #[test]
    fn enclosing_type_fallback_links_assoc_calls() {
        let mut cli_struct = sym("main.rs::Cli", "Cli", "main.rs", Visibility::Private);
        cli_struct.kind = SymbolKind::Struct;
        let symbols = vec![
            sym("main.rs::main", "main", "main.rs", Visibility::Private),
            cli_struct,
        ];
        // Derive-generated `Cli::parse` has no parsed definition; link the type.
        let edges = vec![edge("main.rs::main", "Cli::parse")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(outgoing_names(&sg, "main.rs::main"), vec!["main.rs::Cli"]);
    }

    #[test]
    fn self_calls_resolve_same_file_and_keep_helpers_alive() {
        let symbols = vec![
            method(
                "engine.rs::Engine::analyze",
                "Engine::analyze",
                "engine.rs",
                Visibility::Public,
                false,
            ),
            method(
                "engine.rs::Engine::helper",
                "Engine::helper",
                "engine.rs",
                Visibility::Private,
                false,
            ),
        ];
        let edges = vec![edge("engine.rs::Engine::analyze", "Self::helper")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(
            outgoing_names(&sg, "engine.rs::Engine::analyze"),
            vec!["engine.rs::Engine::helper"]
        );
        assert!(sg.find_unreachable_orphans().is_empty());
    }

    #[test]
    fn test_symbols_are_entrypoints_not_orphans() {
        let mut attr_test = sym(
            "lib.rs::test_parse",
            "test_parse",
            "lib.rs",
            Visibility::Private,
        );
        attr_test.attributes = vec!["test".to_string()];
        // The scanner tags symbols under `tests/` relative to the scan root.
        let mut helper = sym(
            "tests/integration.rs::helper",
            "helper",
            "tests/integration.rs",
            Visibility::Private,
        );
        helper.attributes = vec![deslop_core::TEST_PATH_ATTR.to_string()];
        let symbols = vec![attr_test, helper];
        let sg = SymbolGraph::from_parsed(&symbols, &[]);
        assert!(sg.find_unreachable_orphans().is_empty());
    }

    #[test]
    fn trait_impl_methods_are_entrypoints() {
        let symbols = vec![method(
            "lib.rs::Cache::default",
            "Cache::default",
            "lib.rs",
            Visibility::Private,
            true,
        )];
        let sg = SymbolGraph::from_parsed(&symbols, &[]);
        assert!(sg.find_unreachable_orphans().is_empty());
    }

    #[test]
    fn enum_variant_use_links_the_enum() {
        let mut status = sym("lib.rs::Status", "Status", "lib.rs", Visibility::Private);
        status.kind = SymbolKind::Enum;
        let symbols = vec![
            sym("lib.rs::run", "run", "lib.rs", Visibility::Public),
            status,
        ];
        let edges = vec![DependencyEdge {
            from_symbol: "lib.rs::run".to_string(),
            to_symbol: "Status::Active".to_string(),
            kind: DependencyEdgeKind::ReferencesType,
            count: 1,
        }];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(outgoing_names(&sg, "lib.rs::run"), vec!["lib.rs::Status"]);
        assert!(sg.find_unreachable_orphans().is_empty());
    }

    #[test]
    fn unused_enum_is_still_an_orphan() {
        let mut status = sym("lib.rs::Status", "Status", "lib.rs", Visibility::Private);
        status.kind = SymbolKind::Enum;
        let symbols = vec![
            sym("lib.rs::live", "live", "lib.rs", Visibility::Public),
            status,
        ];
        let sg = SymbolGraph::from_parsed(&symbols, &[]);
        let orphans = sg.find_unreachable_orphans();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].name, "Status");
    }

    #[test]
    fn parallel_edges_collapse_to_one() {
        let symbols = vec![
            sym("lib.rs::a", "a", "lib.rs", Visibility::Public),
            sym("lib.rs::b", "b", "lib.rs", Visibility::Private),
        ];
        let edges = vec![
            edge("lib.rs::a", "b"),
            DependencyEdge {
                from_symbol: "lib.rs::a".to_string(),
                to_symbol: "b".to_string(),
                kind: DependencyEdgeKind::ReferencesType,
                count: 1,
            },
        ];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(sg.graph.edge_count(), 1);
        let degrees = sg.compute_degrees();
        assert_eq!(degrees["lib.rs::a"], (0, 1));
        assert_eq!(degrees["lib.rs::b"], (1, 0));
    }

    fn imports_for(file: &str, pairs: &[(&str, &str)]) -> HashMap<PathBuf, Vec<Import>> {
        let mut map = HashMap::new();
        map.insert(
            PathBuf::from(file),
            pairs
                .iter()
                .map(|(local, path)| Import {
                    local: local.to_string(),
                    path: path.to_string(),
                    is_glob: false,
                })
                .collect(),
        );
        map
    }

    #[test]
    fn renamed_import_rewrites_and_resolves() {
        let symbols = vec![
            sym("app.rs::run", "run", "app.rs", Visibility::Public),
            method(
                "store.rs::Store::charge",
                "Store::charge",
                "store.rs",
                Visibility::Private,
                false,
            ),
        ];
        let edges = vec![edge("app.rs::run", "PStore::charge")];
        let imports = imports_for("app.rs", &[("PStore", "payments::Store")]);
        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);
        assert_eq!(
            outgoing_names(&sg, "app.rs::run"),
            vec!["store.rs::Store::charge"]
        );
    }

    #[test]
    fn module_prefixed_callee_matches_qualified_tail() {
        let symbols = vec![
            sym("runner.rs::run", "run", "runner.rs", Visibility::Public),
            method(
                "server.rs::Server::start",
                "Server::start",
                "server.rs",
                Visibility::Private,
                false,
            ),
            method(
                "other.rs::Other::start",
                "Other::start",
                "other.rs",
                Visibility::Private,
                false,
            ),
        ];
        // `mcp::McpServer::start` shape: module prefix + Type::method.
        let edges = vec![edge("runner.rs::run", "net::Server::start")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert_eq!(
            outgoing_names(&sg, "runner.rs::run"),
            vec!["server.rs::Server::start"]
        );
    }

    #[test]
    fn qualified_callee_still_rejects_free_function_namesake() {
        let symbols = vec![
            sym("main.rs::run", "run", "main.rs", Visibility::Public),
            sym("util.rs::parse", "parse", "util.rs", Visibility::Private),
        ];
        let edges = vec![edge("main.rs::run", "Cli::parse")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert!(outgoing_names(&sg, "main.rs::run").is_empty());
    }

    #[test]
    fn glob_import_disambiguates_ambiguous_bare_name() {
        let symbols = vec![
            sym("app.rs::run", "run", "app.rs", Visibility::Public),
            sym(
                "helpers.rs::assist",
                "assist",
                "helpers.rs",
                Visibility::Private,
            ),
            sym(
                "other.rs::assist",
                "assist",
                "other.rs",
                Visibility::Private,
            ),
        ];
        let edges = vec![edge("app.rs::run", "assist")];
        let mut imports = HashMap::new();
        imports.insert(
            PathBuf::from("app.rs"),
            vec![Import {
                local: String::new(),
                path: "helpers".to_string(),
                is_glob: true,
            }],
        );
        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);
        assert_eq!(
            outgoing_names(&sg, "app.rs::run"),
            vec!["helpers.rs::assist"]
        );
    }

    #[test]
    fn truly_dead_private_fn_still_flagged() {
        let symbols = vec![
            sym("lib.rs::live", "live", "lib.rs", Visibility::Public),
            sym("lib.rs::dead", "dead", "lib.rs", Visibility::Private),
        ];
        let sg = SymbolGraph::from_parsed(&symbols, &[]);
        let orphans = sg.find_unreachable_orphans();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].name, "dead");
    }
}
