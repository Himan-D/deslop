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

/// How an edge between two symbol nodes was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeResolution {
    /// Direct symbol ID hit, `Self::` same-file hit, or qualified `match_qualified` hit.
    Exact,
    /// Resolved via `normalize_callee` import alias, `file_imports`, or `tsconfig` path alias.
    ImportScoped,
    /// Resolved via unqualified bare-name global (`cands.len() == 1`) or same-file unqualified fallback.
    BareHeuristic,
}

pub struct SymbolGraph {
    pub graph: DiGraph<Symbol, DependencyEdgeKind>,
    pub node_indices: HashMap<String, NodeIndex>,
    edge_resolutions: HashMap<(NodeIndex, NodeIndex), EdgeResolution>,
}

impl SymbolGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
            edge_resolutions: HashMap::new(),
        }
    }

    /// Returns how the edge `from -> to` was resolved, if present in the graph.
    pub fn edge_resolution(&self, from: NodeIndex, to: NodeIndex) -> Option<EdgeResolution> {
        self.edge_resolutions.get(&(from, to)).copied()
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

        let tsconfig_aliases = find_tsconfig_aliases(symbols, imports);

        for edge in edges {
            let from_opt = sg.node_indices.get(&edge.from_symbol).copied();
            let to_opt = sg
                .node_indices
                .get(&edge.to_symbol)
                .copied()
                .map(|idx| (idx, EdgeResolution::Exact))
                .or_else(|| {
                    let caller_file = from_opt.map(|u| sg.graph[u].file_path.as_path());
                    let raw_imports: &[Import] = caller_file
                        .and_then(|f| imports.get(f))
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    let expanded_storage: Vec<Import>;
                    let file_imports: &[Import] = if tsconfig_aliases.is_empty() {
                        raw_imports
                    } else {
                        expanded_storage = raw_imports
                            .iter()
                            .map(|imp| Import {
                                local: imp.local.clone(),
                                path: expand_tsconfig_import(&imp.path, &tsconfig_aliases),
                                is_glob: imp.is_glob,
                            })
                            .collect();
                        &expanded_storage
                    };
                    let (normalized, used_import_alias) =
                        normalize_callee(&edge.to_symbol, file_imports);
                    resolve_callee(
                        &normalized,
                        caller_file,
                        &file_scoped,
                        &global,
                        &sg.graph,
                        file_imports,
                    )
                    .map(|(idx, res)| {
                        if used_import_alias {
                            (idx, EdgeResolution::ImportScoped)
                        } else {
                            (idx, res)
                        }
                    })
                });

            if let (Some(u), Some((v, resolution))) = (from_opt, to_opt) {
                // One edge per ordered pair: callers often reference the same
                // symbol several ways (call + type mention), and degrees
                // should count unique relationships, not mentions.
                if u != v && !sg.graph.contains_edge(u, v) {
                    sg.graph.add_edge(u, v, edge.kind);
                    sg.edge_resolutions.insert((u, v), resolution);
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

    /// Tarjan's SCC to identify circular dependency loops (length > 1),
    /// paired with whether any edge within the SCC was resolved via `BareHeuristic`.
    pub fn find_circular_dependencies_with_confidence(&self) -> Vec<(Vec<String>, bool)> {
        let sccs = tarjan_scc(&self.graph);
        let mut cycles = Vec::new();

        for scc in sccs {
            if scc.len() > 1 {
                let scc_set: HashSet<NodeIndex> = scc.iter().copied().collect();
                let uses_bare_heuristic = scc.iter().any(|&u| {
                    self.graph
                        .neighbors_directed(u, Direction::Outgoing)
                        .any(|v| {
                            scc_set.contains(&v)
                                && self.edge_resolution(u, v)
                                    == Some(EdgeResolution::BareHeuristic)
                        })
                });
                let cycle_names: Vec<String> = scc
                    .into_iter()
                    .map(|idx| self.graph[idx].name.clone())
                    .collect();
                cycles.push((cycle_names, uses_bare_heuristic));
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

/// Reads `tsconfig.json` in `root` if present and extracts `compilerOptions.paths`
/// prefix mappings (combined with `compilerOptions.baseUrl`), e.g.
/// `"@/*": ["src/*"]` -> `"@" -> "src"`.
pub fn load_tsconfig_aliases(root: &std::path::Path) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    let tsconfig_path = root.join("tsconfig.json");
    let Ok(content) = std::fs::read_to_string(&tsconfig_path) else {
        return aliases;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return aliases;
    };
    let Some(compiler_opts) = json.get("compilerOptions") else {
        return aliases;
    };

    let base_url = compiler_opts
        .get("baseUrl")
        .and_then(|v| v.as_str())
        .map(|s| {
            let trimmed = s.trim().trim_start_matches("./").trim_end_matches('/');
            if trimmed == "." {
                ""
            } else {
                trimmed
            }
        })
        .unwrap_or("");

    if let Some(paths) = compiler_opts.get("paths").and_then(|v| v.as_object()) {
        for (pattern, targets_val) in paths {
            let Some(target) = targets_val
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let alias_key = pattern
                .trim_end_matches("/*")
                .trim_end_matches('*')
                .trim_end_matches('/');
            if alias_key.is_empty() {
                continue;
            }
            let raw_target = target
                .trim()
                .trim_start_matches("./")
                .trim_end_matches("/*")
                .trim_end_matches('*')
                .trim_end_matches('/');
            let full_target = if base_url.is_empty() || base_url == "." {
                raw_target.to_string()
            } else if raw_target.is_empty() || raw_target == "." {
                base_url.to_string()
            } else {
                format!("{}/{}", base_url, raw_target)
            };
            if !full_target.is_empty() {
                aliases.insert(alias_key.to_string(), full_target);
            }
        }
    }

    aliases
}

/// Expands a `tsconfig` path alias prefix in `import_path` using `aliases`,
/// returning `import_path` unchanged if no alias matches.
pub fn expand_tsconfig_import(import_path: &str, aliases: &HashMap<String, String>) -> String {
    if aliases.is_empty() {
        return import_path.to_string();
    }
    let mut keys: Vec<&String> = aliases.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()));
    for key in keys {
        if import_path == key.as_str() {
            return aliases[key].clone();
        }
        if let Some(rest) = import_path.strip_prefix(key.as_str()) {
            if let Some(after_slash) = rest.strip_prefix('/') {
                return format!("{}/{}", aliases[key], after_slash);
            }
        }
    }
    import_path.to_string()
}

fn find_tsconfig_aliases(
    symbols: &[Symbol],
    imports: &HashMap<std::path::PathBuf, Vec<Import>>,
) -> HashMap<String, String> {
    let paths: Vec<&std::path::Path> = if !imports.is_empty() {
        imports.keys().map(|p| p.as_path()).collect()
    } else {
        symbols.iter().map(|s| s.file_path.as_path()).collect()
    };
    let Some(mut common) = common_dir_prefix(&paths) else {
        return HashMap::new();
    };
    loop {
        if common.join("tsconfig.json").is_file() {
            return load_tsconfig_aliases(&common);
        }
        if !common.pop() {
            break;
        }
    }
    HashMap::new()
}

fn common_dir_prefix(paths: &[&std::path::Path]) -> Option<std::path::PathBuf> {
    let first = paths.first()?;
    let mut prefix: Vec<_> = first.parent().unwrap_or(first).components().collect();
    for path in &paths[1..] {
        let comps: Vec<_> = path.parent().unwrap_or(path).components().collect();
        let common_len = prefix
            .iter()
            .zip(comps.iter())
            .take_while(|(a, b)| a == b)
            .count();
        prefix.truncate(common_len);
    }
    if prefix.is_empty() {
        Some(std::path::PathBuf::new())
    } else {
        Some(prefix.into_iter().collect())
    }
}

/// Rewrites a callee through the caller's `use` imports: strips
/// module-relative heads (`crate::`, `self::`, `super::`) and expands the
/// head segment through renames (`PStore::charge` with
/// `use payments::Store as PStore` becomes `payments::Store::charge`).
/// Single-level only; alias chains are not followed.
fn normalize_callee(callee: &str, imports: &[Import]) -> (String, bool) {
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
            let (final_norm, _) = normalize_callee(&rewritten, &[]);
            return (final_norm, true);
        }
    } else if let Some(imp) = imports
        .iter()
        .find(|i| !i.is_glob && i.local == norm && i.path.contains("::"))
    {
        return (imp.path.clone(), true);
    }
    (norm, false)
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
    file_imports: &[Import],
) -> Option<(NodeIndex, EdgeResolution)> {
    let short = short_name(callee);
    let is_self = callee == "Self" || callee.starts_with("Self::");

    if let Some(file) = caller_file {
        if let Some(cands) = file_scoped.get(&(file, short)) {
            if is_self {
                if cands.len() == 1 {
                    return Some((cands[0], EdgeResolution::Exact));
                }
                if let Some(hit) = match_qualified(callee, cands, graph) {
                    return Some((hit, EdgeResolution::Exact));
                }
                return None;
            }
            if callee.contains("::") {
                if let Some(hit) = match_qualified(callee, cands, graph) {
                    return Some((hit, EdgeResolution::Exact));
                }
                // Qualified call did not match a symbol in this file; fall through
                // to global qualified / import-scoped resolution.
            } else {
                // Same-file unqualified call: pick the unique or first local match
                // rather than leaking across files.
                return cands
                    .first()
                    .copied()
                    .map(|idx| (idx, EdgeResolution::BareHeuristic));
            }
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
                return Some((hit, EdgeResolution::Exact));
            }
            if cands.len() == 1 && (callee.starts_with('.') || callee.contains('/')) {
                return Some((cands[0], EdgeResolution::ImportScoped));
            }
            if cands.len() > 1 {
                if let Some(head) = callee.split("::").next() {
                    let hint = module_hint(head);
                    if !hint.is_empty() {
                        if let Some(hit) = disambiguate_by_file(cands, graph, hint) {
                            return Some((hit, EdgeResolution::ImportScoped));
                        }
                    }
                }
            }
        }
        return resolve_enclosing_type(callee, caller_file, file_scoped, global, graph)
            .map(|idx| (idx, EdgeResolution::Exact));
    }

    if let Some(cands) = cands {
        if cands.len() == 1 {
            return Some((cands[0], EdgeResolution::BareHeuristic));
        }
        for imp in file_imports
            .iter()
            .filter(|i| i.is_glob || i.local == callee)
        {
            let hint = module_hint(&imp.path);
            if !hint.is_empty() {
                if let Some(hit) = disambiguate_by_file(cands, graph, hint) {
                    return Some((hit, EdgeResolution::ImportScoped));
                }
            }
        }
        if let Some(hit) = match_qualified(callee, cands, graph) {
            return Some((hit, EdgeResolution::Exact));
        }
    }
    None
}

/// Extracts the last meaningful module/file segment from an import path across
/// `::`, `/`, and `.`, ignoring leading `./` or `../` and trailing source
/// extensions (`.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.go`).
fn module_hint(path: &str) -> &str {
    let mut p = path.trim();
    loop {
        if let Some(rest) = p.strip_prefix("./").or_else(|| p.strip_prefix("../")) {
            p = rest;
        } else {
            break;
        }
    }
    for ext in [".tsx", ".ts", ".jsx", ".js", ".py", ".go"] {
        if let Some(stem) = p.strip_suffix(ext) {
            p = stem;
            break;
        }
    }
    p.rsplit([':', '/', '.'])
        .find(|s| !s.is_empty())
        .unwrap_or("")
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
    fn relative_ts_import_disambiguates_colliding_function() {
        let symbols = vec![
            sym("app.ts::render", "render", "app.ts", Visibility::Public),
            sym("date.ts::format", "format", "date.ts", Visibility::Public),
            sym("other.ts::format", "format", "other.ts", Visibility::Public),
        ];
        let edges = vec![edge("app.ts::render", "format")];
        let imports = imports_for("app.ts", &[("format", "./date")]);
        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);
        assert_eq!(
            outgoing_names(&sg, "app.ts::render"),
            vec!["date.ts::format"]
        );
    }

    #[test]
    fn dotted_and_slashed_module_imports_disambiguate() {
        let symbols = vec![
            sym("main.py::run", "run", "main.py", Visibility::Public),
            sym("sub.py::parse", "parse", "sub.py", Visibility::Public),
            sym("other.py::parse", "parse", "other.py", Visibility::Public),
            sym("main.go::serve", "serve", "main.go", Visibility::Public),
            sym("http.go::Get", "Get", "http.go", Visibility::Public),
            sym("other.go::Get", "Get", "other.go", Visibility::Public),
        ];
        let edges = vec![
            edge("main.py::run", "parse"),
            edge("main.go::serve", "Get"),
        ];
        let mut imports = imports_for("main.py", &[("parse", "pkg.sub")]);
        imports.extend(imports_for("main.go", &[("Get", "net/http")]));
        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);
        assert_eq!(outgoing_names(&sg, "main.py::run"), vec!["sub.py::parse"]);
        assert_eq!(outgoing_names(&sg, "main.go::serve"), vec!["http.go::Get"]);
    }

    #[test]
    fn same_file_qualified_call_does_not_falsely_resolve() {
        let symbols = vec![
            sym("mod.rs::run", "run", "mod.rs", Visibility::Public),
            method(
                "mod.rs::Foo::new",
                "Foo::new",
                "mod.rs",
                Visibility::Private,
                false,
            ),
            method(
                "mod.rs::Baz::new",
                "Baz::new",
                "mod.rs",
                Visibility::Private,
                false,
            ),
        ];
        let edges = vec![edge("mod.rs::run", "Bar::new")];
        let sg = SymbolGraph::from_parsed(&symbols, &edges);
        assert!(outgoing_names(&sg, "mod.rs::run").is_empty());
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

    #[test]
    fn edge_resolution_distinguishes_exact_import_and_bare_heuristic() {
        let symbols = vec![
            sym("a.rs::alpha", "alpha", "a.rs", Visibility::Public),
            sym("a.rs::local_fn", "local_fn", "a.rs", Visibility::Private),
            sym("b.rs::beta", "beta", "b.rs", Visibility::Public),
            sym("c.rs::gamma", "gamma", "c.rs", Visibility::Public),
            sym("d.rs::gamma", "gamma", "d.rs", Visibility::Public),
            sym("e.rs::unique_fn", "unique_fn", "e.rs", Visibility::Public),
        ];
        let edges = vec![
            // Direct ID hit -> Exact
            edge("a.rs::alpha", "b.rs::beta"),
            // Same-file unqualified fallback -> BareHeuristic
            edge("a.rs::alpha", "local_fn"),
            // Import-scoped disambiguation -> ImportScoped
            edge("a.rs::alpha", "gamma"),
            // Global single-candidate bare name -> BareHeuristic
            edge("b.rs::beta", "unique_fn"),
            // Cycle back from unique_fn -> a.rs::alpha via direct ID -> Exact
            edge("e.rs::unique_fn", "a.rs::alpha"),
        ];
        let imports = imports_for("a.rs", &[("gamma", "c")]);
        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);

        let a = sg.node_indices["a.rs::alpha"];
        let local = sg.node_indices["a.rs::local_fn"];
        let b = sg.node_indices["b.rs::beta"];
        let c = sg.node_indices["c.rs::gamma"];
        let e = sg.node_indices["e.rs::unique_fn"];

        assert_eq!(sg.edge_resolution(a, b), Some(EdgeResolution::Exact));
        assert_eq!(
            sg.edge_resolution(a, local),
            Some(EdgeResolution::BareHeuristic)
        );
        assert_eq!(sg.edge_resolution(a, c), Some(EdgeResolution::ImportScoped));
        assert_eq!(
            sg.edge_resolution(b, e),
            Some(EdgeResolution::BareHeuristic)
        );
        assert_eq!(sg.edge_resolution(e, a), Some(EdgeResolution::Exact));

        // Cycle (alpha -> beta -> unique_fn -> alpha) contains a BareHeuristic edge (beta -> unique_fn)
        let cycles = sg.find_circular_dependencies_with_confidence();
        assert_eq!(cycles.len(), 1);
        assert!(cycles[0].1);

        // A cycle with only Exact edges reports uses_bare_heuristic = false
        let exact_symbols = vec![
            sym("x.rs::x", "x", "x.rs", Visibility::Public),
            sym("y.rs::y", "y", "y.rs", Visibility::Public),
        ];
        let exact_edges = vec![edge("x.rs::x", "y.rs::y"), edge("y.rs::y", "x.rs::x")];
        let exact_sg = SymbolGraph::from_parsed(&exact_symbols, &exact_edges);
        let exact_cycles = exact_sg.find_circular_dependencies_with_confidence();
        assert_eq!(exact_cycles.len(), 1);
        assert!(!exact_cycles[0].1);
    }

    #[test]
    fn tsconfig_alias_expands_and_disambiguates_import() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("deslop_tsconfig_test_{}", unique_id));
        let src_dir = root.join("src");
        let lib_dir = src_dir.join("lib");
        let other_dir = root.join("other");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::create_dir_all(&other_dir).unwrap();

        std::fs::write(
            root.join("tsconfig.json"),
            r#"{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@auth": ["src/lib/auth"]
    }
  }
}"#,
        )
        .unwrap();

        let aliases = load_tsconfig_aliases(&root);
        assert_eq!(aliases.get("@").map(String::as_str), Some("src"));
        assert_eq!(
            expand_tsconfig_import("@/lib/auth", &aliases),
            "src/lib/auth"
        );
        assert_eq!(expand_tsconfig_import("@auth", &aliases), "src/lib/auth");
        assert_eq!(expand_tsconfig_import("lodash", &aliases), "lodash");

        let app_file = src_dir.join("app.ts");
        let auth_file = lib_dir.join("auth.ts");
        let other_file = other_dir.join("legacy.ts");

        let app_str = app_file.to_string_lossy().to_string();
        let auth_str = auth_file.to_string_lossy().to_string();
        let other_str = other_file.to_string_lossy().to_string();

        let symbols = vec![
            sym(&format!("{}::main", app_str), "main", &app_str, Visibility::Public),
            sym(
                &format!("{}::authenticate", auth_str),
                "authenticate",
                &auth_str,
                Visibility::Public,
            ),
            sym(
                &format!("{}::authenticate", other_str),
                "authenticate",
                &other_str,
                Visibility::Public,
            ),
        ];
        let edges = vec![edge(&format!("{}::main", app_str), "authenticate")];
        let mut imports = HashMap::new();
        imports.insert(
            app_file,
            vec![Import {
                local: "authenticate".to_string(),
                path: "@auth".to_string(),
                is_glob: false,
            }],
        );

        let sg = SymbolGraph::from_parsed_with_imports(&symbols, &edges, &imports);
        let main_id = format!("{}::main", app_str);
        let auth_id = format!("{}::authenticate", auth_str);
        assert_eq!(outgoing_names(&sg, &main_id), vec![auth_id.clone()]);
        assert_eq!(
            sg.edge_resolution(sg.node_indices[&main_id], sg.node_indices[&auth_id]),
            Some(EdgeResolution::ImportScoped)
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
