use deslop_core::{DependencyEdgeKind, Import, Symbol};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::path::Path;

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

/// Short name: last segment after `::` or `.` (`Self::foo` -> `foo`,
/// `obj.method` -> `method`).
pub(crate) fn short_name(qualified: &str) -> &str {
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
pub(crate) fn normalize_callee(callee: &str, imports: &[Import]) -> (String, bool) {
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
pub(crate) fn resolve_callee(
    callee: &str,
    caller_file: Option<&Path>,
    file_scoped: &HashMap<(&Path, &str), Vec<NodeIndex>>,
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
    while let Some(rest) = p.strip_prefix("./").or_else(|| p.strip_prefix("../")) {
        p = rest;
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
    caller_file: Option<&Path>,
    file_scoped: &HashMap<(&Path, &str), Vec<NodeIndex>>,
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
