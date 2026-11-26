mod go;
mod python;
mod ts_js;

use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Import, Language, ParsedFile, SourceSpan, Symbol,
    SymbolKind, Visibility,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

pub fn parse_universal_file(path: &Path, content: &str, lang: Language) -> ParsedFile {
    let mut parser = Parser::new();
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    let ts_lang = match lang {
        Language::Python => Some(tree_sitter_python::LANGUAGE.into()),
        Language::Go => Some(tree_sitter_go::LANGUAGE.into()),
        Language::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => {
            if ext == "tsx" {
                Some(tree_sitter_typescript::LANGUAGE_TSX.into())
            } else {
                Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            }
        }
        _ => None,
    };

    if let Some(ts_lang) = ts_lang {
        if parser.set_language(&ts_lang).is_ok() {
            if let Some(tree) = parser.parse(content, None) {
                let mut symbols = Vec::new();
                let mut edges = Vec::new();
                let mut imports = Vec::new();
                extract_tree_sitter_ast(
                    path,
                    content,
                    &tree,
                    lang,
                    &mut symbols,
                    &mut edges,
                    &mut imports,
                );
                if !symbols.is_empty() {
                    return ParsedFile {
                        symbols,
                        edges,
                        imports,
                    };
                }
            }
        }
    }

    // Fallback: Lightweight token scanner if Tree-sitter is unavailable
    let (symbols, edges) = fallback_regex_parse(path, content, lang);
    ParsedFile {
        symbols,
        edges,
        imports: Vec::new(),
    }
}

fn extract_tree_sitter_ast(
    path: &Path,
    content: &str,
    tree: &Tree,
    lang: Language,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let root = tree.root_node();
    let file_str = path.to_string_lossy().to_string();

    match lang {
        Language::Python => {
            python::extract_python_nodes(
                path, &file_str, content, root, None, symbols, edges, imports,
            );
        }
        Language::TypeScript | Language::JavaScript => {
            ts_js::extract_ts_js_nodes(
                path, &file_str, content, root, None, false, symbols, edges, imports,
            );
        }
        Language::Go => {
            go::extract_go_nodes(path, &file_str, content, root, symbols, edges, imports);
        }
        _ => {}
    }
}

pub(super) fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() && start <= end {
        &source[start..end]
    } else {
        ""
    }
}

pub(super) fn hash_slice(slice: &str) -> String {
    let mut hasher = Sha256::new();
    let normalized = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    hasher.update(normalized.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(super) fn count_complexity(node: Node, triggers: &[&str]) -> usize {
    let mut count = 0;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if triggers.contains(&child.kind()) {
            count += 1;
        }
        count += count_complexity(child, triggers);
    }
    count
}

fn is_valid_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(super) fn extract_calls_in_node(
    from_symbol: &str,
    node: Node,
    source: &str,
    call_kind: &str,
    edges: &mut Vec<DependencyEdge>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == call_kind {
            if let Some(fn_node) = child.child(0) {
                let callee = node_text(fn_node, source).trim();
                let to_symbol = if let Some((recv, rest)) = callee.split_once('.') {
                    if !rest.contains('.') && is_valid_ident(recv) && is_valid_ident(rest) {
                        if recv == "this" || recv == "self" {
                            Some(format!("Self::{rest}"))
                        } else {
                            Some(format!("{recv}::{rest}"))
                        }
                    } else if let Some((_, last)) = callee.rsplit_once('.') {
                        is_valid_ident(last).then(|| last.to_string())
                    } else {
                        None
                    }
                } else if is_valid_ident(callee) {
                    Some(callee.to_string())
                } else {
                    None
                };
                if let Some(to_symbol) = to_symbol {
                    edges.push(DependencyEdge {
                        from_symbol: from_symbol.to_string(),
                        to_symbol,
                        kind: DependencyEdgeKind::Calls,
                        count: 1,
                    });
                }
            }
        }
        extract_calls_in_node(from_symbol, child, source, call_kind, edges);
    }
}

// ---------------------------------------------------------------------------
// Fallback: Lightweight token scanner
// ---------------------------------------------------------------------------
fn fallback_regex_parse(
    path: &Path,
    content: &str,
    _lang: Language,
) -> (Vec<Symbol>, Vec<DependencyEdge>) {
    let mut symbols = Vec::new();
    let file_str = path.to_string_lossy().to_string();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("def ")
            || trimmed.starts_with("func ")
            || trimmed.starts_with("function ")
        {
            let parts: Vec<&str> = trimmed.split([' ', '(']).collect();
            if parts.len() > 1 && !parts[1].is_empty() {
                let name = parts[1].to_string();
                symbols.push(Symbol {
                    id: format!("{}::{}", file_str, name),
                    name: name.clone(),
                    kind: SymbolKind::Function,
                    file_path: path.to_path_buf(),
                    span: SourceSpan::new(idx + 1, 1, idx + 2, 1),
                    visibility: Visibility::Public,
                    loc: 1,
                    cyclomatic_complexity: 1,
                    doc: None,
                    signature: trimmed.to_string(),
                    is_pure_hint: true,
                    ast_hash: None,
                    attributes: Vec::new(),
                    is_trait_impl: false,
                });
            }
        }
    }

    (symbols, Vec::new())
}
