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
// Fallback: Lightweight block & call scanner
// ---------------------------------------------------------------------------
fn fallback_regex_parse(
    path: &Path,
    content: &str,
    lang: Language,
) -> (Vec<Symbol>, Vec<DependencyEdge>) {
    let mut symbols = Vec::new();
    let mut edges = Vec::new();
    let file_str = path.to_string_lossy().to_string();
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_fn_decl = trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("func ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("export function ")
            || trimmed.starts_with("export async function ");
        if !is_fn_decl {
            continue;
        }

        let after_kw = trimmed
            .split("function ")
            .nth(1)
            .or_else(|| trimmed.split("def ").nth(1))
            .or_else(|| {
                let rest = trimmed.split("func ").nth(1)?;
                // Handle Go receiver methods: `func (r *Recv) foo(...)`
                if let Some(after_recv) = rest.strip_prefix('(').and_then(|s| s.split_once(')')) {
                    Some(after_recv.1.trim_start())
                } else {
                    Some(rest)
                }
            })
            .unwrap_or("");
        let name = after_kw
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }

        let end_idx = compute_fallback_block_end(&lines, idx, lang);
        let loc = (end_idx - idx + 1).max(1);
        let sym_id = format!("{}::{}", file_str, name);

        for body_line in &lines[idx..=end_idx] {
            for callee in extract_fallback_callees(body_line) {
                if callee != name {
                    edges.push(DependencyEdge {
                        from_symbol: sym_id.clone(),
                        to_symbol: callee,
                        kind: DependencyEdgeKind::Calls,
                        count: 1,
                    });
                }
            }
        }

        symbols.push(Symbol {
            id: sym_id,
            name,
            kind: SymbolKind::Function,
            file_path: path.to_path_buf(),
            span: SourceSpan::new(idx + 1, 1, end_idx + 1, 1),
            visibility: Visibility::Public,
            loc,
            cyclomatic_complexity: 1,
            doc: None,
            signature: trimmed.to_string(),
            is_pure_hint: true,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        });
    }

    (symbols, edges)
}

fn compute_fallback_block_end(lines: &[&str], start_idx: usize, lang: Language) -> usize {
    if lang == Language::Python {
        let base_indent = lines[start_idx]
            .chars()
            .take_while(|c| c.is_whitespace())
            .count();
        let mut end = start_idx;
        for (offset, line) in lines[start_idx + 1..].iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = line.chars().take_while(|c| c.is_whitespace()).count();
            if indent <= base_indent {
                break;
            }
            end = start_idx + 1 + offset;
        }
        return end;
    }

    let mut depth: i32 = 0;
    let mut seen_brace = false;
    for (offset, line) in lines[start_idx..].iter().enumerate() {
        let mut in_quote: Option<char> = None;
        let mut escaped = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if let Some(q) = in_quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    in_quote = None;
                }
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'/') {
                break;
            }
            if ch == '"' || ch == '\'' || ch == '`' {
                in_quote = Some(ch);
                continue;
            }
            if ch == '{' {
                depth += 1;
                seen_brace = true;
            } else if ch == '}' {
                depth -= 1;
                if seen_brace && depth <= 0 {
                    return start_idx + offset;
                }
            }
        }
        // Brace-less declaration (e.g. TS overload `function foo(): void;`)
        if offset == 0 && !seen_brace && line.trim_end().ends_with(';') {
            return start_idx;
        }
    }
    start_idx
}

fn extract_fallback_callees(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return out;
    }
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                in_quote = None;
            }
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            in_quote = Some(b);
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'(' && i > 0 {
            let mut end = i;
            while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            let mut start = end;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
            {
                start -= 1;
            }
            if start < end {
                let ident = &line[start..end];
                if !matches!(
                    ident,
                    "if" | "elif"
                        | "for"
                        | "while"
                        | "switch"
                        | "match"
                        | "catch"
                        | "def"
                        | "func"
                        | "function"
                        | "return"
                        | "await"
                        | "typeof"
                ) {
                    out.push(ident.to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_parse_computes_block_loc_and_ignores_string_braces() {
        let src =
            "function alpha() {\n    const s = \"}\";\n    helper();\n}\nfunction beta() {}\n";
        let (syms, edges) = fallback_regex_parse(Path::new("app.js"), src, Language::JavaScript);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "alpha");
        assert_eq!(syms[0].loc, 4);
        assert!(edges.iter().any(|e| e.to_symbol == "helper"));
    }

    #[test]
    fn fallback_parse_supports_go_receiver_methods() {
        let src = "func (s *Server) Handle() {\n    serve()\n}\n";
        let (syms, edges) = fallback_regex_parse(Path::new("srv.go"), src, Language::Go);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "Handle");
        assert_eq!(syms[0].loc, 3);
        assert!(edges.iter().any(|e| e.to_symbol == "serve"));
    }
}
