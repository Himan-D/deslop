use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Language, SourceSpan, Symbol, SymbolKind, Visibility,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

pub fn parse_universal_file(
    path: &Path,
    content: &str,
    lang: Language,
) -> (Vec<Symbol>, Vec<DependencyEdge>) {
    let mut parser = Parser::new();
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

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
                extract_tree_sitter_ast(path, content, &tree, lang, &mut symbols, &mut edges);
                if !symbols.is_empty() {
                    return (symbols, edges);
                }
            }
        }
    }

    // Fallback: Lightweight token scanner if Tree-sitter is unavailable
    fallback_regex_parse(path, content, lang)
}

fn extract_tree_sitter_ast(
    path: &Path,
    content: &str,
    tree: &Tree,
    lang: Language,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let root = tree.root_node();
    let file_str = path.to_string_lossy().to_string();

    match lang {
        Language::Python => {
            extract_python_nodes(path, &file_str, content, root, None, symbols, edges);
        }
        Language::TypeScript | Language::JavaScript => {
            extract_ts_js_nodes(path, &file_str, content, root, None, symbols, edges);
        }
        Language::Go => {
            extract_go_nodes(path, &file_str, content, root, symbols, edges);
        }
        _ => {}
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() && start <= end {
        &source[start..end]
    } else {
        ""
    }
}

fn hash_slice(slice: &str) -> String {
    let mut hasher = Sha256::new();
    let normalized = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    hasher.update(normalized.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn count_complexity(node: Node, triggers: &[&str]) -> usize {
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

fn extract_calls_in_node(
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
                // Extract base identifier if it's an attribute call like obj.method()
                let clean_callee = if let Some(last_dot) = callee.rfind('.') {
                    &callee[last_dot + 1..]
                } else {
                    callee
                };
                if !clean_callee.is_empty() && clean_callee.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    edges.push(DependencyEdge {
                        from_symbol: from_symbol.to_string(),
                        to_symbol: clean_callee.to_string(),
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
// Python AST Extraction
// ---------------------------------------------------------------------------
fn extract_python_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    current_class: Option<&str>,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let fn_name = node_text(name_node, source).to_string();
                    let qualified_name = if let Some(cls) = current_class {
                        format!("{}::{}", cls, fn_name)
                    } else {
                        fn_name.clone()
                    };

                    let symbol_id = format!("{}::{}", file_str, qualified_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    let complexity_triggers = &[
                        "if_statement", "for_statement", "while_statement",
                        "try_statement", "except_clause", "conditional_expression",
                    ];
                    let cyclomatic = 1 + count_complexity(child, complexity_triggers);

                    let body_text = node_text(child, source);
                    let ast_hash = hash_slice(body_text);

                    let sig_text = child
                        .child_by_field_name("parameters")
                        .map(|p| format!("def {}{}", fn_name, node_text(p, source)))
                        .unwrap_or_else(|| format!("def {}()", fn_name));

                    let visibility = if fn_name.starts_with('_') && !fn_name.starts_with("__") {
                        Visibility::Private
                    } else {
                        Visibility::Public
                    };

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: qualified_name,
                        kind: if current_class.is_some() { SymbolKind::Method } else { SymbolKind::Function },
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility,
                        loc,
                        cyclomatic_complexity: cyclomatic,
                        doc: None,
                        signature: sig_text,
                        is_pure_hint: !body_text.contains("global ") && !body_text.contains("self."),
                        ast_hash: Some(ast_hash),
                    });

                    extract_calls_in_node(&symbol_id, child, source, "call", edges);
                }
            }
            "class_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let class_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, class_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    // Superclass / base class inheritance
                    if let Some(arg_list) = child.child_by_field_name("superclasses") {
                        let mut arg_cursor = arg_list.walk();
                        for base_node in arg_list.children(&mut arg_cursor) {
                            let base_name = node_text(base_node, source).trim();
                            if !base_name.is_empty() && base_name != "(" && base_name != ")" && base_name != "," {
                                edges.push(DependencyEdge {
                                    from_symbol: symbol_id.clone(),
                                    to_symbol: base_name.to_string(),
                                    kind: DependencyEdgeKind::Inherits,
                                    count: 1,
                                });
                            }
                        }
                    }

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: class_name.clone(),
                        kind: SymbolKind::Class,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility: if class_name.starts_with('_') { Visibility::Private } else { Visibility::Public },
                        loc,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: format!("class {}:", class_name),
                        is_pure_hint: false,
                        ast_hash: None,
                    });

                    // Visit methods inside class body
                    if let Some(body_node) = child.child_by_field_name("body") {
                        extract_python_nodes(path, file_str, source, body_node, Some(&class_name), symbols, edges);
                    }
                }
            }
            "import_statement" | "import_from_statement" => {
                let stmt_text = node_text(child, source);
                let imported = stmt_text
                    .replace("import ", "")
                    .replace("from ", "")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !imported.is_empty() {
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: imported,
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                }
            }
            _ => {
                extract_python_nodes(path, file_str, source, child, current_class, symbols, edges);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TypeScript / JavaScript AST Extraction
// ---------------------------------------------------------------------------
fn extract_ts_js_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    current_class: Option<&str>,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" | "generator_function_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let fn_name = node_text(name_node, source).to_string();
                    let qualified = if let Some(cls) = current_class {
                        format!("{}::{}", cls, fn_name)
                    } else {
                        fn_name.clone()
                    };
                    register_ts_fn(path, file_str, source, child, qualified, fn_name, current_class.is_some(), symbols, edges);
                }
            }
            "method_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let fn_name = node_text(name_node, source).to_string();
                    let qualified = if let Some(cls) = current_class {
                        format!("{}::{}", cls, fn_name)
                    } else {
                        fn_name.clone()
                    };
                    register_ts_fn(path, file_str, source, child, qualified, fn_name, true, symbols, edges);
                }
            }
            "class_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let class_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, class_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    // Class heritage: extends and implements
                    let mut heritage_cursor = child.walk();
                    for h_child in child.children(&mut heritage_cursor) {
                        if h_child.kind() == "class_heritage" {
                            let text = node_text(h_child, source);
                            for token in text.split_whitespace() {
                                if token != "extends" && token != "implements" && token.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                    edges.push(DependencyEdge {
                                        from_symbol: symbol_id.clone(),
                                        to_symbol: token.to_string(),
                                        kind: DependencyEdgeKind::Implements,
                                        count: 1,
                                    });
                                }
                            }
                        }
                    }

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: class_name.clone(),
                        kind: SymbolKind::Class,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility: Visibility::Public,
                        loc,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: format!("class {}", class_name),
                        is_pure_hint: false,
                        ast_hash: None,
                    });

                    if let Some(body_node) = child.child_by_field_name("body") {
                        extract_ts_js_nodes(path, file_str, source, body_node, Some(&class_name), symbols, edges);
                    }
                }
            }
            "interface_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let iface_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, iface_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    symbols.push(Symbol {
                        id: symbol_id,
                        name: iface_name.clone(),
                        kind: SymbolKind::Interface,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility: Visibility::Public,
                        loc,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: format!("interface {}", iface_name),
                        is_pure_hint: true,
                        ast_hash: None,
                    });
                }
            }
            "import_statement" => {
                let stmt_text = node_text(child, source);
                if let Some(quote_start) = stmt_text.find(['\'', '"']) {
                    let sub = &stmt_text[quote_start + 1..];
                    if let Some(quote_end) = sub.find(['\'', '"']) {
                        let module_target = &sub[..quote_end];
                        edges.push(DependencyEdge {
                            from_symbol: file_str.to_string(),
                            to_symbol: module_target.to_string(),
                            kind: DependencyEdgeKind::Imports,
                            count: 1,
                        });
                    }
                }
            }
            _ => {
                extract_ts_js_nodes(path, file_str, source, child, current_class, symbols, edges);
            }
        }
    }
}

fn register_ts_fn(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    qualified_name: String,
    fn_name: String,
    is_method: bool,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let symbol_id = format!("{}::{}", file_str, qualified_name);
    let start_point = node.start_position();
    let end_point = node.end_position();
    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

    let complexity_triggers = &[
        "if_statement", "for_statement", "for_in_statement",
        "while_statement", "do_statement", "switch_case", "catch_clause",
        "ternary_expression",
    ];
    let cyclomatic = 1 + count_complexity(node, complexity_triggers);
    let body_text = node_text(node, source);
    let ast_hash = hash_slice(body_text);

    let sig_text = node
        .child_by_field_name("parameters")
        .map(|p| format!("function {}{}", fn_name, node_text(p, source)))
        .unwrap_or_else(|| format!("function {}()", fn_name));

    symbols.push(Symbol {
        id: symbol_id.clone(),
        name: qualified_name,
        kind: if is_method { SymbolKind::Method } else { SymbolKind::Function },
        file_path: path.to_path_buf(),
        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
        visibility: Visibility::Public,
        loc,
        cyclomatic_complexity: cyclomatic,
        doc: None,
        signature: sig_text,
        is_pure_hint: !body_text.contains("this.") && !body_text.contains("console."),
        ast_hash: Some(ast_hash),
    });

    extract_calls_in_node(&symbol_id, node, source, "call_expression", edges);
}

// ---------------------------------------------------------------------------
// Go AST Extraction
// ---------------------------------------------------------------------------
fn extract_go_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let fn_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, fn_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    let complexity_triggers = &[
                        "if_statement", "for_statement", "expression_case", "type_case", "communication_case",
                    ];
                    let cyclomatic = 1 + count_complexity(child, complexity_triggers);
                    let body_text = node_text(child, source);
                    let ast_hash = hash_slice(body_text);

                    let sig_text = child
                        .child_by_field_name("parameters")
                        .map(|p| format!("func {}{}", fn_name, node_text(p, source)))
                        .unwrap_or_else(|| format!("func {}()", fn_name));

                    let visibility = if fn_name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: fn_name.clone(),
                        kind: SymbolKind::Function,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility,
                        loc,
                        cyclomatic_complexity: cyclomatic,
                        doc: None,
                        signature: sig_text,
                        is_pure_hint: !body_text.contains("&") && !body_text.contains("panic"),
                        ast_hash: Some(ast_hash),
                    });

                    extract_calls_in_node(&symbol_id, child, source, "call_expression", edges);
                }
            }
            "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let m_name = node_text(name_node, source).to_string();
                    let receiver = child
                        .child_by_field_name("receiver")
                        .map(|r| node_text(r, source).replace(['(', ')', '*', ' '], ""))
                        .unwrap_or_else(|| "Unknown".to_string());

                    let qualified = format!("{}::{}", receiver, m_name);
                    let symbol_id = format!("{}::{}", file_str, qualified);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    let complexity_triggers = &[
                        "if_statement", "for_statement", "expression_case", "type_case", "communication_case",
                    ];
                    let cyclomatic = 1 + count_complexity(child, complexity_triggers);
                    let body_text = node_text(child, source);
                    let ast_hash = hash_slice(body_text);

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: qualified,
                        kind: SymbolKind::Method,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                        visibility: if m_name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                            Visibility::Public
                        } else {
                            Visibility::Private
                        },
                        loc,
                        cyclomatic_complexity: cyclomatic,
                        doc: None,
                        signature: format!("func ({}) {}()", receiver, m_name),
                        is_pure_hint: false,
                        ast_hash: Some(ast_hash),
                    });

                    extract_calls_in_node(&symbol_id, child, source, "call_expression", edges);
                }
            }
            "type_declaration" => {
                let mut type_cursor = child.walk();
                for t_spec in child.children(&mut type_cursor) {
                    if t_spec.kind() == "type_spec" {
                        if let Some(name_node) = t_spec.child_by_field_name("name") {
                            let type_name = node_text(name_node, source).to_string();
                            let symbol_id = format!("{}::{}", file_str, type_name);
                            let start_point = child.start_position();
                            let end_point = child.end_position();
                            let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                            let type_node = t_spec.child_by_field_name("type");
                            let kind = match type_node.map(|t| t.kind()) {
                                Some("struct_type") => SymbolKind::Struct,
                                Some("interface_type") => SymbolKind::Interface,
                                _ => SymbolKind::TypeAlias,
                            };

                            symbols.push(Symbol {
                                id: symbol_id,
                                name: type_name.clone(),
                                kind,
                                file_path: path.to_path_buf(),
                                span: SourceSpan::new(start_point.row + 1, start_point.column + 1, end_point.row + 1, end_point.column + 1),
                                visibility: if type_name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                                    Visibility::Public
                                } else {
                                    Visibility::Private
                                },
                                loc,
                                cyclomatic_complexity: 1,
                                doc: None,
                                signature: format!("type {} {:?}", type_name, kind),
                                is_pure_hint: true,
                                ast_hash: None,
                            });
                        }
                    }
                }
            }
            _ => {
                extract_go_nodes(path, file_str, source, child, symbols, edges);
            }
        }
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
        if trimmed.starts_with("def ") || trimmed.starts_with("func ") || trimmed.starts_with("function ") {
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
                });
            }
        }
    }

    (symbols, Vec::new())
}
