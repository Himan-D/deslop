use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Import, SourceSpan, Symbol, SymbolKind, Visibility,
};
use std::path::Path;
use tree_sitter::Node;

pub(super) fn extract_go_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_declaration" => {
                extract_go_imports(file_str, source, child, edges, imports);
            }
            "import_spec" => {
                extract_go_import_spec(file_str, source, child, edges, imports);
            }
            "function_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let fn_name = super::node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, fn_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    let complexity_triggers = &[
                        "if_statement",
                        "for_statement",
                        "expression_case",
                        "type_case",
                        "communication_case",
                    ];
                    let cyclomatic = 1 + super::count_complexity(child, complexity_triggers);
                    let body_text = super::node_text(child, source);
                    let ast_hash = super::hash_slice(body_text);

                    let params_text = child
                        .child_by_field_name("parameters")
                        .map(|p| super::node_text(p, source).to_string())
                        .unwrap_or_else(|| "()".to_string());
                    let result_text = child
                        .child_by_field_name("result")
                        .map(|r| format!(" {}", super::node_text(r, source).trim()))
                        .unwrap_or_default();
                    let sig_text = format!("func {}{}{}", fn_name, params_text, result_text);

                    let visibility = go_visibility(&fn_name);

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: fn_name,
                        kind: SymbolKind::Function,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(
                            start_point.row + 1,
                            start_point.column + 1,
                            end_point.row + 1,
                            end_point.column + 1,
                        ),
                        visibility,
                        loc,
                        cyclomatic_complexity: cyclomatic,
                        doc: None,
                        signature: sig_text,
                        is_pure_hint: !body_text.contains('&') && !body_text.contains("panic"),
                        ast_hash: Some(ast_hash),
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });

                    super::extract_calls_in_node(&symbol_id, child, source, "call_expression", edges);
                }
            }
            "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let m_name = super::node_text(name_node, source).to_string();
                    // Receiver `(r *Store)` -> type `Store` (last identifier).
                    let receiver = child
                        .child_by_field_name("receiver")
                        .map(|r| {
                            super::node_text(r, source)
                                .split(|c: char| !c.is_alphanumeric() && c != '_')
                                .rfind(|s| !s.is_empty())
                                .unwrap_or("Unknown")
                                .to_string()
                        })
                        .unwrap_or_else(|| "Unknown".to_string());

                    let qualified = format!("{}::{}", receiver, m_name);
                    let symbol_id = format!("{}::{}", file_str, qualified);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                    let complexity_triggers = &[
                        "if_statement",
                        "for_statement",
                        "expression_case",
                        "type_case",
                        "communication_case",
                    ];
                    let cyclomatic = 1 + super::count_complexity(child, complexity_triggers);
                    let body_text = super::node_text(child, source);
                    let ast_hash = super::hash_slice(body_text);

                    symbols.push(Symbol {
                        id: symbol_id.clone(),
                        name: qualified,
                        kind: SymbolKind::Method,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(
                            start_point.row + 1,
                            start_point.column + 1,
                            end_point.row + 1,
                            end_point.column + 1,
                        ),
                        visibility: go_visibility(&m_name),
                        loc,
                        cyclomatic_complexity: cyclomatic,
                        doc: None,
                        signature: format!(
                            "func ({}) {}{}{}",
                            receiver,
                            m_name,
                            child
                                .child_by_field_name("parameters")
                                .map(|p| super::node_text(p, source).to_string())
                                .unwrap_or_else(|| "()".to_string()),
                            child
                                .child_by_field_name("result")
                                .map(|r| format!(" {}", super::node_text(r, source).trim()))
                                .unwrap_or_default()
                        ),
                        is_pure_hint: false,
                        ast_hash: Some(ast_hash),
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });

                    super::extract_calls_in_node(&symbol_id, child, source, "call_expression", edges);
                }
            }
            "type_declaration" => {
                let mut type_cursor = child.walk();
                for t_spec in child.children(&mut type_cursor) {
                    if t_spec.kind() == "type_spec" {
                        if let Some(name_node) = t_spec.child_by_field_name("name") {
                            let type_name = super::node_text(name_node, source).to_string();
                            let symbol_id = format!("{}::{}", file_str, type_name);
                            let start_point = t_spec.start_position();
                            let end_point = t_spec.end_position();
                            let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

                            let type_node = t_spec.child_by_field_name("type");
                            let kind = match type_node.map(|t| t.kind()) {
                                Some("struct_type") => SymbolKind::Struct,
                                Some("interface_type") => SymbolKind::Interface,
                                _ => SymbolKind::TypeAlias,
                            };

                            let visibility = go_visibility(&type_name);

                            symbols.push(Symbol {
                                id: symbol_id,
                                name: type_name.clone(),
                                kind,
                                file_path: path.to_path_buf(),
                                span: SourceSpan::new(
                                    start_point.row + 1,
                                    start_point.column + 1,
                                    end_point.row + 1,
                                    end_point.column + 1,
                                ),
                                visibility,
                                loc,
                                cyclomatic_complexity: 1,
                                doc: None,
                                signature: format!("type {} {:?}", type_name, kind),
                                is_pure_hint: true,
                                ast_hash: None,
                                attributes: Vec::new(),
                                is_trait_impl: false,
                            });
                        }
                    }
                }
            }
            _ => {
                extract_go_nodes(path, file_str, source, child, symbols, edges, imports);
            }
        }
    }
}

fn go_visibility(name: &str) -> Visibility {
    if name
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

fn extract_go_imports(
    file_str: &str,
    source: &str,
    decl_node: Node,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let mut cursor = decl_node.walk();
    for child in decl_node.children(&mut cursor) {
        match child.kind() {
            "import_spec" => {
                extract_go_import_spec(file_str, source, child, edges, imports);
            }
            "import_spec_list" => {
                extract_go_imports(file_str, source, child, edges, imports);
            }
            _ => {}
        }
    }
}

fn extract_go_import_spec(
    file_str: &str,
    source: &str,
    spec_node: Node,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let Some(path_node) = spec_node.child_by_field_name("path") else {
        return;
    };
    let pkg_path = super::node_text(path_node, source)
        .trim()
        .trim_matches(|c| c == '"' || c == '`')
        .to_string();
    if pkg_path.is_empty() {
        return;
    }

    let alias = spec_node
        .child_by_field_name("name")
        .map(|n| super::node_text(n, source).trim().to_string())
        .filter(|s| !s.is_empty());

    let (local, is_glob) = match alias {
        Some(ref a) if a == "." => (".".to_string(), true),
        Some(a) => (a, false),
        None => (
            pkg_path.rsplit('/').next().unwrap_or(&pkg_path).to_string(),
            false,
        ),
    };

    edges.push(DependencyEdge {
        from_symbol: file_str.to_string(),
        to_symbol: pkg_path.clone(),
        kind: DependencyEdgeKind::Imports,
        count: 1,
    });
    imports.push(Import {
        local,
        path: pkg_path,
        is_glob,
    });
}
