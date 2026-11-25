use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Import, SourceSpan, Symbol, SymbolKind, Visibility,
};
use std::path::Path;
use tree_sitter::Node;

pub(super) fn extract_python_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    current_class: Option<&str>,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "decorated_definition" => {
                let mut attributes = Vec::new();
                let mut dec_cursor = child.walk();
                for dec_child in child.children(&mut dec_cursor) {
                    if dec_child.kind() == "decorator" {
                        if let Some(name) = extract_decorator_name(dec_child, source) {
                            attributes.push(name);
                        }
                    }
                }
                if let Some(def_node) = child.child_by_field_name("definition") {
                    match def_node.kind() {
                        "function_definition" => extract_python_function(
                            path,
                            file_str,
                            source,
                            def_node,
                            current_class,
                            attributes,
                            symbols,
                            edges,
                        ),
                        "class_definition" => {
                            if let Some((class_name, body_node)) = extract_python_class(
                                path,
                                file_str,
                                source,
                                def_node,
                                attributes,
                                symbols,
                                edges,
                            ) {
                                extract_python_nodes(
                                    path,
                                    file_str,
                                    source,
                                    body_node,
                                    Some(&class_name),
                                    symbols,
                                    edges,
                                    imports,
                                );
                            }
                        }
                        _ => extract_python_nodes(
                            path,
                            file_str,
                            source,
                            def_node,
                            current_class,
                            symbols,
                            edges,
                            imports,
                        ),
                    }
                }
            }
            "function_definition" => {
                extract_python_function(
                    path,
                    file_str,
                    source,
                    child,
                    current_class,
                    Vec::new(),
                    symbols,
                    edges,
                );
            }
            "class_definition" => {
                if let Some((class_name, body_node)) = extract_python_class(
                    path,
                    file_str,
                    source,
                    child,
                    Vec::new(),
                    symbols,
                    edges,
                ) {
                    extract_python_nodes(
                        path,
                        file_str,
                        source,
                        body_node,
                        Some(&class_name),
                        symbols,
                        edges,
                        imports,
                    );
                }
            }
            "import_statement" => {
                extract_import_statement(file_str, source, child, edges, imports);
            }
            "import_from_statement" => {
                extract_import_from_statement(file_str, source, child, edges, imports);
            }
            _ => {
                extract_python_nodes(
                    path,
                    file_str,
                    source,
                    child,
                    current_class,
                    symbols,
                    edges,
                    imports,
                );
            }
        }
    }
}

fn extract_decorator_name(decorator_node: Node, source: &str) -> Option<String> {
    let mut cursor = decorator_node.walk();
    for child in decorator_node.children(&mut cursor) {
        if child.kind() == "@" || child.kind() == "comment" {
            continue;
        }
        let target = if child.kind() == "call" {
            child.child_by_field_name("function").unwrap_or(child)
        } else {
            child
        };
        let text = super::node_text(target, source).trim();
        if !text.is_empty() {
            return Some(text.to_string());
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn extract_python_function(
    path: &Path,
    file_str: &str,
    source: &str,
    fn_node: Node,
    current_class: Option<&str>,
    attributes: Vec<String>,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let Some(name_node) = fn_node.child_by_field_name("name") else {
        return;
    };
    let fn_name = super::node_text(name_node, source).to_string();
    let qualified_name = if let Some(cls) = current_class {
        format!("{}::{}", cls, fn_name)
    } else {
        fn_name.clone()
    };

    let symbol_id = format!("{}::{}", file_str, qualified_name);
    let start_point = fn_node.start_position();
    let end_point = fn_node.end_position();
    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

    let complexity_triggers = &[
        "if_statement",
        "for_statement",
        "while_statement",
        "try_statement",
        "except_clause",
        "conditional_expression",
    ];
    let cyclomatic = 1 + super::count_complexity(fn_node, complexity_triggers);

    let body_text = super::node_text(fn_node, source);
    let ast_hash = super::hash_slice(body_text);

    let sig_text = fn_node
        .child_by_field_name("parameters")
        .map(|p| format!("def {}{}", fn_name, super::node_text(p, source)))
        .unwrap_or_else(|| format!("def {}()", fn_name));

    let visibility = if fn_name.starts_with('_') && !fn_name.starts_with("__") {
        Visibility::Private
    } else {
        Visibility::Public
    };

    symbols.push(Symbol {
        id: symbol_id.clone(),
        name: qualified_name,
        kind: if current_class.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
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
        is_pure_hint: !body_text.contains("global ") && !body_text.contains("self."),
        ast_hash: Some(ast_hash),
        attributes,
        is_trait_impl: false,
    });

    super::extract_calls_in_node(&symbol_id, fn_node, source, "call", edges);
}

#[allow(clippy::too_many_arguments)]
fn extract_python_class<'tree>(
    path: &Path,
    file_str: &str,
    source: &str,
    class_node: Node<'tree>,
    attributes: Vec<String>,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) -> Option<(String, Node<'tree>)> {
    let name_node = class_node.child_by_field_name("name")?;
    let class_name = super::node_text(name_node, source).to_string();
    let symbol_id = format!("{}::{}", file_str, class_name);
    let start_point = class_node.start_position();
    let end_point = class_node.end_position();
    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

    // Superclass / base class inheritance
    if let Some(arg_list) = class_node.child_by_field_name("superclasses") {
        let mut arg_cursor = arg_list.walk();
        for base_node in arg_list.children(&mut arg_cursor) {
            let base_name = super::node_text(base_node, source).trim();
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
        id: symbol_id,
        name: class_name.clone(),
        kind: SymbolKind::Class,
        file_path: path.to_path_buf(),
        span: SourceSpan::new(
            start_point.row + 1,
            start_point.column + 1,
            end_point.row + 1,
            end_point.column + 1,
        ),
        visibility: if class_name.starts_with('_') {
            Visibility::Private
        } else {
            Visibility::Public
        },
        loc,
        cyclomatic_complexity: 1,
        doc: None,
        signature: format!("class {}:", class_name),
        is_pure_hint: false,
        ast_hash: None,
        attributes,
        is_trait_impl: false,
    });

    // Return class body so caller recurses without creating mutual recursion.
    class_node
        .child_by_field_name("body")
        .map(|body_node| (class_name, body_node))
}

fn extract_import_statement(
    file_str: &str,
    source: &str,
    stmt: Node,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let mut cursor = stmt.walk();
    for child in stmt.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                let mod_path = super::node_text(child, source).trim().to_string();
                if !mod_path.is_empty() {
                    let local = mod_path.split('.').next().unwrap_or(&mod_path).to_string();
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: mod_path.clone(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    imports.push(Import {
                        local,
                        path: mod_path,
                        is_glob: false,
                    });
                }
            }
            "aliased_import" => {
                let mod_path = child
                    .child_by_field_name("name")
                    .map(|n| super::node_text(n, source).trim().to_string())
                    .unwrap_or_default();
                let alias = child
                    .child_by_field_name("alias")
                    .map(|n| super::node_text(n, source).trim().to_string())
                    .unwrap_or_default();
                if !mod_path.is_empty() {
                    let local = if alias.is_empty() {
                        mod_path.split('.').next().unwrap_or(&mod_path).to_string()
                    } else {
                        alias
                    };
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: mod_path.clone(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    imports.push(Import {
                        local,
                        path: mod_path,
                        is_glob: false,
                    });
                }
            }
            _ => {}
        }
    }
}

fn extract_import_from_statement(
    file_str: &str,
    source: &str,
    stmt: Node,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let module_path = stmt
        .child_by_field_name("module_name")
        .map(|n| {
            super::node_text(n, source)
                .trim()
                .trim_start_matches('.')
                .to_string()
        })
        .unwrap_or_default();

    let join_path = |item: &str| -> String {
        if module_path.is_empty() {
            item.to_string()
        } else {
            format!("{}.{}", module_path, item)
        }
    };

    let mut seen_import_kw = false;
    let mut cursor = stmt.walk();
    for child in stmt.children(&mut cursor) {
        if child.kind() == "import" {
            seen_import_kw = true;
            continue;
        }
        if !seen_import_kw {
            continue;
        }
        match child.kind() {
            "wildcard_import" => {
                if !module_path.is_empty() {
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: module_path.clone(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    imports.push(Import {
                        local: "*".to_string(),
                        path: module_path.replace('.', "::"),
                        is_glob: true,
                    });
                }
            }
            "aliased_import" => {
                let item_name = child
                    .child_by_field_name("name")
                    .map(|n| super::node_text(n, source).trim().to_string())
                    .unwrap_or_default();
                let alias = child
                    .child_by_field_name("alias")
                    .map(|n| super::node_text(n, source).trim().to_string())
                    .unwrap_or_default();
                if !item_name.is_empty() {
                    let full_path = join_path(&item_name);
                    let local = if alias.is_empty() {
                        item_name
                    } else {
                        alias
                    };
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: full_path.clone(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    imports.push(Import {
                        local,
                        path: full_path.replace('.', "::"),
                        is_glob: false,
                    });
                }
            }
            "dotted_name" | "identifier" => {
                let item_name = super::node_text(child, source).trim().to_string();
                if !item_name.is_empty() {
                    let full_path = join_path(&item_name);
                    let local = item_name.split('.').next().unwrap_or(&item_name).to_string();
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: full_path.clone(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    imports.push(Import {
                        local,
                        path: full_path.replace('.', "::"),
                        is_glob: false,
                    });
                }
            }
            _ => {}
        }
    }
}
