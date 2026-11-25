use super::{count_complexity, extract_calls_in_node, hash_slice, node_text};
use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Import, SourceSpan, Symbol, SymbolKind, Visibility,
};
use std::path::Path;
use tree_sitter::Node;

pub(super) fn extract_ts_js_nodes(
    path: &Path,
    file_str: &str,
    source: &str,
    node: Node,
    current_class: Option<&str>,
    is_exported: bool,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
    imports: &mut Vec<Import>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "export_statement" => {
                // Re-exports like `export { a, b as c } from './x'` or `export * from './x'`
                if let Some(src_node) = child.child_by_field_name("source") {
                    if let Some(module_target) = strip_quotes(node_text(src_node, source)) {
                        edges.push(DependencyEdge {
                            from_symbol: file_str.to_string(),
                            to_symbol: module_target.to_string(),
                            kind: DependencyEdgeKind::Imports,
                            count: 1,
                        });
                        extract_ts_reexports(child, source, module_target, imports);
                    }
                }
                extract_ts_js_nodes(
                    path,
                    file_str,
                    source,
                    child,
                    current_class,
                    true,
                    symbols,
                    edges,
                    imports,
                );
            }
            "lexical_declaration" | "variable_declaration" => {
                let mut decl_cursor = child.walk();
                for decl in child.children(&mut decl_cursor) {
                    if decl.kind() == "variable_declarator" {
                        if let (Some(name_node), Some(value_node)) = (
                            decl.child_by_field_name("name"),
                            decl.child_by_field_name("value"),
                        ) {
                            let val_kind = value_node.kind();
                            if matches!(
                                val_kind,
                                "arrow_function" | "function_expression" | "function"
                            ) && name_node.kind() == "identifier"
                            {
                                let fn_name = node_text(name_node, source).to_string();
                                let qualified = if let Some(cls) = current_class {
                                    format!("{}::{}", cls, fn_name)
                                } else {
                                    fn_name.clone()
                                };
                                let visibility = if is_exported {
                                    Visibility::Public
                                } else {
                                    Visibility::Private
                                };
                                register_ts_fn(
                                    path,
                                    file_str,
                                    source,
                                    value_node,
                                    qualified,
                                    fn_name,
                                    false,
                                    visibility,
                                    symbols,
                                    edges,
                                );
                            }
                        }
                    }
                }
            }
            "function_declaration" | "generator_function_declaration" => {
                let fn_name = child
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source).to_string())
                    .or_else(|| is_exported.then(|| "default".to_string()));
                if let Some(fn_name) = fn_name {
                    let qualified = if let Some(cls) = current_class {
                        format!("{}::{}", cls, fn_name)
                    } else {
                        fn_name.clone()
                    };
                    let visibility = if is_exported || current_class.is_some() {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };
                    register_ts_fn(
                        path,
                        file_str,
                        source,
                        child,
                        qualified,
                        fn_name,
                        current_class.is_some(),
                        visibility,
                        symbols,
                        edges,
                    );
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
                    register_ts_fn(
                        path,
                        file_str,
                        source,
                        child,
                        qualified,
                        fn_name,
                        true,
                        Visibility::Public,
                        symbols,
                        edges,
                    );
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
                                if token != "extends"
                                    && token != "implements"
                                    && token.chars().all(|c| c.is_alphanumeric() || c == '_')
                                {
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

                    let visibility = if is_exported {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

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
                        visibility,
                        loc,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: format!("class {}", class_name),
                        is_pure_hint: false,
                        ast_hash: None,
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });

                    if let Some(body_node) = child.child_by_field_name("body") {
                        extract_ts_js_nodes(
                            path,
                            file_str,
                            source,
                            body_node,
                            Some(&class_name),
                            false,
                            symbols,
                            edges,
                            imports,
                        );
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
                    let visibility = if is_exported {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    symbols.push(Symbol {
                        id: symbol_id,
                        name: iface_name.clone(),
                        kind: SymbolKind::Interface,
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
                        signature: format!("interface {}", iface_name),
                        is_pure_hint: true,
                        ast_hash: None,
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });
                }
            }
            "type_alias_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let type_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, type_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;
                    let visibility = if is_exported {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    symbols.push(Symbol {
                        id: symbol_id,
                        name: type_name.clone(),
                        kind: SymbolKind::TypeAlias,
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
                        signature: format!("type {}", type_name),
                        is_pure_hint: true,
                        ast_hash: None,
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });
                }
            }
            "enum_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let enum_name = node_text(name_node, source).to_string();
                    let symbol_id = format!("{}::{}", file_str, enum_name);
                    let start_point = child.start_position();
                    let end_point = child.end_position();
                    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;
                    let visibility = if is_exported {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };

                    symbols.push(Symbol {
                        id: symbol_id,
                        name: enum_name.clone(),
                        kind: SymbolKind::Enum,
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
                        signature: format!("enum {}", enum_name),
                        is_pure_hint: true,
                        ast_hash: None,
                        attributes: Vec::new(),
                        is_trait_impl: false,
                    });
                }
            }
            "import_statement" => {
                let stmt_text = node_text(child, source);
                let module_target = child
                    .child_by_field_name("source")
                    .and_then(|n| strip_quotes(node_text(n, source)))
                    .or_else(|| {
                        let quote_start = stmt_text.find(['\'', '"'])?;
                        let sub = &stmt_text[quote_start + 1..];
                        let quote_end = sub.find(['\'', '"'])?;
                        Some(&sub[..quote_end])
                    });

                if let Some(module_target) = module_target {
                    edges.push(DependencyEdge {
                        from_symbol: file_str.to_string(),
                        to_symbol: module_target.to_string(),
                        kind: DependencyEdgeKind::Imports,
                        count: 1,
                    });
                    extract_ts_imports(child, source, module_target, imports);
                }
            }
            _ => {
                extract_ts_js_nodes(
                    path,
                    file_str,
                    source,
                    child,
                    current_class,
                    is_exported,
                    symbols,
                    edges,
                    imports,
                );
            }
        }
    }
}

fn strip_quotes(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        Some(&trimmed[1..trimmed.len() - 1])
    } else {
        None
    }
}

fn extract_ts_reexports(
    export_node: Node,
    source: &str,
    module_target: &str,
    imports: &mut Vec<Import>,
) {
    let mut cursor = export_node.walk();
    for child in export_node.children(&mut cursor) {
        match child.kind() {
            "*" => {
                imports.push(Import {
                    local: "*".to_string(),
                    path: module_target.to_string(),
                    is_glob: true,
                });
            }
            "namespace_export" => {
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "identifier" {
                        let local = node_text(ns_child, source).trim().to_string();
                        if !local.is_empty() {
                            imports.push(Import {
                                local,
                                path: module_target.to_string(),
                                is_glob: true,
                            });
                        }
                    }
                }
            }
            "export_clause" => {
                let mut clause_cursor = child.walk();
                for spec in child.children(&mut clause_cursor) {
                    if spec.kind() == "export_specifier" {
                        let name_node = spec.child_by_field_name("name");
                        let alias_node = spec.child_by_field_name("alias");
                        if let Some(name_n) = name_node {
                            let orig = node_text(name_n, source).trim();
                            let local = alias_node
                                .map(|a| node_text(a, source).trim())
                                .unwrap_or(orig);
                            if !local.is_empty() {
                                imports.push(Import {
                                    local: local.to_string(),
                                    path: format!("{}::{}", module_target, orig),
                                    is_glob: false,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_ts_imports(
    import_node: Node,
    source: &str,
    module_target: &str,
    imports: &mut Vec<Import>,
) {
    let mut cursor = import_node.walk();
    for child in import_node.children(&mut cursor) {
        if child.kind() == "import_clause" {
            collect_import_clause(child, source, module_target, imports);
        }
    }
}

fn collect_import_clause(
    node: Node,
    source: &str,
    module_target: &str,
    imports: &mut Vec<Import>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // Default import: `import React from 'react'`
            "identifier" => {
                let local = node_text(child, source).trim().to_string();
                if !local.is_empty() {
                    imports.push(Import {
                        local,
                        path: module_target.to_string(),
                        is_glob: false,
                    });
                }
            }
            // Namespace import: `import * as utils from './utils'`
            "namespace_import" => {
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "identifier" {
                        let local = node_text(ns_child, source).trim().to_string();
                        if !local.is_empty() {
                            imports.push(Import {
                                local,
                                path: module_target.to_string(),
                                is_glob: true,
                            });
                        }
                    }
                }
            }
            // Named imports: `import { format as fmt, parse } from './date'`
            "named_imports" => {
                let mut named_cursor = child.walk();
                for spec in child.children(&mut named_cursor) {
                    if spec.kind() == "import_specifier" {
                        let name_node = spec.child_by_field_name("name");
                        let alias_node = spec.child_by_field_name("alias");
                        if let Some(name_n) = name_node {
                            let orig = node_text(name_n, source).trim();
                            let local = alias_node
                                .map(|a| node_text(a, source).trim())
                                .unwrap_or(orig);
                            if !local.is_empty() {
                                imports.push(Import {
                                    local: local.to_string(),
                                    path: format!("{}::{}", module_target, orig),
                                    is_glob: false,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
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
    visibility: Visibility,
    symbols: &mut Vec<Symbol>,
    edges: &mut Vec<DependencyEdge>,
) {
    let symbol_id = format!("{}::{}", file_str, qualified_name);
    let start_point = node.start_position();
    let end_point = node.end_position();
    let loc = (end_point.row.saturating_sub(start_point.row)) + 1;

    let complexity_triggers = &[
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
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
        kind: if is_method {
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
        is_pure_hint: !body_text.contains("this.") && !body_text.contains("console."),
        ast_hash: Some(ast_hash),
        attributes: Vec::new(),
        is_trait_impl: false,
    });

    extract_calls_in_node(&symbol_id, node, source, "call_expression", edges);
}
