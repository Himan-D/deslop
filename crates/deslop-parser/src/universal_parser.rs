use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Language, SourceSpan, Symbol, SymbolKind, Visibility,
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;

static TS_FN_REGEX: OnceLock<Regex> = OnceLock::new();
static TS_CLASS_REGEX: OnceLock<Regex> = OnceLock::new();
static TS_INTERFACE_REGEX: OnceLock<Regex> = OnceLock::new();
static PY_DEF_REGEX: OnceLock<Regex> = OnceLock::new();
static PY_CLASS_REGEX: OnceLock<Regex> = OnceLock::new();
static GO_FUNC_REGEX: OnceLock<Regex> = OnceLock::new();
static CALL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_ts_fn_regex() -> &'static Regex {
    TS_FN_REGEX.get_or_init(|| {
        Regex::new(r#"(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::\s*[^=]+)?\s*=>"#).unwrap()
    })
}

fn get_ts_class_regex() -> &'static Regex {
    TS_CLASS_REGEX.get_or_init(|| {
        Regex::new(r#"(?:export\s+)?class\s+([a-zA-Z0-9_$]+)(?:\s+extends\s+([a-zA-Z0-9_$]+))?(?:\s+implements\s+([a-zA-Z0-9_$,\s]+))?"#).unwrap()
    })
}

fn get_ts_interface_regex() -> &'static Regex {
    TS_INTERFACE_REGEX.get_or_init(|| {
        Regex::new(r#"(?:export\s+)?interface\s+([a-zA-Z0-9_$]+)"#).unwrap()
    })
}

fn get_py_def_regex() -> &'static Regex {
    PY_DEF_REGEX.get_or_init(|| {
        Regex::new(r#"(?m)^\s*(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\):"#).unwrap()
    })
}

fn get_py_class_regex() -> &'static Regex {
    PY_CLASS_REGEX.get_or_init(|| {
        Regex::new(r#"(?m)^\s*class\s+([a-zA-Z0-9_]+)(?:\(([^)]*)\))?:"#).unwrap()
    })
}

fn get_go_func_regex() -> &'static Regex {
    GO_FUNC_REGEX.get_or_init(|| {
        Regex::new(r#"(?m)^func\s+(?:\((?:[a-zA-Z0-9_*\s]+)\)\s+)?([a-zA-Z0-9_]+)\s*\(([^)]*)\)"#).unwrap()
    })
}

fn get_call_regex() -> &'static Regex {
    CALL_REGEX.get_or_init(|| {
        Regex::new(r#"([a-zA-Z0-9_$]+)\s*\("#).unwrap()
    })
}

fn hash_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    let normalized = s.split_whitespace().collect::<Vec<_>>().join(" ");
    hasher.update(normalized.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn parse_universal_file(
    path: &Path,
    content: &str,
    lang: Language,
) -> (Vec<Symbol>, Vec<DependencyEdge>) {
    let mut symbols = Vec::new();
    let mut edges = Vec::new();
    let file_str = path.to_string_lossy();
    let lines: Vec<&str> = content.lines().collect();

    match lang {
        Language::TypeScript | Language::JavaScript => {
            let fn_re = get_ts_fn_regex();
            let class_re = get_ts_class_regex();
            let iface_re = get_ts_interface_regex();

            for (idx, line) in lines.iter().enumerate() {
                let line_num = idx + 1;
                if let Some(caps) = fn_re.captures(line) {
                    let name = caps.get(1).or_else(|| caps.get(3)).map(|m| m.as_str().to_string()).unwrap_or_default();
                    if !name.is_empty() {
                        let id = format!("{}::{}", file_str, name);
                        let vis = if line.contains("export ") { Visibility::Public } else { Visibility::Private };
                        symbols.push(Symbol {
                            id: id.clone(),
                            name: name.clone(),
                            kind: SymbolKind::Function,
                            file_path: path.to_path_buf(),
                            span: SourceSpan::new(line_num, 1, line_num + 5, 1),
                            visibility: vis,
                            loc: 5,
                            cyclomatic_complexity: 1 + line.matches("?").count() + line.matches("&&").count(),
                            doc: None,
                            signature: line.trim().to_string(),
                            is_pure_hint: !line.contains("this.") && !line.contains("console."),
                            ast_hash: Some(hash_str(line)),
                        });
                    }
                } else if let Some(caps) = class_re.captures(line) {
                    let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let id = format!("{}::{}", file_str, name);
                    symbols.push(Symbol {
                        id: id.clone(),
                        name: name.clone(),
                        kind: SymbolKind::Class,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(line_num, 1, line_num + 10, 1),
                        visibility: if line.contains("export ") { Visibility::Public } else { Visibility::Private },
                        loc: 10,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: line.trim().to_string(),
                        is_pure_hint: false,
                        ast_hash: None,
                    });

                    if let Some(base) = caps.get(2) {
                        edges.push(DependencyEdge {
                            from_symbol: id.clone(),
                            to_symbol: base.as_str().to_string(),
                            kind: DependencyEdgeKind::Inherits,
                            count: 1,
                        });
                    }
                    if let Some(ifaces) = caps.get(3) {
                        for iface in ifaces.as_str().split(',') {
                            let trimmed = iface.trim();
                            if !trimmed.is_empty() {
                                edges.push(DependencyEdge {
                                    from_symbol: id.clone(),
                                    to_symbol: trimmed.to_string(),
                                    kind: DependencyEdgeKind::Implements,
                                    count: 1,
                                });
                            }
                        }
                    }
                } else if let Some(caps) = iface_re.captures(line) {
                    let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let id = format!("{}::{}", file_str, name);
                    symbols.push(Symbol {
                        id,
                        name,
                        kind: SymbolKind::Interface,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(line_num, 1, line_num + 5, 1),
                        visibility: if line.contains("export ") { Visibility::Public } else { Visibility::Private },
                        loc: 5,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: line.trim().to_string(),
                        is_pure_hint: true,
                        ast_hash: None,
                    });
                }
            }
        }
        Language::Python => {
            let def_re = get_py_def_regex();
            let class_re = get_py_class_regex();

            for (idx, line) in lines.iter().enumerate() {
                let line_num = idx + 1;
                if let Some(caps) = def_re.captures(line) {
                    let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let id = format!("{}::{}", file_str, name);
                    let vis = if name.starts_with('_') { Visibility::Private } else { Visibility::Public };
                    symbols.push(Symbol {
                        id,
                        name,
                        kind: SymbolKind::Function,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(line_num, 1, line_num + 5, 1),
                        visibility: vis,
                        loc: 5,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: line.trim().to_string(),
                        is_pure_hint: !line.contains("self."),
                        ast_hash: Some(hash_str(line)),
                    });
                } else if let Some(caps) = class_re.captures(line) {
                    let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let id = format!("{}::{}", file_str, name);
                    symbols.push(Symbol {
                        id: id.clone(),
                        name: name.clone(),
                        kind: SymbolKind::Class,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(line_num, 1, line_num + 10, 1),
                        visibility: Visibility::Public,
                        loc: 10,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: line.trim().to_string(),
                        is_pure_hint: false,
                        ast_hash: None,
                    });

                    if let Some(base) = caps.get(2) {
                        for b in base.as_str().split(',') {
                            let tb = b.trim();
                            if !tb.is_empty() {
                                edges.push(DependencyEdge {
                                    from_symbol: id.clone(),
                                    to_symbol: tb.to_string(),
                                    kind: DependencyEdgeKind::Inherits,
                                    count: 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        Language::Go => {
            let func_re = get_go_func_regex();
            for (idx, line) in lines.iter().enumerate() {
                let line_num = idx + 1;
                if let Some(caps) = func_re.captures(line) {
                    let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let id = format!("{}::{}", file_str, name);
                    let is_exported = name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                    symbols.push(Symbol {
                        id,
                        name,
                        kind: SymbolKind::Function,
                        file_path: path.to_path_buf(),
                        span: SourceSpan::new(line_num, 1, line_num + 5, 1),
                        visibility: if is_exported { Visibility::Public } else { Visibility::Private },
                        loc: 5,
                        cyclomatic_complexity: 1,
                        doc: None,
                        signature: line.trim().to_string(),
                        is_pure_hint: false,
                        ast_hash: Some(hash_str(line)),
                    });
                }
            }
        }
        _ => {}
    }

    // Rough cross-symbol call extraction
    let call_re = get_call_regex();
    for (idx, line) in lines.iter().enumerate() {
        for cap in call_re.captures_iter(line) {
            let callee = cap[1].to_string();
            // Don't link standard keywords
            if ["if", "for", "while", "switch", "catch", "return", "function", "match"].contains(&callee.as_str()) {
                continue;
            }
            if let Some(sym) = symbols.iter().find(|s| s.span.start_line <= idx + 1 && s.span.end_line >= idx + 1) {
                if sym.name != callee {
                    edges.push(DependencyEdge {
                        from_symbol: sym.id.clone(),
                        to_symbol: callee,
                        kind: DependencyEdgeKind::Calls,
                        count: 1,
                    });
                }
            }
        }
    }

    (symbols, edges)
}
