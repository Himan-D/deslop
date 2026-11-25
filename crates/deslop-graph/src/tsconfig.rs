use deslop_core::{Import, Symbol};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Reads `tsconfig.json` in `root` if present and extracts `compilerOptions.paths`
/// prefix mappings (combined with `compilerOptions.baseUrl`), e.g.
/// `"@/*": ["src/*"]` -> `"@" -> "src"`.
pub fn load_tsconfig_aliases(root: &Path) -> HashMap<String, String> {
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
    keys.sort_by_key(|b| std::cmp::Reverse(b.len()));
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

pub(crate) fn find_tsconfig_aliases(
    symbols: &[Symbol],
    imports: &HashMap<PathBuf, Vec<Import>>,
) -> HashMap<String, String> {
    let paths: Vec<&Path> = if !imports.is_empty() {
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

fn common_dir_prefix(paths: &[&Path]) -> Option<PathBuf> {
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
        Some(PathBuf::new())
    } else {
        Some(prefix.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EdgeResolution, SymbolGraph};
    use deslop_core::{DependencyEdge, DependencyEdgeKind, SourceSpan, SymbolKind, Visibility};
    use petgraph::Direction;

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
            sym(
                &format!("{}::main", app_str),
                "main",
                &app_str,
                Visibility::Public,
            ),
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
