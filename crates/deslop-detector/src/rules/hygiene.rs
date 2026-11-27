use crate::{DetectionContext, DetectionRule};
use deslop_core::{DependencyEdgeKind, Severity, SlopFinding, SlopKind};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const IGNORED_PLUGINS: &[&str] = &[
    "typescript",
    "vite",
    "eslint",
    "prettier",
    "tailwindcss",
    "react-dom",
];

const MANIFEST_NAMES: &[&str] = &["package.json", "Cargo.toml", "pyproject.toml"];

/// Detect declared dependencies in `package.json`, `Cargo.toml`, or
/// `pyproject.toml` that are never imported in the analyzed codebase.
pub struct UnusedDependencyRule;

impl DetectionRule for UnusedDependencyRule {
    fn rule_name(&self) -> &'static str {
        "unused-dependency"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let Some(common_root) = common_root_dir(ctx) else {
            return Vec::new();
        };

        let imported = collect_imported_packages(ctx);
        let mut findings = Vec::new();

        if let Some(pkg_json) = find_manifest(&common_root, "package.json") {
            findings.extend(check_package_json(&pkg_json, &imported));
        }
        if let Some(cargo_toml) = find_manifest(&common_root, "Cargo.toml") {
            findings.extend(check_cargo_toml(&cargo_toml, &imported));
        }
        if let Some(pyproject_toml) = find_manifest(&common_root, "pyproject.toml") {
            findings.extend(check_pyproject_toml(&pyproject_toml, &imported));
        }

        findings
    }
}

fn common_root_dir(ctx: &DetectionContext) -> Option<PathBuf> {
    let mut dirs = ctx.symbols.iter().map(|s| {
        s.file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    });

    let first = dirs.next()?;
    let mut common: Vec<_> = first.components().collect();

    for dir in dirs {
        let comps: Vec<_> = dir.components().collect();
        let shared_len = common
            .iter()
            .zip(comps.iter())
            .take_while(|(a, b)| a == b)
            .count();
        common.truncate(shared_len);
    }

    if common.is_empty() {
        Some(PathBuf::from("."))
    } else {
        Some(common.into_iter().collect())
    }
}

fn find_manifest(start_dir: &Path, filename: &str) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    for _ in 0..=2 {
        let dir = current?;
        let candidate = dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent().filter(|p| !p.as_os_str().is_empty());
    }
    // Also check current working directory if relative path exhausted its parents.
    if start_dir.is_relative() {
        let candidate = Path::new(filename);
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn normalize_import_target(raw: &str) -> String {
    let base = raw.split("::").next().unwrap_or(raw).trim();
    let pkg = if base.starts_with('@') {
        let mut parts = base.splitn(3, '/');
        match (parts.next(), parts.next()) {
            (Some(scope), Some(name)) => format!("{scope}/{name}"),
            _ => base.to_string(),
        }
    } else {
        base.split('/').next().unwrap_or(base).to_string()
    };
    canonical_pkg_name(&pkg)
}

fn canonical_pkg_name(name: &str) -> String {
    name.trim().replace('-', "_")
}

fn collect_imported_packages(ctx: &DetectionContext) -> HashSet<String> {
    ctx.edges
        .iter()
        .filter(|e| e.kind == DependencyEdgeKind::Imports)
        .map(|e| normalize_import_target(&e.to_symbol))
        .collect()
}

fn should_skip_package(name: &str) -> bool {
    name.starts_with("@types/") || IGNORED_PLUGINS.contains(&name)
}

fn find_declaration_line(content: &str, dep_name: &str) -> usize {
    content
        .lines()
        .position(|line| line.contains(dep_name))
        .map(|idx| idx + 1)
        .unwrap_or(1)
}

fn make_finding(
    manifest_path: &Path,
    manifest_name: &str,
    dep_name: &str,
    line: usize,
) -> SlopFinding {
    SlopFinding {
        kind: SlopKind::UnusedDependency,
        symbol_id: format!("{manifest_name}::{dep_name}"),
        file_path: manifest_path.to_path_buf(),
        line,
        severity: Severity::Low,
        confidence: 0.75,
        title: format!("Unused Dependency: `{dep_name}`"),
        description: format!(
            "Dependency `{dep_name}` declared in `{manifest_name}` is not imported anywhere in the analyzed codebase."
        ),
        remediation: format!(
            "Remove `{dep_name}` from `{manifest_name}` if unused, or verify it is only referenced by external tooling."
        ),
        estimated_lines_saved: 1,
        inline_target: None,
    }
}

fn check_package_json(path: &Path, imported: &HashSet<String>) -> Vec<SlopFinding> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    deps.keys()
        .filter(|dep| !should_skip_package(dep))
        .filter(|dep| !imported.contains(&canonical_pkg_name(dep)))
        .map(|dep| {
            let line = find_declaration_line(&content, dep);
            make_finding(path, MANIFEST_NAMES[0], dep, line)
        })
        .collect()
}

fn check_cargo_toml(path: &Path, imported: &HashSet<String>) -> Vec<SlopFinding> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = toml::from_str::<toml::Value>(&content) else {
        return Vec::new();
    };
    let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) else {
        return Vec::new();
    };

    deps.keys()
        .filter(|dep| !should_skip_package(dep))
        .filter(|dep| !imported.contains(&canonical_pkg_name(dep)))
        .map(|dep| {
            let line = find_declaration_line(&content, dep);
            make_finding(path, MANIFEST_NAMES[1], dep, line)
        })
        .collect()
}

fn check_pyproject_toml(path: &Path, imported: &HashSet<String>) -> Vec<SlopFinding> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = toml::from_str::<toml::Value>(&content) else {
        return Vec::new();
    };
    let Some(deps) = parsed
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    else {
        return Vec::new();
    };

    deps.iter()
        .filter_map(|v| v.as_str())
        .filter_map(|spec| {
            let name = spec
                .split(['>', '<', '=', '!', '~', ';', '[', ' '])
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())?;
            Some(name)
        })
        .filter(|dep| !should_skip_package(dep))
        .filter(|dep| !imported.contains(&canonical_pkg_name(dep)))
        .map(|dep| {
            let line = find_declaration_line(&content, dep);
            make_finding(path, MANIFEST_NAMES[2], dep, line)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{DependencyEdge, SourceSpan, Symbol, SymbolKind, Visibility};
    use deslop_graph::SymbolGraph;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("deslop_hygiene_{label}_{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_symbol(file_path: PathBuf) -> Symbol {
        Symbol {
            id: format!("{}::main", file_path.display()),
            name: "main".to_string(),
            kind: SymbolKind::Function,
            file_path,
            span: SourceSpan::new(1, 1, 5, 1),
            visibility: Visibility::Public,
            loc: 5,
            cyclomatic_complexity: 1,
            doc: None,
            signature: "fn main()".to_string(),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    fn import_edge(from: &str, to: &str) -> DependencyEdge {
        DependencyEdge {
            from_symbol: from.to_string(),
            to_symbol: to.to_string(),
            kind: DependencyEdgeKind::Imports,
            count: 1,
        }
    }

    #[test]
    fn detects_unused_package_json_and_cargo_dependencies() {
        let root = make_temp_dir("mixed");
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        fs::write(
            root.join("package.json"),
            r#"{
  "dependencies": {
    "@acme/sdk": "^1.0.0",
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "lodash": "^4.17.21",
    "unused-js-pkg": "^0.1.0"
  }
}"#,
        )
        .unwrap();

        fs::write(
            root.join("Cargo.toml"),
            r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
my-crate = "1.0"
dead-crate = "0.2"
"#,
        )
        .unwrap();

        let sym_path = src_dir.join("index.ts");
        let sym = make_symbol(sym_path.clone());
        let symbols = vec![sym];
        let edges = vec![
            import_edge(&symbols[0].id, "@acme/sdk/client"),
            import_edge(&symbols[0].id, "lodash/debounce"),
            import_edge(&symbols[0].id, "my_crate::Widget"),
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };

        let findings = UnusedDependencyRule.detect(&ctx);
        let unused_ids: Vec<&str> = findings.iter().map(|f| f.symbol_id.as_str()).collect();

        assert_eq!(findings.len(), 2);
        assert!(unused_ids.contains(&"package.json::unused-js-pkg"));
        assert!(unused_ids.contains(&"Cargo.toml::dead-crate"));
        assert!(findings
            .iter()
            .all(|f| f.kind == SlopKind::UnusedDependency));
        assert!(findings.iter().all(|f| f.severity == Severity::Low));
        assert!(findings
            .iter()
            .all(|f| (f.confidence - 0.75).abs() < f64::EPSILON));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normalizes_scoped_subpaths_and_crate_hyphens() {
        assert_eq!(normalize_import_target("@scope/pkg/sub/path"), "@scope/pkg");
        assert_eq!(normalize_import_target("pkg/sub"), "pkg");
        assert_eq!(normalize_import_target("my_crate::sub::Item"), "my_crate");
        assert_eq!(canonical_pkg_name("my-crate"), "my_crate");
    }
}
