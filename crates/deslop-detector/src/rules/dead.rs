use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind, Symbol, Visibility};

const ROUTE_FILENAMES: &[&str] = &[
    "page.tsx",
    "page.ts",
    "page.jsx",
    "page.js",
    "layout.tsx",
    "route.ts",
    "route.js",
    "middleware.ts",
    "middleware.js",
    "+page.ts",
    "+server.ts",
];

const PUBLIC_ENTRYPOINT_FILENAMES: &[&str] =
    &["main.rs", "lib.rs", "mod.rs", "index.ts", "index.js"];

const FRAMEWORK_DECORATORS: &[&str] = &[
    "app.route",
    "app.get",
    "app.post",
    "router.get",
    "router.post",
    "pytest.fixture",
    "click.command",
];

/// Returns `true` when `sym` is a framework-managed entrypoint (route file,
/// public crate/package root, or route/CLI decorator) that is invoked by the
/// runtime rather than through static call edges.
pub fn is_framework_entrypoint(sym: &Symbol) -> bool {
    let file_name = sym
        .file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if ROUTE_FILENAMES.contains(&file_name) {
        return true;
    }

    if sym.visibility == Visibility::Public && PUBLIC_ENTRYPOINT_FILENAMES.contains(&file_name) {
        return true;
    }

    sym.attributes.iter().any(|attr| {
        let normalized = attr.trim_start_matches('@');
        FRAMEWORK_DECORATORS.iter().any(|dec| {
            normalized == *dec
                || normalized
                    .strip_prefix(dec)
                    .is_some_and(|rest| rest.starts_with('('))
        })
    })
}

/// Detect unreachable dead code
pub struct DeadOrphanRule;

impl DetectionRule for DeadOrphanRule {
    fn rule_name(&self) -> &'static str {
        "dead-orphan"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let orphans = ctx.graph.find_unreachable_orphans();
        orphans
            .into_iter()
            .filter(|sym| {
                !sym.is_test_code()
                    && !sym.is_implicit_entrypoint()
                    && !is_framework_entrypoint(sym)
            })
            // Attributes (`#[global_allocator]`, `#[no_mangle]`, `#[inline]`...)
            // can wire an item in without any call the graph or text can see.
            .filter(|sym| sym.attributes.is_empty())
            // The graph misses method calls on values. If the name is used in
            // call position anywhere in the codebase, it is not provably dead.
            .filter(|sym| !ctx.callsites.is_some_and(|idx| idx.referenced(&sym.name)))
            .map(|sym| SlopFinding {
                kind: SlopKind::DeadOrphan,
                symbol_id: sym.id.clone(),
                file_path: sym.file_path.clone(),
                line: sym.span.start_line,
                severity: Severity::Medium,
                confidence: 0.80,
                title: format!("Unreachable Symbol: `{}`", sym.name),
                description: format!(
                    "Symbol `{}` is not reachable from any public entrypoint or root function.",
                    sym.name
                ),
                remediation: "Delete the unused symbol or verify if it is intended to be called by an upcoming feature.".to_string(),
                estimated_lines_saved: sym.loc,
                inline_target: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{SourceSpan, SymbolKind};
    use deslop_graph::SymbolGraph;
    use std::path::PathBuf;

    fn make_symbol(id: &str, name: &str, file_path: &str, visibility: Visibility) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: PathBuf::from(file_path),
            span: SourceSpan::new(1, 1, 10, 1),
            visibility,
            loc: 10,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {}", name),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    #[test]
    fn skips_nextjs_route_and_fastapi_decorator_entrypoints() {
        let next_page = make_symbol(
            "app/dashboard/page.tsx::DashboardPage",
            "DashboardPage",
            "app/dashboard/page.tsx",
            Visibility::Private,
        );
        let mut fastapi_route = make_symbol(
            "api/users.py::list_users",
            "list_users",
            "api/users.py",
            Visibility::Private,
        );
        fastapi_route.attributes = vec!["app.get".to_string()];

        let dead_helper = make_symbol(
            "src/utils.ts::unusedHelper",
            "unusedHelper",
            "src/utils.ts",
            Visibility::Private,
        );

        assert!(is_framework_entrypoint(&next_page));
        assert!(is_framework_entrypoint(&fastapi_route));
        assert!(!is_framework_entrypoint(&dead_helper));

        let symbols = vec![next_page, fastapi_route, dead_helper];
        let edges = Vec::new();
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };

        let findings = DeadOrphanRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].symbol_id, "src/utils.ts::unusedHelper");
    }
}
