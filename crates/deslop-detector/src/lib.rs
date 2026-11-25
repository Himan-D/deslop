use deslop_core::{ArchitectureConfig, DependencyEdge, Severity, SlopFinding, Symbol};
use deslop_graph::SymbolGraph;

pub mod callsites;
pub use callsites::{bare_name, call_site_identifiers, CallSiteIndex};

pub mod rules;
pub use rules::*;

/// Scores are normalized per 1,000 LOC. Below this size the denominator is
/// floored, so a few findings in a tiny project cannot saturate the index.
pub const MIN_SCORED_LOC: usize = 1000;

/// Repositories with fewer LOC than this produce a low-confidence score.
pub fn score_is_reliable(total_loc: usize) -> bool {
    total_loc >= MIN_SCORED_LOC
}

/// Read-only input shared by every detection rule.
pub struct DetectionContext<'a> {
    pub symbols: &'a [Symbol],
    pub edges: &'a [DependencyEdge],
    pub graph: &'a SymbolGraph,
    pub config: Option<&'a ArchitectureConfig>,
    /// Call-site identifiers across the codebase. When absent, rules that
    /// need textual evidence (dead code) fall back to the graph alone.
    pub callsites: Option<&'a CallSiteIndex>,
}

/// One architectural anti-pattern detector. Each rule is an independent unit
/// struct so rules can be tested, mocked, or swapped individually instead of
/// going through the monolithic engine.
pub trait DetectionRule {
    fn rule_name(&self) -> &'static str;
    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding>;
}

pub struct SlopDetectorEngine;

impl SlopDetectorEngine {
    pub fn analyze(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
        graph: &SymbolGraph,
    ) -> Vec<SlopFinding> {
        Self::analyze_with_config(symbols, edges, graph, None)
    }

    pub fn analyze_with_config(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
        graph: &SymbolGraph,
        config: Option<&ArchitectureConfig>,
    ) -> Vec<SlopFinding> {
        Self::analyze_full(symbols, edges, graph, config, None)
    }

    /// Full analysis, including the textual call-site index used to suppress
    /// dead-code findings for methods the static graph cannot resolve.
    pub fn analyze_full(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
        graph: &SymbolGraph,
        config: Option<&ArchitectureConfig>,
        callsites: Option<&CallSiteIndex>,
    ) -> Vec<SlopFinding> {
        let ctx = DetectionContext {
            symbols,
            edges,
            graph,
            config,
            callsites,
        };
        let mut findings = Vec::new();
        for rule in Self::default_rules() {
            findings.extend(rule.detect(&ctx));
        }
        findings.sort_by_key(|b| std::cmp::Reverse(b.severity));
        findings
    }

    /// The built-in rule set, in deterministic evaluation order.
    pub fn default_rules() -> Vec<Box<dyn DetectionRule>> {
        vec![
            Box::new(GhostAbstractionRule),
            Box::new(TollboothWrapperRule),
            Box::new(StructuralCloneRule),
            Box::new(DeadOrphanRule),
            Box::new(CircularDependencyRule),
            Box::new(GodObjectRule),
            Box::new(ArchitectureViolationRule),
        ]
    }

    /// Calculate the overall Slop Index (0.0 = pristine, 100.0 = catastrophic slop)
    pub fn calculate_slop_index(total_loc: usize, findings: &[SlopFinding]) -> f64 {
        if total_loc == 0 {
            return 0.0;
        }

        let mut penalty = 0.0;
        for f in findings {
            let weight = match f.severity {
                Severity::Low => 1.5,
                Severity::Medium => 4.0,
                Severity::High => 8.0,
                Severity::Critical => 15.0,
            };
            penalty += weight;
        }

        // Normalize per 1,000 lines of code, with the denominator floored so
        // tiny projects are not scored as if they were dense.
        let denominator_loc = total_loc.max(MIN_SCORED_LOC) as f64;
        let normalized = (penalty / (denominator_loc / 1000.0)).clamp(0.0, 100.0);
        (normalized * 10.0).round() / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{DependencyEdgeKind, SlopKind, SourceSpan, SymbolKind, Visibility};
    use std::path::PathBuf;

    fn sym(id: &str, name: &str, kind: SymbolKind, loc: usize) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind,
            file_path: PathBuf::from("lib.rs"),
            span: SourceSpan::new(1, 1, loc, 2),
            visibility: Visibility::Private,
            loc,
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

    #[test]
    fn default_rules_covers_all_seven_detectors() {
        let rules = SlopDetectorEngine::default_rules();
        assert_eq!(rules.len(), 7);
        let mut names: Vec<&str> = rules.iter().map(|r| r.rule_name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 7);
    }

    #[test]
    fn tollbooth_rule_skips_trait_impl_methods() {
        let mut trait_wrapper = sym(
            "lib.rs::Cache::default",
            "Cache::default",
            SymbolKind::Method,
            3,
        );
        trait_wrapper.is_trait_impl = true;
        let plain_wrapper = sym("lib.rs::scan", "scan", SymbolKind::Function, 3);
        let target = sym(
            "lib.rs::scan_cached",
            "scan_cached",
            SymbolKind::Function,
            30,
        );
        let symbols = vec![trait_wrapper, plain_wrapper, target];
        let edges = vec![
            edge("lib.rs::Cache::default", "new"),
            edge("lib.rs::scan", "scan_cached"),
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        let findings = TollboothWrapperRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].symbol_id, "lib.rs::scan");
    }

    #[test]
    fn god_object_rule_skips_small_behaviorless_data() {
        let mut symbols = vec![sym("lib.rs::Symbol", "Symbol", SymbolKind::Struct, 26)];
        let mut edges = Vec::new();
        for i in 0..16 {
            symbols.push(sym(
                &format!("lib.rs::user{}", i),
                &format!("user{}", i),
                SymbolKind::Function,
                10,
            ));
            edges.push(edge(&format!("lib.rs::user{}", i), "Symbol"));
        }
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        // 16 incoming edges but no behavior: shared data, not a god object.
        assert!(GodObjectRule.detect(&ctx).is_empty());

        // Same coupling plus real behavior: flag it.
        let mut with_behavior = symbols.clone();
        for i in 0..3 {
            with_behavior.push(sym(
                &format!("lib.rs::Symbol::m{}", i),
                &format!("Symbol::m{}", i),
                SymbolKind::Method,
                10,
            ));
        }
        let graph = SymbolGraph::from_parsed(&with_behavior, &edges);
        let ctx = DetectionContext {
            symbols: &with_behavior,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        assert_eq!(GodObjectRule.detect(&ctx).len(), 1);
    }

    fn edge_of(kind: DependencyEdgeKind, from: &str, to: &str) -> DependencyEdge {
        DependencyEdge {
            from_symbol: from.to_string(),
            to_symbol: to.to_string(),
            kind,
            count: 1,
        }
    }

    fn run_tollbooth(symbols: &[Symbol], edges: &[DependencyEdge]) -> Vec<SlopFinding> {
        let graph = SymbolGraph::from_parsed(symbols, edges);
        let ctx = DetectionContext {
            symbols,
            edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        TollboothWrapperRule.detect(&ctx)
    }

    #[test]
    fn tollbooth_skips_constructors_public_api_and_test_code() {
        let mut public_facade = sym("lib.rs::api", "api", SymbolKind::Function, 3);
        public_facade.visibility = Visibility::Public;
        let constructor = sym("lib.rs::Thing::new", "Thing::new", SymbolKind::Method, 3);
        let mut test_wrapper = sym("lib.rs::helper", "helper", SymbolKind::Function, 3);
        test_wrapper.attributes = vec!["test".to_string()];
        let target = sym("lib.rs::target", "target", SymbolKind::Function, 40);
        let symbols = vec![public_facade, constructor, test_wrapper, target];
        let edges = vec![
            edge_of(DependencyEdgeKind::Calls, "lib.rs::api", "target"),
            edge_of(DependencyEdgeKind::Calls, "lib.rs::Thing::new", "target"),
            edge_of(DependencyEdgeKind::Calls, "lib.rs::helper", "target"),
        ];
        assert!(run_tollbooth(&symbols, &edges).is_empty());
    }

    #[test]
    fn dead_orphan_is_suppressed_when_name_is_referenced() {
        let mut private_fn = sym("lib.rs::is_fixed", "is_fixed", SymbolKind::Method, 4);
        private_fn.visibility = Visibility::Private;
        let symbols = vec![private_fn];
        let edges: Vec<DependencyEdge> = Vec::new();
        let graph = SymbolGraph::from_parsed(&symbols, &edges);

        // Without the textual index the graph alone calls it dead.
        let bare_ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        assert_eq!(DeadOrphanRule.detect(&bare_ctx).len(), 1);

        // A method call on a value elsewhere in the codebase rescues it.
        let index = CallSiteIndex::build(vec![(
            std::path::Path::new("main.rs"),
            "if config.is_fixed(patterns) { }",
        )]);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: Some(&index),
        };
        assert!(DeadOrphanRule.detect(&ctx).is_empty());
    }

    #[test]
    fn structural_clone_ignores_trait_impls_and_is_medium() {
        let mut a = sym("lib.rs::A::visit", "A::visit", SymbolKind::Method, 6);
        let mut b = sym("lib.rs::B::visit", "B::visit", SymbolKind::Method, 6);
        a.ast_hash = Some("same".into());
        b.ast_hash = Some("same".into());
        a.is_trait_impl = true;
        b.is_trait_impl = true;
        let symbols = vec![a, b];
        let edges: Vec<DependencyEdge> = Vec::new();
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        assert!(StructuralCloneRule.detect(&ctx).is_empty());

        // Non-trait duplicates are still reported, at Medium severity.
        let mut symbols = symbols;
        for s in &mut symbols {
            s.is_trait_impl = false;
        }
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        let findings = StructuralCloneRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn cycle_is_its_own_kind_and_scales_with_files_spanned() {
        let mut a = sym("a.rs::ping", "ping", SymbolKind::Function, 3);
        let mut b = sym("b.rs::pong", "pong", SymbolKind::Function, 3);
        a.file_path = PathBuf::from("a.rs");
        b.file_path = PathBuf::from("b.rs");
        let symbols = vec![a, b];
        let edges = vec![
            edge_of(DependencyEdgeKind::Calls, "a.rs::ping", "pong"),
            edge_of(DependencyEdgeKind::Calls, "b.rs::pong", "ping"),
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        let findings = CircularDependencyRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SlopKind::Cycle);
        assert_eq!(findings[0].severity, Severity::High, "two files, unambiguous names");
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn cycle_through_ambiguous_names_is_downgraded() {
        // Two different `new` symbols: the graph may merge them into a loop.
        let mut a = sym("a.rs::Config::new", "Config::new", SymbolKind::Method, 3);
        let mut b = sym("b.rs::Builder::new", "Builder::new", SymbolKind::Method, 3);
        let other = sym("c.rs::new", "new", SymbolKind::Function, 3);
        a.file_path = PathBuf::from("a.rs");
        b.file_path = PathBuf::from("b.rs");
        let symbols = vec![a, b, other];
        let edges = vec![
            edge_of(DependencyEdgeKind::Calls, "a.rs::Config::new", "new"),
            edge_of(DependencyEdgeKind::Calls, "b.rs::Builder::new", "Config::new"),
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        for f in CircularDependencyRule.detect(&ctx) {
            assert_eq!(f.severity, Severity::Low);
            assert!(f.confidence < 0.95);
        }
    }

    #[test]
    fn qualified_cycle_with_colliding_bare_names_stays_high() {
        let mut a = sym("a.rs::Config::new", "Config::new", SymbolKind::Method, 3);
        let mut b = sym("b.rs::Builder::new", "Builder::new", SymbolKind::Method, 3);
        let other = sym("c.rs::new", "new", SymbolKind::Function, 3);
        a.file_path = PathBuf::from("a.rs");
        b.file_path = PathBuf::from("b.rs");
        let symbols = vec![a, b, other];
        let edges = vec![
            edge_of(DependencyEdgeKind::Calls, "a.rs::Config::new", "Builder::new"),
            edge_of(DependencyEdgeKind::Calls, "b.rs::Builder::new", "Config::new"),
        ];
        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: None,
            callsites: None,
        };
        let findings = CircularDependencyRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn score_denominator_is_floored_for_small_projects() {
        let finding = SlopFinding {
            kind: SlopKind::Cycle,
            symbol_id: "x".into(),
            file_path: PathBuf::from("x.rs"),
            line: 1,
            severity: Severity::Critical,
            confidence: 1.0,
            title: String::new(),
            description: String::new(),
            remediation: String::new(),
            estimated_lines_saved: 0,
        };
        // One Critical in 51 LOC used to saturate at 100; now it is bounded.
        let small = SlopDetectorEngine::calculate_slop_index(51, std::slice::from_ref(&finding));
        assert!(small < 100.0 && small > 0.0, "got {small}");
        assert!(!score_is_reliable(51));
        assert!(score_is_reliable(MIN_SCORED_LOC));
        assert_eq!(SlopDetectorEngine::calculate_slop_index(0, &[finding]), 0.0);
    }

    #[test]
    fn glob_based_layers_and_forbidden_rules_detect_violations() {
        use deslop_core::ForbiddenRule;

        assert!(matches_pattern("src/domain/user.rs", "src/domain/**"));
        assert!(matches_pattern(
            "src\\domain\\nested\\user.rs",
            "src/domain/**"
        ));
        assert!(matches_pattern("apps/web", "apps/*"));
        assert!(!matches_pattern("apps/web/index.ts", "apps/*"));
        assert!(matches_pattern("src/controller/auth.rs", "controller"));

        let mut domain_sym = sym(
            "src/domain/order.rs::Order::create",
            "Order::create",
            SymbolKind::Method,
            10,
        );
        domain_sym.file_path = PathBuf::from("src/domain/order.rs");

        let mut infra_sym = sym(
            "src/infra/db/pg.rs::PgPool::insert",
            "PgPool::insert",
            SymbolKind::Method,
            10,
        );
        infra_sym.file_path = PathBuf::from("src/infra/db/pg.rs");

        let mut app_sym = sym(
            "apps/api/handler.rs::handle",
            "handle",
            SymbolKind::Function,
            10,
        );
        app_sym.file_path = PathBuf::from("apps/api/handler.rs");

        let symbols = vec![domain_sym, infra_sym, app_sym];
        let edges = vec![
            edge(
                "src/domain/order.rs::Order::create",
                "src/infra/db/pg.rs::PgPool::insert",
            ),
            edge(
                "apps/api/handler.rs::handle",
                "src/domain/order.rs::Order::create",
            ),
        ];

        let config = ArchitectureConfig {
            layers: vec!["apps/*/**".into(), "src/domain/**".into()],
            forbidden_rules: vec![ForbiddenRule {
                from: "src/domain/**".into(),
                to: "src/infra/**".into(),
                description: None,
            }],
            allow_exceptions: Vec::new(),
        };

        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: Some(&config),
            callsites: None,
        };

        let findings = ArchitectureViolationRule.detect(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SlopKind::LayerViolation);
        assert_eq!(findings[0].symbol_id, "src/domain/order.rs::Order::create");
    }

    #[test]
    fn allow_exceptions_suppresses_matching_violation_only() {
        use deslop_core::{AllowException, ForbiddenRule};

        let mut exempted_domain = sym(
            "src/domain/legacy.rs::migrate",
            "migrate",
            SymbolKind::Function,
            10,
        );
        exempted_domain.file_path = PathBuf::from("src/domain/legacy.rs");

        let mut other_domain = sym(
            "src/domain/order.rs::save",
            "save",
            SymbolKind::Function,
            10,
        );
        other_domain.file_path = PathBuf::from("src/domain/order.rs");

        let mut infra_sym = sym(
            "src/infra/sql.rs::exec",
            "exec",
            SymbolKind::Function,
            10,
        );
        infra_sym.file_path = PathBuf::from("src/infra/sql.rs");

        let symbols = vec![exempted_domain, other_domain, infra_sym];
        let edges = vec![
            edge("src/domain/legacy.rs::migrate", "src/infra/sql.rs::exec"),
            edge("src/domain/order.rs::save", "src/infra/sql.rs::exec"),
        ];

        let config = ArchitectureConfig {
            layers: vec!["src/infra/**".into(), "src/domain/**".into()],
            forbidden_rules: vec![ForbiddenRule {
                from: "src/domain/**".into(),
                to: "src/infra/**".into(),
                description: None,
            }],
            allow_exceptions: vec![AllowException {
                from: "src/domain/legacy.rs".into(),
                to: "src/infra/**".into(),
                reason: "Legacy migration bridge".into(),
            }],
        };

        let graph = SymbolGraph::from_parsed(&symbols, &edges);
        let ctx = DetectionContext {
            symbols: &symbols,
            edges: &edges,
            graph: &graph,
            config: Some(&config),
            callsites: None,
        };

        let findings = ArchitectureViolationRule.detect(&ctx);
        // Only `src/domain/order.rs::save` should be flagged (both forbidden rule + layer inversion),
        // while `src/domain/legacy.rs::migrate` is completely suppressed.
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|f| f.symbol_id == "src/domain/order.rs::save"));
    }
}
