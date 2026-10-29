use deslop_core::{
    ArchitectureConfig, DependencyEdge, DependencyEdgeKind, Severity, SlopFinding, SlopKind,
    Symbol, SymbolKind, Visibility,
};
use deslop_graph::SymbolGraph;
use std::collections::HashMap;

pub mod callsites;
pub use callsites::{bare_name, call_site_identifiers, CallSiteIndex};

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

/// Evaluates ArchUnit-style declarative architectural rules and forbidden dependencies
pub struct ArchitectureViolationRule;

impl DetectionRule for ArchitectureViolationRule {
    fn rule_name(&self) -> &'static str {
        "architecture-violation"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let Some(config) = ctx.config else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        let sym_files: HashMap<&str, (&std::path::Path, usize)> = ctx
            .symbols
            .iter()
            .map(|s| (s.id.as_str(), (s.file_path.as_path(), s.span.start_line)))
            .collect();

        for edge in ctx.edges {
            let from_path = sym_files
                .get(edge.from_symbol.as_str())
                .map(|(p, _)| p.to_string_lossy())
                .unwrap_or_default();
            let to_path = sym_files
                .get(edge.to_symbol.as_str())
                .map(|(p, _)| p.to_string_lossy())
                .unwrap_or_default();
            let (file_path, line) = sym_files
                .get(edge.from_symbol.as_str())
                .map(|(p, l)| (p.to_path_buf(), *l))
                .unwrap_or_default();

            // Check forbidden rules
            for rule in &config.forbidden_rules {
                if from_path.contains(&rule.from) && to_path.contains(&rule.to) {
                    let desc = rule.description.clone().unwrap_or_else(|| {
                        format!("Dependency from '{}' to '{}' is explicitly forbidden by architecture policy.", rule.from, rule.to)
                    });
                    findings.push(SlopFinding {
                        kind: SlopKind::LayerViolation,
                        symbol_id: edge.from_symbol.clone(),
                        file_path: file_path.clone(),
                        line,
                        severity: Severity::Critical,
                        confidence: 1.0,
                        title: format!("Architectural Rule Violation: {} -> {}", rule.from, rule.to),
                        description: desc,
                        remediation: "Invert dependency or extract a common interface into a lower domain layer.".to_string(),
                        estimated_lines_saved: 0,
                    });
                }
            }

            // Check strict monotonic layer ordering
            if !config.layers.is_empty() {
                let from_layer_idx = config.layers.iter().position(|l| from_path.contains(l));
                let to_layer_idx = config.layers.iter().position(|l| to_path.contains(l));

                if let (Some(f_idx), Some(t_idx)) = (from_layer_idx, to_layer_idx) {
                    if f_idx > t_idx {
                        findings.push(SlopFinding {
                            kind: SlopKind::LayerViolation,
                            symbol_id: edge.from_symbol.clone(),
                            file_path: file_path.clone(),
                            line,
                            severity: Severity::Critical,
                            confidence: 1.0,
                            title: format!("Layer Inversion: Layer '{}' imports upper Layer '{}'", config.layers[f_idx], config.layers[t_idx]),
                            description: format!("Module '{}' in layer '{}' illegally depends on '{}' in higher layer '{}'. Strict monotonic DAG violated.", from_path, config.layers[f_idx], to_path, config.layers[t_idx]),
                            remediation: "Apply Dependency Inversion Principle (DIP): higher layers should depend on abstractions in lower layers.".to_string(),
                            estimated_lines_saved: 0,
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Detect interfaces/traits with exactly 1 implementation
pub struct GhostAbstractionRule;

impl DetectionRule for GhostAbstractionRule {
    fn rule_name(&self) -> &'static str {
        "ghost-abstraction"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut impl_counts: HashMap<&str, usize> = HashMap::new();

        for edge in ctx.edges {
            if edge.kind == DependencyEdgeKind::Implements {
                *impl_counts.entry(&edge.to_symbol).or_insert(0) += 1;
            }
        }

        for sym in ctx.symbols {
            // Test fixtures are intentionally minimal: a one-implementor trait
            // there is a test seam, not architectural debt.
            if sym.is_test_entrypoint() {
                continue;
            }
            if (sym.kind == SymbolKind::Interface || sym.kind == SymbolKind::Trait)
                && sym.visibility != Visibility::Public
            {
                let count = impl_counts.get(sym.name.as_str()).copied().unwrap_or(0);
                if count == 1 {
                    findings.push(SlopFinding {
                        kind: SlopKind::GhostAbstraction,
                        symbol_id: sym.id.clone(),
                        file_path: sym.file_path.clone(),
                        line: sym.span.start_line,
                        severity: Severity::Medium,
                        confidence: 0.90,
                        title: format!("Ghost Abstraction: `{}`", sym.name),
                        description: format!(
                            "Trait/Interface `{}` has exactly 1 implementor. It creates cognitive overhead and indirection without providing polymorphism.",
                            sym.name
                        ),
                        remediation: format!(
                            "Merge `{}` directly into the implementing struct/class and remove the interface seam.",
                            sym.name
                        ),
                        estimated_lines_saved: sym.loc + 10,
                    });
                }
            }
        }

        findings
    }
}

/// Detect wrapper functions that do nothing except forward calls
pub struct TollboothWrapperRule;

impl DetectionRule for TollboothWrapperRule {
    fn rule_name(&self) -> &'static str {
        "tollbooth-wrapper"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut outgoing_calls: HashMap<&str, Vec<&str>> = HashMap::new();

        for edge in ctx.edges {
            if edge.kind == DependencyEdgeKind::Calls {
                outgoing_calls
                    .entry(&edge.from_symbol)
                    .or_default()
                    .push(&edge.to_symbol);
            }
        }

        for sym in ctx.symbols {
            if sym.name == "main" || sym.name.ends_with("::main") || sym.name.starts_with("test_") {
                continue;
            }
            // Trait-impl methods fulfill a contract (e.g. `Default::default`
            // delegating to `new`); they cannot be inlined away.
            if sym.is_trait_impl {
                continue;
            }
            // Tests are roots, never wrappers: a test that exercises one
            // function is doing its job, not adding indirection. Test
            // scaffolding is likewise not production indirection.
            if sym.is_test_code() {
                continue;
            }
            // Public functions are API surface: a thin forwarder there is a
            // deliberate facade (and inlining it would change the API).
            if sym.visibility == Visibility::Public {
                continue;
            }
            // Constructors and conversions are thin by convention.
            if is_constructor_like(&sym.name) {
                continue;
            }

            if (sym.kind == SymbolKind::Function || sym.kind == SymbolKind::Method)
                // A pass-through has one statement: signature, body line, closing brace.
                && sym.loc <= 3
                && sym.cyclomatic_complexity <= 2
            {
                if let Some(calls) = outgoing_calls.get(sym.id.as_str()) {
                    if calls.len() == 1 {
                        let target = calls[0];
                        findings.push(SlopFinding {
                            kind: SlopKind::TollboothWrapper,
                            symbol_id: sym.id.clone(),
                            file_path: sym.file_path.clone(),
                            line: sym.span.start_line,
                            severity: Severity::Low,
                            confidence: 0.85,
                            title: format!("Tollbooth Wrapper: `{}`", sym.name),
                            description: format!(
                                "Function `{}` is a thin pass-through forwarding calls directly to `{}` with negligible logic.",
                                sym.name, target
                            ),
                            remediation: format!(
                                "Call `{}` directly at call sites or inline `{}`.",
                                target, sym.name
                            ),
                            estimated_lines_saved: sym.loc,
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Detect duplicated AST structures across functions
pub struct StructuralCloneRule;

impl DetectionRule for StructuralCloneRule {
    fn rule_name(&self) -> &'static str {
        "structural-clone"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut hash_map: HashMap<&str, Vec<&Symbol>> = HashMap::new();

        for sym in ctx.symbols {
            // Test scaffolding favors independence over DRY; duplicated test
            // helpers are not production clones.
            if sym.is_test_code() {
                continue;
            }
            // Trait impls (serde visitors, Display, From...) repeat the same
            // shape by contract; that repetition is not duplicated logic.
            if sym.is_trait_impl {
                continue;
            }
            if let Some(h) = &sym.ast_hash {
                if sym.loc >= 5 {
                    hash_map.entry(h.as_str()).or_default().push(sym);
                }
            }
        }

        for (_hash, group) in hash_map {
            if group.len() > 1 {
                let primary = group[0];
                for duplicate in &group[1..] {
                    findings.push(SlopFinding {
                        kind: SlopKind::StructuralClone,
                        symbol_id: duplicate.id.clone(),
                        file_path: duplicate.file_path.clone(),
                        line: duplicate.span.start_line,
                        // Clones are real but low-value compared with cycles
                        // and dead code; they inform rather than gate.
                        severity: Severity::Medium,
                        confidence: 0.95,
                        title: format!(
                            "Structural Clone: `{}` matches `{}`",
                            duplicate.name, primary.name
                        ),
                        description: format!(
                            "`{}` shares identical AST logic with `{}` in {}:{}",
                            duplicate.name,
                            primary.name,
                            primary.file_path.display(),
                            primary.span.start_line
                        ),
                        remediation:
                            "Parameterize the shared logic into a single reusable helper function."
                                .to_string(),
                        estimated_lines_saved: duplicate.loc,
                    });
                }
            }
        }

        findings
    }
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
            .filter(|sym| !sym.is_test_code() && !sym.is_implicit_entrypoint())
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
            })
            .collect()
    }
}

/// Constructors and conversions are thin by convention, not by accident.
fn is_constructor_like(name: &str) -> bool {
    let bare = bare_name(name);
    matches!(bare, "new" | "default" | "from" | "build" | "create" | "open" | "init" | "with")
        || bare.starts_with("with_")
        || bare.starts_with("from_")
        || bare.starts_with("new_")
}

/// Detect circular dependency cycles
pub struct CircularDependencyRule;

impl DetectionRule for CircularDependencyRule {
    fn rule_name(&self) -> &'static str {
        "circular-dependency"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let cycles = ctx.graph.find_circular_dependencies();
        let sym_map: HashMap<&str, &Symbol> =
            ctx.symbols.iter().map(|s| (s.name.as_str(), s)).collect();
        // The graph resolves calls by bare name, so `new` or `default` can
        // stitch unrelated types into a fake loop. Count how many symbols
        // share each bare name; cycles through shared names are downgraded.
        let mut bare_counts: HashMap<&str, usize> = HashMap::new();
        for s in ctx.symbols {
            *bare_counts.entry(bare_name(&s.name)).or_insert(0) += 1;
        }
        let mut findings = Vec::new();

        for cycle in cycles {
            let cycle_repr = cycle.join(" -> ");
            if let Some(first_sym_name) = cycle.first() {
                if let Some(first_sym) = sym_map.get(first_sym_name.as_str()) {
                    // Test fixtures may wire types into deliberate loops.
                    if first_sym.is_test_entrypoint() {
                        continue;
                    }
                    // Severity follows how far the loop reaches: a loop inside
                    // one file is cheap to fix, a loop across three or more
                    // files is a layering problem.
                    let files: std::collections::HashSet<&std::path::Path> = cycle
                        .iter()
                        .filter_map(|n| sym_map.get(n.as_str()))
                        .map(|s| s.file_path.as_path())
                        .collect();
                    let ambiguous = cycle
                        .iter()
                        .any(|n| bare_counts.get(bare_name(n)).copied().unwrap_or(0) > 1);
                    let severity = match (ambiguous, files.len()) {
                        (true, _) => Severity::Low,
                        (false, 0 | 1) => Severity::Medium,
                        (false, 2) => Severity::High,
                        (false, _) => Severity::Critical,
                    };
                    let confidence = if ambiguous { 0.5 } else { 0.95 };
                    findings.push(SlopFinding {
                        kind: SlopKind::Cycle,
                        symbol_id: first_sym.id.clone(),
                        file_path: first_sym.file_path.clone(),
                        line: first_sym.span.start_line,
                        severity,
                        confidence,
                        title: format!("Circular Dependency Loop: {}", cycle_repr),
                        description: format!(
                            "A circular dependency loop spans {} file(s): {} -> {}. This tight coupling leads to initialization order bugs and prevents modular compilation.",
                            files.len(), cycle_repr, first_sym_name
                        ),
                        remediation: if ambiguous {
                            "Verify the loop first: it passes through names shared by several symbols, so the static graph may have merged unrelated calls.".to_string()
                        } else {
                            "Break the cycle by extracting shared data/types into an independent leaf module or applying dependency inversion.".to_string()
                        },
                        estimated_lines_saved: 0,
                    });
                }
            }
        }

        findings
    }
}

/// Detect God Objects (excessive fan-in + fan-out + loc)
pub struct GodObjectRule;

impl DetectionRule for GodObjectRule {
    fn rule_name(&self) -> &'static str {
        "god-object"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let degrees = ctx.graph.compute_degrees();
        let mut findings = Vec::new();

        for sym in ctx.symbols {
            if sym.is_test_code() {
                continue;
            }
            if sym.kind == SymbolKind::Struct || sym.kind == SymbolKind::Class {
                // Widely referenced data with (almost) no behavior is a shared
                // domain type, not a god object. Require real behavior or size.
                let method_count = ctx
                    .symbols
                    .iter()
                    .filter(|s| {
                        s.kind == SymbolKind::Method
                            && !s.is_trait_impl
                            && s.name.starts_with(&format!("{}::", sym.name))
                    })
                    .count();
                if method_count < 3 && sym.loc <= 100 {
                    continue;
                }
                if let Some((in_deg, out_deg)) = degrees.get(&sym.id) {
                    if *in_deg + *out_deg > 15 || sym.loc > 300 {
                        findings.push(SlopFinding {
                            kind: SlopKind::GodObject,
                            symbol_id: sym.id.clone(),
                            file_path: sym.file_path.clone(),
                            line: sym.span.start_line,
                            // Large core types are often large by design; this
                            // is a review prompt, not a gate-level defect.
                            severity: Severity::Medium,
                            confidence: 0.85,
                            title: format!("God Object: `{}`", sym.name),
                            description: format!(
                                "Entity `{}` has {} incoming and {} outgoing dependencies ({} LOC). It acts as a bloated central junction.",
                                sym.name, in_deg, out_deg, sym.loc
                            ),
                            remediation: "Decompose this object into single-responsibility cohesive sub-modules.".to_string(),
                            estimated_lines_saved: sym.loc / 3,
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::SourceSpan;
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
}
