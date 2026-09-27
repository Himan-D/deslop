use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Severity, SlopFinding, SlopKind, Symbol, SymbolKind,
    Visibility,
};
use deslop_graph::SymbolGraph;
use std::collections::HashMap;

pub struct SlopDetectorEngine;

impl SlopDetectorEngine {
    pub fn analyze(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
        graph: &SymbolGraph,
    ) -> Vec<SlopFinding> {
        let mut findings = Vec::new();

        // 1. Ghost Abstraction Detector
        findings.extend(Self::detect_ghost_abstractions(symbols, edges));

        // 2. Tollbooth Wrapper Detector
        findings.extend(Self::detect_tollbooth_wrappers(symbols, edges));

        // 3. Structural Clone Detector
        findings.extend(Self::detect_structural_clones(symbols));

        // 4. Dead Orphan Code Detector
        findings.extend(Self::detect_dead_orphans(graph));

        // 5. Circular Dependency Detector
        findings.extend(Self::detect_circular_dependencies(symbols, graph));

        // 6. God Object Detector
        findings.extend(Self::detect_god_objects(symbols, graph));

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Detect interfaces/traits with exactly 1 implementation
    fn detect_ghost_abstractions(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
    ) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut impl_counts: HashMap<&str, usize> = HashMap::new();

        for edge in edges {
            if edge.kind == DependencyEdgeKind::Implements {
                *impl_counts.entry(&edge.to_symbol).or_insert(0) += 1;
            }
        }

        for sym in symbols {
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

    /// Detect wrapper functions that do nothing except forward calls
    fn detect_tollbooth_wrappers(
        symbols: &[Symbol],
        edges: &[DependencyEdge],
    ) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut outgoing_calls: HashMap<&str, Vec<&str>> = HashMap::new();

        for edge in edges {
            if edge.kind == DependencyEdgeKind::Calls {
                outgoing_calls
                    .entry(&edge.from_symbol)
                    .or_default()
                    .push(&edge.to_symbol);
            }
        }

        for sym in symbols {
            if sym.name == "main" || sym.name.ends_with("::main") || sym.name.starts_with("test_") {
                continue;
            }

            if (sym.kind == SymbolKind::Function || sym.kind == SymbolKind::Method)
                && sym.loc <= 6
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

    /// Detect duplicated AST structures across functions
    fn detect_structural_clones(symbols: &[Symbol]) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let mut hash_map: HashMap<&str, Vec<&Symbol>> = HashMap::new();

        for sym in symbols {
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
                        severity: Severity::High,
                        confidence: 0.95,
                        title: format!("Structural Clone: `{}` matches `{}`", duplicate.name, primary.name),
                        description: format!(
                            "`{}` shares identical AST logic with `{}` in {}:{}",
                            duplicate.name,
                            primary.name,
                            primary.file_path.display(),
                            primary.span.start_line
                        ),
                        remediation: "Parameterize the shared logic into a single reusable helper function.".to_string(),
                        estimated_lines_saved: duplicate.loc,
                    });
                }
            }
        }

        findings
    }

    /// Detect unreachable dead code
    fn detect_dead_orphans(graph: &SymbolGraph) -> Vec<SlopFinding> {
        let orphans = graph.find_unreachable_orphans();
        orphans
            .into_iter()
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

    /// Detect circular dependency cycles
    fn detect_circular_dependencies(
        symbols: &[Symbol],
        graph: &SymbolGraph,
    ) -> Vec<SlopFinding> {
        let cycles = graph.find_circular_dependencies();
        let sym_map: HashMap<&str, &Symbol> = symbols.iter().map(|s| (s.name.as_str(), s)).collect();
        let mut findings = Vec::new();

        for cycle in cycles {
            let cycle_repr = cycle.join(" -> ");
            if let Some(first_sym_name) = cycle.first() {
                if let Some(first_sym) = sym_map.get(first_sym_name.as_str()) {
                    findings.push(SlopFinding {
                        kind: SlopKind::BarrelBloat,
                        symbol_id: first_sym.id.clone(),
                        file_path: first_sym.file_path.clone(),
                        line: first_sym.span.start_line,
                        severity: Severity::Critical,
                        confidence: 0.95,
                        title: format!("Circular Dependency Loop: {}", cycle_repr),
                        description: format!(
                            "A circular dependency loop was detected: {} -> {}. This tight coupling leads to initialization order bugs and prevents modular compilation.",
                            cycle_repr, first_sym_name
                        ),
                        remediation: "Break the cycle by extracting shared data/types into an independent leaf module or applying dependency inversion.".to_string(),
                        estimated_lines_saved: 0,
                    });
                }
            }
        }

        findings
    }

    /// Detect God Objects (excessive fan-in + fan-out + loc)
    fn detect_god_objects(
        symbols: &[Symbol],
        graph: &SymbolGraph,
    ) -> Vec<SlopFinding> {
        let degrees = graph.compute_degrees();
        let mut findings = Vec::new();

        for sym in symbols {
            if sym.kind == SymbolKind::Struct || sym.kind == SymbolKind::Class {
                if let Some((in_deg, out_deg)) = degrees.get(&sym.id) {
                    if *in_deg + *out_deg > 15 || sym.loc > 300 {
                        findings.push(SlopFinding {
                            kind: SlopKind::GodObject,
                            symbol_id: sym.id.clone(),
                            file_path: sym.file_path.clone(),
                            line: sym.span.start_line,
                            severity: Severity::High,
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

        // Normalize per 1,000 lines of code
        let normalized = (penalty / (total_loc as f64 / 1000.0)).clamp(0.0, 100.0);
        (normalized * 10.0).round() / 10.0
    }
}
