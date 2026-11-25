use crate::{bare_name, DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind, Symbol};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Detect circular dependency cycles
pub struct CircularDependencyRule;

impl DetectionRule for CircularDependencyRule {
    fn rule_name(&self) -> &'static str {
        "circular-dependency"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let cycles = ctx.graph.find_circular_dependencies_with_confidence();
        let sym_map: HashMap<&str, &Symbol> =
            ctx.symbols.iter().map(|s| (s.name.as_str(), s)).collect();
        let mut bare_counts: HashMap<&str, usize> = HashMap::new();
        for s in ctx.symbols {
            *bare_counts.entry(bare_name(&s.name)).or_insert(0) += 1;
        }
        let mut findings = Vec::new();

        for (cycle, uses_bare_heuristic) in cycles {
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
                    let files: HashSet<&Path> = cycle
                        .iter()
                        .filter_map(|n| sym_map.get(n.as_str()))
                        .map(|s| s.file_path.as_path())
                        .collect();
                    let has_bare_collision = cycle
                        .iter()
                        .any(|n| bare_counts.get(bare_name(n)).copied().unwrap_or(0) > 1);
                    let ambiguous = uses_bare_heuristic && has_bare_collision;
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
