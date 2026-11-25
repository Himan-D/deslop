use crate::{DetectionContext, DetectionRule};
use deslop_core::{DependencyEdgeKind, Severity, SlopFinding, SlopKind, SymbolKind, Visibility};
use std::collections::HashMap;

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
