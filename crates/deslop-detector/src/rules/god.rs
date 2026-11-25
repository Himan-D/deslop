use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind, SymbolKind};

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
