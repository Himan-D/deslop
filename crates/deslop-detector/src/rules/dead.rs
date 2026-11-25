use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind};

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
