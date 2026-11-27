use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind, Symbol};
use std::collections::HashMap;

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
                        inline_target: None,
                    });
                }
            }
        }

        findings
    }
}
