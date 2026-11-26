use crate::{bare_name, DetectionContext, DetectionRule};
use deslop_core::{DependencyEdgeKind, Severity, SlopFinding, SlopKind, SymbolKind, Visibility};
use std::collections::HashMap;

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

/// Constructors and conversions are thin by convention, not by accident.
fn is_constructor_like(name: &str) -> bool {
    let bare = bare_name(name);
    matches!(
        bare,
        "new" | "default" | "from" | "build" | "create" | "open" | "init" | "with"
    ) || bare.starts_with("with_")
        || bare.starts_with("from_")
        || bare.starts_with("new_")
}
