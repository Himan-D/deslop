pub mod delooper;
pub mod lossless;
pub mod refactor;
pub mod testgen;

pub use delooper::{DeloopPlan, DelooperEngine, DeloopingStrategy};
pub use lossless::LosslessRewriter;
pub use refactor::{RefactorEngine, RefactorResult};
pub use testgen::{
    GoTestEmitter, PythonTestEmitter, RustTestEmitter, SynthesizedTestSuite, TestEmitter,
    TestGenerator, TypeScriptTestEmitter,
};

use deslop_core::{
    CodebaseStats, DependencyEdge, Severity, SlopFinding, SlopKind, Symbol, SymbolKind, Visibility,
};
use deslop_detector::SlopDetectorEngine;
use deslop_graph::SymbolGraph;
use deslop_llm::{CompletionProvider, LlmClient};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetComponent {
    pub name: String,
    pub description: String,
    pub responsibilities: Vec<String>,
    pub retained_symbols: Vec<String>,
    pub pruned_symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvertedArchitecture {
    pub codebase_name: String,
    pub slop_score: f64,
    pub original_loc: usize,
    pub projected_loc: usize,
    pub lines_reduced_estimate: usize,
    pub abstraction_reduction_pct: f64,
    pub core_invariants: Vec<String>,
    pub target_components: Vec<TargetComponent>,
    pub deloop_plans: Vec<DeloopPlan>,
    pub llm_narrative: Option<String>,
    pub mermaid_diagram: String,
    pub spec_markdown: String,
}

pub struct InversionEngine;

impl InversionEngine {
    pub fn synthesize_spec(
        codebase_name: &str,
        stats: &CodebaseStats,
        symbols: &[Symbol],
        _edges: &[DependencyEdge],
        graph: &SymbolGraph,
        findings: &[SlopFinding],
    ) -> InvertedArchitecture {
        let slop_score =
            SlopDetectorEngine::calculate_slop_index(stats.total_lines_of_code, findings);

        // Group symbols by file / directory module
        let mut module_map: HashMap<String, Vec<&Symbol>> = HashMap::new();
        for sym in symbols {
            let parent_dir = sym
                .file_path
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "root".to_string());
            module_map.entry(parent_dir).or_default().push(sym);
        }

        let pruned_symbol_ids: HashSet<&str> = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.kind,
                    SlopKind::DeadOrphan | SlopKind::TollboothWrapper | SlopKind::GhostAbstraction
                )
            })
            .map(|f| f.symbol_id.as_str())
            .collect();

        let total_lines_saved: usize = findings.iter().map(|f| f.estimated_lines_saved).sum();
        let projected_loc = stats.total_lines_of_code.saturating_sub(total_lines_saved);

        let abstraction_reduction_pct = if stats.total_symbols > 0 {
            (pruned_symbol_ids.len() as f64 / stats.total_symbols as f64) * 100.0
        } else {
            0.0
        };

        // Synthesize target clean components
        let mut target_components = Vec::new();
        for (module_path, mod_symbols) in &module_map {
            let mut retained = Vec::new();
            let mut pruned = Vec::new();

            for s in mod_symbols {
                if pruned_symbol_ids.contains(s.id.as_str()) {
                    pruned.push(s.name.clone());
                } else {
                    retained.push(s.name.clone());
                }
            }

            if !retained.is_empty() {
                let comp_name = module_path
                    .split('/')
                    .next_back()
                    .unwrap_or("core")
                    .to_string();

                let pure_funcs_count = mod_symbols.iter().filter(|s| s.is_pure_hint).count();

                target_components.push(TargetComponent {
                    name: comp_name.clone(),
                    description: format!(
                        "Module at `{}` containing {} active symbols ({} pure / stateless)",
                        module_path,
                        retained.len(),
                        pure_funcs_count
                    ),
                    responsibilities: vec![
                        format!("Exposes {} core operations", retained.len()),
                        format!(
                            "Eliminates {} unnecessary wrappers / dead symbols",
                            pruned.len()
                        ),
                    ],
                    retained_symbols: retained,
                    pruned_symbols: pruned,
                });
            }
        }

        // Core invariants extracted from public APIs
        let mut core_invariants = Vec::new();
        for sym in symbols
            .iter()
            .filter(|s| s.visibility == Visibility::Public)
        {
            if sym.kind == SymbolKind::Function || sym.kind == SymbolKind::Method {
                core_invariants.push(format!(
                    "Capability `{}`: signature `{}` (LOC: {}, Complexity: {})",
                    sym.name, sym.signature, sym.loc, sym.cyclomatic_complexity
                ));
            }
        }

        let deloop_plans = DelooperEngine::compute_deloop_plans(symbols, graph);

        // Optionally query LLM if API key is provided
        let llm = LlmClient::auto_detect();
        let llm_narrative = if llm.provider != deslop_llm::LlmProvider::Offline {
            let sys = "You are a Principal Software Architect. Synthesize a concise, high-impact architectural de-slopping rationale.";
            let prompt = format!(
                "Analyze codebase `{}`. Original LOC: {}, Slop Score: {:.1}, Detected Cycles: {}. Explain the top 2 architectural inversions needed.",
                codebase_name, stats.total_lines_of_code, slop_score, deloop_plans.len()
            );
            llm.complete(sys, &prompt).ok()
        } else {
            None
        };

        let mermaid_diagram = graph.to_mermaid(25);

        // Generate the clean specification markdown
        let spec_markdown = Self::generate_markdown(
            codebase_name,
            stats,
            slop_score,
            total_lines_saved,
            projected_loc,
            abstraction_reduction_pct,
            &core_invariants,
            &target_components,
            &deloop_plans,
            llm_narrative.as_deref(),
            findings,
            &mermaid_diagram,
        );

        InvertedArchitecture {
            codebase_name: codebase_name.to_string(),
            slop_score,
            original_loc: stats.total_lines_of_code,
            projected_loc,
            lines_reduced_estimate: total_lines_saved,
            abstraction_reduction_pct: (abstraction_reduction_pct * 10.0).round() / 10.0,
            core_invariants,
            target_components,
            deloop_plans,
            llm_narrative,
            mermaid_diagram,
            spec_markdown,
        }
    }

    fn generate_markdown(
        codebase_name: &str,
        stats: &CodebaseStats,
        slop_score: f64,
        total_lines_saved: usize,
        projected_loc: usize,
        abstraction_reduction_pct: f64,
        invariants: &[String],
        components: &[TargetComponent],
        deloop_plans: &[DeloopPlan],
        llm_narrative: Option<&str>,
        findings: &[SlopFinding],
        mermaid: &str,
    ) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# Architectural Inversion Specification: {}\n\n",
            codebase_name
        ));
        md.push_str("> Auto-synthesized by **Deslop Engine** (Rust)\n\n");

        if let Some(narrative) = llm_narrative {
            md.push_str("## Principal Architect Analysis (BYOK AI Synthesis)\n\n");
            md.push_str(narrative);
            md.push_str("\n\n---\n\n");
        }

        md.push_str("## 1. Executive Summary & Scoreboard\n\n");
        md.push_str("| Metric | Current State | Inverted (Target) | Delta |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        md.push_str(&format!(
            "| **Total Lines of Code** | {} LOC | {} LOC | **-{:.1}%** ({} lines) |\n",
            stats.total_lines_of_code,
            projected_loc,
            if stats.total_lines_of_code > 0 {
                (total_lines_saved as f64 / stats.total_lines_of_code as f64) * 100.0
            } else {
                0.0
            },
            total_lines_saved
        ));
        md.push_str(&format!(
            "| **Slop Index** | {:.1} / 100 | **0.0 / 100** | **-100%** |\n",
            slop_score
        ));
        md.push_str(&format!(
            "| **Total Abstractions / Symbols** | {} | {} | **-{:.1}% bloat** |\n",
            stats.total_symbols,
            stats.total_symbols.saturating_sub(
                (stats.total_symbols as f64 * (abstraction_reduction_pct / 100.0)) as usize
            ),
            abstraction_reduction_pct
        ));
        md.push_str(&format!(
            "| **Critical Architectural Flaws** | {} issues | 0 issues | Clean |\n\n",
            findings
                .iter()
                .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
                .count()
        ));

        md.push_str("## 2. Inverted Component Architecture\n\n");
        md.push_str("```mermaid\n");
        md.push_str(mermaid);
        md.push_str("\n```\n\n");

        if !deloop_plans.is_empty() {
            md.push_str("## 3. De-Looping Strategy (Top-Tier Cycle Breaking)\n\n");
            md.push_str("> Strategies employed: **Leaf Module Extraction**, **Dependency Inversion**, and **Deep Cohesive Merging**.\n\n");

            for (i, p) in deloop_plans.iter().enumerate() {
                md.push_str(&format!("### Loop #{}: `{}`\n", i + 1, p.cycle.join(" ⇄ ")));
                md.push_str(&format!(
                    "- **Architectural Rationale:** {}\n",
                    p.architectural_rationale
                ));
                md.push_str(&format!(
                    "- **Optimal Cut Edge:** `{} -> {}`\n",
                    p.cut_edge.0, p.cut_edge.1
                ));
                md.push_str("- **Actionable Refactoring Steps:**\n");
                for step in &p.actionable_steps {
                    md.push_str(&format!("  1. {}\n", step));
                }
                md.push('\n');
            }
        }

        md.push_str("## 4. Synthesized Target Components\n\n");
        for comp in components {
            md.push_str(&format!("### Component `{}`\n", comp.name));
            md.push_str(&format!("{}\n\n", comp.description));
            md.push_str("**Retained Core Capabilities:**\n");
            for r in comp.retained_symbols.iter().take(8) {
                md.push_str(&format!("- `{}`\n", r));
            }
            if comp.retained_symbols.len() > 8 {
                md.push_str(&format!(
                    "- *(and {} more)*\n",
                    comp.retained_symbols.len() - 8
                ));
            }

            if !comp.pruned_symbols.is_empty() {
                md.push_str("\n**Pruned Redundancies / Wrappers:**\n");
                for p in comp.pruned_symbols.iter().take(5) {
                    md.push_str(&format!("- `~~{}~~` *(eliminated)*\n", p));
                }
            }
            md.push('\n');
        }

        md.push_str("## 4. Key Invariant Contracts (Verified Entrypoints)\n\n");
        for inv in invariants.iter().take(15) {
            md.push_str(&format!("- {}\n", inv));
        }
        if invariants.len() > 15 {
            md.push_str(&format!(
                "- *(and {} other entrypoints)*\n",
                invariants.len() - 15
            ));
        }
        md.push('\n');

        md.push_str("## 5. De-Slop Action Plan (Immediate Remediations)\n\n");
        for (i, f) in findings.iter().take(12).enumerate() {
            md.push_str(&format!(
                "**{}. [{:?}] {}**\n- *Location:* `{}:{}`\n- *Problem:* {}\n- *Fix:* {}\n- *Saved:* ~{} LOC\n\n",
                i + 1,
                f.severity,
                f.title,
                f.file_path.display(),
                f.line,
                f.description,
                f.remediation,
                f.estimated_lines_saved
            ));
        }

        md
    }
}
