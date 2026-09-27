use deslop_core::Symbol;
use deslop_graph::SymbolGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeloopingStrategy {
    /// Strategy 1: Extract shared state/types to an independent leaf module
    LeafModuleExtraction {
        shared_leaf_name: String,
        symbols_to_move: Vec<String>,
    },
    /// Strategy 2: Inject interface/callback to invert the upward dependency
    DependencyInversion {
        source: String,
        target: String,
        injected_trait: String,
    },
    /// Strategy 3: Merge co-dependent symbols into a single cohesive unit
    CohesiveMerge {
        target_module: String,
        members: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeloopPlan {
    pub cycle: Vec<String>,
    pub strategy: DeloopingStrategy,
    pub cut_edge: (String, String),
    pub architectural_rationale: String,
    pub actionable_steps: Vec<String>,
}

pub struct DelooperEngine;

impl DelooperEngine {
    /// Analyzes all circular dependency loops and computes top-engineer de-looping strategies
    pub fn compute_deloop_plans(
        symbols: &[Symbol],
        graph: &SymbolGraph,
    ) -> Vec<DeloopPlan> {
        let raw_cycles = graph.find_circular_dependencies();
        let sym_map: HashMap<&str, &Symbol> = symbols.iter().map(|s| (s.name.as_str(), s)).collect();
        let degrees = graph.compute_degrees();

        let mut plans = Vec::new();

        for cycle in raw_cycles {
            if cycle.len() < 2 {
                continue;
            }

            // Find the weakest link in the cycle (lowest fan-in / smallest LOC)
            let mut weakest_from = &cycle[0];
            let mut weakest_to = &cycle[1];
            let mut min_weight = usize::MAX;

            for i in 0..cycle.len() {
                let from = &cycle[i];
                let to = &cycle[(i + 1) % cycle.len()];

                let loc = sym_map.get(from.as_str()).map(|s| s.loc).unwrap_or(10);
                let deg = sym_map
                    .get(from.as_str())
                    .and_then(|s| degrees.get(&s.id))
                    .map(|(in_d, _)| *in_d)
                    .unwrap_or(1);

                let weight = loc + (deg * 5);
                if weight < min_weight {
                    min_weight = weight;
                    weakest_from = from;
                    weakest_to = to;
                }
            }

            // Decide top-tier engineering strategy
            let plan = if cycle.len() == 2 {
                let s1 = &cycle[0];
                let s2 = &cycle[1];
                let loc1 = sym_map.get(s1.as_str()).map(|s| s.loc).unwrap_or(20);
                let loc2 = sym_map.get(s2.as_str()).map(|s| s.loc).unwrap_or(20);

                if loc1 + loc2 < 100 {
                    // Small coupled pair -> Merge them!
                    DeloopPlan {
                        cycle: cycle.clone(),
                        strategy: DeloopingStrategy::CohesiveMerge {
                            target_module: format!("{}_unified", s1.to_lowercase()),
                            members: vec![s1.clone(), s2.clone()],
                        },
                        cut_edge: (weakest_from.clone(), weakest_to.clone()),
                        architectural_rationale: format!(
                            "Tight mutual recursion between `{}` and `{}` (total {} LOC). Merging them into a single deep module eliminates the boundary friction entirely.",
                            s1, s2, loc1 + loc2
                        ),
                        actionable_steps: vec![
                            format!("Consolidate `{}` and `{}` into the same source file.", s1, s2),
                            "Make their mutual interactions internal/private rather than public imports.".to_string(),
                            "Expose a single clean public facade to the rest of the application.".to_string(),
                        ],
                    }
                } else {
                    // Extract shared types into a leaf module
                    let leaf_name = format!("{}_models", s1.to_lowercase());
                    DeloopPlan {
                        cycle: cycle.clone(),
                        strategy: DeloopingStrategy::LeafModuleExtraction {
                            shared_leaf_name: leaf_name.clone(),
                            symbols_to_move: vec![format!("{}SharedTypes", s1)],
                        },
                        cut_edge: (weakest_from.clone(), weakest_to.clone()),
                        architectural_rationale: format!(
                            "Circular coupling `{}` <-> `{}` caused by shared data exchange. Extracting shared types into leaf module `{}` ensures dependencies point strictly downwards in a DAG.",
                            s1, s2, leaf_name
                        ),
                        actionable_steps: vec![
                            format!("Create new leaf module `{}`.", leaf_name),
                            format!("Move data structs and enums referenced by both `{}` and `{}` into the leaf module.", s1, s2),
                            format!("Update `{}` and `{}` to import from `{}` instead of importing each other.", s1, s2, leaf_name),
                        ],
                    }
                }
            } else {
                // Multi-node cycle (A -> B -> C -> A) -> Break via Dependency Inversion
                let trait_name = format!("I{}Delegate", weakest_to);
                DeloopPlan {
                    cycle: cycle.clone(),
                    strategy: DeloopingStrategy::DependencyInversion {
                        source: weakest_from.clone(),
                        target: weakest_to.clone(),
                        injected_trait: trait_name.clone(),
                    },
                    cut_edge: (weakest_from.clone(), weakest_to.clone()),
                    architectural_rationale: format!(
                        "Loop `{}` broken at edge `{} -> {}`. Inverting the call via trait/callback injection `{}` converts the cyclic graph into an acyclic DAG.",
                        cycle.join(" -> "), weakest_from, weakest_to, trait_name
                    ),
                    actionable_steps: vec![
                        format!("Define abstract trait or callback `{}` in `{}`.", trait_name, weakest_from),
                        format!("Pass an implementation of `{}` into `{}` at initialization time.", trait_name, weakest_from),
                        format!("Remove the direct import of `{}` from `{}`.", weakest_to, weakest_from),
                    ],
                }
            };

            plans.push(plan);
        }

        plans
    }
}
