use deslop_core::{
    DeepArchitectureReport, DeepModuleScore, DominatorBottleneck, ModuleMetrics, SymbolKind,
};
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

use crate::SymbolGraph;

pub struct DeepAnalyzer;

impl DeepAnalyzer {
    pub fn analyze(graph: &SymbolGraph) -> DeepArchitectureReport {
        let module_metrics = Self::compute_module_metrics(graph);
        let bottlenecks = Self::compute_bottlenecks(graph);
        let deep_module_scores = Self::compute_deep_scores(graph);

        let avg_depth = if !deep_module_scores.is_empty() {
            let sum: f64 = deep_module_scores.iter().map(|s| s.depth_ratio).sum();
            sum / deep_module_scores.len() as f64
        } else {
            1.0
        };

        DeepArchitectureReport {
            module_metrics,
            bottlenecks,
            deep_module_scores,
            average_depth_ratio: avg_depth,
        }
    }

    /// Computes Robert C. Martin's Package Coupling & Main Sequence Metrics
    fn compute_module_metrics(graph: &SymbolGraph) -> Vec<ModuleMetrics> {
        let mut module_symbols: HashMap<String, Vec<petgraph::graph::NodeIndex>> = HashMap::new();

        for idx in graph.graph.node_indices() {
            let sym = &graph.graph[idx];
            let path_str = sym.file_path.to_string_lossy();
            let mod_name = if let Some(pos) = path_str.find("crates/") {
                let sub = &path_str[pos + 7..];
                sub.split('/').next().unwrap_or("crate").to_string()
            } else if let Some(pos) = path_str.find("fixtures/") {
                let sub = &path_str[pos + 9..];
                sub.split('/').next().unwrap_or("fixture").to_string()
            } else {
                sym.file_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "root".to_string())
            };

            module_symbols.entry(mod_name).or_default().push(idx);
        }

        let mut results = Vec::new();

        for (mod_name, nodes) in &module_symbols {
            let node_set: HashSet<_> = nodes.iter().copied().collect();
            let total_syms = nodes.len();
            if total_syms == 0 {
                continue;
            }

            // Count abstract symbols (interfaces, traits)
            let mut abstract_count = 0;
            for idx in nodes {
                let sym = &graph.graph[*idx];
                if matches!(sym.kind, SymbolKind::Trait | SymbolKind::Interface) {
                    abstract_count += 1;
                }
            }

            let abstractness = abstract_count as f64 / total_syms as f64;

            // Afferent coupling (Ca): external nodes calling inside this module
            let mut ca_set = HashSet::new();
            // Efferent coupling (Ce): internal nodes calling outside this module
            let mut ce_set = HashSet::new();

            for idx in nodes {
                for neighbor in graph.graph.neighbors_directed(*idx, Direction::Incoming) {
                    if !node_set.contains(&neighbor) {
                        ca_set.insert(neighbor);
                    }
                }
                for neighbor in graph.graph.neighbors_directed(*idx, Direction::Outgoing) {
                    if !node_set.contains(&neighbor) {
                        ce_set.insert(neighbor);
                    }
                }
            }

            let ca = ca_set.len();
            let ce = ce_set.len();

            let instability = if ca + ce == 0 {
                0.5
            } else {
                ce as f64 / (ca + ce) as f64
            };

            let distance = (abstractness + instability - 1.0).abs();

            let classification = if distance <= 0.25 {
                "Main Sequence (Balanced)".to_string()
            } else if abstractness < 0.35 && instability < 0.35 {
                "Zone of Pain (Rigid & Fragile)".to_string()
            } else if abstractness > 0.65 && instability > 0.65 {
                "Zone of Uselessness (Over-abstracted)".to_string()
            } else {
                "Off-Sequence (Moderate Skew)".to_string()
            };

            results.push(ModuleMetrics {
                module_name: mod_name.clone(),
                afferent_coupling: ca,
                efferent_coupling: ce,
                instability,
                abstractness,
                distance_from_main_seq: distance,
                classification,
            });
        }

        results.sort_by(|a, b| b.distance_from_main_seq.partial_cmp(&a.distance_from_main_seq).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Identifies architectural bottlenecks and single-point-of-failure chokepoints
    fn compute_bottlenecks(graph: &SymbolGraph) -> Vec<DominatorBottleneck> {
        let total_nodes = graph.graph.node_count();
        if total_nodes == 0 {
            return Vec::new();
        }

        let mut bottlenecks = Vec::new();

        for idx in graph.graph.node_indices() {
            let sym = &graph.graph[idx];
            // Measure downstream reachability from this node
            let mut bfs = Bfs::new(&graph.graph, idx);
            let mut reached = 0;
            while let Some(_) = bfs.next(&graph.graph) {
                reached += 1;
            }

            let in_deg = graph.graph.neighbors_directed(idx, Direction::Incoming).count();
            let reach_pct = (reached as f64 / total_nodes as f64) * 100.0;

            // Chokepoint: high reachability (> 30% of entire graph) and multiple incoming callers
            if reached > 2 && (reach_pct > 25.0 || in_deg >= 4) {
                let is_critical = reach_pct > 40.0 && in_deg >= 3;
                bottlenecks.push(DominatorBottleneck {
                    symbol_name: sym.name.clone(),
                    file_path: format!("{}:{}", sym.file_path.display(), sym.span.start_line),
                    dominated_node_count: reached,
                    downstream_reach_pct: reach_pct,
                    is_critical_chokepoint: is_critical,
                });
            }
        }

        bottlenecks.sort_by(|a, b| b.downstream_reach_pct.partial_cmp(&a.downstream_reach_pct).unwrap_or(std::cmp::Ordering::Equal));
        bottlenecks.truncate(10);
        bottlenecks
    }

    /// Measures Ousterhout's Depth Ratio (Interface Complexity vs Implementation Power)
    fn compute_deep_scores(graph: &SymbolGraph) -> Vec<DeepModuleScore> {
        let mut scores = Vec::new();

        for idx in graph.graph.node_indices() {
            let sym = &graph.graph[idx];
            if sym.loc < 5 {
                continue;
            }

            // Interface complexity approximated by signature parameter count & signature length
            let param_count = sym.signature.matches(',').count() + if sym.signature.contains('(') && !sym.signature.contains("()") { 1 } else { 0 };
            let interface_complexity = (param_count * 2) + (sym.signature.len() / 25).max(1);

            // Implementation power = LOC + cyclomatic complexity * 4
            let implementation_power = sym.loc + (sym.cyclomatic_complexity * 4);

            let depth_ratio = implementation_power as f64 / interface_complexity.max(1) as f64;
            let is_deep = depth_ratio >= 3.0;

            scores.push(DeepModuleScore {
                symbol_name: sym.name.clone(),
                file_path: format!("{}:{}", sym.file_path.display(), sym.span.start_line),
                interface_complexity,
                implementation_power,
                depth_ratio,
                is_deep,
            });
        }

        scores.sort_by(|a, b| b.depth_ratio.partial_cmp(&a.depth_ratio).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }
}
