use crate::SymbolGraph;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStackPath {
    pub entrypoint: String,
    pub frames: Vec<String>,
    pub depth: usize,
    pub tollbooth_frames: usize,
    pub stack_tax_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackProfileReport {
    pub max_stack_depth: usize,
    pub average_stack_depth: f64,
    pub deepest_call_paths: Vec<CallStackPath>,
    pub recursive_symbols: Vec<String>,
    pub runtime_hotspots: Vec<(String, u64)>,
    pub runtime_cold_symbols: Vec<String>,
}

pub struct StackProfiler;

impl StackProfiler {
    /// Ingests Linux perf / flamegraph / pprof folded stack trace files:
    /// e.g. "main;dispatch;handler;query 1420"
    pub fn parse_folded_stacks(folded_content: &str) -> HashMap<String, u64> {
        let mut sample_counts: HashMap<String, u64> = HashMap::new();

        for line in folded_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Line format: "frame1;frame2;frame3 <count>"
            if let Some((stack_str, count_str)) = trimmed.rsplit_once(' ') {
                let count: u64 = count_str.parse().unwrap_or(1);
                for frame in stack_str.split(';') {
                    let clean_frame = frame.trim();
                    if !clean_frame.is_empty() {
                        *sample_counts.entry(clean_frame.to_string()).or_insert(0) += count;
                    }
                }
            }
        }

        sample_counts
    }

    /// Performs deep call stack analysis across the dependency graph
    pub fn profile(
        graph: &SymbolGraph,
        runtime_samples: Option<&HashMap<String, u64>>,
    ) -> StackProfileReport {
        let mut all_paths = Vec::new();
        let mut recursive_symbols = Vec::new();

        // Identify root entrypoint nodes (fan-in == 0 or public / main)
        let mut root_indices = Vec::new();
        for idx in graph.graph.node_indices() {
            let in_deg = graph.graph.neighbors_directed(idx, Direction::Incoming).count();
            let sym = &graph.graph[idx];
            if in_deg == 0 || sym.name == "main" || sym.name.ends_with("::main") {
                root_indices.push(idx);
            }
        }

        // If no strict root, use all nodes
        if root_indices.is_empty() {
            root_indices = graph.graph.node_indices().collect();
        }

        // DFS to find maximum depth paths and detect recursion
        for root in root_indices {
            let mut visited_in_path = Vec::new();
            Self::dfs_paths(
                graph,
                root,
                &mut visited_in_path,
                &mut all_paths,
                &mut recursive_symbols,
                0,
                30, // max depth ceiling
            );
        }

        // Deduplicate recursive symbols
        recursive_symbols.sort();
        recursive_symbols.dedup();

        // Sort paths by depth descending
        all_paths.sort_by_key(|b| std::cmp::Reverse(b.depth));
        all_paths.dedup_by(|a, b| a.frames == b.frames);

        let max_stack_depth = all_paths.first().map(|p| p.depth).unwrap_or(1);
        let average_stack_depth = if !all_paths.is_empty() {
            let total: usize = all_paths.iter().map(|p| p.depth).sum();
            (total as f64 / all_paths.len() as f64 * 10.0).round() / 10.0
        } else {
            1.0
        };

        // Correlate with runtime stack samples if present
        let mut runtime_hotspots = Vec::new();
        let mut runtime_cold_symbols = Vec::new();

        if let Some(samples) = runtime_samples {
            for (frame, count) in samples {
                runtime_hotspots.push((frame.clone(), *count));
            }
            runtime_hotspots.sort_by_key(|b| std::cmp::Reverse(b.1));

            // Identify static symbols with zero runtime samples
            for idx in graph.graph.node_indices() {
                let sym = &graph.graph[idx];
                let has_sample = samples.iter().any(|(f, _)| f.contains(&sym.name) || sym.name.contains(f));
                if !has_sample {
                    runtime_cold_symbols.push(sym.name.clone());
                }
            }
        }

        StackProfileReport {
            max_stack_depth,
            average_stack_depth,
            deepest_call_paths: all_paths.into_iter().take(10).collect(),
            recursive_symbols,
            runtime_hotspots: runtime_hotspots.into_iter().take(15).collect(),
            runtime_cold_symbols,
        }
    }

    fn dfs_paths(
        graph: &SymbolGraph,
        current: NodeIndex,
        path: &mut Vec<NodeIndex>,
        all_paths: &mut Vec<CallStackPath>,
        recursive_symbols: &mut Vec<String>,
        depth: usize,
        max_depth: usize,
    ) {
        if depth >= max_depth {
            return;
        }

        let curr_sym = &graph.graph[current];

        // Check recursion
        if path.contains(&current) {
            recursive_symbols.push(curr_sym.name.clone());
            return;
        }

        path.push(current);

        let neighbors: Vec<NodeIndex> = graph
            .graph
            .neighbors_directed(current, Direction::Outgoing)
            .collect();

        if neighbors.is_empty() {
            // Leaf reached -> record path
            if path.len() > 1 {
                let frame_names: Vec<String> = path.iter().map(|idx| graph.graph[*idx].name.clone()).collect();
                let tollbooth_count = path
                    .iter()
                    .filter(|idx| {
                        let s = &graph.graph[**idx];
                        s.loc <= 5 && s.cyclomatic_complexity <= 2
                    })
                    .count();

                let tax = (tollbooth_count as f64 / path.len() as f64) * 100.0;

                all_paths.push(CallStackPath {
                    entrypoint: frame_names.first().cloned().unwrap_or_default(),
                    frames: frame_names,
                    depth: path.len(),
                    tollbooth_frames: tollbooth_count,
                    stack_tax_pct: (tax * 10.0).round() / 10.0,
                });
            }
        } else {
            for neighbor in neighbors {
                Self::dfs_paths(
                    graph,
                    neighbor,
                    path,
                    all_paths,
                    recursive_symbols,
                    depth + 1,
                    max_depth,
                );
            }
        }

        path.pop();
    }
}
