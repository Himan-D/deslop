pub mod capacity;
pub mod profiler;

pub use capacity::{BreakdownRisk, CapacityAnalyzer, CapacityEstimate, CapacityReport, DeviceProfile};
pub use profiler::{CallStackPath, StackProfileReport, StackProfiler};

use deslop_core::{DependencyEdge, DependencyEdgeKind, Symbol, Visibility};
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

pub struct SymbolGraph {
    pub graph: DiGraph<Symbol, DependencyEdgeKind>,
    pub node_indices: HashMap<String, NodeIndex>,
}

impl SymbolGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    pub fn from_parsed(symbols: &[Symbol], edges: &[DependencyEdge]) -> Self {
        let mut sg = Self::new();

        // Add nodes and build secondary base-name index for O(1) lookups
        let mut base_name_indices: HashMap<&str, NodeIndex> = HashMap::with_capacity(symbols.len());
        for sym in symbols {
            let idx = sg.graph.add_node(sym.clone());
            sg.node_indices.insert(sym.id.clone(), idx);
            base_name_indices.insert(&sym.name, idx);
        }

        // Add edges with O(1) lookups
        for edge in edges {
            let from_opt = sg.node_indices.get(&edge.from_symbol).copied();
            let to_opt = sg.node_indices.get(&edge.to_symbol).copied().or_else(|| {
                base_name_indices.get(edge.to_symbol.as_str()).copied()
            });

            if let (Some(u), Some(v)) = (from_opt, to_opt) {
                if u != v {
                    sg.graph.add_edge(u, v, edge.kind);
                }
            }
        }

        sg
    }

    /// Tarjan's SCC to identify circular dependency loops (length > 1)
    pub fn find_circular_dependencies(&self) -> Vec<Vec<String>> {
        let sccs = tarjan_scc(&self.graph);
        let mut cycles = Vec::new();

        for scc in sccs {
            if scc.len() > 1 {
                let cycle_names: Vec<String> = scc
                    .into_iter()
                    .map(|idx| self.graph[idx].name.clone())
                    .collect();
                cycles.push(cycle_names);
            }
        }

        cycles
    }

    /// Identify dead/orphan symbols: symbols unreachable from any public entrypoint
    pub fn find_unreachable_orphans(&self) -> Vec<Symbol> {
        let mut reachable = HashSet::new();

        // Entrypoints: public functions/methods, or symbols named 'main', 'run', 'handler', 'init'
        let mut roots = Vec::new();
        for idx in self.graph.node_indices() {
            let sym = &self.graph[idx];
            if sym.visibility == Visibility::Public
                || sym.name == "main"
                || sym.name.ends_with("::main")
                || sym.name.contains("handler")
                || sym.name.contains("Route")
            {
                roots.push(idx);
            }
        }

        for root in roots {
            let mut bfs = Bfs::new(&self.graph, root);
            while let Some(visited) = bfs.next(&self.graph) {
                reachable.insert(visited);
            }
        }

        let mut orphans = Vec::new();
        for idx in self.graph.node_indices() {
            if !reachable.contains(&idx) {
                let sym = &self.graph[idx];
                // Only flag private or internal symbols that aren't reachable
                if sym.visibility != Visibility::Public {
                    orphans.push(sym.clone());
                }
            }
        }

        orphans
    }

    /// Computes (in_degree, out_degree) for each symbol
    pub fn compute_degrees(&self) -> HashMap<String, (usize, usize)> {
        let mut res = HashMap::new();
        for idx in self.graph.node_indices() {
            let sym = &self.graph[idx];
            let in_deg = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count();
            let out_deg = self
                .graph
                .neighbors_directed(idx, Direction::Outgoing)
                .count();
            res.insert(sym.id.clone(), (in_deg, out_deg));
        }
        res
    }

    /// Export top architecture components to a clean Mermaid diagram
    pub fn to_mermaid(&self, max_nodes: usize) -> String {
        let mut lines = Vec::new();
        lines.push("flowchart TD".to_string());

        let degrees = self.compute_degrees();
        let mut sorted_nodes: Vec<_> = self.graph.node_indices().collect();
        // Sort by total connectivity (fan-in + fan-out)
        sorted_nodes.sort_by(|a, b| {
            let deg_a = degrees
                .get(&self.graph[*a].id)
                .map(|(i, o)| i + o)
                .unwrap_or(0);
            let deg_b = degrees
                .get(&self.graph[*b].id)
                .map(|(i, o)| i + o)
                .unwrap_or(0);
            deg_b.cmp(&deg_a)
        });

        let selected_indices: HashSet<NodeIndex> =
            sorted_nodes.into_iter().take(max_nodes).collect();

        // Node definitions
        for idx in &selected_indices {
            let sym = &self.graph[*idx];
            let safe_id = format!("node_{}", idx.index());
            let clean_name = sym.name.replace('"', "'");
            let kind_tag = format!("{:?}", sym.kind);
            lines.push(format!(
                "    {}[\"{}\\n<i>({})</i>\"]",
                safe_id, clean_name, kind_tag
            ));
        }

        // Edges
        for edge in self.graph.edge_indices() {
            if let Some((u, v)) = self.graph.edge_endpoints(edge) {
                if selected_indices.contains(&u) && selected_indices.contains(&v) {
                    let weight = self.graph[edge];
                    let label = match weight {
                        DependencyEdgeKind::Calls => "calls",
                        DependencyEdgeKind::Implements => "impl",
                        DependencyEdgeKind::Inherits => "inherits",
                        DependencyEdgeKind::Instantiates => "news",
                        _ => "uses",
                    };
                    lines.push(format!(
                        "    node_{} -->|{}| node_{}",
                        u.index(),
                        label,
                        v.index()
                    ));
                }
            }
        }

        lines.join("\n")
    }
}

impl Default for SymbolGraph {
    fn default() -> Self {
        Self::new()
    }
}
