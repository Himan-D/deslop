use crate::SymbolGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpan {
    pub name: String,
    pub duration_ms: Option<f64>,
    pub status: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCorrelationReport {
    pub total_spans_ingested: usize,
    pub active_runtime_symbols: usize,
    pub dynamic_entrypoints_rescued: Vec<DynamicRescue>,
    pub verified_dead_symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRescue {
    pub symbol_name: String,
    pub file_path: String,
    pub runtime_invocations: usize,
    pub reason: String,
}

pub struct TraceIngestionEngine;

impl TraceIngestionEngine {
    /// Correlates static SymbolGraph nodes with runtime OpenTelemetry spans
    pub fn correlate_traces(graph: &SymbolGraph, spans: &[OtelSpan]) -> TraceCorrelationReport {
        let mut span_counts: HashMap<String, usize> = HashMap::new();
        for s in spans {
            *span_counts.entry(s.name.clone()).or_insert(0) += 1;
        }

        let mut active_runtime_symbols = 0;
        let mut dynamic_entrypoints_rescued = Vec::new();
        let mut verified_dead_symbols = Vec::new();

        for idx in graph.graph.node_indices() {
            let sym = &graph.graph[idx];
            let in_degree = graph
                .graph
                .neighbors_directed(idx, petgraph::Direction::Incoming)
                .count();

            // Match against span names (full name, qualified name, or base name)
            let runtime_hits = span_counts
                .get(&sym.name)
                .or_else(|| span_counts.get(&sym.id))
                .copied()
                .unwrap_or(0);

            if runtime_hits > 0 {
                active_runtime_symbols += 1;
                // If it has 0 static incoming callers but active runtime spans, it's a dynamic rescue!
                if in_degree == 0 {
                    dynamic_entrypoints_rescued.push(DynamicRescue {
                        symbol_name: sym.name.clone(),
                        file_path: sym.file_path.to_string_lossy().to_string(),
                        runtime_invocations: runtime_hits,
                        reason: "Active runtime traffic observed via OpenTelemetry trace telemetry; protected from false-positive dead-code pruning.".to_string(),
                    });
                }
            } else if in_degree == 0 && sym.visibility != deslop_core::Visibility::Public {
                // Zero static callers AND zero runtime invocations
                verified_dead_symbols.push(format!("{} at {}", sym.name, sym.file_path.display()));
            }
        }

        TraceCorrelationReport {
            total_spans_ingested: spans.len(),
            active_runtime_symbols,
            dynamic_entrypoints_rescued,
            verified_dead_symbols,
        }
    }
}
