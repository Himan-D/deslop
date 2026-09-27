use deslop_detector::SlopDetectorEngine;
use deslop_graph::{CapacityAnalyzer, DeepAnalyzer, ScipGenerator, SymbolGraph};
use deslop_inversion::{DelooperEngine, TestGenerator};
use deslop_parser::CodebaseScanner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

pub struct McpServer;

impl McpServer {
    pub fn start() -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();

        let mut line = String::new();
        while handle.read_line(&mut line)? > 0 {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Ok(req) = serde_json::from_str::<McpRequest>(trimmed) {
                    Self::handle_request(req)?;
                }
            }
            line.clear();
        }

        Ok(())
    }

    fn handle_request(req: McpRequest) -> anyhow::Result<()> {
        match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "deslop-mcp",
                        "version": "0.1.0"
                    }
                });
                Self::send_response(req.id, result)?;
            }
            "notifications/initialized" => {
                // Client confirmed initialization
            }
            "tools/list" => {
                let tools = vec![
                    json!({
                        "name": "deslop_scan",
                        "description": "Scans a codebase to compute the Slop Index (0-100), identify ghost abstractions, tollbooth wrappers, and architectural debt.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_deloop",
                        "description": "Discovers circular dependency cycles and identifies the optimal Feedback Arc Set (FAS) cut edge with actionable de-looping refactor steps.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_deep",
                        "description": "Computes Robert C. Martin's Package Coupling metrics (Ca, Ce, Instability, Abstractness, Distance from Main Sequence) and dominator bottlenecks.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_capacity",
                        "description": "Predicts concurrent user capacity, RPS throughput, and breaking points across hardware devices (Cloud, Local, RPi5, Mobile).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_testgen",
                        "description": "Synthesizes characterization and property-based test suites to capture behavioral invariants before de-slopping or refactoring.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" },
                                "symbol": { "type": "string", "description": "Optional specific symbol name to generate tests for" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_prune_diff",
                        "description": "Generates unified diff patch preview showing dead code to delete and tollbooth wrappers to collapse inline.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    }),
                    json!({
                        "name": "deslop_scip",
                        "description": "Exports the full symbol dependency graph into standardized Source Code Intelligence Protocol (SCIP) JSON.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target directory path (defaults to '.')" }
                            }
                        }
                    })
                ];

                Self::send_response(req.id, json!({ "tools": tools }))?;
            }
            "tools/call" => {
                if let Some(params) = req.params {
                    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let args = params.get("arguments").cloned().unwrap_or(json!({}));
                    let path_str = args.get("path").and_then(|p| p.as_str()).unwrap_or(".");
                    let target_path = PathBuf::from(path_str);

                    let response_text = match tool_name {
                        "deslop_scan" => Self::call_scan(&target_path)?,
                        "deslop_deloop" => Self::call_deloop(&target_path)?,
                        "deslop_deep" => Self::call_deep(&target_path)?,
                        "deslop_capacity" => Self::call_capacity(&target_path)?,
                        "deslop_testgen" => {
                            let sym = args.get("symbol").and_then(|s| s.as_str());
                            Self::call_testgen(&target_path, sym)?
                        }
                        "deslop_prune_diff" => Self::call_prune_diff(&target_path)?,
                        "deslop_scip" => Self::call_scip(&target_path)?,
                        _ => format!("Error: Unknown tool '{}'", tool_name),
                    };

                    let result = json!({
                        "content": [
                            {
                                "type": "text",
                                "text": response_text
                            }
                        ]
                    });
                    Self::send_response(req.id, result)?;
                }
            }
            _ => {
                if req.id.is_some() {
                    Self::send_response(req.id, json!(null))?;
                }
            }
        }

        Ok(())
    }

    fn scan_codebase(path: &Path) -> anyhow::Result<(deslop_parser::ParsedCodebase, SymbolGraph, Vec<deslop_core::SlopFinding>)> {
        let scanner = CodebaseScanner::new();
        let parsed = scanner.scan_cached(path, true)?;
        let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
        let findings = SlopDetectorEngine::analyze(&parsed.symbols, &parsed.edges, &graph);
        Ok((parsed, graph, findings))
    }

    fn call_scan(path: &Path) -> anyhow::Result<String> {
        let (parsed, _, findings) = Self::scan_codebase(path)?;
        let score = SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);

        let mut out = String::new();
        out.push_str(&format!("Deslop Architectural Scan: {}\n", path.display()));
        out.push_str(&format!("Slop Index: {:.1} / 100\n", score));
        out.push_str(&format!("Total LOC: {}\n", parsed.stats.total_lines_of_code));
        out.push_str(&format!("Total Files: {}\n", parsed.stats.total_files));
        out.push_str(&format!("Total Symbols: {}\n", parsed.stats.total_symbols));
        out.push_str(&format!("Total Debt Findings: {}\n\n", findings.len()));

        out.push_str("Top Findings:\n");
        for (i, f) in findings.iter().take(10).enumerate() {
            out.push_str(&format!("{}. [{:?}] {}: {} at {}:{}\n", i + 1, f.severity, f.title, f.description, f.file_path.display(), f.line));
        }

        Ok(out)
    }

    fn call_deloop(path: &Path) -> anyhow::Result<String> {
        let (parsed, graph, _) = Self::scan_codebase(path)?;
        let cycles = graph.find_circular_dependencies();
        let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);

        let mut out = String::new();
        out.push_str(&format!("Deslop Circular Dependency De-Looping: {}\n", path.display()));
        out.push_str(&format!("Cycles Detected: {}\n\n", cycles.len()));

        if plans.is_empty() {
            out.push_str("Clean DAG: No circular dependencies detected.\n");
            return Ok(out);
        }

        for (i, p) in plans.iter().enumerate() {
            out.push_str(&format!("Cycle #{}:\n", i + 1));
            out.push_str(&format!("  Loop: {}\n", p.cycle.join(" -> ")));
            out.push_str(&format!("  FAS Cut Candidate: {} -> {}\n", p.cut_edge.0, p.cut_edge.1));
            out.push_str(&format!("  Strategy: {:?}\n", p.strategy));
            out.push_str("  Actionable Steps:\n");
            for step in &p.actionable_steps {
                out.push_str(&format!("    - {}\n", step));
            }
            out.push('\n');
        }

        Ok(out)
    }

    fn call_deep(path: &Path) -> anyhow::Result<String> {
        let (_, graph, _) = Self::scan_codebase(path)?;
        let report = DeepAnalyzer::analyze(&graph);

        let mut out = String::new();
        out.push_str(&format!("Deslop Deep Architectural Report\nAverage Depth Ratio: {:.2}x\n\n", report.average_depth_ratio));

        out.push_str("Package Coupling & Main Sequence:\n");
        for m in &report.module_metrics {
            out.push_str(&format!("  * Module: {} | Ca: {} | Ce: {} | Instability: {:.2} | Abstractness: {:.2} | Distance: {:.2} | Zone: {}\n",
                m.module_name, m.afferent_coupling, m.efferent_coupling, m.instability, m.abstractness, m.distance_from_main_seq, m.classification));
        }

        if !report.bottlenecks.is_empty() {
            out.push_str("\nDominator Chokepoints (Single Points of Failure):\n");
            for b in &report.bottlenecks {
                out.push_str(&format!("  - {} (reaches {:.1}% of graph) at {}\n", b.symbol_name, b.downstream_reach_pct, b.file_path));
            }
        }

        Ok(out)
    }

    fn call_capacity(path: &Path) -> anyhow::Result<String> {
        let (_, graph, _) = Self::scan_codebase(path)?;
        let report = CapacityAnalyzer::analyze(&graph);

        let mut out = String::new();
        out.push_str("Deslop Concurrency & Hardware Capacity Projections:\n\n");
        for est in &report.estimates {
            out.push_str(&format!("Device: {:?}\n", est.device));
            out.push_str(&format!("  Max Concurrent Users: {}\n", est.max_concurrent_users));
            out.push_str(&format!("  Est. Max RPS: {}\n", est.max_requests_per_sec));
            out.push_str(&format!("  Primary Constraint: {}\n\n", est.bottleneck_resource));
        }

        if !report.breaking_risks.is_empty() {
            out.push_str("Breaking Failure Risks:\n");
            for r in &report.breaking_risks {
                out.push_str(&format!("  * [{}] {}: {}\n", r.failure_mode, r.trigger_pattern, r.affected_symbol));
            }
        }

        Ok(out)
    }

    fn call_testgen(path: &Path, symbol: Option<&str>) -> anyhow::Result<String> {
        let (parsed, _, _) = Self::scan_codebase(path)?;

        let suites = if let Some(sym_name) = symbol {
            if let Some(target_sym) = parsed.symbols.iter().find(|s| s.name == sym_name) {
                vec![TestGenerator::generate_for_symbol(target_sym)]
            } else {
                return Ok(format!("Symbol '{}' not found in codebase.", sym_name));
            }
        } else {
            TestGenerator::generate_all(&parsed.symbols)
        };

        let mut out = String::new();
        out.push_str(&format!("Synthesized {} Characterization Test Suite(s):\n\n", suites.len()));
        for s in suites {
            out.push_str(&format!("// Target: {} ({})\n", s.target_symbol, s.file_path));
            out.push_str(&s.test_code);
            out.push_str("\n\n");
        }

        Ok(out)
    }

    fn call_prune_diff(path: &Path) -> anyhow::Result<String> {
        let (_parsed, _graph, findings) = Self::scan_codebase(path)?;
        let prunable: Vec<_> = findings
            .iter()
            .filter(|f| matches!(f.kind, deslop_core::SlopKind::DeadOrphan | deslop_core::SlopKind::TollboothWrapper))
            .collect();

        if prunable.is_empty() {
            return Ok("Codebase is clean. Zero prunable tollbooths or dead code found.".to_string());
        }

        let mut patch = String::new();
        patch.push_str("# Deslop Refactoring Patch\n");
        patch.push_str(&format!("# Target: {}\n", path.display()));
        patch.push_str(&format!("# Prunable Items: {}\n\n", prunable.len()));

        for p in &prunable {
            patch.push_str(&format!("--- a/{}\n", p.file_path.display()));
            patch.push_str(&format!("+++ b/{}\n", p.file_path.display()));
            patch.push_str(&format!("@@ -{},{} +{},0 @@ # Prune {}\n", p.line, p.estimated_lines_saved, p.line, p.title));
            patch.push_str(&format!("- // Deleted {} (~{} LOC)\n\n", p.title, p.estimated_lines_saved));
        }

        Ok(patch)
    }

    fn call_scip(path: &Path) -> anyhow::Result<String> {
        let (parsed, _, _) = Self::scan_codebase(path)?;
        let scip = ScipGenerator::generate(path, &parsed.symbols, &parsed.edges);
        Ok(serde_json::to_string_pretty(&scip)?)
    }

    fn send_response(id: Option<Value>, result: Value) -> anyhow::Result<()> {
        if let Some(id_val) = id {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": result
            });
            let text = serde_json::to_string(&resp)?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{}", text)?;
            stdout.flush()?;
        }
        Ok(())
    }
}
