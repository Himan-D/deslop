use deslop_detector::SlopDetectorEngine;
use deslop_graph::{
    CapacityAnalyzer, DeepAnalyzer, GitChurnAnalyzer, GraphAnalyzer, ScipGenerator, SymbolGraph,
};
use deslop_inversion::{DelooperEngine, TestGenerator};
use deslop_parser::CodebaseScanner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct McpRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// One item produced by the stdio framer: either a complete request or a
/// signal that malformed input was dropped and deserves a JSON-RPC error.
#[derive(Debug, PartialEq)]
pub(crate) enum FramedMessage {
    Request(McpRequest),
    ParseError,
}

/// Accumulates stdio input into complete JSON-RPC messages. Accepts compact
/// newline-delimited JSON (the MCP default) as well as pretty-printed
/// multi-line JSON, buffering until each full value parses. Malformed input
/// yields `ParseError` without killing the session.
pub(crate) struct JsonRpcFramer {
    pending: String,
}

impl JsonRpcFramer {
    pub(crate) fn new() -> Self {
        Self {
            pending: String::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.trim().is_empty()
    }

    pub(crate) fn feed_line(&mut self, line: &str) -> Vec<FramedMessage> {
        self.pending.push_str(line);
        // DoS guard: a single message larger than 16 MiB is rejected.
        if self.pending.len() > 16 * 1024 * 1024 {
            self.pending.clear();
            return vec![FramedMessage::ParseError];
        }

        let mut out = Vec::new();
        for _ in 0..100 {
            let current = self.pending.trim_start().to_string();
            if current.is_empty() {
                self.pending.clear();
                break;
            }
            let mut stream = serde_json::Deserializer::from_str(&current).into_iter::<McpRequest>();
            match stream.next() {
                Some(Ok(req)) => {
                    let used = stream.byte_offset();
                    out.push(FramedMessage::Request(req));
                    self.pending = current[used..].to_string();
                }
                Some(Err(e)) if e.is_eof() => {
                    // Incomplete value: keep buffering.
                    self.pending = current;
                    break;
                }
                Some(Err(_)) => {
                    // Malformed: report once, drop the offending line, resync.
                    out.push(FramedMessage::ParseError);
                    if let Some(nl) = current.find('\n') {
                        self.pending = current[nl + 1..].to_string();
                    } else {
                        self.pending.clear();
                        break;
                    }
                }
                None => {
                    self.pending = current;
                    break;
                }
            }
        }
        out
    }
}

pub struct McpServer;

impl McpServer {
    pub fn start() -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut framer = JsonRpcFramer::new();

        let mut line = String::new();
        loop {
            line.clear();
            if handle.read_line(&mut line)? == 0 {
                break; // EOF
            }

            // Accept LSP-style Content-Length framing too; some hosts send it.
            if framer.is_empty()
                && line
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("content-length:")
            {
                if let Some(body) = Self::read_framed_body(&mut handle, &line)? {
                    for msg in framer.feed_line(&body) {
                        Self::dispatch_framed(msg)?;
                    }
                }
                continue;
            }

            for msg in framer.feed_line(&line) {
                Self::dispatch_framed(msg)?;
            }
        }

        Ok(())
    }

    fn read_framed_body(
        handle: &mut std::io::StdinLock<'_>,
        header_line: &str,
    ) -> anyhow::Result<Option<String>> {
        let len: usize = header_line
            .split_once(':')
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0);
        if len == 0 || len > 16 * 1024 * 1024 {
            return Ok(None);
        }
        // Consume the blank separator line, then the exact payload.
        let mut blank = String::new();
        handle.read_line(&mut blank)?;
        let mut body = vec![0u8; len];
        handle.read_exact(&mut body)?;
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    }

    fn dispatch_framed(msg: FramedMessage) -> anyhow::Result<()> {
        match msg {
            FramedMessage::Request(req) => Self::handle_request(req),
            FramedMessage::ParseError => Self::send_error(
                Some(Value::Null),
                -32700,
                "Parse error: invalid JSON-RPC message",
            ),
        }
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
                let mut tools = vec![
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
                    }),
                    json!({
                        "name": "deslop_churn",
                        "description": "Analyzes git commit history to detect churn hotspots and hidden temporal coupling (files that frequently co-change with 0 static imports).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target repository path (defaults to '.')" },
                                "commits": { "type": "integer", "description": "Number of recent commits to analyze (defaults to 500)" }
                            }
                        }
                    }),
                ];

                // Every deslop tool is a read-only local analysis: no writes,
                // no network, safe to retry.
                for tool in &mut tools {
                    tool["annotations"] = json!({
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    });
                }

                Self::send_response(req.id, json!({ "tools": tools }))?;
            }
            "tools/call" => {
                let Some(params) = req.params else {
                    Self::send_error(
                        req.id,
                        -32602,
                        "Invalid params: tools/call requires {name, arguments}",
                    )?;
                    return Ok(());
                };
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let path_str = args.get("path").and_then(|p| p.as_str()).unwrap_or(".");
                let target_path = PathBuf::from(path_str);

                let (response_text, is_error) = match tool_name {
                    "deslop_scan" => (Self::call_scan(&target_path)?, false),
                    "deslop_deloop" => (Self::call_deloop(&target_path)?, false),
                    "deslop_deep" => (Self::call_deep(&target_path)?, false),
                    "deslop_capacity" => (Self::call_capacity(&target_path)?, false),
                    "deslop_testgen" => {
                        let sym = args.get("symbol").and_then(|s| s.as_str());
                        (Self::call_testgen(&target_path, sym)?, false)
                    }
                    "deslop_prune_diff" => (Self::call_prune_diff(&target_path)?, false),
                    "deslop_scip" => (Self::call_scip(&target_path)?, false),
                    "deslop_churn" => {
                        let commits = args.get("commits").and_then(|c| c.as_u64()).unwrap_or(500) as usize;
                        (Self::call_churn(&target_path, commits)?, false)
                    }
                    _ => (
                        format!(
                            "Unknown tool '{}'. Call tools/list to see available tools (deslop_scan, deslop_deloop, deslop_deep, deslop_capacity, deslop_testgen, deslop_prune_diff, deslop_scip, deslop_churn).",
                            tool_name
                        ),
                        true,
                    ),
                };

                // MCP spec: tool failures ride in the result with isError,
                // not as JSON-RPC errors.
                let mut result = json!({
                    "content": [
                        {
                            "type": "text",
                            "text": response_text
                        }
                    ]
                });
                if is_error {
                    result["isError"] = json!(true);
                }
                Self::send_response(req.id, result)?;
            }
            "ping" => {
                Self::send_response(req.id, json!({}))?;
            }
            _ => {
                if req.id.is_some() {
                    Self::send_error(req.id, -32601, &format!("Method not found: {}", req.method))?;
                }
            }
        }

        Ok(())
    }

    fn scan_codebase(
        path: &Path,
    ) -> anyhow::Result<(
        deslop_parser::ParsedCodebase,
        SymbolGraph,
        Vec<deslop_core::SlopFinding>,
    )> {
        let scanner = CodebaseScanner::new();
        let parsed = scanner.scan_cached(path, true)?;
        let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
        let arch_config = deslop_core::ArchitectureConfig::load_from_dir(path);
        let findings = SlopDetectorEngine::analyze_with_config(
            &parsed.symbols,
            &parsed.edges,
            &graph,
            arch_config.as_ref(),
        );
        Ok((parsed, graph, findings))
    }

    fn call_churn(path: &Path, commits: usize) -> anyhow::Result<String> {
        match GitChurnAnalyzer::analyze(path, commits) {
            Some(report) => {
                let mut out = String::new();
                out.push_str(&format!(
                    "Git Churn & Temporal Coupling Analysis ({})\n",
                    path.display()
                ));
                out.push_str(&format!(
                    "Commits Analyzed: {}\n\n",
                    report.total_commits_analyzed
                ));
                out.push_str("Top Churn Hotspots:\n");
                for (i, h) in report.top_hotspots.iter().take(10).enumerate() {
                    out.push_str(&format!(
                        "{}. {} ({} commits, {})\n",
                        i + 1,
                        h.file_path,
                        h.commit_count,
                        h.churn_risk
                    ));
                }
                out.push_str("\nHidden Temporal Couplings (>40% Co-change Frequency):\n");
                if report.temporal_couplings.is_empty() {
                    out.push_str("  No hidden temporal couplings detected above 40% threshold.\n");
                } else {
                    for (i, c) in report.temporal_couplings.iter().take(10).enumerate() {
                        out.push_str(&format!(
                            "{}. {} <-> {} ({} co-commits, {:.1}% coupling)\n",
                            i + 1,
                            c.file_a,
                            c.file_b,
                            c.co_commit_count,
                            c.coupling_pct
                        ));
                    }
                }
                Ok(out)
            }
            None => Ok(format!(
                "Git history not available or empty repository at {}",
                path.display()
            )),
        }
    }

    fn call_scan(path: &Path) -> anyhow::Result<String> {
        let (parsed, _, findings) = Self::scan_codebase(path)?;
        let score =
            SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);

        let mut out = String::new();
        out.push_str(&format!("Deslop Architectural Scan: {}\n", path.display()));
        out.push_str(&format!("Slop Index: {:.1} / 100\n", score));
        out.push_str(&format!(
            "Total LOC: {}\n",
            parsed.stats.total_lines_of_code
        ));
        out.push_str(&format!("Total Files: {}\n", parsed.stats.total_files));
        out.push_str(&format!("Total Symbols: {}\n", parsed.stats.total_symbols));
        out.push_str(&format!("Total Debt Findings: {}\n\n", findings.len()));

        out.push_str("Top Findings:\n");
        for (i, f) in findings.iter().take(10).enumerate() {
            out.push_str(&format!(
                "{}. [{:?}] {}: {} at {}:{}\n",
                i + 1,
                f.severity,
                f.title,
                f.description,
                f.file_path.display(),
                f.line
            ));
        }

        Ok(out)
    }

    fn call_deloop(path: &Path) -> anyhow::Result<String> {
        let (parsed, graph, _) = Self::scan_codebase(path)?;
        let cycles = graph.find_circular_dependencies();
        let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);

        let mut out = String::new();
        out.push_str(&format!(
            "Deslop Circular Dependency De-Looping: {}\n",
            path.display()
        ));
        out.push_str(&format!("Cycles Detected: {}\n\n", cycles.len()));

        if plans.is_empty() {
            out.push_str("Clean DAG: No circular dependencies detected.\n");
            return Ok(out);
        }

        for (i, p) in plans.iter().enumerate() {
            out.push_str(&format!("Cycle #{}:\n", i + 1));
            out.push_str(&format!("  Loop: {}\n", p.cycle.join(" -> ")));
            out.push_str(&format!(
                "  FAS Cut Candidate: {} -> {}\n",
                p.cut_edge.0, p.cut_edge.1
            ));
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
        out.push_str(&format!(
            "Deslop Deep Architectural Report\nAverage Depth Ratio: {:.2}x\n\n",
            report.average_depth_ratio
        ));

        out.push_str("Package Coupling & Main Sequence:\n");
        for m in &report.module_metrics {
            out.push_str(&format!("  * Module: {} | Ca: {} | Ce: {} | Instability: {:.2} | Abstractness: {:.2} | Distance: {:.2} | Zone: {}\n",
                m.module_name, m.afferent_coupling, m.efferent_coupling, m.instability, m.abstractness, m.distance_from_main_seq, m.classification));
        }

        if !report.bottlenecks.is_empty() {
            out.push_str("\nDominator Chokepoints (Single Points of Failure):\n");
            for b in &report.bottlenecks {
                out.push_str(&format!(
                    "  - {} (reaches {:.1}% of graph) at {}\n",
                    b.symbol_name, b.downstream_reach_pct, b.file_path
                ));
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
            out.push_str(&format!(
                "  Max Concurrent Users: {}\n",
                est.max_concurrent_users
            ));
            out.push_str(&format!("  Est. Max RPS: {}\n", est.max_requests_per_sec));
            out.push_str(&format!(
                "  Primary Constraint: {}\n\n",
                est.bottleneck_resource
            ));
        }

        if !report.breaking_risks.is_empty() {
            out.push_str("Breaking Failure Risks:\n");
            for r in &report.breaking_risks {
                out.push_str(&format!(
                    "  * [{}] {}: {}\n",
                    r.failure_mode, r.trigger_pattern, r.affected_symbol
                ));
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
        out.push_str(&format!(
            "Synthesized {} Characterization Test Suite(s):\n\n",
            suites.len()
        ));
        for s in suites {
            out.push_str(&format!(
                "// Target: {} ({})\n",
                s.target_symbol, s.file_path
            ));
            out.push_str(&s.test_code);
            out.push_str("\n\n");
        }

        Ok(out)
    }

    fn call_prune_diff(path: &Path) -> anyhow::Result<String> {
        let (_parsed, _graph, findings) = Self::scan_codebase(path)?;
        let prunable: Vec<_> = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.kind,
                    deslop_core::SlopKind::DeadOrphan | deslop_core::SlopKind::TollboothWrapper
                )
            })
            .collect();

        if prunable.is_empty() {
            return Ok(
                "Codebase is clean. Zero prunable tollbooths or dead code found.".to_string(),
            );
        }

        let mut patch = String::new();
        patch.push_str("# Deslop Refactoring Patch\n");
        patch.push_str(&format!("# Target: {}\n", path.display()));
        patch.push_str(&format!("# Prunable Items: {}\n\n", prunable.len()));

        for p in &prunable {
            patch.push_str(&format!("--- a/{}\n", p.file_path.display()));
            patch.push_str(&format!("+++ b/{}\n", p.file_path.display()));
            patch.push_str(&format!(
                "@@ -{},{} +{},0 @@ # Prune {}\n",
                p.line, p.estimated_lines_saved, p.line, p.title
            ));
            patch.push_str(&format!(
                "- // Deleted {} (~{} LOC)\n\n",
                p.title, p.estimated_lines_saved
            ));
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
            Self::write_message(&resp)?;
        }
        Ok(())
    }

    fn send_error(id: Option<Value>, code: i32, message: &str) -> anyhow::Result<()> {
        // Notifications (no id) never get a response, per JSON-RPC.
        if let Some(id_val) = id {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "error": {
                    "code": code,
                    "message": message
                }
            });
            Self::write_message(&resp)?;
        }
        Ok(())
    }

    fn write_message(msg: &Value) -> anyhow::Result<()> {
        let text = serde_json::to_string(msg)?;
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{}", text)?;
        stdout.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_json(id: u32, method: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{},"method":"{}"}}"#, id, method)
    }

    #[test]
    fn framer_emits_compact_message_immediately() {
        let mut framer = JsonRpcFramer::new();
        let msgs = framer.feed_line(&format!("{}\n", request_json(1, "ping")));
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            FramedMessage::Request(req) => assert_eq!(req.method, "ping"),
            other => panic!("expected Request, got {:?}", other),
        }
        assert!(framer.is_empty());
    }

    #[test]
    fn framer_buffers_multiline_pretty_json() {
        let mut framer = JsonRpcFramer::new();
        let pretty = "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 7,\n  \"method\": \"tools/list\"\n}\n";
        let mut all = Vec::new();
        for line in pretty.split_inclusive('\n') {
            all.extend(framer.feed_line(line));
        }
        assert_eq!(all.len(), 1);
        match &all[0] {
            FramedMessage::Request(req) => {
                assert_eq!(req.method, "tools/list");
                assert_eq!(req.id, Some(json!(7)));
            }
            other => panic!("expected Request, got {:?}", other),
        }
    }

    #[test]
    fn framer_holds_incomplete_until_closed() {
        let mut framer = JsonRpcFramer::new();
        assert!(framer.feed_line("{\"jsonrpc\": \"2.0\",\n").is_empty());
        assert!(!framer.is_empty());
        let msgs = framer.feed_line("\"id\": 3, \"method\": \"ping\"}\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(msgs[0], FramedMessage::Request(_)));
    }

    #[test]
    fn framer_reports_parse_error_and_resyncs() {
        let mut framer = JsonRpcFramer::new();
        let bad = framer.feed_line("this is not json\n");
        assert_eq!(bad, vec![FramedMessage::ParseError]);
        // Session survives: the next valid message still parses.
        let good = framer.feed_line(&format!("{}\n", request_json(2, "ping")));
        assert_eq!(good.len(), 1);
        assert!(matches!(good[0], FramedMessage::Request(_)));
    }

    #[test]
    fn framer_splits_concatenated_messages() {
        let mut framer = JsonRpcFramer::new();
        let chunk = format!("{}\n{}\n", request_json(1, "ping"), request_json(2, "ping"));
        let msgs = framer.feed_line(&chunk);
        assert_eq!(msgs.len(), 2);
    }
}
