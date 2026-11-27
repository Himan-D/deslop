use deslop_core::{Severity, SlopFinding};
use deslop_detector::{CallSiteIndex, SlopDetectorEngine};
use deslop_graph::SymbolGraph;
use deslop_inversion::{FileRewrite, RefactorEngine};
use deslop_parser::{CodebaseScanner, ParsedCodebase};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Default)]
pub struct LspServer {
    root_path: Option<PathBuf>,
    published_uris: HashSet<String>,
    dirty_uris: HashSet<String>,
    cached_parsed: Option<ParsedCodebase>,
    cached_callsites: Option<CallSiteIndex>,
    cached_findings: Vec<SlopFinding>,
}

impl LspServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();

        loop {
            // Read Content-Length header
            let mut line = String::new();
            if handle.read_line(&mut line)? == 0 {
                break; // EOF
            }

            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            if line_trimmed.starts_with("Content-Length:") {
                let parts: Vec<&str> = line_trimmed.split(':').collect();
                if parts.len() < 2 {
                    continue;
                }
                let len: usize = parts[1].trim().parse().unwrap_or(0);

                // Read empty separator line (\r\n)
                let mut blank = String::new();
                handle.read_line(&mut blank)?;

                // Read payload
                let mut body = vec![0u8; len];
                handle.read_exact(&mut body)?;

                let body_str = String::from_utf8_lossy(&body);
                if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&body_str) {
                    self.handle_request(req)?;
                }
            }
        }

        Ok(())
    }

    fn handle_request(&mut self, req: JsonRpcRequest) -> anyhow::Result<()> {
        match req.method.as_str() {
            "initialize" => {
                if let Some(params) = req.params {
                    if let Some(root_uri) = params.get("rootUri").and_then(|u| u.as_str()) {
                        self.root_path = Some(uri_to_path(root_uri));
                    }
                }

                let result = json!({
                    "capabilities": {
                        "textDocumentSync": 1, // Full
                        "codeActionProvider": true,
                    },
                    "serverInfo": {
                        "name": "deslop-lsp",
                        "version": "0.1.0"
                    }
                });

                self.send_response(req.id, result)?;
            }
            "initialized" => {
                // Client confirmed initialization; run initial scan if root_path exists
                if let Some(root) = self.root_path.clone() {
                    self.publish_diagnostics_for_workspace(&root)?;
                }
            }
            "textDocument/didOpen" | "textDocument/didSave" => {
                if let Some(params) = req.params {
                    if let Some(doc) = params.get("textDocument") {
                        if let Some(uri) = doc.get("uri").and_then(|u| u.as_str()) {
                            self.dirty_uris.remove(uri);
                            let file_path = uri_to_path(uri);
                            let root = self.root_path.clone().unwrap_or_else(|| {
                                file_path.parent().unwrap_or(Path::new(".")).to_path_buf()
                            });
                            self.publish_diagnostics_for_workspace(&root)?;
                        }
                    }
                }
            }
            "textDocument/didChange" => {
                if let Some(uri) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("textDocument"))
                    .and_then(|d| d.get("uri"))
                    .and_then(|u| u.as_str())
                {
                    self.dirty_uris.insert(uri.to_string());
                }
            }
            "textDocument/didClose" => {
                if let Some(uri) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("textDocument"))
                    .and_then(|d| d.get("uri"))
                    .and_then(|u| u.as_str())
                {
                    self.dirty_uris.remove(uri);
                }
            }
            "textDocument/codeAction" => {
                let actions = req
                    .params
                    .as_ref()
                    .map(|p| self.build_code_actions(p))
                    .unwrap_or_default();
                self.send_response(req.id, json!(actions))?;
            }
            "shutdown" => {
                self.send_response(req.id, json!(null))?;
            }
            "exit" => {
                std::process::exit(0);
            }
            _ => {
                // Respond to unhandled request with null if it has an id
                if req.id.is_some() {
                    self.send_response(req.id, json!(null))?;
                }
            }
        }

        Ok(())
    }

    fn publish_diagnostics_for_workspace(&mut self, root: &Path) -> anyhow::Result<()> {
        let scanner = CodebaseScanner::new();
        if let Ok(parsed) = scanner.scan_cached(root, true) {
            let graph = SymbolGraph::from_parsed_with_imports(
                &parsed.symbols,
                &parsed.edges,
                &parsed.imports,
            );
            let callsites = crate::commands::common::callsite_index(&parsed);
            let findings = SlopDetectorEngine::analyze_full(
                &parsed.symbols,
                &parsed.edges,
                &graph,
                None,
                Some(&callsites),
            );

            // Group findings by file URI
            let mut file_diags: HashMap<String, Vec<Value>> = HashMap::new();

            for f in &findings {
                let uri = format!("file://{}", f.file_path.display());
                let sev_num = match f.severity {
                    Severity::Critical | Severity::High => 1, // Error
                    Severity::Medium => 2,                    // Warning
                    Severity::Low => 3,                       // Information
                };

                let line_idx = f.line.saturating_sub(1);
                let diag = json!({
                    "range": {
                        "start": { "line": line_idx, "character": 0 },
                        "end": { "line": line_idx, "character": 80 }
                    },
                    "severity": sev_num,
                    "code": format!("{:?}", f.kind),
                    "source": "deslop",
                    "message": format!("{}: {}", f.title, f.description)
                });

                file_diags.entry(uri).or_default().push(diag);
            }

            // Clear diagnostics for previously published URIs that are now clean
            let current_uris: HashSet<String> = file_diags.keys().cloned().collect();
            let stale_uris: Vec<String> = self
                .published_uris
                .difference(&current_uris)
                .cloned()
                .collect();
            for uri in stale_uris {
                self.send_notification(
                    "textDocument/publishDiagnostics",
                    json!({
                        "uri": uri,
                        "diagnostics": []
                    }),
                )?;
            }

            for (uri, diags) in file_diags {
                self.send_notification(
                    "textDocument/publishDiagnostics",
                    json!({
                        "uri": uri,
                        "diagnostics": diags
                    }),
                )?;
            }

            self.published_uris = current_uris;
            self.cached_findings = findings;
            self.cached_callsites = Some(callsites);
            self.cached_parsed = Some(parsed);
        }

        Ok(())
    }

    fn build_code_actions(&self, params: &Value) -> Vec<Value> {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|d| d.get("uri"))
            .and_then(|u| u.as_str())
        else {
            return Vec::new();
        };

        let (Some(parsed), Some(callsites)) = (&self.cached_parsed, &self.cached_callsites) else {
            return Vec::new();
        };

        if self.dirty_uris.contains(uri) {
            return Vec::new();
        }

        let req_path = uri_to_path(uri);
        let start_line = params
            .get("range")
            .and_then(|r| r.get("start"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize + 1)
            .unwrap_or(1);
        let end_line = params
            .get("range")
            .and_then(|r| r.get("end"))
            .and_then(|e| e.get("line"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize + 1)
            .unwrap_or(start_line);

        let matching_findings: Vec<SlopFinding> = self
            .cached_findings
            .iter()
            .filter(|f| {
                f.file_path == req_path
                    && RefactorEngine::is_prunable(f)
                    && f.line >= start_line.saturating_sub(2)
                    && f.line <= end_line + 2
            })
            .cloned()
            .collect();

        let mut actions = Vec::new();
        for finding in &matching_findings {
            if let Ok(rewrite_set) = RefactorEngine::rewrite_set(
                std::slice::from_ref(finding),
                &parsed.symbols,
                callsites,
            ) {
                if let Some(changes) = rewrites_to_workspace_changes(&rewrite_set.rewrites) {
                    actions.push(json!({
                        "title": format!("Fix: {}", finding.title),
                        "kind": "quickfix",
                        "isPreferred": true,
                        "edit": { "changes": changes }
                    }));
                }
            }
        }

        // Also offer a file-wide safe prune if multiple prunable findings exist in this file
        let file_findings: Vec<SlopFinding> = self
            .cached_findings
            .iter()
            .filter(|f| f.file_path == req_path && RefactorEngine::is_prunable(f))
            .cloned()
            .collect();
        if file_findings.len() > 1 {
            if let Ok(rewrite_set) =
                RefactorEngine::rewrite_set(&file_findings, &parsed.symbols, callsites)
            {
                let applied_count: usize =
                    rewrite_set.rewrites.iter().map(|r| r.items_pruned).sum();
                if let Some(changes) = rewrites_to_workspace_changes(&rewrite_set.rewrites) {
                    actions.push(json!({
                        "title": format!("Prune all {applied_count} safe slop items in file"),
                        "kind": "source.fixAll",
                        "edit": { "changes": changes }
                    }));
                }
            }
        }

        actions
    }

    fn send_response(&self, id: Option<Value>, result: Value) -> anyhow::Result<()> {
        if let Some(id_val) = id {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": result
            });
            self.write_json(&resp)?;
        }
        Ok(())
    }

    fn send_notification(&self, method: &str, params: Value) -> anyhow::Result<()> {
        let notif = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        self.write_json(&notif)?;
        Ok(())
    }

    fn write_json(&self, val: &Value) -> anyhow::Result<()> {
        let text = serde_json::to_string(val)?;
        let mut stdout = io::stdout().lock();
        write!(stdout, "Content-Length: {}\r\n\r\n{}", text.len(), text)?;
        stdout.flush()?;
        Ok(())
    }
}

fn uri_to_path(uri: &str) -> PathBuf {
    PathBuf::from(uri.strip_prefix("file://").unwrap_or(uri))
}

fn rewrites_to_workspace_changes(rewrites: &[FileRewrite]) -> Option<Value> {
    if rewrites.is_empty() {
        return None;
    }
    let mut changes = serde_json::Map::new();
    for rw in rewrites {
        if rw.original == rw.updated {
            continue;
        }
        let uri = format!("file://{}", rw.path.display());
        let orig_lines: Vec<&str> = rw.original.lines().collect();
        let (end_line, end_char) = if rw.original.ends_with('\n') {
            (orig_lines.len(), 0)
        } else if let Some(last) = orig_lines.last() {
            (
                orig_lines.len().saturating_sub(1),
                last.encode_utf16().count(),
            )
        } else {
            (0, 0)
        };
        let text_edit = json!({
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": end_line, "character": end_char }
            },
            "newText": rw.updated
        });
        changes.insert(uri, json!([text_edit]));
    }
    if changes.is_empty() {
        None
    } else {
        Some(Value::Object(changes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{SlopKind, SourceSpan, Symbol, SymbolKind, Visibility};

    #[test]
    fn code_actions_return_real_workspace_edits_for_prunable_finding() {
        let dir = std::env::temp_dir().join(format!("deslop-lsp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("lib.rs");
        let src = "fn dead_helper() {\n    println!(\"unused\");\n}\n\npub fn main_fn() {}\n";
        std::fs::write(&file, src).unwrap();

        let sym = Symbol {
            id: format!("{}::dead_helper", file.display()),
            name: "dead_helper".to_string(),
            kind: SymbolKind::Function,
            file_path: file.clone(),
            span: SourceSpan::new(1, 1, 3, 2),
            visibility: Visibility::Private,
            loc: 3,
            cyclomatic_complexity: 1,
            doc: None,
            signature: "fn dead_helper()".to_string(),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        };

        let finding = SlopFinding {
            kind: SlopKind::DeadOrphan,
            symbol_id: sym.id.clone(),
            file_path: file.clone(),
            line: 1,
            severity: Severity::Medium,
            confidence: 0.9,
            title: "Dead Orphan: `dead_helper`".to_string(),
            description: "Unused".to_string(),
            remediation: "Delete".to_string(),
            estimated_lines_saved: 3,
            inline_target: None,
        };

        let parsed = ParsedCodebase {
            root_dir: dir.clone(),
            files: vec![file.clone()],
            symbols: vec![sym],
            edges: Vec::new(),
            imports: HashMap::new(),
            stats: deslop_core::CodebaseStats::default(),
        };
        let callsites = CallSiteIndex::build([(file.as_path(), src)]);

        let server = LspServer {
            root_path: Some(dir.clone()),
            published_uris: HashSet::new(),
            dirty_uris: HashSet::new(),
            cached_parsed: Some(parsed),
            cached_callsites: Some(callsites),
            cached_findings: vec![finding],
        };

        let uri = format!("file://{}", file.display());
        let actions = server.build_code_actions(&json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 0, "character": 5 }
            }
        }));

        assert_eq!(actions.len(), 1);
        let edit = actions[0]
            .get("edit")
            .expect("CodeAction must include WorkspaceEdit");
        let changes = edit.get("changes").and_then(|c| c.as_object()).unwrap();
        let file_edits = changes.get(&uri).and_then(|v| v.as_array()).unwrap();
        let new_text = file_edits[0]
            .get("newText")
            .and_then(|t| t.as_str())
            .unwrap();
        assert!(!new_text.contains("dead_helper"));
        assert!(new_text.contains("main_fn"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn code_actions_return_empty_when_no_prunable_finding_matches_range() {
        let server = LspServer::default();
        let actions = server.build_code_actions(&json!({
            "textDocument": { "uri": "file:///tmp/clean.rs" },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 0, "character": 0 }
            }
        }));
        assert!(actions.is_empty());
    }
}
