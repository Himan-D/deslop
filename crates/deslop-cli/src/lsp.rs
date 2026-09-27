use deslop_core::Severity;
use deslop_detector::SlopDetectorEngine;
use deslop_graph::SymbolGraph;
use deslop_parser::CodebaseScanner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
                        let path_str = root_uri.trim_start_matches("file://");
                        self.root_path = Some(PathBuf::from(path_str));
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
                            let file_str = uri.trim_start_matches("file://");
                            let file_path = PathBuf::from(file_str);
                            let root = self
                                .root_path
                                .clone()
                                .unwrap_or_else(|| file_path.parent().unwrap_or(Path::new(".")).to_path_buf());
                            self.publish_diagnostics_for_workspace(&root)?;
                        }
                    }
                }
            }
            "textDocument/codeAction" => {
                let actions = vec![
                    json!({
                        "title": "Collapse tollbooth wrapper (deslop inline)",
                        "kind": "quickfix",
                        "isPreferred": true
                    }),
                    json!({
                        "title": "Extract shared types to leaf module (deslop deloop)",
                        "kind": "refactor.extract"
                    }),
                    json!({
                        "title": "Prune unreachable dead code (deslop prune)",
                        "kind": "source.organizeImports"
                    })
                ];
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

    fn publish_diagnostics_for_workspace(&self, root: &Path) -> anyhow::Result<()> {
        let scanner = CodebaseScanner::new();
        if let Ok(parsed) = scanner.scan_cached(root, true) {
            let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
            let findings = SlopDetectorEngine::analyze(&parsed.symbols, &parsed.edges, &graph);

            // Group findings by file path
            let mut file_diags: std::collections::HashMap<String, Vec<Value>> =
                std::collections::HashMap::new();

            for f in findings {
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

            for (uri, diags) in file_diags {
                self.send_notification("textDocument/publishDiagnostics", json!({
                    "uri": uri,
                    "diagnostics": diags
                }))?;
            }
        }

        Ok(())
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
