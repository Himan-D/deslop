use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app")
}

#[test]
fn mcp_lists_check_and_scan_and_gates_sloppy_app() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_deslop"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("deslop mcp spawns");

    let fixture = fixture_dir();
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "deslop_check",
                "arguments": {
                    "path": fixture.to_string_lossy()
                }
            }
        }),
    ];

    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        for req in &requests {
            writeln!(stdin, "{}", serde_json::to_string(req).unwrap()).unwrap();
        }
    }

    let output = child.wait_with_output().expect("wait for deslop mcp");
    assert!(
        output.status.success(),
        "deslop mcp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let responses: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON-RPC response line"))
        .collect();
    assert_eq!(responses.len(), 3, "expected 3 JSON-RPC responses, got {stdout}");

    // 1. initialize
    assert_eq!(responses[0]["id"], 1);
    assert!(responses[0]["result"]["serverInfo"]["name"] == "deslop-mcp");

    // 2. tools/list
    assert_eq!(responses[1]["id"], 2);
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"deslop_check"), "missing deslop_check: {names:?}");
    assert!(names.contains(&"deslop_scan"), "missing deslop_scan: {names:?}");

    // 3. tools/call deslop_check
    assert_eq!(responses[2]["id"], 3);
    assert!(
        responses[2]["result"]["isError"].is_null(),
        "unexpected tool error: {}",
        responses[2]
    );
    let text = responses[2]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let report: Value = serde_json::from_str(text).expect("compact JSON report");
    assert_eq!(report["passed"], false);
    assert!(report["slop_index"].is_number());
    assert!(report["score_reliable"].is_boolean());
    assert!(report["blocking_findings"].is_array());
    assert!(
        !report["blocking_findings"].as_array().unwrap().is_empty(),
        "expected blocking findings for sloppy_app cycle"
    );
    assert!(report["summary"].is_string());
}
