use super::common::scan_and_analyze;
use std::path::Path;

pub fn run(path: &Path, max_nodes: usize, format: &str) -> anyhow::Result<()> {
    let (parsed, graph, _findings, _elapsed) = scan_and_analyze(path)?;

    if format == "json" {
        let serialized = serde_json::to_string_pretty(&parsed.edges)?;
        println!("{}", serialized);
    } else {
        let mermaid = graph.to_mermaid(max_nodes);
        println!("{}", mermaid);
    }
    Ok(())
}
