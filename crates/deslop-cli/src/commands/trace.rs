use super::common::scan_and_analyze;
use colored::*;
use deslop_graph::{OtelSpan, TraceIngestionEngine};
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, spans: &PathBuf) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: OpenTelemetry trace correlation & dynamic entrypoint analysis".bold()
    );
    println!("target: {}", path.display());
    println!("trace telemetry file: {}\n", spans.display());

    let (_parsed, graph, _, _) = scan_and_analyze(path)?;

    let span_data = fs::read_to_string(spans)?;
    let otel_spans: Vec<OtelSpan> =
        if let Ok(spans_list) = serde_json::from_str::<Vec<OtelSpan>>(&span_data) {
            spans_list
        } else if let Ok(val) = serde_json::from_str::<serde_json::Value>(&span_data) {
            if let Some(arr) = val.get("spans").and_then(|v| v.as_array()) {
                serde_json::from_value(serde_json::Value::Array(arr.clone()))?
            } else {
                anyhow::bail!("Unrecognized OpenTelemetry JSON span format");
            }
        } else {
            anyhow::bail!("Invalid JSON in spans file: {}", spans.display());
        };

    let report = TraceIngestionEngine::correlate_traces(&graph, &otel_spans);

    println!("OpenTelemetry Telemetry Ingestion Results:");
    println!(
        "  Total spans ingested: {}",
        report.total_spans_ingested.to_string().cyan().bold()
    );
    println!(
        "  Active runtime symbols: {}",
        report.active_runtime_symbols.to_string().green().bold()
    );
    println!(
        "  Dynamic entrypoints rescued: {}",
        report
            .dynamic_entrypoints_rescued
            .len()
            .to_string()
            .yellow()
            .bold()
    );
    println!(
        "  Verified dead symbols (0 static + 0 runtime calls): {}\n",
        report.verified_dead_symbols.len().to_string().red().bold()
    );

    if !report.dynamic_entrypoints_rescued.is_empty() {
        println!("Rescued Dynamic Entrypoints (Protected from false-positive dead-code pruning):");
        for r in &report.dynamic_entrypoints_rescued {
            println!(
                "  * {} ({} runtime invocations) at {}",
                r.symbol_name.yellow().bold(),
                r.runtime_invocations,
                r.file_path
            );
        }
        println!();
    }

    if !report.verified_dead_symbols.is_empty() {
        println!("Safe Dead-Code Pruning Candidates (Zero runtime traffic & zero static incoming edges):");
        for s in report.verified_dead_symbols.iter().take(10) {
            println!("  - {}", s.red());
        }
        if report.verified_dead_symbols.len() > 10 {
            println!(
                "  ... and {} more verified dead symbols",
                report.verified_dead_symbols.len() - 10
            );
        }
        println!();
    }
    Ok(())
}
