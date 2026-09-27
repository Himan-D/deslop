use super::common::scan_and_analyze;
use colored::*;
use deslop_graph::StackProfiler;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, stacks: Option<PathBuf>) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: call stack profiler & indirection analyzer".bold()
    );
    println!("target: {}\n", path.display());

    let (_parsed, graph, _findings, elapsed) = scan_and_analyze(path)?;

    let runtime_samples = if let Some(stacks_file) = stacks {
        if let Ok(content) = fs::read_to_string(&stacks_file) {
            println!(
                "Loaded runtime stack profile from: {}",
                stacks_file.display()
            );
            Some(StackProfiler::parse_folded_stacks(&content))
        } else {
            eprintln!(
                "{}",
                format!(
                    "warning: could not read stacks file: {}",
                    stacks_file.display()
                )
                .yellow()
            );
            None
        }
    } else {
        None
    };

    let report = StackProfiler::profile(&graph, runtime_samples.as_ref());

    println!("--------------------------------------------------");
    println!(
        "{:<28} {} frames",
        "Max Call Stack Depth:", report.max_stack_depth
    );
    println!(
        "{:<28} {} frames",
        "Avg Call Stack Depth:", report.average_stack_depth
    );
    if !report.recursive_symbols.is_empty() {
        println!(
            "{:<28} {}",
            "Recursive Symbols:",
            report.recursive_symbols.join(", ").red()
        );
    } else {
        println!(
            "{:<28} {}",
            "Recursive Cycles:",
            "0 (safe from stack exhaustion)".green()
        );
    }
    println!(
        "{:<28} {}",
        "Profiler Latency:",
        format!("{:.2?}", elapsed).green()
    );
    println!("--------------------------------------------------\n");

    if !report.deepest_call_paths.is_empty() {
        println!("Deepest call stacks:\n");
        for (i, p) in report.deepest_call_paths.iter().enumerate() {
            let tax_color = if p.stack_tax_pct > 30.0 {
                format!("{:.1}%", p.stack_tax_pct).red().bold()
            } else {
                format!("{:.1}%", p.stack_tax_pct).green()
            };
            let frame_str = p.frames.join(" -> ");
            let frame_display = if frame_str.len() > 80 {
                format!("{}...", &frame_str[..77])
            } else {
                frame_str
            };
            println!(
                "  {}. {} (depth: {}, stack tax: {} wrappers)",
                i + 1,
                frame_display,
                p.depth,
                tax_color
            );
        }
        println!();
    }

    if !report.runtime_hotspots.is_empty() {
        println!("Runtime CPU / sampling hotspots:\n");
        for (frame, count) in report.runtime_hotspots.iter().take(8) {
            println!("  * {:<35} {} samples", frame, count);
        }
        println!();
    }

    if !report.runtime_cold_symbols.is_empty() {
        println!(
            "Static symbols with 0 runtime stack executions: {}",
            report.runtime_cold_symbols.len()
        );
        for sym in report.runtime_cold_symbols.iter().take(5) {
            println!("  * {}", sym);
        }
        if report.runtime_cold_symbols.len() > 5 {
            println!(
                "  * ... and {} more unexercised symbols",
                report.runtime_cold_symbols.len() - 5
            );
        }
        println!();
    }
    Ok(())
}
