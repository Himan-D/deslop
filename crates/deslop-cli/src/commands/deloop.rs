use super::common::scan_and_analyze;
use colored::*;
use deslop_inversion::{DeloopPlan, DelooperEngine};
use deslop_llm::LlmClient;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct DeloopReport {
    target: String,
    loop_count: usize,
    plans: Vec<DeloopPlan>,
    verification_command: &'static str,
}

pub fn run(path: &Path, explain: bool, format: &str) -> anyhow::Result<()> {
    if !matches!(format, "table" | "json") {
        anyhow::bail!("unknown --format '{}': expected table or json", format);
    }

    if format == "json" {
        let (parsed, graph, _findings, _elapsed) = scan_and_analyze(path)?;
        let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);
        let report = DeloopReport {
            target: path.display().to_string(),
            loop_count: plans.len(),
            plans,
            verification_command: "deslop check .",
        };
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }

    println!("{}", "deslop: principal de-looping & cycle breaker".bold());
    println!("target: {}\n", path.display());

    let (parsed, graph, _findings, elapsed) = scan_and_analyze(path)?;
    let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);

    println!(
        "{:<28} {}",
        "Analysis Latency:",
        format!("{:.2?}", elapsed).green()
    );

    if plans.is_empty() {
        println!(
            "{}",
            "Zero circular dependency loops detected. Architecture is an acyclic DAG.".green()
        );
        return Ok(());
    }

    println!("Detected {} circular dependency loop(s):\n", plans.len());

    for (i, p) in plans.iter().enumerate() {
        println!("--------------------------------------------------");
        println!(
            "{}: {}",
            format!("Loop {}", i + 1).bold(),
            p.cycle.join(" <-> ").red()
        );
        println!(
            "{:<24} {} -> {}",
            "Optimal Cut Edge:", p.cut_edge.0, p.cut_edge.1
        );
        println!("{:<24} {}", "Rationale:", p.architectural_rationale);
        println!("{}", "Actionable Steps:".bold());
        for (step_idx, step) in p.actionable_steps.iter().enumerate() {
            println!("  {}. {}", step_idx + 1, step);
        }
        println!("--------------------------------------------------\n");
    }

    if explain {
        let llm = LlmClient::auto_detect();
        println!("Loop explanations:\n");
        for (i, p) in plans.iter().enumerate() {
            println!("--- Loop {} ---", i + 1);
            println!(
                "{}\n",
                llm.explain(
                    &format!("Circular dependency: {}", p.cycle.join(" -> ")),
                    &p.architectural_rationale,
                    &p.actionable_steps.join("; "),
                )
            );
        }
    }

    Ok(())
}
