use super::common::scan_and_analyze;
use colored::*;
use deslop_inversion::DelooperEngine;
use deslop_llm::LlmClient;
use std::path::Path;

pub fn run(path: &Path, explain: bool) -> anyhow::Result<()> {
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
