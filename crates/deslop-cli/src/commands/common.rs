use colored::*;
use deslop_detector::SlopDetectorEngine;
use deslop_graph::SymbolGraph;
use deslop_llm::LlmClient;
use deslop_parser::CodebaseScanner;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use tabled::Tabled;

#[derive(Tabled)]
pub struct FindingRow {
    #[tabled(rename = "Severity")]
    pub severity: String,
    #[tabled(rename = "Kind")]
    pub kind: String,
    #[tabled(rename = "Title")]
    pub title: String,
    #[tabled(rename = "File & Line")]
    pub location: String,
    #[tabled(rename = "Est. Saved")]
    pub saved: String,
}

pub fn create_spinner(msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg);
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

pub fn scan_and_analyze(
    path: &Path,
) -> anyhow::Result<(
    deslop_parser::ParsedCodebase,
    SymbolGraph,
    Vec<deslop_core::SlopFinding>,
    std::time::Duration,
)> {
    let start_instant = std::time::Instant::now();
    let pb = create_spinner("Parsing ASTs concurrently across all CPU cores...");
    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(path)?;
    pb.finish_and_clear();

    let pb_graph = create_spinner("Building semantic dependency graph (O(1) lookups)...");
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
    pb_graph.finish_and_clear();

    let arch_config = deslop_core::ArchitectureConfig::load_from_dir(path);

    let pb_detect = create_spinner("Executing anti-pattern & slop detector matrix...");
    let findings = SlopDetectorEngine::analyze_with_config(
        &parsed.symbols,
        &parsed.edges,
        &graph,
        arch_config.as_ref(),
    );
    pb_detect.finish_and_clear();

    let elapsed = start_instant.elapsed();
    Ok((parsed, graph, findings, elapsed))
}

pub fn print_llm_status() {
    let llm = LlmClient::auto_detect();
    let status_str = match llm.provider {
        deslop_llm::LlmProvider::Gemini => "Gemini API (active)".green().bold(),
        deslop_llm::LlmProvider::OpenAI => "OpenAI API (active)".green().bold(),
        deslop_llm::LlmProvider::Anthropic => "Anthropic API (active)".green().bold(),
        deslop_llm::LlmProvider::OpenRouter => "OpenRouter API (active)".green().bold(),
        deslop_llm::LlmProvider::Offline => "Offline Deterministic Mode (no API key)".yellow(),
    };
    println!("{:<28} {}", "AI Reasoning Engine:".bold(), status_str);
}
