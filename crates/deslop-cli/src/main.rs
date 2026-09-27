use clap::{Parser, Subcommand};
use colored::*;
use deslop_core::Severity;
use deslop_detector::SlopDetectorEngine;
use deslop_graph::{CapacityAnalyzer, StackProfiler, SymbolGraph};
use deslop_inversion::{DelooperEngine, InversionEngine, RefactorEngine};
use deslop_llm::LlmClient;
use deslop_parser::CodebaseScanner;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::{Path, PathBuf};
use tabled::{Table, Tabled};

#[derive(Parser)]
#[command(name = "deslop")]
#[command(about = "Codebase Inversion & Architectural De-slopping Engine in Rust", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a codebase and detect slop, ghost abstractions, and architectural debt
    Scan {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Print all detailed findings
        #[arg(short, long)]
        detailed: bool,
    },

    /// Analyze and resolve circular dependency loops using top-tier de-looping strategies
    Deloop {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Invert a codebase into a clean architectural specification & target blueprint
    Invert {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output markdown file path (defaults to ARCHITECTURE_SPEC.md)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Preview unified diff patches to prune dead code and collapse tollbooth wrappers
    Prune {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Print unified diff to stdout
        #[arg(long, default_value_t = true)]
        diff: bool,

        /// Write patch to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Surgically apply de-slopping refactors, dead code pruning, and tollbooth inlining with automatic rollback on test failure
    Apply {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Optional test verification command (e.g. 'cargo test', 'npm test')
        #[arg(short, long)]
        verify: Option<String>,
    },

    /// Analyze call stack depth, recursion risks, and ingest runtime flamegraph/folded stack profiles
    Profile {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Optional path to collapsed/folded stack profile file (from Linux perf, cargo-flamegraph, py-spy, etc.)
        #[arg(short, long)]
        stacks: Option<PathBuf>,
    },

    /// Predict maximum concurrent users, RPS throughput, and breaking points across hardware devices
    Capacity {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Export the symbol dependency graph to Mermaid or JSON
    Graph {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum number of nodes in graph
        #[arg(short, long, default_value_t = 30)]
        max_nodes: usize,

        /// Output format: mermaid or json
        #[arg(short, long, default_value = "mermaid")]
        format: String,
    },

    /// CI gate check: fails if codebase exceeds slop threshold or contains cycles
    Check {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum allowable slop index (0.0 to 100.0)
        #[arg(long, default_value_t = 25.0)]
        max_slop: f64,
    },
}

#[derive(Tabled)]
struct FindingRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Kind")]
    kind: String,
    #[tabled(rename = "Title")]
    title: String,
    #[tabled(rename = "File & Line")]
    location: String,
    #[tabled(rename = "Est. Saved")]
    saved: String,
}

fn create_spinner(msg: &'static str) -> ProgressBar {
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

fn scan_and_analyze(path: &Path) -> anyhow::Result<(deslop_parser::ParsedCodebase, SymbolGraph, Vec<deslop_core::SlopFinding>, std::time::Duration)> {
    let start_instant = std::time::Instant::now();
    let pb = create_spinner("Parsing ASTs concurrently across all CPU cores...");
    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(path)?;
    pb.finish_and_clear();

    let pb_graph = create_spinner("Building semantic dependency graph (O(1) lookups)...");
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
    pb_graph.finish_and_clear();

    let pb_detect = create_spinner("Executing anti-pattern & slop detector matrix...");
    let findings = SlopDetectorEngine::analyze(&parsed.symbols, &parsed.edges, &graph);
    pb_detect.finish_and_clear();

    let elapsed = start_instant.elapsed();
    Ok((parsed, graph, findings, elapsed))
}

fn print_llm_status() {
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, detailed } => {
            println!("{}", "deslop: codebase architectural scanner".bold());
            println!("target: {}\n", path.display().to_string());

            let (parsed, _graph, findings, elapsed) = scan_and_analyze(&path)?;

            let slop_score = SlopDetectorEngine::calculate_slop_index(
                parsed.stats.total_lines_of_code,
                &findings,
            );

            let score_colored = if slop_score < 15.0 {
                format!("{:.1} / 100 [clean]", slop_score).green().bold()
            } else if slop_score < 35.0 {
                format!("{:.1} / 100 [moderate debt]", slop_score).yellow().bold()
            } else {
                format!("{:.1} / 100 [high slop / over-engineered]", slop_score).red().bold()
            };

            let loc_per_sec = if elapsed.as_secs_f64() > 0.0 {
                (parsed.stats.total_lines_of_code as f64 / elapsed.as_secs_f64()) as usize
            } else {
                parsed.stats.total_lines_of_code * 1000
            };

            println!("--------------------------------------------------");
            println!("{:<28} {}", "Total Source Files:", parsed.stats.total_files);
            println!("{:<28} {}", "Lines of Code (LOC):", parsed.stats.total_lines_of_code);
            println!("{:<28} {}", "Parsed Symbols:", parsed.stats.total_symbols);
            println!("{:<28} {}", "Architectural Slop Index:", score_colored);
            let total_saved: usize = findings.iter().map(|f| f.estimated_lines_saved).sum();
            println!("{:<28} {}", "Prunable Bloat:", format!("~{} lines", total_saved).green());
            println!("{:<28} {} ({} LOC/s)", "Analysis Latency:", format!("{:.2?}", elapsed).green(), loc_per_sec);
            print_llm_status();
            println!("--------------------------------------------------\n");

            if findings.is_empty() {
                println!("{}", "No slop or architectural anti-patterns detected.".green());
                return Ok(());
            }

            println!("Findings: {}", findings.len());

            let rows: Vec<FindingRow> = findings
                .iter()
                .take(if detailed { findings.len() } else { 15 })
                .map(|f| {
                    let sev_str = match f.severity {
                        Severity::Critical => "CRITICAL".red().bold().to_string(),
                        Severity::High => "HIGH".red().to_string(),
                        Severity::Medium => "MEDIUM".yellow().to_string(),
                        Severity::Low => "LOW".cyan().to_string(),
                    };
                    let loc_str = format!("{}:{}", f.file_path.file_name().unwrap_or_default().to_string_lossy(), f.line);
                    let title_trunc = if f.title.len() > 48 {
                        format!("{}...", &f.title[..45])
                    } else {
                        f.title.clone()
                    };
                    FindingRow {
                        severity: sev_str,
                        kind: format!("{:?}", f.kind),
                        title: title_trunc,
                        location: loc_str,
                        saved: format!("~{} LOC", f.estimated_lines_saved),
                    }
                })
                .collect();

            let table = Table::new(rows).to_string();
            println!("{}\n", table);

            if !detailed && findings.len() > 15 {
                println!(
                    "Note: showing top 15 of {} findings. Use --detailed to view all.\n",
                    findings.len()
                );
            }

            println!(
                "Run 'deslop deloop' to inspect cycle breaking strategies."
            );
            println!(
                "Run 'deslop invert' to synthesize a de-slopped architectural specification.\n"
            );
        }

        Commands::Deloop { path } => {
            println!("{}", "deslop: principal de-looping & cycle breaker".bold());
            println!("target: {}\n", path.display().to_string());

            let (parsed, graph, _findings, elapsed) = scan_and_analyze(&path)?;
            let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);

            println!("{:<28} {}", "Analysis Latency:", format!("{:.2?}", elapsed).green());

            if plans.is_empty() {
                println!("{}", "Zero circular dependency loops detected. Architecture is an acyclic DAG.".green());
                return Ok(());
            }

            println!("Detected {} circular dependency loop(s):\n", plans.len());

            for (i, p) in plans.iter().enumerate() {
                println!("--------------------------------------------------");
                println!("{}: {}", format!("Loop {}", i + 1).bold(), p.cycle.join(" <-> ").red());
                println!("{:<24} {} -> {}", "Optimal Cut Edge:", p.cut_edge.0, p.cut_edge.1);
                println!("{:<24} {}", "Rationale:", p.architectural_rationale);
                println!("{}", "Actionable Steps:".bold());
                for (step_idx, step) in p.actionable_steps.iter().enumerate() {
                    println!("  {}. {}", step_idx + 1, step);
                }
                println!("--------------------------------------------------\n");
            }
        }

        Commands::Invert { path, output } => {
            println!("{}", "deslop: architecture inversion synthesizer".bold());
            println!("target: {}\n", path.display().to_string());

            let (parsed, graph, findings, _elapsed) = scan_and_analyze(&path)?;

            let codebase_name = path
                .canonicalize()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "Project".to_string());

            let inverted = InversionEngine::synthesize_spec(
                &codebase_name,
                &parsed.stats,
                &parsed.symbols,
                &parsed.edges,
                &graph,
                &findings,
            );

            let out_file = output.unwrap_or_else(|| PathBuf::from("ARCHITECTURE_SPEC.md"));
            fs::write(&out_file, &inverted.spec_markdown)?;

            println!("{}", "Architectural inversion successful.".green().bold());
            println!("--------------------------------------------------");
            println!("{:<28} {} LOC -> {} LOC ({})", "Transformation:", inverted.original_loc, inverted.projected_loc, format!("-{} LOC", inverted.lines_reduced_estimate).green());
            println!("{:<28} {}%", "Abstraction Reduction:", format!("-{:.1}", inverted.abstraction_reduction_pct).green());
            println!("{:<28} {}", "Resolved Cycles:", inverted.deloop_plans.len());
            println!("{:<28} {}", "Target Components:", inverted.target_components.len());
            print_llm_status();
            println!("{:<28} {}", "Output Specification:", out_file.display().to_string());
            println!("--------------------------------------------------\n");
            println!("Wrote specification to: {}", out_file.display().to_string());
        }

        Commands::Prune { path, diff, output } => {
            println!("{}", "deslop: automated refactor & prune preview".bold());
            println!("target: {}\n", path.display().to_string());

            let (_parsed, _graph, findings, _elapsed) = scan_and_analyze(&path)?;
            let prunable: Vec<_> = findings
                .iter()
                .filter(|f| matches!(f.kind, deslop_core::SlopKind::DeadOrphan | deslop_core::SlopKind::TollboothWrapper))
                .collect();

            if prunable.is_empty() {
                println!("{}", "No dead code or tollbooth wrappers to prune.".green());
                return Ok(());
            }

            let mut patch = String::new();
            patch.push_str("# Deslop Refactoring Patch\n");
            patch.push_str(&format!("# Target: {}\n", path.display()));
            patch.push_str(&format!("# Prunable Items: {}\n\n", prunable.len()));

            for p in &prunable {
                patch.push_str(&format!("--- a/{}\n", p.file_path.display()));
                patch.push_str(&format!("+++ b/{}\n", p.file_path.display()));
                patch.push_str(&format!("@@ -{},{} +{},0 @@ # Prune {}\n", p.line, p.estimated_lines_saved, p.line, p.title));
                patch.push_str(&format!("- // Deleted {} (~{} LOC)\n\n", p.title, p.estimated_lines_saved));
            }

            if let Some(out_path) = output {
                fs::write(&out_path, &patch)?;
                println!("Saved patch file to: {}", out_path.display().to_string());
            } else if diff {
                println!("{}", patch);
            }
        }

        Commands::Apply { path, verify } => {
            println!("{}", "deslop: surgical refactor & verification".bold());
            println!("target: {}\n", path.display().to_string());

            let (parsed, _graph, findings, _elapsed) = scan_and_analyze(&path)?;

            let pb = create_spinner("Executing surgical inlining and dead-code elimination...");
            let res = RefactorEngine::apply(&path, &findings, &parsed.symbols, verify.as_deref())?;
            pb.finish_and_clear();

            if !res.verified {
                eprintln!("{}", "error: verification failed, changes rolled back.".red().bold());
                if let Some(err) = res.error {
                    eprintln!("\n{}", err.red());
                }
                std::process::exit(1);
            }

            println!("{}", "Codebase refactoring applied successfully.".green().bold());
            println!("--------------------------------------------------");
            println!("{:<28} {}", "Files Modified:", res.files_modified.len());
            for f in &res.files_modified {
                println!("  * {}", f.display().to_string());
            }
            println!("{:<28} {}", "Items Pruned / Inlined:", res.items_pruned);
            println!("{:<28} {}", "Net Lines Deleted:", format!("-{} LOC", res.lines_deleted).green());
            if let Some(v_cmd) = verify {
                println!("{:<28} {}", "Verification Command:", format!("'{}' passed cleanly", v_cmd).green());
            }
            println!("--------------------------------------------------\n");
            println!("Refactoring complete with zero regressions.");
        }

        Commands::Profile { path, stacks } => {
            println!("{}", "deslop: call stack profiler & indirection analyzer".bold());
            println!("target: {}\n", path.display().to_string());

            let (_parsed, graph, _findings, elapsed) = scan_and_analyze(&path)?;

            let runtime_samples = if let Some(stacks_file) = stacks {
                if let Ok(content) = fs::read_to_string(&stacks_file) {
                    println!("Loaded runtime stack profile from: {}", stacks_file.display().to_string());
                    Some(StackProfiler::parse_folded_stacks(&content))
                } else {
                    eprintln!("{}", format!("warning: could not read stacks file: {}", stacks_file.display()).yellow());
                    None
                }
            } else {
                None
            };

            let report = StackProfiler::profile(&graph, runtime_samples.as_ref());

            println!("--------------------------------------------------");
            println!("{:<28} {} frames", "Max Call Stack Depth:", report.max_stack_depth);
            println!("{:<28} {} frames", "Avg Call Stack Depth:", report.average_stack_depth);
            if !report.recursive_symbols.is_empty() {
                println!("{:<28} {}", "Recursive Symbols:", report.recursive_symbols.join(", ").red());
            } else {
                println!("{:<28} {}", "Recursive Cycles:", "0 (safe from stack exhaustion)".green());
            }
            println!("{:<28} {}", "Profiler Latency:", format!("{:.2?}", elapsed).green());
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
                println!("Static symbols with 0 runtime stack executions: {}", report.runtime_cold_symbols.len());
                for sym in report.runtime_cold_symbols.iter().take(5) {
                    println!("  * {}", sym);
                }
                if report.runtime_cold_symbols.len() > 5 {
                    println!("  * ... and {} more unexercised symbols", report.runtime_cold_symbols.len() - 5);
                }
                println!();
            }
        }

        Commands::Capacity { path } => {
            println!("{}", "deslop: codebase capacity & failure point predictor".bold());
            println!("target: {}\n", path.display().to_string());

            let (_parsed, graph, _findings, elapsed) = scan_and_analyze(&path)?;

            let report = CapacityAnalyzer::analyze(&graph);

            println!("--------------------------------------------------");
            println!("{:<28} {}", "Scalability Grade:", report.scalability_grade.green());
            println!("{:<28} {}", "Complexity Class:", report.estimated_complexity_class);
            println!("{:<28} {}", "Detected Breaking Risks:", report.breaking_risks.len());
            println!("{:<28} {}", "Prediction Latency:", format!("{:.2?}", elapsed).green());
            println!("--------------------------------------------------\n");

            println!("Device concurrency limits:\n");
            println!("{:<36} {:<16} {:<14} {:<24}", "Hardware Device Profile", "Max Users (CCU)", "Throughput", "Primary Bottleneck");
            println!("-----------------------------------------------------------------------------------------");
            for est in &report.estimates {
                println!(
                    "{:<36} {:<16} {:<14} {:<24}",
                    est.device.name,
                    format!("~{} users", est.max_concurrent_users).green(),
                    format!("{} req/s", est.max_requests_per_sec),
                    est.bottleneck_resource
                );
            }
            println!("-----------------------------------------------------------------------------------------\n");

            if !report.breaking_risks.is_empty() {
                println!("Predicted failure points under load:\n");
                for (i, risk) in report.breaking_risks.iter().enumerate() {
                    println!("--------------------------------------------------");
                    println!("{}. {} ({})", i + 1, risk.trigger_pattern.bold().red(), risk.failure_mode.yellow());
                    println!("   {:<22} {}", "Location:", risk.file_location);
                    let sym_display = if risk.affected_symbol.len() > 70 {
                        format!("{}...", &risk.affected_symbol[..67])
                    } else {
                        risk.affected_symbol.clone()
                    };
                    println!("   {:<22} {}", "Symbol / Chain:", sym_display);
                    println!("   {:<22} {}", "Breaking Threshold:", risk.estimated_breaking_threshold.red());
                    println!("   {:<22} {}", "Remediation:", risk.recommendation);
                }
                println!("--------------------------------------------------\n");
            } else {
                println!("{}", "No critical saturation or unbounded memory breaking points detected.".green());
            }
        }

        Commands::Graph { path, max_nodes, format } => {
            let (parsed, graph, _findings, _elapsed) = scan_and_analyze(&path)?;

            if format == "json" {
                let serialized = serde_json::to_string_pretty(&parsed.edges)?;
                println!("{}", serialized);
            } else {
                let mermaid = graph.to_mermaid(max_nodes);
                println!("{}", mermaid);
            }
        }

        Commands::Check { path, max_slop } => {
            let (parsed, graph, findings, _elapsed) = scan_and_analyze(&path)?;
            let slop_score = SlopDetectorEngine::calculate_slop_index(
                parsed.stats.total_lines_of_code,
                &findings,
            );

            let has_cycles = !graph.find_circular_dependencies().is_empty();

            println!("Codebase Slop Index: {:.1} (Threshold: {:.1})", slop_score, max_slop);

            if slop_score > max_slop || has_cycles {
                eprintln!("{}", "error: ci gate failed: codebase exceeds allowable slop threshold or contains circular dependencies".red());
                std::process::exit(1);
            } else {
                println!("{}", "ci gate passed: codebase architectural health verified.".green());
            }
        }
    }

    Ok(())
}
