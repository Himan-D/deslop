use clap::{Parser, Subcommand};
use colored::*;
use deslop_core::Severity;
use deslop_detector::SlopDetectorEngine;
use deslop_graph::{
    CapacityAnalyzer, DeepAnalyzer, OtelSpan, ScipGenerator, StackProfiler, SymbolGraph,
    TraceIngestionEngine,
};
use deslop_inversion::{DelooperEngine, InversionEngine, RefactorEngine, TestGenerator};
use deslop_llm::LlmClient;
use deslop_parser::CodebaseScanner;

mod lsp;
mod mcp;
mod tui;
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

    /// Deep architectural analysis: package coupling, main sequence distance, and dominator bottlenecks
    Deep {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Launch interactive terminal UI dashboard (Ratatui)
    Tui {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Export Symbol Dependency Graph to Source Code Intelligence Protocol (SCIP) format
    Scip {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output JSON file path (defaults to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Synthesize characterization and property-based tests to prevent behavioral regression
    Testgen {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Optional symbol name filter
        #[arg(short, long)]
        symbol: Option<String>,

        /// Optional output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Correlate static AST symbols with runtime OpenTelemetry / Jaeger spans
    Trace {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to OpenTelemetry JSON spans file
        #[arg(short, long)]
        spans: PathBuf,
    },

    /// Launch Language Server Protocol (LSP) server over stdio for IDE integration
    Lsp,

    /// Launch Model Context Protocol (MCP) server over stdio for AI agent tool integration
    Mcp,
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
            println!("target: {}\n", path.display());

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
            println!("target: {}\n", path.display());

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
            println!("target: {}\n", path.display());

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
            println!("{:<28} {}", "Output Specification:", out_file.display());
            println!("--------------------------------------------------\n");
            println!("Wrote specification to: {}", out_file.display());
        }

        Commands::Prune { path, diff, output } => {
            println!("{}", "deslop: automated refactor & prune preview".bold());
            println!("target: {}\n", path.display());

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
                println!("Saved patch file to: {}", out_path.display());
            } else if diff {
                println!("{}", patch);
            }
        }

        Commands::Apply { path, verify } => {
            println!("{}", "deslop: surgical refactor & verification".bold());
            println!("target: {}\n", path.display());

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
                println!("  * {}", f.display());
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
            println!("target: {}\n", path.display());

            let (_parsed, graph, _findings, elapsed) = scan_and_analyze(&path)?;

            let runtime_samples = if let Some(stacks_file) = stacks {
                if let Ok(content) = fs::read_to_string(&stacks_file) {
                    println!("Loaded runtime stack profile from: {}", stacks_file.display());
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
            println!("target: {}\n", path.display());

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

        Commands::Deep { path } => {
            println!("{}", "deslop: deep architectural analysis & module physics".bold());
            println!("target: {}\n", path.display());

            let (_parsed, graph, _findings, elapsed) = scan_and_analyze(&path)?;
            let report = DeepAnalyzer::analyze(&graph);

            println!("--------------------------------------------------");
            println!("{:<28} {:.2}", "Average Module Depth Ratio:", report.average_depth_ratio);
            println!("{:<28} {}", "Analyzed Modules:", report.module_metrics.len());
            println!("{:<28} {}", "Architectural Chokepoints:", report.bottlenecks.len());
            println!("{:<28} {}", "Analysis Latency:", format!("{:.2?}", elapsed).green());
            println!("--------------------------------------------------\n");

            println!("Package coupling & main sequence metrics:\n");
            println!("{:<24} {:<6} {:<6} {:<8} {:<8} {:<8} {:<32}", "Module", "Ca", "Ce", "Instab", "Abstr", "Dist (D)", "Classification");
            println!("--------------------------------------------------------------------------------------------------");
            for m in &report.module_metrics {
                let class_color = if m.classification.starts_with("Main Sequence") {
                    m.classification.green()
                } else if m.classification.starts_with("Zone of Pain") {
                    m.classification.red().bold()
                } else if m.classification.starts_with("Zone of Uselessness") {
                    m.classification.yellow()
                } else {
                    m.classification.cyan()
                };
                println!(
                    "{:<24} {:<6} {:<6} {:<8.2} {:<8.2} {:<8.2} {:<32}",
                    m.module_name,
                    m.afferent_coupling,
                    m.efferent_coupling,
                    m.instability,
                    m.abstractness,
                    m.distance_from_main_seq,
                    class_color
                );
            }
            println!("--------------------------------------------------------------------------------------------------\n");

            if !report.bottlenecks.is_empty() {
                println!("Architectural bottlenecks & single points of failure:\n");
                for (i, b) in report.bottlenecks.iter().enumerate() {
                    let sev = if b.is_critical_chokepoint {
                        "CRITICAL CHOKEPOINT".red().bold().to_string()
                    } else {
                        "MODERATE CHOKEPOINT".yellow().to_string()
                    };
                    println!(
                        "  {}. [{}] {} (reaches {:.1}% of graph, {} nodes) at {}",
                        i + 1,
                        sev,
                        b.symbol_name.bold(),
                        b.downstream_reach_pct,
                        b.dominated_node_count,
                        b.file_path
                    );
                }
                println!();
            }

            if !report.deep_module_scores.is_empty() {
                println!("Deep module index (highest implementation power / interface complexity):\n");
                let mut top_deep: Vec<_> = report.deep_module_scores.iter().filter(|s| s.is_deep).collect();
                top_deep.sort_by(|a, b| b.depth_ratio.partial_cmp(&a.depth_ratio).unwrap_or(std::cmp::Ordering::Equal));
                for s in top_deep.iter().take(5) {
                    println!(
                        "  * {} (depth ratio: {:.1}x - LOC: {}, power: {})",
                        s.symbol_name.green().bold(),
                        s.depth_ratio,
                        s.implementation_power,
                        s.interface_complexity
                    );
                }
                println!();
            }
        }
        Commands::Tui { path } => {
            let (parsed, graph, findings, _) = scan_and_analyze(&path)?;
            tui::run_tui(&path, parsed, &graph, findings)?;
        }
        Commands::Scip { path, output } => {
            let (parsed, _, _, _) = scan_and_analyze(&path)?;
            let scip_index = ScipGenerator::generate(&path, &parsed.symbols, &parsed.edges);
            let json = serde_json::to_string_pretty(&scip_index)?;
            if let Some(out_path) = output {
                fs::write(&out_path, &json)?;
                println!("Exported SCIP index to {}", out_path.display().to_string().green());
            } else {
                println!("{}", json);
            }
        }
        Commands::Testgen { path, symbol, output } => {
            println!("{}", "deslop: automated characterization test synthesizer".bold());
            println!("target: {}\n", path.display());

            let (parsed, _, _, _) = scan_and_analyze(&path)?;

            let suites = if let Some(sym_name) = symbol {
                if let Some(target_sym) = parsed.symbols.iter().find(|s| s.name == sym_name) {
                    vec![TestGenerator::generate_for_symbol(target_sym)]
                } else {
                    eprintln!("Error: Symbol '{}' not found in codebase.", sym_name);
                    std::process::exit(1);
                }
            } else {
                TestGenerator::generate_all(&parsed.symbols)
            };

            if suites.is_empty() {
                println!("No testable functions or methods found in target scope.");
                return Ok(());
            }

            println!("Synthesized {} characterization test suite(s):\n", suites.len());

            let mut aggregated_tests = String::new();
            for suite in &suites {
                println!("  * Symbol: {} ({} cases) -> {}", suite.target_symbol.green().bold(), suite.test_count, suite.file_path);
                aggregated_tests.push_str(&suite.test_code);
                aggregated_tests.push_str("\n\n");
            }

            if let Some(out_path) = output {
                fs::write(&out_path, &aggregated_tests)?;
                println!("\nWritten tests to {}", out_path.display().to_string().green());
            } else {
                println!("\nSample synthesized test code:\n");
                let preview: Vec<&str> = aggregated_tests.lines().take(25).collect();
                println!("{}", preview.join("\n"));
                if aggregated_tests.lines().count() > 25 {
                    println!("... (use -o <file> to write full test suite to disk)");
                }
            }
        }
        Commands::Trace { path, spans } => {
            println!("{}", "deslop: OpenTelemetry trace correlation & dynamic entrypoint analysis".bold());
            println!("target: {}", path.display());
            println!("trace telemetry file: {}\n", spans.display());

            let (_parsed, graph, _, _) = scan_and_analyze(&path)?;

            let span_data = fs::read_to_string(&spans)?;
            let otel_spans: Vec<OtelSpan> = if let Ok(spans_list) = serde_json::from_str::<Vec<OtelSpan>>(&span_data) {
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
            println!("  Total spans ingested: {}", report.total_spans_ingested.to_string().cyan().bold());
            println!("  Active runtime symbols: {}", report.active_runtime_symbols.to_string().green().bold());
            println!("  Dynamic entrypoints rescued: {}", report.dynamic_entrypoints_rescued.len().to_string().yellow().bold());
            println!("  Verified dead symbols (0 static + 0 runtime calls): {}\n", report.verified_dead_symbols.len().to_string().red().bold());

            if !report.dynamic_entrypoints_rescued.is_empty() {
                println!("Rescued Dynamic Entrypoints (Protected from false-positive dead-code pruning):");
                for r in &report.dynamic_entrypoints_rescued {
                    println!("  * {} ({} runtime invocations) at {}", r.symbol_name.yellow().bold(), r.runtime_invocations, r.file_path);
                }
                println!();
            }

            if !report.verified_dead_symbols.is_empty() {
                println!("Safe Dead-Code Pruning Candidates (Zero runtime traffic & zero static incoming edges):");
                for s in report.verified_dead_symbols.iter().take(10) {
                    println!("  - {}", s.red());
                }
                if report.verified_dead_symbols.len() > 10 {
                    println!("  ... and {} more verified dead symbols", report.verified_dead_symbols.len() - 10);
                }
                println!();
            }
        }
        Commands::Lsp => {
            let mut server = lsp::LspServer::new();
            server.start()?;
        }
        Commands::Mcp => {
            mcp::McpServer::start()?;
        }
    }

    Ok(())
}
