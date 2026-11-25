use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod lsp;
mod mcp;
mod tui;

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
    #[command(next_help_heading = "Core Workflow")]
    Scan {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Print all detailed findings
        #[arg(short, long)]
        detailed: bool,

        /// Explain top findings. Uses an LLM only if a provider key is set, and then sends finding text to that provider
        #[arg(short, long)]
        explain: bool,

        /// Output format: table, json, or sarif (for GitHub code scanning)
        #[arg(long, default_value = "table")]
        format: String,
        /// Report only findings introduced since this git ref (e.g. origin/main)
        #[arg(long, value_name = "REF")]
        base: Option<String>,

        /// Rank top files by git churn × slop severity weight
        #[arg(long)]
        hotspots: bool,
    },

    /// CI gate. Without --base: fails on slop above --max-slop or any cycle.
    /// With --base REF: fails only on cycles or High/Critical findings this change adds.
    Check {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum allowable slop index (0.0 to 100.0); defaults to 25 without --base
        #[arg(long)]
        max_slop: Option<f64>,
        /// Gate only on findings introduced since this git ref (e.g. origin/main)
        #[arg(long, value_name = "REF")]
        base: Option<String>,
    },

    /// Analyze and resolve circular dependency loops using top-tier de-looping strategies
    Deloop {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Explain each loop. Uses an LLM only if a provider key is set, and then sends loop text to that provider
        #[arg(short, long)]
        explain: bool,

        /// Output format: table or json
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Surgically apply de-slopping refactors, dead code pruning, and tollbooth inlining with automatic rollback on test failure
    Apply {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Optional test verification command (e.g. 'cargo test', 'npm test')
        #[arg(short, long)]
        verify: Option<String>,

        /// Write changes without a verification command (without --verify or --yes, prints a preview and writes nothing)
        #[arg(long)]
        yes: bool,
    },

    /// Launch Model Context Protocol (MCP) server over stdio for AI agent tool integration
    Mcp,

    /// Return the single highest-priority finding to fix next (ranked by severity, security, and git churn)
    Next {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: table or json
        #[arg(long, default_value = "table")]
        format: String,

        /// Number of top priority items to return
        #[arg(short = 'n', long, default_value_t = 1)]
        count: usize,
    },

    /// Print or write MCP + AGENTS.md setup for coding agents (claude, cursor, codex, gemini, all)
    Setup {
        /// Target agent: claude, cursor, codex, gemini, or all
        agent: String,

        /// Project directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Write project-local .mcp.json / .cursor/mcp.json (dry-run by default)
        #[arg(long)]
        write: bool,
    },

    /// Invert a codebase into a clean architectural specification & target blueprint
    #[command(next_help_heading = "Advanced & Experimental")]
    Invert {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output markdown file path (defaults to ARCHITECTURE_SPEC.md)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Send a codebase summary to the configured LLM for narrative synthesis
        #[arg(long)]
        llm: bool,
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

    /// Deep architectural analysis: package coupling, main sequence distance, and dominator bottlenecks
    Deep {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Analyze git commit churn hotspots and hidden temporal coupling (CodeScene-style)
    Churn {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Number of git commits to analyze
        #[arg(short, long, default_value_t = 500)]
        commits: usize,
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

    /// Estimate rough concurrent-user and throughput ceilings per device (static heuristic, not a load test)
    Capacity {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,
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

    /// Export Symbol Dependency Graph to Source Code Intelligence Protocol (SCIP) format
    Scip {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output JSON file path (defaults to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Launch Language Server Protocol (LSP) server over stdio for IDE integration
    Lsp,

    /// Launch interactive terminal UI dashboard (Ratatui)
    Tui {
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            detailed,
            explain,
            format,
            base,
            hotspots,
        } => commands::scan::run(&path, detailed, explain, &format, base.as_deref(), hotspots),
        Commands::Deloop {
            path,
            explain,
            format,
        } => commands::deloop::run(&path, explain, &format),
        Commands::Invert { path, output, llm } => commands::invert::run(&path, output, llm),
        Commands::Prune { path, diff, output } => commands::prune::run(&path, diff, output),
        Commands::Apply { path, verify, yes } => commands::apply::run(&path, verify, yes),
        Commands::Profile { path, stacks } => commands::profile::run(&path, stacks),
        Commands::Capacity { path } => commands::capacity::run(&path),
        Commands::Graph {
            path,
            max_nodes,
            format,
        } => commands::graph::run(&path, max_nodes, &format),
        Commands::Check {
            path,
            max_slop,
            base,
        } => commands::check::run(&path, max_slop, base.as_deref()),
        Commands::Deep { path } => commands::deep::run(&path),
        Commands::Tui { path } => commands::tui_cmd::run(&path),
        Commands::Scip { path, output } => commands::scip::run(&path, output),
        Commands::Testgen {
            path,
            symbol,
            output,
        } => commands::testgen::run(&path, symbol, output),
        Commands::Trace { path, spans } => commands::trace::run(&path, &spans),
        Commands::Lsp => commands::lsp_cmd::run(),
        Commands::Mcp => commands::mcp_cmd::run(),
        Commands::Next {
            path,
            format,
            count,
        } => commands::next::run(&path, &format, count),
        Commands::Setup { agent, path, write } => commands::setup::run(&agent, &path, write),
        Commands::Churn { path, commits } => commands::churn::run(&path, commits),
    }
}
