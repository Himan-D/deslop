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
    Scan {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Print all detailed findings
        #[arg(short, long)]
        detailed: bool,

        /// Explain top findings with actionable narrative (LLM when a key is set, deterministic otherwise)
        #[arg(short, long)]
        explain: bool,
    },

    /// Analyze and resolve circular dependency loops using top-tier de-looping strategies
    Deloop {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Explain each loop with actionable narrative (LLM when a key is set, deterministic otherwise)
        #[arg(short, long)]
        explain: bool,
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

    /// Analyze git commit churn hotspots and hidden temporal coupling (CodeScene-style)
    Churn {
        /// Target directory path
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Number of git commits to analyze
        #[arg(short, long, default_value_t = 500)]
        commits: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            detailed,
            explain,
        } => commands::scan::run(&path, detailed, explain),
        Commands::Deloop { path, explain } => commands::deloop::run(&path, explain),
        Commands::Invert { path, output } => commands::invert::run(&path, output),
        Commands::Prune { path, diff, output } => commands::prune::run(&path, diff, output),
        Commands::Apply { path, verify } => commands::apply::run(&path, verify),
        Commands::Profile { path, stacks } => commands::profile::run(&path, stacks),
        Commands::Capacity { path } => commands::capacity::run(&path),
        Commands::Graph {
            path,
            max_nodes,
            format,
        } => commands::graph::run(&path, max_nodes, &format),
        Commands::Check { path, max_slop } => commands::check::run(&path, max_slop),
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
        Commands::Churn { path, commits } => commands::churn::run(&path, commits),
    }
}
