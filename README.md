<div align="center">

<img src="assets/logo.png" width="96" alt="Deslop logo" />

# Deslop

**Deterministic CI & MCP architectural and security gate for AI-era codebases.**

[![Release](https://img.shields.io/github/v/release/Himan-D/deslop?color=f97316)](https://github.com/Himan-D/deslop/releases)
[![CI](https://github.com/Himan-D/deslop/actions/workflows/deslop.yml/badge.svg?branch=main)](https://github.com/Himan-D/deslop/actions/workflows/deslop.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](Cargo.toml)
[![Wiki](https://img.shields.io/badge/docs-wiki-0f172a.svg)](https://github.com/Himan-D/deslop/wiki)

</div>

> Built in **Rust** (`syn` + `tree-sitter`). Catches dependency cycles, architectural layer violations, shallow wrappers, dead code, hardcoded secrets, and injection sinks—locally in milliseconds or in GitHub Actions with SARIF 2.1.0.

---

## 30-Second Quick Start

### Install

**Homebrew**
```bash
brew install Himan-D/tap/deslop
# or from this repo:
brew install --build-from-source ./Formula/deslop.rb
```

**Cargo**
```bash
cargo install deslop-cli
# or directly from GitHub:
cargo install --git https://github.com/Himan-D/deslop deslop-cli
```

### Run in CI (GitHub Action)

Gate pull requests on new dependency cycles or High/Critical findings and upload SARIF 2.1.0 results to GitHub Code Scanning:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # --base needs the base ref's history

- uses: Himan-D/deslop@v1
  with:
    base: origin/main
    sarif: deslop.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: deslop.sarif
```

`--base` checks out the ref with `git archive` into a temp directory and matches findings by kind, relative path, and title. Line numbers are ignored, so edits elsewhere in a file do not make old findings look new.

### Connect via MCP (Claude Code, Cursor, Codex)

Deslop implements a native **Model Context Protocol (2024-11-05)** server over `stdio`:

```bash
deslop mcp
```

Add to **Claude Desktop / Claude Code** (`~/.claude/claude_desktop_config.json` or `claude.json`), **Cursor** (`~/.cursor/mcp.json` or `.cursor/mcp.json`), or **Codex**:

```json
{
  "mcpServers": {
    "deslop": {
      "command": "deslop",
      "args": ["mcp"]
    }
  }
}
```

### Core CLI Workflow

```bash
# Scan a codebase (human-readable, JSON, or SARIF 2.1.0)
deslop scan ./path/to/codebase
deslop scan ./path/to/codebase --format json
deslop scan ./path/to/codebase --format sarif

# Report only findings introduced by this branch relative to a git ref
deslop scan ./path/to/codebase --base origin/main

# Pull-request quality gate (fail on new cycles or High/Critical findings)
deslop check ./path/to/codebase --base origin/main
deslop check ./path/to/codebase --max-slop 25

# De-loop circular dependencies with actionable refactor plans
deslop deloop ./path/to/codebase

# Invert codebase into a formal specification with Mermaid diagrams
deslop invert ./path/to/codebase -o ARCHITECTURE_SPEC.md

# Preview unified diff patches to prune dead code and tollbooths
deslop prune ./path/to/codebase

# Surgically apply refactors with automatic rollback if verification fails
deslop apply ./path/to/codebase --verify "cargo test"
```

---

## What Top Engineers Do for De-Looping (The Core Philosophy)

When principal systems architects untangle complex systems, they do **not** apply Band-Aids (like lazy circular imports or adding more wrapper classes). They apply four foundational de-looping laws:

1. **Strict Monotonic Layering (DAG Enforcement)**:
   - Systems must form a Directed Acyclic Graph. Cycles are broken by identifying the **Feedback Arc Set (FAS)**—the weakest link in the loop with lowest call volume and least semantic weight.
2. **The Leaf Pattern (Seam Extraction)**:
   - When `A` and `B` import each other, mutual recursion is eliminated by extracting their shared data transfer models, schemas, and types into an independent leaf module `C`. Both `A` and `B` depend downward on `C`, eliminating horizontal and circular coupling.
3. **Dependency Inversion via Injected Interfaces / Callbacks**:
   - Upward circular calls are converted into listener callbacks or injected traits (`A` provides an implementation of `ITargetDelegate` to `B` at initialization, rather than `B` importing `A`).
4. **Deep Module Collapse**:
   - Shallow 1:1 interfaces ("ghost abstractions") and single-statement pass-through functions ("tollbooth wrappers") add pure cognitive friction with zero polymorphism. They are collapsed directly into concrete deep modules.

---

## Declarative Architectural Fitness Rules (`deslop.toml`)

Place a `deslop.toml` in the root of any codebase to enforce custom layer hierarchies and forbidden cross-module dependencies. Deslop automatically loads this file during `scan`, `check`, and all MCP tool calls.

```toml
# deslop.toml — Architectural Fitness Rules (ArchUnit-style)

# Strict layer ordering: each layer may only depend downward.
# Violations of monotonic order are flagged as LayerViolation (Critical).
layers = ["controller", "service", "repo"]

# Explicit forbidden cross-module calls, regardless of layer position.
[[forbidden_rules]]
from = "repo"
to   = "controller"
description = "Repository layer cannot import or call the controller layer."

[[forbidden_rules]]
from = "service"
to   = "controller"
description = "Service layer cannot import or call the controller layer."
```

When a violation is detected, `deslop scan` prints a `Critical` finding:
```
[Critical] LayerViolation: repo::fetch -> controller::handle
  repo layer depends on controller layer, violating strict monotonic layer ordering.
```

---

## Scoring, Confidence, and Limits

The Slop Index is a heuristic, not a measurement of quality. It is a weighted count of findings per 1,000 lines of code (Low 1.5, Medium 4, High 8, Critical 15), capped at 100.

- **Small projects are low-confidence.** The denominator is floored at 1,000 LOC, so a few findings in a tiny project cannot saturate the score. `scan` marks the score as low confidence below that size, and JSON output reports `score_reliable: false`.
- **Cycles are graded by reach.** A loop inside one file is Medium. A loop across two files is High. A loop across three or more files is Critical. Loops that pass through names shared by several symbols are downgraded to Low with a "verify first" note, because the graph resolves calls by bare name and can merge unrelated functions (`new`, `default`).
- **Dead code is conservative.** A symbol is reported dead only if its name never appears outside its own definition anywhere in the codebase. Library public API, test code, benchmarks, Go `init()`, and fixtures are never reported. This avoids false positives at the cost of recall.
- **Public facades and constructors are not tollbooths.** Public functions and `new`/`default`/`from`/`with_*` style constructors are intentional API surface.
- **Clones are Medium.** Duplicate logic is real but usually low-value compared with cycles and dead code. Trait impls are skipped, since they repeat by contract.
- **Measured on open-source repos:** see [`docs/CALIBRATION.md`](docs/CALIBRATION.md) for before/after numbers and the spot-check results.

### Acting on Findings

- `deslop prune` writes real unified diffs. It only deletes symbols that no other file references. Apply the patch with `git apply`.
- `deslop apply --verify "<cmd>"` writes the same changes and rolls every touched file back if the command fails. Without `--verify` or `--yes` it previews (writes nothing, exits 2). Use `--yes` to write without verification (explicit opt-in, no rollback net).
- A symbol referenced from another file is reported as skipped, not rewritten. Automatic cross-file rewriting is not implemented.
- `deslop deloop` is advisory. It names the cut edge and steps; it does not move code. Breaking a cycle usually requires type-aware moves that the text rewriter cannot do safely.

---

## Model Context Protocol (MCP) Tools

`deslop mcp` exposes the following tools over `stdio`:

1. `deslop_scan`: Computes the Slop Index (0-100), LOC, symbols, and lists top debt findings.
2. `deslop_deloop`: Discovers cycles and outputs the Feedback Arc Set (FAS) cut edge and actionable steps.
3. `deslop_deep`: Computes Robert C. Martin's Package Coupling ($C_a, C_e, I, A, D$), Zone of Pain, and dominator bottlenecks.
4. `deslop_capacity`: Heuristic concurrent-user and RPS ceilings per device (static estimate, not a load test).
5. `deslop_testgen`: Synthesizes compiling characterization tests with real invocations and determinism checks.
6. `deslop_prune_diff`: Generates a unified diff patch preview showing dead code to delete and tollbooths to collapse.
7. `deslop_scip`: Exports the complete symbol dependency graph in standard SCIP JSON format.
8. `deslop_churn`: Analyzes git commit history to detect churn hotspots and hidden temporal coupling (files that co-change with 0 static imports).
9. `deslop_check`: Runs the architectural quality gate (cycles, layer violations, High/Critical findings, and Slop Index threshold). Accepts `path` (target directory), `base` (optional git ref to diff new findings against), and `max_slop` (optional maximum allowed Slop Index).

See [`docs/AGENT_SETUP.md`](docs/AGENT_SETUP.md) for copy-paste setup snippets for Claude Code, Cursor, Codex, Gemini CLI / Antigravity, `AGENTS.md`/`CLAUDE.md` rules, and pre-commit hooks.

---

## Bring Your Own Key (BYOK) AI Synthesis

Deslop computes **100% of graph metrics, AST parsing, and cycle paths locally in Rust at zero token cost**.

Deslop calls an LLM **only when you opt in**: `scan --explain`, `deloop --explain`, or `invert --llm`, and only if a provider key is set in the environment. The opted-in command prints which provider receives data (finding text, or a codebase summary for `invert`). Keys are read from:

```bash
export GEMINI_API_KEY="your-gemini-key"
# or
export OPENAI_API_KEY="your-openai-key"
# or
export ANTHROPIC_API_KEY="your-anthropic-key"
# or
export OPENROUTER_API_KEY="your-openrouter-key"
```

Without the flag, or without a key, Deslop runs fully offline with zero external network calls.

---

## Full Command Reference & Secondary Subcommands

<details>
<summary>Expand all subcommands (<code>deep</code>, <code>profile</code>, <code>churn</code>, <code>lsp</code>, <code>capacity</code>, <code>scip</code>, <code>tui</code>, <code>trace</code>, <code>testgen</code>)</summary>

```bash
# Deep architectural analysis: package coupling, main sequence distance, and dominator bottlenecks
deslop deep ./path/to/codebase

# Call stack depth profiling, recursion risk analysis, and Stack Tax calculation
deslop profile ./path/to/codebase

# Correlate static AST symbols with runtime CPU flamegraph profiles (perf, cargo-flamegraph, pprof)
deslop profile ./path/to/codebase --stacks ./profile.folded

# Analyze git churn hotspots and hidden temporal coupling (CodeScene-style)
deslop churn ./path/to/codebase --commits 500

# Launch Language Server Protocol (LSP) daemon for VS Code, Neovim, and Helix
deslop lsp

# Rough capacity ceilings per device (static heuristic, not a load test)
deslop capacity ./path/to/codebase

# Export symbol dependency graph to Source Code Intelligence Protocol (SCIP)
deslop scip ./path/to/codebase -o index.scip.json

# Launch interactive terminal UI dashboard (Ratatui)
deslop tui ./path/to/codebase

# Ingest runtime OpenTelemetry traces to protect dynamic entrypoints from false-positive pruning
deslop trace ./path/to/codebase --spans ./spans.json

# Synthesize compiling characterization tests (real invocations + determinism checks; #[ignore] + TODOs where a fixture needs you)
deslop testgen ./path/to/codebase -o tests_invariants.rs

# Explain top findings / LLM-assisted narrative (only sends data when opted in + key set)
deslop scan ./path/to/codebase --explain
deslop invert ./path/to/codebase -o ARCHITECTURE_SPEC.md --llm
```

</details>

---

## Workspace Architecture

```
deslop/
├── Cargo.toml
├── Dockerfile                  # Multi-stage optimized release container
├── docker-compose.yml          # Containerized runner with API key pass-through
├── crates/
│   ├── deslop-core             # Symbol, Edge, Span, SlopFinding data models
│   ├── deslop-parser           # Rust syn AST + Universal multi-language lexer (TS/JS/Py/Go)
│   ├── deslop-graph            # petgraph Symbol Dependency Graph (SDG), Tarjan SCC cycles
│   ├── deslop-detector         # Anti-pattern matrix (tollbooths, ghost traits, clones, orphans)
│   ├── deslop-llm              # Bring-Your-Own-Key (Gemini / OpenAI / Anthropic / OpenRouter / Offline)
│   ├── deslop-inversion        # DelooperEngine (cycle breaker) & InversionEngine (spec synthesizer)
│   └── deslop-cli              # Complete CLI binary (`deslop`)
└── tests/
    └── fixtures/sloppy_app/    # Intentional cycles, ghost abstractions, tollbooths, and clones
```

## Running with Docker

Run Deslop securely in an isolated sandbox without installing Rust on the host:

```bash
# Build the Docker image
docker build -t deslop:latest .

# Run scan on your current repository
docker run --rm -v $(pwd):/workspace deslop:latest scan /workspace

# Run de-looping
docker run --rm -v $(pwd):/workspace deslop:latest deloop /workspace

# Invert with your API key passed securely
docker run --rm -v $(pwd):/workspace \
  -e GEMINI_API_KEY=$GEMINI_API_KEY \
  deslop:latest invert /workspace -o /workspace/ARCHITECTURE_SPEC.md
```

Using `docker-compose`:
```bash
docker compose run --rm deslop invert /workspace
```

## Testing

```bash
cargo test
```
