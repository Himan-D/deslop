# Deslop: Codebase Inversion & Architectural De-Slopping Engine

> A high-performance, deterministic codebase inversion and de-slopping platform written in **Rust**. Inverts bloated, tangled spaghetti and AI-generated slop into clean, verified architectural specifications, resolving circular dependency loops with principal-level engineering strategies.

---

## What Top Engineers Do for De-Looping (The Core Philosophy)

When principal systems architects untangle complex systems, they do **not** apply Band-Aids (like lazy circular imports or adding more wrapper classes). They apply three foundational de-looping laws:

1. **Strict Monotonic Layering (DAG Enforcement)**:
   - Systems must form a Directed Acyclic Graph. Cycles are broken by identifying the **Feedback Arc Set (FAS)**—the weakest link in the loop with lowest call volume and least semantic weight.
2. **The Leaf Pattern (Seam Extraction)**:
   - When `A` and `B` import each other, mutual recursion is eliminated by extracting their shared data transfer models, schemas, and types into an independent leaf module `C`. Both `A` and `B` depend downward on `C`, eliminating horizontal and circular coupling.
3. **Dependency Inversion via Injected Interfaces / Callbacks**:
   - Upward circular calls are converted into listener callbacks or injected traits (`A` provides an implementation of `ITargetDelegate` to `B` at initialization, rather than `B` importing `A`).
4. **Deep Module Collapse**:
   - Shallow 1:1 interfaces ("ghost abstractions") and single-statement pass-through functions ("tollbooth wrappers") add pure cognitive friction with zero polymorphism. They are collapsed directly into concrete deep modules.

---

## Workspace Architecture

```
/Users/himand/deslop/
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

---

## Quick Start

### 1. Build & Run Locally
```bash
# Build the workspace
cargo build --release

# Run a scan on any codebase
target/release/deslop scan ./path/to/codebase

# De-loop circular dependencies with actionable refactor plans
target/release/deslop deloop ./path/to/codebase

# Invert codebase into a formal specification with Mermaid diagrams
target/release/deslop invert ./path/to/codebase -o ARCHITECTURE_SPEC.md

# Call stack depth profiling, recursion risk analysis, and Stack Tax calculation
target/release/deslop profile ./path/to/codebase

# Correlate static AST symbols with runtime CPU flamegraph profiles (perf, cargo-flamegraph, pprof)
target/release/deslop profile ./path/to/codebase --stacks ./profile.folded

# Predict maximum concurrent users, RPS throughput, and breaking points across hardware devices
target/release/deslop capacity ./path/to/codebase

# Preview unified diff patches to prune dead code and tollbooths
target/release/deslop prune ./path/to/codebase

# Surgically apply refactors with automatic rollback if test verification fails
target/release/deslop apply ./path/to/codebase --verify "cargo test"

# Launch interactive terminal UI dashboard (Ratatui)
target/release/deslop tui ./path/to/codebase

# Export symbol dependency graph to Source Code Intelligence Protocol (SCIP)
target/release/deslop scip ./path/to/codebase -o index.scip.json

# Deep architectural analysis: package coupling, main sequence distance, and dominator bottlenecks
target/release/deslop deep ./path/to/codebase

# CI/CD Quality Gate
target/release/deslop check ./path/to/codebase --max-slop 25
```

---

## Bring Your Own Key (BYOK) AI Synthesis

Deslop computes **100% of graph metrics, AST parsing, and cycle paths locally in Rust at zero token cost**.

If you supply an API key in your environment, Deslop uses your LLM for high-level architectural distillation and refactoring rationales:

```bash
# Supports any of:
export GEMINI_API_KEY="your-gemini-key"
# or
export OPENAI_API_KEY="your-openai-key"
# or
export ANTHROPIC_API_KEY="your-anthropic-key"
# or
export OPENROUTER_API_KEY="your-openrouter-key"
```

If no key is present, Deslop runs in **Offline Deterministic Mode** with zero external network calls.

---

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

---

## Testing

Run the automated test suite:
```bash
cargo test
```
