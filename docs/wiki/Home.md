# Deslop Wiki

> **Deslop** is a deterministic architectural & security quality gate written in **Rust**. It parses Rust, TypeScript/JavaScript, Python, and Go into a Symbol Dependency Graph, detects dependency cycles, layer/import boundary violations, dead code, unused manifest dependencies, and SAST security sinks, and gates pull requests and AI coding agents locally at zero token cost.

---

## Wiki Navigation

- **[Architecture and Graph](Architecture-and-Graph.md)** — Workspace crate boundaries, `petgraph` Symbol Dependency Graph, Tarjan SCC + Feedback Arc Set (FAS) de-looping, edge resolution provenance (`Exact`, `ImportScoped`, `BareHeuristic`), `tsconfig.json` parsing, and interactive HTML graphs (`deslop graph --format html`).
- **[Ruleset Reference (`deslop.toml`)](Ruleset-Reference.md)** — Configuration guide for `layers`, `forbidden_rules` (including raw `Imports`), `isolated` feature contracts, `allow_exceptions`, `[security]` SAST settings, and Slop Index scoring.
- **[CI and Agents](CI-and-Agents.md)** — `Himan-D/deslop@v1` GitHub Action, SARIF 2.1.0 Code Scanning (including `security-severity`), `deslop badge`, `deslop setup`, `deslop next`, and `deslop mcp` (10 tools).

### Additional Documentation

- **[Calibration & Spot-Checks](../CALIBRATION.md)** — Before/after measurements and precision spot-checks across open-source repositories.
- **[Agent & Hook Setup Guide](../AGENT_SETUP.md)** — Copy-paste MCP configs for Claude Code, Cursor, Codex, and Gemini CLI / Antigravity, plus `AGENTS.md` and pre-commit hook snippets.

---

## 30-Second Quick Start

### 1. Install

**Homebrew**
```bash
brew install Himan-D/tap/deslop
```

**Cargo**
```bash
cargo install deslop-cli
```

### 2. Scan and Gate Your Repo

```bash
# Run a full architectural & SAST scan (add --hotspots for Churn x Slop ranking)
deslop scan . --hotspots

# Get the single highest-priority finding to fix next
deslop next .

# Gate a feature branch against origin/main (fails on new cycles or High/Critical findings)
deslop check . --base origin/main

# Gate with a Slop Index ceiling
deslop check . --max-slop 25

# Break circular dependencies with Feedback Arc Set (FAS) cut-edge plans
deslop deloop .

# Generate an interactive HTML dependency graph or Shields.io / SVG badge
deslop graph . --format html -o graph.html
deslop badge . --format svg -o slop-badge.svg

# Configure Claude Code, Cursor, Codex, or Gemini CLI
deslop setup all
```

### 3. Connect to Your AI Agent (`deslop mcp`)

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
