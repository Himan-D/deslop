# Deslop Wiki

> **Deslop** is a deterministic codebase inversion and architectural de-slopping engine written in **Rust**. It parses multi-language codebases into a Symbol Dependency Graph, detects dependency cycles, architectural layer violations, dead code, tollbooth wrappers, and structural clones, and gates pull requests and AI coding agents locally at zero token cost.

---

## Wiki Navigation

- **[Architecture and Graph](Architecture-and-Graph.md)** — Workspace crate boundaries, `petgraph` Symbol Dependency Graph, Tarjan SCC + Feedback Arc Set (FAS) de-looping, edge resolution provenance (`Exact`, `ImportScoped`, `BareHeuristic`), and polyglot AST / `tsconfig.json` parsing.
- **[Ruleset Reference (`deslop.toml`)](Ruleset-Reference.md)** — Complete configuration guide for `layers`, `forbidden_rules`, glob patterns (e.g. `src/domain/**`), `allow_exceptions`, and Slop Index scoring & thresholds.
- **[CI and Agents](CI-and-Agents.md)** — `Himan-D/deslop@v1` GitHub Action, SARIF 2.1.0 Code Scanning, `--base origin/main` diffing, `deslop mcp` (9 tools including `deslop_check`), and GitHub `main` branch ruleset recommendations.

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
# Run a full architectural scan
deslop scan .

# Gate a feature branch against origin/main (fails on new cycles or High/Critical findings)
deslop check . --base origin/main

# Gate with a Slop Index ceiling
deslop check . --max-slop 25

# Break circular dependencies with Feedback Arc Set (FAS) cut-edge plans
deslop deloop .
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
