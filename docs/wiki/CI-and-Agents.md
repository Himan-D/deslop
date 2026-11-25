# CI & AI Agents Integration

Deslop is built to run deterministically in CI pipelines and directly inside AI coding agents via the Model Context Protocol (MCP).

---

## 1. GitHub Action (`Himan-D/deslop@v1`) & SARIF 2.1.0

Add Deslop to `.github/workflows/deslop.yml` to gate pull requests on new dependency cycles, `deslop.toml` layer violations, and High/Critical findings, while uploading **SARIF 2.1.0** annotations to GitHub Code Scanning:

```yaml
name: Deslop Architecture Gate

on:
  pull_request:
    branches: [main]

jobs:
  deslop:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # required for upload-sarif
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # --base origin/main needs base ref history

      - uses: Himan-D/deslop@v1
        with:
          base: origin/main
          sarif: deslop.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: deslop.sarif
```

### How `--base origin/main` Diffing Works

- Deslop checks out the base ref (`origin/main`) into a temporary directory using `git archive`.
- Findings are matched between base and head by **kind**, **relative file path**, and **title**.
- Line numbers are intentionally ignored, so unrelated edits above or below an existing symbol do not make pre-existing debt look newly introduced.

---

## 2. Recommended GitHub `main` Branch Ruleset

For repositories enforcing architectural fitness with Deslop, configure a GitHub **Repository Ruleset** targeting `main`:

1. **Require a pull request before merging** (blocks direct pushes to `main`).
2. **Require status checks to pass before merging**:
   - `deslop` (the `Himan-D/deslop@v1` gate job)
   - `cargo test` (or your project's test suite job)
3. **Require branches to be up to date before merging** (recommended so `--base origin/main` always diffs against current `main`).

---

## 3. Model Context Protocol (`deslop mcp`)

Deslop implements a native **MCP (`2024-11-05`)** server over `stdio`:

```bash
deslop mcp
```

### Client Configuration

Add to Claude Code / Claude Desktop, Cursor, Codex, or Gemini CLI / Antigravity:

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

See [`docs/AGENT_SETUP.md`](../AGENT_SETUP.md) for client-specific config paths, `AGENTS.md` / `CLAUDE.md` prompt rules, and `.git/hooks/pre-commit` snippets.

### Available MCP Tools (10 Tools)

| Tool | Purpose |
| :--- | :--- |
| `deslop_scan` | Computes the Slop Index (`0-100`), LOC, symbol count, and top debt findings. |
| `deslop_check` | Runs the architectural & SAST quality gate (cycles, `deslop.toml` violations, High/Critical findings, and Slop Index threshold). Accepts `path`, optional `base` git ref, and optional `max_slop`. |
| `deslop_next` | Returns the top prioritized finding(s) to fix next (ranked by severity, security/cycle impact, and git churn) with code snippets and verification command. |
| `deslop_deloop` | Discovers circular dependency SCCs and outputs the Feedback Arc Set (FAS) cut edge and refactoring steps. |
| `deslop_deep` | Computes Robert C. Martin's Package Coupling ($C_a, C_e, I, A, D$), Zone of Pain, and dominator bottlenecks. |
| `deslop_capacity` | Estimates static concurrent-user and RPS ceilings per device profile (heuristic, not a load test). |
| `deslop_testgen` | Synthesizes compiling characterization tests with real invocations and determinism checks. |
| `deslop_prune_diff` | Generates a unified diff patch preview for dead code deletion and tollbooth wrapper collapse. |
| `deslop_scip` | Exports the symbol dependency graph in standard SCIP JSON format. |
| `deslop_churn` | Analyzes git commit history for churn hotspots and hidden temporal coupling (co-changing files with zero static imports). |

---

## 4. Badges & Visual Graphs

```bash
# Shields.io endpoint JSON or standalone SVG badge
deslop badge . --format json > slop.json
deslop badge . --format svg -o slop-badge.svg

# Self-contained interactive HTML dependency graph (cycles & violations highlighted in red)
deslop graph . --format html -o graph.html
```
