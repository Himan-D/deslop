# Agent & Hook Setup Guide

Copy-paste configurations for connecting `deslop` to AI coding agents via MCP (`deslop mcp`) and enforcing architectural checks in git hooks.

> **Prerequisite:** Ensure `deslop` is installed and available on your `PATH` (`brew install Himan-D/tap/deslop` or `cargo install deslop-cli`).

---

## Claude Code / Claude Desktop

**Claude Code (CLI):**
```bash
claude mcp add deslop -- deslop mcp
```

**Claude Desktop / `.mcp.json` (`~/.claude/claude_desktop_config.json` or project `.mcp.json`):**
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

---

## Cursor

Add to `.cursor/mcp.json` (project-local) or `~/.cursor/mcp.json` (global):

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

---

## Codex / OpenAI CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.deslop]
command = "deslop"
args = ["mcp"]
```

Or as a JSON `mcpServers` entry:

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

---

## Gemini CLI / Antigravity

Add to `~/.gemini/settings.json`:

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

---

## `AGENTS.md` / `CLAUDE.md` Rule

Drop these 4 lines into your repo's `AGENTS.md` or `CLAUDE.md` so agents verify architectural health before wrapping up multi-file changes:

```markdown
## Architecture & Slop Gate
Before finishing any multi-file edit, run `deslop_check` on the workspace (with `base: "HEAD"` or `"origin/main"` when on a branch).
Fix any newly introduced dependency cycles, layer violations, or High/Critical findings before reporting completion.
If `deslop_check` fails, resolve the reported findings or explain why an existing finding is out of scope.
```

---

## Pre-Commit Hook

Save as `.git/hooks/pre-commit` and make it executable (`chmod +x .git/hooks/pre-commit`):

```bash
#!/usr/bin/env bash
set -euo pipefail
deslop check . --base HEAD
```
