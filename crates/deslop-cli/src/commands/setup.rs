use anyhow::{bail, Context};
use colored::*;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const MCP_JSON_SNIPPET: &str = r#"{
  "mcpServers": {
    "deslop": {
      "command": "deslop",
      "args": ["mcp"]
    }
  }
}"#;

const CODEX_TOML_SNIPPET: &str = r#"[mcp_servers.deslop]
command = "deslop"
args = ["mcp"]"#;

const AGENTS_MD_SNIPPET: &str = "\
## Deslop Architecture Guard\n\
Before finishing multi-file edits, run `deslop_next` to inspect architectural priorities\n\
and `deslop_check` to verify no new dependency cycles or high-severity slop were introduced.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentTarget {
    Claude,
    Cursor,
    Codex,
    Gemini,
    All,
}

impl AgentTarget {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" => Ok(Self::Claude),
            "cursor" => Ok(Self::Cursor),
            "codex" => Ok(Self::Codex),
            "gemini" => Ok(Self::Gemini),
            "all" => Ok(Self::All),
            _ => bail!(
                "Unknown agent '{}'. Supported agents: claude, cursor, codex, gemini, all",
                raw
            ),
        }
    }

    fn includes_claude(self) -> bool {
        matches!(self, Self::Claude | Self::All)
    }

    fn includes_cursor(self) -> bool {
        matches!(self, Self::Cursor | Self::All)
    }

    fn includes_codex(self) -> bool {
        matches!(self, Self::Codex | Self::All)
    }

    fn includes_gemini(self) -> bool {
        matches!(self, Self::Gemini | Self::All)
    }
}

/// Merge the `deslop` MCP server entry into an existing JSON config string (if any),
/// preserving all existing top-level keys and `mcpServers` entries.
pub fn merge_mcp_json(existing: Option<&str>) -> anyhow::Result<String> {
    let mut root: Value = match existing {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(raw).context("Failed to parse existing MCP JSON config")?
        }
        _ => json!({}),
    };

    let root_obj = root
        .as_object_mut()
        .context("MCP JSON config root must be a JSON object")?;

    let servers_val = root_obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));

    let servers_obj = servers_val
        .as_object_mut()
        .context("'mcpServers' field in MCP JSON config must be a JSON object")?;

    servers_obj.insert(
        "deslop".to_string(),
        json!({
            "command": "deslop",
            "args": ["mcp"]
        }),
    );

    let pretty = serde_json::to_string_pretty(&root)?;
    Ok(format!("{}\n", pretty))
}

fn write_mcp_json(target: &Path) -> anyhow::Result<()> {
    let existing = if target.exists() {
        Some(
            fs::read_to_string(target)
                .with_context(|| format!("Failed to read {}", target.display()))?,
        )
    } else {
        None
    };

    let merged = merge_mcp_json(existing.as_deref())?;

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }
    }

    fs::write(target, merged).with_context(|| format!("Failed to write {}", target.display()))?;
    Ok(())
}

/// Generate (and optionally write project-local) MCP configuration snippets for AI coding agents.
pub fn run(agent: &str, path: &Path, write: bool) -> anyhow::Result<()> {
    let target = AgentTarget::parse(agent)?;

    if target.includes_claude() {
        let claude_path = path.join(".mcp.json");
        println!("{}", "=== Claude Code ===".cyan().bold());
        if write {
            write_mcp_json(&claude_path)?;
            println!("{} {}", "Wrote".green().bold(), claude_path.display());
        } else {
            println!("Target: {}", claude_path.display());
            println!("{MCP_JSON_SNIPPET}");
        }
        println!("Hint: claude mcp add deslop -- deslop mcp\n");
    }

    if target.includes_cursor() {
        let cursor_path = path.join(".cursor/mcp.json");
        println!("{}", "=== Cursor ===".cyan().bold());
        if write {
            write_mcp_json(&cursor_path)?;
            println!("{} {}", "Wrote".green().bold(), cursor_path.display());
        } else {
            println!("Target: {}", cursor_path.display());
            println!("{MCP_JSON_SNIPPET}");
        }
        println!();
    }

    if target.includes_codex() {
        println!("{}", "=== Codex ===".cyan().bold());
        println!("Target: ~/.codex/config.toml (global config; not auto-written)");
        println!("{CODEX_TOML_SNIPPET}\n");
    }

    if target.includes_gemini() {
        println!("{}", "=== Gemini CLI ===".cyan().bold());
        println!("Target: ~/.gemini/settings.json (global config; not auto-written)");
        println!("{MCP_JSON_SNIPPET}\n");
    }

    println!("{}", "=== AGENTS.md snippet ===".cyan().bold());
    println!("{AGENTS_MD_SNIPPET}\n");

    if !write && (target.includes_claude() || target.includes_cursor()) {
        println!(
            "{}",
            "Tip: re-run with --write to write project-local .mcp.json / .cursor/mcp.json."
                .dimmed()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn merge_mcp_json_preserves_existing_entries() {
        let existing = r#"{
  "otherTopLevel": true,
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}"#;

        let merged = merge_mcp_json(Some(existing)).expect("merge should succeed");
        let parsed: Value = serde_json::from_str(&merged).expect("output should be valid JSON");

        assert_eq!(parsed["otherTopLevel"], json!(true));
        assert_eq!(
            parsed["mcpServers"]["filesystem"]["command"],
            json!("npx")
        );
        assert_eq!(
            parsed["mcpServers"]["deslop"],
            json!({
                "command": "deslop",
                "args": ["mcp"]
            })
        );
    }

    #[test]
    fn merge_mcp_json_creates_new_config_when_empty() {
        let merged = merge_mcp_json(None).expect("merge from None should succeed");
        let parsed: Value = serde_json::from_str(&merged).expect("output should be valid JSON");

        assert_eq!(
            parsed["mcpServers"]["deslop"],
            json!({
                "command": "deslop",
                "args": ["mcp"]
            })
        );
    }

    #[test]
    fn unknown_agent_returns_err() {
        let err = run("windsurf", Path::new("."), false).expect_err("unknown agent should fail");
        let msg = err.to_string();
        assert!(msg.contains("Unknown agent 'windsurf'"));
        assert!(msg.contains("claude"));
        assert!(msg.contains("cursor"));
        assert!(msg.contains("codex"));
        assert!(msg.contains("gemini"));
        assert!(msg.contains("all"));
    }

    #[test]
    fn agent_parsing_is_case_insensitive() {
        assert_eq!(AgentTarget::parse("Claude").unwrap(), AgentTarget::Claude);
        assert_eq!(AgentTarget::parse("CURSOR").unwrap(), AgentTarget::Cursor);
        assert_eq!(AgentTarget::parse("CoDeX").unwrap(), AgentTarget::Codex);
        assert_eq!(AgentTarget::parse("Gemini").unwrap(), AgentTarget::Gemini);
        assert_eq!(AgentTarget::parse("ALL").unwrap(), AgentTarget::All);
    }

    #[test]
    fn write_merges_project_local_configs_without_clobbering() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("deslop-setup-test-{}", nanos));
        fs::create_dir_all(&temp_dir).unwrap();

        let mcp_path = temp_dir.join(".mcp.json");
        fs::write(
            &mcp_path,
            r#"{"mcpServers":{"existing":{"command":"foo","args":[]}}}"#,
        )
        .unwrap();

        run("all", &temp_dir, true).expect("run with write=true should succeed");

        let claude_cfg: Value =
            serde_json::from_str(&fs::read_to_string(&mcp_path).unwrap()).unwrap();
        assert_eq!(claude_cfg["mcpServers"]["existing"]["command"], json!("foo"));
        assert_eq!(claude_cfg["mcpServers"]["deslop"]["command"], json!("deslop"));

        let cursor_path = temp_dir.join(".cursor/mcp.json");
        let cursor_cfg: Value =
            serde_json::from_str(&fs::read_to_string(&cursor_path).unwrap()).unwrap();
        assert_eq!(cursor_cfg["mcpServers"]["deslop"]["command"], json!("deslop"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
