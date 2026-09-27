use crate::mcp;

pub fn run() -> anyhow::Result<()> {
    mcp::McpServer::start()?;
    Ok(())
}
