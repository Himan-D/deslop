use crate::lsp;

pub fn run() -> anyhow::Result<()> {
    let mut server = lsp::LspServer::new();
    server.start()?;
    Ok(())
}
