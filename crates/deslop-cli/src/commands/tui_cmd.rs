use super::common::scan_and_analyze;
use crate::tui;
use std::path::Path;

pub fn run(path: &Path) -> anyhow::Result<()> {
    let (parsed, graph, findings, _) = scan_and_analyze(path)?;
    tui::run_tui(path, parsed, &graph, findings)?;
    Ok(())
}
