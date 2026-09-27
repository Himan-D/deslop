use super::common::scan_and_analyze;
use colored::*;
use deslop_graph::ScipGenerator;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, output: Option<PathBuf>) -> anyhow::Result<()> {
    let (parsed, _, _, _) = scan_and_analyze(path)?;
    let scip_index = ScipGenerator::generate(path, &parsed.symbols, &parsed.edges);
    let json = serde_json::to_string_pretty(&scip_index)?;
    if let Some(out_path) = output {
        fs::write(&out_path, &json)?;
        println!(
            "Exported SCIP index to {}",
            out_path.display().to_string().green()
        );
    } else {
        println!("{}", json);
    }
    Ok(())
}
