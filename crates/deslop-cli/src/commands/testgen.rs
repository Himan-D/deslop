use super::common::scan_and_analyze;
use colored::*;
use deslop_inversion::TestGenerator;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(path: &Path, symbol: Option<String>, output: Option<PathBuf>) -> anyhow::Result<()> {
    println!(
        "{}",
        "deslop: automated characterization test synthesizer".bold()
    );
    println!("target: {}\n", path.display());

    let (parsed, _, _, _) = scan_and_analyze(path)?;

    let suites = if let Some(sym_name) = symbol {
        if let Some(target_sym) = parsed.symbols.iter().find(|s| s.name == sym_name) {
            vec![TestGenerator::generate_for_symbol(target_sym)]
        } else {
            eprintln!("Error: Symbol '{}' not found in codebase.", sym_name);
            std::process::exit(1);
        }
    } else {
        TestGenerator::generate_all(&parsed.symbols)
    };

    if suites.is_empty() {
        println!("No testable functions or methods found in target scope.");
        return Ok(());
    }

    println!(
        "Synthesized {} characterization test suite(s):\n",
        suites.len()
    );

    let mut aggregated_tests = String::new();
    for suite in &suites {
        println!(
            "  * Symbol: {} ({} cases) -> {}",
            suite.target_symbol.green().bold(),
            suite.test_count,
            suite.file_path
        );
        aggregated_tests.push_str(&suite.test_code);
        aggregated_tests.push_str("\n\n");
    }

    if let Some(out_path) = output {
        fs::write(&out_path, &aggregated_tests)?;
        println!(
            "\nWritten tests to {}",
            out_path.display().to_string().green()
        );
    } else {
        println!("\nSample synthesized test code:\n");
        let preview: Vec<&str> = aggregated_tests.lines().take(25).collect();
        println!("{}", preview.join("\n"));
        if aggregated_tests.lines().count() > 25 {
            println!("... (use -o <file> to write full test suite to disk)");
        }
    }
    Ok(())
}
