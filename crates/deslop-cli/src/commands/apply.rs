use super::common::{create_spinner, scan_and_analyze};
use colored::*;
use deslop_inversion::RefactorEngine;
use std::path::Path;

pub fn run(path: &Path, verify: Option<String>) -> anyhow::Result<()> {
    println!("{}", "deslop: surgical refactor & verification".bold());
    println!("target: {}\n", path.display());

    let (parsed, _graph, findings, _elapsed) = scan_and_analyze(path)?;

    let pb = create_spinner("Executing surgical inlining and dead-code elimination...");
    let res = RefactorEngine::apply(path, &findings, &parsed.symbols, verify.as_deref())?;
    pb.finish_and_clear();

    if !res.verified {
        eprintln!(
            "{}",
            "error: verification failed, changes rolled back."
                .red()
                .bold()
        );
        if let Some(err) = res.error {
            eprintln!("\n{}", err.red());
        }
        std::process::exit(1);
    }

    println!(
        "{}",
        "Codebase refactoring applied successfully.".green().bold()
    );
    println!("--------------------------------------------------");
    println!("{:<28} {}", "Files Modified:", res.files_modified.len());
    for f in &res.files_modified {
        println!("  * {}", f.display());
    }
    println!("{:<28} {}", "Items Pruned / Inlined:", res.items_pruned);
    println!(
        "{:<28} {}",
        "Net Lines Deleted:",
        format!("-{} LOC", res.lines_deleted).green()
    );
    if let Some(v_cmd) = verify {
        println!(
            "{:<28} {}",
            "Verification Command:",
            format!("'{}' passed cleanly", v_cmd).green()
        );
        println!("--------------------------------------------------\n");
        println!("Refactoring complete with zero regressions.");
    } else {
        println!("--------------------------------------------------\n");
        println!(
            "{}",
            "Refactoring complete. No verification command was supplied (-V/--verify) — run your test suite before committing.".yellow()
        );
    }
    Ok(())
}
