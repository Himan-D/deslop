use deslop_detector::SlopDetectorEngine;
use deslop_graph::SymbolGraph;
use deslop_inversion::{DelooperEngine, InversionEngine};
use deslop_parser::CodebaseScanner;
use std::path::PathBuf;

#[test]
fn test_deloop_and_inversion_pipeline() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).expect("Failed to scan fixture");

    assert!(parsed.stats.total_files >= 4);
    assert!(parsed.symbols.len() >= 6);

    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
    let cycles = graph.find_circular_dependencies();
    assert_eq!(cycles.len(), 1, "Expected exactly 1 circular dependency loop");

    let deloop_plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, &graph);
    assert_eq!(deloop_plans.len(), 1);
    assert_eq!(deloop_plans[0].cut_edge.0, "processA");
    assert_eq!(deloop_plans[0].cut_edge.1, "processB");

    let findings = SlopDetectorEngine::analyze(&parsed.symbols, &parsed.edges, &graph);
    assert!(!findings.is_empty());

    let inverted = InversionEngine::synthesize_spec(
        "test_sloppy_app",
        &parsed.stats,
        &parsed.symbols,
        &parsed.edges,
        &graph,
        &findings,
    );

    assert!(inverted.original_loc > inverted.projected_loc);
    assert!(inverted.lines_reduced_estimate > 0);
    assert!(inverted.spec_markdown.contains("Architectural Inversion Specification"));
    assert!(inverted.spec_markdown.contains("De-Looping Strategy"));
}

#[test]
fn test_rollback_on_failed_verification() {
    use deslop_inversion::RefactorEngine;
    use std::fs;

    let temp_dir = std::env::temp_dir().join("deslop_test_rollback");
    let _ = fs::create_dir_all(&temp_dir);
    let test_file = temp_dir.join("sample.rs");
    let original_text = "fn unused() { 42 }\nfn active() { 100 }\n";
    fs::write(&test_file, original_text).unwrap();

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&temp_dir).unwrap();
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);
    let findings = SlopDetectorEngine::analyze(&parsed.symbols, &parsed.edges, &graph);

    // Provide a verification command that intentionally fails
    let res = RefactorEngine::apply(
        &temp_dir,
        &findings,
        &parsed.symbols,
        Some("exit 1"), // Intentionally failing verification command
    )
    .unwrap();

    // Verify that the rollback was triggered
    assert!(!res.verified, "Expected verification to fail");
    let current_text = fs::read_to_string(&test_file).unwrap();
    assert_eq!(
        current_text, original_text,
        "File should be identical to snapshot after rollback"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_capacity_prediction() {
    use deslop_graph::CapacityAnalyzer;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).unwrap();
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);

    let report = CapacityAnalyzer::analyze(&graph);
    assert!(!report.estimates.is_empty(), "Should contain device estimates");
    assert_eq!(report.estimates.len(), 4, "Should profile 4 standard device tiers");
    assert!(!report.breaking_risks.is_empty(), "Should detect breaking risks");
}
