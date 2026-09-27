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

#[test]
fn test_deep_architecture_analysis() {
    use deslop_graph::DeepAnalyzer;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).unwrap();
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);

    let report = DeepAnalyzer::analyze(&graph);
    assert!(!report.module_metrics.is_empty(), "Should compute module metrics");
    assert!(report.average_depth_ratio > 0.0, "Should compute average depth ratio");
}

#[test]
fn test_scip_generation() {
    use deslop_graph::ScipGenerator;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).unwrap();

    let scip = ScipGenerator::generate(&fixture_dir, &parsed.symbols, &parsed.edges);

    assert_eq!(scip.metadata.version, 1);
    assert_eq!(scip.metadata.tool_info.name, "deslop");
    assert!(!scip.documents.is_empty(), "SCIP must contain indexed documents");

    // Check occurrences and symbols
    let total_symbols: usize = scip.documents.iter().map(|d| d.symbols.len()).sum();
    let total_occurrences: usize = scip.documents.iter().map(|d| d.occurrences.len()).sum();
    assert!(total_symbols > 0, "SCIP should contain symbols");
    assert!(total_occurrences > 0, "SCIP should contain occurrences");

    // Verify JSON serialization
    let json = serde_json::to_string(&scip).expect("SCIP must serialize to JSON");
    assert!(json.contains("project_root"));
    assert!(json.contains("occurrences"));
}

#[test]
fn test_incremental_cache() {
    use std::fs;

    let temp_dir = std::env::temp_dir().join("deslop_test_incremental_cache");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    // Copy fixture files to temp_dir
    for entry in fs::read_dir(&fixture_dir).unwrap().flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let dest = temp_dir.join(entry.file_name());
            let _ = fs::copy(entry.path(), dest);
        }
    }

    let scanner = CodebaseScanner::new();
    let initial_parsed = scanner.scan_cached(&temp_dir, true).unwrap();

    // Verify cache was saved
    let cache_file = temp_dir.join(".deslop/cache.json");
    assert!(cache_file.exists(), "Cache file .deslop/cache.json should exist");

    // Second scan using the cached files
    let cached_parsed = scanner.scan_cached(&temp_dir, true).unwrap();
    assert_eq!(initial_parsed.stats.total_files, cached_parsed.stats.total_files);
    assert_eq!(initial_parsed.stats.total_symbols, cached_parsed.stats.total_symbols);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_characterization_testgen() {
    use deslop_inversion::TestGenerator;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).unwrap();

    let suites = TestGenerator::generate_all(&parsed.symbols);
    assert!(!suites.is_empty(), "Should generate characterization test suites");

    let first = &suites[0];
    assert!(!first.test_code.is_empty());
    assert!(first.test_count > 0);
}

#[test]
fn test_trace_ingestion_and_dynamic_rescue() {
    use deslop_graph::{OtelSpan, TraceIngestionEngine};

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sloppy_app");

    let scanner = CodebaseScanner::new();
    let parsed = scanner.scan(&fixture_dir).unwrap();
    let graph = SymbolGraph::from_parsed(&parsed.symbols, &parsed.edges);

    let spans = vec![
        OtelSpan {
            name: "calculate_regular_discount".to_string(),
            duration_ms: Some(15.2),
            status: Some("ok".to_string()),
            service_name: Some("pricing-service".to_string()),
        },
        OtelSpan {
            name: "calculate_regular_discount".to_string(),
            duration_ms: Some(12.0),
            status: Some("ok".to_string()),
            service_name: Some("pricing-service".to_string()),
        },
    ];

    let report = TraceIngestionEngine::correlate_traces(&graph, &spans);
    assert_eq!(report.total_spans_ingested, 2);
    assert_eq!(report.active_runtime_symbols, 1);
    assert!(!report.dynamic_entrypoints_rescued.is_empty(), "Should rescue dynamic entrypoint from false-positive dead code detection");
    assert_eq!(report.dynamic_entrypoints_rescued[0].symbol_name, "calculate_regular_discount");
}

#[test]
fn test_architectural_layer_rules() {
    use deslop_core::{ArchitectureConfig, DependencyEdge, DependencyEdgeKind, ForbiddenRule, Severity, SlopKind, Symbol, SymbolKind, Visibility};
    use deslop_detector::SlopDetectorEngine;
    use deslop_graph::SymbolGraph;
    use std::path::PathBuf;

    let config = ArchitectureConfig {
        layers: vec!["controller".to_string(), "service".to_string(), "repo".to_string()],
        forbidden_rules: vec![ForbiddenRule {
            from: "repo".to_string(),
            to: "controller".to_string(),
            description: Some("Repository layer cannot call controller layer".to_string()),
        }],
    };

    let s1 = Symbol {
        id: "repo::fetch".to_string(),
        name: "fetch".to_string(),
        kind: SymbolKind::Function,
        file_path: PathBuf::from("src/repo.rs"),
        span: deslop_core::SourceSpan::new(1, 1, 5, 2),
        visibility: Visibility::Public,
        loc: 5,
        cyclomatic_complexity: 1,
        doc: None,
        signature: "fn fetch()".to_string(),
        is_pure_hint: false,
        ast_hash: None,
    };
    let s2 = Symbol {
        id: "controller::handle".to_string(),
        name: "handle".to_string(),
        kind: SymbolKind::Function,
        file_path: PathBuf::from("src/controller.rs"),
        span: deslop_core::SourceSpan::new(1, 1, 5, 2),
        visibility: Visibility::Public,
        loc: 5,
        cyclomatic_complexity: 1,
        doc: None,
        signature: "fn handle()".to_string(),
        is_pure_hint: false,
        ast_hash: None,
    };

    let edge = DependencyEdge {
        from_symbol: "repo::fetch".to_string(),
        to_symbol: "controller::handle".to_string(),
        kind: DependencyEdgeKind::Calls,
        count: 1,
    };

    let symbols = vec![s1, s2];
    let edges = vec![edge];
    let graph = SymbolGraph::from_parsed(&symbols, &edges);

    let findings = SlopDetectorEngine::analyze_with_config(&symbols, &edges, &graph, Some(&config));
    let layer_violations: Vec<_> = findings.iter().filter(|f| f.kind == SlopKind::LayerViolation).collect();
    assert!(!layer_violations.is_empty(), "Should detect architectural layer violation");
    assert_eq!(layer_violations[0].severity, Severity::Critical);
}

#[test]
fn test_git_churn_analysis() {
    use deslop_graph::GitChurnAnalyzer;
    use std::path::Path;

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_opt = GitChurnAnalyzer::analyze(repo_root, 50);
    assert!(report_opt.is_some(), "GitChurnAnalyzer should successfully analyze the deslop git repository");
    let report = report_opt.unwrap();
    assert!(report.total_commits_analyzed > 0, "Should have analyzed at least 1 commit");
}

#[test]
fn test_lossless_trivia_preservation() {
    use deslop_core::SourceSpan;
    use deslop_inversion::LosslessRewriter;

    let lines = vec![
        "// Copyright notice".to_string(),
        "/// Doc comment for dead function".to_string(),
        "#[inline(always)]".to_string(),
        "fn dead_function() {".to_string(),
        "    println!(\"dead\");".to_string(),
        "}".to_string(),
        "".to_string(),
        "fn live_function() { 42 }".to_string(),
    ];

    let span = SourceSpan {
        start_line: 4, // 1-indexed
        start_col: 1,
        end_line: 6,
        end_col: 2,
    };

    let (start_idx, end_idx) = LosslessRewriter::compute_symbol_pruning_bounds(&lines, &span);
    assert_eq!(start_idx, 1, "Should absorb attached doc comment and attribute");
    assert_eq!(end_idx, 6);
}



