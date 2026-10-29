use deslop_core::{SlopFinding, SlopKind, Symbol, SymbolKind};
use deslop_detector::CallSiteIndex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefactorResult {
    pub files_modified: Vec<PathBuf>,
    pub lines_deleted: usize,
    pub items_pruned: usize,
    pub loops_broken: usize,
    pub verified: bool,
    pub error: Option<String>,
}

pub struct RefactorEngine;

/// One planned file deletion (nothing written yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedDeletion {
    pub file: PathBuf,
    pub symbol_name: String,
    pub start_line: usize,
    pub lines_removed: usize,
}

/// One planned wrapper->target callsite rewrite (nothing written yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedInline {
    pub wrapper: String,
    pub target: String,
}

/// A finding that was deliberately left alone, with the reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedItem {
    pub symbol_name: String,
    pub file: PathBuf,
    pub reason: String,
}

/// Read-only preview of what [`RefactorEngine::apply`] would change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefactorPlan {
    pub deletions: Vec<PlannedDeletion>,
    pub inlines: Vec<PlannedInline>,
    pub skipped: Vec<SkippedItem>,
}

impl RefactorPlan {
    pub fn is_empty(&self) -> bool {
        self.deletions.is_empty() && self.inlines.is_empty()
    }
}

/// The exact new content of one file, computed in memory.
#[derive(Debug, Clone)]
pub struct FileRewrite {
    pub path: PathBuf,
    pub original: String,
    pub updated: String,
    pub items_pruned: usize,
}

/// Everything `apply` would write, plus the human-readable plan.
#[derive(Debug, Clone, Default)]
pub struct RewriteSet {
    pub rewrites: Vec<FileRewrite>,
    pub plan: RefactorPlan,
}

impl RefactorEngine {
    /// Findings that `apply` physically removes (dead symbols, wrappers).
    pub fn is_prunable(finding: &SlopFinding) -> bool {
        matches!(
            finding.kind,
            SlopKind::DeadOrphan | SlopKind::TollboothWrapper
        )
    }

    /// Parses a tollbooth finding into its (wrapper, target) pair.
    pub fn inline_target(finding: &SlopFinding) -> Option<(String, String)> {
        if finding.kind != SlopKind::TollboothWrapper {
            return None;
        }
        let target = finding
            .description
            .split("forwarding calls directly to `")
            .nth(1)
            .and_then(|s| s.split('`').next())?;
        let wrapper = finding
            .title
            .trim_start_matches("Tollbooth Wrapper: `")
            .trim_end_matches('`');
        Some((wrapper.to_string(), target.to_string()))
    }

    /// Computes the rewritten contents of every file that `apply` would
    /// change, without writing anything.
    ///
    /// Safety rule: a prunable symbol is only deleted or inlined when its name
    /// is not used in call position in any *other* file. Text rewriting cannot
    /// retarget cross-file callers, so those symbols are reported as skipped
    /// instead of silently breaking the build.
    pub fn rewrite_set(
        findings: &[SlopFinding],
        symbols: &[Symbol],
        callsites: &CallSiteIndex,
    ) -> anyhow::Result<RewriteSet> {
        let mut plan = RefactorPlan::default();
        // file -> (line ranges to delete, wrapper->target inlines local to that file)
        let mut removals: BTreeMap<PathBuf, Vec<(usize, usize)>> = BTreeMap::new();
        let mut local_inlines: BTreeMap<PathBuf, HashMap<String, String>> = BTreeMap::new();
        let mut items_by_file: HashMap<PathBuf, usize> = HashMap::new();
        let mut seen_inline = std::collections::HashSet::new();

        for f in findings {
            if !Self::is_prunable(f) {
                continue;
            }
            let Some(sym) = symbols.iter().find(|s| s.id == f.symbol_id) else {
                continue;
            };
            let outside = callsites.files_referencing_outside(&sym.name, &f.file_path);
            if !outside.is_empty() {
                plan.skipped.push(SkippedItem {
                    symbol_name: sym.name.clone(),
                    file: f.file_path.clone(),
                    reason: format!(
                        "referenced from {} other file(s); cross-file rewrite is not automatic",
                        outside.len()
                    ),
                });
                continue;
            }

            let content = match fs::read_to_string(&f.file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            if let Some((_, target)) = Self::inline_target(f) {
                if !is_forwarding_free_function(&lines, sym, &target) {
                    plan.skipped.push(SkippedItem {
                        symbol_name: sym.name.clone(),
                        file: f.file_path.clone(),
                        reason: format!(
                            "body is not a single call to free function `{target}`; inlining could change meaning"
                        ),
                    });
                    continue;
                }
            }
            let (start, end) =
                crate::lossless::LosslessRewriter::compute_symbol_pruning_bounds(&lines, &sym.span);
            if start >= end {
                continue;
            }

            removals
                .entry(f.file_path.clone())
                .or_default()
                .push((start, end));
            *items_by_file.entry(f.file_path.clone()).or_insert(0) += 1;
            plan.deletions.push(PlannedDeletion {
                file: f.file_path.clone(),
                symbol_name: sym.name.clone(),
                start_line: start + 1,
                lines_removed: end - start,
            });

            if let Some((wrapper, target)) = Self::inline_target(f) {
                if seen_inline.insert((wrapper.clone(), target.clone())) {
                    plan.inlines.push(PlannedInline {
                        wrapper: wrapper.clone(),
                        target: target.clone(),
                    });
                }
                local_inlines
                    .entry(f.file_path.clone())
                    .or_default()
                    .insert(wrapper, target);
            }
        }

        let mut rewrites = Vec::new();
        let mut files: Vec<PathBuf> = removals.keys().cloned().collect();
        for path in local_inlines.keys() {
            if !files.contains(path) {
                files.push(path.clone());
            }
        }
        files.sort();

        for path in files {
            let original = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let lines: Vec<&str> = original.lines().collect();
            let mut to_remove = vec![false; lines.len()];
            for (start, end) in removals.get(&path).into_iter().flatten() {
                for flag in to_remove.iter_mut().take(*end).skip(*start) {
                    *flag = true;
                }
            }
            let inlines = local_inlines.get(&path);

            let mut kept: Vec<String> = Vec::with_capacity(lines.len());
            for (idx, line) in lines.iter().enumerate() {
                if to_remove[idx] {
                    continue;
                }
                let mut rewritten = (*line).to_string();
                if let Some(map) = inlines {
                    for (wrapper, target) in map {
                        rewritten = crate::lossless::LosslessRewriter::inline_callsite(
                            &rewritten, wrapper, target,
                        );
                    }
                }
                kept.push(rewritten);
            }

            let mut updated = kept.join("\n");
            if original.ends_with('\n') {
                updated.push('\n');
            }
            if updated != original {
                rewrites.push(FileRewrite {
                    items_pruned: items_by_file.get(&path).copied().unwrap_or(0),
                    path,
                    original,
                    updated,
                });
            }
        }

        Ok(RewriteSet { rewrites, plan })
    }

    /// Read-only preview of what [`RefactorEngine::apply`] would change.
    pub fn plan(
        findings: &[SlopFinding],
        symbols: &[Symbol],
        callsites: &CallSiteIndex,
    ) -> anyhow::Result<RefactorPlan> {
        Ok(Self::rewrite_set(findings, symbols, callsites)?.plan)
    }

    /// Applies surgical de-slopping and pruning directly to files, with automatic
    /// rollback if the verification command fails.
    pub fn apply(
        root_dir: &Path,
        findings: &[SlopFinding],
        symbols: &[Symbol],
        callsites: &CallSiteIndex,
        test_command: Option<&str>,
    ) -> anyhow::Result<RefactorResult> {
        let set = Self::rewrite_set(findings, symbols, callsites)?;
        let loops_broken = findings
            .iter()
            .filter(|f| f.kind == SlopKind::Cycle)
            .count();

        // Snapshot exactly the files we are about to write, for rollback.
        let snapshot: Vec<(PathBuf, String)> = set
            .rewrites
            .iter()
            .map(|r| (r.path.clone(), r.original.clone()))
            .collect();

        let mut modified_files = Vec::new();
        let mut lines_deleted = 0;
        let mut items_pruned = 0;
        for rewrite in &set.rewrites {
            fs::write(&rewrite.path, &rewrite.updated)?;
            modified_files.push(rewrite.path.clone());
            lines_deleted += rewrite
                .original
                .lines()
                .count()
                .saturating_sub(rewrite.updated.lines().count());
            items_pruned += rewrite.items_pruned;
        }

        let mut verification_error = None;
        if let Some(cmd) = test_command {
            let output = if cfg!(target_os = "windows") {
                Command::new("cmd")
                    .args(["/C", cmd])
                    .current_dir(root_dir)
                    .output()
            } else {
                Command::new("sh")
                    .args(["-c", cmd])
                    .current_dir(root_dir)
                    .output()
            };
            match output {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    verification_error =
                        Some(format!("Test verification failed:\n{}\n{}", stderr, stdout));
                }
                Err(e) => {
                    verification_error = Some(format!("Failed to execute test command: {}", e));
                }
            }
        }

        if verification_error.is_some() {
            for (path, content) in &snapshot {
                let _ = fs::write(path, content);
            }
            return Ok(RefactorResult {
                files_modified: Vec::new(),
                lines_deleted: 0,
                items_pruned: 0,
                loops_broken: 0,
                verified: false,
                error: verification_error,
            });
        }

        Ok(RefactorResult {
            files_modified: modified_files,
            lines_deleted,
            items_pruned,
            loops_broken,
            verified: true,
            error: None,
        })
    }
}

/// True when `sym` is a free function whose entire body is one call to the
/// free function `target`, so `sym(args)` can become `target(args)` at every
/// call site without changing meaning. Method receivers (`x.target(`,
/// `Self::target(`), extra statements, and differing bodies all fail.
pub fn is_forwarding_free_function(lines: &[String], sym: &Symbol, target: &str) -> bool {
    if sym.kind != SymbolKind::Function || target == sym.name {
        return false;
    }
    let first = sym.span.start_line.saturating_sub(1);
    let last = sym.span.end_line.min(lines.len());
    if last <= first + 1 {
        return false;
    }
    // Drop the signature (first line) and brace-only lines; one statement must remain.
    let body: Vec<&str> = lines[first + 1..last]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !matches!(*l, "{" | "}" | "};"))
        .collect();
    if body.len() != 1 {
        return false;
    }
    let stmt = body[0]
        .trim_start_matches("return ")
        .trim_end_matches(';')
        .trim();
    call_is_free_and_whole(stmt, target)
}

/// `stmt` must be exactly `target(...)`: a free call (not preceded by `.`,
/// `:` or an identifier character) whose argument list closes at the end.
fn call_is_free_and_whole(stmt: &str, target: &str) -> bool {
    let prefix = format!("{target}(");
    if !stmt.starts_with(&prefix) {
        return false;
    }
    let mut depth = 0usize;
    for (i, c) in stmt.char_indices().skip(target.len()) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return stmt[i + 1..].trim().is_empty();
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{Severity, SourceSpan, Visibility};

    fn finding(
        kind: SlopKind,
        file: &Path,
        symbol_id: &str,
        title: &str,
        desc: &str,
    ) -> SlopFinding {
        SlopFinding {
            kind,
            symbol_id: symbol_id.to_string(),
            file_path: file.to_path_buf(),
            line: 1,
            severity: Severity::Low,
            confidence: 0.9,
            title: title.to_string(),
            description: desc.to_string(),
            remediation: String::new(),
            estimated_lines_saved: 3,
        }
    }

    fn sym(id: &str, name: &str, file: &Path, start: usize, end: usize) -> Symbol {
        Symbol {
            id: id.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: file.to_path_buf(),
            span: SourceSpan::new(start, 1, end, 2),
            visibility: Visibility::Private,
            loc: end - start + 1,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {name}()"),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deslop-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn inline_target_parses_wrapper_and_target() {
        let f = finding(
            SlopKind::TollboothWrapper,
            Path::new("x.rs"),
            "x.rs::scan",
            "Tollbooth Wrapper: `scan`",
            "Function `scan` is a thin pass-through forwarding calls directly to `scan_cached` with negligible logic.",
        );
        assert_eq!(
            RefactorEngine::inline_target(&f),
            Some(("scan".to_string(), "scan_cached".to_string()))
        );
        assert!(RefactorEngine::is_prunable(&f));

        let other = finding(
            SlopKind::GodObject,
            Path::new("x.rs"),
            "x.rs::Big",
            "God",
            "",
        );
        assert_eq!(RefactorEngine::inline_target(&other), None);
        assert!(!RefactorEngine::is_prunable(&other));
    }

    #[test]
    fn plan_reports_deletions_without_writing() {
        let dir = temp_dir("plan-test");
        let file = dir.join("sample.rs");
        fs::write(&file, "fn dead() {\n    1\n}\nfn live() {\n    2\n}\n").unwrap();

        let findings = vec![finding(
            SlopKind::DeadOrphan,
            &file,
            &format!("{}::dead", file.display()),
            "Unreachable Symbol: `dead`",
            "dead",
        )];
        let symbols = vec![sym(
            &format!("{}::dead", file.display()),
            "dead",
            &file,
            1,
            3,
        )];

        let plan = RefactorEngine::plan(&findings, &symbols, &CallSiteIndex::default()).unwrap();
        assert_eq!(plan.deletions.len(), 1);
        assert_eq!(plan.deletions[0].symbol_name, "dead");
        assert_eq!(plan.deletions[0].start_line, 1);
        assert_eq!(plan.deletions[0].lines_removed, 3);
        assert!(plan.inlines.is_empty());

        let after = fs::read_to_string(&file).unwrap();
        assert!(after.contains("fn dead()"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_removes_symbol_and_keeps_trailing_newline() {
        let dir = temp_dir("rewrite-test");
        let file = dir.join("sample.rs");
        fs::write(&file, "fn dead() {\n    1\n}\nfn live() {\n    2\n}\n").unwrap();
        let findings = vec![finding(
            SlopKind::DeadOrphan,
            &file,
            &format!("{}::dead", file.display()),
            "Unreachable Symbol: `dead`",
            "dead",
        )];
        let symbols = vec![sym(
            &format!("{}::dead", file.display()),
            "dead",
            &file,
            1,
            3,
        )];
        let set =
            RefactorEngine::rewrite_set(&findings, &symbols, &CallSiteIndex::default()).unwrap();
        assert_eq!(set.rewrites.len(), 1);
        assert_eq!(set.rewrites[0].updated, "fn live() {\n    2\n}\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_file_referenced_symbol_is_skipped_not_deleted() {
        let dir = temp_dir("skip-test");
        let a = dir.join("a.rs");
        let b = dir.join("b.rs");
        fs::write(&a, "fn helper() {\n    1\n}\n").unwrap();
        fs::write(&b, "fn user() { helper(); }\n").unwrap();
        let findings = vec![finding(
            SlopKind::DeadOrphan,
            &a,
            &format!("{}::helper", a.display()),
            "Unreachable Symbol: `helper`",
            "helper",
        )];
        let symbols = vec![sym(&format!("{}::helper", a.display()), "helper", &a, 1, 3)];
        let index = CallSiteIndex::build(vec![
            (a.as_path(), "fn helper() {\n    1\n}\n"),
            (b.as_path(), "fn user() { helper(); }\n"),
        ]);
        let set = RefactorEngine::rewrite_set(&findings, &symbols, &index).unwrap();
        assert!(set.rewrites.is_empty());
        assert_eq!(set.plan.skipped.len(), 1);
        assert!(set.plan.deletions.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tollbooth_inlines_local_callers_and_removes_wrapper() {
        let dir = temp_dir("inline-test");
        let file = dir.join("lib.rs");
        let src = "fn scan_cached() {\n    1\n}\nfn scan() {\n    scan_cached()\n}\nfn run() {\n    scan();\n}\n";
        fs::write(&file, src).unwrap();
        let findings = vec![finding(
            SlopKind::TollboothWrapper,
            &file,
            &format!("{}::scan", file.display()),
            "Tollbooth Wrapper: `scan`",
            "Function `scan` is a thin pass-through forwarding calls directly to `scan_cached` with negligible logic.",
        )];
        let symbols = vec![sym(
            &format!("{}::scan", file.display()),
            "scan",
            &file,
            4,
            6,
        )];
        let index = CallSiteIndex::build(vec![(file.as_path(), src)]);
        let set = RefactorEngine::rewrite_set(&findings, &symbols, &index).unwrap();
        assert_eq!(set.rewrites.len(), 1);
        let updated = &set.rewrites[0].updated;
        assert!(!updated.contains("fn scan()"));
        assert!(updated.contains("scan_cached();"));
        assert_eq!(set.plan.inlines.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    fn lines_of(src: &str) -> Vec<String> {
        src.lines().map(|l| l.to_string()).collect()
    }

    fn fn_sym(name: &str, kind: SymbolKind, start: usize, end: usize) -> Symbol {
        let mut s = sym(
            &format!("x.rs::{name}"),
            name,
            Path::new("x.rs"),
            start,
            end,
        );
        s.kind = kind;
        s
    }

    #[test]
    fn forwarding_check_accepts_only_a_single_free_call() {
        let lines = lines_of("fn scan() {\n    scan_cached(1)\n}\n");
        let wrapper = fn_sym("scan", SymbolKind::Function, 1, 3);
        assert!(is_forwarding_free_function(&lines, &wrapper, "scan_cached"));

        // Go-style and Python-style bodies are accepted too.
        let go = lines_of("func scan() int {\n\treturn scanCached()\n}\n");
        assert!(is_forwarding_free_function(
            &go,
            &fn_sym("scan", SymbolKind::Function, 1, 3),
            "scanCached"
        ));
        let py = lines_of("def scan(x):\n    return scan_cached(x)\n");
        assert!(is_forwarding_free_function(
            &py,
            &fn_sym("scan", SymbolKind::Function, 1, 2),
            "scan_cached"
        ));
    }

    #[test]
    fn forwarding_check_rejects_the_real_failure_modes() {
        // A method whose body builds state and calls a method on it (the
        // deslop-parser `ComplexityCounter::of_block` case).
        let body = lines_of(
            "fn of_block(block: &syn::Block) -> usize {\n    let mut counter = Self { complexity: 1 };\n    counter.visit_block(block);\n    counter.complexity\n}\n",
        );
        assert!(!is_forwarding_free_function(
            &body,
            &fn_sym("of_block", SymbolKind::Method, 1, 5),
            "visit_block"
        ));
        assert!(!is_forwarding_free_function(
            &body,
            &fn_sym("of_block", SymbolKind::Function, 1, 5),
            "visit_block"
        ));

        // A single line that calls a method on a receiver.
        let receiver = lines_of("fn scan() {\n    counter.scan_cached()\n}\n");
        assert!(!is_forwarding_free_function(
            &receiver,
            &fn_sym("scan", SymbolKind::Function, 1, 3),
            "scan_cached"
        ));

        // A single call whose arguments do not close the statement.
        let trailing = lines_of("fn scan() {\n    scan_cached(1) + 2\n}\n");
        assert!(!is_forwarding_free_function(
            &trailing,
            &fn_sym("scan", SymbolKind::Function, 1, 3),
            "scan_cached"
        ));
    }

    #[test]
    fn method_wrappers_are_reported_as_skipped_not_inlined() {
        let dir = temp_dir("skip-method-wrapper");
        let file = dir.join("lib.rs");
        let src = "fn of_block() -> usize {\n    let mut c = Counter::new();\n    c.visit();\n    c.n\n}\nfn visit() {}\n";
        fs::write(&file, src).unwrap();
        let findings = vec![finding(
            SlopKind::TollboothWrapper,
            &file,
            &format!("{}::of_block", file.display()),
            "Tollbooth Wrapper: `of_block`",
            "Function `of_block` is a thin pass-through forwarding calls directly to `visit` with negligible logic.",
        )];
        let symbols = vec![sym(
            &format!("{}::of_block", file.display()),
            "of_block",
            &file,
            1,
            5,
        )];
        let index = CallSiteIndex::build(vec![(file.as_path(), src)]);
        let set = RefactorEngine::rewrite_set(&findings, &symbols, &index).unwrap();
        assert!(set.rewrites.is_empty(), "must not rewrite a non-forwarder");
        assert_eq!(set.plan.skipped.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
