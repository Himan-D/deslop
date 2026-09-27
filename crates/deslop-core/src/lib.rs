use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    Rust,
    TypeScript,
    JavaScript,
    Python,
    Go,
    Unknown,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext {
            "rs" => Language::Rust,
            "ts" | "tsx" => Language::TypeScript,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "py" => Language::Python,
            "go" => Language::Go,
            _ => Language::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Method,
    Struct,
    Class,
    Interface,
    Trait,
    Enum,
    Module,
    File,
    TypeAlias,
    Constant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

impl SourceSpan {
    pub fn new(start_line: usize, start_col: usize, end_line: usize, end_col: usize) -> Self {
        Self {
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub id: String,
    pub name: String,
    pub kind: SymbolKind,
    pub file_path: PathBuf,
    pub span: SourceSpan,
    pub visibility: Visibility,
    pub loc: usize,
    pub cyclomatic_complexity: usize,
    pub doc: Option<String>,
    pub signature: String,
    pub is_pure_hint: bool,
    pub ast_hash: Option<String>,
    /// Attribute paths attached to this symbol (e.g. `test`, `derive`, `inline`).
    /// Used to recognize test entrypoints and generated code.
    #[serde(default)]
    pub attributes: Vec<String>,
    /// True when this method comes from `impl Trait for Type` rather than an
    /// inherent impl block. Such methods are dispatched through the trait and
    /// must be treated as reachable entrypoints.
    #[serde(default)]
    pub is_trait_impl: bool,
}

impl Symbol {
    /// True for any test code: test entrypoints plus helpers living under
    /// `#[cfg(test)]` (e.g. inside `mod tests`). Used by rules that should
    /// ignore test scaffolding (tollbooth, clones). Dead-code detection still
    /// applies to helpers, so unreachable test helpers are flagged.
    pub fn is_test_code(&self) -> bool {
        self.is_test_entrypoint() || self.attributes.iter().any(|a| a == "cfg(test)")
    }

    /// Returns true if this symbol is a test entrypoint: `#[test]`-attributed,
    /// named `test_*`, or living under a `tests/` directory / `test_*` file.
    pub fn is_test_entrypoint(&self) -> bool {
        if self.attributes.iter().any(|a| a == "test") {
            return true;
        }
        if self.name.starts_with("test_") || self.name.contains("::test_") {
            return true;
        }
        if self
            .file_path
            .components()
            .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "__tests__")
        {
            return true;
        }
        self.file_path
            .file_stem()
            .map(|s| {
                let stem = s.to_string_lossy();
                stem.starts_with("test_") || stem.ends_with("_test")
            })
            .unwrap_or(false)
    }
}

/// Uniform source location for anything reportable (symbols, findings).
/// Lets CLI, MCP, and LSP share one location formatter instead of
/// each reaching into different structs.
pub trait DiagnosticLocation {
    fn file_path(&self) -> &std::path::Path;
    fn line(&self) -> usize;
}

impl DiagnosticLocation for Symbol {
    fn file_path(&self) -> &std::path::Path {
        &self.file_path
    }
    fn line(&self) -> usize {
        self.span.start_line
    }
}

/// Short `file:line` label shared by all reporters.
pub fn format_location<T: DiagnosticLocation + ?Sized>(item: &T) -> String {
    let file = item
        .file_path()
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| item.file_path().to_string_lossy().to_string());
    format!("{}:{}", file, item.line())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyEdgeKind {
    Calls,
    Instantiates,
    Implements,
    Imports,
    Inherits,
    ReferencesType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from_symbol: String,
    pub to_symbol: String,
    pub kind: DependencyEdgeKind,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlopKind {
    /// Wrapper function/class that only passes calls through with zero added value
    TollboothWrapper,
    /// Interface or trait with only 1 implementation, no mocks, and zero polymorphism
    GhostAbstraction,
    /// Functions or symbols unreachable from any public entrypoint
    DeadOrphan,
    /// Structurally duplicate logic across different symbols
    StructuralClone,
    /// Layers of barrel re-exports creating circular or deep indirection
    BarrelBloat,
    /// God object with outsized fan-in/fan-out and low cohesion
    GodObject,
    /// Architectural layer or forbidden boundary rule violation (ArchUnit-style)
    LayerViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchitectureConfig {
    pub layers: Vec<String>,
    pub forbidden_rules: Vec<ForbiddenRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenRule {
    pub from: String,
    pub to: String,
    pub description: Option<String>,
}

impl ArchitectureConfig {
    pub fn load_from_dir(root_dir: &std::path::Path) -> Option<Self> {
        let path = root_dir.join("deslop.toml");
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<ArchitectureConfig>(&content) {
                return Some(cfg);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlopFinding {
    pub kind: SlopKind,
    pub symbol_id: String,
    pub file_path: PathBuf,
    pub line: usize,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub estimated_lines_saved: usize,
}

impl DiagnosticLocation for SlopFinding {
    fn file_path(&self) -> &std::path::Path {
        &self.file_path
    }
    fn line(&self) -> usize {
        self.line
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodebaseStats {
    pub total_files: usize,
    pub total_lines_of_code: usize,
    pub total_symbols: usize,
    pub languages: Vec<(Language, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetrics {
    pub module_name: String,
    pub afferent_coupling: usize, // Ca: incoming dependencies from other modules
    pub efferent_coupling: usize, // Ce: outgoing dependencies to other modules
    pub instability: f64, // I = Ce / (Ca + Ce) [0.0 = completely stable, 1.0 = completely unstable]
    pub abstractness: f64, // A = abstract symbols / total symbols
    pub distance_from_main_seq: f64, // D = |A + I - 1| [0.0 = optimal balance, 1.0 = extreme pain or uselessness]
    pub classification: String,      // "Main Sequence", "Zone of Pain", "Zone of Uselessness"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominatorBottleneck {
    pub symbol_name: String,
    pub file_path: String,
    pub dominated_node_count: usize,
    pub downstream_reach_pct: f64,
    pub is_critical_chokepoint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepModuleScore {
    pub symbol_name: String,
    pub file_path: String,
    pub interface_complexity: usize,
    pub implementation_power: usize,
    pub depth_ratio: f64,
    pub is_deep: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepArchitectureReport {
    pub module_metrics: Vec<ModuleMetrics>,
    pub bottlenecks: Vec<DominatorBottleneck>,
    pub deep_module_scores: Vec<DeepModuleScore>,
    pub average_depth_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_symbol(name: &str, file: &str, attrs: Vec<String>) -> Symbol {
        Symbol {
            id: format!("{}::{}", file, name),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: PathBuf::from(file),
            span: SourceSpan::new(1, 1, 5, 2),
            visibility: Visibility::Private,
            loc: 5,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {}", name),
            is_pure_hint: false,
            ast_hash: None,
            attributes: attrs,
            is_trait_impl: false,
        }
    }

    #[test]
    fn test_entrypoint_heuristics() {
        // #[test] attribute wins regardless of name or location.
        assert!(test_symbol("parses", "lib.rs", vec!["test".to_string()]).is_test_entrypoint());
        // test_* naming.
        assert!(test_symbol("test_parse", "lib.rs", vec![]).is_test_entrypoint());
        // tests/ directory and test file stems.
        assert!(test_symbol("helper", "tests/integration.rs", vec![]).is_test_entrypoint());
        assert!(test_symbol("helper", "src/parser_test.rs", vec![]).is_test_entrypoint());
        // Ordinary private helpers are not tests.
        assert!(!test_symbol("helper", "src/lib.rs", vec![]).is_test_entrypoint());
        // `TestGenerator` contains "Test" but matches no test rule.
        assert!(!test_symbol("TestGenerator::emit", "testgen.rs", vec![]).is_test_entrypoint());
    }

    #[test]
    fn format_location_uses_file_stem_and_line() {
        let sym = test_symbol("run", "src/main.rs", vec![]);
        assert_eq!(format_location(&sym), "main.rs:1");
    }
}
