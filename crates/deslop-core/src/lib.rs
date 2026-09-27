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
    pub instability: f64,         // I = Ce / (Ca + Ce) [0.0 = completely stable, 1.0 = completely unstable]
    pub abstractness: f64,        // A = abstract symbols / total symbols
    pub distance_from_main_seq: f64, // D = |A + I - 1| [0.0 = optimal balance, 1.0 = extreme pain or uselessness]
    pub classification: String,   // "Main Sequence", "Zone of Pain", "Zone of Uselessness"
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

