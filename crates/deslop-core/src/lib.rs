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
