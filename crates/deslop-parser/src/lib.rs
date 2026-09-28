pub mod cache;
pub mod rust_parser;
pub mod scanner;
pub mod universal_parser;

pub use cache::CodebaseCache;
pub use scanner::{CodebaseScanner, ParsedCodebase};

use deslop_core::{Language, ParsedFile};
use std::path::Path;

/// Abstraction over per-language file parsers. Lets callers swap or mock the
/// parser (e.g. in tests) instead of depending on concrete parse functions.
pub trait FileParser {
    fn language(&self) -> Language;
    fn parse(&self, path: &Path, content: &str) -> ParsedFile;
}

/// `syn`-based Rust parser.
pub struct RustParser;

impl FileParser for RustParser {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn parse(&self, path: &Path, content: &str) -> ParsedFile {
        rust_parser::parse_rust_file(path, content).unwrap_or_default()
    }
}

/// Tree-sitter parser for TypeScript, JavaScript, Python, and Go.
pub struct UniversalParser {
    language: Language,
}

impl UniversalParser {
    pub fn new(language: Language) -> Self {
        Self { language }
    }
}

impl FileParser for UniversalParser {
    fn language(&self) -> Language {
        self.language
    }

    fn parse(&self, path: &Path, content: &str) -> ParsedFile {
        universal_parser::parse_universal_file(path, content, self.language)
    }
}
