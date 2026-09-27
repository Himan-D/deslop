use crate::rust_parser::parse_rust_file;
use crate::universal_parser::parse_universal_file;
use deslop_core::{CodebaseStats, DependencyEdge, Language, Symbol};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ParsedCodebase {
    pub root_dir: PathBuf,
    pub symbols: Vec<Symbol>,
    pub edges: Vec<DependencyEdge>,
    pub stats: CodebaseStats,
}

pub struct CodebaseScanner {
    ignored_dirs: Vec<&'static str>,
}

impl Default for CodebaseScanner {
    fn default() -> Self {
        Self {
            ignored_dirs: vec![
                ".git",
                "node_modules",
                "target",
                "dist",
                "build",
                ".next",
                ".turbo",
                "vendor",
                ".venv",
                "__pycache__",
                ".idea",
                ".vscode",
            ],
        }
    }
}

impl CodebaseScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan<P: AsRef<Path>>(&self, root: P) -> anyhow::Result<ParsedCodebase> {
        let root_path = root.as_ref().to_path_buf();

        // Phase 1: Fast directory walk to collect candidate files
        let candidate_files: Vec<(PathBuf, Language)> = WalkDir::new(&root_path)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !self.ignored_dirs.iter().any(|d| name == *d)
            })
            .filter_map(|e| e.ok())
            .filter_map(|entry| {
                let path = entry.path();
                if !path.is_file() {
                    return None;
                }
                let ext = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                let lang = Language::from_extension(&ext);
                if lang != Language::Unknown {
                    Some((path.to_path_buf(), lang))
                } else {
                    None
                }
            })
            .collect();

        // Phase 2: Parallel Rayon execution across all CPU cores
        let parsed_chunks: Vec<(Vec<Symbol>, Vec<DependencyEdge>, usize, Language)> = candidate_files
            .par_iter()
            .filter_map(|(path, lang)| {
                let content = fs::read_to_string(path).ok()?;
                let file_loc = content.lines().count();

                let (symbols, edges) = match lang {
                    Language::Rust => parse_rust_file(path, &content).unwrap_or_default(),
                    Language::TypeScript | Language::JavaScript | Language::Python | Language::Go => {
                        parse_universal_file(path, &content, *lang)
                    }
                    Language::Unknown => (Vec::new(), Vec::new()),
                };

                Some((symbols, edges, file_loc, *lang))
            })
            .collect();

        // Phase 3: Fast linear aggregation
        let total_files = parsed_chunks.len();
        let mut symbols = Vec::new();
        let mut edges = Vec::new();
        let mut total_loc = 0;
        let mut lang_counts: HashMap<Language, usize> = HashMap::new();

        for (mut s, mut e, loc, lang) in parsed_chunks {
            symbols.append(&mut s);
            edges.append(&mut e);
            total_loc += loc;
            *lang_counts.entry(lang).or_insert(0) += 1;
        }

        let total_symbols = symbols.len();
        let mut languages_vec: Vec<(Language, usize)> = lang_counts.into_iter().collect();
        languages_vec.sort_by(|a, b| b.1.cmp(&a.1));

        let stats = CodebaseStats {
            total_files,
            total_lines_of_code: total_loc,
            total_symbols,
            languages: languages_vec,
        };

        Ok(ParsedCodebase {
            root_dir: root_path,
            symbols,
            edges,
            stats,
        })
    }
}
