use crate::cache::{CachedFileEntry, CodebaseCache};
use crate::{FileParser, RustParser, UniversalParser};
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
                ".deslop",
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
        self.scan_cached(root, false)
    }

    pub fn scan_cached<P: AsRef<Path>>(
        &self,
        root: P,
        use_cache: bool,
    ) -> anyhow::Result<ParsedCodebase> {
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

        let old_cache = if use_cache {
            CodebaseCache::load(&root_path)
        } else {
            CodebaseCache::default()
        };

        // Phase 2: Parallel execution - reuse cached entries if content hash matches
        let parsed_entries: Vec<(PathBuf, CachedFileEntry)> = candidate_files
            .par_iter()
            .filter_map(|(path, lang)| {
                let mtime = CodebaseCache::get_file_mtime(path);
                let content_bytes = fs::read(path).ok()?;
                let content_hash = CodebaseCache::compute_hash(&content_bytes);

                // Check cache hit
                if let Some(cached) = old_cache.entries.get(path) {
                    if cached.content_hash == content_hash && cached.language == *lang {
                        return Some((path.clone(), cached.clone()));
                    }
                }

                // Cache miss: parse file
                let content_str = String::from_utf8_lossy(&content_bytes);
                let file_loc = content_str.lines().count();

                let (symbols, edges) = match lang {
                    Language::Rust => RustParser.parse(path, &content_str),
                    Language::TypeScript
                    | Language::JavaScript
                    | Language::Python
                    | Language::Go => UniversalParser::new(*lang).parse(path, &content_str),
                    Language::Unknown => (Vec::new(), Vec::new()),
                };

                let entry = CachedFileEntry {
                    content_hash,
                    modified_secs: mtime,
                    symbols,
                    edges,
                    loc: file_loc,
                    language: *lang,
                };

                Some((path.clone(), entry))
            })
            .collect();

        // Phase 3: Fast linear aggregation
        let mut new_cache = CodebaseCache::default();
        let total_files = parsed_entries.len();
        let mut symbols = Vec::new();
        let mut edges = Vec::new();
        let mut total_loc = 0;
        let mut lang_counts: HashMap<Language, usize> = HashMap::new();

        for (path, entry) in parsed_entries {
            total_loc += entry.loc;
            *lang_counts.entry(entry.language).or_insert(0) += 1;
            symbols.extend(entry.symbols.iter().cloned());
            edges.extend(entry.edges.iter().cloned());
            if use_cache {
                new_cache.entries.insert(path, entry);
            }
        }

        if use_cache {
            let _ = new_cache.save(&root_path);
        }

        let total_symbols = symbols.len();
        let mut languages_vec: Vec<(Language, usize)> = lang_counts.into_iter().collect();
        languages_vec.sort_by_key(|b| std::cmp::Reverse(b.1));

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
