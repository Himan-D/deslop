use deslop_core::{DependencyEdge, Language, Symbol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const CACHE_VERSION: u32 = 2;
const CACHE_DIR_NAME: &str = ".deslop";
const CACHE_FILE_NAME: &str = "cache.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFileEntry {
    pub content_hash: String,
    pub modified_secs: u64,
    pub symbols: Vec<Symbol>,
    pub edges: Vec<DependencyEdge>,
    pub loc: usize,
    pub language: Language,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodebaseCache {
    pub version: u32,
    pub entries: HashMap<PathBuf, CachedFileEntry>,
}

impl Default for CodebaseCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            entries: HashMap::new(),
        }
    }
}

impl CodebaseCache {
    pub fn load(root_dir: &Path) -> Self {
        let cache_file = root_dir.join(CACHE_DIR_NAME).join(CACHE_FILE_NAME);
        if let Ok(data) = fs::read_to_string(&cache_file) {
            if let Ok(cache) = serde_json::from_str::<CodebaseCache>(&data) {
                if cache.version == CACHE_VERSION {
                    return cache;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self, root_dir: &Path) -> anyhow::Result<()> {
        let cache_dir = root_dir.join(CACHE_DIR_NAME);
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }
        let cache_file = cache_dir.join(CACHE_FILE_NAME);
        let serialized = serde_json::to_string(self)?;
        fs::write(cache_file, serialized)?;
        Ok(())
    }

    pub fn compute_hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    pub fn get_file_mtime(path: &Path) -> u64 {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(mtime) = metadata.modified() {
                if let Ok(duration) = mtime.duration_since(UNIX_EPOCH) {
                    return duration.as_secs();
                }
            }
        }
        0
    }
}
