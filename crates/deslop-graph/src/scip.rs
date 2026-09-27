use deslop_core::{DependencyEdge, DependencyEdgeKind, Symbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipIndex {
    pub metadata: ScipMetadata,
    pub documents: Vec<ScipDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipMetadata {
    pub version: i32,
    pub tool_info: ScipToolInfo,
    pub project_root: String,
    pub text_document_encoding: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipToolInfo {
    pub name: String,
    pub version: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipDocument {
    pub relative_path: String,
    pub language: String,
    pub occurrences: Vec<ScipOccurrence>,
    pub symbols: Vec<ScipSymbolInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipOccurrence {
    pub range: Vec<i32>, // [start_line, start_col, end_line, end_col]
    pub symbol: String,
    pub symbol_roles: i32, // 1 = Definition, 0 = Reference
    pub syntax_kind: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipSymbolInformation {
    pub symbol: String,
    pub documentation: Vec<String>,
    pub relationships: Vec<ScipRelationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScipRelationship {
    pub symbol: String,
    pub is_implementation: bool,
    pub is_reference: bool,
    pub is_type_definition: bool,
}

pub struct ScipGenerator;

impl ScipGenerator {
    pub fn generate(root_dir: &Path, symbols: &[Symbol], edges: &[DependencyEdge]) -> ScipIndex {
        let metadata = ScipMetadata {
            version: 1,
            tool_info: ScipToolInfo {
                name: "deslop".to_string(),
                version: "0.1.0".to_string(),
                arguments: vec!["scip".to_string()],
            },
            project_root: format!("file://{}", root_dir.display()),
            text_document_encoding: 1, // UTF-8
        };

        // Group outgoing edges by from_symbol
        let mut edge_map: HashMap<&str, Vec<&DependencyEdge>> = HashMap::new();
        for edge in edges {
            edge_map.entry(&edge.from_symbol).or_default().push(edge);
        }

        // Group symbols by relative file path
        let mut doc_map: HashMap<String, Vec<&Symbol>> = HashMap::new();
        for sym in symbols {
            let rel_path = sym
                .file_path
                .strip_prefix(root_dir)
                .unwrap_or(&sym.file_path)
                .to_string_lossy()
                .to_string();
            doc_map.entry(rel_path).or_default().push(sym);
        }

        let mut documents = Vec::new();

        for (rel_path, syms) in doc_map {
            let ext = Path::new(&rel_path)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let language = match ext {
                "rs" => "rust",
                "ts" | "tsx" => "typescript",
                "js" | "jsx" | "mjs" | "cjs" => "javascript",
                "py" => "python",
                "go" => "go",
                _ => "unknown",
            }
            .to_string();

            let mut occurrences = Vec::new();
            let mut scip_symbols = Vec::new();

            for s in syms {
                let scip_symbol_id = format!("deslop-pkg . {}::{}", s.file_path.display(), s.name);

                occurrences.push(ScipOccurrence {
                    range: vec![
                        s.span.start_line.saturating_sub(1) as i32,
                        s.span.start_col.saturating_sub(1) as i32,
                        s.span.end_line.saturating_sub(1) as i32,
                        s.span.end_col.saturating_sub(1) as i32,
                    ],
                    symbol: scip_symbol_id.clone(),
                    symbol_roles: 1, // Definition
                    syntax_kind: match s.kind {
                        deslop_core::SymbolKind::Function | deslop_core::SymbolKind::Method => 1,
                        deslop_core::SymbolKind::Class | deslop_core::SymbolKind::Struct => 2,
                        deslop_core::SymbolKind::Interface | deslop_core::SymbolKind::Trait => 3,
                        _ => 0,
                    },
                });

                let mut relationships = Vec::new();
                if let Some(out_edges) = edge_map.get(s.id.as_str()) {
                    for e in out_edges {
                        relationships.push(ScipRelationship {
                            symbol: e.to_symbol.clone(),
                            is_implementation: e.kind == DependencyEdgeKind::Implements,
                            is_reference: e.kind == DependencyEdgeKind::Calls,
                            is_type_definition: e.kind == DependencyEdgeKind::ReferencesType,
                        });
                    }
                }

                scip_symbols.push(ScipSymbolInformation {
                    symbol: scip_symbol_id,
                    documentation: if let Some(doc) = &s.doc {
                        vec![doc.clone()]
                    } else {
                        vec![s.signature.clone()]
                    },
                    relationships,
                });
            }

            documents.push(ScipDocument {
                relative_path: rel_path,
                language,
                occurrences,
                symbols: scip_symbols,
            });
        }

        documents.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        ScipIndex {
            metadata,
            documents,
        }
    }
}
