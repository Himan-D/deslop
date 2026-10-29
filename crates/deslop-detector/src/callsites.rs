//! Conservative textual index of identifiers that are referenced somewhere.
//!
//! The dependency graph resolves calls by name and misses many uses of a
//! symbol: method calls on values (`config.is_fixed_strings(x)`), types used
//! as literals (`responseWriter{}`), statics, and fields. Dead-code and
//! inlining decisions therefore also consult this index: any occurrence of a
//! name outside its own definition counts as a reference. The index can only
//! hide findings, never invent them, which keeps the detectors conservative.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Keywords whose following identifier is a definition, not a reference.
const DEFINITION_KEYWORDS: &[&str] = &[
    "fn",
    "def",
    "function",
    "func",
    "class",
    "struct",
    "enum",
    "trait",
    "type",
    "var",
    "const",
    "let",
    "static",
    "mod",
    "interface",
    "namespace",
    "union",
];

/// Identifiers used in `source`, excluding the names being defined.
pub fn call_site_identifiers(source: &str) -> HashSet<String> {
    let mut found = HashSet::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        // Go method definitions: `func (r *T) name(` — the first identifier after
        // the receiver's closing paren is the defined name, not a reference.
        let go_name_from = if trimmed.starts_with("func (") {
            line.find(')').map(|i| i + 1)
        } else {
            None
        };
        scan_line(line, go_name_from, &mut found);
    }
    found
}

fn scan_line(line: &str, go_name_from: Option<usize>, found: &mut HashSet<String>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut prev_word: Option<&str> = None;
    let mut go_name_pending = go_name_from;
    while i < bytes.len() {
        let c = bytes[i];
        if !is_ident_byte(c) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident_byte(bytes[i]) {
            i += 1;
        }
        let word = &line[start..i];
        if word.as_bytes()[0].is_ascii_digit() {
            prev_word = Some(word);
            continue;
        }
        let go_defined_name = match go_name_pending {
            Some(from) if start >= from => {
                go_name_pending = None;
                true
            }
            _ => false,
        };
        let is_definition =
            go_defined_name || prev_word.is_some_and(|w| DEFINITION_KEYWORDS.contains(&w));
        if !is_definition {
            found.insert(word.to_string());
        }
        prev_word = Some(word);
    }
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The last path segment of a symbol name: `Config::is_fixed` -> `is_fixed`,
/// `Foo.bar` -> `bar`.
pub fn bare_name(name: &str) -> &str {
    let after_colons = name.rsplit("::").next().unwrap_or(name);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

/// Maps each identifier to the set of files where it appears in call position.
#[derive(Debug, Default, Clone)]
pub struct CallSiteIndex {
    refs: HashMap<String, BTreeSet<PathBuf>>,
}

impl CallSiteIndex {
    /// Builds the index from `(path, source)` pairs.
    pub fn build<'a, I>(files: I) -> Self
    where
        I: IntoIterator<Item = (&'a Path, &'a str)>,
    {
        let mut refs: HashMap<String, BTreeSet<PathBuf>> = HashMap::new();
        for (path, source) in files {
            for ident in call_site_identifiers(source) {
                refs.entry(ident).or_default().insert(path.to_path_buf());
            }
        }
        Self { refs }
    }

    /// True when the symbol's bare name is used in call position in any file.
    pub fn referenced(&self, symbol_name: &str) -> bool {
        self.refs.contains_key(bare_name(symbol_name))
    }

    /// Files other than `own_file` where the symbol's bare name is used.
    pub fn files_referencing_outside(&self, symbol_name: &str, own_file: &Path) -> Vec<PathBuf> {
        self.refs
            .get(bare_name(symbol_name))
            .map(|files| {
                files
                    .iter()
                    .filter(|f| f.as_path() != own_file)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_method_calls_on_values() {
        let ids = call_site_identifiers("let hir = if config.is_fixed_strings(patterns) {");
        assert!(ids.contains("is_fixed_strings"));
    }

    #[test]
    fn non_call_uses_count_as_references() {
        // A type used as a literal, a static used by value, and a field read.
        assert!(call_site_identifiers("w := &responseWriter{}").contains("responseWriter"));
        assert!(
            call_site_identifiers("#[global_allocator] static X: A = ALLOC;").contains("ALLOC")
        );
        assert!(call_site_identifiers("let n = self.methodTrees.len();").contains("methodTrees"));
    }

    #[test]
    fn definitions_are_not_references() {
        let ids = call_site_identifiers("    fn is_fixed_strings<P>(&self, p: &[P]) -> bool {");
        assert!(!ids.contains("is_fixed_strings"));
        let ids = call_site_identifiers("def helper(x):\n    return x");
        assert!(!ids.contains("helper"));
        let ids = call_site_identifiers("function render(x) {");
        assert!(!ids.contains("render"));
    }

    #[test]
    fn go_method_definition_is_not_a_reference() {
        let ids = call_site_identifiers("func (r *Router) Handle(path string) {");
        assert!(!ids.contains("Handle"));
        let ids = call_site_identifiers("\tr.Handle(path)");
        assert!(ids.contains("Handle"));
    }

    #[test]
    fn path_and_method_value_references_count() {
        let ids = call_site_identifiers("let f = Self::normalize;");
        assert!(ids.contains("normalize"));
    }

    #[test]
    fn a_name_is_not_a_reference_to_its_own_definition() {
        let ids = call_site_identifiers("pub const ALLOC: Alloc = Alloc;");
        assert!(!ids.contains("ALLOC"));
        assert!(ids.contains("Alloc"));
    }

    #[test]
    fn bare_name_strips_qualifiers() {
        assert_eq!(bare_name("Config::is_fixed"), "is_fixed");
        assert_eq!(bare_name("ZodString.isDatetime"), "isDatetime");
        assert_eq!(bare_name("plain"), "plain");
    }

    #[test]
    fn index_reports_outside_references() {
        let a = Path::new("a.rs");
        let b = Path::new("b.rs");
        let index = CallSiteIndex::build(vec![
            (a, "fn only_here() {}\nfn caller() { only_here(); }"),
            (b, "fn other() { crate::helper(); }"),
        ]);
        assert!(index.referenced("only_here"));
        assert!(index.referenced("helper"));
        assert!(!index.referenced("unused"));
        assert!(index.files_referencing_outside("only_here", a).is_empty());
        assert_eq!(
            index.files_referencing_outside("helper", a),
            vec![PathBuf::from("b.rs")]
        );
        assert_eq!(
            index.files_referencing_outside("only_here", b),
            vec![PathBuf::from("a.rs")]
        );
    }
}
