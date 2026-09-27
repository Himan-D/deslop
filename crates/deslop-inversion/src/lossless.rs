use deslop_core::SourceSpan;

pub struct LosslessRewriter;

impl LosslessRewriter {
    /// Computes the exact range of lines to prune, including attached doc comments and attributes
    pub fn compute_symbol_pruning_bounds(lines: &[String], span: &SourceSpan) -> (usize, usize) {
        let mut start_idx = span.start_line.saturating_sub(1);
        let end_idx = span.end_line.min(lines.len());

        // Scan backwards to absorb attached doc comments and attributes
        while start_idx > 0 {
            let prev_line = lines[start_idx - 1].trim();
            if prev_line.starts_with("//!")
                || prev_line.to_lowercase().contains("copyright")
                || prev_line.to_lowercase().contains("license")
                || prev_line.contains("TODO")
                || prev_line.contains("FIXME")
            {
                break;
            }

            if prev_line.starts_with("///")
                || prev_line.starts_with("#[")
                || prev_line.starts_with("@")
                || (prev_line.starts_with("/*") && prev_line.ends_with("*/"))
                || prev_line.starts_with("//")
            {
                start_idx -= 1;
            } else {
                break;
            }
        }

        (start_idx, end_idx)
    }

    /// Surgically inlines a callee into a caller callsite while preserving indentation and arguments.
    /// Only replaces word-boundary matches that are actual callsites (followed
    /// by `(`, `::`, or `!`), so renaming `new` never corrupts `news` or `renew`.
    pub fn inline_callsite(source_line: &str, wrapper_name: &str, target_name: &str) -> String {
        if !source_line.contains(wrapper_name) {
            return source_line.to_string();
        }

        // Avoid replacing function definitions
        if source_line.contains(&format!("fn {}", wrapper_name))
            || source_line.contains(&format!("def {}", wrapper_name))
            || source_line.contains(&format!("function {}", wrapper_name))
        {
            return source_line.to_string();
        }

        let mut out = String::with_capacity(source_line.len());
        let mut rest = source_line;
        while let Some(pos) = rest.find(wrapper_name) {
            let (before, matched) = rest.split_at(pos);
            let after = &matched[wrapper_name.len()..];
            let left_ok = before
                .chars()
                .next_back()
                .map(|c| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(true);
            let right_ok = after
                .chars()
                .next()
                .map(|c| matches!(c, '(' | ':' | '!' | '<'))
                .unwrap_or(false);
            out.push_str(before);
            if left_ok && right_ok {
                out.push_str(target_name);
            } else {
                out.push_str(wrapper_name);
            }
            rest = after;
        }
        out.push_str(rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_replaces_callsites_not_substrings() {
        // Real callsite: replaced.
        assert_eq!(
            LosslessRewriter::inline_callsite("let x = scan(&dir);", "scan", "scan_cached"),
            "let x = scan_cached(&dir);"
        );
        // Identifier containing the name: untouched.
        assert_eq!(
            LosslessRewriter::inline_callsite("let scanner = build();", "scan", "scan_cached"),
            "let scanner = build();"
        );
        // Bare name that is not a call: untouched (conservative).
        assert_eq!(
            LosslessRewriter::inline_callsite("let f = scan;", "scan", "scan_cached"),
            "let f = scan;"
        );
        // The classic corruption case: renaming `new` must not touch `news`.
        assert_eq!(
            LosslessRewriter::inline_callsite("let news = renew(x);", "new", "default"),
            "let news = renew(x);"
        );
        // Known limitation: same-named callsites on other types share the
        // rename (precise resolution needs type info). `--verify` rollback
        // guards against breakage; without it the user reviews the diff.
        assert_eq!(
            LosslessRewriter::inline_callsite("let b = Box::new(x);", "new", "default"),
            "let b = Box::default(x);"
        );
    }

    #[test]
    fn inline_skips_function_definitions() {
        assert_eq!(
            LosslessRewriter::inline_callsite("pub fn scan(&self) {", "scan", "scan_cached"),
            "pub fn scan(&self) {"
        );
        assert_eq!(
            LosslessRewriter::inline_callsite("def scan(path):", "scan", "scan_cached"),
            "def scan(path):"
        );
    }
}
