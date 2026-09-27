use deslop_core::SourceSpan;

pub struct LosslessRewriter;

impl LosslessRewriter {
    /// Computes the exact range of lines to prune, including attached doc comments and attributes
    pub fn compute_symbol_pruning_bounds(
        lines: &[String],
        span: &SourceSpan,
    ) -> (usize, usize) {
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

    /// Surgically inlines a callee into a caller callsite while preserving indentation and arguments
    pub fn inline_callsite(
        source_line: &str,
        wrapper_name: &str,
        target_name: &str,
    ) -> String {
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

        source_line.replace(wrapper_name, target_name)
    }
}
