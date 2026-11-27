use crate::{DetectionContext, DetectionRule};
use deslop_core::{Severity, SlopFinding, SlopKind, Symbol, AUX_PATH_ATTR};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const RULE_HARDCODED_SECRET: &str = "hardcoded-secret";
const RULE_INJECTION_SINK: &str = "injection-sink";
const RULE_UNSAFE_DESERIALIZATION: &str = "unsafe-deserialization";
const RULE_WEAK_CRYPTO: &str = "weak-crypto";
const RULE_UNSAFE_AUDIT: &str = "unsafe-audit";

/// Scans source files for common security anti-patterns, hardcoded secrets,
/// injection sinks, unsafe deserialization, weak cryptography, and unaudited
/// `unsafe` / insecure transport or DOM sinks.
pub struct SecurityRule;

impl DetectionRule for SecurityRule {
    fn rule_name(&self) -> &'static str {
        "security"
    }

    fn detect(&self, ctx: &DetectionContext) -> Vec<SlopFinding> {
        let sec_cfg = ctx.config.map(|c| &c.security);
        if sec_cfg.is_some_and(|s| !s.enabled) {
            return Vec::new();
        }

        let is_ignored_rule = |rule_id: &str| -> bool {
            sec_cfg.is_some_and(|s| {
                s.ignore_rules
                    .iter()
                    .any(|r| r.trim().eq_ignore_ascii_case(rule_id))
            })
        };

        let check_secret = !is_ignored_rule(RULE_HARDCODED_SECRET);
        let check_injection = !is_ignored_rule(RULE_INJECTION_SINK);
        let check_deser = !is_ignored_rule(RULE_UNSAFE_DESERIALIZATION);
        let check_crypto = !is_ignored_rule(RULE_WEAK_CRYPTO);
        let check_unsafe = !is_ignored_rule(RULE_UNSAFE_AUDIT);

        if !check_secret && !check_injection && !check_deser && !check_crypto && !check_unsafe {
            return Vec::new();
        }

        // Deduplicate unique file_paths from ctx.symbols in deterministic order,
        // tracking whether each file has at least one non-test/non-aux symbol.
        let mut files: BTreeMap<PathBuf, Vec<&Symbol>> = BTreeMap::new();
        for sym in ctx.symbols {
            files.entry(sym.file_path.clone()).or_default().push(sym);
        }

        let mut findings = Vec::new();

        for (path, syms) in files {
            if syms.iter().all(|s| is_test_or_aux(s)) {
                continue;
            }
            if is_skipped_path(&path) {
                continue;
            }
            let path_str = path.to_string_lossy();
            if sec_cfg.is_some_and(|s| {
                s.ignore_paths
                    .iter()
                    .any(|pat| super::architecture::matches_pattern(&path_str, pat))
            }) {
                continue;
            }

            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let lines: Vec<&str> = content.lines().collect();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();

            let is_rust = ext == "rs";
            let is_python = ext == "py";
            let is_js_family = matches!(ext.as_str(), "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs");

            let mut in_block_comment = false;
            let mut in_py_docstring: Option<&'static str> = None;
            let mut tainted_vars: HashSet<String> = HashSet::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if update_multiline_comment_state(
                    trimmed,
                    is_python,
                    &mut in_block_comment,
                    &mut in_py_docstring,
                ) {
                    continue;
                }
                if trimmed.is_empty() || is_comment_line(trimmed) {
                    continue;
                }

                if check_injection {
                    if let Some(var_name) = detect_tainted_assignment(line) {
                        tainted_vars.insert(var_name);
                    }
                }

                let line_num = idx + 1;
                let snippet = truncate_snippet(trimmed, 160);
                let symbol_id = symbol_id_for_line(&path, &syms, line_num);

                if check_secret {
                    if let Some((severity, detail)) = detect_hardcoded_secret(line) {
                        findings.push(SlopFinding {
                            kind: SlopKind::HardcodedSecret,
                            symbol_id: symbol_id.clone(),
                            file_path: path.clone(),
                            line: line_num,
                            severity,
                            confidence: 0.9,
                            title: "Hardcoded Secret".to_string(),
                            description: format!("{detail} `{snippet}`"),
                            remediation: "Move secrets to environment variables or a secrets manager instead of hardcoding them in source.".to_string(),
                            estimated_lines_saved: 0,
                            inline_target: None,
                        });
                    }
                }

                if check_injection {
                    if let Some(detail) = detect_injection_sink(&lines, idx, &tainted_vars) {
                        findings.push(SlopFinding {
                            kind: SlopKind::InjectionSink,
                            symbol_id: symbol_id.clone(),
                            file_path: path.clone(),
                            line: line_num,
                            severity: Severity::High,
                            confidence: 0.85,
                            title: "Potential Injection Sink".to_string(),
                            description: format!("{detail} `{snippet}`"),
                            remediation: "Avoid dynamic code evaluation, shell invocation with `-c`/`shell=True`, or string-interpolated SQL; use parameterized queries and direct argument arrays.".to_string(),
                            estimated_lines_saved: 0,
                            inline_target: None,
                        });
                    }
                }

                if check_deser {
                    if let Some(detail) = detect_unsafe_deserialization(line) {
                        findings.push(SlopFinding {
                            kind: SlopKind::UnsafeDeserialization,
                            symbol_id: symbol_id.clone(),
                            file_path: path.clone(),
                            line: line_num,
                            severity: Severity::High,
                            confidence: 0.85,
                            title: "Unsafe Deserialization".to_string(),
                            description: format!("{detail} `{snippet}`"),
                            remediation: "Use safe deserialization alternatives such as `json.loads` or `yaml.safe_load` / `SafeLoader`.".to_string(),
                            estimated_lines_saved: 0,
                            inline_target: None,
                        });
                    }
                }

                if check_crypto {
                    if let Some(detail) = detect_weak_crypto(line) {
                        findings.push(SlopFinding {
                            kind: SlopKind::WeakCrypto,
                            symbol_id: symbol_id.clone(),
                            file_path: path.clone(),
                            line: line_num,
                            severity: Severity::Medium,
                            confidence: 0.85,
                            title: "Weak Cryptography".to_string(),
                            description: format!("{detail} `{snippet}`"),
                            remediation: "Use modern cryptographic primitives (e.g. SHA-256+, Argon2/bcrypt for passwords, and a CSPRNG for tokens/sessions).".to_string(),
                            estimated_lines_saved: 0,
                            inline_target: None,
                        });
                    }
                }

                if check_unsafe {
                    if let Some((severity, confidence, detail)) =
                        detect_unsafe_audit(&lines, idx, is_rust, is_js_family)
                    {
                        findings.push(SlopFinding {
                            kind: SlopKind::UnsafeAudit,
                            symbol_id,
                            file_path: path.clone(),
                            line: line_num,
                            severity,
                            confidence,
                            title: "Unsafe / Insecure Audit Finding".to_string(),
                            description: format!("{detail} `{snippet}`"),
                            remediation: "Document `// SAFETY:` invariants above `unsafe` blocks, avoid `dangerouslySetInnerHTML` with untrusted data, enable TLS certificate verification, avoid wildcard CORS with credentials, and use `https://` for non-local URLs.".to_string(),
                            estimated_lines_saved: 0,
                            inline_target: None,
                        });
                    }
                }
            }
        }

        findings
    }
}

fn is_skipped_path(path: &Path) -> bool {
    let norm = path.to_string_lossy().replace('\\', "/");
    norm.split('/').any(|seg| {
        matches!(
            seg,
            "tests" | "__tests__" | "fixtures" | "benches" | "bench" | "testdata"
        )
    })
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || (trimmed.starts_with('#') && !trimmed.starts_with("#[") && !trimmed.starts_with("#!["))
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

/// Updates multi-line block-comment (`/* ... */`) and Python docstring (`"""` / `'''`)
/// state across lines. Returns `true` if the current line should be skipped entirely.
fn update_multiline_comment_state(
    trimmed: &str,
    is_python: bool,
    in_block_comment: &mut bool,
    in_py_docstring: &mut Option<&'static str>,
) -> bool {
    if is_python {
        if let Some(delim) = *in_py_docstring {
            if trimmed.contains(delim) {
                *in_py_docstring = None;
            }
            return true;
        }
        for delim in ["\"\"\"", "'''"] {
            if let Some(rest) = trimmed.strip_prefix(delim) {
                if !rest.contains(delim) {
                    *in_py_docstring = Some(delim);
                }
                return true;
            }
            if trimmed.matches(delim).count() % 2 == 1 {
                *in_py_docstring = Some(delim);
                return false;
            }
        }
        return false;
    }

    let bytes = trimmed.as_bytes();
    let mut i = 0;
    let mut started_with_block = false;
    let mut has_code_outside_block = false;
    let mut quote: Option<u8> = None;
    let mut escaped = false;

    if *in_block_comment {
        if let Some(end_pos) = trimmed.find("*/") {
            *in_block_comment = false;
            i = end_pos + 2;
            if trimmed[i..].trim().is_empty() {
                return true;
            }
        } else {
            return true;
        }
    }

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }

        if b == b'"' || b == b'\'' || b == b'`' {
            has_code_outside_block = true;
            quote = Some(b);
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                break;
            }
            if bytes[i + 1] == b'*' {
                if i == 0 {
                    started_with_block = true;
                }
                if let Some(rel_end) = trimmed[i + 2..].find("*/") {
                    i = i + 2 + rel_end + 2;
                    continue;
                } else {
                    *in_block_comment = true;
                    return started_with_block && !has_code_outside_block;
                }
            }
        }

        if !b.is_ascii_whitespace() {
            has_code_outside_block = true;
        }
        i += 1;
    }

    started_with_block && !has_code_outside_block
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn is_test_or_aux(sym: &Symbol) -> bool {
    sym.is_test_code() || sym.attributes.iter().any(|a| a == AUX_PATH_ATTR)
}

fn symbol_id_for_line(path: &Path, syms: &[&Symbol], line_num: usize) -> String {
    syms.iter()
        .find(|s| {
            !is_test_or_aux(s) && line_num >= s.span.start_line && line_num <= s.span.end_line
        })
        .map(|s| s.id.clone())
        .unwrap_or_else(|| format!("{}::L{}", path.display(), line_num))
}

fn has_word_boundary_before(s: &str, byte_idx: usize) -> bool {
    if byte_idx == 0 {
        return true;
    }
    s[..byte_idx]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
}

fn detect_hardcoded_secret(line: &str) -> Option<(Severity, &'static str)> {
    // Known key prefixes (constructed with concat! so this file never self-triggers).
    let aws_prefix = concat!("AK", "IA");
    if has_prefixed_token(line, aws_prefix, 16, false) {
        return Some((
            Severity::Critical,
            "Detected hardcoded AWS access key prefix:",
        ));
    }

    let gh_prefix = concat!("gh", "p_");
    if has_prefixed_token(line, gh_prefix, 20, false) {
        return Some((
            Severity::Critical,
            "Detected hardcoded GitHub personal access token:",
        ));
    }

    let sk_prefix = concat!("s", "k-");
    if has_prefixed_token(line, sk_prefix, 20, true) {
        return Some((
            Severity::Critical,
            "Detected hardcoded `sk-` API key literal:",
        ));
    }

    let pem_begin = concat!("-----BE", "GIN ");
    let pem_end = concat!("PRIVATE ", "KEY-----");
    if line.contains(pem_begin) && line.contains(pem_end) {
        return Some((Severity::Critical, "Detected embedded private key header:"));
    }

    // Assignment to secret-named vars with a quoted string literal >= 16 chars.
    let lower = line.to_ascii_lowercase();
    let secret_vars = [
        "api_key",
        "jwt_secret",
        "secret_key",
        "private_key",
        "auth_token",
    ];
    for var in secret_vars {
        let mut search_from = 0;
        while let Some(rel_idx) = lower[search_from..].find(var) {
            let idx = search_from + rel_idx;
            let after_idx = idx + var.len();
            search_from = after_idx;

            if !has_word_boundary_before(&lower, idx) {
                continue;
            }
            let after = &lower[after_idx..];
            if after
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }

            // Look for `=` or `:` after the variable name, then a quoted literal.
            let rest = line[after_idx..].trim_start();
            let rest = if let Some(r) = rest.strip_prefix('=') {
                r.trim_start()
            } else if let Some(r) = rest.strip_prefix(':') {
                r.trim_start()
            } else {
                continue;
            };

            if let Some(literal) = extract_quoted_literal(rest) {
                if literal.len() >= 16 && !is_placeholder_secret(literal) {
                    return Some((
                        Severity::High,
                        "Detected hardcoded secret assignment to sensitive variable:",
                    ));
                }
            }
        }
    }

    None
}

fn has_prefixed_token(
    line: &str,
    prefix: &str,
    min_tail_alnum: usize,
    disallow_dash_before: bool,
) -> bool {
    let mut start = 0;
    while let Some(rel) = line[start..].find(prefix) {
        let idx = start + rel;
        let tail_start = idx + prefix.len();
        start = tail_start;

        if !has_word_boundary_before(line, idx) {
            continue;
        }
        if disallow_dash_before && line[..idx].ends_with('-') {
            continue;
        }

        let tail_count = line[tail_start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count();
        if tail_count >= min_tail_alnum {
            return true;
        }
    }
    false
}

fn extract_quoted_literal(s: &str) -> Option<&str> {
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &s[quote.len_utf8()..];
    let mut escaped = false;
    for (byte_idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some(&inner[..byte_idx]);
        }
    }
    None
}

fn is_placeholder_secret(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "test",
        "example",
        "dummy",
        "changeme",
        "xxx",
        "placeholder",
        "your-",
    ];
    PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

fn has_interp_or_concat(s: &str) -> bool {
    s.contains('+')
        || s.contains("${")
        || s.contains("f\"")
        || s.contains("f'")
        || s.contains(concat!("for", "mat!("))
        || s.contains(".format(")
        || s.contains("fmt.Sprintf(")
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    if let Some(pos) = line.find(":=") {
        return Some((&line[..pos], &line[pos + 2..]));
    }
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        let prev = i.checked_sub(1).map(|p| bytes[p]);
        let next = bytes.get(i + 1).copied();
        if matches!(prev, Some(b'=') | Some(b'!') | Some(b'<') | Some(b'>')) {
            continue;
        }
        if matches!(next, Some(b'=') | Some(b'>')) {
            continue;
        }
        return Some((&line[..i], &line[i + 1..]));
    }
    None
}

fn detect_tainted_assignment(line: &str) -> Option<String> {
    let (lhs, rhs) = split_assignment(line)?;
    if !has_interp_or_concat(rhs) {
        return None;
    }

    let lhs_no_type = lhs.split(':').next().unwrap_or(lhs);
    let var = lhs_no_type.split_whitespace().last()?;
    if var.is_empty()
        || !var
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }

    let upper_rhs = rhs.to_ascii_uppercase();
    let is_sql = ["SELECT ", "INSERT ", "UPDATE ", "DELETE "]
        .iter()
        .any(|kw| upper_rhs.contains(kw));
    let lower_var = var.to_ascii_lowercase();
    let is_shell = [
        "rm ", "sh ", "bash ", "zsh ", "curl ", "wget ", "ls ", "cat ", "echo ", "mkdir ", "cp ",
        "mv ", "chmod ", "chown ", "kill ", "-c ", "&&", "| ",
    ]
    .iter()
    .any(|tok| rhs.contains(tok))
        || lower_var.contains("cmd")
        || lower_var.contains("command")
        || lower_var.contains("shell");

    if is_sql || is_shell {
        Some(var.to_string())
    } else {
        None
    }
}

fn detect_tainted_sink(line: &str, tainted_vars: &HashSet<String>) -> Option<&'static str> {
    if tainted_vars.is_empty() {
        return None;
    }

    let sink_calls = [
        concat!("exec", "ute("),
        concat!("que", "ry("),
        concat!("ra", "w("),
        concat!("os.", "system("),
        concat!("sub", "process.run("),
        concat!("sub", "process.Popen("),
        concat!("sub", "process.call("),
        concat!("sub", "process.check_output("),
    ];

    for call in sink_calls {
        for (pos, _) in line.match_indices(call) {
            if !has_word_boundary_before(line, pos) {
                continue;
            }
            let args_start = pos + call.len();
            let args = &line[args_start..];
            if tainted_vars
                .iter()
                .any(|var| contains_identifier(args, var))
            {
                return Some("Detected sink call passing tainted interpolated variable:");
            }
        }
    }

    None
}

fn detect_injection_sink(
    lines: &[&str],
    idx: usize,
    tainted_vars: &HashSet<String>,
) -> Option<&'static str> {
    let line = lines[idx];

    // JS/TS/Python dynamic code evaluation
    let eval_call = concat!("ev", "al(");
    if let Some(pos) = line.find(eval_call) {
        if has_word_boundary_before(line, pos) {
            return Some("Detected dynamic `eval(` call:");
        }
    }

    let new_fn = concat!("new ", "Function(");
    if line.contains(new_fn) {
        return Some("Detected dynamic `new Function(` call:");
    }

    // Python shell execution
    let subproc = concat!("sub", "process.");
    let shell_true = concat!("shell=", "True");
    if line.contains(subproc) && line.contains(shell_true) {
        return Some("Detected `subprocess` call with `shell=True`:");
    }

    let os_sys = concat!("os.", "system(");
    if line.contains(os_sys) {
        return Some("Detected `os.system(` shell execution:");
    }

    // Rust Command::new("sh") / Command::new("bash") with "-c"
    let cmd_sh = concat!("Command::new(", "\"sh\")");
    let cmd_bash = concat!("Command::new(", "\"bash\")");
    if line.contains(cmd_sh) || line.contains(cmd_bash) {
        let end = (idx + 3).min(lines.len());
        if lines[idx..end].iter().any(|l| l.contains("\"-c\"")) {
            return Some("Detected shell `Command::new` invocation with `\"-c\"`:");
        }
    }

    // SQL query calls with string concatenation or interpolation
    let sql_calls = [
        concat!("exec", "ute("),
        concat!("que", "ry("),
        concat!("ra", "w("),
    ];
    let has_sql_call = sql_calls.iter().any(|call| {
        line.match_indices(call)
            .any(|(pos, _)| has_word_boundary_before(line, pos))
    });
    if has_sql_call && has_interp_or_concat(line) {
        let upper = line.to_ascii_uppercase();
        let has_sql_kw = ["SELECT ", "INSERT ", "UPDATE ", "DELETE "]
            .iter()
            .any(|kw| upper.contains(kw));
        if has_sql_kw {
            return Some("Detected SQL query call with string interpolation/concatenation:");
        }
    }

    detect_tainted_sink(line, tainted_vars)
}

fn detect_unsafe_deserialization(line: &str) -> Option<&'static str> {
    let pickle_loads = concat!("pickle.", "loads(");
    let pickle_load = concat!("pickle.", "load(");
    if line.contains(pickle_loads) || line.contains(pickle_load) {
        return Some("Detected unsafe `pickle` deserialization:");
    }

    let yaml_load = concat!("yaml.", "load(");
    if line.contains(yaml_load) && !line.contains("SafeLoader") {
        return Some("Detected `yaml.load(` without `SafeLoader`:");
    }

    None
}

fn detect_weak_crypto(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();

    let has_weak_hash = contains_identifier(&lower, "md5") || contains_identifier(&lower, "sha1");
    if has_weak_hash
        && ["password", "token", "secret", "auth"]
            .iter()
            .any(|kw| lower.contains(kw))
    {
        return Some("Detected weak hash (`md5`/`sha1`) in security-sensitive context:");
    }

    let math_random = concat!("Math.", "random()");
    if line.contains(math_random)
        && ["token", "secret", "auth", "session"]
            .iter()
            .any(|kw| lower.contains(kw))
    {
        return Some("Detected `Math.random()` in security-sensitive context:");
    }

    None
}

fn contains_identifier(lower: &str, ident: &str) -> bool {
    let mut start = 0;
    while let Some(rel) = lower[start..].find(ident) {
        let idx = start + rel;
        let end = idx + ident.len();
        start = end;
        if !has_word_boundary_before(lower, idx) {
            continue;
        }
        if lower[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        return true;
    }
    false
}

fn detect_unsafe_audit(
    lines: &[&str],
    idx: usize,
    is_rust: bool,
    is_js_family: bool,
) -> Option<(Severity, f64, &'static str)> {
    let line = lines[idx];

    if line.contains("verify=False")
        || line.contains("verify = False")
        || line.contains("rejectUnauthorized: false")
        || line.contains("rejectUnauthorized:false")
        || line.contains("danger_accept_invalid_certs(true)")
    {
        return Some((
            Severity::High,
            0.9,
            "Detected disabled TLS certificate verification:",
        ));
    }

    if line.contains("Access-Control-Allow-Origin") && line.contains('*') {
        let start = idx.saturating_sub(1);
        let end = (idx + 1).min(lines.len().saturating_sub(1));
        let has_credentials = lines[start..=end].iter().any(|l| {
            l.contains("credentials: true")
                || l.contains("credentials:true")
                || l.contains("allow_credentials(true)")
        });
        if has_credentials {
            return Some((
                Severity::Medium,
                0.85,
                "Detected wildcard CORS `Access-Control-Allow-Origin: *` with credentials enabled:",
            ));
        }
    }

    if is_rust && has_rust_unsafe(line) {
        let start = idx.saturating_sub(2);
        let has_safety = lines[start..=idx].iter().any(|l| l.contains("SAFETY:"));
        if !has_safety {
            return Some((
                Severity::Medium,
                0.85,
                "Detected Rust `unsafe` without a `SAFETY:` comment:",
            ));
        }
    }

    if is_js_family {
        let dangerous_html = concat!("dangerously", "SetInnerHTML");
        if line.contains(dangerous_html) {
            return Some((
                Severity::Medium,
                0.85,
                "Detected `dangerouslySetInnerHTML` DOM sink:",
            ));
        }
    }

    if has_non_local_http_literal(line) {
        return Some((
            Severity::Medium,
            0.85,
            "Detected non-localhost `http://` URL literal:",
        ));
    }

    None
}

fn has_rust_unsafe(line: &str) -> bool {
    for pat in ["unsafe {", "unsafe{", "unsafe fn "] {
        if let Some(pos) = line.find(pat) {
            if has_word_boundary_before(line, pos) {
                return true;
            }
        }
    }
    false
}

fn has_non_local_http_literal(line: &str) -> bool {
    let http_prefix = concat!("ht", "tp://");
    let safe_prefixes = [
        concat!("ht", "tp://localhost"),
        concat!("ht", "tp://127.0.0.1"),
        concat!("ht", "tp://0.0.0.0"),
        concat!("ht", "tp://schemas."),
        concat!("ht", "tp://www.w3.org"),
        concat!("ht", "tp://json.schemastore.org"),
    ];

    let mut start = 0;
    while let Some(rel) = line[start..].find(http_prefix) {
        let idx = start + rel;
        start = idx + http_prefix.len();

        // Must be inside a quoted string literal (preceded by ", ', or `).
        let preceded_by_quote = idx > 0
            && matches!(
                line[..idx].chars().next_back(),
                Some('"') | Some('\'') | Some('`')
            );
        if !preceded_by_quote {
            continue;
        }

        let rest = &line[idx..];
        let lower_rest = rest.to_ascii_lowercase();
        if !safe_prefixes.iter().any(|p| lower_rest.starts_with(p)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{ArchitectureConfig, SecurityConfig, SourceSpan, SymbolKind, Visibility};
    use deslop_graph::SymbolGraph;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("deslop_sec_{name}_{nanos}"));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn write_file(&self, rel: &str, content: &str) -> PathBuf {
            let full = self.path.join(rel);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&full, content).expect("write test file");
            full
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn make_sym(file_path: PathBuf, name: &str) -> Symbol {
        Symbol {
            id: format!("{}::{name}", file_path.display()),
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path,
            span: SourceSpan::new(1, 1, 50, 1),
            visibility: Visibility::Public,
            loc: 20,
            cyclomatic_complexity: 1,
            doc: None,
            signature: format!("fn {name}()"),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    fn run_security(symbols: &[Symbol], config: Option<&ArchitectureConfig>) -> Vec<SlopFinding> {
        let edges = Vec::new();
        let graph = SymbolGraph::from_parsed(symbols, &edges);
        let ctx = DetectionContext {
            symbols,
            edges: &edges,
            graph: &graph,
            config,
            callsites: None,
        };
        SecurityRule.detect(&ctx)
    }

    #[test]
    fn detects_hardcoded_secrets_and_skips_placeholders_and_comments() {
        let dir = TempDirGuard::new("secrets");
        let aws_val = format!("{}IOSFODNN7EXAMPLE1", concat!("AK", "IA"));
        let gh_val = format!("{}1234567890abcdefghij", concat!("gh", "p_"));
        let sk_val = format!("{}1234567890abcdefghij", concat!("s", "k-"));
        let pem_val = format!(
            "{}{}",
            concat!("-----BE", "GIN "),
            concat!("PRIVATE ", "KEY-----")
        );

        let content = format!(
            "// {aws_val}\n\
             # {gh_val}\n\
             const AWS_KEY = \"{aws_val}\";\n\
             const GH_TOKEN = \"{gh_val}\";\n\
             const OPENAI_KEY = \"{sk_val}\";\n\
             const PEM = \"{pem_val}\";\n\
             const api_key = \"super_secret_production_value_123\";\n\
             const placeholder_key = \"test_placeholder_123456789\";\n\
             const jwt_secret = \"your-example-secret-key-here\";\n"
        );
        let file = dir.write_file("src/secrets.ts", &content);
        let syms = vec![make_sym(file, "loadConfig")];

        let findings = run_security(&syms, None);
        assert_eq!(
            findings.len(),
            5,
            "expected 5 secret findings, got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.kind == SlopKind::HardcodedSecret));
        assert!(findings.iter().all(|f| f.description.contains('`')));
    }

    #[test]
    fn detects_injection_sinks_and_ignores_parameterized_queries() {
        let dir = TempDirGuard::new("injection");
        let content = format!(
            "const x = {}(userInput);\n\
             const fnObj = {}('return 1');\n\
             {}('rm -rf /tmp/x');\n\
             {}(\"ls\", {}=True);\n\
             Command::new(\"sh\").arg(\"-c\").arg(cmd);\n\
             db.query(\"SELECT * FROM users WHERE id = \" + userId);\n\
             db.query(\"SELECT * FROM users WHERE id = $1\", [userId]);\n\
             medieval(something);\n",
            concat!("ev", "al"),
            concat!("new ", "Function"),
            concat!("os.", "system"),
            concat!("sub", "process.run"),
            concat!("shell", ""),
        );
        let file = dir.write_file("src/app.py", &content);
        let syms = vec![make_sym(file, "run")];

        let findings = run_security(&syms, None);
        assert_eq!(
            findings.len(),
            6,
            "expected 6 injection findings, got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.kind == SlopKind::InjectionSink));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn detects_unsafe_deserialization_and_allows_safeloader() {
        let dir = TempDirGuard::new("deser");
        let content = format!(
            "data1 = {}(raw)\n\
             data2 = {}(raw, Loader=yaml.Loader)\n\
             safe_data = {}(raw, Loader=yaml.SafeLoader)\n",
            concat!("pickle.", "loads"),
            concat!("yaml.", "load"),
            concat!("yaml.", "load"),
        );
        let file = dir.write_file("src/loader.py", &content);
        let syms = vec![make_sym(file, "load")];

        let findings = run_security(&syms, None);
        assert_eq!(findings.len(), 2, "got {findings:?}");
        assert!(findings
            .iter()
            .all(|f| f.kind == SlopKind::UnsafeDeserialization));
    }

    #[test]
    fn detects_weak_crypto_in_sensitive_context_only() {
        let dir = TempDirGuard::new("crypto");
        let content = format!(
            "const passHash = md5(password);\n\
             const sessionToken = {}().toString(36);\n\
             const checksum = md5(fileBytes);\n\
             const jitter = {}();\n",
            concat!("Math.", "random"),
            concat!("Math.", "random"),
        );
        let file = dir.write_file("src/crypto.js", &content);
        let syms = vec![make_sym(file, "hash")];

        let findings = run_security(&syms, None);
        assert_eq!(findings.len(), 2, "got {findings:?}");
        assert!(findings.iter().all(|f| f.kind == SlopKind::WeakCrypto));
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn detects_unsafe_audit_and_respects_safety_and_local_http() {
        let dir = TempDirGuard::new("unsafe_audit");
        let rs_content = format!(
            "unsafe fn raw_op() {{}}\n\
             // SAFETY: pointer is valid for lifetime\n\
             unsafe {{ *ptr = 1; }}\n\
             let prod_url = \"{}api.example.com/v1\";\n\
             let local_url = \"{}localhost:8080\";\n\
             let schema_url = \"{}www.w3.org/2000/svg\";\n",
            concat!("ht", "tp://"),
            concat!("ht", "tp://"),
            concat!("ht", "tp://"),
        );
        let rs_file = dir.write_file("src/lib.rs", &rs_content);

        let tsx_content = format!(
            "return <div {}={{{{ __html: html }}}} />;\n",
            concat!("dangerously", "SetInnerHTML"),
        );
        let tsx_file = dir.write_file("src/view.tsx", &tsx_content);

        let syms = vec![make_sym(rs_file, "raw_op"), make_sym(tsx_file, "View")];
        let findings = run_security(&syms, None);

        assert_eq!(findings.len(), 3, "got {findings:?}");
        assert!(findings.iter().all(|f| f.kind == SlopKind::UnsafeAudit));
    }

    #[test]
    fn respects_security_config_and_skips_test_paths() {
        let dir = TempDirGuard::new("cfg");
        let normal_file = dir.write_file(
            "src/auth.js",
            &format!("const tok = {}(); // token\n", concat!("Math.", "random")),
        );
        let ignored_file = dir.write_file(
            "src/legacy/old.js",
            &format!("const tok = {}(); // token\n", concat!("Math.", "random")),
        );
        let test_path_file = dir.write_file(
            "tests/auth_test.js",
            &format!("const tok = {}(); // token\n", concat!("Math.", "random")),
        );

        let syms = vec![
            make_sym(normal_file, "a"),
            make_sym(ignored_file, "b"),
            make_sym(test_path_file, "c"),
        ];

        // With default config: normal_file and ignored_file trigger, tests/ is skipped.
        let all = run_security(&syms, None);
        assert_eq!(all.len(), 2);

        // With ignore_paths: only normal_file triggers.
        let cfg_paths = ArchitectureConfig {
            security: SecurityConfig {
                enabled: true,
                ignore_rules: Vec::new(),
                ignore_paths: vec!["**/legacy/**".to_string()],
            },
            ..Default::default()
        };
        let filtered = run_security(&syms, Some(&cfg_paths));
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].file_path.ends_with("auth.js"));

        // With ignore_rules: weak-crypto is suppressed.
        let cfg_rules = ArchitectureConfig {
            security: SecurityConfig {
                enabled: true,
                ignore_rules: vec!["weak-crypto".to_string()],
                ignore_paths: Vec::new(),
            },
            ..Default::default()
        };
        assert!(run_security(&syms, Some(&cfg_rules)).is_empty());

        // With enabled = false: everything is suppressed.
        let cfg_disabled = ArchitectureConfig {
            security: SecurityConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(run_security(&syms, Some(&cfg_disabled)).is_empty());
    }

    #[test]
    fn ignores_multiline_block_comments_and_python_docstrings() {
        let dir = TempDirGuard::new("comments");
        let js_content = format!(
            "/* {eval_call}(\"x\") */\n\
             /*\n\
               {eval_call}(\"multi\");\n\
               const api_key = \"super_secret_production_value_123\";\n\
             */\n\
             const glob = \"src/*\";\n\
             {eval_call}(\"real\");\n",
            eval_call = concat!("ev", "al"),
        );
        let js_file = dir.write_file("src/commented.ts", &js_content);

        let py_content = format!(
            "def f():\n\
                 \"\"\"\n\
                 {eval_call}(\"docstring\")\n\
                 \"\"\"\n\
                 ''' {eval_call}(\"single_line_docstring\") '''\n\
                 return 1\n",
            eval_call = concat!("ev", "al"),
        );
        let py_file = dir.write_file("src/commented.py", &py_content);

        let syms = vec![make_sym(js_file, "js_fn"), make_sym(py_file, "f")];
        let findings = run_security(&syms, None);
        assert_eq!(
            findings.len(),
            1,
            "expected only real eval, got {findings:?}"
        );
        assert_eq!(findings[0].line, 7);
        assert_eq!(findings[0].kind, SlopKind::InjectionSink);
    }

    #[test]
    fn detects_two_step_tainted_variable_sinks() {
        let dir = TempDirGuard::new("tainted");
        let ts_content = "\
            const sql = `SELECT * FROM users WHERE id = ${userId}`;\n\
            db.query(sql);\n\
            const safe = \"SELECT * FROM users WHERE id = $1\";\n\
            db.query(safe);\n";
        let ts_file = dir.write_file("src/repo.ts", ts_content);

        let rs_content = format!(
            "let q = {}!(\"SELECT * FROM items WHERE id = {{}}\", id);\n\
             conn.execute(&q);\n",
            concat!("for", "mat"),
        );
        let rs_file = dir.write_file("src/repo.rs", &rs_content);

        let py_content = format!(
            "cmd = f\"rm {{target}}\"\n\
             {subproc}(cmd)\n",
            subproc = concat!("sub", "process.run"),
        );
        let py_file = dir.write_file("src/runner.py", &py_content);

        let syms = vec![
            make_sym(ts_file, "get_user"),
            make_sym(rs_file, "get_item"),
            make_sym(py_file, "cleanup"),
        ];
        let findings = run_security(&syms, None);
        assert_eq!(
            findings.len(),
            3,
            "expected 3 tainted sink findings, got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.kind == SlopKind::InjectionSink));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
        assert!(findings.iter().all(|f| (f.confidence - 0.85).abs() < 1e-6));
    }

    #[test]
    fn detects_disabled_tls_verification_and_wildcard_cors_with_credentials() {
        let dir = TempDirGuard::new("tls_cors");
        let py_file = dir.write_file("src/client.py", "resp = requests.get(url, verify=False)\n");
        let ts_file = dir.write_file(
            "src/agent.ts",
            "const agent = new https.Agent({ rejectUnauthorized: false });\n\
             res.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n\
             const opts = { credentials: true };\n",
        );
        let rs_file = dir.write_file(
            "src/http.rs",
            "let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;\n\
             let cors = CorsLayer::new().allow_origin(\"Access-Control-Allow-Origin: *\").allow_credentials(true);\n",
        );

        let syms = vec![
            make_sym(py_file, "fetch"),
            make_sym(ts_file, "handler"),
            make_sym(rs_file, "build_client"),
        ];
        let findings = run_security(&syms, None);
        assert_eq!(
            findings.len(),
            5,
            "expected 3 TLS + 2 CORS findings, got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.kind == SlopKind::UnsafeAudit));

        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let med_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        assert_eq!(high_count, 3);
        assert_eq!(med_count, 2);
        assert!(findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .all(|f| (f.confidence - 0.9).abs() < 1e-6));
    }
}
