use deslop_core::{Language, Symbol, SymbolKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedTestCase {
    pub name: String,
    pub symbol_name: String,
    pub language: Language,
    pub test_code: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedTestSuite {
    pub target_symbol: String,
    pub file_path: String,
    pub language: Language,
    pub test_code: String,
    pub test_count: usize,
}

/// Emits characterization tests for one language. Adding a language means
/// adding one emitter, not editing a match arm in the generator.
pub trait TestEmitter {
    fn language(&self) -> Language;
    fn emit(&self, symbol: &Symbol) -> (String, usize);
}

pub struct RustTestEmitter;
pub struct TypeScriptTestEmitter;
pub struct PythonTestEmitter;
pub struct GoTestEmitter;

pub struct TestGenerator;

impl TestGenerator {
    /// Synthesizes characterization and property-based test suites for candidate symbols
    pub fn generate_for_symbol(symbol: &Symbol) -> SynthesizedTestSuite {
        let ext = symbol
            .file_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let lang = Language::from_extension(ext);

        let emitter: Option<Box<dyn TestEmitter>> = match lang {
            Language::Rust => Some(Box::new(RustTestEmitter)),
            Language::TypeScript | Language::JavaScript => Some(Box::new(TypeScriptTestEmitter)),
            Language::Python => Some(Box::new(PythonTestEmitter)),
            Language::Go => Some(Box::new(GoTestEmitter)),
            Language::Unknown => None,
        };

        let (code, count) = emitter
            .map(|e| e.emit(symbol))
            .unwrap_or((String::new(), 0));

        SynthesizedTestSuite {
            target_symbol: symbol.name.clone(),
            file_path: symbol.file_path.to_string_lossy().to_string(),
            language: lang,
            test_code: code,
            test_count: count,
        }
    }

    /// Synthesizes tests for all critical functions and wrappers in the codebase
    pub fn generate_all(symbols: &[Symbol]) -> Vec<SynthesizedTestSuite> {
        symbols
            .iter()
            .filter(|s| matches!(s.kind, SymbolKind::Function | SymbolKind::Method))
            .take(20)
            .map(Self::generate_for_symbol)
            .collect()
    }
}

/// Splits `s` on `,` ignored inside any bracket pair. Used to separate
/// parameter lists and generic argument lists in every language.
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for c in s.chars() {
        match c {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            '>' | ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// Returns (inside_parens, after_closing_paren) for the first paren group at
/// or after byte index `from`. The offset exists for Go methods, whose
/// receiver parens precede the real parameters.
fn extract_paren_group(sig: &str, from: usize) -> Option<(String, String)> {
    let rel = sig.get(from..)?.find('(')?;
    let start = from + rel;
    let mut depth = 0usize;
    for (i, c) in sig.char_indices().skip_while(|(idx, _)| *idx < start) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((sig[start + 1..i].to_string(), sig[i + 1..].to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

fn sanitize_ident(name: &str) -> String {
    name.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/// Parsed Rust signature: parameter types, whether a `self` receiver is
/// present, and the normalized return type (if any).
struct RustSig {
    param_types: Vec<String>,
    has_receiver: bool,
    returns: Option<String>,
}

fn parse_rust_signature(sig: &str) -> RustSig {
    let mut out = RustSig {
        param_types: Vec::new(),
        has_receiver: false,
        returns: None,
    };
    let Some((params, after)) = extract_paren_group(sig, 0) else {
        return out;
    };
    for part in split_top_level(&params) {
        let nospace: String = part.split_whitespace().collect();
        if matches!(nospace.as_str(), "self" | "&self" | "&mutself") {
            out.has_receiver = true;
            continue;
        }
        // Parameter type follows the first top-level ':'.
        let mut depth = 0usize;
        let mut colon = None;
        for (i, c) in part.char_indices() {
            match c {
                '<' | '(' | '[' | '{' => depth += 1,
                '>' | ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ':' if depth == 0 => {
                    colon = Some(i);
                    break;
                }
                _ => {}
            }
        }
        match colon {
            Some(i) => out.param_types.push(part[i + 1..].trim().to_string()),
            None => out.param_types.push(part.trim().to_string()),
        }
    }
    if let Some(arrow) = after.find("->") {
        let ret: String = after[arrow + 2..]
            .split_whitespace()
            .take_while(|t| *t != "where")
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
        if !ret.is_empty() {
            out.returns = Some(ret);
        }
    }
    out
}

fn strip_rust_lifetimes(ty: &str) -> String {
    let mut out = String::new();
    let mut chars = ty.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            while let Some(&n) = chars.peek() {
                if n.is_alphanumeric() || n == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A default-value expression for a Rust type, or `None` when the type needs
/// a human-provided fixture (custom structs, trait objects, generics).
fn rust_default_expr(ty: &str) -> Option<String> {
    let t: String = strip_rust_lifetimes(ty).split_whitespace().collect();
    if let Some(rest) = t.strip_prefix('&') {
        if let Some(inner) = rest
            .strip_prefix("mut")
            .filter(|s| s.chars().next().map(|c| !c.is_lowercase()).unwrap_or(true))
        {
            return rust_default_expr(inner).map(|d| format!("&mut {d}"));
        }
        if rest == "Path" || rest.ends_with("::Path") {
            return Some("std::path::Path::new(\".\")".to_string());
        }
        if rest == "str" {
            return Some("&\"\"".to_string());
        }
        if rest.starts_with('[') {
            return Some("&[]".to_string());
        }
        return rust_default_expr(rest).map(|d| format!("&{d}"));
    }
    match t.as_str() {
        "bool" => Some("false".to_string()),
        "char" => Some("'x'".to_string()),
        "String" => Some("String::new()".to_string()),
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => Some("0".to_string()),
        "f32" | "f64" => Some("0.0".to_string()),
        "()" => Some("()".to_string()),
        "PathBuf" | "std::path::PathBuf" => Some("std::path::PathBuf::from(\".\")".to_string()),
        _ => {
            if t.starts_with("Vec<") {
                return Some("Vec::new()".to_string());
            }
            if t.starts_with("Option<") {
                return Some("None".to_string());
            }
            if t.starts_with("HashMap<") {
                return Some("std::collections::HashMap::new()".to_string());
            }
            if t.starts_with("HashSet<") {
                return Some("std::collections::HashSet::new()".to_string());
            }
            if t.starts_with("BTreeMap<") {
                return Some("std::collections::BTreeMap::new()".to_string());
            }
            if t.starts_with("BTreeSet<") {
                return Some("std::collections::BTreeSet::new()".to_string());
            }
            if t.starts_with('(') && t.ends_with(')') {
                let inner = &t[1..t.len() - 1];
                if inner.trim().is_empty() {
                    return Some("()".to_string());
                }
                let mut parts = Vec::new();
                for p in split_top_level(inner) {
                    parts.push(rust_default_expr(&p)?);
                }
                return Some(format!("({})", parts.join(", ")));
            }
            None
        }
    }
}

/// True when values of this return type can be compared with `assert_eq`.
fn rust_return_supports_eq(ret: &Option<String>) -> bool {
    let Some(r) = ret else {
        return true; // unit
    };
    let t: String = r.split_whitespace().collect();
    let t = t.strip_prefix('&').unwrap_or(&t);
    match t {
        "()" | "bool" | "char" | "String" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
        | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "f32" | "f64" => true,
        _ => {
            if let Some(inner) = t
                .strip_prefix("Vec<")
                .or_else(|| t.strip_prefix("Option<"))
                .and_then(|s| s.strip_suffix('>'))
            {
                return rust_return_supports_eq(&Some(inner.to_string()));
            }
            if let Some(inner) = t.strip_prefix("Result<").and_then(|s| s.strip_suffix('>')) {
                let args = split_top_level(inner);
                return args.len() == 2
                    && args
                        .iter()
                        .all(|a| rust_return_supports_eq(&Some(a.clone())));
            }
            false
        }
    }
}

impl TestEmitter for RustTestEmitter {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn emit(&self, symbol: &Symbol) -> (String, usize) {
        let sig = parse_rust_signature(&symbol.signature);
        let test_mod = format!("test_{}_invariants", sanitize_ident(&symbol.name));

        // Resolve the call target: free fn, associated fn, or method on a
        // receiver the test cannot construct (ignored with a TODO).
        let (call_path, needs_receiver) = match symbol.name.split_once("::") {
            Some((ty, method)) if symbol.kind == SymbolKind::Method => {
                if sig.has_receiver || ty.contains('<') {
                    (format!("RECEIVER::{method}"), true)
                } else {
                    (format!("{ty}::{method}"), false)
                }
            }
            _ => (symbol.name.clone(), false),
        };

        // Build argument expressions; unknown types become todo!() holes and
        // force the suite to #[ignore] so the suite stays green.
        let mut args = Vec::new();
        let mut missing = Vec::new();
        for ty in &sig.param_types {
            match rust_default_expr(ty) {
                Some(expr) => args.push(expr),
                None => {
                    missing.push(ty.clone());
                    args.push(format!("todo!(\"provide fixture: {ty}\")"));
                }
            }
        }
        let args_str = args.join(", ");
        let ignored = needs_receiver || !missing.is_empty();

        let mut code = String::new();
        code.push_str(
            "// Characterization tests synthesized by deslop — paste into the target module.\n",
        );
        code.push_str(&format!("#[cfg(test)]\nmod {} {{\n", test_mod));
        code.push_str("    use super::*;\n\n");

        if needs_receiver {
            let ty = symbol
                .name
                .split_once("::")
                .map(|(t, _)| t)
                .unwrap_or("Self");
            code.push_str(&format!(
                "    // TODO(deslop): construct a `{ty}` receiver to enable this test.\n"
            ));
        }
        for ty in &missing {
            code.push_str(&format!(
                "    // TODO(deslop): provide a `{ty}` fixture to enable this test.\n"
            ));
        }

        let call = if needs_receiver {
            format!(
                "receiver.{}({})",
                call_path.split("::").last().unwrap_or("call"),
                args_str
            )
        } else {
            format!("{}({})", call_path, args_str)
        };
        let receiver_line = if needs_receiver {
            let ty = symbol
                .name
                .split_once("::")
                .map(|(t, _)| t)
                .unwrap_or("Self");
            format!("        let receiver: {ty} = todo!(\"construct receiver\");\n")
        } else {
            String::new()
        };

        // todo!() holes diverge, so code after them trips unreachable_code;
        // allow it: the holes are intentional fill-in points, not dead code.
        let ignore_attr = if ignored {
            "    #[allow(unreachable_code)]\n    #[ignore = \"needs manual fixture (see TODOs above)\"]\n"
        } else {
            ""
        };
        code.push_str("    #[test]\n");
        code.push_str(ignore_attr);
        code.push_str(&format!(
            "    fn {}_smoke() {{\n{}        let _result = {};\n    }}\n",
            sanitize_ident(&symbol.name),
            receiver_line,
            call
        ));

        let mut count = 1;
        if !ignored && rust_return_supports_eq(&sig.returns) {
            count += 1;
            code.push_str("\n    #[test]\n");
            code.push_str(&format!(
                "    fn {}_deterministic() {{\n{}        let first = {};\n        let second = {};\n        assert_eq!(first, second);\n    }}\n",
                sanitize_ident(&symbol.name),
                receiver_line,
                call,
                call
            ));
        }

        code.push_str("}\n");
        (code, count)
    }
}

// ---------------------------------------------------------------------------
// TypeScript
// ---------------------------------------------------------------------------

fn ts_default_expr(ty: &str) -> String {
    let t = ty.trim().trim_end_matches("[]");
    let is_array = t.len() != ty.trim().len() || t.starts_with("Array");
    if is_array {
        return "[]".to_string();
    }
    match t {
        "number" | "bigint" => "0".to_string(),
        "string" => "\"\"".to_string(),
        "boolean" => "false".to_string(),
        "object" | "" => "{}".to_string(),
        _ if t.starts_with("Record<") || t.starts_with("Partial<") => "{}".to_string(),
        _ => "undefined".to_string(),
    }
}

fn parse_ts_params(params: &str) -> Vec<String> {
    split_top_level(params)
        .into_iter()
        .filter_map(|p| {
            let p = p.trim().to_string();
            if p.is_empty() || p.starts_with("...") {
                return None;
            }
            // Strip defaults (`a = 1`) and optionality (`a?`).
            let before_eq = p.split('=').next().unwrap_or(&p).trim().to_string();
            let ty = before_eq
                .split_once(':')
                .map(|(_, t)| t.trim().trim_end_matches('?').to_string())
                .unwrap_or_else(|| "any".to_string());
            Some(ts_default_expr(&ty))
        })
        .collect()
}

impl TestEmitter for TypeScriptTestEmitter {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn emit(&self, symbol: &Symbol) -> (String, usize) {
        let (params, _) = extract_paren_group(&symbol.signature, 0).unwrap_or_default();
        let args = parse_ts_params(&params).join(", ");
        let stem = symbol
            .file_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "module".to_string());

        let (import_target, call) = match symbol.name.split_once("::") {
            Some((class, method)) => (class.to_string(), format!("new {class}().{method}({args})")),
            None => (
                symbol.name.clone(),
                format!("{name}({args})", name = symbol.name),
            ),
        };

        let mut code = String::new();
        code.push_str("// Characterization tests synthesized by deslop (vitest / jest).\n");
        code.push_str("import { describe, it, expect } from 'vitest';\n");
        code.push_str(&format!(
            "import {{ {import_target} }} from './{stem}'; // TODO(deslop): fix import path if needed\n\n"
        ));
        code.push_str(&format!(
            "describe('{} characterization', () => {{\n",
            symbol.name
        ));
        code.push_str("  it('executes without throwing on default inputs', () => {\n");
        code.push_str(&format!("    expect(() => {call}).not.toThrow();\n"));
        code.push_str("  });\n\n");
        code.push_str("  it('is deterministic across repeated calls', () => {\n");
        code.push_str(&format!("    const first = {call};\n"));
        code.push_str(&format!("    const second = {call};\n"));
        code.push_str("    expect(JSON.stringify(second)).toBe(JSON.stringify(first));\n");
        code.push_str("  });\n");
        code.push_str("});\n");
        (code, 2)
    }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

fn py_default_expr(ty: &str) -> String {
    match ty.trim() {
        "int" => "0".to_string(),
        "float" => "0.0".to_string(),
        "str" => "\"\"".to_string(),
        "bool" => "False".to_string(),
        "list" | "List" => "[]".to_string(),
        "dict" | "Dict" => "{}".to_string(),
        "None" => "None".to_string(),
        _ => "None".to_string(),
    }
}

fn parse_py_params(params: &str, is_method: bool) -> Vec<String> {
    let mut parts = split_top_level(params).into_iter().peekable();
    // Skip self/cls receiver.
    if is_method {
        if let Some(first) = parts.peek() {
            let name = first.split(':').next().unwrap_or("").trim();
            if name == "self" || name == "cls" {
                parts.next();
            }
        }
    }
    parts
        .filter_map(|p| {
            let p = p.trim().to_string();
            if p.is_empty() || p.starts_with('*') {
                return None;
            }
            if p.contains('=') && !p.contains(':') {
                // Untyped default: mirror the literal kind when obvious.
                let default = p.split('=').nth(1).unwrap_or("").trim();
                if default.starts_with(['"', '\'']) {
                    return Some("\"\"".to_string());
                }
                if default == "True" || default == "False" {
                    return Some("False".to_string());
                }
                if default.parse::<f64>().is_ok() {
                    return Some("0".to_string());
                }
                return Some("None".to_string());
            }
            let ty = p
                .split_once(':')
                .map(|(_, t)| t.split('=').next().unwrap_or("").trim().to_string())
                .unwrap_or_else(|| "Any".to_string());
            let base = ty.split('[').next().unwrap_or(&ty);
            Some(py_default_expr(base))
        })
        .collect()
}

impl TestEmitter for PythonTestEmitter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn emit(&self, symbol: &Symbol) -> (String, usize) {
        let (params, _) = extract_paren_group(&symbol.signature, 0).unwrap_or_default();
        let is_method = symbol.kind == SymbolKind::Method;
        let args = parse_py_params(&params, is_method).join(", ");
        let stem = symbol
            .file_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "module".to_string());

        let (import_target, call) = match symbol.name.split_once("::") {
            Some((class, method)) if is_method => {
                (class.to_string(), format!("{class}().{method}({args})"))
            }
            _ => (
                symbol.name.clone(),
                format!("{name}({args})", name = symbol.name),
            ),
        };

        let mut code = String::new();
        code.push_str("# Characterization tests synthesized by deslop (pytest).\n");
        code.push_str(&format!(
            "from {stem} import {import_target}  # TODO(deslop): fix import if needed\n\n\n"
        ));
        code.push_str(&format!(
            "class Test{}Characterization:\n",
            sanitize_ident(&symbol.name)
        ));
        code.push_str(&format!(
            "    def test_{}_smoke(self):\n        {}  # must not raise\n\n",
            sanitize_ident(&symbol.name),
            call
        ));
        code.push_str(&format!(
            "    def test_{}_deterministic(self):\n        first = {call}\n        second = {call}\n        assert first == second\n",
            sanitize_ident(&symbol.name)
        ));
        (code, 2)
    }
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

/// Parses Go parameters (`a, b int, s string, rest ...any`) into types,
/// expanding shared-type name groups. Variadics take no argument.
fn parse_go_params(params: &str) -> Vec<String> {
    let mut types = Vec::new();
    let mut pending_names = 0usize;
    for part in split_top_level(params) {
        let part = part.trim().to_string();
        if part.is_empty() {
            continue;
        }
        if part.starts_with("...") {
            continue; // variadic: zero args is valid
        }
        match part.rsplit_once(' ') {
            Some((_, ty)) if !ty.is_empty() => {
                for _ in 0..pending_names {
                    types.push(ty.to_string());
                }
                types.push(ty.to_string());
                pending_names = 0;
            }
            _ => {
                // Bare name sharing the next part's type (`a, b int`).
                pending_names += 1;
            }
        }
    }
    types
}

fn go_zero_value(ty: &str) -> String {
    let t = ty.trim();
    match t {
        "int" | "int8" | "int16" | "int32" | "int64" | "uint" | "uint8" | "uint16" | "uint32"
        | "uint64" | "float32" | "float64" | "byte" | "rune" | "uintptr" | "complex64"
        | "complex128" => "0".to_string(),
        "string" => "\"\"".to_string(),
        "bool" => "false".to_string(),
        "error" => "nil".to_string(),
        _ => {
            if t.starts_with('*')
                || t.starts_with("map[")
                || t.starts_with("[]")
                || t.starts_with("chan")
                || t.starts_with("func(")
            {
                return "nil".to_string();
            }
            // Any named type's zero value — compiles whenever T is in scope.
            format!("*new({})", t.split('[').next().unwrap_or(t))
        }
    }
}

impl TestEmitter for GoTestEmitter {
    fn language(&self) -> Language {
        Language::Go
    }

    fn emit(&self, symbol: &Symbol) -> (String, usize) {
        // Parse the parameter list after the (method) name: Go method
        // signatures lead with receiver parens (`func (R) M(params)`).
        let anchor = symbol.name.rsplit("::").next().unwrap_or(&symbol.name);
        let from = symbol
            .signature
            .find(anchor)
            .map(|i| i + anchor.len())
            .unwrap_or(0);
        let (params, after) = extract_paren_group(&symbol.signature, from).unwrap_or_default();
        let args: Vec<String> = parse_go_params(&params)
            .into_iter()
            .map(|t| go_zero_value(&t))
            .collect();
        let args_str = args.join(", ");
        // Go signatures carry the result (`func f(x int) string`); empty
        // means no return value, so only a smoke call is emitted.
        let has_result = !after.trim().is_empty();
        let stem = symbol
            .file_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "main".to_string());

        let (receiver, call_name) = match symbol.name.split_once("::") {
            Some((recv, method)) if symbol.kind == SymbolKind::Method => {
                (format!("(*new({recv}))."), method.to_string())
            }
            _ => (String::new(), symbol.name.clone()),
        };
        let call = format!("{receiver}{call_name}({args_str})");

        let mut code = String::new();
        code.push_str("// Characterization tests synthesized by deslop (go test).\n");
        code.push_str(&format!(
            "package {stem} // TODO(deslop): match the target package\n\n"
        ));
        if has_result {
            code.push_str("import (\n    \"reflect\"\n    \"testing\"\n)\n\n");
        } else {
            code.push_str("import \"testing\"\n\n");
        }
        let test_name = format!(
            "Test{}Characterization",
            symbol
                .name
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let mut c = s.chars();
                    match c.next() {
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                        None => String::new(),
                    }
                })
                .collect::<String>()
        );
        code.push_str(&format!("func {test_name}(t *testing.T) {{\n"));
        if has_result {
            code.push_str(&format!("    first := {call}\n"));
            code.push_str(&format!("    second := {call}\n"));
            code.push_str("    if !reflect.DeepEqual(first, second) {\n");
            code.push_str(
                "        t.Fatalf(\"nondeterministic result: %v vs %v\", first, second)\n",
            );
            code.push_str("    }\n");
        } else {
            code.push_str(&format!("    {call} // must not panic\n"));
        }
        code.push_str("}\n");
        (code, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{SourceSpan, Visibility};
    use std::path::PathBuf;

    fn sym(name: &str, kind: SymbolKind, file: &str, sig: &str) -> Symbol {
        Symbol {
            id: format!("{file}::{name}"),
            name: name.to_string(),
            kind,
            file_path: PathBuf::from(file),
            span: SourceSpan::new(1, 1, 5, 2),
            visibility: Visibility::Public,
            loc: 10,
            cyclomatic_complexity: 1,
            doc: None,
            signature: sig.to_string(),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        }
    }

    #[test]
    fn rust_free_fn_gets_real_invocation_and_determinism_check() {
        let s = sym(
            "add",
            SymbolKind::Function,
            "math.rs",
            "fn add (x : i32 , y : i32) -> i32",
        );
        let (code, count) = RustTestEmitter.emit(&s);
        assert!(code.contains("add(0, 0)"), "{code}");
        assert!(code.contains("assert_eq!(first, second)"), "{code}");
        assert!(!code.contains("#[ignore"), "{code}");
        assert_eq!(count, 2);
    }

    #[test]
    fn rust_unknown_types_force_ignored_suite_with_todo_holes() {
        let s = sym(
            "save",
            SymbolKind::Function,
            "db.rs",
            "fn save (conn : & mut Connection , rows : Vec < Row >) -> Result < () , DbError >",
        );
        let (code, count) = RustTestEmitter.emit(&s);
        assert!(
            code.contains("todo!(\"provide fixture: & mut Connection\")"),
            "{code}"
        );
        assert!(code.contains("Vec::new()"), "{code}");
        assert!(code.contains("#[ignore"), "{code}");
        assert!(!code.contains("assert_eq!"), "{code}");
        assert_eq!(count, 1);
    }

    #[test]
    fn rust_method_needing_receiver_is_ignored_with_todo() {
        let s = sym(
            "Store::charge",
            SymbolKind::Method,
            "store.rs",
            "fn charge (& self , amount : f64) -> bool",
        );
        let (code, _) = RustTestEmitter.emit(&s);
        assert!(code.contains("construct a `Store` receiver"), "{code}");
        assert!(code.contains("receiver.charge(0.0)"), "{code}");
        assert!(code.contains("#[ignore"), "{code}");
    }

    #[test]
    fn rust_associated_fn_without_receiver_stays_enabled() {
        let s = sym(
            "Store::open",
            SymbolKind::Method,
            "store.rs",
            "fn open (path : & str) -> bool",
        );
        let (code, count) = RustTestEmitter.emit(&s);
        assert!(code.contains("Store::open(&\"\")"), "{code}");
        assert!(!code.contains("#[ignore"), "{code}");
        assert_eq!(count, 2);
    }

    #[test]
    fn typescript_emits_import_call_and_json_determinism() {
        let s = sym(
            "total",
            SymbolKind::Function,
            "cart.ts",
            "function total(items: any[], rate: number)",
        );
        let (code, count) = TypeScriptTestEmitter.emit(&s);
        assert!(code.contains("from './cart'"), "{code}");
        assert!(code.contains("total([], 0)"), "{code}");
        assert!(code.contains("JSON.stringify"), "{code}");
        assert_eq!(count, 2);
    }

    #[test]
    fn python_emits_import_call_and_equality_check() {
        let s = sym(
            "discount",
            SymbolKind::Function,
            "shop.py",
            "def discount(price: float, pct: int = 10)",
        );
        let (code, count) = PythonTestEmitter.emit(&s);
        assert!(code.contains("from shop import discount"), "{code}");
        assert!(code.contains("discount(0.0, 0)"), "{code}");
        assert!(code.contains("assert first == second"), "{code}");
        assert_eq!(count, 2);
    }

    #[test]
    fn go_emits_zero_values_and_deep_equal() {
        let s = sym(
            "Add",
            SymbolKind::Function,
            "math.go",
            "func Add(a, b int) int",
        );
        let (code, count) = GoTestEmitter.emit(&s);
        assert!(code.contains("Add(0, 0)"), "{code}");
        assert!(code.contains("reflect.DeepEqual"), "{code}");
        assert_eq!(count, 1);
    }

    #[test]
    fn go_void_function_gets_smoke_only() {
        let s = sym(
            "Log",
            SymbolKind::Function,
            "log.go",
            "func Log(msg string)",
        );
        let (code, _) = GoTestEmitter.emit(&s);
        assert!(code.contains("Log(\"\")"), "{code}");
        assert!(!code.contains("DeepEqual"), "{code}");
    }

    #[test]
    fn go_method_uses_zero_receiver() {
        let s = sym(
            "Store::Charge",
            SymbolKind::Method,
            "store.go",
            "func (Store) Charge(amount float64) bool",
        );
        let (code, _) = GoTestEmitter.emit(&s);
        assert!(code.contains("(*new(Store)).Charge(0)"), "{code}");
    }
}
