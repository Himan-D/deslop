use deslop_core::Language;
use deslop_parser::{FileParser, UniversalParser};
use std::path::Path;

#[test]
fn universal_parser_survives_malformed_and_partial_inputs() {
    let cases: &[(Language, &str, &[&str])] = &[
        (
            Language::TypeScript,
            "broken.ts",
            &[
                "",
                "   \n\t\n",
                "import { foo, bar from",
                "export function broken(x: number) {\n  if (x > 0) {\n    return x;",
                "const s = \"unterminated UTF-8 🦀 héllo",
                "const t = `template ${unclosed",
                "@@@ ??? === ;; => {{{",
            ],
        ),
        (
            Language::Python,
            "broken.py",
            &[
                "",
                "   \n\t\n",
                "from pkg import (",
                "def broken(x):\n    if x > 0:\n        return (",
                "s = \"unterminated UTF-8 🦀 héllo",
                "def (::):\n    pass\n@@@ ???",
            ],
        ),
        (
            Language::Go,
            "broken.go",
            &[
                "",
                "   \n\t\n",
                "package main\nimport (",
                "package main\nfunc broken() {\n\tif true {\n",
                "package main\nvar s = \"unterminated UTF-8 🦀 héllo",
                "package main\nfunc 123( { @@@ ???",
            ],
        ),
    ];

    for (lang, filename, inputs) in cases {
        let parser = UniversalParser::new(*lang);
        let path = Path::new(filename);
        for src in *inputs {
            let parsed = parser.parse(path, src);
            // Must return a valid ParsedFile without panicking.
            let _ = (
                parsed.symbols.len(),
                parsed.edges.len(),
                parsed.imports.len(),
            );
        }
    }
}
