//! SARIF 2.1.0 output, so findings appear in GitHub code scanning and other CI tooling.

use super::baseline::relative_key;
use deslop_core::{Severity, SlopFinding};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Builds a SARIF 2.1.0 log for `findings`, with file URIs relative to `root`.
pub fn to_sarif(findings: &[SlopFinding], root: &Path) -> Value {
    // One rule per finding kind, described once.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let rule_id = format!("{:?}", f.kind);
            rules.entry(rule_id.clone()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": { "text": f.title.split(':').next().unwrap_or(&f.title) },
                })
            });
            json!({
                "ruleId": rule_id,
                "level": level(f.severity),
                "message": { "text": format!("{}. {}", f.title, f.remediation) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": relative_key(&f.file_path, root) },
                        "region": { "startLine": f.line.max(1) }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "estimatedLinesSaved": f.estimated_lines_saved,
                }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "deslop",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/",
                    "rules": rules.into_values().collect::<Vec<_>>(),
                }
            },
            "results": results,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::SlopKind;
    use std::path::PathBuf;

    #[test]
    fn sarif_has_schema_version_rules_and_results() {
        let f = SlopFinding {
            kind: SlopKind::Cycle,
            symbol_id: "a.rs::a".into(),
            file_path: PathBuf::from("a.rs"),
            line: 0,
            severity: Severity::High,
            confidence: 0.95,
            title: "Circular Dependency Loop: a -> b".into(),
            description: String::new(),
            remediation: "Break it.".into(),
            estimated_lines_saved: 0,
        };
        let log = to_sarif(&[f], Path::new("."));
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "deslop");
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "Cycle");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "Cycle");
        assert_eq!(result["level"], "error");
        // SARIF lines are 1-based; a zero line is clamped.
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
    }

    #[test]
    fn severity_maps_to_sarif_levels() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Low), "note");
    }
}
