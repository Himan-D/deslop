use serde_json::json;
use std::path::Path;

const LABEL: &str = "deslop";
const LEFT_HEX: &str = "#0f172a";

struct BadgeData {
    message: String,
    color: &'static str,
}

fn badge_color(slop_index: f64, cycles: usize) -> &'static str {
    if slop_index <= 5.0 && cycles == 0 {
        "brightgreen"
    } else if slop_index <= 15.0 && cycles == 0 {
        "green"
    } else if slop_index <= 30.0 {
        "yellow"
    } else {
        "red"
    }
}

fn color_hex(color: &str) -> &'static str {
    match color {
        "brightgreen" => "#44cc11",
        "green" => "#97ca00",
        "yellow" => "#dfb317",
        _ => "#e05d44",
    }
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn compute_badge(path: &Path) -> anyhow::Result<BadgeData> {
    let (parsed, _graph, findings, _elapsed) = super::common::scan_and_analyze(path)?;
    let total_loc = parsed.stats.total_lines_of_code;
    let slop_index =
        deslop_detector::SlopDetectorEngine::calculate_slop_index(total_loc, &findings);
    let cycles = findings
        .iter()
        .filter(|f| f.kind == deslop_core::SlopKind::Cycle)
        .count();

    let message = if cycles == 0 {
        format!("{slop_index:.1}/100")
    } else {
        format!("{slop_index:.1}/100 ({cycles} cycles)")
    };
    let color = badge_color(slop_index, cycles);

    Ok(BadgeData { message, color })
}

fn to_shields_json(data: &BadgeData) -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "label": LABEL,
        "message": data.message,
        "color": data.color,
    })
}

fn render_svg(data: &BadgeData) -> String {
    let left_width = (LABEL.len() * 7 + 16).max(48);
    let right_width = (data.message.len() * 7 + 16).max(60);
    let total_width = left_width + right_width;
    let left_x = left_width / 2;
    let right_x = left_width + right_width / 2;
    let right_hex = color_hex(data.color);
    let escaped_label = xml_escape(LABEL);
    let escaped_msg = xml_escape(&data.message);
    let aria_label = format!("{escaped_label}: {escaped_msg}");

    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total_width}\" height=\"20\" role=\"img\" aria-label=\"{aria_label}\">\
<title>{aria_label}</title>\
<g shape-rendering=\"crispEdges\">\
<rect width=\"{left_width}\" height=\"20\" fill=\"{LEFT_HEX}\"/>\
<rect x=\"{left_width}\" width=\"{right_width}\" height=\"20\" fill=\"{right_hex}\"/>\
</g>\
<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" text-rendering=\"geometricPrecision\" font-size=\"11\">\
<text x=\"{left_x}\" y=\"14\">{escaped_label}</text>\
<text x=\"{right_x}\" y=\"14\">{escaped_msg}</text>\
</g>\
</svg>"
    )
}

pub fn run(path: &Path, format: &str, output: Option<&Path>) -> anyhow::Result<()> {
    let rendered = match format {
        "json" => {
            let data = compute_badge(path)?;
            serde_json::to_string_pretty(&to_shields_json(&data))?
        }
        "svg" => {
            let data = compute_badge(path)?;
            render_svg(&data)
        }
        other => anyhow::bail!("unsupported badge format '{other}': expected 'json' or 'svg'"),
    };

    if let Some(out_path) = output {
        if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out_path, format!("{rendered}\n"))?;
        eprintln!("Wrote {format} badge to {}", out_path.display());
    } else {
        println!("{rendered}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sloppy_app_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("workspace root")
            .join("tests/fixtures/sloppy_app")
    }

    #[test]
    fn badge_color_thresholds() {
        assert_eq!(badge_color(0.0, 0), "brightgreen");
        assert_eq!(badge_color(5.0, 0), "brightgreen");
        assert_eq!(badge_color(5.1, 0), "green");
        assert_eq!(badge_color(15.0, 0), "green");
        assert_eq!(badge_color(15.1, 0), "yellow");
        assert_eq!(badge_color(30.0, 0), "yellow");
        assert_eq!(badge_color(30.1, 0), "red");
        // Any cycle disqualifies brightgreen and green.
        assert_eq!(badge_color(0.0, 1), "yellow");
        assert_eq!(badge_color(10.0, 2), "yellow");
        assert_eq!(badge_color(35.0, 1), "red");
    }

    #[test]
    fn shields_json_on_sloppy_app() {
        let fixture = sloppy_app_fixture();
        let data = compute_badge(&fixture).expect("compute_badge should succeed");
        let payload = to_shields_json(&data);

        assert_eq!(payload["schemaVersion"], 1);
        assert_eq!(payload["label"], "deslop");
        let message = payload["message"].as_str().expect("message string");
        assert!(message.contains("/100"), "unexpected message: {message}");
        let color = payload["color"].as_str().expect("color string");
        assert!(
            matches!(color, "brightgreen" | "green" | "yellow" | "red"),
            "unexpected color: {color}"
        );
    }

    #[test]
    fn svg_rendering_on_sloppy_app() {
        let fixture = sloppy_app_fixture();
        let data = compute_badge(&fixture).expect("compute_badge should succeed");
        let svg = render_svg(&data);

        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains(LEFT_HEX));
        assert!(svg.contains(color_hex(data.color)));
        assert!(svg.contains(">deslop</text>"));
        assert!(svg.contains(&format!(">{}</text>", xml_escape(&data.message))));
    }

    #[test]
    fn run_rejects_unknown_format_and_writes_output_file() {
        let fixture = sloppy_app_fixture();
        let err = run(&fixture, "png", None).expect_err("unknown format should fail");
        assert!(err.to_string().contains("unsupported badge format"));

        let out_file =
            std::env::temp_dir().join(format!("deslop_badge_test_{}.svg", std::process::id()));
        let _ = std::fs::remove_file(&out_file);
        run(&fixture, "svg", Some(&out_file)).expect("writing svg badge should succeed");
        let written = std::fs::read_to_string(&out_file).expect("badge file should exist");
        assert!(written.starts_with("<svg "));
        assert!(written.trim_end().ends_with("</svg>"));
        let _ = std::fs::remove_file(&out_file);
    }
}
