use super::common::scan_and_analyze;
use deslop_core::{format_location, SlopFinding, SlopKind};
use deslop_graph::SymbolGraph;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Serialize)]
struct HtmlFinding {
    kind: String,
    severity: String,
    title: String,
    description: String,
    location: String,
}

#[derive(Serialize)]
struct HtmlNode {
    id: String,
    name: String,
    kind: String,
    location: String,
    in_degree: usize,
    out_degree: usize,
    status: String,
    findings: Vec<HtmlFinding>,
}

#[derive(Serialize)]
struct HtmlEdge {
    source: String,
    target: String,
    kind: String,
    status: String,
}

#[derive(Serialize)]
struct HtmlGraphPayload {
    nodes: Vec<HtmlNode>,
    edges: Vec<HtmlEdge>,
    total_nodes: usize,
    total_edges: usize,
    cycle_count: usize,
    finding_count: usize,
}

pub fn run(
    path: &Path,
    max_nodes: usize,
    format: &str,
    output: Option<&Path>,
) -> anyhow::Result<()> {
    let (parsed, graph, findings, _elapsed) = scan_and_analyze(path)?;

    let content = match format {
        "json" => serde_json::to_string_pretty(&parsed.edges)?,
        "mermaid" => graph.to_mermaid(max_nodes),
        "html" => render_html_graph(&graph, &findings, max_nodes)?,
        other => anyhow::bail!(
            "Unsupported graph format '{}'. Expected one of: mermaid, json, html.",
            other
        ),
    };

    if let Some(out_path) = output {
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(out_path, content)?;
    } else {
        println!("{}", content);
    }

    Ok(())
}

/// Renders a self-contained, zero-external-CDN interactive HTML architecture graph
/// embedding the top `max_nodes` symbols, their dependency edges, and findings.
pub fn render_html_graph(
    graph: &SymbolGraph,
    findings: &[SlopFinding],
    max_nodes: usize,
) -> anyhow::Result<String> {
    let degrees = graph.compute_degrees();
    let mut sorted_nodes: Vec<_> = graph.graph.node_indices().collect();
    sorted_nodes.sort_by(|a, b| {
        let deg_a = degrees
            .get(&graph.graph[*a].id)
            .map(|(i, o)| i + o)
            .unwrap_or(0);
        let deg_b = degrees
            .get(&graph.graph[*b].id)
            .map(|(i, o)| i + o)
            .unwrap_or(0);
        deg_b
            .cmp(&deg_a)
            .then_with(|| graph.graph[*a].id.cmp(&graph.graph[*b].id))
    });

    let selected_vec: Vec<_> = sorted_nodes.into_iter().take(max_nodes).collect();
    let selected_indices: HashSet<_> = selected_vec.iter().copied().collect();

    let cycles = graph.find_circular_dependencies();
    let cycle_sets: Vec<HashSet<&str>> = cycles
        .iter()
        .map(|c| c.iter().map(String::as_str).collect())
        .collect();
    let all_cycle_names: HashSet<&str> = cycle_sets.iter().flatten().copied().collect();

    let mut findings_by_symbol: HashMap<&str, Vec<&SlopFinding>> = HashMap::new();
    for f in findings {
        findings_by_symbol
            .entry(f.symbol_id.as_str())
            .or_default()
            .push(f);
    }

    let mut nodes = Vec::with_capacity(selected_vec.len());
    let mut node_status_by_id: HashMap<&str, &str> = HashMap::with_capacity(selected_vec.len());

    for &idx in &selected_vec {
        let sym = &graph.graph[idx];
        let (in_deg, out_deg) = degrees.get(&sym.id).copied().unwrap_or((0, 0));

        let mut sym_findings: Vec<&SlopFinding> = findings_by_symbol
            .get(sym.id.as_str())
            .cloned()
            .unwrap_or_default();

        // Also attach cycle findings whose title mentions this symbol if not already attached.
        if all_cycle_names.contains(sym.name.as_str()) {
            for f in findings {
                if f.kind == SlopKind::Cycle && f.symbol_id != sym.id && f.title.contains(&sym.name)
                {
                    sym_findings.push(f);
                }
            }
        }

        let has_cycle = all_cycle_names.contains(sym.name.as_str())
            || sym_findings.iter().any(|f| f.kind == SlopKind::Cycle);
        let has_layer_violation = sym_findings
            .iter()
            .any(|f| f.kind == SlopKind::LayerViolation);
        let has_security = sym_findings.iter().any(|f| f.kind.is_security());

        let status = if has_cycle {
            "cycle"
        } else if has_layer_violation {
            "violation"
        } else if has_security {
            "security"
        } else if !sym_findings.is_empty() {
            "warning"
        } else {
            "clean"
        };

        node_status_by_id.insert(sym.id.as_str(), status);

        let html_findings = sym_findings
            .into_iter()
            .map(|f| HtmlFinding {
                kind: format!("{:?}", f.kind),
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                description: f.description.clone(),
                location: format_location(f),
            })
            .collect();

        nodes.push(HtmlNode {
            id: sym.id.clone(),
            name: sym.name.clone(),
            kind: format!("{:?}", sym.kind),
            location: format_location(sym),
            in_degree: in_deg,
            out_degree: out_deg,
            status: status.to_string(),
            findings: html_findings,
        });
    }

    let mut edges = Vec::new();
    for edge in graph.graph.edge_indices() {
        if let Some((u, v)) = graph.graph.edge_endpoints(edge) {
            if selected_indices.contains(&u) && selected_indices.contains(&v) {
                let from_sym = &graph.graph[u];
                let to_sym = &graph.graph[v];

                let in_same_cycle = cycle_sets.iter().any(|set| {
                    set.contains(from_sym.name.as_str()) && set.contains(to_sym.name.as_str())
                });
                let from_status = node_status_by_id
                    .get(from_sym.id.as_str())
                    .copied()
                    .unwrap_or("clean");
                let to_status = node_status_by_id
                    .get(to_sym.id.as_str())
                    .copied()
                    .unwrap_or("clean");

                let status = if in_same_cycle {
                    "cycle"
                } else if from_status == "violation"
                    || to_status == "violation"
                    || from_status == "security"
                {
                    "violation"
                } else {
                    "normal"
                };

                edges.push(HtmlEdge {
                    source: from_sym.id.clone(),
                    target: to_sym.id.clone(),
                    kind: format!("{:?}", graph.graph[edge]),
                    status: status.to_string(),
                });
            }
        }
    }

    let payload = HtmlGraphPayload {
        total_nodes: nodes.len(),
        total_edges: edges.len(),
        cycle_count: cycles.len(),
        finding_count: findings.len(),
        nodes,
        edges,
    };

    let json_raw = serde_json::to_string(&payload)?;
    let json_safe = json_raw
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");

    Ok(HTML_TEMPLATE.replace("__DESLOP_GRAPH_DATA__", &json_safe))
}

const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Deslop Architecture Graph</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --muted: #94a3b8;
    --slate: #64748b;
    --red: #ef4444;
    --orange: #f97316;
    --sky: #38bdf8;
    --emerald: #10b981;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  header {
    height: 56px;
    padding: 0 16px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-shrink: 0;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 600;
    font-size: 15px;
  }
  .stats {
    display: flex;
    gap: 8px;
    font-size: 12px;
  }
  .badge {
    padding: 3px 8px;
    border-radius: 9999px;
    background: #0f172a;
    border: 1px solid var(--border);
    color: var(--muted);
  }
  .badge.danger { border-color: var(--red); color: #fca5a5; }
  .badge.warn { border-color: var(--orange); color: #fdba74; }
  .controls {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  input[type="search"] {
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    width: 240px;
    outline: none;
  }
  input[type="search"]:focus { border-color: var(--sky); }
  button {
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
    cursor: pointer;
  }
  button:hover { border-color: var(--sky); }
  main {
    flex: 1;
    display: flex;
    min-height: 0;
  }
  .canvas-wrap {
    flex: 1;
    position: relative;
    overflow: hidden;
    background: radial-gradient(circle at center, #162033 0%, #0f172a 75%);
  }
  svg {
    width: 100%;
    height: 100%;
    cursor: grab;
    display: block;
  }
  svg.dragging { cursor: grabbing; }
  .node { cursor: pointer; }
  .node text {
    fill: var(--text);
    font-size: 11px;
    pointer-events: none;
    text-anchor: middle;
  }
  .node.dimmed { opacity: 0.18; }
  .edge.dimmed { opacity: 0.1; }
  .legend {
    position: absolute;
    left: 14px;
    bottom: 14px;
    background: rgba(30, 41, 59, 0.9);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 11px;
    display: flex;
    gap: 12px;
    color: var(--muted);
  }
  .legend-item { display: flex; align-items: center; gap: 5px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  aside {
    width: 340px;
    background: var(--panel);
    border-left: 1px solid var(--border);
    padding: 16px;
    overflow-y: auto;
    flex-shrink: 0;
  }
  .panel-title {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
    margin: 0 0 12px 0;
  }
  .node-title {
    font-size: 16px;
    font-weight: 600;
    word-break: break-word;
    margin: 0 0 6px 0;
  }
  .meta-row {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .finding-card {
    background: var(--bg);
    border: 1px solid var(--border);
    border-left: 3px solid var(--orange);
    border-radius: 6px;
    padding: 10px;
    margin-top: 10px;
    font-size: 12px;
  }
  .finding-card.cycle { border-left-color: var(--red); }
  .finding-card h4 { margin: 0 0 4px 0; font-size: 13px; }
  .finding-card p { margin: 4px 0 0 0; color: var(--muted); line-height: 1.4; }
  .empty-state { font-size: 13px; color: var(--muted); line-height: 1.5; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span>Deslop Architecture Graph</span>
    <div class="stats" id="stats-bar"></div>
  </div>
  <div class="controls">
    <input id="search" type="search" placeholder="Filter symbols or file:line..." />
    <button id="reset-view" type="button">Reset View</button>
  </div>
</header>
<main>
  <div class="canvas-wrap">
    <svg id="graph-svg" viewBox="-600 -450 1200 900">
      <defs>
        <marker id="arrow-normal" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
        </marker>
        <marker id="arrow-cycle" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
        </marker>
        <marker id="arrow-violation" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#f97316" />
        </marker>
      </defs>
      <g id="viewport"></g>
    </svg>
    <div class="legend">
      <span class="legend-item"><span class="dot" style="background:#ef4444"></span>Cycle</span>
      <span class="legend-item"><span class="dot" style="background:#f97316"></span>Violation / Security</span>
      <span class="legend-item"><span class="dot" style="background:#38bdf8"></span>Clean Symbol</span>
      <span class="legend-item"><span class="dot" style="background:#64748b"></span>Normal Edge</span>
    </div>
  </div>
  <aside id="inspector"></aside>
</main>
<script>
const GRAPH_DATA = __DESLOP_GRAPH_DATA__;

(function () {
  const svg = document.getElementById("graph-svg");
  const viewport = document.getElementById("viewport");
  const inspector = document.getElementById("inspector");
  const statsBar = document.getElementById("stats-bar");
  const searchInput = document.getElementById("search");
  const resetBtn = document.getElementById("reset-view");

  const statusColor = {
    cycle: "#ef4444",
    violation: "#f97316",
    security: "#ef4444",
    warning: "#f97316",
    clean: "#38bdf8"
  };
  const edgeColor = {
    cycle: "#ef4444",
    violation: "#f97316",
    normal: "#64748b"
  };

  function makeBadge(text, cls) {
    const span = document.createElement("span");
    span.className = "badge" + (cls ? " " + cls : "");
    span.textContent = text;
    return span;
  }

  statsBar.appendChild(makeBadge(GRAPH_DATA.total_nodes + " nodes"));
  statsBar.appendChild(makeBadge(GRAPH_DATA.total_edges + " edges"));
  if (GRAPH_DATA.cycle_count > 0) {
    statsBar.appendChild(makeBadge(GRAPH_DATA.cycle_count + " cycles", "danger"));
  }
  if (GRAPH_DATA.finding_count > 0) {
    statsBar.appendChild(makeBadge(GRAPH_DATA.finding_count + " findings", "warn"));
  }

  // Compute circular or multi-ring layout
  const pos = new Map();
  const n = GRAPH_DATA.nodes.length;
  if (n <= 24) {
    const r = Math.max(180, n * 16);
    GRAPH_DATA.nodes.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / Math.max(1, n) - Math.PI / 2;
      pos.set(node.id, { x: Math.cos(angle) * r, y: Math.sin(angle) * r });
    });
  } else {
    const cols = Math.ceil(Math.sqrt(n));
    const spacing = 140;
    const offsetX = ((cols - 1) * spacing) / 2;
    const rows = Math.ceil(n / cols);
    const offsetY = ((rows - 1) * spacing) / 2;
    GRAPH_DATA.nodes.forEach((node, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      pos.set(node.id, { x: col * spacing - offsetX, y: row * spacing - offsetY });
    });
  }

  const SVG_NS = "http://www.w3.org/2000/svg";
  const edgeEls = [];
  const nodeEls = new Map();
  let selectedId = null;

  GRAPH_DATA.edges.forEach((edge) => {
    const p1 = pos.get(edge.source);
    const p2 = pos.get(edge.target);
    if (!p1 || !p2) return;
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", p1.x);
    line.setAttribute("y1", p1.y);
    line.setAttribute("x2", p2.x);
    line.setAttribute("y2", p2.y);
    line.setAttribute("stroke", edgeColor[edge.status] || "#64748b");
    line.setAttribute("stroke-width", edge.status === "normal" ? "1.5" : "2.5");
    line.setAttribute("marker-end", "url(#arrow-" + (edgeColor[edge.status] ? edge.status : "normal") + ")");
    line.classList.add("edge");
    viewport.appendChild(line);
    edgeEls.push({ el: line, data: edge });
  });

  GRAPH_DATA.nodes.forEach((node) => {
    const p = pos.get(node.id);
    const g = document.createElementNS(SVG_NS, "g");
    g.classList.add("node");
    g.setAttribute("transform", "translate(" + p.x + "," + p.y + ")");

    const radius = Math.min(24, 11 + Math.sqrt(node.in_degree + node.out_degree) * 2.5);
    const circle = document.createElementNS(SVG_NS, "circle");
    circle.setAttribute("r", radius);
    circle.setAttribute("fill", "#0f172a");
    circle.setAttribute("stroke", statusColor[node.status] || "#38bdf8");
    circle.setAttribute("stroke-width", "3");

    const label = document.createElementNS(SVG_NS, "text");
    label.setAttribute("y", radius + 14);
    label.textContent = node.name.length > 26 ? node.name.slice(0, 24) + "..." : node.name;

    g.appendChild(circle);
    g.appendChild(label);
    g.addEventListener("click", (e) => {
      e.stopPropagation();
      selectNode(node.id);
    });
    viewport.appendChild(g);
    nodeEls.set(node.id, { el: g, circle, data: node });
  });

  function renderInspector(node) {
    inspector.innerHTML = "";
    const heading = document.createElement("h2");
    heading.className = "panel-title";
    heading.textContent = node ? "Symbol Inspector" : "Overview";
    inspector.appendChild(heading);

    if (!node) {
      const p = document.createElement("p");
      p.className = "empty-state";
      p.textContent = "Click any node in the graph to inspect its file:line location, kind, connectivity, and attached findings.";
      inspector.appendChild(p);
      return;
    }

    const title = document.createElement("div");
    title.className = "node-title";
    title.textContent = node.name;
    inspector.appendChild(title);

    const loc = document.createElement("div");
    loc.className = "meta-row";
    loc.textContent = "Location: " + node.location;
    inspector.appendChild(loc);

    const kind = document.createElement("div");
    kind.className = "meta-row";
    kind.textContent = "Kind: " + node.kind + " | Status: " + node.status;
    inspector.appendChild(kind);

    const deg = document.createElement("div");
    deg.className = "meta-row";
    deg.textContent = "Fan-in: " + node.in_degree + " | Fan-out: " + node.out_degree;
    inspector.appendChild(deg);

    if (node.findings.length === 0) {
      const clean = document.createElement("p");
      clean.className = "empty-state";
      clean.textContent = "No findings attached to this symbol.";
      inspector.appendChild(clean);
      return;
    }

    node.findings.forEach((f) => {
      const card = document.createElement("div");
      card.className = "finding-card" + (f.kind === "Cycle" ? " cycle" : "");
      const h = document.createElement("h4");
      h.textContent = "[" + f.severity + "] " + f.kind + ": " + f.title;
      const d = document.createElement("p");
      d.textContent = f.description;
      card.appendChild(h);
      card.appendChild(d);
      inspector.appendChild(card);
    });
  }

  function applyFilterAndSelection() {
    const q = searchInput.value.trim().toLowerCase();
    const neighborIds = new Set();
    if (selectedId) {
      neighborIds.add(selectedId);
      edgeEls.forEach(({ data }) => {
        if (data.source === selectedId) neighborIds.add(data.target);
        if (data.target === selectedId) neighborIds.add(data.source);
      });
    }

    nodeEls.forEach(({ el, circle, data }, id) => {
      const matchesSearch = !q || data.name.toLowerCase().includes(q) || data.location.toLowerCase().includes(q);
      const matchesSel = !selectedId || neighborIds.has(id);
      el.classList.toggle("dimmed", !(matchesSearch && matchesSel));
      circle.setAttribute("fill", id === selectedId ? "#1e293b" : "#0f172a");
    });

    edgeEls.forEach(({ el, data }) => {
      const matchesSel = !selectedId || data.source === selectedId || data.target === selectedId;
      const srcMatch = !q || (nodeEls.get(data.source)?.data.name.toLowerCase().includes(q));
      const dstMatch = !q || (nodeEls.get(data.target)?.data.name.toLowerCase().includes(q));
      el.classList.toggle("dimmed", !(matchesSel && (srcMatch || dstMatch)));
    });
  }

  function selectNode(id) {
    selectedId = selectedId === id ? null : id;
    const entry = selectedId ? nodeEls.get(selectedId) : null;
    renderInspector(entry ? entry.data : null);
    applyFilterAndSelection();
  }

  // Pan & zoom
  let panX = 0, panY = 0, scale = 1;
  let dragging = false, startX = 0, startY = 0;

  function updateTransform() {
    viewport.setAttribute("transform", "translate(" + panX + "," + panY + ") scale(" + scale + ")");
  }

  svg.addEventListener("mousedown", (e) => {
    if (e.target === svg) {
      dragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
      svg.classList.add("dragging");
    }
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    panX = e.clientX - startX;
    panY = e.clientY - startY;
    updateTransform();
  });
  window.addEventListener("mouseup", () => {
    dragging = false;
    svg.classList.remove("dragging");
  });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    scale = Math.min(4, Math.max(0.25, scale * factor));
    updateTransform();
  }, { passive: false });
  svg.addEventListener("click", (e) => {
    if (e.target === svg && selectedId) {
      selectNode(selectedId);
    }
  });
  resetBtn.addEventListener("click", () => {
    panX = 0; panY = 0; scale = 1;
    updateTransform();
  });
  searchInput.addEventListener("input", applyFilterAndSelection);

  renderInspector(null);
})();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use deslop_core::{Severity, SourceSpan, Symbol, SymbolKind, Visibility};
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sloppy_app")
    }

    #[test]
    fn html_graph_renders_sloppy_app_nodes_edges_and_cycle_findings() {
        let fixture = fixture_dir();
        let (_parsed, graph, findings, _elapsed) =
            scan_and_analyze(&fixture).expect("fixture scan should succeed");

        let html = render_html_graph(&graph, &findings, 50).expect("html render should succeed");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Deslop Architecture Graph"));
        assert!(html.contains("processA"));
        assert!(html.contains("processB"));
        assert!(html.contains("\"status\":\"cycle\""));
        assert!(html.contains("#ef4444"));
    }

    #[test]
    fn run_writes_html_to_output_and_rejects_unknown_format() {
        let fixture = fixture_dir();
        let temp_file = std::env::temp_dir().join("deslop_graph_test.html");
        let _ = std::fs::remove_file(&temp_file);

        run(&fixture, 25, "html", Some(&temp_file)).expect("run html should succeed");
        let written = std::fs::read_to_string(&temp_file).expect("output html should exist");
        assert!(written.starts_with("<!DOCTYPE html>"));
        assert!(written.contains("processA"));
        let _ = std::fs::remove_file(&temp_file);

        let err = run(&fixture, 25, "xml", None).unwrap_err();
        assert!(err.to_string().contains("Unsupported graph format"));
    }

    #[test]
    fn html_graph_escapes_script_closing_tags_in_json() {
        let sym = Symbol {
            id: "a.ts::evil</script>".to_string(),
            name: "evil</script>".to_string(),
            kind: SymbolKind::Function,
            file_path: PathBuf::from("a.ts"),
            span: SourceSpan::new(1, 0, 2, 0),
            visibility: Visibility::Public,
            loc: 2,
            cyclomatic_complexity: 1,
            doc: None,
            signature: String::new(),
            is_pure_hint: false,
            ast_hash: None,
            attributes: Vec::new(),
            is_trait_impl: false,
        };
        let graph = SymbolGraph::from_parsed(&[sym], &[]);
        let finding = SlopFinding {
            kind: SlopKind::LayerViolation,
            symbol_id: "a.ts::evil</script>".to_string(),
            file_path: PathBuf::from("a.ts"),
            line: 1,
            severity: Severity::High,
            confidence: 1.0,
            title: "Bad </script> import".to_string(),
            description: "Contains </script>".to_string(),
            remediation: String::new(),
            estimated_lines_saved: 0,
            inline_target: None,
        };

        let html = render_html_graph(&graph, &[finding], 10).expect("render should succeed");
        // Only the single real closing </script> tag should exist in the document.
        assert_eq!(html.matches("</script>").count(), 1);
        assert!(html.contains("<\\/script>"));
    }
}
