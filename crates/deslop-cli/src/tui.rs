use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use deslop_core::{CodebaseStats, DeepArchitectureReport, Severity, SlopFinding};
use deslop_detector::SlopDetectorEngine;
use deslop_graph::{CapacityAnalyzer, CapacityReport, DeepAnalyzer, SymbolGraph};
use deslop_inversion::{DeloopPlan, DelooperEngine};
use deslop_parser::ParsedCodebase;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Row, Table, Tabs, Wrap},
    Frame, Terminal,
};
use std::io::{self, stdout};
use std::path::Path;

pub struct TuiApp {
    stats: CodebaseStats,
    findings: Vec<SlopFinding>,
    slop_score: f64,
    plans: Vec<DeloopPlan>,
    capacity_report: CapacityReport,
    deep_report: DeepArchitectureReport,
    active_tab: usize,
    findings_state: ListState,
    should_quit: bool,
    target_path: String,
}

impl TuiApp {
    pub fn new(
        target_path: String,
        parsed: ParsedCodebase,
        graph: &SymbolGraph,
        findings: Vec<SlopFinding>,
    ) -> Self {
        let slop_score = SlopDetectorEngine::calculate_slop_index(parsed.stats.total_lines_of_code, &findings);
        let plans = DelooperEngine::compute_deloop_plans(&parsed.symbols, graph);
        let capacity_report = CapacityAnalyzer::analyze(graph);
        let deep_report = DeepAnalyzer::analyze(graph);

        let mut findings_state = ListState::default();
        if !findings.is_empty() {
            findings_state.select(Some(0));
        }

        Self {
            stats: parsed.stats,
            findings,
            slop_score,
            plans,
            capacity_report,
            deep_report,
            active_tab: 0,
            findings_state,
            should_quit: false,
            target_path,
        }
    }

    pub fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % 5;
    }

    pub fn prev_tab(&mut self) {
        if self.active_tab == 0 {
            self.active_tab = 4;
        } else {
            self.active_tab -= 1;
        }
    }

    pub fn next_finding(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        let i = match self.findings_state.selected() {
            Some(i) => {
                if i >= self.findings.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.findings_state.select(Some(i));
    }

    pub fn prev_finding(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        let i = match self.findings_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.findings.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.findings_state.select(Some(i));
    }
}

pub fn run_tui(
    target_path: &Path,
    parsed: ParsedCodebase,
    graph: &SymbolGraph,
    findings: Vec<SlopFinding>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(
        target_path.display().to_string(),
        parsed,
        graph,
        findings,
    );

    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("TUI Error: {:?}", err);
    }

    Ok(())
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Tab => app.next_tab(),
                        KeyCode::BackTab => app.prev_tab(),
                        KeyCode::Char('1') => app.active_tab = 0,
                        KeyCode::Char('2') => app.active_tab = 1,
                        KeyCode::Char('3') => app.active_tab = 2,
                        KeyCode::Char('4') => app.active_tab = 3,
                        KeyCode::Char('5') => app.active_tab = 4,
                        KeyCode::Down | KeyCode::Char('j') => app.next_finding(),
                        KeyCode::Up | KeyCode::Char('k') => app.prev_finding(),
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn ui(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & Tabs
            Constraint::Min(0),    // Main Content Area
            Constraint::Length(1), // Footer / Keybindings
        ])
        .split(f.area());

    // Tabs
    let tab_titles = vec![
        "[1] Overview",
        "[2] Findings",
        "[3] Cycles",
        "[4] Capacity",
        "[5] Deep Metrics",
    ];
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" deslop v0.1.0 - Target: {} ", app.target_path)),
        )
        .select(app.active_tab)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    // Content based on tab
    match app.active_tab {
        0 => render_overview(f, app, chunks[1]),
        1 => render_findings(f, app, chunks[1]),
        2 => render_cycles(f, app, chunks[1]),
        3 => render_capacity(f, app, chunks[1]),
        4 => render_deep(f, app, chunks[1]),
        _ => {}
    }

    // Footer
    let footer_text = " [Tab/1-5] Switch View  [j/k or Up/Down] Select  [q/Esc] Quit ";
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

fn render_overview(f: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left Box: Scoreboard
    let total_saved: usize = app.findings.iter().map(|f| f.estimated_lines_saved).sum();
    let score_color = if app.slop_score < 20.0 {
        Color::Green
    } else if app.slop_score < 40.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let text = vec![
        Line::from(vec![
            Span::raw("Architectural Slop Index: "),
            Span::styled(format!("{:.1} / 100", app.slop_score), Style::default().fg(score_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw("Total Lines of Code:     "), Span::styled(format!("{}", app.stats.total_lines_of_code), Style::default().fg(Color::White))]),
        Line::from(vec![Span::raw("Total Source Files:      "), Span::styled(format!("{}", app.stats.total_files), Style::default().fg(Color::White))]),
        Line::from(vec![Span::raw("Total Parsed Symbols:    "), Span::styled(format!("{}", app.stats.total_symbols), Style::default().fg(Color::White))]),
        Line::from(vec![Span::raw("Prunable Bloat:          "), Span::styled(format!("~{} LOC", total_saved), Style::default().fg(Color::Green))]),
        Line::from(vec![Span::raw("Circular Dependency Loops:"), Span::styled(format!(" {}", app.plans.len()), if app.plans.is_empty() { Style::default().fg(Color::Green) } else { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) })]),
        Line::from(vec![Span::raw("Hardware Failure Points: "), Span::styled(format!("{}", app.capacity_report.breaking_risks.len()), Style::default().fg(Color::Yellow))]),
        Line::from(vec![Span::raw("Avg Module Depth Ratio:  "), Span::styled(format!("{:.2}x", app.deep_report.average_depth_ratio), Style::default().fg(Color::Cyan))]),
    ];

    let block = Block::default().borders(Borders::ALL).title(" Architectural Scoreboard ");
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, chunks[0]);

    // Right Box: Language Distribution
    let mut lang_lines = Vec::new();
    lang_lines.push(Line::from(Span::styled("Language Distribution:", Style::default().add_modifier(Modifier::BOLD))));
    lang_lines.push(Line::from(""));

    for (lang, count) in &app.stats.languages {
        lang_lines.push(Line::from(vec![
            Span::raw(format!("{:<16}", format!("{:?}", lang))),
            Span::styled(format!("{} files", count), Style::default().fg(Color::Cyan)),
        ]));
    }

    let right_block = Block::default().borders(Borders::ALL).title(" Codebase Topology ");
    let right_p = Paragraph::new(lang_lines).block(right_block);
    f.render_widget(right_p, chunks[1]);
}

fn render_findings(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let items: Vec<ListItem> = app
        .findings
        .iter()
        .map(|finding| {
            let sev_color = match finding.severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::LightRed,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Cyan,
            };
            let line = Line::from(vec![
                Span::styled(format!("[{:?}] ", finding.kind), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::raw(&finding.title),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(" Findings ({}) ", app.findings.len())))
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, chunks[0], &mut app.findings_state);

    // Detail pane
    let detail_text = if let Some(selected) = app.findings_state.selected() {
        if let Some(f_item) = app.findings.get(selected) {
            vec![
                Line::from(vec![Span::styled("Title: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&f_item.title)]),
                Line::from(vec![Span::styled("Severity: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(format!("{:?}", f_item.severity))]),
                Line::from(vec![Span::styled("Location: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(format!("{}:{}", f_item.file_path.display(), f_item.line))]),
                Line::from(vec![Span::styled("Estimated Lines Saved: ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(format!("~{} LOC", f_item.estimated_lines_saved), Style::default().fg(Color::Green))]),
                Line::from(""),
                Line::from(Span::styled("Description:", Style::default().add_modifier(Modifier::BOLD))),
                Line::from(f_item.description.clone()),
                Line::from(""),
                Line::from(Span::styled("Remediation Strategy:", Style::default().add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(&f_item.remediation, Style::default().fg(Color::Cyan))),
            ]
        } else {
            vec![Line::from("No finding selected.")]
        }
    } else {
        vec![Line::from("No finding selected.")]
    };

    let detail_p = Paragraph::new(detail_text)
        .block(Block::default().borders(Borders::ALL).title(" Finding Inspector "))
        .wrap(Wrap { trim: true });
    f.render_widget(detail_p, chunks[1]);
}

fn render_cycles(f: &mut Frame, app: &TuiApp, area: Rect) {
    if app.plans.is_empty() {
        let p = Paragraph::new("\n  Zero circular dependency loops detected! Architecture is an acyclic DAG.")
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL).title(" De-Looping & Cycle Inversion "));
        f.render_widget(p, area);
        return;
    }

    let mut lines = Vec::new();
    for (i, p) in app.plans.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!("Loop #{}: ", i + 1), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(p.cycle.join(" <-> "), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Optimal Cut Edge: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{} -> {}", p.cut_edge.0, p.cut_edge.1)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Rationale:        ", Style::default().fg(Color::Gray)),
            Span::raw(&p.architectural_rationale),
        ]));
        lines.push(Line::from(Span::styled("  Actionable Steps:", Style::default().fg(Color::Green))));
        for (step_idx, step) in p.actionable_steps.iter().enumerate() {
            lines.push(Line::from(format!("    {}. {}", step_idx + 1, step)));
        }
        lines.push(Line::from("--------------------------------------------------"));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(format!(" Detected Cycles ({}) - Minimum Feedback Arc Set ", app.plans.len())))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn render_capacity(f: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    // Concurrency table
    let rows: Vec<Row> = app
        .capacity_report
        .estimates
        .iter()
        .map(|est| {
            Row::new(vec![
                est.device.name.clone(),
                format!("~{} users", est.max_concurrent_users),
                format!("{} req/s", est.max_requests_per_sec),
                est.bottleneck_resource.clone(),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(vec!["Device Profile", "Max Users (CCU)", "Throughput", "Primary Bottleneck"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" Hardware Concurrency Matrix "));
    f.render_widget(table, chunks[0]);

    // Risks
    let mut risk_lines = Vec::new();
    if app.capacity_report.breaking_risks.is_empty() {
        risk_lines.push(Line::from("No critical saturation or unbounded memory breaking points detected."));
    } else {
        for (i, r) in app.capacity_report.breaking_risks.iter().enumerate() {
            risk_lines.push(Line::from(vec![
                Span::styled(format!("{}. {} ", i + 1, r.trigger_pattern), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({})", r.failure_mode), Style::default().fg(Color::Yellow)),
            ]));
            risk_lines.push(Line::from(format!("   Location:    {}", r.file_location)));
            risk_lines.push(Line::from(format!("   Threshold:   {}", r.estimated_breaking_threshold)));
            risk_lines.push(Line::from(format!("   Remediation: {}", r.recommendation)));
            risk_lines.push(Line::from(""));
        }
    }

    let risk_p = Paragraph::new(risk_lines)
        .block(Block::default().borders(Borders::ALL).title(format!(" Predicted Failure Points ({}) ", app.capacity_report.breaking_risks.len())))
        .wrap(Wrap { trim: true });
    f.render_widget(risk_p, chunks[1]);
}

fn render_deep(f: &mut Frame, app: &TuiApp, area: Rect) {
    let rows: Vec<Row> = app
        .deep_report
        .module_metrics
        .iter()
        .map(|m| {
            let color = if m.classification.starts_with("Main Sequence") {
                Color::Green
            } else if m.classification.starts_with("Zone of Pain") {
                Color::Red
            } else if m.classification.starts_with("Zone of Uselessness") {
                Color::Yellow
            } else {
                Color::Cyan
            };
            Row::new(vec![
                m.module_name.clone(),
                m.afferent_coupling.to_string(),
                m.efferent_coupling.to_string(),
                format!("{:.2}", m.instability),
                format!("{:.2}", m.abstractness),
                format!("{:.2}", m.distance_from_main_seq),
                m.classification.clone(),
            ])
            .style(Style::default().fg(color))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
            Constraint::Percentage(12),
            Constraint::Percentage(12),
            Constraint::Percentage(12),
            Constraint::Percentage(19),
        ],
    )
    .header(
        Row::new(vec!["Module", "Ca", "Ce", "Instability", "Abstractness", "Dist (D)", "Classification"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" Robert C. Martin's Package Coupling & Main Sequence "));
    f.render_widget(table, area);
}
