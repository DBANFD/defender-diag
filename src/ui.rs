use crate::{
    cli::{Mode, Options},
    edl::{self, FeedSnapshot},
    reporting::{self, Attempt, Report},
    runner::{self, Progress},
};
use anyhow::{Result, ensure};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, TableState,
        Wrap,
    },
};
use std::{collections::BTreeSet, io::IsTerminal, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Clone, Copy, PartialEq)]
enum Page {
    AnalyzerMenu,
    AnalyzerResults,
    Home,
    Feeds,
    Targets,
    Setup,
    Running,
    Results,
}
struct App {
    workbench: Option<crate::workbench::Section>,
    analyzer: Option<crate::analyzer::AnalyzerReport>,
    analyzer_run: bool,
    analyzer_import: Option<JoinHandle<Result<crate::analyzer::AnalyzerReport>>>,
    analyzer_relevant: bool,
    details: bool,
    page: Page,
    cursor: usize,
    filter: String,
    feeds: Vec<String>,
    hosts: Vec<String>,
    selected: BTreeSet<usize>,
    feed: Option<FeedSnapshot>,
    options: Options,
    status: String,
    input: Option<(usize, String)>,
    excluded: bool,
    attempts: Vec<Attempt>,
    report: Option<Report>,
    rx: Option<mpsc::UnboundedReceiver<Progress>>,
    job: Option<JoinHandle<Result<Report>>>,
    download: Option<JoinHandle<Result<FeedSnapshot>>>,
}
impl App {
    fn new() -> Self {
        Self {
            workbench: None,
            analyzer: None,
            analyzer_run: false,
            analyzer_import: None,
            analyzer_relevant: true,
            details: false,
            page: Page::Home,
            cursor: 0,
            filter: "msdefender".into(),
            feeds: edl::catalog("msdefender"),
            hosts: Vec::new(),
            selected: BTreeSet::new(),
            feed: None,
            options: Options {
                preset: None,
                journal: None,
                generic_http: false,
                mode: Mode::Https,
                port: 443,
                count: 3,
                interval: Duration::from_secs(1),
                timeout: Duration::from_secs(10),
                concurrency: 4,
                resolve_ip: None,
                output: None,
                csv: None,
                https: false,
            },
            status: "Choose an endpoint source. All probes use DIRECT connections.".into(),
            input: None,
            excluded: false,
            attempts: Vec::new(),
            report: None,
            rx: None,
            job: None,
            download: None,
        }
    }
    fn set_hosts(&mut self, hosts: Vec<String>) {
        self.hosts = hosts;
        self.selected = (0..self.hosts.len()).collect();
        self.page = Page::Targets;
        self.cursor = 0;
        self.excluded = false;
    }
    fn count(&self) -> usize {
        match self.page {
            Page::Home => 10,
            Page::AnalyzerMenu => 4,
            Page::AnalyzerResults => self.analyzer_rows().len(),
            Page::Feeds => self.feeds.len(),
            Page::Targets => {
                if self.excluded {
                    self.feed.as_ref().map(|f| f.skipped.len()).unwrap_or(0)
                } else {
                    self.hosts.len()
                }
            }
            Page::Setup => 8,
            Page::Running | Page::Results => self.attempts.len(),
        }
    }
    fn start(&mut self) {
        let hosts: Vec<_> = self
            .selected
            .iter()
            .filter_map(|i| self.hosts.get(*i).cloned())
            .collect();
        if hosts.is_empty() {
            self.status = "Select at least one concrete hostname.".into();
            return;
        }
        let mut options = self.options.clone();
        let dir = match std::env::current_dir().and_then(|p| {
            let d = p.join("results");
            std::fs::create_dir_all(&d)?;
            Ok(d)
        }) {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("Cannot create evidence directory: {e}");
                return;
            }
        };
        options.journal = Some(dir.join(format!(
            "attempts-{}.jsonl",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
        )));
        let (tx, rx) = mpsc::unbounded_channel();
        self.job = Some(tokio::spawn(async move {
            runner::run_observed(hosts, &options, move |event| {
                let _ = tx.send(event);
            })
            .await
        }));
        self.rx = Some(rx);
        self.attempts.clear();
        self.details = false;
        self.report = None;
        self.cursor = 0;
        self.page = Page::Running;
        self.status = "Starting fresh probes...".into();
    }
    fn save(&mut self) {
        let Some(report) = &self.report else {
            self.status =
                "No final report. Completed evidence is retained in results/attempts-*.jsonl."
                    .into();
            return;
        };
        let result = (|| -> Result<String> {
            let dir = std::env::current_dir()?.join("results");
            std::fs::create_dir_all(&dir)?;
            let stem = format!(
                "defender-diag-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
            );
            let json = dir.join(format!("{stem}.json"));
            let csv = dir.join(format!("{stem}.csv"));
            reporting::export(report, Some(&json), Some(&csv))?;
            Ok(format!(
                "Saved JSON (+ matching CSV): {}",
                json.strip_prefix(std::env::current_dir()?)
                    .unwrap_or(&json)
                    .display()
            ))
        })();
        self.status = match result {
            Ok(s) => s,
            Err(e) => {
                format!("Save failed: {e}. Press s to retry from a writable working directory.")
            }
        };
    }
    async fn update(&mut self) {
        if self
            .analyzer_import
            .as_ref()
            .is_some_and(|h| h.is_finished())
        {
            match self.analyzer_import.take().unwrap().await {
                Ok(Ok(report)) => self.show_analyzer(report),
                Ok(Err(e)) => self.status = format!("Import failed: {e}"),
                Err(e) => self.status = format!("Import task failed: {e}"),
            }
        }
        if let Some(rx) = &mut self.rx {
            while let Ok(p) = rx.try_recv() {
                match p {
                    Progress::Status(s) => self.status = s,
                    Progress::Attempt(a) => {
                        self.attempts.push(*a);
                        self.cursor = self.attempts.len().saturating_sub(1);
                    }
                }
            }
        }
        if self.download.as_ref().is_some_and(|h| h.is_finished()) {
            match self.download.take().unwrap().await {
                Ok(Ok(feed)) => {
                    self.status = format!(
                        "Fetched {} concrete hosts; {} excluded entries. Space selects; x reviews exclusions.",
                        feed.targets.len(),
                        feed.skipped.len()
                    );
                    self.set_hosts(feed.targets.clone());
                    self.feed = Some(feed);
                }
                Ok(Err(e)) => self.status = format!("Feed download failed: {e}"),
                Err(e) => self.status = format!("Feed task failed: {e}"),
            }
        }
        if self.job.as_ref().is_some_and(|h| h.is_finished()) {
            match self.job.take().unwrap().await {
                Ok(Ok(mut report)) => {
                    report.source_feed = self.feed.clone();
                    if let Some(feed) = &report.source_feed {
                        report.warnings.push(format!("EDL: {} entries excluded; selected concrete root-hosts only. Feed is not full service coverage.",feed.skipped.len()));
                    }
                    self.attempts = report.attempts.clone();
                    self.report = Some(report);
                    self.page = Page::Results;
                    self.cursor = 0;
                    self.save();
                }
                Ok(Err(e)) => {
                    self.status = format!("Run failed: {e}");
                    self.page = Page::Results;
                }
                Err(e) => {
                    self.status = format!("Run task failed: {e}");
                    self.page = Page::Results;
                }
            }
        }
    }
    fn key(&mut self, key: KeyCode) -> bool {
        if let Some((field, value)) = &mut self.input {
            match key {
                KeyCode::Esc => self.input = None,
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c)
                    if !c.is_control()
                        && value.len() < (if *field == 100 { 2048 } else { 253 }) =>
                {
                    value.push(c)
                }
                KeyCode::Enter => {
                    let (field, value) = (*field, value.clone());
                    let result = if field == 100 {
                        let path = std::path::PathBuf::from(value.trim().trim_matches('"'));
                        self.analyzer_import = Some(tokio::task::spawn_blocking(move || {
                            crate::analyzer::import(&path)
                        }));
                        self.status = "Importing structured analyzer evidence...".into();
                        Ok(())
                    } else if field == 99 {
                        crate::scope::validate(&value).map(|host| {
                            if self.page == Page::Home {
                                self.feed = None;
                                self.set_hosts(vec![host]);
                            } else if !self.hosts.contains(&host) {
                                self.selected.insert(self.hosts.len());
                                self.hosts.push(host);
                            }
                        })
                    } else {
                        value
                            .parse::<u16>()
                            .map_err(|_| "Enter a whole number".into())
                            .and_then(|n| {
                                let valid = match field {
                                    1 => (1..=1000).contains(&n),
                                    2 => n <= 3600,
                                    3 => (1..=3600).contains(&n),
                                    4 => n > 0,
                                    5 => (1..=64).contains(&n),
                                    _ => false,
                                };
                                if !valid {
                                    return Err("Value is outside the displayed range".into());
                                }
                                match field {
                                    1 => self.options.count = n,
                                    2 => self.options.interval = Duration::from_secs(n as u64),
                                    3 => self.options.timeout = Duration::from_secs(n as u64),
                                    4 => self.options.port = n,
                                    5 => self.options.concurrency = n,
                                    _ => {}
                                }
                                Ok(())
                            })
                    };
                    match result {
                        Ok(()) => {
                            self.input = None;
                            if field != 100 {
                                self.status = "Settings updated.".into();
                            }
                        }
                        Err(e) => self.status = e,
                    }
                }
                _ => {}
            }
            return false;
        }
        if self.download.is_some() {
            if matches!(key, KeyCode::Esc | KeyCode::Char('q')) {
                self.download.take().unwrap().abort();
                self.status = "Download cancelled.".into();
            }
            return false;
        }
        match key {
            KeyCode::Char(c @ '1'..='4') if self.page == Page::Setup => {
                use crate::cli::Preset;
                let preset = match c {
                    '1' => Preset::Quick,
                    '2' => Preset::TlsSoak,
                    '3' => Preset::Extended,
                    _ => Preset::Overnight,
                };
                self.options.apply_preset(preset);
                self.status = format!(
                    "{preset:?}: {} rounds, {}s gaps plus probe time. Fresh connections; stage timeout {}s.",
                    self.options.count,
                    self.options.interval.as_secs(),
                    self.options.timeout.as_secs()
                );
            }
            KeyCode::Char('f') if self.page == Page::AnalyzerResults => {
                self.analyzer_relevant = !self.analyzer_relevant;
                self.cursor = 0;
            }
            KeyCode::Char('s') if self.page == Page::AnalyzerResults => {
                if let Some(report) = &self.analyzer {
                    let result = (|| -> Result<String> {
                        let folder = std::env::current_dir()?.join("results");
                        std::fs::create_dir_all(&folder)?;
                        let path = folder.join(format!(
                            "analyzer-summary-{}.json",
                            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
                        ));
                        crate::analyzer::export(report, &path)?;
                        Ok(format!("Saved {}", path.display()))
                    })();
                    self.status = result.unwrap_or_else(|e| format!("Export failed: {e}"));
                }
            }
            KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down => self.cursor = (self.cursor + 1).min(self.count().saturating_sub(1)),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::PageDown => {
                self.cursor = (self.cursor + 10).min(self.count().saturating_sub(1))
            }
            KeyCode::Esc | KeyCode::Char('q') if self.page == Page::Running => {
                if let Some(job) = self.job.take() {
                    job.abort();
                }
                self.rx = None;
                self.page = Page::Results;
                self.status =
                    "Cancelled. Completed evidence remains in results/attempts-*.jsonl; no final report."
                        .into();
            }
            KeyCode::Esc if self.page != Page::Home => {
                self.page = Page::Home;
                self.cursor = 0;
            }
            KeyCode::Char('q') if self.page != Page::Feeds => return true,
            KeyCode::Char('s') if self.page == Page::Results => self.save(),
            KeyCode::Char('d') if matches!(self.page, Page::Running | Page::Results) => {
                self.details = !self.details
            }
            KeyCode::Char('n') if self.page == Page::Results => {
                self.page = Page::Home;
                self.cursor = 0;
            }
            KeyCode::Char('a') if self.page == Page::Targets && !self.excluded => {
                if self.selected.len() == self.hosts.len() {
                    self.selected.clear();
                } else {
                    self.selected = (0..self.hosts.len()).collect();
                }
            }
            KeyCode::Char('x') if self.page == Page::Targets => {
                self.excluded = !self.excluded;
                self.cursor = 0;
            }
            KeyCode::Char('c') if self.page == Page::Targets => {
                self.input = Some((99, String::new()))
            }
            KeyCode::Char(' ') if self.page == Page::Targets && !self.excluded => {
                if self.cursor < self.hosts.len() && !self.selected.remove(&self.cursor) {
                    self.selected.insert(self.cursor);
                }
            }
            KeyCode::Backspace if self.page == Page::Feeds => {
                self.filter.pop();
                self.feeds = edl::catalog(&self.filter);
                self.cursor = 0;
            }
            KeyCode::Char(c) if self.page == Page::Feeds && !c.is_control() => {
                self.filter.push(c);
                self.feeds = edl::catalog(&self.filter);
                self.cursor = 0;
            }
            KeyCode::Enter => match self.page {
                Page::Home => match self.cursor {
                    8 => {
                        self.feed = None;
                        self.set_hosts(vec![
                            "management.azure.com".into(),
                            "portal.azure.com".into(),
                        ]);
                    }
                    9 => {
                        self.feed = None;
                        self.set_hosts(vec!["enterpriseenrollment.manage.microsoft.com".into()]);
                    }
                    7 => self.workbench = Some(crate::workbench::Section::Defender),
                    0 | 1 => {
                        self.filter = if self.cursor == 0 {
                            "msdefender".into()
                        } else {
                            String::new()
                        };
                        self.feeds = edl::catalog(&self.filter);
                        self.page = Page::Feeds;
                        self.cursor = 0;
                        self.status="Type to filter catalogue; arrows + Enter download one feed. Esc returns.".into();
                    }
                    2 => {
                        self.feed = None;
                        self.set_hosts(vec![
                            "edr-weu.eu.endpoint.security.microsoft.com".into(),
                            "login.microsoftonline.com".into(),
                        ]);
                    }
                    3 => {
                        self.feed = None;
                        self.set_hosts(vec!["login.microsoftonline.com".into()]);
                    }
                    4 => self.input = Some((99, String::new())),
                    6 => {
                        self.feed = None;
                        self.set_hosts(crate::cli::regional_targets());
                        self.options.apply_preset(crate::cli::Preset::Extended);
                        self.options.count = 50;
                        self.options.concurrency = 10;
                        self.status = "Regional diagnostic examples: EDR + MDAV + login/download controls. Space to select; no tenant migration implied.".into();
                    }
                    _ => {
                        self.page = Page::AnalyzerMenu;
                        self.cursor = 0;
                        self.status="Microsoft analyzer runs separately from direct probes; imports need no administrator rights.".into();
                    }
                },
                Page::AnalyzerMenu => match self.cursor {
                    3 => self.workbench = Some(crate::workbench::Section::Packages),
                    0 => self.analyzer_run = true,
                    1 => self.input = Some((100, String::new())),
                    _ => {
                        if self.analyzer.is_some() {
                            self.page = Page::AnalyzerResults;
                            self.cursor = 0;
                        } else {
                            self.status = "No analyzer results loaded yet.".into();
                        }
                    }
                },
                Page::Feeds => {
                    if let Some(url) = self.feeds.get(self.cursor).cloned() {
                        self.status =
                            "Downloading selected service feed (direct HTTPS, 30s limit)...".into();
                        self.download = Some(tokio::spawn(async move { edl::fetch(&url).await }));
                    }
                }
                Page::Targets => {
                    if !self.selected.is_empty() {
                        self.page = Page::Setup;
                        self.cursor = 0;
                    } else {
                        self.status="No hosts selected; press c to add a concrete hostname or Space to select.".into();
                    }
                }
                Page::Setup => match self.cursor {
                    0 => {
                        self.options.mode = match self.options.mode {
                            Mode::Dns => Mode::Tcp,
                            Mode::Tcp => Mode::Tls,
                            Mode::Tls => Mode::Https,
                            Mode::Https => Mode::Dns,
                        }
                    }
                    6 => self.options.generic_http = !self.options.generic_http,
                    7 => self.start(),
                    n => self.input = Some((n, String::new())),
                },
                _ => {}
            },
            _ => {}
        }
        false
    }
    fn analyzer_rows(&self) -> Vec<&crate::analyzer::Finding> {
        self.analyzer
            .as_ref()
            .map(|r| {
                r.findings
                    .iter()
                    .filter(|f| !self.analyzer_relevant || f.relevant)
                    .collect()
            })
            .unwrap_or_default()
    }
    fn show_analyzer(&mut self, report: crate::analyzer::AnalyzerReport) {
        self.status = format!(
            "Imported {} structured findings. Source-time evidence; not a direct-probe verdict.",
            report.findings.len()
        );
        self.analyzer = Some(report);
        self.page = Page::AnalyzerResults;
        self.cursor = 0;
    }
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
}
fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}
fn draw(f: &mut Frame, a: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(4),
    ])
    .split(f.area());
    let header = format!(
        " DEFENDER-DIAG  v{}    |    {}    |    {}",
        env!("CARGO_PKG_VERSION"),
        if matches!(a.page, Page::AnalyzerMenu | Page::AnalyzerResults) {
            "ANALYZER EVIDENCE"
        } else {
            "DIRECT CONNECTIONS"
        },
        chrono::Utc::now().format("%H:%M:%S UTC")
    );
    f.render_widget(
        Paragraph::new(header)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(panel(" Security connectivity workbench ")),
        chunks[0],
    );
    let help = match a.page {
        Page::AnalyzerMenu => "↑↓ choose  Enter open  Esc home  q quit",
        Page::AnalyzerResults => "↑↓ inspect  f relevant/all  s export summary  Esc home  q quit",
        Page::Home => "↑↓ choose  Enter open  q quit",
        Page::Feeds => "Type filter  Backspace erase  ↑↓ choose  Enter download  Esc back",
        Page::Targets => "Space select  a all/none  x excluded  c add  Enter settings  Esc home",
        Page::Setup => "↑↓ choose  Enter change / start  Esc home",
        Page::Running => "↑↓ inspect  d details  Esc / q cancel",
        Page::Results => "↑↓ inspect  d details  s save again  n new test  q quit",
    };
    let footer = if let Some((field, text)) = &a.input {
        let label = if *field == 100 {
            "Result ZIP, XML or extracted folder path"
        } else if *field == 99 {
            "Concrete hostname (no URL, wildcard or credentials)"
        } else {
            "New numeric value"
        };
        format!(
            "{label}: {text}_  [Enter apply / Esc cancel]\n{}",
            safe(&a.status)
        )
    } else {
        format!("{help}\n{}", safe(&a.status))
    };
    f.render_widget(
        Paragraph::new(footer)
            .wrap(Wrap { trim: false })
            .block(panel(" Controls / status ")),
        chunks[2],
    );
    if a.page == Page::AnalyzerResults {
        draw_analyzer(f, a, chunks[1]);
        return;
    }
    if matches!(a.page, Page::Running | Page::Results) {
        draw_results(f, a, chunks[1]);
        return;
    }
    let (title, items): (String, Vec<String>) = match a.page {
        Page::Home => (
            " Select endpoint source ".into(),
            vec![
                "Microsoft Defender — regional / service URL feeds".into(),
                "Browse All Microsoft service URL feeds (filter by provider / region)".into(),
                "Quick example targets — MDE West Europe + Entra".into(),
                "Microsoft Entra ID — login.microsoftonline.com".into(),
                "Custom Microsoft service hostname".into(),
                "MDE Client Analyzer — run / import / view findings".into(),
                "Regional comparison — EDR regions + MDAV + control hosts".into(),
                "Defender status — Get-MpComputerStatus / Get-MpPreference".into(),
                "Microsoft Azure — management / portal sample targets".into(),
                "Microsoft Intune — enrollment sample target".into(),
            ],
        ),
        Page::AnalyzerMenu => (
            " MDE Client Analyzer ".into(),
            vec![
                "Run selected Microsoft package - requires administrator; license prompts preserved".into(),
                "Import existing result ZIP / MDEClientAnalyzer.xml / extracted folder".into(),
                "View loaded analyzer findings".into(),
                "Manage packages — standard / preview / import / select / pin".into(),
            ],
        ),
        Page::Feeds => (
            format!(
                " Service catalogue {} | filter: {} | {} feeds ",
                edl::CATALOG_DATE,
                a.filter,
                a.feeds.len()
            ),
            a.feeds.iter().map(|s| crate::catalog::label(s)).collect(),
        ),
        Page::Targets => {
            if a.excluded {
                (
                    " Excluded feed entries — NOT tested; never counted as successes ".into(),
                    a.feed
                        .as_ref()
                        .map(|s| {
                            s.skipped
                                .iter()
                                .map(|x| format!("{} — {}", safe(&x.entry), x.reason))
                                .collect()
                        })
                        .unwrap_or_default(),
                )
            } else {
                (
                    format!(
                        " Select targets | {} selected / {} concrete | x shows exclusions ",
                        a.selected.len(),
                        a.hosts.len()
                    ),
                    a.hosts
                        .iter()
                        .enumerate()
                        .map(|(i, h)| {
                            format!("[{}] {h}", if a.selected.contains(&i) { "x" } else { " " })
                        })
                        .collect(),
                )
            }
        }
        Page::Setup => (
            " Configure test — Enter cycles mode or edits value ".into(),
            vec![
                format!(
                    "Test mode: {:?} (DNS → TCP → verified TLS → HTTPS probe)",
                    a.options.mode
                ),
                format!("Iterations: {} [1..1000]", a.options.count),
                format!(
                    "Delay between rounds: {} seconds [0..3600]",
                    a.options.interval.as_secs()
                ),
                format!(
                    "Stage timeout: {} seconds [1..3600]",
                    a.options.timeout.as_secs()
                ),
                format!("Port: {} [1..65535]", a.options.port),
                format!("Global concurrent tests: {} [1..64]", a.options.concurrency),
                format!(
                    "HTTP probing: {} (Enter toggles)",
                    if a.options.generic_http {
                        "generic HEAD /"
                    } else {
                        "service-aware GET paths; HEAD / fallback"
                    }
                ),
                format!(
                    "▶ START — {} hosts × {} rounds",
                    a.selected.len(),
                    a.options.count
                ),
            ],
        ),
        _ => unreachable!(),
    };
    let list_area = if a.page == Page::Feeds {
        let parts = Layout::vertical([Constraint::Min(4), Constraint::Length(9)]).split(chunks[1]);
        let detail = a
            .feeds
            .get(a.cursor)
            .map(|url| {
                format!(
                    "{}\n{}",
                    crate::catalog::label(url),
                    crate::catalog::description(url)
                )
            })
            .unwrap_or_else(|| "No matching category.".into());
        f.render_widget(
            Paragraph::new(detail)
                .wrap(Wrap { trim: true })
                .block(panel(" Category meaning / scope ")),
            parts[1],
        );
        parts[0]
    } else {
        chunks[1]
    };
    let rows: Vec<_> = items.into_iter().map(ListItem::new).collect();
    let mut state = ListState::default().with_selected(Some(a.cursor));
    f.render_stateful_widget(
        List::new(rows)
            .block(panel(&title))
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
            .highlight_symbol(" ▶ "),
        list_area,
        &mut state,
    );
}
fn draw_analyzer(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
    let Some(report) = &a.analyzer else {
        return;
    };
    let parts = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(4),
        Constraint::Percentage(45),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(format!(
            "Source: {}\nEvents {:?} | {} | imported {}",
            safe(&report.source),
            report.severity_counts,
            if a.analyzer_relevant {
                "Relevant findings"
            } else {
                "All findings"
            },
            report.imported_at
        ))
        .wrap(Wrap { trim: true })
        .block(panel(
            " Microsoft analyzer evidence — source-time snapshot ",
        )),
        parts[0],
    );
    let rows = a.analyzer_rows();
    let items = rows.iter().map(|x| {
        let color = match x.severity.to_ascii_lowercase().as_str() {
            "error" | "critical" | "high" => Color::Red,
            "warning" | "medium" | "low" => Color::Yellow,
            _ => Color::Cyan,
        };
        Row::new(vec![
            x.severity.clone(),
            x.category.clone(),
            x.id.clone(),
            x.check.clone(),
            x.result.clone(),
        ])
        .style(Style::default().fg(color))
    });
    let mut state = TableState::default().with_selected(Some(a.cursor));
    f.render_stateful_widget(
        Table::new(
            items,
            [
                Constraint::Length(13),
                Constraint::Length(15),
                Constraint::Length(12),
                Constraint::Percentage(25),
                Constraint::Min(12),
            ],
        )
        .header(
            Row::new(["Severity", "Category", "ID", "Check", "Result"])
                .style(Style::default().fg(Color::Black).bg(Color::Gray)),
        )
        .block(panel(" Findings / sensor and AV snapshot "))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        parts[1],
        &mut state,
    );
    let detail = rows
        .get(a.cursor)
        .map(|x| {
            format!(
                "{} | {} | {}\n{}\n\nGuidance: {}\n\n{}",
                x.severity,
                x.category,
                x.check,
                x.result,
                x.guidance,
                report.notes.join("\n")
            )
        })
        .unwrap_or_else(|| report.notes.join("\n"));
    f.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: true })
            .block(panel(" Selected finding / remediation guidance ")),
        parts[2],
    );
}
fn draw_results(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
    if a.details {
        let text=a.attempts.get(a.cursor).map(|x|format!(
            "{}\nIP {:?} | port {} | round {} | {}\nRequest: {} {}\nAssessment: {}\n\n{}\n\nError: {:?}\nTLS {:?} | {:?}\nCertificates:\n{}",
            x.hostname,x.ip,x.port,x.iteration,x.timestamp,x.http_method.as_deref().unwrap_or("not attempted"),x.http_path.as_deref().unwrap_or(""),
            x.assessment,safe(&x.diagnostic_note),x.error,x.tls_version,x.cipher,
            x.certificates.iter().map(|c|format!("Subject: {}\nIssuer: {}\nExpires: {}",safe(&c.subject),safe(&c.issuer),safe(&c.expires))).collect::<Vec<_>>().join("\n")
        )).unwrap_or_else(||"No completed attempt selected.".into());
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(panel(" Evidence / interpretation — d returns to table ")),
            area,
        );
        return;
    }
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(if area.height < 24 { 4 } else { 7 }),
        Constraint::Length(3),
    ])
    .split(area);
    let ok = a.attempts.iter().filter(|x| x.success).count();
    let app_errors = a
        .attempts
        .iter()
        .filter(|x| {
            x.http_status.is_some_and(|s| s >= 400) && x.assessment != "known_http_response"
        })
        .count();
    let total = a.attempts.len();
    f.render_widget(
        Paragraph::new(format!(
            "{} | Done {total} | OK {ok} | Fail {} | HTTP review {app_errors} | {:.1}%",
            if a.page == Page::Running {
                "RUNNING"
            } else {
                "FINISHED"
            },
            total - ok,
            if total == 0 {
                0.
            } else {
                100. * ok as f64 / total as f64
            }
        ))
        .block(panel(
            " Overview — HTTP error responses are not transport failures ",
        )),
        parts[0],
    );
    let rows = a.attempts.iter().map(|x| {
        let status = if !x.success {
            x.error
                .as_ref()
                .map(|e| e.code.as_str())
                .unwrap_or("FAIL")
                .to_string()
        } else if x.assessment == "known_http_response" {
            format!("KNOWN {}", x.http_status.unwrap_or_default())
        } else if x.http_status.is_some_and(|s| s >= 400) {
            format!("HTTP {}", x.http_status.unwrap())
        } else {
            "OK".into()
        };
        let color = if !x.success {
            Color::Red
        } else if x.assessment == "known_http_response" {
            Color::Cyan
        } else if x.http_status.is_some_and(|s| s >= 400) {
            Color::Yellow
        } else {
            Color::Green
        };
        let ms = |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "—".into());
        Row::new(vec![
            x.iteration.to_string(),
            x.hostname.clone(),
            x.ip.map(|n| n.to_string()).unwrap_or_else(|| "DNS".into()),
            ms(x.tcp_ms),
            ms(x.tls_ms),
            x.http_status.map(|n| n.to_string()).unwrap_or_default(),
            format!("{:.1}", x.total_ms),
            status,
        ])
        .style(Style::default().fg(color))
    });
    let mut state = TableState::default().with_selected(Some(a.cursor));
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Percentage(33),
                Constraint::Percentage(23),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(5),
                Constraint::Length(9),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new([
                "#", "Hostname", "IP", "TCP ms", "TLS ms", "HTTP", "Total ms", "Status",
            ])
            .style(Style::default().bg(Color::Gray).fg(Color::Black)),
        )
        .block(panel(" Per-IP attempts "))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        parts[1],
        &mut state,
    );
    let details = a
        .attempts
        .get(a.cursor)
        .map(|x| {
            let cert = x
                .certificates
                .first()
                .map(|c| {
                    format!(
                        "Issuer: {} | Expires: {}",
                        safe(&c.issuer),
                        safe(&c.expires)
                    )
                })
                .unwrap_or_default();
            let error = x
                .error
                .as_ref()
                .map(|e| safe(&e.message))
                .unwrap_or_default();
            let rows: Vec<_> = a
                .attempts
                .iter()
                .filter(|v| v.hostname == x.hostname)
                .collect();
            let summary = crate::statistics::summarize(&rows);
            let latency =
                |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "—".into());
            let stats = format!(
                "{} | OK {:.1}% | min {} / avg {} / max {} / p95 {} ms",
                x.hostname,
                summary.success_percent,
                latency(summary.min_ms),
                latency(summary.average_ms),
                latency(summary.max_ms),
                latency(summary.p95_ms)
            );
            let dns = a
                .report
                .as_ref()
                .and_then(|r| {
                    r.dns
                        .iter()
                        .find(|d| d.hostname == x.hostname && d.iteration == x.iteration)
                })
                .map(|d| format!("DNS {:.1} ms: {:?}", d.duration_ms, d.addresses))
                .unwrap_or_default();
            format!(
                "{stats}\n{} | {:?} | {:?}\n{cert}\n{dns}\n{error}",
                x.timestamp, x.tls_version, x.cipher
            )
        })
        .unwrap_or_else(|| "Waiting for first completed probe...".into());
    f.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(panel(" Selected attempt ")),
        parts[2],
    );
    let samples: Vec<u64> = a
        .attempts
        .iter()
        .rev()
        .take(area.width as usize)
        .map(|x| x.total_ms.max(0.) as u64)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    f.render_widget(
        Sparkline::default()
            .data(&samples)
            .style(Style::default().fg(Color::Yellow))
            .block(panel(
                " Recent total latency (ms, includes failed attempts) ",
            )),
        parts[3],
    );
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
pub async fn run() -> Result<bool> {
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "Interactive mode needs a terminal. Run defender-diag --help for scripted commands."
    );
    let mut terminal = ratatui::try_init()?;
    let _restore = Restore;
    let mut app = App::new();
    loop {
        if let Some(section) = app.workbench.take() {
            ratatui::restore();
            let result = crate::workbench::run(section).await;
            terminal = ratatui::try_init()?;
            if let Err(e) = result {
                app.status = format!("Diagnostics: {e}");
            }
        }
        if app.analyzer_run {
            app.analyzer_run = false;
            ratatui::restore();
            let result = std::env::current_dir()
                .map_err(anyhow::Error::from)
                .and_then(|p| crate::analyzer::run(None, &p.join("results/analyzer")));
            terminal = ratatui::try_init()?;
            match result {
                Ok(report) => app.show_analyzer(report),
                Err(e) => app.status = format!("Analyzer did not complete: {e}"),
            }
        }
        app.update().await;
        terminal.draw(|f| draw(f, &app))?;
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            if k.modifiers.contains(event::KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
                break;
            }
            if app.key(k.code) {
                break;
            }
        }
        tokio::task::yield_now().await;
    }
    if let Some(job) = app.job {
        job.abort();
    }
    if let Some(job) = app.download {
        job.abort();
    }
    if let Some(job) = app.analyzer_import {
        job.abort();
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analyzer_menu_import_filter_and_render() {
        let mut a = App::new();
        a.cursor = 5;
        a.key(KeyCode::Enter);
        assert!(a.page == Page::AnalyzerMenu);
        assert_eq!(a.count(), 4);
        let report = crate::analyzer::parse_xml(
            include_bytes!("../tests/fixtures/analyzer-synthetic.xml"),
            "synthetic",
        )
        .unwrap();
        a.show_analyzer(report);
        let relevant = a.count();
        a.key(KeyCode::Char('f'));
        assert!(a.count() > relevant);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 35)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        let text: String = t
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("ANALYZER EVIDENCE"));
        assert!(text.contains("SYNTH-001"));
        assert!(!text.contains("DIRECT CONNECTIONS"));
    }
    #[test]
    fn defender_home_entry_and_remaining_targets() {
        let mut a = App::new();
        assert_eq!(a.count(), 10);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 40)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        let text: String = t
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Defender status"));
        assert!(!text.contains("Intune policy investigation"));
        assert!(!text.contains("Windows evidence collections"));
        a.cursor = 7;
        a.key(KeyCode::Enter);
        assert!(matches!(
            a.workbench,
            Some(crate::workbench::Section::Defender)
        ));
        a.workbench = None;
        a.cursor = 8;
        a.key(KeyCode::Enter);
        assert!(a.hosts.contains(&"management.azure.com".into()));
    }
    #[test]
    fn selection_settings_and_rendering() {
        let mut a = App::new();
        a.cursor = 2;
        a.key(KeyCode::Enter);
        assert_eq!(a.hosts.len(), 2);
        a.key(KeyCode::Char('a'));
        assert!(a.selected.is_empty());
        a.key(KeyCode::Enter);
        assert!(a.page == Page::Targets);
        a.key(KeyCode::Char(' '));
        a.key(KeyCode::Enter);
        assert!(a.page == Page::Setup);
        a.key(KeyCode::Enter);
        assert_eq!(a.options.mode, Mode::Dns);
        a.cursor = 1;
        a.key(KeyCode::Enter);
        for c in "1001".chars() {
            a.key(KeyCode::Char(c));
        }
        a.key(KeyCode::Enter);
        assert_eq!(a.options.count, 3);
        a.key(KeyCode::Esc);
        a.cursor = 6;
        a.key(KeyCode::Enter);
        assert!(a.options.generic_http);
        let backend = ratatui::backend::TestBackend::new(120, 35);
        let mut t = ratatui::Terminal::new(backend).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        for page in [
            Page::Home,
            Page::Feeds,
            Page::Targets,
            Page::Setup,
            Page::Running,
            Page::Results,
        ] {
            a.page = page;
            t.draw(|f| draw(f, &a)).unwrap();
        }
    }
    #[test]
    fn category_description_presets_and_regional_selection() {
        let mut a = App::new();
        let mut home = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        home.draw(|f| draw(f, &a)).unwrap();
        let home_text: String = home
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(home_text.contains("Regional comparison"));
        a.key(KeyCode::Enter);
        a.feeds = edl::catalog("msdefender/eu/any");
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        let text: String = t
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("EU (Europe)"));
        assert!(text.contains("Worldwide shared"));
        a.page = Page::Home;
        a.cursor = 6;
        a.key(KeyCode::Enter);
        assert_eq!(a.hosts.len(), 10);
        a.key(KeyCode::Enter);
        a.key(KeyCode::Char('4'));
        assert_eq!(a.options.count, 1000);
        a.key(KeyCode::Char('2'));
        assert_eq!(a.options.mode, Mode::Tls);
        assert_eq!(a.options.count, 100);
    }
    #[test]
    fn narrow_terminal_does_not_panic() {
        let mut a = App::new();
        let mut attempt = Attempt::new(
            "test.example".into(),
            Some("127.0.0.1".parse().unwrap()),
            443,
            1,
        );
        attempt.success = true;
        a.attempts.push(attempt);
        for (w, h) in [(40, 12), (80, 24), (160, 45)] {
            let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &a)).unwrap();
            a.page = Page::Results;
            t.draw(|f| draw(f, &a)).unwrap();
            if w >= 80 {
                let rendered: String = t
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(
                    rendered.contains("127.0.0.1"),
                    "Result row must be visible at {w}x{h}"
                );
            }
        }
    }
}
