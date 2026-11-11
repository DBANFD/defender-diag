//! Terminal dashboard: state and event loop here, keys in `input`, drawing in `render`.
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

mod input;
mod render;
use render::*;
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
                html: None,
                https: false,
                proxy: crate::proxy::session(),
            },
            status: format!(
                "Choose an endpoint source. All probes use {} connections.",
                crate::proxy::session_label()
            ),
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
            Page::Home => 11,
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
            reporting::export_html(report, &dir.join(format!("{stem}.html")))?;
            Ok(format!(
                "Saved JSON (+ matching CSV and HTML): {}",
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

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
pub async fn run(proxy: crate::proxy::ProxyChoice) -> Result<bool> {
    crate::proxy::plan(&proxy).map_err(anyhow::Error::msg)?;
    crate::proxy::set_session(proxy);
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
            include_bytes!("../../tests/fixtures/analyzer-synthetic.xml"),
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
        assert_eq!(a.count(), 11);
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
        assert!(text.contains("MDE connectivity check"));
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
