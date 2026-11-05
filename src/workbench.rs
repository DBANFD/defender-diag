//! Dashboard pages for runtime packages, collection plans and evidence investigation.
use crate::{collection, graph, packages};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListState, Paragraph, Wrap},
};
use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};
#[derive(Clone, Copy, PartialEq)]
pub enum Section {
    Packages,
    Collections,
    Intune,
}
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Menu,
    Packages,
    Plan,
    Graph,
    Viewer,
}
struct State {
    page: Page,
    cursor: usize,
    scroll: u16,
    text: String,
    status: String,
    input: Option<(String, String)>,
    channel: packages::Channel,
    packages: Vec<packages::Package>,
    collection: collection::Options,
    graph: graph::Options,
    search: String,
}
impl State {
    fn new(section: Section) -> Self {
        Self {
            page: match section {
                Section::Packages => Page::Packages,
                Section::Intune => Page::Graph,
                _ => Page::Menu,
            },
            cursor: 0,
            scroll: 0,
            text: String::new(),
            status: "Read-only diagnostics. Raw evidence stays private; no automatic uploads."
                .into(),
            input: None,
            channel: packages::Channel::Standard,
            packages: packages::list(&packages::store()).unwrap_or_default(),
            collection: collection::Options::default(),
            graph: graph::Options {
                tenant: String::new(),
                client_id: String::new(),
                entra_device_id: String::new(),
                managed_device_id: None,
                beta: false,
                directory: false,
                reports: false,
                output_dir: "results/intune".into(),
            },
            search: String::new(),
        }
    }
    fn rows(&self) -> Vec<String> {
        match self.page {
            Page::Menu => [
                "Quick health check",
                "Connectivity",
                "Defender onboarding and protection",
                "Intune / MDM local policy",
                "Firewall events and network",
                "Comprehensive standard collection",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            Page::Packages => self
                .packages
                .iter()
                .map(|p| {
                    format!(
                        "{} | version {} | {} | {}",
                        p.channel.name(),
                        p.script_version.as_deref().unwrap_or("not exposed"),
                        p.acquired_at,
                        &p.sha256[..12]
                    )
                })
                .collect(),
            Page::Graph => vec![
                format!("Tenant ID: {}", self.graph.tenant),
                format!("Public client application ID: {}", self.graph.client_id),
                format!("Verified Entra deviceId: {}", self.graph.entra_device_id),
                format!(
                    "Intune managed-device ID (optional): {}",
                    self.graph.managed_device_id.as_deref().unwrap_or("")
                ),
                format!("Beta policy families: {}", self.graph.beta),
                format!(
                    "Resolve Entra object ID (+ Device.Read.All): {}",
                    self.graph.directory
                ),
                format!(
                    "Bounded compliance reports (tenant pages, device rows retained): {}",
                    self.graph.reports
                ),
                format!("Output: {}", self.graph.output_dir.display()),
                "START authenticated read-only investigation (admin consent/RBAC required)".into(),
                "Local-only Intune collection (no authentication)".into(),
            ],
            _ => vec![],
        }
    }
    fn viewer(&mut self, text: String) {
        self.text = text;
        self.scroll = 0;
        self.page = Page::Viewer;
    }
    fn input_done(&mut self, key: &str, value: &str) -> Result<()> {
        let value = value.trim().trim_matches('"');
        match key {
            "hours" => self.collection.hours = value.parse()?,
            "MiB" => self.collection.max_mib = value.parse()?,
            "timeout" => self.collection.timeout_seconds = value.parse()?,
            "events" => self.collection.max_events = value.parse()?,
            "until" => {
                self.collection.until = if value.is_empty() {
                    Some(chrono::Utc::now().to_rfc3339())
                } else {
                    Some(value.into())
                }
            }
            "output" => self.collection.output_dir = value.into(),
            "tenant" => self.graph.tenant = graph::guid(value).map_err(anyhow::Error::msg)?,
            "client" => self.graph.client_id = graph::guid(value).map_err(anyhow::Error::msg)?,
            "entra" => {
                self.graph.entra_device_id = graph::guid(value).map_err(anyhow::Error::msg)?
            }
            "managed" => {
                self.graph.managed_device_id = if value.is_empty() {
                    None
                } else {
                    Some(graph::guid(value).map_err(anyhow::Error::msg)?)
                }
            }
            "graph-output" => self.graph.output_dir = value.into(),
            "search" => {
                self.search = value.into();
                self.scroll = 0;
            }
            _ => {}
        }
        Ok(())
    }
}
fn plan_text(p: &collection::Plan) -> String {
    format!(
        "Preset: {:?} (Windows only)\nOutput: {} / new unique run folder\nEvent window: {} to {}\nLimits: {} MiB payload, {} events/channel, {}s/collector\n\nScope: {}\n\n{}\n\n{}\n\nGaps:\n{}",
        p.preset,
        p.output_parent.display(),
        p.from,
        p.until,
        p.max_bytes / 1024 / 1024,
        p.max_events,
        p.timeout_seconds,
        p.collectors.join(", "),
        p.elevation,
        p.impact,
        p.gaps.join("\n")
    )
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
pub async fn run(section: Section) -> Result<()> {
    let mut terminal = ratatui::try_init()?;
    let _restore = Restore;
    let mut s = State::new(section);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let mut job: Option<tokio::task::JoinHandle<Result<String>>> = None;
    let mut cancel = collection::cancel_token();
    loop {
        while let Ok(message) = rx.try_recv() {
            s.status = message;
        }
        if job.as_ref().is_some_and(|j| j.is_finished()) {
            match job.take().unwrap().await {
                Ok(Ok(text)) => {
                    s.status = "Completed; review coverage and partial errors.".into();
                    if s.page == Page::Packages {
                        s.packages = packages::list(&packages::store())?;
                        s.text = text;
                    } else {
                        s.viewer(text);
                    }
                }
                Ok(Err(e)) => {
                    s.status = format!("Failed: {}", crate::analyzer::clean(&e.to_string()))
                }
                Err(e) => s.status = format!("Task failed: {e}"),
            }
        }
        terminal.draw(|f|{
            let area=Layout::vertical([Constraint::Length(3),Constraint::Min(4),Constraint::Length(6)]).split(f.area());
            let title=match s.page{Page::Menu=>"Windows collections: choose a preset to review scope",Page::Packages=>"Analyzer packages: operator-owned; never embedded",Page::Plan=>"Collection scope: review before R starts",Page::Graph=>"Intune: local evidence or optional Graph authentication",Page::Viewer=>"Evidence / coverage (raw values may identify a device)"};
            f.render_widget(Paragraph::new(title).style(Style::default().fg(Color::Cyan)).block(Block::default().borders(Borders::ALL)),area[0]);
            if matches!(s.page,Page::Menu|Page::Packages|Page::Graph){let rows=s.rows();let mut state=ListState::default().with_selected(Some(s.cursor));f.render_stateful_widget(List::new(rows).highlight_symbol("> ").highlight_style(Style::default().fg(Color::Cyan)).block(Block::default().borders(Borders::ALL)),area[1],&mut state);}
            else {let text=match s.page{Page::Plan=>collection::plan(&s.collection).map(|p|plan_text(&p)).unwrap_or_else(|e|e.to_string()),_=>if s.search.is_empty(){s.text.clone()}else{s.text.lines().filter(|l|l.to_lowercase().contains(&s.search.to_lowercase())).collect::<Vec<_>>().join("\n")}};f.render_widget(Paragraph::new(crate::analyzer::clean(&text)).wrap(Wrap{trim:false}).scroll((s.scroll,0)).block(Block::default().borders(Borders::ALL)),area[1]);}
            let help=if job.is_some(){if s.page==Page::Packages {"Package acquisition/validation in progress; wait before changing selection."} else {"Esc cancels; wait for partial manifest. No new task while running."}}else{match s.page{Page::Packages=>"C channel | D download/update | I import ZIP | S select | P pin | U unpin | Enter metadata | Esc back",Page::Plan=>"R run | H hours M size T timeout E events U end O output | N native MDM report | PgUp/PgDn | Esc back",Page::Graph=>"Arrows/Enter edit | START begins sign-in | Local-only needs no cloud access | Esc back",Page::Viewer=>"Arrows/PgUp/PgDn scroll | / search | Esc back",Page::Menu=>"Arrows/Enter preview | Esc return"}};
            let input=s.input.as_ref().map(|(k,v)|format!("{k}: {v}_ [Enter accept, Esc cancel]")).unwrap_or_default();
            let package_note=if s.page==Page::Packages{let selected=packages::selection(&packages::store()).ok().flatten().map(|x|format!("{} pinned={}",x.id,x.pinned)).unwrap_or_else(||"none".into());format!("Channel {} | selected {selected}",s.channel.name())}else{String::new()};
            f.render_widget(Paragraph::new(format!("{help}\n{input}{package_note}\n{}",s.status)).wrap(Wrap{trim:true}).block(Block::default().borders(Borders::ALL)),area[2]);
        })?;
        if !event::poll(Duration::from_millis(50))? {
            tokio::task::yield_now().await;
            continue;
        }
        let Event::Key(k) = event::read()? else {
            continue;
        };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        let key =
            if k.modifiers.contains(event::KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
                KeyCode::Esc
            } else {
                k.code
            };
        if job.is_some() {
            if key == KeyCode::Esc && s.page != Page::Packages {
                cancel.store(true, Ordering::Relaxed);
                s.status = "Cancellation requested; preserving completed evidence...".into();
            }
            continue;
        }
        if let Some((field, value)) = &mut s.input {
            match key {
                KeyCode::Esc => s.input = None,
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c) if !c.is_control() && value.len() < 2048 => value.push(c),
                KeyCode::Enter => {
                    let (field, value) = (field.clone(), value.clone());
                    s.input = None;
                    if field == "package-path" {
                        let channel = s.channel;
                        let path = PathBuf::from(value.trim().trim_matches('"'));
                        job = Some(tokio::task::spawn_blocking(move || {
                            Ok(serde_json::to_string_pretty(&packages::import(
                                &packages::store(),
                                &path,
                                channel,
                                "offline import (operator-declared channel)",
                                vec![],
                            )?)?)
                        }));
                    } else if let Err(e) = s.input_done(&field, &value) {
                        s.status = format!("Input error: {e}");
                    }
                }
                _ => {}
            }
            continue;
        }
        match key {
            KeyCode::Esc => {
                if matches!(s.page, Page::Viewer | Page::Plan) {
                    s.page = match section {
                        Section::Packages => Page::Packages,
                        Section::Intune => Page::Graph,
                        _ => Page::Menu,
                    };
                    s.cursor = 0;
                    s.search.clear();
                } else {
                    break;
                }
            }
            KeyCode::Up => {
                s.cursor = s.cursor.saturating_sub(1);
                s.scroll = s.scroll.saturating_sub(1);
            }
            KeyCode::Down => {
                s.cursor = (s.cursor + 1).min(s.rows().len().saturating_sub(1));
                s.scroll = s.scroll.saturating_add(1);
            }
            KeyCode::PageUp => s.scroll = s.scroll.saturating_sub(10),
            KeyCode::PageDown => s.scroll = s.scroll.saturating_add(10),
            KeyCode::Enter => match s.page {
                Page::Menu => {
                    s.collection.preset = [
                        collection::Preset::Quick,
                        collection::Preset::Connectivity,
                        collection::Preset::Defender,
                        collection::Preset::Intune,
                        collection::Preset::Firewall,
                        collection::Preset::Comprehensive,
                    ][s.cursor];
                    s.collection
                        .until
                        .get_or_insert_with(|| chrono::Utc::now().to_rfc3339());
                    s.page = Page::Plan;
                    s.scroll = 0;
                }
                Page::Packages => {
                    if let Some(p) = s.packages.get(s.cursor) {
                        s.viewer(serde_json::to_string_pretty(p)?);
                    }
                }
                Page::Graph => match s.cursor {
                    0 => s.input = Some(("tenant".into(), s.graph.tenant.clone())),
                    1 => s.input = Some(("client".into(), s.graph.client_id.clone())),
                    2 => s.input = Some(("entra".into(), s.graph.entra_device_id.clone())),
                    3 => {
                        s.input = Some((
                            "managed".into(),
                            s.graph.managed_device_id.clone().unwrap_or_default(),
                        ))
                    }
                    4 => s.graph.beta = !s.graph.beta,
                    5 => s.graph.directory = !s.graph.directory,
                    6 => s.graph.reports = !s.graph.reports,
                    7 => {
                        s.input = Some((
                            "graph-output".into(),
                            s.graph.output_dir.to_string_lossy().into(),
                        ))
                    }
                    8 => {
                        let o = s.graph.clone();
                        cancel = collection::cancel_token();
                        let c = cancel.clone();
                        let tx = tx.clone();
                        job = Some(tokio::spawn(async move {
                            let p = graph::run(&o, c, |m| {
                                let _ = tx.send(m);
                            })
                            .await?;
                            Ok(format!(
                                "Output: {}\n{}",
                                p.display(),
                                std::fs::read_to_string(p.join("graph-private.json"))?
                            ))
                        }));
                    }
                    _ => {
                        s.collection.preset = collection::Preset::Intune;
                        s.collection
                            .until
                            .get_or_insert_with(|| chrono::Utc::now().to_rfc3339());
                        s.page = Page::Plan;
                        s.scroll = 0;
                    }
                },
                _ => {}
            },
            KeyCode::Char(c) => match s.page {
                Page::Packages => match c.to_ascii_lowercase() {
                    'c' => {
                        s.channel = match s.channel {
                            packages::Channel::Standard => packages::Channel::Preview,
                            _ => packages::Channel::Standard,
                        }
                    }
                    'd' => {
                        let channel = s.channel;
                        job = Some(tokio::spawn(async move {
                            Ok(serde_json::to_string_pretty(
                                &packages::download(&packages::store(), channel).await?,
                            )?)
                        }));
                        s.status =
                            "Downloading verified official channel, then validating package..."
                                .into();
                    }
                    'i' => s.input = Some(("package-path".into(), String::new())),
                    's' | 'p' => {
                        if let Some(p) = s.packages.get(s.cursor) {
                            s.status = match packages::select(
                                &packages::store(),
                                &p.id,
                                c.eq_ignore_ascii_case(&'p'),
                            ) {
                                Ok(()) => format!(
                                    "Selected {}; pinned={}",
                                    p.id,
                                    c.eq_ignore_ascii_case(&'p')
                                ),
                                Err(e) => e.to_string(),
                            };
                        }
                    }
                    'u' => {
                        if let Some(p) = packages::selection(&packages::store())? {
                            packages::select(&packages::store(), &p.id, false)?;
                        }
                    }
                    _ => {}
                },
                Page::Plan => match c.to_ascii_lowercase() {
                    'r' => {
                        let o = s.collection.clone();
                        if let Err(e) = collection::plan(&o) {
                            s.status = e.to_string();
                            continue;
                        }
                        cancel = collection::cancel_token();
                        let c = cancel.clone();
                        let tx = tx.clone();
                        job = Some(tokio::spawn(async move {
                            let p = collection::run(&o, c, |m| {
                                let _ = tx.send(m);
                            })
                            .await?;
                            Ok(format!(
                                "Output: {}\n{}",
                                p.display(),
                                std::fs::read_to_string(p.join("SUMMARY.txt"))?
                            ))
                        }));
                    }
                    'n' => s.collection.mdm_report = !s.collection.mdm_report,
                    'h' | 'm' | 't' | 'e' | 'u' | 'o' => {
                        let field = match c.to_ascii_lowercase() {
                            'h' => "hours",
                            'm' => "MiB",
                            't' => "timeout",
                            'e' => "events",
                            'u' => "until",
                            _ => "output",
                        };
                        s.input = Some((field.into(), String::new()));
                    }
                    _ => {}
                },
                Page::Viewer if c == '/' => s.input = Some(("search".into(), s.search.clone())),
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn menu_and_scope() {
        let mut s = State::new(Section::Collections);
        assert_eq!(s.rows().len(), 6);
        s.input_done("hours", "48").unwrap();
        assert_eq!(s.collection.hours, 48);
        let s = State::new(Section::Intune);
        assert!(s.rows().iter().any(|r| r.contains("Local-only")));
    }
}
