//! Dashboard pages for runtime packages and local Defender status.
use crate::{defender, packages, process};
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
    Defender,
}
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Menu,
    Packages,

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
    search: String,
}
impl State {
    fn new(section: Section) -> Self {
        Self {
            page: match section {
                Section::Packages => Page::Packages,
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
            search: String::new(),
        }
    }
    fn rows(&self) -> Vec<String> {
        match self.page {
            Page::Menu => [
                "Get-MpComputerStatus (all status fields)",
                "Get-MpPreference (all returned preferences)",
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
        if key == "search" {
            self.search = value.into();
            self.scroll = 0;
        }
        Ok(())
    }
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
    let mut job: Option<tokio::task::JoinHandle<Result<String>>> = None;
    let mut cancel = process::cancel_token();
    loop {
        if job.as_ref().is_some_and(|j| j.is_finished()) {
            match job.take().unwrap().await {
                Ok(Ok(text)) => {
                    s.status = "Completed. Read-only snapshot; no files saved.".into();
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
            let title=match s.page{Page::Menu=>"Defender status (Windows): choose a read-only query",Page::Packages=>"Analyzer packages: operator-owned; never embedded",Page::Viewer=>"Query output (preferences may contain private paths and exclusions)"};
            f.render_widget(Paragraph::new(title).style(Style::default().fg(Color::Cyan)).block(Block::default().borders(Borders::ALL)),area[0]);
            if matches!(s.page,Page::Menu|Page::Packages){let rows=s.rows();let mut state=ListState::default().with_selected(Some(s.cursor));f.render_stateful_widget(List::new(rows).highlight_symbol("> ").highlight_style(Style::default().fg(Color::Cyan)).block(Block::default().borders(Borders::ALL)),area[1],&mut state);}
            else {let text=if s.search.is_empty(){s.text.clone()}else{s.text.lines().filter(|l|l.to_lowercase().contains(&s.search.to_lowercase())).collect::<Vec<_>>().join("\n")};f.render_widget(Paragraph::new(crate::analyzer::clean(&text)).wrap(Wrap{trim:false}).scroll((s.scroll,0)).block(Block::default().borders(Borders::ALL)),area[1]);}
            let help=if job.is_some(){if s.page==Page::Packages {"Package acquisition/validation in progress; wait before changing selection."} else {"Esc cancels the query. No files saved."}}else{match s.page{Page::Packages=>"C channel | D download/update | I import ZIP | S select | P pin | U unpin | Enter metadata | Esc back",Page::Viewer=>"Arrows/PgUp/PgDn scroll | / search | Esc back",Page::Menu=>"Arrows/Enter run query | Esc return"}};
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
                s.status = "Cancelling query...".into();
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
                if matches!(s.page, Page::Viewer) {
                    s.page = match section {
                        Section::Packages => Page::Packages,
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
                    let query = if s.cursor == 0 {
                        defender::Query::ComputerStatus
                    } else {
                        defender::Query::Preferences
                    };
                    cancel = process::cancel_token();
                    let c = cancel.clone();
                    job = Some(tokio::spawn(async move { defender::run(query, c).await }));
                    s.status = "Reading local Defender data (60-second timeout)...".into();
                }
                Page::Packages => {
                    if let Some(p) = s.packages.get(s.cursor) {
                        s.viewer(serde_json::to_string_pretty(p)?);
                    }
                }
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
    fn defender_menu() {
        let s = State::new(Section::Defender);
        assert_eq!(s.rows().len(), 2);
        assert!(s.rows()[0].contains("Get-MpComputerStatus"));
        assert!(s.rows()[1].contains("Get-MpPreference"));
    }
}
