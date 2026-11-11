//! Keyboard and text-input handling for the dashboard.
use super::*;
impl App {
    pub(super) fn key(&mut self, key: KeyCode) -> bool {
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
                    10 => self.workbench = Some(crate::workbench::Section::MdeCheck),
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
}
