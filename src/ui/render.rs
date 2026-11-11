//! Dashboard drawing. Reads application state, never changes it.
use super::*;
pub(super) fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
}
pub(super) fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}
pub(super) fn draw(f: &mut Frame, a: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(4),
    ])
    .split(f.area());
    let route_label = format!("{} CONNECTIONS", crate::proxy::session_label());
    let header = format!(
        " DEFENDER-DIAG  v{}    |    {}    |    {}",
        env!("CARGO_PKG_VERSION"),
        if matches!(a.page, Page::AnalyzerMenu | Page::AnalyzerResults) {
            "ANALYZER EVIDENCE"
        } else {
            &route_label
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
                "Microsoft Defender - regional / service URL feeds".into(),
                "Browse All Microsoft service URL feeds (filter by provider / region)".into(),
                "Quick example targets - MDE West Europe + Entra".into(),
                "Microsoft Entra ID - login.microsoftonline.com".into(),
                "Custom Microsoft service hostname".into(),
                "MDE Client Analyzer - run / import / view findings".into(),
                "Regional comparison - EDR regions + MDAV + control hosts".into(),
                "Defender status - Get-MpComputerStatus / Get-MpPreference".into(),
                "Microsoft Azure - management / portal sample targets".into(),
                "Microsoft Intune - enrollment sample target".into(),
                "MDE connectivity check - Standard / Streamlined (EU default)".into(),
            ],
        ),
        Page::AnalyzerMenu => (
            " MDE Client Analyzer ".into(),
            vec![
                "Run selected Microsoft package - requires administrator; license prompts preserved".into(),
                "Import existing result ZIP / MDEClientAnalyzer.xml / extracted folder".into(),
                "View loaded analyzer findings".into(),
                "Manage packages - standard / preview / import / select / pin".into(),
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
                    " Excluded feed entries - NOT tested; never counted as successes ".into(),
                    a.feed
                        .as_ref()
                        .map(|s| {
                            s.skipped
                                .iter()
                                .map(|x| format!("{} - {}", safe(&x.entry), x.reason))
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
            " Configure test - Enter cycles mode or edits value ".into(),
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
                    "▶ START - {} hosts × {} rounds",
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
pub(super) fn draw_analyzer(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
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
            " Microsoft analyzer evidence - source-time snapshot ",
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
pub(super) fn draw_results(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
    if a.details {
        let text=a.attempts.get(a.cursor).map(|x|format!(
            "{}\nIP {:?} | port {} | round {} | {}\nRequest: {} {}\nAssessment: {}\n\n{}\n\nError: {:?}\nTLS {:?} | {:?}\nCertificates:\n{}",
            x.hostname,x.ip,x.port,x.iteration,x.timestamp,x.http_method.as_deref().unwrap_or("not attempted"),x.http_path.as_deref().unwrap_or(""),
            x.assessment,format_args!("{}\n{}",safe(&x.diagnostic_note),crate::endpoints::alternate_address_note(x,&a.attempts)),x.error,x.tls_version,x.cipher,
            x.certificates.iter().map(|c|format!("Subject: {}\nIssuer: {}\nExpires: {}",safe(&c.subject),safe(&c.issuer),safe(&c.expires))).collect::<Vec<_>>().join("\n")
        )).unwrap_or_else(||"No completed attempt selected.".into());
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(panel(" Evidence / interpretation - d returns to table ")),
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
            "{} | Done {total} | Transport OK {ok} | Failed attempts {} | HTTP review {app_errors} | {:.1}%",
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
            " Overview - HTTP error responses are not transport failures ",
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
        let ms = |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "-".into());
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
                |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "-".into());
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
                "{stats}\n{}\n{}\n{} | {:?} | {:?}\n{cert}\n{dns}\n{error}",
                safe(&x.diagnostic_note),
                crate::endpoints::alternate_address_note(x, &a.attempts),
                x.timestamp,
                x.tls_version,
                x.cipher
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
