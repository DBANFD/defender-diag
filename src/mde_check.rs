//! Curated, commercial-cloud diagnostic samples, not an onboarding-mode detector.
use crate::{
    cli::{Mode, Options},
    process::Cancel,
    reporting::{Attempt, DnsResult},
    runner,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, atomic::Ordering},
    time::Duration,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    Eu,
    Us,
    Uk,
}
impl Region {
    pub fn name(self) -> &'static str {
        match self {
            Self::Eu => "eu",
            Self::Us => "us",
            Self::Uk => "uk",
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::Eu => Self::Us,
            Self::Us => Self::Uk,
            Self::Uk => Self::Eu,
        }
    }
}
#[derive(Clone, Debug, clap::Args)]
pub struct CheckOptions {
    #[arg(long, value_enum, default_value = "eu")]
    pub region: Region,
    #[arg(long,default_value_t=3,value_parser=clap::value_parser!(u16).range(1..=1000))]
    pub count: u16,
    #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u32).range(1..=120))]
    pub timeout_seconds: u32,
    /// Write a new JSON report; never overwrite an existing file.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Route: direct (default), env, system (Windows WinHTTP) or http://host:port.
    #[arg(long, default_value = "direct", value_parser = crate::proxy::parse_choice)]
    pub proxy: crate::proxy::ProxyChoice,
}
impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            region: Region::Eu,
            count: 3,
            timeout_seconds: 10,
            output: None,
            proxy: Default::default(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Target {
    pub region: String,
    pub model: String,
    pub hostname: String,
    pub path: String,
    pub purpose: String,
    pub source: String,
    pub expected_status: u16,
}
pub fn catalog() -> &'static [Target] {
    static TARGETS: OnceLock<Vec<Target>> = OnceLock::new();
    TARGETS.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/mde-probes.json"))
            .expect("reviewed probe catalog")
    })
}
pub fn targets(region: Region) -> Vec<Target> {
    catalog()
        .iter()
        .filter(|t| t.region == region.name())
        .cloned()
        .collect()
}
pub const LIMITS: &str = "DIRECT commercial-cloud samples, not a complete allowlist, sensor health verdict or configured onboarding-mode detection. HTTP 200 is the diagnostic response criterion; response bodies and sensor certificate pinning are not validated. Per host/round, one validated HTTPS 200 address is enough for reachability; failed alternate IPs remain warnings. Supporting updates, storage uploads, SmartScreen, configuration and tenant-specific endpoints are outside this sample. Government/other regions need their official lists and Client Analyzer.";
pub const COMPARE: &str = "Why mdatp may pass: it tests the installed client's URLs/paths and network settings; feeds cover broader regions/features and generic roots. This app connects DIRECT unless --proxy is set (HTTP CONNECT only; no PAC or proxy authentication), validates with native roots/rustls (not sensor pinning), and tests every resolved IPv4/IPv6 address. Compare on the SAME endpoint and time, with the same URL/path, region and route. On Linux run `mdatp connectivity test`; on Windows use Client Analyzer with the actual onboarding parameters. Do not change onboarding mode based on this sample.";
#[derive(Debug, Serialize)]
pub struct HostResult {
    pub target: Target,
    pub responding_rounds: u16,
    pub observed_rounds: u16,
    pub expected_rounds: u16,
    pub transport_successes: usize,
    pub address_failures: usize,
    pub http_reviews: usize,
    pub verdict: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ModelResult {
    pub model: String,
    pub verdict: String,
    pub responding_hosts: usize,
    pub total_hosts: usize,
    pub address_failures: usize,
}
#[derive(Serialize)]
pub struct CheckReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub started_at: String,
    pub completed_at: String,
    pub region: Region,
    pub route: String,
    pub cancelled: bool,
    pub conclusion: String,
    pub limitations: String,
    pub comparison_guidance: String,
    pub proxy: crate::proxy::ProxyInfo,
    pub hosts: Vec<HostResult>,
    pub models: Vec<ModelResult>,
    pub dns: Vec<DnsResult>,
    pub attempts: Vec<Attempt>,
    pub warnings: Vec<String>,
}
pub fn summarize(
    targets: &[Target],
    attempts: &[Attempt],
    count: u16,
    cancelled: bool,
) -> (Vec<HostResult>, Vec<ModelResult>, String) {
    let hosts: Vec<_> = targets
        .iter()
        .map(|t| {
            let rows: Vec<_> = attempts
                .iter()
                .filter(|a| a.hostname == t.hostname && (1..=count).contains(&a.iteration))
                .collect();
            let responding_rounds = (1..=count)
                .filter(|round| {
                    rows.iter().any(|a| {
                        a.iteration == *round
                            && a.success
                            && a.error.is_none()
                            && a.http_status == Some(t.expected_status)
                            && a.http_method.as_deref() == Some("GET")
                            && a.http_path.as_deref() == Some(t.path.as_str())
                    })
                })
                .count() as u16;
            let observed_rounds = (1..=count)
                .filter(|round| rows.iter().any(|a| a.iteration == *round))
                .count() as u16;
            let verdict = if cancelled || observed_rounds < count {
                "incomplete"
            } else if responding_rounds == count {
                "responding"
            } else if responding_rounds > 0 {
                "intermittent"
            } else if rows.iter().any(|a| a.success) {
                "http_review"
            } else {
                "not_reached"
            };
            HostResult {
                target: t.clone(),
                responding_rounds,
                observed_rounds,
                expected_rounds: count,
                transport_successes: rows.iter().filter(|a| a.success).count(),
                address_failures: rows.iter().filter(|a| !a.success).count(),
                http_reviews: rows
                    .iter()
                    .filter(|a| a.success && a.http_status != Some(t.expected_status))
                    .count(),
                verdict: verdict.into(),
            }
        })
        .collect();
    let models: Vec<_> = ["standard", "streamlined"]
        .into_iter()
        .map(|model| {
            let rows: Vec<_> = hosts.iter().filter(|h| h.target.model == model).collect();
            let n = rows.iter().filter(|h| h.verdict == "responding").count();
            let verdict = if rows.is_empty() || rows.iter().any(|h| h.verdict == "incomplete") {
                "incomplete"
            } else if n == rows.len() {
                "responding"
            } else if rows.iter().any(|h| h.responding_rounds > 0) {
                "partial_or_intermittent"
            } else {
                "not_confirmed"
            };
            ModelResult {
                model: model.into(),
                verdict: verdict.into(),
                responding_hosts: n,
                total_hosts: rows.len(),
                address_failures: rows.iter().map(|h| h.address_failures).sum(),
            }
        })
        .collect();
    let standard = models[0].verdict == "responding";
    let streamlined = models[1].verdict == "responding";
    let conclusion = if cancelled || models.iter().any(|m| m.verdict == "incomplete") {
        "Incomplete test; no combined verdict"
    } else {
        match (standard, streamlined) {
            (true, true) => "Both Standard and Streamlined sampled paths are responding",
            (true, false) => "Standard sampled paths responding; Streamlined not fully confirmed",
            (false, true) => "Streamlined sampled paths responding; Standard not fully confirmed",
            _ => {
                "Neither sample fully confirmed; inspect partial results (not proof both modes are blocked)"
            }
        }
    };
    (hosts, models, conclusion.into())
}
pub async fn run(
    o: &CheckOptions,
    cancel: Cancel,
    emit: impl Fn(String) + Send + Sync,
) -> Result<CheckReport> {
    ensure!(
        (1..=1000).contains(&o.count) && (1..=120).contains(&o.timeout_seconds),
        "Invalid MDE check limits"
    );
    let ts = targets(o.region);
    let started_at = chrono::Utc::now().to_rfc3339();
    let options = Options {
        preset: None,
        journal: None,
        generic_http: false,
        mode: Mode::Https,
        port: 443,
        count: o.count,
        interval: Duration::from_secs(1),
        timeout: Duration::from_secs(o.timeout_seconds.into()),
        concurrency: 4,
        resolve_ip: None,
        output: None,
        csv: None,
        html: None,
        https: true,
        proxy: o.proxy.clone(),
    };
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = observed.clone();
    let mut was_cancelled = false;
    let result = tokio::select! {
        r=runner::run_observed(ts.iter().map(|t|t.hostname.clone()).collect(),&options,|e|match e{runner::Progress::Status(s)=>emit(s),runner::Progress::Attempt(a)=>{captured.lock().unwrap().push(*a);}})=>Some(r?),
        _=async{while !cancel.load(Ordering::Relaxed){tokio::time::sleep(Duration::from_millis(100)).await;}}=>{was_cancelled=true;None}
    };
    let (attempts, dns, warnings) = if let Some(r) = result {
        (r.attempts, r.dns, r.warnings)
    } else {
        (
            observed.lock().unwrap().clone(),
            vec![],
            vec![
                "Cancelled: completed attempts retained; unfinished DNS/address attempts omitted."
                    .into(),
            ],
        )
    };
    let (hosts, models, conclusion) = summarize(&ts, &attempts, o.count, was_cancelled);
    let plan_info =
        crate::proxy::describe(&crate::proxy::plan(&o.proxy).map_err(anyhow::Error::msg)?);
    Ok(CheckReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at,
        completed_at: chrono::Utc::now().to_rfc3339(),
        region: o.region,
        route: plan_info.source.clone(),
        cancelled: was_cancelled,
        conclusion,
        limitations: LIMITS.into(),
        comparison_guidance: COMPARE.into(),
        proxy: plan_info,
        hosts,
        models,
        dns,
        attempts,
        warnings,
    })
}
/// Display status for the curated sample; never a sensor-health verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Incomplete,
}
impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Incomplete => "INCOMPLETE",
        }
    }
}
pub fn outcome(verdict: &str) -> Outcome {
    match verdict {
        "responding" => Outcome::Pass,
        "partial_or_intermittent" | "not_confirmed" => Outcome::Fail,
        _ => Outcome::Incomplete,
    }
}
pub fn console(r: &CheckReport) {
    use std::io::IsTerminal;
    let color = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").as_deref() != Ok("dumb");
    for line in text(r).lines() {
        let model = r
            .models
            .iter()
            .find(|m| line.starts_with(&format!("{}:", m.model.to_uppercase())));
        if color && let Some(m) = model {
            let ansi = match outcome(&m.verdict) {
                Outcome::Pass => "32",
                Outcome::Fail => "31",
                Outcome::Incomplete => "33",
            };
            println!("\x1b[1;{ansi}m{line}\x1b[0m");
        } else {
            println!("{line}");
        }
    }
}
pub fn text(r: &CheckReport) -> String {
    use std::fmt::Write;
    let mut s = format!(
        "MDE connectivity check | {} | DIRECT | {}\n{}\n\n",
        r.region.name().to_uppercase(),
        r.completed_at,
        r.conclusion
    );
    for m in &r.models {
        let _ = writeln!(
            s,
            "{}: {} - {} ({}/{} hosts responding every round; {} failed address attempts)",
            m.model.to_uppercase(),
            outcome(&m.verdict).label(),
            m.verdict,
            m.responding_hosts,
            m.total_hosts,
            m.address_failures
        );
    }
    s.push_str(
        "\nA responding host may still have failed alternate IPs. Failures are retained below.\n",
    );
    for h in &r.hosts {
        let _ = writeln!(
            s,
            "\n[{}] {} | rounds {}/{} | address failures {} | HTTP review {}\n  GET https://{}{}\n  {}",
            h.target.model,
            h.verdict,
            h.responding_rounds,
            h.expected_rounds,
            h.address_failures,
            h.http_reviews,
            h.target.hostname,
            h.target.path,
            h.target.purpose
        );
    }
    s.push_str("\nATTEMPT DETAILS\n");
    for a in &r.attempts {
        let _ = writeln!(
            s,
            "{} round {} {} {:?} | HTTP {:?} | {}\n  {}",
            a.timestamp,
            a.iteration,
            a.hostname,
            a.ip,
            a.http_status,
            a.error
                .as_ref()
                .map(|e| e.code.as_str())
                .unwrap_or("HTTPS transport OK"),
            a.diagnostic_note
        );
    }
    let _ = write!(
        s,
        "\nSCOPE\n{}\n\nCOMPARING WITH MDATP\n{}\n{}\n",
        r.limitations, r.comparison_guidance, r.proxy.note
    );
    s
}
pub fn export(r: &CheckReport, path: &std::path::Path) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(file, r)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good(t: &Target, round: u16) -> Attempt {
        let mut a = Attempt::new(
            t.hostname.clone(),
            Some("192.0.2.1".parse().unwrap()),
            443,
            round,
        );
        a.success = true;
        a.http_status = Some(200);
        a.http_method = Some("GET".into());
        a.http_path = Some(t.path.clone());
        a
    }
    #[test]
    fn display_outcome_does_not_turn_partial_or_unknown_into_pass() {
        assert_eq!(outcome("responding"), Outcome::Pass);
        for v in ["partial_or_intermittent", "not_confirmed"] {
            assert_eq!(outcome(v), Outcome::Fail);
        }
        for v in ["incomplete", "unknown", ""] {
            assert_eq!(outcome(v), Outcome::Incomplete);
        }
    }
    #[test]
    fn catalog_is_concrete_sourced_and_uses_real_paths() {
        for t in catalog() {
            assert!(crate::scope::validate(&t.hostname).is_ok());
            assert!(!t.hostname.contains('*'));
            assert_ne!(t.path, "/");
            let p = crate::endpoints::probe(&t.hostname, 443, false);
            assert_eq!(p.method, "GET");
            assert_eq!(p.path, t.path);
            assert!(!t.source.is_empty());
        }
        assert_eq!(targets(Region::Eu).len(), 11);
    }
    #[test]
    fn ipv6_failure_does_not_hide_working_ipv4_or_make_an_outage() {
        let ts = targets(Region::Eu);
        let mut a: Vec<_> = ts.iter().map(|t| good(t, 1)).collect();
        let mut failed = good(&ts[0], 1);
        failed.ip = Some("2001:db8::1".parse().unwrap());
        failed.success = false;
        failed.http_status = None;
        failed.error = Some(crate::reporting::Failure::new("TCP_UNREACHABLE", "fixture"));
        a.push(failed);
        let (hosts, models, conclusion) = summarize(&ts, &a, 1, false);
        assert_eq!(hosts[0].address_failures, 1);
        assert!(models.iter().all(|m| m.verdict == "responding"));
        assert!(conclusion.starts_with("Both"));
        assert!(!crate::endpoints::alternate_address_note(a.last().unwrap(), &a).is_empty());
    }
    #[test]
    fn http_rejections_and_wrong_paths_are_not_diagnostic_passes() {
        let ts = targets(Region::Eu);
        let mut a = good(&ts[0], 1);
        a.http_status = Some(403);
        let (h, _, c) = summarize(&ts, &[a.clone()], 1, false);
        assert_eq!(h[0].verdict, "http_review");
        assert_eq!(h[0].transport_successes, 1);
        assert!(c.starts_with("Incomplete"));
        a.http_status = Some(200);
        a.http_path = Some("/".into());
        let (h, _, _) = summarize(&ts, &[a], 1, false);
        assert_eq!(h[0].responding_rounds, 0);
    }
    #[test]
    fn intermittent_cancelled_and_missing_results_never_pass() {
        let ts = targets(Region::Eu);
        let mut attempts: Vec<_> = ts.iter().flat_map(|t| [good(t, 1), good(t, 2)]).collect();
        attempts[0].success = false;
        attempts[0].http_status = None;
        let (h, m, _) = summarize(&ts, &attempts, 2, false);
        assert_eq!(h[0].verdict, "intermittent");
        assert_eq!(m[0].verdict, "partial_or_intermittent");
        let (_, m, c) = summarize(&ts, &attempts, 2, true);
        assert!(m.iter().all(|m| m.verdict == "incomplete"));
        assert!(c.starts_with("Incomplete"));
        assert!(summarize(&ts, &[], 3, false).2.starts_with("Incomplete"));
    }
}
