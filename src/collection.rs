//! Windows-only bounded, read-only collectors. Raw evidence never uploads.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
pub type Cancel = Arc<AtomicBool>;
pub fn cancel_token() -> Cancel {
    Arc::new(AtomicBool::new(false))
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, clap::ValueEnum)]
pub enum Preset {
    Quick,
    Connectivity,
    Defender,
    Intune,
    Firewall,
    Comprehensive,
}
#[derive(Clone, Debug, clap::Args)]
pub struct Options {
    #[arg(value_enum, default_value = "quick")]
    pub preset: Preset,
    #[arg(long,default_value_t=24,value_parser=clap::value_parser!(u32).range(1..=720))]
    pub hours: u32,
    /// RFC3339 window end; snapshots always reflect collection time.
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long,default_value_t=64,value_parser=clap::value_parser!(u32).range(1..=1024))]
    pub max_mib: u32,
    #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u32).range(1..=100000))]
    pub max_events: u32,
    #[arg(long,default_value_t=120,value_parser=clap::value_parser!(u32).range(1..=1800))]
    pub timeout_seconds: u32,
    #[arg(long, default_value = "results/collections")]
    pub output_dir: PathBuf,
    /// Opt in to native MDM report (may include existing ETLs and registry data).
    #[arg(long)]
    pub mdm_report: bool,
    /// Execute the displayed scope. Without this flag, print the plan only.
    #[arg(long)]
    pub run: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            preset: Preset::Quick,
            hours: 24,
            until: None,
            max_mib: 64,
            max_events: 1000,
            timeout_seconds: 120,
            output_dir: "results/collections".into(),
            mdm_report: false,
            run: false,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub preset: Preset,
    pub collectors: Vec<String>,
    pub from: String,
    pub until: String,
    pub max_bytes: u64,
    pub max_events: u32,
    pub timeout_seconds: u32,
    pub output_parent: PathBuf,
    pub elevation: String,
    pub impact: String,
    pub gaps: Vec<String>,
}
pub fn plan(o: &Options) -> Result<Plan> {
    ensure!(
        (1..=720).contains(&o.hours)
            && (1..=1024).contains(&o.max_mib)
            && (1..=100000).contains(&o.max_events)
            && (1..=1800).contains(&o.timeout_seconds),
        "Invalid collection limits"
    );
    let until = if let Some(s) = &o.until {
        chrono::DateTime::parse_from_rfc3339(s)?.with_timezone(&chrono::Utc)
    } else {
        chrono::Utc::now()
    };
    let names: &[&str] = match o.preset {
        Preset::Quick => &["health", "enrollment"],
        Preset::Connectivity => &["network", "events-sense", "events-defender"],
        Preset::Defender => &[
            "health",
            "preferences",
            "events-defender",
            "events-sense",
            "enrollment",
            "gpresult",
        ],
        Preset::Intune => &[
            "enrollment",
            "events-mdm",
            "events-aad",
            "mdm-effective",
            "gpresult",
        ],
        Preset::Firewall => &["events-firewall", "network"],
        Preset::Comprehensive => &[
            "health",
            "preferences",
            "enrollment",
            "gpresult",
            "network",
            "events-defender",
            "events-sense",
            "events-mdm",
            "events-aad",
            "mdm-effective",
            "events-firewall",
        ],
    };
    let mut collectors = names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    if o.mdm_report {
        collectors.push("mdm-report".into())
    }
    Ok(Plan{schema_version:1,preset:o.preset,collectors,from:(until-chrono::Duration::hours(o.hours.into())).to_rfc3339(),until:until.to_rfc3339(),max_bytes:u64::from(o.max_mib)*1024*1024,max_events:o.max_events,timeout_seconds:o.timeout_seconds,output_parent:o.output_dir.clone(),elevation:"Windows only. Administrator recommended; unavailable/denied collectors are recorded individually. No automatic elevation.".into(),impact:"Read-only snapshots and bounded recent event queries. Writes private output and a support ZIP. No sync, policy changes, uploads, packet capture, performance recording or memory dumps.".into(),gaps:vec!["Time window applies to events only, not snapshots or native MDM report.".into(),"Event limit can truncate; missing channels do not prove absence of activity.".into(),"Local evidence is not a complete cloud assignment list. User policy reflects the collecting account.".into(),"Native MDM report size is monitored; a running native writer may transiently exceed the budget before cancellation.".into()]})
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEvidence {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultRow {
    pub collector: String,
    pub collector_version: String,
    pub started_at: String,
    pub completed_at: String,
    pub status: String,
    pub error: Option<String>,
    pub files: Vec<FileEvidence>,
}
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub tool_version: String,
    pub started_at: String,
    pub completed_at: String,
    pub cancelled: bool,
    pub plan: Plan,
    pub results: Vec<ResultRow>,
}
pub fn new_dir(parent: &Path, prefix: &str) -> Result<PathBuf> {
    fs::create_dir_all(parent)?;
    let path = parent.join(format!(
        "{prefix}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
    ));
    fs::create_dir(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let identity = std::process::Command::new(crate::analyzer::powershell()?)
            .env_remove("PSModulePath")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ])
            .output()?;
        ensure!(identity.status.success(), "Cannot identify output owner");
        let sid = String::from_utf8(identity.stdout)?.trim().to_string();
        ensure!(
            sid.starts_with("S-1-")
                && sid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"S-".contains(&b)),
            "Invalid owner SID"
        );
        let result = std::process::Command::new(
            PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot unavailable")?)
                .join("System32/icacls.exe"),
        )
        .arg(&path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("*{sid}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
        ])
        .output()?;
        ensure!(
            result.status.success(),
            "Cannot restrict evidence directory ACL"
        );
    }
    Ok(path)
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}
pub fn evidence(path: &Path) -> Result<FileEvidence> {
    let bytes = fs::read(path)?;
    Ok(FileEvidence {
        path: path
            .file_name()
            .context("Missing file name")?
            .to_string_lossy()
            .into(),
        bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}
async fn read_bound(r: impl tokio::io::AsyncRead + Unpin, cap: u64) -> Result<Vec<u8>> {
    let mut v = vec![];
    r.take(cap + 1).read_to_end(&mut v).await?;
    ensure!(v.len() as u64 <= cap, "Output size limit exceeded");
    Ok(v)
}
pub async fn process(
    mut command: tokio::process::Command,
    timeout: Duration,
    cap: u64,
    cancel: Cancel,
    artifact: Option<PathBuf>,
) -> Result<Vec<u8>> {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let deadline = Instant::now() + timeout;
    let reads = async { tokio::try_join!(read_bound(stdout, cap), read_bound(stderr, 64 * 1024)) };
    tokio::pin!(reads);
    let result = loop {
        tokio::select! {
            r=&mut reads=>break r,
            _=tokio::time::sleep(Duration::from_millis(100))=>{
                if cancel.load(Ordering::Relaxed){break Err(anyhow::anyhow!("Cancelled"));}
                if Instant::now()>=deadline{break Err(anyhow::anyhow!("Collector timeout"));}
                if artifact.as_ref().and_then(|p|fs::metadata(p).ok()).is_some_and(|m|m.len()>cap){break Err(anyhow::anyhow!("Native artifact size limit exceeded"));}
            }
        }
    };
    let result = match result {
        Ok((out, err)) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait: Result<std::process::ExitStatus> = tokio::select! {
                r=tokio::time::timeout(remaining,child.wait())=>r.context("Collector timeout").and_then(|r|r.map_err(Into::into)),
                _=async {while !cancel.load(Ordering::Relaxed){tokio::time::sleep(Duration::from_millis(100)).await;}}=>Err(anyhow::anyhow!("Cancelled")),
            };
            match wait {
                Ok(status) if status.success() => Ok(out),
                Ok(status) => Err(anyhow::anyhow!(
                    "Collector exit {:?}: {}",
                    status.code(),
                    crate::analyzer::clean(&String::from_utf8_lossy(&err))
                )),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };
    if result.is_err() {
        #[cfg(windows)]
        if let Some(pid) = child.id() {
            let _ = tokio::process::Command::new(
                PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_default())
                    .join("System32/taskkill.exe"),
            )
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(0x08000000)
            .output()
            .await;
        }
        let _ = child.kill().await;
    }
    result
}
#[cfg(windows)]
async fn collect_one(
    name: &str,
    p: &Plan,
    cancel: Cancel,
    cap: u64,
    artifact: PathBuf,
) -> Result<Vec<u8>> {
    let mut c = tokio::process::Command::new(crate::analyzer::powershell()?);
    c.env_remove("PSModulePath")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("../collectors/windows.ps1"),
        ])
        .env("DD_KIND", name)
        .env("DD_FROM", &p.from)
        .env("DD_UNTIL", &p.until)
        .env("DD_EVENTS", p.max_events.to_string())
        .env("DD_ARTIFACT", &artifact);
    process(
        c,
        Duration::from_secs(p.timeout_seconds.into()),
        cap,
        cancel,
        Some(artifact),
    )
    .await
}
#[cfg(not(windows))]
async fn collect_one(
    _name: &str,
    _p: &Plan,
    _cancel: Cancel,
    _cap: u64,
    _artifact: PathBuf,
) -> Result<Vec<u8>> {
    anyhow::bail!("Windows-only collector unavailable")
}
pub async fn run(o: &Options, cancel: Cancel, progress: impl Fn(String)) -> Result<PathBuf> {
    ensure!(
        cfg!(windows),
        "Local collections require Windows; existing connectivity and report import remain cross-platform"
    );
    let p = plan(o)?;
    let root = new_dir(&o.output_dir, "collection")?;
    let mut m = Manifest {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: String::new(),
        cancelled: false,
        plan: p,
        results: vec![],
    };
    write_new(
        &root.join("plan.json"),
        &serde_json::to_vec_pretty(&m.plan)?,
    )?;
    let mut used = 0u64;
    for name in &m.plan.collectors {
        progress(format!("Collecting {name}"));
        let mut row = ResultRow {
            collector: name.clone(),
            collector_version: "1".into(),
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: String::new(),
            status: "ok".into(),
            error: None,
            files: vec![],
        };
        let artifact = root.join(format!("{name}-native.zip"));
        let cap = m.plan.max_bytes.saturating_sub(used);
        if cancel.load(Ordering::Relaxed) {
            row.status = "cancelled".into();
        } else if cap == 0 {
            row.status = "size_limit".into();
        } else {
            match collect_one(name, &m.plan, cancel.clone(), cap, artifact.clone()).await {
                Ok(bytes) => {
                    let native = fs::metadata(&artifact).map(|m| m.len()).unwrap_or(0);
                    if bytes.len() as u64 + native > cap {
                        row.status = "size_limit".into();
                        row.error = Some("Combined output exceeds remaining budget".into());
                    } else {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                            && (v["truncated"] == true
                                || v["errors"].as_array().is_some_and(|e| !e.is_empty()))
                        {
                            row.status = "partial".into();
                        }
                        let path = root.join(format!("{name}.txt"));
                        write_new(&path, &bytes)?;
                        row.files.push(evidence(&path)?);
                    }
                }
                Err(e) => {
                    row.status = if cancel.load(Ordering::Relaxed) {
                        "cancelled"
                    } else {
                        "unavailable_or_failed"
                    }
                    .into();
                    row.error = Some(crate::analyzer::clean(&e.to_string()));
                }
            }
        }
        if artifact.exists() {
            // Only our new native output can be removed on overflow, never existing evidence.
            let n = fs::metadata(&artifact)?.len();
            if n > cap || row.status == "size_limit" {
                fs::remove_file(&artifact)?;
                row.status = "size_limit".into();
            } else {
                row.files.push(evidence(&artifact)?);
            }
        }
        used += row.files.iter().map(|f| f.bytes).sum::<u64>();
        row.completed_at = chrono::Utc::now().to_rfc3339();
        write_new(
            &root.join(format!("{name}-result.json")),
            &serde_json::to_vec_pretty(&row)?,
        )?;
        m.results.push(row);
    }
    m.cancelled = cancel.load(Ordering::Relaxed);
    m.completed_at = chrono::Utc::now().to_rfc3339();
    write_new(&root.join("manifest.json"), &serde_json::to_vec_pretty(&m)?)?;
    let summary = shareable(&m);
    write_new(
        &root.join("shareable-summary.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    let text = format!(
        "Defender Diag collection\n{}\n\nPrivate raw evidence: do not share without review. Shareable summary excludes all collected values and error text. It is not a health verdict.\n",
        m.results
            .iter()
            .map(|r| format!("{}: {} ({} files)", r.collector, r.status, r.files.len()))
            .collect::<Vec<_>>()
            .join("\n")
    );
    write_new(&root.join("SUMMARY.txt"), text.as_bytes())?;
    support_zip(&root)?;
    progress(format!("Collection complete: {}", root.display()));
    Ok(root)
}
pub fn shareable(m: &Manifest) -> serde_json::Value {
    serde_json::json!({"schema_version":1,"tool_version":m.tool_version,"cancelled":m.cancelled,"collectors":m.results.iter().map(|r|serde_json::json!({"collector":r.collector,"status":r.status,"files":r.files.len()})).collect::<Vec<_>>(),"notice":"Contains no raw values, identifiers, paths, timestamps or error text. Arbitrary diagnostic files cannot be automatically guaranteed anonymous; raw bundle is separate and private."})
}
pub fn support_zip(root: &Path) -> Result<()> {
    let mut paths = fs::read_dir(root)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("support-private.zip"))?;
    let mut zip = zip::ZipWriter::new(f);
    for path in paths {
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "Unexpected symlink in output"
        );
        if path.is_file() {
            zip.start_file(
                path.file_name().unwrap().to_string_lossy(),
                zip::write::SimpleFileOptions::default(),
            )?;
            std::io::copy(&mut fs::File::open(path)?, &mut zip)?;
        }
    }
    zip.finish()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn output_size_and_timeout_are_enforced() {
        let mut command = if cfg!(windows) {
            let mut c = tokio::process::Command::new("powershell.exe");
            c.args(["-NoProfile", "-Command", "'x' * 10000"]);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.args(["-c", "printf '%010000d' 0"]);
            c
        };
        command.kill_on_drop(true);
        assert!(
            process(command, Duration::from_secs(10), 128, cancel_token(), None)
                .await
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
        let command = if cfg!(windows) {
            let mut c = tokio::process::Command::new("powershell.exe");
            c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 10"]);
            c
        } else {
            let mut c = tokio::process::Command::new("sleep");
            c.arg("10");
            c
        };
        assert!(
            process(
                command,
                Duration::from_millis(100),
                128,
                cancel_token(),
                None
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("timeout")
        );
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn mocked_collector_preserves_partial_health() {
        let script = format!(
            "function Get-Service {{ throw 'fixture unavailable' }}; function Get-MpComputerStatus {{ [pscustomobject]@{{AMRunningMode='Normal';AntivirusEnabled=$true}} }}; & {{ {} }}",
            include_str!("../collectors/windows.ps1")
        );
        let mut c = tokio::process::Command::new(crate::analyzer::powershell().unwrap());
        c.env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .env("DD_KIND", "health")
            .env("DD_FROM", "2026-01-01T00:00:00Z")
            .env("DD_UNTIL", "2026-01-02T00:00:00Z")
            .env("DD_EVENTS", "5");
        let bytes = process(
            c,
            Duration::from_secs(15),
            1024 * 1024,
            cancel_token(),
            None,
        )
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["errors"].as_array().unwrap().len(), 1);
        assert_eq!(v["defender"]["AntivirusEnabled"], true);
        assert!(v["sense"].is_null());
    }
    #[test]
    fn preset_scope_and_redaction() {
        let p = plan(&Options {
            preset: Preset::Intune,
            ..Default::default()
        })
        .unwrap();
        assert!(p.collectors.contains(&"mdm-effective".into()));
        assert!(!p.collectors.contains(&"mdm-report".into()));
        let m = Manifest {
            schema_version: 1,
            tool_version: "fixture".into(),
            started_at: "private".into(),
            completed_at: "private".into(),
            cancelled: false,
            plan: p,
            results: vec![ResultRow {
                collector: "health".into(),
                collector_version: "1".into(),
                started_at: "private".into(),
                completed_at: "private".into(),
                status: "partial".into(),
                error: Some("secret user@example.com".into()),
                files: vec![],
            }],
        };
        assert!(!shareable(&m).to_string().contains("user@example.com"));
    }
    #[tokio::test]
    async fn process_cancellation_and_limits() {
        let mut c = if cfg!(windows) {
            let mut c = tokio::process::Command::new("powershell.exe");
            c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"]);
            c
        } else {
            let mut c = tokio::process::Command::new("sleep");
            c.arg("30");
            c
        };
        c.kill_on_drop(true);
        let cancel = cancel_token();
        cancel.store(true, Ordering::Relaxed);
        assert!(
            process(c, Duration::from_secs(5), 1024, cancel, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("Cancelled")
        );
    }
}
