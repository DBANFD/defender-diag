//! Microsoft analyzer orchestration and read-only, bounded XML/ZIP import.
//! Imported evidence is never merged with direct-probe success percentages.
use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};
const XML_LIMIT: u64 = 16 * 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: String,
    pub severity: String,
    pub category: String,
    pub id: String,
    pub check: String,
    pub result: String,
    pub guidance: String,
    pub relevant: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerReport {
    pub schema_version: u32,
    pub source: String,
    pub source_sha256: String,
    pub imported_at: String,
    pub source_modified_at: Option<String>,
    pub run_exit_code: Option<i32>,
    pub findings: Vec<Finding>,
    pub severity_counts: BTreeMap<String, usize>,
    pub notes: Vec<String>,
}
pub fn clean(s: &str) -> String {
    static ANCHOR: OnceLock<Regex> = OnceLock::new();
    let anchor = ANCHOR.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*href=['"]([^'"]+)['"][^>]*>(.*?)</a>"#).unwrap()
    });
    let linked = anchor.replace_all(s, "$2 ($1)");
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    let re=RE.get_or_init(||[
        r"(?i)\b(https?|socks5?)://[^\s/@<>]+@",
        r"(?i)\b[^\s:/@<>]+:[^\s/@<>]+@",
        r#"(?i)(https?://[^\s?<>"']+)\?[^\s<>"']*"#,
        r"(?im)\b(authorization|proxy-authorization|password|passwd|access_token|refresh_token|client_secret|token|secret)\s*[:=]\s*[^\r\n]+",
        r"<[^>]*>",
    ].iter().map(|p|Regex::new(p).unwrap()).collect());
    let s = re[0].replace_all(&linked, "$1://[REDACTED]@");
    let s = re[1].replace_all(&s, "[REDACTED]@");
    let s = re[2].replace_all(&s, "$1?[REDACTED]");
    let s = re[3].replace_all(&s, "$1=[REDACTED]");
    let s = re[4].replace_all(&s, " ");
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(16384)
        .collect::<String>()
        .trim()
        .to_string()
}
fn value(node: roxmltree::Node<'_, '_>, name: &str) -> String {
    node.children()
        .find(|n| n.has_tag_name(name))
        .and_then(|n| n.text())
        .map(clean)
        .unwrap_or_default()
}
fn rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "error" | "high" | "critical" => 0,
        "warning" | "medium" | "low" => 1,
        "informational" | "info" => 2,
        _ => 3,
    }
}
fn relevant(category: &str, check: &str, severity: &str) -> bool {
    let s = format!("{category} {check}").to_ascii_lowercase();
    rank(severity) <= 1
        || [
            "connect", "proxy", "tls", "ssl", "cert", "dns", "onboard", "sense", "sensor", "av",
            "cloud", "edr", "tamper",
        ]
        .iter()
        .any(|word| s.contains(word))
}
pub fn parse_xml(bytes: &[u8], source: &str) -> Result<AnalyzerReport> {
    ensure!(
        bytes.len() as u64 <= XML_LIMIT,
        "Analyzer XML exceeds 16 MiB"
    );
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(bytes.len().is_multiple_of(2), "Invalid UTF-16 XML");
        let le = bytes[0] == 0xff;
        let words: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if le {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect();
        String::from_utf16(&words).context("Invalid UTF-16")?
    } else {
        std::str::from_utf8(bytes)?
            .trim_start_matches('\u{feff}')
            .to_string()
    };
    let doc = roxmltree::Document::parse(&text)
        .context("Invalid analyzer XML (DTDs/external entities are not supported)")?;
    ensure!(
        doc.root_element().has_tag_name("MDEResults"),
        "Not an MDE Client Analyzer MDEResults XML report"
    );
    let mut findings = Vec::new();
    let mut counts = BTreeMap::new();
    for node in doc
        .root_element()
        .children()
        .filter(|n| n.has_tag_name("events"))
        .flat_map(|n| n.children())
        .filter(|n| n.has_tag_name("event"))
    {
        ensure!(findings.len() < 10000, "Too many analyzer findings");
        let severity = value(node, "severity");
        let category = value(node, "category");
        let check = value(node, "check");
        *counts
            .entry(if severity.is_empty() {
                "Unknown".into()
            } else {
                severity.clone()
            })
            .or_insert(0) += 1;
        findings.push(Finding {
            kind: "event".into(),
            relevant: relevant(&category, &check, &severity),
            severity,
            category,
            id: clean(node.attribute("id").unwrap_or("")),
            check,
            result: value(node, "checkresult"),
            guidance: value(node, "guidance"),
        });
    }
    let mut notes=vec!["Analyzer evidence is a source-time snapshot, not current device state or a direct-probe result. Zero errors is not proof of complete collection.".into(),
        "Only selected snapshot fields and structured events are imported. Sensitive patterns are redacted; original vendor artifacts are preserved separately and can contain sensitive data.".into()];
    if findings.is_empty() {
        notes.push(
            "No structured analyzer events were present; collection may be incomplete.".into(),
        );
    }
    // Explicitly omit onboarding payloads, custom policy blobs and arbitrary registry material.
    let allowed = [
        "scriptVersion",
        "scriptRunTime",
        "traceStartTime",
        "traceStopTime",
        "ScriptVersion",
        "ScriptVer",
        "StartTime",
        "EndTime",
        "date",
        "Date",
        "Time",
        "deviceName",
        "OSName",
        "OSBuild",
        "Architecture",
        "SenseVersion",
        "SenseConfigVersion",
        "SenseServiceStatus",
        "SenseStartType",
        "SenseProxyConfig",
        "SimplifiedConnectivity",
        "Location",
        "DefenderState",
        "DefenderAVProxy",
        "SSLOptions",
        "NetworkProtectionState",
        "DefenderServiceStartType",
        "AVPlatformVersion",
        "AVSignatureVersion",
        "AVEngineVersion",
        "SystemWideProxy",
        "CurlProxy",
        "SenseCMEnrollmentStatus",
        "MDfWSState",
    ];
    for section in doc
        .root_element()
        .children()
        .filter(|n| n.is_element() && !n.has_tag_name("events"))
    {
        for node in section
            .children()
            .filter(|n| n.is_element() && allowed.contains(&n.tag_name().name()))
        {
            ensure!(findings.len() < 10000, "Too many analyzer fields");
            let check = clean(
                node.attribute("displayName")
                    .unwrap_or(node.tag_name().name()),
            );
            let is_proxy = node
                .tag_name()
                .name()
                .to_ascii_lowercase()
                .contains("proxy");
            let result = if is_proxy {
                "[Proxy field present; raw configuration withheld. Review original analyzer report locally.]".into()
            } else {
                value(node, "value")
            };
            findings.push(Finding {
                kind: "snapshot".into(),
                severity: value(node, "alert"),
                category: section.tag_name().name().into(),
                id: node.tag_name().name().into(),
                check,
                result,
                guidance: String::new(),
                relevant: true,
            });
        }
    }
    findings.sort_by_key(|f| (rank(&f.severity), !f.relevant, f.kind.clone()));
    Ok(AnalyzerReport {
        schema_version: 1,
        source: clean(source),
        source_sha256: format!("{:x}", Sha256::digest(bytes)),
        imported_at: chrono::Utc::now().to_rfc3339(),
        source_modified_at: None,
        run_exit_code: None,
        findings,
        severity_counts: counts,
        notes,
    })
}
fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.take(limit + 1).read_to_end(&mut buf)?;
    ensure!(buf.len() as u64 <= limit, "Input exceeds size limit");
    Ok(buf)
}
fn find_xml(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, visited: &mut usize) -> Result<()> {
    ensure!(depth <= 6, "Result directory nesting exceeds 6 levels");
    for entry in fs::read_dir(dir)? {
        *visited += 1;
        ensure!(*visited <= 10000, "Too many result directory entries");
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            find_xml(&entry.path(), depth + 1, out, visited)?;
        } else if entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case("MDEClientAnalyzer.xml")
        {
            out.push(entry.path());
        }
    }
    Ok(())
}
pub fn import(path: &Path) -> Result<AnalyzerReport> {
    if path.is_dir() {
        let mut matches = Vec::new();
        find_xml(path, 0, &mut matches, &mut 0)?;
        ensure!(
            matches.len() == 1,
            "Expected exactly one MDEClientAnalyzer.xml; found {}. Select a specific run or XML file.",
            matches.len()
        );
        return import(&matches[0]);
    }
    let file = fs::File::open(path).context("Open analyzer results")?;
    let modified = file
        .metadata()?
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
    let mut report = if path
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("zip"))
    {
        ensure!(
            file.metadata()?.len() <= ARCHIVE_LIMIT,
            "Result archive exceeds 512 MiB; import its XML directly"
        );
        let mut zip = zip::ZipArchive::new(file)?;
        ensure!(zip.len() <= 10000, "Too many archive entries");
        let names: Vec<_> = zip
            .file_names()
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|n| {
                n.replace('\\', "/")
                    .rsplit('/')
                    .next()
                    .is_some_and(|v| v.eq_ignore_ascii_case("MDEClientAnalyzer.xml"))
            })
            .map(|s| s.into_owned())
            .collect();
        ensure!(
            names.len() == 1,
            "Expected exactly one MDEClientAnalyzer.xml in result ZIP; found {}",
            names.len()
        );
        let member = zip.by_name(&names[0])?;
        ensure!(member.size() <= XML_LIMIT, "Analyzer XML exceeds 16 MiB");
        let bytes = read_limited(member, XML_LIMIT)?;
        parse_xml(&bytes, &format!("{}!{}", path.display(), names[0]))?
    } else {
        ensure!(
            path.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("xml")),
            "Select a result ZIP, XML or extracted result folder (HTML-only import is not supported)"
        );
        parse_xml(&read_limited(file, XML_LIMIT)?, &path.display().to_string())?
    };
    report.source_modified_at = modified;
    Ok(report)
}
pub fn export(report: &AnalyzerReport, path: &Path) -> Result<()> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(f, report)?;
    Ok(())
}
pub fn console(r: &AnalyzerReport) {
    println!(
        "MDE CLIENT ANALYZER | source: {} | events: {:?}",
        r.source, r.severity_counts
    );
    for n in &r.notes {
        println!("NOTE: {n}");
    }
    for f in &r.findings {
        println!(
            "[{}] {} {} / {}: {}\n  {}",
            f.severity, f.id, f.category, f.check, f.result, f.guidance
        );
    }
}
#[derive(Debug)]
pub struct Prepared {
    pub run_dir: PathBuf,
    pub script: PathBuf,
    pub sha256: String,
}
fn safe_member(name: &str) -> Result<PathBuf> {
    let normalized = name.replace('\\', "/");
    ensure!(
        !normalized.starts_with('/') && !normalized.contains(':') && !normalized.contains('\0'),
        "Unsafe ZIP member"
    );
    ensure!(
        normalized.split('/').all(|p| p != ".." && p != "."),
        "Unsafe ZIP traversal"
    );
    for part in normalized.split('/').filter(|p| !p.is_empty()) {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            !part.ends_with(['.', ' '])
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !((stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.len() == 4
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "Unsafe Windows ZIP filename"
        );
    }
    Ok(PathBuf::from(normalized))
}
pub fn prepare(package: Option<&Path>, parent: &Path) -> Result<Prepared> {
    let bytes = if let Some(path) = package {
        read_limited(fs::File::open(path)?, 64 * 1024 * 1024)?
    } else {
        let path = crate::packages::selected(&crate::packages::store())?;
        read_limited(fs::File::open(path)?, 64 * 1024 * 1024)?
    };
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "Analyzer package exceeds size limit"
    );
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let mut zip = zip::ZipArchive::new(Cursor::new(&bytes))?;
    ensure!(zip.len() <= 2000, "Analyzer package exceeds 2000 entries");
    let mut total = 0u64;
    for i in 0..zip.len() {
        let f = zip.by_index(i)?;
        safe_member(&f.name()?)?;
        ensure!(
            !f.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000),
            "Symlink in analyzer package"
        );
        total = total
            .checked_add(f.size())
            .context("Archive size overflow")?;
        ensure!(
            f.size() <= 64 * 1024 * 1024 && total <= 256 * 1024 * 1024,
            "Analyzer archive expands beyond limits"
        );
    }
    fs::create_dir_all(parent)?;
    let run_dir = parent.join(format!(
        "run-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
    ));
    fs::create_dir(&run_dir)?;
    let mut scripts = Vec::new();
    let mut expanded = 0u64;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let relative = safe_member(&entry.name()?)?;
        let target = run_dir.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        fs::create_dir_all(target.parent().context("Missing file parent")?)?;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let written = std::io::copy(&mut (&mut entry).take(64 * 1024 * 1024 + 1), &mut f)?;
        ensure!(written <= 64 * 1024 * 1024, "Expanded file exceeds bound");
        expanded = expanded
            .checked_add(written)
            .context("Expanded size overflow")?;
        ensure!(
            expanded <= 256 * 1024 * 1024,
            "Expanded package exceeds bound"
        );
        if target
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("MDEClientAnalyzer.ps1"))
        {
            scripts.push(target);
        }
    }
    ensure!(
        scripts.len() == 1,
        "Expected one MDEClientAnalyzer.ps1 in analyzer package"
    );
    let script = std::path::absolute(scripts.remove(0))?;
    ensure!(
        script.parent().unwrap().join("Tools/EULA.ps1").is_file(),
        "Analyzer package is missing Tools/EULA.ps1"
    );
    let run_dir = std::path::absolute(run_dir)?;
    fs::write(run_dir.join("package-sha256.txt"), format!("{hash}\n"))?;
    Ok(Prepared {
        run_dir,
        script,
        sha256: hash,
    })
}
#[cfg(windows)]
pub fn powershell() -> Result<PathBuf> {
    let system = std::env::var_os("SystemRoot").context("SystemRoot is unavailable")?;
    let root = PathBuf::from(system);
    let sysnative = root.join("Sysnative/WindowsPowerShell/v1.0/powershell.exe");
    Ok(if sysnative.exists() {
        sysnative
    } else {
        root.join("System32/WindowsPowerShell/v1.0/powershell.exe")
    })
}
#[cfg(windows)]
pub fn run(package: Option<&Path>, parent: &Path) -> Result<AnalyzerReport> {
    use std::process::Command;
    let ps = powershell()?;
    let status=Command::new(&ps).env_remove("PSModulePath").args(["-NoProfile","-NonInteractive","-Command",
        "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 65 }"]).status()?;
    ensure!(
        status.success(),
        "Analyzer collection requires administrator rights. Close and Run as administrator; import works without elevation."
    );
    let selected;
    let package = if package.is_some() {
        package
    } else {
        selected = crate::packages::selected(&crate::packages::store())?;
        Some(selected.as_path())
    };
    let prepared = prepare(package, parent)?;
    crate::packages::verify(&prepared.script)?;
    // Path passes via environment data, never interpolated into PowerShell program text.
    let verify=Command::new(&ps).env_remove("PSModulePath").env("DEFENDER_DIAG_SCRIPT",&prepared.script).args(["-NoProfile","-NonInteractive","-Command",
        "$s=Get-AuthenticodeSignature -LiteralPath $env:DEFENDER_DIAG_SCRIPT; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'O=Microsoft Corporation') { exit 0 } else { Write-Error 'Microsoft analyzer signature validation failed'; exit 66 }"]).status()?;
    ensure!(
        verify.success(),
        "Microsoft signature validation failed. Package retained at {}",
        prepared.run_dir.display()
    );
    println!(
        "Running original Microsoft analyzer (default diagnostics). Respond to its license/publisher prompts if shown.\nRun directory: {}",
        prepared.run_dir.display()
    );
    let root = prepared
        .script
        .parent()
        .context("Analyzer package root missing")?;
    // AllSigned; no remote, crash, reboot, memory-dump or tracing switches.
    let status = Command::new(&ps)
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-ExecutionPolicy", "AllSigned", "-File"])
        .arg(&prepared.script)
        .arg("-outputDir")
        .arg(root)
        .current_dir(root)
        .status()?;
    let result = root.join("MDEClientAnalyzerResult");
    let mut report=import(&result).with_context(||format!("Analyzer exited {:?}; no readable structured results. Inspect {}. License decline or incomplete collection is not success.",status.code(),prepared.run_dir.display()))?;
    report.run_exit_code = status.code();
    if let Ok(packages) = crate::packages::list(&crate::packages::store()) {
        for p in packages.into_iter().filter(|p| p.sha256 == prepared.sha256) {
            report.notes.push(format!(
                "Package {} | channel {} | source {} | version {} | acquired {}",
                p.id,
                p.channel.name(),
                p.source,
                p.script_version.as_deref().unwrap_or("not exposed"),
                p.acquired_at
            ));
        }
    }
    report.notes.push(format!("Collected with Microsoft analyzer package SHA256 {}. Process exit {:?}; findings are not a health guarantee.",prepared.sha256,status.code()));
    if !status.success() {
        report
            .notes
            .push("Analyzer process exited unsuccessfully; results may be partial.".into());
    }
    export(
        &report,
        &prepared.run_dir.join("defender-diag-analyzer-summary.json"),
    )?;
    Ok(report)
}
#[cfg(not(windows))]
pub fn run(_package: Option<&Path>, _parent: &Path) -> Result<AnalyzerReport> {
    anyhow::bail!(
        "Bundled analyzer collection is Windows-only. Import existing Windows result ZIP/XML on this platform."
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    const XML: &str = r#"<MDEResults><general/><EDRCompInfo><SenseServiceStatus displayName="Sense"><value>Running</value><alert>None</alert></SenseServiceStatus><SenseProxyConfig displayName="Proxy"><value>http://user:secret@proxy:8080</value></SenseProxyConfig></EDRCompInfo><events><event id="130001"><severity>Error</severity><category>Connectivity</category><check>TLS</check><checkresult>Failed https://u:p@host/?token=private</checkresult><guidance>Check &lt;a href='https://learn.microsoft.com/test'&gt;TLS&lt;/a&gt;</guidance></event></events></MDEResults>"#;
    #[test]
    fn parses_findings_and_redacts_secrets() {
        let r = parse_xml(XML.as_bytes(), "fixture").unwrap();
        assert_eq!(r.severity_counts["Error"], 1);
        assert_eq!(r.findings.len(), 3);
        let json = serde_json::to_string(&r).unwrap();
        for secret in ["user:secret", "u:p@", "token=private"] {
            assert!(!json.contains(secret));
        }
        assert!(r.findings[0].relevant);
        assert_eq!(r.findings[0].id, "130001");
    }
    #[test]
    fn rejects_dtd_and_wrong_documents() {
        assert!(
            parse_xml(
                b"<!DOCTYPE x [<!ENTITY x 'oops'>]><MDEResults>&x;</MDEResults>",
                "bad"
            )
            .is_err()
        );
        assert!(parse_xml(b"<html/>", "bad").is_err());
        assert!(parse_xml(b"<MDEResults>", "bad").is_err());
    }
    #[test]
    fn empty_report_is_not_all_clear() {
        let r = parse_xml(b"<MDEResults/>", "empty").unwrap();
        assert!(r.notes.iter().any(|n| n.contains("incomplete")));
    }
    #[test]
    fn traversal_and_ads_are_rejected() {
        for n in [
            "../evil",
            "..\\evil",
            "/root",
            "C:\\evil",
            "Tools/file:stream",
        ] {
            assert!(safe_member(n).is_err());
        }
        assert!(safe_member("Tools/tool.exe").is_ok());
    }
    #[test]
    fn utf16_and_create_new_exports() {
        let mut bytes = vec![0xff, 0xfe];
        for w in XML.encode_utf16() {
            bytes.extend(w.to_le_bytes());
        }
        let r = parse_xml(&bytes, "utf16").unwrap();
        assert_eq!(r.findings.len(), 3);
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("report.json");
        export(&r, &p).unwrap();
        assert!(export(&r, &p).is_err());
    }
    #[test]
    fn imports_nested_zip_without_extracting_other_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("result.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&p).unwrap());
        zip.start_file(
            "MDEClientAnalyzerResult/SystemInfoLogs/MDEClientAnalyzer.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(XML.as_bytes()).unwrap();
        zip.finish().unwrap();
        let r = import(&p).unwrap();
        assert_eq!(r.findings.len(), 3);
        assert!(!d.path().join("MDEClientAnalyzerResult").exists());
    }
    #[test]
    fn ambiguous_zip_and_unsafe_package_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ambiguous.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&p).unwrap());
        for name in [
            "first/MDEClientAnalyzer.xml",
            "second/MDEClientAnalyzer.xml",
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(XML.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        assert!(import(&p).is_err());
        let bad = d.path().join("bad.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&bad).unwrap());
        writer
            .start_file("../escape.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"bad").unwrap();
        writer.finish().unwrap();
        assert!(prepare(Some(&bad), &d.path().join("extract")).is_err());
        assert!(!d.path().join("extract").exists());
    }
}
