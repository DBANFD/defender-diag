//! Operator-owned runtime package store. No package is embedded or published.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Standard,
    Preview,
}
impl Channel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Preview => "preview",
        }
    }
    pub fn url(self) -> &'static str {
        match self {
            Self::Standard => "https://aka.ms/mdatpanalyzer",
            Self::Preview => "https://aka.ms/MDEClientAnalyzerPreview",
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub schema_version: u32,
    pub id: String,
    pub channel: Channel,
    pub acquired_at: String,
    pub source: String,
    pub redirects: Vec<String>,
    pub sha256: String,
    pub script_version: Option<String>,
    pub signatures: serde_json::Value,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Selection {
    pub id: String,
    pub pinned: bool,
}
pub fn store() -> PathBuf {
    if let Some(p) = std::env::var_os("LOCALAPPDATA") {
        PathBuf::from(p).join("DefenderDiag/packages")
    } else if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(p).join("defender-diag/packages")
    } else {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
            .join(".local/share/defender-diag/packages")
    }
}
pub async fn execute(action: crate::cli::PackageAction) -> Result<()> {
    use crate::cli::PackageAction;
    let root = store();
    match action {
        PackageAction::List => println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"store":root,"packages":list(&root)?,"selection":selection(&root)?})
            )?
        ),
        PackageAction::Download { channel } => println!(
            "{}",
            serde_json::to_string_pretty(&download(&root, channel).await?)?
        ),
        PackageAction::Import { path, channel } => println!(
            "{}",
            serde_json::to_string_pretty(&import(
                &root,
                &path,
                channel,
                "offline import (channel operator-declared)",
                vec![]
            )?)?
        ),
        PackageAction::Select { id, pin } => select(&root, &id, pin)?,
        PackageAction::Unpin => {
            let s = selection(&root)?.context("No selected package")?;
            select(&root, &s.id, false)?;
        }
    }
    Ok(())
}
pub fn list(root: &Path) -> Result<Vec<Package>> {
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for e in fs::read_dir(root)? {
        let e = e?;
        if e.file_type()?.is_dir() && e.path().join("metadata.json").is_file() {
            out.push(serde_json::from_slice(&fs::read(
                e.path().join("metadata.json"),
            )?)?);
        }
    }
    out.sort_by(|a: &Package, b| a.acquired_at.cmp(&b.acquired_at));
    Ok(out)
}
fn valid_id(id: &str) -> Result<()> {
    ensure!(
        id.len() < 100
            && id
                .split_once('-')
                .is_some_and(|(c, h)| matches!(c, "standard" | "preview")
                    && h.len() == 64
                    && h.bytes().all(|b| b.is_ascii_hexdigit())),
        "Invalid package ID"
    );
    Ok(())
}
pub fn selection(root: &Path) -> Result<Option<Selection>> {
    if !root.exists() {
        return Ok(None);
    }
    let mut files = fs::read_dir(root)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("selection-")
                && e.path().extension().is_some_and(|x| x == "json")
        })
        .map(|e| e.path())
        .collect::<Vec<_>>();
    files.sort();
    files
        .last()
        .map(|p| Ok(serde_json::from_slice(&fs::read(p)?)?))
        .transpose()
}
pub fn selected(root: &Path) -> Result<PathBuf> {
    let s = selection(root)?
        .context("No package selected. Use analyzer packages download/import, then select.")?;
    checked_path(root, &s.id)
}
pub fn checked_path(root: &Path, id: &str) -> Result<PathBuf> {
    valid_id(id)?;
    let path = root.join(id).join("package.zip");
    let hash = format!("{:x}", Sha256::digest(read_zip(&path)?));
    ensure!(
        id.ends_with(&hash),
        "Package hash mismatch; stored content changed"
    );
    Ok(path)
}
pub fn select(root: &Path, id: &str, pinned: bool) -> Result<()> {
    checked_path(root, id)?;
    let mut temp = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer(
        &mut temp,
        &Selection {
            id: id.into(),
            pinned,
        },
    )?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(root.join(format!(
        "selection-{}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
    )))?;
    Ok(())
}
fn read_zip(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    fs::File::open(path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024 * 1024, "Package exceeds 64 MiB");
    Ok(bytes)
}
pub fn allowed_download(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && matches!(url.host_str(), Some("aka.ms" | "download.microsoft.com"))
}
pub async fn download(root: &Path, channel: Channel) -> Result<Package> {
    install_download(root, channel, fetch_download(channel)).await
}
async fn install_download(
    root: &Path,
    channel: Channel,
    fetch: impl std::future::Future<Output = Result<(Vec<u8>, Vec<String>)>>,
) -> Result<Package> {
    let (bytes, chain) = fetch.await?;
    fs::create_dir_all(root)?;
    let mut tmp = tempfile::NamedTempFile::new_in(root)?;
    tmp.write_all(&bytes)?;
    import(root, tmp.path(), channel, channel.url(), chain)
}
async fn fetch_download(channel: Channel) -> Result<(Vec<u8>, Vec<String>)> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(120))
        .build()?;
    let mut url = reqwest::Url::parse(channel.url())?;
    let mut chain = vec![];
    for _ in 0..6 {
        ensure!(
            allowed_download(&url),
            "Blocked Analyzer redirect: unexpected origin"
        );
        chain.push(url.to_string());
        let mut response = client.get(url.clone()).send().await?;
        if response.status().is_redirection() {
            url = url.join(
                response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .context("Redirect has no Location")?
                    .to_str()?,
            )?;
            continue;
        }
        ensure!(
            response.status().is_success(),
            "Download returned HTTP {}",
            response.status()
        );
        ensure!(
            url.host_str() == Some("download.microsoft.com"),
            "Package must be delivered by download.microsoft.com"
        );
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 64 * 1024 * 1024,
                "Package exceeds 64 MiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        return Ok((bytes, chain));
    }
    anyhow::bail!("Too many redirects; previous selection preserved")
}
pub fn import(
    root: &Path,
    path: &Path,
    channel: Channel,
    source: &str,
    redirects: Vec<String>,
) -> Result<Package> {
    import_verified(root, path, channel, source, redirects, verify)
}
fn import_verified(
    root: &Path,
    path: &Path,
    channel: Channel,
    source: &str,
    redirects: Vec<String>,
    verifier: impl Fn(&Path) -> Result<serde_json::Value>,
) -> Result<Package> {
    let bytes = read_zip(path)?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let id = format!("{}-{hash}", channel.name());
    fs::create_dir_all(root)?;
    let stage = tempfile::tempdir_in(root)?;
    let zip = stage.path().join("package.zip");
    fs::write(&zip, bytes)?;
    let prepared = crate::analyzer::prepare(Some(&zip), stage.path())?;
    let signatures = verifier(&prepared.script)?;
    let text = fs::read_to_string(&prepared.script).unwrap_or_default();
    let re =
        regex::Regex::new(r#"(?im)^\s*\$ScriptVer(?:sion)?\s*=\s*['"]([^'"\r\n]{1,100})['"]"#)?;
    let package = Package {
        schema_version: 1,
        id: id.clone(),
        channel,
        acquired_at: chrono::Utc::now().to_rfc3339(),
        source: source.into(),
        redirects,
        sha256: hash,
        script_version: re.captures(&text).map(|c| c[1].into()),
        signatures,
    };
    let dest = root.join(&id);
    if !dest.exists() {
        // Only commit ZIP/metadata after bounded extraction and signature validation.
        let commit = tempfile::tempdir_in(root)?;
        fs::copy(&zip, commit.path().join("package.zip"))?;
        fs::write(
            commit.path().join("metadata.json"),
            serde_json::to_vec_pretty(&package)?,
        )?;
        fs::rename(commit.path(), &dest)?;
    }
    // Successful updates may switch only an unpinned selection of the same channel.
    let old = selection(root)?;
    if old
        .as_ref()
        .is_none_or(|s| !s.pinned && s.id.starts_with(channel.name()))
    {
        select(root, &id, false)?;
    }
    Ok(package)
}
#[cfg(windows)]
pub fn verify(script: &Path) -> Result<serde_json::Value> {
    let ps = crate::analyzer::powershell()?;
    let out=std::process::Command::new(ps).env_remove("PSModulePath").env("DD_SCRIPT",script).args(["-NoProfile","-NonInteractive","-Command",r#"$ErrorActionPreference='Stop'; $files=@(Get-ChildItem -LiteralPath (Split-Path -LiteralPath $env:DD_SCRIPT) -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1','.exe','.dll' }); $rows=@(foreach($f in $files){$s=Get-AuthenticodeSignature -LiteralPath $f.FullName; [pscustomobject]@{file=$f.Name;status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject;thumbprint=[string]$s.SignerCertificate.Thumbprint}}); $rows | ConvertTo-Json -Depth 4 -Compress; if(!$rows.Count -or @($rows|Where-Object { $_.status -ne 'Valid' -or $_.subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)' }).Count){exit 66}"#]).output()?;
    ensure!(
        out.status.success(),
        "Microsoft Authenticode verification failed; package not installed. Results: {} {}",
        crate::analyzer::clean(&String::from_utf8_lossy(&out.stdout)),
        crate::analyzer::clean(&String::from_utf8_lossy(&out.stderr))
    );
    Ok(serde_json::from_slice(&out.stdout)?)
}
#[cfg(not(windows))]
pub fn verify(_script: &Path) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"status":"not_verified","reason":"Authenticode requires Windows; hash is identity only. Execution unsupported here."}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn update_switch_pin_and_failed_download_preserve_packages() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("store");
        let fixture = |name: &str, version: &str| {
            let p = d.path().join(name);
            let mut z = zip::ZipWriter::new(fs::File::create(&p).unwrap());
            for (name, body) in [
                (
                    "MDEClientAnalyzer.ps1",
                    format!("$ScriptVer = '{version}'\n# Anonymous fixture, never executed"),
                ),
                ("Tools/EULA.ps1", "# fixture".into()),
            ] {
                z.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                z.write_all(body.as_bytes()).unwrap();
            }
            z.finish().unwrap();
            p
        };
        let a = import_verified(
            &root,
            &fixture("a.zip", "fixture-a"),
            Channel::Standard,
            "fixture",
            vec![],
            |_| Ok(serde_json::json!({"status":"mock verifier"})),
        )
        .unwrap();
        select(&root, &a.id, true).unwrap();
        let b = import_verified(
            &root,
            &fixture("b.zip", "fixture-b"),
            Channel::Standard,
            "fixture",
            vec![],
            |_| Ok(serde_json::json!({"status":"mock verifier"})),
        )
        .unwrap();
        assert_eq!(selection(&root).unwrap().unwrap().id, a.id);
        assert_eq!(list(&root).unwrap().len(), 2);
        assert!(
            install_download(&root, Channel::Standard, async {
                anyhow::bail!("synthetic network failure")
            })
            .await
            .is_err()
        );
        assert_eq!(selection(&root).unwrap().unwrap().id, a.id);
        select(&root, &b.id, false).unwrap();
        assert_eq!(selection(&root).unwrap().unwrap().id, b.id);
        assert!(checked_path(&root, &a.id).is_ok());
    }
    #[test]
    fn redirect_boundaries() {
        for u in [
            "http://download.microsoft.com/a",
            "https://download.microsoft.com.evil.example/a",
            "https://user@download.microsoft.com/a",
            "https://evil.example/a",
        ] {
            assert!(!allowed_download(&u.parse().unwrap()));
        }
        assert!(allowed_download(
            &"https://download.microsoft.com/download/a.zip"
                .parse()
                .unwrap()
        ));
    }
    #[test]
    fn invalid_import_keeps_pin() {
        let d = tempfile::tempdir().unwrap();
        let hash = format!("{:x}", Sha256::digest(b"fixture"));
        let id = format!("standard-{hash}");
        fs::create_dir(d.path().join(&id)).unwrap();
        fs::write(d.path().join(&id).join("package.zip"), b"fixture").unwrap();
        select(d.path(), &id, true).unwrap();
        let p = d.path().join("bad.zip");
        fs::write(&p, b"not a zip").unwrap();
        assert!(import(d.path(), &p, Channel::Standard, "offline", vec![]).is_err());
        assert!(selection(d.path()).unwrap().unwrap().pinned);
        assert!(selected(d.path()).is_ok());
        assert!(checked_path(d.path(), "../escape").is_err());
    }
}
