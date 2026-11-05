//! Local read-only Defender queries. No authentication, uploads or automatic files.
use crate::process::Cancel;
use anyhow::Result;
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Query {
    #[value(alias = "running-mode")]
    ComputerStatus,
    Preferences,
}
impl Query {
    pub fn command(self) -> &'static str {
        match self {
            Self::ComputerStatus => {
                "Get-MpComputerStatus -ErrorAction Stop | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties,PSComputerName"
            }
            Self::Preferences => {
                "Get-MpPreference -ErrorAction Stop | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties,PSComputerName"
            }
        }
    }
}
pub fn script(query: Query) -> String {
    format!(
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); {} | ConvertTo-Json -Depth 12",
        query.command()
    )
}
pub fn render(query: Query, bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)?
        .trim_start_matches('\u{feff}')
        .trim();
    let value: serde_json::Value = serde_json::from_str(text)?;
    anyhow::ensure!(
        value.as_object().is_some_and(|o| !o.is_empty()),
        "Defender returned no data or an unexpected response"
    );
    Ok(crate::analyzer::clean(&format!(
        "Command: {}\nRead at: {}\n\n{}",
        query.command(),
        chrono::Utc::now().to_rfc3339(),
        serde_json::to_string_pretty(&value)?
    )))
}
#[cfg(windows)]
pub async fn run(query: Query, cancel: Cancel) -> Result<String> {
    let mut command = tokio::process::Command::new(crate::analyzer::powershell()?);
    command.env_remove("PSModulePath").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script(query),
    ]);
    let bytes = crate::process::process(
        command,
        std::time::Duration::from_secs(60),
        4 * 1024 * 1024,
        cancel,
        None,
    )
    .await?;
    render(query, &bytes)
}
#[cfg(not(windows))]
pub async fn run(_query: Query, _cancel: Cancel) -> Result<String> {
    anyhow::bail!("Local Defender status requires Windows and the Defender PowerShell module")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_and_preferences_preserve_values() {
        assert!(
            render(Query::ComputerStatus, br#"{"AMRunningMode":"Passive","AntivirusEnabled":true,"AMProductVersion":"fixture-version"}"#)
                .unwrap()
                .contains("Passive")
        );
        for bytes in [b"null".as_slice(), b"{}", b"invalid"] {
            assert!(render(Query::ComputerStatus, bytes).is_err());
        }
        let text = render(
            Query::Preferences,
            br#"{"DisableRealtimeMonitoring":false,"ExclusionPath":["C:\\Fixture"]}"#,
        )
        .unwrap();
        assert!(text.contains("false"));
        assert!(text.contains("Fixture"));
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn mocked_powershell_queries() {
        for query in [Query::ComputerStatus, Query::Preferences] {
            let mock = format!(
                "function Get-MpComputerStatus {{ [pscustomobject]@{{AMRunningMode='Normal'; AntivirusEnabled=$true; AMProductVersion='fixture-version'}} }}; function Get-MpPreference {{ [pscustomobject]@{{DisableRealtimeMonitoring=$false; ExclusionPath=@('C:\\Fixture')}} }}; & {{ {} }}",
                script(query)
            );
            let mut command = tokio::process::Command::new(crate::analyzer::powershell().unwrap());
            command.env_remove("PSModulePath").args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &mock,
            ]);
            let bytes = crate::process::process(
                command,
                std::time::Duration::from_secs(15),
                65536,
                crate::process::cancel_token(),
                None,
            )
            .await
            .unwrap();
            let text = render(query, &bytes).unwrap();
            if matches!(query, Query::ComputerStatus) {
                assert!(text.contains("AntivirusEnabled"));
                assert!(text.contains("fixture-version"));
            }
        }
    }
}
