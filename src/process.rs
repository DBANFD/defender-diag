//! Bounded child-process runner for read-only Defender queries.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::PathBuf,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancellation_is_reported() {
        let mut c = if cfg!(windows) {
            let mut c = tokio::process::Command::new("powershell.exe");
            c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 10"]);
            c
        } else {
            let mut c = tokio::process::Command::new("sleep");
            c.arg("10");
            c
        };
        c.kill_on_drop(true);
        let cancel = cancel_token();
        cancel.store(true, Ordering::Relaxed);
        assert!(
            process(c, Duration::from_secs(15), 1024, cancel, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("Cancelled")
        );
    }
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
}
