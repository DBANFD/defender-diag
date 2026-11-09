#![forbid(unsafe_code)]
use clap::Parser;
use defender_diag::{
    cli::{Cli, Command, targets},
    reporting, runner,
};
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::from(1),
        Err(e) => {
            eprintln!("CONFIG_OR_REPORT_ERROR: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}
async fn execute() -> anyhow::Result<bool> {
    let cli = Cli::parse();
    let command = match cli.command {
        None => return defender_diag::ui::run(Default::default()).await,
        Some(Command::Ui { proxy }) => return defender_diag::ui::run(proxy).await,
        Some(command) => command,
    };
    let mut source_feed = None;
    let (hosts, options) = match command {
        Command::MdeCheck { options } => {
            let cancel = defender_diag::process::cancel_token();
            let signal = cancel.clone();
            let watcher = tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.store(true, std::sync::atomic::Ordering::Relaxed);
            });
            let result =
                defender_diag::mde_check::run(&options, cancel, |s| eprintln!("{s}")).await;
            watcher.abort();
            let report = result?;
            defender_diag::mde_check::console(&report);
            if let Some(path) = &options.output {
                defender_diag::mde_check::export(&report, path)?;
            }
            return Ok(!report.cancelled && report.models.iter().all(|m| m.verdict == "responding"));
        }
        Command::Defender { query } => {
            let cancel = defender_diag::process::cancel_token();
            let signal = cancel.clone();
            let watcher = tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.store(true, std::sync::atomic::Ordering::Relaxed);
            });
            let result = defender_diag::defender::run(query, cancel).await;
            watcher.abort();
            println!("{}", result?);
            return Ok(true);
        }
        Command::Analyzer { action } => {
            use defender_diag::{analyzer, cli::AnalyzerCommand};
            match action {
                AnalyzerCommand::Packages { action } => {
                    defender_diag::packages::execute(action).await?;
                }
                AnalyzerCommand::Import { path, output } => {
                    let report = analyzer::import(&path)?;
                    analyzer::console(&report);
                    if let Some(output) = output {
                        analyzer::export(&report, &output)?;
                    }
                }
                AnalyzerCommand::Run { package, work_dir } => {
                    let report = analyzer::run(package.as_deref(), &work_dir)?;
                    analyzer::console(&report);
                    return Ok(report.run_exit_code == Some(0));
                }
                AnalyzerCommand::Prepare { package, work_dir } => {
                    let p = analyzer::prepare(package.as_deref(), &work_dir)?;
                    println!(
                        "Prepared (not executed): {}\nPackage SHA256: {}",
                        p.run_dir.display(),
                        p.sha256
                    );
                }
            }
            return Ok(true);
        }
        Command::Ui { .. } => unreachable!(),
        Command::Feeds { filter } => {
            for url in defender_diag::edl::catalog(&filter) {
                println!(
                    "{}\n  {}\n  {url}\n",
                    defender_diag::catalog::label(&url),
                    defender_diag::catalog::description(&url)
                );
            }
            return Ok(true);
        }
        Command::Edl { feed, options } => {
            let snapshot = defender_diag::edl::fetch(&feed).await?;
            eprintln!(
                "{} concrete hosts; {} entries excluded (wildcards/paths/patterns).",
                snapshot.targets.len(),
                snapshot.skipped.len()
            );
            for x in &snapshot.skipped {
                eprintln!("SKIPPED {}: {}", x.entry, x.reason);
            }
            anyhow::ensure!(
                !snapshot.targets.is_empty(),
                "Feed has no concrete root-host targets"
            );
            let hosts = snapshot.targets.clone();
            source_feed = Some(snapshot);
            (hosts, options)
        }
        Command::Test { host, options } => (
            vec![defender_diag::scope::validate(&host).map_err(anyhow::Error::msg)?],
            options,
        ),
        Command::Profile {
            name,
            options,
            tenant_host,
            config,
        } => (targets(name, tenant_host, config)?, options),
    };
    let mut report = runner::run(hosts, &options).await?;
    report.source_feed = source_feed;
    reporting::console(&report);
    reporting::export(&report, options.output.as_deref(), options.csv.as_deref())?;
    if let Some(path) = &options.html {
        reporting::export_html(&report, path)?;
    }
    Ok(report.attempts.iter().all(|a| a.success))
}
