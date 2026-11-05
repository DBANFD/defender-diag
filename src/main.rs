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
        None | Some(Command::Ui) => return defender_diag::ui::run().await,
        Some(command) => command,
    };
    let command = match command {
        Command::Intune {
            action: defender_diag::cli::IntuneAction::Local { mut options },
        } => {
            options.preset = defender_diag::collection::Preset::Intune;
            Command::Collect { options }
        }
        other => other,
    };
    let mut source_feed = None;
    let (hosts, options) = match command {
        Command::Intune { action } => {
            use defender_diag::cli::IntuneAction;
            match action {
                IntuneAction::Coverage { beta } => println!(
                    "{}",
                    serde_json::to_string_pretty(&defender_diag::graph::coverage(beta))?
                ),
                IntuneAction::Cloud { options } => {
                    let cancel = defender_diag::collection::cancel_token();
                    let c = cancel.clone();
                    let watcher = tokio::spawn(async move {
                        let _ = tokio::signal::ctrl_c().await;
                        c.store(true, std::sync::atomic::Ordering::Relaxed);
                    });
                    let result =
                        defender_diag::graph::run(&options, cancel, |s| eprintln!("{s}")).await;
                    watcher.abort();
                    println!("{}", result?.display());
                }
                IntuneAction::Local { .. } => unreachable!(),
            }
            return Ok(true);
        }
        Command::Collect { options } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&defender_diag::collection::plan(&options)?)?
            );
            if options.run {
                let cancel = defender_diag::collection::cancel_token();
                let signal = cancel.clone();
                let watcher = tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    signal.store(true, std::sync::atomic::Ordering::Relaxed);
                });
                let result =
                    defender_diag::collection::run(&options, cancel, |s| eprintln!("{s}")).await;
                watcher.abort();
                println!("{}", result?.display());
            }
            return Ok(true);
        }
        Command::Firewall {
            path,
            search,
            direction,
            action,
            output,
            csv,
        } => {
            let mut v = defender_diag::firewall::parse(&std::fs::read(path)?)?;
            v["rules"] = defender_diag::firewall::filter(
                &v,
                &search,
                direction.as_deref(),
                action.as_deref(),
            )
            .into();
            defender_diag::firewall::export(&v, output.as_deref(), csv.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&v)?);
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
        Command::Ui => unreachable!(),
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
    Ok(report.attempts.iter().all(|a| a.success))
}
