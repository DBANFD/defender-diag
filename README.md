# Defender Diag

A terminal dashboard and command-line tool for investigating Microsoft Defender connectivity. Follow DNS, TCP, TLS, and HTTPS results separately, compare service endpoints, and export evidence for further analysis.

Written in Rust. Current version: **0.5.0**.

## Features

- Interactive target selection, live results, latency graphs, and per-host statistics.
- Direct DNS, TCP, verified TLS, and optional service-aware HTTPS probes.
- Searchable service feeds, regional comparisons, and configurable repeat-test presets.
- JSON and CSV reports, plus an incremental JSONL journal for longer runs.
- Import MDE Client Analyzer findings, with optional Windows collection using a separately supplied Microsoft package.

## Build and run

Install [Rust](https://www.rust-lang.org/tools/install) and a native compiler toolchain. On Windows, use the MSVC toolchain with Visual Studio C++ Build Tools and the Windows SDK.

```sh
git clone https://github.com/DBANFD/demomx.git
cd demomx
cargo build --release --locked
```

Launch the dashboard on Windows:

```powershell
.\target\release\defender-diag.exe
```

On Linux or macOS, the binary path is `./target/release/defender-diag`.

For command-line use, run these examples from the directory containing the Windows binary:

```powershell
.\defender-diag.exe --help
.\defender-diag.exe test login.microsoftonline.com --https
.\defender-diag.exe profile mde --count 10
.\defender-diag.exe test login.microsoftonline.com --preset tls-soak --journal soak.jsonl --output soak.json
```

The examples contact the named public services. Custom targets belong in your local configuration.

## Reading the results

Transport success means that the selected connection stages completed. An HTTP response, including 403 or 404, does not by itself establish Defender sensor health. HTTP 5xx responses remain visible for investigation.

Connections are direct; the tool does not reproduce the sensor's proxy context. TLS certificate verification stays enabled. Reports can contain hostnames, IP addresses, and certificate information, so inspect them before sharing.

## Documentation

| Guide | Contents |
| --- | --- |
| [Usage](USAGE.md) | Dashboard controls, CLI options, profiles, exit codes, and limitations |
| [Testing guide](TESTING_GUIDE.md) | Feed categories, repeat presets, regional comparisons, and journals |
| [Endpoint behavior](ENDPOINT_BEHAVIOR.md) | Probe paths and interpretation of service responses |
| [Client Analyzer](ANALYZER.md) | Importing reports and running a separately supplied Windows package |
| [Report schema](REPORT_SCHEMA.md) | JSON, CSV, and Analyzer output fields |
| [Changelog](CHANGELOG.md) | Changes by version |

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Source is organized under `src/`, with local integration fixtures under `tests/`, feed data under `assets/`, and configuration examples under `examples/`. The CI workflow checks Windows, Linux, and macOS.

Windows is the primary development platform. Cross-platform operational qualification and a full elevated Client Analyzer collection pilot remain ongoing.

## MDE Client Analyzer

Normal source builds do not bundle Microsoft binaries. Import works with an existing report; Windows collection accepts a package supplied by the operator. Microsoft's package retains its own license and prompts. See the [integration guide](ANALYZER.md).

## License

Project source is licensed under [MIT](LICENSE). Microsoft Client Analyzer and other third-party components retain their respective licenses. Defender Diag is an independent project, not an official Microsoft product.
