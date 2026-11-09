# Defender Diag v0.7.1

Portable terminal dashboard and CLI for Microsoft service connectivity, runtime MDE Client Analyzer package management, and local Windows Defender status.

## Downloads

| Asset | Platform |
| --- | --- |
| `x86_64-pc-windows-msvc.zip` | Windows 11 / Windows Server, x64 |
| `x86_64-unknown-linux-gnu.tar.gz` | Linux x64, glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+) |
| `x86_64-apple-darwin.tar.gz` | macOS Intel; built/tested on macOS 15 |
| `aarch64-apple-darwin.tar.gz` | macOS Apple Silicon; built/tested on macOS 15 |

Download the archive matching your CPU, extract it and run `defender-diag.exe` on Windows or `./defender-diag` from Terminal on Linux/macOS. Use `--help` for CLI commands. Rust is not required. Archives include usage documentation and the MIT license. GitHub's automatic source ZIP/tarballs contain source code, not compiled applications.

Verify the archive against `SHA256SUMS.txt` using `Get-FileHash -Algorithm SHA256` on Windows, `sha256sum` on Linux, or `shasum -a 256` on macOS. Checksums detect mismatches; they are not a publisher signature. These builds are not publisher code-signed or Apple-notarized. OS download protections may prompt or block execution; source builds remain available.

## New in 0.7.0

- Pinned, colored Standard and Streamlined results: green PASS, red FAIL and yellow INCOMPLETE, with alternate-address warnings.

- Dedicated Standard/Streamlined MDE diagnostic comparison, EU by default, with US/UK choices. Uses concrete GET paths, not generic root URLs.
- Reports both samples separately, repeated-test intermittency and failed alternate addresses. A responding sample is not full readiness or onboarding-mode detection.
- Clearer DNS/TCP/TLS/HTTP failure guidance and comparison with `mdatp connectivity test`. Raw errors and verification remain intact.

## Features

- DNS, TCP, verified TLS and HTTPS diagnostics, Microsoft-only regional feeds and repeated tests.
- Runtime Analyzer standard/preview download/import with package hashes, Microsoft signature verification, side-by-side selection and pinning.
- Full `Get-MpComputerStatus` and `Get-MpPreference` output in the Windows dashboard and CLI.

## Scope and validation

Release jobs run formatting, strict Clippy, offline tests, release builds and executable version/help smoke checks for every listed target. This is not full operational qualification across every supported OS/version or customer network. Local Windows Defender queries and official Analyzer package acquisition were exercised during development; a full elevated Analyzer collection still needs a pilot.

Local Defender PowerShell queries and Analyzer execution are Windows-only. Linux/macOS retain connectivity diagnostics and Analyzer report import. macOS versions older than the build/test runner are not qualified by this release. Linux ARM and Windows ARM native binaries are not included.

Microsoft packages are not embedded or redistributed. Acquire them separately through the runtime package manager; Microsoft's licensing and prompts apply. No customer fixtures, credentials, local work logs or diagnostic evidence are included. Intune policy investigation, generic Windows evidence collection and effective Firewall rule viewing are not included.
