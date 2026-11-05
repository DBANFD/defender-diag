param([Parameter(Mandatory)][string]$AnalyzerZip)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $AnalyzerZip)) { throw "Analyzer ZIP not found: $AnalyzerZip" }
$previous = $env:DEFENDER_DIAG_ANALYZER_ZIP
Push-Location $PSScriptRoot
try {
    $env:DEFENDER_DIAG_ANALYZER_ZIP = (Resolve-Path -LiteralPath $AnalyzerZip).Path
    cargo fmt --all --check
    if ($LASTEXITCODE) { throw 'Formatting failed' }
    cargo clippy --locked --all-targets -- -D warnings
    if ($LASTEXITCODE) { throw 'Clippy failed' }
    cargo test --locked
    if ($LASTEXITCODE) { throw 'Tests failed' }
    cargo build --release --locked
    if ($LASTEXITCODE) { throw 'Build failed' }
    Get-FileHash target/release/defender-diag.exe -Algorithm SHA256
} finally {
    $env:DEFENDER_DIAG_ANALYZER_ZIP = $previous
    Pop-Location
}
