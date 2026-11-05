# Changelog

## 0.6.0

- Microsoft-only feeds and custom-target classification, preserving Microsoft regions/clouds and documented dependencies.
- Runtime standard/preview Analyzer download/import, version selection/pinning and redirect/signature validation. Public build-time embedding removed.
- Local Defender status page and CLI for AMRunningMode and Get-MpPreference, with bounded cancellable queries.
- Removed Intune policy investigation, Graph authentication, Windows evidence presets and effective Firewall rule features before release. Microsoft service connectivity categories remain.
- Anonymous offline query/process fixtures; full elevated Analyzer pilot remains pending.


## 0.5.0 - 2026-11-04

- Readable feed categories, scope descriptions and friendly-name search.
- Quick/TLS-soak/Extended/Overnight presets, plus regional EDR/MDAV/control target selection.
- Global bounded concurrency across hosts and interleaved address probes.
- Incremental JSONL evidence journal preserves completed attempts on cancellation.
- Script review and limits documented in TESTING_GUIDE.md.


## 0.4.0 - 2026-11-04

- Optional embedded Microsoft MDE Client Analyzer, signature-checked Windows launch and preserved native license prompts.
- Read-only XML/ZIP/folder import; dashboard findings, guidance, relevant/all filter and redacted JSON export.
- Separate analyzer evidence schema with source hash, timestamps and vendor exit code; direct-probe statistics remain independent.
- Bounded extraction/import and synthetic fixtures. Full elevated collection and other-OS qualification remain pending.

## 0.3.0 - 2026-11-04

- Neutral service-feed branding in menus and help; technical source provenance retained.
- Reviewed existing PowerShell/shell scripts and Microsoft connectivity guidance. Added exact-host service-aware GET paths and a generic HEAD / comparison toggle.
- Added 55 historical/unverified root-response rules, explanatory assessment fields, and a d-key evidence view. Known generic responses are cyan; all 5xx remain review-worthy. Certificate failures are never suppressed.
- Excluded known wildcard-family apexes from feed targets. Explicit manual tests preserve raw failures and provide context.
- Export schema 2 records HTTP method, path and assessment. Existing source scripts and historical reports preserved.
- Formatting, strict Clippy, 19 tests and Windows release build passed. MDAV heartbeat returned 200; CDN root 404 matched historical context. EDR WEU TLS reset failures were retained without a root-cause claim.

## 0.2.0 - 2026-11-04

- Added an interactive terminal dashboard when launched without arguments, with bordered panels, live per-IP rows, colored outcomes and latency graph.
- Added keyboard target selection, test settings, DNS/TCP/TLS/HTTPS modes, automatic JSON/CSV saves and repeatable runs.
- Added the initial feed catalogue (superseded by Microsoft-only scope in 0.6.0). Added live verified-HTTPS feed download, filtering, exclusion review and concrete-host selection.
- Added feed provenance to JSON: source URL, UTC retrieval time, SHA-256, eligible inventory and exclusions.
- Preserved existing CLI commands; added ui, feeds, edl and --mode.
- Kept wildcard and path exclusions explicit; HTTP 4xx/5xx remain transport successes with amber application-status indicators.
- Verified 16 tests, strict Clippy, formatting and Windows release build. Live keyboard tests and feed import completed. Other OS qualification remains pending.

## 0.1.0 - 2026-11-04

Initial CLI MVP: OS DNS, per-IP TCP, verified TLS, optional HTTPS HEAD, repeated testing, summaries and JSON/CSV reports.
