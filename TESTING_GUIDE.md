# Category guide and sustained testing

## Selecting a URL category
Feed names now expand provider, region and service codes, and the highlighted feed has a scope/purpose panel. Search accepts friendly names such as Europe as well as msdefender/eu.

- All scopes / All service categories: broad combined published feed, including scopes that may not apply to your tenant.
- EU (Europe): European service subset; also review Worldwide shared dependencies.
- Worldwide / shared: common service dependencies, not a synonym for every regional feed.
- Malware sample submission: submission destinations; these probes do not upload samples.
- MAPS: antivirus cloud protection destinations.
- Common Linux/macOS: operating-system-specific dependencies.
- Certificate revocation lists: certificate validation dependencies. HTTP-only URLs remain excluded from HTTPS probes.
- Streamlined connectivity patterns: consolidated service patterns; wildcards require concrete hostnames.
- Government labels distinguish DoD, GCC, GCC High and US Government. They do not automatically apply to commercial tenants.

All/Any is scoped to its parent feed. This catalogue is not a declaration that every listed endpoint is required or that a successful sample validates the full service.

References checked 2026-11-04:
- [Feed catalogue](https://docs.paloaltonetworks.com/resources/edl-hosting-service)
- [Microsoft network requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-environment)

## Longer runs
In test settings press **1 Quick**, **2 TLS soak**, **3 Extended**, or **4 Overnight**. Settings remain editable before START.

| Preset | Probe | Rounds | Pause after each completed round | Minimum pause time alone |
|---|---|---:|---:|---:|
| Quick | HTTPS | 3 | 1 second | 2 seconds |
| TLS soak | Verified TLS | 100 | 2 seconds | 3m 18s |
| Extended | HTTPS | 300 | 5 seconds | 24m 55s |
| Overnight | HTTPS | 1,000 | 30 seconds | 8h 19m 30s |

Actual duration adds DNS and probe time; these are not fixed wall-clock durations or fixed sampling rates. Presets use a 15-second timeout per stage, not a 15-second total deadline. TLS soak creates fresh connections each round; it does not keep one connection open. DNS is resolved each round through the OS, whose caching still applies.

CLI examples:
~~~powershell
.\defender-diag.exe test edr-weu.eu.endpoint.security.microsoft.com --preset tls-soak --journal soak.jsonl --output soak.json
.\defender-diag.exe profile mde-regional --mode https --count 50 --interval 5s --timeout 15s --concurrency 10 --journal regional.jsonl --output regional.json
.\defender-diag.exe test login.microsoftonline.com --preset overnight --journal overnight.jsonl --output overnight.json
~~~

CLI presets reject simultaneous count/interval/timeout/mode/https switches to avoid silently overriding requested values. Use manual options to customize. CLI journals are opt-in with --journal; the terminal UI always creates results/attempts-*.jsonl.

## Regional comparison
The new home-menu selection starts with 50 HTTPS rounds, 5-second pauses and concurrency 10. Select/deselect targets before starting. It carries the ten concrete diagnostic hosts from Test-MDERegionalComparison.ps1:
- EDR: WEU, NEU, WEU3, NEU3 and WUS.
- MDAV: EU, US and UK heartbeat probes.
- Controls: login.microsoftonline.com and download.microsoft.com.

These are diagnostic reference targets, not tenant configuration recommendations. Distinct service responses must be interpreted separately. DNS runs in a bounded batch; then per-IP probes from different hosts are interleaved under one global concurrency limit. Probes in a round are near-concurrent where slots allow, not guaranteed simultaneous. Every resolved address is still tested separately.

## Evidence during a run
A journal has one JSON object per line with journal_schema=1, kind and data. Kinds: start (run settings and targets), dns (DnsResult), attempt (Attempt), end (completion timestamp and count). The start record includes the app version. Each record is flushed when written; OS/device write caches still apply. A missing end record means incomplete, and a crash can leave a partial final line. Completed earlier lines remain readable. Journal writes fail the run rather than silently losing evidence. Existing journals are never overwritten.

Full JSON/CSV and summaries are still produced after a successful run completion. Cancelled runs retain the journal and completed UI rows, without inventing a completed report. Journals contain diagnostic evidence and should be handled as internal files.

## Planned improvements

- Local and remote socket tuples for packet-capture correlation.
- Explicit direct-versus-proxy comparisons.
- Total per-probe deadlines and fixed-duration scheduling.
- Per-stage failure trends and consecutive-failure streaks.
