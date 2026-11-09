# defender-diag

A portable Rust terminal dashboard and CLI for direct DNS, TCP, and verified TLS troubleshooting. Optional service-aware HTTPS probes distinguish HTTP responses (including 403/404/500) from transport failures.

**Status:** version 0.6.0. See the pull request and CI for current checks. Interactive keyboard navigation, Entra HTTPS and service feed import were exercised live. CI covers Windows, Linux, and macOS; see the repository Actions tab for current results. Cross-platform production qualification remains outstanding.

See [Defender status](DEFENDER_STATUS.md) for local running mode and preference queries.

## Interactive terminal dashboard

Run defender-diag.exe without arguments (or with ui). It opens a full-screen keyboard-driven dashboard. The EXE contains the menu, graphics and feed catalogue; no sidecar files or Rust installation are needed. A modern terminal with Unicode support is recommended; maximize it (120 columns or wider) for long hostnames and certificate details.

1. Choose Defender feeds, all Microsoft service URL feeds, example targets, Entra, or a custom Microsoft service hostname.
2. For feeds, type to filter by provider, region or service (e.g. msdefender/eu). Arrows select a feed; Enter downloads current contents over verified direct HTTPS.
3. Space toggles hosts; a selects all/none; x shows excluded entries; c adds a concrete hostname. Enter opens test settings.
4. Choose DNS only, DNS+TCP, DNS+TCP+verified TLS, or HTTPS probes. Configure rounds, delay, timeout, port and concurrency; select START.
5. Follow live rows and the latency graph. Green means transport success, red means transport failure, cyan KNOWN means a generic response matching a historical script baseline, and amber means an HTTP response requiring review. Press d for request and interpretation details. Arrows inspect attempts and per-host latency statistics.
6. Completed runs automatically save JSON and CSV to ./results in the working directory. Press s to save another copy, n for a new test, or q to quit. Esc cancels a running test; cancelled-run rows remain visible and completed evidence is retained in the incremental JSONL journal.

The catalogue embeds 155 Microsoft URL-feed links captured on 2026-11-04 from the linked service catalogue. Feed contents are downloaded fresh, with no silent cached fallback. The catalogue itself is a dated snapshot; use the CLI edl command for a newer published feed URL until the next catalogue update. IP feeds are intentionally excluded because TLS requires a concrete hostname.

## Category descriptions and longer testing

Feed browsing now displays readable scope/service names and a category explanation. Search by Europe or the original path. In test settings use 1 Quick, 2 TLS soak, 3 Extended, or 4 Overnight. The new regional comparison menu combines EDR reference regions with MDAV and general controls. Completed attempts are saved incrementally, including during cancelled UI runs. See [TESTING_GUIDE.md](TESTING_GUIDE.md) for exact timings, CLI examples, scope caveats and the review of the existing diagnostic scripts.

## MDE Client Analyzer

Select **MDE Client Analyzer** from the home menu to run a separately supplied Windows collector or import existing XML/ZIP/folder results. The app surfaces errors, warnings, sensor/AV details and guidance. Collection requires administrator rights; import does not. Source builds do not include the Microsoft package; supply your own package for Windows collection. See [ANALYZER.md](ANALYZER.md) for usage, licensing, build instructions and validation limits. Full elevated collection remains to be piloted.

## Install and build

Install stable Rust using rustup. Windows needs Visual Studio C++ Build Tools (MSVC and Windows SDK); Debian/Ubuntu needs a C compiler/linker, e.g. build-essential; macOS needs Xcode command line tools. A native root certificate store is required.

Run from this folder on a host with access to crates.io:

~~~sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
~~~

The binary is target/release/defender-diag (defender-diag.exe on Windows). Cargo.lock is included from successful dependency resolution. Use --locked for reproducible checks/builds.

## Usage

~~~sh
defender-diag
defender-diag feeds --filter msdefender/eu
defender-diag edl --feed https://saasedl.paloaltonetworks.com/feeds/msdefender/eu/any/url --mode dns --output eu-dns.json
defender-diag test login.microsoftonline.com
defender-diag test edr-weu.eu.endpoint.security.microsoft.com --count 30 --interval 2s
defender-diag test login.microsoftonline.com --port 443 --output results.json
defender-diag test login.microsoftonline.com --https --csv attempts.csv
defender-diag profile mde --count 10
defender-diag profile entra
defender-diag profile custom --config examples/endpoints.json
defender-diag profile mde --config region-specific.json --count 10
~~~

Use a documented Microsoft service hostname. Manual hosts must match the sourced Microsoft classification registry. A configuration file replaces the example list; --tenant-host appends a concrete host. Files use {"endpoints":["login.microsoftonline.com"]}. Maximum 256 hosts; duplicates are removed. Only ASCII DNS hostnames are accepted (use punycode for IDNs); URLs, credentials, IP literals, wildcards and paths are rejected. --resolve-ip bypasses DNS and records that fact while preserving hostname validation, SNI and HTTP Host.

Options:
- --count 1..1000 (default 1); --interval delay between completed rounds (default 1s).
- --timeout per-stage deadline (default 10s, positive, maximum 1h).
- --concurrency 1..64 (default 4), limiting simultaneous DNS lookups and, in the probe phase, per-IP connections across hosts. Addresses from different hosts are interleaved.
- --port 1..65535 (default 443); the selected mode determines whether TLS is attempted.
- --mode dns|tcp|tls|https selects the deepest stage (CLI default tls); DNS/TCP modes do not load trust roots.
- --https enables service-aware HTTP/1.1 probes after TLS. Selected EDR/MDAV/gateway/CDN/telemetry hosts use GET on specific test paths; other hosts use HEAD /. --generic-http forces HEAD / for comparison. The interactive settings menu also exposes this switch. Redirects are recorded, never followed.
- --proxy selects the route: direct (default), env (HTTPS_PROXY or ALL_PROXY, honouring NO_PROXY), system (Windows WinHTTP from `netsh winhttp show proxy`, including its bypass list and <local>) or an explicit http://host:port. Only unauthenticated HTTP CONNECT proxies are supported; credentials in the URL are rejected, and a 407 reply is reported as PROXY_AUTH_REQUIRED. The proxy resolves target names, so a proxied host gets one attempt per round with no IP, and local DNS results are kept as evidence only. DNS mode always resolves locally. `defender-diag ui --proxy ...` applies the route to every dashboard test, including the MDE connectivity check.
- --html writes a self-contained HTML report (no scripts or external resources). The dashboard saves HTML next to JSON and CSV.
- --output JSON and --csv CSV use create-new semantics and refuse to overwrite evidence. Parent folders must exist. An I/O failure may leave a partial file; errors exit 2.

Exit codes: 0 = every selected transport probe succeeded; 1 = at least one DNS/TCP/TLS/HTTP transport probe failed; 2 = configuration, trust-store setup, or output error. HTTP application statuses do not cause exit 1.

## Evidence and interpretation

DNS uses Tokio's OS resolver, honoring host OS resolution policies and caches, and records every unique returned IPv4/IPv6 address for every round. It does not claim to enumerate authoritative DNS records: OS address selection and caches can affect results. DNS timeout cancellation may not terminate an underlying blocking OS lookup.

In TLS/HTTPS modes, each IP receives a new TCP connection and a full TLS handshake (session resumption disabled). SNI and verification use the original hostname. Native trust anchors are loaded with rustls-native-certs and validated by rustls. SSL_CERT_FILE/SSL_CERT_DIR can affect root loading. This is not Schannel/Secure Transport validation parity: automatic AIA fetching, native revocation checks and OS TLS policy are not reproduced. Client certificates and TLS 1.0/1.1 are unsupported. Certificate subject, issuer and expiry are recorded for the server-supplied chain after successful verification; the root may not be sent.

TCP codes separate timeout, refusal, unreachable, permission denial, reset and other errors. TLS certificate errors preserve rustls details (such as hostname mismatch, unknown issuer or expiration). TLS timeout is distinct from TCP success. A certificate error can indicate interception or missing enterprise roots; it is not proof of either. Compare evidence from affected and unaffected networks before attributing cause.

Each attempted stage has elapsed milliseconds, including failed stages; unattempted stages are null. Success percentages count per-IP attempts, so a hostname with more returned addresses contributes more attempts. DNS failure is a hostname-only failed row. Successful latency statistics use the selected connection stages, excluding DNS, queueing and delays. DNS-only mode produces one hostname row per round with lookup latency and all addresses in the DNS observation. p95 is nearest-rank ceil(0.95*N). Failures never enter successful-latency statistics. Empty successful samples produce null latency metrics.

Connections are DIRECT unless --proxy is set. Proxy environment variable names are reported, never their values; the configured proxy is exported as host:port only. These settings do not establish the Defender sensor's effective proxy configuration. No credentials, cookies, tokens, request authorization or proxy authentication are sent. HTTP response headers/bodies are not exported; this avoids leaking Set-Cookie or redirect tokens. Certificate identities and internal host/IP values remain operationally sensitive evidence.

A 403/404 proves an HTTPS response was received on that connection; it does not establish service enrollment, authentication, sensor health, or access to all required paths.

## Profiles and endpoint sources

Built-in mde contains only edr-weu.eu.endpoint.security.microsoft.com; entra contains only login.microsoftonline.com. Custom requires classified Microsoft service hosts. These are EXAMPLES, not comprehensive allowlists. Keep region/tenant-specific endpoint files under your own change control.

Microsoft's official [connectivity verification guidance](https://learn.microsoft.com/en-us/defender-endpoint/verify-connectivity) explains that endpoint selection depends on onboarding geography and standard/streamlined connectivity, and provides the Defender Client Analyzer workflow. Use that analyzer for sensor-context checks.

The [external endpoint feed service](https://docs.paloaltonetworks.com/resources/edl-hosting-service) provides dynamically maintained MS Defender lists. The dashboard and edl command import concrete root-host entries from those lists. Wildcards, non-root URL paths, explicit HTTP URLs, IPs/ranges and unsupported patterns are excluded with reasons. Feed URL, retrieval timestamp, SHA-256 and parsed inventory are recorded in JSON under source_feed. Selected targets are represented by the attempt rows. Never remove a wildcard and assume its apex tests every covered service.

## Deferred beyond this MVP

- --dns-server resolver override, explicit A/AAAA record queries, and CNAME-chain display. The OS API does not expose CNAME chains.
- Invalid-certificate inspection mode (verification is always enabled).
- Automatic GET fallback on method rejection, arbitrary custom paths, selected safe response-header capture.
- WinINET/PAC/WPAD discovery, proxy authentication and sensor-effective proxy analysis.
- Automatic catalogue refresh, wildcard expansion using tenant inventory, and URL-path-specific probes. The embedded feed catalogue is dated; imported concrete hosts are not full service coverage.
- Stage-specific aggregate percentiles, streaming final reports, complete interrupted-run summaries and retry scheduling. Incremental JSONL journaling is available.
- Signed installation packages, dependency/security audit and completed Windows Server/Linux/macOS qualification.

Memory is bounded by configuration and returned DNS results, but reports accumulate in memory. Avoid large host sets multiplied by 1000 iterations until streaming storage is implemented. Use --journal for CLI runs to preserve completed attempts incrementally. The terminal UI enables journaling automatically; a missing end record identifies an incomplete run.

## Architecture and tests

Separate modules cover CLI/configuration, DNS, TCP, TLS, HTTP, proxy detection, statistics, reporting, orchestration, EDL import and the terminal UI. No application unsafe Rust is allowed. Unit tests cover hostile hostname parsing, limits, TCP classification, HTTP status handling and statistics. Integration fixtures use local loopback TLS servers for SNI/Host correctness, trusted and untrusted certificates, stalled TLS, JSON/CSV output and evidence overwrite protection. They do not contact public services.

CI defines stable Windows, Ubuntu and macOS builds. A passing CI run and a real endpoint pilot are required before claiming production readiness.

## Endpoint response interpretation

See [ENDPOINT_BEHAVIOR.md](ENDPOINT_BEHAVIOR.md) for the script review, official sources and probe-path decisions. 55 exact-root HTTPS response rules are embedded from the existing script as historical/unverified context, not Microsoft service-health guarantees. They never override failed DNS, TCP or TLS stages. Generic root expectations do not apply to a different test path. HTTP 5xx remains review-worthy even if an old script accepted it.

Known wildcard-family apexes are excluded when importing feeds; concrete service names are required. An explicitly requested apex still records its raw DNS failure with contextual guidance. No undocumented DNS failures are silently labelled expected. Version 0.3.0 exports schema 2 with method, path and assessment fields; prior reports remain unchanged.

Defender queries: exit 0 means output was retrieved, not that protection is healthy. Missing module, access denial, cancellation and query errors exit 2. Use `defender computer-status` or `defender preferences`; see [Defender status](DEFENDER_STATUS.md).

## MDE connectivity comparison
Dashboard: **MDE connectivity check**. CLI: `defender-diag mde-check --region eu --count 3 --output mde-check.json`. Regions: eu/us/uk; default eu. CLI permits 1-1000 rounds and `--timeout-seconds` 1-120 (default 10 per stage); interval is one second, concurrency four. Ctrl+C/Esc cancels and retains completed attempts in the partial result. Exit 0 means both curated samples responded; 1 means partial/incomplete/not confirmed; 2 means a fatal configuration/report error. This does not report the device's configured onboarding mode or full service readiness. See [coverage and interpretation](MDE_CONNECTIVITY.md).
