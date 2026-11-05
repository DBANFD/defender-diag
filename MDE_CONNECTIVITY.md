# MDE Standard and Streamlined connectivity samples

## Use
Open **MDE connectivity check** in the dashboard. EU is the default, based on tenant data location, not device location. Enter on region cycles EU/US/UK; Enter on iterations cycles 3/10/30. START runs both samples. The explanation row is available before running. Progress shows rounds/address work; Esc cancels, and results retain completed attempts. Scroll with arrows/Page Up/Down or search with `/`.

```powershell
defender-diag mde-check --region eu --count 3 --output mde-check.json
```

CLI allows 1-1000 rounds, 1-second interval, four concurrent addresses, and 1-120 seconds per stage via --timeout-seconds (default 10). Output JSON is optional and never overwrites files. The dashboard displays results without automatic export.

## What is tested
These are read-only HTTPS GET diagnostic requests, not website home pages or uploads. All resolved IPs are tested independently with the hostname/SNI and certificate verification preserved.

| Sample | EU targets and paths | Purpose |
| --- | --- | --- |
| Standard | winatp-gw-weu.microsoft.com/test, winatp-gw-neu.microsoft.com/test | EDR command/control diagnostics |
| Standard | eu-v20.events.data.microsoft.com/ping | Telemetry diagnostic |
| Standard | cdn.x.cp.wd.microsoft.com/ping, x.cp.wd.microsoft.com/api/report | Cloud protection diagnostics |
| Streamlined | edr-weu, edr-neu, edr-weu3, edr-neu3 under eu.endpoint.security.microsoft.com, each /edr/commands/test | Consolidated command/control diagnostics |
| Streamlined | mdav.eu.endpoint.security.microsoft.com/mdav/wdcp.svc/heartbeat | Consolidated AV diagnostic |
| Streamlined | eu-v20.events.endpoint.security.microsoft.com/ping | Consolidated telemetry diagnostic |

US uses the CUS/EUS regional equivalents (including CUS3/EUS3 for streamlined); UK uses UKS/UKW and UK telemetry/MDAV. The exact versioned registry is assets/mde-probes.json. These lists intentionally cover diagnostic samples, not every failover, storage, update, SmartScreen, configuration or OS-specific dependency. Other commercial regions and sovereign clouds remain in the general feed browser but are not supported by this comparison. Do not test a different region and interpret it as your tenant's readiness.

## Interpretation
- **Responding:** every sampled hostname returned a validated HTTPS GET 200 on the exact diagnostic path on at least one address in every round. HTTP 200 is the diagnostic response criterion; response bodies and sensor certificate pinning are not validated.
- **Alternate-address warning:** IPv4 might work while IPv6 fails, or one backend IP might fail. This remains visible even when hostname reachability passes; success on one IP does not prove all routes are healthy.
- **Partial/intermittent:** some hosts or rounds responded, others did not. Repeat and inspect per-IP/timestamp evidence.
- **Not confirmed:** no sampled host met the criterion. A proxy-only route, different client behavior or service changes can explain this; it does not establish that the sensor is offline.
- **Incomplete:** missing host/round evidence or cancellation. Never treated as a pass.
- **HTTP 403/404/etc.:** HTTPS transport succeeded but the diagnostic response criterion was not met. In general feed tests, these can be normal rejection of a bare request; do not call them network failure. 5xx remains a response requiring review, not proof of interception or sensor health.

The top line says whether both samples responded, only Standard was fully confirmed, only Streamlined was fully confirmed, or neither was fully confirmed. It never detects the installed onboarding mode. New services may use consolidated domains even on standard connectivity. Passing does not certify complete allowlist coverage or eligibility for migration.

## Why mdatp can pass while a broad feed reports errors
`mdatp connectivity test` runs on the Linux endpoint against its diagnostic destinations using its current network settings. A broad feed spans services, regions, operating systems and feature-dependent destinations; root paths, wildcard parents, resource-specific storage, authentication and optional IPv6 probes need different interpretation.

Defender Diag is DIRECT-only and ignores explicit proxy settings. Native roots/rustls validation does not reproduce Defender certificate pinning or all OS trust behavior. It also tests every returned IP rather than accepting an available address as the only evidence. Results from a Windows workstation cannot establish connectivity from a different Linux device. Compare the same device/time, URL/path, address family, region and route. DNS success and a recognizable issuer do not prove TLS or sensor connectivity.

On the actual Linux endpoint run `mdatp connectivity test`. For Windows use Client Analyzer with the device's onboarding parameters; for a pre-onboarding streamlined check Microsoft documents `MDEClientAnalyzer.cmd -o <onboarding-package.cmd>`. This tool does not change onboarding, proxy configuration, policies or service state.

## Sources and maintenance
Reviewed 2026-11-05:
- [Microsoft Linux connectivity diagnostics](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-connectivity): Standard diagnostic paths.
- [Microsoft verification guidance](https://learn.microsoft.com/en-us/defender-endpoint/verify-connectivity): tenant/geo-aware Analyzer verification.
- [Standard commercial requirements](https://learn.microsoft.com/en-us/defender-endpoint/standard-device-connectivity-urls-commercial).
- [Streamlined commercial requirements](https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial): consolidated domain and supporting dependencies.
- Concrete streamlined probes independently transcribed from Microsoft's official [Client Analyzer](https://aka.ms/mdatpanalyzer), Tools/RegionsURLs.json, ScriptVer 15Jul2026, ZIP SHA256 139dc66c7dbe52b04ee94ee3b61f5d531f8323c1bc09cd61413d7bdd9ed3c2e5. This is a reviewed metadata snapshot, not a claim these exact hosts are universally required. No Microsoft scripts or binaries are redistributed.

Live behavior can change. Update the explicit registry with reviewed Microsoft evidence; never convert a timeout or invalid certificate into success merely because it happened before.
