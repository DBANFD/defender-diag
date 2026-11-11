# Endpoint behavior review - 2026-11-04

## Existing scripts reviewed

- Test-MDEConnectivity.ps1: knownQuirks, expectedNoDns, HTTP/TLS verdicts, endpoint port metadata.
- Test-MDEConnectivity.sh: parallel expected-response rules and historical control-run comments.
- Invoke-MDEFullDiag.ps1: EDR/MDAV repeated URL proof paths.
- Test-MDERegionalComparison.ps1: region/hostname catalogue and request paths.

Original scripts remain unchanged. Their historical observations are useful context; they do not establish today's DNS or service behavior. Some rows explicitly say they were not baselined. Those retain an unverified expectation label.

55 exact-host root-response rules were carried into assets/endpoint-expectations.json. Wildcard and path-specific rows were not generalized. CRL and Windows Update port-80 observations were excluded from this HTTPS rule set. Historical 5xx observations remain review-worthy. DNS/TCP/TLS errors cannot be converted to success by an expectation rule.

The old scripts include an enterprise-registration exception based partly on a recognizable public issuer name. It was deliberately not carried over: issuer names alone do not validate trust, hostname, expiry, or absence of interception.

## Request selection

| Target | Request | Basis |
|---|---|---|
| Five exact EDR region hosts from the regional script | GET /edr/commands/test | Local regional comparison and full-diagnostics scripts |
| mdav.eu/us/uk.endpoint.security.microsoft.com | GET /mdav/wdcp.svc/heartbeat | Local regional comparison and full-diagnostics scripts |
| Six exact winatp-gw region hosts listed in Microsoft's Linux troubleshooting example | GET /test | Microsoft Linux troubleshooting documentation |
| Exact CDN and v20 telemetry names in that example | GET /ping | Microsoft Linux troubleshooting documentation |
| x.cp.wd.microsoft.com | GET /api/report | Microsoft Linux troubleshooting documentation |
| Other hosts, non-443 ports, or --generic-http | HEAD / | Generic transport probe; no sensor-specific protocol claim |

Only response headers are read, not service response bodies. A status 200 is therefore not a semantic validation of the service-specific response payload. Custom tenant names are not matched using loose substring rules. --generic-http and the interactive HTTP-probing toggle permit comparison against the original root probe.

## Expected versus observed

- 4xx at a bare service root can be compatible with working HTTPS transport. A matching historical rule is displayed as KNOWN in cyan, with its provenance in details/JSON.
- Unbaselined script expectations remain amber and explicitly qualified.
- Any 5xx remains review-worthy. Historical MDAV/SmartScreen 502 or MAPS 503 observations do not prove that a new 5xx is benign. Intermediaries and services can both generate these responses.
- Certificate errors remain failures, including when the issuer has a familiar public CA name.
- The four wildcard-family apexes identified by the old scripts are excluded from feed-selected targets. An explicit manual test retains the raw DNS result and explains the limitation. There is no assumption that public DNS state can never change.
- reflector.defender.microsoft.com is documented as an optional IPv6 test endpoint. DNS/TCP failures receive that context without being rewritten as successes. TLS errors are still classified as transport failures.
- dmd.metaservices.microsoft.com is not in the scripts' expected-no-DNS list. Its earlier lookup failure is unresolved; it is not relabelled benign or retired without evidence.

## Official references

- [Linux cloud-connectivity troubleshooting](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-connectivity): service-specific test paths and mdatp connectivity test; also discusses HTTP 502 in the TLS-inspection troubleshooting context.
- [Streamlined commercial connectivity URLs](https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial): wildcard core service requirement, optional IPv6 reflector, supporting endpoints and port-80 certificate validation.
- [Verify client connectivity](https://learn.microsoft.com/en-us/defender-endpoint/verify-connectivity): Client Analyzer and onboarding/region context.
- [Validate Antivirus cloud connectivity](https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus): MpCmdRun -ValidateMapsConnection and why a generic HTTP success does not necessarily validate MAPS.

Feed source URLs remain in technical provenance for reproducibility; product menus and help use neutral service-feed labels.

## 0.7.0 curated connectivity comparison
The new [MDE check](MDE_CONNECTIVITY.md) uses an independently assembled, sourced exact-host/path registry (`assets/mde-probes.json`). It supersedes historical-script paths for those exact hosts. These GET paths are also used by normal HTTPS probes unless `--generic-http` is selected. Raw DNS/TCP/TLS evidence remains unchanged. Failed address attempts now carry stage-specific next steps and live context when another IP worked in the same round.
