# Windows diagnostic collections and Firewall

## Review before execution
Dashboard: Windows evidence collections > preset > scope preview. H edits hours, U sets an RFC3339 end, M sets MiB, E caps event count, T sets each collector's timeout, O changes output, N opts into the native MDM report. R explicitly starts. Esc requests cancellation and waits for the partial manifest.

~~~powershell
defender-diag collect quick
defender-diag collect defender --hours 48 --max-mib 64 --timeout-seconds 120 --run
defender-diag collect intune --until 2026-01-02T00:00:00Z --hours 24 --run
defender-diag intune local --run
defender-diag collect comprehensive --mdm-report --run
~~~

Without --run the CLI prints the exact plan only. Ctrl+C requests cancellation. Collection does not elevate automatically. Administrator access is recommended for complete machine evidence; denied/missing sources are recorded individually. Windows PowerShell 5.1 and the OS modules are used; the PowerShell 7 module path is not inherited.

## Preset coverage
| Preset | Collectors |
|---|---|
| Quick | SENSE service and Defender AV status; dsregcmd /status |
| Connectivity | IP/DNS/WinHTTP/current-user proxy snapshot; SENSE and Defender operational events |
| Defender | Quick + selected AV preferences/exclusions, Defender/SENSE events, computer gpresult /Z |
| Intune | dsregcmd /status; MDM Admin and AAD Operational events; PolicyManager current device-area values; computer gpresult /Z |
| Firewall | ActiveStore rules/associated filters/profile settings, PersistentStore configured rule summary, network profiles; firewall events; network snapshot |
| Comprehensive | Union of the standard collectors above |

--mdm-report separately opts into MDMDiagnosticsTool DeviceEnrollment;DeviceProvisioning;Autopilot output. It can contain existing ETLs and registry evidence. No preset starts packet capture, performance tracing or memory dumps. Those intensive collectors are not implemented in this release.

Events come from exactly these channels: Microsoft-Windows-Windows Defender/Operational, Microsoft-Windows-SENSE/Operational, Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin, Microsoft-Windows-AAD/Operational, and Microsoft-Windows-Windows Firewall With Advanced Security/Firewall, according to the selected preset. Newest records are bounded by --max-events; the truncation flag is retained.

Health fields cover AV mode, engine/platform/signature versions and selected protection flags, not a complete sensor health assessment. Preferences cover selected protection/cloud/ASR settings, exclusions and proxy settings. Local PolicyManager values are observations, not a complete policy/assignment inventory or universal winning-policy attribution. Group Policy evidence is computer scope; user enrollment/proxy details reflect the collecting account. Missing events or values are not evidence of absence.

## Bounds, evidence and privacy
Default: 24-hour event window, 1,000 events per event collector, 64 MiB aggregate collected payload, 120 seconds per collector. Limits: 720 hours, 100,000 events, 1 GiB, 1,800 seconds. Snapshot and native MDM report times are current collection time, not historical reconstruction.

Stdout is bounded; native MDM artifact size is monitored every 100ms. A native writer can transiently exceed the cap before termination. Only a newly created oversized native artifact is removed; existing evidence is never overwritten. Budget excludes manifest/summary overhead and the duplicate support ZIP. Free disk space must accommodate both payloads and ZIP.

Each run gets a new directory restricted to the current Windows SID and SYSTEM (Unix output directories use mode 0700). Output includes:
- plan.json: declared scope/limits.
- Individual collector payloads and result JSON, including unavailable/failed/partial/cancelled statuses.
- manifest.json: tool/collector versions, timestamps, limits, errors, file sizes and SHA-256.
- SUMMARY.txt and shareable-summary.json.
- support-private.zip: raw evidence and manifest; never uploaded automatically.

Only shareable-summary.json excludes raw values, identifiers, paths, timestamps and arbitrary error text. Raw reports, manifests and ZIPs may include sensitive tenant/device/user configuration, exclusions, certificate and proxy information. Arbitrary diagnostic content cannot be guaranteed anonymous automatically. Cancellation/timeout preserves completed collectors; a process crash can leave per-collector results without a final manifest.

## Effective Firewall
Collect with the Firewall preset, then open the snapshot:
~~~powershell
defender-diag firewall C:\Private\collection\firewall.txt --search 443 --direction outbound --action block --output filtered.json --csv filtered.csv
~~~
Dashboard: Effective Windows Firewall > I imports firewall.txt. / searches; 1/2 filter inbound/outbound; 3/4 filter block/allow; 0 resets; S exports JSON and CSV.

ActiveStore is queried with TracePolicyStore. Rules include direction/action/enabled/profiles/source plus port, address, application, service, interface, interface-type and security filters. Active profile defaults and local merge settings, network profiles, and separately labelled PersistentStore configuration are retained. Null/empty source remains unknown. CSV filters are JSON-valued cells; formula-leading cells are neutralized. Exports use create-new.

This inventory is not a full packet verdict. It does not reconstruct every Windows Filtering Platform provider, third-party filter, dynamic connection state, IPsec negotiation or network-device policy, and cannot prove packets passed.

## Supported methods
Reviewed 2026-11-05:
- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus) and [Get-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference)
- [dsregcmd interpretation](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd)
- [gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [MDM diagnostics](https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs)
- [Get-NetFirewallRule and associated filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule)
