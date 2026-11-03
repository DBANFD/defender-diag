# Security Field Notes

Practical security notes covering Microsoft identity, endpoint protection, and Azure.

**[Browse the notebook](https://dbanfd.github.io/demomx/)**

## In the notebook

| Topic | Note |
| --- | --- |
| Identity | [Going passwordless with Microsoft Entra ID](Entra_Passwordless_TAP_Guide.html) |
| Identity | [Setting up Microsoft Entra Private Access](Entra_Private_Access_Setup.html) |
| Endpoint | [Repairing Defender onboarding on Server 2016](Windows_Server_2016_MDE_Onboarding_Remediation.html) |
| Endpoint | [When Defender Antivirus stays disabled](Server2016_Defender_Troubleshooting.html) |
| Azure | [Reaching on-premises servers with Azure Bastion](Azure_Bastion_OnPrem_RDP.html) |
| Endpoint | [Defender policy says “Succeeded”. Is the setting effective?](Defender_Effective_Policy.html) |
| Endpoint | [Five KQL checks before trusting an endpoint investigation](KQL_Endpoint_Evidence_Checks.html) |
| Endpoint | [Defender on Linux: a health-check runbook](Defender_Linux_Health_Runbook.html) |
| Endpoint | [A vulnerability finding is not proof of exposure](Vulnerability_Exposure_Evidence.html) |
| Identity | [Entra device IDs explained through a practical lookup script](Entra_Device_ID_Lookup.html) |
| Operations | [Migrating Microsoft Graph security alerts to v2](Graph_Alerts_V2_Migration.html) |
| Operations | [Moving Sentinel operations to the Defender portal](Sentinel_Defender_Portal_Transition.html) |
| Azure | [Targeted malware scans in Defender for Storage](Defender_Storage_Targeted_Scanning.html) |

## About these notes

A collection of troubleshooting investigations, implementation guides, and architecture notes. Each article describes a specific scenario and practical next steps. Check current product documentation and adapt the guidance before applying it in your environment.

## Technical review

All five existing articles were reviewed against Microsoft documentation on 2 November 2026. Each article links its sources and distinguishes documented behavior from historical observations.

## New practical notes and downloads

Five additional notes were reviewed against Microsoft documentation on 3 November 2026.

- [Defender snapshot](Get-DefenderSnapshot.ps1): local read-only status and selected preferences.
- [Endpoint evidence queries](endpoint-evidence-checks.kql): five independent Defender XDR hunting queries.
- [Linux checklist](linux-defender-checks.sh): health and cloud-connectivity checks; no protection changes.
- [Exposure worksheet](exposure-assessment-template.csv): one worked example row.
- [Entra device lookup](Find-EntraDeviceId.ps1): exact-name offline lookup with explicit ambiguous and invalid results.

Actual outputs and populated worksheets can contain operational or identifying data; keep them private.

## Microsoft update notes

Three notes translate recent Microsoft changes into practical checks: Graph alert API migration, the Sentinel portal transition, and targeted storage malware scans. Reviewed on 3 November 2026, with links to Microsoft documentation in each article.

## Site structure

The site uses plain HTML, CSS, and a small JavaScript filter. It requires no build step or external dependencies. All articles remain accessible without JavaScript.

- `index.html`: searchable article library and introduction.
- `site.css`: shared layout and article styles, including mobile and print views.
- `site.js`: topic filters and title/summary search.
- Individual HTML files: standalone articles with stable URLs.

To preview locally, run `python -m http.server 8000` from the repository folder and open `http://localhost:8000`.
