# Security Field Notes

Practical security notes by **Bill Andersson**, covering Microsoft identity, endpoint protection, and Azure.

**[Browse the notebook](https://dbanfd.github.io/demomx/)** · [GitHub profile](https://github.com/DBANFD)

## In the notebook

| Topic | Note |
| --- | --- |
| Identity | [Going passwordless with Microsoft Entra ID](Entra_Passwordless_TAP_Guide.html) |
| Identity | [Setting up Microsoft Entra Private Access](Entra_Private_Access_Setup.html) |
| Endpoint | [Repairing Defender onboarding on Server 2016](Windows_Server_2016_MDE_Onboarding_Remediation.html) |
| Endpoint | [When Defender Antivirus stays disabled](Server2016_Defender_Troubleshooting.html) |
| Azure | [Reaching on-premises servers with Azure Bastion](Azure_Bastion_OnPrem_RDP.html) |

## About these notes

This is a personal collection of troubleshooting investigations, implementation guides, and architecture notes. Each article describes a specific scenario and practical next steps. Check current product documentation and adapt the guidance before applying it in your environment.

## Technical review

All five existing articles were reviewed against Microsoft documentation on 2 November 2026. Each article links its sources and distinguishes documented behavior from historical observations. This was a documentation and command-syntax review, not a live tenant or server validation.

## Site structure

The site uses plain HTML, CSS, and a small JavaScript filter. It requires no build step or external dependencies. All articles remain accessible without JavaScript.

- `index.html`: searchable article library and introduction.
- `site.css`: shared layout and article styles, including mobile and print views.
- `site.js`: topic filters and title/summary search.
- Individual HTML files: standalone articles with stable URLs.

To preview locally, run `python -m http.server 8000` from the repository folder and open `http://localhost:8000`.
