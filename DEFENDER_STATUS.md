# Local Defender status

Dashboard: **Defender status** > **Get-MpComputerStatus** or **Get-MpPreference** > Enter.
Use arrows or Page Up/Down to scroll, `/` to filter lines, and Esc to return. Select a query again for a fresh snapshot. Esc during a query cancels it.

```powershell
defender-diag defender computer-status
defender-diag defender preferences
```

Status uses the full `Get-MpComputerStatus` output, including running mode, protection state, signature versions and scan information. Preferences use `Get-MpPreference`. Both retain all returned data properties and arrays, omitting only CIM transport metadata. Values are displayed as indented JSON with the command and query time. Empty responses are reported as unavailable rather than guessed. The previous `running-mode` CLI name remains an alias for the full computer-status query.

Windows only, using Windows PowerShell and the installed Defender module. Queries are read-only: no policy changes, cloud authentication, collection bundles, automatic output files or uploads. Run as administrator if the OS denies access; the tool does not elevate itself. Linux/macOS retain connectivity and Analyzer import support and report these queries as Windows-only.

A query is limited to 60 seconds and 4 MiB of output. Ctrl+C in the CLI or Esc in the dashboard requests cancellation. Missing Defender, access denial, timeout and malformed output are visible errors. Exit 0 means a query succeeded, not a healthy protection verdict. Preferences can contain private exclusions, identifiers and paths; common credential patterns are redacted, but arbitrary output is not guaranteed anonymous. OS policy may hide exclusions; absent values do not establish absence of configuration. Preference output does not identify winning Intune policies or cloud assignments.

The former `collect`, `intune` policy-investigation and `firewall` rule-viewer commands have been removed. Existing evidence files are preserved. Microsoft Intune and other Microsoft connectivity feeds/profiles remain available.

References checked 2026-11-05:
- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)
- [Get-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference)
