# MDE Client Analyzer integration

Source builds support importing existing reports and running a separately supplied Windows package. Select **MDE Client Analyzer** on the home menu. Run collection from an administrator terminal; Microsoft license and publisher prompts remain interactive. The dashboard returns after collection and shows structured findings, severity counts, selected sensor/AV configuration and Microsoft guidance. Use arrows to select, **f** for relevant/all findings, and **s** to export a redacted summary.

For collection, the executable extracts the selected package into a new results/analyzer/run-* directory. It checks the main script's Microsoft Authenticode signature and invokes Windows PowerShell with AllSigned. It does not modify vendor scripts, accept the EULA automatically, or enable optional advanced tracing/dumps. Raw vendor results remain on disk.

Microsoft's workflow and output layout: https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows

## Import existing results

Import works without elevation, including on Linux/macOS. Choose Import in the menu or use:

~~~powershell
.\defender-diag.exe analyzer import C:\Evidence\MDEClientAnalyzerResult.zip --output summary.json
.\defender-diag.exe analyzer import C:\Evidence\MDEClientAnalyzerResult
.\defender-diag.exe analyzer run
.\defender-diag.exe analyzer prepare --work-dir .\package-check
~~~

Import accepts XML, a result folder, or a ZIP containing exactly one MDEClientAnalyzer.xml. It does not execute imported files. HTML-only reports are not parsed. Multiple XML reports are rejected as ambiguous. XML is limited to 16 MiB and result ZIPs to 512 MiB. Package extraction rejects traversal, symlinks and oversized contents.

Findings are historical evidence from the selected report, separate from direct connectivity percentages. Errors and warnings are always relevant; the default view also includes connectivity, proxy, TLS, certificate, DNS, onboarding, sensor and AV checks. An empty event list is marked incomplete, never an all-clear. Import success means parsing succeeded, not that the endpoint is healthy.

Summary export redacts common credential patterns and URL query values, withholds proxy snapshot values, and excludes arbitrary configuration payloads. Raw Microsoft reports are unchanged and may contain sensitive endpoint information. Redaction is pattern-based, not a guarantee that arbitrary free text is secret-free; inspect before sharing.

## Package and build

Obtain the package through Microsoft's documented Client Analyzer workflow and follow its license terms. The package is not included in this repository or covered by the project license.

A normal Cargo build supports import and `analyzer run --package PATH` on Windows. For an optional local bundled build, pass a package explicitly to `./Build-Release.ps1 -AnalyzerZip PATH`. There is no automatic package download or update.

The delivered app is one EXE, but running Analyzer necessarily extracts its files and writes reports. Windows PowerShell and the Analyzer's OS prerequisites are still required.

## Platform scope

Windows collection requires elevation and the Microsoft package's prerequisites. Import does not require elevation. Native Linux/macOS Analyzer collection and advanced capture options are not included. Cross-platform import qualification and a full elevated Windows collection pilot remain ongoing.
