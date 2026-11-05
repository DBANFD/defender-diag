# Runtime MDE Client Analyzer packages

Public builds **never embed Microsoft packages**, including when the old DEFENDER_DIAG_ANALYZER_ZIP environment variable is present. The MIT license covers this project's source only. Microsoft's license, notices and interactive prompts remain in its package.

## Manage packages
Dashboard: **MDE Client Analyzer > Manage packages**. C changes standard/preview; D downloads/updates; I imports a ZIP; arrows choose a stored version; S selects; P selects and pins; U unpins; Enter shows metadata.

~~~powershell
defender-diag analyzer packages download standard
defender-diag analyzer packages download preview
defender-diag analyzer packages import C:\Private\MDEClientAnalyzer.zip --channel standard
defender-diag analyzer packages list
defender-diag analyzer packages select standard-<64-character-sha256> --pin
defender-diag analyzer packages unpin
defender-diag analyzer run
~~~

Standard: https://aka.ms/mdatpanalyzer
Preview: https://aka.ms/MDEClientAnalyzerPreview

These links were verified against [Microsoft's Windows Analyzer instructions](https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows) on 2026-11-05. Every redirect must be HTTPS on aka.ms or download.microsoft.com, with final content on download.microsoft.com. Unexpected redirects fail closed instead of expanding trust automatically.

Windows stores packages under %LOCALAPPDATA%\DefenderDiag\packages. Linux/macOS use XDG_DATA_HOME/defender-diag/packages or ~/.local/share/defender-diag/packages. Packages are retained side by side using channel and content SHA-256. Successful updates switch only an unpinned selection of the same channel. Failed acquisition/validation leaves the selection and older packages intact. Explicit selection can switch a pinned version. A channel may temporarily deliver identical bytes to another channel.

Metadata records channel, source, redirect chain, acquisition time, SHA-256, exposed script version (null if unavailable) and file signature results. Offline channel labels are operator-declared, not inferred from the filename. SHA-256 identifies content; it is not publisher authentication.

Validation uses bounded extraction, disallows traversal/alternate streams/Windows device filenames/symlinks, and limits archive entries/expanded size. On Windows the PS1/PSM1/EXE/DLL payloads require valid Microsoft Authenticode signatures. Other package data files are not individually Authenticode-authenticated. Offline packages must come from a trusted source; a collection of signed files is not a signed ZIP manifest. Import on other platforms records signatures as not_verified and cannot execute the Windows collector.

## Run and import findings
Run from an administrator terminal. The selected ZIP hash is rechecked and freshly extracted; signatures are checked again. The original main script runs with AllSigned and Microsoft's prompts. No license is autoaccepted. Collection notes record package hash and matching stored metadata. An explicitly supplied --package remains supported and is verified at execution.

~~~powershell
defender-diag analyzer run --package C:\Private\MDEClientAnalyzer.zip
defender-diag analyzer prepare --package C:\Private\MDEClientAnalyzer.zip
defender-diag analyzer import C:\Private\MDEClientAnalyzerResult.zip --output summary.json
~~~

XML/ZIP/folder result import remains read-only and cross-platform. Multiple structured reports in a ZIP are rejected as ambiguous. HTML-only import is unsupported. The dashboard shows errors, warnings, selected sensor/AV fields and guidance; F toggles relevant/all, S exports the pattern-redacted summary.

Raw Microsoft artifacts remain private and unchanged. Pattern redaction cannot guarantee arbitrary vendor content is anonymous. Evidence is a source-time snapshot, not current state or a direct-probe success verdict.

Known limits: signature verification can depend on Windows trust/revocation access; blocked validation is reported, not bypassed. Download requests have a 120-second timeout, at most six redirect hops and a 64-MiB package limit. Package verification/import is not an interruptible collector job. Full elevated vendor collection remains a separate live pilot; package download/verification does not establish sensor health.
