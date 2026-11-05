# Microsoft-only scope

The application diagnoses Microsoft Defender, device management, Windows Firewall and Microsoft cloud service connectivity. The feed host is not the service provider: the external feed host remains usable only for Microsoft service lists.

## Classification
- The embedded catalogue has **155 Microsoft URL feeds**: Defender, Microsoft 365 and Intune, retaining every existing region/cloud/service category in those families.
- The importer permits only msdefender, m365, msintune and azure provider paths on the approved feed host. Non-Microsoft provider paths are rejected in the CLI and dashboard.
- Azure currently has no concrete URL feed in the embedded snapshot. The Azure sample profile and custom registry support its documented service namespaces. IP-only Azure service-tag lists cannot supply a TLS hostname/SNI and are not converted into guessed URLs.
- Entra sample targets and Microsoft 365 identity categories remain available.
- Manual targets and custom JSON configuration use assets/microsoft-scope.json, with an explicit domain/pattern, purpose and source per rule. Exact boundary matching prevents suffix impersonation. This includes Microsoft 365, Intune, Azure and sovereign-cloud namespaces outside microsoft.com.
- Azure tenant resource namespaces classify the hosting service, not the author or safety of tenant-hosted content.
- Entries in an approved Microsoft service feed may include external dependencies. They remain associated with that source; the report's classification map supplies a known registry purpose or explicitly says the source did not supply a precise purpose. Domain ownership alone does not exclude them.
- The classification registry is an intentionally maintainable starting set, not the entire Microsoft namespace. Unrecognized manual hosts require a sourced registry change or a documented Microsoft feed; there is no bypass flag.
- Custom files keep the existing {"endpoints":["login.microsoftonline.com"]} format.

## Maintenance
To add a namespace, add a reviewed rule with a current first-party source, its Microsoft-service purpose, and whether subdomains are covered. Prefer exact dependency hostnames to broad third-party domains. Add boundary tests. Updating a rule is not a declaration that every customer needs that destination.

Sources:
- [Microsoft 365 endpoints and cloud variants](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges)
- [Intune endpoints and certificate dependencies](https://learn.microsoft.com/en-us/intune/fundamentals/endpoints)
- [Defender network requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-environment)
- [Azure domain reference](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains)

Source review: 2026-11-05. Service feeds and Microsoft documentation can change; the snapshot and registry require review over time.
