# Intune policy investigation

Local Windows evidence and optional Graph enrichment are separate. Neither mode changes policies, assignments, enrollment or synchronization state.

## Local mode

Use the dashboard's Intune page > Local-only, or `defender-diag intune local --hours 48 --run`. Without --run, the command previews scope. It collects enrollment state, MDM/AAD events, current PolicyManager device-area values and computer Group Policy results. Local evidence is not a complete cloud assignment list. See [collection coverage](COLLECTIONS.md).

## Optional cloud mode

Use an operator-owned Entra public-client app registration with device-code/public-client flow enabled. Supply its tenant GUID and application/client GUID. No application identity, secret or token cache is embedded. Login starts only when explicitly selected. Conditional Access can prohibit device login; the app does not bypass that decision.

Delegated permissions:
- DeviceManagementManagedDevices.Read.All: Intune device resolution and snapshot.
- DeviceManagementConfiguration.Read.All: policy inventory, assignments and available reports.
- Optional --directory adds Device.Read.All for Entra directory object lookup.

Administrator consent and an Intune license are required. The signed-in user also needs suitable Intune RBAC read permissions and scope-tag access, for example an appropriately scoped Read Only Operator. Consent does not replace RBAC. Missing access is recorded as a coverage error. No ReadWrite permissions are requested. Tokens stay in process memory and are not exported. Graph authentication currently supports the global Microsoft cloud; connectivity feeds retain sovereign-cloud categories.

~~~powershell
defender-diag intune coverage --beta
defender-diag intune cloud --tenant <tenant-guid> --client-id <public-client-guid> --entra-device-id <verified-deviceId>
defender-diag intune cloud --tenant <tenant-guid> --client-id <public-client-guid> --entra-device-id <verified-deviceId> --managed-device-id <intune-id> --beta --directory --reports
~~~

The dashboard exposes the same fields and toggles. START initiates authentication. Output goes into a new private directory with a manifest, summary, structural shareable summary and support-private.zip.

## Identity and interpretation

Entra deviceId, Entra object id and Intune managedDevice id are different. Supply a verified Entra deviceId, for example DeviceId from the appropriate dsregcmd device section. Resolution requires an exact azureADDeviceId match. Multiple matches require --managed-device-id; display names are never used to guess identity. Optional directory lookup verifies the returned deviceId before recording object id; otherwise entra_object_id remains null.

Assignment records retain target types, device/user group IDs, exclusions and filter references when returned. With beta enabled, available assignment-filter definitions are included. The tool does not simulate dynamic-group membership, filter evaluation, precedence or the full targeting engine. Every policy row states applicability: not determined. Tenant inventory is not a list of policies applying to the selected device.

## Coverage

| Family | Inventory / assignments | Reported deployment / settings |
|---|---|---|
| Configuration profiles | v1.0 deviceConfigurations and assignments | Deprecated deviceStatuses is not queried; per-device/per-setting status not collected |
| Compliance | v1.0 deviceCompliancePolicies and assignments | Optional v1.0 compliance report actions; exact managed-device rows retained |
| Settings Catalog | Optional beta configurationPolicies and assignments | Not collected in this version |
| Modern endpoint security / baselines | Optional beta configurationPolicies with templateReference | Not collected in this version |
| Legacy endpoint security / baselines | Optional beta intents and assignments | Not collected in this version |
| Scripts, remediations, apps, app protection and other families | Not covered | Not covered |

Beta dependencies are explicit, opt-in and labelled per row. Coverage and errors remain visible if an API is unavailable.

--reports invokes getDevicePoliciesComplianceReport and getDevicePolicySettingsComplianceReport. Published report documentation lists no supported filters for these exports: bounded tenant pages are read, but only exact DeviceId matches are retained. Other device rows can be transiently received in memory and are not written. Returned state/conflict/error codes, IDs, settings and available timestamps remain under reported_status, separate from assignments. Reports can lag changes. No returned rows does not prove no policies apply.

Limits: 100 pages/10,000 rows per list; 8 MiB per response; 64 MiB per paginated list; up to 500 policy rows and a 64-MiB inventory threshold (the last row can exceed that threshold). Report actions read at most 100 pages of 100 rows. Permission errors, unexpected schemas and limits produce explicit partial coverage. HTTP 429/503 uses bounded Retry-After/backoff with at most five attempts. Next links must remain on the approved HTTPS Graph origin; redirects never receive the bearer token.

Local values are never inferred: locally_observed_effective_values stays null in cloud output. Keep the separate local bundle for comparison. There is no automatic winning-policy attribution across arbitrary registry keys.

## Validation boundary

Offline fixtures cover pagination, hostile next links, access-denied handling, retry bounds, ambiguous IDs, report conflicts and coverage. Authenticated tenant validation has not been performed. A live pilot needs the operator's registration, consent, role access and verified device identifiers. Local collection does not depend on it.

## Sources reviewed 2026-11-05

- [Device login](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Managed devices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0)
- [Configuration assignments](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfigurationassignment-list?view=graph-rest-1.0)
- [Compliance assignments](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicyassignment-list?view=graph-rest-1.0)
- [Configuration policy beta API](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-list?view=graph-rest-beta)
- [Legacy intents](https://learn.microsoft.com/en-us/graph/api/intune-deviceintent-devicemanagementintent-list?view=graph-rest-beta)
- [Deprecated status resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfigurationdevicestatus?view=graph-rest-1.0)
- [Reports and available properties](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports)
- [Policy report](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementreports-getdevicepoliciescompliancereport?view=graph-rest-1.0)
- [Settings report](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementreports-getdevicepolicysettingscompliancereport?view=graph-rest-1.0)
