#requires -Version 5.1
<#
.SYNOPSIS
Collects selected local Defender properties without changing configuration.
.DESCRIPTION
Run in elevated Windows PowerShell with the Defender module available.
No tenant calls, registry writes, exclusions, hostnames, or user names collected.
Actual output is operational information; review it before sharing externally.
Failure is reported as Unavailable, never interpreted as healthy.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$status = $null
$preferences = $null
$statusRead = 'Available'
$preferenceRead = 'Available'
try {
    $status = Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,
        AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,
        AMProductVersion,AMEngineVersion,AntivirusSignatureVersion,AntivirusSignatureLastUpdated
} catch { $statusRead = 'Unavailable' }
try {
    $preferences = Get-MpPreference | Select-Object DisableRealtimeMonitoring,
        DisableBehaviorMonitoring,MAPSReporting,SubmitSamplesConsent,EnableNetworkProtection
} catch { $preferenceRead = 'Unavailable' }
[pscustomobject]@{
    CollectedAtUtc = [DateTime]::UtcNow.ToString('o')
    StatusRead = $statusRead
    PreferenceRead = $preferenceRead
    Status = $status
    Preferences = $preferences
}
