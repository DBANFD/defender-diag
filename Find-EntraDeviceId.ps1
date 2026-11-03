#requires -Version 5.1
<#
.SYNOPSIS
Matches exact display names in a local CSV. Does not connect to a tenant.
.DESCRIPTION
Required CSV headers: displayName,id,deviceId. Returns every matching row.
Duplicate names are Ambiguous, never automatically selected. Output may contain
sensitive identifiers from YOUR input. Keep real exports and results private.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string[]]$Name
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rows = @(Import-Csv -LiteralPath $CsvPath)
if ($rows.Count -eq 0) { throw 'Input CSV must contain headers and at least one data row.' }
foreach ($column in @('displayName','id','deviceId')) {
    if ($column -notin $rows[0].PSObject.Properties.Name) {
        throw "Missing required CSV header: $column"
    }
}
$index = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($row in $rows) {
    $key = ([string]$row.displayName).Trim()
    if (-not $key) { continue }
    if (-not $index.ContainsKey($key)) { $index[$key] = [System.Collections.Generic.List[object]]::new() }
    $index[$key].Add($row)
}
foreach ($requested in $Name) {
    $key = ([string]$requested).Trim()
    if (-not $key -or -not $index.ContainsKey($key)) {
        [pscustomobject]@{RequestedName=$key;Status='NotFound';MatchCount=0;DisplayName=$null;ObjectId=$null;DeviceId=$null;IdentifiersValid=$null}
        continue
    }
    $matchesForName = $index[$key]
    foreach ($row in $matchesForName) {
        $objectId = ([string]$row.id).Trim()
        $deviceId = ([string]$row.deviceId).Trim()
        $parsedObject = [guid]::Empty
        $parsedDevice = [guid]::Empty
        $validObject = [guid]::TryParse($objectId,[ref]$parsedObject) -and $parsedObject -ne [guid]::Empty
        $validDevice = [guid]::TryParse($deviceId,[ref]$parsedDevice) -and $parsedDevice -ne [guid]::Empty
        $valid = $validObject -and $validDevice
        $status = if ($matchesForName.Count -gt 1) { 'Ambiguous' } elseif (-not $valid) { 'InvalidIdentifiers' } else { 'UniqueMatch' }
        [pscustomobject]@{RequestedName=$key;Status=$status;MatchCount=$matchesForName.Count;DisplayName=$row.displayName;ObjectId=$objectId;DeviceId=$deviceId;IdentifiersValid=$valid}
    }
}
