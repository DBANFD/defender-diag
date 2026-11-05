# Read-only collectors. All inputs are environment data, never interpolated program text.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$kind=$env:DD_KIND
$from=[DateTimeOffset]::Parse($env:DD_FROM).UtcDateTime
$until=[DateTimeOffset]::Parse($env:DD_UNTIL).UtcDateTime
$max=[int]$env:DD_EVENTS
function Json($value) { ConvertTo-Json -InputObject $value -Depth 16 -Compress }
switch ($kind) {
 'health' {
   $errors=[Collections.Generic.List[string]]::new();$sense=$null;$av=$null
   try{$sense=Get-Service Sense | Select-Object Name,Status,StartType}catch{$errors.Add('SENSE service unavailable or access denied')}
   try{$av=Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AMEngineVersion,AMProductVersion,IsTamperProtected}catch{$errors.Add('Defender status unavailable or access denied')}
   Json ([ordered]@{sense=$sense;defender=$av;errors=@($errors)})
 }
 'preferences' { Json (Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,MAPSReporting,SubmitSamplesConsent,PUAProtection,EnableNetworkProtection,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,ExclusionPath,ExclusionProcess,ExclusionExtension,ProxyServer,ProxyPacUrl) }
 'enrollment' { & "$env:SystemRoot\System32\dsregcmd.exe" /status; if($LASTEXITCODE){throw "dsregcmd exit $LASTEXITCODE"} }
 'gpresult' { & "$env:SystemRoot\System32\gpresult.exe" /Scope Computer /Z; if($LASTEXITCODE){throw "gpresult exit $LASTEXITCODE"} }
 'network' { Json ([ordered]@{ip=Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer;dns=Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses; winhttp=(& "$env:SystemRoot\System32\netsh.exe" winhttp show proxy); userProxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL}) }
 'mdm-report' { & "$env:SystemRoot\System32\mdmdiagnosticstool.exe" -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' -zip $env:DD_ARTIFACT; if($LASTEXITCODE){throw "MDM diagnostics exit $LASTEXITCODE"} }
 'mdm-effective' { Json (@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction Stop | ForEach-Object { [ordered]@{area=$_.PSChildName;values=Get-ItemProperty -LiteralPath $_.PSPath | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider} })) }
 default {
   $channels=@{'events-defender'='Microsoft-Windows-Windows Defender/Operational';'events-sense'='Microsoft-Windows-SENSE/Operational';'events-mdm'='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin';'events-firewall'='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';'events-aad'='Microsoft-Windows-AAD/Operational'}
   if(!$channels.ContainsKey($kind)){throw 'Unknown collector'}
   $rows=@()
   try { $rows=@(Get-WinEvent -FilterHashtable @{LogName=$channels[$kind];StartTime=$from;EndTime=$until} -MaxEvents ($max+1) | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,RecordId,Message) }
   catch { if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw} }
   Json ([ordered]@{channel=$channels[$kind];from=$from.ToString('o');until=$until.ToString('o');truncated=($rows.Count -gt $max);events=@($rows|Select-Object -First $max)})
 }
}
