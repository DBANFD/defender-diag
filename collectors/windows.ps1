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
 'firewall' {
   $errors=[Collections.Generic.List[string]]::new()
   $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | ForEach-Object {
     $r=$_
     $filters=[ordered]@{}
     foreach($pair in @(@('ports','Get-NetFirewallPortFilter'),@('addresses','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('service','Get-NetFirewallServiceFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interfaceType','Get-NetFirewallInterfaceTypeFilter'),@('security','Get-NetFirewallSecurityFilter'))) {
       try { $filters[$pair[0]]=@(& $pair[1] -AssociatedNetFirewallRule $r | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties,PSComputerName) } catch { $filters[$pair[0]]=$null; $errors.Add("Filter $($pair[0]) unavailable") }
     }
     [ordered]@{name=$r.Name;displayName=$r.DisplayName;direction=[string]$r.Direction;action=[string]$r.Action;enabled=[string]$r.Enabled;profiles=[string]$r.Profile;source=$r.PolicyStoreSource;sourceType=[string]$r.PolicyStoreSourceType;filters=$filters}
   })
   $active=$null;$local=$null;$net=$null
   try{$active=@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{Name=[string]$_.Name;Enabled=[string]$_.Enabled;DefaultInboundAction=[string]$_.DefaultInboundAction;DefaultOutboundAction=[string]$_.DefaultOutboundAction;AllowInboundRules=[string]$_.AllowInboundRules;AllowLocalFirewallRules=[string]$_.AllowLocalFirewallRules;AllowLocalIPsecRules=[string]$_.AllowLocalIPsecRules;AllowUserApps=[string]$_.AllowUserApps;AllowUserPorts=[string]$_.AllowUserPorts;DisabledInterfaceAliases=$_.DisabledInterfaceAliases} })}catch{$errors.Add('Active profile settings unavailable')}
   try{$local=@(Get-NetFirewallRule -PolicyStore PersistentStore | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile)}catch{$errors.Add('Local PersistentStore unavailable')}
   try{$net=@(Get-NetConnectionProfile | ForEach-Object { [ordered]@{InterfaceAlias=$_.InterfaceAlias;InterfaceIndex=$_.InterfaceIndex;NetworkCategory=[string]$_.NetworkCategory;IPv4Connectivity=[string]$_.IPv4Connectivity;IPv6Connectivity=[string]$_.IPv6Connectivity} })}catch{$errors.Add('Network profiles unavailable')}
   Json ([ordered]@{schema_version=1;store='ActiveStore';rules=$rules;profiles=$active;networkProfiles=$net;localConfiguredRules=$local;errors=@($errors);note='Active policy inventory is not a packet verdict. Null source is unknown. PersistentStore is configuration, not resultant policy.'})
 }
 default {
   $channels=@{'events-defender'='Microsoft-Windows-Windows Defender/Operational';'events-sense'='Microsoft-Windows-SENSE/Operational';'events-mdm'='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin';'events-firewall'='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';'events-aad'='Microsoft-Windows-AAD/Operational'}
   if(!$channels.ContainsKey($kind)){throw 'Unknown collector'}
   $rows=@()
   try { $rows=@(Get-WinEvent -FilterHashtable @{LogName=$channels[$kind];StartTime=$from;EndTime=$until} -MaxEvents ($max+1) | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,RecordId,Message) }
   catch { if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw} }
   Json ([ordered]@{channel=$channels[$kind];from=$from.ToString('o');until=$until.ToString('o');truncated=($rows.Count -gt $max);events=@($rows|Select-Object -First $max)})
 }
}
