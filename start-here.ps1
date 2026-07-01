#Requires -RunAsAdministrator
<#
    Harden-Windows.ps1
    Windows 11 Home 25H2 hardening script.
    Built from a live assessment of this machine (DOM\illim).

    Your chosen policy:
      * Defender          : LEFT ON (not disabled -- it is your only AV)
      * Windows Update    : FULLY STOPPED (your request; see Section 4 - reversible)
      * Firewall          : block inbound, allow outbound
      * File sharing/print: FULL LOCKDOWN (SMB server, NetBIOS, UPnP, Spooler off)

    HOW TO RUN:
      1. Press Start, type "PowerShell", right-click -> "Run as administrator".
      2. Run:  Set-ExecutionPolicy -Scope Process Bypass -Force
      3. Run:  C:\Users\illim\Hardening\Harden-Windows.ps1
      4. Reboot when it finishes.

    TO UNDO:  Section 0 creates a System Restore point named 'Pre-Hardening' and backs up
              your firewall to firewall-backup.wfw. To revert, either:
                - System Restore to 'Pre-Hardening'  (rstrui.exe), or
                - restore firewall only:  netsh advfirewall import "C:\Users\illim\Hardening\firewall-backup.wfw"

    Each section is independent. To skip one, comment out its function call at the bottom.
#>

$ErrorActionPreference = 'Continue'
$base = 'C:\Users\illim\Hardening'
$log  = Join-Path $base ("harden-log-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $log -Append | Out-Null

# ---------- helpers ----------
function Step($desc, [scriptblock]$action){
    try   { & $action; Write-Host "[ OK ] $desc" -ForegroundColor Green }
    catch { Write-Host "[WARN] $desc  ->  $($_.Exception.Message)" -ForegroundColor Yellow }
}
function SetReg($path,$name,$value,$type='DWord'){
    if(-not (Test-Path $path)){ New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
}
function DisableSvc($name){
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if($s){
        if($s.Status -ne 'Stopped'){ Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
        Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
        try { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name Start -Value 4 -ErrorAction Stop } catch {}
    }
}

Write-Host "`n===== WINDOWS 11 HARDENING - starting $(Get-Date) =====`n" -ForegroundColor Cyan

# ================================================================
# SECTION 0 - Safety net: restore point + firewall backup
# ================================================================
function Invoke-Section0 {
    Write-Host "`n--- Section 0: safety backups ---" -ForegroundColor Cyan
    Step "Enable System Protection on C:"     { Enable-ComputerRestore -Drive 'C:\' }
    Step "Allow back-to-back restore points"  { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' 'SystemRestorePointCreationFrequency' 0 }
    Step "Create restore point 'Pre-Hardening'" { Checkpoint-Computer -Description 'Pre-Hardening' -RestorePointType 'MODIFY_SETTINGS' }
    Step "Back up current firewall to firewall-backup.wfw" { netsh advfirewall export "$base\firewall-backup.wfw" | Out-Null }
}

# ================================================================
# SECTION 1 - Firewall: block all inbound, allow outbound
# ================================================================
function Invoke-Section1 {
    Write-Host "`n--- Section 1: firewall ---" -ForegroundColor Cyan
    Step "All profiles ON, inbound=Block, outbound=Allow, log dropped packets" {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -LogBlocked True -LogMaxSizeKilobytes 8192 `
            -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
    }
    # Explicit BLOCK rules (block beats allow) so these stay shut even if an app re-adds an allow rule.
    $tcp = 135,137,138,139,445,3389,5040,5357,5358,5985,5986,7680,1900,3702
    $udp = 137,138,1900,3702,5040,5353,5355
    Step "Add HARDEN block rule (inbound TCP: RPC/NetBIOS/SMB/RDP/WinRM/UPnP/DO)" {
        New-NetFirewallRule -DisplayName 'HARDEN-Block-Inbound-TCP' -Direction Inbound -Action Block -Protocol TCP -LocalPort $tcp -Profile Any | Out-Null
    }
    Step "Add HARDEN block rule (inbound UDP: NetBIOS/SSDP/WS-Disc/mDNS/LLMNR)" {
        New-NetFirewallRule -DisplayName 'HARDEN-Block-Inbound-UDP' -Direction Inbound -Action Block -Protocol UDP -LocalPort $udp -Profile Any | Out-Null
    }
    # Turn OFF built-in inbound allow groups for remote/sharing (best-effort, language-independent group IDs)
    foreach($g in @('@FirewallAPI.dll,-28502','@FirewallAPI.dll,-32752','@FirewallAPI.dll,-28752','@FirewallAPI.dll,-36001')){
        Step "Disable inbound allow group $g" { Get-NetFirewallRule -Group $g -ErrorAction Stop | Where-Object Direction -eq 'Inbound' | Disable-NetFirewallRule }
    }
}

# ================================================================
# SECTION 2 - Kill remote-access surface (no remote possibilities)
# ================================================================
function Invoke-Section2 {
    Write-Host "`n--- Section 2: remote access off ---" -ForegroundColor Cyan
    Step "Deny Remote Desktop"        { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 }
    Step "Disable Remote Assistance"  { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0; SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowFullControl' 0 }
    Step "No remote UAC via local accounts" { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0 }
    foreach($svc in 'TermService','UmRdpService','SessionEnv','WinRM','RemoteRegistry','RemoteAccess','SharedAccess','sshd','ssh-agent'){
        Step "Disable service: $svc" { DisableSvc $svc }
    }
}

# ================================================================
# SECTION 3 - File sharing / discovery / printing lockdown
# ================================================================
function Invoke-Section3 {
    Write-Host "`n--- Section 3: sharing/printing lockdown ---" -ForegroundColor Cyan
    foreach($svc in 'LanmanServer','Spooler','SSDPSRV','upnphost','fdPHost','FDResPub','lltdsvc','CDPSvc','DoSvc'){
        Step "Disable service: $svc" { DisableSvc $svc }
    }
    Step "Keep SMBv1 server off + enforce SMB signing" {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false
    }
    Step "Disable SMBv1 client feature" { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
    Step "Turn off NetBIOS-over-TCP on all adapters" {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { SetReg $_.PSPath 'NetbiosOptions' 2 }
    }
}

# ================================================================
# SECTION 4 - Stop Windows Update (YOUR REQUEST - see warning in README)
# ================================================================
function Invoke-Section4 {
    Write-Host "`n--- Section 4: STOP Windows Update (leaves future flaws unpatched) ---" -ForegroundColor Cyan
    Step "Policy: NoAutoUpdate + don't contact WU"  {
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AUOptions' 1
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' 1
    }
    foreach($svc in 'wuauserv','UsoSvc','WaaSMedicSvc'){ Step "Disable service: $svc" { DisableSvc $svc } }
    Write-Host "      NOTE: UsoSvc/WaaSMedicSvc are protected; the NoAutoUpdate policy is the real guard." -ForegroundColor DarkYellow
}

# ================================================================
# SECTION 5 - UAC to strictest
# ================================================================
function Invoke-Section5 {
    Write-Host "`n--- Section 5: UAC ---" -ForegroundColor Cyan
    $sys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Step "UAC: always prompt on secure desktop, admin-approval for built-in admin" {
        SetReg $sys 'EnableLUA' 1
        SetReg $sys 'ConsentPromptBehaviorAdmin' 2
        SetReg $sys 'PromptOnSecureDesktop' 1
        SetReg $sys 'FilterAdministratorToken' 1
        SetReg $sys 'EnableInstallerDetection' 1
    }
}

# ================================================================
# SECTION 6 - Credential / LSA hardening
# ================================================================
function Invoke-Section6 {
    Write-Host "`n--- Section 6: credentials / LSA ---" -ForegroundColor Cyan
    $lsa='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Step "LSA protected process (RunAsPPL)"        { SetReg $lsa 'RunAsPPL' 2 }
    Step "Block anonymous/null-session enumeration"{ SetReg $lsa 'RestrictAnonymous' 1; SetReg $lsa 'RestrictAnonymousSAM' 1; SetReg $lsa 'EveryoneIncludesAnonymous' 0; SetReg $lsa 'LimitBlankPasswordUse' 1 }
    Step "No LM hash, NTLMv2 only"                 { SetReg $lsa 'NoLMHash' 1; SetReg $lsa 'LmCompatibilityLevel' 5 }
    Step "Require NTLMv2 128-bit session security" { SetReg "$lsa\MSV1_0" 'NTLMMinClientSec' 537395200; SetReg "$lsa\MSV1_0" 'NTLMMinServerSec' 537395200 }
    Step "WDigest: no plaintext creds in memory"   { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }
}

# ================================================================
# SECTION 7 - Network protocol hardening
# ================================================================
function Invoke-Section7 {
    Write-Host "`n--- Section 7: network protocols ---" -ForegroundColor Cyan
    Step "Disable LLMNR" { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
    Step "Disable mDNS"  { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0 }
}

# ================================================================
# SECTION 8 - Malware execution hardening
# ================================================================
function Invoke-Section8 {
    Write-Host "`n--- Section 8: execution hardening ---" -ForegroundColor Cyan
    Step "Disable AutoRun/AutoPlay everywhere" {
        SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
        SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
    }
    Step "Enable SmartScreen (file/app reputation)" {
        SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Warn' 'String'
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' 'String'
    }
    Step "Enable PowerShell script-block + module logging (forensics)" {
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
        SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String'
    }
}

# ================================================================
# SECTION 9 - Defender-based hardening (ONLY because you kept Defender ON)
#             Comment out Invoke-Section9 below if you don't want to use Defender features.
# ================================================================
function Invoke-Section9 {
    Write-Host "`n--- Section 9: Defender ASR + network/PUA protection ---" -ForegroundColor Cyan
    $asr = @(
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # block credential theft from LSASS
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', # block exe content from email/webmail
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # block Office apps creating child processes
        '3b576869-a4ec-4529-8536-b80a7769e899', # block Office creating executable content
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', # block Office code injection
        'd3e037e1-3eb8-44c8-a917-57927947596d', # block JS/VBS launching downloaded exe
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc', # block obfuscated scripts
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', # block Win32 API calls from Office macros
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # block untrusted/unsigned processes from USB
        'c1db55ab-c21a-4637-bb3f-a12568109d35', # advanced ransomware protection
        'e6db77e5-3df2-4cf1-b95a-636979351e5b', # block WMI event-subscription persistence
        '26190899-1602-49e8-8b27-eb1d0a1ce869', # block comm-app child processes
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'  # block Adobe Reader child processes
    )
    foreach($g in $asr){ Step "ASR rule $g -> Block" { Add-MpPreference -AttackSurfaceReductionRules_Ids $g -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop } }
    Step "Network protection = Block"            { Set-MpPreference -EnableNetworkProtection Enabled }
    Step "PUA (potentially-unwanted apps) = Block"{ Set-MpPreference -PUAProtection Enabled }
    Step "Cloud protection = Advanced"           { Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -SubmitSamplesConsent SendSafeSamples }
    # Controlled Folder Access blocks ransomware but also blocks some legit apps from writing to Documents/Pictures.
    # Starting in AUDIT so it won't break anything; flip to Enabled after reviewing the logs if you want.
    Step "Controlled Folder Access = Audit (anti-ransomware, non-breaking)" { Set-MpPreference -EnableControlledFolderAccess AuditMode }
}

# ================================================================
# SECTION 10 - Telemetry reduction (privacy / exposure surface)
# ================================================================
function Invoke-Section10 {
    Write-Host "`n--- Section 10: telemetry ---" -ForegroundColor Cyan
    Step "Minimize telemetry" { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0 }
    foreach($svc in 'DiagTrack','dmwappushservice'){ Step "Disable service: $svc" { DisableSvc $svc } }
}

# ================================================================
# SECTION 11 - Core Isolation / Memory Integrity (HVCI) - needs reboot
#   Blocks kernel-level malware/unsigned drivers. If a device misbehaves after reboot,
#   turn it off in Windows Security > Device security > Core isolation.
# ================================================================
function Invoke-Section11 {
    Write-Host "`n--- Section 11: Memory Integrity (activates after reboot) ---" -ForegroundColor Cyan
    Step "Enable HVCI / Memory Integrity" { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1 }
}

# ---------- RUN (comment out any line to skip that section) ----------
Invoke-Section0
Invoke-Section1
Invoke-Section2
Invoke-Section3
Invoke-Section4
Invoke-Section5
Invoke-Section6
Invoke-Section7
Invoke-Section8
Invoke-Section9
Invoke-Section10
Invoke-Section11

Write-Host "`n===== DONE. Review the log, then REBOOT. =====" -ForegroundColor Cyan
Write-Host "Log saved to: $log" -ForegroundColor Cyan
Write-Host "To undo: System Restore to 'Pre-Hardening' (rstrui.exe)." -ForegroundColor Cyan
Stop-Transcript | Out-Null
