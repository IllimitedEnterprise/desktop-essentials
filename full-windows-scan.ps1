#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Windows Security Vulnerability Scanner
.DESCRIPTION
    Scans your Windows system for security vulnerabilities, misconfigurations,
    suspicious activity, and remote access risks. Outputs a full HTML report.
.NOTES
    Run as Administrator for full results.
    Usage: powershell -ExecutionPolicy Bypass -File WindowsSecurityScan.ps1
#>

param(
    [string]$ReportPath = "$env:USERPROFILE\Desktop\SecurityScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
)

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

# ---- Colour helpers ----------------------------------------------------------
function Write-Header { param($t) Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-OK     { param($t) Write-Host "  [OK]   $t" -ForegroundColor Green }
function Write-Warn   { param($t) Write-Host "  [WARN] $t" -ForegroundColor Yellow }
function Write-Crit   { param($t) Write-Host "  [CRIT] $t" -ForegroundColor Red }
function Write-Info   { param($t) Write-Host "  [INFO] $t" -ForegroundColor White }

# ---- Result collector --------------------------------------------------------
$Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$Passed   = 0
$Warnings = 0
$Critical = 0

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet("OK","WARN","CRIT","INFO")]
        [string]$Status,
        [string]$Detail,
        [string]$Recommendation = ""
    )
    $Results.Add([PSCustomObject]@{
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
    })
    switch ($Status) {
        "OK"   { $script:Passed++;   Write-OK   "$Check - $Detail" }
        "WARN" { $script:Warnings++; Write-Warn "$Check - $Detail" }
        "CRIT" { $script:Critical++; Write-Crit "$Check - $Detail" }
        "INFO" { Write-Info "$Check - $Detail" }
    }
}

# ==============================================================================
Write-Host "`n  Windows Security Scanner  " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "  $(Get-Date -Format 'dddd, dd MMMM yyyy  HH:mm:ss')  `n" -ForegroundColor Gray

# ---- 1. SYSTEM INFO ----------------------------------------------------------
Write-Header "SYSTEM INFORMATION"
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

Add-Result "System" "OS Version"      "INFO" "$($os.Caption) Build $($os.BuildNumber)"
Add-Result "System" "Architecture"    "INFO" $os.OSArchitecture
Add-Result "System" "Hostname"        "INFO" $env:COMPUTERNAME
$domainStatus = if ($cs.PartOfDomain) { 'Domain' } else { 'Workgroup' }
Add-Result "System" "Domain/Workgroup" "INFO" "$($cs.Domain)  ($domainStatus)"
Add-Result "System" "Uptime"          "INFO" "Last boot: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'))"
Add-Result "System" "Current User"    "INFO" "$env:USERDOMAIN\$env:USERNAME"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Add-Result "System" "Admin Rights" "WARN" "Script NOT running as Administrator - some checks may be incomplete" `
        "Re-run: Right-click PowerShell > Run as Administrator"
}

# ---- 2. WINDOWS UPDATE -------------------------------------------------------
Write-Header "WINDOWS UPDATE"
try {
    $wu = New-Object -ComObject Microsoft.Update.Session
    $searcher = $wu.CreateUpdateSearcher()
    $pending  = $searcher.Search("IsInstalled=0 and Type='Software'").Updates
    $count    = $pending.Count
    if ($count -gt 0) {
        Add-Result "Updates" "Pending Updates" "WARN" "$count update(s) waiting to be installed" `
            "Open Settings and Windows Update to install all available updates"
    } else {
        Add-Result "Updates" "Pending Updates" "OK" "System is up to date"
    }
} catch {
    Add-Result "Updates" "Pending Updates" "INFO" "Could not query Windows Update (COM unavailable)"
}

# Last update date from hotfix list
$lastHotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastHotfix) {
    $daysSince = ((Get-Date) - $lastHotfix.InstalledOn).Days
    if ($daysSince -gt 60) {
        Add-Result "Updates" "Last Patch Applied" "WARN" "Last hotfix was $daysSince days ago ($($lastHotfix.HotFixID))" `
            "Ensure Windows Update is enabled and run regularly"
    } else {
        Add-Result "Updates" "Last Patch Applied" "OK" "Last hotfix $daysSince days ago ($($lastHotfix.HotFixID))"
    }
}

# ---- 3. ANTIVIRUS AND DEFENDER -----------------------------------------------
Write-Header "ANTIVIRUS AND DEFENDER"
$avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct
if ($avProducts) {
    foreach ($av in $avProducts) {
        $hex       = [Convert]::ToString($av.productState, 16).PadLeft(6,'0')
        $rtEnabled = $hex.Substring(1,1) -eq '1'
        $upToDate  = $hex.Substring(4,2) -eq '00'
        $status    = if ($rtEnabled -and $upToDate) { "OK" } elseif ($rtEnabled) { "WARN" } else { "CRIT" }
        $detail    = "$($av.displayName) | RT: $(if($rtEnabled){'ON'}else{'OFF'}) | Sigs: $(if($upToDate){'Current'}else{'OUT OF DATE'})"
        Add-Result "Antivirus" "AV Product" $status $detail `
            "Ensure real-time protection is ON and signatures are up to date"
    }
} else {
    Add-Result "Antivirus" "AV Product" "CRIT" "No antivirus product detected in SecurityCenter2" `
        "Install/enable Windows Defender or a third-party AV solution"
}

# Defender specific checks
try {
    $defPref = Get-MpPreference
    $defStat = Get-MpComputerStatus
    $rtStatus = if ($defStat.RealTimeProtectionEnabled) { "OK" } else { "CRIT" }
    Add-Result "Antivirus" "Defender Real-Time Protection" $rtStatus `
        $(if($defStat.RealTimeProtectionEnabled){"Enabled"}else{"DISABLED"}) `
        "Enable via: Set-MpPreference -DisableRealtimeMonitoring `$false"

    if ($defStat.AntivirusSignatureAge -gt 3) {
        Add-Result "Antivirus" "Defender Signature Age" "WARN" "$($defStat.AntivirusSignatureAge) days old" `
            "Run: Update-MpSignature"
    } else {
        Add-Result "Antivirus" "Defender Signature Age" "OK" "$($defStat.AntivirusSignatureAge) day(s) old"
    }

    $tamper = if ($defPref.TamperProtection -ne 0) { "OK" } else { "WARN" }
    $tamperDetail = if ($defPref.TamperProtection -ne 0) { "Enabled" } else { "Disabled - AV can be silently disabled" }
    Add-Result "Antivirus" "Tamper Protection" $tamper $tamperDetail `
        "Enable in Windows Security app > Virus and threat protection settings"

    if ($defPref.DisableIOAVProtection) {
        Add-Result "Antivirus" "Download Scanning" "CRIT" "Download/attachment scanning is DISABLED" `
            "Run: Set-MpPreference -DisableIOAVProtection `$false"
    } else {
        Add-Result "Antivirus" "Download Scanning" "OK" "Enabled"
    }
} catch {}

# ---- 4. FIREWALL -------------------------------------------------------------
Write-Header "FIREWALL"
$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    $st = if ($p.Enabled) { "OK" } else { "CRIT" }
    Add-Result "Firewall" "$($p.Name) Profile" $st `
        $(if($p.Enabled){"Enabled"}else{"DISABLED"}) `
        "Enable via: Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"

    if ($p.Enabled) {
        $inSt  = if ($p.DefaultInboundAction -eq "Block") { "OK" } else { "WARN" }
        Add-Result "Firewall" "$($p.Name) Default Inbound" $inSt `
            $p.DefaultInboundAction `
            "Set to Block: Set-NetFirewallProfile -Profile $($p.Name) -DefaultInboundAction Block"
    }
}

# Suspicious firewall rules (inbound allows on risky ports)
$riskyPorts = @(23,135,139,445,3389,5900,4444,5985,5986,1433,3306,6379,27017)
$suspRules  = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.Profile -ne 'Domain' } |
    ForEach-Object {
        $portFilter = $_ | Get-NetFirewallPortFilter
        if ($portFilter.LocalPort -in $riskyPorts -or $portFilter.LocalPort -eq "Any") { $_ }
    }
if ($suspRules) {
    foreach ($r in ($suspRules | Select-Object -First 10)) {
        Add-Result "Firewall" "Suspicious Inbound Rule" "WARN" `
            "Rule '$($r.DisplayName)' allows inbound - verify this is intentional" `
            "Review or disable: Disable-NetFirewallRule -DisplayName '$($r.DisplayName)'"
    }
} else {
    Add-Result "Firewall" "Inbound Rules Review" "OK" "No obviously risky inbound allow rules found"
}

# ---- 5. OPEN NETWORK PORTS ---------------------------------------------------
Write-Header "OPEN NETWORK PORTS"
$listeningPorts = Get-NetTCPConnection -State Listen | Sort-Object LocalPort
$udpPorts       = Get-NetUDPEndpoint | Sort-Object LocalPort

$dangerPorts = @{
    21   = "FTP (unencrypted)"
    23   = "Telnet (unencrypted)"
    135  = "RPC Endpoint Mapper"
    139  = "NetBIOS Session"
    445  = "SMB - potential EternalBlue risk"
    1433 = "SQL Server"
    1723 = "PPTP VPN"
    3389 = "Remote Desktop (RDP)"
    4444 = "Metasploit default listener"
    5900 = "VNC Remote Desktop"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    6379 = "Redis (often unauthenticated)"
    27017= "MongoDB (often unauthenticated)"
}

$foundDanger = $false
foreach ($conn in $listeningPorts) {
    if ($dangerPorts.ContainsKey([int]$conn.LocalPort)) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Add-Result "Network" "Port $($conn.LocalPort) Open" "WARN" `
            "$($dangerPorts[[int]$conn.LocalPort]) - Process: $($proc.Name) (PID $($conn.OwningProcess))" `
            "Disable the service if not needed, or restrict via firewall"
        $foundDanger = $true
    }
}
if (-not $foundDanger) {
    Add-Result "Network" "Risky Ports Scan" "OK" "None of the high-risk ports (RDP/VNC/Telnet/SMB etc.) are listening"
}

$totalListening = $listeningPorts.Count
Add-Result "Network" "Total Listening TCP Ports" "INFO" "$totalListening port(s) in LISTEN state"

# Active outbound connections
$established = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127|::1|0\.0)' }
Add-Result "Network" "Active Outbound Connections" "INFO" "$($established.Count) established connection(s) to remote hosts"

# ---- 6. REMOTE ACCESS SERVICES -----------------------------------------------
Write-Header "REMOTE ACCESS SERVICES"

# RDP
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    Add-Result "Remote Access" "Remote Desktop (RDP)" "WARN" "RDP is ENABLED" `
        "Disable if unused: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1"
} else {
    Add-Result "Remote Access" "Remote Desktop (RDP)" "OK" "Disabled"
}

# RDP NLA (Network Level Authentication)
$nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    if ($nla.UserAuthentication -eq 1) {
        Add-Result "Remote Access" "RDP Network Level Auth" "OK" "NLA required (more secure)"
    } else {
        Add-Result "Remote Access" "RDP Network Level Auth" "CRIT" "NLA is DISABLED - RDP accepts connections without pre-auth" `
            "Enable: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
    }
}

# WinRM
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue
if ($winrm.Status -eq "Running") {
    Add-Result "Remote Access" "WinRM (PowerShell Remoting)" "WARN" "WinRM service is RUNNING - allows remote PowerShell" `
        "Stop if unused: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"
} else {
    Add-Result "Remote Access" "WinRM (PowerShell Remoting)" "OK" "WinRM service is stopped/disabled"
}

# Remote Registry
$remReg = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
if ($remReg.Status -eq "Running") {
    Add-Result "Remote Access" "Remote Registry" "WARN" "Remote Registry service is RUNNING" `
        "Disable: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled"
} else {
    Add-Result "Remote Access" "Remote Registry" "OK" "Remote Registry is stopped/disabled"
}

# SSH server
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if ($sshd.Status -eq "Running") {
    Add-Result "Remote Access" "OpenSSH Server" "WARN" "OpenSSH Server (sshd) is RUNNING" `
        "Disable if unused: Stop-Service sshd; Set-Service sshd -StartupType Disabled"
} else {
    Add-Result "Remote Access" "OpenSSH Server" "OK" "OpenSSH Server not running"
}

# Check for VNC processes
$vncProcs = Get-Process | Where-Object { $_.Name -match "vnc|vncserver|tightvnc|realvnc|ultravnc|teamviewer|anydesk|logmein|screenconnect|gotomypc" }
if ($vncProcs) {
    foreach ($p in $vncProcs) {
        Add-Result "Remote Access" "Remote Access Software" "WARN" `
            "Process found: $($p.Name) (PID $($p.Id))" `
            "Verify this is intentional and the software is secured with a strong password"
    }
} else {
    Add-Result "Remote Access" "Remote Desktop Software" "OK" "No VNC/TeamViewer/AnyDesk processes running"
}

# ---- 7. USER ACCOUNTS --------------------------------------------------------
Write-Header "USER ACCOUNTS"

$localUsers = Get-LocalUser
foreach ($u in $localUsers) {
    if ($u.Enabled) {
        if ($u.PasswordRequired -eq $false) {
            Add-Result "Users" "No Password: $($u.Name)" "CRIT" "Account '$($u.Name)' has no password required" `
                "Set a password: net user $($u.Name) NewStrongPassword123!"
        }
        if ($u.PasswordNeverExpires) {
            Add-Result "Users" "Password Never Expires: $($u.Name)" "WARN" `
                "Account '$($u.Name)' has a non-expiring password" `
                "Set expiry: Set-LocalUser -Name '$($u.Name)' -PasswordNeverExpires `$false"
        }
        $daysSinceLogin = if ($u.LastLogon) { ((Get-Date) - $u.LastLogon).Days } else { 9999 }
        if ($daysSinceLogin -gt 90 -and $u.Name -notin @("Administrator","DefaultAccount","WDAGUtilityAccount")) {
            Add-Result "Users" "Stale Account: $($u.Name)" "WARN" `
                "Last login $daysSinceLogin days ago - may be unused" `
                "Disable if unused: Disable-LocalUser -Name '$($u.Name)'"
        }
    }
}

# Guest account
$guest = Get-LocalUser "Guest" -ErrorAction SilentlyContinue
if ($guest.Enabled) {
    Add-Result "Users" "Guest Account" "CRIT" "Built-in Guest account is ENABLED" `
        "Disable: Disable-LocalUser -Name 'Guest'"
} else {
    Add-Result "Users" "Guest Account" "OK" "Guest account disabled"
}

# Built-in Administrator
$builtinAdmin = Get-LocalUser "Administrator" -ErrorAction SilentlyContinue
if ($builtinAdmin.Enabled) {
    Add-Result "Users" "Built-in Administrator" "WARN" "Built-in Administrator account is enabled - rename it" `
        "Rename: Rename-LocalUser -Name 'Administrator' -NewName 'SysAdmin2025'"
} else {
    Add-Result "Users" "Built-in Administrator" "OK" "Built-in Administrator account is disabled"
}

# Admins list
$admins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
Add-Result "Users" "Local Administrators" "INFO" "Members: $($admins -join ', ')"
if ($admins.Count -gt 2) {
    Add-Result "Users" "Excessive Admins" "WARN" "$($admins.Count) local administrator accounts - minimize this" `
        "Remove unnecessary accounts from the Administrators group"
}

# ---- 8. STARTUP AND PERSISTENCE ----------------------------------------------
Write-Header "STARTUP AND PERSISTENCE"

$suspExts   = @('.vbs','.bat','.cmd','.ps1','.js','.jar','.scr','.pif','.hta','.wsf')
$startupKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
$suspFound = $false
foreach ($key in $startupKeys) {
    $items = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($items) {
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $val  = $_.Value
            $ext  = [System.IO.Path]::GetExtension($val.Split('"')[0].Trim().Split(' ')[0])
            $flag = $suspExts -contains $ext.ToLower()
            $st   = if ($flag) { "WARN" } else { "INFO" }
            Add-Result "Startup" "Run Key: $($_.Name)" $st `
                "[$($key -replace 'HKLM:\\|HKCU:\\','')] $val" `
                $(if($flag){"Investigate this startup script: $val"}else{""})
            if ($flag) { $suspFound = $true }
        }
    }
}

# Scheduled tasks - look for suspicious ones
$tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notmatch '\\Microsoft\\' }
$suspTasks = $tasks | Where-Object {
    $actions = $_.Actions | ForEach-Object { $_.Execute }
    $actions | Where-Object { $_ -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32" }
}
if ($suspTasks) {
    foreach ($t in ($suspTasks | Select-Object -First 10)) {
        Add-Result "Startup" "Suspicious Scheduled Task" "WARN" `
            "Task '$($t.TaskName)' runs: $($t.Actions[0].Execute) $($t.Actions[0].Arguments)" `
            "Review in Task Scheduler; disable if unknown"
    }
} else {
    Add-Result "Startup" "Scheduled Tasks" "OK" "No obviously suspicious non-Microsoft scheduled tasks found"
}

# ---- 9. SERVICES -------------------------------------------------------------
Write-Header "SERVICES"
$riskyServices = @{
    "Telnet"          = "Telnet server - unencrypted remote access"
    "TlntSvr"         = "Telnet server - unencrypted remote access"
    "SNMP"            = "SNMP - can leak system info if community string is 'public'"
    "FTPSVC"          = "FTP server - unencrypted"
    "W3SVC"           = "IIS Web Server - ensure it is needed and patched"
    "MSSQLSERVER"     = "SQL Server - ensure firewall restricts access"
    "MySQL"           = "MySQL - ensure firewall restricts access"
    "TeamViewer"      = "TeamViewer remote access service"
    "AnyDesk"         = "AnyDesk remote access service"
    "LogMeIn"         = "LogMeIn remote access service"
    "UltraVNCServer"  = "UltraVNC remote access server"
    "vncserver"       = "VNC remote access server"
    "ScreenConnect"   = "ConnectWise remote access service"
}
foreach ($svcName in $riskyServices.Keys) {
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Add-Result "Services" "Risky Service Running" "WARN" `
            "$($svc.DisplayName): $($riskyServices[$svcName])" `
            "Stop and disable if not required: Stop-Service '$svcName'; Set-Service '$svcName' -StartupType Disabled"
    }
}

# Services running as LocalSystem with unusual paths
$suspSvcPaths = Get-CimInstance Win32_Service | Where-Object {
    $_.StartMode -eq "Auto" -and
    $_.State -eq "Running" -and
    $_.PathName -match "(temp|appdata|users\\public|downloads)" -and
    $_.PathName -notmatch "microsoft|windows"
}
if ($suspSvcPaths) {
    foreach ($s in $suspSvcPaths) {
        Add-Result "Services" "Service in Suspicious Path" "CRIT" `
            "'$($s.Name)' running from: $($s.PathName)" `
            "Investigate immediately - malware often installs services from user-writable paths"
    }
} else {
    Add-Result "Services" "Service Path Check" "OK" "No services running from user-writable/temp paths"
}

# ---- 10. SECURITY POLICIES ---------------------------------------------------
Write-Header "SECURITY POLICIES"

# UAC
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
if ($uac.EnableLUA -eq 0) {
    Add-Result "Policy" "UAC (User Account Control)" "CRIT" "UAC is DISABLED - apps run with full admin rights silently" `
        "Enable: Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
} else {
    $uacLevel = switch ($uac.ConsentPromptBehaviorAdmin) {
        0 { "No prompt (RISKY)" } 1 { "Prompt for creds on secure desktop" }
        2 { "Prompt for creds" }   3 { "Prompt for consent on secure desktop" }
        4 { "Prompt for consent" } 5 { "Prompt for non-Windows binaries" }
        default { "Unknown ($($uac.ConsentPromptBehaviorAdmin))" }
    }
    $uacSt = if ($uac.ConsentPromptBehaviorAdmin -in @(0,4)) { "WARN" } else { "OK" }
    Add-Result "Policy" "UAC Level" $uacSt "Behaviour: $uacLevel" `
        "Recommended: level 3 (prompt on secure desktop)"
}

# SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($smb1.State -eq "Enabled") {
    Add-Result "Policy" "SMBv1 Protocol" "CRIT" "SMBv1 is ENABLED - vulnerable to EternalBlue/WannaCry" `
        "Disable: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
} else {
    Add-Result "Policy" "SMBv1 Protocol" "OK" "SMBv1 is disabled"
}

# AutoRun/AutoPlay
$autoRun = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
if (-not $autoRun -or $autoRun.NoDriveTypeAutoRun -lt 255) {
    Add-Result "Policy" "AutoRun" "WARN" "AutoRun may be enabled for some drive types (common malware vector via USB)" `
        "Disable: Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
} else {
    Add-Result "Policy" "AutoRun" "OK" "AutoRun disabled for all drive types"
}

# PowerShell script execution policy
$execPolicy = Get-ExecutionPolicy -Scope LocalMachine
if ($execPolicy -in @("Unrestricted","Bypass")) {
    Add-Result "Policy" "PowerShell Execution Policy" "WARN" `
        "Execution policy is '$execPolicy' - any script can run" `
        "Set: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
} else {
    Add-Result "Policy" "PowerShell Execution Policy" "OK" "Policy is '$execPolicy'"
}

# PowerShell v2
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
if ($psv2.State -eq "Enabled") {
    Add-Result "Policy" "PowerShell v2" "WARN" "PowerShell v2 is enabled - lacks modern security controls (logging, AMSI)" `
        "Disable: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
} else {
    Add-Result "Policy" "PowerShell v2" "OK" "PowerShell v2 is disabled"
}

# LLMNR (used in relay attacks)
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
if (-not $llmnr -or $llmnr.EnableMulticast -ne 0) {
    Add-Result "Policy" "LLMNR (Link-Local Multicast Name Resolution)" "WARN" `
        "LLMNR may be enabled - used in credential relay/MITM attacks on local networks" `
        "Disable via Group Policy: Computer Configuration > Admin Templates > Network > DNS Client > Turn off Multicast"
} else {
    Add-Result "Policy" "LLMNR" "OK" "LLMNR is disabled"
}

# ---- 11. DISK ENCRYPTION -----------------------------------------------------
Write-Header "DISK ENCRYPTION"
$volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($volumes) {
    foreach ($v in $volumes) {
        $st = if ($v.ProtectionStatus -eq "On") { "OK" } else { "WARN" }
        Add-Result "Encryption" "BitLocker: $($v.MountPoint)" $st `
            "Status: $($v.ProtectionStatus) | Encryption: $($v.EncryptionPercentage)%" `
            "Enable BitLocker: Enable-BitLocker -MountPoint '$($v.MountPoint)' -RecoveryPasswordProtector"
    }
} else {
    Add-Result "Encryption" "BitLocker" "WARN" "BitLocker not available or no encrypted volumes detected" `
        "Enable BitLocker on your system drive via Control Panel > BitLocker Drive Encryption"
}

# ---- 12. AUDIT AND LOGGING ---------------------------------------------------
Write-Header "AUDIT AND LOGGING"

# Windows Event Log sizes
$importantLogs = @("Security","System","Application")
foreach ($logName in $importantLogs) {
    $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if ($log) {
        $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
        $st     = if ($sizeMB -ge 20) { "OK" } else { "WARN" }
        Add-Result "Logging" "$logName Log Max Size" $st "${sizeMB}MB" `
            "Increase to at least 20MB: wevtutil sl $logName /ms:20971520"
    }
}

# Audit policy - logon events
$auditLogon = auditpol /get /subcategory:"Logon" 2>$null
if ($auditLogon -match "Success and Failure") {
    Add-Result "Logging" "Audit Logon Events" "OK" "Success and Failure audited"
} elseif ($auditLogon -match "Success|Failure") {
    Add-Result "Logging" "Audit Logon Events" "WARN" "Only partial logon auditing ($($auditLogon -match 'Success|Failure'))" `
        "Set full auditing: auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
} else {
    Add-Result "Logging" "Audit Logon Events" "WARN" "Logon auditing may not be fully configured" `
        "Enable: auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
}

# PowerShell script block logging
$psSBL = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($psSBL.EnableScriptBlockLogging -eq 1) {
    Add-Result "Logging" "PS Script Block Logging" "OK" "Enabled - PowerShell commands are logged"
} else {
    Add-Result "Logging" "PS Script Block Logging" "WARN" "Disabled - malicious PowerShell will not be logged" `
        "Enable via: HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging > EnableScriptBlockLogging = 1"
}

# ---- 13. SUSPICIOUS PROCESSES ------------------------------------------------
Write-Header "SUSPICIOUS PROCESSES"
$suspNames = @("nc","ncat","netcat","mimikatz","pwdump","gsecdump","fgdump","procdump",
               "wce","ophcrack","hashcat","psexec","plink","tor","proxifier",
               "ngrok","frpc","chisel","meterpreter","cobalt","beacon")
$runningProcs = Get-Process
$foundSusp = $false
foreach ($p in $runningProcs) {
    if ($suspNames -contains $p.Name.ToLower()) {
        Add-Result "Processes" "Suspicious Process" "CRIT" `
            "Process '$($p.Name)' (PID $($p.Id)) is a known hacking/tunnelling tool" `
            "Investigate and terminate if unexpected: Stop-Process -Id $($p.Id) -Force"
        $foundSusp = $true
    }
}
if (-not $foundSusp) {
    Add-Result "Processes" "Known Hacking Tools" "OK" "No known hacking/credential-dump processes detected"
}

# Processes with no file on disk (hollowing indicator)
$hollowed = $runningProcs | Where-Object {
    try { -not (Test-Path $_.MainModule.FileName) } catch { $false }
} | Where-Object { $_.Name -notin @("Idle","System","Registry","smss","csrss","wininit","services","lsass","svchost","fontdrvhost","dwm","winlogon","LogonUI","sihost","taskhostw","ShellExperienceHost","SearchHost","StartMenuExperienceHost","RuntimeBroker","backgroundTaskHost","ctfmon","SecurityHealthSystray","SgrmBroker","spoolsv") }
if ($hollowed) {
    foreach ($h in ($hollowed | Select-Object -First 5)) {
        Add-Result "Processes" "Process with No Disk Image" "WARN" `
            "'$($h.Name)' (PID $($h.Id)) has no path on disk - possible process hollowing" `
            "Investigate with Process Explorer or: Get-Process -Id $($h.Id) | Select-Object *"
    }
}

# ---- 14. NETWORK CONNECTIONS -------------------------------------------------
Write-Header "ACTIVE NETWORK CONNECTIONS"
$activeConns = Get-NetTCPConnection -State Established | Where-Object {
    $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)'
} | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Process       = $proc.Name
        PID           = $_.OwningProcess
        LocalAddress  = "$($_.LocalAddress):$($_.LocalPort)"
        RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
    }
}
if ($activeConns) {
    foreach ($c in $activeConns) {
        Add-Result "Network" "Outbound Connection" "INFO" `
            "$($c.Process) (PID $($c.PID)) -> $($c.RemoteAddress)"
    }
} else {
    Add-Result "Network" "Outbound Connections" "INFO" "No active outbound TCP connections to external hosts"
}

# ---- 15. CREDENTIAL EXPOSURE -------------------------------------------------
Write-Header "CREDENTIAL EXPOSURE"

# WDigest - if 1, credentials stored in cleartext in LSASS memory
$wdigest = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -eq 1) {
    Add-Result "Credentials" "WDigest Cleartext Creds" "CRIT" `
        "WDigest UseLogonCredential=1 - passwords stored in LSASS memory in CLEARTEXT (Mimikatz ready)" `
        "Fix: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
} else {
    Add-Result "Credentials" "WDigest Cleartext Creds" "OK" "WDigest cleartext credential caching is disabled"
}

# LSASS Protected Process
$lsassPPL = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
if ($lsassPPL.RunAsPPL -eq 1) {
    Add-Result "Credentials" "LSASS Protected Process" "OK" "LSASS running as Protected Process Light (harder to dump)"
} else {
    Add-Result "Credentials" "LSASS Protected Process" "WARN" "LSASS is NOT running as Protected Process Light" `
        "Enable: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 (requires reboot)"
}

# Credential Guard
$credGuard = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
if ($credGuard.EnableVirtualizationBasedSecurity -eq 1) {
    Add-Result "Credentials" "Credential Guard" "OK" "Virtualization-based security/Credential Guard enabled"
} else {
    Add-Result "Credentials" "Credential Guard" "INFO" "Credential Guard not detected (may require Windows 11 Enterprise)" `
        "Enable via Group Policy: Computer Config > Admin Templates > System > Device Guard"
}

# ---- SUMMARY ----------------------------------------------------------------
Write-Header "SCAN SUMMARY"
$score = [math]::Max(0, 100 - ($Critical * 15) - ($Warnings * 5))
Write-Host "`n  Security Score: $score / 100" -ForegroundColor $(if($score -ge 80){"Green"}elseif($score -ge 60){"Yellow"}else{"Red"})
Write-Host "  Critical Issues: $Critical" -ForegroundColor Red
Write-Host "  Warnings:        $Warnings" -ForegroundColor Yellow
Write-Host "  Passed Checks:   $Passed`n"  -ForegroundColor Green

# ---- HTML REPORT -------------------------------------------------------------
$scoreColor = if ($score -ge 80) { "#27a058" } elseif ($score -ge 60) { "#d97706" } else { "#dc2626" }
$badgeHtml = {
    param($s)
    switch ($s) {
        "OK"   { '<span style="background:#d1fae5;color:#065f46;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">OK</span>' }
        "WARN" { '<span style="background:#fef3c7;color:#92400e;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">WARN</span>' }
        "CRIT" { '<span style="background:#fee2e2;color:#991b1b;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">CRIT</span>' }
        "INFO" { '<span style="background:#dbeafe;color:#1e40af;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">INFO</span>' }
    }
}

$rowsHtml = $Results | ForEach-Object {
    $badge = & $badgeHtml $_.Status
    $rec   = if ($_.Recommendation) { "<div style='font-size:12px;color:#6b7280;margin-top:4px;font-family:monospace;background:#f9fafb;padding:4px 8px;border-radius:4px;border-left:3px solid #d1d5db'><b>Fix:</b> $($_.Recommendation)</div>" } else { "" }
    "<tr style='border-bottom:1px solid #f3f4f6'>
       <td style='padding:10px 12px;font-size:13px;color:#6b7280'>$($_.Category)</td>
       <td style='padding:10px 12px;font-size:14px;font-weight:500;color:#111827'>$($_.Check)</td>
       <td style='padding:10px 12px'>$badge</td>
       <td style='padding:10px 12px;font-size:13px;color:#374151'>$($_.Detail)$rec</td>
      </tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Scan - $env:COMPUTERNAME</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827}
  header{background:#1e293b;color:white;padding:2rem;display:flex;align-items:center;gap:2rem}
  .score-wrap{text-align:center;flex-shrink:0}
  .score-num{font-size:48px;font-weight:700;color:$scoreColor}
  .score-lbl{font-size:12px;opacity:.6;margin-top:4px}
  header h1{font-size:22px;font-weight:600}
  header p{font-size:14px;opacity:.7;margin-top:6px}
  .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;padding:1.5rem 2rem;background:white;border-bottom:1px solid #e5e7eb}
  .metric{text-align:center}
  .metric .val{font-size:28px;font-weight:700}
  .metric .lbl{font-size:12px;color:#6b7280;margin-top:4px}
  .crit{color:#dc2626}.warn{color:#d97706}.pass{color:#16a34a}.info{color:#2563eb}
  main{padding:2rem;max-width:1100px;margin:0 auto}
  h2{font-size:18px;font-weight:600;margin:2rem 0 1rem;color:#1e293b;padding-bottom:.5rem;border-bottom:2px solid #e5e7eb}
  table{width:100%;border-collapse:collapse;background:white;border-radius:8px;border:1px solid #e5e7eb;overflow:hidden}
  th{background:#f8fafc;padding:10px 12px;font-size:12px;color:#6b7280;font-weight:600;text-align:left;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #e5e7eb}
  tr:hover{background:#fafafa}
  .footer{text-align:center;padding:2rem;font-size:12px;color:#9ca3af}
</style>
</head>
<body>
<header>
  <div class="score-wrap">
    <div class="score-num">$score</div>
    <div class="score-lbl">Security Score</div>
  </div>
  <div>
    <h1>Windows Security Scan - $env:COMPUTERNAME</h1>
    <p>$($os.Caption) &bull; Scanned: $(Get-Date -Format 'dddd dd MMMM yyyy, HH:mm:ss') &bull; User: $env:USERDOMAIN\$env:USERNAME</p>
  </div>
</header>
<div class="metrics">
  <div class="metric"><div class="val crit">$Critical</div><div class="lbl">Critical Issues</div></div>
  <div class="metric"><div class="val warn">$Warnings</div><div class="lbl">Warnings</div></div>
  <div class="metric"><div class="val pass">$Passed</div><div class="lbl">Passed</div></div>
  <div class="metric"><div class="val info">$($Results.Count)</div><div class="lbl">Total Checks</div></div>
</div>
<main>
  <h2>All Findings</h2>
  <table>
    <thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail / Recommendation</th></tr></thead>
    <tbody>$($rowsHtml -join "`n")</tbody>
  </table>
</main>
<div class="footer">Generated by WindowsSecurityScan.ps1 &bull; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</body>
</html>
"@

$html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`n  [✓] HTML report saved to: $ReportPath`" -ForegroundColor Cyan
Write-Host "  Opening report in browser..." -ForegroundColor Gray
Start-Process $ReportPath
