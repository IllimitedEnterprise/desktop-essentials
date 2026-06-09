# ============================================
# SYSTEM HARDENING SCRIPT FOR WINDOWS
# ============================================
# WARNING: Run this script as Administrator
# ============================================

# Function to log actions
$LogFile = "C:\Hardening_Log.txt"
function Log-Action {
    param ([string]$Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Message" | Out-File -FilePath $LogFile -Append
}

# -------------------------------
# 1. Disable Remote Desktop & Assistance
# -------------------------------
try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    Log-Action "Remote Desktop disabled."
} catch { Log-Action "Failed to disable Remote Desktop: $_" }

try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    Log-Action "Remote Assistance disabled."
} catch { Log-Action "Failed to disable Remote Assistance: $_" }

# -------------------------------
# 2. Disable PowerShell Remoting & WinRM
# -------------------------------
try {
    Disable-PSRemoting -Force -ErrorAction Stop
    Stop-Service WinRM -Force -ErrorAction Stop
    Set-Service WinRM -StartupType Disabled
    Log-Action "PowerShell remoting and WinRM disabled."
} catch { Log-Action "Failed to disable PowerShell remoting or WinRM: $_" }

# -------------------------------
# 3. Disable File & Printer Sharing, Network Discovery, SMB
# -------------------------------
try {
    # Disable network discovery
    Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled False
    Log-Action "Network discovery disabled."

    # Disable File and Printer Sharing
    Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled False
    Log-Action "File and Printer Sharing disabled."

    # Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Log-Action "SMBv1 disabled."

    # Disable SMB Direct (SMBv3 features)
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
    Log-Action "SMB2/3 disabled."
} catch { Log-Action "Failed to disable file sharing/SMB: $_" }

# -------------------------------
# 4. Disable unnecessary remote services
# -------------------------------
$RemoteServices = @(
    "RemoteRegistry",
    "Spooler",       # Only if printer not used
    "Telnet",
    "Tftp"
)

foreach ($service in $RemoteServices) {
    try {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service $service -Force
            Set-Service $service -StartupType Disabled
            Log-Action "$service disabled."
        }
    } catch { Log-Action "Failed to disable ${service}: $_" }}

# -------------------------------
# 5. Configure Windows Firewall
# -------------------------------
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Log-Action "Firewall enabled and inbound connections blocked by default."
} catch { Log-Action "Failed to configure firewall: $_" }

# -------------------------------
# 6. BitLocker
# -------------------------------
try {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnlyEncryption -TpmProtector -ErrorAction Stop
    Log-Action "BitLocker enabled on C: drive."
} catch { Log-Action "Failed to enable BitLocker: $_" }

# -------------------------------
# 7. Memory Integrity (Core Isolation)
# -------------------------------
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1
    Log-Action "Memory Integrity enabled (requires restart)."
} catch { Log-Action "Failed to enable Memory Integrity: $_" }

# -------------------------------
# 8. Create standard user account
# -------------------------------
try {
    $username = "Kraayan"
    if (-Not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $username -NoPassword -Description "Standard user account" -AccountNeverExpires
        Add-LocalGroupMember -Group "Users" -Member $username
        Log-Action "Standard user $username created."
    } else {
        Log-Action "User $username already exists."
    }
} catch { Log-Action "Failed to create user ${username}: $_" }

# -------------------------------
# 9. Microsoft Defender Settings
# -------------------------------
try {
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false
    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced
    # Enable behavior monitoring
    Set-MpPreference -EnableBehaviorMonitoring $true
    # Enable all protections
    Set-MpPreference -PUAProtection Enabled
    Log-Action "Microsoft Defender protections enabled."
} catch { Log-Action "Failed to configure Microsoft Defender: $_" }

# -------------------------------
# 10. Audit Listening Ports & Firewall Rules
# -------------------------------
try {
    Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,State,OwningProcess | Out-File "C:\ListeningPorts.txt"
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Out-File "C:\FirewallRules.txt"
    Log-Action "Audit of listening ports and firewall rules completed."
} catch { Log-Action "Failed to audit ports/firewall rules: $_" }

# -------------------------------
# 11. Windows Update
# -------------------------------
try {
    # Ensure updates are enabled
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Force
    Log-Action "Windows Update enabled."
} catch { Log-Action "Failed to configure Windows Update: $_" }

# -------------------------------
# 12. Manual Steps / Notes
# -------------------------------
Log-Action "NOTE: Please disable UPnP on your router manually via router settings."

# -------------------------------
# Script complete
# -------------------------------
Log-Action "System hardening script completed. Review logs for any errors."
Write-Output "Hardening complete. Logs saved to $LogFile"
