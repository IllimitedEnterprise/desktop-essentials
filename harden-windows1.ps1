# ===========================================
# Windows 11 Hardening Script
# ===========================================

# Function to log actions
function Log-Action {
    param([string]$Message)
    Write-Host "[*] $Message"
}

# 1. Disable unnecessary services
$servicesToDisable = @(
    "XblGameSave",      # Xbox Game Save
    "DiagTrack",        # Connected User Experiences and Telemetry
    "dmwappushservice", # Device Management
    "MapsBroker",       # Maps
    "Fax",              # Fax
    "WMPNetworkSvc",    # Windows Media Player Network Sharing
    "RetailDemo",       # Retail Demo Service
    "XblAuthManager"    # Xbox Live Auth
)

foreach ($svc in $servicesToDisable) {
    Log-Action "Disabling service: $svc"
    Stop-Service -Name $svc -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled
}

# 2. Disable Windows Telemetry & Data Collection
Log-Action "Disabling Telemetry and Data Collection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableTelemetry" -Value 1 -Force

# 3. Configure Windows Defender (Real-Time & Tamper Protection)
Log-Action "Configuring Windows Defender"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -EnableControlledFolderAccess Enabled

# 4. Enable BitLocker (if available)
if ((Get-BitLockerVolume).VolumeStatus -eq 'FullyDecrypted') {
    Log-Action "Enabling BitLocker on OS drive"
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
}

# 5. Configure Firewall & Network Security
Log-Action "Configuring Firewall"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# 6. Remove unnecessary apps (bloatware)
$appsToRemove = @(
    "Microsoft.XboxApp",
    "Microsoft.YourPhone",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People"
)

foreach ($app in $appsToRemove) {
    Log-Action "Removing app: $app"
    Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
}

# 7. Enforce strong password policies
Log-Action "Enforcing password policy"
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:5

# 8. Disable SMBv1 (legacy and insecure)
Log-Action "Disabling SMBv1"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# 9. Enable auditing for security events
Log-Action "Enabling advanced audit policies"
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

# 10. Disable unnecessary scheduled tasks (telemetry)
$tasksToDisable = @(
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
)

foreach ($task in $tasksToDisable) {
    Log-Action "Disabling scheduled task: $task"
    Disable-ScheduledTask -TaskPath $task.Split('\')[0..($task.Split('\').Length-2)] -TaskName $task.Split('\')[-1] -ErrorAction SilentlyContinue
}

# 11. Configure Windows Update to automatic & secure
Log-Action "Configuring Windows Update"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Force

# 12. Enable Controlled Folder Access (Ransomware Protection)
Log-Action "Enabling Controlled Folder Access"
Set-MpPreference -EnableControlledFolderAccess Enabled

# 13. Disable macros in Office via registry (if Office installed)
Log-Action "Disabling Office macros"
$officePaths = @(
    "HKCU:\Software\Microsoft\Office\16.0\Word\Security",
    "HKCU:\Software\Microsoft\Office\16.0\Excel\Security",
    "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Security"
)

foreach ($path in $officePaths) {
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4
    }
}

Log-Action "Hardening script completed. Please restart the system."
