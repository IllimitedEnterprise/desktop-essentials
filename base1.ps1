<#
.SYNOPSIS
    Remediation companion to Check-SmbNetbiosExposure.ps1 — hardens the findings.

.DESCRIPTION
    Applies fixes for the issues the audit script flags:
      1. Disable SMB1 (Windows feature + SMB server)
      2. Require SMB signing (+ optionally disable insecure guest logon)
      3. Disable NetBIOS over TCP/IP on all IP-enabled adapters
      4. Report risky listening ports and offer to stop/disable known legacy
         services (Telnet, FTP, SNMP, Remote Registry) — never kills unknown apps.

    SAFETY MODEL:
      - DRY RUN by default. It shows exactly what WOULD change and does nothing.
      - Pass -Apply to actually make changes.
      - Before applying it writes a rollback file (JSON) capturing prior state.
      - Already-hardened settings are skipped (idempotent).

.PARAMETER Apply
    Actually perform the changes. Without it, the script only previews.

.PARAMETER IncludeServices
    Also stop & disable known legacy services (Telnet/FTP/SNMP/RemoteRegistry).

.PARAMETER RollbackPath
    Where to write the pre-change state snapshot. Default: script folder.

.EXAMPLE
    .\Harden-SmbNetbiosExposure.ps1                # preview only
    .\Harden-SmbNetbiosExposure.ps1 -Apply         # apply core hardening
    .\Harden-SmbNetbiosExposure.ps1 -Apply -IncludeServices

.NOTES
    MUST be run in an ELEVATED PowerShell (Run as Administrator).
    Disabling SMB1 can break access to very old NAS/printers/XP-era hosts.
    A reboot is recommended after applying.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$IncludeServices,
    [string]$RollbackPath = (Join-Path $PSScriptRoot "harden-rollback-$(Get-Date -Format yyyyMMdd-HHmmss).json")
)

$ErrorActionPreference = 'Stop'
$rollback = [ordered]@{ Timestamp = (Get-Date -Format u); Host = $env:COMPUTERNAME }
$mode = if ($Apply) { "APPLY" } else { "DRY-RUN (preview only — pass -Apply to change)" }

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor DarkCyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host ("=" * 62) -ForegroundColor DarkCyan
}

# Executes a change only when -Apply is set; otherwise just prints the intent.
function Invoke-Change($description, [scriptblock]$action) {
    if ($Apply) {
        Write-Host "[APPLY] $description" -ForegroundColor Green
        try { & $action; Write-Host "        done." -ForegroundColor DarkGreen }
        catch { Write-Host "        FAILED: $($_.Exception.Message)" -ForegroundColor Red }
    } else {
        Write-Host "[WOULD] $description" -ForegroundColor Yellow
    }
}

# --- Elevation guard -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[X] This script MUST run elevated (Run as Administrator). Aborting." -ForegroundColor Red
    return
}

Write-Host ""
Write-Host " Hardening mode: $mode" -ForegroundColor White
Write-Host " Rollback snapshot: $RollbackPath" -ForegroundColor Gray

# ==========================================================================
# 1. SMB1
# ==========================================================================
Write-Section "1. Disable SMB1 (SMBv1 / CIFS)"

$smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$rollback.SMB1_OptionalFeature = "$($smb1Feature.State)"
if ($smb1Feature -and $smb1Feature.State -eq 'Enabled') {
    Invoke-Change "Disable Windows optional feature 'SMB1Protocol' (reboot needed)" {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
    }
} else {
    Write-Host "[SKIP] SMB1 optional feature already disabled/absent." -ForegroundColor DarkGray
}

$srvSmb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$rollback.SMB1_Server = "$srvSmb1"
if ($srvSmb1 -eq $true) {
    Invoke-Change "Set-SmbServerConfiguration -EnableSMB1Protocol `$false" {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    }
} else {
    Write-Host "[SKIP] SMB1 already disabled on SMB server." -ForegroundColor DarkGray
}

# Disable the SMB1 client driver/dependency (mrxsmb10) as well
$mrxsmb10 = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue
if ($mrxsmb10 -and $mrxsmb10.StartType -ne 'Disabled') {
    $rollback.SMB1_ClientDriver = "$($mrxsmb10.StartType)"
    Invoke-Change "Disable SMB1 client driver (mrxsmb10) via sc config" {
        sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null
        sc.exe config mrxsmb10 start= disabled | Out-Null
    }
} else {
    Write-Host "[SKIP] SMB1 client driver already disabled/absent." -ForegroundColor DarkGray
}

# ==========================================================================
# 2. SMB signing / guest hardening
# ==========================================================================
Write-Section "2. Require SMB signing + block insecure guest logon"

$smbCfg = Get-SmbServerConfiguration
$rollback.SMB_RequireSecuritySignature = "$($smbCfg.RequireSecuritySignature)"
if (-not $smbCfg.RequireSecuritySignature) {
    Invoke-Change "Require SMB server signing" {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbServerConfiguration -EnableSecuritySignature   $true -Force
    }
} else {
    Write-Host "[SKIP] SMB server signing already required." -ForegroundColor DarkGray
}

# Client-side: require signing too
$smbClient = Get-SmbClientConfiguration
$rollback.SMBClient_RequireSecuritySignature = "$($smbClient.RequireSecuritySignature)"
if (-not $smbClient.RequireSecuritySignature) {
    Invoke-Change "Require SMB client signing" {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    }
} else {
    Write-Host "[SKIP] SMB client signing already required." -ForegroundColor DarkGray
}

# Block insecure guest logons (prevents unauthenticated SMB access)
$lanmanKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$curGuest = (Get-ItemProperty -Path $lanmanKey -Name AllowInsecureGuestAuth -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
$rollback.AllowInsecureGuestAuth = "$curGuest"
if ($curGuest -ne 0) {
    Invoke-Change "Disable insecure guest logon (AllowInsecureGuestAuth=0)" {
        New-Item -Path $lanmanKey -Force | Out-Null
        Set-ItemProperty -Path $lanmanKey -Name AllowInsecureGuestAuth -Value 0 -Type DWord
    }
} else {
    Write-Host "[SKIP] Insecure guest logon already disabled." -ForegroundColor DarkGray
}

# ==========================================================================
# 3. NetBIOS over TCP/IP
# ==========================================================================
Write-Section "3. Disable NetBIOS over TCP/IP (all adapters)"

$nbConfigs = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
$nbRollback = @()
foreach ($nb in $nbConfigs) {
    $nbRollback += [pscustomobject]@{ Desc = $nb.Description; Setting = $nb.SettingID; Option = $nb.TcpipNetbiosOptions }
    if ($nb.TcpipNetbiosOptions -ne 2) {
        Invoke-Change "Disable NetBIOS on '$($nb.Description)' (SetTcpipNetbios=2)" {
            $r = $nb.SetTcpipNetbios(2)
            if ($r.ReturnValue -ne 0) {
                # Fallback: registry per-interface (needs reboot)
                $ifKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($nb.SettingID)"
                if (Test-Path $ifKey) { Set-ItemProperty -Path $ifKey -Name NetbiosOptions -Value 2 -Type DWord }
            }
        }
    } else {
        Write-Host "[SKIP] NetBIOS already disabled on '$($nb.Description)'." -ForegroundColor DarkGray
    }
}
$rollback.NetBIOS = $nbRollback

# Also disable the LLMNR + mDNS name-poisoning vectors (defense-in-depth)
$dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$curLlmnr = (Get-ItemProperty -Path $dnsKey -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
$rollback.LLMNR_EnableMulticast = "$curLlmnr"
if ($curLlmnr -ne 0) {
    Invoke-Change "Disable LLMNR (EnableMulticast=0) — blocks LLMNR poisoning" {
        New-Item -Path $dnsKey -Force | Out-Null
        Set-ItemProperty -Path $dnsKey -Name EnableMulticast -Value 0 -Type DWord
    }
} else {
    Write-Host "[SKIP] LLMNR already disabled." -ForegroundColor DarkGray
}

# ==========================================================================
# 4. Legacy services on risky ports
# ==========================================================================
Write-Section "4. Legacy services on risky ports"

# Map risky listening ports -> the Windows service that typically owns them.
$legacyServices = @{
    "TlntSvr"        = "Telnet Server (port 23, cleartext)"
    "FTPSVC"         = "FTP Server / IIS FTP (port 21, cleartext)"
    "SNMP"           = "SNMP Service (port 161)"
    "RemoteRegistry" = "Remote Registry (lateral-movement aid)"
    "SessionEnv"     = $null  # placeholder, not touched
}

# Show what's actually listening on flagged ports first
$riskyPorts = 21,23,69,111,135,137,138,139,161,512,513,514,1434,5900
$listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $riskyPorts -contains $_.LocalPort }
if ($listening) {
    Write-Host "Currently listening on flagged ports:" -ForegroundColor White
    foreach ($l in $listening) {
        $pname = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        Write-Host ("   {0}:{1}  <-  {2} (PID {3})" -f $l.LocalAddress, $l.LocalPort, $pname, $l.OwningProcess) -ForegroundColor Red
    }
} else {
    Write-Host "[OK] Nothing listening on the common legacy TCP ports." -ForegroundColor Green
}

if ($IncludeServices) {
    $svcRollback = @()
    foreach ($name in ($legacyServices.Keys | Where-Object { $legacyServices[$_] })) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartType -ne 'Disabled') {
            $svcRollback += [pscustomobject]@{ Name = $name; StartType = "$($svc.StartType)"; Status = "$($svc.Status)" }
            Invoke-Change "Stop & disable '$name' — $($legacyServices[$name])" {
                Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                Set-Service  -Name $name -StartupType Disabled
            }
        } else {
            Write-Host "[SKIP] '$name' not present or already disabled." -ForegroundColor DarkGray
        }
    }
    $rollback.LegacyServices = $svcRollback
} else {
    Write-Host "[INFO] Re-run with -IncludeServices to auto-disable Telnet/FTP/SNMP/RemoteRegistry." -ForegroundColor Gray
}

# ==========================================================================
# Save rollback snapshot + summary
# ==========================================================================
Write-Section "Summary"

if ($Apply) {
    $rollback | ConvertTo-Json -Depth 6 | Set-Content -Path $RollbackPath -Encoding UTF8
    Write-Host "[OK] Pre-change state saved to:" -ForegroundColor Green
    Write-Host "     $RollbackPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "[!] A REBOOT is recommended to fully apply SMB1 / NetBIOS changes." -ForegroundColor Yellow
    Write-Host "    Verify afterwards by re-running Check-SmbNetbiosExposure.ps1" -ForegroundColor Gray
} else {
    Write-Host "DRY-RUN complete. No changes made." -ForegroundColor White
    Write-Host "Re-run with -Apply to harden (add -IncludeServices to also disable legacy services)." -ForegroundColor Gray
}
