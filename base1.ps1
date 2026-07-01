<#
.SYNOPSIS
    Local host security audit: SMB1/NetBIOS status + listening TCP/UDP ports.

.DESCRIPTION
    Defensive posture check for the LOCAL machine. It reports:
      - SMB1 (SMBv1 / CIFS) client & server state  -> the EternalBlue/WannaCry protocol
      - SMB server signing / hardening settings
      - NetBIOS over TCP/IP status per adapter
      - All listening TCP and UDP ports, with risky/legacy ports flagged

    NOTE: This does NOT scan for "all" CVEs. True vulnerability scanning needs a
    dedicated scanner (Nessus, OpenVAS, nmap --script vuln) with a CVE database.
    This gives you the exposure picture a scanner would build on.

.NOTES
    Run in an ELEVATED PowerShell (Run as Administrator) for full results.
#>

[CmdletBinding()]
param(
    [switch]$AsJson
)

$ErrorActionPreference = 'SilentlyContinue'
$report = [ordered]@{}

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}

# --- Elevation check -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Not elevated. Some checks may be incomplete. Re-run as Administrator." -ForegroundColor Yellow
}

# --- 1. SMB1 status --------------------------------------------------------
Write-Section "SMB1 / SMBv1 (EternalBlue / WannaCry protocol)"

$smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($smb1Feature) {
    $state = $smb1Feature.State
    $report.SMB1_OptionalFeature = "$state"
    if ($state -eq 'Enabled') {
        Write-Host "[VULN] SMB1 Windows feature is ENABLED. Disable it." -ForegroundColor Red
        Write-Host "       Fix: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" -ForegroundColor Gray
    } else {
        Write-Host "[OK]   SMB1 Windows feature is $state." -ForegroundColor Green
    }
}

$srvSmb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$report.SMB1_Server = "$srvSmb1"
if ($srvSmb1 -eq $true) {
    Write-Host "[VULN] SMB1 is ENABLED on the SMB server. Disable it." -ForegroundColor Red
    Write-Host "       Fix: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" -ForegroundColor Gray
} elseif ($null -ne $srvSmb1) {
    Write-Host "[OK]   SMB1 disabled on SMB server." -ForegroundColor Green
}

# --- 2. SMB server hardening ----------------------------------------------
Write-Section "SMB Server Hardening"

$smbCfg = Get-SmbServerConfiguration
$report.SMB_SigningRequired = "$($smbCfg.RequireSecuritySignature)"
$report.SMB_EncryptData     = "$($smbCfg.EncryptData)"

if ($smbCfg.RequireSecuritySignature) {
    Write-Host "[OK]   SMB signing is REQUIRED." -ForegroundColor Green
} else {
    Write-Host "[WARN] SMB signing NOT required (relay-attack risk)." -ForegroundColor Yellow
    Write-Host "       Fix: Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" -ForegroundColor Gray
}
Write-Host ("       SMB2/3 present: {0}" -f $smbCfg.EnableSMB2Protocol)

# --- 3. NetBIOS over TCP/IP ------------------------------------------------
Write-Section "NetBIOS over TCP/IP (per adapter)"

$nbConfigs = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
$nbList = @()
foreach ($nb in $nbConfigs) {
    # TcpipNetbiosOptions: 0=default(DHCP), 1=enabled, 2=disabled
    switch ($nb.TcpipNetbiosOptions) {
        1       { $s = "ENABLED";        $col = "Red" }
        2       { $s = "Disabled";       $col = "Green" }
        default { $s = "Default (via DHCP - often enabled)"; $col = "Yellow" }
    }
    $nbList += [pscustomobject]@{ Adapter = $nb.Description; NetBIOS = $s }
    Write-Host ("[{0}] {1} -> NetBIOS: {2}" -f $(if($col -eq 'Green'){'OK'}else{'CHK'}), $nb.Description, $s) -ForegroundColor $col
}
$report.NetBIOS = $nbList
Write-Host "       To disable: set 'Disable NetBIOS over TCP/IP' in adapter WINS settings," -ForegroundColor Gray
Write-Host "       or per-adapter registry NetbiosOptions=2 under NetBT\Parameters\Interfaces." -ForegroundColor Gray

# --- 4. Listening TCP/UDP ports -------------------------------------------
Write-Section "Listening TCP / UDP Ports"

# Ports commonly considered risky/legacy when exposed
$riskyPorts = @{
    21   = "FTP (cleartext)";        23   = "Telnet (cleartext)"
    25   = "SMTP";                   69   = "TFTP"
    110  = "POP3 (cleartext)";       111  = "RPCbind/portmapper"
    135  = "MS RPC endpoint mapper"; 137  = "NetBIOS Name"
    138  = "NetBIOS Datagram";       139  = "NetBIOS Session (SMB over NetBIOS)"
    143  = "IMAP (cleartext)";       161  = "SNMP"
    445  = "SMB (EternalBlue vector)"; 512 = "rexec"
    513  = "rlogin";                 514  = "rsh/syslog"
    1433 = "MS SQL";                 1434 = "MS SQL browser (UDP)"
    3389 = "RDP (BlueKeep vector)";  5900 = "VNC"
}

function Show-Ports($conns, $proto) {
    Write-Host ""
    Write-Host " $proto listeners:" -ForegroundColor White
    $rows = foreach ($c in $conns) {
        $port = $c.LocalPort
        $procName = (Get-Process -Id $c.OwningProcess).ProcessName
        $flag = if ($riskyPorts.ContainsKey([int]$port)) { "RISKY: " + $riskyPorts[[int]$port] } else { "" }
        [pscustomobject]@{
            Proto   = $proto
            Local   = "$($c.LocalAddress):$port"
            PID     = $c.OwningProcess
            Process = $procName
            Note    = $flag
        }
    }
    $rows = $rows | Sort-Object { [int]($_.Local -split ':')[-1] } -Unique
    $rows | Format-Table -AutoSize | Out-String | Write-Host
    foreach ($r in $rows | Where-Object Note) {
        Write-Host ("   [FLAG] {0}  ->  {1}  ({2})" -f $r.Local, $r.Note, $r.Process) -ForegroundColor Red
    }
    return $rows
}

$tcp = Get-NetTCPConnection -State Listen
$udp = Get-NetUDPEndpoint
$report.TCP_Listeners = Show-Ports $tcp "TCP"
$report.UDP_Listeners = Show-Ports $udp "UDP"

# --- Summary ---------------------------------------------------------------
Write-Section "Summary"
Write-Host "Hostname : $env:COMPUTERNAME"
Write-Host "Scan time: $(Get-Date -Format u)"
Write-Host ""
Write-Host "Reminder: this audits LOCAL exposure only. For real CVE detection run a"
Write-Host "vulnerability scanner (nmap --script vuln, OpenVAS, Nessus) against the host."

if ($AsJson) {
    Write-Host ""
    $report | ConvertTo-Json -Depth 5
}
