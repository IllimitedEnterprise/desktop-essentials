# Windows Desktop Hardening & Threat-Hunt Runbook
## Hand this content or file to your System Admin Agent, with elevated permissions.

> **Audience:** an autonomous agent tasked with assessing and hardening a Windows 10/11 desktop.
> **Goal:** lock down remote access, remove bloat, and run a manual threat hunt (processes, persistence, DLL injection) **without relying solely on Windows Defender's verdict**.
> **Environment assumed:** Windows 11, PowerShell 5.1, single primary interactive user. Adapt paths/usernames as needed.

---

## 0. Operating principles (read first)

1. **Read-only before write.** Always run the *collection/recon* phase first, analyze, and only then change anything.
2. **Confirm before anything hard to reverse.** Uninstalling apps and disabling services/sharing are hard to undo. Present findings and get explicit scope confirmation before destructive actions.
3. **Don't trust the AV "all clear."** Defender being green is a data point, not proof. Hunt manually.
4. **Distinguish "disabled" from "secure."** A service that is *Stopped* but *Manual* can be restarted; set it to *Disabled* to actually close the vector.
5. **Know the false positives** (Section 7) before raising alarms. Most "NotSigned" hits on a healthy machine are benign (catalog-signed Store apps, .NET NGEN images).

### 0.1 Elevation pattern (critical)

Most hardening needs Administrator. If your shell runs **sandboxed**, a normal `Start-Process -Verb RunAs` may be **auto-cancelled** before the UAC prompt reaches the user (error: *"operação foi cancelada pelo utilizador" / "operation was cancelled by the user"*). Workarounds:

- Run the elevation launcher with the sandbox disabled so the **real UAC prompt** appears for the user to approve.
- Put the privileged work in a `.ps1`, launch it elevated, and have it **write results to a temp `.out` file** you then read back (elevated stdout is not captured directly):

```powershell
$p = Start-Process powershell.exe -Verb RunAs -ArgumentList `
  '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\path\to\script.ps1' `
  -PassThru -Wait
# script.ps1 writes its findings to C:\...\out.txt ; read that file afterwards
```

### 0.2 Localization caveat

On non-English Windows (e.g. **Portuguese**), built-in firewall **`-DisplayGroup`** names ("File and Printer Sharing", "Remote Desktop") will **not match** English strings. Use **explicit port rules** instead of group names.

---

## 1. Recon / baseline (read-only)

Run these first and record the output. None of them change state.

### 1.1 Antivirus posture
```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
  AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge, NISEnabled, BehaviorMonitorEnabled, TamperProtected
Get-MpThreatDetection   # threat history; empty = none recorded
```
- `FullScanAge = 4294967295` means **a full scan has never run** — kick one off (Section 6).

### 1.2 Remote-access surface
```powershell
# RDP (1 = denied/disabled)
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
# Remote Assistance (0/absent = off)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -EA SilentlyContinue).fAllowToGetHelp
# Remote-capable services
Get-Service WinRM,RemoteRegistry,TermService,SessionEnv,UmRdpService,sshd -EA SilentlyContinue |
  Select-Object Name,Status,StartType
# Firewall must be ON for all profiles
Get-NetFirewallProfile | Select-Object Name,Enabled
# Everything currently listening for inbound
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort -Unique
```

### 1.3 Installed software inventory
```powershell
# Store (Appx) packages
Get-AppxPackage | Select-Object Name, PackageFullName
# Win32 desktop programs (all three uninstall hives)
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $paths -EA SilentlyContinue | Where-Object DisplayName |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName -Unique
```

---

## 2. Remote-access hardening (requires elevation)

Run as Administrator (see 0.1). Idempotent — safe to re-run.

```powershell
# --- WinRM / PowerShell remoting ---
Stop-Service WinRM -Force -EA SilentlyContinue
Set-Service  WinRM -StartupType Disabled

# --- RDP ---
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
Stop-Service TermService -Force -EA SilentlyContinue
Set-Service  TermService -StartupType Disabled

# --- Remote Registry ---
Stop-Service RemoteRegistry -Force -EA SilentlyContinue
Set-Service  RemoteRegistry -StartupType Disabled

# --- Remote Assistance ---
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0

# --- Firewall ON, all profiles ---
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### 2.1 SMB / file & printer sharing (AGGRESSIVE — only if the user never shares files/printers on the LAN)
```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Stop-Service LanmanServer -Force -EA SilentlyContinue
Set-Service  LanmanServer -StartupType Disabled
```
> ⚠️ This also disables administrative shares (`\\host\C$`). Confirm with the user first.

### 2.2 Explicit firewall block rules (immediate closure)
Disabling the SMB service does **not** release ports **139/445** until a **reboot** (the sockets are held by the kernel SMB driver). Add explicit blocks so they're closed immediately, and as defense-in-depth:

```powershell
$blocks = @(
  @{N='CC-Block Remote SMB (445)';     P=445},
  @{N='CC-Block Remote NetBIOS (139)'; P=139},
  @{N='CC-Block Remote RDP (3389)';    P=3389},
  @{N='CC-Block Remote WinRM (5985)';  P=5985},
  @{N='CC-Block Remote WinRM-S (5986)';P=5986}
)
foreach ($b in $blocks) {
  New-NetFirewallRule -DisplayName $b.N -Direction Inbound -Action Block `
    -Protocol TCP -LocalPort $b.P -Profile Any | Out-Null
}
```
> Do **not** rely on `Disable-NetFirewallRule -DisplayGroup '...'` on localized Windows — the English group names won't match (see 0.2). Explicit port rules above are language-independent.

### 2.3 Verify
```powershell
Get-Service WinRM,RemoteRegistry,TermService,LanmanServer | Select Name,Status,StartType   # expect Stopped + Disabled
Get-NetTCPConnection -State Listen | ? LocalPort -in 139,445,3389,5985,5986                 # expect none after reboot
```

---

## 3. Bloatware removal (per-user — no elevation needed)

Removing Appx packages for the current user does **not** need admin. **Confirm the category list with the user first.** All are reinstallable from the Microsoft Store.

```powershell
$targets = @(
  # Xbox suite (safe if the user doesn't game on this PC)
  'Microsoft.GamingApp','Microsoft.XboxGamingOverlay','Microsoft.Xbox.TCUI',
  'Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay',
  # Phone Link ("mobile links")
  'Microsoft.YourPhone',
  # Bing widgets
  'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.BingSearch',
  # Misc
  'Microsoft.MicrosoftSolitaireCollection','Clipchamp.Clipchamp',
  'Microsoft.GetHelp','Microsoft.WindowsFeedbackHub','Microsoft.Todos'
)
foreach ($n in $targets) {
  $pkg = Get-AppxPackage -Name $n -EA SilentlyContinue
  if ($pkg) { $pkg | Remove-AppxPackage; "REMOVED $n" } else { "SKIP    $n (absent)" }
}
```

**Do NOT blanket-remove** (each has side effects or may be in use):
- `Microsoft.Windows.PeopleExperienceHost`, `Microsoft.XboxGameCallableUI` — system components.
- `MSTeams`, `Microsoft.ZuneMusic` (Media Player) — leave unless the user confirms they're unused.
- To uninstall for **all** users / prevent re-provisioning on new accounts, additionally use `Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage` (requires elevation) — only with explicit consent.

---

## 4. Manual threat hunt (read-only collection, then analyze)

Run the collection elevated so you can read **all** processes' modules and HKLM persistence. Write everything to a `.out` file and analyze. The full collection script is in **Appendix A**; the checks it performs:

### 4.1 Running processes
```powershell
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
```
For each unique `ExecutablePath`: `Get-AuthenticodeSignature`. **Flag** if:
- signature status ≠ `Valid`, **and** signer is not Microsoft/Windows, **or**
- the path is in a user-writable / odd location: `\Temp\`, `\AppData\Local\Temp`, `\Users\Public`, `\Windows\Temp`, `\Downloads\`, `$Recycle`.

### 4.2 Network — external connections
```powershell
Get-NetTCPConnection -State Established |
  ? RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80|::)' |
  % { $p=Get-Process -Id $_.OwningProcess -EA SilentlyContinue
      "{0}:{1} PID {2} {3}" -f $_.RemoteAddress,$_.RemotePort,$_.OwningProcess,$p.ProcessName }
```
- Reverse-resolve unknown IPs: `(Resolve-DnsName <ip> -Type PTR).NameHost`.
- **Non-standard high ports + persistent sockets** are often legitimate **WebSocket data feeds** (trading platforms, chat, live data) — see 7.4 before alarming.

### 4.3 Persistence / autostart vectors
- **Run keys:** `HKLM` + `HKCU` `...\CurrentVersion\Run` and `RunOnce` (+ `Wow6432Node`).
- **Startup folders:** `%APPDATA%\...\Start Menu\Programs\Startup`, `%ProgramData%\...\Startup`.
- **Scheduled tasks:** `Get-ScheduledTask | ? {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'}` — scrutinize tasks whose action is a **script** (`.cmd/.ps1/.vbs/.js`) or lives in a user folder.
- **Services:** non-Microsoft / unsigned binaries (resolve `PathName`, check signature).
- **Winlogon:** `Shell` must be `explorer.exe`, `Userinit` must be `...\userinit.exe,`.
- **Image File Execution Options:** any `Debugger` value = hijack; check `GlobalFlag`/`SilentProcessExit`.

### 4.4 DLL / code-injection vectors ("pass as a ghost / regain access")
- **AppInit_DLLs** (`...\Windows NT\CurrentVersion\Windows`, both native + `Wow6432Node`): value should be **empty** and `LoadAppInit_DLLs = 0`.
- **LSA packages** (`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`): `Notification Packages` (default `scecli`), `Security Packages`, `Authentication Packages` (default `msv1_0`) — extra entries = possible password filter / SSP backdoor.
- **COM hijacking:** `HKCU:\SOFTWARE\Classes\CLSID\*\InprocServer32` overriding HKLM — flag any DLL in a user-writable/odd path (OneDrive's `FileSyncShell64.dll` etc. are expected).
- **Loaded-module sweep (the real "ghost DLL" check):** enumerate every process's `.Modules`; for each `FileName` check the signature **and existence on disk**. Flag:
  - status ≠ `Valid`, or path in a suspicious location, **or**
  - **PHANTOM** = module loaded from a path with **no file on disk** → hallmark of process hollowing / module ghosting.
- **KnownDLLs** tampering (`HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`).

### 4.5 Fileless & boot persistence
- **WMI event subscriptions:**
  ```powershell
  Get-CimInstance -Namespace root\subscription -Class __EventFilter
  Get-CimInstance -Namespace root\subscription -Class __EventConsumer   # ActiveScript/CommandLine consumers = red flag
  Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding
  ```
  (The default `SCM Event Log Filter/Consumer` pair is benign.)
- **BootExecute:** `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager` → should be exactly `autocheck autochk *`.

### 4.6 Browser sanity (if a suspicious connection traces to a browser)
- **Extensions** are the usual culprit: `...\Chrome\User Data\Default\Extensions\*` — read each `manifest.json` `name`. (`ghbmnnjooekpmoecnnnilnnbdlolhkhi` = Google Docs Offline, `nmmhkkegccagdldgiimedpiccmgmieda` = Google Wallet/Web Store are built-in defaults.)
- **Startup pages / homepage / default search:** read `...\Default\Preferences` JSON (`session.startup_urls`, `homepage`, `default_search_provider_data`).
- A domain **not** in `History`/`Sessions` but actively connected = a **sub-resource** (ad, embedded player, WebSocket) of an open page, or an incognito tab — trace the parent tab via **Chrome Task Manager (Shift+Esc)**.

---

## 5. Baseline findings on a HEALTHY machine (what "already secure" looks like)

Use these as the expected-good reference when you report:

| Area | Secure baseline |
|---|---|
| Defender | Real-time ON, signatures current, 0 threats, Tamper Protection ON |
| RDP | `fDenyTSConnections = 1` |
| Remote Assistance | not enabled / `0` |
| RemoteRegistry | Stopped **and** Disabled |
| OpenSSH server (`sshd`) | not installed |
| Firewall | Enabled on Domain/Private/Public |
| Listeners | only RPC (135, 49xxx), SMB (139/445), Delivery Optimization (7680), local-only loopback ports |
| Run keys | `SecurityHealth`, `OneDrive`, Edge auto-launch only |
| Winlogon | `Shell=explorer.exe`, `Userinit=...userinit.exe,` |
| AppInit_DLLs | empty, `LoadAppInit_DLLs=0` |
| IFEO | no `Debugger` entries |
| LSA | `Notification=scecli`, `Authentication=msv1_0`, `Security` empty |
| COM (HKCU) | only OneDrive shell extensions + system `shell32.dll` |
| WMI subscription | only `SCM Event Log Filter/Consumer` |
| BootExecute | `autocheck autochk *` |
| Scheduled tasks (non-MS) | vendor updaters only (Edge, Google, OneDrive) + the user's own tools |

---

## 6. Post-assessment

```powershell
# Full antivirus scan (run in background; can take 30-90 min). Run the cmdlet DIRECTLY as the
# long-running task — do NOT wrap it in Start-Job inside a short-lived launcher, or it dies with the launcher.
Start-MpScan -ScanType FullScan
```
- **Reboot** to fully release any now-disabled SMB sockets (139/445).
- Re-run Section 1.2 + 2.3 after reboot to confirm the surface stayed closed.

---

## 7. Known false positives — do NOT raise these as threats

1. **Catalog-signed Store apps** (`C:\Program Files\WindowsApps\...`): `Get-AuthenticodeSignature` reports **`NotSigned`** because the signature lives in a package catalog, not embedded. Examples seen as benign: Intel Arc Graphics (`AppUp.IntelArcSoftware`), `WidgetService`, `MicrosoftStartFeedProvider`. Verify the package publisher instead.
2. **.NET NGEN native images** (`C:\WINDOWS\assembly\NativeImages_v4.*\...\*.ni.dll`): always unsigned by design. Loaded by any .NET process (incl. PowerShell). Benign.
3. **OneDrive shell extensions** in HKCU `InprocServer32` (`FileSyncShell64.dll`, `FileCoAuthLib64.dll` under `AppData\Local\Microsoft\OneDrive\...`): expected, signed Microsoft.
4. **Persistent connections on non-standard high ports** from a browser/app: commonly **legitimate WebSocket feeds** — trading/prop-firm platforms (live positions), chat, market data — often routed through shared VPS/CDN hosting. A domain looking "shady" on Scamadviser/urlquery may just be **shared infrastructure** abused by *other* tenants. Confirm with the user what app/site was open before concluding malice.
5. **`SCM Event Log Filter/Consumer`** WMI pair: default Windows component, not persistence.

---

## 8. Decision checklist before acting

- [ ] Recon (Section 1) complete and recorded
- [ ] User confirmed **which app categories** to remove
- [ ] User confirmed **SMB aggressive** step (breaks LAN file/printer sharing) — yes/no
- [ ] Elevation obtained (UAC approved)
- [ ] Hardening applied + verified (2.3)
- [ ] Threat hunt collected + analyzed against Section 5 baseline & Section 7 false positives
- [ ] Any anomaly explained or escalated to the user
- [ ] Full scan started; reboot recommended

---

## Appendix A — Threat-hunt collection script (`hunt.ps1`)

Run elevated; writes to `C:\...\hunt.out`. Covers processes, external network, run keys, startup, Winlogon/AppInit/IFEO/LSA, HKCU COM hijacks, non-MS services, non-MS scheduled tasks, WMI persistence, BootExecute.

```powershell
$log = "$env:TEMP\hunt.out"; $sb = New-Object System.Text.StringBuilder
function W($t){ [void]$sb.AppendLine($t) }
$susp = '\\Temp\\|\\AppData\\Local\\Temp|\\Users\\Public|\\Windows\\Temp|\\Downloads\\|\$Recycle'
$cache=@{}
function SigOf($p){ if(-not $p){return 'EMPTY'}; if(-not(Test-Path -LiteralPath $p)){return 'PHANTOM(no file)'}
  if($cache[$p]){return $cache[$p]}
  try{$s=Get-AuthenticodeSignature -LiteralPath $p -EA Stop
      $r="$($s.Status)|$($s.SignerCertificate.Subject -replace '.*?CN=([^,]+).*','$1')"}catch{$r='ERR'}
  $cache[$p]=$r;$r }

W '## PROCESSES (non-MS / unsigned / odd location)'
Get-CimInstance Win32_Process | % { $p=$_.ExecutablePath; if(-not $p){return}
  $s=SigOf $p; if(($p -match $susp) -or ($s -notmatch 'Valid\|.*(Microsoft|Windows)')){
    W ("PID {0} PPID {1} {2}`n   SIG {3}`n   CMD {4}" -f $_.ProcessId,$_.ParentProcessId,$p,$s,$_.CommandLine) } }

W "`n## NETWORK (external established)"
Get-NetTCPConnection -State Established -EA SilentlyContinue |
  ? RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80|::)' |
  % { $o=Get-Process -Id $_.OwningProcess -EA SilentlyContinue
      W ("{0}:{1} PID {2} {3}" -f $_.RemoteAddress,$_.RemotePort,$_.OwningProcess,$o.ProcessName) }

W "`n## RUN KEYS"
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' |
  % { if(Test-Path $_){ (Get-ItemProperty $_).PSObject.Properties | ? Name -notmatch '^PS' |
      % { W ("{0} = {1}" -f $_.Name,$_.Value) } } }

W "`n## STARTUP FOLDERS"
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |
  % { if(Test-Path $_){ Get-ChildItem $_ -Force | ? Name -ne 'desktop.ini' | % { W ("{0}\{1}" -f $_.DirectoryName,$_.Name) } } }

W "`n## INJECTION (Winlogon/AppInit/IFEO/LSA)"
$wl=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
W ("Shell={0}  Userinit={1}" -f $wl.Shell,$wl.Userinit)
'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows' |
  % { if(Test-Path $_){ $v=Get-ItemProperty $_; W ("AppInit='{0}' Load={1}" -f $v.AppInit_DLLs,$v.LoadAppInit_DLLs) } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -EA SilentlyContinue |
  % { $d=Get-ItemProperty $_.PSPath; if($d.Debugger){ W ("IFEO {0} -> {1}" -f $_.PSChildName,$d.Debugger) } }
$lsa=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
W ("LSA Notify={0} | Security={1} | Auth={2}" -f ($lsa.'Notification Packages' -join ','),($lsa.'Security Packages' -join ','),($lsa.'Authentication Packages' -join ','))

W "`n## COM HIJACK (HKCU InprocServer32)"
if(Test-Path 'HKCU:\SOFTWARE\Classes\CLSID'){ Get-ChildItem 'HKCU:\SOFTWARE\Classes\CLSID' -EA SilentlyContinue |
  % { $ip=Join-Path $_.PSPath 'InprocServer32'; if(Test-Path $ip){ $v=(Get-ItemProperty $ip).'(default)'; if($v){ W ("{0} -> {1}" -f $_.PSChildName,$v) } } } }

W "`n## SERVICES (non-MS / unsigned)"
Get-CimInstance Win32_Service | ? PathName | % {
  $bin=($_.PathName -replace '^"([^"]+)".*','$1' -replace '^([^\s]+\.exe).*','$1'); $s=SigOf $bin
  if($s -notmatch 'Valid\|.*(Microsoft|Windows)'){ W ("{0} [{1}] {2} :: {3}" -f $_.Name,$_.State,$_.PathName,$s) } }

W "`n## SCHEDULED TASKS (non-MS, enabled)"
Get-ScheduledTask -EA SilentlyContinue | ? {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'} | % {
  $a=($_.Actions | % { "$($_.Execute) $($_.Arguments)" }) -join ' ; '; W ("{0}{1} -> {2}" -f $_.TaskPath,$_.TaskName,$a) }

W "`n## WMI PERSISTENCE"
Get-CimInstance -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue | % { W ("FILTER {0} :: {1}" -f $_.Name,$_.Query) }
Get-CimInstance -Namespace root\subscription -Class __EventConsumer -EA SilentlyContinue | % { W ("CONSUMER {0} :: {1}{2}" -f $_.Name,$_.CommandLineTemplate,$_.ScriptText) }

W "`n## BOOT"
W ("BootExecute = {0}" -f ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute).BootExecute -join ' | '))

$sb.ToString() | Out-File $log -Encoding utf8; "DONE" | Out-File $log -Append -Encoding utf8
```

## Appendix B — Loaded-module ("ghost DLL") sweep (`dllhunt.ps1`)

Run elevated; flags any loaded module that is unsigned/invalid, loaded from a suspicious location, or **PHANTOM** (no file on disk).

```powershell
$log="$env:TEMP\dllhunt.out"; $sb=New-Object System.Text.StringBuilder
function W($t){ [void]$sb.AppendLine($t) }
$susp='\\Temp\\|\\AppData\\Local\\Temp|\\Users\\Public|\\Windows\\Temp|\\Downloads\\|\$Recycle'; $c=@{}
function SigOf($p){ if(-not $p){return 'EMPTY'}; if(-not(Test-Path -LiteralPath $p)){return 'PHANTOM(no file on disk)'}
  if($c[$p]){return $c[$p]}; try{$s=Get-AuthenticodeSignature -LiteralPath $p -EA Stop
    $r="$($s.Status)|$($s.SignerCertificate.Subject -replace '.*?CN=([^,]+).*','$1')"}catch{$r='ERR'}; $c[$p]=$r;$r }
$n=0
foreach($pr in Get-Process){ try{$m=$pr.Modules}catch{continue}; if(-not $m){continue}
  foreach($x in $m){ $f=$x.FileName; if(-not $f){continue}; $s=SigOf $f
    if(($s -notlike 'Valid*') -or ($f -match $susp)){ W ("{0}(PID {1}) {2}`n   SIG {3}" -f $pr.ProcessName,$pr.Id,$f,$s); $n++ } } }
if($n -eq 0){ W 'CLEAN: no unsigned/invalid/phantom/odd-location modules.' }
W ("Total flagged: {0}" -f $n)
$sb.ToString() | Out-File $log -Encoding utf8; "DONE" | Out-File $log -Append -Encoding utf8
```
> **Expected noise to ignore (Section 7):** `*.ni.dll` under `assembly\NativeImages`, catalog-signed `WindowsApps` binaries, vendor `.node`/native add-ins from signed apps. **Investigate:** any `PHANTOM`, or any module under `\Temp`, `\Downloads`, `\Users\Public`, or an unexpected `AppData` path.

---

*Generated from a live assessment. Adapt usernames/paths and always confirm destructive scope with the user before executing Sections 2.1 and 3.*

UNDER DEVELOPMENT
# 1. Preview everything it would do (safe):
.\Harden-SmbNetbiosExposure.ps1

# 2. Apply core hardening:
.\Harden-SmbNetbiosExposure.ps1 -Apply

# 3. Also disable legacy services:
.\Harden-SmbNetbiosExposure.ps1 -Apply -IncludeServices

# Harden AND reboot into the recovery menu afterward:
.\Harden-SmbNetbiosExposure.ps1 -Apply -RebootToRecovery
