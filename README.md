# RDP-TrustFix

PowerShell script to suppress security warnings when opening `.rdp` files on **Windows 11** (post-2024 updates).

## The Problem

Recent Windows 11 security updates introduced two blocking dialogs every time you open an RDP file:

1. **"Do you trust this RDP connection?"** — a new consent prompt added to mitigate [CVE-2024-49105](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49105)
2. **"Unknown publisher / Caution: remote connection"** — shown when the `.rdp` file is not digitally signed

Both dialogs require manual confirmation on every launch, which is disruptive in environments with many managed RDP connections.

## Solution

`Remove-RdpWarnings.ps1` addresses both warnings without Group Policy or domain membership:

| Warning | Fix applied |
|---|---|
| Launch consent dialog | `RdpLaunchConsentAccepted` registry key |
| Unknown publisher | Per-server whitelist + optional certificate signing |

## Usage

```powershell
# Open interactive menu (default — no parameters)
.\Remove-RdpWarnings.ps1

# Show inline help
.\Remove-RdpWarnings.ps1 -Help

# Suppress consent dialog only (registry fix, no prompts)
.\Remove-RdpWarnings.ps1 -NoMenu

# Consent fix + add all servers from .rdp files to trusted list
.\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP"

# Full fix: auto-scan common locations + sign all .rdp files found
.\Remove-RdpWarnings.ps1 -AutoScan -SignFiles

# Full fix: specific folder + auto-scan combined + signing
.\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP" -AutoScan -SignFiles

# Custom certificate subject name
.\Remove-RdpWarnings.ps1 -AutoScan -SignFiles -CertSubject "MyCompany RDP"

# Revert all registry changes
.\Remove-RdpWarnings.ps1 -Undo
```

### Interactive menu

Running the script with no parameters opens a numbered menu:

```
  [1] Registry only                         Suppress consent dialog (fastest, no .rdp files needed)
  [2] Registry + specific folder            You provide the folder path — adds servers to whitelist
  [3] Registry + auto-scan                  Scan Desktop/Documents/Downloads/OneDrive automatically
  [4] Full fix — specific folder + sign     Folder path, cert creation, .rdp file signing
  [5] Full fix — auto-scan + sign           Auto-scan all locations, cert creation, .rdp file signing
  [6] Full fix — auto-scan + folder + sign  Combined: auto-scan AND specific folder + signing
  [U] Undo                                  Revert all registry changes made by this script
  [H] Help                                  Show full help and documentation
  [Q] Quit
```

## What the script does

### Mode 1 — Registry only
Sets two HKCU registry values under `Software\Microsoft\Terminal Server Client`:
- `RdpLaunchConsentAccepted = 1`
- `RedirectionWarningDialogVersion = 1`

### Mode 2 — Per-server trust (`-RdpFolder` / `-AutoScan`)
Parses all `.rdp` files found, extracts hostnames, and adds each one to
`HKCU\...\Terminal Server Client\Servers\<hostname>`. Suppresses the unknown-publisher warning per host.

**Auto-scan locations:** Desktop, Public Desktop, Documents, Downloads, OneDrive (personal + business), Network Shortcuts.

### Mode 3 — Certificate signing (`-SignFiles`)
1. Creates (or reuses) a self-signed code-signing certificate in `CurrentUser\My` valid for 10 years
2. Adds the certificate to `CurrentUser\TrustedPublisher`
3. Registers the certificate thumbprint in `HKCU\Software\Policies\Microsoft\Windows NT\Terminal Services\TrustedCertThumbprints`
4. Signs every `.rdp` file found using `RDPSign.exe`

## Requirements

- Windows 10 / 11
- PowerShell 5.1 or later
- `RDPSign.exe` (present by default in `%SystemRoot%\System32`) — only needed for `-SignFiles`
- No administrator rights required

## Undo

Run with `-Undo` to remove all registry keys written by this script. Signed `.rdp` files are not modified during undo.

## References

- [Security warnings when opening RDP files in Windows](https://woshub.com/security-warnings-opening-rdp-files-windows/)
- [CVE-2024-49105 — Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49105)
- [RDPSign.exe documentation — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rdpsign)
