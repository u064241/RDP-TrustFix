#Requires -Version 5.1
<#
.SYNOPSIS
    Removes security warnings when opening RDP files in Windows 11.

.DESCRIPTION
    Handles two distinct warnings:
      1. "Do you trust this RDP connection?" - new consent dialog (post-2024 updates)
      2. "Unknown publisher" - unsigned RDP file warning

    Run without parameters to open the interactive menu.

.PARAMETER RdpFolder
    Path to a specific folder containing .rdp files. Can be combined with -AutoScan.

.PARAMETER AutoScan
    Automatically scan common user locations for .rdp files:
    Desktop, Documents, Downloads, OneDrive, Network Shortcuts.
    Can be combined with -RdpFolder.

.PARAMETER SignFiles
    Sign all .rdp files found. Requires -RdpFolder or -AutoScan.

.PARAMETER CertSubject
    Subject name for the self-signed certificate. Default: "RDP Trusted Publisher"

.PARAMETER Undo
    Reverts all registry changes made by this script.

.PARAMETER Help
    Shows this help screen.

.EXAMPLE
    # Open interactive menu
    .\Remove-RdpWarnings.ps1

.EXAMPLE
    # Suppress consent dialog only (registry fix, no files needed)
    .\Remove-RdpWarnings.ps1 -NoMenu

.EXAMPLE
    # Consent fix + trust servers in a specific folder
    .\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP"

.EXAMPLE
    # Full fix: auto-scan all common locations, sign every .rdp found
    .\Remove-RdpWarnings.ps1 -AutoScan -SignFiles

.EXAMPLE
    # Full fix: specific folder + auto-scan combined
    .\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP" -AutoScan -SignFiles

.EXAMPLE
    # Revert all registry changes
    .\Remove-RdpWarnings.ps1 -Undo
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RdpFolder,
    [switch]$AutoScan,
    [switch]$SignFiles,
    [string]$CertSubject = "RDP Trusted Publisher",
    [switch]$Undo,
    [switch]$NoMenu,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Output helpers

function Write-Step { param([string]$m); Write-Host "  >> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m); Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m); Write-Host "  [!!] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m); Write-Host "  [ERR] $m" -ForegroundColor Red }

function Write-Banner {
    Write-Host @"
==============================================
  Remove-RdpWarnings.ps1  v1.1
  Windows 11 RDP security warning suppressor
==============================================
"@ -ForegroundColor White
}

#endregion

#region Help

function Show-Help {
    Write-Banner
    Write-Host @"
DESCRIPTION
  Suppresses Windows 11 security warnings when opening .rdp files.
  Targets two distinct dialogs:
    1. "Do you trust this RDP connection?" (CVE-2024-49105 consent dialog)
    2. "Unknown publisher"  (unsigned .rdp file warning)

SYNTAX
  .\Remove-RdpWarnings.ps1  [options]

OPTIONS
  (none)              Open the interactive menu
  -NoMenu             Registry-only fix, no prompts
  -RdpFolder <path>   Process .rdp files in a specific folder (recursive)
  -AutoScan           Scan common locations automatically:
                        Desktop, Documents, Downloads, OneDrive,
                        Network Shortcuts, Public Desktop
  -SignFiles          Create/reuse a self-signed cert and sign all .rdp files
                      Requires -RdpFolder or -AutoScan
  -CertSubject <name> Certificate subject name (default: "RDP Trusted Publisher")
  -Undo               Remove all registry keys written by this script
  -Help               Show this help screen

MODES (in increasing depth)
  1. Registry only     Fast, no files needed. Fixes the consent dialog.
  2. + Per-server      Adds each RDP host to the per-user whitelist.
  3. + Sign            Creates a cert, signs .rdp files, registers as trusted
                       publisher. Fully eliminates the "Unknown publisher" warning.

EXAMPLES
  .\Remove-RdpWarnings.ps1
  .\Remove-RdpWarnings.ps1 -NoMenu
  .\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP"
  .\Remove-RdpWarnings.ps1 -AutoScan -SignFiles
  .\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP" -AutoScan -SignFiles
  .\Remove-RdpWarnings.ps1 -Undo

NO ADMIN REQUIRED  (certificate is created in CurrentUser store)
"@ -ForegroundColor Gray

    Write-Host ""
}

#endregion

#region Interactive menu

function Invoke-Menu {
    Write-Banner
    Write-Host "  Select an option:`n" -ForegroundColor White

    $options = @(
        [PSCustomObject]@{ Key = '1'; Label = 'Registry only';                       Desc = 'Suppress consent dialog (fastest, no .rdp files needed)' }
        [PSCustomObject]@{ Key = '2'; Label = 'Registry + specific folder';          Desc = 'You provide the folder path — adds servers to whitelist' }
        [PSCustomObject]@{ Key = '3'; Label = 'Registry + auto-scan';                Desc = 'Scan Desktop/Documents/Downloads/OneDrive automatically' }
        [PSCustomObject]@{ Key = '4'; Label = 'Full fix — specific folder + sign';   Desc = 'Folder path, cert creation, .rdp file signing' }
        [PSCustomObject]@{ Key = '5'; Label = 'Full fix — auto-scan + sign';         Desc = 'Auto-scan all locations, cert creation, .rdp file signing' }
        [PSCustomObject]@{ Key = '6'; Label = 'Full fix — auto-scan + folder + sign';Desc = 'Combined: auto-scan AND specific folder + signing' }
        [PSCustomObject]@{ Key = 'U'; Label = 'Undo';                                Desc = 'Revert all registry changes made by this script' }
        [PSCustomObject]@{ Key = 'H'; Label = 'Help';                                Desc = 'Show full help and documentation' }
        [PSCustomObject]@{ Key = 'Q'; Label = 'Quit';                                Desc = '' }
    )

    foreach ($opt in $options) {
        $keyColor = if ($opt.Key -eq 'U') { 'Yellow' } elseif ($opt.Key -eq 'Q') { 'DarkGray' } else { 'Cyan' }
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host $opt.Key -NoNewline -ForegroundColor $keyColor
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-38}" -f $opt.Label) -NoNewline -ForegroundColor White
        if ($opt.Desc) {
            Write-Host "  $($opt.Desc)" -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
    }

    Write-Host ""
    $choice = Read-Host "  Choice"

    switch ($choice.Trim().ToUpper()) {
        '1' { return @{ RdpFolder = $null; AutoScan = $false; SignFiles = $false; Undo = $false } }
        '2' {
            $folder = Read-Host "  Enter folder path"
            return @{ RdpFolder = $folder.Trim(); AutoScan = $false; SignFiles = $false; Undo = $false }
        }
        '3' { return @{ RdpFolder = $null; AutoScan = $true; SignFiles = $false; Undo = $false } }
        '4' {
            $folder = Read-Host "  Enter folder path"
            return @{ RdpFolder = $folder.Trim(); AutoScan = $false; SignFiles = $true; Undo = $false }
        }
        '5' { return @{ RdpFolder = $null; AutoScan = $true; SignFiles = $true; Undo = $false } }
        '6' {
            $folder = Read-Host "  Enter folder path"
            return @{ RdpFolder = $folder.Trim(); AutoScan = $true; SignFiles = $true; Undo = $false }
        }
        'U' { return @{ RdpFolder = $null; AutoScan = $false; SignFiles = $false; Undo = $true } }
        'H' { Show-Help; exit 0 }
        'Q' { exit 0 }
        default {
            Write-Warn "Invalid choice: $choice"
            exit 1
        }
    }
}

#endregion

#region Registry helpers

function Set-RegistryValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

function Remove-RegistryValue {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) { Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue }
}

#endregion

#region Undo

function Invoke-Undo {
    Write-Host "`nReverting RDP trust registry settings..." -ForegroundColor Magenta

    $tscPath = 'HKCU:\Software\Microsoft\Terminal Server Client'
    Write-Step "Removing RdpLaunchConsentAccepted"
    Remove-RegistryValue -Path $tscPath -Name 'RdpLaunchConsentAccepted'

    Write-Step "Removing RedirectionWarningDialogVersion"
    Remove-RegistryValue -Path $tscPath -Name 'RedirectionWarningDialogVersion'

    Write-Step "Removing trusted RDP publisher thumbprints (HKCU policy)"
    $policyPath = 'HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    Remove-RegistryValue -Path $policyPath -Name 'TrustedCertThumbprints'

    Write-Ok "Undo complete. Restart mstsc.exe if open."
}

#endregion

#region Warning 1 — Launch consent dialog

function Set-LaunchConsent {
    Write-Host "`n[1] Suppressing launch consent dialog..." -ForegroundColor Magenta

    $tscPath = 'HKCU:\Software\Microsoft\Terminal Server Client'
    Write-Step "RdpLaunchConsentAccepted = 1"
    Set-RegistryValue -Path $tscPath -Name 'RdpLaunchConsentAccepted' -Value 1

    # Keeps the warning dialog at version 1 (suppresses newer, stricter prompts)
    Write-Step "RedirectionWarningDialogVersion = 1"
    Set-RegistryValue -Path $tscPath -Name 'RedirectionWarningDialogVersion' -Value 1

    Write-Ok "Launch consent dialog suppressed."
}

#endregion

#region RDP file discovery

function Get-AutoScanLocations {
    $locations = @(
        "$env:USERPROFILE\Desktop",
        "$env:PUBLIC\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA\Microsoft\Windows\Network Shortcuts"
    )

    if ($env:OneDrive -and (Test-Path $env:OneDrive)) {
        $locations += $env:OneDrive
    }

    # OneDrive for Business (variable name, e.g. "OneDrive - Contoso")
    Get-ChildItem "$env:USERPROFILE" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'OneDrive*' -and $_.FullName -ne $env:OneDrive } |
        ForEach-Object { $locations += $_.FullName }

    return $locations | Where-Object { Test-Path $_ } | Select-Object -Unique
}

function Get-RdpFileList {
    param([string[]]$Folders)

    $seen  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($folder in $Folders) {
        Get-ChildItem -Path $folder -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { if ($seen.Add($_.FullName)) { $files.Add($_) } }
    }

    return $files
}

#endregion

#region Warning 2 — Per-server trust

function Get-RdpServers {
    param([System.Collections.Generic.List[System.IO.FileInfo]]$Files)

    $servers = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $Files) {
        $content  = Get-Content $file.FullName -ErrorAction SilentlyContinue
        $hostLine = $content | Where-Object { $_ -match '^full address:s:(.+)$' } | Select-Object -First 1
        if ($hostLine -match '^full address:s:(.+)$') {
            $srv = $Matches[1].Trim() -replace ':\d+$', ''
            if ($srv -and -not $servers.Contains($srv)) {
                $servers.Add($srv)
                Write-Step "Found server: $srv  ($($file.Name))"
            }
        }
    }

    return $servers
}

function Set-TrustedServers {
    param([System.Collections.Generic.List[string]]$Servers)

    if (-not $Servers -or $Servers.Count -eq 0) {
        Write-Warn "No servers found in .rdp files — skipping per-server trust."
        return
    }

    Write-Host "`n[2a] Adding servers to per-user trusted list..." -ForegroundColor Magenta

    foreach ($server in $Servers) {
        $serverPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers\$server"
        Write-Step "Trusting: $server"
        if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
        # UsernameHint presence alone is sufficient to suppress the unknown-publisher warning
        if (-not (Get-ItemProperty -Path $serverPath -Name 'UsernameHint' -ErrorAction SilentlyContinue)) {
            Set-ItemProperty -Path $serverPath -Name 'UsernameHint' -Value '' -Type String
        }
    }

    Write-Ok "Servers added to trusted list."
}

#endregion

#region Warning 2 — Certificate signing

function Get-OrCreate-SigningCert {
    param([string]$Subject)

    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq "CN=$Subject" -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing' } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($cert) {
        Write-Ok "Reusing existing cert: $($cert.Thumbprint)"
        return $cert
    }

    Write-Step "Creating self-signed code-signing certificate..."

    $cert = New-SelfSignedCertificate `
        -Subject "CN=$Subject" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyUsage DigitalSignature `
        -Type CodeSigningCert `
        -NotAfter (Get-Date).AddYears(10) `
        -FriendlyName $Subject

    Write-Ok "Certificate created: $($cert.Thumbprint)"
    return $cert
}

function Register-TrustedPublisher {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    Write-Host "`n[2b] Registering certificate as trusted RDP publisher..." -ForegroundColor Magenta

    $thumb = $Cert.Thumbprint

    Write-Step "Adding to CurrentUser\TrustedPublisher store"
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($Cert)
    $store.Close()

    Write-Step "Registering thumbprint in HKCU policy: $thumb"
    $policyPath = 'HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }

    $existing = (Get-ItemProperty -Path $policyPath -Name 'TrustedCertThumbprints' -ErrorAction SilentlyContinue)?.TrustedCertThumbprints
    $newValue  = if ($existing -and $existing -notmatch $thumb) { "$existing,$thumb" } else { $thumb }
    Set-ItemProperty -Path $policyPath -Name 'TrustedCertThumbprints' -Value $newValue -Type String

    Write-Ok "Publisher registered."
}

function Invoke-SignRdpFiles {
    param(
        [System.Collections.Generic.List[System.IO.FileInfo]]$Files,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    Write-Host "`n[2c] Signing .rdp files with RDPSign.exe..." -ForegroundColor Magenta

    $rdpSign = "$env:SystemRoot\System32\RDPSign.exe"
    if (-not (Test-Path $rdpSign)) {
        Write-Warn "RDPSign.exe not found at $rdpSign — skipping file signing."
        return
    }

    if (-not $Files -or $Files.Count -eq 0) {
        Write-Warn "No .rdp files to sign."
        return
    }

    foreach ($file in $Files) {
        Write-Step "Signing: $($file.FullName)"
        $result = & $rdpSign /sha256 $Cert.Thumbprint $file.FullName 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Ok "Signed: $($file.Name)" }
        else                      { Write-Warn "Failed to sign $($file.Name): $result" }
    }
}

#endregion

#region Main

if ($Help) {
    Show-Help
    exit 0
}

# Determine effective parameters: from menu or from CLI args
$effectiveRdpFolder = $RdpFolder
$effectiveAutoScan  = $AutoScan.IsPresent
$effectiveSignFiles = $SignFiles.IsPresent
$effectiveUndo      = $Undo.IsPresent

$noArgsProvided = (-not $RdpFolder) -and (-not $AutoScan) -and (-not $SignFiles) -and (-not $Undo) -and (-not $NoMenu)

if ($noArgsProvided) {
    $menuResult = Invoke-Menu
    $effectiveRdpFolder = $menuResult.RdpFolder
    $effectiveAutoScan  = $menuResult.AutoScan
    $effectiveSignFiles = $menuResult.SignFiles
    $effectiveUndo      = $menuResult.Undo
    Write-Host ""
}

Write-Banner

if ($effectiveUndo) {
    Invoke-Undo
    exit 0
}

# Validate: -SignFiles needs a source
if ($effectiveSignFiles -and -not $effectiveRdpFolder -and -not $effectiveAutoScan) {
    Write-Err "-SignFiles requires -RdpFolder or -AutoScan to locate .rdp files."
    Write-Host "        Example: .\Remove-RdpWarnings.ps1 -AutoScan -SignFiles`n" -ForegroundColor Yellow
    exit 1
}

# --- Warning 1: launch consent ---
Set-LaunchConsent

# --- Collect folders to scan ---
$searchFolders = [System.Collections.Generic.List[string]]::new()

if ($effectiveAutoScan) {
    Write-Host "`n[2] Auto-scanning common locations for .rdp files..." -ForegroundColor Magenta
    foreach ($loc in (Get-AutoScanLocations)) {
        Write-Step "Scanning: $loc"
        $searchFolders.Add($loc)
    }
}

if ($effectiveRdpFolder) {
    if (-not (Test-Path $effectiveRdpFolder)) {
        Write-Warn "Folder not found: $effectiveRdpFolder"
    } else {
        if (-not $effectiveAutoScan) {
            Write-Host "`n[2] Processing .rdp files in: $effectiveRdpFolder" -ForegroundColor Magenta
        } else {
            Write-Step "Also scanning: $effectiveRdpFolder"
        }
        $searchFolders.Add($effectiveRdpFolder)
    }
}

if ($searchFolders.Count -gt 0) {
    $rdpFiles = Get-RdpFileList -Folders $searchFolders
    Write-Ok "Total .rdp files found: $($rdpFiles.Count)"

    $servers = Get-RdpServers -Files $rdpFiles
    Set-TrustedServers -Servers $servers

    if ($effectiveSignFiles) {
        $cert = Get-OrCreate-SigningCert -Subject $CertSubject
        Register-TrustedPublisher -Cert $cert
        Invoke-SignRdpFiles -Files $rdpFiles -Cert $cert
    }
} else {
    Write-Host "`n[2] No folder specified — only registry fix applied." -ForegroundColor DarkGray
    Write-Host "    Use -RdpFolder, -AutoScan, or the interactive menu for full fix." -ForegroundColor DarkGray
}

Write-Host @"

==============================================
  Done. Close and reopen any RDP files.
  Run with -Undo to revert all changes.
==============================================
"@ -ForegroundColor Green

#endregion
