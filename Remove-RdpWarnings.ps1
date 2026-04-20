#Requires -Version 5.1
<#
.SYNOPSIS
    Removes security warnings when opening RDP files in Windows 11.

.DESCRIPTION
    Handles two distinct warnings:
      1. "Do you trust this RDP connection?" - new consent dialog (post-2024 updates)
      2. "Unknown publisher" - unsigned RDP file warning

    Approach:
      - Sets registry keys to accept the launch consent
      - Optionally creates a self-signed code-signing certificate
      - Optionally signs .rdp files with RDPSign.exe
      - Registers the certificate thumbprint as a trusted RDP publisher
      - Adds each RDP server hostname to the per-user trusted servers list

.PARAMETER RdpFolder
    Path to folder containing .rdp files to process. Defaults to current directory.

.PARAMETER SignFiles
    Sign all .rdp files found in RdpFolder. Requires admin rights for cert creation.

.PARAMETER CertSubject
    Subject name for the self-signed certificate. Default: "RDP Trusted Publisher"

.PARAMETER Undo
    Reverts all registry changes made by this script.

.EXAMPLE
    # Accept consent dialog only (fastest, no signing)
    .\Remove-RdpWarnings.ps1

.EXAMPLE
    # Full fix: accept consent + sign all RDP files in C:\RDP
    .\Remove-RdpWarnings.ps1 -RdpFolder "C:\RDP" -SignFiles

.EXAMPLE
    # Revert everything
    .\Remove-RdpWarnings.ps1 -Undo
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RdpFolder = $PWD,
    [switch]$SignFiles,
    [string]$CertSubject = "RDP Trusted Publisher",
    [switch]$Undo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Step {
    param([string]$Message)
    Write-Host "  >> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!!] $Message" -ForegroundColor Yellow
}

function Test-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

function Remove-RegistryValue {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
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

#region Warning 2 — Unknown publisher (per server)

function Get-RdpServers {
    param([string]$Folder)

    $servers = @()
    $rdpFiles = Get-ChildItem -Path $Folder -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $rdpFiles) {
        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
        $hostLine = $content | Where-Object { $_ -match '^full address:s:(.+)$' }
        if ($hostLine -match '^full address:s:(.+)$') {
            $host = $Matches[1].Trim()
            # Strip port if present (hostname:port)
            $host = $host -replace ':\d+$', ''
            if ($host -and $host -notin $servers) {
                $servers += $host
                Write-Step "Found server: $host  ($($file.Name))"
            }
        }
    }
    return $servers
}

function Set-TrustedServers {
    param([string[]]$Servers)

    if (-not $Servers -or $Servers.Count -eq 0) {
        Write-Warn "No servers found in .rdp files — skipping per-server trust."
        return
    }

    Write-Host "`n[2a] Adding servers to per-user trusted list..." -ForegroundColor Magenta

    foreach ($server in $Servers) {
        $serverPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers\$server"
        Write-Step "Trusting: $server"
        if (-not (Test-Path $serverPath)) {
            New-Item -Path $serverPath -Force | Out-Null
        }
        # UsernameHint presence alone is sufficient to suppress the unknown-publisher warning
        if (-not (Get-ItemProperty -Path $serverPath -Name 'UsernameHint' -ErrorAction SilentlyContinue)) {
            Set-ItemProperty -Path $serverPath -Name 'UsernameHint' -Value '' -Type String
        }
    }

    Write-Ok "Servers added to trusted list."
}

#endregion

#region Warning 2 — Unknown publisher (certificate signing)

function Get-OrCreate-SigningCert {
    param([string]$Subject)

    # Look for existing cert in user store
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

    $thumb = $cert.Thumbprint

    # Add to user Trusted Publishers store
    Write-Step "Adding to CurrentUser\TrustedPublisher store"
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($cert)
    $store.Close()

    # Register thumbprint via HKCU policy key (avoids needing admin for HKLM)
    Write-Step "Registering thumbprint in HKCU policy: $thumb"
    $policyPath = 'HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    if (-not (Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
    }

    $existing = (Get-ItemProperty -Path $policyPath -Name 'TrustedCertThumbprints' -ErrorAction SilentlyContinue)?.TrustedCertThumbprints
    if ($existing -and $existing -notmatch $thumb) {
        $newValue = "$existing,$thumb"
    } else {
        $newValue = $thumb
    }
    Set-ItemProperty -Path $policyPath -Name 'TrustedCertThumbprints' -Value $newValue -Type String

    Write-Ok "Publisher registered."
    return $thumb
}

function Invoke-SignRdpFiles {
    param(
        [string]$Folder,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    Write-Host "`n[2c] Signing .rdp files with RDPSign.exe..." -ForegroundColor Magenta

    $rdpSign = "$env:SystemRoot\System32\RDPSign.exe"
    if (-not (Test-Path $rdpSign)) {
        Write-Warn "RDPSign.exe not found at $rdpSign — skipping file signing."
        return
    }

    $rdpFiles = Get-ChildItem -Path $Folder -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue
    if (-not $rdpFiles) {
        Write-Warn "No .rdp files found in: $Folder"
        return
    }

    foreach ($file in $rdpFiles) {
        Write-Step "Signing: $($file.FullName)"
        $result = & $rdpSign /sha256 $Cert.Thumbprint $file.FullName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Signed: $($file.Name)"
        } else {
            Write-Warn "Failed to sign $($file.Name): $result"
        }
    }
}

#endregion

#region Main

Write-Host @"
==============================================
  Remove-RdpWarnings.ps1
  Windows 11 RDP security warning suppressor
==============================================
"@ -ForegroundColor White

if ($Undo) {
    Invoke-Undo
    exit 0
}

# --- Warning 1: launch consent ---
Set-LaunchConsent

# --- Warning 2: per-server trust (always run if RDP files exist) ---
Write-Host "`n[2] Processing .rdp files in: $RdpFolder" -ForegroundColor Magenta
$servers = Get-RdpServers -Folder $RdpFolder
Set-TrustedServers -Servers $servers

# --- Warning 2: certificate signing (optional) ---
if ($SignFiles) {
    $cert = Get-OrCreate-SigningCert -Subject $CertSubject
    Register-TrustedPublisher -Cert $cert
    Invoke-SignRdpFiles -Folder $RdpFolder -Cert $cert
}

Write-Host @"

==============================================
  Done. Close and reopen any RDP files.
  Run with -Undo to revert all changes.
==============================================
"@ -ForegroundColor Green

#endregion
