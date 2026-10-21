<#
.SYNOPSIS
    Astrilis Union Recording & Compliance Policy Script
.DESCRIPTION
    Ensures administrative privileges, checks execution constraints (STA mode),
    monitors registry integrity, and logs system changes.
.VERSION
    2.6.6
#>

Clear-Host

# ===============================
# STA Mode Enforcement
# ===============================
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $hostExe = (Get-Process -Id$PID).Path
    if ($PSCommandPath) {$argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
        Start-Process -FilePath $hostExe -ArgumentList$argList -Wait | Out-Null
        exit
    }
    $tempScript = Join-Path$env:TEMP 'Astrilis_Tier_2.ps1'
    try {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/matthewgobbels-cell/Astrilis-Union-Recording-policy/refs/heads/main/script.ps1' -OutFile $tempScript -UseBasicParsing
        Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$tempScript`"") -Wait | Out-Null
    } catch {
        Write-Warning "WinForms steps need STA mode. Use: powershell -STA -ExecutionPolicy Bypass -File `"<script.ps1>`""
    }
    exit
}

$script:WinFormsLoaded =$false
function Initialize-WinForms {
    if (-not $script:WinFormsLoaded) {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $script:WinFormsLoaded =$true
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$script:AstrilisTier2Version = '2.6.6'

function Open-LocalMachineRegistryKey {
    param([string]$SubKeyPath)

    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        if ([string]::IsNullOrWhiteSpace($SubKeyPath)) { return$base }
        return $base.OpenSubKey($SubKeyPath)
    } catch {
        return $null
    }
}

# ===============================
# ASCII Banner (ASTRILIS RECORDING POLICY T2)
# ===============================
Write-Host '    _         _        _ _       _          _   _       _            ' -ForegroundColor Cyan
Write-Host '   / \   ___ | |_ _ __(_) |___  | |        | | | |_ __ (_) ___  _ __ ' -ForegroundColor Cyan
Write-Host '  / _ \ / __|| __| `__| | / __| | |_____   | | | | `__| |/ _ \| `_ \ ' -ForegroundColor Cyan
Write-Host ' / ___ \\__ \| |_| |  | | \__ \ | |_____|  | |_| | |  | | (_) | | | |' -ForegroundColor Cyan
Write-Host '/_/   \_\___/ \__|_|  |_|_|___/ |_|         \___/|_|  |_|\___/|_| |_|' -ForegroundColor Cyan
Write-Host ' ____   ___  _     ___ ______   __  _____ ____  ' -ForegroundColor Cyan
Write-Host '|  _ \ / _ \| |   |_ _/ ___\ \ / / |_   _|___ \ ' -ForegroundColor Cyan
Write-Host '| |_) | | | | |    | | |    \ V /    | |   __) |' -ForegroundColor Cyan
Write-Host '|  __/| |_| | |___ | | |___  | |     | |  / __/ ' -ForegroundColor Cyan
Write-Host '|_|    \___/|_____|___\____| |_|     |_| |_____|' -ForegroundColor Cyan
Write-Host ""
Write-Host "Astrilis Union Tier 2 v$($script:AstrilisTier2Version)" -ForegroundColor White
Write-Host ""

if (-not (Test-Admin)) {
    Write-Host "WARNING: Run as Administrator for full results." -ForegroundColor Yellow
}

# ===============================
# Loading Bar Function
# ===============================
function Show-LoadingBar {
    for ($i = 0; $i -le 20; $i++) {
        $percent = $i * 5
        $bar = ("#" * $i) + ("-" * (20 - $i))
        Write-Host "`r[ $bar ]$percent%" -NoNewline
        Start-Sleep -Milliseconds 60
    }
    Write-Host ""
}

function Write-MonitorAlert {
    param(
        [string]$Message,
        [string]$LogFile = (Join-Path$env:TEMP 'astrilis_tier2_security_events.log'),
        [string]$Color = 'White'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    try {
        Add-Content -LiteralPath $LogFile -Value "[$timestamp]$Message" -ErrorAction Stop
    } catch {
        $fallback = Join-Path$env:TEMP 'astrilis_tier2_security_events.log'
        try { Add-Content -LiteralPath $fallback -Value "[$timestamp]$Message" -ErrorAction SilentlyContinue } catch {}
    }
}

function Test-RecordingCompliance {
    $complianceStatus =$true
    
    if (-not (Test-Admin)) {
        Write-MonitorAlert -Message "Policy Check Warning: Running without Administrator privileges." -Color Yellow
        $complianceStatus =$false
    } else {
        Write-MonitorAlert -Message "Policy Check Success: Administrative context verified." -Color Green
    }

    return $complianceStatus
}

$result = Test-RecordingCompliance
if ($result) {
    Write-Host "`nAstrilis Union Recording Policy validation completed successfully." -ForegroundColor Green
} else {
    Write-Host "`nAstrilis Union Recording Policy validation completed with warnings." -ForegroundColor Yellow
}
