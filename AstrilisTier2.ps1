$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "`n[WARNING] This script is NOT running with Administrator privileges." -ForegroundColor Red
    Write-Host "[ACTION] Please right-click PowerShell and then select 'Run as Administrator.'" -ForegroundColor Yellow
    Write-Host ""
    Pause
    exit 1
}

function Write-ColoredLine {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param(
        [string]$Message = "Press Enter to Continue"
    )
    Start-Sleep -Seconds 1
    Write-ColoredLine $Message Yellow
    while ($true) {
        if ([System.Console]::KeyAvailable) {
            $key = [System.Console]::ReadKey($true)
            if ($key.Key -eq "Enter") { break }
        }
        Start-Sleep -Milliseconds 100
    }
}

Clear-Host
Write-Host "    _         _        _ _       _          _   _       _            " -ForegroundColor Cyan
Write-Host "   / \   ___ | |_ _ __(_) |___  | |        | | | |_ __ (_) ___  _ __ " -ForegroundColor Cyan
Write-Host "  / _ \ / __|| __| `__| | / __| | |_____   | | | | `__| |/ _ \| `_ \ " -ForegroundColor Cyan
Write-Host " / ___ \\__ \| |_| |  | | \__ \ | |_____|  | |_| | |  | | (_) | | | |" -ForegroundColor Cyan
Write-Host "/_/   \_\___/ \__|_|  |_|_|___/ |_|         \___/|_|  |_|\___/|_| |_|" -ForegroundColor Cyan
Write-Host " ____  _____ ____ ___  ____  ____ ___ _   _  ____   ____   ___  _     ___ ______   __ " -ForegroundColor Cyan
Write-Host "|  _ \| ____/ ___/ _ \|  _ \|  _ \_ _| \ | |/ ___| |  _ \ / _ \| |   |_ _/ ___\ \ / / " -ForegroundColor Cyan
Write-Host "| |_) |  _|| |  | | | | |_) | | | | ||  \| | |  _  | |_) | | | | |    | | |    \ V /  " -ForegroundColor Cyan
Write-Host "|  _ <| |__| |__| |_| |  _ <| |_| | || |\  | |_| | |  __/| |_| | |___ | | |___  | |   " -ForegroundColor Cyan
Write-Host "|_| \_\_____\____\___/|_| \_\____/___|_| \_|\____| |_|    \___/|_____|___\____| |_|   " -ForegroundColor Cyan
Write-ColoredLine ""
Write-ColoredLine "=== Astrilis Recording Rule Hub ===" Yellow
Write-ColoredLine "Complete both steps with 100% success to pass." White
Write-ColoredLine "Applications will download and extract to C:\ToolsAstrilis." White
Write-ColoredLine "If a prompt shows up, press OK to run the application." White
Write-ColoredLine "Follow the instructions listed on each step." White
Write-ColoredLine "This PowerShell process currently features live Task Manager monitoring." White
Write-Host ""
$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1

if ($cpu.NumberOfCores -ge 4 -and $cpu.MaxClockSpeed -ge 2500) {
    Write-Host "Detected CPU: $($cpu.Name)" -ForegroundColor Green
    Write-Host "Your CPU looks good." -ForegroundColor Green 
} else {
    Write-Host "Detected CPU: $($cpu.Name)" -ForegroundColor Red
    Write-Host "Your CPU may be a bit weak. This process may take longer for you." -ForegroundColor Yellow
}

Write-Host ""
 
$gpuList = Get-WmiObject Win32_VideoController
$gpuNames = $gpuList | Select-Object -ExpandProperty Name

$activeGPU = $gpuList | Where-Object { $_.Name -match "NVIDIA|RTX" } | Select-Object -First 1

if (-not $activeGPU) {
    $activeGPU = $gpuList | Sort-Object AdapterRAM -Descending | Select-Object -First 1
}

$activeGPUName = $activeGPU.Name

Write-Host "Detected GPUs:" -ForegroundColor White
$gpuNames | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

Write-Host ""
Write-Host "Active GPU: $activeGPUName" -ForegroundColor Cyan

$goodGPUs = @("RTX 30", "RTX 40", "RTX 50", "RX 6000", "RX 7000")

$gpuIsGood = $false
foreach ($keyword in $goodGPUs) {
    if ($activeGPUName -like "*$keyword*") {
        $gpuIsGood = $true
        break
    }
}

if ($gpuIsGood) {
    Write-Host "Your GPU looks good." -ForegroundColor Green
} else {
    Write-Host "Your GPU may be a bit weak. Some processes may be slower." -ForegroundColor Yellow
}

$gpuName = $activeGPUName

Write-ColoredLine ""
Write-ColoredLine "=== Discord Servers ===" Yellow
Write-ColoredLine "discord.gg/astrilis" White
Write-ColoredLine ""
Write-ColoredLine "=== Credits ===" Yellow
Write-ColoredLine "Made by skrimworthy" White
Write-Host ""
Wait-ForEnter -Message "Press Enter to Continue"
Clear-Host

# ====== STEP 1: SYSTEM CHECK ====== 

Write-ColoredLine "Step 1 of 2: SYSTEM Check" White
Write-ColoredLine "INSTRUCTION: Reach 100% success" Yellow

Write-Host ""

function Show-LoadingBar {
    for ($i = 0; $i -le 10; $i++) {
        $percent = $i * 10
        $bar = "#" * $i + "-" * (10 - $i)
        Write-Host -NoNewline "`rProgress: [ $bar ] $percent% " -ForegroundColor White
        Start-Sleep -Milliseconds 200
    }
    Write-Host ""
    Write-Host ""
}

Show-LoadingBar

$exclusionsOutput = @()
$defenderOutput = @()
$modulesOutput = @()
$windowsOutput = @()
$memoryIntegrityOutput = @()
$threatsOutput = @()
$powershellSigOutput = @()

$defaultModules = @(
    "Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host",
    "Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security",
    "Microsoft.PowerShell.Utility", "PackageManagement", "PowerShellGet", "PSReadLine", "Pester", "ThreadJob"
)

$protectedModule = "Microsoft.PowerShell.Operation.Validation"
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"
$deletedAny = $false
$protectedFilePath = "$modulesPath\$protectedModule\1.0.1\Diagnostics\Comprehensive\Comprehensive.Tests.ps1"
$expectedHash = "99B7CBE4325BA089DD9440A202B9E35D9E6F134A46312F3F1E93E71F23C8DAE3"

Get-ChildItem $modulesPath -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $moduleName = $_.Name
    $modulePath = $_.FullName
    $isDefault = $defaultModules -contains $moduleName
    $isProtected = $moduleName -eq $protectedModule
    $files = Get-ChildItem $modulePath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
    $unauthorizedFiles = @()

    foreach ($file in $files) {
        $sig = Get-AuthenticodeSignature $file.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
            $unauthorizedFiles += $file
        }
    }

    if (-not $isDefault -and -not $isProtected) {
        foreach ($file in $files) { try { $file.Attributes = 'Normal' } catch {} }
        try {
            Remove-Item $modulePath -Recurse -Force -ErrorAction Stop
            $modulesOutput += "FAILURE: Removed unauthorized module: $moduleName"
            $deletedAny = $true
        } catch {
            $modulesOutput += "WARNING: Could not delete module '$moduleName'"
        }
    }
    elseif ($isProtected) {
        if ($unauthorizedFiles.Count -eq 0) {
            $modulesOutput += "SUCCESS: Protected module '$moduleName' verified."
        } else {
            foreach ($file in $unauthorizedFiles) {
                if ($file.FullName -ieq $protectedFilePath) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                        $sha256 = [System.Security.Cryptography.SHA256]::Create()
                        $actual = $sha256.ComputeHash($bytes)
                        $hash = ([BitConverter]::ToString($actual)).Replace("-", "")
                        if ($hash -ne $expectedHash) {
                            $modulesOutput += "WARNING: Protected file altered: '$($file.FullName)'"
                        }
                    } catch {}
                }
            }
            $modulesOutput += "SUCCESS: Protected module intact."
        }
    }
    else {
        foreach ($file in $unauthorizedFiles) {
            try {
                $file.Attributes = 'Normal'
                Remove-Item $file.FullName -Force -ErrorAction Stop
                $modulesOutput += "FAILURE: Removed unauthorized file: '$($file.FullName)'"
                $deletedAny = $true
            } catch {
                $modulesOutput += "WARNING: Could not delete file '$($file.FullName)'"
            }
        }
        if ($unauthorizedFiles.Count -eq 0) {
            $modulesOutput += "SUCCESS: Module '$moduleName' passed signature check."
        }
    }
}

Get-ChildItem $modulesPath -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
        try {
            Remove-Item $_.FullName -Force
            $modulesOutput += "FAILURE: Removed unsigned file: '$($_.FullName)'"
            $deletedAny = $true
        } catch {
            $modulesOutput += "WARNING: Could not delete root file '$($_.FullName)'"
        }
    } else {
        $modulesOutput += "SUCCESS: Root file '$($_.Name)' is signed."
    }
}

if (-not $deletedAny) {
    $modulesOutput += "SUCCESS: No unauthorized modules/files found."
}

try {
    if ($env:OS -eq "Windows_NT" -and (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop)) {
        $windowsOutput += "SUCCESS: Running on Windows."
    } else {
        $windowsOutput += "FAILURE: Not running on Windows."
    }
} catch {
    $windowsOutput += "FAILURE: OS check failed."
}

try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = Get-ItemPropertyValue -Path $regPath -Name "Enabled" -ErrorAction Stop
    $memoryIntegrityOutput += "SUCCESS: Memory Integrity supported."
    if ($enabled -eq 1) {
        $memoryIntegrityOutput += "SUCCESS: Memory Integrity is ON."
    } else {
        $memoryIntegrityOutput += "FAILURE: Memory Integrity is OFF."
    }
} catch {
    $memoryIntegrityOutput += "FAILURE: Memory Integrity not supported or inaccessible."
}

try {
    $defender = Get-MpComputerStatus
    $service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue

    if ($defender.AntivirusEnabled -and $service.Status -eq 'Running') {
        if (-not $defender.RealTimeProtectionEnabled) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                Start-MpWDOScan
                $defenderOutput += "FAILURE: Realtime protection was OFF. Enabling..."
            } catch {
                $defenderOutput += "WARNING: Could not re-enable Defender."
            }
        } else {
            $defenderOutput += "SUCCESS: Realtime protection is ON."
        }
    } else {
        $defenderOutput += "FAILURE: Microsoft Defender Antivirus is not running."
    }
} catch {
    $defenderOutput += "WARNING: Could not query Defender status."
}

try {
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    if ($exclusions) {
        $exclusionsOutput += "FAILURE: Exclusion paths found:`n$($exclusions -join "`n")"
    } else {
        $exclusionsOutput += "SUCCESS: No Defender exclusions set."
    }
} catch {
    $exclusionsOutput += "WARNING: Could not check exclusions."
}

try {
    $threats = Get-MpThreat | Where-Object { $_.Status -eq "Active" }
    if ($threats) {
        foreach ($t in $threats) {
            $threatsOutput += "FAILURE: $($t.ThreatName) | $($t.Resources)"
        }
    } else {
        $threatsOutput += "SUCCESS: No active threats."
    }
} catch {
    $threatsOutput += "WARNING: Threat scan failed."
}

try {
    $psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $sig = Get-AuthenticodeSignature -FilePath $psPath
    if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Windows*') {
        $powershellSigOutput += "SUCCESS: PowerShell is signed and valid."
    } else {
        $powershellSigOutput += "FAILURE: PowerShell binary signature invalid."
    }
} catch {
    $powershellSigOutput += "WARNING: Could not verify PowerShell binary."
}

function Write-Section {
    param([string]$Title, [string[]]$Lines)
    Write-Host "--- $Title ---" -ForegroundColor White
    foreach ($line in $Lines) {
        if ($line -match "^SUCCESS") { Write-Host $line -ForegroundColor Green }
        elseif ($line -match "^FAILURE") { Write-Host $line -ForegroundColor Red }
        elseif ($line -match "^WARNING") { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line -ForegroundColor White }
    }
}

Write-Section "Files + Modules" $modulesOutput
Write-Section "OS Check" $windowsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Exclusions" $exclusionsOutput
Write-Section "Threats" $threatsOutput
Write-Section "Binary Sig" $powershellSigOutput

$allResults = $modulesOutput + $windowsOutput + $memoryIntegrityOutput + $defenderOutput + $exclusionsOutput + $threatsOutput + $powershellSigOutput
$total = ($allResults | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success = ($allResults | Where-Object { $_ -match '^SUCCESS' }).Count
$rate = if ($total -gt 0) { [math]::Round(($success / $total) * 100, 0) } else { 0 }
$rateColor = if ($rate -eq 100) { "Green" } else { "Red" }

Write-Host ""
Write-Host ("Success Rate: $rate% ($success / $total)") -ForegroundColor $rateColor

Wait-ForEnter -Message "Press Enter to Continue"
Clear-Host

# ====== STEP 2: PROCESS EXPLORER ======

function Write-ColoredLine {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    Start-Sleep -Seconds 1
    Write-ColoredLine "Press Enter to continue to Live Monitor." Yellow
    while ($true) {
        if ([System.Console]::KeyAvailable) {
            $key = [System.Console]::ReadKey($true)
            if ($key.Key -eq "Enter") { break }
        }
        Start-Sleep -Milliseconds 100
    }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $scriptPath = try {
        (Resolve-Path -Path $MyInvocation.MyCommand.Definition).Path
    } catch {
        Write-Host "[ERROR] Could not resolve script path. Are you running this from a file?" -ForegroundColor Red
        pause
        exit 1
    }

    Write-Host "[INFO] Relaunching with admin rights..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

Clear-Host
Write-ColoredLine "Step 2 of 2: Process Explorer" White
Write-ColoredLine "INSTRUCTION: Wait for Process Explorer to open. Scroll to the bottom, then close the window." Yellow
Write-Host ""
Show-LoadingBar

$processNames = @("procexp", "procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $processNames -contains $_.ProcessName.ToLower()
}

if ($runningPE) {
    foreach ($proc in $runningPE) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-ColoredLine "[SUCCESS] Terminated Process Explorer PID $($proc.Id)." Green
        } catch {
            Write-ColoredLine "[FAILED] Failed to terminate PID $($proc.Id): $($_.Exception.Message)" Red
        }
    }
    Start-Sleep -Seconds 1
} else {
    Write-ColoredLine "[SUCCESS] No running Process Explorer processes were found." Green
}

$baseFolder = "C:\ToolsAstrilis"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

$regFileUrl = "https://pastebin.com/raw/gse8NxwU"
$regFilePath = Join-Path $baseFolder "procexp_config.reg"

try {
    if (Test-Path $baseFolder) {
        Remove-Item -Path $baseFolder -Recurse -Force -ErrorAction Stop
        Write-ColoredLine "[SUCCESS] Cleaned up existing C:\ToolsAstrilis folder." Green
    }

    New-Item -ItemType Directory -Path $baseFolder -Force -ErrorAction Stop | Out-Null
    Write-ColoredLine "[SUCCESS] Prepared C:\ToolsAstrilis." Green
} catch {
    Write-ColoredLine "[FAILED] Could not prepare C:\ToolsAstrilis: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

$curl = "$env:SystemRoot\System32\curl.exe"

if (-not (Test-Path $curl)) {
    Write-ColoredLine "[FAILED] curl.exe was not found at $curl." Red
    Wait-ForEnter
    exit 1
}

try {
    Write-ColoredLine "[INFO] Downloading Process Explorer..." Yellow

    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $zipPath $zipUrl

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe returned exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $zipPath)) {
        throw "Process Explorer ZIP was not created."
    }

    if ((Get-Item $zipPath).Length -lt 10000) {
        throw "Downloaded Process Explorer ZIP is unexpectedly small."
    }

    Write-ColoredLine "[SUCCESS] Downloaded Process Explorer." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

try {
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractFolder -Force -ErrorAction Stop
    Write-ColoredLine "[SUCCESS] Extracted Process Explorer zip." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to extract Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

try {
    Write-ColoredLine "[INFO] Downloading Process Explorer registry configuration..." Yellow

    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $regFilePath $regFileUrl

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe returned exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $regFilePath)) {
        throw "Registry configuration file was not created."
    }

    if ((Get-Item $regFilePath).Length -eq 0) {
        throw "Registry configuration file is empty."
    }

    Write-ColoredLine "[SUCCESS] Downloaded Process Explorer registry configuration." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download registry config: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

try {
    $regExe = "$env:SystemRoot\System32\reg.exe"

    if (-not (Test-Path $regExe)) {
        throw "reg.exe not found at expected location: $regExe"
    }

    & $regExe import $regFilePath

    if ($LASTEXITCODE -eq 0) {
        Write-ColoredLine "[SUCCESS] Imported registry configuration successfully." Green
    } else {
        throw "reg import returned exit code $LASTEXITCODE."
    }
} catch {
    Write-ColoredLine "[FAILED] Registry importing failed: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $actualExe) {
    Write-ColoredLine "[FAILED] procexp64.exe was not found after extraction." Red
    Write-ColoredLine "[FAILED] Success Rate: 0% (0 / 1)." Red
    Wait-ForEnter
    exit 1
}

try {
    Write-ColoredLine "[SUCCESS] Found procexp64.exe." Green

    $process = Start-Process -FilePath $actualExe.FullName -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 1

    try {
        $wshell = New-Object -ComObject WScript.Shell
        Start-Sleep -Milliseconds 500

        if ($wshell.AppActivate($process.Id)) {
            Start-Sleep -Milliseconds 500
            $wshell.SendKeys('% ')
            Start-Sleep -Milliseconds 200
            $wshell.SendKeys('x')
            Start-Sleep -Milliseconds 500
            Write-ColoredLine "[SUCCESS] Process Explorer window maximized." Green
        }
    } catch {}

    Write-ColoredLine "[SUCCESS] Process Explorer launched successfully." Green
    Write-Host ""

    $process.WaitForExit()

    Write-ColoredLine "[SUCCESS] Success Rate: 100% (1 / 1)." Green
} catch {
    Write-ColoredLine "[FAILED] Could not launch Process Explorer: $($_.Exception.Message)" Red
    Write-ColoredLine "[FAILED] Success Rate: 0% (0 / 1)." Red
}

Wait-ForEnter

# ===============================
# PAGE 3: LIVE TASK MANAGER MONITOR
# ===============================
Clear-Host
Write-ColoredLine "=========================================================" Magenta
Write-ColoredLine "        ASTRILIS UNION LIVE COMPLIANCE MONITOR           " Magenta
Write-ColoredLine "=========================================================" Magenta
Write-ColoredLine " System Integrity Verified. Guard rails active." Green
Write-ColoredLine " Task Manager is being monitored live." Cyan
Write-ColoredLine " Press [Ctrl+C] at any time to exit live monitoring mode." Yellow
Write-ColoredLine "=========================================================" Magenta
Write-Host ""

$taskManagerActive = $false

while ($true) {
    $currentProcesses = Get-Process -ErrorAction SilentlyContinue

    # Track Task Manager state precisely (covers 'taskmgr' process and typical window titles)
    $taskMgrProc = $currentProcesses | Where-Object { $_.ProcessName -ieq 'taskmgr' -or $_.MainWindowTitle -match 'Task Manager' }
    
    if ($taskMgrProc -and -not $taskManagerActive) {
        $taskManagerActive = $true
        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] [ALERT] Task Manager was opened!" -ForegroundColor Red
        
        # Pop up alert notification window
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("Task Manager was opened! Violation detected.", "Astrilis Union Policy Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    } elseif (-not $taskMgrProc -and $taskManagerActive) {
        $taskManagerActive = $false
        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] [INFO] Task Manager was closed." -ForegroundColor Yellow
    }

    Start-Sleep -Milliseconds 800
}
