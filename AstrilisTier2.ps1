# No global error swallowing - failed checks get reported as potential tampering
Clear-Host

function Red($msg)   { Write-Host $msg -ForegroundColor Red }
function Green($msg) { Write-Host $msg -ForegroundColor Green }
function Yellow($msg) { Write-Host $msg -ForegroundColor Yellow }
function Cyan($msg)  { Write-Host $msg -ForegroundColor Cyan }
function White($msg) { Write-Host $msg -ForegroundColor White }

function Pause-AndScroll($label) {
    Write-Host ""
    Write-Host ">>> SCROLL UP AND REVIEW THE $label ABOVE <<<" -ForegroundColor Magenta
    Write-Host "Press ENTER when you are done reviewing..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "      REAL-TIME SYSTEM INTEGRITY MONITOR     " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "This script will walk you through several checks." -ForegroundColor White
Write-Host "You will be asked to scroll and review each section." -ForegroundColor White
Write-Host "Press ENTER at each prompt to continue." -ForegroundColor Yellow
Write-Host ""

# --- [1/16] Prefetch ---
Write-Host "=== [1/16] PREFETCH FILES (Recent Program Launches) ===" -ForegroundColor Cyan
Write-Host "Prefetch files reveal every program that has been run on this PC." -ForegroundColor White
Write-Host "Look for suspicious EXEs - cheats, injectors, loaders, spoofers." -ForegroundColor Yellow
Write-Host ""

$prefetchPath = Join-Path $env:SystemRoot "Prefetch"
$prefetchOk = $false
try {
    if (-not (Test-Path $prefetchPath -ErrorAction Stop)) {
        Red "Prefetch folder not found or not accessible. Try running as Administrator."
        Red "Possible tampering or blocking - path missing."
    } else {
        $prefetchOk = $true
        $pfItems = Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction Stop
        $pfItems | Sort-Object LastWriteTime -Descending | ForEach-Object {
            $name = $_.Name -replace "-[A-F0-9]+\.pf$", ""
            Write-Host "$($_.LastWriteTime)  |  $name" -ForegroundColor Yellow
        }
    }
} catch {
    Red "Prefetch folder access denied or error: $($_.Exception.Message)"
    Red "Possible blocking or tampering - check could not complete."
}

Write-Host ""
Write-Host "[INSTRUCTION] Scroll up and look for anything suspicious:" -ForegroundColor Magenta
Write-Host "  - Cheats" -ForegroundColor White
Write-Host "  - Spoofers" -ForegroundColor White
Write-Host "  - and so on" -ForegroundColor White
Pause-AndScroll "PREFETCH LIST"

if ($prefetchOk) {
    Write-Host "[ACTION] Opening Prefetch folder in Explorer for visual inspection..." -ForegroundColor Cyan
    Start-Process "explorer.exe" -ArgumentList $prefetchPath
    Start-Sleep -Seconds 2
}
Write-Host ""

# --- [2/16] Local AppData ---
Write-Host "=== [2/16] LOCAL APPDATA CONTENTS ===" -ForegroundColor Cyan
Write-Host "LocalAppData holds per-user app data. Cheats often dump files here." -ForegroundColor Yellow
Write-Host ""

$localApp = $env:LOCALAPPDATA
try {
    Get-ChildItem $localApp -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 60 | ForEach-Object {
        if ($_.PSIsContainer) { Write-Host "$($_.LastWriteTime)  |  $($_.Name)" -ForegroundColor White }
        else { Write-Host "$($_.LastWriteTime)  |  $($_.Name)" -ForegroundColor Yellow }
    }
} catch {
    Red "LocalAppData access denied or error: $($_.Exception.Message)"
    Red "Possible tampering or blocking - check could not complete."
}

Write-Host ""
Write-Host "[INSTRUCTION] Look for folders/files you do not recognize:" -ForegroundColor Magenta
Write-Host "  - Random string folder names (e.g. xKf29a, tmp_loader)" -ForegroundColor White
Write-Host "  - Cheat-related names (aimware, esp, triggerbot, spoofer, etc.)" -ForegroundColor White
Write-Host "  - Recently modified folders that do not match any app you use" -ForegroundColor White
Pause-AndScroll "LOCAL APPDATA LIST"

Write-Host "[ACTION] Opening LocalAppData in Explorer..." -ForegroundColor Cyan
Start-Process "explorer.exe" -ArgumentList $localApp
Start-Sleep -Seconds 2
Write-Host ""

# --- [3/16] Roaming AppData ---
Write-Host "=== [3/16] ROAMING APPDATA CONTENTS ===" -ForegroundColor Cyan
Write-Host "Roaming AppData is another common cheat drop location." -ForegroundColor Yellow
Write-Host ""

$roaming = $env:APPDATA
try {
    Get-ChildItem $roaming -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 60 | ForEach-Object {
        if ($_.PSIsContainer) { Write-Host "$($_.LastWriteTime)  |  $($_.Name)" -ForegroundColor White }
        else { Write-Host "$($_.LastWriteTime)  |  $($_.Name)" -ForegroundColor Yellow }
    }
} catch {
    Red "Roaming AppData access denied or error: $($_.Exception.Message)"
    Red "Possible tampering or blocking - check could not complete."
}

Write-Host ""
Write-Host "[INSTRUCTION] Same as LocalAppData - look for:" -ForegroundColor Magenta
Write-Host "  - Unfamiliar folder names with recent modification dates" -ForegroundColor White
Write-Host "  - Any .exe .dll .log files sitting loose in the root" -ForegroundColor White
Write-Host "  - Folders named after games that have extra subfolders" -ForegroundColor White
Pause-AndScroll "ROAMING APPDATA LIST"

# open so they can double-check if they want
Write-Host "[ACTION] Opening Roaming AppData in Explorer..." -ForegroundColor Cyan
Start-Process "explorer.exe" -ArgumentList $roaming
Start-Sleep -Seconds 2
Write-Host ""

# --- [4/16] Defender status ---
Write-Host "=== [4/16] WINDOWS DEFENDER STATUS ===" -ForegroundColor Cyan
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Green "RealTimeProtection : $($mp.RealTimeProtectionEnabled)"
    Green "AntivirusEnabled   : $($mp.AntivirusEnabled)"
    Green "BehaviorMonitor    : $($mp.BehaviorMonitorEnabled)"
    Green "IOAVProtection     : $($mp.IOAVProtectionEnabled)"
    Green "TamperProtection   : $($mp.IsTamperProtected)"
    Green "AntispywareEnabled : $($mp.AntispywareEnabled)"
} catch {
    Red "Defender status query failed: $($_.Exception.Message)"
    Red "Possible tampering or WMI/Defender blocked - treat as suspicious."
}
Pause-AndScroll "DEFENDER STATUS"
Write-Host ""

# --- [5/16] Defender exclusions ---
Write-Host "=== [5/16] DEFENDER EXCLUSIONS ===" -ForegroundColor Cyan
Write-Host "Exclusions are added by cheats to hide from Defender scans." -ForegroundColor Yellow
Write-Host ""

try {
    $pref = Get-MpPreference -ErrorAction Stop
    if ($pref.ExclusionPath) {
        Red "!! Defender Exclusion PATHS found - these should not be here !!"
        $pref.ExclusionPath | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else { Green "No exclusion paths found - GOOD" }

    if ($pref.ExclusionProcess) {
        Red "!! Defender Exclusion PROCESSES found !!"
        $pref.ExclusionProcess | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else { Green "No exclusion processes found - GOOD" }

    if ($pref.ExclusionExtension) {
        Red "!! Defender Exclusion EXTENSIONS found !!"
        $pref.ExclusionExtension | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else { Green "No exclusion extensions found - GOOD" }
} catch {
    Red "Defender preferences query failed: $($_.Exception.Message)"
    Red "Possible tampering or access blocked - treat as suspicious."
}
Pause-AndScroll "DEFENDER EXCLUSIONS"
Write-Host "`n"

# --- [6/16] TPM, Virtualization, Secure Boot (all must be ON) ---
Write-Host "=== [6/16] TPM, VIRTUALIZATION, SECURE BOOT (REQUIRED: ALL ON) ===" -ForegroundColor Cyan
Write-Host "These three must be enabled. If any is OFF, enable in BIOS/UEFI and re-run." -ForegroundColor Yellow
Write-Host ""

$tpmOk = $false
$virtOk = $false
$secureBootOk = $false

try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Green "TPM: Present and Ready - OK"
        $tpmOk = $true
    } else {
        Red "TPM: NOT ready or not present. Enable TPM in BIOS/UEFI."
    }
} catch {
    Red "TPM check failed: $($_.Exception.Message). Enable TPM in BIOS/UEFI."
}

try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.HypervisorPresent) {
        Green "Virtualization: Hypervisor present - OK"
        $virtOk = $true
    } else {
        Red "Virtualization: NOT present. Enable VT-x/AMD-V (and Hyper-V if needed) in BIOS/UEFI."
    }
} catch {
    Red "Virtualization check failed: $($_.Exception.Message). Enable in BIOS/UEFI."
}

try {
    if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) { Import-Module SecureBoot -ErrorAction SilentlyContinue }
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sb) {
        Green "Secure Boot: Enabled - OK"
        $secureBootOk = $true
    } else {
        Red "Secure Boot: DISABLED. Enable Secure Boot in BIOS/UEFI."
    }
} catch {
    Red "Secure Boot check failed: $($_.Exception.Message). Enable Secure Boot in BIOS/UEFI."
}

if (-not ($tpmOk -and $virtOk -and $secureBootOk)) {
    Red "REQUIREMENT NOT MET: TPM, Virtualization, and Secure Boot must all be ON. Fix in BIOS/UEFI and re-run."
} else {
    Green "All three requirements satisfied: TPM, Virtualization, Secure Boot are ON."
}
Pause-AndScroll "TPM / VIRTUALIZATION / SECURE BOOT"
Write-Host ""

# --- [7/16] Memory integrity / HVCI ---
Write-Host "=== [7/16] MEMORY INTEGRITY AND DEVICE GUARD ===" -ForegroundColor Cyan
$hvciOk = $false
try {
    $hvci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction Stop
    $hvciOk = $true
    if ($hvci.Enabled -eq 1) { Green "Memory Integrity: ENABLED" }
    else { Red "Memory Integrity: DISABLED - cheats can inject drivers more easily" }
} catch {
    Red "HVCI registry read failed: $($_.Exception.Message)"
    Red "Possible tampering or access denied - cannot confirm Memory Integrity status."
}

try {
    Get-CimInstance Win32_DeviceGuard -ErrorAction Stop | ForEach-Object {
        Green "VBS Status              : $($_.VirtualizationBasedSecurityStatus)"
        Green "Code Integrity Policy   : $($_.CodeIntegrityPolicyEnforcementStatus)"
    }
} catch {
    Red "Device Guard WMI query failed: $($_.Exception.Message)"
    Red "Possible blocking - VBS/CI status unknown."
}
Pause-AndScroll "MEMORY INTEGRITY STATUS"
Write-Host ""

# --- [8/16] Loaded drivers (user-space visible) ---
Write-Host "=== [8/16] LOADED DRIVERS (signature check) ===" -ForegroundColor Cyan
# WMI only sees what it can - kernel-mapped stuff won't show, but still worth a look
Write-Host "Listing drivers visible via WMI. Unsigned or unknown signers are risky." -ForegroundColor Yellow
Write-Host ""

try {
    $drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop
    $unsignedCount = 0
    $drivers | ForEach-Object {
        $signed = $_.IsSigned
        if ($null -eq $signed -or -not $signed) {
            $unsignedCount++
            Yellow "UNSIGNED: $($_.DeviceName) | Driver: $($_.DriverName)"
        }
    }
    if ($unsignedCount -eq 0) {
        Green "No unsigned drivers reported by WMI (good)."
    } else {
        Red "Found $unsignedCount unsigned driver(s) - review above."
    }
} catch {
    Red "Driver enumeration failed: $($_.Exception.Message)"
    Red "Possible tampering or WMI blocked - cannot verify driver signatures."
}
Pause-AndScroll "LOADED DRIVERS"
Write-Host ""

# --- [9/16] PCI configuration space / vendor & device IDs (spoof check) ---
Write-Host "=== [9/16] PCI DEVICES - VENDOR/DEVICE IDs (spoof check) ===" -ForegroundColor Cyan
Write-Host "Enumerating PCI devices via PnP. Known DMA/FPGA-related or spoofed IDs are flagged." -ForegroundColor Yellow
Write-Host ""

# Known vendor IDs often used for DMA/FPGA hardware (FTDI USB-JTAG on Squirrel, etc.). Flag these.
$dmaFpgaVendorIds = @('VEN_0403', 'VEN_10EE', 'VEN_1D50', 'VEN_0547')  # FTDI, Xilinx, OpenMoko, PLX
$knownGoodVendors = @('VEN_8086', 'VEN_1022', 'VEN_10DE', 'VEN_1002', 'VEN_14E4', 'VEN_1969', 'VEN_168C')  # Intel, AMD, NVIDIA, Broadcom, etc.
try {
    $pciWithIds = Get-CimInstance Win32_PnPEntity -Filter "DeviceID LIKE 'PCI%'" -ErrorAction Stop
    $suspiciousCount = 0
    foreach ($pnp in $pciWithIds) {
        $id = $pnp.DeviceID
        if (-not $id) { continue }
        $venMatch = [regex]::Match($id, 'VEN_([0-9A-Fa-f]{4})')
        $devMatch = [regex]::Match($id, 'DEV_([0-9A-Fa-f]{4})')
        if ($venMatch.Success) {
            $ven = 'VEN_' + $venMatch.Groups[1].Value
            $dev = if ($devMatch.Success) { 'DEV_' + $devMatch.Groups[1].Value } else { 'DEV_????' }
            $isDmaFpga = $dmaFpgaVendorIds -contains $ven
            $isKnownGood = $knownGoodVendors -contains $ven
            if ($isDmaFpga) {
                $suspiciousCount++
                Red "SUSPICIOUS (DMA/FPGA-related): $ven $dev - $($pnp.Name)"
            } elseif (-not $isKnownGood) {
                Yellow "Unknown vendor (review): $ven $dev - $($pnp.Name)"
            }
        }
    }
    if ($suspiciousCount -eq 0) {
        Green "No known DMA/FPGA-related PCI vendor IDs found in enumeration."
    } else {
        Red "Found $suspiciousCount device(s) with DMA/FPGA-associated vendor IDs - investigate."
    }
} catch {
    Red "PCI device enumeration failed: $($_.Exception.Message)"
    Red "Possible tampering or access denied - cannot verify PCI configuration."
}
Pause-AndScroll "PCI VENDOR/DEVICE IDs"
Write-Host ""

# --- [10/16] FPGA bitstreams / DMA firmware files ---
Write-Host "=== [10/16] FPGA BITSTREAMS / DMA FIRMWARE SCAN ===" -ForegroundColor Cyan
Write-Host "Scanning for FPGA bitstream/firmware files." -ForegroundColor Yellow
Write-Host ""

$bitstreamExt = @('*.bit', '*.rbf', '*.bin')
$dmaKeywords = @('pcileech', 'squirrel', 'dma', 'fpga', 'pcileech-fpga', 'lambdaconcept')
$scanDirs = @(
    [Environment]::GetFolderPath('UserProfile') + "\Downloads",
    $env:TEMP,
    $env:LOCALAPPDATA,
    $env:APPDATA
)
$foundSuspicious = $false
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir -ErrorAction SilentlyContinue)) { continue }
    try {
        Get-ChildItem $dir -Recurse -Include $bitstreamExt -ErrorAction Stop | ForEach-Object {
            $foundSuspicious = $true
            Yellow "FPGA bitstream/firmware: $($_.FullName)"
        }
        Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $name = $_.Name.ToLower()
            ($dmaKeywords | Where-Object { $name -like "*$_*" }).Count -gt 0
        } | Select-Object -First 30 | ForEach-Object {
            $foundSuspicious = $true
            Yellow "DMA/fpga-related name: $($_.FullName)"
        }
    } catch {
        Red "Scan of $dir failed: $($_.Exception.Message)"
    }
}
if (-not $foundSuspicious) { Green "No FPGA bitstreams or obvious DMA-related filenames found in user folders." }
else { Red "Review the files above - FPGA/DMA firmware or tools may be present." }
Pause-AndScroll "FPGA / DMA FIRMWARE SCAN"
Write-Host ""

# --- [11/16] Memory baseline note (continuous monitoring runs during process list) ---
Write-Host "=== [11/16] MEMORY & COUNTER BASELINE ===" -ForegroundColor Cyan
Write-Host "Memory timing is monitored continuously while the process list runs below. Press CTRL+C to stop and see your score." -ForegroundColor Yellow
Write-Host ""

# --- [12/16] Vulnerable drivers & kernel debugger (bypass hardening) ---
Write-Host "=== [12/16] VULNERABLE DRIVERS & KERNEL DEBUGGER ===" -ForegroundColor Cyan
Write-Host "Checking for known vulnerable drivers (capcom.sys, gdrv.sys, etc.) and kernel debugger." -ForegroundColor Yellow
Write-Host ""

$vulnDrivers = @('capcom.sys', 'gdrv.sys', 'DBUtil_2_3.sys', 'AsIO.sys', 'RTCore64.sys', 'PROCEXP152.sys')
$driversPath = Join-Path $env:SystemRoot "System32\drivers"
$foundVuln = $false
try {
    foreach ($name in $vulnDrivers) {
        $p = Join-Path $driversPath $name
        if (Test-Path $p -ErrorAction Stop) {
            $foundVuln = $true
            Red "VULNERABLE DRIVER PRESENT: $name - used for kernel execution / memory access. Remove or block."
        }
    }
    if (-not $foundVuln) { Green "No known vulnerable drivers found in System32\drivers." }
} catch {
    Red "Driver path check failed: $($_.Exception.Message)"
}

try {
    $sm = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction Stop
    if ($sm.GlobalFlag -and $sm.GlobalFlag -ne 0) {
        Yellow "Session Manager GlobalFlag set - possible debugging / bypass environment."
    }
    $bcd = & bcdedit /enum 2>$null
    if ($bcd -match 'debug\s+Yes') {
        Yellow "Boot configuration has debug enabled - possible kernel debugging."
    }
    if ($bcd -match 'testsigning\s+Yes') {
        Red "Test signing is ON - kernel can load unsigned drivers. Disable for integrity."
    }
} catch {
    if ($_.Exception.Message -notmatch 'Cannot find') { Red "Session Manager registry read failed." }
}
Pause-AndScroll "VULNERABLE DRIVERS / DEBUGGER"
Write-Host ""

# --- [13/16] Startup / Run keys ---
Write-Host "=== [13/16] STARTUP / RUN KEYS ===" -ForegroundColor Cyan
Write-Host "Persistence via Run/RunOnce. Blocked reads = possible tampering." -ForegroundColor Yellow
Write-Host ""

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($rk in $runKeys) {
    try {
        $val = Get-ItemProperty $rk -ErrorAction Stop
        $val.PSObject.Properties | Where-Object { $_.Name -notmatch '^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)' } | ForEach-Object {
            $exePath = $_.Value -replace '^[""]?([^""]+).*', '$1'
            Write-Host "  $($_.Name) => $exePath" -ForegroundColor White
            if ($exePath -match '\.(exe|dll|bat|cmd)$' -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                $sig = Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue
                if ($sig -and $sig.Status -ne 'Valid') {
                    Red "    ^^ UNSIGNED or INVALID signature - suspicious"
                }
            }
        }
    } catch {
        if ($_.Exception.Message -match 'Cannot find path') {
            Green "  (no entries or key missing - ok)"
        } else {
            Red "  Run key read failed for $rk : $($_.Exception.Message)"
            Red "  Possible tampering or access denied."
        }
    }
}
Pause-AndScroll "STARTUP / RUN KEYS"
Write-Host ""

# --- [14/16] Malwarebytes ---
Write-Host "=== [14/16] MALWAREBYTES EXCLUSIONS ===" -ForegroundColor Cyan
$mbPath = "HKLM:\SOFTWARE\Malwarebytes"
try {
    if (Test-Path $mbPath -ErrorAction Stop) {
        $mb = Get-ChildItem $mbPath -Recurse -ErrorAction Stop
        if ($mb) {
            Red "Malwarebytes registry entries detected:"
            $mb | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Red }
        } else { Green "No suspicious Malwarebytes registry entries" }
    } else { Yellow "Malwarebytes not detected on this system" }
} catch {
    Red "Malwarebytes registry read failed: $($_.Exception.Message)"
    Red "Possible access denied - treat as suspicious."
}
Pause-AndScroll "MALWAREBYTES SECTION"
Write-Host ""

# --- [15/16] Downloads scan + Authenticode ---
Write-Host "=== [15/16] DOWNLOADS FOLDER SCAN ===" -ForegroundColor Cyan
Write-Host "Scanning for executables and scripts in Downloads. Unsigned = flag." -ForegroundColor Yellow
Write-Host ""

$downloadsDir = [Environment]::GetFolderPath('UserProfile') + "\Downloads"
try {
    Get-ChildItem $downloadsDir -Recurse -ErrorAction Stop | Where-Object { $_.Extension -match "\.(exe|dll|sys|bat|ps1|vbs|cmd)$" } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 40 | ForEach-Object {
            Write-Host "$($_.LastWriteTime)  |  $($_.FullName)" -ForegroundColor Yellow
            $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -ne 'Valid') {
                Red "  ^^ UNSIGNED or INVALID - review"
            }
        }
} catch {
    Red "Downloads folder access denied or error: $($_.Exception.Message)"
    Red "Possible tampering or blocking - check could not complete."
}

Write-Host ""
Write-Host "[INSTRUCTION] Look for:" -ForegroundColor Magenta
Write-Host "  - Cheat EXEs, injectors, DLLs" -ForegroundColor White
Write-Host "  - ZIP extractions of cheat tools" -ForegroundColor White
Pause-AndScroll "DOWNLOADS SCAN"
Write-Host ""

# --- [16/16] Live process monitor + memory timing (no whitelist; press CTRL+C for score) ---
Write-Host "=== [16/16] LIVE PROCESS MONITOR + MEMORY TIMING ===" -ForegroundColor Cyan
Write-Host "Monitoring ALL new processes and memory counters. No whitelist - every new process is listed." -ForegroundColor White
Write-Host "Press CTRL+C to stop and see your session score." -ForegroundColor Yellow
Write-Host ""

$known = @{}
$sessionNewProcesses = 0
$sessionMemorySpikes = 0
$sessionVulnDriverLoads = 0
$lastMemBytes = $null
$loopCount = 0
$loadedVulnDriversSeen = @{}
$vulnDriverNames = @('gdrv.sys', 'capcom.sys', 'DBUtil_2_3.sys', 'AsIO.sys', 'RTCore64.sys', 'PROCEXP152.sys')
try {
    Get-Process -ErrorAction Stop | ForEach-Object { $known[$_.Id] = $_.ProcessName }
} catch {
    Red "Initial process snapshot failed: $($_.Exception.Message)"
}

Write-Host "Baseline captured. Watching for new processes, memory spikes, and loaded vulnerable drivers..." -ForegroundColor Green
Write-Host ""

trap { break }

while ($true) {
    Start-Sleep -Seconds 1
    $loopCount++

    # Memory timing check every 5 seconds while process list runs
    if (($loopCount % 5) -eq 0) {
        try {
            $memNow = (Get-Counter '\Memory\Committed Bytes' -ErrorAction Stop).CounterSamples.CookedValue
            if ($null -ne $lastMemBytes -and $lastMemBytes -gt 0) {
                $pct = [Math]::Abs($memNow - $lastMemBytes) / $lastMemBytes
                if ($pct -gt 0.15) {
                    $sessionMemorySpikes++
                    $ts = Get-Date -Format "HH:mm:ss"
                    Red "[$ts] *** MEMORY SPIKE DETECTED *** (committed change ~$([Math]::Round($pct * 100))%)"
                }
            }
            $lastMemBytes = $memNow
        } catch { }

        # Check for vulnerable drivers LOADED in kernel (ring 0) - catches gdrv.sys/capcom.sys load + ring 0 execution e.g. DbgPrint
        try {
            $loaded = Get-CimInstance Win32_SystemDriver -ErrorAction Stop
            foreach ($drv in $loaded) {
                $path = $drv.PathName
                if (-not $path) { continue }
                $pathLower = $path.ToLower()
                foreach ($vuln in $vulnDriverNames) {
                    if ($pathLower -like "*$($vuln.ToLower())*" -and -not $loadedVulnDriversSeen[$path]) {
                        $loadedVulnDriversSeen[$path] = $true
                        $sessionVulnDriverLoads++
                        $ts = Get-Date -Format "HH:mm:ss"
                        Red "[$ts] *** VULNERABLE DRIVER LOADED (RING 0) ***: $vuln"
                        Red "    Path: $path - Ring 0 code (e.g. DbgPrint) may be executing."
                    }
                }
            }
        } catch { }
    }

    $current = $null
    try { $current = Get-Process -ErrorAction Stop }
    catch { continue }
    if (-not $current) { continue }

    foreach ($proc in $current) {
        if (-not $known.ContainsKey($proc.Id)) {
            $procPath = $null
            try { $procPath = $proc.Path }
            catch { }

            $timestamp = Get-Date -Format "HH:mm:ss"
            $hash = ""
            try {
                if ($procPath -and (Test-Path $procPath -ErrorAction SilentlyContinue)) {
                    $hash = (Get-FileHash $procPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                }
            } catch { }

            $sessionNewProcesses++
            Write-Host "[$timestamp] NEW PROCESS" -ForegroundColor Red -NoNewline
            Write-Host " | Name: " -NoNewline
            Write-Host $proc.ProcessName -ForegroundColor Yellow -NoNewline
            Write-Host " | PID: $($proc.Id)" -ForegroundColor White
            if ($procPath) { Write-Host "          Path: $procPath" -ForegroundColor DarkYellow }
            else { Write-Host "          Path: (access denied or unknown)" -ForegroundColor Red }
            if ($hash) { Write-Host "          MD5:  $hash" -ForegroundColor DarkCyan }
            try {
                $start = $proc.StartTime
                if ($start) { Write-Host "          Started: $start" -ForegroundColor DarkGray }
            } catch { }
            try {
                $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                if ($cim -and $cim.ParentProcessId) { Write-Host "          Parent PID: $($cim.ParentProcessId)" -ForegroundColor DarkGray }
                if ($cim -and $cim.CommandLine) { Write-Host "          CmdLine: $($cim.CommandLine)" -ForegroundColor DarkGray }
            } catch { }

            $known[$proc.Id] = $proc.ProcessName
        }
    }

    $currentIds = $current | Select-Object -ExpandProperty Id
    $deadIds = @($known.Keys | Where-Object { $_ -notin $currentIds })
    foreach ($id in $deadIds) { $known.Remove($id) }
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "              SESSION SCORE                  " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
$score = 100
$score -= ($sessionNewProcesses * 2)
$score -= ($sessionMemorySpikes * 15)
$score -= ($sessionVulnDriverLoads * 30)
if ($score -lt 0) { $score = 0 }
Write-Host "New processes this session     : $sessionNewProcesses" -ForegroundColor White
Write-Host "Memory spikes this session    : $sessionMemorySpikes" -ForegroundColor $(if ($sessionMemorySpikes -gt 0) { "Red" } else { "Green" })
Write-Host "Vuln driver loaded (ring 0)   : $sessionVulnDriverLoads" -ForegroundColor $(if ($sessionVulnDriverLoads -gt 0) { "Red" } else { "Green" })
Write-Host "SCORE: $score / 100" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" })
Write-Host "=============================================" -ForegroundColor Cyan
