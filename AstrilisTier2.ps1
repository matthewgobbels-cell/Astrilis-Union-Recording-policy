Clear-Host

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $hostExe = (Get-Process -Id $PID).Path
    if ($PSCommandPath) {
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
        Start-Process -FilePath $hostExe -ArgumentList $argList -Wait | Out-Null
        exit
    }
    $tempScript = Join-Path $env:TEMP 'Astrilis_Union_Tier_2.ps1'
    try {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/LOCJDUPDATER/LOCT2UPDATER/main/Loc_Tier_2.ps1' -OutFile $tempScript -UseBasicParsing
        Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$tempScript`"") -Wait | Out-Null
    } catch {
        Write-Warning "WinForms steps need STA mode. Use: powershell -STA -ExecutionPolicy Bypass -File `"<script.ps1>`""
    }
    exit
}

$script:WinFormsLoaded = $false
function Initialize-WinForms {
    if (-not $script:WinFormsLoaded) {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $script:WinFormsLoaded = $true
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$script:LocTier2Version = '2.6.5'

function Open-LocalMachineRegistryKey {
    param([string]$SubKeyPath)

    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        if ([string]::IsNullOrWhiteSpace($SubKeyPath)) { return $base }
        return $base.OpenSubKey($SubKeyPath)
    } catch {
        return $null
    }
}

function Add-RegistryKeyFingerprint {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$Prefix,
        [System.Collections.Generic.List[string]]$Parts
    )

    foreach ($name in $Key.GetValueNames()) {
        $raw = $Key.GetValue($name)
        if ($null -eq $raw) {
            $Parts.Add("$Prefix|$name=")
        } elseif ($raw -is [byte[]]) {
            $Parts.Add("$Prefix|$name=0x$([BitConverter]::ToString($raw).Replace('-', ''))")
        } else {
            $Parts.Add("$Prefix|$name=$raw")
        }
    }

    foreach ($subName in $Key.GetSubKeyNames()) {
        $subKey = $Key.OpenSubKey($subName)
        if ($subKey) {
            Add-RegistryKeyFingerprint -Key $subKey -Prefix "$Prefix\$subName" -Parts $Parts
            $subKey.Close()
        } else {
            $Parts.Add("$Prefix\$subName=<missing>")
        }
    }
}

# ===============================
# ASCII Banner (ASTRILIS UNION RECORDING POLICY T2)
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
Write-Host "Astrilis Union Tier 2 v$($script:LocTier2Version)" -ForegroundColor White
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
        Write-Host "`r[ $bar ] $percent%" -NoNewline
        Start-Sleep -Milliseconds 60
    }
    Write-Host ""
}

function Write-Section {
    param($Title, $Lines)

    if (-not $Lines -or $Lines.Count -eq 0) { return }
    Write-Host $Title -ForegroundColor Cyan
    foreach ($line in $Lines) {
        if ($line -like "SUCCESS*") { Write-Host "  $line" -ForegroundColor Green }
        elseif ($line -like "FAILURE*") { Write-Host "  $line" -ForegroundColor Red }
        elseif ($line -like "WARNING*") { Write-Host "  $line" -ForegroundColor Yellow }
        else { Write-Host "  $line" -ForegroundColor Gray }
    }
    Write-Host ""
}

function Wait-NextStep {
    param(
        [string]$Prompt,
        [string]$Label
    )
    Read-Host $Prompt | Out-Null
    Clear-Host
    Write-Host $Label -ForegroundColor Cyan
}

function Invoke-ToolDownload {
    param(
        [string]$Url,
        [string]$ZipPath,
        [string]$DestDir
    )

    if (-not $Url -or -not $ZipPath -or -not $DestDir) { return $false }

    try {
        $zipParent = Split-Path $ZipPath -Parent
        if ($zipParent -and -not (Test-Path $zipParent)) {
            New-Item -ItemType Directory -Path $zipParent -Force | Out-Null
        }
        if (-not (Test-Path $DestDir)) {
            New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
        }

        if (Test-Path -LiteralPath $ZipPath) {
            Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        }

        $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $downloaded = $false
        foreach ($attempt in 1..2) {
            try {
                Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 120 `
                    -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' | Out-Null
                if ((Test-Path -LiteralPath $ZipPath) -and ((Get-Item -LiteralPath $ZipPath).Length -gt 1024)) {
                    $downloaded = $true
                    break
                }
            } catch {
                if ($attempt -eq 2) { throw }
                Start-Sleep -Seconds 2
            }
        }

        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if (-not $downloaded) { return $false }

        if (Test-Path $DestDir) {
            Remove-Item -LiteralPath $DestDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null

        if (-not (Expand-ToolArchive -ZipPath $ZipPath -DestDir $DestDir)) { return $false }
        return $true
    } catch {
        Write-Warning "Download failed: $($_.Exception.Message)"
        return $false
    }
}

function Expand-ToolArchive {
    param(
        [string]$ZipPath,
        [string]$DestDir
    )

    try {
        Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force
        return $true
    } catch {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            if (-not (Test-Path $DestDir)) {
                New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
            }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestDir)
            return $true
        } catch {
            return $false
        }
    }
}

function Resolve-ToolExecutable {
    param(
        [string]$DestDir,
        [string]$ExeName,
        [string[]]$FallbackNames = @()
    )

    foreach ($name in @($ExeName) + @($FallbackNames)) {
        $direct = Join-Path $DestDir $name
        if (Test-Path -LiteralPath $direct) { return $direct }
    }

    foreach ($name in @($ExeName) + @($FallbackNames)) {
        $found = Get-ChildItem -Path $DestDir -Filter $name -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    return $null
}

function Start-AstrilisUnionExternalTool {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ZipPath,
        [string]$DestDir,
        [string]$ExeName,
        [string[]]$FallbackExeNames = @(),
        [string[]]$StartArguments = @(),
        [switch]$Wait,
        [ValidateSet('Normal', 'Maximized')]
        [string]$WindowStyle = 'Normal'
    )

    $exe = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        if ($attempt -gt 1) {
            Remove-Item -LiteralPath $DestDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        }

        $exe = Resolve-ToolExecutable -DestDir $DestDir -ExeName $ExeName -FallbackNames $FallbackExeNames
        if (-not $exe) {
            if (-not (Invoke-ToolDownload -Url $Url -ZipPath $ZipPath -DestDir $DestDir)) { continue }
            $exe = Resolve-ToolExecutable -DestDir $DestDir -ExeName $ExeName -FallbackNames $FallbackExeNames
        }

        if ($exe) { break }
    }

    if (-not $exe) {
        Write-Host "FAILED: $Name unavailable (download blocked, AV, or extract failed)." -ForegroundColor Red
        return $false
    }

    try { Unblock-File -LiteralPath $exe -ErrorAction SilentlyContinue } catch {}

    try {
        $startParams = @{
            FilePath         = $exe
            WorkingDirectory = Split-Path -Parent $exe
            WindowStyle      = $WindowStyle
            PassThru         = $true
            ErrorAction      = 'Stop'
        }
        if ($StartArguments.Count -gt 0) { $startParams['ArgumentList'] = $StartArguments }

        Write-Host "Launching $Name..." -ForegroundColor Green
        $proc = Start-Process @startParams
        if ($Wait) { $proc.WaitForExit() }
        Write-Host "OK: $Name opened." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "FAILED: $Name could not start - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Complete-AstrilisUnionToolStep {
    param(
        [string]$Name,
        [bool]$Succeeded
    )

    Write-Host ""
    if (-not $Succeeded) {
        Write-Host "Step skipped - $Name did not open. Check firewall/AV or run as admin." -ForegroundColor Yellow
    }
    Read-Host "Press Enter to continue" | Out-Null
    Write-Host ""
}

function Show-WinObjCheckGuide {
    Write-Host "Must navigate to Sessions > 0 > DosDevices and expand each subfolder." -ForegroundColor Yellow
    Write-Host ""
}

function Show-AutorunsCheckGuide {
    Write-Host "Wait for it to say 'Ready' in bottom left before scrolling." -ForegroundColor Yellow
    Write-Host ""
}

function Get-BamDevicePath {
    param([string]$Remainder)

    foreach ($drive in Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue) {
        if ($drive.Name -notmatch '^[A-Z]$') { continue }
        $candidate = "$($drive.Name):\$Remainder"
        if (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }

    return "$env:SystemDrive\$Remainder"
}

function Get-ActivityModeratorEntries {
    param([int]$SignatureBudget = 100)

    $entries = @()
    $seen = @{}
    $signaturesChecked = 0
    $roots = @(
        'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
    )

    foreach ($root in $roots) {
        $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root
        if (-not $rootKey) { continue }

        foreach ($sidName in $rootKey.GetSubKeyNames()) {
            if ($sidName -eq 'S-1-5-18') { continue }

            $sidKey = $rootKey.OpenSubKey($sidName)
            if (-not $sidKey) { continue }

            foreach ($valueName in $sidKey.GetValueNames()) {
                try {
                    $raw = $sidKey.GetValue($valueName)
                    if ($raw -isnot [byte[]] -or $raw.Length -lt 8) { continue }

                    $fileTime = [BitConverter]::ToInt64($raw, 0)
                    if ($fileTime -le 0) { continue }

                    $execTime = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
                    $exe = Split-Path $valueName -Leaf
                    $path = ""

                    if ($valueName -match '^\\Device\\HarddiskVolume\d+\\(.+)$') {
                        $path = Get-BamDevicePath -Remainder $matches[1]
                    } elseif ($valueName -match '^\\??\\(.+)$') {
                        $path = Get-BamDevicePath -Remainder $matches[1]
                    }

                    $dedupeKey = "$exe|$path|$($execTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    if ($seen.ContainsKey($dedupeKey)) { continue }
                    $seen[$dedupeKey] = $true

                    $sigStatus = "N/A"
                    if ($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
                        if ($signaturesChecked -lt $SignatureBudget) {
                            try {
                                $sig = Get-AuthenticodeSignature -LiteralPath $path
                                $sigStatus = if ($sig.Status -eq "Valid") { "Valid" } else { "Invalid" }
                            } catch {
                                $sigStatus = "Invalid"
                            }
                            $signaturesChecked++
                        } else {
                            $sigStatus = "N/A"
                        }
                    }

                    $timeText = $execTime.ToString("yyyy-MM-dd HH:mm:ss")
                    $entries += [PSCustomObject]@{
                        'Examiner Time'       = $timeText
                        'Last Execution Time' = $timeText
                        'Application'         = $exe
                        'Path'                = $path
                        'Signature'           = $sigStatus
                    }
                } catch { continue }
            }

            $sidKey.Close()
        }

        $rootKey.Close()
    }

    return $entries
}

function Get-CheatFolderHits {
    $hits = New-Object 'System.Collections.Generic.HashSet[string]'
    $scanPaths = @(
        (Join-Path $env:USERPROFILE "Downloads"),
        (Join-Path $env:USERPROFILE "Desktop"),
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:ProgramData,
        $env:TEMP,
        "$env:SystemDrive\"
    )

    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }

        $maxDepth = 2
        if ($scanPath -eq "$env:SystemDrive\") { $maxDepth = 1 }

        Get-ChildItem -Path $scanPath -Directory -Recurse -Depth $maxDepth -ErrorAction SilentlyContinue | ForEach-Object {
            $nameLower = $_.Name.ToLower()
            $matched = Get-MatchedCheatKeyword -Text $nameLower -FolderName
            if ($matched) { [void]$hits.Add($_.FullName) }
        }
    }

    return @($hits)
}

function Get-Exclusions {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        foreach ($item in @($prefs.ExclusionPath) + @($prefs.ExclusionProcess) + @($prefs.ExclusionExtension)) {
            if ($item) { [void]$list.Add([string]$item) }
        }
    } catch {}

    $regRoots = @(
        'SOFTWARE\Microsoft\Windows Defender\Exclusions',
        'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
    )
    $regTypes = @('Paths', 'Processes', 'Extensions')

    foreach ($root in $regRoots) {
        foreach ($type in $regTypes) {
            try {
                $key = Open-LocalMachineRegistryKey -SubKeyPath "$root\$type"
                if (-not $key) { continue }
                foreach ($name in $key.GetValueNames()) {
                    if ($name) { [void]$list.Add($name) }
                }
                $key.Close()
            } catch {}
        }
    }

    return @($list)
}

$script:DefenderExclusionsRegRoots = @(
    'SOFTWARE\Microsoft\Windows Defender\Exclusions',
    'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
)
$script:DefenderThreatsRegRoots = @(
    'SOFTWARE\Microsoft\Windows Defender\Threats',
    'SOFTWARE\Policies\Microsoft\Windows Defender\Threats'
)
$script:DefenderThreatsSystemSubkeys = @(
    'ThreatSeverityDefaultAction',
    'ThreatIDDefaultAction',
    'ThreatTypeDefaultAction'
)

function Get-RegistrySubtreeFingerprint {
    param([string]$RelativePath)

    $parts = New-Object 'System.Collections.Generic.List[string]'

    try {
        $root = Open-LocalMachineRegistryKey -SubKeyPath $RelativePath
        if (-not $root) { return 'MISSING' }
        Add-RegistryKeyFingerprint -Key $root -Prefix $RelativePath -Parts $parts
        $root.Close()
    } catch {
        return 'ERROR'
    }

    if ($parts.Count -eq 0) { return 'EMPTY' }
    return ($parts | Sort-Object) -join '|'
}

function Get-DefenderRegistryMonitorLabels {
    $labels = @{}
    foreach ($root in $script:DefenderExclusionsRegRoots) {
        $labels[$root] = "Defender Exclusions registry ($root)"
    }
    foreach ($root in $script:DefenderThreatsRegRoots) {
        $labels[$root] = "Defender Threats registry ($root)"
    }
    return $labels
}

function Get-DefenderRegistryFingerprints {
    $fps = @{}
    foreach ($root in ($script:DefenderExclusionsRegRoots + $script:DefenderThreatsRegRoots)) {
        $fps[$root] = Get-RegistrySubtreeFingerprint -RelativePath $root
    }
    return $fps
}

function Get-AllowedDefenderThreats {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($relPath in @(
        'SOFTWARE\Microsoft\Windows Defender\Exclusions\Threats',
        'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Threats'
    )) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $relPath
            if (-not $key) { continue }
            foreach ($name in $key.GetValueNames()) {
                if ($name) { [void]$list.Add("$relPath -> $name") }
            }
            foreach ($subName in $key.GetSubKeyNames()) {
                [void]$list.Add("$relPath\$subName")
            }
            $key.Close()
        } catch {}
    }

    foreach ($root in $script:DefenderThreatsRegRoots) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $root
            if (-not $key) { continue }
            foreach ($subName in $key.GetSubKeyNames()) {
                if ($script:DefenderThreatsSystemSubkeys -contains $subName) { continue }
                if ($subName -match '(?i)^\{?[0-9A-F-]{36}\}?$|^\d+$') {
                    [void]$list.Add("$root\$subName")
                }
            }
            $key.Close()
        } catch {}
    }

    return @($list)
}

function Get-DefenderStatusAlerts {
    $alerts = @()

    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        if (-not $def.RealTimeProtectionEnabled) {
            $alerts += 'FAILURE: Real-time protection disabled'
        }
        if (-not $def.IsTamperProtected) {
            $alerts += 'WARNING: Tamper protection disabled'
        }
    } catch {
        $alerts += 'WARNING: Defender status unavailable'
    }

    foreach ($disableKey in @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    )) {
        try {
            $disabled = Get-ItemPropertyValue -Path $disableKey -Name 'DisableAntiSpyware' -ErrorAction Stop
            if ($disabled -eq 1) { $alerts += 'FAILURE: DisableAntiSpyware active' }
        } catch {}
    }

    return $alerts
}

function Get-RegistryToolProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    foreach ($procName in @('regedit.exe', 'reg.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $procId = [int]$_.ProcessId
                if (-not $seen.Add($procId)) { return }
                $path = [string]$_.ExecutablePath
                $cmd = [string]$_.CommandLine
                $label = "$procName (PID $procId)"
                if ($path) { $label += " -> $path" }
                if ($cmd) { $label += " [$cmd]" }
                $messages += $label
            }
        } catch {}
    }

    return $messages
}

$script:WindhawkProcessName = 'windhawk.exe'
$script:WindhawkWatchPaths = @(
    'C:\Users\Stef\Downloads\windhawk.exe',
    (Join-Path $env:USERPROFILE 'Downloads\windhawk.exe'),
    (Join-Path ${env:ProgramFiles} 'Windhawk\windhawk.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Windhawk\windhawk.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Windhawk\windhawk.exe')
)

function Get-WindhawkProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    try {
        Get-CimInstance Win32_Process -Filter "Name='$($script:WindhawkProcessName)'" -ErrorAction Stop | ForEach-Object {
            $procId = [int]$_.ProcessId
            if (-not $seen.Add($procId)) { return }
            $path = [string]$_.ExecutablePath
            $label = "$($script:WindhawkProcessName) (PID $procId)"
            if ($path) { $label += " -> $path" }
            $messages += $label
        }
    } catch {}

    return $messages
}

function Get-WindhawkStep1Alerts {
    $alerts = @()
    $hits = @(Get-WindhawkProcessHits)

    if ($hits.Count -gt 0) {
        foreach ($hit in $hits) {
            $alerts += "FAILURE: Windhawk running $hit"
        }
        return $alerts
    }

    $foundPaths = @()
    foreach ($p in ($script:WindhawkWatchPaths | Select-Object -Unique)) {
        if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
            $foundPaths += $p
        }
    }
    if ($foundPaths.Count -gt 0) {
        foreach ($p in $foundPaths) {
            $alerts += "WARNING: Windhawk found $p"
        }
        return $alerts
    }

    $alerts += 'SUCCESS: Windhawk not detected'
    return $alerts
}

function Get-PrefetchLastRunTime {
    param([string]$FilePath)

    try {
        $fs = [System.IO.File]::OpenRead($FilePath)
        try {
            $buffer = New-Object byte[] 144
            $read = $fs.Read($buffer, 0, $buffer.Length)
            if ($read -lt 24) { return "Unknown" }

            $version = [BitConverter]::ToInt32($buffer, 0)
            $candidates = @()

            if ($read -ge 24) {
                $candidates += [BitConverter]::ToInt64($buffer, 16)
            }
            if ($read -ge 136 -and $version -ge 26) {
                $candidates += [BitConverter]::ToInt64($buffer, 128)
            }

            foreach ($fileTime in $candidates) {
                if ($fileTime -le 0) { continue }
                try {
                    $dt = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
                    if ($dt.Year -ge 2000 -and $dt.Year -le 2100) {
                        return $dt.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                } catch {}
            }
            return "Unknown"
        } finally {
            $fs.Close()
        }
    } catch {
        return "Unknown"
    }
}

function Get-BamRegistryFingerprints {
    $fps = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $roots = @(
        'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
    )

    foreach ($root in $roots) {
        try {
            $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root
            if (-not $rootKey) { continue }

            foreach ($sidName in $rootKey.GetSubKeyNames()) {
                if ($sidName -eq 'S-1-5-18') { continue }
                $sidKey = $rootKey.OpenSubKey($sidName)
                if (-not $sidKey) { continue }

                foreach ($valueName in $sidKey.GetValueNames()) {
                    if ($valueName) { [void]$fps.Add("$root|$sidName|$valueName") }
                }
                $sidKey.Close()
            }
            $rootKey.Close()
        } catch {}
    }

    return @($fps)
}

function Get-PrefetchFileNames {
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (-not (Test-Path $prefetchPath)) { return @($names) }

    try {
        Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction Stop | ForEach-Object {
            [void]$names.Add($_.Name)
        }
    } catch {}

    return @($names)
}

function Get-TamperLogEvents {
    param([datetime]$Since)

    $events = @()
    $filters = @(
        @{ LogName = 'Security'; Id = 1102 },
        @{ LogName = 'System'; Id = 104 },
        @{ LogName = 'Microsoft-Windows-Eventlog/Operational'; Id = 104 }
    )

    foreach ($filter in $filters) {
        try {
            $filter.StartTime = $Since
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object { $events += $_ }
        } catch {}
    }

    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = 23
            StartTime = $Since
        } -ErrorAction Stop | Where-Object {
            $_.Message -match '(?i)\\Prefetch\\|\\bam\\|\\dam\\|UserSettings'
        } | ForEach-Object { $events += $_ }
    } catch {}

    return $events
}

function Write-MonitorAlert {
    param(
        [string]$Message,
        [string]$LogFile,
        [string]$Color = 'White'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    try {
        Add-Content -LiteralPath $LogFile -Value "[$timestamp] $Message" -ErrorAction Stop
    } catch {
        $fallback = Join-Path $env:TEMP 'astrilis_union_tier2_security_events.log'
        try { Add-Content -LiteralPath $fallback -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue } catch {}
    }
}

function Convert-UserAssistName {
    param([string]$Name)

    if ([string]::IsNullOrEmpty($Name)) { return $Name }
    $chars = $Name.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int][char]$chars[$i]
        if ($c -ge 65 -and $c -le 90) { $chars[$i] = [char](((($c - 65 + 13) % 26) + 65)) }
        elseif ($c -ge 97 -and $c -le 122) { $chars[$i] = [char](((($c - 97 + 13) % 26) + 97)) }
    }
    return -join $chars
}

$script:CursorSchemeValueNames = @(
    '(Default)', 'Arrow', 'Help', 'AppStarting', 'Wait', 'Crosshair', 'IBeam',
    'NWPen', 'No', 'SizeNS', 'SizeWE', 'SizeNWSE', 'SizeNESW', 'SizeAll',
    'UpArrow', 'Hand', 'CursorBaseSize'
)

function Expand-CursorPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-CursorSchemeState {
    $state = @{}
    $keyPath = 'HKCU:\Control Panel\Cursors'
    if (-not (Test-Path $keyPath)) { return $state }

    foreach ($name in $script:CursorSchemeValueNames) {
        try {
            $state[$name] = [string](Get-ItemPropertyValue -Path $keyPath -Name $name -ErrorAction Stop)
        } catch {
            $state[$name] = ''
        }
    }
    return $state
}

function Get-CursorSchemeChanges {
    param(
        [hashtable]$Baseline,
        [hashtable]$Current
    )

    $changes = @()
    foreach ($name in $script:CursorSchemeValueNames) {
        $old = if ($Baseline.ContainsKey($name)) { [string]$Baseline[$name] } else { '' }
        $new = if ($Current.ContainsKey($name)) { [string]$Current[$name] } else { '' }
        if ($old -eq $new) { continue }

        $displayOld = Expand-CursorPath $old
        $displayNew = Expand-CursorPath $new
        $msg = "$name changed: '$displayOld' -> '$displayNew'"

        if ($displayNew -match '(?i)\.(cur|ani)$' -and $displayNew -notmatch '(?i)\\windows\\cursors\\') {
            $msg += ' [non-standard cursor path]'
        }

        $kw = Get-MatchedCheatKeyword -Text $displayNew
        if ($kw) { $msg += " [keyword: $kw]" }

        $changes += $msg
    }
    return $changes
}

$script:NvidiaShadowPlayFtsRegPath = 'SOFTWARE\NVIDIA Corporation\Global\NvApp\ShadowPlay\FTS'
$script:NvidiaStreamproofGuid = '497B8458-4244-4EE6-BFEA-F3D2BA294F21'
$script:NvidiaStreamproofValues = @(36)

function Test-NvidiaStreamproofBypassActive {
    param($State)

    if (-not $State.Exists) { return $false }

    foreach ($entry in $State.Values.GetEnumerator()) {
        $nameNorm = $entry.Key.Trim('{}').ToLower()
        if ($nameNorm -ne $script:NvidiaStreamproofGuid.ToLower()) { continue }
        if ($entry.Value -isnot [int]) { continue }
        if ($script:NvidiaStreamproofValues -contains $entry.Value) { return $true }
    }

    return $false
}

function Get-NvidiaShadowPlayFtsAlerts {
    $alerts = @()
    $state = Get-NvidiaShadowPlayFtsState
    $nvidiaGpu = Test-NvidiaGpuPresent

    if (-not $nvidiaGpu) {
        $alerts += 'SUCCESS: NVIDIA ShadowPlay N/A'
        return $alerts
    }

    if (-not $state.Exists) {
        $alerts += 'SUCCESS: ShadowPlay FTS N/A'
        return $alerts
    }

    if (Test-NvidiaStreamproofBypassActive -State $state) {
        foreach ($entry in $state.Values.GetEnumerator()) {
            $nameNorm = $entry.Key.Trim('{}').ToLower()
            if ($nameNorm -ne $script:NvidiaStreamproofGuid.ToLower()) { continue }
            if ($entry.Value -isnot [int]) { continue }
            if ($script:NvidiaStreamproofValues -contains $entry.Value) {
                $alerts += "FAILURE: NVIDIA streamproof bypass ($($entry.Key)=$($entry.Value))"
            }
        }
        return $alerts
    }

    $alerts += 'SUCCESS: ShadowPlay FTS clean'
    return $alerts
}

function Test-NvidiaGpuPresent {
    try {
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name
        foreach ($gpu in $gpus) {
            if ($gpu -match '(?i)nvidia') { return $true }
        }
    } catch {}
    return $false
}

function Get-NvidiaShadowPlayFtsState {
    $state = @{
        Exists = $false
        Values = @{}
    }

    try {
        $key = Open-LocalMachineRegistryKey -SubKeyPath $script:NvidiaShadowPlayFtsRegPath
        if (-not $key) { return $state }

        $state.Exists = $true
        foreach ($name in $key.GetValueNames()) {
            $raw = $key.GetValue($name)
            if ($raw -is [int]) {
                $state.Values[$name] = [int]$raw
            } elseif ($raw -is [byte[]] -and $raw.Length -ge 4) {
                $state.Values[$name] = [BitConverter]::ToInt32($raw, 0)
            } else {
                $state.Values[$name] = [string]$raw
            }
        }
        $key.Close()
    } catch {}

    return $state
}

function Get-NvidiaShadowPlayFtsFingerprint {
    $state = Get-NvidiaShadowPlayFtsState
    if (-not $state.Exists) { return 'MISSING' }

    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in ($state.Values.Keys | Sort-Object)) {
        $parts.Add("$name=$($state.Values[$name])")
    }
    if ($parts.Count -eq 0) { return 'EMPTY' }
    return ($parts -join '|')
}

function Get-MainCplProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    foreach ($procName in @('rundll32.exe', 'control.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $procId = [int]$_.ProcessId
                if (-not $seen.Add($procId)) { return }
                $path = [string]$_.ExecutablePath
                $cmd = [string]$_.CommandLine
                $label = "$procName (PID $procId)"
                if ($path) { $label += " -> $path" }
                if ($cmd) { $label += " [$cmd]" }
                $messages += $label
            }
        } catch {}
    }

    return $messages
}
