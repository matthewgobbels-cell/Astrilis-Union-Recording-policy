[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:PSDefaultParameterValues = @{}
foreach ($__n in @(
    'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression','Test-Path','Get-Item',
    'Get-ChildItem','Get-ItemProperty','Get-ItemPropertyValue','Get-CimInstance','Get-WmiObject',
    'Get-Process','Start-Process','Get-Service','Get-WinEvent','Get-AuthenticodeSignature',
    'Get-Module','New-Item','Remove-Item','Add-Content'
)) {
    Microsoft.PowerShell.Management\Remove-Item -Path "Alias:\$__n" -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item -Path "Function:\$__n" -Force -ErrorAction SilentlyContinue
}

Clear-Host

$script:AstrilisUnionVersion = '1.3.0'
try { $Host.UI.RawUI.WindowTitle = "Astrilis Union v$($script:AstrilisUnionVersion) - Recording Check" } catch {}

$script:DiscordWebhookUrl = 'https://discord.com/api/webhooks/1562244671059525693/r57V01mUwNASYmPsHR_kQbZmejr4Ckk5tJ6BfEgWwR_XWuUcLtDDsPaptfPFsbAfDXte'$script:DetectedRobloxAccount = $null$script:MonitorEventLog = New-Object System.Collections.Generic.List[string]

# --- Entropy Calculation & Multi-Layer .cfg Detection Engine ---
try {
    if (-not ('AstrilisUnion.FastEntropy' -as [type])) {
        Add-Type -Namespace AstrilisUnion -Name FastEntropy -UsingNamespace System.IO, System.Collections.Generic, System.Diagnostics, System.Text, System.Text.RegularExpressions -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern IntPtr OpenFileById(IntPtr hVolumeHint, ref FILE_ID_DESCRIPTOR lpFileId, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwFlagsAndAttributes);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern uint GetFinalPathNameByHandleW(IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool CloseHandle(IntPtr hObject);

[StructLayout(LayoutKind.Sequential)]
private struct FILE_ID_DESCRIPTOR {
    public uint dwSize;
    public uint Type;
    public ulong FileId;
    public ulong Reserved;
}

public static double Compute(string filePath) {
    if (!System.IO.File.Exists(filePath)) return 0.0;
    try {
        using (var fs = new System.IO.FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite)) {
            int toRead = (int)System.Math.Min(fs.Length, 4194304L);
            if (toRead <= 0) return 0.0;
            byte[] buffer = new byte[toRead];
            int read = fs.Read(buffer, 0, toRead);
            if (read <= 0) return 0.0;
            int[] counts = new int[256];
            for (int i = 0; i < read; i++) {
                counts[buffer[i]]++;
            }
            double entropy = 0.0;
            double len = (double)read;
            for (int i = 0; i < 256; i++) {
                if (counts[i] > 0) {
                    double p = counts[i] / len;
                    entropy -= p * System.Math.Log(p, 2);
                }
            }
            return System.Math.Round(entropy, 3);
        }
    } catch {
        return -1.0;
    }
}

private static readonly HashSet<string> SkipDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
    "Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information",
    "Microsoft", "Packages", "Google", "BraveSoftware", "Mozilla", "Opera Software", "Vivaldi",
    "Discord", "Spotify", "Steam", "EpicGamesLauncher", "UnrealEngine", "NVIDIA", "NVIDIA Corporation",
    "AMD", "Intel", "Package Cache", "node_modules", ".git", ".gemini", ".vscode",
    "Application Data", "Local Settings", "NetHood", "PrintHood", "SendTo", "Start Menu", "Templates",
    "Cookies", "Recent", "OneDrive", "Roblox", "Bloxstrap", "Fishstrap", "CEF", "cache", ".cache", "Code Cache", "CBGames"
};

private static readonly Regex CfgRegex = new Regex(
    "(\"humanoid_root_part\"|\"silent_target_hrp\"|\"target_torso_r6\"|\"rage_bypass_ss\"|\"smoothcamlock\"|\"triggerbot_hitbox_expansion\"|\"rivals_skin_changer_enabled\"|\"walkspeed_enable\"|\"silent_?aim\"|\"cam_?lock\"|\"hitbox_?expand\"|\"skeleton_?esp\"|\"box_?esp\"|\"stream_?proof\"|\"jump_?power\"|\\[(Aimbot\vert{}SilentAim\vert{}Triggerbot\vert{}Ragebot)\\])",
    RegexOptions.IgnoreCase | RegexOptions.Compiled);

private static bool IsIgnoredCfgPath(string fullPath, bool strictRecentFilter) {
    if (string.IsNullOrEmpty(fullPath)) return true;
    string lower = fullPath.ToLowerInvariant();
    if (lower.Contains("\\windows\\") || lower.Contains("\\program files\\") || lower.Contains("\\program files (x86)\\") ||
        lower.Contains("\\steam\\") || lower.Contains("\\counter-strike\\") || lower.Contains("\\valve\\") ||
        lower.Contains("\\apex\\") || lower.Contains("\\call of duty\\") || lower.Contains("\\overwatch\\") ||
        lower.Contains("\\$recycle.bin\\") || lower.Contains("\\system volume information\\") ||
        lower.EndsWith("\\frm.cfg") || lower.EndsWith("\\crash_reporter.cfg") || lower.EndsWith("\\setup.cfg")) {
        return true;
    }
    if (strictRecentFilter) {
        if (lower.Contains("\\microsoft\\") || lower.Contains("\\packages\\") || lower.Contains("\\.cache\\") ||
            lower.Contains("\\cbgames\\") || lower.Contains("\\node_modules\\") || lower.Contains("\\.git\\") ||
            lower.Contains("\\.gemini\\") || lower.Contains("\\.vscode\\") || lower.Contains("\\package cache\\") ||
            lower.Contains("\\unrealengine\\") || lower.Contains("\\epicgameslauncher\\")) {
            return true;
        }
    }
    return false;
}

private static bool EndsWithCfgUnmanaged(IntPtr basePtr, int byteOffset, ushort nameLenBytes) {
    if (nameLenBytes < 8) return false;
    int pos = byteOffset + nameLenBytes - 8;
    char c0 = (char)Marshal.ReadInt16(basePtr, pos);
    if (c0 != '.') return false;
    char c1 = (char)Marshal.ReadInt16(basePtr, pos + 2);
    char c2 = (char)Marshal.ReadInt16(basePtr, pos + 4);
    char c3 = (char)Marshal.ReadInt16(basePtr, pos + 6);
    return (c1 == 'c' || c1 == 'C') && (c2 == 'f' || c2 == 'F') && (c3 == 'g' || c3 == 'G');
}

private static string ResolveFrnPath(IntPtr hVol, ulong frn, Dictionary<ulong, string> cache) {
    string cached;
    if (cache.TryGetValue(frn, out cached)) return cached;
    string result = "";
    FILE_ID_DESCRIPTOR fid = new FILE_ID_DESCRIPTOR();
    fid.dwSize = 24;
    fid.Type = 0;
    fid.FileId = frn;
    fid.Reserved = 0;
    IntPtr hDir = OpenFileById(hVol, ref fid, 0U, 7U, IntPtr.Zero, 0x02000000U);
    if (hDir != IntPtr.Zero && hDir != new IntPtr(-1)) {
        try {
            StringBuilder sb = new StringBuilder(1024);
            uint len = GetFinalPathNameByHandleW(hDir, sb, 1024U, 0U);
            if (len > 0 && len < 1024) {
                result = sb.ToString();
                if (result.StartsWith("\\\\?\\")) result = result.Substring(4);
            }
        } finally {
            CloseHandle(hDir);
        }
    }
    cache[frn] = result;
    return result;
}

private static void InspectCfgFile(string file, long sinceTicks, List<string> hits, HashSet<string> seenFiles) {
    if (string.IsNullOrEmpty(file) || !seenFiles.Add(file)) return;
    try {
        if (IsIgnoredCfgPath(file, false)) return;
        FileInfo fi = new FileInfo(file);
        if (!fi.Exists || fi.Length > 524288) return;
        bool isRecent = (sinceTicks > 0 && (fi.CreationTime.Ticks >= sinceTicks || fi.LastWriteTime.Ticks >= sinceTicks));
        if (fi.Length <= 32 && !isRecent) return;
        string owner = FindAssociatedBinary(file);
        string txt = fi.Length > 0 ? File.ReadAllText(file) : "";
        Match m = txt.Length > 0 ? CfgRegex.Match(txt) : Match.Empty;
        if (m.Success) {
            string key = m.Groups[1].Value.Trim('"', '[', ']');
            hits.Add("MATCH|" + key + "|" + file + "|" + owner + "|" + fi.LastWriteTime.Ticks);
        } else if (isRecent && !IsIgnoredCfgPath(file, true)) {
            hits.Add("RECENT|session|" + file + "|" + owner + "|" + Math.Max(fi.CreationTime.Ticks, fi.LastWriteTime.Ticks));
        }
    } catch {}
}

private static bool ScanMftAndUsnVolume(string driveRoot, long sinceTicks, List<string> hits, HashSet<string> seenFiles, HashSet<string> seenUsn) {
    if (string.IsNullOrEmpty(driveRoot)) return false;
    string volName = "\\\\.\\" + driveRoot.TrimEnd('\\');
    IntPtr hVol = CreateFileW(volName, 0x80000000U, 3U, IntPtr.Zero, 3U, 0U, IntPtr.Zero);
    if (hVol == IntPtr.Zero || hVol == new IntPtr(-1)) return false;

    IntPtr jBuf = Marshal.AllocHGlobal(64);
    IntPtr inBuf = Marshal.AllocHGlobal(64);
    IntPtr outBuf = Marshal.AllocHGlobal(65536);
    Dictionary<ulong, string> dirCache = new Dictionary<ulong, string>();
    bool mftSuccess = false;

    try {
        uint bytesRet = 0;
        if (!DeviceIoControl(hVol, 0x000900f4U, IntPtr.Zero, 0U, jBuf, 64U, out bytesRet, IntPtr.Zero)) {
            return false;
        }
        ulong journalId = (ulong)Marshal.ReadInt64(jBuf, 0);
        long firstUsn = Marshal.ReadInt64(jBuf, 8);
        long nextUsn = Marshal.ReadInt64(jBuf, 16);

        long startUsn = Math.Max(firstUsn, nextUsn - 67108864L);
        Marshal.WriteInt64(inBuf, 0, startUsn);
        Marshal.WriteInt32(inBuf, 8, unchecked((int)0xFFFFFFFF));
        Marshal.WriteInt32(inBuf, 12, 0);
        Marshal.WriteInt64(inBuf, 16, 0L);
        Marshal.WriteInt64(inBuf, 24, 0L);
        Marshal.WriteInt64(inBuf, 32, unchecked((long)journalId));

        while (DeviceIoControl(hVol, 0x000900bbU, inBuf, 40U, outBuf, 65536U, out bytesRet, IntPtr.Zero) && bytesRet > 8U) {
            long nextReadUsn = Marshal.ReadInt64(outBuf, 0);
            if (nextReadUsn <= startUsn) break;
            int offset = 8;
            while (offset + 60 <= (int)bytesRet) {
                int recLen = Marshal.ReadInt32(outBuf, offset);
                if (recLen <= 0) break;
                ushort majorVer = (ushort)Marshal.ReadInt16(outBuf, offset + 4);
                if (majorVer == 2) {
                    uint attr = (uint)Marshal.ReadInt32(outBuf, offset + 52);
                    if ((attr & 0x10U) == 0U) {
                        ushort nameLen = (ushort)Marshal.ReadInt16(outBuf, offset + 56);
                        ushort nameOff = (ushort)Marshal.ReadInt16(outBuf, offset + 58);
                        if (offset + nameOff + nameLen <= (int)bytesRet && EndsWithCfgUnmanaged(outBuf, offset + nameOff, nameLen)) {
                            long ftUtc = Marshal.ReadInt64(outBuf, offset + 32);
                            long localTicks = 0L;
                            try { localTicks = DateTime.FromFileTimeUtc(ftUtc).ToLocalTime().Ticks; } catch {}
                            if (sinceTicks <= 0 || localTicks >= sinceTicks) {
                                uint reason = (uint)Marshal.ReadInt32(outBuf, offset + 40);
                                if ((reason & 0x00003307U) != 0U) {
                                    ulong fileFrn = (ulong)Marshal.ReadInt64(outBuf, offset + 8);
                                    ulong parentFrn = (ulong)Marshal.ReadInt64(outBuf, offset + 16);
                                    string fileName = Marshal.PtrToStringUni(new IntPtr(outBuf.ToInt64() + offset + nameOff), nameLen / 2);
                                    string parentDir = ResolveFrnPath(hVol, parentFrn, dirCache);
                                    string fullPath = !string.IsNullOrEmpty(parentDir) ? Path.Combine(parentDir, fileName) : (driveRoot + fileName);
                                    if (!IsIgnoredCfgPath(fullPath, true)) {
                                        if (File.Exists(fullPath)) {
                                            InspectCfgFile(fullPath, sinceTicks, hits, seenFiles);
                                        }
                                        string act = "";
                                        if ((reason & 0x00000200U) != 0U) act = "Deleted";
                                        else if ((reason & 0x00001000U) != 0U) {
                                            string renamedTo = ResolveFrnPath(hVol, fileFrn, dirCache);
                                            act = !string.IsNullOrEmpty(renamedTo) ? ("Renamed -> " + Path.GetFileName(renamedTo)) : "Renamed";
                                        }
                                        else if ((reason & 0x00002000U) != 0U) act = "Renamed";
                                        else if ((reason & 0x00000100U) != 0U) act = "Created";
                                        else if ((reason & 0x00000007U) != 0U) act = "Edited/Saved";

                                        if (!string.IsNullOrEmpty(act)) {
                                            string usnKey = act + "|" + fullPath;
                                            if (seenUsn.Add(usnKey)) {
                                                string owner = FindAssociatedBinary(fullPath);
                                                hits.Add("USN|" + act + "|" + fullPath + "|" + owner + "|" + localTicks);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                offset += recLen;
            }
            startUsn = nextReadUsn;
            Marshal.WriteInt64(inBuf, 0, startUsn);
        }

        Marshal.WriteInt64(inBuf, 0, 0L);
        Marshal.WriteInt64(inBuf, 8, 0L);
        Marshal.WriteInt64(inBuf, 16, nextUsn);
        int mftPages = 0;
        while (DeviceIoControl(hVol, 0x000900b3U, inBuf, 24U, outBuf, 65536U, out bytesRet, IntPtr.Zero) && bytesRet > 8U) {
            mftPages++;
            long nextFrn = Marshal.ReadInt64(outBuf, 0);
            int offset = 8;
            while (offset + 60 <= (int)bytesRet) {
                int recLen = Marshal.ReadInt32(outBuf, offset);
                if (recLen <= 0) break;
                ushort majorVer = (ushort)Marshal.ReadInt16(outBuf, offset + 4);
                if (majorVer == 2) {
                    uint attr = (uint)Marshal.ReadInt32(outBuf, offset + 52);
                    if ((attr & 0x10U) == 0U) {
                        ushort nameLen = (ushort)Marshal.ReadInt16(outBuf, offset + 56);
                        ushort nameOff = (ushort)Marshal.ReadInt16(outBuf, offset + 58);
                        if (offset + nameOff + nameLen <= (int)bytesRet && EndsWithCfgUnmanaged(outBuf, offset + nameOff, nameLen)) {
                            ulong parentFrn = (ulong)Marshal.ReadInt64(outBuf, offset + 16);
                            string parentDir = ResolveFrnPath(hVol, parentFrn, dirCache);
                            if (!string.IsNullOrEmpty(parentDir)) {
                                string fileName = Marshal.PtrToStringUni(new IntPtr(outBuf.ToInt64() + offset + nameOff), nameLen / 2);
                                InspectCfgFile(Path.Combine(parentDir, fileName), sinceTicks, hits, seenFiles);
                            }
                        }
                    }
                }
                offset += recLen;
            }
            Marshal.WriteInt64(inBuf, 0, nextFrn);
        }
        if (mftPages > 0) mftSuccess = true;
    } catch {} finally {
        Marshal.FreeHGlobal(jBuf);
        Marshal.FreeHGlobal(inBuf);
        Marshal.FreeHGlobal(outBuf);
        CloseHandle(hVol);
    }
    return mftSuccess;
}

public static string[] ScanCheatConfigs(string[] extraDirs, long sinceTicks) {
    List<string> hits = new List<string>();
    HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    HashSet<string> seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    HashSet<string> seenUsn = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    HashSet<string> mftCoveredRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    try {
        foreach (DriveInfo d in DriveInfo.GetDrives()) {
            if (!d.IsReady) continue;
            if (d.DriveType == DriveType.Fixed) {
                if (ScanMftAndUsnVolume(d.RootDirectory.FullName, sinceTicks, hits, seenFiles, seenUsn)) {
                    mftCoveredRoots.Add(d.RootDirectory.FullName);
                }
            }
        }
    } catch {}

    string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    string tempPath = Path.GetTempPath();

    if (!mftCoveredRoots.Contains(Path.GetPathRoot(userProfile))) {
        ScanCfgDir(userProfile, 0, 4, sinceTicks, hits, visited, seenFiles);
        ScanCfgDir(appData, 0, 3, sinceTicks, hits, visited, seenFiles);
        ScanCfgDir(localAppData, 0, 3, sinceTicks, hits, visited, seenFiles);
        ScanCfgDir(progData, 0, 3, sinceTicks, hits, visited, seenFiles);
        ScanCfgDir(tempPath, 0, 2, sinceTicks, hits, visited, seenFiles);
    }

    if (extraDirs != null) {
        foreach (string ed in extraDirs) {
            if (!string.IsNullOrEmpty(ed) && Directory.Exists(ed)) {
                ScanCfgDir(ed, 0, 2, sinceTicks, hits, visited, seenFiles);
            }
        }
    }

    try {
        foreach (DriveInfo d in DriveInfo.GetDrives()) {
            if (!d.IsReady) continue;
            if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable) continue;
            if (mftCoveredRoots.Contains(d.RootDirectory.FullName)) continue;
            ScanCfgDir(d.RootDirectory.FullName, 0, 3, sinceTicks, hits, visited, seenFiles);
        }
    } catch {}

    return hits.ToArray();
}

private static void ScanCfgDir(string dir, int depth, int maxDepth, long sinceTicks, List<string> hits, HashSet<string> visited, HashSet<string> seenFiles) {
    if (depth > maxDepth || string.IsNullOrEmpty(dir)) return;
    if (!visited.Add(dir)) return;

    try {
        foreach (string file in Directory.GetFiles(dir, "*.cfg")) {
            InspectCfgFile(file, sinceTicks, hits, seenFiles);
        }
    } catch {}

    if (depth == maxDepth) return;

    try {
        foreach (string sub in Directory.GetDirectories(dir)) {
            string name = Path.GetFileName(sub);
            if (SkipDirs.Contains(name)) continue;
            try {
                FileAttributes attr = File.GetAttributes(sub);
                if ((attr & FileAttributes.ReparsePoint) != 0) continue;
            } catch { continue; }
            ScanCfgDir(sub, depth + 1, maxDepth, sinceTicks, hits, visited, seenFiles);
        }
    } catch {}
}

private static readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
private static readonly HashSet<string> _seenCfgEvents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
private static readonly Queue<string> _cfgEventQueue = new Queue<string>();
private static readonly object _sync = new object();
private static bool _started = false;

public static void StartCfgWatcher() {
    lock (_sync) {
        if (_started) return;
        _started = true;
        string[] roots = new string[] {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.GetTempPath()
        };
        HashSet<string> addedRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string r in roots) {
            if (!string.IsNullOrEmpty(r) && Directory.Exists(r) && addedRoots.Add(r)) {
                AddWatcher(r);
            }
        }
        try {
            foreach (DriveInfo d in DriveInfo.GetDrives()) {
                if (!d.IsReady) continue;
                if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable) continue;
                string dr = d.RootDirectory.FullName;
                if (addedRoots.Add(dr)) AddWatcher(dr);
            }
        } catch {}
    }
}

private static void AddWatcher(string path) {
    try {
        FileSystemWatcher fsw = new FileSystemWatcher(path, "*.cfg");
        fsw.IncludeSubdirectories = true;
        fsw.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size;
        FileSystemEventHandler handler = (s, e) => {
            if (e == null || string.IsNullOrEmpty(e.FullPath)) return;
            RecordCfgEvent(e.ChangeType.ToString(), e.FullPath);
        };
        RenamedEventHandler renHandler = (s, e) => {
            if (e == null || string.IsNullOrEmpty(e.FullPath)) return;
            if (e.FullPath.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) || e.OldFullPath.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)) {
                RecordCfgEvent("Renamed", e.FullPath);
            }
        };
        fsw.Created += handler;
        fsw.Changed += handler;
        fsw.Deleted += handler;
        fsw.Renamed += renHandler;
        fsw.EnableRaisingEvents = true;
        _watchers.Add(fsw);
    } catch {}
}

private static void RecordCfgEvent(string action, string fullPath) {
    try {
        string lower = fullPath.ToLowerInvariant();
        if (lower.Contains("\\steam\\") || lower.Contains("\\counter-strike\\") || lower.Contains("\\valve\\") ||
            lower.Contains("\\windows\\") || lower.Contains("\\program files\\") || lower.Contains("\\program files (x86)\\") ||
            lower.Contains("\\.cache\\") || lower.Contains("\\cbgames\\") ||
            lower.EndsWith("\\frm.cfg") || lower.EndsWith("\\crash_reporter.cfg") || lower.EndsWith("\\setup.cfg")) {
            return;
        }
        string owner = FindAssociatedBinary(fullPath);
        string entry = action + "|" + fullPath + "|" + owner;
        lock (_sync) {
            if (_seenCfgEvents.Add(action + "|" + fullPath)) {
                _cfgEventQueue.Enqueue(entry);
            }
        }
    } catch {}
}

public static string FindAssociatedBinary(string cfgPath) {
    try {
        string dir = Path.GetDirectoryName(cfgPath);
        for (int i = 0; i < 3 && !string.IsNullOrEmpty(dir); i++) {
            try {
                foreach (string ext in new string[] { "*.exe", "*.dll" }) {
                    string[] bins = Directory.GetFiles(dir, ext);
                    if (bins.Length > 0) {
                        return Path.GetFileName(bins[0]) + " (" + bins[0] + ")";
                    }
                }
            } catch {}
            dir = Path.GetDirectoryName(dir);
        }
    } catch {}
    return "";
}

public static string[] DrainCfgEvents() {
    lock (_sync) {
        if (_cfgEventQueue.Count == 0) return new string[0];
        string[] arr = _cfgEventQueue.ToArray();
        _cfgEventQueue.Clear();
        return arr;
    }
}
'@ -ErrorAction SilentlyContinue
    }
    if ('AstrilisUnion.FastEntropy' -as [type]) {
        [AstrilisUnion.FastEntropy]::StartCfgWatcher()
    }
} catch {}

function Get-FileEntropy {
    param ([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return 0.0 }
    try {
        if ('AstrilisUnion.FastEntropy' -as [type]) {
            return [AstrilisUnion.FastEntropy]::Compute($FilePath)
        }
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -eq 0) { return 0.0 }$sampleLen = [Math]::Min($bytes.Length, 1048576)$byteCounts = @{}
        for ($i = 0; $i -lt $sampleLen; $i++) { $byteCounts[$bytes[$i]]++ }$entropy = 0.0
        $len = [double]$sampleLen
        foreach ($count in$byteCounts.Values) {
            $p =$count / $len$entropy -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($entropy, 3)
    } catch {
        return -1.0
    }
}

function Get-SuspiciousHighEntropyFileAlerts {
    $alerts = @()$targetFolders = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),$env:TEMP,
        "$env:SystemDrive\"
    )
    $scannedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($folder in$targetFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $files = Get-ChildItem -LiteralPath$folder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '(?i)^\.(exe\vert{}dll)$' -and $_.Length -gt 50KB -and$_.Length -lt 30MB } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20

        foreach ($file in$files) {
            if (-not $scannedFiles.Add($file.FullName)) { continue }
            $entropy = Get-FileEntropy -FilePath$file.FullName
            if ($entropy -lt 7.20 -or $entropy -gt 7.95) { continue }$alerts += "WARNING: High-entropy packed binary [Entropy: $entropy] -> $($file.FullName)"
        }
    }
    return $alerts
}

# --- Automatic Execution ---
try {
    Write-Host "Running Astrilis Union Scan..." -ForegroundColor Cyan
    $cfgHits = [AstrilisUnion.FastEntropy]::ScanCheatConfigs($null, 0)$entropyHits = Get-SuspiciousHighEntropyFileAlerts

    $summaryText = "Astrilis Union v1.3.0 Scan Summary:`nConfig Matches: $($cfgHits.Count)`nPacked Binaries: $($entropyHits.Count)"
    Write-Host $summaryText -ForegroundColor Green

    if ($script:DiscordWebhookUrl) {
        $payload = @{ content =$summaryText } | ConvertTo-Json
        Invoke-RestMethod -Uri $script:DiscordWebhookUrl -Method Post -Body$payload -ContentType 'application/json' -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Scan execution finished with warnings." -ForegroundColor Yellow
}
