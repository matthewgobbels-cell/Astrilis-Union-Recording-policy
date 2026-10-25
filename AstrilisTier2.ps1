<#
  Astrilis Union - Compliance Verification v3.3
  Stage 1 : System verification   (integrity, software and client-process checks)
  Stage 2 : Process Explorer      (process list shown on the recording)
  Stage 3 : Session monitor       (live monitoring for the duration of the match)
  Run in an elevated 64-bit PowerShell window while screen recording.
  Read-only: nothing on the system is modified. A full report is saved to disk.
  Made by skrimworthy
#>

$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:Ver = '3.3'
$script:Width = 78

# ============================================================================ PRE-FLIGHT
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Host ' Astrilis Union compliance verification requires Administrator privileges.' -ForegroundColor Red
    Write-Host ' Right-click PowerShell, choose "Run as administrator", and start it again.' -ForegroundColor Yellow
    Write-Host ''
    Pause
    exit 1
}
if ([IntPtr]::Size -ne 8) {
    Write-Host "`n Astrilis Union compliance verification requires 64-bit PowerShell." -ForegroundColor Red
    Pause
    exit 1
}

# ============================================================================ NATIVE HELPERS
if (-not ('Astrilis.Native' -as [type])) {
    Add-Type -Namespace Astrilis -Name Native -UsingNamespace System.Collections.Generic -MemberDefinition @'
[DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool i, int pid);
[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
[DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);
[DllImport("kernel32.dll")] static extern int GetProcessId(IntPtr h);
[DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, UIntPtr len);
[DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int c, IntPtr b, int l, out int rl);

[StructLayout(LayoutKind.Sequential)]
public struct MBI {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public ushort PartitionId; public UIntPtr RegionSize; public uint State; public uint Protect; public uint Type;
}

# Counts committed, private, executable+writable memory regions in a process.
public static long[] ScanRwx(int pid) {
    IntPtr h = OpenProcess(0x0410, false, pid);
    if (h == IntPtr.Zero) return null;
    long count = 0, total = 0, addr = 0;
    MBI m;
    UIntPtr sz = (UIntPtr)Marshal.SizeOf(typeof(MBI));
    while (VirtualQueryEx(h, (IntPtr)addr, out m, sz) != UIntPtr.Zero) {
        long size = (long)m.RegionSize.ToUInt64();
        if (m.State == 0x1000 && m.Type == 0x20000 && m.Protect == 0x40) { count++; total += size; }
        long next = addr + size;
        if (next <= addr || next > 0x7FFFFFFEFFFFL) break;
        addr = next;
    }
    CloseHandle(h);
    return new long[] { count, total };
}

# Finds processes holding a memory-read handle to any of the target PIDs.
public static int[] FindReaders(int[] targets) {
    List<int> res = new List<int>();
    if (targets == null || targets.Length == 0) return res.ToArray();
    HashSet<int> tset = new HashSet<int>(targets);
    int me = GetCurrentProcessId();
    IntPtr probe = OpenProcess(0x1000, false, me);
    int len = 0x40000;
    IntPtr buf = Marshal.AllocHGlobal(len);
    try {
        int need = 0, st = 0;
        for (int t = 0; t < 16; t++) {
            st = NtQuerySystemInformation(0x40, buf, len, out need);
            if (st == unchecked((int)0xC0000004)) {
                Marshal.FreeHGlobal(buf);
                len = (need > len ? need : len * 2) + 0x10000;
                buf = Marshal.AllocHGlobal(len);
                continue;
            }
            break;
        }
        if (st != 0) return null;
        int p = IntPtr.Size;
        long count = Marshal.ReadIntPtr(buf).ToInt64();
        int hdr = p * 2, es = p * 3 + 16;

        int ptype = -1;
        if (probe != IntPtr.Zero) {
            for (long i = 0; i < count; i++) {
                int off = (int)(hdr + i * es);
                int owner = (int)Marshal.ReadIntPtr(buf, off + p).ToInt64();
                if (owner == me && Marshal.ReadIntPtr(buf, off + p * 2) == probe) {
                    ptype = (int)(ushort)Marshal.ReadInt16(buf, off + p * 3 + 6);
                    break;
                }
            }
        }

        IntPtr self = GetCurrentProcess();
        Dictionary<int, IntPtr> opened = new Dictionary<int, IntPtr>();
        HashSet<int> done = new HashSet<int>();
        for (long i = 0; i < count; i++) {
            int off = (int)(hdr + i * es);
            int owner = (int)Marshal.ReadIntPtr(buf, off + p).ToInt64();
            if (owner <= 4 || done.Contains(owner) || tset.Contains(owner)) continue;
            if (ptype >= 0 && (int)(ushort)Marshal.ReadInt16(buf, off + p * 3 + 6) != ptype) continue;
            uint access = (uint)Marshal.ReadInt32(buf, off + p * 3);
            if ((access & 0x10) == 0) continue;
            IntPtr hv = Marshal.ReadIntPtr(buf, off + p * 2);
            IntPtr oh;
            if (!opened.TryGetValue(owner, out oh)) { oh = OpenProcess(0x40, false, owner); opened[owner] = oh; }
            if (oh == IntPtr.Zero) continue;
            IntPtr dup;
            if (!DuplicateHandle(oh, hv, self, out dup, 0, false, 2)) continue;
            try {
                int op = GetProcessId(dup);
                if (op != 0 && tset.Contains(op)) { res.Add(owner); done.Add(owner); }
            } catch { } finally { CloseHandle(dup); }
        }
        foreach (KeyValuePair<int, IntPtr> kv in opened) { if (kv.Value != IntPtr.Zero) CloseHandle(kv.Value); }
    } catch { return null; } finally { Marshal.FreeHGlobal(buf); if (probe != IntPtr.Zero) CloseHandle(probe); }
    return res.ToArray();
}

[DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);

static bool Rd(IntPtr h, long addr, byte[] buf, int len) {
    IntPtr n;
    if (!ReadProcessMemory(h, (IntPtr)addr, buf, len, out n)) return false;
    return n.ToInt64() == len;
}

static int RvaToOff(byte[] d, uint rva, int secTab, int nsec) {
    for (int i = 0; i < nsec; i++) {
        int s = secTab + i * 40;
        uint vsz = BitConverter.ToUInt32(d, s + 8);
        uint va = BitConverter.ToUInt32(d, s + 12);
        uint rsz = BitConverter.ToUInt32(d, s + 16);
        uint raw = BitConverter.ToUInt32(d, s + 20);
        uint span = vsz > rsz ? vsz : rsz;
        if (rva >= va && rva < va + span) return (int)(rva - va + raw);
    }
    return -1;
}

static string Hex(byte[] b, int off, int n) {
    System.Text.StringBuilder sb = new System.Text.StringBuilder();
    for (int i = 0; i < n; i++) sb.Append(b[off + i].ToString("X2"));
    return sb.ToString();
}

static long HookDest(IntPtr h, long addr, byte[] b, out string kind) {
    kind = "";
    int[] offs = new int[] { 0, 3, 8 };
    foreach (int k in offs) {
        if (k + 12 > b.Length) continue;
        if (b[k] == 0xE9) { kind = "jmp"; return addr + k + 5 + BitConverter.ToInt32(b, k + 1); }
        if (b[k] == 0xEB) { kind = "short-jmp"; return addr + k + 2 + (sbyte)b[k + 1]; }
        if (b[k] == 0xFF && b[k + 1] == 0x25) {
            kind = "jmp-indirect";
            byte[] q = new byte[8];
            if (Rd(h, addr + k + 6 + BitConverter.ToInt32(b, k + 2), q, 8)) return BitConverter.ToInt64(q, 0);
            return 0;
        }
        if (b[k] == 0x48 && b[k + 1] == 0xB8 && b[k + 10] == 0xFF && b[k + 11] == 0xE0) { kind = "mov-jmp"; return BitConverter.ToInt64(b, k + 2); }
        if (b[k] == 0x49 && b[k + 1] == 0xBB && b[k + 10] == 0x41 && b[k + 11] == 0xFF) { kind = "mov-jmp"; return BitConverter.ToInt64(b, k + 2); }
        if (b[k] == 0x68 && b[k + 5] == 0xC3) { kind = "push-ret"; return (long)BitConverter.ToInt32(b, k + 1); }
    }
    return 0;
}

public static string[] ScanHooks(int pid, string diskPath, long targetBase, bool ntPrefix, string[] extra) {
    List<string> res = new List<string>();
    byte[] d;
    try { d = System.IO.File.ReadAllBytes(diskPath); } catch { return null; }
    IntPtr h = OpenProcess(0x1010, false, pid);
    if (h == IntPtr.Zero) return null;
    try {
        if (d.Length < 0x400) return null;
        int pe = BitConverter.ToInt32(d, 0x3C);
        if (pe < 0 || pe + 0x100 > d.Length || BitConverter.ToUInt32(d, pe) != 0x4550) return null;
        int nsec = BitConverter.ToUInt16(d, pe + 6);
        int osz = BitConverter.ToUInt16(d, pe + 20);
        int opt = pe + 24;
        if (BitConverter.ToUInt16(d, opt) != 0x20B) return null;
        int secTab = opt + osz;
        uint expRva = BitConverter.ToUInt32(d, opt + 112);
        uint expSize = BitConverter.ToUInt32(d, opt + 116);
        int eo = RvaToOff(d, expRva, secTab, nsec);
        if (eo < 0) return null;
        int nNames = BitConverter.ToInt32(d, eo + 24);
        int aF = RvaToOff(d, BitConverter.ToUInt32(d, eo + 28), secTab, nsec);
        int aN = RvaToOff(d, BitConverter.ToUInt32(d, eo + 32), secTab, nsec);
        int aO = RvaToOff(d, BitConverter.ToUInt32(d, eo + 36), secTab, nsec);
        if (aF < 0 || aN < 0 || aO < 0) return null;
        HashSet<string> want = new HashSet<string>();
        if (extra != null) { foreach (string x in extra) want.Add(x); }
        byte[] mem = new byte[24];
        byte[] db = new byte[16];
        for (int i = 0; i < nNames; i++) {
            int no = RvaToOff(d, BitConverter.ToUInt32(d, aN + i * 4), secTab, nsec);
            if (no < 0) continue;
            int e = no;
            while (e < d.Length && d[e] != 0) e++;
            string name = System.Text.Encoding.ASCII.GetString(d, no, e - no);
            bool isNt = ntPrefix && name.Length > 2 && (name.StartsWith("Nt") || name.StartsWith("Zw")) && char.IsUpper(name[2]);
            if (!isNt && !want.Contains(name)) continue;
            int ord = BitConverter.ToUInt16(d, aO + i * 2);
            uint frva = BitConverter.ToUInt32(d, aF + ord * 4);
            if (frva >= expRva && frva < expRva + expSize) continue;
            int fo = RvaToOff(d, frva, secTab, nsec);
            if (fo < 0 || fo + 24 > d.Length) continue;
            long addr = targetBase + frva;
            if (!Rd(h, addr, mem, 24)) continue;
            bool same = true;
            for (int j = 0; j < 16; j++) { if (mem[j] != d[fo + j]) { same = false; break; } }
            if (same) continue;
            string kind;
            long dest = HookDest(h, addr, mem, out kind);
            Array.Copy(d, fo, db, 0, 16);
            res.Add(name + "|" + (kind.Length > 0 ? kind : "modified") + "|" + dest.ToString("X") + "|" + Hex(mem, 0, 16) + "|" + Hex(db, 0, 16));
        }
    } catch { return null; } finally { CloseHandle(h); }
    return res.ToArray();
}

public static string[] ScanSyscallStubs(int pid) {
    List<string> res = new List<string>();
    IntPtr h = OpenProcess(0x0410, false, pid);
    if (h == IntPtr.Zero) return null;
    long addr = 0, scanned = 0;
    MBI m;
    UIntPtr sz = (UIntPtr)Marshal.SizeOf(typeof(MBI));
    while (VirtualQueryEx(h, (IntPtr)addr, out m, sz) != UIntPtr.Zero) {
        long size = (long)m.RegionSize.ToUInt64();
        uint pr = m.Protect & 0xFF;
        bool exec = (pr == 0x10 || pr == 0x20 || pr == 0x40 || pr == 0x80);
        if (m.State == 0x1000 && m.Type != 0x1000000 && exec && size > 0 && size <= 0x2000000 && scanned < 0x10000000) {
            byte[] buf = new byte[size];
            if (Rd(h, m.BaseAddress.ToInt64(), buf, (int)size)) {
                scanned += size;
                for (int i = 0; i + 2 < buf.Length; i++) {
                    if (buf[i] == 0x0F && buf[i + 1] == 0x05) {
                        int lo = i - 24;
                        if (lo < 0) lo = 0;
                        bool stub = false;
                        for (int k = lo; k + 3 < i; k++) {
                            if (buf[k] == 0x4C && buf[k + 1] == 0x8B && buf[k + 2] == 0xD1 && buf[k + 3] == 0xB8) { stub = true; break; }
                        }
                        if (stub) {
                            res.Add(m.BaseAddress.ToInt64().ToString("X") + "|" + (m.Type == 0x20000 ? "private" : "mapped") + "|" + i.ToString("X"));
                            break;
                        }
                    }
                }
            }
        }
        long next = addr + size;
        if (next <= addr || next > 0x7FFFFFFEFFFFL) break;
        addr = next;
        if (res.Count >= 20) break;
    }
    CloseHandle(h);
    return res.ToArray();
}

public static double Entropy(string path) {
    try {
        using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite)) {
            int n = (int)Math.Min(fs.Length, 4194304L);
            if (n <= 0) return 0.0;
            byte[] b = new byte[n];
            int r = fs.Read(b, 0, n);
            if (r <= 0) return 0.0;
            int[] c = new int[256];
            for (int i = 0; i < r; i++) c[b[i]]++;
            double e = 0.0;
            for (int i = 0; i < 256; i++) { if (c[i] > 0) { double q = c[i] / (double)r; e -= q * Math.Log(q, 2); } }
            return Math.Round(e, 3);
        }
    } catch { return -1.0; }
}
'@ -ErrorAction SilentlyContinue
}

# ============================================================================ DATA
$script:Indicators = @(
    'matcha', 'isabelle', 'severe', 'aegis', 'potassium', 'lattice', 'spectre', 'matrix', 'clarity', 'loader', 'photon', 'valex', 'aimmy',
    'keyauth', 'xeno', 'melatonin', 'evolve', 'serotonin', 'ghostify', 'dx9ware', 'unicore', 'lumen', 'monolith', 'skript',
    'ntfsdump', 'atlanta', 'eulen', 'hammafia', 'redengine', 'susano', 'bypass', 'volt', 'fleasion',
    'solara', 'wave', 'synapse', 'krnl', 'fluxus', 'celery', 'wearedevs', 'injector', 'executor'
)

$script:OfficialWinExe = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @(
    'ctfmon.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe', 'securityhealthhost.exe', 'msmpeng.exe', 'nissrv.exe', 'mpcmdrun.exe',
    'mpdefendercoreservice.exe', 'smartscreen.exe', 'svchost.exe', 'explorer.exe', 'csrss.exe', 'lsass.exe', 'lsaiso.exe', 'services.exe',
    'winlogon.exe', 'wininit.exe', 'smss.exe', 'dwm.exe', 'taskhostw.exe', 'taskhost.exe', 'taskeng.exe', 'runtimebroker.exe', 'conhost.exe',
    'dllhost.exe', 'sihost.exe', 'fontdrvhost.exe', 'spoolsv.exe', 'searchindexer.exe', 'searchhost.exe', 'searchprotocolhost.exe',
    'searchfilterhost.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe', 'applicationframehost.exe', 'textinputhost.exe',
    'wmiprvse.exe', 'audiodg.exe', 'backgroundtaskhost.exe', 'taskmgr.exe', 'cmd.exe', 'powershell.exe', 'regedit.exe', 'reg.exe', 'notepad.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'wuauclt.exe', 'usocoreworker.exe',
    'musnotification.exe', 'werfault.exe', 'wermgr.exe', 'sppsvc.exe', 'trustedinstaller.exe', 'tiworker.exe', 'consent.exe', 'logonui.exe',
    'userinit.exe', 'mmc.exe', 'control.exe', 'dashost.exe', 'unsecapp.exe', 'wlanext.exe', 'compattelrunner.exe', 'lockapp.exe',
    'systemsettings.exe', 'sgrmbroker.exe', 'wudfhost.exe', 'msdtc.exe', 'schtasks.exe', 'taskkill.exe', 'tasklist.exe', 'net.exe', 'net1.exe',
    'netsh.exe', 'sc.exe', 'certutil.exe', 'bcdedit.exe', 'fsutil.exe', 'wevtutil.exe', 'vssadmin.exe', 'whoami.exe', 'ping.exe', 'ipconfig.exe',
    'wsmprovhost.exe', 'sdbinst.exe', 'dism.exe', 'sfc.exe', 'bitsadmin.exe', 'esentutl.exe', 'wmic.exe', 'mousocoreworker.exe', 'ctfmon.exe'
)) { [void]$script:OfficialWinExe.Add($n) }

$script:FlaggedDownloads = @('software.exe', 'upgrade.exe')
$script:OfficialDirRx = '(?i)^(?:[a-z]:|\\device\\harddiskvolume\d+)\\(?:windows\\(?:system32|syswow64|winsxs|systemapps|servicing|immersivecontrolpanel)\\|windows\\[^\\]+$|program files(?: \(x86\))?\\windows defender(?: advanced threat protection)?\\|programdata\\microsoft\\windows defender\\|program files\\windowsapps\\)'

$script:MicrosoftShippedRoots = @(
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5', '8F43288AD272F3103B6FB1428485EA3014C0BCFE', 'CDD4EEAE6000AC7F40C3802C171E30148030C072',
    'A43489159A520F0D93D032CCAF37E7FE20A8B419', '7F88CD7223F3C813818C994614A89C99FA3B5247', '73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74',
    '999A64C37FF47D9FAB95F14769891460EEC4C3C5', '06F1AA330B927B753A40E68CDF22E34BCBEF3352', 'F40042E2E5F7E8EF8189FED15519AECE42C3BFA2',
    '31F9FC8BA3805986B721EA7295C65B3A44534274', '0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8', '92B46C76E13054E104F230517E6E504D43AB10B5',
    '245C97DF7514E7CF2DF8BE72AE957B9E04741E85', 'BE36A4562FB2EE05DBB3D32323ADF445084ED656', '18F7C1FCC3090203FD5BAA2F861A754976C8DD25'
)
$script:VulnDrivers = @(
    'iqvw64e.sys', 'iqvw64.sys', 'gdrv.sys', 'dbutil_2_3.sys', 'kprocesshacker.sys', 'mhyprot2.sys', 'mhyprot3.sys', 'capcom.sys',
    'physmem.sys', 'hw.sys', 'speedfan.sys', 'viragt64.sys', 'tfsysmon.sys', 'amsdk.sys', 'adv64drv.sys', 'bs_def64.sys', 'bs_hwmio64.sys',
    'iomap64.sys', 'asupio.sys', 'ucorew64.sys', 'msio64.sys', 'ntiolib_x64.sys', 'winio64.sys', 'inpoutx64.sys', 'kevp64.sys',
    'rtcore64.sys', 'winring0x64.sys', 'winring0.sys', 'eneio64.sys', 'asio.sys', 'asio2.sys', 'asio3.sys', 'directio64.sys', 'cpuz141.sys', 'atillk64.sys', 'amifldrv64.sys'
)
$script:MasqueradePaths = @{
    'svchost.exe' = @('\windows\system32\svchost.exe', '\windows\syswow64\svchost.exe'); 'explorer.exe' = @('\windows\explorer.exe')
    'csrss.exe' = @('\windows\system32\csrss.exe'); 'lsass.exe' = @('\windows\system32\lsass.exe'); 'services.exe' = @('\windows\system32\services.exe')
    'winlogon.exe' = @('\windows\system32\winlogon.exe'); 'dwm.exe' = @('\windows\system32\dwm.exe'); 'taskhostw.exe' = @('\windows\system32\taskhostw.exe')
    'runtimebroker.exe' = @('\windows\system32\runtimebroker.exe'); 'conhost.exe' = @('\windows\system32\conhost.exe'); 'dllhost.exe' = @('\windows\system32\dllhost.exe', '\windows\syswow64\dllhost.exe')
}
$script:ReaderAllowlist = @('robloxplayerbeta', 'robloxcrashhandler', 'robloxplayerlauncher', 'bloxstrap', 'fishstrap', 'msmpeng', 'nissrv',
    'securityhealthservice', 'mpdefendercoreservice', 'csrss', 'lsass', 'wininit', 'services', 'searchindexer', 'wmiprvse', 'procexp', 'procexp64', 'taskmgr', 'perfmon', 'resmon', 'svchost')
$script:DnsAllow = '(?i)(^|\.)(microsoft\.com|clarity\.ms|msftconnecttest\.com|photonengine\.com|matrix\.org|roblox\.com|rbxcdn\.com|rbx\.com|discord\.com|discordapp\.com|gstatic\.com|googleapis\.com|cloudflare\.com|windowsupdate\.com|live\.com|office\.com|nvidia\.com|steampowered\.com|github\.com|githubusercontent\.com)$'

$script:ObsKnownExe = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @('obs64.exe', 'obs32.exe', 'obs-browser-page.exe', 'obs-ffmpeg-mux.exe', 'obs-amf-test.exe', 'obs-nvenc-test.exe', 'obs-qsv-test.exe',
    'obs-webrtc-test.exe', 'get-graphics-offsets32.exe', 'get-graphics-offsets64.exe', 'inject-helper32.exe', 'inject-helper64.exe', 'uninstall.exe', 'unins000.exe')) { [void]$script:ObsKnownExe.Add($n) }

$script:CrtDllRx = '(?i)^(vcruntime\d+(_\d+)?|msvcp\d+(_\d+)?|concrt\d+|vccorlib\d+|msvcr\d+|mfc\d+\w*|ucrtbase)\.dll$'

# ============================================================================ HELPERS
function Get-Indicator {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $l = $Text.ToLower()
    foreach ($k in $script:Indicators) {
        if ($k -eq 'loader' -and $l -match '(download|upload|bootload|workload|dataload)er') { continue }
        if ($k.Length -le 4) {
            if ($l -match ('(^|[\\_\s\-\.])' + [regex]::Escape($k) + '($|[\\_\s\-\.])')) { return $k }
        } elseif ($l.Contains($k)) { return $k }
    }
    return $null
}

function Test-TrustedDir {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $p = $Path.ToLower().Replace('/', '\')
    foreach ($d in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($d -and $p.StartsWith($d.ToLower() + '\')) { return $true }
    }
    return $false
}

function Test-UserlandPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path.ToLower().Replace('/', '\') -match '\\(downloads|desktop|temp)\\')
}

$script:SigCache = @{}
function Get-SigInfo {
    param([string]$Path)
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $info = @{ Status = 'Unknown'; Subject = '' }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $info.Status = [string]$sig.Status
        if ($sig.SignerCertificate) { $info.Subject = [string]$sig.SignerCertificate.Subject }
    } catch {}
    $script:SigCache[$Path] = $info
    return $info
}

function Get-BootTime { try { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } catch { $null } }
function Get-LogonTime {
    try { $e = Get-Process -Name explorer | Sort-Object StartTime | Select-Object -First 1; if ($e.StartTime) { return $e.StartTime } } catch {}
    $b = Get-BootTime; if ($b) { return $b }
    return (Get-Date).AddHours(-12)
}

function Get-ExampleText {
    param([string[]]$Items, [int]$Max = 3)
    $s = ($Items | Select-Object -First $Max) -join ', '
    if ($Items.Count -gt $Max) { $s += ", +$($Items.Count - $Max) more" }
    return $s
}

function Test-FlaggedDownload {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $norm = $Path.Replace('/', '\')
    $leaf = $norm.Substring($norm.LastIndexOf('\') + 1).ToLower()
    if ($script:FlaggedDownloads -contains $leaf -and $norm.ToLower() -match '\\downloads\\') {
        return "FAILURE: Flagged file '$leaf' present in Downloads -> $Path"
    }
    return $null
}

function Test-OfficialExe {
    param([string]$Name, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not $script:OfficialWinExe.Contains($Name)) { return $null }
    $goodDir = ($Path.Replace('/', '\') -match $script:OfficialDirRx)
    $status = 'Missing'; $isMs = $false
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $s = Get-SigInfo -Path $Path
        $status = $s.Status
        $isMs = ($s.Status -eq 'Valid' -and $s.Subject -match 'Microsoft')
    }
    if (-not $goodDir) { return "FAILURE: Official Windows file name '$Name' outside system folders (possible impostor, signature: $status) -> $Path" }
    if ($status -ne 'Missing' -and -not $isMs) { return "FAILURE: Official Windows file '$Name' lacks a valid Microsoft signature ($status) -> $Path" }
    return $null
}
