<#
  TCAR ARC - Compliance Verification v3.3
  Stage 1 : System verification   (integrity, software and client-process checks)
  Stage 2 : Process Explorer      (process list shown on the recording)
  Stage 3 : Session monitor       (live monitoring for the duration of the match)
  Run in an elevated 64-bit PowerShell window while screen recording.
  Read-only: nothing on the system is modified. A full report is saved to disk.
#>

$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:Ver = '3.3'
$script:Width = 78

# ============================================================================ PRE-FLIGHT
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Host ' TCAR ARC requires Administrator privileges.' -ForegroundColor Red
    Write-Host ' Right-click PowerShell, choose "Run as administrator", and start it again.' -ForegroundColor Yellow
    Write-Host ''
    Pause
    exit 1
}
if ([IntPtr]::Size -ne 8) {
    Write-Host "`n TCAR ARC requires 64-bit PowerShell." -ForegroundColor Red
    Pause
    exit 1
}

# ============================================================================ NATIVE HELPERS
if (-not ('TCAR.Native' -as [type])) {
    Add-Type -Namespace TCAR -Name Native -UsingNamespace System.Collections.Generic -MemberDefinition @'
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

// Counts committed, private, executable+writable memory regions in a process.
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

// Finds processes holding a memory-read handle to any of the target PIDs.
// Speed: only handles whose object type is "Process" are duplicated (the type index is learned
// from a probe handle), instead of duplicating every readable handle on the system.
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

// Recognises the common inline-hook trampolines at the start of a function (directly, after
// "mov r10,rcx", or after "mov r10,rcx; mov eax,imm32") and returns the redirect destination.
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

// Compares the first 16 bytes of exported functions of a loaded system DLL in a target process
// against the same bytes in the on-disk file. ntPrefix selects every Nt*/Zw* export; extra adds named exports.
// Each result line:  name|kind|destinationHex|memoryBytes|diskBytes   (kind = redirect type or "modified")
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

// Finds direct/indirect system-call stubs ("mov r10,rcx; mov eax,imm; ... syscall") inside executable
// memory that is not an image (private or mapped regions). Legitimate code only issues syscalls from ntdll/win32u.
// Each result line:  regionBaseHex|private-or-mapped|offsetHex
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

// Shannon entropy of the first 4 MB of a file (packed/encrypted binaries score ~7.2-7.95).
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

# Official Windows executables. Any file with one of these names must live in a Windows system location
# AND carry a valid Microsoft signature, otherwise it is treated as an impostor.
# (Kept separate from $Indicators: those are substring keywords, and adding system names there would
#  match legitimate files.)
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

# Files that must never be present in the Downloads folder.
$script:FlaggedDownloads = @('software.exe', 'upgrade.exe')

# Locations where an official Windows executable is allowed to live (drive letter or \Device\HarddiskVolumeN prefix).
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

# OBS Studio: executables that legitimately ship with / are launched by OBS.
$script:ObsKnownExe = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @('obs64.exe', 'obs32.exe', 'obs-browser-page.exe', 'obs-ffmpeg-mux.exe', 'obs-amf-test.exe', 'obs-nvenc-test.exe', 'obs-qsv-test.exe',
    'obs-webrtc-test.exe', 'get-graphics-offsets32.exe', 'get-graphics-offsets64.exe', 'inject-helper32.exe', 'inject-helper64.exe', 'uninstall.exe', 'unins000.exe')) { [void]$script:ObsKnownExe.Add($n) }

# Microsoft C/C++ runtime DLLs. Apps may ship their own copy, but it must be the genuine, Microsoft-signed one.
$script:CrtDllRx = '(?i)^(vcruntime\d+(_\d+)?|msvcp\d+(_\d+)?|concrt\d+|vccorlib\d+|msvcr\d+|mfc\d+\w*|ucrtbase)\.dll$'

# APIs whose tampering is never acceptable (memory access, thread/process injection, module loading, ETW, AMSI, input and capture hiding).
$script:HookCritical = @('NtProtectVirtualMemory', 'NtWriteVirtualMemory', 'NtReadVirtualMemory', 'NtAllocateVirtualMemory', 'NtFreeVirtualMemory', 'NtCreateThreadEx',
    'NtOpenProcess', 'NtQuerySystemInformation', 'NtQueryVirtualMemory', 'NtMapViewOfSection', 'NtUnmapViewOfSection', 'NtSetContextThread', 'NtGetContextThread',
    'NtQueueApcThread', 'NtSuspendThread', 'NtResumeThread', 'NtTerminateProcess', 'NtCreateSection', 'NtDuplicateObject', 'NtQueryInformationProcess',
    'NtSetInformationThread', 'NtDeviceIoControlFile', 'NtTraceEvent', 'NtTraceControl', 'EtwEventWrite', 'EtwEventWriteFull', 'EtwEventWriteTransfer',
    'LdrLoadDll', 'LdrGetProcedureAddress', 'AmsiScanBuffer', 'AmsiScanString', 'AmsiInitialize', 'AmsiOpenSession', 'ReadProcessMemory', 'WriteProcessMemory',
    'VirtualProtect', 'VirtualProtectEx', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
    'GetProcAddress', 'SetWindowsHookExA', 'SetWindowsHookExW', 'SetWindowDisplayAffinity', 'GetAsyncKeyState', 'SendInput')
# Extra named exports checked in addition to the Nt*/Zw* syscall stubs of ntdll.dll and win32u.dll.
$script:HookApis = @{
    'ntdll.dll'      = @('EtwEventWrite', 'EtwEventWriteFull', 'EtwEventWriteTransfer', 'LdrLoadDll', 'LdrGetProcedureAddress', 'LdrGetDllHandle', 'RtlAddVectoredExceptionHandler')
    'kernelbase.dll' = @('ReadProcessMemory', 'WriteProcessMemory', 'VirtualProtect', 'VirtualProtectEx', 'VirtualAlloc', 'VirtualAllocEx', 'CreateRemoteThread', 'CreateRemoteThreadEx',
        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'OpenProcess', 'CreateProcessW', 'CreateProcessA', 'CreateProcessInternalW', 'GetModuleHandleW')
    'kernel32.dll'   = @('ReadProcessMemory', 'WriteProcessMemory', 'VirtualProtect', 'VirtualProtectEx', 'VirtualAlloc', 'VirtualAllocEx', 'CreateRemoteThread', 'CreateRemoteThreadEx',
        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'OpenProcess', 'CreateProcessW', 'CreateProcessA')
    'user32.dll'     = @('SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'SendInput', 'SetWindowDisplayAffinity', 'GetWindowDisplayAffinity', 'FindWindowW', 'EnumWindows')
    'amsi.dll'       = @('AmsiScanBuffer', 'AmsiScanString', 'AmsiInitialize', 'AmsiOpenSession')
}

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

# A file named software.exe / upgrade.exe inside a Downloads folder is flagged.
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

# An official Windows executable name must be in a Windows system location and validly signed by Microsoft.
# Returns a finding string, or $null when the file is genuine.
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

# Fast, time-budgeted file-name search (depth-limited, skips junctions and cache-heavy folders).
function Find-NamedFiles {
    param([string[]]$Roots, $Names, [int]$MaxDepth = 3, [int]$BudgetSec = 30)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $found = New-Object 'System.Collections.Generic.List[string]'
    $skip = '(?i)^(node_modules|\.git|winsxs|windowsapps|packages|npm-cache|code cache|gpucache|cache)$'
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    foreach ($r in $Roots) { if ($r -and (Test-Path -LiteralPath $r)) { $stack.Push(@($r, 0)) } }
    while ($stack.Count -gt 0 -and $sw.Elapsed.TotalSeconds -lt $BudgetSec) {
        $cur = $stack.Pop(); $dir = [string]$cur[0]; $d = [int]$cur[1]
        try { foreach ($f in [IO.Directory]::EnumerateFiles($dir)) { if ($Names.Contains([IO.Path]::GetFileName($f))) { $found.Add($f) } } } catch {}
        if ($d -lt $MaxDepth) {
            try {
                foreach ($sub in [IO.Directory]::EnumerateDirectories($dir)) {
                    if ([IO.Path]::GetFileName($sub) -match $skip) { continue }
                    if (([IO.File]::GetAttributes($sub) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push(@($sub, ($d + 1)))
                }
            } catch {}
        }
    }
    return $found.ToArray()
}

# Fast, time-budgeted folder-name search for indicator keywords.
function Find-IndicatorFolders {
    param([string[]]$Roots, [int]$MaxDepth = 2, [int]$BudgetSec = 20)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $found = New-Object 'System.Collections.Generic.List[string]'
    $skip = '(?i)^(node_modules|\.git|winsxs|windowsapps|packages|npm-cache|code cache|gpucache|cache)$'
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    foreach ($r in $Roots) { if ($r -and (Test-Path -LiteralPath $r)) { $stack.Push(@($r, 0)) } }
    while ($stack.Count -gt 0 -and $sw.Elapsed.TotalSeconds -lt $BudgetSec) {
        $cur = $stack.Pop(); $dir = [string]$cur[0]; $d = [int]$cur[1]
        if ($d -ge $MaxDepth + 1) { continue }
        try {
            foreach ($sub in [IO.Directory]::EnumerateDirectories($dir)) {
                $leaf = [IO.Path]::GetFileName($sub)
                if ($leaf -match $skip) { continue }
                if (([IO.File]::GetAttributes($sub) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if (Get-Indicator $leaf) { $found.Add($sub) }
                if ($d -lt $MaxDepth) { $stack.Push(@($sub, ($d + 1))) }
            }
        } catch {}
    }
    return $found.ToArray()
}

# One DLL/EXE loaded into the Roblox client. Returns $null when it is acceptable.
function Test-LoadedModule {
    param([string]$File)
    $kw = Get-Indicator $File
    $tag = if ($kw) { " [match: $kw]" } else { '' }
    $s = Get-SigInfo -Path $File
    if ($s.Status -ne 'Valid') {
        $e = [TCAR.Native]::Entropy($File)
        return "FAILURE: Unsigned module$tag loaded in client ($($s.Status), entropy $e) -> $File"
    }
    if ($kw) { return "FAILURE: Module matches unauthorized-software indicator [$kw] -> $File" }
    if (Test-UserlandPath $File) { return "WARNING: Signed module loaded from a user folder -> $File" }
    return $null
}

# One process record. Returns $null when it is acceptable.
function Test-ProcessRecord {
    param([string]$Name, [string]$Path)
    if ($Path) {
        $nl = $Name.ToLower()
        if ($script:MasqueradePaths.ContainsKey($nl)) {
            $ok = $false
            foreach ($suf in $script:MasqueradePaths[$nl]) { if ($Path.ToLower().EndsWith($suf)) { $ok = $true } }
            if (-not $ok) { return "FAILURE: System process name '$Name' running from a non-standard path -> $Path" }
        }
        $imp = Test-OfficialExe -Name $Name -Path $Path
        if ($imp) { return $imp }
        $fd = Test-FlaggedDownload -Path $Path
        if ($fd) { return $fd }
    }
    $kw = Get-Indicator $Name
    if (-not $kw -and $Path -and -not (Test-TrustedDir $Path)) { $kw = Get-Indicator $Path }
    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $userland = Test-UserlandPath $Path
        if ($kw -or $userland) {
            $s = Get-SigInfo -Path $Path
            $bad = ($s.Status -ne 'Valid')
            if ($kw -and $bad) { return "FAILURE: Unsigned process matches indicator [$kw] -> $Name -> $Path" }
            if ($kw)           { return "WARNING: Process matches indicator [$kw] (signed) -> $Name -> $Path" }
            if ($bad)          { return "WARNING: Unsigned program running from a user folder -> $Name -> $Path" }
        }
    } elseif ($kw) {
        return "FAILURE: Process matches indicator [$kw] -> $Name"
    }
    return $null
}

# ============================================================================ CHECKS
function Get-SystemInfoAlerts {
    $o = @()
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($cpu) { $o += "INFO: CPU -> $($cpu.Name.Trim()) ($($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T)" }
    foreach ($g in @(Get-CimInstance Win32_VideoController)) { $o += "INFO: GPU -> $($g.Name) (driver $($g.DriverVersion))" }
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os) { $o = @("SUCCESS: $($os.Caption), build $($os.BuildNumber)") + $o } else { $o = @('FAILURE: OS query failed') + $o }
    return $o
}

function Get-DefenderAlerts {
    $o = @()
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { $o += 'SUCCESS: Antivirus and real-time protection enabled' }
        else {
            if (-not $mp.AntivirusEnabled) { $o += 'FAILURE: Antivirus is disabled' }
            if (-not $mp.RealTimeProtectionEnabled) { $o += 'FAILURE: Real-time protection is off' }
        }
        if (-not $mp.IsTamperProtected) { $o += 'WARNING: Tamper protection is off' }
        if ($mp.AntivirusSignatureAge -gt 7) { $o += "WARNING: Definitions are $($mp.AntivirusSignatureAge) days old" }
    } catch { $o += "WARNING: Defender status unavailable ($($_.Exception.Message))" }
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Microsoft\Windows Defender') {
        if ((Get-ItemProperty -Path $k -Name DisableAntiSpyware).DisableAntiSpyware -eq 1) { $o += "FAILURE: DisableAntiSpyware policy active ($k)" }
    }
    $ms = Get-Process -Name MsMpEng | Select-Object -First 1
    if (-not $ms) { $o += 'FAILURE: Antivirus engine (MsMpEng) is not running' }
    elseif ($ms.Path -and $ms.Path -notlike "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe") { $o += "FAILURE: Antivirus engine running from unexpected path: $($ms.Path)" }
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Nal') { $o += 'FAILURE: Vulnerable Intel driver service (Nal) is registered' }
    return $o
}

function Get-ExclusionList {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        $p = Get-MpPreference -ErrorAction Stop
        foreach ($i in @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension)) { if ($i) { [void]$set.Add([string]$i) } }
    } catch {}
    foreach ($root in 'SOFTWARE\Microsoft\Windows Defender\Exclusions', 'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions') {
        foreach ($t in 'Paths', 'Processes', 'Extensions') {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$root\$t")
            if ($k) { foreach ($n in $k.GetValueNames()) { if ($n) { [void]$set.Add($n) } }; $k.Close() }
        }
    }
    return @($set)
}

function Get-ExclusionAlerts {
    $ex = @(Get-ExclusionList)
    if ($ex.Count -eq 0) { return @('SUCCESS: No antivirus exclusions configured') }
    return @($ex | ForEach-Object { $kw = Get-Indicator $_; $t = if ($kw) { " [match: $kw]" } else { '' }; "FAILURE: Antivirus exclusion$t -> $_" })
}

# Windows Security "Protection history": every recorded detection is flagged.
function Get-ThreatAlerts {
    $o = @()
    $detCount = 0
    try {
        $active = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.Status -eq 'Active' })
        foreach ($t in $active) { $o += "FAILURE: Active threat $($t.ThreatName) | $($t.Resources)" }
        $names = @{}
        Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = [string]$_.ThreatName }
        $det = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending)
        $detCount = $det.Count
        $shown = 0
        foreach ($d in $det) {
            $res = ([string]($d.Resources -join ', ')) -replace '^(file|containerfile|process):_', ''
            $kw = Get-Indicator $res
            $n = $names[[string]$d.ThreatID]; if (-not $n) { $n = "ThreatID $($d.ThreatID)" }
            $when = Get-Date $d.InitialDetectionTime -Format 'yyyy-MM-dd HH:mm'
            $lvl = if ($kw) { 'FAILURE' } else { 'WARNING' }
            $tag = if ($kw) { " [match: $kw]" } else { '' }
            $o += "${lvl}: Protection history entry$tag - $n ($when) -> $res"
            $shown++
            if ($shown -ge 25) { break }
        }
        if ($det.Count -gt $shown) { $o += "WARNING: $($det.Count - $shown) older protection history entries not listed" }
    } catch { $o += 'WARNING: Threat data unavailable' }

    # Event-log view of the same history (also catches records that were removed from the detection list)
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 1013 } -MaxEvents 2)) {
        $o += "WARNING: Antivirus protection history was cleared at $(Get-Date $e.TimeCreated -Format 'yyyy-MM-dd HH:mm')"
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 5001 } -MaxEvents 3)) {
        $o += "WARNING: Real-time protection was turned off at $(Get-Date $e.TimeCreated -Format 'yyyy-MM-dd HH:mm')"
    }
    if ($detCount -eq 0) {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 1116, 1117 } -MaxEvents 10)) {
            $nm = ''; if ($e.Message -match '(?im)^\s*Name:\s*(.+)$') { $nm = $matches[1].Trim() }
            $o += "WARNING: Protection event $($e.Id) at $(Get-Date $e.TimeCreated -Format 'yyyy-MM-dd HH:mm') -> $nm"
        }
    }
    if ($o.Count -eq 0) { $o += 'SUCCESS: Protection history is empty - no detections recorded' }
    return $o
}

function Get-IntegrityAlerts {
    $o = @()
    $h = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled
    if ($h -eq 1) { $o += 'SUCCESS: Memory Integrity (HVCI) is on' } elseif ($null -eq $h) { $o += 'FAILURE: Memory Integrity unsupported or unreadable' } else { $o += 'FAILURE: Memory Integrity (HVCI) is off' }
    $bcd = & "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>&1 | Out-String
    if ($bcd -match '(?im)^\s*testsigning\s+Yes') { $o += 'FAILURE: Test signing is enabled (unsigned drivers can load)' }
    if ($bcd -match '(?im)^\s*nointegritychecks\s+Yes') { $o += 'FAILURE: Driver integrity checks are disabled' }
    if ($bcd -match '(?im)^\s*debug\s+Yes') { $o += 'WARNING: Kernel debugging is enabled' }
    try { if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) { $o += 'WARNING: Secure Boot is off' } } catch {}
    return $o
}

function Get-DriverAlerts {
    $o = @(); $unsigned = @(); $n = 0
    foreach ($d in @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' })) {
        $p = [Environment]::ExpandEnvironmentVariables(([string]$d.PathName).Trim().Trim('"'))
        if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
        if ($p -like '\SystemRoot\*') { $p = $env:SystemRoot + $p.Substring(11) } elseif ($p -like 'System32\*') { $p = Join-Path $env:SystemRoot $p }
        $leaf = (Split-Path -Leaf $p).ToLower()
        $kw = Get-Indicator $d.Name; if (-not $kw) { $kw = Get-Indicator $p }
        if ($kw) { $o += "FAILURE: Driver matches indicator [$kw]: $($d.Name) -> $p"; continue }
        if ($script:VulnDrivers -contains $leaf) { $o += "FAILURE: Known-vulnerable driver loaded: $($d.Name) -> $p"; continue }
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $n++
        $s = Get-SigInfo -Path $p
        if ($s.Status -eq 'HashMismatch') { $o += "FAILURE: Driver signature hash mismatch: $($d.Name) -> $p" }
        elseif ($s.Status -ne 'Valid') { $unsigned += $d.Name }
    }
    if ($unsigned.Count -gt 0) { $o += "WARNING: $($unsigned.Count) running driver(s) without a valid signature ($(Get-ExampleText $unsigned))" }
    if ($o.Count -eq 0) { $o += "SUCCESS: All $n running drivers carry valid signatures" }
    return $o
}

function Get-DmaInputAlerts {
    $o = @()
    $fpga = @{ '10EE' = 'Xilinx'; '1172' = 'Altera/Intel FPGA'; '1204' = 'Lattice'; '11AA' = 'Microsemi'; '1D0F' = 'Amazon/Xilinx' }
    foreach ($dev in @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -like 'PCI\VEN_*' })) {
        if ($dev.DeviceID -match '^PCI\\VEN_([0-9A-Fa-f]{4})' -and $fpga.ContainsKey($matches[1].ToUpper())) {
            $o += "FAILURE: FPGA PCIe device present ($($fpga[$matches[1].ToUpper()])) -> $($dev.Name)"
        }
    }
    foreach ($s in 'ViGEmBus', 'HidHide', 'WinIo', 'interception') {
        if (Get-Service -Name $s) { $o += "WARNING: Input/hardware access driver installed -> $s" }
    }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No DMA hardware or virtual input drivers' }
    return $o
}

function Get-ProcessScanAlerts {
    $o = @(); $unsigned = @(); $seen = @{}
    foreach ($p in @(Get-CimInstance Win32_Process)) {
        $r = Test-ProcessRecord -Name ([string]$p.Name) -Path ([string]$p.ExecutablePath)
        if (-not $r -or $seen.ContainsKey($r)) { continue }
        $seen[$r] = $true
        if ($r -like 'WARNING: Unsigned program running from a user folder*') { $unsigned += [string]$p.Name } else { $o += $r }
    }
    if ($unsigned.Count -gt 0) { $o += "WARNING: $($unsigned.Count) unsigned program(s) running from user folders ($(Get-ExampleText $unsigned))" }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No unapproved, masquerading or unsigned user-folder processes' }
    return $o
}

function Get-ClientModuleAlerts {
    $o = @()
    $procs = @(Get-Process -Name RobloxPlayerBeta)
    if ($procs.Count -eq 0) { return @('INFO: Roblox not started yet - client is verified live in stage 3') }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $checked = 0
    foreach ($p in $procs) {
        $mods = $null
        try { $mods = $p.Modules } catch { $o += "WARNING: Could not enumerate modules of client PID $($p.Id)"; continue }
        foreach ($m in $mods) {
            $f = [string]$m.FileName
            if (-not $f -or -not $seen.Add($f)) { continue }
            if ($f.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { continue }
            $checked++
            $r = Test-LoadedModule -File $f
            if ($r) { $o += $r }
        }
    }
    if (-not ($o | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $o += "SUCCESS: All $checked non-Windows modules in the client are validly signed" }
    return $o
}

function Get-ClientMemoryAlerts {
    $o = @()
    $procs = @(Get-Process -Name RobloxPlayerBeta)
    if ($procs.Count -eq 0) { return @('INFO: Roblox not started yet - memory is scanned live in stage 3') }
    foreach ($p in $procs) {
        if ($p.Responding -eq $false) { $o += "WARNING: Client PID $($p.Id) is not responding" }
        $r = [TCAR.Native]::ScanRwx($p.Id)
        if ($null -eq $r) { $o += "WARNING: Could not scan memory of client PID $($p.Id)" }
        elseif ($r[0] -gt 0) { $o += "WARNING: Client PID $($p.Id) holds $($r[0]) private read/write/execute region(s), $([math]::Round($r[1] / 1KB)) KB - review" }
        else { $o += "SUCCESS: No private read/write/execute regions in client PID $($p.Id)" }
    }
    return $o
}

function Get-MemoryReaderAlerts {
    $ids = @(Get-Process -Name RobloxPlayerBeta | ForEach-Object { $_.Id })
    if ($ids.Count -eq 0) { return @('INFO: Roblox not started yet - handle scan runs live in stage 3') }
    $readers = [TCAR.Native]::FindReaders([int[]]$ids)
    if ($null -eq $readers) { return @('WARNING: Handle scan could not complete') }
    $o = @()
    foreach ($rid in ($readers | Select-Object -Unique)) {
        if ($rid -eq $PID) { continue }
        $c = Get-CimInstance Win32_Process -Filter "ProcessId=$rid"
        $name = [string]$c.Name; $path = [string]$c.ExecutablePath
        $nl = ($name -replace '\.exe$', '').ToLower()
        $trusted = (Test-TrustedDir $path) -and ((Get-SigInfo -Path $path).Status -eq 'Valid')
        if ($script:ReaderAllowlist -contains $nl -and $trusted) {
            $foreign = @()
            try {
                foreach ($m in (Get-Process -Id $rid).Modules) {
                    $mp = [string]$m.FileName
                    if (-not $mp -or $mp.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
                    if ($mp -like "$env:ProgramData\Microsoft\Windows Defender\*" -or $mp -like "$env:ProgramFiles\Windows Defender\*") { continue }
                    if ((Get-SigInfo -Path $mp).Status -ne 'Valid') { $foreign += $mp }
                }
            } catch {}
            if ($foreign.Count -gt 0) { $o += "FAILURE: $name (PID $rid) has a read handle to the client and loaded unsigned module(s): $(Get-ExampleText $foreign)" }
            continue
        }
        if ($trusted) { $o += "WARNING: Signed program holds a memory-read handle to the client: $name (PID $rid)"; continue }
        $o += "FAILURE: Unapproved process reading client memory: $name (PID $rid) -> $path"
    }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No unapproved process is reading client memory' }
    return $o
}

# ---------------------------------------------------------------------------- OBS & app tamper
function Get-ObsRoots {
    $roots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @(Get-Process -Name obs64, obs32)) {
        $path = $null; try { $path = $p.Path } catch {}
        if ($path) {
            $r = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $path))
            if ($r -and -not $roots.Contains($r)) { $roots.Add($r) }
        }
    }
    foreach ($r in @("$env:ProgramFiles\obs-studio", "${env:ProgramFiles(x86)}\obs-studio", "$env:LOCALAPPDATA\Programs\obs-studio")) {
        if ($r -and (Test-Path -LiteralPath "$r\bin") -and -not $roots.Contains($r)) { $roots.Add($r) }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OBS Studio', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OBS Studio') {
        $loc = ([string](Get-ItemProperty -Path $k -Name InstallLocation).InstallLocation).TrimEnd('\')
        if ($loc -and (Test-Path -LiteralPath "$loc\bin") -and -not $roots.Contains($loc)) { $roots.Add($loc) }
    }
    return @($roots)
}

# One module (DLL/EXE) loaded into obs64. Returns $null when it is acceptable.
function Test-ObsModule {
    param([string]$File, [string[]]$Roots)
    $leaf = [IO.Path]::GetFileName($File)
    $inObs = $false
    foreach ($r in $Roots) { if ($r -and $File.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { $inObs = $true } }
    $inPlugin = ($File -match '(?i)\\obs-plugins\\') -or ($File -match '(?i)\\obs-studio\\plugins\\')
    $kw = Get-Indicator $File
    $s = Get-SigInfo -Path $File
    $isMs = ($s.Status -eq 'Valid' -and $s.Subject -match 'Microsoft')
    $sysName = (Test-Path -LiteralPath (Join-Path "$env:SystemRoot\System32" $leaf)) -or ($leaf -match $script:CrtDllRx)

    # A Windows or C/C++ runtime DLL name (vcruntime140.dll, version.dll, dxgi.dll ...) outside the system folders
    # must be the genuine Microsoft-signed file; anything else is a sideloaded / proxy DLL.
    if ($sysName -and -not $isMs) {
        return "FAILURE: Windows/runtime DLL name '$leaf' loaded in OBS from outside the system folders without a Microsoft signature (sideloaded or proxy DLL, $($s.Status)) -> $File"
    }
    if ($s.Status -ne 'Valid') {
        $e = [TCAR.Native]::Entropy($File)
        $tag = if ($kw) { " [match: $kw]" } else { '' }
        if ($inPlugin -or -not $inObs) { return "FAILURE: Unsigned module$tag loaded in OBS ($($s.Status), entropy $e) -> $File" }
        return "WARNING: Unsigned OBS component$tag loaded ($($s.Status), entropy $e) - reinstall OBS if this is not a plugin -> $File"
    }
    if ($kw) { return "FAILURE: OBS module matches unauthorized-software indicator [$kw] -> $File" }
    if (-not $inObs -and -not (Test-TrustedDir $File)) { return "WARNING: Signed module loaded in OBS from outside the OBS and program folders -> $File" }
    return $null
}

function Get-ObsTamperAlerts {
    $o = @()
    $roots = @(Get-ObsRoots)
    $procs = @(Get-Process -Name obs64, obs32)
    if ($roots.Count -eq 0 -and $procs.Count -eq 0) { return @('INFO: OBS Studio is not installed or running - nothing to verify') }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $budget = 25
    $checked = 0
    $unsignedPlug = @(); $unsignedBin = @()

    foreach ($root in $roots) {
        # the OBS executables themselves
        foreach ($e in @(Get-ChildItem -Path "$root\bin\*\obs*.exe")) {
            $s = Get-SigInfo -Path $e.FullName; $checked++
            if ($s.Status -ne 'Valid') { $o += "FAILURE: OBS executable is not validly signed ($($s.Status)) -> $($e.FullName)" }
            if (Test-Path -LiteralPath "$($e.FullName).local") { $o += "FAILURE: DLL redirection folder next to OBS executable -> $($e.FullName).local" }
            if (Test-Path -LiteralPath "$($e.FullName).manifest") { $o += "WARNING: External manifest next to OBS executable -> $($e.FullName).manifest" }
        }
        # every executable inside the OBS install tree must be a known OBS component
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter *.exe)) {
            $s = Get-SigInfo -Path $f.FullName; $checked++
            if ($script:ObsKnownExe.Contains($f.Name)) {
                if ($s.Status -ne 'Valid') { $o += "FAILURE: OBS component executable is not validly signed ($($s.Status)) -> $($f.FullName)" }
            } elseif ($s.Status -ne 'Valid') { $o += "FAILURE: Unrecognized unsigned executable inside the OBS install -> $($f.FullName)" }
            else { $o += "WARNING: Unrecognized executable inside the OBS install -> $($f.FullName)" }
        }
        # plugin and core DLLs
        foreach ($dir in @(@("$root\obs-plugins", $true), @("$root\bin", $false))) {
            foreach ($f in @(Get-ChildItem -LiteralPath $dir[0] -Recurse -File -Filter *.dll)) {
                if ($sw.Elapsed.TotalSeconds -gt $budget) { break }
                $checked++
                $kw = Get-Indicator $f.Name
                $s = Get-SigInfo -Path $f.FullName
                $isMs = ($s.Status -eq 'Valid' -and $s.Subject -match 'Microsoft')
                $sysName = (Test-Path -LiteralPath (Join-Path "$env:SystemRoot\System32" $f.Name)) -or ($f.Name -match $script:CrtDllRx)
                if ($sysName -and -not $isMs) { $o += "FAILURE: Windows/runtime DLL name '$($f.Name)' in the OBS folder without a Microsoft signature (sideload/proxy DLL, $($s.Status)) -> $($f.FullName)" }
                elseif ($kw) { $o += "FAILURE: OBS file matches indicator [$kw] -> $($f.FullName)" }
                elseif ($s.Status -ne 'Valid') { if ($dir[1]) { $unsignedPlug += $f.FullName } else { $unsignedBin += $f.FullName } }
            }
        }
    }
    # user-installed plugins (loaded by OBS from the profile folder)
    foreach ($f in @(Get-ChildItem -LiteralPath "$env:APPDATA\obs-studio\plugins" -Recurse -File -Filter *.dll)) {
        $checked++
        $kw = Get-Indicator $f.Name
        if ($kw) { $o += "FAILURE: OBS user plugin matches indicator [$kw] -> $($f.FullName)" }
        elseif ((Get-SigInfo -Path $f.FullName).Status -ne 'Valid') { $unsignedPlug += $f.FullName }
    }
    if ($unsignedPlug.Count -gt 0) { $o += "WARNING: $($unsignedPlug.Count) unsigned OBS plugin DLL(s) installed ($(Get-ExampleText ($unsignedPlug | ForEach-Object { Split-Path -Leaf $_ })))" }
    if ($unsignedBin.Count -gt 0) { $o += "WARNING: $($unsignedBin.Count) unsigned DLL(s) in the OBS bin folder ($(Get-ExampleText ($unsignedBin | ForEach-Object { Split-Path -Leaf $_ })))" }

    # scripts (Lua/Python) saved in scene collections run inside OBS
    foreach ($f in @(Get-ChildItem -Path "$env:APPDATA\obs-studio\basic\scenes\*.json")) {
        $txt = [IO.File]::ReadAllText($f.FullName)
        foreach ($mt in [regex]::Matches($txt, '"path"\s*:\s*"([^"]+\.(?:lua|py))"', 'IgnoreCase')) {
            $sp = ($mt.Groups[1].Value -replace '\\\\', '\') -replace '/', '\'
            $kw = Get-Indicator $sp
            if ($kw) { $o += "FAILURE: OBS script matches indicator [$kw] in collection '$($f.BaseName)' -> $sp" }
            else { $o += "WARNING: OBS script runs in collection '$($f.BaseName)' -> $sp" }
        }
    }

    # live process: loaded modules, unrecognized programs launched by OBS, injected executable memory
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $live = 0
    foreach ($p in $procs) {
        $mods = $null
        try { $mods = @($p.Modules) } catch { $o += "WARNING: Could not enumerate modules of OBS PID $($p.Id)"; continue }
        foreach ($m in $mods) {
            $f = [string]$m.FileName
            if (-not $f -or -not $seen.Add($f)) { continue }
            if ($f.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { continue }
            $live++
            $r = Test-ObsModule -File $f -Roots $roots
            if ($r) { $o += $r }
        }
        $res = [TCAR.Native]::ScanRwx($p.Id)
        if ($null -ne $res -and $res[0] -gt 0) { $o += "WARNING: OBS PID $($p.Id) holds $($res[0]) private read/write/execute region(s), $([math]::Round($res[1] / 1KB)) KB (possible injected code)" }
    }
    $ids = @($procs | ForEach-Object { [int]$_.Id })
    if ($ids.Count -gt 0) {
        foreach ($c in @(Get-CimInstance Win32_Process | Where-Object { $ids -contains [int]$_.ParentProcessId })) {
            $nm = [string]$c.Name; $path = [string]$c.ExecutablePath
            if ($nm -ieq 'conhost.exe') { continue }
            if ($script:ObsKnownExe.Contains($nm)) {
                $under = $false
                foreach ($r in $roots) { if ($path -and $path.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { $under = $true } }
                if ($path -and -not $under) { $o += "FAILURE: OBS helper name '$nm' running from outside the OBS install -> $path" }
                continue
            }
            $st = 'Unknown'; if ($path -and (Test-Path -LiteralPath $path)) { $st = (Get-SigInfo -Path $path).Status }
            if ($st -ne 'Valid') { $o += "FAILURE: Unrecognized unsigned program launched by OBS: $nm -> $path" }
            else { $o += "WARNING: Unrecognized program launched by OBS: $nm -> $path" }
        }
    }

    if (-not ($o | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) {
        if ($procs.Count -gt 0) { $o += "SUCCESS: OBS install, plugins, $live loaded modules and child processes verified ($checked files)" }
        else { $o += "SUCCESS: OBS install and plugins verified ($checked files); OBS is not running" }
    }
    return $o
}

# ---------------------------------------------------------------------------- Native syscall hooks
# Compares the in-memory prologues of ntdll/win32u/kernelbase/kernel32/user32/amsi exports (syscall stubs, ETW,
# AMSI, memory and loader APIs) with the on-disk files, and looks for syscall stubs living outside ntdll.
function Invoke-HookScan {
    param([System.Diagnostics.Process]$Proc, [string]$Label, [bool]$Strict)
    $o = @()
    $mods = $null
    try { $mods = @($Proc.Modules) } catch { return @("WARNING: Could not read modules of $Label (PID $($Proc.Id)) - hook scan skipped") }
    $sys32 = "$env:SystemRoot\System32"
    $found = New-Object 'System.Collections.Generic.List[object]'
    foreach ($t in @(@('ntdll.dll', $true), @('win32u.dll', $true), @('kernelbase.dll', $false), @('kernel32.dll', $false), @('user32.dll', $false), @('amsi.dll', $false))) {
        $m = $mods | Where-Object { $_.ModuleName -ieq $t[0] -and ([string]$_.FileName) -like "$sys32\*" } | Select-Object -First 1
        if (-not $m) { continue }
        $extra = $script:HookApis[$t[0]]
        $r = [TCAR.Native]::ScanHooks($Proc.Id, (Join-Path $sys32 $t[0]), $m.BaseAddress.ToInt64(), [bool]$t[1], [string[]]$extra)
        if ($null -eq $r) { $o += "WARNING: Hook scan of $($t[0]) in $Label (PID $($Proc.Id)) could not run"; continue }
        foreach ($line in $r) {
            $pt = ([string]$line).Split('|')
            $found.Add(@{ Dll = $t[0]; Name = $pt[0]; Kind = $pt[1]; Dest = [Convert]::ToInt64($pt[2], 16) })
        }
    }

    $groups = @{}; $groupCrit = @{}
    $critMod = @(); $mod = @()
    foreach ($f in $found) {
        $crit = ($script:HookCritical -contains $f.Name)
        $tag = "$($f.Dll)!$($f.Name)"
        if ($f.Kind -eq 'modified') { if ($crit) { $critMod += $tag } else { $mod += $tag }; continue }
        $dm = $null
        if ($f.Dest -ne 0) {
            $dm = $mods | Where-Object { $a = $_.BaseAddress.ToInt64(); $f.Dest -ge $a -and $f.Dest -lt ($a + $_.ModuleMemorySize) } | Select-Object -First 1
        }
        $key = if ($dm) { [string]$dm.FileName } elseif ($f.Dest -ne 0) { 'unbacked' } else { 'unresolved' }
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object 'System.Collections.Generic.List[string]'; $groupCrit[$key] = $false }
        $groups[$key].Add($tag)
        if ($crit) { $groupCrit[$key] = $true }
    }
    foreach ($key in @($groups.Keys)) {
        $items = @($groups[$key])
        $ex = Get-ExampleText $items
        $lvl = 'WARNING'; $where = $key
        if ($key -eq 'unbacked') { $where = 'unbacked (private) memory'; if ($Strict -or $groupCrit[$key]) { $lvl = 'FAILURE' } }
        elseif ($key -eq 'unresolved') { $where = 'an unresolved address'; if ($Strict) { $lvl = 'FAILURE' } }
        else {
            $s = Get-SigInfo -Path $key
            if ($s.Status -eq 'Valid' -and $s.Subject -match 'Microsoft' -and $key.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { continue }   # Windows shim/compat layer
            if ($s.Status -ne 'Valid' -or (Get-Indicator $key)) { $lvl = 'FAILURE' }
        }
        $o += "${lvl}: Inline hook on $($items.Count) native API function(s) in $Label (PID $($Proc.Id)) redirected to $where ($ex)"
    }
    if ($critMod.Count -gt 0) { $o += "FAILURE: Patched prologue of critical API(s) in $Label (PID $($Proc.Id)) - syscall/ETW/AMSI/memory bypass pattern ($(Get-ExampleText $critMod))" }
    if ($mod.Count -gt 0) { $o += "WARNING: $($mod.Count) function prologue(s) differ from the on-disk file in $Label (PID $($Proc.Id)) ($(Get-ExampleText $mod))" }

    $st = [TCAR.Native]::ScanSyscallStubs($Proc.Id)
    if ($st -and $st.Count -gt 0) {
        $first = ([string]$st[0]).Split('|')
        $lvl = if ($Strict) { 'FAILURE' } else { 'WARNING' }
        $o += "${lvl}: Direct syscall stub in executable non-image memory of $Label (PID $($Proc.Id)): $($st.Count) region(s), first at 0x$($first[0]) ($($first[1]))"
    }
    return $o
}

function Get-SyscallHookAlerts {
    $o = @(); $scanned = @()
    $o += @(Invoke-HookScan -Proc (Get-Process -Id $PID) -Label 'this PowerShell session' -Strict $true)
    $scanned += 'PowerShell'
    foreach ($p in @(Get-Process -Name obs64, obs32)) { $o += @(Invoke-HookScan -Proc $p -Label 'OBS' -Strict $true); $scanned += 'OBS' }
    $rbx = @(Get-Process -Name RobloxPlayerBeta)
    foreach ($p in $rbx) { $o += @(Invoke-HookScan -Proc $p -Label 'Roblox client' -Strict $false); $scanned += 'Roblox client' }
    if (-not ($o | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $o += "SUCCESS: Native API prologues match disk, no stray syscall stubs ($(($scanned | Select-Object -Unique) -join ', '))" }
    if ($rbx.Count -eq 0) { $o += 'INFO: Roblox not started yet - client hooks are scanned live in stage 3' }
    return $o
}

function Get-InjectionVectorAlerts {
    $o = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $d = [string](Get-ItemProperty -Path $k -Name AppInit_DLLs).AppInit_DLLs
        if ($d.Trim()) { $o += "FAILURE: AppInit_DLLs configured (loads into every process) -> $d" }
    }
    foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($k in @(Get-ChildItem $root)) {
            $dbg = [string](Get-ItemProperty -Path $k.PSPath -Name Debugger).Debugger
            if (-not $dbg) { continue }
            if ($k.PSChildName -match '(?i)roblox|obs64|obs32|powershell') { $o += "FAILURE: Launch hook (IFEO debugger) on $($k.PSChildName) -> $dbg" }
            elseif ($k.PSChildName -ieq 'Taskmgr.exe' -and $dbg -match '(?i)procexp') { continue }
            else { $o += "WARNING: IFEO debugger on $($k.PSChildName) -> $dbg" }
        }
    }
    foreach ($v in 'COR_ENABLE_PROFILING', 'COR_PROFILER', 'COR_PROFILER_PATH', 'CORECLR_ENABLE_PROFILING', 'CORECLR_PROFILER', 'CORECLR_PROFILER_PATH', 'COMPLUS_ENABLE_PROFILING') {
        foreach ($scope in 'Machine', 'User', 'Process') {
            $val = [Environment]::GetEnvironmentVariable($v, $scope)
            if ($val) { $o += "FAILURE: .NET profiler variable $v ($scope) = $val" }
        }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
        $props = Get-ItemProperty -Path $k
        if (-not $props) { continue }
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -match '^PS') { continue }
            $kw = Get-Indicator ([string]$pr.Value); if (-not $kw) { $kw = Get-Indicator $pr.Name }
            if ($kw) { $o += "FAILURE: Autorun entry matches indicator [$kw]: '$($pr.Name)' -> $($pr.Value)" }
        }
    }
    foreach ($t in @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\Windows\*' })) {
        $act = (@($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ')
        $kw = Get-Indicator $act; if (-not $kw) { $kw = Get-Indicator $t.TaskName }
        if ($kw) { $o += "FAILURE: Scheduled task matches indicator [$kw]: '$($t.TaskName)' -> $act" }
        elseif ($act -match '(?i)(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32).*(-enc|encodedcommand|bypass|hidden|downloadstring|iex)') { $o += "WARNING: Scheduled task runs a hidden/encoded script: '$($t.TaskName)'" }
    }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No load-hook, profiler or autorun injection vectors found' }
    return $o
}

function Get-SoftwareIndicatorAlerts {
    $o = @(); $packed = @()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    # software.exe / upgrade.exe anywhere inside Downloads
    $fl = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $script:FlaggedDownloads) { [void]$fl.Add($n) }
    foreach ($hit in @(Find-NamedFiles -Roots @("$env:USERPROFILE\Downloads") -Names $fl -MaxDepth 4 -BudgetSec 15)) {
        $r = Test-FlaggedDownload -Path $hit
        if ($r) { $o += $r }
    }

    foreach ($fd in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:TEMP, "$env:SystemDrive\")) {
        foreach ($f in @(Get-ChildItem -LiteralPath $fd -File | Where-Object { $_.Extension -match '(?i)^\.(exe|dll)$' } | Sort-Object LastWriteTime -Descending | Select-Object -First 25)) {
            if (-not $seen.Add($f.FullName)) { continue }
            $kw = Get-Indicator $f.Name
            $signed = ((Get-SigInfo -Path $f.FullName).Status -eq 'Valid')
            if ($kw -and -not $signed) { $o += "FAILURE: Unsigned binary matches indicator [$kw] -> $($f.FullName)"; continue }
            if ($kw) { $o += "WARNING: Binary matches indicator [$kw] (signed) -> $($f.FullName)"; continue }
            if (-not $signed -and $f.Length -gt 50KB -and $f.Length -lt 30MB) {
                $e = [TCAR.Native]::Entropy($f.FullName)
                if ($e -ge 7.2 -and $e -le 7.95) { $packed += $f.Name }
            }
        }
    }
    if ($packed.Count -gt 0) { $o += "WARNING: $($packed.Count) unsigned high-entropy (possibly packed) binar$(if ($packed.Count -eq 1) {'y'} else {'ies'}) in user folders ($(Get-ExampleText $packed))" }
    $folders = @(Find-IndicatorFolders -Roots @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData) -MaxDepth 2 -BudgetSec 20)
    if ($folders.Count -gt 0) { $o += "WARNING: $($folders.Count) folder name(s) match software indicators ($(Get-ExampleText ($folders | ForEach-Object { Split-Path -Leaf $_ })))" }
    if (Test-Path "$env:ProgramData\KeyAuth") { $o += "FAILURE: Licensing-service data folder found -> $env:ProgramData\KeyAuth" }
    if (Test-Path 'HKCU:\Antenna') { $o += 'FAILURE: Known registry marker present (HKCU:\Antenna)' }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No indicator matches or packed binaries in user folders' }
    return $o
}

# Official Windows executables (ctfmon.exe, SecurityHealthService.exe, ...) found outside system folders,
# or anywhere without a valid Microsoft signature.
function Get-ImpostorAlerts {
    $o = @()
    $roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, "$env:SystemRoot\Temp")
    $hits = @(Find-NamedFiles -Roots $roots -Names $script:OfficialWinExe -MaxDepth 3 -BudgetSec 40)
    $hits += @(Find-NamedFiles -Roots @("$env:SystemDrive\", $env:SystemRoot) -Names $script:OfficialWinExe -MaxDepth 0 -BudgetSec 5)
    $n = 0
    foreach ($f in ($hits | Select-Object -Unique)) {
        $n++
        $r = Test-OfficialExe -Name ([IO.Path]::GetFileName($f)) -Path $f
        if ($r) { $o += $r }
    }
    if ($o.Count -eq 0) { $o += "SUCCESS: No impostor or unsigned official-Windows executables ($n candidate file(s) checked)" }
    return $o
}

function Get-NetworkAlerts {
    $o = @()
    $pipes = @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { Split-Path -Leaf $_ })
    foreach ($pp in $pipes) {
        if ($pp -match '(?i)krampus|solara|wavepipe|celery|fluxus|krnl|wearedevs|oxygen|hydrogen|comet|valyse|xeno|synapse') { $o += "FAILURE: Named pipe matches an indicator -> \\.\pipe\$pp" }
    }
    foreach ($line in @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts")) {
        $t = $line.Trim()
        if ($t -and -not $t.StartsWith('#') -and $t -match '(?i)roblox|rbxcdn|clientsettings') { $o += "FAILURE: Hosts file redirects a Roblox domain -> $t" }
    }
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($ie.ProxyEnable -eq 1) { $o += "WARNING: System proxy enabled -> $($ie.ProxyServer)" }
    $dns = @()
    foreach ($h in @(Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique)) {
        if (-not $h -or $h -match $script:DnsAllow) { continue }
        if (Get-Indicator $h) { $dns += $h }
    }
    if ($dns.Count -gt 0) { $o += "WARNING: $($dns.Count) DNS cache entr$(if ($dns.Count -eq 1) {'y'} else {'ies'}) match indicators ($(Get-ExampleText $dns))" }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No pipe, hosts-file, proxy or DNS indicators' }
    return $o
}

function Get-RootCertAlerts {
    $o = @(); $user = @()
    $auth = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem 'Cert:\LocalMachine\AuthRoot' | ForEach-Object { [void]$auth.Add($_.Thumbprint) }
    foreach ($t in $script:MicrosoftShippedRoots) { [void]$auth.Add($t) }
    foreach ($store in @(@('Cert:\CurrentUser\Root', 'user'), @('Cert:\LocalMachine\Root', 'machine'))) {
        foreach ($c in @(Get-ChildItem $store[0])) {
            if ($auth.Contains($c.Thumbprint)) { continue }
            $short = $c.Subject; if ($c.Subject -match 'CN=([^,]+)') { $short = $matches[1] }
            if ($c.Subject -match '(?i)microsoft') { $o += "FAILURE: Forged Microsoft root certificate '$short' ($($store[1]) store)" }
            elseif ($store[1] -eq 'user') { $user += $short }
        }
    }
    if ($user.Count -gt 0) { $o += "WARNING: $($user.Count) user-installed root certificate(s) ($(Get-ExampleText $user))" }
    if ($o.Count -eq 0) { $o += 'SUCCESS: No user-installed root certificates' }
    return $o
}

function Get-ExecutionHistoryAlerts {
    $o = @()
    $logon = Get-LogonTime
    $entries = @()
    foreach ($root in 'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings') {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($root)
        if (-not $rk) { continue }
        foreach ($sid in $rk.GetSubKeyNames()) {
            if ($sid -eq 'S-1-5-18') { continue }
            $sk = $rk.OpenSubKey($sid)
            foreach ($n in $sk.GetValueNames()) {
                $raw = $sk.GetValue($n)
                if ($n -notmatch '\\' -or $raw -isnot [byte[]] -or $raw.Length -lt 8) { continue }
                try { $entries += [pscustomobject]@{ Time = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw, 0)); Path = $n } } catch {}
            }
            $sk.Close()
        }
        $rk.Close()
    }
    if ($entries.Count -eq 0) { return @('FAILURE: Execution history (BAM) is empty - wiped or not recording') }
    $svc = Get-Service -Name bam
    if (-not $svc -or $svc.Status -ne 'Running') { $o += 'FAILURE: BAM service is not running' }
    $hit = $false
    foreach ($e in $entries) {
        $kw = Get-Indicator $e.Path
        if ($kw) { $hit = $true; $o += "FAILURE: Execution history matches indicator [$kw] at $(Get-Date $e.Time -Format 'yyyy-MM-dd HH:mm:ss') -> $($e.Path)" }
        $fd = Test-FlaggedDownload -Path $e.Path
        if ($fd) { $hit = $true; $o += ($fd -replace '^FAILURE: ', 'FAILURE: Execution history - ') + " (ran $(Get-Date $e.Time -Format 'yyyy-MM-dd HH:mm:ss'))" }
        $leaf = ([string]$e.Path).Substring(([string]$e.Path).LastIndexOf('\') + 1)
        if ($script:OfficialWinExe.Contains($leaf) -and ([string]$e.Path) -notmatch $script:OfficialDirRx) {
            $hit = $true
            $o += "FAILURE: Execution history - official Windows file name '$leaf' ran outside system folders at $(Get-Date $e.Time -Format 'yyyy-MM-dd HH:mm:ss') -> $($e.Path)"
        }
    }
    if (-not $hit -and $o.Count -eq 0) { $o += "SUCCESS: $($entries.Count) history entries reviewed, no indicator matches" }
    $recent = @($entries | Where-Object { $_.Time -ge $logon -and $_.Path -notmatch '(?i)\\windows\\' } | Sort-Object Time -Descending | Select-Object -First 10)
    foreach ($e in $recent) { $o += "INFO: $(Get-Date $e.Time -Format 'HH:mm:ss')  $($e.Path)" }
    return $o
}

function Get-AuditTrailAlerts {
    $o = @()
    $pfDir = "$env:WINDIR\Prefetch"
    $pf = @(Get-ChildItem -LiteralPath $pfDir -Filter '*.pf')
    if (-not (Test-Path -LiteralPath $pfDir)) { $o += 'FAILURE: Prefetch folder is missing' }
    elseif ($pf.Count -eq 0) { $o += 'FAILURE: Prefetch folder is empty (wiped or disabled)' }
    elseif ($pf.Count -lt 20) { $o += "WARNING: Only $($pf.Count) prefetch files present (recently cleaned?)" }
    foreach ($f in $pf) {
        $kw = Get-Indicator $f.Name
        if ($kw) { $o += "FAILURE: Prefetch entry matches indicator [$kw] -> $($f.Name) ($(Get-Date $f.LastWriteTime -Format 'yyyy-MM-dd HH:mm'))" }
        elseif ($f.Name -match '(?i)^(SOFTWARE|UPGRADE)\.EXE-') { $o += "WARNING: Prefetch entry for flagged file name -> $($f.Name) ($(Get-Date $f.LastWriteTime -Format 'yyyy-MM-dd HH:mm'))" }
    }
    $ep = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher
    if ($ep -eq 0) { $o += 'FAILURE: Prefetch logging is disabled (EnablePrefetcher = 0)' } elseif ($ep -eq 2) { $o += 'WARNING: Application prefetch is off (EnablePrefetcher = 2)' }
    $sm = Get-Service -Name SysMain
    if (-not $sm -or $sm.Status -ne 'Running') { $o += 'FAILURE: SysMain service is not running' }

    $usn = & "$env:SystemRoot\System32\fsutil.exe" usn queryjournal $env:SystemDrive 2>&1 | Out-String
    if ($usn -match '(?im)^\s*Usn Journal ID\s*:\s*0x([0-9a-f]+)') {
        $created = $null; try { $created = [DateTime]::FromFileTime([Convert]::ToInt64($matches[1], 16)) } catch {}
        $boot = Get-BootTime
        if ($created -and $boot -and $created -gt $boot.AddMinutes(10)) { $o += 'FAILURE: USN journal was recreated after boot (deleted this session)' }
        elseif ($created -and $created -gt (Get-Date).AddDays(-2)) { $o += 'WARNING: USN journal is less than 2 days old' }
    } else { $o += 'FAILURE: USN journal is missing or unreadable' }

    $since = Get-BootTime
    foreach ($flt in @(@{ LogName = 'Security'; Id = 1102 }, @{ LogName = 'System'; Id = 104 })) {
        $flt.StartTime = $since
        foreach ($e in @(Get-WinEvent -FilterHashtable $flt -MaxEvents 5)) { $o += "FAILURE: '$($flt.LogName)' event log was cleared at $(Get-Date $e.TimeCreated -Format 'HH:mm:ss')" }
    }
    $hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path -LiteralPath $hist) {
        $pat = 'wevtutil\s+(cl|clear-log)|Clear-EventLog|fsutil\s+usn\s+deletejournal|vssadmin.*delete\s+shadows|Set-MpPreference[^\r\n]*-Disable|Add-MpPreference[^\r\n]*-Exclusion|bcdedit[^\r\n]*testsigning\s+on'
        foreach ($l in @(Get-Content $hist | Select-Object -Last 1500 | Where-Object { $_ -match "(?i)$pat" -and $_ -notmatch 'TCAR|RecordingPolicy' } | Select-Object -Unique -First 5)) {
            $o += "FAILURE: Log/antivirus tampering command in PowerShell history -> $($l.Trim())"
        }
    }
    if ($o.Count -eq 0) { $o += "SUCCESS: Prefetch ($($pf.Count) files), USN journal and event logs intact" }
    return $o
}

# ---------------------------------------------------------------------------- PowerShell module integrity
# One DLL loaded into (or installed for) PowerShell. Returns $null when it is acceptable.
function Test-PsModuleFile {
    param([string]$File, [string]$Who = 'PowerShell')
    $kw = Get-Indicator ([IO.Path]::GetFileName($File))
    $tag = if ($kw) { " [match: $kw]" } else { '' }
    $s = Get-SigInfo -Path $File
    if ($s.Status -ne 'Valid') {
        $e = [TCAR.Native]::Entropy($File)
        return "FAILURE: Unsigned DLL$tag loaded in $Who ($($s.Status), entropy $e) -> $File"
    }
    if ($kw) { return "FAILURE: Module matches unauthorized-software indicator [$kw] loaded in $Who -> $File" }
    if ($s.Subject -notmatch 'Microsoft' -and -not (Test-TrustedDir $File)) { return "WARNING: Non-Microsoft DLL loaded in $Who from outside the Windows/Program Files folders -> $File" }
    return $null
}

# Every module mapped into any running PowerShell process (the NotSigned / HashMismatch DLL check).
function Get-PsLoadedModuleAlerts {
    param([int]$BudgetSec = 25)
    $o = @(); $checked = 0; $skipped = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $selfAsm = ''; try { $selfAsm = [string][TCAR.Native].Assembly.Location } catch {}
    foreach ($p in @(Get-Process -Name powershell, pwsh, powershell_ise)) {
        $mods = $null
        try { $mods = @($p.Modules) } catch { $o += "WARNING: Could not enumerate modules of PowerShell PID $($p.Id)"; continue }
        $who = if ($p.Id -eq $PID) { 'this PowerShell session' } else { "PowerShell PID $($p.Id)" }
        $files = @($mods | ForEach-Object { [string]$_.FileName } | Where-Object { $_ -and $_ -ne $selfAsm -and $_ -notmatch '(?i)\\assembly\\NativeImages_' } | Sort-Object -Unique)
        $user = @($files | Where-Object { -not $_.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase) })
        $sysf = @($files | Where-Object { $_.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase) })
        foreach ($f in $user) { $checked++; $r = Test-PsModuleFile -File $f -Who $who; if ($r) { $o += $r } }
        foreach ($f in $sysf) {
            if ($sw.Elapsed.TotalSeconds -gt $BudgetSec) { $skipped++; continue }
            $checked++
            $r = Test-PsModuleFile -File $f -Who $who
            if ($r) { $o += $r }
        }
    }
    $script:PsModChecked = $checked
    $script:PsModSkipped = $skipped
    return $o
}

# Assemblies loaded from memory (Assembly.Load(byte[]) / reflective loading) never show up as DLL files.
function Get-PsAssemblyAlerts {
    $o = @()
    foreach ($a in [AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($a.IsDynamic) { continue }
        $loc = ''; try { $loc = [string]$a.Location } catch {}
        if ($loc) { continue }
        $own = $false; try { if ($a.GetType('TCAR.Native', $false)) { $own = $true } } catch {}
        if ($own) { continue }
        $o += "WARNING: In-memory (reflectively loaded) assembly in this PowerShell session -> $($a.FullName)"
    }
    return $o
}

# PSModulePath entries and the DLLs / module scripts installed in them.
function Get-PsModulePathAlerts {
    $o = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $dirs = @($env:PSModulePath -split ';' | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique)
    foreach ($d in $dirs) {
        if ($d -notmatch '(?i)\\(WindowsPowerShell|PowerShell(\\7)?)\\Modules$|\\v1\.0\\Modules$') { $o += "WARNING: Non-standard PowerShell module path in PSModulePath -> $d" }
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $isSys = $d.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter *.dll)) {
            if ($sw.Elapsed.TotalSeconds -gt 25) { break }
            $kw = Get-Indicator $f.Name
            $s = Get-SigInfo -Path $f.FullName
            if ($s.Status -ne 'Valid') {
                $lvl = if ($isSys -or $kw) { 'FAILURE' } else { 'WARNING' }
                $o += "${lvl}: Unsigned DLL ($($s.Status)) in a PowerShell module folder -> $($f.FullName)"
            } elseif ($kw) { $o += "FAILURE: PowerShell module DLL matches indicator [$kw] -> $($f.FullName)" }
        }
        if ($isSys) {
            foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter *.psm1)) {
                if ($sw.Elapsed.TotalSeconds -gt 25) { break }
                $s = Get-SigInfo -Path $f.FullName
                if ($s.Status -eq 'HashMismatch') { $o += "FAILURE: Built-in PowerShell module script was modified after signing -> $($f.FullName)" }
                elseif ($s.Status -eq 'NotSigned') { $o += "WARNING: Built-in PowerShell module script is unsigned -> $($f.FullName)" }
            }
        }
    }
    return $o
}

function Get-PowerShellAlerts {
    $o = @()
    $ps = Get-AuthenticodeSignature -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not ($ps.Status -eq 'Valid' -and $ps.SignerCertificate.Subject -like '*Microsoft Windows*')) { $o += 'FAILURE: powershell.exe signature is invalid' }
    $sma = ''; try { $sma = [string][psobject].Assembly.Location } catch {}
    if ($sma) {
        $s = Get-SigInfo -Path $sma
        if ($s.Status -ne 'Valid') { $o += "FAILURE: System.Management.Automation.dll is not validly signed ($($s.Status)) -> $sma" }
    }

    $o += @(Get-PsLoadedModuleAlerts)
    $o += @(Get-PsAssemblyAlerts)
    $o += @(Get-PsModulePathAlerts)

    $defaults = @('Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Diagnostics', 'Microsoft.PowerShell.Host', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Operation.Validation', 'PackageManagement', 'PowerShellGet', 'PSReadLine', 'Pester', 'ThreadJob')
    $extra = @(Get-ChildItem "$env:ProgramFiles\WindowsPowerShell\Modules" -Directory | Where-Object { $defaults -notcontains $_.Name } | ForEach-Object { $_.Name })
    if ($extra.Count -gt 0) { $o += "WARNING: $($extra.Count) non-default PowerShell module(s) installed ($(Get-ExampleText $extra))" }
    foreach ($fn in @(Get-ChildItem Function:\ | Where-Object { $_.Source -eq '' -and $_.Name -match '^(Get|Test|Select|Where|Invoke)-' -and (Get-Command -CommandType Cmdlet -Name $_.Name) })) {
        $o += "FAILURE: Function overrides built-in cmdlet -> $($fn.Name)"
    }
    foreach ($al in @(Get-Alias | Where-Object { Get-Command -CommandType Cmdlet -Name $_.Name })) {
        $o += "FAILURE: Alias overrides built-in cmdlet -> $($al.Name) = $($al.Definition)"
    }
    foreach ($p in @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)) {
        if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { $o += "WARNING: PowerShell profile runs code at startup -> $p" }
    }
    if (-not ($o | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) {
        $o += "SUCCESS: $($script:PsModChecked) loaded modules, module folders and session are untampered"
    }
    return $o
}

# ============================================================================ UI
function Write-Bar {
    param([string]$Text, [string]$Bg = 'DarkCyan', [string]$Fg = 'White')
    Write-Host (' ' + $Text.PadRight($script:Width)) -ForegroundColor $Fg -BackgroundColor $Bg
}

function Write-Badge {
    param([string]$Status)
    switch ($Status) {
        'PASS' { Write-Host ' PASS ' -NoNewline -ForegroundColor Black -BackgroundColor Green }
        'WARN' { Write-Host ' WARN ' -NoNewline -ForegroundColor Black -BackgroundColor Yellow }
        'FAIL' { Write-Host ' FAIL ' -NoNewline -ForegroundColor White -BackgroundColor Red }
        default { Write-Host " $Status " -NoNewline -ForegroundColor Black -BackgroundColor Gray }
    }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 100)
    if ($Text.Length -gt $Max) { return $Text.Substring(0, $Max - 3) + '...' }
    return $Text
}

function Write-Header {
    param([string]$Subtitle)
    Clear-Host
    Write-Host ''
    Write-Bar ('TCAR ARC  |  COMPLIANCE VERIFICATION' + (' ' * 19) + 'v' + $script:Ver) 'DarkCyan' 'White'
    Write-Bar $Subtitle 'DarkGray' 'White'
    Write-Host ''
}

function Get-Status {
    param([string[]]$Lines)
    if (@($Lines | Where-Object { $_ -like 'FAILURE*' }).Count -gt 0) { return 'FAIL' }
    if (@($Lines | Where-Object { $_ -like 'WARNING*' }).Count -gt 0) { return 'WARN' }
    return 'PASS'
}

function Get-Summary {
    param([string[]]$Lines, [string]$Status)
    $flagged = @($Lines | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' }).Count
    if ($flagged -gt 0) { return "$flagged finding$(if ($flagged -ne 1) {'s'})" }
    $first = @($Lines | Where-Object { $_ -like 'SUCCESS*' } | Select-Object -First 1)
    if ($first.Count -eq 0) { $first = @($Lines | Where-Object { $_ -like 'INFO*' } | Select-Object -First 1) }
    if ($first.Count -eq 0) { return '' }
    return (Limit-Text (($first[0] -replace '^(SUCCESS|INFO):\s*', '')) 46)
}

function Wait-Enter {
    param([string]$Message = 'Press Enter to continue')
    Write-Host ''
    Write-Host "  > $Message" -ForegroundColor Yellow
    [void](Read-Host)
}

# ============================================================================ INTRO
$refId = 'TC-' + (Get-Date -Format 'yyMMdd') + '-' + ('{0:X4}' -f (Get-Random -Maximum 65535))
Write-Header 'Session preparation'
Write-Host "  Host       $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Operator   $env:USERNAME" -ForegroundColor Gray
Write-Host "  Reference  $refId" -ForegroundColor Gray
Write-Host "  Started    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ''
Write-Host '  Stages' -ForegroundColor White
Write-Host '    1  System verification   integrity, software and client-process checks' -ForegroundColor Gray
Write-Host '    2  Process Explorer      full process list shown on the recording' -ForegroundColor Gray
Write-Host '    3  Session monitor       live monitoring until the match ends' -ForegroundColor Gray
Write-Host ''
Write-Host '  Before you begin' -ForegroundColor White
Write-Host '    - Roblox must be CLOSED now. You will be told when to open it (stage 3).' -ForegroundColor Yellow
Write-Host '    - Keep this window visible for the whole recording.' -ForegroundColor Gray
Wait-Enter 'Press Enter to begin stage 1'
while (@(Get-Process -Name RobloxPlayerBeta, RobloxPlayerLauncher -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Host ''
    Write-Host '  Roblox is currently running. Close it completely (check the system tray too).' -ForegroundColor Red
    Write-Host '  > Close Roblox, then press Enter' -ForegroundColor Yellow
    [void](Read-Host)
}

# ============================================================================ STAGE 1
Write-Header 'Stage 1 of 3  -  System verification'

$checks = @(
    @{ N = 'System information';          R = { Get-SystemInfoAlerts } },
    @{ N = 'Antivirus';                   R = { Get-DefenderAlerts } },
    @{ N = 'Antivirus exclusions';        R = { Get-ExclusionAlerts } },
    @{ N = 'Protection history';          R = { Get-ThreatAlerts } },
    @{ N = 'Memory integrity & boot';     R = { Get-IntegrityAlerts } },
    @{ N = 'Kernel drivers';              R = { Get-DriverAlerts } },
    @{ N = 'Hardware access devices';     R = { Get-DmaInputAlerts } },
    @{ N = 'Running processes';           R = { Get-ProcessScanAlerts } },
    @{ N = 'Client: loaded modules';      R = { Get-ClientModuleAlerts } },
    @{ N = 'Client: memory regions';      R = { Get-ClientMemoryAlerts } },
    @{ N = 'Client: external readers';    R = { Get-MemoryReaderAlerts } },
    @{ N = 'OBS & app tamper';            R = { Get-ObsTamperAlerts } },
    @{ N = 'Native syscall hooks';        R = { Get-SyscallHookAlerts } },
    @{ N = 'Load-hook vectors';           R = { Get-InjectionVectorAlerts } },
    @{ N = 'Software indicators';         R = { Get-SoftwareIndicatorAlerts } },
    @{ N = 'Network & pipes';             R = { Get-NetworkAlerts } },
    @{ N = 'Root certificates';           R = { Get-RootCertAlerts } },
    @{ N = 'Execution history';           R = { Get-ExecutionHistoryAlerts } },
    @{ N = 'Audit trail integrity';       R = { Get-AuditTrailAlerts } },
    @{ N = 'PowerShell module integrity'; R = { Get-PowerShellAlerts } },
    @{ N = 'Windows file impostors';      R = { Get-ImpostorAlerts } }
)

Write-Host ('  {0,-3}{1,-30}{2,-8}{3}' -f '#', 'CHECK', 'RESULT', 'DETAIL') -ForegroundColor DarkGray
Write-Host ('  ' + ('-' * $script:Width)) -ForegroundColor DarkGray

$results = @()
$totals = @{ PASS = 0; WARN = 0; FAIL = 0 }
$i = 0
foreach ($c in $checks) {
    $i++
    Write-Host ('  {0,-3}{1,-30}' -f $i, $c.N) -NoNewline -ForegroundColor White
    Write-Host 'checking...' -NoNewline -ForegroundColor DarkGray
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $lines = @()
    try { $lines = @(& $c.R) } catch { $lines = @("WARNING: Check could not complete ($($_.Exception.Message))") }
    $sw.Stop()
    $secs = [math]::Round($sw.Elapsed.TotalSeconds)
    $st = Get-Status $lines
    $totals[$st]++
    $results += @{ Name = $c.N; Lines = $lines; Status = $st; Secs = $secs }
    Write-Host ("`r" + (' ' * 60) + "`r") -NoNewline
    Write-Host ('  {0,-3}{1,-30}' -f $i, $c.N) -NoNewline -ForegroundColor White
    Write-Badge $st
    Write-Host ('  ' + (Get-Summary $lines $st)) -NoNewline -ForegroundColor Gray
    Write-Host "  [${secs}s]" -ForegroundColor DarkGray
}
Write-Host ('  ' + ('-' * $script:Width)) -ForegroundColor DarkGray

# ---- findings (capped so the screen never floods)
$cap = 4
$flaggedTotal = 0
$printedHeader = $false
foreach ($r in $results) {
    $flag = @($r.Lines | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' } | Sort-Object { if ($_ -like 'FAILURE*') { 0 } else { 1 } })
    if ($flag.Count -eq 0) { continue }
    $flaggedTotal += $flag.Count
    if (-not $printedHeader) { Write-Host ''; Write-Host '  FINDINGS' -ForegroundColor White; $printedHeader = $true }
    Write-Host ''
    Write-Host "  $($r.Name)" -ForegroundColor Cyan
    foreach ($l in ($flag | Select-Object -First $cap)) {
        $isFail = ($l -like 'FAILURE*')
        $text = Limit-Text ($l -replace '^(FAILURE|WARNING):\s*', '') 104
        Write-Host $(if ($isFail) { '    ! ' } else { '    ~ ' }) -NoNewline -ForegroundColor $(if ($isFail) { 'Red' } else { 'Yellow' })
        Write-Host $text -ForegroundColor $(if ($isFail) { 'Red' } else { 'Yellow' })
    }
    if ($flag.Count -gt $cap) { Write-Host "    ... and $($flag.Count - $cap) more (see saved report)" -ForegroundColor DarkGray }
}

# ---- recent activity
$act = @(($results | Where-Object { $_.Name -eq 'Execution history' }).Lines | Where-Object { $_ -like 'INFO*' } | Select-Object -First 8)
if ($act.Count -gt 0) {
    Write-Host ''
    Write-Host '  RECENT ACTIVITY (programs run since sign-in)' -ForegroundColor White
    foreach ($l in $act) { Write-Host ('    ' + (Limit-Text ($l -replace '^INFO:\s*', '') 104)) -ForegroundColor DarkGray }
}

# ---- verdict
Write-Host ''
$verdict = 'COMPLIANT'; $vbg = 'Green'; $vfg = 'Black'
if ($totals.FAIL -gt 0) { $verdict = 'NON-COMPLIANT'; $vbg = 'Red'; $vfg = 'White' }
elseif ($totals.WARN -gt 0) { $verdict = 'COMPLIANT - REVIEW NOTES'; $vbg = 'Yellow'; $vfg = 'Black' }
Write-Bar ("RESULT: $verdict    ($($totals.PASS) pass / $($totals.WARN) warn / $($totals.FAIL) fail)") $vbg $vfg

# ---- save report
$reportDir = Join-Path $env:ProgramData 'TCAR_ARC'
$reportFile = Join-Path $reportDir "report_$refId.txt"
try {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    $rep = @("TCAR ARC compliance report", "Reference : $refId", "Host      : $env:COMPUTERNAME", "User      : $env:USERNAME", "Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", "Result    : $verdict", '')
    foreach ($r in $results) { $rep += "== $($r.Name) [$($r.Status)] ($($r.Secs)s)"; $rep += $r.Lines | ForEach-Object { "   $_" }; $rep += '' }
    Set-Content -LiteralPath $reportFile -Value $rep -Encoding UTF8
    Write-Host "  Full report saved: $reportFile" -ForegroundColor DarkGray
} catch {}
Wait-Enter 'Press Enter to continue to stage 2'

# ============================================================================ STAGE 2
Write-Header 'Stage 2 of 3  -  Process Explorer'
Write-Host '  Process Explorer will open maximized. Scroll through the full process list' -ForegroundColor Gray
Write-Host '  on the recording, then close it (File > Exit) to continue.' -ForegroundColor Yellow
Write-Host ''

foreach ($pe in @(Get-Process | Where-Object { @('procexp', 'procexp64', 'procexp64a') -contains $_.ProcessName.ToLower() })) {
    try { Stop-Process -Id $pe.Id -Force -ErrorAction Stop; Write-Host "  Closed an existing Process Explorer instance (PID $($pe.Id))" -ForegroundColor DarkGray } catch {}
}

function Get-ProcExpFile {
    param([string]$Work)
    $ProgressPreference = 'SilentlyContinue'
    $script:PeErrors = @()
    # allow TLS 1.2 and 1.3 (a TLS 1.2-only setting is a common cause of "connection closed" errors)
    try { [Net.ServicePointManager]::SecurityProtocol = ([Net.SecurityProtocolType]3072 -bor [Net.SecurityProtocolType]12288) }
    catch { try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]3072 } catch {} }
    New-Item -ItemType Directory -Path $Work -Force | Out-Null
    $zipUrl = 'https://download.sysinternals.com/files/ProcessExplorer.zip'
    $zip = Join-Path $Work 'pe.zip'
    $out = Join-Path $Work 'x'
    $methods = @(
        { Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing -ErrorAction Stop },
        { (New-Object Net.WebClient).DownloadFile($zipUrl, $zip) },
        { Start-BitsTransfer -Source $zipUrl -Destination $zip -ErrorAction Stop }
    )
    foreach ($m in $methods) {
        try {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            & $m
            if (Test-Path -LiteralPath $zip) {
                Expand-Archive -Path $zip -DestinationPath $out -Force -ErrorAction Stop
                $e = Get-ChildItem -Path $out -Filter 'procexp64.exe' -Recurse | Select-Object -First 1
                if ($e) { return $e.FullName }
            }
        } catch { $script:PeErrors += $_.Exception.Message }
    }
    # fallback: single signed exe from the Sysinternals live share
    try {
        $exe = Join-Path $Work 'procexp64.exe'
        Invoke-WebRequest -Uri 'https://live.sysinternals.com/procexp64.exe' -OutFile $exe -UseBasicParsing -ErrorAction Stop
        if (Test-Path -LiteralPath $exe) { return $exe }
    } catch { $script:PeErrors += $_.Exception.Message }
    # fallback: a copy already on this PC (still signature-checked by the caller)
    $cmd = Get-Command 'procexp64.exe' -ErrorAction SilentlyContinue
    $cands = @($(if ($cmd) { $cmd.Source }), "$env:ProgramFiles\ProcessExplorer\procexp64.exe", "$env:ProgramFiles\Sysinternals\procexp64.exe", "$env:SystemDrive\Sysinternals\procexp64.exe", "$env:USERPROFILE\Downloads\procexp64.exe", "$env:USERPROFILE\Downloads\ProcessExplorer\procexp64.exe")
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

$peOk = $false
while ($true) {
    $work = Join-Path $env:TEMP ('TCAR_ARC_' + [guid]::NewGuid().ToString('N'))
    try {
        Write-Host '  Getting Process Explorer from Sysinternals...' -ForegroundColor Gray
        $exePath = Get-ProcExpFile -Work $work
        if (-not $exePath) { throw ('Could not download Process Explorer. ' + (@($script:PeErrors | Select-Object -Last 1) -join '')) }
        $sig = Get-AuthenticodeSignature -LiteralPath $exePath
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Process Explorer is not validly signed by Microsoft - not launched' }
        Write-Host '  Publisher signature verified (Microsoft).' -ForegroundColor Green
        Write-Host '  Launching...' -ForegroundColor Gray
        $proc = Start-Process -FilePath $exePath -ArgumentList '/accepteula' -WindowStyle Maximized -PassThru
        $proc.WaitForExit()
        $peOk = $true
    } catch {
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($peOk) { break }
    Write-Host '  Check your internet connection. A VPN, proxy, firewall or antivirus can block sysinternals.com.' -ForegroundColor Yellow
    $ans = Read-Host '  Type R to retry, or press Enter to continue without it'
    if ($ans -notmatch '^(?i)r') { break }
}
Write-Host ''
Write-Badge $(if ($peOk) { 'PASS' } else { 'FAIL' })
Write-Host $(if ($peOk) { '  Stage 2 completed' } else { '  Stage 2 did not complete' }) -ForegroundColor Gray
Wait-Enter 'Press Enter to start the session monitor'

# ============================================================================ STAGE 3
# Live session dashboard. Fixed panel that redraws in place (no scrolling log).
# End the session with Q or Esc (works on 60% keyboards), then confirm with Y.
Write-Header 'Stage 3 of 3  -  Live session'
Write-Host '  The live panel starts next. Once it shows "waiting for Roblox", START ROBLOX and join the match.' -ForegroundColor Yellow
Write-Host '  Leave this window open until the match has finished,' -ForegroundColor Gray
Write-Host '  then show it again on the recording.' -ForegroundColor Gray
Write-Host '  To finish the session press Q (or Esc), then Y to confirm.' -ForegroundColor White
Write-Host '  A calm panel with the status ALL CLEAR is the expected result.' -ForegroundColor DarkGray
Wait-Enter 'Press Enter to open the live panel'

function Get-ActiveThreatsOnly {
    $o = @()
    try { foreach ($t in @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.Status -eq 'Active' })) { $o += "FAILURE: Active antivirus threat $($t.ThreatName) | $($t.Resources)" } } catch {}
    return $o
}

$logFile = Join-Path $reportDir "session_$refId.log"
$mc = @{ ALERT = 0; NOTICE = 0; INFO = 0 }
$seenAlerts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$feed = New-Object 'System.Collections.Generic.List[object]'
$feedRows = 10
$script:Top = 0
$script:Col = 0
$PW = $script:Width + 2
$dot = [string][char]0x25CF
$blkOn = [string][char]0x2588
$blkOff = [string][char]0x2591

function Write-MonitorEvent {
    param([string]$Line, [switch]$AlwaysShow)
    $lvl = 'INFO'; $text = $Line
    if ($Line -match '(?s)^(SUCCESS|FAILURE|WARNING|INFO):\s*(.*)$') {
        $text = $matches[2]
        $lvl = switch ($matches[1]) { 'FAILURE' { 'ALERT' } 'WARNING' { 'NOTICE' } default { 'INFO' } }
    }
    $key = "$lvl|" + ($text -replace '\bPID \d+', 'PID' -replace '\s+', ' ')
    if (-not $AlwaysShow -and -not $seenAlerts.Add($key)) { return }
    $mc[$lvl]++
    $feed.Add(@{ T = (Get-Date -Format 'HH:mm:ss'); L = $lvl; X = $text })
    while ($feed.Count -gt $feedRows) { $feed.RemoveAt(0) }
    try { Add-Content -LiteralPath $logFile -Value ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $text) -ErrorAction Stop } catch {}
}

function Set-Row { param([int]$N); [Console]::SetCursorPosition(0, $script:Top + $N); $script:Col = 0 }
function Put {
    param([string]$T, [string]$Fg = 'Gray', [string]$Bg = '')
    if ($Bg) { Write-Host $T -NoNewline -ForegroundColor $Fg -BackgroundColor $Bg } else { Write-Host $T -NoNewline -ForegroundColor $Fg }
    $script:Col += $T.Length
}
function Close-Row { if ($script:Col -lt $PW) { Write-Host (' ' * ($PW - $script:Col)) -NoNewline } }

function Show-Panel {
    param([datetime]$Since, [int]$ClientPid, [int]$Tick, [string]$Footer = '')
    $el = (Get-Date) - $Since
    if ($mc.ALERT -gt 0) { $ac = 'Red'; $afg = 'White'; $lab = ' ALERTS RAISED ' }
    elseif ($mc.NOTICE -gt 0) { $ac = 'Yellow'; $afg = 'Black'; $lab = '  NEEDS REVIEW  ' }
    else { $ac = 'Green'; $afg = 'Black'; $lab = '   ALL CLEAR    ' }

    # header strip
    Set-Row 1
    Put (' LIVE SESSION   ' + $refId).PadRight($PW - $lab.Length) 'White' 'DarkBlue'
    Put $lab $afg $ac
    Set-Row 2; Close-Row

    # stats
    Set-Row 3
    Put '  Uptime   ' 'DarkGray'; Put ('{0:hh\:mm\:ss}' -f $el) 'White'
    Put '      Client   ' 'DarkGray'
    if ($ClientPid -gt 0) { Put $dot 'Green'; Put " running (PID $ClientPid)" 'White' } else { Put $dot 'DarkGray'; Put ' waiting for Roblox' 'Gray' }
    Close-Row
    Set-Row 4
    Put '  Alerts   ' 'DarkGray'; Put ([string]$mc.ALERT).PadRight(6) $(if ($mc.ALERT -gt 0) { 'Red' } else { 'White' })
    Put '  Notices  ' 'DarkGray'; Put ([string]$mc.NOTICE).PadRight(6) $(if ($mc.NOTICE -gt 0) { 'Yellow' } else { 'White' })
    Put '  Events   ' 'DarkGray'; Put ([string]($mc.ALERT + $mc.NOTICE + $mc.INFO)) 'White'
    Close-Row

    # sweep progress (deep sweep every 10 s = 20 ticks)
    $pos = $Tick % 20
    $filled = [int]($pos * 20 / 20)
    Set-Row 5
    Put '  Sweep    ' 'DarkGray'
    Put ($blkOn * $filled) $ac
    Put ($blkOff * (20 - $filled)) 'DarkGray'
    Put ('  next deep scan in {0}s' -f [math]::Ceiling((20 - $pos) / 2)) 'DarkGray'
    Close-Row
    Set-Row 6; Close-Row

    # activity feed
    Set-Row 7
    Put (' RECENT ACTIVITY').PadRight($PW) 'White' 'DarkGray'
    for ($i = 0; $i -lt $feedRows; $i++) {
        Set-Row (8 + $i)
        $idx = $i - ($feedRows - $feed.Count)
        if ($idx -ge 0) {
            $e = $feed[$idx]
            Put ('  ' + $e.T + '  ') 'DarkGray'
            switch ($e.L) {
                'ALERT'  { Put '[!] ' 'Red';    Put (Limit-Text $e.X 62) 'Red' }
                'NOTICE' { Put '[?] ' 'Yellow'; Put (Limit-Text $e.X 62) 'Yellow' }
                default  { Put '[i] ' 'DarkGray'; Put (Limit-Text $e.X 62) 'Gray' }
            }
        }
        Close-Row
    }
    Set-Row (8 + $feedRows); Close-Row
    Set-Row (9 + $feedRows)
    if ($Footer) { Put ('  ' + $Footer) 'Yellow' } else { Put '  [Q] finish session' 'DarkGray' }
    Close-Row
}

# ---- initialise
$knownMods = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($rp in @(Get-Process -Name RobloxPlayerBeta)) { try { foreach ($m in $rp.Modules) { [void]$knownMods.Add([string]$m.FileName) } } catch {} }
$knownPids = @{}
foreach ($cp in @(Get-CimInstance Win32_Process)) { $knownPids[[int]$cp.ProcessId] = $true }
$prevExcl = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in (Get-ExclusionList)) { [void]$prevExcl.Add($e) }
$knownObsMods = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($op in @(Get-Process -Name obs64, obs32)) { try { foreach ($m in $op.Modules) { [void]$knownObsMods.Add([string]$m.FileName) } } catch {} }
$knownPsMods = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($pp in @(Get-Process -Name powershell, pwsh, powershell_ise)) { try { foreach ($m in $pp.Modules) { [void]$knownPsMods.Add([string]$m.FileName) } } catch {} }
$obsRoots = @(Get-ObsRoots)
$lastRbxPid = 0
$baseRwx = @{}
$clientSince = $null
$clientVerified = $false
$graceSec = 45
$tick = 0
$monStart = Get-Date
$done = $false
$confirming = $false
$oldCtrlC = $false
try { $oldCtrlC = [Console]::TreatControlCAsInput; [Console]::TreatControlCAsInput = $true } catch {}
try { [Console]::CursorVisible = $false } catch {}

Clear-Host
$script:Top = [Console]::CursorTop
Write-MonitorEvent -Line "INFO: Session started ($refId) - stage 1 result: $verdict" -AlwaysShow

try {
    while (-not $done) {
        Start-Sleep -Milliseconds 500
        $tick++

        # ---- keys: Q / Esc = finish (with confirmation); Ctrl+C is ignored
        try {
            while ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                if ($confirming) {
                    if ($k.Key -eq 'Y') { $done = $true } else { $confirming = $false }
                } elseif ($k.Key -eq 'Q' -or $k.Key -eq 'Escape') { $confirming = $true }
            }
        } catch {}
        if ($done) { break }

        # ---- modules newly loaded into the client (every ~2 s)
        if ($tick % 4 -eq 0) {
            $rbx = @(Get-Process -Name RobloxPlayerBeta)
            foreach ($rp in $rbx) {
                if ($rp.Id -ne $lastRbxPid) {
                    $lastRbxPid = $rp.Id
                    $clientSince = Get-Date
                    $clientVerified = $false
                    $baseRwx.Remove($rp.Id)
                    Write-MonitorEvent -Line "INFO: Roblox client detected (PID $($rp.Id)) - startup checks running" -AlwaysShow
                }
                try {
                    foreach ($m in $rp.Modules) {
                        $file = [string]$m.FileName
                        if (-not $file -or -not $knownMods.Add($file)) { continue }
                        if ($file.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { continue }
                        $r = Test-LoadedModule -File $file
                        if ($r) { Write-MonitorEvent -Line ($r -replace '^(FAILURE|WARNING): ', '$1: New module - ') -AlwaysShow }
                        elseif ($clientSince -and ((Get-Date) - $clientSince).TotalSeconds -gt $graceSec) { Write-MonitorEvent -Line "INFO: New signed module loaded in client -> $file" -AlwaysShow }
                    }
                } catch {}
            }
            if ($rbx.Count -eq 0) { $lastRbxPid = 0; $clientSince = $null; $clientVerified = $false }

            # ---- once startup settles, run the full client verification on the live client
            if ($clientSince -and -not $clientVerified -and ((Get-Date) - $clientSince).TotalSeconds -gt $graceSec) {
                $clientVerified = $true
                foreach ($l in @((Get-ClientModuleAlerts) + (Get-ClientMemoryAlerts) + (Get-MemoryReaderAlerts) + (Get-SyscallHookAlerts))) {
                    if ($l -like 'INFO: Roblox not started*') { continue }
                    Write-MonitorEvent -Line $l -AlwaysShow
                }
            }

            # ---- modules newly loaded into OBS and PowerShell
            if ($tick % 8 -eq 0) { $obsRoots = @(Get-ObsRoots) }
            foreach ($op in @(Get-Process -Name obs64, obs32)) {
                try {
                    foreach ($m in $op.Modules) {
                        $file = [string]$m.FileName
                        if (-not $file -or -not $knownObsMods.Add($file)) { continue }
                        if ($file.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { continue }
                        $r = Test-ObsModule -File $file -Roots $obsRoots
                        if ($r) { Write-MonitorEvent -Line ($r -replace '^(FAILURE|WARNING): ', '$1: New module - ') -AlwaysShow }
                    }
                } catch {}
            }
            foreach ($pp in @(Get-Process -Name powershell, pwsh, powershell_ise)) {
                try {
                    foreach ($m in $pp.Modules) {
                        $file = [string]$m.FileName
                        if (-not $file -or -not $knownPsMods.Add($file)) { continue }
                        if ($file -match '(?i)\\assembly\\NativeImages_') { continue }
                        $r = Test-PsModuleFile -File $file -Who $(if ($pp.Id -eq $PID) { 'this PowerShell session' } else { "PowerShell PID $($pp.Id)" })
                        if ($r) { Write-MonitorEvent -Line ($r -replace '^(FAILURE|WARNING): ', '$1: New module - ') -AlwaysShow }
                    }
                } catch {}
            }

            # ---- newly started processes
            foreach ($cp in @(Get-CimInstance Win32_Process)) {
                $id = [int]$cp.ProcessId
                if ($knownPids.ContainsKey($id)) { continue }
                $knownPids[$id] = $true
                $r = Test-ProcessRecord -Name ([string]$cp.Name) -Path ([string]$cp.ExecutablePath)
                if ($r) { Write-MonitorEvent -Line ($r -replace '^(FAILURE|WARNING): ', '$1: New process - ') -AlwaysShow }
                elseif ([string]$cp.Name -imatch '^(notepad|wscript|cscript|mshta|regedit|reg)\.exe$' -or ([string]$cp.Name -ieq 'cmd.exe' -and [string]$cp.CommandLine -match '\.bat\b')) {
                    Write-MonitorEvent -Line "WARNING: Script/editor tool launched -> $($cp.Name) [$($cp.CommandLine)]" -AlwaysShow
                }
            }
        }

        # ---- every ~10 s: external readers, memory regions
        if ($tick % 20 -eq 0) {
            foreach ($l in (Get-MemoryReaderAlerts)) { if ($l -like 'FAILURE*' -or $l -like 'WARNING*') { Write-MonitorEvent -Line $l } }
            foreach ($rp in @(Get-Process -Name RobloxPlayerBeta)) {
                $res = [TCAR.Native]::ScanRwx($rp.Id)
                if ($null -ne $res) {
                    if (-not $baseRwx.ContainsKey($rp.Id) -or ($clientSince -and ((Get-Date) - $clientSince).TotalSeconds -le $graceSec)) { $baseRwx[$rp.Id] = $res[0] }
                    elseif ($res[0] -gt $baseRwx[$rp.Id]) {
                        Write-MonitorEvent -Line "WARNING: New private read/write/execute memory in client PID $($rp.Id) ($($baseRwx[$rp.Id]) -> $($res[0]) regions)" -AlwaysShow
                        $baseRwx[$rp.Id] = $res[0]
                    }
                }
            }
        }

        # ---- every ~20 s: antivirus state, exclusions, log clearing, native API hooks (OBS tree re-verified every ~60 s)
        if ($tick % 40 -eq 0) {
            foreach ($l in (Get-DefenderAlerts)) { if ($l -like 'FAILURE*') { Write-MonitorEvent -Line $l } }
            foreach ($e in (Get-ExclusionList)) { if ($prevExcl.Add($e)) { Write-MonitorEvent -Line "FAILURE: Antivirus exclusion added during the session -> $e" -AlwaysShow } }
            foreach ($flt in @(@{ LogName = 'Security'; Id = 1102 }, @{ LogName = 'System'; Id = 104 })) {
                $flt.StartTime = $monStart
                foreach ($ev in @(Get-WinEvent -FilterHashtable $flt -MaxEvents 3)) { Write-MonitorEvent -Line "FAILURE: '$($flt.LogName)' event log cleared during the session" }
            }
            foreach ($l in (Get-ActiveThreatsOnly)) { Write-MonitorEvent -Line $l }
            foreach ($l in (Get-SyscallHookAlerts)) { if ($l -like 'FAILURE*' -or $l -like 'WARNING*') { Write-MonitorEvent -Line $l } }
            if ($tick % 120 -eq 0 -and @(Get-Process -Name obs64, obs32).Count -gt 0) {
                foreach ($l in (Get-ObsTamperAlerts)) { if ($l -like 'FAILURE*' -or $l -like 'WARNING*') { Write-MonitorEvent -Line $l } }
            }
        }

        $foot = if ($confirming) { 'Finish the session now?   Y = yes     any other key = keep monitoring' } else { '' }
        Show-Panel -Since $monStart -ClientPid $lastRbxPid -Tick $tick -Footer $foot
    }
} finally {
    try { [Console]::TreatControlCAsInput = $oldCtrlC } catch {}
    try { [Console]::CursorVisible = $true } catch {}
    $el = (Get-Date) - $monStart
    Write-MonitorEvent -Line ("INFO: Session ended after {0:hh\:mm\:ss} - {1} alert(s), {2} notice(s)" -f $el, $mc.ALERT, $mc.NOTICE) -AlwaysShow
    Show-Panel -Since $monStart -ClientPid $lastRbxPid -Tick 0 -Footer 'Session finished'
    Set-Row (11 + $feedRows)
    Write-Host "  Session log saved: $logFile" -ForegroundColor DarkGray
    Write-Host ''
}
