# OPS057: public disposable Windows Server API control, NOT a private PCFM test.
# Never execute on the investigated PC. No SID, ACL, FileId, host or path is emitted.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Linq;
using System.Runtime.InteropServices;
public static class Ops057SecurityProbe {
    const uint READ_ATTRIBUTES = 0x80, READ_CONTROL = 0x00020000;
    const uint SHARE_ALL = 7, OPEN_EXISTING = 3;
    const uint BACKUP_SEMANTICS = 0x02000000, OPEN_REPARSE_POINT = 0x00200000;
    const uint OWNER_INFO = 1, GROUP_INFO = 2, DACL_INFO = 4;
    const uint FILE_PERSISTENT_ACLS = 8;
    const ushort SE_DACL_PRESENT = 0x0004;
    static readonly IntPtr Invalid = new IntPtr(-1);

    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string name, uint access, uint share,
       IntPtr security, uint disposition, uint flags, IntPtr templateHandle);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(IntPtr handle, int infoClass, [Out] byte[] info, uint length);
    [DllImport("kernel32.dll", EntryPoint="GetVolumeInformationByHandleW", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformationByHandle(IntPtr handle, StringBuilder volumeName, uint volumeLength,
       out uint serial, out uint componentLength, out uint flags, StringBuilder fileSystem, uint fsLength);
    [DllImport("advapi32.dll", ExactSpelling=true)]
    static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint securityInfo,
       out IntPtr owner, out IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetSecurityDescriptorControl(IntPtr descriptor, out ushort control, out uint revision);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);

    static IntPtr Open(string name, uint access) {
        IntPtr h = CreateFile(name, access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                   BACKUP_SEMANTICS | OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Invalid) throw new InvalidOperationException("CreateFileW failed " + Marshal.GetLastWin32Error());
        return h;
    }
    static byte[] Identity(IntPtr h) {
        // FILE_ID_INFO = ULONGLONG volume serial + 16 byte FileId.
        byte[] bytes = new byte[24];
        if (!GetFileInformationByHandleEx(h, 18, bytes, (uint)bytes.Length))
            throw new InvalidOperationException("GetFileInformationByHandleEx(FileIdInfo) failed " + Marshal.GetLastWin32Error());
        if (!bytes.Skip(8).Any(x => x != 0))
            throw new InvalidOperationException("Zero 128-bit FileId");
        return bytes;
    }
    static string FileSystem(IntPtr h) {
        var name = new StringBuilder(128);
        var fs = new StringBuilder(128);
        uint serial, component, flags;
        if (!GetVolumeInformationByHandle(h, name, (uint)name.Capacity,
             out serial, out component, out flags, fs, (uint)fs.Capacity))
            throw new InvalidOperationException("GetVolumeInformationByHandleW failed " + Marshal.GetLastWin32Error());
        if ((flags & FILE_PERSISTENT_ACLS) == 0)
            throw new InvalidOperationException("Persistent ACL capability unavailable");
        string value = fs.ToString().ToUpperInvariant();
        if (value != "NTFS" && value != "REFS")
            throw new InvalidOperationException("Unsupported FS");
        return value;
    }
    static byte[] BoundRead(IntPtr h, out string fs, out bool groupPresent) {
        byte[] before = Identity(h);
        fs = FileSystem(h);
        IntPtr owner=IntPtr.Zero, group=IntPtr.Zero, dacl=IntPtr.Zero, sd=IntPtr.Zero;
        try {
            uint status = GetSecurityInfo(h, 1, OWNER_INFO|GROUP_INFO|DACL_INFO,
                                          out owner,out group,out dacl,IntPtr.Zero,out sd);
            if (status != 0) throw new InvalidOperationException("GetSecurityInfo code " + status);
            if (sd == IntPtr.Zero || owner == IntPtr.Zero || dacl == IntPtr.Zero)
                throw new InvalidOperationException("Missing security descriptor, owner, or non-NULL DACL");
            ushort control;
            uint revision;
            if (!GetSecurityDescriptorControl(sd, out control, out revision))
                throw new InvalidOperationException("GetSecurityDescriptorControl failed " + Marshal.GetLastWin32Error());
            if ((control & SE_DACL_PRESENT) == 0)
                throw new InvalidOperationException("Security descriptor lacks DACL_PRESENT");
            groupPresent = (group != IntPtr.Zero);
        } finally {
            if (sd != IntPtr.Zero) {
                IntPtr returned = LocalFree(sd);
                if (returned != IntPtr.Zero) throw new InvalidOperationException("LocalFree failed");
            }
        }
        byte[] after = Identity(h);
        if (!before.SequenceEqual(after))
            throw new InvalidOperationException("FileId changed around GetSecurityInfo on same handle");
        return before;
    }
    public static string Probe(string path) {
        IntPtr a=Invalid, b=Invalid;
        try {
            a = Open(path, READ_ATTRIBUTES | READ_CONTROL);
            b = Open(path, READ_ATTRIBUTES | READ_CONTROL);
            string fs1,fs2;
            bool group1,group2;
            byte[] id1 = BoundRead(a, out fs1, out group1);
            byte[] id2 = BoundRead(b, out fs2, out group2);
            if (!id1.SequenceEqual(id2) || fs1 != fs2 || group1 != group2)
                throw new InvalidOperationException("Two-handle snapshots inconsistent");
            // Group existence is a presence observation, NOT a security decision.
            return fs1 + "|" + (group1 ? "PRESENT" : "ABSENT");
        } finally {
            if (b != Invalid) CloseHandle(b);
            if (a != Invalid) CloseHandle(a);
        }
    }
}
'@

$folder=Join-Path $env:RUNNER_TEMP ('ops057-' + [guid]::NewGuid().ToString('N'))
$output=Join-Path $env:RUNNER_TEMP 'ops057-public-metadata'
try {
    [void](New-Item -ItemType Directory -Path $folder -ErrorAction Stop)
    $observed=[Ops057SecurityProbe]::Probe($folder)
    $parts=$observed.Split('|')
    if($parts.Count -ne 2){throw 'Invalid internal status'}
    [void](New-Item -ItemType Directory -Path $output -Force -ErrorAction Stop)
    $receipt=[ordered]@{
        schema = 'pcfm-ops057-public-native-v1'
        classification = 'PUBLIC_DISPOSABLE_WINDOWS_SERVER_NOT_PC_EVIDENCE'
        os_version = [System.Environment]::OSVersion.Version.ToString()
        filesystem = $parts[0]
        fileid128_before_after_both_handles = 'OBSERVED_MATCH'
        getsecurityinfo_owner_group_dacl_same_held_handles = 'OBSERVED'
        owner_present = $true
        group_present = ($parts[1] -eq 'PRESENT')
        dacl_present_and_nonnull = $true
        read_control_requested = $true
        sharing = 'FILE_SHARE_READ_WRITE_DELETE'
        raw_ids_sids_dacls_serials_exported = $false
        effective_rights = 'NOT_EVALUATED'
        sacl_mic = 'NOT_REQUESTED'
        ancestor_chain = 'NOT_CHECKED'
        atomic_sd_snapshot = 'NOT_PROVEN'
        target_file_absence = 'NOT_CHECKED'
        windows10_pro_native = 'NOT_RUN'
        private_pcfm_executed = $false
        evtx_export_performed = $false
        investigated_pc_touched = $false
        production_deployment_gate = 'BLOCKED'
    }
    $receipt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $output 'receipt.json') -Encoding utf8
    Write-Host ('OPS057_NATIVE_OBSERVED fs='+$parts[0]+' fileid=BOUND_MATCH owner=YES dacl=NON_NULL group='+$parts[1]+' Windows10=NOT_RUN')
} finally {
    if(Test-Path -LiteralPath $folder){
        Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction Stop
    }
}
