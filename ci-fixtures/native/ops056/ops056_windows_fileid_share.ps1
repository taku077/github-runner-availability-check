# OPS056: public disposable Windows Server native test, NEVER investigated PC.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Linq;
using System.Runtime.InteropServices;
public static class Ops056Native {
    const uint READ_ATTR=0x80, DELETE=0x10000, SHARE_READ=1, SHARE_WRITE=2, SHARE_DELETE=4;
    const uint OPEN_EXISTING=3, BACKUP=0x02000000, REPARSE=0x00200000, PERSISTENT_ACLS=8;
    static readonly IntPtr Invalid = new IntPtr(-1);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr sec,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(IntPtr handle,int info,[Out] byte[] bytes,uint size);
    [DllImport("kernel32.dll",EntryPoint="GetVolumeInformationByHandleW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformationByHandle(IntPtr handle,StringBuilder volume,uint vlen,out uint serial,out uint comp,out uint flags,StringBuilder fs,uint fslen);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);
    static IntPtr Open(string path,uint access,uint share) {
        IntPtr h=CreateFile(path,access,share,IntPtr.Zero,OPEN_EXISTING,BACKUP|REPARSE,IntPtr.Zero);
        if(h==Invalid) throw new InvalidOperationException("CreateFileW win32="+Marshal.GetLastWin32Error());
        return h;
    }
    static byte[] FileId(IntPtr h) {
        byte[] data=new byte[24];
        if(!GetFileInformationByHandleEx(h,18,data,(uint)data.Length))
            throw new InvalidOperationException("FileIdInfo win32="+Marshal.GetLastWin32Error());
        if(!data.Skip(8).Any(b=>b!=0)) throw new InvalidOperationException("Missing 128-bit file ID");
        return data;
    }
    static string Volume(IntPtr h) {
        var name=new StringBuilder(128);var fs=new StringBuilder(128);
        uint sn,comp,flags;
        if(!GetVolumeInformationByHandle(h,name,128,out sn,out comp,out flags,fs,128))
            throw new InvalidOperationException("Volume win32="+Marshal.GetLastWin32Error());
        if((flags&PERSISTENT_ACLS)==0) throw new InvalidOperationException("No persistent ACL flag");
        string result=fs.ToString().ToUpperInvariant();
        if(result!="NTFS" && result!="REFS") throw new InvalidOperationException("Unsupported FS");
        return result;
    }
    static string Snapshot(IntPtr h,out byte[] id) {
        id=FileId(h);string fs=Volume(h);
        if(!id.SequenceEqual(FileId(h))) throw new InvalidOperationException("Same-handle ID changed");
        return fs;
    }
    // No file ID, serial, SID, username, source path, or host identifier returned.
    public static string Test(string path) {
        IntPtr a=Invalid,b=Invalid;
        try {
            a=Open(path,READ_ATTR,SHARE_READ);
            b=Open(path,READ_ATTR,SHARE_READ);
            byte[] aid,bid;
            string fs=Snapshot(a,out aid), other=Snapshot(b,out bid);
            if(fs!=other || !aid.SequenceEqual(bid)) throw new InvalidOperationException("Cross-handle mismatch");
            IntPtr attempted=CreateFile(path,DELETE,SHARE_READ|SHARE_WRITE|SHARE_DELETE,IntPtr.Zero,OPEN_EXISTING,BACKUP|REPARSE,IntPtr.Zero);
            int code=Marshal.GetLastWin32Error();
            if(attempted!=Invalid) {
                CloseHandle(attempted);
                // Attribute-only source HANDLE does not universally block
                // DELETE access. Report, never infer TOCTOU protection.
                return fs+"|DELETE_OPEN_SUCCEEDED_ATTR_ONLY";
            }
            if(code!=32) throw new InvalidOperationException("Unexpected DELETE open error "+code);
            return fs+"|SHARING_VIOLATION_32";
        } finally {
            if(b!=Invalid) CloseHandle(b);
            if(a!=Invalid) CloseHandle(a);
        }
    }
    public static bool MissingRejected(string path) {
        IntPtr h=CreateFile(path,READ_ATTR,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,BACKUP|REPARSE,IntPtr.Zero);
        if(h!=Invalid){CloseHandle(h);return false;}
        int error=Marshal.GetLastWin32Error();
        return error==2 || error==3;
    }
}
'@
$dir = Join-Path $env:RUNNER_TEMP ('ops056-' + [guid]::NewGuid().ToString('N'))
$receiptDir=Join-Path $env:RUNNER_TEMP 'ops056-receipt'
try {
  [void](New-Item -ItemType Directory -Path $dir -ErrorAction Stop)
  $result=[Ops056Native]::Test($dir)
  $fs,$share=$result.Split('|')
  if(-not [Ops056Native]::MissingRejected((Join-Path $dir 'missing-child'))){throw 'missing directory accepted'}
  [void](New-Item -ItemType Directory -Path $receiptDir -Force -ErrorAction Stop)
  $receipt=[ordered]@{
    schema='pcfm-ops056-public-native-v1'
    test='disposable Windows Server 2022/2025'
    native='PASS_NATIVE_SERVER_ONLY'
    os_version=[System.Environment]::OSVersion.Version.ToString()
    filesystem=$fs
    two_handles_fileid128_volume='OBSERVED_UNVERIFIED'
    delete_open=$share
    missing_directory='REJECTED'
    windows10_native='NOT_RUN'
    private_pc_touched=$false
    fileid_or_serial_exported=$false
    acl_effective_rights='NOT_TESTED'
    parent_chain='NOT_TESTED'
    evtx_export_performed=$false
    production_deployment_gate='BLOCKED'
  }
  $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $receiptDir 'receipt.json') -Encoding utf8
  Write-Host ("OPS056_NATIVE_OBSERVED fs="+$fs+" handles=2 delete_access="+$share+" Windows10=NOT_RUN")
} finally {
  if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop}
}
