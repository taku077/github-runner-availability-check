# OPS057 public same-HANDLE read-only security-descriptor observation

This is a disposable **Windows Server 2022/2025** API fixture in a public repository. It does not import, execute or expose private PCFM source, and must not run on the investigated Windows 10 Pro computer.

A new temporary directory (owned by the CI runner) is opened with `FILE_READ_ATTRIBUTES|READ_CONTROL`, `OPEN_EXISTING`, `FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT`, and share flags READ|WRITE|DELETE. Two handles remain open. On each same handle, `GetFileInformationByHandleEx(FileIdInfo)` is called before and after `GetSecurityInfo(OWNER|GROUP|DACL)` and `GetVolumeInformationByHandleW`. Missing owner, NULL DACL, missing DACL_PRESENT, invalid FileId or mismatched identities reject. The allocated security descriptor is released with LocalFree. Only boolean/enum metadata is emitted, never raw ID, ACL, SID, path or volume serial.

A successful call **does not** show effective ACE rights, privilege context, SACL/MIC, ancestor-chain safety, atomic descriptor snapshots, target-file absence or anti-TOCTOU write prevention. Windows 10 Pro = NOT_RUN; product deployment BLOCKED. Windows Server results cannot be silently promoted to Win10 acceptance. No EVTX export/clear or OS policy changes.

Sources:
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo#remarks
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
