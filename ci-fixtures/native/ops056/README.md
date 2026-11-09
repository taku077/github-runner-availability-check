# OPS056 — disposable public native handle / share behavior

Public GitHub-hosted Windows Server 2022/2025 test only; NEVER run on investigated PC. No private PCFM source, EVTX, logs, credentials or host identifiers.

Native API observations use CreateFileW (two simultaneously held, read-attribute-only directory handles), GetFileInformationByHandleEx(FileIdInfo), GetVolumeInformationByHandleW. Compares nonzero 128-bit file IDs and volume info on the same retained handles. An attempted DELETE-access open while attribute-only handles omit FILE_SHARE_DELETE is OBSERVED, not assumed denied: the result is either DELETE_OPEN_SUCCEEDED_ATTR_ONLY or SHARING_VIOLATION_32; any other Win32 result fails closed. Initial native Windows Server 2022/2025 run #42669351666 observed success, disproving the fixture's original unconditional denial expectation. This control does NOT prove generic anti-TOCTOU protection. Missing-directory OPEN_EXISTING must fail. No raw FileIds, serials, paths or usernames are included in output. Test folder is disposed in finally.

Metadata-only receipt, Windows Server results. Windows 10 Pro native=NOT_RUN, effective ACL/parent chain=NOT_TESTED, private monitor and all production deployment gates BLOCKED. No original event logs or OS security settings touched.

Official sources: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew ; https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex ; https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
