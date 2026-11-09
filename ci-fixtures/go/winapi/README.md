# Public Win32 handle/volume API smoke fixture

This small, independently authored test is for the **public** GitHub Actions
`windows-2022` and `windows-2025` runner images. It is not the private PCFM
collector and does not use any private source code or information from a user's
Windows PC, network, event logs, credentials, or evidence.

`TestPublicWindowsFileIdAndFilesystemOnSameHandle` uses a disposable temporary
folder created by Go's `testing.T.TempDir()`. It opens two **read-only**
directory handles, observes `GetFileInformationByHandleEx(FileIdInfo=18)` and
`GetVolumeInformationByHandleW` through the *same* handle, and checks that the
128-bit IDs, volume identities, filesystem name and persistent-ACL capability
are stable across the observations. It releases both handles, and never
changes event logs, security settings, services, persistence or registries.
The only output is a synthetic test verdict and a generic filesystem name;
never a real path, volume serial number, file ID or account identifier.

Expected CI: Go 1.27 on Windows Server 2022 / 2025, with an Ubuntu job for
portable tests. The Windows-only test is intentionally absent on Ubuntu.
Passing proves a narrow **Windows Server runner API observation only**; it
neither exercises Windows 10 Pro nor establishes PCFM ACL authorization,
parent-directory reparse safety, race resistance, evidence provenance or
permission to execute `EvtExportLog`. A failure requires investigation rather
than an inference about spyware or interference with a real PC.

Official specifications:
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
