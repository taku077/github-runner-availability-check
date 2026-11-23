# PCFM-OPS160 — native offline EVTX copy verification on disposable Windows CI

Date: 2026-11-23 JST. This is a **public synthetic fixture**, not the investigated PC or PCFM production service. All processing is confined to GitHub-hosted Windows Server 2022/2025 runners; no real incident data, credentials or private PCFM source are copied into the public repo.

## What is tested

OPS047 writes exactly two deliberately benign Application events, exports a filtered native EVTX using Microsoft's `wevtutil epl`, compares its contents using `Get-WinEvent`, and creates a local SHA256/record-ID receipt. OPS160 separately reopens that *already exported copy* with `System.Diagnostics.Eventing.Reader.EventLogReader` and `PathType.FilePath` and verifies:

1. Existing file restricted to the disposable runner temporary folder, no reparse-file target, at most 1 MiB; declared SHA256/size match.
2. Exactly two records; each claimed record ID is unique and maps to matching provider, event ID and UTC ticks.
3. SHA256 of the original copy remains unchanged before and after reading.
4. Three negative probes fail closed: modified **temporary second copy**, false expected SHA256 and duplicate expected record ID.
5. The CI uploads only a small metadata receipt; unlike the separate OPS047 workflow, this workflow does not upload native EVTX.

The negative probes do not write to the original EVTX or the event log. The existing OPS047 producer intentionally writes two synthetic Application events **only on the disposable CI runner**, not on the Windows PC under investigation. The workflow uses pull_request, repository contents:read, SHA-pinned external actions and checkout without retained credentials. It never calls the paused private CI.

## Evidence limits and next admission gates

The EVTX export is a filtered copy, **not** the original Windows Event Log service database. Both expected labels and SHA256 are supplied by the same runner and are not independently signed. Cross-API reread does not prove source authenticity or operator independence. No Windows10 Pro native result, Security/Sysmon high privilege test, 24-hour process, event loss/overwrite, bookmark restart, malware detection, TP/FP/FN or independent custody is shown. Github-hosted Windows Server is not the investigated PC and no claims of absence or presence of intrusion arise from this test.

Result must remain Windows CI **NOT_RUN** until exact-HEAD Windows jobs and logs are read back. Production = BLOCKED, PC compromise = UNDETERMINED, independent enforcement = NOT_ACCEPTED. Owner consent and forensic acquisition assessment are separate requirements before any real PC contact.

Sources:
- Microsoft EventLogReader: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader
- Microsoft EvtExportLog: https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtexportlog
- Microsoft wevtutil: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
- NIST SP 800-86: https://csrc.nist.gov/pubs/sp/800/86/final
- GitHub Actions least-privilege workflow: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
