# OPS047 — native EVTX preservation of precisely two controlled synthetic events

This is a **public-only disposable-runner** evidence-transport experiment, not PCFM production evidence. It extends OPS046 without rewriting that completed experiment.

- Windows Server 2022 and 2025 generate exactly two intentional Application events using Microsoft `eventcreate`, unique run GUID markers, a dedicated test provider and Event ID 246. Neither creates security events nor changes the investigated PC. 
- `wevtutil epl` filters by provider and ID; `Get-WinEvent` independently reopens the native export and compares event source, ID, record ID, UTC ticks and event XML. It FAILS CLOSED unless the export has **exactly two** events; all unrelated live events are excluded from the exported artifact.
- The export is bounded to 1 MiB, SHA256 is computed before copy; SHA256 of both source and upload copy must match. The upload copy is re-read as EVTX and checked against source events. A JSON receipt records the exported EVTX's digest, size, IDs and explicitly LIMITED benign-action labels.
- The public GitHub artifact contains **raw filtered synthetic EVTX and metadata JSON**, retained for 2 days. The EVTX may contain the **ephemeral CI runner computer name**; therefore never invoke this workflow on user machines or substitute personal logs. Copy the exact artifact into a private Drive folder and check ZIP CRC and original EVTX SHA256 independently before declaring preservation.
- This is a *filtered export*, **not** the event logging service's original database, independently authenticated timestamp or trustworthy third-party label. The upload and digest do not prevent a compromised runner from fabricating a correctly hashed sample. No Hayabusa/PCFM detector is evaluated and TP/FP/FN/TN are unavailable. Actual EVTX bytes may be preserved for offline reanalysis; benign labels apply **only to the two deliberate test actions**.
- No private PCFM code, credentials, incident data, production deployment or additional cloud service introduced. Gates remain BLOCKED.

Sources:
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
https://docs.github.com/en/actions/tutorials/store-and-share-data
https://csrc.nist.gov/pubs/sp/800/86/final
