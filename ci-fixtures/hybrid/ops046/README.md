# OPS046 — controlled benign evidence pilot
Two deliberately benign eventcreate calls on disposable GitHub Windows Server 2022 and 2025 runners produce unique Application/EventID=246 records. Get-WinEvent compares live EventRecordID, provider and full UTC ticks with the native EVTX exported by wevtutil. No investigated-PC interaction.
Only the two controlled actions receive the bounded benign-action label; other EVTX events remain unknown. This self-generated provenance is not external independent truth adjudication. The test does NOT run Hayabusa/PCFM, calculate TP/FP/FN/TN or claim a normal-machine corpus. Raw EVTX and XML stay in the disposable runner. A metadata-only receipt containing SHA256, IDs and scope is the only uploaded artifact.
Sources: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
Gate: production_deployment=BLOCKED; user PC and private source untouched.
