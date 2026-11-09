# OPS053: fixed-source nested event identifier inventory

Public-only, disposable GitHub-hosted Ubuntu CI reruns the immutable OTRF `SDWIN-220705170038` ZIP ingestion, verifying SHA256 `2ea34cf2d3526e30f9fe004fc4f53f8a04d8e6885e697d77c44102567279ac67`, original Git Blob SHA1, ZIP CRC, 25,208 JSON events and no native EVTX via the OPS052 inspector.

This extension recursively inventories *only six whitelisted key names* (EventRecordID, RecordID, RecordNumber, SequenceNumber, Computer and Channel) and reports event presence, top-level vs nested, System-ancestor and identifier **type counts**, never actual values. Strings containing serialized XML/JSON are NOT searched. Malformed or oversized nested objects fail closed, and a missing recognized key cannot prove absence from the original Windows event log.

A key resembling RecordID is **not independently authenticated source EventRecordID**. Missing third-party ground truth and denominators mean TP/FP/FN/TN, precision/recall/FPR stay null; deployment remains BLOCKED. The original ZIP is deleted from the runner, aggregate JSON only is uploaded. This is not user-PC evidence.

Microsoft event schema: https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-elements
NIST validation: https://www.nist.gov/publications/validation-forensic-science-guiding-principles-collection-and-use-validation-data
OTRF case: https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-220705170038.html
