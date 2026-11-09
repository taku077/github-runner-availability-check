# OPS052 — pinned public OTRF ZIP acquisition and structure-only review

A disposable public GitHub-hosted Ubuntu runner downloads exactly one pinned public OTRF case (SDWIN-220705170038), checks Git blob identity, computes SHA256, verifies bounded ZIP archive paths, CRC, and JSON Lines objects or native EVTX headers. Python unit tests reject malformed archive, tampered source hashes, duplicate JSON keys, spoofed extension-based truth and fake negative interpretation.

Raw ZIP, log lines, hostnames and event contents are never uploaded, published, or copied to the investigated PC. Only a small aggregate field-presence metadata receipt is retained. The ZIP may have lab incident context and third-party copyright; no dataset redistribution is authorized. README's GPL vs LICENSE/docs introduction MIT discrepancy remains unresolved.

A valid ZIP and 100% successful parsing do not supply independent event-level truth. All TP/FP/FN/TN/precision/recall/FPR remain null; production deployment BLOCKED.

Sources: https://docs.github.com/en/rest/repos/contents ; https://docs.github.com/en/rest/git/blobs ; https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-220705170038.html

Initial OPS052 Run 42641907290 verified the downloaded Git blob but failed closed on unexpected JSON serialization. Revised code accepts a JSON array or JSONL and records unknown serialization as INCOMPLETE_NOT_SCORABLE with null event counts; it never fabricates zero events or scores.

Second CI Run 42642672176 verified ZIP SHA256 2ea34cf2d3526e30f9fe004fc4f53f8a04d8e6885e697d77c44102567279ac67 and CRC. One 48,978,066-byte JSONL member parsed, but a 120-byte non-UTF8 .json-named item made the aggregate count null. New guard explicitly recognizes only <=4KB AppleDouble / __MACOSX sidecars; other non-UTF8 JSON continues to block counting.
