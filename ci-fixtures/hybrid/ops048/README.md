# OPS048 — verified EventRecordID linkage, never detection performance inference

Runs only on a disposable public GitHub-hosted Ubuntu runner. Downloads the pinned, *public synthetic only* Windows2022/2025 OPS047 artifacts from Run 42630986537 (2-day retention). Failure or expiry is a hard stop; do not substitute user PC evidence.

Checks both EVTX file SHA256 against independently retained pinned values, native ElfFile header, original OPS047 metadata scope, two explicit EventRecordIDs per OS, and explicitly non-independent controlled-action labels. Uses Hayabusa v4.3.1, SHA256-pinned Linux release, its verbose JSONL output, two threads and a bounded runtime. No native EVTX is modified. No PCFM private source is used.

Matches every JSONL detection to the **known RecordID, EventID=246, correct EVTX basename and valid RuleID UUID**. Unrecognized IDs, paths, duplicate JSON keys or oversized inputs fail closed. Multiple detection rows for one event are retained as counts; they are not collapsed into 'one attack.' Metadata receipt carries source and JSONL SHA256, per-event alert counts and non-sensitive RecordIDs only; raw event XML, hostnames, JSONL and EVTX are not re-uploaded.

**A detection here is a REVIEW candidate, not automatically an FP. No detection is NOT a verified true negative.** These are intentional actions, not an independently labeled representative benign/attack corpus. All TP/FP/FN/TN, precision, recall and FPR remain null. The source EVTX is a filtered native export, not a full event log service database.

This workflow is an expiring one-shot acceptance test of previously preserved OPS047 fixtures. Later reruns are not proof of a regression if the 2-day upstream artifact has expired; primary source copies are held privately in project Drive. Production deployment remains BLOCKED.

Sources: https://yamato-security.github.io/hayabusa/output/ ; https://yamato-security.github.io/hayabusa/commands/dfir-timeline/ ; https://github.com/actions/download-artifact .
