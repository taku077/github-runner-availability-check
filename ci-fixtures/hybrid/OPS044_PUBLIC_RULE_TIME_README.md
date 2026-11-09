# OPS-044 — public rule provenance and native XML timestamp receipt

Scope: use ONLY the pinned PUBLIC Hayabusa v4.3.1 release, the public test EVTX
at the pinned commit, and disposable GitHub-hosted Ubuntu/Windows runners.
Do not use an investigated user's PC, evidence, device identifiers or settings.

This test deliberately keeps **two separate assertions**:

1. On Ubuntu, the Hayabusa alert `RuleID` and `RuleFile` are compared against
   the *actual extracted release rule file* and its SHA-256. The complete
   extracted `.yml` inventory is also summarized with a deterministic SHA-256.
   Matching a rule's UUID and bytes **does not validate its detection logic**.
2. On Windows Server 2022, a fresh independently SHA-verified sample EVTX is
   read with Microsoft `Get-WinEvent -Path`; its original XML `SystemTime`
   timestamps (including fractional seconds) are preserved separately from
   the Hayabusa timeline timestamps. Disagreement is never rewritten to match.

Outputs: GitHub-hosted public CI logs, a short-lived sanitized reference
artifact (public event IDs/record IDs/channel/timestamps plus public rule hashes),
and a Windows-only native XML timestamp receipt for this PUBLIC test fixture.

Fail closed on input/release SHA mismatch, missing/ambiguous/mismatched RuleID
or RuleFile, source ID mismatch or unexpected timestamp shifts. The previous
PCFM-OPS-043 result was only 9/9 record matches at **whole-second** time
granularity; it was NOT subsecond timestamp equivalence. If this trial
uncovers additional differences, classify them rather than ignoring them.

Official documentation:
- https://yamato-security.github.io/hayabusa/output/
- https://yamato-security.github.io/hayabusa/rules/creating-rules/
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent

This public repo does not publish the private PCFM project or any user's
original evidence. This test does not authorize EVTX export, ACL changes,
software installation, permanent monitoring, or PCFM production deployment.


## OPS044 precision correction (independent archive review)

The byte-preserved public GitHub Actions artifact contains a Hayabusa-reported
`timestamp_utc` such as `2021-04-29T09:23:54.244226+00:00`.
The independently parsed Windows EVTX XML has
`2021-04-29T09:23:54.2442261Z` for the same RecordID, a one-100ns-tick
difference. The previous Windows comparator had read the JSON with default
PowerShell `ConvertFrom-Json`, which converts ISO8601 strings to DateTime.
Casting that DateTime back to `[string]` can discard the fractional portion,
causing the *false* historical "second-only" classification.

The comparator now requires PowerShell 7.5+ `-DateKind String` to retain the
original JSON strings. With the public source index expressing microseconds
(6 digits) and source XML expressing 100-nanosecond ticks (7 digits), accept
a match only within **9 ticks (0.9 microseconds)**, with no claim of exact
100ns equivalence. Reject unrelated time changes. This fixes a test-harness
provenance error, not a demonstrated flaw in Hayabusa's timestamp output.
