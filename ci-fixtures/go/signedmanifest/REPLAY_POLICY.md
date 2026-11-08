# Synthetic replay-ledger contract (not a production replay database)

This **new, independent public test code** adds a narrow call boundary:
`VerifyAndRecord` checks a canonical Ed25519-signed synthetic manifest,
caller-supplied pinned context/public key and matching byte stream BEFORE
requesting an atomic replay-ledger insertion. Same capture ID with identical
signed bytes is `ErrReplay`; same ID with a different signed manifest is
`ErrCaptureConflict`; a storage error or unknown ledger outcome always fails.

The library does not implement durable storage, key registration, timestamp
services, Windows file access, original evidence acquisition or device trust.
An application implementing `ReplayLedger` must independently enforce atomic,
durable capture-ID uniqueness **across workers, processes, restarts and
backup/restore**. A transient commit acknowledgement failure needs manual
reconciliation; never automatically treat a retry as newly accepted. The
memory-backed test double is **not persistent**. Keys and capture IDs are
supplied independently, never accepted on faith from the manifest.

Recommended pre-deployment requirements (not implemented):
1. Trust anchor and key custody: independent public-key enrollment, role
   separation, key rotation, compromise response and historical verification.
2. Durable ledger: atomic transaction with verified backups, independent
   monitor, failure alert, recovery and cross-replica consistency.
3. Time: authoritative external time evidence if an actual historical time
   assertion is required. The string inside a signed manifest is a claim.
4. Immutable custody: protect original bytes with independently configured
   retention/WORM where feasible, verify object lock in the chosen storage,
   log extraction time/UTC source/tool/custodian and avoid editing originals.
5. No software alone establishes the PC's original capture trust or absence
   of sophisticated malware. Run owner-approved threat modeling before use.

References: NIST SP 800-57 Pt. 1 Rev. 5 key management;
RFC 3161 Time-Stamp Protocol; Microsoft Azure Blob immutable WORM overview.
