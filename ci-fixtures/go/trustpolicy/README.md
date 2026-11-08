# Synthetic externally pinned key-policy fixture

This independent, newly authored public package validates a **synthetic** Ed25519
public-key policy snapshot before any caller chooses a key for verification.
It is standard-library-only. It does not read files, manage real private keys,
fetch certificates, contact a time authority, or access the owner's PC.

The caller must obtain a trusted `Pin` (generation and full SHA-256 fingerprint)
through a genuinely independent authenticated channel. `Fingerprint(snapshot)`
is deliberately *untrusted* and must never be called on the same untrusted
snapshot to manufacture its own allegedly trusted pin.

`ValidateAndPin` rejects invalid, unsorted, duplicate and substituted key
records, unrecognized states, and mismatched version/generation/fingerprint.
It copies active keys into an internal map; `ResolveActive` returns another
copy. Retired, revoked, unknown or absent keys are rejected. A key rotation
requires a new independently authorized pin. The package does not permit
historical acceptance of a retired key from a self-asserted capture timestamp.

## Not provided / release gate

No real trust-anchor enrollment, hardware-backed key custody, certificate
revocation validation, trusted timestamps, replay ledger implementation,
immutable evidence storage, audit logging, or Windows acquisition is provided.
A matching key fingerprint by itself cannot establish source authenticity.

Use only synthetic test vectors. A consumer must separately verify policy
approval signatures or trusted distribution, independently preserve the latest
accepted generation across restarts/backups, and define revocation response.
A malicious or compromised source could still have a valid signature.

This package is not integrated into the private PCFM software, and its CI
success must not be characterized as proof of PC integrity.

References: NIST SP 800-57 Part 1 Rev. 5 (key management), RFC 3161 (TSA
validation), and Microsoft Azure immutable Blob Storage documentation (WORM).
