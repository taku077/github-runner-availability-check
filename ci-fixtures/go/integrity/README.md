# Synthetic reader-integrity validation (new public code)

This directory contains newly authored, standard-library-only code to hash an
`io.Reader` and check a canonical SHA-256 digest. The input is caller-owned and
never opened, modified, stored, logged, or transferred by this package.

The interface is intentionally **reader-only** rather than accepting paths,
opening files, or walking directories. `Verify` rejects malformed hashes before
reading and reports stream errors separately from mismatches. Failure to read
the full stream never gives a verified result.

This is a **generic development test fixture**, not a forensic acquisition tool
and not an adaptation or publication of code from the private PCFM repository.
The checksum only establishes equality of two byte sequences supplied to the
library: it cannot authenticate a hash recorded by an adversary, determine file
origin, eliminate TOCTOU races, or establish a chain of custody. Never use this
public fixture to process private evidence or secrets.

The existing `.github/workflows/public-go-fixture.yml` automatically tests
this directory on public Windows and Ubuntu runners after relevant main pushes.
No external Go dependencies are used.
