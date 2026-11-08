# Synthetic signed manifest verifier (independent public test code)

This is new, standalone, standard-library-only synthetic code. It does NOT
read Windows event logs, evidence files, host configuration, registry, paths,
network state, credentials, or private project source. The caller must supply
an `io.Reader`, the exact canonical compact JSON manifest, expected capture
and source IDs, expected key ID, and the independently trusted Ed25519 public
key. No private signing key is stored or loaded by the package.

The signature covers a domain-separated, deterministic JSON encoding of
`version`, `capture_id`, `source_label`, `captured_utc`, `byte_count`, `sha256`
and `key_id`. The signature field is separate. The manifest format rejects
unknown or duplicate fields, whitespace, noncanonical JSON, malformed hashes,
non-UTC timestamps, unsafe identifiers, key substitution, and bad signatures
**before reading any content**. Data is streamed exactly once via `io.Reader`;
a digest or length mismatch results in `false`, and a read error is never a
positive result. Validation limits a manifest to 2048 bytes.

## Security limits

- A valid signature authenticates the signed fields **only if** a verifying
  application independently authenticates the public key and safeguards the
  signing private key. The manifest cannot authenticate itself. No key is
  generated, enrolled, discovered or trusted by this package.
- The timestamp is a signed **claim**, not an externally trusted timestamp.
- An authorized signer can still sign fabricated content or backdated data.
- No replay database, monotonic sequence, timestamp authority, device
  attestation, append-only log, secure capture, or chain of custody is provided.
- Matching the stream's digest does not prove the provenance of those bytes.
- The deterministic **test-only** signing key in `manifest_test.go` is public
  and must never be used to sign real evidence.
- All tests use synthetic bytes only; a passing test is not a verdict on any
  private application or the owner's PC.

The existing path-scoped public CI workflow runs these tests on Windows 2022,
Windows 2025, and Ubuntu 24.04. No private repository data is transferred.

References: https://pkg.go.dev/crypto/ed25519 and
https://pkg.go.dev/encoding/json .
