package signedmanifest

import (
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "errors"
    "io"
)

// LedgerOutcome is the result of ONE atomic, durable ledger write.
// The ledger, not this package, must enforce uniqueness under concurrency
// and across process restarts. Zero and unrecognized values are errors.
type LedgerOutcome uint8

const (
    LedgerInserted LedgerOutcome = iota + 1
    LedgerDuplicate
    LedgerConflict
)

var (
    ErrNilContext = errors.New("signedmanifest: nil context")
    ErrNilLedger = errors.New("signedmanifest: no replay ledger")
    ErrReplay = errors.New("signedmanifest: capture replay")
    ErrCaptureConflict = errors.New("signedmanifest: capture ID reused with changed manifest")
    ErrInvalidLedgerOutcome = errors.New("signedmanifest: invalid ledger outcome")
)

// ReplayLedger must be implemented with a separately protected, persistent,
// atomic insert-if-absent operation keyed on CaptureID. The value is the
// SHA-256 fingerprint of the fully verified canonical signed manifest bytes.
// A repeated ID with the same fingerprint is LedgerDuplicate; a different
// fingerprint is LedgerConflict. LedgerInserted MUST mean the write has been
// committed durably before it returns. All storage errors MUST fail closed.
// No ledger implementation or signing key is provided here.
type ReplayLedger interface {
    RecordOnce(ctx context.Context, captureID string, fingerprint [sha256.Size]byte) (LedgerOutcome, error)
}

// VerifyAndRecord first checks the signature, independently pinned capture
// context, and actual stream hash/length; only then requests a durable atomic
// registration. It never considers replay or ledger errors accepted. A mismatch
// is (false, bytesRead, nil); any I/O failure is an error.
//
// A successful result does NOT establish that the key was controlled by the
// claimed collector, that a timestamp is trustworthy, that the input originated
// from the claimed device, or that an external ledger really is durable.
// Cancellation is checked before stream reading and before ledger commit;
// it does not interrupt a blocked io.Reader. Never reuse this as proof of
// forensic provenance or a replacement for custody logging and WORM storage.
func VerifyAndRecord(ctx context.Context, r io.Reader, raw []byte, expected Expected, trustedKey ed25519.PublicKey, ledger ReplayLedger) (bool, int64, error) {
    if ctx == nil {
        return false, 0, ErrNilContext
    }
    if ledger == nil {
        return false, 0, ErrNilLedger
    }
    if err := ctx.Err(); err != nil {
        return false, 0, err
    }
    verified, n, err := VerifyStream(r, raw, expected, trustedKey)
    if err != nil || !verified {
        return false, n, err
    }
    if err := ctx.Err(); err != nil {
        return false, n, err
    }
    result, err := ledger.RecordOnce(ctx, expected.CaptureID, sha256.Sum256(raw))
    if err != nil {
        return false, n, err
    }
    switch result {
    case LedgerInserted:
        return true, n, nil
    case LedgerDuplicate:
        return false, n, ErrReplay
    case LedgerConflict:
        return false, n, ErrCaptureConflict
    default:
        return false, n, ErrInvalidLedgerOutcome
    }
}
