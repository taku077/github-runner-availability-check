// Package integrity offers standalone, stream-only SHA-256 checks for synthetic
// data. It does not open files, modify data, or establish evidence provenance.
package integrity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrNilReader signals an absent byte stream.
	ErrNilReader = errors.New("integrity: nil reader")
	// ErrExpectedDigest signals an invalid canonical SHA-256 hex string.
	ErrExpectedDigest = errors.New("integrity: expected 64 lowercase hexadecimal characters")
)

// Digest consumes r until EOF and returns the lowercase SHA-256 checksum and
// number of bytes read. On an I/O error the checksum is empty and err is set;
// the byte count is diagnostic only, not an accepted or verified result.
func Digest(r io.Reader) (hexDigest string, bytesRead int64, err error) {
	h, bytesRead, err := digest(r)
	if err != nil {
		return "", bytesRead, err
	}
	return hex.EncodeToString(h[:]), bytesRead, nil
}

// Verify consumes r and checks it against a canonical lowercase SHA-256 hex
// digest. It rejects malformed expected values before reading and never
// reports success on partial reads. A mismatch is (false, bytesRead, nil).
func Verify(r io.Reader, expectedHex string) (match bool, bytesRead int64, err error) {
	if len(expectedHex) != sha256.Size*2 {
		return false, 0, ErrExpectedDigest
	}
	for i := 0; i < len(expectedHex); i++ {
		c := expectedHex[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false, 0, ErrExpectedDigest
		}
	}
	want, decodeErr := hex.DecodeString(expectedHex)
	if decodeErr != nil { // Defensive; the preceding validation should exclude it.
		return false, 0, ErrExpectedDigest
	}
	got, count, readErr := digest(r)
	if readErr != nil {
		return false, count, readErr
	}
	return subtle.ConstantTimeCompare(got[:], want) == 1, count, nil
}

func digest(r io.Reader) (sum [sha256.Size]byte, bytesRead int64, err error) {
	if r == nil {
		return sum, 0, ErrNilReader
	}
	h := sha256.New()
	bytesRead, err = io.Copy(h, r)
	if err != nil {
		return sum, bytesRead, fmt.Errorf("integrity: reading stream: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, bytesRead, nil
}
