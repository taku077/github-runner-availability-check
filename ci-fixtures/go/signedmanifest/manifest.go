// Package signedmanifest verifies strictly encoded synthetic capture metadata
// using an out-of-band trusted Ed25519 public key and the actual input bytes.
// No private signing keys, file paths, or evidence are accessed by this package.
package signedmanifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/taku077/github-runner-availability-check/ci-fixtures/go/integrity"
)

const (
	schemaVersion    = 1
	maxManifestBytes = 2048
	domainPrefix     = "public-synthetic-capture-manifest/v1\n"
)

var (
	ErrInvalidManifest  = errors.New("signedmanifest: invalid canonical manifest")
	ErrUntrustedContext = errors.New("signedmanifest: capture context or trusted key mismatch")
	ErrInvalidSignature = errors.New("signedmanifest: invalid Ed25519 signature")
)

// Manifest is a v1 JSON envelope. Its text MUST be the compact encoding/json
// representation in the field order below, without trailing newline or extras.
// CapturedUTC is only a signed assertion: no trusted timestamp is established.
// SourceLabel is a non-sensitive logical label, never an evidence filename/path.
// The Ed25519 public key is NOT embedded: it must be obtained independently.
type Manifest struct {
	Version     int    `json:"version"`
	CaptureID   string `json:"capture_id"`
	SourceLabel string `json:"source_label"`
	CapturedUTC string `json:"captured_utc"`
	ByteCount   int64  `json:"byte_count"`
	SHA256      string `json:"sha256"`
	KeyID       string `json:"key_id"`
	Signature   string `json:"signature"` // base64.RawStdEncoding, exactly 64 decoded bytes
}

// Expected binds the signed manifest to an independently selected capture,
// logical source and trusted key ID. It is NOT read from the manifest itself.
type Expected struct {
	CaptureID   string
	SourceLabel string
	KeyID       string
}

type signedFields struct {
	Version     int    `json:"version"`
	CaptureID   string `json:"capture_id"`
	SourceLabel string `json:"source_label"`
	CapturedUTC string `json:"captured_utc"`
	ByteCount   int64  `json:"byte_count"`
	SHA256      string `json:"sha256"`
	KeyID       string `json:"key_id"`
}

// SigningBytes is intended for test-only signing and independently controlled
// external signers. It MUST NOT be interpreted as authority to create keys.
// No signature bytes are included, so the encoding is non-circular.
func SigningBytes(m Manifest) ([]byte, error) {
	if err := validateFields(m); err != nil {
		return nil, err
	}
	fields := signedFields{
		m.Version, m.CaptureID, m.SourceLabel, m.CapturedUTC,
		m.ByteCount, m.SHA256, m.KeyID,
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: field encoding: %v", ErrInvalidManifest, err)
	}
	return append([]byte(domainPrefix), b...), nil
}

// VerifyStream checks the canonical envelope and signature BEFORE consuming r,
// then hashes the stream and checks its byte count. A content mismatch returns
// (false, count, nil); any I/O failure is an error, never a positive match.
// The caller must independently pin expected identifiers and trustedKey.
// It must also separately validate key custody, provenance, clocks and replay.
func VerifyStream(r io.Reader, raw []byte, expected Expected, trustedKey ed25519.PublicKey) (bool, int64, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return false, 0, ErrInvalidManifest
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, 0, ErrInvalidManifest
	}
	if err := validateFields(m); err != nil {
		return false, 0, err
	}
	canon, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canon, raw) {
		// Also rejects duplicate JSON keys, extra fields, whitespace, and reordering.
		return false, 0, ErrInvalidManifest
	}
	if len(trustedKey) != ed25519.PublicKeySize ||
		expected.CaptureID == "" || expected.SourceLabel == "" || expected.KeyID == "" ||
		m.CaptureID != expected.CaptureID || m.SourceLabel != expected.SourceLabel || m.KeyID != expected.KeyID {
		return false, 0, ErrUntrustedContext
	}
	sig, err := base64.RawStdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(sig) != m.Signature {
		return false, 0, ErrInvalidManifest
	}
	payload, err := SigningBytes(m)
	if err != nil {
		return false, 0, err
	}
	if !ed25519.Verify(trustedKey, payload, sig) {
		return false, 0, ErrInvalidSignature
	}
	match, n, err := integrity.Verify(r, m.SHA256)
	if err != nil {
		return false, n, err
	}
	return match && n == m.ByteCount, n, nil
}

func validateFields(m Manifest) error {
	if m.Version != schemaVersion ||
		!safeID(m.CaptureID, false) || !safeID(m.SourceLabel, false) || !safeID(m.KeyID, true) ||
		m.ByteCount < 0 || len(m.SHA256) != 64 {
		return ErrInvalidManifest
	}
	for _, b := range []byte(m.SHA256) {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return ErrInvalidManifest
		}
	}
	if len(m.CapturedUTC) != len("2026-01-02T03:04:05Z") {
		return ErrInvalidManifest
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", m.CapturedUTC)
	if err != nil || t.UTC().Format("2006-01-02T15:04:05Z") != m.CapturedUTC {
		return ErrInvalidManifest
	}
	return nil
}

func safeID(s string, allowDot bool) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			(i > 0 && (c == '-' || c == '_' || (allowDot && c == '.'))) {
			continue
		}
		return false
	}
	return true
}
