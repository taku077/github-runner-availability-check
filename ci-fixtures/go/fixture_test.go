// Package fixture tests the public CI toolchain using deterministic,
// synthetic standard-library inputs. It is not PC-monitoring code.
package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestSHA256StandardVector(t *testing.T) {
	got := sha256.Sum256([]byte("abc"))
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("SHA-256 standard test vector mismatch: %x", got)
	}
}

func TestHexDecodeRoundTrip(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	encoded := hex.EncodeToString(payload)
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(payload) {
		t.Fatalf("decoded length %d, want %d", len(decoded), len(payload))
	}
	for i := range payload {
		if decoded[i] != payload[i] {
			t.Fatalf("byte %d: %x != %x", i, decoded[i], payload[i])
		}
	}
}

func TestHexDecodeRejectsOddLength(t *testing.T) {
	if _, err := hex.DecodeString("abc"); err == nil {
		t.Fatal("expected an error for odd-length hex input")
	}
}

func TestSyntheticUTCRoundTrip(t *testing.T) {
	const iso = "2026-01-02T03:04:05Z"
	parsed, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.UTC().Format(time.RFC3339); got != iso {
		t.Fatalf("UTC round trip: got %q, want %q", got, iso)
	}
}
