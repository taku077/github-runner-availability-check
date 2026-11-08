// Package trustpolicy validates independently pinned, synthetic Ed25519 key
// policy snapshots. It does NOT distribute, authenticate, or revoke real keys.
package trustpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
)

const (
	snapshotVersion   = 1
	maxRecords        = 64
	fingerprintDomain = "public-synthetic-key-policy/v1\n"
)

type KeyState uint8

const (
	KeyActive KeyState = iota + 1
	KeyRetired
	KeyRevoked
)

type KeyRecord struct {
	KeyID     string            `json:"key_id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	State     KeyState          `json:"state"`
}

type Snapshot struct {
	Version    int         `json:"version"`
	Generation uint64      `json:"generation"`
	Keys       []KeyRecord `json:"keys"`
}

// Pin must be supplied from an independently authenticated channel, not from
// the snapshot or signed capture manifest being checked. Generation alone is
// not sufficient to authenticate a snapshot: the fingerprint MUST match too.
type Pin struct {
	Generation  uint64
	Fingerprint [sha256.Size]byte
}

var (
	ErrInvalidSnapshot = errors.New("trustpolicy: invalid snapshot")
	ErrPinMismatch     = errors.New("trustpolicy: independent policy pin mismatch")
	ErrKeyNotActive    = errors.New("trustpolicy: key unavailable or not active")
)

type Policy struct {
	active map[string]ed25519.PublicKey
}

// Fingerprint computes the *untrusted* canonical snapshot fingerprint. Calling
// this function does not authorize the snapshot. Only an independently obtained
// matching Pin provides an authentication boundary.
func Fingerprint(snapshot Snapshot) ([sha256.Size]byte, error) {
	if !validSnapshot(snapshot) {
		return [sha256.Size]byte{}, ErrInvalidSnapshot
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidSnapshot
	}
	// Domain separation prevents confusion with unrelated SHA-256 records.
	return sha256.Sum256(append([]byte(fingerprintDomain), b...)), nil
}

// ValidateAndPin checks the independently pinned snapshot generation AND full
// fingerprint before constructing an immutable copy of the active-key map.
// Retired and revoked records are present for audit but cannot authorize data.
// A previously valid signature is NOT accepted under a retired/revoked key
// without a separately designed historical trust and trusted-time mechanism.
func ValidateAndPin(snapshot Snapshot, pin Pin) (*Policy, error) {
	if pin.Generation == 0 || snapshot.Generation != pin.Generation {
		return nil, ErrPinMismatch
	}
	got, err := Fingerprint(snapshot)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(got[:], pin.Fingerprint[:]) != 1 {
		return nil, ErrPinMismatch
	}
	result := &Policy{active: make(map[string]ed25519.PublicKey)}
	for _, rec := range snapshot.Keys {
		if rec.State == KeyActive {
			result.active[rec.KeyID] = append(ed25519.PublicKey(nil), rec.PublicKey...)
		}
	}
	return result, nil
}

// ResolveActive returns a defensive copy or fails closed. The zero value and
// nil *Policy reject all keys. No manifest-supplied key can add trust.
func (p *Policy) ResolveActive(id string) (ed25519.PublicKey, error) {
	if p == nil || !safeKeyID(id) {
		return nil, ErrKeyNotActive
	}
	key, ok := p.active[id]
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, ErrKeyNotActive
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func validSnapshot(s Snapshot) bool {
	if s.Version != snapshotVersion || s.Generation == 0 || len(s.Keys) == 0 || len(s.Keys) > maxRecords {
		return false
	}
	prior := ""
	for _, r := range s.Keys {
		if !safeKeyID(r.KeyID) || (prior != "" && prior >= r.KeyID) ||
			len(r.PublicKey) != ed25519.PublicKeySize ||
			(r.State != KeyActive && r.State != KeyRetired && r.State != KeyRevoked) {
			return false
		}
		prior = r.KeyID
	}
	return true
}

func safeKeyID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			(i > 0 && (c == '-' || c == '_' || c == '.')) {
			continue
		}
		return false
	}
	return true
}
