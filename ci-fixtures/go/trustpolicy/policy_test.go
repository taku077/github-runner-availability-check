package trustpolicy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func fixture() Snapshot {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	return Snapshot{Version: 1, Generation: 2, Keys: []KeyRecord{
		{KeyID: "archive-v1", PublicKey: append([]byte(nil), pub...), State: KeyRetired},
		{KeyID: "collector-v2", PublicKey: append([]byte(nil), pub...), State: KeyActive},
		{KeyID: "revoked-v0", PublicKey: append([]byte(nil), pub...), State: KeyRevoked},
	}}
}
func goodPin(t *testing.T, s Snapshot) Pin {
	t.Helper()
	digest, err := Fingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return Pin{Generation: s.Generation, Fingerprint: digest}
}
func TestActiveKeyAccepted(t *testing.T) {
	s := fixture()
	p, e := ValidateAndPin(s, goodPin(t, s))
	if e != nil {
		t.Fatal(e)
	}
	k, e := p.ResolveActive("collector-v2")
	if e != nil || !bytes.Equal(k, s.Keys[1].PublicKey) {
		t.Fatalf("key=%x,err=%v", k, e)
	}
}
func TestRetiredKeyRejected(t *testing.T) {
	s := fixture()
	p, e := ValidateAndPin(s, goodPin(t, s))
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.ResolveActive("archive-v1")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
}
func TestRevokedKeyRejected(t *testing.T) {
	s := fixture()
	p, e := ValidateAndPin(s, goodPin(t, s))
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.ResolveActive("revoked-v0")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
}
func TestUnknownKeyRejected(t *testing.T) {
	s := fixture()
	p, e := ValidateAndPin(s, goodPin(t, s))
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.ResolveActive("unknown-v99")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
}
func TestGenerationRollbackRejected(t *testing.T) {
	s := fixture()
	pin := goodPin(t, s)
	pin.Generation++
	_, e := ValidateAndPin(s, pin)
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
}
func TestFingerprintSubstitutionRejected(t *testing.T) {
	s := fixture()
	pin := goodPin(t, s)
	s.Keys[1].PublicKey[0] ^= 1
	_, e := ValidateAndPin(s, pin)
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
}
func TestRevocationStateChangeRequiresNewPin(t *testing.T) {
	s := fixture()
	pin := goodPin(t, s)
	s.Keys[1].State = KeyRevoked
	_, e := ValidateAndPin(s, pin)
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
}
func TestZeroPinRejected(t *testing.T) {
	s := fixture()
	_, e := ValidateAndPin(s, Pin{})
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
}
func TestWrongDigestRejected(t *testing.T) {
	s := fixture()
	pin := goodPin(t, s)
	pin.Fingerprint[31] ^= 1
	_, e := ValidateAndPin(s, pin)
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
}
func TestUnsortedRejected(t *testing.T) {
	s := fixture()
	s.Keys[0], s.Keys[1] = s.Keys[1], s.Keys[0]
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestDuplicateIDRejected(t *testing.T) {
	s := fixture()
	s.Keys[1].KeyID = s.Keys[0].KeyID
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestEmptyKeyListRejected(t *testing.T) {
	s := fixture()
	s.Keys = nil
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestMalformedPublicKeyRejected(t *testing.T) {
	s := fixture()
	s.Keys[1].PublicKey = []byte{1}
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestUnknownKeyStateRejected(t *testing.T) {
	s := fixture()
	s.Keys[1].State = 99
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestEmptyPolicyFailsClosed(t *testing.T) {
	var p *Policy
	_, e := p.ResolveActive("collector-v2")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
	p = &Policy{}
	_, e = p.ResolveActive("collector-v2")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
}
func TestDefensiveCopyAgainstSnapshotMutation(t *testing.T) {
	s := fixture()
	pin := goodPin(t, s)
	p, e := ValidateAndPin(s, pin)
	if e != nil {
		t.Fatal(e)
	}
	orig, err := p.ResolveActive("collector-v2")
	if err != nil {
		t.Fatal(err)
	}
	s.Keys[1].PublicKey[0] ^= 1
	got, e := p.ResolveActive("collector-v2")
	if e != nil || !bytes.Equal(got, orig) {
		t.Fatal("mutation escaped snapshot")
	}
	got[0] ^= 1
	again, e := p.ResolveActive("collector-v2")
	if e != nil || !bytes.Equal(again, orig) {
		t.Fatal("mutation escaped resolve")
	}
}
func TestRotationRequiresNewPin(t *testing.T) {
	old := fixture()
	pin := goodPin(t, old)
	next := fixture()
	next.Generation = 3
	next.Keys[1].State = KeyRetired
	newPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x25}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	next.Keys = append(next.Keys[:2], KeyRecord{KeyID: "collector-v3", PublicKey: newPub, State: KeyActive}, next.Keys[2])
	_, e := ValidateAndPin(next, pin)
	if !errors.Is(e, ErrPinMismatch) {
		t.Fatal(e)
	}
	np, e := ValidateAndPin(next, goodPin(t, next))
	if e != nil {
		t.Fatal(e)
	}
	_, e = np.ResolveActive("collector-v2")
	if !errors.Is(e, ErrKeyNotActive) {
		t.Fatal(e)
	}
	_, e = np.ResolveActive("collector-v3")
	if e != nil {
		t.Fatal(e)
	}
}
func TestInvalidVersionAndGeneration(t *testing.T) {
	s := fixture()
	s.Version = 2
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
	s = fixture()
	s.Generation = 0
	_, e = Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
func TestMalformedIDAndTooMany(t *testing.T) {
	s := fixture()
	s.Keys[1].KeyID = "../collector"
	_, e := Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
	s = fixture()
	many := make([]KeyRecord, 65)
	for i := range many {
		many[i] = s.Keys[1]
	}
	s.Keys = many
	_, e = Fingerprint(s)
	if !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal(e)
	}
}
