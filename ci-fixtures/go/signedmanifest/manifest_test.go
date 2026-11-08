package signedmanifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/taku077/github-runner-availability-check/ci-fixtures/go/integrity"
)

const syntheticContent = "synthetic evidence bytes only"

// Fixed public test key is NOT a trusted real-world identity or a production
// secret. Anyone who can see this test can recreate this key and its signature.
func syntheticKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return public, private
}

func sample(t *testing.T) ([]byte, Expected, ed25519.PublicKey) {
	t.Helper()
	public, private := syntheticKeys()
	digest := sha256.Sum256([]byte(syntheticContent))
	m := Manifest{
		Version:     1,
		CaptureID:   "sample-001",
		SourceLabel: "synthetic-stream",
		CapturedUTC: "2026-01-02T03:04:05Z",
		ByteCount:   int64(len(syntheticContent)),
		SHA256:      hex.EncodeToString(digest[:]),
		KeyID:       "test-key-v1",
	}
	payload, err := SigningBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, Expected{CaptureID: m.CaptureID, SourceLabel: m.SourceLabel, KeyID: m.KeyID}, public
}

func TestValidSignedManifest(t *testing.T) {
	raw, expected, key := sample(t)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), raw, expected, key)
	if err != nil || !ok || n != int64(len(syntheticContent)) {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestTamperedContentFails(t *testing.T) {
	raw, expected, key := sample(t)
	data := []byte(syntheticContent)
	data[0] ^= 1
	ok, n, err := VerifyStream(bytes.NewReader(data), raw, expected, key)
	if err != nil || ok || n != int64(len(data)) {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestTruncatedContentFails(t *testing.T) {
	raw, expected, key := sample(t)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent[:5]), raw, expected, key)
	if err != nil || ok || n != 5 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestWrongCaptureIDRejectedBeforeReading(t *testing.T) {
	raw, expected, key := sample(t)
	expected.CaptureID = "different-capture"
	r := &countReader{Reader: strings.NewReader(syntheticContent)}
	ok, n, err := VerifyStream(r, raw, expected, key)
	if !errors.Is(err, ErrUntrustedContext) || ok || n != 0 || r.calls != 0 {
		t.Fatalf("got (%v,%d,%v,%d)", ok, n, err, r.calls)
	}
}

func TestWrongSourceLabelRejectedBeforeReading(t *testing.T) {
	raw, expected, key := sample(t)
	expected.SourceLabel = "other-source"
	r := &countReader{Reader: strings.NewReader(syntheticContent)}
	ok, n, err := VerifyStream(r, raw, expected, key)
	if !errors.Is(err, ErrUntrustedContext) || ok || n != 0 || r.calls != 0 {
		t.Fatalf("got (%v,%d,%v,%d)", ok, n, err, r.calls)
	}
}

func TestWrongKeyIDRejectedBeforeReading(t *testing.T) {
	raw, expected, key := sample(t)
	expected.KeyID = "untrusted-key"
	r := &countReader{Reader: strings.NewReader(syntheticContent)}
	ok, n, err := VerifyStream(r, raw, expected, key)
	if !errors.Is(err, ErrUntrustedContext) || ok || n != 0 || r.calls != 0 {
		t.Fatalf("got (%v,%d,%v,%d)", ok, n, err, r.calls)
	}
}

func TestWrongTrustedKeyFailsSignature(t *testing.T) {
	raw, expected, _ := sample(t)
	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	key := otherPrivate.Public().(ed25519.PublicKey)
	r := &countReader{Reader: strings.NewReader(syntheticContent)}
	ok, n, err := VerifyStream(r, raw, expected, key)
	if !errors.Is(err, ErrInvalidSignature) || ok || n != 0 || r.calls != 0 {
		t.Fatalf("got (%v,%d,%v,%d)", ok, n, err, r.calls)
	}
}

func TestInvalidKeySizeRejectedBeforeReading(t *testing.T) {
	raw, expected, _ := sample(t)
	r := &countReader{Reader: strings.NewReader(syntheticContent)}
	ok, n, err := VerifyStream(r, raw, expected, ed25519.PublicKey{1, 2, 3})
	if !errors.Is(err, ErrUntrustedContext) || ok || n != 0 || r.calls != 0 {
		t.Fatalf("got (%v,%d,%v,%d)", ok, n, err, r.calls)
	}
}

func TestSignedFieldTamperingRejected(t *testing.T) {
	raw, expected, key := sample(t)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.ByteCount++
	altered, _ := json.Marshal(m)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, key)
	if !errors.Is(err, ErrInvalidSignature) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestManifestSignatureMutationRejected(t *testing.T) {
	raw, expected, key := sample(t)
	var m Manifest
	_ = json.Unmarshal(raw, &m)
	m.Signature = "" + m.Signature[:10] + "A" + m.Signature[11:]
	altered, _ := json.Marshal(m)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, key)
	if !errors.Is(err, ErrInvalidSignature) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestNoncanonicalJSONRejected(t *testing.T) {
	raw, expected, key := sample(t)
	var m Manifest
	_ = json.Unmarshal(raw, &m)
	cases := [][]byte{
		append(append([]byte{}, raw...), '\n'),
		append([]byte(" "), raw...),
		[]byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(raw), `"version":1`, `"unknown":0,"version":1`, 1)),
	}
	for _, c := range cases {
		ok, n, err := VerifyStream(strings.NewReader(syntheticContent), c, expected, key)
		if !errors.Is(err, ErrInvalidManifest) || ok || n != 0 {
			t.Fatalf("bad raw %s: (%v,%d,%v)", string(c)[:min(len(c), 64)], ok, n, err)
		}
	}
}

func TestMalformedFieldsRejected(t *testing.T) {
	raw, expected, key := sample(t)
	var original Manifest
	_ = json.Unmarshal(raw, &original)
	cases := []Manifest{original, original, original, original, original, original, original}
	cases[0].Version = 2
	cases[1].CaptureID = "a/b"
	cases[2].SourceLabel = "bad path"
	cases[3].CapturedUTC = "2026-01-02T03:04:05+00:00"
	cases[4].ByteCount = -1
	cases[5].SHA256 = strings.ToUpper(original.SHA256)
	cases[6].KeyID = "invalid:colon"
	for i, m := range cases {
		altered, _ := json.Marshal(m)
		ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, key)
		if !errors.Is(err, ErrInvalidManifest) || ok || n != 0 {
			t.Fatalf("case %d (%v,%d,%v)", i, ok, n, err)
		}
	}
}

func TestNilReaderPropagatesError(t *testing.T) {
	raw, expected, key := sample(t)
	ok, n, err := VerifyStream(nil, raw, expected, key)
	if !errors.Is(err, integrity.ErrNilReader) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

type countReader struct {
	io.Reader
	calls int
}

func (r *countReader) Read(p []byte) (int, error) { r.calls++; return r.Reader.Read(p) }

type failReader struct{ read bool }

var errFailure = errors.New("synthetic reader failure")

func (r *failReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		return copy(p, []byte("abc")), nil
	}
	return 0, errFailure
}
func TestReadErrorNeverSucceeds(t *testing.T) {
	raw, expected, key := sample(t)
	ok, n, err := VerifyStream(&failReader{}, raw, expected, key)
	if !errors.Is(err, errFailure) || ok || n != 3 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestSignatureEncodingInvalid(t *testing.T) {
	raw, expected, key := sample(t)
	var m Manifest
	_ = json.Unmarshal(raw, &m)
	m.Signature = "*bad*"
	altered, _ := json.Marshal(m)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, key)
	if !errors.Is(err, ErrInvalidManifest) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestManifestSizeLimit(t *testing.T) {
	raw, expected, key := sample(t)
	padding := bytes.Repeat([]byte(" "), 3000)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), append(raw, padding...), expected, key)
	if !errors.Is(err, ErrInvalidManifest) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestSignedTimeClaimTamperingRejected(t *testing.T) {
	raw, expected, key := sample(t)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.CapturedUTC = "2026-01-02T03:04:06Z" // Still canonical UTC, but no longer signed.
	altered, _ := json.Marshal(m)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, key)
	if !errors.Is(err, ErrInvalidSignature) || ok || n != 0 {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestSignerCanClaimIncorrectLengthButVerifierRejects(t *testing.T) {
	raw, expected, public := sample(t)
	_, private := syntheticKeys()
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.ByteCount++ // Signer claims the stream is longer than its actual bytes.
	payload, err := SigningBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	altered, _ := json.Marshal(m)
	ok, n, err := VerifyStream(strings.NewReader(syntheticContent), altered, expected, public)
	if err != nil || ok || n != int64(len(syntheticContent)) {
		t.Fatalf("got (%v,%d,%v)", ok, n, err)
	}
}

func TestSigningBytesValidatesFields(t *testing.T) {
	m := Manifest{Version: 1, CaptureID: "bad/path", SourceLabel: "synthetic", CapturedUTC: "2026-01-02T03:04:05Z", SHA256: strings.Repeat("0", 64), KeyID: "test-key"}
	b, err := SigningBytes(m)
	if !errors.Is(err, ErrInvalidManifest) || len(b) != 0 {
		t.Fatalf("got (%q,%v)", b, err)
	}
}
