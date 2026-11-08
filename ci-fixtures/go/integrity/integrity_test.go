package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

const shaABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestDigestKnownVector(t *testing.T) {
	got, n, err := Digest(strings.NewReader("abc"))
	if err != nil || n != 3 || got != shaABC {
		t.Fatalf("digest = (%q, %d, %v)", got, n, err)
	}
}

func TestDigestEmptyStream(t *testing.T) {
	got, n, err := Digest(strings.NewReader(""))
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err != nil || n != 0 || got != empty {
		t.Fatalf("empty digest = (%q, %d, %v)", got, n, err)
	}
}

func TestDigestChunkedStream(t *testing.T) {
	r := &oneByteReader{data: []byte("abc")}
	got, n, err := Digest(r)
	if err != nil || n != 3 || got != shaABC {
		t.Fatalf("chunked = (%q, %d, %v)", got, n, err)
	}
}

type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestVerifyMatch(t *testing.T) {
	ok, n, err := Verify(strings.NewReader("abc"), shaABC)
	if err != nil || !ok || n != 3 {
		t.Fatalf("verify = (%v, %d, %v)", ok, n, err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	other := sha256.Sum256([]byte("different"))
	ok, n, err := Verify(strings.NewReader("abc"), hex.EncodeToString(other[:]))
	if err != nil || ok || n != 3 {
		t.Fatalf("mismatch = (%v, %d, %v)", ok, n, err)
	}
}

func TestVerifyRejectsMalformedExpectedWithoutReading(t *testing.T) {
	invalid := []string{"", "abc", strings.ToUpper(shaABC), " " + shaABC,
		shaABC + " ", strings.Repeat("g", 64), "0x" + shaABC}
	for _, value := range invalid {
		r := &countingReader{r: strings.NewReader("abc")}
		ok, n, err := Verify(r, value)
		if !errors.Is(err, ErrExpectedDigest) || ok || n != 0 || r.calls != 0 {
			t.Fatalf("invalid %q: (%v, %d, %v), calls=%d", value, ok, n, err, r.calls)
		}
	}
}

type countingReader struct {
	r     io.Reader
	calls int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	return r.r.Read(p)
}

func TestDigestRejectsNilReader(t *testing.T) {
	got, n, err := Digest(nil)
	if !errors.Is(err, ErrNilReader) || got != "" || n != 0 {
		t.Fatalf("nil digest = (%q, %d, %v)", got, n, err)
	}
}

func TestVerifyRejectsNilReader(t *testing.T) {
	ok, n, err := Verify(nil, shaABC)
	if !errors.Is(err, ErrNilReader) || ok || n != 0 {
		t.Fatalf("nil verify = (%v, %d, %v)", ok, n, err)
	}
}

var errSyntheticRead = errors.New("synthetic read failure")

type failingReader struct{ sent bool }

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, []byte("abc")), nil
	}
	return 0, errSyntheticRead
}

func TestDigestReadFailureIsNotAValidChecksum(t *testing.T) {
	got, n, err := Digest(&failingReader{})
	if !errors.Is(err, errSyntheticRead) || got != "" || n != 3 {
		t.Fatalf("failed stream = (%q, %d, %v)", got, n, err)
	}
}

func TestVerifyReadFailureNeverMatches(t *testing.T) {
	ok, n, err := Verify(&failingReader{}, shaABC)
	if !errors.Is(err, errSyntheticRead) || ok || n != 3 {
		t.Fatalf("failed verification = (%v, %d, %v)", ok, n, err)
	}
}

func TestVerifyLargeSyntheticBuffer(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 3, 0xfe, 0xff}, 80000)
	known := sha256.Sum256(data)
	ok, n, err := Verify(bytes.NewReader(data), hex.EncodeToString(known[:]))
	if err != nil || !ok || n != int64(len(data)) {
		t.Fatalf("large = (%v, %d, %v)", ok, n, err)
	}
}
