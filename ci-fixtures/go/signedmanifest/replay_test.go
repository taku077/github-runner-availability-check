package signedmanifest

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "io"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
)

// memoryLedger is a test double, never durable. A real implementation must
// perform the entire insert/compare in a persistent atomic transaction.
type memoryLedger struct {
    mu sync.Mutex
    entries map[string][sha256.Size]byte
    calls int
    failure error
    fixed LedgerOutcome
}
func (l *memoryLedger) RecordOnce(ctx context.Context, id string, fp [sha256.Size]byte) (LedgerOutcome,error) {
    l.mu.Lock()
    defer l.mu.Unlock()
    l.calls++
    if l.failure!=nil {return 0,l.failure}
    if l.fixed!=0 {return l.fixed,nil}
    if l.entries==nil {l.entries=make(map[string][sha256.Size]byte)}
    if prior,exists:=l.entries[id];exists {
        if prior==fp {return LedgerDuplicate,nil}
        return LedgerConflict,nil
    }
    l.entries[id]=fp
    return LedgerInserted,nil
}
func testVerified(t *testing.T, l ReplayLedger) (bool,int64,error) {
    t.Helper()
    raw, want, key:=sample(t)
    return VerifyAndRecord(context.Background(),strings.NewReader(syntheticContent),raw,want,key,l)
}
func TestReplayFirstCommitAccepted(t *testing.T) {
    ledger:=&memoryLedger{}
    ok,n,err:=testVerified(t,ledger)
    if !ok||n!=int64(len(syntheticContent))||err!=nil||ledger.calls!=1 {t.Fatalf("got %t %d %v calls=%d",ok,n,err,ledger.calls)}
}
func TestReplayExactDuplicateRejected(t *testing.T) {
    l:=&memoryLedger{}
    testVerified(t,l)
    ok,n,err:=testVerified(t,l)
    if ok||n!=int64(len(syntheticContent))||!errors.Is(err,ErrReplay)||l.calls!=2 {t.Fatalf("got %t %d %v calls=%d",ok,n,err,l.calls)}
}
func TestReplayResignedSameCaptureIDIsConflict(t *testing.T) {
    raw, expected, key:=sample(t)
    l:=&memoryLedger{}
    ok,_,err:=VerifyAndRecord(context.Background(),strings.NewReader(syntheticContent),raw,expected,key,l)
    if !ok||err!=nil {t.Fatalf("first %t %v",ok,err)}
    var m Manifest
    if err:=json.Unmarshal(raw,&m);err!=nil {t.Fatal(err)}
    m.CapturedUTC="2026-01-02T03:04:06Z"
    b,err:=SigningBytes(m)
    if err!=nil {t.Fatal(err)}
    _,private:=syntheticKeys()
    m.Signature=base64.RawStdEncoding.EncodeToString(ed25519.Sign(private,b))
    changed,err:=json.Marshal(m)
    if err!=nil {t.Fatal(err)}
    ok,n,err:=VerifyAndRecord(context.Background(),strings.NewReader(syntheticContent),changed,expected,key,l)
    if ok||n!=int64(len(syntheticContent))||!errors.Is(err,ErrCaptureConflict) {t.Fatalf("changed %t %d %v",ok,n,err)}
}
func TestReplayLedgerAbsentRejectedBeforeReading(t *testing.T) {
    raw,e,key:=sample(t)
    r:=&countReader{Reader:strings.NewReader(syntheticContent)}
    ok,n,err:=VerifyAndRecord(context.Background(),r,raw,e,key,nil)
    if ok||n!=0||!errors.Is(err,ErrNilLedger)||r.calls!=0 {t.Fatalf("got %t %d %v calls %d",ok,n,err,r.calls)}
}
func TestReplayNilContextRejectedBeforeReading(t *testing.T) {
    raw,e,key:=sample(t)
    r:=&countReader{Reader:strings.NewReader(syntheticContent)}
    ok,n,err:=VerifyAndRecord(nil,r,raw,e,key,&memoryLedger{})
    if ok||n!=0||!errors.Is(err,ErrNilContext)||r.calls!=0 {t.Fatalf("got %t %d %v calls %d",ok,n,err,r.calls)}
}
func TestReplayCanceledContextRejectedBeforeReading(t *testing.T) {
    raw,e,key:=sample(t)
    ctx,cancel:=context.WithCancel(context.Background()); cancel()
    r:=&countReader{Reader:strings.NewReader(syntheticContent)}
    ok,n,err:=VerifyAndRecord(ctx,r,raw,e,key,&memoryLedger{})
    if ok||n!=0||!errors.Is(err,context.Canceled)||r.calls!=0 {t.Fatalf("got %t %d %v calls %d",ok,n,err,r.calls)}
}
func TestReplayInvalidSignatureDoesNotWrite(t *testing.T) {
    raw,e,key:=sample(t)
    raw=bytes.Replace(raw,[]byte(`"version":1`),[]byte(`"version":2`),1)
    l:=&memoryLedger{}
    ok,n,err:=VerifyAndRecord(context.Background(),strings.NewReader(syntheticContent),raw,e,key,l)
    if ok||n!=0||err==nil||l.calls!=0 {t.Fatalf("got %t %d %v calls=%d",ok,n,err,l.calls)}
}
func TestReplayMismatchedStreamDoesNotWrite(t *testing.T) {
    raw,e,key:=sample(t)
    l:=&memoryLedger{}
    ok,n,err:=VerifyAndRecord(context.Background(),strings.NewReader("wrong"),raw,e,key,l)
    if ok||n!=5||err!=nil||l.calls!=0 {t.Fatalf("got %t %d %v calls=%d",ok,n,err,l.calls)}
}
func TestReplayReaderErrorDoesNotWrite(t *testing.T) {
    raw,e,key:=sample(t)
    l:=&memoryLedger{}
    ok,n,err:=VerifyAndRecord(context.Background(),&failReader{},raw,e,key,l)
    if ok||n!=3||!errors.Is(err,errFailure)||l.calls!=0 {t.Fatalf("got %t %d %v calls=%d",ok,n,err,l.calls)}
}
func TestReplayLedgerStorageErrorFailClosed(t *testing.T) {
    failure:=errors.New("synthetic storage not durable")
    l:=&memoryLedger{failure:failure}
    ok,n,err:=testVerified(t,l)
    if ok||n!=int64(len(syntheticContent))||!errors.Is(err,failure) {t.Fatalf("got %t %d %v",ok,n,err)}
}
func TestReplayInvalidLedgerOutcomeFailClosed(t *testing.T) {
    l:=&memoryLedger{fixed:LedgerOutcome(99)}
    ok,n,err:=testVerified(t,l)
    if ok||n!=int64(len(syntheticContent))||!errors.Is(err,ErrInvalidLedgerOutcome) {t.Fatalf("got %t %d %v",ok,n,err)}
}
func TestReplayLedgerConflictFailClosed(t *testing.T) {
    l:=&memoryLedger{fixed:LedgerConflict}
    ok,_,err:=testVerified(t,l)
    if ok||!errors.Is(err,ErrCaptureConflict) {t.Fatalf("got %t %v",ok,err)}
}
func TestReplayLedgerDuplicateFailClosed(t *testing.T) {
    l:=&memoryLedger{fixed:LedgerDuplicate}
    ok,_,err:=testVerified(t,l)
    if ok||!errors.Is(err,ErrReplay) {t.Fatalf("got %t %v",ok,err)}
}
func TestReplayConcurrentSameRecordAcceptsOnce(t *testing.T) {
    l:=&memoryLedger{}
    raw,e,key:=sample(t)
    const workers=32
    var successful atomic.Int32
    var failures atomic.Int32
    var wg sync.WaitGroup
    for i:=0;i<workers;i++ {
        wg.Add(1)
        go func(){
            defer wg.Done()
            ok,_,err:=VerifyAndRecord(context.Background(),strings.NewReader(syntheticContent),raw,e,key,l)
            if ok&&err==nil {successful.Add(1)} else if !ok&&errors.Is(err,ErrReplay) {failures.Add(1)}
        }()
    }
    wg.Wait()
    if successful.Load()!=1||failures.Load()!=workers-1||l.calls!=workers {
        t.Fatalf("accepted %d duplicates %d calls %d",successful.Load(),failures.Load(),l.calls)
    }
}
func TestReplaySignedEmptyContent(t *testing.T) {
    raw,e,key:=sample(t)
    var m Manifest
    if err:=json.Unmarshal(raw,&m);err!=nil {t.Fatal(err)}
    h:=sha256.Sum256(nil)
    m.ByteCount=0
    m.SHA256=hexEncode(h[:])
    bytesToSign,err:=SigningBytes(m);if err!=nil {t.Fatal(err)}
    _,private:=syntheticKeys()
    m.Signature=base64.RawStdEncoding.EncodeToString(ed25519.Sign(private,bytesToSign))
    altered,_:=json.Marshal(m)
    ok,n,err:=VerifyAndRecord(context.Background(),strings.NewReader(""),altered,e,key,&memoryLedger{})
    if !ok||n!=0||err!=nil {t.Fatalf("got %t %d %v",ok,n,err)}
}
func hexEncode(b []byte) string {
    const symbols="0123456789abcdef"
    var out strings.Builder
    for _,v:=range b {out.WriteByte(symbols[v>>4]);out.WriteByte(symbols[v&15])}
    return out.String()
}
func TestReplayNoAccidentalReaderOnBadContext(t *testing.T) {
    raw,e,key:=sample(t)
    r:=&countReader{Reader:io.LimitReader(strings.NewReader("abc"),1)}
    l:=&memoryLedger{}
    e.KeyID="other"
    ok,n,err:=VerifyAndRecord(context.Background(),r,raw,e,key,l)
    if ok||n!=0||err==nil||l.calls!=0||r.calls!=0 {t.Fatalf("got %t %d %v calls %d reads %d",ok,n,err,l.calls,r.calls)}
}
