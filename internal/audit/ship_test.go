package audit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testSigner(t *testing.T, cn string) (crypto.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBatchSignatureCoversEveryField(t *testing.T) {
	signer, certPEM := testSigner(t, "pii-data")
	b := Batch{V: 1, Service: "pii-data", Node: "pd1", FromSeq: 1, ToSeq: 2, HeadSeq: 2, HeadHash: "h", SentAt: "now", Entries: []string{`{"seq":1}`, `{"seq":2}`}}
	if err := b.Sign(signer, certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := b.VerifySignature(); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*Batch){
		"entry":   func(c *Batch) { c.Entries = []string{`{"seq":1}`, `{"seq":3}`} },
		"range":   func(c *Batch) { c.ToSeq = 3 },
		"head":    func(c *Batch) { c.HeadHash = "x" },
		"node":    func(c *Batch) { c.Node = "pd2" },
		"service": func(c *Batch) { c.Service = "keys-data" },
	}
	for name, change := range changes {
		c := b
		c.Entries = append([]string(nil), b.Entries...)
		change(&c)
		if _, err := c.VerifySignature(); err == nil {
			t.Fatalf("%s changed and the signature still verifies", name)
		}
	}
}

type collected struct {
	mu       sync.Mutex
	seqs     []uint64
	beats    int
	maxBatch int
}

func fakeCollector(c *collected) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := b.VerifySignature(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		if len(b.Entries) == 0 {
			c.beats++
		} else if len(b.Entries) > c.maxBatch {
			c.maxBatch = len(b.Entries)
		}
		for _, e := range b.Entries {
			var en Entry
			json.Unmarshal([]byte(e), &en)
			c.seqs = append(c.seqs, en.Seq)
		}
		c.mu.Unlock()
		ack := b.ToSeq
		if len(b.Entries) == 0 {
			ack = b.HeadSeq
		}
		json.NewEncoder(w).Encode(map[string]uint64{"acked_seq": ack})
	}))
}

func clientCreds(srv *httptest.Server, signer crypto.Signer, certPEM []byte) func() (*tls.Config, crypto.Signer, []byte, error) {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return func() (*tls.Config, crypto.Signer, []byte, error) {
		return &tls.Config{RootCAs: pool}, signer, certPEM, nil
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShippingDeliversBacklogThenNewEntriesInOrder(t *testing.T) {
	c := &collected{}
	srv := fakeCollector(c)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path, "pd1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 250; i++ {
		l.Log("store_record", "ok")
	}
	signer, certPEM := testSigner(t, "pii-data")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.StartShipping(ctx, ShipConfig{URL: srv.URL, Service: "pii-data", Interval: 20 * time.Millisecond, MaxBatch: 100, Creds: clientCreds(srv, signer, certPEM)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		l.Log("fetch_record", "ok")
	}
	waitFor(t, "280 delivered entries", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.seqs) >= 280
	})
	waitFor(t, "the shipped position", func() bool { return readCursor(path+".shipped") == 280 })
	waitFor(t, "a heartbeat", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.beats > 0
	})
	c.mu.Lock()
	seqs := append([]uint64(nil), c.seqs...)
	maxBatch := c.maxBatch
	c.mu.Unlock()
	if len(seqs) != 280 {
		t.Fatalf("delivered %d entries, want 280 without repeats", len(seqs))
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("entry %d delivered as seq %d", i, s)
		}
	}
	if maxBatch > 100 {
		t.Fatalf("a batch held %d entries", maxBatch)
	}
	l.mu.Lock()
	shipped := l.shipped()
	l.mu.Unlock()
	if shipped != 280 {
		t.Fatalf("retention sees %d as shipped", shipped)
	}
}

func TestShippingNeverHoldsUpLogging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path, "pd1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	signer, certPEM := testSigner(t, "pii-data")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	creds := func() (*tls.Config, crypto.Signer, []byte, error) { return &tls.Config{}, signer, certPEM, nil }
	if err := l.StartShipping(ctx, ShipConfig{URL: "https://127.0.0.1:1", Service: "pii-data", Interval: 10 * time.Millisecond, MaxBatch: 5, Creds: creds}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 200; i++ {
		if err := l.Log("store_record", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("logging took %s while the collector was unreachable", d)
	}
	if readCursor(path+".shipped") != 0 {
		t.Fatal("entries were marked shipped without a collector")
	}
	l.mu.Lock()
	held := l.shipped != nil
	l.mu.Unlock()
	if held {
		t.Fatal("retention waits for shipping although nothing was ever delivered")
	}
}

func TestScanForwardFromCursorStopsAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 300)
	var seqs []uint64
	n, err := ScanForward(path, Query{AfterSeq: 120, Limit: 50}, func(l Line) error {
		seqs = append(seqs, l.Entry.Seq)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 50 || seqs[0] != 121 || seqs[49] != 170 {
		t.Fatalf("got %d entries from %d to %d", n, seqs[0], seqs[len(seqs)-1])
	}
}
