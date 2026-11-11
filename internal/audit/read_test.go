package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var readEvents = []string{"store_record", "fetch_record", "delete_record"}

func writeEntries(t *testing.T, path string, n int) {
	t.Helper()
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 200)
	for i := 1; i <= n; i++ {
		tenant := "t1"
		if i%10 == 0 {
			tenant = "t2"
		}
		if err := l.Log(readEvents[i%3], "ok", WithTenant(tenant), WithKey(fmt.Sprintf("tok-%04d", i)), WithActor("app"), WithDetail(map[string]string{"pad": pad})); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadBackwardPagesAcrossBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 1200)
	var seqs []uint64
	before := uint64(0)
	for page := 0; page < 100; page++ {
		lines, next, err := ReadBackward(path, Query{BeforeSeq: before, Limit: 97})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			seqs = append(seqs, l.Entry.Seq)
		}
		if next == 0 {
			break
		}
		before = next
	}
	if len(seqs) != 1200 {
		t.Fatalf("read %d entries, want 1200", len(seqs))
	}
	for i, s := range seqs {
		if s != uint64(1200-i) {
			t.Fatalf("entry %d has seq %d, want %d", i, s, 1200-i)
		}
	}
}

func TestReadBackwardRawKeepsTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 400)
	lines, _, err := ReadBackward(path, Query{Limit: 400})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(lines); i++ {
		h := sha256.Sum256(lines[i+1].Raw)
		if lines[i].Entry.PrevHash != hex.EncodeToString(h[:]) {
			t.Fatalf("entry %d does not chain to the bytes handed out for entry %d", lines[i].Entry.Seq, lines[i+1].Entry.Seq)
		}
	}
}

func TestReadBackwardFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 300)
	count := func(q Query) int {
		t.Helper()
		q.Limit = 1000
		lines, _, err := ReadBackward(path, q)
		if err != nil {
			t.Fatal(err)
		}
		return len(lines)
	}
	if n := count(Query{TenantID: "t2"}); n != 30 {
		t.Fatalf("tenant t2: %d, want 30", n)
	}
	if n := count(Query{EventOK: func(e string) bool { return e == "fetch_record" }}); n != 100 {
		t.Fatalf("fetch_record: %d, want 100", n)
	}
	if n := count(Query{KeyID: "tok-0007"}); n != 1 {
		t.Fatalf("one token: %d, want 1", n)
	}
	if n := count(Query{ActorID: "someone-else"}); n != 0 {
		t.Fatalf("other actor: %d, want 0", n)
	}
	if n := count(Query{Result: "error"}); n != 0 {
		t.Fatalf("errors: %d, want 0", n)
	}
	if n := count(Query{From: time.Now().Add(time.Hour)}); n != 0 {
		t.Fatalf("from the future: %d, want 0", n)
	}
	if n := count(Query{To: time.Now().Add(-time.Hour)}); n != 0 {
		t.Fatalf("until an hour ago: %d, want 0", n)
	}
}

func TestEntryWithoutTenantIsShownToEveryTenant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	l.Log("startup", "ok", WithActor("system"))
	l.Log("store_record", "ok", WithTenant("t2"))
	l.Close()
	lines, _, err := ReadBackward(path, Query{TenantID: "t1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0].Entry.Event != "startup" {
		t.Fatalf("tenant t1 sees %d entries, want only startup", len(lines))
	}
}

func TestReadBackwardIgnoresAnUnterminatedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 5)
	appendRaw(t, path, []byte(`{"seq":6,"prev_hash":"ab`))
	lines, next, err := ReadBackward(path, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 || lines[0].Entry.Seq != 5 || next != 0 {
		t.Fatalf("got %d entries starting at %d, next %d", len(lines), lines[0].Entry.Seq, next)
	}
}

func TestScanForwardStreamsInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeEntries(t, path, 1200)
	var last uint64
	n, err := ScanForward(path, Query{TenantID: "t1"}, func(l Line) error {
		if l.Entry.Seq <= last {
			return fmt.Errorf("seq %d after %d", l.Entry.Seq, last)
		}
		last = l.Entry.Seq
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1080 {
		t.Fatalf("streamed %d entries of tenant t1, want 1080", n)
	}
}
