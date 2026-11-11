package audit

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setClock(t *testing.T, at *time.Time) {
	t.Helper()
	old := nowUTC
	nowUTC = func() time.Time { return *at }
	t.Cleanup(func() { nowUTC = old })
}

func setRetention(t *testing.T, d time.Duration) {
	t.Helper()
	old := retention
	retention = d
	t.Cleanup(func() { retention = old })
}

func onDay(d int) time.Time {
	return time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC)
}

func logOn(t *testing.T, l *Logger, now *time.Time, d, n int) {
	t.Helper()
	*now = onDay(d)
	for i := 0; i < n; i++ {
		if err := l.Log("store_record", "ok", WithTenant("t1")); err != nil {
			t.Fatal(err)
		}
	}
}

func problems(r *Report) string {
	return strings.Join(r.Problems, "; ")
}

func TestRotationKeepsOneChainAcrossFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := onDay(1)
	setClock(t, &now)
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	logOn(t, l, &now, 1, 3)
	logOn(t, l, &now, 2, 2)
	l.Close()

	arcs, err := Archives(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(arcs) != 1 || arcs[0].FirstSeq != 1 || arcs[0].LastSeq != 3 || arcs[0].Day != "2026-10-01" {
		t.Fatalf("archives %+v", arcs)
	}
	lines, next, err := ReadBackward(path, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 6 || next != 0 {
		t.Fatalf("read %d entries, next %d", len(lines), next)
	}
	for i, l := range lines {
		if l.Entry.Seq != uint64(6-i) {
			t.Fatalf("entry %d has seq %d", i, l.Entry.Seq)
		}
	}
	rot := lines[2].Entry
	if rot.Event != RotatedEvent || rot.Detail["last_seq"] != "3" {
		t.Fatalf("entry 4 is %s %v", rot.Event, rot.Detail)
	}
	sum, err := fileSHA256(arcs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Detail["sha256"] != sum || rot.Detail["archive"] != filepath.Base(arcs[0].Path) {
		t.Fatalf("rotation entry does not name the archive it closed: %v", rot.Detail)
	}
	n, err := ScanForward(path, Query{}, func(Line) error { return nil })
	if err != nil || n != 6 {
		t.Fatalf("forward scan %d (%v)", n, err)
	}
	r, err := InspectSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Clean() || r.Entries != 6 || r.Archives != 1 {
		t.Fatalf("%s archives=%d: %s", r, r.Archives, problems(r))
	}

	l, err = New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	logOn(t, l, &now, 2, 1)
	l.Close()
	if arcs, _ := Archives(path); len(arcs) != 1 {
		t.Fatalf("a restart on the same day rotated again: %d archives", len(arcs))
	}
}

func TestCursorCrossesArchives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := onDay(1)
	setClock(t, &now)
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	for d := 1; d <= 3; d++ {
		logOn(t, l, &now, d, 4)
	}
	l.Close()
	var seqs []uint64
	before := uint64(0)
	for i := 0; i < 20; i++ {
		lines, next, err := ReadBackward(path, Query{Limit: 3, BeforeSeq: before})
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
	if len(seqs) != 14 {
		t.Fatalf("read %d entries, want 14", len(seqs))
	}
	for i, s := range seqs {
		if s != uint64(14-i) {
			t.Fatalf("entry %d has seq %d", i, s)
		}
	}
}

func TestRetentionDeletesOldArchivesAndRecordsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := onDay(1)
	setClock(t, &now)
	setRetention(t, 3*24*time.Hour)
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	logOn(t, l, &now, 1, 2)
	logOn(t, l, &now, 2, 2)
	logOn(t, l, &now, 3, 2)
	logOn(t, l, &now, 6, 1)
	l.Close()

	arcs, err := Archives(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(arcs) != 1 || arcs[0].Day != "2026-10-03" {
		t.Fatalf("archives left %+v", arcs)
	}
	lines, _, err := ReadBackward(path, Query{Limit: 50, EventOK: func(e string) bool { return e == ArchiveDeletedEvent }})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("%d deletions recorded, want 2", len(lines))
	}
	r, err := InspectSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Clean() || r.StartSeq != 6 {
		t.Fatalf("%s start=%d: %s", r, r.StartSeq, problems(r))
	}
}

func TestUnshippedArchivesAreKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := onDay(1)
	setClock(t, &now)
	setRetention(t, 3*24*time.Hour)
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	l.SetShipped(func() uint64 { return 2 })
	logOn(t, l, &now, 1, 2)
	logOn(t, l, &now, 2, 2)
	logOn(t, l, &now, 3, 2)
	logOn(t, l, &now, 6, 1)
	l.Close()
	arcs, err := Archives(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(arcs) != 2 || arcs[0].Day != "2026-10-02" {
		t.Fatalf("only the shipped archive may go: %+v", arcs)
	}
}

func TestTamperedOrMissingArchiveIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := onDay(1)
	setClock(t, &now)
	l, err := New(path, "n1")
	if err != nil {
		t.Fatal(err)
	}
	logOn(t, l, &now, 1, 3)
	logOn(t, l, &now, 2, 1)
	l.Close()
	arcs, err := Archives(path)
	if err != nil || len(arcs) != 1 {
		t.Fatalf("archives %v %v", arcs, err)
	}

	f, err := os.Create(arcs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	zw.Write([]byte("rewritten\n"))
	zw.Close()
	f.Close()
	r, err := InspectSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Clean() || !strings.Contains(problems(r), "does not match the hash") {
		t.Fatalf("tampered archive not reported: %s", problems(r))
	}

	if err := os.Remove(arcs[0].Path); err != nil {
		t.Fatal(err)
	}
	r, err = InspectSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(problems(r), "is missing and its deletion is not recorded") {
		t.Fatalf("missing archive not reported: %s", problems(r))
	}
}
