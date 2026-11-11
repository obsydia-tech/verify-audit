package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func logN(t *testing.T, path string, n int) {
	t.Helper()
	l, err := New(path, "t1")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log("ev", "ok", WithTenant("x")); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func appendRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func report(t *testing.T, path string) *Report {
	t.Helper()
	r, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func torn(t *testing.T, path string) []string {
	t.Helper()
	m, err := filepath.Glob(path + ".torn-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func expect(t *testing.T, r *Report, entries, segments, bad, recoveries int) {
	t.Helper()
	if r.Entries != entries || r.Segments != segments || r.BadLines != bad || r.Recoveries != recoveries || r.TailBytes != 0 {
		t.Fatalf("got %s, want entries=%d segments=%d bad_lines=%d recoveries=%d tail_bytes=0; problems: %v",
			r, entries, segments, bad, recoveries, r.Problems)
	}
}

func TestChainResumesAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logN(t, path, 3)
	logN(t, path, 2)
	expect(t, report(t, path), 5, 1, 0, 0)
	if err := Verify(path); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(torn(t, path)) != 0 {
		t.Fatal("unexpected torn file")
	}
}

func TestDamagedTailIsSetAside(t *testing.T) {
	cases := map[string][]byte{
		"torn entry": []byte(`{"seq":3,"prev_hash":"ab`),
		"nul tail":   make([]byte, 700),
		"glued line": append(make([]byte, 300), []byte("{\"seq\":1,\"prev_hash\":\"x\"}\n")...),
	}
	for name, tail := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			logN(t, path, 2)
			appendRaw(t, path, tail)
			logN(t, path, 1)
			expect(t, report(t, path), 4, 1, 0, 1)
			if err := Verify(path); err != nil {
				t.Fatalf("verify: %v", err)
			}
			files := torn(t, path)
			if len(files) != 1 {
				t.Fatalf("torn files: %v", files)
			}
			got, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tail) {
				t.Fatalf("set aside %d bytes, want %d", len(got), len(tail))
			}
		})
	}
}

func TestGarbageOnlyFileStartsNewChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("garbage without newline"), 0600); err != nil {
		t.Fatal(err)
	}
	logN(t, path, 1)
	expect(t, report(t, path), 2, 1, 0, 1)
	if err := Verify(path); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRepeatedRecoveryKeepsEveryFragment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logN(t, path, 1)
	appendRaw(t, path, []byte("x"))
	logN(t, path, 0)
	appendRaw(t, path, []byte("y"))
	logN(t, path, 0)
	expect(t, report(t, path), 3, 1, 0, 2)
	if n := len(torn(t, path)); n != 2 {
		t.Fatalf("torn files: %d, want 2", n)
	}
}

func TestOldDamageInTheMiddleIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	other := filepath.Join(dir, "other.log")
	logN(t, path, 1)
	appendRaw(t, path, []byte("\x00\x00junk\n"))
	logN(t, other, 2)
	second, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, path, second)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	logN(t, path, 1)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(after, before) {
		t.Fatal("existing content was changed")
	}
	expect(t, report(t, path), 4, 2, 1, 0)
	if len(torn(t, path)) != 0 {
		t.Fatal("unexpected torn file")
	}
	if err := Verify(path); err == nil {
		t.Fatal("verify passed on a log with old damage")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logN(t, path, 3)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"event":"ev"`), []byte(`"event":"eX"`), 1)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err == nil {
		t.Fatal("verify passed on a tampered log")
	}
}
