package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setRetryInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := retryInterval
	retryInterval = d
	t.Cleanup(func() { retryInterval = old })
}

func newGateLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path, "n1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, path
}

func breakAuditFile(t *testing.T, l *Logger) {
	t.Helper()
	if err := l.file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func repairAuditFile(t *testing.T, l *Logger, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	l.file = f
}

func readAuditFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func TestGateRefusesAndResumes(t *testing.T) {
	setRetryInterval(t, 0)
	l, path := newGateLogger(t)

	if err := l.Log("a", "ok"); err != nil {
		t.Fatalf("Log a: %v", err)
	}
	if err := l.Ready(); err != nil {
		t.Fatalf("Ready on a healthy log: %v", err)
	}

	breakAuditFile(t, l)
	if err := l.Log("b", "ok"); err == nil {
		t.Fatal("Log on a broken file returned nil")
	}
	if err := l.Ready(); err == nil {
		t.Fatal("Ready on a broken file returned nil")
	}
	if err := l.Ready(); err == nil {
		t.Fatal("second Ready on a broken file returned nil")
	}
	if err := l.Log("c", "ok"); err == nil {
		t.Fatal("second Log on a broken file returned nil")
	}
	if l.Err() == nil {
		t.Fatal("Err is nil while the log is broken")
	}

	repairAuditFile(t, l, path)
	if err := l.Ready(); err != nil {
		t.Fatalf("Ready after repair: %v", err)
	}
	if err := l.Err(); err != nil {
		t.Fatalf("Err after repair: %v", err)
	}
	if err := l.Log("d", "ok"); err != nil {
		t.Fatalf("Log d: %v", err)
	}
	l.Close()

	if err := Verify(path); err != nil {
		t.Fatalf("chain after resume: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(readAuditFile(t, path)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 entries, got %d", len(lines))
	}
	if !strings.Contains(lines[1], `"event":"audit_resumed"`) {
		t.Fatalf("second entry is not audit_resumed: %s", lines[1])
	}
	for _, want := range []string{`"entries_lost":"2"`, `"writes_refused":"2"`, `"first_error":`, `"since":`} {
		if !strings.Contains(lines[1], want) {
			t.Fatalf("audit_resumed lacks %s: %s", want, lines[1])
		}
	}
	if !strings.Contains(lines[2], `"event":"d"`) {
		t.Fatalf("last entry is not d: %s", lines[2])
	}
}

func TestGateRetryIsRateLimited(t *testing.T) {
	setRetryInterval(t, time.Hour)
	l, path := newGateLogger(t)

	breakAuditFile(t, l)
	if err := l.Log("x", "ok"); err == nil {
		t.Fatal("Log on a broken file returned nil")
	}
	repairAuditFile(t, l, path)
	if err := l.Ready(); err == nil {
		t.Fatal("Ready retried inside the retry interval")
	}
	retryInterval = 0
	if err := l.Ready(); err != nil {
		t.Fatalf("Ready after the retry interval: %v", err)
	}
	l.Close()

	if !strings.Contains(readAuditFile(t, path), `"writes_refused":"1"`) {
		t.Fatal("refused write was not counted")
	}
}

func TestGateProbeDoesNotCount(t *testing.T) {
	setRetryInterval(t, 0)
	l, path := newGateLogger(t)

	breakAuditFile(t, l)
	if err := l.Log("x", "ok"); err == nil {
		t.Fatal("Log on a broken file returned nil")
	}
	if err := l.Probe(); err == nil {
		t.Fatal("Probe on a broken file returned nil")
	}
	repairAuditFile(t, l, path)
	if err := l.Probe(); err != nil {
		t.Fatalf("Probe after repair: %v", err)
	}
	l.Close()

	data := readAuditFile(t, path)
	for _, want := range []string{`"entries_lost":"1"`, `"writes_refused":"0"`} {
		if !strings.Contains(data, want) {
			t.Fatalf("audit_resumed lacks %s: %s", want, data)
		}
	}
}
