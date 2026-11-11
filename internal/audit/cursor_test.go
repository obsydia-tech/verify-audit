package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCursorKeepsDestination(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log.shipped")
	if v, d := readShipState(p); v != 0 || d != "" {
		t.Fatalf("missing file: %d %q", v, d)
	}
	if err := os.WriteFile(p, []byte("42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if v, d := readShipState(p); v != 42 || d != "" {
		t.Fatalf("legacy cursor: %d %q", v, d)
	}
	if err := writeCursor(p, 7, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if v, d := readShipState(p); v != 7 || d != "0123456789abcdef" {
		t.Fatalf("cursor with destination: %d %q", v, d)
	}
	if readCursor(p) != 7 {
		t.Fatal("readCursor must ignore the destination")
	}
	if err := writeCursor(p, 0, ""); err != nil {
		t.Fatal(err)
	}
	if v, d := readShipState(p); v != 0 || d != "" {
		t.Fatalf("reset cursor: %d %q", v, d)
	}
}
