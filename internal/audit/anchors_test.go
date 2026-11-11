package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAnchorMailRoundTripAndTamper(t *testing.T) {
	signer, certPEM := testSigner(t, "audit-shipper")
	at := time.Date(2026, 10, 21, 19, 0, 0, 0, time.UTC)
	in := []Anchor{
		{Tenant: "t1", Service: "pii-data", Node: "pd1", Seq: 4768, Hash: "aa", SentAt: "s", At: "2026-10-21T19:00:00Z"},
		{Tenant: "t1", Service: "keys-logic", Node: "kl1", Seq: 2655, Hash: "bb", SentAt: "s", At: "2026-10-21T19:00:00Z"},
	}
	mail, err := ComposeAnchorMail("core0@example.com", "admin+core0-anchors-1234abcd@example.com", "Core0 audit anchors t1 2026-10-21 19:00 UTC", at, in, signer, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mail, []byte("\r\n")) || bytes.Contains(bytes.ReplaceAll(mail, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatal("mail lines are not CRLF")
	}
	out, cert, err := ParseAnchorMail(mail)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0] != in[0] || out[1] != in[1] || cert.Subject.CommonName != "audit-shipper" {
		t.Fatalf("parsed %+v from %s", out, cert.Subject.CommonName)
	}
	tampered := bytes.Replace(mail, []byte(`"seq":4768`), []byte(`"seq":4767`), 1)
	if _, _, err := ParseAnchorMail(tampered); err == nil {
		t.Fatal("a changed anchor still verifies")
	}
	if _, _, err := ParseAnchorMail([]byte("Subject: x\r\n\r\nhello\r\n")); err == nil {
		t.Fatal("a mail without anchors was accepted")
	}
}

func TestSplitMbox(t *testing.T) {
	box := "From a@b Tue Oct 21 19:00:00 2026\nSubject: one\n\nbody1\n\nFrom a@b Tue Oct 21 20:00:00 2026\nSubject: two\n\nbody2\n"
	msgs := SplitMbox([]byte(box))
	if len(msgs) != 2 || !strings.Contains(string(msgs[0]), "body1") || !strings.Contains(string(msgs[1]), "body2") {
		t.Fatalf("split into %d messages", len(msgs))
	}
}
