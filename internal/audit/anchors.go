package audit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Anchor is the head of one audit stream at the moment an anchor mail is made.
type Anchor struct {
	Tenant  string `json:"tenant"`
	Service string `json:"service"`
	Node    string `json:"node"`
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
	SentAt  string `json:"sent_at"`
	At      string `json:"at"`
}

const (
	anchorSigBegin = "-----BEGIN CORE0 ANCHOR SIGNATURE-----"
	anchorSigEnd   = "-----END CORE0 ANCHOR SIGNATURE-----"
)

func anchorBody(anchors []Anchor) ([]byte, error) {
	var b bytes.Buffer
	for _, a := range anchors {
		line, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// ComposeAnchorMail builds a plain text mail holding the anchors, a signature
// over them made with signer, and the certificate of that key.
func ComposeAnchorMail(from, to, subject string, at time.Time, anchors []Anchor, signer crypto.Signer, certPEM []byte) ([]byte, error) {
	body, err := anchorBody(anchors)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var id [8]byte
	rand.Read(id[:])
	var m bytes.Buffer
	fmt.Fprintf(&m, "From: %s\nTo: %s\nSubject: %s\nDate: %s\nMessage-ID: <core0-anchors-%d-%x@core0>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 7bit\nX-Core0-Anchors: 1\n\n",
		from, to, subject, at.UTC().Format(time.RFC1123Z), at.Unix(), id)
	m.Write(body)
	fmt.Fprintf(&m, "%s\n%s\n%s\n", anchorSigBegin, base64.StdEncoding.EncodeToString(sig), anchorSigEnd)
	m.Write(bytes.TrimSpace(certPEM))
	m.WriteByte('\n')
	return bytes.ReplaceAll(m.Bytes(), []byte("\n"), []byte("\r\n")), nil
}

// ParseAnchorMail reads the anchors out of a mail made by ComposeAnchorMail and
// checks their signature against the certificate in the mail, which it returns
// for the caller to judge.
func ParseAnchorMail(raw []byte) ([]Anchor, *x509.Certificate, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(text, "\n\n")
	if i < 0 {
		return nil, nil, errors.New("not a mail: no body")
	}
	lines := strings.Split(text[i+2:], "\n")
	var body bytes.Buffer
	var anchors []Anchor
	k := 0
	for ; k < len(lines); k++ {
		l := strings.TrimSpace(lines[k])
		if l == anchorSigBegin {
			break
		}
		if l == "" {
			continue
		}
		var a Anchor
		if err := json.Unmarshal([]byte(l), &a); err != nil {
			return nil, nil, fmt.Errorf("line %q is not an anchor", l)
		}
		anchors = append(anchors, a)
		body.WriteString(l)
		body.WriteByte('\n')
	}
	if k+2 >= len(lines) || strings.TrimSpace(lines[k+2]) != anchorSigEnd {
		return nil, nil, errors.New("no anchor signature")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[k+1]))
	if err != nil {
		return nil, nil, errors.New("anchor signature is not base64")
	}
	block, _ := pem.Decode([]byte(strings.Join(lines[k+3:], "\n")))
	if block == nil {
		return nil, nil, errors.New("no certificate after the signature")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("certificate key is not ECDSA")
	}
	digest := sha256.Sum256(body.Bytes())
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, nil, errors.New("anchor signature does not match the anchors")
	}
	if len(anchors) == 0 {
		return nil, nil, errors.New("the mail holds no anchors")
	}
	return anchors, cert, nil
}

// SplitMbox splits an mbox file into its messages.
func SplitMbox(data []byte) [][]byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	var out [][]byte
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, []byte(strings.Join(cur, "\n")))
		}
		cur = nil
	}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "From ") {
			flush()
			continue
		}
		cur = append(cur, l)
	}
	flush()
	return out
}
