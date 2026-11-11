package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const ringSize = 4096

// ShipConfig tells a Logger where to deliver its entries. Creds returns the
// client TLS configuration, the key that signs each batch and the PEM of the
// certificate that goes with that key; it is called for every batch so that a
// renewed certificate is picked up.
type ShipConfig struct {
	URL      string
	Service  string
	Interval time.Duration
	MaxBatch int
	Creds    func() (*tls.Config, crypto.Signer, []byte, error)
}

// Batch is one delivery: a run of consecutive entries, or none at all when it
// only reports the head of the chain.
type Batch struct {
	V        int      `json:"v"`
	Service  string   `json:"service"`
	Node     string   `json:"node"`
	FromSeq  uint64   `json:"from_seq"`
	ToSeq    uint64   `json:"to_seq"`
	HeadSeq  uint64   `json:"head_seq"`
	HeadHash string   `json:"head_hash"`
	SentAt   string   `json:"sent_at"`
	Entries  []string `json:"entries"`
	Cert     string   `json:"cert"`
	Sig      string   `json:"sig"`
}

// Digest covers every field of the batch except the certificate and signature.
func (b *Batch) Digest() []byte {
	h := sha256.New()
	fmt.Fprintf(h, "obsydia-audit-batch-v%d\n%s\n%s\n%d\n%d\n%d\n%s\n%s\n", b.V, b.Service, b.Node, b.FromSeq, b.ToSeq, b.HeadSeq, b.HeadHash, b.SentAt)
	for _, e := range b.Entries {
		io.WriteString(h, e)
		h.Write([]byte{'\n'})
	}
	return h.Sum(nil)
}

func (b *Batch) Sign(signer crypto.Signer, certPEM []byte) error {
	b.Cert = string(certPEM)
	sig, err := signer.Sign(rand.Reader, b.Digest(), crypto.SHA256)
	if err != nil {
		return err
	}
	b.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifySignature checks the signature against the certificate carried in
// the batch and returns that certificate. Whether the certificate is to be
// trusted is for the caller to decide.
func (b *Batch) VerifySignature() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(b.Cert))
	if block == nil {
		return nil, errors.New("no certificate in the batch")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return nil, errors.New("signature is not base64")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, b.Digest(), sig) {
		return nil, errors.New("signature does not match the batch")
	}
	return cert, nil
}

// PEMCreds builds ShipConfig.Creds from a function that loads the service's
// certificate, key and CA in PEM.
func PEMCreds(load func() ([]byte, []byte, []byte, error), serverName string) func() (*tls.Config, crypto.Signer, []byte, error) {
	return func() (*tls.Config, crypto.Signer, []byte, error) {
		certPEM, keyPEM, caPEM, err := load()
		if err != nil {
			return nil, nil, nil, err
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, nil, err
		}
		signer, ok := pair.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, nil, nil, errors.New("the certificate key cannot sign")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, nil, errors.New("no CA certificate")
		}
		return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13}, signer, certPEM, nil
	}
}

type shipper struct {
	l          *Logger
	cfg        ShipConfig
	cursorPath string
	cursor     atomic.Uint64
	lastReport time.Time
	dest       string
}

const DestinationHeader = "X-Core0-Destination"

var errDestinationChanged = errors.New("the collector reports a new destination")

func readCursor(path string) uint64 {
	v, _ := readShipState(path)
	return v
}

func readShipState(path string) (uint64, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, ""
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, ""
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, ""
	}
	if len(fields) > 1 {
		return v, fields[1]
	}
	return v, ""
}

func writeCursor(path string, v uint64, dest string) error {
	line := strconv.FormatUint(v, 10)
	if dest != "" {
		line += " " + dest
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(line+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StartShipping delivers every entry of the log, from the last one the
// collector acknowledged, in batches. It never holds up Log: while the
// collector cannot be reached the entries wait on disk. The acknowledged
// position is kept next to the log and also decides which archives retention
// may delete.
func (l *Logger) StartShipping(ctx context.Context, cfg ShipConfig) error {
	if cfg.URL == "" || cfg.Service == "" || cfg.Creds == nil {
		return errors.New("audit shipping needs a URL, a service name and credentials")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 100
	}
	s := &shipper{l: l, cfg: cfg, cursorPath: l.path + ".shipped"}
	seq, dest := readShipState(s.cursorPath)
	s.cursor.Store(seq)
	s.dest = dest
	l.mu.Lock()
	l.notify = make(chan struct{}, 1)
	if s.cursor.Load() > 0 {
		l.shipped = s.cursor.Load
	}
	l.mu.Unlock()
	go s.run(ctx)
	return nil
}

func (l *Logger) head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.prevHash
}

func (l *Logger) backlog(after uint64) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seq <= after {
		return 0
	}
	return l.seq - after
}

func (l *Logger) pending(after uint64, max int) ([]Line, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seq <= after {
		return nil, true
	}
	if len(l.recent) == 0 || l.recent[0].Entry.Seq > after+1 {
		return nil, false
	}
	var out []Line
	for _, ln := range l.recent {
		if ln.Entry.Seq > after {
			out = append(out, ln)
			if len(out) == max {
				break
			}
		}
	}
	return out, true
}

func (s *shipper) run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	s.flush(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.flush(ctx, true)
		case <-s.l.notify:
			if s.l.backlog(s.cursor.Load()) >= uint64(s.cfg.MaxBatch) {
				s.flush(ctx, false)
			}
		}
	}
}

func (s *shipper) flush(ctx context.Context, beat bool) {
	for round := 0; round < 1000; round++ {
		if ctx.Err() != nil {
			return
		}
		after := s.cursor.Load()
		lines, ok := s.l.pending(after, s.cfg.MaxBatch)
		if !ok {
			var err error
			if lines, err = s.fromDisk(after); err != nil {
				s.report(err)
				return
			}
		}
		if len(lines) == 0 {
			if beat {
				err := s.send(ctx, nil)
				if errors.Is(err, errDestinationChanged) {
					continue
				}
				if err != nil {
					s.report(err)
				}
			}
			return
		}
		if err := s.send(ctx, lines); err != nil {
			if errors.Is(err, errDestinationChanged) {
				continue
			}
			s.report(err)
			return
		}
		beat = false
		if len(lines) < s.cfg.MaxBatch {
			return
		}
	}
}

func (s *shipper) fromDisk(after uint64) ([]Line, error) {
	var out []Line
	_, err := ScanForward(s.l.path, Query{AfterSeq: after, Limit: s.cfg.MaxBatch}, func(ln Line) error {
		out = append(out, Line{Raw: append([]byte(nil), ln.Raw...), Entry: ln.Entry})
		return nil
	})
	return out, err
}

func (s *shipper) send(ctx context.Context, lines []Line) error {
	tlsCfg, signer, certPEM, err := s.cfg.Creds()
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	headSeq, headHash := s.l.head()
	b := Batch{V: 1, Service: s.cfg.Service, Node: s.l.node, HeadSeq: headSeq, HeadHash: headHash, SentAt: nowUTC().Format(time.RFC3339Nano)}
	if len(lines) > 0 {
		b.FromSeq = lines[0].Entry.Seq
		b.ToSeq = lines[len(lines)-1].Entry.Seq
		b.Entries = make([]string, len(lines))
		for i, ln := range lines {
			b.Entries[i] = string(ln.Raw)
		}
	} else {
		b.FromSeq = headSeq + 1
		b.ToSeq = headSeq
	}
	if err := b.Sign(signer, certPEM); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	body, err := json.Marshal(&b)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.cfg.URL, "/")+"/v1/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.dest != "" {
		req.Header.Set(DestinationHeader, s.dest)
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	dest := resp.Header.Get(DestinationHeader)
	if resp.StatusCode == http.StatusConflict && dest != "" && dest != s.dest {
		if err := writeCursor(s.cursorPath, 0, dest); err != nil {
			return fmt.Errorf("save shipped position: %w", err)
		}
		s.cursor.Store(0)
		s.dest = dest
		fmt.Fprintf(os.Stderr, "[audit] %s: collector destination changed to %s, resending the whole log from seq 1\n", s.l.node, dest)
		return errDestinationChanged
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("collector answered %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var ack struct {
		AckedSeq uint64 `json:"acked_seq"`
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return fmt.Errorf("collector answer: %w", err)
	}
	if dest != "" && dest != s.dest {
		if err := writeCursor(s.cursorPath, s.cursor.Load(), dest); err != nil {
			return fmt.Errorf("save shipped position: %w", err)
		}
		s.dest = dest
	}
	if len(lines) == 0 {
		return nil
	}
	if ack.AckedSeq != b.ToSeq {
		return fmt.Errorf("collector acknowledged %d, sent up to %d", ack.AckedSeq, b.ToSeq)
	}
	if err := writeCursor(s.cursorPath, b.ToSeq, s.dest); err != nil {
		return fmt.Errorf("save shipped position: %w", err)
	}
	s.cursor.Store(b.ToSeq)
	s.l.mu.Lock()
	if s.l.shipped == nil {
		s.l.shipped = s.cursor.Load
	}
	s.l.mu.Unlock()
	return nil
}

func (s *shipper) report(err error) {
	now := time.Now()
	if now.Sub(s.lastReport) < time.Minute {
		return
	}
	s.lastReport = now
	fmt.Fprintf(os.Stderr, "[audit] %s: shipping to %s failed, %d entries waiting: %v\n", s.l.node, s.cfg.URL, s.l.backlog(s.cursor.Load()), err)
}
