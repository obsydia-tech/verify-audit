package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var genesisHash = strings.Repeat("0", 64)

// RecoveryEvent is the event of the entry appended after a damaged tail was set aside.
const RecoveryEvent = "audit_recovery"

// Entry is a single audit log entry. Each entry carries the hash of the previous one.
type Entry struct {
	Seq      uint64            `json:"seq"`
	PrevHash string            `json:"prev_hash"`
	TS       time.Time         `json:"ts"`
	Path     []string          `json:"path"`
	Latency  map[string]int64  `json:"latency_ms,omitempty"`
	Event    string            `json:"event"`
	ActorID  string            `json:"actor_id,omitempty"`
	TenantID string            `json:"tenant_id,omitempty"`
	KeyID    string            `json:"key_id,omitempty"`
	Result   string            `json:"result"`
	Error    string            `json:"error,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// Logger is a tamper-evident append-only audit logger. Every entry is on disk before Log returns.
type Logger struct {
	failSince  time.Time
	firstErr   error
	lastTry    time.Time
	lastReport time.Time
	lost       uint64
	refused    uint64

	mu       sync.Mutex
	file     *os.File
	size     int64
	seq      uint64
	prevHash string
	node     string
	lastErr  error

	path         string
	lastDay      string
	firstSeq     uint64
	rotateFailAt time.Time
	shipped      func() uint64
	recent       []Line
	notify       chan struct{}
}

type chainPos struct {
	seq  uint64
	hash string
	ts   time.Time
}

// New opens the audit log at path and resumes the chain from the last valid entry.
// Anything after that entry is moved to path.torn-TIMESTAMP and recorded in the chain.
func New(path string, node string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	l := &Logger{file: f, node: node, prevHash: genesisHash, path: path}
	detail, err := l.recoverTail(path)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("recover audit log: %w", err)
	}
	l.loadFileStart()
	if detail != nil {
		if err := l.Log(RecoveryEvent, "ok", WithActor("system"), WithDetail(detail)); err != nil {
			f.Close()
			return nil, fmt.Errorf("record audit recovery: %w", err)
		}
	}
	return l, nil
}

func (l *Logger) recoverTail(path string) (map[string]string, error) {
	st, err := l.file.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	end, last, err := lastEntry(l.file, size)
	if err != nil {
		return nil, err
	}
	if last != nil {
		l.seq = last.seq
		l.prevHash = last.hash
		l.lastDay = last.ts.UTC().Format(dayLayout)
	}
	l.size = end
	if end == size {
		return nil, nil
	}
	tail := make([]byte, size-end)
	if _, err := l.file.ReadAt(tail, end); err != nil {
		return nil, err
	}
	name, err := setAside(path, tail)
	if err != nil {
		return nil, err
	}
	if err := l.file.Truncate(end); err != nil {
		return nil, err
	}
	if err := l.file.Sync(); err != nil {
		return nil, err
	}
	syncDir(filepath.Dir(path))
	sum := sha256.Sum256(tail)
	return map[string]string{
		"bytes":     strconv.Itoa(len(tail)),
		"nul_bytes": strconv.Itoa(bytes.Count(tail, []byte{0})),
		"sha256":    hex.EncodeToString(sum[:]),
		"file":      filepath.Base(name),
	}, nil
}

func lastEntry(f *os.File, size int64) (int64, *chainPos, error) {
	window := int64(64 * 1024)
	for {
		start := size - window
		if start < 0 {
			start = 0
		}
		buf := make([]byte, size-start)
		if _, err := f.ReadAt(buf, start); err != nil {
			return 0, nil, err
		}
		i := bytes.LastIndexByte(buf, '\n')
		for i >= 0 {
			prev := bytes.LastIndexByte(buf[:i], '\n')
			if prev < 0 && start > 0 {
				break
			}
			line := buf[prev+1 : i]
			if e, ok := parseEntry(line); ok {
				h := sha256.Sum256(line)
				return start + int64(i) + 1, &chainPos{seq: e.Seq, hash: hex.EncodeToString(h[:]), ts: e.TS}, nil
			}
			i = prev
		}
		if start == 0 {
			return 0, nil, nil
		}
		window *= 4
	}
}

func parseEntry(line []byte) (*Entry, bool) {
	if len(line) == 0 || line[0] != '{' {
		return nil, false
	}
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return nil, false
	}
	if e.Seq == 0 || len(e.PrevHash) != 64 {
		return nil, false
	}
	return &e, true
}

func setAside(path string, data []byte) (string, error) {
	base := path + ".torn-" + time.Now().UTC().Format("20060102T150405Z")
	name := base
	for n := 1; ; n++ {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(err, os.ErrExist) {
			name = base + "-" + strconv.Itoa(n)
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return "", err
		}
		return name, f.Close()
	}
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

func fdatasync(f *os.File) error {
	for {
		err := syscall.Fdatasync(int(f.Fd()))
		if err != syscall.EINTR {
			return err
		}
	}
}

// UnavailableMarker is carried in the error a service returns when it refuses
// an operation because its audit log cannot be written.
const UnavailableMarker = "audit_unavailable"

var (
	retryInterval  = time.Second
	reportInterval = 30 * time.Second
)

// Log appends one entry and returns only after it is on disk.
// On error nothing is added to the chain and the file is cut back to the last good entry.
// While the log cannot be written, a write is retried at most once per retryInterval and
// the first entry after the gap is an audit_resumed entry that describes it.
func (l *Logger) Log(event, result string, opts ...func(*Entry)) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.resume(); err != nil {
		l.lost++
		l.report()
		return err
	}
	if err := l.write(event, result, opts...); err != nil {
		return l.fail(err)
	}
	return nil
}

func (l *Logger) write(event, result string, opts ...func(*Entry)) error {
	ts := nowUTC()
	l.maybeRotate(ts)
	return l.appendEntry(ts, event, result, opts...)
}

func (l *Logger) appendEntry(ts time.Time, event, result string, opts ...func(*Entry)) error {
	e := &Entry{
		Seq:      l.seq + 1,
		PrevHash: l.prevHash,
		TS:       ts,
		Path:     []string{l.node},
		Event:    event,
		Result:   result,
	}
	for _, opt := range opts {
		opt(e)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	h := sha256.Sum256(data)
	line := make([]byte, 0, len(data)+1)
	line = append(line, data...)
	line = append(line, '\n')

	if _, err := l.file.WriteAt(line, l.size); err != nil {
		l.file.Truncate(l.size)
		return fmt.Errorf("write audit log: %w", err)
	}
	if err := fdatasync(l.file); err != nil {
		l.file.Truncate(l.size)
		return fmt.Errorf("sync audit log: %w", err)
	}

	if l.size == 0 {
		l.firstSeq = e.Seq
	}
	l.seq = e.Seq
	l.prevHash = hex.EncodeToString(h[:])
	l.size += int64(len(line))
	l.lastDay = ts.Format(dayLayout)
	if l.notify != nil {
		l.recent = append(l.recent, Line{Raw: append([]byte(nil), data...), Entry: e})
		if len(l.recent) > ringSize {
			l.recent = l.recent[len(l.recent)-ringSize:]
		}
		select {
		case l.notify <- struct{}{}:
		default:
		}
	}
	return nil
}

func (l *Logger) fail(err error) error {
	now := time.Now()
	if l.lastErr == nil {
		l.failSince = now
		l.firstErr = err
		l.lastReport = now
		fmt.Fprintf(os.Stderr, "[audit] %s: audit log is not writable, writes are refused until it recovers: %v\n", l.node, err)
	}
	l.lastErr = err
	l.lastTry = now
	l.lost++
	return err
}

func (l *Logger) resume() error {
	if l.lastErr == nil {
		return nil
	}
	now := time.Now()
	if now.Sub(l.lastTry) < retryInterval {
		return l.lastErr
	}
	l.lastTry = now
	detail := map[string]string{
		"since":          l.failSince.UTC().Format(time.RFC3339Nano),
		"first_error":    l.firstErr.Error(),
		"entries_lost":   fmt.Sprintf("%d", l.lost),
		"writes_refused": fmt.Sprintf("%d", l.refused),
	}
	if err := l.write("audit_resumed", "ok", WithActor("system"), WithDetail(detail)); err != nil {
		l.lastErr = err
		return err
	}
	fmt.Fprintf(os.Stderr, "[audit] %s: audit log is writable again after %s: %d entries lost, %d writes refused\n",
		l.node, now.Sub(l.failSince).Round(time.Millisecond), l.lost, l.refused)
	l.lastErr = nil
	l.firstErr = nil
	l.lost = 0
	l.refused = 0
	return nil
}

func (l *Logger) report() {
	now := time.Now()
	if now.Sub(l.lastReport) < reportInterval {
		return
	}
	l.lastReport = now
	fmt.Fprintf(os.Stderr, "[audit] %s: audit log still not writable since %s: %d entries lost, %d writes refused: %v\n",
		l.node, l.failSince.UTC().Format(time.RFC3339), l.lost, l.refused, l.lastErr)
}

// Ready reports whether a write operation may go ahead. A refused write is
// counted and reported in the audit_resumed entry.
func (l *Logger) Ready() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.resume(); err != nil {
		l.refused++
		l.report()
		return err
	}
	return nil
}

// Probe retries a log that cannot be written without counting a refused write.
func (l *Logger) Probe() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.resume()
}

// Err returns the error of the last Log call, nil after a successful one.
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func WithTenant(id string) func(*Entry) {
	return func(e *Entry) { e.TenantID = id }
}

func WithKey(id string) func(*Entry) {
	return func(e *Entry) { e.KeyID = id }
}

func WithActor(id string) func(*Entry) {
	return func(e *Entry) { e.ActorID = id }
}

func WithPath(path []string) func(*Entry) {
	return func(e *Entry) { e.Path = path }
}

func WithLatency(latency map[string]int64) func(*Entry) {
	return func(e *Entry) { e.Latency = latency }
}

func WithError(err error) func(*Entry) {
	return func(e *Entry) {
		if err != nil {
			e.Error = err.Error()
		}
	}
}

func WithDetail(detail map[string]string) func(*Entry) {
	return func(e *Entry) { e.Detail = detail }
}

// Report is the result of reading a whole audit log.
type Report struct {
	Entries      int
	Segments     int
	BadLines     int
	Recoveries   int
	TailBytes    int
	ProblemCount int
	Problems     []string
	Archives     int
	Duplicates   int
	StartSeq     uint64
}

type chainState struct {
	hash   string
	seq    uint64
	linked bool
}

// Clean reports whether the log is one unbroken chain with no damaged lines.
func (r *Report) Clean() bool {
	return r.ProblemCount == 0
}

func (r *Report) String() string {
	return fmt.Sprintf("entries=%d segments=%d bad_lines=%d recoveries=%d tail_bytes=%d problems=%d",
		r.Entries, r.Segments, r.BadLines, r.Recoveries, r.TailBytes, r.ProblemCount)
}

func (r *Report) problem(format string, a ...any) {
	r.ProblemCount++
	if len(r.Problems) < 20 {
		r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
	}
}

func (r *Report) check(n int, line []byte, st *chainState) {
	e, ok := parseEntry(line)
	if !ok {
		r.BadLines++
		r.problem("line %d: not an audit entry (%d bytes, %d NUL)", n, len(line), bytes.Count(line, []byte{0}))
		st.linked = false
		return
	}
	if st.linked && e.PrevHash == st.hash && e.Seq == st.seq+1 {
		if r.Segments == 0 {
			r.Segments = 1
		}
	} else {
		r.Segments++
		if e.Seq == 1 && e.PrevHash == genesisHash {
			r.problem("line %d: chain restarted at seq 1", n)
		} else {
			r.problem("line %d: chain broken at seq %d", n, e.Seq)
		}
	}
	if e.Event == RecoveryEvent {
		r.Recoveries++
	}
	r.Entries++
	h := sha256.Sum256(line)
	st.hash = hex.EncodeToString(h[:])
	st.seq = e.Seq
	st.linked = true
}

// Inspect reads the whole log and reports every break instead of stopping at the first one.
func Inspect(path string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read log: %w", err)
	}
	defer f.Close()

	r := &Report{}
	st := &chainState{hash: genesisHash, linked: true}
	rd := bufio.NewReaderSize(f, 1<<20)
	n := 0
	for {
		line, rerr := rd.ReadBytes('\n')
		if rerr != nil && rerr != io.EOF {
			return nil, fmt.Errorf("read log: %w", rerr)
		}
		switch {
		case len(line) == 0:
		case line[len(line)-1] != '\n':
			r.TailBytes = len(line)
			r.problem("unterminated tail of %d bytes", len(line))
		default:
			n++
			line = line[:len(line)-1]
			if len(line) > 0 {
				r.check(n, line, st)
			}
		}
		if rerr == io.EOF {
			break
		}
	}
	return r, nil
}

// Verify returns an error when the log is not one unbroken chain.
func Verify(path string) error {
	r, err := Inspect(path)
	if err != nil {
		return err
	}
	if r.Clean() {
		return nil
	}
	return fmt.Errorf("%s; first problem: %s", r, r.Problems[0])
}
