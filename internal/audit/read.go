package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"time"
)

// Query selects audit entries. Empty fields match everything. Entries
// without a tenant (service start, stop, pair events) match every tenant.
type Query struct {
	BeforeSeq uint64
	AfterSeq  uint64
	Limit     int
	TenantID  string
	EventOK   func(event string) bool
	Result    string
	ActorID   string
	KeyID     string
	From      time.Time
	To        time.Time
}

// Line is one entry with the exact bytes it has in the log, so that the
// hash chain can be checked on what is handed out.
type Line struct {
	Raw   []byte
	Entry *Entry
}

func (q *Query) Match(e *Entry) bool {
	if q.TenantID != "" && e.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	if q.EventOK != nil && !q.EventOK(e.Event) {
		return false
	}
	if q.Result != "" && e.Result != q.Result {
		return false
	}
	if q.ActorID != "" && e.ActorID != q.ActorID {
		return false
	}
	if q.KeyID != "" && e.KeyID != q.KeyID {
		return false
	}
	if !q.From.IsZero() && e.TS.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !e.TS.Before(q.To) {
		return false
	}
	return true
}

const readBlock = 64 * 1024

func completeEnd(r io.ReaderAt, size int64) (int64, error) {
	end := size
	for end > 0 {
		start := end - readBlock
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start)
		if _, err := r.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

func backwardLines(r io.ReaderAt, size int64, fn func(line []byte) bool) error {
	end, err := completeEnd(r, size)
	if err != nil {
		return err
	}
	var carry []byte
	for end > 0 {
		start := end - readBlock
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start, end-start+int64(len(carry)))
		if _, err := r.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		buf = append(buf, carry...)
		carry = nil
		if start > 0 {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				carry = buf
				end = start
				continue
			}
			carry = append([]byte(nil), buf[:i+1]...)
			buf = buf[i+1:]
		}
		lines := bytes.Split(bytes.TrimSuffix(buf, []byte{'\n'}), []byte{'\n'})
		for j := len(lines) - 1; j >= 0; j-- {
			if !fn(lines[j]) {
				return nil
			}
		}
		end = start
	}
	return nil
}

func forwardLines(r io.ReaderAt, size int64, fn func(line []byte, complete bool) error) error {
	br := bufio.NewReaderSize(io.NewSectionReader(r, 0, size), 1<<20)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			complete := line[len(line)-1] == '\n'
			if complete {
				line = line[:len(line)-1]
			}
			if err := fn(line, complete); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

type source struct {
	path    string
	archive bool
	first   uint64
	last    uint64
}

func sources(path string) ([]source, error) {
	arcs, err := Archives(path)
	if err != nil {
		return nil, err
	}
	out := make([]source, 0, len(arcs)+1)
	for _, a := range arcs {
		out = append(out, source{path: a.Path, archive: true, first: a.FirstSeq, last: a.LastSeq})
	}
	return append(out, source{path: path}), nil
}

func openSource(s source) (io.ReaderAt, int64, func(), error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, 0, nil, err
	}
	if !s.archive {
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, nil, err
		}
		return f, st.Size(), func() { f.Close() }, nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, 0, nil, err
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, 0, nil, err
	}
	return bytes.NewReader(data), int64(len(data)), func() {}, nil
}

// ReadBackward returns up to q.Limit matching entries, newest first, from the
// log at path and its archives, with a sequence lower than q.BeforeSeq when
// it is set. The second value is the BeforeSeq for the next, older page, or 0
// when nothing older is left. An unterminated last line is an entry still
// being written and is skipped.
func ReadBackward(path string, q Query) ([]Line, uint64, error) {
	srcs, err := sources(path)
	if err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []Line
	var lowest uint64
	for i := len(srcs) - 1; i >= 0; i-- {
		s := srcs[i]
		if s.archive && q.BeforeSeq > 0 && s.first >= q.BeforeSeq {
			continue
		}
		r, size, done, err := openSource(s)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		full := false
		err = backwardLines(r, size, func(line []byte) bool {
			e, ok := parseEntry(line)
			if !ok {
				return true
			}
			if lowest > 0 && e.Seq >= lowest {
				return true
			}
			if q.BeforeSeq > 0 && e.Seq >= q.BeforeSeq {
				return true
			}
			lowest = e.Seq
			if !q.Match(e) {
				return true
			}
			out = append(out, Line{Raw: append([]byte(nil), line...), Entry: e})
			if len(out) == limit {
				full = true
				return false
			}
			return true
		})
		done()
		if err != nil {
			return nil, 0, err
		}
		if full {
			return out, out[len(out)-1].Entry.Seq, nil
		}
	}
	return out, 0, nil
}

var errScanDone = errors.New("scan done")

// ScanForward calls fn for every matching entry of the log at path and its
// archives, oldest first, after q.AfterSeq when it is set and up to q.Limit
// entries when it is set, and returns how many it passed on.
func ScanForward(path string, q Query, fn func(Line) error) (int, error) {
	srcs, err := sources(path)
	if err != nil {
		return 0, err
	}
	n := 0
	var last uint64
	for _, s := range srcs {
		if s.archive && q.AfterSeq > 0 && s.last <= q.AfterSeq {
			continue
		}
		r, size, done, err := openSource(s)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return n, err
		}
		err = forwardLines(r, size, func(line []byte, complete bool) error {
			if !complete {
				return nil
			}
			e, ok := parseEntry(line)
			if !ok || e.Seq <= last {
				return nil
			}
			last = e.Seq
			if e.Seq <= q.AfterSeq || !q.Match(e) {
				return nil
			}
			if err := fn(Line{Raw: line, Entry: e}); err != nil {
				return err
			}
			n++
			if q.Limit > 0 && n >= q.Limit {
				return errScanDone
			}
			return nil
		})
		done()
		if errors.Is(err, errScanDone) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
