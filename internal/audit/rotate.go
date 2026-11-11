package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// RotatedEvent opens every file after a rotation and records the archive it closed.
	RotatedEvent = "audit_rotated"
	// ArchiveDeletedEvent records an archive removed at the end of its retention.
	ArchiveDeletedEvent = "audit_archive_deleted"
	dayLayout           = "2006-01-02"
)

var (
	nowUTC      = func() time.Time { return time.Now().UTC() }
	retention   = 90 * 24 * time.Hour
	rotateRetry = time.Minute
)

// Archive is one rotated day of the log, compressed.
type Archive struct {
	Path     string
	Day      string
	FirstSeq uint64
	LastSeq  uint64
}

func archivePrefix(path string) string {
	return strings.TrimSuffix(path, ".log") + "-"
}

// Archives lists the archives of the log at path, oldest first.
func Archives(path string) ([]Archive, error) {
	prefix := archivePrefix(path)
	matches, err := filepath.Glob(prefix + "*.log.gz")
	if err != nil {
		return nil, err
	}
	var out []Archive
	for _, m := range matches {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(m, prefix), ".log.gz"), "-")
		if len(parts) != 5 {
			continue
		}
		first, err1 := strconv.ParseUint(parts[3], 10, 64)
		last, err2 := strconv.ParseUint(parts[4], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Archive{Path: m, Day: parts[0] + "-" + parts[1] + "-" + parts[2], FirstSeq: first, LastSeq: last})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeq < out[j].FirstSeq })
	return out, nil
}

// SetShipped makes retention keep every archive that holds entries above the
// sequence fn reports as delivered to the external copy.
func (l *Logger) SetShipped(fn func() uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.shipped = fn
}

func (l *Logger) loadFileStart() {
	if l.size == 0 {
		return
	}
	n := int64(1 << 20)
	if n > l.size {
		n = l.size
	}
	buf := make([]byte, n)
	got, _ := l.file.ReadAt(buf, 0)
	buf = buf[:got]
	i := bytes.IndexByte(buf, '\n')
	if i < 0 {
		return
	}
	if e, ok := parseEntry(buf[:i]); ok {
		l.firstSeq = e.Seq
		if l.lastDay == "" {
			l.lastDay = e.TS.UTC().Format(dayLayout)
		}
	}
}

func (l *Logger) maybeRotate(ts time.Time) {
	today := ts.Format(dayLayout)
	if l.path == "" || l.lastDay == "" || today <= l.lastDay {
		return
	}
	if !l.rotateFailAt.IsZero() && ts.Sub(l.rotateFailAt) < rotateRetry {
		return
	}
	if err := l.rotate(ts); err != nil {
		l.rotateFailAt = ts
		fmt.Fprintf(os.Stderr, "[audit] %s: rotation failed, writing on in the current file: %v\n", l.node, err)
		return
	}
	l.rotateFailAt = time.Time{}
	l.prune(ts)
}

func (l *Logger) rotate(ts time.Time) error {
	if l.size == 0 {
		return nil
	}
	name := fmt.Sprintf("%s%s-%012d-%012d.log.gz", archivePrefix(l.path), l.lastDay, l.firstSeq, l.seq)
	tmp := name + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	zw := gzip.NewWriter(io.MultiWriter(out, h))
	if _, err := io.Copy(zw, io.NewSectionReader(l.file, 0, l.size)); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		os.Remove(tmp)
		return err
	}
	next := l.path + ".next"
	nf, err := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := os.Rename(next, l.path); err != nil {
		nf.Close()
		os.Remove(next)
		return err
	}
	syncDir(filepath.Dir(l.path))
	old := l.file
	l.file = nf
	old.Close()
	closedLast, closedBytes := l.seq, l.size
	l.size = 0
	l.firstSeq = 0
	return l.appendEntry(ts, RotatedEvent, "ok", WithActor("system"), WithDetail(map[string]string{
		"archive":  filepath.Base(name),
		"sha256":   hex.EncodeToString(h.Sum(nil)),
		"last_seq": strconv.FormatUint(closedLast, 10),
		"bytes":    strconv.FormatInt(closedBytes, 10),
	}))
}

func (l *Logger) prune(ts time.Time) {
	arcs, err := Archives(l.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit] %s: list archives: %v\n", l.node, err)
		return
	}
	cutoff := ts.Add(-retention).Format(dayLayout)
	var shipped uint64
	haveShip := l.shipped != nil
	if haveShip {
		shipped = l.shipped()
	}
	removed := false
	for _, a := range arcs {
		if a.Day >= cutoff || (haveShip && a.LastSeq > shipped) {
			continue
		}
		if err := l.appendEntry(ts, ArchiveDeletedEvent, "ok", WithActor("system"), WithDetail(map[string]string{
			"archive":   filepath.Base(a.Path),
			"first_seq": strconv.FormatUint(a.FirstSeq, 10),
			"last_seq":  strconv.FormatUint(a.LastSeq, 10),
			"reason":    "retention",
		})); err != nil {
			fmt.Fprintf(os.Stderr, "[audit] %s: retention stopped, the deletion could not be recorded: %v\n", l.node, err)
			return
		}
		if err := os.Remove(a.Path); err != nil {
			fmt.Fprintf(os.Stderr, "[audit] %s: remove %s: %v\n", l.node, filepath.Base(a.Path), err)
			continue
		}
		removed = true
	}
	if removed {
		syncDir(filepath.Dir(l.path))
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// InspectSet reads the log at path together with its archives as one chain.
// It reports an archive whose bytes differ from the hash recorded when it was
// rotated, an archive that is gone without a recorded deletion, and a log that
// starts after entries no recorded deletion accounts for.
func InspectSet(path string) (*Report, error) {
	srcs, err := sources(path)
	if err != nil {
		return nil, err
	}
	r := &Report{}
	st := &chainState{hash: genesisHash, linked: true}
	rotated := map[string]string{}
	deleted := map[string]bool{}
	deletedLast := map[uint64]bool{}
	present := map[string]string{}
	var last uint64
	started := false
	n := 0
	for _, s := range srcs {
		if s.archive {
			sum, err := fileSHA256(s.path)
			if err != nil {
				return nil, err
			}
			present[filepath.Base(s.path)] = sum
			r.Archives++
		}
		ra, size, done, err := openSource(s)
		if errors.Is(err, os.ErrNotExist) && !s.archive {
			continue
		}
		if err != nil {
			r.problem("%s: cannot be read: %v", filepath.Base(s.path), err)
			continue
		}
		err = forwardLines(ra, size, func(line []byte, complete bool) error {
			if !complete {
				r.TailBytes += len(line)
				r.problem("%s: unterminated tail of %d bytes", filepath.Base(s.path), len(line))
				return nil
			}
			n++
			if len(line) == 0 {
				return nil
			}
			e, ok := parseEntry(line)
			if ok && last > 0 && e.Seq <= last {
				r.Duplicates++
				return nil
			}
			if ok && !started {
				started = true
				r.StartSeq = e.Seq
				if e.Seq > 1 {
					st.hash = e.PrevHash
					st.seq = e.Seq - 1
				}
			}
			r.check(n, line, st)
			if !ok {
				return nil
			}
			last = e.Seq
			switch e.Event {
			case RotatedEvent:
				rotated[e.Detail["archive"]] = e.Detail["sha256"]
			case ArchiveDeletedEvent:
				deleted[e.Detail["archive"]] = true
				if v, err := strconv.ParseUint(e.Detail["last_seq"], 10, 64); err == nil {
					deletedLast[v] = true
				}
			}
			return nil
		})
		done()
		if err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(rotated))
	for name := range rotated {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if got, ok := present[name]; ok {
			if got != rotated[name] {
				r.problem("archive %s does not match the hash recorded when it was rotated", name)
			}
		} else if !deleted[name] {
			r.problem("archive %s is missing and its deletion is not recorded", name)
		}
	}
	if r.StartSeq > 1 && !deletedLast[r.StartSeq-1] {
		r.problem("log starts at seq %d and no recorded deletion accounts for the entries before it", r.StartSeq)
	}
	return r, nil
}
