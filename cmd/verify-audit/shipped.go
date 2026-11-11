package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/obsydia-tech/verify-audit/internal/audit"
)

type shippedStream struct {
	batches []*audit.Batch
	times   []time.Time
	beats   int
}

func runShipped(args []string) int {
	fl := flag.NewFlagSet("shipped", flag.ExitOnError)
	idPath := fl.String("identity", "", "age identity file that opens the shipped copy")
	caPath := fl.String("ca", "", "Core0 CA certificate (PEM) the batch certificates must chain to")
	maxGap := fl.Duration("max-gap", 2*time.Minute, "longest silence allowed in a stream")
	anchorsPath := fl.String("anchors", "", "mailbox (.mbox file) or directory of .eml files with the hourly anchor mails")
	fl.Parse(args)
	if fl.NArg() != 1 || *idPath == "" {
		fmt.Println("usage: verify-audit shipped -identity <age key file> [-ca <Core0 CA PEM>] <shipped copy directory>")
		return 2
	}
	idFile, err := os.Open(*idPath)
	if err != nil {
		fmt.Println("ERROR:", err)
		return 2
	}
	ids, err := age.ParseIdentities(idFile)
	idFile.Close()
	if err != nil {
		fmt.Println("ERROR:", err)
		return 2
	}
	var roots *x509.CertPool
	if *caPath != "" {
		pemData, err := os.ReadFile(*caPath)
		if err != nil {
			fmt.Println("ERROR:", err)
			return 2
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemData) {
			fmt.Println("ERROR: no certificate in", *caPath)
			return 2
		}
	}

	streams := map[string]*shippedStream{}
	var problems []string
	problem := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	type anchorRef struct {
		a    audit.Anchor
		mail string
	}
	var anchorRefs []anchorRef
	wanted := map[string]map[uint64]bool{}
	found := map[string]string{}
	mails := 0
	if *anchorsPath != "" {
		msgs, err := loadAnchorMails(*anchorsPath)
		if err != nil {
			fmt.Println("ERROR:", err)
			return 2
		}
		for _, m := range msgs {
			mails++
			list, cert, err := audit.ParseAnchorMail(m.data)
			if err != nil {
				problem("%s: %v", m.name, err)
				continue
			}
			if roots != nil {
				if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
					problem("%s: anchor certificate not issued by this Core0: %v", m.name, err)
					continue
				}
			}
			if cert.Subject.CommonName != "audit-shipper" {
				problem("%s: anchors signed by %q, not by the audit collector", m.name, cert.Subject.CommonName)
				continue
			}
			for _, a := range list {
				k := a.Service + "/" + a.Node
				if wanted[k] == nil {
					wanted[k] = map[uint64]bool{}
				}
				wanted[k][a.Seq] = true
				anchorRefs = append(anchorRefs, anchorRef{a: a, mail: m.name})
			}
		}
	}
	files := 0
	err = filepath.WalkDir(fl.Arg(0), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".jsonl.age") {
			return nil
		}
		files++
		name := filepath.Base(p)
		f, err := os.Open(p)
		if err != nil {
			problem("%s: %v", name, err)
			return nil
		}
		defer f.Close()
		r, err := age.Decrypt(f, ids...)
		if err != nil {
			problem("%s: cannot be opened with this key: %v", name, err)
			return nil
		}
		var b audit.Batch
		if err := json.NewDecoder(r).Decode(&b); err != nil {
			problem("%s: not a batch: %v", name, err)
			return nil
		}
		cert, err := b.VerifySignature()
		if err != nil {
			problem("%s: %v", name, err)
			return nil
		}
		if roots != nil {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				problem("%s: certificate not issued by this Core0: %v", name, err)
				return nil
			}
		}
		if cert.Subject.CommonName != b.Service {
			problem("%s: signed by %q but claims to be %q", name, cert.Subject.CommonName, b.Service)
			return nil
		}
		key := b.Service + "/" + b.Node
		st := streams[key]
		if st == nil {
			st = &shippedStream{}
			streams[key] = st
		}
		if t, err := time.Parse(time.RFC3339Nano, b.SentAt); err == nil {
			st.times = append(st.times, t)
		}
		if len(b.Entries) == 0 {
			st.beats++
			return nil
		}
		st.batches = append(st.batches, &b)
		return nil
	})
	if err != nil {
		fmt.Println("ERROR:", err)
		return 2
	}

	keys := make([]string, 0, len(streams))
	for k := range streams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("files=%d streams=%d\n", files, len(keys))
	for _, k := range keys {
		st := streams[k]
		sort.Slice(st.batches, func(i, j int) bool { return st.batches[i].FromSeq < st.batches[j].FromSeq })
		var lastSeq, firstSeq uint64
		var lastHash string
		entries := 0
		deletedUpTo := map[uint64]bool{}
		for _, b := range st.batches {
			if lastSeq > 0 && b.FromSeq > lastSeq+1 {
				problem("%s: entries %d-%d are missing from the copy", k, lastSeq+1, b.FromSeq-1)
			}
			for _, raw := range b.Entries {
				var e audit.Entry
				if err := json.Unmarshal([]byte(raw), &e); err != nil {
					problem("%s: an entry of batch %d-%d is not an audit entry", k, b.FromSeq, b.ToSeq)
					continue
				}
				if e.Seq <= lastSeq {
					continue
				}
				if lastSeq > 0 && e.Seq == lastSeq+1 && e.PrevHash != lastHash {
					problem("%s: chain broken at seq %d", k, e.Seq)
				}
				if e.Event == audit.ArchiveDeletedEvent {
					if last, err := strconv.ParseUint(e.Detail["last_seq"], 10, 64); err == nil {
						deletedUpTo[last] = true
					}
				}
				if firstSeq == 0 {
					firstSeq = e.Seq
				}
				sum := sha256.Sum256([]byte(raw))
				lastHash = hex.EncodeToString(sum[:])
				if wanted[k][e.Seq] {
					found[fmt.Sprintf("%s#%d", k, e.Seq)] = lastHash
				}
				lastSeq = e.Seq
				entries++
			}
		}
		if firstSeq > 1 && !deletedUpTo[firstSeq-1] {
			problem("%s: the copy starts at seq %d and holds no record of the deletion of the archive ending at seq %d", k, firstSeq, firstSeq-1)
		}
		sort.Slice(st.times, func(i, j int) bool { return st.times[i].Before(st.times[j]) })
		for i := 1; i < len(st.times); i++ {
			if gap := st.times[i].Sub(st.times[i-1]); gap > *maxGap {
				problem("%s: silent for %s, from %s to %s", k, gap.Round(time.Second), st.times[i-1].UTC().Format(time.RFC3339), st.times[i].UTC().Format(time.RFC3339))
			}
		}
		span := ""
		if len(st.times) > 0 {
			span = fmt.Sprintf(" %s..%s", st.times[0].UTC().Format("15:04:05"), st.times[len(st.times)-1].UTC().Format("15:04:05"))
		}
		fmt.Printf("  %-22s entries=%d seq=%d..%d batches=%d heartbeats=%d%s\n", k, entries, firstSeq, lastSeq, len(st.batches), st.beats, span)
	}
	for _, r := range anchorRefs {
		k := r.a.Service + "/" + r.a.Node
		got, ok := found[fmt.Sprintf("%s#%d", k, r.a.Seq)]
		switch {
		case !ok:
			problem("%s: anchored entry %s seq %d is not in the copy", r.mail, k, r.a.Seq)
		case got != r.a.Hash:
			problem("%s: entry %s seq %d differs from its anchor", r.mail, k, r.a.Seq)
		}
	}
	if *anchorsPath != "" {
		fmt.Printf("anchor mails=%d anchors=%d\n", mails, len(anchorRefs))
	}
	for _, p := range problems {
		fmt.Println("  " + p)
	}
	if len(problems) > 0 {
		fmt.Printf("SHIPPED COPY HAS %d PROBLEMS\n", len(problems))
		return 1
	}
	fmt.Println("SHIPPED COPY OK")
	return 0
}

type anchorMail struct {
	name string
	data []byte
}

func loadAnchorMails(p string) ([]anchorMail, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	var out []anchorMail
	if st.IsDir() {
		err := filepath.WalkDir(p, func(f string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(strings.ToLower(f), ".eml") {
				return nil
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			out = append(out, anchorMail{name: filepath.Base(f), data: data})
			return nil
		})
		return out, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(data), "From ") || strings.Contains(string(data), "\nFrom ") {
		for i, m := range audit.SplitMbox(data) {
			if strings.Contains(string(m), "X-Core0-Anchors:") {
				out = append(out, anchorMail{name: fmt.Sprintf("%s#%d", filepath.Base(p), i+1), data: m})
			}
		}
		return out, nil
	}
	return []anchorMail{{name: filepath.Base(p), data: data}}, nil
}
