package main

import (
	"fmt"
	"os"

	"github.com/obsydia-tech/verify-audit/internal/audit"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "shipped" {
		os.Exit(runShipped(os.Args[2:]))
	}
	if len(os.Args) < 2 {
		fmt.Println("usage: verify-audit <audit log path>   (its archives next to it are read too)")
		fmt.Println("       verify-audit shipped -identity <age key file> [-ca <Core0 CA PEM>] <shipped copy directory>")
		os.Exit(2)
	}
	r, err := audit.InspectSet(os.Args[1])
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}
	fmt.Println(r)
	fmt.Printf("archives=%d duplicates=%d start_seq=%d\n", r.Archives, r.Duplicates, r.StartSeq)
	for _, p := range r.Problems {
		fmt.Println("  " + p)
	}
	if r.ProblemCount > len(r.Problems) {
		fmt.Printf("  ... and %d more\n", r.ProblemCount-len(r.Problems))
	}
	if !r.Clean() {
		fmt.Println("BROKEN")
		os.Exit(1)
	}
	fmt.Println("CHAIN OK")
}
