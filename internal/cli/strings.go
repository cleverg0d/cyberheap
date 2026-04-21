package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
	"github.com/cleverg0d/cyberheap/internal/scanner"
)

type stringsFlags struct {
	minLen   int
	maxLen   int
	regex    string
	grep     string
	unique   bool
	sortMode string
	format   string
	noBanner bool
	noColor  bool
	include  string // "all" | "utf8" | "instances"
	scan     bool
	limit    int
	ascii    bool
}

// newStringsCmd exposes every Java-resolvable string in a heap dump:
//
//   - STRING_IN_UTF8 records (intern'd class/field/method names and
//     Java string constants)
//   - java.lang.String instances (every runtime-constructed string)
//
// This is what a pentester would use after scan+spider findings to go
// fishing for anything that didn't match a preset pattern — config
// keys, URLs, messages, inline credentials with unusual shape.
func newStringsCmd() *cobra.Command {
	var f stringsFlags
	cmd := &cobra.Command{
		Use:   "strings <file.hprof | http(s)://...>",
		Short: "Dump resolvable strings from a heap dump, optionally scan them",
		Long: `Walk the HPROF file and emit every string CyberHeap can resolve:
STRING_IN_UTF8 records (class/field/method names + interned literals)
and java.lang.String instances (runtime-constructed strings).

Filters keep the signal up:

  --min-length N        drop strings shorter than N (default 4)
  --max-length N        drop strings longer than N  (default 4096, 0 = unlimited)
  --regex PAT           Go regex filter on value
  --grep TEXT           case-insensitive substring filter
  --unique              deduplicate identical values
  --include KIND        "all" | "utf8" | "instances" (default all)
  --ascii               drop anything outside printable ASCII

Use --scan to run CyberHeap's regex secret catalogue over the
resolved strings only. Compared to "cyberheap scan" this trades
binary-noise coverage for a much cleaner signal — every match is on
a real Java string, not a coincidental byte substring.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStrings(cmd, args[0], &f)
		},
	}
	cmd.Flags().IntVar(&f.minLen, "min-length", 4, "drop strings shorter than N characters")
	cmd.Flags().IntVar(&f.maxLen, "max-length", 4096, "drop strings longer than N (0 = unlimited)")
	cmd.Flags().StringVar(&f.regex, "regex", "", "Go regex filter (case-sensitive)")
	cmd.Flags().StringVar(&f.grep, "grep", "", "case-insensitive substring filter")
	cmd.Flags().BoolVar(&f.unique, "unique", false, "deduplicate identical values")
	cmd.Flags().StringVar(&f.sortMode, "sort", "", "sort order: length, alpha, freq (requires --unique for freq)")
	cmd.Flags().StringVar(&f.format, "format", "plain", "output format: plain, json")
	cmd.Flags().BoolVar(&f.noBanner, "no-banner", true, "suppress the banner (default: true, because plain output is meant to be piped)")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable ANSI colors (--scan only)")
	cmd.Flags().StringVar(&f.include, "include", "all", `which source to include: "all", "utf8" (intern'd constants only), "instances" (runtime java.lang.String only)`)
	cmd.Flags().BoolVar(&f.scan, "scan", false, "run the regex secret scanner over the resolved strings instead of dumping them")
	cmd.Flags().IntVar(&f.limit, "limit", 0, "cap output at N strings (0 = unlimited)")
	cmd.Flags().BoolVar(&f.ascii, "ascii", false, "drop non-printable-ASCII strings")
	return cmd
}

func runStrings(cmd *cobra.Command, arg string, f *stringsFlags) error {
	f.noColor = f.noColor || os.Getenv("NO_COLOR") != ""

	tgt, err := openTarget(arg)
	if err != nil {
		return err
	}
	defer tgt.Close()

	h, err := hprof.ParseHeader(tgt.file)
	if err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	tgt.header = h

	mi, err := buildIndex(tgt)
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	defer mi.Close()
	idx := mi.Index

	var reFilter *regexp.Regexp
	if f.regex != "" {
		reFilter, err = regexp.Compile(f.regex)
		if err != nil {
			return fmt.Errorf("--regex %s: %w", f.regex, err)
		}
	}
	grepLower := strings.ToLower(f.grep)

	// Phase 1 — collect candidates.
	values := collectStrings(idx, f, reFilter, grepLower)

	// Phase 2 — dedup / sort / limit.
	values = postProcess(values, f)

	// Phase 3 — emit.
	w := cmd.OutOrStdout()
	if f.scan {
		return emitScanOverStrings(w, values, tgt, f)
	}
	return emitRawStrings(w, values, f)
}

// stringEntry is produced by the collection phase so we can carry a
// frequency count for post-processing.
type stringEntry struct {
	Value string
	Count int
}

func collectStrings(idx *heap.Index, f *stringsFlags, re *regexp.Regexp, grepLower string) []stringEntry {
	seen := make(map[string]int, 1<<16)
	var stream []string

	accept := func(s string) bool {
		if len(s) < f.minLen {
			return false
		}
		if f.maxLen > 0 && len(s) > f.maxLen {
			return false
		}
		if f.ascii && !isPrintableASCII(s) {
			return false
		}
		if grepLower != "" && !strings.Contains(strings.ToLower(s), grepLower) {
			return false
		}
		if re != nil && !re.MatchString(s) {
			return false
		}
		return true
	}

	if f.include == "all" || f.include == "utf8" {
		for _, v := range idx.Strings {
			if !accept(v) {
				continue
			}
			if _, existed := seen[v]; existed {
				seen[v]++
				continue
			}
			seen[v] = 1
			stream = append(stream, v)
		}
	}
	if f.include == "all" || f.include == "instances" {
		// java.lang.String instances live under the class with that FQN.
		if cls, ok := idx.ClassByName["java.lang.String"]; ok {
			for _, inst := range idx.Instances[cls.ID] {
				v, ok := idx.ReadString(inst.ID)
				if !ok || !accept(v) {
					continue
				}
				if _, existed := seen[v]; existed {
					seen[v]++
					continue
				}
				seen[v] = 1
				stream = append(stream, v)
			}
		}
	}

	out := make([]stringEntry, 0, len(stream))
	for _, v := range stream {
		out = append(out, stringEntry{Value: v, Count: seen[v]})
	}
	return out
}

func postProcess(items []stringEntry, f *stringsFlags) []stringEntry {
	// --unique: we already deduplicated during collection. The "Count"
	// field survives and represents the number of occurrences. When
	// --unique is not set, expand entries with Count > 1 back into
	// duplicates so "plain" output looks natural.
	if !f.unique {
		expanded := make([]stringEntry, 0, len(items))
		for _, e := range items {
			for i := 0; i < e.Count; i++ {
				expanded = append(expanded, stringEntry{Value: e.Value, Count: 1})
			}
		}
		items = expanded
	}

	switch f.sortMode {
	case "length":
		sort.SliceStable(items, func(i, j int) bool {
			if len(items[i].Value) != len(items[j].Value) {
				return len(items[i].Value) > len(items[j].Value)
			}
			return items[i].Value < items[j].Value
		})
	case "alpha":
		sort.SliceStable(items, func(i, j int) bool { return items[i].Value < items[j].Value })
	case "freq":
		if !f.unique {
			// Frequency is only meaningful when values are deduplicated.
			// Promote to unique silently.
			seen := map[string]int{}
			for _, e := range items {
				seen[e.Value]++
			}
			items = items[:0]
			for v, c := range seen {
				items = append(items, stringEntry{Value: v, Count: c})
			}
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Count != items[j].Count {
				return items[i].Count > items[j].Count
			}
			return items[i].Value < items[j].Value
		})
	}

	if f.limit > 0 && len(items) > f.limit {
		items = items[:f.limit]
	}
	return items
}

func emitRawStrings(w io.Writer, items []stringEntry, f *stringsFlags) error {
	switch f.format {
	case "json":
		return json.NewEncoder(w).Encode(items)
	case "plain":
		bw := bufio.NewWriter(w)
		defer bw.Flush()
		for _, e := range items {
			if f.unique && e.Count > 1 {
				fmt.Fprintf(bw, "%s\t(x%d)\n", e.Value, e.Count)
			} else {
				fmt.Fprintln(bw, e.Value)
			}
		}
		return nil
	}
	return fmt.Errorf("unknown format %q", f.format)
}

// emitScanOverStrings runs the regex pattern set over joined strings.
// We separate values with NUL bytes so patterns can't accidentally
// match across string boundaries (a real concern with URL/token regexes
// that include ":" or "/").
func emitScanOverStrings(w io.Writer, items []stringEntry, tgt *target, f *stringsFlags) error {
	if len(items) == 0 {
		return errors.New("strings --scan: no strings survived filters — nothing to scan")
	}

	var buf strings.Builder
	buf.Grow(1 << 20)
	for _, e := range items {
		buf.WriteString(e.Value)
		buf.WriteByte(0) // NUL — hard boundary
	}

	matches, err := scanner.Scan(strings.NewReader(buf.String()), scanner.Options{})
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		fmt.Fprintln(w, "  no secrets matched — try relaxing filters or running the full `scan` command")
		return nil
	}

	enriched := enrich(matches)
	// Pretend we have a minimal scanFlags for printFinding reuse.
	sf := &scanFlags{format: "pretty", noColor: f.noColor, maxValue: 200}
	labelWidth := 0
	for _, em := range enriched {
		l := len(em.m.Pattern.Name) + 1
		if l > labelWidth {
			labelWidth = l
		}
	}
	if labelWidth > 36 {
		labelWidth = 36
	}

	if tgt.header != nil {
		fmt.Fprintf(w, "  source:     %s\n", tgt.displayName)
		fmt.Fprintf(w, "  strings:    %d resolved\n", len(items))
		fmt.Fprintf(w, "  matches:    %d\n\n", len(enriched))
	}
	var curSev scanner.Severity = -1
	for _, em := range enriched {
		if em.m.Pattern.Severity != curSev {
			curSev = em.m.Pattern.Severity
			fmt.Fprintln(w, sectionDivider(curSev, f.noColor))
			fmt.Fprintln(w)
		}
		printFinding(w, em, sf, labelWidth, nil)
	}
	return nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			if c != '\t' && c != '\n' && c != '\r' {
				return false
			}
		}
	}
	return true
}
