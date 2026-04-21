package scanner

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"sync"
)

// Options controls the scan. Zero value is a full scan with builtin patterns.
type Options struct {
	Patterns   []*Pattern
	Severities SeveritySet // if nil, all severities
	Categories CategorySet // if nil, all categories
	ScanUTF16  bool        // if true, also scan a UTF-16LE-squeezed view
}

// Scan reads the entire input into memory and runs all enabled patterns.
//
// Memory: O(file size). For the MVP this is acceptable up to ~2 GB dumps on
// 16 GB+ hosts. Streaming/mmap will replace this in Phase 2 once the HPROF
// parser is in place.
func Scan(r io.Reader, opts Options) ([]Match, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	patterns := opts.Patterns
	if len(patterns) == 0 {
		patterns = BuiltinPatterns()
	}
	patterns = filterPatterns(patterns, opts.Severities, opts.Categories)

	findings := scanBuffer(data, patterns, 0)

	if opts.ScanUTF16 {
		squeezed, offsets := squeezeUTF16LE(data)
		utf16Findings := scanBuffer(squeezed, patterns, -1)
		// Rewrite offsets from squeezed space back to source bytes.
		for i := range utf16Findings {
			off := utf16Findings[i].Offset
			if int(off) < len(offsets) {
				utf16Findings[i].Offset = offsets[off]
			}
		}
		findings = append(findings, utf16Findings...)
	}

	return deduplicate(findings), nil
}

func filterPatterns(pats []*Pattern, sev SeveritySet, cat CategorySet) []*Pattern {
	if sev == nil && cat == nil {
		return pats
	}
	out := pats[:0:0]
	for _, p := range pats {
		if sev != nil && !sev[p.Severity] {
			continue
		}
		if cat != nil && !cat[p.Category] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// scanBuffer runs every pattern over data in parallel.
// offsetBase = -1 signals UTF-16 path (caller rewrites offsets later).
func scanBuffer(data []byte, patterns []*Pattern, offsetBase int64) []Match {
	var (
		mu  sync.Mutex
		out []Match
		wg  sync.WaitGroup
	)

	for _, p := range patterns {
		wg.Add(1)
		go func(p *Pattern) {
			defer wg.Done()
			hits := p.re.FindAllSubmatchIndex(data, -1)
			local := make([]Match, 0, len(hits))
			for _, idx := range hits {
				fullStart, fullEnd := idx[0], idx[1]
				grpStart, grpEnd := fullStart, fullEnd
				if p.captureGroup > 0 && len(idx) > 2*p.captureGroup+1 {
					grpStart = idx[2*p.captureGroup]
					grpEnd = idx[2*p.captureGroup+1]
				}
				if grpStart < 0 || grpEnd < 0 || grpEnd <= grpStart {
					continue
				}
				full := data[fullStart:fullEnd]
				val := data[grpStart:grpEnd]
				if p.maxLen > 0 && len(val) > p.maxLen {
					continue
				}
				if p.postFilter != nil && !p.postFilter(val) {
					continue
				}
				off := int64(fullStart)
				if offsetBase >= 0 {
					off = offsetBase + int64(fullStart)
				}
				local = append(local, Match{
					Pattern: p,
					Value:   string(val),
					Full:    string(full),
					Offset:  off,
					Count:   1,
				})
			}
			if len(local) > 0 {
				mu.Lock()
				out = append(out, local...)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}

// deduplicate merges matches with the same (pattern, value) pair, keeping the
// earliest offset and a cumulative count. Sorts by severity desc, then offset.
func deduplicate(in []Match) []Match {
	type key struct {
		name string
		val  string
	}
	byKey := make(map[key]*Match, len(in))
	for i := range in {
		k := key{in[i].Pattern.Name, in[i].Value}
		if existing, ok := byKey[k]; ok {
			existing.Count++
			if in[i].Offset < existing.Offset {
				existing.Offset = in[i].Offset
			}
			continue
		}
		m := in[i]
		byKey[k] = &m
	}
	out := make([]Match, 0, len(byKey))
	for _, m := range byKey {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern.Severity != out[j].Pattern.Severity {
			return out[i].Pattern.Severity > out[j].Pattern.Severity
		}
		if out[i].Pattern.Category != out[j].Pattern.Category {
			return out[i].Pattern.Category < out[j].Pattern.Category
		}
		return out[i].Offset < out[j].Offset
	})
	return out
}

// squeezeUTF16LE extracts a printable-ASCII view from a UTF-16LE-encoded
// region. For each pair (low, high), if high is 0x00 and low is printable
// ASCII, we keep low. This lets ASCII patterns match strings stored as char[]
// in JDK 8 heap dumps. Non-matching pairs break the squeeze run with 0x00,
// preventing regex crossings.
//
// Returns the squeezed buffer and a parallel offsets[] where offsets[i] is the
// source byte offset for squeezed byte i.
func squeezeUTF16LE(data []byte) ([]byte, []int64) {
	out := make([]byte, 0, len(data)/2)
	offs := make([]int64, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		low, high := data[i], data[i+1]
		if high == 0x00 && low >= 0x20 && low < 0x7F {
			out = append(out, low)
			offs = append(offs, int64(i))
		} else if len(out) > 0 && out[len(out)-1] != 0x00 {
			out = append(out, 0x00)
			offs = append(offs, int64(i))
		}
	}
	return out, offs
}

// MatchSummary groups matches by severity for quick totals.
type MatchSummary struct {
	Total int
	BySev map[Severity]int
	ByCat map[Category]int
}

func Summarize(matches []Match) MatchSummary {
	s := MatchSummary{
		BySev: map[Severity]int{},
		ByCat: map[Category]int{},
	}
	for _, m := range matches {
		s.Total++
		s.BySev[m.Pattern.Severity]++
		s.ByCat[m.Pattern.Category]++
	}
	return s
}

// ContextSnippet pulls a short printable window around offset for display.
// Best-effort: replaces non-printable bytes with '.'.
func ContextSnippet(data []byte, offset int64, matchLen, window int) string {
	start := int(offset) - window
	if start < 0 {
		start = 0
	}
	end := int(offset) + matchLen + window
	if end > len(data) {
		end = len(data)
	}
	b := make([]byte, 0, end-start)
	for _, c := range data[start:end] {
		if c >= 0x20 && c < 0x7F {
			b = append(b, c)
		} else {
			b = append(b, '.')
		}
	}
	s := string(b)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// ScanBytes is a convenience wrapper for callers that already have a buffer.
func ScanBytes(data []byte, opts Options) []Match {
	return deduplicate(scanBuffer(data, effectivePatterns(opts), 0))
}

func effectivePatterns(opts Options) []*Pattern {
	pats := opts.Patterns
	if len(pats) == 0 {
		pats = BuiltinPatterns()
	}
	return filterPatterns(pats, opts.Severities, opts.Categories)
}

// compileTimeCheck ensures we don't accidentally leave dead helpers.
var _ = bytes.Equal
