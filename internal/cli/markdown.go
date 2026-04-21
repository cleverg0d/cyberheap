package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/cleverg0d/cyberheap/internal/scanner"
	"github.com/cleverg0d/cyberheap/internal/spiders"
)

// emitMarkdown renders a pentest-report-friendly Markdown document.
//
// Design goals:
//
//   - Paste-ready for client reports — GFM-compatible, no custom blocks.
//   - Severity ordering matches the pretty view.
//   - Structured findings expand each class/object as a table so readers
//     unfamiliar with heap dumps can still make sense of them.
//   - Respects --mask (values obfuscated) and omits `offset` fields that
//     would only confuse non-technical stakeholders.
func emitMarkdown(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding, elapsed time.Duration, f *scanFlags) error {
	total := len(items) + len(spFindings)
	bySev := map[scanner.Severity]int{}
	for _, em := range items {
		bySev[em.m.Pattern.Severity]++
	}
	for _, sf := range spFindings {
		bySev[spiderSevToScanner(sf.Severity)]++
	}

	fmt.Fprintln(w, "# Heap Dump Security Assessment")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Target:** `%s`  \n", tgt.displayName)
	if tgt.header != nil {
		fmt.Fprintf(w, "**Format:** HPROF %s (ID size %d bytes)  \n", tgt.header.Version, tgt.header.IDSize)
		fmt.Fprintf(w, "**Captured:** %s  \n", tgt.header.Timestamp.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Fprintf(w, "**Size:** %s  \n", humanBytes(tgt.size))
	fmt.Fprintf(w, "**Scan duration:** %s  \n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "**Report generated:** %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	// Severity summary table.
	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Count |")
	fmt.Fprintln(w, "|----------|------:|")
	for _, sev := range allSeverities {
		if bySev[sev] == 0 {
			continue
		}
		fmt.Fprintf(w, "| %s %s | %d |\n", severityBadge(sev), sev, bySev[sev])
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n", total)
	fmt.Fprintln(w)

	if total == 0 {
		fmt.Fprintln(w, "_No secrets found with the current pattern set and filters._")
		return nil
	}

	// Regex findings — grouped by severity → by pattern.
	if len(items) > 0 {
		fmt.Fprintln(w, "## Regex-pattern findings")
		fmt.Fprintln(w)
		emitMarkdownRegexTable(w, items, f)
	}

	// Structured findings — one subsection per finding for readability.
	if len(spFindings) > 0 {
		fmt.Fprintln(w, "## Class-aware findings")
		fmt.Fprintln(w)
		emitMarkdownStructured(w, spFindings, f)
	}

	// Appendix: methodology and CWE references.
	fmt.Fprintln(w, "## Methodology")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Findings were produced by CyberHeap, which combines two passes over the heap dump:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. **Pattern scan** — curated regular expressions for well-known credential formats (AWS, GCP, GitHub, OpenAI, JWT, private keys, …). Matches are deduplicated by (pattern, value).")
	fmt.Fprintln(w, "2. **Class-aware scan** — HPROF parser + object index; for each targeted Java class (Spring DataSource, Hikari, Jasypt, Shiro, Redis, Cloud SDKs, …) relevant field values are read directly out of heap instances.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "**Relevant CWEs:**")
	fmt.Fprintln(w, "- CWE-200: Exposure of Sensitive Information")
	fmt.Fprintln(w, "- CWE-312: Cleartext Storage of Sensitive Information")
	fmt.Fprintln(w, "- CWE-522: Insufficiently Protected Credentials")
	fmt.Fprintln(w, "- CWE-798: Use of Hard-coded Credentials")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The heap dump itself was typically exposed via `/actuator/heapdump` on a Spring Boot instance, JVM flight recorder, or an uploaded artefact. Mitigation starts with closing that exposure, then rotating every credential listed above.")
	return nil
}

func emitMarkdownRegexTable(w io.Writer, items []enrichedMatch, f *scanFlags) {
	// Group by severity in descending order.
	groups := map[scanner.Severity][]enrichedMatch{}
	for _, em := range items {
		groups[em.m.Pattern.Severity] = append(groups[em.m.Pattern.Severity], em)
	}
	for _, sev := range allSeverities {
		g, ok := groups[sev]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "### %s %s\n\n", severityBadge(sev), sev)
		fmt.Fprintln(w, "| Pattern | Value | Occurrences |")
		fmt.Fprintln(w, "|---------|-------|------------:|")
		// Stable order: by pattern name then by count desc.
		sort.Slice(g, func(i, j int) bool {
			if g[i].m.Pattern.Name != g[j].m.Pattern.Name {
				return g[i].m.Pattern.Name < g[j].m.Pattern.Name
			}
			return g[i].m.Count > g[j].m.Count
		})
		for _, em := range g {
			display := em.m.Value
			if em.dec != nil && !f.mask {
				display = em.dec.Text
			}
			if f.mask {
				if em.dec != nil {
					display = maskDecoded(em.dec.Kind, em.dec.Text)
				} else {
					display = maskForPattern(em.m.Pattern.Name, em.m.Value)
				}
			}
			fmt.Fprintf(w, "| %s | %s | %d |\n",
				mdCode(mdEscape(em.m.Pattern.Name)),
				mdCode(mdEscape(truncateForMd(display, 140))),
				em.m.Count)
		}
		fmt.Fprintln(w)
	}
}

func emitMarkdownStructured(w io.Writer, spFindings []spiders.Finding, f *scanFlags) {
	// Ordering: by severity desc, then spider, then title.
	sort.Slice(spFindings, func(i, j int) bool {
		si, sj := spFindings[i].Severity, spFindings[j].Severity
		if si != sj {
			return si > sj
		}
		if spFindings[i].Spider != spFindings[j].Spider {
			return spFindings[i].Spider < spFindings[j].Spider
		}
		return spFindings[i].Title < spFindings[j].Title
	})
	for _, sf := range spFindings {
		sev := spiderSevToScanner(sf.Severity)
		fmt.Fprintf(w, "### %s %s — %s\n\n", severityBadge(sev), sev, mdEscape(sf.Title))
		fmt.Fprintf(w, "- **Class:** `%s`\n", mdEscape(sf.ClassFQN))
		fmt.Fprintf(w, "- **Object ID:** `0x%x`\n", sf.ObjectID)
		fmt.Fprintf(w, "- **Source:** `%s` spider\n\n", sf.Spider)
		fmt.Fprintln(w, "| Field | Value |")
		fmt.Fprintln(w, "|-------|-------|")
		for _, kv := range sf.Fields {
			val := kv.Value
			if f.mask && looksSensitive(kv.Name) {
				val = maskSecret(val, 2, 2)
			}
			fmt.Fprintf(w, "| %s | %s |\n",
				mdCode(mdEscape(kv.Name)),
				mdCode(mdEscape(truncateForMd(val, 140))))
		}
		fmt.Fprintln(w)
	}
}

// severityBadge returns a coloured unicode symbol that renders in
// GitHub-flavored Markdown without any extensions.
func severityBadge(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "🟣" // magenta matches our terminal theme
	case scanner.SeverityHigh:
		return "🔴"
	case scanner.SeverityMedium:
		return "🟡"
	case scanner.SeverityLow:
		return "🟢"
	case scanner.SeverityInfo:
		return "🔵"
	}
	return "⚪"
}

// mdEscape handles the Markdown / table-column specials we care about.
//
// Backticks inside a value wrapped in inline-code (like “ `value` “)
// break the code span. The safe way in GitHub-flavoured Markdown is to
// swap the wrapping to a pair of backticks so the value can contain a
// single backtick verbatim. We do that at the call site — here we only
// escape pipes (which terminate table columns) and strip newlines
// (which break table row parsing).
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// mdCode wraps a value in an inline-code span, doubling the backticks
// if the value contains a single backtick so the span stays balanced.
// Example: a secret like `db'pass` renders verbatim; a secret like
// "a`b" renders as “ a`b “.
func mdCode(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	// GFM allows N backticks as a delimiter as long as the body doesn't
	// contain exactly N consecutive backticks. Three is enough for any
	// realistic secret.
	return "``` " + s + " ```"
}

func truncateForMd(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
