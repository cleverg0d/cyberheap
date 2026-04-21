package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/decode"
	"github.com/cleverg0d/cyberheap/internal/hprof"
	"github.com/cleverg0d/cyberheap/internal/scanner"
	"github.com/cleverg0d/cyberheap/internal/spiders"
)

type scanFlags struct {
	format       string
	severities   []string
	categories   []string
	skipHeader   bool
	utf16        bool
	noColor      bool
	mask         bool
	minCount     int
	verbose      bool
	maxValue     int
	outputDir    string
	noBanner     bool
	noRegex      bool
	noSpiders    bool
	diffAgainst  string
	patternFiles []string
	patternsOnly bool
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan <file.hprof | http(s)://host/actuator/heapdump>",
		Short: "Scan a heap dump for credentials, keys, tokens and secrets",
		Long: `Scan runs a fast regex-based pass over the raw bytes of an HPROF file.
This catches credentials, API keys, tokens, JDBC URLs and similar artefacts
without requiring full heap parsing. Recognized tokens (basic auth, JWT) are
decoded inline for quick triage.

The target may be a local file path or an http(s) URL (e.g. an exposed
Spring Boot actuator/heapdump endpoint). Remote dumps are streamed to a
temp file and deleted after the scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], &f)
		},
	}
	cmd.Flags().StringVar(&f.format, "format", "pretty", "output format: pretty, json, markdown")
	cmd.Flags().StringSliceVar(&f.severities, "severity", nil, "filter by severity: critical,high,medium,low,info")
	cmd.Flags().StringSliceVar(&f.categories, "category", nil, "filter by category: datasource,cloud,scm,jwt,auth,credentials,connection-string,private-key,payment-saas,personal")
	cmd.Flags().BoolVar(&f.skipHeader, "no-header-check", false, "skip HPROF header validation (scan any file as raw bytes)")
	cmd.Flags().BoolVar(&f.utf16, "utf16", false, "also scan a squeezed view for UTF-16LE strings (JDK 8 char[])")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable ANSI colors")
	cmd.Flags().BoolVar(&f.mask, "mask", false, "mask secret values in output (for client-facing evidence)")
	cmd.Flags().IntVar(&f.minCount, "min-count", 1, "drop findings seen fewer than N times")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "show byte offsets and the raw encoded value for decoded findings")
	cmd.Flags().IntVar(&f.maxValue, "max-value", 120, "truncate raw values longer than N chars (0 = unlimited)")
	cmd.Flags().StringVarP(&f.outputDir, "output", "o", "", "save/merge findings as JSON into DIR/<target>.json")
	cmd.Flags().BoolVar(&f.noBanner, "no-banner", false, "suppress the banner")
	cmd.Flags().BoolVar(&f.noRegex, "no-regex", false, "skip the regex pass (structured class-aware only)")
	cmd.Flags().BoolVar(&f.noSpiders, "no-spiders", false, "skip the structured class-aware pass (regex only)")
	cmd.Flags().StringVar(&f.diffAgainst, "diff-against", "", "compare this scan against an earlier JSON report and tag findings as new (+), unchanged (=) or closed (-)")
	cmd.Flags().StringArrayVar(&f.patternFiles, "patterns", nil, "load extra regex patterns from a gitleaks-compatible TOML file (repeatable)")
	cmd.Flags().BoolVar(&f.patternsOnly, "patterns-only", false, "use ONLY --patterns files, skip the built-in pattern catalogue")
	return cmd
}

func runScan(cmd *cobra.Command, arg string, f *scanFlags) error {
	f.noColor = f.noColor || os.Getenv("NO_COLOR") != ""

	tgt, err := openTarget(arg)
	if err != nil {
		return err
	}
	defer tgt.Close()

	if !f.skipHeader {
		h, err := hprof.ParseHeader(tgt.file)
		if err != nil {
			return fmt.Errorf("not a readable HPROF file: %w (use --no-header-check to scan anyway)", err)
		}
		tgt.header = h
		if _, err := tgt.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	sevSet, err := parseSeverities(f.severities)
	if err != nil {
		return err
	}
	catSet, err := parseCategories(f.categories)
	if err != nil {
		return err
	}

	start := time.Now()

	var enriched []enrichedMatch
	var spiderFindings []spiders.Finding
	var regexElapsed, spiderElapsed time.Duration

	if !f.noRegex {
		patterns, perr := resolvePatternSet(f.patternFiles, f.patternsOnly)
		if perr != nil {
			return perr
		}
		t0 := time.Now()
		scanOpts := scanner.Options{
			Severities: sevSet,
			Categories: catSet,
			ScanUTF16:  f.utf16,
			Patterns:   patterns,
		}
		// Auto-pick streaming for large dumps so we don't try to ReadAll
		// a 5 GiB file into RAM. ShouldStream returns true above ~512 MiB;
		// below that the single-pass path is both faster and simpler.
		var (
			matches []scanner.Match
			err     error
		)
		if scanner.ShouldStream(tgt.size) {
			if _, serr := tgt.file.Seek(0, io.SeekStart); serr != nil {
				return fmt.Errorf("seek for streaming scan: %w", serr)
			}
			matches, err = scanner.ScanStream(tgt.file, tgt.size, scanner.StreamOptions{Options: scanOpts})
		} else {
			matches, err = scanner.Scan(tgt.file, scanOpts)
		}
		if err != nil {
			return fmt.Errorf("regex scan: %w", err)
		}
		regexElapsed = time.Since(t0)

		if f.minCount > 1 {
			filtered := matches[:0:0]
			for _, m := range matches {
				if m.Count >= f.minCount {
					filtered = append(filtered, m)
				}
			}
			matches = filtered
		}
		enriched = enrich(matches)
	}

	if !f.noSpiders {
		t0 := time.Now()
		mi, err := buildIndex(tgt)
		if err != nil {
			// Don't fail the whole scan — just tell the user and keep the regex findings.
			fmt.Fprintf(cmd.ErrOrStderr(), "  %sstructured pass skipped: %v%s\n",
				dimOnly(!f.noColor), err, resetOnly(!f.noColor))
		} else {
			defer mi.Close()
			for _, sp := range spiders.Registry() {
				spiderFindings = append(spiderFindings, sp.Sniff(mi.Index)...)
			}
			spiderFindings = filterSpiderFindings(spiderFindings, sevSet, catSet)
		}
		spiderElapsed = time.Since(t0)
	}

	elapsed := time.Since(start)
	_ = regexElapsed
	_ = spiderElapsed

	diff, err := loadDiffState(f.diffAgainst)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	switch f.format {
	case "json":
		if err := emitJSON(w, tgt, enriched, spiderFindings); err != nil {
			return err
		}
	case "pretty":
		if err := emitPretty(w, tgt, enriched, spiderFindings, elapsed, f, diff); err != nil {
			return err
		}
	case "markdown", "md":
		if err := emitMarkdown(w, tgt, enriched, spiderFindings, elapsed, f); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (use pretty, json, or markdown)", f.format)
	}

	if f.outputDir != "" {
		path, added, updated, err := saveReport(f.outputDir, tgt.safeName, tgt.displayName, enriched, spiderFindings)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "\n  %ssaved%s %s  (+%d new, %d updated)\n",
			dimOnly(!f.noColor), resetOnly(!f.noColor), path, added, updated)
	}

	return nil
}

// filterSpiderFindings applies the same --severity / --category filters the
// regex scanner honours.
func filterSpiderFindings(in []spiders.Finding, sev scanner.SeveritySet, cat scanner.CategorySet) []spiders.Finding {
	if sev == nil && cat == nil {
		return in
	}
	out := in[:0:0]
	for _, f := range in {
		if sev != nil && !sev[spiderSevToScanner(f.Severity)] {
			continue
		}
		if cat != nil && !cat[scanner.Category(f.Category)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func spiderSevToScanner(s spiders.Severity) scanner.Severity {
	switch s {
	case spiders.SeverityCritical:
		return scanner.SeverityCritical
	case spiders.SeverityHigh:
		return scanner.SeverityHigh
	case spiders.SeverityMedium:
		return scanner.SeverityMedium
	case spiders.SeverityLow:
		return scanner.SeverityLow
	}
	return scanner.SeverityInfo
}

// enrichedMatch pairs a scanner.Match with an optional inline decoding.
type enrichedMatch struct {
	m   scanner.Match
	dec *decode.Decoded
}

func enrich(matches []scanner.Match) []enrichedMatch {
	out := make([]enrichedMatch, 0, len(matches))
	for _, m := range matches {
		em := enrichedMatch{m: m}
		em.dec = decode.TryDecode(m.Pattern.Name, m.Value)
		out = append(out, em)
	}
	return out
}

func parseSeverities(raw []string) (scanner.SeveritySet, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := scanner.SeveritySet{}
	for _, item := range raw {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			sev, ok := scanner.ParseSeverity(s)
			if !ok {
				return nil, fmt.Errorf("unknown severity %q", s)
			}
			out[sev] = true
		}
	}
	return out, nil
}

// knownCategories lists the category names every built-in pattern and
// spider uses. Custom TOML rules can define new categories — those are
// accepted verbatim. Strictness here is the difference between a typo
// ("cloul" instead of "cloud") producing no findings silently vs. an
// explicit error the user can fix.
var knownCategories = map[scanner.Category]bool{
	scanner.CatDatasource:  true,
	scanner.CatCredentials: true,
	scanner.CatCloud:       true,
	scanner.CatSCM:         true,
	scanner.CatPaymentSaaS: true,
	scanner.CatPrivateKey:  true,
	scanner.CatJWT:         true,
	scanner.CatConnString:  true,
	scanner.CatAuth:        true,
	scanner.CatPersonal:    true,
	// Spider-emitted categories that aren't in the scanner enum:
	"shiro": true,
}

func parseCategories(raw []string) (scanner.CategorySet, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := scanner.CategorySet{}
	for _, item := range raw {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			cat := scanner.Category(s)
			if !knownCategories[cat] {
				return nil, fmt.Errorf("unknown category %q (known: datasource, credentials, cloud, scm, payment-saas, private-key, jwt, connection-string, auth, personal, shiro)", s)
			}
			out[cat] = true
		}
	}
	return out, nil
}

type jsonFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	Value       string `json:"value"`
	Offset      int64  `json:"offset"`
	Count       int    `json:"count"`
	DecodedKind string `json:"decoded_kind,omitempty"`
	DecodedText string `json:"decoded_text,omitempty"`
}

type jsonSpiderFinding struct {
	Severity string            `json:"severity"`
	Category string            `json:"category"`
	Spider   string            `json:"spider"`
	Title    string            `json:"title"`
	ClassFQN string            `json:"class_fqn"`
	ObjectID string            `json:"object_id"`
	Fields   map[string]string `json:"fields"`
}

type jsonOut struct {
	File     string              `json:"file"`
	Size     int64               `json:"size_bytes"`
	Total    int                 `json:"total"`
	Findings []jsonFinding       `json:"findings"`
	Spiders  []jsonSpiderFinding `json:"structured_findings,omitempty"`
}

func emitJSON(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding) error {
	out := jsonOut{File: tgt.displayName, Size: tgt.size, Total: len(items) + len(spFindings)}
	for _, em := range items {
		f := jsonFinding{
			Severity: em.m.Pattern.Severity.String(),
			Category: string(em.m.Pattern.Category),
			Pattern:  em.m.Pattern.Name,
			Value:    em.m.Value,
			Offset:   em.m.Offset,
			Count:    em.m.Count,
		}
		if em.dec != nil {
			f.DecodedKind = em.dec.Kind
			f.DecodedText = em.dec.Text
		}
		out.Findings = append(out.Findings, f)
	}
	for _, sf := range spFindings {
		fm := make(map[string]string, len(sf.Fields))
		for _, kv := range sf.Fields {
			fm[kv.Name] = kv.Value
		}
		out.Spiders = append(out.Spiders, jsonSpiderFinding{
			Severity: spiderSevToScanner(sf.Severity).String(),
			Category: sf.Category,
			Spider:   sf.Spider,
			Title:    sf.Title,
			ClassFQN: sf.ClassFQN,
			ObjectID: fmt.Sprintf("0x%x", sf.ObjectID),
			Fields:   fm,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

var allSeverities = []scanner.Severity{
	scanner.SeverityCritical,
	scanner.SeverityHigh,
	scanner.SeverityMedium,
	scanner.SeverityLow,
	scanner.SeverityInfo,
}

func emitPretty(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding, elapsed time.Duration, f *scanFlags, diff *diffState) error {
	if !f.noBanner {
		fmt.Fprint(w, banner(Version, f.noColor))
		fmt.Fprintln(w)
	}

	// Summary by severity — regex + structured combined.
	bySev := map[scanner.Severity]int{}
	for _, em := range items {
		bySev[em.m.Pattern.Severity]++
	}
	for _, sf := range spFindings {
		bySev[spiderSevToScanner(sf.Severity)]++
	}
	total := len(items) + len(spFindings)

	targetKind := "file"
	if tgt.isRemote {
		targetKind = "url "
	}
	fmt.Fprintln(w, kvLine(targetKind, tgt.displayName, f.noColor))
	if tgt.header != nil {
		fmt.Fprintln(w, kvLine("format", fmt.Sprintf(
			"HPROF %s   size %s   id-size %d bytes   header %d bytes",
			tgt.header.Version, humanBytes(tgt.size), tgt.header.IDSize, tgt.header.HeaderLen,
		), f.noColor))
		fmt.Fprintln(w, kvLine("timestamp",
			tgt.header.Timestamp.Format("2006-01-02 15:04:05 MST"), f.noColor))
	} else {
		fmt.Fprintln(w, kvLine("size", humanBytes(tgt.size), f.noColor))
	}
	fmt.Fprintln(w, kvLine("elapsed", elapsed.Round(time.Millisecond).String(), f.noColor))

	// Compose the severity-bullet summary line.
	var parts []string
	for _, sev := range allSeverities {
		n := bySev[sev]
		label := fmt.Sprintf("%s %d %s", sevBullet(sev, f.noColor), n, sev)
		if n == 0 && !f.verbose {
			if !f.noColor {
				label = cDim + fmt.Sprintf("● %d %s", n, sev) + cReset
			}
		}
		parts = append(parts, label)
	}
	fmt.Fprintln(w, kvLine("summary", fmt.Sprintf("%d findings (regex %d + structured %d)   %s",
		total, len(items), len(spFindings), strings.Join(parts, "   ")), f.noColor))

	if total == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  No secrets found with current patterns and filters.")
		return nil
	}

	// Regex findings section.
	if len(items) > 0 {
		labelWidth := 0
		for _, em := range items {
			l := len(em.m.Pattern.Name) + 1
			if l > labelWidth {
				labelWidth = l
			}
		}
		if labelWidth > 36 {
			labelWidth = 36
		}

		var curSev scanner.Severity = -1
		for _, em := range items {
			if em.m.Pattern.Severity != curSev {
				curSev = em.m.Pattern.Severity
				fmt.Fprintln(w)
				fmt.Fprintln(w, sectionDivider(curSev, f.noColor))
				fmt.Fprintln(w)
			}
			printFinding(w, em, f, labelWidth, diff)
		}
	}

	// Structured findings section — rendered with class/object context.
	if len(spFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, structuredDivider(f.noColor))
		fmt.Fprintln(w)
		for _, sf := range spFindings {
			printStructured(w, sf, f, diff)
		}
	}

	if diff != nil {
		diff.printGoneSection(w, f.noColor)
	}

	fmt.Fprintln(w)
	return nil
}

// structuredDivider draws a cyan divider labeled "STRUCTURED" to separate
// class-aware findings from the regex-based section above.
func structuredDivider(noColor bool) string {
	label := " STRUCTURED (class-aware) "
	full := 80
	side := (full - len(label)) / 2
	line := strings.Repeat("━", side) + label + strings.Repeat("━", full-side-len(label))
	if noColor {
		return line
	}
	return cBold + cBCyan + line + cReset
}

// printStructured renders a single spider finding: severity-coloured header
// with class FQN, then an indented key=value block per captured field.
func printStructured(w io.Writer, sf spiders.Finding, f *scanFlags, diff *diffState) {
	sev := spiderSevToScanner(sf.Severity)
	open, close := sevStyle(sev, f.noColor)
	bold := ""
	reset := ""
	if !f.noColor {
		bold = cBold
		reset = cReset
	}
	marker := ""
	if diff != nil && diff.enabled {
		marker = formatDiffMarker(diff.markStruct(sf.Spider, sf.ClassFQN, sf.ObjectID), f.noColor) + " "
	}
	fmt.Fprintf(w, "  %s%s[%s]%s %s%s%s\n",
		marker, open, sev, close, bold, sf.Title, reset)
	fmt.Fprintf(w, "      %sclass:%s %s   %sobject:%s 0x%x\n",
		dimOnly(!f.noColor), resetOnly(!f.noColor), sf.ClassFQN,
		dimOnly(!f.noColor), resetOnly(!f.noColor), sf.ObjectID)
	for _, kv := range sf.Fields {
		val := kv.Value
		if f.mask && looksSensitive(kv.Name) {
			val = maskSecret(val, 2, 2)
		}
		val = oneLine(val, truncLen(f, false))
		fmt.Fprintf(w, "      %s%-22s%s  %s\n",
			dimOnly(!f.noColor), kv.Name, resetOnly(!f.noColor), val)
	}
	fmt.Fprintln(w)
}

// looksSensitive decides which structured-field names get masked under --mask.
// Keep non-credential fields (url, driverClassName) in plain text.
func looksSensitive(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") ||
		strings.Contains(n, "secret") ||
		strings.Contains(n, "key") ||
		strings.Contains(n, "token")
}

func printFinding(w io.Writer, em enrichedMatch, f *scanFlags, labelWidth int, diff *diffState) {
	label := em.m.Pattern.Name + ":"
	padding := labelWidth - len(label)
	if padding < 1 {
		padding = 1
	}

	// Diff tag before the label — keeps the value column aligned.
	marker := ""
	if diff != nil && diff.enabled {
		m := diff.markRegex(em.m.Pattern.Name, em.m.Value)
		marker = formatDiffMarker(m, f.noColor)
	}

	// Decoded form is the primary display value — what a pentester actually
	// cares about (cleartext creds, JWT claims). Raw encoded value becomes
	// secondary and is only shown in verbose mode.
	//
	// --mask masks BOTH: the decoded value stays the primary line (so the
	// user still sees what kind of secret it is), but it's obfuscated with
	// a shape-aware strategy. Raw is also masked when shown in verbose.
	hasDecoded := em.dec != nil
	var primary string
	switch {
	case f.mask && hasDecoded:
		primary = maskDecoded(em.dec.Kind, em.dec.Text)
	case f.mask:
		primary = maskForPattern(em.m.Pattern.Name, em.m.Value)
	case hasDecoded:
		primary = em.dec.Text
	default:
		primary = em.m.Value
	}
	primary = oneLine(primary, truncLen(f, hasDecoded && !f.mask))

	sevOpen, sevClose := sevStyle(em.m.Pattern.Severity, f.noColor)
	fmt.Fprintf(w, "  %s%s%s%s%s  %s", marker, sevOpen, label, sevClose, strings.Repeat(" ", padding), primary)

	// Count suffix goes AFTER the value so the value column stays aligned
	// and `(xN)` reads as a multiplier on the secret itself.
	if em.m.Count > 1 {
		fmt.Fprintf(w, " %s(x%d)%s", dimOnly(!f.noColor), em.m.Count, resetOnly(!f.noColor))
	}

	if f.verbose {
		fmt.Fprintf(w, "   %s@ 0x%x%s", dimOnly(!f.noColor), em.m.Offset, resetOnly(!f.noColor))
	}
	fmt.Fprintln(w)

	// Verbose: show the raw source value under the decoded primary line, so
	// the analyst can tie the finding back to exact bytes in the dump.
	if hasDecoded && f.verbose {
		var raw string
		if f.mask {
			raw = maskForPattern(em.m.Pattern.Name, em.m.Value)
		} else {
			raw = em.m.Value
		}
		raw = oneLine(raw, truncLen(f, false))
		fmt.Fprintf(w, "  %s%sraw: %s%s\n",
			strings.Repeat(" ", labelWidth+2), dimOnly(!f.noColor), raw, resetOnly(!f.noColor))
	}
}

// truncLen computes the per-value truncation budget. Decoded values get a
// larger budget because they are already human-readable (JWT claims expand
// across several fields).
func truncLen(f *scanFlags, decoded bool) int {
	if f.maxValue <= 0 {
		return 1 << 30
	}
	base := f.maxValue
	if decoded {
		base *= 3
	}
	if f.verbose {
		base *= 2
	}
	return base
}

func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if max > 0 && len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func dimOnly(on bool) string {
	if on {
		return cDim
	}
	return ""
}

func resetOnly(on bool) string {
	if on {
		return cReset
	}
	return ""
}
