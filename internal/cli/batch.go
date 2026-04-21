package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
	"github.com/cleverg0d/cyberheap/internal/scanner"
	"github.com/cleverg0d/cyberheap/internal/spiders"
)

// newBatchCmd wires `cyberheap batch` for scanning many dumps at once.
//
// Typical pentest: a client hands over 10 heap dumps from different
// instances and we want one summary plus per-file JSON evidence. Shell
// glob does the file expansion; this command handles the aggregation.
func newBatchCmd() *cobra.Command {
	var f batchFlags
	cmd := &cobra.Command{
		Use:   "batch <file.hprof> [more.hprof ...]",
		Short: "Scan several HPROF files and print an aggregate summary",
		Long: `Iterate over the supplied HPROF files, run the full scan pipeline on
each, and emit an aggregate severity table at the end.

Typical use:

  cyberheap batch dumps/*.hprof -o ./reports --severity=critical,high

Each dump's findings go into a separate JSON report in -o DIR (named
after the source filename). The stdout output is a compact
"filename → counts" table plus the totals across all files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBatch(cmd, args, &f)
		},
	}
	cmd.Flags().StringSliceVar(&f.severities, "severity", nil, "filter (critical,high,medium,low,info)")
	cmd.Flags().StringSliceVar(&f.categories, "category", nil, "filter by category")
	cmd.Flags().BoolVar(&f.noRegex, "no-regex", false, "skip the regex pass")
	cmd.Flags().BoolVar(&f.noSpiders, "no-spiders", false, "skip the structured pass")
	cmd.Flags().BoolVar(&f.utf16, "utf16", false, "also scan a UTF-16LE view")
	cmd.Flags().BoolVar(&f.mask, "mask", false, "mask secret values in per-file reports")
	cmd.Flags().StringVarP(&f.outputDir, "output", "o", "", "save per-file JSON reports to DIR")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable ANSI colors")
	cmd.Flags().BoolVar(&f.noBanner, "no-banner", false, "suppress the banner")
	cmd.Flags().BoolVar(&f.failOnCritical, "fail-on-critical", false, "exit non-zero if any CRITICAL finding was produced (CI-friendly)")
	return cmd
}

type batchFlags struct {
	severities     []string
	categories     []string
	noRegex        bool
	noSpiders      bool
	utf16          bool
	mask           bool
	outputDir      string
	noColor        bool
	noBanner       bool
	failOnCritical bool
}

// batchRow is one dump's entry in the summary table.
type batchRow struct {
	file         string
	sizeBytes    int64
	elapsed      time.Duration
	regexTotal   int
	spiderTotal  int
	bySev        map[scanner.Severity]int
	savedPath    string
	savedAdded   int
	savedUpdated int
	err          error
}

func runBatch(cmd *cobra.Command, files []string, f *batchFlags) error {
	f.noColor = f.noColor || os.Getenv("NO_COLOR") != ""

	w := cmd.OutOrStdout()
	if !f.noBanner {
		fmt.Fprint(w, banner(Version, f.noColor))
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  batch scan: %d file(s)\n\n", len(files))

	sevSet, err := parseSeverities(f.severities)
	if err != nil {
		return err
	}
	catSet, err := parseCategories(f.categories)
	if err != nil {
		return err
	}

	rows := make([]batchRow, 0, len(files))
	totals := map[scanner.Severity]int{}
	totalRegex, totalSpider := 0, 0
	anyCritical := false
	startAll := time.Now()

	for _, path := range files {
		row := scanOne(path, sevSet, catSet, f)
		rows = append(rows, row)
		if row.err == nil {
			totalRegex += row.regexTotal
			totalSpider += row.spiderTotal
			for s, n := range row.bySev {
				totals[s] += n
			}
			if row.bySev[scanner.SeverityCritical] > 0 {
				anyCritical = true
			}
		}
	}

	printBatchTable(w, rows, f)
	printBatchTotals(w, totalRegex, totalSpider, totals, time.Since(startAll), f)

	if f.failOnCritical && anyCritical {
		return fmt.Errorf("batch: one or more files produced CRITICAL findings")
	}
	return nil
}

func scanOne(path string, sevSet scanner.SeveritySet, catSet scanner.CategorySet, f *batchFlags) batchRow {
	row := batchRow{file: path, bySev: map[scanner.Severity]int{}}

	file, err := os.Open(path)
	if err != nil {
		row.err = err
		return row
	}
	defer file.Close()

	st, _ := file.Stat()
	if st != nil {
		row.sizeBytes = st.Size()
	}
	if _, err := hprof.ParseHeader(file); err != nil {
		row.err = err
		return row
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		row.err = err
		return row
	}

	start := time.Now()

	var enriched []enrichedMatch
	var spFindings []spiders.Finding

	if !f.noRegex {
		matches, serr := scanner.Scan(file, scanner.Options{
			Severities: sevSet,
			Categories: catSet,
			ScanUTF16:  f.utf16,
		})
		if serr != nil {
			row.err = serr
			return row
		}
		enriched = enrich(matches)
		row.regexTotal = len(enriched)
	}
	if !f.noSpiders {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			row.err = err
			return row
		}
		idx, ierr := heap.Build(file)
		if ierr == nil {
			for _, sp := range spiders.Registry() {
				spFindings = append(spFindings, sp.Sniff(idx)...)
			}
			spFindings = filterSpiderFindings(spFindings, sevSet, catSet)
		}
		row.spiderTotal = len(spFindings)
	}

	row.elapsed = time.Since(start)
	for _, em := range enriched {
		row.bySev[em.m.Pattern.Severity]++
	}
	for _, sf := range spFindings {
		row.bySev[spiderSevToScanner(sf.Severity)]++
	}

	if f.outputDir != "" {
		slug := slugForFilename(filepath.Base(path))
		savedPath, added, updated, serr := saveReport(f.outputDir, slug, path, enriched, spFindings)
		if serr == nil {
			row.savedPath = savedPath
			row.savedAdded = added
			row.savedUpdated = updated
		}
	}
	return row
}

func printBatchTable(w io.Writer, rows []batchRow, f *batchFlags) {
	fmt.Fprintln(w, "  results:")
	fmt.Fprintln(w)
	// Fixed column layout: file | size | elapsed | per-sev counters.
	nameWidth := 36
	for _, r := range rows {
		base := filepath.Base(r.file)
		if len(base) > nameWidth {
			nameWidth = len(base)
		}
	}
	if nameWidth > 60 {
		nameWidth = 60
	}
	for _, r := range rows {
		name := filepath.Base(r.file)
		if len(name) > nameWidth {
			name = "..." + name[len(name)-nameWidth+3:]
		}
		if r.err != nil {
			fmt.Fprintf(w, "  %-*s  %serror: %v%s\n",
				nameWidth, name, dimOnly(!f.noColor), r.err, resetOnly(!f.noColor))
			continue
		}
		parts := []string{}
		for _, sev := range allSeverities {
			n := r.bySev[sev]
			if n == 0 {
				continue
			}
			open, close := sevStyle(sev, f.noColor)
			parts = append(parts, fmt.Sprintf("%s%s:%d%s", open, sev, n, close))
		}
		sevLine := strings.Join(parts, " ")
		fmt.Fprintf(w, "  %-*s  %s   %s   %s\n",
			nameWidth, name,
			humanBytes(r.sizeBytes),
			r.elapsed.Round(time.Millisecond),
			sevLine)
		if r.savedPath != "" {
			fmt.Fprintf(w, "  %s%s  saved %s (+%d new, %d updated)%s\n",
				strings.Repeat(" ", nameWidth), dimOnly(!f.noColor),
				r.savedPath, r.savedAdded, r.savedUpdated, resetOnly(!f.noColor))
		}
	}
	fmt.Fprintln(w)
}

func printBatchTotals(w io.Writer, totalRegex, totalSpider int, totals map[scanner.Severity]int, totalElapsed time.Duration, f *batchFlags) {
	// Sort severities by value desc for readable "worst first" row.
	keys := make([]scanner.Severity, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

	parts := []string{}
	for _, k := range keys {
		open, close := sevStyle(k, f.noColor)
		parts = append(parts, fmt.Sprintf("%s%d %s%s", open, totals[k], k, close))
	}
	grand := totalRegex + totalSpider
	if grand == 0 {
		fmt.Fprintln(w, "  totals:      0 findings across all files")
	} else {
		fmt.Fprintf(w, "  totals:      %d findings (regex %d + structured %d)   %s\n",
			grand, totalRegex, totalSpider, strings.Join(parts, "  "))
	}
	fmt.Fprintf(w, "  wall time:   %s\n", totalElapsed.Round(time.Millisecond))
}
