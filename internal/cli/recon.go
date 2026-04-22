package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/recon"
)

type reconFlags struct {
	wordlistFile string
	concurrency  int
	timeout      time.Duration
	showAuth     bool
	showAll      bool
	noAutoScan   bool

	// Passed through to the auto-scan of a downloaded heap dump.
	verifyCreds bool
	offline     bool
	dnsServer   string
	format      string
	outputDir   string
}

func newReconCmd() *cobra.Command {
	var f reconFlags
	cmd := &cobra.Command{
		Use:   "recon <host|url>",
		Short: "Probe common actuator / JMX paths on a target; auto-scan any exposed heap dump",
		Long: `Recon walks a curated list of Spring Boot actuator / debug / Jolokia paths
against the target, reports which ones are reachable, and if /actuator/heapdump
responds with a downloadable dump it hands the file off to the scan pipeline
automatically.

No RCE primitives are attempted. /env POST injection, /gateway route poisoning
and Jolokia exploits are out of scope — use dedicated tooling for that.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecon(cmd, args[0], &f)
		},
	}
	cmd.Flags().StringVarP(&f.wordlistFile, "wordlist", "w", "", "path to a wordlist file (one path per line); overrides built-in list")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 12, "parallel probe requests")
	cmd.Flags().DurationVarP(&f.timeout, "timeout", "t", 5*time.Second, "per-probe HTTP timeout")
	cmd.Flags().BoolVar(&f.showAuth, "show-auth", false, "also show 401/403 results (endpoint exists but requires auth)")
	cmd.Flags().BoolVar(&f.showAll, "show-all", false, "show every response code incl. 404 (very noisy)")
	cmd.Flags().BoolVar(&f.noAutoScan, "no-auto-scan", false, "skip the automatic scan of a downloaded heap dump")

	// Pass-through to the auto-scan stage.
	cmd.Flags().BoolVarP(&f.verifyCreds, "verify-creds", "C", false, "when auto-scanning, actively validate credentials")
	cmd.Flags().BoolVar(&f.offline, "offline", false, "when auto-scanning, skip all network verification")
	cmd.Flags().StringVar(&f.dnsServer, "dns", "1.1.1.1", "when auto-scanning, DNS server for verification")
	cmd.Flags().StringVarP(&f.format, "format", "f", "pretty", "when auto-scanning, output format: pretty, json, markdown")
	cmd.Flags().StringVarP(&f.outputDir, "output", "o", "", "when auto-scanning, save JSON report to DIR/<target>.json")
	return cmd
}

func runRecon(cmd *cobra.Command, target string, f *reconFlags) error {
	paths := recon.DefaultPaths()
	if f.wordlistFile != "" {
		fp, err := os.Open(f.wordlistFile)
		if err != nil {
			return fmt.Errorf("open wordlist: %w", err)
		}
		defer fp.Close()
		paths = recon.LoadWordlist(fp)
		if len(paths) == 0 {
			return fmt.Errorf("wordlist %s is empty", f.wordlistFile)
		}
	}

	show := map[int]bool{200: true}
	if f.showAuth {
		show[401] = true
		show[403] = true
	}
	if f.showAll {
		show = nil // Run treats empty as "200 only" — we need all, build it manually
		show = map[int]bool{}
		for i := 100; i < 600; i++ {
			show[i] = true
		}
		show[0] = true // network errors
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(cmd.Context(), f.timeout*time.Duration(len(paths)+8))
	defer cancel()

	opts := recon.Options{
		BaseURL:      target,
		Paths:        paths,
		Concurrency:  f.concurrency,
		Timeout:      f.timeout,
		ShowStatuses: show,
	}
	shown, all, err := recon.Run(ctx, opts)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	w := cmd.OutOrStdout()
	noColor := f.format != "pretty" || os.Getenv("NO_COLOR") != ""
	printReconResults(w, target, shown, paths, elapsed, f, noColor)

	if f.noAutoScan {
		return nil
	}

	// If any probed path advertises a heapdump, grab it and hand off
	// to the existing scan pipeline. Pass the first LIVE heapdump
	// discovered.
	for i := range all {
		if all[i].HeapdumpHit() {
			return autoScanHeapdump(cmd, &all[i], f)
		}
	}
	return nil
}

func printReconResults(w io.Writer, target string, shown []Result, allPaths []string, elapsed time.Duration, f *reconFlags, noColor bool) {
	if !noColor {
		// Reuse the existing banner for a consistent look.
		fmt.Fprint(w, banner(Version, false))
		fmt.Fprintln(w)
	}
	dim := dimOnly(!noColor)
	reset := resetOnly(!noColor)

	fmt.Fprintln(w, kvLine("target", target, noColor))
	fmt.Fprintln(w, kvLine("paths", fmt.Sprintf("%d probed in %s", len(allPaths), elapsed.Round(time.Millisecond)), noColor))

	if len(shown) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  no live endpoints (use --show-auth or --show-all for broader view)")
		return
	}

	// Align columns by the longest path string.
	maxPath := 0
	for _, r := range shown {
		if len(r.Path) > maxPath {
			maxPath = len(r.Path)
		}
	}
	if maxPath > 48 {
		maxPath = 48
	}

	fmt.Fprintln(w)
	for _, r := range shown {
		size := ""
		if r.Size > 0 {
			size = humanBytesInt(r.Size)
		}
		line := fmt.Sprintf("  %s %-*s  %s%s%s",
			statusBadge(r.Status, noColor),
			maxPath, r.Path,
			dim, r.ContentType, reset,
		)
		if size != "" {
			line += fmt.Sprintf("  %s%s%s", dim, size, reset)
		}
		if r.Note != "" {
			line += "  " + dim + "· " + r.Note + reset
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

// Result here aliases recon.Result so the pretty-printer stays in the
// cli package without exposing internal recon types into the public API.
type Result = recon.Result

func statusBadge(code int, noColor bool) string {
	label := fmt.Sprintf("[%d]", code)
	if code == 0 {
		label = "[ERR]"
	}
	if noColor {
		return label
	}
	var color string
	switch {
	case code >= 200 && code < 300:
		color = cBGreen
	case code >= 300 && code < 400:
		color = cBCyan
	case code == 401 || code == 403:
		color = cYellow
	case code >= 400 && code < 500:
		color = cDim
	case code >= 500:
		color = cBRed
	default:
		color = cDim
	}
	return color + label + cReset
}

func humanBytesInt(n int64) string {
	switch {
	case n > 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n > 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n > 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// autoScanHeapdump downloads the hit to a temp file and runs the
// standard scan pipeline against it, reusing all existing rendering.
func autoScanHeapdump(cmd *cobra.Command, hit *Result, f *reconFlags) error {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "  ↓ downloading %s ... ", hit.URL)

	tmp, err := os.CreateTemp("", "cyberheap-recon-*.hprof")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	dlCtx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()
	n, err := recon.DownloadHeapdump(dlCtx, hit.URL, tmp.Name(), "cyberheap/recon", 10*time.Minute)
	if err != nil {
		fmt.Fprintf(w, "failed: %v\n\n", err)
		return nil
	}
	fmt.Fprintf(w, "%s saved to %s\n\n", humanBytesInt(n), filepath.Base(tmp.Name()))

	sf := &scanFlags{
		format:        f.format,
		outputDir:     f.outputDir,
		doVerifyCreds: f.verifyCreds,
		offline:       f.offline,
		dnsServer:     f.dnsServer,
		timeout:       f.timeout,
		minCount:      1,
	}
	sf.noColor = os.Getenv("NO_COLOR") != "" || strings.ToLower(f.format) != "pretty"
	return runScan(cmd, tmp.Name(), sf)
}
