package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
)

type infoFlags struct {
	asJSON   bool
	deep     bool
	topN     int
	noBanner bool
	noColor  bool
	grep     string
}

func newInfoCmd() *cobra.Command {
	var f infoFlags
	cmd := &cobra.Command{
		Use:   "info <file.hprof | http(s)://host/...>",
		Short: "Show HPROF file metadata and (with --deep) class/instance statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(cmd, args[0], &f)
		},
	}
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "emit JSON instead of pretty text")
	cmd.Flags().BoolVar(&f.deep, "deep", false, "parse the full dump to show class/instance stats (slower)")
	cmd.Flags().IntVar(&f.topN, "top", 15, "how many most-populated classes to show in --deep mode")
	cmd.Flags().BoolVar(&f.noBanner, "no-banner", false, "suppress the banner")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable ANSI colors")
	cmd.Flags().StringVar(&f.grep, "grep", "", "case-insensitive substring filter over class FQNs (implies --deep)")
	return cmd
}

type infoOutput struct {
	File           string `json:"file"`
	SizeBytes      int64  `json:"size_bytes"`
	FormatVersion  string `json:"format_version"`
	IDSize         int    `json:"id_size"`
	TimestampISO   string `json:"timestamp_iso"`
	TimestampEpoch int64  `json:"timestamp_unix_ms"`
	HeaderLen      int64  `json:"header_len"`

	// --deep fields.
	TagCounts      map[string]int  `json:"tag_counts,omitempty"`
	Strings        int             `json:"strings,omitempty"`
	Classes        int             `json:"classes,omitempty"`
	TotalInstances int             `json:"total_instances,omitempty"`
	TopClasses     []topClassEntry `json:"top_classes,omitempty"`
	ParseElapsedMs int64           `json:"parse_elapsed_ms,omitempty"`
}

type topClassEntry struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func runInfo(cmd *cobra.Command, arg string, f *infoFlags) error {
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

	out := infoOutput{
		File:           tgt.displayName,
		SizeBytes:      tgt.size,
		FormatVersion:  h.Version.String(),
		IDSize:         h.IDSize,
		TimestampISO:   h.Timestamp.Format("2006-01-02 15:04:05 MST"),
		TimestampEpoch: h.Timestamp.UnixMilli(),
		HeaderLen:      h.HeaderLen,
	}

	var idx *heap.Index
	if f.grep != "" {
		f.deep = true
	}
	if f.deep {
		start := time.Now()
		mi, err := buildIndex(tgt)
		if err != nil {
			return fmt.Errorf("index: %w", err)
		}
		defer mi.Close()
		idx = mi.Index
		out.ParseElapsedMs = time.Since(start).Milliseconds()
		out.Strings = len(idx.Strings)
		out.Classes = len(idx.Classes)
		out.TotalInstances = idx.TotalInstances
		out.TagCounts = tagCountsStringKeys(idx.TagCounts)
		for _, cs := range idx.TopClassesByInstances(f.topN) {
			out.TopClasses = append(out.TopClasses, topClassEntry{Name: cs.Name, Count: cs.Count})
		}
	}

	w := cmd.OutOrStdout()
	if f.asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	return emitInfoPretty(w, tgt, h, idx, f)
}

func emitInfoPretty(w io.Writer, tgt *target, h *hprof.Header, idx *heap.Index, f *infoFlags) error {
	if !f.noBanner {
		fmt.Fprint(w, banner(Version, f.noColor))
		fmt.Fprintln(w)
	}

	targetKind := "file"
	if tgt.isRemote {
		targetKind = "url "
	}
	fmt.Fprintln(w, kvLine(targetKind, tgt.displayName, f.noColor))
	fmt.Fprintln(w, kvLine("size", fmt.Sprintf("%s (%d bytes)", humanBytes(tgt.size), tgt.size), f.noColor))
	fmt.Fprintln(w, kvLine("format", fmt.Sprintf("HPROF %s", h.Version.String()), f.noColor))
	fmt.Fprintln(w, kvLine("id-size", fmt.Sprintf("%d bytes", h.IDSize), f.noColor))
	fmt.Fprintln(w, kvLine("timestamp", h.Timestamp.Format("2006-01-02 15:04:05 MST"), f.noColor))
	fmt.Fprintln(w, kvLine("header", fmt.Sprintf("%d bytes", h.HeaderLen), f.noColor))

	if idx == nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, dimOnly(!f.noColor)+"  (use --deep to parse records, count classes and show top instance populations)"+resetOnly(!f.noColor))
		return nil
	}

	// Deep stats.
	fmt.Fprintln(w)
	fmt.Fprintln(w, kvLine("strings", fmt.Sprintf("%d", len(idx.Strings)), f.noColor))
	fmt.Fprintln(w, kvLine("classes", fmt.Sprintf("%d", len(idx.Classes)), f.noColor))
	fmt.Fprintln(w, kvLine("instances", fmt.Sprintf("%d", idx.TotalInstances), f.noColor))
	fmt.Fprintln(w, kvLine("sub-recs", fmt.Sprintf("%d", idx.SubRecordCount), f.noColor))

	// Tag breakdown — show top tags by count.
	fmt.Fprintln(w)
	fmt.Fprintln(w, dimOnly(!f.noColor)+"  record types:"+resetOnly(!f.noColor))
	for _, tc := range sortedTagCounts(idx.TagCounts) {
		fmt.Fprintf(w, "    %-22s  %d\n", tc.tag.String(), tc.count)
	}

	// Top classes OR a focused grep view.
	if f.grep != "" {
		needle := strings.ToLower(f.grep)
		type row struct {
			name  string
			count int
		}
		var rows []row
		for name, cd := range idx.ClassByName {
			if !strings.Contains(strings.ToLower(name), needle) {
				continue
			}
			rows = append(rows, row{name, len(idx.Instances[cd.ID])})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].count != rows[j].count {
				return rows[i].count > rows[j].count
			}
			return rows[i].name < rows[j].name
		})
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s  classes matching %q (%d total):%s\n",
			dimOnly(!f.noColor), f.grep, len(rows), resetOnly(!f.noColor))
		for _, r := range rows {
			fmt.Fprintf(w, "    %-70s  %d\n", truncateLeft(r.name, 70), r.count)
		}
		return nil
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s  top %d classes by instance count:%s\n",
		dimOnly(!f.noColor), f.topN, resetOnly(!f.noColor))
	for _, cs := range idx.TopClassesByInstances(f.topN) {
		fmt.Fprintf(w, "    %-60s  %d\n", truncateLeft(cs.Name, 60), cs.Count)
	}

	return nil
}

type tagCount struct {
	tag   hprof.Tag
	count int
}

func sortedTagCounts(m map[hprof.Tag]int) []tagCount {
	out := make([]tagCount, 0, len(m))
	for t, n := range m {
		out = append(out, tagCount{t, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].tag < out[j].tag
	})
	return out
}

func tagCountsStringKeys(m map[hprof.Tag]int) map[string]int {
	out := make(map[string]int, len(m))
	for t, n := range m {
		out[t.String()] = n
	}
	return out
}

func truncateLeft(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

// humanBytes converts a byte count into a human-readable string like
// "108.2 MiB" or "4.3 GiB". Lives here so cmd/scan and cmd/info can share it.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	suffix := "KMGTPE"[exp]
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), suffix)
}
