package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cleverg0d/cyberheap/internal/spiders"
)

// savedFinding is the per-finding record persisted to disk.
type savedFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	Value       string `json:"value"`
	Offset      int64  `json:"offset"`
	Count       int    `json:"count"`
	DecodedKind string `json:"decoded_kind,omitempty"`
	DecodedText string `json:"decoded_text,omitempty"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// savedStructured is a persisted spider finding.
type savedStructured struct {
	Severity  string            `json:"severity"`
	Category  string            `json:"category"`
	Spider    string            `json:"spider"`
	Title     string            `json:"title"`
	ClassFQN  string            `json:"class_fqn"`
	ObjectID  string            `json:"object_id"`
	Fields    map[string]string `json:"fields"`
	FirstSeen string            `json:"first_seen"`
	LastSeen  string            `json:"last_seen"`
}

// savedReport is the on-disk shape for a target's rolling report. Multiple
// scans against the same target merge into the same file, deduplicating
// findings by (pattern, value) for regex hits and by (spider, class, object)
// for structured hits.
type savedReport struct {
	Target     string            `json:"target"`
	Runs       int               `json:"runs"`
	FirstScan  string            `json:"first_scan"`
	LastScan   string            `json:"last_scan"`
	LastFile   string            `json:"last_source_file,omitempty"`
	Findings   []savedFinding    `json:"findings"`
	Structured []savedStructured `json:"structured,omitempty"`
}

// saveReport writes (or merges) the scan findings to outputDir/<safeName>.json.
// Returns the path that was written and a summary of new/updated counts.
func saveReport(outputDir, safeName, displayName string, items []enrichedMatch, spFindings []spiders.Finding) (path string, added, updated int, err error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", 0, 0, fmt.Errorf("mkdir %s: %w", outputDir, err)
	}

	path = filepath.Join(outputDir, safeName+".json")
	now := time.Now().UTC().Format(time.RFC3339)

	// Load existing report if any.
	report := savedReport{Target: safeName, FirstScan: now}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &report)
	}
	report.Runs++
	report.LastScan = now
	report.LastFile = displayName

	// Index existing findings by (pattern, value) for merge.
	type key struct{ pat, val string }
	idx := map[key]int{}
	for i, f := range report.Findings {
		idx[key{f.Pattern, f.Value}] = i
	}

	for _, em := range items {
		k := key{em.m.Pattern.Name, em.m.Value}
		sf := savedFinding{
			Severity: em.m.Pattern.Severity.String(),
			Category: string(em.m.Pattern.Category),
			Pattern:  em.m.Pattern.Name,
			Value:    em.m.Value,
			Offset:   em.m.Offset,
			Count:    em.m.Count,
			LastSeen: now,
		}
		if em.dec != nil {
			sf.DecodedKind = em.dec.Kind
			sf.DecodedText = em.dec.Text
		}
		if i, ok := idx[k]; ok {
			// Preserve first_seen from the existing record, roll forward counts.
			existing := report.Findings[i]
			sf.FirstSeen = existing.FirstSeen
			if sf.Count < existing.Count {
				sf.Count = existing.Count
			}
			report.Findings[i] = sf
			updated++
		} else {
			sf.FirstSeen = now
			report.Findings = append(report.Findings, sf)
			added++
		}
	}

	// Structured findings: merge by (spider, class, objectID).
	type skey struct{ spider, class, obj string }
	sidx := map[skey]int{}
	for i, s := range report.Structured {
		sidx[skey{s.Spider, s.ClassFQN, s.ObjectID}] = i
	}
	for _, sf := range spFindings {
		fm := make(map[string]string, len(sf.Fields))
		for _, kv := range sf.Fields {
			fm[kv.Name] = kv.Value
		}
		ss := savedStructured{
			Severity: spiderSevToScannerName(sf.Severity),
			Category: sf.Category,
			Spider:   sf.Spider,
			Title:    sf.Title,
			ClassFQN: sf.ClassFQN,
			ObjectID: fmt.Sprintf("0x%x", sf.ObjectID),
			Fields:   fm,
			LastSeen: now,
		}
		k := skey{sf.Spider, sf.ClassFQN, ss.ObjectID}
		if i, ok := sidx[k]; ok {
			ss.FirstSeen = report.Structured[i].FirstSeen
			report.Structured[i] = ss
			updated++
		} else {
			ss.FirstSeen = now
			report.Structured = append(report.Structured, ss)
			added++
		}
	}

	// Stable, reader-friendly ordering.
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		return a.Value < b.Value
	})
	sort.Slice(report.Structured, func(i, j int) bool {
		a, b := report.Structured[i], report.Structured[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Spider != b.Spider {
			return a.Spider < b.Spider
		}
		return a.ClassFQN < b.ClassFQN
	})

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", 0, 0, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", 0, 0, fmt.Errorf("write %s: %w", path, err)
	}
	return path, added, updated, nil
}

func spiderSevToScannerName(s spiders.Severity) string {
	switch s {
	case spiders.SeverityCritical:
		return "CRITICAL"
	case spiders.SeverityHigh:
		return "HIGH"
	case spiders.SeverityMedium:
		return "MEDIUM"
	case spiders.SeverityLow:
		return "LOW"
	}
	return "INFO"
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}
