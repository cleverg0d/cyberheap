package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cleverg0d/cyberheap/internal/spiders"
)

// diffMarker tags each finding in output so a retest can spot the delta
// at a glance:
//
//	"+"  — new since the previous report
//	"="  — unchanged (same pattern + same value)
//	"-"  — appears only in --diff-against, missing from current scan
type diffMarker string

const (
	diffNew       diffMarker = "+"
	diffUnchanged diffMarker = "="
	diffGone      diffMarker = "-"
)

// diffState precomputes the marker lookup tables once per scan so we
// don't repeatedly scan the whole previous report per finding.
type diffState struct {
	enabled bool
	// Regex findings keyed by (pattern, value).
	prevRegex map[string]bool
	// Structured findings keyed by (spider, class, object_id).
	prevStruct map[string]bool
	// Gone findings — entries in previous that aren't in current.
	// Filled at emit time once we know the current-scan contents.
	goneRegex  []savedFinding
	goneStruct []savedStructured
}

func loadDiffState(path string) (*diffState, error) {
	if path == "" {
		return &diffState{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--diff-against %s: %w", path, err)
	}
	var rep savedReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("--diff-against %s: not a saved report: %w", path, err)
	}
	s := &diffState{
		enabled:    true,
		prevRegex:  make(map[string]bool, len(rep.Findings)),
		prevStruct: make(map[string]bool, len(rep.Structured)),
		goneRegex:  append([]savedFinding(nil), rep.Findings...),
		goneStruct: append([]savedStructured(nil), rep.Structured...),
	}
	for _, f := range rep.Findings {
		s.prevRegex[regexKey(f.Pattern, f.Value)] = true
	}
	for _, st := range rep.Structured {
		s.prevStruct[structKey(st.Spider, st.ClassFQN, st.ObjectID)] = true
	}
	return s, nil
}

func regexKey(pattern, value string) string {
	return pattern + "\x00" + value
}

func structKey(spider, class, objID string) string {
	return spider + "\x00" + class + "\x00" + objID
}

// markRegex returns the marker for a current-scan regex finding.
// Side effect: removes it from goneRegex so only truly-missing ones remain.
func (s *diffState) markRegex(pattern, value string) diffMarker {
	if !s.enabled {
		return ""
	}
	k := regexKey(pattern, value)
	if s.prevRegex[k] {
		s.removeGoneRegex(pattern, value)
		return diffUnchanged
	}
	return diffNew
}

func (s *diffState) markStruct(spider, class string, objID uint64) diffMarker {
	if !s.enabled {
		return ""
	}
	idStr := fmt.Sprintf("0x%x", objID)
	k := structKey(spider, class, idStr)
	if s.prevStruct[k] {
		s.removeGoneStruct(spider, class, idStr)
		return diffUnchanged
	}
	return diffNew
}

func (s *diffState) removeGoneRegex(pattern, value string) {
	for i, g := range s.goneRegex {
		if g.Pattern == pattern && g.Value == value {
			s.goneRegex = append(s.goneRegex[:i], s.goneRegex[i+1:]...)
			return
		}
	}
}

func (s *diffState) removeGoneStruct(spider, class, objID string) {
	for i, g := range s.goneStruct {
		if g.Spider == spider && g.ClassFQN == class && g.ObjectID == objID {
			s.goneStruct = append(s.goneStruct[:i], s.goneStruct[i+1:]...)
			return
		}
	}
}

// printGoneSection emits a terminal-friendly block for findings that were
// in the previous report but aren't in the current one. Called at the
// end of emitPretty when --diff-against is set.
func (s *diffState) printGoneSection(w io.Writer, noColor bool) {
	if !s.enabled || (len(s.goneRegex) == 0 && len(s.goneStruct) == 0) {
		return
	}
	fmt.Fprintln(w)
	header := "  CLOSED since previous scan"
	if !noColor {
		header = cDim + header + cReset
	}
	fmt.Fprintln(w, header)
	for _, g := range s.goneRegex {
		fmt.Fprintf(w, "    %s-%s %s: %s\n",
			dimOnly(!noColor), resetOnly(!noColor), g.Pattern, truncateToFit(g.Value, 80))
	}
	for _, g := range s.goneStruct {
		fmt.Fprintf(w, "    %s-%s %s @ %s\n",
			dimOnly(!noColor), resetOnly(!noColor), g.Title, g.ClassFQN)
	}
}

// Also used for spider-finding output.
// Convenience so spider printer can tag itself without threading enrichedMatch.
var _ = spiders.Finding{}

// formatDiffMarker renders a colored "+", "=", or "-" tag with one
// trailing space so output columns stay aligned whether --diff-against
// is used or not. Returns empty string when no diff is in effect.
func formatDiffMarker(m diffMarker, noColor bool) string {
	if m == "" {
		return ""
	}
	if noColor {
		return string(m) + " "
	}
	switch m {
	case diffNew:
		return cBGreen + "+" + cReset + " "
	case diffUnchanged:
		return cDim + "=" + cReset + " "
	case diffGone:
		return cBRed + "-" + cReset + " "
	}
	return string(m) + " "
}

func truncateToFit(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
