package cli

import (
	"fmt"
	"os"

	"github.com/cleverg0d/cyberheap/internal/scanner"
)

// resolvePatternSet loads user-supplied TOML rule files and merges them
// with CyberHeap's built-in regex catalogue. Returns nil to signal
// "use defaults" (scanner.Scan interprets a nil slice as built-ins).
//
// Behavior:
//
//	patternFiles == []           → return nil (use built-ins)
//	patternFiles + patternsOnly   → return ONLY user-loaded patterns
//	patternFiles without the flag → merge user-loaded on top of built-ins
//	                                (user IDs with same name override built-ins)
func resolvePatternSet(patternFiles []string, onlyCustom bool) ([]*scanner.Pattern, error) {
	if len(patternFiles) == 0 {
		return nil, nil
	}
	var loaded []*scanner.Pattern
	for _, p := range patternFiles {
		rules, warnings, err := scanner.LoadPatternsTOML(p)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("--patterns %s: no rules found", p)
		}
		// Surface "accepted-but-ignored" gitleaks fields so the user
		// doesn't quietly lose a filter they expected.
		for _, w := range warnings {
			fmt.Fprintln(os.Stderr, "  warning:", w)
		}
		loaded = append(loaded, rules...)
	}
	if onlyCustom {
		return loaded, nil
	}
	return scanner.MergePatterns(scanner.BuiltinPatterns(), loaded), nil
}
