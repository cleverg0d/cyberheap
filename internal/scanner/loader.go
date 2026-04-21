package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoadPatternsTOML parses a gitleaks-compatible TOML file and returns
// pattern definitions ready to plug into Options.Patterns.
//
// Supported shape (accepts a proper subset of gitleaks.toml):
//
//	[[rules]]
//	id          = "custom-internal-token"     # required — our Pattern.Name
//	description = "Acme internal token"        # optional, not displayed
//	regex       = '''acme_[A-Za-z0-9]{32}'''   # required
//	secretGroup = 0                            # optional, 0 = whole match
//	severity    = "HIGH"                       # extension: critical|high|medium|low|info
//	category    = "credentials"                # extension: our Category string
//
//	[rules.allowlist]
//	regexes   = ['''EXAMPLE''', '''DEMO''']    # skip any match matching these
//	stopwords = ["example", "fake"]             # case-insensitive substrings to skip
//
// gitleaks' `entropy`, `keywords`, and `paths` fields are accepted but
// ignored — CyberHeap scans opaque heap bytes so path filtering is
// irrelevant and entropy filtering would need per-match shim that's
// usually counterproductive on the structured regexes we ship.
// LoadWarnings returned alongside LoadPatternsTOML (when non-empty) tells
// the user about gitleaks-only fields we accepted but don't honour, so a
// `entropy = 4.0` line doesn't silently go nowhere.
type LoadWarnings []string

// LoadPatternsTOML parses a gitleaks-compatible TOML file. If some fields
// in the file have no effect in CyberHeap (currently: `keywords`,
// `entropy`, `paths`), they are surfaced through the returned LoadWarnings
// instead of being silently dropped.
func LoadPatternsTOML(path string) ([]*Pattern, LoadWarnings, error) {
	var cfg tomlConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, nil, fmt.Errorf("load %s: %w", path, err)
	}
	out := make([]*Pattern, 0, len(cfg.Rules))
	var warnings LoadWarnings
	for i, r := range cfg.Rules {
		p, err := compileRule(r)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: rule #%d (id=%q): %w", path, i, r.ID, err)
		}
		out = append(out, p)
		if len(r.Keywords) > 0 {
			warnings = append(warnings,
				fmt.Sprintf("%s: rule %q sets `keywords` — CyberHeap ignores this field (RE2 is fast enough not to need keyword pre-filtering)", path, r.ID))
		}
		if r.Entropy > 0 {
			warnings = append(warnings,
				fmt.Sprintf("%s: rule %q sets `entropy = %g` — CyberHeap doesn't apply entropy filtering; use an allowlist regex instead if you need low-entropy matches dropped", path, r.ID, r.Entropy))
		}
		if len(r.Allowlist.Paths) > 0 {
			warnings = append(warnings,
				fmt.Sprintf("%s: rule %q sets `allowlist.paths` — CyberHeap scans heap bytes, not filesystem paths; this field has no effect", path, r.ID))
		}
	}
	return out, warnings, nil
}

type tomlConfig struct {
	Rules []tomlRule `toml:"rules"`
}

type tomlRule struct {
	ID          string        `toml:"id"`
	Description string        `toml:"description"`
	Regex       string        `toml:"regex"`
	SecretGroup int           `toml:"secretGroup"`
	Severity    string        `toml:"severity"`
	Category    string        `toml:"category"`
	MaxLen      int           `toml:"maxLen"`
	Allowlist   tomlAllowlist `toml:"allowlist"`
	// Silently accepted but unused — keep parsing so real gitleaks.toml
	// files don't need to be stripped before use.
	Keywords []string `toml:"keywords"`
	Entropy  float64  `toml:"entropy"`
}

type tomlAllowlist struct {
	Regexes   []string `toml:"regexes"`
	Stopwords []string `toml:"stopwords"`
	Paths     []string `toml:"paths"` // unused — we don't have a path axis in heap data
}

func compileRule(r tomlRule) (*Pattern, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	if r.Regex == "" {
		return nil, fmt.Errorf("missing regex")
	}
	re, err := regexp.Compile(r.Regex)
	if err != nil {
		return nil, fmt.Errorf("bad regex: %w", err)
	}
	sev := SeverityHigh
	if r.Severity != "" {
		if s, ok := ParseSeverity(r.Severity); ok {
			sev = s
		} else {
			return nil, fmt.Errorf("unknown severity %q", r.Severity)
		}
	}
	cat := CatCredentials
	if r.Category != "" {
		cat = Category(r.Category)
	}
	maxLen := r.MaxLen
	if maxLen == 0 {
		maxLen = 2048
	}
	p := &Pattern{
		Name:         r.ID,
		Category:     cat,
		Severity:     sev,
		re:           re,
		captureGroup: r.SecretGroup,
		maxLen:       maxLen,
	}
	if len(r.Allowlist.Regexes) > 0 || len(r.Allowlist.Stopwords) > 0 {
		filter, err := buildAllowFilter(r.Allowlist)
		if err != nil {
			return nil, fmt.Errorf("allowlist: %w", err)
		}
		p.postFilter = filter
	}
	return p, nil
}

// buildAllowFilter produces a postFilter that returns false (drop) when
// the match hits the allowlist. Both regexes (match anywhere in the
// value) and stopwords (case-insensitive substring) are supported.
func buildAllowFilter(a tomlAllowlist) (func([]byte) bool, error) {
	var allowRe []*regexp.Regexp
	for _, r := range a.Regexes {
		c, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("allowlist regex %q: %w", r, err)
		}
		allowRe = append(allowRe, c)
	}
	stops := make([]string, 0, len(a.Stopwords))
	for _, s := range a.Stopwords {
		if s == "" {
			continue
		}
		stops = append(stops, strings.ToLower(s))
	}
	return func(value []byte) bool {
		for _, re := range allowRe {
			if re.Match(value) {
				return false
			}
		}
		if len(stops) > 0 {
			lower := strings.ToLower(string(value))
			for _, s := range stops {
				if strings.Contains(lower, s) {
					return false
				}
			}
		}
		return true
	}, nil
}

// MergePatterns stacks user-loaded patterns on top of builtins.
// Duplicate IDs override built-ins so users can shadow ours with a
// tightened version if our default is too noisy for their corpus.
func MergePatterns(builtin, extra []*Pattern) []*Pattern {
	byName := make(map[string]*Pattern, len(builtin)+len(extra))
	order := make([]string, 0, len(builtin)+len(extra))
	for _, p := range builtin {
		if _, seen := byName[p.Name]; !seen {
			order = append(order, p.Name)
		}
		byName[p.Name] = p
	}
	for _, p := range extra {
		if _, seen := byName[p.Name]; !seen {
			order = append(order, p.Name)
		}
		byName[p.Name] = p
	}
	out := make([]*Pattern, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}
