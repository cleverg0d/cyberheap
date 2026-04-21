package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTOML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.toml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestLoadPatternsTOML_MinimalRule(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
id = "acme-token"
regex = "acme_[A-Za-z0-9]{10}"
`)
	rules, _, err := LoadPatternsTOML(path)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "acme-token", rules[0].Name)
	assert.Equal(t, SeverityHigh, rules[0].Severity)   // default
	assert.Equal(t, CatCredentials, rules[0].Category) // default
	assert.True(t, rules[0].re.MatchString("acme_abc1234567"))
	assert.False(t, rules[0].re.MatchString("nope_abc1234567"))
}

func TestLoadPatternsTOML_RichRule(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
id = "acme-cloud-key"
description = "Acme Cloud API key"
regex = '''\bAKEY-[A-Z0-9]{20}\b'''
severity = "CRITICAL"
category = "cloud"
secretGroup = 0

[rules.allowlist]
regexes = ['''EXAMPLE''']
stopwords = ["dummy"]
`)
	rules, _, err := LoadPatternsTOML(path)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	r := rules[0]
	assert.Equal(t, "acme-cloud-key", r.Name)
	assert.Equal(t, SeverityCritical, r.Severity)
	assert.Equal(t, Category("cloud"), r.Category)
	assert.NotNil(t, r.postFilter)
	// Allowlist drops EXAMPLE-prefixed IDs and anything containing "dummy".
	assert.True(t, r.postFilter([]byte("AKEY-ABCDEFGHIJKLMNOPQRST")))
	assert.False(t, r.postFilter([]byte("AKEY-EXAMPLEABCDEFGHIJKL")))
	assert.False(t, r.postFilter([]byte("AKEY-AAAAAAAAAAAAdummy1")))
}

func TestLoadPatternsTOML_BadRegex(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
id = "broken"
regex = "acme_(unclosed"
`)
	_, _, err := LoadPatternsTOML(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad regex")
}

func TestLoadPatternsTOML_MissingID(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
regex = "."
`)
	_, _, err := LoadPatternsTOML(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing id")
}

func TestLoadPatternsTOML_UnknownSeverity(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
id = "x"
regex = "."
severity = "BANANA"
`)
	_, _, err := LoadPatternsTOML(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity")
}

func TestLoadPatternsTOML_MultipleRules(t *testing.T) {
	path := writeTOML(t, `
[[rules]]
id = "first"
regex = "first_[a-z]+"

[[rules]]
id = "second"
regex = "second_[0-9]+"
severity = "medium"
category = "scm"
`)
	rules, _, err := LoadPatternsTOML(path)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "first", rules[0].Name)
	assert.Equal(t, "second", rules[1].Name)
	assert.Equal(t, SeverityMedium, rules[1].Severity)
	assert.Equal(t, Category("scm"), rules[1].Category)
}

func TestMergePatterns_OverridesByName(t *testing.T) {
	builtin := BuiltinPatterns()[:2]
	override := *builtin[0]
	override.Severity = SeverityLow

	merged := MergePatterns(builtin, []*Pattern{&override})
	assert.Len(t, merged, 2)

	// First pattern should be overridden (same slot).
	var found bool
	for _, p := range merged {
		if p.Name == builtin[0].Name {
			assert.Equal(t, SeverityLow, p.Severity)
			found = true
		}
	}
	assert.True(t, found)
}

func TestMergePatterns_NewRuleAppended(t *testing.T) {
	extra := &Pattern{Name: "ultra-custom", Severity: SeverityCritical, Category: CatCredentials}
	merged := MergePatterns(BuiltinPatterns(), []*Pattern{extra})
	assert.Equal(t, len(BuiltinPatterns())+1, len(merged))
	assert.Equal(t, "ultra-custom", merged[len(merged)-1].Name)
}
