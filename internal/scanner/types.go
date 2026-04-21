package scanner

import "regexp"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "critical", "CRITICAL", "Critical":
		return SeverityCritical, true
	case "high", "HIGH", "High":
		return SeverityHigh, true
	case "medium", "MEDIUM", "Medium":
		return SeverityMedium, true
	case "low", "LOW", "Low":
		return SeverityLow, true
	case "info", "INFO", "Info":
		return SeverityInfo, true
	}
	return 0, false
}

// Category groups findings by domain so the user can filter noise.
type Category string

const (
	CatDatasource  Category = "datasource"
	CatCredentials Category = "credentials"
	CatCloud       Category = "cloud"
	CatSCM         Category = "scm"
	CatPaymentSaaS Category = "payment-saas"
	CatPrivateKey  Category = "private-key"
	CatJWT         Category = "jwt"
	CatConnString  Category = "connection-string"
	CatAuth        Category = "auth"
	CatPersonal    Category = "personal"
)

type Pattern struct {
	Name     string
	Category Category
	Severity Severity

	// re matches the full finding. captureGroup says which sub-group is the
	// actual secret (0 = whole match). Extractable secrets usually use a
	// capture group so we can show just the credential, not the surrounding
	// key=... syntax.
	re           *regexp.Regexp
	captureGroup int

	// maxLen trims absurdly long matches (mostly binary noise in heap memory).
	maxLen int

	// postFilter, if set, gets the extracted value and can reject it.
	// Used to drop e.g. stacktrace noise that syntactically matches an email.
	postFilter func(value []byte) bool
}

type Match struct {
	Pattern *Pattern
	Value   string // extracted secret (capture group if any)
	Full    string // full matched text (for context)
	Offset  int64  // byte offset in the source
	Count   int    // how many times this (pattern, value) occurred
}

// SeveritySet is a simple filter built from --severity flag.
type SeveritySet map[Severity]bool

func AllSeverities() SeveritySet {
	return SeveritySet{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
		SeverityInfo:     true,
	}
}

// CategorySet is a simple filter built from --category flag.
type CategorySet map[Category]bool
