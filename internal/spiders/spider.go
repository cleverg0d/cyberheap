// Package spiders contains class-aware extractors that run over a parsed
// HPROF index. Unlike the regex scanner, spiders find credentials by Java
// class identity — e.g. "every instance of DataSourceProperties, read its
// password field" — which is robust even when the cleartext doesn't appear
// near any recognisable marker in the dump.
package spiders

import (
	"github.com/cleverg0d/cyberheap/internal/heap"
)

// Severity mirrors scanner.Severity so spiders and the regex scanner can
// share a rendering pipeline without a cross-package dependency.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Finding is what a spider returns. Compared to scanner.Match it carries
// structural context (ClassFQN, ObjectID) that we surface in the output.
type Finding struct {
	Spider   string
	Severity Severity
	Category string
	Title    string

	ClassFQN string
	ObjectID uint64

	Fields []Field

	// Flags are post-processor tags: "default-creds", "weak", etc.
	Flags []string
}

// Field is a single name/value pair extracted from an instance.
type Field struct {
	Name  string
	Value string
}

// Spider sniffs one class of credential or configuration out of the heap.
type Spider interface {
	Name() string
	Category() string
	Sniff(idx *heap.Index) []Finding
}

// Registry holds all spiders available to the scan command.
func Registry() []Spider {
	return []Spider{
		&dataSourceSpider{},
		&shiroSpider{},
		&propertySourceSpider{},
		&redisSpider{},
		&envSpider{},
		&jasyptSpider{},
		&cloudCredsSpider{},
		&authnSpider{},
	}
}
