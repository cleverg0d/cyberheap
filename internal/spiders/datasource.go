package spiders

import (
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// dataSourceSpider lifts JDBC connection configuration out of all common
// datasource implementations. Each entry declares the target class FQN plus
// the field names to read.
type dataSourceSpider struct{}

func (s *dataSourceSpider) Name() string     { return "datasource" }
func (s *dataSourceSpider) Category() string { return "datasource" }

type dsTarget struct {
	fqn    string
	title  string
	fields []string // preferred extraction order, also used as display order
}

// Canonical list of DataSource-like classes we care about. For each we keep
// a small, ordered list of fields (url/username/password at minimum).
//
// Hikari and Druid are by far the most common in Spring Boot and Aliyun
// stacks; MongoDB and Weblogic rarer but still worth the two extra lines.
var dsTargets = []dsTarget{
	{
		fqn:    "org.springframework.boot.autoconfigure.jdbc.DataSourceProperties",
		title:  "Spring DataSourceProperties",
		fields: []string{"driverClassName", "url", "username", "password"},
	},
	{
		fqn:    "com.zaxxer.hikari.HikariConfig",
		title:  "Hikari connection pool config",
		fields: []string{"driverClassName", "jdbcUrl", "username", "password", "dataSourceClassName"},
	},
	{
		fqn:    "com.zaxxer.hikari.HikariDataSource",
		title:  "Hikari DataSource",
		fields: []string{"driverClassName", "jdbcUrl", "username", "password"},
	},
	{
		fqn:    "com.alibaba.druid.pool.DruidDataSource",
		title:  "Druid DataSource",
		fields: []string{"driverClass", "url", "username", "password"},
	},
	{
		fqn:    "com.alibaba.druid.pool.DruidAbstractDataSource",
		title:  "Druid DataSource (abstract)",
		fields: []string{"driverClass", "url", "username", "password"},
	},
	{
		fqn:    "weblogic.jdbc.common.internal.ConnectionEnvFactory",
		title:  "Weblogic JDBC connection factory",
		fields: []string{"url", "user", "password"},
	},
	{
		fqn:    "org.apache.commons.dbcp2.BasicDataSource",
		title:  "Apache DBCP2 DataSource",
		fields: []string{"driverClassName", "url", "username", "password"},
	},
	{
		fqn:    "org.apache.tomcat.jdbc.pool.DataSourceProxy",
		title:  "Tomcat JDBC pool DataSource",
		fields: []string{"driverClassName", "url", "username", "password"},
	},
	{
		fqn:    "com.mongodb.MongoClientURI",
		title:  "MongoDB client URI",
		fields: []string{"uri", "userName", "password", "database"},
	},
	{
		fqn:    "com.mongodb.ConnectionString",
		title:  "MongoDB connection string",
		fields: []string{"connectionString", "username", "password", "database"},
	},
}

func (s *dataSourceSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	// One object can match several targets (HikariDataSource also matches
	// HikariConfig, its parent). Emit only one finding per distinct heap
	// object, whichever target produces a usable result first.
	seen := map[uint64]bool{}
	for _, t := range dsTargets {
		for _, cls := range idx.Subclasses(t.fqn) {
			for _, inst := range idx.Instances[cls.ID] {
				if seen[inst.ID] {
					continue
				}
				f := extractDS(idx, inst.ID, t, cls.Name)
				if f != nil {
					out = append(out, *f)
					seen[inst.ID] = true
				}
			}
		}
	}
	return out
}

func extractDS(idx *heap.Index, objID uint64, t dsTarget, actualClassFQN string) *Finding {
	inst := idx.InstancesByID[objID]
	if inst == nil {
		return nil
	}
	fields := make([]Field, 0, len(t.fields))
	passwordVisible := false

	for _, name := range t.fields {
		v, err := idx.ReadField(inst, name)
		if err != nil {
			continue
		}
		s := valueAsString(idx, v)
		if s == "" {
			continue
		}
		// Reject obvious SQL fragments captured by pool classes that
		// alias "password" over a nearby String slot (Hikari runtime
		// layout puts connectionTestQuery next to password, and after
		// pool.start() the password field is sometimes nulled).
		if strings.Contains(strings.ToLower(name), "password") && looksLikeSQL(s) {
			continue
		}
		fields = append(fields, Field{Name: name, Value: s})
		if strings.Contains(strings.ToLower(name), "password") && s != "" {
			passwordVisible = true
		}
	}

	// Require at least one credential-like field. A finding that only has
	// driverClassName or poolName is noise — pools commonly null out the
	// password field after start-up while keeping their identity string.
	if !hasCredentialEvidence(fields) {
		return nil
	}

	sev := SeverityMedium
	if passwordVisible {
		sev = SeverityHigh
	}

	return &Finding{
		Spider:   "datasource",
		Severity: sev,
		Category: "datasource",
		Title:    t.title,
		ClassFQN: actualClassFQN,
		ObjectID: objID,
		Fields:   fields,
	}
}

// hasCredentialEvidence returns true if the extracted fields actually carry
// something worth reporting: a password/secret, or a connection URL/URI.
// A lone driverClassName (or equivalent identity string) is not enough —
// that alone is just framework noise, not a credential leak.
func hasCredentialEvidence(fs []Field) bool {
	for _, f := range fs {
		ln := strings.ToLower(f.Name)
		if strings.Contains(ln, "password") ||
			strings.Contains(ln, "passwd") ||
			strings.Contains(ln, "secret") {
			return true
		}
		if ln == "url" || ln == "jdbcurl" || ln == "uri" || ln == "connectionstring" {
			v := strings.ToLower(f.Value)
			if strings.Contains(v, "://") || strings.HasPrefix(v, "jdbc:") {
				return true
			}
		}
	}
	return false
}

// looksLikeSQL returns true for short connection-test queries such as
// "SELECT 1", "/* ping */ SELECT 1" — never a real password.
func looksLikeSQL(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if len(low) < 4 {
		return false
	}
	for _, prefix := range []string{"select ", "select\t", "/* ping", "values(", "call ", "commit", "begin"} {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	return false
}

// valueAsString best-effort renders a heap value for display.
// For String object refs we resolve; for primitives we stringify.
func valueAsString(idx *heap.Index, v heap.Value) string {
	if v.IsNull() {
		return ""
	}
	if v.Type.String() == "object" {
		if s, ok := idx.ReadString(v.ObjectID); ok {
			return s
		}
		return ""
	}
	// Rarely needed for DataSource fields; return empty to avoid bogus output.
	return ""
}
