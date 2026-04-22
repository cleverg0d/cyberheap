package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractHostFromValue_JDBC verifies we peel off the correct
// host:port from every JDBC dialect we claim to support. The double
// "jdbc:<vendor>://..." scheme is the reason a dedicated parser exists
// rather than leaning on net/url.
func TestExtractHostFromValue_JDBC(t *testing.T) {
	cases := []struct {
		v      string
		host   string
		port   int
		scheme string
	}{
		{
			v:      "jdbc:sqlserver://10.0.0.5:1433;databaseName=appdb",
			host:   "10.0.0.5",
			port:   1433,
			scheme: "jdbc:sqlserver",
		},
		{
			v:      "jdbc:mysql://db.example.com:3307/app?useSSL=false",
			host:   "db.example.com",
			port:   3307,
			scheme: "jdbc:mysql",
		},
		{
			v:      "jdbc:postgresql://pg.internal/accounts",
			host:   "pg.internal",
			port:   5432, // default
			scheme: "jdbc:postgresql",
		},
	}
	for _, c := range cases {
		h, ok := ExtractHostFromValue(c.v)
		assert.True(t, ok, c.v)
		assert.Equal(t, c.host, h.Host, c.v)
		assert.Equal(t, c.port, h.Port, c.v)
		assert.Equal(t, c.scheme, h.Scheme, c.v)
	}
}

// TestExtractHostFromValue_HTTPandBare covers URL parsing (via url.Parse),
// bare host:port strings (Redis/DB URIs), and plain hostname/IP values.
// Also guards against false positives on plain words.
func TestExtractHostFromValue_HTTPandBare(t *testing.T) {
	assertHost := func(t *testing.T, v, host string, port int) {
		t.Helper()
		h, ok := ExtractHostFromValue(v)
		assert.True(t, ok, v)
		assert.Equal(t, host, h.Host, v)
		assert.Equal(t, port, h.Port, v)
	}

	assertHost(t, "https://api.example.com/v1", "api.example.com", 443)
	assertHost(t, "http://10.0.0.5:8080/admin", "10.0.0.5", 8080)
	assertHost(t, "redis://cache.internal:6380", "cache.internal", 6380)
	assertHost(t, "10.0.0.5", "10.0.0.5", 0)
	assertHost(t, "mail.example.com:25", "mail.example.com", 25)

	// Negative cases — these aren't hosts and must not confuse the extractor.
	for _, v := range []string{
		"password", "", "1.0.2", "localhost", // single-label not accepted
		"some random log line", "admin:secret",
		"com.microsoft.sqlserver.jdbc.SQLServerDriver", // Java classname — mixed-case final label
		"org.springframework.web.servlet.ViewResolver",
	} {
		_, ok := ExtractHostFromValue(v)
		assert.False(t, ok, v)
	}
}

// TestExtractHostsFromValues_Dedup checks that the same endpoint seen
// from multiple findings collapses to a single Host entry, so the
// verification pass sends one round-trip per distinct endpoint.
func TestExtractHostsFromValues_Dedup(t *testing.T) {
	values := []string{
		"jdbc:sqlserver://db:1433;x=y",
		"jdbc:sqlserver://db:1433;z=w",
		"https://api.example.com/",
		"https://api.example.com/other",
		"not-a-host",
	}
	got := ExtractHostsFromValues(values)
	assert.Len(t, got, 2)
	keys := map[string]bool{got[0].Key(): true, got[1].Key(): true}
	assert.True(t, keys["db:1433"])
	assert.True(t, keys["api.example.com:443"])
}
