package verify

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Host is a network endpoint extracted from a finding.
// Port == 0 means unknown (DNS still attempted, TCP probe skipped).
type Host struct {
	Raw    string
	Scheme string
	Host   string
	Port   int
}

func (h Host) Key() string {
	if h.Port > 0 {
		return h.Host + ":" + strconv.Itoa(h.Port)
	}
	return h.Host
}

// ExtractHostFromValue parses JDBC URLs, scheme://host URLs, host:port,
// or bare hostname/IP. ok=false when nothing networky matches.
func ExtractHostFromValue(v string) (Host, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return Host{}, false
	}
	// JDBC first — its jdbc:<vendor>:// shape confuses url.Parse.
	if h, ok := parseJDBCURL(v); ok {
		return h, true
	}
	if strings.Contains(v, "://") {
		if h, ok := parseSchemeURL(v); ok {
			return h, true
		}
	}
	if h, ok := parseHostPort(v); ok {
		return h, true
	}
	if isHostLiteral(v) {
		return Host{Raw: v, Host: strings.ToLower(v)}, true
	}
	return Host{}, false
}

func ExtractHostsFromValues(values []string) []Host {
	seen := map[string]bool{}
	var out []Host
	for _, v := range values {
		h, ok := ExtractHostFromValue(v)
		if !ok {
			continue
		}
		k := h.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	return out
}

// parseJDBCURL: "jdbc:<vendor>://<host>:<port>[;/?...]"
func parseJDBCURL(v string) (Host, bool) {
	low := strings.ToLower(v)
	if !strings.HasPrefix(low, "jdbc:") {
		return Host{}, false
	}
	rest := v[5:] // drop "jdbc:"
	sepIdx := strings.Index(rest, "://")
	if sepIdx <= 0 {
		return Host{}, false
	}
	vendor := rest[:sepIdx]
	auth := rest[sepIdx+3:]
	auth = truncateAtAny(auth, ";/?# \t\"'")
	host, port := splitHostPort(auth)
	if host == "" {
		return Host{}, false
	}
	if port == 0 {
		port = jdbcDefaultPort(vendor)
	}
	return Host{
		Raw:    v,
		Scheme: "jdbc:" + strings.ToLower(vendor),
		Host:   strings.ToLower(host),
		Port:   port,
	}, true
}

// parseSchemeURL handles "scheme://..." URLs via net/url.
func parseSchemeURL(v string) (Host, bool) {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return Host{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Host{}, false
	}
	port := 0
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			port = n
		}
	}
	if port == 0 {
		port = schemeDefaultPort(u.Scheme)
	}
	return Host{
		Raw:    v,
		Scheme: strings.ToLower(u.Scheme),
		Host:   strings.ToLower(host),
		Port:   port,
	}, true
}

// parseHostPort extracts a Host from a bare "host:port" string.
// Rejects anything with whitespace or path separators to avoid matching
// arbitrary colon-bearing strings like "key:value" log lines.
func parseHostPort(v string) (Host, bool) {
	if strings.ContainsAny(v, " \t\n/?#@") {
		return Host{}, false
	}
	if strings.Count(v, ":") != 1 {
		return Host{}, false
	}
	host, port := splitHostPort(v)
	if host == "" || port == 0 {
		return Host{}, false
	}
	if !isHostLiteral(host) {
		return Host{}, false
	}
	return Host{Raw: v, Host: strings.ToLower(host), Port: port}, true
}

// splitHostPort peels off a trailing ":<digits>" port.
func splitHostPort(authority string) (string, int) {
	if authority == "" {
		return "", 0
	}
	colon := strings.LastIndexByte(authority, ':')
	if colon < 0 {
		return authority, 0
	}
	host := authority[:colon]
	portStr := authority[colon+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return authority, 0
	}
	return host, port
}

// isHostLiteral: valid hostname or IP. Narrow — rejects plain words
// and version strings like "1.0.2".
func isHostLiteral(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if !strings.ContainsRune(s, '.') {
		return false
	}
	allNumeric := true
	for _, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' {
			allNumeric = false
			break
		}
	}
	if allNumeric {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i, r := range l {
			if r == '-' {
				if i == 0 || i == len(l)-1 {
					return false
				}
				continue
			}
			if !(r == '_' ||
				(r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9')) {
				return false
			}
		}
	}
	// Last label: real TLDs are short and all-lowercase. Uppercase here
	// signals a Java classname like ".SQLServerDriver".
	last := labels[len(labels)-1]
	if len(last) > 24 {
		return false
	}
	for _, r := range last {
		if r >= 'A' && r <= 'Z' {
			return false
		}
	}
	return true
}

func truncateAtAny(s, seps string) string {
	end := len(s)
	for _, sep := range seps {
		if i := strings.IndexByte(s, byte(sep)); i >= 0 && i < end {
			end = i
		}
	}
	return s[:end]
}

// schemeDefaultPort: conventional TCP port per URL scheme, 0 if unknown.
func schemeDefaultPort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	case "redis":
		return 6379
	case "rediss":
		return 6380
	case "mongodb":
		return 27017
	case "mongodb+srv":
		return 27017
	case "amqp":
		return 5672
	case "amqps":
		return 5671
	case "smtp":
		return 25
	case "smtps":
		return 465
	case "ftp":
		return 21
	case "ssh":
		return 22
	case "ldap":
		return 389
	case "ldaps":
		return 636
	}
	return 0
}

// jdbcDefaultPort: default TCP port per JDBC vendor.
func jdbcDefaultPort(vendor string) int {
	switch strings.ToLower(vendor) {
	case "sqlserver", "microsoft:sqlserver":
		return 1433
	case "mysql":
		return 3306
	case "mariadb":
		return 3306
	case "postgresql":
		return 5432
	case "oracle:thin", "oracle":
		return 1521
	case "db2":
		return 50000
	case "h2":
		return 8082
	}
	return 0
}
