package recon

import (
	"bufio"
	"io"
	"strings"
)

// defaultPaths are the high-yield actuator and debug paths seen on
// exposed Spring Boot, generic Java apps, and common JMX bridges.
// Intentionally kept short (no 20k-wordlist fuzzing) — pentester can
// pass --wordlist for bigger lists. Every entry starts with "/".
var defaultPaths = []string{
	// Spring Boot 1.x legacy base paths
	"/env", "/health", "/info", "/metrics", "/dump", "/trace",
	"/mappings", "/configprops", "/beans", "/autoconfig",
	"/heapdump", "/threaddump", "/loggers",

	// Spring Boot 2.x+ under /actuator
	"/actuator", "/actuator/",
	"/actuator/env", "/actuator/env.json",
	"/actuator/heapdump",
	"/actuator/threaddump",
	"/actuator/configprops",
	"/actuator/beans",
	"/actuator/mappings",
	"/actuator/httpexchanges", "/actuator/httptrace",
	"/actuator/logfile",
	"/actuator/loggers",
	"/actuator/health",
	"/actuator/info",
	"/actuator/metrics",
	"/actuator/gateway/routes",

	// JMX bridges (Jolokia) — dangerous if exposed
	"/actuator/jolokia",
	"/actuator/jolokia/list",
	"/jolokia",
	"/jolokia/list",
	"/jolokia/version",

	// Common non-root mount points
	"/management/actuator",
	"/management/actuator/heapdump",
	"/management/actuator/env",
	"/management/health",
	"/api/actuator",
	"/api/actuator/heapdump",
	"/admin/actuator",
	"/admin/actuator/heapdump",
}

// LoadWordlist reads one path per line from r, skipping blanks and
// comments. Relative entries are normalised to start with "/".
func LoadWordlist(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		out = append(out, line)
	}
	return out
}

// DefaultPaths returns a copy of the built-in path list.
func DefaultPaths() []string {
	out := make([]string, len(defaultPaths))
	copy(out, defaultPaths)
	return out
}
