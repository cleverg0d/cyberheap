package spiders

import "strings"

// defaultCredPairs: well-known vendor defaults. Lowercased "user:pass"
// (empty password → "user:"). Mutually exclusive with weakPasswords —
// a pair that matches here gets ONLY "default-creds", never "weak".
var defaultCredPairs = map[string]bool{
	"admin:admin":                 true,
	"admin:123456":                true,
	"admin:admin123":              true,
	"administrator:administrator": true,
	"root:root":                   true,
	"root:toor":                   true,
	"root:admin":                  true,
	"cisco:cisco":                 true,
	"tomcat:tomcat":               true,
	"tomcat:s3cret":               true,
	"jenkins:jenkins":             true,
	"user:user":                   true,
	"test:test":                   true,
	"demo:demo":                   true,
	"guest:guest":                 true,
	"guest:":                      true,
	"sa:":                         true,
	"sa:sa":                       true,
	"postgres:postgres":           true,
	"postgres:":                   true,
	"mysql:mysql":                 true,
	"mysql:":                      true,
	"oracle:oracle":               true,
	"minio:minio":                 true,
	"minioadmin:minioadmin":       true,
}

// weakPasswords: passwords that are NOT default-pair but still trivially
// guessable. Match against password value (case-insensitive).
var weakPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true,
	"passw0rd": true, "p@ssw0rd": true, "p@ssword": true,
	"123456": true, "12345678": true, "123456789": true, "1234567890": true,
	"qwerty": true, "qwerty123": true, "qwertyuiop": true,
	"abc123": true, "letmein": true, "welcome": true, "welcome1": true,
	"iloveyou": true, "monkey": true, "dragon": true, "master": true,
	"shadow": true, "sunshine": true, "princess": true, "football": true,
	"secret": true, "default": true, "changeme": true, "temp": true,
	"access": true, "trustno1": true, "starwars": true,
}

// TagDefaultAndWeak annotates findings with "default-creds" (exact
// match in defaultCredPairs) OR "weak" (password in weakPasswords, or
// length < 8). Priority: default > weak. A pair is either one or the
// other, never both.
func TagDefaultAndWeak(findings []Finding) []Finding {
	for i := range findings {
		user, pass := pickUserPass(findings[i].Fields)
		if pass == "" {
			continue
		}
		if user != "" {
			key := strings.ToLower(user) + ":" + strings.ToLower(pass)
			if defaultCredPairs[key] {
				findings[i].Flags = appendUnique(findings[i].Flags, "default-creds")
				continue
			}
		}
		if isWeakPassword(pass) {
			findings[i].Flags = appendUnique(findings[i].Flags, "weak")
		}
	}
	return findings
}

// pickUserPass extracts the first username-like and password-like field.
func pickUserPass(fields []Field) (user, pass string) {
	for _, f := range fields {
		n := strings.ToLower(f.Name)
		if pass == "" && strings.Contains(n, "password") {
			pass = f.Value
		}
		if user == "" && (n == "username" || n == "user" || n == "login" ||
			strings.HasSuffix(n, "username") || strings.HasSuffix(n, "user") ||
			strings.HasSuffix(n, "login")) {
			user = f.Value
		}
	}
	return
}

// isWeakPassword: in the known-weak dictionary OR shorter than 8 chars.
func isWeakPassword(pass string) bool {
	if weakPasswords[strings.ToLower(pass)] {
		return true
	}
	return len(pass) < 8
}

// ClassifyBasicAuth categorises a "user:pass" blob captured by the
// basic-auth regex. Returns "default-creds", "weak", or "".
func ClassifyBasicAuth(userPass string) string {
	i := strings.IndexByte(userPass, ':')
	if i < 0 {
		return ""
	}
	user, pass := userPass[:i], userPass[i+1:]
	if pass == "" {
		return ""
	}
	key := strings.ToLower(user) + ":" + strings.ToLower(pass)
	if defaultCredPairs[key] {
		return "default-creds"
	}
	if isWeakPassword(pass) {
		return "weak"
	}
	return ""
}

func appendUnique(in []string, s string) []string {
	for _, v := range in {
		if v == s {
			return in
		}
	}
	return append(in, s)
}

// HasFlag reports whether a finding carries the given flag.
func HasFlag(f Finding, flag string) bool {
	for _, v := range f.Flags {
		if v == flag {
			return true
		}
	}
	return false
}
