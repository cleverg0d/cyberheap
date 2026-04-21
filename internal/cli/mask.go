package cli

import (
	"strings"
)

// maskForPattern picks a masking strategy based on pattern name so that
// passwords collapse to "Fc****34", emails keep the domain for triage, and
// tokens keep enough prefix/suffix to stay identifiable in a report.
func maskForPattern(patternName, value string) string {
	switch patternName {
	case "email-address":
		return maskEmail(value)
	case "password-assignment", "spring-datasource-password", "jdbc-url-with-password":
		return maskSecret(value, 1, 1)
	case "jwt-token", "bearer-token":
		return maskJWT(value)
	}
	// Default: token-style. Keep a short head and tail so analysts can pair
	// findings across reports without exposing the whole credential.
	return maskSecret(value, 4, 4)
}

// maskJWT preserves the header (alg/typ are non-sensitive and useful in
// reports) and masks payload + signature.
func maskJWT(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return maskSecret(v, 4, 4)
	}
	return parts[0] + "." + maskSecret(parts[1], 2, 2) + "." + maskSecret(parts[2], 2, 2)
}

// maskDecoded masks the decoded form of a finding. Different decoded shapes
// want different strategies so the client-facing output stays informative
// without leaking the credential itself.
func maskDecoded(kind, text string) string {
	switch kind {
	case "basic-auth":
		// "user:password" — keep the username fully visible, mask the secret.
		i := strings.IndexByte(text, ':')
		if i > 0 && i < len(text)-1 {
			return text[:i+1] + maskSecret(text[i+1:], 1, 1)
		}
		return maskSecret(text, 2, 2)
	case "jwt-claims":
		// Claim values may themselves be secrets (email, sub ids). Mask every
		// value after each "key=" while keeping the key names so the report
		// still tells the reader what kind of token this was.
		return maskKVList(text)
	case "jwt-payload-raw":
		return maskSecret(text, 4, 4)
	}
	return maskSecret(text, 4, 4)
}

// maskKVList walks a space-separated "key=value" list and masks each value.
// Handles bracketed values like "aud=[account,portal]" as a single unit.
func maskKVList(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			b.WriteString(s[i:])
			break
		}
		eq += i
		b.WriteString(s[i : eq+1])
		j := eq + 1
		// Value ends at next space outside brackets.
		depth := 0
		for j < len(s) {
			c := s[j]
			if c == '[' {
				depth++
			} else if c == ']' {
				depth--
			} else if c == ' ' && depth == 0 {
				break
			}
			j++
		}
		val := s[eq+1 : j]
		b.WriteString(maskSecret(val, 2, 2))
		if j < len(s) {
			b.WriteByte(s[j])
			j++
		}
		i = j
	}
	return b.String()
}

func maskEmail(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return maskSecret(email, 2, 0)
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return strings.Repeat("*", len(local)) + domain
	}
	keep := 2
	if len(local) <= 4 {
		keep = 1
	}
	return local[:keep] + strings.Repeat("*", len(local)-keep) + domain
}

// maskSecret shows `head` leading and `tail` trailing chars, masking the
// middle. Short values (<=head+tail+2) are replaced entirely to avoid
// exposing most of a weak secret.
func maskSecret(v string, head, tail int) string {
	if len(v) <= head+tail+2 {
		return strings.Repeat("*", len(v))
	}
	middle := len(v) - head - tail
	return v[:head] + strings.Repeat("*", middle) + v[len(v)-tail:]
}
