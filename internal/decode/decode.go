// Package decode provides best-effort inline decoding of secrets that
// scanner.Match surfaces as raw strings. It is intentionally forgiving:
// if we cannot decode, we return nil and let the caller show the raw value.
package decode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Decoded holds a single human-readable interpretation of a secret.
type Decoded struct {
	Kind string // e.g. "basic-auth", "jwt-claims"
	Text string // one-line summary suitable for terminal display
}

// TryDecode attempts to enrich a Match with a decoded representation.
// It is routed primarily by pattern name; generic base64 fallback is used
// when the pattern name is unknown but the value looks like base64.
func TryDecode(patternName, value string) *Decoded {
	switch patternName {
	case "basic-auth":
		return decodeBasicAuth(value)
	case "jwt-token":
		return decodeJWT(value)
	case "bearer-token":
		// Bearer tokens are usually JWTs in Spring/Keycloak stacks.
		if d := decodeJWT(value); d != nil {
			return d
		}
		return nil
	case "jasypt-enc-value":
		// Needs the master password to reverse — reserved for Phase 5.
		return nil
	}
	return nil
}

// decodeBasicAuth accepts the raw capture (base64-encoded "user:password").
// Trailing noise is trimmed because the regex often grabs a few extra bytes
// of binary heap memory.
func decodeBasicAuth(s string) *Decoded {
	cleaned := cleanBase64(s)
	raw, ok := tryBase64(cleaned)
	if !ok {
		return nil
	}
	text := string(raw)
	idx := strings.IndexByte(text, ':')
	if idx <= 0 || idx == len(text)-1 {
		return nil
	}
	if !looksMostlyPrintable(raw) {
		return nil
	}
	return &Decoded{Kind: "basic-auth", Text: text}
}

// decodeJWT pulls iss/sub/exp/aud out of the payload segment.
// We do NOT verify the signature — this is triage, not auth.
func decodeJWT(s string) *Decoded {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	payloadBytes, ok := tryBase64URL(parts[1])
	if !ok {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		// Not JSON — fall back to raw payload preview.
		return &Decoded{Kind: "jwt-payload-raw", Text: truncate(string(payloadBytes), 160)}
	}
	return &Decoded{Kind: "jwt-claims", Text: summarizeClaims(claims)}
}

var jwtInterestingKeys = []string{"iss", "sub", "aud", "preferred_username", "email", "scope", "azp", "iat", "exp"}

func summarizeClaims(claims map[string]any) string {
	var parts []string
	for _, k := range jwtInterestingKeys {
		v, ok := claims[k]
		if !ok {
			continue
		}
		switch k {
		case "iat", "exp":
			if f, isFloat := v.(float64); isFloat {
				t := time.Unix(int64(f), 0).UTC().Format("2006-01-02 15:04:05Z")
				parts = append(parts, fmt.Sprintf("%s=%s", k, t))
				continue
			}
		case "aud":
			// aud can be string or []string — stringify compactly.
			parts = append(parts, fmt.Sprintf("%s=%s", k, compactAny(v)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, compactAny(v)))
	}
	if len(parts) == 0 {
		b, _ := json.Marshal(claims)
		return truncate(string(b), 200)
	}
	return strings.Join(parts, " ")
}

func compactAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var ss []string
		for _, item := range x {
			ss = append(ss, compactAny(item))
		}
		return "[" + strings.Join(ss, ",") + "]"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// cleanBase64 drops trailing bytes that aren't part of the base64 alphabet
// (both standard and URL variants). This is important because the scanner
// regex sometimes over-captures by a few bytes of heap garbage.
func cleanBase64(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isBase64Char(c) {
			s = s[:i]
			break
		}
	}
	// Drop partial trailing group if no padding present.
	if strings.IndexByte(s, '=') < 0 {
		for len(s)%4 != 0 {
			s = s[:len(s)-1]
		}
	}
	return s
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

func tryBase64(s string) ([]byte, bool) {
	// Try standard, with padding first, then without.
	if raw, err := base64.StdEncoding.DecodeString(pad(s)); err == nil {
		return raw, true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return raw, true
	}
	return nil, false
}

func tryBase64URL(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return raw, true
	}
	if raw, err := base64.URLEncoding.DecodeString(pad(s)); err == nil {
		return raw, true
	}
	// Fall back to standard encoding — some emitters mix alphabets.
	return tryBase64(s)
}

func pad(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

func looksMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7F) || c == '\t' {
			printable++
		}
	}
	return printable*10 >= len(b)*8 // >=80% printable
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
