package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestVerifyJWT_Expired constructs a JWT with an exp in the past and
// checks the verdict picks it up. No signing — we only parse claims.
func TestVerifyJWT_Expired(t *testing.T) {
	tok := craftJWT(t, map[string]any{
		"iss": "https://kc.example.com/realms/master",
		"sub": "alice",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	st := verifyJWT(tok)
	assert.True(t, st.Expired)
	assert.Equal(t, "expired", st.Reason)
	assert.Equal(t, "alice", st.Subject)
	assert.Equal(t, "https://kc.example.com/realms/master", st.Issuer)
}

// TestVerifyJWT_Valid confirms a future-exp token is reported as usable.
// "Usable" here means "non-expired"; signature is out of scope for v1.
func TestVerifyJWT_Valid(t *testing.T) {
	tok := craftJWT(t, map[string]any{
		"iss": "https://issuer.example.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	st := verifyJWT(tok)
	assert.False(t, st.Expired)
	assert.Empty(t, st.Reason)
}

// TestVerifyJWT_Malformed rejects strings that aren't three base64
// segments — catches noisy extractor captures that look vaguely JWT-ish.
func TestVerifyJWT_Malformed(t *testing.T) {
	for _, bad := range []string{"", "not.a.jwt.too.many", "only.one", "aa.bb"} {
		st := verifyJWT(bad)
		assert.Equal(t, "malformed", st.Reason, bad)
	}
}

// TestVerifyCred_ExpiredJWTShortCircuit: when a vendor-pattern token is
// a JWT and its exp has passed, VerifyCred must NOT send an HTTP call.
// The asserted absence of a network hit lives in the choice of client:
// a zero-value http.Client would fail any real request immediately, so
// the result here proves we never called .Do().
func TestVerifyCred_ExpiredJWTShortCircuit(t *testing.T) {
	tok := craftJWT(t, map[string]any{
		"iss": "example",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	r, ok := VerifyCred(context.Background(), "github-token", tok, nil)
	assert.True(t, ok)
	assert.Equal(t, CredRevoked, r.Verdict)
	assert.Contains(t, r.Reason, "expired")
}

// craftJWT builds a three-part JWT with the given payload. Signature is
// a literal dummy string since we don't verify signatures in verify.
func craftJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "none", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb) + ".signature"
}
