package decode

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeBasicAuth_Clean(t *testing.T) {
	src := "client:secret"
	enc := base64.StdEncoding.EncodeToString([]byte(src))
	d := TryDecode("basic-auth", enc)
	require.NotNil(t, d)
	assert.Equal(t, "basic-auth", d.Kind)
	assert.Equal(t, src, d.Text)
}

func TestDecodeBasicAuth_WithTrailingNoise(t *testing.T) {
	// Regex over-capture — a couple of bytes appended to the real base64.
	// 21-char plaintext encodes to 28 pad-free base64 chars; adding "kk"
	// makes a 30-char string that cleanBase64 must trim back to 28.
	src := "user01:ExamplePass-01"
	enc := base64.StdEncoding.EncodeToString([]byte(src)) + "kk"
	d := TryDecode("basic-auth", enc)
	require.NotNil(t, d)
	assert.Equal(t, src, d.Text)
}

func TestDecodeBasicAuth_Invalid(t *testing.T) {
	assert.Nil(t, TryDecode("basic-auth", "not$$$base64"))
	assert.Nil(t, TryDecode("basic-auth", "aGVsbG8=")) // "hello" — no colon
}

func TestDecodeJWT_StandardClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{
		"iss": "https://auth.example.com/realms/demo",
		"sub": "abc123",
		"aud": []string{"account"},
		"iat": 1700000000,
		"exp": 1700003600,
	}
	pj, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(pj)
	token := header + "." + payload + ".fakesig"

	d := TryDecode("jwt-token", token)
	require.NotNil(t, d)
	assert.Equal(t, "jwt-claims", d.Kind)
	assert.Contains(t, d.Text, "iss=https://auth.example.com/realms/demo")
	assert.Contains(t, d.Text, "sub=abc123")
	assert.Contains(t, d.Text, "iat=2023-11-14")
	assert.Contains(t, d.Text, "exp=2023-11-14")
	assert.Contains(t, d.Text, "aud=[account]")
}

func TestDecodeJWT_Malformed(t *testing.T) {
	assert.Nil(t, TryDecode("jwt-token", "not.a.jwt"))
	assert.Nil(t, TryDecode("jwt-token", "onlyonepart"))
}

func TestDecodeBearer_DelegatesToJWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"bob"}`))
	token := header + "." + payload + ".sig"
	d := TryDecode("bearer-token", token)
	require.NotNil(t, d)
	assert.Contains(t, d.Text, "sub=bob")
}

func TestCleanBase64_StripsGarbage(t *testing.T) {
	assert.Equal(t, "YWJjZA==", cleanBase64("YWJjZA==!@#"))
}

func TestLooksMostlyPrintable(t *testing.T) {
	assert.True(t, looksMostlyPrintable([]byte("hello:world")))
	assert.False(t, looksMostlyPrintable([]byte{0x00, 0x01, 0x02, 'a', 'b'}))
	assert.False(t, looksMostlyPrintable(nil))
}

func TestTruncate(t *testing.T) {
	s := strings.Repeat("x", 300)
	assert.Equal(t, 163, len(truncate(s, 160)))
}
