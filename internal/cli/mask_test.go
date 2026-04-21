package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"j.doe.user01@corp.example.com": "j.**********@corp.example.com",
		"hello@example.com":             "he***@example.com",
		"a@b.com":                       "*@b.com",
	}
	for in, want := range cases {
		assert.Equal(t, want, maskEmail(in), "email %q", in)
	}
}

func TestMaskJWT_PreservesHeader(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.thisisthesignaturepart"
	masked := maskJWT(jwt)
	parts := strings.Split(masked, ".")
	assert.Equal(t, 3, len(parts))
	assert.Equal(t, "eyJhbGciOiJIUzI1NiJ9", parts[0], "header survives")
	assert.Contains(t, parts[1], "*")
	assert.Contains(t, parts[2], "*")
}

func TestMaskSecret_ShortValuesFullyMasked(t *testing.T) {
	assert.Equal(t, "******", maskSecret("abcdef", 2, 2))
	// Length 16 with head=4, tail=4 leaves 8 middle chars to mask.
	assert.Equal(t, "abcd********wxyz", maskSecret("abcd12345678wxyz", 4, 4))
}

func TestMaskForPattern_Dispatch(t *testing.T) {
	assert.Equal(t, "al***@host.com", maskForPattern("email-address", "alice@host.com"))
	assert.Contains(t, maskForPattern("password-assignment", "supersecret"), "*")
	jwt := "eyJ.pay.sig"
	assert.Equal(t, "eyJ.***.***", maskForPattern("jwt-token", jwt))
}
