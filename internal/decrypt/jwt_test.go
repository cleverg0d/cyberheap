package decrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintJWTHMAC produces an HS-signed token for tests.
func mintJWTHMAC(t *testing.T, alg string, claims map[string]any, secret string) string {
	t.Helper()
	var h hash.Hash
	switch alg {
	case "HS256":
		h = hmac.New(sha256.New, []byte(secret))
	case "HS384":
		h = hmac.New(sha512.New384, []byte(secret))
	case "HS512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		t.Fatalf("unsupported HS alg %q", alg)
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)
	h1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	h.Write([]byte(h1 + "." + c))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return h1 + "." + c + "." + sig
}

func mintJWTRSA(t *testing.T, alg string, claims map[string]any, priv *rsa.PrivateKey, pss bool) string {
	t.Helper()
	var h crypto.Hash
	var hasher hash.Hash
	switch alg {
	case "RS256", "PS256":
		h, hasher = crypto.SHA256, sha256.New()
	case "RS384", "PS384":
		h, hasher = crypto.SHA384, sha512.New384()
	case "RS512", "PS512":
		h, hasher = crypto.SHA512, sha512.New()
	default:
		t.Fatalf("unsupported RSA alg %q", alg)
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)
	h1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	hasher.Write([]byte(h1 + "." + c))

	var sig []byte
	var err error
	if pss {
		sig, err = rsa.SignPSS(rand.Reader, priv, h, hasher.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, h, hasher.Sum(nil))
	}
	require.NoError(t, err)
	return h1 + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mintJWTECDSA(t *testing.T, alg string, claims map[string]any, priv *ecdsa.PrivateKey) string {
	t.Helper()
	var hasher hash.Hash
	var sz int
	switch alg {
	case "ES256":
		hasher, sz = sha256.New(), 32
	case "ES384":
		hasher, sz = sha512.New384(), 48
	case "ES512":
		hasher, sz = sha512.New(), 66
	default:
		t.Fatalf("unsupported ES alg %q", alg)
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)
	h1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	hasher.Write([]byte(h1 + "." + c))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hasher.Sum(nil))
	require.NoError(t, err)

	rBytes := make([]byte, sz)
	sBytes := make([]byte, sz)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	sig := append(rBytes, sBytes...)
	return h1 + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mintJWTEd25519(t *testing.T, claims map[string]any, priv ed25519.PrivateKey) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)
	h1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := ed25519.Sign(priv, []byte(h1+"."+c))
	return h1 + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- HMAC -----------------------------------------------------------------

func TestVerifyJWT_HMAC_RoundTrip(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			tok := mintJWTHMAC(t, alg, map[string]any{"sub": "alice"}, "topsecret")
			res, err := VerifyJWT(tok, "topsecret")
			require.NoError(t, err)
			assert.True(t, res.SignatureValid)
			assert.Equal(t, alg, res.Alg)
			assert.Equal(t, "alice", res.Claims["sub"])
		})
	}
}

func TestVerifyJWT_HMAC_WrongSecret(t *testing.T) {
	tok := mintJWTHMAC(t, "HS256", map[string]any{"sub": "bob"}, "real-secret")
	res, err := VerifyJWT(tok, "guessed")
	require.NoError(t, err)
	assert.False(t, res.SignatureValid)
	assert.Contains(t, res.Mismatch, "mismatch")
	assert.Equal(t, "bob", res.Claims["sub"])
}

func TestVerifyJWT_NoKey_JustDecode(t *testing.T) {
	tok := mintJWTHMAC(t, "HS256", map[string]any{"sub": "carol", "scope": "admin"}, "irrelevant")
	res, err := VerifyJWT(tok, nil)
	require.NoError(t, err)
	assert.False(t, res.SignatureValid)
	assert.Equal(t, "carol", res.Claims["sub"])
}

func TestVerifyJWT_EmptyStringIsDecodeOnly(t *testing.T) {
	tok := mintJWTHMAC(t, "HS256", map[string]any{"sub": "dave"}, "real")
	res, err := VerifyJWT(tok, "")
	require.NoError(t, err)
	assert.False(t, res.SignatureValid)
	assert.Equal(t, "dave", res.Claims["sub"])
}

func TestVerifyJWT_Malformed(t *testing.T) {
	_, err := VerifyJWT("not.a.jwt.at.all", nil)
	assert.Error(t, err)
}

func TestVerifyJWT_AlgNoneRejected(t *testing.T) {
	// Craft an unsigned token — classic "alg=none" attack.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	tok := header + "." + payload + "."
	// Even supplying a "key" must not allow verification to pass.
	res, err := VerifyJWT(tok, []byte("anything"))
	require.NoError(t, err)
	assert.False(t, res.SignatureValid)
}

// --- RSA ------------------------------------------------------------------

func TestVerifyJWT_RSA_PKCS1(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, alg := range []string{"RS256", "RS384", "RS512"} {
		t.Run(alg, func(t *testing.T) {
			tok := mintJWTRSA(t, alg, map[string]any{"sub": "rsa-user"}, priv, false)
			res, err := VerifyJWT(tok, &priv.PublicKey)
			require.NoError(t, err)
			assert.True(t, res.SignatureValid)
			assert.Equal(t, "rsa-user", res.Claims["sub"])
		})
	}
}

func TestVerifyJWT_RSA_PSS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, alg := range []string{"PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			tok := mintJWTRSA(t, alg, map[string]any{"sub": "pss-user"}, priv, true)
			res, err := VerifyJWT(tok, &priv.PublicKey)
			require.NoError(t, err)
			assert.True(t, res.SignatureValid)
		})
	}
}

func TestVerifyJWT_RSA_WrongKey(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := mintJWTRSA(t, "RS256", map[string]any{"sub": "user"}, priv1, false)
	res, err := VerifyJWT(tok, &priv2.PublicKey)
	require.NoError(t, err)
	assert.False(t, res.SignatureValid)
}

// --- ECDSA ----------------------------------------------------------------

func TestVerifyJWT_ECDSA(t *testing.T) {
	cases := []struct {
		alg   string
		curve elliptic.Curve
	}{
		{"ES256", elliptic.P256()},
		{"ES384", elliptic.P384()},
		{"ES512", elliptic.P521()},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			require.NoError(t, err)
			tok := mintJWTECDSA(t, c.alg, map[string]any{"sub": "ec-user"}, priv)
			res, err := VerifyJWT(tok, &priv.PublicKey)
			require.NoError(t, err)
			assert.True(t, res.SignatureValid)
		})
	}
}

// --- Ed25519 --------------------------------------------------------------

func TestVerifyJWT_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tok := mintJWTEd25519(t, map[string]any{"sub": "ed-user"}, priv)
	res, err := VerifyJWT(tok, pub)
	require.NoError(t, err)
	assert.True(t, res.SignatureValid)
	assert.Equal(t, "EdDSA", res.Alg)
}

// --- Parse public key ----------------------------------------------------

func TestParsePublicKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	key, err := ParsePublicKey(pemBytes)
	require.NoError(t, err)
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestParsePublicKey_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	key, err := ParsePublicKey(pemBytes)
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestParsePublicKey_BadPEM(t *testing.T) {
	_, err := ParsePublicKey([]byte("not a PEM"))
	assert.Error(t, err)
}

// --- Auto HMAC brute-force -------------------------------------------------

func TestTryJWTAuto_FindsSecret(t *testing.T) {
	tok := mintJWTHMAC(t, "HS256", map[string]any{"sub": "x"}, "real-secret-2026")
	res, used, ok := TryJWTAuto(tok, []string{"wrong1", "real-secret-2026", "wrong2"})
	require.True(t, ok)
	assert.True(t, res.SignatureValid)
	assert.Equal(t, "real-secret-2026", used)
}

func TestTryJWTAuto_SkipsAsymmetric(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := mintJWTRSA(t, "RS256", map[string]any{"sub": "x"}, priv, false)
	res, used, ok := TryJWTAuto(tok, []string{"s1", "s2", "s3"})
	assert.False(t, ok)
	assert.Equal(t, "", used)
	assert.NotNil(t, res)
	assert.Equal(t, "x", res.Claims["sub"]) // still decoded
}

// Touch math/big so the import-checker is happy even if we remove later tests.
var _ = big.NewInt
