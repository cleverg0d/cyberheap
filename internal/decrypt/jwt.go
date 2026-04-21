package decrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// JWTResult is the full inspection outcome for one token. Even with a
// wrong key we still parse and expose the header and claims — that's
// often the point of the exercise.
type JWTResult struct {
	Header         map[string]any // alg, typ, kid, ...
	Claims         map[string]any // iss, sub, exp, ...
	Alg            string         // e.g. "HS256", "RS256", "ES256", "EdDSA"
	SignatureValid bool           // only true if a key was supplied AND verified
	Mismatch       string         // describes why verification failed, if any
}

// VerifyJWT decodes the token and, if a key is given, checks the
// signature. `key` may be:
//
//   - string or []byte         → HMAC shared secret (HS256/384/512)
//   - *rsa.PublicKey           → RSA signatures (RS* and PS*)
//   - *ecdsa.PublicKey         → ECDSA signatures (ES*)
//   - ed25519.PublicKey        → Ed25519 (EdDSA)
//   - nil / ""                 → skip verification
//
// Pass nil to just dump claims from an untrusted token.
func VerifyJWT(token string, key any) (*JWTResult, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: expected 3 segments, got %d", len(parts))
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: header decode: %w", err)
	}
	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: payload decode: %w", err)
	}

	var res JWTResult
	if err := json.Unmarshal(headerBytes, &res.Header); err != nil {
		return nil, fmt.Errorf("jwt: header not JSON: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &res.Claims); err != nil {
		return nil, fmt.Errorf("jwt: payload not JSON: %w", err)
	}

	if a, ok := res.Header["alg"].(string); ok {
		res.Alg = a
	}

	if isEmptyKey(key) {
		return &res, nil
	}

	sig, err := decodeJWTPart(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: signature decode: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	ok, verr := verifyWithKey(res.Alg, signingInput, sig, key)
	if verr != nil {
		res.Mismatch = verr.Error()
		return &res, nil
	}
	if ok {
		res.SignatureValid = true
	} else {
		res.Mismatch = "signature mismatch (wrong key, algorithm, or signature)"
	}
	return &res, nil
}

// TryJWTAuto brute-forces HMAC shared secrets against the token. Only
// HMAC family algorithms support brute-forcing; for RS/ES/PS/EdDSA the
// caller must supply a public key and verify deterministically.
func TryJWTAuto(token string, candidates []string) (res *JWTResult, secret string, ok bool) {
	res, err := VerifyJWT(token, nil)
	if err != nil {
		return nil, "", false
	}
	if !strings.HasPrefix(strings.ToUpper(res.Alg), "HS") {
		// Public-key algorithms cannot be brute-forced sensibly.
		return res, "", false
	}
	for _, s := range candidates {
		if s == "" {
			continue
		}
		r, err := VerifyJWT(token, s)
		if err == nil && r.SignatureValid {
			return r, s, true
		}
	}
	return res, "", false
}

// ParsePublicKey reads a PEM-encoded public key or X.509 certificate and
// returns a Go key ready for VerifyJWT. Accepts RSA, EC, and Ed25519.
func ParsePublicKey(pemData []byte) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
}

func isEmptyKey(key any) bool {
	switch v := key.(type) {
	case nil:
		return true
	case string:
		return v == ""
	case []byte:
		return len(v) == 0
	}
	return false
}

// verifyWithKey dispatches on (alg, key type). Returns ok + error; the
// error is only set on "can't try" paths, never on signature mismatch.
func verifyWithKey(alg string, signed, sig []byte, key any) (bool, error) {
	a := strings.ToUpper(alg)
	switch {
	case strings.HasPrefix(a, "HS"):
		secret, ok := keyAsBytes(key)
		if !ok {
			return false, fmt.Errorf("alg %s needs a shared secret, got %T", alg, key)
		}
		return verifyHMAC(a, signed, sig, secret)
	case strings.HasPrefix(a, "RS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("alg %s needs an RSA public key, got %T", alg, key)
		}
		return verifyRSAPKCS1(a, signed, sig, pub), nil
	case strings.HasPrefix(a, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("alg %s needs an RSA public key, got %T", alg, key)
		}
		return verifyRSAPSS(a, signed, sig, pub), nil
	case strings.HasPrefix(a, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("alg %s needs an ECDSA public key, got %T", alg, key)
		}
		return verifyECDSA(a, signed, sig, pub), nil
	case a == "EDDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("alg %s needs an ed25519.PublicKey, got %T", alg, key)
		}
		return ed25519.Verify(pub, signed, sig), nil
	case a == "NONE":
		return false, errors.New("alg 'none' is dangerous and always rejected")
	}
	return false, fmt.Errorf("unsupported JWT alg %q", alg)
}

func keyAsBytes(key any) ([]byte, bool) {
	switch v := key.(type) {
	case string:
		return []byte(v), true
	case []byte:
		return v, true
	}
	return nil, false
}

func verifyHMAC(alg string, signed, sig []byte, secret []byte) (bool, error) {
	var h hash.Hash
	switch alg {
	case "HS256":
		h = hmac.New(sha256.New, secret)
	case "HS384":
		h = hmac.New(sha512.New384, secret)
	case "HS512":
		h = hmac.New(sha512.New, secret)
	default:
		return false, fmt.Errorf("jwt: HMAC %q not supported", alg)
	}
	h.Write(signed)
	return hmac.Equal(h.Sum(nil), sig), nil
}

func verifyRSAPKCS1(alg string, signed, sig []byte, pub *rsa.PublicKey) bool {
	h, hasher := jwtHash(alg)
	if h == 0 {
		return false
	}
	hasher.Write(signed)
	return rsa.VerifyPKCS1v15(pub, h, hasher.Sum(nil), sig) == nil
}

func verifyRSAPSS(alg string, signed, sig []byte, pub *rsa.PublicKey) bool {
	h, hasher := jwtHash(alg)
	if h == 0 {
		return false
	}
	hasher.Write(signed)
	// JWA says PSS salt length equals the hash output size (RFC 7518 §3.5).
	return rsa.VerifyPSS(pub, h, hasher.Sum(nil), sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}) == nil
}

// verifyECDSA handles the JWT flavor of ECDSA: signature is the raw R||S
// concatenation (fixed-width for the curve), not the ASN.1 DER envelope
// that ecdsa.Verify expects elsewhere.
func verifyECDSA(alg string, signed, sig []byte, pub *ecdsa.PublicKey) bool {
	var hasher hash.Hash
	var sz int
	switch alg {
	case "ES256":
		hasher = sha256.New()
		sz = 32
	case "ES384":
		hasher = sha512.New384()
		sz = 48
	case "ES512":
		hasher = sha512.New()
		sz = 66 // P-521 coordinates round up to 66 bytes each
	default:
		return false
	}
	if len(sig) != 2*sz {
		return false
	}
	r := new(big.Int).SetBytes(sig[:sz])
	s := new(big.Int).SetBytes(sig[sz:])
	hasher.Write(signed)
	return ecdsa.Verify(pub, hasher.Sum(nil), r, s)
}

func jwtHash(alg string) (crypto.Hash, hash.Hash) {
	switch {
	case strings.HasSuffix(alg, "256"):
		return crypto.SHA256, sha256.New()
	case strings.HasSuffix(alg, "384"):
		return crypto.SHA384, sha512.New384()
	case strings.HasSuffix(alg, "512"):
		return crypto.SHA512, sha512.New()
	}
	return 0, nil
}

// decodeJWTPart accepts both URL-safe (standard for JWT) and padded forms.
// Go's base64.RawURLEncoding refuses any padding; RawStdEncoding refuses
// URL chars. We try the permissive combinations in order.
func decodeJWTPart(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(padBase64(s)); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(padBase64(s)); err == nil {
		return b, nil
	}
	return nil, errors.New("not valid base64url")
}

func padBase64(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}
