package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ShiroCipherMode selects which AES mode Shiro used to encrypt the cookie.
type ShiroCipherMode int

const (
	ShiroCBC ShiroCipherMode = iota // Shiro ≤ 1.2.4 (most CVE-2016-4437 exploitation)
	ShiroGCM                        // Shiro 1.4+ (CVE-2020-1957 era switched default)
)

// WellKnownShiroKeys is the non-exhaustive catalogue of default keys
// shipped in various public examples and vulnerable releases. These are
// tried first in auto-detect mode before any key discovered in the heap.
var WellKnownShiroKeys = []string{
	"kPH+bIxk5D2deZiIxcaaaA==", // Shiro ≤ 1.2.4 distribution default (CVE-2016-4437)
	"2AvVhdsgUs0FSA3SDFAdag==",
	"4AvVhmFLUs0KTA3Kprsdag==",
	"3AvVhmFLUs0KTA3Kprsdag==",
	"5aaC5qKm5oqA5pyvAAAAAA==",
	"Z3VucwAAAAAAAAAAAAAAAA==",
	"wGiHplamyXlVB11UXWol8g==",
}

// DecryptShiroCookie reverses one Shiro RememberMe cookie.
//
// Inputs:
//
//	keyB64  — the cipherKey, base64-encoded, 16/24/32 bytes raw (AES-128/192/256)
//	cookie  — the "rememberMe" cookie value, base64 (optional "=" padding OK)
//	mode    — ShiroCBC or ShiroGCM
//
// Output is the raw plaintext the cookie decrypted to. For a successful
// RememberMe decryption the first four bytes are almost always the Java
// serialization magic 0xACED 0x0005.
func DecryptShiroCookie(keyB64, cookie string, mode ShiroCipherMode) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return nil, fmt.Errorf("shiro: bad base64 key: %w", err)
	}
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, fmt.Errorf("shiro: key length %d not in {16, 24, 32}", l)
	}

	raw, err := decodeCookieBase64(cookie)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch mode {
	case ShiroCBC:
		return shiroCBCDecrypt(block, raw)
	case ShiroGCM:
		return shiroGCMDecrypt(block, raw)
	}
	return nil, errors.New("shiro: unknown cipher mode")
}

// TryShiroAuto cycles through well-known default keys plus any extras
// supplied by the caller (typically extracted from the heap by the Shiro
// spider). For each key it tries CBC then GCM. Returns the first mode
// that produces a Java-serialized blob.
func TryShiroAuto(cookie string, extraKeys []string) (plaintext []byte, keyB64 string, mode ShiroCipherMode, ok bool) {
	candidates := append([]string{}, WellKnownShiroKeys...)
	candidates = append(candidates, extraKeys...)
	for _, k := range candidates {
		for _, m := range []ShiroCipherMode{ShiroCBC, ShiroGCM} {
			if pt, err := DecryptShiroCookie(k, cookie, m); err == nil && LooksLikeJavaSerialized(pt) {
				return pt, k, m, true
			}
		}
	}
	return nil, "", 0, false
}

// LooksLikeJavaSerialized checks for the Java ObjectOutputStream magic
// prefix 0xACED 0x0005. This is the tell-tale signature of a RememberMe
// payload that decrypted correctly.
func LooksLikeJavaSerialized(b []byte) bool {
	return len(b) >= 4 && b[0] == 0xAC && b[1] == 0xED && b[2] == 0x00 && b[3] == 0x05
}

func decodeCookieBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Shiro uses URL-safe OR standard depending on the deployment.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Unpadded variants — sometimes seen in manually-copied cookies.
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("shiro: cookie is not valid base64")
}

func shiroCBCDecrypt(block cipher.Block, raw []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(raw) < bs+bs {
		return nil, errors.New("shiro/CBC: payload too short for IV + ciphertext")
	}
	iv := raw[:bs]
	ct := raw[bs:]
	if len(ct)%bs != 0 {
		return nil, fmt.Errorf("shiro/CBC: ciphertext length %d not multiple of %d", len(ct), bs)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pt, err := pkcs5Unpad(pt, bs)
	if err != nil {
		return nil, fmt.Errorf("shiro/CBC: %w", err)
	}
	return pt, nil
}

func shiroGCMDecrypt(block cipher.Block, raw []byte) ([]byte, error) {
	// Modern Shiro layout: 16-byte IV prefix, ciphertext + 16-byte GCM tag.
	const ivLen = 16
	if len(raw) < ivLen+16 {
		return nil, errors.New("shiro/GCM: payload too short for IV + tag")
	}
	iv := raw[:ivLen]
	ct := raw[ivLen:]
	gcm, err := cipher.NewGCMWithNonceSize(block, ivLen)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("shiro/GCM: %w", err)
	}
	return pt, nil
}
