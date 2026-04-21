package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptShiroCBCForTest mirrors Shiro's DefaultBlockCipherService encrypt
// path: AES-CBC-PKCS5, random 16-byte IV prepended to ciphertext, the
// whole blob returned as base64. Lives in _test.go only — CyberHeap
// never encrypts in production, it only reads.
func encryptShiroCBCForTest(keyB64 string, plaintext []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pkcs5Pad(plaintext, block.BlockSize())
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return base64.StdEncoding.EncodeToString(append(iv, ct...)), nil
}

func encryptShiroGCMForTest(keyB64 string, plaintext []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, iv, plaintext, nil)
	return base64.StdEncoding.EncodeToString(append(iv, ct...)), nil
}

// javaSerializedSample is a minimal byte sequence that starts with the
// standard ObjectOutputStream magic. We use it as the "plaintext" under
// round-trip tests so the LooksLikeJavaSerialized check fires.
var javaSerializedSample = []byte{
	0xAC, 0xED, 0x00, 0x05,
	't', 0x00, 0x04, 'b', 'o', 'b', ' ', // fake name payload
}

const testShiroKey = "kPH+bIxk5D2deZiIxcaaaA==" // 16 bytes, historical Shiro default

func TestDecryptShiro_CBC_RoundTrip(t *testing.T) {
	cookie, err := encryptShiroCBCForTest(testShiroKey, javaSerializedSample)
	require.NoError(t, err)
	got, err := DecryptShiroCookie(testShiroKey, cookie, ShiroCBC)
	require.NoError(t, err)
	assert.Equal(t, javaSerializedSample, got)
	assert.True(t, LooksLikeJavaSerialized(got))
}

func TestDecryptShiro_GCM_RoundTrip(t *testing.T) {
	cookie, err := encryptShiroGCMForTest(testShiroKey, javaSerializedSample)
	require.NoError(t, err)
	got, err := DecryptShiroCookie(testShiroKey, cookie, ShiroGCM)
	require.NoError(t, err)
	assert.Equal(t, javaSerializedSample, got)
}

func TestDecryptShiro_WrongKey(t *testing.T) {
	cookie, err := encryptShiroCBCForTest(testShiroKey, javaSerializedSample)
	require.NoError(t, err)
	// Any other valid 16-byte key should fail to unpad or produce junk.
	_, err = DecryptShiroCookie("AAAAAAAAAAAAAAAAAAAAAA==", cookie, ShiroCBC)
	assert.Error(t, err)
}

func TestDecryptShiro_BadKeyLength(t *testing.T) {
	// 10 bytes — not AES-valid.
	bad := base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err := DecryptShiroCookie(bad, "whatever==", ShiroCBC)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key length")
}

func TestTryShiroAuto_UsesWellKnown(t *testing.T) {
	// The historical default is in WellKnownShiroKeys, so auto-detect
	// should succeed without needing any extra candidates.
	cookie, err := encryptShiroCBCForTest(testShiroKey, javaSerializedSample)
	require.NoError(t, err)
	pt, usedKey, mode, ok := TryShiroAuto(cookie, nil)
	require.True(t, ok)
	assert.Equal(t, javaSerializedSample, pt)
	assert.Equal(t, testShiroKey, usedKey)
	assert.Equal(t, ShiroCBC, mode)
}

func TestTryShiroAuto_ExtraKeyMatches(t *testing.T) {
	// Random 16-byte key — not in the well-known list.
	rawKey := make([]byte, 16)
	_, _ = rand.Read(rawKey)
	key := base64.StdEncoding.EncodeToString(rawKey)

	cookie, err := encryptShiroGCMForTest(key, javaSerializedSample)
	require.NoError(t, err)
	_, used, mode, ok := TryShiroAuto(cookie, []string{key})
	require.True(t, ok)
	assert.Equal(t, key, used)
	assert.Equal(t, ShiroGCM, mode)
}

func TestLooksLikeJavaSerialized(t *testing.T) {
	assert.True(t, LooksLikeJavaSerialized([]byte{0xAC, 0xED, 0x00, 0x05, 0x00}))
	assert.False(t, LooksLikeJavaSerialized([]byte{0xAC, 0xED, 0x00, 0x04}))
	assert.False(t, LooksLikeJavaSerialized(nil))
}
