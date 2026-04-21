package decrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJasyptRoundTrip_AllSupportedAlgos encrypts and decrypts a fixed
// plaintext under every supported algorithm. This exercises the full
// pipeline — PBKDF1 derivation, CBC cipher setup, PKCS5 padding — and
// will catch any regression in the core routines.
func TestJasyptRoundTrip_AllSupportedAlgos(t *testing.T) {
	const master = "s3cret-master"
	const plaintext = "spring.datasource.password=hunter2"

	for _, algo := range SupportedJasyptAlgos {
		t.Run(algo.Name, func(t *testing.T) {
			enc, err := jasyptEncryptForTest(master, plaintext, algo.Name)
			require.NoError(t, err)
			got, err := DecryptJasypt(master, enc, algo.Name)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

func TestDecryptJasypt_WrongPassword(t *testing.T) {
	enc, err := jasyptEncryptForTest("correct", "hello world", "PBEWithMD5AndDES")
	require.NoError(t, err)
	_, err = DecryptJasypt("wrong", enc, "PBEWithMD5AndDES")
	assert.Error(t, err)
}

func TestDecryptJasypt_EncWrapper(t *testing.T) {
	enc, err := jasyptEncryptForTest("master", "hello world", "PBEWithMD5AndDES")
	require.NoError(t, err)
	got, err := DecryptJasypt("master", "ENC("+enc+")", "PBEWithMD5AndDES")
	require.NoError(t, err)
	assert.Equal(t, "hello world", got)
}

func TestDecryptJasypt_DefaultAlgoIsMD5DES(t *testing.T) {
	// Empty algo string must fall back to the Jasypt 1.x default.
	enc, err := jasyptEncryptForTest("master", "x", "PBEWithMD5AndDES")
	require.NoError(t, err)
	got, err := DecryptJasypt("master", enc, "")
	require.NoError(t, err)
	assert.Equal(t, "x", got)
}

func TestDecryptJasypt_UnsupportedAlgo(t *testing.T) {
	_, err := DecryptJasypt("master", "deadbeef", "PBEWithHMACSHA512AndAES256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestTryJasyptAuto_FindsMaster(t *testing.T) {
	enc, err := jasyptEncryptForTest("s3cret-master", "prod-database-password", "PBEWithMD5AndDES")
	require.NoError(t, err)
	pt, master, algo, ok := TryJasyptAuto(enc, []string{"wrong", "nope", "s3cret-master", "alsowrong"})
	assert.True(t, ok)
	assert.Equal(t, "prod-database-password", pt)
	assert.Equal(t, "s3cret-master", master)
	assert.Equal(t, "PBEWithMD5AndDES", algo)
}

func TestTryJasyptAuto_NoMatch(t *testing.T) {
	enc, err := jasyptEncryptForTest("real", "secret", "PBEWithMD5AndDES")
	require.NoError(t, err)
	_, _, _, ok := TryJasyptAuto(enc, []string{"wrong1", "wrong2"})
	assert.False(t, ok)
}

func TestLooksLikePlaintext(t *testing.T) {
	assert.True(t, looksLikePlaintext("spring.datasource.password=hunter2"))
	assert.False(t, looksLikePlaintext(string([]byte{0x00, 0xff, 0xfe, 0xfd})))
	assert.False(t, looksLikePlaintext(""))
}
