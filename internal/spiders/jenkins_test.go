package spiders

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// TestJenkinsSpider_UsernamePasswordNoKey: credential captured without
// decryption when master key not present — ciphertext surfaces verbatim.
func TestJenkinsSpider_UsernamePasswordNoKey(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringAlloc{}
	mint := newStringMint(b, ids)

	// Strings we reference.
	usernameStr := mint.mint("jenkins-admin")
	idStr := mint.mint("cred-001")
	descStr := mint.mint("Prod deploy user")
	cipherStr := mint.mint(encryptJenkinsV1(t, []byte("hunter2"), []byte("0123456789abcdef")))

	// hudson.util.Secret class: single field `value` (object ref).
	secretName := ids.add(b, "hudson/util/Secret")
	valueFld := ids.add(b, "value")
	const secretClass uint64 = 0x4100
	b.AddLoadClass(0x41, secretClass, secretName)
	b.AddClassDump(secretClass, 0, 8, []hprof.FieldDecl{
		{NameID: valueFld, Type: hprof.PrimObject},
	})
	const secretInst uint64 = 0x4200
	b.AddInstanceDump(secretInst, secretClass, b.PackID(cipherStr))

	// UsernamePasswordCredentialsImpl: id / description / username / password.
	credName := ids.add(b, "com/cloudbees/plugins/credentials/impl/UsernamePasswordCredentialsImpl")
	idFld := ids.add(b, "id")
	descFld := ids.add(b, "description")
	userFld := ids.add(b, "username")
	passFld := ids.add(b, "password")
	const credClass uint64 = 0x4300
	b.AddLoadClass(0x43, credClass, credName)
	b.AddClassDump(credClass, 0, 32, []hprof.FieldDecl{
		{NameID: idFld, Type: hprof.PrimObject},
		{NameID: descFld, Type: hprof.PrimObject},
		{NameID: userFld, Type: hprof.PrimObject},
		{NameID: passFld, Type: hprof.PrimObject},
	})
	const credInst uint64 = 0x4400
	b.AddInstanceDump(credInst, credClass, b.PackBytes(
		b.PackID(idStr),
		b.PackID(descStr),
		b.PackID(usernameStr),
		b.PackID(secretInst),
	))

	idx, err := heap.Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	findings := (&jenkinsSpider{}).Sniff(idx)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "Jenkins username/password credential", f.Title)
	assert.Equal(t, SeverityHigh, f.Severity)

	m := map[string]string{}
	for _, kv := range f.Fields {
		m[kv.Name] = kv.Value
	}
	assert.Equal(t, "cred-001", m["id"])
	assert.Equal(t, "Prod deploy user", m["description"])
	assert.Equal(t, "jenkins-admin", m["username"])
	assert.NotEmpty(t, m["secret (encrypted, base64)"])
	_, hasPlain := m["secret (decrypted)"]
	assert.False(t, hasPlain, "no master key in heap → no decrypted field")
}

// TestDecryptJenkinsV1_RoundTrip verifies our inline decrypt matches
// the Jenkins V1 payload format end-to-end.
func TestDecryptJenkinsV1_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := "super-secret-admin-token"
	ct := encryptJenkinsV1(t, []byte(plaintext), key)
	got, ok := decryptJenkinsV1(ct, key)
	require.True(t, ok)
	assert.Equal(t, plaintext, got)
}

// TestDecryptJenkinsV1_BadKey rejects a decrypt attempt with a wrong
// key: PKCS5 unpad either gives garbage or an invalid pad byte — the
// roundtrip assertion guards the happy path; here we only need the
// result to differ from the expected plaintext.
func TestDecryptJenkinsV1_BadKey(t *testing.T) {
	good := []byte("0123456789abcdef")
	bad := []byte("fedcba9876543210")
	ct := encryptJenkinsV1(t, []byte("hello world"), good)
	got, ok := decryptJenkinsV1(ct, bad)
	// Decryption completes (no padding error every time on AES), but
	// the plaintext won't match. Accept either outcome.
	if ok {
		assert.NotEqual(t, "hello world", got)
	}
}

// encryptJenkinsV1 builds the V1 payload Jenkins emits:
//
//	byte 0x01 | 16-byte IV | int32 ciphertext length | AES-CBC ciphertext
func encryptJenkinsV1(t *testing.T, plaintext, key []byte) string {
	t.Helper()
	require.Len(t, key, 16)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	padded := padPKCS5(plaintext, block.BlockSize())
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	buf := make([]byte, 0, 1+16+4+len(ct))
	buf = append(buf, 0x01)
	buf = append(buf, iv...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
	buf = append(buf, lenBuf...)
	buf = append(buf, ct...)
	return base64.StdEncoding.EncodeToString(buf)
}

func padPKCS5(b []byte, size int) []byte {
	pad := size - len(b)%size
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}
