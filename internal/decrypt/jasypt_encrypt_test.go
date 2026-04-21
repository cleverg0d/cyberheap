package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// jasyptEncryptForTest mirrors the two Jasypt encrypt pipelines (PBKDF1
// and PBKDF2) so we can run full encrypt→decrypt round-trip tests without
// a precomputed Java fixture. Production code only decrypts; this lives in
// a _test.go file on purpose.
func jasyptEncryptForTest(master, plaintext, algoName string) (string, error) {
	algo, err := findAlgo(algoName)
	if err != nil {
		return "", err
	}

	salt := make([]byte, algo.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	var key, iv []byte

	switch algo.KDF {
	case kdfPBKDF1:
		h, err := hashFactory(algo.Hash)
		if err != nil {
			return "", err
		}
		derived := pbkdf1([]byte(master), salt, algo.Iterations, algo.KeyLen+algo.BlockSize, h)
		key = derived[:algo.KeyLen]
		iv = derived[algo.KeyLen : algo.KeyLen+algo.BlockSize]
	case kdfPBKDF2:
		prf, err := prfFactory(algo.Hash)
		if err != nil {
			return "", err
		}
		key = pbkdf2([]byte(master), salt, algo.Iterations, algo.KeyLen, prf)
		iv = make([]byte, algo.IVLen)
		if _, err := rand.Read(iv); err != nil {
			return "", err
		}
	}

	var block cipher.Block
	switch algo.Cipher {
	case "DES":
		block, err = des.NewCipher(key)
	case "3DES":
		block, err = des.NewTripleDESCipher(key)
	case "AES":
		block, err = aes.NewCipher(key)
	default:
		return "", fmt.Errorf("unsupported cipher %q", algo.Cipher)
	}
	if err != nil {
		return "", err
	}

	padded := pkcs5Pad([]byte(plaintext), algo.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// Layout matches Jasypt's on-disk shape: PBKDF1 prepends salt only,
	// PBKDF2 prepends salt then iv.
	out := append([]byte{}, salt...)
	if algo.IVLen > 0 {
		out = append(out, iv...)
	}
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func pkcs5Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}
