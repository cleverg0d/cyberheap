package decrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// pbkdf2 implements PBKDF2 (RFC 2898 §5.2) with a pluggable PRF hash.
// Jasypt 3.x `PBEWithHMACSHA*AndAES_*` algorithms use PBKDF2 here with
// HMAC-SHA as the PRF, so a dependency on x/crypto is avoided.
//
// Parameters:
//
//	password    — master password bytes
//	salt        — random salt from the ciphertext blob
//	iterations  — Jasypt default is 1000
//	keyLen      — derived key length in bytes (16 for AES-128, 32 for AES-256)
//	prf         — constructor for a new HMAC hash (e.g. sha256.New)
func pbkdf2(password, salt []byte, iterations, keyLen int, prf func() hash.Hash) []byte {
	hashLen := prf().Size()
	blocks := (keyLen + hashLen - 1) / hashLen

	out := make([]byte, 0, blocks*hashLen)
	block := make([]byte, hashLen)
	u := make([]byte, hashLen)
	var counter [4]byte

	for i := 1; i <= blocks; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		// U1 = PRF(password, salt || INT(i))
		h := hmac.New(prf, password)
		h.Write(salt)
		h.Write(counter[:])
		u = h.Sum(u[:0])
		copy(block, u)
		// U_n = PRF(password, U_{n-1}); T_i = XOR(U1 .. Un)
		for j := 1; j < iterations; j++ {
			h = hmac.New(prf, password)
			h.Write(u)
			u = h.Sum(u[:0])
			for k := range block {
				block[k] ^= u[k]
			}
		}
		out = append(out, block...)
	}
	return out[:keyLen]
}

// prfFactory resolves the Jasypt algorithm-name hash portion into a
// hmac-ready PRF constructor.
func prfFactory(name string) (func() hash.Hash, error) {
	switch name {
	case "MD5":
		return md5.New, nil
	case "SHA1", "SHA-1":
		return sha1.New, nil
	case "SHA256", "SHA-256":
		return sha256.New, nil
	case "SHA512", "SHA-512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported PRF hash: %s", name)
}
