// Package decrypt implements the cleartext-recovery primitives CyberHeap
// surfaces via the "decrypt" subcommand:
//
//   - Jasypt string encryptors (PBEWithMD5AndDES / TripleDES / SHA variants)
//   - Apache Shiro RememberMe cookies (AES-CBC, AES-GCM)
//   - JWT signature verification and claim display
//
// The algorithms here deliberately re-implement what the Java libraries
// use on the encryption side rather than pulling in an unrelated Go
// crypto library — transparency matters for a pentest tool.
package decrypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// pbkdf1 is the original PKCS#5 v1 key-derivation routine used by Java's
// PBE ciphers since the DES era. Jasypt 1.x + Spring inherit it.
//
// Algorithm per RFC 2898:
//
//	T_1 = Hash(password || salt)
//	T_i = Hash(T_{i-1})          for i = 2 .. c
//	DK  = T_c [0 .. dkLen-1]     (truncate)
//
// For PBEWithMD5AndDES Jasypt uses iterations=1000, salt=8 bytes, hash=MD5
// and derives a 16-byte buffer: first 8 go into the DES key, next 8 into
// the IV. The TripleDES variant uses two MD5 rounds to build 24-byte key
// plus 8-byte IV.
func pbkdf1(password, salt []byte, iterations, dkLen int, h hash.Hash) []byte {
	// First round hashes password || salt.
	h.Reset()
	h.Write(password)
	h.Write(salt)
	cur := h.Sum(nil)
	// Subsequent rounds hash the previous output.
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(cur)
		cur = h.Sum(nil)
	}
	// Jasypt's PBEWithMD5AndTripleDES needs 32 bytes but the raw
	// PBKDF1 primitive only produces one hash-width chunk. Extend by
	// re-hashing.
	if dkLen > len(cur) {
		out := make([]byte, 0, dkLen)
		out = append(out, cur...)
		prev := cur
		for len(out) < dkLen {
			h.Reset()
			h.Write(prev)
			prev = h.Sum(nil)
			out = append(out, prev...)
		}
		return out[:dkLen]
	}
	return cur[:dkLen]
}

// hashFactory returns a fresh hash.Hash for the named algorithm. Jasypt
// algorithm strings look like "PBEWithMD5AndDES" — the caller extracts
// the hash portion ("MD5") and passes it here.
func hashFactory(name string) (hash.Hash, error) {
	switch name {
	case "MD5":
		return md5.New(), nil
	case "SHA1", "SHA-1":
		return sha1.New(), nil
	case "SHA256", "SHA-256":
		return sha256.New(), nil
	case "SHA512", "SHA-512":
		return sha512.New(), nil
	}
	return nil, errors.New("unsupported hash: " + name)
}
