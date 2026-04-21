package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// jasyptKDF tags how Jasypt derives the AES/DES key from the master password.
type jasyptKDF int

const (
	kdfPBKDF1 jasyptKDF = iota // Jasypt 1.x legacy (MD5/SHA1 + DES/3DES)
	kdfPBKDF2                  // Jasypt 3.x modern (HMAC-SHA* + AES)
)

// JasyptAlgo describes one supported Jasypt cipher profile.
//
// Layout:
//
//	PBKDF1 (IVLen == 0):  base64(salt || ciphertext)
//	                      IV is derived together with the key from the hash output.
//	PBKDF2 (IVLen  > 0):  base64(salt || iv || ciphertext)
//	                      IV is random, prepended between salt and ciphertext.
type JasyptAlgo struct {
	Name       string    // exactly as it appears in application.properties
	KDF        jasyptKDF // PBKDF1 or PBKDF2
	Hash       string    // "MD5" | "SHA1" | "SHA256" | "SHA512"
	Iterations int       // Jasypt default = 1000 for every supported profile
	SaltLen    int       // 8 for DES-era algos, 16 for AES-era
	IVLen      int       // 0 for PBKDF1 (IV co-derived), 16 for AES-CBC
	KeyLen     int       // cipher key size in bytes
	BlockSize  int       // 8 for DES/3DES, 16 for AES
	Cipher     string    // "DES" | "3DES" | "AES"
}

// SupportedJasyptAlgos enumerates profiles we handle. Order matters for
// --auto mode: Jasypt 3.x defaults come first so modern installs resolve
// quickly, then Jasypt 1.x defaults behind them.
var SupportedJasyptAlgos = []JasyptAlgo{
	// --- Jasypt 3.x PBKDF2 + AES ---
	{
		Name: "PBEWithHMACSHA512AndAES_256", KDF: kdfPBKDF2, Hash: "SHA512",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 32, BlockSize: 16, Cipher: "AES",
	},
	{
		Name: "PBEWithHMACSHA512AndAES_128", KDF: kdfPBKDF2, Hash: "SHA512",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 16, BlockSize: 16, Cipher: "AES",
	},
	{
		Name: "PBEWithHMACSHA256AndAES_256", KDF: kdfPBKDF2, Hash: "SHA256",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 32, BlockSize: 16, Cipher: "AES",
	},
	{
		Name: "PBEWithHMACSHA256AndAES_128", KDF: kdfPBKDF2, Hash: "SHA256",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 16, BlockSize: 16, Cipher: "AES",
	},
	{
		Name: "PBEWithHMACSHA1AndAES_256", KDF: kdfPBKDF2, Hash: "SHA1",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 32, BlockSize: 16, Cipher: "AES",
	},
	{
		Name: "PBEWithHMACSHA1AndAES_128", KDF: kdfPBKDF2, Hash: "SHA1",
		Iterations: 1000, SaltLen: 16, IVLen: 16, KeyLen: 16, BlockSize: 16, Cipher: "AES",
	},

	// --- Jasypt 1.x PBKDF1 + DES/3DES (unchanged) ---
	{
		Name: "PBEWithMD5AndDES", KDF: kdfPBKDF1, Hash: "MD5",
		Iterations: 1000, SaltLen: 8, IVLen: 0, KeyLen: 8, BlockSize: 8, Cipher: "DES",
	},
	{
		Name: "PBEWithMD5AndTripleDES", KDF: kdfPBKDF1, Hash: "MD5",
		Iterations: 1000, SaltLen: 8, IVLen: 0, KeyLen: 24, BlockSize: 8, Cipher: "3DES",
	},
	{
		Name: "PBEWithSHA1AndDESede", KDF: kdfPBKDF1, Hash: "SHA1",
		Iterations: 1000, SaltLen: 8, IVLen: 0, KeyLen: 24, BlockSize: 8, Cipher: "3DES",
	},
}

// DecryptJasypt reverses a Jasypt PBE-encrypted string given the master
// password. The input may be raw base64 or the ENC(...) wrapper; both
// are accepted.
func DecryptJasypt(master, encValue, algoName string) (string, error) {
	algo, err := findAlgo(algoName)
	if err != nil {
		return "", err
	}
	raw, err := unwrapAndDecode(encValue)
	if err != nil {
		return "", err
	}
	if len(raw) < algo.SaltLen+algo.IVLen {
		return "", fmt.Errorf("jasypt: ciphertext too short for %s (need ≥ %d bytes, got %d)",
			algo.Name, algo.SaltLen+algo.IVLen, len(raw))
	}

	salt := raw[:algo.SaltLen]
	rem := raw[algo.SaltLen:]
	var iv []byte
	if algo.IVLen > 0 {
		iv = rem[:algo.IVLen]
		rem = rem[algo.IVLen:]
	}
	ct := rem
	if len(ct)%algo.BlockSize != 0 {
		return "", fmt.Errorf("jasypt: ciphertext length %d not a multiple of block size %d",
			len(ct), algo.BlockSize)
	}

	var key []byte
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
		// iv was already sliced off above
	}

	pt, err := jasyptDecryptCBC(algo.Cipher, key, iv, ct)
	if err != nil {
		return "", err
	}
	pt, err = pkcs5Unpad(pt, algo.BlockSize)
	if err != nil {
		return "", fmt.Errorf("jasypt: decryption failed (wrong password or algorithm?): %w", err)
	}
	return string(pt), nil
}

// TryJasyptAuto tries every candidate master password against every
// supported algorithm and returns the first clean result.
func TryJasyptAuto(encValue string, candidates []string) (plaintext, master, algo string, ok bool) {
	for _, a := range SupportedJasyptAlgos {
		for _, cand := range candidates {
			if cand == "" {
				continue
			}
			if pt, err := DecryptJasypt(cand, encValue, a.Name); err == nil && looksLikePlaintext(pt) {
				return pt, cand, a.Name, true
			}
		}
	}
	return "", "", "", false
}

func looksLikePlaintext(s string) bool {
	if s == "" {
		return false
	}
	printable := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r' {
			printable++
		}
	}
	return printable*10 >= len(s)*8
}

// defaultJasyptAlgo is Jasypt 1.x's historical default. We keep it as the
// empty-flag default because it's still the most widely-deployed profile
// in real pentest scopes — Jasypt 3.x is opt-in and usually specified
// explicitly in application.properties. For modern installs the caller
// should pass --algo or --auto, which walks every supported profile.
const defaultJasyptAlgo = "PBEWithMD5AndDES"

func findAlgo(name string) (JasyptAlgo, error) {
	if name == "" {
		name = defaultJasyptAlgo
	}
	for _, a := range SupportedJasyptAlgos {
		if strings.EqualFold(a.Name, name) {
			return a, nil
		}
	}
	return JasyptAlgo{}, fmt.Errorf("unsupported Jasypt algorithm %q (try one of: %s)", name, algoList())
}

func algoList() string {
	names := make([]string, len(SupportedJasyptAlgos))
	for i, a := range SupportedJasyptAlgos {
		names[i] = a.Name
	}
	return strings.Join(names, ", ")
}

// unwrapAndDecode handles ENC(...) wrapping and also accepts raw hex or
// raw base64. Jasypt's default output is base64.
func unwrapAndDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "ENC(") && strings.HasSuffix(s, ")") {
		s = s[4 : len(s)-1]
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("jasypt: value is neither base64 nor hex")
}

// jasyptDecryptCBC dispatches on the cipher family. Renamed from
// cbcDecrypt to avoid colliding with the Shiro helpers.
func jasyptDecryptCBC(cipherName string, key, iv, ct []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	switch cipherName {
	case "DES":
		block, err = des.NewCipher(key)
	case "3DES":
		block, err = des.NewTripleDESCipher(key)
	case "AES":
		block, err = aes.NewCipher(key) // Go selects 128/192/256 by key length
	default:
		return nil, fmt.Errorf("unsupported cipher %q", cipherName)
	}
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("bad IV length %d (want %d)", len(iv), block.BlockSize())
	}
	dec := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ct))
	dec.CryptBlocks(pt, ct)
	return pt, nil
}

// pkcs5Unpad strips PKCS#5 / PKCS#7 padding. Returns an error if the
// padding is obviously wrong — usually a sign of an incorrect password.
func pkcs5Unpad(pt []byte, blockSize int) ([]byte, error) {
	if len(pt) == 0 || len(pt)%blockSize != 0 {
		return nil, errors.New("pkcs5: bad length")
	}
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("pkcs5: invalid padding byte")
	}
	for i := len(pt) - pad; i < len(pt); i++ {
		if int(pt[i]) != pad {
			return nil, errors.New("pkcs5: inconsistent padding")
		}
	}
	return pt[:len(pt)-pad], nil
}
