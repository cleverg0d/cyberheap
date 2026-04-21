package spiders

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// shiroSpider pulls the Apache Shiro RememberMe cipher key out of the heap.
// Whoever has this key can forge a serialized Java object in the
// "rememberMe" cookie — a direct path to RCE on many Shiro-backed apps
// (CVE-2016-4437 and the long tail of related Shiro deserialization bugs).
//
// Target classes:
//
//	org.apache.shiro.web.mgt.CookieRememberMeManager
//	  ← extends AbstractRememberMeManager which holds the byte[] cipherKey
//	    via cipherService (encryptionCipherKey / decryptionCipherKey fields).
type shiroSpider struct{}

func (s *shiroSpider) Name() string     { return "shiro" }
func (s *shiroSpider) Category() string { return "shiro" }

func (s *shiroSpider) Sniff(idx *heap.Index) []Finding {
	// AbstractRememberMeManager is the ancestor; Subclasses() already
	// returns CookieRememberMeManager and every concrete subclass via
	// the precomputed children map. Calling it twice (abstract + cookie)
	// like we did previously was redundant work that the per-object
	// `seen` map silently swallowed.
	var out []Finding
	seen := map[uint64]bool{}

	candidates := idx.Subclasses("org.apache.shiro.mgt.AbstractRememberMeManager")

	for _, cls := range candidates {
		for _, inst := range idx.Instances[cls.ID] {
			if seen[inst.ID] {
				continue
			}
			seen[inst.ID] = true

			var fields []Field
			addKey := func(label, path string) {
				v, err := idx.ReadField(inst, path)
				if err != nil || v.IsNull() {
					return
				}
				raw := idx.ReadByteArray(v.ObjectID)
				if len(raw) == 0 {
					return
				}
				fields = append(fields,
					Field{Name: label + " (base64)", Value: base64.StdEncoding.EncodeToString(raw)},
					Field{Name: label + " (hex)", Value: hex.EncodeToString(raw)},
					Field{Name: label + " (bytes)", Value: humanLen(raw)},
				)
			}

			// Top-level convenience fields in AbstractRememberMeManager
			// that some older Shiro versions expose directly.
			addKey("cipherKey", "cipherKey")
			addKey("encryptionCipherKey", "encryptionCipherKey")
			addKey("decryptionCipherKey", "decryptionCipherKey")

			// Modern Shiro: cipherService carries the key internally.
			// Try a couple of common paths.
			addKey("cipherService.key", "cipherService.key")
			addKey("cipherService.encryptionCipherKey", "cipherService.encryptionCipherKey")

			if algo, err := idx.ReadField(inst, "cipherService.algorithmName"); err == nil && !algo.IsNull() {
				if s, ok := idx.ReadString(algo.ObjectID); ok && s != "" {
					fields = append(fields, Field{Name: "algorithm", Value: s})
				}
			}

			if len(fields) == 0 {
				continue
			}
			out = append(out, Finding{
				Spider:   "shiro",
				Severity: SeverityCritical,
				Category: "shiro",
				Title:    "Shiro RememberMe cipher key (RCE primitive)",
				ClassFQN: cls.Name,
				ObjectID: inst.ID,
				Fields:   fields,
			})
		}
	}
	return out
}

func humanLen(b []byte) string {
	// Shiro default is a 16-byte AES-128 key; longer keys are sometimes
	// seen in custom deployments. Show the length so the analyst can
	// pick the right decryption routine.
	switch len(b) {
	case 16:
		return "16 (AES-128)"
	case 24:
		return "24 (AES-192)"
	case 32:
		return "32 (AES-256)"
	default:
		return itoa(len(b))
	}
}

// itoa avoids pulling strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return sign + string(digits[i:])
}
