package spiders

import (
	"github.com/cleverg0d/cyberheap/internal/heap"
)

// jasyptSpider collects candidate master passwords used by Jasypt
// encryptors live in the heap at the moment of the dump. These are the
// values users typically set through:
//
//   - application.properties: jasypt.encryptor.password=XXX
//   - environment variable:    JASYPT_ENCRYPTOR_PASSWORD=XXX
//   - programmatic API:        encryptor.setPassword("XXX")
//
// After construction, the Jasypt encryptor caches the password on the
// instance field "password" (char[]) or in the config object. We harvest
// each candidate so `cyberheap decrypt jasypt --auto` can try them in
// bulk against an ENC(...) value.
type jasyptSpider struct{}

func (s *jasyptSpider) Name() string     { return "jasypt" }
func (s *jasyptSpider) Category() string { return "credentials" }

// Target classes — every JAsypt encryptor with a settable password.
var jasyptTargets = []string{
	"org.jasypt.encryption.pbe.StandardPBEStringEncryptor",
	"org.jasypt.encryption.pbe.StandardPBEByteEncryptor",
	"org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor",
	"org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor",
	"org.jasypt.encryption.pbe.PooledPBEStringEncryptor",
	"org.jasypt.encryption.pbe.PooledPBEByteEncryptor",
	"org.jasypt.encryption.pbe.config.SimpleStringPBEConfig",
	"org.jasypt.encryption.pbe.config.SimplePBEConfig",
	"org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig",
	"com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver",
}

func (s *jasyptSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	seen := map[uint64]bool{}

	for _, fqn := range jasyptTargets {
		for _, cls := range idx.Subclasses(fqn) {
			for _, inst := range idx.Instances[cls.ID] {
				if seen[inst.ID] {
					continue
				}
				seen[inst.ID] = true

				// The password might live either directly on the
				// encryptor, or on an inner "config" object — try both.
				pw := readJasyptPassword(idx, inst)
				if pw == "" {
					continue
				}
				out = append(out, Finding{
					Spider:   "jasypt",
					Severity: SeverityCritical,
					Category: "credentials",
					Title:    "Jasypt master password (decrypts every ENC(...) value)",
					ClassFQN: cls.Name,
					ObjectID: inst.ID,
					Fields:   []Field{{Name: "password", Value: pw}},
				})
			}
		}
	}
	return out
}

// readJasyptPassword tries the most common field paths where Jasypt
// stashes the master password post-init.
func readJasyptPassword(idx *heap.Index, inst *heap.InstanceRef) string {
	for _, path := range []string{
		"password",
		"passwordCharArray",
		"config.password",
		"config.passwordCharArray",
	} {
		v, err := idx.ReadField(inst, path)
		if err != nil || v.IsNull() {
			continue
		}
		// Might be a java.lang.String, a char[], or a byte[].
		if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
			return s
		}
		if arr, ok := idx.PrimArrays[v.ObjectID]; ok {
			if s := primArrayToString(arr); s != "" {
				return s
			}
		}
	}
	return ""
}

// primArrayToString converts a char[] or byte[] primitive array to a
// displayable Go string.
func primArrayToString(arr *heap.PrimArray) string {
	switch arr.ElementType.String() {
	case "char":
		return decodeCharArray(arr.Elements)
	case "byte":
		return string(arr.Elements)
	}
	return ""
}
