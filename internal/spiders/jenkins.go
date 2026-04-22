package spiders

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// jenkinsSpider extracts credentials stored by Jenkins core and the most
// common credentials plugin. Secrets on-heap are kept as the encrypted
// Base64 payload Jenkins writes to `credentials.xml`. When a master
// `CryptoConfidentialKey` instance is present in the same dump we
// decrypt inline; otherwise the ciphertext is surfaced so the operator
// can feed it to `cyberheap decrypt jenkins` with `master.key` harvested
// from disk.
type jenkinsSpider struct{}

func (s *jenkinsSpider) Name() string     { return "jenkins" }
func (s *jenkinsSpider) Category() string { return "credentials" }

// jenkinsCredTarget describes one credential plugin class we know how
// to extract from. Field names follow the Java source of each plugin.
type jenkinsCredTarget struct {
	fqn         string
	title       string
	userField   string // optional — username / apiTokenId / subject
	secretField string // the hudson.util.Secret reference
	idField     string
	descField   string
}

var jenkinsCredTargets = []jenkinsCredTarget{
	{
		fqn:         "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
		title:       "Jenkins username/password credential",
		userField:   "username",
		secretField: "password",
		idField:     "id",
		descField:   "description",
	},
	{
		fqn:         "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl",
		title:       "Jenkins secret-text credential",
		secretField: "secret",
		idField:     "id",
		descField:   "description",
	},
	{
		fqn:         "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",
		title:       "Jenkins SSH private-key credential",
		userField:   "username",
		secretField: "passphrase",
		idField:     "id",
		descField:   "description",
	},
	{
		fqn:         "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl",
		title:       "Jenkins certificate credential",
		secretField: "password",
		idField:     "id",
		descField:   "description",
	},
	{
		fqn:         "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
		title:       "Jenkins secret-file credential",
		secretField: "secretBytes",
		idField:     "id",
		descField:   "description",
	},
}

// jenkinsSecretKeyIDs: ConfidentialKey identifiers whose cached AES key
// can decrypt Secret payloads. The primary one is `hudson.util.Secret`.
var jenkinsSecretKeyIDs = map[string]bool{
	"hudson.util.Secret":     true,
	"hudson.util.Secret.KEY": true,
}

func (s *jenkinsSpider) Sniff(idx *heap.Index) []Finding {
	master := harvestJenkinsMasterKey(idx)
	var out []Finding
	for _, t := range jenkinsCredTargets {
		for _, cls := range idx.Subclasses(t.fqn) {
			for _, inst := range idx.Instances[cls.ID] {
				f := extractJenkinsCred(idx, inst, cls.Name, t, master)
				if f != nil {
					out = append(out, *f)
				}
			}
		}
	}
	return out
}

// extractJenkinsCred reads the credential envelope (id/description/
// username) and follows the Secret reference to the encrypted payload.
// When master is non-nil and the payload is in Jenkins V1 format
// (AES-CBC with a 16-byte IV prefix) the plaintext replaces the
// ciphertext in the finding.
func extractJenkinsCred(idx *heap.Index, inst *heap.InstanceRef, className string, t jenkinsCredTarget, master []byte) *Finding {
	var fields []Field
	addStr := func(label, name string) {
		if name == "" {
			return
		}
		v, err := idx.ReadField(inst, name)
		if err != nil || v.IsNull() {
			return
		}
		if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
			fields = append(fields, Field{Name: label, Value: s})
		}
	}
	addStr("id", t.idField)
	addStr("description", t.descField)
	addStr("username", t.userField)

	cipherText := readJenkinsSecretField(idx, inst, t.secretField)
	if cipherText == "" {
		// No usable secret — skip: a credential with no password is
		// just noise, the Jenkins UI renders empty passwords too.
		if len(fields) == 0 {
			return nil
		}
		return &Finding{
			Spider:   "jenkins",
			Severity: SeverityHigh,
			Category: "credentials",
			Title:    t.title,
			ClassFQN: className,
			ObjectID: inst.ID,
			Fields:   fields,
		}
	}
	fields = append(fields, Field{Name: "secret (encrypted, base64)", Value: cipherText})
	if master != nil {
		if plain, ok := decryptJenkinsV1(cipherText, master); ok {
			fields = append(fields, Field{Name: "secret (decrypted)", Value: plain})
		}
	}
	return &Finding{
		Spider:   "jenkins",
		Severity: SeverityHigh,
		Category: "credentials",
		Title:    t.title,
		ClassFQN: className,
		ObjectID: inst.ID,
		Fields:   fields,
	}
}

// readJenkinsSecretField follows the ref at fieldName to a
// hudson.util.Secret instance and returns the base64 ciphertext stored
// in its `value` field. Plugins that pre-decode to a byte[] are also
// handled by reading the bytes directly and re-encoding as base64 for
// consistent display.
func readJenkinsSecretField(idx *heap.Index, inst *heap.InstanceRef, fieldName string) string {
	if fieldName == "" {
		return ""
	}
	ref, err := idx.ReadField(inst, fieldName)
	if err != nil || ref.IsNull() {
		return ""
	}
	target, ok := idx.InstancesByID[ref.ObjectID]
	if ok {
		// Typical path: Secret instance; read its `value` String.
		if val, err := idx.ReadField(target, "value"); err == nil && !val.IsNull() {
			if s, ok := idx.ReadString(val.ObjectID); ok && s != "" {
				return s
			}
		}
		// Fallback: some plugins wrap the secret in another object
		// (SecretBytes, wrapper with `data` or `bytes` field).
		for _, inner := range []string{"bytes", "data", "encryptedValue"} {
			if v, err := idx.ReadField(target, inner); err == nil && !v.IsNull() {
				if b := idx.ReadByteArray(v.ObjectID); len(b) > 0 {
					return base64.StdEncoding.EncodeToString(b)
				}
			}
		}
	}
	// Ref pointed directly at a String or byte[].
	if s, ok := idx.ReadString(ref.ObjectID); ok && s != "" {
		return s
	}
	if b := idx.ReadByteArray(ref.ObjectID); len(b) > 0 {
		return base64.StdEncoding.EncodeToString(b)
	}
	return ""
}

// harvestJenkinsMasterKey walks every CryptoConfidentialKey instance
// in the heap and returns the AES key bytes for the one whose `id`
// matches a Jenkins Secret key. Returns nil when no key is present;
// the spider then emits only the ciphertext.
func harvestJenkinsMasterKey(idx *heap.Index) []byte {
	roots := []string{
		"jenkins.security.CryptoConfidentialKey",
		"hudson.util.Secret$CryptoConfidentialKey",
	}
	for _, root := range roots {
		for _, cls := range idx.Subclasses(root) {
			for _, inst := range idx.Instances[cls.ID] {
				if key := readConfidentialKey(idx, inst); key != nil {
					return key
				}
			}
		}
	}
	return nil
}

// readConfidentialKey checks that the ConfidentialKey ID is Jenkins-
// Secret-related, then follows the cached SecretKey reference into the
// backing byte[].
func readConfidentialKey(idx *heap.Index, inst *heap.InstanceRef) []byte {
	idVal, err := idx.ReadField(inst, "id")
	if err != nil || idVal.IsNull() {
		return nil
	}
	id, ok := idx.ReadString(idVal.ObjectID)
	if !ok {
		return nil
	}
	// Id may be "hudson.util.Secret.KEY" or "hudson.util.Secret" — both
	// valid depending on Jenkins version.
	if !jenkinsSecretKeyIDs[id] && !strings.HasPrefix(id, "hudson.util.Secret") {
		return nil
	}
	for _, fieldName := range []string{"secret", "cached", "secretCache"} {
		ref, err := idx.ReadField(inst, fieldName)
		if err != nil || ref.IsNull() {
			continue
		}
		if key := followSecretKey(idx, ref.ObjectID); key != nil {
			return key
		}
	}
	return nil
}

// followSecretKey descends through AtomicReference → SecretKeySpec
// → key byte[]. Returns nil if the chain doesn't resolve.
func followSecretKey(idx *heap.Index, objID uint64) []byte {
	// Direct SecretKeySpec / byte[] in some older Jenkins versions.
	if b := idx.ReadByteArray(objID); len(b) >= 16 {
		return b
	}
	for hops := 0; hops < 4; hops++ {
		inst, ok := idx.InstancesByID[objID]
		if !ok {
			return nil
		}
		// SecretKeySpec stores the key directly.
		if keyField, err := idx.ReadField(inst, "key"); err == nil && !keyField.IsNull() {
			if b := idx.ReadByteArray(keyField.ObjectID); len(b) >= 16 {
				return b
			}
		}
		// AtomicReference.value / wrappers — chase one hop.
		for _, fn := range []string{"value", "referent", "secret"} {
			if v, err := idx.ReadField(inst, fn); err == nil && !v.IsNull() {
				objID = v.ObjectID
				break
			}
		}
	}
	return nil
}

// decryptJenkinsV1 attempts the modern Jenkins Secret encoding:
//
//	byte[0]   = 0x01   (payload version)
//	byte[1:17] = IV    (16 bytes for AES-CBC)
//	byte[17:21] = int32 big-endian length of ciphertext
//	byte[21:]  = AES-128-CBC(PKCS5Padding, key=master, iv=IV)
//
// Returns the decoded plaintext and true on success. Legacy Jenkins
// (pre-2017) used AES-128-ECB with a "::::MAGIC::::" suffix; we fall
// back to that when the V1 header byte is missing.
func decryptJenkinsV1(base64Payload string, key []byte) (string, bool) {
	if len(key) < 16 {
		return "", false
	}
	key = key[:16]
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Payload))
	if err != nil || len(raw) < 22 {
		return "", false
	}
	if raw[0] == 0x01 {
		iv := raw[1:17]
		length := int(binary.BigEndian.Uint32(raw[17:21]))
		if length <= 0 || 21+length > len(raw) {
			return "", false
		}
		ct := raw[21 : 21+length]
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", false
		}
		if len(ct)%block.BlockSize() != 0 {
			return "", false
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
		return unpadPKCS5(pt), true
	}
	// Legacy ECB with MAGIC suffix stripping.
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	if len(raw)%block.BlockSize() != 0 {
		return "", false
	}
	pt := make([]byte, len(raw))
	for i := 0; i < len(raw); i += block.BlockSize() {
		block.Decrypt(pt[i:i+block.BlockSize()], raw[i:i+block.BlockSize()])
	}
	const magic = "::::MAGIC::::"
	if i := strings.Index(string(pt), magic); i >= 0 {
		return string(pt[:i]), true
	}
	return "", false
}

func unpadPKCS5(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > 16 || pad > len(b) {
		return string(b)
	}
	return string(b[:len(b)-pad])
}
