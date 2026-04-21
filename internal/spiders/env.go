package spiders

import (
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// envSpider walks the JVM's snapshot of the process environment.
//
// The JDK caches getenv() results in java.lang.ProcessEnvironment, which
// holds two static fields:
//
//   - theEnvironment             HashMap<Variable, Value>   (raw, byte-backed)
//   - theUnmodifiableEnvironment Map<String,  String>       (convenience view)
//
// We prefer the unmodifiable view because its keys and values are ordinary
// java.lang.String — a one-step ReadString per entry. For the rare case
// where only the raw map is present, we fall back to walking the byte[]
// values inside each Variable/Value wrapper.
//
// This matters: production env vars like DB_PASSWORD, AWS_SECRET_ACCESS_KEY,
// VAULT_TOKEN typically arrive via environment, and Spring's
// SystemEnvironmentPropertySource mirrors the same data — but PropertySource
// spider only catches it when Spring is in the picture.
type envSpider struct{}

func (s *envSpider) Name() string     { return "env" }
func (s *envSpider) Category() string { return "credentials" }

func (s *envSpider) Sniff(idx *heap.Index) []Finding {
	cls, ok := idx.ClassByName["java.lang.ProcessEnvironment"]
	if !ok {
		return nil
	}

	// Prefer the String/String unmodifiable view.
	if ref, ok := idx.StaticField(cls.ID, "theUnmodifiableEnvironment"); ok && !ref.IsNull() {
		if f := extractEnvMap(idx, cls, ref.ObjectID, false); f != nil {
			return []Finding{*f}
		}
	}
	// Fallback: the raw HashMap<Variable, Value>.
	if ref, ok := idx.StaticField(cls.ID, "theEnvironment"); ok && !ref.IsNull() {
		if f := extractEnvMap(idx, cls, ref.ObjectID, true); f != nil {
			return []Finding{*f}
		}
	}
	return nil
}

// extractEnvMap walks a map instance and collects entries whose key name
// looks secret-bearing. wrappedValues=true means keys and values are
// ProcessEnvironment's Variable/Value objects (byte[] under the hood) rather
// than plain String; we transparently unwrap them.
func extractEnvMap(idx *heap.Index, cls *heap.ClassDef, mapID uint64, wrappedValues bool) *Finding {
	mapInst, ok := idx.InstancesByID[mapID]
	if !ok {
		return nil
	}
	var fields []Field
	walkMapLike(idx, mapInst, func(k, v heap.Value) bool {
		key := readEnvName(idx, k, wrappedValues)
		if key == "" || !looksSecretKey(key) {
			return true
		}
		val := readEnvValue(idx, v, wrappedValues)
		if val == "" || looksTrivialValue(val) {
			return true
		}
		fields = append(fields, Field{Name: key, Value: val})
		return true
	})

	if len(fields) == 0 {
		return nil
	}
	return &Finding{
		Spider:   "env",
		Severity: SeverityHigh,
		Category: "credentials",
		Title:    "JVM process environment variables",
		ClassFQN: cls.Name,
		ObjectID: mapInst.ID,
		Fields:   fields,
	}
}

func readEnvName(idx *heap.Index, v heap.Value, wrapped bool) string {
	if v.IsNull() {
		return ""
	}
	// Plain String path works for theUnmodifiableEnvironment.
	if s, ok := idx.ReadString(v.ObjectID); ok {
		return s
	}
	if !wrapped {
		return ""
	}
	// ProcessEnvironment.Variable holds a byte[] in "bytes" or "value".
	inst, ok := idx.InstancesByID[v.ObjectID]
	if !ok {
		return ""
	}
	for _, candidate := range []string{"bytes", "value"} {
		b, ok := readByteArrayField(idx, inst, candidate)
		if ok && len(b) > 0 {
			return string(b)
		}
	}
	return ""
}

func readEnvValue(idx *heap.Index, v heap.Value, wrapped bool) string {
	if v.IsNull() {
		return ""
	}
	if s, ok := idx.ReadString(v.ObjectID); ok {
		return s
	}
	if !wrapped {
		return ""
	}
	inst, ok := idx.InstancesByID[v.ObjectID]
	if !ok {
		return ""
	}
	for _, candidate := range []string{"bytes", "value"} {
		b, ok := readByteArrayField(idx, inst, candidate)
		if ok && len(b) > 0 {
			return string(b)
		}
	}
	return ""
}

// looksTrivialValue rejects values that happen to sit under a
// secret-shaped key name but plainly aren't credentials: booleans,
// small integers (counts, timeouts, port numbers), file paths
// (env vars like HOME/PWD on POSIX or C:\Windows\... on Windows),
// and obvious flags such as "none"/"disabled".
func looksTrivialValue(v string) bool {
	if len(v) < 4 {
		return true
	}
	lv := strings.ToLower(strings.TrimSpace(v))
	switch lv {
	case "true", "false", "null", "none", "nil", "disabled", "enabled", "yes", "no":
		return true
	}
	// POSIX filesystem path.
	if strings.HasPrefix(v, "/") && !strings.Contains(v, " ") && !strings.Contains(v, ":") {
		return true
	}
	// Windows filesystem path (C:\..., \\server\share\...).
	if len(v) >= 3 && v[1] == ':' && v[2] == '\\' {
		return true
	}
	if strings.HasPrefix(v, "\\\\") {
		return true
	}
	// Pure integer (counts, timeouts, port numbers).
	onlyDigits := true
	for _, c := range v {
		if c < '0' || c > '9' {
			onlyDigits = false
			break
		}
	}
	if onlyDigits {
		return true
	}
	return false
}

// readByteArrayField reads an instance field that references a byte[].
func readByteArrayField(idx *heap.Index, inst *heap.InstanceRef, path string) ([]byte, bool) {
	v, err := idx.ReadField(inst, path)
	if err != nil || v.IsNull() {
		return nil, false
	}
	b := idx.ReadByteArray(v.ObjectID)
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}
