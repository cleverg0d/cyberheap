package spiders

import (
	"fmt"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// redisSpider extracts Redis connection credentials from the three client
// libraries we see in enterprise Java: Spring Data Redis,
// Jedis (direct), and Lettuce (RedisURI).
//
// Each library models auth differently, so we use a small extraction table
// per target class rather than a one-size-fits-all Fields list.
type redisSpider struct{}

func (s *redisSpider) Name() string     { return "redis" }
func (s *redisSpider) Category() string { return "connection-string" }

func (s *redisSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	seen := map[uint64]bool{}

	emit := func(f *Finding) {
		if f == nil {
			return
		}
		if seen[f.ObjectID] {
			return
		}
		seen[f.ObjectID] = true
		out = append(out, *f)
	}

	// Spring Data Redis — configuration classes hold hostname/port/database
	// and a RedisPassword wrapper with the secret as a byte[].
	for _, root := range []string{
		"org.springframework.data.redis.connection.RedisStandaloneConfiguration",
		"org.springframework.data.redis.connection.RedisSentinelConfiguration",
		"org.springframework.data.redis.connection.RedisClusterConfiguration",
		"org.springframework.data.redis.connection.RedisSocketConfiguration",
	} {
		for _, cls := range idx.Subclasses(root) {
			for _, inst := range idx.Instances[cls.ID] {
				emit(extractSpringRedis(idx, inst, cls.Name))
			}
		}
	}

	// Jedis — direct client; JedisShardInfo carries host/port/password.
	for _, root := range []string{
		"redis.clients.jedis.JedisShardInfo",
		"redis.clients.jedis.Connection",
	} {
		for _, cls := range idx.Subclasses(root) {
			for _, inst := range idx.Instances[cls.ID] {
				emit(extractJedisShard(idx, inst, cls.Name))
			}
		}
	}

	// Lettuce — RedisURI embeds user, password (char[]), host, port.
	for _, cls := range idx.Subclasses("io.lettuce.core.RedisURI") {
		for _, inst := range idx.Instances[cls.ID] {
			emit(extractLettuceURI(idx, inst, cls.Name))
		}
	}

	return out
}

// --- helpers shared across extractors -------------------------------------

func addStringField(idx *heap.Index, inst *heap.InstanceRef, label, path string, fields *[]Field) {
	v, err := idx.ReadField(inst, path)
	if err != nil || v.IsNull() {
		return
	}
	s, ok := idx.ReadString(v.ObjectID)
	if !ok || s == "" {
		return
	}
	*fields = append(*fields, Field{Name: label, Value: s})
}

func addNumField(idx *heap.Index, inst *heap.InstanceRef, label, path string, fields *[]Field) {
	v, err := idx.ReadField(inst, path)
	if err != nil {
		return
	}
	switch v.Type {
	case hprof.PrimInt, hprof.PrimLong, hprof.PrimShort:
		if v.IntBits == 0 {
			return
		}
		*fields = append(*fields, Field{Name: label, Value: fmt.Sprintf("%d", v.IntBits)})
	}
}

// addBytePasswordField reads a byte[] password object ref and pushes it as a
// plain string field. Returns true if the value was non-empty.
func addBytePasswordField(idx *heap.Index, inst *heap.InstanceRef, label, path string, fields *[]Field) bool {
	v, err := idx.ReadField(inst, path)
	if err != nil || v.IsNull() {
		return false
	}
	b := idx.ReadByteArray(v.ObjectID)
	if len(b) == 0 {
		return false
	}
	*fields = append(*fields, Field{Name: label, Value: string(b)})
	return true
}

// addCharPasswordField reads a char[] password (Lettuce stores secrets this
// way to let callers zero them out) and renders it as a string.
func addCharPasswordField(idx *heap.Index, inst *heap.InstanceRef, label, path string, fields *[]Field) bool {
	v, err := idx.ReadField(inst, path)
	if err != nil || v.IsNull() {
		return false
	}
	arr, ok := idx.PrimArrays[v.ObjectID]
	if !ok || arr.ElementType != hprof.PrimChar {
		return false
	}
	// char[] elements are big-endian 16-bit; decode to UTF-16BE runes.
	s := decodeCharArray(arr.Elements)
	if s == "" {
		return false
	}
	*fields = append(*fields, Field{Name: label, Value: s})
	return true
}

func decodeCharArray(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	out := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		r := rune(b[i*2])<<8 | rune(b[i*2+1])
		out = append(out, r)
	}
	return string(out)
}

// --- per-library extractors -----------------------------------------------

func extractSpringRedis(idx *heap.Index, inst *heap.InstanceRef, clsName string) *Finding {
	var fields []Field
	addStringField(idx, inst, "hostName", "hostName", &fields)
	addStringField(idx, inst, "master", "master", &fields) // Sentinel-only
	addStringField(idx, inst, "username", "username", &fields)
	addNumField(idx, inst, "port", "port", &fields)
	addNumField(idx, inst, "database", "database", &fields)

	hasPassword := addBytePasswordField(idx, inst, "password", "password.thePassword", &fields)

	if !hasAnyConnEvidence(fields) {
		return nil
	}
	sev := SeverityMedium
	if hasPassword {
		sev = SeverityHigh
	}
	return &Finding{
		Spider:   "redis",
		Severity: sev,
		Category: "connection-string",
		Title:    "Spring Data Redis config",
		ClassFQN: clsName,
		ObjectID: inst.ID,
		Fields:   fields,
	}
}

func extractJedisShard(idx *heap.Index, inst *heap.InstanceRef, clsName string) *Finding {
	var fields []Field
	addStringField(idx, inst, "host", "host", &fields)
	addNumField(idx, inst, "port", "port", &fields)
	addStringField(idx, inst, "user", "user", &fields)
	addStringField(idx, inst, "clientName", "clientName", &fields)
	addNumField(idx, inst, "db", "db", &fields)
	hasPassword := false
	// Jedis stores the password as plain java.lang.String.
	if v, err := idx.ReadField(inst, "password"); err == nil && !v.IsNull() {
		if s, ok := idx.ReadString(v.ObjectID); ok && s != "" {
			fields = append(fields, Field{Name: "password", Value: s})
			hasPassword = true
		}
	}
	if !hasAnyConnEvidence(fields) {
		return nil
	}
	sev := SeverityMedium
	if hasPassword {
		sev = SeverityHigh
	}
	return &Finding{
		Spider:   "redis",
		Severity: sev,
		Category: "connection-string",
		Title:    "Jedis shard info",
		ClassFQN: clsName,
		ObjectID: inst.ID,
		Fields:   fields,
	}
}

func extractLettuceURI(idx *heap.Index, inst *heap.InstanceRef, clsName string) *Finding {
	var fields []Field
	addStringField(idx, inst, "host", "host", &fields)
	addStringField(idx, inst, "username", "username", &fields)
	addStringField(idx, inst, "clientName", "clientName", &fields)
	addStringField(idx, inst, "socket", "socket", &fields)
	addNumField(idx, inst, "port", "port", &fields)
	addNumField(idx, inst, "database", "database", &fields)

	hasPassword := addCharPasswordField(idx, inst, "password", "password", &fields)

	if !hasAnyConnEvidence(fields) {
		return nil
	}
	sev := SeverityMedium
	if hasPassword {
		sev = SeverityHigh
	}
	return &Finding{
		Spider:   "redis",
		Severity: sev,
		Category: "connection-string",
		Title:    "Lettuce RedisURI",
		ClassFQN: clsName,
		ObjectID: inst.ID,
		Fields:   fields,
	}
}

// hasAnyConnEvidence: at least one of host/port/password/user must be
// non-empty. `clientName` is deliberately excluded — it's an internal
// Spring/Jedis identifier set by framework code, not a credential, so
// a finding that contains only clientName would be noise.
func hasAnyConnEvidence(fs []Field) bool {
	for _, f := range fs {
		switch f.Name {
		case "host", "hostName", "port", "master", "socket", "password", "username", "user":
			if f.Value != "" {
				return true
			}
		}
	}
	return false
}
