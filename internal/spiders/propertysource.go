package spiders

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// urlEmbeddedAuthRe matches URLs that carry credentials in the authority
// (scheme://user:pass@host). Used to promote any property value with
// embedded auth into a secret-prefix seed, regardless of its key name —
// catches Eureka `eureka.client.serviceUrl.defaultZone=http://u:p@host/`
// and similar Spring Cloud discovery configs.
var urlEmbeddedAuthRe = regexp.MustCompile(`\b[a-z][a-z0-9+\-.]*://[^\s:/@"']{1,100}:[^\s@"']{1,200}@`)

// propertySourceSpider harvests credentials from Spring's PropertySource
// objects. Spring Boot loads application.properties / application.yml into
// MapPropertySource instances keyed off arbitrary names. Every instance
// holds a Map<String, Object> called "source" — our HashMap walker unpacks
// it and we pull keys whose name hints at a secret (password, secret, key,
// token, credential).
//
// This catches leaks the regex pass misses: in the on-disk form a line
// looks like "spring.mail.password=xxx", but in heap the key and value are
// stored as separate String objects inside a HashMap.Node, with plenty of
// unrelated bytes in between.
type propertySourceSpider struct{}

func (s *propertySourceSpider) Name() string     { return "propertysource" }
func (s *propertySourceSpider) Category() string { return "credentials" }

// Target classes. Spring Boot uses subclasses of MapPropertySource for:
//
//   - application.properties / application.yml
//   - system environment variables (SystemEnvironmentPropertySource)
//   - @ConfigurationProperties-bound beans
//   - random values, JNDI, servlet context params, ...
//
// We match the root class and every subclass, so custom ConfigMap-like
// sources are included automatically.
var psRoots = []string{
	"org.springframework.core.env.MapPropertySource",
	"org.springframework.boot.env.OriginTrackedMapPropertySource",
	"org.springframework.core.env.PropertiesPropertySource",
	"org.springframework.core.env.SystemEnvironmentPropertySource",
}

// secretKeyHints triggers extraction when any substring matches (lowercase).
// Curated to avoid the common false-positive patterns:
//   - "pwd" alone matches "PWD" (working directory) and is dropped
//   - "auth" alone matches "persistAuthorization", "authMode", etc.
//   - "key" alone matches "KeyStore", "keyboard", hashes
//
// We keep only composites that unambiguously mean "carries a secret".
var secretKeyHints = []string{
	"password", "passphrase", "passwd",
	"secret",
	"apikey", "api-key", "api_key", "api.key",
	"accesskey", "access-key", "access_key", "access.key",
	"privatekey", "private-key", "private_key", "private.key",
	"signingkey", "signing-key", "signing_key", "signing.key",
	"clientsecret", "client-secret", "client_secret", "client.secret",
	"encryption", "cipher",
	"token", "credential",
	"jwt.secret", "jwt.key", "jwt.signing",
}

func (s *propertySourceSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	seen := map[uint64]bool{}

	for _, root := range psRoots {
		for _, cls := range idx.Subclasses(root) {
			for _, inst := range idx.Instances[cls.ID] {
				if seen[inst.ID] {
					continue
				}
				seen[inst.ID] = true

				// The map lives under the "source" field on every Spring
				// PropertySource we care about.
				sourceRef, err := idx.ReadField(inst, "source")
				if err != nil || sourceRef.IsNull() {
					continue
				}
				mapInst, ok := idx.InstancesByID[sourceRef.ObjectID]
				if !ok {
					continue
				}

				// Read the optional property source name for attribution.
				srcName := ""
				if nameRef, err := idx.ReadField(inst, "name"); err == nil && !nameRef.IsNull() {
					if n, ok := idx.ReadString(nameRef.ObjectID); ok {
						srcName = n
					}
				}

				// Group keys by dotted prefix: a prefix is "secret" if any
				// of its keys match secretKeyHints. Emit the secret key plus
				// companion keys (login/url/clientId/scope) under the same
				// prefix so the OAuth block travels together.
				type kvPair struct{ k, v string }
				var pairs []kvPair
				walkMapLike(idx, mapInst, func(k, v heap.Value) bool {
					key, ok := idx.ReadString(k.ObjectID)
					if !ok {
						return true
					}
					val := readPropertyValue(idx, v)
					if val == "" {
						return true
					}
					pairs = append(pairs, kvPair{key, val})
					return true
				})

				secretPrefixes := map[string]bool{}
				for _, p := range pairs {
					if looksSecretKey(p.k) || urlEmbeddedAuthRe.MatchString(p.v) {
						secretPrefixes[propertyPrefix(p.k)] = true
					}
				}
				if len(secretPrefixes) == 0 {
					continue
				}

				var fields []Field
				for _, p := range pairs {
					if !secretPrefixes[propertyPrefix(p.k)] {
						continue
					}
					if !looksSecretKey(p.k) &&
						!looksCompanionKey(p.k) &&
						!urlEmbeddedAuthRe.MatchString(p.v) {
						continue
					}
					fields = append(fields, Field{Name: p.k, Value: p.v})
				}
				if len(fields) == 0 {
					continue
				}
				// Alphabetical sort keeps same-prefix keys contiguous.
				sort.SliceStable(fields, func(i, j int) bool {
					return fields[i].Name < fields[j].Name
				})
				title := "Spring PropertySource"
				if srcName != "" {
					title = "Spring PropertySource: " + srcName
				}
				out = append(out, Finding{
					Spider:   "propertysource",
					Severity: SeverityHigh,
					Category: "credentials",
					Title:    title,
					ClassFQN: cls.Name,
					ObjectID: inst.ID,
					Fields:   fields,
				})
			}
		}
	}
	return out
}

// walkMapLike abstracts over the several Map shapes Spring stores
// properties in:
//   - HashMap / LinkedHashMap / Hashtable / Properties : table[] + Node.next
//   - java.util.Collections$SingletonMap : single "k" / "v" pair
//   - java.util.Collections$UnmodifiableMap : wraps another map in "m"
func walkMapLike(idx *heap.Index, inst *heap.InstanceRef, visit func(k, v heap.Value) bool) {
	if inst == nil {
		return
	}
	cls, ok := idx.Classes[inst.ClassID]
	if !ok {
		return
	}
	switch cls.Name {
	case "java.util.Collections$SingletonMap":
		k, kerr := idx.ReadField(inst, "k")
		v, verr := idx.ReadField(inst, "v")
		if kerr == nil && verr == nil {
			visit(k, v)
		}
		return
	case "java.util.Collections$UnmodifiableMap",
		"java.util.Collections$SynchronizedMap",
		"java.util.Collections$CheckedMap":
		inner, err := idx.ReadField(inst, "m")
		if err == nil && !inner.IsNull() {
			if next, ok := idx.InstancesByID[inner.ObjectID]; ok {
				walkMapLike(idx, next, visit)
			}
		}
		return
	}
	idx.WalkHashMap(inst, visit)
}

// looksSecretKey checks whether a property key name suggests sensitive data.
// Case-insensitive substring match against secretKeyHints.
func looksSecretKey(k string) bool {
	if k == "" {
		return false
	}
	lk := strings.ToLower(k)
	for _, h := range secretKeyHints {
		if strings.Contains(lk, h) {
			return true
		}
	}
	return false
}

// propertyPrefix returns the dotted prefix of a Spring property key
// (everything before the last '.'). Used for grouping related entries.
func propertyPrefix(k string) string {
	if i := strings.LastIndexByte(k, '.'); i > 0 {
		return k[:i]
	}
	return ""
}

// companionKeySuffixes match the final dotted segment (lowercased,
// hyphens/underscores stripped). Kept tight to avoid noise like
// ".subject" / ".enabled" / ".format".
var companionKeySuffixes = []string{
	"username", "user", "userid", "login", "email", "account", "principal",
	"clientid", "clientname",
	"host", "hostname", "server", "endpoint", "address",
	"url", "uri", "baseurl", "endpointurl",
	"scope", "realm", "issuer", "audience", "granttype", "grantflow",
	"database", "schema", "dbname",
	// Spring Cloud discovery / service-registry surface: expose sibling
	// keys when ANY entry in the prefix carries embedded auth.
	"defaultzone", "serviceurl", "servicepath",
	"fetchregistry", "registerwitheureka",
}

// looksCompanionKey gates inclusion of non-secret keys under a secret prefix.
func looksCompanionKey(k string) bool {
	leaf := k
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		leaf = k[i+1:]
	}
	normalized := strings.ToLower(leaf)
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	for _, s := range companionKeySuffixes {
		if strings.Contains(normalized, s) {
			return true
		}
	}
	return false
}

// readPropertyValue handles the three ways Spring stores property values
// inside a PropertySource map:
//   - plain java.lang.String
//   - OriginTrackedValue (spring-boot wrapper carrying source-location
//     metadata; the real value is under the "value" field)
//   - primitive wrappers (Integer, Long, Boolean) — stringified trivially
func readPropertyValue(idx *heap.Index, v heap.Value) string {
	if v.IsNull() {
		return ""
	}
	if v.Type.String() != "object" {
		return ""
	}
	// Try plain String first.
	if s, ok := idx.ReadString(v.ObjectID); ok {
		return s
	}
	// OriginTrackedValue.value
	if inst, ok := idx.InstancesByID[v.ObjectID]; ok {
		inner, err := idx.ReadField(inst, "value")
		if err == nil && !inner.IsNull() {
			if s, ok := idx.ReadString(inner.ObjectID); ok {
				return s
			}
		}
	}
	return ""
}
