package spiders

import (
	"sort"
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// authnSpider heuristically flags any user class whose fields match
// password/identity/host hints. Rules: at least one non-empty password-
// shaped field, and class FQN not already owned by another spider.
type authnSpider struct{}

func (s *authnSpider) Name() string     { return "authn" }
func (s *authnSpider) Category() string { return "credentials" }

// authnSkipPrefixes: JDK internals, other spiders' domains, and noisy
// framework packages with no app secrets.
var authnSkipPrefixes = []string{
	// JDK / stdlib
	"java.", "javax.", "jakarta.", "sun.", "com.sun.", "jdk.", "com.oracle.",
	"kotlin.", "scala.", "groovy.",

	// Covered by dedicated spiders
	"org.springframework.boot.autoconfigure.jdbc.",
	"org.springframework.core.env.",
	"org.springframework.boot.env.",
	"org.springframework.data.redis.",
	"com.zaxxer.hikari.",
	"com.alibaba.druid.",
	"com.mongodb.",
	"org.apache.commons.dbcp2.",
	"org.apache.tomcat.jdbc.",
	"weblogic.jdbc.",
	"org.apache.shiro.",
	"redis.clients.jedis.",
	"io.lettuce.",
	"org.jasypt.",
	"com.ulisesbocchio.jasyptspringboot.",
	"com.amazonaws.",
	"software.amazon.awssdk.",
	"com.aliyun.",
	"com.aliyuncs.",
	"com.obs.services.",
	"com.qcloud.cos.",

	// Framework internals — carry connection metadata, rarely app creds
	"org.hibernate.",
	"com.microsoft.sqlserver.",
	"com.mysql.",
	"org.postgresql.",
	"oracle.jdbc.",
	"org.apache.catalina.",
	"org.apache.tomcat.",
	"org.apache.coyote.",
	"org.apache.logging.",
	"ch.qos.logback.",
	"org.slf4j.",
	"com.fasterxml.jackson.",
	"org.springframework.core.",
	"org.springframework.beans.",
	"org.springframework.context.",
	"org.springframework.aop.",
	"org.springframework.web.",
	"org.springframework.security.crypto.",
	"org.springframework.security.web.",
	"org.springframework.security.authentication.",
	"org.springframework.boot.context.",
	"org.springframework.boot.devtools.",
	"org.springframework.boot.logging.",
	"org.springframework.boot.actuate.",
	"org.springframework.cloud.",
	"org.apache.http.",
	"org.eclipse.jetty.",
	"io.netty.",
	"org.jboss.",
	"net.bytebuddy.",
	"com.github.benmanes.caffeine.",
}

// proxySeparators mark runtime proxy FQNs; trimmed for display.
var proxySeparators = []string{
	"$$EnhancerBySpringCGLIB$$",
	"$$EnhancerByCGLIB$$",
	"$$FastClassBySpringCGLIB$$",
	"$$FastClassByCGLIB$$",
	"$HibernateProxy$",
	"$$Lambda$",
}

// passwordHints: lowercased substring match. Bare "key"/"pwd" excluded
// to avoid keyStore / HashMap.keys / env PWD false positives.
var passwordHints = []string{
	"password", "passwd", "passphrase",
	"secret",
	"apikey", "api_key", "apitoken", "api_token",
	"accesskey", "access_key",
	"privatekey", "private_key",
	"clientsecret", "client_secret",
	"encryptionkey", "signingkey", "signing_key",
	"token", "credential",
}

// identityHints — fields shown next to a password match.
var identityHints = []string{
	"username", "userlogin", "user_login", "login",
	"email", "account", "principal",
	"clientid", "client_id",
	"user",
}

// hostHints — network context shown next to a password match.
var hostHints = []string{
	"host", "hostname", "server", "endpoint",
	"url", "uri", "baseurl", "base_url",
	"connectionstring", "connection_string",
}

// trivialStringValues are filler values suppressed from output: booleans,
// loopback, charsets, and the param-name-as-value pattern.
var trivialStringValues = map[string]bool{
	"true": true, "false": true, "null": true, "none": true,
	"0": true, "1": true, "-1": true,
	"localhost": true, "127.0.0.1": true, "0.0.0.0": true,
	"password": true, "username": true, "email": true,
	"token": true, "secret": true, "credential": true, "credentials": true,
	"utf-8": true, "utf-16": true, "iso-8859-1": true,
	"ascii": true, "us-ascii": true, "windows-1251": true,
}

// demoteSuffixes neutralise meta fields (param names, charsets, attrs)
// whose substring matches a hint but whose value isn't a secret.
var demoteSuffixes = []string{
	"parameter", "param", "paramname",
	"attr", "attribute", "attributename",
	"charset", "encoding",
	"header", "prefix", "suffix",
}

type fieldKind int

const (
	kindOther fieldKind = iota
	kindPassword
	kindIdentity
	kindHost
)

// classifyField maps a field name to password/identity/host/other.
func classifyField(name string) fieldKind {
	n := strings.ToLower(name)
	for _, suf := range demoteSuffixes {
		if strings.HasSuffix(n, suf) {
			return kindOther
		}
	}
	for _, h := range passwordHints {
		if strings.Contains(n, h) {
			return kindPassword
		}
	}
	for _, h := range identityHints {
		if strings.Contains(n, h) {
			return kindIdentity
		}
	}
	for _, h := range hostHints {
		if strings.Contains(n, h) {
			return kindHost
		}
	}
	return kindOther
}

// authnFieldSet groups object-type field names by kind. Collected once per
// class and reused across every instance of that class.
type authnFieldSet struct {
	password []string
	identity []string
	host     []string
}

func (s *authnSpider) Sniff(idx *heap.Index) []Finding {
	var out []Finding
	seen := map[uint64]bool{}

	for classID, instances := range idx.Instances {
		cd, ok := idx.Classes[classID]
		if !ok || cd.Name == "" {
			continue
		}
		if skipClassByFQN(cd.Name) {
			continue
		}
		set := collectAuthnFields(idx, cd)
		if len(set.password) == 0 {
			continue
		}
		for _, inst := range instances {
			if seen[inst.ID] {
				continue
			}
			f := extractAuthn(idx, inst, cd, set)
			if f == nil {
				continue
			}
			seen[inst.ID] = true
			out = append(out, *f)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].ObjectID < out[j].ObjectID
	})
	return out
}

// collectAuthnFields walks the class chain (including supers so
// inherited cred fields aren't missed).
func collectAuthnFields(idx *heap.Index, leaf *heap.ClassDef) authnFieldSet {
	var set authnFieldSet
	seenName := map[string]bool{}
	cls := leaf
	for cls != nil {
		for _, f := range cls.InstanceFields {
			if f.Type != hprof.PrimObject {
				continue
			}
			if seenName[f.Name] {
				continue
			}
			seenName[f.Name] = true
			switch classifyField(f.Name) {
			case kindPassword:
				set.password = append(set.password, f.Name)
			case kindIdentity:
				set.identity = append(set.identity, f.Name)
			case kindHost:
				set.host = append(set.host, f.Name)
			}
		}
		if cls.SuperID == 0 {
			break
		}
		cls = idx.Classes[cls.SuperID]
	}
	return set
}

// extractAuthn returns nil when no password-shaped field resolves to a usable value.
func extractAuthn(idx *heap.Index, inst *heap.InstanceRef, cls *heap.ClassDef, set authnFieldSet) *Finding {
	all := make([]string, 0, len(set.password)+len(set.identity)+len(set.host))
	all = append(all, set.password...)
	all = append(all, set.identity...)
	all = append(all, set.host...)

	fields := make([]Field, 0, len(all))
	passwordVisible := false

	for _, name := range all {
		v, err := idx.ReadField(inst, name)
		if err != nil || v.IsNull() {
			continue
		}
		raw, ok := idx.ReadString(v.ObjectID)
		if !ok {
			continue
		}
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}
		if trivialStringValues[strings.ToLower(val)] {
			continue
		}
		if classifyField(name) == kindPassword {
			if looksLikeSQL(val) {
				continue
			}
			passwordVisible = true
		}
		fields = append(fields, Field{Name: name, Value: val})
	}

	if !passwordVisible {
		return nil
	}

	sort.SliceStable(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})

	display := displayClassName(cls.Name)
	return &Finding{
		Spider:   "authn",
		Severity: SeverityHigh,
		Category: "credentials",
		Title:    "App credentials: " + shortClassName(display),
		ClassFQN: display,
		ObjectID: inst.ID,
		Fields:   fields,
	}
}

// skipClassByFQN filters JDK internals, array descriptors, and other
// spiders' domains.
func skipClassByFQN(fqn string) bool {
	if fqn == "" || strings.HasPrefix(fqn, "[") {
		return true
	}
	for _, p := range authnSkipPrefixes {
		if strings.HasPrefix(fqn, p) {
			return true
		}
	}
	return false
}

// displayClassName trims runtime-proxy suffixes.
func displayClassName(fqn string) string {
	for _, sep := range proxySeparators {
		if i := strings.Index(fqn, sep); i > 0 {
			return fqn[:i]
		}
	}
	return fqn
}

func shortClassName(fqn string) string {
	if i := strings.LastIndex(fqn, "."); i >= 0 {
		return fqn[i+1:]
	}
	return fqn
}
