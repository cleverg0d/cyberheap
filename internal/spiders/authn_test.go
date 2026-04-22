package spiders

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// stringAlloc issues sequential StringInUTF8 IDs the way a real JVM does.
// Centralised here so every test uses the same ID-generation pattern.
type stringAlloc struct{ next uint64 }

func (s *stringAlloc) add(b *hprof.Builder, text string) uint64 {
	s.next++
	id := s.next
	b.AddString(id, text)
	return id
}

// buildString installs a java.lang.String class (if not already) and emits
// an instance pointing at a JDK9+ byte[] + LATIN1 coder = 0 value.
// Returns the String object ID. Callers that need many strings share one
// stringClass/coder/value layout by calling ensureStringClass first.
type stringMint struct {
	b            *hprof.Builder
	ids          *stringAlloc
	stringClass  uint64
	nextInstID   uint64
	nextBytesID  uint64
	stringsReady bool
}

func newStringMint(b *hprof.Builder, ids *stringAlloc) *stringMint {
	return &stringMint{b: b, ids: ids, nextInstID: 0x30000, nextBytesID: 0x40000}
}

func (m *stringMint) ensureClass() {
	if m.stringsReady {
		return
	}
	nameID := m.ids.add(m.b, "java/lang/String")
	valueField := m.ids.add(m.b, "value")
	coderField := m.ids.add(m.b, "coder")
	m.stringClass = 0x1F00
	m.b.AddLoadClass(0xF0, m.stringClass, nameID)
	m.b.AddClassDump(m.stringClass, 0, 9, []hprof.FieldDecl{
		{NameID: valueField, Type: hprof.PrimObject},
		{NameID: coderField, Type: hprof.PrimByte},
	})
	m.stringsReady = true
}

func (m *stringMint) mint(text string) uint64 {
	m.ensureClass()
	m.nextInstID++
	m.nextBytesID++
	strID := m.nextInstID
	bytesID := m.nextBytesID
	m.b.AddPrimitiveArray(bytesID, hprof.PrimByte, []byte(text))
	m.b.AddInstanceDump(strID, m.stringClass, m.b.PackBytes(m.b.PackID(bytesID), m.b.PackByte(0)))
	return strID
}

// TestAuthnSpider_CustomController is the motivating case: a plain
// user-app bean with password + clientSecret + username fields. Covers
// the BCCController / TradeControlService shape Bagrad flagged —
// JDumpSpider's UserPassSearcher catches it, we didn't before this spider.
func TestAuthnSpider_CustomController(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringAlloc{}
	mint := newStringMint(b, ids)

	passStr := mint.mint("hunter2")
	userStr := mint.mint("alice@example.com")
	hostStr := mint.mint("10.0.0.5")
	clientSecretStr := mint.mint("CS-deadbeef")

	controllerName := ids.add(b, "com/acme/app/BCCController")
	passField := ids.add(b, "password")
	userField := ids.add(b, "username")
	hostField := ids.add(b, "host")
	clientField := ids.add(b, "clientSecret")

	const controllerClass uint64 = 0x1100
	const controllerInst uint64 = 0x2100

	b.AddLoadClass(1, controllerClass, controllerName)
	b.AddClassDump(controllerClass, 0, 32, []hprof.FieldDecl{
		{NameID: passField, Type: hprof.PrimObject},
		{NameID: userField, Type: hprof.PrimObject},
		{NameID: hostField, Type: hprof.PrimObject},
		{NameID: clientField, Type: hprof.PrimObject},
	})
	b.AddInstanceDump(controllerInst, controllerClass, b.PackBytes(
		b.PackID(passStr),
		b.PackID(userStr),
		b.PackID(hostStr),
		b.PackID(clientSecretStr),
	))

	idx, err := heap.Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	s := &authnSpider{}
	findings := s.Sniff(idx)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, SeverityHigh, f.Severity)
	assert.Equal(t, "com.acme.app.BCCController", f.ClassFQN)
	assert.Equal(t, "App credentials: BCCController", f.Title)

	got := map[string]string{}
	for _, kv := range f.Fields {
		got[kv.Name] = kv.Value
	}
	assert.Equal(t, "hunter2", got["password"])
	assert.Equal(t, "CS-deadbeef", got["clientSecret"])
	assert.Equal(t, "alice@example.com", got["username"])
	assert.Equal(t, "10.0.0.5", got["host"])

	// Fields must be alphabetically sorted — Bagrad's display requirement.
	names := make([]string, len(f.Fields))
	for i, kv := range f.Fields {
		names[i] = kv.Name
	}
	assert.Equal(t, []string{"clientSecret", "host", "password", "username"}, names)
}

// TestAuthnSpider_SkipFrameworkNamespace verifies that classes in
// namespaces owned by dedicated spiders (or JDK internals) are ignored
// even when their fields look credential-shaped. Without this filter
// we'd double-emit for HikariDataSource, Hibernate internals, etc.
func TestAuthnSpider_SkipFrameworkNamespace(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringAlloc{}
	mint := newStringMint(b, ids)

	passStr := mint.mint("neverReported")

	hibernateName := ids.add(b, "org/hibernate/FakeCredProvider")
	passField := ids.add(b, "password")

	const hibernateClass uint64 = 0x1200
	const hibernateInst uint64 = 0x2200

	b.AddLoadClass(1, hibernateClass, hibernateName)
	b.AddClassDump(hibernateClass, 0, 8, []hprof.FieldDecl{
		{NameID: passField, Type: hprof.PrimObject},
	})
	b.AddInstanceDump(hibernateInst, hibernateClass, b.PackID(passStr))

	idx, err := heap.Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	findings := (&authnSpider{}).Sniff(idx)
	assert.Empty(t, findings, "org.hibernate.* must be skipped by prefix filter")
}

// TestAuthnSpider_NoPasswordFieldIgnored guards the central rule: without
// at least one non-empty password-shaped field, a hostname-only or
// username-only class is not enough to fire a Critical finding. Prevents
// SQLServerConnection-style noise that UserPassSearcher emits freely.
func TestAuthnSpider_NoPasswordFieldIgnored(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringAlloc{}
	mint := newStringMint(b, ids)

	userStr := mint.mint("ops")
	hostStr := mint.mint("svc.internal")

	className := ids.add(b, "com/acme/app/ReadOnlyService")
	userField := ids.add(b, "username")
	hostField := ids.add(b, "host")

	const cls uint64 = 0x1300
	const inst uint64 = 0x2300

	b.AddLoadClass(1, cls, className)
	b.AddClassDump(cls, 0, 16, []hprof.FieldDecl{
		{NameID: userField, Type: hprof.PrimObject},
		{NameID: hostField, Type: hprof.PrimObject},
	})
	b.AddInstanceDump(inst, cls, b.PackBytes(b.PackID(userStr), b.PackID(hostStr)))

	idx, err := heap.Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	findings := (&authnSpider{}).Sniff(idx)
	assert.Empty(t, findings, "class without password-shaped field must not fire")
}

// TestAuthnSpider_CGLIBProxyDisplayName verifies the proxy-suffix strip:
// the heap class is MailConfig$$EnhancerBySpringCGLIB$$abc123 but
// developers care about MailConfig, so that's what we render.
func TestAuthnSpider_CGLIBProxyDisplayName(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringAlloc{}
	mint := newStringMint(b, ids)

	passStr := mint.mint("smtp-secret")
	userStr := mint.mint("mailer@example.com")

	proxyName := ids.add(b, "kz/acme/MailConfig$$EnhancerBySpringCGLIB$$abc123")
	passField := ids.add(b, "password")
	userField := ids.add(b, "username")

	const cls uint64 = 0x1400
	const inst uint64 = 0x2400

	b.AddLoadClass(1, cls, proxyName)
	b.AddClassDump(cls, 0, 16, []hprof.FieldDecl{
		{NameID: passField, Type: hprof.PrimObject},
		{NameID: userField, Type: hprof.PrimObject},
	})
	b.AddInstanceDump(inst, cls, b.PackBytes(b.PackID(passStr), b.PackID(userStr)))

	idx, err := heap.Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	findings := (&authnSpider{}).Sniff(idx)
	require.Len(t, findings, 1)
	assert.Equal(t, "kz.acme.MailConfig", findings[0].ClassFQN)
	assert.Equal(t, "App credentials: MailConfig", findings[0].Title)
}
