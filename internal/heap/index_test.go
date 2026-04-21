package heap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// stringIDs is a small helper to keep ID generation tidy in tests.
type stringIDs struct{ next uint64 }

func (s *stringIDs) add(b *hprof.Builder, text string) uint64 {
	s.next++
	id := s.next
	b.AddString(id, text)
	return id
}

// TestBuild_BasicClass verifies the happy path: a single class with two
// instance fields, one instance on the heap, all strings reachable.
// This exercises the "leaf-to-root" INSTANCE_DUMP layout (which the
// production fix corrected from root-to-leaf).
func TestBuild_BasicClass(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	classNameID := ids.add(b, "com/example/User")
	ageID := ids.add(b, "age")
	refID := ids.add(b, "partner") // object ref field

	const userClassID uint64 = 0x1000
	const userInst uint64 = 0x2000
	const partnerInst uint64 = 0x3000

	b.AddLoadClass(1, userClassID, classNameID)
	b.AddClassDump(userClassID, 0, 12, []hprof.FieldDecl{
		{NameID: ageID, Type: hprof.PrimInt},
		{NameID: refID, Type: hprof.PrimObject},
	})

	// User instance: age=42, partner=partnerInst.
	values := b.PackBytes(b.PackInt32(42), b.PackID(partnerInst))
	b.AddInstanceDump(userInst, userClassID, values)

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	// Class name normalized from "com/example/User" to "com.example.User".
	cls, ok := idx.ClassByName["com.example.User"]
	require.True(t, ok)
	assert.Equal(t, userClassID, cls.ID)
	assert.Len(t, idx.Instances[userClassID], 1)

	inst := idx.InstancesByID[userInst]
	require.NotNil(t, inst)

	// Read the primitive field by name.
	v, err := idx.ReadField(inst, "age")
	require.NoError(t, err)
	assert.Equal(t, hprof.PrimInt, v.Type)
	assert.EqualValues(t, 42, v.IntBits)

	// Read the object ref field.
	v, err = idx.ReadField(inst, "partner")
	require.NoError(t, err)
	assert.Equal(t, hprof.PrimObject, v.Type)
	assert.Equal(t, partnerInst, v.ObjectID)
}

// TestReadField_DottedPath walks an object reference chain. This is the
// same path spiders use when reading "cipherService.algorithmName".
func TestReadField_DottedPath(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	childClassName := ids.add(b, "com/example/Child")
	parentClassName := ids.add(b, "com/example/Parent")
	nameField := ids.add(b, "name")
	childField := ids.add(b, "child")
	valueField := ids.add(b, "value")

	const childClass uint64 = 0x1001
	const parentClass uint64 = 0x1002
	const child uint64 = 0x2001
	const parent uint64 = 0x2002
	const nameStr uint64 = 0x3001 // java.lang.String instance we won't build fully

	b.AddLoadClass(1, childClass, childClassName)
	b.AddLoadClass(2, parentClass, parentClassName)

	// Child has a "name" object ref.
	b.AddClassDump(childClass, 0, 8, []hprof.FieldDecl{
		{NameID: nameField, Type: hprof.PrimObject},
	})
	// Parent has a "child" object ref AND a "value" int.
	b.AddClassDump(parentClass, 0, 12, []hprof.FieldDecl{
		{NameID: childField, Type: hprof.PrimObject},
		{NameID: valueField, Type: hprof.PrimInt},
	})

	b.AddInstanceDump(child, childClass, b.PackID(nameStr))
	b.AddInstanceDump(parent, parentClass, b.PackBytes(
		b.PackID(child),
		b.PackInt32(77),
	))

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	parentInst := idx.InstancesByID[parent]
	require.NotNil(t, parentInst)

	// Direct field
	v, err := idx.ReadField(parentInst, "value")
	require.NoError(t, err)
	assert.EqualValues(t, 77, v.IntBits)

	// Dotted path: parent → child → name
	v, err = idx.ReadField(parentInst, "child.name")
	require.NoError(t, err)
	assert.Equal(t, nameStr, v.ObjectID)
}

// TestReadField_SuperClassFields verifies the class chain walk when a
// field is declared on a superclass, not on the runtime class. This
// is the exact case that was broken by the root-first bug before the
// leaf-first fix.
func TestReadField_SuperClassFields(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	animalName := ids.add(b, "com/example/Animal")
	dogName := ids.add(b, "com/example/Dog")
	legsField := ids.add(b, "legs")   // defined on Animal
	breedField := ids.add(b, "breed") // defined on Dog

	const animalClass uint64 = 0x1010
	const dogClass uint64 = 0x1011
	const dog uint64 = 0x2010
	const breedStr uint64 = 0x3010

	b.AddLoadClass(1, animalClass, animalName)
	b.AddLoadClass(2, dogClass, dogName)

	b.AddClassDump(animalClass, 0, 4, []hprof.FieldDecl{
		{NameID: legsField, Type: hprof.PrimInt},
	})
	// Dog extends Animal.
	b.AddClassDump(dogClass, animalClass, 12, []hprof.FieldDecl{
		{NameID: breedField, Type: hprof.PrimObject},
	})

	// HPROF packs leaf-first: Dog fields (breed, 8 bytes) then Animal
	// fields (legs, 4 bytes).
	values := b.PackBytes(
		b.PackID(breedStr),
		b.PackInt32(4),
	)
	b.AddInstanceDump(dog, dogClass, values)

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	inst := idx.InstancesByID[dog]
	require.NotNil(t, inst)

	// Reach into the super-class field from a subclass instance.
	v, err := idx.ReadField(inst, "legs")
	require.NoError(t, err)
	assert.EqualValues(t, 4, v.IntBits)

	v, err = idx.ReadField(inst, "breed")
	require.NoError(t, err)
	assert.Equal(t, breedStr, v.ObjectID)
}

// TestReadString_JDK9_ByteArrayLATIN1 checks the JDK 9+ String
// representation: byte[] value + byte coder (0 = LATIN1).
func TestReadString_JDK9_ByteArrayLATIN1(t *testing.T) {
	idx, strObj := buildStringDumpJDK9(t, "hello", 0)
	got, ok := idx.ReadString(strObj)
	require.True(t, ok)
	assert.Equal(t, "hello", got)
}

// TestReadString_JDK9_ByteArrayUTF16 checks the coder=1 path (UTF-16LE).
func TestReadString_JDK9_ByteArrayUTF16(t *testing.T) {
	// UTF-16LE encoding of "Héllo" — verifies decodeUTF16LE.
	idx, strObj := buildStringDumpJDK9UTF16(t, "Héllo")
	got, ok := idx.ReadString(strObj)
	require.True(t, ok)
	assert.Equal(t, "Héllo", got)
}

// TestReadString_JDK8_CharArray checks the JDK 8 representation:
// java.lang.String with a char[] value and no coder field.
func TestReadString_JDK8_CharArray(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	stringName := ids.add(b, "java/lang/String")
	valueField := ids.add(b, "value")

	const stringClass uint64 = 0x1100
	const stringInst uint64 = 0x2100
	const charArray uint64 = 0x2101

	b.AddLoadClass(1, stringClass, stringName)
	b.AddClassDump(stringClass, 0, 8, []hprof.FieldDecl{
		{NameID: valueField, Type: hprof.PrimObject},
	})
	b.AddInstanceDump(stringInst, stringClass, b.PackID(charArray))
	b.AddPrimitiveArray(charArray, hprof.PrimChar, b.CharArrayBytes("world"))

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	got, ok := idx.ReadString(stringInst)
	require.True(t, ok)
	assert.Equal(t, "world", got)
}

// TestWalkHashMap walks a small HashMap laid out as HotSpot writes it:
// table[] object array with Node instances holding {key, value, next}.
func TestWalkHashMap(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	hmName := ids.add(b, "java/util/HashMap")
	nodeName := ids.add(b, "java/util/HashMap$Node")
	tableField := ids.add(b, "table")
	keyField := ids.add(b, "key")
	valField := ids.add(b, "value")
	nextField := ids.add(b, "next")

	const hmClass uint64 = 0x1200
	const nodeClass uint64 = 0x1201
	const hmInst uint64 = 0x2200
	const tableArr uint64 = 0x2201
	const node1 uint64 = 0x2202
	const node2 uint64 = 0x2203
	// Pretend "keys" and "values" are simple object IDs; we don't resolve
	// them to actual Strings in this test — we just verify the walker
	// returns them.
	const k1 uint64 = 0x3000
	const v1 uint64 = 0x3001
	const k2 uint64 = 0x3002
	const v2 uint64 = 0x3003

	b.AddLoadClass(1, hmClass, hmName)
	b.AddLoadClass(2, nodeClass, nodeName)

	b.AddClassDump(hmClass, 0, 8, []hprof.FieldDecl{
		{NameID: tableField, Type: hprof.PrimObject},
	})
	b.AddClassDump(nodeClass, 0, 24, []hprof.FieldDecl{
		{NameID: keyField, Type: hprof.PrimObject},
		{NameID: valField, Type: hprof.PrimObject},
		{NameID: nextField, Type: hprof.PrimObject},
	})

	// HashMap instance: table → object array of two Nodes.
	b.AddInstanceDump(hmInst, hmClass, b.PackID(tableArr))

	// Two nodes in the same bucket — node1 → node2 via "next".
	b.AddInstanceDump(node1, nodeClass, b.PackBytes(b.PackID(k1), b.PackID(v1), b.PackID(node2)))
	b.AddInstanceDump(node2, nodeClass, b.PackBytes(b.PackID(k2), b.PackID(v2), b.PackID(0)))

	// table[0] = node1 (no bucket at index 1)
	b.AddObjectArray(tableArr, 0, []uint64{node1, 0})

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	hmI := idx.InstancesByID[hmInst]
	require.NotNil(t, hmI)

	got := map[uint64]uint64{}
	n := idx.WalkHashMap(hmI, func(k, v Value) bool {
		got[k.ObjectID] = v.ObjectID
		return true
	})
	assert.Equal(t, 2, n, "walked both nodes in the bucket chain")
	assert.Equal(t, v1, got[k1])
	assert.Equal(t, v2, got[k2])
}

// TestStaticField reads a static object-ref field — used by the env
// spider when it dereferences ProcessEnvironment.theUnmodifiableEnvironment.
func TestStaticField(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	cfgName := ids.add(b, "com/example/Config")
	refName := ids.add(b, "instance")

	const cfgClass uint64 = 0x1300
	const target uint64 = 0x3300

	b.AddLoadClass(1, cfgClass, cfgName)
	b.AddClassDumpWithStatics(cfgClass, 0, 0,
		[]hprof.StaticFieldDecl{
			{NameID: refName, Type: hprof.PrimObject, Value: b.PackID(target)},
		},
		nil,
	)

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	v, ok := idx.StaticField(cfgClass, "instance")
	require.True(t, ok)
	assert.Equal(t, target, v.ObjectID)

	// Unknown field returns ok=false.
	_, ok = idx.StaticField(cfgClass, "nope")
	assert.False(t, ok)
}

// TestSubclasses exercises the inheritance-chain walker that spiders
// use to match a target root class plus every subclass.
func TestSubclasses(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	rootName := ids.add(b, "com/example/Vehicle")
	carName := ids.add(b, "com/example/Car")
	truckName := ids.add(b, "com/example/Truck")
	miniName := ids.add(b, "com/example/Minivan") // extends Car

	const root uint64 = 0x1400
	const car uint64 = 0x1401
	const truck uint64 = 0x1402
	const mini uint64 = 0x1403

	b.AddLoadClass(1, root, rootName)
	b.AddLoadClass(2, car, carName)
	b.AddLoadClass(3, truck, truckName)
	b.AddLoadClass(4, mini, miniName)

	b.AddClassDump(root, 0, 0, nil)
	b.AddClassDump(car, root, 0, nil)
	b.AddClassDump(truck, root, 0, nil)
	b.AddClassDump(mini, car, 0, nil)

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)

	all := idx.Subclasses("com.example.Vehicle")
	names := map[string]bool{}
	for _, c := range all {
		names[c.Name] = true
	}
	assert.True(t, names["com.example.Vehicle"])
	assert.True(t, names["com.example.Car"])
	assert.True(t, names["com.example.Truck"])
	assert.True(t, names["com.example.Minivan"], "transitive subclass via Car")
}

// TestBuildFromBytes_MatchesStreaming guarantees that the zero-copy
// mmap path produces an equivalent index to the streaming path on the
// same dump. Regression guard: if either code path drifts, this test
// flags it before production sees corrupt Index state.
func TestBuildFromBytes_MatchesStreaming(t *testing.T) {
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	// A realistic mini-dump: two classes with one instance each, arrays,
	// a String with byte[]+coder, plus inheritance.
	clsA := ids.add(b, "com/example/A")
	clsB := ids.add(b, "com/example/B")
	stringName := ids.add(b, "java/lang/String")
	fieldX := ids.add(b, "x")
	fieldLabel := ids.add(b, "label")
	fieldValue := ids.add(b, "value")
	fieldCoder := ids.add(b, "coder")

	const (
		classA    uint64 = 0x1A0
		classB    uint64 = 0x1B0
		classStr  uint64 = 0x1C0
		instA     uint64 = 0x2A0
		instB     uint64 = 0x2B0
		strInst   uint64 = 0x2C0
		strBytes  uint64 = 0x2D0
		arrObject uint64 = 0x2E0
	)

	b.AddLoadClass(1, classA, clsA)
	b.AddLoadClass(2, classB, clsB)
	b.AddLoadClass(3, classStr, stringName)

	b.AddClassDump(classA, 0, 4, []hprof.FieldDecl{
		{NameID: fieldX, Type: hprof.PrimInt},
	})
	b.AddClassDump(classB, classA, 8, []hprof.FieldDecl{
		{NameID: fieldLabel, Type: hprof.PrimObject},
	})
	b.AddClassDump(classStr, 0, 9, []hprof.FieldDecl{
		{NameID: fieldValue, Type: hprof.PrimObject},
		{NameID: fieldCoder, Type: hprof.PrimByte},
	})

	b.AddInstanceDump(instA, classA, b.PackInt32(7))
	b.AddInstanceDump(instB, classB, b.PackBytes(b.PackID(strInst), b.PackInt32(42)))
	b.AddInstanceDump(strInst, classStr, b.PackBytes(b.PackID(strBytes), b.PackByte(0)))

	b.AddPrimitiveArray(strBytes, hprof.PrimByte, []byte("mmap-ok"))
	b.AddObjectArray(arrObject, classB, []uint64{instB})

	data := b.Bytes()

	fromStream, err := Build(bytes.NewReader(data))
	require.NoError(t, err)
	fromBytes, err := BuildFromBytes(data)
	require.NoError(t, err)

	// Both paths must agree on the shape of the heap.
	assert.Equal(t, len(fromStream.Classes), len(fromBytes.Classes))
	assert.Equal(t, len(fromStream.InstancesByID), len(fromBytes.InstancesByID))
	assert.Equal(t, len(fromStream.PrimArrays), len(fromBytes.PrimArrays))
	assert.Equal(t, len(fromStream.ObjArrays), len(fromBytes.ObjArrays))
	assert.Equal(t, len(fromStream.Strings), len(fromBytes.Strings))
	assert.Equal(t, fromStream.TotalInstances, fromBytes.TotalInstances)

	// And on the resolved content.
	for id, got := range fromStream.Classes {
		other, ok := fromBytes.Classes[id]
		require.True(t, ok, "class id %x missing in zero-copy index", id)
		assert.Equal(t, got.Name, other.Name)
		assert.Equal(t, len(got.InstanceFields), len(other.InstanceFields))
	}

	// Field reads through both indexes must yield the same value.
	instBStream := fromStream.InstancesByID[instB]
	instBBytes := fromBytes.InstancesByID[instB]
	require.NotNil(t, instBStream)
	require.NotNil(t, instBBytes)
	vs, err := fromStream.ReadField(instBStream, "x")
	require.NoError(t, err)
	vb, err := fromBytes.ReadField(instBBytes, "x")
	require.NoError(t, err)
	assert.Equal(t, vs.IntBits, vb.IntBits)

	// String resolution must work identically.
	gotStream, ok := fromStream.ReadString(strInst)
	require.True(t, ok)
	gotBytes, ok := fromBytes.ReadString(strInst)
	require.True(t, ok)
	assert.Equal(t, gotStream, "mmap-ok")
	assert.Equal(t, gotStream, gotBytes)
}

// TestBuildFromBytes_TruncatedFile errors out cleanly on short input
// instead of panicking or silently returning a partial index.
func TestBuildFromBytes_TruncatedFile(t *testing.T) {
	b := hprof.NewBuilder(8)
	b.AddString(1, "irrelevant")
	data := b.Bytes()
	// Cut off the last few bytes to simulate a truncated mmap region.
	cut := data[:len(data)-3]
	_, err := BuildFromBytes(cut)
	assert.Error(t, err)
}

// --- helpers for the JDK 9+ String tests --------------------------------

// buildStringDumpJDK9 assembles a dump that contains one java.lang.String
// with a byte[] value + byte coder and returns the index + the String
// object's ID for ReadString assertions.
func buildStringDumpJDK9(t *testing.T, s string, coder byte) (*Index, uint64) {
	t.Helper()
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	stringName := ids.add(b, "java/lang/String")
	valueField := ids.add(b, "value")
	coderField := ids.add(b, "coder")

	const stringClass uint64 = 0x1500
	const stringInst uint64 = 0x2500
	const byteArr uint64 = 0x2501

	b.AddLoadClass(1, stringClass, stringName)
	b.AddClassDump(stringClass, 0, 9, []hprof.FieldDecl{
		{NameID: valueField, Type: hprof.PrimObject},
		{NameID: coderField, Type: hprof.PrimByte},
	})
	// LATIN1 = 0, UTF16 = 1. Each LATIN1 byte is a code point 0-255.
	b.AddPrimitiveArray(byteArr, hprof.PrimByte, []byte(s))
	b.AddInstanceDump(stringInst, stringClass, b.PackBytes(b.PackID(byteArr), b.PackByte(coder)))

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)
	return idx, stringInst
}

// buildStringDumpJDK9UTF16 produces the UTF-16LE variant (coder=1).
// Encoding is little-endian per JDK convention for String.coder=1.
func buildStringDumpJDK9UTF16(t *testing.T, s string) (*Index, uint64) {
	t.Helper()
	b := hprof.NewBuilder(8)
	ids := &stringIDs{}

	stringName := ids.add(b, "java/lang/String")
	valueField := ids.add(b, "value")
	coderField := ids.add(b, "coder")

	const stringClass uint64 = 0x1501
	const stringInst uint64 = 0x2510
	const byteArr uint64 = 0x2511

	b.AddLoadClass(1, stringClass, stringName)
	b.AddClassDump(stringClass, 0, 9, []hprof.FieldDecl{
		{NameID: valueField, Type: hprof.PrimObject},
		{NameID: coderField, Type: hprof.PrimByte},
	})
	// Encode as UTF-16LE: low byte first, then high byte.
	var utf16le []byte
	for _, r := range s {
		utf16le = append(utf16le, byte(r), byte(r>>8))
	}
	b.AddPrimitiveArray(byteArr, hprof.PrimByte, utf16le)
	b.AddInstanceDump(stringInst, stringClass, b.PackBytes(b.PackID(byteArr), b.PackByte(1)))

	idx, err := Build(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)
	return idx, stringInst
}
