package heap

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// Value is a decoded field value. For PrimObject we expose ObjectID; for
// primitives the raw bits are in IntBits (reinterpret for float/double).
type Value struct {
	Type     hprof.PrimitiveType
	ObjectID uint64
	IntBits  int64
}

// IsNull reports whether an object reference field is the null pointer.
func (v Value) IsNull() bool {
	return v.Type == hprof.PrimObject && v.ObjectID == 0
}

// ReadField decodes a single instance field by a dotted path.
//
// Examples:
//
//	"password"                 -> direct field on inst
//	"dataSource.password"      -> follow dataSource object ref, then read its password
//	"cipherService.key.value"  -> 3-level descent
//
// For the terminal segment of the path the returned Value still requires
// string or array resolution for human-readable output; see ReadString and
// ReadByteArray. For intermediate segments the resolver follows object refs
// automatically.
func (idx *Index) ReadField(inst *InstanceRef, path string) (Value, error) {
	if inst == nil {
		return Value{}, fmt.Errorf("nil instance")
	}
	segments := strings.Split(path, ".")
	cur := inst
	for i, seg := range segments {
		v, err := idx.readDirectField(cur, seg)
		if err != nil {
			return Value{}, fmt.Errorf("%s: %w", path, err)
		}
		if i == len(segments)-1 {
			return v, nil
		}
		if v.Type != hprof.PrimObject || v.ObjectID == 0 {
			return Value{}, fmt.Errorf("%s: cannot descend into non-object %q", path, seg)
		}
		next, ok := idx.InstancesByID[v.ObjectID]
		if !ok {
			return Value{}, fmt.Errorf("%s: object 0x%x not found after %q", path, v.ObjectID, seg)
		}
		cur = next
	}
	return Value{}, fmt.Errorf("empty path")
}

// readDirectField looks up a single field on an instance, walking the class
// hierarchy.
//
// Per hprof_b_spec.h, INSTANCE_DUMP values are packed "this class first,
// followed by super class, super-super class, ..., Object". That's the
// opposite of what a C++/Java object layout looks like in memory — but it
// is what HPROF writes, so we read in the same order.
func (idx *Index) readDirectField(inst *InstanceRef, name string) (Value, error) {
	idSize := idx.Header.IDSize
	chain := idx.classChain(inst.ClassID)
	offset := 0
	for _, cls := range chain {
		for _, f := range cls.InstanceFields {
			sz := f.Type.Size(idSize)
			if sz == 0 {
				return Value{}, fmt.Errorf("class %q field %q: bad type %d", cls.Name, f.Name, f.Type)
			}
			if offset+sz > len(inst.Values) {
				return Value{}, fmt.Errorf("class %q field %q: values truncated", cls.Name, f.Name)
			}
			if f.Name == name {
				return decodeValue(inst.Values[offset:offset+sz], f.Type, idSize), nil
			}
			offset += sz
		}
	}
	return Value{}, fmt.Errorf("no field %q on %s (or supers)", name, idx.className(inst.ClassID))
}

// classChain returns [this, super, super-super, ..., Object] — matching the
// HPROF leaf-to-root packing of INSTANCE_DUMP values.
func (idx *Index) classChain(classID uint64) []*ClassDef {
	var chain []*ClassDef
	id := classID
	for id != 0 {
		cd, ok := idx.Classes[id]
		if !ok {
			break
		}
		chain = append(chain, cd)
		id = cd.SuperID
	}
	return chain
}

// className returns the FQN of a class or "<0x%x>" if unknown.
func (idx *Index) className(id uint64) string {
	if cd, ok := idx.Classes[id]; ok && cd.Name != "" {
		return cd.Name
	}
	return fmt.Sprintf("<class 0x%x>", id)
}

func decodeValue(raw []byte, t hprof.PrimitiveType, idSize int) Value {
	v := Value{Type: t}
	switch t {
	case hprof.PrimObject:
		if idSize == 4 {
			v.ObjectID = uint64(binary.BigEndian.Uint32(raw))
		} else {
			v.ObjectID = binary.BigEndian.Uint64(raw)
		}
	case hprof.PrimBoolean, hprof.PrimByte:
		v.IntBits = int64(raw[0])
	case hprof.PrimChar, hprof.PrimShort:
		v.IntBits = int64(binary.BigEndian.Uint16(raw))
	case hprof.PrimInt, hprof.PrimFloat:
		v.IntBits = int64(int32(binary.BigEndian.Uint32(raw)))
	case hprof.PrimLong, hprof.PrimDouble:
		v.IntBits = int64(binary.BigEndian.Uint64(raw))
	}
	return v
}

// ReadString resolves a java.lang.String object reference to a Go string.
// Supports both JDK 8 (char[] value) and JDK 9+ (byte[] value + byte coder
// where 0 = LATIN1 / ISO-8859-1, 1 = UTF-16LE).
//
// Returns ok=false when the object is nil or not a String.
func (idx *Index) ReadString(objID uint64) (string, bool) {
	if objID == 0 {
		return "", false
	}
	inst, ok := idx.InstancesByID[objID]
	if !ok {
		return "", false
	}
	cd, ok := idx.Classes[inst.ClassID]
	if !ok || cd.Name != "java.lang.String" {
		return "", false
	}

	valueField, err := idx.readDirectField(inst, "value")
	if err != nil || valueField.Type != hprof.PrimObject || valueField.ObjectID == 0 {
		return "", false
	}
	arr, ok := idx.PrimArrays[valueField.ObjectID]
	if !ok {
		return "", false
	}

	switch arr.ElementType {
	case hprof.PrimByte:
		// JDK 9+: byte[] value with separate coder field.
		coder := int64(0)
		if c, err := idx.readDirectField(inst, "coder"); err == nil {
			coder = c.IntBits
		}
		if coder == 1 {
			return decodeUTF16LE(arr.Elements), true
		}
		// LATIN1: each byte is a code point 0-255.
		return string(arr.Elements), true
	case hprof.PrimChar:
		// JDK 8: char[] — UTF-16 BE (HPROF writes multibyte primitives BE).
		return decodeUTF16BE(arr.Elements), true
	}
	return "", false
}

// ReadByteArray returns the raw bytes of a byte[] object (e.g. Shiro
// cipherKey which is stored as a byte[]). Returns nil if not found.
func (idx *Index) ReadByteArray(objID uint64) []byte {
	if objID == 0 {
		return nil
	}
	arr, ok := idx.PrimArrays[objID]
	if !ok || arr.ElementType != hprof.PrimByte {
		return nil
	}
	return arr.Elements
}

func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func decodeUTF16BE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.BigEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// StaticField looks up a named static field on a class and returns its
// decoded value. Static values are captured verbatim during CLASS_DUMP
// parsing, so this is a lookup-only operation — no additional I/O needed.
//
// Returns ok=false when the class is unknown or the field isn't declared.
func (idx *Index) StaticField(classID uint64, name string) (Value, bool) {
	cd, ok := idx.Classes[classID]
	if !ok || cd.raw == nil {
		return Value{}, false
	}
	for _, sf := range cd.raw.StaticFields {
		if idx.Strings[sf.NameStringID] != name {
			continue
		}
		sz := sf.Type.Size(idx.Header.IDSize)
		if sz == 0 || sz > len(sf.Value) {
			return Value{}, false
		}
		return decodeValue(sf.Value[:sz], sf.Type, idx.Header.IDSize), true
	}
	return Value{}, false
}

// Subclasses returns the root class matched by rootFQN plus every class
// that transitively extends it, walking the precomputed children map in
// O(descendants). Called repeatedly by spiders; the precomputed map
// turned a per-spider O(classes*depth) scan into a single BFS.
func (idx *Index) Subclasses(rootFQN string) []*ClassDef {
	root, ok := idx.ClassByName[rootFQN]
	if !ok {
		return nil
	}
	out := []*ClassDef{root}
	// BFS: each dequeued class contributes its direct children to the
	// frontier. Terminates naturally at leaves (empty children list).
	queue := []uint64{root.ID}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, childID := range idx.childrenByParent[parent] {
			if cd, ok := idx.Classes[childID]; ok {
				out = append(out, cd)
				queue = append(queue, childID)
			}
		}
	}
	return out
}

// subclassesLinearFallback preserves the original O(N*depth) behavior
// for the pre-finalize window in case anything ever calls Subclasses
// before the index build completed. Kept unexported; Build/BuildFromBytes
// always call finalizeNames before returning.
func (idx *Index) subclassesLinearFallback(rootFQN string) []*ClassDef {
	root, ok := idx.ClassByName[rootFQN]
	if !ok {
		return nil
	}
	var out []*ClassDef
	for _, cd := range idx.Classes {
		if cd.ID == root.ID {
			out = append(out, cd)
			continue
		}
		id := cd.SuperID
		for id != 0 {
			if id == root.ID {
				out = append(out, cd)
				break
			}
			parent, ok := idx.Classes[id]
			if !ok {
				break
			}
			id = parent.SuperID
		}
	}
	return out
}
