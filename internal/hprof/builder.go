package hprof

import (
	"bytes"
	"encoding/binary"
)

// Builder is a minimal HPROF 1.0.2 writer used by tests. It lets us
// synthesize dumps with exactly the shape we want to exercise the
// parser / indexer / resolver / spider layers — no external JVM needed.
//
// It lives in the production package (not a separate _test package) so
// heap and spiders tests can import it without circular-import drama,
// but it is NEVER called from production code paths.
//
// Usage:
//
//	b := hprof.NewBuilder(8)
//	b.AddString(1, "com/example/Greeter")
//	b.AddLoadClass(1, 100, 1)
//	b.AddClassDump(100, 0, 12, []hprof.FieldDecl{{NameID: 2, Type: hprof.PrimInt}})
//	b.AddInstanceDump(1000, 100, b.PackInt32(42))
//	data := b.Bytes()
//
// Encoding of multi-byte primitives matches HPROF: big-endian throughout.
type Builder struct {
	idSize  int
	buf     *bytes.Buffer
	heapBuf *bytes.Buffer
}

// FieldDecl is a single CLASS_DUMP instance-field declaration.
type FieldDecl struct {
	NameID uint64        // points at a prior AddString
	Type   PrimitiveType // PrimObject / PrimInt / PrimByte / ...
}

// StaticFieldDecl is a single CLASS_DUMP static-field declaration.
type StaticFieldDecl struct {
	NameID uint64
	Type   PrimitiveType
	Value  []byte // size must match Type.Size(idSize)
}

// NewBuilder creates a fresh Builder. idSize must be 4 or 8; real-world
// 64-bit JVMs emit 8-byte IDs (HotSpot default) so 8 is the usual test
// value.
func NewBuilder(idSize int) *Builder {
	b := &Builder{
		idSize:  idSize,
		buf:     &bytes.Buffer{},
		heapBuf: &bytes.Buffer{},
	}
	b.writeHeader()
	return b
}

// writeHeader emits the fixed 31-byte HPROF 1.0.2 header with a zero
// timestamp. ID size is taken from the builder config.
func (b *Builder) writeHeader() {
	b.buf.WriteString("JAVA PROFILE 1.0.2")
	b.buf.WriteByte(0x00)
	binary.Write(b.buf, binary.BigEndian, uint32(b.idSize))
	binary.Write(b.buf, binary.BigEndian, uint32(0)) // ts hi
	binary.Write(b.buf, binary.BigEndian, uint32(0)) // ts lo
}

// writeRecord wraps a top-level record body with its tag + length prefix.
func (b *Builder) writeRecord(tag Tag, body []byte) {
	b.buf.WriteByte(byte(tag))
	binary.Write(b.buf, binary.BigEndian, uint32(0)) // timediff µs
	binary.Write(b.buf, binary.BigEndian, uint32(len(body)))
	b.buf.Write(body)
}

// AddString writes a STRING_IN_UTF8 record. Use the returned ID to wire
// it into LOAD_CLASS / CLASS_DUMP field names. `text` is stored verbatim
// (no modified UTF-8 escaping) which is fine for ASCII test inputs.
func (b *Builder) AddString(id uint64, text string) {
	body := &bytes.Buffer{}
	b.writeID(body, id)
	body.WriteString(text)
	b.writeRecord(TagStringInUTF8, body.Bytes())
}

// AddLoadClass registers a Java class name. The indexer uses this pass
// to build ClassByName lookup; without it a synthetic class dump is
// anonymous.
func (b *Builder) AddLoadClass(serial uint32, classID, nameStringID uint64) {
	body := &bytes.Buffer{}
	binary.Write(body, binary.BigEndian, serial)
	b.writeID(body, classID)
	binary.Write(body, binary.BigEndian, uint32(0)) // stack trace serial
	b.writeID(body, nameStringID)
	b.writeRecord(TagLoadClass, body.Bytes())
}

// AddClassDump writes a CLASS_DUMP sub-record inside the heap dump
// segment. Only the bits CyberHeap reads are filled — constant pool is
// always empty, reserved slots are zero.
func (b *Builder) AddClassDump(classID, superID uint64, instanceSize uint32, fields []FieldDecl) {
	b.addClassDumpFull(classID, superID, instanceSize, nil, fields)
}

// AddClassDumpWithStatics is the full variant — caller provides static
// field declarations alongside instance fields. Use this to test
// Index.StaticField().
func (b *Builder) AddClassDumpWithStatics(classID, superID uint64, instanceSize uint32, statics []StaticFieldDecl, fields []FieldDecl) {
	b.addClassDumpFull(classID, superID, instanceSize, statics, fields)
}

func (b *Builder) addClassDumpFull(classID, superID uint64, instanceSize uint32, statics []StaticFieldDecl, fields []FieldDecl) {
	body := b.heapBuf
	body.WriteByte(SubClassDump)
	b.writeID(body, classID)
	binary.Write(body, binary.BigEndian, uint32(0)) // stack trace
	b.writeID(body, superID)
	b.writeID(body, 0) // class loader
	b.writeID(body, 0) // signers
	b.writeID(body, 0) // protection domain
	b.writeID(body, 0) // reserved 1
	b.writeID(body, 0) // reserved 2
	binary.Write(body, binary.BigEndian, instanceSize)
	binary.Write(body, binary.BigEndian, uint16(0)) // const pool count = 0

	binary.Write(body, binary.BigEndian, uint16(len(statics)))
	for _, sf := range statics {
		b.writeID(body, sf.NameID)
		body.WriteByte(byte(sf.Type))
		body.Write(sf.Value) // caller must size this correctly for sf.Type
	}

	binary.Write(body, binary.BigEndian, uint16(len(fields)))
	for _, f := range fields {
		b.writeID(body, f.NameID)
		body.WriteByte(byte(f.Type))
	}
}

// AddInstanceDump writes an INSTANCE_DUMP sub-record. `packedValues`
// must already be big-endian-packed in leaf-first order: this class's
// fields (in declaration order) followed by each superclass's fields.
// Use the Pack* helpers to build it.
func (b *Builder) AddInstanceDump(objectID, classID uint64, packedValues []byte) {
	body := b.heapBuf
	body.WriteByte(SubInstanceDump)
	b.writeID(body, objectID)
	binary.Write(body, binary.BigEndian, uint32(0)) // stack trace serial
	b.writeID(body, classID)
	binary.Write(body, binary.BigEndian, uint32(len(packedValues)))
	body.Write(packedValues)
}

// AddObjectArray writes an OBJECT_ARRAY_DUMP sub-record.
func (b *Builder) AddObjectArray(arrayID, elementClassID uint64, elements []uint64) {
	body := b.heapBuf
	body.WriteByte(SubObjectArrayDump)
	b.writeID(body, arrayID)
	binary.Write(body, binary.BigEndian, uint32(0))
	binary.Write(body, binary.BigEndian, uint32(len(elements)))
	b.writeID(body, elementClassID)
	for _, e := range elements {
		b.writeID(body, e)
	}
}

// AddPrimitiveArray writes a PRIMITIVE_ARRAY_DUMP sub-record.
// numElements is computed from len(data)/elementType.Size(idSize).
func (b *Builder) AddPrimitiveArray(arrayID uint64, elementType PrimitiveType, data []byte) {
	body := b.heapBuf
	body.WriteByte(SubPrimitiveArrayDump)
	b.writeID(body, arrayID)
	binary.Write(body, binary.BigEndian, uint32(0))
	elemSize := elementType.Size(b.idSize)
	num := 0
	if elemSize > 0 {
		num = len(data) / elemSize
	}
	binary.Write(body, binary.BigEndian, uint32(num))
	body.WriteByte(byte(elementType))
	body.Write(data)
}

// Bytes flushes the accumulated heap-dump segment and returns the
// complete HPROF file. Safe to call multiple times; subsequent calls
// after adding more records emit another segment.
func (b *Builder) Bytes() []byte {
	if b.heapBuf.Len() > 0 {
		b.writeRecord(TagHeapDumpSegment, b.heapBuf.Bytes())
		b.heapBuf.Reset()
	}
	// HEAP_DUMP_END is required so a reader that expects the sentinel
	// doesn't stop at EOF with an "unexpected end" error.
	b.writeRecord(TagHeapDumpEnd, nil)
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

// --- packing helpers ----------------------------------------------------

// PackID returns idSize-wide big-endian bytes for the given object ID.
func (b *Builder) PackID(id uint64) []byte {
	buf := make([]byte, b.idSize)
	if b.idSize == 4 {
		binary.BigEndian.PutUint32(buf, uint32(id))
	} else {
		binary.BigEndian.PutUint64(buf, id)
	}
	return buf
}

// PackInt32 packs a signed 32-bit integer as big-endian bytes.
func (b *Builder) PackInt32(v int32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(v))
	return out
}

// PackInt64 packs a signed 64-bit integer as big-endian bytes.
func (b *Builder) PackInt64(v int64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(v))
	return out
}

// PackByte packs a single byte.
func (b *Builder) PackByte(v byte) []byte {
	return []byte{v}
}

// PackChar packs a Java char (big-endian uint16).
func (b *Builder) PackChar(v uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, v)
	return out
}

// PackBytes concatenates the arguments in order. Convenience for building
// instance value payloads where several fields are packed together.
func (b *Builder) PackBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// CharArrayBytes encodes a Go string as a big-endian UTF-16 char[] body,
// ready for AddPrimitiveArray(..., PrimChar, ...). Matches JDK 8's
// java.lang.String.value layout.
func (b *Builder) CharArrayBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		// Surrogate-pair split for code points above the BMP is rare in
		// tests; we stick to BMP characters. A more thorough impl would
		// call utf16.Encode.
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

// writeID is the internal counterpart of PackID that writes into an
// existing buffer rather than allocating a fresh slice per call.
func (b *Builder) writeID(w *bytes.Buffer, id uint64) {
	if b.idSize == 4 {
		binary.Write(w, binary.BigEndian, uint32(id))
	} else {
		binary.Write(w, binary.BigEndian, id)
	}
}

// IDSize is exposed so tests can align byte counts without peeking into
// the builder internals.
func (b *Builder) IDSize() int { return b.idSize }
