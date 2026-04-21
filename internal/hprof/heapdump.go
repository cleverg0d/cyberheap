package hprof

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ClassDump is the payload of a CLASS_DUMP sub-record.
type ClassDump struct {
	ClassObjectID       uint64
	StackTraceSerial    uint32
	SuperClassObjectID  uint64
	ClassLoaderObjectID uint64
	SignersObjectID     uint64
	ProtectionDomainID  uint64
	InstanceSize        uint32
	StaticFields        []StaticField
	InstanceFields      []InstanceField
}

type StaticField struct {
	NameStringID uint64
	Type         PrimitiveType
	// Raw value bytes (for objects it's an ID in big-endian).
	Value []byte
}

type InstanceField struct {
	NameStringID uint64
	Type         PrimitiveType
}

// InstanceDump is the payload of an INSTANCE_DUMP sub-record.
// Values is the packed field values, to be decoded against the flattened
// class hierarchy (super-class fields first, innermost last).
type InstanceDump struct {
	ObjectID         uint64
	StackTraceSerial uint32
	ClassObjectID    uint64
	Values           []byte
}

// ObjectArrayDump is the payload of an OBJECT_ARRAY_DUMP sub-record.
type ObjectArrayDump struct {
	ArrayID          uint64
	StackTraceSerial uint32
	NumElements      uint32
	ElementClassID   uint64
	Elements         []byte // raw, numElements * idSize bytes
}

// PrimitiveArrayDump is the payload of a PRIMITIVE_ARRAY_DUMP sub-record.
type PrimitiveArrayDump struct {
	ArrayID          uint64
	StackTraceSerial uint32
	NumElements      uint32
	ElementType      PrimitiveType
	Elements         []byte // numElements * elementType.Size(idSize) bytes
}

// HeapVisitor is the callback bundle passed to WalkHeapDump. Return a non-nil
// error from any method to abort iteration early. Implementations may leave
// fields nil to skip a sub-record type — the walker still advances correctly.
type HeapVisitor struct {
	OnClassDump      func(*ClassDump) error
	OnInstanceDump   func(*InstanceDump) error
	OnObjectArray    func(*ObjectArrayDump) error
	OnPrimitiveArray func(*PrimitiveArrayDump) error
}

// WalkHeapDump iterates the body of a HEAP_DUMP / HEAP_DUMP_SEGMENT record
// and dispatches each sub-record to the visitor. Root sub-records (0x01..0x08,
// 0xFF) are recognized and skipped — we do not need their payloads yet.
func WalkHeapDump(body []byte, idSize int, v *HeapVisitor) error {
	i := 0
	for i < len(body) {
		tag := body[i]
		i++
		n, err := parseSubRecord(tag, body[i:], idSize, v)
		if err != nil {
			return fmt.Errorf("hprof: sub-record 0x%02x at +%d: %w", tag, i-1, err)
		}
		i += n
	}
	return nil
}

func parseSubRecord(tag byte, rem []byte, idSize int, v *HeapVisitor) (int, error) {
	switch tag {
	// Root markers — we just need to know their fixed body size.
	case SubRootUnknown, SubRootStickyClass, SubRootMonitorUsed:
		return idSize, bounds(rem, idSize)
	case SubRootJNIGlobal:
		return idSize + idSize, bounds(rem, idSize+idSize)
	case SubRootJNILocal, SubRootJavaFrame:
		return idSize + 4 + 4, bounds(rem, idSize+8)
	case SubRootNativeStack, SubRootThreadBlock:
		return idSize + 4, bounds(rem, idSize+4)
	case SubRootThreadObject:
		return idSize + 4 + 4, bounds(rem, idSize+8)

	case SubClassDump:
		return parseClassDump(rem, idSize, v)
	case SubInstanceDump:
		return parseInstanceDump(rem, idSize, v)
	case SubObjectArrayDump:
		return parseObjectArrayDump(rem, idSize, v)
	case SubPrimitiveArrayDump:
		return parsePrimitiveArrayDump(rem, idSize, v)
	}
	return 0, fmt.Errorf("unknown sub-record tag 0x%02x", tag)
}

func bounds(rem []byte, n int) error {
	if len(rem) < n {
		return errors.New("truncated sub-record")
	}
	return nil
}

func parseClassDump(rem []byte, idSize int, v *HeapVisitor) (int, error) {
	// Header: id + u4 + id*4 + u4 + u4 + u4 (reserved + instance size + ...)
	// Actual layout:
	//   classObjectID id
	//   stackTraceSerial u4
	//   superClassObjectID id
	//   classLoaderObjectID id
	//   signersObjectID id
	//   protectionDomainObjectID id
	//   reserved1 id
	//   reserved2 id
	//   instanceSize u4
	//   constantPoolSize u2
	//     per entry: index u2 + type u1 + value (primitive)
	//   staticFieldCount u2
	//     per field: nameStringID id + type u1 + value
	//   instanceFieldCount u2
	//     per field: nameStringID id + type u1
	headerLen := idSize + 4 + idSize*4 + idSize*2 + 4
	if err := bounds(rem, headerLen+2); err != nil {
		return 0, err
	}
	off := 0
	cd := &ClassDump{}
	cd.ClassObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	cd.StackTraceSerial = binary.BigEndian.Uint32(rem[off:])
	off += 4
	cd.SuperClassObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	cd.ClassLoaderObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	cd.SignersObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	cd.ProtectionDomainID = readID(rem[off:off+idSize], idSize)
	off += idSize
	off += idSize * 2 // reserved1, reserved2
	cd.InstanceSize = binary.BigEndian.Uint32(rem[off:])
	off += 4

	// Constant pool entries.
	if len(rem) < off+2 {
		return 0, errors.New("class dump: truncated before const pool")
	}
	cpCount := binary.BigEndian.Uint16(rem[off:])
	off += 2
	for i := uint16(0); i < cpCount; i++ {
		if len(rem) < off+2+1 {
			return 0, errors.New("class dump: truncated const pool entry")
		}
		off += 2 // index
		pt := PrimitiveType(rem[off])
		off++
		sz := pt.Size(idSize)
		if sz == 0 || len(rem) < off+sz {
			return 0, errors.New("class dump: bad const pool type")
		}
		off += sz
	}

	// Static fields.
	if len(rem) < off+2 {
		return 0, errors.New("class dump: truncated before static fields")
	}
	staticCount := binary.BigEndian.Uint16(rem[off:])
	off += 2
	cd.StaticFields = make([]StaticField, 0, staticCount)
	for i := uint16(0); i < staticCount; i++ {
		if len(rem) < off+idSize+1 {
			return 0, errors.New("class dump: truncated static field header")
		}
		nameID := readID(rem[off:off+idSize], idSize)
		off += idSize
		pt := PrimitiveType(rem[off])
		off++
		sz := pt.Size(idSize)
		if sz == 0 || len(rem) < off+sz {
			return 0, errors.New("class dump: bad static field value")
		}
		cd.StaticFields = append(cd.StaticFields, StaticField{
			NameStringID: nameID,
			Type:         pt,
			Value:        append([]byte(nil), rem[off:off+sz]...),
		})
		off += sz
	}

	// Instance fields.
	if len(rem) < off+2 {
		return 0, errors.New("class dump: truncated before instance fields")
	}
	instCount := binary.BigEndian.Uint16(rem[off:])
	off += 2
	cd.InstanceFields = make([]InstanceField, 0, instCount)
	for i := uint16(0); i < instCount; i++ {
		if len(rem) < off+idSize+1 {
			return 0, errors.New("class dump: truncated instance field")
		}
		nameID := readID(rem[off:off+idSize], idSize)
		off += idSize
		pt := PrimitiveType(rem[off])
		off++
		cd.InstanceFields = append(cd.InstanceFields, InstanceField{
			NameStringID: nameID,
			Type:         pt,
		})
	}

	if v != nil && v.OnClassDump != nil {
		if err := v.OnClassDump(cd); err != nil {
			return 0, err
		}
	}
	return off, nil
}

func parseInstanceDump(rem []byte, idSize int, v *HeapVisitor) (int, error) {
	// id + u4 + id + u4 + values
	headerLen := idSize + 4 + idSize + 4
	if err := bounds(rem, headerLen); err != nil {
		return 0, err
	}
	off := 0
	id := &InstanceDump{}
	id.ObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	id.StackTraceSerial = binary.BigEndian.Uint32(rem[off:])
	off += 4
	id.ClassObjectID = readID(rem[off:off+idSize], idSize)
	off += idSize
	valuesLen := binary.BigEndian.Uint32(rem[off:])
	off += 4
	if err := bounds(rem[off:], int(valuesLen)); err != nil {
		return 0, err
	}
	id.Values = rem[off : off+int(valuesLen)]
	off += int(valuesLen)

	if v != nil && v.OnInstanceDump != nil {
		if err := v.OnInstanceDump(id); err != nil {
			return 0, err
		}
	}
	return off, nil
}

func parseObjectArrayDump(rem []byte, idSize int, v *HeapVisitor) (int, error) {
	// id + u4 + u4 + id + num*id
	headerLen := idSize + 4 + 4 + idSize
	if err := bounds(rem, headerLen); err != nil {
		return 0, err
	}
	off := 0
	oa := &ObjectArrayDump{}
	oa.ArrayID = readID(rem[off:off+idSize], idSize)
	off += idSize
	oa.StackTraceSerial = binary.BigEndian.Uint32(rem[off:])
	off += 4
	oa.NumElements = binary.BigEndian.Uint32(rem[off:])
	off += 4
	oa.ElementClassID = readID(rem[off:off+idSize], idSize)
	off += idSize
	dataLen := int(oa.NumElements) * idSize
	if err := bounds(rem[off:], dataLen); err != nil {
		return 0, err
	}
	oa.Elements = rem[off : off+dataLen]
	off += dataLen
	if v != nil && v.OnObjectArray != nil {
		if err := v.OnObjectArray(oa); err != nil {
			return 0, err
		}
	}
	return off, nil
}

func parsePrimitiveArrayDump(rem []byte, idSize int, v *HeapVisitor) (int, error) {
	// id + u4 + u4 + u1 + num*size
	headerLen := idSize + 4 + 4 + 1
	if err := bounds(rem, headerLen); err != nil {
		return 0, err
	}
	off := 0
	pa := &PrimitiveArrayDump{}
	pa.ArrayID = readID(rem[off:off+idSize], idSize)
	off += idSize
	pa.StackTraceSerial = binary.BigEndian.Uint32(rem[off:])
	off += 4
	pa.NumElements = binary.BigEndian.Uint32(rem[off:])
	off += 4
	pa.ElementType = PrimitiveType(rem[off])
	off++
	sz := pa.ElementType.Size(idSize)
	if sz == 0 {
		return 0, fmt.Errorf("primitive array: bad element type %d", pa.ElementType)
	}
	dataLen := int(pa.NumElements) * sz
	if err := bounds(rem[off:], dataLen); err != nil {
		return 0, err
	}
	pa.Elements = rem[off : off+dataLen]
	off += dataLen
	if v != nil && v.OnPrimitiveArray != nil {
		if err := v.OnPrimitiveArray(pa); err != nil {
			return 0, err
		}
	}
	return off, nil
}
