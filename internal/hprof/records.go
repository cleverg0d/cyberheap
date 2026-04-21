package hprof

// Top-level HPROF record tags as defined in hprof_b_spec.h.
// Only the ones we care about are named; the rest are skipped by length.
type Tag byte

const (
	TagStringInUTF8    Tag = 0x01
	TagLoadClass       Tag = 0x02
	TagUnloadClass     Tag = 0x03
	TagStackFrame      Tag = 0x04
	TagStackTrace      Tag = 0x05
	TagAllocSites      Tag = 0x06
	TagHeapSummary     Tag = 0x07
	TagStartThread     Tag = 0x0A
	TagEndThread       Tag = 0x0B
	TagHeapDump        Tag = 0x0C
	TagCPUSamples      Tag = 0x0D
	TagControlSettings Tag = 0x0E
	TagHeapDumpSegment Tag = 0x1C
	TagHeapDumpEnd     Tag = 0x2C
)

// String returns a short human-readable label for the tag (used in info).
func (t Tag) String() string {
	switch t {
	case TagStringInUTF8:
		return "STRING_IN_UTF8"
	case TagLoadClass:
		return "LOAD_CLASS"
	case TagUnloadClass:
		return "UNLOAD_CLASS"
	case TagStackFrame:
		return "STACK_FRAME"
	case TagStackTrace:
		return "STACK_TRACE"
	case TagAllocSites:
		return "ALLOC_SITES"
	case TagHeapSummary:
		return "HEAP_SUMMARY"
	case TagStartThread:
		return "START_THREAD"
	case TagEndThread:
		return "END_THREAD"
	case TagHeapDump:
		return "HEAP_DUMP"
	case TagCPUSamples:
		return "CPU_SAMPLES"
	case TagControlSettings:
		return "CONTROL_SETTINGS"
	case TagHeapDumpSegment:
		return "HEAP_DUMP_SEGMENT"
	case TagHeapDumpEnd:
		return "HEAP_DUMP_END"
	}
	return "UNKNOWN"
}

// PrimitiveType enumerates the Java primitive types used by HPROF CLASS_DUMP
// and PRIMITIVE_ARRAY_DUMP records.
type PrimitiveType byte

const (
	PrimObject  PrimitiveType = 2
	PrimBoolean PrimitiveType = 4
	PrimChar    PrimitiveType = 5
	PrimFloat   PrimitiveType = 6
	PrimDouble  PrimitiveType = 7
	PrimByte    PrimitiveType = 8
	PrimShort   PrimitiveType = 9
	PrimInt     PrimitiveType = 10
	PrimLong    PrimitiveType = 11
)

// Size returns the byte size of a primitive value given the ID size from the
// header (object refs take IDSize bytes; fixed primitives are 1/2/4/8).
func (p PrimitiveType) Size(idSize int) int {
	switch p {
	case PrimObject:
		return idSize
	case PrimBoolean, PrimByte:
		return 1
	case PrimChar, PrimShort:
		return 2
	case PrimFloat, PrimInt:
		return 4
	case PrimDouble, PrimLong:
		return 8
	}
	return 0
}

// String for debugging / info output.
func (p PrimitiveType) String() string {
	switch p {
	case PrimObject:
		return "object"
	case PrimBoolean:
		return "boolean"
	case PrimChar:
		return "char"
	case PrimFloat:
		return "float"
	case PrimDouble:
		return "double"
	case PrimByte:
		return "byte"
	case PrimShort:
		return "short"
	case PrimInt:
		return "int"
	case PrimLong:
		return "long"
	}
	return "unknown"
}

// Heap-dump sub-record tags (inside HEAP_DUMP / HEAP_DUMP_SEGMENT bodies).
const (
	SubRootUnknown        = 0xFF
	SubRootJNIGlobal      = 0x01
	SubRootJNILocal       = 0x02
	SubRootJavaFrame      = 0x03
	SubRootNativeStack    = 0x04
	SubRootStickyClass    = 0x05
	SubRootThreadBlock    = 0x06
	SubRootMonitorUsed    = 0x07
	SubRootThreadObject   = 0x08
	SubClassDump          = 0x20
	SubInstanceDump       = 0x21
	SubObjectArrayDump    = 0x22
	SubPrimitiveArrayDump = 0x23
)
