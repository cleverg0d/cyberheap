// Package heap builds a navigable index over a parsed HPROF file.
// It sits between the low-level hprof.Reader and domain spiders,
// offering "find class by FQN, iterate instances, read string values"
// in the spirit of JDumpSpider's IHeapHolder.
package heap

import (
	"fmt"
	"io"
	"sort"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// ClassDef is the resolved, string-bearing form of hprof.ClassDump.
type ClassDef struct {
	ID             uint64
	Name           string // FQN, normalized with '.' separators
	SuperID        uint64
	InstanceSize   uint32
	InstanceFields []FieldDef
	// We keep static field descriptors but not values (not needed by
	// current spiders). Can be retrieved via Raw if ever required.
	raw *hprof.ClassDump
}

// FieldDef is a resolved instance field descriptor.
type FieldDef struct {
	Name string
	Type hprof.PrimitiveType
}

// InstanceRef is a cheap handle: we keep the raw values slice pointing into
// the file buffer. Values are decoded lazily by callers that need them.
type InstanceRef struct {
	ID      uint64
	ClassID uint64
	// Values are packed in HPROF INSTANCE_DUMP layout: this class's
	// fields first (in declaration order from CLASS_DUMP), followed by
	// super class, super-super, ..., ending at Object. Callers walk
	// them via resolve.readDirectField, which iterates classChain()
	// leaf-to-root to match this byte order.
	Values []byte
}

// PrimArray holds a primitive array body we may need to decode strings.
type PrimArray struct {
	ID          uint64
	ElementType hprof.PrimitiveType
	NumElements uint32
	Elements    []byte
}

// ObjArray holds an object array body (e.g. Object[] entries of a HashMap.table).
type ObjArray struct {
	ID             uint64
	ElementClassID uint64
	NumElements    uint32
	Elements       []byte // numElements * idSize bytes, each an object ref
}

// Index is the full in-memory view of a dump.
type Index struct {
	Header *hprof.Header

	// Strings interned by ID. HPROF files can have millions of records, so
	// we store the string text directly rather than offsets — a typical
	// dump's string table is 10-100 MB, comfortably in RAM for our 2 GB
	// working target (streaming/mmap version is a Phase 2.2 concern).
	Strings map[uint64]string

	// Classes by ID and by fully-qualified name. A single class may appear
	// in ClassByName twice across multiple class loaders; in that case
	// the later one wins. Good enough for triage.
	Classes     map[uint64]*ClassDef
	ClassByName map[string]*ClassDef

	// Instance references grouped by class ID.
	Instances     map[uint64][]*InstanceRef
	InstancesByID map[uint64]*InstanceRef

	// Primitive and object arrays, keyed by array ID.
	PrimArrays map[uint64]*PrimArray
	ObjArrays  map[uint64]*ObjArray

	// Reverse inheritance map: superID → list of direct child class IDs.
	// Built once during finalizeNames(); lets Subclasses() descend the
	// tree in O(descendant_count) instead of scanning every class for
	// every lookup (the naive scan is O(classes*depth) per spider, and
	// we have ~10 spiders each calling Subclasses several times).
	childrenByParent map[uint64][]uint64

	// Stats for `info` command.
	TagCounts      map[hprof.Tag]int
	SubRecordCount int // total heap dump sub-records seen
	TotalInstances int
	ClassNameHits  int // how many LOAD_CLASS classes had a matching string name
}

// pendingClass queues LOAD_CLASS records while we haven't yet seen the
// STRING_IN_UTF8 record that names them. Class naming is resolved once
// all records have been ingested.
type pendingClass struct {
	classID      uint64
	nameStringID uint64
}

// newIndex allocates an empty Index with map capacities tuned for a
// typical multi-hundred-MiB dump. Used by both streaming and byte-slice
// builders.
func newIndex(h *hprof.Header) *Index {
	return &Index{
		Header:        h,
		Strings:       make(map[uint64]string, 1<<14),
		Classes:       make(map[uint64]*ClassDef, 1<<12),
		ClassByName:   make(map[string]*ClassDef, 1<<12),
		Instances:     make(map[uint64][]*InstanceRef, 1<<12),
		InstancesByID: make(map[uint64]*InstanceRef, 1<<16),
		PrimArrays:    make(map[uint64]*PrimArray, 1<<14),
		ObjArrays:     make(map[uint64]*ObjArray, 1<<12),
		TagCounts:     make(map[hprof.Tag]int, 16),
	}
}

// finalizeNames resolves class FQNs and instance-field metadata after
// every record has been ingested. Split out so Build and BuildFromBytes
// share the post-processing.
func (idx *Index) finalizeNames(pending []pendingClass) {
	for _, pc := range pending {
		name := idx.Strings[pc.nameStringID]
		if name != "" {
			idx.ClassNameHits++
		}
		name = normalizeClassName(name)
		cd, ok := idx.Classes[pc.classID]
		if !ok {
			cd = &ClassDef{ID: pc.classID, Name: name}
			idx.Classes[pc.classID] = cd
		} else {
			cd.Name = name
		}
		if name != "" {
			idx.ClassByName[name] = cd
		}
	}
	for _, cd := range idx.Classes {
		if cd.raw == nil {
			continue
		}
		cd.InstanceFields = make([]FieldDef, len(cd.raw.InstanceFields))
		for i, f := range cd.raw.InstanceFields {
			cd.InstanceFields[i] = FieldDef{
				Name: idx.Strings[f.NameStringID],
				Type: f.Type,
			}
		}
	}
	// Build reverse inheritance map once. Subclasses() uses this for
	// O(descendants) lookup instead of scanning every class per call.
	idx.childrenByParent = make(map[uint64][]uint64, len(idx.Classes))
	for _, cd := range idx.Classes {
		if cd.SuperID != 0 {
			idx.childrenByParent[cd.SuperID] = append(idx.childrenByParent[cd.SuperID], cd.ID)
		}
	}
}

// Build reads an HPROF file through an io.Reader, ingesting records
// one at a time. Each HEAP_DUMP_SEGMENT body is copied because the
// Reader reuses its internal buffer on every Next().
//
// Use this path for:
//   - Remote targets (HTTP streams),
//   - Small-to-medium dumps where mmap would be overkill.
//
// Peak RAM ≈ dump size (the bodyCopy slices keep the heap-dump segments
// alive). For multi-GB dumps use BuildFromBytes on an mmap'd region.
func Build(r io.Reader) (*Index, error) {
	rd, err := hprof.NewReader(r)
	if err != nil {
		return nil, err
	}
	idx := newIndex(rd.Header)
	idSize := rd.Header.IDSize

	var pending []pendingClass

	for {
		rec, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		idx.TagCounts[rec.Tag]++

		switch rec.Tag {
		case hprof.TagStringInUTF8:
			id, text, err := hprof.ParseString(rec.Body, idSize)
			if err == nil {
				idx.Strings[id] = text
			}
		case hprof.TagLoadClass:
			lc, err := hprof.ParseLoadClass(rec.Body, idSize)
			if err == nil {
				pending = append(pending, pendingClass{
					classID:      lc.ClassObjectID,
					nameStringID: lc.ClassNameStringID,
				})
			}
		case hprof.TagHeapDump, hprof.TagHeapDumpSegment:
			// Copy the body because subsequent Next() calls overwrite rd.buf.
			// Instance/class payloads we store must remain stable.
			bodyCopy := append([]byte(nil), rec.Body...)
			if err := idx.ingestHeapSegment(bodyCopy, idSize); err != nil {
				return nil, fmt.Errorf("heap dump at 0x%x: %w", rec.Offset, err)
			}
		}
	}

	idx.finalizeNames(pending)
	return idx, nil
}

func (idx *Index) ingestHeapSegment(body []byte, idSize int) error {
	return hprof.WalkHeapDump(body, idSize, &hprof.HeapVisitor{
		OnClassDump: func(cd *hprof.ClassDump) error {
			idx.SubRecordCount++
			// ClassDump may appear before LOAD_CLASS is resolved — prefill
			// the entry so ParseLoadClass pass finds it.
			existing, ok := idx.Classes[cd.ClassObjectID]
			if !ok {
				existing = &ClassDef{ID: cd.ClassObjectID}
				idx.Classes[cd.ClassObjectID] = existing
			}
			existing.SuperID = cd.SuperClassObjectID
			existing.InstanceSize = cd.InstanceSize
			existing.raw = cd
			return nil
		},
		OnInstanceDump: func(id *hprof.InstanceDump) error {
			idx.SubRecordCount++
			idx.TotalInstances++
			ref := &InstanceRef{
				ID:      id.ObjectID,
				ClassID: id.ClassObjectID,
				Values:  id.Values,
			}
			idx.Instances[id.ClassObjectID] = append(idx.Instances[id.ClassObjectID], ref)
			idx.InstancesByID[id.ObjectID] = ref
			return nil
		},
		OnObjectArray: func(oa *hprof.ObjectArrayDump) error {
			idx.SubRecordCount++
			idx.ObjArrays[oa.ArrayID] = &ObjArray{
				ID:             oa.ArrayID,
				ElementClassID: oa.ElementClassID,
				NumElements:    oa.NumElements,
				Elements:       oa.Elements,
			}
			return nil
		},
		OnPrimitiveArray: func(pa *hprof.PrimitiveArrayDump) error {
			idx.SubRecordCount++
			idx.PrimArrays[pa.ArrayID] = &PrimArray{
				ID:          pa.ArrayID,
				ElementType: pa.ElementType,
				NumElements: pa.NumElements,
				Elements:    pa.Elements,
			}
			return nil
		},
	})
}

// normalizeClassName converts HPROF's "java/lang/String" form to FQN dots.
// Array descriptors ("[Ljava/lang/String;") keep their leading "[" markers
// but internal slashes are rewritten.
func normalizeClassName(name string) string {
	if name == "" {
		return ""
	}
	b := []byte(name)
	for i, c := range b {
		if c == '/' {
			b[i] = '.'
		}
	}
	return string(b)
}

// TopClassesByInstances returns the N most populated classes, sorted desc.
// Tie-break by class name for stable output.
type ClassStat struct {
	Name  string
	Count int
}

func (idx *Index) TopClassesByInstances(n int) []ClassStat {
	out := make([]ClassStat, 0, len(idx.Instances))
	for classID, list := range idx.Instances {
		name := "<unknown>"
		if cd, ok := idx.Classes[classID]; ok && cd.Name != "" {
			name = cd.Name
		}
		out = append(out, ClassStat{Name: name, Count: len(list)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
