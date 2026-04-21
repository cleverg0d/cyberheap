package heap

import (
	"encoding/binary"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// WalkHashMap iterates key/value pairs out of a java.util.HashMap-like
// object instance. Supports any map whose storage is:
//
//   - a "table" field pointing to an object array, AND
//   - each non-null array element is a Node-style object with
//     "key", "value", and "next" fields (collision chain).
//
// This covers java.util.HashMap, LinkedHashMap, Hashtable, Properties,
// ConcurrentHashMap (for the common Node layout — TreeBin/TreeNode buckets
// are skipped, which only appear when a single bucket has 8+ entries and
// is not typical for config maps).
//
// The visit callback returns false to stop iteration early.
// Returns the number of entries actually visited.
func (idx *Index) WalkHashMap(inst *InstanceRef, visit func(key, value Value) bool) int {
	if inst == nil {
		return 0
	}
	table, err := idx.ReadField(inst, "table")
	if err != nil || table.IsNull() {
		return 0
	}
	arr, ok := idx.ObjArrays[table.ObjectID]
	if !ok {
		return 0
	}
	idSize := idx.Header.IDSize
	visited := 0
	for i := uint32(0); i < arr.NumElements; i++ {
		off := int(i) * idSize
		if off+idSize > len(arr.Elements) {
			break
		}
		ref := readObjIDAt(arr.Elements, off, idSize)
		if ref == 0 {
			continue
		}
		stop := false
		idx.walkNodeChain(ref, func(k, v Value) bool {
			visited++
			if !visit(k, v) {
				stop = true
				return false
			}
			return true
		})
		if stop {
			break
		}
	}
	return visited
}

// walkNodeChain follows Node.next until the chain terminates or the visitor
// returns false. Defensive against cycles (cap at 4096 links per chain).
func (idx *Index) walkNodeChain(startID uint64, visit func(key, value Value) bool) {
	cur := startID
	for step := 0; cur != 0 && step < 4096; step++ {
		nodeInst, ok := idx.InstancesByID[cur]
		if !ok {
			return
		}
		key, kerr := idx.readDirectField(nodeInst, "key")
		val, verr := idx.readDirectField(nodeInst, "val") // ConcurrentHashMap.Node uses "val"
		if verr != nil {
			val, verr = idx.readDirectField(nodeInst, "value") // HashMap.Node uses "value"
		}
		if kerr == nil && verr == nil {
			if !visit(key, val) {
				return
			}
		}
		next, err := idx.readDirectField(nodeInst, "next")
		if err != nil || next.IsNull() {
			return
		}
		cur = next.ObjectID
	}
}

func readObjIDAt(buf []byte, offset, idSize int) uint64 {
	if idSize == 4 {
		return uint64(binary.BigEndian.Uint32(buf[offset:]))
	}
	return binary.BigEndian.Uint64(buf[offset:])
}

// MapSize returns the best-effort count of entries in a map-like object.
// Uses the "size" field directly — every JDK map tracks it — without
// walking the table.
func (idx *Index) MapSize(inst *InstanceRef) int {
	v, err := idx.ReadField(inst, "size")
	if err != nil {
		return -1
	}
	if v.Type == hprof.PrimInt || v.Type == hprof.PrimLong {
		return int(v.IntBits)
	}
	return -1
}
