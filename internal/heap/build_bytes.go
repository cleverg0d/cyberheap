package heap

import (
	"encoding/binary"
	"fmt"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// BuildFromBytes is the zero-copy counterpart of Build. It indexes an
// HPROF file that's already resident as a byte slice — typically an
// mmap'd file mapping. No record body is ever copied:
//
//   - InstanceRef.Values alias directly into `data`
//   - PrimArray.Elements alias into `data`
//   - ObjArray.Elements alias into `data`
//
// The caller MUST keep `data` alive (and, for mmap, kept mapped) for
// the entire lifetime of the returned Index. On Index.Close()-style
// cleanup — which we don't need in Go — the caller would munmap.
//
// Compared to Build() the peak resident set is halved on multi-GiB
// dumps: the file pages back the byte slice, so the OS pages in only
// what the parser touches and can evict what's no longer needed.
func BuildFromBytes(data []byte) (*Index, error) {
	h, err := hprof.ParseHeaderFromBytes(data)
	if err != nil {
		return nil, err
	}
	idx := newIndex(h)
	idSize := h.IDSize

	var pending []pendingClass

	off := int(h.HeaderLen)
	for off < len(data) {
		// Each top-level record header is 9 bytes: tag(1) + timediff(4) + length(4).
		if off+9 > len(data) {
			return nil, fmt.Errorf("hprof: truncated record header at offset %d", off)
		}
		tag := hprof.Tag(data[off])
		length := int(binary.BigEndian.Uint32(data[off+5 : off+9]))
		off += 9
		if off+length > len(data) {
			return nil, fmt.Errorf("hprof: record at offset %d claims %d body bytes, only %d remain",
				off-9, length, len(data)-off)
		}
		body := data[off : off+length]
		off += length

		idx.TagCounts[tag]++

		switch tag {
		case hprof.TagStringInUTF8:
			if id, text, err := hprof.ParseString(body, idSize); err == nil {
				idx.Strings[id] = text
			}
		case hprof.TagLoadClass:
			if lc, err := hprof.ParseLoadClass(body, idSize); err == nil {
				pending = append(pending, pendingClass{
					classID:      lc.ClassObjectID,
					nameStringID: lc.ClassNameStringID,
				})
			}
		case hprof.TagHeapDump, hprof.TagHeapDumpSegment:
			// ingestHeapSegment stashes sub-slices of `body` into the
			// index — and `body` is itself a slice into `data`, so the
			// backing memory is the mmap region. Zero copy.
			if err := idx.ingestHeapSegment(body, idSize); err != nil {
				return nil, fmt.Errorf("heap dump at offset %d: %w", off-length, err)
			}
		}
	}

	idx.finalizeNames(pending)
	return idx, nil
}
