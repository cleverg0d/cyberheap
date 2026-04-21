package cli

import (
	"fmt"
	"os"

	"github.com/edsrzf/mmap-go"

	"github.com/cleverg0d/cyberheap/internal/heap"
)

// mmapThreshold picks the size at which the zero-copy mmap path becomes
// meaningfully better than streaming. For dumps below this we just read
// through the io.Reader path — it's simpler and the runtime difference
// is negligible on a modern SSD.
const mmapThreshold = 256 * 1024 * 1024 // 256 MiB

// mappedIndex is a heap.Index plus the munmap cleanup the caller must
// run before the enclosing *os.File is closed. Safe to ignore if you
// only keep the index for the lifetime of one CLI invocation — Go's
// runtime will munmap on process exit either way — but correctness-
// minded code calls Close().
type mappedIndex struct {
	Index  *heap.Index
	closer func() error
}

func (m *mappedIndex) Close() error {
	if m == nil || m.closer == nil {
		return nil
	}
	err := m.closer()
	m.closer = nil
	return err
}

// buildIndex is the one place CLI subcommands reach for a full Index.
// It picks the cheapest path:
//
//	size < mmapThreshold → streaming Build (io.Reader)
//	size ≥ mmapThreshold → mmap + BuildFromBytes (zero-copy)
//
// For URL targets we always stream because the file is already fully
// materialized in a temp file and copying again via mmap would be
// counterproductive — but we still enjoy the path when the user scans
// a big local dump.
func buildIndex(t *target) (*mappedIndex, error) {
	if t.size >= mmapThreshold && !t.isRemote {
		m, err := mmap.Map(t.file, mmap.RDONLY, 0)
		if err == nil {
			idx, err := heap.BuildFromBytes(m)
			if err != nil {
				_ = m.Unmap()
				return nil, fmt.Errorf("mmap parse: %w", err)
			}
			return &mappedIndex{
				Index:  idx,
				closer: func() error { return m.Unmap() },
			}, nil
		}
		// mmap failure is non-fatal (filesystem without mmap support,
		// unusual handle state): fall back to streaming so the user
		// still gets a scan. Report the fallback but don't abort.
		fmt.Fprintf(os.Stderr, "  (mmap unavailable: %v — falling back to streaming)\n", err)
	}

	// Streaming fallback. Caller owns the file handle; we rewind so
	// the reader starts at offset 0.
	if _, err := t.file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("seek: %w", err)
	}
	idx, err := heap.Build(t.file)
	if err != nil {
		return nil, fmt.Errorf("streaming parse: %w", err)
	}
	return &mappedIndex{Index: idx}, nil
}
