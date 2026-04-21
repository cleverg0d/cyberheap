package scanner

import (
	"fmt"
	"io"
	"sync"
)

// Streaming scan defaults. Tuned for dumps that won't fit in RAM (multi-GB):
//
//	ChunkSize       : 64 MiB is a sweet spot — small enough to cap memory,
//	                  large enough that the overhead of spawning goroutines
//	                  per pattern amortizes cleanly.
//	OverlapBytes    : maximum realistic pattern length. JWTs go up to a few
//	                  KiB, private keys 2–4 KiB; 16 KiB is a comfortable
//	                  ceiling with zero measurable cost for typical dumps.
//	Auto threshold  : 512 MiB. Below that the single-buffer path is both
//	                  faster (no chunk stitching) and small enough that
//	                  io.ReadAll is fine on a pentest laptop.
const (
	DefaultChunkSize          = 64 * 1024 * 1024
	DefaultOverlapBytes       = 16 * 1024
	DefaultStreamingThreshold = 512 * 1024 * 1024
)

// StreamOptions configure ScanStream. Zero values mean "use defaults".
type StreamOptions struct {
	Options                              // inherits Patterns/Severities/Categories/ScanUTF16
	ChunkSize    int                     // per-chunk read size (bytes)
	OverlapBytes int                     // overlap between adjacent chunks
	Progress     func(done, total int64) // optional: called after each chunk
}

// ScanStream scans a file in overlapping chunks. Use this when the dump
// is large enough that reading the whole thing into RAM would be a
// problem — typically anything above ~500 MB on a 16 GB laptop.
//
// Correctness model: we read [chunkStart .. chunkStart+chunkSize+overlap)
// so a pattern that spans the chunk boundary is still fully visible in
// at least one pass. Duplicates introduced by the overlap are removed by
// the normal dedupe step at the end. Offsets are absolute file offsets.
func ScanStream(r io.ReaderAt, size int64, opts StreamOptions) ([]Match, error) {
	if size <= 0 {
		return nil, nil
	}
	chunk := opts.ChunkSize
	if chunk <= 0 {
		chunk = DefaultChunkSize
	}
	overlap := opts.OverlapBytes
	if overlap < 0 {
		overlap = 0
	}
	if overlap == 0 {
		overlap = DefaultOverlapBytes
	}
	patterns := effectivePatterns(opts.Options)
	if len(patterns) == 0 {
		return nil, fmt.Errorf("scanner: no patterns enabled")
	}

	var (
		mu      sync.Mutex
		matches []Match
	)

	var offset int64
	for offset < size {
		end := offset + int64(chunk)
		if end > size {
			end = size
		}
		readEnd := end
		// If we're not at EOF, keep the overlap window so boundary
		// matches land inside one chunk or the next in full.
		if end < size {
			readEnd = end + int64(overlap)
			if readEnd > size {
				readEnd = size
			}
		}

		buf := make([]byte, readEnd-offset)
		if _, err := r.ReadAt(buf, offset); err != nil && err != io.EOF {
			return nil, fmt.Errorf("scanner: read at %d: %w", offset, err)
		}

		chunkMatches := scanBuffer(buf, patterns, offset)
		if len(chunkMatches) > 0 {
			mu.Lock()
			matches = append(matches, chunkMatches...)
			mu.Unlock()
		}

		if opts.Progress != nil {
			opts.Progress(end, size)
		}

		offset = end
	}

	// UTF-16 squeeze: only meaningful over the whole file view. For
	// streaming we skip it by default — streaming mode is for giant
	// dumps, and the squeeze would need its own overlap logic. Opt-in
	// via ScanUTF16 still works on the in-memory path.

	return deduplicate(matches), nil
}

// ShouldStream decides whether a source of the given size benefits from
// streaming mode. Callers should use it to auto-pick between Scan and
// ScanStream for *os.File targets.
func ShouldStream(size int64) bool {
	return size >= DefaultStreamingThreshold
}
