package scanner

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bytesReaderAt is io.ReaderAt over a byte slice. Tests use this to
// drive ScanStream without writing temp files.
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, nil
	}
	n := copy(p, b[off:])
	return n, nil
}

// TestScanStream_FindsAllKnownPatterns runs a "representative corpus"
// through streaming with a deliberately small chunk size so chunk stitching
// is exercised on a modest input.
func TestScanStream_FindsAllKnownPatterns(t *testing.T) {
	corpus := []byte("" +
		"prefix-filler-01... aws_access_key_id=AKIAIOSFODNN7EXAMPLE more-filler... " +
		"tail spring.datasource.password=Sup3rS3cret! more " +
		"email=user@example.com end.")

	data := bytesReaderAt(corpus)
	matches, err := ScanStream(data, int64(len(corpus)), StreamOptions{
		ChunkSize:    64, // tiny — forces multi-chunk even on this small input
		OverlapBytes: 32,
	})
	require.NoError(t, err)

	names := map[string]bool{}
	for _, m := range matches {
		names[m.Pattern.Name] = true
	}
	assert.True(t, names["aws-access-key-id"], "hit after chunking")
	assert.True(t, names["spring-datasource-password"], "hit across chunks")
	assert.True(t, names["email-address"])
}

// TestScanStream_MatchAcrossBoundary verifies that a long token sitting
// exactly on the chunk boundary still ends up in the results exactly
// once. We craft a 200-char OpenAI-shaped key with the chunk boundary
// deliberately placed inside it.
func TestScanStream_MatchAcrossBoundary(t *testing.T) {
	// Real pattern length — approximate OpenAI project key shape.
	// Split-literal so GitHub push-protection doesn't flag a static
	// API-key shape in the source file.
	secret := "sk-" + strings.Repeat("a", 20) + "T3Blbk" + "FJ" + strings.Repeat("b", 20)
	// Use non-word bytes as padding so our `\b`-anchored patterns
	// treat the secret's start/end as word boundaries (Xs would not).
	prefix := bytes.Repeat([]byte("."), 100)
	corpus := append(append([]byte{}, prefix...), []byte(secret)...)
	corpus = append(corpus, bytes.Repeat([]byte("."), 100)...)

	data := bytesReaderAt(corpus)
	// Chunk size 120 → the secret straddles the 120-byte boundary.
	// Overlap 64 → a full pattern fits into the overlap window.
	matches, err := ScanStream(data, int64(len(corpus)), StreamOptions{
		ChunkSize:    120,
		OverlapBytes: 64,
	})
	require.NoError(t, err)

	var found bool
	for _, m := range matches {
		if m.Pattern.Name == "openai-key" && m.Value == secret {
			found = true
			assert.Equal(t, 1, m.Count, "dedup collapses the overlap duplicate")
			break
		}
	}
	assert.True(t, found, "boundary-straddling openai-key should be caught")
}

// TestScanStream_EmptyInput returns no matches and no error on zero bytes.
func TestScanStream_EmptyInput(t *testing.T) {
	matches, err := ScanStream(bytesReaderAt{}, 0, StreamOptions{})
	require.NoError(t, err)
	assert.Empty(t, matches)
}

// TestScanStream_EqualsInMemory: run the same corpus through Scan() and
// ScanStream() and compare. The streaming path must not silently drop
// matches that the in-memory path finds.
func TestScanStream_EqualsInMemory(t *testing.T) {
	// Build a corpus with six distinct matchable secrets.
	parts := [][]byte{
		[]byte("spring.datasource.password=One-Pass!\n"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"),
		[]byte("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n"),
		[]byte("email: alice@example.com\n"),
		[]byte("redis://cache.internal:6379/0\n"),
		[]byte("Authorization: Bearer opaque-session-token-abcdef1234567890\n"),
	}
	// Interleave with enough padding that chunk boundaries land on
	// different matches for each chunk size.
	var corpus []byte
	for _, p := range parts {
		corpus = append(corpus, bytes.Repeat([]byte("."), 50)...)
		corpus = append(corpus, p...)
		corpus = append(corpus, bytes.Repeat([]byte("."), 50)...)
	}

	memMatches, err := Scan(bytes.NewReader(corpus), Options{})
	require.NoError(t, err)
	streamMatches, err := ScanStream(bytesReaderAt(corpus), int64(len(corpus)), StreamOptions{
		ChunkSize:    80,
		OverlapBytes: 40,
	})
	require.NoError(t, err)

	memNames := patternNameSet(memMatches)
	streamNames := patternNameSet(streamMatches)
	assert.Equal(t, memNames, streamNames,
		"streaming scan should produce the same pattern set as the in-memory scan")
}

// TestShouldStream_ThresholdBoundary verifies the auto-select logic.
func TestShouldStream_ThresholdBoundary(t *testing.T) {
	assert.False(t, ShouldStream(100*1024*1024))
	assert.False(t, ShouldStream(DefaultStreamingThreshold-1))
	assert.True(t, ShouldStream(DefaultStreamingThreshold))
	assert.True(t, ShouldStream(5*1024*1024*1024)) // 5 GiB
}

// TestScanStream_ProgressCallback verifies we report progress at least
// once per chunk.
func TestScanStream_ProgressCallback(t *testing.T) {
	corpus := bytes.Repeat([]byte("x"), 1000)
	var calls int
	var lastDone int64
	_, err := ScanStream(bytesReaderAt(corpus), int64(len(corpus)), StreamOptions{
		ChunkSize:    100,
		OverlapBytes: 20,
		Progress: func(done, total int64) {
			calls++
			lastDone = done
			assert.Equal(t, int64(1000), total)
		},
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, calls, 10, "about one call per 100-byte chunk")
	assert.Equal(t, int64(1000), lastDone, "final progress reports full completion")
}

// patternNameSet collapses matches to the unique set of pattern names
// that fired. Helps stable assertions regardless of dedupe order.
func patternNameSet(ms []Match) map[string]bool {
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		out[m.Pattern.Name] = true
	}
	return out
}

// Silence unused-import warnings in trimmed-down variants of this file.
var _ = base64.StdEncoding
