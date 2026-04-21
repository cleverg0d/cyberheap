package hprof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func craftHeader(magic string, idSize uint32, ts time.Time) []byte {
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.BigEndian, idSize)
	ms := uint64(ts.UnixMilli())
	_ = binary.Write(&buf, binary.BigEndian, uint32(ms>>32))
	_ = binary.Write(&buf, binary.BigEndian, uint32(ms))
	return buf.Bytes()
}

func TestParseHeader_V102_ID8(t *testing.T) {
	ts := time.UnixMilli(1700000000000).UTC()
	raw := craftHeader("JAVA PROFILE 1.0.2", 8, ts)

	h, err := ParseHeader(bytes.NewReader(raw))
	require.NoError(t, err)
	assert.Equal(t, V1_0_2, h.Version)
	assert.Equal(t, 8, h.IDSize)
	assert.True(t, h.Timestamp.Equal(ts))
	assert.Equal(t, int64(len("JAVA PROFILE 1.0.2")+1+12), h.HeaderLen)
}

func TestParseHeader_V101_ID4(t *testing.T) {
	ts := time.UnixMilli(1234567890123).UTC()
	raw := craftHeader("JAVA PROFILE 1.0.1", 4, ts)

	h, err := ParseHeader(bytes.NewReader(raw))
	require.NoError(t, err)
	assert.Equal(t, V1_0_1, h.Version)
	assert.Equal(t, 4, h.IDSize)
	assert.True(t, h.Timestamp.Equal(ts))
}

func TestParseHeader_BadMagic(t *testing.T) {
	raw := craftHeader("HELLO WORLD", 8, time.Now())
	_, err := ParseHeader(bytes.NewReader(raw))
	assert.ErrorIs(t, err, ErrBadMagic)
}

func TestParseHeader_UnsupportedVersion(t *testing.T) {
	raw := craftHeader("JAVA PROFILE 1.0.3", 8, time.Now())
	_, err := ParseHeader(bytes.NewReader(raw))
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
}

func TestParseHeader_BadIDSize(t *testing.T) {
	raw := craftHeader("JAVA PROFILE 1.0.2", 16, time.Now())
	_, err := ParseHeader(bytes.NewReader(raw))
	assert.ErrorIs(t, err, ErrBadIDSize)
}

func TestParseHeader_TruncatedMagic(t *testing.T) {
	// No NUL, no trailing body.
	_, err := ParseHeader(bytes.NewReader([]byte("JAVA PROFILE 1.0.2")))
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF),
		"expected EOF-like error, got %v", err)
}

func TestParseHeader_NoNULReportsBadMagic(t *testing.T) {
	// 40 bytes without NUL — surfaced as ErrBadMagic, not ErrMagicTooLong,
	// because users see this when they point cyberheap at an unrelated file.
	raw := bytes.Repeat([]byte("A"), 40)
	_, err := ParseHeader(bytes.NewReader(raw))
	assert.ErrorIs(t, err, ErrBadMagic)
}

func TestParseHeader_RealFile(t *testing.T) {
	// Private fixture, excluded from VCS. Test is skipped on clean clones.
	path := filepath.Join("..", "..", ".claude", "fixtures", "example", "heapdump")
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("private heapdump fixture not available: %v", err)
	}
	defer f.Close()

	h, err := ParseHeader(f)
	require.NoError(t, err)
	assert.Equal(t, V1_0_2, h.Version)
	assert.Equal(t, 8, h.IDSize)
	assert.False(t, h.Timestamp.IsZero())
	t.Logf("real header: version=%s id=%d ts=%s headerLen=%d",
		h.Version, h.IDSize, h.Timestamp, h.HeaderLen)
}
