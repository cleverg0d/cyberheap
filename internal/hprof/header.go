package hprof

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"time"
)

// ParseHeaderFromBytes is a convenience wrapper around ParseHeader for
// callers that already have the whole file as a byte slice (typically
// from mmap). Keeps the zero-copy path from needing a bufio wrapper.
func ParseHeaderFromBytes(data []byte) (*Header, error) {
	return ParseHeader(bytes.NewReader(data))
}

const (
	magicPrefix   = "JAVA PROFILE 1.0."
	maxMagicBytes = 32
)

// ParseHeader reads and validates the HPROF file header from r.
//
// Layout:
//
//	magic string ("JAVA PROFILE 1.0.X"), NUL-terminated
//	u4  identifier size (4 or 8)
//	u4  timestamp high (ms since epoch)
//	u4  timestamp low  (ms since epoch)
func ParseHeader(r io.Reader) (*Header, error) {
	magic, err := readMagic(r)
	if err != nil {
		// Treat "no NUL in first 32 bytes" as "not a HPROF file" for UX —
		// a real HPROF header's magic string is at most 20 bytes.
		if err == ErrMagicTooLong {
			return nil, ErrBadMagic
		}
		return nil, err
	}

	if !strings.HasPrefix(magic, magicPrefix) {
		return nil, ErrBadMagic
	}
	suffix := magic[len(magicPrefix):]

	var version Version
	switch suffix {
	case "1":
		version = V1_0_1
	case "2":
		version = V1_0_2
	default:
		return nil, ErrUnsupportedVersion
	}

	var tail [12]byte
	if _, err := io.ReadFull(r, tail[:]); err != nil {
		return nil, err
	}

	idSize := int(binary.BigEndian.Uint32(tail[0:4]))
	if idSize != 4 && idSize != 8 {
		return nil, ErrBadIDSize
	}

	hi := uint64(binary.BigEndian.Uint32(tail[4:8]))
	lo := uint64(binary.BigEndian.Uint32(tail[8:12]))
	ms := int64(hi<<32 | lo)

	headerLen := int64(len(magic)) + 1 + 12

	return &Header{
		Version:   version,
		IDSize:    idSize,
		Timestamp: time.UnixMilli(ms).UTC(),
		HeaderLen: headerLen,
	}, nil
}

// readMagic consumes bytes up to and including the first NUL, returning the
// magic without the terminator. It reads at most maxMagicBytes to avoid
// running away on non-HPROF input.
func readMagic(r io.Reader) (string, error) {
	var buf [1]byte
	var sb strings.Builder
	for i := 0; i < maxMagicBytes; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		if buf[0] == 0x00 {
			return sb.String(), nil
		}
		sb.WriteByte(buf[0])
	}
	return "", ErrMagicTooLong
}
