package hprof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Record is a lightweight view over one top-level HPROF record.
// Body is a slice pointing into an internally-managed buffer; it is only
// valid until the next call to the iterating Next/Walk. Copy if you need
// to retain it.
type Record struct {
	Tag      Tag
	TimeDiff uint32 // microseconds since header
	Offset   int64  // absolute byte offset of this record's header
	Body     []byte
}

// Reader iterates top-level records of an HPROF file.
// It does not interpret record bodies — use the specialized helpers
// (ParseString, ParseLoadClass, WalkHeapDump) on the returned slice.
type Reader struct {
	r       io.Reader
	Header  *Header
	offset  int64 // running byte offset, used for Record.Offset
	buf     []byte
	errSeen error
}

// NewReader parses the header and returns a Reader positioned at the
// first record. The caller keeps ownership of r; reading past the final
// record yields io.EOF.
func NewReader(r io.Reader) (*Reader, error) {
	h, err := ParseHeader(r)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, Header: h, offset: h.HeaderLen, buf: make([]byte, 0, 4096)}, nil
}

// Next reads the next record header and body. The returned Record.Body
// slice is only valid until the next call.
func (rd *Reader) Next() (*Record, error) {
	if rd.errSeen != nil {
		return nil, rd.errSeen
	}
	var head [9]byte
	n, err := io.ReadFull(rd.r, head[:])
	if err == io.EOF {
		rd.errSeen = io.EOF
		return nil, io.EOF
	}
	if err == io.ErrUnexpectedEOF && n == 0 {
		rd.errSeen = io.EOF
		return nil, io.EOF
	}
	if err != nil {
		rd.errSeen = err
		return nil, err
	}

	tag := Tag(head[0])
	td := binary.BigEndian.Uint32(head[1:5])
	length := binary.BigEndian.Uint32(head[5:9])

	rec := &Record{Tag: tag, TimeDiff: td, Offset: rd.offset}
	rd.offset += 9

	if cap(rd.buf) < int(length) {
		rd.buf = make([]byte, length)
	} else {
		rd.buf = rd.buf[:length]
	}
	if _, err := io.ReadFull(rd.r, rd.buf); err != nil {
		rd.errSeen = err
		return rec, err
	}
	rec.Body = rd.buf
	rd.offset += int64(length)
	return rec, nil
}

// ParseString interprets a STRING_IN_UTF8 record body.
// Layout: id (idSize bytes) + modified-UTF-8 bytes.
func ParseString(body []byte, idSize int) (id uint64, text string, err error) {
	if len(body) < idSize {
		return 0, "", errors.New("hprof: STRING_IN_UTF8 record too short")
	}
	id = readID(body[:idSize], idSize)
	text, err = DecodeModifiedUTF8(body[idSize:])
	return
}

// LoadClass is the payload of a LOAD_CLASS record.
type LoadClass struct {
	ClassSerial       uint32
	ClassObjectID     uint64
	StackTraceSerial  uint32
	ClassNameStringID uint64
}

// ParseLoadClass decodes a LOAD_CLASS record.
// Layout: classSerial u4, classObjectID id, stackTraceSerial u4, classNameStringID id.
func ParseLoadClass(body []byte, idSize int) (LoadClass, error) {
	needed := 4 + idSize + 4 + idSize
	if len(body) < needed {
		return LoadClass{}, fmt.Errorf("hprof: LOAD_CLASS body too short (%d < %d)", len(body), needed)
	}
	off := 0
	lc := LoadClass{}
	lc.ClassSerial = binary.BigEndian.Uint32(body[off:])
	off += 4
	lc.ClassObjectID = readID(body[off:off+idSize], idSize)
	off += idSize
	lc.StackTraceSerial = binary.BigEndian.Uint32(body[off:])
	off += 4
	lc.ClassNameStringID = readID(body[off:off+idSize], idSize)
	return lc, nil
}

// readID reads a 4- or 8-byte big-endian identifier. HPROF uses a single
// uniform ID size for the whole file, declared in the header.
func readID(b []byte, size int) uint64 {
	switch size {
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	}
	return 0
}
