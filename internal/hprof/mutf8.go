package hprof

import "errors"

// DecodeModifiedUTF8 converts Java's "modified UTF-8" (as used in HPROF
// STRING_IN_UTF8 records and .class file constants) into a Go string.
//
// Differences from standard UTF-8:
//   - NUL (U+0000) is encoded as the two-byte sequence 0xC0 0x80, not 0x00.
//   - Code points above U+FFFF are encoded as a pair of three-byte surrogates
//     rather than a single four-byte sequence.
//
// We treat malformed sequences as literal bytes rather than failing — class
// names and field names are always pure ASCII in practice, and being lenient
// here avoids refusing to parse dumps over a rare corruption.
func DecodeModifiedUTF8(src []byte) (string, error) {
	// Fast path: ASCII-only input is common in HPROF (field/class names).
	ascii := true
	for _, b := range src {
		if b >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(src), nil
	}

	out := make([]rune, 0, len(src))
	for i := 0; i < len(src); {
		b := src[i]
		switch {
		case b&0x80 == 0:
			out = append(out, rune(b))
			i++
		case b&0xE0 == 0xC0:
			if i+1 >= len(src) {
				return string(out), errors.New("mutf8: truncated 2-byte sequence")
			}
			b2 := src[i+1]
			r := rune(b&0x1F)<<6 | rune(b2&0x3F)
			out = append(out, r)
			i += 2
		case b&0xF0 == 0xE0:
			if i+2 >= len(src) {
				return string(out), errors.New("mutf8: truncated 3-byte sequence")
			}
			b2, b3 := src[i+1], src[i+2]
			r := rune(b&0x0F)<<12 | rune(b2&0x3F)<<6 | rune(b3&0x3F)
			// Supplementary code points come as surrogate pairs: a high
			// surrogate (U+D800..U+DBFF) followed by a low one (U+DC00..U+DFFF).
			if r >= 0xD800 && r <= 0xDBFF && i+5 < len(src) {
				c2 := src[i+3]
				if c2&0xF0 == 0xE0 {
					b5, b6 := src[i+4], src[i+5]
					low := rune(c2&0x0F)<<12 | rune(b5&0x3F)<<6 | rune(b6&0x3F)
					if low >= 0xDC00 && low <= 0xDFFF {
						combined := 0x10000 + ((r - 0xD800) << 10) + (low - 0xDC00)
						out = append(out, combined)
						i += 6
						continue
					}
				}
			}
			out = append(out, r)
			i += 3
		default:
			// Lenient fallback: emit as-is and advance one byte.
			out = append(out, rune(b))
			i++
		}
	}
	return string(out), nil
}
