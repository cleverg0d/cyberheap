package hprof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeModifiedUTF8_ASCII(t *testing.T) {
	s, err := DecodeModifiedUTF8([]byte("java/lang/String"))
	require.NoError(t, err)
	assert.Equal(t, "java/lang/String", s)
}

func TestDecodeModifiedUTF8_NullAsC080(t *testing.T) {
	// Java encodes U+0000 as two bytes 0xC0 0x80 rather than a raw 0x00.
	s, err := DecodeModifiedUTF8([]byte{0x41, 0xC0, 0x80, 0x42})
	require.NoError(t, err)
	assert.Equal(t, "A\x00B", s)
}

func TestDecodeModifiedUTF8_Multibyte(t *testing.T) {
	// U+00E9 "é" = 0xC3 0xA9 in both standard and modified UTF-8.
	s, err := DecodeModifiedUTF8([]byte{0x63, 0xC3, 0xA9, 0x2E})
	require.NoError(t, err)
	assert.Equal(t, "cé.", s)
}

func TestDecodeModifiedUTF8_SurrogatePair(t *testing.T) {
	// U+1F600 🙂-adjacent "GRINNING FACE" encoded as surrogate pair under mUTF-8:
	// High D83D = 0xED 0xA0 0xBD, Low DE00 = 0xED 0xB8 0x80.
	raw := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}
	s, err := DecodeModifiedUTF8(raw)
	require.NoError(t, err)
	assert.Equal(t, "\U0001F600", s)
}
