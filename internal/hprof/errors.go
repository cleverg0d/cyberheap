package hprof

import "errors"

var (
	ErrBadMagic           = errors.New("hprof: not an HPROF file (bad magic)")
	ErrUnsupportedVersion = errors.New("hprof: unsupported format version")
	ErrBadIDSize          = errors.New("hprof: unsupported identifier size (expected 4 or 8)")
	ErrMagicTooLong       = errors.New("hprof: magic string not terminated within 32 bytes")
)
