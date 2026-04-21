package hprof

import "time"

type Version int

const (
	V1_0_1 Version = 1
	V1_0_2 Version = 2
)

func (v Version) String() string {
	switch v {
	case V1_0_1:
		return "1.0.1"
	case V1_0_2:
		return "1.0.2"
	default:
		return "unknown"
	}
}

type Header struct {
	Version   Version
	IDSize    int
	Timestamp time.Time
	HeaderLen int64
}
