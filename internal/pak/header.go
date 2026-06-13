package pak

import (
	"encoding/binary"
	"fmt"
)

type MagicVariant int

const (
	MagicVariantA MagicVariant = iota // ef 4d e5 06
	MagicVariantB                     // 7d 37 21 fb
)

var magicA = [4]byte{0xef, 0x4d, 0xe5, 0x06}
var magicB = [4]byte{0x7d, 0x37, 0x21, 0xfb}

// Header holds the decoded CryPak custom prefix.
type Header struct {
	Magic     MagicVariant
	ZipOffset uint32 // byte offset in the file where ZIP data begins
	Raw       []byte // original header bytes
}

// ParseHeader decodes the custom header from the first bytes of a pak file.
// Minimum input length: 8 bytes (4 magic + 4 offset).
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("too short: need 8 bytes, got %d", len(data))
	}
	var m MagicVariant
	switch [4]byte(data[:4]) {
	case magicA:
		m = MagicVariantA
	case magicB:
		m = MagicVariantB
	default:
		return nil, fmt.Errorf("unknown magic: %02x %02x %02x %02x", data[0], data[1], data[2], data[3])
	}
	offset := binary.LittleEndian.Uint32(data[4:8])
	return &Header{Magic: m, ZipOffset: offset, Raw: data[:8]}, nil
}
