package pak_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

// MagicA is the primary CryPak magic observed in Evolve pak files.
var MagicA = []byte{0xef, 0x4d, 0xe5, 0x06}

func makeFakePakHeader(magic []byte, zipOffset uint32) []byte {
	buf := &bytes.Buffer{}
	buf.Write(magic)
	// 4-byte field: offset to start of ZIP data
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], zipOffset)
	buf.Write(b[:])
	return buf.Bytes()
}

func TestParseHeaderMagicA(t *testing.T) {
	raw := makeFakePakHeader(MagicA, 16)
	h, err := pak.ParseHeader(raw)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Magic != pak.MagicVariantA {
		t.Errorf("Magic = %d, want MagicVariantA", h.Magic)
	}
	if h.ZipOffset != 16 {
		t.Errorf("ZipOffset = %d, want 16", h.ZipOffset)
	}
}

func TestParseHeaderUnknownMagic(t *testing.T) {
	raw := makeFakePakHeader([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 0)
	_, err := pak.ParseHeader(raw)
	if err == nil {
		t.Fatal("expected error for unknown magic, got nil")
	}
}
