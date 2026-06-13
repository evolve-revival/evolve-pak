package pak_test

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

// These are the decrypted Twofish keys for Scripts.pak, recovered via RSA in a prior session.
// They serve as a fixture so that CDR/file decryption tests don't require RSA.
var scriptsPakKeys = func() [16][16]byte {
	raw := [16]string{
		"ab1c7992a159745250ab867603100d1a",
		"b1f1a08ce1adbc20c3d84c0b8d4072d5",
		"84c2247093abde804f63217ef18ff63b",
		"32e575dd56fc438e25c70264b9a706e6",
		"234d6c0b2685bd6e38f18026e30a4760",
		"5d3e0cd1f647deea8825e483b98f02d8",
		"f9a521e6d105042825a165e0192a05da",
		"76554f96092c984810a4980c569f2f43",
		"da470790bed1b3ea0958883bc26f15f6",
		"0bc49e305f1cab0813e5f29fd892303a",
		"678adcaf2d048cc46e5d2530a255620f",
		"bca0ceecdd27060b6fe751e421da4158",
		"1af8cebe1b759b64218eaa0f62aa9cfa",
		"447db865a12198aa7d5d0a8f1fa96ae7",
		"c307ab3e6652eecba7a649ed5d733559",
		"d0530197a06078025e600fc423a40e57",
	}
	var keys [16][16]byte
	for i, s := range raw {
		b, _ := hex.DecodeString(s)
		copy(keys[i][:], b)
	}
	return keys
}()

var scriptsPakCDRIV = func() [16]byte {
	b, _ := hex.DecodeString("28a1717f9af77108936c5de0d965d11d")
	var iv [16]byte
	copy(iv[:], b)
	return iv
}()

const scriptsPakPath = "/home/navitank/Desktop/EvolveFilesLegacy/Game/Scripts.pak"

func skipIfMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("test file not found: %s", path)
	}
}

func TestOpenWithKeys_CDR(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	r, err := pak.OpenWithKeys(scriptsPakPath, scriptsPakKeys, scriptsPakCDRIV)
	if err != nil {
		t.Fatalf("OpenWithKeys: %v", err)
	}

	if len(r.Entries) != 757 {
		t.Errorf("expected 757 entries, got %d", len(r.Entries))
	}

	// Spot-check first entry matches PakDecrypt output.
	e := r.Entries[0]
	if e.Name != "Entities/AdvancedDoor.ent" {
		t.Errorf("entries[0].Name = %q, want %q", e.Name, "Entities/AdvancedDoor.ent")
	}
	if e.CRC != 0x3d4ef380 {
		t.Errorf("entries[0].CRC = 0x%08x, want 0x3d4ef380", e.CRC)
	}
	if e.CompressedSize != 101 {
		t.Errorf("entries[0].CompressedSize = %d, want 101", e.CompressedSize)
	}
	if e.UncompressedSize != 161 {
		t.Errorf("entries[0].UncompressedSize = %d, want 161", e.UncompressedSize)
	}
}

func TestExtract_AllEntries(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	r, err := pak.OpenWithKeys(scriptsPakPath, scriptsPakKeys, scriptsPakCDRIV)
	if err != nil {
		t.Fatalf("OpenWithKeys: %v", err)
	}

	for i, e := range r.Entries {
		data, err := r.Extract(e)
		if err != nil {
			t.Errorf("entries[%d] %s: %v", i, e.Name, err)
			continue
		}
		if uint32(len(data)) != e.UncompressedSize {
			t.Errorf("entries[%d] %s: got %d bytes, want %d", i, e.Name, len(data), e.UncompressedSize)
		}
	}
}

func TestExtract_FirstEntry(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	r, err := pak.OpenWithKeys(scriptsPakPath, scriptsPakKeys, scriptsPakCDRIV)
	if err != nil {
		t.Fatalf("OpenWithKeys: %v", err)
	}

	data, err := r.Extract(r.Entries[0])
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(data) != 161 {
		t.Errorf("got %d bytes, want 161", len(data))
	}

	// PakDecrypt output: first 8 bytes = 437279586d6c4200 = "CryXmlB\x00"
	wantPrefix, _ := hex.DecodeString("437279586d6c4200")
	if len(data) >= len(wantPrefix) {
		got := data[:len(wantPrefix)]
		for i := range wantPrefix {
			if got[i] != wantPrefix[i] {
				t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, got[i], wantPrefix[i])
			}
		}
	}
}
