package crypto_test

import (
	"encoding/binary"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

// TestFindKeyInBlob plants a known key inside a synthetic "exe blob" and verifies FindKey locates it.
func TestFindKeyInBlob(t *testing.T) {
	key := [4]uint32{0xdeadbeef, 0xcafebabe, 0x01234567, 0x89abcdef}

	// Create plaintext that will be encrypted with this key
	plain := [2]uint32{0x504B0304, 0x00000000} // "PK\x03\x04" ZIP magic as first block
	ct := crypto.XTEACipher(plain, key)

	// Build a synthetic ciphertext (8 bytes representing the first block of a pak)
	ctBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(ctBytes[0:], ct[0])
	binary.BigEndian.PutUint32(ctBytes[4:], ct[1])

	// Build a synthetic exe blob: padding + key bytes + more padding
	blob := make([]byte, 512)
	copy(blob[128:], keyToBytes(key))

	found := crypto.FindKey(blob, ctBytes, plain)
	if found == nil {
		t.Fatal("FindKey: key not found in blob")
	}
	if *found != key {
		t.Errorf("FindKey: got %v, want %v", found, key)
	}
}

func keyToBytes(key [4]uint32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], key[0])
	binary.LittleEndian.PutUint32(b[4:], key[1])
	binary.LittleEndian.PutUint32(b[8:], key[2])
	binary.LittleEndian.PutUint32(b[12:], key[3])
	return b
}
