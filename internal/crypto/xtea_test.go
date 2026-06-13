package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

// XTEA test vectors from https://en.wikipedia.org/wiki/XTEA
func TestXTEADecipherZeroBlock(t *testing.T) {
	// key = 00000000 00000000 00000000 00000000
	// plaintext = 0000000000000000
	// ciphertext (32 rounds) = dee9d4d8f7131ed9
	key := [4]uint32{0, 0, 0, 0}
	ct, _ := hex.DecodeString("dee9d4d8f7131ed9")
	block := [2]uint32{
		uint32(ct[0])<<24 | uint32(ct[1])<<16 | uint32(ct[2])<<8 | uint32(ct[3]),
		uint32(ct[4])<<24 | uint32(ct[5])<<16 | uint32(ct[6])<<8 | uint32(ct[7]),
	}
	got := crypto.XTEADecipher(block, key)
	if got[0] != 0 || got[1] != 0 {
		t.Errorf("XTEADecipher zero vector: got %08x %08x, want 00000000 00000000", got[0], got[1])
	}
}

func TestXTEARoundTrip(t *testing.T) {
	key := [4]uint32{0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210}
	plaintext := [2]uint32{0xdeadbeef, 0xcafebabe}
	ct := crypto.XTEACipher(plaintext, key)
	pt := crypto.XTEADecipher(ct, key)
	if pt != plaintext {
		t.Errorf("round-trip failed: got %08x %08x", pt[0], pt[1])
	}
}

func TestXTEADecryptSlice(t *testing.T) {
	key := [4]uint32{1, 2, 3, 4}
	plain := []byte("hello world12345") // 16 bytes = 2 XTEA blocks
	enc := crypto.EncryptXTEA(bytes.Clone(plain), key)
	dec := crypto.DecryptXTEA(enc, key)
	if !bytes.Equal(dec, plain) {
		t.Errorf("DecryptXTEA: got %q, want %q", dec, plain)
	}
}
