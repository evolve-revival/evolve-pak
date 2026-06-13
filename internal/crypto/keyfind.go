package crypto

import (
	"encoding/binary"
)

// FindKey scans blob (word-aligned, 4-byte steps) for a 16-byte XTEA key that decrypts
// cipherBlock into an expected plaintext block.
//
// cipherBlock: 8 bytes (first XTEA block of the pak file, starting at byte 0).
// expected: the [2]uint32 we expect after decryption.
// Block words are read as BigEndian; key words are read as LittleEndian (Windows x64 native).
// Requires both plaintext words to match.
//
// Returns nil if no key found.
func FindKey(blob []byte, cipherBlock []byte, expected [2]uint32) *[4]uint32 {
	return findKey(blob, cipherBlock, expected, false, true, true)
}

// FindKeyOpts is the extended version allowing endianness and match-mode control.
//
// blockLE: if true, reads cipherBlock words as LittleEndian; if false, BigEndian.
// keyLE: if true, reads key words as LittleEndian; if false, BigEndian.
// matchBothWords: if true, require both pt[0]==expected[0] AND pt[1]==expected[1];
//
//	if false, require only pt[0]==expected[0] (relaxed, avoids guessing bytes 4-7).
func FindKeyOpts(blob []byte, cipherBlock []byte, expected [2]uint32, blockLE bool, keyLE bool, matchBothWords bool) *[4]uint32 {
	return findKey(blob, cipherBlock, expected, blockLE, keyLE, matchBothWords)
}

func findKey(blob []byte, cipherBlock []byte, expected [2]uint32, blockLE bool, keyLE bool, matchBothWords bool) *[4]uint32 {
	if len(cipherBlock) < 8 {
		return nil
	}
	var ct [2]uint32
	if blockLE {
		ct = [2]uint32{
			binary.LittleEndian.Uint32(cipherBlock[0:]),
			binary.LittleEndian.Uint32(cipherBlock[4:]),
		}
	} else {
		ct = [2]uint32{
			binary.BigEndian.Uint32(cipherBlock[0:]),
			binary.BigEndian.Uint32(cipherBlock[4:]),
		}
	}
	for i := 0; i+16 <= len(blob); i += 4 {
		var k [4]uint32
		if keyLE {
			k = [4]uint32{
				binary.LittleEndian.Uint32(blob[i:]),
				binary.LittleEndian.Uint32(blob[i+4:]),
				binary.LittleEndian.Uint32(blob[i+8:]),
				binary.LittleEndian.Uint32(blob[i+12:]),
			}
		} else {
			k = [4]uint32{
				binary.BigEndian.Uint32(blob[i:]),
				binary.BigEndian.Uint32(blob[i+4:]),
				binary.BigEndian.Uint32(blob[i+8:]),
				binary.BigEndian.Uint32(blob[i+12:]),
			}
		}
		pt := XTEADecipher(ct, k)
		if matchBothWords {
			if pt == expected {
				result := k
				return &result
			}
		} else {
			if pt[0] == expected[0] {
				result := k
				return &result
			}
		}
	}
	return nil
}
