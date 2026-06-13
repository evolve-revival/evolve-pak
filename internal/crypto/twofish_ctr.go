package crypto

import (
	"fmt"

	"golang.org/x/crypto/twofish"
)

// TwofishCTR decrypts (or encrypts — CTR is symmetric) src using Twofish in
// CTR mode with a little-endian 128-bit counter.  iv is the initial counter
// value (16 bytes).  Returns a new slice; src is not modified.
func TwofishCTR(key, iv, src []byte) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("twofish init: %w", err)
	}

	var ctr [16]byte
	copy(ctr[:], iv)

	dst := make([]byte, len(src))
	var ks [16]byte

	for i := 0; i < len(src); {
		block.Encrypt(ks[:], ctr[:])
		ctrIncrLE(&ctr)

		end := i + 16
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ ks[j-i]
		}
		i = end
	}
	return dst, nil
}

// ctrIncrLE increments a 128-bit little-endian counter in place.
func ctrIncrLE(ctr *[16]byte) {
	for i := 0; i < 16; i++ {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
}
