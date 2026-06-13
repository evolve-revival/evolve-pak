package crypto

import "encoding/binary"

const xteaRounds = 32
const xteaDelta = 0x9E3779B9

// XTEACipher encrypts a single 64-bit block (as two uint32) with key.
func XTEACipher(v [2]uint32, key [4]uint32) [2]uint32 {
	v0, v1 := v[0], v[1]
	var sum uint32
	for i := 0; i < xteaRounds; i++ {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
		sum += xteaDelta
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
	}
	return [2]uint32{v0, v1}
}

// XTEADecipher decrypts a single 64-bit block.
func XTEADecipher(v [2]uint32, key [4]uint32) [2]uint32 {
	v0, v1 := v[0], v[1]
	sum := uint32(0xc6ef3720) // xteaDelta * xteaRounds wrapped to uint32
	for i := 0; i < xteaRounds; i++ {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
		sum -= xteaDelta
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
	}
	return [2]uint32{v0, v1}
}

// EncryptXTEA encrypts src in-place in ECB mode (8-byte blocks). len(src) must be a multiple of 8.
func EncryptXTEA(src []byte, key [4]uint32) []byte {
	for i := 0; i+8 <= len(src); i += 8 {
		v0 := binary.BigEndian.Uint32(src[i:])
		v1 := binary.BigEndian.Uint32(src[i+4:])
		out := XTEACipher([2]uint32{v0, v1}, key)
		binary.BigEndian.PutUint32(src[i:], out[0])
		binary.BigEndian.PutUint32(src[i+4:], out[1])
	}
	return src
}

// DecryptXTEA decrypts src in-place in ECB mode. len(src) must be a multiple of 8.
func DecryptXTEA(src []byte, key [4]uint32) []byte {
	for i := 0; i+8 <= len(src); i += 8 {
		v0 := binary.BigEndian.Uint32(src[i:])
		v1 := binary.BigEndian.Uint32(src[i+4:])
		out := XTEADecipher([2]uint32{v0, v1}, key)
		binary.BigEndian.PutUint32(src[i:], out[0])
		binary.BigEndian.PutUint32(src[i+4:], out[1])
	}
	return src
}
