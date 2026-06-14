package pak

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

// vanillaRSAKey is the DER-encoded RSA-1024 public key for vanilla Evolve paks.
// Source: RSAKeyData.bin from PakDecrypter.zip (EvolveUnpaker project).
var vanillaRSAKey, _ = hex.DecodeString(
	"30818902818100a2d11f0c51fa6b451d7e05fe3f06725610" +
		"a9a77b674fb665f4a12bcf07cd944f6ebf9df30fcc7b63eb" +
		"3da5e659523aa7d854ac389d5922693bba599e82951272d7" +
		"1f1f55434b7bbc9cdde60507714ce53d8411f91ab0c12490" +
		"5ade7b249e988606351aef2c59f5f4ca28ca3c7acbe77aa5" +
		"5691e0984e16433624a15be375b0530203010001",
)

// EOCD comment layout for CryEngine paks (all offsets within the 2320-byte comment):
//
//	[0:6]      CryEngineExtendedHeader (6 bytes): [uint32 size=6][uint8 encType=1][uint8 sigType=3]
//	[6:139]    CryEngineSigningHeader (133 bytes)
//	[139:2320] CryEngineEncryptionHeader (2181 bytes):
//	             [139:143] uint32 headerSize = 2181
//	             [143:271] IV_encrypted (128-byte RSA ciphertext)
//	             [271]     1 padding byte
//	             [272:400] keys_encrypted[0] (128-byte RSA ciphertext)
//	             [272+i*128 : 272+(i+1)*128] keys_encrypted[i] for i=0..15
const (
	encHeaderOff = 139
	ivEncOff     = encHeaderOff + 4  // 143
	keyEncOff    = ivEncOff + 128 + 1 // 272 (IV block + 1 pad byte)
	keyStride    = 128
	numKeys      = 16
)

// KeyRing holds the 16 Twofish keys and CDR IV decrypted from a pak's EOCD comment.
type KeyRing struct {
	Keys  [numKeys][16]byte
	CDRIV [16]byte
}

// DecryptEOCDComment parses the 2320-byte EOCD comment and decrypts the key
// table using the embedded vanilla RSA public key.
// Pass an optional overrideKey (DER bytes) to use a different RSA key.
func DecryptEOCDComment(comment, overrideKey []byte) (*KeyRing, error) {
	if len(comment) != 2320 {
		return nil, fmt.Errorf("EOCD comment: expected 2320 bytes, got %d", len(comment))
	}

	encType := comment[4]
	sigType := comment[5]
	if encType != 1 {
		return nil, fmt.Errorf("unexpected encType %d (want 1=Twofish)", encType)
	}
	if sigType != 3 {
		return nil, fmt.Errorf("unexpected sigType %d (want 3=RSA)", sigType)
	}

	encHeaderSize := binary.LittleEndian.Uint32(comment[encHeaderOff:])
	if encHeaderSize != 2181 {
		return nil, fmt.Errorf("unexpected encHeaderSize %d (want 2181)", encHeaderSize)
	}

	keys := [][]byte{vanillaRSAKey}
	if len(overrideKey) > 0 {
		keys = append([][]byte{overrideKey}, keys...)
	}

	for _, derKey := range keys {
		kr, err := decryptKeyTable(comment, derKey)
		if err == nil {
			return kr, nil
		}
	}

	return nil, errors.New("EOCD: RSA+OAEP decode failed with all available keys")
}

// RekeyEOCDComment decrypts the key table from the 2320-byte EOCD comment
// using srcPubDER (pass nil to use the embedded vanilla RSA public key), then
// re-encrypts it using dstPrivDER (PKCS#1 DER RSA-1024 private key). Returns
// a new 2320-byte EOCD comment suitable for writing back over the tail of the
// pak file.
//
// Only the EOCD comment changes; LFHs, entry data, and the CDR are untouched.
func RekeyEOCDComment(comment, srcPubDER, dstPrivDER []byte) ([]byte, error) {
	kr, err := DecryptEOCDComment(comment, srcPubDER)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return buildEOCDComment(dstPrivDER, kr.Keys, kr.CDRIV)
}

func decryptKeyTable(comment, derKey []byte) (*KeyRing, error) {
	ivBlock := comment[ivEncOff : ivEncOff+128]
	ivPlain, err := crypto.RSAPublicDecryptOAEP(derKey, ivBlock)
	if err != nil {
		return nil, fmt.Errorf("IV: %w", err)
	}
	if len(ivPlain) != 16 {
		return nil, fmt.Errorf("IV: expected 16 bytes, got %d", len(ivPlain))
	}

	var kr KeyRing
	copy(kr.CDRIV[:], ivPlain)

	for i := 0; i < numKeys; i++ {
		off := keyEncOff + i*keyStride
		keyBlock := comment[off : off+128]
		keyPlain, err := crypto.RSAPublicDecryptOAEP(derKey, keyBlock)
		if err != nil {
			return nil, fmt.Errorf("key[%d]: %w", i, err)
		}
		if len(keyPlain) != 16 {
			return nil, fmt.Errorf("key[%d]: expected 16 bytes, got %d", i, len(keyPlain))
		}
		copy(kr.Keys[i][:], keyPlain)
	}

	return &kr, nil
}
