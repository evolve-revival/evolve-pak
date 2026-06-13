package crypto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
)

// RSAPublicDecryptOAEP performs the non-standard CryEngine RSA operation:
//   m = c^e mod n  (raw public-key modexp, not PKCS#1 v1.5 or OAEP decrypt)
//
// followed by OAEP-SHA256 decode to recover the 16-byte Twofish key.
//
// derKey is a DER-encoded PKIX RSA public key (140 bytes for the vanilla key).
// ctBlock is a 128-byte RSA ciphertext block from the EOCD comment.
func RSAPublicDecryptOAEP(derKey, ctBlock []byte) ([]byte, error) {
	// The RSAKeyData.bin key is DER-encoded in PKCS#1 format (RSAPublicKey),
	// not PKIX/SPKI (SubjectPublicKeyInfo). Use ParsePKCS1PublicKey.
	rsaPub, err := x509.ParsePKCS1PublicKey(derKey)
	if err != nil {
		return nil, errors.New("RSA: parse public key: " + err.Error())
	}

	n := rsaPub.N
	e := rsaPub.E

	// Raw RSA: m = c^e mod n  (public-key operation, recovers the OAEP-encoded message).
	c := new(big.Int).SetBytes(ctBlock)
	eInt := new(big.Int).SetInt64(int64(e))
	m := new(big.Int).Exp(c, eInt, n)

	// Pad to key size (128 bytes for a 1024-bit key).
	modLen := (n.BitLen() + 7) / 8
	raw := make([]byte, modLen)
	mBytes := m.Bytes()
	if len(mBytes) > modLen {
		return nil, errors.New("RSA: result larger than modulus")
	}
	copy(raw[modLen-len(mBytes):], mBytes)

	return oaepSHA256Decode(raw)
}

// oaepSHA256Decode recovers the message from an OAEP-SHA256 encoded block.
// em is modLen bytes (128 for 1024-bit RSA).
// Returns the unpadded plaintext (16 bytes for a Twofish key).
func oaepSHA256Decode(em []byte) ([]byte, error) {
	const hLen = sha256.Size // 32

	if len(em) < 2*hLen+2 {
		return nil, errors.New("OAEP: message too short")
	}
	if em[0] != 0x00 {
		return nil, errors.New("OAEP: first byte is not 0x00")
	}

	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]

	// Recover seed.
	seedMask := mgf1SHA256(maskedDB, hLen)
	seed := make([]byte, hLen)
	for i := range seed {
		seed[i] = maskedSeed[i] ^ seedMask[i]
	}

	// Recover DB.
	dbMask := mgf1SHA256(seed, len(maskedDB))
	db := make([]byte, len(maskedDB))
	for i := range db {
		db[i] = maskedDB[i] ^ dbMask[i]
	}

	// Verify pHash = SHA256("") for empty OAEP label.
	pHash := sha256.Sum256(nil)
	for i := 0; i < hLen; i++ {
		if db[i] != pHash[i] {
			return nil, errors.New("OAEP: pHash mismatch")
		}
	}

	// Find 0x01 separator after padding zeros.
	i := hLen
	for i < len(db) && db[i] == 0x00 {
		i++
	}
	if i >= len(db) || db[i] != 0x01 {
		return nil, errors.New("OAEP: no 0x01 separator")
	}

	return db[i+1:], nil
}

// mgf1SHA256 is MGF1 with SHA-256 as the hash function (RFC 8017 §B.2.1).
func mgf1SHA256(seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	var counter uint32
	for len(out) < length {
		h := sha256.New()
		h.Write(seed)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h.Write(ctr[:])
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:length]
}
