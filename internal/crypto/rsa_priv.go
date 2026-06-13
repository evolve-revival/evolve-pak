package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
)

// RSAPrivateEncryptOAEP is the mirror of RSAPublicDecryptOAEP.
// It OAEP-SHA256 encodes plaintext (typically 16 bytes; max modLen−2·hLen−2) into a
// 128-byte block, then computes c = m^d mod n using the RSA-1024 private key.
// This is the operation used by CryEngine's internal pak-build tools to
// protect each Twofish key in the EOCD comment.
func RSAPrivateEncryptOAEP(privKeyDER, plaintext []byte) ([]byte, error) {
	priv, err := x509.ParsePKCS1PrivateKey(privKeyDER)
	if err != nil {
		return nil, errors.New("RSA private: parse key: " + err.Error())
	}

	modLen := (priv.N.BitLen() + 7) / 8 // 128 for RSA-1024

	em, err := oaepSHA256Encode(plaintext, modLen)
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, priv.D, priv.N)

	out := make([]byte, modLen)
	cBytes := c.Bytes()
	if len(cBytes) > modLen {
		return nil, errors.New("RSA private: result larger than modulus")
	}
	copy(out[modLen-len(cBytes):], cBytes)
	return out, nil
}

// oaepSHA256Encode encodes msg into a modLen-byte OAEP block (RFC 8017 §7.1.1).
// msg must be ≤ modLen - 2*hLen - 2 bytes (for 128-byte modulus and SHA-256: ≤ 62 bytes).
func oaepSHA256Encode(msg []byte, modLen int) ([]byte, error) {
	const hLen = sha256.Size // 32

	maxMsgLen := modLen - 2*hLen - 2
	if len(msg) > maxMsgLen {
		return nil, errors.New("OAEP encode: message too long")
	}

	// lHash = SHA256("") — empty label
	lHash := sha256.Sum256(nil)

	// DB = lHash || PS (zero padding) || 0x01 || msg
	dbLen := modLen - hLen - 1 // 95 bytes for 128-byte modulus
	db := make([]byte, dbLen)
	copy(db[0:], lHash[:])
	// db[hLen : hLen+psLen] are already zero
	psLen := dbLen - hLen - 1 - len(msg)
	db[hLen+psLen] = 0x01
	copy(db[hLen+psLen+1:], msg)

	// Random seed
	seed := make([]byte, hLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, errors.New("OAEP encode: rand: " + err.Error())
	}

	dbMask := mgf1SHA256(seed, dbLen)
	maskedDB := make([]byte, dbLen)
	for i := range db {
		maskedDB[i] = db[i] ^ dbMask[i]
	}

	seedMask := mgf1SHA256(maskedDB, hLen)
	maskedSeed := make([]byte, hLen)
	for i := range seed {
		maskedSeed[i] = seed[i] ^ seedMask[i]
	}

	em := make([]byte, modLen)
	em[0] = 0x00
	copy(em[1:], maskedSeed)
	copy(em[1+hLen:], maskedDB)
	return em, nil
}
