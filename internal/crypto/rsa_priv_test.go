package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

func TestRSAPrivateEncryptOAEPRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	pubDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)

	plaintext := []byte("0123456789abcdef") // 16 bytes — one Twofish key

	ct, err := crypto.RSAPrivateEncryptOAEP(privDER, plaintext)
	if err != nil {
		t.Fatalf("RSAPrivateEncryptOAEP: %v", err)
	}
	if len(ct) != 128 {
		t.Fatalf("ciphertext: got %d bytes, want 128", len(ct))
	}

	// Decrypt with public key (existing function — mirrors the game's runtime path)
	recovered, err := crypto.RSAPublicDecryptOAEP(pubDER, ct)
	if err != nil {
		t.Fatalf("RSAPublicDecryptOAEP: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("round-trip: got %q, want %q", recovered, plaintext)
	}
}

func TestRSAPrivateEncryptOAEPDifferentEachCall(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	plain := []byte("0123456789abcdef")

	ct1, err := crypto.RSAPrivateEncryptOAEP(privDER, plain)
	if err != nil {
		t.Fatalf("first RSAPrivateEncryptOAEP: %v", err)
	}
	ct2, err := crypto.RSAPrivateEncryptOAEP(privDER, plain)
	if err != nil {
		t.Fatalf("second RSAPrivateEncryptOAEP: %v", err)
	}

	// OAEP uses a random seed — two encryptions of the same plaintext must differ
	same := true
	for i := range ct1 {
		if ct1[i] != ct2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two RSAPrivateEncryptOAEP calls produced identical ciphertext (random seed broken)")
	}
}
