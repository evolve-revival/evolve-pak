package pak_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

// TestRekeyEOCDComment_Synthetic verifies rekey with two freshly-generated RSA keys.
// After rekeying, the pak opens with keyB and is rejected by keyA.
func TestRekeyEOCDComment_Synthetic(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	privA := x509.MarshalPKCS1PrivateKey(keyA)
	pubA := x509.MarshalPKCS1PublicKey(&keyA.PublicKey)
	privB := x509.MarshalPKCS1PrivateKey(keyB)
	pubB := x509.MarshalPKCS1PublicKey(&keyB.PublicKey)

	// Pack a small test dir signed with keyA.
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("hello revival"), 0o644); err != nil {
		t.Fatal(err)
	}
	origPak := filepath.Join(t.TempDir(), "original.pak")
	if _, err := pak.Pack(srcDir, origPak, privA); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if _, err := pak.Open(origPak, pubA); err != nil {
		t.Fatalf("Open with keyA before rekey: %v", err)
	}

	// Read the EOCD comment, rekey with keyB.
	fi, _ := os.Stat(origPak)
	f, err := os.Open(origPak)
	if err != nil {
		t.Fatal(err)
	}
	comment := make([]byte, 2320)
	_, err = f.ReadAt(comment, fi.Size()-2320)
	f.Close()
	if err != nil {
		t.Fatalf("read comment: %v", err)
	}
	newComment, err := pak.RekeyEOCDComment(comment, pubA, privB)
	if err != nil {
		t.Fatalf("RekeyEOCDComment: %v", err)
	}

	// Write newComment into a copy of the pak.
	data, _ := os.ReadFile(origPak)
	copy(data[len(data)-2320:], newComment)
	rekeyedPak := filepath.Join(t.TempDir(), "rekeyed.pak")
	if err := os.WriteFile(rekeyedPak, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Must open with keyB.
	r, err := pak.Open(rekeyedPak, pubB)
	if err != nil {
		t.Fatalf("Open rekeyed pak with keyB: %v", err)
	}
	if len(r.Entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(r.Entries))
	}
	got, err := r.Extract(r.Entries[0])
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if string(got) != "hello revival" {
		t.Errorf("content mismatch: got %q, want %q", got, "hello revival")
	}

	// Must NOT open with keyA (neither keyA nor vanilla matches keyB-signed EOCD).
	if _, err := pak.Open(rekeyedPak, pubA); err == nil {
		t.Error("Open rekeyed pak with wrong key should fail but succeeded")
	}
}

// TestRekeyEOCDComment_RealPak verifies rekey on a production Scripts.pak.
// It proves the operation preserves real production pak structure end-to-end.
func TestRekeyEOCDComment_RealPak(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	// Generate a fresh revival-style keypair.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	pubDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)

	// Read the vanilla-signed EOCD comment from Scripts.pak.
	fi, err := os.Stat(scriptsPakPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(scriptsPakPath)
	if err != nil {
		t.Fatal(err)
	}
	comment := make([]byte, 2320)
	_, err = f.ReadAt(comment, fi.Size()-2320)
	f.Close()
	if err != nil {
		t.Fatalf("read comment: %v", err)
	}

	// Rekey with the new private key.
	newComment, err := pak.RekeyEOCDComment(comment, nil, privDER)
	if err != nil {
		t.Fatalf("RekeyEOCDComment: %v", err)
	}

	// Write into a temp copy — only the last 2320 bytes differ.
	original, err := os.ReadFile(scriptsPakPath)
	if err != nil {
		t.Fatal(err)
	}
	patched := make([]byte, len(original))
	copy(patched, original)
	copy(patched[len(patched)-2320:], newComment)

	rekeyedPath := filepath.Join(t.TempDir(), "Scripts_rekeyed.pak")
	if err := os.WriteFile(rekeyedPath, patched, 0o644); err != nil {
		t.Fatal(err)
	}

	// Open with the new public key; entry count and CryXmlB magic must match.
	r, err := pak.Open(rekeyedPath, pubDER)
	if err != nil {
		t.Fatalf("Open rekeyed Scripts.pak with new key: %v", err)
	}
	if len(r.Entries) != 757 {
		t.Errorf("entries: got %d, want 757", len(r.Entries))
	}
	got, err := r.Extract(r.Entries[0])
	if err != nil {
		t.Fatalf("Extract first entry: %v", err)
	}
	wantMagic, _ := hex.DecodeString("437279586d6c4200")
	if len(got) < 8 {
		t.Fatalf("entry too short: %d bytes", len(got))
	}
	for i, b := range wantMagic {
		if got[i] != b {
			t.Errorf("magic[%d] = 0x%02x, want 0x%02x", i, got[i], b)
		}
	}

	// Vanilla key must NOT open the rekeyed pak.
	if _, err := pak.Open(rekeyedPath, nil); err == nil {
		t.Error("vanilla key should not open rekeyed pak but did")
	}
}

func TestDecryptEOCDComment_KnownKeys(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	f, err := os.Open(scriptsPakPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fi, _ := f.Stat()
	comment := make([]byte, 2320)
	if _, err := f.ReadAt(comment, fi.Size()-2320); err != nil {
		t.Fatalf("read comment: %v", err)
	}

	kr, err := pak.DecryptEOCDComment(comment, nil)
	if err != nil {
		t.Fatalf("DecryptEOCDComment: %v", err)
	}

	// Verify CDR IV.
	wantCDRIV := "28a1717f9af77108936c5de0d965d11d"
	if got := hex.EncodeToString(kr.CDRIV[:]); got != wantCDRIV {
		t.Errorf("CDRIV = %s, want %s", got, wantCDRIV)
	}

	// Verify all 16 keys.
	wantKeys := [16]string{
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
	for i, want := range wantKeys {
		got := hex.EncodeToString(kr.Keys[i][:])
		if got != want {
			t.Errorf("Keys[%d] = %s, want %s", i, got, want)
		}
	}
}

func TestOpen_EndToEnd(t *testing.T) {
	skipIfMissing(t, scriptsPakPath)

	r, err := pak.Open(scriptsPakPath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(r.Entries) != 757 {
		t.Errorf("got %d entries, want 757", len(r.Entries))
	}

	// Extract first entry via full RSA path.
	data, err := r.Extract(r.Entries[0])
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(data) != 161 {
		t.Errorf("got %d bytes, want 161", len(data))
	}
	wantPrefix, _ := hex.DecodeString("437279586d6c4200")
	for i, b := range wantPrefix {
		if data[i] != b {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, data[i], b)
		}
	}
}
