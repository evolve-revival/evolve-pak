package pak_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

func TestPackRoundTrip(t *testing.T) {
	// Generate test RSA-1024 keypair
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	pubDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)

	// Create two test files
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "Scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"Scripts/hello.lua": []byte("-- hello\nreturn {}"),
		"Scripts/world.lua": []byte("-- world\nreturn {x=1, y=2}"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(srcDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Pack
	outPak := filepath.Join(t.TempDir(), "test.pak")
	n, err := pak.Pack(srcDir, outPak, privDER)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if n != 2 {
		t.Errorf("Pack returned %d files, want 2", n)
	}

	// Open with matching public key
	r, err := pak.Open(outPak, pubDER)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(r.Entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(r.Entries))
	}

	// Verify each entry's content survives the round-trip
	byName := make(map[string]pak.Entry)
	for _, e := range r.Entries {
		byName[e.Name] = e
	}
	for name, want := range files {
		e, ok := byName[name]
		if !ok {
			t.Errorf("entry %q not found in pak", name)
			continue
		}
		got, err := r.Extract(e)
		if err != nil {
			t.Errorf("Extract %q: %v", name, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("content %q: got %q, want %q", name, got, want)
		}
	}
}

func TestPackEmptyDirFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	privDER := x509.MarshalPKCS1PrivateKey(priv)

	srcDir := t.TempDir() // no files
	outPak := filepath.Join(t.TempDir(), "empty.pak")

	_, err := pak.Pack(srcDir, outPak, privDER)
	if err == nil {
		t.Error("expected error packing empty directory, got nil")
	}
}
