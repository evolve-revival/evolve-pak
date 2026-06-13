package pak_test

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

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
