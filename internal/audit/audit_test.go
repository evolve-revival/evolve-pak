package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/evolve-revival/evolve-pak/internal/audit"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"textures/hunter_skin.dds", "textures"},
		{"sounds/hunter_voice_en.wav", "audio"},
		{"sounds/hunter_voice_en.ogg", "audio"},
		{"videos/trailer_goliath.bik", "video"},
		{"scripts/ai/hunter_pathfind.lua", "scripts"},
		{"shaders/forward_pass.cfx", "shaders"},
		{"animations/monster_leap.caf", "animations"},
		{"objects/stage_props.cgf", "geometry"},
		{"unknown/file.xyz", "other"},
	}
	for _, tt := range tests {
		got := audit.Classify(tt.path)
		if got != tt.want {
			t.Errorf("Classify(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestScanDir(t *testing.T) {
	tmpDir := t.TempDir()
	// Create fake pak files of different sizes
	os.WriteFile(filepath.Join(tmpDir, "big.pak"), make([]byte, 2048), 0644)
	os.WriteFile(filepath.Join(tmpDir, "small.PAK"), make([]byte, 512), 0644) // case-insensitive
	os.WriteFile(filepath.Join(tmpDir, "notapak.exe"), make([]byte, 100), 0644)

	r, err := audit.ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(r.Paks) != 2 {
		t.Fatalf("expected 2 paks, got %d", len(r.Paks))
	}
	// Should be sorted descending by size
	if r.Paks[0].Size < r.Paks[1].Size {
		t.Error("paks not sorted descending by size")
	}
	if r.TotalBytes != 2048+512 {
		t.Errorf("TotalBytes = %d, want %d", r.TotalBytes, 2048+512)
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{int64(1.5 * 1024 * 1024 * 1024), "1.5 GB"},
	}
	for _, tt := range tests {
		got := audit.HumanBytes(tt.input)
		if got != tt.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
