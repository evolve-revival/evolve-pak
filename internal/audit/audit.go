package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

type PakStat struct {
	Name string
	Size int64
}

// Report is a high-level summary of pak files found on disk.
type Report struct {
	Paks       []PakStat
	TotalBytes int64
}

// CategoryReport breaks down pak contents by file-type category.
type CategoryReport struct {
	// By category name → aggregate stats.
	Categories map[string]*CategoryStat
	TotalEntries int
	TotalCompressed   int64
	TotalUncompressed int64
	Errors []string
}

type CategoryStat struct {
	Entries    int
	Compressed   int64
	Uncompressed int64
}

// ScanDir walks gameDir, finds all .pak files, and returns a disk-level report.
func ScanDir(gameDir string) (*Report, error) {
	r := &Report{}
	err := filepath.Walk(gameDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".pak") {
			return nil
		}
		rel, _ := filepath.Rel(gameDir, path)
		r.Paks = append(r.Paks, PakStat{Name: rel, Size: info.Size()})
		r.TotalBytes += info.Size()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", gameDir, err)
	}
	sort.Slice(r.Paks, func(i, j int) bool {
		return r.Paks[i].Size > r.Paks[j].Size
	})
	return r, nil
}

// ScanDirContents opens each pak in gameDir and returns a breakdown by file category.
// Errors opening individual paks are collected in CategoryReport.Errors (not fatal).
func ScanDirContents(gameDir string) (*CategoryReport, error) {
	diskReport, err := ScanDir(gameDir)
	if err != nil {
		return nil, err
	}

	cr := &CategoryReport{
		Categories: make(map[string]*CategoryStat),
	}

	for _, ps := range diskReport.Paks {
		pakPath := filepath.Join(gameDir, ps.Name)
		r, err := pak.Open(pakPath, nil)
		if err != nil {
			cr.Errors = append(cr.Errors, fmt.Sprintf("%s: %v", ps.Name, err))
			continue
		}

		for _, e := range r.Entries {
			cat := Classify(e.Name)
			if cr.Categories[cat] == nil {
				cr.Categories[cat] = &CategoryStat{}
			}
			cs := cr.Categories[cat]
			cs.Entries++
			cs.Compressed += int64(e.CompressedSize)
			cs.Uncompressed += int64(e.UncompressedSize)
			cr.TotalEntries++
			cr.TotalCompressed += int64(e.CompressedSize)
			cr.TotalUncompressed += int64(e.UncompressedSize)
		}
	}

	return cr, nil
}

func (r *Report) Print() {
	fmt.Printf("%-50s  %10s\n", "PAK FILE", "SIZE")
	fmt.Println(strings.Repeat("-", 63))
	for _, p := range r.Paks {
		fmt.Printf("%-50s  %10s\n", p.Name, HumanBytes(p.Size))
	}
	fmt.Println(strings.Repeat("-", 63))
	fmt.Printf("%-50s  %10s\n", fmt.Sprintf("TOTAL (%d paks)", len(r.Paks)), HumanBytes(r.TotalBytes))
}

func (cr *CategoryReport) Print() {
	// Sorted category names.
	cats := make([]string, 0, len(cr.Categories))
	for cat := range cr.Categories {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		return cr.Categories[cats[i]].Uncompressed > cr.Categories[cats[j]].Uncompressed
	})

	fmt.Printf("%-14s  %8s  %12s  %14s\n", "CATEGORY", "ENTRIES", "COMPRESSED", "UNCOMPRESSED")
	fmt.Println(strings.Repeat("-", 54))
	for _, cat := range cats {
		cs := cr.Categories[cat]
		fmt.Printf("%-14s  %8d  %12s  %14s\n", cat,
			cs.Entries, HumanBytes(cs.Compressed), HumanBytes(cs.Uncompressed))
	}
	fmt.Println(strings.Repeat("-", 54))
	fmt.Printf("%-14s  %8d  %12s  %14s\n", "TOTAL",
		cr.TotalEntries, HumanBytes(cr.TotalCompressed), HumanBytes(cr.TotalUncompressed))

	if len(cr.Errors) > 0 {
		fmt.Printf("\n%d pak(s) could not be opened:\n", len(cr.Errors))
		for _, e := range cr.Errors {
			fmt.Printf("  %s\n", e)
		}
	}
}

func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
