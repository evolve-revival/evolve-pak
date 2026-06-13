package audit

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/evolve-revival/evolve-pak/internal/pak"
)

// PerfEntry is a single large or poorly-compressed file found in a pak.
type PerfEntry struct {
	PakName      string
	EntryName    string
	Compressed   int64
	Uncompressed int64
}

func (e PerfEntry) CompressionRatio() float64 {
	if e.Uncompressed == 0 {
		return 0
	}
	return float64(e.Compressed) / float64(e.Uncompressed)
}

// PerfReport holds the top entries by uncompressed size across all openable paks.
type PerfReport struct {
	Entries []PerfEntry
	Errors  []string
	TopN    int
}

// ScanDirPerf opens each pak in gameDir, collects per-entry sizes, and returns
// the top topN entries by uncompressed size.
func ScanDirPerf(gameDir string, topN int) (*PerfReport, error) {
	diskReport, err := ScanDir(gameDir)
	if err != nil {
		return nil, err
	}

	pr := &PerfReport{TopN: topN}
	var all []PerfEntry

	for _, ps := range diskReport.Paks {
		pakPath := filepath.Join(gameDir, ps.Name)
		r, err := pak.Open(pakPath, nil)
		if err != nil {
			pr.Errors = append(pr.Errors, fmt.Sprintf("%s: %v", ps.Name, err))
			continue
		}
		for _, e := range r.Entries {
			all = append(all, PerfEntry{
				PakName:      ps.Name,
				EntryName:    e.Name,
				Compressed:   int64(e.CompressedSize),
				Uncompressed: int64(e.UncompressedSize),
			})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Uncompressed > all[j].Uncompressed
	})

	if topN > len(all) {
		topN = len(all)
	}
	pr.Entries = all[:topN]
	return pr, nil
}

func (pr *PerfReport) Print() {
	fmt.Printf("Top %d largest entries by uncompressed size\n\n", pr.TopN)
	fmt.Printf("%-6s  %-12s  %-14s  %s\n", "RATIO", "COMPRESSED", "UNCOMPRESSED", "FILE")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range pr.Entries {
		ratio := e.CompressionRatio()
		flag := ""
		if ratio > 0.9 && e.Uncompressed > 0 {
			flag = " !"
		}
		fmt.Printf("%.3f%s  %12s  %14s  %s → %s\n",
			ratio, flag,
			HumanBytes(e.Compressed), HumanBytes(e.Uncompressed),
			e.PakName, e.EntryName)
	}
	if len(pr.Errors) > 0 {
		fmt.Printf("\n%d pak(s) skipped (unrecognised key).\n", len(pr.Errors))
	}
}
