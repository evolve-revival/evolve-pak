package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evolve-revival/evolve-pak/internal/audit"
	"github.com/evolve-revival/evolve-pak/internal/crypto"
	"github.com/evolve-revival/evolve-pak/internal/pak"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "evolve-pak",
	Short: "Inspect, audit, and extract Evolve .pak files",
}

var listCmd = &cobra.Command{
	Use:   "list <file.pak>",
	Short: "List entries in a pak file",
	Args:  cobra.ExactArgs(1),
	RunE:  runList,
}

var extractCmd = &cobra.Command{
	Use:   "extract <file.pak> [outdir]",
	Short: "Extract all files from a pak to a directory",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runExtract,
}

var inspectCmd = &cobra.Command{
	Use:   "inspect <file.pak>",
	Short: "Show pak header info",
	Args:  cobra.ExactArgs(1),
	RunE:  runInspect,
}

var auditCmd = &cobra.Command{
	Use:   "audit <game-dir>",
	Short: "Show size breakdown across all pak files in a game directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runAudit,
}

var perfCmd = &cobra.Command{
	Use:   "perf <game-dir>",
	Short: "List the largest entries across all openable pak files",
	Args:  cobra.ExactArgs(1),
	RunE:  runPerf,
}

var packCmd = &cobra.Command{
	Use:   "pack <dir> <out.pak>",
	Short: "Pack a directory into an encrypted pak file (requires --privkey from keygen)",
	Args:  cobra.ExactArgs(2),
	RunE:  runPack,
}

var keyfindCmd = &cobra.Command{
	Use:   "keyfind <Evolve.exe> <any.pak>",
	Short: "Scan Evolve.exe for the XTEA key that decrypts the pak file",
	Args:  cobra.ExactArgs(2),
	RunE:  runKeyfind,
}

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an RSA-1024 keypair for signing custom pak files",
	Args:  cobra.NoArgs,
	RunE:  runKeygen,
}

func runList(_ *cobra.Command, args []string) error {
	r, err := pak.Open(args[0], nil)
	if err != nil {
		return err
	}
	for _, e := range r.Entries {
		fmt.Printf("%8d  %8d  %s\n", e.CompressedSize, e.UncompressedSize, e.Name)
	}
	fmt.Printf("\n%d entries\n", len(r.Entries))
	return nil
}

func runExtract(_ *cobra.Command, args []string) error {
	pakPath := args[0]
	outDir := strings.TrimSuffix(filepath.Base(pakPath), filepath.Ext(pakPath))
	if len(args) == 2 {
		outDir = args[1]
	}

	r, err := pak.Open(pakPath, nil)
	if err != nil {
		return err
	}

	for _, e := range r.Entries {
		data, err := r.Extract(e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s: %v\n", e.Name, err)
			continue
		}

		outPath := filepath.Join(outDir, filepath.FromSlash(e.Name))
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return err
		}
	}

	fmt.Printf("Extracted %d files to %s\n", len(r.Entries), outDir)
	return nil
}

func runInspect(_ *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	buf = buf[:n]

	h, err := pak.ParseHeader(buf)
	if err != nil {
		fmt.Printf("Header parse failed: %v\n", err)
		fmt.Printf("Raw first bytes: % x\n", buf[:min(16, len(buf))])
		return nil
	}

	variantName := map[pak.MagicVariant]string{
		pak.MagicVariantA: "A (ef 4d e5 06)",
		pak.MagicVariantB: "B (7d 37 21 fb)",
	}[h.Magic]

	fi, _ := f.Stat()
	fmt.Printf("File:    %s\n", args[0])
	fmt.Printf("Size:    %s\n", humanBytes(fi.Size()))
	fmt.Printf("Magic:   %s\n", variantName)
	return nil
}

func runKeyfind(_ *cobra.Command, args []string) error {
	exeData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read exe: %w", err)
	}
	pakData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("read pak: %w", err)
	}
	if len(pakData) < 8 {
		return fmt.Errorf("pak too small: %d bytes", len(pakData))
	}

	cipherBlock := pakData[:8]
	fmt.Printf("Scanning %d bytes of %s...\n", len(exeData), args[0])
	fmt.Printf("Pak first block (ciphertext): % x\n", cipherBlock)

	type attempt struct {
		label          string
		blockLE        bool
		keyLE          bool
		word0          uint32
		matchBothWords bool
	}

	word0Attempts := []attempt{
		{"BE-block BE-key word0=0x504B0304", false, false, 0x504B0304, false},
		{"BE-block LE-key word0=0x504B0304", false, true, 0x504B0304, false},
		{"LE-block BE-key word0=0x04034B50", true, false, 0x04034B50, false},
		{"LE-block LE-key word0=0x04034B50", true, true, 0x04034B50, false},
	}

	for _, a := range word0Attempts {
		fmt.Printf("Trying %s...\n", a.label)
		expected := [2]uint32{a.word0, 0}
		key := crypto.FindKeyOpts(exeData, cipherBlock, expected, a.blockLE, a.keyLE, false)
		if key != nil {
			fmt.Printf("Key found! (%s)\n", a.label)
			fmt.Printf("Key words: %08x %08x %08x %08x\n", key[0], key[1], key[2], key[3])
			return nil
		}
	}

	fmt.Println("Key not found.")
	return nil
}

var (
	auditContents bool
	perfTopN      int
	keygenOutDir  string
	keygenForce   bool
	packPrivKey   string
)

func runAudit(_ *cobra.Command, args []string) error {
	if auditContents {
		cr, err := audit.ScanDirContents(args[0])
		if err != nil {
			return err
		}
		cr.Print()
		return nil
	}
	report, err := audit.ScanDir(args[0])
	if err != nil {
		return err
	}
	report.Print()
	return nil
}

func runKeygen(_ *cobra.Command, _ []string) error {
	privPath := filepath.Join(keygenOutDir, "revival.priv")
	pubPath := filepath.Join(keygenOutDir, "revival.pub")

	if !keygenForce {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s already exists (use --force to overwrite)", p)
			}
		}
	}

	fmt.Println("Generating RSA-1024 keypair...")
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("GenerateKey: %w", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(priv)
	pubDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)

	if err := os.WriteFile(privPath, privDER, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pubDER, 0o644); err != nil {
		os.Remove(privPath)
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	h := sha256.Sum256(pubDER)
	fmt.Printf("Private key: %s\n", privPath)
	fmt.Printf("Public key:  %s\n", pubPath)
	fmt.Printf("Fingerprint: %x\n", h[:8])
	fmt.Println("Keep revival.priv secret. Drop revival.pub + dbghelp.dll into bin64_SteamRetail/.")
	return nil
}

func runPack(_ *cobra.Command, args []string) error {
	if packPrivKey == "" {
		return fmt.Errorf("--privkey is required (run 'evolve-pak keygen' first)")
	}
	privDER, err := os.ReadFile(packPrivKey)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	fmt.Printf("Packing %s -> %s...\n", args[0], args[1])
	n, err := pak.Pack(args[0], args[1], privDER)
	if err != nil {
		return err
	}
	fi, err := os.Stat(args[1])
	if err != nil {
		fmt.Printf("Done. %d files written.\n", n)
		return nil
	}
	fmt.Printf("Done. %d files, %s written.\n", n, humanBytes(fi.Size()))
	return nil
}

func runPerf(_ *cobra.Command, args []string) error {
	pr, err := audit.ScanDirPerf(args[0], perfTopN)
	if err != nil {
		return err
	}
	pr.Print()
	return nil
}

func init() {
	auditCmd.Flags().BoolVarP(&auditContents, "contents", "c", false, "open each pak and break down by file category")
	perfCmd.Flags().IntVarP(&perfTopN, "top", "n", 20, "number of entries to show")
	packCmd.Flags().StringVar(&packPrivKey, "privkey", "", "path to revival.priv (from keygen)")
	keygenCmd.Flags().StringVar(&keygenOutDir, "out-dir", ".", "directory to write revival.priv and revival.pub")
	keygenCmd.Flags().BoolVar(&keygenForce, "force", false, "overwrite existing key files")
	rootCmd.AddCommand(listCmd, extractCmd, inspectCmd, auditCmd, perfCmd, packCmd, keyfindCmd, keygenCmd)
}

func humanBytes(b int64) string {
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
