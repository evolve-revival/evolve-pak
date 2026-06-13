package pak

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

type fileRecord struct {
	name              string
	crc               uint32
	compressedSize    uint32
	uncompressedSize  uint32
	localHeaderOffset uint32
}

// Pack walks srcDir and writes all files into an encrypted CryPak at destPath,
// using privKeyDER (PKCS#1 DER RSA-1024 private key) to protect the Twofish key table.
// Returns the number of files packed.
func Pack(srcDir, destPath string, privKeyDER []byte) (_ int, retErr error) {
	// Generate 16 Twofish keys and one CDR IV.
	var keys [16][16]byte
	var cdrIV [16]byte
	for i := range keys {
		if _, err := rand.Read(keys[i][:]); err != nil {
			return 0, fmt.Errorf("rand keys: %w", err)
		}
	}
	if _, err := rand.Read(cdrIV[:]); err != nil {
		return 0, fmt.Errorf("rand cdrIV: %w", err)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", destPath, err)
	}
	defer func() {
		out.Close()
		if retErr != nil {
			os.Remove(destPath)
		}
	}()

	w := &errWriter{w: out}
	var pos uint32
	var records []fileRecord

	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		rel, _ := filepath.Rel(srcDir, path)
		entryName := strings.ReplaceAll(rel, string(filepath.Separator), "/")

		// CRC32 of uncompressed data (standard ZIP CRC32, IEEE polynomial).
		crc := crc32.ChecksumIEEE(raw)

		// Deflate compress.
		var deflateBuf bytes.Buffer
		fw, err := flate.NewWriter(&deflateBuf, flate.BestCompression)
		if err != nil {
			return fmt.Errorf("flate.NewWriter: %w", err)
		}
		if _, err := fw.Write(raw); err != nil {
			return fmt.Errorf("deflate %s: %w", entryName, err)
		}
		if err := fw.Close(); err != nil {
			return fmt.Errorf("deflate close %s: %w", entryName, err)
		}
		compressed := deflateBuf.Bytes()

		compSize := uint32(len(compressed))
		uncompSize := uint32(len(raw))

		iv := fileIV(compSize, uncompSize, crc)
		ki := keyIndex(crc)

		// Build 30-byte fixed LFH.
		var lfh [30]byte
		binary.LittleEndian.PutUint32(lfh[0:], 0x04034b50) // PK\x03\x04
		binary.LittleEndian.PutUint16(lfh[4:], 20)          // version needed
		binary.LittleEndian.PutUint16(lfh[6:], 0)           // flags
		binary.LittleEndian.PutUint16(lfh[8:], methodDeflateTwofish)
		binary.LittleEndian.PutUint16(lfh[10:], 0) // mod time
		binary.LittleEndian.PutUint16(lfh[12:], 0) // mod date
		binary.LittleEndian.PutUint32(lfh[14:], crc)
		binary.LittleEndian.PutUint32(lfh[18:], compSize)
		binary.LittleEndian.PutUint32(lfh[22:], uncompSize)
		binary.LittleEndian.PutUint16(lfh[26:], uint16(len(entryName)))
		binary.LittleEndian.PutUint16(lfh[28:], 0) // extra len

		encLFH, err := crypto.TwofishCTR(keys[ki][:], iv[:], lfh[:])
		if err != nil {
			return fmt.Errorf("encrypt LFH %s: %w", entryName, err)
		}

		encData, err := crypto.TwofishCTR(keys[ki][:], iv[:], compressed)
		if err != nil {
			return fmt.Errorf("encrypt data %s: %w", entryName, err)
		}

		records = append(records, fileRecord{
			name:              entryName,
			crc:               crc,
			compressedSize:    compSize,
			uncompressedSize:  uncompSize,
			localHeaderOffset: pos,
		})

		w.write(encLFH)
		w.write([]byte(entryName)) // filename unencrypted
		w.write(encData)
		pos += 30 + uint32(len(entryName)) + compSize
		return nil
	})
	if err != nil {
		return 0, err
	}
	if w.err != nil {
		return 0, fmt.Errorf("write file data: %w", w.err)
	}
	if len(records) == 0 {
		return 0, fmt.Errorf("no files found in %s", srcDir)
	}

	// Build unencrypted CDR.
	var cdrBuf bytes.Buffer
	for _, r := range records {
		var cdr [46]byte
		binary.LittleEndian.PutUint32(cdr[0:], 0x02014b50) // PK\x01\x02
		binary.LittleEndian.PutUint16(cdr[4:], 20)          // version made
		binary.LittleEndian.PutUint16(cdr[6:], 20)          // version needed
		binary.LittleEndian.PutUint16(cdr[8:], 0)           // flags
		binary.LittleEndian.PutUint16(cdr[10:], methodDeflateTwofish)
		binary.LittleEndian.PutUint16(cdr[12:], 0) // mod time
		binary.LittleEndian.PutUint16(cdr[14:], 0) // mod date
		binary.LittleEndian.PutUint32(cdr[16:], r.crc)
		binary.LittleEndian.PutUint32(cdr[20:], r.compressedSize)
		binary.LittleEndian.PutUint32(cdr[24:], r.uncompressedSize)
		binary.LittleEndian.PutUint16(cdr[28:], uint16(len(r.name)))
		binary.LittleEndian.PutUint16(cdr[30:], 0) // extra len
		binary.LittleEndian.PutUint16(cdr[32:], 0) // comment len
		binary.LittleEndian.PutUint16(cdr[34:], 0) // disk start
		binary.LittleEndian.PutUint16(cdr[36:], 0) // internal attr
		binary.LittleEndian.PutUint32(cdr[38:], 0) // external attr
		binary.LittleEndian.PutUint32(cdr[42:], r.localHeaderOffset)
		cdrBuf.Write(cdr[:])
		cdrBuf.Write([]byte(r.name))
	}

	cdrStart := pos
	encCDR, err := crypto.TwofishCTR(keys[0][:], cdrIV[:], cdrBuf.Bytes())
	if err != nil {
		return 0, fmt.Errorf("encrypt CDR: %w", err)
	}
	w.write(encCDR)

	// Build EOCD comment (2320 bytes).
	comment, err := buildEOCDComment(privKeyDER, keys, cdrIV)
	if err != nil {
		return 0, fmt.Errorf("build EOCD comment: %w", err)
	}

	// Write EOCD record (22 bytes).
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[4:], 0)
	binary.LittleEndian.PutUint16(eocd[6:], 0)
	binary.LittleEndian.PutUint16(eocd[8:], uint16(len(records)))
	binary.LittleEndian.PutUint16(eocd[10:], uint16(len(records)))
	binary.LittleEndian.PutUint32(eocd[12:], uint32(len(encCDR)))
	binary.LittleEndian.PutUint32(eocd[16:], cdrStart)
	binary.LittleEndian.PutUint16(eocd[20:], 2320)
	w.write(eocd[:])
	w.write(comment)

	return len(records), w.err
}

// errWriter is a write-once sticky-error wrapper around *os.File.
type errWriter struct {
	w   *os.File
	err error
}

func (ew *errWriter) write(p []byte) {
	if ew.err != nil {
		return
	}
	_, ew.err = ew.w.Write(p)
}

// buildEOCDComment assembles the 2320-byte CryEngine EOCD comment.
// Layout matches keyring.go constants: encHeaderOff=139, ivEncOff=143, keyEncOff=272.
func buildEOCDComment(privKeyDER []byte, keys [16][16]byte, cdrIV [16]byte) ([]byte, error) {
	comment := make([]byte, 2320)

	// CryEngineExtendedHeader [0:6]
	binary.LittleEndian.PutUint32(comment[0:], 6)
	comment[4] = 1 // encType: Twofish
	comment[5] = 3 // sigType: RSA

	// CryEngineSigningHeader [6:139] — 133 bytes of zeros (not computed)

	// CryEngineEncryptionHeader starts at 139
	binary.LittleEndian.PutUint32(comment[139:], 2181) // encHeaderSize

	// Encrypt CDR IV at offset 143
	encIV, err := crypto.RSAPrivateEncryptOAEP(privKeyDER, cdrIV[:])
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt IV: %w", err)
	}
	copy(comment[143:], encIV) // 128 bytes; comment[271] = 0x00 padding (already zero)

	// Encrypt each of the 16 Twofish keys starting at offset 272
	for i := 0; i < 16; i++ {
		encKey, err := crypto.RSAPrivateEncryptOAEP(privKeyDER, keys[i][:])
		if err != nil {
			return nil, fmt.Errorf("RSA encrypt key[%d]: %w", i, err)
		}
		copy(comment[272+i*128:], encKey)
	}

	return comment, nil
}
