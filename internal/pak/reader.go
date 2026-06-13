package pak

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/evolve-revival/evolve-pak/internal/crypto"
)

// compressionMethod values used in CryEngine paks.
const (
	methodStored         = 0
	methodDeflate        = 8
	methodDeflateTwofish = 14 // encrypted+deflate; data is raw deflate after decryption
)

// Entry is a file entry inside a pak archive.
type Entry struct {
	Name             string
	CompressedSize   uint32
	UncompressedSize uint32
	CRC              uint32

	// private
	localHeaderOffset uint32
	method            uint16
	key               [16]byte
	iv                [16]byte
}

// Reader holds a decrypted view of an Evolve pak file's central directory.
type Reader struct {
	path    string
	Entries []Entry
}

// Open opens a pak file, decrypting the key table from the EOCD comment using
// the embedded vanilla RSA public key (or optionally a custom DER key via rsaDER).
func Open(pakPath string, rsaDER []byte) (*Reader, error) {
	f, err := os.Open(pakPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	const commentLen = 2320
	const eocdFixedSize = 22
	eocdOffset := fi.Size() - eocdFixedSize - commentLen
	if eocdOffset < 0 {
		return nil, fmt.Errorf("file too small for Evolve EOCD")
	}

	comment := make([]byte, commentLen)
	if _, err := f.ReadAt(comment, fi.Size()-commentLen); err != nil {
		return nil, fmt.Errorf("read EOCD comment: %w", err)
	}

	kr, err := DecryptEOCDComment(comment, rsaDER)
	if err != nil {
		return nil, err
	}

	return OpenWithKeys(pakPath, kr.Keys, kr.CDRIV)
}

// OpenWithKeys opens a pak file using pre-derived Twofish keys and CDR IV.
// This is the low-level constructor; Open is the normal entry point.
func OpenWithKeys(pakPath string, keys [16][16]byte, cdrIV [16]byte) (*Reader, error) {
	f, err := os.Open(pakPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fi.Size()

	// 1. Find the EOCD by scanning backwards from the end of file.
	//    CryEngine EOCD always has a 2320-byte comment, so we know exactly where it is.
	const eocdSig = uint32(0x06054b50)
	const commentLen = 2320
	const eocdFixedSize = 22
	eocdOffset := fileSize - eocdFixedSize - commentLen
	if eocdOffset < 0 {
		return nil, fmt.Errorf("file too small for Evolve EOCD")
	}
	var eocd [eocdFixedSize]byte
	if _, err := f.ReadAt(eocd[:], eocdOffset); err != nil {
		return nil, fmt.Errorf("read EOCD: %w", err)
	}
	if binary.LittleEndian.Uint32(eocd[0:]) != eocdSig {
		return nil, fmt.Errorf("EOCD signature not found at expected offset 0x%x", eocdOffset)
	}

	cdrSize := int64(binary.LittleEndian.Uint32(eocd[12:]))
	cdrOffset := int64(binary.LittleEndian.Uint32(eocd[16:]))

	// 3. Read and decrypt the CDR.
	cdrEnc := make([]byte, cdrSize)
	if _, err := f.ReadAt(cdrEnc, cdrOffset); err != nil {
		return nil, fmt.Errorf("read CDR: %w", err)
	}
	cdrDec, err := crypto.TwofishCTR(keys[0][:], cdrIV[:], cdrEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt CDR: %w", err)
	}

	// 4. Parse CDR entries.
	raw, err := parseCDR(cdrDec)
	if err != nil {
		return nil, fmt.Errorf("parse CDR: %w", err)
	}

	entries := make([]Entry, len(raw))
	for i, r := range raw {
		iv := fileIV(r.sizeCompressed, r.sizeUncompressed, r.crc)
		ki := keyIndex(r.crc)
		entries[i] = Entry{
			Name:              r.name,
			CompressedSize:    r.sizeCompressed,
			UncompressedSize:  r.sizeUncompressed,
			CRC:               r.crc,
			localHeaderOffset: r.localHeaderOffset,
			method:            r.method,
			key:               keys[ki],
			iv:                iv,
		}
	}

	return &Reader{
		path:    pakPath,
		Entries: entries,
	}, nil
}

// Extract decrypts and decompresses the given entry, returning its raw bytes.
//
// CryEngine PAK encryption: the LFH and the file data are each decrypted with
// a fresh CTR stream starting from the file's IV.  The file data does NOT
// continue the LFH's CTR — it resets (libcrypak's newCounterSection=true).
func (r *Reader) Extract(e Entry) ([]byte, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Local file headers use absolute file offsets (ZIP data starts at byte 0).
	offset := int64(e.localHeaderOffset)

	// Step 1: read and decrypt the 30-byte fixed LFH with a fresh CTR at IV.
	var lfhRaw [30]byte
	if _, err := f.ReadAt(lfhRaw[:], offset); err != nil {
		return nil, fmt.Errorf("read LFH: %w", err)
	}
	lfhDec, err := crypto.TwofishCTR(e.key[:], e.iv[:], lfhRaw[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt LFH: %w", err)
	}
	if sig := binary.LittleEndian.Uint32(lfhDec[0:]); sig != 0x04034b50 {
		return nil, fmt.Errorf("bad LFH signature 0x%08x", sig)
	}
	lfhNameLen := int(binary.LittleEndian.Uint16(lfhDec[26:]))
	lfhExtraLen := int(binary.LittleEndian.Uint16(lfhDec[28:]))

	// Step 2: read and decrypt file data with a FRESH CTR reset to IV.
	//         File data begins immediately after the LFH name+extra fields.
	dataOffset := offset + 30 + int64(lfhNameLen) + int64(lfhExtraLen)
	encData := make([]byte, e.CompressedSize)
	if _, err := f.ReadAt(encData, dataOffset); err != nil {
		return nil, fmt.Errorf("read file data: %w", err)
	}
	compressed, err := crypto.TwofishCTR(e.key[:], e.iv[:], encData)
	if err != nil {
		return nil, fmt.Errorf("decrypt file data: %w", err)
	}

	// Step 3: decompress.
	switch e.method {
	case methodStored:
		return compressed, nil
	case methodDeflate, methodDeflateTwofish:
		return deflateDecompress(compressed, int(e.UncompressedSize))
	default:
		return nil, fmt.Errorf("unsupported compression method %d", e.method)
	}
}

// --- internal helpers ---

type cdrEntry struct {
	method            uint16
	crc               uint32
	sizeCompressed    uint32
	sizeUncompressed  uint32
	nameLen           uint16
	extraLen          uint16
	commentLen        uint16
	localHeaderOffset uint32
	name              string
}

const cdrSig = uint32(0x02014b50)

func parseCDR(data []byte) ([]cdrEntry, error) {
	var entries []cdrEntry
	pos := 0
	for pos < len(data) {
		if pos+46 > len(data) {
			break
		}
		sig := binary.LittleEndian.Uint32(data[pos:])
		if sig != cdrSig {
			break
		}
		method := binary.LittleEndian.Uint16(data[pos+10:])
		crc := binary.LittleEndian.Uint32(data[pos+16:])
		sc := binary.LittleEndian.Uint32(data[pos+20:])
		su := binary.LittleEndian.Uint32(data[pos+24:])
		nameLen := binary.LittleEndian.Uint16(data[pos+28:])
		extraLen := binary.LittleEndian.Uint16(data[pos+30:])
		commentLen := binary.LittleEndian.Uint16(data[pos+32:])
		localOffset := binary.LittleEndian.Uint32(data[pos+42:])

		nameStart := pos + 46
		nameEnd := nameStart + int(nameLen)
		if nameEnd > len(data) {
			return nil, fmt.Errorf("CDR entry name at %d extends past data (%d > %d)", pos, nameEnd, len(data))
		}
		entries = append(entries, cdrEntry{
			method:            method,
			crc:               crc,
			sizeCompressed:    sc,
			sizeUncompressed:  su,
			nameLen:           nameLen,
			extraLen:          extraLen,
			commentLen:        commentLen,
			localHeaderOffset: localOffset,
			name:              string(data[nameStart:nameEnd]),
		})
		pos += 46 + int(nameLen) + int(extraLen) + int(commentLen)
	}
	return entries, nil
}

// keyIndex returns the Twofish key index (0–15) for a file with the given CRC.
func keyIndex(crc uint32) int {
	return int((^(crc >> 2)) & 0x0F)
}

// fileIV derives the per-file Twofish IV from the file's data descriptor.
// Matches CryEngine's getInitialVector() in libcrypak/ZipUtil.cpp.
func fileIV(sizeCompressed, sizeUncompressed, crc uint32) [16]byte {
	var temp [4]uint32
	temp[0] = sizeUncompressed ^ (sizeCompressed << 12)
	if sizeCompressed == 0 {
		temp[1] = 1
	}
	temp[2] = crc ^ (sizeCompressed << 12)
	if sizeUncompressed == 0 {
		temp[3] = 1 ^ sizeCompressed
	} else {
		temp[3] = sizeCompressed
	}
	var iv [16]byte
	binary.LittleEndian.PutUint32(iv[0:], temp[0])
	binary.LittleEndian.PutUint32(iv[4:], temp[1])
	binary.LittleEndian.PutUint32(iv[8:], temp[2])
	binary.LittleEndian.PutUint32(iv[12:], temp[3])
	return iv
}

func deflateDecompress(data []byte, expectedSize int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("deflate: %w", err)
	}
	if len(out) != expectedSize {
		return nil, fmt.Errorf("deflate: got %d bytes, expected %d", len(out), expectedSize)
	}
	return out, nil
}
