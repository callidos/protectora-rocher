package communication

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	CompressionNone byte = 0 // Pas de compression
	CompressionZstd byte = 1 // Compression Zstandard avec CRC

	minCompressionSize = 64          // Taille minimale pour tenter la compression
	maxCompressionSize = 1024 * 1024 // 1MB max
)

var (
	ErrCorruptedData     = errors.New("data corrupted")
	ErrUnsupportedFormat = errors.New("unsupported compression format")
)

// Pools pour réutiliser les encodeurs/décodeurs
var (
	encoderPool = sync.Pool{
		New: func() interface{} {
			enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
			return enc
		},
	}

	decoderPool = sync.Pool{
		New: func() interface{} {
			dec, _ := zstd.NewReader(nil)
			return dec
		},
	}
)

// CompressData compresse les données avec zstd uniquement
func CompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{CompressionNone}, nil
	}

	if len(data) > maxCompressionSize {
		return nil, ErrDataTooLarge
	}

	// Pour les petites données, pas de compression
	if len(data) < minCompressionSize {
		return wrapWithFlag(data, CompressionNone), nil
	}

	// Compression Zstandard
	compressed, err := compressZstd(data)
	if err != nil {
		return wrapWithFlag(data, CompressionNone), nil
	}

	// Si la compression n'améliore pas, renvoyer les données originales
	if len(compressed) >= len(data) {
		return wrapWithFlag(data, CompressionNone), nil
	}

	return compressed, nil
}

// DecompressData décompresse les données selon le flag
func DecompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidFormat
	}

	flag := data[0]
	payload := data[1:]

	switch flag {
	case CompressionNone:
		return payload, nil

	case CompressionZstd:
		return decompressZstd(payload)

	default:
		return nil, ErrUnsupportedFormat
	}
}

// compressZstd compresse avec Zstandard et ajoute un CRC
func compressZstd(data []byte) ([]byte, error) {
	encoder := encoderPool.Get().(*zstd.Encoder)
	defer encoderPool.Put(encoder)

	compressed := encoder.EncodeAll(data, nil)

	// Calcul du CRC pour vérifier l'intégrité
	crc := crc32.ChecksumIEEE(compressed)

	// Format: flag + CRC + données compressées
	result := make([]byte, 1+4+len(compressed))
	result[0] = CompressionZstd
	binary.BigEndian.PutUint32(result[1:5], crc)
	copy(result[5:], compressed)

	return result, nil
}

// decompressZstd décompresse Zstandard et vérifie le CRC
func decompressZstd(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, ErrInvalidFormat
	}

	storedCRC := binary.BigEndian.Uint32(data[:4])
	compressed := data[4:]

	// Vérification du CRC
	computedCRC := crc32.ChecksumIEEE(compressed)
	if storedCRC != computedCRC {
		return nil, ErrCorruptedData
	}

	decoder := decoderPool.Get().(*zstd.Decoder)
	defer decoderPool.Put(decoder)

	decompressed, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		return nil, ErrCorruptedData
	}

	return decompressed, nil
}

// wrapWithFlag encapsule les données avec un flag de compression
func wrapWithFlag(data []byte, flag byte) []byte {
	result := make([]byte, 1+len(data))
	result[0] = flag
	copy(result[1:], data)
	return result
}
