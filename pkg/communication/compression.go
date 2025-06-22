package communication

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	CompressionNone   byte = 0 // Pas de compression
	CompressionZstd   byte = 1 // Compression Zstandard avec CRC
	CompressionCustom byte = 2 // Compression optimisée pour l'alphabet restreint

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

// Alphabet optimisé pour la compression custom (32 caractères = 5 bits)
const customAlphabet = " abcdefghijklmnopqrstuvwxyz,.!?-"

var (
	charToCode = make(map[byte]uint8, len(customAlphabet))
	codeToChar = make(map[uint8]byte, len(customAlphabet))
)

func init() {
	// Initialisation des tables de conversion
	for i, char := range customAlphabet {
		charToCode[byte(char)] = uint8(i)
		codeToChar[uint8(i)] = byte(char)
	}
}

// CompressData compresse les données en choisissant automatiquement la meilleure méthode
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

	// Tentative de compression custom pour l'alphabet restreint
	if isCustomAlphabet(data) {
		compressed, err := compressCustom(data)
		if err == nil && len(compressed) < len(data) {
			return compressed, nil
		}
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

	case CompressionCustom:
		return decompressCustom(data) // Passe tout le data car la longueur est encodée

	default:
		return nil, ErrUnsupportedFormat
	}
}

// isCustomAlphabet vérifie si les données utilisent uniquement l'alphabet custom
func isCustomAlphabet(data []byte) bool {
	for _, b := range data {
		if _, ok := charToCode[b]; !ok {
			return false
		}
	}
	return true
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

// compressCustom compresse avec l'encodage 5-bits pour l'alphabet restreint
func compressCustom(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{CompressionCustom, 0, 0}, nil
	}

	// Format: flag + longueur (2 bytes) + données encodées
	result := make([]byte, 3, 3+(len(data)*5+7)/8)
	result[0] = CompressionCustom
	binary.BigEndian.PutUint16(result[1:3], uint16(len(data)))

	var bitBuffer uint16
	var bitsCount uint8

	for _, b := range data {
		code, ok := charToCode[b]
		if !ok {
			return nil, errors.New("invalid character for custom compression")
		}

		bitBuffer = (bitBuffer << 5) | uint16(code)
		bitsCount += 5

		// Écrire les bytes complets
		for bitsCount >= 8 {
			result = append(result, byte(bitBuffer>>(bitsCount-8)))
			bitsCount -= 8
			bitBuffer &= (1 << bitsCount) - 1
		}
	}

	// Écrire les bits restants
	if bitsCount > 0 {
		result = append(result, byte(bitBuffer<<(8-bitsCount)))
	}

	return result, nil
}

// decompressCustom décompresse l'encodage 5-bits
func decompressCustom(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, ErrInvalidFormat
	}

	length := binary.BigEndian.Uint16(data[1:3])
	encoded := data[3:]

	result := make([]byte, 0, length)
	var bitBuffer uint32
	var bitsCount uint8
	byteIndex := 0

	for len(result) < int(length) && byteIndex < len(encoded) {
		// Charger plus de bits si nécessaire
		for bitsCount < 5 && byteIndex < len(encoded) {
			bitBuffer = (bitBuffer << 8) | uint32(encoded[byteIndex])
			bitsCount += 8
			byteIndex++
		}

		if bitsCount < 5 {
			break
		}

		// Extraire 5 bits
		code := uint8(bitBuffer >> (bitsCount - 5))
		bitsCount -= 5
		bitBuffer &= (1 << bitsCount) - 1

		// Convertir en caractère
		char, ok := codeToChar[code]
		if !ok {
			return nil, ErrCorruptedData
		}

		result = append(result, char)
	}

	if len(result) != int(length) {
		return nil, ErrCorruptedData
	}

	return result, nil
}

// wrapWithFlag encapsule les données avec un flag de compression
func wrapWithFlag(data []byte, flag byte) []byte {
	result := make([]byte, 1+len(data))
	result[0] = flag
	copy(result[1:], data)
	return result
}
