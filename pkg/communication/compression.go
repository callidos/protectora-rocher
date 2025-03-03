package communication

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Flags pour indiquer la méthode de compression utilisée.
const (
	CompressionNoneFlag    byte = 0 // Données non compressées
	CompressionZstdFlag    byte = 1 // Compression avec Zstandard (avec checksum)
	CompressionSpecialFlag byte = 2 // Compression spécialisée (encodage fixe sur 5 bits)
)

// Seuil minimal pour tenter la compression spécialisée.
const SpecializedMinLength = 16

var (
	encoderPool sync.Pool
	decoderPool sync.Pool

	// Alphabet autorisé pour la compression spécialisée.
	// On autorise l'espace, les 26 lettres minuscules et 4 signes de ponctuation (',', '.', '!', '?').
	// Total : 1 + 26 + 4 = 31 symboles, qui tiennent en 5 bits.
	allowedAlphabet = " abcdefghijklmnopqrstuvwxyz,.!?"
	// Tables d'encodage et de décodage.
	charToCode map[byte]uint8
	codeToChar map[uint8]byte
)

func init() {
	// Initialisation du pool pour l'encodeur Zstandard (sans option de checksum puisque nous le faisons manuellement).
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		panic(fmt.Sprintf("failed to create zstd encoder: %v", err))
	}
	encoderPool = sync.Pool{
		New: func() interface{} {
			enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
			if err != nil {
				panic(err)
			}
			return enc
		},
	}
	encoderPool.Put(enc)

	dec, err := zstd.NewReader(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create zstd decoder: %v", err))
	}
	decoderPool = sync.Pool{
		New: func() interface{} {
			dec, err := zstd.NewReader(nil)
			if err != nil {
				panic(err)
			}
			return dec
		},
	}
	decoderPool.Put(dec)

	charToCode = make(map[byte]uint8)
	codeToChar = make(map[uint8]byte)
	for i := 0; i < len(allowedAlphabet); i++ {
		b := allowedAlphabet[i]
		charToCode[b] = uint8(i)
		codeToChar[uint8(i)] = b
	}
}

func isEligibleForSpecial(data []byte) bool {
	for _, b := range data {
		if _, ok := charToCode[b]; !ok {
			return false
		}
	}
	return true
}

func specializedSmallCompress(data []byte) ([]byte, error) {
	n := len(data)
	out := make([]byte, 0, 3+(n*5+7)/8)
	out = append(out, CompressionSpecialFlag)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(n))
	out = append(out, lenBytes...)

	var bitBuffer uint16
	var bitsInBuffer uint8

	for _, b := range data {
		code, ok := charToCode[b]
		if !ok {
			return nil, fmt.Errorf("character %q not in allowed alphabet", b)
		}
		bitBuffer = (bitBuffer << 5) | uint16(code)
		bitsInBuffer += 5
		for bitsInBuffer >= 8 {
			bitsInBuffer -= 8
			byteVal := byte(bitBuffer >> bitsInBuffer)
			out = append(out, byteVal)
			bitBuffer &= (1 << bitsInBuffer) - 1
		}
	}
	if bitsInBuffer > 0 {
		byteVal := byte(bitBuffer << (8 - bitsInBuffer))
		out = append(out, byteVal)
	}
	return out, nil
}

func specializedSmallDecompress(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("data too short for specialized decompression")
	}
	n := binary.BigEndian.Uint16(data[1:3])
	bitStream := data[3:]
	out := make([]byte, 0, n)
	var bitBuffer uint32
	var bitsInBuffer uint8
	streamIndex := 0

	for uint(len(out)) < uint(n) {
		if bitsInBuffer < 5 && streamIndex < len(bitStream) {
			bitBuffer = (bitBuffer << 8) | uint32(bitStream[streamIndex])
			bitsInBuffer += 8
			streamIndex++
		}
		if bitsInBuffer < 5 {
			return nil, fmt.Errorf("not enough bits to decode symbol")
		}
		shift := bitsInBuffer - 5
		code := uint8(bitBuffer >> shift)
		bitBuffer &= (1 << shift) - 1
		bitsInBuffer -= 5

		char, ok := codeToChar[code]
		if !ok {
			return nil, fmt.Errorf("invalid code %d in specialized decompression", code)
		}
		out = append(out, char)
	}
	return out, nil
}

func CompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{CompressionNoneFlag}, nil
	}

	if len(data) >= SpecializedMinLength && isEligibleForSpecial(data) {
		special, err := specializedSmallCompress(data)
		if err == nil && len(special) < len(data) {
			return special, nil
		}
	}

	encoder := encoderPool.Get().(*zstd.Encoder)
	compressed := encoder.EncodeAll(data, nil)
	encoderPool.Put(encoder)

	if len(compressed) >= len(data) {
		result := make([]byte, 1+len(data))
		result[0] = CompressionNoneFlag
		copy(result[1:], data)
		return result, nil
	}

	crc := crc32.ChecksumIEEE(compressed)
	crcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBytes, crc)

	result := make([]byte, 1+4+len(compressed))
	result[0] = CompressionZstdFlag
	copy(result[1:5], crcBytes)
	copy(result[5:], compressed)
	return result, nil
}

func DecompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("compressed data is empty")
	}
	flag := data[0]
	payload := data[1:]
	switch flag {
	case CompressionNoneFlag:
		return payload, nil
	case CompressionZstdFlag:
		if len(payload) < 4 {
			return nil, fmt.Errorf("payload too short for CRC")
		}
		storedCRC := binary.BigEndian.Uint32(payload[:4])
		actualCompressed := payload[4:]
		computedCRC := crc32.ChecksumIEEE(actualCompressed)
		if storedCRC != computedCRC {
			return nil, fmt.Errorf("checksum mismatch: stored %08x, computed %08x", storedCRC, computedCRC)
		}
		decoder := decoderPool.Get().(*zstd.Decoder)
		out, err := decoder.DecodeAll(actualCompressed, nil)
		decoderPool.Put(decoder)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
		return out, nil
	case CompressionSpecialFlag:
		return specializedSmallDecompress(data)
	default:
		return nil, fmt.Errorf("unknown compression flag: %d", flag)
	}
}
