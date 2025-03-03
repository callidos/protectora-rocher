package tests

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// TestCompressionDecompression vérifie que la décompression restitue les données originales.
func TestCompressionDecompression(t *testing.T) {
	originalData := []byte("this is a compression test")

	start := time.Now()
	compressedData, err := communication.CompressData(originalData)
	compressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Compression failed: %v", err)
	}
	t.Logf("Compression time: %v", compressDuration)

	start = time.Now()
	decompressedData, err := communication.DecompressData(compressedData)
	decompressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Decompression failed: %v", err)
	}
	t.Logf("Decompression time: %v", decompressDuration)

	if !bytes.Equal(originalData, decompressedData) {
		t.Errorf("Decompressed data does not match the original")
	}
}

// TestCompressEmptyData teste la compression d'une donnée vide.
func TestCompressEmptyData(t *testing.T) {
	start := time.Now()
	compressedData, err := communication.CompressData([]byte{})
	compressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Compression failed for empty data: %v", err)
	}
	t.Logf("Compression time for empty data: %v", compressDuration)

	if len(compressedData) == 0 {
		t.Fatalf("Compressed empty data should not be empty")
	}

	start = time.Now()
	decompressedData, err := communication.DecompressData(compressedData)
	decompressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Decompression failed for empty data: %v", err)
	}
	t.Logf("Decompression time for empty data: %v", decompressDuration)

	if len(decompressedData) != 0 {
		t.Errorf("Expected empty decompressed data, got non-empty")
	}
}

// TestDecompressCorruptedData teste la décompression de données corrompues.
func TestDecompressCorruptedData(t *testing.T) {
	corruptedData := []byte("corrupted data")
	_, err := communication.DecompressData(corruptedData)
	if err == nil {
		t.Error("Expected failure when decompressing corrupted data")
	}
}

// TestCompressLargeData teste la compression et décompression de grandes données.
func TestCompressLargeData(t *testing.T) {
	largeData := make([]byte, 1_000_000)

	start := time.Now()
	compressedData, err := communication.CompressData(largeData)
	compressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Compression failed for large data: %v", err)
	}
	t.Logf("Compression time for large data: %v", compressDuration)

	start = time.Now()
	decompressedData, err := communication.DecompressData(compressedData)
	decompressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Decompression failed for large data: %v", err)
	}
	t.Logf("Decompression time for large data: %v", decompressDuration)

	if len(decompressedData) != len(largeData) {
		t.Errorf("Expected decompressed size %d, got %d", len(largeData), len(decompressedData))
	}
}

// TestCompressionEdgeCases teste divers cas limites.
func TestCompressionEdgeCases(t *testing.T) {
	testCases := []struct {
		input      []byte
		shouldFail bool
	}{
		{nil, false},                      // Données vides
		{[]byte("short"), false},          // Chaîne courte admissible
		{make([]byte, 10), false},         // Données de 10 octets
		{[]byte("this is a test"), false}, // Texte admissible
		{make([]byte, 1_000_000), false},  // Données grandes
		{[]byte(strings.Repeat("A", 100)), true},
	}

	for idx, tc := range testCases {
		start := time.Now()
		compressedData, err := communication.CompressData(tc.input)
		compressDuration := time.Since(start)
		if err != nil {
			t.Fatalf("Test case %d: Compression failed: %v", idx, err)
		}
		t.Logf("Test case %d: Compression time: %v", idx, compressDuration)

		if tc.shouldFail {
			if len(compressedData) > 5 {
				// Simulation de troncature pour provoquer une erreur.
				corruptedData := compressedData[:len(compressedData)-2]
				_, err = communication.DecompressData(corruptedData)
				if err == nil {
					t.Error("Expected failure for corrupted input, but decompression succeeded")
				}
			} else {
				t.Log("Skipping corruption for very small compressed data")
			}
		} else {
			start = time.Now()
			decompressedData, err := communication.DecompressData(compressedData)
			decompressDuration := time.Since(start)
			if err != nil {
				t.Errorf("Test case %d: Decompression failed: %v", idx, err)
			}
			t.Logf("Test case %d: Decompression time: %v", idx, decompressDuration)

			if !bytes.Equal(tc.input, decompressedData) {
				t.Errorf("Test case %d: Decompressed data does not match original", idx)
			}
		}
	}
}

// TestCompressionPerformance mesure la performance sur un gros volume.
func TestCompressionPerformance(t *testing.T) {
	largeData := make([]byte, 10<<20) // 10 MB de données

	start := time.Now()
	compressedData, err := communication.CompressData(largeData)
	compressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Compression failed for large data: %v", err)
	}

	t.Logf("Original size: %d bytes, Compressed size: %d bytes", len(largeData), len(compressedData))
	t.Logf("Compression time: %v", compressDuration)

	start = time.Now()
	decompressedData, err := communication.DecompressData(compressedData)
	decompressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Decompression failed for large data: %v", err)
	}
	t.Logf("Decompression time: %v", decompressDuration)

	if !bytes.Equal(largeData, decompressedData) {
		t.Errorf("Decompressed data does not match the original")
	}
}

// TestSpecializedCompression teste la compression spécialisée pour de petits messages admissibles.
func TestSpecializedCompression(t *testing.T) {
	originalData := []byte("hello, world!")
	if len(originalData) < communication.SpecializedMinLength {
		originalData = append(originalData, []byte(" this is extended")...)
	}

	start := time.Now()
	compressedData, err := communication.CompressData(originalData)
	compressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Specialized compression failed: %v", err)
	}
	t.Logf("Specialized compression time: %v", compressDuration)

	if len(compressedData) > 0 && compressedData[0] != communication.CompressionSpecialFlag {
		t.Logf("Specialized compression non utilisée, flag=%d", compressedData[0])
	} else {
		t.Log("Specialized compression utilisée")
		if len(compressedData) < 3 {
			t.Fatalf("Compressed data too short for specialized header")
		}
		lengthFromHeader := binary.BigEndian.Uint16(compressedData[1:3])
		if int(lengthFromHeader) != len(originalData) {
			t.Errorf("Header length %d does not match original length %d", lengthFromHeader, len(originalData))
		}
	}

	start = time.Now()
	decompressedData, err := communication.DecompressData(compressedData)
	decompressDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Specialized decompression failed: %v", err)
	}
	t.Logf("Specialized decompression time: %v", decompressDuration)

	if !bytes.Equal(originalData, decompressedData) {
		t.Errorf("Specialized decompressed data does not match the original")
	}
}

// TestRepeatedCompressionDecompression teste la compression/décompression répétée.
func TestRepeatedCompressionDecompression(t *testing.T) {
	data := []byte("repeated test data for compression")
	var totalCompressTime, totalDecompressTime time.Duration

	for i := 0; i < 100; i++ {
		start := time.Now()
		compressed, err := communication.CompressData(data)
		totalCompressTime += time.Since(start)
		if err != nil {
			t.Fatalf("Iteration %d: Compression failed: %v", i, err)
		}

		start = time.Now()
		decompressed, err := communication.DecompressData(compressed)
		totalDecompressTime += time.Since(start)
		if err != nil {
			t.Fatalf("Iteration %d: Decompression failed: %v", i, err)
		}

		if !bytes.Equal(data, decompressed) {
			t.Errorf("Iteration %d: Decompressed data does not match original", i)
		}
	}
	t.Logf("Average compression time: %v", totalCompressTime/100)
	t.Logf("Average decompression time: %v", totalDecompressTime/100)
}
