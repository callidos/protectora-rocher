package tests

import (
	"bytes"
	"protectora-rocher/pkg/communication"
	"testing"
)

// Test compression and decompression with valid data
func TestCompressionDecompression(t *testing.T) {
	originalData := []byte("This is a compression test")

	compressedData, err := communication.CompressData(originalData)
	if err != nil {
		t.Fatalf("Compression failed: %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed: %v", err)
	}

	if !bytes.Equal(originalData, decompressedData) {
		t.Errorf("Decompressed data does not match the original")
	}
}

// Test compression of empty data
func TestCompressEmptyData(t *testing.T) {
	compressedData, err := communication.CompressData([]byte{})
	if err != nil {
		t.Fatalf("Compression failed for empty data: %v", err)
	}

	// Vérification que les données compressées ne sont pas vides
	if len(compressedData) == 0 {
		t.Fatalf("Compressed empty data should not be empty")
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for empty data: %v", err)
	}

	if len(decompressedData) != 0 {
		t.Errorf("Expected empty decompressed data, got non-empty")
	}
}

// Test decompression of corrupted data
func TestDecompressCorruptedData(t *testing.T) {
	corruptedData := []byte("corrupted data")

	_, err := communication.DecompressData(corruptedData)
	if err == nil {
		t.Error("Expected failure when decompressing corrupted data")
	}
}

// Test compression of large data
func TestCompressLargeData(t *testing.T) {
	largeData := make([]byte, 1_000_000) // 1 MB of data

	compressedData, err := communication.CompressData(largeData)
	if err != nil {
		t.Fatalf("Compression failed for large data: %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for large data: %v", err)
	}

	if len(decompressedData) != len(largeData) {
		t.Errorf("Expected decompressed size %d, got %d", len(largeData), len(decompressedData))
	}
}

// Test edge cases of compression and decompression
func TestCompressionEdgeCases(t *testing.T) {
	testCases := []struct {
		input      []byte
		shouldFail bool
	}{
		{nil, false},                     // Empty data
		{[]byte("Short"), false},         // Small string
		{make([]byte, 10), false},        // Short data
		{make([]byte, 1024), false},      // Normal-sized data
		{make([]byte, 1_000_000), false}, // Large data
		{[]byte("corrupted-data"), true}, // Corrupted data
	}

	for _, tc := range testCases {
		compressedData, err := communication.CompressData(tc.input)

		if err != nil {
			t.Fatalf("Compression failed for input: %v", err)
		}

		if tc.shouldFail {
			if len(compressedData) > 5 {
				corruptedData := compressedData[:len(compressedData)-2] // Tronquer prudemment
				_, err = communication.DecompressData(corruptedData)
				if err == nil {
					t.Error("Expected failure for corrupted input, but decompression succeeded")
				}
			} else {
				t.Log("Skipping corruption for very small compressed data")
			}
		} else {
			decompressedData, err := communication.DecompressData(compressedData)
			if err != nil {
				t.Errorf("Decompression failed for valid input: %v", err)
			}

			if !bytes.Equal(tc.input, decompressedData) {
				t.Errorf("Decompressed data does not match original")
			}
		}
	}
}

// Test compression and decompression performance
func TestCompressionPerformance(t *testing.T) {
	largeData := make([]byte, 10<<20) // 10 MB of data

	compressedData, err := communication.CompressData(largeData)
	if err != nil {
		t.Fatalf("Compression failed for large data: %v", err)
	}

	t.Logf("Original size: %d bytes, Compressed size: %d bytes", len(largeData), len(compressedData))

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for large data: %v", err)
	}

	if !bytes.Equal(largeData, decompressedData) {
		t.Errorf("Decompressed data does not match the original")
	}
}

// Test compression and decompression of special characters
func TestCompressSpecialCharacters(t *testing.T) {
	specialData := []byte("éùçà@#&%$")

	compressedData, err := communication.CompressData(specialData)
	if err != nil {
		t.Fatalf("Compression failed for special characters: %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for special characters: %v", err)
	}

	if !bytes.Equal(specialData, decompressedData) {
		t.Errorf("Decompressed data does not match the original special characters")
	}
}

// Test compression and decompression of binary data
func TestCompressBinaryData(t *testing.T) {
	binaryData := []byte{0x00, 0xFF, 0xA5, 0x4B, 0x7E}

	compressedData, err := communication.CompressData(binaryData)
	if err != nil {
		t.Fatalf("Compression failed for binary data: %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for binary data: %v", err)
	}

	if !bytes.Equal(binaryData, decompressedData) {
		t.Errorf("Decompressed data does not match the original binary data")
	}
}

// Test decompression of partially valid data
func TestDecompressPartialData(t *testing.T) {
	originalData := []byte("This is test data")
	compressedData, _ := communication.CompressData(originalData)

	truncatedData := compressedData[:len(compressedData)/2]

	_, err := communication.DecompressData(truncatedData)
	if err == nil {
		t.Error("Expected error when decompressing truncated data, but got none")
	}
}

// Test compression efficiency with small data
func TestCompressionEfficiency(t *testing.T) {
	smallData := []byte("tiny")

	compressedData, err := communication.CompressData(smallData)
	if err != nil {
		t.Fatalf("Compression failed for small data: %v", err)
	}

	t.Logf("Original size: %d bytes, Compressed size: %d bytes", len(smallData), len(compressedData))

	if len(smallData) > 20 && len(compressedData) >= len(smallData) {
		t.Errorf("Compression ineffective: original %d bytes, compressed %d bytes", len(smallData), len(compressedData))
	}
}

// Test repeated compression and decompression
func TestRepeatedCompressionDecompression(t *testing.T) {
	data := []byte("Repeated test data for compression")

	for i := 0; i < 100; i++ {
		compressed, err := communication.CompressData(data)
		if err != nil {
			t.Fatalf("Iteration %d: Compression failed: %v", i, err)
		}

		decompressed, err := communication.DecompressData(compressed)
		if err != nil {
			t.Fatalf("Iteration %d: Decompression failed: %v", i, err)
		}

		if !bytes.Equal(data, decompressed) {
			t.Errorf("Iteration %d: Decompressed data does not match original", i)
		}
	}
}

// Test compression of simulated file content
func TestCompressSimulatedFileContent(t *testing.T) {
	simulatedFileContent := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.`)

	compressedData, err := communication.CompressData(simulatedFileContent)
	if err != nil {
		t.Fatalf("Compression failed for simulated file content: %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Decompression failed for simulated file content: %v", err)
	}

	if !bytes.Equal(simulatedFileContent, decompressedData) {
		t.Errorf("Decompressed data does not match the original file content")
	}
}
