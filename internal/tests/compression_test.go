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
	compressedData, err := communication.CompressData(nil)
	if err != nil {
		t.Fatalf("Compression failed for empty data: %v", err)
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
			corruptedData := compressedData[:len(compressedData)-1] // Corrupt the data
			_, err = communication.DecompressData(corruptedData)
			if err == nil {
				t.Error("Expected failure for corrupted input, but decompression succeeded")
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
