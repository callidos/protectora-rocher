package communication

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

func CompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("failed to close gzip writer: %w", err)
		}
		return buffer.Bytes(), nil
	}

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buffer.Bytes(), nil
}

func DecompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("compressed data is empty")
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	uncompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return uncompressedData, nil
}
