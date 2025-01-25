package communication

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

func CompressData(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	defer writer.Close()

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
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

	return io.ReadAll(reader)
}
