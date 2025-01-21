package communication

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// CompressData compresse les données en utilisant Gzip
func CompressData(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)

	_, err := writer.Write(data)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("erreur lors de la compression: %v", err)
	}
	writer.Close()

	return buffer.Bytes(), nil
}

// DecompressData décompresse les données Gzip
func DecompressData(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création du lecteur de décompression: %v", err)
	}
	defer reader.Close()

	uncompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture des données décompressées: %v", err)
	}

	return uncompressedData, nil
}
