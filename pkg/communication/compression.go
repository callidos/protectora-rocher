package communication

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// CompressData compresse les données de manière asynchrone et renvoie un canal de résultat.
func CompressData(data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)

		_, err := writer.Write(data)
		if err != nil {
			errorChan <- fmt.Errorf("erreur lors de la compression: %v", err)
			return
		}
		writer.Close()

		resultChan <- buffer.Bytes()
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}

// DecompressData décompresse les données de manière asynchrone et renvoie un canal de résultat.
func DecompressData(data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			errorChan <- fmt.Errorf("erreur lors de la création du lecteur de décompression: %v", err)
			return
		}
		defer reader.Close()

		uncompressedData, err := io.ReadAll(reader)
		if err != nil {
			errorChan <- fmt.Errorf("erreur lors de la lecture des données décompressées: %v", err)
			return
		}

		resultChan <- uncompressedData
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
