package tests

import (
	"bytes"
	"protectora-rocher/pkg/communication"
	"testing"
)

// Test de compression et décompression avec des données valides
func TestCompressionDecompression(t *testing.T) {
	originalData := []byte("Ceci est un test de compression")

	compressedData, err := communication.CompressData(originalData)
	if err != nil {
		t.Fatalf("Erreur lors de la compression : %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Erreur lors de la décompression : %v", err)
	}

	if !bytes.Equal(originalData, decompressedData) {
		t.Errorf("Les données décompressées ne correspondent pas aux originales")
	}
}

// Test de compression de données vides
func TestCompressEmptyData(t *testing.T) {
	data := []byte{}

	compressedData, err := communication.CompressData(data)
	if err != nil {
		t.Fatalf("Erreur lors de la compression de données vides : %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Erreur lors de la décompression de données vides : %v", err)
	}

	if len(decompressedData) != 0 {
		t.Errorf("La décompression de données vides devrait donner une sortie vide")
	}
}

// Test de décompression de données corrompues
func TestDecompressCorruptedData(t *testing.T) {
	corruptedData := []byte("données corrompues")

	_, err := communication.DecompressData(corruptedData)
	if err == nil {
		t.Errorf("La décompression de données corrompues devrait échouer")
	}
}

// Test de compression de données volumineuses
func TestCompressLargeData(t *testing.T) {
	largeData := make([]byte, 1000000) // 1 Mo de données

	compressedData, err := communication.CompressData(largeData)
	if err != nil {
		t.Fatalf("Erreur lors de la compression de grandes données : %v", err)
	}

	decompressedData, err := communication.DecompressData(compressedData)
	if err != nil {
		t.Fatalf("Erreur lors de la décompression de grandes données : %v", err)
	}

	if len(decompressedData) != len(largeData) {
		t.Errorf("Les données décompressées ne correspondent pas à la taille originale")
	}
}
