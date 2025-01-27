package tests

import (
	"bytes"
	"os"
	"protectora-rocher/pkg/communication"
	"testing"
)

var testKey = []byte("thisisaverysecurekeyforaes256!!thisisahmackey!!") // 64 octets

// TestEncryptFile vérifie le chiffrement d'un fichier.
func TestEncryptFile(t *testing.T) {
	// Création des fichiers temporaires
	inputFile := "test_input.txt"
	encryptedFile := "test_output.enc"

	// Nettoyage des fichiers après le test
	t.Cleanup(func() {
		os.Remove(inputFile)
		os.Remove(encryptedFile)
	})

	err := os.WriteFile(inputFile, []byte("Ceci est un test pour le chiffrement de fichier."), 0644)
	if err != nil {
		t.Fatalf("Erreur lors de la création du fichier d'entrée: %v", err)
	}

	// Chiffrement
	err = communication.EncryptFile(inputFile, encryptedFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors du chiffrement du fichier: %v", err)
	}

	// Vérification de l'existence du fichier chiffré
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatal("Le fichier chiffré n'a pas été créé.")
	}
}

// TestDecryptFile vérifie le déchiffrement d'un fichier.
func TestDecryptFile(t *testing.T) {
	// Création des fichiers temporaires
	inputFile := "test_input.txt"
	encryptedFile := "test_output.enc"
	decryptedFile := "test_decrypted.txt"

	// Nettoyage des fichiers après le test
	t.Cleanup(func() {
		os.Remove(inputFile)
		os.Remove(encryptedFile)
		os.Remove(decryptedFile)
	})

	err := os.WriteFile(inputFile, []byte("Ceci est un test pour le chiffrement de fichier."), 0644)
	if err != nil {
		t.Fatalf("Erreur lors de la création du fichier d'entrée: %v", err)
	}

	// Chiffrement
	err = communication.EncryptFile(inputFile, encryptedFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors du chiffrement du fichier: %v", err)
	}

	// Vérification que le fichier chiffré existe et n'est pas vide
	fileInfo, err := os.Stat(encryptedFile)
	if err != nil {
		t.Fatalf("Erreur lors de la vérification du fichier chiffré: %v", err)
	}
	if fileInfo.Size() <= 0 {
		t.Fatal("Le fichier chiffré est vide.")
	}

	// Déchiffrement
	err = communication.DecryptFile(encryptedFile, decryptedFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors du déchiffrement du fichier: %v", err)
	}

	// Vérification du contenu
	content, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Erreur lors de la lecture du fichier déchiffré: %v", err)
	}
	expectedContent := "Ceci est un test pour le chiffrement de fichier."
	if string(content) != expectedContent {
		t.Errorf("Contenu déchiffré incorrect. Attendu: %q, obtenu: %q", expectedContent, string(content))
	}
}

// TestSecureFileTransfer vérifie le transfert sécurisé d'un fichier.
func TestSecureFileTransfer(t *testing.T) {
	// Création des fichiers temporaires
	inputFile := "test_input.txt"
	outputFile := "test_output.txt"

	// Nettoyage des fichiers après le test
	t.Cleanup(func() {
		os.Remove(inputFile)
		os.Remove(outputFile)
	})

	err := os.WriteFile(inputFile, []byte("Test de transfert sécurisé de fichier."), 0644)
	if err != nil {
		t.Fatalf("Erreur lors de la création du fichier d'entrée: %v", err)
	}

	var buffer bytes.Buffer

	// Transfert sécurisé
	err = communication.SecureFileTransfer(&buffer, inputFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors du transfert sécurisé du fichier: %v", err)
	}

	// Réception sécurisée
	err = communication.ReceiveSecureFile(&buffer, outputFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors de la réception sécurisée du fichier: %v", err)
	}

	// Vérification du contenu
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Erreur lors de la lecture du fichier reçu: %v", err)
	}
	expectedContent := "Test de transfert sécurisé de fichier."
	if string(content) != expectedContent {
		t.Errorf("Contenu du fichier reçu incorrect. Attendu: %q, obtenu: %q", expectedContent, string(content))
	}
}

// TestCorruptedFileDetection vérifie la détection des fichiers corrompus.
func TestCorruptedFileDetection(t *testing.T) {
	// Création des fichiers temporaires
	inputFile := "test_input.txt"
	encryptedFile := "test_output.enc"

	// Nettoyage des fichiers après le test
	t.Cleanup(func() {
		os.Remove(inputFile)
		os.Remove(encryptedFile)
	})

	err := os.WriteFile(inputFile, []byte("Test de détection de fichier corrompu."), 0644)
	if err != nil {
		t.Fatalf("Erreur lors de la création du fichier d'entrée: %v", err)
	}

	// Chiffrement
	err = communication.EncryptFile(inputFile, encryptedFile, testKey)
	if err != nil {
		t.Fatalf("Erreur lors du chiffrement du fichier: %v", err)
	}

	// Corruption du fichier chiffré
	file, err := os.OpenFile(encryptedFile, os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Erreur lors de l'ouverture du fichier pour corruption: %v", err)
	}
	defer file.Close()

	_, err = file.WriteAt([]byte("corruption"), 10) // Écrit un texte corrompu à l'offset 10
	if err != nil {
		t.Fatalf("Erreur lors de la corruption du fichier: %v", err)
	}

	// Déchiffrement attendu comme invalide
	err = communication.DecryptFile(encryptedFile, "corrupted_output.txt", testKey)
	if err == nil {
		t.Error("Le fichier corrompu a été accepté alors qu'il aurait dû être rejeté.")
	}

	// Suppression manuelle du fichier corrompu
	t.Cleanup(func() {
		os.Remove("corrupted_output.txt")
	})
}
