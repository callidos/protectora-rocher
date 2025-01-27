package communication

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// EncryptFile chiffre un fichier et l'écrit dans un fichier de sortie sécurisé.
func EncryptFile(inputPath, outputPath string, key []byte) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("erreur ouverture fichier source: %w", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erreur création fichier chiffré: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur création du chiffrement AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur d'initialisation de GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("erreur génération du nonce: %w", err)
	}

	_, err = outputFile.Write(nonce)
	if err != nil {
		return fmt.Errorf("erreur écriture nonce: %w", err)
	}

	hmacHash := hmac.New(sha3.New256, key[32:])
	buffer := make([]byte, 4096)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("erreur lecture fichier: %w", err)
		}
		if n == 0 {
			break
		}

		encryptedData := aesGCM.Seal(nil, nonce, buffer[:n], nil)
		hmacHash.Write(encryptedData)

		_, err = outputFile.Write(encryptedData)
		if err != nil {
			return fmt.Errorf("erreur écriture données chiffrées: %w", err)
		}
	}

	hmacSum := hmacHash.Sum(nil)
	_, err = outputFile.Write(hmacSum)
	if err != nil {
		return fmt.Errorf("erreur écriture HMAC: %w", err)
	}

	return nil
}

// DecryptFile déchiffre un fichier chiffré et le sauvegarde en clair.
func DecryptFile(inputPath, outputPath string, key []byte) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("erreur ouverture fichier chiffré: %w", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erreur création fichier déchiffré: %w", err)
	}
	defer outputFile.Close()

	// Initialisation du chiffrement AES-GCM
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur création du chiffrement AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur d'initialisation de GCM: %w", err)
	}

	// Lecture du nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(inputFile, nonce); err != nil {
		return fmt.Errorf("erreur lecture nonce: %w", err)
	}

	// Lecture des données chiffrées jusqu'au HMAC
	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("erreur récupération informations fichier: %w", err)
	}

	hmacSize := sha3.New256().Size()
	dataSize := fileInfo.Size() - int64(len(nonce)) - int64(hmacSize)

	if dataSize <= 0 {
		return fmt.Errorf("fichier corrompu ou incomplet : données insuffisantes")
	}

	chunk := make([]byte, 4096)
	hmacHash := hmac.New(sha3.New256, key[32:])
	for dataSize > 0 {
		readSize := int64(len(chunk))
		if dataSize < readSize {
			readSize = dataSize
		}

		n, err := inputFile.Read(chunk[:readSize])
		if err != nil && err != io.EOF {
			return fmt.Errorf("erreur lecture fichier chiffré: %w", err)
		}
		if n == 0 {
			break
		}

		hmacHash.Write(chunk[:n])

		decryptedData, err := aesGCM.Open(nil, nonce, chunk[:n], nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement données: %w", err)
		}

		if _, err := outputFile.Write(decryptedData); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}

		dataSize -= int64(n)
	}

	// Lecture et vérification du HMAC
	expectedHMAC := hmacHash.Sum(nil)
	fileHMAC := make([]byte, len(expectedHMAC))
	if _, err := inputFile.Read(fileHMAC); err != nil {
		return fmt.Errorf("erreur lecture HMAC: %w", err)
	}

	if !hmac.Equal(expectedHMAC, fileHMAC) {
		return fmt.Errorf("HMAC invalide : données corrompues ou altérées")
	}

	return nil
}

// SecureFileTransfer envoie un fichier via une connexion sécurisée.
func SecureFileTransfer(writer io.Writer, filePath string, key []byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("erreur ouverture fichier: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 4096)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("erreur lecture fichier: %w", err)
		}
		if n == 0 {
			break
		}

		encryptedData, err := EncryptAESGCM(buffer[:n], key)
		if err != nil {
			return fmt.Errorf("erreur chiffrement: %w", err)
		}

		writer.Write([]byte(encryptedData + "\n"))
	}
	return nil
}

// ReceiveSecureFile réceptionne un fichier via une connexion sécurisée.
func ReceiveSecureFile(reader io.Reader, outputPath string, key []byte) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erreur création fichier: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		decryptedData, err := DecryptAESGCM(scanner.Text(), key)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}
		file.Write(decryptedData)
	}
	return nil
}
