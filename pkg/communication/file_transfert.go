package communication

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

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
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	// Préparation du HMAC
	hmacHash := hmac.New(sha3.New256, key[32:])

	buffer := make([]byte, bufferSize)
	for {
		n, err := inputFile.Read(buffer)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("erreur lecture fichier: %w", err)
		}
		if n == 0 {
			break
		}

		// Générer un nonce pour chaque bloc
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("erreur génération nonce: %w", err)
		}

		// Chiffrement du bloc
		encryptedBlock := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		// Combiner nonce + données chiffrées
		combined := append(nonce, encryptedBlock...)

		// Mise à jour du HMAC
		hmacHash.Write(combined)

		// Écrire la taille du bloc
		blockSize := make([]byte, 4)
		binary.BigEndian.PutUint32(blockSize, uint32(len(combined)))
		if _, err := outputFile.Write(blockSize); err != nil {
			return fmt.Errorf("erreur écriture taille bloc: %w", err)
		}

		// Écrire le bloc nonce + données chiffrées
		if _, err := outputFile.Write(combined); err != nil {
			return fmt.Errorf("erreur écriture bloc chiffré: %w", err)
		}
	}

	// Écrire le HMAC final
	hmacSum := hmacHash.Sum(nil)
	if _, err := outputFile.Write(hmacSum); err != nil {
		return fmt.Errorf("erreur écriture HMAC: %w", err)
	}

	return nil
}

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

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	// Lire tout le contenu du fichier
	fileData, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("erreur lecture données du fichier: %w", err)
	}

	// Extraire le HMAC (32 octets en fin de fichier)
	hmacSize := 32
	if len(fileData) < hmacSize {
		return fmt.Errorf("fichier trop court pour contenir HMAC")
	}
	hmacData := fileData[len(fileData)-hmacSize:]
	encryptedData := fileData[:len(fileData)-hmacSize]

	// Calcul du HMAC sur tous les blocs
	hmacHash := hmac.New(sha3.New256, key[32:])
	reader := bytes.NewReader(encryptedData)

	for {
		// Lecture de la taille du bloc
		blockSizeBytes := make([]byte, 4)
		_, err := io.ReadFull(reader, blockSizeBytes)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("erreur lecture taille bloc: %w", err)
		}

		size := binary.BigEndian.Uint32(blockSizeBytes)
		if size == 0 {
			return fmt.Errorf("taille de bloc invalide (0)")
		}

		// Lecture du bloc (nonce + données chiffrées)
		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return fmt.Errorf("erreur lecture bloc chiffré: %w", err)
		}

		// Mise à jour du HMAC
		hmacHash.Write(chunk)

		// Séparation du nonce et du ciphertext
		nonceSize := aesGCM.NonceSize()
		if len(chunk) < nonceSize {
			return fmt.Errorf("bloc trop court pour contenir le nonce")
		}
		nonce := chunk[:nonceSize]
		encryptedBlock := chunk[nonceSize:]

		// Déchiffrement
		decryptedBlock, err := aesGCM.Open(nil, nonce, encryptedBlock, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		// Écriture des données déchiffrées
		if _, err := outputFile.Write(decryptedBlock); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	// Vérification du HMAC final
	expectedHMAC := hmacHash.Sum(nil)
	if !hmac.Equal(expectedHMAC, hmacData) {
		return fmt.Errorf("HMAC invalide : fichier corrompu ou altéré")
	}

	return nil
}

func SecureFileTransfer(writer io.Writer, filePath string, key []byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("erreur ouverture fichier: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	buffer := make([]byte, 4096)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("erreur lecture fichier: %w", err)
		}
		if n == 0 {
			break
		}

		// Générer un nonce pour chaque bloc
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("erreur génération nonce: %w", err)
		}

		// Chiffrement du bloc
		encrypted := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		// Combinaison nonce + données chiffrées
		combined := append(nonce, encrypted...)

		// Écriture de la taille du bloc
		blockSize := make([]byte, 4)
		binary.BigEndian.PutUint32(blockSize, uint32(len(combined)))
		if _, err := writer.Write(blockSize); err != nil {
			return fmt.Errorf("erreur écriture taille bloc: %w", err)
		}

		// Écriture du bloc
		if _, err := writer.Write(combined); err != nil {
			return fmt.Errorf("erreur écriture bloc chiffré: %w", err)
		}
	}

	return nil
}

func ReceiveSecureFile(reader io.Reader, outputPath string, key []byte) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erreur création fichier: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	for {
		// Lecture de la taille du bloc
		blockSize := make([]byte, 4)
		if _, err := io.ReadFull(reader, blockSize); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("erreur lecture taille bloc: %w", err)
		}

		size := binary.BigEndian.Uint32(blockSize)
		if size == 0 {
			return fmt.Errorf("taille de bloc invalide (0)")
		}

		// Lecture du bloc (nonce + données chiffrées)
		combined := make([]byte, size)
		if _, err := io.ReadFull(reader, combined); err != nil {
			return fmt.Errorf("erreur lecture bloc chiffré: %w", err)
		}

		// Séparer le nonce et le ciphertext
		nonceSize := aesGCM.NonceSize()
		if len(combined) < nonceSize {
			return fmt.Errorf("bloc trop court pour contenir le nonce")
		}
		nonce := combined[:nonceSize]
		encrypted := combined[nonceSize:]

		// Déchiffrement
		decrypted, err := aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		// Écriture des données déchiffrées
		if _, err := file.Write(decrypted); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	return nil
}
