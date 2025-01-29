package communication

import (
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

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("erreur génération nonce: %w", err)
	}

	if _, err := outputFile.Write(nonce); err != nil {
		return fmt.Errorf("erreur écriture nonce: %w", err)
	}

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

		encrypted := aesGCM.Seal(nil, nonce, buffer[:n], nil)
		hmacHash.Write(encrypted)

		// Écrire la taille du bloc chiffré avant les données
		blockSize := make([]byte, 4)
		binary.BigEndian.PutUint32(blockSize, uint32(len(encrypted)))
		if _, err := outputFile.Write(blockSize); err != nil {
			return fmt.Errorf("erreur écriture taille bloc: %w", err)
		}

		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("erreur écriture bloc chiffré: %w", err)
		}
	}

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

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(inputFile, nonce); err != nil {
		return fmt.Errorf("erreur lecture nonce: %w", err)
	}

	hmacHash := hmac.New(sha3.New256, key[32:])
	for {
		blockSize := make([]byte, 4)
		if _, err := io.ReadFull(inputFile, blockSize); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("erreur lecture taille bloc: %w", err)
		}

		size := binary.BigEndian.Uint32(blockSize)
		encrypted := make([]byte, size)
		if _, err := io.ReadFull(inputFile, encrypted); err != nil {
			return fmt.Errorf("erreur lecture bloc chiffré: %w", err)
		}

		hmacHash.Write(encrypted)

		decrypted, err := aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		if _, err := outputFile.Write(decrypted); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	expectedHMAC := hmacHash.Sum(nil)
	fileHMAC := make([]byte, len(expectedHMAC))
	if _, err := io.ReadFull(inputFile, fileHMAC); err != nil {
		return fmt.Errorf("erreur lecture HMAC: %w", err)
	}
	if !hmac.Equal(expectedHMAC, fileHMAC) {
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

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("erreur génération nonce: %w", err)
	}

	if _, err := writer.Write(nonce); err != nil {
		return fmt.Errorf("erreur écriture nonce: %w", err)
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

		encrypted := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		blockSize := make([]byte, 4)
		binary.BigEndian.PutUint32(blockSize, uint32(len(encrypted)))
		if _, err := writer.Write(blockSize); err != nil {
			return fmt.Errorf("erreur écriture taille bloc: %w", err)
		}
		if _, err := writer.Write(encrypted); err != nil {
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

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return fmt.Errorf("erreur lecture nonce: %w", err)
	}

	for {
		blockSize := make([]byte, 4)
		if _, err := io.ReadFull(reader, blockSize); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("erreur lecture taille bloc: %w", err)
		}

		size := binary.BigEndian.Uint32(blockSize)
		encrypted := make([]byte, size)
		if _, err := io.ReadFull(reader, encrypted); err != nil {
			return fmt.Errorf("erreur lecture bloc chiffré: %w", err)
		}

		decrypted, err := aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		if _, err := file.Write(decrypted); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	return nil
}
