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
	"sync"

	"golang.org/x/crypto/sha3"
)

// EncryptFile chiffre un fichier et écrit un fichier sécurisé.
func EncryptFile(inputPath, outputPath string, key []byte) error {
	// Ouverture des fichiers
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

	// Initialisation AES-GCM
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

	// Écriture du nonce dans le fichier
	if _, err := outputFile.Write(nonce); err != nil {
		return fmt.Errorf("erreur écriture nonce: %w", err)
	}

	hmacHash := hmac.New(sha3.New256, key[32:])
	var wg sync.WaitGroup
	dataChan := make(chan []byte, 4)
	errChan := make(chan error, 1)

	// Lecture et chiffrement en goroutines
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(dataChan)

		buffer := make([]byte, bufferSize)
		for {
			n, err := inputFile.Read(buffer)
			if err != nil && !errors.Is(err, io.EOF) {
				errChan <- fmt.Errorf("erreur lecture fichier: %w", err)
				return
			}
			if n == 0 {
				break
			}

			// Chiffrement du bloc
			encrypted := aesGCM.Seal(nil, nonce, buffer[:n], nil)
			hmacHash.Write(encrypted)
			dataChan <- encrypted
		}
	}()

	// Écriture des blocs chiffrés
	wg.Add(1)
	go func() {
		defer wg.Done()
		for data := range dataChan {
			if _, err := outputFile.Write(data); err != nil {
				errChan <- fmt.Errorf("erreur écriture fichier: %w", err)
				return
			}
		}
	}()

	// Attendre la fin des goroutines
	wg.Wait()
	close(errChan)

	// Vérification des erreurs
	if err := <-errChan; err != nil {
		return err
	}

	// Écriture du HMAC
	hmacSum := hmacHash.Sum(nil)
	if _, err := outputFile.Write(hmacSum); err != nil {
		return fmt.Errorf("erreur écriture HMAC: %w", err)
	}

	return nil
}

// DecryptFile déchiffre un fichier et vérifie son intégrité.
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

	// Initialisation AES-GCM
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	// Lecture du nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(inputFile, nonce); err != nil {
		return fmt.Errorf("erreur lecture nonce: %w", err)
	}

	hmacHash := hmac.New(sha3.New256, key[32:]) // HMAC avec la clé HMAC (32 derniers octets)

	for {
		// Lecture de la taille du bloc
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

		// Ajout au HMAC
		hmacHash.Write(encrypted)

		// Déchiffrement
		decrypted, err := aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		// Écriture des données déchiffrées
		if _, err := outputFile.Write(decrypted); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	// Lecture et validation du HMAC
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

// SecureFileTransfer envoie un fichier chiffré via une connexion sécurisée.
func SecureFileTransfer(writer io.Writer, filePath string, key []byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("erreur ouverture fichier: %w", err)
	}
	defer file.Close()

	// Initialisation AES-GCM
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	// Génération du nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("erreur génération nonce: %w", err)
	}

	// Écriture du nonce au début de la transmission
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

		// Chiffrement du bloc
		encrypted := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		// Envoi du bloc chiffré
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

// ReceiveSecureFile reçoit un fichier chiffré et le déchiffre.
func ReceiveSecureFile(reader io.Reader, outputPath string, key []byte) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erreur création fichier: %w", err)
	}
	defer file.Close()

	// Initialisation AES-GCM
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return fmt.Errorf("erreur initialisation AES: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	// Lecture du nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return fmt.Errorf("erreur lecture nonce: %w", err)
	}

	// Lecture des blocs chiffrés
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

		// Déchiffrement du bloc
		decrypted, err := aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("erreur déchiffrement: %w", err)
		}

		// Écriture du bloc déchiffré dans le fichier
		if _, err := file.Write(decrypted); err != nil {
			return fmt.Errorf("erreur écriture données déchiffrées: %w", err)
		}
	}

	return nil
}
