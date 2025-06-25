package communication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	fileBufferSize = 64 * 1024 // 64KB chunks
	fileNonceSize  = 24
	hashSize       = 32
	maxFileSize    = 100 * 1024 * 1024 // 100MB limite pour éviter les attaques DoS
	fileTimeout    = 30 * time.Second  // Timeout pour les opérations de fichier
	fileKeySize    = 32
)

// Erreurs spécifiques au transfert de fichiers
var (
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrFileTooLarge     = errors.New("file too large")
	ErrFileTimeout      = errors.New("file operation timeout")
)

// FileEncryptor gère le chiffrement de fichiers avec NaCl secretbox
type FileEncryptor struct {
	key    [fileKeySize]byte
	hasher hash.Hash
	mu     sync.Mutex // Protection pour l'utilisation du hasher
}

// NewFileEncryptor crée un nouvel encrypteur de fichiers avec validation renforcée
func NewFileEncryptor(masterKey []byte) (*FileEncryptor, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("key too short: need 32 bytes, got %d", len(masterKey))
	}

	// Dérivation de clé sécurisée pour le chiffrement de fichiers
	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-file-encryption-v2")
	h := hkdf.New(sha256.New, masterKey, salt, info)

	var key [fileKeySize]byte
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return &FileEncryptor{
		key:    key,
		hasher: sha256.New(),
	}, nil
}

// EncryptFile chiffre un fichier avec NaCl secretbox et validation d'intégrité
func (fe *FileEncryptor) EncryptFile(inputPath, outputPath string) error {
	return fe.encryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

// encryptFileWithTimeout chiffre un fichier avec timeout configurable
func (fe *FileEncryptor) encryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	// Ouverture et validation du fichier source
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return ErrFileNotFound
	}
	defer inputFile.Close()

	// Vérification de la taille du fichier pour éviter les attaques DoS
	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	if stat.Size() > maxFileSize {
		return ErrFileTooLarge
	}

	if stat.Size() == 0 {
		return fmt.Errorf("cannot encrypt empty file")
	}

	// Création du fichier de sortie avec permissions restrictives
	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return ErrFileCreation
	}
	defer func() {
		outputFile.Close()
		// En cas d'erreur, supprimer le fichier partiellement créé
		if err != nil {
			os.Remove(outputPath)
		}
	}()

	// Canal pour gérer le timeout
	done := make(chan error, 1)
	go func() {
		done <- fe.performEncryption(inputFile, outputFile)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrFileTimeout
	}
}

// performEncryption effectue le chiffrement réel avec NaCl secretbox
func (fe *FileEncryptor) performEncryption(inputFile *os.File, outputFile *os.File) error {
	// Protection thread-safe pour le hasher
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.mu.Unlock()

	buffer := make([]byte, fileBufferSize)
	var totalProcessed int64

	for {
		n, readErr := inputFile.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("read error: %w", readErr)
		}
		if n == 0 {
			break
		}

		totalProcessed += int64(n)
		if totalProcessed > maxFileSize {
			return ErrFileTooLarge
		}

		// Chiffrement du chunk avec NaCl secretbox
		encryptedChunk, err := fe.encryptChunk(buffer[:n])
		if err != nil {
			return err
		}

		// Mise à jour du hash global de manière thread-safe
		fe.mu.Lock()
		fe.hasher.Write(encryptedChunk)
		fe.mu.Unlock()

		// Écriture de la taille du chunk
		if err := binary.Write(outputFile, binary.BigEndian, uint32(len(encryptedChunk))); err != nil {
			return fmt.Errorf("write size error: %w", err)
		}

		// Écriture du chunk chiffré
		if _, err := outputFile.Write(encryptedChunk); err != nil {
			return fmt.Errorf("write chunk error: %w", err)
		}
	}

	// Écriture du hash final pour l'intégrité du fichier
	fe.mu.Lock()
	finalHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	if _, err := outputFile.Write(finalHash); err != nil {
		return fmt.Errorf("write hash error: %w", err)
	}

	return nil
}

// DecryptFile déchiffre un fichier avec vérification d'intégrité
func (fe *FileEncryptor) DecryptFile(inputPath, outputPath string) error {
	return fe.decryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

// decryptFileWithTimeout déchiffre un fichier avec timeout configurable
func (fe *FileEncryptor) decryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	// Ouverture du fichier chiffré
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return ErrFileNotFound
	}
	defer inputFile.Close()

	// Vérification de la taille du fichier
	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	if stat.Size() > maxFileSize*2 { // Marge pour les métadonnées de chiffrement
		return ErrFileTooLarge
	}

	// Vérification de la taille minimale (hash + nonce + secretbox overhead minimum)
	if stat.Size() < hashSize+fileNonceSize+secretbox.Overhead {
		return ErrCorruptedFile
	}

	// Création du fichier de sortie avec permissions restrictives
	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return ErrFileCreation
	}
	defer func() {
		outputFile.Close()
		// En cas d'erreur, supprimer le fichier partiellement créé
		if err != nil {
			os.Remove(outputPath)
		}
	}()

	// Canal pour gérer le timeout
	done := make(chan error, 1)
	go func() {
		done <- fe.performDecryption(inputFile, outputFile)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrFileTimeout
	}
}

// performDecryption effectue le déchiffrement réel
func (fe *FileEncryptor) performDecryption(inputFile *os.File, outputFile *os.File) error {
	// Lecture de tout le contenu pour vérifier le hash
	fileData, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("read file error: %w", err)
	}

	// Extraction du hash final
	if len(fileData) < hashSize {
		return ErrCorruptedFile
	}

	expectedHash := fileData[len(fileData)-hashSize:]
	encryptedData := fileData[:len(fileData)-hashSize]

	// Vérification de l'intégrité globale de manière thread-safe
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.hasher.Write(encryptedData)
	computedHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	// Utilisation de CompareConstantTime pour éviter les attaques de timing
	if !CompareConstantTime(expectedHash, computedHash) {
		// Nettoyage sécurisé des données sensibles
		secureZero(fileData)
		return ErrCorruptedFile
	}

	// Déchiffrement chunk par chunk
	offset := 0
	for offset < len(encryptedData) {
		// Lecture de la taille du chunk
		if offset+4 > len(encryptedData) {
			break
		}

		chunkSize := binary.BigEndian.Uint32(encryptedData[offset : offset+4])
		offset += 4

		// Validation de la taille du chunk pour éviter les attaques
		if chunkSize > fileBufferSize*2 || offset+int(chunkSize) > len(encryptedData) {
			secureZero(fileData)
			return ErrCorruptedFile
		}

		// Déchiffrement du chunk
		encryptedChunk := encryptedData[offset : offset+int(chunkSize)]
		decryptedChunk, err := fe.decryptChunk(encryptedChunk)
		if err != nil {
			secureZero(fileData)
			return err
		}

		// Écriture du chunk déchiffré
		if _, err := outputFile.Write(decryptedChunk); err != nil {
			secureZero(fileData)
			secureZero(decryptedChunk)
			return fmt.Errorf("write decrypted error: %w", err)
		}

		// Nettoyage sécurisé du chunk déchiffré
		secureZero(decryptedChunk)
		offset += int(chunkSize)
	}

	// Nettoyage sécurisé des données
	secureZero(fileData)
	return nil
}

// encryptChunk chiffre un chunk de données avec NaCl secretbox
func (fe *FileEncryptor) encryptChunk(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty chunk")
	}

	var nonce [fileNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrEncryptionFailed
	}

	// Chiffrement avec NaCl secretbox
	encrypted := secretbox.Seal(nil, data, &nonce, &fe.key)

	// Format: nonce + ciphertext
	result := make([]byte, 0, len(nonce)+len(encrypted))
	result = append(result, nonce[:]...)
	result = append(result, encrypted...)

	return result, nil
}

// decryptChunk déchiffre un chunk de données avec NaCl secretbox
func (fe *FileEncryptor) decryptChunk(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < fileNonceSize {
		return nil, ErrDecryptionFailed
	}

	var nonce [fileNonceSize]byte
	copy(nonce[:], encryptedData[:fileNonceSize])
	ciphertext := encryptedData[fileNonceSize:]

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &fe.key)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Fonctions de commodité pour la rétrocompatibilité

// EncryptFile fonction globale pour chiffrer un fichier
func EncryptFile(inputPath, outputPath string, key []byte) error {
	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}
	return encryptor.EncryptFile(inputPath, outputPath)
}

// DecryptFile fonction globale pour déchiffrer un fichier
func DecryptFile(inputPath, outputPath string, key []byte) error {
	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}
	return encryptor.DecryptFile(inputPath, outputPath)
}

// SecureFileTransfer transmet un fichier chiffré via un writer avec timeout
func SecureFileTransfer(writer io.Writer, filePath string, key []byte) error {
	return SecureFileTransferWithTimeout(writer, filePath, key, fileTimeout)
}

// SecureFileTransferWithTimeout transmet un fichier chiffré via un writer avec timeout configurable
func SecureFileTransferWithTimeout(writer io.Writer, filePath string, key []byte, timeout time.Duration) error {
	if writer == nil {
		return errors.New("writer cannot be nil")
	}

	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return ErrFileNotFound
	}
	defer file.Close()

	// Vérification de la taille du fichier
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	if stat.Size() > maxFileSize {
		return ErrFileTooLarge
	}

	// Canal pour gérer le timeout
	done := make(chan error, 1)
	go func() {
		done <- encryptor.performFileTransfer(file, writer)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrFileTimeout
	}
}

// performFileTransfer effectue le transfert réel
func (fe *FileEncryptor) performFileTransfer(file *os.File, writer io.Writer) error {
	buffer := make([]byte, fileBufferSize)
	var totalProcessed int64

	for {
		n, readErr := file.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("read error: %w", readErr)
		}
		if n == 0 {
			break
		}

		totalProcessed += int64(n)
		if totalProcessed > maxFileSize {
			return ErrFileTooLarge
		}

		// Chiffrement du chunk
		encryptedChunk, err := fe.encryptChunk(buffer[:n])
		if err != nil {
			return err
		}

		// Envoi de la taille du chunk
		if err := binary.Write(writer, binary.BigEndian, uint32(len(encryptedChunk))); err != nil {
			return fmt.Errorf("write size error: %w", err)
		}

		// Envoi du chunk chiffré
		if _, err := writer.Write(encryptedChunk); err != nil {
			return fmt.Errorf("write chunk error: %w", err)
		}

		// Nettoyage sécurisé du chunk chiffré
		secureZero(encryptedChunk)
	}

	return nil
}

// ReceiveSecureFile reçoit et déchiffre un fichier depuis un reader avec timeout
func ReceiveSecureFile(reader io.Reader, outputPath string, key []byte) error {
	return ReceiveSecureFileWithTimeout(reader, outputPath, key, fileTimeout)
}

// ReceiveSecureFileWithTimeout reçoit et déchiffre un fichier depuis un reader avec timeout configurable
func ReceiveSecureFileWithTimeout(reader io.Reader, outputPath string, key []byte, timeout time.Duration) error {
	if reader == nil {
		return errors.New("reader cannot be nil")
	}

	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return ErrFileCreation
	}
	defer func() {
		file.Close()
		// En cas d'erreur, supprimer le fichier partiellement créé
		if err != nil {
			os.Remove(outputPath)
		}
	}()

	// Canal pour gérer le timeout
	done := make(chan error, 1)
	go func() {
		done <- encryptor.performFileReception(reader, file)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrFileTimeout
	}
}

// performFileReception effectue la réception réelle
func (fe *FileEncryptor) performFileReception(reader io.Reader, file *os.File) error {
	var totalReceived int64

	for {
		// Lecture de la taille du chunk
		var chunkSize uint32
		if err := binary.Read(reader, binary.BigEndian, &chunkSize); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read size error: %w", err)
		}

		// Validation de la taille du chunk pour éviter les attaques DoS
		if chunkSize == 0 || chunkSize > fileBufferSize*2 {
			return ErrCorruptedFile
		}

		// Vérification que le total ne dépasse pas la limite
		totalReceived += int64(chunkSize)
		if totalReceived > maxFileSize*2 {
			return ErrFileTooLarge
		}

		// Lecture du chunk chiffré
		encryptedChunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(reader, encryptedChunk); err != nil {
			return fmt.Errorf("read chunk error: %w", err)
		}

		// Déchiffrement du chunk
		decryptedChunk, err := fe.decryptChunk(encryptedChunk)
		if err != nil {
			secureZero(encryptedChunk)
			return err
		}

		// Écriture du chunk déchiffré
		if _, err := file.Write(decryptedChunk); err != nil {
			secureZero(encryptedChunk)
			secureZero(decryptedChunk)
			return fmt.Errorf("write decrypted error: %w", err)
		}

		// Nettoyage sécurisé des chunks
		secureZero(encryptedChunk)
		secureZero(decryptedChunk)
	}

	return nil
}

// ValidateEncryptedFile valide qu'un fichier est correctement chiffré
func ValidateEncryptedFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return ErrFileNotFound
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	// Vérification basique de la taille (hash + nonce minimum + secretbox overhead)
	if stat.Size() < hashSize+fileNonceSize+secretbox.Overhead {
		return ErrCorruptedFile
	}

	// Lecture du début pour vérifier la structure
	header := make([]byte, 8) // Taille d'un premier chunk
	if _, err := file.Read(header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Vérification que la première valeur ressemble à une taille de chunk valide
	chunkSize := binary.BigEndian.Uint32(header[:4])
	if chunkSize == 0 || chunkSize > fileBufferSize*2 {
		return ErrCorruptedFile
	}

	return nil
}

// GetFileEncryptionOverhead retourne l'overhead du chiffrement pour un fichier
func GetFileEncryptionOverhead(fileSize int64) int64 {
	if fileSize == 0 {
		return hashSize + fileNonceSize + secretbox.Overhead
	}

	// Calcul approximatif : chunks + nonces + overhead secretbox + hash final + tailles des chunks
	numChunks := (fileSize + fileBufferSize - 1) / fileBufferSize
	overhead := numChunks*(fileNonceSize+secretbox.Overhead+4) + hashSize // nonce + overhead + taille par chunk + hash final

	return overhead
}

// GetFileStats retourne les statistiques d'un fichier chiffré
func GetFileStats(filePath string) map[string]interface{} {
	file, err := os.Open(filePath)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	// Estimation du nombre de chunks
	estimatedChunks := (stat.Size() - hashSize) / (fileBufferSize + fileNonceSize + secretbox.Overhead + 4)
	if estimatedChunks < 0 {
		estimatedChunks = 0
	}

	return map[string]interface{}{
		"file_size":        stat.Size(),
		"estimated_chunks": estimatedChunks,
		"overhead":         GetFileEncryptionOverhead(stat.Size()),
		"is_valid":         ValidateEncryptedFile(filePath) == nil,
		"last_modified":    stat.ModTime(),
	}
}
