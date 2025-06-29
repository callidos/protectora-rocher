package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	fileBufferSize = 64 * 1024 // 64KB chunks
	fileNonceSize  = 24
	fileHashSize   = 32
	maxFileSize    = 100 * 1024 * 1024 // 100MB limite pour éviter les attaques DoS
	fileTimeout    = 30 * time.Second  // Timeout pour les opérations de fichier
	fileKeySize    = 32
)

// FileEncryptor gère le chiffrement de fichiers avec NaCl secretbox
type FileEncryptor struct {
	key          [fileKeySize]byte
	hasher       hash.Hash
	mu           sync.Mutex // Protection pour l'utilisation du hasher
	nonceCounter uint64     // Compteur pour générer des nonces uniques
}

// NewFileEncryptor crée un nouvel encrypteur de fichiers
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
		key:          key,
		hasher:       sha256.New(),
		nonceCounter: 0,
	}, nil
}

// generateFileNonce génère un nonce unique pour un chunk
func (fe *FileEncryptor) generateFileNonce(baseNonce []byte, chunkIndex uint64) [fileNonceSize]byte {
	var nonce [fileNonceSize]byte
	
	// Copier la base du nonce (16 premiers octets)
	copy(nonce[:16], baseNonce)
	
	// Ajouter l'index du chunk dans les 8 derniers octets
	binary.BigEndian.PutUint64(nonce[16:], chunkIndex)
	
	return nonce
}

// EncryptFile chiffre un fichier avec validation d'intégrité
func (fe *FileEncryptor) EncryptFile(inputPath, outputPath string) error {
	return fe.encryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

// encryptFileWithTimeout chiffre un fichier avec timeout configurable
func (fe *FileEncryptor) encryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	// Ouverture et validation du fichier source
	inputFile, err := openFileSecure(inputPath)
	if err != nil {
		return NewFileError("Failed to open input file", err)
	}
	defer inputFile.Close()

	// Vérification de la taille du fichier
	stat, err := inputFile.Stat()
	if err != nil {
		return NewFileError("Failed to get file stats", err)
	}

	if stat.Size() > maxFileSize {
		return NewFileError("File too large", ErrDataTooLarge)
	}

	if stat.Size() == 0 {
		return NewFileError("Cannot encrypt empty file", ErrInvalidInput)
	}

	// Création du fichier de sortie
	outputFile, err := createFileSecure(outputPath)
	if err != nil {
		return NewFileError("Failed to create output file", err)
	}
	defer func() {
		outputFile.Close()
		if err != nil {
			removeFileSecure(outputPath) // Nettoyer en cas d'erreur
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
		return NewTimeoutError("File encryption timeout", nil)
	}
}

// performEncryption effectue le chiffrement réel
func (fe *FileEncryptor) performEncryption(inputFile *os.File, outputFile *os.File) error {
	// Générer un nonce de base pour ce fichier
	baseNonce := make([]byte, 16)
	if _, err := rand.Read(baseNonce); err != nil {
		return NewCryptographicError("Failed to generate base nonce", err)
	}

	// Écrire le nonce de base au début du fichier
	if _, err := outputFile.Write(baseNonce); err != nil {
		return NewFileError("Failed to write base nonce", err)
	}

	// Initialiser le hasher pour l'intégrité
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.hasher.Write(baseNonce) // Inclure le nonce de base dans le hash
	fe.mu.Unlock()

	// Chiffrer par chunks
	buffer := make([]byte, fileBufferSize)
	chunkIndex := uint64(0)

	for {
		n, readErr := inputFile.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return NewFileError("Failed to read input file", readErr)
		}
		if n == 0 {
			break
		}

		// Générer nonce unique pour ce chunk
		chunkNonce := fe.generateFileNonce(baseNonce, chunkIndex)

		// Chiffrer le chunk
		encrypted := secretbox.Seal(nil, buffer[:n], &chunkNonce, &fe.key)

		// Mettre à jour le hash avec les données chiffrées
		fe.mu.Lock()
		fe.hasher.Write(encrypted)
		fe.mu.Unlock()

		// Écrire la taille du chunk chiffré (4 octets)
		sizeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeBytes, uint32(len(encrypted)))
		if _, err := outputFile.Write(sizeBytes); err != nil {
			return NewFileError("Failed to write chunk size", err)
		}

		// Écrire le chunk chiffré
		if _, err := outputFile.Write(encrypted); err != nil {
			return NewFileError("Failed to write encrypted chunk", err)
		}

		chunkIndex++
	}

	// Écrire le hash final pour l'intégrité
	fe.mu.Lock()
	finalHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	if _, err := outputFile.Write(finalHash); err != nil {
		return NewFileError("Failed to write integrity hash", err)
	}

	return nil
}

// DecryptFile déchiffre un fichier avec vérification d'intégrité
func (fe *FileEncryptor) DecryptFile(inputPath, outputPath string) error {
	return fe.decryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

// decryptFileWithTimeout déchiffre un fichier avec timeout
func (fe *FileEncryptor) decryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	// Ouverture du fichier chiffré
	inputFile, err := openFileSecure(inputPath)
	if err != nil {
		return NewFileError("Failed to open encrypted file", err)
	}
	defer inputFile.Close()

	// Vérification de la taille
	stat, err := inputFile.Stat()
	if err != nil {
		return NewFileError("Failed to get file stats", err)
	}

	minSize := 16 + fileHashSize + 4 + secretbox.Overhead // base nonce + hash + min chunk
	if stat.Size() < int64(minSize) {
		return NewFileError("File too small to be valid", ErrCorruptedFile)
	}

	if stat.Size() > maxFileSize*2 { // Marge pour métadonnées
		return NewFileError("Encrypted file too large", ErrDataTooLarge)
	}

	// Création du fichier de sortie
	outputFile, err := createFileSecure(outputPath)
	if err != nil {
		return NewFileError("Failed to create output file", err)
	}
	defer func() {
		outputFile.Close()
		if err != nil {
			removeFileSecure(outputPath) // Nettoyer en cas d'erreur
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
		return NewTimeoutError("File decryption timeout", nil)
	}
}

// performDecryption effectue le déchiffrement réel
func (fe *FileEncryptor) performDecryption(inputFile *os.File, outputFile *os.File) error {
	// Lire le nonce de base
	baseNonce := make([]byte, 16)
	if _, err := io.ReadFull(inputFile, baseNonce); err != nil {
		return NewFileError("Failed to read base nonce", err)
	}

	// Lire tout le reste du fichier
	remainingData, err := io.ReadAll(inputFile)
	if err != nil {
		return NewFileError("Failed to read encrypted data", err)
	}

	if len(remainingData) < fileHashSize {
		return NewFileError("File too small for integrity hash", ErrCorruptedFile)
	}

	// Séparer les données et le hash
	encryptedDataLen := len(remainingData) - fileHashSize
	encryptedData := remainingData[:encryptedDataLen]
	storedHash := remainingData[encryptedDataLen:]

	// Vérifier l'intégrité
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.hasher.Write(baseNonce)
	fe.hasher.Write(encryptedData)
	computedHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	if !ConstantTimeCompare(storedHash, computedHash) {
		secureZeroMemory(remainingData)
		return NewFileError("Integrity check failed", ErrCorruptedFile)
	}

	// Déchiffrer chunk par chunk
	offset := 0
	chunkIndex := uint64(0)

	for offset < len(encryptedData) {
		// Lire la taille du chunk
		if offset+4 > len(encryptedData) {
			break
		}

		chunkSize := binary.BigEndian.Uint32(encryptedData[offset : offset+4])
		offset += 4

		// Validation de la taille
		if chunkSize == 0 || chunkSize > fileBufferSize*2 {
			secureZeroMemory(remainingData)
			return NewFileError("Invalid chunk size", ErrCorruptedFile)
		}

		if offset+int(chunkSize) > len(encryptedData) {
			secureZeroMemory(remainingData)
			return NewFileError("Chunk extends beyond data", ErrCorruptedFile)
		}

		// Extraire le chunk chiffré
		encryptedChunk := encryptedData[offset : offset+int(chunkSize)]

		// Générer le nonce pour ce chunk
		chunkNonce := fe.generateFileNonce(baseNonce, chunkIndex)

		// Déchiffrer
		decrypted, ok := secretbox.Open(nil, encryptedChunk, &chunkNonce, &fe.key)
		if !ok {
			secureZeroMemory(remainingData)
			return NewFileError("Failed to decrypt chunk", ErrDecryption)
		}

		// Écrire les données déchiffrées
		if _, err := outputFile.Write(decrypted); err != nil {
			secureZeroMemory(remainingData)
			secureZeroMemory(decrypted)
			return NewFileError("Failed to write decrypted data", err)
		}

		// Nettoyer le chunk déchiffré
		secureZeroMemory(decrypted)

		offset += int(chunkSize)
		chunkIndex++
	}

	// Nettoyer les données sensibles
	secureZeroMemory(remainingData)

	return nil
}

// ValidateEncryptedFile valide qu'un fichier est correctement chiffré
func ValidateEncryptedFile(filePath string) error {
	file, err := openFileSecure(filePath)
	if err != nil {
		return NewFileError("Cannot open file for validation", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return NewFileError("Cannot get file stats", err)
	}

	// Vérification de la taille minimale
	minSize := 16 + fileHashSize + 4 + secretbox.Overhead
	if stat.Size() < int64(minSize) {
		return NewFileError("File too small to be valid encrypted file", ErrCorruptedFile)
	}

	// Lire et valider l'en-tête
	header := make([]byte, 16+8) // base nonce + first chunk size
	if _, err := file.Read(header); err != nil {
		return NewFileError("Cannot read file header", err)
	}

	// Vérifier que la première taille de chunk est raisonnable
	firstChunkSize := binary.BigEndian.Uint32(header[16:20])
	if firstChunkSize == 0 || firstChunkSize > fileBufferSize*2 {
		return NewFileError("Invalid first chunk size", ErrCorruptedFile)
	}

	return nil
}

// GetFileEncryptionOverhead calcule l'overhead du chiffrement
func GetFileEncryptionOverhead(fileSize int64) int64 {
	if fileSize == 0 {
		return 16 + fileHashSize + 4 + secretbox.Overhead
	}

	// Calculer le nombre de chunks
	numChunks := (fileSize + fileBufferSize - 1) / fileBufferSize
	
	// Overhead = nonce de base + hash final + (taille + overhead secretbox) par chunk
	overhead := 16 + fileHashSize + numChunks*(4+secretbox.Overhead)

	return overhead
}

// GetFileStats retourne les statistiques d'un fichier chiffré
func GetFileStats(filePath string) map[string]interface{} {
	file, err := openFileSecure(filePath)
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

	// Estimation du nombre de chunks et de la taille originale
	fileSize := stat.Size()
	if fileSize < 16+fileHashSize {
		return map[string]interface{}{
			"error": "file too small",
		}
	}

	// Estimation approximative de la taille originale
	dataSize := fileSize - 16 - fileHashSize // Soustraire nonce de base et hash
	estimatedChunks := int64(0)
	estimatedOriginalSize := int64(0)

	if dataSize > 0 {
		// Estimation basée sur l'overhead moyen par chunk
		avgChunkOverhead := 4 + secretbox.Overhead // 4 bytes taille + overhead secretbox
		avgChunkSize := fileBufferSize + avgChunkOverhead
		estimatedChunks = (dataSize + int64(avgChunkSize) - 1) / int64(avgChunkSize)
		estimatedOriginalSize = dataSize - estimatedChunks*int64(avgChunkOverhead)
	}

	return map[string]interface{}{
		"file_size":              fileSize,
		"estimated_chunks":       estimatedChunks,
		"estimated_original_size": estimatedOriginalSize,
		"overhead":               GetFileEncryptionOverhead(estimatedOriginalSize),
		"is_valid":               ValidateEncryptedFile(filePath) == nil,
		"last_modified":          stat.ModTime(),
		"encryption_method":      "NaCl-secretbox",
		"chunk_size":             fileBufferSize,
	}
}

// EncryptFileWithKey fonction utilitaire pour chiffrer avec une clé directe
func EncryptFileWithKey(inputPath, outputPath string, key [32]byte) error {
	encryptor, err := NewFileEncryptor(key[:])
	if err != nil {
		return err
	}
	return encryptor.EncryptFile(inputPath, outputPath)
}

// DecryptFileWithKey fonction utilitaire pour déchiffrer avec une clé directe
func DecryptFileWithKey(inputPath, outputPath string, key [32]byte) error {
	encryptor, err := NewFileEncryptor(key[:])
	if err != nil {
		return err
	}
	return encryptor.DecryptFile(inputPath, outputPath)
}

// StreamFileEncryptor pour le chiffrement en streaming de gros fichiers
type StreamFileEncryptor struct {
	*FileEncryptor
	baseNonce   []byte
	chunkIndex  uint64
	hasher      hash.Hash
	initialized bool
}

// NewStreamFileEncryptor crée un encrypteur de streaming
func NewStreamFileEncryptor(masterKey []byte) (*StreamFileEncryptor, error) {
	base, err := NewFileEncryptor(masterKey)
	if err != nil {
		return nil, err
	}

	return &StreamFileEncryptor{
		FileEncryptor: base,
		hasher:        sha256.New(),
		initialized:   false,
	}, nil
}

// InitializeStream initialise le stream avec le nonce de base
func (sfe *StreamFileEncryptor) InitializeStream(writer io.Writer) error {
	if sfe.initialized {
		return fmt.Errorf("stream already initialized")
	}

	// Générer nonce de base
	sfe.baseNonce = make([]byte, 16)
	if _, err := rand.Read(sfe.baseNonce); err != nil {
		return NewCryptographicError("Failed to generate base nonce", err)
	}

	// Écrire le nonce de base
	if _, err := writer.Write(sfe.baseNonce); err != nil {
		return NewFileError("Failed to write base nonce", err)
	}

	// Initialiser le hasher
	sfe.hasher.Reset()
	sfe.hasher.Write(sfe.baseNonce)
	sfe.chunkIndex = 0
	sfe.initialized = true

	return nil
}

// EncryptChunk chiffre un chunk de données
func (sfe *StreamFileEncryptor) EncryptChunk(writer io.Writer, data []byte) error {
	if !sfe.initialized {
		return fmt.Errorf("stream not initialized")
	}

	if len(data) == 0 {
		return nil
	}

	if len(data) > fileBufferSize {
		return fmt.Errorf("chunk too large: %d > %d", len(data), fileBufferSize)
	}

	// Générer nonce pour ce chunk
	chunkNonce := sfe.generateFileNonce(sfe.baseNonce, sfe.chunkIndex)

	// Chiffrer
	encrypted := secretbox.Seal(nil, data, &chunkNonce, &sfe.key)

	// Mettre à jour le hash
	sfe.hasher.Write(encrypted)

	// Écrire taille + données
	sizeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBytes, uint32(len(encrypted)))

	if _, err := writer.Write(sizeBytes); err != nil {
		return NewFileError("Failed to write chunk size", err)
	}

	if _, err := writer.Write(encrypted); err != nil {
		return NewFileError("Failed to write encrypted chunk", err)
	}

	sfe.chunkIndex++
	return nil
}

// FinalizeStream finalise le stream en écrivant le hash d'intégrité
func (sfe *StreamFileEncryptor) FinalizeStream(writer io.Writer) error {
	if !sfe.initialized {
		return fmt.Errorf("stream not initialized")
	}

	// Écrire le hash final
	finalHash := sfe.hasher.Sum(nil)
	if _, err := writer.Write(finalHash); err != nil {
		return NewFileError("Failed to write final hash", err)
	}

	sfe.initialized = false
	return nil
}

// StreamFileDecryptor pour le déchiffrement en streaming
type StreamFileDecryptor struct {
	*FileEncryptor
	baseNonce   []byte
	chunkIndex  uint64
	hasher      hash.Hash
	initialized bool
}

// NewStreamFileDecryptor crée un déchiffreur de streaming
func NewStreamFileDecryptor(masterKey []byte) (*StreamFileDecryptor, error) {
	base, err := NewFileEncryptor(masterKey)
	if err != nil {
		return nil, err
	}

	return &StreamFileDecryptor{
		FileEncryptor: base,
		hasher:        sha256.New(),
		initialized:   false,
	}, nil
}

// InitializeStream initialise le stream en lisant le nonce de base
func (sfd *StreamFileDecryptor) InitializeStream(reader io.Reader) error {
	if sfd.initialized {
		return fmt.Errorf("stream already initialized")
	}

	// Lire le nonce de base
	sfd.baseNonce = make([]byte, 16)
	if _, err := io.ReadFull(reader, sfd.baseNonce); err != nil {
		return NewFileError("Failed to read base nonce", err)
	}

	// Initialiser le hasher
	sfd.hasher.Reset()
	sfd.hasher.Write(sfd.baseNonce)
	sfd.chunkIndex = 0
	sfd.initialized = true

	return nil
}

// DecryptChunk déchiffre le prochain chunk
func (sfd *StreamFileDecryptor) DecryptChunk(reader io.Reader) ([]byte, error) {
	if !sfd.initialized {
		return nil, fmt.Errorf("stream not initialized")
	}

	// Lire la taille du chunk
	sizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, sizeBytes); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, NewFileError("Failed to read chunk size", err)
	}

	chunkSize := binary.BigEndian.Uint32(sizeBytes)
	if chunkSize == 0 || chunkSize > fileBufferSize*2 {
		return nil, NewFileError("Invalid chunk size", ErrCorruptedFile)
	}

	// Lire le chunk chiffré
	encrypted := make([]byte, chunkSize)
	if _, err := io.ReadFull(reader, encrypted); err != nil {
		return nil, NewFileError("Failed to read encrypted chunk", err)
	}

	// Mettre à jour le hash
	sfd.hasher.Write(encrypted)

	// Générer le nonce
	chunkNonce := sfd.generateFileNonce(sfd.baseNonce, sfd.chunkIndex)

	// Déchiffrer
	decrypted, ok := secretbox.Open(nil, encrypted, &chunkNonce, &sfd.key)
	if !ok {
		return nil, NewFileError("Failed to decrypt chunk", ErrDecryption)
	}

	sfd.chunkIndex++
	return decrypted, nil
}

// VerifyIntegrity vérifie l'intégrité du stream en lisant le hash final
func (sfd *StreamFileDecryptor) VerifyIntegrity(reader io.Reader) error {
	if !sfd.initialized {
		return fmt.Errorf("stream not initialized")
	}

	// Lire le hash stocké
	storedHash := make([]byte, fileHashSize)
	if _, err := io.ReadFull(reader, storedHash); err != nil {
		return NewFileError("Failed to read integrity hash", err)
	}

	// Calculer le hash attendu
	computedHash := sfd.hasher.Sum(nil)

	// Comparer
	if !ConstantTimeCompare(storedHash, computedHash) {
		return NewFileError("Integrity verification failed", ErrCorruptedFile)
	}

	sfd.initialized = false
	return nil
}

// Fonctions utilitaires pour les opérations de fichiers

// SecureFileMove déplace un fichier de manière sécurisée
func SecureFileMove(srcPath, dstPath string) error {
	// Essayer un rename d'abord (plus rapide si même système de fichiers)
	if err := os.Rename(srcPath, dstPath); err == nil {
		return nil
	}

	// Si rename échoue, copier puis supprimer
	if err := SecureFileCopy(srcPath, dstPath); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	if err := removeFileSecure(srcPath); err != nil {
		// Essayer de nettoyer le fichier de destination si suppression échoue
		removeFileSecure(dstPath)
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	return nil
}

// SecureFileCopy copie un fichier de manière sécurisée
func SecureFileCopy(srcPath, dstPath string) error {
	src, err := openFileSecure(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer src.Close()

	dst, err := createFileSecure(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer func() {
		dst.Close()
		if err != nil {
			removeFileSecure(dstPath)
		}
	}()

	// Copier avec vérification d'intégrité
	hasher := sha256.New()
	teeReader := io.TeeReader(src, hasher)

	_, err = io.Copy(dst, teeReader)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Vérifier que la copie est identique
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("failed to sync destination: %w", err)
	}

	return nil
}

// GetFileHash calcule le hash SHA256 d'un fichier
func GetFileHash(filePath string) ([]byte, error) {
	file, err := openFileSecure(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	return hasher.Sum(nil), nil
}

// CompareFiles compare deux fichiers pour vérifier qu'ils sont identiques
func CompareFiles(path1, path2 string) (bool, error) {
	hash1, err := GetFileHash(path1)
	if err != nil {
		return false, fmt.Errorf("failed to hash file1: %w", err)
	}

	hash2, err := GetFileHash(path2)
	if err != nil {
		return false, fmt.Errorf("failed to hash file2: %w", err)
	}

	return ConstantTimeCompare(hash1, hash2), nil
}

// EstimateEncryptionTime estime le temps de chiffrement d'un fichier
func EstimateEncryptionTime(fileSize int64) time.Duration {
	// Estimation basée sur une vitesse de ~50MB/s (dépend du matériel)
	const avgSpeedMBps = 50
	const bytesPerMB = 1024 * 1024
	
	seconds := float64(fileSize) / (avgSpeedMBps * bytesPerMB)
	return time.Duration(seconds * float64(time.Second))
}

// CleanupTempFiles nettoie les fichiers temporaires avec un préfixe donné
func CleanupTempFiles(directory, prefix string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	var errors []string
	for _, entry := range entries {
		if !entry.IsDir() && (prefix == "" || strings.HasPrefix(entry.Name(), prefix)) {
			filePath := filepath.Join(directory, entry.Name())
			if err := removeFileSecure(filePath); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", filePath, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}