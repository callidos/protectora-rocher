package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	fileBufferSize = 64 * 1024
	fileNonceSize  = 24
	fileHashSize   = 32
	maxFileSize    = 100 * 1024 * 1024
	fileTimeout    = 30 * time.Second
	fileKeySize    = 32
)

var (
	ErrFileNotFound  = errors.New("file not found")
	ErrFileCreation  = errors.New("file creation failed")
	ErrCorruptedFile = errors.New("file corrupted")
)

// FileEncryptor manages file encryption with NaCl secretbox
type FileEncryptor struct {
	key          [fileKeySize]byte
	hasher       hash.Hash
	mu           sync.Mutex
	nonceCounter uint64
}

// NewFileEncryptor creates a new file encryptor
func NewFileEncryptor(masterKey []byte) (*FileEncryptor, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("key too short: need 32 bytes, got %d", len(masterKey))
	}

	// Secure key derivation for file encryption
	encKey, err := deriveKeyWithContext(masterKey, "file", fileKeySize)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	var key [fileKeySize]byte
	copy(key[:], encKey)
	secureZeroMemory(encKey)

	return &FileEncryptor{
		key:          key,
		hasher:       sha256.New(),
		nonceCounter: 0,
	}, nil
}

// generateSecureFileNonce generates a truly random nonce for file chunks
func (fe *FileEncryptor) generateSecureFileNonce() ([fileNonceSize]byte, error) {
	var nonce [fileNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("failed to generate file nonce: %w", err)
	}
	return nonce, nil
}

// EncryptFile encrypts a file with integrity validation
func (fe *FileEncryptor) EncryptFile(inputPath, outputPath string) error {
	return fe.encryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

func (fe *FileEncryptor) encryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	if stat.Size() > maxFileSize {
		return ErrDataTooLarge
	}

	if stat.Size() == 0 {
		return ErrInvalidInput
	}

	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		outputFile.Close()
		if err != nil {
			os.Remove(outputPath) // Clean up on error
		}
	}()

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

func (fe *FileEncryptor) performEncryption(inputFile *os.File, outputFile *os.File) error {
	// Generate base nonce for this file
	baseNonce, err := fe.generateSecureFileNonce()
	if err != nil {
		return err
	}

	// Write base nonce to file
	if _, err := outputFile.Write(baseNonce[:]); err != nil {
		return fmt.Errorf("failed to write base nonce: %w", err)
	}

	// Initialize hasher for integrity
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.hasher.Write(baseNonce[:])
	fe.mu.Unlock()

	// Encrypt by chunks
	buffer := make([]byte, fileBufferSize)
	chunkIndex := uint64(0)

	for {
		n, readErr := inputFile.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("failed to read input file: %w", readErr)
		}
		if n == 0 {
			break
		}

		// Generate unique nonce for this chunk
		chunkNonce, err := fe.generateSecureFileNonce()
		if err != nil {
			return err
		}

		// Encrypt chunk
		encrypted := secretbox.Seal(nil, buffer[:n], &chunkNonce, &fe.key)

		// Update hash with encrypted data
		fe.mu.Lock()
		fe.hasher.Write(encrypted)
		fe.mu.Unlock()

		// Write chunk size (4 bytes)
		sizeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeBytes, uint32(len(encrypted)))
		if _, err := outputFile.Write(sizeBytes); err != nil {
			return fmt.Errorf("failed to write chunk size: %w", err)
		}

		// Write nonce
		if _, err := outputFile.Write(chunkNonce[:]); err != nil {
			return fmt.Errorf("failed to write chunk nonce: %w", err)
		}

		// Write encrypted chunk
		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		chunkIndex++
	}

	// Write final hash for integrity
	fe.mu.Lock()
	finalHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	if _, err := outputFile.Write(finalHash); err != nil {
		return fmt.Errorf("failed to write integrity hash: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file with integrity verification
func (fe *FileEncryptor) DecryptFile(inputPath, outputPath string) error {
	return fe.decryptFileWithTimeout(inputPath, outputPath, fileTimeout)
}

func (fe *FileEncryptor) decryptFileWithTimeout(inputPath, outputPath string, timeout time.Duration) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer inputFile.Close()

	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	minSize := fileNonceSize + fileHashSize + 4 + fileNonceSize + secretbox.Overhead
	if stat.Size() < int64(minSize) {
		return ErrCorruptedFile
	}

	if stat.Size() > maxFileSize*2 {
		return ErrDataTooLarge
	}

	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		outputFile.Close()
		if err != nil {
			os.Remove(outputPath)
		}
	}()

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

func (fe *FileEncryptor) performDecryption(inputFile *os.File, outputFile *os.File) error {
	// Read base nonce
	var baseNonce [fileNonceSize]byte
	if _, err := io.ReadFull(inputFile, baseNonce[:]); err != nil {
		return fmt.Errorf("failed to read base nonce: %w", err)
	}

	// Read rest of file
	remainingData, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}
	defer secureZeroMemory(remainingData)

	if len(remainingData) < fileHashSize {
		return ErrCorruptedFile
	}

	// Separate data and hash
	encryptedDataLen := len(remainingData) - fileHashSize
	encryptedData := remainingData[:encryptedDataLen]
	storedHash := remainingData[encryptedDataLen:]

	// Verify integrity
	fe.mu.Lock()
	fe.hasher.Reset()
	fe.hasher.Write(baseNonce[:])
	fe.hasher.Write(encryptedData)
	computedHash := fe.hasher.Sum(nil)
	fe.mu.Unlock()

	if !ConstantTimeCompare(storedHash, computedHash) {
		return ErrCorruptedFile
	}

	// Decrypt chunk by chunk
	offset := 0

	for offset < len(encryptedData) {
		// Read chunk size
		if offset+4 > len(encryptedData) {
			break
		}

		chunkSize := binary.BigEndian.Uint32(encryptedData[offset : offset+4])
		offset += 4

		if chunkSize == 0 || chunkSize > fileBufferSize*2 {
			return ErrCorruptedFile
		}

		// Read chunk nonce
		if offset+fileNonceSize > len(encryptedData) {
			return ErrCorruptedFile
		}

		var chunkNonce [fileNonceSize]byte
		copy(chunkNonce[:], encryptedData[offset:offset+fileNonceSize])
		offset += fileNonceSize

		// Read encrypted chunk
		if offset+int(chunkSize) > len(encryptedData) {
			return ErrCorruptedFile
		}

		encryptedChunk := encryptedData[offset : offset+int(chunkSize)]

		// Decrypt
		decrypted, ok := secretbox.Open(nil, encryptedChunk, &chunkNonce, &fe.key)
		if !ok {
			return fmt.Errorf("failed to decrypt chunk: %w", ErrDecryption)
		}

		// Write decrypted data
		if _, err := outputFile.Write(decrypted); err != nil {
			secureZeroMemory(decrypted)
			return fmt.Errorf("failed to write decrypted data: %w", err)
		}

		secureZeroMemory(decrypted)
		offset += int(chunkSize)
	}

	return nil
}

// ValidateEncryptedFile validates encrypted file format
func ValidateEncryptedFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file for validation: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot get file stats: %w", err)
	}

	minSize := fileNonceSize + fileHashSize + 4 + fileNonceSize + secretbox.Overhead
	if stat.Size() < int64(minSize) {
		return ErrCorruptedFile
	}

	// Read and validate header
	header := make([]byte, fileNonceSize+8)
	if _, err := file.Read(header); err != nil {
		return fmt.Errorf("cannot read file header: %w", err)
	}

	// Verify first chunk size is reasonable
	firstChunkSize := binary.BigEndian.Uint32(header[fileNonceSize : fileNonceSize+4])
	if firstChunkSize == 0 || firstChunkSize > fileBufferSize*2 {
		return ErrCorruptedFile
	}

	return nil
}

// GetFileEncryptionOverhead calculates encryption overhead
func GetFileEncryptionOverhead(fileSize int64) int64 {
	if fileSize == 0 {
		return int64(fileNonceSize + fileHashSize + 4 + fileNonceSize + secretbox.Overhead)
	}

	numChunks := (fileSize + fileBufferSize - 1) / fileBufferSize
	// Overhead = base nonce + hash + (size + nonce + overhead) per chunk
	overhead := int64(fileNonceSize + fileHashSize + numChunks*(4+fileNonceSize+secretbox.Overhead))
	return overhead
}

// GetFileStats returns encrypted file statistics
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

	fileSize := stat.Size()
	if fileSize < int64(fileNonceSize+fileHashSize) {
		return map[string]interface{}{
			"error": "file too small",
		}
	}

	// Estimate original size
	dataSize := fileSize - int64(fileNonceSize) - int64(fileHashSize)
	estimatedChunks := int64(0)
	estimatedOriginalSize := int64(0)

	if dataSize > 0 {
		avgChunkOverhead := int64(4 + fileNonceSize + secretbox.Overhead)
		avgChunkSize := int64(fileBufferSize) + avgChunkOverhead
		estimatedChunks = (dataSize + avgChunkSize - 1) / avgChunkSize
		estimatedOriginalSize = dataSize - estimatedChunks*avgChunkOverhead
	}

	return map[string]interface{}{
		"file_size":               fileSize,
		"estimated_chunks":        estimatedChunks,
		"estimated_original_size": estimatedOriginalSize,
		"overhead":                GetFileEncryptionOverhead(estimatedOriginalSize),
		"is_valid":                ValidateEncryptedFile(filePath) == nil,
		"last_modified":           stat.ModTime(),
		"encryption_method":       "NaCl-secretbox",
		"chunk_size":              fileBufferSize,
	}
}

// Utility functions
func EncryptFileWithKey(inputPath, outputPath string, key [32]byte) error {
	encryptor, err := NewFileEncryptor(key[:])
	if err != nil {
		return err
	}
	return encryptor.EncryptFile(inputPath, outputPath)
}

func DecryptFileWithKey(inputPath, outputPath string, key [32]byte) error {
	encryptor, err := NewFileEncryptor(key[:])
	if err != nil {
		return err
	}
	return encryptor.DecryptFile(inputPath, outputPath)
}

// GetFileHash calculates SHA256 hash of a file
func GetFileHash(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
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

// CompareFiles compares two files for equality
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

// EstimateEncryptionTime estimates file encryption time
func EstimateEncryptionTime(fileSize int64) time.Duration {
	const avgSpeedMBps = 50
	const bytesPerMB = 1024 * 1024

	seconds := float64(fileSize) / (avgSpeedMBps * bytesPerMB)
	return time.Duration(seconds * float64(time.Second))
}

// CleanupTempFiles cleans up temporary files with given prefix
func CleanupTempFiles(directory, prefix string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	var errors []string
	for _, entry := range entries {
		if !entry.IsDir() && (prefix == "" || strings.HasPrefix(entry.Name(), prefix)) {
			filePath := filepath.Join(directory, entry.Name())
			if err := os.Remove(filePath); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", filePath, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}
