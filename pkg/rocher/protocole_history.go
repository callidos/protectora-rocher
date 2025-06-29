package rocher

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// messageEntry stores message metadata with UUID
type messageEntry struct {
	timestamp time.Time
	msgID     string   // UUID
	hash      [32]byte // Full SHA256 hash for better collision resistance
	recipient string
}

// MessageHistory manages anti-replay with automatic cleanup
type MessageHistory struct {
	messages       map[string]messageEntry // Key is UUID string
	hashIndex      map[[32]byte]string     // Hash -> UUID mapping
	mu             sync.RWMutex
	lastCleanup    time.Time
	cleanupStop    chan struct{}
	recipientIndex map[string][]string // recipient -> []messageIDs
}

func NewMessageHistory() *MessageHistory {
	mh := &MessageHistory{
		messages:       make(map[string]messageEntry),
		hashIndex:      make(map[[32]byte]string),
		lastCleanup:    time.Now(),
		cleanupStop:    make(chan struct{}),
		recipientIndex: make(map[string][]string),
	}

	// Start automatic cleanup
	go mh.periodicCleanup()

	return mh
}

// periodicCleanup periodically cleans old entries
func (mh *MessageHistory) periodicCleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mh.cleanup()
		case <-mh.cleanupStop:
			return
		}
	}
}

// cleanup removes expired entries
func (mh *MessageHistory) cleanup() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-replayWindow)

	toDelete := make([]string, 0, len(mh.messages)/10)

	for msgID, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, msgID)
		}
	}

	// Remove expired entries
	for _, msgID := range toDelete {
		if entry, exists := mh.messages[msgID]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, msgID)

			// Clean recipient index
			if entry.recipient != "" {
				mh.removeFromRecipientIndex(entry.recipient, msgID)
			}
		}
	}

	mh.lastCleanup = now
}

// removeFromRecipientIndex removes a message ID from recipient index
func (mh *MessageHistory) removeFromRecipientIndex(recipient, msgID string) {
	if msgIDs, exists := mh.recipientIndex[recipient]; exists {
		// Remove msgID from slice
		for i, id := range msgIDs {
			if id == msgID {
				mh.recipientIndex[recipient] = append(msgIDs[:i], msgIDs[i+1:]...)
				break
			}
		}

		// Remove empty recipient entries
		if len(mh.recipientIndex[recipient]) == 0 {
			delete(mh.recipientIndex, recipient)
		}
	}
}

// generateMessageHash generates a secure hash for deduplication
func generateMessageHash(msgID string, timestamp int64, recipient string, data []byte) [32]byte {
	hasher := sha256.New()

	// Include all relevant fields in hash
	hasher.Write([]byte(msgID))

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	hasher.Write(timestampBytes)

	if recipient != "" {
		hasher.Write([]byte(recipient))
	}

	// Include a sample of data to detect duplicates with same metadata
	if len(data) > 0 {
		sampleSize := len(data)
		if sampleSize > 256 {
			sampleSize = 256
		}
		hasher.Write(data[:sampleSize])

		// Also include data length
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))
		hasher.Write(lengthBytes)
	}

	return sha256.Sum256(hasher.Sum(nil))
}

// CheckAndStore checks for replay and stores new message
func (mh *MessageHistory) CheckAndStore(msgID string, timestamp int64, recipient string, data []byte) error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Conditional cleanup
	now := time.Now()
	if now.Sub(mh.lastCleanup) > cleanupInterval {
		mh.cleanupUnsafe(now)
	}

	// Check size limit
	if len(mh.messages) >= maxHistoryEntries {
		return ErrInvalidMessage
	}

	// Validate UUID format
	if _, err := uuid.Parse(msgID); err != nil {
		return ErrInvalidMessage
	}

	// Primary check: UUID must be unique
	if _, exists := mh.messages[msgID]; exists {
		return ErrInvalidMessage // Replay attack detected
	}

	// Generate hash for secondary validation
	hash := generateMessageHash(msgID, timestamp, recipient, data)

	// Secondary check: hash collision detection
	if existingUUID, exists := mh.hashIndex[hash]; exists && existingUUID != msgID {
		// This is extremely unlikely with SHA256, but we log it
		fmt.Printf("[WARNING] Hash collision detected: new UUID %s collides with existing UUID %s\n", msgID, existingUUID)
		// We still allow it since UUIDs are different
	}

	// Store message
	entry := messageEntry{
		timestamp: now,
		msgID:     msgID,
		hash:      hash,
		recipient: recipient,
	}

	mh.messages[msgID] = entry
	mh.hashIndex[hash] = msgID

	// Update recipient index
	if recipient != "" {
		mh.recipientIndex[recipient] = append(mh.recipientIndex[recipient], msgID)
	}

	return nil
}

// cleanupUnsafe performs cleanup without locking (caller must hold lock)
func (mh *MessageHistory) cleanupUnsafe(now time.Time) {
	cutoff := now.Add(-replayWindow)

	toDelete := make([]string, 0, len(mh.messages)/10)
	for msgID, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, msgID)
		}
	}

	for _, msgID := range toDelete {
		if entry, exists := mh.messages[msgID]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, msgID)

			if entry.recipient != "" {
				mh.removeFromRecipientIndex(entry.recipient, msgID)
			}
		}
	}

	mh.lastCleanup = now
}

// Reset clears history safely
func (mh *MessageHistory) Reset() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Clear all maps
	mh.messages = make(map[string]messageEntry)
	mh.hashIndex = make(map[[32]byte]string)
	mh.recipientIndex = make(map[string][]string)
	mh.lastCleanup = time.Now()
}

// Stop stops automatic cleanup
func (mh *MessageHistory) Stop() {
	select {
	case <-mh.cleanupStop:
		// Already stopped
	default:
		close(mh.cleanupStop)
	}
}

// GetStats returns statistics
func (mh *MessageHistory) GetStats() map[string]interface{} {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	return map[string]interface{}{
		"total_messages":   len(mh.messages),
		"hash_entries":     len(mh.hashIndex),
		"last_cleanup":     mh.lastCleanup,
		"max_entries":      maxHistoryEntries,
		"recipients_count": len(mh.recipientIndex),
	}
}

// GetRecipientStats returns statistics for a specific recipient
func (mh *MessageHistory) GetRecipientStats(recipient string) map[string]interface{} {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	msgIDs, exists := mh.recipientIndex[recipient]
	if !exists {
		return map[string]interface{}{
			"recipient":     recipient,
			"message_count": 0,
			"exists":        false,
		}
	}

	return map[string]interface{}{
		"recipient":     recipient,
		"message_count": len(msgIDs),
		"exists":        true,
		"message_ids":   msgIDs,
	}
}

// Session history management
var (
	sessionHistories   = make(map[string]*MessageHistory)
	sessionHistoriesMu sync.RWMutex
)

// getSessionHistory returns history for a given session
func getSessionHistory(sessionID string) *MessageHistory {
	sessionHistoriesMu.RLock()
	history, exists := sessionHistories[sessionID]
	sessionHistoriesMu.RUnlock()

	if exists {
		return history
	}

	// Create new history for this session
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Double check after acquiring write lock
	if history, exists := sessionHistories[sessionID]; exists {
		return history
	}

	history = NewMessageHistory()
	sessionHistories[sessionID] = history
	return history
}

// ResetMessageHistory resets all session histories
func ResetMessageHistory() {
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Stop and clean all session histories
	for sessionID, history := range sessionHistories {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// ResetSessionHistory resets history for a specific session
func ResetSessionHistory(sessionID string) {
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	if history, exists := sessionHistories[sessionID]; exists {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// StopMessageHistory stops automatic cleanup for all sessions
func StopMessageHistory() {
	sessionHistoriesMu.RLock()
	histories := make([]*MessageHistory, 0, len(sessionHistories))
	for _, history := range sessionHistories {
		histories = append(histories, history)
	}
	sessionHistoriesMu.RUnlock()

	// Stop all histories
	for _, history := range histories {
		history.Stop()
	}
}

// GetMessageHistoryStats returns global history statistics
func GetMessageHistoryStats() map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_sessions"] = len(sessionHistories)

	sessionStats := make(map[string]interface{})
	totalMessages := 0
	for sessionID, history := range sessionHistories {
		histStats := history.GetStats()
		sessionStats[sessionID] = histStats
		if msgCount, ok := histStats["total_messages"].(int); ok {
			totalMessages += msgCount
		}
	}
	stats["sessions"] = sessionStats
	stats["total_messages_all_sessions"] = totalMessages

	return stats
}

// GetSessionHistoryStats returns statistics for a specific session
func GetSessionHistoryStats(sessionID string) map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	if history, exists := sessionHistories[sessionID]; exists {
		return history.GetStats()
	}

	return map[string]interface{}{
		"error": "session not found",
	}
}

// MessageExists checks if a message ID exists in any session
func MessageExists(msgID string) bool {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	for _, history := range sessionHistories {
		history.mu.RLock()
		_, exists := history.messages[msgID]
		history.mu.RUnlock()

		if exists {
			return true
		}
	}

	return false
}

// CleanupExpiredMessages removes expired messages across all sessions
func CleanupExpiredMessages() int {
	sessionHistoriesMu.RLock()
	histories := make([]*MessageHistory, 0, len(sessionHistories))
	for _, history := range sessionHistories {
		histories = append(histories, history)
	}
	sessionHistoriesMu.RUnlock()

	cleanedCount := 0
	for _, history := range histories {
		history.mu.Lock()
		initialCount := len(history.messages)
		history.cleanupUnsafe(time.Now())
		cleanedCount += initialCount - len(history.messages)
		history.mu.Unlock()
	}

	return cleanedCount
}
