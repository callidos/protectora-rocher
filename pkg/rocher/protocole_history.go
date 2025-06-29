package rocher

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/google/uuid"
)

// messageEntry stores message metadata
type messageEntry struct {
	timestamp time.Time
	msgID     string
	hash      [32]byte
	recipient string
}

// MessageHistory manages anti-replay with thread-safe operations
type MessageHistory struct {
	messages       map[string]messageEntry
	hashIndex      map[[32]byte]string
	recipientIndex map[string][]string
	mu             sync.RWMutex
	lastCleanup    time.Time
	cleanupStop    chan struct{}
}

func NewMessageHistory() *MessageHistory {
	mh := &MessageHistory{
		messages:       make(map[string]messageEntry),
		hashIndex:      make(map[[32]byte]string),
		recipientIndex: make(map[string][]string),
		lastCleanup:    time.Now(),
		cleanupStop:    make(chan struct{}),
	}

	go mh.periodicCleanup()
	return mh
}

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

func (mh *MessageHistory) removeFromRecipientIndex(recipient, msgID string) {
	if msgIDs, exists := mh.recipientIndex[recipient]; exists {
		for i, id := range msgIDs {
			if id == msgID {
				mh.recipientIndex[recipient] = append(msgIDs[:i], msgIDs[i+1:]...)
				break
			}
		}
		if len(mh.recipientIndex[recipient]) == 0 {
			delete(mh.recipientIndex, recipient)
		}
	}
}

func generateMessageHash(msgID string, timestamp int64, recipient string, data []byte) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte(msgID))

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	hasher.Write(timestampBytes)

	if recipient != "" {
		hasher.Write([]byte(recipient))
	}

	if len(data) > 0 {
		sampleSize := len(data)
		if sampleSize > 256 {
			sampleSize = 256
		}
		hasher.Write(data[:sampleSize])

		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))
		hasher.Write(lengthBytes)
	}

	return sha256.Sum256(hasher.Sum(nil))
}

// CheckAndStore checks for replay and stores new message atomically
func (mh *MessageHistory) CheckAndStore(msgID string, timestamp int64, recipient string, data []byte) error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Conditional cleanup
	now := time.Now()
	if now.Sub(mh.lastCleanup) > cleanupInterval {
		mh.cleanupUnsafe(now)
	}

	if len(mh.messages) >= maxHistoryEntries {
		return ErrInvalidMessage
	}

	if _, err := uuid.Parse(msgID); err != nil {
		return ErrInvalidMessage
	}

	// Primary check: UUID must be unique
	if _, exists := mh.messages[msgID]; exists {
		return ErrInvalidMessage
	}

	// Generate hash for secondary validation
	hash := generateMessageHash(msgID, timestamp, recipient, data)

	// Secondary check: hash collision detection
	if existingUUID, exists := mh.hashIndex[hash]; exists && existingUUID != msgID {
		// Log collision but allow since UUIDs are different
		return nil
	}

	// Store message atomically
	entry := messageEntry{
		timestamp: now,
		msgID:     msgID,
		hash:      hash,
		recipient: recipient,
	}

	mh.messages[msgID] = entry
	mh.hashIndex[hash] = msgID

	if recipient != "" {
		mh.recipientIndex[recipient] = append(mh.recipientIndex[recipient], msgID)
	}

	return nil
}

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

func (mh *MessageHistory) Reset() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	mh.messages = make(map[string]messageEntry)
	mh.hashIndex = make(map[[32]byte]string)
	mh.recipientIndex = make(map[string][]string)
	mh.lastCleanup = time.Now()
}

func (mh *MessageHistory) Stop() {
	select {
	case <-mh.cleanupStop:
	default:
		close(mh.cleanupStop)
	}
}

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

// Thread-safe session history management using sync.Map
var sessionHistories sync.Map

// getSessionHistory returns history for a session - thread-safe
func getSessionHistory(sessionID string) *MessageHistory {
	_, loaded := sessionHistories.LoadOrStore(sessionID, NewMessageHistory())
	_ = loaded // Ignore loaded flag
	value, _ := sessionHistories.Load(sessionID)
	return value.(*MessageHistory)
}

func ResetMessageHistory() {
	sessionHistories.Range(func(key, value interface{}) bool {
		if history, ok := value.(*MessageHistory); ok {
			history.Stop()
			history.Reset()
		}
		sessionHistories.Delete(key)
		return true
	})
}

func ResetSessionHistory(sessionID string) {
	if value, ok := sessionHistories.Load(sessionID); ok {
		if history, ok := value.(*MessageHistory); ok {
			history.Stop()
			history.Reset()
		}
		sessionHistories.Delete(sessionID)
	}
}

func StopMessageHistory() {
	sessionHistories.Range(func(key, value interface{}) bool {
		if history, ok := value.(*MessageHistory); ok {
			history.Stop()
		}
		return true
	})
}

func GetMessageHistoryStats() map[string]interface{} {
	stats := make(map[string]interface{})
	sessionStats := make(map[string]interface{})
	totalMessages := 0
	sessionCount := 0

	sessionHistories.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		history := value.(*MessageHistory)
		histStats := history.GetStats()
		sessionStats[sessionID] = histStats
		sessionCount++

		if msgCount, ok := histStats["total_messages"].(int); ok {
			totalMessages += msgCount
		}
		return true
	})

	stats["total_sessions"] = sessionCount
	stats["sessions"] = sessionStats
	stats["total_messages_all_sessions"] = totalMessages

	return stats
}

func MessageExists(msgID string) bool {
	exists := false
	sessionHistories.Range(func(key, value interface{}) bool {
		history := value.(*MessageHistory)
		history.mu.RLock()
		_, found := history.messages[msgID]
		history.mu.RUnlock()
		if found {
			exists = true
			return false // Stop iteration
		}
		return true
	})
	return exists
}

func CleanupExpiredMessages() int {
	cleanedCount := 0
	sessionHistories.Range(func(key, value interface{}) bool {
		history := value.(*MessageHistory)
		history.mu.Lock()
		initialCount := len(history.messages)
		history.cleanupUnsafe(time.Now())
		cleanedCount += initialCount - len(history.messages)
		history.mu.Unlock()
		return true
	})
	return cleanedCount
}
