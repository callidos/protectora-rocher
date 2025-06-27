package rocher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// messageEntry structure for storing message metadata with UUID
type messageEntry struct {
	timestamp time.Time
	msgID     string   // UUID instead of sequence number
	hash      [16]byte // Partial hash for duplicate detection
	recipient string   // Message recipient
}

// MessageHistory manages anti-replay with automatic cleanup and UUID-based validation
type MessageHistory struct {
	messages       map[string]messageEntry // Key is now UUID string
	hashIndex      map[[16]byte]string     // Hash index points to UUID
	mu             sync.RWMutex
	lastCleanup    time.Time
	cleanupStop    chan struct{}
	recipientIndex map[string][]string // Index by recipient -> []messageIDs
}

func NewMessageHistory() *MessageHistory {
	mh := &MessageHistory{
		messages:       make(map[string]messageEntry),
		hashIndex:      make(map[[16]byte]string),
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

// cleanup removes expired entries efficiently
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

// generateMessageHash generates a partial hash for a message with UUID and recipient
func generateMessageHash(msgID string, timestamp int64, recipient string, data []byte) [16]byte {
	var hash [16]byte

	// Combine msgID, timestamp, recipient and data sample
	idBytes := []byte(msgID)
	recipientBytes := []byte(recipient)

	// Mix msgID
	for i := 0; i < 8 && i < len(idBytes); i++ {
		hash[i] = idBytes[i]
	}

	// Mix timestamp
	binary.BigEndian.PutUint64(hash[8:16], uint64(timestamp))

	// XOR with recipient
	for i := 0; i < 8 && i < len(recipientBytes); i++ {
		hash[i] ^= recipientBytes[i]
	}

	// XOR with data sample for more uniqueness
	if len(data) > 0 {
		for i := 0; i < 16 && i < len(data); i++ {
			hash[i] ^= data[i]
		}
	}

	return hash
}

// CheckAndStore checks and stores a message with UUID-based validation
func (mh *MessageHistory) CheckAndStore(msgID string, timestamp int64, recipient string, data []byte) error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Conditional cleanup for performance
	now := time.Now()
	if now.Sub(mh.lastCleanup) > cleanupInterval {
		mh.cleanupUnsafe(now)
	}

	// Check size limit to avoid memory exhaustion
	if len(mh.messages) >= maxHistoryEntries {
		return ErrInvalidMessage
	}

	// Validate UUID format
	if _, err := uuid.Parse(msgID); err != nil {
		return ErrInvalidMessage
	}

	// Generate message hash
	hash := generateMessageHash(msgID, timestamp, recipient, data)

	// Fast hash check
	if _, exists := mh.hashIndex[hash]; exists {
		return ErrInvalidMessage
	}

	// UUID check (should be unique)
	if _, exists := mh.messages[msgID]; exists {
		return ErrInvalidMessage
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

// cleanupUnsafe non-thread-safe version for internal use
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

// Reset cleans history safely
func (mh *MessageHistory) Reset() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Clean maps
	for msgID := range mh.messages {
		delete(mh.messages, msgID)
	}
	for hash := range mh.hashIndex {
		delete(mh.hashIndex, hash)
	}
	for recipient := range mh.recipientIndex {
		delete(mh.recipientIndex, recipient)
	}

	mh.lastCleanup = time.Now()
}

// Stop stops automatic cleanup
func (mh *MessageHistory) Stop() {
	close(mh.cleanupStop)
}

// GetStats returns optimized statistics
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

// Session history isolation - no more global singleton
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

// ResetMessageHistory safely resets global history
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
	for sessionID, history := range sessionHistories {
		sessionStats[sessionID] = history.GetStats()
	}
	stats["sessions"] = sessionStats

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

// GetRecipientHistoryStats returns statistics for a specific recipient in a session
func GetRecipientHistoryStats(sessionID string, recipient string) map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	if history, exists := sessionHistories[sessionID]; exists {
		return history.GetRecipientStats(recipient)
	}

	return map[string]interface{}{
		"error": "session not found",
	}
}

// Message filtering and routing utilities

// MessageFilter represents a filter for messages
type MessageFilter struct {
	Recipients []string          `json:"recipients,omitempty"`
	FromTime   *time.Time        `json:"from_time,omitempty"`
	ToTime     *time.Time        `json:"to_time,omitempty"`
	MessageIDs []string          `json:"message_ids,omitempty"`
	SessionIDs []string          `json:"session_ids,omitempty"`
	MaxResults int               `json:"max_results,omitempty"`
	Custom     map[string]string `json:"custom,omitempty"`
}

// ValidateMessageFilter validates a message filter
func ValidateMessageFilter(filter *MessageFilter) error {
	if filter == nil {
		return errors.New("filter cannot be nil")
	}

	// Validate recipients
	for _, recipient := range filter.Recipients {
		if err := ValidateRecipient(recipient); err != nil {
			return fmt.Errorf("invalid recipient '%s': %w", recipient, err)
		}
	}

	// Validate message IDs
	for _, msgID := range filter.MessageIDs {
		if err := ValidateMessageID(msgID); err != nil {
			return fmt.Errorf("invalid message ID '%s': %w", msgID, err)
		}
	}

	// Validate session IDs
	for _, sessionID := range filter.SessionIDs {
		if err := ValidateSessionIDString(sessionID); err != nil {
			return fmt.Errorf("invalid session ID '%s': %w", sessionID, err)
		}
	}

	// Validate time range
	if filter.FromTime != nil && filter.ToTime != nil {
		if filter.FromTime.After(*filter.ToTime) {
			return errors.New("from_time cannot be after to_time")
		}
	}

	// Validate max results
	if filter.MaxResults < 0 {
		return errors.New("max_results cannot be negative")
	}
	if filter.MaxResults > 10000 {
		filter.MaxResults = 10000 // Cap at reasonable limit
	}

	return nil
}

// MessageInfo represents information about a message without the content
type MessageInfo struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Recipient string    `json:"recipient"`
	SessionID string    `json:"session_id"`
	Size      int       `json:"size"`
	TTL       int       `json:"ttl"`
}

// ExtractMessageInfo extracts metadata from an envelope without revealing content
func ExtractMessageInfo(envelope *Envelope) *MessageInfo {
	if envelope == nil {
		return nil
	}

	return &MessageInfo{
		ID:        envelope.ID,
		Timestamp: time.Unix(envelope.Timestamp, 0),
		Recipient: envelope.Recipient,
		SessionID: envelope.SessionID,
		Size:      len(envelope.Data),
		TTL:       envelope.TTL,
	}
}

// Enhanced statistics and monitoring

// GetDetailedMessageStats returns detailed statistics about messages
func GetDetailedMessageStats() map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	totalMessages := 0
	totalRecipients := make(map[string]int)
	sessionCount := len(sessionHistories)
	oldestMessage := time.Now()
	newestMessage := time.Time{}

	for _, history := range sessionHistories {
		history.mu.RLock()

		sessionMessages := len(history.messages)
		totalMessages += sessionMessages

		// Count messages per recipient
		for recipient, msgIDs := range history.recipientIndex {
			totalRecipients[recipient] += len(msgIDs)
		}

		// Find oldest and newest messages
		for _, entry := range history.messages {
			if entry.timestamp.Before(oldestMessage) {
				oldestMessage = entry.timestamp
			}
			if entry.timestamp.After(newestMessage) {
				newestMessage = entry.timestamp
			}
		}

		history.mu.RUnlock()
	}

	stats := map[string]interface{}{
		"total_messages":    totalMessages,
		"total_sessions":    sessionCount,
		"unique_recipients": len(totalRecipients),
		"recipients_stats":  totalRecipients,
	}

	if totalMessages > 0 {
		stats["oldest_message"] = oldestMessage
		stats["newest_message"] = newestMessage
		stats["time_span"] = newestMessage.Sub(oldestMessage)
	}

	return stats
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

// Advanced message operations

// FindMessagesByRecipient finds all messages for a specific recipient across sessions
func FindMessagesByRecipient(recipient string, limit int) []MessageInfo {
	if limit <= 0 {
		limit = 100
	}

	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	var results []MessageInfo

	for _, history := range sessionHistories {
		history.mu.RLock()

		if msgIDs, exists := history.recipientIndex[recipient]; exists {
			for _, msgID := range msgIDs {
				if len(results) >= limit {
					history.mu.RUnlock()
					return results
				}

				if entry, exists := history.messages[msgID]; exists {
					info := MessageInfo{
						ID:        entry.msgID,
						Timestamp: entry.timestamp,
						Recipient: entry.recipient,
						Size:      0, // Size not stored in entry
					}
					results = append(results, info)
				}
			}
		}

		history.mu.RUnlock()
	}

	return results
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

// GetMessageInfo retrieves information about a specific message
func GetMessageInfo(msgID string) *MessageInfo {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	for _, history := range sessionHistories {
		history.mu.RLock()

		if entry, exists := history.messages[msgID]; exists {
			info := &MessageInfo{
				ID:        entry.msgID,
				Timestamp: entry.timestamp,
				Recipient: entry.recipient,
				Size:      0, // Size not stored in entry
			}
			history.mu.RUnlock()
			return info
		}

		history.mu.RUnlock()
	}

	return nil
}

// Performance optimizations and caching

// MessageCache represents a simple LRU cache for recent messages
type MessageCache struct {
	entries    map[string]*MessageInfo
	order      []string
	maxEntries int
	mu         sync.RWMutex
}

// NewMessageCache creates a new message cache
func NewMessageCache(maxEntries int) *MessageCache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}

	return &MessageCache{
		entries:    make(map[string]*MessageInfo),
		order:      make([]string, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// Get retrieves a message info from cache
func (mc *MessageCache) Get(msgID string) (*MessageInfo, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	info, exists := mc.entries[msgID]
	return info, exists
}

// Put stores a message info in cache
func (mc *MessageCache) Put(msgID string, info *MessageInfo) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// If already exists, update and move to front
	if _, exists := mc.entries[msgID]; exists {
		mc.entries[msgID] = info
		mc.moveToFront(msgID)
		return
	}

	// Add new entry
	mc.entries[msgID] = info
	mc.order = append([]string{msgID}, mc.order...)

	// Evict if necessary
	if len(mc.order) > mc.maxEntries {
		oldest := mc.order[len(mc.order)-1]
		delete(mc.entries, oldest)
		mc.order = mc.order[:len(mc.order)-1]
	}
}

// moveToFront moves an entry to the front of the order slice
func (mc *MessageCache) moveToFront(msgID string) {
	for i, id := range mc.order {
		if id == msgID {
			// Remove from current position
			mc.order = append(mc.order[:i], mc.order[i+1:]...)
			// Add to front
			mc.order = append([]string{msgID}, mc.order...)
			break
		}
	}
}

// Clear clears the cache
func (mc *MessageCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.entries = make(map[string]*MessageInfo)
	mc.order = mc.order[:0]
}

// Size returns the current cache size
func (mc *MessageCache) Size() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.entries)
}
