package tests

import (
	"strconv"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// Test secure message sending with various durations
func TestSendMessage(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")
	msg := "Test message"

	tests := []struct {
		duration   int
		shouldFail bool
	}{
		{0, false},
		{60, false},
		{-10, true},
	}

	for _, tc := range tests {
		mockConn.Buffer.Reset()
		err := communication.SendMessage(mockConn, msg, key, 1, tc.duration)

		if (err != nil) != tc.shouldFail {
			t.Errorf("Duration %d: expected failure: %v, got error: %v", tc.duration, tc.shouldFail, err)
		} else if err == nil && mockConn.Buffer.String() == "" {
			t.Error("Message was not sent")
		}
	}
}

// Test receiving valid secure messages
func TestReceiveMessage(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")
	msg := "Test message"

	data := "1|" + strconv.FormatInt(time.Now().Unix(), 10) + "|60|" + msg
	encrypted, _ := communication.EncryptAESGCM([]byte(data), key)
	mockConn.Buffer.WriteString(encrypted + "|" + communication.GenerateHMAC(encrypted, key) + "\n")

	received, err := communication.ReceiveMessage(mockConn, key)
	if err != nil || received != msg {
		t.Errorf("Expected: %q, got: %q, error: %v", msg, received, err)
	}
}

// Test replay attack detection
func TestReplayAttack(t *testing.T) {
	communication.ResetMessageHistory()
	mockConn := &MockConnection{}
	key := []byte("securekey!")

	data := "1|" + strconv.FormatInt(time.Now().Unix(), 10) + "|0|Replay attack"
	encrypted, _ := communication.EncryptAESGCM([]byte(data), key)
	mockConn.Buffer.WriteString(encrypted + "|" + communication.GenerateHMAC(encrypted, key) + "\n")

	_, err := communication.ReceiveMessage(mockConn, key)
	if err != nil {
		t.Fatal("Unexpected error on first reception:", err)
	}

	mockConn.Buffer.Reset()
	mockConn.Buffer.WriteString(encrypted + "|" + communication.GenerateHMAC(encrypted, key) + "\n")

	if _, err := communication.ReceiveMessage(mockConn, key); err == nil {
		t.Error("Replay attack was not detected")
	}
}

// Test rejection of corrupted messages (invalid HMAC)
func TestCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")

	mockConn.Buffer.WriteString("corrupt_message|invalidHMAC\n")

	if _, err := communication.ReceiveMessage(mockConn, key); err == nil {
		t.Error("Corrupted message was not rejected")
	}
}

// Test expired message rejection
func TestExpiredMessage(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")

	data := "2|" + strconv.FormatInt(time.Now().Unix()-1000, 10) + "|500|Expired"
	encrypted, _ := communication.EncryptAESGCM([]byte(data), key)
	mockConn.Buffer.WriteString(encrypted + "|" + communication.GenerateHMAC(encrypted, key) + "\n")

	if _, err := communication.ReceiveMessage(mockConn, key); err == nil {
		t.Error("Expired message was not rejected")
	}
}

// Test malformed message rejection
func TestMalformedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")

	mockConn.Buffer.WriteString("malformed_message\n")

	if _, err := communication.ReceiveMessage(mockConn, key); err == nil {
		t.Error("Malformed message was not rejected")
	}
}

// Performance test for sending and receiving messages
func TestMessagePerformance(t *testing.T) {
	mockConn := &MockConnection{}
	key := []byte("securekey!")
	msg := "Performance test message"

	start := time.Now()

	for i := 0; i < 1000; i++ {
		if err := communication.SendMessage(mockConn, msg, key, 1, 0); err != nil {
			t.Fatalf("Error sending message: %v", err)
		}
	}

	t.Logf("Time for 1000 messages: %v", time.Since(start))
}
