package tests

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"protectora-rocher/pkg/communication"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestFullKyberExchange performs a full client-server key exchange simulation
func TestFullKyberExchange(t *testing.T) {
	serverPubKey, serverPrivKey, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server Ed25519 keys: %v", err)
	}

	serverConn, clientConn := net.Pipe()

	// Pass the private key as ed25519.PrivateKey
	resultChan, err := communication.PerformAuthenticatedKeyExchange(
		serverConn,
		serverPrivKey, // We use the private key directly, since the public key is not needed in this function.
	)
	if err != nil {
		t.Fatalf("Server setup error: %v", err)
	}

	// Simulate client-side logic
	clientSharedKey, clientErr := simulateClient(clientConn, serverPubKey)
	if clientErr != nil {
		t.Fatalf("Client error: %v", clientErr)
	}
	clientConn.Close()

	// Get the key exchange result from the server
	result := <-resultChan
	if result.Err != nil {
		t.Fatalf("Server error: %v", result.Err)
	}

	// Check if the shared keys match
	if !bytes.Equal(result.Key[:], clientSharedKey) {
		t.Fatalf("Shared keys do not match.\nServer: %x\nClient: %x", result.Key[:], clientSharedKey)
	}
}

// simulateClient handles the client-side logic of the Kyber exchange
func simulateClient(conn net.Conn, serverPubEd25519 ed25519.PublicKey) ([]byte, error) {
	// Read the Kyber public key and signature
	pkBytes, err := readBytesWithLength(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read Kyber public key: %v", err)
	}

	signature, err := readBytesWithLength(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ed25519 signature: %v", err)
	}

	// Verify the signature using the server's public key
	if !ed25519.Verify(serverPubEd25519, pkBytes, signature) {
		return nil, fmt.Errorf("invalid Ed25519 signature")
	}

	// Unpack the Kyber public key (no return value for Unpack)
	var pkServer kyber768.PublicKey
	pkServer.Unpack(pkBytes) // This modifies pkServer directly

	// Prepare ciphertext and shared key
	ct := make([]byte, kyber768.CiphertextSize)
	sharedKey := make([]byte, kyber768.SharedKeySize)
	pkServer.EncapsulateTo(ct, sharedKey, nil)

	// Send the ciphertext to the server
	if err := writeBytesWithLength(conn, ct); err != nil {
		return nil, fmt.Errorf("failed to send Kyber ciphertext: %v", err)
	}

	return sharedKey, nil
}

// readBytesWithLength reads length-prefixed data from the connection
func readBytesWithLength(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}

	length := (uint32(lenBuf[0]) << 24) | (uint32(lenBuf[1]) << 16) | (uint32(lenBuf[2]) << 8) | uint32(lenBuf[3])
	data := make([]byte, length)

	if _, err := conn.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// writeBytesWithLength sends length-prefixed data to the connection
func writeBytesWithLength(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	lenBuf := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}
