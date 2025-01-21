package communication

import (
	"crypto/rand"
	"fmt"
	"net"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeyPair() ([curve25519.ScalarSize]byte, [curve25519.PointSize]byte, error) {
	privateKey := [curve25519.ScalarSize]byte{}
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return privateKey, [curve25519.PointSize]byte{}, fmt.Errorf("erreur de génération de la clé privée: %v", err)
	}

	var publicKey [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return privateKey, publicKey, nil
}

func GenerateSharedKey(privateKey [curve25519.ScalarSize]byte, otherPublicKey [curve25519.PointSize]byte) ([curve25519.ScalarSize]byte, error) {
	var sharedKey [curve25519.ScalarSize]byte
	sharedSecret, err := curve25519.X25519(privateKey[:], otherPublicKey[:])
	if err != nil {
		return sharedKey, fmt.Errorf("erreur de génération de la clé partagée: %v", err)
	}

	copy(sharedKey[:], sharedSecret)
	return sharedKey, nil
}

func PerformKeyExchange(conn net.Conn) ([32]byte, error) {
	privateKey := [32]byte{}
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de génération de clé privée: %v", err)
	}

	publicKey := [32]byte{}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	_, err = conn.Write(publicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur d'envoi de clé publique: %v", err)
	}

	peerPublicKey := [32]byte{}
	_, err = conn.Read(peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de réception de clé publique: %v", err)
	}

	sharedKey, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de génération de la clé partagée: %v", err)
	}

	var finalKey [32]byte
	copy(finalKey[:], sharedKey)

	return finalKey, nil
}
