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

func PerformKeyExchange(conn net.Conn) ([curve25519.ScalarSize]byte, error) {
	clientPrivateKey, clientPublicKey, err := GenerateKeyPair()
	if err != nil {
		return [curve25519.ScalarSize]byte{}, fmt.Errorf("erreur de génération des clés du client: %v", err)
	}

	_, err = conn.Write(clientPublicKey[:])
	if err != nil {
		return [curve25519.ScalarSize]byte{}, fmt.Errorf("erreur d'envoi de la clé publique du client: %v", err)
	}

	serverPublicKey := [curve25519.PointSize]byte{}
	_, err = conn.Read(serverPublicKey[:])
	if err != nil {
		return [curve25519.ScalarSize]byte{}, fmt.Errorf("erreur de lecture de la clé publique du serveur: %v", err)
	}

	sharedKey, err := GenerateSharedKey(clientPrivateKey, serverPublicKey)
	if err != nil {
		return [curve25519.ScalarSize]byte{}, err
	}

	return sharedKey, nil
}
