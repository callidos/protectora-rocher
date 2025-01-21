package communication

import (
	"crypto/rand"
	"fmt"
	"net"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

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

func PerformAuthenticatedKeyExchange(conn net.Conn, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) ([32]byte, error) {
	var privateCurve25519 [32]byte
	_, err := rand.Read(privateCurve25519[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de génération de la clé privée : %v", err)
	}

	var publicCurve25519 [32]byte
	curve25519.ScalarBaseMult(&publicCurve25519, &privateCurve25519)

	_, err = conn.Write(publicCurve25519[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur d'envoi de la clé publique Curve25519")
	}

	var peerPublicKey [32]byte
	_, err = conn.Read(peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de réception de la clé publique Curve25519")
	}

	_, err = conn.Write(publicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur d'envoi de la clé publique Ed25519")
	}

	peerEd25519Key := make([]byte, ed25519.PublicKeySize)
	_, err = conn.Read(peerEd25519Key)
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de réception de la clé publique Ed25519")
	}

	signature := ed25519.Sign(privateKey, peerPublicKey[:])
	_, err = conn.Write(signature)
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur d'envoi de la signature")
	}

	signatureReceived := make([]byte, ed25519.SignatureSize)
	_, err = conn.Read(signatureReceived)
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de réception de la signature")
	}

	if !ed25519.Verify(peerEd25519Key, publicCurve25519[:], signatureReceived) {
		return [32]byte{}, fmt.Errorf("échec de la vérification de la signature")
	}

	sharedKey, err := curve25519.X25519(privateCurve25519[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("erreur de génération de la clé partagée")
	}

	var finalKey [32]byte
	copy(finalKey[:], sharedKey)

	return finalKey, nil
}
