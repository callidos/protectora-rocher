package communication

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const keyRotationInterval = 10 * time.Minute

var (
	mutex       sync.Mutex
	currentKey  [32]byte
	lastKeyTime time.Time
)

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur de génération de clé Ed25519 : %v", err)
	}
	return publicKey, privateKey, nil
}

func PerformAuthenticatedKeyExchange(conn net.Conn, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) ([32]byte, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if time.Since(lastKeyTime) > keyRotationInterval || currentKey == [32]byte{} {
		fmt.Println("Rotation des clés en cours...")
		err := exchangeNewSessionKey(conn, privateKey, publicKey)
		if err != nil {
			return [32]byte{}, err
		}
		lastKeyTime = time.Now()
	}
	return currentKey, nil
}

func exchangeNewSessionKey(conn net.Conn, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) error {
	var privateCurve25519 [32]byte
	_, err := rand.Read(privateCurve25519[:])
	if err != nil {
		return fmt.Errorf("erreur de génération de clé privée Curve25519 : %v", err)
	}

	var publicCurve25519 [32]byte
	curve25519.ScalarBaseMult(&publicCurve25519, &privateCurve25519)

	_, err = conn.Write(publicCurve25519[:])
	if err != nil {
		return fmt.Errorf("erreur d'envoi de la clé publique")
	}

	var peerPublicKey [32]byte
	_, err = conn.Read(peerPublicKey[:])
	if err != nil {
		return fmt.Errorf("erreur de réception de la clé publique")
	}

	_, err = conn.Write(publicKey)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de la clé publique Ed25519")
	}

	peerEd25519Key := make([]byte, ed25519.PublicKeySize)
	_, err = conn.Read(peerEd25519Key)
	if err != nil {
		return fmt.Errorf("erreur de réception de la clé publique Ed25519")
	}

	signature := ed25519.Sign(privateKey, peerPublicKey[:])
	_, err = conn.Write(signature)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de la signature")
	}

	signatureReceived := make([]byte, ed25519.SignatureSize)
	_, err = conn.Read(signatureReceived)
	if err != nil {
		return fmt.Errorf("erreur de réception de la signature")
	}

	if !ed25519.Verify(peerEd25519Key, publicCurve25519[:], signatureReceived) {
		return fmt.Errorf("échec de la vérification de la signature")
	}

	sharedKey, err := curve25519.X25519(privateCurve25519[:], peerPublicKey[:])
	if err != nil {
		return fmt.Errorf("erreur de génération de la clé partagée")
	}

	copy(currentKey[:], sharedKey)

	fmt.Println("Nouvelle clé de session échangée avec succès.")

	return nil
}
