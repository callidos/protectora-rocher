package main

import (
	"log"
	"net"
	"os"
	"protectora-rocher/pkg/communication"

	"github.com/gordonklaus/portaudio"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8443")
	if err != nil {
		log.Fatalf("Erreur lors de la connexion au serveur : %v", err)
	}
	defer conn.Close()

	log.Println("Connecté au serveur vocal sécurisé. Parlez maintenant...")

	portaudio.Initialize()
	defer portaudio.Terminate()

	buffer := make([]byte, 4096)
	stream, err := portaudio.OpenDefaultStream(1, 0, 44100, len(buffer)/2, buffer)
	if err != nil {
		log.Fatalf("Erreur ouverture du flux audio : %v", err)
	}
	defer stream.Close()

	stream.Start()
	for {
		err := stream.Read()
		if err != nil {
			log.Println("Erreur de lecture audio :", err)
			break
		}

		encryptedData, err := communication.EncryptAudio(buffer)
		if err != nil {
			log.Println("Erreur de chiffrement :", err)
			break
		}

		_, err = conn.Write(encryptedData)
		if err != nil {
			log.Println("Erreur d'envoi du message :", err)
			break
		}

		response := make([]byte, 4096)
		n, err := conn.Read(response)
		if err != nil {
			log.Println("Erreur de réception de la réponse :", err)
			break
		}

		decryptedResponse, err := communication.DecryptAudio(response[:n])
		if err != nil {
			log.Println("Erreur de déchiffrement de la réponse :", err)
			break
		}

		log.Println("Relecture du son reçu...")
		os.Stdout.Write(decryptedResponse)
	}
}
