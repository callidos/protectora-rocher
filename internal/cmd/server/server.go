package main

import (
	"log"
	"net"
	"protectora-rocher/pkg/communication"

	"github.com/gordonklaus/portaudio"
)

func main() {
	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatalf("Erreur lors de l'écoute : %v", err)
	}
	defer listener.Close()

	log.Println("Serveur de communication vocale sécurisé en écoute sur le port 8443...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Erreur d'acceptation de la connexion :", err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 4096)
	portaudio.Initialize()
	defer portaudio.Terminate()

	stream, err := portaudio.OpenDefaultStream(0, 1, 44100, len(buffer)/2, buffer)
	if err != nil {
		log.Fatalf("Erreur ouverture du flux audio : %v", err)
	}
	defer stream.Close()

	log.Println("En attente de données audio...")

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Println("Erreur de réception des données audio :", err)
			return
		}

		decryptedData, err := communication.DecryptAudio(buffer[:n])
		if err != nil {
			log.Println("Erreur de déchiffrement :", err)
			return
		}

		stream.Write()
		log.Println("Audio joué avec succès.")

		encryptedResponse, _ := communication.EncryptAudio(decryptedData)
		conn.Write(encryptedResponse)
	}
}
