package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"protocole-comm/pkg/communication"
)

func main() {
	serverAddress := flag.String("server", "localhost:8080", "Adresse du serveur (par défaut localhost:8080)")
	message := flag.String("message", "", "Message à envoyer au serveur")
	flag.Parse()

	if *message == "" {
		fmt.Println("Erreur : Le message ne peut pas être vide.")
		flag.Usage()
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", *serverAddress)
	if err != nil {
		log.Fatal("Erreur de connexion au serveur:", err)
		os.Exit(1)
	}
	defer conn.Close()

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		log.Fatal("Erreur d'échange de clés:", err)
	}

	sharedKeySlice := sharedKey[:]

	fmt.Println("Clé partagée générée:", sharedKeySlice)

	err = communication.SendMessage(conn, *message, sharedKeySlice)
	if err != nil {
		log.Fatal("Erreur d'envoi de message:", err)
	}

	fmt.Println("Message envoyé au serveur:", *message)
}
