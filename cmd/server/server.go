package main

import (
	"fmt"
	"log"
	"net"
	"protocole-comm/pkg/communication"
)

func main() {
	listen, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Erreur d'écoute:", err)
	}
	defer listen.Close()

	fmt.Println("Serveur démarré, en attente de connexions...")

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal("Erreur d'acceptation de connexion:", err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		fmt.Println("Erreur d'échange de clés:", err)
		return
	}

	fmt.Println("Clé partagée générée:", sharedKey)
}
