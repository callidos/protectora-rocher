package main

import (
	"fmt"
	"io"
	"net"
	"sync"
)

var clients = make(map[net.Conn]bool)
var mutex sync.Mutex

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Serveur relais en attente de connexions...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Erreur d'acceptation de connexion:", err)
			continue
		}

		mutex.Lock()
		clients[conn] = true
		mutex.Unlock()

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer func() {
		mutex.Lock()
		delete(clients, conn)
		mutex.Unlock()
		conn.Close()
	}()

	fmt.Println("Nouvelle connexion:", conn.RemoteAddr())

	for {
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				fmt.Println("Client déconnecté:", conn.RemoteAddr())
			} else {
				fmt.Println("Erreur de lecture:", err)
			}
			break
		}

		relayMessage(buffer[:n], conn)
	}
}

func relayMessage(msg []byte, sender net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	for conn := range clients {
		if conn != sender {
			_, err := conn.Write(msg)
			if err != nil {
				fmt.Println("Erreur d'envoi du message:", err)
			}
		}
	}
}
