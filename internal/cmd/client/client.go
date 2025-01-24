package main

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"protectora-rocher/pkg/communication"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Erreur de connexion au serveur:", err)
		return
	}
	defer conn.Close()

	sharedKey := []byte("thisisaverysecurekey!")

	// Goroutine pour écouter les messages entrants
	go func() {
		for {
			response, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Println("Erreur de réception:", err)
				break
			}

			decryptedMsg, err := communication.DecryptMessage(response, sharedKey)
			if err != nil {
				fmt.Println("Erreur de déchiffrement:", err)
			} else {
				fmt.Println("Message reçu :", decryptedMsg)
			}
		}
	}()

	fmt.Println("Tapez vos messages (exit pour quitter):")
	for {
		fmt.Print("> ")
		text, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if text == "exit\n" {
			break
		}

		encryptedMsg, err := communication.EncryptMessage(text, sharedKey)
		if err != nil {
			fmt.Println("Erreur de chiffrement:", err)
			continue
		}

		_, err = conn.Write([]byte(encryptedMsg + "\n"))
		if err != nil {
			fmt.Println("Erreur d'envoi du message:", err)
			break
		}
	}
}
