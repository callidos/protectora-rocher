package communication

import (
	"bufio"
	"fmt"
	"net"
)

func HandleConnection(conn net.Conn) {
	defer conn.Close()

	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("Erreur de lecture:", err)
		return
	}

	fmt.Println("Message reçu du client:", message)

	_, err = fmt.Fprintf(conn, "Message reçu: %s", message)
	if err != nil {
		fmt.Println("Erreur d'envoi de réponse:", err)
	}
}
