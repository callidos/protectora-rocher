package communication

import (
	"fmt"
	"net"
)

func SendMessage(conn net.Conn, message string) error {
	_, err := fmt.Fprintf(conn, "%s", message+"\n")
	return err
}
