// api_test.go
package test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/rocher"
)

// TestBasicClientServer teste la communication client-serveur de base
func TestBasicClientServer(t *testing.T) {
	t.Log("Test de communication client-serveur de base...")

	port := ":18080"
	address := "localhost" + port

	// Variables pour capturer les messages
	var receivedMessages []struct {
		clientID  string
		message   string
		recipient string
	}
	var mu sync.Mutex

	// Créer le serveur
	server, err := rocher.QuickServer(address, func(clientID, message, recipient string) {
		mu.Lock()
		receivedMessages = append(receivedMessages, struct {
			clientID  string
			message   string
			recipient string
		}{clientID, message, recipient})
		mu.Unlock()
		t.Logf("📥 Serveur reçu de %s: '%s' pour '%s'", clientID, message, recipient)
	})
	if err != nil {
		t.Fatalf("Erreur création serveur: %v", err)
	}
	defer server.Close()

	// Démarrer le serveur
	if err := server.Start(); err != nil {
		t.Fatalf("Erreur démarrage serveur: %v", err)
	}

	// Attendre que le serveur soit prêt
	time.Sleep(100 * time.Millisecond)

	// Créer le client
	var clientMessages []struct {
		message   string
		recipient string
	}
	var clientMu sync.Mutex

	client, err := rocher.QuickClient(address, "alice", func(message, recipient string) {
		clientMu.Lock()
		clientMessages = append(clientMessages, struct {
			message   string
			recipient string
		}{message, recipient})
		clientMu.Unlock()
		t.Logf("📥 Client reçu: '%s' pour '%s'", message, recipient)
	})
	if err != nil {
		t.Fatalf("Erreur création client: %v", err)
	}
	defer client.Close()

	// Attendre que la connexion soit établie
	time.Sleep(200 * time.Millisecond)

	// Vérifier que le client est connecté
	if !client.IsConnected() {
		t.Fatal("Client devrait être connecté")
	}

	// Vérifier l'ID utilisateur
	if client.GetUserID() != "alice" {
		t.Errorf("UserID incorrect. Attendu: 'alice', Reçu: '%s'", client.GetUserID())
	}

	// Test d'envoi client → serveur
	testMessages := []struct {
		message   string
		recipient string
	}{
		{"Hello Server!", "server@example.com"},
		{"Message avec émojis 🚀", "admin@example.com"},
		{"Caractères spéciaux: àéîôù", "user@example.com"},
	}

	for i, tm := range testMessages {
		t.Run(fmt.Sprintf("ClientToServer_%d", i+1), func(t *testing.T) {
			err := client.Send(tm.message, tm.recipient)
			if err != nil {
				t.Fatalf("Erreur envoi message: %v", err)
			}

			// Attendre que le message soit reçu
			time.Sleep(100 * time.Millisecond)

			mu.Lock()
			found := false
			for _, received := range receivedMessages {
				if received.message == tm.message && received.recipient == tm.recipient {
					found = true
					break
				}
			}
			mu.Unlock()

			if !found {
				t.Errorf("Message non reçu par le serveur: '%s' pour '%s'", tm.message, tm.recipient)
			} else {
				t.Logf("✅ Message transmis: '%s' pour '%s'", tm.message, tm.recipient)
			}
		})
	}

	// Test d'envoi serveur → client
	t.Run("ServerToClient", func(t *testing.T) {
		testMsg := "Hello Client from Server!"
		testRecipient := "alice@client.com"

		err := server.Send(testMsg, testRecipient)
		if err != nil {
			t.Fatalf("Erreur envoi du serveur: %v", err)
		}

		// Attendre que le message soit reçu
		time.Sleep(100 * time.Millisecond)

		clientMu.Lock()
		found := false
		for _, received := range clientMessages {
			if received.message == testMsg && received.recipient == testRecipient {
				found = true
				break
			}
		}
		clientMu.Unlock()

		if !found {
			t.Errorf("Message du serveur non reçu par le client: '%s' pour '%s'", testMsg, testRecipient)
		} else {
			t.Logf("✅ Message serveur→client transmis: '%s' pour '%s'", testMsg, testRecipient)
		}
	})

	t.Log("✅ Test communication client-serveur réussi")
}

// TestMultipleClients teste plusieurs clients connectés simultanément
func TestMultipleClients(t *testing.T) {
	t.Log("Test de clients multiples...")

	port := ":18081"
	address := "localhost" + port

	// Structure pour suivre les messages reçus par client
	type ReceivedMessage struct {
		ClientID  string
		Message   string
		Recipient string
	}

	var receivedMessages []ReceivedMessage
	var mu sync.Mutex

	// Créer le serveur
	server, err := rocher.QuickServer(address, func(clientID, message, recipient string) {
		mu.Lock()
		receivedMessages = append(receivedMessages, ReceivedMessage{
			ClientID:  clientID,
			Message:   message,
			Recipient: recipient,
		})
		mu.Unlock()
		t.Logf("📥 Serveur reçu de %s: '%s' pour '%s'", clientID, message, recipient)
	})
	if err != nil {
		t.Fatalf("Erreur création serveur: %v", err)
	}
	defer server.Close()

	if err := server.Start(); err != nil {
		t.Fatalf("Erreur démarrage serveur: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Créer plusieurs clients
	clientNames := []string{"alice", "bob", "charlie"}
	clients := make([]*rocher.Client, len(clientNames))

	for i, name := range clientNames {
		client, err := rocher.QuickClient(address, name, func(message, recipient string) {
			t.Logf("📥 Client %s reçu: '%s' pour '%s'", name, message, recipient)
		})
		if err != nil {
			t.Fatalf("Erreur création client %s: %v", name, err)
		}
		clients[i] = client
		defer client.Close()

		// Vérifier l'ID utilisateur
		if client.GetUserID() != name {
			t.Errorf("UserID incorrect pour %s. Attendu: '%s', Reçu: '%s'",
				name, name, client.GetUserID())
		}
	}

	time.Sleep(300 * time.Millisecond)

	// Vérifier que tous les clients sont connectés
	connectedClients := server.GetClients()
	if len(connectedClients) != len(clientNames) {
		t.Errorf("Nombre de clients connectés incorrect. Attendu: %d, Reçu: %d",
			len(clientNames), len(connectedClients))
	}

	t.Logf("✅ %d clients connectés: %v", len(connectedClients), connectedClients)

	// Test d'envoi depuis chaque client
	for i, client := range clients {
		clientName := clientNames[i]
		message := fmt.Sprintf("Message from %s", clientName)
		recipient := fmt.Sprintf("%s@example.com", clientName)

		err := client.Send(message, recipient)
		if err != nil {
			t.Errorf("Erreur envoi depuis %s: %v", clientName, err)
			continue
		}

		time.Sleep(50 * time.Millisecond)

		// Vérifier réception
		mu.Lock()
		found := false
		for _, received := range receivedMessages {
			if received.Message == message && received.Recipient == recipient {
				found = true
				break
			}
		}
		mu.Unlock()

		if !found {
			t.Errorf("Message de %s non reçu", clientName)
		} else {
			t.Logf("✅ Message de %s reçu", clientName)
		}
	}

	// Test d'envoi broadcast depuis le serveur
	t.Run("ServerBroadcast", func(t *testing.T) {
		broadcastMsg := "Message broadcast à tous!"
		broadcastRecipient := "all@broadcast.com"

		err := server.Send(broadcastMsg, broadcastRecipient)
		if err != nil {
			t.Fatalf("Erreur broadcast: %v", err)
		}

		time.Sleep(200 * time.Millisecond)
		t.Log("✅ Broadcast envoyé à tous les clients")
	})

	t.Log("✅ Test clients multiples réussi")
}

// TestClientOptions teste les différentes options de configuration
func TestClientOptions(t *testing.T) {
	t.Log("Test des options de configuration...")

	port := ":18082"
	address := "localhost" + port

	// Test avec options personnalisées
	opts := rocher.DefaultClientOptions()
	opts.UserID = "test_user"
	opts.ConnectTimeout = 5 * time.Second
	opts.SendTimeout = 3 * time.Second
	opts.Debug = true

	var receivedMessage, receivedRecipient string
	opts.OnMessage = func(message, recipient string) {
		receivedMessage = message
		receivedRecipient = recipient
	}

	// Créer serveur avec options par défaut
	server, err := rocher.NewServer(address, rocher.DefaultClientOptions())
	if err != nil {
		t.Fatalf("Erreur création serveur: %v", err)
	}
	defer server.Close()

	server.Start()
	time.Sleep(100 * time.Millisecond)

	// Créer client avec options personnalisées
	client, err := rocher.NewClient(address, opts)
	if err != nil {
		t.Fatalf("Erreur création client: %v", err)
	}
	defer client.Close()

	time.Sleep(200 * time.Millisecond)

	// Vérifier les options
	if client.GetUserID() != "test_user" {
		t.Errorf("UserID incorrect. Attendu: 'test_user', Reçu: '%s'", client.GetUserID())
	}

	// Test d'envoi pour vérifier le callback
	testMsg := "Test message"
	testRecipient := "callback@test.com"

	err = server.Send(testMsg, testRecipient)
	if err != nil {
		t.Fatalf("Erreur envoi: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if receivedMessage != testMsg {
		t.Errorf("Message callback incorrect. Attendu: '%s', Reçu: '%s'", testMsg, receivedMessage)
	}
	if receivedRecipient != testRecipient {
		t.Errorf("Recipient callback incorrect. Attendu: '%s', Reçu: '%s'", testRecipient, receivedRecipient)
	}
	t.Log("✅ Test options de configuration réussi")
}
