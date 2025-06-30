package test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/rocher"
)

// TestParseAddress teste le parsing des adresses
func TestParseAddress(t *testing.T) {
	fmt.Println("=== Test: Parse d'adresses ===")

	tests := []struct {
		input           string
		expectedNetwork string
		expectedAddr    string
		shouldError     bool
		description     string
	}{
		{"tcp://localhost:8080", "tcp", "localhost:8080", false, "Format complet TCP"},
		{"tcp4://127.0.0.1:9000", "tcp4", "127.0.0.1:9000", false, "TCP IPv4 explicite"},
		{"localhost:8080", "tcp", "localhost:8080", false, "Format court (TCP par défaut)"},
		{"127.0.0.1:9999", "tcp", "127.0.0.1:9999", false, "IP avec port"},
		{"udp://localhost:8080", "", "", true, "Protocole non supporté"},
		{"localhost", "", "", true, "Port manquant"},
		{"://localhost:8080", "", "", true, "Protocole vide"},
		{"tcp://", "", "", true, "Adresse vide"},
	}

	for i, test := range tests {
		fmt.Printf("Test %d: %s\n", i+1, test.description)

		// Utiliser une fonction interne simulée pour tester
		network, addr, err := parseAddressTest(test.input)

		if test.shouldError {
			if err == nil {
				t.Errorf("Test %d: Devrait retourner une erreur pour '%s'", i+1, test.input)
			} else {
				fmt.Printf("  ✅ Erreur attendue: %v\n", err)
			}
		} else {
			if err != nil {
				t.Errorf("Test %d: Erreur inattendue pour '%s': %v", i+1, test.input, err)
			} else if network != test.expectedNetwork || addr != test.expectedAddr {
				t.Errorf("Test %d: Résultat incorrect\n  Attendu: %s://%s\n  Obtenu: %s://%s",
					i+1, test.expectedNetwork, test.expectedAddr, network, addr)
			} else {
				fmt.Printf("  ✅ Correct: %s://%s\n", network, addr)
			}
		}
	}

	fmt.Println("✅ Tests de parsing terminés")
}

// parseAddressTest simule la fonction parseAddress pour les tests
func parseAddressTest(address string) (network, addr string, err error) {
	if strings.Contains(address, "://") {
		parts := strings.SplitN(address, "://", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("format d'adresse invalide")
		}

		network = parts[0]
		addr = parts[1]

		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return "", "", fmt.Errorf("protocole non supporté: %s", network)
		}

		if addr == "" {
			return "", "", fmt.Errorf("adresse vide")
		}
	} else {
		network = "tcp"
		addr = address
	}

	if !strings.Contains(addr, ":") {
		return "", "", fmt.Errorf("port manquant dans l'adresse")
	}

	return network, addr, nil
}

// TestClientServerBasic teste la communication client-serveur de base
func TestClientServerBasic(t *testing.T) {
	fmt.Println("=== Test: Client-Serveur basique ===")

	serverPort := ":8901" // Port de test unique
	var wg sync.WaitGroup
	var serverErr, clientErr error

	// Messages de test
	testMessages := []string{
		"Hello from client!",
		"Message avec emojis 🚀🔐",
		"Test caractères spéciaux: àéèüñ",
	}

	// Variables pour capturer les messages
	var serverReceivedMsgs []string
	var clientReceivedMsgs []string
	var serverMu, clientMu sync.Mutex

	// Déclarer la variable server
	var server *rocher.Server

	// Démarrer le serveur
	wg.Add(1)
	go func() {
		defer wg.Done()

		opts := rocher.DefaultClientOptions()
		opts.OnServerMessage = func(clientID, msg string) {
			serverMu.Lock()
			serverReceivedMsgs = append(serverReceivedMsgs, msg)
			serverMu.Unlock()

			fmt.Printf("🖥️  Serveur reçoit de %s: %s\n", clientID, msg)

			// Envoyer une réponse
			response := fmt.Sprintf("Echo: %s", msg)
			if err := server.SendTo(clientID, response); err != nil {
				serverErr = fmt.Errorf("réponse serveur: %v", err)
			}
		}
		opts.Debug = true

		var err error
		server, err = rocher.NewServer(serverPort, opts)
		if err != nil {
			serverErr = fmt.Errorf("création serveur: %v", err)
			return
		}
		defer server.Close()

		if err := server.Start(); err != nil {
			serverErr = fmt.Errorf("démarrage serveur: %v", err)
			return
		}

		fmt.Println("🖥️  Serveur démarré sur", serverPort)

		// Attendre un peu pour simuler un serveur qui tourne
		time.Sleep(3 * time.Second)
	}()

	// Attendre que le serveur démarre
	time.Sleep(200 * time.Millisecond)

	// Démarrer le client
	wg.Add(1)
	go func() {
		defer wg.Done()

		client, err := rocher.QuickClient("localhost"+serverPort, func(msg string) {
			clientMu.Lock()
			clientReceivedMsgs = append(clientReceivedMsgs, msg)
			clientMu.Unlock()

			fmt.Printf("💻 Client reçoit: %s\n", msg)
		})

		if err != nil {
			clientErr = fmt.Errorf("connexion client: %v", err)
			return
		}
		defer client.Close()

		fmt.Println("💻 Client connecté")

		// Envoyer les messages de test
		for i, msg := range testMessages {
			fmt.Printf("💻 Client envoie (%d): %s\n", i+1, msg)

			if err := client.Send(msg); err != nil {
				clientErr = fmt.Errorf("envoi message %d: %v", i+1, err)
				return
			}

			// Attendre un peu entre les messages
			time.Sleep(300 * time.Millisecond)
		}

		// Attendre les réponses
		timeout := time.After(2 * time.Second)
		for len(clientReceivedMsgs) < len(testMessages) {
			select {
			case <-timeout:
				clientErr = fmt.Errorf("timeout en attente des réponses")
				return
			default:
				time.Sleep(50 * time.Millisecond)
			}
		}

		fmt.Println("✅ Client terminé")
	}()

	wg.Wait()

	// Vérifications
	if serverErr != nil {
		t.Fatalf("Erreur serveur: %v", serverErr)
	}

	if clientErr != nil {
		t.Fatalf("Erreur client: %v", clientErr)
	}

	// Vérifier que tous les messages ont été reçus
	serverMu.Lock()
	clientMu.Lock()
	defer serverMu.Unlock()
	defer clientMu.Unlock()

	if len(serverReceivedMsgs) != len(testMessages) {
		t.Errorf("Serveur: messages manquants. Attendu %d, reçu %d",
			len(testMessages), len(serverReceivedMsgs))
	}

	if len(clientReceivedMsgs) != len(testMessages) {
		t.Errorf("Client: réponses manquantes. Attendu %d, reçu %d",
			len(testMessages), len(clientReceivedMsgs))
	}

	// Vérifier l'intégrité des messages
	for i, originalMsg := range testMessages {
		if i < len(serverReceivedMsgs) && serverReceivedMsgs[i] != originalMsg {
			t.Errorf("Message %d corrompu côté serveur:\nOriginal: %s\nReçu: %s",
				i+1, originalMsg, serverReceivedMsgs[i])
		}

		expectedResponse := fmt.Sprintf("Echo: %s", originalMsg)
		if i < len(clientReceivedMsgs) && clientReceivedMsgs[i] != expectedResponse {
			t.Errorf("Réponse %d incorrecte côté client:\nAttendu: %s\nReçu: %s",
				i+1, expectedResponse, clientReceivedMsgs[i])
		}
	}

	fmt.Println("✅ Test Client-Serveur basique réussi!")
}

// TestMultipleClients teste plusieurs clients simultanés
func TestMultipleClients(t *testing.T) {
	fmt.Println("=== Test: Clients multiples ===")

	serverPort := ":8902"
	clientCount := 3
	messagesPerClient := 2

	var wg sync.WaitGroup
	var serverErr error
	var clientErrors []error = make([]error, clientCount)

	// Statistiques
	var totalMessagesReceived int
	var messagesMu sync.Mutex

	// Déclarer la variable server
	var server *rocher.Server

	// Démarrer le serveur
	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		server, err = rocher.QuickServer(serverPort, func(clientID, msg string) {
			messagesMu.Lock()
			totalMessagesReceived++
			count := totalMessagesReceived
			messagesMu.Unlock()

			fmt.Printf("🖥️  [%d] Serveur reçoit de %s: %s\n", count, clientID, msg)

			// Broadcast à tous les autres clients
			response := fmt.Sprintf("[Broadcast] Client %s dit: %s", clientID, msg)
			if err := server.Send(response); err != nil {
				serverErr = fmt.Errorf("broadcast: %v", err)
			}
		})

		if err != nil {
			serverErr = fmt.Errorf("création serveur: %v", err)
			return
		}
		defer server.Close()

		if err := server.Start(); err != nil {
			serverErr = fmt.Errorf("démarrage serveur: %v", err)
			return
		}

		fmt.Printf("🖥️  Serveur multi-clients démarré sur %s\n", serverPort)

		// Serveur actif pendant le test
		time.Sleep(4 * time.Second)
	}()

	// Attendre que le serveur démarre
	time.Sleep(300 * time.Millisecond)

	// Démarrer plusieurs clients
	for clientID := 0; clientID < clientCount; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			clientName := fmt.Sprintf("Client-%d", id+1)
			var clientReceivedCount int
			var clientMu sync.Mutex

			client, err := rocher.QuickClient("localhost"+serverPort, func(msg string) {
				clientMu.Lock()
				clientReceivedCount++
				count := clientReceivedCount
				clientMu.Unlock()

				fmt.Printf("💻 %s reçoit [%d]: %s\n", clientName, count, msg)
			})

			if err != nil {
				clientErrors[id] = fmt.Errorf("%s connexion: %v", clientName, err)
				return
			}
			defer client.Close()

			fmt.Printf("💻 %s connecté\n", clientName)

			// Envoyer des messages
			for msgNum := 1; msgNum <= messagesPerClient; msgNum++ {
				message := fmt.Sprintf("Message %d de %s", msgNum, clientName)

				if err := client.Send(message); err != nil {
					clientErrors[id] = fmt.Errorf("%s envoi %d: %v", clientName, msgNum, err)
					return
				}

				time.Sleep(200 * time.Millisecond)
			}

			// Attendre un peu pour recevoir les broadcasts
			time.Sleep(1 * time.Second)

			fmt.Printf("✅ %s terminé\n", clientName)
		}(clientID)
	}

	wg.Wait()

	// Vérifications
	if serverErr != nil {
		t.Fatalf("Erreur serveur: %v", serverErr)
	}

	for i, err := range clientErrors {
		if err != nil {
			t.Errorf("Erreur client %d: %v", i+1, err)
		}
	}

	// Vérifier le nombre total de messages
	expectedTotal := clientCount * messagesPerClient
	if totalMessagesReceived != expectedTotal {
		t.Errorf("Messages reçus par le serveur: attendu %d, reçu %d",
			expectedTotal, totalMessagesReceived)
	}

	fmt.Printf("✅ Test clients multiples réussi! (%d clients, %d messages)\n",
		clientCount, totalMessagesReceived)
}

// TestClientOptions teste les différentes options
func TestClientOptions(t *testing.T) {
	fmt.Println("=== Test: Options client ===")

	// Test des options par défaut
	opts := rocher.DefaultClientOptions()

	if opts.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout par défaut incorrect: %v", opts.ConnectTimeout)
	}

	if opts.SendTimeout != 5*time.Second {
		t.Errorf("SendTimeout par défaut incorrect: %v", opts.SendTimeout)
	}

	if opts.MessageBufferSize != 100 {
		t.Errorf("MessageBufferSize par défaut incorrect: %d", opts.MessageBufferSize)
	}

	if opts.Debug != false {
		t.Errorf("Debug devrait être false par défaut")
	}

	// Test des callbacks
	messageReceived := false
	errorReceived := false

	opts.OnMessage = func(msg string) {
		messageReceived = true
	}

	opts.OnError = func(err error) {
		errorReceived = true
	}

	// Tester les callbacks
	opts.OnMessage("test")
	opts.OnError(fmt.Errorf("test error"))

	if !messageReceived {
		t.Error("Callback OnMessage non fonctionnel")
	}

	if !errorReceived {
		t.Error("Callback OnError non fonctionnel")
	}

	fmt.Println("✅ Test des options réussi!")
}

// TestConnectionErrors teste la gestion d'erreurs de connexion
func TestConnectionErrors(t *testing.T) {
	fmt.Println("=== Test: Gestion d'erreurs de connexion ===")

	// Test 1: Port inexistant
	_, err := rocher.QuickClient("localhost:99999", func(string) {})
	if err == nil {
		t.Error("Devrait échouer sur un port inexistant")
	}
	fmt.Println("✅ Détection port inexistant")

	// Test 2: Adresse invalide
	_, err = rocher.QuickClient("invalid-address", func(string) {})
	if err == nil {
		t.Error("Devrait échouer sur une adresse invalide")
	}
	fmt.Println("✅ Détection adresse invalide")

	// Test 3: Protocole non supporté
	_, err = rocher.NewClient("udp://localhost:8080", nil)
	if err == nil {
		t.Error("Devrait rejeter le protocole UDP")
	}
	fmt.Println("✅ Rejet protocole non supporté")

	fmt.Println("✅ Gestion d'erreurs de connexion correcte")
}

// TestServerBroadcast teste les fonctionnalités de broadcast du serveur
func TestServerBroadcast(t *testing.T) {
	fmt.Println("=== Test: Broadcast serveur ===")

	serverPort := ":8903"
	var wg sync.WaitGroup
	var serverErr error

	// Créer le serveur
	server, err := rocher.QuickServer(serverPort, func(clientID, msg string) {
		fmt.Printf("🖥️  Message de %s: %s\n", clientID, msg)
		// Le serveur ne fait que recevoir dans ce test
	})

	if err != nil {
		t.Fatalf("Création serveur: %v", err)
	}
	defer server.Close()

	if err := server.Start(); err != nil {
		t.Fatalf("Démarrage serveur: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Créer 2 clients
	clientCount := 2
	clients := make([]*rocher.Client, clientCount)
	receivedMessages := make([][]string, clientCount)
	receivedMutexes := make([]sync.Mutex, clientCount)

	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			client, err := rocher.QuickClient("localhost"+serverPort, func(msg string) {
				receivedMutexes[id].Lock()
				receivedMessages[id] = append(receivedMessages[id], msg)
				receivedMutexes[id].Unlock()

				fmt.Printf("💻 Client-%d reçoit: %s\n", id+1, msg)
			})

			if err != nil {
				serverErr = fmt.Errorf("client %d: %v", id+1, err)
				return
			}

			clients[id] = client
		}(i)
	}

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("Erreur clients: %v", serverErr)
	}

	// Attendre que les clients soient connectés
	time.Sleep(300 * time.Millisecond)

	// Envoyer un broadcast depuis le serveur
	broadcastMsg := "Message broadcast du serveur!"
	if err := server.Send(broadcastMsg); err != nil {
		t.Fatalf("Erreur broadcast: %v", err)
	}

	// Attendre que les messages arrivent
	time.Sleep(500 * time.Millisecond)

	// Vérifier que tous les clients ont reçu le message
	for i := 0; i < clientCount; i++ {
		receivedMutexes[i].Lock()
		msgCount := len(receivedMessages[i])
		receivedMutexes[i].Unlock()

		if msgCount != 1 {
			t.Errorf("Client %d: attendu 1 message, reçu %d", i+1, msgCount)
		} else {
			receivedMutexes[i].Lock()
			if receivedMessages[i][0] != broadcastMsg {
				t.Errorf("Client %d: message incorrect. Attendu '%s', reçu '%s'",
					i+1, broadcastMsg, receivedMessages[i][0])
			}
			receivedMutexes[i].Unlock()
		}

		clients[i].Close()
	}

	fmt.Println("✅ Test broadcast serveur réussi!")
}
func TestClientStats(t *testing.T) {
	fmt.Println("=== Test: Statistiques client ===")

	serverPort := ":8904"

	// Déclarer la variable server
	var server *rocher.Server

	// Serveur simple
	var err error
	server, err = rocher.QuickServer(serverPort, func(clientID, msg string) {
		// Echo simple
		server.SendTo(clientID, "Echo: "+msg)
	})
	if err != nil {
		t.Fatalf("Création serveur: %v", err)
	}
	defer server.Close()

	server.Start()
	time.Sleep(200 * time.Millisecond)

	// Client
	client, err := rocher.QuickClient("localhost"+serverPort, func(msg string) {
		// Recevoir l'echo
	})
	if err != nil {
		t.Fatalf("Création client: %v", err)
	}
	defer client.Close()

	// Envoyer quelques messages
	for i := 0; i < 3; i++ {
		client.Send(fmt.Sprintf("Message %d", i+1))
		time.Sleep(100 * time.Millisecond)
	}

	// Attendre les réponses
	time.Sleep(500 * time.Millisecond)

	// Vérifier les statistiques
	stats := client.GetStats()

	if !stats["connected"].(bool) {
		t.Error("Client devrait être connecté")
	}

	if messagesSent, ok := stats["messages_sent"].(uint64); ok {
		if messagesSent != 3 {
			t.Errorf("Messages envoyés: attendu 3, obtenu %d", messagesSent)
		}
	}

	fmt.Printf("📊 Statistiques client: %+v\n", stats)
	fmt.Println("✅ Test statistiques réussi!")
}

// BenchmarkAPIClientServer benchmark de l'API
func BenchmarkAPIClientServer(b *testing.B) {
	serverPort := ":8905"

	// Déclarer la variable server
	var server *rocher.Server

	// Serveur de benchmark
	var err error
	server, err = rocher.QuickServer(serverPort, func(clientID, msg string) {
		server.SendTo(clientID, "OK")
	})
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	server.Start()
	time.Sleep(100 * time.Millisecond)

	// Client de benchmark
	client, err := rocher.QuickClient("localhost"+serverPort, func(msg string) {})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	message := "Benchmark message"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.Send(message)
	}
}

// TestAPIStartup teste le démarrage de l'API (remplace TestMain)
func TestAPIStartup(t *testing.T) {
	fmt.Println("🚀 === SUITE DE TESTS API ROCHER ===")
	fmt.Println("Tests de l'API simplifiée pour développeurs")
	fmt.Println()
}

// Mock pour Server.SetOnMessage (à ajouter à api.go)
type ServerWithSetOnMessage interface {
	SetOnMessage(func(string, string))
	Start() error
	Close() error
	Send(string) error
	SendTo(string, string) error
}
