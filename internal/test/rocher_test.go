package test

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/rocher"
)

// TestBasicKeyExchange teste l'échange de clés Kyber768 de base
func TestBasicKeyExchange(t *testing.T) {
	fmt.Println("=== Test: Échange de clés Kyber768 ===")

	// Créer une connexion simulée
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	var initiatorSecret, responderSecret []byte
	var initiatorErr, responderErr error

	// Test côté initiateur
	wg.Add(1)
	go func() {
		defer wg.Done()
		kex := rocher.NewKyberKeyExchange()
		initiatorSecret, initiatorErr = kex.PerformKeyExchange(conn1, true)
	}()

	// Test côté destinataire
	wg.Add(1)
	go func() {
		defer wg.Done()
		kex := rocher.NewKyberKeyExchange()
		responderSecret, responderErr = kex.PerformKeyExchange(conn2, false)
	}()

	wg.Wait()

	// Vérifications
	if initiatorErr != nil {
		t.Fatalf("Échec de l'échange côté initiateur: %v", initiatorErr)
	}

	if responderErr != nil {
		t.Fatalf("Échec de l'échange côté destinataire: %v", responderErr)
	}

	if len(initiatorSecret) == 0 || len(responderSecret) == 0 {
		t.Fatal("Secrets partagés vides")
	}

	if !rocher.ConstantTimeCompare(initiatorSecret, responderSecret) {
		t.Fatal("Les secrets partagés ne correspondent pas")
	}

	fmt.Printf("✅ Échange de clés réussi! Secret de %d bytes\n", len(initiatorSecret))
}

// TestSecureChannelEncryption teste le chiffrement/déchiffrement
func TestSecureChannelEncryption(t *testing.T) {
	fmt.Println("=== Test: Chiffrement SecureChannel ===")

	// Créer un secret partagé factice
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	// Créer le canal sécurisé
	channel, err := rocher.NewSecureChannel(sharedSecret)
	if err != nil {
		t.Fatalf("Échec création canal sécurisé: %v", err)
	}
	defer channel.Close()

	// Messages de test
	testMessages := []string{
		"Hello, World!",
		"Message avec accents: café, naïve, résumé 🚀",
		"Message long: " + strings.Repeat("A", 1000),
		"Message vide peut poser problème",
		"Caractères spéciaux: !@#$%^&*()_+-=[]{}|;':\",./<>?",
	}

	for i, originalMsg := range testMessages {
		// Tronquer le message pour l'affichage
		displayMsg := originalMsg
		if len(displayMsg) > 50 {
			displayMsg = displayMsg[:47] + "..."
		}
		fmt.Printf("Test message %d: '%s'\n", i+1, displayMsg)

		// Chiffrer
		encryptedMsg, err := channel.EncryptMessage([]byte(originalMsg))
		if err != nil {
			t.Fatalf("Échec chiffrement message %d: %v", i+1, err)
		}

		// Vérifier la structure du message chiffré
		if encryptedMsg.ID == "" {
			t.Errorf("Message %d: ID manquant", i+1)
		}

		if encryptedMsg.Timestamp == 0 {
			t.Errorf("Message %d: Timestamp manquant", i+1)
		}

		if len(encryptedMsg.Nonce) != 24 {
			t.Errorf("Message %d: Nonce invalide (taille: %d)", i+1, len(encryptedMsg.Nonce))
		}

		// Déchiffrer
		decryptedBytes, err := channel.DecryptMessage(encryptedMsg)
		if err != nil {
			t.Fatalf("Échec déchiffrement message %d: %v", i+1, err)
		}

		decryptedMsg := string(decryptedBytes)

		// Vérifier l'intégrité
		if originalMsg != decryptedMsg {
			t.Errorf("Message %d: Intégrité compromise\nOriginal: %s\nDéchiffré: %s",
				i+1, originalMsg, decryptedMsg)
		}
	}

	fmt.Println("✅ Tous les tests de chiffrement ont réussi!")
}

// TestSimpleMessenger teste le messenger complet
func TestSimpleMessenger(t *testing.T) {
	fmt.Println("=== Test: SimpleMessenger complet ===")

	// Créer une connexion simulée
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	var senderErr, receiverErr error
	receivedMessages := make([]string, 0)

	// Messages de test
	testMessages := []string{
		"Premier message sécurisé",
		"Message avec emojis 🔐🚀💻",
		"Test de performance: " + strings.Repeat("X", 500),
	}

	// Côté expéditeur
	wg.Add(1)
	go func() {
		defer wg.Done()

		sender := rocher.NewSimpleMessenger(true)

		// Établir la connexion
		err := sender.Connect(conn1)
		if err != nil {
			senderErr = fmt.Errorf("connexion expéditeur: %v", err)
			return
		}
		defer sender.Close()

		// Envoyer les messages
		for i, msg := range testMessages {
			// Tronquer pour l'affichage
			displayMsg := msg
			if len(displayMsg) > 40 {
				displayMsg = displayMsg[:37] + "..."
			}
			fmt.Printf("📤 Envoi du message %d: '%s'\n", i+1, displayMsg)

			err := sender.SendMessage(msg, conn1)
			if err != nil {
				senderErr = fmt.Errorf("envoi message %d: %v", i+1, err)
				return
			}

			// Petit délai entre les messages
			time.Sleep(50 * time.Millisecond)
		}

		fmt.Println("✅ Tous les messages envoyés")
	}()

	// Côté destinataire
	wg.Add(1)
	go func() {
		defer wg.Done()

		receiver := rocher.NewSimpleMessenger(false)

		// Établir la connexion
		err := receiver.Connect(conn2)
		if err != nil {
			receiverErr = fmt.Errorf("connexion destinataire: %v", err)
			return
		}
		defer receiver.Close()

		// Recevoir les messages
		for i := 0; i < len(testMessages); i++ {
			msg, err := receiver.ReceiveMessage(conn2)
			if err != nil {
				receiverErr = fmt.Errorf("réception message %d: %v", i+1, err)
				return
			}

			// Tronquer pour l'affichage
			displayMsg := msg
			if len(displayMsg) > 40 {
				displayMsg = displayMsg[:37] + "..."
			}
			fmt.Printf("📨 Reçu message %d: '%s'\n", i+1, displayMsg)

			receivedMessages = append(receivedMessages, msg)
		}

		fmt.Println("✅ Tous les messages reçus")
	}()

	wg.Wait()

	// Vérifications
	if senderErr != nil {
		t.Fatalf("Erreur expéditeur: %v", senderErr)
	}

	if receiverErr != nil {
		t.Fatalf("Erreur destinataire: %v", receiverErr)
	}

	if len(receivedMessages) != len(testMessages) {
		t.Fatalf("Nombre de messages incorrect: attendu %d, reçu %d",
			len(testMessages), len(receivedMessages))
	}

	// Vérifier l'intégrité de chaque message
	for i, originalMsg := range testMessages {
		if i < len(receivedMessages) && receivedMessages[i] != originalMsg {
			t.Errorf("Message %d corrompu:\nOriginal: %s\nReçu: %s",
				i+1, originalMsg, receivedMessages[i])
		}
	}

	fmt.Println("✅ Test SimpleMessenger réussi!")
}

// TestSecureChat teste le chat sécurisé asynchrone
func TestSecureChat(t *testing.T) {
	fmt.Println("=== Test: SecureChat asynchrone ===")

	// Créer une connexion simulée
	aliceConn, bobConn := net.Pipe()
	defer aliceConn.Close()
	defer bobConn.Close()

	var wg sync.WaitGroup
	var aliceErr, bobErr error

	// Alice (initiatrice)
	wg.Add(1)
	go func() {
		defer wg.Done()

		alice, err := rocher.NewSecureChat(aliceConn, true, "Alice")
		if err != nil {
			aliceErr = fmt.Errorf("création chat Alice: %v", err)
			return
		}
		defer alice.Close()

		fmt.Println("👩 Alice: Chat établi")

		// Envoyer des messages
		messages := []string{
			"Salut Bob! 👋",
			"Comment ça va?",
			"Le chiffrement Kyber fonctionne! 🔐",
		}

		for i, msg := range messages {
			alice.SendMessage(msg)
			fmt.Printf("👩 Alice envoie (%d): %s\n", i+1, msg)
			time.Sleep(200 * time.Millisecond)
		}

		// Recevoir les réponses
		responsesReceived := 0
		timeout := time.After(5 * time.Second)

		for responsesReceived < len(messages) {
			select {
			case <-timeout:
				aliceErr = fmt.Errorf("timeout en attente des réponses de Bob")
				return
			default:
				if msg, ok := alice.ReceiveMessage(); ok {
					fmt.Printf("👩 Alice reçoit: %s\n", msg)
					responsesReceived++
				}

				if err, ok := alice.GetError(); ok {
					aliceErr = fmt.Errorf("erreur Alice: %v", err)
					return
				}

				time.Sleep(50 * time.Millisecond)
			}
		}

		fmt.Println("✅ Alice a terminé")
	}()

	// Bob (destinataire)
	wg.Add(1)
	go func() {
		defer wg.Done()

		time.Sleep(100 * time.Millisecond) // Laisser Alice démarrer

		bob, err := rocher.NewSecureChat(bobConn, false, "Bob")
		if err != nil {
			bobErr = fmt.Errorf("création chat Bob: %v", err)
			return
		}
		defer bob.Close()

		fmt.Println("👨 Bob: Chat établi")

		// Réponses prédéfinies
		responses := []string{
			"Salut Alice! 😊",
			"Ça va super bien, merci!",
			"Oui, c'est impressionnant! 🚀",
		}

		messagesReceived := 0
		timeout := time.After(5 * time.Second)

		for messagesReceived < len(responses) {
			select {
			case <-timeout:
				bobErr = fmt.Errorf("timeout en attente des messages d'Alice")
				return
			default:
				if msg, ok := bob.ReceiveMessage(); ok {
					fmt.Printf("👨 Bob reçoit: %s\n", msg)

					// Envoyer une réponse
					if messagesReceived < len(responses) {
						response := responses[messagesReceived]
						bob.SendMessage(response)
						fmt.Printf("👨 Bob répond: %s\n", response)
						messagesReceived++
					}
				}

				if err, ok := bob.GetError(); ok {
					bobErr = fmt.Errorf("erreur Bob: %v", err)
					return
				}

				time.Sleep(50 * time.Millisecond)
			}
		}

		fmt.Println("✅ Bob a terminé")
	}()

	wg.Wait()

	// Vérifications
	if aliceErr != nil {
		t.Fatalf("Erreur Alice: %v", aliceErr)
	}

	if bobErr != nil {
		t.Fatalf("Erreur Bob: %v", bobErr)
	}

	fmt.Println("✅ Test SecureChat réussi!")
}

// TestPerformance teste les performances du système
func TestPerformance(t *testing.T) {
	fmt.Println("=== Test: Performance ===")

	// Test avec différentes tailles de messages
	messageSizes := []int{100, 1000, 10000}
	messageCount := 50

	for _, size := range messageSizes {
		fmt.Printf("Test performance: %d messages de %d bytes\n", messageCount, size)

		// Créer une connexion
		conn1, conn2 := net.Pipe()

		// Créer le message de test
		testMessage := strings.Repeat("A", size)

		var wg sync.WaitGroup
		var duration time.Duration
		var err error

		// Mesurer le temps d'envoi/réception
		start := time.Now()

		// Expéditeur
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn1.Close()

			sender := rocher.NewSimpleMessenger(true)
			if err = sender.Connect(conn1); err != nil {
				return
			}
			defer sender.Close()

			for i := 0; i < messageCount; i++ {
				if err = sender.SendMessage(testMessage, conn1); err != nil {
					return
				}
			}
		}()

		// Destinataire
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn2.Close()

			receiver := rocher.NewSimpleMessenger(false)
			if err = receiver.Connect(conn2); err != nil {
				return
			}
			defer receiver.Close()

			for i := 0; i < messageCount; i++ {
				if _, err = receiver.ReceiveMessage(conn2); err != nil {
					return
				}
			}
		}()

		wg.Wait()
		duration = time.Since(start)

		if err != nil {
			t.Errorf("Erreur performance (taille %d): %v", size, err)
			continue
		}

		totalBytes := int64(messageCount * size)
		throughput := float64(totalBytes) / duration.Seconds() / 1024 / 1024 // MB/s
		messagesPerSecond := float64(messageCount) / duration.Seconds()

		fmt.Printf("  Durée: %v\n", duration)
		fmt.Printf("  Débit: %.2f MB/s\n", throughput)
		fmt.Printf("  Messages/seconde: %.2f\n", messagesPerSecond)
	}

	fmt.Println("✅ Tests de performance terminés")
}

// TestErrorHandling teste la gestion d'erreurs
func TestErrorHandling(t *testing.T) {
	fmt.Println("=== Test: Gestion d'erreurs ===")

	// Test 1: Message trop grand
	channel, err := rocher.NewSecureChannel(make([]byte, 32))
	if err != nil {
		t.Fatalf("Erreur création canal: %v", err)
	}
	defer channel.Close()

	largeMessage := make([]byte, 2*1024*1024) // 2MB
	_, err = channel.EncryptMessage(largeMessage)
	if err == nil {
		t.Error("Devrait rejeter les messages trop grands")
	}
	fmt.Println("✅ Rejet des messages trop grands")

	// Test 2: Secret partagé trop court
	_, err = rocher.NewSecureChannel(make([]byte, 16)) // Trop court
	if err == nil {
		t.Error("Devrait rejeter les secrets partagés trop courts")
	}
	fmt.Println("✅ Rejet des secrets trop courts")

	// Test 3: Message vide
	_, err = channel.EncryptMessage([]byte{})
	if err == nil {
		t.Error("Devrait rejeter les messages vides")
	}
	fmt.Println("✅ Rejet des messages vides")

	fmt.Println("✅ Gestion d'erreurs correcte")
}

// BenchmarkKeyExchange benchmark l'échange de clés
func BenchmarkKeyExchange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		conn1, conn2 := net.Pipe()

		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			defer conn1.Close()
			kex := rocher.NewKyberKeyExchange()
			kex.PerformKeyExchange(conn1, true)
		}()

		go func() {
			defer wg.Done()
			defer conn2.Close()
			kex := rocher.NewKyberKeyExchange()
			kex.PerformKeyExchange(conn2, false)
		}()

		wg.Wait()
	}
}

// BenchmarkEncryption benchmark le chiffrement
func BenchmarkEncryption(b *testing.B) {
	channel, _ := rocher.NewSecureChannel(make([]byte, 32))
	defer channel.Close()

	message := []byte("Message de test pour benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := channel.EncryptMessage(message)
		channel.DecryptMessage(encrypted)
	}
}

// TestMain point d'entrée principal des tests
func TestMain(m *testing.M) {
	fmt.Println("🚀 === SUITE DE TESTS ROCHER ===")
	fmt.Println("Système de chiffrement post-quantique avec Kyber768")
	fmt.Println()

	// Exécuter tous les tests
	m.Run()

	fmt.Println()
	fmt.Println("🎉 === TESTS TERMINÉS ===")
}

// Fonction utilitaire pour les tests
func TestUtilities(t *testing.T) {
	fmt.Println("=== Test: Fonctions utilitaires ===")

	// Test de troncature locale
	longString := "Ceci est une très longue chaîne de caractères pour tester la troncature"
	maxLen := 20
	truncated := longString
	if len(longString) > maxLen {
		truncated = longString[:maxLen-3] + "..."
	}

	if len(truncated) > maxLen {
		t.Errorf("Troncature incorrecte: %d caractères", len(truncated))
	}

	// Test de génération d'ID simple
	testID := fmt.Sprintf("test_%d", time.Now().UnixNano())
	if len(testID) == 0 {
		t.Error("ID vide")
	}

	fmt.Printf("✅ ID généré: %s\n", testID)
	fmt.Println("✅ Fonctions utilitaires OK")
}
