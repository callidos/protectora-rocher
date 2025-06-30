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

// TestSecureChannelEncryption teste le chiffrement/déchiffrement inter-rôles
func TestSecureChannelEncryption(t *testing.T) {
	fmt.Println("=== Test: Chiffrement SecureChannel ===")

	// Créer un secret partagé factice
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1) // Éviter les zéros
	}

	// Créer les canaux pour les deux rôles
	initiatorChannel, err := rocher.NewSecureChannel(sharedSecret, true)
	if err != nil {
		t.Fatalf("Échec création canal initiateur: %v", err)
	}
	defer initiatorChannel.Close()

	responderChannel, err := rocher.NewSecureChannel(sharedSecret, false)
	if err != nil {
		t.Fatalf("Échec création canal répondeur: %v", err)
	}
	defer responderChannel.Close()

	// Messages de test
	testMessages := []string{
		"Hello, World!",
		"Message avec accents: café, naïve, résumé 🚀",
		"Message long: " + strings.Repeat("A", 1000),
		"Caractères spéciaux: !@#$%^&*()_+-=[]{}|;':\",./<>?",
	}

	// Test dans les deux directions
	directions := []struct {
		name      string
		sender    *rocher.SecureChannel
		receiver  *rocher.SecureChannel
		direction string
	}{
		{"Initiateur -> Répondeur", initiatorChannel, responderChannel, "🔄"},
		{"Répondeur -> Initiateur", responderChannel, initiatorChannel, "🔃"},
	}

	for _, dir := range directions {
		fmt.Printf("Test direction: %s %s\n", dir.direction, dir.name)

		for i, originalMsg := range testMessages {
			// Tronquer le message pour l'affichage
			displayMsg := originalMsg
			if len(displayMsg) > 50 {
				displayMsg = displayMsg[:47] + "..."
			}
			fmt.Printf("  Test message %d: '%s'\n", i+1, displayMsg)

			// Chiffrer avec l'expéditeur
			encryptedMsg, err := dir.sender.EncryptMessage([]byte(originalMsg))
			if err != nil {
				t.Fatalf("Échec chiffrement message %d (%s): %v", i+1, dir.name, err)
			}

			// Vérifier la structure du message chiffré
			if err := rocher.ValidateMessage(encryptedMsg); err != nil {
				t.Errorf("Message %d (%s) invalide: %v", i+1, dir.name, err)
			}

			// Déchiffrer avec le destinataire
			decryptedBytes, err := dir.receiver.DecryptMessage(encryptedMsg)
			if err != nil {
				t.Fatalf("Échec déchiffrement message %d (%s): %v", i+1, dir.name, err)
			}

			decryptedMsg := string(decryptedBytes)

			// Vérifier l'intégrité
			if originalMsg != decryptedMsg {
				t.Errorf("Message %d (%s): Intégrité compromise\nOriginal: %s\nDéchiffré: %s",
					i+1, dir.name, originalMsg, decryptedMsg)
			}
		}
	}

	fmt.Println("✅ Tous les tests de chiffrement ont réussi!")
}

// TestCrossRoleEncryption teste le chiffrement entre rôles différents
func TestCrossRoleEncryption(t *testing.T) {
	fmt.Println("=== Test: Chiffrement inter-rôles ===")

	// Créer un secret partagé
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1) // Éviter les zéros
	}

	// Créer les canaux pour initiateur et répondeur
	initiatorChannel, err := rocher.NewSecureChannel(sharedSecret, true)
	if err != nil {
		t.Fatalf("Échec création canal initiateur: %v", err)
	}
	defer initiatorChannel.Close()

	responderChannel, err := rocher.NewSecureChannel(sharedSecret, false)
	if err != nil {
		t.Fatalf("Échec création canal répondeur: %v", err)
	}
	defer responderChannel.Close()

	// Test: Initiateur chiffre -> Répondeur déchiffre
	message1 := "Message de l'initiateur vers le répondeur"
	encrypted1, err := initiatorChannel.EncryptMessage([]byte(message1))
	if err != nil {
		t.Fatalf("Échec chiffrement initiateur: %v", err)
	}

	decrypted1, err := responderChannel.DecryptMessage(encrypted1)
	if err != nil {
		t.Fatalf("Échec déchiffrement par répondeur: %v", err)
	}

	if string(decrypted1) != message1 {
		t.Errorf("Message 1 corrompu: '%s' != '%s'", string(decrypted1), message1)
	}

	// Test: Répondeur chiffre -> Initiateur déchiffre
	message2 := "Message du répondeur vers l'initiateur"
	encrypted2, err := responderChannel.EncryptMessage([]byte(message2))
	if err != nil {
		t.Fatalf("Échec chiffrement répondeur: %v", err)
	}

	decrypted2, err := initiatorChannel.DecryptMessage(encrypted2)
	if err != nil {
		t.Fatalf("Échec déchiffrement par initiateur: %v", err)
	}

	if string(decrypted2) != message2 {
		t.Errorf("Message 2 corrompu: '%s' != '%s'", string(decrypted2), message2)
	}

	fmt.Println("✅ Chiffrement inter-rôles réussi!")
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
	var mu sync.Mutex

	// Messages de test
	testMessages := []string{
		"Premier message sécurisé",
		"Message avec emojis 🔐🚀💻",
		"Test de performance: " + strings.Repeat("X", 500),
	}

	// Côté expéditeur (initiateur)
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

		// Attendre un peu pour s'assurer que le récepteur est prêt
		time.Sleep(100 * time.Millisecond)

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
			time.Sleep(100 * time.Millisecond)
		}

		fmt.Println("✅ Tous les messages envoyés")
	}()

	// Côté destinataire (répondeur)
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

			mu.Lock()
			receivedMessages = append(receivedMessages, msg)
			mu.Unlock()
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

	mu.Lock()
	defer mu.Unlock()

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
			time.Sleep(300 * time.Millisecond)
		}

		// Recevoir les réponses
		responsesReceived := 0
		timeout := time.After(10 * time.Second) // Timeout plus long

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

				time.Sleep(100 * time.Millisecond)
			}
		}

		fmt.Println("✅ Alice a terminé")
	}()

	// Bob (destinataire)
	wg.Add(1)
	go func() {
		defer wg.Done()

		time.Sleep(200 * time.Millisecond) // Laisser Alice démarrer

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
		timeout := time.After(10 * time.Second) // Timeout plus long

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

				time.Sleep(100 * time.Millisecond)
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
	messageCount := 20 // Réduit pour accélérer les tests

	for _, size := range messageSizes {
		fmt.Printf("Test performance: %d messages de %d bytes\n", messageCount, size)

		// Créer une connexion
		conn1, conn2 := net.Pipe()

		// Créer le message de test
		testMessage := strings.Repeat("A", size)

		var wg sync.WaitGroup
		var duration time.Duration
		var perfErr error

		// Mesurer le temps d'envoi/réception
		start := time.Now()

		// Expéditeur
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn1.Close()

			sender := rocher.NewSimpleMessenger(true)
			if perfErr = sender.Connect(conn1); perfErr != nil {
				return
			}
			defer sender.Close()

			for i := 0; i < messageCount; i++ {
				if perfErr = sender.SendMessage(testMessage, conn1); perfErr != nil {
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
			if perfErr = receiver.Connect(conn2); perfErr != nil {
				return
			}
			defer receiver.Close()

			for i := 0; i < messageCount; i++ {
				if _, perfErr = receiver.ReceiveMessage(conn2); perfErr != nil {
					return
				}
			}
		}()

		wg.Wait()
		duration = time.Since(start)

		if perfErr != nil {
			t.Errorf("Erreur performance (taille %d): %v", size, perfErr)
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
	channel, err := rocher.NewSecureChannel(make([]byte, 32), true)
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
	_, err = rocher.NewSecureChannel(make([]byte, 16), true) // Trop court
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

	// Test 4: Tentative de déchiffrement avec mauvais rôle
	channel2, err := rocher.NewSecureChannel(make([]byte, 32), false)
	if err != nil {
		t.Fatalf("Erreur création canal 2: %v", err)
	}
	defer channel2.Close()

	// Chiffrer avec un canal et essayer de déchiffrer avec l'autre (même rôle)
	msg, err := channel.EncryptMessage([]byte("test"))
	if err != nil {
		t.Fatalf("Erreur chiffrement: %v", err)
	}

	_, err = channel.DecryptMessage(msg) // Même rôle, devrait échouer
	if err == nil {
		t.Error("Devrait échouer lors du déchiffrement avec le même rôle")
	}
	fmt.Println("✅ Échec attendu avec même rôle")

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
	channel, _ := rocher.NewSecureChannel(make([]byte, 32), true)
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
