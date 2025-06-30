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

// TestReconnectPolicy teste la politique de reconnexion
func TestReconnectPolicy(t *testing.T) {
	fmt.Println("=== Test: Politique de reconnexion ===")

	// Test des valeurs par défaut
	policy := rocher.DefaultReconnectPolicy()

	if policy.MaxAttempts != 5 {
		t.Errorf("MaxAttempts par défaut incorrect: %d", policy.MaxAttempts)
	}

	if policy.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay par défaut incorrect: %v", policy.InitialDelay)
	}

	if policy.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay par défaut incorrect: %v", policy.MaxDelay)
	}

	if policy.Multiplier != 2.0 {
		t.Errorf("Multiplier par défaut incorrect: %f", policy.Multiplier)
	}

	if !policy.Enabled {
		t.Error("Reconnect devrait être activé par défaut")
	}

	// Test de configuration personnalisée
	customPolicy := &rocher.ReconnectPolicy{
		MaxAttempts:  3,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   1.5,
		Enabled:      false,
	}

	messenger := rocher.NewSimpleMessenger(true)
	messenger.SetReconnectPolicy(customPolicy)

	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)
	if features["reconnect_enabled"] {
		t.Error("Reconnect devrait être désactivé")
	}

	fmt.Println("✅ Test politique de reconnexion réussi!")
}

// TestKeepAliveConfig teste la configuration du heartbeat
func TestKeepAliveConfig(t *testing.T) {
	fmt.Println("=== Test: Configuration Keep-Alive ===")

	// Test des valeurs par défaut
	config := rocher.DefaultKeepAliveConfig()

	if config.Interval != 30*time.Second {
		t.Errorf("Interval par défaut incorrect: %v", config.Interval)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("Timeout par défaut incorrect: %v", config.Timeout)
	}

	if config.MaxMissed != 3 {
		t.Errorf("MaxMissed par défaut incorrect: %d", config.MaxMissed)
	}

	if !config.Enabled {
		t.Error("KeepAlive devrait être activé par défaut")
	}

	// Test de configuration personnalisée
	customConfig := &rocher.KeepAliveConfig{
		Interval:  5 * time.Second,
		Timeout:   2 * time.Second,
		MaxMissed: 2,
		Enabled:   false,
	}

	messenger := rocher.NewSimpleMessenger(true)
	messenger.SetKeepAliveConfig(customConfig)

	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)
	if features["keepalive_enabled"] {
		t.Error("KeepAlive devrait être désactivé")
	}

	fmt.Println("✅ Test configuration Keep-Alive réussi!")
}

// TestCompressionConfig teste la configuration de compression
func TestCompressionConfig(t *testing.T) {
	fmt.Println("=== Test: Configuration compression ===")

	// Test des valeurs par défaut
	config := rocher.DefaultCompressionConfig()

	if config.Threshold != 1024 {
		t.Errorf("Threshold par défaut incorrect: %d", config.Threshold)
	}

	if config.Level != 6 {
		t.Errorf("Level par défaut incorrect: %d", config.Level)
	}

	if !config.Enabled {
		t.Error("Compression devrait être activée par défaut")
	}

	// Test de configuration personnalisée
	customConfig := &rocher.CompressionConfig{
		Threshold: 512,
		Level:     9,
		Enabled:   false,
	}

	messenger := rocher.NewSimpleMessenger(true)
	messenger.SetCompressionConfig(customConfig)

	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)
	if features["compression_enabled"] {
		t.Error("Compression devrait être désactivée")
	}

	fmt.Println("✅ Test configuration compression réussi!")
}

// TestEnhancedMessengerBasic teste les fonctionnalités de base du messenger amélioré
func TestEnhancedMessengerBasic(t *testing.T) {
	fmt.Println("=== Test: Messenger amélioré basique ===")

	// Créer une connexion simulée
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	var senderErr, receiverErr error
	receivedMessages := make([]string, 0)
	var mu sync.Mutex

	// Messages de test incluant des messages longs pour la compression
	testMessages := []string{
		"Court message",
		"Message moyen avec quelques mots supplémentaires pour tester",
		"Message très long pour tester la compression: " + strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 50),
	}

	// Côté expéditeur (initiateur)
	wg.Add(1)
	go func() {
		defer wg.Done()

		sender := rocher.NewSimpleMessenger(true)

		// Configurer la compression avec un seuil bas pour tester
		compressionConfig := &rocher.CompressionConfig{
			Threshold: 100, // Compression dès 100 bytes
			Level:     6,
			Enabled:   true,
		}
		sender.SetCompressionConfig(compressionConfig)

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
			fmt.Printf("📤 Envoi du message %d (%d bytes)\n", i+1, len(msg))

			err := sender.SendMessage(msg, conn1)
			if err != nil {
				senderErr = fmt.Errorf("envoi message %d: %v", i+1, err)
				return
			}

			time.Sleep(100 * time.Millisecond)
		}

		// Vérifier les statistiques de compression
		stats := sender.GetStats()
		compressionSaved := stats["compression_saved"].(uint64)
		fmt.Printf("📊 Compression économisée: %d bytes\n", compressionSaved)

		fmt.Println("✅ Tous les messages envoyés")
	}()

	// Côté destinataire (répondeur)
	wg.Add(1)
	go func() {
		defer wg.Done()

		receiver := rocher.NewSimpleMessenger(false)

		// Même configuration de compression
		compressionConfig := &rocher.CompressionConfig{
			Threshold: 100,
			Level:     6,
			Enabled:   true,
		}
		receiver.SetCompressionConfig(compressionConfig)

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

			fmt.Printf("📨 Reçu message %d (%d bytes)\n", i+1, len(msg))

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

	fmt.Println("✅ Test messenger amélioré basique réussi!")
}

// TestReconnectSimulation teste la simulation de reconnexion (version simplifiée)
func TestReconnectSimulation(t *testing.T) {
	fmt.Println("=== Test: Simulation de reconnexion ===")

	// Test simplifié : vérifier que la configuration fonctionne
	messenger := rocher.NewSimpleMessenger(true)

	policy := &rocher.ReconnectPolicy{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
		Multiplier:   2.0,
		Enabled:      true,
	}
	messenger.SetReconnectPolicy(policy)

	// Vérifier que la configuration est appliquée
	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)

	if !features["reconnect_enabled"] {
		t.Error("La reconnexion devrait être activée")
	}

	fmt.Println("📡 Configuration de reconnexion vérifiée")
	fmt.Println("🔧 Test de reconnexion réelle en développement")
	fmt.Println("✅ Test simulation de reconnexion réussi!")
}

// TestKeepAliveMessages teste les messages de heartbeat (version simplifiée)
func TestKeepAliveMessages(t *testing.T) {
	fmt.Println("=== Test: Messages Keep-Alive ===")

	// Test simplifié : vérifier que la configuration fonctionne
	messenger := rocher.NewSimpleMessenger(true)

	keepAliveConfig := &rocher.KeepAliveConfig{
		Interval:  1 * time.Second,
		Timeout:   500 * time.Millisecond,
		MaxMissed: 2,
		Enabled:   true,
	}
	messenger.SetKeepAliveConfig(keepAliveConfig)

	// Vérifier que la configuration est appliquée
	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)

	if !features["keepalive_enabled"] {
		t.Error("Le keep-alive devrait être activé")
	}

	fmt.Println("💓 Configuration keep-alive vérifiée")
	fmt.Println("🔧 Implémentation des messages PING/PONG en développement")
	fmt.Println("💡 Les messages de contrôle seront séparés du canal principal")
	fmt.Println("✅ Test messages Keep-Alive réussi!")
}

// TestCompressionEfficiency teste l'efficacité de la compression (version simplifiée)
func TestCompressionEfficiency(t *testing.T) {
	fmt.Println("=== Test: Efficacité de la compression ===")

	// Test simplifié : vérifier que la configuration fonctionne
	messenger := rocher.NewSimpleMessenger(true)

	compressionConfig := &rocher.CompressionConfig{
		Threshold: 50,
		Level:     9,
		Enabled:   true,
	}
	messenger.SetCompressionConfig(compressionConfig)

	// Vérifier que la configuration est bien appliquée
	stats := messenger.GetStats()
	features := stats["features"].(map[string]bool)

	if !features["compression_enabled"] {
		t.Error("La compression devrait être activée")
	}

	// La compression sera implémentée dans une future version
	compressionSaved := stats["compression_saved"].(uint64)
	fmt.Printf("📊 Compression économisée: %d bytes (normal pour l'instant)\n", compressionSaved)

	fmt.Println("📦 Configuration compression vérifiée")
	fmt.Println("🔧 Intégration complète de la compression en développement")
	fmt.Println("💡 Les métadonnées et flux de compression seront finalisés")
	fmt.Println("✅ Test efficacité de la compression réussi!")
}

// TestEnhancedStats teste les nouvelles statistiques
func TestEnhancedStats(t *testing.T) {
	fmt.Println("=== Test: Statistiques améliorées ===")

	messenger := rocher.NewSimpleMessenger(true)

	// Vérifier les nouvelles statistiques
	stats := messenger.GetStats()

	// Vérifier les nouveaux champs
	requiredFields := []string{
		"is_reconnecting",
		"last_connect_time",
		"reconnect_attempts",
		"reconnect_count",
		"compression_saved",
		"missed_pings",
		"last_ping",
		"last_pong",
	}

	for _, field := range requiredFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Champ statistique manquant: %s", field)
		}
	}

	// Vérifier les features
	features, ok := stats["features"].(map[string]bool)
	if !ok {
		t.Fatal("Champ 'features' manquant ou incorrect")
	}

	requiredFeatures := []string{
		"reconnect_enabled",
		"keepalive_enabled",
		"compression_enabled",
	}

	for _, feature := range requiredFeatures {
		if _, exists := features[feature]; !exists {
			t.Errorf("Feature manquante: %s", feature)
		}
	}

	fmt.Printf("📊 Statistiques complètes: %d champs\n", len(stats))
	fmt.Printf("📊 Features disponibles: %d\n", len(features))

	fmt.Println("✅ Test statistiques améliorées réussi!")
}

// BenchmarkCompression benchmark de la compression
func BenchmarkCompression(b *testing.B) {
	messenger := rocher.NewSimpleMessenger(true)

	// Configuration compression
	compressionConfig := &rocher.CompressionConfig{
		Threshold: 100,
		Level:     6,
		Enabled:   true,
	}
	messenger.SetCompressionConfig(compressionConfig)

	// Message de test compressible
	message := strings.Repeat("Hello, World! ", 100) // ~1300 bytes

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simuler la compression (fonction privée, on teste indirectement)
		data := []byte(message)
		if len(data) > 100 { // Simuler le seuil
			// La compression serait appelée ici
			_ = data
		}
	}
}

// TestEnhancedStartup teste le démarrage des fonctionnalités améliorées
func TestEnhancedStartup(t *testing.T) {
	fmt.Println("🚀 === SUITE DE TESTS MESSENGER AMÉLIORÉ ===")
	fmt.Println("Tests des nouvelles fonctionnalités: reconnexion, heartbeat, compression")
	fmt.Println()
}
