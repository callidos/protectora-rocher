// api.go
package rocher

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Client représente un client sécurisé simplifié
type Client struct {
	messenger *SimpleMessenger
	conn      net.Conn
	isServer  bool
	userID    string // CHAMP POUR IDENTIFIER L'UTILISATEUR

	// Callback pour les messages reçus
	onMessage func(message, recipient, sessionToken string) // SIGNATURE MODIFIÉE
	onError   func(error)

	// Contrôle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// État
	connected bool
	mu        sync.RWMutex
}

// ClientOptions configure le comportement du client
type ClientOptions struct {
	// Timeout pour la connexion
	ConnectTimeout time.Duration

	// Timeout pour l'envoi de messages
	SendTimeout time.Duration

	// Buffer size pour les messages entrants
	MessageBufferSize int

	// ID utilisateur pour ce client
	UserID string

	// Configuration Forward Secrecy
	KeyRotation *KeyRotationConfig

	// Callback pour les messages reçus (client simple) - SIGNATURE MODIFIÉE
	OnMessage func(message, recipient, sessionToken string)

	// Callback pour les messages reçus (serveur avec ID client) - SIGNATURE MODIFIÉE
	OnServerMessage func(clientID, message, recipient, sessionToken string)

	// Callback pour les erreurs
	OnError func(error)

	// Logs de debug
	Debug bool
}

// DefaultClientOptions retourne des options par défaut
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		ConnectTimeout:    10 * time.Second,
		SendTimeout:       5 * time.Second,
		MessageBufferSize: 100,
		UserID:            "anonymous",
		KeyRotation:       DefaultKeyRotationConfig(),              // NOUVEAU
		OnMessage:         func(string, string, string) {},         // SIGNATURE MODIFIÉE
		OnServerMessage:   func(string, string, string, string) {}, // SIGNATURE MODIFIÉE
		OnError:           func(error) {},
		Debug:             false,
	}
}

// NewClient crée un nouveau client et se connecte à l'adresse donnée
func NewClient(address string, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = DefaultClientOptions()
	}

	if opts.Debug {
		fmt.Printf("[DEBUG] Connexion à %s\n", address)
	}

	// Parser l'adresse
	network, addr, err := parseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("adresse invalide: %w", err)
	}

	// Se connecter
	conn, err := net.DialTimeout(network, addr, opts.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connexion échouée: %w", err)
	}

	// Créer le client
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		messenger: NewSimpleMessenger(true), // Client = initiateur
		conn:      conn,
		isServer:  false,
		userID:    opts.UserID, // NOUVEAU CHAMP INITIALISÉ
		onMessage: opts.OnMessage,
		onError:   opts.OnError,
		ctx:       ctx,
		cancel:    cancel,
	}

	// NOUVEAU: Configurer Forward Secrecy avant la connexion
	if opts.KeyRotation != nil {
		client.messenger.SetKeyRotationConfig(opts.KeyRotation)
	}

	// Établir la connexion sécurisée
	if err := client.messenger.Connect(conn); err != nil {
		conn.Close()
		cancel()
		return nil, fmt.Errorf("échange de clés échoué: %w", err)
	}

	client.connected = true

	// Démarrer la boucle de réception
	client.wg.Add(1)
	go client.receiveLoop(opts)

	if opts.Debug {
		fmt.Printf("[DEBUG] Client connecté avec succès\n")
	}

	return client, nil
}

// NewServer crée un serveur qui écoute sur l'adresse donnée
func NewServer(address string, opts *ClientOptions) (*Server, error) {
	if opts == nil {
		opts = DefaultClientOptions()
	}

	// Parser l'adresse
	network, addr, err := parseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("adresse invalide: %w", err)
	}

	// Créer le listener
	listener, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("écoute échouée: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		listener:          listener,
		clients:           make(map[string]*Client),
		onMessage:         opts.OnServerMessage,
		onError:           opts.OnError,
		ctx:               ctx,
		cancel:            cancel,
		debug:             opts.Debug,
		keyRotationConfig: opts.KeyRotation, // NOUVEAU
	}

	if opts.Debug {
		fmt.Printf("[DEBUG] Serveur en écoute sur %s\n", address)
	}

	return server, nil
}

// Server représente un serveur sécurisé
type Server struct {
	listener net.Listener
	clients  map[string]*Client
	mu       sync.RWMutex

	onMessage func(clientID, message, recipient, sessionToken string) // SIGNATURE MODIFIÉE
	onError   func(error)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	debug             bool
	keyRotationConfig *KeyRotationConfig // NOUVEAU
}

// SetOnMessage change le callback des messages (utile pour les tests) - SIGNATURE MODIFIÉE
func (s *Server) SetOnMessage(fn func(string, string, string, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onMessage = fn
}

// Start démarre le serveur
func (s *Server) Start() error {
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// acceptLoop accepte les connexions entrantes
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					return // Serveur fermé
				}
				s.onError(fmt.Errorf("accept error: %w", err))
				continue
			}

			// Traiter la connexion dans une goroutine
			go s.handleConnection(conn)
		}
	}
}

// handleConnection traite une nouvelle connexion client
func (s *Server) handleConnection(conn net.Conn) {
	clientID := conn.RemoteAddr().String()

	if s.debug {
		fmt.Printf("[DEBUG] Nouvelle connexion: %s\n", clientID)
	}

	// Créer le client (serveur = répondeur)
	ctx, cancel := context.WithCancel(s.ctx)

	client := &Client{
		messenger: NewSimpleMessenger(false), // Serveur = répondeur
		conn:      conn,
		isServer:  true,
		userID:    clientID, // UTILISER L'ID DE CONNEXION COMME USERID
		onMessage: func(msg, recipient, sessionToken string) { // SIGNATURE MODIFIÉE
			s.onMessage(clientID, msg, recipient, sessionToken)
		},
		onError: s.onError,
		ctx:     ctx,
		cancel:  cancel,
	}

	// NOUVEAU: Configurer Forward Secrecy pour le client serveur
	if s.keyRotationConfig != nil {
		client.messenger.SetKeyRotationConfig(s.keyRotationConfig)
	}

	// Établir la connexion sécurisée
	if err := client.messenger.Connect(conn); err != nil {
		s.onError(fmt.Errorf("client %s: échange de clés échoué: %w", clientID, err))
		conn.Close()
		cancel()
		return
	}

	client.connected = true

	// Ajouter aux clients connectés
	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	// Démarrer la boucle de réception
	client.wg.Add(1)
	go client.receiveLoop(DefaultClientOptions())

	// Attendre la déconnexion
	client.wg.Wait()

	// Nettoyer
	s.mu.Lock()
	delete(s.clients, clientID)
	s.mu.Unlock()

	if s.debug {
		fmt.Printf("[DEBUG] Client déconnecté: %s\n", clientID)
	}
}

// Send envoie un message à tous les clients connectés - SIGNATURE MODIFIÉE
func (s *Server) Send(message, recipient, sessionToken string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var errors []string
	for clientID, client := range s.clients {
		if err := client.Send(message, recipient, sessionToken); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", clientID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("erreurs d'envoi: %s", strings.Join(errors, ", "))
	}

	return nil
}

// SendTo envoie un message à un client spécifique - SIGNATURE MODIFIÉE
func (s *Server) SendTo(clientID, message, recipient, sessionToken string) error {
	s.mu.RLock()
	client, exists := s.clients[clientID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("client %s non trouvé", clientID)
	}

	return client.Send(message, recipient, sessionToken)
}

// GetClients retourne la liste des clients connectés
func (s *Server) GetClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]string, 0, len(s.clients))
	for clientID := range s.clients {
		clients = append(clients, clientID)
	}

	return clients
}

// Close ferme le serveur
func (s *Server) Close() error {
	s.cancel()

	// Fermer tous les clients
	s.mu.Lock()
	for _, client := range s.clients {
		client.Close()
	}
	s.mu.Unlock()

	// Fermer le listener
	err := s.listener.Close()

	// Attendre que toutes les goroutines se terminent
	s.wg.Wait()

	return err
}

// Send envoie un message de manière synchrone - SIGNATURE MODIFIÉE
func (c *Client) Send(message, recipient, sessionToken string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return fmt.Errorf("client non connecté")
	}

	return c.messenger.SendWithTimeout(message, recipient, sessionToken, c.conn, 5*time.Second)
}

// IsConnected retourne l'état de la connexion
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetUserID retourne l'ID utilisateur du client
func (c *Client) GetUserID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userID
}

// GetKeyRotationStats retourne les statistiques de rotation des clés - NOUVEAU
func (c *Client) GetKeyRotationStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.messenger == nil {
		return map[string]interface{}{
			"forward_secrecy_enabled": false,
			"error":                   "messenger not initialized",
		}
	}

	return c.messenger.GetKeyRotationStats()
}

// ForceKeyRotation force une rotation des clés immédiate - NOUVEAU
func (c *Client) ForceKeyRotation() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.messenger == nil {
		return fmt.Errorf("messenger not initialized")
	}

	return c.messenger.ForceKeyRotation()
}

// SetMaxOldKeys configure le nombre maximum d'anciennes clés à conserver - NOUVEAU
func (c *Client) SetMaxOldKeys(max int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.messenger != nil {
		c.messenger.SetMaxOldKeys(max)
	}
}

// SetKeyRotationConfig configure la rotation des clés - NOUVEAU
func (c *Client) SetKeyRotationConfig(config *KeyRotationConfig) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.messenger != nil {
		c.messenger.SetKeyRotationConfig(config)
	}
}

// receiveLoop boucle de réception des messages - LOGIQUE MODIFIÉE
func (c *Client) receiveLoop(opts *ClientOptions) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			message, recipient, sessionToken, err := c.messenger.ReceiveWithTimeout(c.conn, 10*time.Second) // SIGNATURE MODIFIÉE
			if err != nil {
				if c.ctx.Err() != nil {
					return // Fermeture normale
				}

				// Gestion des timeouts
				if strings.Contains(err.Error(), "timeout") {
					continue // Retry
				}

				c.onError(fmt.Errorf("receive error: %w", err))
				return
			}

			// Appeler le callback avec le destinataire et session token
			c.onMessage(message, recipient, sessionToken) // SIGNATURE MODIFIÉE
		}
	}
}

// Close ferme la connexion client
func (c *Client) Close() error {
	c.cancel()

	c.mu.Lock()
	if c.connected {
		c.connected = false
		if c.messenger != nil {
			c.messenger.Close()
		}
		if c.conn != nil {
			c.conn.Close()
		}
	}
	c.mu.Unlock()

	c.wg.Wait()
	return nil
}

// GetStats retourne les statistiques de la connexion
func (c *Client) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.messenger == nil {
		return map[string]interface{}{
			"connected": false,
			"user_id":   c.userID,
		}
	}

	stats := c.messenger.GetStats()
	stats["connected"] = c.connected
	stats["is_server"] = c.isServer
	stats["user_id"] = c.userID

	return stats
}

// parseAddress parse une adresse au format "protocol://host:port"
func parseAddress(address string) (network, addr string, err error) {
	// Format supportés:
	// tcp://localhost:8080
	// tcp://127.0.0.1:8080
	// localhost:8080 (défaut TCP)

	if strings.Contains(address, "://") {
		parts := strings.SplitN(address, "://", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("format d'adresse invalide")
		}

		network = parts[0]
		addr = parts[1]

		// Valider le protocole
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return "", "", fmt.Errorf("protocole non supporté: %s", network)
		}
	} else {
		// Défaut TCP
		network = "tcp"
		addr = address
	}

	// Valider que l'adresse contient un port
	if !strings.Contains(addr, ":") {
		return "", "", fmt.Errorf("port manquant dans l'adresse")
	}

	return network, addr, nil
}

// Fonctions utilitaires pour une utilisation encore plus simple - SIGNATURES MODIFIÉES

// QuickClient crée un client avec configuration minimale - SIGNATURE MODIFIÉE
func QuickClient(address, userID string, onMessage func(string, string, string)) (*Client, error) {
	opts := DefaultClientOptions()
	opts.UserID = userID
	opts.OnMessage = onMessage
	return NewClient(address, opts)
}

// QuickServer crée un serveur avec configuration minimale - SIGNATURE MODIFIÉE
func QuickServer(address string, onMessage func(string, string, string, string)) (*Server, error) {
	opts := DefaultClientOptions()
	opts.OnServerMessage = onMessage

	return NewServer(address, opts)
}

// QuickClientWithFS crée un client avec Forward Secrecy personnalisé - NOUVEAU
func QuickClientWithFS(address, userID string, onMessage func(string, string, string), fsConfig *KeyRotationConfig) (*Client, error) {
	opts := DefaultClientOptions()
	opts.UserID = userID
	opts.OnMessage = onMessage
	if fsConfig != nil {
		opts.KeyRotation = fsConfig
	}
	return NewClient(address, opts)
}

// QuickServerWithFS crée un serveur avec Forward Secrecy personnalisé - NOUVEAU
func QuickServerWithFS(address string, onMessage func(string, string, string, string), fsConfig *KeyRotationConfig) (*Server, error) {
	opts := DefaultClientOptions()
	opts.OnServerMessage = onMessage
	if fsConfig != nil {
		opts.KeyRotation = fsConfig
	}
	return NewServer(address, opts)
}
