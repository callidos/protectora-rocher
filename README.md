# 🛡️ R.O.C.H.E.R Protocol
## Robust and Optimized Communication Harnessing Enhanced Resilience

[![Go](https://img.shields.io/badge/Go-1.19+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![Security](https://img.shields.io/badge/Security-Post%20Quantum-FF6B6B?style=for-the-badge&logo=security&logoColor=white)](https://github.com/callidos/protectora-rocher)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensource&logoColor=white)](LICENSE)

> **R.O.C.H.E.R** is an ultra-secure communication protocol designed for critical environments. It combines post-quantum cryptography, Forward Secrecy, and advanced resilience mechanisms to ensure confidentiality, integrity, and availability of communications.

---

## 🌟 Key Features

### 🔐 State-of-the-Art Security
- **Post-Quantum Cryptography**: Key exchange with **Kyber768** resistant to quantum computers
- **Hybrid Encryption**: **NaCl secretbox** with **AES-256-GCM** for maximum security
- **Forward Secrecy**: Automatic key rotation with multi-generation support
- **Zero-Knowledge Proofs**: **GNARK** compatible for anonymous authentication

### 🚀 Advanced Features
- **Automatic Reconnection**: Reconnection policy with exponential backoff
- **Intelligent Keep-Alive**: Disconnection detection and session maintenance
- **Adaptive Compression**: Automatic **Gzip** compression based on message size
- **Anti-Replay Protection**: Strict time windows and timestamp validation

### 🎯 Ease of Use
- **Simplified API**: Clients and servers in just a few lines of code
- **Flexible Configuration**: Predefined profiles and advanced customization
- **Integrated Monitoring**: Detailed metrics and real-time statistics
- **Robust Error Handling**: Structured error types and automatic recovery

---

## 📚 Table of Contents

- [🚀 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [🏗️ Architecture](#️-architecture)
- [🔧 Configuration](#-configuration)
- [📖 Usage Guide](#-usage-guide)
- [🔐 Security](#-security)
- [📊 Monitoring](#-monitoring)
- [🤝 Contributing](#-contributing)

---

## 🚀 Installation

### Prerequisites
- **Go 1.19+** or higher
- Network access for dependencies
- Compatible operating system (Linux, Windows, macOS)

### Standard Installation
```bash
# Clone the repository
git clone https://github.com/callidos/protectora-rocher
cd protectora-rocher

# Install dependencies
go mod tidy

# Run tests
go test ./... -v

# Verify installation
go run examples/simple_client.go
```

### Installation via Go Modules
```bash
go get github.com/callidos/protectora-rocher
```

---

## ⚡ Quick Start

### 🖥️ Simple Server
```go
package main

import (
    "fmt"
    "log"
    "github.com/callidos/protectora-rocher/pkg/rocher"
)

func main() {
    // Create server with callback
    server, err := rocher.QuickServer("tcp://localhost:8080", 
        func(clientID, message, messageType, recipient, sessionToken string) {
            fmt.Printf("Client %s: [%s] %s\n", clientID, messageType, message)
        })
    
    if err != nil {
        log.Fatal(err)
    }
    
    // Start server
    server.Start()
    
    // Send message to all clients
    server.Send("Hello all clients!", "broadcast", "all", "session-123")
    
    // Keep server running
    select {}
}
```

### 💻 Simple Client
```go
package main

import (
    "fmt"
    "log"
    "time"
    "github.com/callidos/protectora-rocher/pkg/rocher"
)

func main() {
    // Create client with callback
    client, err := rocher.QuickClient("tcp://localhost:8080", "user-123",
        func(message, messageType, recipient, sessionToken string) {
            fmt.Printf("Received [%s]: %s\n", messageType, message)
        })
    
    if err != nil {
        log.Fatal(err)
    }
    
    // Send messages
    client.Send("Hello server!", "chat", "server", "session-123")
    client.Send("Private message", "private", "admin", "session-456")
    
    // Keep connection alive
    time.Sleep(10 * time.Second)
    client.Close()
}
```

---

## 🏗️ Architecture

### 🔄 Communication Flow
```
┌─────────────────┐    Kyber768 KEM    ┌─────────────────┐
│     Client      │◄──────────────────►│     Server      │
│   (Initiator)   │                    │   (Responder)   │
└─────────────────┘                    └─────────────────┘
         │                                        │
         ▼                                        ▼
┌─────────────────┐                    ┌─────────────────┐
│ SecureChannel   │                    │ SecureChannel   │
│   with FS       │                    │   with FS       │
└─────────────────┘                    └─────────────────┘
         │                                        │
         ▼                                        ▼
┌─────────────────┐                    ┌─────────────────┐
│ NaCl Encrypted  │                    │ NaCl Encrypted  │
│    Messages     │                    │    Messages     │
└─────────────────┘                    └─────────────────┘
```

### 🧩 Core Components

#### 1. **Key Exchange (key_exchange.go)**
- **Kyber768**: Post-quantum cryptography
- Secure initiator/responder exchange
- Key size validation

#### 2. **Encryption (encryption.go)**
- **NaCl secretbox**: Authenticated encryption
- Key derivation with **HKDF-SHA256**
- Temporal message validation

#### 3. **Forward Secrecy (forward_secrecy.go)**
- Automatic key rotation
- Multi-generation conservation
- Peer synchronization

#### 4. **Messenger (messenger.go)**
- Automatic reconnection
- Intelligent keep-alive
- Adaptive compression

#### 5. **Simplified API (api.go)**
- High-level clients and servers
- Default configuration
- Event callbacks

---

## 🔧 Configuration

### ⚙️ Forward Secrecy Configuration
```go
fsConfig := &rocher.KeyRotationConfig{
    TimeInterval:  30 * time.Minute,  // Rotate every 30 minutes
    MaxMessages:   1000,              // Rotate after 1000 messages
    MaxBytes:      10 * 1024 * 1024,  // Rotate after 10MB
    ForceRotation: false,             // No forced rotation
    Enabled:       true,              // Forward Secrecy enabled
}

client, err := rocher.QuickClientWithFS("tcp://localhost:8080", "user-123", 
    onMessage, fsConfig)
```

### 🔄 Reconnection Configuration
```go
reconnectPolicy := &rocher.ReconnectPolicy{
    MaxAttempts:  5,                  // Max 5 attempts
    InitialDelay: 1 * time.Second,    // Initial delay 1s
    MaxDelay:     30 * time.Second,   // Max delay 30s
    Multiplier:   2.0,                // Factor x2
    Enabled:      true,               // Reconnection enabled
}

messenger := rocher.NewSimpleMessenger(true)
messenger.SetReconnectPolicy(reconnectPolicy)
```

### 💓 Keep-Alive Configuration
```go
keepAliveConfig := &rocher.KeepAliveConfig{
    Interval:  30 * time.Second,  // Ping every 30s
    Timeout:   10 * time.Second,  // Timeout 10s
    MaxMissed: 3,                 // Max 3 missed pings
    Enabled:   true,              // Keep-alive enabled
}

messenger.SetKeepAliveConfig(keepAliveConfig)
```

### 🗜️ Compression Configuration
```go
compressionConfig := &rocher.CompressionConfig{
    Type:      rocher.GzipCompression,  // Gzip algorithm
    Threshold: 1024,                    // 1KB threshold
    Level:     6,                       // Medium level
    Enabled:   true,                    // Compression enabled
}

messenger.SetCompressionConfig(compressionConfig)
```

---

## 📖 Usage Guide

### 📝 Message Types
```go
// Chat message
client.Send("Hello!", "chat", "user-456", "session-123")

// Private message
client.Send("Confidential", "private", "admin", "secure-session")

// System notification
client.Send("Alert", "notification", "all", "system-alert")

// Command
client.Send("restart", "command", "server", "admin-session")
```

### 🔑 Session Management
```go
// Create session
sessionToken := "user-123-" + time.Now().Format("20060102150405")

// Send with session
client.Send("Message with session", "chat", "user-456", sessionToken)

// Validate session server-side
func onMessage(clientID, message, messageType, recipient, sessionToken string) {
    if !validateSession(sessionToken) {
        return // Ignore message
    }
    
    // Process valid message
    processMessage(message, messageType)
}
```

### 📊 Monitoring and Statistics
```go
// Client statistics
stats := client.GetStats()
fmt.Printf("Messages sent: %d\n", stats["messages_sent"])
fmt.Printf("Bytes received: %d\n", stats["bytes_received"])

// Forward Secrecy statistics
fsStats := client.GetKeyRotationStats()
fmt.Printf("Rotation ID: %d\n", fsStats["current_rotation_id"])
fmt.Printf("Next rotation: %v\n", fsStats["next_rotation_time"])

// Force rotation
client.ForceKeyRotation()
```

---

## 🔐 Security

### 🛡️ Cryptographic Guarantees

| Property | Algorithm | Level |
|----------|-----------|-------|
| **Key Exchange** | Kyber768 | Post-quantum |
| **Encryption** | NaCl secretbox | 256-bit |
| **Integrity** | Poly1305 | Authentication |
| **Derivation** | HKDF-SHA256 | Directional keys |
| **Forward Secrecy** | Auto rotation | Multi-generation |

### 🔒 Best Practices

#### ✅ Recommendations
```go
// 1. Always use Forward Secrecy
fsConfig := rocher.DefaultKeyRotationConfig()
fsConfig.TimeInterval = 15 * time.Minute  // Frequent rotation

// 2. Validate sessions
func validateSession(token string) bool {
    return len(token) >= 16 && !isExpired(token)
}

// 3. Limit old keys
client.SetMaxOldKeys(3)  // Keep only 3 generations

// 4. Active monitoring
go func() {
    for {
        stats := client.GetKeyRotationStats()
        if !stats["synchronized"].(bool) {
            log.Warn("Desynchronization detected")
        }
        time.Sleep(time.Minute)
    }
}()
```

#### ⚠️ Warnings
- Never log keys or tokens
- Validate all incoming messages
- Implement appropriate timeouts
- Monitor security metrics

---

## 📊 Monitoring

### 📈 Available Metrics
```go
// Basic metrics
type Stats struct {
    MessagesSent     uint64
    MessagesReceived uint64
    BytesSent        uint64
    BytesReceived    uint64
    ReconnectAttempts uint64
    CompressionSaved  uint64
    Uptime           time.Duration
}

// Forward Secrecy metrics
type FSStats struct {
    CurrentRotationID   uint64
    PeerRotationID      uint64
    LastRotation        time.Time
    NextRotationTime    time.Time
    OldChannelsCount    int
    TimeUntilRotation   time.Duration
    Synchronized        bool
}
```

### 📊 Monitoring Example
```go
func monitorConnection(client *rocher.Client) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            stats := client.GetStats()
            fsStats := client.GetKeyRotationStats()
            
            // Structured logs
            log.WithFields(log.Fields{
                "messages_sent": stats["messages_sent"],
                "bytes_received": stats["bytes_received"],
                "rotation_id": fsStats["current_rotation_id"],
                "synchronized": fsStats["synchronized"],
            }).Info("Connection stats")
            
            // Alerts
            if !fsStats["synchronized"].(bool) {
                log.Warn("Forward Secrecy desynchronized")
            }
        }
    }
}
```

---

## 🧪 Testing and Validation

### 🔬 Unit Tests
```bash
# Complete tests
go test ./... -v -race

# Security tests
go test ./pkg/rocher -run TestSecurity -v

# Performance tests
go test ./pkg/rocher -run TestPerformance -bench=. -v

# Integration tests
go test ./integration -v
```

### 🎯 Benchmarks
```bash
# Key exchange benchmark
go test -bench=BenchmarkKeyExchange -v

# Encryption benchmark
go test -bench=BenchmarkEncryption -v

# Forward Secrecy benchmark
go test -bench=BenchmarkForwardSecrecy -v
```

---

## 🤝 Contributing

### 📋 Contribution Process
1. **Fork** the project
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### 🔍 Guidelines
- Follow existing code style
- Add tests for new features
- Document API changes
- Maintain backward compatibility

### 🏷️ Code Standards
```go
// Example function structure
func (c *Client) SendSecureMessage(
    message string, 
    messageType string, 
    recipient string, 
    sessionToken string,
) error {
    // Parameter validation
    if message == "" {
        return NewInputError("message cannot be empty", nil)
    }
    
    // Business logic
    return c.messenger.SendMessage(message, messageType, recipient, sessionToken, c.conn)
}
```

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Kyber Team** for post-quantum cryptography
- **NaCl Team** for authenticated encryption
- **Go Community** for tools and libraries
- **Contributors** for continuous improvements

---

## 📞 Support

- **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/callidos/protectora-rocher)
- **Issues**: [GitHub Issues](https://github.com/callidos/protectora-rocher/issues)
- **Discussions**: [GitHub Discussions](https://github.com/callidos/protectora-rocher/discussions)

---

<div align="center">

**🛡️ R.O.C.H.E.R - The first post-quantic rock 🛡️**

*Built with ❤️ for critical security*

</div>