# R.O.C.H.E.R Protocol (Robust and Optimized Communication Harnessing Enhanced Resilience)

**R.O.C.H.E.R** is an ultra-secure communication protocol designed for critical environments, such as military applications and highly confidential systems. It relies on a robust and modern architecture using advanced technologies to ensure the confidentiality, integrity, and availability of communications.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [API Overview](#api-overview)
- [Documentation](#documentation)
- [Contributing](#contributing)

---

## Features

- **Advanced encryption**: Utilizes **AES-256-GCM** to secure messages.
- **Post-quantum key exchange**: Implements **Kyber** for quantum-resistant security.
- **Attack detection**: Protection against replay attacks with strict time windows.
- **Modular and independent**: Designed as a standalone protocol, easily integrable into existing systems.
- **GNARK Compatibility**: Secure authentication based on zero-knowledge proofs (ZKP).
- **Key rotation support**: Implements a hybrid key management system with automatic rotation.
- **Efficient compression**: Gzip compression to optimize network usage.
- **Error handling and logging**: Robust logging using Logrus for security auditing.

---

## Architecture

The protocol follows a strict client-server architecture with clear separation of responsibilities, while remaining independent from both client and server implementations.

### Overview:

1. **Protocol Core**:
   - Located in the `pkg/communication` package.
   - Provides secure communication primitives.

2. **Core Modules**:
   - **Encryption**: AES-GCM encryption with HMAC for integrity.
   - **Compression**: Gzip compression for reducing message sizes.
   - **Key exchange**: Kyber for post-quantum security and Ed25519 for authentication.
   - **Anti-replay protection**: Prevents duplicate message attacks.
   - **Session management**: Supports ephemeral and persistent session modes.

---

## Technologies Used

- **Language**: Go (Golang).
- **Libraries**:
  - `golang.org/x/crypto` for encryption and key exchange.
  - `github.com/sirupsen/logrus` for logging.
- **Security Standards**:
  - AES-256-GCM for encryption.
  - Kyber for post-quantum key exchange.
  - HMAC-SHA256 for message integrity.

---

## Installation

### Prerequisites

- Go version 1.19 or higher.
- Terminal access.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/callidos/protectora-rocher.git
   cd protectora-rocher
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Run tests to verify functionality:
   ```bash
   go test ./internal/tests -v
   ```

---

## Usage Example

Below is an example demonstrating how to use the R.O.C.H.E.R protocol for secure communication between a client and a server.

### Client Code

```go
package main

import (
    "net"
    "github.com/callidos/protectora-rocher/pkg/communication"
)

func main() {
    conn, _ := net.Dial("tcp", "localhost:8080")
    sharedKey := []byte("thisisaverysecurekeythisisaverysecurekey")

    err := communication.SendSecureMessage(conn, "Hello, secure world!", sharedKey, 1, 3600)
    if err != nil {
        panic(err)
    }
}
```

### Server Code

```go
package main

import (
    "net"
    "github.com/callidos/protectora-rocher/pkg/communication"
)

func main() {
    listener, _ := net.Listen("tcp", ":8080")
    for {
        conn, _ := listener.Accept()
        sharedKey := []byte("thisisaverysecurekeythisisaverysecurekey")
        go communication.HandleNewConnection(conn, conn, sharedKey)
    }
}
```

---

## API Overview

The R.O.C.H.E.R protocol provides an easy-to-use API for developers:

### Session Management
```go
err := communication.InitializeSession(communication.SessionEphemeral)
if err != nil {
    log.Fatal("Session initialization failed:", err)
}
```

### Secure Message Transmission
```go
err := communication.SendSecureMessage(conn, "Confidential Data", sharedKey, 42, 3600)
if err != nil {
    log.Fatal("Failed to send message:", err)
}
```

### Key Exchange
```go
resultChan, err := communication.PerformKeyExchange(conn, privateKey)
if err != nil {
    log.Fatal("Key exchange failed:", err)
}

result := <-resultChan
fmt.Println("Derived key:", base64.StdEncoding.EncodeToString(result.Key[:]))
```

---

## Documentation

For more details, check the [GoDoc documentation](https://pkg.go.dev/github.com/callidos/protectora-rocher/pkg/communication).

---

## Contributing

1. Clone the repository.
2. Create a branch for your changes:
   ```bash
   git checkout -b my-feature-branch
   ```
3. Make changes and run tests.
4. Submit your changes via a pull request.

---

## License

This project is licensed under the MIT License.
