
# R.O.C.H.E.R Protocol (Robust and Optimized Communication Harnessing Enhanced Resilience)

**R.O.C.H.E.R** is an ultra-secure communication protocol designed for critical environments, such as military applications and highly confidential systems. It relies on a robust and modern architecture using advanced technologies to ensure the confidentiality, integrity, and availability of communications.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [Documentation](#documentation)
- [Contributing](#contributing)

---

## Features

- **Advanced encryption**: Utilizes **AES-256-GCM** to secure messages.
- **Post-quantum key exchange**: Implements **Kyber** for quantum-resistant security.
- **Attack detection**: Protection against replay attacks with strict time windows.
- **Modularity**: Designed as an independent protocol, easily integrable into other systems.
- **GNARK Compatibility**: Secure authentication based on zero-knowledge proofs.
- **Easy-to-use API**: Simplified API for developers to integrate the protocol easily.
- **Flexible data handling**: Supports secure message sending and receiving with integrated encryption and compression.

---

## Architecture

The protocol follows a strict client-server architecture with a clear separation of responsibilities:

1. **Protocol**:
   - Located in the `pkg/communication` package.
   - Independent from the client and server for easy integration.

2. **Modules**:
   - **Encryption**: Handles sensitive data using AES-GCM.
   - **Compression**: Reduces message size with Gzip.
   - **Key exchange**: Implements Ed25519 and Kyber for secure key exchange.
   - **Anti-replay**: Manages sequences and timestamps to prevent duplicates.
   - **Session management**: Enables ephemeral or persistent session modes.

---

## Technologies Used

- **Language**: Go (Golang).
- **Libraries**:
  - `golang.org/x/crypto` for advanced encryption.
  - `github.com/sirupsen/logrus` for structured logging.
- **Security Standards**:
  - AES-256-GCM for encryption.
  - Kyber for post-quantum keys.
  - HMAC-SHA256 for message integrity.

---

## Installation

### Prerequisites

- Go version 1.19 or higher.
- Terminal access.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/protectora-rocher.git
   cd protectora-rocher
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Run tests to verify functionality:
   ```bash
   go test ./tests -v
   ```

---

## Usage Example

Here is a simple example showing how to use the R.O.C.H.E.R protocol to send and receive secure messages.

### Client Code

```go
package main

import (
    "net"
    "github.com/your-username/protectora-rocher/pkg/communication"
)

func main() {
    conn, _ := net.Dial("tcp", "localhost:8080")
    sharedKey := []byte("thisisaverysecurekey!")

    err := communication.SendSecureMessage(conn, "Hello, secure world!", sharedKey, 1, 60)
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
        sharedKey := []byte("thisisaverysecurekey!")
        go communication.HandleNewConnection(conn, conn, sharedKey)
    }
}
```

---

## Documentation

For more details, check the [GoDoc documentation](https://pkg.go.dev/github.com/callidos/protectora-rocher/pkg/communication).

---

## Contributing

1. Clone the repository.
2. Create a branch for your changes:
   ```bash
   git checkout -b my-branch
   ```
3. Submit your changes via a pull request.
