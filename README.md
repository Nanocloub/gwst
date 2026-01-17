# GWST - Generic WebSocket Tunnel

GWST is a versatile WebSocket tunneling tool that allows you to create secure and efficient tunnels for various network protocols.

## Features

- Support for both client and server modes
- **Multiple transport protocols**: WebSocket, TCP, QUIC (pluggable architecture)
- TLS encryption for secure connections
- **AEGIS-128L authenticated encryption for data protection**
- Configurable endpoints using YAML
- Multiple simultaneous tunnels
- UDP support with early data
- Custom target routing
- High-performance encryption with minimal overhead

## Supported Transports

GWST supports multiple transport protocols that can be freely mixed:

- **WebSocket** (ws/wss) - Default, HTTP-compatible, proxy-friendly
- **TCP** - Direct TCP connections, lowest latency, best performance
- **QUIC** - Modern multiplexed UDP-based protocol, ideal for mobile networks

Each endpoint can independently choose its transport protocol. See [TRANSPORT.md](TRANSPORT.md) for details.

## Security

GWST now supports **AEGIS-128L** authenticated encryption for protecting your data transmission:

- **High Performance**: Near-hardware-speed encryption on modern CPUs
- **Authenticated Encryption**: Provides both confidentiality and integrity
- **Easy Configuration**: Simply set a 16+ byte key in the configuration
- **Minimal Overhead**: Less than 5% performance impact on modern hardware

For detailed information about encryption, see [ENCRYPTION.md](ENCRYPTION.md).

### Quick Start with Multi-Transport

```yaml
# TCP server with encryption
- is_client: false
  listen_addr: ":8000"
  target_addr: "localhost:80"
  transport: "tcp"
  key: "1234567890123456"  # Enables AEGIS-128L encryption

# TCP client with encryption  
- is_client: true
  listen_addr: ":9000"
  target_addr: "127.0.0.1:8000"
  transport: "tcp"
  key: "1234567890123456"  # Must match server key

# WebSocket server (default transport)
- is_client: false
  listen_addr: ":8001"
  target_addr: "localhost:80"
  path: "/ws"
  key: "1234567890123456"
  tls: true
  cert_file: "cert.pem"
  key_file: "key.pem"
```

See [example-multi-transport.yaml](example-multi-transport.yaml) for complete examples.

## Installation

To install GWST, make sure you have Go installed on your system, then run:

```bash
go run . ./example.yaml
```
