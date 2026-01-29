# HL7 Server Module

Mock HL7 2.x server for Medaudit 2.0 testing and development.

## Features

- **MLLP-Wrapped HL7 Messages**: Accepts standard HL7 2.x messages wrapped in MLLP protocol
- **Automatic ACK Generation**: Generates and sends HL7 acknowledgment (ACK) messages
- **Non-Encrypted by Default**: Runs on plain TCP for easy testing
- **Optional TLS/SSL Encryption**: Enable encryption with certificate and key files
- **Comprehensive Logging**: Logs all messages to JSON Lines format
- **Configurable**: JSON-based configuration system
- **CLI Interface**: Command-line tool for easy management

## Usage

### Start Non-Encrypted Server (Default)

```bash
python -m hl7server start
```

This starts the server on `localhost:2575` without encryption.

### Start on Custom Host/Port

```bash
python -m hl7server start --host 0.0.0.0 --port 3000
```

### Start with TLS Encryption

```bash
python -m hl7server start --use-tls --cert-file server.crt --key-file server.key
```

### Create Configuration File

```bash
python -m hl7server config --create
```

Creates `hl7server.json` in the current directory with default settings.

### Show Current Configuration

```bash
python -m hl7server config --show
```

## Configuration

Configuration can be loaded from:
- `hl7server.json` in current directory
- `~/.hl7server.json` in user home
- `~/.config/hl7server.json` in XDG config directory

Command-line arguments override configuration file values.

### Configuration Format

```json
{
  "server": {
    "host": "localhost",
    "port": 2575,
    "use_tls": false,
    "cert_file": null,
    "key_file": null,
    "verbose": true
  },
  "logging": {
    "enabled": true,
    "log_dir": "logs/hl7server"
  }
}
```

## API Usage

### Basic Usage

```python
from hl7server import HL7Server

# Create server
server = HL7Server(
    host="localhost",
    port=2575,
    verbose=True
)

# Start server
server.start()

# Run indefinitely
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
```

### With Custom Message Callback

```python
def handle_message(message, client_address):
    """Custom handler for received messages."""
    print(f"Received from {client_address}: {message[:100]}")

server = HL7Server(
    host="localhost",
    port=2575,
    message_callback=handle_message
)
```

### With TLS Encryption

```python
server = HL7Server(
    host="0.0.0.0",
    port=2575,
    use_tls=True,
    cert_file="path/to/cert.crt",
    key_file="path/to/key.key"
)
```

## MLLP Protocol

The server uses the MLLP (Minimal Lower Layer Protocol) for HL7 message transport:

```
[Start Byte][HL7 Message][End Bytes]
   0x0B      UTF-8 Text    0x1C 0x0D
```

- **Start Byte**: `0x0B` (vertical tab)
- **Message**: HL7 v2.x message
- **End Bytes**: `0x1C 0x0D` (file separator + carriage return)

## Logging

All messages are logged to:
- **Console**: Real-time server activity (if `verbose=True`)
- **File**: `logs/hl7server/hl7_server_*.log` - Server activity log
- **JSON Lines**: `logs/hl7server/hl7_messages.jsonl` - Message details in JSON format

## Testing with Medaudit Proxy

The HL7 server works seamlessly with the Medaudit HTTP-to-HL7 proxy:

### Terminal 1: Start HL7 Server

```bash
python -m hl7server start --port 2575
```

### Terminal 2: Start HTTP-to-HL7 Proxy

```bash
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575
```

### Terminal 3: Send Test Message via HTTP

```bash
curl -X POST http://localhost:8080/ -d 'MSH|^~\&|TEST|TEST|TEST|TEST|20240101120000||ADT^A01|12345|P|2.5'
```

The flow:
1. HTTP request → Proxy
2. Proxy converts to HL7 and wraps in MLLP
3. Message sent to HL7 Server on port 2575
4. Server receives and logs message
5. Server generates ACK
6. ACK sent back to proxy
7. Proxy converts ACK back to HTTP response

## Integration with Tests

Use the server in tests for validating HL7 message handling:

```python
import pytest
from hl7server import HL7Server

@pytest.fixture
def hl7_server():
    server = HL7Server(port=2575, verbose=False)
    server.start()
    yield server
    server.stop()

def test_hl7_message(hl7_server):
    # Send message to server and verify ACK
    ...
```

## Generating SSL Certificates (for TLS testing)

Create self-signed certificates for testing:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate
openssl req -new -x509 -key server.key -out server.crt -days 365
```

Then start with TLS:

```bash
python -m hl7server start --use-tls --cert-file server.crt --key-file server.key
```

## Architecture Notes

- **Threading Model**: Each client connection handled in separate daemon thread
- **MLLP Parsing**: Robust frame parsing handles partial messages and errors
- **ACK Generation**: Extracts message control ID from MSH segment for proper acknowledgment
- **Logging**: Structured JSON Lines format for easy analysis and integration
- **Error Handling**: Graceful handling of disconnections and parsing errors

## Future Enhancements

- Message validation against HL7 schema
- Custom ACK response templates
- Message routing and forwarding
- Performance metrics and statistics
- Message replay and recording
- Multi-protocol support (HL7 3.x, FHIR)
