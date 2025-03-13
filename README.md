# PhalanxDB - Distributed database build on Gun.JS

A Node.js implementation with Express server integration built on Gun.JS. PhalanxDB is designed for integration with cli_debrid and Riven, and is likely not useful in any other context.

## Features

- Gun.js peer-to-peer database integration
- Express server setup
- Rate limiting

## Installation

### Local Setup

1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   cd gunjs-client
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the application:
   ```bash
   npm start
   ```

### Docker Setup

1. Build the Docker image:
   ```bash
   docker build -t gunjs-client .
   ```

2. Run the container:
   ```bash
   docker run -p 8765:8765 gunjs-client
   ```

## API Endpoints

All endpoints require authentication using a Bearer token. The encryption key should be provided in the Authorization header.

### Add Data

```bash
curl -X POST http://localhost:3000/data \
  -H "Authorization: Bearer phalanx_db_v1_32byte_key_20240312_01" \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "example_hash_123",
    "cached": true,
    "timestamp": "2024-03-12T12:00:00Z"
  }'
```

### Get All Data

```bash
curl http://localhost:3000/data \
  -H "Authorization: Bearer phalanx_db_v1_32byte_key_20240312_01"
```

### Get Specific Data by Hash

```bash
curl http://localhost:3000/data/example_hash_123 \
  -H "Authorization: Bearer phalanx_db_v1_32byte_key_20240312_01"
```

### Debug Endpoint

```bash
curl http://localhost:3000/debug \
  -H "Authorization: Bearer phalanx_db_v1_32byte_key_20240312_01"
```

## Links

- https://github.com/rivenmedia/riven
- https://github.com/godver3/cli_debrid
- https://github.com/amark/gun