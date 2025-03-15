# PhalanxDB - Distributed database build on Gun.JS

A Node.js implementation with Express server integration built on Gun.JS. PhalanxDB is designed for integration with cli_debrid and Riven, and is likely not useful in any other context.

## Features

- Gun.js peer-to-peer database integration
- Express server setup
- Rate limiting for endpoints
- Cache management:
  - Three-state cache system: `cached`, `uncached`, and `unchecked`
  - Automatic cache expiration after 7 days (moves from `cached` to `unchecked`)
  - Automatic recheck trigger after 24 hours of being `uncached` (moves to `unchecked`)

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

1. Create a docker-compose.yml file with the following content:
   ```yaml
   services:
     phalanx_db:
       image: godver3/phalanx_db:latest
       container_name: phalanx_db
       restart: unless-stopped
       ports:
         - "3000:3000"
       volumes:
         - phalanx_data:/app/gun-relays
         - phalanx_data:/app/node-data.json

   volumes:
     phalanx_data:
       name: phalanx_data
   ```

2. Start the container:
   ```bash
   docker compose up -d
   ```

## API Endpoints

All endpoints require authentication using a Bearer token. The encryption key should be provided in the Authorization header.

### Add Data

```bash
curl -X POST http://localhost:3000/data \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "example_hash_123",
    "cached": true,
    "timestamp": "2024-03-12T12:00:00Z",
    "provider": "real_debrid"
  }'
```

The `cached` field accepts the following values:
- `true`: Item is confirmed to be cached
- `false`: Item is confirmed to not be cached
- `"unchecked"`: Item needs verification (automatically set after expiration)

### Get All Data

```bash
curl http://localhost:3000/data \
  -H "Authorization: Bearer TOKEN"
```

### Get Specific Data by Hash

```bash
curl http://localhost:3000/data/example_hash_123 \
  -H "Authorization: Bearer TOKEN"
```

### Debug Endpoint

```bash
curl http://localhost:3000/debug \
  -H "Authorization: Bearer TOKEN"
```

The TOKEN should be set to the value of `ENCRYPTION_KEY` from the `.env` file. 

## Links

- https://github.com/rivenmedia/riven
- https://github.com/godver3/cli_debrid
- https://github.com/amark/gun