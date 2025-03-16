# PhalanxDB - Distributed database build on Gun.JS

A Node.js implementation with Express server integration built on Gun.JS. PhalanxDB is designed for integration with cli_debrid and Riven, and is likely not useful in any other context.

## Features

- Gun.js peer-to-peer database integration
- Express server setup
- Rate limiting for endpoints
- Cache management:
  - Two-state cache system: `cached` and `uncached`
  - Automatic expiry calculation when not explicitly provided:
    - Cached items expire after 7 days from their last modification
    - Uncached items expire after 24 hours from their last modification
  - Cache status and expiry dates are preserved as provided

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
    "infohash": "example_hash_123",
    "cached": true,
    "service": "real_debrid",
    "last_modified": "2024-03-12T12:00:00Z",
    "expiry": "2024-03-19T12:00:00Z"
  }'
```

**Data Validation Requirements:**
- Required fields:
  - `infohash`: must be a string
  - `service`: must be a string
  - `cached`: must be a boolean (true or false)
- Optional fields:
  - `last_modified`: if provided, must be a valid ISO 8601 timestamp with Z suffix
  - `expiry`: if provided, must be a valid ISO 8601 timestamp with Z suffix
- Requests missing required fields or containing invalid data types will be rejected

Note: All timestamps must be in UTC format (ISO 8601) with the 'Z' suffix indicating UTC timezone (e.g., "2024-03-12T12:00:00Z")

The `cached` field and expiry handling:
- `true`: Item is cached (default expiry: 7 days from last_modified if not provided)
- `false`: Item is not cached (default expiry: 24 hours from last_modified if not provided)
- `last_modified` defaults to server's current time if not provided
- The `expiry` field can be provided explicitly, otherwise defaults are calculated
- All timestamps must be in UTC format with 'Z' suffix
- Cache status and expiry values are preserved as provided, without automatic expiration logic

### Get All Data

```bash
curl http://localhost:3000/data \
  -H "Authorization: Bearer TOKEN"
```

### Get Specific Data by Infohash

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