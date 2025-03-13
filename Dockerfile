FROM --platform=${TARGETPLATFORM} node:18-alpine

WORKDIR /app

COPY package*.json ./

# Install dependencies with additional configuration for ARM builds
RUN apk add --no-cache python3 make g++ && \
    npm install && \
    apk del python3 make g++

COPY . .

EXPOSE 3000

# Set the entrypoint directly instead of relying on docker-entrypoint.sh
ENTRYPOINT ["node", "client.js"] 