const Gun = require('gun');  // Use standard Gun import
require('gun/lib/webrtc');  // Add WebRTC support
require('gun/sea');  // Add SEA support
require('dotenv').config();  // Load environment variables
const express = require('express');  // Add Express for HTTP server
const bodyParser = require('body-parser');  // Add body-parser for parsing requests
const fs = require('fs');  // Add fs import at top with other requires
const path = require('path');  // Add path import at top with other requires

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
    console.error('ERROR: ENCRYPTION_KEY not found in environment variables');
    process.exit(1);
}

// Node identity configuration
const NODE_ID = 'phalanx-db';

// List of services to exclude
const EXCLUDED_SERVICES = ['usenet', 'direct', 'torrent', 'web', 'test', '#'];

class PhalanxMonitor {
    constructor() {
        this.gun = null;
        this.cacheTable = null;
        this.connectedRelays = [];
        this.startupTime = new Date();
        this.lastUpdateTime = null; // Track timestamp of newest item seen
        this.pair = null; // Will store SEA key pair
        this.memoryLoggingInterval = null;
        this.EXCLUDED_SERVICES = ['usenet', 'direct', 'torrent', 'web', 'test', '#']; // Services to exclude

        // Initialize Express app and server
        this.app = express();
        this.server = null; // Will hold the HTTP server instance
        this.app.use(bodyParser.json());
    }

    // Add memory logging function
    logMemoryUsage() {
        const used = process.memoryUsage();
        console.log('\n----- MEMORY USAGE [' + new Date().toISOString() + '] -----');
        for (let key in used) {
            console.log(`${key}: ${Math.round(used[key] / 1024 / 1024 * 100) / 100} MB`);
        }
        console.log('---------------------------------------------\n');
    }

    async initialize() {
        try {
            // Initialize encryption first
            await this.initializeEncryption();
            
            console.log('Discovering relay servers...');
            const relays = await this.discoverRelays();
            
            // Initialize Gun with built-in RAD storage
            const DATA_DIR = 'data';  // Define data directory constant

            // Create data directory if it doesn't exist
            if (!fs.existsSync(DATA_DIR)) {
                fs.mkdirSync(DATA_DIR);
            }

            this.gun = Gun({
                peers: relays,
                localStorage: false,
                multicast: false,
                retry: 2000,
                pid: NODE_ID,
                sea: true,
                axe: false,
                radisk: true,
                file: path.join(DATA_DIR, 'phalanx-db')  // Store RAD files in data subdirectory
            });

            // Initialize the cache table
            this.cacheTable = this.gun.get('cache');
            
            console.log('Monitor initialized successfully');
            this.logConnectedRelays();
            this.setupSubscription();

            // Setup periodic memory logging
            this.memoryLoggingInterval = setInterval(() => {
                this.logMemoryUsage();
            }, 30000); // Log every 30 seconds

            // Start the HTTP server
            this.startHttpServer();

            return true;
        } catch (error) {
            console.error('Failed to initialize monitor:', error);
            return false;
        }
    }
    
    async discoverRelays() {
        try {
            // Import gun-relays dynamically
            const { default: Relays } = await import('gun-relays');
            
            // Get initial relay list
            const relays = await Relays();
            
            // Add our custom relay to the list
            const customRelay = 'http://129.153.56.54:8888/gun';
            if (!relays.includes(customRelay)) {
                relays.push(customRelay);
                console.log(`Added custom relay: ${customRelay}`);
            }
            
            console.log(`Discovered ${relays.length} potential relay servers`);
            if (relays.length > 0) {
                console.log('Relays:');
                relays.forEach((relay, index) => {
                    console.log(`  ${index + 1}. ${relay}`);
                });
            }
            
            this.connectedRelays = relays;
            return relays;
        } catch (err) {
            console.error('Error discovering relays:', err);
            return [];
        }
    }

    // Log all currently connected relay servers
    logConnectedRelays() {
        if (!this.gun) {
            console.warn('Cannot log relays: Gun not initialized');
            return;
        }
        
        try {
            const allPeers = this.gun.back('opt.peers') || {};
            const relayServers = [];
            
            // Process peers and identify relay servers
            Object.entries(allPeers).forEach(([url, peer]) => {
                if (url.startsWith('http')) {
                    // Check if the peer has a wire property to confirm it's connected
                    const isConnected = peer && peer.wire ? true : false;
                    relayServers.push({
                        url,
                        connected: isConnected
                    });
                }
            });
            
            // Log the results
            console.log(`\n----- RELAY CONNECTION STATUS [${new Date().toISOString()}] -----`);
            console.log(`Total relay connections: ${relayServers.length}`);
            
            if (relayServers.length > 0) {
                console.log('Connected relays:');
                relayServers.forEach((relay, index) => {
                    console.log(`  ${index + 1}. ${relay.url} - ${relay.connected ? 'CONNECTED' : 'DISCONNECTED'}`);
                });
            } else {
                console.log('No relay connections detected.');
            }
            console.log('-----------------------------------------------------\n');
        } catch (error) {
            console.error('Error logging relay connections:', error);
        }
    }

    // Initialize SEA encryption
    async initializeEncryption() {
        try {
            // Create a deterministic key pair from our encryption key
            this.pair = await Gun.SEA.pair();
            console.log('SEA encryption initialized successfully');
            return true;
        } catch (error) {
            console.error('Failed to initialize SEA encryption:', error);
            return false;
        }
    }

    // Decrypt data, handling both encrypted and unencrypted legacy data
    async decrypt(data) {
        try {
            if (!this.pair) {
                throw new Error('Encryption not initialized');
            }

            if (!data || !data.encryptedData) {
                throw new Error('Invalid encrypted object');
            }

            // Decrypt using SEA
            const decrypted = await Gun.SEA.decrypt(data.encryptedData, ENCRYPTION_KEY);
            if (!decrypted) {
                throw new Error('Decryption failed');
            }
            
            // Parse the decrypted data if it was originally an object
            try {
                return JSON.parse(decrypted);
            } catch {
                return decrypted;
            }
        } catch (error) {
            console.error('SEA decryption error:', error);
            return null;
        }
    }

    // Encrypt data using SEA and the ENCRYPTION_KEY
    async encrypt(data) {
        try {
            if (!this.pair) {
                throw new Error('Encryption not initialized');
            }

            // Stringify the data if it's an object
            const dataString = typeof data === 'string' ? data : JSON.stringify(data);

            // Encrypt using SEA
            const encryptedData = await Gun.SEA.encrypt(dataString, ENCRYPTION_KEY);

            return { encryptedData };
        } catch (error) {
            console.error('SEA encryption error:', error);
            return null;
        }
    }

    // Helper function to validate ISO date format
    isValidISODate(dateString) {
        if (typeof dateString !== 'string') return false;
        
        // Check if it's an ISO 8601 format and ends with 'Z' (Zulu time zone)
        const isISOFormat = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(dateString);
        
        if (!isISOFormat) return false;
        
        // Check if it's a valid date
        const date = new Date(dateString);
        return !isNaN(date.getTime());
    }

    // Clean data object by removing Gun.js metadata and returning useful structure
    cleanData(data, key = null) {
        if (!data || typeof data !== 'object') {
            return null;
        }

        // Ensure 'infohash' and 'services' are present
        const infohash = data.infohash || key;
        const services = data.services;

        if (!infohash || !services || typeof services !== 'object') {
            return null;
        }

        // Return the cleaned data
        return {
            infohash: infohash,
            services: services
        };
    }

    // Setup subscription to listen for new data
    setupSubscription() {
        if (!this.gun || !this.cacheTable) {
            console.error('Cannot setup subscription: Gun or cacheTable not initialized');
            return;
        }
        
        console.log('Setting up subscription to monitor new data...');
        
        // Single subscription for both initial data and updates
        this.cacheTable.map().on(async (data, key) => {
            this.processEntry(data, key);
        });
        
        console.log('Subscription active. Waiting for new data...');
        this.logMemoryUsage();
    }

    // Separate method to process entries to avoid duplicate code
    async processEntry(data, key) {
        // Skip invalid keys
        if (!key || key === '' || key.length === 0 || key === '_' || key === 'cache') {
            return;
        }
        
        try {
            if (!data) {
                return;
            }

            // Decrypt if necessary
            let decryptedData;
            if (data.encryptedData) {
                decryptedData = await this.decrypt(data);
                if (!decryptedData) {
                    return;
                }
            } else {
                decryptedData = data;
            }

            // Use cleanData to parse the data
            const cleanedData = this.cleanData(decryptedData, key);
            if (!cleanedData || !cleanedData.services) {
                return;
            }

            // Check all services for the newest last_modified timestamp
            Object.values(cleanedData.services).forEach(service => {
                if (service.last_modified && this.isValidISODate(service.last_modified)) {
                    if (!this.lastUpdateTime || new Date(service.last_modified) > new Date(this.lastUpdateTime)) {
                        this.lastUpdateTime = service.last_modified;
                    }
                }
            });

        } catch (error) {
            console.error(`Error processing data for key ${key}:`, error);
        }
    }

    // Get data with SEA decryption
    async getData(infohash) {
        if (!this.gun) {
            console.warn('Gun not initialized');
            return null;
        }

        return new Promise((resolve) => {
            this.cacheTable.get(infohash).once(async (data) => {
                try {
                    if (!data) {
                        resolve(null);
                        return;
                    }

                    // Decrypt if encrypted
                    let decryptedData;
                    if (data.encryptedData) {
                        decryptedData = await this.decrypt(data);
                        if (!decryptedData) {
                            console.warn(`Failed to decrypt data for infohash: ${infohash}`);
                            resolve(null);
                            return;
                        }
                    } else {
                        decryptedData = JSON.parse(JSON.stringify(data));
                    }

                    // Pass infohash to cleanData
                    const cleanedData = this.cleanData(decryptedData, infohash);
                    resolve(cleanedData);
                } catch (error) {
                    console.error(`Error processing data for infohash ${infohash}:`, error);
                    resolve(null);
                }
            });
        });
    }

    // Set data with SEA encryption
    async setData(infohash, data) {
        try {
            // Validate and clean data
            const existingData = await this.getData(infohash);

            // Prepare the new service data
            const serviceName = data.service.toLowerCase().replace(/\s+/g, '_');
            
            // Calculate default last_modified
            const lastModified = data.last_modified && this.isValidISODate(data.last_modified)
                ? data.last_modified
                : new Date().toISOString();

            // Update lastUpdateTime if this is the newest item we've seen
            if (!this.lastUpdateTime || new Date(lastModified) > new Date(this.lastUpdateTime)) {
                this.lastUpdateTime = lastModified;
            }

            // Calculate default expiry based on cached status
            let expiry;
            if (data.expiry && this.isValidISODate(data.expiry)) {
                expiry = data.expiry;
            } else {
                const lastModifiedDate = new Date(lastModified);
                if (isNaN(lastModifiedDate.getTime())) {
                    throw new Error('Invalid last_modified date');
                }

                if (data.cached) {
                    // Cached items expire after 7 days
                    expiry = new Date(lastModifiedDate.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
                } else {
                    // Uncached items expire after 24 hours
                    expiry = new Date(lastModifiedDate.getTime() + 24 * 60 * 60 * 1000).toISOString();
                }
            }

            const serviceData = {
                cached: data.cached,
                last_modified: lastModified,
                expiry: expiry
            };

            // Merge with existing data
            const services = existingData && existingData.services ? existingData.services : {};
            services[serviceName] = serviceData;

            // Assemble the full data object
            const fullData = {
                infohash: infohash,
                services: services
            };

            // Encrypt the data
            const encryptedData = await this.encrypt(fullData);
            if (!encryptedData) {
                throw new Error('Data encryption failed');
            }

            // Store the data
            return new Promise((resolve) => {
                this.cacheTable.get(infohash).put(encryptedData, (ack) => {
                    if (ack.err) {
                        console.error('Error storing data:', ack.err);
                        resolve(false);
                    } else {
                        resolve(true);
                    }
                });
            });
        } catch (error) {
            console.error('Error in setData:', error);
            return false;
        }
    }

    // Invalidate data for a specific infohash and optionally a specific service
    async invalidateData(infohash, service = null) {
        try {
            if (!infohash) {
                throw new Error('Infohash is required');
            }

            // Get existing data
            const existingData = await this.getData(infohash);
            if (!existingData || !existingData.services) {
                return true; // Nothing to invalidate
            }

            if (service) {
                // Remove specified service
                if (existingData.services[service]) {
                    delete existingData.services[service];

                    // If there are other services, update the data
                    if (Object.keys(existingData.services).length > 0) {
                        // Encrypt and store the updated data
                        const encryptedData = await this.encrypt(existingData);
                        if (!encryptedData) {
                            throw new Error('Data encryption failed');
                        }

                        return new Promise((resolve) => {
                            this.cacheTable.get(infohash).put(encryptedData, (ack) => {
                                if (ack.err) {
                                    console.error('Error updating data:', ack.err);
                                    resolve(false);
                                } else {
                                    resolve(true);
                                }
                            });
                        });
                    } else {
                        // No services left, remove the entire entry
                        return new Promise((resolve) => {
                            this.cacheTable.get(infohash).put(null, (ack) => {
                                if (ack.err) {
                                    console.error('Error invalidating data:', ack.err);
                                    resolve(false);
                                } else {
                                    console.log(`Data invalidated for infohash: ${infohash}`);
                                    resolve(true);
                                }
                            });
                        });
                    }
                } else {
                    return true; // Service not found, nothing to do
                }
            } else {
                // Remove the entire entry
                return new Promise((resolve) => {
                    this.cacheTable.get(infohash).put(null, (ack) => {
                        if (ack.err) {
                            console.error('Error invalidating data:', ack.err);
                            resolve(false);
                        } else {
                            console.log(`Data invalidated for infohash: ${infohash}`);
                            resolve(true);
                        }
                    });
                });
            }
        } catch (error) {
            console.error('Error in invalidateData:', error);
            return false;
        }
    }

    // Cleanup method to stop intervals when shutting down
    cleanup() {
        console.log('Cleaning up resources...');
        
        // Clear memory logging interval
        if (this.memoryLoggingInterval) {
            clearInterval(this.memoryLoggingInterval);
            this.memoryLoggingInterval = null;
        }

        // Close the HTTP server if running
        if (this.server) {
            this.server.close(() => {
                console.log('HTTP server closed.');
            });
            this.server = null;
        }

        // Unsubscribe from the cache table
        if (this.cacheTable) {
            this.cacheTable.map().off();
        }
        
        // Log final memory state
        this.logMemoryUsage();
        
        console.log('Cleanup completed');
    }

    // Reset and rebuild service counts from actual data
    async rebuildServiceCounts() {
        if (!this.gun) {
            console.warn('Gun not initialized');
            return;
        }

        // Reset counts
        this.serviceCounts.clear();
        
        return new Promise((resolve) => {
            let completed = false;
            let totalProcessed = 0;

            console.log('Rebuilding service counts...');

            // Process all entries
            this.cacheTable.map().once(async (data, hash) => {
                if (hash === '_' || hash === '' || !hash) return;
                
                totalProcessed++;
                
                try {
                    // Decrypt and clean data
                    let processedData;
                    if (data && data.encryptedData) {
                        processedData = await this.decrypt(data);
                    } else if (data) {
                        processedData = JSON.parse(JSON.stringify(data));
                    }

                    if (!processedData) return;

                    // Clean the data
                    const cleanedData = this.cleanData(processedData);
                    if (!cleanedData || !cleanedData.services) return;

                    // Update counts
                    Object.keys(cleanedData.services).forEach(serviceName => {
                        const count = this.serviceCounts.get(serviceName) || 0;
                        this.serviceCounts.set(serviceName, count + 1);
                    });
                } catch (error) {
                    console.error(`Error processing entry ${hash}:`, error);
                }
            }).then(() => {
                completed = true;
                console.log(`Service counts rebuilt. Processed ${totalProcessed} entries.`);
                this.logServiceCounts();
                resolve();
            });

            // Set a timeout
            setTimeout(() => {
                if (!completed) {
                    console.warn('Timeout while rebuilding service counts');
                    resolve();
                }
            }, 30000);
        });
    }

    // Add this method inside the PhalanxMonitor class

    startHttpServer() {
        const port = process.env.PORT || 8888; // Use PORT from environment or default to 3000

        // Authentication middleware
        const authenticateRequest = (req, res, next) => {
            const authHeader = req.headers.authorization;
            const clientIP = req.ip || req.connection.remoteAddress;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                console.warn(`Authentication attempt without token from IP: ${clientIP}`);
                return res.status(401).json({ error: 'Missing authentication token' });
            }
        
            const token = authHeader.split(' ')[1];
            if (token !== ENCRYPTION_KEY) {
                console.warn(`Invalid authentication attempt from IP: ${clientIP}`);
                return res.status(403).json({ error: 'Invalid authentication token' });
            }
        
            next();
        };

        // Define the /debug endpoint
        this.app.get('/debug', authenticateRequest, (req, res) => {
            const memoryUsage = process.memoryUsage();

            res.json({
                timestamp: new Date().toISOString(),
                lastUpdate: this.lastUpdateTime || 'No updates yet',
                memoryUsage: {
                    rss: `${(memoryUsage.rss / 1024 / 1024).toFixed(2)} MB`,
                    heapTotal: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
                    heapUsed: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
                    external: `${(memoryUsage.external / 1024 / 1024).toFixed(2)} MB`,
                    arrayBuffers: `${(memoryUsage.arrayBuffers / 1024 / 1024).toFixed(2)} MB`,
                },
                uptime: `${process.uptime().toFixed(2)} seconds`,
                startupTime: this.startupTime.toISOString(),
                connectedRelays: this.connectedRelays,
            });
        });

        // POST /data - Add or update data
        this.app.post('/data', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            const data = req.body;

            // Validate required fields
            if (!data.infohash || !data.service || data.cached === undefined) {
                return res.status(400).json({ 
                    error: 'Missing required fields. infohash, service, and cached are required.'
                });
            }

            // Validate data types
            if (typeof data.infohash !== 'string' || typeof data.service !== 'string') {
                return res.status(400).json({ 
                    error: 'Invalid data types. infohash and service must be strings.'
                });
            }

            // Normalize service name: convert to lowercase and replace spaces with underscores
            data.service = data.service.toLowerCase().replace(/\s+/g, '_');

            if (typeof data.cached !== 'boolean') {
                return res.status(400).json({ 
                    error: 'Invalid data type. cached must be a boolean (true or false).'
                });
            }

            // Validate timestamp formats if provided
            if (data.last_modified) {
                if (!this.isValidISODate(data.last_modified)) {
                    return res.status(400).json({ 
                        error: 'Invalid last_modified timestamp format. Must be ISO 8601 format with Z suffix (e.g., 2024-03-12T12:00:00Z).'
                    });
                }
            }

            if (data.expiry) {
                if (!this.isValidISODate(data.expiry)) {
                    return res.status(400).json({ 
                        error: 'Invalid expiry timestamp format. Must be ISO 8601 format with Z suffix (e.g., 2024-03-19T12:00:00Z).'
                    });
                }
            }

            try {
                const success = await this.setData(data.infohash, data);
                if (success) {
                    res.json({ status: 'success', message: 'Data added successfully' });
                } else {
                    res.status(400).json({ error: 'Invalid data format' });
                }
            } catch (error) {
                console.error('Error in /data POST:', error);
                res.status(500).json({ error: error.message });
            }
        });

        // GET /data/:infohash - Retrieve data by infohash
        this.app.get('/data/:infohash', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            const infohash = req.params.infohash;
            const service = req.query.service; // Optional service parameter

            try {
                const data = await this.getData(infohash);
                if (!data) {
                    return res.status(404).json({ error: 'Data not found' });
                }

                if (service) {
                    // Return data for the specified service only
                    if (data.services[service]) {
                        const serviceData = data.services[service];
                        res.json({
                            total: 1,
                            data: [{
                                infohash: data.infohash,
                                services: {
                                    [service]: serviceData
                                }
                            }],
                            schema_version: "2.0"
                        });
                    } else {
                        res.status(404).json({ error: `Service ${service} not found for this infohash` });
                    }
                } else {
                    // Return data for all services
                    res.json({
                        total: Object.keys(data.services).length,
                        data: [data],
                        schema_version: "2.0"
                    });
                }
            } catch (error) {
                console.error('Error in /data/:infohash GET:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });

        // DELETE /data/:infohash - Invalidate data for infohash, optionally for a specific service
        this.app.delete('/data/:infohash', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            const infohash = req.params.infohash;
            const service = req.query.service; // Optional service parameter

            try {
                const success = await this.invalidateData(infohash, service);
                if (success) {
                    res.json({ 
                        status: 'success', 
                        message: service 
                            ? `Service ${service} invalidated for infohash ${infohash}` 
                            : `Data invalidated for infohash ${infohash}` 
                    });
                } else {
                    res.status(400).json({ error: 'Failed to invalidate data' });
                }
            } catch (error) {
                console.error('Error in /data DELETE:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });

        // Start the server
        this.server = this.app.listen(port, () => {
            console.log(`HTTP server is running on port ${port}`);
        });

        // Handle server errors
        this.server.on('error', (err) => {
            console.error('HTTP server error:', err);
        });
    }
}

// Create and initialize monitor
const monitor = new PhalanxMonitor();

// Initialize the monitor
monitor.initialize().then(success => {
    if (success) {
        console.log('Monitor is running. Press Ctrl+C to exit.');
    } else {
        console.error('Failed to initialize monitor. Exiting.');
        process.exit(1);
    }
});

// Setup graceful shutdown handlers
process.on('SIGINT', () => {
    console.log('\nReceived SIGINT (Ctrl+C). Shutting down gracefully...');
    monitor.cleanup();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\nReceived SIGTERM. Shutting down gracefully...');
    monitor.cleanup();
    process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    monitor.cleanup();
    process.exit(1);
});

// Log startup configuration
console.log('\nMonitor Configuration:');
console.log('====================');
console.log(`Node ID: ${NODE_ID}`);
console.log(`Type: Monitor-only client`);
console.log('\nEncryption Configuration:');
console.log('----------------------');
console.log(`Type: SEA (Security, Encryption, Authorization)`);
console.log(`Algorithm: AES-GCM (via SEA)`);
console.log(`Key Status: ${ENCRYPTION_KEY ? 'Configured' : 'Missing'}`);
console.log(`Encryption: ${ENCRYPTION_KEY ? 'Enabled' : 'Disabled'}`);
console.log('====================\n');

// Export the PhalanxMonitor class
module.exports = PhalanxMonitor;
