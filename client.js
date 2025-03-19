const Gun = require('gun');
require('gun/lib/webrtc');  // Add WebRTC support
require('gun/sea');  // Add SEA support
const express = require('express');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
require('dotenv').config();  // Load environment variables

// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});

// Apply rate limiting to all routes
const app = express();
app.use(limiter);

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
    console.error('ERROR: ENCRYPTION_KEY not found in environment variables');
    process.exit(1);
}

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

// Node identity configuration
const NODE_ID = 'phalanx-db'; // Consistent ID for all nodes in our network

// Helper function to validate ISO date format
function isValidISODate(dateString) {
    if (typeof dateString !== 'string') return false;
    
    // Check if it's an ISO 8601 format and ends with 'Z'
    const isISOFormat = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(dateString);
    
    if (!isISOFormat) return false;
    
    // Check if it's a valid date
    const date = new Date(dateString);
    return !isNaN(date.getTime());
}

class GunNode {
    constructor(config = {}) {
        this.gun = null;
        this.cacheTable = null;
        this.app = express();
        this.setupExpress();
        this.connectedPeers = new Set();
        this.connectedWebRTCPeers = new Set();  // Add new set for WebRTC peers
        this.lastSyncTime = null;
        this.startupTime = new Date(); // Track when this node started
        this.seenEntries = new Set(); // Track entries we've already seen
        this.config = {
            isRemoteServer: config.isRemoteServer || false,
            connectToRemote: !config.isRemoteServer && (config.connectToRemote || false),
            port: config.port || 8888,
            peers: [] // Will be populated dynamically
        };
        this.pair = null; // Will store SEA key pair
        
        // Add a simple in-memory cache for frequently accessed entries
        this.entryCache = new Map();
        this.entryCacheTTL = 60000; // 60 seconds cache TTL
    }

    setupExpress() {
        this.app.use(bodyParser.json());
        
        // Add Gun.js endpoint (protected)
        this.app.use('/gun', authenticateRequest, (req, res) => {
            try {
                if (!this.gun) {
                    return res.status(503).json({ error: 'Gun not initialized' });
                }
                this.gun.web(req, res);
            } catch (error) {
                console.error('Error in /gun endpoint:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });
        
        // Add debug trace endpoint
        this.app.get('/debug-trace/:key', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }
            
            const infohash = req.params.key;
            const trace = {};
            
            // Get raw data directly from Gun
            this.cacheTable.get(infohash).once(async rawData => {
                trace.raw = rawData;
                
                // Add a test object with explicit cached property
                const testObj = {
                    infohash: infohash + "_test",
                    cached: true,
                    service: "test_service",
                    last_modified: new Date().toISOString()
                };
                trace.testInput = testObj;
                
                // Calculate expiry for test object
                const expiryDate = new Date(testObj.last_modified);
                expiryDate.setDate(expiryDate.getDate() + 7);
                testObj.expiry = expiryDate.toISOString();
                trace.testWithExpiry = {...testObj};
                
                // Test encryption
                const encrypted = await this.encrypt(testObj);
                trace.encrypted = encrypted;
                
                // Test decryption
                if (encrypted && encrypted.encryptedData) {
                    try {
                        const decrypted = await this.decrypt(encrypted);
                        trace.decrypted = decrypted;
                    } catch (error) {
                        trace.decryptionError = error.message;
                    }
                }
                
                // Get processed data
                if (rawData) {
                    try {
                        let processed = null;
                        if (rawData.encryptedData) {
                            processed = await this.decrypt(rawData);
                            trace.decryptedActual = processed;
                        } else {
                            processed = rawData;
                            trace.decryptedActual = "Not encrypted";
                        }
                        
                        // Clean the data
                        const cleaned = this.cleanData(processed);
                        trace.cleaned = cleaned;
                    } catch (error) {
                        trace.processingError = error.message;
                    }
                }
                
                res.json(trace);
            });
        });
        
        // Add data endpoint (protected)
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
                if (!isValidISODate(data.last_modified)) {
                    return res.status(400).json({ 
                        error: 'Invalid last_modified timestamp format. Must be ISO 8601 format with Z suffix (e.g., 2024-03-12T12:00:00Z).'
                    });
                }
            }
            
            if (data.expiry) {
                if (!isValidISODate(data.expiry)) {
                    return res.status(400).json({ 
                        error: 'Invalid expiry timestamp format. Must be ISO 8601 format with Z suffix (e.g., 2024-03-12T12:00:00Z).'
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

        // Get all data endpoint (protected and optimized)
        this.app.get('/data', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }
            
            try {
                const result = await this.getFilteredData({
                    limit: parseInt(req.query.limit) || 50, // Increase limit to get more data for sorting
                    filter: req.query.filter || {},
                    minTimestamp: req.query.minTimestamp,
                    maxTimestamp: req.query.maxTimestamp
                });

                // Update schema version to 2.0
                result.schema_version = "2.0";
                // Remove schema_fields as they're now defined by the structure
                delete result.schema_fields;
                
                res.json(result);
            } catch (error) {
                console.error('Error in /data GET:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });

        // Add debug endpoint (protected)
        this.app.get('/debug', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            // Get all peers using gun.back('opt.peers')
            const allPeers = this.gun.back('opt.peers') || {};
            const relayServers = [];
            const webrtcPeers = [];

            // Process peers and categorize them
            Object.entries(allPeers).forEach(([url, peer]) => {
                if (url.startsWith('http')) {
                    relayServers.push(url);
                } else {
                    webrtcPeers.push(url);
                }
            });

            let dataCount = 0;
            let validCount = 0;

            // Get data count using the same validation logic as /data endpoint
            await new Promise((resolve) => {
                this.getAllData((allData) => {
                    dataCount = Object.keys(allData).length;
                    
                    // Count valid entries using the same logic as /data endpoint
                    Object.values(allData).forEach(data => {
                        if (data && data.services && typeof data.services === 'object') {
                            // Check if at least one service has valid data
                            const hasValidService = Object.values(data.services).some(service => {
                                return (
                                    service &&
                                    typeof service === 'object' &&
                                    (service.cached === true || service.cached === false) &&
                                    service.last_modified &&
                                    isValidISODate(service.last_modified) &&
                                    service.expiry &&
                                    isValidISODate(service.expiry)
                                );
                            });
                            
                            if (hasValidService) {
                                validCount++;
                            }
                        }
                    });
                    resolve();
                });
            });
            
            res.json({
                node: {
                    id: NODE_ID,
                    uptime: Math.floor((Date.now() - this.startupTime) / 1000),
                    port: this.config.port
                },
                peers: {
                    relay_servers: relayServers,
                    webrtc_peers: {
                        connected: webrtcPeers.length,
                        peers: webrtcPeers
                    }
                },
                storage: {
                    enabled: this.gun._.opt.file ? true : false,
                    file: this.gun._.opt.file || null
                },
                data: {
                    total: dataCount,
                    valid: validCount
                },
                encryption: {
                    enabled: !!ENCRYPTION_KEY,
                    sea: !!this.pair
                }
            });
        });

        // Get specific data endpoint (protected)
        this.app.get('/data/:infohash', authenticateRequest, async (req, res) => {
            const startTime = Date.now();
            
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            let infohashes;
            if (req.params.infohash.includes(',')) {
                // Handle multiple infohashes
                infohashes = req.params.infohash.split(',').map(hash => hash.trim());
            } else {
                // Single infohash
                infohashes = [req.params.infohash];
            }

            const service = req.query.service;
            
            // Prevent multiple responses
            let hasResponded = false;
            const sendResponse = (statusCode, data) => {
                if (!hasResponded) {
                    hasResponded = true;
                    res.status(statusCode).json(data);
                }
            };
            
            try {
                // For single infohash, use direct lookup
                if (infohashes.length === 1) {
                    this.getData(infohashes[0], (data) => {
                        if (!data) {
                            return sendResponse(404, { error: 'Data not found' });
                        }

                        // If service specified, only include that service
                        if (service && data.services) {
                            const serviceData = data.services[service];
                            if (!serviceData) {
                                return sendResponse(404, { error: 'Service not found for this infohash' });
                            }

                            const result = {
                                total: 1,
                                data: [{
                                    infohash: data.infohash,
                                    services: {
                                        [service]: serviceData
                                    }
                                }],
                                schema_version: "2.0"
                            };
                            return sendResponse(200, result);
                        }

                        // Return full data if no service specified
                        return sendResponse(200, {
                            total: 1,
                            data: [data],
                            schema_version: "2.0"
                        });
                    });
                    return;
                }
                
                // For multiple infohashes or no service specified, use existing getAllData approach
                this.getAllData((allData) => {
                    if (hasResponded) return; // Skip if we've already responded
                    
                    const results = {};
                    
                    infohashes.forEach(infohash => {
                        // Create an empty result structure for this infohash
                        const result = {
                            infohash: infohash,
                            services: {}
                        };
                        
                        // Search for entries with the matching infohash
                        Object.entries(allData).forEach(([key, value]) => {
                            if (key.startsWith(`${infohash}|`)) {
                                // Extract the service name from the key
                                const [_, entryService] = key.split('|');
                                
                                // If service is specified, only include matching service
                                if (!service || service === entryService) {
                                    // Create service data object and validate it
                                    const serviceData = {
                                        cached: value.cached === true || value.cached === false ? value.cached : null,
                                        last_modified: value.last_modified && isValidISODate(value.last_modified) ? value.last_modified : null,
                                        expiry: value.expiry && isValidISODate(value.expiry) ? value.expiry : null
                                    };
                                    
                                    // Only add service if all fields are valid
                                    if (serviceData.cached !== null && 
                                        serviceData.last_modified !== null && 
                                        serviceData.expiry !== null) {
                                        // Add to services object using the service name as key
                                        result.services[entryService] = serviceData;
                                    }
                                }
                            }
                        });
                        
                        // Only include results that have at least one valid service
                        if (Object.keys(result.services).length > 0) {
                            results[infohash] = {
                                total: Object.keys(result.services).length,
                                data: [result],
                                schema_version: "2.0"
                            };
                        } else {
                            // No valid services found for this infohash
                            results[infohash] = {
                                total: 0,
                                data: [],
                                schema_version: "2.0"
                            };
                        }
                    });
                    
                    // If only one infohash was requested, maintain backward compatibility
                    if (infohashes.length === 1) {
                        const singleResult = results[infohashes[0]];
                        if (singleResult.total === 0) {
                            return sendResponse(404, { error: 'Data not found' });
                        }
                        return sendResponse(200, singleResult);
                    }
                    
                    sendResponse(200, {
                        total_hashes: infohashes.length,
                        results: results,
                        schema_version: "2.0"
                    });
                });
            } catch (error) {
                console.error('Error in /data/:infohash endpoint:', error);
                sendResponse(500, { error: 'Internal server error' });
            }
        });

        // Add invalidate data endpoint (protected)
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
                res.status(500).json({ error: error.message });
            }
        });
    }

    async initialize() {
        try {
            // Initialize encryption first
            await this.initializeEncryption();
            
            // Create a server for this node
            const port = this.config.port;
            const server = this.app.listen(port, () => {
                console.log(`Node running on port ${port}`);
            });

            // Initialize Gun with basic configuration
            this.gun = Gun({
                web: server,
                peers: this.config.peers,
                file: 'node-data.json',
                radisk: true,
                multicast: false,
                retry: 2000,
                pid: NODE_ID,
                super: this.config.isRemoteServer,
                sea: true,
                axe: false,
                rtcConfig: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun1.l.google.com:19302' },
                        { urls: 'stun2.l.google.com:19302' },
                        {
                            urls: 'turn:openrelay.metered.ca:443',
                            username: 'openrelayproject',
                            credential: 'openrelayproject'
                        }
                    ]
                }
            });

            // Track peer connections
            this.gun.on('hi', peer => {
                const peerUrl = peer.url || peer.id;
                
                // Check if this is a WebRTC peer
                if (peer.url && peer.url.startsWith('http')) {
                    // This is a relay server
                    this.connectedPeers.add(peerUrl);
                } else {
                    // This is likely a WebRTC peer
                    this.connectedWebRTCPeers.add(peerUrl);
                }
            });

            this.gun.on('bye', peer => {
                const peerUrl = peer.url || peer.id;
                
                // Remove from both sets (only one removal will actually happen)
                this.connectedPeers.delete(peerUrl);
                this.connectedWebRTCPeers.delete(peerUrl);
            });

            // Initialize the cache table
            this.cacheTable = this.gun.get('cache');
            
            console.log('Node initialized successfully');
            return true;
        } catch (error) {
            console.error('Failed to initialize node:', error);
            return false;
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

    // Clean data object by removing Gun.js metadata
    cleanData(data) {
        if (!data || typeof data !== 'object') return null;
        
        // Create a new object structure with services nested
        const cleaned = {
            infohash: data.infohash
        };

        // If infohash contains a service suffix, extract just the infohash part
        if (cleaned.infohash && cleaned.infohash.includes('|')) {
            cleaned.infohash = cleaned.infohash.split('|')[0];
        }

        // Return null if no valid infohash
        if (!cleaned.infohash || typeof cleaned.infohash !== 'string') {
            return null;
        }

        // Initialize services object, preserving existing services if they exist
        cleaned.services = data.services || {};

        // If we're dealing with legacy data (flat structure), convert it to services structure
        if (!data.services) {
            const serviceName = data.provider || data.service || 'default';
            
            // Create the service object
            const serviceObj = {};
            
            // Add service data - only add if it's a valid boolean
            if (data.cached === true || data.cached === false) {
                serviceObj.cached = data.cached;
            } else {
                return null; // Invalid cached status
            }
            
            // Only add if valid ISO date
            if (data.last_modified && isValidISODate(data.last_modified)) {
                serviceObj.last_modified = data.last_modified;
            } else {
                return null; // Invalid or missing last_modified
            }
            
            // Only add if valid ISO date
            if (data.expiry && isValidISODate(data.expiry)) {
                serviceObj.expiry = data.expiry;
            } else {
                return null; // Invalid or missing expiry
            }
            
            // Add the service object to the services property
            cleaned.services[serviceName] = serviceObj;
        }

        return cleaned;
    }

    // Validate and fix schema to ensure all required fields are present
    validateAndFixSchema(data) {
        // Check if we already have a nested services structure
        if (data.services && typeof data.services === 'object') {
            // New format - validate and fix services
            const serviceNames = Object.keys(data.services);
            
            // Ensure at least one service exists
            if (serviceNames.length === 0) {
                data.services.default = {
                    cached: false,
                    last_modified: new Date().toISOString(),
                    expiry: null
                };
            }
            
            // Validate each service
            for (const serviceName of serviceNames) {
                const service = data.services[serviceName];
                
                // Ensure service is an object
                if (!service || typeof service !== 'object') {
                    data.services[serviceName] = {
                        cached: false,
                        last_modified: new Date().toISOString(),
                        expiry: null
                    };
                    continue;
                }
                
                // Ensure cached status exists as a boolean
                if (service.cached !== true && service.cached !== false) {
                    console.warn(`Missing or invalid cached status in service ${serviceName}`);
                    service.cached = false;
                }
                
                // Ensure last_modified exists and is valid
                if (!service.last_modified) {
                    console.warn(`Missing last_modified in service ${serviceName}`);
                    service.last_modified = new Date().toISOString();
                } else if (!isValidISODate(service.last_modified)) {
                    console.warn(`Invalid last_modified timestamp format in service ${serviceName}: ${service.last_modified}`);
                    service.last_modified = new Date().toISOString();
                }
                
                // Ensure expiry exists and is valid
                if (!service.expiry) {
                    console.warn(`Missing expiry in service ${serviceName}, calculating based on cached status`);
                    const expiryDate = new Date(service.last_modified);
                    if (service.cached === true) {
                        expiryDate.setDate(expiryDate.getDate() + 7); // 7 days for cached=true
                    } else {
                        expiryDate.setHours(expiryDate.getHours() + 24); // 24 hours for cached=false
                    }
                    service.expiry = expiryDate.toISOString();
                } else if (!isValidISODate(service.expiry)) {
                    console.warn(`Invalid expiry timestamp format in service ${serviceName}: ${service.expiry}`);
                    const expiryDate = new Date(service.last_modified);
                    if (service.cached === true) {
                        expiryDate.setDate(expiryDate.getDate() + 7);
                    } else {
                        expiryDate.setHours(expiryDate.getHours() + 24);
                    }
                    service.expiry = expiryDate.toISOString();
                }
            }
            
            return data;
        }
        
        // Legacy format - transform to new format while validating
        
        // Ensure infohash exists
        if (!data.infohash) {
            console.warn('Missing infohash in data object');
            data.infohash = 'unknown_' + Date.now();
        }

        // Extract service name or use default
        const serviceName = data.service || 'default';

        // Create services structure
        const serviceData = {
            cached: data.cached === true || data.cached === false ? data.cached : false
        };
        
        // Ensure last_modified exists and is valid
        if (!data.last_modified) {
            console.warn('Missing last_modified in data object');
            serviceData.last_modified = new Date().toISOString();
        } else if (!isValidISODate(data.last_modified)) {
            console.warn(`Invalid last_modified timestamp format: ${data.last_modified}`);
            serviceData.last_modified = new Date().toISOString();
        } else {
            serviceData.last_modified = data.last_modified;
        }

        // Ensure expiry exists and is valid
        if (!data.expiry) {
            console.warn('Missing expiry in data object, calculating based on cached status');
            const expiryDate = new Date(serviceData.last_modified);
            if (serviceData.cached === true) {
                expiryDate.setDate(expiryDate.getDate() + 7); // 7 days for cached=true
            } else {
                expiryDate.setHours(expiryDate.getHours() + 24); // 24 hours for cached=false
            }
            serviceData.expiry = expiryDate.toISOString();
        } else if (!isValidISODate(data.expiry)) {
            console.warn(`Invalid expiry timestamp format: ${data.expiry}`);
            const expiryDate = new Date(serviceData.last_modified);
            if (serviceData.cached === true) {
                expiryDate.setDate(expiryDate.getDate() + 7);
            } else {
                expiryDate.setHours(expiryDate.getHours() + 24);
            }
            serviceData.expiry = expiryDate.toISOString();
        } else {
            serviceData.expiry = data.expiry;
        }

        // Create new object with nested services
        const transformedData = {
            infohash: data.infohash,
            services: {
                [serviceName]: serviceData
            }
        };

        return transformedData;
    }

    // Validate schema without fixing issues - just returns true/false
    validateSchema(data) {
        // Check if all required fields exist and are valid
        if (!data || typeof data !== 'object') {
            console.warn('Invalid data object');
            return false;
        }
        
        // Check infohash
        if (!data.infohash || typeof data.infohash !== 'string') {
            console.warn('Missing or invalid infohash in data object');
            return false;
        }
        
        // Check for services object
        if (!data.services || typeof data.services !== 'object') {
            console.warn('Missing or invalid services object');
            return false;
        }
        
        // New schema format - verify at least one valid service entry exists
        const serviceNames = Object.keys(data.services);
        if (serviceNames.length === 0) {
            console.warn('No services defined for infohash');
            return false;
        }
        
        // Check if at least one service has valid data
        let hasValidService = false;
        for (const serviceName of serviceNames) {
            const service = data.services[serviceName];
            
            // Check service data structure
            if (!service || typeof service !== 'object') continue;
            
            // Check cached status is a boolean
            if (service.cached !== true && service.cached !== false) {
                console.warn(`Invalid cached status in service ${serviceName}`);
                continue;
            }
            
            // Check last_modified exists and is valid format
            if (!service.last_modified || !isValidISODate(service.last_modified)) {
                console.warn(`Invalid last_modified in service ${serviceName}`);
                continue;
            }
            
            // Check expiry exists and is valid format
            if (!service.expiry || !isValidISODate(service.expiry)) {
                console.warn(`Invalid expiry in service ${serviceName}`);
                continue;
            }
            
            // This service is valid
            hasValidService = true;
            break;
        }
        
        if (!hasValidService) {
            console.warn('No valid service found for infohash');
            return false;
        }
        
        // All checks passed
        return true;
    }

    // Encryption utilities using SEA
    async encrypt(data) {
        try {
            if (!this.pair) {
                throw new Error('Encryption not initialized');
            }
            
            // Convert data to string if it's an object
            const dataStr = typeof data === 'object' ? JSON.stringify(data) : data;
            
            // Add retry logic for encryption
            let retries = 3;
            let encrypted = null;
            let lastError = null;
            
            while (retries > 0 && !encrypted) {
                try {
                    // Encrypt using SEA
                    encrypted = await Gun.SEA.encrypt(dataStr, ENCRYPTION_KEY);
                    break;
                } catch (error) {
                    lastError = error;
                    retries--;
                    if (retries > 0) {
                        console.warn(`Encryption failed, retrying... (${retries} attempts left)`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
            }
            
            if (!encrypted) {
                throw new Error(`Failed to encrypt data after multiple attempts: ${lastError}`);
            }
            
            return {
                encryptedData: encrypted,
                last_modified: data.last_modified || new Date().toISOString()
            };
        } catch (error) {
            console.error('SEA encryption error:', error);
            return null;
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

            // Add retry logic for decryption
            let retries = 3;
            let decrypted = null;
            let lastError = null;
            
            while (retries > 0 && !decrypted) {
                try {
                    // Decrypt using SEA
                    decrypted = await Gun.SEA.decrypt(data.encryptedData, ENCRYPTION_KEY);
                    break;
                } catch (error) {
                    lastError = error;
                    retries--;
                    if (retries > 0) {
                        console.warn(`Decryption failed, retrying... (${retries} attempts left)`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
            }
            
            if (!decrypted) {
                throw new Error(`Failed to decrypt data after multiple attempts: ${lastError}`);
            }
            
            // Parse the decrypted data if it was originally an object
            try {
                const parsed = JSON.parse(decrypted);
                return this.cleanData(parsed);
            } catch {
                return decrypted;
            }
        } catch (error) {
            console.error('SEA decryption error:', error);
            return null;
        }
    }

    // Get data with SEA decryption
    async getData(key, callback) {
        const startTime = Date.now();
        
        // Check the cache first
        if (this.entryCache.has(key)) {
            const cachedEntry = this.entryCache.get(key);
            // Check if the cached entry is still valid
            if (Date.now() < cachedEntry.expiry) {
                // Validate the cached data
                if (this.validateSchema(cachedEntry.data)) {
                    callback(cachedEntry.data);
                    return;
                } else {
                    // Remove invalid entry from cache
                    this.entryCache.delete(key);
                }
            } else {
                // Remove expired entry
                this.entryCache.delete(key);
            }
        }
        
        // Proceed with normal retrieval if not in cache
        this.cacheTable.get(key).once(async (data) => {
            if (!data) {
                callback(null);
                return;
            }

            try {
                // Decrypt the data if it's encrypted
                let decryptedData;
                if (data.encryptedData) {
                    decryptedData = await this.decrypt(data);
                    if (!decryptedData) {
                        console.warn(`Failed to decrypt data for key: ${key}`);
                        callback(null);
                        return;
                    }
                } else {
                    // Make a copy of the raw data for legacy support
                    decryptedData = JSON.parse(JSON.stringify(data));
                }
                
                // Add the infohash if not present
                if (!decryptedData.infohash) {
                    decryptedData.infohash = key;
                }
                
                // Clean the data before returning
                const cleanedData = this.cleanData(decryptedData);
                
                // Only proceed if we have valid data
                if (!cleanedData || !this.validateSchema(cleanedData)) {
                    console.warn(`Invalid data format for key: ${key}`);
                    callback(null);
                    return;
                }
                
                // Store in cache
                this.entryCache.set(key, {
                    data: cleanedData,
                    expiry: Date.now() + this.entryCacheTTL
                });
                
                callback(cleanedData);
            } catch (error) {
                console.error(`Error processing data for key ${key}:`, error);
                callback(null);
            }
        });
    }

    // Get all data with SEA decryption
    getAllData(callback) {
        const allData = {};
        let receivedCount = 0;
        let lastReceived = Date.now();
        let pendingDecryptions = 0;
        
        // Set a timeout to ensure we don't wait forever
        const maxWaitTime = 3000; // 3 seconds max wait
        const startTime = Date.now();
        
        // We'll consider data collection complete if no new data 
        // has been received for 500ms, or we hit the max wait time,
        // and all decryptions are complete
        const checkComplete = () => {
            const now = Date.now();
            if (((now - lastReceived > 500 && receivedCount > 0) || (now - startTime > maxWaitTime)) && pendingDecryptions === 0) {
                callback(allData);
                return true;
            }
            return false;
        };
        
        const intervalId = setInterval(() => {
            if (checkComplete()) {
                clearInterval(intervalId);
            }
        }, 500);
        
        this.cacheTable.map().once(async (data, hash) => {
            if (data) {
                try {
                    pendingDecryptions++;
                    // Decrypt the data if it's encrypted
                    let decryptedData;
                    if (data.encryptedData) {
                        decryptedData = await this.decrypt(data);
                        if (!decryptedData) {
                            console.warn(`Failed to decrypt data for hash: ${hash}`);
                            pendingDecryptions--;
                            return;
                        }
                    } else {
                        // Make a copy of the raw data for legacy support
                        decryptedData = JSON.parse(JSON.stringify(data));
                    }
                    
                    // Add the hash as infohash if not present
                    if (!decryptedData.infohash) {
                        decryptedData.infohash = hash;
                    }
                    
                    allData[hash] = decryptedData;
                    receivedCount++;
                    lastReceived = Date.now();
                } catch (error) {
                    console.error(`Error processing data for hash ${hash}:`, error);
                } finally {
                    pendingDecryptions--;
                    // Check if we're done after this decryption
                    if (checkComplete()) {
                        clearInterval(intervalId);
                    }
                }
            }
        });
    }

    // Set data with SEA encryption
    async setData(infohash, data) {
        // First get existing data if any
        const existingData = await new Promise((resolve) => {
            this.getData(infohash, (result) => {
                resolve(result);
            });
        });

        // Extract the service name (default to 'default' if not specified)
        const serviceName = data.provider || data.service || 'default';
        
        // Create or update the data object with nested services structure
        const processedData = {
            infohash: infohash,
            services: existingData ? {...existingData.services} : {}
        };
        
        // Create the service data object
        const serviceData = {
            cached: data.cached === true || data.cached === false ? data.cached : false,
            last_modified: data.last_modified || new Date().toISOString()
        };
        
        // Handle timestamp formatting
        if (!serviceData.last_modified.endsWith('Z')) {
            serviceData.last_modified = new Date(serviceData.last_modified).toISOString();
        }
        
        // Directly use expiry if provided, otherwise calculate based on cached
        if (data.expiry) {
            serviceData.expiry = data.expiry.endsWith('Z') 
                ? data.expiry 
                : new Date(data.expiry).toISOString();
        } else if (serviceData.cached === true) {
            // Only calculate if not provided
            const expiryDate = new Date(serviceData.last_modified);
            expiryDate.setDate(expiryDate.getDate() + 7); // 7 days for cached=true
            serviceData.expiry = expiryDate.toISOString();
        } else {
            // Only calculate if not provided
            const expiryDate = new Date(serviceData.last_modified);
            expiryDate.setHours(expiryDate.getHours() + 24); // 24 hours for cached=false
            serviceData.expiry = expiryDate.toISOString();
        }

        // Add or update the service data in the nested structure
        processedData.services[serviceName] = serviceData;

        // Update or invalidate the cache for this infohash
        if (this.entryCache.has(infohash)) {
            // Remove from cache - we'll update it on next retrieval
            this.entryCache.delete(infohash);
            console.log(`Cache entry invalidated for infohash: ${infohash} (data updated)`);
        }

        // Encrypt the processed data
        const encryptedData = await this.encrypt(processedData);
        if (!encryptedData) {
            console.error('Failed to encrypt data');
            return false;
        }

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
    }

    // Get filtered data (simplified)
    async getFilteredData(options = {}) {
        const { limit = 50, minTimestamp, maxTimestamp, filter = {} } = options;
        
        return new Promise((resolve) => {
            this.getAllData((allData) => {
                // Process all data entries
                const processedEntries = Object.entries(allData)
                    .map(([infohash, data]) => {
                        // Skip if no services or invalid data
                        if (!data || !data.services || typeof data.services !== 'object') {
                            return null;
                        }

                        // Process each service entry
                        const validServices = {};
                        let newestTimestamp = 0;

                        Object.entries(data.services).forEach(([serviceName, serviceData]) => {
                            // Validate service data
                            if (serviceData.cached !== true && serviceData.cached !== false) return;
                            if (!serviceData.last_modified || !isValidISODate(serviceData.last_modified)) return;
                            if (!serviceData.expiry || !isValidISODate(serviceData.expiry)) return;

                            // Add valid service data
                            validServices[serviceName] = serviceData;

                            // Track newest timestamp
                            const timestamp = new Date(serviceData.last_modified).getTime();
                            if (timestamp > newestTimestamp) {
                                newestTimestamp = timestamp;
                            }
                        });

                        // Skip if no valid services
                        if (Object.keys(validServices).length === 0) {
                            return null;
                        }

                        return {
                            infohash,
                            services: validServices,
                            newest_timestamp: newestTimestamp
                        };
                    })
                    .filter(entry => entry !== null); // Remove invalid entries

                // Apply timestamp filters if provided
                let filteredEntries = processedEntries;
                if (minTimestamp) {
                    filteredEntries = filteredEntries.filter(entry => 
                        entry.newest_timestamp >= new Date(minTimestamp).getTime()
                    );
                }
                
                if (maxTimestamp) {
                    filteredEntries = filteredEntries.filter(entry => 
                        entry.newest_timestamp <= new Date(maxTimestamp).getTime()
                    );
                }
                
                // Apply any additional filter properties
                if (Object.keys(filter).length > 0) {
                    filteredEntries = filteredEntries.filter(entry => {
                        // For service-specific filters, check all services
                        return Object.values(entry.services).some(serviceData => {
                            return Object.entries(filter).every(([key, value]) => {
                                if (key === 'cached' || key === 'last_modified' || key === 'expiry') {
                                    return serviceData[key] === value;
                                }
                                return entry[key] === value;
                            });
                        });
                    });
                }

                // Sort by newest timestamp and apply limit
                filteredEntries.sort((a, b) => b.newest_timestamp - a.newest_timestamp);
                filteredEntries = filteredEntries.slice(0, limit);

                // Remove the temporary newest_timestamp field
                filteredEntries.forEach(entry => {
                    delete entry.newest_timestamp;
                });

                resolve({
                    total: filteredEntries.length,
                    limit,
                    data: filteredEntries,
                    schema_version: "2.0"
                });
            });
        });
    }

    // Invalidate specific infohash data
    async invalidateData(infohash, service = null) {
        try {
            if (!infohash) {
                throw new Error('Infohash is required');
            }

            // If service is specified, only invalidate that service
            if (service) {
                // Get existing data first
                const existingData = await new Promise((resolve) => {
                    this.getData(infohash, (result) => {
                        resolve(result);
                    });
                });

                if (existingData && existingData.services) {
                    // Remove only the specified service
                    if (existingData.services[service]) {
                        delete existingData.services[service];
                        
                        // If there are still other services, update the data
                        if (Object.keys(existingData.services).length > 0) {
                            return await this.setData(infohash, existingData);
                        }
                    }
                }
            }

            // Remove from local cache if present
            if (this.entryCache.has(infohash)) {
                this.entryCache.delete(infohash);
                console.log(`Cache entry invalidated for infohash: ${infohash}`);
            }

            // Use Gun's null operation to remove the data
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
        } catch (error) {
            console.error('Error in invalidateData:', error);
            return false;
        }
    }
}

// Parse command line arguments
const args = process.argv.slice(2);
const nodeType = args[0] || 'local';  // Default to local if no argument
const port = args[1] || 8888;  // Optional port argument

// Configure node based on type
const config = {
    isRemoteServer: nodeType === 'remote',
    connectToRemote: nodeType === 'local',
    port: parseInt(port)
};

// Create and initialize node
const node = new GunNode(config);

// Initialize relay discovery
const initializeRelays = async () => {
    try {
        // Import gun-relays dynamically
        const { default: Relays, forceListUpdate } = await import('gun-relays');
        
        // Get initial relay list
        const relays = await Relays();
        node.config.peers = relays;
        
        // Initialize node after relay discovery
        await node.initialize();
        
    } catch (err) {
        console.error('Error initializing relays:', err);
        // Fallback to local node only if relay discovery fails
        await node.initialize();
    }
};

initializeRelays();

// Log startup configuration
console.log('\nNode Configuration:');
console.log('==================');
console.log(`Node ID: ${NODE_ID}`);
console.log(`Mode: ${config.isRemoteServer ? 'Remote Server' : 'Local Client'}`);
console.log(`Port: ${config.port}`);
console.log(`Peer Discovery: Enabled (using gun-relays)`);
console.log('\nEncryption Configuration:');
console.log('----------------------');
console.log(`Type: SEA (Security, Encryption, Authorization)`);
console.log(`Algorithm: AES-GCM (via SEA)`);
console.log(`Key Status: ${ENCRYPTION_KEY ? 'Configured' : 'Missing'}`);
console.log(`Encryption: ${ENCRYPTION_KEY ? 'Enabled' : 'Disabled'}`);
console.log('==================\n');