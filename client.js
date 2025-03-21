const Gun = require('gun');  // Use standard Gun import
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
        this.startupCount = 0; // Add startup count property
        this.config = {
            isRemoteServer: config.isRemoteServer || false,
            connectToRemote: !config.isRemoteServer && (config.connectToRemote || false),
            port: config.port || 8888,
            peers: [] // Will be populated dynamically
        };
        this.pair = null; // Will store SEA key pair
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

            // Get data count using the graph-based method (Method 2)
            const graph = this.gun._.graph;
            const dataCount = Object.entries(graph).filter(([key, value]) => {
                return key.startsWith('cache/') && 
                       key !== 'cache' && 
                       value !== null && 
                       typeof value === 'object';
            }).length;

            // For valid count, check entries that have either encryptedData or valid services
            const validCount = Object.entries(graph)
                .filter(([key, value]) => {
                    if (!key.startsWith('cache/') || key === 'cache' || !value || typeof value !== 'object') {
                        return false;
                    }
                    // Check if it's an encrypted entry
                    if (value.encryptedData) {
                        return true;
                    }
                    // Check if it has valid services
                    if (value.services && typeof value.services === 'object') {
                        return Object.values(value.services).some(service => {
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
                    }
                    return false;
                }).length;
            
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
                    startup_count: this.startupCount,
                    total: dataCount,
                    valid: validCount,
                    graph_size: Object.keys(graph).length  // Added for verification
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
                
                // For multiple infohashes, fetch them in parallel
                const results = {};
                let completedQueries = 0;
                
                infohashes.forEach(infohash => {
                    this.getData(infohash, (data) => {
                        completedQueries++;
                        
                        if (data) {
                            // If service is specified, filter the services
                            if (service && data.services) {
                                const serviceData = data.services[service];
                                if (serviceData) {
                                    results[infohash] = {
                                        total: 1,
                                        data: [{
                                            infohash: data.infohash,
                                            services: {
                                                [service]: serviceData
                                            }
                                        }],
                                        schema_version: "2.0"
                                    };
                                } else {
                                    results[infohash] = {
                                        total: 0,
                                        data: [],
                                        schema_version: "2.0"
                                    };
                                }
                            } else {
                                // Include all services
                                results[infohash] = {
                                    total: Object.keys(data.services).length,
                                    data: [data],
                                    schema_version: "2.0"
                                };
                            }
                        } else {
                            results[infohash] = {
                                total: 0,
                                data: [],
                                schema_version: "2.0"
                            };
                        }
                        
                        // If all queries are complete, send the response
                        if (completedQueries === infohashes.length) {
                            sendResponse(200, {
                                total_hashes: infohashes.length,
                                results: results,
                                schema_version: "2.0"
                            });
                        }
                    });
                });
                
                // Set a timeout to ensure we don't wait forever
                setTimeout(() => {
                    if (!hasResponded) {
                        sendResponse(408, { error: 'Request timeout while fetching data' });
                    }
                }, 5000); // 5 second timeout
                
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

        // Add test counting endpoint
        this.app.get('/test-count', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            const counts = {
                method1: 0,  // Direct map count
                method2: 0,  // Path-based count
                method3: 0,  // Node traversal count
                timing: {}
            };

            try {
                // Method 1: Direct map count
                const startMethod1 = Date.now();
                await new Promise((resolve) => {
                    let seen = new Set();
                    this.cacheTable.map().on((data, key) => {
                        if (!seen.has(key) && data !== null && data !== undefined) {
                            counts.method1++;
                            seen.add(key);
                        }
                    });
                    
                    // Force resolution after 3 seconds
                    setTimeout(resolve, 3000);
                });
                counts.timing.method1 = Date.now() - startMethod1;

                // Method 2: Path-based count using Gun's back() chain
                const startMethod2 = Date.now();
                const graph = this.gun._.graph;
                const cacheEntries = Object.entries(graph).filter(([key, value]) => {
                    return key.startsWith('cache/') && 
                           key !== 'cache' && 
                           value !== null && 
                           typeof value === 'object';
                });
                counts.method2 = cacheEntries.length;
                
                // Additional graph analysis
                const graphAnalysis = {
                    total_nodes: Object.keys(graph).length,
                    cache_prefix_nodes: cacheEntries.length,
                    root_cache_node: graph['cache'] ? 1 : 0,
                    null_nodes: Object.values(graph).filter(v => v === null).length,
                    non_object_nodes: Object.values(graph).filter(v => v !== null && typeof v !== 'object').length
                };
                counts.timing.method2 = Date.now() - startMethod2;

                // Method 3: Node validation with detailed counting
                const startMethod3 = Date.now();
                const validation = {
                    total_processed: 0,
                    invalid_structure: 0,
                    missing_required_fields: 0,
                    valid_entries: 0
                };
                
                await new Promise((resolve) => {
                    let processed = new Set();
                    this.cacheTable.map().once((data, key) => {
                        validation.total_processed++;
                        
                        if (!processed.has(key) && data !== null) {
                            // Basic structure check
                            if (!data || typeof data !== 'object') {
                                validation.invalid_structure++;
                                return;
                            }
                            
                            // Check for required fields
                            if (!data.encryptedData && !data.services && !data.infohash) {
                                validation.missing_required_fields++;
                                return;
                            }
                            
                            counts.method3++;
                            validation.valid_entries++;
                            processed.add(key);
                        }
                    });
                    
                    // Force resolution after 3 seconds
                    setTimeout(resolve, 3000);
                });
                counts.timing.method3 = Date.now() - startMethod3;

                // Enhanced diagnostics
                const diagnostics = {
                    gun_stats: {
                        graph_size: Object.keys(graph).length,
                        graph_keys: Object.keys(graph).slice(0, 5),
                        graph_analysis: graphAnalysis
                    },
                    cache_table: {
                        exists: !!this.cacheTable,
                        path: this.cacheTable ? this.cacheTable._.path : null
                    },
                    radisk: {
                        enabled: this.gun._.opt.radisk,
                        file: this.gun._.opt.file
                    },
                    validation_details: validation
                };

                res.json({
                    counts,
                    diagnostics,
                    timestamp: new Date().toISOString()
                });

            } catch (error) {
                console.error('Error in test-count endpoint:', error);
                res.status(500).json({ 
                    error: 'Internal server error',
                    details: error.message,
                    partial_counts: counts
                });
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
                file: 'phalanx-db.json',  // File storage location
                radisk: true,             // Enable RAD storage
                localStorage: false,       // Disable localStorage in Node.js
                multicast: false,         // Disable multicast for better performance
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

            // Initialize the cache table
            this.cacheTable = this.gun.get('cache');

            // Get initial count
            console.log('Getting initial database count...');
            this.startupCount = await this.getStartupCount();
            console.log(`Initial database count: ${this.startupCount}`);
            
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
        if (!data || typeof data !== 'object') {
            console.warn('cleanData: Input is not an object');
            return null;
        }
        
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
            console.warn('cleanData: Missing or invalid infohash');
            return null;
        }

        // Initialize services object, preserving existing services if they exist
        cleaned.services = data.services || {};

        // If we're dealing with legacy data (flat structure), convert it to services structure
        if (!data.services) {
            console.log('cleanData: Converting legacy data structure');
            const serviceName = data.provider || data.service || 'default';
            
            // Create the service object
            const serviceObj = {};
            
            // Add service data - only add if it's a valid boolean
            if (data.cached === true || data.cached === false) {
                serviceObj.cached = data.cached;
            } else {
                console.warn('cleanData: Invalid cached status in legacy data');
                return null; // Invalid cached status
            }
            
            // Only add if valid ISO date
            if (data.last_modified && isValidISODate(data.last_modified)) {
                serviceObj.last_modified = data.last_modified;
            } else {
                console.warn('cleanData: Invalid or missing last_modified in legacy data');
                return null; // Invalid or missing last_modified
            }
            
            // Only add if valid ISO date
            if (data.expiry && isValidISODate(data.expiry)) {
                serviceObj.expiry = data.expiry;
            } else {
                console.warn('cleanData: Invalid or missing expiry in legacy data');
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
            console.warn('validateSchema: Invalid data object - not an object');
            return false;
        }
        
        // Check infohash
        if (!data.infohash || typeof data.infohash !== 'string') {
            console.warn('validateSchema: Missing or invalid infohash');
            return false;
        }
        
        // Check for services object
        if (!data.services || typeof data.services !== 'object') {
            console.warn('validateSchema: Missing or invalid services object');
            return false;
        }
        
        // New schema format - verify at least one valid service entry exists
        const serviceNames = Object.keys(data.services);
        if (serviceNames.length === 0) {
            console.warn('validateSchema: No services defined for infohash');
            return false;
        }
        
        // Check if at least one service has valid data
        let hasValidService = false;
        for (const serviceName of serviceNames) {
            const service = data.services[serviceName];
            
            // Check service data structure
            if (!service || typeof service !== 'object') {
                console.warn(`validateSchema: Invalid service object for ${serviceName}`);
                continue;
            }
            
            // Check cached status is a boolean
            if (service.cached !== true && service.cached !== false) {
                console.warn(`validateSchema: Invalid cached status in service ${serviceName}`);
                continue;
            }
            
            // Check last_modified exists and is valid format
            if (!service.last_modified || !isValidISODate(service.last_modified)) {
                console.warn(`validateSchema: Invalid last_modified in service ${serviceName}: ${service.last_modified}`);
                continue;
            }
            
            // Check expiry exists and is valid format
            if (!service.expiry || !isValidISODate(service.expiry)) {
                console.warn(`validateSchema: Invalid expiry in service ${serviceName}: ${service.expiry}`);
                continue;
            }
            
            // This service is valid
            hasValidService = true;
            break;
        }
        
        if (!hasValidService) {
            console.warn('validateSchema: No valid service found for infohash');
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
                        await new Promise(resolve => setTimeout(resolve, 100)); // Reduce retry delay to 100ms
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
        if (!this.gun) {
            console.warn('Gun not initialized');
            callback(null);
            return;
        }

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
                
                callback(cleanedData);
            } catch (error) {
                console.error(`Error processing data for key ${key}:`, error);
                callback(null);
            }
        });
    }

    // Get all data with SEA decryption
    getAllData(callback) {
        if (!this.gun) {
            console.warn('Gun not initialized');
            callback({});
            return;
        }

        const results = {};
        let completed = false;
        let totalProcessed = 0;
        let totalDecrypted = 0;
        let totalValid = 0;

        console.log('Starting getAllData retrieval...');

        // Use Gun's native map().once() to get all data
        this.cacheTable.map().once(async (data, hash) => {
            totalProcessed++;
            console.log(`Processing hash: ${hash}, data present: ${!!data}`);
            
            if (!data) return;
            
            try {
                // Decrypt the data if it's encrypted
                let decryptedData;
                if (data.encryptedData) {
                    decryptedData = await this.decrypt(data);
                    if (!decryptedData) {
                        console.warn(`Failed to decrypt data for hash: ${hash}`);
                        return;
                    }
                    totalDecrypted++;
                    console.log(`Successfully decrypted data for hash: ${hash}`);
                } else {
                    decryptedData = JSON.parse(JSON.stringify(data));
                    console.log(`Non-encrypted data found for hash: ${hash}`);
                }
                
                // Add the hash as infohash if not present
                if (!decryptedData.infohash) {
                    decryptedData.infohash = hash;
                }
                
                // Clean and validate the data
                const cleanedData = this.cleanData(decryptedData);
                if (!cleanedData || !this.validateSchema(cleanedData)) {
                    console.warn(`Invalid data format for hash: ${hash}, cleaned: ${!!cleanedData}, schema valid: ${!!cleanedData && this.validateSchema(cleanedData)}`);
                    return;
                }
                
                totalValid++;
                console.log(`Valid data added for hash: ${hash}`);
                results[hash] = cleanedData;
            } catch (error) {
                console.error(`Error processing data for hash ${hash}:`, error);
            }
        }).then(() => {
            completed = true;
            console.log(`getAllData completed. Total processed: ${totalProcessed}, decrypted: ${totalDecrypted}, valid: ${totalValid}`);
            callback(results);
        });

        // Set a timeout to ensure we don't wait forever
        setTimeout(() => {
            if (!completed) {
                console.warn(`getAllData timeout reached, returning partial results. Processed: ${totalProcessed}, decrypted: ${totalDecrypted}, valid: ${totalValid}`);
                callback(results);
            }
        }, 15000); // Increased to 15 seconds
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
        
        return new Promise(async (resolve) => {
            if (!this.gun) {
                console.warn('Gun not initialized');
                resolve({
                    total: 0,
                    returned: 0,
                    limit,
                    data: [],
                    schema_version: "2.0"
                });
                return;
            }

            try {
                // Get data directly from the graph
                const graph = this.gun._.graph;
                console.log(`Processing graph with ${Object.keys(graph).length} total entries`);

                // Process all entries from the graph
                const processedEntries = await Promise.all(
                    Object.entries(graph)
                        .filter(([key, value]) => {
                            return key.startsWith('cache/') && 
                                   key !== 'cache' && 
                                   value !== null && 
                                   typeof value === 'object';
                        })
                        .map(async ([key, value]) => {
                            const infohash = key.replace('cache/', '');
                            
                            try {
                                // Handle encrypted data
                                if (value.encryptedData) {
                                    const decrypted = await this.decrypt(value);
                                    if (!decrypted) {
                                        console.log(`Failed to decrypt data for ${infohash}`);
                                        return null;
                                    }
                                    value = decrypted;
                                }

                                // Validate and clean the data
                                if (!value || !value.services || typeof value.services !== 'object') {
                                    console.log(`Invalid data structure for ${infohash}`);
                                    return null;
                                }

                                // Process services
                                const validServices = {};
                                let newestTimestamp = 0;

                                Object.entries(value.services).forEach(([serviceName, serviceData]) => {
                                    if (serviceData.cached !== true && serviceData.cached !== false) {
                                        console.log(`Invalid cached status for service ${serviceName} in ${infohash}`);
                                        return;
                                    }
                                    if (!serviceData.last_modified || !isValidISODate(serviceData.last_modified)) {
                                        console.log(`Invalid last_modified for service ${serviceName} in ${infohash}`);
                                        return;
                                    }
                                    if (!serviceData.expiry || !isValidISODate(serviceData.expiry)) {
                                        console.log(`Invalid expiry for service ${serviceName} in ${infohash}`);
                                        return;
                                    }

                                    validServices[serviceName] = serviceData;

                                    const timestamp = new Date(serviceData.last_modified).getTime();
                                    if (timestamp > newestTimestamp) {
                                        newestTimestamp = timestamp;
                                    }
                                });

                                if (Object.keys(validServices).length === 0) {
                                    console.log(`No valid services for ${infohash}`);
                                    return null;
                                }

                                return {
                                    infohash,
                                    services: validServices,
                                    newest_timestamp: newestTimestamp
                                };
                            } catch (error) {
                                console.error(`Error processing entry ${infohash}:`, error);
                                return null;
                            }
                        })
                );

                // Filter out null entries and apply filters
                let filteredEntries = processedEntries.filter(entry => entry !== null);
                console.log(`Found ${filteredEntries.length} valid entries before filtering`);

                // Apply timestamp filters
                if (minTimestamp) {
                    const minTime = new Date(minTimestamp).getTime();
                    filteredEntries = filteredEntries.filter(entry => entry.newest_timestamp >= minTime);
                    console.log(`After minTimestamp filter: ${filteredEntries.length} entries`);
                }
                
                if (maxTimestamp) {
                    const maxTime = new Date(maxTimestamp).getTime();
                    filteredEntries = filteredEntries.filter(entry => entry.newest_timestamp <= maxTime);
                    console.log(`After maxTimestamp filter: ${filteredEntries.length} entries`);
                }
                
                // Apply additional filters
                if (Object.keys(filter).length > 0) {
                    filteredEntries = filteredEntries.filter(entry => {
                        return Object.values(entry.services).some(serviceData => {
                            return Object.entries(filter).every(([key, value]) => {
                                if (key === 'cached' || key === 'last_modified' || key === 'expiry') {
                                    return serviceData[key] === value;
                                }
                                return entry[key] === value;
                            });
                        });
                    });
                    console.log(`After additional filters: ${filteredEntries.length} entries`);
                }

                // Sort by newest timestamp and apply limit
                filteredEntries.sort((a, b) => b.newest_timestamp - a.newest_timestamp);
                const limitedEntries = filteredEntries.slice(0, limit);
                console.log(`After limiting to ${limit}: ${limitedEntries.length} entries`);

                // Remove the temporary newest_timestamp field
                limitedEntries.forEach(entry => {
                    delete entry.newest_timestamp;
                });

                resolve({
                    total: filteredEntries.length,
                    returned: limitedEntries.length,
                    limit,
                    data: limitedEntries,
                    schema_version: "2.0"
                });
            } catch (error) {
                console.error('Error in getFilteredData:', error);
                resolve({
                    total: 0,
                    returned: 0,
                    limit,
                    data: [],
                    schema_version: "2.0",
                    error: error.message
                });
            }
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

    async getStartupCount() {
        return new Promise((resolve) => {
            let count = 0;
            let seen = new Set();
            let completed = false;

            console.log('Starting initial database count...');

            this.cacheTable.map().on((data, key) => {
                if (!seen.has(key) && data !== null && data !== undefined) {
                    count++;
                    seen.add(key);
                }
            });

            // Force resolution after 10 seconds to ensure we get a good initial count
            setTimeout(() => {
                if (!completed) {
                    completed = true;
                    console.log(`Initial count completed: ${count} entries found`);
                    resolve(count);
                }
            }, 10000);
        });
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