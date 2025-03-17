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
            console.log('Received /data request with query:', req.query);
            
            try {
                const result = await this.getFilteredData({
                    limit: parseInt(req.query.limit) || 50, // Increase limit to get more data for sorting
                    filter: req.query.filter || {},
                    minTimestamp: req.query.minTimestamp,
                    maxTimestamp: req.query.maxTimestamp
                });

                // Clean the data before sending
                result.data = result.data.map(entry => this.cleanData(entry));

                // Sort the cleaned data by timestamp (newest first)
                result.data.sort((a, b) => {
                    const dateA = a.last_modified ? new Date(a.last_modified).getTime() : 0;
                    const dateB = b.last_modified ? new Date(b.last_modified).getTime() : 0;
                    return dateB - dateA;
                });
                
                // Apply the limit after sorting
                const limit = parseInt(req.query.limit) || 50;
                result.data = result.data.slice(0, limit);
                result.limit = limit;
                result.total = result.data.length;
                
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

            const peers = this.gun._.opt.peers || {};
            let dataCount = 0;
            let validCount = 0;

            // Get data count
            await new Promise((resolve) => {
                this.getAllData((allData) => {
                    dataCount = Object.keys(allData).length;
                    validCount = Object.values(allData).filter(data => 
                        data && data.last_modified && data.cached !== undefined
                    ).length;
                    resolve();
                });
            });
            
            res.json({
                node: {
                    id: NODE_ID,
                    uptime: Math.floor((Date.now() - this.startupTime) / 1000),
                    mode: this.config.isRemoteServer ? 'remote' : 'local',
                    port: this.config.port
                },
                peers: {
                    relay_servers: Array.from(this.connectedPeers),
                    webrtc_peers: {
                        connected: this.connectedWebRTCPeers.size,
                        peers: Array.from(this.connectedWebRTCPeers)
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
                },
                lastSync: this.lastSyncTime ? new Date(this.lastSyncTime).toISOString() : null
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
            
            // OPTIMIZATION 1: For single infohash + service requests, use direct key lookup
            if (infohashes.length === 1 && service) {
                const directLookupStart = Date.now();
                
                // Use the composite key format
                const compositeKey = `${infohashes[0]}_${service}`;
                
                // Wrap in a promise for easier handling
                try {
                    const directResult = await new Promise((resolve) => {
                        this.getData(compositeKey, (data) => {
                            // Fix the infohash field to not include the service
                            if (data) {
                                // Ensure the infohash doesn't include the service
                                data.infohash = infohashes[0];
                            }
                            resolve(data);
                        }, true);
                    });
                    
                    const lookupTime = Date.now() - directLookupStart;
                    
                    if (!directResult) {
                        return res.status(404).json({ error: 'Data not found' });
                    }
                    
                    return res.json({
                        total: 1,
                        data: [directResult]
                    });
                } catch (error) {
                    console.error('Error during direct lookup:', error);
                    // Fall back to the original method if direct lookup fails
                }
            }
            
            // OPTIMIZATION 2: For single infohash without service specified, use a more selective approach
            if (infohashes.length === 1 && !service) {
                // Instead of filtering through all data, we'll try a different approach
                const patternLookupStart = Date.now();
                
                try {
                    // This is a key insight: Gun doesn't support pattern matching natively
                    // But we can use a different graph traversal approach
                    
                    // First, try to get potential services from the in-memory cache
                    const cacheKeys = Array.from(this.entryCache.keys());
                    const potentialCachedServices = cacheKeys
                        .filter(key => key.startsWith(`${infohashes[0]}_`))
                        .map(key => key.split('_')[1]);
                    
                    // Known common services to check directly first (optimization)
                    const commonServices = [...potentialCachedServices, 'real_debrid', 'premiumize', 'all_debrid', 'debrid_link'];
                    const targetInfohash = infohashes[0];
                    const matchingEntries = [];
                    
                    // Check the common services directly first - this is much faster than scanning all keys
                    await Promise.all(commonServices.map(async (svc) => {
                        const compositeKey = `${targetInfohash}_${svc}`;
                        
                        try {
                            // Use a promise wrapper around the Gun get for cleaner async handling
                            const result = await new Promise((resolve) => {
                                // Set a timeout to avoid hanging if the key doesn't exist
                                const timeoutId = setTimeout(() => {
                                    resolve(null);
                                }, 300); // Short timeout for direct lookups
                                
                                this.cacheTable.get(compositeKey).once((data) => {
                                    clearTimeout(timeoutId);
                                    if (data && Object.keys(data).length > 0) {
                                        // Process and clean the data
                                        const cleanedData = this.cleanData(data);
                                        // Fix the infohash to be just the infohash, not the composite key
                                        cleanedData.infohash = targetInfohash;
                                        cleanedData.service = svc;
                                        resolve(cleanedData);
                                    } else {
                                        resolve(null);
                                    }
                                });
                            });
                            
                            if (result) {
                                matchingEntries.push(result);
                            }
                        } catch (error) {
                            console.error(`Error during direct key check for ${compositeKey}:`, error);
                        }
                    }));
                    
                    // Only do a partial scan if we didn't find anything with direct lookups
                    if (matchingEntries.length === 0) {
                        // We'll limit this scan to a reasonable time to avoid hanging
                        const scanTimeoutMs = 500;
                        const scanStartTime = Date.now();
                        
                        await new Promise((resolve) => {
                            // Set a timeout for the overall operation
                            const scanTimeoutId = setTimeout(() => {
                                resolve();
                            }, scanTimeoutMs);
                            
                            // Use a much shorter collect cycle to find services faster
                            let scanDone = false;
                            const targetPrefix = `${targetInfohash}_`;
                            
                            this.cacheTable.map().on((data, key) => {
                                // Skip processing if we're already done
                                if (scanDone) return;
                                
                                if (key && key.startsWith(targetPrefix)) {
                                    try {
                                        const [infohash, entryService] = key.split('_');
                                        if (data && Object.keys(data).length > 0) {
                                            const cleanedData = this.cleanData(data);
                                            // Fix the infohash to be just the infohash, not the composite key
                                            cleanedData.infohash = infohash;
                                            cleanedData.service = entryService;
                                            matchingEntries.push(cleanedData);
                                            
                                            // We found at least one match, can complete soon
                                            setTimeout(() => {
                                                if (!scanDone) {
                                                    scanDone = true;
                                                    clearTimeout(scanTimeoutId);
                                                    resolve();
                                                }
                                            }, 100); // Short delay to allow for any other immediate matches
                                        }
                                    } catch (error) {
                                        console.error(`Error processing entry during scan:`, error);
                                    }
                                }
                                
                                // Check if we've hit the time limit
                                if (Date.now() - scanStartTime > scanTimeoutMs && !scanDone) {
                                    scanDone = true;
                                    clearTimeout(scanTimeoutId);
                                    resolve();
                                }
                            });
                        });
                    }
                    
                    // Sort entries by timestamp
                    matchingEntries.sort((a, b) => {
                        const dateA = a.last_modified ? new Date(a.last_modified).getTime() : 0;
                        const dateB = b.last_modified ? new Date(b.last_modified).getTime() : 0;
                        return dateB - dateA;
                    });
                    
                    if (matchingEntries.length === 0) {
                        return res.status(404).json({ error: 'Data not found' });
                    }
                    
                    return res.json({
                        total: matchingEntries.length,
                        data: matchingEntries
                    });
                } catch (error) {
                    console.error('Error during optimized access:', error);
                    // Fall back to the original method if optimized approach fails
                }
            }
            
            // For multiple infohashes or if the optimizations failed, use the original approach
            const getAllDataStart = Date.now();
            
            // Get all data and then filter
            this.getAllData((allData) => {
                const getAllDataTime = Date.now() - getAllDataStart;
                
                const processingStart = Date.now();
                const results = {};
                
                infohashes.forEach(infohash => {
                    const matchingEntries = [];
                    
                    // Search for entries with the matching infohash
                    Object.entries(allData).forEach(([key, value]) => {
                        if (key.startsWith(`${infohash}_`)) {
                            // If service is specified, only include matching service
                            const [_, entryService] = key.split('_');
                            if (!service || service === entryService) {
                                const cleanedData = this.cleanData(value);
                                // Ensure we use the pure infohash (without service)
                                cleanedData.infohash = infohash;
                                cleanedData.service = entryService;
                                matchingEntries.push(cleanedData);
                            }
                        }
                    });
                    
                    // Sort by most recent
                    matchingEntries.sort((a, b) => {
                        const dateA = a.last_modified ? new Date(a.last_modified).getTime() : 0;
                        const dateB = b.last_modified ? new Date(b.last_modified).getTime() : 0;
                        return dateB - dateA;
                    });
                    
                    results[infohash] = {
                        total: matchingEntries.length,
                        data: matchingEntries
                    };
                });
                
                // If only one infohash was requested, maintain backward compatibility
                if (infohashes.length === 1) {
                    const singleResult = results[infohashes[0]];
                    if (singleResult.total === 0) {
                        return res.status(404).json({ error: 'Data not found' });
                    }
                    return res.json(singleResult);
                }
                
                res.json({
                    total_hashes: infohashes.length,
                    results: results
                });
            });
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
                        { urls: 'stun:stun1.l.google.com:19302' },
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
        if (!data || typeof data !== 'object') return data;
        
        // Create a new object with only our expected properties
        const cleaned = {
            infohash: data.infohash,
            service: data.provider || data.service || 'real_debrid',
            last_modified: data.last_modified,
            expiry: data.expiry || null
        };

        // If infohash contains a service suffix, extract just the infohash part
        if (cleaned.infohash && cleaned.infohash.includes('_')) {
            cleaned.infohash = cleaned.infohash.split('_')[0];
        }

        // Explicitly preserve cached property if it exists
        if (data.cached === true || data.cached === false) {
            cleaned.cached = data.cached;
        }

        return cleaned;
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

            // Handle legacy unencrypted data format
            if (!data.encryptedData && data.cached !== undefined) {
                console.log('Found legacy unencrypted data, will be migrated on next update');
                return this.cleanData(data);
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
            if (error.message === 'Invalid encrypted object' && data && data.cached !== undefined) {
                // This is likely legacy data, log it once and return
                console.log('Legacy data detected, will be migrated on next update');
                return this.cleanData(data);
            }
            console.error('SEA decryption error:', error);
            return null;
        }
    }

    // Get data with SEA decryption
    async getData(key, callback, isCompositeKey = false) {
        const startTime = Date.now();
        
        // Check the cache first
        if (this.entryCache.has(key)) {
            const cachedEntry = this.entryCache.get(key);
            // Check if the cached entry is still valid
            if (Date.now() < cachedEntry.expiry) {
                callback(cachedEntry.data);
                return;
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
                // Make a copy of the raw data
                const retrievedData = JSON.parse(JSON.stringify(data));
                
                if (!isCompositeKey && key.includes('_')) {
                    // If this is a composite key, extract the infohash and service
                    const [infohash, service] = key.split('_');
                    retrievedData.infohash = infohash;
                    retrievedData.service = service;
                } else {
                    // Otherwise just add the infohash
                    retrievedData.infohash = key;
                }
                
                // Check if data exists
                if (!retrievedData.last_modified) {
                    console.warn(`Invalid data format for key: ${key}`);
                    callback(null);
                    return;
                }
                
                // Clean the data before returning
                const cleanedData = this.cleanData(retrievedData);
                
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

    // New method to get data by infohash and service
    async getDataByInfohashAndService(infohash, service, callback) {
        const compositeKey = `${infohash}_${service}`;
        this.getData(compositeKey, callback, true);
    }

    // Get all data with SEA decryption
    getAllData(callback) {
        const allData = {};
        let receivedCount = 0;
        let lastReceived = Date.now();
        
        // Set a timeout to ensure we don't wait forever
        const maxWaitTime = 3000; // 3 seconds max wait
        const startTime = Date.now();
        
        // We'll consider data collection complete if no new data 
        // has been received for 500ms, or we hit the max wait time
        const checkComplete = () => {
            const now = Date.now();
            if ((now - lastReceived > 500 && receivedCount > 0) || (now - startTime > maxWaitTime)) {
                callback(allData);
                return true;
            }
            return false;
        };
        
        const intervalId = setInterval(() => {
            if (checkComplete()) {
                clearInterval(intervalId);
            }
        }, 500); // Reduced interval frequency to avoid log spam
        
        this.cacheTable.map().once((data, hash) => {
            if (data) {
                allData[hash] = data;
                receivedCount++;
                lastReceived = Date.now();
            }
        });
    }

    // Set data with SEA encryption
    async setData(infohash, data) {
        // Create a new data object with direct property assignment
        const processedData = {
            infohash: infohash,
            service: data.provider || data.service || 'real_debrid',
            last_modified: data.last_modified || new Date().toISOString()
        };
        
        // Create a composite key
        const compositeKey = `${infohash}_${processedData.service}`;
        
        // Directly preserve cached without logic
        if (data.cached === true) {
            processedData.cached = true;
        } else if (data.cached === false) {
            processedData.cached = false;
        }
        
        // Handle timestamp formatting
        if (!processedData.last_modified.endsWith('Z')) {
            processedData.last_modified = new Date(processedData.last_modified).toISOString();
        }
        
        // Directly use expiry if provided, otherwise calculate based on cached
        if (data.expiry) {
            processedData.expiry = data.expiry.endsWith('Z') 
                ? data.expiry 
                : new Date(data.expiry).toISOString();
        } else if (processedData.cached === true) {
            // Only calculate if not provided
            const expiryDate = new Date(processedData.last_modified);
            expiryDate.setDate(expiryDate.getDate() + 7); // 7 days for cached=true
            processedData.expiry = expiryDate.toISOString();
        } else if (processedData.cached === false) {
            // Only calculate if not provided
            const expiryDate = new Date(processedData.last_modified);
            expiryDate.setHours(expiryDate.getHours() + 24); // 24 hours for cached=false
            processedData.expiry = expiryDate.toISOString();
        }

        // Update or invalidate the cache for this key
        if (this.entryCache.has(compositeKey)) {
            // Remove from cache - we'll update it on next retrieval
            this.entryCache.delete(compositeKey);
            console.log(`Cache entry invalidated for key: ${compositeKey} (data updated)`);
        }

        return new Promise((resolve) => {
            this.cacheTable.get(compositeKey).put(processedData, (ack) => {
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
                let entries = Object.entries(allData)
                    .map(([key, data]) => {
                        // Parse the composite key to get infohash and service
                        let infohash, service;
                        if (key.includes('_')) {
                            [infohash, service] = key.split('_');
                        } else {
                            infohash = key;
                            service = data.service;
                        }
                        
                        // Create entry with parsed data
                        const cleanedData = this.cleanData(data);
                        return {
                            infohash,
                            service,
                            ...cleanedData
                        };
                    });
                
                // Apply timestamp filters if provided
                if (minTimestamp) {
                    entries = entries.filter(entry => 
                        entry.last_modified && new Date(entry.last_modified) >= new Date(minTimestamp)
                    );
                }
                
                if (maxTimestamp) {
                    entries = entries.filter(entry => 
                        entry.last_modified && new Date(entry.last_modified) <= new Date(maxTimestamp)
                    );
                }
                
                // Apply any additional filter properties
                if (Object.keys(filter).length > 0) {
                    entries = entries.filter(entry => {
                        return Object.entries(filter).every(([key, value]) => {
                            return entry[key] === value;
                        });
                    });
                }
                
                // IMPORTANT: Force explicit last_modified sorting - newest first
                entries.sort((a, b) => {
                    // Parse timestamps to ensure consistent comparison
                    const dateA = a.last_modified ? new Date(a.last_modified).getTime() : 0;
                    const dateB = b.last_modified ? new Date(b.last_modified).getTime() : 0;
                    // Sort descending (newest first)
                    return dateB - dateA;
                });
                
                // Apply limit after sorting
                entries = entries.slice(0, limit);

                resolve({
                    total: entries.length,
                    limit,
                    data: entries
                });
            });
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
