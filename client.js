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
                    connected: Object.keys(peers).length,
                    addresses: Object.keys(peers)
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
        this.app.get('/data/:key', authenticateRequest, (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            this.getData(req.params.key, (data) => {
                if (!data) {
                    return res.status(404).json({ error: 'Data not found' });
                }
                
                // Clean and return the data
                const cleanedData = this.cleanData(data);
                cleanedData.infohash = req.params.key; // Ensure infohash is included
                res.json(cleanedData);
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
                        { urls: 'stun:stun2.l.google.com:19302' },
                        {
                            urls: 'turn:openrelay.metered.ca:443',
                            username: 'openrelayproject',
                            credential: 'openrelayproject'
                        }
                    ]
                }
            });


            // Log all SEA-related operations
            this.gun.on('auth', ack => {
                if (ack.err) {
                    console.error('Authentication Error:', {
                        timestamp: new Date().toISOString(),
                        error: ack.err
                    });
                }
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
    async getData(infohash, callback) {
        this.cacheTable.get(infohash).once(async (data) => {
            if (!data) {
                callback(null);
                return;
            }

            try {
                // Make a copy of the raw data
                const retrievedData = JSON.parse(JSON.stringify(data));
                
                // Add infohash to the data
                retrievedData.infohash = infohash;
                
                // Check if data exists
                if (!retrievedData.last_modified) {
                    console.warn(`Invalid data format for infohash: ${infohash}`);
                    callback(null);
                    return;
                }
                
                // Clean the data before returning
                const cleanedData = this.cleanData(retrievedData);
                callback(cleanedData);
            } catch (error) {
                console.error(`Error processing data for infohash ${infohash}:`, error);
                callback(null);
            }
        });
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
        }, 100);
        
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

        return new Promise((resolve) => {
            this.cacheTable.get(infohash).put(processedData, (ack) => {
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
                    .map(([hash, data]) => ({
                        infohash: hash,
                        ...this.cleanData(data)
                    }));
                
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
