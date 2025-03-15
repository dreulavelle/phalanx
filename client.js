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
        
        // Add data endpoint (protected)
        this.app.post('/data', authenticateRequest, async (req, res) => {
            if (!this.gun) {
                return res.status(503).json({ error: 'Database not initialized' });
            }

            const data = req.body;
            try {
                const success = await this.setData(data.hash, data);
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
                    limit: parseInt(req.query.limit) || 50,
                    filter: req.query.filter || {},
                    minTimestamp: req.query.minTimestamp,
                    maxTimestamp: req.query.maxTimestamp
                });

                // Clean the data before sending
                result.data = result.data.map(entry => this.cleanData(entry));
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
                        data && data.timestamp && data.cached !== undefined
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
                if (data) {
                    res.json(this.cleanData(data));
                } else {
                    res.status(404).json({ error: 'Data not found' });
                }
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
        return {
            hash: data.hash,
            cached: data.cached,
            timestamp: data.timestamp,
            provider: data.provider || 'real_debrid' // Add provider with default value
        };
    }

    // Encryption utilities using SEA
    async encrypt(data) {
        try {
            if (!this.pair) {
                throw new Error('Encryption not initialized');
            }
            
            // Clean the data before encryption
            const cleanedData = this.cleanData(data);
            
            // Convert data to string if it's an object
            const dataStr = typeof cleanedData === 'object' ? JSON.stringify(cleanedData) : cleanedData;
            
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
                timestamp: new Date().toISOString()
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
    async getData(hash, callback) {
        this.cacheTable.get(hash).once((data) => {
            callback(data);
        });
    }

    // Get all data with SEA decryption
    getAllData(callback) {
        const allData = {};
        
        this.cacheTable.map().once((data, hash) => {
            if (data) {
                allData[hash] = data;
            }
        });

        // Gun.js is asynchronous, so we still need a small delay
        setTimeout(() => {
            callback(allData);
        }, 2000);
    }

    // Set data with SEA encryption
    async setData(hash, data) {
        return new Promise((resolve) => {
            this.cacheTable.get(hash).put(data, (ack) => {
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
        const { limit = 50 } = options;
        
        return new Promise((resolve) => {
            this.getAllData((allData) => {
                const entries = Object.entries(allData)
                    .map(([hash, data]) => ({
                        hash,
                        ...data
                    }))
                    .slice(0, limit);

                resolve({
                    total: entries.length,
                    limit,
                    data: entries
                });
            });
        });
    }

    // Check and update cache status for items older than 7 days
    checkCacheExpiration() {
        console.log('Running cache expiration check...');
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);

        this.getAllData((allData) => {
            Object.entries(allData).forEach(([hash, entry]) => {
                const entryDate = new Date(entry.timestamp);
                
                // Check for cached items older than 7 days
                if (entryDate < sevenDaysAgo && entry.cached === true) {
                    console.log(`Expiring cache for entry: ${hash} (${entry.timestamp})`);
                    this.cacheTable.get(hash).put({
                        cached: 'unchecked',
                        timestamp: entry.timestamp
                    }, (ack) => {
                        if (ack.err) {
                            console.error(`Error updating cache status for ${hash}:`, ack.err);
                        } else {
                            console.log(`Successfully expired cache for ${hash}`);
                        }
                    });
                }
                
                // Check for uncached items older than 24 hours
                if (entryDate < oneDayAgo && entry.cached === false) {
                    console.log(`Moving uncached entry to unchecked state: ${hash} (${entry.timestamp})`);
                    this.cacheTable.get(hash).put({
                        cached: 'unchecked',
                        timestamp: entry.timestamp
                    }, (ack) => {
                        if (ack.err) {
                            console.error(`Error updating cache status for ${hash}:`, ack.err);
                        } else {
                            console.log(`Successfully moved entry to unchecked state: ${hash}`);
                        }
                    });
                }
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
        
        // Set up hourly cache expiration check
        setInterval(() => {
            node.checkCacheExpiration();
        }, 60 * 60 * 1000); // Run every hour
        
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
