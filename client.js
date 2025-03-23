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
            gatheringIntervalMinutes: config.gatheringIntervalMinutes || 15,
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

            // Simple graph size check
            const graph = this.gun._.graph || {};
            const graphSize = Object.keys(graph).length;
            const validCount = Object.keys(graph).length;

            res.json({
                node: {
                    id: NODE_ID,
                    uptime: Math.floor((Date.now() - this.startupTime) / 1000),
                    port: this.config.port
                },
                peers: {
                    relay_servers: relayServers
                },
                storage: {
                    enabled: this.gun._.opt.file ? true : false,
                    file: this.gun._.opt.file || null
                },
                data: {
                    valid: validCount,
                    estimated_count: this.estimatedCount || 0
                },
                updates: this.dataUpdateTracking ? {
                    total_updates: this.dataUpdateTracking.totalUpdates,
                    unique_nodes: this.dataUpdateTracking.uniqueNodes.size,
                    last_update: new Date(this.dataUpdateTracking.lastReceived).toISOString(),
                    age_ms: Date.now() - this.dataUpdateTracking.lastReceived
                } : null,
                data_gathering: {
                    active: this.dataGatheringActive || !!this.dataGatheringInterval,
                    next_run_in_ms: this.nextGatheringTime ? this.nextGatheringTime - Date.now() : null,
                    last_run: this.lastGatheringTime ? new Date(this.lastGatheringTime).toISOString() : null,
                    total_entries_found: this.totalGatheringEntries || 0,
                    interval_minutes: this.config.gatheringIntervalMinutes || 15
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

            try {
                // Get a fresh estimate
                const estimatedCount = await this.estimateCount();
                
                // Use direct graph access for simple metrics
                const graph = this.gun._.graph || {};
                const totalKeys = Object.keys(graph).length;
                const cacheKeys = Object.keys(graph).filter(key => key.startsWith('cache/')).length;
                
                // Get update stats
                const updateStats = this.dataUpdateTracking ? {
                    total_updates: this.dataUpdateTracking.totalUpdates,
                    unique_nodes: this.dataUpdateTracking.uniqueNodes.size,
                    last_update_age_ms: Date.now() - this.dataUpdateTracking.lastReceived
                } : null;
                
                res.json({
                    estimates: {
                        count: estimatedCount,
                        total_graph_size: totalKeys,
                        cache_keys: cacheKeys
                    },
                    updates: updateStats,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Error in test-count endpoint:', error);
                res.status(500).json({ 
                    error: 'Internal server error',
                    details: error.message
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

            // Initialize Gun with optimized configuration
            const fs = require('fs');
            const path = require('path');
            
            // Ensure data directory exists
            const dataDir = path.join(process.cwd(), 'data');
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }

            this.gun = Gun({
                web: server,
                peers: this.config.peers,
                file: 'phalanx-db.json',
                radisk: true,
                localStorage: false,
                multicast: false,
                retry: 2000,
                pid: NODE_ID,
                super: this.config.isRemoteServer,
                sea: true,
                axe: false,
                cache: false,
                memory: true,
                chunk: 1024 * 1024 * 2,
                wait: 500,
                gap: 1000,
                pack: 1024 * 1024 * 5,
                max: 1024 * 1024 * 10
            });

            // Initialize the cache table
            this.cacheTable = this.gun.get('cache');
            
            // Setup minimal data update tracking
            this.dataUpdateTracking = {
                lastReceived: Date.now(),
                totalUpdates: 0,
                uniqueNodes: new Set(),
                errorCount: 0
            };
            
            // Set up a lightweight subscription for updates
            this.updateSubscription = this.subscribeToLightUpdates();
            
            // Set up periodic graph cleanup (every 5 minutes)
            setInterval(() => {
                this.cleanupGraph();
            }, 5 * 60 * 1000);

            // Do initial graph cleanup
            await this.cleanupGraph();
            
            // Get an approximate count asynchronously without blocking startup
            this.estimateCount().then(count => {
                this.estimatedCount = count;
                console.log(`Estimated database count: ~${count} entries`);
            }).catch(err => {
                console.warn('Error estimating count:', err);
                this.estimatedCount = 0;
            });
            
            // Set up periodic data gathering
            this.setupPeriodicDataGathering();
            
            console.log('Node initialized successfully');
            return true;
        } catch (error) {
            console.error('Failed to initialize node:', error);
            return false;
        }
    }
    
    // Set up periodic data gathering to continue discovering entries
    setupPeriodicDataGathering() {
        // Initial delay before starting periodic gathering (configurable, default 5 minutes)
        const initialDelayMinutes = this.config.initialDelayMinutes || 1;
        const initialDelay = initialDelayMinutes * 60 * 1000;
        
        // Interval between gathering attempts (from config, default 15 minutes)
        const gatheringIntervalMinutes = this.config.gatheringIntervalMinutes || 15;
        const gatheringInterval = gatheringIntervalMinutes * 60 * 1000;
        
        // Set initial state for tracking
        this.lastGatheringTime = null;
        this.nextGatheringTime = Date.now() + initialDelay;
        this.totalGatheringEntries = 0;
        
        // Initialize as active immediately
        this.dataGatheringActive = true;
        
        // Set up periodic gathering with initial delay
        setTimeout(() => {
            console.log(`Starting periodic data gathering (every ${gatheringIntervalMinutes} minutes)...`);
            
            // Run the first gathering
            this.gatherMoreData();
            
            // Set up interval for subsequent gatherings
            this.dataGatheringInterval = setInterval(() => {
                this.gatherMoreData();
            }, gatheringInterval);
            
        }, initialDelay);
        
        console.log(`Periodic data gathering scheduled to start in ${initialDelay/1000} seconds`);
        console.log(`Gathering interval set to ${gatheringIntervalMinutes} minutes`);
        
        // Option to run immediately if interval is very small
        if (gatheringIntervalMinutes <= 2) {
            console.log('Interval is very small, running first gathering cycle immediately...');
            setTimeout(() => this.gatherMoreData(), 5000); // Start after 5 seconds
        }
    }
    
    // Gather more data by sampling the network
    async gatherMoreData() {
        if (!this.gun) {
            console.warn('Cannot gather data: Gun not initialized');
            return;
        }
        
        console.log('Starting data gathering cycle...');
        
        // Update gathering time tracking
        this.lastGatheringTime = Date.now();
        const gatheringIntervalMinutes = this.config.gatheringIntervalMinutes || 15;
        this.nextGatheringTime = Date.now() + (gatheringIntervalMinutes * 60 * 1000); // Schedule next run
        
        try {
            // Get current count
            const beforeCount = await this.estimateCount();
            
            // Sample more data from the network
            const samplePromise = new Promise(resolve => {
                const alreadySeen = new Set();
                let newEntriesFound = 0;
                const maxSampleTime = 60 * 1000; // 60 seconds max
                
                // Sample from cache table
                this.cacheTable.map().on((data, key) => {
                    if (data && key !== 'cache' && !alreadySeen.has(key)) {
                        alreadySeen.add(key);
                        newEntriesFound++;
                        
                        // Log progress sparingly
                        if (newEntriesFound % 50 === 0) {
                            console.log(`Data gathering found ${newEntriesFound} entries so far...`);
                        }
                    }
                });
                
                // Set a timeout to end sampling
                setTimeout(() => {
                    this.cacheTable.map().off();
                    resolve(newEntriesFound);
                }, maxSampleTime);
            });
            
            // Wait for the sampling to complete
            const newEntriesFound = await samplePromise;
            
            // Get updated count
            const afterCount = await this.estimateCount();
            const increase = afterCount - beforeCount;
            
            // Update tracking metrics
            this.totalGatheringEntries = (this.totalGatheringEntries || 0) + newEntriesFound;
            
            console.log(`Data gathering cycle completed: found ${newEntriesFound} entries, count increased by ${increase} (${beforeCount} → ${afterCount})`);
            
            // Update the estimated count
            this.estimatedCount = afterCount;
        } catch (error) {
            console.error('Error during data gathering cycle:', error);
        }
    }
    
    // Cleanup method to stop intervals when shutting down
    cleanup() {
        console.log('Cleaning up resources...');
        
        // Clear data gathering interval if it exists
        if (this.dataGatheringInterval) {
            clearInterval(this.dataGatheringInterval);
            this.dataGatheringInterval = null;
            this.dataGatheringActive = false;
            console.log('Stopped periodic data gathering');
        }
        
        // Unsubscribe from updates if subscription exists
        if (this.updateSubscription) {
            this.updateSubscription.unsubscribe();
            this.updateSubscription = null;
            console.log('Unsubscribed from data updates');
        }

        // Clean up the graph before exit
        this.cleanupGraph().then(() => {
            console.log('Graph cleanup completed');
        });
        
        console.log('Cleanup completed');
    }
    
    // Lightweight subscription method that just listens for updates without heavy processing
    subscribeToLightUpdates() {
        if (!this.gun) {
            console.warn('Gun not initialized');
            return null;
        }
        
        console.log('Setting up lightweight data update listener (cleanup disabled)');
        
        // Track when nodes were last processed to avoid duplicates
        const processedNodes = new Map();
        const throttleTime = 10000; // 10 seconds throttle
        
        // Keep track of active subscriptions
        let activeSubscriptions = new Set();
        
        // Set up health check logging only (no cleanup)
        const healthCheckInterval = setInterval(() => {
            const currentMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
            
            // Log subscription health metrics
            console.log(`Subscription Health (cleanup disabled):
                - Active subscriptions: ${activeSubscriptions.size}
                - Processed nodes: ${processedNodes.size}
                - Memory usage: ${currentMemory}MB
                - Last update: ${new Date(this.dataUpdateTracking.lastReceived).toISOString()}
                - Total updates: ${this.dataUpdateTracking.totalUpdates}
                - Error count: ${this.dataUpdateTracking.errorCount || 0}
            `);
        }, 60000); // Log every minute
        
        // Listen for updates to cache with proper subscription management
        const subscription = this.cacheTable.map().on(async (data, key) => {
            // Skip null data, cache root, or Gun metadata
            if (!data || key === 'cache' || key === '_') return;
            
            // Basic throttling
            const now = Date.now();
            const lastTime = processedNodes.get(key) || 0;
            if (now - lastTime < throttleTime) return;
            
            try {
                // Decrypt and validate data before counting it
                let decryptedData;
                if (data.encryptedData) {
                    decryptedData = await this.decrypt(data);
                    if (!decryptedData) {
                        console.warn(`Failed to decrypt data for key: ${key}`);
                        return;
                    }
                } else {
                    // Handle legacy data format
                    try {
                        decryptedData = JSON.parse(JSON.stringify(data));
                        
                        // If it's legacy format, try to convert it
                        if (!decryptedData.services) {
                            const serviceName = decryptedData.service || decryptedData.provider || 'default';
                            
                            // Only convert if we have valid cached status
                            if (decryptedData.cached !== true && decryptedData.cached !== false) {
                                console.warn(`Skipping legacy data conversion - invalid cached status for key: ${key}`);
                                return;
                            }
                            
                            // Ensure timestamps
                            const last_modified = decryptedData.last_modified || new Date().toISOString();
                            let expiry = decryptedData.expiry;
                            if (!expiry) {
                                const expiryDate = new Date(last_modified);
                                if (decryptedData.cached) {
                                    expiryDate.setDate(expiryDate.getDate() + 7);
                                } else {
                                    expiryDate.setHours(expiryDate.getHours() + 24);
                                }
                                expiry = expiryDate.toISOString();
                            }
                            
                            // Convert to new format
                            decryptedData = {
                                infohash: decryptedData.infohash || key,
                                services: {
                                    [serviceName]: {
                                        cached: decryptedData.cached,
                                        last_modified,
                                        expiry
                                    }
                                }
                            };
                        }
                    } catch (parseError) {
                        console.warn(`Failed to parse legacy data for key: ${key}`, parseError);
                        return;
                    }
                }
                
                // Add the infohash if not present
                if (!decryptedData.infohash) {
                    decryptedData.infohash = key;
                }
                
                // Clean and validate the data
                const cleanedData = this.cleanData(decryptedData);
                if (!cleanedData || !this.validateSchema(cleanedData)) {
                    console.warn(`Invalid data format for key: ${key}`);
                    return;
                }
                
                // Track valid updates
                processedNodes.set(key, now);
                this.dataUpdateTracking.lastReceived = now;
                this.dataUpdateTracking.totalUpdates++;
                this.dataUpdateTracking.uniqueNodes.add(key);
                
                // Add to active subscriptions without cleanup
                activeSubscriptions.add(key);
                
                // Log updates sparingly
                if (this.dataUpdateTracking.totalUpdates % 100 === 0) {
                    const currentMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
                    console.log(`Received ~${this.dataUpdateTracking.totalUpdates} valid updates, active: ${activeSubscriptions.size}, memory: ${currentMemory}MB`);
                }
            } catch (error) {
                console.error('Error processing update:', error);
                this.dataUpdateTracking.errorCount = (this.dataUpdateTracking.errorCount || 0) + 1;
            }
        });
        
        // Return unsubscribe function
        return {
            unsubscribe: () => {
                clearInterval(healthCheckInterval);
                subscription.off();
                activeSubscriptions.clear();
                processedNodes.clear();
                console.log('Unsubscribed from all data updates');
            }
        };
    }
    
    // Get a quick estimate of the database size
    async estimateCount() {
        return new Promise((resolve) => {
            // Use direct graph access for faster estimation
            const graph = this.gun._.graph || {};
            const cacheEntries = Object.keys(graph).filter(key => 
                key.startsWith('cache/') && key !== 'cache'
            ).length;
            
            // If we have entries from the graph, use that as it's fastest
            if (cacheEntries > 0) {
                resolve(cacheEntries);
                return;
            }
            
            // Fall back to sampling with a timeout
            let count = 0;
            let sampleSize = 0;
            const maxSamples = 1000;
            
            // Set up a promise that will resolve after a timeout
            const timeoutPromise = new Promise(resolve => {
                setTimeout(() => resolve('timeout'), 3000);
            });
            
            // Set up the sampling promise
            const samplingPromise = new Promise(resolve => {
                this.cacheTable.map().on((data, key) => {
                    if (data && key !== 'cache') {
                        count++;
                    }
                    sampleSize++;
                    
                    // If we've sampled enough, resolve
                    if (sampleSize >= maxSamples) {
                        resolve('complete');
                    }
                });
            });
            
            // Race between timeout and sampling
            Promise.race([timeoutPromise, samplingPromise])
                .then(() => {
                    this.cacheTable.map().off();
                    resolve(count);
                })
                .catch(err => {
                    console.error('Error during count estimation:', err);
                    this.cacheTable.map().off();
                    resolve(0);
                });
        });
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

        // Create a promise that will resolve with the data or timeout
        const dataPromise = new Promise((resolve) => {
            const subscription = this.cacheTable.get(key).once(async (data) => {
                try {
                    if (!data) {
                        resolve(null);
                        return;
                    }

                    // Decrypt the data if it's encrypted
                    let decryptedData;
                    if (data.encryptedData) {
                        decryptedData = await this.decrypt(data);
                        if (!decryptedData) {
                            console.warn(`Failed to decrypt data for key: ${key}`);
                            resolve(null);
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
                        resolve(null);
                        return;
                    }
                    
                    resolve(cleanedData);
                } catch (error) {
                    console.error(`Error processing data for key ${key}:`, error);
                    resolve(null);
                }
            });

            // Ensure subscription is cleaned up after use
            setTimeout(() => {
                subscription.off();
            }, 100);
        });

        // Set a timeout for the entire operation
        const timeoutPromise = new Promise((resolve) => {
            setTimeout(() => {
                resolve(null);
            }, 5000); // 5 second timeout
        });

        // Race between data retrieval and timeout
        const result = await Promise.race([dataPromise, timeoutPromise]);
        callback(result);
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
            if (hash === '_') return; // Skip internal Gun.js metadata
            
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
        }, 15000); // 15 seconds timeout
    }

    // Set data with SEA encryption
    async setData(infohash, data) {
        try {
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
                const expiryDate = new Date(serviceData.last_modified);
                expiryDate.setDate(expiryDate.getDate() + 7); // 7 days for cached=true
                serviceData.expiry = expiryDate.toISOString();
            } else {
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
                let retries = 3;
                const attemptPut = () => {
                    if (retries <= 0) {
                        console.error('Failed to store data after all retries');
                        resolve(false);
                        return;
                    }

                    const timeout = setTimeout(() => {
                        retries--;
                        console.warn(`Write operation timed out, retries left: ${retries}`);
                        if (retries > 0) {
                            attemptPut();
                        } else {
                            resolve(false);
                        }
                    }, 10000);

                    try {
                        this.cacheTable.get(infohash).put(encryptedData, (ack) => {
                            clearTimeout(timeout);
                            if (ack.err) {
                                if (ack.err === 'Chunk too big!' && retries > 0) {
                                    retries--;
                                    console.warn(`Chunk too big, retrying with delay... (${retries} retries left)`);
                                    setTimeout(attemptPut, 1000);
                                } else {
                                    console.error('Error storing data:', ack.err);
                                    resolve(false);
                                }
                            } else {
                                resolve(true);
                            }
                        });
                    } catch (error) {
                        clearTimeout(timeout);
                        console.error('Error in put operation:', error);
                        retries--;
                        if (retries > 0) {
                            setTimeout(attemptPut, 1000);
                        } else {
                            resolve(false);
                        }
                    }
                };

                attemptPut();
            });
        } catch (error) {
            console.error('Error in setData:', error);
            return false;
        }
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
                // Get data directly from the graph for better performance
                const graph = this.gun._.graph;
                const cacheEntries = Object.entries(graph).filter(([key]) => 
                    key.startsWith('cache/') && key !== 'cache'
                );
                
                console.log(`Processing ${cacheEntries.length} cache entries`);

                // Process all entries from the graph
                const processedEntries = await Promise.all(
                    cacheEntries.map(async ([key, value]) => {
                        if (!value || typeof value !== 'object') return null;
                        
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
                                if (!this.validateServiceData(serviceData)) return;

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
                }
                
                if (maxTimestamp) {
                    const maxTime = new Date(maxTimestamp).getTime();
                    filteredEntries = filteredEntries.filter(entry => entry.newest_timestamp <= maxTime);
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
                }

                // Sort by newest timestamp and apply limit
                filteredEntries.sort((a, b) => b.newest_timestamp - a.newest_timestamp);
                const limitedEntries = filteredEntries.slice(0, limit);

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

    // Helper method to validate service data
    validateServiceData(serviceData) {
        if (serviceData.cached !== true && serviceData.cached !== false) {
            return false;
        }
        if (!serviceData.last_modified || !isValidISODate(serviceData.last_modified)) {
            return false;
        }
        if (!serviceData.expiry || !isValidISODate(serviceData.expiry)) {
            return false;
        }
        return true;
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

    // Add graph cleanup method
    async cleanupGraph() {
        if (!this.gun) return;

        console.log('Starting graph cleanup...');
        const before = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
        const graph = this.gun._.graph;
        let cleaned = 0;
        let retained = 0;

        // Get all cache entries
        const entries = Object.entries(graph).filter(([key]) => key.startsWith('cache/'));
        console.log(`Found ${entries.length} total entries in graph`);

        for (const [key, value] of entries) {
            try {
                if (!value || value === null) {
                    delete graph[key];
                    cleaned++;
                    continue;
                }

                // If it's encrypted data, try to decrypt to validate
                if (value.encryptedData) {
                    const decrypted = await this.decrypt(value);
                    if (!decrypted) {
                        delete graph[key];
                        cleaned++;
                        continue;
                    }
                }

                // Check if the data is expired
                if (value.services) {
                    const now = new Date();
                    const allExpired = Object.values(value.services).every(service => 
                        service.expiry && new Date(service.expiry) < now
                    );
                    if (allExpired) {
                        delete graph[key];
                        cleaned++;
                        continue;
                    }
                }

                retained++;
            } catch (error) {
                console.warn(`Error processing graph entry ${key}:`, error);
                delete graph[key];
                cleaned++;
            }
        }

        // Clean up Gun's internal caches if possible
        if (this.gun._.opt && this.gun._.opt.cache) {
            this.gun._.opt.cache = {};
        }

        // Force garbage collection if available
        if (global.gc) {
            try {
                global.gc();
            } catch (e) {
                console.warn('Failed to force garbage collection:', e);
            }
        }

        const after = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
        console.log(`Graph cleanup completed:
            - Cleaned entries: ${cleaned}
            - Retained entries: ${retained}
            - Memory before: ${before}MB
            - Memory after: ${after}MB
            - Memory reduced: ${Math.max(0, before - after)}MB
        `);

        return { cleaned, retained, memoryReduced: Math.max(0, before - after) };
    }
}

// Parse command line arguments
const args = process.argv.slice(2);
const nodeType = args[0] || 'local';  // Default to local if no argument
const port = args[1] || 8888;  // Optional port argument
const gatheringInterval = args[2] ? parseInt(args[2]) : 15;  // Optional gathering interval in minutes, default 15
const initialDelay = args[3] ? parseInt(args[3]) : 5;  // Optional initial delay in minutes, default 5

// Configure node based on type
const config = {
    isRemoteServer: nodeType === 'remote',
    connectToRemote: nodeType === 'local',
    port: parseInt(port),
    gatheringIntervalMinutes: gatheringInterval,
    initialDelayMinutes: initialDelay
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

// Setup graceful shutdown handlers
process.on('SIGINT', () => {
    console.log('\nReceived SIGINT (Ctrl+C). Shutting down gracefully...');
    node.cleanup();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\nReceived SIGTERM. Shutting down gracefully...');
    node.cleanup();
    process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    node.cleanup();
    process.exit(1);
});

// Log startup configuration
console.log('\nNode Configuration:');
console.log('==================');
console.log(`Node ID: ${NODE_ID}`);
console.log(`Mode: ${config.isRemoteServer ? 'Remote Server' : 'Local Client'}`);
console.log(`Port: ${config.port}`);
console.log(`Data Gathering Interval: ${config.gatheringIntervalMinutes} minutes`);
console.log(`Initial Delay: ${config.initialDelayMinutes} minutes`);
console.log(`Peer Discovery: Enabled (using gun-relays)`);
console.log('\nEncryption Configuration:');
console.log('----------------------');
console.log(`Type: SEA (Security, Encryption, Authorization)`);
console.log(`Algorithm: AES-GCM (via SEA)`);
console.log(`Key Status: ${ENCRYPTION_KEY ? 'Configured' : 'Missing'}`);
console.log(`Encryption: ${ENCRYPTION_KEY ? 'Enabled' : 'Disabled'}`);
console.log('==================\n');