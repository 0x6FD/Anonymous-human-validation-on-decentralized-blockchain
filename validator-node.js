// ============================================
// VALIDATOR NODE SERVICE
// ============================================
// Run this on each laptop with: node validator-node.js
// Each validator needs its own config (port, name, etc.)

const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');

// ============================================
// CONFIGURATION
// ============================================
// Each validator node needs unique configuration
const CONFIG = {
    NODE_NAME: process.env.NODE_NAME || "NodeA",
    PORT: process.env.PORT || 3001,
    VALIDATOR_NETWORK: [
        // List of all validators in the network
        { name: "NodeA", host: "192.168.1.101", port: 3001 },
        { name: "NodeB", host: "192.168.1.102", port: 3001 },
        { name: "NodeC", host: "192.168.1.103", port: 3001 },
        { name: "NodeD", host: "192.168.1.104", port: 3001 },
        { name: "NodeE", host: "192.168.1.105", port: 3001 }
    ],
    CONSENSUS_THRESHOLD: 3,  // Need 3 out of 5 approvals
    DATA_DIR: './validator-data'
};

// ============================================
// INITIALIZE EXPRESS APP
// ============================================
const app = express();
app.use(bodyParser.json({ limit: '10mb' }));
app.use(cors());

// ============================================
// VALIDATOR STATE
// ============================================
let validatorKeypair = null;
let verifiedBiometricHashes = new Set();  // Store hashes of verified biometrics
let pendingVerifications = new Map();     // Track ongoing verification requests

// ============================================
// CRYPTOGRAPHY FUNCTIONS
// ============================================

// Generate validator's keypair on startup
function generateValidatorKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',  // P-256 curve (same as browser)
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    return { publicKey, privateKey };
}

// Sign data with validator's private key
function signData(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
}

// Verify a signature
function verifySignature(data, signature, publicKey) {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
}

// Hash biometric data
function hashBiometric(biometricData) {
    return crypto.createHash('sha256').update(biometricData).digest('hex');
}

// ============================================
// VALIDATOR INITIALIZATION
// ============================================
function initializeValidator() {
    // Create data directory if it doesn't exist
    if (!fs.existsSync(CONFIG.DATA_DIR)) {
        fs.mkdirSync(CONFIG.DATA_DIR);
    }
    
    // Check if keypair already exists
    const publicKeyPath = `${CONFIG.DATA_DIR}/public.pem`;
    const privateKeyPath = `${CONFIG.DATA_DIR}/private.pem`;
    
    if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
        // Load existing keypair
        validatorKeypair = {
            publicKey: fs.readFileSync(publicKeyPath, 'utf8'),
            privateKey: fs.readFileSync(privateKeyPath, 'utf8')
        };
        console.log(`[${CONFIG.NODE_NAME}] Loaded existing keypair`);
    } else {
        // Generate new keypair
        validatorKeypair = generateValidatorKeypair();
        fs.writeFileSync(publicKeyPath, validatorKeypair.publicKey);
        fs.writeFileSync(privateKeyPath, validatorKeypair.privateKey);
        console.log(`[${CONFIG.NODE_NAME}] Generated new keypair`);
    }
    
    // Load verified biometric hashes from disk
    const hashesPath = `${CONFIG.DATA_DIR}/verified-hashes.json`;
    if (fs.existsSync(hashesPath)) {
        const hashes = JSON.parse(fs.readFileSync(hashesPath, 'utf8'));
        verifiedBiometricHashes = new Set(hashes);
        console.log(`[${CONFIG.NODE_NAME}] Loaded ${verifiedBiometricHashes.size} verified hashes`);
    }
}

// Save verified hashes to disk
function saveVerifiedHashes() {
    const hashesPath = `${CONFIG.DATA_DIR}/verified-hashes.json`;
    fs.writeFileSync(hashesPath, JSON.stringify([...verifiedBiometricHashes]));
}

// ============================================
// API ENDPOINTS
// ============================================

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'online',
        nodeName: CONFIG.NODE_NAME,
        verifiedCount: verifiedBiometricHashes.size
    });
});

// Get validator's public key
app.get('/public-key', (req, res) => {
    res.json({
        nodeName: CONFIG.NODE_NAME,
        publicKey: validatorKeypair.publicKey
    });
});

// ============================================
// VERIFICATION REQUEST HANDLER
// ============================================
// This is the main endpoint that receives verification requests

app.post('/verify', async (req, res) => {
    const { verificationId, userPublicKey, biometricHash } = req.body;
    
    console.log(`[${CONFIG.NODE_NAME}] Received verification request: ${verificationId}`);
    
    try {
        // STEP 1: Validate the request
        if (!verificationId || !userPublicKey || !biometricHash) {
            return res.status(400).json({
                vote: 'DENY',
                reason: 'Missing required fields'
            });
        }
        
        // STEP 2: Check for duplicate biometric
        // This is the uniqueness check - has this person verified before?
        if (verifiedBiometricHashes.has(biometricHash)) {
            console.log(`[${CONFIG.NODE_NAME}] DENY - Duplicate biometric detected`);
            return res.json({
                nodeName: CONFIG.NODE_NAME,
                vote: 'DENY',
                reason: 'Biometric already verified (duplicate detected)'
            });
        }
        
        // STEP 3: Validate the public key format
        // Make sure it's actually a valid public key
        try {
            // Try to create a key object from it (will throw if invalid)
            crypto.createPublicKey(userPublicKey);
        } catch (error) {
            console.log(`[${CONFIG.NODE_NAME}] DENY - Invalid public key format`);
            return res.json({
                nodeName: CONFIG.NODE_NAME,
                vote: 'DENY',
                reason: 'Invalid public key format'
            });
        }
        
        // STEP 4: Additional checks could go here
        // - Liveness detection verification
        // - Biometric quality checks
        // - Rate limiting
        // - Blacklist checks
        
        // STEP 5: All checks passed - APPROVE
        console.log(`[${CONFIG.NODE_NAME}] APPROVE - All checks passed`);
        
        // Store the verification request temporarily
        // We'll finalize it only after consensus is reached
        pendingVerifications.set(verificationId, {
            userPublicKey,
            biometricHash,
            timestamp: Date.now()
        });
        
        res.json({
            nodeName: CONFIG.NODE_NAME,
            vote: 'APPROVE',
            reason: 'Verification checks passed'
        });
        
    } catch (error) {
        console.error(`[${CONFIG.NODE_NAME}] Error processing verification:`, error);
        res.status(500).json({
            nodeName: CONFIG.NODE_NAME,
            vote: 'DENY',
            reason: 'Internal error during verification'
        });
    }
});

// ============================================
// CONSENSUS FINALIZATION
// ============================================
// Called after all validators have voted
// If consensus is reached, sign the credential and save the biometric hash

app.post('/finalize', async (req, res) => {
    const { verificationId, consensusReached, votes } = req.body;
    
    console.log(`[${CONFIG.NODE_NAME}] Finalization request for ${verificationId}`);
    console.log(`Consensus: ${consensusReached}, Votes:`, votes);
    
    try {
        // Get the pending verification
        const verification = pendingVerifications.get(verificationId);
        
        if (!verification) {
            return res.status(404).json({
                error: 'Verification not found'
            });
        }
        
        if (consensusReached) {
            // CONSENSUS REACHED - Issue credential
            
            // Sign the user's public key with our private key
            const signature = signData(verification.userPublicKey, validatorKeypair.privateKey);
            
            // Add biometric hash to our verified set
            verifiedBiometricHashes.add(verification.biometricHash);
            saveVerifiedHashes();
            
            console.log(`[${CONFIG.NODE_NAME}] Credential issued for ${verificationId}`);
            
            // Clean up pending verification
            pendingVerifications.delete(verificationId);
            
            res.json({
                success: true,
                nodeName: CONFIG.NODE_NAME,
                signature: signature,
                publicKey: validatorKeypair.publicKey
            });
            
        } else {
            // CONSENSUS FAILED - Clean up
            console.log(`[${CONFIG.NODE_NAME}] Consensus failed for ${verificationId}`);
            pendingVerifications.delete(verificationId);
            
            res.json({
                success: false,
                reason: 'Consensus not reached'
            });
        }
        
    } catch (error) {
        console.error(`[${CONFIG.NODE_NAME}] Error finalizing:`, error);
        res.status(500).json({
            error: 'Finalization error'
        });
    }
});

// ============================================
// NETWORK COMMUNICATION
// ============================================
// Functions for validators to communicate with each other

async function broadcastToValidators(endpoint, data) {
    const promises = CONFIG.VALIDATOR_NETWORK
        .filter(v => v.name !== CONFIG.NODE_NAME)  // Don't send to ourselves
        .map(async (validator) => {
            try {
                const response = await fetch(`http://${validator.host}:${validator.port}${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                return await response.json();
            } catch (error) {
                console.error(`Failed to contact ${validator.name}:`, error.message);
                return { nodeName: validator.name, vote: 'OFFLINE' };
            }
        });
    
    return await Promise.all(promises);
}

// Check health of all validators
app.get('/network-status', async (req, res) => {
    const statuses = await Promise.all(
        CONFIG.VALIDATOR_NETWORK.map(async (validator) => {
            try {
                const response = await fetch(`http://${validator.host}:${validator.port}/health`, {
                    method: 'GET',
                    timeout: 2000
                });
                const data = await response.json();
                return { ...data, reachable: true };
            } catch (error) {
                return {
                    nodeName: validator.name,
                    status: 'offline',
                    reachable: false
                };
            }
        })
    );
    
    res.json({
        totalNodes: CONFIG.VALIDATOR_NETWORK.length,
        onlineNodes: statuses.filter(s => s.reachable).length,
        nodes: statuses
    });
});

// ============================================
// CLEANUP AND MAINTENANCE
// ============================================

// Periodically clean up old pending verifications (older than 10 minutes)
setInterval(() => {
    const now = Date.now();
    const tenMinutes = 10 * 60 * 1000;
    
    for (const [verificationId, verification] of pendingVerifications.entries()) {
        if (now - verification.timestamp > tenMinutes) {
            console.log(`[${CONFIG.NODE_NAME}] Cleaning up stale verification: ${verificationId}`);
            pendingVerifications.delete(verificationId);
        }
    }
}, 60 * 1000);  // Run every minute

// ============================================
// START SERVER
// ============================================

initializeValidator();

app.listen(CONFIG.PORT, () => {
    console.log('='.repeat(50));
    console.log(`Validator Node: ${CONFIG.NODE_NAME}`);
    console.log(`Port: ${CONFIG.PORT}`);
    console.log(`Public Key Fingerprint: ${crypto.createHash('sha256').update(validatorKeypair.publicKey).digest('hex').substring(0, 16)}`);
    console.log(`Verified Biometrics: ${verifiedBiometricHashes.size}`);
    console.log('='.repeat(50));
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log(`\n[${CONFIG.NODE_NAME}] Shutting down gracefully...`);
    saveVerifiedHashes();
    process.exit(0);
});
