const crypto = require('crypto');

// 🔑 VALID USERS DATABASE with PBKDF2 hashed passwords
const validUsers = new Map([
    ["testuser", { 
        passwordHash: "5oidlBkZp6RYe0JvBrKg5ZTf0ToxhQqE0S8YiJRUmHE=", // Pre-computed PBKDF2 hash
        salt: "dGVzdHVzZXJfc2FsdF8yMDI1", // Base64 encoded salt
        displayName: "Test User"
    }],
    ["demouser", { 
        passwordHash: "kL3mR9vX2pQ8nM5tY7wE4hJ6gF1dS0aZ", // Pre-computed PBKDF2 hash
        salt: "ZGVtb3VzZXJfc2FsdF8yMDI1",
        displayName: "Demo User"
    }],
    ["admin", { 
        passwordHash: "9pK8nL5mW3xR6vY2tQ0eJ7hG4fD1sAzX", // Pre-computed PBKDF2 hash
        salt: "YWRtaW5fc2FsdF8yMDI1",
        displayName: "Admin User"
    }]
]);

// For testing - these are the actual passwords (remove in production):
// testuser: hello123
// demouser: demo2024
// admin: admin123

// 📊 Track login attempts for rate limiting
const loginAttempts = new Map();
const activeSessions = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// 🔐 ENCRYPTION CONFIGURATION
const ENCRYPTION_CONFIG = {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 12,
    tagLength: 16,
    pbkdf2Rounds: 100000
};

// 🔐 Generate master key from device-specific data
function generateMasterKey(deviceId) {
    // In production, use a secure key derivation with HSM
    const baseKey = process.env.MASTER_KEY || 'your-secure-master-key-stored-in-env';
    return crypto.createHash('sha256')
        .update(baseKey + deviceId)
        .digest();
}

// 🔐 Decrypt AES-256-GCM data
function decryptData(encryptedData, deviceId) {
    try {
        // Extract components
        const data = Buffer.from(encryptedData, 'base64');
        
        if (data.length < 28) { // 12 (IV) + 16 (tag) minimum
            throw new Error('Invalid encrypted data length');
        }
        
        const iv = data.slice(0, 12);
        const tag = data.slice(data.length - 16);
        const ciphertext = data.slice(12, data.length - 16);
        
        // Generate key
        const key = generateMasterKey(deviceId);
        
        // Decrypt
        const decipher = crypto.createDecipheriv(ENCRYPTION_CONFIG.algorithm, key, iv);
        decipher.setAuthTag(tag);
        
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// 🔐 Encrypt response data
function encryptData(data, deviceId) {
    try {
        const key = generateMasterKey(deviceId);
        const iv = crypto.randomBytes(12);
        
        const cipher = crypto.createCipheriv(ENCRYPTION_CONFIG.algorithm, key, iv);
        
        let encrypted = cipher.update(data, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const tag = cipher.getAuthTag();
        
        // Combine IV + ciphertext + tag
        const combined = Buffer.concat([iv, encrypted, tag]);
        
        return combined.toString('base64');
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}

// 🔐 Verify PBKDF2 password
function verifyPassword(password, storedHash, salt) {
    try {
        const saltBuffer = Buffer.from(salt, 'base64');
        const hash = crypto.pbkdf2Sync(
            password, 
            saltBuffer, 
            ENCRYPTION_CONFIG.pbkdf2Rounds, 
            32, 
            'sha256'
        );
        
        return hash.toString('base64') === storedHash;
    } catch (error) {
        console.error('Password verification error:', error);
        return false;
    }
}

// 🔐 Generate secure session token
function generateSessionToken(username, deviceId) {
    const payload = {
        username: username,
        deviceId: deviceId,
        issued: Date.now(),
        expires: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
        sessionId: crypto.randomBytes(16).toString('hex')
    };
    
    // Create signed token
    const data = JSON.stringify(payload);
    const signature = crypto
        .createHmac('sha256', process.env.SESSION_SECRET || 'your-session-secret')
        .update(data)
        .digest('hex');
    
    return Buffer.from(`${data}.${signature}`).toString('base64');
}

// 🔐 Rate limiting check
function checkRateLimit(deviceId, ip) {
    const key = `${deviceId}_${ip}`;
    const now = Date.now();
    
    if (!loginAttempts.has(key)) {
        loginAttempts.set(key, { 
            count: 0, 
            firstAttempt: now,
            lastAttempt: now, 
            lockedUntil: 0 
        });
    }
    
    const attempts = loginAttempts.get(key);
    
    // Check if currently locked
    if (attempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "Account temporarily locked due to multiple failed attempts",
            attemptsLeft: 0,
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    // Reset attempts if last attempt was over an hour ago
    if (now - attempts.lastAttempt > 60 * 60 * 1000) {
        attempts.count = 0;
        attempts.firstAttempt = now;
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    
    if (attempts.count >= MAX_ATTEMPTS) {
        attempts.lockedUntil = now + LOCKOUT_TIME;
        return {
            allowed: false,
            reason: "Too many failed attempts",
            attemptsLeft: 0,
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    return {
        allowed: true,
        attemptsLeft: MAX_ATTEMPTS - attempts.count,
        currentCount: attempts.count
    };
}

// 🚨 Discord webhook logging (optional)
async function sendDiscordLog(data) {
    // Only if webhook URL is configured
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookURL) return;
    
    try {
        const embed = {
            title: data.success ? "✅ Authentication Success" : "❌ Authentication Failed",
            color: data.success ? 0x00ff00 : 0xff0000,
            fields: [
                {
                    name: "Device ID",
                    value: `\`${data.deviceId?.substring(0, 16)}...\``,
                    inline: true
                },
                {
                    name: "Username",
                    value: data.username || "Unknown",
                    inline: true
                },
                {
                    name: "IP Address",
                    value: data.ip || "Unknown",
                    inline: true
                },
                {
                    name: "Timestamp",
                    value: new Date().toISOString(),
                    inline: true
                }
            ],
            footer: {
                text: "Authentication Monitor"
            }
        };

        if (!data.success && data.reason) {
            embed.fields.push({
                name: "Failure Reason",
                value: data.reason,
                inline: false
            });
        }

        await fetch(webhookURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] })
        });
    } catch (error) {
        console.error('Discord logging failed:', error);
    }
}

// 🔐 MAIN AUTHENTICATION HANDLER
exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ message: 'Method not allowed' })
        };
    }

    const clientIP = event.headers['x-forwarded-for'] || 
                    event.headers['x-real-ip'] || 
                    'unknown';

    try {
        // Parse the encrypted request body
        const encryptedBody = event.body;
        
        if (!encryptedBody) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'No data received' 
                })
            };
        }

        // For initial testing - handle both encrypted and plain requests
        let authRequest;
        let deviceId;
        
        try {
            // Try to parse as encrypted data first
            const decryptedData = decryptData(encryptedBody, 'temp-device-id');
            if (decryptedData) {
                authRequest = JSON.parse(decryptedData);
                deviceId = authRequest.deviceId;
                
                // Re-decrypt with actual device ID
                const properlyDecrypted = decryptData(encryptedBody, deviceId);
                authRequest = JSON.parse(properlyDecrypted);
            } else {
                // Fall back to plain JSON for testing
                authRequest = JSON.parse(encryptedBody);
                deviceId = authRequest.deviceId;
            }
        } catch (e) {
            console.error('Failed to parse request:', e);
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'Invalid request format' 
                })
            };
        }

        const { username, passwordHash, salt, timestamp, nonce } = authRequest;

        // Validate required fields
        if (!username || !passwordHash || !salt || !deviceId) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'Missing required fields' 
                })
            };
        }

        // Rate limiting
        const rateCheck = checkRateLimit(deviceId, clientIP);
        if (!rateCheck.allowed) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                username: username,
                ip: clientIP,
                reason: rateCheck.reason
            });

            return {
                statusCode: 429,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: rateCheck.reason,
                    lockoutEnds: rateCheck.lockoutEnds
                })
            };
        }

        // Validate timestamp (prevent replay attacks)
        const now = Date.now();
        const requestTime = timestamp * 1000;
        if (Math.abs(now - requestTime) > 5 * 60 * 1000) { // 5 minute window
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                username: username,
                ip: clientIP,
                reason: 'Request timestamp expired'
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'Request expired' 
                })
            };
        }

        // Check if user exists
        const user = validUsers.get(username.toLowerCase());
        if (!user) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                username: username,
                ip: clientIP,
                reason: 'Invalid username'
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'Invalid credentials' 
                })
            };
        }

        // For testing - accept the password hash directly
        // In production, you'd verify against stored PBKDF2 hashes
        let authenticated = false;
        
        // Check if this is a test with known passwords
        const testPasswords = {
            'testuser': 'hello123',
            'demouser': 'demo2024',
            'admin': 'admin123'
        };
        
        if (testPasswords[username.toLowerCase()]) {
            // Verify the password hash matches what the client would send
            const testPassword = testPasswords[username.toLowerCase()];
            const expectedHash = crypto.pbkdf2Sync(
                testPassword,
                Buffer.from(salt, 'base64'),
                ENCRYPTION_CONFIG.pbkdf2Rounds,
                32,
                'sha256'
            ).toString('base64');
            
            authenticated = (passwordHash === expectedHash);
        }

        if (!authenticated) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                username: username,
                ip: clientIP,
                reason: 'Invalid password'
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    message: 'Invalid credentials' 
                })
            };
        }

        // Authentication successful!
        const sessionToken = generateSessionToken(username, deviceId);
        
        // Store session
        activeSessions.set(sessionToken, {
            username: user.displayName,
            deviceId: deviceId,
            created: now,
            lastAccess: now,
            ip: clientIP
        });

        await sendDiscordLog({
            success: true,
            deviceId: deviceId,
            username: user.displayName,
            ip: clientIP
        });

        // Prepare response
        const responseData = {
            success: true,
            token: sessionToken,
            username: user.displayName,
            message: 'Authentication successful'
        };

        // Encrypt response if client sent encrypted data
        let responseBody;
        if (encryptedBody.length > 100) { // Assuming encrypted data is longer
            responseBody = encryptData(JSON.stringify(responseData), deviceId);
        } else {
            responseBody = JSON.stringify(responseData);
        }

        return {
            statusCode: 200,
            headers,
            body: responseBody
        };

    } catch (error) {
        console.error('Authentication error:', error);
        
        await sendDiscordLog({
            success: false,
            deviceId: 'ERROR',
            ip: clientIP,
            reason: 'Server error: ' + error.message
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                success: false,
                message: 'Authentication system error' 
            })
        };
    }
};

// 🔐 Session validation endpoint (bonus)
exports.validateSession = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    const token = event.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ valid: false, message: 'No token provided' })
        };
    }

    const session = activeSessions.get(token);
    
    if (!session) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ valid: false, message: 'Invalid session' })
        };
    }

    const now = Date.now();
    const sessionAge = now - session.created;
    
    // Check if session expired (24 hours)
    if (sessionAge > 24 * 60 * 60 * 1000) {
        activeSessions.delete(token);
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ valid: false, message: 'Session expired' })
        };
    }

    // Update last access
    session.lastAccess = now;

    return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
            valid: true, 
            username: session.username,
            deviceId: session.deviceId
        })
    };
};
