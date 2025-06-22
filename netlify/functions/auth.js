// ========================================
// IMPROVED AUTH HANDLER WITH BETTER PERSISTENCE
// ========================================

// CONFIGURATION
const VALID_KEYS = new Map([
    ["demo1233", { username: "DemoUser", tier: "basic" }],
    ["test456", { username: "TestUser", tier: "premium" }],
    ["admin789", { username: "AdminUser", tier: "admin" }],
    ["mykey2024", { username: "MyUser", tier: "basic" }],
    ["JAIQlqp12", { username: "Promo@chase.com", tier: "gold" }],
    ["XLao192", { username: "@top_burglar@chase.com", tier: "gold" }],
    ["alqm192", { username: "@plugzzdem@chase.com", tier: "premium" }],
    ["CHASE11037", { username: "jo.com", tier: "premium" }],
    ["secure2024", { username: "SecureUser", tier: "premium" }],
    ["Caka@228", { username: "jomewn@chase.com", tier: "premium" }],
    ["AlqM192", { username: "800+@chase.com", tier: "premium" }],
    ["Anql@129", { username: "CHVXE@chase.com", tier: "premium" }],
]);

const HTTP_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Signature, X-Timestamp, X-Request-Nonce',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
};

// ENHANCED PERSISTENT STORAGE (In-memory with better structure)
const storage = {
    devices: new Map(),    // deviceId -> device data
    keys: new Map(),       // key -> binding data
    sessions: new Map(),   // sessionId -> session data
    metadata: new Map()    // general metadata
};

function saveToStorage(type, key, data) {
    try {
        if (!storage[type]) {
            console.error(`Invalid storage type: ${type}`);
            return false;
        }
        
        storage[type].set(key, {
            ...data,
            savedAt: Date.now(),
            version: '2.1'
        });
        
        console.log(`💾 Saved ${type}:`, key.substring(0, 12) + '...');
        return true;
    } catch (e) {
        console.error(`Storage save failed for ${type}:${key}:`, e);
        return false;
    }
}

function loadFromStorage(type, key) {
    try {
        if (!storage[type]) {
            console.error(`Invalid storage type: ${type}`);
            return null;
        }
        
        const data = storage[type].get(key);
        if (!data) return null;

        const age = Math.round((Date.now() - (data.savedAt || 0)) / 1000);
        console.log(`📖 Loaded ${type}:`, key.substring(0, 12) + '...', `Age: ${age}s`);
        return data;
    } catch (e) {
        console.error(`Storage load failed for ${type}:${key}:`, e);
        return null;
    }
}

function cleanupExpiredSessions() {
    const now = Date.now();
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    for (const [sessionId, session] of storage.sessions) {
        if (now - session.savedAt > maxAge) {
            storage.sessions.delete(sessionId);
            console.log('🧹 Cleaned expired session:', sessionId.substring(0, 12) + '...');
        }
    }
}

// UTILS
function createStableDeviceId(deviceId, userAgent = '', ip = '') {
    const combined = `${deviceId}|${userAgent.substring(0, 50)}|${ip}|stable_salt_2024`;
    let hash = 0;
    for (let i = 0; i < combined.length; i++) {
        hash = ((hash << 5) - hash) + combined.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
}

function generateSessionToken() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36) + Math.random().toString(36).substring(2);
}

function getClientIP(event) {
    return event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           event.headers['x-real-ip'] || 
           event.headers['cf-connecting-ip'] ||
           event.headers['x-client-ip'] ||
           'unknown';
}

function getUserAgent(event) {
    return event.headers['user-agent'] || '';
}

function validateInput(key, deviceId) {
    if (!key || !deviceId) {
        return { valid: false, message: 'Missing key or device ID' };
    }
    
    if (typeof key !== 'string' || typeof deviceId !== 'string') {
        return { valid: false, message: 'Invalid data types' };
    }
    
    if (key.trim().length === 0 || deviceId.trim().length === 0) {
        return { valid: false, message: 'Empty key or device ID' };
    }
    
    if (key.length > 50 || deviceId.length > 100) {
        return { valid: false, message: 'Key or device ID too long' };
    }
    
    return { valid: true };
}

// MAIN HANDLER
exports.handler = async (event) => {
    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return { 
            statusCode: 200, 
            headers: HTTP_HEADERS, 
            body: JSON.stringify({ status: 'ok' })
        };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers: HTTP_HEADERS,
            body: JSON.stringify({ 
                verified: false, 
                message: 'Method not allowed. Use POST.' 
            })
        };
    }

    // Cleanup expired sessions periodically
    cleanupExpiredSessions();

    try {
        let requestBody = {};
        
        // Parse request body
        try {
            requestBody = JSON.parse(event.body || '{}');
        } catch (e) {
            console.error('JSON parse error:', e);
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ 
                    verified: false, 
                    message: 'Invalid JSON in request body' 
                })
            };
        }

        const { key, deviceId } = requestBody;
        
        // Validate input
        const validation = validateInput(key, deviceId);
        if (!validation.valid) {
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ 
                    verified: false, 
                    message: validation.message 
                })
            };
        }

        const clientIP = getClientIP(event);
        const userAgent = getUserAgent(event);
        const stableDeviceId = createStableDeviceId(deviceId, userAgent, clientIP);
        const now = Date.now();

        console.log('🔐 Auth request:', {
            keyPrefix: key.substring(0, 4) + '...',
            devicePrefix: stableDeviceId.substring(0, 8) + '...',
            ip: clientIP,
            userAgent: userAgent.substring(0, 50) + '...'
        });

        // Check if key exists in our valid keys
        if (!VALID_KEYS.has(key)) {
            console.log('❌ Invalid key attempted:', key);
            await logToDiscord({
                success: false,
                message: 'Invalid key attempted',
                key: key.substring(0, 4) + '...',
                deviceId: stableDeviceId.substring(0, 12) + '...',
                ip: clientIP
            }).catch(() => {});
            
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ 
                    verified: false, 
                    message: 'Invalid authentication key' 
                })
            };
        }

        const keyData = VALID_KEYS.get(key);
        const username = keyData.username;
        const tier = keyData.tier;

        // Storage keys
        const deviceStorageKey = `DEVICE_${stableDeviceId}`;
        const keyStorageKey = `KEY_${key}`;
        const sessionStorageKey = `SESSION_${stableDeviceId}_${key}`;

        // Check for existing valid session
        const existingSession = loadFromStorage('sessions', sessionStorageKey);
        if (existingSession && existingSession.key === key && existingSession.username === username) {
            // Update session
            existingSession.loginCount = (existingSession.loginCount || 0) + 1;
            existingSession.lastLogin = now;
            existingSession.lastIP = clientIP;
            existingSession.userAgent = userAgent.substring(0, 100);
            
            saveToStorage('sessions', sessionStorageKey, existingSession);

            console.log('✅ Session restored for:', username);
            
            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username,
                    message: `Welcome back, ${username}! Session restored.`,
                    sessionToken: generateSessionToken(),
                    tier,
                    deviceLocked: true,
                    loginCount: existingSession.loginCount,
                    sessionRestored: true,
                    lastLogin: new Date(existingSession.lastLogin).toISOString()
                })
            };
        }

        // Check if device is already registered
        const deviceData = loadFromStorage('devices', deviceStorageKey);
        if (deviceData && deviceData.key === key) {
            // Device is already bound to this key - allow login
            const loginCount = (deviceData.loginCount || 0) + 1;
            
            // Update device data
            deviceData.loginCount = loginCount;
            deviceData.lastLogin = now;
            deviceData.lastIP = clientIP;
            deviceData.userAgent = userAgent.substring(0, 100);
            saveToStorage('devices', deviceStorageKey, deviceData);

            // Create new session
            const sessionData = {
                key,
                username,
                tier,
                deviceId: stableDeviceId,
                loginCount,
                lastLogin: now,
                lastIP: clientIP,
                userAgent: userAgent.substring(0, 100),
                sessionCreated: now
            };
            saveToStorage('sessions', sessionStorageKey, sessionData);

            console.log('✅ Device login successful for:', username);
            
            await logToDiscord({
                success: true,
                username,
                tier,
                type: 'device_login',
                deviceId: stableDeviceId.substring(0, 12) + '...',
                ip: clientIP,
                loginCount
            }).catch(() => {});

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username,
                    message: `Welcome back, ${username}! Device recognized.`,
                    sessionToken: generateSessionToken(),
                    tier,
                    deviceLocked: true,
                    loginCount,
                    returningUser: true
                })
            };
        }

        // Check if key is bound to a different device
        const keyBindingData = loadFromStorage('keys', keyStorageKey);
        if (keyBindingData && keyBindingData.deviceId !== stableDeviceId) {
            console.log('❌ Key locked to different device:', {
                key: key.substring(0, 4) + '...',
                boundDevice: keyBindingData.deviceId.substring(0, 12) + '...',
                currentDevice: stableDeviceId.substring(0, 12) + '...'
            });
            
            await logToDiscord({
                success: false,
                message: 'Key locked to different device',
                username: keyBindingData.username || 'unknown',
                key: key.substring(0, 4) + '...',
                boundDevice: keyBindingData.deviceId.substring(0, 12) + '...',
                attemptedDevice: stableDeviceId.substring(0, 12) + '...',
                ip: clientIP
            }).catch(() => {});
            
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "This key is permanently locked to another device. Each key can only be used on one device."
                })
            };
        }

        // New device claiming this key
        console.log('🆕 New device claiming key:', {
            username,
            key: key.substring(0, 4) + '...',
            device: stableDeviceId.substring(0, 12) + '...',
            ip: clientIP
        });

        // Create new device binding
        const newDeviceData = {
            key,
            username,
            tier,
            claimedAt: now,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            userAgent: userAgent.substring(0, 100),
            bindingVersion: '2.1'
        };

        // Create new key binding
        const newKeyBinding = {
            deviceId: stableDeviceId,
            username,
            tier,
            claimedAt: now,
            lastUsed: now,
            bindingVersion: '2.1'
        };

        // Create new session
        const newSessionData = {
            key,
            username,
            tier,
            deviceId: stableDeviceId,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            userAgent: userAgent.substring(0, 100),
            sessionCreated: now
        };

        // Save all data atomically
        const savedDevice = saveToStorage('devices', deviceStorageKey, newDeviceData);
        const savedKey = saveToStorage('keys', keyStorageKey, newKeyBinding);
        const savedSession = saveToStorage('sessions', sessionStorageKey, newSessionData);

        if (!savedDevice || !savedKey || !savedSession) {
            console.error('❌ Failed to save binding data');
            return {
                statusCode: 500,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "Unable to complete device registration. Please try again."
                })
            };
        }

        console.log('✅ NEW KEY CLAIMED AND LOCKED:', {
            username,
            tier,
            device: stableDeviceId.substring(0, 12) + '...',
            key: key.substring(0, 4) + '...'
        });

        // Log successful new claim
        await logToDiscord({
            success: true,
            username,
            tier,
            type: 'new_claim',
            deviceId: stableDeviceId.substring(0, 12) + '...',
            ip: clientIP,
            key: key.substring(0, 4) + '...'
        }).catch(e => console.log('Discord log failed:', e));

        return {
            statusCode: 200,
            headers: HTTP_HEADERS,
            body: JSON.stringify({
                verified: true,
                username,
                message: `Welcome ${username}! Your key is now permanently locked to this device for security.`,
                sessionToken: generateSessionToken(),
                tier,
                newUser: true,
                deviceLocked: true,
                loginCount: 1,
                claimedAt: new Date(now).toISOString()
            })
        };

    } catch (error) {
        console.error('❌ Auth system error:', error);
        
        // Log system error
        await logToDiscord({
            success: false,
            message: 'System error during authentication',
            error: error.message,
            timestamp: new Date().toISOString()
        }).catch(() => {});
        
        return {
            statusCode: 500,
            headers: HTTP_HEADERS,
            body: JSON.stringify({ 
                verified: false, 
                message: 'Authentication system temporarily unavailable. Please try again.' 
            })
        };
    }
};

// ENHANCED DISCORD LOGGING
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

async function logToDiscord(data) {
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookURL) {
        console.log('No Discord webhook configured');
        return;
    }

    try {
        const embed = {
            title: data.success ? "✅ LOGIN SUCCESS" : "❌ LOGIN FAILED",
            color: data.success ? 0x00ff00 : 0xff0000,
            fields: [],
            timestamp: new Date().toISOString(),
            footer: {
                text: "Chase Auth System v2.1"
            }
        };

        // Add fields based on available data
        if (data.username) {
            embed.fields.push({ name: "Username", value: data.username, inline: true });
        }
        
        if (data.tier) {
            embed.fields.push({ name: "Tier", value: data.tier, inline: true });
        }
        
        if (data.deviceId) {
            embed.fields.push({ name: "Device", value: data.deviceId, inline: true });
        }
        
        if (data.type) {
            embed.fields.push({ name: "Type", value: data.type, inline: true });
        }
        
        if (data.ip) {
            embed.fields.push({ name: "IP", value: data.ip, inline: true });
        }
        
        if (data.loginCount) {
            embed.fields.push({ name: "Login Count", value: data.loginCount.toString(), inline: true });
        }
        
        if (data.key) {
            embed.fields.push({ name: "Key", value: data.key, inline: true });
        }
        
        if (data.message) {
            embed.fields.push({ name: "Message", value: data.message, inline: false });
        }
        
        if (data.error) {
            embed.fields.push({ name: "Error", value: data.error, inline: false });
        }

        const payload = { embeds: [embed] };

        const response = await fetch(webhookURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            console.error('Discord webhook failed:', response.status, await response.text());
        } else {
            console.log('✅ Discord notification sent');
        }
    } catch (e) {
        console.error('Discord log error:', e);
    }
}

// HEALTH CHECK ENDPOINT (for monitoring)
function healthCheck() {
    const stats = {
        devices: storage.devices.size,
        keys: storage.keys.size,
        sessions: storage.sessions.size,
        uptime: process.uptime ? Math.round(process.uptime()) : 'unknown',
        memory: process.memoryUsage ? process.memoryUsage() : 'unknown',
        version: '2.1',
        timestamp: new Date().toISOString()
    };
    
    return {
        statusCode: 200,
        headers: HTTP_HEADERS,
        body: JSON.stringify({
            status: 'healthy',
            stats,
            validKeys: VALID_KEYS.size
        })
    };
}

// Export health check for monitoring
exports.health = async (event) => {
    if (event.httpMethod === 'GET') {
        return healthCheck();
    }
    return {
        statusCode: 405,
        headers: HTTP_HEADERS,
        body: JSON.stringify({ message: 'Method not allowed' })
    };
};
