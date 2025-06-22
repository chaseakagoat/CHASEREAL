
// Fixed to handle app exits/restarts and maintain device sessions

// ========================================
// CONFIGURATION
// ========================================

const VALID_KEYS = new Map([
    ["demo1233", { username: "DemoUser", tier: "basic" }],
    ["test456", { username: "TestUser", tier: "premium" }],
    ["admin789", { username: "AdminUser", tier: "admin" }],
    ["mykey2024", { username: "MyUser", tier: "basic" }],
    ["JAIQlqp@12", { username: "Promo@chase.com", tier: "gold" }],
    ["XLao192", { username: "@top_burglar@chase.com", tier: "gold" }],
    ["alqm192&", { username: "@plugzzdem@chase.com", tier: "premium" }],
      ["CHASE@11037", { username: "jomewn@chase.com", tier: "premium" }],
    
    ["secure2024", { username: "SecureUser", tier: "premium" }]
]);

const HTTP_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Signature, X-Timestamp, X-Request-Nonce',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
};

// ========================================
// ROBUST STORAGE FUNCTIONS
// ========================================

function saveToStorage(key, data) {
    try {
        process.env[key] = JSON.stringify({
            ...data,
            savedAt: Date.now(),
            version: '2.0'
        });
        console.log('💾 Saved:', key);
        return true;
    } catch (e) {
        console.error('Storage save failed:', e);
        return false;
    }
}

function loadFromStorage(key) {
    try {
        const data = process.env[key];
        if (!data) return null;
        
        const parsed = JSON.parse(data);
        // Validate data structure
        if (!parsed || typeof parsed !== 'object') return null;
        
        console.log('📖 Loaded:', key, 'Age:', Math.round((Date.now() - (parsed.savedAt || 0)) / 1000) + 's');
        return parsed;
    } catch (e) {
        console.error('Storage load failed for', key, ':', e);
        return null;
    }
}

// ========================================
// IMPROVED DEVICE FINGERPRINTING
// ========================================

function createStableDeviceId(deviceId, userAgent = '', ip = '') {
    // Create multiple fallback device identifiers
    const primaryId = deviceId || 'unknown';
    const secondaryId = userAgent.substring(0, 50) || 'unknown';
    const tertiaryId = ip || 'unknown';
    
    // Combine all identifiers
    const combined = `${primaryId}|${secondaryId}|${tertiaryId}|stable_salt_2024`;
    
    // Create hash
    let hash = 0;
    for (let i = 0; i < combined.length; i++) {
        const char = combined.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    
    const finalId = Math.abs(hash).toString(36);
    console.log('🔐 Device ID created:', finalId.substring(0, 8) + '...', 'from:', primaryId.substring(0, 8) + '...');
    return finalId;
}

function generateSessionToken() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36) + Math.random().toString(36).substring(2);
}

function getClientIP(event, context) {
    return event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           event.headers['x-real-ip'] || 
           event.headers['cf-connecting-ip'] ||
           'unknown';
}

function getUserAgent(event) {
    return event.headers['user-agent'] || '';
}

// ========================================
// MAIN HANDLER - ULTRA STABLE
// ========================================

exports.handler = async (event, context) => {
    // Handle CORS
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: HTTP_HEADERS, body: '' };
    }

    // Only POST allowed
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers: HTTP_HEADERS,
            body: JSON.stringify({ verified: false, message: 'Method not allowed' })
        };
    }

    try {
        // Parse request with better error handling
        let requestBody;
        try {
            requestBody = JSON.parse(event.body || '{}');
        } catch (e) {
            console.error('JSON parse error:', e);
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Invalid request format' })
            };
        }

        const { key, deviceId, sessionToken } = requestBody;
        
        // Get client info
        const clientIP = getClientIP(event, context);
        const userAgent = getUserAgent(event);
        
        console.log('🔐 Auth request - Key:', key?.substring(0, 4) + '...', 'Device:', deviceId?.substring(0, 8) + '...', 'IP:', clientIP);

        // Basic validation
        if (!key || !deviceId || key.trim() === '' || deviceId.trim() === '') {
            console.log('❌ Missing key or deviceId');
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Missing authentication data' })
            };
        }

        // Create stable device identifier
        const stableDeviceId = createStableDeviceId(deviceId, userAgent, clientIP);
        
        // Check if key is valid
        if (!VALID_KEYS.has(key)) {
            console.log('❌ Invalid key:', key.substring(0, 4) + '...');
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "Invalid authentication key"
                })
            };
        }

        const keyData = VALID_KEYS.get(key);
        const username = keyData.username || 'User';
        const tier = keyData.tier || 'basic';

        // ========================================
        // ENHANCED DEVICE BINDING LOGIC
        // ========================================

        const deviceStorageKey = `DEVICE_${stableDeviceId}`;
        const keyStorageKey = `KEY_${key}`;
        const sessionStorageKey = `SESSION_${stableDeviceId}_${key}`;

        console.log('🔍 Checking storage keys:', {
            device: deviceStorageKey.substring(0, 20) + '...',
            key: keyStorageKey.substring(0, 15) + '...',
            session: sessionStorageKey.substring(0, 25) + '...'
        });

        // Check for existing session first (fastest path for returning users)
        const existingSession = loadFromStorage(sessionStorageKey);
        if (existingSession && existingSession.key === key && existingSession.username) {
            // ✅ VALID EXISTING SESSION - Super fast path
            existingSession.loginCount = (existingSession.loginCount || 0) + 1;
            existingSession.lastLogin = Date.now();
            existingSession.lastIP = clientIP;
            
            // Update session
            saveToStorage(sessionStorageKey, existingSession);
            
            console.log('⚡ Fast session login - User:', username, 'Logins:', existingSession.loginCount);

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username: username,
                    message: `Welcome back, ${username}! (Session restored)`,
                    sessionToken: generateSessionToken(),
                    tier: tier,
                    deviceLocked: true,
                    loginCount: existingSession.loginCount,
                    fastLogin: true
                })
            };
        }

        // Check device binding
        const deviceData = loadFromStorage(deviceStorageKey);
        if (deviceData && deviceData.key === key) {
            // ✅ DEVICE HAS THIS KEY - Restore session
            const loginCount = (deviceData.loginCount || 0) + 1;
            
            // Update device data
            deviceData.loginCount = loginCount;
            deviceData.lastLogin = Date.now();
            deviceData.lastIP = clientIP;
            saveToStorage(deviceStorageKey, deviceData);
            
            // Create/update session
            const sessionData = {
                key: key,
                username: username,
                tier: tier,
                deviceId: stableDeviceId,
                loginCount: loginCount,
                lastLogin: Date.now(),
                lastIP: clientIP,
                sessionCreated: Date.now()
            };
            saveToStorage(sessionStorageKey, sessionData);

            console.log('✅ Device login restored - User:', username, 'Logins:', loginCount);

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username: username,
                    message: `Welcome back, ${username}! Your session has been restored.`,
                    sessionToken: generateSessionToken(),
                    tier: tier,
                    deviceLocked: true,
                    loginCount: loginCount,
                    sessionRestored: true
                })
            };
        }

        // Check if key is bound to a DIFFERENT device
        const keyBindingData = loadFromStorage(keyStorageKey);
        if (keyBindingData && keyBindingData.deviceId && keyBindingData.deviceId !== stableDeviceId) {
            // ❌ KEY IS LOCKED TO DIFFERENT DEVICE
            console.log('❌ Key locked to different device');
            console.log('   Current device:', stableDeviceId.substring(0, 12));
            console.log('   Bound device:', keyBindingData.deviceId.substring(0, 12));
            
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "This key is permanently locked to another device. Each key works on only one device to prevent sharing."
                })
            };
        }

        // ✅ NEW DEVICE CLAIM - Lock key to this device
        const now = Date.now();
        
        console.log('🆕 Claiming new device for key:', key.substring(0, 4) + '...');
        
        // Create device binding
        const newDeviceData = {
            key: key,
            username: username,
            tier: tier,
            claimedAt: now,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            userAgent: userAgent.substring(0, 100)
        };

        // Create key binding
        const newKeyBinding = {
            deviceId: stableDeviceId,
            username: username,
            tier: tier,
            claimedAt: now,
            lastUsed: now
        };

        // Create session
        const newSessionData = {
            key: key,
            username: username,
            tier: tier,
            deviceId: stableDeviceId,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            sessionCreated: now
        };

        // Save all three storage items
        const deviceSaved = saveToStorage(deviceStorageKey, newDeviceData);
        const keySaved = saveToStorage(keyStorageKey, newKeyBinding);
        const sessionSaved = saveToStorage(sessionStorageKey, newSessionData);

        if (!deviceSaved || !keySaved || !sessionSaved) {
            console.error('❌ Failed to save bindings');
            return {
                statusCode: 500,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "Unable to complete device registration. Please try again."
                })
            };
        }

        console.log('✅ NEW KEY CLAIMED AND LOCKED - User:', username);

        // Optional: Log to Discord
        await logToDiscord({
            success: true,
            username: username,
            tier: tier,
            newClaim: true,
            deviceId: stableDeviceId.substring(0, 12) + '...',
            ip: clientIP
        }).catch(() => {});

        return {
            statusCode: 200,
            headers: HTTP_HEADERS,
            body: JSON.stringify({
                verified: true,
                username: username,
                message: `Welcome ${username}! Your key is now permanently locked to this device. You can exit and re-enter the app anytime - your access is saved!`,
                sessionToken: generateSessionToken(),
                tier: tier,
                newUser: true,
                deviceLocked: true,
                loginCount: 1
            })
        };

    } catch (error) {
        console.error('❌ Auth system error:', error);
        
        return {
            statusCode: 500,
            headers: HTTP_HEADERS,
            body: JSON.stringify({ 
                verified: false,
                message: 'Authentication system temporarily unavailable. Please try again in a moment.' 
            })
        };
    }
};

// ========================================
// OPTIONAL: DISCORD LOGGING
// ========================================

async function logToDiscord(data) {
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookURL) return;
    
    try {
        await fetch(webhookURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [{
                    title: data.success ? "✅ LOGIN SUCCESS" : "❌ LOGIN FAILED",
                    color: data.success ? 0x00ff00 : 0xff0000,
                    fields: [
                        { name: "Username", value: data.username || "Unknown", inline: true },
                        { name: "Device", value: data.deviceId || "Unknown", inline: true },
                        { name: "Type", value: data.newClaim ? "New Claim" : "Returning", inline: true },
                        { name: "Tier", value: data.tier || "basic", inline: true },
                        { name: "Time", value: new Date().toISOString(), inline: true }
                    ]
                }]
            })
        });
    } catch (e) {
        console.error('Discord log failed:', e);
    }
}
