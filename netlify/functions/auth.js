// 🔒 BULLETPROOF DEVICE-LOCKED AUTHENTICATION
// Fixed to prevent blocking legitimate users

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
    ["secure2024", { username: "SecureUser", tier: "premium" }]
]);

const HTTP_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Signature, X-Timestamp, X-Request-Nonce',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
};

// ========================================
// SIMPLE STORAGE FUNCTIONS
// ========================================

function saveToStorage(key, data) {
    try {
        process.env[key] = JSON.stringify(data);
        return true;
    } catch (e) {
        console.error('Storage save failed:', e);
        return false;
    }
}

function loadFromStorage(key) {
    try {
        const data = process.env[key];
        return data ? JSON.parse(data) : null;
    } catch (e) {
        console.error('Storage load failed:', e);
        return null;
    }
}

// ========================================
// UTILITY FUNCTIONS
// ========================================

function createDeviceId(deviceId, ip = '') {
    // Create a consistent device identifier
    let hash = 0;
    const str = deviceId + ip + 'salt2024';
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
}

function generateToken() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function getClientIP(event, context) {
    return event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           event.headers['x-real-ip'] || 
           'unknown';
}

// ========================================
// MAIN HANDLER - SIMPLIFIED AND RELIABLE
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
        // Parse request
        let requestBody;
        try {
            requestBody = JSON.parse(event.body || '{}');
        } catch (e) {
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Invalid request format' })
            };
        }

        const { key, deviceId } = requestBody;
        
        // Basic validation
        if (!key || !deviceId || key.trim() === '' || deviceId.trim() === '') {
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Missing key or device ID' })
            };
        }

        const clientIP = getClientIP(event, context);
        const finalDeviceId = createDeviceId(deviceId, clientIP);
        
        console.log('🔐 Auth request - Key:', key.substring(0, 4) + '...', 'Device:', finalDeviceId.substring(0, 8) + '...');

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
        // DEVICE BINDING LOGIC
        // ========================================

        const deviceStorageKey = `DEVICE_${finalDeviceId}`;
        const keyStorageKey = `KEY_${key}`;

        // Check if this device already has this key
        const deviceData = loadFromStorage(deviceStorageKey);
        if (deviceData && deviceData.key === key) {
            // ✅ EXISTING USER ON SAME DEVICE
            deviceData.loginCount = (deviceData.loginCount || 0) + 1;
            deviceData.lastLogin = Date.now();
            saveToStorage(deviceStorageKey, deviceData);

            console.log('✅ Returning user - User:', username, 'Logins:', deviceData.loginCount);

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username: username,
                    message: `Welcome back, ${username}! Login #${deviceData.loginCount}`,
                    sessionToken: generateToken(),
                    tier: tier,
                    deviceLocked: true,
                    loginCount: deviceData.loginCount
                })
            };
        }

        // Check if key is already bound to another device
        const keyBindingData = loadFromStorage(keyStorageKey);
        if (keyBindingData && keyBindingData.deviceId !== finalDeviceId) {
            // ❌ KEY IS LOCKED TO DIFFERENT DEVICE
            console.log('❌ Key locked to different device - Key:', key.substring(0, 4) + '...');
            
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "This key is permanently locked to another device. Each key can only be used on one device."
                })
            };
        }

        // ✅ NEW DEVICE CLAIM - Lock key to this device
        const now = Date.now();
        
        const newDeviceData = {
            key: key,
            username: username,
            tier: tier,
            claimedAt: now,
            loginCount: 1,
            lastLogin: now
        };

        const newKeyBinding = {
            deviceId: finalDeviceId,
            username: username,
            tier: tier,
            claimedAt: now
        };

        // Save both bindings
        const deviceSaved = saveToStorage(deviceStorageKey, newDeviceData);
        const keySaved = saveToStorage(keyStorageKey, newKeyBinding);

        if (!deviceSaved || !keySaved) {
            console.error('❌ Failed to save device/key binding');
            return {
                statusCode: 500,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "Unable to complete device registration. Please try again."
                })
            };
        }

        console.log('✅ NEW KEY CLAIMED - User:', username, 'Device:', finalDeviceId.substring(0, 8) + '...');

        return {
            statusCode: 200,
            headers: HTTP_HEADERS,
            body: JSON.stringify({
                verified: true,
                username: username,
                message: `Welcome ${username}! Your key is now permanently locked to this device. You can login unlimited times, but this key won't work on other devices.`,
                sessionToken: generateToken(),
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
                message: 'Authentication system temporarily unavailable' 
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
                        { name: "Time", value: new Date().toISOString(), inline: true },
                        { name: "Status", value: data.newClaim ? "New Claim" : "Returning User", inline: true }
                    ]
                }]
            })
        });
    } catch (e) {
        console.error('Discord log failed:', e);
    }
}
