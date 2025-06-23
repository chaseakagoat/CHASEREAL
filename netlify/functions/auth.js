const admin = require('firebase-admin');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// Initialize Firebase Admin (only once)
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            type: "service_account",
            project_id: process.env.FIREBASE_PROJECT_ID,
            private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
            private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
            client_email: process.env.FIREBASE_CLIENT_EMAIL,
            client_id: process.env.FIREBASE_CLIENT_ID,
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            universe_domain: "googleapis.com"
        })
    });
}

const db = admin.firestore();

const COLLECTION_SESSIONS = 'sessions';
const COLLECTION_DEVICES = 'devices';
const COLLECTION_KEYS = 'keys';

// CONFIGURATION
const VALID_KEYS = new Map([
    ["demo1233", { username: "DemoUser", tier: "basic" }],
    ["test456", { username: "TestUser", tier: "premium" }],
    ["admin789", { username: "AdminUser", tier: "admin" }],
    ["mykey2024", { username: "MyUser", tier: "basic" }],
    ["Alao822", { username: "Promo@chase.com", tier: "gold" }],
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

// FIRESTORE HELPERS
async function saveToFirestore(collection, docId, data) {
    try {
        await db.collection(collection).doc(docId).set({
            ...data,
            savedAt: admin.firestore.FieldValue.serverTimestamp(),
            version: '2.0'
        }, { merge: true });
        console.log('💾 Saved:', collection, docId);
        return true;
    } catch (error) {
        console.error('Firestore save failed:', error);
        return false;
    }
}

async function loadFromFirestore(collection, docId) {
    try {
        const doc = await db.collection(collection).doc(docId).get();
        if (!doc.exists) {
            console.log('📖 Document not found:', collection, docId);
            return null;
        }
        const data = doc.data();
        console.log('📖 Loaded:', collection, docId);
        return data;
    } catch (error) {
        console.error('Firestore load failed:', error);
        return null;
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
           'unknown';
}

function getUserAgent(event) {
    return event.headers['user-agent'] || '';
}

// MAIN HANDLER
exports.handler = async (event) => {
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: HTTP_HEADERS, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers: HTTP_HEADERS,
            body: JSON.stringify({ verified: false, message: 'Method not allowed' })
        };
    }

    try {
        let requestBody = {};
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

        const { key, deviceId } = requestBody;
        const clientIP = getClientIP(event);
        const userAgent = getUserAgent(event);
        const stableDeviceId = createStableDeviceId(deviceId, userAgent, clientIP);

        console.log('🔐 Auth request:', key?.substring(0, 4) + '...', 'Device:', stableDeviceId.substring(0, 8), 'IP:', clientIP);

        if (!key || !deviceId || key.trim() === '' || deviceId.trim() === '') {
            return {
                statusCode: 400,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Missing authentication data' })
            };
        }

        if (!VALID_KEYS.has(key)) {
            console.log('❌ Invalid key:', key);
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({ verified: false, message: 'Invalid authentication key' })
            };
        }

        const keyData = VALID_KEYS.get(key);
        const username = keyData.username;
        const tier = keyData.tier;

        // Check existing session
        const sessionData = await loadFromFirestore(COLLECTION_SESSIONS, `${stableDeviceId}_${key}`);
        if (sessionData && sessionData.key === key && sessionData.username) {
            const updatedSession = {
                ...sessionData,
                loginCount: (sessionData.loginCount || 0) + 1,
                lastLogin: Date.now(),
                lastIP: clientIP
            };
            await saveToFirestore(COLLECTION_SESSIONS, `${stableDeviceId}_${key}`, updatedSession);

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username,
                    message: `Welcome back, ${username}! (Session restored)`,
                    sessionToken: generateSessionToken(),
                    tier,
                    deviceLocked: true,
                    loginCount: updatedSession.loginCount,
                    fastLogin: true
                })
            };
        }

        // Check device binding
        const deviceData = await loadFromFirestore(COLLECTION_DEVICES, stableDeviceId);
        if (deviceData && deviceData.key === key) {
            const loginCount = (deviceData.loginCount || 0) + 1;
            const updatedDevice = {
                ...deviceData,
                loginCount,
                lastLogin: Date.now(),
                lastIP: clientIP
            };
            await saveToFirestore(COLLECTION_DEVICES, stableDeviceId, updatedDevice);

            const newSession = {
                key,
                username,
                tier,
                deviceId: stableDeviceId,
                loginCount,
                lastLogin: Date.now(),
                lastIP: clientIP,
                sessionCreated: Date.now()
            };
            await saveToFirestore(COLLECTION_SESSIONS, `${stableDeviceId}_${key}`, newSession);

            return {
                statusCode: 200,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: true,
                    username,
                    message: `Welcome back, ${username}! Your session has been restored.`,
                    sessionToken: generateSessionToken(),
                    tier,
                    deviceLocked: true,
                    loginCount,
                    sessionRestored: true
                })
            };
        }

        // Check if key is bound to different device
        const keyBinding = await loadFromFirestore(COLLECTION_KEYS, key);
        if (keyBinding && keyBinding.deviceId !== stableDeviceId) {
            console.log('❌ Key locked to different device');
            return {
                statusCode: 401,
                headers: HTTP_HEADERS,
                body: JSON.stringify({
                    verified: false,
                    message: "This key is permanently locked to another device."
                })
            };
        }

        // New device/key binding
        const now = Date.now();

        const newDeviceData = {
            key,
            username,
            tier,
            claimedAt: now,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            userAgent: userAgent.substring(0, 100)
        };

        const newKeyBinding = {
            deviceId: stableDeviceId,
            username,
            tier,
            claimedAt: now,
            lastUsed: now
        };

        const newSessionData = {
            key,
            username,
            tier,
            deviceId: stableDeviceId,
            loginCount: 1,
            lastLogin: now,
            lastIP: clientIP,
            sessionCreated: now
        };

        // Save all data
        await saveToFirestore(COLLECTION_DEVICES, stableDeviceId, newDeviceData);
        await saveToFirestore(COLLECTION_KEYS, key, newKeyBinding);
        await saveToFirestore(COLLECTION_SESSIONS, `${stableDeviceId}_${key}`, newSessionData);

        console.log('✅ NEW KEY CLAIMED AND LOCKED - User:', username);

        // OPTIONAL: Discord logging
        await logToDiscord({
            success: true,
            username,
            tier,
            newClaim: true,
            deviceId: stableDeviceId.substring(0, 12) + '...',
            ip: clientIP
        }).catch(() => {});

        return {
            statusCode: 200,
            headers: HTTP_HEADERS,
            body: JSON.stringify({
                verified: true,
                username,
                message: `Welcome ${username}! Your key is now permanently locked to this device.`,
                sessionToken: generateSessionToken(),
                tier,
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
            body: JSON.stringify({ verified: false, message: 'Auth system unavailable.' })
        };
    }
};

// DISCORD LOGGING
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
                        { name: "Username", value: data.username, inline: true },
                        { name: "Device", value: data.deviceId, inline: true },
                        { name: "Type", value: data.newClaim ? "New Claim" : "Returning", inline: true },
                        { name: "Tier", value: data.tier, inline: true },
                        { name: "IP", value: data.ip, inline: true },
                        { name: "Time", value: new Date().toISOString(), inline: true }
                    ]
                }]
            })
        });
    } catch (e) {
        console.error('Discord log failed:', e);
    }
}
