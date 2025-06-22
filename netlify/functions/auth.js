// SIMPLE TEST VERSION - NO FIREBASE
const VALID_KEYS = new Map([
    ["demo1233", { username: "DemoUser", tier: "basic" }],
    ["test456", { username: "TestUser", tier: "premium" }],
    ["admin789", { username: "AdminUser", tier: "admin" }],
]);

const HTTP_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Signature, X-Timestamp, X-Request-Nonce',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
};

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
        const requestBody = JSON.parse(event.body || '{}');
        const { key, deviceId } = requestBody;

        console.log('🔐 Test auth request:', key, deviceId);

        if (!key || !deviceId) {
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
        
        console.log('✅ SUCCESS - User:', keyData.username);

        return {
            statusCode: 200,
            headers: HTTP_HEADERS,
            body: JSON.stringify({
                verified: true,
                username: keyData.username,
                message: `Welcome ${keyData.username}! (Test mode - no Firebase)`,
                sessionToken: "test-token-123",
                tier: keyData.tier,
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
