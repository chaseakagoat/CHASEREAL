// 🔐 PRIVATE Chase UDID Authentication - ULTRA SECURE
const crypto = require('crypto');

// 🔐 ENCRYPTED DISCORD WEBHOOK URL (AES-256-CBC)
const ENCRYPTED_WEBHOOK = "fHVWWeTGXd5/CXS+2KXyLKmdlyyQ2XDZ0ZrxoT3Ge3KbTQ5qO5gFa3shjm8sDgTnzzN7GzUqDKT0n10u9lIEy0BxMGL0PvpK6dDZKDnxOniRBRX4Wo0EDeMcxMMYhOcG4t8irouxyNgrtNrg5n79PZPURNEIOC+kKsh+dayHjhg=";

// 🔐 PRIVATE ACCESS VERIFICATION
function verifyPrivateAccess(headers) {
    const providedKey = headers['x-private-key'];
    const expectedKey = process.env.PRIVATE_KEY;
    
    if (!providedKey || !expectedKey) {
        return false;
    }
    
    return providedKey === expectedKey;
}

// 🔐 Decrypt webhook URL using AES
function getWebhookURL() {
    try {
        const AES_KEY = Buffer.from(process.env.AES_KEY, 'base64');
        const AES_IV = Buffer.from(process.env.AES_IV, 'base64');
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, AES_IV);
        let url = decipher.update(ENCRYPTED_WEBHOOK, 'base64', 'utf8');
        url += decipher.final('utf8');
        return url;
    } catch (error) {
        console.error('🔒 AES decrypt failed:', error.message);
        return null;
    }
}

// 🔐 Authorized device UDIDs
const authorizedDevices = new Set([
    "stable_2992280087542020475_11759857", // Your device UDID
    // Add more authorized devices here
]);

// 📊 Track login attempts for rate limiting (per device)
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// 🚨 Track IP attempts for abuse detection
const ipAttempts = new Map();
const MAX_IP_ATTEMPTS = 20; // per hour
const IP_LOCKOUT_TIME = 60 * 60 * 1000; // 1 hour

// 🔐 JWT Helper Functions
function generateJWT(payload) {
    try {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            console.error('JWT_SECRET not found in environment variables');
            return null;
        }
        
        const header = { alg: 'HS256', typ: 'JWT' };
        const now = Math.floor(Date.now() / 1000);
        
        const jwtPayload = {
            ...payload,
            iat: now,
            exp: now + (60 * 60), // 1 hour expiration
            iss: 'chase-private-auth-system'
        };
        
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
        
        const signature = crypto
            .createHmac('sha256', secret)
            .update(`${encodedHeader}.${encodedPayload}`)
            .digest('base64url');
        
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error) {
        console.error('JWT generation failed:', error);
        return null;
    }
}

// 🚨 Check IP rate limiting
function checkIPRateLimit(ip) {
    const now = Date.now();
    
    if (!ipAttempts.has(ip)) {
        ipAttempts.set(ip, { count: 0, lastAttempt: now, lockedUntil: 0 });
    }
    
    const attempts = ipAttempts.get(ip);
    
    if (attempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "IP rate limited",
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    if (now - attempts.lastAttempt > IP_LOCKOUT_TIME) {
        attempts.count = 0;
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    
    if (attempts.count >= MAX_IP_ATTEMPTS) {
        attempts.lockedUntil = now + IP_LOCKOUT_TIME;
        return {
            allowed: false,
            reason: "Too many IP attempts",
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    return {
        allowed: true,
        attemptsLeft: MAX_IP_ATTEMPTS - attempts.count
    };
}

// 🚨 Send Discord webhook notification
async function sendDiscordLog(data) {
    const webhookURL = getWebhookURL();
    if (!webhookURL) {
        console.error('❌ No webhook URL available - logging disabled');
        return;
    }
    
    try {
        const embed = {
            title: data.success ? "✅ PRIVATE AUTH SUCCESS" : "❌ PRIVATE AUTH FAILED",
            color: data.success ? 0x00ff00 : 0xff0000,
            fields: [
                {
                    name: "🔍 Device ID",
                    value: `\`${data.deviceId.substring(0, 20)}...\``,
                    inline: true
                },
                {
                    name: "📱 Status",
                    value: data.success ? "Private Access Granted" : "Private Access Denied",
                    inline: true
                },
                {
                    name: "🕐 Timestamp",
                    value: new Date().toISOString(),
                    inline: true
                },
                {
                    name: "🌍 IP Address",
                    value: data.ip || "Unknown",
                    inline: true
                },
                {
                    name: "🔒 Auth Type",
                    value: "PRIVATE ENDPOINT",
                    inline: true
                },
                {
                    name: "📊 Attempt Count",
                    value: data.attemptCount?.toString() || "1",
                    inline: true
                }
            ],
            footer: {
                text: "🔐 Chase Private Security Monitor",
                icon_url: "https://cdn-icons-png.flaticon.com/512/174/174857.png"
            },
            timestamp: new Date().toISOString()
        };

        if (!data.success && data.reason) {
            embed.fields.push({
                name: "⚠️ Failure Reason",
                value: data.reason,
                inline: false
            });
        }

        const payload = {
            embeds: [embed],
            username: "🔐 Chase Private Security Bot",
            avatar_url: "https://cdn-icons-png.flaticon.com/512/3064/3064197.png"
        };

        const response = await fetch(webhookURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            console.error('Discord webhook failed:', response.status);
        }

    } catch (error) {
        console.error('Discord webhook error:', error);
    }
}

// 🔐 Check device rate limiting
function checkRateLimit(deviceId, ip) {
    const key = `${deviceId}_${ip}`;
    const now = Date.now();
    
    if (!loginAttempts.has(key)) {
        loginAttempts.set(key, { count: 0, lastAttempt: now, lockedUntil: 0 });
    }
    
    const attempts = loginAttempts.get(key);
    
    if (attempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "Rate limited",
            attemptsLeft: 0,
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    if (now - attempts.lastAttempt > 60 * 60 * 1000) {
        attempts.count = 0;
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    
    if (attempts.count >= MAX_ATTEMPTS) {
        attempts.lockedUntil = now + LOCKOUT_TIME;
        return {
            allowed: false,
            reason: "Too many attempts",
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

exports.handler = async (event, context) => {
    // Handle CORS
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, X-Private-Key',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    };

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

    // 🔐 VERIFY PRIVATE ACCESS FIRST
    if (!verifyPrivateAccess(event.headers)) {
        console.log('❌ Unauthorized access attempt to private endpoint');
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ message: 'Forbidden - Private endpoint' })
        };
    }

    try {
        const { deviceId, username, password } = JSON.parse(event.body);
        
        // Get client IP
        const clientIP = event.headers['x-forwarded-for']?.split(',')[0] || 
                        event.headers['x-real-ip'] || 
                        context.clientContext?.ip || 
                        'unknown';

        console.log('🔐 Private auth request from IP:', clientIP, 'Device:', deviceId?.substring(0, 20) + '...');

        // Check IP rate limiting first
        const ipCheck = checkIPRateLimit(clientIP);
        if (!ipCheck.allowed) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId || 'UNKNOWN',
                ip: clientIP,
                reason: ipCheck.reason,
                authType: 'Private IP Rate Limit',
                attemptCount: MAX_IP_ATTEMPTS
            });

            return {
                statusCode: 429,
                headers,
                body: JSON.stringify({ 
                    message: 'IP temporarily blocked due to abuse',
                    lockoutEnds: ipCheck.lockoutEnds
                })
            };
        }

        if (!deviceId) {
            await sendDiscordLog({
                success: false,
                deviceId: 'MISSING',
                ip: clientIP,
                reason: 'Missing device ID',
                authType: 'Private UDID Check',
                attemptCount: 1
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ message: 'Missing deviceId' })
            };
        }

        // Check device rate limiting
        const rateCheck = checkRateLimit(deviceId, clientIP);
        if (!rateCheck.allowed) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                ip: clientIP,
                reason: rateCheck.reason,
                authType: 'Private UDID Check',
                attemptCount: MAX_ATTEMPTS
            });

            return {
                statusCode: 429,
                headers,
                body: JSON.stringify({ 
                    message: 'Too many attempts. Try again later.',
                    lockoutEnds: rateCheck.lockoutEnds
                })
            };
        }

        // Check if device is authorized
        const isAuthorized = authorizedDevices.has(deviceId);
        
        // Log the attempt
        await sendDiscordLog({
            success: isAuthorized,
            deviceId: deviceId,
            ip: clientIP,
            reason: isAuthorized ? null : 'Device not in private authorized list',
            authType: 'Private UDID Check',
            attemptCount: rateCheck.currentCount
        });

        if (!isAuthorized) {
            console.log('Unauthorized device attempt on private endpoint:', deviceId);
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    verified: false,
                    message: 'Device not authorized for private access' 
                })
            };
        }

        // Generate secure JWT token
        const token = generateJWT({
            deviceId: deviceId,
            authorized: true,
            ip: clientIP,
            privateAccess: true
        });

        if (!token) {
            console.error('Failed to generate JWT token');
            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({ message: 'Authentication token generation failed' })
            };
        }

        console.log('✅ Private authorized device access granted:', deviceId.substring(0, 20) + '...');

        // Success response with JWT
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                token: token,
                deviceId: deviceId,
                timestamp: Date.now(),
                message: 'Private device access authorized'
            })
        };

    } catch (error) {
        console.error('Private auth error:', error);
        
        // Log critical errors
        await sendDiscordLog({
            success: false,
            deviceId: 'ERROR',
            ip: event.headers['x-forwarded-for'] || 'unknown',
            reason: 'Private server error: ' + error.message,
            authType: 'Private System Error',
            attemptCount: 1
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ message: 'Internal server error' })
        };
    }
};
