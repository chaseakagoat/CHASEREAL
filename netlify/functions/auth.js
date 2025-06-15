// Chase UDID Authentication with Advanced Security
const crypto = require('crypto');

// 🔐 ENCRYPTED DISCORD WEBHOOK URL (AES-256-CBC)
const ENCRYPTED_WEBHOOK = "fHVWWeTGXd5/CXS+2KXyLKmdlyyQ2XDZ0ZrxoT3Ge3KbTQ5qO5gFa3shjm8sDgTnzzN7GzUqDKT0n10u9lIEy0BxMGL0PvpK6dDZKDnxOniRBRX4Wo0EDeMcxMMYhOcG4t8irouxyNgrtNrg5n79PZPURNEIOC+kKsh+dayHjhg=";

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
        // No fallback - return null for security
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
            iss: 'chase-auth-system'
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
    
    // Check if currently locked out
    if (attempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "IP rate limited",
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    // Reset if last attempt was over 1 hour ago
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
            title: data.success ? "✅ SUCCESSFUL LOGIN" : "❌ FAILED LOGIN ATTEMPT",
            color: data.success ? 0x00ff00 : 0xff0000,
            fields: [
                {
                    name: "🔍 Device ID",
                    value: `\`${data.deviceId.substring(0, 20)}...\``,
                    inline: true
                },
                {
                    name: "📱 Status",
                    value: data.success ? "Authorized Access" : "Unauthorized Attempt",
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
                    value: data.authType || "UDID Check",
                    inline: true
                },
                {
                    name: "📊 Attempt Count",
                    value: data.attemptCount?.toString() || "1",
                    inline: true
                }
            ],
            footer: {
                text: "Chase Security Monitor - Enhanced",
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

        if (data.attemptCount >= 3) {
            embed.fields.push({
                name: "🚨 Security Alert",
                value: "Multiple failed attempts detected!",
                inline: false
            });
        }

        const payload = {
            embeds: [embed],
            username: "Chase Security Bot Enhanced",
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
    
    // Check if currently locked out
    if (attempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "Rate limited",
            attemptsLeft: 0,
            lockoutEnds: attempts.lockedUntil
        };
    }
    
    // Reset if last attempt was over 1 hour ago
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
        'Access-Control-Allow-Headers': 'Content-Type',
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

    try {
        const { deviceId, username, password } = JSON.parse(event.body);
        
        // Get client IP
        const clientIP = event.headers['x-forwarded-for']?.split(',')[0] || 
                        event.headers['x-real-ip'] || 
                        context.clientContext?.ip || 
                        'unknown';

        console.log('Auth request from IP:', clientIP, 'Device:', deviceId?.substring(0, 20) + '...');

        // Check IP rate limiting first
        const ipCheck = checkIPRateLimit(clientIP);
        if (!ipCheck.allowed) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId || 'UNKNOWN',
                ip: clientIP,
                reason: ipCheck.reason,
                authType: 'IP Rate Limit',
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
                authType: 'UDID Check',
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
                authType: 'UDID Check',
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
        
        // Determine auth type
        let authType = 'UDID Check';
        if (username && password) {
            authType = 'Credential Login';
        }

        // Log the attempt
        await sendDiscordLog({
            success: isAuthorized,
            deviceId: deviceId,
            ip: clientIP,
            reason: isAuthorized ? null : 'Device not in authorized list',
            authType: authType,
            attemptCount: rateCheck.currentCount
        });

        if (!isAuthorized) {
            console.log('Unauthorized device attempt:', deviceId);
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    verified: false,
                    message: 'Device not authorized' 
                })
            };
        }

        // Generate secure JWT token
        const token = generateJWT({
            deviceId: deviceId,
            authorized: true,
            ip: clientIP
        });

        if (!token) {
            console.error('Failed to generate JWT token');
            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({ message: 'Authentication token generation failed' })
            };
        }

        console.log('Authorized device access granted:', deviceId.substring(0, 20) + '...');

        // Success response with JWT
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                token: token,
                deviceId: deviceId,
                timestamp: Date.now(),
                message: 'Device authorized'
            })
        };

    } catch (error) {
        console.error('Auth error:', error);
        
        // Log critical errors
        await sendDiscordLog({
            success: false,
            deviceId: 'ERROR',
            ip: event.headers['x-forwarded-for'] || 'unknown',
            reason: 'Server error: ' + error.message,
            authType: 'System Error',
            attemptCount: 1
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ message: 'Internal server error' })
        };
    }
};
