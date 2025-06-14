// Chase UDID Authentication with Discord Webhook Logging
const crypto = require('crypto');

// 🔐 ENCRYPTED DISCORD WEBHOOK URL (Base64 encoded)
const encryptedWebhookData = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTM4MzU2NTk1MTU2NzUyODAxNy9XcEx6N0NfM29SanByNkRZTVR5VEY1aU5FTVpYUmRpcy1MZXJqbTc1eWx2SER1WFBSc1FBdXRWcUhuVW5WRFdROC1YUQ==";

// 🔐 Decrypt webhook URL
function getWebhookURL() {
    try {
        return Buffer.from(encryptedWebhookData, 'base64').toString('utf8');
    } catch (error) {
        console.error('Failed to decrypt webhook URL');
        return null;
    }
}

// 🔐 Authorized device UDIDs (Real Apple UDIDs)
const authorizedDevices = new Set([
    "00008130-000671DC2EF2001C", // Your real UDID
    // Add more authorized devices here
]);

// 📊 Track login attempts for rate limiting
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// 🚨 Send Discord webhook notification
async function sendDiscordLog(data) {
    const webhookURL = getWebhookURL();
    if (!webhookURL) return;
    
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
                text: "Chase Security Monitor",
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
            username: "Chase Security Bot",
            avatar_url: "https://cdn-icons-png.flaticon.com/512/3064/3064197.png"
        };

        await fetch(webhookURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

    } catch (error) {
        console.error('Discord webhook failed:', error);
    }
}

// 🔐 Check and update rate limiting
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
        const { deviceId, username, password, authType, success } = JSON.parse(event.body);
        
        // Get client IP
        const clientIP = event.headers['x-forwarded-for'] || 
                        event.headers['x-real-ip'] || 
                        context.clientContext?.ip || 
                        'unknown';

        console.log('Auth request from IP:', clientIP, 'Device:', deviceId?.substring(0, 20) + '...', 'Type:', authType);

        // Handle Face ID result logging
        if (authType && authType.includes('FaceID')) {
            await sendDiscordLog({
                success: success === true,
                deviceId: deviceId,
                ip: clientIP,
                reason: success === true ? null : 'Face ID authentication failed',
                authType: authType,
                attemptCount: 1
            });

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    logged: true,
                    timestamp: Date.now()
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

        // Check rate limiting
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
        
        // Determine auth type (only if not already provided)
        let finalAuthType = authType || 'UDID Check';
        if (!authType && username && password) {
            finalAuthType = 'Credential Login';
        }

        // Log the attempt
        await sendDiscordLog({
            success: isAuthorized,
            deviceId: deviceId,
            ip: clientIP,
            reason: isAuthorized ? null : 'Device not in authorized list',
            authType: finalAuthType,
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

        console.log('Authorized device access granted:', deviceId.substring(0, 20) + '...');

        // Success response
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
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
