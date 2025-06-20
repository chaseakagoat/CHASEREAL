// Chase KEY Authentication with Discord Webhook Logging

// 🔐 ENCRYPTED DISCORD WEBHOOK URL (Base64 encoded)
function getWebhookURL() {
    try {
        const encoded = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTM4MzU2NTk1MTU2NzUyODAxNy9XcEx6N0NfM29SanByNkRZTVR5VEY1aU5FTVpYUmRpcy1MZXJqbTc1eWx2SER1WFBSc1FBdXRWcUhuVW5WRFdROC1YUQ==";
        return Buffer.from(encoded, 'base64').toString('utf8');
    } catch (error) {
        console.error('Failed to decrypt webhook URL');
        return null;
    }
}

// 🔑 VALID KEYS (One-time use keys)
const validKeys = new Map([
    ["testkey123", "TestUser"],
    ["mypassword", "MyUser"], 
    ["demo2024", "DemoUser"],
    ["admin123", "AdminUser"],
    ["chase2024", "ChaseUser"],
    ["helloworld", "HelloUser"],
    ["password123", "PassUser"],
    ["secure123", "SecureUser"]
]);

// 📱 Track authorized devices (after successful key login)
const authorizedDevices = new Map();

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
                    value: `\`${data.deviceId ? data.deviceId.substring(0, 15) + '...' : 'Unknown'}\``,
                    inline: true
                },
                {
                    name: "👤 Username",
                    value: data.username || "Unknown",
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
                    value: data.authType || "Key Login",
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

        if (data.keyUsed) {
            embed.fields.push({
                name: "🔑 Key Used",
                value: `\`${data.keyUsed.substring(0, 6)}...\``,
                inline: true
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
        const { key, deviceId, username, password, authType, success } = JSON.parse(event.body);
        
        // Get client IP
        const clientIP = event.headers['x-forwarded-for'] || 
                        event.headers['x-real-ip'] || 
                        context.clientContext?.ip || 
                        'unknown';

        console.log('Auth request from IP:', clientIP, 'Device:', deviceId?.substring(0, 15) + '...', 'Type:', authType);

        // Handle Face ID result logging
        if (authType && authType.includes('FaceID')) {
            await sendDiscordLog({
                success: success === true,
                deviceId: deviceId,
                ip: clientIP,
                reason: success === true ? null : 'Face ID authentication failed',
                authType: authType,
                attemptCount: 1,
                username: authorizedDevices.get(deviceId) || 'Unknown'
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

        // Handle device authorization check (for Face ID)
        if (!key && deviceId) {
            const isAuthorized = authorizedDevices.has(deviceId);
            
            await sendDiscordLog({
                success: isAuthorized,
                deviceId: deviceId,
                ip: clientIP,
                reason: isAuthorized ? null : 'Device not authorized for Face ID',
                authType: 'Device Check',
                attemptCount: 1,
                username: authorizedDevices.get(deviceId) || 'Unknown'
            });

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    verified: isAuthorized,
                    username: authorizedDevices.get(deviceId),
                    message: isAuthorized ? 'Device authorized' : 'Device not authorized'
                })
            };
        }

        if (!key || !deviceId) {
            await sendDiscordLog({
                success: false,
                deviceId: deviceId || 'MISSING',
                ip: clientIP,
                reason: 'Missing key or device ID',
                authType: 'Key Login',
                attemptCount: 1
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ message: 'Missing key or deviceId' })
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
                authType: 'Key Login',
                attemptCount: MAX_ATTEMPTS,
                keyUsed: key
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

        // Check if key is valid
        if (!validKeys.has(key)) {
            // Check if device is already authorized (returning user)
            if (authorizedDevices.has(deviceId)) {
                const username = authorizedDevices.get(deviceId);
                
                await sendDiscordLog({
                    success: true,
                    deviceId: deviceId,
                    ip: clientIP,
                    reason: null,
                    authType: 'Returning User',
                    attemptCount: rateCheck.currentCount,
                    username: username
                });

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        verified: true,
                        username: username
                    })
                };
            }

            // Invalid key and not authorized device
            await sendDiscordLog({
                success: false,
                deviceId: deviceId,
                ip: clientIP,
                reason: 'Invalid key',
                authType: 'Key Login',
                attemptCount: rateCheck.currentCount,
                keyUsed: key
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    verified: false,
                    message: "Invalid or already used key"
                })
            };
        }

        // Key is valid - get username and authorize device
        const username = validKeys.get(key);
        
        // Save device for future Face ID access
        authorizedDevices.set(deviceId, username);
        
        // Remove key so it can't be reused
        validKeys.delete(key);
        
        await sendDiscordLog({
            success: true,
            deviceId: deviceId,
            ip: clientIP,
            reason: null,
            authType: 'Successful Key Login',
            attemptCount: rateCheck.currentCount,
            username: username,
            keyUsed: key
        });

        console.log('Successful key login - Device authorized for Face ID:', deviceId.substring(0, 15) + '...');

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                username: username
            })
        };

    } catch (error) {
        console.error('Auth error:', error);
        
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
