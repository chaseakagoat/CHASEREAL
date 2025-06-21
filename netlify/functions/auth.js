// 🔑 SIMPLE KEY-BASED AUTHENTICATION FOR CHASE APP
// Matches your iOS app's current implementation

// 🔑 VALID KEYS (One-time use keys that work with your app)
const validKeys = new Map([
    ["testkey123", "TestUser"],
    ["hello123", "TestUser"],      // For easy testing
    ["demo2024", "DemoUser"], 
    ["admin123", "AdminUser"],
    ["chase2024", "ChaseUser"],
    ["mypassword", "MyUser"],
    ["password123", "PassUser"],
    ["secure123", "SecureUser"]
]);

// 📱 Track authorized devices (after successful key login)
const authorizedDevices = new Map();

// 📊 Track login attempts for rate limiting
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// 🚨 Discord webhook logging (optional)
async function sendDiscordLog(data) {
    // Only log if webhook URL is configured
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookURL) return;
    
    try {
        const embed = {
            title: data.success ? "✅ LOGIN SUCCESS" : "❌ LOGIN FAILED",
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
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

    } catch (error) {
        console.error('Discord webhook failed:', error);
    }
}

// 🔐 Rate limiting check
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

// 🔐 MAIN AUTHENTICATION HANDLER
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
        const requestBody = JSON.parse(event.body);
        const { key, deviceId } = requestBody;
        
        // Get client IP
        const clientIP = event.headers['x-forwarded-for'] || 
                        event.headers['x-real-ip'] || 
                        context.clientContext?.ip || 
                        'unknown';

        console.log('🔑 Auth request from IP:', clientIP, 'Device:', deviceId?.substring(0, 15) + '...', 'Key provided:', !!key);

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
                body: JSON.stringify({ 
                    verified: false,
                    message: 'Missing key or deviceId' 
                })
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
                    verified: false,
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

                console.log('✅ Returning authorized user:', username);

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        verified: true,
                        username: username,
                        message: "Welcome back!"
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

            console.log('❌ Invalid key attempted:', key.substring(0, 6) + '...');

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
        
        // Save device for future access
        authorizedDevices.set(deviceId, username);
        
        // Remove key so it can't be reused (one-time use)
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

        console.log('✅ Successful key login - Device authorized:', deviceId.substring(0, 15) + '...', 'User:', username);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                username: username,
                message: "Login successful! Device authorized."
            })
        };

    } catch (error) {
        console.error('❌ Auth error:', error);
        
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
            body: JSON.stringify({ 
                verified: false,
                message: 'Authentication system error' 
            })
        };
    }
};
