// 🔒 DEVICE-LOCKED NETLIFY AUTHENTICATION
// Keys can ONLY be used on the device they were first claimed on

// 🔑 AVAILABLE KEYS (Once claimed, locked to that device forever)
const validKeys = new Map([
    ["demo123", { username: "DemoUser", tier: "basic", created: Date.now() }],
    ["test456", { username: "TestUser", tier: "premium", created: Date.now() }],
    ["admin789", { username: "AdminUser", tier: "admin", created: Date.now() }],
    ["mykey2024", { username: "MyUser", tier: "basic", created: Date.now() }],
    ["secure2024", { username: "SecureUser", tier: "premium", created: Date.now() }],
    // Add your own keys here
]);

// 📱 Device tracking - keys are forever locked to first device used
const deviceKeyBindings = new Map(); // deviceId -> { key, username, tier, claimedAt, loginCount }
const keyDeviceBindings = new Map(); // key -> { deviceId, username, claimedAt, locked: true }

// 🚨 Security tracking
const securityEvents = new Map();
const suspiciousActivity = new Map();
const blockedDevices = new Set();
const blockedIPs = new Set();

// 📊 Rate limiting
const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;
const LOCKOUT_TIME = 30 * 60 * 1000; // 30 minutes
const MAX_DAILY_ATTEMPTS = 20;

// 🔒 Security configuration
const SECURITY_CONFIG = {
    enableTimestampValidation: true,
    maxTimestampDrift: 5 * 60 * 1000, // 5 minutes
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    suspiciousThreshold: 5,
    autoBlockThreshold: 10
};

// 🛡️ Security validation functions
function validateTimestamp(timestamp) {
    if (!SECURITY_CONFIG.enableTimestampValidation) return true;
    
    const now = Date.now();
    const requestTime = parseInt(timestamp) * 1000;
    const drift = Math.abs(now - requestTime);
    
    return drift <= SECURITY_CONFIG.maxTimestampDrift;
}

function generateSecureToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 64; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result + '_' + Date.now();
}

function hashDeviceFingerprint(deviceId, additionalData = '') {
    let hash = 0;
    const str = deviceId + additionalData + 'salt123';
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
}

// 🔍 Security checks
function detectSuspiciousActivity(ip, deviceId, patterns = {}) {
    const now = Date.now();
    
    if (!suspiciousActivity.has(ip)) {
        suspiciousActivity.set(ip, {
            attempts: 0,
            firstSeen: now,
            lastSeen: now,
            devices: new Set(),
            patterns: [],
            blocked: false
        });
    }
    
    const activity = suspiciousActivity.get(ip);
    activity.attempts++;
    activity.lastSeen = now;
    activity.devices.add(deviceId);
    
    if (patterns.rapidAttempts && activity.attempts > SECURITY_CONFIG.suspiciousThreshold) {
        activity.patterns.push('rapid_attempts');
    }
    
    if (activity.devices.size > 5) {
        activity.patterns.push('multiple_devices');
    }
    
    if (activity.attempts >= SECURITY_CONFIG.autoBlockThreshold) {
        activity.blocked = true;
        blockedIPs.add(ip);
        return { blocked: true, reason: 'Automatic block due to suspicious activity' };
    }
    
    return { 
        blocked: false, 
        suspicious: activity.patterns.length > 0,
        patterns: activity.patterns 
    };
}

// 🔐 Rate limiting
function checkAdvancedRateLimit(deviceId, ip) {
    const deviceKey = `device_${deviceId}`;
    const ipKey = `ip_${ip}`;
    const now = Date.now();
    
    if (!loginAttempts.has(deviceKey)) {
        loginAttempts.set(deviceKey, { 
            count: 0, 
            lastAttempt: now, 
            lockedUntil: 0,
            dailyCount: 0,
            dailyReset: now + (24 * 60 * 60 * 1000)
        });
    }
    
    if (!loginAttempts.has(ipKey)) {
        loginAttempts.set(ipKey, { 
            count: 0, 
            lastAttempt: now, 
            lockedUntil: 0,
            dailyCount: 0,
            dailyReset: now + (24 * 60 * 60 * 1000)
        });
    }
    
    const deviceAttempts = loginAttempts.get(deviceKey);
    const ipAttempts = loginAttempts.get(ipKey);
    
    if (blockedIPs.has(ip)) {
        return {
            allowed: false,
            reason: "IP address blocked",
            severity: "high"
        };
    }
    
    if (deviceAttempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "Device temporarily locked",
            lockoutEnds: deviceAttempts.lockedUntil,
            severity: "medium"
        };
    }
    
    if (ipAttempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "IP temporarily locked", 
            lockoutEnds: ipAttempts.lockedUntil,
            severity: "medium"
        };
    }
    
    if (now > deviceAttempts.dailyReset) {
        deviceAttempts.dailyCount = 0;
        deviceAttempts.dailyReset = now + (24 * 60 * 60 * 1000);
    }
    
    if (now > ipAttempts.dailyReset) {
        ipAttempts.dailyCount = 0;
        ipAttempts.dailyReset = now + (24 * 60 * 60 * 1000);
    }
    
    deviceAttempts.count++;
    deviceAttempts.dailyCount++;
    deviceAttempts.lastAttempt = now;
    
    ipAttempts.count++;
    ipAttempts.dailyCount++;
    ipAttempts.lastAttempt = now;
    
    if (ipAttempts.dailyCount >= MAX_DAILY_ATTEMPTS) {
        ipAttempts.lockedUntil = now + (24 * 60 * 60 * 1000);
        return {
            allowed: false,
            reason: "Daily attempt limit exceeded",
            severity: "high"
        };
    }
    
    if (deviceAttempts.count >= MAX_ATTEMPTS) {
        deviceAttempts.lockedUntil = now + LOCKOUT_TIME;
    }
    
    if (ipAttempts.count >= MAX_ATTEMPTS) {
        ipAttempts.lockedUntil = now + LOCKOUT_TIME;
    }
    
    return {
        allowed: true,
        deviceAttemptsLeft: Math.max(0, MAX_ATTEMPTS - deviceAttempts.count),
        ipAttemptsLeft: Math.max(0, MAX_ATTEMPTS - ipAttempts.count),
        dailyAttemptsLeft: Math.max(0, MAX_DAILY_ATTEMPTS - ipAttempts.dailyCount)
    };
}

// 🚨 Discord logging
async function sendEnhancedDiscordLog(data) {
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookURL) return;
    
    try {
        const embed = {
            title: data.success ? "✅ LOGIN SUCCESS" : "❌ LOGIN FAILED",
            color: data.success ? 0x00ff00 : (data.severity === 'high' ? 0xff0000 : 0xff8800),
            fields: [
                {
                    name: "🔍 Device Hash",
                    value: `\`${data.deviceHash || 'Unknown'}\``,
                    inline: true
                },
                {
                    name: "👤 Username",
                    value: data.username || "Unknown",
                    inline: true
                },
                {
                    name: "🔒 Auth Status",
                    value: data.success ? "✅ Authorized" : "❌ Denied",
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
                    name: "📱 Platform",
                    value: data.biometricEnabled ? "iOS (Biometric)" : "iOS (Standard)",
                    inline: true
                }
            ],
            footer: {
                text: "Device-Locked Security Monitor",
                icon_url: "https://cdn-icons-png.flaticon.com/512/3064/3064197.png"
            },
            timestamp: new Date().toISOString()
        };

        if (!data.success) {
            embed.fields.push({
                name: "⚠️ Failure Reason",
                value: data.reason || "Unknown error",
                inline: false
            });
        }

        if (data.keyUsed && data.success) {
            embed.fields.push({
                name: "🔑 Key Status",
                value: data.newClaim ? "🆕 First Time Claim (Device Locked)" : "🔄 Returning to Locked Device",
                inline: true
            });
        }

        const payload = {
            embeds: [embed],
            username: "Device-Locked Security",
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

// 🔐 MAIN DEVICE-LOCKED AUTHENTICATION HANDLER
exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, X-Signature, X-Timestamp, X-Request-Nonce',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ 
                verified: false,
                message: 'Method not allowed' 
            })
        };
    }

    try {
        const requestBody = JSON.parse(event.body);
        const { key, deviceId, timestamp, biometricEnabled } = requestBody;
        
        const clientIP = event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                        event.headers['x-real-ip'] || 
                        event.headers['cf-connecting-ip'] ||
                        context.clientContext?.ip || 
                        'unknown';

        const deviceHash = hashDeviceFingerprint(deviceId, clientIP);
        
        console.log('🔒 Device-locked auth request - IP:', clientIP, 'Device Hash:', deviceHash.substring(0, 16) + '...', 'Biometric:', biometricEnabled);

        // Validate required fields
        if (!key || !deviceId) {
            await sendEnhancedDiscordLog({
                success: false,
                deviceHash: deviceHash.substring(0, 16) + '...',
                ip: clientIP,
                reason: 'Missing required authentication data',
                severity: 'medium',
                biometricEnabled: biometricEnabled || false
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

        // Validate timestamp if provided
        if (timestamp && !validateTimestamp(timestamp)) {
            await sendEnhancedDiscordLog({
                success: false,
                deviceHash: deviceHash.substring(0, 16) + '...',
                ip: clientIP,
                reason: 'Invalid timestamp - possible replay attack',
                severity: 'high',
                biometricEnabled: biometricEnabled || false
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    verified: false,
                    message: 'Request timestamp invalid' 
                })
            };
        }

        // Check for suspicious activity
        const suspiciousCheck = detectSuspiciousActivity(clientIP, deviceId, { rapidAttempts: true });
        if (suspiciousCheck.blocked) {
            await sendEnhancedDiscordLog({
                success: false,
                deviceHash: deviceHash.substring(0, 16) + '...',
                ip: clientIP,
                reason: suspiciousCheck.reason,
                severity: 'high',
                securityFlags: ['AUTO_BLOCKED', 'SUSPICIOUS_ACTIVITY'],
                biometricEnabled: biometricEnabled || false
            });

            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ 
                    verified: false,
                    message: 'Access denied due to security policy' 
                })
            };
        }

        // Rate limiting
        const rateCheck = checkAdvancedRateLimit(deviceId, clientIP);
        if (!rateCheck.allowed) {
            await sendEnhancedDiscordLog({
                success: false,
                deviceHash: deviceHash.substring(0, 16) + '...',
                ip: clientIP,
                reason: rateCheck.reason,
                severity: rateCheck.severity || 'medium',
                securityFlags: ['RATE_LIMITED'],
                biometricEnabled: biometricEnabled || false
            });

            return {
                statusCode: 429,
                headers,
                body: JSON.stringify({ 
                    verified: false,
                    message: rateCheck.reason,
                    lockoutEnds: rateCheck.lockoutEnds
                })
            };
        }

        // 🔑 KEY-DEVICE BINDING LOGIC - THIS IS THE MAIN CHANGE!

        // Check if this key is already bound to a device
        if (keyDeviceBindings.has(key)) {
            const keyBinding = keyDeviceBindings.get(key);
            
            // Key is already claimed - check if it's THIS device
            if (keyBinding.deviceId === deviceId) {
                // ✅ SAME DEVICE - Allow login and update stats
                const deviceInfo = deviceKeyBindings.get(deviceId);
                deviceInfo.loginCount = (deviceInfo.loginCount || 0) + 1;
                
                const sessionToken = generateSecureToken();

                await sendEnhancedDiscordLog({
                    success: true,
                    deviceHash: deviceHash.substring(0, 16) + '...',
                    ip: clientIP,
                    username: deviceInfo.username,
                    keyUsed: key,
                    newClaim: false,
                    biometricEnabled: biometricEnabled || false
                });

                console.log('✅ Device-locked key accepted - User:', deviceInfo.username, 'Login count:', deviceInfo.loginCount);

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        verified: true,
                        username: deviceInfo.username,
                        message: `Welcome back! This key is locked to your device. (Login #${deviceInfo.loginCount})`,
                        sessionToken: sessionToken,
                        tier: deviceInfo.tier || 'basic',
                        deviceLocked: true
                    })
                };
            } else {
                // ❌ DIFFERENT DEVICE - Reject login
                await sendEnhancedDiscordLog({
                    success: false,
                    deviceHash: deviceHash.substring(0, 16) + '...',
                    ip: clientIP,
                    reason: `Key is locked to a different device (claimed by ${keyBinding.username})`,
                    severity: 'high',
                    securityFlags: ['DEVICE_MISMATCH', 'KEY_LOCKED_TO_OTHER_DEVICE'],
                    biometricEnabled: biometricEnabled || false
                });

                console.log('❌ Key locked to different device - Rejected');

                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({
                        verified: false,
                        message: "This key is permanently locked to a different device and cannot be used here."
                    })
                };
            }
        }

        // Key is not yet bound to any device - check if it's valid
        if (!validKeys.has(key)) {
            await sendEnhancedDiscordLog({
                success: false,
                deviceHash: deviceHash.substring(0, 16) + '...',
                ip: clientIP,
                reason: 'Invalid authentication key',
                severity: 'medium',
                keyUsed: key.substring(0, 6) + '...',
                biometricEnabled: biometricEnabled || false
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    verified: false,
                    message: "Invalid authentication key"
                })
            };
        }

        // ✅ NEW KEY CLAIM - Lock key to this device forever
        const keyData = validKeys.get(key);
        const username = typeof keyData === 'string' ? keyData : keyData.username || 'User';
        const tier = typeof keyData === 'object' ? keyData.tier || 'basic' : 'basic';
        const now = Date.now();
        
        // Create device binding
        deviceKeyBindings.set(deviceId, {
            key: key,
            username: username,
            tier: tier,
            claimedAt: now,
            loginCount: 1
        });
        
        // Create key binding (lock key to this device)
        keyDeviceBindings.set(key, {
            deviceId: deviceId,
            username: username,
            claimedAt: now,
            locked: true
        });
        
        // Remove key from available pool
        validKeys.delete(key);
        
        const sessionToken = generateSecureToken();
        
        await sendEnhancedDiscordLog({
            success: true,
            deviceHash: deviceHash.substring(0, 16) + '...',
            ip: clientIP,
            username: username,
            keyUsed: key,
            newClaim: true,
            tier: tier,
            biometricEnabled: biometricEnabled || false
        });

        console.log('✅ NEW KEY LOCKED TO DEVICE - User:', username, 'Tier:', tier, 'Device:', deviceHash.substring(0, 16) + '...');

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                username: username,
                message: "Key claimed and permanently locked to this device! You can now use this key unlimited times, but ONLY on this device.",
                sessionToken: sessionToken,
                tier: tier,
                newUser: true,
                deviceLocked: true
            })
        };

    } catch (error) {
        console.error('❌ Device-locked auth error:', error);
        
        await sendEnhancedDiscordLog({
            success: false,
            deviceHash: 'ERROR',
            ip: event.headers['x-forwarded-for'] || 'unknown',
            reason: 'Server error: ' + error.message,
            severity: 'high',
            securityFlags: ['SYSTEM_ERROR']
        }).catch(() => {});

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                verified: false,
                message: 'Authentication system temporarily unavailable' 
            })
        };
    }
};
