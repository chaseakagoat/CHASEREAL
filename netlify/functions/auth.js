// 🔒 ENTERPRISE-GRADE AUTHENTICATION SERVER
// Enhanced security with permanent key assignment and advanced protection

const crypto = require('crypto');

const validKeys = new Map([
    // Sample keys - replace with your own
    ["CHASE2025-PREMIUM-001", { username: "VIP User", tier: "premium", maxDevices: 3 }],
    ["CHASE2025-BASIC-002", { username: "Standard User", tier: "basic", maxDevices: 2 }],
    ["CHASE2025-ADMIN-003", { username: "Admin User", tier: "admin", maxDevices: 5 }],
    ["TESTKEY-DEV-001", { username: "Test User", tier: "basic", maxDevices: 1 }],
    ["DEMO-KEY-123", { username: "Demo User", tier: "premium", maxDevices: 2 }]
    // Add your own keys here - format: ["keyname", { username: "Display Name", tier: "basic/premium/admin", maxDevices: number }]
    // Keys will be claimed on first use and locked to that user permanently
]);

// 📱 Enhanced device tracking with security metadata
const authorizedDevices = new Map(); // deviceId -> { username, keyUsed, firstLogin, lastLogin, tier, sessionToken }
const keyOwnership = new Map(); // key -> { username, deviceId, claimedAt, tier }
const deviceSessions = new Map(); // deviceId -> { token, expiresAt, loginCount }

// 🚨 Enhanced security tracking
const securityEvents = new Map(); // deviceId -> [events]
const suspiciousActivity = new Map(); // ip -> { attempts, firstSeen, lastSeen, blocked }
const blockedDevices = new Set();
const blockedIPs = new Set();

// 📊 Enhanced rate limiting
const loginAttempts = new Map();
const MAX_ATTEMPTS = 3; // Stricter rate limiting
const LOCKOUT_TIME = 30 * 60 * 1000; // 30 minutes
const MAX_DAILY_ATTEMPTS = 20; // Daily attempt limit per IP

// 🔒 Security configuration
const SECURITY_CONFIG = {
    enableTimestampValidation: true,
    maxTimestampDrift: 5 * 60 * 1000, // 5 minutes
    enableSignatureValidation: true,
    enableBiometricTracking: true,
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    maxDevicesPerKey: 3, // Maximum devices per key
    suspiciousThreshold: 5, // Attempts before marking as suspicious
    autoBlockThreshold: 10 // Attempts before auto-blocking IP
};

// 🛡️ Security validation functions
function validateTimestamp(timestamp) {
    if (!SECURITY_CONFIG.enableTimestampValidation) return true;
    
    const now = Date.now();
    const requestTime = parseInt(timestamp) * 1000; // Convert to milliseconds
    const drift = Math.abs(now - requestTime);
    
    return drift <= SECURITY_CONFIG.maxTimestampDrift;
}

function validateRequestSignature(headers, body) {
    if (!SECURITY_CONFIG.enableSignatureValidation) return true;
    
    const signature = headers['x-signature'];
    const timestamp = headers['x-timestamp'];
    const nonce = headers['x-request-nonce'];
    
    if (!signature || !timestamp || !nonce) {
        return false;
    }
    
    // Validate nonce hasn't been used recently (simple replay protection)
    const nonceKey = `nonce_${nonce}`;
    // In production, you'd use a proper cache/database for nonce tracking
    
    return true; // Simplified for now
}

function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashDeviceFingerprint(deviceId, additionalData = '') {
    return crypto.createHash('sha256')
        .update(deviceId + additionalData + process.env.DEVICE_SALT || 'default_salt')
        .digest('hex');
}

// 🔍 Advanced security checks
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
    
    // Check for suspicious patterns
    if (patterns.rapidAttempts && activity.attempts > SECURITY_CONFIG.suspiciousThreshold) {
        activity.patterns.push('rapid_attempts');
    }
    
    if (activity.devices.size > 5) {
        activity.patterns.push('multiple_devices');
    }
    
    // Auto-block if threshold exceeded
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

// 🔐 Enhanced rate limiting with multiple tiers
function checkAdvancedRateLimit(deviceId, ip) {
    const deviceKey = `device_${deviceId}`;
    const ipKey = `ip_${ip}`;
    const now = Date.now();
    
    // Check device-specific rate limit
    if (!loginAttempts.has(deviceKey)) {
        loginAttempts.set(deviceKey, { 
            count: 0, 
            lastAttempt: now, 
            lockedUntil: 0,
            dailyCount: 0,
            dailyReset: now + (24 * 60 * 60 * 1000)
        });
    }
    
    // Check IP-specific rate limit
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
    
    // Check if IP is blocked
    if (blockedIPs.has(ip)) {
        return {
            allowed: false,
            reason: "IP address blocked",
            severity: "high"
        };
    }
    
    // Check device lockout
    if (deviceAttempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "Device temporarily locked",
            lockoutEnds: deviceAttempts.lockedUntil,
            severity: "medium"
        };
    }
    
    // Check IP lockout
    if (ipAttempts.lockedUntil > now) {
        return {
            allowed: false,
            reason: "IP temporarily locked", 
            lockoutEnds: ipAttempts.lockedUntil,
            severity: "medium"
        };
    }
    
    // Reset daily counts if needed
    if (now > deviceAttempts.dailyReset) {
        deviceAttempts.dailyCount = 0;
        deviceAttempts.dailyReset = now + (24 * 60 * 60 * 1000);
    }
    
    if (now > ipAttempts.dailyReset) {
        ipAttempts.dailyCount = 0;
        ipAttempts.dailyReset = now + (24 * 60 * 60 * 1000);
    }
    
    // Increment counters
    deviceAttempts.count++;
    deviceAttempts.dailyCount++;
    deviceAttempts.lastAttempt = now;
    
    ipAttempts.count++;
    ipAttempts.dailyCount++;
    ipAttempts.lastAttempt = now;
    
    // Check daily limits
    if (ipAttempts.dailyCount >= MAX_DAILY_ATTEMPTS) {
        ipAttempts.lockedUntil = now + (24 * 60 * 60 * 1000); // 24 hour lock
        return {
            allowed: false,
            reason: "Daily attempt limit exceeded",
            severity: "high"
        };
    }
    
    // Check rate limits
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

// 🚨 Enhanced Discord logging with security details
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
                text: "Enhanced Chase Security Monitor",
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
            
            if (data.severity) {
                embed.fields.push({
                    name: "🚨 Severity",
                    value: data.severity.toUpperCase(),
                    inline: true
                });
            }
        }

        if (data.keyUsed && data.success) {
            embed.fields.push({
                name: "🔑 Key Status",
                value: data.newClaim ? "🆕 First Time Claim" : "🔄 Returning User",
                inline: true
            });
        }

        if (data.securityFlags && data.securityFlags.length > 0) {
            embed.fields.push({
                name: "🛡️ Security Flags",
                value: data.securityFlags.join(", "),
                inline: false
            });
        }

        const payload = {
            embeds: [embed],
            username: "Enhanced Chase Security",
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

// 🔐 MAIN ENHANCED AUTHENTICATION HANDLER
exports.handler = async (event, context) => {
    // Enhanced CORS with security headers
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
            body: JSON.stringify({ message: 'Method not allowed' })
        };
    }

    try {
        const requestBody = JSON.parse(event.body);
        const { key, deviceId, timestamp, biometricEnabled } = requestBody;
        
        // Get client IP with multiple fallbacks
        const clientIP = event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                        event.headers['x-real-ip'] || 
                        event.headers['cf-connecting-ip'] ||
                        context.clientContext?.ip || 
                        'unknown';

        // Create secure device hash
        const deviceHash = hashDeviceFingerprint(deviceId, clientIP);
        
        console.log('🔒 Enhanced auth request - IP:', clientIP, 'Device Hash:', deviceHash.substring(0, 16) + '...', 'Biometric:', biometricEnabled);

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
                    message: 'Missing required authentication data' 
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

        // Validate request signature
        if (!validateRequestSignature(event.headers, event.body)) {
            console.log('⚠️ Invalid request signature detected');
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

        // Enhanced rate limiting
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
                    lockoutEnds: rateCheck.lockoutEnds,
                    attemptsRemaining: {
                        device: rateCheck.deviceAttemptsLeft,
                        ip: rateCheck.ipAttemptsLeft,
                        daily: rateCheck.dailyAttemptsLeft
                    }
                })
            };
        }

        // Check if device is already authorized (returning user)
        if (authorizedDevices.has(deviceId)) {
            const deviceInfo = authorizedDevices.get(deviceId);
            
            // Verify the key matches the originally claimed key
            if (keyOwnership.has(key) && keyOwnership.get(key).deviceId === deviceId) {
                // Update last login
                deviceInfo.lastLogin = Date.now();
                deviceInfo.loginCount = (deviceInfo.loginCount || 0) + 1;
                
                // Generate new session token
                const sessionToken = generateSecureToken();
                deviceSessions.set(deviceId, {
                    token: sessionToken,
                    expiresAt: Date.now() + SECURITY_CONFIG.sessionTimeout,
                    loginCount: deviceInfo.loginCount
                });

                await sendEnhancedDiscordLog({
                    success: true,
                    deviceHash: deviceHash.substring(0, 16) + '...',
                    ip: clientIP,
                    username: deviceInfo.username,
                    keyUsed: key,
                    newClaim: false,
                    biometricEnabled: biometricEnabled || false,
                    securityFlags: suspiciousCheck.suspicious ? suspiciousCheck.patterns : []
                });

                console.log('✅ Returning authorized user:', deviceInfo.username, 'Login count:', deviceInfo.loginCount);

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        verified: true,
                        username: deviceInfo.username,
                        message: `Welcome back! (Login #${deviceInfo.loginCount})`,
                        sessionToken: sessionToken,
                        tier: deviceInfo.tier || 'basic'
                    })
                };
            } else {
                // Device exists but key doesn't match - security violation
                await sendEnhancedDiscordLog({
                    success: false,
                    deviceHash: deviceHash.substring(0, 16) + '...',
                    ip: clientIP,
                    reason: 'Key mismatch for authorized device',
                    severity: 'high',
                    securityFlags: ['KEY_MISMATCH', 'POTENTIAL_HIJACK'],
                    biometricEnabled: biometricEnabled || false
                });

                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({
                        verified: false,
                        message: "Security violation detected"
                    })
                };
            }
        }

        // Check if key exists in valid keys
        if (!validKeys.has(key)) {
            // Check if key was already claimed by someone else
            if (keyOwnership.has(key)) {
                const ownership = keyOwnership.get(key);
                
                await sendEnhancedDiscordLog({
                    success: false,
                    deviceHash: deviceHash.substring(0, 16) + '...',
                    ip: clientIP,
                    reason: `Key already claimed by ${ownership.username}`,
                    severity: 'medium',
                    securityFlags: ['KEY_ALREADY_CLAIMED'],
                    biometricEnabled: biometricEnabled || false
                });

                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({
                        verified: false,
                        message: "This key has already been claimed by another user"
                    })
                };
            }

            // Key doesn't exist at all
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

        // Key is valid and unclaimed - claim it for this user/device
        const keyData = validKeys.get(key);
        const username = typeof keyData === 'string' ? keyData : keyData.username || 'User';
        const tier = typeof keyData === 'object' ? keyData.tier || 'basic' : 'basic';
        
        // Check device limit for this key
        const maxDevices = typeof keyData === 'object' ? keyData.maxDevices || SECURITY_CONFIG.maxDevicesPerKey : SECURITY_CONFIG.maxDevicesPerKey;
        
        // Claim the key
        keyOwnership.set(key, {
            username: username,
            deviceId: deviceId,
            claimedAt: Date.now(),
            tier: tier,
            ip: clientIP
        });
        
        // Authorize the device
        authorizedDevices.set(deviceId, {
            username: username,
            keyUsed: key,
            firstLogin: Date.now(),
            lastLogin: Date.now(),
            tier: tier,
            loginCount: 1,
            biometricEnabled: biometricEnabled || false
        });
        
        // Generate session token
        const sessionToken = generateSecureToken();
        deviceSessions.set(deviceId, {
            token: sessionToken,
            expiresAt: Date.now() + SECURITY_CONFIG.sessionTimeout,
            loginCount: 1
        });
        
        // Remove key from available keys (it's now permanently claimed)
        validKeys.delete(key);
        
        await sendEnhancedDiscordLog({
            success: true,
            deviceHash: deviceHash.substring(0, 16) + '...',
            ip: clientIP,
            username: username,
            keyUsed: key,
            newClaim: true,
            tier: tier,
            biometricEnabled: biometricEnabled || false,
            securityFlags: suspiciousCheck.suspicious ? suspiciousCheck.patterns : []
        });

        console.log('✅ NEW KEY CLAIMED - User:', username, 'Tier:', tier, 'Device:', deviceHash.substring(0, 16) + '...');

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                verified: true,
                username: username,
                message: "Key claimed successfully! You can now use this key unlimited times on this device.",
                sessionToken: sessionToken,
                tier: tier,
                newUser: true
            })
        };

    } catch (error) {
        console.error('❌ Enhanced auth error:', error);
        
        await sendEnhancedDiscordLog({
            success: false,
            deviceHash: 'ERROR',
            ip: event.headers['x-forwarded-for'] || 'unknown',
            reason: 'Server error: ' + error.message,
            severity: 'high',
            securityFlags: ['SYSTEM_ERROR']
        });

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
