const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();

// 🔒 Enhanced authenticateKey function with permanent key claiming
exports.authenticateKey = functions.https.onRequest(async (req, res) => {
  // Enhanced CORS with security headers
  res.set('Access-Control-Allow-Origin', '*');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  
  // Handle preflight request
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type, X-Device-Fingerprint, X-Timestamp, X-Signature');
    res.status(204).send('');
    return;
  }
  
  // Validate request method
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      verified: false, 
      message: 'Method not allowed' 
    });
  }
  
  try {
    const { key, deviceId, timestamp, biometricEnabled } = req.body;
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    
    console.log('🔑 Auth request - IP:', clientIP, 'Device:', deviceId?.substring(0, 15) + '...', 'Key provided:', !!key);
    
    // Basic validation
    if (!key || !deviceId) {
      return res.status(400).json({ 
        verified: false, 
        message: 'Missing key or deviceId' 
      });
    }
    
    // Rate limiting check
    const rateLimitResult = await checkRateLimit(deviceId, clientIP);
    if (!rateLimitResult.allowed) {
      return res.status(429).json({
        verified: false,
        message: rateLimitResult.reason,
        lockoutEnds: rateLimitResult.lockoutEnds
      });
    }
    
    // Check if device is already authorized (returning user)
    const deviceQuery = await db.collection('authorizedDevices')
      .where('deviceId', '==', deviceId)
      .limit(1)
      .get();
    
    if (!deviceQuery.empty) {
      const deviceDoc = deviceQuery.docs[0];
      const deviceData = deviceDoc.data();
      
      // Verify the key matches the originally claimed key
      if (deviceData.keyUsed === key) {
        // Update last login
        await db.collection('authorizedDevices').doc(deviceDoc.id).update({
          lastLogin: admin.firestore.FieldValue.serverTimestamp(),
          loginCount: admin.firestore.FieldValue.increment(1),
          lastIP: clientIP
        });
        
        // Generate new session token
        const sessionToken = generateSessionToken();
        
        // Log successful return
        await logSecurityEvent({
          success: true,
          deviceId: deviceId,
          ip: clientIP,
          username: deviceData.username,
          authType: 'Returning User',
          biometricEnabled: biometricEnabled || false
        });
        
        console.log('✅ Returning authorized user:', deviceData.username);
        
        return res.status(200).json({
          verified: true,
          username: deviceData.username,
          message: `Welcome back! (Login #${(deviceData.loginCount || 0) + 1})`,
          sessionToken: sessionToken,
          tier: deviceData.tier || 'basic'
        });
      } else {
        // Device exists but key doesn't match - security violation
        await logSecurityEvent({
          success: false,
          deviceId: deviceId,
          ip: clientIP,
          reason: 'Key mismatch for authorized device',
          severity: 'high',
          securityFlags: ['KEY_MISMATCH', 'POTENTIAL_HIJACK'],
          biometricEnabled: biometricEnabled || false
        });
        
        return res.status(401).json({
          verified: false,
          message: "Security violation detected"
        });
      }
    }
    
    // Check if key exists and is available
    const keyQuery = await db.collection('validKeys')
      .where('key', '==', key)
      .limit(1)
      .get();
    
    if (keyQuery.empty) {
      // Check if key was already claimed by someone else
      const claimedKeyQuery = await db.collection('claimedKeys')
        .where('key', '==', key)
        .limit(1)
        .get();
      
      if (!claimedKeyQuery.empty) {
        const claimedData = claimedKeyQuery.docs[0].data();
        
        await logSecurityEvent({
          success: false,
          deviceId: deviceId,
          ip: clientIP,
          reason: `Key already claimed by ${claimedData.username}`,
          severity: 'medium',
          securityFlags: ['KEY_ALREADY_CLAIMED'],
          biometricEnabled: biometricEnabled || false
        });
        
        return res.status(401).json({
          verified: false,
          message: "This key has already been claimed by another user"
        });
      }
      
      // Key doesn't exist at all
      await logSecurityEvent({
        success: false,
        deviceId: deviceId,
        ip: clientIP,
        reason: 'Invalid authentication key',
        severity: 'medium',
        keyUsed: key.substring(0, 6) + '...',
        biometricEnabled: biometricEnabled || false
      });
      
      return res.status(401).json({
        verified: false,
        message: "Invalid authentication key"
      });
    }
    
    // Key is valid and unclaimed - claim it for this user/device
    const keyDoc = keyQuery.docs[0];
    const keyData = keyDoc.data();
    const username = keyData.username || 'User';
    const tier = keyData.tier || 'basic';
    
    // Start transaction to claim key atomically
    await db.runTransaction(async (transaction) => {
      // Move key to claimed keys
      const claimedKeyRef = db.collection('claimedKeys').doc();
      transaction.set(claimedKeyRef, {
        key: key,
        username: username,
        deviceId: deviceId,
        claimedAt: admin.firestore.FieldValue.serverTimestamp(),
        tier: tier,
        ip: clientIP,
        biometricEnabled: biometricEnabled || false
      });
      
      // Authorize the device
      const deviceRef = db.collection('authorizedDevices').doc();
      transaction.set(deviceRef, {
        username: username,
        keyUsed: key,
        deviceId: deviceId,
        firstLogin: admin.firestore.FieldValue.serverTimestamp(),
        lastLogin: admin.firestore.FieldValue.serverTimestamp(),
        tier: tier,
        loginCount: 1,
        biometricEnabled: biometricEnabled || false,
        lastIP: clientIP
      });
      
      // Remove key from available keys
      transaction.delete(db.collection('validKeys').doc(keyDoc.id));
    });
    
    // Generate session token
    const sessionToken = generateSessionToken();
    
    // Log successful claim
    await logSecurityEvent({
      success: true,
      deviceId: deviceId,
      ip: clientIP,
      username: username,
      keyUsed: key,
      authType: 'Successful Key Claim',
      tier: tier,
      biometricEnabled: biometricEnabled || false,
      newClaim: true
    });
    
    console.log('✅ NEW KEY CLAIMED - User:', username, 'Tier:', tier, 'Device:', deviceId.substring(0, 15) + '...');
    
    return res.status(200).json({
      verified: true,
      username: username,
      message: "Key claimed successfully! You can now use this key unlimited times on this device.",
      sessionToken: sessionToken,
      tier: tier,
      newUser: true
    });
    
  } catch (error) {
    console.error('❌ Authentication error:', error);
    
    // Log system error
    await logSecurityEvent({
      success: false,
      deviceId: 'ERROR',
      ip: req.headers['x-forwarded-for'] || 'unknown',
      reason: 'Server error: ' + error.message,
      severity: 'high',
      securityFlags: ['SYSTEM_ERROR']
    }).catch(() => {}); // Don't let logging errors crash the response
    
    return res.status(500).json({ 
      verified: false,
      message: 'Authentication system temporarily unavailable' 
    });
  }
});

// 🔐 Rate limiting function
async function checkRateLimit(deviceId, ip) {
  const now = Date.now();
  const maxAttempts = 3;
  const lockoutTime = 30 * 60 * 1000; // 30 minutes
  
  try {
    // Check device attempts
    const deviceAttemptsRef = db.collection('rateLimits').doc(`device_${deviceId}`);
    const deviceDoc = await deviceAttemptsRef.get();
    
    let deviceAttempts = { count: 0, lastAttempt: now, lockedUntil: 0 };
    if (deviceDoc.exists) {
      deviceAttempts = deviceDoc.data();
    }
    
    // Check if currently locked out
    if (deviceAttempts.lockedUntil > now) {
      return {
        allowed: false,
        reason: "Device temporarily locked",
        lockoutEnds: deviceAttempts.lockedUntil
      };
    }
    
    // Reset if last attempt was over 1 hour ago
    if (now - deviceAttempts.lastAttempt > 60 * 60 * 1000) {
      deviceAttempts.count = 0;
    }
    
    deviceAttempts.count++;
    deviceAttempts.lastAttempt = now;
    
    if (deviceAttempts.count >= maxAttempts) {
      deviceAttempts.lockedUntil = now + lockoutTime;
    }
    
    // Update rate limit record
    await deviceAttemptsRef.set(deviceAttempts);
    
    if (deviceAttempts.lockedUntil > now) {
      return {
        allowed: false,
        reason: "Too many attempts",
        lockoutEnds: deviceAttempts.lockedUntil
      };
    }
    
    return {
      allowed: true,
      attemptsLeft: maxAttempts - deviceAttempts.count
    };
    
  } catch (error) {
    console.error('Rate limit check failed:', error);
    // If rate limiting fails, allow the request but log the error
    return { allowed: true };
  }
}

// 🔑 Generate secure session token
function generateSessionToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 64; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result + '_' + Date.now();
}

// 🚨 Security event logging
async function logSecurityEvent(eventData) {
  try {
    await db.collection('securityLogs').add({
      ...eventData,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      userAgent: 'iOS Chase App',
      platform: 'iOS'
    });
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
}

// 🔧 Helper function to initialize keys (run this once to add keys to Firestore)
exports.initializeKeys = functions.https.onRequest(async (req, res) => {
  // Only allow this in development or with proper authentication
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }
  
  const { adminKey } = req.body;
  
  // Simple admin key check (replace with your own secure method)
  if (adminKey !== 'your-admin-key-here') {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  try {
    // Sample keys to initialize (customize these)
    const keysToAdd = [
      { key: 'demo123', username: 'DemoUser', tier: 'basic' },
      { key: 'test456', username: 'TestUser', tier: 'premium' },
      { key: 'admin789', username: 'AdminUser', tier: 'admin' },
      // Add your own keys here
    ];
    
    const batch = db.batch();
    
    keysToAdd.forEach(keyData => {
      const keyRef = db.collection('validKeys').doc();
      batch.set(keyRef, {
        ...keyData,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        active: true
      });
    });
    
    await batch.commit();
    
    return res.status(200).json({ 
      success: true, 
      message: `Initialized ${keysToAdd.length} keys`,
      keys: keysToAdd.map(k => k.key)
    });
    
  } catch (error) {
    console.error('Key initialization error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to initialize keys' 
    });
  }
});
