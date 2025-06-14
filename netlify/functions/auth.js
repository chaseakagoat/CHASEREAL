// Chase Auth API - Netlify Function
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
    const { key, deviceId, timestamp, nonce, sessionToken, clientHash } = JSON.parse(event.body);

    console.log('Auth request:', { key: key?.substring(0, 4) + '...', deviceId });

    // Validate required fields
    if (!key || !deviceId) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: 'Missing key or deviceId' })
      };
    }

    // Simple key validation (you can make this more complex later)
    const isValidKey = validateKey(key);
    
    if (!isValidKey) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          verified: false,
          message: 'Invalid or already used key' 
        })
      };
    }

    // Success response
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        verified: true,
        username: `user_${Date.now()}`,
        userId: `uid_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: Date.now()
      })
    };

  } catch (error) {
    console.error('Auth error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};

// Simple key validation function
function validateKey(key) {
  // For now, accept any key that's at least 6 characters
  // Later you can add database checks, one-time use, etc.
  return key && key.length >= 6;
}
