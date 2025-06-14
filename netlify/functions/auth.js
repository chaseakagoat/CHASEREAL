// Encrypted UDID Authentication
const authorizedDevices = new Set([
  // Add your device UDIDs here - get from console logs
  "stable_123456789_abc12345", // Your device UDID will look like this
  // Add more as needed
]);

exports.handler = async (event, context) => {
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
    const { deviceId } = JSON.parse(event.body);

    if (!deviceId) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: 'Missing deviceId' })
      };
    }

    const isAuthorized = authorizedDevices.has(deviceId);
    console.log('Device auth check:', deviceId, 'Authorized:', isAuthorized);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        verified: isAuthorized,
        deviceId: deviceId,
        timestamp: Date.now()
      })
    };

  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: 'Server error' })
    };
  }
};
