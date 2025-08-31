// api/signature.js
const crypto = require('crypto');

export default function handler(req, res) {
  // CORS 설정
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const { timestamp, accessKey, secretKey, method = 'GET', uri = '/api/signature' } = req.query;

    if (!timestamp || !accessKey || !secretKey) {
      return res.status(400).json({
        error: 'Missing required parameters: timestamp, accessKey, secretKey'
      });
    }

    // 네이버 클라우드 플랫폼 서명 생성
    const space = ' ';
    const newLine = '\n';
    const url = uri;
    const message = method + space + url + newLine + timestamp + newLine + accessKey;
    
    // HMAC-SHA256 서명 생성
    const signature = crypto
      .createHmac('sha256', secretKey)
      .update(message)
      .digest('base64');

    return res.status(200).json({
      signature: signature,
      timestamp: timestamp,
      message: message // 디버깅용
    });

  } catch (error) {
    return res.status(500).json({
      error: 'Internal server error',
      details: error.message
    });
  }
}
