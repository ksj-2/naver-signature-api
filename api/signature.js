// api/signature.js
const crypto = require('crypto');

module.exports = (req, res) => {
  // CORS 설정 (Make.com에서 접근 가능하도록)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // OPTIONS 요청 처리
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    // POST 요청만 허용
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { secret, message } = req.body;

    // 필수 파라미터 확인
    if (!secret || !message) {
      return res.status(400).json({ 
        error: 'Missing required parameters: secret and message' 
      });
    }

    // HMAC-SHA256 서명 생성
    const signature = crypto
      .createHmac('sha256', secret)
      .update(message)
      .digest('base64');

    // 결과 반환
    res.status(200).json({
      signature: signature,
      message: message,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Signature generation error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
};
