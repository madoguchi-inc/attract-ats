// Netlify Function: AI設定を返す（内部ツール用）
// フロントエンドからWhisper APIを直接呼ぶために必要
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_API_KEY) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'OPENAI_API_KEY not configured' }) };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ key: OPENAI_API_KEY }),
  };
};
