// Netlify Serverless Function: Gmail API 連携 (送受信)
// 環境変数:
//   GOOGLE_SERVICE_ACCOUNT_EMAIL - サービスアカウントのメール
//   GOOGLE_PRIVATE_KEY - サービスアカウントの秘密鍵 (PEM形式, \n をそのまま)
//   GMAIL_USER_EMAIL - 送受信に使うメールアドレス (例: recruitment@madoguchi.inc)

const crypto = require('crypto');

// ===== JWT 作成 & アクセストークン取得 =====
function createJWT(serviceAccountEmail, privateKey, userEmail) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccountEmail,
    sub: userEmail,
    scope: 'https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  const encHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const input = `${encHeader}.${encPayload}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(input);
  const signature = sign.sign(privateKey, 'base64url');

  return `${input}.${signature}`;
}

async function getAccessToken(serviceAccountEmail, privateKey, userEmail) {
  const jwt = createJWT(serviceAccountEmail, privateKey, userEmail);
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || JSON.stringify(data));
  return data.access_token;
}

// ===== メール送信 =====
function createRawEmail(from, to, subject, htmlBody) {
  // Subject を UTF-8 Base64 エンコード
  const encodedSubject = '=?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=';
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(htmlBody).toString('base64'),
  ];
  return Buffer.from(lines.join('\r\n')).toString('base64url');
}

async function sendEmail(accessToken, userEmail, to, subject, body) {
  const htmlBody = body.replace(/\n/g, '<br>');
  const raw = createRawEmail(userEmail, to, subject, htmlBody);

  const res = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/send`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ raw }),
    }
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));
  return data;
}

// ===== メール取得 =====
async function fetchEmails(accessToken, candidateEmail, maxResults = 20) {
  // 候補者のメールアドレスで検索 (送信 + 受信)
  const query = encodeURIComponent(`from:${candidateEmail} OR to:${candidateEmail}`);
  const listRes = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${query}&maxResults=${maxResults}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const listData = await listRes.json();
  if (!listRes.ok) throw new Error(listData.error?.message || JSON.stringify(listData));

  if (!listData.messages || listData.messages.length === 0) {
    return [];
  }

  // 各メッセージの詳細を取得
  const messages = await Promise.all(
    listData.messages.map(async (msg) => {
      const detailRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      const detail = await detailRes.json();
      if (!detailRes.ok) return null;
      return parseGmailMessage(detail, candidateEmail);
    })
  );

  return messages.filter(Boolean);
}

function parseGmailMessage(msg, candidateEmail) {
  const headers = msg.payload?.headers || [];
  const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';

  const from = getHeader('From');
  const to = getHeader('To');
  const subject = getHeader('Subject');
  const date = getHeader('Date');

  // 本文を抽出
  let body = '';
  if (msg.payload?.body?.data) {
    body = Buffer.from(msg.payload.body.data, 'base64url').toString('utf-8');
  } else if (msg.payload?.parts) {
    const textPart = msg.payload.parts.find(p => p.mimeType === 'text/plain');
    const htmlPart = msg.payload.parts.find(p => p.mimeType === 'text/html');
    const part = textPart || htmlPart;
    if (part?.body?.data) {
      body = Buffer.from(part.body.data, 'base64url').toString('utf-8');
    }
    // multipart/alternative の中にさらに parts がある場合
    if (!body) {
      for (const p of msg.payload.parts) {
        if (p.parts) {
          const sub = p.parts.find(sp => sp.mimeType === 'text/plain') || p.parts.find(sp => sp.mimeType === 'text/html');
          if (sub?.body?.data) {
            body = Buffer.from(sub.body.data, 'base64url').toString('utf-8');
            break;
          }
        }
      }
    }
  }

  // HTMLタグを除去してプレーンテキストに
  const plainBody = body.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').trim();

  // 方向判定: from に候補者メールが含まれていれば受信
  const isInbound = from.toLowerCase().includes(candidateEmail.toLowerCase());

  return {
    id: msg.id,
    threadId: msg.threadId,
    direction: isInbound ? 'inbound' : 'outbound',
    from,
    to,
    subject,
    body: plainBody.substring(0, 1000), // 長すぎる場合は切り詰め
    date: date ? new Date(date).toISOString() : null,
    labelIds: msg.labelIds || [],
  };
}

// ===== メインハンドラー =====
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  // 環境変数チェック
  const SA_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  const GMAIL_USER = process.env.GMAIL_USER_EMAIL;

  if (!SA_EMAIL || !PRIVATE_KEY || !GMAIL_USER) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Gmail API の環境変数が設定されていません (GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_PRIVATE_KEY, GMAIL_USER_EMAIL)',
      }),
    };
  }

  try {
    const reqBody = JSON.parse(event.body);
    const { action } = reqBody;

    // アクセストークン取得
    const accessToken = await getAccessToken(SA_EMAIL, PRIVATE_KEY, GMAIL_USER);

    if (action === 'send') {
      const { to, subject, body, candidateName } = reqBody;
      if (!to || !subject || !body) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: '宛先、件名、本文は必須です' }) };
      }
      const result = await sendEmail(accessToken, GMAIL_USER, to, subject, body);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          messageId: result.id,
          message: `${candidateName || to} へメールを送信しました`,
        }),
      };
    }

    if (action === 'fetch') {
      const { candidateEmail, maxResults } = reqBody;
      if (!candidateEmail) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: '候補者メールアドレスが必要です' }) };
      }
      const messages = await fetchEmails(accessToken, candidateEmail, maxResults || 20);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, messages }),
      };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: '不明なaction: ' + action }) };
  } catch (err) {
    console.error('Gmail function error:', err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'エラー: ' + err.message }),
    };
  }
};
